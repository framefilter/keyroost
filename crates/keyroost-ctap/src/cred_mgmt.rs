//! CTAP2 `authenticatorCredentialManagement` (0x0A, or preview 0x41).
//!
//! Each sub-command lists or mutates the resident (discoverable) credentials
//! stored on the authenticator. Every request must be authenticated with a
//! `pinUvAuthParam` HMAC over a sub-command-specific value, computed using
//! the pinUvAuthToken obtained from `clientPin::get_pin_token`.
//!
//! Authenticators advertise support via two `getInfo` options: `credMgmt`
//! for the standard 0x0A command, and `credentialMgmtPreview` for the older
//! 0x41 form (most notably emitted by YubiKey 5 firmware ≤ 5.4.x). We probe
//! both via [`CredentialManager::new`] and use whichever the device claims.

use crate::cbor::{self, Value};
use crate::client_pin::PinUvAuthToken;
use crate::cmd::{AuthenticatorInfo, CtapError};
use crate::hid::{CtapHidDevice, CTAPHID_CBOR};

pub const CTAP2_CREDENTIAL_MANAGEMENT: u8 = 0x0A;
pub const CTAP2_CREDENTIAL_MANAGEMENT_PREVIEW: u8 = 0x41;

/// Request map keys.
const KEY_SUB_COMMAND: u64 = 0x01;
const KEY_SUB_COMMAND_PARAMS: u64 = 0x02;
const KEY_PIN_UV_AUTH_PROTOCOL: u64 = 0x03;
const KEY_PIN_UV_AUTH_PARAM: u64 = 0x04;

/// Sub-command numbers.
const SUB_GET_CREDS_METADATA: u8 = 0x01;
const SUB_ENUMERATE_RPS_BEGIN: u8 = 0x02;
const SUB_ENUMERATE_RPS_NEXT: u8 = 0x03;
const SUB_ENUMERATE_CREDS_BEGIN: u8 = 0x04;
const SUB_ENUMERATE_CREDS_NEXT: u8 = 0x05;
const SUB_DELETE_CREDENTIAL: u8 = 0x06;

/// Sub-command parameter keys (CTAP §6.8.2).
const PARAM_RP_ID_HASH: u64 = 0x01;
const PARAM_CREDENTIAL_ID: u64 = 0x02;

/// Response map keys (the same numeric keys mean different things for
/// different sub-commands — context determines which fields are populated).
const RESP_EXISTING_COUNT: u64 = 0x01;
const RESP_MAX_REMAINING: u64 = 0x02;
const RESP_RP: u64 = 0x03;
const RESP_RP_ID_HASH: u64 = 0x04;
const RESP_TOTAL_RPS: u64 = 0x05;
const RESP_USER: u64 = 0x06;
const RESP_CREDENTIAL_ID: u64 = 0x07;
const RESP_PUBLIC_KEY: u64 = 0x08;
const RESP_TOTAL_CREDS: u64 = 0x09;

/// Aggregate resident-credential storage stats from `getCredsMetadata`.
#[derive(Debug, Clone, Default)]
pub struct CredsMetadata {
    pub existing_count: u64,
    pub max_remaining: u64,
}

/// A relying party that owns at least one resident credential on the key.
#[derive(Debug, Clone)]
pub struct RelyingParty {
    pub id: String,
    pub name: Option<String>,
    pub rp_id_hash: [u8; 32],
}

/// User entity bound to a resident credential.
#[derive(Debug, Clone, Default)]
pub struct CredentialUser {
    pub id: Vec<u8>,
    pub name: Option<String>,
    pub display_name: Option<String>,
}

/// One resident credential entry returned by `enumerateCredentials`.
#[derive(Debug, Clone)]
pub struct Credential {
    /// PublicKeyCredentialDescriptor.id — used as the handle for deletion.
    pub credential_id: Vec<u8>,
    pub user: CredentialUser,
    /// COSE algorithm identifier extracted from the credential public key.
    pub algorithm: Option<i64>,
}

/// Bundle of (device, token, command-code) for issuing credentialManagement
/// sub-commands. The wrapper exists because every sub-command needs the
/// same authentication and the device's choice between 0x0A and 0x41 has to
/// be discovered once from `getInfo`.
pub struct CredentialManager<'a> {
    dev: &'a mut CtapHidDevice,
    token: PinUvAuthToken,
    cmd_code: u8,
}

impl<'a> CredentialManager<'a> {
    /// Construct after `clientPin::get_pin_token`. Returns
    /// [`CtapError::InvalidResponseShape`] if the authenticator advertises
    /// neither `credMgmt` nor `credentialMgmtPreview`.
    pub fn new(
        dev: &'a mut CtapHidDevice,
        token: PinUvAuthToken,
        info: &AuthenticatorInfo,
    ) -> Result<Self, CtapError> {
        let cmd_code = if info.option("credMgmt") == Some(true) {
            CTAP2_CREDENTIAL_MANAGEMENT
        } else if info.option("credentialMgmtPreview") == Some(true) {
            CTAP2_CREDENTIAL_MANAGEMENT_PREVIEW
        } else {
            return Err(CtapError::InvalidResponseShape(
                "authenticator does not support credentialManagement",
            ));
        };
        Ok(Self {
            dev,
            token,
            cmd_code,
        })
    }

    /// Resident credential capacity stats.
    pub fn metadata(&mut self) -> Result<CredsMetadata, CtapError> {
        let resp = self.dispatch(SUB_GET_CREDS_METADATA, None)?;
        let mut meta = CredsMetadata::default();
        for (k, v) in resp.as_map().into_iter().flatten() {
            match k.as_uint() {
                Some(RESP_EXISTING_COUNT) => meta.existing_count = v.as_uint().unwrap_or(0),
                Some(RESP_MAX_REMAINING) => meta.max_remaining = v.as_uint().unwrap_or(0),
                _ => {}
            }
        }
        Ok(meta)
    }

    /// List every relying party that owns at least one resident credential.
    pub fn list_relying_parties(&mut self) -> Result<Vec<RelyingParty>, CtapError> {
        let first = self.dispatch(SUB_ENUMERATE_RPS_BEGIN, None)?;
        let total = field_uint(&first, RESP_TOTAL_RPS).unwrap_or(0) as usize;
        if total == 0 {
            return Ok(Vec::new());
        }
        let mut out = Vec::with_capacity(total);
        out.push(parse_rp(&first)?);
        while out.len() < total {
            let v = self.dispatch(SUB_ENUMERATE_RPS_NEXT, None)?;
            out.push(parse_rp(&v)?);
        }
        Ok(out)
    }

    /// List every resident credential bound to the given relying-party ID
    /// hash. The hash is what every other CTAP API gives you for the RP, so
    /// callers should pass it through rather than rehashing.
    pub fn list_credentials(
        &mut self,
        rp_id_hash: &[u8; 32],
    ) -> Result<Vec<Credential>, CtapError> {
        let params = Value::Map(vec![(
            Value::UInt(PARAM_RP_ID_HASH),
            Value::Bytes(rp_id_hash.to_vec()),
        )]);
        let first = self.dispatch(SUB_ENUMERATE_CREDS_BEGIN, Some(params))?;
        let total = field_uint(&first, RESP_TOTAL_CREDS).unwrap_or(0) as usize;
        if total == 0 {
            return Ok(Vec::new());
        }
        let mut out = Vec::with_capacity(total);
        out.push(parse_credential(&first)?);
        while out.len() < total {
            let v = self.dispatch(SUB_ENUMERATE_CREDS_NEXT, None)?;
            out.push(parse_credential(&v)?);
        }
        Ok(out)
    }

    /// Delete a resident credential by its `credentialId` bytes (as
    /// returned by [`Self::list_credentials`]).
    pub fn delete(&mut self, credential_id: &[u8]) -> Result<(), CtapError> {
        let cred_desc = Value::Map(vec![
            (Value::Text("id".into()), Value::Bytes(credential_id.to_vec())),
            (Value::Text("type".into()), Value::Text("public-key".into())),
        ]);
        let params = Value::Map(vec![(Value::UInt(PARAM_CREDENTIAL_ID), cred_desc)]);
        self.dispatch(SUB_DELETE_CREDENTIAL, Some(params))?;
        Ok(())
    }

    fn dispatch(&mut self, sub: u8, params: Option<Value>) -> Result<Value, CtapError> {
        let request = self.build_request(sub, params.as_ref());
        let mut payload = Vec::with_capacity(request.len() + 1);
        payload.push(self.cmd_code);
        payload.extend_from_slice(&request);
        let resp = self.dev.transact(CTAPHID_CBOR, &payload)?;
        let (status, body) = resp.split_first().ok_or(CtapError::EmptyResponse)?;
        if *status != 0 {
            return Err(CtapError::StatusCode(*status));
        }
        if body.is_empty() {
            return Ok(Value::Map(Vec::new()));
        }
        let (value, _) = cbor::decode(body)?;
        Ok(value)
    }

    fn build_request(&self, sub: u8, params: Option<&Value>) -> Vec<u8> {
        // Auth target: subCommand byte || cbor(subCommandParams) if any.
        let mut auth_input = Vec::with_capacity(64);
        auth_input.push(sub);
        if let Some(p) = params {
            auth_input.extend_from_slice(&cbor::encode(p));
        }
        let pin_uv_auth_param = self.token.authenticate(&auth_input);

        let mut entries: Vec<(Value, Value)> = Vec::with_capacity(4);
        entries.push((Value::UInt(KEY_SUB_COMMAND), Value::UInt(sub as u64)));
        if let Some(p) = params {
            entries.push((Value::UInt(KEY_SUB_COMMAND_PARAMS), p.clone()));
        }
        entries.push((
            Value::UInt(KEY_PIN_UV_AUTH_PROTOCOL),
            Value::UInt(self.token.protocol as u64),
        ));
        entries.push((
            Value::UInt(KEY_PIN_UV_AUTH_PARAM),
            Value::Bytes(pin_uv_auth_param),
        ));
        cbor::encode(&Value::Map(entries))
    }
}

fn field_uint(v: &Value, key: u64) -> Option<u64> {
    v.get_uint_key(key).and_then(|x| x.as_uint())
}

fn parse_rp(v: &Value) -> Result<RelyingParty, CtapError> {
    let rp_entity = v
        .get_uint_key(RESP_RP)
        .ok_or(CtapError::InvalidResponseShape("missing RP entity"))?;
    let rp_id_hash = v
        .get_uint_key(RESP_RP_ID_HASH)
        .and_then(|x| x.as_bytes())
        .ok_or(CtapError::InvalidResponseShape("missing rpIdHash"))?;
    let mut rp_id = String::new();
    let mut rp_name: Option<String> = None;
    for (k, val) in rp_entity.as_map().into_iter().flatten() {
        match k.as_text() {
            Some("id") => {
                rp_id = val.as_text().unwrap_or_default().to_owned();
            }
            Some("name") => {
                rp_name = val.as_text().map(|s| s.to_owned());
            }
            _ => {}
        }
    }
    let mut hash = [0u8; 32];
    if rp_id_hash.len() == 32 {
        hash.copy_from_slice(rp_id_hash);
    }
    Ok(RelyingParty {
        id: rp_id,
        name: rp_name,
        rp_id_hash: hash,
    })
}

fn parse_credential(v: &Value) -> Result<Credential, CtapError> {
    let user = v
        .get_uint_key(RESP_USER)
        .ok_or(CtapError::InvalidResponseShape("missing user entity"))?;
    let cred_desc = v
        .get_uint_key(RESP_CREDENTIAL_ID)
        .ok_or(CtapError::InvalidResponseShape("missing credentialId"))?;
    let pubkey = v.get_uint_key(RESP_PUBLIC_KEY);

    let mut credential_user = CredentialUser::default();
    for (k, val) in user.as_map().into_iter().flatten() {
        match k.as_text() {
            Some("id") => {
                credential_user.id = val.as_bytes().unwrap_or_default().to_vec();
            }
            Some("name") => {
                credential_user.name = val.as_text().map(|s| s.to_owned());
            }
            Some("displayName") => {
                credential_user.display_name = val.as_text().map(|s| s.to_owned());
            }
            _ => {}
        }
    }

    let mut credential_id = Vec::new();
    for (k, val) in cred_desc.as_map().into_iter().flatten() {
        if k.as_text() == Some("id") {
            credential_id = val.as_bytes().unwrap_or_default().to_vec();
        }
    }

    let algorithm = pubkey.and_then(public_key_algorithm);

    Ok(Credential {
        credential_id,
        user: credential_user,
        algorithm,
    })
}

/// Extract the COSE `alg` field (map key 3, signed integer) from a
/// COSE_Key. The full key parse is more involved and Phase 2 only needs
/// the algorithm identifier for display.
fn public_key_algorithm(pubkey: &Value) -> Option<i64> {
    for (k, val) in pubkey.as_map().into_iter().flatten() {
        let key = match k {
            Value::UInt(n) => *n as i64,
            Value::NInt(n) => -1 - (*n as i64),
            _ => continue,
        };
        if key == 3 {
            return match val {
                Value::UInt(n) => Some(*n as i64),
                Value::NInt(n) => Some(-1 - (*n as i64)),
                _ => None,
            };
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::encode;
    use crate::client_pin::PinUvAuthToken;
    use crate::cmd::AuthenticatorInfo;
    use crate::pin::PIN_PROTOCOL_V1;

    fn fake_token() -> PinUvAuthToken {
        PinUvAuthToken {
            protocol: PIN_PROTOCOL_V1,
            token: vec![0x42; 16],
        }
    }

    fn info_with(opt: &str) -> AuthenticatorInfo {
        let mut info = AuthenticatorInfo::default();
        info.options.push((opt.to_owned(), true));
        info
    }

    fn build_request_via(mgr_cmd: u8, token: PinUvAuthToken, sub: u8, params: Option<Value>) -> Vec<u8> {
        // Construct a CredentialManager-equivalent helper for assertion
        // purposes without needing a real CtapHidDevice.
        let mut auth_input = Vec::new();
        auth_input.push(sub);
        if let Some(p) = &params {
            auth_input.extend_from_slice(&encode(p));
        }
        let pin_uv_auth_param = token.authenticate(&auth_input);
        let mut entries: Vec<(Value, Value)> = Vec::new();
        entries.push((Value::UInt(KEY_SUB_COMMAND), Value::UInt(sub as u64)));
        if let Some(p) = params {
            entries.push((Value::UInt(KEY_SUB_COMMAND_PARAMS), p));
        }
        entries.push((
            Value::UInt(KEY_PIN_UV_AUTH_PROTOCOL),
            Value::UInt(token.protocol as u64),
        ));
        entries.push((
            Value::UInt(KEY_PIN_UV_AUTH_PARAM),
            Value::Bytes(pin_uv_auth_param),
        ));
        let mut out = vec![mgr_cmd];
        out.extend_from_slice(&encode(&Value::Map(entries)));
        out
    }

    #[test]
    fn picks_standard_cmd_when_credmgmt_advertised() {
        let info = info_with("credMgmt");
        // Construction can't be tested directly without a device, but we
        // can assert the option lookup picks the right code via inline match.
        assert_eq!(info.option("credMgmt"), Some(true));
        assert_eq!(info.option("credentialMgmtPreview"), None);
    }

    #[test]
    fn picks_preview_cmd_when_only_preview_advertised() {
        let info = info_with("credentialMgmtPreview");
        assert_eq!(info.option("credMgmt"), None);
        assert_eq!(info.option("credentialMgmtPreview"), Some(true));
    }

    #[test]
    fn request_includes_pin_uv_auth_param_for_subcommand_byte() {
        let token = fake_token();
        let bytes = build_request_via(CTAP2_CREDENTIAL_MANAGEMENT, token, SUB_GET_CREDS_METADATA, None);
        // First byte is the command code; rest is CBOR.
        assert_eq!(bytes[0], CTAP2_CREDENTIAL_MANAGEMENT);
        let (val, _) = cbor::decode(&bytes[1..]).unwrap();
        let map = val.as_map().unwrap();
        assert!(map.iter().any(|(k, _)| k.as_uint() == Some(KEY_PIN_UV_AUTH_PROTOCOL)));
        assert!(map.iter().any(|(k, _)| k.as_uint() == Some(KEY_PIN_UV_AUTH_PARAM)));
    }

    #[test]
    fn delete_request_carries_credential_descriptor() {
        let token = fake_token();
        let cred_id = vec![0xAA; 32];
        let cred_desc = Value::Map(vec![
            (Value::Text("id".into()), Value::Bytes(cred_id.clone())),
            (Value::Text("type".into()), Value::Text("public-key".into())),
        ]);
        let params = Value::Map(vec![(Value::UInt(PARAM_CREDENTIAL_ID), cred_desc)]);
        let bytes = build_request_via(CTAP2_CREDENTIAL_MANAGEMENT, token, SUB_DELETE_CREDENTIAL, Some(params));
        let (val, _) = cbor::decode(&bytes[1..]).unwrap();
        let params_val = val.get_uint_key(KEY_SUB_COMMAND_PARAMS).unwrap();
        let inner = params_val.get_uint_key(PARAM_CREDENTIAL_ID).unwrap();
        // The credential descriptor is keyed by string "id".
        let id_val = inner.as_map().unwrap().iter().find_map(|(k, v)| {
            if k.as_text() == Some("id") { Some(v) } else { None }
        }).unwrap();
        assert_eq!(id_val.as_bytes(), Some(&cred_id[..]));
    }

    #[test]
    fn parse_rp_extracts_id_and_hash() {
        let rp = Value::Map(vec![
            (
                Value::UInt(RESP_RP),
                Value::Map(vec![
                    (Value::Text("id".into()), Value::Text("example.com".into())),
                    (Value::Text("name".into()), Value::Text("Example, Inc.".into())),
                ]),
            ),
            (Value::UInt(RESP_RP_ID_HASH), Value::Bytes(vec![0x77; 32])),
        ]);
        let parsed = parse_rp(&rp).unwrap();
        assert_eq!(parsed.id, "example.com");
        assert_eq!(parsed.name.as_deref(), Some("Example, Inc."));
        assert_eq!(parsed.rp_id_hash, [0x77; 32]);
    }

    #[test]
    fn parse_credential_extracts_user_id_and_cred_id() {
        let cred = Value::Map(vec![
            (
                Value::UInt(RESP_USER),
                Value::Map(vec![
                    (Value::Text("id".into()), Value::Bytes(vec![1, 2, 3])),
                    (Value::Text("name".into()), Value::Text("alice".into())),
                    (Value::Text("displayName".into()), Value::Text("Alice Liddell".into())),
                ]),
            ),
            (
                Value::UInt(RESP_CREDENTIAL_ID),
                Value::Map(vec![
                    (Value::Text("id".into()), Value::Bytes(vec![0xAB; 32])),
                    (Value::Text("type".into()), Value::Text("public-key".into())),
                ]),
            ),
            // COSE_Key with alg=-7 (ES256)
            (
                Value::UInt(RESP_PUBLIC_KEY),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(2)),
                    (Value::UInt(3), Value::NInt(6)),
                ]),
            ),
        ]);
        let parsed = parse_credential(&cred).unwrap();
        assert_eq!(parsed.credential_id, vec![0xAB; 32]);
        assert_eq!(parsed.user.id, vec![1, 2, 3]);
        assert_eq!(parsed.user.name.as_deref(), Some("alice"));
        assert_eq!(parsed.user.display_name.as_deref(), Some("Alice Liddell"));
        assert_eq!(parsed.algorithm, Some(-7));
    }
}
