//! `authenticatorMakeCredential` (CTAP 2.1 §6.1, command 0x01): the request
//! encoder, the response parser and the device call.
//!
//! Scope is what keyroost needs to create one credential on a key: an ES256
//! credential, optionally resident, optionally with the `credProtect`,
//! `hmac-secret` and `largeBlobKey` extensions. No excludeList, no
//! enterpriseAttestation, no attestation verification (the attestation
//! statement is ignored).

use std::time::Duration;

use zeroize::{Zeroize, Zeroizing};

use crate::auth_data::parse_auth_data;
use crate::cbor::{self, Value};
use crate::client_pin::PinUvAuthToken;
use crate::cmd::{split_status, AuthenticatorInfo, CtapError};
use crate::hid::CTAPHID_CBOR;
use crate::transport::{with_timeout, CtapTransport};

pub const CTAP2_MAKE_CREDENTIAL: u8 = 0x01;

/// makeCredential waits for a touch (and, on some keys, on-device user
/// verification), so it needs the same long window `reset` uses rather than a
/// normal CTAP transaction timeout.
const MAKE_CREDENTIAL_TIMEOUT: Duration = Duration::from_secs(30);

/// COSE algorithm ES256 (ECDSA P-256 with SHA-256).
pub const COSE_ALG_ES256: i64 = -7;

/// CTAP 2.1 §6.1: `user.id` is at most 64 bytes.
const MAX_USER_ID_LEN: usize = 64;

// Request map keys (CTAP 2.1 §6.1).
const KEY_CLIENT_DATA_HASH: u64 = 0x01;
const KEY_RP: u64 = 0x02;
const KEY_USER: u64 = 0x03;
const KEY_PUB_KEY_CRED_PARAMS: u64 = 0x04;
const KEY_EXTENSIONS: u64 = 0x06;
const KEY_OPTIONS: u64 = 0x07;
const KEY_PIN_UV_AUTH_PARAM: u64 = 0x08;
const KEY_PIN_UV_AUTH_PROTOCOL: u64 = 0x09;

// Response map keys (CTAP 2.1 §6.1).
const RESP_AUTH_DATA: u64 = 0x02;
const RESP_LARGE_BLOB_KEY: u64 = 0x05;

// Extension identifiers, as they appear in getInfo, the request and the
// authenticator-data extension outputs.
const EXT_CRED_PROTECT: &str = "credProtect";
const EXT_HMAC_SECRET: &str = "hmac-secret";
const EXT_LARGE_BLOB_KEY: &str = "largeBlobKey";

/// One makeCredential request.
pub struct MakeCredentialRequest<'a> {
    pub client_data_hash: [u8; 32],
    pub rp_id: &'a str,
    pub rp_name: &'a str,
    /// `user.id`, 1 to 64 bytes.
    pub user_id: &'a [u8],
    pub user_name: &'a str,
    /// Ask for a resident (discoverable) credential: options `{"rk": true}`.
    pub resident: bool,
    /// `credProtect` policy 1, 2 or 3; `None` leaves the extension out.
    pub cred_protect: Option<u8>,
    pub hmac_secret: bool,
    pub large_blob_key: bool,
    /// The pinUvAuthToken and the pinUvAuthProtocol (1 or 2) it was obtained
    /// under; the protocol must match the token's own.
    pub pin_uv_auth: Option<(&'a PinUvAuthToken, u32)>,
}

/// What keyroost keeps from a makeCredential response.
pub struct MadeCredential {
    pub credential_id: Vec<u8>,
    /// The per-credential `largeBlobKey` (response key 0x05), when the
    /// authenticator returned one.
    pub large_blob_key: Option<Zeroizing<[u8; 32]>>,
    /// The `credProtect` policy the authenticator reports in its
    /// authenticator-data extension outputs, when present.
    pub cred_protect: Option<u8>,
}

// Hand-written so the largeBlobKey never lands in a log.
impl std::fmt::Debug for MadeCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MadeCredential")
            .field("credential_id", &self.credential_id)
            .field(
                "large_blob_key",
                &self.large_blob_key.as_ref().map(|_| "<redacted>"),
            )
            .field("cred_protect", &self.cred_protect)
            .finish()
    }
}

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

/// Encode the makeCredential request map (without the command byte).
///
/// Map keys are ascending and every text-keyed map is in CTAP canonical
/// order (shorter key first, then bytewise): `{"id", "name"}`,
/// `{"alg", "type"}`, `{"credProtect", "hmac-secret", "largeBlobKey"}`.
/// `user.displayName` is never sent.
pub fn encode_make_credential(r: &MakeCredentialRequest) -> Vec<u8> {
    let mut entries = vec![
        (
            Value::UInt(KEY_CLIENT_DATA_HASH),
            Value::Bytes(r.client_data_hash.to_vec()),
        ),
        (
            Value::UInt(KEY_RP),
            Value::Map(vec![
                (text("id"), text(r.rp_id)),
                (text("name"), text(r.rp_name)),
            ]),
        ),
        (
            Value::UInt(KEY_USER),
            Value::Map(vec![
                (text("id"), Value::Bytes(r.user_id.to_vec())),
                (text("name"), text(r.user_name)),
            ]),
        ),
        (
            Value::UInt(KEY_PUB_KEY_CRED_PARAMS),
            Value::Array(vec![Value::Map(vec![
                // -7 is CBOR negative integer n = 6.
                (text("alg"), Value::NInt((-1 - COSE_ALG_ES256) as u64)),
                (text("type"), text("public-key")),
            ])]),
        ),
    ];

    // "credProtect" and "hmac-secret" are both 11 bytes and 'c' < 'h';
    // "largeBlobKey" is 12 bytes, so it sorts last.
    let mut extensions = Vec::new();
    if let Some(policy) = r.cred_protect {
        extensions.push((text(EXT_CRED_PROTECT), Value::UInt(u64::from(policy))));
    }
    if r.hmac_secret {
        extensions.push((text(EXT_HMAC_SECRET), Value::Bool(true)));
    }
    if r.large_blob_key {
        extensions.push((text(EXT_LARGE_BLOB_KEY), Value::Bool(true)));
    }
    if !extensions.is_empty() {
        entries.push((Value::UInt(KEY_EXTENSIONS), Value::Map(extensions)));
    }

    if r.resident {
        entries.push((
            Value::UInt(KEY_OPTIONS),
            Value::Map(vec![(text("rk"), Value::Bool(true))]),
        ));
    }

    if let Some((token, protocol)) = r.pin_uv_auth {
        entries.push((
            Value::UInt(KEY_PIN_UV_AUTH_PARAM),
            Value::Bytes(token.authenticate(&r.client_data_hash)),
        ));
        entries.push((
            Value::UInt(KEY_PIN_UV_AUTH_PROTOCOL),
            Value::UInt(u64::from(protocol)),
        ));
    }

    cbor::encode(&Value::Map(entries))
}

/// Parse a makeCredential response body (the CBOR map after the status
/// byte). The authenticator data must carry attested credential data; a
/// `largeBlobKey` must be exactly 32 bytes. As elsewhere in this crate, the
/// first of duplicate map keys wins.
pub fn parse_make_credential(resp: &[u8]) -> Result<MadeCredential, CtapError> {
    let (value, _) = cbor::decode(resp)?;
    let Value::Map(entries) = value else {
        return Err(CtapError::InvalidResponseShape(
            "makeCredential response is not a map",
        ));
    };

    let mut auth_data = None;
    let mut large_blob_key: Option<Result<Zeroizing<[u8; 32]>, CtapError>> = None;
    for (k, v) in entries {
        match k.as_uint() {
            Some(RESP_AUTH_DATA) if auth_data.is_none() => {
                auth_data = Some(v);
            }
            Some(RESP_LARGE_BLOB_KEY) => {
                // Every copy is wiped, a duplicate one included.
                if let Value::Bytes(mut bytes) = v {
                    if large_blob_key.is_none() {
                        large_blob_key = Some(large_blob_key_from(&bytes));
                    }
                    bytes.zeroize();
                } else if large_blob_key.is_none() {
                    large_blob_key = Some(Err(LARGE_BLOB_KEY_SHAPE));
                }
            }
            _ => {}
        }
    }
    let large_blob_key = large_blob_key.transpose()?;

    let auth_data = auth_data.ok_or(CtapError::InvalidResponseShape(
        "makeCredential response has no authenticator data",
    ))?;
    let auth_data = auth_data.as_bytes().ok_or(CtapError::InvalidResponseShape(
        "makeCredential authenticator data is not a byte string",
    ))?;
    let auth_data = parse_auth_data(auth_data)?;
    let credential_id = auth_data
        .credential_id
        .ok_or(CtapError::InvalidResponseShape(
            "makeCredential authenticator data has no attested credential",
        ))?;

    let cred_protect = match auth_data.extensions.as_ref().and_then(|ext| {
        ext.as_map()?
            .iter()
            .find(|(k, _)| k.as_text() == Some(EXT_CRED_PROTECT))
    }) {
        None => None,
        Some((_, v)) => Some(v.as_uint().and_then(|n| u8::try_from(n).ok()).ok_or(
            CtapError::InvalidResponseShape("credProtect output is not a small integer"),
        )?),
    };

    Ok(MadeCredential {
        credential_id,
        large_blob_key,
        cred_protect,
    })
}

const LARGE_BLOB_KEY_SHAPE: CtapError =
    CtapError::InvalidResponseShape("largeBlobKey is not 32 bytes");

fn large_blob_key_from(bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>, CtapError> {
    let mut key = Zeroizing::new([0u8; 32]);
    if bytes.len() != key.len() {
        return Err(LARGE_BLOB_KEY_SHAPE);
    }
    key.copy_from_slice(bytes);
    Ok(key)
}

/// Check a request against the key's getInfo and the request's own limits,
/// so an unsupported request fails with a clear message before the key is
/// asked for a touch.
fn check_request(info: &AuthenticatorInfo, req: &MakeCredentialRequest) -> Result<(), CtapError> {
    if req.user_id.is_empty() || req.user_id.len() > MAX_USER_ID_LEN {
        return Err(CtapError::InvalidArgument(
            "the credential's user ID must be 1 to 64 bytes",
        ));
    }
    if let Some((token, protocol)) = req.pin_uv_auth {
        if token.protocol != protocol {
            return Err(CtapError::InvalidArgument(
                "the PIN/UV auth protocol does not match the token's",
            ));
        }
    }
    let has = |ext: &str| info.extensions.iter().any(|e| e == ext);
    if let Some(policy) = req.cred_protect {
        if !(1..=3).contains(&policy) {
            return Err(CtapError::InvalidArgument(
                "credProtect policy must be 1, 2 or 3",
            ));
        }
        if !has(EXT_CRED_PROTECT) {
            return Err(CtapError::Unsupported(
                "this key does not support credential protection (credProtect)",
            ));
        }
    }
    if req.hmac_secret && !has(EXT_HMAC_SECRET) {
        return Err(CtapError::Unsupported(
            "this key does not support the hmac-secret extension",
        ));
    }
    if req.large_blob_key && !has(EXT_LARGE_BLOB_KEY) {
        return Err(CtapError::Unsupported(
            "this key does not support large-blob keys (largeBlobKey)",
        ));
    }
    if req.resident && info.option("rk") != Some(true) {
        return Err(CtapError::Unsupported(
            "this key cannot store discoverable (resident) credentials",
        ));
    }
    Ok(())
}

/// Issue `authenticatorMakeCredential`. The key waits for a touch, so the
/// call runs under a long timeout, restored afterwards as `reset` does.
/// Requests the key's getInfo says it cannot honor are refused before
/// anything is sent.
pub fn make_credential(
    dev: &mut impl CtapTransport,
    info: &AuthenticatorInfo,
    req: &MakeCredentialRequest,
) -> Result<MadeCredential, CtapError> {
    check_request(info, req)?;
    let mut payload = vec![CTAP2_MAKE_CREDENTIAL];
    payload.extend_from_slice(&encode_make_credential(req));
    // The response carries the largeBlobKey; wipe the raw buffer after.
    let resp = Zeroizing::new(with_timeout(dev, MAKE_CREDENTIAL_TIMEOUT, |d| {
        d.transact(CTAPHID_CBOR, &payload)
    })?);
    let (status, body) = split_status(&resp)?;
    if status != 0 {
        return Err(CtapError::StatusCode(status));
    }
    parse_make_credential(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pin::PIN_PROTOCOL_V1;

    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn v1_token() -> PinUvAuthToken {
        PinUvAuthToken {
            protocol: PIN_PROTOCOL_V1,
            token: vec![0x5a; 16],
        }
    }

    const USER_ID: &[u8] = &[
        0x01, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, b'v', b'a', b'u', b'l', b't',
    ];

    fn vault_request(token: &PinUvAuthToken) -> MakeCredentialRequest<'_> {
        MakeCredentialRequest {
            client_data_hash: [0x11; 32],
            rp_id: "fido2-vault.token2",
            rp_name: "FidoParole",
            user_id: USER_ID,
            user_name: "vault",
            resident: true,
            cred_protect: Some(3),
            hmac_secret: true,
            large_blob_key: true,
            pin_uv_auth: Some((token, PIN_PROTOCOL_V1)),
        }
    }

    fn full_info() -> AuthenticatorInfo {
        AuthenticatorInfo {
            extensions: vec![
                EXT_CRED_PROTECT.into(),
                EXT_HMAC_SECRET.into(),
                EXT_LARGE_BLOB_KEY.into(),
            ],
            options: vec![("rk".into(), true)],
            ..Default::default()
        }
    }

    /// Written by hand from CTAP 2.1 §6.1. pinUvAuthParam is the first 16
    /// bytes of HMAC-SHA-256(key = 16 x 0x5a, msg = 32 x 0x11), computed with
    /// an independent HMAC implementation.
    const EXPECTED_KAT: &str = concat!(
        "a8",
        // 1: clientDataHash
        "01 5820 1111111111111111111111111111111111111111111111111111111111111111",
        // 2: rp {"id": "fido2-vault.token2", "name": "FidoParole"}
        "02 a2 626964 72 6669646f322d7661756c742e746f6b656e32",
        "646e616d65 6a 4669646f5061726f6c65",
        // 3: user {"id": h'01a0..a7' || "vault", "name": "vault"}
        "03 a2 626964 4e 01a0a1a2a3a4a5a6a7 7661756c74",
        "646e616d65 65 7661756c74",
        // 4: pubKeyCredParams [{"alg": -7, "type": "public-key"}]
        "04 81 a2 63616c67 26 6474797065 6a 7075626c69632d6b6579",
        // 6: extensions {"credProtect": 3, "hmac-secret": true, "largeBlobKey": true}
        "06 a3 6b 6372656450726f74656374 03",
        "6b 686d61632d736563726574 f5",
        "6c 6c61726765426c6f624b6579 f5",
        // 7: options {"rk": true}
        "07 a1 62726b f5",
        // 8: pinUvAuthParam
        "08 50 e2019a86620dd331caf307ac4dec120d",
        // 9: pinUvAuthProtocol
        "09 01",
    );

    #[test]
    fn encode_make_credential_kat() {
        let token = v1_token();
        let encoded = encode_make_credential(&vault_request(&token));
        assert_eq!(encoded, unhex(EXPECTED_KAT));

        // And the structure decodes as the spec lays it out.
        let (v, rest) = cbor::decode(&encoded).unwrap();
        assert!(rest.is_empty());
        let keys: Vec<u64> = v
            .as_map()
            .unwrap()
            .iter()
            .map(|(k, _)| k.as_uint().unwrap())
            .collect();
        assert_eq!(keys, vec![1, 2, 3, 4, 6, 7, 8, 9]);
        let user = v.get_uint_key(3).unwrap().as_map().unwrap();
        assert!(user.iter().all(|(k, _)| k.as_text() != Some("displayName")));
        assert_eq!(
            v.get_uint_key(8).unwrap().as_bytes().unwrap(),
            &token.authenticate(&[0x11; 32])[..]
        );
    }

    #[test]
    fn encode_make_credential_minimal() {
        let req = MakeCredentialRequest {
            client_data_hash: [0x22; 32],
            rp_id: "a",
            rp_name: "b",
            user_id: &[0x07],
            user_name: "c",
            resident: false,
            cred_protect: None,
            hmac_secret: false,
            large_blob_key: false,
            pin_uv_auth: None,
        };
        let expected = unhex(concat!(
            "a4",
            "01 5820 2222222222222222222222222222222222222222222222222222222222222222",
            "02 a2 626964 6161 646e616d65 6162",
            "03 a2 626964 4107 646e616d65 6163",
            "04 81 a2 63616c67 26 6474797065 6a 7075626c69632d6b6579",
        ));
        assert_eq!(encode_make_credential(&req), expected);
    }

    /// Authenticator data with AT and ED, credential ID `cafe`, extensions
    /// `{"credProtect": 3}`.
    fn auth_data_bytes() -> Vec<u8> {
        unhex(concat!(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "c5 00000000 00000000000000000000000000000000",
            "0002 cafe",
            "a5 0102 0326 2001",
            "21 5820 1111111111111111111111111111111111111111111111111111111111111111",
            "22 5820 2222222222222222222222222222222222222222222222222222222222222222",
            "a1 6b 6372656450726f74656374 03",
        ))
    }

    fn response(large_blob_key: Option<Vec<u8>>) -> Vec<u8> {
        let mut entries = vec![
            (Value::UInt(1), Value::Text("packed".into())),
            (Value::UInt(2), Value::Bytes(auth_data_bytes())),
            (Value::UInt(3), Value::Map(vec![])),
        ];
        if let Some(k) = large_blob_key {
            entries.push((Value::UInt(5), Value::Bytes(k)));
        }
        cbor::encode(&Value::Map(entries))
    }

    #[test]
    fn parse_make_credential_reads_large_blob_key() {
        let key: Vec<u8> = (0..32).collect();
        let made = parse_make_credential(&response(Some(key.clone()))).unwrap();
        assert_eq!(made.credential_id, vec![0xca, 0xfe]);
        assert_eq!(
            made.large_blob_key.as_deref().map(|k| &k[..]),
            Some(&key[..])
        );
        assert_eq!(made.cred_protect, Some(3));

        let made = parse_make_credential(&response(None)).unwrap();
        assert!(made.large_blob_key.is_none());

        for bad in [vec![0u8; 31], vec![0u8; 33], vec![]] {
            assert!(matches!(
                parse_make_credential(&response(Some(bad))),
                Err(CtapError::InvalidResponseShape(
                    "largeBlobKey is not 32 bytes"
                ))
            ));
        }
    }

    #[test]
    fn parse_make_credential_needs_an_attested_credential() {
        // No authData at all.
        let no_ad = cbor::encode(&Value::Map(vec![(
            Value::UInt(1),
            Value::Text("none".into()),
        )]));
        assert!(parse_make_credential(&no_ad).is_err());
        // authData without the AT flag.
        let mut bare = vec![0u8; 37];
        bare[32] = crate::auth_data::FLAG_UP;
        let resp = cbor::encode(&Value::Map(vec![(Value::UInt(2), Value::Bytes(bare))]));
        assert!(parse_make_credential(&resp).is_err());
        // Not a map.
        assert!(parse_make_credential(&[0x01]).is_err());
        assert!(parse_make_credential(&[]).is_err());
    }

    /// Answers every transact with a fixed response, recording requests and
    /// the timeout in force when each was sent.
    struct FixedDevice {
        response: Vec<u8>,
        requests: Vec<(u8, Vec<u8>, Duration)>,
        timeout: Duration,
    }

    impl FixedDevice {
        fn new(response: Vec<u8>) -> Self {
            FixedDevice {
                response,
                requests: Vec::new(),
                timeout: Duration::from_secs(3),
            }
        }
    }

    impl CtapTransport for FixedDevice {
        fn transact(&mut self, cmd: u8, payload: &[u8]) -> Result<Vec<u8>, CtapError> {
            self.requests.push((cmd, payload.to_vec(), self.timeout));
            Ok(self.response.clone())
        }
        fn set_timeout(&mut self, timeout: Duration) {
            self.timeout = timeout;
        }
        fn read_timeout(&self) -> Duration {
            self.timeout
        }
    }

    #[test]
    fn make_credential_sends_command_under_touch_timeout() {
        let key = vec![0x44; 32];
        let mut ok = vec![0x00];
        ok.extend(response(Some(key.clone())));
        let mut dev = FixedDevice::new(ok);
        let token = v1_token();
        let req = vault_request(&token);
        let made = make_credential(&mut dev, &full_info(), &req).unwrap();
        assert_eq!(made.credential_id, vec![0xca, 0xfe]);
        assert_eq!(
            made.large_blob_key.as_deref().map(|k| &k[..]),
            Some(&key[..])
        );

        assert_eq!(dev.requests.len(), 1);
        let (cmd, payload, timeout) = &dev.requests[0];
        assert_eq!(*cmd, CTAPHID_CBOR);
        assert_eq!(payload[0], CTAP2_MAKE_CREDENTIAL);
        assert_eq!(&payload[1..], &unhex(EXPECTED_KAT)[..]);
        assert_eq!(*timeout, MAKE_CREDENTIAL_TIMEOUT);
        assert_eq!(
            dev.timeout,
            Duration::from_secs(3),
            "caller's timeout restored"
        );
    }

    #[test]
    fn make_credential_maps_status_errors() {
        let mut dev = FixedDevice::new(vec![0x2e]);
        let token = v1_token();
        let err = make_credential(&mut dev, &full_info(), &vault_request(&token)).unwrap_err();
        assert!(matches!(err, CtapError::StatusCode(0x2e)));
        let mut dev = FixedDevice::new(vec![]);
        let err = make_credential(&mut dev, &full_info(), &vault_request(&token)).unwrap_err();
        assert!(matches!(err, CtapError::EmptyResponse));
    }

    #[test]
    fn make_credential_refuses_what_the_key_lacks_before_sending() {
        let token = v1_token();
        let without = |drop: &str| {
            let mut info = full_info();
            info.extensions.retain(|e| e != drop);
            info
        };
        let cases = [
            without(EXT_CRED_PROTECT),
            without(EXT_HMAC_SECRET),
            without(EXT_LARGE_BLOB_KEY),
            AuthenticatorInfo {
                options: vec![("rk".into(), false)],
                ..full_info()
            },
        ];
        for info in cases {
            let mut dev = FixedDevice::new(vec![0x00]);
            let err = make_credential(&mut dev, &info, &vault_request(&token)).unwrap_err();
            assert!(matches!(err, CtapError::Unsupported(_)), "{err:?}");
            assert!(dev.requests.is_empty());
        }
    }

    #[test]
    fn make_credential_refuses_bad_arguments_before_sending() {
        let token = v1_token();
        let with = |tweak: fn(&mut MakeCredentialRequest)| {
            let mut req = vault_request(&token);
            tweak(&mut req);
            req
        };
        let bad = [
            with(|r| r.user_id = &[]),
            with(|r| r.user_id = &[0u8; 65]),
            with(|r| r.cred_protect = Some(4)),
            with(|r| r.pin_uv_auth = r.pin_uv_auth.map(|(t, _)| (t, 2))),
        ];
        for req in bad {
            let mut dev = FixedDevice::new(vec![0x00]);
            let err = make_credential(&mut dev, &full_info(), &req).unwrap_err();
            assert!(matches!(err, CtapError::InvalidArgument(_)), "{err:?}");
            assert!(dev.requests.is_empty());
        }
    }
}
