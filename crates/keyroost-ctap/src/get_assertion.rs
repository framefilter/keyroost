//! `authenticatorGetAssertion` (CTAP 2.1 §6.2, command 0x02) and
//! `authenticatorGetNextAssertion` (§6.3, command 0x08): the request encoder,
//! the response parser and the device call that collects every assertion.
//!
//! Scope is what keyroost needs to read a credential back: an optional
//! one-entry allowList, the `hmac-secret` (one salt) and `largeBlobKey`
//! extensions, an optional `{"up": false}`, and a pinUvAuthToken. The
//! signature is not verified (keyroost trusts the key it is talking to for
//! these reads), so it is ignored.

use std::time::Duration;

use zeroize::{Zeroize, Zeroizing};

use crate::auth_data::parse_auth_data;
use crate::cbor::{self, Value};
use crate::client_pin::PinUvAuthToken;
use crate::cmd::{split_status, AuthenticatorInfo, CtapError};
use crate::hid::CTAPHID_CBOR;
use crate::hmac_secret::HmacSecretSession;
use crate::make_credential::{large_blob_key_from, LARGE_BLOB_KEY_SHAPE};
use crate::transport::{with_timeout, CtapTransport};

pub const CTAP2_GET_ASSERTION: u8 = 0x02;
pub const CTAP2_GET_NEXT_ASSERTION: u8 = 0x08;

/// getAssertion waits for a touch, so it gets the same long window
/// makeCredential and `reset` use. getNextAssertion does not (the touch
/// already happened) and runs under the caller's normal timeout.
const GET_ASSERTION_TIMEOUT: Duration = Duration::from_secs(30);

/// The most assertions one getAssertion may announce. A key holds far fewer
/// resident credentials per RP; a larger count is treated as a malformed
/// response rather than looped over.
const MAX_ASSERTIONS: u32 = 256;

/// `CTAP2_ERR_NO_CREDENTIALS`: no credential matches the RP ID / allowList.
const CTAP2_ERR_NO_CREDENTIALS: u8 = 0x2E;

// Request map keys (CTAP 2.1 §6.2).
const KEY_RP_ID: u64 = 0x01;
const KEY_CLIENT_DATA_HASH: u64 = 0x02;
const KEY_ALLOW_LIST: u64 = 0x03;
const KEY_EXTENSIONS: u64 = 0x04;
const KEY_OPTIONS: u64 = 0x05;
const KEY_PIN_UV_AUTH_PARAM: u64 = 0x06;
const KEY_PIN_UV_AUTH_PROTOCOL: u64 = 0x07;

// Response map keys (CTAP 2.1 §6.2).
const RESP_CREDENTIAL: u64 = 0x01;
const RESP_AUTH_DATA: u64 = 0x02;
const RESP_USER: u64 = 0x04;
const RESP_NUMBER_OF_CREDENTIALS: u64 = 0x05;
const RESP_LARGE_BLOB_KEY: u64 = 0x07;

const EXT_HMAC_SECRET: &str = "hmac-secret";
const EXT_LARGE_BLOB_KEY: &str = "largeBlobKey";

/// One getAssertion request.
pub struct GetAssertionRequest<'a> {
    pub client_data_hash: [u8; 32],
    pub rp_id: &'a str,
    /// A single credential ID for the allowList; `None` asks the key for
    /// every discoverable credential of the RP.
    pub allow: Option<&'a [u8]>,
    /// Ask for `hmac-secret` with this session and 32-byte salt. The same
    /// session decrypts the output of every assertion in the batch.
    pub hmac: Option<(&'a HmacSecretSession, [u8; 32])>,
    pub large_blob_key: bool,
    /// User presence. `false` sends options `{"up": false}`; `true` (the
    /// spec default) sends no options at all.
    pub up: bool,
    /// The pinUvAuthToken and the pinUvAuthProtocol (1 or 2) it was obtained
    /// under; the protocol must match the token's own.
    pub pin_uv_auth: Option<(&'a PinUvAuthToken, u32)>,
}

/// What keyroost keeps from one getAssertion / getNextAssertion response.
pub struct Assertion {
    pub credential_id: Vec<u8>,
    /// `user.id`, when the authenticator returned the user entity.
    pub user_id: Option<Vec<u8>>,
    /// `user.name`, when the authenticator returned it.
    pub user_name: Option<String>,
    /// The decrypted `hmac-secret` output, when it was asked for and present.
    pub hmac_output: Option<Zeroizing<[u8; 32]>>,
    /// The per-credential `largeBlobKey` (response key 0x07).
    pub large_blob_key: Option<Zeroizing<[u8; 32]>>,
    /// `numberOfCredentials` (response key 0x05); only the first response of
    /// a batch carries it.
    pub number_of_credentials: Option<u32>,
}

// Hand-written so the hmac-secret output and largeBlobKey never land in a log.
impl std::fmt::Debug for Assertion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Assertion")
            .field("credential_id", &self.credential_id)
            .field("user_id", &self.user_id)
            .field("user_name", &self.user_name)
            .field(
                "hmac_output",
                &self.hmac_output.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "large_blob_key",
                &self.large_blob_key.as_ref().map(|_| "<redacted>"),
            )
            .field("number_of_credentials", &self.number_of_credentials)
            .finish()
    }
}

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

/// Encode the getAssertion request map (without the command byte).
///
/// Map keys are ascending and every text-keyed map is in CTAP canonical
/// order (shorter key first, then bytewise): `{"id", "type"}` and
/// `{"hmac-secret", "largeBlobKey"}`. `"uv"` is never sent: verification
/// comes from the pinUvAuthToken.
pub fn encode_get_assertion(r: &GetAssertionRequest) -> Vec<u8> {
    let mut entries = vec![
        (Value::UInt(KEY_RP_ID), text(r.rp_id)),
        (
            Value::UInt(KEY_CLIENT_DATA_HASH),
            Value::Bytes(r.client_data_hash.to_vec()),
        ),
    ];

    if let Some(id) = r.allow {
        entries.push((
            Value::UInt(KEY_ALLOW_LIST),
            Value::Array(vec![Value::Map(vec![
                (text("id"), Value::Bytes(id.to_vec())),
                (text("type"), text("public-key")),
            ])]),
        ));
    }

    // "hmac-secret" is 11 bytes, "largeBlobKey" 12, so this order is
    // canonical.
    let mut extensions = Vec::new();
    if let Some((session, salt)) = &r.hmac {
        extensions.push((text(EXT_HMAC_SECRET), session.extension_input(salt)));
    }
    if r.large_blob_key {
        extensions.push((text(EXT_LARGE_BLOB_KEY), Value::Bool(true)));
    }
    if !extensions.is_empty() {
        entries.push((Value::UInt(KEY_EXTENSIONS), Value::Map(extensions)));
    }

    if !r.up {
        entries.push((
            Value::UInt(KEY_OPTIONS),
            Value::Map(vec![(text("up"), Value::Bool(false))]),
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

/// Parse a getAssertion / getNextAssertion response body (the CBOR map after
/// the status byte).
///
/// Permissive about what is present: only the credential and the
/// authenticator data are required; the user, `numberOfCredentials`, the
/// `largeBlobKey` and the `hmac-secret` output are `None` when absent. What
/// is present must have the spec's shape. With `hmac`, an `hmac-secret`
/// output is decrypted under that session; without one it is ignored. As
/// elsewhere in this crate, the first of duplicate map keys wins.
pub fn parse_get_assertion(
    resp: &[u8],
    hmac: Option<&HmacSecretSession>,
) -> Result<Assertion, CtapError> {
    let (credential_id, assertion) = parse_assertion(resp, hmac)?;
    let credential_id = credential_id.ok_or(NO_CREDENTIAL)?;
    Ok(Assertion {
        credential_id,
        ..assertion
    })
}

const NO_CREDENTIAL: CtapError =
    CtapError::InvalidResponseShape("getAssertion response names no credential");

/// The parser behind [`parse_get_assertion`], leaving the credential ID
/// optional: CTAP 2.1 §6.2 lets the key omit it when the allowList held
/// exactly one entry, which only [`get_assertions`] knows. The returned
/// `Assertion` has an empty `credential_id`.
fn parse_assertion(
    resp: &[u8],
    hmac: Option<&HmacSecretSession>,
) -> Result<(Option<Vec<u8>>, Assertion), CtapError> {
    let (value, _) = cbor::decode(resp)?;
    let Value::Map(entries) = value else {
        return Err(CtapError::InvalidResponseShape(
            "getAssertion response is not a map",
        ));
    };

    let mut credential = None;
    let mut auth_data = None;
    let mut user = None;
    let mut count = None;
    let mut large_blob_key: Option<Result<Zeroizing<[u8; 32]>, CtapError>> = None;
    for (k, v) in entries {
        match k.as_uint() {
            Some(RESP_CREDENTIAL) if credential.is_none() => credential = Some(v),
            Some(RESP_AUTH_DATA) if auth_data.is_none() => auth_data = Some(v),
            Some(RESP_USER) if user.is_none() => user = Some(v),
            Some(RESP_NUMBER_OF_CREDENTIALS) if count.is_none() => count = Some(v),
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

    let credential_id = credential
        .map(|c| {
            c.as_map()
                .and_then(|m| m.iter().find(|(k, _)| k.as_text() == Some("id")))
                .and_then(|(_, id)| id.as_bytes())
                .map(<[u8]>::to_vec)
                .ok_or(CtapError::InvalidResponseShape(
                    "getAssertion credential has no byte-string ID",
                ))
        })
        .transpose()?;

    let auth_data = auth_data.ok_or(CtapError::InvalidResponseShape(
        "getAssertion response has no authenticator data",
    ))?;
    let auth_data = auth_data.as_bytes().ok_or(CtapError::InvalidResponseShape(
        "getAssertion authenticator data is not a byte string",
    ))?;
    let auth_data = parse_auth_data(auth_data)?;

    let hmac_output = match hmac {
        None => None,
        Some(session) => match auth_data.extensions.as_ref().and_then(|ext| {
            ext.as_map()?
                .iter()
                .find(|(k, _)| k.as_text() == Some(EXT_HMAC_SECRET))
        }) {
            None => None,
            Some((_, v)) => {
                let enc = v.as_bytes().ok_or(CtapError::InvalidResponseShape(
                    "hmac-secret output is not a byte string",
                ))?;
                Some(session.decrypt_output(enc)?)
            }
        },
    };

    let (user_id, user_name) = match user {
        None => (None, None),
        Some(u) => {
            let map = u.as_map().ok_or(CtapError::InvalidResponseShape(
                "getAssertion user is not a map",
            ))?;
            let field = |name: &str| map.iter().find(|(k, _)| k.as_text() == Some(name));
            let id = field("id")
                .map(|(_, v)| {
                    v.as_bytes()
                        .map(<[u8]>::to_vec)
                        .ok_or(CtapError::InvalidResponseShape(
                            "getAssertion user ID is not a byte string",
                        ))
                })
                .transpose()?;
            let name = field("name")
                .map(|(_, v)| {
                    v.as_text()
                        .map(str::to_owned)
                        .ok_or(CtapError::InvalidResponseShape(
                            "getAssertion user name is not text",
                        ))
                })
                .transpose()?;
            (id, name)
        }
    };

    let number_of_credentials =
        count
            .map(|v| {
                v.as_uint().and_then(|n| u32::try_from(n).ok()).ok_or(
                    CtapError::InvalidResponseShape("numberOfCredentials is not a 32-bit count"),
                )
            })
            .transpose()?;

    Ok((
        credential_id,
        Assertion {
            credential_id: Vec::new(),
            user_id,
            user_name,
            hmac_output,
            large_blob_key,
            number_of_credentials,
        },
    ))
}

/// Check a request against the key's getInfo, so an unsupported request
/// fails with a clear message before the key is asked for a touch.
fn check_request(info: &AuthenticatorInfo, req: &GetAssertionRequest) -> Result<(), CtapError> {
    if let Some((token, protocol)) = req.pin_uv_auth {
        if token.protocol != protocol {
            return Err(CtapError::InvalidArgument(
                "the PIN/UV auth protocol does not match the token's",
            ));
        }
    }
    let has = |ext: &str| info.extensions.iter().any(|e| e == ext);
    if req.hmac.is_some() && !has(EXT_HMAC_SECRET) {
        return Err(CtapError::Unsupported(
            "this key does not support the hmac-secret extension",
        ));
    }
    if req.large_blob_key && (!has(EXT_LARGE_BLOB_KEY) || info.option("largeBlobs") != Some(true)) {
        return Err(CtapError::Unsupported(
            "this key does not support large-blob keys (largeBlobKey)",
        ));
    }
    Ok(())
}

/// Turn one getAssertion / getNextAssertion reply into a complete
/// [`Assertion`], checking the outputs the request asked for are there.
/// `first` marks the getAssertion reply, the one whose `0x2E` means "no
/// matching credential".
fn read_one(resp: &[u8], req: &GetAssertionRequest, first: bool) -> Result<Assertion, CtapError> {
    let (status, body) = split_status(resp)?;
    match status {
        0 => {}
        CTAP2_ERR_NO_CREDENTIALS if first => return Err(CtapError::NoCredentials),
        s => return Err(CtapError::StatusCode(s)),
    }
    let (credential_id, assertion) = parse_assertion(body, req.hmac.as_ref().map(|(s, _)| *s))?;
    // The key may leave the credential out when the allowList held exactly
    // one entry (CTAP 2.1 §6.2); keyroost only ever sends one.
    let credential_id = credential_id
        .or_else(|| req.allow.map(<[u8]>::to_vec))
        .ok_or(NO_CREDENTIAL)?;
    if req.large_blob_key && assertion.large_blob_key.is_none() {
        return Err(CtapError::InvalidResponseShape(
            "the key returned no largeBlobKey for an assertion",
        ));
    }
    if req.hmac.is_some() && assertion.hmac_output.is_none() {
        return Err(CtapError::InvalidResponseShape(
            "the key returned no hmac-secret output for an assertion",
        ));
    }
    Ok(Assertion {
        credential_id,
        ..assertion
    })
}

/// Issue `authenticatorGetAssertion`, then `authenticatorGetNextAssertion`
/// once for each further credential the first reply announces
/// (`numberOfCredentials - 1` times), and return every assertion in order.
///
/// getAssertion waits for a touch (unless `up` is false), so it runs under a
/// long timeout, restored afterwards; getNextAssertion needs no touch and
/// runs under the caller's timeout. Requests the key's getInfo says it cannot
/// honor are refused before anything is sent. A key with no matching
/// credential answers [`CtapError::NoCredentials`]. When the request asked
/// for `largeBlobKey` or `hmac-secret`, an assertion without that output is
/// an error.
pub fn get_assertions(
    dev: &mut impl CtapTransport,
    info: &AuthenticatorInfo,
    req: &GetAssertionRequest,
) -> Result<Vec<Assertion>, CtapError> {
    check_request(info, req)?;
    let mut payload = vec![CTAP2_GET_ASSERTION];
    payload.extend_from_slice(&encode_get_assertion(req));
    // The responses carry largeBlobKeys; wipe the raw buffers after.
    let resp = Zeroizing::new(with_timeout(dev, GET_ASSERTION_TIMEOUT, |d| {
        d.transact(CTAPHID_CBOR, &payload)
    })?);
    let first = read_one(&resp, req, true)?;

    let count = first.number_of_credentials.unwrap_or(1);
    if count == 0 || count > MAX_ASSERTIONS {
        return Err(CtapError::InvalidResponseShape(
            "numberOfCredentials is out of range",
        ));
    }
    let mut out = Vec::with_capacity(count as usize);
    out.push(first);
    for _ in 1..count {
        let resp = Zeroizing::new(dev.transact(CTAPHID_CBOR, &[CTAP2_GET_NEXT_ASSERTION])?);
        out.push(read_one(&resp, req, false)?);
    }
    Ok(out)
}

/// The vault name a keyroost vault credential carries in its user ID: a
/// `0x01` tag, 8 further bytes, then the name in UTF-8. Anything else
/// (another tag, no name, invalid UTF-8) is not a vault handle: `None`.
pub fn vault_name_from_user_id(id: &[u8]) -> Option<String> {
    if id.len() > 9 && id[0] == 0x01 {
        std::str::from_utf8(&id[9..]).ok().map(str::to_owned)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pin::{PinProtocol, ProtocolV1, SharedSecretV1, PIN_PROTOCOL_V1};
    use std::collections::VecDeque;

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

    fn v1_protocol() -> ProtocolV1 {
        ProtocolV1 {
            secret: SharedSecretV1([0x42; 32]),
        }
    }

    /// A v1 hmac-secret session over the shared secret 32 x 0x42, with a
    /// stand-in platform key `{1: 2}`.
    fn v1_session() -> HmacSecretSession {
        HmacSecretSession::for_test(
            Box::new(v1_protocol()),
            Value::Map(vec![(Value::UInt(1), Value::UInt(2))]),
        )
    }

    const SALT: [u8; 32] = [0x5a; 32];

    const USER_ID: &[u8] = &[
        0x01, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, b'v', b'a', b'u', b'l', b't',
    ];

    fn full_info() -> AuthenticatorInfo {
        AuthenticatorInfo {
            extensions: vec![EXT_HMAC_SECRET.into(), EXT_LARGE_BLOB_KEY.into()],
            options: vec![("largeBlobs".into(), true)],
            ..Default::default()
        }
    }

    fn vault_request<'a>(
        token: &'a PinUvAuthToken,
        session: &'a HmacSecretSession,
    ) -> GetAssertionRequest<'a> {
        GetAssertionRequest {
            client_data_hash: [0x11; 32],
            rp_id: "fido2-vault.token2",
            allow: Some(&[0xca, 0xfe]),
            hmac: Some((session, SALT)),
            large_blob_key: true,
            up: false,
            pin_uv_auth: Some((token, PIN_PROTOCOL_V1)),
        }
    }

    /// Written by hand from CTAP 2.1 §6.2 and §12.5. The AES and HMAC values
    /// were computed with an independent implementation (OpenSSL):
    /// - saltEnc = AES-256-CBC(key = 32 x 0x42, IV = 0, 32 x 0x5a)
    /// - saltAuth = HMAC-SHA-256(key = 32 x 0x42, saltEnc)[..16]
    /// - pinUvAuthParam = HMAC-SHA-256(key = 16 x 0x5a, 32 x 0x11)[..16]
    const EXPECTED_KAT: &str = concat!(
        "a7",
        // 1: rpId "fido2-vault.token2"
        "01 72 6669646f322d7661756c742e746f6b656e32",
        // 2: clientDataHash
        "02 5820 1111111111111111111111111111111111111111111111111111111111111111",
        // 3: allowList [{"id": h'cafe', "type": "public-key"}]
        "03 81 a2 626964 42 cafe 6474797065 6a 7075626c69632d6b6579",
        // 4: extensions {"hmac-secret": {1: {1: 2}, 2: saltEnc, 3: saltAuth},
        //                "largeBlobKey": true}
        "04 a2 6b 686d61632d736563726574 a3",
        "01 a1 0102",
        "02 5820 a95faacb949e1a813357e3b0f300dd0b56d0f4e29dd91fcb6cc1ea1266727823",
        "03 50 c58685e15118f9b41fa62393e080ff30",
        "6c 6c61726765426c6f624b6579 f5",
        // 5: options {"up": false}
        "05 a1 627570 f4",
        // 6: pinUvAuthParam
        "06 50 e2019a86620dd331caf307ac4dec120d",
        // 7: pinUvAuthProtocol
        "07 01",
    );

    #[test]
    fn encode_get_assertion_kat() {
        let token = v1_token();
        let session = v1_session();
        let encoded = encode_get_assertion(&vault_request(&token, &session));
        assert_eq!(encoded, unhex(EXPECTED_KAT));
    }

    #[test]
    fn encode_get_assertion_minimal() {
        // up = true sends no options; no allowList, extensions or PIN.
        let req = GetAssertionRequest {
            client_data_hash: [0x22; 32],
            rp_id: "a",
            allow: None,
            hmac: None,
            large_blob_key: false,
            up: true,
            pin_uv_auth: None,
        };
        let expected = unhex(concat!(
            "a2",
            "01 6161",
            "02 5820 2222222222222222222222222222222222222222222222222222222222222222",
        ));
        assert_eq!(encode_get_assertion(&req), expected);

        // largeBlobKey alone.
        let req = GetAssertionRequest {
            large_blob_key: true,
            ..req
        };
        let expected = unhex(concat!(
            "a3",
            "01 6161",
            "02 5820 2222222222222222222222222222222222222222222222222222222222222222",
            "04 a1 6c 6c61726765426c6f624b6579 f5",
        ));
        assert_eq!(encode_get_assertion(&req), expected);
    }

    /// AES-256-CBC(key = 32 x 0x42, IV = 0, 32 x 0x77), from OpenSSL: the
    /// encrypted hmac-secret output the simulated key returns.
    const HMAC_OUTPUT_ENC: &str =
        "3d9d5e38a5c2874bdf87dbe0923b23ab694c153cd41b5cb139539384f67e2603";

    /// Authenticator data without attested credential data; with `ext`, the
    /// ED flag is set and the map is appended.
    fn auth_data(ext: Option<Value>) -> Vec<u8> {
        let mut ad = vec![0xbb; 32];
        ad.push(crate::auth_data::FLAG_UP | if ext.is_some() { 0x80 } else { 0 });
        ad.extend_from_slice(&[0, 0, 0, 7]);
        if let Some(ext) = ext {
            ad.extend(cbor::encode(&ext));
        }
        ad
    }

    fn hmac_ext(enc: Vec<u8>) -> Value {
        Value::Map(vec![(text(EXT_HMAC_SECRET), Value::Bytes(enc))])
    }

    struct Resp {
        credential: Option<Vec<u8>>,
        hmac_enc: Option<Vec<u8>>,
        user: Option<Value>,
        count: Option<u64>,
        lbk: Option<Vec<u8>>,
    }

    fn user(id: &[u8], name: Option<&str>) -> Value {
        let mut entries = vec![(text("id"), Value::Bytes(id.to_vec()))];
        if let Some(name) = name {
            entries.push((text("name"), text(name)));
            entries.push((text("displayName"), text(name)));
        }
        Value::Map(entries)
    }

    fn vault_resp(cred: &[u8], name: &str, count: Option<u64>) -> Resp {
        let mut id = USER_ID[..9].to_vec();
        id.extend_from_slice(name.as_bytes());
        Resp {
            credential: Some(cred.to_vec()),
            hmac_enc: Some(unhex(HMAC_OUTPUT_ENC)),
            user: Some(user(&id, Some(name))),
            count,
            lbk: Some(vec![cred[0]; 32]),
        }
    }

    fn encode_resp(r: &Resp) -> Vec<u8> {
        let mut entries = Vec::new();
        if let Some(id) = &r.credential {
            entries.push((
                Value::UInt(1),
                Value::Map(vec![
                    (text("id"), Value::Bytes(id.clone())),
                    (text("type"), text("public-key")),
                ]),
            ));
        }
        entries.push((
            Value::UInt(2),
            Value::Bytes(auth_data(r.hmac_enc.clone().map(hmac_ext))),
        ));
        entries.push((Value::UInt(3), Value::Bytes(vec![0x30; 70])));
        if let Some(u) = &r.user {
            entries.push((Value::UInt(4), u.clone()));
        }
        if let Some(n) = r.count {
            entries.push((Value::UInt(5), Value::UInt(n)));
        }
        if let Some(k) = &r.lbk {
            entries.push((Value::UInt(7), Value::Bytes(k.clone())));
        }
        cbor::encode(&Value::Map(entries))
    }

    fn ok(body: Vec<u8>) -> Vec<u8> {
        let mut out = vec![0x00];
        out.extend(body);
        out
    }

    #[test]
    fn parse_reads_user_hmac_and_lbk() {
        let session = v1_session();
        let lbk: Vec<u8> = (0..32).collect();
        let resp = Resp {
            lbk: Some(lbk.clone()),
            ..vault_resp(&[0xca, 0xfe], "vault", Some(1))
        };
        let a = parse_get_assertion(&encode_resp(&resp), Some(&session)).unwrap();
        assert_eq!(a.credential_id, vec![0xca, 0xfe]);
        assert_eq!(a.user_id.as_deref(), Some(USER_ID));
        assert_eq!(a.user_name.as_deref(), Some("vault"));
        assert_eq!(a.hmac_output.as_deref(), Some(&[0x77u8; 32]));
        assert_eq!(a.large_blob_key.as_deref().map(|k| &k[..]), Some(&lbk[..]));
        assert_eq!(a.number_of_credentials, Some(1));
        assert_eq!(
            vault_name_from_user_id(a.user_id.as_deref().unwrap()).as_deref(),
            Some("vault")
        );
        // Secrets stay out of Debug.
        let dbg = format!("{a:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("119"), "{dbg}");

        // Without a session the hmac-secret output is left encrypted: absent.
        let a = parse_get_assertion(&encode_resp(&resp), None).unwrap();
        assert!(a.hmac_output.is_none());
    }

    #[test]
    fn parse_is_permissive_but_checks_shapes() {
        // Only credential and authData: everything else is None.
        let bare = Resp {
            credential: Some(vec![0x01]),
            hmac_enc: None,
            user: None,
            count: None,
            lbk: None,
        };
        let a = parse_get_assertion(&encode_resp(&bare), None).unwrap();
        assert_eq!(a.credential_id, vec![0x01]);
        assert!(a.user_id.is_none() && a.user_name.is_none());
        assert!(a.hmac_output.is_none() && a.large_blob_key.is_none());
        assert!(a.number_of_credentials.is_none());

        // A user with only an ID.
        let id_only = Resp {
            user: Some(user(&[0x09], None)),
            ..vault_resp(&[0x01], "x", None)
        };
        let a = parse_get_assertion(&encode_resp(&id_only), None).unwrap();
        assert_eq!(a.user_id, Some(vec![0x09]));
        assert!(a.user_name.is_none());

        let session = v1_session();
        let shape = |r: Resp| {
            matches!(
                parse_get_assertion(&encode_resp(&r), Some(&session)),
                Err(CtapError::InvalidResponseShape(_))
            )
        };
        // No credential descriptor (the public parser has no allowList to
        // fall back on).
        assert!(shape(Resp {
            credential: None,
            ..vault_resp(&[0x01], "x", None)
        }));
        // largeBlobKey of the wrong length.
        for bad in [vec![0u8; 31], vec![0u8; 33], vec![]] {
            assert!(shape(Resp {
                lbk: Some(bad),
                ..vault_resp(&[0x01], "x", None)
            }));
        }
        // hmac-secret output that does not decrypt to 32 bytes.
        assert!(shape(Resp {
            hmac_enc: Some(vec![0u8; 31]),
            ..vault_resp(&[0x01], "x", None)
        }));
        // numberOfCredentials beyond u32.
        assert!(shape(Resp {
            count: Some(u64::from(u32::MAX) + 1),
            ..vault_resp(&[0x01], "x", None)
        }));
        // user that is not a map.
        assert!(shape(Resp {
            user: Some(Value::UInt(3)),
            ..vault_resp(&[0x01], "x", None)
        }));

        // No authData, not a map, empty.
        let no_ad = cbor::encode(&Value::Map(vec![(
            Value::UInt(1),
            Value::Map(vec![(text("id"), Value::Bytes(vec![1]))]),
        )]));
        assert!(parse_get_assertion(&no_ad, None).is_err());
        assert!(parse_get_assertion(&[0x01], None).is_err());
        assert!(parse_get_assertion(&[], None).is_err());
    }

    #[test]
    fn unknown_user_handle_has_no_name() {
        // Not a keyroost vault handle: wrong tag, too short, empty name,
        // invalid UTF-8.
        assert_eq!(vault_name_from_user_id(&[]), None);
        assert_eq!(vault_name_from_user_id(&[0x01; 9]), None);
        assert_eq!(vault_name_from_user_id(&USER_ID[..9]), None);
        let mut other_tag = USER_ID.to_vec();
        other_tag[0] = 0x02;
        assert_eq!(vault_name_from_user_id(&other_tag), None);
        let mut bad_utf8 = USER_ID[..9].to_vec();
        bad_utf8.extend_from_slice(&[0xff, 0xfe]);
        assert_eq!(vault_name_from_user_id(&bad_utf8), None);
        // A random 32-byte handle from some other RP.
        assert_eq!(vault_name_from_user_id(&[0x9c; 32]), None);

        // Shortest valid: tag, 8 bytes, one name byte.
        let mut one = USER_ID[..9].to_vec();
        one.push(b'a');
        assert_eq!(vault_name_from_user_id(&one).as_deref(), Some("a"));
        assert_eq!(vault_name_from_user_id(USER_ID).as_deref(), Some("vault"));
    }

    /// Answers each transact with the next scripted response, recording the
    /// requests and the timeout in force when each was sent.
    struct ScriptedDevice {
        responses: VecDeque<Vec<u8>>,
        requests: Vec<(u8, Vec<u8>, Duration)>,
        timeout: Duration,
    }

    impl ScriptedDevice {
        fn new(responses: Vec<Vec<u8>>) -> Self {
            ScriptedDevice {
                responses: responses.into(),
                requests: Vec::new(),
                timeout: Duration::from_secs(3),
            }
        }
    }

    impl CtapTransport for ScriptedDevice {
        fn transact(&mut self, cmd: u8, payload: &[u8]) -> Result<Vec<u8>, CtapError> {
            self.requests.push((cmd, payload.to_vec(), self.timeout));
            self.responses
                .pop_front()
                .ok_or(CtapError::Transport("script exhausted".into()))
        }
        fn set_timeout(&mut self, timeout: Duration) {
            self.timeout = timeout;
        }
        fn read_timeout(&self) -> Duration {
            self.timeout
        }
    }

    #[test]
    fn next_assertions_collected() {
        let token = v1_token();
        let session = v1_session();
        let req = GetAssertionRequest {
            allow: None,
            ..vault_request(&token, &session)
        };
        let mut dev = ScriptedDevice::new(vec![
            ok(encode_resp(&vault_resp(&[0x01], "one", Some(3)))),
            ok(encode_resp(&vault_resp(&[0x02], "two", None))),
            ok(encode_resp(&vault_resp(&[0x03], "three", None))),
        ]);
        let got = get_assertions(&mut dev, &full_info(), &req).unwrap();

        assert_eq!(got.len(), 3);
        let names: Vec<_> = got
            .iter()
            .map(|a| vault_name_from_user_id(a.user_id.as_deref().unwrap()).unwrap())
            .collect();
        assert_eq!(names, ["one", "two", "three"]);
        for (i, a) in got.iter().enumerate() {
            assert_eq!(a.credential_id, vec![i as u8 + 1]);
            // One session decrypts every output in the batch.
            assert_eq!(a.hmac_output.as_deref(), Some(&[0x77u8; 32]));
            assert_eq!(
                a.large_blob_key.as_deref(),
                Some(&[i as u8 + 1; 32]),
                "assertion {i}"
            );
        }
        assert_eq!(got[0].number_of_credentials, Some(3));

        // getAssertion once under the touch window, then getNextAssertion
        // twice (empty payload) under the caller's timeout.
        assert_eq!(dev.requests.len(), 3);
        let (cmd, payload, timeout) = &dev.requests[0];
        assert_eq!(*cmd, CTAPHID_CBOR);
        assert_eq!(payload[0], CTAP2_GET_ASSERTION);
        assert_eq!(&payload[1..], &encode_get_assertion(&req)[..]);
        assert_eq!(*timeout, GET_ASSERTION_TIMEOUT);
        for (cmd, payload, timeout) in &dev.requests[1..] {
            assert_eq!(*cmd, CTAPHID_CBOR);
            assert_eq!(payload, &[CTAP2_GET_NEXT_ASSERTION]);
            assert_eq!(*timeout, Duration::from_secs(3));
        }
        assert_eq!(dev.timeout, Duration::from_secs(3), "timeout restored");
    }

    #[test]
    fn single_assertion_when_count_absent_or_one() {
        let token = v1_token();
        let session = v1_session();
        let req = vault_request(&token, &session);
        for count in [None, Some(1)] {
            let mut dev =
                ScriptedDevice::new(vec![ok(encode_resp(&vault_resp(&[0xca], "v", count)))]);
            let got = get_assertions(&mut dev, &full_info(), &req).unwrap();
            assert_eq!(got.len(), 1);
            assert_eq!(dev.requests.len(), 1);
        }
    }

    #[test]
    fn credential_falls_back_to_the_allow_list_entry() {
        // CTAP 2.1 §6.2: the credential may be omitted when the allowList
        // held exactly one entry.
        let token = v1_token();
        let session = v1_session();
        let req = vault_request(&token, &session);
        let resp = Resp {
            credential: None,
            ..vault_resp(&[0x01], "v", None)
        };
        let mut dev = ScriptedDevice::new(vec![ok(encode_resp(&resp))]);
        let got = get_assertions(&mut dev, &full_info(), &req).unwrap();
        assert_eq!(got[0].credential_id, vec![0xca, 0xfe]);

        // Without an allowList there is nothing to fall back on.
        let req = GetAssertionRequest { allow: None, ..req };
        let mut dev = ScriptedDevice::new(vec![ok(encode_resp(&resp))]);
        assert!(matches!(
            get_assertions(&mut dev, &full_info(), &req),
            Err(CtapError::InvalidResponseShape(_))
        ));
    }

    #[test]
    fn missing_requested_outputs_are_refused() {
        let token = v1_token();
        let session = v1_session();
        let req = vault_request(&token, &session);
        let cases = [
            Resp {
                lbk: None,
                ..vault_resp(&[0x01], "v", None)
            },
            Resp {
                hmac_enc: None,
                ..vault_resp(&[0x01], "v", None)
            },
        ];
        for resp in cases {
            let mut dev = ScriptedDevice::new(vec![ok(encode_resp(&resp))]);
            assert!(matches!(
                get_assertions(&mut dev, &full_info(), &req),
                Err(CtapError::InvalidResponseShape(_))
            ));
        }
        // A later assertion of the batch lacking its largeBlobKey fails the
        // whole call too.
        let mut dev = ScriptedDevice::new(vec![
            ok(encode_resp(&vault_resp(&[0x01], "one", Some(2)))),
            ok(encode_resp(&Resp {
                lbk: None,
                ..vault_resp(&[0x02], "two", None)
            })),
        ]);
        assert!(matches!(
            get_assertions(&mut dev, &full_info(), &req),
            Err(CtapError::InvalidResponseShape(_))
        ));

        // Not asked for: their absence is fine.
        let plain = GetAssertionRequest {
            hmac: None,
            large_blob_key: false,
            ..vault_request(&token, &session)
        };
        let resp = Resp {
            hmac_enc: None,
            lbk: None,
            ..vault_resp(&[0x01], "v", None)
        };
        let mut dev = ScriptedDevice::new(vec![ok(encode_resp(&resp))]);
        assert_eq!(
            get_assertions(&mut dev, &full_info(), &plain)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn implausible_credential_counts_are_refused() {
        let token = v1_token();
        let session = v1_session();
        let req = vault_request(&token, &session);
        for count in [0, u64::from(MAX_ASSERTIONS) + 1] {
            let mut dev = ScriptedDevice::new(vec![ok(encode_resp(&vault_resp(
                &[0x01],
                "v",
                Some(count),
            )))]);
            assert!(matches!(
                get_assertions(&mut dev, &full_info(), &req),
                Err(CtapError::InvalidResponseShape(_))
            ));
            assert_eq!(dev.requests.len(), 1, "no getNextAssertion sent");
        }
    }

    #[test]
    fn no_credentials_maps_to_typed_error() {
        let token = v1_token();
        let session = v1_session();
        let req = vault_request(&token, &session);
        let mut dev = ScriptedDevice::new(vec![vec![0x2e]]);
        let err = get_assertions(&mut dev, &full_info(), &req).unwrap_err();
        assert!(matches!(err, CtapError::NoCredentials), "{err:?}");
        assert_eq!(err.to_string(), "this key holds no matching credential");

        // Other statuses stay raw.
        let mut dev = ScriptedDevice::new(vec![vec![0x2f]]);
        let err = get_assertions(&mut dev, &full_info(), &req).unwrap_err();
        assert!(matches!(err, CtapError::StatusCode(0x2f)));
        // A failing getNextAssertion fails the call.
        let mut dev = ScriptedDevice::new(vec![
            ok(encode_resp(&vault_resp(&[0x01], "one", Some(2)))),
            vec![0x30],
        ]);
        let err = get_assertions(&mut dev, &full_info(), &req).unwrap_err();
        assert!(matches!(err, CtapError::StatusCode(0x30)));
        let mut dev = ScriptedDevice::new(vec![vec![]]);
        let err = get_assertions(&mut dev, &full_info(), &req).unwrap_err();
        assert!(matches!(err, CtapError::EmptyResponse));
    }

    #[test]
    fn get_assertions_refuses_what_the_key_lacks_before_sending() {
        let token = v1_token();
        let session = v1_session();
        let without_ext = |drop: &str| {
            let mut info = full_info();
            info.extensions.retain(|e| e != drop);
            info
        };
        let cases = [
            without_ext(EXT_HMAC_SECRET),
            without_ext(EXT_LARGE_BLOB_KEY),
            AuthenticatorInfo {
                options: vec![("largeBlobs".into(), false)],
                ..full_info()
            },
            AuthenticatorInfo {
                options: vec![],
                ..full_info()
            },
        ];
        for info in cases {
            let mut dev = ScriptedDevice::new(vec![]);
            let err =
                get_assertions(&mut dev, &info, &vault_request(&token, &session)).unwrap_err();
            assert!(matches!(err, CtapError::Unsupported(_)), "{err:?}");
            assert!(dev.requests.is_empty());
        }

        // A PIN protocol that does not match the token's.
        let req = GetAssertionRequest {
            pin_uv_auth: Some((&token, 2)),
            ..vault_request(&token, &session)
        };
        let mut dev = ScriptedDevice::new(vec![]);
        let err = get_assertions(&mut dev, &full_info(), &req).unwrap_err();
        assert!(matches!(err, CtapError::InvalidArgument(_)), "{err:?}");
        assert!(dev.requests.is_empty());
    }

    #[test]
    fn hmac_output_kat_is_independent() {
        // Guard the fixture itself: the OpenSSL ciphertext decrypts with the
        // crate's protocol v1 to the expected plaintext.
        assert_eq!(
            v1_protocol().decrypt(&unhex(HMAC_OUTPUT_ENC)).unwrap(),
            vec![0x77; 32]
        );
    }
}
