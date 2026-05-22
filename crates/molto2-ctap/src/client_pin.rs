//! High-level CTAP2 `clientPin` (0x06) commands.
//!
//! Each public function runs the full request-response cycle and returns a
//! typed result. The PIN protocol crypto (ECDH, AES, HMAC) lives in
//! [`crate::pin`]; this module is the glue between those primitives and
//! the CBOR wire format.
//!
//! Only PIN protocol v1 is wired in for now — every authenticator on the
//! market supports it, and that's enough to set/change PINs and obtain the
//! pinUvAuthToken that Phase 2's credentialManagement work needs.
//! Protocol v2 lives in [`crate::pin`] already and gets wired through here
//! when the first device demands it.

use crate::cbor::{self, Value};
use crate::cmd::CtapError;
use crate::hid::{CtapHidDevice, CTAPHID_CBOR};
use crate::pin::{
    left16_sha256, pad_pin_to_64, EphemeralKey, PinProtocol, ProtocolV1, SharedSecretV1,
    PIN_PROTOCOL_V1,
};

pub const CTAP2_CLIENT_PIN: u8 = 0x06;

/// `clientPin` request map keys.
const KEY_PIN_PROTOCOL: u64 = 0x01;
const KEY_SUB_COMMAND: u64 = 0x02;
const KEY_KEY_AGREEMENT: u64 = 0x03;
const KEY_PIN_UV_AUTH_PARAM: u64 = 0x04;
const KEY_NEW_PIN_ENC: u64 = 0x05;
const KEY_PIN_HASH_ENC: u64 = 0x06;

/// `clientPin` sub-command numbers.
const SUB_GET_PIN_RETRIES: u8 = 0x01;
const SUB_GET_KEY_AGREEMENT: u8 = 0x02;
const SUB_SET_PIN: u8 = 0x03;
const SUB_CHANGE_PIN: u8 = 0x04;
const SUB_GET_PIN_TOKEN: u8 = 0x05;

/// COSE_Key map keys for an EC2 P-256 public key.
const COSE_KTY: i64 = 1;
const COSE_ALG: i64 = 3;
const COSE_CRV: i64 = -1;
const COSE_X: i64 = -2;
const COSE_Y: i64 = -3;
const COSE_KTY_EC2: u64 = 2;
const COSE_ALG_ECDH_ES_HKDF_256: i64 = -25;
const COSE_CRV_P256: u64 = 1;

/// PIN-related response, decoded into the fields callers actually care about.
#[derive(Debug, Clone, Default)]
pub struct PinResponse {
    /// Number of PIN attempts remaining before the authenticator locks out
    /// (3..=8 typically, varies by vendor).
    pub retries: Option<u32>,
    /// Authenticator's P-256 public key, from `getKeyAgreement`.
    pub key_agreement: Option<([u8; 32], [u8; 32])>,
    /// Encrypted pinUvAuthToken returned by `getPinToken`.
    pub pin_token_enc: Option<Vec<u8>>,
}

/// PIN/UV auth token obtained from `getPinToken`. The token itself is
/// opaque (16 or 32 random bytes); the bundled shared secret remembers the
/// HMAC key callers need to authenticate later requests.
pub struct PinUvAuthToken {
    pub protocol: u32,
    pub token: Vec<u8>,
    /// HMAC key for authenticating subsequent CTAP commands. For v1 this is
    /// the token itself; for v2 it's derived per-protocol.
    pub hmac_key: Vec<u8>,
}

impl PinUvAuthToken {
    /// `LEFT(HMAC-SHA-256(hmac_key, data), 16)` — the tag CTAP expects on
    /// every request that requires PIN/UV auth.
    pub fn authenticate(&self, data: &[u8]) -> Vec<u8> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.hmac_key)
            .expect("HMAC accepts any key length");
        mac.update(data);
        let full = mac.finalize().into_bytes();
        if self.protocol == PIN_PROTOCOL_V1 {
            full[..16].to_vec()
        } else {
            full.to_vec()
        }
    }
}

/// Read the current PIN retry counter. No auth required.
pub fn get_pin_retries(dev: &mut CtapHidDevice) -> Result<u32, CtapError> {
    let req = build_request(PIN_PROTOCOL_V1, SUB_GET_PIN_RETRIES, &[]);
    let resp = dispatch(dev, &req)?;
    resp.retries
        .ok_or(CtapError::InvalidResponseShape("missing retries"))
}

/// Fetch the authenticator's ephemeral P-256 public key for ECDH.
pub fn get_key_agreement(
    dev: &mut CtapHidDevice,
) -> Result<([u8; 32], [u8; 32]), CtapError> {
    let req = build_request(PIN_PROTOCOL_V1, SUB_GET_KEY_AGREEMENT, &[]);
    let resp = dispatch(dev, &req)?;
    resp.key_agreement
        .ok_or(CtapError::InvalidResponseShape("missing keyAgreement"))
}

/// Set the initial PIN on an authenticator that doesn't have one yet.
pub fn set_pin(dev: &mut CtapHidDevice, new_pin: &str) -> Result<(), CtapError> {
    validate_pin(new_pin)?;
    let (proto, peer) = key_agreement_v1(dev)?;
    let our_pub = peer.our_public_cose();
    let new_pin_enc = proto.encrypt(&pad_pin_to_64(new_pin));
    let pin_auth = proto.authenticate(&new_pin_enc);

    let extra = vec![
        (Value::UInt(KEY_KEY_AGREEMENT), our_pub),
        (Value::UInt(KEY_PIN_UV_AUTH_PARAM), Value::Bytes(pin_auth)),
        (Value::UInt(KEY_NEW_PIN_ENC), Value::Bytes(new_pin_enc)),
    ];
    let req = build_request_extra(PIN_PROTOCOL_V1, SUB_SET_PIN, &extra);
    dispatch(dev, &req)?;
    Ok(())
}

/// Change an existing PIN.
pub fn change_pin(
    dev: &mut CtapHidDevice,
    old_pin: &str,
    new_pin: &str,
) -> Result<(), CtapError> {
    validate_pin(new_pin)?;
    let (proto, peer) = key_agreement_v1(dev)?;
    let our_pub = peer.our_public_cose();
    let new_pin_enc = proto.encrypt(&pad_pin_to_64(new_pin));
    let pin_hash_enc = proto.encrypt(&left16_sha256(old_pin.as_bytes()));
    let mut auth_input = Vec::with_capacity(new_pin_enc.len() + pin_hash_enc.len());
    auth_input.extend_from_slice(&new_pin_enc);
    auth_input.extend_from_slice(&pin_hash_enc);
    let pin_auth = proto.authenticate(&auth_input);

    let extra = vec![
        (Value::UInt(KEY_KEY_AGREEMENT), our_pub),
        (Value::UInt(KEY_PIN_UV_AUTH_PARAM), Value::Bytes(pin_auth)),
        (Value::UInt(KEY_NEW_PIN_ENC), Value::Bytes(new_pin_enc)),
        (Value::UInt(KEY_PIN_HASH_ENC), Value::Bytes(pin_hash_enc)),
    ];
    let req = build_request_extra(PIN_PROTOCOL_V1, SUB_CHANGE_PIN, &extra);
    dispatch(dev, &req)?;
    Ok(())
}

/// Obtain a pinUvAuthToken bound to the current PIN. The returned token is
/// usable as an HMAC key for credential management and similar commands
/// until the authenticator power-cycles.
pub fn get_pin_token(
    dev: &mut CtapHidDevice,
    pin: &str,
) -> Result<PinUvAuthToken, CtapError> {
    let (proto, peer) = key_agreement_v1(dev)?;
    let our_pub = peer.our_public_cose();
    let pin_hash_enc = proto.encrypt(&left16_sha256(pin.as_bytes()));

    let extra = vec![
        (Value::UInt(KEY_KEY_AGREEMENT), our_pub),
        (Value::UInt(KEY_PIN_HASH_ENC), Value::Bytes(pin_hash_enc)),
    ];
    let req = build_request_extra(PIN_PROTOCOL_V1, SUB_GET_PIN_TOKEN, &extra);
    let resp = dispatch(dev, &req)?;
    let enc_token = resp
        .pin_token_enc
        .ok_or(CtapError::InvalidResponseShape("missing pinToken"))?;
    let token = proto
        .decrypt(&enc_token)
        .map_err(|_| CtapError::InvalidResponseShape("pinToken decrypt failed"))?;
    Ok(PinUvAuthToken {
        protocol: PIN_PROTOCOL_V1,
        hmac_key: token.clone(),
        token,
    })
}

/// Bundle of negotiated v1 state used by every subsequent sub-command.
struct PeerKey {
    /// Authenticator's public key — we keep this so we can echo it as the
    /// `keyAgreement` parameter (CTAP echoes the host's, not the peer's).
    our_x: [u8; 32],
    our_y: [u8; 32],
}

impl PeerKey {
    fn our_public_cose(&self) -> Value {
        cose_p256_public(&self.our_x, &self.our_y)
    }
}

fn key_agreement_v1(dev: &mut CtapHidDevice) -> Result<(ProtocolV1, PeerKey), CtapError> {
    let (peer_x, peer_y) = get_key_agreement(dev)?;
    let our = EphemeralKey::generate();
    let (our_x, our_y) = our.public_xy();
    let SharedSecretV1(secret) = our
        .shared_secret_v1(&peer_x, &peer_y)
        .map_err(|_| CtapError::InvalidResponseShape("invalid peer keyAgreement point"))?;
    Ok((
        ProtocolV1 {
            secret: SharedSecretV1(secret),
        },
        PeerKey { our_x, our_y },
    ))
}

fn validate_pin(pin: &str) -> Result<(), CtapError> {
    let n = pin.len();
    if !(4..=63).contains(&n) {
        return Err(CtapError::InvalidResponseShape(
            "PIN must be 4..=63 UTF-8 bytes",
        ));
    }
    Ok(())
}

/// CBOR-encode the `clientPin` request and dispatch it.
fn dispatch(dev: &mut CtapHidDevice, req: &[u8]) -> Result<PinResponse, CtapError> {
    let mut payload = Vec::with_capacity(req.len() + 1);
    payload.push(CTAP2_CLIENT_PIN);
    payload.extend_from_slice(req);
    let resp = dev.transact(CTAPHID_CBOR, &payload)?;
    let (status, body) = resp
        .split_first()
        .ok_or(CtapError::EmptyResponse)?;
    if *status != 0 {
        return Err(CtapError::StatusCode(*status));
    }
    if body.is_empty() {
        // Some sub-commands (setPin, changePin) return no payload on success.
        return Ok(PinResponse::default());
    }
    let (value, _) = cbor::decode(body)?;
    parse_pin_response(&value)
}

fn build_request(protocol: u32, sub: u8, extra: &[(Value, Value)]) -> Vec<u8> {
    build_request_extra(protocol, sub, extra)
}

fn build_request_extra(protocol: u32, sub: u8, extra: &[(Value, Value)]) -> Vec<u8> {
    let mut entries = Vec::with_capacity(2 + extra.len());
    entries.push((Value::UInt(KEY_PIN_PROTOCOL), Value::UInt(protocol as u64)));
    entries.push((Value::UInt(KEY_SUB_COMMAND), Value::UInt(sub as u64)));
    entries.extend_from_slice(extra);
    cbor::encode(&Value::Map(entries))
}

fn cose_p256_public(x: &[u8; 32], y: &[u8; 32]) -> Value {
    // COSE_Key for ECDH-ES + HKDF-256, EC2 / P-256.
    Value::Map(vec![
        (n(COSE_KTY), Value::UInt(COSE_KTY_EC2)),
        (n(COSE_ALG), n(COSE_ALG_ECDH_ES_HKDF_256)),
        (n(COSE_CRV), Value::UInt(COSE_CRV_P256)),
        (n(COSE_X), Value::Bytes(x.to_vec())),
        (n(COSE_Y), Value::Bytes(y.to_vec())),
    ])
}

/// Helper: encode a (possibly negative) CBOR integer as `UInt` or `NInt`.
fn n(v: i64) -> Value {
    if v >= 0 {
        Value::UInt(v as u64)
    } else {
        Value::NInt(((-1) - v) as u64)
    }
}

fn parse_pin_response(v: &Value) -> Result<PinResponse, CtapError> {
    let map = v
        .as_map()
        .ok_or(CtapError::InvalidResponseShape("expected map"))?;
    let mut out = PinResponse::default();
    for (k, val) in map {
        let Some(key) = k.as_uint() else { continue };
        match key {
            // keyAgreement (authenticator's public key) — same COSE shape we send.
            0x01 => {
                if let Some(m) = val.as_map() {
                    let mut x = None;
                    let mut y = None;
                    for (kk, vv) in m {
                        let Some(kn) = kk.as_uint().map(|u| u as i64).or_else(|| {
                            if let Value::NInt(n) = kk {
                                Some(-1 - *n as i64)
                            } else {
                                None
                            }
                        }) else {
                            continue;
                        };
                        match kn {
                            COSE_X => {
                                if let Some(b) = vv.as_bytes() {
                                    if b.len() == 32 {
                                        let mut a = [0u8; 32];
                                        a.copy_from_slice(b);
                                        x = Some(a);
                                    }
                                }
                            }
                            COSE_Y => {
                                if let Some(b) = vv.as_bytes() {
                                    if b.len() == 32 {
                                        let mut a = [0u8; 32];
                                        a.copy_from_slice(b);
                                        y = Some(a);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    if let (Some(x), Some(y)) = (x, y) {
                        out.key_agreement = Some((x, y));
                    }
                }
            }
            // pinUvAuthToken (encrypted, decrypted by caller)
            0x02 => {
                if let Some(b) = val.as_bytes() {
                    out.pin_token_enc = Some(b.to_vec());
                }
            }
            // pinRetries
            0x03 => {
                out.retries = val.as_uint().map(|n| n as u32);
            }
            _ => {}
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_carries_protocol_and_subcommand() {
        let bytes = build_request(PIN_PROTOCOL_V1, SUB_GET_PIN_RETRIES, &[]);
        let (val, _) = cbor::decode(&bytes).unwrap();
        let map = val.as_map().unwrap();
        assert_eq!(map.len(), 2);
        assert_eq!(map[0].0.as_uint(), Some(KEY_PIN_PROTOCOL));
        assert_eq!(map[0].1.as_uint(), Some(1));
        assert_eq!(map[1].0.as_uint(), Some(KEY_SUB_COMMAND));
        assert_eq!(map[1].1.as_uint(), Some(SUB_GET_PIN_RETRIES as u64));
    }

    #[test]
    fn cose_key_round_trips_back_to_xy() {
        let x = [0x11u8; 32];
        let y = [0x22u8; 32];
        let v = cose_p256_public(&x, &y);
        let bytes = cbor::encode(&v);
        let (decoded, _) = cbor::decode(&bytes).unwrap();
        // The keyAgreement parser in parse_pin_response expects the same
        // shape under map key 0x01, so wrap and re-parse.
        let wrapped = Value::Map(vec![(Value::UInt(1), decoded)]);
        let parsed = parse_pin_response(&wrapped).unwrap();
        assert_eq!(parsed.key_agreement, Some((x, y)));
    }

    #[test]
    fn parse_get_pin_retries_response() {
        let resp = Value::Map(vec![(Value::UInt(0x03), Value::UInt(7))]);
        let p = parse_pin_response(&resp).unwrap();
        assert_eq!(p.retries, Some(7));
    }

    #[test]
    fn parse_get_pin_token_response() {
        let resp = Value::Map(vec![(
            Value::UInt(0x02),
            Value::Bytes(vec![0xAA, 0xBB, 0xCC, 0xDD]),
        )]);
        let p = parse_pin_response(&resp).unwrap();
        assert_eq!(p.pin_token_enc.as_deref(), Some(&[0xAA, 0xBB, 0xCC, 0xDD][..]));
    }

    #[test]
    fn validate_pin_rejects_too_short_or_too_long() {
        assert!(validate_pin("123").is_err());
        assert!(validate_pin("1234").is_ok());
        assert!(validate_pin(&"x".repeat(63)).is_ok());
        assert!(validate_pin(&"x".repeat(64)).is_err());
    }

    #[test]
    fn auth_token_v1_truncates_to_16() {
        let t = PinUvAuthToken {
            protocol: PIN_PROTOCOL_V1,
            token: vec![0u8; 16],
            hmac_key: vec![0u8; 16],
        };
        assert_eq!(t.authenticate(b"hello").len(), 16);
    }
}
