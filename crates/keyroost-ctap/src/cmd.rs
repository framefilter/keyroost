//! High-level CTAP2 commands.
//!
//! Phase 1 covers only `authenticatorGetInfo` (0x04) and
//! `authenticatorReset` (0x07). Credential management, makeCredential,
//! getAssertion, and PIN/UV protocols come in later phases.

use std::time::Duration;

use crate::cbor::{self, Value};
use crate::hid::{CtapHidDevice, HidTransportError, CTAPHID_CBOR};

pub const CTAP2_GET_INFO: u8 = 0x04;
pub const CTAP2_RESET: u8 = 0x07;

/// Reset has to land within ~10s of plug-in on most authenticators and
/// always requires a touch — so we wait considerably longer than a normal
/// CTAP transaction.
const RESET_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub enum CtapError {
    Hid(HidTransportError),
    Cbor(cbor::CborError),
    /// CTAP2 status byte in the response was non-zero. See the FIDO CTAP
    /// spec section "Authenticator API Response Codes" for meanings; the
    /// commonest cases are `0x30` (CTAP2_ERR_NOT_ALLOWED — e.g. reset
    /// outside the touch window) and `0x2F` (CTAP2_ERR_USER_ACTION_TIMEOUT).
    StatusCode(u8),
    EmptyResponse,
    InvalidResponseShape(&'static str),
    /// A caller-supplied argument was rejected before anything was sent to
    /// the device (e.g. a PIN outside the 4–63 byte range).
    InvalidArgument(&'static str),
}

impl std::fmt::Display for CtapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CtapError::Hid(e) => write!(f, "{}", e),
            CtapError::Cbor(e) => write!(f, "{}", e),
            CtapError::StatusCode(c) => match (ctap_status_hint(*c), ctap_status_name(*c)) {
                // Lead with a plain-English explanation when we have one, keeping
                // the spec name + hex for the technically inclined.
                (Some(hint), Some(name)) => {
                    write!(f, "{} (CTAP2 status 0x{:02X} {})", hint, c, name)
                }
                (Some(hint), None) => {
                    write!(f, "{} (CTAP2 status 0x{:02X})", hint, c)
                }
                (None, Some(name)) => write!(
                    f,
                    "authenticator returned CTAP2 status 0x{:02X} ({})",
                    c, name
                ),
                (None, None) => write!(f, "authenticator returned CTAP2 status 0x{:02X}", c),
            },
            CtapError::EmptyResponse => write!(f, "authenticator returned an empty CBOR response"),
            CtapError::InvalidResponseShape(s) => {
                write!(f, "authenticator response had wrong shape: {}", s)
            }
            CtapError::InvalidArgument(s) => write!(f, "invalid argument: {}", s),
        }
    }
}

/// Plain-English explanation for the CTAP2 status codes a user is most likely
/// to hit and least likely to understand from the spec name alone. Returns
/// `None` when the spec name is already clear enough (or the code is unknown),
/// in which case the caller falls back to the spec name / raw hex.
fn ctap_status_hint(code: u8) -> Option<&'static str> {
    Some(match code {
        // The big one for Token2 PIN+ keys: the new PIN doesn't meet the key's
        // complexity policy (length / character mix), not a transient failure.
        0x37 => {
            "the new PIN doesn't meet this key's complexity requirements \u{2014} \
                 try a longer PIN or a different mix of characters (Token2 PIN+ \
                 keys enforce a complexity policy)"
        }
        0x31 => "the PIN was incorrect",
        0x32 => {
            "too many wrong PIN attempts \u{2014} the key is locked; remove and \
                 re-insert it, and note it may reset after repeated failures"
        }
        0x33 => "the PIN authentication was rejected; unlock again and retry",
        0x34 => "too many PIN retries this session \u{2014} remove and re-insert the key",
        0x35 => "no PIN is set on this key yet",
        0x36 => "this operation needs a fresh PIN/UV authentication first",
        0x3B => "the key needs a physical touch to continue",
        0x3C => "user verification is temporarily blocked \u{2014} remove and re-insert the key",
        0x2F => "timed out waiting for you to act on the key",
        _ => return None,
    })
}

/// Map the CTAP2 status bytes we're most likely to surface to their spec
/// names. Not exhaustive — covers the PIN / credentialManagement domain plus
/// the common generic errors. Returns `None` for unknown codes so the caller
/// can still print the raw hex.
fn ctap_status_name(code: u8) -> Option<&'static str> {
    Some(match code {
        0x00 => "CTAP2_OK",
        0x11 => "CTAP2_ERR_CBOR_UNEXPECTED_TYPE",
        0x12 => "CTAP2_ERR_INVALID_CBOR",
        0x14 => "CTAP2_ERR_MISSING_PARAMETER",
        0x19 => "CTAP2_ERR_CREDENTIAL_EXCLUDED",
        0x2B => "CTAP2_ERR_UNSUPPORTED_OPTION",
        0x2C => "CTAP2_ERR_INVALID_OPTION",
        0x2D => "CTAP2_ERR_KEEPALIVE_CANCEL",
        0x2E => "CTAP2_ERR_NO_CREDENTIALS",
        0x2F => "CTAP2_ERR_USER_ACTION_TIMEOUT",
        0x30 => "CTAP2_ERR_NOT_ALLOWED",
        0x31 => "CTAP2_ERR_PIN_INVALID",
        0x32 => "CTAP2_ERR_PIN_BLOCKED",
        0x33 => "CTAP2_ERR_PIN_AUTH_INVALID",
        0x34 => "CTAP2_ERR_PIN_AUTH_BLOCKED",
        0x35 => "CTAP2_ERR_PIN_NOT_SET",
        0x36 => "CTAP2_ERR_PUAT_REQUIRED",
        0x37 => "CTAP2_ERR_PIN_POLICY_VIOLATION",
        0x39 => "CTAP2_ERR_REQUEST_TOO_LARGE",
        0x3A => "CTAP2_ERR_ACTION_TIMEOUT",
        0x3B => "CTAP2_ERR_UP_REQUIRED",
        0x3C => "CTAP2_ERR_UV_BLOCKED",
        0x3F => "CTAP2_ERR_INTEGRITY_FAILURE",
        _ => return None,
    })
}

impl std::error::Error for CtapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CtapError::Hid(e) => Some(e),
            CtapError::Cbor(e) => Some(e),
            _ => None,
        }
    }
}

impl From<HidTransportError> for CtapError {
    fn from(e: HidTransportError) -> Self {
        CtapError::Hid(e)
    }
}

impl From<cbor::CborError> for CtapError {
    fn from(e: cbor::CborError) -> Self {
        CtapError::Cbor(e)
    }
}

/// Decoded `authenticatorGetInfo` response. Fields cover the keys that
/// matter for Phase 1's "show what's there" GUI; other keys (algorithms,
/// uvModality, etc.) are added on demand.
#[derive(Debug, Clone, Default)]
pub struct AuthenticatorInfo {
    pub versions: Vec<String>,
    pub extensions: Vec<String>,
    pub aaguid: [u8; 16],
    pub options: Vec<(String, bool)>,
    pub max_msg_size: Option<u64>,
    pub pin_uv_auth_protocols: Vec<u64>,
    pub max_credential_count_in_list: Option<u64>,
    pub max_credential_id_length: Option<u64>,
    pub transports: Vec<String>,
    pub firmware_version: Option<u64>,
}

impl AuthenticatorInfo {
    /// Look up a named option flag — e.g. `"rk"` (resident keys),
    /// `"clientPin"`, `"up"`, `"uv"`. Returns `None` when the authenticator
    /// did not advertise the option.
    pub fn option(&self, name: &str) -> Option<bool> {
        self.options
            .iter()
            .find_map(|(k, v)| if k == name { Some(*v) } else { None })
    }
}

/// Issue `authenticatorGetInfo` and decode the response.
pub fn get_info(dev: &mut CtapHidDevice) -> Result<AuthenticatorInfo, CtapError> {
    let resp = dev.transact(CTAPHID_CBOR, &[CTAP2_GET_INFO])?;
    let (status, body) = split_status(&resp)?;
    if status != 0 {
        return Err(CtapError::StatusCode(status));
    }
    let (value, _) = cbor::decode(body)?;
    parse_authenticator_info(&value)
}

/// Issue `authenticatorReset`. Most authenticators require this within ~10
/// seconds of plug-in *and* a physical touch — failures with status 0x2D
/// usually mean the touch window has closed.
pub fn reset(dev: &mut CtapHidDevice) -> Result<(), CtapError> {
    dev.set_timeout(RESET_TIMEOUT);
    let resp = dev.transact(CTAPHID_CBOR, &[CTAP2_RESET])?;
    let (status, _) = split_status(&resp)?;
    if status != 0 {
        return Err(CtapError::StatusCode(status));
    }
    Ok(())
}

fn split_status(resp: &[u8]) -> Result<(u8, &[u8]), CtapError> {
    resp.split_first()
        .map(|(s, rest)| (*s, rest))
        .ok_or(CtapError::EmptyResponse)
}

/// Parse a decoded `authenticatorGetInfo` CBOR map. Public so the fuzz
/// harness can drive it with arbitrary device bytes.
pub fn parse_authenticator_info(v: &Value) -> Result<AuthenticatorInfo, CtapError> {
    let map = v
        .as_map()
        .ok_or(CtapError::InvalidResponseShape("expected map at top level"))?;
    let mut info = AuthenticatorInfo::default();
    for (k, val) in map {
        let Some(key) = k.as_uint() else { continue };
        match key {
            0x01 => info.versions = collect_strings(val),
            0x02 => info.extensions = collect_strings(val),
            0x03 => {
                if let Some(b) = val.as_bytes() {
                    if b.len() == 16 {
                        info.aaguid.copy_from_slice(b);
                    }
                }
            }
            0x04 => info.options = collect_named_bools(val),
            0x05 => info.max_msg_size = val.as_uint(),
            0x06 => info.pin_uv_auth_protocols = collect_uints(val),
            0x07 => info.max_credential_count_in_list = val.as_uint(),
            0x08 => info.max_credential_id_length = val.as_uint(),
            0x09 => info.transports = collect_strings(val),
            0x0E => info.firmware_version = val.as_uint(),
            _ => {}
        }
    }
    Ok(info)
}

fn collect_strings(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_text().map(|s| s.to_owned()))
                .collect()
        })
        .unwrap_or_default()
}

fn collect_uints(v: &Value) -> Vec<u64> {
    v.as_array()
        .map(|a| a.iter().filter_map(|x| x.as_uint()).collect())
        .unwrap_or_default()
}

fn collect_named_bools(v: &Value) -> Vec<(String, bool)> {
    v.as_map()
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| match (k.as_text(), v.as_bool()) {
                    (Some(k), Some(b)) => Some((k.to_owned(), b)),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::encode;

    fn synth_getinfo_response() -> Vec<u8> {
        let v = Value::Map(vec![
            (
                Value::UInt(1),
                Value::Array(vec![
                    Value::Text("U2F_V2".into()),
                    Value::Text("FIDO_2_0".into()),
                ]),
            ),
            (
                Value::UInt(2),
                Value::Array(vec![Value::Text("hmac-secret".into())]),
            ),
            (Value::UInt(3), Value::Bytes(vec![0x11; 16])),
            (
                Value::UInt(4),
                Value::Map(vec![
                    (Value::Text("rk".into()), Value::Bool(true)),
                    (Value::Text("clientPin".into()), Value::Bool(false)),
                    (Value::Text("up".into()), Value::Bool(true)),
                ]),
            ),
            (Value::UInt(5), Value::UInt(1200)),
            (Value::UInt(6), Value::Array(vec![Value::UInt(1)])),
        ]);
        let mut bytes = vec![0u8]; // status byte
        bytes.extend(encode(&v));
        bytes
    }

    #[test]
    fn parse_getinfo_realistic_response() {
        let resp = synth_getinfo_response();
        let (status, body) = split_status(&resp).unwrap();
        assert_eq!(status, 0);
        let (val, _) = cbor::decode(body).unwrap();
        let info = parse_authenticator_info(&val).unwrap();
        assert_eq!(info.versions, vec!["U2F_V2", "FIDO_2_0"]);
        assert_eq!(info.extensions, vec!["hmac-secret"]);
        assert_eq!(info.aaguid, [0x11; 16]);
        assert_eq!(info.option("rk"), Some(true));
        assert_eq!(info.option("clientPin"), Some(false));
        assert_eq!(info.option("unknown"), None);
        assert_eq!(info.max_msg_size, Some(1200));
        assert_eq!(info.pin_uv_auth_protocols, vec![1]);
    }

    #[test]
    fn ignores_unknown_map_keys() {
        let v = Value::Map(vec![
            (
                Value::UInt(1),
                Value::Array(vec![Value::Text("FIDO_2_0".into())]),
            ),
            (Value::UInt(99), Value::UInt(7)),
            (Value::Text("not_a_uint_key".into()), Value::Null),
        ]);
        let info = parse_authenticator_info(&v).unwrap();
        assert_eq!(info.versions, vec!["FIDO_2_0"]);
    }

    #[test]
    fn empty_response_errors_cleanly() {
        let err = split_status(&[]).unwrap_err();
        assert!(matches!(err, CtapError::EmptyResponse));
    }

    #[test]
    fn aaguid_with_wrong_length_is_ignored() {
        let v = Value::Map(vec![(Value::UInt(3), Value::Bytes(vec![0x11; 8]))]);
        let info = parse_authenticator_info(&v).unwrap();
        assert_eq!(info.aaguid, [0u8; 16]);
    }
}
