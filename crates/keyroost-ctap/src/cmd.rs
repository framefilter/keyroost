//! High-level CTAP2 commands.
//!
//! Phase 1 covers only `authenticatorGetInfo` (0x04) and
//! `authenticatorReset` (0x07). Credential management, makeCredential,
//! getAssertion, and PIN/UV protocols come in later phases.

use std::time::Duration;

use crate::cbor::{self, Value};
use crate::hid::{HidTransportError, CTAPHID_CBOR};
use crate::transport::{with_timeout, CtapTransport};

pub const CTAP2_GET_INFO: u8 = 0x04;
pub const CTAP2_RESET: u8 = 0x07;

/// Reset has to land within ~10s of plug-in on most authenticators and
/// always requires a touch — so we wait considerably longer than a normal
/// CTAP transaction.
const RESET_TIMEOUT: Duration = Duration::from_secs(30);

#[non_exhaustive]
#[derive(Debug)]
pub enum CtapError {
    Hid(HidTransportError),
    Cbor(cbor::CborError),
    /// CTAP2 status byte in the response was non-zero. See the FIDO CTAP
    /// spec section "Authenticator API Response Codes" for meanings; the
    /// commonest cases are `0x30` (CTAP2_ERR_NOT_ALLOWED — e.g. reset
    /// outside the touch window) and `0x2F` (CTAP2_ERR_USER_ACTION_TIMEOUT).
    StatusCode(u8),
    /// The authenticator requires a PIN change before it will issue a
    /// pinUvAuthToken. This can be known from GetInfo or reported by a token
    /// request as CTAP2_ERR_PIN_POLICY_VIOLATION (0x37).
    PinChangeRequired,
    /// The key holds no credential matching the request
    /// (CTAP2_ERR_NO_CREDENTIALS, 0x2E, from getAssertion). Kept apart from
    /// [`CtapError::StatusCode`] so a caller can tell "nothing stored here"
    /// from a failure.
    NoCredentials,
    EmptyResponse,
    InvalidResponseShape(&'static str),
    /// A caller-supplied argument was rejected before anything was sent to
    /// the device (e.g. a PIN outside the 4–63 byte range).
    InvalidArgument(&'static str),
    /// The key's getInfo says it doesn't support this operation, so nothing
    /// was sent (e.g. `toggleAlwaysUv` on a key that doesn't list `alwaysUv`).
    Unsupported(&'static str),
    /// A non-HID transport (e.g. PC/SC over NFC or a contact reader) failed at
    /// the link level — reader I/O error, card removed, or an ISO 7816 status
    /// word that does not map to a CTAP2 status.
    Transport(String),
    /// A smart-card reader answered with an ISO 7816 status word that does not
    /// map to a CTAP2 status (for example `6D00`, instruction not supported).
    Apdu {
        sw1: u8,
        sw2: u8,
    },
    /// The operating system's random source failed, so nothing that needs
    /// a fresh nonce was built (there is no fallback).
    Random,
    /// Built-in user verification (a fingerprint) was not offered, refused
    /// or blocked. The caller can ask for the PIN instead. Never a PIN-auth
    /// error: a refused finger does not invalidate a PIN session.
    Fingerprint(FingerprintError),
}

/// Why a fingerprint (CTAP 2.1 built-in user verification) did not give a
/// pinUvAuthToken. Every case reads as one plain sentence that points the
/// user at the PIN, with the CTAP2 status in parentheses when the key sent
/// one.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintError {
    /// The key's getInfo does not offer built-in UV with permission tokens.
    NotOffered,
    /// The key offers built-in UV but has no fingerprint enrolled
    /// (getInfo `uv: false`).
    NoneEnrolled,
    /// The key offers built-in UV but a fingerprint token cannot carry the
    /// permission this needs (`be` without `uvBioEnroll`, `acfg` without
    /// `uvAcfg`); the PIN can.
    NotForThis,
    /// No fingerprint tries are left: `status` is `Some(0x3C)` when the key
    /// said so on a token request, `None` when getUVRetries read 0.
    Blocked { status: Option<u8> },
    /// The key answered the token request with this CTAP2 status.
    Refused(u8),
}

impl std::fmt::Display for FingerprintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (sentence, status) = match *self {
            FingerprintError::NotOffered => (
                "this key does not offer fingerprint unlock; use the PIN instead",
                None,
            ),
            FingerprintError::NoneEnrolled => (
                "this key has no fingerprint enrolled; use the PIN instead",
                None,
            ),
            FingerprintError::NotForThis => (
                "this key does not allow this with a fingerprint; use the PIN instead",
                None,
            ),
            FingerprintError::Blocked { status } => (
                "fingerprint unlock is blocked after too many tries; use the PIN instead",
                // getUVRetries read 0: no status to show, say what was read.
                Some(status.ok_or("no fingerprint tries left")),
            ),
            FingerprintError::Refused(code) => (
                match code {
                    0x3F => "the fingerprint was not recognized; try again or use the PIN instead",
                    0x2F | 0x3A => "timed out waiting for the fingerprint; use the PIN instead",
                    // From getPinUvAuthTokenUsingUvWithPermissions, NOT_ALLOWED
                    // means built-in UV is supported but not configured.
                    0x30 => "this key has no fingerprint enrolled; use the PIN instead",
                    _ => "the key did not accept the fingerprint; use the PIN instead",
                },
                Some(Ok(code)),
            ),
        };
        match status {
            None => f.write_str(sentence),
            Some(Err(why)) => write!(f, "{sentence} ({why})"),
            Some(Ok(code)) => match ctap_status_name(code) {
                Some(name) => write!(f, "{sentence} (CTAP2 status 0x{code:02X} {name})"),
                None => write!(f, "{sentence} (CTAP2 status 0x{code:02X})"),
            },
        }
    }
}

/// The CTAP2 statuses a built-in UV token request
/// (`getPinUvAuthTokenUsingUvWithPermissions`) answers when the finger did not
/// unlock the key, as a [`FingerprintError`]. Any other status is not about
/// the finger and stays a [`CtapError::StatusCode`] (`None`).
pub fn fingerprint_refusal(code: u8) -> Option<FingerprintError> {
    match code {
        0x3C => Some(FingerprintError::Blocked { status: Some(code) }),
        // OPERATION_DENIED, USER_ACTION_TIMEOUT, NOT_ALLOWED, PIN_AUTH_BLOCKED,
        // ACTION_TIMEOUT, UV_INVALID, UNAUTHORIZED_PERMISSION.
        0x27 | 0x2F | 0x30 | 0x34 | 0x3A | 0x3F | 0x40 => Some(FingerprintError::Refused(code)),
        _ => None,
    }
}

impl CtapError {
    /// True when this is a PIN / PIN-auth failure raised *during* an
    /// already-authenticated session: `0x31` (PIN_INVALID), `0x33`
    /// (PIN_AUTH_INVALID), or `0x34` (PIN_AUTH_BLOCKED). Callers use this to
    /// decide whether an in-flight session has been invalidated by the key and
    /// must be re-unlocked. Non-`StatusCode` errors are never PIN/auth errors.
    pub fn is_pin_auth_error(&self) -> bool {
        matches!(self, CtapError::StatusCode(0x31 | 0x33 | 0x34))
    }
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
            CtapError::PinChangeRequired => {
                write!(f, "the key requires a PIN change before this operation")
            }
            CtapError::NoCredentials => write!(f, "this key holds no matching credential"),
            CtapError::EmptyResponse => write!(f, "authenticator returned an empty CBOR response"),
            CtapError::InvalidResponseShape(s) => {
                write!(f, "authenticator response had wrong shape: {}", s)
            }
            CtapError::InvalidArgument(s) => write!(f, "invalid argument: {}", s),
            CtapError::Unsupported(s) => write!(f, "the key does not support {s}"),
            CtapError::Transport(s) => write!(f, "reader transport error: {}", s),
            CtapError::Apdu { sw1, sw2 } => {
                write!(f, "the card refused the FIDO request ({sw1:02X}{sw2:02X})")
            }
            CtapError::Random => write!(f, "the system's random number source failed"),
            CtapError::Fingerprint(e) => write!(f, "{e}"),
        }
    }
}

/// Plain-English explanation for the CTAP2 status codes a user is most likely
/// to hit and least likely to understand from the spec name alone. Returns
/// `None` when the spec name is already clear enough (or the code is unknown),
/// in which case the caller falls back to the spec name / raw hex.
fn ctap_status_hint(code: u8) -> Option<&'static str> {
    Some(match code {
        // PIN policy violation: the new PIN doesn't meet the key's complexity
        // policy (length / character mix), not a transient failure.
        0x37 => {
            "the new PIN doesn't meet this key's complexity requirements \u{2014} \
                 try a longer PIN or a different mix of characters (some keys \
                 enforce a minimum length or required character variety)"
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
        // Not always a timeout. A YubiKey 5 (firmware 5.7) answered a
        // touch that didn't come in time with this, where 0x2F was expected.
        0x27 => {
            "the key refused the operation; on some keys this means the touch \
                 didn't come in time"
        }
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
        0x27 => "CTAP2_ERR_OPERATION_DENIED",
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
        0x3D => "CTAP2_ERR_INTEGRITY_FAILURE",
        0x3E => "CTAP2_ERR_INVALID_SUBCOMMAND",
        0x3F => "CTAP2_ERR_UV_INVALID",
        0x40 => "CTAP2_ERR_UNAUTHORIZED_PERMISSION",
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
    pub force_pin_change: Option<bool>,
    pub min_pin_length: Option<u64>,
    pub firmware_version: Option<u64>,
    /// `maxSerializedLargeBlobArray` (getInfo key 0x0B): the maximum size, in
    /// bytes, of the serialized large-blob array this authenticator stores —
    /// including the 16-byte checksum trailer. Spec minimum is 1024 when the
    /// `largeBlobs` option is supported; absent on keys without large blobs.
    pub max_serialized_large_blob_array: Option<u64>,
    /// `longTouchForReset` (getInfo key 0x18, CTAP 2.2): the key wants a
    /// long touch, not a short one, to confirm `authenticatorReset`. Set by
    /// the `enableLongTouchForReset` configuration, which CanoKey 3.1 offers
    /// and which only a reset clears.
    pub long_touch_for_reset: Option<bool>,
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
pub fn get_info(dev: &mut impl CtapTransport) -> Result<AuthenticatorInfo, CtapError> {
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
pub fn reset(dev: &mut impl CtapTransport) -> Result<(), CtapError> {
    // with_timeout scopes the wide reset window: it saves the caller's
    // deadline (not the default — an embedder that widened the timeout for a
    // slow transport must get *its* value back) and restores it on success
    // and error alike, so a later command on this device doesn't inherit the
    // 30s reset window.
    let resp = with_timeout(dev, RESET_TIMEOUT, |d| {
        d.transact(CTAPHID_CBOR, &[CTAP2_RESET])
    })?;
    let (status, _) = split_status(&resp)?;
    if status != 0 {
        return Err(CtapError::StatusCode(status));
    }
    Ok(())
}

pub(crate) fn split_status(resp: &[u8]) -> Result<(u8, &[u8]), CtapError> {
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
            0x0b => info.max_serialized_large_blob_array = val.as_uint(),
            0x0C => info.force_pin_change = val.as_bool(),
            0x0D => info.min_pin_length = val.as_uint(),
            0x0E => info.firmware_version = val.as_uint(),
            0x18 => info.long_touch_for_reset = val.as_bool(),
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
            (Value::UInt(0x0C), Value::Bool(true)), // forcePINChange
            (Value::UInt(0x0D), Value::UInt(6)),    // minPINLength
            (Value::UInt(0x0E), Value::UInt(328706)), // firmwareVersion
            (Value::UInt(0x18), Value::Bool(true)), // longTouchForReset
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
        // 0x0C/0x0D are the new arms; 0x0E firmwareVersion stays put.
        assert_eq!(info.force_pin_change, Some(true));
        assert_eq!(info.min_pin_length, Some(6));
        assert_eq!(info.firmware_version, Some(328706));
        assert_eq!(info.long_touch_for_reset, Some(true));
    }

    #[test]
    fn classifies_pin_auth_errors_for_relock() {
        assert!(CtapError::StatusCode(0x31).is_pin_auth_error());
        assert!(CtapError::StatusCode(0x33).is_pin_auth_error());
        assert!(CtapError::StatusCode(0x34).is_pin_auth_error());
        // Non-PIN-auth status codes and other variants must not re-lock.
        assert!(!CtapError::StatusCode(0x32).is_pin_auth_error());
        assert!(!CtapError::StatusCode(0x30).is_pin_auth_error());
        assert!(!CtapError::EmptyResponse.is_pin_auth_error());
    }

    #[test]
    fn operation_denied_reads_in_plain_words() {
        let s = CtapError::StatusCode(0x27).to_string();
        assert_eq!(
            s,
            "the key refused the operation; on some keys this means the touch \
             didn't come in time (CTAP2 status 0x27 CTAP2_ERR_OPERATION_DENIED)"
        );
        // The timeout code keeps its own words.
        let t = CtapError::StatusCode(0x2F).to_string();
        assert!(t.starts_with("timed out waiting"), "{t}");
    }

    #[test]
    fn fingerprint_error_texts() {
        assert_eq!(
            FingerprintError::NotOffered.to_string(),
            "this key does not offer fingerprint unlock; use the PIN instead"
        );
        assert_eq!(
            FingerprintError::NoneEnrolled.to_string(),
            "this key has no fingerprint enrolled; use the PIN instead"
        );
        assert_eq!(
            FingerprintError::NotForThis.to_string(),
            "this key does not allow this with a fingerprint; use the PIN instead"
        );
        assert_eq!(
            FingerprintError::Blocked { status: None }.to_string(),
            "fingerprint unlock is blocked after too many tries; use the PIN instead \
             (no fingerprint tries left)"
        );
        assert_eq!(
            FingerprintError::Blocked { status: Some(0x3C) }.to_string(),
            "fingerprint unlock is blocked after too many tries; use the PIN instead \
             (CTAP2 status 0x3C CTAP2_ERR_UV_BLOCKED)"
        );
        assert_eq!(
            FingerprintError::Refused(0x3F).to_string(),
            "the fingerprint was not recognized; try again or use the PIN instead \
             (CTAP2 status 0x3F CTAP2_ERR_UV_INVALID)"
        );
        assert_eq!(
            FingerprintError::Refused(0x2F).to_string(),
            "timed out waiting for the fingerprint; use the PIN instead \
             (CTAP2 status 0x2F CTAP2_ERR_USER_ACTION_TIMEOUT)"
        );
        assert_eq!(
            FingerprintError::Refused(0x3A).to_string(),
            "timed out waiting for the fingerprint; use the PIN instead \
             (CTAP2 status 0x3A CTAP2_ERR_ACTION_TIMEOUT)"
        );
        assert_eq!(
            FingerprintError::Refused(0x27).to_string(),
            "the key did not accept the fingerprint; use the PIN instead \
             (CTAP2 status 0x27 CTAP2_ERR_OPERATION_DENIED)"
        );
        assert_eq!(
            FingerprintError::Refused(0x34).to_string(),
            "the key did not accept the fingerprint; use the PIN instead \
             (CTAP2 status 0x34 CTAP2_ERR_PIN_AUTH_BLOCKED)"
        );
        assert_eq!(
            FingerprintError::Refused(0x40).to_string(),
            "the key did not accept the fingerprint; use the PIN instead \
             (CTAP2 status 0x40 CTAP2_ERR_UNAUTHORIZED_PERMISSION)"
        );
        // From getPinUvAuthTokenUsingUvWithPermissions, NOT_ALLOWED means
        // built-in UV is supported but not configured (CTAP 2.1 §6.5.5.7.3).
        assert_eq!(
            FingerprintError::Refused(0x30).to_string(),
            "this key has no fingerprint enrolled; use the PIN instead \
             (CTAP2 status 0x30 CTAP2_ERR_NOT_ALLOWED)"
        );
        // The CtapError wrapper shows the same sentence.
        assert_eq!(
            CtapError::Fingerprint(FingerprintError::NotOffered).to_string(),
            FingerprintError::NotOffered.to_string()
        );
    }

    #[test]
    fn fingerprint_refusal_maps_the_built_in_uv_statuses() {
        assert_eq!(
            fingerprint_refusal(0x3C),
            Some(FingerprintError::Blocked { status: Some(0x3C) })
        );
        for code in [0x27, 0x2F, 0x30, 0x34, 0x3A, 0x3F, 0x40] {
            assert_eq!(
                fingerprint_refusal(code),
                Some(FingerprintError::Refused(code))
            );
        }
        for code in [0x2B, 0x31, 0x33, 0x37, 0x11] {
            assert_eq!(fingerprint_refusal(code), None);
        }
        // A fingerprint refusal never relocks a PIN session.
        assert!(!CtapError::Fingerprint(FingerprintError::Refused(0x34)).is_pin_auth_error());
    }

    #[test]
    fn status_names_match_ctap_2_1() {
        assert_eq!(ctap_status_name(0x3D), Some("CTAP2_ERR_INTEGRITY_FAILURE"));
        assert_eq!(ctap_status_name(0x3E), Some("CTAP2_ERR_INVALID_SUBCOMMAND"));
        assert_eq!(ctap_status_name(0x3F), Some("CTAP2_ERR_UV_INVALID"));
        assert_eq!(
            ctap_status_name(0x40),
            Some("CTAP2_ERR_UNAUTHORIZED_PERMISSION")
        );
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

    #[test]
    fn parses_max_serialized_large_blob_array() {
        // CTAP2.1 authenticatorGetInfo key 0x0B.
        let v = Value::Map(vec![(Value::UInt(0x0b), Value::UInt(2048))]);
        let info = parse_authenticator_info(&v).unwrap();
        assert_eq!(info.max_serialized_large_blob_array, Some(2048));
    }

    #[test]
    fn max_serialized_large_blob_array_defaults_to_none() {
        let v = Value::Map(vec![]);
        let info = parse_authenticator_info(&v).unwrap();
        assert_eq!(info.max_serialized_large_blob_array, None);
    }
}
