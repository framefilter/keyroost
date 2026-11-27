//! High-level CTAP2 `clientPin` (0x06) commands.
//!
//! Each public function runs the full request-response cycle and returns a
//! typed result. The PIN protocol crypto (ECDH, AES, HMAC) lives in
//! [`crate::pin`]; this module is the glue between those primitives and
//! the CBOR wire format.
//!
//! **PIN/UV auth protocol negotiation.** The authenticator advertises the
//! protocols it supports in `authenticatorGetInfo`'s `pinUvAuthProtocols`, an
//! ordered list whose first entry is the device's *preference* (the Solo 2
//! reports `[2, 1]`). [`select_pin_protocol`] walks that list and picks the
//! device's first-listed protocol that we implement (v1 and v2), defaulting to
//! v1 when the list is absent, empty, or names only protocols we don't know.
//! The chosen protocol drives the ECDH key derivation, AES/HMAC framing, and
//! the `pinUvAuthProtocol` field on every request, and is recorded on the
//! returned [`PinUvAuthToken`] so credentialManagement re-uses it verbatim.
//!
//! For obtaining the pinUvAuthToken we prefer the CTAP 2.1
//! `getPinUvAuthTokenUsingPinWithPermissions` (0x09) when the device advertises
//! the `pinUvAuthToken` option, because 2.1 authenticators require an explicit
//! `cm` permission before they will honour credentialManagement; we fall back
//! to the legacy `getPinToken` (0x05) on older keys.
//!
//! **Built-in user verification.** A key with a fingerprint sensor can hand
//! out the same token for a finger instead of the PIN:
//! `getPinUvAuthTokenUsingUvWithPermissions` (0x06, see
//! [`get_pin_uv_auth_token_using_uv`]) when getInfo has both `uv` and
//! `pinUvAuthToken` true ([`built_in_uv`]), with the remaining finger tries
//! from `getUVRetries` (0x07, [`get_uv_retries`]). [`get_token`] is the one
//! call front ends use: the PIN, a fingerprint, or a fingerprint with the
//! PIN as fallback ([`TokenSource`]), reporting which one gave the token.

use crate::cbor::{self, Value};
use crate::cmd::{fingerprint_refusal, get_info, AuthenticatorInfo, CtapError, FingerprintError};
use crate::hid::CTAPHID_CBOR;
use crate::pin::{
    left16_sha256, pad_pin_to_64, EphemeralKey, PinProtocol, ProtocolV1, ProtocolV2,
    PIN_PROTOCOL_V1, PIN_PROTOCOL_V2,
};
use crate::transport::{with_timeout, CtapTransport};

pub const CTAP2_CLIENT_PIN: u8 = 0x06;

/// `clientPin` request map keys.
const KEY_PIN_PROTOCOL: u64 = 0x01;
const KEY_SUB_COMMAND: u64 = 0x02;
const KEY_KEY_AGREEMENT: u64 = 0x03;
const KEY_PIN_UV_AUTH_PARAM: u64 = 0x04;
const KEY_NEW_PIN_ENC: u64 = 0x05;
const KEY_PIN_HASH_ENC: u64 = 0x06;
const KEY_PERMISSIONS: u64 = 0x09;
const KEY_RP_ID: u64 = 0x0A;

/// `clientPin` sub-command numbers.
const SUB_GET_PIN_RETRIES: u8 = 0x01;
const SUB_GET_KEY_AGREEMENT: u8 = 0x02;
const SUB_SET_PIN: u8 = 0x03;
const SUB_CHANGE_PIN: u8 = 0x04;
const SUB_GET_PIN_TOKEN: u8 = 0x05;
/// `getPinUvAuthTokenUsingPinWithPermissions` — the CTAP 2.1 replacement for
/// `getPinToken`. Unlike 0x05 it binds the returned token to an explicit
/// permission set, which 2.1 authenticators require for credentialManagement.
const SUB_GET_PIN_UV_AUTH_TOKEN_USING_PIN: u8 = 0x09;
/// `getPinUvAuthTokenUsingUvWithPermissions` — the token for a built-in user
/// verification (a fingerprint) instead of the PIN.
const SUB_GET_PIN_UV_AUTH_TOKEN_USING_UV: u8 = 0x06;
/// `getUVRetries` — built-in UV attempts left before the key blocks it.
const SUB_GET_UV_RETRIES: u8 = 0x07;

/// How long a built-in UV token request may wait for the finger: the same
/// window as the other user-present calls (getAssertion, a fingerprint
/// capture).
const UV_TOKEN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// COSE_Key map keys for an EC2 P-256 public key.
const COSE_KTY: i64 = 1;
const COSE_ALG: i64 = 3;
const COSE_CRV: i64 = -1;
const COSE_X: i64 = -2;
const COSE_Y: i64 = -3;
const COSE_KTY_EC2: u64 = 2;
const COSE_ALG_ECDH_ES_HKDF_256: i64 = -25;
const COSE_CRV_P256: u64 = 1;

/// A PIN/UV auth protocol the host implements. Used as the result of
/// negotiating against the device's advertised `pinUvAuthProtocols`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectedPinProtocol {
    V1,
    V2,
}

impl SelectedPinProtocol {
    /// Wire identifier used in the `pinUvAuthProtocol` request field.
    pub fn version(self) -> u32 {
        match self {
            SelectedPinProtocol::V1 => PIN_PROTOCOL_V1,
            SelectedPinProtocol::V2 => PIN_PROTOCOL_V2,
        }
    }
}

/// Negotiate the PIN/UV auth protocol against the device's advertised list.
///
/// `supported` is `authenticatorGetInfo`'s `pinUvAuthProtocols` verbatim: an
/// ordered list whose first entry is the authenticator's preference. We honour
/// that preference by picking the device's first-listed protocol we also
/// implement. When the list is absent/empty or names only protocols we don't
/// know, we default to v1 — the protocol every CTAP2 authenticator supports.
pub fn select_pin_protocol(supported: &[u64]) -> SelectedPinProtocol {
    for &p in supported {
        if p == PIN_PROTOCOL_V2 as u64 {
            return SelectedPinProtocol::V2;
        }
        if p == PIN_PROTOCOL_V1 as u64 {
            return SelectedPinProtocol::V1;
        }
        // Unknown protocol id — skip and keep honouring the device's order.
    }
    SelectedPinProtocol::V1
}

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
    /// Built-in user verification attempts left (`uvRetries`, response key
    /// 0x05), from `getUVRetries`.
    pub uv_retries: Option<u32>,
}

/// PIN/UV auth token obtained from `getPinToken`. The token itself is
/// opaque (16 or 32 random bytes); the bundled shared secret remembers the
/// HMAC key callers need to authenticate later requests.
///
/// `Clone` so a caller can keep a copy for a cached session while handing one
/// to a [`CredentialManager`](crate::cred_mgmt::CredentialManager) (which takes
/// the token by value). The same token stays valid for the device session, so
/// cloning avoids a redundant second PIN/ECDH exchange.
#[derive(Clone)]
pub struct PinUvAuthToken {
    pub protocol: u32,
    /// Random 16-or-32-byte value the authenticator generates per session.
    /// Used both as the HMAC key for `pinUvAuthParam` on later requests and
    /// as the identifier the authenticator looks up when verifying them.
    pub token: Vec<u8>,
}

// The token is a session credential (it authorizes credential management on
// the key until power-down); scrub it — and every clone — on drop.
impl Drop for PinUvAuthToken {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.token.zeroize();
    }
}

impl PinUvAuthToken {
    /// CTAP `pinUvAuthParam`: HMAC of `data` under the token. v1 truncates
    /// to 16 bytes, v2 returns the full 32-byte tag.
    pub fn authenticate(&self, data: &[u8]) -> Vec<u8> {
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha256;
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.token)
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
pub fn get_pin_retries(dev: &mut impl CtapTransport) -> Result<u32, CtapError> {
    let req = build_request_extra(PIN_PROTOCOL_V1, SUB_GET_PIN_RETRIES, &[]);
    let resp = dispatch(dev, &req)?;
    resp.retries
        .ok_or(CtapError::InvalidResponseShape("missing retries"))
}

/// Fetch the authenticator's ephemeral P-256 public key for ECDH.
///
/// `protocol` MUST be the same pinUvAuthProtocol the following operation will
/// use. Declaring v1 here while the operation runs v2 makes strict
/// authenticators (YubiKey) reject the operation's `pinUvAuthParam` with
/// `CTAP2_ERR_PIN_AUTH_INVALID` (0x33); lenient ones (Solo 2) tolerate the
/// mismatch, which is why this only surfaced on the YubiKey. Confirmed from an
/// on-wire trace: getKeyAgreement declared 1 while setPIN ran 2.
pub fn get_key_agreement(
    dev: &mut impl CtapTransport,
    protocol: u32,
) -> Result<([u8; 32], [u8; 32]), CtapError> {
    let req = build_request_extra(protocol, SUB_GET_KEY_AGREEMENT, &[]);
    let resp = dispatch(dev, &req)?;
    resp.key_agreement
        .ok_or(CtapError::InvalidResponseShape("missing keyAgreement"))
}

/// Set the initial PIN on an authenticator that doesn't have one yet.
pub fn set_pin(dev: &mut impl CtapTransport, new_pin: &str) -> Result<(), CtapError> {
    use zeroize::Zeroize;
    validate_pin(new_pin)?;
    let chosen = negotiate_protocol(dev)?;
    let (proto, peer) = key_agreement(dev, chosen)?;
    let our_pub = peer.our_public_cose();
    let mut padded = pad_pin_to_64(new_pin);
    let new_pin_enc = proto.encrypt(&padded)?;
    padded.zeroize();
    let pin_auth = proto.authenticate(&new_pin_enc);

    let extra = vec![
        (Value::UInt(KEY_KEY_AGREEMENT), our_pub),
        (Value::UInt(KEY_PIN_UV_AUTH_PARAM), Value::Bytes(pin_auth)),
        (Value::UInt(KEY_NEW_PIN_ENC), Value::Bytes(new_pin_enc)),
    ];
    let req = build_request_extra(chosen.version(), SUB_SET_PIN, &extra);
    dispatch(dev, &req)?;
    Ok(())
}

/// Change an existing PIN.
pub fn change_pin(
    dev: &mut impl CtapTransport,
    old_pin: &str,
    new_pin: &str,
) -> Result<(), CtapError> {
    use zeroize::Zeroize;
    validate_pin(new_pin)?;
    let chosen = negotiate_protocol(dev)?;
    let (proto, peer) = key_agreement(dev, chosen)?;
    let our_pub = peer.our_public_cose();
    let mut padded = pad_pin_to_64(new_pin);
    let new_pin_enc = proto.encrypt(&padded)?;
    padded.zeroize();
    let mut pin_hash = left16_sha256(old_pin.as_bytes());
    let pin_hash_enc = proto.encrypt(&pin_hash)?;
    pin_hash.zeroize();
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
    let req = build_request_extra(chosen.version(), SUB_CHANGE_PIN, &extra);
    dispatch(dev, &req)?;
    Ok(())
}

/// Obtain a pinUvAuthToken bound to the current PIN. The returned token is
/// usable as an HMAC key for credential management and similar commands
/// until the authenticator power-cycles.
pub fn get_pin_token(dev: &mut impl CtapTransport, pin: &str) -> Result<PinUvAuthToken, CtapError> {
    let chosen = negotiate_protocol(dev)?;
    token_legacy(dev, pin, chosen)
}

/// A token request can also report forcePINChange as 0x37 when GetInfo did not
/// advertise it. Only token requests get this mapping: setPIN and changePIN use
/// the same status for a genuinely rejected new PIN.
fn dispatch_token_request(
    dev: &mut impl CtapTransport,
    req: &[u8],
) -> Result<PinResponse, CtapError> {
    dispatch(dev, req).map_err(|error| match error {
        CtapError::StatusCode(0x37) => CtapError::PinChangeRequired,
        other => other,
    })
}

/// `getPinToken` (0x05) with the protocol already negotiated.
fn token_legacy(
    dev: &mut impl CtapTransport,
    pin: &str,
    chosen: SelectedPinProtocol,
) -> Result<PinUvAuthToken, CtapError> {
    use zeroize::Zeroize;
    let (proto, peer) = key_agreement(dev, chosen)?;
    let our_pub = peer.our_public_cose();
    let mut pin_hash = left16_sha256(pin.as_bytes());
    let pin_hash_enc = proto.encrypt(&pin_hash)?;
    pin_hash.zeroize();

    let extra = vec![
        (Value::UInt(KEY_KEY_AGREEMENT), our_pub),
        (Value::UInt(KEY_PIN_HASH_ENC), Value::Bytes(pin_hash_enc)),
    ];
    let req = build_request_extra(chosen.version(), SUB_GET_PIN_TOKEN, &extra);
    let resp = dispatch_token_request(dev, &req)?;
    let enc_token = resp
        .pin_token_enc
        .ok_or(CtapError::InvalidResponseShape("missing pinToken"))?;
    let token = proto
        .decrypt(&enc_token)
        .map_err(|_| CtapError::InvalidResponseShape("pinToken decrypt failed"))?;
    check_token_len(token, chosen.version()).map(|token| PinUvAuthToken {
        protocol: chosen.version(),
        token,
    })
}

/// Validate the decrypted pinUvAuthToken length: the spec fixes it at 16 or
/// 32 bytes. Anything else means a corrupted exchange — catch it here rather
/// than let a bogus value ride along as an HMAC key. The rejected buffer is
/// wiped before the error returns.
fn check_token_len(mut token: Vec<u8>, _protocol: u32) -> Result<Vec<u8>, CtapError> {
    use zeroize::Zeroize;
    if token.len() == 16 || token.len() == 32 {
        Ok(token)
    } else {
        token.zeroize();
        Err(CtapError::InvalidResponseShape(
            "pinUvAuthToken is not 16 or 32 bytes",
        ))
    }
}

/// Permission bits for [`get_pin_uv_auth_token_with_permissions`]
/// (CTAP 2.1 §6.5.5.7.1). Combine with bitwise OR.
pub mod permissions {
    pub const MAKE_CREDENTIAL: u32 = 0x01;
    pub const GET_ASSERTION: u32 = 0x02;
    pub const CREDENTIAL_MANAGEMENT: u32 = 0x04;
    pub const BIO_ENROLLMENT: u32 = 0x08;
    pub const LARGE_BLOB_WRITE: u32 = 0x10;
    pub const AUTHENTICATOR_CONFIGURATION: u32 = 0x20;
}

/// Obtain a pinUvAuthToken, negotiating the command from `getInfo`: prefer the
/// CTAP 2.1 `getPinUvAuthTokenUsingPinWithPermissions` (0x09) when the device
/// advertises the `pinUvAuthToken` option, otherwise fall back to legacy
/// `getPinToken` (0x05).
///
/// This is the difference that makes credentialManagement work on spec-strict
/// 2.1 authenticators (e.g. YubiKey 5): a legacy-0x05 token carries only
/// implicit `mc`/`ga` permissions, so credentialManagement is rejected with
/// `CTAP2_ERR_PIN_AUTH_INVALID` (0x33). Requesting `cm` via 0x09 fixes it.
/// Legacy keys ignore the permission argument.
pub fn get_pin_uv_auth_token(
    dev: &mut impl CtapTransport,
    pin: &str,
    info: &AuthenticatorInfo,
    permissions: u32,
) -> Result<PinUvAuthToken, CtapError> {
    get_token(
        dev,
        info,
        TokenSource::Pin(pin),
        permissions,
        None,
        &mut || {},
    )
    .map(|(t, _)| t)
}

/// The PIN token with the command negotiated from getInfo: 0x09 with
/// `permissions` and `rp_id` when the key advertises `pinUvAuthToken`,
/// otherwise legacy 0x05, which takes neither.
fn pin_token(
    dev: &mut impl CtapTransport,
    info: &AuthenticatorInfo,
    pin: &str,
    permissions: u32,
    rp_id: Option<&str>,
) -> Result<PinUvAuthToken, CtapError> {
    // We already hold `getInfo`, so negotiate the protocol straight from it
    // rather than paying for another round-trip in the helpers below.
    let chosen = select_pin_protocol(&info.pin_uv_auth_protocols);
    if info.option("pinUvAuthToken") == Some(true) {
        token_with_permissions(dev, pin, permissions, rp_id, chosen)
    } else {
        token_legacy(dev, pin, chosen)
    }
}

/// CTAP 2.1 `getPinUvAuthTokenUsingPinWithPermissions` (sub-command 0x09).
/// Like [`get_pin_token`] but binds the returned token to `permissions` (and,
/// when the permission set requires it, an `rp_id`).
pub fn get_pin_uv_auth_token_with_permissions(
    dev: &mut impl CtapTransport,
    pin: &str,
    permissions: u32,
    rp_id: Option<&str>,
) -> Result<PinUvAuthToken, CtapError> {
    let chosen = negotiate_protocol(dev)?;
    token_with_permissions(dev, pin, permissions, rp_id, chosen)
}

/// Whether the key offers a fingerprint (CTAP 2.1 built-in user
/// verification) for a pinUvAuthToken, read from getInfo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuiltInUv {
    /// `uv` and `pinUvAuthToken` are both true:
    /// [`get_pin_uv_auth_token_using_uv`] can be asked.
    Ready,
    /// `uv` is false (built-in UV supported but not configured, i.e. no
    /// fingerprint enrolled) and `pinUvAuthToken` is true.
    NoneEnrolled,
    /// Anything else: no built-in UV token on this key.
    NotOffered,
}

/// Read the key's built-in UV state from getInfo. Keyed on the `uv` and
/// `pinUvAuthToken` options only, never on `bioEnroll`: a key can manage
/// fingerprints without letting a finger unlock it (CTAP 2.1 allows the
/// 0x06 sub-command only when both options are true).
pub fn built_in_uv(info: &AuthenticatorInfo) -> BuiltInUv {
    match (info.option("uv"), info.option("pinUvAuthToken")) {
        (Some(true), Some(true)) => BuiltInUv::Ready,
        (Some(false), Some(true)) => BuiltInUv::NoneEnrolled,
        _ => BuiltInUv::NotOffered,
    }
}

/// Whether a built-in UV token may carry `permissions` on this key. Through
/// 0x06, CTAP 2.1 grants `be` only with the `uvBioEnroll` option and `acfg`
/// only with `uvAcfg` (the PIN path needs only `bioEnroll` / `authnrCfg`);
/// otherwise the key answers CTAP2_ERR_UNAUTHORIZED_PERMISSION (0x40). The
/// other permissions follow the same options on both paths, so they don't
/// decide between finger and PIN.
pub fn uv_grants(info: &AuthenticatorInfo, permissions: u32) -> bool {
    let needs =
        |bit: u32, option: &str| permissions & bit == 0 || info.option(option) == Some(true);
    needs(permissions::BIO_ENROLLMENT, "uvBioEnroll")
        && needs(permissions::AUTHENTICATOR_CONFIGURATION, "uvAcfg")
}

/// Whether getInfo lets a fingerprint unlock this key for `permissions`:
/// `Ok` when [`built_in_uv`] is [`BuiltInUv::Ready`] and [`uv_grants`]
/// allows them, else why not: [`FingerprintError::NoneEnrolled`],
/// [`FingerprintError::NotOffered`] or [`FingerprintError::NotForThis`].
/// Reads `info` only, no I/O, so a caller can refuse before any question or
/// PIN prompt. [`get_token`] checks the same before asking for the finger.
pub fn uv_precheck(info: &AuthenticatorInfo, permissions: u32) -> Result<(), FingerprintError> {
    match built_in_uv(info) {
        BuiltInUv::Ready if !uv_grants(info, permissions) => Err(FingerprintError::NotForThis),
        BuiltInUv::Ready => Ok(()),
        BuiltInUv::NoneEnrolled => Err(FingerprintError::NoneEnrolled),
        BuiltInUv::NotOffered => Err(FingerprintError::NotOffered),
    }
}

/// Read how many built-in UV (fingerprint) attempts are left
/// (`getUVRetries`, 0x07). No auth, no finger. The request declares the
/// protocol [`select_pin_protocol`] picks from `info`.
pub fn get_uv_retries(
    dev: &mut impl CtapTransport,
    info: &AuthenticatorInfo,
) -> Result<u32, CtapError> {
    let chosen = select_pin_protocol(&info.pin_uv_auth_protocols);
    let req = build_request_extra(chosen.version(), SUB_GET_UV_RETRIES, &[]);
    let resp = dispatch(dev, &req)?;
    resp.uv_retries
        .ok_or(CtapError::InvalidResponseShape("missing uvRetries"))
}

/// CTAP 2.1 `getPinUvAuthTokenUsingUvWithPermissions` (sub-command 0x06): a
/// pinUvAuthToken for a fingerprint (built-in user verification) instead of
/// the PIN, bound to `permissions` and, when given, `rp_id`. The key waits
/// for the finger, so the request runs under a 30 s read window. Call it only
/// when [`built_in_uv`] is [`BuiltInUv::Ready`] and [`uv_grants`] allows the
/// permissions.
///
/// A refused, timed-out or blocked finger comes back as
/// [`CtapError::Fingerprint`], so the caller can offer the PIN; 0x37 is
/// [`CtapError::PinChangeRequired`] as on the PIN path.
///
/// `forcePINChange` in getInfo is refused here with no I/O. CTAP 2.1 checks
/// it only for the PIN token commands; refusing it on this path too is
/// keyroost's choice, so a key that wants a new PIN gets one before any
/// token, whichever way it would be unlocked.
pub fn get_pin_uv_auth_token_using_uv(
    dev: &mut impl CtapTransport,
    info: &AuthenticatorInfo,
    permissions: u32,
    rp_id: Option<&str>,
) -> Result<PinUvAuthToken, CtapError> {
    if info.force_pin_change == Some(true) {
        return Err(CtapError::PinChangeRequired);
    }
    let chosen = select_pin_protocol(&info.pin_uv_auth_protocols);
    let (proto, peer) = key_agreement(dev, chosen)?;
    let extra = uv_token_extra(peer.our_public_cose(), permissions, rp_id);
    let req = build_request_extra(chosen.version(), SUB_GET_PIN_UV_AUTH_TOKEN_USING_UV, &extra);
    let resp = with_timeout(dev, UV_TOKEN_TIMEOUT, |d| dispatch_token_request(d, &req)).map_err(
        |error| match error {
            CtapError::StatusCode(code) => fingerprint_refusal(code)
                .map(CtapError::Fingerprint)
                .unwrap_or(error),
            other => other,
        },
    )?;
    open_token(proto.as_ref(), resp, chosen)
}

/// Build the request-map entries unique to the 0x06 sub-command: the
/// keyAgreement, permissions and optional rpId; no pinHashEnc, since the
/// finger replaces the PIN. Split out so the wire shape is unit-testable
/// without a device.
fn uv_token_extra(our_pub: Value, permissions: u32, rp_id: Option<&str>) -> Vec<(Value, Value)> {
    let mut extra = vec![
        (Value::UInt(KEY_KEY_AGREEMENT), our_pub),
        (
            Value::UInt(KEY_PERMISSIONS),
            Value::UInt(permissions as u64),
        ),
    ];
    if let Some(rp) = rp_id {
        extra.push((Value::UInt(KEY_RP_ID), Value::Text(rp.to_string())));
    }
    extra
}

/// Where [`get_token`] gets the pinUvAuthToken from.
#[derive(Clone, Copy)]
pub enum TokenSource<'a> {
    /// The PIN (0x09, or legacy 0x05 on a key without `pinUvAuthToken`).
    Pin(&'a str),
    /// A fingerprint (0x06) only.
    Fingerprint,
    /// A fingerprint, and the PIN when the finger is refused or cannot be
    /// asked; with `None`, the fingerprint error is returned instead.
    FingerprintOrPin(Option<&'a str>),
}

// Hand-written so a PIN never reaches a log or a panic message.
impl std::fmt::Debug for TokenSource<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            TokenSource::Pin(_) => "Pin(<redacted>)",
            TokenSource::Fingerprint => "Fingerprint",
            TokenSource::FingerprintOrPin(Some(_)) => "FingerprintOrPin(Some(<redacted>))",
            TokenSource::FingerprintOrPin(None) => "FingerprintOrPin(None)",
        })
    }
}

/// How a token from [`get_token`] was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verified {
    Pin,
    Fingerprint,
}

/// Why the user is asked for a finger: the first unlock, again because
/// the key dropped the token it gave, or again because the key lists its
/// vaults only under a second token. Non-exhaustive, so a new reason is no
/// breaking change; [`prompt`](Self::prompt) says each one.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerAsk {
    Unlock,
    Again,
    /// The key refused the vault-bound token for listing the vaults (it
    /// lists only under a token bound to no relying party), so a second
    /// token is asked for, for the listing.
    ListVaults,
}

impl FingerAsk {
    /// The line shown while the key waits for the finger.
    pub fn prompt(self) -> &'static str {
        match self {
            FingerAsk::Unlock => "Touch the fingerprint sensor\u{2026}",
            FingerAsk::Again => {
                "The key asked for a new unlock: touch the fingerprint sensor again\u{2026}"
            }
            FingerAsk::ListVaults => {
                "This key needs a second fingerprint to list its vaults: touch the fingerprint \
                 sensor again\u{2026}"
            }
        }
    }
}

/// Obtain a pinUvAuthToken bound to `permissions` (and `rp_id`, where the
/// command takes one) from the PIN, a fingerprint, or a fingerprint with the
/// PIN as fallback, and say which one gave it.
///
/// - `Pin`: 0x09 with the rpId, or legacy 0x05 (which ignores both
///   `permissions` and `rp_id`) on a key without `pinUvAuthToken`.
/// - `Fingerprint`: refused with no I/O when [`built_in_uv`] is not
///   [`BuiltInUv::Ready`] or [`uv_grants`] does not allow `permissions`;
///   refused without asking for the finger when getUVRetries reads 0 (a
///   failed read is not a refusal: the token request answers for itself).
///   Then `on_finger` runs once, right before the key agreement that leads
///   to the 0x06 request, which waits for the finger.
/// - `FingerprintOrPin(pin)`: the fingerprint; on any
///   [`CtapError::Fingerprint`] with a PIN given, the PIN instead (without a
///   second `on_finger`). Any other error is returned as is.
///
/// `forcePINChange` refuses every source with
/// [`CtapError::PinChangeRequired`] before any I/O: CTAP 2.1 requires the
/// PIN change before the PIN token commands, and keyroost asks for it before
/// a fingerprint token too.
pub fn get_token(
    dev: &mut impl CtapTransport,
    info: &AuthenticatorInfo,
    source: TokenSource<'_>,
    permissions: u32,
    rp_id: Option<&str>,
    on_finger: &mut dyn FnMut(),
) -> Result<(PinUvAuthToken, Verified), CtapError> {
    // Stop here so callers do not mistake the resulting 0x37 for a new-PIN
    // policy error, and so no finger is asked for a token that cannot come.
    if info.force_pin_change == Some(true) {
        return Err(CtapError::PinChangeRequired);
    }
    let pin = match source {
        TokenSource::Pin(pin) => {
            return pin_token(dev, info, pin, permissions, rp_id).map(|t| (t, Verified::Pin))
        }
        TokenSource::Fingerprint => None,
        TokenSource::FingerprintOrPin(pin) => pin,
    };
    match (finger_token(dev, info, permissions, rp_id, on_finger), pin) {
        (Ok(token), _) => Ok((token, Verified::Fingerprint)),
        (Err(CtapError::Fingerprint(_)), Some(pin)) => {
            pin_token(dev, info, pin, permissions, rp_id).map(|t| (t, Verified::Pin))
        }
        (Err(error), _) => Err(error),
    }
}

/// The fingerprint half of [`get_token`].
fn finger_token(
    dev: &mut impl CtapTransport,
    info: &AuthenticatorInfo,
    permissions: u32,
    rp_id: Option<&str>,
    on_finger: &mut dyn FnMut(),
) -> Result<PinUvAuthToken, CtapError> {
    uv_precheck(info, permissions).map_err(CtapError::Fingerprint)?;
    if let Ok(0) = get_uv_retries(dev, info) {
        return Err(CtapError::Fingerprint(FingerprintError::Blocked {
            status: None,
        }));
    }
    on_finger();
    get_pin_uv_auth_token_using_uv(dev, info, permissions, rp_id)
}

/// Decrypt the pinUvAuthToken from a 0x09 or 0x06 answer under the shared
/// secret of its key agreement, and check its length.
fn open_token(
    proto: &dyn PinProtocol,
    resp: PinResponse,
    chosen: SelectedPinProtocol,
) -> Result<PinUvAuthToken, CtapError> {
    let enc_token = resp
        .pin_token_enc
        .ok_or(CtapError::InvalidResponseShape("missing pinUvAuthToken"))?;
    let token = proto
        .decrypt(&enc_token)
        .map_err(|_| CtapError::InvalidResponseShape("pinUvAuthToken decrypt failed"))?;
    check_token_len(token, chosen.version()).map(|token| PinUvAuthToken {
        protocol: chosen.version(),
        token,
    })
}

/// `getPinUvAuthTokenUsingPinWithPermissions` (0x09) with the protocol already
/// negotiated.
fn token_with_permissions(
    dev: &mut impl CtapTransport,
    pin: &str,
    permissions: u32,
    rp_id: Option<&str>,
    chosen: SelectedPinProtocol,
) -> Result<PinUvAuthToken, CtapError> {
    use zeroize::Zeroize;
    let (proto, peer) = key_agreement(dev, chosen)?;
    let our_pub = peer.our_public_cose();
    let mut pin_hash = left16_sha256(pin.as_bytes());
    let pin_hash_enc = proto.encrypt(&pin_hash)?;
    pin_hash.zeroize();

    let extra = pin_uv_auth_token_extra(our_pub, pin_hash_enc, permissions, rp_id);
    let req = build_request_extra(
        chosen.version(),
        SUB_GET_PIN_UV_AUTH_TOKEN_USING_PIN,
        &extra,
    );
    let resp = dispatch_token_request(dev, &req)?;
    open_token(proto.as_ref(), resp, chosen)
}

/// Build the request-map entries unique to the 0x09 sub-command (everything
/// past `pinUvAuthProtocol` + `subCommand`). Split out so the wire shape is
/// unit-testable without a device.
fn pin_uv_auth_token_extra(
    our_pub: Value,
    pin_hash_enc: Vec<u8>,
    permissions: u32,
    rp_id: Option<&str>,
) -> Vec<(Value, Value)> {
    let mut extra = vec![
        (Value::UInt(KEY_KEY_AGREEMENT), our_pub),
        (Value::UInt(KEY_PIN_HASH_ENC), Value::Bytes(pin_hash_enc)),
        (
            Value::UInt(KEY_PERMISSIONS),
            Value::UInt(permissions as u64),
        ),
    ];
    if let Some(rp) = rp_id {
        extra.push((Value::UInt(KEY_RP_ID), Value::Text(rp.to_string())));
    }
    extra
}

/// The platform's ephemeral public key from one key agreement (PIN/UV auth
/// protocol 1 or 2), sent as the `keyAgreement` parameter of every
/// subsequent sub-command or `hmac-secret` input under that agreement.
pub(crate) struct PeerKey {
    /// The platform's (our) public key, not the authenticator's: CTAP
    /// requests carry the host's key so the authenticator can derive the
    /// same shared secret.
    our_x: [u8; 32],
    our_y: [u8; 32],
}

impl PeerKey {
    pub(crate) fn our_public_cose(&self) -> Value {
        cose_p256_public(&self.our_x, &self.our_y)
    }
}

/// Run the ECDH key-agreement step and build the negotiated PIN protocol.
///
/// `chosen` is the protocol [`select_pin_protocol`] picked for this device. The
/// returned [`PinProtocol`] is boxed so the v1/v2 split key derivation and
/// AES/HMAC framing stay behind one interface; callers don't branch on version.
pub(crate) fn key_agreement(
    dev: &mut impl CtapTransport,
    chosen: SelectedPinProtocol,
) -> Result<(Box<dyn PinProtocol>, PeerKey), CtapError> {
    let (peer_x, peer_y) = get_key_agreement(dev, chosen.version())?;
    let our = EphemeralKey::generate()?;
    let (our_x, our_y) = our.public_xy();
    let proto: Box<dyn PinProtocol> = match chosen {
        SelectedPinProtocol::V1 => {
            let secret = our
                .shared_secret_v1(&peer_x, &peer_y)
                .map_err(|_| CtapError::InvalidResponseShape("invalid peer keyAgreement point"))?;
            Box::new(ProtocolV1 { secret })
        }
        SelectedPinProtocol::V2 => {
            let secret = our
                .shared_secret_v2(&peer_x, &peer_y)
                .map_err(|_| CtapError::InvalidResponseShape("invalid peer keyAgreement point"))?;
            Box::new(ProtocolV2 { secret })
        }
    };
    Ok((proto, PeerKey { our_x, our_y }))
}

/// Negotiate the protocol from the device's `getInfo` for the standalone
/// `clientPin` flows that don't receive an [`AuthenticatorInfo`] from their
/// caller (`set_pin`, `change_pin`, `get_pin_token`). One extra read-only
/// `getInfo` round-trip keeps these public signatures unchanged while still
/// honouring the device's preferred protocol.
fn negotiate_protocol(dev: &mut impl CtapTransport) -> Result<SelectedPinProtocol, CtapError> {
    let info = get_info(dev)?;
    Ok(select_pin_protocol(&info.pin_uv_auth_protocols))
}

fn validate_pin(pin: &str) -> Result<(), CtapError> {
    let n = pin.len();
    if !(4..=63).contains(&n) {
        return Err(CtapError::InvalidArgument("PIN must be 4..=63 UTF-8 bytes"));
    }
    Ok(())
}

/// CBOR-encode the `clientPin` request and dispatch it.
fn dispatch(dev: &mut impl CtapTransport, req: &[u8]) -> Result<PinResponse, CtapError> {
    let mut payload = Vec::with_capacity(req.len() + 1);
    payload.push(CTAP2_CLIENT_PIN);
    payload.extend_from_slice(req);
    let resp = dev.transact(CTAPHID_CBOR, &payload)?;
    let (status, body) = resp.split_first().ok_or(CtapError::EmptyResponse)?;
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

/// Parse a decoded `clientPin` response map. Public so the fuzz harness can
/// drive it with arbitrary device bytes.
pub fn parse_pin_response(v: &Value) -> Result<PinResponse, CtapError> {
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
            // uvRetries; a count past u32 is not a count.
            0x05 => {
                out.uv_retries = val.as_uint().and_then(|n| u32::try_from(n).ok());
            }
            _ => {}
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RecordingTransport {
        response: Vec<u8>,
        calls: usize,
    }

    impl CtapTransport for RecordingTransport {
        fn transact(&mut self, _cmd: u8, _payload: &[u8]) -> Result<Vec<u8>, CtapError> {
            self.calls += 1;
            Ok(self.response.clone())
        }
    }

    #[test]
    fn forced_pin_change_skips_all_token_transport_io() {
        // Exercise both the legacy and permission-based branches. GetInfo has
        // already answered, so neither branch needs to touch the key again.
        for pin_uv_auth_token in [false, true] {
            let info = AuthenticatorInfo {
                force_pin_change: Some(true),
                options: if pin_uv_auth_token {
                    vec![("pinUvAuthToken".into(), true)]
                } else {
                    Vec::new()
                },
                ..Default::default()
            };
            let mut dev = RecordingTransport {
                response: Vec::new(),
                calls: 0,
            };
            let error = match get_pin_uv_auth_token(
                &mut dev,
                "test-pin",
                &info,
                permissions::CREDENTIAL_MANAGEMENT,
            ) {
                Ok(_) => panic!("a forced PIN change must reject the token request"),
                Err(error) => error,
            };
            assert!(matches!(error, CtapError::PinChangeRequired));
            assert_eq!(dev.calls, 0);
        }
    }

    #[test]
    fn token_request_pin_policy_violation_means_pin_change_required() {
        let mut dev = RecordingTransport {
            response: vec![0x37],
            calls: 0,
        };
        let error = dispatch_token_request(&mut dev, &[]).unwrap_err();
        assert!(matches!(&error, CtapError::PinChangeRequired));
        assert_eq!(
            error.to_string(),
            "the key requires a PIN change before this operation"
        );
        assert_eq!(dev.calls, 1);
    }

    #[test]
    fn token_request_preserves_wrong_pin_error() {
        let mut dev = RecordingTransport {
            response: vec![0x31],
            calls: 0,
        };
        let error = dispatch_token_request(&mut dev, &[]).unwrap_err();
        assert!(matches!(error, CtapError::StatusCode(0x31)));
        assert_eq!(dev.calls, 1);
    }

    #[test]
    fn request_carries_protocol_and_subcommand() {
        let bytes = build_request_extra(PIN_PROTOCOL_V1, SUB_GET_PIN_RETRIES, &[]);
        let (val, _) = cbor::decode(&bytes).unwrap();
        let map = val.as_map().unwrap();
        assert_eq!(map.len(), 2);
        assert_eq!(map[0].0.as_uint(), Some(KEY_PIN_PROTOCOL));
        assert_eq!(map[0].1.as_uint(), Some(1));
        assert_eq!(map[1].0.as_uint(), Some(KEY_SUB_COMMAND));
        assert_eq!(map[1].1.as_uint(), Some(SUB_GET_PIN_RETRIES as u64));
    }

    /// Regression (YubiKey 0x33): a getKeyAgreement built for a v2 flow must
    /// declare protocol 2, not a hardcoded 1. Strict authenticators reject the
    /// later pinUvAuthParam when the key agreement was negotiated under a
    /// different protocol.
    #[test]
    fn get_key_agreement_request_declares_chosen_protocol() {
        let bytes = build_request_extra(PIN_PROTOCOL_V2, SUB_GET_KEY_AGREEMENT, &[]);
        let (val, _) = cbor::decode(&bytes).unwrap();
        let map = val.as_map().unwrap();
        assert_eq!(map[0].0.as_uint(), Some(KEY_PIN_PROTOCOL));
        assert_eq!(map[0].1.as_uint(), Some(PIN_PROTOCOL_V2 as u64));
        assert_eq!(map[1].1.as_uint(), Some(SUB_GET_KEY_AGREEMENT as u64));
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
        assert_eq!(
            p.pin_token_enc.as_deref(),
            Some(&[0xAA, 0xBB, 0xCC, 0xDD][..])
        );
    }

    #[test]
    fn validate_pin_rejects_too_short_or_too_long() {
        assert!(validate_pin("123").is_err());
        assert!(validate_pin("1234").is_ok());
        assert!(validate_pin(&"x".repeat(63)).is_ok());
        assert!(validate_pin(&"x".repeat(64)).is_err());
    }

    fn find(map: &[(Value, Value)], key: u64) -> Option<&Value> {
        map.iter()
            .find(|(k, _)| k.as_uint() == Some(key))
            .map(|(_, v)| v)
    }

    #[test]
    fn pin_uv_auth_token_request_carries_cm_permission() {
        let our_pub = cose_p256_public(&[0x11; 32], &[0x22; 32]);
        let extra = pin_uv_auth_token_extra(
            our_pub,
            vec![0xAB; 16],
            permissions::CREDENTIAL_MANAGEMENT,
            None,
        );
        let bytes =
            build_request_extra(PIN_PROTOCOL_V1, SUB_GET_PIN_UV_AUTH_TOKEN_USING_PIN, &extra);
        let (val, _) = cbor::decode(&bytes).unwrap();
        let map = val.as_map().unwrap();
        // protocol + subCommand + keyAgreement + pinHashEnc + permissions.
        assert_eq!(map.len(), 5);
        assert_eq!(
            find(map, KEY_PIN_PROTOCOL).and_then(Value::as_uint),
            Some(1)
        );
        assert_eq!(
            find(map, KEY_SUB_COMMAND).and_then(Value::as_uint),
            Some(SUB_GET_PIN_UV_AUTH_TOKEN_USING_PIN as u64)
        );
        assert_eq!(
            find(map, KEY_PERMISSIONS).and_then(Value::as_uint),
            Some(0x04)
        );
        assert!(find(map, KEY_PIN_HASH_ENC)
            .and_then(Value::as_bytes)
            .is_some());
        // rpId omitted when not supplied.
        assert!(find(map, KEY_RP_ID).is_none());
    }

    #[test]
    fn pin_uv_auth_token_request_includes_rp_id_when_given() {
        let our_pub = cose_p256_public(&[1; 32], &[2; 32]);
        let extra = pin_uv_auth_token_extra(
            our_pub,
            vec![0; 16],
            permissions::GET_ASSERTION,
            Some("example.com"),
        );
        let bytes =
            build_request_extra(PIN_PROTOCOL_V1, SUB_GET_PIN_UV_AUTH_TOKEN_USING_PIN, &extra);
        let (val, _) = cbor::decode(&bytes).unwrap();
        let map = val.as_map().unwrap();
        assert_eq!(map.len(), 6);
        assert_eq!(
            find(map, KEY_RP_ID).and_then(Value::as_text),
            Some("example.com")
        );
    }

    #[test]
    fn select_pin_protocol_prefers_device_first_listed_v2() {
        // Solo 2 reports [2, 1]: honour its preference for v2.
        assert_eq!(select_pin_protocol(&[2, 1]), SelectedPinProtocol::V2);
    }

    #[test]
    fn select_pin_protocol_v1_only() {
        assert_eq!(select_pin_protocol(&[1]), SelectedPinProtocol::V1);
    }

    #[test]
    fn select_pin_protocol_honours_v1_first_preference() {
        // Device lists v1 first: pick v1 even though we also support v2.
        assert_eq!(select_pin_protocol(&[1, 2]), SelectedPinProtocol::V1);
    }

    #[test]
    fn select_pin_protocol_defaults_to_v1_when_empty_or_missing() {
        assert_eq!(select_pin_protocol(&[]), SelectedPinProtocol::V1);
    }

    #[test]
    fn select_pin_protocol_defaults_to_v1_for_unknown_only_list() {
        // A device advertising only a protocol we don't implement (e.g. 3)
        // falls back to v1, the universally-supported baseline.
        assert_eq!(select_pin_protocol(&[3]), SelectedPinProtocol::V1);
    }

    #[test]
    fn select_pin_protocol_skips_unknown_then_picks_known() {
        // Unknown leading id is skipped; the next known id (v1) wins.
        assert_eq!(select_pin_protocol(&[3, 1]), SelectedPinProtocol::V1);
        // ...and v2 wins if it's the first known one after an unknown.
        assert_eq!(select_pin_protocol(&[3, 2, 1]), SelectedPinProtocol::V2);
    }

    #[test]
    fn selected_protocol_version_maps_to_wire_ids() {
        assert_eq!(SelectedPinProtocol::V1.version(), PIN_PROTOCOL_V1);
        assert_eq!(SelectedPinProtocol::V2.version(), PIN_PROTOCOL_V2);
    }

    #[test]
    fn request_carries_v2_protocol_when_selected() {
        let bytes = build_request_extra(SelectedPinProtocol::V2.version(), SUB_GET_PIN_TOKEN, &[]);
        let (val, _) = cbor::decode(&bytes).unwrap();
        let map = val.as_map().unwrap();
        assert_eq!(
            find(map, KEY_PIN_PROTOCOL).and_then(Value::as_uint),
            Some(2)
        );
    }

    #[test]
    fn auth_token_v2_returns_full_32() {
        let t = PinUvAuthToken {
            protocol: PIN_PROTOCOL_V2,
            token: vec![0u8; 32],
        };
        assert_eq!(t.authenticate(b"hello").len(), 32);
    }

    #[test]
    fn auth_token_v1_truncates_to_16() {
        let t = PinUvAuthToken {
            protocol: PIN_PROTOCOL_V1,
            token: vec![0u8; 16],
        };
        assert_eq!(t.authenticate(b"hello").len(), 16);
    }

    // --- Built-in user verification (fingerprint) --------------------------

    use crate::pin::EphemeralKey;
    use std::time::Duration;

    /// A scripted authenticator with built-in UV. It runs real ECDH, so a
    /// token it hands out decrypts only under the secret our key agreement
    /// derived: sub 2 answers with its public key, sub 6 with `token`
    /// encrypted for the protocol the request declares (or `sub6_status`),
    /// sub 7 with `{5: retries}` (or `sub7_status`). Every call records its
    /// sub-command, decoded request map and the read timeout in effect.
    struct UvDevice {
        key: EphemeralKey,
        token: Vec<u8>,
        sub6_status: Option<u8>,
        retries: u32,
        sub7_status: Option<u8>,
        calls: Vec<(u8, Value)>,
        /// The decrypted pinHashEnc of every PIN token request (sub 5 or 9).
        pin_hashes: Vec<[u8; 16]>,
        timeout: Duration,
        timeouts: Vec<Duration>,
        set_calls: Vec<Duration>,
    }

    impl UvDevice {
        fn new() -> Self {
            UvDevice {
                key: EphemeralKey::generate().unwrap(),
                token: (0u8..32).collect(),
                sub6_status: None,
                retries: 5,
                sub7_status: None,
                calls: Vec::new(),
                pin_hashes: Vec::new(),
                timeout: Duration::from_secs(2),
                timeouts: Vec::new(),
                set_calls: Vec::new(),
            }
        }

        fn subs(&self) -> Vec<u8> {
            self.calls.iter().map(|(sub, _)| *sub).collect()
        }

        fn reply(map: Vec<(Value, Value)>) -> Vec<u8> {
            let mut resp = vec![0x00];
            resp.extend(cbor::encode(&Value::Map(map)));
            resp
        }

        /// The key's side of the agreement the request's keyAgreement and
        /// declared protocol make.
        fn shared(&self, req: &Value) -> Box<dyn PinProtocol> {
            let theirs = parse_pin_response(&Value::Map(vec![(
                Value::UInt(1),
                req.get_uint_key(KEY_KEY_AGREEMENT).unwrap().clone(),
            )]))
            .unwrap()
            .key_agreement
            .unwrap();
            let protocol = req.get_uint_key(KEY_PIN_PROTOCOL).unwrap().as_uint();
            if protocol == Some(2) {
                Box::new(ProtocolV2 {
                    secret: self.key.shared_secret_v2(&theirs.0, &theirs.1).unwrap(),
                })
            } else {
                Box::new(ProtocolV1 {
                    secret: self.key.shared_secret_v1(&theirs.0, &theirs.1).unwrap(),
                })
            }
        }

        /// Answer a token request with `token` encrypted for it.
        fn issue(&self, device: &dyn PinProtocol) -> Vec<u8> {
            let enc = device.encrypt(&self.token).unwrap();
            Self::reply(vec![(Value::UInt(2), Value::Bytes(enc))])
        }
    }

    impl CtapTransport for UvDevice {
        fn transact(&mut self, cmd: u8, payload: &[u8]) -> Result<Vec<u8>, CtapError> {
            assert_eq!(cmd, CTAPHID_CBOR);
            assert_eq!(payload[0], CTAP2_CLIENT_PIN);
            let (req, _) = cbor::decode(&payload[1..]).unwrap();
            let sub = req
                .get_uint_key(KEY_SUB_COMMAND)
                .unwrap()
                .as_uint()
                .unwrap() as u8;
            self.calls.push((sub, req.clone()));
            self.timeouts.push(self.timeout);
            match sub {
                SUB_GET_KEY_AGREEMENT => {
                    let (x, y) = self.key.public_xy();
                    Ok(Self::reply(vec![(
                        Value::UInt(1),
                        cose_p256_public(&x, &y),
                    )]))
                }
                SUB_GET_PIN_UV_AUTH_TOKEN_USING_UV => {
                    if let Some(status) = self.sub6_status {
                        return Ok(vec![status]);
                    }
                    let device = self.shared(&req);
                    Ok(self.issue(device.as_ref()))
                }
                SUB_GET_PIN_UV_AUTH_TOKEN_USING_PIN | SUB_GET_PIN_TOKEN => {
                    let device = self.shared(&req);
                    let enc = req
                        .get_uint_key(KEY_PIN_HASH_ENC)
                        .and_then(Value::as_bytes)
                        .unwrap();
                    let hash = device.decrypt(enc).unwrap();
                    self.pin_hashes.push(hash.as_slice().try_into().unwrap());
                    Ok(self.issue(device.as_ref()))
                }
                SUB_GET_UV_RETRIES => match self.sub7_status {
                    Some(status) => Ok(vec![status]),
                    None => Ok(Self::reply(vec![(
                        Value::UInt(5),
                        Value::UInt(self.retries as u64),
                    )])),
                },
                other => panic!("UvDevice: unexpected clientPin sub-command {other:#04x}"),
            }
        }
        fn set_timeout(&mut self, timeout: Duration) {
            self.set_calls.push(timeout);
            self.timeout = timeout;
        }
        fn read_timeout(&self) -> Duration {
            self.timeout
        }
    }

    fn uv_info(protocols: Vec<u64>) -> AuthenticatorInfo {
        AuthenticatorInfo {
            pin_uv_auth_protocols: protocols,
            options: vec![("uv".into(), true), ("pinUvAuthToken".into(), true)],
            ..Default::default()
        }
    }

    #[test]
    fn uv_token_request_carries_subcommand_6_permissions_and_no_pin_hash() {
        let cose = cose_p256_public(&[0x11; 32], &[0x22; 32]);
        let extra = uv_token_extra(
            cose.clone(),
            permissions::CREDENTIAL_MANAGEMENT,
            Some("example.com"),
        );
        let keys: Vec<u64> = extra.iter().map(|(k, _)| k.as_uint().unwrap()).collect();
        assert_eq!(keys, [KEY_KEY_AGREEMENT, KEY_PERMISSIONS, KEY_RP_ID]);

        let extra = uv_token_extra(cose.clone(), permissions::CREDENTIAL_MANAGEMENT, None);
        let keys: Vec<u64> = extra.iter().map(|(k, _)| k.as_uint().unwrap()).collect();
        assert_eq!(keys, [KEY_KEY_AGREEMENT, KEY_PERMISSIONS]);

        // Byte-exact: {1: 2, 2: 6, 3: COSE key, 9: 0x04, 10: "example.com"}.
        let extra = uv_token_extra(
            cose,
            permissions::CREDENTIAL_MANAGEMENT,
            Some("example.com"),
        );
        let bytes =
            build_request_extra(PIN_PROTOCOL_V2, SUB_GET_PIN_UV_AUTH_TOKEN_USING_UV, &extra);
        let mut expected = vec![0xA5, 0x01, 0x02, 0x02, 0x06, 0x03];
        // COSE_Key {1: 2, 3: -25, -1: 1, -2: x, -3: y}
        expected.extend([
            0xA5, 0x01, 0x02, 0x03, 0x38, 0x18, 0x20, 0x01, 0x21, 0x58, 0x20,
        ]);
        expected.extend([0x11; 32]);
        expected.extend([0x22, 0x58, 0x20]);
        expected.extend([0x22; 32]);
        expected.extend([0x09, 0x04, 0x0A, 0x6B]);
        expected.extend(b"example.com");
        assert_eq!(bytes, expected);
    }

    #[test]
    fn uv_retries_request_is_subcommand_7() {
        let mut dev = UvDevice::new();
        dev.retries = 4;
        assert_eq!(get_uv_retries(&mut dev, &uv_info(vec![2, 1])).unwrap(), 4);
        assert_eq!(dev.calls.len(), 1);
        let (sub, req) = &dev.calls[0];
        assert_eq!(*sub, 7);
        assert_eq!(
            *req,
            Value::Map(vec![
                (Value::UInt(1), Value::UInt(2)),
                (Value::UInt(2), Value::UInt(7)),
            ])
        );
        // A refused read stays a plain status, not a fingerprint error.
        let mut dev = UvDevice::new();
        dev.sub7_status = Some(0x2B);
        assert!(matches!(
            get_uv_retries(&mut dev, &uv_info(vec![1])),
            Err(CtapError::StatusCode(0x2B))
        ));
        // A reply without uvRetries is a malformed answer.
        let mut dev = RecordingTransport {
            response: vec![0x00, 0xA0],
            calls: 0,
        };
        assert!(matches!(
            get_uv_retries(&mut dev, &uv_info(vec![1])),
            Err(CtapError::InvalidResponseShape(_))
        ));
    }

    #[test]
    fn parse_pin_response_reads_uv_retries() {
        let resp = Value::Map(vec![(Value::UInt(0x05), Value::UInt(3))]);
        assert_eq!(parse_pin_response(&resp).unwrap().uv_retries, Some(3));
        // A count past u32 is not a count.
        let resp = Value::Map(vec![(Value::UInt(0x05), Value::UInt(1 << 32))]);
        assert_eq!(parse_pin_response(&resp).unwrap().uv_retries, None);
    }

    #[test]
    fn uv_token_round_trips_against_a_simulated_key() {
        for (protocols, expected) in [(vec![2u64, 1], 2u32), (vec![1], 1)] {
            let mut dev = UvDevice::new();
            let token = get_pin_uv_auth_token_using_uv(
                &mut dev,
                &uv_info(protocols),
                permissions::CREDENTIAL_MANAGEMENT | permissions::LARGE_BLOB_WRITE,
                Some("keyroost.vault"),
            )
            .unwrap();
            assert_eq!(token.token, dev.token);
            assert_eq!(token.protocol, expected);
            assert_eq!(dev.subs(), [2, 6]);
            // Both requests declare the chosen protocol.
            for (_, req) in &dev.calls {
                assert_eq!(
                    req.get_uint_key(KEY_PIN_PROTOCOL).and_then(Value::as_uint),
                    Some(expected as u64)
                );
            }
            let req = &dev.calls[1].1;
            assert_eq!(
                req.get_uint_key(KEY_PERMISSIONS).and_then(Value::as_uint),
                Some(0x14)
            );
            assert_eq!(
                req.get_uint_key(KEY_RP_ID).and_then(Value::as_text),
                Some("keyroost.vault")
            );
            assert!(req.get_uint_key(KEY_PIN_HASH_ENC).is_none());
        }
    }

    #[test]
    fn uv_token_widens_the_read_window_for_the_finger_only() {
        // Sub 6 waits for a finger: it runs under the 30 s window, key
        // agreement under the caller's, and the caller's comes back after.
        let mut dev = UvDevice::new();
        let caller = dev.timeout;
        get_pin_uv_auth_token_using_uv(
            &mut dev,
            &uv_info(vec![2]),
            permissions::GET_ASSERTION,
            None,
        )
        .unwrap();
        assert_eq!(dev.timeouts, [caller, Duration::from_secs(30)]);
        assert_eq!(dev.set_calls, [Duration::from_secs(30), caller]);
        assert_eq!(dev.read_timeout(), caller);

        // A refusal restores it too.
        let mut dev = UvDevice::new();
        dev.sub6_status = Some(0x3F);
        assert!(get_pin_uv_auth_token_using_uv(
            &mut dev,
            &uv_info(vec![2]),
            permissions::GET_ASSERTION,
            None
        )
        .is_err());
        assert_eq!(dev.set_calls, [Duration::from_secs(30), caller]);
        assert_eq!(dev.read_timeout(), caller);

        // The retries read is not a user-present call.
        let mut dev = UvDevice::new();
        get_uv_retries(&mut dev, &uv_info(vec![2])).unwrap();
        assert!(dev.set_calls.is_empty());
    }

    #[test]
    fn forced_pin_change_skips_uv_token_io() {
        let mut dev = UvDevice::new();
        let info = AuthenticatorInfo {
            force_pin_change: Some(true),
            ..uv_info(vec![2, 1])
        };
        let result = get_pin_uv_auth_token_using_uv(
            &mut dev,
            &info,
            permissions::CREDENTIAL_MANAGEMENT,
            None,
        );
        assert!(matches!(result, Err(CtapError::PinChangeRequired)));
        assert!(dev.calls.is_empty());
    }

    #[test]
    fn uv_token_pin_policy_violation_means_pin_change_required() {
        let mut dev = UvDevice::new();
        dev.sub6_status = Some(0x37);
        let result = get_pin_uv_auth_token_using_uv(
            &mut dev,
            &uv_info(vec![2]),
            permissions::CREDENTIAL_MANAGEMENT,
            None,
        );
        assert!(matches!(result, Err(CtapError::PinChangeRequired)));
    }

    #[test]
    fn uv_refusals_become_fingerprint_errors() {
        let token_with = |status: u8| {
            let mut dev = UvDevice::new();
            dev.sub6_status = Some(status);
            match get_pin_uv_auth_token_using_uv(
                &mut dev,
                &uv_info(vec![2, 1]),
                permissions::CREDENTIAL_MANAGEMENT,
                None,
            ) {
                Ok(_) => panic!("status {status:#04x} must refuse"),
                Err(error) => error,
            }
        };
        for code in [0x27, 0x2F, 0x30, 0x34, 0x3A, 0x3F, 0x40] {
            let err = token_with(code);
            assert!(
                matches!(err, CtapError::Fingerprint(FingerprintError::Refused(c)) if c == code),
                "{code:#04x}: {err:?}"
            );
        }
        assert!(matches!(
            token_with(0x3C),
            CtapError::Fingerprint(FingerprintError::Blocked { status: Some(0x3C) })
        ));
        assert!(matches!(token_with(0x2B), CtapError::StatusCode(0x2B)));
    }

    #[test]
    fn built_in_uv_reads_uv_and_pin_uv_auth_token() {
        let cases = [
            ((Some(true), Some(true), None), BuiltInUv::Ready),
            (
                (Some(false), Some(true), Some(true)),
                BuiltInUv::NoneEnrolled,
            ),
            ((Some(true), None, Some(true)), BuiltInUv::NotOffered),
            ((None, Some(true), Some(true)), BuiltInUv::NotOffered),
            ((Some(false), None, None), BuiltInUv::NotOffered),
            ((None, None, Some(false)), BuiltInUv::NotOffered),
        ];
        for ((uv, token, bio), expected) in cases {
            let mut options = Vec::new();
            for (name, value) in [("uv", uv), ("pinUvAuthToken", token), ("bioEnroll", bio)] {
                if let Some(value) = value {
                    options.push((name.to_string(), value));
                }
            }
            let info = AuthenticatorInfo {
                options,
                ..Default::default()
            };
            assert_eq!(built_in_uv(&info), expected, "{uv:?} {token:?} {bio:?}");
        }
    }

    #[test]
    fn uv_grants_follows_uv_bio_enroll_and_uv_acfg() {
        use permissions::*;
        let with = |opts: &[(&str, bool)]| AuthenticatorInfo {
            options: opts.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
            ..uv_info(vec![2])
        };
        let plain = with(&[("uv", true), ("pinUvAuthToken", true)]);
        // mc, ga, cm and lbw do not depend on the UV-only options.
        assert!(uv_grants(&plain, MAKE_CREDENTIAL | GET_ASSERTION));
        assert!(uv_grants(&plain, CREDENTIAL_MANAGEMENT | LARGE_BLOB_WRITE));
        // be needs uvBioEnroll; bioEnroll alone (the PIN path's option) is not enough.
        assert!(!uv_grants(&plain, BIO_ENROLLMENT));
        let bio = with(&[("bioEnroll", true)]);
        assert!(!uv_grants(&bio, CREDENTIAL_MANAGEMENT | BIO_ENROLLMENT));
        let uv_bio = with(&[("uvBioEnroll", true)]);
        assert!(uv_grants(&uv_bio, CREDENTIAL_MANAGEMENT | BIO_ENROLLMENT));
        assert!(!uv_grants(&with(&[("uvBioEnroll", false)]), BIO_ENROLLMENT));
        // acfg needs uvAcfg; authnrCfg alone is not enough.
        assert!(!uv_grants(
            &with(&[("authnrCfg", true)]),
            AUTHENTICATOR_CONFIGURATION
        ));
        assert!(uv_grants(
            &with(&[("uvAcfg", true)]),
            AUTHENTICATOR_CONFIGURATION
        ));
        // Asking both needs both.
        assert!(!uv_grants(
            &uv_bio,
            BIO_ENROLLMENT | AUTHENTICATOR_CONFIGURATION
        ));
        let both = with(&[("uvBioEnroll", true), ("uvAcfg", true)]);
        assert!(uv_grants(
            &both,
            BIO_ENROLLMENT | AUTHENTICATOR_CONFIGURATION
        ));
    }

    // --- One token call: PIN, fingerprint, fingerprint else PIN ------------

    const TEST_PIN: &str = "4711-test";

    type TokenResult = Result<(PinUvAuthToken, Verified), CtapError>;

    /// Run [`get_token`] and count how often it asked for the finger.
    fn token_via(
        dev: &mut UvDevice,
        info: &AuthenticatorInfo,
        source: TokenSource<'_>,
        permissions: u32,
        rp_id: Option<&str>,
    ) -> (TokenResult, usize) {
        let mut fingers = 0;
        let result = get_token(dev, info, source, permissions, rp_id, &mut || fingers += 1);
        (result, fingers)
    }

    fn refusal(result: TokenResult) -> CtapError {
        match result {
            Ok(_) => panic!("the token request must be refused"),
            Err(error) => error,
        }
    }

    /// The one getInfo check for a fingerprint token: ready, none enrolled,
    /// not offered, or not allowed for these permissions.
    #[test]
    fn uv_precheck_says_why_a_finger_cannot_unlock() {
        use permissions::{BIO_ENROLLMENT as BE, CREDENTIAL_MANAGEMENT as CM};
        let ready = info_with(&[("uv", true), ("pinUvAuthToken", true)]);
        assert_eq!(uv_precheck(&ready, CM), Ok(()));
        assert_eq!(
            uv_precheck(&ready, CM | BE),
            Err(FingerprintError::NotForThis)
        );
        let bio = info_with(&[
            ("uv", true),
            ("pinUvAuthToken", true),
            ("uvBioEnroll", true),
        ]);
        assert_eq!(uv_precheck(&bio, CM | BE), Ok(()));
        assert_eq!(
            uv_precheck(&info_with(&[("uv", false), ("pinUvAuthToken", true)]), CM),
            Err(FingerprintError::NoneEnrolled)
        );
        assert_eq!(
            uv_precheck(&info_with(&[("uv", true)]), CM),
            Err(FingerprintError::NotOffered)
        );
    }

    fn info_with(opts: &[(&str, bool)]) -> AuthenticatorInfo {
        AuthenticatorInfo {
            options: opts.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
            ..uv_info(vec![2, 1])
        }
    }

    #[test]
    fn pin_source_sends_0x09_with_the_rp_id() {
        let mut dev = UvDevice::new();
        let (result, fingers) = token_via(
            &mut dev,
            &uv_info(vec![2, 1]),
            TokenSource::Pin(TEST_PIN),
            permissions::GET_ASSERTION | permissions::LARGE_BLOB_WRITE,
            Some("keyroost.vault"),
        );
        let (token, verified) = result.ok().unwrap();
        assert_eq!(verified, Verified::Pin);
        assert_eq!(token.token, dev.token);
        assert_eq!(fingers, 0);
        assert_eq!(dev.subs(), [2, 9]);
        let req = &dev.calls[1].1;
        assert_eq!(
            req.get_uint_key(KEY_RP_ID).and_then(Value::as_text),
            Some("keyroost.vault")
        );
        assert_eq!(
            req.get_uint_key(KEY_PERMISSIONS).and_then(Value::as_uint),
            Some(0x12)
        );
        assert_eq!(dev.pin_hashes, [left16_sha256(TEST_PIN.as_bytes())]);
    }

    #[test]
    fn pin_source_on_a_legacy_key_uses_0x05_without_the_rp_id() {
        let mut dev = UvDevice::new();
        let info = AuthenticatorInfo {
            pin_uv_auth_protocols: vec![1],
            options: vec![("clientPin".into(), true)],
            ..Default::default()
        };
        let (result, _) = token_via(
            &mut dev,
            &info,
            TokenSource::Pin(TEST_PIN),
            permissions::GET_ASSERTION,
            Some("keyroost.vault"),
        );
        assert_eq!(result.ok().unwrap().1, Verified::Pin);
        assert_eq!(dev.subs(), [2, 5]);
        assert!(dev.calls[1].1.get_uint_key(KEY_RP_ID).is_none());
        assert!(dev.calls[1].1.get_uint_key(KEY_PERMISSIONS).is_none());
        assert_eq!(dev.pin_hashes, [left16_sha256(TEST_PIN.as_bytes())]);
    }

    #[test]
    fn fingerprint_source_refuses_without_uv_and_sends_nothing() {
        let cases = [
            (
                info_with(&[("uv", false), ("pinUvAuthToken", true)]),
                FingerprintError::NoneEnrolled,
            ),
            (
                info_with(&[("pinUvAuthToken", true)]),
                FingerprintError::NotOffered,
            ),
            (info_with(&[("uv", true)]), FingerprintError::NotOffered),
        ];
        for (info, expected) in cases {
            let mut dev = UvDevice::new();
            let (result, fingers) = token_via(
                &mut dev,
                &info,
                TokenSource::Fingerprint,
                permissions::CREDENTIAL_MANAGEMENT,
                None,
            );
            let err = refusal(result);
            assert!(
                matches!(err, CtapError::Fingerprint(e) if e == expected),
                "{expected:?}: {err:?}"
            );
            assert!(dev.calls.is_empty());
            assert_eq!(fingers, 0);
        }
    }

    #[test]
    fn fingerprint_source_checks_retries_then_asks_once() {
        let mut dev = UvDevice::new();
        let (result, fingers) = token_via(
            &mut dev,
            &uv_info(vec![2, 1]),
            TokenSource::Fingerprint,
            permissions::GET_ASSERTION | permissions::LARGE_BLOB_WRITE,
            Some("keyroost.vault"),
        );
        let (token, verified) = result.ok().unwrap();
        assert_eq!(verified, Verified::Fingerprint);
        assert_eq!(token.token, dev.token);
        assert_eq!(fingers, 1);
        assert_eq!(dev.subs(), [7, 2, 6]);
        let req = &dev.calls[2].1;
        assert_eq!(
            req.get_uint_key(KEY_PERMISSIONS).and_then(Value::as_uint),
            Some(0x12)
        );
        assert_eq!(
            req.get_uint_key(KEY_RP_ID).and_then(Value::as_text),
            Some("keyroost.vault")
        );
        assert!(dev.pin_hashes.is_empty());
    }

    #[test]
    fn zero_uv_retries_refuse_before_the_finger() {
        let mut dev = UvDevice::new();
        dev.retries = 0;
        let (result, fingers) = token_via(
            &mut dev,
            &uv_info(vec![2]),
            TokenSource::Fingerprint,
            permissions::CREDENTIAL_MANAGEMENT,
            None,
        );
        assert!(matches!(
            refusal(result),
            CtapError::Fingerprint(FingerprintError::Blocked { status: None })
        ));
        assert_eq!(dev.subs(), [7]);
        assert_eq!(fingers, 0);
    }

    #[test]
    fn a_failed_retries_read_does_not_block() {
        let mut dev = UvDevice::new();
        dev.sub7_status = Some(0x2B);
        let (result, fingers) = token_via(
            &mut dev,
            &uv_info(vec![2]),
            TokenSource::Fingerprint,
            permissions::CREDENTIAL_MANAGEMENT,
            None,
        );
        assert_eq!(result.ok().unwrap().1, Verified::Fingerprint);
        assert_eq!(dev.subs(), [7, 2, 6]);
        assert_eq!(fingers, 1);
    }

    #[test]
    fn fingerprint_source_refuses_permissions_the_finger_cannot_grant() {
        // F1: through 0x06, be needs uvBioEnroll and acfg needs uvAcfg; the
        // PIN path's bioEnroll / authnrCfg are not enough.
        for (perm, pin_option, uv_option) in [
            (permissions::BIO_ENROLLMENT, "bioEnroll", "uvBioEnroll"),
            (
                permissions::AUTHENTICATOR_CONFIGURATION,
                "authnrCfg",
                "uvAcfg",
            ),
        ] {
            let perms = permissions::CREDENTIAL_MANAGEMENT | perm;
            let ready = [("uv", true), ("pinUvAuthToken", true)];
            let pin_only = info_with(&[ready[0], ready[1], (pin_option, true)]);

            // Fingerprint and auto without a PIN: refused, no I/O, no finger.
            for source in [
                TokenSource::Fingerprint,
                TokenSource::FingerprintOrPin(None),
            ] {
                let mut dev = UvDevice::new();
                let (result, fingers) = token_via(&mut dev, &pin_only, source, perms, None);
                let err = refusal(result);
                assert!(
                    matches!(err, CtapError::Fingerprint(FingerprintError::NotForThis)),
                    "{perm:#04x} {source:?}: {err:?}"
                );
                assert_eq!(
                    err.to_string(),
                    "this key does not allow this with a fingerprint; use the PIN instead"
                );
                assert!(dev.calls.is_empty());
                assert_eq!(fingers, 0);
            }

            // Auto with a PIN: straight to the PIN, no finger.
            let mut dev = UvDevice::new();
            let (result, fingers) = token_via(
                &mut dev,
                &pin_only,
                TokenSource::FingerprintOrPin(Some(TEST_PIN)),
                perms,
                None,
            );
            assert_eq!(result.ok().unwrap().1, Verified::Pin);
            assert_eq!(dev.subs(), [2, 9]);
            assert_eq!(fingers, 0);

            // With the UV option the finger can grant it.
            let mut dev = UvDevice::new();
            let granted = info_with(&[ready[0], ready[1], (uv_option, true)]);
            let (result, fingers) =
                token_via(&mut dev, &granted, TokenSource::Fingerprint, perms, None);
            assert_eq!(result.ok().unwrap().1, Verified::Fingerprint);
            assert_eq!(dev.subs(), [7, 2, 6]);
            assert_eq!(fingers, 1);
        }
    }

    #[test]
    fn auto_falls_back_to_the_given_pin_on_every_refusal() {
        for code in [0x27, 0x2F, 0x30, 0x34, 0x3A, 0x3C, 0x3F, 0x40] {
            let mut dev = UvDevice::new();
            dev.sub6_status = Some(code);
            let (result, fingers) = token_via(
                &mut dev,
                &uv_info(vec![2, 1]),
                TokenSource::FingerprintOrPin(Some(TEST_PIN)),
                permissions::CREDENTIAL_MANAGEMENT,
                Some("example.com"),
            );
            let (token, verified) = result.ok().unwrap();
            assert_eq!(verified, Verified::Pin, "{code:#04x}");
            assert_eq!(token.token, dev.token);
            assert_eq!(dev.subs(), [7, 2, 6, 2, 9], "{code:#04x}");
            assert_eq!(fingers, 1, "{code:#04x}");
            // The PIN request carries the same permissions and rpId.
            let req = &dev.calls[4].1;
            assert_eq!(
                req.get_uint_key(KEY_RP_ID).and_then(Value::as_text),
                Some("example.com")
            );
            assert_eq!(dev.pin_hashes, [left16_sha256(TEST_PIN.as_bytes())]);
        }

        // No tries left: the PIN, without asking for the finger.
        let mut dev = UvDevice::new();
        dev.retries = 0;
        let (result, fingers) = token_via(
            &mut dev,
            &uv_info(vec![2, 1]),
            TokenSource::FingerprintOrPin(Some(TEST_PIN)),
            permissions::CREDENTIAL_MANAGEMENT,
            None,
        );
        assert_eq!(result.ok().unwrap().1, Verified::Pin);
        assert_eq!(dev.subs(), [7, 2, 9]);
        assert_eq!(fingers, 0);
    }

    #[test]
    fn auto_without_a_pin_returns_the_fingerprint_error() {
        let mut dev = UvDevice::new();
        dev.sub6_status = Some(0x3F);
        let (result, fingers) = token_via(
            &mut dev,
            &uv_info(vec![2, 1]),
            TokenSource::FingerprintOrPin(None),
            permissions::CREDENTIAL_MANAGEMENT,
            None,
        );
        assert!(matches!(
            refusal(result),
            CtapError::Fingerprint(FingerprintError::Refused(0x3F))
        ));
        assert_eq!(dev.subs(), [7, 2, 6]);
        assert_eq!(fingers, 1);
    }

    #[test]
    fn auto_on_a_key_without_uv_uses_the_pin_without_a_finger() {
        for (info, expected) in [
            (
                info_with(&[("uv", false), ("pinUvAuthToken", true)]),
                FingerprintError::NoneEnrolled,
            ),
            (
                info_with(&[("pinUvAuthToken", true)]),
                FingerprintError::NotOffered,
            ),
        ] {
            let mut dev = UvDevice::new();
            let (result, fingers) = token_via(
                &mut dev,
                &info,
                TokenSource::FingerprintOrPin(Some(TEST_PIN)),
                permissions::CREDENTIAL_MANAGEMENT,
                None,
            );
            assert_eq!(result.ok().unwrap().1, Verified::Pin);
            assert_eq!(dev.subs(), [2, 9]);
            assert_eq!(fingers, 0);

            // Without a PIN: the fingerprint error, before any I/O.
            let mut dev = UvDevice::new();
            let (result, fingers) = token_via(
                &mut dev,
                &info,
                TokenSource::FingerprintOrPin(None),
                permissions::CREDENTIAL_MANAGEMENT,
                None,
            );
            let err = refusal(result);
            assert!(
                matches!(err, CtapError::Fingerprint(e) if e == expected),
                "{err:?}"
            );
            assert!(dev.calls.is_empty());
            assert_eq!(fingers, 0);
        }
    }

    #[test]
    fn auto_does_not_fall_back_on_other_errors() {
        let mut dev = UvDevice::new();
        dev.sub6_status = Some(0x2B);
        let (result, fingers) = token_via(
            &mut dev,
            &uv_info(vec![2, 1]),
            TokenSource::FingerprintOrPin(Some(TEST_PIN)),
            permissions::CREDENTIAL_MANAGEMENT,
            None,
        );
        assert!(matches!(refusal(result), CtapError::StatusCode(0x2B)));
        assert_eq!(dev.subs(), [7, 2, 6]);
        assert_eq!(fingers, 1);

        // A PIN change the key asks for is not a finger refusal either.
        let mut dev = UvDevice::new();
        dev.sub6_status = Some(0x37);
        let (result, _) = token_via(
            &mut dev,
            &uv_info(vec![2, 1]),
            TokenSource::FingerprintOrPin(Some(TEST_PIN)),
            permissions::CREDENTIAL_MANAGEMENT,
            None,
        );
        assert!(matches!(refusal(result), CtapError::PinChangeRequired));
        assert_eq!(dev.subs(), [7, 2, 6]);
    }

    #[test]
    fn forced_pin_change_refuses_every_source_before_the_finger() {
        let info = AuthenticatorInfo {
            force_pin_change: Some(true),
            ..uv_info(vec![2, 1])
        };
        for source in [
            TokenSource::Pin(TEST_PIN),
            TokenSource::Fingerprint,
            TokenSource::FingerprintOrPin(Some(TEST_PIN)),
            TokenSource::FingerprintOrPin(None),
        ] {
            let mut dev = UvDevice::new();
            let (result, fingers) = token_via(
                &mut dev,
                &info,
                source,
                permissions::CREDENTIAL_MANAGEMENT,
                None,
            );
            assert!(
                matches!(refusal(result), CtapError::PinChangeRequired),
                "{source:?}"
            );
            assert!(dev.calls.is_empty(), "{source:?}");
            assert_eq!(fingers, 0, "{source:?}");
        }
    }

    #[test]
    fn token_source_debug_hides_the_pin() {
        let shown = [
            format!("{:?}", TokenSource::Pin(TEST_PIN)),
            format!("{:?}", TokenSource::FingerprintOrPin(Some(TEST_PIN))),
        ];
        for text in &shown {
            assert!(!text.contains(TEST_PIN), "{text}");
            assert!(text.contains("redacted"), "{text}");
        }
        assert_eq!(format!("{:?}", TokenSource::Fingerprint), "Fingerprint");
        assert_eq!(
            format!("{:?}", TokenSource::FingerprintOrPin(None)),
            "FingerprintOrPin(None)"
        );
    }

    #[test]
    fn finger_prompts() {
        assert_eq!(
            FingerAsk::Unlock.prompt(),
            "Touch the fingerprint sensor\u{2026}"
        );
        assert_eq!(
            FingerAsk::Again.prompt(),
            "The key asked for a new unlock: touch the fingerprint sensor again\u{2026}"
        );
        assert_eq!(
            FingerAsk::ListVaults.prompt(),
            "This key needs a second fingerprint to list its vaults: touch the fingerprint \
             sensor again\u{2026}"
        );
    }
}
