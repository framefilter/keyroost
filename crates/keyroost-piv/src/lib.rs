//! PIV (Personal Identity Verification — NIST SP 800-73-4 / FIPS 201) byte layer.
//!
//! A pure, I/O-free APDU builder + parser layer for the PIV smartcard
//! application, the same shape as [`keyroost_oath`] and [`keyroost_openpgp`]: it
//! turns intentions into APDU byte vectors and response bytes into typed values,
//! and performs **no card I/O** (that lives in `keyroost-transport`'s
//! `PivSession`). PIV is a CCID/APDU applet on YubiKeys (and other PIV cards),
//! reachable over the same PC/SC layer keyroost already uses.
//!
//! # Scope
//!
//! This first cut covers the **read path** — SELECT, GET DATA (certificate /
//! CHUID objects), the Yubico version/serial extensions, and PIN-retry querying
//! — enough for a read-only `piv status`. The write/auth operations (GENERAL
//! AUTHENTICATE sign/decrypt, GENERATE ASYMMETRIC KEY PAIR, certificate import,
//! and PIN/PUK/management-key management) are not built yet; see PLAN.md.

#![forbid(unsafe_code)]

use keyroost_proto::apdu::{build_apdu, build_apdu_get};

/// PIV card-application AID (the 5-byte RID/PIX prefix; the card matches on it).
/// Full PIV AID is `A0 00 00 03 08 00 00 10 00 01 00`; selecting by the prefix
/// is what `yubikey-piv-tool` / `ykman` do and the card resolves it.
pub const AID: [u8; 5] = [0xA0, 0x00, 0x00, 0x03, 0x08];

/// Status word: success.
pub const SW_OK: u16 = 0x9000;
/// First byte of a `61xx` "more data available" status word.
pub const SW_MORE_DATA: u8 = 0x61;
/// File/application or object not found (e.g. an empty certificate slot).
pub const SW_NOT_FOUND: u16 = 0x6A82;

/// PIN reference (P2) for the PIV application PIN.
pub const PIN_REF_APPLICATION: u8 = 0x80;
/// PIN reference (P2) for the PUK.
pub const PIN_REF_PUK: u8 = 0x81;

/// PIV / Yubico-PIV instruction bytes.
#[derive(Clone, Copy)]
#[repr(u8)]
pub enum Instruction {
    /// SELECT (ISO 7816) — activate the PIV application by AID.
    Select = 0xA4,
    /// VERIFY — present the PIN (or query its retry counter with an empty body).
    Verify = 0x20,
    /// GET DATA — read a PIV data object (certificate, CHUID, …).
    GetData = 0xCB,
    /// GET RESPONSE — pull the next chunk of a `61xx`-chained reply.
    GetResponse = 0xC0,
    /// Yubico extension: GET VERSION (applet/firmware version, 3 bytes).
    GetVersion = 0xFD,
    /// Yubico extension: GET SERIAL (4-byte device serial; firmware 5+).
    GetSerial = 0xF8,
}

impl Instruction {
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}

const INS_SELECT_P1_BY_AID: u8 = 0x04;
/// P1-P2 addressing the data-object namespace for GET DATA.
const GET_DATA_P1: u8 = 0x3F;
const GET_DATA_P2: u8 = 0xFF;
/// BER tag introducing a GET DATA object selector.
const TAG_OBJECT_SELECTOR: u8 = 0x5C;
/// BER tag wrapping a GET DATA response payload.
const TAG_DATA_TEMPLATE: u8 = 0x53;

/// The four PIV asymmetric key slots, identified by their key reference and the
/// certificate data object that holds the slot's X.509 certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    /// `9A` — PIV Authentication.
    Authentication,
    /// `9C` — Digital Signature.
    Signature,
    /// `9D` — Key Management (decryption).
    KeyManagement,
    /// `9E` — Card Authentication.
    CardAuthentication,
}

impl Slot {
    /// The key-reference byte (`9A`/`9C`/`9D`/`9E`).
    #[must_use]
    pub const fn key_ref(self) -> u8 {
        match self {
            Slot::Authentication => 0x9A,
            Slot::Signature => 0x9C,
            Slot::KeyManagement => 0x9D,
            Slot::CardAuthentication => 0x9E,
        }
    }

    /// The 3-byte certificate data-object tag for this slot (`5F C1 0x`).
    #[must_use]
    pub const fn cert_object_tag(self) -> [u8; 3] {
        match self {
            Slot::Authentication => [0x5F, 0xC1, 0x05],
            Slot::Signature => [0x5F, 0xC1, 0x0A],
            Slot::KeyManagement => [0x5F, 0xC1, 0x0B],
            Slot::CardAuthentication => [0x5F, 0xC1, 0x01],
        }
    }

    /// Short human label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Slot::Authentication => "authentication (9A)",
            Slot::Signature => "signature (9C)",
            Slot::KeyManagement => "key management (9D)",
            Slot::CardAuthentication => "card authentication (9E)",
        }
    }

    /// All four slots, in canonical order.
    #[must_use]
    pub const fn all() -> [Slot; 4] {
        [
            Slot::Authentication,
            Slot::Signature,
            Slot::KeyManagement,
            Slot::CardAuthentication,
        ]
    }
}

/// CHUID (Card Holder Unique Identifier) data-object tag.
pub const OBJECT_CHUID: [u8; 3] = [0x5F, 0xC1, 0x02];

/// Errors from parsing PIV responses.
#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    /// A length field ran past the end of the buffer.
    Truncated,
    /// Expected the `0x53` data template wrapper and didn't find it.
    NotDataObject,
    /// A version/serial response was the wrong size.
    BadResponse(&'static str),
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ParseError::Truncated => write!(f, "PIV response truncated"),
            ParseError::NotDataObject => write!(f, "PIV response is not a 0x53 data object"),
            ParseError::BadResponse(w) => write!(f, "malformed PIV response: {w}"),
        }
    }
}

impl std::error::Error for ParseError {}

// ---------------------------------------------------------------------------
// APDU builders
// ---------------------------------------------------------------------------

/// SELECT the PIV application by AID (case 4: a trailing `Le` requests the
/// application property template the card returns on success).
#[must_use]
pub fn select() -> Vec<u8> {
    let mut apdu = build_apdu(
        0x00,
        Instruction::Select.code(),
        INS_SELECT_P1_BY_AID,
        0x00,
        &AID,
    );
    apdu.push(0x00); // case-4 Le
    apdu
}

/// GET DATA for the 3-byte object `tag` (e.g. a slot's [`Slot::cert_object_tag`]
/// or [`OBJECT_CHUID`]). Case 4 — a certificate response is large and arrives via
/// the `61xx` / GET RESPONSE loop.
#[must_use]
pub fn get_data(tag: &[u8]) -> Vec<u8> {
    let mut selector = Vec::with_capacity(2 + tag.len());
    selector.push(TAG_OBJECT_SELECTOR);
    selector.push(tag.len() as u8);
    selector.extend_from_slice(tag);
    let mut apdu = build_apdu(
        0x00,
        Instruction::GetData.code(),
        GET_DATA_P1,
        GET_DATA_P2,
        &selector,
    );
    apdu.push(0x00); // case-4 Le
    apdu
}

/// VERIFY the application PIN. The PIN is padded to 8 bytes with `0xFF` per
/// SP 800-73. The PIN bytes come from the caller and are never logged.
#[must_use]
pub fn verify_pin(pin: &[u8]) -> Vec<u8> {
    build_apdu(
        0x00,
        Instruction::Verify.code(),
        0x00,
        PIN_REF_APPLICATION,
        &pad_pin(pin),
    )
}

/// VERIFY with an empty body — queries the PIN retry counter without consuming a
/// try. The card answers `63Cx` (x tries left), `9000` (already verified), or
/// `6983` (blocked). Case 1 (no `Lc`, no `Le`).
#[must_use]
pub fn verify_pin_status() -> Vec<u8> {
    vec![0x00, Instruction::Verify.code(), 0x00, PIN_REF_APPLICATION]
}

/// Yubico GET VERSION (case 2): 3-byte `major.minor.patch`.
#[must_use]
pub fn get_version() -> Vec<u8> {
    build_apdu_get(0x00, Instruction::GetVersion.code(), 0x00, 0x00, 0x00)
}

/// Yubico GET SERIAL (case 2): 4-byte big-endian serial (firmware 5+).
#[must_use]
pub fn get_serial() -> Vec<u8> {
    build_apdu_get(0x00, Instruction::GetSerial.code(), 0x00, 0x00, 0x00)
}

/// GET RESPONSE for the `61xx` continuation loop.
#[must_use]
pub fn get_response() -> Vec<u8> {
    build_apdu_get(0x00, Instruction::GetResponse.code(), 0x00, 0x00, 0x00)
}

/// Pad a PIN to the fixed 8-byte PIV field with trailing `0xFF`. A PIN already
/// 8 bytes or longer is returned truncated to 8 (PIV PINs are 6–8 bytes).
fn pad_pin(pin: &[u8]) -> Vec<u8> {
    let mut out = [0xFFu8; 8].to_vec();
    let n = pin.len().min(8);
    out[..n].copy_from_slice(&pin[..n]);
    out
}

// ---------------------------------------------------------------------------
// Response parsers
// ---------------------------------------------------------------------------

/// Unwrap a GET DATA response: strip the outer `0x53` template and return the
/// inner value bytes (for a certificate object, the `70`/`71`/`FE` cert TLVs).
pub fn unwrap_data_object(buf: &[u8]) -> Result<&[u8], ParseError> {
    if buf.first() != Some(&TAG_DATA_TEMPLATE) {
        return Err(ParseError::NotDataObject);
    }
    let (len, header) = read_ber_len(&buf[1..])?;
    let start = 1 + header;
    let end = start.checked_add(len).ok_or(ParseError::Truncated)?;
    buf.get(start..end).ok_or(ParseError::Truncated)
}

/// Parse a Yubico GET VERSION reply (exactly 3 bytes) into `(major, minor, patch)`.
pub fn parse_version(buf: &[u8]) -> Result<(u8, u8, u8), ParseError> {
    match buf {
        [a, b, c] => Ok((*a, *b, *c)),
        _ => Err(ParseError::BadResponse("version is not 3 bytes")),
    }
}

/// Parse a Yubico GET SERIAL reply (4-byte big-endian).
pub fn parse_serial(buf: &[u8]) -> Result<u32, ParseError> {
    match buf {
        [a, b, c, d] => Ok(u32::from_be_bytes([*a, *b, *c, *d])),
        _ => Err(ParseError::BadResponse("serial is not 4 bytes")),
    }
}

/// Read a BER-TLV length field, returning `(length, header_byte_count)`.
/// Handles the short form and the `0x81`/`0x82` long forms (a PIV cert easily
/// exceeds 255 bytes, so the 2-byte form is required).
fn read_ber_len(buf: &[u8]) -> Result<(usize, usize), ParseError> {
    let first = *buf.first().ok_or(ParseError::Truncated)?;
    if first < 0x80 {
        return Ok((first as usize, 1));
    }
    let n = (first & 0x7F) as usize;
    if n == 0 || n > 2 {
        return Err(ParseError::BadResponse("unsupported BER length form"));
    }
    let bytes = buf.get(1..1 + n).ok_or(ParseError::Truncated)?;
    let len = bytes.iter().fold(0usize, |acc, &b| (acc << 8) | b as usize);
    Ok((len, 1 + n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_bytes() {
        // 00 A4 04 00 05 A0 00 00 03 08 00
        assert_eq!(
            select(),
            vec![0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00]
        );
    }

    #[test]
    fn get_data_auth_cert_bytes() {
        // 00 CB 3F FF 05 5C 03 5F C1 05 00
        assert_eq!(
            get_data(&Slot::Authentication.cert_object_tag()),
            vec![0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x05, 0x00]
        );
    }

    #[test]
    fn slot_key_refs_and_tags() {
        assert_eq!(Slot::Authentication.key_ref(), 0x9A);
        assert_eq!(Slot::Signature.key_ref(), 0x9C);
        assert_eq!(Slot::KeyManagement.key_ref(), 0x9D);
        assert_eq!(Slot::CardAuthentication.key_ref(), 0x9E);
        assert_eq!(Slot::Signature.cert_object_tag(), [0x5F, 0xC1, 0x0A]);
        assert_eq!(
            Slot::CardAuthentication.cert_object_tag(),
            [0x5F, 0xC1, 0x01]
        );
    }

    #[test]
    fn verify_pin_pads_to_eight() {
        // 00 20 00 80 08 31 32 33 34 35 36 FF FF   ("123456" + FF FF)
        assert_eq!(
            verify_pin(b"123456"),
            vec![0x00, 0x20, 0x00, 0x80, 0x08, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF]
        );
    }

    #[test]
    fn verify_status_is_case1() {
        assert_eq!(verify_pin_status(), vec![0x00, 0x20, 0x00, 0x80]);
    }

    #[test]
    fn version_and_serial_apdus() {
        assert_eq!(get_version(), vec![0x00, 0xFD, 0x00, 0x00, 0x00]);
        assert_eq!(get_serial(), vec![0x00, 0xF8, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn unwrap_short_data_object() {
        // 53 03 AA BB CC -> AA BB CC
        assert_eq!(
            unwrap_data_object(&[0x53, 0x03, 0xAA, 0xBB, 0xCC]).unwrap(),
            &[0xAA, 0xBB, 0xCC]
        );
    }

    #[test]
    fn unwrap_long_form_data_object() {
        // 53 81 80 <128 bytes>
        let mut buf = vec![0x53, 0x81, 0x80];
        buf.extend(std::iter::repeat(0x11).take(128));
        let inner = unwrap_data_object(&buf).unwrap();
        assert_eq!(inner.len(), 128);
        assert!(inner.iter().all(|&b| b == 0x11));
    }

    #[test]
    fn unwrap_rejects_non_template_and_truncation() {
        assert_eq!(
            unwrap_data_object(&[0x70, 0x01, 0x00]),
            Err(ParseError::NotDataObject)
        );
        assert_eq!(
            unwrap_data_object(&[0x53, 0x05, 0x00]),
            Err(ParseError::Truncated)
        );
    }

    #[test]
    fn parse_version_and_serial_values() {
        assert_eq!(parse_version(&[5, 7, 1]).unwrap(), (5, 7, 1));
        assert!(parse_version(&[5, 7]).is_err());
        assert_eq!(parse_serial(&[0x02, 0x40, 0x8A, 0x1B]).unwrap(), 0x02408A1B);
        assert!(parse_serial(&[0x00, 0x01]).is_err());
    }
}
