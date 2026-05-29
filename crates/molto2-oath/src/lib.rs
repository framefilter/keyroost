//! Yubico/Trussed OATH (TOTP/HOTP) applet protocol over APDU.
//!
//! Phase 3 of extending MoltoUI toward ykman parity. The OATH applet is a
//! CCID/APDU smartcard applet on Trussed devices (Solo 2, Nitrokey 3) and on
//! YubiKeys, reachable over the existing PC/SC transport — no second transport
//! stack. This crate is the pure-Rust command/response layer (APDU builders +
//! TLV parsing); the actual card exchange lives in `molto2-transport`.
//!
//! Codes follow Yubico's OATH spec (AID `A0 00 00 05 27 21 01`, INS
//! `Put`/`Delete`/`List`/`Calculate`/`SendRemaining`). The Trussed
//! implementation removed Yubico's `SetCode`/`Validate` authorization handshake,
//! so provisioning/list/delete interoperate but OATH password-auth diverges —
//! target the Trussed variant first (see `PLAN.md` Phase 3).
//!
//! # What is and isn't here
//!
//! This is the *byte layer*: it turns intentions into APDU byte vectors and
//! turns response byte slices into typed structures. It performs **no I/O**.
//! Card transmit, the `61xx` / `SEND_REMAINING` reassembly loop, and password
//! authentication (`SET_CODE` / `VALIDATE`) are deliberately left for the
//! transport phase; see the `TODO(transport)` notes on [`send_remaining`] and
//! [`Instruction`].

use molto2_proto::apdu::{build_apdu, build_apdu_get};

/// OATH applet AID (`A0 00 00 05 27 21 01`), selected with `SELECT (00 A4 04 00)`.
pub const AID: [u8; 7] = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01];

/// ISO 7816 `SELECT` instruction (not OATH-specific, used to activate the applet).
pub const INS_SELECT: u8 = 0xA4;
/// `SELECT` P1: select by DF name (AID).
pub const P1_SELECT_BY_NAME: u8 = 0x04;

/// OATH applet instruction bytes (Yubico OATH spec).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Instruction {
    /// Add (provision) a credential.
    Put = 0x01,
    /// Remove a credential by name.
    Delete = 0x02,
    /// Set/clear the applet access password.
    ///
    /// TODO(transport): not modelled — the Trussed variant diverges from Yubico
    /// here, and exercising it needs the `VALIDATE` challenge from `SELECT`.
    SetCode = 0x03,
    /// Wipe all credentials and access settings.
    Reset = 0x04,
    /// Rename a credential.
    Rename = 0x05,
    /// List credential names (and their type/algorithm prefix byte).
    List = 0xA1,
    /// Compute one OTP for a named credential.
    Calculate = 0xA2,
    /// Answer the access-password challenge.
    ///
    /// TODO(transport): paired with [`Instruction::SetCode`]; not modelled.
    Validate = 0xA3,
    /// Compute OTPs for all credentials at once.
    CalculateAll = 0xA4,
    /// Continue reading a response the card split across `61xx` exchanges.
    SendRemaining = 0xA5,
}

impl Instruction {
    /// The raw instruction byte.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}

/// OATH TLV tag bytes (Yubico OATH spec).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Tag {
    /// Credential name (UTF-8) sent to the card.
    Name = 0x71,
    /// Credential name returned in a `LIST` entry (carries a type/algo prefix).
    NameList = 0x72,
    /// Key material: `[ (type<<4)|algo, digits, secret... ]`.
    Key = 0x73,
    /// Challenge (8-byte big-endian counter for TOTP/HOTP).
    Challenge = 0x74,
    /// Full HMAC response.
    Response = 0x75,
    /// Dynamically-truncated response: `[ digits, b0, b1, b2, b3 ]`.
    TruncatedResponse = 0x76,
    /// Marker that a credential produced no response (e.g. touch-required).
    NoResponse = 0x77,
    /// Credential property flags (`0x02` = require touch).
    Property = 0x78,
    /// Applet version, present in the `SELECT` response.
    Version = 0x79,
    /// Initial moving factor (HOTP counter) at provisioning time.
    Imf = 0x7A,
    /// Algorithm byte (used standalone in some responses).
    Algorithm = 0x7B,
    /// Touch requirement byte.
    Touch = 0x7C,
}

impl Tag {
    /// The raw tag byte.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}

/// `PROPERTY` TLV value requesting that the credential require a touch.
pub const PROPERTY_REQUIRE_TOUCH: u8 = 0x02;

/// `CALCULATE` P2 selecting the dynamically-truncated response (`0x76`).
pub const P2_TRUNCATED: u8 = 0x01;
/// `CALCULATE` P2 selecting the full response (`0x75`).
pub const P2_FULL: u8 = 0x00;

/// Status word: success.
pub const SW_OK: u16 = 0x9000;
/// High byte of the "more data available" status (`61xx`).
pub const SW_MORE_DATA: u8 = 0x61;

/// OATH credential kind. Encoded in the high nibble of the KEY/NAME_LIST prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OathType {
    /// Counter-based (RFC 4226).
    Hotp,
    /// Time-based (RFC 6238).
    Totp,
}

impl OathType {
    /// The 4-bit type nibble (already shifted into the high nibble).
    #[must_use]
    pub const fn nibble(self) -> u8 {
        match self {
            OathType::Hotp => 0x10,
            OathType::Totp => 0x20,
        }
    }

    /// Decode the high nibble of a prefix byte.
    #[must_use]
    pub const fn from_prefix(prefix: u8) -> Option<Self> {
        match prefix & 0xF0 {
            0x10 => Some(OathType::Hotp),
            0x20 => Some(OathType::Totp),
            _ => None,
        }
    }
}

/// HMAC algorithm. Encoded in the low nibble of the KEY/NAME_LIST prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// HMAC-SHA1.
    Sha1,
    /// HMAC-SHA256.
    Sha256,
    /// HMAC-SHA512.
    Sha512,
}

impl Algorithm {
    /// The 4-bit algorithm nibble.
    #[must_use]
    pub const fn nibble(self) -> u8 {
        match self {
            Algorithm::Sha1 => 0x01,
            Algorithm::Sha256 => 0x02,
            Algorithm::Sha512 => 0x03,
        }
    }

    /// Decode the low nibble of a prefix byte.
    #[must_use]
    pub const fn from_prefix(prefix: u8) -> Option<Self> {
        match prefix & 0x0F {
            0x01 => Some(Algorithm::Sha1),
            0x02 => Some(Algorithm::Sha256),
            0x03 => Some(Algorithm::Sha512),
            _ => None,
        }
    }
}

/// Compose the `(type<<4)|algorithm` prefix byte shared by KEY and NAME_LIST.
#[must_use]
pub const fn prefix_byte(oath_type: OathType, algorithm: Algorithm) -> u8 {
    oath_type.nibble() | algorithm.nibble()
}

// ---------------------------------------------------------------------------
// TLV encoding (short-form length only; OATH values never exceed 255 bytes per
// TLV in the commands we build).
// ---------------------------------------------------------------------------

/// Append a short-form TLV (`tag`, 1-byte length, value) to `out`.
///
/// # Panics
/// Panics if `value` is longer than 255 bytes, which no OATH command we build
/// can produce (names, keys, and challenges are all small).
fn push_tlv(out: &mut Vec<u8>, tag: Tag, value: &[u8]) {
    assert!(value.len() <= 255, "OATH TLV value exceeds short-form length");
    out.push(tag.code());
    out.push(value.len() as u8);
    out.extend_from_slice(value);
}

// ---------------------------------------------------------------------------
// APDU builders
// ---------------------------------------------------------------------------

/// `SELECT` the OATH applet: `00 A4 04 00 07 A0 00 00 05 27 21 01`.
#[must_use]
pub fn select() -> Vec<u8> {
    build_apdu(0x00, INS_SELECT, P1_SELECT_BY_NAME, 0x00, &AID)
}

/// Parameters for provisioning a credential via [`put`].
#[derive(Debug, Clone)]
pub struct PutParams<'a> {
    /// Credential name as stored on the card (UTF-8, e.g. `"issuer:account"`).
    pub name: &'a str,
    /// Raw (already base32-decoded) HMAC secret.
    pub secret: &'a [u8],
    /// Credential kind.
    pub oath_type: OathType,
    /// HMAC algorithm.
    pub algorithm: Algorithm,
    /// Number of OTP digits (6 or 8).
    pub digits: u8,
    /// Whether the credential should require a touch to compute.
    pub require_touch: bool,
    /// Initial moving factor (HOTP counter). Ignored for TOTP; when non-zero an
    /// `IMF` TLV is appended.
    pub imf: u32,
}

/// Build a `PUT` APDU to provision a credential.
///
/// Data layout: `NAME(0x71) || KEY(0x73) [|| PROPERTY(0x78) ][|| IMF(0x7A)]`.
/// The KEY value is `[ (type<<4)|algo, digits, secret... ]`.
#[must_use]
pub fn put(params: &PutParams<'_>) -> Vec<u8> {
    let mut data = Vec::new();
    push_tlv(&mut data, Tag::Name, params.name.as_bytes());

    let mut key = Vec::with_capacity(2 + params.secret.len());
    key.push(prefix_byte(params.oath_type, params.algorithm));
    key.push(params.digits);
    key.extend_from_slice(params.secret);
    push_tlv(&mut data, Tag::Key, &key);

    if params.require_touch {
        push_tlv(&mut data, Tag::Property, &[PROPERTY_REQUIRE_TOUCH]);
    }
    if params.imf != 0 {
        push_tlv(&mut data, Tag::Imf, &params.imf.to_be_bytes());
    }

    build_apdu(0x00, Instruction::Put.code(), 0x00, 0x00, &data)
}

/// Build a `DELETE` APDU removing the credential named `name`.
/// Data layout: `NAME(0x71) <name>`.
#[must_use]
pub fn delete(name: &str) -> Vec<u8> {
    let mut data = Vec::new();
    push_tlv(&mut data, Tag::Name, name.as_bytes());
    build_apdu(0x00, Instruction::Delete.code(), 0x00, 0x00, &data)
}

/// Build a `RENAME` APDU. Data layout: `NAME(0x71) <old> || NAME(0x71) <new>`.
#[must_use]
pub fn rename(old: &str, new: &str) -> Vec<u8> {
    let mut data = Vec::new();
    push_tlv(&mut data, Tag::Name, old.as_bytes());
    push_tlv(&mut data, Tag::Name, new.as_bytes());
    build_apdu(0x00, Instruction::Rename.code(), 0x00, 0x00, &data)
}

/// Build a `LIST` APDU (case-2; the response is a sequence of `NAME_LIST` TLVs).
#[must_use]
pub fn list() -> Vec<u8> {
    build_apdu_get(0x00, Instruction::List.code(), 0x00, 0x00, 0x00)
}

/// Build a `CALCULATE` APDU requesting a truncated OTP for `name`.
///
/// `challenge` is the 8-byte big-endian counter (for TOTP,
/// `floor(unix_time / period)`; for HOTP, the moving factor). P2 is set to
/// [`P2_TRUNCATED`] so the card returns a `TRUNCATED_RESPONSE` (`0x76`).
/// Data layout: `NAME(0x71) <name> || CHALLENGE(0x74) <8 bytes>`.
#[must_use]
pub fn calculate(name: &str, challenge: &[u8; 8]) -> Vec<u8> {
    let mut data = Vec::new();
    push_tlv(&mut data, Tag::Name, name.as_bytes());
    push_tlv(&mut data, Tag::Challenge, challenge);
    build_apdu(0x00, Instruction::Calculate.code(), 0x00, P2_TRUNCATED, &data)
}

/// Build a `CALCULATE_ALL` APDU (truncated). Data layout: `CHALLENGE(0x74) <8 bytes>`.
#[must_use]
pub fn calculate_all(challenge: &[u8; 8]) -> Vec<u8> {
    let mut data = Vec::new();
    push_tlv(&mut data, Tag::Challenge, challenge);
    build_apdu(
        0x00,
        Instruction::CalculateAll.code(),
        0x00,
        P2_TRUNCATED,
        &data,
    )
}

/// Build a `SEND_REMAINING` APDU (case-2).
///
/// When a response is larger than one APDU the card answers with `SW = 61 xx`.
/// The reader then issues `SEND_REMAINING` repeatedly, concatenating each
/// response body, until the status word is `9000`.
///
/// TODO(transport): the reassembly loop itself (transmit, inspect `SW`, repeat)
/// belongs in `molto2-transport`; this builder only emits the request APDU.
#[must_use]
pub fn send_remaining() -> Vec<u8> {
    build_apdu_get(0x00, Instruction::SendRemaining.code(), 0x00, 0x00, 0x00)
}

/// Build the 8-byte big-endian TOTP challenge for `unix_seconds` and `period`.
///
/// The counter is `floor(unix_seconds / period)` (RFC 6238), serialized big-endian.
///
/// # Panics
/// Panics if `period` is zero.
#[must_use]
pub fn totp_challenge(unix_seconds: u64, period: u32) -> [u8; 8] {
    assert!(period != 0, "TOTP period must be non-zero");
    (unix_seconds / u64::from(period)).to_be_bytes()
}

// ---------------------------------------------------------------------------
// TLV parsing
// ---------------------------------------------------------------------------

/// Error returned by the response parsers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// A TLV claimed more bytes than the buffer contained.
    Truncated,
    /// A `NAME_LIST` / `KEY` prefix byte had an unknown type or algorithm nibble.
    BadPrefix(u8),
    /// A credential name was not valid UTF-8.
    InvalidUtf8,
    /// A `TRUNCATED_RESPONSE` value was malformed (wrong length).
    BadTruncatedResponse,
    /// A required tag was absent from the response.
    MissingTag(u8),
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ParseError::Truncated => write!(f, "TLV truncated: length exceeds buffer"),
            ParseError::BadPrefix(b) => write!(f, "unknown OATH type/algorithm prefix {b:#04x}"),
            ParseError::InvalidUtf8 => write!(f, "credential name is not valid UTF-8"),
            ParseError::BadTruncatedResponse => write!(f, "malformed TRUNCATED_RESPONSE TLV"),
            ParseError::MissingTag(t) => write!(f, "expected TLV tag {t:#04x} not present"),
        }
    }
}

impl std::error::Error for ParseError {}

/// A single parsed short-form TLV borrowed from the response buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv<'a> {
    /// Raw tag byte.
    pub tag: u8,
    /// Value bytes (length already validated against the buffer).
    pub value: &'a [u8],
}

/// Parse a flat bag of short-form TLVs from `buf`.
///
/// OATH responses use 1-byte lengths throughout, so this does not implement
/// BER long-form lengths. Returns [`ParseError::Truncated`] if any TLV runs off
/// the end of the buffer.
pub fn parse_tlvs(buf: &[u8]) -> Result<Vec<Tlv<'_>>, ParseError> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < buf.len() {
        if i + 2 > buf.len() {
            return Err(ParseError::Truncated);
        }
        let tag = buf[i];
        let len = buf[i + 1] as usize;
        let start = i + 2;
        let end = start.checked_add(len).ok_or(ParseError::Truncated)?;
        if end > buf.len() {
            return Err(ParseError::Truncated);
        }
        out.push(Tlv {
            tag,
            value: &buf[start..end],
        });
        i = end;
    }
    Ok(out)
}

/// Find the value of the first TLV with `tag` in a flat bag.
#[must_use]
pub fn find_tag<'a>(tlvs: &[Tlv<'a>], tag: Tag) -> Option<&'a [u8]> {
    tlvs.iter().find(|t| t.tag == tag.code()).map(|t| t.value)
}

/// One entry from a `LIST` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialInfo {
    /// Credential name (UTF-8).
    pub name: String,
    /// Credential kind decoded from the prefix byte.
    pub oath_type: OathType,
    /// HMAC algorithm decoded from the prefix byte.
    pub algorithm: Algorithm,
}

/// Parse a `LIST` response into credential entries.
///
/// The response is a sequence of `NAME_LIST` (`0x72`) TLVs; each value is
/// `[ (type<<4)|algo, name_utf8... ]`. Non-`NAME_LIST` tags are ignored so the
/// parser tolerates a card that interleaves other tags.
pub fn parse_list(buf: &[u8]) -> Result<Vec<CredentialInfo>, ParseError> {
    let tlvs = parse_tlvs(buf)?;
    let mut out = Vec::new();
    for tlv in &tlvs {
        if tlv.tag != Tag::NameList.code() {
            continue;
        }
        let value = tlv.value;
        let prefix = *value.first().ok_or(ParseError::Truncated)?;
        let oath_type = OathType::from_prefix(prefix).ok_or(ParseError::BadPrefix(prefix))?;
        let algorithm = Algorithm::from_prefix(prefix).ok_or(ParseError::BadPrefix(prefix))?;
        let name =
            core::str::from_utf8(&value[1..]).map_err(|_| ParseError::InvalidUtf8)?;
        out.push(CredentialInfo {
            name: name.to_owned(),
            oath_type,
            algorithm,
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// OTP truncation / formatting
// ---------------------------------------------------------------------------

/// Format an OTP from the 4 dynamically-truncated big-endian bytes.
///
/// Applies the RFC 4226 dynamic-truncation finish: mask off the top bit, reduce
/// modulo `10^digits`, and zero-pad to `digits`. This is the formatter the
/// card's `TRUNCATED_RESPONSE` feeds (it has already selected the offset).
///
/// # Panics
/// Panics if `digits` is 0 or greater than 9 (a `u32` cannot hold a 10-digit
/// decimal in the general case; OATH uses 6 or 8).
#[must_use]
pub fn format_truncated(bytes: &[u8; 4], digits: u8) -> String {
    assert!((1..=9).contains(&digits), "OATH digits must be 1..=9");
    let raw = u32::from_be_bytes(*bytes) & 0x7FFF_FFFF;
    let modulus = 10u32.pow(u32::from(digits));
    let code = raw % modulus;
    format!("{code:0width$}", width = digits as usize)
}

/// A parsed `TRUNCATED_RESPONSE` (`0x76`): digit count plus the formatted code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpCode {
    /// Number of digits the card reported.
    pub digits: u8,
    /// Zero-padded decimal code.
    pub code: String,
}

/// Parse a `TRUNCATED_RESPONSE` (`0x76`) value `[ digits, b0, b1, b2, b3 ]`.
pub fn parse_truncated_response(value: &[u8]) -> Result<OtpCode, ParseError> {
    if value.len() != 5 {
        return Err(ParseError::BadTruncatedResponse);
    }
    let digits = value[0];
    if !(1..=9).contains(&digits) {
        return Err(ParseError::BadTruncatedResponse);
    }
    let bytes = [value[1], value[2], value[3], value[4]];
    Ok(OtpCode {
        digits,
        code: format_truncated(&bytes, digits),
    })
}

/// Parse a `CALCULATE` response: locate the `TRUNCATED_RESPONSE` and format it.
pub fn parse_calculate(buf: &[u8]) -> Result<OtpCode, ParseError> {
    let tlvs = parse_tlvs(buf)?;
    let value = find_tag(&tlvs, Tag::TruncatedResponse)
        .ok_or(ParseError::MissingTag(Tag::TruncatedResponse.code()))?;
    parse_truncated_response(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Truncation / formatting: RFC 4226 Appendix D --------------------

    #[test]
    fn rfc4226_truncation_6_and_8_digits() {
        // RFC 4226 Appendix D, count = 0:
        //   HMAC-SHA1 = 1f8698690e02ca16618550ef7f19da8e945b555a
        //   the low nibble of the last byte (0x5a -> 0xa = offset 10) selects the
        //   4-byte slice, and after masking the top bit the RFC's worked example
        //   gives Snum = 1284755224, which is the big-endian integer 0x4C93CF18.
        //   Snum % 10^6 = 755224 (the canonical 6-digit HOTP), % 10^8 = 84755224.
        //
        // NOTE: the task brief printed the slice as `50 ef 7f 19`; that is the raw
        // pre-mask slice text but does not arithmetically yield 1284755224
        // (0x50EF7F19 = 1357872921). The byte vector that reproduces the RFC's
        // documented Snum/HOTP is 0x4C93CF18, used here so the known-answer holds.
        let dt = [0x4C, 0x93, 0xCF, 0x18];
        assert_eq!(u32::from_be_bytes(dt) & 0x7FFF_FFFF, 1_284_755_224);
        assert_eq!(format_truncated(&dt, 6), "755224");
        assert_eq!(format_truncated(&dt, 8), "84755224");
    }

    #[test]
    fn format_zero_pads() {
        // Pick bytes whose masked value mod 10^6 is small to force padding.
        // 0x00000001 -> 1 -> "000001"
        assert_eq!(format_truncated(&[0x00, 0x00, 0x00, 0x01], 6), "000001");
    }

    #[test]
    fn parse_truncated_response_roundtrip() {
        // [digits=6, 4C 93 CF 18] -> RFC 4226 canonical 755224.
        let value = [6, 0x4C, 0x93, 0xCF, 0x18];
        let otp = parse_truncated_response(&value).unwrap();
        assert_eq!(otp.digits, 6);
        assert_eq!(otp.code, "755224");
    }

    #[test]
    fn parse_truncated_response_rejects_bad_length() {
        assert_eq!(
            parse_truncated_response(&[6, 0x4C, 0x93]),
            Err(ParseError::BadTruncatedResponse)
        );
    }

    // --- APDU framing ----------------------------------------------------

    #[test]
    fn select_bytes() {
        assert_eq!(
            select(),
            vec![0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01]
        );
    }

    #[test]
    fn put_bytes_fixed_vector() {
        // name = "ab", secret = 01 02 03, TOTP/SHA1, 6 digits, no touch.
        let params = PutParams {
            name: "ab",
            secret: &[0x01, 0x02, 0x03],
            oath_type: OathType::Totp,
            algorithm: Algorithm::Sha1,
            digits: 6,
            require_touch: false,
            imf: 0,
        };
        let apdu = put(&params);
        // header: 00 01 00 00
        // NAME(71) len2 "ab" = 71 02 61 62
        // KEY(73) len5: prefix (0x20|0x01=0x21) digits(06) secret(01 02 03)
        //   = 73 05 21 06 01 02 03
        // Lc = 4 + 7 = 11 = 0x0B
        let expected = vec![
            0x00, 0x01, 0x00, 0x00, 0x0B, // header + Lc
            0x71, 0x02, 0x61, 0x62, // NAME "ab"
            0x73, 0x05, 0x21, 0x06, 0x01, 0x02, 0x03, // KEY
        ];
        assert_eq!(apdu, expected);
    }

    #[test]
    fn put_bytes_with_touch_and_imf() {
        let params = PutParams {
            name: "x",
            secret: &[0xAA],
            oath_type: OathType::Hotp,
            algorithm: Algorithm::Sha256,
            digits: 8,
            require_touch: true,
            imf: 1,
        };
        let apdu = put(&params);
        let expected = vec![
            0x00, 0x01, 0x00, 0x00,
            // Lc: NAME(71 01 78)=3 + KEY(73 03 12 08 AA)=5 + PROP(78 01 02)=3 + IMF(7A 04 00000001)=6 = 17 = 0x11
            0x11,
            0x71, 0x01, 0x78, // NAME "x"
            0x73, 0x03, 0x12, 0x08, 0xAA, // KEY: prefix 0x10|0x02=0x12, digits 8
            0x78, 0x01, 0x02, // PROPERTY require-touch
            0x7A, 0x04, 0x00, 0x00, 0x00, 0x01, // IMF = 1
        ];
        assert_eq!(apdu, expected);
    }

    #[test]
    fn calculate_bytes_fixed_vector() {
        let challenge = [0x00, 0x00, 0x00, 0x00, 0x03, 0x4F, 0x09, 0x6D];
        let apdu = calculate("ab", &challenge);
        // header: 00 A2 00 01 (P2 truncated)
        // NAME(71) 02 "ab", CHALLENGE(74) 08 <8 bytes>
        // Lc = 4 + 10 = 14 = 0x0E
        let expected = vec![
            0x00, 0xA2, 0x00, 0x01, 0x0E,
            0x71, 0x02, 0x61, 0x62,
            0x74, 0x08, 0x00, 0x00, 0x00, 0x00, 0x03, 0x4F, 0x09, 0x6D,
        ];
        assert_eq!(apdu, expected);
    }

    #[test]
    fn delete_bytes() {
        let apdu = delete("ab");
        assert_eq!(apdu, vec![0x00, 0x02, 0x00, 0x00, 0x04, 0x71, 0x02, 0x61, 0x62]);
    }

    #[test]
    fn list_and_send_remaining_are_case2() {
        assert_eq!(list(), vec![0x00, 0xA1, 0x00, 0x00, 0x00]);
        assert_eq!(send_remaining(), vec![0x00, 0xA5, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn totp_challenge_counter() {
        // unix 1111111111, period 30 -> floor = 37037037 = 0x0235_23ED
        assert_eq!(37_037_037u32.to_be_bytes(), [0x02, 0x35, 0x23, 0xED]);
        assert_eq!(
            totp_challenge(1_111_111_111, 30),
            [0x00, 0x00, 0x00, 0x00, 0x02, 0x35, 0x23, 0xED]
        );
    }

    // --- TLV round-trip --------------------------------------------------

    #[test]
    fn list_parse_roundtrip() {
        // Two NAME_LIST entries built by hand:
        //   72 03 21 'a' 'b'   -> TOTP/SHA1 "ab"
        //   72 04 13 'f' 'o' 'o' -> HOTP/SHA512 "foo"
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x72, 0x03, 0x21, b'a', b'b']);
        buf.extend_from_slice(&[0x72, 0x04, 0x13, b'f', b'o', b'o']);

        let creds = parse_list(&buf).unwrap();
        assert_eq!(creds.len(), 2);
        assert_eq!(
            creds[0],
            CredentialInfo {
                name: "ab".to_owned(),
                oath_type: OathType::Totp,
                algorithm: Algorithm::Sha1,
            }
        );
        assert_eq!(
            creds[1],
            CredentialInfo {
                name: "foo".to_owned(),
                oath_type: OathType::Hotp,
                algorithm: Algorithm::Sha512,
            }
        );
    }

    #[test]
    fn parse_tlvs_detects_truncation() {
        // tag 71, claims length 5 but only 2 bytes follow.
        assert_eq!(parse_tlvs(&[0x71, 0x05, 0x61, 0x62]), Err(ParseError::Truncated));
    }

    #[test]
    fn parse_list_rejects_bad_prefix() {
        // prefix 0x99: type nibble 0x90 unknown.
        let buf = [0x72, 0x02, 0x99, b'a'];
        assert_eq!(parse_list(&buf), Err(ParseError::BadPrefix(0x99)));
    }

    #[test]
    fn select_response_version_tag() {
        // A minimal SELECT bag: VERSION(79) 03 05 02 04
        let buf = [0x79, 0x03, 0x05, 0x02, 0x04];
        let tlvs = parse_tlvs(&buf).unwrap();
        assert_eq!(find_tag(&tlvs, Tag::Version), Some(&[0x05, 0x02, 0x04][..]));
        // No password challenge present.
        assert_eq!(find_tag(&tlvs, Tag::Challenge), None);
    }

    #[test]
    fn parse_calculate_extracts_code() {
        // CALCULATE response with a TRUNCATED_RESPONSE(76) 05 06 4C 93 CF 18
        let buf = [0x76, 0x05, 0x06, 0x4C, 0x93, 0xCF, 0x18];
        let otp = parse_calculate(&buf).unwrap();
        assert_eq!(otp.code, "755224");
        assert_eq!(otp.digits, 6);
    }

    #[test]
    fn prefix_byte_composition() {
        assert_eq!(prefix_byte(OathType::Totp, Algorithm::Sha1), 0x21);
        assert_eq!(prefix_byte(OathType::Hotp, Algorithm::Sha256), 0x12);
        assert_eq!(prefix_byte(OathType::Hotp, Algorithm::Sha512), 0x13);
    }
}
