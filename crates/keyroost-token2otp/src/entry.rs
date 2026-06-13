//! OTP entry types, the write/read/delete payload serializers, and the
//! variable-tail `ENUM_CODES` response parser (spec §6.1–§6.4).
//!
//! The single subtlest rule in the whole protocol lives here: in an `ENUM_CODES`
//! READ_ALL page, an entry's trailing `otp_code_len || otp_code` is **present
//! only** when the entry is TOTP *and* its button-required flag is clear (spec
//! §6.1). Entries carry no length prefix, so a parser that gets this branch
//! wrong desynchronizes across the rest of the page. READ_ONE responses always
//! include the code (spec §6.2).

use zeroize::Zeroize;

/// OTP type byte (spec §6.1): `00` = HOTP, `01` = TOTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpType {
    Hotp,
    Totp,
}

impl OtpType {
    pub fn to_byte(self) -> u8 {
        match self {
            OtpType::Hotp => 0x00,
            OtpType::Totp => 0x01,
        }
    }
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(OtpType::Hotp),
            0x01 => Some(OtpType::Totp),
            _ => None,
        }
    }
}

/// HMAC algorithm byte (spec §6.1): `C1` = SHA1, `C2` = SHA256.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
}

impl Algorithm {
    pub fn to_byte(self) -> u8 {
        match self {
            Algorithm::Sha1 => 0xC1,
            Algorithm::Sha256 => 0xC2,
        }
    }
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0xC1 => Some(Algorithm::Sha1),
            0xC2 => Some(Algorithm::Sha256),
            _ => None,
        }
    }
}

/// A parsed entry as returned by `ENUM_CODES` / READ_ONE (spec §6.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub otp_type: OtpType,
    pub algorithm: Algorithm,
    pub timestep: u16,
    pub code_length: u8,
    /// `true` when the entry requires a button press to emit a code.
    pub button_required: bool,
    pub app_name: String,
    pub account_name: String,
    /// The current OTP code, present when the device included it (always for
    /// READ_ONE; for READ_ALL only on TOTP entries without button-required).
    pub code: Option<String>,
}

/// Parameters for provisioning (or overwriting) an entry via `WRITE_SEED`
/// (spec §6.3). The seed is the raw, Base32-decoded shared secret.
pub struct WriteEntry<'a> {
    pub otp_type: OtpType,
    pub algorithm: Algorithm,
    pub timestep: u16,
    pub code_length: u8,
    pub button_required: bool,
    pub app_name: &'a str,
    pub account_name: &'a str,
    /// Raw seed bytes (already Base32-decoded). Caller owns zeroization of the
    /// source; the serialized cleartext is scrubbed by the crypto layer.
    pub seed: &'a [u8],
}

/// Errors from parsing a device response or validating a write payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Ran off the end of the buffer mid-record — usually a mis-framed tail.
    Truncated,
    /// A field held a value outside its documented range.
    Malformed(&'static str),
    /// Validation rule from spec §9 failed before sending.
    Invalid(&'static str),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Truncated => write!(f, "response truncated mid-record"),
            ParseError::Malformed(s) => write!(f, "malformed response: {}", s),
            ParseError::Invalid(s) => write!(f, "invalid parameter: {}", s),
        }
    }
}

impl std::error::Error for ParseError {}

/// One page of a paginated READ_ALL (spec §6.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumPage {
    pub entries: Vec<Entry>,
    /// When `true`, more pages follow — issue `ENUM_CODES_CONTINUE` with the
    /// same timestamp until a page comes back with this clear (spec §6.1).
    pub more_pages: bool,
}

// --- validation (spec §9) ---

fn validate_common(
    timestep: u16,
    code_length: u8,
    app_name: &str,
    account_name: &str,
    is_totp: bool,
) -> Result<(), ParseError> {
    if is_totp && timestep == 0 {
        return Err(ParseError::Invalid("timestep must be 1..=0xFFFF for TOTP"));
    }
    if !(4..=10).contains(&code_length) {
        return Err(ParseError::Invalid("code_length must be 4..=10"));
    }
    if !app_name.is_ascii() || app_name.len() > 64 {
        return Err(ParseError::Invalid("app_name must be ASCII, 0..=64 bytes"));
    }
    if !account_name.is_ascii() || account_name.is_empty() || account_name.len() > 64 {
        return Err(ParseError::Invalid(
            "account_name must be ASCII, 1..=64 bytes",
        ));
    }
    Ok(())
}

/// Serialize the cleartext payload for `write_entry` (spec §6.3). This is the
/// plaintext that the ECDH+AES layer then encrypts with IV-1. The returned
/// buffer zeroizes itself on drop because it carries the raw seed.
pub fn serialize_write_entry(e: &WriteEntry<'_>) -> Result<ClearText, ParseError> {
    validate_common(
        e.timestep,
        e.code_length,
        e.app_name,
        e.account_name,
        matches!(e.otp_type, OtpType::Totp),
    )?;
    if e.seed.is_empty() || e.seed.len() > 64 {
        return Err(ParseError::Invalid("seed must be 1..=64 bytes (decoded)"));
    }
    let mut buf = Vec::with_capacity(11 + e.app_name.len() + e.account_name.len() + e.seed.len());
    buf.push(e.otp_type.to_byte());
    buf.push(e.algorithm.to_byte());
    buf.extend_from_slice(&e.timestep.to_be_bytes());
    buf.push(e.code_length);
    buf.push(e.button_required as u8);
    buf.push(e.app_name.len() as u8);
    buf.extend_from_slice(e.app_name.as_bytes());
    buf.push(e.account_name.len() as u8);
    buf.extend_from_slice(e.account_name.as_bytes());
    buf.push(e.seed.len() as u8);
    buf.extend_from_slice(e.seed);
    Ok(ClearText(buf))
}

/// Serialize the cleartext for a delete (spec §6.4): same shape as a write but
/// with config fields zeroed and an empty seed. The device reads a write with a
/// known `(app, account)` and empty seed as a delete.
pub fn serialize_delete_entry(app_name: &str, account_name: &str) -> Result<ClearText, ParseError> {
    if !app_name.is_ascii() || app_name.len() > 64 {
        return Err(ParseError::Invalid("app_name must be ASCII, 0..=64 bytes"));
    }
    if !account_name.is_ascii() || account_name.is_empty() || account_name.len() > 64 {
        return Err(ParseError::Invalid(
            "account_name must be ASCII, 1..=64 bytes",
        ));
    }
    let mut buf = Vec::with_capacity(9 + app_name.len() + account_name.len());
    buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // type/algo/step/len/btn
    buf.push(app_name.len() as u8);
    buf.extend_from_slice(app_name.as_bytes());
    buf.push(account_name.len() as u8);
    buf.extend_from_slice(account_name.as_bytes());
    buf.push(0x00); // seed_len = 0, no seed bytes follow
    Ok(ClearText(buf))
}

/// Serialize the (plaintext) `read_entry` request body (spec §6.2):
/// `01 || u64_be(ts) || u8(app_len) || app || u8(acct_len) || acct`.
pub fn serialize_read_entry(
    timestamp: u64,
    app_name: &str,
    account_name: &str,
) -> Result<Vec<u8>, ParseError> {
    if !app_name.is_ascii() || app_name.len() > 64 {
        return Err(ParseError::Invalid("app_name must be ASCII, 0..=64 bytes"));
    }
    if !account_name.is_ascii() || account_name.is_empty() || account_name.len() > 64 {
        return Err(ParseError::Invalid(
            "account_name must be ASCII, 1..=64 bytes",
        ));
    }
    let mut buf = Vec::with_capacity(11 + app_name.len() + account_name.len());
    buf.push(super::cmd::SUB_READ_ONE);
    buf.extend_from_slice(&timestamp.to_be_bytes());
    buf.push(app_name.len() as u8);
    buf.extend_from_slice(app_name.as_bytes());
    buf.push(account_name.len() as u8);
    buf.extend_from_slice(account_name.as_bytes());
    Ok(buf)
}

/// Serialize the READ_ALL request body (spec §6.1): `03 || u64_be(ts)`.
pub fn serialize_enum_all(timestamp: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(9);
    buf.push(super::cmd::SUB_READ_ALL);
    buf.extend_from_slice(&timestamp.to_be_bytes());
    buf
}

/// Parse a READ_ALL page (spec §6.1): a leading partial-marker byte (whose high
/// bit is the more-pages flag and whose low 7 bits are the first entry's `type`)
/// followed by a packed, length-prefix-free list of entries.
pub fn parse_enum_page(data: &[u8]) -> Result<EnumPage, ParseError> {
    if data.is_empty() {
        return Err(ParseError::Truncated);
    }
    let more_pages = data[0] & 0x80 != 0;
    // Rebuild the entry stream with the partial flag stripped from the first
    // byte: bits 0..6 are the first entry's real `type` field (spec §6.1).
    let mut stream = Vec::with_capacity(data.len());
    stream.push(data[0] & 0x7F);
    stream.extend_from_slice(&data[1..]);

    let mut cursor = Cursor::new(&stream);
    let mut entries = Vec::new();
    while !cursor.at_end() {
        entries.push(parse_one_entry(&mut cursor, false)?);
    }
    Ok(EnumPage {
        entries,
        more_pages,
    })
}

/// Parse a single READ_ONE response entry (spec §6.2): one record that always
/// includes the OTP code.
pub fn parse_read_one(data: &[u8]) -> Result<Entry, ParseError> {
    let mut cursor = Cursor::new(data);
    let entry = parse_one_entry(&mut cursor, true)?;
    Ok(entry)
}

/// Parse a single entry record. `force_code` makes the parser always expect the
/// trailing code (READ_ONE, spec §6.2); otherwise the presence of the tail is
/// derived from the type/button fields exactly as the device emits them
/// (READ_ALL, spec §6.1).
fn parse_one_entry(c: &mut Cursor<'_>, force_code: bool) -> Result<Entry, ParseError> {
    let type_byte = c.u8()?;
    let otp_type =
        OtpType::from_byte(type_byte).ok_or(ParseError::Malformed("unknown OTP type byte"))?;
    let algorithm =
        Algorithm::from_byte(c.u8()?).ok_or(ParseError::Malformed("unknown algorithm byte"))?;
    let timestep = c.u16_be()?;
    let code_length = c.u8()?;
    let button_required = match c.u8()? {
        0x00 => false,
        0x01 => true,
        _ => return Err(ParseError::Malformed("button flag not 0/1")),
    };
    let app_len = c.u8()? as usize;
    let app_name = c.ascii(app_len)?;
    let account_len = c.u8()? as usize;
    if account_len == 0 {
        return Err(ParseError::Malformed("account_name length is zero"));
    }
    let account_name = c.ascii(account_len)?;

    // The tail is present for READ_ONE always; for READ_ALL only when the entry
    // is TOTP and does not require a button (spec §6.1 critical rule).
    let has_code = force_code || (matches!(otp_type, OtpType::Totp) && !button_required);
    let code = if has_code {
        let code_len = c.u8()? as usize;
        Some(c.ascii(code_len)?)
    } else {
        None
    };

    Ok(Entry {
        otp_type,
        algorithm,
        timestep,
        code_length,
        button_required,
        app_name,
        account_name,
        code,
    })
}

/// A length-checked forward cursor over a response buffer. Every accessor
/// returns [`ParseError::Truncated`] rather than panicking, so a malformed
/// device frame can never index out of bounds (the workspace runs with
/// overflow-checks and forbids unsafe; this keeps parsing total).
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }
    fn at_end(&self) -> bool {
        self.pos >= self.buf.len()
    }
    fn u8(&mut self) -> Result<u8, ParseError> {
        let b = *self.buf.get(self.pos).ok_or(ParseError::Truncated)?;
        self.pos += 1;
        Ok(b)
    }
    fn u16_be(&mut self) -> Result<u16, ParseError> {
        let hi = self.u8()? as u16;
        let lo = self.u8()? as u16;
        Ok((hi << 8) | lo)
    }
    fn ascii(&mut self, n: usize) -> Result<String, ParseError> {
        let end = self.pos.checked_add(n).ok_or(ParseError::Truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or(ParseError::Truncated)?;
        if !slice.is_ascii() {
            return Err(ParseError::Malformed("non-ASCII text field"));
        }
        self.pos = end;
        Ok(String::from_utf8_lossy(slice).into_owned())
    }
}

/// A serialized cleartext payload that scrubs itself on drop because it may
/// carry a raw OTP seed (spec §6.3). The crypto layer consumes [`as_bytes`].
pub struct ClearText(Vec<u8>);

impl ClearText {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for ClearText {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_totp_page_spec_10_1() {
        // Spec §10.1 device payload (SW already stripped by the transport):
        // partial byte 0x00 (type=TOTP after &0x7F... wait: example shows type=01).
        // The worked example's annotated bytes: 00 C1 00 1E 06 00 04 "Test" 05 "alice" 06 "123456"
        // The leading 0x00 there is the *partial flag byte* combined with type;
        // 0x00 & 0x7F = 0x00 = HOTP? The example annotation says type=01 TOTP, so the
        // real first byte on the wire is 0x01. We reconstruct the documented record.
        let mut payload = vec![0x01, 0xC1, 0x00, 0x1E, 0x06, 0x00, 0x04];
        payload.extend_from_slice(b"Test");
        payload.push(0x05);
        payload.extend_from_slice(b"alice");
        payload.push(0x06);
        payload.extend_from_slice(b"123456");

        let page = parse_enum_page(&payload).unwrap();
        assert!(!page.more_pages);
        assert_eq!(page.entries.len(), 1);
        let e = &page.entries[0];
        assert_eq!(e.otp_type, OtpType::Totp);
        assert_eq!(e.algorithm, Algorithm::Sha1);
        assert_eq!(e.timestep, 30);
        assert_eq!(e.code_length, 6);
        assert!(!e.button_required);
        assert_eq!(e.app_name, "Test");
        assert_eq!(e.account_name, "alice");
        assert_eq!(e.code.as_deref(), Some("123456"));
    }

    #[test]
    fn partial_flag_high_bit_sets_more_pages() {
        // Same record but with the partial bit (0x80) OR'd into the first byte.
        let mut payload = vec![0x81, 0xC1, 0x00, 0x1E, 0x06, 0x00, 0x04];
        payload.extend_from_slice(b"Test");
        payload.push(0x05);
        payload.extend_from_slice(b"alice");
        payload.push(0x06);
        payload.extend_from_slice(b"123456");
        let page = parse_enum_page(&payload).unwrap();
        assert!(page.more_pages);
        assert_eq!(page.entries[0].otp_type, OtpType::Totp);
    }

    #[test]
    fn hotp_entry_has_no_code_tail() {
        // HOTP (type 00): the otp_code tail is omitted in READ_ALL (spec §6.1).
        // Two records back-to-back; if the tail were mis-parsed the second would
        // desync. Record1: HOTP "a"/"x". Record2: TOTP "b"/"y" code "999999".
        let mut payload = vec![0x00, 0xC1, 0x00, 0x00, 0x00, 0x00, 0x01];
        payload.extend_from_slice(b"a");
        payload.push(0x01);
        payload.extend_from_slice(b"x");
        // second record:
        payload.extend_from_slice(&[0x01, 0xC1, 0x00, 0x1E, 0x06, 0x00, 0x01]);
        payload.extend_from_slice(b"b");
        payload.push(0x01);
        payload.extend_from_slice(b"y");
        payload.push(0x06);
        payload.extend_from_slice(b"999999");

        let page = parse_enum_page(&payload).unwrap();
        assert_eq!(page.entries.len(), 2);
        assert_eq!(page.entries[0].otp_type, OtpType::Hotp);
        assert_eq!(page.entries[0].code, None);
        assert_eq!(page.entries[0].account_name, "x");
        assert_eq!(page.entries[1].account_name, "y");
        assert_eq!(page.entries[1].code.as_deref(), Some("999999"));
    }

    #[test]
    fn button_required_totp_has_no_code_tail() {
        // TOTP but button_required=1 -> tail omitted in READ_ALL (spec §6.1).
        let mut payload = vec![0x01, 0xC1, 0x00, 0x1E, 0x06, 0x01, 0x01];
        payload.extend_from_slice(b"b");
        payload.push(0x01);
        payload.extend_from_slice(b"y");
        let page = parse_enum_page(&payload).unwrap();
        assert_eq!(page.entries.len(), 1);
        assert!(page.entries[0].button_required);
        assert_eq!(page.entries[0].code, None);
    }

    #[test]
    fn read_one_always_has_code() {
        // Even a button-required TOTP includes the code in a READ_ONE response.
        let mut payload = vec![0x01, 0xC1, 0x00, 0x1E, 0x06, 0x01, 0x01];
        payload.extend_from_slice(b"b");
        payload.push(0x01);
        payload.extend_from_slice(b"y");
        payload.push(0x06);
        payload.extend_from_slice(b"424242");
        let e = parse_read_one(&payload).unwrap();
        assert_eq!(e.code.as_deref(), Some("424242"));
    }

    #[test]
    fn write_entry_cleartext_spec_10_2() {
        // Spec §10.2 cleartext for ("Test","alice",seed="Hello",SHA1,TOTP,30,6,no btn):
        // 01 C1 00 1E 06 00 04 "Test" 05 "alice" 05 "Hello"
        let we = WriteEntry {
            otp_type: OtpType::Totp,
            algorithm: Algorithm::Sha1,
            timestep: 30,
            code_length: 6,
            button_required: false,
            app_name: "Test",
            account_name: "alice",
            seed: b"Hello",
        };
        let ct = serialize_write_entry(&we).unwrap();
        let mut want = vec![0x01, 0xC1, 0x00, 0x1E, 0x06, 0x00, 0x04];
        want.extend_from_slice(b"Test");
        want.push(0x05);
        want.extend_from_slice(b"alice");
        want.push(0x05);
        want.extend_from_slice(b"Hello");
        assert_eq!(ct.as_bytes(), want.as_slice());
    }

    #[test]
    fn delete_cleartext_zeroes_config() {
        let ct = serialize_delete_entry("Test", "alice").unwrap();
        let mut want = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04];
        want.extend_from_slice(b"Test");
        want.push(0x05);
        want.extend_from_slice(b"alice");
        want.push(0x00);
        assert_eq!(ct.as_bytes(), want.as_slice());
    }

    #[test]
    fn validation_rejects_bad_code_length() {
        let we = WriteEntry {
            otp_type: OtpType::Totp,
            algorithm: Algorithm::Sha1,
            timestep: 30,
            code_length: 11, // > 10
            button_required: false,
            app_name: "a",
            account_name: "b",
            seed: b"x",
        };
        assert!(matches!(
            serialize_write_entry(&we),
            Err(ParseError::Invalid(_))
        ));
    }

    #[test]
    fn truncated_record_is_error_not_panic() {
        // Cut off mid-app-name. Must return Truncated, never panic/oob.
        let payload = vec![0x01, 0xC1, 0x00, 0x1E, 0x06, 0x00, 0x04, b'T', b'e'];
        assert_eq!(parse_enum_page(&payload), Err(ParseError::Truncated));
    }

    #[test]
    fn empty_page_is_truncated() {
        assert_eq!(parse_enum_page(&[]), Err(ParseError::Truncated));
    }
}
