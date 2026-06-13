//! Token2 OTP-on-FIDO management protocol — pure byte layer.
//!
//! Token2's PIN+ / FIDO2+ security keys can store TOTP/HOTP entries that the
//! key computes on-device. The host manages those entries over a proprietary
//! APDU protocol (distinct from CTAP/FIDO2) carried on either USB-HID feature
//! reports or PC/SC. This crate is the I/O-free half — APDU builders, the
//! enumerate-response parser, the device-info bit decoder, and the cleartext
//! payload builders for the encrypted write path — the same shape as
//! [`keyroost_oath`](https://docs.rs/keyroost-oath) and the other applet byte
//! layers. It performs **no card I/O and no crypto**: the transport (HID
//! chunking / PC/SC) and the ECDH+AES blob construction for `write_entry`
//! live a layer up, where the dependencies are allowed.
//!
//! Implemented from the vendor's published *OTP on FIDO Command Manual*
//! (§§1.1–1.11) via the protocol reference in issue #20. All multi-byte
//! integers are big-endian; length-prefixed strings are one length byte then
//! raw ASCII bytes. The worked byte traces in the spec's §10 are reproduced
//! as known-answer tests below.

#![forbid(unsafe_code)]

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Management-applet AID (`SELECT` by name selects the OTP applet over PC/SC).
pub const AID_OTP: [u8; 8] = [0xF0, 0x00, 0x00, 0x01, 0x4F, 0x74, 0x70, 0x01];
/// FIDO-applet AID — must be SELECTed before reading the serial over PC/SC.
pub const AID_FIDO: [u8; 8] = [0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01];

/// Status word: success.
pub const SW_OK: u16 = 0x9000;

/// A `CLA INS P1 P2` command header from the §6 table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Command(pub u8, pub u8, pub u8, pub u8);

impl Command {
    /// `WRITE_HOTP_SEED` — set the button-press HOTP seed (encrypted, IV-2).
    pub const WRITE_HOTP_SEED: Command = Command(0x80, 0xC5, 0x00, 0x00);
    /// `GET_ECDH_PUBKEY` — fetch the device's P-256 public key (64 bytes).
    pub const GET_ECDH_PUBKEY: Command = Command(0x80, 0xC5, 0x01, 0x00);
    /// `READ_CONFIG` — read the device-info blob.
    pub const READ_CONFIG: Command = Command(0x80, 0xC5, 0x02, 0x00);
    /// `SET_DEVICE_TYPE` — enable/disable USB interfaces (bitmask of disables).
    pub const SET_DEVICE_TYPE: Command = Command(0x80, 0xC5, 0x02, 0x01);
    /// `CFG_HOTP_ENTER` — button-HOTP trailing-Enter config.
    pub const CFG_HOTP_ENTER: Command = Command(0x80, 0xC5, 0x02, 0x02);
    /// `CFG_HOTP_TOUCH` — button-HOTP long-touch config.
    pub const CFG_HOTP_TOUCH: Command = Command(0x80, 0xC5, 0x02, 0x04);
    /// `ENABLE_TOTP` — enable/disable the TOTP function (1-byte 00/01).
    pub const ENABLE_TOTP: Command = Command(0x80, 0xC5, 0x02, 0x05);
    /// `CFG_HOTP_KBD_TYPE` — button-HOTP keypad-vs-row config.
    pub const CFG_HOTP_KBD_TYPE: Command = Command(0x80, 0xC5, 0x02, 0x06);
    /// `ENUM_CODES` — read one / enumerate entries (subcommand in data).
    pub const ENUM_CODES: Command = Command(0x80, 0xC5, 0x05, 0x00);
    /// `ENUM_CODES_CONTINUE` — next page of an enumeration.
    pub const ENUM_CODES_CONTINUE: Command = Command(0x80, 0xC5, 0x05, 0x01);
    /// `WRITE_SEED` — write/delete an entry (encrypted, IV-1), or erase-all
    /// when sent with empty data.
    pub const WRITE_SEED: Command = Command(0x80, 0xC5, 0x05, 0x02);
    /// `GET_INFO` on the FIDO applet — used to read the serial number.
    pub const GET_INFO: Command = Command(0x80, 0x33, 0x00, 0x00);
}

/// `ENUM_CODES` subcommand byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EnumSub {
    /// Read a single named entry (always includes the OTP code).
    ReadOne = 0x01,
    /// Read code only, no metadata (unused by the reference client).
    GetMetadata = 0x02,
    /// Enumerate all entries (the only paginating mode).
    ReadAll = 0x03,
}

/// AES-CBC IV for OTP-entry writes/deletes (`WRITE_SEED`). A constant by
/// design — freshness comes from the per-command ephemeral keypair.
pub const IV_ENTRY: [u8; 16] = [
    0x9D, 0xD8, 0x91, 0x8E, 0x34, 0xF3, 0xCC, 0xAB, 0x08, 0xCB, 0x75, 0x18, 0xF7, 0x19, 0x38, 0xF1,
];
/// AES-CBC IV for button-HOTP seed writes/deletes (`WRITE_HOTP_SEED`).
pub const IV_BTN_HOTP: [u8; 16] = [0u8; 16];

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A device status word, mapped to its protocol meaning (§3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusError {
    /// `6A 80` / `6A 83` — entry not found (also "empty token" on enumerate).
    EntryNotFound,
    /// `6A 84` — not enough space on the device.
    NotEnoughSpace,
    /// `6A 86` — HOTP-over-HID not supported on this model.
    HidNotSupported,
    /// `6F F9` — timed out waiting for a button press.
    ButtonPressRequired,
    /// Any other non-`9000` word.
    BadStatus(u16),
}

impl core::fmt::Display for StatusError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StatusError::EntryNotFound => write!(f, "entry not found"),
            StatusError::NotEnoughSpace => write!(f, "not enough space on the device"),
            StatusError::HidNotSupported => {
                write!(f, "HOTP over HID is not supported on this model")
            }
            StatusError::ButtonPressRequired => write!(f, "timed out waiting for a button press"),
            StatusError::BadStatus(sw) => write!(f, "unexpected status word {sw:#06X}"),
        }
    }
}

impl std::error::Error for StatusError {}

/// Map a 16-bit status word to `Ok(())` or the corresponding [`StatusError`].
pub fn check_status(sw: u16) -> Result<(), StatusError> {
    match sw {
        SW_OK => Ok(()),
        0x6A80 | 0x6A83 => Err(StatusError::EntryNotFound),
        0x6A84 => Err(StatusError::NotEnoughSpace),
        0x6A86 => Err(StatusError::HidNotSupported),
        0x6FF9 => Err(StatusError::ButtonPressRequired),
        other => Err(StatusError::BadStatus(other)),
    }
}

/// Errors building a request from caller input (the §9 validation rules).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildError {
    /// `timestep` outside `1..=0xFFFF`.
    BadTimestep,
    /// `code_length` outside `4..=10` (entries) or not 6/8 (button HOTP).
    BadCodeLength,
    /// `app_name` longer than 64 bytes, or not ASCII.
    BadAppName,
    /// `account_name` empty, longer than 64 bytes, or not ASCII.
    BadAccountName,
    /// Decoded seed empty or longer than 64 bytes.
    BadSeed,
}

impl core::fmt::Display for BuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BuildError::BadTimestep => write!(f, "timestep must be 1..=65535"),
            BuildError::BadCodeLength => write!(f, "code length out of range"),
            BuildError::BadAppName => write!(f, "app name must be 0..=64 ASCII bytes"),
            BuildError::BadAccountName => write!(f, "account name must be 1..=64 ASCII bytes"),
            BuildError::BadSeed => write!(f, "seed must be 1..=64 bytes"),
        }
    }
}

impl std::error::Error for BuildError {}

/// Errors parsing a device response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// A field's length ran past the end of the buffer.
    Truncated,
    /// A response tag/marker didn't match what the command expects.
    BadResponse,
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ParseError::Truncated => write!(f, "Token2 OTP response truncated"),
            ParseError::BadResponse => write!(f, "malformed Token2 OTP response"),
        }
    }
}

impl std::error::Error for ParseError {}

// ---------------------------------------------------------------------------
// APDU framing (§3)
// ---------------------------------------------------------------------------

/// Serialize an APDU in the protocol's wire form. PC/SC `SELECT` uses the
/// short single-byte `Lc`; everything else uses the extended 3-byte form
/// (`00 Lc_hi Lc_lo`). Empty data emits no `Lc` at all (case-1).
#[must_use]
pub fn serialize_apdu(cmd: Command, data: &[u8]) -> Vec<u8> {
    serialize_apdu_inner(cmd, data, false)
}

/// [`serialize_apdu`] but forcing the short `Lc` form — only valid for the
/// PC/SC `SELECT`, whose data is the 8-byte AID.
#[must_use]
pub fn serialize_select(aid: &[u8]) -> Vec<u8> {
    serialize_apdu_inner(Command(0x00, 0xA4, 0x04, 0x00), aid, true)
}

fn serialize_apdu_inner(cmd: Command, data: &[u8], short_lc: bool) -> Vec<u8> {
    let Command(cla, ins, p1, p2) = cmd;
    let mut out = Vec::with_capacity(4 + 3 + data.len());
    out.extend_from_slice(&[cla, ins, p1, p2]);
    if data.is_empty() {
        return out;
    }
    if short_lc {
        debug_assert!(data.len() <= 255);
        out.push(data.len() as u8);
    } else {
        // Extended: 00 || Lc_hi || Lc_lo (the spec uses extended Lc for every
        // command except SELECT; host-built data never exceeds 16 bits).
        debug_assert!(data.len() <= 0xFFFF);
        out.push(0x00);
        out.push((data.len() >> 8) as u8);
        out.push(data.len() as u8);
    }
    out.extend_from_slice(data);
    out
}

// ---------------------------------------------------------------------------
// Entry model + enumerate request/response (§6.1, §6.2)
// ---------------------------------------------------------------------------

/// OTP entry kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpKind {
    Hotp,
    Totp,
}

impl OtpKind {
    #[must_use]
    pub const fn id(self) -> u8 {
        match self {
            OtpKind::Hotp => 0x00,
            OtpKind::Totp => 0x01,
        }
    }
    #[must_use]
    pub const fn from_id(id: u8) -> Option<Self> {
        match id {
            0x00 => Some(OtpKind::Hotp),
            0x01 => Some(OtpKind::Totp),
            _ => None,
        }
    }
}

/// HMAC algorithm for an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpAlgorithm {
    Sha1,
    Sha256,
}

impl OtpAlgorithm {
    #[must_use]
    pub const fn id(self) -> u8 {
        match self {
            OtpAlgorithm::Sha1 => 0xC1,
            OtpAlgorithm::Sha256 => 0xC2,
        }
    }
    #[must_use]
    pub const fn from_id(id: u8) -> Option<Self> {
        match id {
            0xC1 => Some(OtpAlgorithm::Sha1),
            0xC2 => Some(OtpAlgorithm::Sha256),
            _ => None,
        }
    }
}

/// One enumerated entry. `code` is present when the device returned it (always
/// for `READ_ONE`; for `READ_ALL` only on TOTP entries that don't require a
/// button press — see the §6.1 variable-tail rule).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub kind: OtpKind,
    pub algorithm: OtpAlgorithm,
    pub timestep: u16,
    pub code_length: u8,
    pub button_required: bool,
    pub app_name: String,
    pub account_name: String,
    pub code: Option<String>,
}

/// The fields needed to provision (write) an entry. `seed` is the raw,
/// already-Base32-decoded shared secret.
#[derive(Debug, Clone)]
pub struct NewEntry<'a> {
    pub kind: OtpKind,
    pub algorithm: OtpAlgorithm,
    pub timestep: u16,
    pub code_length: u8,
    pub button_required: bool,
    pub app_name: &'a str,
    pub account_name: &'a str,
    pub seed: &'a [u8],
}

fn validate_names(app: &str, account: &str) -> Result<(), BuildError> {
    if app.len() > 64 || !app.is_ascii() {
        return Err(BuildError::BadAppName);
    }
    if account.is_empty() || account.len() > 64 || !account.is_ascii() {
        return Err(BuildError::BadAccountName);
    }
    Ok(())
}

/// `ENUM_CODES` request data to enumerate all entries at `timestamp` (seconds):
/// `0x03 || u64_be(timestamp)`. Pair with [`Command::ENUM_CODES`].
#[must_use]
pub fn enum_all_request(timestamp: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(9);
    v.push(EnumSub::ReadAll as u8);
    v.extend_from_slice(&timestamp.to_be_bytes());
    v
}

/// `ENUM_CODES_CONTINUE` request data: `u64_be(timestamp)`.
#[must_use]
pub fn enum_continue_request(timestamp: u64) -> Vec<u8> {
    timestamp.to_be_bytes().to_vec()
}

/// `ENUM_CODES` request data to read one entry (§6.2):
/// `0x01 || u64_be(ts) || u8(app_len) || app || u8(acct_len) || acct`.
pub fn read_one_request(
    timestamp: u64,
    app_name: &str,
    account_name: &str,
) -> Result<Vec<u8>, BuildError> {
    validate_names(app_name, account_name)?;
    let mut v = Vec::with_capacity(9 + 2 + app_name.len() + account_name.len());
    v.push(EnumSub::ReadOne as u8);
    v.extend_from_slice(&timestamp.to_be_bytes());
    v.push(app_name.len() as u8);
    v.extend_from_slice(app_name.as_bytes());
    v.push(account_name.len() as u8);
    v.extend_from_slice(account_name.as_bytes());
    Ok(v)
}

/// Cleartext payload for `write_entry` (§6.3), to be ECDH+AES-wrapped with
/// [`IV_ENTRY`] by the transport before sending as `WRITE_SEED`.
pub fn write_entry_cleartext(e: &NewEntry<'_>) -> Result<Vec<u8>, BuildError> {
    if e.timestep == 0 {
        return Err(BuildError::BadTimestep);
    }
    if !(4..=10).contains(&e.code_length) {
        return Err(BuildError::BadCodeLength);
    }
    validate_names(e.app_name, e.account_name)?;
    if e.seed.is_empty() || e.seed.len() > 64 {
        return Err(BuildError::BadSeed);
    }
    let mut v = Vec::new();
    v.push(e.kind.id());
    v.push(e.algorithm.id());
    v.extend_from_slice(&e.timestep.to_be_bytes());
    v.push(e.code_length);
    v.push(u8::from(e.button_required));
    v.push(e.app_name.len() as u8);
    v.extend_from_slice(e.app_name.as_bytes());
    v.push(e.account_name.len() as u8);
    v.extend_from_slice(e.account_name.as_bytes());
    v.push(e.seed.len() as u8);
    v.extend_from_slice(e.seed);
    Ok(v)
}

/// Cleartext payload for `delete_entry` (§6.4): the write shape with all
/// configurable fields zeroed and an empty seed. ECDH+AES-wrap with
/// [`IV_ENTRY`] and send as `WRITE_SEED`.
pub fn delete_entry_cleartext(app_name: &str, account_name: &str) -> Result<Vec<u8>, BuildError> {
    validate_names(app_name, account_name)?;
    let mut v = Vec::new();
    v.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // type/algo/timestep/codelen/btn
    v.push(app_name.len() as u8);
    v.extend_from_slice(app_name.as_bytes());
    v.push(account_name.len() as u8);
    v.extend_from_slice(account_name.as_bytes());
    v.push(0x00); // seed_len = 0
    Ok(v)
}

/// Parse an `ENUM_CODES` / `ENUM_CODES_CONTINUE` response page (§6.1).
///
/// Returns the parsed entries and whether more pages follow (the high bit of
/// the leading partial-marker byte). `full_decode` must be `true` for a
/// `READ_ONE` response (the code is always present) and `false` for a
/// `READ_ALL` page (the code tail is omitted for HOTP / button-required
/// entries — the parser branches on those fields, per the §6.1 critical rule).
pub fn parse_entries(buf: &[u8], full_decode: bool) -> Result<(Vec<Entry>, bool), ParseError> {
    let (&marker, mut rest) = buf.split_first().ok_or(ParseError::Truncated)?;
    let more_pages = marker & 0x80 != 0;
    // The partial flag shares the leading byte with the first entry's `type`
    // field: bit 7 is the flag, bits 0–6 are the type. Reconstruct a buffer
    // whose first byte is just the type so the field walker is uniform.
    let mut first = Vec::with_capacity(rest.len() + 1);
    first.push(marker & 0x7F);
    first.extend_from_slice(rest);
    rest = &first;

    let mut entries = Vec::new();
    let mut pos = 0usize;
    while pos < rest.len() {
        let (entry, consumed) = parse_one_entry(&rest[pos..], full_decode)?;
        entries.push(entry);
        pos += consumed;
    }
    Ok((entries, more_pages))
}

/// Parse a single `READ_ONE` entry record (always includes the code).
pub fn parse_one_entry_full(buf: &[u8]) -> Result<Entry, ParseError> {
    let (entry, _) = parse_one_entry(buf, true)?;
    Ok(entry)
}

fn parse_one_entry(buf: &[u8], full_decode: bool) -> Result<(Entry, usize), ParseError> {
    // Fixed head: type, algorithm, timestep(2), code_length, btn_flag.
    let head = buf.get(..6).ok_or(ParseError::Truncated)?;
    let kind = OtpKind::from_id(head[0]).ok_or(ParseError::BadResponse)?;
    let algorithm = OtpAlgorithm::from_id(head[1]).ok_or(ParseError::BadResponse)?;
    let timestep = u16::from_be_bytes([head[2], head[3]]);
    let code_length = head[4];
    let button_required = head[5] != 0;
    let mut pos = 6;

    let app_name = take_lp_string(buf, &mut pos)?;
    let account_name = take_lp_string(buf, &mut pos)?;

    // The OTP-code tail is present only for READ_ONE, or for a READ_ALL entry
    // that is TOTP *and* not button-required. Get this branch wrong and the
    // rest of the page mis-frames (§6.1).
    let code = if full_decode || (kind == OtpKind::Totp && !button_required) {
        Some(take_lp_string(buf, &mut pos)?)
    } else {
        None
    };

    Ok((
        Entry {
            kind,
            algorithm,
            timestep,
            code_length,
            button_required,
            app_name,
            account_name,
            code,
        },
        pos,
    ))
}

/// Read a one-byte-length-prefixed ASCII string, advancing `pos`.
fn take_lp_string(buf: &[u8], pos: &mut usize) -> Result<String, ParseError> {
    let len = *buf.get(*pos).ok_or(ParseError::Truncated)? as usize;
    let start = *pos + 1;
    let end = start.checked_add(len).ok_or(ParseError::Truncated)?;
    let bytes = buf.get(start..end).ok_or(ParseError::Truncated)?;
    *pos = end;
    // Names/codes are ASCII per the spec; lossy keeps the parser panic-free on
    // a non-conforming device rather than erroring out a whole page.
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

// ---------------------------------------------------------------------------
// Device info (§6.9) + serial (§6.10)
// ---------------------------------------------------------------------------

/// Decoded `READ_CONFIG` device-info blob (§6.9). Bit positions are 1-based in
/// the manual; "bit 1" is `value & 0x01`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    pub transfer_type: u8,
    pub device_config: u8,
    pub appearance: [u8; 4],
    pub fido_version: [u8; 3],
    pub device_extension: u8,
}

impl DeviceInfo {
    // --- transfer_type (byte 0) ---
    #[must_use]
    pub fn fido_disabled(&self) -> bool {
        self.transfer_type & 0x01 != 0
    }
    #[must_use]
    pub fn keystroke_hotp_disabled(&self) -> bool {
        self.transfer_type & 0x02 != 0
    }

    // --- device_config (byte 1) ---
    #[must_use]
    pub fn hotp_suppresses_enter(&self) -> bool {
        self.device_config & 0x01 != 0
    }
    #[must_use]
    pub fn fido_pin_set(&self) -> bool {
        self.device_config & 0x02 != 0
    }
    #[must_use]
    pub fn hotp_supported(&self) -> bool {
        self.device_config & 0x04 != 0
    }
    #[must_use]
    pub fn fingerprint_present(&self) -> bool {
        self.device_config & 0x08 != 0
    }
    #[must_use]
    pub fn nfc_supported(&self) -> bool {
        self.device_config & 0x10 != 0
    }
    #[must_use]
    pub fn hotp_long_press(&self) -> bool {
        self.device_config & 0x20 != 0
    }
    #[must_use]
    pub fn pin_locked(&self) -> bool {
        self.device_config & 0x40 != 0
    }
    #[must_use]
    pub fn button_hotp_configured(&self) -> bool {
        self.device_config & 0x80 != 0
    }

    // --- device_extension (byte 9) ---
    #[must_use]
    pub fn totp_supported(&self) -> bool {
        self.device_extension & 0x01 != 0
    }
    #[must_use]
    pub fn fido_2_1_supported(&self) -> bool {
        self.device_extension & 0x02 != 0
    }
    #[must_use]
    pub fn fingerprint_registration_supported(&self) -> bool {
        self.device_extension & 0x04 != 0
    }
    #[must_use]
    pub fn hotp_uses_numpad(&self) -> bool {
        self.device_extension & 0x08 != 0
    }
    #[must_use]
    pub fn ccid_supported(&self) -> bool {
        self.device_extension & 0x10 != 0
    }
    /// Note the inverted sense in the manual: bit 6 set means button-HOTP is
    /// **not** supported.
    #[must_use]
    pub fn button_hotp_supported(&self) -> bool {
        self.device_extension & 0x20 == 0
    }
}

/// `READ_CONFIG` request data: the single byte is how many response bytes to
/// return (`1..=64`; the firmware fills the first 10). Defaults sensibly when
/// asked for fewer than 10.
#[must_use]
pub fn read_config_request(num_bytes: u8) -> Vec<u8> {
    vec![num_bytes.clamp(10, 64)]
}

/// Parse a `READ_CONFIG` response (§6.9). Requires at least 10 bytes.
pub fn parse_device_info(buf: &[u8]) -> Result<DeviceInfo, ParseError> {
    let b = buf.get(..10).ok_or(ParseError::Truncated)?;
    Ok(DeviceInfo {
        transfer_type: b[0],
        device_config: b[1],
        appearance: [b[2], b[3], b[4], b[5]],
        fido_version: [b[6], b[7], b[8]],
        device_extension: b[9],
    })
}

/// Fixed 18-byte request payload for the FIDO-applet serial-number read (§6.10).
#[must_use]
pub fn serial_request() -> Vec<u8> {
    let mut v = vec![0u8; 18];
    v[0] = 0xD1;
    v[1] = 0x10;
    v
}

/// Parse a serial-number response (§6.10): `D1 || sn_len || <sn_len ASCII-hex>`,
/// returning the hex-decoded serial bytes.
pub fn parse_serial(buf: &[u8]) -> Result<Vec<u8>, ParseError> {
    if buf.first() != Some(&0xD1) {
        return Err(ParseError::BadResponse);
    }
    let len = *buf.get(1).ok_or(ParseError::Truncated)? as usize;
    let hex = buf.get(2..2 + len).ok_or(ParseError::Truncated)?;
    decode_ascii_hex(hex).ok_or(ParseError::BadResponse)
}

fn decode_ascii_hex(s: &[u8]) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    fn nib(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    s.chunks(2)
        .map(|p| Some((nib(p[0])? << 4) | nib(p[1])?))
        .collect()
}

// ---------------------------------------------------------------------------
// PKCS#7 padding (§7) — pure, used by the transport's AES step
// ---------------------------------------------------------------------------

/// PKCS#7-pad `data` to a multiple of `block` (1..=255). A full extra block is
/// added when already aligned, per the standard.
#[must_use]
pub fn pkcs7_pad(data: &[u8], block: usize) -> Vec<u8> {
    debug_assert!((1..=255).contains(&block));
    let pad = block - (data.len() % block);
    let mut out = Vec::with_capacity(data.len() + pad);
    out.extend_from_slice(data);
    out.extend(std::iter::repeat(pad as u8).take(pad));
    out
}

/// Strip PKCS#7 padding, validating it. Returns `None` on malformed padding.
#[must_use]
pub fn pkcs7_unpad(data: &[u8], block: usize) -> Option<Vec<u8>> {
    if data.is_empty() || data.len() % block != 0 {
        return None;
    }
    let pad = *data.last()? as usize;
    if pad == 0 || pad > block || pad > data.len() {
        return None;
    }
    let cut = data.len() - pad;
    if data[cut..].iter().any(|&b| b as usize != pad) {
        return None;
    }
    Some(data[..cut].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    // §10.1 — enumerate-all request at t=0.
    #[test]
    fn enum_all_apdu_matches_spec() {
        let apdu = serialize_apdu(Command::ENUM_CODES, &enum_all_request(0));
        assert_eq!(hex(&apdu), "80c50500000009030000000000000000");
    }

    // §10.1 — the device response for one TOTP entry "Test"/"alice" code 123456.
    //
    // NB: the spec's printed trace shows the leading byte as `00`, but annotates
    // it "type byte = 01 → TOTP" and includes a code tail (which READ_ALL emits
    // only for a TOTP, non-button entry). A type of 0x00 is HOTP, which has no
    // code tail — so the printed `00` is a transcription slip; the structurally
    // correct leading byte is `01` (partial flag clear, type = TOTP). Reported
    // back to the vendor in issue #20.
    #[test]
    fn parse_enum_all_spec_example() {
        let resp = [
            0x01, 0xC1, 0x00, 0x1E, 0x06, 0x00, 0x04, b'T', b'e', b's', b't', 0x05, b'a', b'l',
            b'i', b'c', b'e', 0x06, b'1', b'2', b'3', b'4', b'5', b'6',
        ];
        let (entries, more) = parse_entries(&resp, false).unwrap();
        assert!(!more);
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.kind, OtpKind::Totp);
        assert_eq!(e.algorithm, OtpAlgorithm::Sha1);
        assert_eq!(e.timestep, 30);
        assert_eq!(e.code_length, 6);
        assert!(!e.button_required);
        assert_eq!(e.app_name, "Test");
        assert_eq!(e.account_name, "alice");
        assert_eq!(e.code.as_deref(), Some("123456"));
    }

    // §10.2 — write-entry cleartext for ("Test","alice", seed "Hello", SHA1 TOTP 30 6).
    #[test]
    fn write_entry_cleartext_matches_spec() {
        let ct = write_entry_cleartext(&NewEntry {
            kind: OtpKind::Totp,
            algorithm: OtpAlgorithm::Sha1,
            timestep: 30,
            code_length: 6,
            button_required: false,
            app_name: "Test",
            account_name: "alice",
            seed: b"Hello",
        })
        .unwrap();
        assert_eq!(
            hex(&ct),
            "01c1001e0600045465737405616c69636505 48656c6c6f".replace(' ', "")
        );
    }

    // §10.3 — serial number read request + response decode.
    #[test]
    fn serial_request_and_parse() {
        assert_eq!(
            hex(&serialize_apdu(Command::GET_INFO, &serial_request())),
            "80330000000012d11000000000000000000000000000000000"
        );
        // Response "1234567890" ASCII-hex → bytes 12 34 56 78 90.
        let resp = [
            0xD1, 0x0A, b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0',
        ];
        assert_eq!(
            parse_serial(&resp).unwrap(),
            vec![0x12, 0x34, 0x56, 0x78, 0x90]
        );
    }

    #[test]
    fn partial_flag_lives_in_first_type_byte() {
        // marker 0x81 → more pages, first entry type = 0x01 (TOTP).
        let resp = [
            0x81, 0xC1, 0x00, 0x1E, 0x06, 0x00, 0x01, b'X', 0x01, b'y', 0x06, b'0', b'0', b'0',
            b'0', b'0', b'0',
        ];
        let (entries, more) = parse_entries(&resp, false).unwrap();
        assert!(more);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, OtpKind::Totp);
        assert_eq!(entries[0].code.as_deref(), Some("000000"));
    }

    #[test]
    fn variable_tail_hotp_and_button_omit_code() {
        // Two entries in one page: a HOTP (no code tail) then a TOTP (code tail).
        // If the parser doesn't branch on type/button, it mis-frames here.
        // entry 1's type byte (0x00 = HOTP) doubles as the page's partial marker
        // (bit 7 clear), so there is no separate leading byte.
        let mut resp = Vec::new();
        // entry 1: HOTP, SHA1, ts=30, len=6, btn=0, app="A", acct="b"  (no code)
        resp.extend_from_slice(&[0x00, 0xC1, 0x00, 0x1E, 0x06, 0x00, 0x01, b'A', 0x01, b'b']);
        // entry 2: TOTP, SHA1, ts=30, len=6, btn=0, app="C", acct="d", code "111111"
        resp.extend_from_slice(&[
            0x01, 0xC1, 0x00, 0x1E, 0x06, 0x00, 0x01, b'C', 0x01, b'd', 0x06, b'1', b'1', b'1',
            b'1', b'1', b'1',
        ]);
        // The leading 0x00 marker folds into entry 1's type (HOTP=0x00).
        let (entries, _) = parse_entries(&resp, false).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].kind, OtpKind::Hotp);
        assert_eq!(entries[0].code, None);
        assert_eq!(entries[0].account_name, "b");
        assert_eq!(entries[1].kind, OtpKind::Totp);
        assert_eq!(entries[1].code.as_deref(), Some("111111"));
        assert_eq!(entries[1].app_name, "C");
    }

    #[test]
    fn button_required_totp_omits_code_in_enum() {
        // TOTP but button-required → code tail omitted in READ_ALL.
        let resp = [0x01, 0xC1, 0x00, 0x1E, 0x06, 0x01, 0x01, b'A', 0x01, b'b'];
        let (entries, _) = parse_entries(&resp, false).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].button_required);
        assert_eq!(entries[0].code, None);
    }

    #[test]
    fn status_word_mapping() {
        assert_eq!(check_status(0x9000), Ok(()));
        assert_eq!(check_status(0x6A80), Err(StatusError::EntryNotFound));
        assert_eq!(check_status(0x6A83), Err(StatusError::EntryNotFound));
        assert_eq!(check_status(0x6A84), Err(StatusError::NotEnoughSpace));
        assert_eq!(check_status(0x6A86), Err(StatusError::HidNotSupported));
        assert_eq!(check_status(0x6FF9), Err(StatusError::ButtonPressRequired));
        assert_eq!(check_status(0x6700), Err(StatusError::BadStatus(0x6700)));
    }

    #[test]
    fn select_uses_short_lc() {
        assert_eq!(
            hex(&serialize_select(&AID_OTP)),
            "00a4040008f00000014f747001"
        );
    }

    #[test]
    fn device_info_bits() {
        // device_config 0x04 = HOTP supported; extension 0x01 = TOTP supported,
        // extension 0x20 = button-HOTP NOT supported.
        let info = parse_device_info(&[0x00, 0x04, 0, 0, 0, 0, 0x02, 0x00, 0x01, 0x21]).unwrap();
        assert!(info.hotp_supported());
        assert!(!info.fido_disabled());
        assert!(info.totp_supported());
        assert!(!info.button_hotp_supported()); // bit 6 set → unsupported
        assert_eq!(info.fido_version, [0x02, 0x00, 0x01]);
        assert_eq!(parse_device_info(&[0; 9]), Err(ParseError::Truncated));
    }

    #[test]
    fn validation_rejects_bad_input() {
        let base = NewEntry {
            kind: OtpKind::Totp,
            algorithm: OtpAlgorithm::Sha1,
            timestep: 30,
            code_length: 6,
            button_required: false,
            app_name: "A",
            account_name: "b",
            seed: b"x",
        };
        assert_eq!(
            write_entry_cleartext(&NewEntry {
                timestep: 0,
                ..base.clone()
            }),
            Err(BuildError::BadTimestep)
        );
        assert_eq!(
            write_entry_cleartext(&NewEntry {
                code_length: 11,
                ..base.clone()
            }),
            Err(BuildError::BadCodeLength)
        );
        assert_eq!(
            write_entry_cleartext(&NewEntry {
                account_name: "",
                ..base.clone()
            }),
            Err(BuildError::BadAccountName)
        );
        assert_eq!(
            write_entry_cleartext(&NewEntry {
                seed: b"",
                ..base.clone()
            }),
            Err(BuildError::BadSeed)
        );
    }

    #[test]
    fn pkcs7_roundtrip_and_full_block() {
        let p = pkcs7_pad(b"Hello", 16);
        assert_eq!(p.len(), 16);
        assert_eq!(p[15], 11);
        assert_eq!(pkcs7_unpad(&p, 16).unwrap(), b"Hello");
        // already-aligned → a full extra block
        let q = pkcs7_pad(&[0u8; 16], 16);
        assert_eq!(q.len(), 32);
        assert_eq!(pkcs7_unpad(&q, 16).unwrap(), vec![0u8; 16]);
        // bad padding rejected
        assert_eq!(pkcs7_unpad(&[1, 2, 3, 9], 16), None);
        assert_eq!(pkcs7_unpad(&[], 16), None);
    }

    #[test]
    fn parse_truncated_is_error_not_panic() {
        // Truncated mid-string must error, never panic.
        let resp = [0x00, 0xC1, 0x00, 0x1E, 0x06, 0x00, 0x10, b'A']; // app_len=16 but 1 byte
        assert_eq!(parse_entries(&resp, false), Err(ParseError::Truncated));
        assert_eq!(
            parse_serial(&[0xD1, 0x04, b'1']),
            Err(ParseError::Truncated)
        );
    }

    #[test]
    fn delete_cleartext_shape() {
        let ct = delete_entry_cleartext("Test", "alice").unwrap();
        // 6 zero head bytes, then 04 "Test" 05 "alice" 00
        assert_eq!(
            hex(&ct),
            "000000000000 04 54657374 05 616c696365 00".replace(' ', "")
        );
    }
}
