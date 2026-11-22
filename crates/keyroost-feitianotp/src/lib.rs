//! Feitian OTP (TOTP/HOTP) applet protocol over APDU.
//!
//! Feitian's FIDO security keys carry an applet for one-time-password
//! credentials, AID `D1 56 00 01 32 83 26 01 01`. It is reached over the key's
//! smart-card interface (CCID or NFC), like the Yubico/Trussed OATH applet
//! `keyroost-oath` drives, but it is a different protocol: its own instruction
//! bytes and tags, three slots, and a TOTP period that lives in the stored
//! name because the applet has no field for it.
//!
//! `docs/PROTOCOL-feitianotp.md` is the wire reference. It says, command by
//! command, what was measured on a key and what is known only from Feitian's
//! own client software; the doc comments here repeat that where it matters.
//!
//! # What is and isn't here
//!
//! This is the *byte layer*: it turns intentions into APDU byte vectors and
//! response byte slices into typed structures. It performs **no I/O**; the
//! card exchange lives in `keyroost-transport`.
//!
//! Left out on purpose, because nothing here has run them on hardware: the
//! applet's `RESET`, the slot access codes, and the touch flag a `PUT` can
//! carry.

use keyroost_proto::apdu::{build_apdu, build_apdu_get, try_build_apdu};
use zeroize::Zeroizing;

/// Feitian OTP applet AID, selected with `SELECT (00 A4 04 00)`. Its first
/// five bytes are Feitian's registered RID.
pub const AID: [u8; 9] = [0xD1, 0x56, 0x00, 0x01, 0x32, 0x83, 0x26, 0x01, 0x01];

/// ISO 7816-4 `SELECT` instruction.
pub const INS_SELECT: u8 = 0xA4;
/// `SELECT` P1: select by DF name (AID).
pub const P1_SELECT_BY_NAME: u8 = 0x04;

/// Applet instruction bytes (CLA is `0x00` for all of them).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Instruction {
    /// Remove a credential by name.
    Delete = 0x08,
    /// Store a credential.
    Put = 0x09,
    /// List one slot's credentials.
    List = 0x17,
    /// Compute a code for one credential.
    Calculate = 0xA2,
}

impl Instruction {
    /// The raw INS byte.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}

/// TLV tags used in command data and responses.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Tag {
    /// A credential name in a command; in the `SELECT` answer, an 8-byte
    /// value (see [`SelectInfo::challenge`]).
    Name = 0x51,
    /// One `LIST` entry: a type/algorithm byte, then the name.
    NameList = 0x52,
    /// A credential's algorithm, type, digit count and secret, in a `PUT`.
    Key = 0x53,
    /// The `CALCULATE` challenge.
    Challenge = 0x54,
    /// Applet version, in the `SELECT` answer.
    Version = 0x59,
    /// The `CALCULATE` answer: digit count and four truncated bytes.
    TruncatedResponse = 0x76,
    /// Which slots have an access code, in the `SELECT` answer.
    Access = 0x7B,
}

impl Tag {
    /// The raw tag byte.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}

/// `CALCULATE` P1 for a TOTP or HOTP code.
pub const P1_CALCULATE_OTP: u8 = 0x01;

/// ISO 7816-4 `GET RESPONSE` instruction.
pub const INS_GET_RESPONSE: u8 = 0xC0;

/// Success status word.
pub const SW_OK: u16 = 0x9000;
/// SW1 of "more data available" (`61xx`). Feitian's client fetches the rest
/// with [`get_response`]; the measured keys answered every command whole.
pub const SW_MORE_DATA: u8 = 0x61;
/// "Wrong length". Feitian's client answers it on a `LIST` by sending
/// [`list_legacy`] instead; no key at hand has returned it there.
pub const SW_WRONG_LENGTH: u16 = 0x6700;
/// "No touch arrived". Both measured keys (applet 1.0.1 and 1.0.2) answer a
/// `CALCULATE` with it a few seconds after one that was not touched, and the
/// 1.0.2 key answers a `PUT` and a `DELETE` the same way; nothing is
/// computed, stored or removed, and an HOTP counter does not move.
pub const SW_NO_TOUCH: u16 = 0x6984;
/// "Security status not satisfied". In Feitian's client it means the slot
/// has an access code that must be presented first; not seen on hardware, as
/// neither measured key had one set.
pub const SW_ACCESS_CODE_REQUIRED: u16 = 0x6982;

/// A credential slot, the P2 of every command but `SELECT`.
///
/// Feitian's apps store codes in [`Slot::Default`]. The other two are the
/// slots the key can type from when its button is pressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Slot {
    /// Keyboard slot 1 (`0x00`).
    Keyboard1 = 0x00,
    /// Keyboard slot 2 (`0x01`).
    Keyboard2 = 0x01,
    /// The default slot (`0xF0`).
    Default = 0xF0,
}

impl Slot {
    /// Every slot, in the order a full listing reports them.
    pub const ALL: [Slot; 3] = [Slot::Keyboard1, Slot::Keyboard2, Slot::Default];

    /// The P2 byte.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// The slot a P2 byte names, if any.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0x00 => Some(Slot::Keyboard1),
            0x01 => Some(Slot::Keyboard2),
            0xF0 => Some(Slot::Default),
            _ => None,
        }
    }

    /// The slot's bit in the `SELECT` answer's access byte ([`Tag::Access`]).
    #[must_use]
    pub const fn access_bit(self) -> u8 {
        match self {
            Slot::Keyboard1 => 0x01,
            Slot::Keyboard2 => 0x02,
            Slot::Default => 0x04,
        }
    }

    /// How the slot is named to a user: `default`, `1` or `2`.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Slot::Keyboard1 => "1",
            Slot::Keyboard2 => "2",
            Slot::Default => "default",
        }
    }
}

/// OTP kind. The applet also stores static passwords (`0x30`) and
/// challenge-response secrets (`0x40`); those are not handled here and a
/// listing counts them in [`Listing::skipped`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OathType {
    /// Counter-based (RFC 4226).
    Hotp = 0x10,
    /// Time-based (RFC 6238).
    Totp = 0x20,
}

impl OathType {
    /// The type byte of a `PUT`, and the high nibble of a `LIST` entry's
    /// first byte.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Decode the kind from a `LIST` entry's first byte (high nibble).
    #[must_use]
    pub const fn from_packed(byte: u8) -> Option<Self> {
        match byte & 0xF0 {
            0x10 => Some(OathType::Hotp),
            0x20 => Some(OathType::Totp),
            _ => None,
        }
    }
}

/// HMAC algorithm. The applet takes these two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Algorithm {
    /// HMAC-SHA-1.
    Sha1 = 0x01,
    /// HMAC-SHA-256.
    Sha256 = 0x02,
}

impl Algorithm {
    /// The algorithm byte of a `PUT`, and the low nibble of a `LIST` entry's
    /// first byte.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Decode the algorithm from a `LIST` entry's first byte (low nibble).
    #[must_use]
    pub const fn from_packed(byte: u8) -> Option<Self> {
        match byte & 0x0F {
            0x01 => Some(Algorithm::Sha1),
            0x02 => Some(Algorithm::Sha256),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// TLV encoding
// ---------------------------------------------------------------------------

/// The longest value one TLV carries here. Lengths are a single byte, and
/// nothing shows how the applet would read one of 128 or more (where BER
/// switches to a second length byte), so longer values are refused.
pub const MAX_TLV_LEN: usize = 127;

/// Error from the fallible APDU builders. Names come from users, imported
/// `otpauth://` URIs and QR codes, *and from the card's own LIST answer*, so
/// a value that cannot be framed is an error, never a panic.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildError {
    /// A TLV value is longer than [`MAX_TLV_LEN`]. `what` names the field.
    ValueTooLong { what: &'static str, len: usize },
    /// The composed command body exceeds the 255-byte short-APDU limit.
    BodyTooLong { len: usize },
    /// The credential name is empty.
    EmptyName,
    /// The secret is empty.
    EmptySecret,
    /// A digit count the applet does not take (it takes 6 or 8).
    UnsupportedDigits(u8),
    /// A TOTP period that cannot be stored (the name prefix holds 30 or 60).
    UnsupportedPeriod(u32),
}

impl core::fmt::Display for BuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BuildError::ValueTooLong { what, len } => write!(
                f,
                "Feitian OTP {what} is {len} bytes; one field holds at most {MAX_TLV_LEN}"
            ),
            BuildError::BodyTooLong { len } => write!(
                f,
                "Feitian OTP command body is {len} bytes; a short APDU holds at most 255"
            ),
            BuildError::EmptyName => write!(f, "Feitian OTP name is empty"),
            BuildError::EmptySecret => write!(f, "Feitian OTP secret is empty"),
            BuildError::UnsupportedDigits(d) => {
                write!(f, "Feitian OTP codes have 6 or 8 digits, not {d}")
            }
            BuildError::UnsupportedPeriod(p) => write!(
                f,
                "Feitian OTP keeps a 30 or 60 second period, not {p} seconds"
            ),
        }
    }
}

impl std::error::Error for BuildError {}

/// Append a TLV (`tag`, 1-byte length, value), refusing a value past
/// [`MAX_TLV_LEN`]. `what` names the field for the error.
fn try_push_tlv(
    out: &mut Vec<u8>,
    tag: Tag,
    what: &'static str,
    value: &[u8],
) -> Result<(), BuildError> {
    if value.len() > MAX_TLV_LEN {
        return Err(BuildError::ValueTooLong {
            what,
            len: value.len(),
        });
    }
    out.push(tag.code());
    out.push(value.len() as u8);
    out.extend_from_slice(value);
    Ok(())
}

/// Frame `data` as a case-3 short APDU with CLA `0x00`, mapping an over-long
/// composed body to [`BuildError::BodyTooLong`].
fn finish_apdu(ins: u8, p1: u8, p2: u8, data: &[u8]) -> Result<Vec<u8>, BuildError> {
    try_build_apdu(0x00, ins, p1, p2, data).map_err(|e| BuildError::BodyTooLong { len: e.len })
}

/// Append a name TLV, refusing an empty name.
fn push_name(out: &mut Vec<u8>, name: &str) -> Result<(), BuildError> {
    if name.is_empty() {
        return Err(BuildError::EmptyName);
    }
    try_push_tlv(out, Tag::Name, "name", name.as_bytes())
}

// ---------------------------------------------------------------------------
// APDU builders
// ---------------------------------------------------------------------------

/// `SELECT` the applet: `00 A4 04 00 09 D1 56 00 01 32 83 26 01 01`.
///
/// No `Le` byte: this is the form sent to the measured keys. The answer is
/// read by [`parse_select`].
#[must_use]
pub fn select() -> Vec<u8> {
    build_apdu(0x00, INS_SELECT, P1_SELECT_BY_NAME, 0x00, &AID)
}

/// The ISO `GET RESPONSE`, `00 C0 00 00 00`, for an answer that ends `61xx`.
#[must_use]
pub fn get_response() -> Vec<u8> {
    build_apdu_get(0x00, INS_GET_RESPONSE, 0x00, 0x00, 0x00)
}

/// Build a `LIST` APDU for one slot: `00 17 00 <slot> 00`. An empty slot
/// answers a bare `9000`. The answer is read by [`parse_list`].
#[must_use]
pub fn list(slot: Slot) -> Vec<u8> {
    build_apdu_get(0x00, Instruction::List.code(), 0x00, slot.code(), 0x00)
}

/// The four-byte `LIST`, `00 17 00 00`, with no slot and no `Le`.
///
/// Feitian's client sends this when [`list`] is answered
/// [`SW_WRONG_LENGTH`], and then asks no other slot. No key at hand needed
/// it, so which slot its entries belong to is not known from hardware.
#[must_use]
pub fn list_legacy() -> Vec<u8> {
    vec![0x00, Instruction::List.code(), 0x00, 0x00]
}

/// Parameters for storing a credential via [`put`].
#[derive(Debug, Clone)]
pub struct PutParams<'a> {
    /// The slot to store into.
    pub slot: Slot,
    /// The name as stored on the card (see [`stored_name`]).
    pub name: &'a str,
    /// Raw (already base32-decoded) HMAC secret.
    pub secret: &'a [u8],
    /// Credential kind.
    pub oath_type: OathType,
    /// HMAC algorithm.
    pub algorithm: Algorithm,
    /// Number of OTP digits: 6 or 8.
    pub digits: u8,
}

/// Build a `PUT` APDU storing a credential: `00 09 00 <slot>`.
///
/// Data layout: `KEY(0x53) || NAME(0x51)`. The KEY value is
/// `[ algorithm, type, digits, secret... ]`, and its length byte is written
/// **one less** than the value's real length. Feitian's own client does this,
/// and credentials written in this form compute the right codes on hardware;
/// what the applet makes of the true length has not been tried. Do not
/// "correct" it.
///
/// The command has no counter field, so an HOTP credential starts at 0, and
/// no period field: a TOTP credential's period is part of `name`.
///
/// # Errors
/// Returns [`BuildError`] for an empty name or secret, a digit count other
/// than 6 or 8, or a name or secret that does not fit the framing.
pub fn put(params: &PutParams<'_>) -> Result<Vec<u8>, BuildError> {
    if params.name.is_empty() {
        return Err(BuildError::EmptyName);
    }
    if params.secret.is_empty() {
        return Err(BuildError::EmptySecret);
    }
    if !matches!(params.digits, 6 | 8) {
        return Err(BuildError::UnsupportedDigits(params.digits));
    }
    // `key` and `data` hold the raw HMAC secret; wipe them on drop. (The
    // returned APDU carries it too and is wrapped by the transport layer.)
    let mut key = Zeroizing::new(Vec::with_capacity(3 + params.secret.len()));
    key.push(params.algorithm.code());
    key.push(params.oath_type.code());
    key.push(params.digits);
    key.extend_from_slice(params.secret);

    let mut data = Zeroizing::new(Vec::new());
    try_push_tlv(&mut data, Tag::Key, "secret", &key)?;
    // The value is at least four bytes, so this cannot underflow.
    data[1] -= 1;
    push_name(&mut data, params.name)?;
    finish_apdu(Instruction::Put.code(), 0x00, params.slot.code(), &data)
}

/// Build a `DELETE` APDU removing the credential stored as `name` in `slot`:
/// `00 08 00 <slot>` with `NAME(0x51) <name>`.
///
/// # Errors
/// Returns [`BuildError`] when `name` is empty or does not fit the framing.
pub fn delete(slot: Slot, name: &str) -> Result<Vec<u8>, BuildError> {
    let mut data = Vec::new();
    push_name(&mut data, name)?;
    finish_apdu(Instruction::Delete.code(), 0x00, slot.code(), &data)
}

/// Build a TOTP `CALCULATE` APDU: `00 A2 01 <slot>` with
/// `CHALLENGE(0x54) <8 bytes> || NAME(0x51) <name>`. `name` is the stored
/// name, prefix included; `challenge` comes from [`totp_challenge`].
///
/// # Errors
/// Returns [`BuildError`] when `name` is empty or does not fit the framing.
pub fn calculate_totp(slot: Slot, name: &str, challenge: &[u8; 8]) -> Result<Vec<u8>, BuildError> {
    calculate(slot, name, challenge)
}

/// Build an HOTP `CALCULATE` APDU: as [`calculate_totp`] with an empty
/// challenge (`54 00`). The key moves its counter on once it has computed a
/// code; a fresh credential's first code is the one for counter 0.
///
/// # Errors
/// Returns [`BuildError`] when `name` is empty or does not fit the framing.
pub fn calculate_hotp(slot: Slot, name: &str) -> Result<Vec<u8>, BuildError> {
    calculate(slot, name, &[])
}

fn calculate(slot: Slot, name: &str, challenge: &[u8]) -> Result<Vec<u8>, BuildError> {
    let mut data = Vec::new();
    try_push_tlv(&mut data, Tag::Challenge, "challenge", challenge)?;
    push_name(&mut data, name)?;
    finish_apdu(
        Instruction::Calculate.code(),
        P1_CALCULATE_OTP,
        slot.code(),
        &data,
    )
}

/// Build the 8-byte big-endian TOTP challenge for `unix_seconds` and `period`.
///
/// The counter is `floor(unix_seconds / period)` (RFC 6238), serialized
/// big-endian.
///
/// # Panics
/// Panics if `period` is zero.
#[must_use]
pub fn totp_challenge(unix_seconds: u64, period: u32) -> [u8; 8] {
    assert!(period != 0, "TOTP period must be non-zero");
    (unix_seconds / u64::from(period)).to_be_bytes()
}

// ---------------------------------------------------------------------------
// Credential names
// ---------------------------------------------------------------------------

/// Joins issuer and account in a stored name: `issuer_#_account`.
pub const ISSUER_SEPARATOR: &str = "_#_";

/// The TOTP periods a stored name can carry.
pub const PERIODS: [u32; 2] = [30, 60];

/// A stored name split per Feitian's on-card convention,
/// `[period:][issuer_#_]account`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NameParts<'a> {
    /// The TOTP period from a `30:` / `60:` prefix.
    pub period: Option<u32>,
    pub issuer: Option<&'a str>,
    pub account: &'a str,
}

/// Split a stored name into period, issuer and account.
///
/// The applet has no period field. Feitian's apps put the period in front of
/// a TOTP name as two digits and a colon, `30:` or `60:`, and join issuer and
/// account with `_#_`; HOTP names carry no prefix. A TOTP name without the
/// prefix (possible when written by Feitian's bare command-line tool) reads
/// here as having no stored period.
#[must_use]
pub fn parse_name(name: &str, oath_type: OathType) -> NameParts<'_> {
    let (period, rest) = match oath_type {
        OathType::Totp => match name.split_once(':') {
            Some(("30", rest)) if !rest.is_empty() => (Some(30), rest),
            Some(("60", rest)) if !rest.is_empty() => (Some(60), rest),
            _ => (None, name),
        },
        OathType::Hotp => (None, name),
    };
    let (issuer, account) = match rest.split_once(ISSUER_SEPARATOR) {
        Some((issuer, account)) if !issuer.is_empty() && !account.is_empty() => {
            (Some(issuer), account)
        }
        _ => (None, rest),
    };
    NameParts {
        period,
        issuer,
        account,
    }
}

/// The TOTP period a stored name implies: its `30:` / `60:` prefix, else 30.
#[must_use]
pub fn totp_period(name: &str) -> u32 {
    parse_name(name, OathType::Totp).period.unwrap_or(30)
}

/// Compose the name to store for a credential, the inverse of [`parse_name`]:
/// `issuer_#_account` (or the account alone), with the `30:` / `60:` period
/// in front for TOTP. `period` is ignored for HOTP.
///
/// # Errors
/// [`BuildError::EmptyName`] for an empty account, and
/// [`BuildError::UnsupportedPeriod`] for a TOTP period other than 30 or 60.
pub fn stored_name(
    issuer: Option<&str>,
    account: &str,
    oath_type: OathType,
    period: u32,
) -> Result<String, BuildError> {
    if account.is_empty() {
        return Err(BuildError::EmptyName);
    }
    let mut out = String::new();
    if oath_type == OathType::Totp {
        if !PERIODS.contains(&period) {
            return Err(BuildError::UnsupportedPeriod(period));
        }
        out.push_str(&period.to_string());
        out.push(':');
    }
    if let Some(issuer) = issuer.filter(|i| !i.is_empty()) {
        out.push_str(issuer);
        out.push_str(ISSUER_SEPARATOR);
    }
    out.push_str(account);
    Ok(out)
}

/// The longest stored name keyroost writes, in bytes, with the `30:` prefix
/// and the `_#_` separator counted: Libre Key Companion's limit, the tightest
/// of the known clients. The applet's own limit is not measured.
/// `keyroost_import::plan::limits` mirrors it for imports.
pub const NAME_MAX: usize = 64;

/// Why [`checked_stored_name`] refused a name.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameError {
    /// [`stored_name`] refused it: an empty account, or a period the name
    /// can't carry.
    Build(BuildError),
    /// The name has [`ISSUER_SEPARATOR`] in it where the key would split it,
    /// so it would come back as another app and account.
    ReadsBackDifferently,
    /// The stored name is longer than [`NAME_MAX`].
    TooLong { stored: String },
}

impl core::fmt::Display for NameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            NameError::Build(e) => write!(f, "{e}"),
            NameError::ReadsBackDifferently => write!(
                f,
                "the name would read back differently on the key: it keeps the app \
                 and the account apart with {ISSUER_SEPARATOR}, and this name has that \
                 in it"
            ),
            NameError::TooLong { stored } => write!(
                f,
                "the name is {} bytes as stored ({stored:?}); keyroost stores names of \
                 up to {NAME_MAX} bytes on this key",
                stored.len()
            ),
        }
    }
}

impl std::error::Error for NameError {}

/// [`stored_name`], refused unless the key would read the name back as the
/// same app and account, and unless it fits [`NAME_MAX`]. The one check
/// `keyroostctl feitian add` and the app's add form both run, so they refuse
/// the same names in the same words.
///
/// # Errors
/// See [`NameError`].
pub fn checked_stored_name(
    issuer: Option<&str>,
    account: &str,
    oath_type: OathType,
    period: u32,
) -> Result<String, NameError> {
    let issuer = issuer.filter(|i| !i.is_empty());
    let stored = stored_name(issuer, account, oath_type, period).map_err(NameError::Build)?;
    let parts = parse_name(&stored, oath_type);
    if parts.issuer != issuer || parts.account != account {
        return Err(NameError::ReadsBackDifferently);
    }
    if stored.len() > NAME_MAX {
        return Err(NameError::TooLong { stored });
    }
    Ok(stored)
}

// ---------------------------------------------------------------------------
// Response parsing
// ---------------------------------------------------------------------------

/// Error returned by the response parsers.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// A TLV claimed more bytes than the buffer contained.
    Truncated,
    /// A `TRUNCATED_RESPONSE` value was malformed (wrong length or digits).
    BadTruncatedResponse,
    /// A required tag was absent from the response.
    MissingTag(u8),
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ParseError::Truncated => write!(f, "TLV truncated: length exceeds buffer"),
            ParseError::BadTruncatedResponse => write!(f, "malformed TRUNCATED_RESPONSE TLV"),
            ParseError::MissingTag(t) => write!(f, "expected TLV tag {t:#04x} not present"),
        }
    }
}

impl std::error::Error for ParseError {}

/// A single parsed TLV borrowed from the response buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv<'a> {
    /// Raw tag byte.
    pub tag: u8,
    /// Value bytes (length already validated against the buffer).
    pub value: &'a [u8],
}

/// Parse a flat run of TLVs with one-byte lengths, as every measured answer
/// is laid out. Returns [`ParseError::Truncated`] if a TLV runs off the end
/// of the buffer.
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

fn find_tag<'a>(tlvs: &[Tlv<'a>], tag: Tag) -> Option<&'a [u8]> {
    tlvs.iter().find(|t| t.tag == tag.code()).map(|t| t.value)
}

/// What the applet says about itself in its `SELECT` answer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SelectInfo {
    /// Applet version bytes (`59`): `01 00 02` is 1.0.2. Empty if absent.
    pub version: Vec<u8>,
    /// The value under tag `51`, eight bytes on the measured keys. Feitian's
    /// client calls it the challenge and salts a slot's access-code key with
    /// it. Within a day it stayed the same across SELECTs and card resets.
    /// Two captures of this model a day apart held different values; whether
    /// one key's value changes is not established.
    pub challenge: Vec<u8>,
    /// The access byte (`7B`), one bit per slot ([`Slot::access_bit`]).
    /// `None` when the answer carried none.
    pub access: Option<u8>,
}

impl SelectInfo {
    /// The version as `(major, minor, patch)`, when it is three bytes.
    #[must_use]
    pub fn version_triple(&self) -> Option<(u8, u8, u8)> {
        match self.version[..] {
            [a, b, c] => Some((a, b, c)),
            _ => None,
        }
    }

    /// Whether the access byte marks `slot` as having an access code.
    /// `None` when the answer carried no access byte.
    #[must_use]
    pub fn access_code_set(&self, slot: Slot) -> Option<bool> {
        self.access.map(|bits| bits & slot.access_bit() != 0)
    }
}

/// Parse the `SELECT` answer: a flat run of `VERSION(0x59)`, `0x51` and
/// `ACCESS(0x7B)` TLVs. Tags it does not know are ignored, and a missing one
/// leaves its field empty.
pub fn parse_select(buf: &[u8]) -> Result<SelectInfo, ParseError> {
    let tlvs = parse_tlvs(buf)?;
    Ok(SelectInfo {
        version: find_tag(&tlvs, Tag::Version).unwrap_or_default().to_vec(),
        challenge: find_tag(&tlvs, Tag::Name).unwrap_or_default().to_vec(),
        access: find_tag(&tlvs, Tag::Access).and_then(|v| v.first().copied()),
    })
}

/// One credential from a `LIST` answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    /// The slot it was listed from. A name is only unique within its slot.
    pub slot: Slot,
    /// The name exactly as stored, period prefix included. `CALCULATE` and
    /// `DELETE` must send it back unchanged; [`parse_name`] splits it.
    pub name: String,
    /// Credential kind.
    pub oath_type: OathType,
    /// HMAC algorithm.
    pub algorithm: Algorithm,
}

/// A decoded `LIST` answer for one slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listing {
    /// The entries that decoded cleanly.
    pub credentials: Vec<Credential>,
    /// Entries the slot holds that are not shown: an empty value, a kind
    /// other than TOTP/HOTP (the applet also stores static passwords and
    /// challenge-response secrets), an unknown algorithm, an empty name or
    /// one that is not UTF-8. Non-zero means the listing is **partial**.
    pub skipped: usize,
}

/// Parse one slot's `LIST` answer.
///
/// The answer is a run of `NAME_LIST (0x52)` TLVs, each value
/// `[ type | algorithm, name_utf8... ]` with the type in the high nibble and
/// the algorithm in the low one. An empty slot answers with no data. Other
/// tags are ignored.
pub fn parse_list(buf: &[u8], slot: Slot) -> Result<Listing, ParseError> {
    let tlvs = parse_tlvs(buf)?;
    let mut credentials = Vec::new();
    let mut skipped = 0usize;
    for tlv in &tlvs {
        if tlv.tag != Tag::NameList.code() {
            continue;
        }
        // Skip one undecodable entry rather than failing the listing: one
        // odd credential must not hide every other one in the slot. The skip
        // is counted so callers can tell a partial listing from a full one.
        let Some((&packed, name)) = tlv.value.split_first() else {
            skipped += 1;
            continue;
        };
        let (Some(oath_type), Some(algorithm)) = (
            OathType::from_packed(packed),
            Algorithm::from_packed(packed),
        ) else {
            skipped += 1;
            continue;
        };
        let name = match core::str::from_utf8(name) {
            Ok(name) if !name.is_empty() => name,
            _ => {
                skipped += 1;
                continue;
            }
        };
        credentials.push(Credential {
            slot,
            name: name.to_owned(),
            oath_type,
            algorithm,
        });
    }
    Ok(Listing {
        credentials,
        skipped,
    })
}

// ---------------------------------------------------------------------------
// OTP truncation / formatting
// ---------------------------------------------------------------------------

/// Format an OTP from the four dynamically-truncated big-endian bytes: mask
/// off the top bit, reduce modulo `10^digits`, zero-pad to `digits`
/// (RFC 4226).
///
/// # Panics
/// Panics if `digits` is 0 or greater than 9.
#[must_use]
pub fn format_truncated(bytes: &[u8; 4], digits: u8) -> String {
    assert!((1..=9).contains(&digits), "OTP digits must be 1..=9");
    let raw = u32::from_be_bytes(*bytes) & 0x7FFF_FFFF;
    let code = raw % 10u32.pow(u32::from(digits));
    format!("{code:0width$}", width = digits as usize)
}

/// A parsed `CALCULATE` answer: digit count plus the formatted code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpCode {
    /// Number of digits the card reported.
    pub digits: u8,
    /// Zero-padded decimal code.
    pub code: String,
}

/// Parse a `CALCULATE` answer, `76 05 <digits> <4 bytes>`.
///
/// `0x76` is the only response tag in this protocol; the Yubico applet's
/// full-response `0x75` does not exist here.
pub fn parse_calculate(buf: &[u8]) -> Result<OtpCode, ParseError> {
    let tlvs = parse_tlvs(buf)?;
    let value = find_tag(&tlvs, Tag::TruncatedResponse)
        .ok_or(ParseError::MissingTag(Tag::TruncatedResponse.code()))?;
    let [digits, b0, b1, b2, b3] = *value else {
        return Err(ParseError::BadTruncatedResponse);
    };
    if !(1..=9).contains(&digits) {
        return Err(ParseError::BadTruncatedResponse);
    }
    Ok(OtpCode {
        digits,
        code: format_truncated(&[b0, b1, b2, b3], digits),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_codes_round_trip() {
        for slot in Slot::ALL {
            assert_eq!(Slot::from_code(slot.code()), Some(slot));
        }
        assert_eq!(Slot::from_code(0x02), None);
        assert_eq!(Slot::from_code(0xFF), None);
        // The three access bits are distinct.
        assert_eq!(
            Slot::ALL.iter().fold(0, |acc, s| acc | s.access_bit()),
            0x07
        );
    }

    #[test]
    fn packed_byte_splits_into_type_and_algorithm() {
        assert_eq!(OathType::from_packed(0x21), Some(OathType::Totp));
        assert_eq!(Algorithm::from_packed(0x21), Some(Algorithm::Sha1));
        assert_eq!(OathType::from_packed(0x12), Some(OathType::Hotp));
        assert_eq!(Algorithm::from_packed(0x12), Some(Algorithm::Sha256));
        // Static password and challenge-response are stored but not handled.
        assert_eq!(OathType::from_packed(0x31), None);
        assert_eq!(OathType::from_packed(0x41), None);
        // No SHA-512.
        assert_eq!(Algorithm::from_packed(0x23), None);
    }

    #[test]
    fn name_splits_period_issuer_and_account() {
        let p = parse_name("30:GitHub_#_alice", OathType::Totp);
        assert_eq!(
            (p.period, p.issuer, p.account),
            (Some(30), Some("GitHub"), "alice")
        );
        let p = parse_name("60:alice", OathType::Totp);
        assert_eq!((p.period, p.issuer, p.account), (Some(60), None, "alice"));
        // HOTP names are never prefixed, even when they look it.
        let p = parse_name("30:GitHub_#_alice", OathType::Hotp);
        assert_eq!(
            (p.period, p.issuer, p.account),
            (None, Some("30:GitHub"), "alice")
        );
        // Only the two periods the convention has, and something after them.
        for name in ["15:alice", "030:alice", "30:", "3:alice", "alice"] {
            assert_eq!(parse_name(name, OathType::Totp).period, None, "{name}");
        }
        // A separator at either end is part of the account.
        let p = parse_name("_#_alice", OathType::Hotp);
        assert_eq!((p.issuer, p.account), (None, "_#_alice"));
        let p = parse_name("GitHub_#_", OathType::Hotp);
        assert_eq!((p.issuer, p.account), (None, "GitHub_#_"));
    }

    #[test]
    fn totp_period_defaults_to_thirty() {
        assert_eq!(totp_period("60:a_#_b"), 60);
        assert_eq!(totp_period("30:a_#_b"), 30);
        assert_eq!(totp_period("a_#_b"), 30);
    }

    #[test]
    fn stored_name_is_the_inverse_of_parse_name() {
        let name = stored_name(Some("GitHub"), "alice", OathType::Totp, 60).unwrap();
        assert_eq!(name, "60:GitHub_#_alice");
        let p = parse_name(&name, OathType::Totp);
        assert_eq!(
            (p.period, p.issuer, p.account),
            (Some(60), Some("GitHub"), "alice")
        );

        assert_eq!(
            stored_name(None, "alice", OathType::Totp, 30).unwrap(),
            "30:alice"
        );
        // An empty issuer is no issuer.
        assert_eq!(
            stored_name(Some(""), "alice", OathType::Totp, 30).unwrap(),
            "30:alice"
        );
        // HOTP: no prefix, period ignored.
        assert_eq!(
            stored_name(Some("GitHub"), "alice", OathType::Hotp, 0).unwrap(),
            "GitHub_#_alice"
        );
    }

    #[test]
    fn stored_name_refuses_what_the_card_cannot_hold() {
        assert_eq!(
            stored_name(None, "", OathType::Totp, 30),
            Err(BuildError::EmptyName)
        );
        for period in [0, 15, 45, 90] {
            assert_eq!(
                stored_name(None, "alice", OathType::Totp, period),
                Err(BuildError::UnsupportedPeriod(period))
            );
        }
    }

    #[test]
    fn checked_stored_name_refuses_what_would_not_read_back() {
        let check = |i: Option<&str>, a: &str| checked_stored_name(i, a, OathType::Totp, 30);
        assert_eq!(check(Some("GitHub"), "alice").unwrap(), "30:GitHub_#_alice");
        assert_eq!(check(Some(""), "alice").unwrap(), "30:alice");
        // The separator inside either part would move the key's split.
        assert_eq!(
            check(Some("a_#_b"), "c"),
            Err(NameError::ReadsBackDifferently)
        );
        assert_eq!(check(None, "a_#_b"), Err(NameError::ReadsBackDifferently));
        assert!(NameError::ReadsBackDifferently.to_string().contains("_#_"));
        assert_eq!(
            check(None, ""),
            Err(NameError::Build(BuildError::EmptyName))
        );
        // The limit counts the prefix and the separator: 3 + 1 + 3 + 57 = 64.
        let fits = "a".repeat(57);
        assert_eq!(check(Some("x"), &fits).unwrap().len(), NAME_MAX);
        let over = format!("{fits}a");
        let err = check(Some("x"), &over).unwrap_err();
        assert_eq!(
            err,
            NameError::TooLong {
                stored: format!("30:x_#_{over}")
            }
        );
        assert!(err
            .to_string()
            .starts_with("the name is 65 bytes as stored"));
        assert!(err.to_string().ends_with("up to 64 bytes on this key"));
    }

    #[test]
    fn put_refuses_bad_parameters_without_building() {
        let ok = PutParams {
            slot: Slot::Default,
            name: "30:a",
            secret: &[1, 2, 3],
            oath_type: OathType::Totp,
            algorithm: Algorithm::Sha1,
            digits: 6,
        };
        assert!(put(&ok).is_ok());
        assert_eq!(
            put(&PutParams {
                name: "",
                ..ok.clone()
            }),
            Err(BuildError::EmptyName)
        );
        assert_eq!(
            put(&PutParams {
                secret: &[],
                ..ok.clone()
            }),
            Err(BuildError::EmptySecret)
        );
        for digits in [0, 5, 7, 9, 10] {
            assert_eq!(
                put(&PutParams {
                    digits,
                    ..ok.clone()
                }),
                Err(BuildError::UnsupportedDigits(digits))
            );
        }
    }

    #[test]
    fn put_refuses_values_past_one_length_byte() {
        let name = "n".repeat(MAX_TLV_LEN + 1);
        let secret = [0u8; MAX_TLV_LEN];
        let base = PutParams {
            slot: Slot::Default,
            name: "30:a",
            secret: &[1],
            oath_type: OathType::Totp,
            algorithm: Algorithm::Sha1,
            digits: 6,
        };
        assert_eq!(
            put(&PutParams {
                name: &name,
                ..base.clone()
            }),
            Err(BuildError::ValueTooLong {
                what: "name",
                len: MAX_TLV_LEN + 1
            })
        );
        // The key value is the secret plus three header bytes.
        assert_eq!(
            put(&PutParams {
                secret: &secret[..MAX_TLV_LEN - 2],
                ..base.clone()
            }),
            Err(BuildError::ValueTooLong {
                what: "secret",
                len: MAX_TLV_LEN + 1
            })
        );
        // Each at its own limit fits a field, but not one short APDU together.
        let longest_name = "n".repeat(MAX_TLV_LEN);
        assert_eq!(
            put(&PutParams {
                name: &longest_name,
                secret: &secret[..MAX_TLV_LEN - 3],
                ..base.clone()
            }),
            Err(BuildError::BodyTooLong {
                len: 2 * (2 + MAX_TLV_LEN)
            })
        );
        // A 64-byte name with a 64-byte secret does.
        let name = "n".repeat(64);
        let apdu = put(&PutParams {
            name: &name,
            secret: &secret[..64],
            ..base
        })
        .unwrap();
        assert_eq!(apdu.len(), 5 + (2 + 3 + 64) + (2 + 64));
    }

    #[test]
    fn delete_and_calculate_refuse_an_empty_name() {
        assert_eq!(delete(Slot::Default, ""), Err(BuildError::EmptyName));
        assert_eq!(
            calculate_hotp(Slot::Default, ""),
            Err(BuildError::EmptyName)
        );
        assert_eq!(
            calculate_totp(Slot::Default, "", &[0; 8]),
            Err(BuildError::EmptyName)
        );
    }

    #[test]
    fn tlv_parser_reports_truncation() {
        assert_eq!(parse_tlvs(&[]), Ok(Vec::new()));
        assert_eq!(parse_tlvs(&[0x52]), Err(ParseError::Truncated));
        assert_eq!(parse_tlvs(&[0x52, 0x02, 0x21]), Err(ParseError::Truncated));
        assert_eq!(parse_tlvs(&[0x52, 0xFF]), Err(ParseError::Truncated));
        let tlvs = parse_tlvs(&[0x7B, 0x01, 0x00, 0x59, 0x00]).unwrap();
        assert_eq!(tlvs.len(), 2);
        assert_eq!(tlvs[1].value, &[] as &[u8]);
    }

    #[test]
    fn select_answer_with_nothing_known_parses_to_empty_fields() {
        let info = parse_select(&[]).unwrap();
        assert_eq!(info, SelectInfo::default());
        assert_eq!(info.version_triple(), None);
        assert_eq!(info.access_code_set(Slot::Default), None);
        // Unknown tags are ignored; an empty access TLV is no access byte.
        let info = parse_select(&[0x99, 0x01, 0xAA, 0x7B, 0x00]).unwrap();
        assert_eq!(info.access, None);
    }

    #[test]
    fn access_byte_is_read_per_slot() {
        // Not measured: no key at hand had an access code. Bit layout from
        // Feitian's client (bit 0 slot 1, bit 1 slot 2, bit 2 default).
        let info = parse_select(&[0x7B, 0x01, 0x05]).unwrap();
        assert_eq!(info.access_code_set(Slot::Keyboard1), Some(true));
        assert_eq!(info.access_code_set(Slot::Keyboard2), Some(false));
        assert_eq!(info.access_code_set(Slot::Default), Some(true));
    }

    #[test]
    fn list_skips_and_counts_what_it_cannot_show() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x52, 0x02, 0x21, b'a']); // TOTP/SHA-1 "a"
        buf.extend_from_slice(&[0x52, 0x00]); // empty value
        buf.extend_from_slice(&[0x52, 0x02, 0x31, b'p']); // static password
        buf.extend_from_slice(&[0x52, 0x02, 0x23, b's']); // unknown algorithm
        buf.extend_from_slice(&[0x52, 0x01, 0x21]); // empty name
        buf.extend_from_slice(&[0x52, 0x02, 0x21, 0xFF]); // not UTF-8
        buf.extend_from_slice(&[0x99, 0x01, 0x00]); // another tag: ignored
        buf.extend_from_slice(&[0x52, 0x02, 0x12, b'h']); // HOTP/SHA-256 "h"
        let listing = parse_list(&buf, Slot::Keyboard2).unwrap();
        assert_eq!(listing.skipped, 5);
        assert_eq!(
            listing
                .credentials
                .iter()
                .map(|c| (c.name.as_str(), c.oath_type, c.algorithm, c.slot))
                .collect::<Vec<_>>(),
            vec![
                ("a", OathType::Totp, Algorithm::Sha1, Slot::Keyboard2),
                ("h", OathType::Hotp, Algorithm::Sha256, Slot::Keyboard2),
            ]
        );
    }

    #[test]
    fn calculate_answer_must_be_a_five_byte_truncated_response() {
        assert_eq!(parse_calculate(&[]), Err(ParseError::MissingTag(0x76)));
        // The Yubico applet's full-response tag is not this protocol's.
        assert_eq!(
            parse_calculate(&[0x75, 0x05, 0x06, 0, 0, 0, 1]),
            Err(ParseError::MissingTag(0x76))
        );
        assert_eq!(
            parse_calculate(&[0x76, 0x04, 0x06, 0, 0, 0]),
            Err(ParseError::BadTruncatedResponse)
        );
        assert_eq!(
            parse_calculate(&[0x76, 0x06, 0x06, 0, 0, 0, 1, 2]),
            Err(ParseError::BadTruncatedResponse)
        );
        for digits in [0u8, 10] {
            assert_eq!(
                parse_calculate(&[0x76, 0x05, digits, 0, 0, 0, 1]),
                Err(ParseError::BadTruncatedResponse)
            );
        }
        assert_eq!(
            parse_calculate(&[0x76, 0x05, 0x06, 0, 0, 0]),
            Err(ParseError::Truncated)
        );
    }

    #[test]
    fn truncation_masks_the_top_bit_and_pads() {
        assert_eq!(format_truncated(&[0xFF, 0xFF, 0xFF, 0xFF], 6), "483647");
        assert_eq!(format_truncated(&[0x00, 0x00, 0x00, 0x07], 6), "000007");
        assert_eq!(format_truncated(&[0x00, 0x0B, 0xC7, 0x3D], 8), "00771901");
    }

    #[test]
    fn totp_challenge_is_the_big_endian_time_step() {
        assert_eq!(
            totp_challenge(1_794_930_384, 30),
            [0, 0, 0, 0, 0x03, 0x90, 0xF2, 0xE4]
        );
        assert_eq!(totp_challenge(59, 60), [0; 8]);
        assert_eq!(totp_challenge(60, 60), [0, 0, 0, 0, 0, 0, 0, 1]);
    }
}
