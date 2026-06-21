//! Pure-Rust byte layer for the Token2 T2F2 / PIN+ on-device OTP management
//! applet — the protocol that provisions and reads the TOTP/HOTP entries the
//! key stores, *not* CTAP/FIDO2 (that is the standard FIDO interface, handled by
//! `keyroost-ctap`).
//!
//! This crate is hardware-free in the same spirit as [`keyroost_oath`] and
//! [`keyroost_proto`]: it builds APDUs, parses responses, and performs the
//! ECDH+AES payload encryption that seed-bearing commands require. The actual
//! USB-HID / PC/SC transmission lives in `keyroost-transport`.
//!
//! Spec reference: the bundled *Token2 OTP — Protocol & SDK Reference*, which is
//! cross-checked against the vendor *OTP on FIDO Command Manual* §§1.1–1.11. The
//! one command not in the vendor manual is [`read_serial`](cmd::READ_SERIAL_INS)
//! (§6.10), observed in the reference client only.
//!
//! # Security posture
//!
//! TOTP/HOTP are shared-secret schemes and are **not** phishing-resistant; the
//! spec is emphatic that FIDO2 should be preferred for any account that supports
//! it. This crate exists to manage OTP on legacy services, not to endorse it for
//! new deployments. Seeds are scrubbed from memory on drop and never logged.

#![forbid(unsafe_code)]

pub mod crypto;
pub mod entry;
pub mod hidframe;

pub use crypto::{encrypt_seed_payload, EncryptError, IV_HOTP, IV_OTP};
pub use entry::{
    parse_enum_page, serialize_delete_entry, serialize_read_entry, serialize_write_entry,
    Algorithm, Entry, EnumPage, OtpType, ParseError, WriteEntry,
};

use zeroize::Zeroizing;

/// USB Vendor ID for the Token2 T2F2 / PIN+ FIDO2 key (decimal 13470).
///
/// Distinct from [`keyroost_proto::USB_VID`]'s Molto2 PID — same vendor, but the
/// FIDO key and the Molto2 TOTP token are different products. Match on VID plus
/// the manufacturer/product strings per spec §2.1.
pub const USB_VID: u16 = 0x349E;
/// USB Product ID seen on the reference udev rule (spec §2.1).
pub const USB_PID: u16 = 0x0022;
/// Manufacturer string to match when the VID alone is ambiguous (spec §2.1).
pub const USB_MANUFACTURER: &str = "TOKEN2";
/// Product string to match alongside [`USB_MANUFACTURER`] (spec §2.1).
pub const USB_PRODUCT: &str = "FIDO2 Security Key";
/// HID usage page these keys expose (standard FIDO/U2F page). Used as the
/// primary discriminator alongside the VID, since the PID varies by model.
pub const FIDO_USAGE_PAGE: u16 = 0xF1D0;

/// PC/SC SELECT AID for the OTP management applet (spec §2.2), `"Otp\x01"`-suffixed.
pub const OTP_APPLET_AID: [u8; 8] = [0xF0, 0x00, 0x00, 0x01, 0x4F, 0x74, 0x70, 0x01];
/// PC/SC SELECT AID for the FIDO applet — needed before reading the serial
/// number over PC/SC (spec §5, §6.10).
pub const FIDO_APPLET_AID: [u8; 8] = [0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01];

/// APDU command bytes (`CLA INS P1 P2`) from spec §6.
pub mod cmd {
    /// `WRITE_HOTP_SEED` — encrypted (IV-2), spec §1.7.
    pub const WRITE_HOTP_SEED: [u8; 4] = [0x80, 0xC5, 0x00, 0x00];
    /// `GET_ECDH_PUBKEY` — device returns its raw 64-byte P-256 pubkey, §1.1.
    pub const GET_ECDH_PUBKEY: [u8; 4] = [0x80, 0xC5, 0x01, 0x00];
    /// `READ_CONFIG` — host sends 1 byte (read length); device returns info, §1.11.
    pub const READ_CONFIG: [u8; 4] = [0x80, 0xC5, 0x02, 0x00];
    /// `SET_DEVICE_TYPE` — host sends a 1-byte disable bitmask, §1.6. **Bricking
    /// risk** — see [`SetDeviceTypeError`].
    pub const SET_DEVICE_TYPE: [u8; 4] = [0x80, 0xC5, 0x02, 0x01];
    /// `CFG_HOTP_ENTER` — 1 byte, §1.8.
    pub const CFG_HOTP_ENTER: [u8; 4] = [0x80, 0xC5, 0x02, 0x02];
    /// `CFG_HOTP_TOUCH` — 1 byte, §1.9.
    pub const CFG_HOTP_TOUCH: [u8; 4] = [0x80, 0xC5, 0x02, 0x04];
    /// `ENABLE_TOTP` — 1 byte (00/01), §1.2.
    pub const ENABLE_TOTP: [u8; 4] = [0x80, 0xC5, 0x02, 0x05];
    /// `CFG_HOTP_KBD_TYPE` — 1 byte, §1.10.
    pub const CFG_HOTP_KBD_TYPE: [u8; 4] = [0x80, 0xC5, 0x02, 0x06];
    /// `ENUM_CODES` — host sends subcommand + args, §1.4.
    pub const ENUM_CODES: [u8; 4] = [0x80, 0xC5, 0x05, 0x00];
    /// `ENUM_CODES_CONTINUE` — host sends an 8-byte timestamp, §1.5.
    pub const ENUM_CODES_CONTINUE: [u8; 4] = [0x80, 0xC5, 0x05, 0x01];
    /// `WRITE_SEED` — encrypted (IV-1), or empty data for erase-all, §1.3.
    pub const WRITE_SEED: [u8; 4] = [0x80, 0xC5, 0x05, 0x02];
    /// `GET_INFO` on the FIDO applet — read serial number, §6.10 (reference only).
    pub const READ_SERIAL_INS: [u8; 4] = [0x80, 0x33, 0x00, 0x00];

    /// ENUM_CODES subcommand: read one entry by name (§6.2).
    pub const SUB_READ_ONE: u8 = 0x01;
    /// ENUM_CODES subcommand: code-only, no metadata (§6, unused by reference).
    pub const SUB_GET_METADATA: u8 = 0x02;
    /// ENUM_CODES subcommand: paginated read-all (§6.1).
    pub const SUB_READ_ALL: u8 = 0x03;
}

/// ISO-7816 status words this applet returns (spec §3.1).
pub mod sw {
    pub const OK: u16 = 0x9000;
    pub const ENTRY_NOT_FOUND: u16 = 0x6A80;
    pub const ENTRY_NOT_FOUND_ALT: u16 = 0x6A83;
    pub const NOT_ENOUGH_SPACE: u16 = 0x6A84;
    pub const HID_NOT_SUPPORTED: u16 = 0x6A86;
    pub const BUTTON_TIMEOUT: u16 = 0x6FF9;
}

/// An expected, surface-to-the-user error from the applet, mirroring the
/// reference client's exception hierarchy (spec §8.4). Transport-level and
/// crypto errors are separate types in their own modules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OtpError {
    /// `6A80` / `6A83`. Note: on a clean `ENUM_CODES` READ_ALL this means "zero
    /// entries", which [`is_empty_token`](OtpError::is_empty_token) flags so the
    /// caller can treat it as success.
    EntryNotFound,
    /// `6A84` — device storage is full.
    NotEnoughSpace,
    /// `6FF9` — timed out waiting for the confirming button press.
    ButtonPressRequired,
    /// `6A86` — this model does not expose HOTP-over-HID (older PIN+ revisions).
    HidNotSupported,
    /// Any other non-`9000` status word.
    BadStatusCode(u16),
}

impl OtpError {
    /// Map a raw status word to an [`OtpError`], or `Ok(())` for `9000`.
    pub fn check(sw: u16) -> Result<(), OtpError> {
        match sw {
            sw::OK => Ok(()),
            sw::ENTRY_NOT_FOUND | sw::ENTRY_NOT_FOUND_ALT => Err(OtpError::EntryNotFound),
            sw::NOT_ENOUGH_SPACE => Err(OtpError::NotEnoughSpace),
            sw::BUTTON_TIMEOUT => Err(OtpError::ButtonPressRequired),
            sw::HID_NOT_SUPPORTED => Err(OtpError::HidNotSupported),
            other => Err(OtpError::BadStatusCode(other)),
        }
    }

    /// True for the `EntryNotFound` that a READ_ALL returns on an empty token,
    /// which the caller should treat as "zero entries", not an error (spec §3.1,
    /// §11).
    pub fn is_empty_token(&self) -> bool {
        matches!(self, OtpError::EntryNotFound)
    }
}

impl std::fmt::Display for OtpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OtpError::EntryNotFound => write!(f, "entry not found"),
            OtpError::NotEnoughSpace => write!(f, "not enough space on device"),
            OtpError::ButtonPressRequired => {
                write!(f, "timed out waiting for a button press on the key")
            }
            OtpError::HidNotSupported => {
                write!(f, "HOTP-over-HID is not supported on this model")
            }
            OtpError::BadStatusCode(sw) => write!(f, "unexpected status word {:#06X}", sw),
        }
    }
}

impl std::error::Error for OtpError {}

/// Build an extended-length APDU: `CLA INS P1 P2 00 Lc_hi Lc_lo data...`
/// (spec §3). Used for every command except the PC/SC SELECT, which is
/// short-form via [`build_select`].
///
/// The device ignores Le and returns whatever it has, so none is appended.
pub fn build_apdu(header: [u8; 4], data: &[u8]) -> Vec<u8> {
    let len = data.len();
    assert!(len <= 0xFFFF, "extended APDU body exceeds 16-bit Lc");
    let mut out = Vec::with_capacity(7 + len);
    out.extend_from_slice(&header);
    if len > 0 {
        if len <= 0xFF {
            // Short-form Lc (single byte). Required for T=0 contact readers,
            // which reject the extended (3-byte `00 hi lo`) form with 6700
            // ("wrong length"); short form is equally valid over T=CL (NFC) and
            // USB-HID, so it's the safe universal encoding. Every OTP command
            // body fits well under 255 bytes (seeds, timestamps, flags).
            out.push(len as u8);
        } else {
            // Extended Lc for the (unused in practice) >255-byte case.
            out.push(0x00);
            out.push((len >> 8) as u8);
            out.push((len & 0xFF) as u8);
        }
        out.extend_from_slice(data);
    }
    // erase-all (WRITE_SEED with empty data) sends no Lc/Le at all — just the
    // 4-byte header. The device interprets a bodyless WRITE_SEED as erase-all.
    out
}

/// Build the short-form PC/SC SELECT-by-name APDU for an applet AID (spec §2.2,
/// §3): `00 A4 04 00 Lc aid...`. Short Lc is used *only* here.
pub fn build_select(aid: &[u8]) -> Vec<u8> {
    assert!(!aid.is_empty() && aid.len() <= 255, "SELECT AID length");
    let mut out = Vec::with_capacity(5 + aid.len());
    out.extend_from_slice(&[0x00, 0xA4, 0x04, 0x00]);
    out.push(aid.len() as u8);
    out.extend_from_slice(aid);
    out
}

/// Build the `ENABLE_TOTP` APDU (spec §6.7). `enabled` → `0x01`, else `0x00`.
pub fn enable_totp(enabled: bool) -> Vec<u8> {
    build_apdu(cmd::ENABLE_TOTP, &[enabled as u8])
}

/// Build the `READ_CONFIG` request for `num_bytes` of device info (spec §6.9).
/// `num_bytes` is clamped to `1..=64`; the firmware fills the first 10.
/// Build the `GET_ECDH_PUBKEY` request (§1.1): short case-2 APDU
/// `80 C5 01 00 00` — header plus a single `Le` byte (`00`), exactly as the
/// vendor pseudocode shows. Built explicitly rather than via `build_apdu`, which
/// omits Le for empty bodies; without Le the device answers with a stub instead
/// of the full 64-byte key, which made the HID probe fail and forced CCID.
pub fn get_ecdh_pubkey() -> Vec<u8> {
    vec![
        cmd::GET_ECDH_PUBKEY[0],
        cmd::GET_ECDH_PUBKEY[1],
        cmd::GET_ECDH_PUBKEY[2],
        cmd::GET_ECDH_PUBKEY[3],
        0x00, // Le = 0x00 (return all available)
    ]
}

pub fn read_config(num_bytes: u8) -> Vec<u8> {
    let n = num_bytes.clamp(1, 64);
    // §1.11: `80 C5 02 00` with P3 = number of response bytes wanted. This is a
    // short ISO case-2 APDU (header + single Le byte) — the same shape the
    // vendor pseudocode uses for the other read command, `80 C5 01 00 00`.
    // Earlier we built this with an *extended-Lc data* body, which made the
    // device answer `61 01` (only 1 byte available) over PC/SC; a plain Le byte
    // is what asks for the full block.
    vec![
        cmd::READ_CONFIG[0],
        cmd::READ_CONFIG[1],
        cmd::READ_CONFIG[2],
        cmd::READ_CONFIG[3],
        n, // P3 = Le = number of bytes wanted
    ]
}

/// Build the bodyless `WRITE_SEED` that erases every entry (spec §6.5). The
/// device requires a confirming button press, so the transport should set its
/// "detect button wait" flag.
pub fn erase_all() -> Vec<u8> {
    build_apdu(cmd::WRITE_SEED, &[])
}

/// Build the FIDO-applet `GET_INFO` serial-number request (spec §6.10): the
/// fixed 18-byte payload `D1 10` followed by 16 zero bytes.
pub fn read_serial_request() -> Vec<u8> {
    let mut payload = [0u8; 18];
    payload[0] = 0xD1;
    payload[1] = 0x10;
    build_apdu(cmd::READ_SERIAL_INS, &payload)
}

/// Parse the serial-number response (spec §6.10): `D1 len ascii_hex...`. The SN
/// is double-encoded — ASCII-hex characters the host then hex-decodes to bytes.
pub fn parse_serial(data: &[u8]) -> Result<Vec<u8>, ParseError> {
    if data.len() < 2 || data[0] != 0xD1 {
        return Err(ParseError::Truncated);
    }
    let sn_len = data[1] as usize;
    let hex = data.get(2..2 + sn_len).ok_or(ParseError::Truncated)?;
    decode_ascii_hex(hex)
}

/// Decode an even-length ASCII-hex byte slice (spec §6.10 SN field).
fn decode_ascii_hex(hex: &[u8]) -> Result<Vec<u8>, ParseError> {
    if hex.len() % 2 != 0 {
        return Err(ParseError::Malformed("serial hex length is odd"));
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for pair in hex.chunks_exact(2) {
        let hi = hex_nibble(pair[0]).ok_or(ParseError::Malformed("non-hex char in serial"))?;
        let lo = hex_nibble(pair[1]).ok_or(ParseError::Malformed("non-hex char in serial"))?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Decoded `READ_CONFIG` device-info blob (spec §6.9). Each meaningful bit is
/// exposed as a named boolean rather than making callers mask bytes (spec §8.3).
///
/// Bit numbering follows the manual: "bit 1" is `value & 0x01`, "bit 8" is
/// `value & 0x80` (spec §6.9 reminder).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    pub transfer_type: u8,
    pub device_config: u8,
    pub appearance: [u8; 4],
    pub fido_version: [u8; 3],
    pub device_extension: u8,
    /// Anything beyond byte 9, retained for forward-compat (spec §8.3).
    pub raw_tail: Vec<u8>,
    /// Number of bytes actually returned by READ_CONFIG. Over CCID/NFC some
    /// firmware returns only byte 0 (interface states) while USB-HID returns the
    /// full block; this lets callers tell a real `false` from a zero-pad.
    pub raw_len: usize,
}

impl DeviceInfo {
    /// Parse the device-info response (spec §6.9). The interface-state bits all
    /// live in byte 0 (`transfer_type`), so that byte is the only hard
    /// requirement. Some firmware returns just the config byte(s) rather than the
    /// full fixed-format block, so the later appearance/version/extension fields
    /// are filled from whatever is present and default to zero when absent.
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.is_empty() {
            return Err(ParseError::Truncated);
        }
        let get = |i: usize| data.get(i).copied().unwrap_or(0);
        Ok(DeviceInfo {
            transfer_type: data[0],
            device_config: get(1),
            appearance: [get(2), get(3), get(4), get(5)],
            fido_version: [get(6), get(7), get(8)],
            device_extension: get(9),
            raw_tail: if data.len() > 10 {
                data[10..].to_vec()
            } else {
                Vec::new()
            },
            raw_len: data.len(),
        })
    }

    /// Whether the response actually contained the config byte (byte 1), as
    /// opposed to being a short CCID/NFC stub that only carried byte 0. When this
    /// is false, flags derived from `device_config` / `device_extension` (e.g.
    /// the button-HOTP seed status) are not trustworthy and should be treated as
    /// unknown rather than `false`.
    pub fn has_config_byte(&self) -> bool {
        self.raw_len >= 2
    }

    // --- transfer-type bits (byte 0) ---
    /// Bit 1: FIDO interface disabled.
    pub fn fido_disabled(&self) -> bool {
        self.transfer_type & 0x01 != 0
    }
    /// Bit 2: HOTP-via-keystroke disabled.
    pub fn hotp_keystroke_disabled(&self) -> bool {
        self.transfer_type & 0x02 != 0
    }
    /// Bit 3: CCID/smart-card interface disabled.
    pub fn ccid_disabled(&self) -> bool {
        self.transfer_type & 0x04 != 0
    }

    // --- device-config bits (byte 1) ---
    /// Bit 1: HOTP will *not* send Enter after the code.
    pub fn hotp_suppresses_enter(&self) -> bool {
        self.device_config & 0x01 != 0
    }
    /// Bit 2: a FIDO PIN is registered.
    pub fn fido_pin_set(&self) -> bool {
        self.device_config & 0x02 != 0
    }
    /// Bit 3: HOTP is supported.
    pub fn hotp_supported(&self) -> bool {
        self.device_config & 0x04 != 0
    }
    /// Bit 4: a fingerprint sensor is present.
    pub fn fingerprint_present(&self) -> bool {
        self.device_config & 0x08 != 0
    }
    /// Bit 5: NFC is supported.
    pub fn nfc_supported(&self) -> bool {
        self.device_config & 0x10 != 0
    }
    /// Bit 6: HOTP is triggered by a *long* press (else short tap).
    pub fn hotp_long_press(&self) -> bool {
        self.device_config & 0x20 != 0
    }
    /// Bit 7: the FIDO PIN is locked.
    pub fn pin_locked(&self) -> bool {
        self.device_config & 0x40 != 0
    }
    /// Bit 8: the HOTP-on-button seed slot is occupied.
    pub fn button_hotp_configured(&self) -> bool {
        self.device_config & 0x80 != 0
    }

    // --- device-extension bits (byte 9) ---
    /// Bit 1: the TOTP function is supported.
    pub fn totp_supported(&self) -> bool {
        self.device_extension & 0x01 != 0
    }
    /// Bit 2: FIDO 2.1 is supported.
    pub fn fido_21_supported(&self) -> bool {
        self.device_extension & 0x02 != 0
    }
    /// Bit 4: HOTP keystrokes use the numeric-keypad layout (else main row).
    pub fn hotp_uses_numpad(&self) -> bool {
        self.device_extension & 0x08 != 0
    }
    /// Bit 5: a CCID interface is supported.
    pub fn ccid_supported(&self) -> bool {
        self.device_extension & 0x10 != 0
    }
    /// Bit 6 is set when HOTP-on-button is **not** supported; this returns the
    /// inverted, positive sense ("is button-HOTP available?") for ergonomics.
    pub fn button_hotp_supported(&self) -> bool {
        self.device_extension & 0x20 == 0
    }
}

/// Which USB interfaces a `SET_DEVICE_TYPE` mask would leave enabled, and the
/// guard against bricking the device (spec §6.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetDeviceTypeError {
    /// The supplied mask would disable every interface, leaving the device with
    /// no way to be talked to — refused client-side exactly as the vendor
    /// companion app does (spec §6.8).
    WouldBrick,
}

impl std::fmt::Display for SetDeviceTypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SetDeviceTypeError::WouldBrick => write!(
                f,
                "refusing SET_DEVICE_TYPE: mask would disable every interface and brick the key"
            ),
        }
    }
}

impl std::error::Error for SetDeviceTypeError {}

/// The three interface bits in a `SET_DEVICE_TYPE` disable-mask (spec §6.8).
pub const DEV_FIDO: u8 = 0x01;
pub const DEV_KEYBOARD: u8 = 0x02;
pub const DEV_CCID: u8 = 0x04;
/// All three interface bits — a mask equal to this disables everything.
pub const DEV_ALL: u8 = DEV_FIDO | DEV_KEYBOARD | DEV_CCID;

/// Build a guarded `SET_DEVICE_TYPE` APDU from a disable-mask (spec §6.8).
///
/// The firmware does **not** refuse a mask that disables every interface, which
/// bricks the key. This function performs the same client-side check the vendor
/// companion app does and returns [`SetDeviceTypeError::WouldBrick`] rather than
/// emit such an APDU. Bits outside the three known interfaces are ignored for
/// the brick check but still sent, matching the raw protocol.
pub fn set_device_type(disable_mask: u8) -> Result<Vec<u8>, SetDeviceTypeError> {
    if disable_mask & DEV_ALL == DEV_ALL {
        return Err(SetDeviceTypeError::WouldBrick);
    }
    Ok(build_apdu(cmd::SET_DEVICE_TYPE, &[disable_mask]))
}

/// Validate an entry seed length after Base32 decode (spec §9): `1..=64` bytes.
pub fn validate_seed_len(decoded_len: usize) -> Result<(), &'static str> {
    match decoded_len {
        1..=64 => Ok(()),
        0 => Err("seed is empty after Base32 decode"),
        _ => Err("seed exceeds 64 bytes after Base32 decode"),
    }
}

/// Decode a user-supplied Base32 (RFC 4648) seed, re-padding stripped `=` first
/// (spec §9, §10). Returns the raw seed bytes, wrapped so they zeroize on drop.
pub fn decode_base32_seed(s: &str) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let upper = cleaned.trim_end_matches('=').to_ascii_uppercase();
    let decoded = base32_decode(&upper)?;
    validate_seed_len(decoded.len())?;
    Ok(Zeroizing::new(decoded))
}

/// Minimal RFC 4648 Base32 decoder (no external dep, matching the "vendor over
/// depend" convention — base32 is already hand-rolled elsewhere in the tree).
/// Input must be upper-case with padding already stripped.
fn base32_decode(s: &str) -> Result<Vec<u8>, &'static str> {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    for ch in s.bytes() {
        let val = ALPHABET
            .iter()
            .position(|&a| a == ch)
            .ok_or("invalid Base32 character in seed")? as u64;
        buffer = (buffer << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_config_apdu_form() {
        // §1.11: short case-2 `80 C5 02 00 <Le>` — Le is the byte count wanted.
        assert_eq!(read_config(64), vec![0x80, 0xC5, 0x02, 0x00, 0x40]);
        assert_eq!(*read_config(0).last().unwrap(), 0x01); // clamped to >=1
        assert_eq!(*read_config(200).last().unwrap(), 0x40); // clamped to <=64
                                                             // §1.1 pubkey read: short case-2 with Le=0x00.
        assert_eq!(get_ecdh_pubkey(), vec![0x80, 0xC5, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn enum_codes_apdu_layout() {
        // ENUM_CODES READ_ALL at t=0 (spec §10.1 host frame). A 9-byte body uses
        // short-form Lc (single 0x09), the encoding T=0 contact readers accept.
        let mut data = vec![cmd::SUB_READ_ALL];
        data.extend_from_slice(&0u64.to_be_bytes());
        let apdu = build_apdu(cmd::ENUM_CODES, &data);
        assert_eq!(
            apdu,
            vec![
                0x80, 0xC5, 0x05, 0x00, // header
                0x09, // short Lc = 9
                0x03, // READ_ALL
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // u64 ts = 0
            ]
        );
    }

    #[test]
    fn erase_all_is_bodyless_write_seed() {
        // erase-all is a WRITE_SEED with no data at all (spec §6.5, §11).
        assert_eq!(erase_all(), vec![0x80, 0xC5, 0x05, 0x02]);
    }

    #[test]
    fn select_uses_short_lc() {
        let apdu = build_select(&OTP_APPLET_AID);
        assert_eq!(
            apdu,
            vec![0x00, 0xA4, 0x04, 0x00, 0x08, 0xF0, 0x00, 0x00, 0x01, 0x4F, 0x74, 0x70, 0x01]
        );
    }

    #[test]
    fn status_word_mapping() {
        assert_eq!(OtpError::check(0x9000), Ok(()));
        assert_eq!(OtpError::check(0x6A80), Err(OtpError::EntryNotFound));
        assert_eq!(OtpError::check(0x6A83), Err(OtpError::EntryNotFound));
        assert_eq!(OtpError::check(0x6A84), Err(OtpError::NotEnoughSpace));
        assert_eq!(OtpError::check(0x6A86), Err(OtpError::HidNotSupported));
        assert_eq!(OtpError::check(0x6FF9), Err(OtpError::ButtonPressRequired));
        assert_eq!(
            OtpError::check(0x6985),
            Err(OtpError::BadStatusCode(0x6985))
        );
        assert!(OtpError::check(0x6A80).unwrap_err().is_empty_token());
    }

    #[test]
    fn set_device_type_refuses_brick() {
        assert_eq!(
            set_device_type(DEV_ALL),
            Err(SetDeviceTypeError::WouldBrick)
        );
        // disabling just the keyboard leaves FIDO+CCID — allowed (spec §6.8 example).
        // Short-form Lc (single 0x01) for the 1-byte mask body.
        assert_eq!(
            set_device_type(DEV_KEYBOARD).unwrap(),
            vec![0x80, 0xC5, 0x02, 0x01, 0x01, 0x02]
        );
    }

    #[test]
    fn device_info_bit_decoding() {
        // extension bit 1 set (TOTP supported), config bit 3 set (HOTP supported),
        // config bit 8 set (button-HOTP slot occupied).
        let data = [0x00, 0x84, 0x86, 0x01, 0x00, 0x00, 0x02, 0x00, 0x01, 0x01];
        let info = DeviceInfo::parse(&data).unwrap();
        assert!(info.totp_supported());
        assert!(info.hotp_supported());
        assert!(info.button_hotp_configured());
        assert!(!info.hotp_suppresses_enter());
        assert!(info.button_hotp_supported()); // ext bit 6 clear -> supported
    }

    #[test]
    fn device_info_parses_short_response() {
        // Some firmware returns only the config byte(s) from READ_CONFIG rather
        // than the full 10-byte block. The interface-state bits live in byte 0,
        // so a 1-byte response (e.g. 0x02 = keyboard-HID disabled) must still
        // parse, with the optional trailing fields defaulting to zero.
        let info = DeviceInfo::parse(&[0x02]).unwrap();
        assert!(!info.fido_disabled());
        assert!(info.hotp_keystroke_disabled());
        assert!(!info.ccid_disabled());
        // device_extension defaults to 0 -> button-HOTP reported as supported.
        assert!(info.button_hotp_supported());
        // An empty response is still rejected.
        assert!(DeviceInfo::parse(&[]).is_err());
    }

    #[test]
    fn serial_double_decode() {
        // D1, len=10 ascii-hex chars "1234567890" -> bytes 12 34 56 78 90 (spec §10.3).
        let resp = [
            0xD1, 0x0A, b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0',
        ];
        assert_eq!(
            parse_serial(&resp).unwrap(),
            vec![0x12, 0x34, 0x56, 0x78, 0x90]
        );
    }

    #[test]
    fn base32_seed_decodes_hello() {
        // "Hello" = 0x48 65 6c 6c 6f; Base32 = "JBSWY3DP" (spec §10.2 uses this seed).
        let seed = decode_base32_seed("JBSWY3DP").unwrap();
        assert_eq!(&seed[..], b"Hello");
    }

    #[test]
    fn base32_repads_stripped_padding() {
        // lower-case + stripped padding should still decode (spec §9 forgiving rule).
        let seed = decode_base32_seed("jbswy3dp").unwrap();
        assert_eq!(&seed[..], b"Hello");
    }
}
