//! CanoKey's vendor commands over APDU.
//!
//! A CanoKey carries, beside the standard OpenPGP, PIV, OATH and FIDO
//! applets, an Admin applet of its own (AID `F0 00 00 00 00`): it reports
//! the firmware version, the hardware variant, the serial and the device
//! configuration, and resets single applets or the whole device. Its PIV
//! applet has a configurable table of algorithm IDs, and over USB its FIDO
//! applet answers a private selector instead of the standard FIDO AID.
//!
//! Every command and rule here is taken from the CanoKey firmware source,
//! canokey-core 3.1.2 (`a349b26`), and CanoKey's own Admin documentation:
//! `applets/admin/admin.c`, `include/admin.h`, `applets/piv/piv.c` and
//! `src/apdu.c`. Where a rule only holds from a firmware version on, the
//! item says so.
//!
//! # What is and isn't here
//!
//! This is the *byte layer*: it turns intentions into APDU byte vectors and
//! response byte slices into typed values. It performs **no I/O**; the card
//! exchange lives in `keyroost-transport`.

use keyroost_proto::apdu::{build_apdu, build_apdu_get};
use zeroize::Zeroizing;

/// The Admin applet's AID (`src/apdu.c`).
pub const ADMIN_AID: [u8; 5] = [0xF0, 0x00, 0x00, 0x00, 0x00];

/// The FIDO applet's selector over a USB APDU interface (CCID or WebUSB)
/// from firmware 3.1.2 on: `F0 43 41 4E 4F 46 49 44`. Over USB that firmware
/// answers only this one; over NFC it answers only the standard FIDO AID
/// (`A0 00 00 06 47 2F 00 01`). Earlier firmware answers the standard AID
/// over every interface, so a host tries this selector first and the
/// standard AID after it, as CanoKey's own `ckman` does. The SELECT answers
/// `U2F_V2`, needs no PIN and writes nothing (canokey-core `c07ad675`).
pub const FIDO_USB_AID: [u8; 8] = [0xF0, 0x43, 0x41, 0x4E, 0x4F, 0x46, 0x49, 0x44];

/// The historical bytes of the ATR a CanoKey answers over its USB CCID
/// interface, `Canokey` in ASCII
/// (`interfaces/USB/class/ccid/ccid.c`: `3B F7 11 00 00 81 31 FE 65 ...`).
/// A CanoKey held to an NFC reader gets an ATR the reader builds, which is
/// not known to carry them.
pub const CCID_ATR_HISTORICAL_BYTES: &[u8] = b"Canokey";

/// Success.
pub const SW_OK: u16 = 0x9000;
/// The command needs a verified Admin PIN, or, for a factory reset, a touch
/// that didn't come.
pub const SW_SECURITY_STATUS_NOT_SATISFIED: u16 = 0x6982;
/// The Admin PIN is blocked.
pub const SW_AUTHENTICATION_BLOCKED: u16 = 0x6983;
/// A factory reset sent while the Admin PIN still has tries left, or over NFC.
pub const SW_CONDITIONS_NOT_SATISFIED: u16 = 0x6985;
/// The instruction is unknown (or the applet it resets is not built in).
pub const SW_INS_NOT_SUPPORTED: u16 = 0x6D00;

/// Admin PIN length limits (`admin.c`: `min_length = 6`, `PIN_MAX_LENGTH`).
pub const ADMIN_PIN_MIN_LEN: usize = 6;
/// See [`ADMIN_PIN_MIN_LEN`].
pub const ADMIN_PIN_MAX_LEN: usize = 64;
/// The Admin PIN's retry limit (`admin.c`: `PIN_RETRY_COUNTER 3`). A wrong
/// PIN entered this many times in a row blocks it; only a factory reset
/// unblocks it, restoring the default PIN `123456`.
pub const ADMIN_PIN_RETRIES: u8 = 3;

/// Admin instruction bytes (`include/admin.h`); CLA is `00`.
mod ins {
    pub const RESET_OPENPGP: u8 = 0x03;
    pub const RESET_PIV: u8 = 0x04;
    pub const RESET_OATH: u8 = 0x05;
    pub const RESET_NDEF: u8 = 0x07;
    pub const RESET_CTAP: u8 = 0x09;
    pub const RESET_PASS: u8 = 0x13;
    pub const VERIFY: u8 = 0x20;
    pub const READ_VERSION: u8 = 0x31;
    pub const READ_SN: u8 = 0x32;
    pub const READ_CONFIG: u8 = 0x42;
    pub const FACTORY_RESET: u8 = 0x50;
}

/// `SELECT` of the Admin applet. Selecting it ends any other applet's
/// session on the key (PIN and management-key authentication included), so
/// a host reads the Admin applet before it authenticates to another one.
#[must_use]
pub fn select_admin() -> Vec<u8> {
    build_apdu(0x00, 0xA4, 0x04, 0x00, &ADMIN_AID)
}

/// `SELECT` of the FIDO applet by [`FIDO_USB_AID`].
#[must_use]
pub fn select_fido_usb() -> Vec<u8> {
    let mut apdu = build_apdu(0x00, 0xA4, 0x04, 0x00, &FIDO_USB_AID);
    apdu.push(0x00);
    apdu
}

/// Read the firmware version (INS 31, P1 00): text such as `3.1.2`, needing
/// no PIN. Decode it with [`parse_firmware_version`].
#[must_use]
pub fn read_firmware_version() -> Vec<u8> {
    build_apdu_get(0x00, ins::READ_VERSION, 0x00, 0x00, 0x00)
}

/// Read the hardware variant (INS 31, P1 01): text naming the hardware,
/// such as `CanoKey NFC-A (STM32)`, needing no PIN. Decode it with
/// [`parse_text`].
#[must_use]
pub fn read_hardware_variant() -> Vec<u8> {
    build_apdu_get(0x00, ins::READ_VERSION, 0x01, 0x00, 0x00)
}

/// Read the four-byte device serial (INS 32, P1 00), needing no PIN.
/// Decode it with [`parse_serial`].
#[must_use]
pub fn read_serial() -> Vec<u8> {
    build_apdu_get(0x00, ins::READ_SN, 0x00, 0x00, 0x00)
}

/// Read the device configuration (INS 42), needing no PIN from firmware
/// 3.1.0 on (earlier firmware asks for the Admin PIN, and lays the bytes
/// out differently). Decode it with [`parse_config`].
#[must_use]
pub fn read_config() -> Vec<u8> {
    build_apdu_get(0x00, ins::READ_CONFIG, 0x00, 0x00, 0x00)
}

/// VERIFY with no data: whether the Admin PIN is verified in this session
/// (`9000`), and otherwise how many tries it has left (`63Cx`) or that it
/// is blocked (`6983`). Costs no try. Read the answer with
/// [`pin_tries_from_sw`].
#[must_use]
pub fn pin_status() -> Vec<u8> {
    vec![0x00, ins::VERIFY, 0x00, 0x00]
}

/// Why an Admin PIN can't be sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinError {
    /// Shorter than [`ADMIN_PIN_MIN_LEN`] or longer than
    /// [`ADMIN_PIN_MAX_LEN`] bytes: the applet would refuse it without
    /// counting a try.
    Length,
}

impl std::fmt::Display for PinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PinError::Length => write!(
                f,
                "a CanoKey Admin PIN is {ADMIN_PIN_MIN_LEN} to {ADMIN_PIN_MAX_LEN} characters"
            ),
        }
    }
}

impl std::error::Error for PinError {}

/// VERIFY the Admin PIN. The APDU carries the PIN, so it is wiped on drop.
/// A wrong PIN costs one of [`ADMIN_PIN_RETRIES`] tries.
///
/// # Errors
/// [`PinError::Length`] for a PIN the applet would refuse by its length.
pub fn verify_pin(pin: &[u8]) -> Result<Zeroizing<Vec<u8>>, PinError> {
    if !(ADMIN_PIN_MIN_LEN..=ADMIN_PIN_MAX_LEN).contains(&pin.len()) {
        return Err(PinError::Length);
    }
    Ok(Zeroizing::new(build_apdu(
        0x00,
        ins::VERIFY,
        0x00,
        0x00,
        pin,
    )))
}

/// The tries an Admin PIN has left, from the status word of a VERIFY:
/// `Some(x)` for `63Cx`, `Some(0)` for `6983` (blocked), `None` for any
/// other status word (`9000` among them).
#[must_use]
pub fn pin_tries_from_sw(sw: u16) -> Option<u8> {
    match sw {
        SW_AUTHENTICATION_BLOCKED => Some(0),
        _ if sw & 0xFFF0 == 0x63C0 => Some((sw & 0x000F) as u8),
        _ => None,
    }
}

/// An applet the Admin applet resets on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applet {
    /// OpenPGP keys, data objects and PINs.
    OpenPgp,
    /// PIV keys, data objects, PIN, PUK and management key (the attestation
    /// key and certificate are kept).
    Piv,
    /// Every OATH account and the OATH password.
    Oath,
    /// The NDEF message (only on firmware built with the NDEF applet).
    Ndef,
    /// Every FIDO2 credential and the FIDO2 PIN (firmware 3.0.0 and later).
    Ctap,
    /// Both PASS touch slots (firmware 3.0.0 and later).
    Pass,
}

impl Applet {
    const fn ins(self) -> u8 {
        match self {
            Applet::OpenPgp => ins::RESET_OPENPGP,
            Applet::Piv => ins::RESET_PIV,
            Applet::Oath => ins::RESET_OATH,
            Applet::Ndef => ins::RESET_NDEF,
            Applet::Ctap => ins::RESET_CTAP,
            Applet::Pass => ins::RESET_PASS,
        }
    }
}

/// Reset one applet to its factory state. Needs the Admin PIN verified in
/// the same Admin session (`6982` otherwise); no touch.
#[must_use]
pub fn reset_applet(applet: Applet) -> Vec<u8> {
    vec![0x00, applet.ins(), 0x00, 0x00]
}

/// Reset the whole device (INS 50 with `RESET`): every applet, the Admin
/// PIN and the device configuration return to their defaults; the serial
/// stays. The key accepts it only once the Admin PIN is blocked, only over
/// USB, and only when it is touched within about two seconds while it
/// blinks; otherwise it answers `6985` (PIN not blocked, or NFC) or `6982`
/// (no touch).
#[must_use]
pub fn factory_reset() -> Vec<u8> {
    build_apdu(0x00, ins::FACTORY_RESET, 0x00, 0x00, b"RESET")
}

/// A firmware version, as the Admin applet reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareVersion {
    pub major: u8,
    pub minor: u8,
    /// `0` when the text gives only major and minor.
    pub patch: u8,
    /// A development or build suffix, with its leading `-` or `+`
    /// (`-dev`, `-O`), as reported.
    pub suffix: Option<String>,
}

impl FirmwareVersion {
    /// The numeric part, `[major, minor, patch]`, for comparing versions.
    #[must_use]
    pub fn numbers(&self) -> [u8; 3] {
        [self.major, self.minor, self.patch]
    }
}

impl std::fmt::Display for FirmwareVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if let Some(suffix) = &self.suffix {
            f.write_str(suffix)?;
        }
        Ok(())
    }
}

/// Read a firmware version from the Admin applet's text: an optional `v`,
/// two or three dot-separated numbers, then an optional suffix starting
/// with `-` or `+` (the form CanoKey's own libcanokey accepts). `None` for
/// any other text, or a number above 255.
#[must_use]
pub fn parse_firmware_version(data: &[u8]) -> Option<FirmwareVersion> {
    let text = std::str::from_utf8(data)
        .ok()?
        .trim_matches(|c: char| c.is_whitespace() || c == '\0');
    let text = text.strip_prefix('v').unwrap_or(text);
    let at = text.find(['-', '+']).unwrap_or(text.len());
    let (numbers, suffix) = text.split_at(at);
    if suffix.len() == 1 {
        return None;
    }
    let parts: Vec<&str> = numbers.split('.').collect();
    if !(2..=3).contains(&parts.len())
        || parts
            .iter()
            .any(|p| p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()))
    {
        return None;
    }
    Some(FirmwareVersion {
        major: parts[0].parse().ok()?,
        minor: parts[1].parse().ok()?,
        patch: parts.get(2).map_or(Some(0), |p| p.parse().ok())?,
        suffix: (!suffix.is_empty()).then(|| suffix.to_string()),
    })
}

/// Read the Admin applet's text answers (firmware version, hardware
/// variant): UTF-8 with surrounding whitespace and NUL padding trimmed.
/// `None` when nothing is left or it isn't UTF-8.
#[must_use]
pub fn parse_text(data: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(data).ok()?;
    let text = text.trim_matches(|c: char| c.is_whitespace() || c == '\0');
    (!text.is_empty()).then(|| text.to_string())
}

/// Read the device serial from the four bytes the Admin applet's INS 32 or
/// PIV's GET SERIAL returns: their big-endian value, which CanoKey shows in
/// decimal. `None` for any other length, and for a serial that was never
/// written (see [`serial_is_unset`]).
#[must_use]
pub fn parse_serial(data: &[u8]) -> Option<u32> {
    let bytes: [u8; 4] = data.try_into().ok()?;
    let serial = u32::from_be_bytes(bytes);
    (!serial_is_unset(serial)).then_some(serial)
}

/// Whether a serial value is one a key with no serial written reports: all
/// zero bytes (the firmware's answer when its serial file is missing) or
/// all `FF` (erased flash, as on a DevKit). Every such key reports the same
/// value, so it tells none of them apart.
#[must_use]
pub const fn serial_is_unset(serial: u32) -> bool {
    serial == 0 || serial == u32::MAX
}

/// The device configuration as firmware 3.1 reports it (INS 42, six bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// The LED stays on when the key isn't blinking.
    pub led_on: bool,
    /// The NDEF message can't be changed.
    pub ndef_read_only: bool,
    /// The NDEF applet answers.
    pub ndef_enabled: bool,
    /// The key announces its WebUSB landing page.
    pub webusb_landing: bool,
    /// The feature switches, one bit each ([`Feature`]); `1` is on.
    pub features: u8,
}

/// One of the switches in [`Config::features`] (firmware 3.1.0 and later).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feature {
    Pass = 0,
    OpenPgpUsb = 1,
    OpenPgpNfc = 2,
    PivUsb = 3,
    PivNfc = 4,
    WebAuthn = 5,
}

impl Config {
    /// Whether `feature` is switched on.
    #[must_use]
    pub fn feature(&self, feature: Feature) -> bool {
        self.features & (1 << feature as u8) != 0
    }
}

/// Read the device configuration from the 3.1 layout: LED, a reserved byte,
/// NDEF read-only, NDEF enabled, WebUSB landing page, feature switches.
/// `None` for another length or a flag byte that isn't `0` or `1`.
#[must_use]
pub fn parse_config(data: &[u8]) -> Option<Config> {
    let raw: [u8; 6] = data.try_into().ok()?;
    if [raw[0], raw[2], raw[3], raw[4]].iter().any(|&b| b > 1) {
        return None;
    }
    Some(Config {
        led_on: raw[0] == 1,
        ndef_read_only: raw[2] == 1,
        ndef_enabled: raw[3] == 1,
        webusb_landing: raw[4] == 1,
        features: raw[5],
    })
}

/// Read the PIV applet's algorithm ID table (`00 EE 01 00`), sent with PIV
/// selected. Needs no authentication from firmware 3.1.0 on (3.0 asks for
/// the management key). Decode it with [`parse_piv_algorithm_ids`].
#[must_use]
pub fn read_piv_algorithm_ids() -> Vec<u8> {
    build_apdu_get(0x00, 0xEE, 0x01, 0x00, 0x00)
}

/// The PIV algorithm IDs a CanoKey uses for the algorithms outside SP
/// 800-78 (RSA-2048 `07`, P-256 `11` and P-384 `14` are fixed). Each is
/// configurable, so a host reads them rather than assume the defaults;
/// with `enabled` off, none of these algorithms is available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PivAlgorithmIds {
    pub enabled: bool,
    pub ed25519: u8,
    pub rsa3072: u8,
    pub rsa4096: u8,
    pub x25519: u8,
    pub secp256k1: u8,
    pub secp521r1: u8,
    pub sm2: u8,
    pub mldsa65: u8,
    pub mlkem768: u8,
}

impl PivAlgorithmIds {
    /// The table a CanoKey ships with (`piv.c`: `ALG_*_DEFAULT`).
    pub const DEFAULT: PivAlgorithmIds = PivAlgorithmIds {
        enabled: true,
        ed25519: 0xE0,
        rsa3072: 0x05,
        rsa4096: 0x16,
        x25519: 0xE1,
        secp256k1: 0x53,
        secp521r1: 0x15,
        sm2: 0x54,
        mldsa65: 0xE2,
        mlkem768: 0xE3,
    };
}

/// Read the PIV algorithm ID table from firmware 3.1's ten bytes: enabled,
/// then Ed25519, RSA-3072, RSA-4096, X25519, secp256k1, P-521, SM2,
/// ML-DSA-65, ML-KEM-768. Longer tables (later firmware appends IDs) are
/// read for these ten. `None` when shorter, when the enable byte isn't `0`
/// or `1`, or when an enabled table breaks the firmware's own rule that the
/// IDs are distinct and none is `00`, `07`, `0A`, `11`, `14` or `FF`.
#[must_use]
pub fn parse_piv_algorithm_ids(data: &[u8]) -> Option<PivAlgorithmIds> {
    let raw = data.get(..10)?;
    if raw[0] > 1 {
        return None;
    }
    let ids = &raw[1..];
    if raw[0] == 1 {
        for (i, id) in ids.iter().enumerate() {
            if [0x00, 0x07, 0x0A, 0x11, 0x14, 0xFF].contains(id) || ids[..i].contains(id) {
                return None;
            }
        }
    }
    Some(PivAlgorithmIds {
        enabled: raw[0] == 1,
        ed25519: ids[0],
        rsa3072: ids[1],
        rsa4096: ids[2],
        x25519: ids[3],
        secp256k1: ids[4],
        secp521r1: ids[5],
        sm2: ids[6],
        mldsa65: ids[7],
        mlkem768: ids[8],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_commands_are_the_documented_bytes() {
        assert_eq!(
            select_admin(),
            [0x00, 0xA4, 0x04, 0x00, 0x05, 0xF0, 0, 0, 0, 0]
        );
        assert_eq!(read_firmware_version(), [0x00, 0x31, 0x00, 0x00, 0x00]);
        assert_eq!(read_hardware_variant(), [0x00, 0x31, 0x01, 0x00, 0x00]);
        assert_eq!(read_serial(), [0x00, 0x32, 0x00, 0x00, 0x00]);
        assert_eq!(read_config(), [0x00, 0x42, 0x00, 0x00, 0x00]);
        assert_eq!(pin_status(), [0x00, 0x20, 0x00, 0x00]);
        assert_eq!(reset_applet(Applet::Oath), [0x00, 0x05, 0x00, 0x00]);
        assert_eq!(reset_applet(Applet::Piv), [0x00, 0x04, 0x00, 0x00]);
        assert_eq!(reset_applet(Applet::OpenPgp), [0x00, 0x03, 0x00, 0x00]);
        assert_eq!(reset_applet(Applet::Ctap), [0x00, 0x09, 0x00, 0x00]);
        assert_eq!(reset_applet(Applet::Ndef), [0x00, 0x07, 0x00, 0x00]);
        assert_eq!(reset_applet(Applet::Pass), [0x00, 0x13, 0x00, 0x00]);
        assert_eq!(
            factory_reset(),
            [0x00, 0x50, 0x00, 0x00, 0x05, b'R', b'E', b'S', b'E', b'T']
        );
        assert_eq!(
            select_fido_usb(),
            [0x00, 0xA4, 0x04, 0x00, 0x08, 0xF0, 0x43, 0x41, 0x4E, 0x4F, 0x46, 0x49, 0x44, 0x00]
        );
        assert_eq!(read_piv_algorithm_ids(), [0x00, 0xEE, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn verify_carries_the_pin_unpadded_and_checks_its_length() {
        assert_eq!(
            verify_pin(b"123456").unwrap().as_slice(),
            b"\x00\x20\x00\x00\x06123456"
        );
        assert_eq!(verify_pin(b"12345"), Err(PinError::Length));
        assert_eq!(verify_pin(&[b'1'; 65]), Err(PinError::Length));
        assert!(verify_pin(&[b'1'; 64]).is_ok());
    }

    #[test]
    fn pin_tries_come_from_63cx_and_6983() {
        assert_eq!(pin_tries_from_sw(0x63C2), Some(2));
        assert_eq!(pin_tries_from_sw(0x63C0), Some(0));
        assert_eq!(pin_tries_from_sw(0x6983), Some(0));
        assert_eq!(pin_tries_from_sw(0x9000), None);
        assert_eq!(pin_tries_from_sw(0x6700), None);
    }

    #[test]
    fn firmware_versions_parse_as_libcanokey_reads_them() {
        let v = parse_firmware_version(b"3.1.2").unwrap();
        assert_eq!((v.numbers(), v.suffix), ([3, 1, 2], None));
        let v = parse_firmware_version(b"v3.1-dev").unwrap();
        assert_eq!(
            (v.numbers(), v.suffix.as_deref()),
            ([3, 1, 0], Some("-dev"))
        );
        assert_eq!(
            parse_firmware_version(b"3.0.2-O").unwrap().to_string(),
            "3.0.2-O"
        );
        for bad in [
            &b"3"[..],
            b"3.1.2.4",
            b"3.x",
            b"",
            b"3.1-",
            b"abc",
            b"3.256.0",
            b"\xFF",
        ] {
            assert_eq!(parse_firmware_version(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn serials_are_big_endian_and_unwritten_ones_are_none() {
        assert_eq!(parse_serial(&[0x1A, 0x2B, 0x3C, 0x4D]), Some(439_041_101));
        assert_eq!(parse_serial(&[0; 4]), None);
        assert_eq!(parse_serial(&[0xFF; 4]), None);
        assert_eq!(parse_serial(&[1, 2, 3]), None);
    }

    #[test]
    fn the_configuration_reads_the_31_layout() {
        let c = parse_config(&[1, 0, 0, 1, 1, 0b0011_1111]).unwrap();
        assert!(c.led_on && !c.ndef_read_only && c.ndef_enabled && c.webusb_landing);
        assert!(c.feature(Feature::PivUsb) && c.feature(Feature::WebAuthn));
        let c = parse_config(&[0, 0, 1, 0, 0, 0b0000_0001]).unwrap();
        assert!(c.feature(Feature::Pass) && !c.feature(Feature::OpenPgpUsb));
        assert_eq!(parse_config(&[2, 0, 0, 0, 0, 0]), None);
        assert_eq!(parse_config(&[1, 0, 0, 1, 1]), None);
    }

    #[test]
    fn the_algorithm_id_table_reads_the_firmware_default() {
        let raw = [1, 0xE0, 0x05, 0x16, 0xE1, 0x53, 0x15, 0x54, 0xE2, 0xE3];
        assert_eq!(
            parse_piv_algorithm_ids(&raw),
            Some(PivAlgorithmIds::DEFAULT)
        );
        // Later firmware appends IDs; the first ten read the same.
        let mut longer = raw.to_vec();
        longer.extend([0xE4, 0xE5]);
        assert_eq!(
            parse_piv_algorithm_ids(&longer),
            Some(PivAlgorithmIds::DEFAULT)
        );
        // A disabled table is kept as it is, unchecked.
        let off = parse_piv_algorithm_ids(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        assert!(!off.enabled);
    }

    #[test]
    fn an_algorithm_id_table_the_firmware_would_refuse_is_none() {
        let mut dup = [1, 0xE0, 0x05, 0x16, 0xE1, 0x53, 0x15, 0x54, 0xE2, 0xE3];
        dup[2] = 0xE0;
        assert_eq!(parse_piv_algorithm_ids(&dup), None);
        let mut reserved = [1, 0xE0, 0x05, 0x16, 0xE1, 0x53, 0x15, 0x54, 0xE2, 0xE3];
        reserved[3] = 0x11;
        assert_eq!(parse_piv_algorithm_ids(&reserved), None);
        assert_eq!(
            parse_piv_algorithm_ids(&[2, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            None
        );
        assert_eq!(parse_piv_algorithm_ids(&[1, 0xE0]), None);
    }
}
