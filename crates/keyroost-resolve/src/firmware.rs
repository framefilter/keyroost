//! The firmware version to show for a FIDO key, read the way its vendor
//! states it.
//!
//! CTAPHID INIT carries three "device version" bytes (major, minor, build),
//! and vendors fill them differently:
//!
//! * Yubico: the firmware version itself (`5.7.4`), matching getInfo's
//!   `firmwareVersion` (`0x050704`).
//! * SoloKeys Solo 2: the major version, then its two-byte minor version
//!   split big-endian across the minor and build bytes, with no patch:
//!   `2, 3, 196` is firmware 2.964 (solo2 `runners/lpc55/src/initializer.rs`).
//! * Nitrokey 3: `0.0.0`; the real version comes from its admin
//!   application (`keyroost_transport::identity::trussed_admin_firmware`).
//! * Token2 PIN+: bytes Token2's own tools never show. Token2 names PIN+
//!   firmware by release (`R3.4`) and identifies it from the first five
//!   digits of the key's serial number, per its published "PIN+ Serial
//!   Number Prefix Reference" ([`token2_release`]).
//! * Feitian: bytes that are not the version Feitian lists for a key (a
//!   BioPass FIDO Pro's say `1.0.1`). Feitian's product list
//!   (<https://fido.ftsafe.com/products/>) gives each key a COS version,
//!   apart from the versions of its applications, and the key reports it
//!   in its device information, read over its smart-card reader
//!   (`keyroost_transport::identity::feitian_cos_version`). It is shown as
//!   the three bytes read, `47.17.00` for that key, where Feitian writes
//!   4.7.17. When that read gives nothing (no reader for the key here, or
//!   a key that doesn't answer it), the INIT bytes are shown as they are.
//!
//! [`key_firmware`] applies these rules for one key; the CLI's `fido info`
//! and the app's key header both show what it returns.

use std::path::Path;

/// SoloKeys' USB vendor ID, and the Solo 2's product ID.
const SOLOKEYS_VID: u16 = 0x1209;
const SOLO2_PID: u16 = 0xbeee;

/// Token2's USB vendor ID.
const TOKEN2_VID: u16 = keyroost_proto::USB_VID;

/// Feitian's USB vendor ID.
const FEITIAN_VID: u16 = 0x096e;

/// The firmware to show for the FIDO key at HID `path`, whose CTAPHID INIT
/// reported `version`: the INIT version read the vendor's way
/// ([`init_firmware`]); for a Token2, the release its serial names (the
/// row's `serial` when the scan read it, else read over USB); for a
/// Feitian key, the COS version it reports over `reader`, else its INIT
/// bytes as they are; when INIT says
/// 0.0.0 (a Nitrokey 3), what the admin application reports over `reader`.
/// `None` when the key doesn't say, or isn't found by `path`.
///
/// May ask the key (the Token2 serial, the admin application), so run it
/// off the UI thread, with no other handle to the key open: macOS opens
/// HID devices exclusively.
pub fn key_firmware(
    path: &Path,
    version: (u8, u8, u8),
    serial: Option<&str>,
    reader: Option<&str>,
    debug: bool,
) -> Option<String> {
    let (vendor_id, product_id) = keyroost_hid::enumerate()
        .ok()?
        .into_iter()
        .find(|d| d.path == path)
        .map(|d| (d.vendor_id, d.product_id))?;
    if let Some(v) = init_firmware(vendor_id, product_id, version) {
        return Some(v);
    }
    if vendor_id == TOKEN2_VID {
        // The row's serial when the scan read it in the FIDO form (the long
        // decimal serial; a card applet's short serial is a different
        // number); otherwise read it over USB. An unlisted prefix stays
        // unlisted rather than read again.
        let release = match serial.filter(|s| token2_fido_serial(s)) {
            Some(serial) => token2_release(serial),
            None => token2_release_hid(path, debug),
        };
        return release.map(str::to_owned);
    }
    if vendor_id == FEITIAN_VID {
        let cos = reader.and_then(|r| keyroost_transport::identity::feitian_cos_version(r, debug));
        return feitian_firmware(cos, version);
    }
    reader.and_then(|r| keyroost_transport::identity::trussed_admin_firmware(r, debug))
}

/// A Feitian key's firmware: the COS version it reported (`cos`) when the
/// read gave one; else its CTAPHID INIT bytes as they are, which is what
/// keyroost showed before it read the COS version. `None` when neither
/// says anything (INIT 0.0.0).
fn feitian_firmware(cos: Option<String>, version: (u8, u8, u8)) -> Option<String> {
    cos.or_else(|| {
        let (major, minor, build) = version;
        (version != (0, 0, 0)).then(|| format!("{major}.{minor}.{build}"))
    })
}

/// The firmware a key's CTAPHID INIT version bytes state, read the way
/// its vendor writes them; `None` when they don't state it (a Token2's, a
/// Feitian key's, or all zeros, as on a Nitrokey 3), so the caller asks the
/// key another way.
pub fn init_firmware(vendor_id: u16, product_id: u16, version: (u8, u8, u8)) -> Option<String> {
    let (major, minor, build) = version;
    if vendor_id == TOKEN2_VID || vendor_id == FEITIAN_VID || version == (0, 0, 0) {
        return None;
    }
    if (vendor_id, product_id) == (SOLOKEYS_VID, SOLO2_PID) {
        return Some(format!("{major}.{}", u16::from_be_bytes([minor, build])));
    }
    Some(format!("{major}.{minor}.{build}"))
}

/// Token2's "PIN+ Serial Number Prefix Reference": the first five digits of
/// a PIN+ key's serial number and the firmware release they identify. From
/// <https://www.token2.com/site/page/pin-firmware-feature-support-matrix-openpgp-fido2-otp-and-piv-across-releases>
/// (updated 2026-10-14). The one range of whole serials that table lists
/// (a custom access card) is left out. `packaging/check-token2-prefixes.py`
/// compares this with the page; the release playbook runs it in pre-flight.
const TOKEN2_PREFIXES: &[(&str, &str)] = &[
    ("86105", "R1"),
    ("86104", "R1"),
    ("86103", "R1"),
    ("86202", "R1"),
    ("96105", "R2"),
    ("96104", "R2"),
    ("96103", "R2"),
    ("23103", "R2"),
    ("76103", "R3"),
    ("76104", "R3"),
    ("76202", "R3"),
    ("86106", "R3"),
    ("76106", "R3"),
    ("76105", "R3.1"),
    ("26105", "R3.1"),
    ("72102", "R3.1"),
    ("77103", "R3.2"),
    ("24103", "R3.2"),
    ("72101", "R3.2"),
    ("72103", "R3.2"),
    ("22103", "R3.2"),
    ("66105", "R3.3"),
    ("66104", "R3.3"),
    ("66103", "R3.3"),
    ("66107", "R3.3"),
    ("66106", "R3.3"),
    ("66114", "R3.3"),
    ("66113", "R3.3"),
    ("66202", "R3.3"),
    ("66102", "R3.3"),
    ("66302", "R3.3"),
    ("66101", "R3.3"),
    ("66111", "R3.3"),
    ("72113", "R3.3"),
    ("24133", "R3.3"),
    ("65103", "R3.4"),
    ("65104", "R3.4"),
    ("72114", "R3.4"),
    ("74134", "R3.4"),
    ("65101", "R3.4"),
    ("65111", "R3.4"),
    ("65202", "R3.4"),
    ("65102", "R3.4"),
    ("65302", "R3.4"),
    ("65105", "R3.4"),
    ("65124", "R3.4"),
    ("65123", "R3.4"),
    ("65107", "R3.4"),
    ("65106", "R3.4"),
    ("65114", "R3.4"),
    ("65113", "R3.4"),
];

/// The PIN+ firmware release a Token2 serial number identifies, from its
/// first five digits; `None` for a serial too short, not starting with
/// digits, or with a prefix Token2's table doesn't list.
pub fn token2_release(serial: &str) -> Option<&'static str> {
    let prefix = serial.get(..5)?;
    if !prefix.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    TOKEN2_PREFIXES
        .iter()
        .find(|(p, _)| *p == prefix)
        .map(|(_, release)| *release)
}

/// Whether `serial` is a Token2 serial in the FIDO form (the long decimal
/// serial, which carries the prefix), not a card applet's short one.
fn token2_fido_serial(serial: &str) -> bool {
    serial.len() >= 10 && serial.bytes().all(|b| b.is_ascii_digit())
}

/// The release of the Token2 key at HID `path`, from its serial number read
/// over USB (the §6.10 serial request, read-only, the one device scans
/// send). `None` when the key doesn't answer or isn't in Token2's table.
fn token2_release_hid(path: &Path, debug: bool) -> Option<&'static str> {
    match keyroost_transport::identity::token2_serial_reply_hid(path, debug) {
        keyroost_transport::identity::KeyAnswer::Reply(reply) => token2_release_from_reply(&reply),
        _ => None,
    }
}

/// [`token2_release`] for a §6.10 serial reply in the FIDO format
/// (`D1 len hex-text`). The hex text, decoded and printed again, is the
/// form a row's serial takes ([`crate::identity::token2_from_fido_reply`]);
/// on a PIN+ key its characters are the decimal serial.
fn token2_release_from_reply(reply: &[u8]) -> Option<&'static str> {
    let bytes = keyroost_token2otp::parse_serial(reply).ok()?;
    let serial: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    token2_release(&serial)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_bytes_read_the_vendor_s_way() {
        // YubiKey: the bytes are the version.
        assert_eq!(
            init_firmware(0x1050, 0x0407, (5, 7, 4)).as_deref(),
            Some("5.7.4")
        );
        // Solo 2: a two-byte minor split across minor and build, no patch.
        assert_eq!(
            init_firmware(0x1209, 0xbeee, (2, 3, 196)).as_deref(),
            Some("2.964")
        );
        // Another 0x1209 product reads the bytes as they are.
        assert_eq!(
            init_firmware(0x1209, 0x0001, (1, 2, 3)).as_deref(),
            Some("1.2.3")
        );
        // Token2 and all-zero bytes don't state it.
        assert_eq!(init_firmware(0x349e, 0x0024, (2, 1, 2)), None);
        // A Feitian key's INIT bytes are not its COS version (a BioPass FIDO
        // Pro: INIT 1.0.1, COS 4.7.17), so they are not shown.
        assert_eq!(init_firmware(0x096e, 0x086a, (1, 0, 1)), None);
        assert_eq!(init_firmware(0x20a0, 0x42b2, (0, 0, 0)), None);
    }

    /// The COS version a Feitian key reports wins; without one, its INIT
    /// bytes are shown as before.
    #[test]
    fn a_feitian_key_shows_its_cos_version_else_its_init_bytes() {
        assert_eq!(
            feitian_firmware(Some("47.17.00".into()), (1, 0, 1)).as_deref(),
            Some("47.17.00")
        );
        assert_eq!(feitian_firmware(None, (1, 0, 1)).as_deref(), Some("1.0.1"));
        assert_eq!(feitian_firmware(None, (0, 0, 0)), None);
    }

    #[test]
    fn only_a_long_decimal_serial_is_trusted_for_the_release() {
        assert!(token2_fido_serial("65103012345678"));
        // An OpenPGP applet's 8-digit serial is a different number.
        assert!(!token2_fido_serial("65103012"));
        assert!(!token2_fido_serial("6510a012345678"));
        assert!(!token2_fido_serial(""));
    }

    #[test]
    fn a_token2_serial_reply_names_its_release() {
        // D1, len, the serial as hex text: a PIN+ Dual Ace's prefix 65103.
        let mut reply = vec![0xD1, 14];
        reply.extend_from_slice(b"65103012345678");
        assert_eq!(token2_release_from_reply(&reply), Some("R3.4"));
        // An unlisted prefix, and a reply that isn't the FIDO format.
        let mut unknown = vec![0xD1, 14];
        unknown.extend_from_slice(b"99999012345678");
        assert_eq!(token2_release_from_reply(&unknown), None);
        assert_eq!(token2_release_from_reply(&[0x90, 0x00]), None);
    }

    #[test]
    fn a_token2_serial_prefix_names_its_release() {
        assert_eq!(token2_release("651031234567"), Some("R3.4"));
        assert_eq!(token2_release("65104"), Some("R3.4"));
        assert_eq!(token2_release("661031234567"), Some("R3.3"));
        assert_eq!(token2_release("861031234567"), Some("R1"));
        assert_eq!(
            token2_release("960000000000"),
            None,
            "prefix not in the table"
        );
        assert_eq!(token2_release("6510"), None, "too short");
        assert_eq!(token2_release("6510a1234567"), None, "not digits");
        // The table holds five-digit numeric prefixes, each once.
        let mut seen = std::collections::HashSet::new();
        for (p, r) in TOKEN2_PREFIXES {
            assert!(p.len() == 5 && p.bytes().all(|b| b.is_ascii_digit()), "{p}");
            assert!(r.starts_with('R'), "{r}");
            assert!(seen.insert(*p), "{p} listed twice");
        }
    }
}
