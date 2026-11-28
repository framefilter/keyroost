//! CanoKey identification: its USB IDs, its PC/SC reader name, the model
//! name and the serial number as CanoKey shows them.
//!
//! Everything here is read from the CanoKey firmware source (canokey-core
//! 3.1.2, `a349b26`) and CanoKey's own tools, not inferred:
//!
//! * USB ID `20A0:42D4`, manufacturer string `canokeys.org`, product string
//!   set per hardware variant (`CanoKey` by default, `CanoKey Canary` on a
//!   Canary) and CCID interface string `OpenPGP PIV OATH`
//!   (`interfaces/USB/device/usbd_desc.c`). The PC/SC reader name is built
//!   from those strings, so it starts with `canokeys.org`.
//! * One four-byte serial number, reported as the USB `iSerialNumber` string
//!   in upper-case hex (`%02X%02X%02X%02X`), as bytes 10..14 of the OpenPGP
//!   AID, and raw by the Admin applet (INS 32) and PIV GET SERIAL. CanoKey
//!   shows it as the decimal value of the four bytes read big-endian, as its
//!   `ckman` CLI and PKCS#11 module print it (`u32::from_be_bytes`, `%lu`),
//!   so keyroost shows that form. The hex form is kept as the row's former
//!   serial: a name recorded under it by an earlier keyroost still applies.
//! * A key whose serial was never written reads all zero bytes (the
//!   firmware's `fill_sn` when the serial file is absent) or all `FF` bytes
//!   (erased flash, as on a DevKit). Every such key reports the same value,
//!   so it identifies none of them and is treated as no serial at all.

/// CanoKey's USB vendor ID. Shared with Nitrokey (`20A0:42B2` is a
/// Nitrokey 3), so a CanoKey is told apart by its product ID too.
pub const VID: u16 = 0x20a0;
/// CanoKey's USB product ID.
pub const PID: u16 = 0x42d4;
/// The vendor name keyroost shows for a CanoKey.
pub const VENDOR: &str = "CanoKey";
/// The OpenPGP card manufacturer ID in a CanoKey's AID (GnuPG's registry
/// names it `CanoKeys`).
pub const OPENPGP_MANUFACTURER: u16 = 0xF1D0;

/// The USB manufacturer string, which every CanoKey reader name starts with.
const MANUFACTURER: &str = "canokeys.org";
/// The CCID interface string, part of the reader name and not of the model.
const CCID_INTERFACE: &str = "OpenPGP PIV OATH";

/// Whether a USB device is a CanoKey.
#[must_use]
pub fn is_usb(vendor_id: u16, product_id: u16) -> bool {
    (vendor_id, product_id) == (VID, PID)
}

/// Whether a PC/SC reader is a CanoKey's own (its name starts with the
/// USB manufacturer string), as opposed to a reader a CanoKey is held to
/// over NFC.
#[must_use]
pub fn is_reader_name(reader_name: &str) -> bool {
    reader_name
        .trim_start()
        .get(..MANUFACTURER.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(MANUFACTURER))
}

/// Whether a factory reset of `dev` is CanoKey's own device-wide one
/// (`keyroost_transport::CanoKeyAdminSession::factory_reset`) rather than
/// keyroost's applet-by-applet plan: a CanoKey reached through its own USB
/// reader. The device-wide reset wipes every applet (FIDO2, OATH, OpenPGP,
/// PIV, NDEF, PASS) and the device settings in one step, once its Admin PIN
/// is blocked, and is the only reset of the key's OATH applet that needs no
/// Admin PIN; the key refuses it over NFC, where the plan applies.
#[must_use]
pub fn takes_device_reset(dev: &crate::Device) -> bool {
    dev.vendor == VENDOR && dev.reader.as_deref().is_some_and(is_reader_name)
}

/// A CanoKey serial number, from the hex form the key reports it in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Serial {
    /// A written serial: `decimal` as CanoKey shows it, `hex` (eight upper-
    /// case digits) as the key reports it.
    Assigned { decimal: String, hex: String },
    /// All zero or all `FF` bytes: no serial was written.
    Unset,
    /// Not eight hex digits, so not a CanoKey serial; left as it is.
    Unrecognized,
}

/// Read a CanoKey serial from its hex form: the USB `iSerialNumber` string
/// or the hex of the OpenPGP AID's serial bytes, in either case.
#[must_use]
pub fn serial_from_hex(text: &str) -> Serial {
    let text = text.trim();
    if text.len() != 8 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Serial::Unrecognized;
    }
    match u32::from_str_radix(text, 16) {
        Ok(0 | u32::MAX) => Serial::Unset,
        Ok(value) => Serial::Assigned {
            decimal: value.to_string(),
            hex: text.to_ascii_uppercase(),
        },
        Err(_) => Serial::Unrecognized,
    }
}

/// A row's serial and former serial from a CanoKey serial in hex form:
/// the decimal serial with the hex one as the former serial, nothing for an
/// unset serial, and anything unrecognized as it was.
#[must_use]
pub fn row_serial(text: &str) -> (String, Option<String>) {
    match serial_from_hex(text) {
        Serial::Assigned { decimal, hex } => (decimal, Some(hex)),
        Serial::Unset => (String::new(), None),
        Serial::Unrecognized => (text.to_string(), None),
    }
}

/// The model in a CanoKey's USB product string: `CanoKey Canary` is
/// `Canary`. `None` when the string names no more than the vendor (the
/// default product string, `CanoKey`).
#[must_use]
pub fn model_from_product(product: &str) -> Option<String> {
    let mut words: Vec<&str> = product.split_whitespace().collect();
    if words
        .first()
        .is_some_and(|w| w.eq_ignore_ascii_case(VENDOR))
    {
        words.remove(0);
    }
    let model = words.join(" ");
    (!model.is_empty()).then_some(model)
}

/// The model in a CanoKey's PC/SC reader name, when the name carries the
/// product string. Windows names the reader `canokeys.org OpenPGP PIV OATH
/// <n>` (no model); pcsc-lite adds the product, the interface in brackets,
/// the serial in parentheses and two index groups. `None` when no model is
/// left once the manufacturer, interface, serial and indexes are taken out.
#[must_use]
pub fn model_from_reader(reader_name: &str) -> Option<String> {
    let mut kept = String::with_capacity(reader_name.len());
    let mut depth = 0i32;
    for ch in reader_name.chars() {
        match ch {
            '[' | '(' => depth += 1,
            ']' | ')' => depth = (depth - 1).max(0),
            _ if depth == 0 => kept.push(ch),
            _ => {}
        }
    }
    let without_interface = remove_ignore_ascii_case(&kept, CCID_INTERFACE);
    let mut words: Vec<&str> = without_interface
        .split_whitespace()
        .filter(|w| !w.eq_ignore_ascii_case(MANUFACTURER))
        .collect();
    // Reader index groups: one number on Windows, `00 00` on pcsc-lite.
    while words
        .last()
        .is_some_and(|w| w.bytes().all(|b| b.is_ascii_digit()))
    {
        words.pop();
    }
    model_from_product(&words.join(" "))
}

/// `haystack` with every ASCII-case-insensitive occurrence of `needle`
/// replaced by a space.
fn remove_ignore_ascii_case(haystack: &str, needle: &str) -> String {
    let lower = haystack.to_ascii_lowercase();
    let needle = needle.to_ascii_lowercase();
    let mut out = String::with_capacity(haystack.len());
    let mut at = 0;
    while let Some(found) = lower[at..].find(&needle) {
        out.push_str(&haystack[at..at + found]);
        out.push(' ');
        at += found + needle.len();
    }
    out.push_str(&haystack[at..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_canokey_product_id_under_the_shared_vendor_id_is_a_canokey() {
        assert!(is_usb(0x20a0, 0x42d4));
        assert!(!is_usb(0x20a0, 0x42b2), "a Nitrokey 3");
        assert!(!is_usb(0x2581, 0x42d4));
    }

    #[test]
    fn reader_names_are_recognized_by_the_manufacturer_string() {
        assert!(is_reader_name("canokeys.org OpenPGP PIV OATH 0"));
        assert!(is_reader_name(
            "canokeys.org CanoKey Canary [OpenPGP PIV OATH] (1A2B3C4D) 00 00"
        ));
        assert!(is_reader_name("CanoKeys.org OpenPGP PIV OATH"));
        assert!(!is_reader_name("ACS ACR122U PICC Interface 0"));
        assert!(!is_reader_name("canokey"));
    }

    #[test]
    fn a_written_serial_reads_as_its_big_endian_decimal_value() {
        assert_eq!(
            serial_from_hex("1A2B3C4D"),
            Serial::Assigned {
                decimal: "439041101".into(),
                hex: "1A2B3C4D".into()
            }
        );
        // The OpenPGP AID hex keyroost built in lower case reads the same.
        assert_eq!(serial_from_hex("1a2b3c4d"), serial_from_hex("1A2B3C4D"));
        // No leading zeros, as ckman and the PKCS#11 module print it.
        assert_eq!(
            row_serial("00000123"),
            ("291".to_string(), Some("00000123".to_string()))
        );
    }

    #[test]
    fn an_unwritten_serial_is_no_serial() {
        assert_eq!(serial_from_hex("00000000"), Serial::Unset);
        assert_eq!(serial_from_hex("FFFFFFFF"), Serial::Unset);
        assert_eq!(row_serial("ffffffff"), (String::new(), None));
    }

    #[test]
    fn anything_but_eight_hex_digits_is_left_as_it_is() {
        for text in ["", "123", "1A2B3C4D5E", "1A2B3C4G", "439041101"] {
            assert_eq!(serial_from_hex(text), Serial::Unrecognized, "{text}");
            assert_eq!(row_serial(text), (text.to_string(), None));
        }
    }

    #[test]
    fn the_model_is_the_product_string_after_the_vendor() {
        assert_eq!(
            model_from_product("CanoKey Canary").as_deref(),
            Some("Canary")
        );
        assert_eq!(model_from_product("CanoKey"), None);
        assert_eq!(model_from_product("Pigeon").as_deref(), Some("Pigeon"));
    }

    #[test]
    fn the_model_comes_out_of_a_reader_name_only_when_it_carries_one() {
        // Windows: manufacturer and interface strings and an index only.
        assert_eq!(model_from_reader("canokeys.org OpenPGP PIV OATH 0"), None);
        // pcsc-lite: product, interface, serial, two index groups.
        assert_eq!(
            model_from_reader("canokeys.org CanoKey Canary [OpenPGP PIV OATH] (1A2B3C4D) 00 00")
                .as_deref(),
            Some("Canary")
        );
        assert_eq!(model_from_reader("canokeys.org CanoKey"), None);
    }
}
