//! Pure-Rust protocol layer for the Token2 Molto2 / Molto2v2 programmable TOTP token.
//!
//! This crate is hardware-free: it builds APDUs and parses responses. The
//! `keyroost-transport` crate wraps it with a real PC/SC connection.

pub mod apdu;
pub mod codec;
pub mod commands;
pub mod sha1;
pub mod sha256;
pub mod sha512;
pub mod sm4;

pub use commands::{
    answer_challenge, derive_sm4_key, factory_reset, get_challenge, get_info, set_config,
    set_customer_key, set_seed, set_title, sw_auth_failed, sw_ok, sync_time, Command,
    DisplayTimeout, HmacAlgo, OtpDigits, ProfileConfig, TimeStep, DEFAULT_CUSTOMER_KEY,
};

/// USB Vendor ID assigned to Token2. Shared across the whole product line —
/// the Molto2 token *and* Token2's FIDO keys (PIN+, FIDO2+) all use it — so VID
/// alone does not identify a Molto2; classify by PID with [`token2_product`].
pub const USB_VID: u16 = 0x349E;
/// USB Product ID for the Molto2 / Molto2v2.
///
/// Token2 confirmed (issue #25, 2026-06-15) that this PID is **always and only**
/// the Molto2 and **will not change**, making it the authoritative, stable
/// signal for Molto2 detection — preferable to the brittle reader-name match
/// that misfired in issue #21. (Token2 also noted the `READ_CONFIG` appearance
/// field can overlap across products, so PID + product description is the
/// recommended discriminator, not the config blob.)
pub const USB_PID: u16 = 0x0300;
/// Brand substring shared by every Token2 PC/SC reader name. Necessary but
/// **not sufficient** to identify a Molto2 — use [`is_molto2_reader`], which
/// also excludes Token2's FIDO keys.
pub const READER_NAME_HINT: &str = "TOKEN2";

/// True when a PC/SC reader name denotes a Token2 **Molto2 / Molto2v2** TOTP
/// token, as opposed to one of Token2's *FIDO* keys (FIDO2+, PIN+, PIN+R3, …).
///
/// Token2 brands its whole line "TOKEN2" and its FIDO keys also expose a CCID
/// reader, so identifying a Molto2 by the brand is wrong twice over:
/// - the original bare-`"TOKEN2"` substring matched every Token2 FIDO key
///   (issue #21, a ghost Molto2 in the GUI);
/// - a follow-up that matched `"TOKEN2"` *unless* the name said "fido" or
///   "security key" still misfired on `Token2 PIN+R3 00 00` — the PIN+R3
///   mini's reader names neither — flagging that FIDO key as a Molto2 and
///   making `keyroostctl` attempt Molto2 commands on it (`SW 6A81`).
///
/// The only reliable signal is the **product name**: a Molto2's reader carries
/// `Molto2` (e.g. `TOKEN2 Molto2 [CCID Interface] 00 00`), every other Token2
/// device is a FIDO key. So match on `"molto"` and nothing else — no
/// brand-level fallback to re-admit the FIDO line.
#[must_use]
pub fn is_molto2_reader(reader_name: &str) -> bool {
    reader_name.to_ascii_lowercase().contains("molto")
}

/// Product family a Token2 USB PID (under [`USB_VID`]) belongs to.
///
/// The discriminator that matters for this tool is **Molto2 vs. everything
/// else**: the Molto2 speaks the proprietary TOTP protocol in this crate, the
/// FIDO line does not. The NFC reader is not a token at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Token2Product {
    /// The Molto2 / Molto2v2 programmable TOTP token (`0x0300`).
    Molto2,
    /// A member of the 3.x FIDO line (PIN+, PIN+ Mini, FIDO2+, Bio3 Dual, …).
    /// These expose a CCID reader too, which is what made name-matching
    /// mistake them for a Molto2 in issue #21.
    Fido,
    /// The TOKEN2 MFA NFC reader (`0x0430`) — a contactless reader peripheral,
    /// not a security token.
    NfcReader,
}

/// Authoritative Token2 USB PID → product map, as published by Token2 in
/// issue #25 (2026-06-15). Token2 submits new PIDs to the CCID repo, so this
/// table can grow; unknown PIDs under [`USB_VID`] fall through to `None` in
/// [`token2_product`] rather than being guessed at.
///
/// Kept as `(pid, product, human description)` so the diagnostic `list` surface
/// can label a device with the vendor's own wording.
pub const TOKEN2_PRODUCTS: &[(u16, Token2Product, &str)] = &[
    (0x0013, Token2Product::Fido, "PIN+ Mini (OTP + PGP)"),
    (0x0014, Token2Product::Fido, "PIN+ Mini (FIDO + PGP)"),
    (0x0015, Token2Product::Fido, "PIN+ Mini (PGP)"),
    (0x0016, Token2Product::Fido, "PIN+ Mini (OTP + PGP + FIDO)"),
    (0x0023, Token2Product::Fido, "PIN+ Series (OTP + PGP)"),
    (0x0024, Token2Product::Fido, "PIN+ Series (FIDO + PGP)"),
    (0x0025, Token2Product::Fido, "PIN+ Series (PGP)"),
    (0x0026, Token2Product::Fido, "FIDO2 Security Key (0026)"),
    (0x0203, Token2Product::Fido, "Bio3 Dual (OTP + PGP)"),
    (0x0204, Token2Product::Fido, "Bio3 Dual (FIDO + PGP)"),
    (0x0205, Token2Product::Fido, "Bio3 Dual (PGP)"),
    (0x0206, Token2Product::Fido, "Bio3 Dual (OTP + PGP + FIDO)"),
    (0x0300, Token2Product::Molto2, "Molto2"),
    (0x0430, Token2Product::NfcReader, "TOKEN2 MFA NFC Reader"),
];

/// Classify a Token2 USB PID into its [`Token2Product`] family.
///
/// Returns `None` for a PID not in [`TOKEN2_PRODUCTS`] — a newer SKU Token2 has
/// shipped since this table was captured. Callers should treat an unknown
/// Token2 PID as "not provably a Molto2" and fall back to the cross-checks
/// (no FIDO-HID sibling, reader name) rather than assuming a family.
#[must_use]
pub fn token2_product(pid: u16) -> Option<Token2Product> {
    TOKEN2_PRODUCTS
        .iter()
        .find_map(|&(p, kind, _)| (p == pid).then_some(kind))
}

/// The vendor's human description for a Token2 USB PID, if known.
#[must_use]
pub fn token2_pid_label(pid: u16) -> Option<&'static str> {
    TOKEN2_PRODUCTS
        .iter()
        .find_map(|&(p, _, label)| (p == pid).then_some(label))
}

/// True when a USB VID:PID is the Molto2 — the authoritative detection signal
/// Token2 confirmed in issue #25. Prefer this over [`is_molto2_reader`] wherever
/// the USB PID is available (the HID/USB enumeration path); the reader-name
/// match remains the fallback for the bare PC/SC path, where only the reader
/// string is in hand.
#[must_use]
pub fn is_molto2_usb(vid: u16, pid: u16) -> bool {
    vid == USB_VID && token2_product(pid) == Some(Token2Product::Molto2)
}

#[cfg(test)]
mod reader_match_tests {
    use super::is_molto2_reader;

    #[test]
    fn matches_molto2_readers() {
        // The real Molto2 reader name (docs/BRINGUP.md), plus index/case variants.
        assert!(is_molto2_reader("TOKEN2 Molto2 [CCID Interface] 00 00"));
        assert!(is_molto2_reader("Token2 Molto2 0"));
        assert!(is_molto2_reader("token2 molto2v2 [ccid] 01 00"));
    }

    #[test]
    fn rejects_token2_fido_keys() {
        // Token2's FIDO keys share the brand and expose a CCID reader, but must
        // not be flagged as a Molto2. The reader strings below are real ones
        // reported on Linux in issue #21 (a PIN+R3 / "3.2 mini" and a FIDO2+).
        assert!(!is_molto2_reader("TOKEN2 FIDO2 Security Key 00 00"));
        assert!(!is_molto2_reader("Token2 PIN+R3 00 00"));
        assert!(!is_molto2_reader("Token2 PIN+ [FIDO] 0"));
        // A bare-"TOKEN2" reader is NOT assumed to be a Molto2 anymore — the
        // bare-brand fallback is exactly what misfired on PIN+R3.
        assert!(!is_molto2_reader("TOKEN2 [CCID Interface] 00 00"));
    }

    #[test]
    fn rejects_unrelated_readers() {
        assert!(!is_molto2_reader("Yubico YubiKey OTP+FIDO+CCID 00 00"));
        assert!(!is_molto2_reader(
            "SoloKeys Solo 2 [CCID/ICCD Interface] 00 00"
        ));
        assert!(!is_molto2_reader(""));
    }
}

#[cfg(test)]
mod token2_pid_tests {
    use super::{
        is_molto2_usb, token2_pid_label, token2_product, Token2Product, TOKEN2_PRODUCTS, USB_PID,
        USB_VID,
    };

    #[test]
    fn molto2_pid_classifies_as_molto2() {
        assert_eq!(token2_product(USB_PID), Some(Token2Product::Molto2));
        assert_eq!(token2_product(0x0300), Some(Token2Product::Molto2));
        assert!(is_molto2_usb(USB_VID, USB_PID));
    }

    #[test]
    fn fido_pids_are_not_molto2() {
        // The exact PIDs My1 reported on real hardware in issue #21.
        for pid in [0x0016, 0x0026] {
            assert_eq!(token2_product(pid), Some(Token2Product::Fido));
            assert!(!is_molto2_usb(USB_VID, pid));
        }
    }

    #[test]
    fn nfc_reader_is_its_own_family() {
        assert_eq!(token2_product(0x0430), Some(Token2Product::NfcReader));
        assert!(!is_molto2_usb(USB_VID, 0x0430));
    }

    #[test]
    fn unknown_pid_is_none_not_a_guess() {
        // A future SKU we haven't captured yet must not be assumed to be a
        // Molto2 — better to fall back to the cross-checks than misclassify.
        assert_eq!(token2_product(0x0999), None);
        assert!(!is_molto2_usb(USB_VID, 0x0999));
    }

    #[test]
    fn molto2_signal_requires_the_token2_vid() {
        // Same PID under a foreign VID is not a Molto2.
        assert!(!is_molto2_usb(0x1050, USB_PID));
    }

    #[test]
    fn label_matches_table() {
        assert_eq!(token2_pid_label(USB_PID), Some("Molto2"));
        assert_eq!(token2_pid_label(0x0999), None);
        // Every table entry round-trips through both lookups.
        for &(pid, kind, label) in TOKEN2_PRODUCTS {
            assert_eq!(token2_product(pid), Some(kind));
            assert_eq!(token2_pid_label(pid), Some(label));
        }
    }
}
