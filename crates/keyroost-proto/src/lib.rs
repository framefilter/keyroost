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
/// alone does not identify a Molto2; see [`is_molto2_reader`].
pub const USB_VID: u16 = 0x349E;
/// USB Product ID for the Molto2 / Molto2v2.
pub const USB_PID: u16 = 0x0300;
/// Brand substring shared by every Token2 PC/SC reader name. Necessary but
/// **not sufficient** to identify a Molto2 — use [`is_molto2_reader`], which
/// also excludes Token2's FIDO keys.
pub const READER_NAME_HINT: &str = "TOKEN2";

/// True when a PC/SC reader name denotes a Token2 **Molto2 / Molto2v2** TOTP
/// token, as opposed to one of Token2's *FIDO* keys (PIN+, FIDO2+).
///
/// Token2 brands its whole line "TOKEN2" and its FIDO keys also expose a CCID
/// reader, so the old bare-`"TOKEN2"` substring match mis-flagged those FIDO
/// keys as a Molto2 — a ghost/duplicate device in the GUI (issue #21). The
/// Molto2's reader name carries the product name `Molto2`
/// (e.g. `TOKEN2 Molto2 [CCID Interface] 00 00`); the FIDO keys carry
/// `FIDO2 Security Key`. Match on the product name, with a fallback that
/// accepts a bare-`TOKEN2` reader only when nothing announces a FIDO interface
/// (so a future Molto2 whose reader omits the product word still resolves,
/// without re-admitting the FIDO keys).
#[must_use]
pub fn is_molto2_reader(reader_name: &str) -> bool {
    let n = reader_name.to_ascii_lowercase();
    if n.contains("molto") {
        return true;
    }
    n.contains("token2") && !n.contains("fido") && !n.contains("security key")
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
        // Bare-TOKEN2 fallback: a Molto2 whose reader omits the product word,
        // as long as nothing announces a FIDO interface.
        assert!(is_molto2_reader("TOKEN2 [CCID Interface] 00 00"));
    }

    #[test]
    fn rejects_token2_fido_keys() {
        // Issue #21: Token2's FIDO keys share the brand and expose a CCID
        // reader, but must not be flagged as a Molto2.
        assert!(!is_molto2_reader("TOKEN2 FIDO2 Security Key 00 00"));
        assert!(!is_molto2_reader("Token2 PIN+ [FIDO] 0"));
        assert!(!is_molto2_reader(
            "TOKEN2 Security Key [CCID Interface] 01 00"
        ));
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
