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
pub mod trace;

pub use commands::{
    answer_challenge, delete_seed, derive_sm4_key, factory_reset, get_challenge, get_info,
    parse_public_data, read_public_data, set_config, set_customer_key, set_seed, set_title,
    sw_auth_failed, sw_ok, sync_time, Command, DisplayTimeout, HmacAlgo, OtpDigits, ProfileConfig,
    ProfilePublicData, PublicDataError, TimeStep, DEFAULT_CUSTOMER_KEY,
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
    /// A member of Token2's FIDO key line (PIN+, PIN+ Mini, Bio3 Dual, …),
    /// spanning R1 through R3.x.
    ///
    /// This is a **family** marker, not a capability claim. Several PIDs in the
    /// family name a function set with FIDO switched off (the OTP-only and
    /// PGP-only configurations), so `Fido` must never be read as "speaks CTAP"
    /// — nor as "has the OTP applet". Probe the device for what it can do.
    ///
    /// These expose a CCID reader too, which is what made name-matching
    /// mistake them for a Molto2 in issue #21.
    Fido,
    /// The TOKEN2 MFA NFC reader (`0x0430`) — a contactless reader peripheral,
    /// not a security token.
    NfcReader,
}

/// The applet set a Token2 USB PID switches on, as data.
///
/// Token2 ships one piece of hardware in several configurations and encodes
/// which one in the PID: "each PID corresponds to a specific operating mode or
/// function (FIDO, OTP, PGP, or combinations)". This is that function set,
/// carried in [`TOKEN2_PRODUCTS`] alongside the human description so callers
/// never have to parse the description string to recover it.
///
/// Scope: these are the three functions the vendor's PID table settles. It says
/// nothing about PIV (release-gated, not PID-encoded — see the generation note
/// on [`TOKEN2_PRODUCTS`]) and nothing about the Molto2's programmable TOTP
/// protocol, which is a different product family entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Token2Functions {
    /// FIDO2/CTAP is switched on.
    pub fido: bool,
    /// The on-device OTP applet is switched on.
    pub otp: bool,
    /// The OpenPGP card applet is switched on.
    pub pgp: bool,
}

impl Token2Functions {
    const fn new(fido: bool, otp: bool, pgp: bool) -> Self {
        Self { fido, otp, pgp }
    }

    /// None of the three — the Molto2 and the NFC reader, which are not
    /// configurations of the PIN+ hardware at all.
    pub const NONE: Self = Self::new(false, false, false);
    pub const FIDO: Self = Self::new(true, false, false);
    pub const OTP: Self = Self::new(false, true, false);
    pub const PGP: Self = Self::new(false, false, true);
    pub const FIDO_OTP: Self = Self::new(true, true, false);
    pub const FIDO_PGP: Self = Self::new(true, false, true);
    pub const OTP_PGP: Self = Self::new(false, true, true);
    /// The vendor's default shipping configuration for each family.
    pub const OTP_PGP_FIDO: Self = Self::new(true, true, true);
}

/// Authoritative Token2 USB PID → product map. Two first-party sources:
///
/// - Token2 published the original list in issue #25 (2026-06-15), which is
///   where `0x0300` (Molto2) and `0x0430` (NFC reader) come from — neither
///   appears in the vendor page below, which covers only the PIN+ line.
/// - Token2's "VID/PID Reference for PIN+ Devices" table, which adds the
///   FIDO-only / OTP-only / FIDO+OTP function sets and settles what `0x0026`
///   actually is: <https://www.token2.com/site/page/pin-firmware-feature-support-matrix-openpgp-fido2-otp-and-piv-across-releases>
///
/// **A PID names an enabled function set, not a distinct piece of hardware.**
/// In the vendor's words, "each PID corresponds to a specific operating mode or
/// function (FIDO, OTP, PGP, or combinations)". `0x0023` and `0x0026` are the
/// same physical PIN+ key with different applets switched on. Two consequences:
/// one model appears under several PIDs below, and a unit can lack a feature
/// its siblings have — so a PID says something about *configuration* only, and
/// nothing here may be treated as proof that an applet is present.
///
/// **A PID does not identify a generation.** `0x0020`–`0x0022` are reused
/// verbatim by PIN+ R1/R2 *and* by R3/R3.1/R3.2/R3.3+, so no caller may infer a
/// firmware release from a PID — and therefore none may infer the release-gated
/// features either (OpenPGP arrives in R3, PIV in R3.3). Generation comes from
/// the device's serial-number prefix or its own version report, never from this
/// table. That is why the descriptions below name a family and a function set
/// but never a revision.
///
/// Token2 submits new PIDs to the CCID repo, so this table can grow; unknown
/// PIDs under [`USB_VID`] fall through to `None` in [`token2_product`] rather
/// than being guessed at.
///
/// Kept as `(pid, product, functions, human description)`: the diagnostic `list`
/// surface labels a device with the vendor's own wording, and callers that need
/// the function set read [`Token2Functions`] as data rather than parsing the
/// description — the two must stay in step, which
/// `functions_match_the_vendor_description` pins.
pub const TOKEN2_PRODUCTS: &[(u16, Token2Product, Token2Functions, &str)] = &[
    // Mini USB A/C. `0x0016` is the vendor's default shipping configuration.
    (
        0x0010,
        Token2Product::Fido,
        Token2Functions::FIDO,
        "PIN+ Mini (FIDO)",
    ),
    (
        0x0011,
        Token2Product::Fido,
        Token2Functions::OTP,
        "PIN+ Mini (OTP)",
    ),
    (
        0x0012,
        Token2Product::Fido,
        Token2Functions::FIDO_OTP,
        "PIN+ Mini (FIDO + OTP)",
    ),
    (
        0x0013,
        Token2Product::Fido,
        Token2Functions::OTP_PGP,
        "PIN+ Mini (OTP + PGP)",
    ),
    (
        0x0014,
        Token2Product::Fido,
        Token2Functions::FIDO_PGP,
        "PIN+ Mini (FIDO + PGP)",
    ),
    (
        0x0015,
        Token2Product::Fido,
        Token2Functions::PGP,
        "PIN+ Mini (PGP)",
    ),
    (
        0x0016,
        Token2Product::Fido,
        Token2Functions::OTP_PGP_FIDO,
        "PIN+ Mini (OTP + PGP + FIDO)",
    ),
    // PIN+ series. `0x0020`–`0x0022` are shared by R1/R2 and R3.x — see the
    // generation note above; the PGP-bearing sets below are R3 and later, but
    // the PID alone still does not tell you which release you are talking to.
    // `0x0026` is the vendor's default shipping configuration.
    (
        0x0020,
        Token2Product::Fido,
        Token2Functions::FIDO,
        "PIN+ Series (FIDO)",
    ),
    (
        0x0021,
        Token2Product::Fido,
        Token2Functions::OTP,
        "PIN+ Series (OTP)",
    ),
    (
        0x0022,
        Token2Product::Fido,
        Token2Functions::FIDO_OTP,
        "PIN+ Series (FIDO + OTP)",
    ),
    (
        0x0023,
        Token2Product::Fido,
        Token2Functions::OTP_PGP,
        "PIN+ Series (OTP + PGP)",
    ),
    (
        0x0024,
        Token2Product::Fido,
        Token2Functions::FIDO_PGP,
        "PIN+ Series (FIDO + PGP)",
    ),
    (
        0x0025,
        Token2Product::Fido,
        Token2Functions::PGP,
        "PIN+ Series (PGP)",
    ),
    (
        0x0026,
        Token2Product::Fido,
        Token2Functions::OTP_PGP_FIDO,
        "PIN+ Series (OTP + PGP + FIDO)",
    ),
    // Bio3 Dual A+C. `0x0206` is the vendor's default shipping configuration.
    (
        0x0200,
        Token2Product::Fido,
        Token2Functions::FIDO,
        "Bio3 Dual (FIDO)",
    ),
    (
        0x0201,
        Token2Product::Fido,
        Token2Functions::OTP,
        "Bio3 Dual (OTP)",
    ),
    (
        0x0202,
        Token2Product::Fido,
        Token2Functions::FIDO_OTP,
        "Bio3 Dual (FIDO + OTP)",
    ),
    (
        0x0203,
        Token2Product::Fido,
        Token2Functions::OTP_PGP,
        "Bio3 Dual (OTP + PGP)",
    ),
    (
        0x0204,
        Token2Product::Fido,
        Token2Functions::FIDO_PGP,
        "Bio3 Dual (FIDO + PGP)",
    ),
    (
        0x0205,
        Token2Product::Fido,
        Token2Functions::PGP,
        "Bio3 Dual (PGP)",
    ),
    (
        0x0206,
        Token2Product::Fido,
        Token2Functions::OTP_PGP_FIDO,
        "Bio3 Dual (OTP + PGP + FIDO)",
    ),
    (
        0x0300,
        Token2Product::Molto2,
        Token2Functions::NONE,
        "Molto2",
    ),
    (
        0x0430,
        Token2Product::NfcReader,
        Token2Functions::NONE,
        "TOKEN2 MFA NFC Reader",
    ),
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
        .find_map(|&(p, kind, _, _)| (p == pid).then_some(kind))
}

/// The vendor's human description for a Token2 USB PID, if known.
#[must_use]
pub fn token2_pid_label(pid: u16) -> Option<&'static str> {
    TOKEN2_PRODUCTS
        .iter()
        .find_map(|&(p, _, _, label)| (p == pid).then_some(label))
}

/// The applet set a Token2 USB PID switches on, if the PID is known.
///
/// `None` means "not in the table", which is *not* the same as "no functions" —
/// Token2 ships new PIDs, and an id we have not captured tells us nothing about
/// what the key can do. See [`token2_pid_may_have_otp`] for the fail-open rule
/// callers should apply to an unknown id.
#[must_use]
pub fn token2_functions(pid: u16) -> Option<Token2Functions> {
    TOKEN2_PRODUCTS
        .iter()
        .find_map(|&(p, _, funcs, _)| (p == pid).then_some(funcs))
}

/// Whether a Token2 USB PID may have the on-device OTP applet — **fail open**.
///
/// True unless the PID is one we positively know ships without OTP. An unknown
/// PID answers `true`: Token2 adds ids for new configurations, and hiding an
/// applet a user's key really has is a worse failure than offering one that
/// turns out to be absent (the surface then reports the device's own error).
///
/// This asymmetry is deliberate — **do not "tidy" it into
/// `token2_functions(pid).is_some_and(|f| f.otp)`**, which would silently drop
/// OTP from every key Token2 ships after this table was captured.
///
/// # Do not use this to withhold a capability
///
/// v0.7.7 wired this into the device list, so a PID whose function set omits
/// OTP lost the capability bit — which also removes the GUI's OTP tab and makes
/// `--key <name>` fail to find the device. Token2 then reported on issue #95
/// that a key can carry OTP over **CCID** while its function set reads
/// `FIDO + PGP`, because the model has no HOTP-over-HID and ships with the HID
/// channel disabled. A function set therefore says what is switched on, not
/// which channel serves it, and never that an applet is absent —
/// [`TOKEN2_PRODUCTS`] says exactly that in its own docs.
///
/// The reliable answer comes from `SELECT`ing the applet over a reader, which
/// `keyroost-transport`'s probe already does. Where that probe cannot run (a
/// HID-only enumeration, or no smart-card service) the honest state is
/// *unknown*, and unknown must resolve to "offer it" — not to a guess from the
/// PID. Use this only to *inform* a message, never to deny a surface.
#[must_use]
pub fn token2_pid_may_have_otp(pid: u16) -> bool {
    token2_functions(pid).is_none_or(|f| f.otp)
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
        is_molto2_usb, token2_functions, token2_pid_label, token2_pid_may_have_otp, token2_product,
        Token2Functions, Token2Product, TOKEN2_PRODUCTS, USB_PID, USB_VID,
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
    fn every_published_pin_plus_pid_is_covered() {
        // The full function-set matrix from Token2's VID/PID reference: Mini
        // (0x0010-0x0016), PIN+ (0x0020-0x0026) and Bio3 Dual (0x0200-0x0206).
        // Each id is one enabled applet combination of the same hardware, so a
        // gap here means a real key enumerates as an unrecognized SKU.
        let published = (0x0010..=0x0016)
            .chain(0x0020..=0x0026)
            .chain(0x0200..=0x0206);
        for pid in published {
            assert_eq!(
                token2_product(pid),
                Some(Token2Product::Fido),
                "PID {pid:#06x} missing from TOKEN2_PRODUCTS"
            );
            assert!(!is_molto2_usb(USB_VID, pid));
        }
    }

    #[test]
    fn shared_pids_do_not_identify_a_generation() {
        // Token2 reuses 0x0020-0x0022 verbatim across PIN+ R1/R2 *and*
        // R3/R3.1/R3.2/R3.3+. Nothing may infer a firmware release — or the
        // features gated on one — from these ids, so their labels name a family
        // and a function set and deliberately carry no revision.
        for pid in [0x0020u16, 0x0021, 0x0022] {
            let label = token2_pid_label(pid).expect("shared PID is in the table");
            assert!(
                !label.contains("R1")
                    && !label.contains("R2")
                    && !label.contains("R3")
                    && !label.contains("3."),
                "shared PID {pid:#06x} must not claim a generation: {label}"
            );
        }
    }

    #[test]
    fn default_configuration_pids_are_the_full_function_set() {
        // The vendor's default shipping configuration for each family is the
        // OTP + PGP + FIDO id. 0x0026 in particular was previously mislabelled
        // as a generic "FIDO2 Security Key".
        assert_eq!(
            token2_pid_label(0x0016),
            Some("PIN+ Mini (OTP + PGP + FIDO)")
        );
        assert_eq!(
            token2_pid_label(0x0026),
            Some("PIN+ Series (OTP + PGP + FIDO)")
        );
        assert_eq!(
            token2_pid_label(0x0206),
            Some("Bio3 Dual (OTP + PGP + FIDO)")
        );
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
        // Every table entry round-trips through all three lookups.
        for &(pid, kind, funcs, label) in TOKEN2_PRODUCTS {
            assert_eq!(token2_product(pid), Some(kind));
            assert_eq!(token2_pid_label(pid), Some(label));
            assert_eq!(token2_functions(pid), Some(funcs));
        }
    }

    #[test]
    fn functions_match_the_vendor_description() {
        // The function set is carried as data so no caller has to parse the
        // description at runtime; this test is the one place the two are
        // compared, so a new row cannot drift from its own label. The Molto2 and
        // the NFC reader are not PIN+ configurations and name no function set.
        for &(pid, _, funcs, label) in TOKEN2_PRODUCTS {
            let Some(set) = label.split_once('(').map(|(_, rest)| rest) else {
                assert_eq!(funcs, Token2Functions::NONE, "{label} names no functions");
                continue;
            };
            let named = |f: &str| set.split(&['(', ')', '+'][..]).any(|w| w.trim() == f);
            assert_eq!(funcs.fido, named("FIDO"), "FIDO bit wrong for {label}");
            assert_eq!(funcs.otp, named("OTP"), "OTP bit wrong for {label}");
            assert_eq!(funcs.pgp, named("PGP"), "PGP bit wrong for {label}");
            assert!(
                funcs != Token2Functions::NONE,
                "PID {pid:#06x} names functions but carries none"
            );
        }
    }

    #[test]
    fn otp_less_configurations_are_known_to_lack_otp() {
        // The FIDO-only, PGP-only and FIDO+PGP ids across all three families.
        // These are the units that were being offered an OTP surface they have
        // no applet for (issue #82).
        for pid in [
            0x0010u16, 0x0014, 0x0015, // PIN+ Mini
            0x0020, 0x0024, 0x0025, // PIN+ Series
            0x0200, 0x0204, 0x0205, // Bio3 Dual
        ] {
            assert!(
                !token2_functions(pid).expect("known PID").otp,
                "PID {pid:#06x} must not claim OTP"
            );
            assert!(!token2_pid_may_have_otp(pid));
        }
    }

    #[test]
    fn otp_bearing_configurations_keep_otp() {
        for pid in [
            0x0011u16, 0x0012, 0x0013, 0x0016, // PIN+ Mini
            0x0021, 0x0022, 0x0023, 0x0026, // PIN+ Series
            0x0201, 0x0202, 0x0203, 0x0206, // Bio3 Dual
        ] {
            assert!(
                token2_functions(pid).expect("known PID").otp,
                "PID {pid:#06x} must claim OTP"
            );
            assert!(token2_pid_may_have_otp(pid));
        }
    }

    #[test]
    fn unknown_pid_fails_open_on_otp() {
        // Token2 ships new ids; an id we have not captured must keep the
        // pre-table behaviour of offering OTP rather than hiding an applet the
        // key may well have. Suppression is only ever for a *known* OTP-less id.
        assert_eq!(token2_functions(0x0999), None);
        assert!(token2_pid_may_have_otp(0x0999));
        assert!(token2_pid_may_have_otp(0x0027));
    }
}
