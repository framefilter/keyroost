//! Fingerprinting a PIV applet from its ATR/ATS historical bytes, its SELECT
//! response, and — for a couple of identities — a live probe of whether a
//! specific applet can be selected by AID at all ([`FEITIAN_RID`],
//! [`SWISSBIT_RID`]). Whether the card answers a particular instruction
//! is an equally valid fingerprinting signal this module's shape
//! accommodates the same way, even though no identity currently decides on
//! that alone. Best-effort, vendor-fingerprinting logic layered on top of the
//! plain PIV byte layer. Pure and I/O-free, like the rest of this crate:
//! [`atr_identity`] and [`select_identity`] turn raw bytes the transport
//! layer already has into short fingerprinting strings, and [`classify`]
//! turns those strings (plus the live-probe bits the transport layer
//! supplies) into an [`AppletFingerprint`].
//!
//! This is fingerprinting, not a protocol the spec defines — every rule here
//! is inferred from what a particular vendor's implementation happens to put
//! in a particular field, answer to a command, or expose as a selectable
//! applet, so a card this doesn't recognize just reports
//! [`AppletFingerprint::Generic`] rather than erroring.

/// Feitian Technologies' registered RID (Registered Application Provider
/// Identifier — the 5-byte ISO 7816-5 prefix common to every AID Feitian
/// registers under) — see
/// <https://qccdata.qichacha.com/Disclosure/f31b9be6f9eb76113e9c078f7f375997.pdf>
/// for the source associating this RID with Feitian.
/// [`AppletFingerprint::Feitian`] is recognised solely by whether the card
/// accepts a SELECT for this RID on its own (no PIX) — the transport layer
/// SELECTs it (then re-SELECTs PIV) only when nothing else already
/// fingerprinted the applet, since this is the lowest-priority, catch-all
/// criterion and every other one is cheaper to check first.
pub const FEITIAN_RID: [u8; 5] = [0xD1, 0x56, 0x00, 0x01, 0x32];

/// An obscure second PIV applet instance some Gemalto/Thales IDPrime cards
/// register under, alongside the standard PIV AID — see
/// <https://blog.rchapman.org/posts/Smart_card_installing_Hello_World_on_a_Gemalto_IDPrime_PIV_2.0_card>.
/// [`AppletFingerprint::IdPrime`] is recognised solely by whether the card
/// accepts a SELECT for this AID (`SW = 9000` or the non-standard `SW =
/// 6999`) — the transport layer SELECTs it (then re-SELECTs PIV) only when
/// nothing else, not even [`FEITIAN_RID`], already fingerprinted the applet,
/// since this is the lowest-priority, catch-all criterion and every other
/// one is cheaper to check first.
pub const IDPRIME_SECONDARY_PIV_AID: [u8; 11] = [
    0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x02, 0x00,
];

/// Trussed's admin application AID. On a Nitrokey
/// ([`AppletFingerprint::Trussed`]`(`[`TrussedVariant::NitroKey`]`)`), its
/// firmware version ([`NITROKEY_GET_VERSION_STRING`]) and hardware variant
/// ([`NITROKEY_GET_ADMIN_STATUS`]) are read through this application's
/// management commands rather than anything PIV-specific.
pub const NITROKEY_ADMIN_AID: [u8; 9] = [0xA0, 0x00, 0x00, 0x08, 0x47, 0x00, 0x00, 0x00, 0x01];

/// Trussed/Nitrokey admin application management command: `GET STATUS`
/// (`INS 0x80`), a bare case-1 APDU (no data, no `Le`) answering with a
/// 5-byte status structure — see [`parse_nitrokey_variant`] for the one byte
/// this crate reads out of it. Only meaningful once [`NITROKEY_ADMIN_AID`]
/// is selected.
pub const NITROKEY_GET_ADMIN_STATUS: [u8; 4] = [0x00, 0x80, 0x00, 0x00];

/// Trussed/Nitrokey admin application management command (`INS 0x62`), a
/// bare case-1 APDU (no data, no `Le`) answering with the device's serial
/// number as an unsigned big-endian 128-bit integer — decoded by
/// [`crate::parse_serial`] like any other serial reply. Only meaningful once
/// [`NITROKEY_ADMIN_AID`] is selected.
pub const NITROKEY_GET_SERIAL: [u8; 4] = [0x00, 0x62, 0x00, 0x00];

/// Trussed/Nitrokey admin application management command: `GET_VERSION`
/// (`INS 0x61`) with `P1 = 0x01` for its string-output form (rather than the
/// binary form other `P1` values select), answering with the firmware
/// version as plain ASCII (e.g. `"1.2.3"`), decoded by [`parse_ascii_text`]
/// and [`parse_dotted_version`]. Only meaningful once [`NITROKEY_ADMIN_AID`]
/// is selected.
pub const NITROKEY_GET_VERSION_STRING: [u8; 5] = [0x00, 0x61, 0x01, 0x00, 0x00];

/// Swissbit's officially registered RID (Registered Application Provider
/// Identifier) — `D2 76 00 01 62`, published in the German card-issuer RID
/// registry at
/// <https://www.kartenbezogene-identifier.de/de/rapi/rid-liste.html>. A
/// token whose select identity fingerprints as `OpenFips201` qualifies for
/// [`OpenFips201Variant::SwissbitIShield2`] when SELECTing this RID succeeds
/// with `SW = 9000` — the transport layer SELECTs it (then re-SELECTs PIV)
/// and passes the result to [`classify`] as `swissbit_rid_selectable`.
pub const SWISSBIT_RID: [u8; 5] = [0xD2, 0x76, 0x00, 0x01, 0x62];

/// Decode a plain-text command response as a `String`: no TLV or other
/// framing at all, just the raw bytes themselves, decoded here as lossy
/// UTF-8. `None` when empty.
#[must_use]
pub fn parse_ascii_text(data: &[u8]) -> Option<String> {
    (!data.is_empty()).then(|| String::from_utf8_lossy(data).into_owned())
}

/// Split a dotted ASCII version string (e.g. `"3.35.0"`) into its numeric
/// components, for `keyroost_transport::PivStatus::version_firmware`.
/// `None` if the string is empty or any component isn't a valid `u8` — a
/// version string this crate can't make sense of is reported as "no
/// firmware version" rather than risking a wrong one.
#[must_use]
pub fn parse_dotted_version(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() {
        return None;
    }
    s.split('.').map(|part| part.parse::<u8>().ok()).collect()
}

/// Decode the hardware variant out of a [`NITROKEY_GET_ADMIN_STATUS`]
/// response: byte offset 4 of the firmware's `AdminStatus::serialize()`
/// layout (init-status flags, IFS block count, EFS block count as
/// big-endian `u16`, then this one variant byte) — see
/// <https://github.com/Nitrokey/nitrokey-3-firmware/blob/main/components/apps/src/lib.rs#L909>
/// (`Variant`: `Usbip = 0`, `Lpc55 = 1`, `Nrf52 = 2`). `None` when the
/// response is shorter than 5 bytes, or the byte names no variant this crate
/// knows (a firmware newer than this table).
#[must_use]
pub fn parse_nitrokey_variant(data: &[u8]) -> Option<&'static str> {
    match data.get(4)? {
        0 => Some("USBIP"),
        1 => Some("LPC55"),
        2 => Some("NRF52"),
        _ => None,
    }
}

/// The display name for
/// [`AppletFingerprint::Trussed`]`(`[`TrussedVariant::NitroKey`]`)` once its
/// hardware variant is known: `"NitroKey (<variant>)"`.
#[must_use]
pub fn format_nitrokey_name(variant: &str) -> String {
    format!("NitroKey ({variant})")
}

/// The display name for [`AppletFingerprint::YubiKey`]: `"Yubico YubiKey
/// <major> Series"`, from the major-version byte (`version[0]`) of the
/// Yubico `GET VERSION` extension reply the transport layer already fetched
/// for `keyroost_transport::PivStatus::version` — this deliberately takes
/// that reply rather than issuing its own GET VERSION, so fingerprinting a
/// YubiKey never sends the command a second time. `None` when the reply is
/// empty (nothing to name a series after).
#[must_use]
pub fn format_yubikey_name(version: &[u8]) -> Option<String> {
    let major = *version.first()?;
    Some(format!("Yubico YubiKey {major} Series"))
}

/// A best-effort fingerprint of the PIV applet implementation behind a
/// session — from ATR/select text, from whether a specific applet can be
/// selected by AID at all, and in general from whether the card supports a
/// particular instruction. `Generic` is the default and the fallback: it
/// means no more specific fingerprint matched, not that fingerprinting
/// failed outright.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AppletFingerprint {
    /// No more specific fingerprint below matched.
    #[default]
    Generic,
    /// Based on <https://github.com/arekinath/PivApplet>.
    ArekinathPivApplet(ArekinathVariant),
    /// Authentrend's ATkey PIV applets — <https://authentrend.com/atkey-card-nfc>.
    AuthentrendATKey,
    /// Feitian Technologies' security keys — recognised purely by whether
    /// the card can select Feitian's registered RID ([`FEITIAN_RID`]): the
    /// "does a specific applet exist" fingerprinting method, rather than an
    /// ATR/select text hint.
    Feitian,
    /// HID's Crescendo product line — <https://www.hidglobal.com/product-mix/crescendo>.
    HidCrescendo(HidCrescendoVariant),
    /// Gemalto/Thales IDPrime PIV cards — recognised purely by whether the
    /// card can select their obscure second PIV applet instance
    /// ([`IDPRIME_SECONDARY_PIV_AID`]): the "does a specific applet exist"
    /// fingerprinting method, rather than an ATR/select text hint.
    IdPrime,
    /// Based on the Trussed applet — <https://github.com/trussed-dev/piv-authenticator>.
    Trussed(TrussedVariant),
    /// Based on <https://github.com/makinako/OpenFIPS201>.
    OpenFips201(OpenFips201Variant),
    /// Thetis' PRO FIDO2 Security Key with PinPlex — recognised by ATR
    /// historical bytes that contain both `"PIV"` and `"8888888"`
    /// (case-insensitively), provided the ATR didn't already fingerprint as
    /// [`AppletFingerprint::Token2`]: Token2's own ATR signature is close
    /// enough to this criterion that checking it alone would misclassify a
    /// Token2 device as Thetis — see
    /// <https://github.com/framefilter/keyroost/issues/125>. [`classify`]
    /// enforces the exclusion by checking the Token2 branch first.
    Thetis,
    /// Token2 PIV products — <https://token2.com/c/piv-devices>.
    Token2,
    /// Identiv/Hirsch's uTrust series — <https://www.hirschsecure.com/germany/en/products>.
    UTrust,
    /// Yubico's YubiKey series — <https://www.yubico.com/products/>.
    YubiKey,
}

/// Sub-fingerprint within [`AppletFingerprint::ArekinathPivApplet`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArekinathVariant {
    /// No more specific variant matched.
    Generic,
    /// A Swissbit iShield Key running PivApplet — recognised by its ATR
    /// identity ("iShield") on top of the base PivApplet select identity.
    SwissbitIShield1,
}

/// Sub-fingerprint within [`AppletFingerprint::HidCrescendo`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HidCrescendoVariant {
    /// Matched via the select identity (`"HID Global ActivID..."`) rather
    /// than a recognised ATR identity — neither [`Self::C2300`] nor
    /// [`Self::C4000`] applies.
    Generic,
    /// ATR identity is `"C2300"`.
    C2300,
    /// ATR identity is `"C4000"`.
    C4000,
}

/// Sub-fingerprint within [`AppletFingerprint::Trussed`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrussedVariant {
    /// A Nitrokey running the Trussed `piv-authenticator` — recognised by
    /// its select identity, not its ATR (Nitrokey's ATR doesn't carry a
    /// usable card-issuer-data field; the select identity does).
    NitroKey,
}

/// Sub-fingerprint within [`AppletFingerprint::OpenFips201`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenFips201Variant {
    /// No more specific variant matched.
    Generic,
    /// A Swissbit iShield Key running OpenFIPS201 — recognised by whether
    /// Swissbit's own registered RID ([`SWISSBIT_RID`]) can also be
    /// selected on the same card.
    SwissbitIShield2,
}

impl core::fmt::Display for AppletFingerprint {
    /// The identifier form: `Variant` for a unit variant, `Variant::Sub` for
    /// one carrying a sub-fingerprint — e.g. `OpenFips201::SwissbitIShield2`,
    /// matching Rust's own path syntax for a nested enum variant. Not derived
    /// `Debug`'s parentheses, so this reads unambiguously next to the
    /// friendly name from [`AppletFingerprint::applet_name`] wherever both
    /// appear (`keyroostctl piv status`'s `--json` output).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AppletFingerprint::Generic => write!(f, "Generic"),
            AppletFingerprint::ArekinathPivApplet(v) => write!(f, "ArekinathPivApplet::{v}"),
            AppletFingerprint::AuthentrendATKey => write!(f, "AuthentrendATKey"),
            AppletFingerprint::Feitian => write!(f, "Feitian"),
            AppletFingerprint::HidCrescendo(v) => write!(f, "HidCrescendo::{v}"),
            AppletFingerprint::IdPrime => write!(f, "IdPrime"),
            AppletFingerprint::Trussed(v) => write!(f, "Trussed::{v}"),
            AppletFingerprint::OpenFips201(v) => write!(f, "OpenFips201::{v}"),
            AppletFingerprint::Thetis => write!(f, "Thetis"),
            AppletFingerprint::Token2 => write!(f, "Token2"),
            AppletFingerprint::UTrust => write!(f, "UTrust"),
            AppletFingerprint::YubiKey => write!(f, "YubiKey"),
        }
    }
}

impl core::fmt::Display for ArekinathVariant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            ArekinathVariant::Generic => "Generic",
            ArekinathVariant::SwissbitIShield1 => "SwissbitIShield1",
        })
    }
}

impl core::fmt::Display for HidCrescendoVariant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            HidCrescendoVariant::Generic => "Generic",
            HidCrescendoVariant::C2300 => "C2300",
            HidCrescendoVariant::C4000 => "C4000",
        })
    }
}

impl core::fmt::Display for TrussedVariant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            TrussedVariant::NitroKey => "NitroKey",
        })
    }
}

impl core::fmt::Display for OpenFips201Variant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            OpenFips201Variant::Generic => "Generic",
            OpenFips201Variant::SwissbitIShield2 => "SwissbitIShield2",
        })
    }
}

impl AppletFingerprint {
    /// A generic, human-readable display name for this fingerprint — the
    /// fallback a caller shows when the token didn't report a specific name
    /// of its own (see `keyroost_transport::PivStatus::applet_name`).
    /// Distinct from the [`Display`](core::fmt::Display) impl above, which
    /// renders the variant name(s) rather than a product name (a Swissbit
    /// iShield's `OpenFips201::SwissbitIShield2` vs. this method's
    /// `"Swissbit iShield 2 Series"`).
    #[must_use]
    pub fn applet_name(&self) -> &'static str {
        match self {
            AppletFingerprint::Generic => "Generic PIV",
            AppletFingerprint::ArekinathPivApplet(ArekinathVariant::Generic) => {
                "Generic Arekinath's PivApplet Variant"
            }
            AppletFingerprint::ArekinathPivApplet(ArekinathVariant::SwissbitIShield1) => {
                "Swissbit iShield 1 Series"
            }
            AppletFingerprint::AuthentrendATKey => "Authentrend ATKey Series",
            AppletFingerprint::Feitian => "Feitian Security Key",
            AppletFingerprint::HidCrescendo(HidCrescendoVariant::Generic) => {
                "HID Crescendo ActivId"
            }
            AppletFingerprint::HidCrescendo(HidCrescendoVariant::C2300) => "HID Crescendo C2300",
            AppletFingerprint::HidCrescendo(HidCrescendoVariant::C4000) => "HID Crescendo C4000",
            AppletFingerprint::IdPrime => "IdPrime PIV Series",
            AppletFingerprint::Trussed(TrussedVariant::NitroKey) => "NitroKey",
            AppletFingerprint::OpenFips201(OpenFips201Variant::Generic) => "Generic OpenFIPS201",
            AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2) => {
                "Swissbit iShield 2 Series"
            }
            AppletFingerprint::Thetis => "Thetis Series",
            AppletFingerprint::Token2 => "Token2 Series",
            AppletFingerprint::UTrust => "Identiv/Hirsch uTrust Series",
            AppletFingerprint::YubiKey => "Yubico YubiKey Series",
        }
    }
}

/// ISO 7816-3 §8.2.3 historical bytes from a raw ATR (or a PC/SC-synthesised
/// contactless pseudo-ATR): walks past TS, T0, and the TA/TB/TC/TD
/// interface-byte blocks the T0/TD nibbles describe, then returns the
/// trailing `hist_len`-byte block T0's low nibble names. `None` on any
/// structural short-read (truncated ATR) — a malformed ATR just yields no
/// fingerprint rather than a wrong one.
#[must_use]
pub fn atr_historical_bytes(atr: &[u8]) -> Option<&[u8]> {
    let t0 = *atr.get(1)?;
    let hist_len = usize::from(t0 & 0x0F);
    let mut y = t0 >> 4;
    let mut pos = 2usize;
    loop {
        for bit in 0..3 {
            if y & (1 << bit) != 0 {
                atr.get(pos)?;
                pos += 1;
            }
        }
        if y & 0b1000 == 0 {
            break;
        }
        let td = *atr.get(pos)?;
        pos += 1;
        y = td >> 4;
    }
    atr.get(pos..pos + hist_len)
}

/// ISO 7816-4 §8.1.1 COMPACT-TLV objects from a historical-byte region: each
/// object is a header byte `(tag << 4) | len` followed by `len` value bytes.
/// A `0x00` header is padding and ends the run, as does a length that
/// overruns the buffer — either way, whatever parsed cleanly is kept.
fn compact_tlv(mut data: &[u8]) -> Vec<(u8, &[u8])> {
    let mut out = Vec::new();
    while let Some((&head, rest)) = data.split_first() {
        if head == 0x00 {
            break;
        }
        let len = usize::from(head & 0x0F);
        if rest.len() < len {
            break;
        }
        out.push((head >> 4, &rest[..len]));
        data = &rest[len..];
    }
    out
}

/// Decode raw bytes into a `String` one byte per `char` (not UTF-8/lossy
/// decoding) — some historical-byte fields embed a literal NUL as a
/// separator (Token2's "TK\0PIV"), which a lossy UTF-8 decode would leave
/// intact anyway, but this keeps the mapping exact for any non-ASCII byte
/// too rather than substituting a replacement character.
fn bytes_as_chars(raw: &[u8]) -> String {
    raw.iter().map(|&b| b as char).collect()
}

/// The "atr identity" fingerprint text, per keyroost's fingerprinting scheme:
///
/// * category `0x00`/`0x80` (the two COMPACT-TLV historical-byte layouts):
///   the COMPACT-TLV "card issuer's data" object (tag `0x5`) — this is the
///   free-text field ISO 7816-4 reserves for exactly this, and it's where
///   real tokens put a product name (a YubiKey's tag-5 object decodes to
///   literally `"YubiKey"`).
/// * any other category: the entire historical-byte block.
///
/// Both are decoded via [`bytes_as_chars`]. `None` when there are no
/// historical bytes, or (for the TLV categories) no tag-5 object.
#[must_use]
pub fn atr_identity(historical: &[u8]) -> Option<String> {
    let (&category, rest) = historical.split_first()?;
    let raw: &[u8] = match category {
        0x00 | 0x80 => {
            compact_tlv(rest)
                .into_iter()
                .find(|(tag, _)| *tag == 0x5)?
                .1
        }
        _ => historical,
    };
    (!raw.is_empty()).then(|| bytes_as_chars(raw))
}

/// The "select identity" fingerprint text: ISO 7816-4 tag `0x50` (Application
/// Label), searched recursively through the SELECT response's (possibly
/// nested) constructed BER-TLV structure — vendors disagree on whether it
/// sits directly under the `0x6F` FCI or nested inside a proprietary `0xA5`
/// template, so this doesn't assume either shape. Decoded as lossy UTF-8:
/// unlike ATR issuer data, this field carries vendor+version text
/// (`"PivApplet/1.10"`, `"OpenFIPS201"`, ...), not a fixed-width value that
/// would legitimately embed a NUL. `None` when absent or empty.
#[must_use]
pub fn select_identity(select_response: &[u8]) -> Option<String> {
    let value = crate::find_tlv_recursive(select_response, 0x50)?;
    (!value.is_empty()).then(|| String::from_utf8_lossy(value).into_owned())
}

/// Whether [`classify`] would use a positive `swissbit_rid_selectable` — i.e.
/// whether it's worth the transport layer's spending an extra SELECT/
/// re-SELECT round trip to find out. Only true once the base OpenFIPS201
/// select identity is already present; probing on every card regardless
/// would mean two extra APDUs on every PIV status read for a bit that only
/// ever matters on Swissbit's own firmware.
#[must_use]
pub fn wants_swissbit_probe(select_identity: Option<&str>) -> bool {
    select_identity.is_some_and(|s| s.to_ascii_lowercase().contains("openfips201"))
}

/// Resolve an [`AppletFingerprint`] from the fingerprint text plus the three
/// live-probe bits — all "can a specific applet be selected by AID at all"
/// checks ([`wants_swissbit_probe`]'s [`SWISSBIT_RID`],
/// `feitian_rid_selectable`'s [`FEITIAN_RID`], and `idprime_aid_selectable`'s
/// [`IDPRIME_SECONDARY_PIV_AID`]) — the transport layer can supply. Comparisons are
/// case-insensitive throughout, per the fingerprinting scheme. When more
/// than one fingerprint's criteria are satisfied, the one backed by the most
/// criteria wins — realised here as a priority order from most-specific to
/// least, since with the duplicate uTrust definition dropped no two entries
/// can actually tie. `feitian_rid_selectable` and, after it,
/// `idprime_aid_selectable` sit at the very end of that order: each is the
/// sole criterion for its own identity ([`AppletFingerprint::Feitian`] /
/// [`AppletFingerprint::IdPrime`]), so a caller only needs to have actually
/// performed that probe (an extra SELECT round trip) when every other branch
/// here — including the other one of the two — would otherwise fall through
/// to `Generic`. Passing `false` for a probe that wasn't run is exactly as
/// safe as any other unanswered criterion.
#[must_use]
pub fn classify(
    atr_identity: Option<&str>,
    select_identity: Option<&str>,
    swissbit_rid_selectable: bool,
    feitian_rid_selectable: bool,
    idprime_aid_selectable: bool,
) -> AppletFingerprint {
    let atr = atr_identity.map(str::to_ascii_lowercase);
    let atr = atr.as_deref();
    let sel = select_identity.map(str::to_ascii_lowercase);
    let sel = sel.as_deref();

    // 2 criteria: select identity starts with "PivApplet" AND contains "/".
    let arekinath = sel.is_some_and(|s| s.starts_with("pivapplet") && s.contains('/'));
    // 1 criterion: select identity includes "OpenFIPS201".
    let open_fips_201 = sel.is_some_and(|s| s.contains("openfips201"));
    // 1 criterion: select identity starts with "HID Global ActivID".
    let hid_crescendo_sel = sel.is_some_and(|s| s.starts_with("hid global activid"));

    if arekinath && atr == Some("ishield") {
        // 3 criteria (the 2 above plus the ATR identity).
        AppletFingerprint::ArekinathPivApplet(ArekinathVariant::SwissbitIShield1)
    } else if open_fips_201 && swissbit_rid_selectable {
        // 2 criteria (the 1 above plus the live probe).
        AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2)
    } else if arekinath {
        AppletFingerprint::ArekinathPivApplet(ArekinathVariant::Generic)
    } else if atr == Some("c2300") || atr == Some("c4000") || hid_crescendo_sel {
        // The ATR identity picks the variant when it names a recognised
        // model; a match via the select identity alone (neither C2300 nor
        // C4000) is the generic `Generic`.
        AppletFingerprint::HidCrescendo(match atr {
            Some("c2300") => HidCrescendoVariant::C2300,
            Some("c4000") => HidCrescendoVariant::C4000,
            _ => HidCrescendoVariant::Generic,
        })
    } else if sel.is_some_and(|s| s.starts_with("nitrokey")) {
        AppletFingerprint::Trussed(TrussedVariant::NitroKey)
    } else if open_fips_201 {
        AppletFingerprint::OpenFips201(OpenFips201Variant::Generic)
    } else if atr.is_some_and(|a| a.starts_with("tk\0piv") || a.starts_with("tk piv")) {
        AppletFingerprint::Token2
    } else if atr.is_some_and(|a| a.contains("piv") && a.contains("8888888")) {
        AppletFingerprint::Thetis
    } else if atr == Some("utrust") {
        AppletFingerprint::UTrust
    } else if atr == Some("yubikey") {
        AppletFingerprint::YubiKey
    } else if sel.is_some_and(|s| s.starts_with("atpiv")) {
        AppletFingerprint::AuthentrendATKey
    } else if feitian_rid_selectable {
        AppletFingerprint::Feitian
    } else if idprime_aid_selectable {
        AppletFingerprint::IdPrime
    } else {
        AppletFingerprint::Generic
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- atr_historical_bytes: interface-byte walk ------------------------

    #[test]
    fn historical_bytes_after_no_interface_bytes() {
        // T0 = 0x02: no TA/TB/TC/TD, 2 historical bytes follow immediately.
        let atr = [0x3B, 0x02, 0xAA, 0xBB];
        assert_eq!(atr_historical_bytes(&atr), Some(&[0xAA, 0xBB][..]));
    }

    #[test]
    fn historical_bytes_skip_one_interface_byte() {
        // T0 = 0x1F: y = 1 (TA1 present), hist_len = F = 15... trim to fit.
        // Use a smaller, exact example instead: T0 = 0x12 -> y=1 (TA1), len=2.
        let atr = [0x3B, 0x12, 0x96, 0xAA, 0xBB];
        assert_eq!(atr_historical_bytes(&atr), Some(&[0xAA, 0xBB][..]));
    }

    #[test]
    fn historical_bytes_walk_chained_td_blocks() {
        // T0 = 0x81: y=8 (TD1 present, no TA/TB/TC in block 1), hist_len=1.
        // TD1 = 0x00: protocol 0, y'=0 -> block 2 has nothing, chain ends.
        let atr = [0x3B, 0x81, 0x00, 0xAA];
        assert_eq!(atr_historical_bytes(&atr), Some(&[0xAA][..]));
    }

    #[test]
    fn truncated_atr_yields_none() {
        // T0 claims 4 historical bytes, only 1 is actually present.
        let atr = [0x3B, 0x04, 0xAA];
        assert_eq!(atr_historical_bytes(&atr), None);
        // Missing T0 entirely.
        assert_eq!(atr_historical_bytes(&[0x3B]), None);
    }

    // --- atr_identity: category 0x80 (real YubiKey historical bytes) -----

    #[test]
    fn yubikey_tag5_is_the_atr_identity() {
        // 80 73 C0 21 C0 57 59 75 62 69 4B 65 79 40:
        //   category 0x80, tag-7 card capabilities (C0 21 C0), tag-5 issuer
        //   data "YubiKey" (57 59 75 62 69 4B 65 79 -> len 7), tag-4 empty.
        let hist = [
            0x80, 0x73, 0xC0, 0x21, 0xC0, 0x57, 0x59, 0x75, 0x62, 0x69, 0x4B, 0x65, 0x79, 0x40,
        ];
        assert_eq!(atr_identity(&hist).as_deref(), Some("YubiKey"));
    }

    #[test]
    fn tag5_absent_is_no_identity_for_tlv_categories() {
        // category 0x80, only a tag-7 object — no tag 5 anywhere.
        let hist = [0x80, 0x73, 0xC0, 0x21, 0xC0];
        assert_eq!(atr_identity(&hist), None);
    }

    #[test]
    fn embedded_nul_survives_atr_identity() {
        // category 0x00, tag-5 "TK\0PIV" (6 bytes), no status trailer.
        let hist = [0x00, 0x56, b'T', b'K', 0x00, b'P', b'I', b'V'];
        assert_eq!(atr_identity(&hist).as_deref(), Some("TK\0PIV"));
    }

    #[test]
    fn non_tlv_category_is_the_whole_block_as_chars() {
        // category 0x41 (proprietary) - not 0x00/0x80, so no TLV decode:
        // the whole historical-byte block becomes the identity.
        let hist = [0x41, b'u', b'T', b'r', b'u', b's', b't'];
        assert_eq!(atr_identity(&hist).as_deref(), Some("AuTrust"));
    }

    #[test]
    fn empty_historical_bytes_is_no_identity() {
        assert_eq!(atr_identity(&[]), None);
    }

    // --- select_identity: recursive tag-0x50 search -----------------------

    #[test]
    fn select_identity_at_top_level() {
        // 6F <len> 50 <len> "OpenFIPS201"
        let mut resp = vec![0x6F, 0x0D, 0x50, 0x0B];
        resp.extend_from_slice(b"OpenFIPS201");
        assert_eq!(select_identity(&resp).as_deref(), Some("OpenFIPS201"));
    }

    #[test]
    fn select_identity_nested_under_proprietary_template() {
        // 6F <len> A5 <len> 50 <len> "PivApplet/1.10"
        let label = b"PivApplet/1.10";
        let mut inner = vec![0x50, label.len() as u8];
        inner.extend_from_slice(label);
        let mut resp = vec![0x6F, (inner.len() + 2) as u8, 0xA5, inner.len() as u8];
        resp.extend_from_slice(&inner);
        assert_eq!(select_identity(&resp).as_deref(), Some("PivApplet/1.10"));
    }

    #[test]
    fn select_identity_absent_is_none() {
        let resp = [0x6F, 0x02, 0x84, 0x00];
        assert_eq!(select_identity(&resp), None);
    }

    // --- wants_swissbit_probe -----------------------------------------

    #[test]
    fn probe_only_wanted_for_openfips201() {
        assert!(wants_swissbit_probe(Some("OpenFIPS201")));
        assert!(wants_swissbit_probe(Some("openfips201 v1.0"))); // case-insensitive
        assert!(!wants_swissbit_probe(Some("PivApplet/1.10")));
        assert!(!wants_swissbit_probe(None));
    }

    // --- classify: one case per fingerprint, plus the priority ordering ---

    #[test]
    fn classify_falls_back_to_generic() {
        assert_eq!(
            classify(None, None, false, false, false),
            AppletFingerprint::Generic
        );
        assert_eq!(
            classify(
                Some("something unknown"),
                Some("also unknown"),
                false,
                false,
                false
            ),
            AppletFingerprint::Generic
        );
    }

    #[test]
    fn classify_feitian_only_via_the_rid_probe() {
        // The probe bit alone, no other fingerprinting text, is enough.
        assert_eq!(
            classify(None, None, false, true, false),
            AppletFingerprint::Feitian
        );
        // It's the lowest-priority criterion: any other match wins over it.
        assert_eq!(
            classify(Some("YubiKey"), None, false, true, false),
            AppletFingerprint::YubiKey
        );
        // Without the probe (or a false result from it), an otherwise
        // unidentified card stays Generic.
        assert_eq!(
            classify(None, None, false, false, false),
            AppletFingerprint::Generic
        );
    }

    #[test]
    fn classify_idprime_only_via_the_aid_probe() {
        // The probe bit alone, no other fingerprinting text, is enough.
        assert_eq!(
            classify(None, None, false, false, true),
            AppletFingerprint::IdPrime
        );
        // It's lower priority than even Feitian's own catch-all probe.
        assert_eq!(
            classify(None, None, false, true, true),
            AppletFingerprint::Feitian
        );
        // Without the probe (or a false result from it), an otherwise
        // unidentified card stays Generic.
        assert_eq!(
            classify(None, None, false, false, false),
            AppletFingerprint::Generic
        );
    }

    #[test]
    fn classify_arekinath_any_and_swissbit_variant() {
        assert_eq!(
            classify(None, Some("PivApplet/1.10"), false, false, false),
            AppletFingerprint::ArekinathPivApplet(ArekinathVariant::Generic)
        );
        // Case-insensitive on both fields, and the ATR identity narrows to
        // the Swissbit variant.
        assert_eq!(
            classify(Some("iShield"), Some("pivapplet/2.0"), false, false, false),
            AppletFingerprint::ArekinathPivApplet(ArekinathVariant::SwissbitIShield1)
        );
        // "PivApplet" without a "/" doesn't satisfy the base 2-criteria match.
        assert_eq!(
            classify(None, Some("PivApplet"), false, false, false),
            AppletFingerprint::Generic
        );
    }

    #[test]
    fn classify_authentrend_atkey() {
        assert_eq!(
            classify(None, Some("ATPIV v3"), false, false, false),
            AppletFingerprint::AuthentrendATKey
        );
    }

    #[test]
    fn classify_hid_crescendo_variants_by_atr() {
        assert_eq!(
            classify(Some("C2300"), None, false, false, false),
            AppletFingerprint::HidCrescendo(HidCrescendoVariant::C2300)
        );
        assert_eq!(
            classify(Some("C4000"), None, false, false, false),
            AppletFingerprint::HidCrescendo(HidCrescendoVariant::C4000)
        );
    }

    #[test]
    fn classify_hid_crescendo_any_via_select_identity_alone() {
        // Matched via the select identity, with an ATR that names neither
        // recognised model (or none at all) — the generic `Generic` variant.
        assert_eq!(
            classify(None, Some("HID Global ActivID PIV"), false, false, false),
            AppletFingerprint::HidCrescendo(HidCrescendoVariant::Generic)
        );
        assert_eq!(
            classify(
                Some("something else"),
                Some("HID Global ActivID PIV"),
                false,
                false,
                false
            ),
            AppletFingerprint::HidCrescendo(HidCrescendoVariant::Generic)
        );
    }

    #[test]
    fn classify_trussed_nitrokey() {
        // Select identity, not ATR identity — Nitrokey's ATR is ignored.
        assert_eq!(
            classify(
                None,
                Some("Nitrokey PIV Authenticator"),
                false,
                false,
                false
            ),
            AppletFingerprint::Trussed(TrussedVariant::NitroKey)
        );
        assert_eq!(
            classify(Some("Nitrokey"), None, false, false, false),
            AppletFingerprint::Generic
        );
    }

    #[test]
    fn classify_openfips201_any_and_swissbit_variant() {
        assert_eq!(
            classify(None, Some("OpenFIPS201"), false, false, false),
            AppletFingerprint::OpenFips201(OpenFips201Variant::Generic)
        );
        assert_eq!(
            classify(None, Some("OpenFIPS201"), true, false, false),
            AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2)
        );
        // The probe bit alone (no OpenFIPS201 select identity) matches nothing.
        assert_eq!(
            classify(None, None, true, false, false),
            AppletFingerprint::Generic
        );
    }

    #[test]
    fn classify_token2_either_spelling() {
        assert_eq!(
            classify(Some("TK\0PIV v1"), None, false, false, false),
            AppletFingerprint::Token2
        );
        assert_eq!(
            classify(Some("TK PIV v1"), None, false, false, false),
            AppletFingerprint::Token2
        );
    }

    #[test]
    fn classify_thetis_needs_both_substrings_case_insensitively() {
        assert_eq!(
            classify(Some("PIV 8888888"), None, false, false, false),
            AppletFingerprint::Thetis
        );
        // Case-insensitive on the ATR identity, same as every other branch.
        assert_eq!(
            classify(Some("piv 8888888"), None, false, false, false),
            AppletFingerprint::Thetis
        );
        // Either substring alone isn't enough.
        assert_eq!(
            classify(Some("PIV only"), None, false, false, false),
            AppletFingerprint::Generic
        );
        assert_eq!(
            classify(Some("8888888 only"), None, false, false, false),
            AppletFingerprint::Generic
        );
    }

    #[test]
    fn token2_r3_3_historical_bytes_are_not_misclassified_as_thetis() {
        // Real ATR historical bytes from a Token2 R3.3+ device: "TK\0PIV"
        // (the signature `classify`'s Token2 branch matches on), followed by
        // a 2-byte version and, coincidentally, "8888888" — the very
        // substring `classify`'s Thetis branch looks for. This is the exact
        // collision documented on `AppletFingerprint::Thetis` and
        // <https://github.com/framefilter/keyroost/issues/125>: were the
        // Thetis branch checked first (or independently of the Token2
        // branch), this ATR would misclassify as Thetis.
        let historical = [
            0x54, 0x4B, 0x00, 0x50, 0x49, 0x56, 0x04, 0x02, 0x38, 0x38, 0x38, 0x38, 0x38, 0x38,
            0x38,
        ];
        let identity = atr_identity(&historical);
        assert_eq!(identity.as_deref(), Some("TK\0PIV\u{4}\u{2}8888888"));
        assert_eq!(
            classify(identity.as_deref(), None, false, false, false),
            AppletFingerprint::Token2
        );
    }

    #[test]
    fn classify_utrust_and_yubikey() {
        assert_eq!(
            classify(Some("uTrust"), None, false, false, false),
            AppletFingerprint::UTrust
        );
        assert_eq!(
            classify(Some("YubiKey"), None, false, false, false),
            AppletFingerprint::YubiKey
        );
    }

    #[test]
    fn applet_name_matches_the_display_name_table() {
        // Pins the exact generic display name for every constructible value,
        // so a future variant added without a matching arm fails to
        // compile, not just fails a test.
        let cases = [
            (AppletFingerprint::Generic, "Generic PIV"),
            (
                AppletFingerprint::ArekinathPivApplet(ArekinathVariant::Generic),
                "Generic Arekinath's PivApplet Variant",
            ),
            (
                AppletFingerprint::ArekinathPivApplet(ArekinathVariant::SwissbitIShield1),
                "Swissbit iShield 1 Series",
            ),
            (
                AppletFingerprint::AuthentrendATKey,
                "Authentrend ATKey Series",
            ),
            (AppletFingerprint::Feitian, "Feitian Security Key"),
            (
                AppletFingerprint::HidCrescendo(HidCrescendoVariant::Generic),
                "HID Crescendo ActivId",
            ),
            (
                AppletFingerprint::HidCrescendo(HidCrescendoVariant::C2300),
                "HID Crescendo C2300",
            ),
            (
                AppletFingerprint::HidCrescendo(HidCrescendoVariant::C4000),
                "HID Crescendo C4000",
            ),
            (AppletFingerprint::IdPrime, "IdPrime PIV Series"),
            (
                AppletFingerprint::Trussed(TrussedVariant::NitroKey),
                "NitroKey",
            ),
            (
                AppletFingerprint::OpenFips201(OpenFips201Variant::Generic),
                "Generic OpenFIPS201",
            ),
            (
                AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2),
                "Swissbit iShield 2 Series",
            ),
            (AppletFingerprint::Thetis, "Thetis Series"),
            (AppletFingerprint::Token2, "Token2 Series"),
            (AppletFingerprint::UTrust, "Identiv/Hirsch uTrust Series"),
            (AppletFingerprint::YubiKey, "Yubico YubiKey Series"),
        ];
        for (id, expected) in cases {
            assert_eq!(id.applet_name(), expected);
        }
    }

    // --- Display: Rust-style `::` for sub-identities, not Debug's parens --

    #[test]
    fn display_uses_a_double_colon_for_sub_identities() {
        assert_eq!(AppletFingerprint::Generic.to_string(), "Generic");
        assert_eq!(
            AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2).to_string(),
            "OpenFips201::SwissbitIShield2"
        );
        assert_eq!(
            AppletFingerprint::ArekinathPivApplet(ArekinathVariant::Generic).to_string(),
            "ArekinathPivApplet::Generic"
        );
        assert_eq!(
            AppletFingerprint::Trussed(TrussedVariant::NitroKey).to_string(),
            "Trussed::NitroKey"
        );
        assert_eq!(
            AppletFingerprint::HidCrescendo(HidCrescendoVariant::C4000).to_string(),
            "HidCrescendo::C4000"
        );
        assert_eq!(AppletFingerprint::Feitian.to_string(), "Feitian");
        assert_eq!(AppletFingerprint::IdPrime.to_string(), "IdPrime");
        assert_eq!(AppletFingerprint::Thetis.to_string(), "Thetis");
        assert_eq!(AppletFingerprint::YubiKey.to_string(), "YubiKey");
    }

    // --- plain-text response decoding ---------------------------------------

    #[test]
    fn ascii_text_decodes_plain_text() {
        // No TLV framing at all — the Nitrokey admin app's firmware reply.
        let fw = b"3.35.0";
        assert_eq!(parse_ascii_text(fw).as_deref(), Some("3.35.0"));
    }

    #[test]
    fn ascii_text_empty_is_none() {
        assert_eq!(parse_ascii_text(&[]), None);
    }

    // --- Nitrokey admin status: hardware variant byte -----------------------

    #[test]
    fn nitrokey_variant_reads_offset_4() {
        // init_status, ifs_blocks, efs_blocks (2 bytes BE), variant.
        assert_eq!(
            parse_nitrokey_variant(&[0x00, 0x10, 0x00, 0x20, 0x00]),
            Some("USBIP")
        );
        assert_eq!(
            parse_nitrokey_variant(&[0x00, 0x10, 0x00, 0x20, 0x01]),
            Some("LPC55")
        );
        assert_eq!(
            parse_nitrokey_variant(&[0x00, 0x10, 0x00, 0x20, 0x02]),
            Some("NRF52")
        );
    }

    #[test]
    fn nitrokey_variant_unknown_byte_or_short_response_is_none() {
        assert_eq!(
            parse_nitrokey_variant(&[0x00, 0x10, 0x00, 0x20, 0x03]),
            None
        );
        assert_eq!(parse_nitrokey_variant(&[0x00, 0x10, 0x00, 0x20]), None); // 4 bytes, no offset 4
        assert_eq!(parse_nitrokey_variant(&[]), None);
    }

    #[test]
    fn format_nitrokey_name_wraps_the_variant() {
        assert_eq!(format_nitrokey_name("NRF52"), "NitroKey (NRF52)");
    }

    // --- YubiKey display name from the already-fetched GET VERSION reply --

    #[test]
    fn format_yubikey_name_uses_the_major_version_byte() {
        assert_eq!(
            format_yubikey_name(&[5, 7, 4]).as_deref(),
            Some("Yubico YubiKey 5 Series")
        );
        assert_eq!(
            format_yubikey_name(&[4, 3, 7]).as_deref(),
            Some("Yubico YubiKey 4 Series")
        );
    }

    #[test]
    fn format_yubikey_name_empty_reply_is_none() {
        assert_eq!(format_yubikey_name(&[]), None);
    }

    // --- dotted version string -> byte components --------------------------

    #[test]
    fn dotted_version_splits_numeric_components() {
        assert_eq!(parse_dotted_version("3.35.0"), Some(vec![3, 35, 0]));
        assert_eq!(parse_dotted_version("1.2.3"), Some(vec![1, 2, 3]));
        // A single component (no dot) is still a valid one-element version.
        assert_eq!(parse_dotted_version("5"), Some(vec![5]));
    }

    #[test]
    fn dotted_version_rejects_empty_or_non_numeric() {
        assert_eq!(parse_dotted_version(""), None);
        assert_eq!(parse_dotted_version("a.b.c"), None);
        assert_eq!(parse_dotted_version("3..0"), None); // empty component
                                                        // A component that doesn't fit in a u8 makes the whole thing
                                                        // unparsable rather than silently truncating it.
        assert_eq!(parse_dotted_version("3.999.0"), None);
    }
}
