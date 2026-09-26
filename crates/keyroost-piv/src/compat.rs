//! Per-fingerprint known-support table for the non-standard PIV commands keyroost
//! exposes.
//!
//! A handful of management operations in this crate are vendor extensions, not
//! SP 800-73-4: Yubico's MOVE KEY and DELETE KEY, which landed in YubiKey
//! firmware 5.7. "Speaks PIV" says nothing about whether a given applet
//! implements them, and the answer can differ between firmware versions of the
//! same product. This module encodes what keyroost has actually observed,
//! keyed by [`AppletFingerprint`], as a **combined known-support table**: for each
//! fingerprint it knows about, a list of per-version verdicts each either
//! `Verdict::KnownSupported` ("extension known to be supported at this version")
//! or `Verdict::KnownUnsupported` ("extension known to be unsupported at this
//! version"). There are two such lists per extension — one keyed by the PIV
//! *applet's* own version, one by the *firmware's* — since the two can diverge
//! (see [`crate` root docs][crate] / `PivStatus::version` vs
//! `PivStatus::version_firmware` in `keyroost-transport`) and a fingerprint may
//! have data on one axis but not the other.
//!
//! [`resolve`] queries both tables with the live applet's fingerprint and its
//! applet and firmware versions and returns a three-way [`FeatureGate`] a UI
//! consumes directly: enable the control ([`FeatureGate::Supported`]), enable
//! it but flag it ([`FeatureGate::Unverified`]), or disable it
//! ([`FeatureGate::Unsupported`]). Each axis is queried independently with the
//! same semantics, then the two outcomes are combined (see [`resolve`] for the
//! combination rule). Per axis, a verdict extends across the untested
//! versions adjacent to it, in both directions: a known-supported verdict extends
//! *forward* ("known to work at this version, assumed to still work at any
//! later, untested version") and, symmetrically, a known-unsupported verdict extends
//! *backward* ("known not to work at this version, assumed not to work at any
//! earlier, untested version either"). Anything less certain — no verdicts
//! for the fingerprint at all, no reported version, or a known-unsupported verdict old
//! enough that a later firmware might have added the extension — resolves to
//! [`FeatureGate::Unverified`] on that axis, which keeps the control usable
//! unless the other axis disagrees.
//!
//! The same per-version rows also carry [`PivQuirk`]s — observed behavioral
//! wrinkles that need a workaround rather than gating a control. Quirks are
//! resolved separately by [`resolve_quirks`], with simpler semantics than
//! [`resolve`]: no known-support distinction, just "take the current entry on each
//! axis and merge whatever quirks it lists."
//!
//! [`PivExtension`] isn't limited to commands a UI puts a control in front
//! of, either: [`PivExtension::GetMetadata`] and [`PivExtension::Attest`]
//! are Yubico vendor extensions exactly like MOVE KEY/DELETE KEY, just
//! consumed internally (`keyroost-transport`'s `PivSession::metadata`/
//! `attest`) rather than gating a button — a fingerprint that has never
//! implemented one is a plain "unsupported extension" fact, the same shape
//! [`resolve`] already models, not a [`PivQuirk`] (which is reserved for a
//! device that *does* implement something and gets a detail of it wrong).

use std::collections::BTreeSet;

use crate::fingerprint::{
    AppletFingerprint, ArekinathVariant, HidCrescendoVariant, OpenFips201Variant, TrussedVariant,
    UTrustVariant, HID_CRESCENDO_ACA_FACTORY_XAUTH_KEY,
};
use crate::KeyAlg;

/// One offerable choice in a management-key algorithm picker — every
/// [`crate::MgmtAlg`] variant, plus [`Self::Delete`] for a device (HID
/// Crescendo) that can remove its management key outright instead of only
/// ever replacing it. A sibling of [`crate::MgmtAlg`] rather than an added
/// variant on it: "Delete" isn't a cipher, so it has no sensible
/// [`crate::MgmtAlg::id`]/[`crate::MgmtAlg::block_size`]/
/// [`crate::MgmtAlg::key_len`], and every one of those methods (plus every
/// real-crypto caller across `keyroost-transport`) would otherwise need an
/// arm for a case that can't occur there — the same reason `keyroost`'s own
/// GUI-side `PivMgmtAlgSel` selector keeps `Delete` as a sibling choice
/// rather than folding it into `crate::MgmtAlg`, converting to
/// `Option<crate::MgmtAlg>` (`None` for `Delete`) the same way this type's
/// [`Self::to_mgmt_alg`] does. Exists purely as [`PivExtension::ManagementKeyAlgorithm`]'s
/// argument, so [`resolve`] can gate each choice in a management-key picker
/// the same way [`PivExtension::SlotKeyAlgorithm`] already gates each
/// [`crate::KeyAlg`] in a slot's key-algorithm picker.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MgmtAlgChoice {
    /// [`crate::MgmtAlg::TripleDes`].
    TripleDes,
    /// [`crate::MgmtAlg::Aes128`].
    Aes128,
    /// [`crate::MgmtAlg::Aes192`].
    Aes192,
    /// [`crate::MgmtAlg::Aes256`].
    Aes256,
    /// Remove the management key outright rather than replace it — no
    /// corresponding [`crate::MgmtAlg`] variant, since it isn't a real
    /// cipher. HID Crescendo's own PUT XAUTH KEY "remove" form
    /// ([`crate::fingerprint::hid_crescendo_aca_put_xauth_key_remove`]) is
    /// the only mechanism keyroost implements for this today.
    Delete,
}

impl MgmtAlgChoice {
    /// The real [`crate::MgmtAlg`] this choice names, or `None` for
    /// [`Self::Delete`], which names no algorithm at all.
    #[must_use]
    pub const fn to_mgmt_alg(self) -> Option<crate::MgmtAlg> {
        match self {
            MgmtAlgChoice::TripleDes => Some(crate::MgmtAlg::TripleDes),
            MgmtAlgChoice::Aes128 => Some(crate::MgmtAlg::Aes128),
            MgmtAlgChoice::Aes192 => Some(crate::MgmtAlg::Aes192),
            MgmtAlgChoice::Aes256 => Some(crate::MgmtAlg::Aes256),
            MgmtAlgChoice::Delete => None,
        }
    }

    /// Short human label — [`crate::MgmtAlg::label`] for every real algorithm,
    /// `"Delete"` for [`Self::Delete`].
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            MgmtAlgChoice::Delete => "Delete",
            MgmtAlgChoice::TripleDes => crate::MgmtAlg::TripleDes.label(),
            MgmtAlgChoice::Aes128 => crate::MgmtAlg::Aes128.label(),
            MgmtAlgChoice::Aes192 => crate::MgmtAlg::Aes192.label(),
            MgmtAlgChoice::Aes256 => crate::MgmtAlg::Aes256.label(),
        }
    }
}

/// One of the non-standard, vendor-extension PIV commands keyroost exposes —
/// nothing in SP 800-73-4 defines it, so support varies by applet and is
/// gated by device fingerprint through [`resolve`]. Not limited to commands a
/// UI puts a control in front of: [`Self::GetMetadata`]/[`Self::Attest`] are
/// consumed internally by `keyroost-transport`'s `PivSession`, gating
/// whether it bothers sending the APDU at all rather than gating a button.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PivExtension {
    /// Yubico MOVE KEY — relocate a slot's private key into another slot.
    MoveKey,
    /// Yubico DELETE KEY — erase a slot's private key in place. Whether
    /// this is even worth *offering* on an already-empty slot is a
    /// separate question from whether the operation is supported at all —
    /// see [`Self::GetSlotKeyStatus`] for the gate a caller checks before
    /// trusting a "no key here" reading enough to block the button on it;
    /// this extension's own gate only answers "can DELETE KEY run here at
    /// all".
    DeleteKey,
    /// Yubico GET METADATA (`INS 0xF7`) — key/PIN algorithm, policy, origin,
    /// retries.
    GetMetadata,
    /// Whether a slot's private-key occupancy (does it hold a key at all,
    /// independent of any certificate) can be read straight from the
    /// device, rather than inferred. Unlike every other extension here,
    /// this one is **not** primarily version-gated per fingerprint —
    /// [`resolve`] special-cases it to fall through to
    /// [`Self::GetMetadata`]'s own verdict whenever `applet_verdicts` carries
    /// no [`Self::GetSlotKeyStatus`] entry for the fingerprint at all (see
    /// [`resolve`]'s doc for the mechanics), because GET METADATA's `algorithm` field *is*
    /// how this capability is provided on every fingerprint that provides
    /// it via a Yubico-compatible mechanism. An entry only belongs in a
    /// fingerprint's table when it reports slot key status through some
    /// *other*, independently-confirmed channel — today: HID Crescendo's
    /// GET PIV PROPERTIES
    /// (`keyroost_transport::PivSession::hid_crescendo_slot_algorithm`),
    /// which answers this even though [`Self::GetMetadata`] itself resolves
    /// [`FeatureGate::Unsupported`] there. Consumed internally, the same
    /// way [`Self::GetMetadata`]/[`Self::Attest`] are (see this enum's own
    /// doc) — `keyroost_transport::PivSession::slot_key_algorithm` already
    /// tries both channels unconditionally and doesn't need this gate to
    /// decide whether to bother; the one real consumer today is a UI
    /// deciding whether a `None` algorithm reading is trustworthy enough to
    /// *block* an operation on (see [`Self::DeleteKey`]'s doc for why that
    /// distinction matters there specifically).
    GetSlotKeyStatus,
    /// Yubico ATTEST (`INS 0xF9`) — a slot's self-signed attestation
    /// certificate, proving on-card key generation.
    Attest,
    /// Unlocking PIV management functionality (key-gen, cert import,
    /// set-retries, management-key rotation, …) via PIN VERIFY instead of the
    /// standard `0x9B` GENERAL AUTHENTICATE round. Some devices (HID
    /// Crescendo) implement this directly — PIN VERIFY alone satisfies the
    /// same access condition GENERAL AUTHENTICATE on `0x9B` would. Others
    /// (YubiKey) implement it only indirectly: PIN VERIFY unlocks *reading*
    /// the actual management key off a PIN-protected data object
    /// (`keyroost_piv::OBJECT_PIN_PROTECTED_DATA`,
    /// `keyroost_piv::parse_pin_protected_management_key`), and the standard
    /// `0x9B` round still has to run with that key afterward. A caller
    /// checks this extension first, to decide whether to offer PIN-based
    /// management unlock at all (and how — `Supported` plain, `Unverified`
    /// with a caveat);
    /// `keyroost_transport::PivSession::authenticate_management_via_pin`
    /// itself then branches on the live *fingerprint* (HID Crescendo direct,
    /// everything else indirect) — see that method's own doc for why it
    /// isn't gated any more narrowly than that.
    PinManagementAuth,
    /// Resetting the PIV applet to factory defaults — wiping every slot's
    /// keys and certificates along with the PIN, PUK, and management key.
    /// SP 800-73-4 doesn't define one true mechanism for this: the dominant
    /// one in practice is Yubico's proprietary `INS 0xFB` "RESET" instruction
    /// (`keyroost_piv::piv::reset`), widely mimicked by other vendors, so
    /// keyroost defaults to sending it unless a fingerprint-specific rule
    /// selects a different sequence instead — see [`Self::ResetGlobal`] for
    /// HID Crescendo's own alternative
    /// (`keyroost_transport::PivSession::factory_reset` implements both,
    /// preferring `ResetGlobal`'s mechanism whenever it's available).
    /// Whether `INS
    /// 0xFB` is accepted can additionally depend on the quirk below, which
    /// this extension itself says nothing about — a caller checks support
    /// here first, then checks whether [`resolve_quirks`] reports
    /// [`PivQuirk::ResetNeedsManagementAuth`] (the HID Crescendo
    /// alternative); its absence carries a meaning of its own — see that
    /// quirk's doc. This extension is PIV-scoped only — see
    /// [`Self::ResetGlobal`] for the distinction from a reset that also takes
    /// other applets with it.
    Reset,
    /// A device-level reset directive that covers the PIV applet *and* at
    /// least one other applet in the same operation — HID Crescendo's own
    /// RESET CARD, run against its ACA (Access Control Applet) instance
    /// (`keyroost_piv::fingerprint::HID_CRESCENDO_ACA_AID`, `INS 0x38`;
    /// <https://docs.hidglobal.com/crescendo/api/c4000/reset-card.htm>),
    /// clears PIV's PKI keys and data containers alongside the XAUTH key,
    /// OATH keys/configuration, and (per the C4000 page) FIDO credentials —
    /// implemented by `keyroost_transport::PivSession::factory_reset`. This is
    /// what distinguishes it from [`Self::Reset`]:
    /// [`Self::Reset`] is defined as wiping *only* PIV, however it gets there;
    /// [`Self::ResetGlobal`] is a *different* directive, wider by definition,
    /// that happens to take PIV with it. It does not have to cover every
    /// applet on the device to count — PIV plus at least one other applet is
    /// enough — so a device offering this is not thereby claiming a full
    /// factory reset in one command, only that PIV isn't the only casualty.
    /// Resolved independently of [`Self::Reset`]: a device can support
    /// either, both, or neither.
    ResetGlobal,
    /// Setting the PIV PIN's and PUK's retry counters. The only mechanism
    /// keyroost implements today is Yubico SET PIN RETRIES (`INS 0xFA`,
    /// `keyroost_piv::set_pin_retries`) — one APDU that sets both counters
    /// together and resets both the PIN and the PUK to their factory
    /// defaults in the process, with no way to change one counter without
    /// the other, so unlike [`Self::MoveKey`]/[`Self::DeleteKey`] (two
    /// genuinely independent operations that just happen to share a YubiKey
    /// known-support row) this is modeled as a single extension covering
    /// both counters, not two separate PIN/PUK gates. This extension names
    /// the *capability*, though, not that one specific wire mechanism: a
    /// vendor can reach the same result its own proprietary way — HID
    /// Crescendo's SDK exposes an `UpdatePINProperties` method that in
    /// principle covers this ground (see `HID_CRESCENDO_C4000_APPLET_VERDICTS`'s
    /// doc) — the same shape [`Self::PinManagementAuth`] already
    /// uses for a capability two vendors reach by genuinely different
    /// mechanisms (direct PIN unlock on HID Crescendo, the indirect
    /// PIN-protected-management-key scheme on YubiKey) under one gate. A
    /// fingerprint with a confirmed alternative mechanism would resolve
    /// [`FeatureGate::Supported`] here too, once keyroost has an APDU-level
    /// implementation of it to run. Until then, every non-YubiKey verdict on
    /// this extension reflects keyroost only having the Yubico extension
    /// implemented and probed for — not a claim that no other device could
    /// ever support the capability.
    SetPinPukRetries,
    /// Replacing the card-management key. Same shape as
    /// [`Self::SetPinPukRetries`]'s own doc: this extension names the
    /// *capability*, not one specific wire mechanism, so a fingerprint
    /// reaching the same result its own proprietary way still resolves
    /// [`FeatureGate::Supported`] here. HID Crescendo is exactly that case,
    /// not a hypothetical one — a unit whose GET PIV PROPERTIES read doesn't
    /// name `0x9B` as a real slot object has no such object to write the
    /// standard APDU against at all, and rotates the ACA's XAUTH key 1
    /// instead, via HID's own PUT XAUTH KEY
    /// (`keyroost_transport::PivSession::hid_crescendo_aca_put_xauth_key_op`,
    /// called from `keyroost_transport::PivSession::set_management_key`
    /// itself, which branches on the fingerprint before ever building the
    /// standard APDU). Every non-YubiKey verdict on this extension otherwise
    /// reflects keyroost only having the Yubico extension implemented and
    /// probed for — not a claim that no other device could ever support the
    /// capability.
    SetManagementKey,
    /// Setting a slot's PIN policy (tag `0xAA`: does using the freshly
    /// generated private key require the PIN once per session, every time, or
    /// never) as part of GENERATE ASYMMETRIC KEYPAIR — Yubico's own extension
    /// to the standard command
    /// (<https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html>).
    /// Distinct from *reading* a slot's PIN policy back, which travels over
    /// [`Self::GetMetadata`] instead and is never guarded by this extension.
    /// `default` (send no `0xAA` tag at all) is standard PIV and always works
    /// regardless of this extension's verdict; only a non-default value needs
    /// it. See [`PivQuirk::SlotPinPolicyOnceNotSupported`] for the narrower
    /// case of a device that supports this extension in general but rejects
    /// one specific value.
    SlotPinPolicy,
    /// Setting a slot's touch policy (tag `0xAB`: does using the freshly
    /// generated private key require a physical touch never, always, or
    /// cached for a short window after the last one) as part of GENERATE
    /// ASYMMETRIC KEYPAIR — the sibling of [`Self::SlotPinPolicy`], same
    /// Yubico extension reference. Same "default needs nothing, this
    /// extension only gates the button once a non-default value is
    /// requested" shape, and the same GetMetadata/GENERATE split: reading a
    /// slot's touch policy back is unaffected by this extension's verdict.
    /// See [`PivQuirk::SlotTouchPolicyCachedNotSupported`] for the narrower
    /// case of a device that supports this extension in general but rejects
    /// the specific `cached` value.
    SlotTouchPolicy,
    /// Whether a given [`crate::KeyAlg`] can be used in a slot on this
    /// device — RSA-1024/2048 and ECC P-256/P-384 are standardized by SP
    /// 800-73-4 itself, but not every applet implements every standardized
    /// algorithm either (some drop RSA-1024 outright), and RSA-3072/4096, ECC
    /// P-521, and the Ed25519/X25519 curves are vendor extensions with no
    /// standard obligation at all. A plain, payload-free capability marker exactly
    /// like every other variant here — [`resolve`] gates it through the same
    /// per-fingerprint known-support tables and version-matching rule as
    /// [`Self::MoveKey`]/[`Self::DeleteKey`], and it's consumed internally
    /// (APDU construction and response parsing in `keyroost-transport`) the
    /// same way [`Self::GetMetadata`]/[`Self::Attest`] are, as well as
    /// surfaced to a UI's algorithm picker.
    ///
    /// Says nothing about which byte names `KeyAlg` on the wire — that's a
    /// separate question, resolved by [`slot_key_algorithm_apdu_id`]/
    /// [`key_alg_from_apdu_id`] rather than carried on this variant. Those
    /// default to [`crate::KeyAlg::id`]'s Yubico encoding and consult a
    /// small, per-fingerprint override table for any fingerprint confirmed to
    /// use a different byte — HID Crescendo C4000 is one such case, reporting
    /// RSA-4096 as `0x04` rather than `0x16` on GENERATE ASYMMETRIC KEYPAIR
    /// itself, not just its own proprietary GET PIV PROPERTIES / INJECT PKI
    /// KEY commands. Almost every entry in that table is non-versioned — one
    /// wire byte for the fingerprint's whole lifetime — except
    /// `Trussed::NitroKey`'s: its RSA-4096 byte itself changed, from `0xE1`
    /// pre-1.8.2 firmware to Yubico's own `0x16` at 1.8.2 and later, so that
    /// one entry is gated by firmware version like this variant's own
    /// known-support tables are. See `slot_key_algorithm_apdu_id_override`'s
    /// own doc for both cases.
    SlotKeyAlgorithm(KeyAlg),
    /// Whether a given [`MgmtAlgChoice`] can be set as the management key's
    /// algorithm on this device — the management-key counterpart of
    /// [`Self::SlotKeyAlgorithm`], same plain payload-free-per-value shape:
    /// [`resolve`] gates it through the same per-fingerprint known-support
    /// tables and version-matching rule, surfaced to a UI's management-key
    /// algorithm picker the same way [`Self::SlotKeyAlgorithm`] is surfaced to
    /// a slot's key-algorithm picker. Distinct from [`Self::SetManagementKey`]:
    /// that extension gates *whether the management key can be changed at
    /// all*; this one gates *which algorithm a change can use*, so a device
    /// can resolve [`FeatureGate::Supported`] on [`Self::SetManagementKey`]
    /// while still disabling individual algorithms here (e.g. HID Crescendo's
    /// XAUTH key rejects AES-192/AES-256 outright even though it accepts a
    /// replacement key in general). [`MgmtAlgChoice::Delete`] is a value like
    /// any other here, not a special case at the [`resolve`] layer — every
    /// fingerprint but [`AppletFingerprint::HidCrescendo`] resolves it
    /// [`FeatureGate::Unsupported`], since only HID Crescendo's XAUTH key can
    /// be removed outright rather than only ever replaced.
    ManagementKeyAlgorithm(MgmtAlgChoice),
}

impl PivExtension {
    /// A one-sentence statement of what running this extension needs, phrased
    /// for the user. A UI or the CLI follows it with a state-specific suffix —
    /// [`FeatureGate::UNVERIFIED_SUFFIX`] or [`FeatureGate::INCOMPATIBLE_SUFFIX`]
    /// — so both surfaces say the same thing. Not `const` — unlike every other
    /// variant, [`Self::SlotKeyAlgorithm`]'s sentence names the specific
    /// algorithm, so this has to build a `String` rather than return a
    /// `&'static str`; every other arm still returns the exact same fixed
    /// wording it always did, just heap-allocated now.
    #[must_use]
    pub fn requirement(self) -> String {
        match self {
            PivExtension::MoveKey => {
                "Moving keys between slots needs YubiKey 5.7+ or a compatible third-party device."
                    .to_string()
            }
            PivExtension::DeleteKey => {
                "Key deletion needs YubiKey 5.7+ or a compatible third-party device.".to_string()
            }
            PivExtension::GetMetadata => {
                "Reading key/PIN metadata needs YubiKey firmware 5.3+ or a compatible \
                 third-party device."
                    .to_string()
            }
            PivExtension::GetSlotKeyStatus => {
                "Reading a slot's key occupancy directly needs YubiKey firmware 5.3+ or a \
                 compatible third-party device."
                    .to_string()
            }
            PivExtension::Attest => {
                "Reading a key's attestation certificate needs YubiKey firmware 4.3+ or a \
                 compatible third-party device."
                    .to_string()
            }
            PivExtension::PinManagementAuth => {
                "Unlocking management with a PIN instead of the management key needs \
                 YubiKey 3+ or a compatible third-party device."
                    .to_string()
            }
            PivExtension::Reset => {
                "Resetting the PIV applet needs a YubiKey or a compatible third-party device."
                    .to_string()
            }
            PivExtension::ResetGlobal => {
                "A device-wide reset that takes PIV with it needs a compatible third-party \
                 device (e.g. HID Crescendo)."
                    .to_string()
            }
            PivExtension::SetPinPukRetries => {
                "Setting the PIN/PUK retry counts needs a YubiKey or a compatible third-party \
                 device."
                    .to_string()
            }
            PivExtension::SetManagementKey => {
                "Changing the management key needs a YubiKey or a compatible third-party device."
                    .to_string()
            }
            PivExtension::SlotPinPolicy => {
                "Setting a slot's PIN policy needs YubiKey firmware 4+ or a compatible \
                 third-party device."
                    .to_string()
            }
            PivExtension::SlotTouchPolicy => {
                "Setting a slot's touch policy needs YubiKey firmware 4+ or a compatible \
                 third-party device."
                    .to_string()
            }
            PivExtension::SlotKeyAlgorithm(alg) => {
                format!(
                    "Generating a {} key needs a compatible device.",
                    alg.label()
                )
            }
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Delete) => {
                "Deleting the management key outright needs a compatible third-party device \
                 (e.g. HID Crescendo)."
                    .to_string()
            }
            PivExtension::ManagementKeyAlgorithm(alg) => {
                format!(
                    "Using a {} management key needs a compatible device.",
                    alg.label()
                )
            }
        }
    }
}

/// A version-gated behavioral wrinkle keyroost has observed on some PIV
/// devices — distinct from [`PivExtension`]: an extension is "supported or
/// not", a quirk is "present and needs a workaround" regardless of support.
/// Carried on `VersionQuirks::quirks` and surfaced by [`resolve_quirks`].
/// Nothing in this crate acts on a resolved quirk yet — the workaround code
/// for each one lands separately.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PivQuirk {
    /// The serial number returned by the Yubico extension APDU GET SERIAL
    /// (`INS 0xF8`) is packed BCD encoded rather than a plain big-endian
    /// integer.
    InsF8SerialIsBcd,
    /// The algorithm identifier (tag `0x01`) in the Yubico extension APDU GET
    /// METADATA (`INS 0xF7`) response cannot be trusted on this device — at
    /// some point it stops reflecting the slot's actual key state and gets
    /// stuck, and it does not reliably recover (a factory reset of the
    /// applet has been observed to not restore reliable reporting on a unit
    /// that had already gone stale) — so it must always be ignored when this
    /// quirk is set, regardless of what value is read. Not necessarily wrong
    /// from the very first read: a device can answer correctly for a while
    /// (observed: a brand-new unit, then several key generations later) and
    /// still carry this quirk, since there's no known state a caller could
    /// use to tell "still reliable" apart from "already gone stale" — see
    /// `SWISSBIT_ISHIELD2_APPLET_QUIRKS`'s doc for the specific history
    /// that ruled out a version-gated floor.
    InsF7MetadataAlgorithmInvalid,
    /// GET METADATA (`INS 0xF7`) might report a PIN/touch policy (tag `0x02`,
    /// packing `(pin_policy, touch_policy)` — see [`crate::Metadata::policy`])
    /// on this device, but the returned values are either invalid/stuck/stale
    /// or malformed by other means — not a live reflection of what GENERATE
    /// ASYMMETRIC KEYPAIR actually set for the slot. A caller with this quirk
    /// set must ignore tag `0x02` entirely, the same "always ignore, never
    /// trust a lucky-looking value" rule [`Self::InsF7MetadataAlgorithmInvalid`]
    /// applies to the algorithm tag — kept as a separate variant because the
    /// two tags have been observed to fail independently: a device can report
    /// a stale algorithm while its policy tag is fine, or vice versa. Says
    /// nothing about whether GENERATE ASYMMETRIC KEYPAIR's own PIN/touch
    /// policy tags (`0xAA`/`0xAB`) are accepted — that's
    /// [`PivExtension::SlotPinPolicy`]/[`PivExtension::SlotTouchPolicy`]'s own
    /// [`resolve`] verdict, queried separately; a device can reject *setting*
    /// a non-default policy and still echo a (meaningless) tag `0x02` back on
    /// every GET METADATA call, which is exactly the case this quirk exists
    /// to name.
    InsF7MetadataPinTouchPolicyInvalid,
    /// [`PivExtension::Reset`] and [`PivExtension::ResetGlobal`] require
    /// an authenticated management-key session before it is accepted —
    /// e.g. HID Crescendo's own reset mechanism
    /// (<https://docs.hidglobal.com/crescendo/api/low-level/reset-card.htm>),
    /// implemented by `keyroost_transport::PivSession::factory_reset`.
    ///
    /// A fingerprint that does *not* carry this quirk only means RESET
    /// doesn't need an authenticated management-key session — it is *not* a
    /// promise that PIN/PUK blocking is required instead. The widespread
    /// YubiKey convention layers that precondition on top (`INS 0xFB`
    /// accepted with no management-key session at all, but only once the PIV
    /// PIN *and* PUK are both already blocked — every retry exhausted), and
    /// for a long time that was the only alternative keyroost had observed to
    /// this quirk's mechanism, but it isn't the only one: a live Token2
    /// applet at version 5.112.0 has been observed accepting `INS 0xFB`
    /// outright, with neither the PIN nor the PUK blocked and no
    /// authenticated session either (see `TOKEN2_APPLET_VERDICTS`'s
    /// doc) — so this quirk's absence really only
    /// answers "does RESET need management auth", not "what, if anything,
    /// RESET needs instead".
    ///
    /// `keyroost_transport::PivSession::force_reset` is written for exactly
    /// this uncertainty: it always tries a bare RESET first and only starts
    /// burning PIN/PUK retries if that bare attempt comes back
    /// `PivResetNotAllowed` (the YubiKey-style "blocked precondition" status
    /// words). On a device that accepts RESET unconditionally, like the
    /// Token2 unit above, the bare attempt already succeeds and nothing ever
    /// gets burned; on a device that actually enforces the blocked-PIN/PUK
    /// precondition, the bare attempt's refusal is what triggers the burn.
    /// Neither this quirk nor [`PivExtension::Reset`]'s verdict distinguishes
    /// the two cases up front — `force_reset` finds out empirically instead
    /// of assuming either one.
    ///
    /// **Safety constraint on that burn:** deliberately burning through PIN
    /// and PUK retries to unlock RESET must only ever run when
    /// [`PivExtension::Reset`] resolves [`FeatureGate::Supported`] — never
    /// [`FeatureGate::Unverified`]. A blocked-precondition refusal is only
    /// good evidence a burn will help when RESET is confirmed to exist on
    /// this device; doing it on a device where RESET support is merely
    /// unverified risks bricking it outright if `INS 0xFB` then turns out
    /// unsupported there — PIN and PUK both blocked with no working RESET is
    /// unrecoverable. [`FeatureGate::Unverified`] must fall back to a manual,
    /// user-driven PIN/PUK block (or simply refuse), same as any other
    /// unverified extension. `keyroost_transport::PivSession::plan_factory_reset`
    /// enforces this by resolving `FactoryResetPlan::Unverified` rather than
    /// `FactoryResetPlan::BurnPinPukThenReset` whenever the gate isn't
    /// [`FeatureGate::Supported`].
    ResetNeedsManagementAuth,
    /// This fingerprint (at the version the entry covers) ships with a
    /// well-known, publicly documented factory-default value for the
    /// standard PIV management key (key reference `0x9B`) — the raw key
    /// bytes are carried right on the variant, unlike every other
    /// [`PivQuirk`], because there's nothing else to derive them from.
    /// Deliberately a slice, not a fixed-size array: `0x9B`'s algorithm
    /// varies by fingerprint (and, on YubiKey, by firmware — 3-DES/AES-192
    /// are 24 bytes, but AES-128 is 16 and AES-256 is 32; see
    /// [`crate::MgmtAlg::key_len`]), so a caller must not assume any one
    /// length for this quirk's payload. A caller offering a "use the default
    /// management key" convenience reads this off [`resolve_quirks`] (via
    /// [`default_9b_management_key`]) and disables that convenience entirely
    /// when it's absent — an absent entry means keyroost has no known
    /// default for this fingerprint, not that the device has none; see each
    /// fingerprint's own applet-axis quirks const (e.g. `YUBIKEY_APPLET_QUIRKS`)
    /// for what's actually known.
    ///
    /// Five distinct values are seeded today, each shared by every
    /// fingerprint observed to ship it:
    /// * `01 02 03 04 05 06 07 08` repeated three times (24 bytes) — the
    ///   standard PIV default YubiKey documents
    ///   (<https://docs.yubico.com/software/yubikey/tools/authenticator/auth-guide/piv-certificates.html>)
    ///   and a wide range of third-party PIV implementations mimic outright,
    ///   not just genuine YubiKeys — including the Trussed `piv-authenticator`
    ///   (fingerprinted as [`AppletFingerprint::Trussed`]), whose
    ///   `constants.rs` hard-codes this exact value as
    ///   `DEFAULT_MANAGEMENT_KEY`
    ///   (<https://github.com/trussed-dev/piv-authenticator/blob/main/src/constants.rs>).
    /// * Token2's own vendor-specific value (24 bytes)
    ///   (<https://www.token2.com/pages/pin-firmware-feature-support-matrix-openpgp-fido2-otp-and-piv-across-releases>).
    /// * Feitian's own vendor-specific value (24 bytes)
    ///   (<https://fido.ftsafe.com/feitian-sk-manager-tool-user-manual/>).
    /// * HID Crescendo's documented all-zero factory-delivery value for XAUTH
    ///   key 1 (24 bytes, [`HID_CRESCENDO_ACA_FACTORY_XAUTH_KEY`]) — HID
    ///   Crescendo has no standard PIV management key at all (see
    ///   [`PivExtension::PinManagementAuth`]'s doc), but the same "well-known
    ///   default credential" convenience applies to its XAUTH key, so it's
    ///   seeded here too rather than duplicated through a parallel
    ///   mechanism; `keyroost_transport::PivSession`'s HID Crescendo reset
    ///   path reads this entry back to restore XAUTH key 1 after RESET CARD,
    ///   rather than hard-coding the constant a second time.
    /// * Identiv/Hirsch uTrust Gov's own vendor-specific value (16 bytes,
    ///   `IDPRIME_AND_UTRUST_GOV_DEFAULT_MGMT_KEY`) — distinct from the
    ///   YubiKey-mimicking value its sibling `UTrust::Generic` ships instead;
    ///   see [`UTrustVariant::Gov`]'s doc for the source. Also confirmed on
    ///   IdPrime hardware (a live unit's factory-default `0x9B` key,
    ///   algorithm AES-128 — hence the 16-byte length matching this value
    ///   rather than `YUBIKEY_DEFAULT_MGMT_KEY`'s 24) — hence the constant's
    ///   name naming both fingerprints rather than just the one it was
    ///   originally seeded for.
    ///
    /// Most seeded values happen to be 24 bytes, but that's a fact about
    /// what's been observed so far, not a constraint this variant enforces —
    /// `IDPRIME_AND_UTRUST_GOV_DEFAULT_MGMT_KEY` above is already only 16, and a future
    /// row for an AES-256 default must not need this type to change either.
    Default9bManagementKey(&'static [u8]),
    /// This fingerprint (at the version the entry covers) is known to take
    /// unusually long to complete [`PivExtension::Reset`] — observed at over
    /// a minute on `ArekinathPivApplet::SwissbitIShield1`
    /// (<https://github.com/swissbit-eis/PivApplet>). Says nothing about
    /// whether RESET is *supported* — that's still
    /// [`PivExtension::Reset`]'s own [`resolve`] verdict, queried
    /// separately — only that, when it is, a caller shouldn't mistake a slow
    /// device for a hung one. A caller that finds this quirk set (via
    /// [`resolve_quirks`]) should surface [`Self::RESET_LONG_RUNNING_HINT`]
    /// to the user before running RESET, worded identically wherever it's
    /// shown so the GUI and the CLI say the same thing.
    ResetLongRunning,
    /// [`PivExtension::Reset`] fails on this fingerprint if the standard PIV
    /// management key (`0x9B`) has been changed away from 3DES to an AES
    /// variant — it must be changed back to 3DES before RESET is attempted.
    /// This is a bug in every known version of `ArekinathPivApplet`, upstream
    /// and the Swissbit fork alike: its RESET handling unconditionally casts
    /// the `0x9B` key object to `DESKey`
    /// (<https://github.com/arekinath/PivApplet/blob/v0.9.0/src/net/cooperi/pivapplet/PivApplet.java#L2778>,
    /// tracked upstream as <https://github.com/arekinath/PivApplet/issues/78>),
    /// with no `else` branch for any other key type. When the stored key is
    /// actually an `AESKey` (SET MANAGEMENT KEY was used to switch algorithms
    /// — supported on this applet since major version 4, well before this
    /// quirk's own concern kicks in) that cast throws, and the exception
    /// surfaces to the client as a non-success status word rather than a
    /// completed reset.
    ///
    /// A caller that finds this quirk set (via [`resolve_quirks`]) must
    /// determine the card's current management-key algorithm first — the
    /// same way [`PivExtension::PinManagementAuth`]'s standard round does,
    /// via `keyroost_transport::PivSession::management_key_algorithm` — and
    /// abort with a clear error instead of sending RESET when that algorithm
    /// isn't [`crate::MgmtAlg::TripleDes`]; there's no on-card way to reset
    /// while leaving the AES key in place, so the recovery is to change the
    /// management key back to 3DES first and retry.
    ResetFailsIfManagementKeyIsAes,
    /// [`PivExtension::SlotPinPolicy`] is supported on this device in
    /// principle — GENERATE ASYMMETRIC KEYPAIR accepts the `0xAA` tag — but
    /// the specific `Once` value is rejected. A caller offering the PIN
    /// policy picker (GUI combo box, `keyroostctl piv generate-key
    /// --pin-policy`) disables/refuses just that one choice rather than
    /// dimming the whole control the way an [`PivExtension::SlotPinPolicy`]
    /// [`FeatureGate::Unsupported`] verdict would — every other value
    /// (`default`/`never`/`always`) is unaffected.
    SlotPinPolicyOnceNotSupported,
    /// [`PivExtension::SlotTouchPolicy`] is supported on this device in
    /// principle, but the specific `Cached` value is rejected — the touch
    /// counterpart of [`Self::SlotPinPolicyOnceNotSupported`], same narrow
    /// single-value scope and the same caller obligation (disable/refuse just
    /// `Cached`, leave `default`/`never`/`always` alone).
    SlotTouchPolicyCachedNotSupported,
    /// The card-to-host half of management-key mutual authentication (`0x9B`
    /// GENERAL AUTHENTICATE step 2 — see
    /// `keyroost_transport::PivSession::authenticate_management`) answers
    /// with the encrypted host challenge under the wrong tag on this device.
    /// SP 800-73-4 calls for `0x82`; observed hardware (IdPrime PIV Applet)
    /// instead echoes `0x80` — the witness tag from step 1 — while carrying
    /// the correct encrypted value underneath it. Hardware-observed via the
    /// trace this quirk was added from, not inferred from spec reading.
    ///
    /// A caller that finds this quirk set (via [`resolve_quirks`]) must
    /// parse that response permissively — [`crate::parse_general_auth_permissive`]
    /// instead of [`crate::parse_general_auth`] with a hardcoded `0x82` —
    /// accepting whichever tag the reply's single TLV element actually
    /// carries. Only safe when the reply holds exactly one TLV element: a
    /// response with more than one tag has no unambiguous "this one is the
    /// challenge response" answer, so [`crate::parse_general_auth_permissive`]
    /// still refuses to parse a multi-tag reply rather than guessing which
    /// tag is meant.
    HostChallengeResponsePermissiveTag,
}

impl PivQuirk {
    /// Shared wording for [`Self::ResetLongRunning`], reused verbatim by the
    /// GUI's PIV pane (Reset applet card) and `keyroostctl piv reset` so
    /// both surfaces warn in the same words rather than drifting apart.
    pub const RESET_LONG_RUNNING_HINT: &'static str = "This device is known to take a long \
        time to reset \u{2014} more than a minute is not unusual. Be patient; do not unplug \
        the device or abort.";
}

/// Extract the well-known factory-default management-key bytes from a
/// resolved quirk set, if [`PivQuirk::Default9bManagementKey`] is present in
/// it — [`resolve_quirks`]'s return value is the expected input. `None` means
/// keyroost has no known default for this fingerprint/version, the signal a
/// "use the default management key" UI convenience uses to disable itself.
/// The returned slice's length is whatever that fingerprint's management-key
/// algorithm actually takes (16/24/32 bytes) — never assume 24.
#[must_use]
pub fn default_9b_management_key(quirks: &BTreeSet<PivQuirk>) -> Option<&'static [u8]> {
    quirks.iter().find_map(|q| match q {
        PivQuirk::Default9bManagementKey(key) => Some(*key),
        _ => None,
    })
}

/// One or more extensions' shared known-support verdicts within one
/// fingerprint's applet-axis or firmware-axis table — e.g.
/// [`YUBIKEY_APPLET_VERDICTS`]. Carrying several extensions on one row is
/// semantically identical to one row per extension, each with the same
/// `verdicts` — it's purely a way to collapse rows that would otherwise
/// repeat the same verdicts verbatim for two or more extensions this
/// fingerprint happens to treat identically.
struct ExtensionVerdicts {
    /// The extension(s) these verdicts apply to — non-empty. More than one
    /// entry means this fingerprint's evidence doesn't distinguish between
    /// them: they were tested (or reasoned about) together and landed on the
    /// same verdict at every version, so there's nothing extension-specific
    /// left to say.
    extensions: &'static [PivExtension],
    /// This (fingerprint, extension-set) pair's per-version verdicts,
    /// **ascending by [`VersionVerdict::version`]** and non-empty.
    verdicts: &'static [VersionVerdict],
}

/// "At [`Self::version`] (and, until the next one, above it) the extension's
/// verdict is [`Self::verdict`]." Versions are compared as plain byte slices,
/// the same ordering `keyroost_transport::PivStatus::version` uses elsewhere
/// (`[] < [5, 7] < [5, 7, 0] < [5, 8]`).
struct VersionVerdict {
    version: &'static [u8],
    verdict: Verdict,
}

/// One recorded known-support verdict, carried by a [`VersionVerdict`].
// The shared `Known` prefix is deliberate, not accidental redundancy: it
// groups these three as one family at a glance (in a match arm, in
// autocomplete, in this enum's own listing) — see each variant's doc for how
// they differ.
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// Extension known to be supported at this version (and, by the
    /// no-regression assumption in [`resolve`], at every later one until a
    /// contrary verdict). Says nothing about versions *before* it.
    KnownSupported,
    /// Extension known to be unsupported at this version, and — in the
    /// absence of a later verdict on the same row — assumed to have been
    /// unsupported at every earlier, untested version too (the backward
    /// mirror of [`Self::KnownSupported`]'s forward, no-regression
    /// assumption). Unlike [`Self::KnownUnsupportedSince`], this one
    /// *doesn't* extend forward past itself: a version newer than every
    /// verdict on the row softens to [`FeatureGate::Unverified`], since a
    /// later firmware may simply have added the extension.
    KnownUnsupported,
    /// Extension known to be unsupported at this version, and — the mirror
    /// image of [`Self::KnownSupported`]'s extension direction rather than
    /// [`Self::KnownUnsupported`]'s — assumed to *stay* unsupported at every
    /// later, untested version too, with no softening to
    /// [`FeatureGate::Unverified`] the way [`Self::KnownUnsupported`] gets.
    /// Says nothing about versions *before* it: an earlier version might
    /// have supported the extension, e.g. a vendor SDK generation that
    /// implemented it before a later architectural pivot away from it.
    ///
    /// For a case where merely "no verdict this old has flipped yet" isn't
    /// the reasoning — where there's a specific, standing reason to expect
    /// the vendor never will: a vendor with a track record of never
    /// mimicking Yubico's extension APDUs, instead consistently building its
    /// own proprietary alternatives, is unlikely to start mimicking Yubico
    /// now. That's a bet about the vendor's whole pattern of behavior, not
    /// just an absence observed on one firmware, so use this instead of
    /// [`Self::KnownUnsupported`] for it — see e.g. HID Crescendo's
    /// [`PivExtension::GetMetadata`]/[`PivExtension::Attest`] rows in
    /// `HID_CRESCENDO_C2300_APPLET_VERDICTS`, which apply this reasoning
    /// to a vendor that has never implemented *any* Yubico extension APDU
    /// and instead ships its own (ACA XAUTH in place of `GENERAL
    /// AUTHENTICATE` on `0x9B`, GET PIV PROPERTIES in place of GET
    /// METADATA). Use [`Self::KnownUnsupported`] instead for an ordinary "no
    /// evidence either way yet" gap.
    KnownUnsupportedSince,
}

/// "At [`Self::version`] (and, until a later entry, above it) these quirks
/// are active." Same version-ordering convention as [`VersionVerdict`], but
/// purely additive: there's no known-supported/known-unsupported state, so a quirk
/// entry can never suppress a quirk an earlier entry already reported.
struct VersionQuirks {
    version: &'static [u8],
    quirks: &'static [PivQuirk],
}

/// Which cross-axis merge policy [`resolve`]/[`resolve_quirks`] uses to
/// combine a fingerprint's applet-version-axis and firmware-version-axis
/// results into one, selected per fingerprint via `axis_merge_mode` rather
/// than hard-coded once for every fingerprint — a knob for a future
/// fingerprint that needs a different reconciliation policy than today's
/// uniform default, exactly as [`PivQuirk`] is a per-fingerprint knob rather
/// than a single global behavior.
///
/// Every fingerprint is seeded on [`Self::MergeRelaxed`] today (see each
/// `_AXIS_MERGE_MODE` const, one per fingerprint group). **This has no
/// observable effect on any resolved verdict or quirk right now:** no
/// fingerprint reports genuinely conflicting data on both axes for the same
/// extension. The one fingerprint with real verdict data on both axes,
/// `Trussed(NitroKey)`, has its applet-axis and firmware-axis rows agree
/// wherever both have an opinion (see `TRUSSED_NITROKEY_APPLET_VERDICTS`'s
/// doc) — so [`Self::MergeRelaxed`] and [`Self::MergeStrict`] resolve
/// identically for it, and [`Self::AppletWins`]/[`Self::FirmwareWins`]'s
/// tie-break never triggers for it either, since there's no conflict to
/// break. This mode selection exists so a fingerprint that starts reporting
/// two genuinely divergent axis values has somewhere to declare how they
/// reconcile, without [`resolve`]/[`resolve_quirks`] needing new logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AxisMergeMode {
    /// Verdicts: a real verdict ([`FeatureGate::Supported`]/
    /// [`FeatureGate::Unsupported`]) on one axis wins over
    /// [`FeatureGate::Unverified`] on the other; two real but *conflicting*
    /// verdicts (one `Supported`, the other `Unsupported`) soften to
    /// `Unverified` instead of either winning outright — see
    /// `combine_relaxed`. Quirks: unioned, identical to
    /// [`Self::MergeStrict`] — this mode only changes verdict combination.
    MergeRelaxed,
    /// Verdicts: [`FeatureGate::Unsupported`] on either axis wins outright,
    /// even against [`FeatureGate::Supported`] on the other — see
    /// `combine_strict`. Quirks: unioned, identical to
    /// [`Self::MergeRelaxed`].
    MergeStrict,
    /// Verdicts: a real verdict wins over [`FeatureGate::Unverified`] on the
    /// other axis, same as [`Self::MergeRelaxed`] — but when *both* axes
    /// carry a real verdict and they genuinely conflict, the applet axis's
    /// own verdict wins outright instead of softening to `Unverified` — see
    /// `combine_preferring`. Quirks: when both an applet version and a
    /// firmware version were reported, the applet axis's quirks entry
    /// replaces the union outright (the firmware axis's entry for that
    /// version is dropped); when only one axis (or neither) reported a
    /// version, quirks still union normally, same as every other mode.
    AppletWins,
    /// Mirror image of [`Self::AppletWins`] for both verdicts and quirks:
    /// the firmware axis's verdict wins a genuine conflict, and the
    /// firmware axis's quirks entry replaces the union when both versions
    /// were reported.
    FirmwareWins,
}

/// The commonly-mimicked YubiKey PIV factory-default management key: 24
/// bytes of `01 02 03 04 05 06 07 08` repeated three times (3-DES /
/// AES-192) —
/// <https://docs.yubico.com/software/yubikey/tools/authenticator/auth-guide/piv-certificates.html>.
/// Seeded on [`PivQuirk::Default9bManagementKey`] for every fingerprint known
/// to ship this exact value, genuine YubiKeys and third-party mimics alike —
/// see that variant's doc.
const YUBIKEY_DEFAULT_MGMT_KEY: &[u8] = &[
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
];

/// Token2's own vendor-specific PIV factory-default management key —
/// <https://www.token2.com/pages/pin-firmware-feature-support-matrix-openpgp-fido2-otp-and-piv-across-releases>.
const TOKEN2_DEFAULT_MGMT_KEY: &[u8] = &[
    0x86, 0x53, 0x62, 0x86, 0x53, 0x62, 0x86, 0x53, 0x62, 0x86, 0x53, 0x62, 0x86, 0x53, 0x62, 0x86,
    0x53, 0x62, 0x86, 0x53, 0x62, 0x86, 0x53, 0x62,
];

/// Feitian's own vendor-specific PIV factory-default management key — ASCII
/// `"12345678"` repeated three times —
/// <https://fido.ftsafe.com/feitian-sk-manager-tool-user-manual/>.
const FEITIAN_DEFAULT_MGMT_KEY: &[u8] = &[
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
];

/// Identiv/Hirsch uTrust Gov's own vendor-specific PIV factory-default
/// management key — half `YUBIKEY_DEFAULT_MGMT_KEY`'s length (16 bytes,
/// the `0x01..=0x08` pattern repeated twice rather than three times), so
/// `UTrust::Gov` does *not* mimic the YubiKey default the way `UTrust::Generic`
/// does — <https://hirschsecure.atlassian.net/wiki/spaces/FIDO/pages/4395401218/PIV>.
const IDPRIME_AND_UTRUST_GOV_DEFAULT_MGMT_KEY: &[u8] = &[
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
];

/// This fingerprint's known-support verdicts for `extension`, keyed by the
/// PIV **applet's own** version (Yubico's `GET VERSION` extension reply, or —
/// for HID Crescendo — the version its own GET PIV PROPERTIES query reports).
/// Dispatches to one const table per fingerprint (see each table's own doc
/// for its data and reasoning) and looks `extension` up within it. `None`
/// means keyroost has no applet-version data for this (fingerprint,
/// extension) pair — either the fingerprint has no table at all, or its
/// table has no entry for `extension` — and [`resolve`] treats that axis as
/// [`FeatureGate::Unverified`] for it.
#[must_use]
fn applet_verdicts(
    fingerprint: AppletFingerprint,
    extension: PivExtension,
) -> Option<&'static [VersionVerdict]> {
    find_verdicts(
        match fingerprint {
            AppletFingerprint::YubiKey => YUBIKEY_APPLET_VERDICTS,
            AppletFingerprint::Token2 => TOKEN2_APPLET_VERDICTS,
            AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2) => {
                SWISSBIT_ISHIELD2_APPLET_VERDICTS
            }
            AppletFingerprint::OpenFips201(OpenFips201Variant::Generic) => {
                OPENFIPS201_GENERIC_APPLET_VERDICTS
            }
            AppletFingerprint::Thetis => THETIS_APPLET_VERDICTS,
            AppletFingerprint::ArekinathPivApplet(ArekinathVariant::Generic) => {
                AREKINATH_GENERIC_APPLET_VERDICTS
            }
            AppletFingerprint::ArekinathPivApplet(ArekinathVariant::SwissbitIShield1) => {
                AREKINATH_SWISSBIT_ISHIELD1_APPLET_VERDICTS
            }
            AppletFingerprint::HidCrescendo(HidCrescendoVariant::C2300) => {
                HID_CRESCENDO_C2300_APPLET_VERDICTS
            }
            AppletFingerprint::HidCrescendo(HidCrescendoVariant::C4000) => {
                HID_CRESCENDO_C4000_APPLET_VERDICTS
            }
            AppletFingerprint::HidCrescendo(HidCrescendoVariant::Generic) => {
                HID_CRESCENDO_GENERIC_APPLET_VERDICTS
            }
            AppletFingerprint::Generic => GENERIC_APPLET_VERDICTS,
            AppletFingerprint::AuthentrendATKey => AUTHENTREND_ATKEY_APPLET_VERDICTS,
            AppletFingerprint::Feitian => FEITIAN_APPLET_VERDICTS,
            AppletFingerprint::IdPrime => IDPRIME_APPLET_VERDICTS,
            AppletFingerprint::Trussed(TrussedVariant::NitroKey) => {
                TRUSSED_NITROKEY_APPLET_VERDICTS
            }
            AppletFingerprint::UTrust(UTrustVariant::Generic) => UTRUST_GENERIC_APPLET_VERDICTS,
            AppletFingerprint::UTrust(UTrustVariant::Gov) => UTRUST_GOV_APPLET_VERDICTS,
        },
        extension,
    )
}

/// Same lookup as `applet_verdicts`, against each fingerprint's
/// **firmware**-version table instead — e.g. [`YUBIKEY_FIRMWARE_VERDICTS`].
/// Every one of those tables is empty except
/// [`TRUSSED_NITROKEY_FIRMWARE_VERDICTS`] (see its own doc for the data it
/// carries and why): no other fingerprint has firmware-version data for any
/// extension yet (HID Crescendo's GET PIV PROPERTIES version is an *applet*
/// version, not a firmware one — see `HID_CRESCENDO_C2300_APPLET_VERDICTS`'s
/// doc).
#[must_use]
fn firmware_verdicts(
    fingerprint: AppletFingerprint,
    extension: PivExtension,
) -> Option<&'static [VersionVerdict]> {
    find_verdicts(
        match fingerprint {
            AppletFingerprint::YubiKey => YUBIKEY_FIRMWARE_VERDICTS,
            AppletFingerprint::Token2 => TOKEN2_FIRMWARE_VERDICTS,
            AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2) => {
                SWISSBIT_ISHIELD2_FIRMWARE_VERDICTS
            }
            AppletFingerprint::OpenFips201(OpenFips201Variant::Generic) => {
                OPENFIPS201_GENERIC_FIRMWARE_VERDICTS
            }
            AppletFingerprint::Thetis => THETIS_FIRMWARE_VERDICTS,
            AppletFingerprint::ArekinathPivApplet(ArekinathVariant::Generic) => {
                AREKINATH_GENERIC_FIRMWARE_VERDICTS
            }
            AppletFingerprint::ArekinathPivApplet(ArekinathVariant::SwissbitIShield1) => {
                AREKINATH_SWISSBIT_ISHIELD1_FIRMWARE_VERDICTS
            }
            AppletFingerprint::HidCrescendo(HidCrescendoVariant::C2300) => {
                HID_CRESCENDO_C2300_FIRMWARE_VERDICTS
            }
            AppletFingerprint::HidCrescendo(HidCrescendoVariant::C4000) => {
                HID_CRESCENDO_C4000_FIRMWARE_VERDICTS
            }
            AppletFingerprint::HidCrescendo(HidCrescendoVariant::Generic) => {
                HID_CRESCENDO_GENERIC_FIRMWARE_VERDICTS
            }
            AppletFingerprint::Generic => GENERIC_FIRMWARE_VERDICTS,
            AppletFingerprint::AuthentrendATKey => AUTHENTREND_ATKEY_FIRMWARE_VERDICTS,
            AppletFingerprint::Feitian => FEITIAN_FIRMWARE_VERDICTS,
            AppletFingerprint::IdPrime => IDPRIME_FIRMWARE_VERDICTS,
            AppletFingerprint::Trussed(TrussedVariant::NitroKey) => {
                TRUSSED_NITROKEY_FIRMWARE_VERDICTS
            }
            AppletFingerprint::UTrust(UTrustVariant::Generic) => UTRUST_GENERIC_FIRMWARE_VERDICTS,
            AppletFingerprint::UTrust(UTrustVariant::Gov) => UTRUST_GOV_FIRMWARE_VERDICTS,
        },
        extension,
    )
}

/// Shared lookup backing `applet_verdicts`/`firmware_verdicts`: find
/// `extension`'s entry within one fingerprint's already-selected table —
/// `extension` may be listed alongside others on the same row, per
/// [`ExtensionVerdicts::extensions`].
#[must_use]
fn find_verdicts(
    table: &'static [ExtensionVerdicts],
    extension: PivExtension,
) -> Option<&'static [VersionVerdict]> {
    table
        .iter()
        .find(|e| e.extensions.contains(&extension))
        .map(|e| e.verdicts)
}

/// This fingerprint's active [`PivQuirk`]s, keyed by the PIV **applet's own**
/// version. Dispatches to one const per fingerprint (see each const's own
/// doc for its data and reasoning) and returns it outright — unlike
/// `applet_verdicts`/`firmware_verdicts`, there's no extension axis to
/// look up within it, since a quirk applies to the fingerprint/version as a
/// whole (see [`PivQuirk`]'s own doc). A fingerprint with no data at all
/// (today: [`AppletFingerprint::IdPrime`] and
/// `AppletFingerprint::OpenFips201(`[`OpenFips201Variant::Generic`]`)`)
/// still gets its own const — [`IDPRIME_APPLET_QUIRKS`]/
/// [`OPENFIPS201_GENERIC_APPLET_QUIRKS`] — just an empty one, the same as an
/// unpopulated firmware-axis const.
#[must_use]
fn applet_quirks(fingerprint: AppletFingerprint) -> &'static [VersionQuirks] {
    match fingerprint {
        AppletFingerprint::YubiKey => YUBIKEY_APPLET_QUIRKS,
        AppletFingerprint::Token2 => TOKEN2_APPLET_QUIRKS,
        AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2) => {
            SWISSBIT_ISHIELD2_APPLET_QUIRKS
        }
        AppletFingerprint::OpenFips201(OpenFips201Variant::Generic) => {
            OPENFIPS201_GENERIC_APPLET_QUIRKS
        }
        AppletFingerprint::Thetis => THETIS_APPLET_QUIRKS,
        AppletFingerprint::ArekinathPivApplet(ArekinathVariant::Generic) => {
            AREKINATH_GENERIC_APPLET_QUIRKS
        }
        AppletFingerprint::ArekinathPivApplet(ArekinathVariant::SwissbitIShield1) => {
            AREKINATH_SWISSBIT_ISHIELD1_APPLET_QUIRKS
        }
        AppletFingerprint::HidCrescendo(HidCrescendoVariant::C2300) => {
            HID_CRESCENDO_C2300_APPLET_QUIRKS
        }
        AppletFingerprint::HidCrescendo(HidCrescendoVariant::C4000) => {
            HID_CRESCENDO_C4000_APPLET_QUIRKS
        }
        AppletFingerprint::HidCrescendo(HidCrescendoVariant::Generic) => {
            HID_CRESCENDO_GENERIC_APPLET_QUIRKS
        }
        AppletFingerprint::Generic => GENERIC_APPLET_QUIRKS,
        AppletFingerprint::AuthentrendATKey => AUTHENTREND_ATKEY_APPLET_QUIRKS,
        AppletFingerprint::Feitian => FEITIAN_APPLET_QUIRKS,
        AppletFingerprint::IdPrime => IDPRIME_APPLET_QUIRKS,
        AppletFingerprint::Trussed(TrussedVariant::NitroKey) => TRUSSED_NITROKEY_APPLET_QUIRKS,
        AppletFingerprint::UTrust(UTrustVariant::Generic) => UTRUST_GENERIC_APPLET_QUIRKS,
        AppletFingerprint::UTrust(UTrustVariant::Gov) => UTRUST_GOV_APPLET_QUIRKS,
    }
}

/// Same lookup as `applet_quirks`, against each fingerprint's **firmware**
/// axis instead — e.g. [`YUBIKEY_FIRMWARE_QUIRKS`]. Every one of those
/// consts is empty today: no fingerprint has firmware-version-gated quirk
/// data yet.
#[must_use]
fn firmware_quirks(fingerprint: AppletFingerprint) -> &'static [VersionQuirks] {
    match fingerprint {
        AppletFingerprint::YubiKey => YUBIKEY_FIRMWARE_QUIRKS,
        AppletFingerprint::Token2 => TOKEN2_FIRMWARE_QUIRKS,
        AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2) => {
            SWISSBIT_ISHIELD2_FIRMWARE_QUIRKS
        }
        AppletFingerprint::OpenFips201(OpenFips201Variant::Generic) => {
            OPENFIPS201_GENERIC_FIRMWARE_QUIRKS
        }
        AppletFingerprint::Thetis => THETIS_FIRMWARE_QUIRKS,
        AppletFingerprint::ArekinathPivApplet(ArekinathVariant::Generic) => {
            AREKINATH_GENERIC_FIRMWARE_QUIRKS
        }
        AppletFingerprint::ArekinathPivApplet(ArekinathVariant::SwissbitIShield1) => {
            AREKINATH_SWISSBIT_ISHIELD1_FIRMWARE_QUIRKS
        }
        AppletFingerprint::HidCrescendo(HidCrescendoVariant::C2300) => {
            HID_CRESCENDO_C2300_FIRMWARE_QUIRKS
        }
        AppletFingerprint::HidCrescendo(HidCrescendoVariant::C4000) => {
            HID_CRESCENDO_C4000_FIRMWARE_QUIRKS
        }
        AppletFingerprint::HidCrescendo(HidCrescendoVariant::Generic) => {
            HID_CRESCENDO_GENERIC_FIRMWARE_QUIRKS
        }
        AppletFingerprint::Generic => GENERIC_FIRMWARE_QUIRKS,
        AppletFingerprint::AuthentrendATKey => AUTHENTREND_ATKEY_FIRMWARE_QUIRKS,
        AppletFingerprint::Feitian => FEITIAN_FIRMWARE_QUIRKS,
        AppletFingerprint::IdPrime => IDPRIME_FIRMWARE_QUIRKS,
        AppletFingerprint::Trussed(TrussedVariant::NitroKey) => TRUSSED_NITROKEY_FIRMWARE_QUIRKS,
        AppletFingerprint::UTrust(UTrustVariant::Generic) => UTRUST_GENERIC_FIRMWARE_QUIRKS,
        AppletFingerprint::UTrust(UTrustVariant::Gov) => UTRUST_GOV_FIRMWARE_QUIRKS,
    }
}

/// `fingerprint`'s selected [`AxisMergeMode`] — dispatches to one const per
/// fingerprint (see each const's own doc), the same shape as
/// `applet_quirks`/`firmware_quirks` above.
#[must_use]
fn axis_merge_mode(fingerprint: AppletFingerprint) -> AxisMergeMode {
    match fingerprint {
        AppletFingerprint::YubiKey => YUBIKEY_AXIS_MERGE_MODE,
        AppletFingerprint::Token2 => TOKEN2_AXIS_MERGE_MODE,
        AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2) => {
            SWISSBIT_ISHIELD2_AXIS_MERGE_MODE
        }
        AppletFingerprint::OpenFips201(OpenFips201Variant::Generic) => {
            OPENFIPS201_GENERIC_AXIS_MERGE_MODE
        }
        AppletFingerprint::Thetis => THETIS_AXIS_MERGE_MODE,
        AppletFingerprint::ArekinathPivApplet(ArekinathVariant::Generic) => {
            AREKINATH_GENERIC_AXIS_MERGE_MODE
        }
        AppletFingerprint::ArekinathPivApplet(ArekinathVariant::SwissbitIShield1) => {
            AREKINATH_SWISSBIT_ISHIELD1_AXIS_MERGE_MODE
        }
        AppletFingerprint::HidCrescendo(HidCrescendoVariant::C2300) => {
            HID_CRESCENDO_C2300_AXIS_MERGE_MODE
        }
        AppletFingerprint::HidCrescendo(HidCrescendoVariant::C4000) => {
            HID_CRESCENDO_C4000_AXIS_MERGE_MODE
        }
        AppletFingerprint::HidCrescendo(HidCrescendoVariant::Generic) => {
            HID_CRESCENDO_GENERIC_AXIS_MERGE_MODE
        }
        AppletFingerprint::Generic => GENERIC_AXIS_MERGE_MODE,
        AppletFingerprint::AuthentrendATKey => AUTHENTREND_ATKEY_AXIS_MERGE_MODE,
        AppletFingerprint::Feitian => FEITIAN_AXIS_MERGE_MODE,
        AppletFingerprint::IdPrime => IDPRIME_AXIS_MERGE_MODE,
        AppletFingerprint::Trussed(TrussedVariant::NitroKey) => TRUSSED_NITROKEY_AXIS_MERGE_MODE,
        AppletFingerprint::UTrust(UTrustVariant::Generic) => UTRUST_GENERIC_AXIS_MERGE_MODE,
        AppletFingerprint::UTrust(UTrustVariant::Gov) => UTRUST_GOV_AXIS_MERGE_MODE,
    }
}

// --- Per-device tables ---------------------------------------------------
//
// Five consts per fingerprint below, always in the same order — the
// fingerprint's `AxisMergeMode` selection, applet-axis known-support
// verdicts, firmware-axis known-support verdicts, applet-axis quirks, then
// firmware-axis quirks — so a device's complete data set sits together as
// one block, rather than being split across separate axis-at-a-time or
// verdicts/quirks-at-a-time tables. Looked up through `axis_merge_mode`
// (merge mode), `applet_verdicts`/`firmware_verdicts` (verdicts), and
// `applet_quirks`/`firmware_quirks` (quirks) — see each function's own doc
// for its axis' lookup semantics.
//
// Every firmware-axis quirks const is empty today: no fingerprint has
// firmware-version-gated quirk data yet. On the verdicts side,
// `TRUSSED_NITROKEY_FIRMWARE_VERDICTS` is the one exception — see its own
// doc — every other firmware-axis verdicts const is empty for the same
// reason as the quirks (HID Crescendo's GET PIV PROPERTIES version is an
// *applet* version — see `HID_CRESCENDO_C2300_APPLET_VERDICTS`'s doc — not a
// firmware one).
//
// `PivQuirk::Default9bManagementKey` entries deliberately repeat the quirk
// on every `VersionQuirks` entry of a quirks const that has more than one:
// per `latest_quirks`, entries don't accumulate with each other, only across
// the applet/firmware axes, so a version-gated const that only listed the
// default key on its earliest entry would lose it again once a later entry
// (e.g. one clearing an unrelated, actually version-gated quirk) takes over.
// The default management key itself is not known to be version-gated for
// any seeded fingerprint, so it's simply carried on every entry of a const
// instead of modeling a fourth axis for it.

/// YubiKey's cross-axis merge mode — see [`AxisMergeMode`]'s doc.
const YUBIKEY_AXIS_MERGE_MODE: AxisMergeMode = AxisMergeMode::MergeRelaxed;

/// YubiKey's applet-axis known-support table:
///
/// * [`PivExtension::MoveKey`]/[`PivExtension::DeleteKey`]/
///   [`PivExtension::SlotKeyAlgorithm`]`(`[`KeyAlg::Rsa3072`]/[`KeyAlg::Rsa4096`]/
///   [`KeyAlg::Ed25519`]/[`KeyAlg::X25519`]`)` — share one row: all six shipped
///   together in firmware 5.7 (the key-management extensions per Yubico's own
///   changelog; the four algorithms as the firmware generation that widened
///   PIV's key types), unsupported at every earlier version, supported from
///   5.7 on. The
///   empty-slice version on the known-unsupported verdict is a "from the very
///   first version" sentinel — it orders below every real version
///   (`[] < [5, 7]`), so that verdict is the one that applies to anything
///   older than 5.7. This sentinel is load-bearing and not implied by
///   [`resolve_in`]'s backward-extension rule: the verdict *above* it is a
///   known-supported verdict (`[5, 7]`), not known-unsupported, and a
///   known-supported verdict says nothing about versions before it.
/// * [`PivExtension::Attest`] — shipped in firmware 4.3
///   (<https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html>:
///   "Only available in YubiKey 4.3 & 5"): same two-tier shape as the row
///   above — a known-unsupported verdict at the `[]` sentinel and a
///   known-supported verdict at `[4, 3]`.
/// * [`PivExtension::GetMetadata`] — shipped in firmware 5.3 (same reference:
///   "Only available in YubiKey 5.3"), same shape again with the
///   known-supported verdict at `[5, 3]` instead.
/// * [`PivExtension::PinManagementAuth`] — `Verdict::KnownSupported` from
///   applet version 3 on. This is the *indirect* scheme on YubiKey: a caller
///   still has to read the PIN-protected management key back and run the
///   standard `0x9B` round with it — see [`PivExtension::PinManagementAuth`]'s
///   own doc.
/// * [`PivExtension::Reset`]/[`PivExtension::SetPinPukRetries`]/
///   [`PivExtension::SetManagementKey`]/[`PivExtension::SlotKeyAlgorithm`]`(`
///   [`KeyAlg::Rsa1024`]/[`KeyAlg::Rsa2048`]/[`KeyAlg::EccP256`]/
///   [`KeyAlg::EccP384`]`)` — share one row: RESET (`INS 0xFB`), SET PIN
///   RETRIES (per
///   <https://docs.yubico.com/yesdk/users-manual/application-piv/commands.html#set-pin-retries>,
///   "All YubiKeys with the PIV application."), and SET MANAGEMENT KEY as
///   core key management have all been supported by every YubiKey PIV
///   implementation observed, exactly like the two SP 800-73-4-standardized
///   algorithm pairs. So this is a single `Verdict::KnownSupported` at the
///   universal `[]` version, no known-unsupported floor to gate below it —
///   unlike the MOVE KEY/DELETE KEY/RSA-4096/Ed25519/X25519 row above, none
///   of these seven arrived in a specific later firmware. YubiKey carries no
///   [`PivQuirk::ResetNeedsManagementAuth`] entry on `YUBIKEY_APPLET_QUIRKS`
///   either: "supported" for RESET here means the card accepts the
///   instruction, not that it accepts it unconditionally — the precondition
///   (PIN *and* PUK both already blocked) is exactly what that quirk's
///   absence signals, per its own doc.
/// * [`PivExtension::ResetGlobal`]/[`PivExtension::SlotKeyAlgorithm`]`(`
///   [`KeyAlg::EccP521`]`)` — share one row: `Verdict::KnownUnsupportedSince`
///   at the universal `[]` version. RESET GLOBAL is the same verdict every
///   other non-HID-Crescendo fingerprint's table gives it — see e.g.
///   `GENERIC_APPLET_VERDICTS`'s doc for why. ECC P-521 is the one
///   algorithm no YubiKey firmware generation has ever added — unlike the
///   5.7 trio above, there's no expectation a future firmware brings it, so
///   it gets the "stays unsupported" verdict rather than the two-tier shape.
/// * [`PivExtension::SlotPinPolicy`]/[`PivExtension::SlotTouchPolicy`] —
///   `Verdict::KnownSupported` at applet major version `[4]`
///   (<https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html>),
///   no known-unsupported floor to gate below — like the RESET/SET PIN
///   RETRIES/SET MANAGEMENT KEY row above, these predate the 5.x lineage the
///   MOVE KEY/DELETE KEY/ATTEST/GET METADATA rows are anchored to. See
///   `YUBIKEY_APPLET_QUIRKS` for the touch-policy `Cached` value's own
///   narrower gate at this same version.
/// * No entry for [`PivExtension::GetSlotKeyStatus`] — falls through to
///   [`PivExtension::GetMetadata`]'s own verdict above, per [`resolve`]'s
///   special case.
const YUBIKEY_APPLET_VERDICTS: &[ExtensionVerdicts] = &[
    ExtensionVerdicts {
        extensions: &[
            PivExtension::MoveKey,
            PivExtension::DeleteKey,
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa3072),
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa4096),
            PivExtension::SlotKeyAlgorithm(KeyAlg::Ed25519),
            PivExtension::SlotKeyAlgorithm(KeyAlg::X25519),
        ],
        verdicts: &[
            VersionVerdict {
                version: &[],
                verdict: Verdict::KnownUnsupported,
            },
            VersionVerdict {
                version: &[5, 7],
                verdict: Verdict::KnownSupported,
            },
        ],
    },
    ExtensionVerdicts {
        extensions: &[PivExtension::Attest],
        verdicts: &[
            VersionVerdict {
                version: &[],
                verdict: Verdict::KnownUnsupported,
            },
            VersionVerdict {
                version: &[4, 3],
                verdict: Verdict::KnownSupported,
            },
        ],
    },
    ExtensionVerdicts {
        extensions: &[PivExtension::GetMetadata],
        verdicts: &[
            VersionVerdict {
                version: &[],
                verdict: Verdict::KnownUnsupported,
            },
            VersionVerdict {
                version: &[5, 3],
                verdict: Verdict::KnownSupported,
            },
        ],
    },
    ExtensionVerdicts {
        extensions: &[PivExtension::PinManagementAuth],
        verdicts: &[VersionVerdict {
            version: &[3],
            verdict: Verdict::KnownSupported,
        }],
    },
    // `PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::{TripleDes,Aes128,
    // Aes192,Aes256})` joins this row: every YubiKey firmware generation
    // observed accepts all four as the management key's algorithm too, same
    // universal `[]` `Verdict::KnownSupported` as RESET/SET PIN RETRIES/SET
    // MANAGEMENT KEY.
    ExtensionVerdicts {
        extensions: &[
            PivExtension::Reset,
            PivExtension::SetPinPukRetries,
            PivExtension::SetManagementKey,
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa1024),
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa2048),
            PivExtension::SlotKeyAlgorithm(KeyAlg::EccP256),
            PivExtension::SlotKeyAlgorithm(KeyAlg::EccP384),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::TripleDes),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Aes128),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Aes192),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Aes256),
        ],
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownSupported,
        }],
    },
    // `PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Delete)` joins
    // this row: no standard PIV equivalent, since YubiKey's management key
    // is mandatory and never removable, same universal `[]`
    // `Verdict::KnownUnsupportedSince` as RESET GLOBAL/ECC P-521.
    ExtensionVerdicts {
        extensions: &[
            PivExtension::ResetGlobal,
            PivExtension::SlotKeyAlgorithm(KeyAlg::EccP521),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Delete),
        ],
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownUnsupportedSince,
        }],
    },
    ExtensionVerdicts {
        extensions: &[PivExtension::SlotPinPolicy, PivExtension::SlotTouchPolicy],
        verdicts: &[VersionVerdict {
            version: &[4],
            verdict: Verdict::KnownSupported,
        }],
    },
];

/// YubiKey's firmware-axis known-support verdicts — empty: YubiKey has no
/// firmware-version data for any extension yet (HID Crescendo's GET PIV
/// PROPERTIES version is an *applet* version — see
/// `HID_CRESCENDO_C2300_APPLET_VERDICTS`'s doc — not a firmware one). Every
/// other `_FIRMWARE_VERDICTS` const below is empty for the same reason,
/// except [`TRUSSED_NITROKEY_FIRMWARE_VERDICTS`] — see its own doc for the
/// data it carries.
const YUBIKEY_FIRMWARE_VERDICTS: &[ExtensionVerdicts] = &[];

/// YubiKey's applet-axis quirks. YubiKey carries no
/// [`PivQuirk::ResetNeedsManagementAuth`] entry at all — its absence is
/// exactly how a caller learns RESET follows the PIN/PUK-blocked convention
/// instead; see that quirk's doc. The default-management-key quirk isn't
/// gated on any version split — it's repeated on every entry so it applies
/// at every applet version.
///
/// The `[3]` entry also carries [`PivQuirk::SlotTouchPolicyCachedNotSupported`],
/// even though touch policy itself
/// ([`YUBIKEY_APPLET_VERDICTS`]'s [`PivExtension::SlotTouchPolicy`] row) only
/// goes known-supported at applet version 4, one entry up — that extension
/// verdict is the real guard a caller checks first, so a quirk that merely
/// narrows one *value* within it is inert wherever the extension itself
/// isn't `Supported` yet. Placing it here instead of on its own `[4]` entry
/// just avoids a second entry that would otherwise be identical to this one;
/// it takes effect the moment [`PivExtension::SlotTouchPolicy`] does, at `[4]`,
/// same as if it had its own entry there. The `[4, 3]` entry drops it again —
/// the `Cached` value specifically isn't accepted until firmware 4.3
/// (<https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html>) —
/// which is the entry's only reason to exist: its quirk list is otherwise
/// identical to the `[]` entry's, but [`latest_quirks`] takes one entry's
/// quirk list as-is rather than accumulating across entries on the same
/// axis, so a version boundary that merely *drops* a quirk still needs its
/// own entry to do that.
const YUBIKEY_APPLET_QUIRKS: &[VersionQuirks] = &[
    VersionQuirks {
        version: &[],
        quirks: &[PivQuirk::Default9bManagementKey(YUBIKEY_DEFAULT_MGMT_KEY)],
    },
    VersionQuirks {
        version: &[3],
        quirks: &[
            PivQuirk::Default9bManagementKey(YUBIKEY_DEFAULT_MGMT_KEY),
            PivQuirk::SlotTouchPolicyCachedNotSupported,
        ],
    },
    VersionQuirks {
        version: &[4, 3],
        quirks: &[PivQuirk::Default9bManagementKey(YUBIKEY_DEFAULT_MGMT_KEY)],
    },
];

/// YubiKey's firmware-axis quirks — empty: no fingerprint has
/// firmware-version-gated quirk data yet. Every other `_FIRMWARE_QUIRKS`
/// const below is empty for the same reason.
const YUBIKEY_FIRMWARE_QUIRKS: &[VersionQuirks] = &[];

/// Token2's cross-axis merge mode — see [`AxisMergeMode`]'s doc.
const TOKEN2_AXIS_MERGE_MODE: AxisMergeMode = AxisMergeMode::MergeRelaxed;

/// Token2's applet-axis known-support table:
///
/// * [`PivExtension::MoveKey`]/[`PivExtension::DeleteKey`]/
///   [`PivExtension::SlotTouchPolicy`] — share one row: applet version
///   5.112.0 has been observed to reject all three outright (MOVE KEY/DELETE
///   KEY outright; SlotTouchPolicy via a rejected `0xAB` tag on GENERATE
///   ASYMMETRIC KEYPAIR — contrast [`PivExtension::SlotPinPolicy`] below,
///   whose `0xAA` tag the same live unit *accepts*, so this isn't a blanket
///   "policy tags unsupported" verdict), and every version below it is
///   assumed to as well per [`resolve_in`]'s backward-extension rule (no
///   earlier hardware has been available to test, but a feature known not to
///   work at 5.112.0 is presumed not to work in any older, untested version
///   either). There is no known-supported verdict on this row, so a version
///   *above* 5.112.0 resolves [`FeatureGate::Unverified`], not
///   [`FeatureGate::Unsupported`] — a known-unsupported verdict is
///   deliberately never treated as covering a version it hasn't actually
///   observed on the other side either. The row needs no explicit `[]`
///   sentinel: the single `[5, 112, 0]` known-unsupported verdict is enough
///   for [`resolve_in`] to extend backward on its own.
/// * [`PivExtension::Reset`]/[`PivExtension::SetPinPukRetries`]/
///   [`PivExtension::GetMetadata`]/[`PivExtension::SetManagementKey`]/
///   [`PivExtension::SlotPinPolicy`]/[`PivExtension::PinManagementAuth`]/
///   [`PivExtension::SlotKeyAlgorithm`]`(`
///   [`KeyAlg::Rsa1024`]/[`KeyAlg::Rsa2048`]/[`KeyAlg::Rsa3072`]/
///   [`KeyAlg::Rsa4096`]/[`KeyAlg::EccP256`]/[`KeyAlg::EccP384`]/
///   [`KeyAlg::Ed25519`]/[`KeyAlg::X25519`]`)` — share one row:
///   `Verdict::KnownSupported` pinned to applet version 5.112.0, the only
///   version keyroost has hardware evidence for — a live unit at this version
///   accepts `INS 0xFB`, Yubico's SET PIN RETRIES APDU, GET METADATA, Yubico's
///   SET MANAGEMENT KEY APDU, the `0xAA` tag on GENERATE ASYMMETRIC KEYPAIR,
///   PIN VERIFY unlocking management (see [`PivExtension::PinManagementAuth`]'s
///   own doc for the indirect-vs-direct distinction — this crate's read path
///   treats every non-HID-Crescendo fingerprint as indirect regardless), and
///   every [`crate::KeyAlg`] except ECC P-521 on that same GENERATE ASYMMETRIC
///   KEYPAIR alike. Unlike the MOVE KEY/DELETE KEY/SlotTouchPolicy row above —
///   all three `Verdict::KnownUnsupported` at this same version — Token2
///   mimics some Yubico extension APDUs and not others, so each extension's
///   verdict for this fingerprint is independent and this row's positive
///   result doesn't imply anything about those. No known-unsupported floor is
///   recorded below 5.112.0 here either, so an older reported version
///   resolves [`FeatureGate::Unverified`] rather than inheriting this verdict
///   backward — unlike YubiKey's universal `[]` version on its own RESET row,
///   this one only speaks for 5.112.0 and later. For RESET specifically:
///   Token2 carries no [`PivQuirk::ResetNeedsManagementAuth`] entry on
///   [`TOKEN2_APPLET_QUIRKS`] either, so — same as YubiKey — this device
///   doesn't need an authenticated management-key session for RESET. Unlike
///   YubiKey, though, that same live unit accepted `INS 0xFB` with *neither*
///   the PIN nor the PUK blocked — it does not also fall back to the YubiKey
///   convention's blocked-precondition gate; see
///   [`PivQuirk::ResetNeedsManagementAuth`]'s own doc for why this quirk's
///   absence doesn't imply that convention.
/// * [`PivExtension::ResetGlobal`]/[`PivExtension::SlotKeyAlgorithm`]`(`
///   [`KeyAlg::EccP521`]`)` — share one row: `Verdict::KnownUnsupportedSince`
///   at the universal `[]` version. RESET GLOBAL gets this same verdict on
///   every fingerprint's table — see `GENERIC_APPLET_VERDICTS`'s doc for
///   why. ECC P-521 is the one algorithm the 5.112.0 unit above rejects on
///   GENERATE ASYMMETRIC KEYPAIR.
/// * No entry for [`PivExtension::Attest`].
const TOKEN2_APPLET_VERDICTS: &[ExtensionVerdicts] = &[
    ExtensionVerdicts {
        extensions: &[
            PivExtension::MoveKey,
            PivExtension::DeleteKey,
            PivExtension::SlotTouchPolicy,
        ],
        verdicts: &[VersionVerdict {
            version: &[5, 112, 0],
            verdict: Verdict::KnownUnsupported,
        }],
    },
    ExtensionVerdicts {
        extensions: &[
            PivExtension::Reset,
            PivExtension::SetPinPukRetries,
            PivExtension::GetMetadata,
            PivExtension::SetManagementKey,
            PivExtension::SlotPinPolicy,
            PivExtension::PinManagementAuth,
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa1024),
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa2048),
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa3072),
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa4096),
            PivExtension::SlotKeyAlgorithm(KeyAlg::EccP256),
            PivExtension::SlotKeyAlgorithm(KeyAlg::EccP384),
            PivExtension::SlotKeyAlgorithm(KeyAlg::Ed25519),
            PivExtension::SlotKeyAlgorithm(KeyAlg::X25519),
        ],
        verdicts: &[VersionVerdict {
            version: &[5, 112, 0],
            verdict: Verdict::KnownSupported,
        }],
    },
    // `PivExtension::ManagementKeyAlgorithm` — 3DES/AES-128/AES-192/AES-256
    // are all accepted as the management key's algorithm: one
    // `Verdict::KnownSupported` row at the universal `[]` version (this
    // fingerprint's own RESET/SET PIN RETRIES row above sits at a specific
    // `[5, 112, 0]` version instead, so it isn't the same row to join).
    // `MgmtAlgChoice::Delete` has no standard PIV equivalent on this
    // fingerprint — the management key is mandatory, never removable — so it
    // joins the RESET GLOBAL/ECC P-521 row below instead, which already
    // carries that same universal `[]` `Verdict::KnownUnsupportedSince`.
    ExtensionVerdicts {
        extensions: &[
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::TripleDes),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Aes128),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Aes192),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Aes256),
        ],
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownSupported,
        }],
    },
    ExtensionVerdicts {
        extensions: &[
            PivExtension::ResetGlobal,
            PivExtension::SlotKeyAlgorithm(KeyAlg::EccP521),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Delete),
        ],
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownUnsupportedSince,
        }],
    },
];

/// See [`YUBIKEY_FIRMWARE_VERDICTS`]'s doc — empty.
const TOKEN2_FIRMWARE_VERDICTS: &[ExtensionVerdicts] = &[];

/// Token2's applet-axis quirks: GET SERIAL's reply is packed BCD rather than
/// a plain big-endian integer, and this fingerprint ships its own
/// vendor-specific default management key ([`TOKEN2_DEFAULT_MGMT_KEY`])
/// rather than mimicking YubiKey's. The empty-slice version is the "from the
/// very first version" sentinel also used by [`YUBIKEY_APPLET_VERDICTS`]'s
/// MoveKey row: it orders at or below every real version (`[] <= anything`),
/// so this entry matches regardless of which applet version Token2 reports.
const TOKEN2_APPLET_QUIRKS: &[VersionQuirks] = &[VersionQuirks {
    version: &[],
    quirks: &[
        PivQuirk::InsF8SerialIsBcd,
        PivQuirk::Default9bManagementKey(TOKEN2_DEFAULT_MGMT_KEY),
    ],
}];

/// See [`YUBIKEY_FIRMWARE_QUIRKS`]'s doc — empty.
const TOKEN2_FIRMWARE_QUIRKS: &[VersionQuirks] = &[];

/// The Swissbit iShield 2 Pro's (`OpenFips201::SwissbitIShield2`) cross-axis
/// merge mode — see [`AxisMergeMode`]'s doc.
const SWISSBIT_ISHIELD2_AXIS_MERGE_MODE: AxisMergeMode = AxisMergeMode::MergeRelaxed;

/// The Swissbit iShield 2 Pro's (`OpenFips201::SwissbitIShield2`) applet-axis
/// known-support table:
///
/// * [`PivExtension::MoveKey`]/[`PivExtension::DeleteKey`]/
///   [`PivExtension::SlotPinPolicy`]/[`PivExtension::SlotTouchPolicy`] —
///   share one row: applet version 1.4.1.0 and every earlier version have
///   been observed to reject all four — MOVE KEY/DELETE KEY outright,
///   *setting* either slot policy on GENERATE ASYMMETRIC KEYPAIR too. Same
///   single-verdict shape as `TOKEN2_APPLET_VERDICTS`'s rows, just with
///   `[1, 4, 1, 0]` as the observed/backward-extending version instead of
///   `[5, 112, 0]`. A version above 1.4.1.0 falls off the end of the row and
///   resolves [`FeatureGate::Unverified`] — the known-unsupported verdict
///   deliberately doesn't extend to a future, untested version. Some slots
///   do echo a PIN/touch policy value back in their GET METADATA response,
///   but that value has been observed unrelated to what was actually
///   requested — stale or synthesized, not a live reflection of on-card
///   state — so it's no evidence either policy extension actually works; see
///   [`PivQuirk::InsF7MetadataPinTouchPolicyInvalid`] (carried on
///   `SWISSBIT_ISHIELD2_APPLET_QUIRKS` below), which names exactly that and
///   is why a caller must ignore GET METADATA's tag `0x02` on this
///   fingerprint entirely. *Setting* either policy is treated as unsupported
///   regardless of what GET METADATA claims to report back.
/// * [`PivExtension::ResetGlobal`]/[`PivExtension::SlotKeyAlgorithm`]`(`
///   [`KeyAlg::Rsa1024`]/[`KeyAlg::Ed25519`]/[`KeyAlg::X25519`]`)` — share one
///   row: `Verdict::KnownUnsupportedSince` at the universal `[]` version.
///   RESET GLOBAL gets this same verdict on every fingerprint's table — see
///   `GENERIC_APPLET_VERDICTS`'s doc for why. RSA-1024 and the Ed25519/
///   X25519 curves are absent from both the pre- and post-1.4 algorithm lists
///   below — OpenFIPS201's own closed algorithm set never included them — so
///   they land on the same "stays unsupported" row rather than either of the
///   two-tier shapes those lists use, the same closed-enumeration reasoning
///   `HID_CRESCENDO_C2300_APPLET_VERDICTS`'s own row uses.
/// * [`PivExtension::Reset`]/[`PivExtension::GetMetadata`]/
///   [`PivExtension::SlotKeyAlgorithm`]`(`[`KeyAlg::Rsa2048`]/[`KeyAlg::EccP256`]/
///   [`KeyAlg::EccP384`]`)` — share one row: `Verdict::KnownSupported` at
///   the universal `[]` version. Both tested applet versions (1.0.0.0 and
///   1.4.1.0) accept RESET, answer GET METADATA, and accept RSA-2048/ECC
///   P-256/P-384 on GENERATE ASYMMETRIC KEYPAIR alike, so there's no
///   known-unsupported floor to gate below, same shape as YubiKey's own
///   [`PivExtension::Reset`] row. GET METADATA's half of this is orthogonal
///   to [`PivQuirk::InsF7MetadataAlgorithmInvalid`] (see
///   `SWISSBIT_ISHIELD2_APPLET_QUIRKS` below) — that quirk is about the
///   *algorithm field* value being unreliable at every tested version, not
///   about whether GET METADATA itself is implemented.
/// * [`PivExtension::SetManagementKey`] — `Verdict::KnownSupported` pinned
///   to major version `[1]` rather than the universal `[]` sentinel the row
///   above uses: both tested applet versions (1.0.0.0 and 1.4.1.0) accept SET
///   MANAGEMENT KEY, but `[1]` orders below both under this module's
///   byte-slice comparison (a shorter version is a prefix match, so
///   `[1] < [1, 0, 0, 0]`), covering the whole 1.x lineage without claiming
///   anything about a hypothetical pre-1.0 release this fingerprint has never
///   shipped.
/// * [`PivExtension::SlotKeyAlgorithm`]`(`[`KeyAlg::Rsa3072`]/[`KeyAlg::Rsa4096`]/
///   [`KeyAlg::EccP521`]`)`/[`PivExtension::PinManagementAuth`]/
///   [`PivExtension::SetPinPukRetries`] — share one row: the same two-tier
///   `Verdict::KnownUnsupported`-then-`Verdict::KnownSupported` shape as
///   YubiKey's MOVE KEY/DELETE KEY row in [`YUBIKEY_APPLET_VERDICTS`], just
///   anchored to this fingerprint's actual tested floor (`[1, 0, 0, 0]`)
///   instead of the universal `[]` sentinel YubiKey uses there, and rising
///   to `[1, 4]` (which, under this module's prefix ordering, already covers
///   the confirmed `1.4.1.0` unit
///   `slot_key_algorithm_apdu_id_override`'s own EccP521 byte override was
///   observed on). SET PIN RETRIES is confirmed supported from that same
///   `1.4` floor — not the narrower `1.4.1.0` a standalone row once pinned
///   it to — hence sharing this entry rather than keeping its own. A version
///   strictly between the two tested points is untested and guessed, not
///   confirmed on hardware, but per [`resolve_in`]'s bracketing rule it
///   still resolves [`FeatureGate::Unsupported`] rather than softening to
///   [`FeatureGate::Unverified`] — the known-unsupported floor is bracketed
///   by the known-supported verdict above it, so it's treated as
///   authoritative up to that point.
const SWISSBIT_ISHIELD2_APPLET_VERDICTS: &[ExtensionVerdicts] = &[
    ExtensionVerdicts {
        extensions: &[
            PivExtension::MoveKey,
            PivExtension::DeleteKey,
            PivExtension::SlotPinPolicy,
            PivExtension::SlotTouchPolicy,
        ],
        verdicts: &[VersionVerdict {
            version: &[1, 4, 1, 0],
            verdict: Verdict::KnownUnsupported,
        }],
    },
    // `PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Delete)` joins
    // this row: no standard PIV equivalent on this fingerprint — the
    // management key is mandatory, never removable — same universal `[]`
    // `Verdict::KnownUnsupportedSince`.
    ExtensionVerdicts {
        extensions: &[
            PivExtension::ResetGlobal,
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa1024),
            PivExtension::SlotKeyAlgorithm(KeyAlg::Ed25519),
            PivExtension::SlotKeyAlgorithm(KeyAlg::X25519),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Delete),
        ],
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownUnsupportedSince,
        }],
    },
    // `PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::{TripleDes,Aes128,
    // Aes192,Aes256})` joins this row: all four are accepted as the
    // management key's algorithm too, same universal `[]`
    // `Verdict::KnownSupported`.
    ExtensionVerdicts {
        extensions: &[
            PivExtension::Reset,
            PivExtension::GetMetadata,
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa2048),
            PivExtension::SlotKeyAlgorithm(KeyAlg::EccP256),
            PivExtension::SlotKeyAlgorithm(KeyAlg::EccP384),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::TripleDes),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Aes128),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Aes192),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Aes256),
        ],
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownSupported,
        }],
    },
    ExtensionVerdicts {
        extensions: &[PivExtension::SetManagementKey],
        verdicts: &[VersionVerdict {
            version: &[1],
            verdict: Verdict::KnownSupported,
        }],
    },
    ExtensionVerdicts {
        extensions: &[
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa3072),
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa4096),
            PivExtension::SlotKeyAlgorithm(KeyAlg::EccP521),
            PivExtension::PinManagementAuth,
            PivExtension::SetPinPukRetries,
        ],
        verdicts: &[
            VersionVerdict {
                version: &[1, 0, 0, 0],
                verdict: Verdict::KnownUnsupported,
            },
            VersionVerdict {
                version: &[1, 4],
                verdict: Verdict::KnownSupported,
            },
        ],
    },
];

/// See [`YUBIKEY_FIRMWARE_VERDICTS`]'s doc — empty.
const SWISSBIT_ISHIELD2_FIRMWARE_VERDICTS: &[ExtensionVerdicts] = &[];

/// The Swissbit iShield 2 Pro's (`OpenFips201::SwissbitIShield2`) applet-axis
/// quirks. Devices have been observed to eventually stop reliably updating
/// GET METADATA's algorithm identifier (tag 0x01): it gets stuck at some
/// point and no longer reflects the slot's actual key state, so it must
/// always be ignored while this quirk is set. This was previously believed
/// fixed at applet version 1.4.1.0 — a brand-new 1.4.1.0 unit answered
/// reliably at first — but the same unit, still on 1.4.1.0, was later
/// observed to report a stale algorithm again after a handful of key
/// generations; a factory reset of the applet did not restore reliable
/// reporting either. So this isn't a version-gated bug with a fixed floor —
/// it's a "goes stale at some point in the device's lifetime, regardless of
/// applet version" one, and there is no known state (version, freshly reset,
/// otherwise) this quirk can be assumed clear of. Accordingly there's only
/// one entry here, at the empty-slice "from the very first version" sentinel
/// (see [`TOKEN2_APPLET_QUIRKS`]'s doc) rather than a version floor, and it
/// never clears at any later version — unlike a normal version-gated quirk,
/// a caller must always ignore tag `0x01` on this fingerprint. Also carries
/// [`PivQuirk::InsF7MetadataPinTouchPolicyInvalid`] (GET METADATA's PIN/touch
/// policy tag, `0x02`, has been observed unreliable on every tested applet
/// version, 1.0.0.0 through 1.4.1.0 alike, with no version yet confirmed
/// clear of it — see [`SWISSBIT_ISHIELD2_APPLET_VERDICTS`]'s
/// [`PivExtension::SlotPinPolicy`]/[`PivExtension::SlotTouchPolicy`] doc for
/// the same observation from the "does *setting* it work" side) and
/// [`PivQuirk::Default9bManagementKey`], mimicking the YubiKey default
/// management key like most other third-party implementations do.
const SWISSBIT_ISHIELD2_APPLET_QUIRKS: &[VersionQuirks] = &[VersionQuirks {
    version: &[],
    quirks: &[
        PivQuirk::InsF7MetadataAlgorithmInvalid,
        PivQuirk::InsF7MetadataPinTouchPolicyInvalid,
        PivQuirk::Default9bManagementKey(YUBIKEY_DEFAULT_MGMT_KEY),
    ],
}];

/// See [`YUBIKEY_FIRMWARE_QUIRKS`]'s doc — empty.
const SWISSBIT_ISHIELD2_FIRMWARE_QUIRKS: &[VersionQuirks] = &[];

/// The Thetis PRO FIDO2 Security Key with PinPlex's cross-axis merge mode —
/// see [`AxisMergeMode`]'s doc.
const THETIS_AXIS_MERGE_MODE: AxisMergeMode = AxisMergeMode::MergeRelaxed;

/// The Thetis PRO FIDO2 Security Key with PinPlex's
/// (`AppletFingerprint::Thetis`) applet-axis known-support table:
///
/// * [`PivExtension::MoveKey`]/[`PivExtension::DeleteKey`]/
///   [`PivExtension::SlotTouchPolicy`] — share one row: applet version
///   5.112.0 and every earlier version have been observed to reject all
///   three — MOVE KEY/DELETE KEY outright, the `0xAB` tag on GENERATE
///   ASYMMETRIC KEYPAIR too (contrast [`PivExtension::SlotPinPolicy`] below,
///   whose `0xAA` tag the same live unit *accepts*). Same single-verdict
///   shape as the tables above: `[5, 112, 0]` is both the exact-match verdict
///   and the one [`resolve_in`] extends backward from. A version above
///   5.112.0 falls off the end of the row and resolves
///   [`FeatureGate::Unverified`] — the known-unsupported verdict deliberately
///   doesn't extend to a future, untested version.
/// * [`PivExtension::Reset`]/[`PivExtension::SetPinPukRetries`]/
///   [`PivExtension::GetMetadata`]/[`PivExtension::SetManagementKey`]/
///   [`PivExtension::SlotPinPolicy`]/[`PivExtension::PinManagementAuth`]/
///   [`PivExtension::SlotKeyAlgorithm`] (every [`crate::KeyAlg`] except ECC
///   P-521) — share one row: `Verdict::KnownSupported` pinned to applet
///   version 5.112.0, the only version keyroost has hardware evidence for —
///   a live unit at this version accepts `INS 0xFB`, answers GET METADATA,
///   and accepts Yubico's SET PIN RETRIES APDU, Yubico's SET MANAGEMENT KEY
///   APDU, the `0xAA` tag on GENERATE ASYMMETRIC KEYPAIR, PIN VERIFY
///   unlocking management, and every algorithm but ECC P-521 on that same
///   GENERATE ASYMMETRIC KEYPAIR alike. Unlike the MOVE KEY/DELETE KEY/
///   SlotTouchPolicy row above — all three `Verdict::KnownUnsupported` at
///   this same version — this fingerprint mimics some Yubico extension APDUs
///   and not others, so each extension's verdict for this fingerprint is
///   independent and this row's positive result doesn't imply anything about
///   those. No known-unsupported floor is recorded below 5.112.0 here either,
///   so an older reported version resolves [`FeatureGate::Unverified`] rather
///   than inheriting this verdict backward. For RESET specifically: Thetis
///   carries no [`PivQuirk::ResetNeedsManagementAuth`] entry on
///   [`THETIS_APPLET_QUIRKS`] either, so RESET doesn't need an authenticated
///   management-key session on this fingerprint.
/// * [`PivExtension::ResetGlobal`]/[`PivExtension::SlotKeyAlgorithm`]`(`
///   [`KeyAlg::EccP521`]`)` — share one row: `Verdict::KnownUnsupportedSince`
///   at the universal `[]` version. RESET GLOBAL gets this same verdict on
///   every fingerprint's table — see `GENERIC_APPLET_VERDICTS`'s doc for
///   why. ECC P-521 is the one algorithm the 5.112.0 unit above rejects on
///   GENERATE ASYMMETRIC KEYPAIR.
const THETIS_APPLET_VERDICTS: &[ExtensionVerdicts] = &[
    ExtensionVerdicts {
        extensions: &[
            PivExtension::MoveKey,
            PivExtension::DeleteKey,
            PivExtension::SlotTouchPolicy,
        ],
        verdicts: &[VersionVerdict {
            version: &[5, 112, 0],
            verdict: Verdict::KnownUnsupported,
        }],
    },
    ExtensionVerdicts {
        extensions: &[
            PivExtension::Reset,
            PivExtension::SetPinPukRetries,
            PivExtension::GetMetadata,
            PivExtension::SetManagementKey,
            PivExtension::SlotPinPolicy,
            PivExtension::PinManagementAuth,
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa1024),
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa2048),
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa3072),
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa4096),
            PivExtension::SlotKeyAlgorithm(KeyAlg::EccP256),
            PivExtension::SlotKeyAlgorithm(KeyAlg::EccP384),
            PivExtension::SlotKeyAlgorithm(KeyAlg::Ed25519),
            PivExtension::SlotKeyAlgorithm(KeyAlg::X25519),
        ],
        verdicts: &[VersionVerdict {
            version: &[5, 112, 0],
            verdict: Verdict::KnownSupported,
        }],
    },
    // `PivExtension::ManagementKeyAlgorithm` — 3DES/AES-128/AES-192/AES-256
    // are all accepted as the management key's algorithm: one
    // `Verdict::KnownSupported` row at the universal `[]` version (this
    // fingerprint's own RESET/SET PIN RETRIES row above sits at a specific
    // `[5, 112, 0]` version instead, so it isn't the same row to join).
    // `MgmtAlgChoice::Delete` has no standard PIV equivalent on this
    // fingerprint — the management key is mandatory, never removable — so it
    // joins the RESET GLOBAL/ECC P-521 row below instead, which already
    // carries that same universal `[]` `Verdict::KnownUnsupportedSince`.
    ExtensionVerdicts {
        extensions: &[
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::TripleDes),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Aes128),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Aes192),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Aes256),
        ],
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownSupported,
        }],
    },
    ExtensionVerdicts {
        extensions: &[
            PivExtension::ResetGlobal,
            PivExtension::SlotKeyAlgorithm(KeyAlg::EccP521),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Delete),
        ],
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownUnsupportedSince,
        }],
    },
];

/// See [`YUBIKEY_FIRMWARE_VERDICTS`]'s doc — empty.
const THETIS_FIRMWARE_VERDICTS: &[ExtensionVerdicts] = &[];

/// The Thetis PRO FIDO2 Security Key with PinPlex's
/// (`AppletFingerprint::Thetis`) applet-axis quirks. Observed at applet
/// version 5.112.0, the only version tested so far. Earlier versions are
/// assumed to encode GET SERIAL's reply the same way rather than confirmed
/// to — no earlier-version hardware has been available to test — so the
/// empty-slice version below is a deliberate "from the very first version"
/// assumption, not a direct observation, using the same sentinel as
/// [`TOKEN2_APPLET_QUIRKS`]'s row. Mimics the YubiKey default management key
/// like most other third-party implementations do.
const THETIS_APPLET_QUIRKS: &[VersionQuirks] = &[VersionQuirks {
    version: &[],
    quirks: &[
        PivQuirk::InsF8SerialIsBcd,
        PivQuirk::Default9bManagementKey(YUBIKEY_DEFAULT_MGMT_KEY),
    ],
}];

/// See [`YUBIKEY_FIRMWARE_QUIRKS`]'s doc — empty.
const THETIS_FIRMWARE_QUIRKS: &[VersionQuirks] = &[];

/// `ArekinathPivApplet::Generic`'s cross-axis merge mode — see
/// [`AxisMergeMode`]'s doc.
const AREKINATH_GENERIC_AXIS_MERGE_MODE: AxisMergeMode = AxisMergeMode::MergeRelaxed;

/// `ArekinathPivApplet::Generic`'s (<https://github.com/arekinath/PivApplet>)
/// applet-axis known-support table. Identical in shape and version thresholds
/// to [`AREKINATH_SWISSBIT_ISHIELD1_APPLET_VERDICTS`] below, kept as two
/// separate tables even though the two fingerprints share one upstream
/// codebase:
///
/// * [`PivExtension::MoveKey`]/[`PivExtension::DeleteKey`]/
///   [`PivExtension::SlotTouchPolicy`] — share one row: this applet's own
///   source implements none of the three in applet version 5.4.0 or any
///   release before it — MOVE KEY/DELETE KEY, and no touch-policy equivalent
///   either — a `Verdict::KnownUnsupported` verdict pinned to `[5, 4, 0]`,
///   extended backward by [`resolve_in`]'s rule to cover every earlier
///   version too. A version above 5.4.0 falls off the end of the row and
///   resolves [`FeatureGate::Unverified`] — the known-unsupported verdict
///   doesn't extend forward to an untested future release.
/// * [`PivExtension::GetMetadata`] — lands in this applet's own source at
///   version 5.3.0: a `Verdict::KnownUnsupported` verdict at the
///   empty-slice `[]` sentinel (every version before 5.3.0) and a
///   `Verdict::KnownSupported` verdict at `[5, 3, 0]` covering that
///   version and every later one, assumed not to have regressed. As on
///   YubiKey's row, the `[]` sentinel is load-bearing — the verdict above it
///   is known-supported, which says nothing about the versions before it.
/// * [`PivExtension::Reset`]/[`PivExtension::SetPinPukRetries`]/
///   [`PivExtension::PinManagementAuth`] — share one row: same shape as
///   [`PivExtension::GetMetadata`] above, a `Verdict::KnownUnsupported`
///   verdict at `[]` and a `Verdict::KnownSupported` verdict at `[5]` — the
///   major version, not a specific `5.0.0` patch release, since PIN
///   VERIFY-based management unlock is confirmed at major version 5 without
///   pinning it to the same `5.0.0` floor RESET/SET PIN RETRIES themselves
///   were confirmed at; merged into this one entry rather than a second,
///   separately-pinned row since [`resolve_in`]'s prefix ordering already
///   makes `[5]` cover `5.0.0` and every later 5.x release alike. This
///   fingerprint carries no [`PivQuirk::ResetNeedsManagementAuth`] entry on
///   [`AREKINATH_GENERIC_APPLET_QUIRKS`], so — same as YubiKey and Token2 —
///   RESET doesn't need an authenticated management-key session on this
///   applet either.
/// * [`PivExtension::ResetGlobal`]/[`PivExtension::SlotKeyAlgorithm`]`(`
///   [`KeyAlg::Rsa3072`]/[`KeyAlg::Rsa4096`]/[`KeyAlg::EccP521`]/
///   [`KeyAlg::Ed25519`]/[`KeyAlg::X25519`]`)` — share one row:
///   `Verdict::KnownUnsupportedSince` at the universal `[]` version. RESET
///   GLOBAL gets this same verdict on every fingerprint's table — see
///   `GENERIC_APPLET_VERDICTS`'s doc for why. The five algorithms are ones
///   this applet's own source has never implemented, at any release, so
///   there's nothing to gate by version on either side — unlike the two-tier
///   rows above, this is a flat "always unsupported" verdict.
/// * [`PivExtension::SetManagementKey`]/[`PivExtension::SlotPinPolicy`] —
///   share one row: `Verdict::KnownSupported` pinned to major version
///   `[4]`, predating the 5.x lineage every other row above is anchored to.
///   SET MANAGEMENT KEY is core key management this applet's own source has
///   supported since its major version 4 releases; PIN policy on GENERATE
///   ASYMMETRIC KEYPAIR (<https://github.com/arekinath/PivApplet>) the same —
///   neither has a known-unsupported floor to gate below the way MOVE
///   KEY/DELETE KEY/SlotTouchPolicy's row above has one.
/// * [`PivExtension::SlotKeyAlgorithm`]`(`[`KeyAlg::Rsa1024`]/[`KeyAlg::Rsa2048`]/
///   [`KeyAlg::EccP256`]/[`KeyAlg::EccP384`]`)` — RSA-1024/2048 and ECC
///   P-256/P-384 (the same four YubiKey supports below its own 5.7 cutover —
///   see [`YUBIKEY_APPLET_VERDICTS`]'s row) have never varied by version
///   either: `Verdict::KnownSupported` at the universal `[]` version,
///   distinct from the row above's `[4]` pin — this applet's algorithm
///   support predates even its earliest major-version-4 release, so there's
///   nothing to gate by version at all.
const AREKINATH_GENERIC_APPLET_VERDICTS: &[ExtensionVerdicts] = &[
    ExtensionVerdicts {
        extensions: &[
            PivExtension::MoveKey,
            PivExtension::DeleteKey,
            PivExtension::SlotTouchPolicy,
        ],
        verdicts: &[VersionVerdict {
            version: &[5, 4, 0],
            verdict: Verdict::KnownUnsupported,
        }],
    },
    ExtensionVerdicts {
        extensions: &[PivExtension::GetMetadata],
        verdicts: &[
            VersionVerdict {
                version: &[],
                verdict: Verdict::KnownUnsupported,
            },
            VersionVerdict {
                version: &[5, 3, 0],
                verdict: Verdict::KnownSupported,
            },
        ],
    },
    ExtensionVerdicts {
        extensions: &[
            PivExtension::Reset,
            PivExtension::SetPinPukRetries,
            PivExtension::PinManagementAuth,
        ],
        verdicts: &[
            VersionVerdict {
                version: &[],
                verdict: Verdict::KnownUnsupported,
            },
            VersionVerdict {
                version: &[5],
                verdict: Verdict::KnownSupported,
            },
        ],
    },
    // `PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Delete)` joins
    // this row: no standard PIV equivalent on this fingerprint — the
    // management key is mandatory, never removable — same universal `[]`
    // `Verdict::KnownUnsupportedSince`.
    ExtensionVerdicts {
        extensions: &[
            PivExtension::ResetGlobal,
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa3072),
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa4096),
            PivExtension::SlotKeyAlgorithm(KeyAlg::EccP521),
            PivExtension::SlotKeyAlgorithm(KeyAlg::Ed25519),
            PivExtension::SlotKeyAlgorithm(KeyAlg::X25519),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Delete),
        ],
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownUnsupportedSince,
        }],
    },
    ExtensionVerdicts {
        extensions: &[PivExtension::SetManagementKey, PivExtension::SlotPinPolicy],
        verdicts: &[VersionVerdict {
            version: &[4],
            verdict: Verdict::KnownSupported,
        }],
    },
    // `PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::{TripleDes,Aes128,
    // Aes192,Aes256})` joins this row: all four are accepted as the
    // management key's algorithm too, same universal `[]`
    // `Verdict::KnownSupported`.
    ExtensionVerdicts {
        extensions: &[
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa1024),
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa2048),
            PivExtension::SlotKeyAlgorithm(KeyAlg::EccP256),
            PivExtension::SlotKeyAlgorithm(KeyAlg::EccP384),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::TripleDes),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Aes128),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Aes192),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Aes256),
        ],
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownSupported,
        }],
    },
];

/// See [`YUBIKEY_FIRMWARE_VERDICTS`]'s doc — empty.
const AREKINATH_GENERIC_FIRMWARE_VERDICTS: &[ExtensionVerdicts] = &[];

/// `ArekinathPivApplet::Generic`'s applet-axis quirks: mimics the YubiKey PIV
/// factory-default management key like most other third-party
/// implementations do, plus [`PivQuirk::ResetFailsIfManagementKeyIsAes`] —
/// a bug in this applet's upstream source itself (see that quirk's own doc),
/// not something any particular firmware sample could have avoided, so it's
/// seeded at the universal `[]` version rather than gated to one.
const AREKINATH_GENERIC_APPLET_QUIRKS: &[VersionQuirks] = &[VersionQuirks {
    version: &[],
    quirks: &[
        PivQuirk::Default9bManagementKey(YUBIKEY_DEFAULT_MGMT_KEY),
        PivQuirk::ResetFailsIfManagementKeyIsAes,
    ],
}];

/// See [`YUBIKEY_FIRMWARE_QUIRKS`]'s doc — empty.
const AREKINATH_GENERIC_FIRMWARE_QUIRKS: &[VersionQuirks] = &[];

/// `ArekinathPivApplet::SwissbitIShield1`'s cross-axis merge mode — see
/// [`AxisMergeMode`]'s doc.
const AREKINATH_SWISSBIT_ISHIELD1_AXIS_MERGE_MODE: AxisMergeMode = AxisMergeMode::MergeRelaxed;

/// `ArekinathPivApplet::SwissbitIShield1`'s
/// (<https://github.com/swissbit-eis/PivApplet>) applet-axis known-support
/// table — identical to [`AREKINATH_GENERIC_APPLET_VERDICTS`] above (see its
/// doc for the per-extension reasoning), except every non-[`PivExtension::ResetGlobal`]
/// row here is *additionally* confirmed on a real firmware v3.35.0 device
/// reporting applet version 5.4.0 — past the 5, 5.3.0, and 5.4.0 thresholds
/// below, so it only confirms the known-supported side of those rows, not
/// the floor. The same live unit confirms [`PivExtension::SlotPinPolicy`]
/// works and [`PivExtension::SlotTouchPolicy`] doesn't, exactly matching
/// [`AREKINATH_GENERIC_APPLET_VERDICTS`]'s own two rows for those extensions
/// — its `[5, 4, 0]` [`PivExtension::SlotTouchPolicy`] pin *is* this device's
/// confirmed version, unlike MoveKey/DeleteKey/GetMetadata/Reset/
/// SetPinPukRetries/[`PivExtension::PinManagementAuth`] above where 5.4.0 is
/// merely the *floor* their table entries are pinned to.
/// [`PivExtension::SlotKeyAlgorithm`]'s rows are
/// shared verbatim with [`AREKINATH_GENERIC_APPLET_VERDICTS`] too — see its
/// own doc: this is the one upstream codebase both fingerprints share, so its
/// algorithm support is identical and equally version-independent on either
/// sub-fingerprint.
const AREKINATH_SWISSBIT_ISHIELD1_APPLET_VERDICTS: &[ExtensionVerdicts] = &[
    ExtensionVerdicts {
        extensions: &[
            PivExtension::MoveKey,
            PivExtension::DeleteKey,
            PivExtension::SlotTouchPolicy,
        ],
        verdicts: &[VersionVerdict {
            version: &[5, 4, 0],
            verdict: Verdict::KnownUnsupported,
        }],
    },
    ExtensionVerdicts {
        extensions: &[PivExtension::GetMetadata],
        verdicts: &[
            VersionVerdict {
                version: &[],
                verdict: Verdict::KnownUnsupported,
            },
            VersionVerdict {
                version: &[5, 3, 0],
                verdict: Verdict::KnownSupported,
            },
        ],
    },
    ExtensionVerdicts {
        extensions: &[
            PivExtension::Reset,
            PivExtension::SetPinPukRetries,
            PivExtension::PinManagementAuth,
        ],
        verdicts: &[
            VersionVerdict {
                version: &[],
                verdict: Verdict::KnownUnsupported,
            },
            VersionVerdict {
                version: &[5],
                verdict: Verdict::KnownSupported,
            },
        ],
    },
    // `PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Delete)` joins
    // this row: no standard PIV equivalent on this fingerprint — the
    // management key is mandatory, never removable — same universal `[]`
    // `Verdict::KnownUnsupportedSince`.
    ExtensionVerdicts {
        extensions: &[
            PivExtension::ResetGlobal,
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa3072),
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa4096),
            PivExtension::SlotKeyAlgorithm(KeyAlg::EccP521),
            PivExtension::SlotKeyAlgorithm(KeyAlg::Ed25519),
            PivExtension::SlotKeyAlgorithm(KeyAlg::X25519),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Delete),
        ],
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownUnsupportedSince,
        }],
    },
    ExtensionVerdicts {
        extensions: &[PivExtension::SetManagementKey, PivExtension::SlotPinPolicy],
        verdicts: &[VersionVerdict {
            version: &[4],
            verdict: Verdict::KnownSupported,
        }],
    },
    // `PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::{TripleDes,Aes128,
    // Aes192,Aes256})` joins this row: all four are accepted as the
    // management key's algorithm too, same universal `[]`
    // `Verdict::KnownSupported`.
    ExtensionVerdicts {
        extensions: &[
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa1024),
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa2048),
            PivExtension::SlotKeyAlgorithm(KeyAlg::EccP256),
            PivExtension::SlotKeyAlgorithm(KeyAlg::EccP384),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::TripleDes),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Aes128),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Aes192),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Aes256),
        ],
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownSupported,
        }],
    },
];

/// See [`YUBIKEY_FIRMWARE_VERDICTS`]'s doc — empty.
const AREKINATH_SWISSBIT_ISHIELD1_FIRMWARE_VERDICTS: &[ExtensionVerdicts] = &[];

/// `ArekinathPivApplet::SwissbitIShield1`'s applet-axis quirks — shares
/// [`AREKINATH_GENERIC_APPLET_QUIRKS`]'s default-management-key and
/// [`PivQuirk::ResetFailsIfManagementKeyIsAes`] entries above (kept as a
/// separate const even though the two fingerprints share one upstream
/// codebase, the same separation
/// [`AREKINATH_SWISSBIT_ISHIELD1_APPLET_VERDICTS`] uses — and the same reason
/// the AES-reset bug applies to both: it's in the shared upstream source, not
/// anything Swissbit's fork changed), plus one quirk this variant doesn't
/// share with `Generic`: [`PivQuirk::ResetLongRunning`] — a real
/// SwissbitIShield1 unit has been observed to take over a minute to complete
/// [`PivExtension::Reset`], a wait long enough to look like a hang if a
/// caller doesn't warn for it up front. Seeded at the universal `[]` version
/// since every applet version sampled so far shares the same slow RESET;
/// narrow this to a specific version floor if a future sample turns out
/// faster.
const AREKINATH_SWISSBIT_ISHIELD1_APPLET_QUIRKS: &[VersionQuirks] = &[VersionQuirks {
    version: &[],
    quirks: &[
        PivQuirk::Default9bManagementKey(YUBIKEY_DEFAULT_MGMT_KEY),
        PivQuirk::ResetFailsIfManagementKeyIsAes,
        PivQuirk::ResetLongRunning,
    ],
}];

/// See [`YUBIKEY_FIRMWARE_QUIRKS`]'s doc — empty.
const AREKINATH_SWISSBIT_ISHIELD1_FIRMWARE_QUIRKS: &[VersionQuirks] = &[];

/// HID Crescendo C2300's cross-axis merge mode — see [`AxisMergeMode`]'s doc.
const HID_CRESCENDO_C2300_AXIS_MERGE_MODE: AxisMergeMode = AxisMergeMode::MergeRelaxed;

/// HID Crescendo C2300's applet-axis known-support table. Each bullet below
/// still walks its extension's own reasoning individually, even though every
/// extension that lands on `Verdict::KnownUnsupportedSince` shares one row
/// in the table below, and separately every extension that lands on
/// `Verdict::KnownSupported` shares the other — the two verdicts happen to
/// coincide across several otherwise-independent claims, not because they're
/// the same claim. [`PivExtension::SlotKeyAlgorithm`]'s own per-algorithm
/// verdicts (see its bullet below) happen to coincide with these same two
/// rows too, and are folded into them for exactly the same reason:
///
/// * [`PivExtension::DeleteKey`] — `Verdict::KnownSupported` at the
///   universal `[]` version: `keyroost_transport::PivSession::delete_key`
///   implements HID's own INJECT PKI KEY (`INS 0xD8`) removal form for this
///   family (`keyroost_piv::fingerprint::hid_crescendo_c2300_delete_key`),
///   so unlike [`PivExtension::MoveKey`] below this is a presence claim, not
///   an absence one — see that function's doc for what's confirmed from
///   HID's own API references versus reconstructed from their generic
///   "zero-length data field removes the key" rule (neither page gives a
///   literal delete example). Same shape [`PivExtension::ResetGlobal`]'s row
///   below uses: a positive claim needs no minimum applet version to gate
///   below, so one `KnownSupported` verdict at `[]` is the whole row.
///   Deliberately **not** shared with [`HID_CRESCENDO_GENERIC_APPLET_VERDICTS`]
///   — this is a presence claim tied to two specific, named families'
///   documented command references, not the vendor-wide absence pattern the
///   other rows here lean on; `Generic` keeps resolving
///   [`FeatureGate::Unverified`] for [`PivExtension::DeleteKey`], same as any
///   fingerprint with no entry for it — `PivSession::delete_key` still
///   attempts something sensible for it (see that method's doc); this table
///   only decides what the *UI* shows ahead of time, not what the transport
///   layer is willing to try.
/// * [`PivExtension::MoveKey`] — `Verdict::KnownUnsupportedSince` at the
///   universal `[]` version, on a standing-pattern reasoning shared with
///   [`PivExtension::Attest`]/[`PivExtension::GetMetadata`]/
///   [`PivExtension::Reset`]/[`PivExtension::SetPinPukRetries`] below: this
///   family has never attempted to mimic a Yubico extension APDU, building
///   its own proprietary alternatives instead (ACA XAUTH, GET PIV
///   PROPERTIES, RESET CARD). For MOVE KEY specifically there is no HID
///   equivalent at all, documented or otherwise: no ACA command relocates a
///   key between PIV slots. That absence of even a proprietary alternative
///   makes the standing-pattern bet the *only* evidence for this row
///   (contrast GET METADATA below, where the alternative's actual
///   documented shape is additional confirmation), but the same reasoning
///   that justifies [`HID_CRESCENDO_GENERIC_APPLET_VERDICTS`] sharing this
///   verdict applies here too. Should a real unit ever turn out to support
///   MOVE KEY after all, this row needs a firmware sample to correct it,
///   exactly like every other verdict here. Deliberately **not** mirrored
///   onto [`PivExtension::DeleteKey`] above — DELETE KEY turned out to have
///   the opposite answer on this family: HID's own INJECT PKI KEY
///   (`INS 0xD8`), sent with a zero-length key-data field, is a genuine,
///   documented alternative, so that row carries `Verdict::KnownSupported`
///   instead of leaving the family unlisted. The absence-vs-presence split
///   between the two rows is deliberate, not an oversight: MOVE (relocate a
///   key between slots) and DELETE (remove one in place) aren't the same
///   operation just because Yubico's extension API happens to bundle them
///   under one opcode — HID's proprietary API has no obligation to bundle
///   them the same way, and evidently doesn't.
/// * [`PivExtension::Attest`]/[`PivExtension::GetMetadata`] —
///   `Verdict::KnownUnsupportedSince` at the universal `[]` version for
///   both, same standing-pattern reasoning as [`PivExtension::MoveKey`]
///   above (this GET PIV PROPERTIES read is itself the proprietary
///   alternative standing in for GET METADATA): a live unit reporting
///   applet version `3.0.3.6` (read from its GET PIV PROPERTIES response's
///   tag `0x01` "Applet Version Block" —
///   [`crate::fingerprint::parse_hid_crescendo_version`] — and reported on
///   the *applet* axis despite not coming from Yubico's own GET VERSION
///   extension) has been observed to refuse both extensions outright
///   (`SW = 6D 00`, "instruction not supported"), but the standing pattern
///   is what justifies the universal `[]` version rather than pinning just
///   `3.0.3.6` (or, generalized, `3.0.3.<any>`) the way an ordinary
///   `Verdict::KnownUnsupported` would. See
///   `HID_CRESCENDO_C4000_APPLET_VERDICTS`'s doc for C4000's own version
///   of this same pair of rows.
/// * [`PivExtension::GetSlotKeyStatus`] — `Verdict::KnownSupported` at the
///   universal `[]` version: GET PIV PROPERTIES
///   (`keyroost_transport::PivSession::hid_crescendo_slot_algorithm`, via
///   [`crate::fingerprint::parse_hid_crescendo_slot_key_algorithms`]) names
///   every slot that actually has a key loaded — independent of this same
///   fingerprint's [`PivExtension::GetMetadata`] row above
///   (`Verdict::KnownUnsupportedSince`): the two questions (does GET
///   METADATA work; can this fingerprint report slot key status at all)
///   have separate, independently confirmed answers here, unlike every
///   fingerprint with no entry for this extension, where they're the same
///   question — see [`resolve`]'s special-case doc for the mechanics. This
///   extension is deliberately sparse across every table in this module: a
///   fingerprint only gets a [`PivExtension::GetSlotKeyStatus`] entry when
///   it reports slot key status through some *other* channel, independently
///   confirmed and gated on its own terms — entirely unrelated to whatever
///   [`PivExtension::GetMetadata`] says for that same fingerprint.
/// * [`PivExtension::PinManagementAuth`] — `Verdict::KnownSupported` at
///   the universal `[]` version: every unit in this family unlocks
///   management functionality directly via PIN VERIFY, with no [`PivQuirk`]
///   needed (unlike YubiKey) — PIN VERIFY *is* the unlock, full stop.
/// * [`PivExtension::Reset`] — `Verdict::KnownUnsupportedSince` at the
///   universal `[]` version, on the same standing-pattern reasoning as
///   [`PivExtension::GetMetadata`] above, and a card-wide reset alternative
///   already exists for it
///   (<https://docs.hidglobal.com/crescendo/api/low-level/reset-card.htm>,
///   implemented by `keyroost_transport::PivSession::factory_reset` — see
///   [`PivQuirk::ResetNeedsManagementAuth`], set on
///   [`HID_CRESCENDO_C2300_APPLET_QUIRKS`], and [`PivExtension::ResetGlobal`] below for
///   that same mechanism's own known-support data).
/// * [`PivExtension::SetPinPukRetries`] — `Verdict::KnownUnsupportedSince`
///   at the universal `[]` version, on the same standing-pattern reasoning
///   as [`PivExtension::Reset`] above. See
///   `HID_CRESCENDO_C4000_APPLET_VERDICTS`'s doc for a caveat specific to
///   that family's row.
/// * [`PivExtension::ResetGlobal`] — `Verdict::KnownSupported` at the
///   universal `[]` version: RESET CARD against the ACA instance
///   (`INS 0x38`,
///   <https://docs.hidglobal.com/crescendo/api/low-level/reset-card.htm>) is
///   documented for this family and needs no minimum applet version — the
///   opposite verdict from [`PivExtension::Reset`] above for this same
///   fingerprint: the two extensions are resolved independently, and a
///   device can carry either verdict without the other. Deliberately **not**
///   shared with [`HID_CRESCENDO_GENERIC_APPLET_VERDICTS`]: RESET CARD's own
///   documentation names the C2300 and C4000 families specifically, so
///   unlike [`PivExtension::Reset`] (where every HID Crescendo model shares
///   one "never mimics a Yubico extension APDU" absence to reason from)
///   there is no equivalently general basis here to extend a *presence*
///   claim to a model this data doesn't name.
/// * [`PivExtension::SetManagementKey`] — `Verdict::KnownSupported` at the
///   universal `[]` version, same "positive claim needs no minimum applet
///   version" shape as [`PivExtension::DeleteKey`] above: a unit whose GET
///   PIV PROPERTIES read doesn't name `0x9B` as a real slot object has no
///   standard management key to rotate, but does have a documented,
///   implemented alternative — HID's own PUT XAUTH KEY against the ACA's
///   XAUTH key 1
///   (`keyroost_transport::PivSession::hid_crescendo_aca_put_xauth_key_op`,
///   dispatched from `keyroost_transport::PivSession::set_management_key`
///   itself). Unlike [`PivExtension::MoveKey`]/[`PivExtension::Reset`] above,
///   this isn't a standing-pattern absence bet — it's a genuine, implemented
///   presence claim, so it's shared with [`HID_CRESCENDO_GENERIC_APPLET_VERDICTS`]
///   the same way [`PivExtension::GetSlotKeyStatus`]'s row is: the capability
///   belongs to the GET PIV PROPERTIES / XAUTH mechanism itself, present
///   across the whole product line, not to two specifically named models.
/// * [`PivExtension::SlotPinPolicy`]/[`PivExtension::SlotTouchPolicy`] —
///   `Verdict::KnownUnsupportedSince` at the universal `[]` version, on the
///   same standing-pattern reasoning as [`PivExtension::MoveKey`] above: this
///   family has never attempted to mimic a Yubico extension APDU, and GET PIV
///   PROPERTIES / INJECT PKI KEY carry no PIN/touch-policy fields of their
///   own to stand in for these two.
/// * [`PivExtension::SlotKeyAlgorithm`] — C2300's own GENERATE KEY PAIR
///   reference
///   (<https://docs.hidglobal.com/crescendo/api/low-level/generate-key-pair.htm>)
///   states outright that "the GENERATE KEY PAIR command is used to generate
///   2048-bit RSA keys, 256-bit EC or 384-bit EC keys" and lists exactly
///   those three in its cryptographic-mechanism-identifier table — a closed
///   enumeration, not a handful of examples — so RSA-2048/ECC P-256/ECC
///   P-384 are `Verdict::KnownSupported` — joining the
///   [`PivExtension::DeleteKey`]/[`PivExtension::GetSlotKeyStatus`]/
///   [`PivExtension::PinManagementAuth`]/[`PivExtension::ResetGlobal`]/
///   [`PivExtension::SetManagementKey`] row above, same verdict — and every
///   other [`crate::KeyAlg`] (RSA-1024/3072/4096, ECC P-521, Ed25519, X25519)
///   is `Verdict::KnownUnsupportedSince` — joining the
///   [`PivExtension::MoveKey`]/[`PivExtension::Attest`]/
///   [`PivExtension::GetMetadata`]/[`PivExtension::Reset`]/
///   [`PivExtension::SetPinPukRetries`]/[`PivExtension::SlotPinPolicy`]/
///   [`PivExtension::SlotTouchPolicy`] row — both at the universal `[]`
///   version. See `HID_CRESCENDO_C4000_APPLET_VERDICTS`'s doc for C4000's
///   own, wider closed list from its own reference. Not shared with
///   [`HID_CRESCENDO_GENERIC_APPLET_VERDICTS`]: the two named families'
///   closed lists differ from each other (C4000's includes RSA-3072/4096,
///   C2300's doesn't), so there's no single list to extend to an
///   unclassified unit.
const HID_CRESCENDO_C2300_APPLET_VERDICTS: &[ExtensionVerdicts] = &[
    // `PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::{Aes192,Aes256})`
    // joins this row: HID Crescendo's ACA XAUTH key rejects both outright —
    // they're outside XAUTH's closed algorithm set (see the
    // `PivExtension::SlotKeyAlgorithm` rows already here for the same
    // closed-enumeration reasoning) — same universal `[]`
    // `Verdict::KnownUnsupportedSince`.
    ExtensionVerdicts {
        extensions: &[
            PivExtension::MoveKey,
            PivExtension::Attest,
            PivExtension::GetMetadata,
            PivExtension::Reset,
            PivExtension::SetPinPukRetries,
            PivExtension::SlotPinPolicy,
            PivExtension::SlotTouchPolicy,
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa1024),
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa3072),
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa4096),
            PivExtension::SlotKeyAlgorithm(KeyAlg::EccP521),
            PivExtension::SlotKeyAlgorithm(KeyAlg::Ed25519),
            PivExtension::SlotKeyAlgorithm(KeyAlg::X25519),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Aes192),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Aes256),
        ],
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownUnsupportedSince,
        }],
    },
    // `PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::{TripleDes,Aes128,
    // Delete})` joins this row: HID Crescendo's ACA XAUTH key accepts 3DES or
    // AES-128 (`hid_crescendo_aca_put_xauth_key`'s own restriction), and —
    // unlike every other fingerprint — can be removed outright via
    // `MgmtAlgChoice::Delete` (`hid_crescendo_aca_put_xauth_key_remove`), same
    // universal `[]` `Verdict::KnownSupported`.
    ExtensionVerdicts {
        extensions: &[
            PivExtension::DeleteKey,
            PivExtension::GetSlotKeyStatus,
            PivExtension::PinManagementAuth,
            PivExtension::ResetGlobal,
            PivExtension::SetManagementKey,
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa2048),
            PivExtension::SlotKeyAlgorithm(KeyAlg::EccP256),
            PivExtension::SlotKeyAlgorithm(KeyAlg::EccP384),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::TripleDes),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Aes128),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Delete),
        ],
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownSupported,
        }],
    },
];

/// See [`YUBIKEY_FIRMWARE_VERDICTS`]'s doc — empty.
const HID_CRESCENDO_C2300_FIRMWARE_VERDICTS: &[ExtensionVerdicts] = &[];

/// HID Crescendo C2300's applet-axis quirks. This fingerprint doesn't
/// support [`PivExtension::Reset`] at all (see `HID_CRESCENDO_C2300_APPLET_VERDICTS`'s
/// Reset row) — [`PivQuirk::ResetNeedsManagementAuth`] here describes its
/// *replacement* mechanism instead (RESET CARD against the ACA instance,
/// [`PivExtension::ResetGlobal`] — see that same const's ResetGlobal row),
/// implemented by `keyroost_transport::PivSession::factory_reset` (see this
/// quirk's own doc). HID Crescendo has no standard PIV management key at
/// all — its "default key" is XAUTH key 1's documented all-zero
/// factory-delivery value ([`HID_CRESCENDO_ACA_FACTORY_XAUTH_KEY`]), seeded
/// here too so `keyroost_transport::PivSession`'s post-RESET-CARD restore
/// step reads it back from this table rather than a separately hard-coded
/// constant. Shared verbatim with [`HID_CRESCENDO_C4000_APPLET_QUIRKS`]/
/// [`HID_CRESCENDO_GENERIC_APPLET_QUIRKS`] below — all three sub-fingerprints
/// get this row, same as `HID_CRESCENDO_C2300_APPLET_VERDICTS`'s Reset row
/// — see its doc for why `Generic` is included alongside the two named
/// models. (Unlike this quirk, that same const's ResetGlobal row
/// deliberately does NOT extend to `Generic` — see that doc for why the two
/// don't follow the same rule here.)
const HID_CRESCENDO_C2300_APPLET_QUIRKS: &[VersionQuirks] = &[VersionQuirks {
    version: &[],
    quirks: &[
        PivQuirk::ResetNeedsManagementAuth,
        PivQuirk::Default9bManagementKey(&HID_CRESCENDO_ACA_FACTORY_XAUTH_KEY),
    ],
}];

/// See [`YUBIKEY_FIRMWARE_QUIRKS`]'s doc — empty.
const HID_CRESCENDO_C2300_FIRMWARE_QUIRKS: &[VersionQuirks] = &[];

/// HID Crescendo C4000's cross-axis merge mode — see [`AxisMergeMode`]'s doc.
const HID_CRESCENDO_C4000_AXIS_MERGE_MODE: AxisMergeMode = AxisMergeMode::MergeRelaxed;

/// HID Crescendo C4000's applet-axis known-support table — same shape and
/// reasoning throughout as `HID_CRESCENDO_C2300_APPLET_VERDICTS` (see its
/// doc for the per-extension detail), with two differences:
///
/// * [`PivExtension::Attest`]/[`PivExtension::GetMetadata`] here are
///   **assumed from documentation, not confirmed on hardware: no C4000 test
///   device has been available.**
///   <https://docs.hidglobal.com/crescendo/api/c4000/get-piv-properties.htm>
///   gives no indication this family gained support for Yubico's
///   non-standard extension APDUs either — the C4000 GET PIV PROPERTIES
///   command is itself HID's own proprietary replacement for the same
///   information GET METADATA would carry, which is already reason enough
///   to expect Yubico's extension is absent here too. Should a real C4000 —
///   or, for that matter, C2300 — unit ever turn out to support either
///   extension after all, this row needs a firmware sample to correct it,
///   exactly like every other verdict here.
/// * [`PivExtension::SetPinPukRetries`] — this family's SDK specifically
///   does document a method that in principle covers this ground —
///   `UpdatePINProperties`
///   (<https://docs.hidglobal.com/hid-crescendo-sdk-v2.1/API%20references/html/classCrescendoDLL_1_1SDKCore.html#a0d787ce0adb6ddf90f14772485af9e3e>)
///   — but its APDU-level wire format is undocumented, so there is no
///   keyroost implementation to gate on: this row blocks C4000 for that
///   reason (no implementation), not because HID has no mechanism for it at
///   all.
/// * [`PivExtension::ResetGlobal`]'s RESET CARD reference
///   (<https://docs.hidglobal.com/crescendo/api/c4000/reset-card.htm>) is
///   C4000's own page, distinct from (but equivalent to) C2300's.
/// * [`PivExtension::SlotPinPolicy`]/[`PivExtension::SlotTouchPolicy`] — same
///   `Verdict::KnownUnsupportedSince` row as
///   `HID_CRESCENDO_C2300_APPLET_VERDICTS`'s — see its doc.
/// * [`PivExtension::SlotKeyAlgorithm`] — unlike every row above, this one
///   *is* confirmed from C4000's own dedicated reference rather than assumed
///   from C2300's:
///   <https://docs.hidglobal.com/crescendo/api/c4000/generate-key-pair.htm>
///   states "the GENERATE KEY PAIR command is used to generate RSA keys
///   (2048, 3072, or 4096 bits) or elliptic curve (EC) keys (256 or 384
///   bits)" and lists exactly those five in its
///   cryptographic-mechanism-identifier table — a closed enumeration, so
///   RSA-2048/3072/4096 and ECC P-256/P-384 are `Verdict::KnownSupported` —
///   joining the [`PivExtension::DeleteKey`]/[`PivExtension::GetSlotKeyStatus`]/
///   [`PivExtension::PinManagementAuth`]/[`PivExtension::ResetGlobal`]/
///   [`PivExtension::SetManagementKey`] row below, same verdict — and
///   RSA-1024/ECC P-521/Ed25519/X25519 are `Verdict::KnownUnsupportedSince`
///   — joining the [`PivExtension::MoveKey`]/[`PivExtension::Attest`]/
///   [`PivExtension::GetMetadata`]/[`PivExtension::Reset`]/
///   [`PivExtension::SetPinPukRetries`]/[`PivExtension::SlotPinPolicy`]/
///   [`PivExtension::SlotTouchPolicy`] row — both at the universal `[]`
///   version. The reference's own EC bit-length list caps out at 384, so
///   P-521 is as absent from it as Ed25519/X25519 are. Wider than
///   `HID_CRESCENDO_C2300_APPLET_VERDICTS`'s own row (which excludes
///   RSA-3072/4096 too) — the two families' closed lists genuinely differ,
///   which is also why this fingerprint isn't shared with
///   [`HID_CRESCENDO_GENERIC_APPLET_VERDICTS`]. See
///   `slot_key_algorithm_apdu_id_override`'s doc for the *wire-byte*
///   question this same reference also answers — RSA-4096 is `0x04` here,
///   not [`crate::KeyAlg::id`]'s `0x16` — a separate axis from this
///   known-support gate.
const HID_CRESCENDO_C4000_APPLET_VERDICTS: &[ExtensionVerdicts] = &[
    // `PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::{Aes192,Aes256})`
    // joins this row: HID Crescendo's ACA XAUTH key rejects both outright —
    // they're outside XAUTH's closed algorithm set (see the
    // `PivExtension::SlotKeyAlgorithm` rows already here for the same
    // closed-enumeration reasoning) — same universal `[]`
    // `Verdict::KnownUnsupportedSince`.
    ExtensionVerdicts {
        extensions: &[
            PivExtension::MoveKey,
            PivExtension::Attest,
            PivExtension::GetMetadata,
            PivExtension::Reset,
            PivExtension::SetPinPukRetries,
            PivExtension::SlotPinPolicy,
            PivExtension::SlotTouchPolicy,
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa1024),
            PivExtension::SlotKeyAlgorithm(KeyAlg::EccP521),
            PivExtension::SlotKeyAlgorithm(KeyAlg::Ed25519),
            PivExtension::SlotKeyAlgorithm(KeyAlg::X25519),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Aes192),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Aes256),
        ],
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownUnsupportedSince,
        }],
    },
    // `PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::{TripleDes,Aes128,
    // Delete})` joins this row: HID Crescendo's ACA XAUTH key accepts 3DES or
    // AES-128 (`hid_crescendo_aca_put_xauth_key`'s own restriction), and —
    // unlike every other fingerprint — can be removed outright via
    // `MgmtAlgChoice::Delete` (`hid_crescendo_aca_put_xauth_key_remove`), same
    // universal `[]` `Verdict::KnownSupported`.
    ExtensionVerdicts {
        extensions: &[
            PivExtension::DeleteKey,
            PivExtension::GetSlotKeyStatus,
            PivExtension::PinManagementAuth,
            PivExtension::ResetGlobal,
            PivExtension::SetManagementKey,
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa2048),
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa3072),
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa4096),
            PivExtension::SlotKeyAlgorithm(KeyAlg::EccP256),
            PivExtension::SlotKeyAlgorithm(KeyAlg::EccP384),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::TripleDes),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Aes128),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Delete),
        ],
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownSupported,
        }],
    },
];

/// See [`YUBIKEY_FIRMWARE_VERDICTS`]'s doc — empty.
const HID_CRESCENDO_C4000_FIRMWARE_VERDICTS: &[ExtensionVerdicts] = &[];

/// HID Crescendo C4000's applet-axis quirks — same row as
/// [`HID_CRESCENDO_C2300_APPLET_QUIRKS`] above; see its doc.
const HID_CRESCENDO_C4000_APPLET_QUIRKS: &[VersionQuirks] = &[VersionQuirks {
    version: &[],
    quirks: &[
        PivQuirk::ResetNeedsManagementAuth,
        PivQuirk::Default9bManagementKey(&HID_CRESCENDO_ACA_FACTORY_XAUTH_KEY),
    ],
}];

/// See [`YUBIKEY_FIRMWARE_QUIRKS`]'s doc — empty.
const HID_CRESCENDO_C4000_FIRMWARE_QUIRKS: &[VersionQuirks] = &[];

/// HID Crescendo Generic's cross-axis merge mode — see [`AxisMergeMode`]'s
/// doc.
const HID_CRESCENDO_GENERIC_AXIS_MERGE_MODE: AxisMergeMode = AxisMergeMode::MergeRelaxed;

/// HID Crescendo Generic's (matched via select identity only — neither C2300
/// nor C4000 applies) applet-axis known-support table:
///
/// * [`PivExtension::MoveKey`], [`PivExtension::Reset`],
///   [`PivExtension::SetPinPukRetries`], [`PivExtension::SlotPinPolicy`],
///   [`PivExtension::SlotTouchPolicy`] — share one row:
///   `Verdict::KnownUnsupportedSince` at the universal `[]` version, shared
///   with `HID_CRESCENDO_C2300_APPLET_VERDICTS`/`HID_CRESCENDO_C4000_APPLET_VERDICTS`:
///   the reasoning ("never implements a Yubico extension APDU, always ships
///   its own") is about the vendor's pattern across the whole product line,
///   not about a specific tested model, the same broadening
///   `keyroost_piv::fingerprint`'s ACA AID doc applies to the
///   transport-level XAUTH fallback.
/// * [`PivExtension::GetSlotKeyStatus`]/[`PivExtension::SetManagementKey`] —
///   share one row: both `Verdict::KnownSupported` at the universal `[]`
///   version, shared with the two named models for the same
///   vendor-wide-pattern reasoning: each is a property of a mechanism
///   present, in some form, across the whole product line (GET PIV
///   PROPERTIES for the former, GET PIV PROPERTIES plus PUT XAUTH KEY for the
///   latter — see `HID_CRESCENDO_C2300_APPLET_VERDICTS`'s doc), not a claim
///   tied to two specifically named, individually tested models the way
///   [`PivExtension::DeleteKey`] below is.
/// * No entries for [`PivExtension::DeleteKey`] (the C2300/C4000 presence
///   claim isn't general enough to extend here — see
///   `HID_CRESCENDO_C2300_APPLET_VERDICTS`'s doc), [`PivExtension::Attest`],
///   [`PivExtension::GetMetadata`], [`PivExtension::PinManagementAuth`], or
///   [`PivExtension::ResetGlobal`] (see that extension's bullet on
///   `HID_CRESCENDO_C2300_APPLET_VERDICTS`'s doc for why a presence claim
///   doesn't reach `Generic`), or [`PivExtension::SlotKeyAlgorithm`] (C2300's
///   and C4000's own GENERATE KEY PAIR references document two genuinely
///   different closed algorithm lists — see
///   `HID_CRESCENDO_C4000_APPLET_VERDICTS`'s doc — so there's no single
///   list to extend to an unclassified unit; `slot_key_algorithm_apdu_id_override`'s
///   *wire-byte* answer still applies to `Generic`, though — see its doc for
///   why that's a different axis this reasoning doesn't touch).
const HID_CRESCENDO_GENERIC_APPLET_VERDICTS: &[ExtensionVerdicts] = &[
    // `PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::{Aes192,Aes256})`
    // joins this row: HID Crescendo's ACA XAUTH key rejects both outright —
    // they're outside XAUTH's closed algorithm set, the same
    // closed-enumeration reasoning `HID_CRESCENDO_C2300_APPLET_VERDICTS`'s
    // own `PivExtension::SlotKeyAlgorithm` rows use — same universal `[]`
    // `Verdict::KnownUnsupportedSince`.
    ExtensionVerdicts {
        extensions: &[
            PivExtension::MoveKey,
            PivExtension::Reset,
            PivExtension::SetPinPukRetries,
            PivExtension::SlotPinPolicy,
            PivExtension::SlotTouchPolicy,
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Aes192),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Aes256),
        ],
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownUnsupportedSince,
        }],
    },
    // `PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::{TripleDes,Aes128,
    // Delete})` joins this row: HID Crescendo's ACA XAUTH key accepts 3DES or
    // AES-128 (`hid_crescendo_aca_put_xauth_key`'s own restriction), and —
    // unlike every other fingerprint — can be removed outright via
    // `MgmtAlgChoice::Delete` (`hid_crescendo_aca_put_xauth_key_remove`), same
    // universal `[]` `Verdict::KnownSupported`.
    ExtensionVerdicts {
        extensions: &[
            PivExtension::GetSlotKeyStatus,
            PivExtension::SetManagementKey,
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::TripleDes),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Aes128),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Delete),
        ],
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownSupported,
        }],
    },
];

/// See [`YUBIKEY_FIRMWARE_VERDICTS`]'s doc — empty.
const HID_CRESCENDO_GENERIC_FIRMWARE_VERDICTS: &[ExtensionVerdicts] = &[];

/// HID Crescendo Generic's applet-axis quirks — same row as
/// [`HID_CRESCENDO_C2300_APPLET_QUIRKS`] above; see its doc for why `Generic`
/// gets the same row as the two named models here.
const HID_CRESCENDO_GENERIC_APPLET_QUIRKS: &[VersionQuirks] = &[VersionQuirks {
    version: &[],
    quirks: &[
        PivQuirk::ResetNeedsManagementAuth,
        PivQuirk::Default9bManagementKey(&HID_CRESCENDO_ACA_FACTORY_XAUTH_KEY),
    ],
}];

/// See [`YUBIKEY_FIRMWARE_QUIRKS`]'s doc — empty.
const HID_CRESCENDO_GENERIC_FIRMWARE_QUIRKS: &[VersionQuirks] = &[];

/// [`AppletFingerprint::Generic`]'s cross-axis merge mode — see
/// [`AxisMergeMode`]'s doc.
const GENERIC_AXIS_MERGE_MODE: AxisMergeMode = AxisMergeMode::MergeRelaxed;

/// [`AppletFingerprint::Generic`]'s applet-axis known-support table — a
/// single entry pairing [`PivExtension::ResetGlobal`] with
/// [`PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Delete)`](PivExtension::ManagementKeyAlgorithm),
/// both `Verdict::KnownUnsupportedSince` at the universal `[]` version.
/// Every non-HID-Crescendo fingerprint's table carries this same
/// [`PivExtension::ResetGlobal`] entry — deliberately explicit rather than
/// left absent (which would resolve [`FeatureGate::Unverified`], same as any
/// fingerprint with no entry for this extension): `PivSession::factory_reset`
/// checks this gate *first*, ahead of [`PivExtension::Reset`]'s own shape —
/// an `Unverified` default here would make a *non*-HID-Crescendo device with
/// a genuinely working [`PivExtension::Reset`] path (e.g. the PIN/PUK-burn
/// convention) attempt HID's ACA RESET CARD mechanism first instead, fail
/// (there's no such applet on that card), and never fall through to the
/// mechanism that would have worked. An explicit
/// `Verdict::KnownUnsupportedSince` here closes that: every fingerprint
/// that isn't HID Crescendo is a flat "no" on this axis, not "no data yet".
/// This is why [`YUBIKEY_APPLET_VERDICTS`], `TOKEN2_APPLET_VERDICTS`,
/// [`SWISSBIT_ISHIELD2_APPLET_VERDICTS`], [`THETIS_APPLET_VERDICTS`], and
/// both `ArekinathPivApplet` tables above each also carry their own explicit
/// [`PivExtension::ResetGlobal`] entry instead of being left absent, and why
/// [`AUTHENTREND_ATKEY_APPLET_VERDICTS`], [`IDPRIME_APPLET_VERDICTS`],
/// `TRUSSED_NITROKEY_APPLET_VERDICTS`, [`UTRUST_GENERIC_APPLET_VERDICTS`],
/// and [`UTRUST_GOV_APPLET_VERDICTS`] below are each a single-entry table
/// with exactly this same row. [`FEITIAN_APPLET_VERDICTS`] and
/// [`OPENFIPS201_GENERIC_APPLET_VERDICTS`] each carry this same row too,
/// alongside further rows of their own now — see their own docs.
///
/// [`PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Delete)`](PivExtension::ManagementKeyAlgorithm)
/// joins the [`PivExtension::ResetGlobal`] row rather than getting an entry
/// of its own: no standard PIV equivalent on this fingerprint — the
/// management key is mandatory, never removable — so it resolves the same
/// way. No entry for the four real algorithms: keyroost has no known-support
/// data for this fingerprint's management-key algorithm, so each resolves
/// [`FeatureGate::Unverified`] rather than being asserted one way or the
/// other.
const GENERIC_APPLET_VERDICTS: &[ExtensionVerdicts] = &[ExtensionVerdicts {
    extensions: &[
        PivExtension::ResetGlobal,
        PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Delete),
    ],
    verdicts: &[VersionVerdict {
        version: &[],
        verdict: Verdict::KnownUnsupportedSince,
    }],
}];

/// See [`YUBIKEY_FIRMWARE_VERDICTS`]'s doc — empty.
const GENERIC_FIRMWARE_VERDICTS: &[ExtensionVerdicts] = &[];

/// [`AppletFingerprint::Generic`]'s applet-axis quirks. No more specific
/// fingerprint matched, but a device that speaks plain PIV with nothing else
/// recognisable about it is, in practice, overwhelmingly likely to ship the
/// same YubiKey-mimicked default every other unrecognised third-party
/// implementation does.
const GENERIC_APPLET_QUIRKS: &[VersionQuirks] = &[VersionQuirks {
    version: &[],
    quirks: &[PivQuirk::Default9bManagementKey(YUBIKEY_DEFAULT_MGMT_KEY)],
}];

/// See [`YUBIKEY_FIRMWARE_QUIRKS`]'s doc — empty.
const GENERIC_FIRMWARE_QUIRKS: &[VersionQuirks] = &[];

/// Authentrend's ATkey's cross-axis merge mode — see [`AxisMergeMode`]'s doc.
const AUTHENTREND_ATKEY_AXIS_MERGE_MODE: AxisMergeMode = AxisMergeMode::MergeRelaxed;

/// Authentrend's ATkey's applet-axis known-support table — see
/// `GENERIC_APPLET_VERDICTS`'s doc for why this fingerprint gets an
/// explicit [`PivExtension::ResetGlobal`] entry, and why
/// [`PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Delete)`](PivExtension::ManagementKeyAlgorithm)
/// joins that same entry instead of getting one of its own.
///
/// The [`PivExtension::SetPinPukRetries`]/[`PivExtension::SetManagementKey`]/
/// [`PivExtension::DeleteKey`]/[`PivExtension::MoveKey`]/
/// [`PivExtension::GetMetadata`]/[`PivExtension::PinManagementAuth`]/
/// [`PivExtension::SlotPinPolicy`]/[`PivExtension::SlotTouchPolicy`]/
/// [`PivExtension::Reset`] row below, and the [`PivExtension::SlotKeyAlgorithm`]
/// rows after it, are hardware-observed on a live applet v6.0.1 unit: applet
/// v6 mimics the YubiKey PIV extension set close to completely — every one
/// of those nine extensions is accepted, and [`crate::KeyAlg::Rsa1024`]/
/// [`crate::KeyAlg::Rsa2048`]/[`crate::KeyAlg::EccP256`]/
/// [`crate::KeyAlg::EccP384`] are all accepted as a slot key algorithm.
/// [`MgmtAlgChoice::TripleDes`]/[`MgmtAlgChoice::Aes128`]/
/// [`MgmtAlgChoice::Aes192`]/[`MgmtAlgChoice::Aes256`] join the same row too:
/// all four are accepted as the management key's algorithm on the same unit
/// — distinct from [`MgmtAlgChoice::Delete`] right above, which stays its
/// own separate `Verdict::KnownUnsupportedSince` row regardless (the
/// management key is mandatory on this fingerprint, never removable, same
/// as every other non-HID-Crescendo one). Every extension and algorithm on
/// this row gets a `Verdict::KnownSupported` verdict keyed to `[6]`, not
/// the exact tested version `[6, 0, 1]`: only one v6.0.1 unit was actually
/// probed, but the whole v6 lineup is assumed to share this support, so the
/// verdict is deliberately floored at the major version rather than the
/// precise build — a deviation, spelled out here rather than left implicit,
/// from this module's usual "key the verdict to exactly what was tested"
/// discipline. Per `Verdict::KnownSupported`'s own no-regression-forward
/// assumption, no claim is made about any version before `[6]`.
/// [`crate::KeyAlg::Rsa3072`]/[`crate::KeyAlg::Rsa4096`]/
/// [`crate::KeyAlg::EccP521`]/[`crate::KeyAlg::Ed25519`]/
/// [`crate::KeyAlg::X25519`] were rejected on the same unit, so they instead
/// get a `Verdict::KnownUnsupported` row at the exact tested version,
/// `[6, 0, 1]` — kept there rather than widened to `[6]` the same way,
/// since nothing here assumes the rest of the v6 lineup shares an
/// *absence*: the ordinary "observed absence" verdict, not
/// `Verdict::KnownUnsupportedSince`, so a later applet version is left
/// free to soften back to [`FeatureGate::Unverified`] rather than being
/// asserted unsupported forever.
const AUTHENTREND_ATKEY_APPLET_VERDICTS: &[ExtensionVerdicts] = &[
    ExtensionVerdicts {
        extensions: &[
            PivExtension::ResetGlobal,
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Delete),
        ],
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownUnsupportedSince,
        }],
    },
    ExtensionVerdicts {
        extensions: &[
            PivExtension::SetPinPukRetries,
            PivExtension::SetManagementKey,
            PivExtension::DeleteKey,
            PivExtension::MoveKey,
            PivExtension::GetMetadata,
            PivExtension::PinManagementAuth,
            PivExtension::SlotPinPolicy,
            PivExtension::SlotTouchPolicy,
            PivExtension::Reset,
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa1024),
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa2048),
            PivExtension::SlotKeyAlgorithm(KeyAlg::EccP256),
            PivExtension::SlotKeyAlgorithm(KeyAlg::EccP384),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::TripleDes),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Aes128),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Aes192),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Aes256),
        ],
        verdicts: &[VersionVerdict {
            version: &[6],
            verdict: Verdict::KnownSupported,
        }],
    },
    ExtensionVerdicts {
        extensions: &[
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa3072),
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa4096),
            PivExtension::SlotKeyAlgorithm(KeyAlg::EccP521),
            PivExtension::SlotKeyAlgorithm(KeyAlg::Ed25519),
            PivExtension::SlotKeyAlgorithm(KeyAlg::X25519),
        ],
        verdicts: &[VersionVerdict {
            version: &[6, 0, 1],
            verdict: Verdict::KnownUnsupported,
        }],
    },
];

/// See [`YUBIKEY_FIRMWARE_VERDICTS`]'s doc — empty.
const AUTHENTREND_ATKEY_FIRMWARE_VERDICTS: &[ExtensionVerdicts] = &[];

/// Authentrend's ATkey's applet-axis quirks: mimics the YubiKey PIV
/// factory-default management key like most other third-party
/// implementations do. No version-gated quirk observed on this fingerprint.
const AUTHENTREND_ATKEY_APPLET_QUIRKS: &[VersionQuirks] = &[VersionQuirks {
    version: &[],
    quirks: &[PivQuirk::Default9bManagementKey(YUBIKEY_DEFAULT_MGMT_KEY)],
}];

/// See [`YUBIKEY_FIRMWARE_QUIRKS`]'s doc — empty.
const AUTHENTREND_ATKEY_FIRMWARE_QUIRKS: &[VersionQuirks] = &[];

/// Feitian's cross-axis merge mode — see [`AxisMergeMode`]'s doc.
const FEITIAN_AXIS_MERGE_MODE: AxisMergeMode = AxisMergeMode::MergeRelaxed;

/// Feitian's applet-axis known-support table — see
/// `GENERIC_APPLET_VERDICTS`'s doc for why this fingerprint gets an
/// explicit [`PivExtension::ResetGlobal`] entry. [`PivExtension::ResetGlobal`]
/// itself: Feitian's own SK Manager tool
/// (<https://fido.ftsafe.com/feitian-sk-manager-tool-user-manual/>, the same
/// source [`FEITIAN_DEFAULT_MGMT_KEY`] cites) implies a proprietary
/// reset/provisioning path exists on this hardware, but keyroost hasn't
/// reverse-engineered it, so from keyroost's point of view the extension
/// stays unsupported regardless of what the device itself can do.
///
/// The [`PivExtension::SetManagementKey`]/[`PivExtension::SetPinPukRetries`]/
/// [`PivExtension::MoveKey`]/[`PivExtension::DeleteKey`]/
/// [`PivExtension::GetMetadata`] rows below are hardware-observed
/// `Verdict::KnownUnsupported` at applet version `[0]` on a live unit —
/// none of Yubico's vendor-extension APDUs these five represent are accepted.
/// [`PivExtension::SetManagementKey`] specifically shares
/// [`PivExtension::ResetGlobal`]'s reasoning above: the same SK Manager tool
/// implies Feitian has its own proprietary management-key-change mechanism,
/// not Yubico's SET MANAGEMENT KEY APDU — keyroost hasn't implemented that
/// proprietary mechanism yet, so this extension is unsupported by keyroost
/// today independent of the device's own capability.
///
/// [`PivExtension::SlotPinPolicy`]/[`PivExtension::SlotTouchPolicy`] join the
/// same hardware-observed `Verdict::KnownUnsupported` group at applet
/// version `[0]`: the live unit's GENERATE ASYMMETRIC KEYPAIR rejects both
/// the `0xAA` and `0xAB` tags. [`PivExtension::PinManagementAuth`] joins the
/// same row on the same live unit: PIN VERIFY doesn't unlock the standard
/// [`crate::OBJECT_PIN_PROTECTED_DATA`] object the indirect mechanism reads.
///
/// [`PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Delete)`](PivExtension::ManagementKeyAlgorithm)
/// joins the [`PivExtension::ResetGlobal`] row instead of getting an entry of
/// its own — see `GENERIC_APPLET_VERDICTS`'s doc for why.
///
/// [`PivExtension::SlotKeyAlgorithm`]`(`[`KeyAlg::Rsa3072`]/[`KeyAlg::Rsa4096`]/
/// [`KeyAlg::EccP521`]/[`KeyAlg::Ed25519`]/[`KeyAlg::X25519`]`)` join the same
/// `Verdict::KnownUnsupported` `[0]` row above — same live unit's GENERATE
/// ASYMMETRIC KEYPAIR rejects all five. The separate row below,
/// [`KeyAlg::Rsa1024`]/[`KeyAlg::Rsa2048`]/[`KeyAlg::EccP256`]/
/// [`KeyAlg::EccP384`], is `Verdict::KnownSupported` instead — the same unit
/// accepts all four — so it can't join that row; both stay pinned to the
/// exact tested version `[0]` rather than widened to a major version the way
/// [`AUTHENTREND_ATKEY_APPLET_VERDICTS`] does — only a v0 unit has been
/// probed here, so no claim is made about any other version either way.
const FEITIAN_APPLET_VERDICTS: &[ExtensionVerdicts] = &[
    ExtensionVerdicts {
        extensions: &[
            PivExtension::ResetGlobal,
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Delete),
        ],
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownUnsupportedSince,
        }],
    },
    ExtensionVerdicts {
        extensions: &[
            PivExtension::SetManagementKey,
            PivExtension::SetPinPukRetries,
            PivExtension::MoveKey,
            PivExtension::DeleteKey,
            PivExtension::GetMetadata,
            PivExtension::SlotPinPolicy,
            PivExtension::SlotTouchPolicy,
            PivExtension::PinManagementAuth,
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa3072),
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa4096),
            PivExtension::SlotKeyAlgorithm(KeyAlg::EccP521),
            PivExtension::SlotKeyAlgorithm(KeyAlg::Ed25519),
            PivExtension::SlotKeyAlgorithm(KeyAlg::X25519),
        ],
        verdicts: &[VersionVerdict {
            version: &[0],
            verdict: Verdict::KnownUnsupported,
        }],
    },
    ExtensionVerdicts {
        extensions: &[
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa1024),
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa2048),
            PivExtension::SlotKeyAlgorithm(KeyAlg::EccP256),
            PivExtension::SlotKeyAlgorithm(KeyAlg::EccP384),
        ],
        verdicts: &[VersionVerdict {
            version: &[0],
            verdict: Verdict::KnownSupported,
        }],
    },
];

/// See [`YUBIKEY_FIRMWARE_VERDICTS`]'s doc — empty.
const FEITIAN_FIRMWARE_VERDICTS: &[ExtensionVerdicts] = &[];

/// Feitian's applet-axis quirks: this vendor ships its own vendor-specific
/// PIV factory-default management key rather than mimicking YubiKey's — see
/// [`FEITIAN_DEFAULT_MGMT_KEY`]'s doc.
const FEITIAN_APPLET_QUIRKS: &[VersionQuirks] = &[VersionQuirks {
    version: &[],
    quirks: &[PivQuirk::Default9bManagementKey(FEITIAN_DEFAULT_MGMT_KEY)],
}];

/// See [`YUBIKEY_FIRMWARE_QUIRKS`]'s doc — empty.
const FEITIAN_FIRMWARE_QUIRKS: &[VersionQuirks] = &[];

/// Gemalto/Thales IDPrime's cross-axis merge mode — see [`AxisMergeMode`]'s
/// doc.
const IDPRIME_AXIS_MERGE_MODE: AxisMergeMode = AxisMergeMode::MergeRelaxed;

/// Gemalto/Thales IDPrime's applet-axis known-support table — see
/// `GENERIC_APPLET_VERDICTS`'s doc for why this fingerprint gets an
/// explicit [`PivExtension::ResetGlobal`] entry, and why
/// [`PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Delete)`](PivExtension::ManagementKeyAlgorithm)
/// joins that same entry instead of getting one of its own.
///
/// [`PivExtension::SetManagementKey`]/[`PivExtension::SetPinPukRetries`]/
/// [`PivExtension::MoveKey`]/[`PivExtension::DeleteKey`] join the same row,
/// same universal `[]` `Verdict::KnownUnsupportedSince`: IDPrime doesn't
/// mimic any of Yubico's vendor-extension APDUs these four represent — it's
/// built on its own applet with its own proprietary commands for
/// key/PIN/PUK/management-key administration instead — so keyroost has no
/// working mechanism for any of them on this fingerprint, independent of
/// whatever the device itself can do, the same reasoning
/// [`FEITIAN_APPLET_VERDICTS`]'s doc uses for its own identical row.
/// [`PivExtension::Reset`] joins the row too, on the same reasoning as
/// [`PivExtension::ResetGlobal`] right beside it: IDPrime hasn't been
/// observed to accept Yubico's `INS 0xFB` RESET either, PIV-scoped or
/// otherwise, so keyroost has no working reset mechanism for this
/// fingerprint at all yet.
/// [`PivExtension::SlotPinPolicy`]/[`PivExtension::SlotTouchPolicy`] get
/// their own row rather than joining the one above: unlike MOVE KEY/DELETE
/// KEY/RESET/SET MANAGEMENT KEY/SET PIN PUK RETRIES (Yubico's own vendor
/// extension APDUs, which this vendor has no track record of mimicking and
/// so get the stronger `Verdict::KnownUnsupportedSince`), pin/touch policy
/// are standard SP 800-73-4 tags (`0xAA`/`0xAB` on GENERATE ASYMMETRIC
/// KEYPAIR) — a future IDPrime firmware plausibly could add them, so this is
/// plain `Verdict::KnownUnsupported` instead, softening to
/// [`FeatureGate::Unverified`] rather than staying blocked forever.
/// [`PivExtension::PinManagementAuth`] joins the same row on the same
/// reasoning: PIN VERIFY on this fingerprint doesn't unlock the standard
/// [`crate::OBJECT_PIN_PROTECTED_DATA`] object the indirect mechanism reads
/// (see that extension's own doc), but the object itself is standard SP
/// 800-73-4, not a Yubico vendor extension, so a future IDPrime firmware
/// plausibly could populate it — plain `Verdict::KnownUnsupported`, not
/// the stronger `Since`. Seeded at
/// the universal `[]` floor with no bracketing `Verdict::KnownSupported`
/// entry above it (unlike e.g. [`YUBIKEY_APPLET_VERDICTS`]'s `Attest` row) —
/// per [`resolve_in`]'s bracketing rule, that means only a query that
/// reports version `[]` itself resolves [`FeatureGate::Unsupported`]; any
/// actually-reported (non-empty) version softens straight to
/// [`FeatureGate::Unverified`], same as no data at all. Narrow this to a real
/// tested floor — or add a bracketing entry — once a version-tagged report
/// comes in.
///
/// [`PivExtension::SlotKeyAlgorithm`]`(`[`KeyAlg::Rsa2048`]`)` gets a row of
/// its own rather than joining either row above: hardware-observed
/// `Verdict::KnownSupported` at the same universal `[]` floor — the live
/// unit's GENERATE ASYMMETRIC KEYPAIR accepts RSA-2048 — which is neither of
/// the two verdicts already seeded here. No other algorithm has been probed
/// on this fingerprint yet, so nothing else is claimed either way.
const IDPRIME_APPLET_VERDICTS: &[ExtensionVerdicts] = &[
    ExtensionVerdicts {
        extensions: &[
            PivExtension::ResetGlobal,
            PivExtension::Reset,
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Delete),
            PivExtension::SetManagementKey,
            PivExtension::SetPinPukRetries,
            PivExtension::MoveKey,
            PivExtension::DeleteKey,
        ],
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownUnsupportedSince,
        }],
    },
    ExtensionVerdicts {
        extensions: &[
            PivExtension::SlotPinPolicy,
            PivExtension::SlotTouchPolicy,
            PivExtension::PinManagementAuth,
        ],
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownUnsupported,
        }],
    },
    ExtensionVerdicts {
        extensions: &[PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa2048)],
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownSupported,
        }],
    },
];

/// See [`YUBIKEY_FIRMWARE_VERDICTS`]'s doc — empty.
const IDPRIME_FIRMWARE_VERDICTS: &[ExtensionVerdicts] = &[];

/// Gemalto/Thales IDPrime's applet-axis quirks, both hardware-observed on a
/// live unit and both seeded at the universal `[]` floor rather than a
/// specific applet version — neither observation carried a version read, so
/// there's no narrower bound to give either yet; narrow this once a
/// version-tagged report comes in, the same way every other `version: &[]`
/// entry in this module is a "least specific true statement" placeholder, not
/// a claim that older/newer versions are unaffected:
///
/// * [`PivQuirk::HostChallengeResponsePermissiveTag`] — management-key
///   mutual-auth step 2 answers with the encrypted host challenge under tag
///   `0x80` instead of `0x82`; see that variant's own doc.
/// * [`PivQuirk::Default9bManagementKey`] — the unit's factory-default `0x9B`
///   key is the same 16-byte AES-128 pattern `IDPRIME_AND_UTRUST_GOV_DEFAULT_MGMT_KEY`
///   already names for uTrust Gov; see [`PivQuirk::Default9bManagementKey`]'s
///   doc for why that constant is reused here rather than duplicated.
const IDPRIME_APPLET_QUIRKS: &[VersionQuirks] = &[VersionQuirks {
    version: &[],
    quirks: &[
        PivQuirk::HostChallengeResponsePermissiveTag,
        PivQuirk::Default9bManagementKey(IDPRIME_AND_UTRUST_GOV_DEFAULT_MGMT_KEY),
    ],
}];

/// See [`YUBIKEY_FIRMWARE_QUIRKS`]'s doc — empty.
const IDPRIME_FIRMWARE_QUIRKS: &[VersionQuirks] = &[];

/// The Trussed-based Nitrokey's (`Trussed::NitroKey`) cross-axis merge mode
/// — see [`AxisMergeMode`]'s doc.
const TRUSSED_NITROKEY_AXIS_MERGE_MODE: AxisMergeMode = AxisMergeMode::MergeRelaxed;

/// The Trussed-based Nitrokey's (`Trussed::NitroKey`) applet-axis
/// known-support table — see `GENERIC_APPLET_VERDICTS`'s doc for why this
/// fingerprint gets an explicit [`PivExtension::ResetGlobal`] entry, same
/// single-row shape as every other non-HID-Crescendo fingerprint's
/// applet-axis table: a lone `Verdict::KnownUnsupportedSince` verdict at
/// the universal `[]` version. This row is deliberately repeated on
/// [`TRUSSED_NITROKEY_FIRMWARE_VERDICTS`] too — see that const's own doc for
/// why carrying the same flat "no" on both axes is intentional, not
/// leftover duplication. No [`PivExtension::SetManagementKey`] entry here
/// any more — its only evidence now lives on
/// [`TRUSSED_NITROKEY_FIRMWARE_VERDICTS`], pinned to the firmware version
/// keyroost actually has confirmation at; see that const's own doc.
///
/// Deliberately thin beyond that single row, and deliberately never grown to
/// key anything to the *applet* version: the Trussed `piv-authenticator`'s
/// reply to Yubico's `GET VERSION` extension (`INS 0xFD`) is not a real
/// version at all. Its `src/lib.rs`, the `YubicoPivExtension::GetVersion`
/// arm, hard-codes the reply outright (`// make up a version, be >= 5.0.0`,
/// then the literal bytes `06 06 06`) —
/// <https://github.com/trussed-dev/piv-authenticator> — so every Trussed
/// unit, on every firmware, on every hardware revision, answers this
/// extension identically with "6.6.6". A live unit confirms it: firmware
/// 1.8.3 reports this same dummy "6.6.6" applet version. Version-gating a
/// verdict on that value would apply identically to every unit ever made —
/// no different from the universal `[]` row already used here — so it can
/// never actually distinguish one firmware's behavior from another's. The
/// axis that genuinely varies is the *firmware* version, read separately via
/// Nitrokey's own admin application (see
/// `keyroost_transport::PivStatus::version_firmware`'s doc) — that's what
/// [`TRUSSED_NITROKEY_FIRMWARE_VERDICTS`] keys its rows to, and why this
/// fingerprint is the one exception noted on that const's own doc rather
/// than following [`YUBIKEY_FIRMWARE_VERDICTS`]'s "always empty" norm.
///
/// [`PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Delete)`](PivExtension::ManagementKeyAlgorithm)
/// joins the [`PivExtension::ResetGlobal`] row below instead of getting an
/// entry of its own — see `GENERIC_APPLET_VERDICTS`'s doc for why. The four
/// real algorithms are instead gated on the firmware axis, in
/// [`TRUSSED_NITROKEY_FIRMWARE_VERDICTS`] — see its own doc.
const TRUSSED_NITROKEY_APPLET_VERDICTS: &[ExtensionVerdicts] = &[ExtensionVerdicts {
    extensions: &[
        PivExtension::ResetGlobal,
        PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Delete),
    ],
    verdicts: &[VersionVerdict {
        version: &[],
        verdict: Verdict::KnownUnsupportedSince,
    }],
}];

/// The Trussed-based Nitrokey's (`Trussed::NitroKey`) firmware-axis
/// known-support table — the one exception to [`YUBIKEY_FIRMWARE_VERDICTS`]'s
/// "every `_FIRMWARE_VERDICTS` const is empty" doc, because keyroost's
/// evidence for these extensions is firmware-version keyed, not
/// applet-version keyed: the applet version this fingerprint reports is a
/// hard-coded dummy ("6.6.6", identical on every unit) rather than a real
/// one, so the firmware version is the only axis actually capable of
/// resolving a verdict here — see `TRUSSED_NITROKEY_APPLET_VERDICTS`'s doc
/// for where that dummy value comes from.
///
/// * [`PivExtension::ResetGlobal`] — `Verdict::KnownUnsupportedSince` at
///   the universal `[]` version, deliberately repeated from
///   `TRUSSED_NITROKEY_APPLET_VERDICTS`'s own row rather than left off this
///   table: both axes carry the same flat "no" independently, so a caller
///   that only has a firmware version to report (say, the applet version
///   never answered) still sees the known-unsupported verdict rather than
///   falling through to [`FeatureGate::Unverified`]. Harmless duplication —
///   [`resolve`]'s combination rule already treats either axis resolving
///   `Unsupported` as authoritative — kept here as belt-and-suspenders
///   coverage rather than relying on the applet axis alone.
/// * [`PivExtension::SetManagementKey`], [`PivExtension::Reset`],
///   [`PivExtension::GetMetadata`], [`PivExtension::PinManagementAuth`] —
///   `Verdict::KnownSupported` at firmware `[1, 8]`: the Trussed
///   `piv-authenticator` source confirms the first three
///   (<https://github.com/trussed-dev/piv-authenticator>), corroborated by a
///   live unit at firmware 1.8.3 accepting all four, PIN VERIFY unlocking
///   management included.
/// * [`PivExtension::SetPinPukRetries`], [`PivExtension::MoveKey`],
///   [`PivExtension::DeleteKey`], [`PivExtension::Attest`],
///   [`PivExtension::SlotPinPolicy`], [`PivExtension::SlotTouchPolicy`] —
///   `Verdict::KnownUnsupported` pinned to exactly the version keyroost has
///   evidence for, firmware 1.8.3 (`[1, 8, 3]`): a live unit there rejects
///   all six, corroborated for the two policy rows by the Trussed
///   `piv-authenticator` source itself
///   (<https://github.com/trussed-dev/piv-authenticator>), which implements
///   no `0xAA`/`0xAB` handling on GENERATE ASYMMETRIC KEYPAIR. Per
///   `Verdict::KnownUnsupported`'s backward-extension rule this is assumed
///   to also hold at every earlier, untested version — including 1.8 itself —
///   without a separate `[1, 8]` entry on these rows; the single `[1, 8, 3]`
///   verdict already covers both. A firmware newer than 1.8.3 with no verdict
///   of its own softens to [`FeatureGate::Unverified`] rather than staying
///   `Unsupported`, since a later firmware may have added any of these six —
///   unlike [`PivExtension::ResetGlobal`]'s `Verdict::KnownUnsupportedSince`
///   row above, which has a standing reason (this vendor's own architecture)
///   to expect it never comes back.
/// * [`PivExtension::SlotKeyAlgorithm`] — RSA-2048, RSA-4096, and ECC P-256
///   are supported on every firmware keyroost has evidence for, pre-1.8.2 and
///   1.8.2-and-later alike: one `Verdict::KnownSupported` row at the
///   universal `[]` version, no known-unsupported floor to gate below. RSA-4096
///   is grouped in here even though its *wire byte* changes at the same 1.8.2
///   boundary — see `slot_key_algorithm_apdu_id_override`'s own doc — since
///   that's a separate axis from whether the algorithm is supported at all,
///   same distinction `HID_CRESCENDO_C4000_APPLET_VERDICTS`'s own
///   [`PivExtension::SlotKeyAlgorithm`] doc draws. RSA-3072 and ECC P-384 are
///   new at 1.8.2: the same two-tier `Verdict::KnownUnsupported`-then-
///   `Verdict::KnownSupported` shape as this table's own
///   [`PivExtension::SetManagementKey`]/[`PivExtension::Reset`]/
///   [`PivExtension::GetMetadata`]/[`PivExtension::PinManagementAuth`] row
///   above, pinned to `[1, 8, 2]` rather than that row's `[1, 8]` — this
///   crate's evidence places the boundary one patch release later for these
///   two algorithms specifically. RSA-1024, ECC
///   P-521, and Ed25519/X25519 are absent from the Trussed `piv-authenticator`
///   source's own supported-algorithm set at every firmware generation
///   examined, so they join [`PivExtension::ResetGlobal`]'s row above — same
///   `Verdict::KnownUnsupportedSince` at the universal `[]` version — the
///   same closed-enumeration reasoning `HID_CRESCENDO_C2300_APPLET_VERDICTS`'s
///   own row uses.
const TRUSSED_NITROKEY_FIRMWARE_VERDICTS: &[ExtensionVerdicts] = &[
    ExtensionVerdicts {
        extensions: &[
            PivExtension::ResetGlobal,
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa1024),
            PivExtension::SlotKeyAlgorithm(KeyAlg::EccP521),
            PivExtension::SlotKeyAlgorithm(KeyAlg::Ed25519),
            PivExtension::SlotKeyAlgorithm(KeyAlg::X25519),
        ],
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownUnsupportedSince,
        }],
    },
    ExtensionVerdicts {
        extensions: &[
            PivExtension::SetManagementKey,
            PivExtension::Reset,
            PivExtension::GetMetadata,
            PivExtension::PinManagementAuth,
        ],
        verdicts: &[VersionVerdict {
            version: &[1, 8],
            verdict: Verdict::KnownSupported,
        }],
    },
    // `PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::{Aes128,Aes192})`
    // joins this row: both are rejected on firmware 1.8.3 (the newest
    // tested) and, per `Verdict::KnownUnsupported`'s backward-extension
    // rule, assumed rejected on every earlier version too — a firmware newer
    // than 1.8.3 softens to `FeatureGate::Unverified` rather than staying
    // `Unsupported`, since a later release may have added them.
    ExtensionVerdicts {
        extensions: &[
            PivExtension::SetPinPukRetries,
            PivExtension::MoveKey,
            PivExtension::DeleteKey,
            PivExtension::Attest,
            PivExtension::SlotPinPolicy,
            PivExtension::SlotTouchPolicy,
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Aes128),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Aes192),
        ],
        verdicts: &[VersionVerdict {
            version: &[1, 8, 3],
            verdict: Verdict::KnownUnsupported,
        }],
    },
    // `PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::{TripleDes,Aes256})`
    // joins this row: both have been supported at every firmware generation
    // keyroost has evidence for, same universal `[]` `Verdict::KnownSupported`.
    ExtensionVerdicts {
        extensions: &[
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa2048),
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa4096),
            PivExtension::SlotKeyAlgorithm(KeyAlg::EccP256),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::TripleDes),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Aes256),
        ],
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownSupported,
        }],
    },
    ExtensionVerdicts {
        extensions: &[
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa3072),
            PivExtension::SlotKeyAlgorithm(KeyAlg::EccP384),
        ],
        verdicts: &[
            VersionVerdict {
                version: &[],
                verdict: Verdict::KnownUnsupported,
            },
            VersionVerdict {
                version: &[1, 8, 2],
                verdict: Verdict::KnownSupported,
            },
        ],
    },
];

/// The Trussed-based Nitrokey's (`Trussed::NitroKey`) applet-axis quirks. The
/// Trussed `piv-authenticator`'s own default management key is the same
/// YubiKey-standard value seeded here, hard-coded as `DEFAULT_MANAGEMENT_KEY`
/// in its `constants.rs` —
/// <https://github.com/trussed-dev/piv-authenticator/blob/main/src/constants.rs>.
/// Only `NitroKey` is fingerprinted today (see that variant's doc), but the
/// value is a property of the shared Trussed applet code, not a
/// Nitrokey-specific customization, so any future `TrussedVariant` seeded
/// here should get its own const with this same row.
const TRUSSED_NITROKEY_APPLET_QUIRKS: &[VersionQuirks] = &[VersionQuirks {
    version: &[],
    quirks: &[PivQuirk::Default9bManagementKey(YUBIKEY_DEFAULT_MGMT_KEY)],
}];

/// See [`YUBIKEY_FIRMWARE_QUIRKS`]'s doc — empty.
const TRUSSED_NITROKEY_FIRMWARE_QUIRKS: &[VersionQuirks] = &[];

/// `OpenFips201::Generic`'s cross-axis merge mode — see [`AxisMergeMode`]'s
/// doc.
const OPENFIPS201_GENERIC_AXIS_MERGE_MODE: AxisMergeMode = AxisMergeMode::MergeRelaxed;

/// `OpenFips201::Generic`'s applet-axis known-support table — see
/// `GENERIC_APPLET_VERDICTS`'s doc for why this fingerprint gets an
/// explicit [`PivExtension::ResetGlobal`] entry. Distinct from
/// [`SWISSBIT_ISHIELD2_APPLET_VERDICTS`] above, which additionally carries
/// MOVE KEY/DELETE KEY data of its own — that sub-fingerprint rejects them
/// outright rather than lacking the mechanism keyroost would need to reach
/// them at all, see that const's own doc.
///
/// [`PivExtension::SlotPinPolicy`]/[`PivExtension::SlotTouchPolicy`] also get
/// an explicit `Verdict::KnownUnsupportedSince` row at the universal `[]`
/// version: upstream OpenFIPS201 has not been observed to mimic any Yubico
/// extension, the same standing-vendor-pattern reasoning
/// `HID_CRESCENDO_C2300_APPLET_VERDICTS`'s doc uses. [`PivExtension::Reset`]
/// joins that same row too — unlike [`SWISSBIT_ISHIELD2_APPLET_VERDICTS`]'s
/// own `Reset` row, this generic OpenFIPS201 fingerprint hasn't been observed
/// to accept Yubico's `INS 0xFB` RESET either, so keyroost has no working
/// reset mechanism for it at all yet, PIV-scoped or otherwise.
/// [`PivExtension::SetManagementKey`]/[`PivExtension::SetPinPukRetries`]/
/// [`PivExtension::MoveKey`]/[`PivExtension::DeleteKey`] join that same row
/// on the same reasoning: upstream OpenFIPS201
/// (<https://github.com/makinako/OpenFIPS201>) ships its own commands for
/// key/PIN/PUK/management-key administration rather than mimicking any of
/// these four Yubico vendor-extension APDUs, none of which keyroost has
/// implemented for this fingerprint. This leaves the
/// [`PivExtension::ManagementKeyAlgorithm`] row below (which real algorithms
/// a management-key *change* could use) effectively unreachable in practice
/// — a caller checks [`PivExtension::SetManagementKey`] first, per that
/// extension's own doc — but it's kept rather than removed: it's still an
/// accurate statement about what the applet itself accepts, keyroost just
/// has no mechanism to reach that code path on this fingerprint yet.
///
/// Deliberately no [`PivExtension::SlotKeyAlgorithm`] rows: upstream
/// OpenFIPS201 (<https://github.com/makinako/OpenFIPS201>) documents a
/// different supported-algorithm set per release line (v1, v1.10, v2, …),
/// but keyroost has no way to read *which* line a given unit is running —
/// this fingerprint carries no applet- or firmware-version identification at
/// all yet, unlike [`OpenFips201Variant::SwissbitIShield2`], whose GET
/// VERSION reply this table's sibling const keys its own
/// [`PivExtension::SlotKeyAlgorithm`] rows to. Seeding a version-gated
/// verdict here regardless would silently assume every `Generic` unit is one
/// specific release line, which is exactly the kind of inferred-not-observed
/// claim this module's known-support tables exist to avoid — see this
/// module's own doc and `resolve`'s "no data at all" fallback to
/// [`FeatureGate::Unverified`]. Every [`KeyAlg`] on this fingerprint
/// therefore resolves [`FeatureGate::Unverified`] until a real version
/// signal is found.
const OPENFIPS201_GENERIC_APPLET_VERDICTS: &[ExtensionVerdicts] = &[
    // `PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Delete)` joins
    // this row: no standard PIV equivalent on this fingerprint — the
    // management key is mandatory, never removable — same universal `[]`
    // `Verdict::KnownUnsupportedSince`. `PivExtension::Reset`/
    // `PivExtension::SetManagementKey`/`PivExtension::SetPinPukRetries`/
    // `PivExtension::MoveKey`/`PivExtension::DeleteKey` join it too — see
    // this const's own doc.
    ExtensionVerdicts {
        extensions: &[
            PivExtension::ResetGlobal,
            PivExtension::Reset,
            PivExtension::SlotPinPolicy,
            PivExtension::SlotTouchPolicy,
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Delete),
            PivExtension::SetManagementKey,
            PivExtension::SetPinPukRetries,
            PivExtension::MoveKey,
            PivExtension::DeleteKey,
        ],
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownUnsupportedSince,
        }],
    },
    // `PivExtension::ManagementKeyAlgorithm` — 3DES/AES-128/AES-192/AES-256
    // are all accepted as the management key's algorithm: one
    // `Verdict::KnownSupported` row at the universal `[]` version. No other
    // row in this table shares that exact verdict, so this stays a
    // standalone entry rather than joining one.
    ExtensionVerdicts {
        extensions: &[
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::TripleDes),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Aes128),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Aes192),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Aes256),
        ],
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownSupported,
        }],
    },
];

/// See [`YUBIKEY_FIRMWARE_VERDICTS`]'s doc — empty.
const OPENFIPS201_GENERIC_FIRMWARE_VERDICTS: &[ExtensionVerdicts] = &[];

/// `OpenFips201::Generic`'s applet-axis quirks — empty: no quirks known for a
/// generic OpenFIPS201 implementation yet. Distinct from
/// `SWISSBIT_ISHIELD2_APPLET_QUIRKS` above, which is a specific
/// OpenFIPS201-based product with its own observed quirks.
const OPENFIPS201_GENERIC_APPLET_QUIRKS: &[VersionQuirks] = &[];

/// See [`YUBIKEY_FIRMWARE_QUIRKS`]'s doc — empty.
const OPENFIPS201_GENERIC_FIRMWARE_QUIRKS: &[VersionQuirks] = &[];

/// Identiv/Hirsch's uTrust Generic's cross-axis merge mode — see
/// [`AxisMergeMode`]'s doc.
const UTRUST_GENERIC_AXIS_MERGE_MODE: AxisMergeMode = AxisMergeMode::MergeRelaxed;

/// Identiv/Hirsch's uTrust Generic (the general-purpose FIDO2 Security Keys
/// line — [`UTrustVariant::Generic`])'s applet-axis known-support table —
/// see `GENERIC_APPLET_VERDICTS`'s doc for why this fingerprint gets an
/// explicit [`PivExtension::ResetGlobal`] entry, and why
/// [`PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Delete)`](PivExtension::ManagementKeyAlgorithm)
/// joins that same entry instead of getting one of its own.
///
/// The [`PivExtension::DeleteKey`]/[`PivExtension::MoveKey`]/
/// [`PivExtension::SetPinPukRetries`]/[`PivExtension::Reset`]/
/// [`PivExtension::GetMetadata`]/[`PivExtension::SetManagementKey`]/
/// [`PivExtension::PinManagementAuth`]/[`PivExtension::SlotPinPolicy`]/
/// [`PivExtension::SlotTouchPolicy`] rows below are hardware-observed
/// `Verdict::KnownUnsupported` on a live unit, same as the quirk this
/// fingerprint mimics ([`UTRUST_GENERIC_APPLET_QUIRKS`]'s YubiKey-shaped
/// default management key) would suggest. The observed device has no
/// supported mechanism to report either an applet or a firmware version —
/// neither GET VERSION nor GET PIV PROPERTIES answered — so, per `resolve`'s
/// "Both axes unset" fallback (see its doc), these rows are pinned at the
/// universal `version: &[]` sentinel rather than a real version number.
///
/// [`PivExtension::SlotKeyAlgorithm`]`(`[`KeyAlg::Rsa3072`]/[`KeyAlg::Rsa4096`]/
/// [`KeyAlg::EccP256`]/[`KeyAlg::EccP384`]/[`KeyAlg::EccP521`]/
/// [`KeyAlg::Ed25519`]/[`KeyAlg::X25519`]`)` join the row above on the same
/// `Verdict::KnownUnsupported` `[]` verdict — the same live unit's GENERATE
/// ASYMMETRIC KEYPAIR rejects all seven; unlike
/// [`FEITIAN_APPLET_VERDICTS`]'s otherwise-similar split, this fingerprint
/// rejects ECC entirely, not just the P-521/Ed25519/X25519 tail. The separate
/// row below, [`KeyAlg::Rsa1024`]/[`KeyAlg::Rsa2048`], is
/// `Verdict::KnownSupported` instead — the same unit accepts both — so it
/// can't join that row; same universal `[]` sentinel as the rows above, for
/// the same reason.
const UTRUST_GENERIC_APPLET_VERDICTS: &[ExtensionVerdicts] = &[
    ExtensionVerdicts {
        extensions: &[
            PivExtension::DeleteKey,
            PivExtension::MoveKey,
            PivExtension::SetPinPukRetries,
            PivExtension::Reset,
            PivExtension::GetMetadata,
            PivExtension::SetManagementKey,
            PivExtension::PinManagementAuth,
            PivExtension::SlotPinPolicy,
            PivExtension::SlotTouchPolicy,
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa3072),
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa4096),
            PivExtension::SlotKeyAlgorithm(KeyAlg::EccP256),
            PivExtension::SlotKeyAlgorithm(KeyAlg::EccP384),
            PivExtension::SlotKeyAlgorithm(KeyAlg::EccP521),
            PivExtension::SlotKeyAlgorithm(KeyAlg::Ed25519),
            PivExtension::SlotKeyAlgorithm(KeyAlg::X25519),
        ],
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownUnsupported,
        }],
    },
    ExtensionVerdicts {
        extensions: &[
            PivExtension::ResetGlobal,
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Delete),
        ],
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownUnsupportedSince,
        }],
    },
    ExtensionVerdicts {
        extensions: &[
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa1024),
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa2048),
        ],
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownSupported,
        }],
    },
];

/// See [`YUBIKEY_FIRMWARE_VERDICTS`]'s doc — empty.
const UTRUST_GENERIC_FIRMWARE_VERDICTS: &[ExtensionVerdicts] = &[];

/// Identiv/Hirsch's uTrust Generic's applet-axis quirks: mimics the YubiKey
/// PIV factory-default management key like most other third-party
/// implementations do. No version-gated quirk observed on this fingerprint.
const UTRUST_GENERIC_APPLET_QUIRKS: &[VersionQuirks] = &[VersionQuirks {
    version: &[],
    quirks: &[PivQuirk::Default9bManagementKey(YUBIKEY_DEFAULT_MGMT_KEY)],
}];

/// See [`YUBIKEY_FIRMWARE_QUIRKS`]'s doc — empty.
const UTRUST_GENERIC_FIRMWARE_QUIRKS: &[VersionQuirks] = &[];

/// Identiv/Hirsch's uTrust Gov's (`UTrustVariant::Gov`) cross-axis merge
/// mode — see [`AxisMergeMode`]'s doc.
const UTRUST_GOV_AXIS_MERGE_MODE: AxisMergeMode = AxisMergeMode::MergeRelaxed;

/// Identiv/Hirsch's uTrust Gov ([`UTrustVariant::Gov`])'s applet-axis
/// known-support table. Nothing currently fingerprints this variant (see
/// its doc) — reserved for when it can be told apart from
/// [`UTrustVariant::Generic`] on the wire — but it still carries the same
/// universal [`PivExtension::ResetGlobal`] entry every non-HID-Crescendo
/// fingerprint gets; see `GENERIC_APPLET_VERDICTS`'s doc for why, and for
/// why [`PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Delete)`](PivExtension::ManagementKeyAlgorithm)
/// joins that same entry instead of getting one of its own.
///
/// The [`PivExtension::DeleteKey`]/[`PivExtension::MoveKey`]/
/// [`PivExtension::SetPinPukRetries`]/[`PivExtension::Reset`]/
/// [`PivExtension::GetMetadata`]/[`PivExtension::SetManagementKey`] rows
/// below **are a guess, not a hardware observation** — unlike
/// [`UTRUST_GENERIC_APPLET_VERDICTS`]'s identically-shaped
/// `Verdict::KnownUnsupported` rows at the same `version: &[]` sentinel,
/// which *are* observed on a live unit. No Gov-fingerprinted device has ever
/// been probed for any of these six extensions — `classify` can't even
/// produce this fingerprint yet, per the doc above. The guess mirrors
/// Generic's verdicts only because it's unlikely Gov implements these
/// Yubico-shaped vendor extensions when it doesn't even mimic the
/// Yubico-shaped default management key [`UTRUST_GENERIC_APPLET_QUIRKS`]
/// does; see [`UTrustVariant::Gov`]'s doc for why Gov's default differs
/// (`IDPRIME_AND_UTRUST_GOV_DEFAULT_MGMT_KEY`). Treat this row as a placeholder to
/// replace with a real verdict the first time a Gov unit is actually probed,
/// not as evidence in its own right. Seeded ahead of Gov being reachable from
/// `classify` at all, same as [`UTRUST_GOV_APPLET_QUIRKS`] already is.
const UTRUST_GOV_APPLET_VERDICTS: &[ExtensionVerdicts] = &[
    ExtensionVerdicts {
        extensions: &[
            PivExtension::DeleteKey,
            PivExtension::MoveKey,
            PivExtension::SetPinPukRetries,
            PivExtension::Reset,
            PivExtension::GetMetadata,
            PivExtension::SetManagementKey,
        ],
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownUnsupported,
        }],
    },
    ExtensionVerdicts {
        extensions: &[
            PivExtension::ResetGlobal,
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Delete),
        ],
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownUnsupportedSince,
        }],
    },
];

/// See [`YUBIKEY_FIRMWARE_VERDICTS`]'s doc — empty.
const UTRUST_GOV_FIRMWARE_VERDICTS: &[ExtensionVerdicts] = &[];

/// Identiv/Hirsch's uTrust Gov's applet-axis quirks: its own vendor-specific
/// default management key (`IDPRIME_AND_UTRUST_GOV_DEFAULT_MGMT_KEY`), *not* the
/// YubiKey-mimicking one [`UTRUST_GENERIC_APPLET_QUIRKS`] uses — see
/// [`UTrustVariant::Gov`]'s doc. No version-gated quirk observed on this
/// fingerprint. Currently unreachable from `classify` regardless (nothing on
/// the wire distinguishes Gov from Generic yet), but seeded ahead of that so
/// the data is ready once it can be.
const UTRUST_GOV_APPLET_QUIRKS: &[VersionQuirks] = &[VersionQuirks {
    version: &[],
    quirks: &[PivQuirk::Default9bManagementKey(
        IDPRIME_AND_UTRUST_GOV_DEFAULT_MGMT_KEY,
    )],
}];

/// See [`YUBIKEY_FIRMWARE_QUIRKS`]'s doc — empty.
const UTRUST_GOV_FIRMWARE_QUIRKS: &[VersionQuirks] = &[];

/// The UI-facing resolution of a [`PivExtension`] against a live applet,
/// produced by [`resolve`]. Not `#[non_exhaustive]`: it is a closed
/// three-way outcome and every caller is expected to render all three
/// (enable / enable-and-flag / dim) rather than fall through a wildcard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeatureGate {
    /// Enable the control, no warning: the extension is known-supported at the
    /// reported version, or at an earlier one and assumed not to have
    /// regressed.
    Supported,
    /// Enable the control, but flag it: keyroost has no known-support data for
    /// this fingerprint, none at or below the reported version, no reported
    /// version to match, or only a known-unsupported verdict old enough that a later
    /// firmware may have added the extension. See [`Self::UNVERIFIED_SUFFIX`].
    Unverified,
    /// Disable the control (dimmed): a known-unsupported verdict covers the reported
    /// version, so the extension is known to be unsupported here.
    Unsupported,
}

impl FeatureGate {
    /// Sentence that follows [`PivExtension::requirement`] when a control is
    /// gated [`Unverified`](Self::Unverified): the device has no
    /// known-support data, so support can't be confirmed either way.
    pub const UNVERIFIED_SUFFIX: &'static str =
        "This device is unverified; the operation may fail.";
    /// Sentence that follows [`PivExtension::requirement`] when a control is
    /// gated [`Unsupported`](Self::Unsupported): a known-unsupported verdict covers
    /// this device's version.
    pub const INCOMPATIBLE_SUFFIX: &'static str = "This device is known to be incompatible.";
}

/// Resolve `extension` for an applet fingerprinted as `fingerprint`, reporting
/// `applet_version` (the PIV applet's own version bytes) and/or
/// `firmware_version` (the device firmware's version bytes) — either or both
/// `None` when the card never reported that one.
///
/// **Both axes unset, one exception:** when `applet_version` and
/// `firmware_version` are *both* `None`, each is substituted with
/// `Some(&[])` before anything below runs. A verdict pinned at the universal
/// `version: &[]` sentinel (e.g. `GENERIC_APPLET_VERDICTS`'s
/// [`PivExtension::ResetGlobal`] row) means "applies at any version, known or
/// not", so a caller that couldn't read a version off the device on *either*
/// axis should still see it rather than getting a blanket
/// [`FeatureGate::Unverified`]. This is the sensible fallback for a
/// fingerprint that has no supported mechanism to query a version at all
/// (neither GET VERSION nor GET PIV PROPERTIES answered, say) — such a
/// device isn't actually unverified on an extension whose verdict doesn't
/// depend on version in the first place, so it shouldn't be dimmed as if it
/// were. This is deliberately narrower than "either axis is `None`": when
/// exactly one axis has data, the other is left as a bare `None` and
/// resolves to [`FeatureGate::Unverified`] via step 1 below, unchanged from
/// before.
///
/// `applet_version` is queried against `applet_verdicts` and
/// `firmware_version` against `firmware_verdicts`, **with
/// identical per-axis lookup semantics**:
///
/// 1. The version is `None` → that axis is [`FeatureGate::Unverified`]
///    (nothing to version-match).
/// 2. No known-support row for `fingerprint` on that axis →
///    [`FeatureGate::Unverified`] (support unknown; don't block).
/// 3. A row exists: take the verdict with the greatest version `<=` the
///    reported version. If there is none — the reported version is older
///    than every verdict on record — fall back to the row's *first* (lowest)
///    verdict, i.e. the nearest one *above* the reported version:
///    * known-unsupported → [`FeatureGate::Unsupported`]: a feature known not to
///      work at that version is assumed not to work at any earlier, untested
///      version either — the backward mirror of the "assumed not to have
///      regressed" forward extension a known-supported verdict gets below;
///    * known-supported, or known-unsupported-since → [`FeatureGate::Unverified`]:
///      neither says anything about the versions before it, so there's
///      nothing to extend backward.
///
///    Otherwise, with a verdict at or below the reported version in hand:
///    * known-supported → [`FeatureGate::Supported`] (covers both an exact-version
///      match and an earlier known-supported verdict assumed not to have regressed);
///    * known-unsupported-since → [`FeatureGate::Unsupported`] unconditionally
///      (covers both an exact-version match and an earlier one) — the mirror
///      image of known-supported's forward extension, for a feature with a
///      standing reason to expect it never comes back (see
///      `Verdict::KnownUnsupportedSince`'s doc);
///    * known-unsupported, verdict version **equals** the reported version →
///      [`FeatureGate::Unsupported`];
///    * known-unsupported, verdict version **below** the reported version, and it is
///      the last (highest) verdict in the row → [`FeatureGate::Unverified`]:
///      the known-unsupported verdict may predate a firmware that added the extension;
///    * known-unsupported, verdict version **below** the reported version, but a
///      later verdict exists (for a version above this one's) → the row's
///      known-unsupported knowledge brackets this version, so it is treated as
///      authoritative: [`FeatureGate::Unsupported`].
///
/// The two per-axis outcomes are then combined by `merge_gates`, per
/// `fingerprint`'s own [`AxisMergeMode`] (looked up via `axis_merge_mode`):
/// see that enum's doc for what each of its four modes does. Every
/// fingerprint is seeded on [`AxisMergeMode::MergeRelaxed`] today, whose
/// rule is: either axis reporting a real verdict
/// ([`FeatureGate::Supported`]/[`FeatureGate::Unsupported`]) wins over
/// [`FeatureGate::Unverified`] on the other, and two *conflicting* real
/// verdicts soften to [`FeatureGate::Unverified`] rather than either winning
/// outright. This means when only one of `applet_version`/`firmware_version`
/// carries data for `fingerprint` — the common case, and the only case any
/// currently-seeded fingerprint is in — the other axis resolves to
/// [`FeatureGate::Unverified`] and simply doesn't change the outcome under
/// any of the four modes, so the combined result equals the one axis that
/// has an opinion.
///
/// **One special case, ahead of all of the above:**
/// [`PivExtension::GetSlotKeyStatus`] falls through entirely to
/// `resolve(`[`PivExtension::GetMetadata`]`, fingerprint, applet_version,
/// firmware_version)` whenever `applet_verdicts` carries no
/// [`PivExtension::GetSlotKeyStatus`] entry for `fingerprint` at all — not the
/// ordinary step-2 [`FeatureGate::Unverified`] default every other extension
/// gets in that situation. This is deliberate, not a workaround: GET
/// METADATA's `algorithm` field *is* how slot-key-status is provided on every
/// fingerprint that doesn't have its own [`PivExtension::GetSlotKeyStatus`]
/// entry, so "no entry here" genuinely means "ask [`PivExtension::GetMetadata`]
/// instead", not "no data, assume unverified". A fingerprint that *does*
/// have an entry (today: HID Crescendo, which provides this a different way —
/// see `HID_CRESCENDO_C2300_APPLET_VERDICTS`'s doc) is resolved through the ordinary per-axis
/// machinery below, exactly like every other extension, and never
/// consults [`PivExtension::GetMetadata`] at all.
#[must_use]
pub fn resolve(
    extension: PivExtension,
    fingerprint: AppletFingerprint,
    applet_version: Option<&[u8]>,
    firmware_version: Option<&[u8]>,
) -> FeatureGate {
    if extension == PivExtension::GetSlotKeyStatus
        && applet_verdicts(fingerprint, PivExtension::GetSlotKeyStatus).is_none()
    {
        return resolve(
            PivExtension::GetMetadata,
            fingerprint,
            applet_version,
            firmware_version,
        );
    }
    // See "Both axes unset, one exception" above: only when *neither* axis
    // carries a reported version does the universal `[]` sentinel version
    // apply to both — an axis that's `None` while the other has data is left
    // alone and still resolves to `Unverified` on its own. This is the
    // sensible fallback for a fingerprint with no supported mechanism to
    // query a version at all, rather than dimming every version-independent
    // verdict as unverified just because nothing could be read.
    let (applet_version, firmware_version) = match (applet_version, firmware_version) {
        (None, None) => (Some(&[][..]), Some(&[][..])),
        versions => versions,
    };
    let applet_gate = resolve_in(applet_verdicts(fingerprint, extension), applet_version);
    let firmware_gate = resolve_in(firmware_verdicts(fingerprint, extension), firmware_version);
    merge_gates(axis_merge_mode(fingerprint), applet_gate, firmware_gate)
}

/// [`AxisMergeMode::MergeStrict`]'s rule: [`FeatureGate::Unsupported`] wins
/// outright; otherwise [`FeatureGate::Supported`] wins; otherwise
/// [`FeatureGate::Unverified`]. Named to pair with `combine_relaxed`/
/// `combine_preferring` — this was keyroost's only cross-axis rule before
/// [`AxisMergeMode`] existed.
#[must_use]
fn combine_strict(a: FeatureGate, b: FeatureGate) -> FeatureGate {
    match (a, b) {
        (FeatureGate::Unsupported, _) | (_, FeatureGate::Unsupported) => FeatureGate::Unsupported,
        (FeatureGate::Supported, _) | (_, FeatureGate::Supported) => FeatureGate::Supported,
        (FeatureGate::Unverified, FeatureGate::Unverified) => FeatureGate::Unverified,
    }
}

/// [`AxisMergeMode::MergeRelaxed`]'s rule: a real verdict
/// ([`FeatureGate::Supported`]/[`FeatureGate::Unsupported`]) wins over
/// [`FeatureGate::Unverified`] on the other side — same as
/// `combine_strict` in every case but one — but two real, *conflicting*
/// verdicts (one `Supported`, the other `Unsupported`) soften to
/// [`FeatureGate::Unverified`] instead of letting `Unsupported` win outright
/// the way `combine_strict` does.
#[must_use]
fn combine_relaxed(a: FeatureGate, b: FeatureGate) -> FeatureGate {
    match (a, b) {
        (FeatureGate::Unsupported, FeatureGate::Supported)
        | (FeatureGate::Supported, FeatureGate::Unsupported) => FeatureGate::Unverified,
        (FeatureGate::Unsupported, _) | (_, FeatureGate::Unsupported) => FeatureGate::Unsupported,
        (FeatureGate::Supported, _) | (_, FeatureGate::Supported) => FeatureGate::Supported,
        (FeatureGate::Unverified, FeatureGate::Unverified) => FeatureGate::Unverified,
    }
}

/// The shared tie-break rule behind [`AxisMergeMode::AppletWins`]/
/// [`AxisMergeMode::FirmwareWins`]: a real verdict wins over
/// [`FeatureGate::Unverified`] on the other side — same as
/// `combine_relaxed` — but when `a` and `b` are both real verdicts that
/// genuinely conflict, `preferred` (the selected axis's own gate — `a` for
/// `AppletWins`, `b` for `FirmwareWins`) wins outright instead of softening
/// to [`FeatureGate::Unverified`] the way `combine_relaxed` would.
#[must_use]
fn combine_preferring(a: FeatureGate, b: FeatureGate, preferred: FeatureGate) -> FeatureGate {
    match (a, b) {
        (FeatureGate::Unverified, FeatureGate::Unverified) => FeatureGate::Unverified,
        (FeatureGate::Unverified, real) | (real, FeatureGate::Unverified) => real,
        (x, y) if x == y => x,
        _ => preferred,
    }
}

/// Dispatch to the right per-axis combination primitive for `mode` — the
/// [`resolve`] orchestrator [`AxisMergeMode`]'s doc describes; see each
/// primitive's own doc for its exact rule.
#[must_use]
fn merge_gates(
    mode: AxisMergeMode,
    applet_gate: FeatureGate,
    firmware_gate: FeatureGate,
) -> FeatureGate {
    match mode {
        AxisMergeMode::MergeStrict => combine_strict(applet_gate, firmware_gate),
        AxisMergeMode::MergeRelaxed => combine_relaxed(applet_gate, firmware_gate),
        AxisMergeMode::AppletWins => combine_preferring(applet_gate, firmware_gate, applet_gate),
        AxisMergeMode::FirmwareWins => {
            combine_preferring(applet_gate, firmware_gate, firmware_gate)
        }
    }
}

/// [`resolve`]'s per-axis lookup, given the (fingerprint, extension) pair's
/// verdicts already looked up via `applet_verdicts`/`firmware_verdicts` —
/// `None` when there were none. Taking the verdicts directly, rather than a
/// table plus the keys to look them up with, also lets a test supply its own
/// synthetic verdicts without wiring a row into the const tables.
fn resolve_in(verdicts: Option<&[VersionVerdict]>, version: Option<&[u8]>) -> FeatureGate {
    let Some(version) = version else {
        return FeatureGate::Unverified;
    };
    let Some(verdicts) = verdicts else {
        return FeatureGate::Unverified;
    };
    let Some(idx) = verdicts.iter().rposition(|v| v.version <= version) else {
        // The reported version is older than every verdict on record. Fall
        // back to the nearest one *above* it — `verdicts[0]`, since rows are
        // sorted ascending — and, if that verdict is `KnownUnsupported`,
        // extend it backward: a feature known not to work at that version is
        // assumed not to work at any earlier, untested version either. A
        // `KnownSupported` verdict, by contrast, says nothing about versions
        // before it — and neither does a `KnownUnsupportedSince` one, by the
        // same "says nothing about the past" rule that gives it its name; it
        // falls into the same `_` arm as `KnownSupported` here.
        return match verdicts.first() {
            Some(VersionVerdict {
                verdict: Verdict::KnownUnsupported,
                ..
            }) => FeatureGate::Unsupported,
            _ => FeatureGate::Unverified,
        };
    };
    let chosen = &verdicts[idx];
    match chosen.verdict {
        // Known supported at or below the reported version — and assumed not
        // to have regressed in any newer version we have no verdict for.
        Verdict::KnownSupported => FeatureGate::Supported,
        // A known-unsupported verdict for exactly this version: a direct observation
        // that this build lacks the extension. Nothing softens that.
        Verdict::KnownUnsupported if chosen.version == version => FeatureGate::Unsupported,
        // A known-unsupported verdict from an *older* version with nothing newer on
        // record: the extension may have been added in a firmware we haven't
        // observed, so warn rather than block.
        Verdict::KnownUnsupported if idx + 1 == verdicts.len() => FeatureGate::Unverified,
        // A known-unsupported verdict from an older version, but a later verdict exists
        // (for a version above this applet's): our known-unsupported knowledge
        // brackets this version, so treat it as authoritative and block.
        Verdict::KnownUnsupported => FeatureGate::Unsupported,
        // `KnownUnsupportedSince` at or below the reported version — and,
        // mirroring `KnownSupported`'s forward extension exactly, assumed to
        // *stay* unsupported in any newer version we have no verdict for.
        // Unlike plain `KnownUnsupported` above, this never softens to
        // `Unverified` just for being the row's last (highest) verdict — the
        // whole point of this variant is that there's a standing reason not
        // to expect a later firmware to add the extension back.
        Verdict::KnownUnsupportedSince => FeatureGate::Unsupported,
    }
}

/// This fingerprint's wire algorithm-identifier override for `key_alg`, if
/// it's confirmed to use a byte other than [`KeyAlg::id`]'s Yubico-default
/// one on the mechanism [`slot_key_algorithm_apdu_id`]/
/// [`key_alg_from_apdu_id`] serve — GENERATE ASYMMETRIC KEYPAIR / GENERAL
/// AUTHENTICATE / GET METADATA, and (via
/// `keyroost_transport::PivSession::hid_crescendo_slot_algorithm`) HID
/// Crescendo's own GET PIV PROPERTIES read too, which shares this same
/// override rather than decoding through a second, parallel table.
/// `firmware_version` exists purely for the one entry below that needs it
/// ([`AppletFingerprint::Trussed`]'s); every other entry ignores it entirely
/// — no other fingerprint has been observed to change its own wire byte for
/// an algorithm across firmware generations, so there's nothing else to key
/// by version yet.
///
/// Every HID Crescendo variant (`C2300`, `C4000`, and the unclassified
/// `Generic`) shares one answer here:
/// [`crate::fingerprint::hid_crescendo_c4000_algorithm_id`] — already the
/// source of truth for GET PIV PROPERTIES and INJECT PKI KEY — doubles as
/// this override too, on the same "one `PIVCryptographicMechanismIdentifier`
/// field, shared across the whole product line" basis that function's own
/// doc already reasons from for extending C4000's confirmed table to C2300.
/// HID Crescendo C4000's standard GENERATE ASYMMETRIC KEYPAIR (`INS 0x47`)
/// independently confirms this same table for its own command —
/// <https://docs.hidglobal.com/crescendo/api/c4000/generate-key-pair.htm> —
/// and the only byte it actually diverges from [`KeyAlg::id`] on is RSA-4096
/// (`0x04` here, `0x16` there); every other algorithm it names already
/// agrees with the default. Applying the same table to every variant here is
/// a wider claim than `HID_CRESCENDO_C4000_APPLET_VERDICTS`/
/// `HID_CRESCENDO_C2300_APPLET_VERDICTS`'s own [`PivExtension::SlotKeyAlgorithm`]
/// rows make (those stay narrower, per-family, and don't extend to
/// `Generic`) — a different axis from this override: an algorithm's support
/// gate says nothing about which byte names it once encountered, and vice
/// versa, so a byte GET PIV PROPERTIES reports for an algorithm C2300's own
/// GENERATE KEY PAIR can't create (RSA-4096, say) is still decoded
/// correctly here.
///
/// `OpenFips201(`[`OpenFips201Variant::SwissbitIShield2`]`)` carries a
/// second, unrelated override: a confirmed unit (applet v1.4.1.0, firmware
/// v1.1.2) uses `0x32` for [`KeyAlg::EccP521`], not [`KeyAlg::id`]'s
/// INCITS 504-1 default of `0x15` — the only algorithm this sub-fingerprint
/// is known to diverge on, so every other [`KeyAlg`] falls through to
/// `None` (and from there to the default) unchanged. No other
/// `OpenFips201`/`ArekinathPivApplet` variant (including
/// [`crate::fingerprint::ArekinathVariant::SwissbitIShield1`], a different
/// applet on the same vendor's hardware) has been confirmed either way, so
/// this doesn't extend past the one sub-fingerprint it was actually
/// observed on.
///
/// `Trussed(`[`TrussedVariant::NitroKey`]`)` carries the one entry that
/// actually needs `firmware_version`: pre-1.8.2 firmware answers RSA-4096 as
/// `0xE1` — [`KeyAlg::id`]'s own default byte for [`KeyAlg::X25519`], not
/// RSA-4096 — while 1.8.2 and later switch to Yubico's usual `0x16`, matching
/// the default table like the rest of this fingerprint's algorithms already
/// do (see [`TRUSSED_NITROKEY_FIRMWARE_VERDICTS`]'s own
/// [`PivExtension::SlotKeyAlgorithm`] doc for the *support* side of this same
/// 1.8.2 boundary). The `0xE1`/X25519 collision is harmless in practice:
/// pre-1.8.2 firmware doesn't support X25519 at all (see that same doc), so
/// [`key_alg_from_apdu_id`]'s search — which walks [`KeyAlg::ALL`] in
/// declaration order and returns the *first* match — always resolves `0xE1`
/// on this fingerprint to RSA-4096, since RSA-4096 sorts ahead of X25519 in
/// [`KeyAlg::ALL`] and this override makes RSA-4096 resolve to that byte
/// first. An absent `firmware_version` (device never answered, or answered
/// with firmware keyroost couldn't parse) falls through to `None` here —
/// deliberately the *not-overridden* branch, so an unknown firmware defaults
/// to Yubico's `0x16` rather than guessing the older, narrower byte.
#[must_use]
fn slot_key_algorithm_apdu_id_override(
    fingerprint: AppletFingerprint,
    key_alg: KeyAlg,
    firmware_version: Option<&[u8]>,
) -> Option<u8> {
    match fingerprint {
        AppletFingerprint::HidCrescendo(_) => {
            crate::fingerprint::hid_crescendo_c4000_algorithm_id(key_alg)
        }
        AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2)
            if key_alg == KeyAlg::EccP521 =>
        {
            Some(0x32)
        }
        AppletFingerprint::Trussed(TrussedVariant::NitroKey)
            if key_alg == KeyAlg::Rsa4096
                && firmware_version.is_some_and(|v| v < [1, 8, 2].as_slice()) =>
        {
            Some(0xE1)
        }
        _ => None,
    }
}

/// The wire algorithm-identifier byte to send for `key_alg` on `fingerprint`
/// (reporting `firmware_version`, if known) in a GENERATE ASYMMETRIC KEYPAIR /
/// GENERAL AUTHENTICATE APDU: `slot_key_algorithm_apdu_id_override`'s entry
/// for this triple if it has one, or [`KeyAlg::id`]'s Yubico-default byte
/// otherwise. A caller building such an APDU should always go through this
/// rather than [`KeyAlg::id`] directly — see that method's doc.
/// `firmware_version` only ever changes the answer for
/// `Trussed(`[`TrussedVariant::NitroKey`]`)`'s RSA-4096 entry — see
/// `slot_key_algorithm_apdu_id_override`'s own doc — so passing `None` for
/// any other fingerprint is equivalent to omitting a firmware version this
/// fingerprint doesn't key anything on.
#[must_use]
pub fn slot_key_algorithm_apdu_id(
    key_alg: KeyAlg,
    fingerprint: AppletFingerprint,
    firmware_version: Option<&[u8]>,
) -> u8 {
    slot_key_algorithm_apdu_id_override(fingerprint, key_alg, firmware_version)
        .unwrap_or_else(|| key_alg.id())
}

/// The inverse of [`slot_key_algorithm_apdu_id`]: resolve a device-reported
/// wire algorithm-identifier byte (GET METADATA tag `0x01`, or a GENERATE
/// ASYMMETRIC KEYPAIR / GENERAL AUTHENTICATE reply that echoes one) back to a
/// [`KeyAlg`], preferring whichever algorithm this fingerprint's own
/// `slot_key_algorithm_apdu_id_override` says `id` actually means over
/// [`KeyAlg::from_id`]'s Yubico-default table. Tries every [`KeyAlg::ALL`]
/// variant, in declaration order, through [`slot_key_algorithm_apdu_id`] and
/// returns the first one whose resolved byte matches `id` — see
/// `slot_key_algorithm_apdu_id_override`'s own `Trussed`/`NitroKey` doc for
/// why that ordering is load-bearing on pre-1.8.2 firmware, not incidental —
/// falling back to [`KeyAlg::from_id`] when none does, which also covers
/// every fingerprint with no override data at all (every candidate then
/// resolves to its own [`KeyAlg::id`] default, so this is equivalent to
/// calling [`KeyAlg::from_id`] directly in that case, just by a longer path).
#[must_use]
pub fn key_alg_from_apdu_id(
    id: u8,
    fingerprint: AppletFingerprint,
    firmware_version: Option<&[u8]>,
) -> Option<KeyAlg> {
    KeyAlg::ALL
        .into_iter()
        .find(|&alg| slot_key_algorithm_apdu_id(alg, fingerprint, firmware_version) == id)
        .or_else(|| KeyAlg::from_id(id))
}

/// The entry in `quirks` with the greatest [`VersionQuirks::version`] `<=`
/// `version`, if any — the "current" quirks entry for that version, ignoring
/// anything with a higher version on record. Same lookup rule as step 3 of
/// [`resolve_in`], but there's no known-support reasoning to apply once the
/// entry is found: quirks are taken as-is.
fn latest_quirks<'a>(quirks: &'a [VersionQuirks], version: &[u8]) -> Option<&'a VersionQuirks> {
    let idx = quirks.iter().rposition(|v| v.version <= version)?;
    Some(&quirks[idx])
}

/// Resolve the set of [`PivQuirk`]s active for an applet fingerprinted as
/// `fingerprint`, reporting `applet_version` and/or `firmware_version` —
/// either or both `None` when the card never reported that one:
///
/// **Both axes unset, one exception:** same fallback as [`resolve`]'s own
/// "Both axes unset" doc — when `applet_version` and `firmware_version` are
/// *both* `None`, each is substituted with `Some(&[])` before anything below
/// runs, so a quirk seeded at the universal `version: &[]` sentinel (e.g.
/// `YUBIKEY_APPLET_QUIRKS`'s [`PivQuirk::Default9bManagementKey`] row)
/// still applies to a fingerprint with no supported mechanism to query a
/// version at all, rather than silently resolving no quirks whatsoever. When
/// exactly one axis has data, the other is left as a bare `None` and
/// contributes nothing on its own, exactly as step 1/2 below already say.
///
/// 1. If `applet_version` is available, take `fingerprint`'s `applet_quirks`
///    entry with the highest version `<=` `applet_version` (if any).
/// 2. If `firmware_version` is available, take `fingerprint`'s
///    `firmware_quirks` entry with the highest version `<=`
///    `firmware_version` (if any).
/// 3. Merge the two per `merge_quirk_sets`, per `fingerprint`'s own
///    [`AxisMergeMode`] (looked up via `axis_merge_mode`) — see that
///    enum's doc for what each of its four modes does on this axis. Every
///    fingerprint is seeded on [`AxisMergeMode::MergeRelaxed`] today, whose
///    rule for quirks — shared with [`AxisMergeMode::MergeStrict`] — is a
///    plain union: unlike [`resolve`], there's no known-support reasoning
///    here, each axis contributes at most one entry's quirks, and quirks
///    only ever accumulate — nothing in either entry can suppress a quirk
///    the other added.
#[must_use]
pub fn resolve_quirks(
    fingerprint: AppletFingerprint,
    applet_version: Option<&[u8]>,
    firmware_version: Option<&[u8]>,
) -> BTreeSet<PivQuirk> {
    // See "Both axes unset, one exception" above — mirrors `resolve`'s own
    // substitution exactly.
    let (applet_version, firmware_version) = match (applet_version, firmware_version) {
        (None, None) => (Some(&[][..]), Some(&[][..])),
        versions => versions,
    };
    merge_quirk_sets(
        axis_merge_mode(fingerprint),
        applet_quirks(fingerprint),
        applet_version,
        firmware_quirks(fingerprint),
        firmware_version,
    )
}

/// [`resolve_quirks`] against explicit applet/firmware quirk lists, so a
/// test can supply its own without wiring one into the const tables — same
/// role [`resolve_in`] plays for [`resolve`]. Always unions whatever each
/// axis's [`latest_quirks`] entry contributes — the [`AxisMergeMode::MergeRelaxed`]/
/// [`AxisMergeMode::MergeStrict`] rule, and `merge_quirk_sets`'s fallback
/// for [`AxisMergeMode::AppletWins`]/[`AxisMergeMode::FirmwareWins`] whenever
/// they don't have both axes' versions to pick an exclusive winner from.
fn resolve_quirks_in(
    applet_entries: &[VersionQuirks],
    firmware_entries: &[VersionQuirks],
    applet_version: Option<&[u8]>,
    firmware_version: Option<&[u8]>,
) -> BTreeSet<PivQuirk> {
    let mut quirks = BTreeSet::new();
    if let Some(version) = applet_version {
        if let Some(entry) = latest_quirks(applet_entries, version) {
            quirks.extend(entry.quirks.iter().copied());
        }
    }
    if let Some(version) = firmware_version {
        if let Some(entry) = latest_quirks(firmware_entries, version) {
            quirks.extend(entry.quirks.iter().copied());
        }
    }
    quirks
}

/// Dispatch to the right cross-axis quirk-merging rule for `mode` — the
/// quirks counterpart of `merge_gates`. [`AxisMergeMode::MergeRelaxed`]/
/// [`AxisMergeMode::MergeStrict`] both fall through to [`resolve_quirks_in`]'s
/// plain union — quirks have no known-support notion to make those two modes
/// diverge on this axis, unlike `merge_gates`. [`AxisMergeMode::AppletWins`]/
/// [`AxisMergeMode::FirmwareWins`] only pick an exclusive winner when *both*
/// `applet_version` and `firmware_version` were reported — quirks have no
/// `FeatureGate`-shaped notion of "conflict" to tie-break on the way
/// `combine_preferring` does for verdicts, so with only one axis (or
/// neither) reporting a version, this falls back to the same union
/// [`AxisMergeMode::MergeRelaxed`]/[`AxisMergeMode::MergeStrict`] always use.
#[must_use]
fn merge_quirk_sets(
    mode: AxisMergeMode,
    applet_entries: &[VersionQuirks],
    applet_version: Option<&[u8]>,
    firmware_entries: &[VersionQuirks],
    firmware_version: Option<&[u8]>,
) -> BTreeSet<PivQuirk> {
    let both_reported = applet_version.is_some() && firmware_version.is_some();
    match mode {
        AxisMergeMode::AppletWins if both_reported => applet_version
            .and_then(|v| latest_quirks(applet_entries, v))
            .map(|e| e.quirks.iter().copied().collect())
            .unwrap_or_default(),
        AxisMergeMode::FirmwareWins if both_reported => firmware_version
            .and_then(|v| latest_quirks(firmware_entries, v))
            .map(|e| e.quirks.iter().copied().collect())
            .unwrap_or_default(),
        _ => resolve_quirks_in(
            applet_entries,
            firmware_entries,
            applet_version,
            firmware_version,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- User-facing wording: requirement() + a suffix -------------------

    #[test]
    fn requirement_is_distinct_per_extension_and_composes_with_a_suffix() {
        let reqs = [
            PivExtension::MoveKey.requirement(),
            PivExtension::DeleteKey.requirement(),
            PivExtension::GetMetadata.requirement(),
            PivExtension::GetSlotKeyStatus.requirement(),
            PivExtension::Attest.requirement(),
            PivExtension::PinManagementAuth.requirement(),
            PivExtension::Reset.requirement(),
            PivExtension::ResetGlobal.requirement(),
            PivExtension::SetPinPukRetries.requirement(),
            PivExtension::SetManagementKey.requirement(),
            PivExtension::SlotPinPolicy.requirement(),
            PivExtension::SlotTouchPolicy.requirement(),
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa2048).requirement(),
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa4096).requirement(),
        ];
        for (i, a) in reqs.iter().enumerate() {
            for b in &reqs[i + 1..] {
                assert_ne!(a, b);
            }
            // Ends a sentence, so "<req> <suffix>" reads as two.
            assert!(a.ends_with('.'), "{a:?}");
        }
        for suffix in [
            FeatureGate::UNVERIFIED_SUFFIX,
            FeatureGate::INCOMPATIBLE_SUFFIX,
        ] {
            assert!(suffix.ends_with('.'), "{suffix:?}");
            assert!(!suffix.is_empty());
        }
    }

    // --- YubiKey: the seeded 5.7 gate, both extensions -------------------

    #[test]
    fn yubikey_below_5_7_is_unsupported() {
        for ext in [PivExtension::MoveKey, PivExtension::DeleteKey] {
            // Matches the known-unsupported sentinel verdict (version `[]`), which is
            // not the last verdict, so the known-unsupported verdict is authoritative.
            assert_eq!(
                resolve(ext, AppletFingerprint::YubiKey, Some(&[5, 6, 0]), None),
                FeatureGate::Unsupported
            );
            assert_eq!(
                resolve(ext, AppletFingerprint::YubiKey, Some(&[4, 3, 7]), None),
                FeatureGate::Unsupported
            );
        }
    }

    #[test]
    fn yubikey_5_7_and_newer_is_supported() {
        for ext in [PivExtension::MoveKey, PivExtension::DeleteKey] {
            // Bare [5, 7] clears the bar: `[5, 7] <= [5, 7]`.
            assert_eq!(
                resolve(ext, AppletFingerprint::YubiKey, Some(&[5, 7]), None),
                FeatureGate::Supported
            );
            assert_eq!(
                resolve(ext, AppletFingerprint::YubiKey, Some(&[5, 7, 4]), None),
                FeatureGate::Supported
            );
            // A later version with no verdict of its own falls to the [5, 7]
            // known-supported verdict, assumed not to have regressed.
            assert_eq!(
                resolve(ext, AppletFingerprint::YubiKey, Some(&[6, 0, 0]), None),
                FeatureGate::Supported
            );
        }
    }

    #[test]
    fn yubikey_without_any_reported_version_matches_the_universal_unsupported_verdict() {
        // Neither axis reported a version at all, so `resolve` substitutes
        // the universal `[]` sentinel on both — see `resolve`'s "Both axes
        // unset" doc. `MoveKey`'s row is pinned `KnownUnsupported` exactly at
        // `[]` (with a later `[5, 7]` verdict on record), so that sentinel
        // match resolves `Unsupported`, not `Unverified`.
        assert_eq!(
            resolve(
                PivExtension::MoveKey,
                AppletFingerprint::YubiKey,
                None,
                None
            ),
            FeatureGate::Unsupported
        );
    }

    #[test]
    fn firmware_version_is_ignored_when_the_extension_has_no_firmware_axis_data() {
        // Today no `PivExtension` has firmware-version verdicts, so any
        // firmware_version — however implausible — leaves the applet-version
        // axis as the sole opinion.
        for ext in [PivExtension::MoveKey, PivExtension::DeleteKey] {
            assert_eq!(
                resolve(
                    ext,
                    AppletFingerprint::YubiKey,
                    Some(&[5, 7]),
                    Some(&[9, 9, 9]),
                ),
                FeatureGate::Supported
            );
            assert_eq!(
                resolve(
                    ext,
                    AppletFingerprint::YubiKey,
                    Some(&[5, 6]),
                    Some(&[9, 9, 9]),
                ),
                FeatureGate::Unsupported
            );
        }
    }

    // --- Token2: the seeded 5.112.0 known-unsupported verdict, both extensions ---

    #[test]
    fn token2_5_112_0_is_unsupported() {
        for ext in [PivExtension::MoveKey, PivExtension::DeleteKey] {
            assert_eq!(
                resolve(ext, AppletFingerprint::Token2, Some(&[5, 112, 0]), None),
                FeatureGate::Unsupported
            );
        }
    }

    #[test]
    fn token2_older_versions_are_also_unsupported() {
        // No verdict at or below these versions, so `resolve_in` falls back
        // to the row's only (and therefore nearest-above) verdict: the
        // 5.112.0 known-unsupported verdict, extended backward.
        for ext in [PivExtension::MoveKey, PivExtension::DeleteKey] {
            assert_eq!(
                resolve(ext, AppletFingerprint::Token2, Some(&[5, 111, 0]), None),
                FeatureGate::Unsupported
            );
            assert_eq!(
                resolve(ext, AppletFingerprint::Token2, Some(&[0]), None),
                FeatureGate::Unsupported
            );
        }
    }

    #[test]
    fn token2_newer_versions_are_unverified_not_known_unsupported() {
        // No known-supported verdict on this row, and 5.112.0 is the last (highest)
        // entry, so — per `resolve_in`'s "trailing stale known-unsupported" rule — a
        // version above it doesn't inherit the verdict: the known-unsupported verdict is
        // deliberately never treated as covering a version it hasn't
        // actually observed.
        for ext in [PivExtension::MoveKey, PivExtension::DeleteKey] {
            assert_eq!(
                resolve(ext, AppletFingerprint::Token2, Some(&[5, 113, 0]), None),
                FeatureGate::Unverified
            );
        }
    }

    // --- Thetis PRO FIDO2 Security Key with PinPlex: the seeded 5.112.0 -
    // --- known-unsupported verdict, both extensions -----------------------

    #[test]
    fn thetis_5_112_0_is_unsupported() {
        for ext in [PivExtension::MoveKey, PivExtension::DeleteKey] {
            assert_eq!(
                resolve(ext, AppletFingerprint::Thetis, Some(&[5, 112, 0]), None),
                FeatureGate::Unsupported
            );
            // No verdict at or below this version, so `resolve_in` falls
            // back to the row's only verdict — the 5.112.0 known-unsupported verdict,
            // extended backward.
            assert_eq!(
                resolve(ext, AppletFingerprint::Thetis, Some(&[0]), None),
                FeatureGate::Unsupported
            );
            // Same trailing-known-unsupported softening above the highest verdict.
            assert_eq!(
                resolve(ext, AppletFingerprint::Thetis, Some(&[5, 113, 0]), None),
                FeatureGate::Unverified
            );
        }
    }

    // --- Swissbit iShield 2 Pro: the bracketed <= 1.4.1.0 known-unsupported verdict ---

    #[test]
    fn swissbit_ishield2_at_or_below_1_4_1_0_is_unsupported() {
        for ext in [PivExtension::MoveKey, PivExtension::DeleteKey] {
            let fp = AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2);
            // The exact observed version: known-unsupported via the direct-match
            // rule.
            assert_eq!(
                resolve(ext, fp, Some(&[1, 4, 1, 0]), None),
                FeatureGate::Unsupported
            );
            // Anything older: no verdict at or below it, so `resolve_in`
            // falls back to the row's only verdict — the `[1, 4, 1, 0]`
            // known-unsupported verdict, extended backward rather than softening to
            // `Unverified`.
            for older in [&[0][..], &[1][..], &[1, 4, 0][..]] {
                assert_eq!(
                    resolve(ext, fp, Some(older), None),
                    FeatureGate::Unsupported
                );
            }
        }
    }

    #[test]
    fn swissbit_ishield2_above_1_4_1_0_is_unverified_not_known_unsupported() {
        // The known-unsupported verdict deliberately doesn't extend to a version keyroost
        // hasn't actually observed: `[1, 4, 1, 0]` is the last verdict in
        // the row, so anything strictly newer softens to `Unverified` per
        // `resolve_in`'s trailing-known-unsupported rule.
        for ext in [PivExtension::MoveKey, PivExtension::DeleteKey] {
            let fp = AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2);
            for newer in [&[1, 4, 1, 1][..], &[1, 5, 0][..], &[2, 0][..]] {
                assert_eq!(resolve(ext, fp, Some(newer), None), FeatureGate::Unverified);
            }
        }
    }

    #[test]
    fn swissbit_ishield2_other_openfips201_variant_is_known_unsupported_since() {
        // The row above is keyed to the SwissbitIShield2 sub-fingerprint
        // specifically — its `[1, 4, 1, 0]` floor doesn't leak to the
        // generic OpenFIPS201 variant. That variant doesn't resolve
        // `Unverified` here any more either, though: it now carries its own,
        // separate `Verdict::KnownUnsupportedSince` row for both extensions
        // — see `OPENFIPS201_GENERIC_APPLET_VERDICTS`'s doc and
        // `idprime_and_openfips201_generic_yubico_extensions_are_known_unsupported_since`.
        for ext in [PivExtension::MoveKey, PivExtension::DeleteKey] {
            assert_eq!(
                resolve(
                    ext,
                    AppletFingerprint::OpenFips201(OpenFips201Variant::Generic),
                    Some(&[1, 4, 1, 0]),
                    None,
                ),
                FeatureGate::Unsupported
            );
        }
    }

    // --- Swissbit iShield 2 Pro: SET PIN/PUK RETRIES arrives at 1.4.1.0 ----

    #[test]
    fn swissbit_ishield2_set_pin_puk_retries_unsupported_at_or_below_1_0_0_0() {
        let fp = AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2);
        // The tested floor: known-unsupported via the direct-match rule.
        assert_eq!(
            resolve(
                PivExtension::SetPinPukRetries,
                fp,
                Some(&[1, 0, 0, 0]),
                None
            ),
            FeatureGate::Unsupported
        );
        // Anything older falls back to this same verdict, extended backward.
        for older in [&[0][..], &[1][..], &[1, 0, 0][..]] {
            assert_eq!(
                resolve(PivExtension::SetPinPukRetries, fp, Some(older), None),
                FeatureGate::Unsupported
            );
        }
    }

    #[test]
    fn swissbit_ishield2_set_pin_puk_retries_supported_at_or_above_1_4() {
        // `[1, 4]` now, not the narrower `[1, 4, 1, 0]` an earlier, separate
        // row once pinned it to — merged into the same row RSA-3072/RSA-4096/
        // ECC P-521/`PinManagementAuth` share, see
        // `SWISSBIT_ISHIELD2_APPLET_VERDICTS`'s doc.
        let fp = AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2);
        for version in [&[1, 4][..], &[1, 4, 1, 0][..], &[2, 0][..]] {
            assert_eq!(
                resolve(PivExtension::SetPinPukRetries, fp, Some(version), None),
                FeatureGate::Supported
            );
        }
    }

    #[test]
    fn swissbit_ishield2_set_pin_puk_retries_between_the_two_tested_points_is_unsupported() {
        // A version strictly between the known-unsupported floor and the
        // known-supported point is bracketed by the two verdicts (there's a
        // later verdict on the row), so `resolve_in` treats the older
        // known-unsupported verdict as still authoritative rather than
        // softening to `Unverified`.
        let fp = AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2);
        for version in [&[1, 1, 0][..], &[1, 3, 9, 9][..]] {
            assert_eq!(
                resolve(PivExtension::SetPinPukRetries, fp, Some(version), None),
                FeatureGate::Unsupported
            );
        }
    }

    #[test]
    fn swissbit_ishield2_pin_management_auth_supported_at_or_above_1_4() {
        // Same merged row as `PivExtension::SetPinPukRetries` — see
        // `SWISSBIT_ISHIELD2_APPLET_VERDICTS`'s doc.
        let fp = AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2);
        for version in [&[1, 4][..], &[1, 4, 1, 0][..], &[2, 0][..]] {
            assert_eq!(
                resolve(PivExtension::PinManagementAuth, fp, Some(version), None),
                FeatureGate::Supported
            );
        }
        for version in [&[1, 0, 0, 0][..], &[1, 1, 0][..]] {
            assert_eq!(
                resolve(PivExtension::PinManagementAuth, fp, Some(version), None),
                FeatureGate::Unsupported
            );
        }
    }

    // --- Swissbit iShield 2 Pro: RESET / GET METADATA supported throughout -

    #[test]
    fn swissbit_ishield2_reset_and_get_metadata_supported_at_any_version() {
        let fp = AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2);
        for ext in [PivExtension::Reset, PivExtension::GetMetadata] {
            for version in [&[0][..], &[1, 0, 0, 0][..], &[1, 4, 1, 0][..], &[2, 0][..]] {
                assert_eq!(
                    resolve(ext, fp, Some(version), None),
                    FeatureGate::Supported
                );
            }
            // Neither axis reported a version at all, so `resolve`
            // substitutes the universal `[]` sentinel on both — see
            // `resolve`'s "Both axes unset" doc. Both rows are pinned
            // `KnownSupported` exactly at `[]`, so that sentinel match
            // resolves `Supported`, same as any other version.
            assert_eq!(resolve(ext, fp, None, None), FeatureGate::Supported);
        }
    }

    // --- HID Crescendo: MOVE KEY only, `KnownUnsupportedSince` ------------

    #[test]
    fn hid_crescendo_move_key_is_known_unsupported_since_regardless_of_version() {
        // `Verdict::KnownUnsupportedSince` at the universal `[]` version:
        // unlike a plain `KnownUnsupported` verdict (see the Token2/Swissbit/
        // Thetis tests above), this doesn't soften to `Unverified` for a
        // version newer than anything on the row — every *reported* version
        // matches it. (A missing version report on both axes is a separate
        // case, covered below: `resolve` substitutes the `[]` sentinel for
        // both when neither is reported at all, so it matches this same row
        // too — see
        // `hid_crescendo_move_key_without_any_reported_version_matches_the_universal_verdict`.)
        for variant in [
            HidCrescendoVariant::C2300,
            HidCrescendoVariant::C4000,
            HidCrescendoVariant::Generic,
        ] {
            let fp = AppletFingerprint::HidCrescendo(variant);
            for version in [&[0][..], &[3, 0, 3, 6][..], &[99][..]] {
                assert_eq!(
                    resolve(PivExtension::MoveKey, fp, Some(version), Some(version)),
                    FeatureGate::Unsupported,
                    "{variant:?} at {version:?}"
                );
            }
        }
    }

    #[test]
    fn hid_crescendo_move_key_without_any_reported_version_matches_the_universal_verdict() {
        // Neither axis reported a version, so `resolve` substitutes the
        // universal `[]` sentinel on both — see `resolve`'s "Both axes
        // unset" doc. MoveKey's row on every HID Crescendo variant is pinned
        // `KnownUnsupportedSince` exactly at `[]`, so that sentinel match
        // resolves `Unsupported`, same as any other version.
        for variant in [
            HidCrescendoVariant::C2300,
            HidCrescendoVariant::C4000,
            HidCrescendoVariant::Generic,
        ] {
            assert_eq!(
                resolve(
                    PivExtension::MoveKey,
                    AppletFingerprint::HidCrescendo(variant),
                    None,
                    None,
                ),
                FeatureGate::Unsupported
            );
        }
    }

    // --- HID Crescendo: DELETE KEY only, `KnownSupported` on C2300/C4000 --

    #[test]
    fn hid_crescendo_c2300_c4000_delete_key_is_known_supported_regardless_of_version() {
        // `Verdict::KnownSupported` at the universal `[]` version: a
        // reported version, present or absent, doesn't change the verdict —
        // unlike a version-gated row (contrast the YubiKey tests above),
        // there's nothing to fall below or above. Still needs *some*
        // reported version to reach the row at all — see
        // `resolve_in`: `applet_version: None` returns `Unverified` before
        // even looking at the table (matches
        // `yubikey_without_a_reported_version_is_unverified`).
        for variant in [HidCrescendoVariant::C2300, HidCrescendoVariant::C4000] {
            let fp = AppletFingerprint::HidCrescendo(variant);
            for version in [&[0][..], &[3, 0, 3, 6][..], &[99][..]] {
                assert_eq!(
                    resolve(PivExtension::DeleteKey, fp, Some(version), Some(version)),
                    FeatureGate::Supported,
                    "{variant:?} at {version:?}"
                );
            }
        }
    }

    #[test]
    fn hid_crescendo_generic_delete_key_carries_no_row_and_stays_unverified() {
        // Deliberately not extended to `Generic` — see `HID_CRESCENDO_C2300_APPLET_VERDICTS`'s
        // Crescendo DeleteKey bullet: this is a presence claim tied to
        // C2300/C4000's own named API references, not the vendor-wide
        // absence pattern that justifies covering `Generic` on that table's
        // MoveKey/Reset HID Crescendo rows.
        assert_eq!(
            resolve(
                PivExtension::DeleteKey,
                AppletFingerprint::HidCrescendo(HidCrescendoVariant::Generic),
                Some(&[3, 0, 3, 6]),
                None,
            ),
            FeatureGate::Unverified
        );
    }

    // --- No row for the fingerprint -------------------------------------

    #[test]
    fn unknown_fingerprint_is_unverified_regardless_of_version() {
        for version in [None, Some(&[5, 7, 4][..]), Some(&[1, 0][..])] {
            assert_eq!(
                resolve(
                    PivExtension::DeleteKey,
                    AppletFingerprint::Generic,
                    version,
                    version,
                ),
                FeatureGate::Unverified
            );
            // A second fingerprint that resolves `Unverified` here too, for
            // a different reason than "no row at all" — unlike
            // `AppletFingerprint::Token2`, whose row's single
            // known-unsupported verdict extends backward to resolve
            // `Unsupported` for these same low versions; see
            // `token2_older_versions_are_also_unsupported`. Also unlike HID
            // Crescendo, which now does carry a row on this table — see
            // `hid_crescendo_move_key_is_known_unsupported_since_regardless_of_version` —
            // unlike either `UTrust` variant, which now also carries one —
            // see `utrust_generic_and_gov_yubico_extensions_are_known_unsupported`
            // — unlike `Feitian`, which now also carries one — see
            // `feitian_yubico_extensions_are_known_unsupported_at_v0` — and
            // unlike `IdPrime`/`OpenFips201::Generic`, which now also each
            // carry one — see
            // `idprime_and_openfips201_generic_yubico_extensions_are_known_unsupported_since`.
            // `AuthentrendATKey` itself now carries a `MoveKey` row too —
            // `Verdict::KnownSupported` floored at `[6]` (the whole v6
            // lineup is assumed to share this support, not just the exact
            // v6.0.1 unit actually tested) — but every version here
            // (`None`, `[5, 7, 4]`, `[1, 0]`) is below that floor, and
            // `Verdict::KnownSupported` says nothing about versions before
            // it, so all three still resolve `Unverified`; see
            // `authentrend_atkey_yubico_extension_set_is_known_supported_at_v6`
            // for the floor-and-above case.
            assert_eq!(
                resolve(
                    PivExtension::MoveKey,
                    AppletFingerprint::AuthentrendATKey,
                    version,
                    version,
                ),
                FeatureGate::Unverified
            );
        }
    }

    // --- combine_strict(): AxisMergeMode::MergeStrict's cross-axis rule ----

    #[test]
    fn combine_strict_prefers_unsupported_over_anything_else() {
        assert_eq!(
            combine_strict(FeatureGate::Unsupported, FeatureGate::Supported),
            FeatureGate::Unsupported
        );
        assert_eq!(
            combine_strict(FeatureGate::Supported, FeatureGate::Unsupported),
            FeatureGate::Unsupported
        );
        assert_eq!(
            combine_strict(FeatureGate::Unverified, FeatureGate::Unsupported),
            FeatureGate::Unsupported
        );
        assert_eq!(
            combine_strict(FeatureGate::Unsupported, FeatureGate::Unverified),
            FeatureGate::Unsupported
        );
    }

    #[test]
    fn combine_strict_prefers_supported_over_unverified() {
        assert_eq!(
            combine_strict(FeatureGate::Supported, FeatureGate::Unverified),
            FeatureGate::Supported
        );
        assert_eq!(
            combine_strict(FeatureGate::Unverified, FeatureGate::Supported),
            FeatureGate::Supported
        );
    }

    #[test]
    fn combine_strict_of_only_unverified_is_unverified() {
        assert_eq!(
            combine_strict(FeatureGate::Unverified, FeatureGate::Unverified),
            FeatureGate::Unverified
        );
    }

    #[test]
    fn combine_strict_is_symmetric_and_idempotent() {
        for gate in [
            FeatureGate::Supported,
            FeatureGate::Unverified,
            FeatureGate::Unsupported,
        ] {
            // Combining a gate with itself is that gate again...
            assert_eq!(combine_strict(gate, gate), gate);
            for other in [
                FeatureGate::Supported,
                FeatureGate::Unverified,
                FeatureGate::Unsupported,
            ] {
                // ...and argument order never matters.
                assert_eq!(combine_strict(gate, other), combine_strict(other, gate));
            }
        }
    }

    // --- combine_relaxed(): AxisMergeMode::MergeRelaxed's cross-axis rule --

    #[test]
    fn combine_relaxed_softens_a_genuine_conflict_to_unverified() {
        // The one case combine_relaxed disagrees with combine_strict on:
        // a real Supported vs. a real Unsupported neither wins outright.
        assert_eq!(
            combine_relaxed(FeatureGate::Unsupported, FeatureGate::Supported),
            FeatureGate::Unverified
        );
        assert_eq!(
            combine_relaxed(FeatureGate::Supported, FeatureGate::Unsupported),
            FeatureGate::Unverified
        );
    }

    #[test]
    fn combine_relaxed_prefers_a_real_verdict_over_unverified() {
        assert_eq!(
            combine_relaxed(FeatureGate::Supported, FeatureGate::Unverified),
            FeatureGate::Supported
        );
        assert_eq!(
            combine_relaxed(FeatureGate::Unverified, FeatureGate::Supported),
            FeatureGate::Supported
        );
        assert_eq!(
            combine_relaxed(FeatureGate::Unsupported, FeatureGate::Unverified),
            FeatureGate::Unsupported
        );
        assert_eq!(
            combine_relaxed(FeatureGate::Unverified, FeatureGate::Unsupported),
            FeatureGate::Unsupported
        );
    }

    #[test]
    fn combine_relaxed_of_only_unverified_is_unverified() {
        assert_eq!(
            combine_relaxed(FeatureGate::Unverified, FeatureGate::Unverified),
            FeatureGate::Unverified
        );
    }

    #[test]
    fn combine_relaxed_is_symmetric_and_idempotent() {
        for gate in [
            FeatureGate::Supported,
            FeatureGate::Unverified,
            FeatureGate::Unsupported,
        ] {
            assert_eq!(combine_relaxed(gate, gate), gate);
            for other in [
                FeatureGate::Supported,
                FeatureGate::Unverified,
                FeatureGate::Unsupported,
            ] {
                assert_eq!(combine_relaxed(gate, other), combine_relaxed(other, gate));
            }
        }
    }

    // --- combine_preferring(): AppletWins/FirmwareWins's tie-break ---------

    #[test]
    fn combine_preferring_agrees_with_relaxed_when_there_is_no_conflict() {
        // No real-vs-real conflict in any of these — `preferred` never gets
        // consulted, so the outcome matches `combine_relaxed` exactly.
        for (a, b) in [
            (FeatureGate::Supported, FeatureGate::Unverified),
            (FeatureGate::Unverified, FeatureGate::Supported),
            (FeatureGate::Unsupported, FeatureGate::Unverified),
            (FeatureGate::Unverified, FeatureGate::Unsupported),
            (FeatureGate::Unverified, FeatureGate::Unverified),
            (FeatureGate::Supported, FeatureGate::Supported),
            (FeatureGate::Unsupported, FeatureGate::Unsupported),
        ] {
            for preferred in [FeatureGate::Supported, FeatureGate::Unsupported] {
                assert_eq!(
                    combine_preferring(a, b, preferred),
                    combine_relaxed(a, b),
                    "a={a:?} b={b:?} preferred={preferred:?}"
                );
            }
        }
    }

    #[test]
    fn combine_preferring_lets_preferred_win_a_genuine_conflict() {
        // Same conflicting inputs `combine_relaxed` softens to Unverified —
        // here `preferred` decides instead, regardless of which side of the
        // conflict it came from.
        assert_eq!(
            combine_preferring(
                FeatureGate::Unsupported,
                FeatureGate::Supported,
                FeatureGate::Unsupported
            ),
            FeatureGate::Unsupported
        );
        assert_eq!(
            combine_preferring(
                FeatureGate::Unsupported,
                FeatureGate::Supported,
                FeatureGate::Supported
            ),
            FeatureGate::Supported
        );
        assert_eq!(
            combine_preferring(
                FeatureGate::Supported,
                FeatureGate::Unsupported,
                FeatureGate::Unsupported
            ),
            FeatureGate::Unsupported
        );
        assert_eq!(
            combine_preferring(
                FeatureGate::Supported,
                FeatureGate::Unsupported,
                FeatureGate::Supported
            ),
            FeatureGate::Supported
        );
    }

    // --- merge_gates(): mode dispatch ---------------------------------------

    #[test]
    fn merge_gates_dispatches_strict_and_relaxed_to_their_own_primitive() {
        // A genuine conflict is exactly where strict and relaxed disagree —
        // the case that actually proves each mode reaches its own primitive
        // rather than both collapsing onto the same behavior.
        let (a, b) = (FeatureGate::Unsupported, FeatureGate::Supported);
        assert_eq!(
            merge_gates(AxisMergeMode::MergeStrict, a, b),
            combine_strict(a, b)
        );
        assert_eq!(
            merge_gates(AxisMergeMode::MergeRelaxed, a, b),
            combine_relaxed(a, b)
        );
        assert_eq!(
            merge_gates(AxisMergeMode::MergeStrict, a, b),
            FeatureGate::Unsupported
        );
        assert_eq!(
            merge_gates(AxisMergeMode::MergeRelaxed, a, b),
            FeatureGate::Unverified
        );
    }

    #[test]
    fn merge_gates_applet_wins_and_firmware_wins_break_a_conflict_toward_their_own_axis() {
        let (applet_gate, firmware_gate) = (FeatureGate::Unsupported, FeatureGate::Supported);
        assert_eq!(
            merge_gates(AxisMergeMode::AppletWins, applet_gate, firmware_gate),
            FeatureGate::Unsupported
        );
        assert_eq!(
            merge_gates(AxisMergeMode::FirmwareWins, applet_gate, firmware_gate),
            FeatureGate::Supported
        );
    }

    #[test]
    fn merge_gates_applet_wins_and_firmware_wins_still_let_a_real_verdict_beat_unverified() {
        // No conflict here (one side is Unverified) — AppletWins/FirmwareWins
        // must not override a lone real verdict just because it happens to
        // sit on the "losing" axis.
        assert_eq!(
            merge_gates(
                AxisMergeMode::AppletWins,
                FeatureGate::Unverified,
                FeatureGate::Supported
            ),
            FeatureGate::Supported
        );
        assert_eq!(
            merge_gates(
                AxisMergeMode::FirmwareWins,
                FeatureGate::Supported,
                FeatureGate::Unverified
            ),
            FeatureGate::Supported
        );
    }

    // --- The resolve() rules, exercised against a synthetic row ---------

    fn gate(verdicts: &'static [VersionVerdict], version: Option<&[u8]>) -> FeatureGate {
        resolve_in(Some(verdicts), version)
    }

    #[test]
    fn applet_older_than_every_known_supported_verdict_is_unverified() {
        // The nearest verdict above is known-supported, which says nothing about
        // versions before it, so there's nothing to extend backward.
        assert_eq!(
            gate(
                &[VersionVerdict {
                    version: &[5, 0],
                    verdict: Verdict::KnownSupported,
                }],
                Some(&[4, 9]),
            ),
            FeatureGate::Unverified
        );
    }

    #[test]
    fn applet_older_than_every_known_unsupported_verdict_is_unsupported() {
        // The nearest verdict above is known-unsupported: a feature known not to
        // work at that version is assumed not to work at any earlier,
        // untested version either — the backward mirror of
        // `earlier_known_supported_is_assumed_not_to_regress` below.
        assert_eq!(
            gate(
                &[VersionVerdict {
                    version: &[5, 0],
                    verdict: Verdict::KnownUnsupported,
                }],
                Some(&[4, 9]),
            ),
            FeatureGate::Unsupported
        );
    }

    #[test]
    fn applet_older_than_every_verdict_uses_the_nearest_one_above() {
        // Two verdicts, both above the reported version: the fallback picks
        // the row's first (lowest, i.e. nearest-above) entry, not just any
        // entry — so a known-unsupported verdict further above doesn't leak backward past a
        // known-supported verdict that's nearer.
        assert_eq!(
            gate(
                &[
                    VersionVerdict {
                        version: &[5, 0],
                        verdict: Verdict::KnownSupported,
                    },
                    VersionVerdict {
                        version: &[6, 0],
                        verdict: Verdict::KnownUnsupported,
                    },
                ],
                Some(&[4, 9]),
            ),
            FeatureGate::Unverified
        );
    }

    #[test]
    fn exact_version_known_unsupported_match_is_unsupported() {
        assert_eq!(
            gate(
                &[VersionVerdict {
                    version: &[5, 7],
                    verdict: Verdict::KnownUnsupported,
                }],
                Some(&[5, 7]),
            ),
            FeatureGate::Unsupported
        );
    }

    #[test]
    fn trailing_stale_known_unsupported_is_unverified() {
        // Only known-unsupported, from a version below the applet's, and it is the
        // last verdict — the extension might have been added since.
        assert_eq!(
            gate(
                &[VersionVerdict {
                    version: &[5, 0],
                    verdict: Verdict::KnownUnsupported,
                }],
                Some(&[5, 4]),
            ),
            FeatureGate::Unverified
        );
    }

    #[test]
    fn bracketed_known_unsupported_stays_authoritative() {
        // A known-unsupported verdict below the applet's version, with a later verdict above
        // it: keyroost's known-unsupported knowledge brackets the applet version.
        assert_eq!(
            gate(
                &[
                    VersionVerdict {
                        version: &[5, 0],
                        verdict: Verdict::KnownUnsupported,
                    },
                    VersionVerdict {
                        version: &[6, 0],
                        verdict: Verdict::KnownSupported,
                    },
                ],
                Some(&[5, 4]),
            ),
            FeatureGate::Unsupported
        );
    }

    #[test]
    fn earlier_known_supported_is_assumed_not_to_regress() {
        assert_eq!(
            gate(
                &[VersionVerdict {
                    version: &[5, 7],
                    verdict: Verdict::KnownSupported,
                }],
                Some(&[9, 1, 2]),
            ),
            FeatureGate::Supported
        );
    }

    // --- KnownUnsupportedSince: the mirror image of KnownSupported's -----
    // --- extension direction ----------------------------------------------

    #[test]
    fn applet_older_than_every_known_unsupported_since_verdict_is_unverified() {
        // Same fallback shape as `applet_older_than_every_known_supported_verdict_is_unverified`:
        // the nearest verdict above says nothing about versions before it,
        // so there's nothing to extend backward — unlike plain
        // `KnownUnsupported`, which *would* extend backward here.
        assert_eq!(
            gate(
                &[VersionVerdict {
                    version: &[5, 0],
                    verdict: Verdict::KnownUnsupportedSince,
                }],
                Some(&[4, 9]),
            ),
            FeatureGate::Unverified
        );
    }

    #[test]
    fn known_unsupported_since_never_softens_to_unverified_going_forward() {
        // Unlike plain `KnownUnsupported` (see
        // `trailing_stale_known_unsupported_is_unverified`), being the row's
        // last (highest) verdict doesn't soften this to `Unverified` — the
        // whole point of this variant is that it's assumed to stay
        // unsupported indefinitely.
        assert_eq!(
            gate(
                &[VersionVerdict {
                    version: &[5, 0],
                    verdict: Verdict::KnownUnsupportedSince,
                }],
                Some(&[9, 9, 9]),
            ),
            FeatureGate::Unsupported
        );
        // Exact match on the verdict's own version, same as the fallback
        // that fires when nothing is strictly below it.
        assert_eq!(
            gate(
                &[VersionVerdict {
                    version: &[5, 0],
                    verdict: Verdict::KnownUnsupportedSince,
                }],
                Some(&[5, 0]),
            ),
            FeatureGate::Unsupported
        );
    }

    #[test]
    fn known_unsupported_since_at_the_universal_empty_version_covers_everything() {
        // `[]` orders at or below every real version, so a lone
        // `KnownUnsupportedSince` verdict there is always the chosen one —
        // never the "older than every verdict" fallback — and, per the test
        // above, never softens going forward either. This is the exact shape
        // `HID_CRESCENDO_C2300_APPLET_VERDICTS`'s GetMetadata/Attest rows use
        // C2300/C4000.
        let verdicts: &[VersionVerdict] = &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownUnsupportedSince,
        }];
        for version in [&[0][..], &[3, 0, 3, 6][..], &[255, 255, 255][..]] {
            assert_eq!(gate(verdicts, Some(version)), FeatureGate::Unsupported);
        }
    }

    // --- resolve_quirks(): the separate, non-gating quirks axis ----------

    fn quirks(
        applet_entries: &'static [VersionQuirks],
        firmware_entries: &'static [VersionQuirks],
        applet_version: Option<&[u8]>,
        firmware_version: Option<&[u8]>,
    ) -> BTreeSet<PivQuirk> {
        resolve_quirks_in(
            applet_entries,
            firmware_entries,
            applet_version,
            firmware_version,
        )
    }

    #[test]
    fn no_data_on_either_axis_resolves_to_no_quirks() {
        // OpenFips201::Generic carries no quirk row at all on either axis —
        // unlike YubiKey or either UTrust variant, each with its own default
        // management key (see `default_9b_management_key_seeded_fingerprints`
        // and `utrust_gov_has_its_own_default_management_key_not_the_yubikey_one`),
        // or IdPrime, which now carries
        // `PivQuirk::HostChallengeResponsePermissiveTag` (see
        // `idprime_has_the_host_challenge_response_permissive_tag_quirk`).
        assert_eq!(
            resolve_quirks(
                AppletFingerprint::OpenFips201(OpenFips201Variant::Generic),
                Some(&[5, 7]),
                Some(&[5, 7])
            ),
            BTreeSet::new()
        );
    }

    #[test]
    fn idprime_has_the_host_challenge_response_permissive_tag_quirk() {
        // Hardware-observed on a live unit's management-key GENERAL
        // AUTHENTICATE trace — see `IDPRIME_APPLET_QUIRKS`'s doc. Seeded at
        // the universal `[]` floor alongside `Default9bManagementKey` (see
        // `idprime_shares_utrust_govs_default_management_key`), so both apply
        // regardless of reported version (including no version at all).
        assert_eq!(
            resolve_quirks(AppletFingerprint::IdPrime, None, None),
            BTreeSet::from([
                PivQuirk::HostChallengeResponsePermissiveTag,
                PivQuirk::Default9bManagementKey(IDPRIME_AND_UTRUST_GOV_DEFAULT_MGMT_KEY),
            ])
        );
        assert_eq!(
            resolve_quirks(AppletFingerprint::IdPrime, Some(&[5, 7]), Some(&[5, 7])),
            BTreeSet::from([
                PivQuirk::HostChallengeResponsePermissiveTag,
                PivQuirk::Default9bManagementKey(IDPRIME_AND_UTRUST_GOV_DEFAULT_MGMT_KEY),
            ])
        );
    }

    #[test]
    fn quirk_axis_picks_the_highest_matching_version() {
        let entries: &[VersionQuirks] = &[
            VersionQuirks {
                version: &[5, 0],
                quirks: &[PivQuirk::InsF8SerialIsBcd],
            },
            VersionQuirks {
                version: &[5, 7],
                quirks: &[PivQuirk::InsF7MetadataAlgorithmInvalid],
            },
        ];
        // Below every entry: no quirks at all.
        assert_eq!(quirks(entries, &[], Some(&[4, 9]), None), BTreeSet::new());
        // Between the two entries: only the lower one's quirk applies.
        assert_eq!(
            quirks(entries, &[], Some(&[5, 3]), None),
            BTreeSet::from([PivQuirk::InsF8SerialIsBcd])
        );
        // At or above the higher entry: only *its* quirk — entries don't
        // accumulate across each other, only across the two axes.
        assert_eq!(
            quirks(entries, &[], Some(&[6, 0]), None),
            BTreeSet::from([PivQuirk::InsF7MetadataAlgorithmInvalid])
        );
    }

    #[test]
    fn quirks_from_both_axes_merge_into_one_set() {
        let applet_entries: &[VersionQuirks] = &[VersionQuirks {
            version: &[],
            quirks: &[PivQuirk::InsF8SerialIsBcd],
        }];
        let firmware_entries: &[VersionQuirks] = &[VersionQuirks {
            version: &[],
            quirks: &[PivQuirk::InsF7MetadataAlgorithmInvalid],
        }];
        assert_eq!(
            quirks(
                applet_entries,
                firmware_entries,
                Some(&[1, 0]),
                Some(&[1, 0]),
            ),
            BTreeSet::from([
                PivQuirk::InsF8SerialIsBcd,
                PivQuirk::InsF7MetadataAlgorithmInvalid,
            ])
        );
    }

    #[test]
    fn quirks_ignore_an_axis_with_no_reported_version() {
        let applet_entries: &[VersionQuirks] = &[VersionQuirks {
            version: &[],
            quirks: &[PivQuirk::InsF8SerialIsBcd],
        }];
        assert_eq!(
            quirks(applet_entries, &[], None, Some(&[9, 9])),
            BTreeSet::new()
        );
    }

    #[test]
    fn unknown_fingerprint_has_no_quirks() {
        // OpenFips201::Generic, again, at a different version — see
        // `no_data_on_either_axis_resolves_to_no_quirks` for why plain
        // `Generic` no longer fits this test: it now carries its own
        // `Default9bManagementKey` row (see
        // `default_9b_management_key_seeded_fingerprints`) — and why IdPrime
        // no longer fits it either: it now carries
        // `PivQuirk::HostChallengeResponsePermissiveTag` (see
        // `idprime_has_the_host_challenge_response_permissive_tag_quirk`).
        assert_eq!(
            resolve_quirks(
                AppletFingerprint::OpenFips201(OpenFips201Variant::Generic),
                Some(&[1, 0]),
                Some(&[1, 0])
            ),
            BTreeSet::new()
        );
    }

    // --- merge_quirk_sets(): AppletWins/FirmwareWins's exclusive pick -------

    #[test]
    fn merge_quirk_sets_unions_for_relaxed_and_strict_exactly_like_resolve_quirks_in() {
        let applet_entries: &[VersionQuirks] = &[VersionQuirks {
            version: &[],
            quirks: &[PivQuirk::InsF8SerialIsBcd],
        }];
        let firmware_entries: &[VersionQuirks] = &[VersionQuirks {
            version: &[],
            quirks: &[PivQuirk::ResetLongRunning],
        }];
        let expected: BTreeSet<PivQuirk> =
            [PivQuirk::InsF8SerialIsBcd, PivQuirk::ResetLongRunning].into();
        for mode in [AxisMergeMode::MergeRelaxed, AxisMergeMode::MergeStrict] {
            assert_eq!(
                merge_quirk_sets(
                    mode,
                    applet_entries,
                    Some(&[1, 0]),
                    firmware_entries,
                    Some(&[1, 0])
                ),
                expected
            );
        }
    }

    #[test]
    fn merge_quirk_sets_applet_wins_and_firmware_wins_pick_exclusively_when_both_reported() {
        let applet_entries: &[VersionQuirks] = &[VersionQuirks {
            version: &[],
            quirks: &[PivQuirk::InsF8SerialIsBcd],
        }];
        let firmware_entries: &[VersionQuirks] = &[VersionQuirks {
            version: &[],
            quirks: &[PivQuirk::ResetLongRunning],
        }];
        assert_eq!(
            merge_quirk_sets(
                AxisMergeMode::AppletWins,
                applet_entries,
                Some(&[1, 0]),
                firmware_entries,
                Some(&[1, 0])
            ),
            [PivQuirk::InsF8SerialIsBcd].into()
        );
        assert_eq!(
            merge_quirk_sets(
                AxisMergeMode::FirmwareWins,
                applet_entries,
                Some(&[1, 0]),
                firmware_entries,
                Some(&[1, 0])
            ),
            [PivQuirk::ResetLongRunning].into()
        );
    }

    #[test]
    fn merge_quirk_sets_applet_wins_and_firmware_wins_fall_back_to_union_with_only_one_axis_reported(
    ) {
        // Only the applet axis reported a version — AppletWins/FirmwareWins
        // have nothing to pick an exclusive winner from, so both fall back
        // to the ordinary union (identical to `MergeRelaxed`/`MergeStrict`).
        let applet_entries: &[VersionQuirks] = &[VersionQuirks {
            version: &[],
            quirks: &[PivQuirk::InsF8SerialIsBcd],
        }];
        let firmware_entries: &[VersionQuirks] = &[VersionQuirks {
            version: &[],
            quirks: &[PivQuirk::ResetLongRunning],
        }];
        for mode in [AxisMergeMode::AppletWins, AxisMergeMode::FirmwareWins] {
            assert_eq!(
                merge_quirk_sets(mode, applet_entries, Some(&[1, 0]), firmware_entries, None),
                [PivQuirk::InsF8SerialIsBcd].into()
            );
        }
    }

    // --- Every fingerprint's default AxisMergeMode --------------------------

    #[test]
    fn every_fingerprint_defaults_to_merge_relaxed() {
        // A deliberate, visible assertion: today every fingerprint is seeded
        // on `MergeRelaxed` (see `AxisMergeMode`'s own doc for why that has
        // no live effect yet). Changing any one fingerprint's mode should
        // break this test, not drift by silently.
        for fp in [
            AppletFingerprint::YubiKey,
            AppletFingerprint::Token2,
            AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2),
            AppletFingerprint::OpenFips201(OpenFips201Variant::Generic),
            AppletFingerprint::Thetis,
            AppletFingerprint::ArekinathPivApplet(ArekinathVariant::Generic),
            AppletFingerprint::ArekinathPivApplet(ArekinathVariant::SwissbitIShield1),
            AppletFingerprint::HidCrescendo(HidCrescendoVariant::C2300),
            AppletFingerprint::HidCrescendo(HidCrescendoVariant::C4000),
            AppletFingerprint::HidCrescendo(HidCrescendoVariant::Generic),
            AppletFingerprint::Generic,
            AppletFingerprint::AuthentrendATKey,
            AppletFingerprint::Feitian,
            AppletFingerprint::IdPrime,
            AppletFingerprint::Trussed(TrussedVariant::NitroKey),
            AppletFingerprint::UTrust(UTrustVariant::Generic),
            AppletFingerprint::UTrust(UTrustVariant::Gov),
        ] {
            assert_eq!(axis_merge_mode(fp), AxisMergeMode::MergeRelaxed, "{fp:?}");
        }
    }

    // --- Token2: the seeded BCD-serial quirk ------------------------------

    #[test]
    fn token2_bcd_serial_quirk_matches_any_reported_applet_version() {
        // The `[]` sentinel orders at or below every real version, so this
        // fires regardless of how old or new the reported version is. Token2
        // also carries its own vendor-specific default management key on the
        // same row — see `default_9b_management_key_seeded_fingerprints`.
        for version in [&[0, 0][..], &[1, 0][..], &[9, 9, 9][..]] {
            assert_eq!(
                resolve_quirks(AppletFingerprint::Token2, Some(version), None),
                BTreeSet::from([
                    PivQuirk::InsF8SerialIsBcd,
                    PivQuirk::Default9bManagementKey(TOKEN2_DEFAULT_MGMT_KEY),
                ])
            );
        }
    }

    #[test]
    fn token2_bcd_serial_quirk_still_matches_with_no_reported_version_at_all() {
        // Neither axis reported a version, so `resolve_quirks` substitutes
        // the universal `[]` sentinel on both — see its own "Both axes
        // unset" doc. Token2's quirk row is seeded exactly there, so it
        // still applies; the firmware axis contributes nothing regardless,
        // since Token2 has no firmware-axis quirk data at all.
        assert_eq!(
            resolve_quirks(AppletFingerprint::Token2, None, None),
            BTreeSet::from([
                PivQuirk::InsF8SerialIsBcd,
                PivQuirk::Default9bManagementKey(TOKEN2_DEFAULT_MGMT_KEY),
            ])
        );
    }

    // --- Thetis PRO FIDO2 Security Key with PinPlex: the seeded --------
    // --- BCD-serial quirk --------------------------------------------------

    #[test]
    fn thetis_bcd_serial_quirk_matches_any_reported_applet_version() {
        // The `[]` sentinel orders at or below every real version, so this
        // fires regardless of how old or new the reported version is —
        // including versions below 5.112.0, the only one actually tested;
        // see the row's comment on why that's an assumption, not an
        // observation. Thetis mimics the YubiKey default management key too
        // — see `default_9b_management_key_seeded_fingerprints`.
        for version in [&[0, 0][..], &[1, 0][..], &[9, 9, 9][..]] {
            assert_eq!(
                resolve_quirks(AppletFingerprint::Thetis, Some(version), None),
                BTreeSet::from([
                    PivQuirk::InsF8SerialIsBcd,
                    PivQuirk::Default9bManagementKey(YUBIKEY_DEFAULT_MGMT_KEY),
                ])
            );
        }
        // Neither axis reported a version at all: `resolve_quirks`
        // substitutes the universal `[]` sentinel on both, so this still
        // matches the same row as every version above.
        assert_eq!(
            resolve_quirks(AppletFingerprint::Thetis, None, None),
            BTreeSet::from([
                PivQuirk::InsF8SerialIsBcd,
                PivQuirk::Default9bManagementKey(YUBIKEY_DEFAULT_MGMT_KEY),
            ])
        );
    }

    // --- Swissbit iShield 2 Pro (OpenFips201): the seeded, then-cleared, -
    // --- GET METADATA algorithm-identifier quirk -------------------------

    #[test]
    fn swissbit_ishield2_metadata_quirk_applies_at_every_version() {
        // The sentinel version `[]` matches regardless of how old the
        // reported version is, so this is active from the very first
        // version on record — and, unlike a normal version-gated quirk,
        // there is no later version it clears at either: a 1.4.1.0 unit was
        // observed to report reliably when brand-new and unreliably again
        // after several key generations (applet reset included), so every
        // tested and hypothetical future version carries it. The default-
        // management-key and PIN/touch-policy quirks ride along on the same
        // single entry — see `default_9b_management_key_seeded_fingerprints`.
        for version in [
            &[0][..],
            &[1][..],
            &[1, 3, 9][..],
            &[1, 4, 0][..],
            &[1, 4, 1][..],
            &[1, 4, 1, 0][..],
            &[1, 5, 0][..],
            &[2, 0][..],
        ] {
            assert_eq!(
                resolve_quirks(
                    AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2),
                    Some(version),
                    None,
                ),
                BTreeSet::from([
                    PivQuirk::InsF7MetadataAlgorithmInvalid,
                    PivQuirk::InsF7MetadataPinTouchPolicyInvalid,
                    PivQuirk::Default9bManagementKey(YUBIKEY_DEFAULT_MGMT_KEY),
                ]),
                "{version:?}"
            );
        }
    }

    #[test]
    fn swissbit_ishield2_other_openfips201_variant_has_no_quirk() {
        // The row is keyed to the SwissbitIShield2 sub-fingerprint
        // specifically — the generic OpenFIPS201 variant isn't covered.
        assert_eq!(
            resolve_quirks(
                AppletFingerprint::OpenFips201(OpenFips201Variant::Generic),
                Some(&[1]),
                None,
            ),
            BTreeSet::new()
        );
    }

    // --- PivQuirk::Default9bManagementKey: the seeded factory-default -----
    // --- management-key quirk, by fingerprint -----------------------------

    #[test]
    fn default_9b_management_key_seeded_fingerprints() {
        let yubikey_mimics = [
            AppletFingerprint::Generic,
            AppletFingerprint::YubiKey,
            AppletFingerprint::ArekinathPivApplet(ArekinathVariant::Generic),
            AppletFingerprint::ArekinathPivApplet(ArekinathVariant::SwissbitIShield1),
            AppletFingerprint::AuthentrendATKey,
            AppletFingerprint::UTrust(UTrustVariant::Generic),
            AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2),
            AppletFingerprint::Trussed(TrussedVariant::NitroKey),
        ];
        for fp in yubikey_mimics {
            assert_eq!(
                default_9b_management_key(&resolve_quirks(fp, Some(&[0]), None)),
                Some(YUBIKEY_DEFAULT_MGMT_KEY),
                "{fp:?}"
            );
        }
        // Thetis carries its own row (with `InsF8SerialIsBcd` alongside it —
        // see `thetis_bcd_serial_quirk_matches_any_reported_applet_version`),
        // so it's checked separately rather than folded into the loop above.
        assert_eq!(
            default_9b_management_key(&resolve_quirks(AppletFingerprint::Thetis, Some(&[0]), None)),
            Some(YUBIKEY_DEFAULT_MGMT_KEY)
        );

        assert_eq!(
            default_9b_management_key(&resolve_quirks(AppletFingerprint::Token2, Some(&[0]), None)),
            Some(TOKEN2_DEFAULT_MGMT_KEY)
        );
        assert_eq!(
            default_9b_management_key(&resolve_quirks(
                AppletFingerprint::Feitian,
                Some(&[0]),
                None
            )),
            Some(FEITIAN_DEFAULT_MGMT_KEY)
        );
        for variant in [
            HidCrescendoVariant::C2300,
            HidCrescendoVariant::C4000,
            HidCrescendoVariant::Generic,
        ] {
            assert_eq!(
                default_9b_management_key(&resolve_quirks(
                    AppletFingerprint::HidCrescendo(variant),
                    Some(&[0]),
                    None,
                )),
                Some(&HID_CRESCENDO_ACA_FACTORY_XAUTH_KEY[..]),
                "{variant:?}"
            );
        }
    }

    #[test]
    fn utrust_gov_has_its_own_default_management_key_not_the_yubikey_one() {
        // Unlike `UTrust::Generic` above, `UTrust::Gov` doesn't mimic the
        // YubiKey default management key — per internal documentation
        // (<https://hirschsecure.atlassian.net/wiki/spaces/FIDO/pages/4395401218/PIV>)
        // it ships its own, shorter one instead (16 bytes vs. YubiKey's 24).
        // `classify` can't produce this fingerprint yet regardless — see
        // `UTrustVariant::Gov`'s doc — but the data is seeded ahead of that.
        assert_eq!(
            default_9b_management_key(&resolve_quirks(
                AppletFingerprint::UTrust(UTrustVariant::Gov),
                Some(&[0]),
                None
            )),
            Some(IDPRIME_AND_UTRUST_GOV_DEFAULT_MGMT_KEY)
        );
    }

    #[test]
    fn idprime_shares_utrust_govs_default_management_key() {
        // Hardware-observed on a live unit: IdPrime's factory-default `0x9B`
        // key is the exact same 16-byte AES-128 pattern as `UTrust::Gov`'s
        // (see `utrust_gov_has_its_own_default_management_key_not_the_yubikey_one`
        // right above) — `IDPRIME_APPLET_QUIRKS` reuses that same constant
        // rather than duplicating the byte pattern under a second name.
        assert_eq!(
            default_9b_management_key(&resolve_quirks(
                AppletFingerprint::IdPrime,
                Some(&[0]),
                None
            )),
            Some(IDPRIME_AND_UTRUST_GOV_DEFAULT_MGMT_KEY)
        );
    }

    #[test]
    fn default_9b_management_key_applies_below_and_at_yubikey_applet_version_3() {
        // The default management key applies at any reported version,
        // including below 3 — unlike `SlotTouchPolicyCachedNotSupported`,
        // which only starts at applet version 3 (see
        // `YUBIKEY_APPLET_QUIRKS`'s own doc).
        for version in [&[0][..], &[2, 9][..], &[3][..], &[5, 7][..]] {
            assert_eq!(
                default_9b_management_key(&resolve_quirks(
                    AppletFingerprint::YubiKey,
                    Some(version),
                    None
                )),
                Some(YUBIKEY_DEFAULT_MGMT_KEY),
                "{version:?}"
            );
        }
    }

    #[test]
    fn default_9b_management_key_absent_without_a_seeded_row() {
        // IdPrime no longer belongs here — it now carries its own
        // `Default9bManagementKey` row (see
        // `idprime_shares_utrust_govs_default_management_key`).
        assert_eq!(
            default_9b_management_key(&resolve_quirks(
                AppletFingerprint::OpenFips201(OpenFips201Variant::Generic),
                Some(&[0]),
                None
            )),
            None
        );
    }

    #[test]
    fn default_9b_management_key_still_present_without_any_reported_version() {
        // Neither axis reported a version at all: `resolve_quirks`
        // substitutes the universal `[]` sentinel on both — see its own
        // "Both axes unset" doc — so YubiKey's row, seeded exactly there,
        // still applies rather than silently disappearing.
        assert_eq!(
            default_9b_management_key(&resolve_quirks(AppletFingerprint::YubiKey, None, None)),
            Some(YUBIKEY_DEFAULT_MGMT_KEY)
        );
    }

    #[test]
    fn default_9b_management_key_absent_without_a_reported_version_when_genuinely_unseeded() {
        // Unlike YubiKey above, OpenFips201::Generic carries no quirk row at
        // all on either axis (see `no_data_on_either_axis_resolves_to_no_quirks`),
        // so there's no `[]`-seeded row for the substitution to find even
        // once it applies — this still resolves no quirks, the "genuinely no
        // data" case the substitution doesn't paper over. IdPrime no longer
        // fits this test: it now carries its own `[]`-seeded
        // `PivQuirk::HostChallengeResponsePermissiveTag` row (see
        // `idprime_has_the_host_challenge_response_permissive_tag_quirk`), so
        // its quirk set isn't empty any more — `default_9b_management_key`
        // still correctly reads `None` off it, just not for "no data at all"
        // reasons.
        assert_eq!(
            default_9b_management_key(&resolve_quirks(
                AppletFingerprint::OpenFips201(OpenFips201Variant::Generic),
                None,
                None
            )),
            None
        );
    }

    // --- PivQuirk::ResetLongRunning: SwissbitIShield1's slow RESET ---------

    #[test]
    fn swissbit_ishield1_carries_reset_long_running_at_any_version() {
        // Seeded at the universal `[]` version, so it applies from the
        // lowest reported version on up, alongside the shared
        // default-management-key and AES-reset quirks every other
        // ArekinathPivApplet fingerprint also carries.
        for version in [&[0][..], &[5, 4, 0][..], &[9, 9, 9][..]] {
            assert_eq!(
                resolve_quirks(
                    AppletFingerprint::ArekinathPivApplet(ArekinathVariant::SwissbitIShield1),
                    Some(version),
                    None,
                ),
                BTreeSet::from([
                    PivQuirk::Default9bManagementKey(YUBIKEY_DEFAULT_MGMT_KEY),
                    PivQuirk::ResetFailsIfManagementKeyIsAes,
                    PivQuirk::ResetLongRunning,
                ]),
                "{version:?}"
            );
        }
    }

    #[test]
    fn arekinath_generic_has_no_reset_long_running_quirk() {
        // The quirk is scoped to the SwissbitIShield1 sub-fingerprint
        // specifically, not the whole ArekinathPivApplet family — `Generic`
        // shares the default-management-key and AES-reset rows but not this
        // one.
        assert_eq!(
            resolve_quirks(
                AppletFingerprint::ArekinathPivApplet(ArekinathVariant::Generic),
                Some(&[0]),
                None,
            ),
            BTreeSet::from([
                PivQuirk::Default9bManagementKey(YUBIKEY_DEFAULT_MGMT_KEY),
                PivQuirk::ResetFailsIfManagementKeyIsAes,
            ])
        );
    }

    // --- PivQuirk::ResetFailsIfManagementKeyIsAes: ArekinathPivApplet's -----
    // --- AES-management-key RESET bug, both variants ------------------------

    #[test]
    fn arekinath_both_variants_carry_reset_fails_if_management_key_is_aes_at_any_version() {
        // A bug in the shared upstream source itself (see the quirk's own
        // doc), not tied to any particular sampled firmware — seeded at the
        // universal `[]` version, so it applies regardless of reported
        // version, on both fingerprints that share this codebase.
        for fp in [
            AppletFingerprint::ArekinathPivApplet(ArekinathVariant::Generic),
            AppletFingerprint::ArekinathPivApplet(ArekinathVariant::SwissbitIShield1),
        ] {
            for version in [&[0][..], &[5, 4, 0][..], &[9, 9, 9][..]] {
                assert!(
                    resolve_quirks(fp, Some(version), None)
                        .contains(&PivQuirk::ResetFailsIfManagementKeyIsAes),
                    "{fp:?} {version:?}"
                );
            }
        }
    }

    // --- HID Crescendo (C2300 and C4000): GET METADATA/ATTEST known-unsupported --
    // --- by their own GET PIV PROPERTIES version, on the applet axis -------

    #[test]
    fn hid_crescendo_c2300_get_metadata_and_attest_known_unsupported_at_any_version() {
        let fp = AppletFingerprint::HidCrescendo(HidCrescendoVariant::C2300);
        for ext in [PivExtension::GetMetadata, PivExtension::Attest] {
            // The one version actually observed (`3.0.3.6`, family byte
            // already stripped by `parse_hid_crescendo_version`) — on the
            // *applet* axis, since it's an applet version despite coming
            // from GET PIV PROPERTIES rather than Yubico's GET VERSION
            // extension.
            assert_eq!(
                resolve(ext, fp, Some(&[3, 0, 3, 6]), None),
                FeatureGate::Unsupported
            );
            // Older and newer versions alike — `KnownUnsupportedSince` at the
            // universal `[]` version makes no exception in either direction,
            // unlike an ordinary `KnownUnsupported` pinned to one build.
            assert_eq!(resolve(ext, fp, Some(&[0]), None), FeatureGate::Unsupported);
            assert_eq!(
                resolve(ext, fp, Some(&[9, 9, 9, 9]), None),
                FeatureGate::Unsupported
            );
            // No applet version at all (HID Crescendo's own GET VERSION
            // extension didn't answer, and its GET PIV PROPERTIES read
            // itself hasn't happened yet either), and no firmware version
            // either — `resolve` substitutes the universal `[]` sentinel on
            // both axes when neither is reported, so this still matches the
            // same `KnownUnsupportedSince` row as every other version above.
            assert_eq!(resolve(ext, fp, None, None), FeatureGate::Unsupported);
        }
    }

    #[test]
    fn hid_crescendo_generic_has_no_get_metadata_attest_data() {
        // Generic never selects a recognised model at all, so there's no
        // version source for it either way.
        let fp = AppletFingerprint::HidCrescendo(HidCrescendoVariant::Generic);
        for ext in [PivExtension::GetMetadata, PivExtension::Attest] {
            assert_eq!(
                resolve(ext, fp, Some(&[3, 0, 3, 6]), None),
                FeatureGate::Unverified
            );
        }
    }

    #[test]
    fn hid_crescendo_c4000_get_metadata_and_attest_known_unsupported_by_documentation() {
        // Assumed from HID's own C4000 documentation, not confirmed on
        // hardware — see `HID_CRESCENDO_C4000_APPLET_VERDICTS`'s doc. Same
        // `KnownUnsupportedSince` at the universal `[]` version as C2300, so
        // no version — documented, observed, or hypothetical-future — is an
        // exception.
        let fp = AppletFingerprint::HidCrescendo(HidCrescendoVariant::C4000);
        for ext in [PivExtension::GetMetadata, PivExtension::Attest] {
            // The documented current version.
            assert_eq!(
                resolve(ext, fp, Some(&[4, 0, 0, 12, 34]), None),
                FeatureGate::Unsupported
            );
            // Anything older than 4.0.0 altogether.
            assert_eq!(
                resolve(ext, fp, Some(&[3, 9, 9, 9, 9]), None),
                FeatureGate::Unsupported
            );
            // A hypothetical future applet revision — unlike an ordinary
            // `KnownUnsupported` row, this doesn't soften to `Unverified`
            // just for being newer than anything documented so far.
            assert_eq!(
                resolve(ext, fp, Some(&[5, 0, 0, 0, 0]), None),
                FeatureGate::Unsupported
            );
            // Neither axis reported at all: `resolve` substitutes the
            // universal `[]` sentinel on both, so this still matches the
            // same `KnownUnsupportedSince` row.
            assert_eq!(resolve(ext, fp, None, None), FeatureGate::Unsupported);
        }
    }

    #[test]
    fn get_metadata_and_attest_data_does_not_leak_to_other_fingerprints() {
        for ext in [PivExtension::GetMetadata, PivExtension::Attest] {
            assert_eq!(
                resolve(ext, AppletFingerprint::Generic, None, None),
                FeatureGate::Unverified
            );
        }
        // Attest specifically: Token2 carries no row for it (unlike
        // GetMetadata, which has its own genuine `TOKEN2_APPLET_VERDICTS` row
        // now — see `token2_and_thetis_5_112_0_get_metadata_is_supported`
        // below — so it's deliberately not part of this leak check anymore).
        assert_eq!(
            resolve(
                PivExtension::Attest,
                AppletFingerprint::Token2,
                Some(&[5, 112, 0]),
                None,
            ),
            FeatureGate::Unverified
        );
    }

    // --- Token2/Thetis GET METADATA: KnownSupported at 5.112.0 -------------

    #[test]
    fn token2_and_thetis_5_112_0_get_metadata_is_supported() {
        for fp in [AppletFingerprint::Token2, AppletFingerprint::Thetis] {
            assert_eq!(
                resolve(PivExtension::GetMetadata, fp, Some(&[5, 112, 0]), None),
                FeatureGate::Supported
            );
            // No known-unsupported floor recorded below 5.112.0 on either
            // row, so an older reported version resolves `Unverified` rather
            // than inheriting the known-supported verdict backward.
            assert_eq!(
                resolve(PivExtension::GetMetadata, fp, Some(&[5, 111, 0]), None),
                FeatureGate::Unverified
            );
            // A later, untested version is assumed not to have regressed —
            // same forward no-regression rule as every other
            // `Verdict::KnownSupported` row.
            assert_eq!(
                resolve(PivExtension::GetMetadata, fp, Some(&[5, 113, 0]), None),
                FeatureGate::Supported
            );
        }
    }

    // --- YubiKey ATTEST: gained in firmware 4.3 -----------------------------
    // See <https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html>.

    #[test]
    fn yubikey_attest_below_4_3_is_unsupported() {
        // Matches the known-unsupported sentinel verdict (version `[]`), which is not
        // the last verdict, so the known-unsupported verdict is authoritative — same shape as
        // `yubikey_below_5_7_is_unsupported` for MOVE KEY/DELETE KEY.
        assert_eq!(
            resolve(
                PivExtension::Attest,
                AppletFingerprint::YubiKey,
                Some(&[4, 2]),
                None
            ),
            FeatureGate::Unsupported
        );
        assert_eq!(
            resolve(
                PivExtension::Attest,
                AppletFingerprint::YubiKey,
                Some(&[3, 4, 0]),
                None,
            ),
            FeatureGate::Unsupported
        );
        // GET METADATA is a separate table with its own `[]` sentinel below
        // its own 5.3 bar — 4.2 is below that bar too, and bracketed by the
        // same sentinel logic, so it resolves the same way here.
        assert_eq!(
            resolve(
                PivExtension::GetMetadata,
                AppletFingerprint::YubiKey,
                Some(&[4, 2]),
                None,
            ),
            FeatureGate::Unsupported
        );
    }

    #[test]
    fn yubikey_attest_4_3_and_newer_is_supported() {
        assert_eq!(
            resolve(
                PivExtension::Attest,
                AppletFingerprint::YubiKey,
                Some(&[4, 3]),
                None
            ),
            FeatureGate::Supported
        );
        assert_eq!(
            resolve(
                PivExtension::Attest,
                AppletFingerprint::YubiKey,
                Some(&[4, 3, 7]),
                None,
            ),
            FeatureGate::Supported
        );
        // A later version with no verdict of its own falls to the `[4, 3]`
        // known-supported verdict, assumed not to have regressed.
        assert_eq!(
            resolve(
                PivExtension::Attest,
                AppletFingerprint::YubiKey,
                Some(&[5, 7]),
                None,
            ),
            FeatureGate::Supported
        );
    }

    // --- YubiKey GET METADATA: gained in firmware 5.3 -----------------------
    // See <https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html>.

    #[test]
    fn yubikey_get_metadata_below_5_3_is_unsupported() {
        assert_eq!(
            resolve(
                PivExtension::GetMetadata,
                AppletFingerprint::YubiKey,
                Some(&[5, 2, 0]),
                None,
            ),
            FeatureGate::Unsupported
        );
        assert_eq!(
            resolve(
                PivExtension::GetMetadata,
                AppletFingerprint::YubiKey,
                Some(&[4, 3, 7]),
                None,
            ),
            FeatureGate::Unsupported
        );
        // ATTEST is a separate, unaffected table — 4.3.7 is already at/above
        // its own 4.3 bar.
        assert_eq!(
            resolve(
                PivExtension::Attest,
                AppletFingerprint::YubiKey,
                Some(&[4, 3, 7]),
                None,
            ),
            FeatureGate::Supported
        );
    }

    #[test]
    fn yubikey_get_metadata_5_3_and_newer_is_supported() {
        assert_eq!(
            resolve(
                PivExtension::GetMetadata,
                AppletFingerprint::YubiKey,
                Some(&[5, 3]),
                None,
            ),
            FeatureGate::Supported
        );
        assert_eq!(
            resolve(
                PivExtension::GetMetadata,
                AppletFingerprint::YubiKey,
                Some(&[5, 7]),
                None,
            ),
            FeatureGate::Supported
        );
    }

    #[test]
    fn yubikey_attest_and_get_metadata_without_any_reported_version_match_the_universal_verdict() {
        // Neither axis reported a version, so `resolve` substitutes the
        // universal `[]` sentinel on both. Both rows are pinned
        // `KnownUnsupported` exactly at `[]` (with a later known-supported
        // verdict on record), so that sentinel match resolves `Unsupported`,
        // the same as any other exact-match version.
        for ext in [PivExtension::Attest, PivExtension::GetMetadata] {
            assert_eq!(
                resolve(ext, AppletFingerprint::YubiKey, None, None),
                FeatureGate::Unsupported
            );
        }
    }

    // --- GetSlotKeyStatus: falls through to GetMetadata absent its own row ---

    #[test]
    fn get_slot_key_status_without_its_own_row_mirrors_get_metadata_exactly() {
        // No GetSlotKeyStatus row in `YUBIKEY_APPLET_VERDICTS` (across its
        // 5.3 boundary — the version that matters for that table's own
        // YubiKey GetMetadata row), Token2 (which does carry its own
        // GetMetadata row now — see `TOKEN2_APPLET_VERDICTS`'s doc — but still
        // no GetSlotKeyStatus row of its own, which is what the fallthrough
        // actually keys on), or an unrecognized fingerprint — every one of
        // these must resolve identically to `resolve(GetMetadata, ...)`.
        let cases: &[(AppletFingerprint, Option<&[u8]>)] = &[
            (AppletFingerprint::YubiKey, None),
            (AppletFingerprint::YubiKey, Some(&[5, 2])),
            (AppletFingerprint::YubiKey, Some(&[5, 3])),
            (AppletFingerprint::YubiKey, Some(&[6, 0])),
            (AppletFingerprint::Token2, Some(&[5, 112, 0])),
            (AppletFingerprint::Generic, None),
            (AppletFingerprint::Generic, Some(&[1, 0])),
        ];
        for &(fp, version) in cases {
            assert_eq!(
                resolve(PivExtension::GetSlotKeyStatus, fp, version, version),
                resolve(PivExtension::GetMetadata, fp, version, version),
                "{fp:?} at {version:?}"
            );
        }
    }

    #[test]
    fn hid_crescendo_get_slot_key_status_is_known_supported_regardless_of_version() {
        // Unlike every fingerprint in the fallback test above, HID Crescendo
        // has its own row here — `Verdict::KnownSupported` at the universal
        // `[]` version — resolved directly, never falling through to
        // `GetMetadata` (which is `KnownUnsupportedSince` for these same
        // three fingerprints; see `HID_CRESCENDO_C2300_APPLET_VERDICTS`'s doc). The two
        // extensions must therefore resolve *differently* here, the opposite
        // of the fallback test above.
        for variant in [
            HidCrescendoVariant::C2300,
            HidCrescendoVariant::C4000,
            HidCrescendoVariant::Generic,
        ] {
            let fp = AppletFingerprint::HidCrescendo(variant);
            for version in [&[0][..], &[3, 0, 3, 6][..], &[99][..]] {
                assert_eq!(
                    resolve(
                        PivExtension::GetSlotKeyStatus,
                        fp,
                        Some(version),
                        Some(version)
                    ),
                    FeatureGate::Supported,
                    "{variant:?} at {version:?}"
                );
            }
            // Neither axis reported at all: `resolve` substitutes the
            // universal `[]` sentinel on both, so this still matches the
            // same `KnownSupported` row as every version above.
            assert_eq!(
                resolve(PivExtension::GetSlotKeyStatus, fp, None, None),
                FeatureGate::Supported,
                "{variant:?} with no reported version"
            );
        }
        // And explicitly not delegating to `GetMetadata`: C2300/C4000 have
        // their own `KnownUnsupportedSince` row there (see
        // `HID_CRESCENDO_C2300_APPLET_VERDICTS`'s doc), while `Generic` has no GetMetadata row at
        // all (deliberately not extended the way that table's Reset rows
        // are — see that table's own doc) and so resolves `Unverified`
        // — neither matches `GetSlotKeyStatus`'s `Supported` for any of the
        // three, but for two different reasons.
        for (variant, get_metadata_verdict) in [
            (HidCrescendoVariant::C2300, FeatureGate::Unsupported),
            (HidCrescendoVariant::C4000, FeatureGate::Unsupported),
            (HidCrescendoVariant::Generic, FeatureGate::Unverified),
        ] {
            assert_eq!(
                resolve(
                    PivExtension::GetMetadata,
                    AppletFingerprint::HidCrescendo(variant),
                    Some(&[3, 0, 3, 6]),
                    Some(&[3, 0, 3, 6]),
                ),
                get_metadata_verdict,
                "{variant:?}"
            );
        }
    }

    // --- PinManagementAuth: HID Crescendo direct, YubiKey indirect -------

    #[test]
    fn hid_crescendo_pin_management_auth_supported_at_any_version() {
        // The universal `[]` sentinel: HID Crescendo's PIN-unlock is direct
        // (no quirk needed), same shape as `KnownUnsupportedSince` at `[]` on
        // the other tables, just the opposite verdict.
        for variant in [HidCrescendoVariant::C2300, HidCrescendoVariant::C4000] {
            let fp = AppletFingerprint::HidCrescendo(variant);
            for version in [&[0][..], &[1, 2, 3][..], &[9, 9, 9][..]] {
                assert_eq!(
                    resolve(PivExtension::PinManagementAuth, fp, Some(version), None),
                    FeatureGate::Supported
                );
            }
            // Neither axis reported at all: `resolve` substitutes the
            // universal `[]` sentinel on both, so this still matches the
            // same `KnownSupported` row as every version above.
            assert_eq!(
                resolve(PivExtension::PinManagementAuth, fp, None, None),
                FeatureGate::Supported
            );
        }
    }

    #[test]
    fn yubikey_pin_management_auth_below_3_is_unverified() {
        // No known-unsupported sentinel on this row (unlike MOVE KEY/DELETE
        // KEY's YubiKey row): a version below the first known-supported verdict
        // just has nothing to extend backward from.
        assert_eq!(
            resolve(
                PivExtension::PinManagementAuth,
                AppletFingerprint::YubiKey,
                Some(&[2, 9, 9]),
                None,
            ),
            FeatureGate::Unverified
        );
    }

    #[test]
    fn yubikey_pin_management_auth_3_and_newer_is_supported() {
        // Unlike HID Crescendo's direct unlock, a caller still has to read
        // the retrieved "management key" back and run it through the
        // standard 9B round (see `PivExtension::PinManagementAuth`'s own
        // doc) — but that's `PivSession::authenticate_management_via_pin`'s
        // job at the transport layer, not something this gate distinguishes
        // on its own.
        for version in [&[3][..], &[3, 1, 0][..], &[5, 7][..]] {
            assert_eq!(
                resolve(
                    PivExtension::PinManagementAuth,
                    AppletFingerprint::YubiKey,
                    Some(version),
                    None,
                ),
                FeatureGate::Supported
            );
        }
    }

    // --- PIV RESET: YubiKey supported at any version, HID Crescendo never --

    #[test]
    fn yubikey_reset_supported_at_any_version_with_no_management_auth_quirk() {
        // The universal `[]` sentinel: no known-unsupported floor to clear, unlike
        // MOVE KEY/DELETE KEY's YubiKey row — RESET didn't arrive in a
        // specific later firmware.
        for version in [&[0][..], &[1, 0][..], &[9, 9, 9][..]] {
            assert_eq!(
                resolve(
                    PivExtension::Reset,
                    AppletFingerprint::YubiKey,
                    Some(version),
                    None
                ),
                FeatureGate::Supported
            );
            // `Supported` here means the card accepts `INS 0xFB` at all —
            // *without* `ResetNeedsManagementAuth`, which per that quirk's
            // doc is exactly how a caller reads off the PIN/PUK-blocked
            // convention instead.
            assert!(
                !resolve_quirks(AppletFingerprint::YubiKey, Some(version), None)
                    .contains(&PivQuirk::ResetNeedsManagementAuth)
            );
        }
        // Neither axis reported at all: `resolve` substitutes the universal
        // `[]` sentinel on both, so this still matches the same
        // `KnownSupported` row as every version above.
        assert_eq!(
            resolve(PivExtension::Reset, AppletFingerprint::YubiKey, None, None),
            FeatureGate::Supported
        );
    }

    // --- Slot PIN/touch policy: SlotPinPolicy/SlotTouchPolicy ------------

    #[test]
    fn yubikey_slot_pin_and_touch_policy_supported_from_v4_touch_cached_quirk_until_4_3() {
        for version in [&[4][..], &[4, 1][..], &[5, 7][..]] {
            for ext in [PivExtension::SlotPinPolicy, PivExtension::SlotTouchPolicy] {
                assert_eq!(
                    resolve(ext, AppletFingerprint::YubiKey, Some(version), None),
                    FeatureGate::Supported
                );
            }
        }
        // Below v4, neither row has anything to extend backward from (both
        // are `KnownSupported`, which says nothing about earlier versions).
        for ext in [PivExtension::SlotPinPolicy, PivExtension::SlotTouchPolicy] {
            assert_eq!(
                resolve(ext, AppletFingerprint::YubiKey, Some(&[3, 4]), None),
                FeatureGate::Unverified
            );
        }
        // The touch policy `Cached` value specifically isn't accepted until
        // 4.3 — the quirk marks that even though the extension as a whole is
        // already `Supported` at v4. It's carried on the `[3]` entry rather
        // than living on its own `[4]` entry — see `YUBIKEY_APPLET_QUIRKS`'s
        // doc — but is inert below v4 since `SlotTouchPolicy` itself isn't
        // `Supported` there yet — a caller checks the extension gate first.
        assert!(resolve_quirks(AppletFingerprint::YubiKey, Some(&[3]), None)
            .contains(&PivQuirk::SlotTouchPolicyCachedNotSupported));
        assert!(resolve_quirks(AppletFingerprint::YubiKey, Some(&[4]), None)
            .contains(&PivQuirk::SlotTouchPolicyCachedNotSupported));
        assert!(
            resolve_quirks(AppletFingerprint::YubiKey, Some(&[4, 1]), None)
                .contains(&PivQuirk::SlotTouchPolicyCachedNotSupported)
        );
        assert!(
            !resolve_quirks(AppletFingerprint::YubiKey, Some(&[4, 3]), None)
                .contains(&PivQuirk::SlotTouchPolicyCachedNotSupported)
        );
        assert!(
            !resolve_quirks(AppletFingerprint::YubiKey, Some(&[5, 7]), None)
                .contains(&PivQuirk::SlotTouchPolicyCachedNotSupported)
        );
        assert!(
            !resolve_quirks(AppletFingerprint::YubiKey, Some(&[2, 9, 9]), None)
                .contains(&PivQuirk::SlotTouchPolicyCachedNotSupported)
        );
        // The PIN policy `Once` value has no such quirk on YubiKey at any
        // observed version.
        assert!(
            !resolve_quirks(AppletFingerprint::YubiKey, Some(&[4]), None)
                .contains(&PivQuirk::SlotPinPolicyOnceNotSupported)
        );
    }

    #[test]
    fn arekinath_slot_pin_policy_supported_from_v4_touch_policy_unsupported_through_5_4_0() {
        for fp in [
            AppletFingerprint::ArekinathPivApplet(ArekinathVariant::Generic),
            AppletFingerprint::ArekinathPivApplet(ArekinathVariant::SwissbitIShield1),
        ] {
            for version in [&[4][..], &[4, 5][..], &[5, 4, 0][..]] {
                assert_eq!(
                    resolve(PivExtension::SlotPinPolicy, fp, Some(version), None),
                    FeatureGate::Supported
                );
            }
            for version in [&[4][..], &[4, 5][..], &[5, 4, 0][..]] {
                assert_eq!(
                    resolve(PivExtension::SlotTouchPolicy, fp, Some(version), None),
                    FeatureGate::Unsupported
                );
            }
            // Past the confirmed 5.4.0 ceiling, touch policy softens to
            // unverified rather than staying blocked — a later applet
            // release may have added it.
            assert_eq!(
                resolve(PivExtension::SlotTouchPolicy, fp, Some(&[5, 5, 0]), None),
                FeatureGate::Unverified
            );
        }
    }

    #[test]
    fn hid_crescendo_slot_pin_and_touch_policy_unsupported_at_any_version_including_generic() {
        for variant in [
            HidCrescendoVariant::C2300,
            HidCrescendoVariant::C4000,
            HidCrescendoVariant::Generic,
        ] {
            let fp = AppletFingerprint::HidCrescendo(variant);
            for ext in [PivExtension::SlotPinPolicy, PivExtension::SlotTouchPolicy] {
                for version in [&[0][..], &[3, 0, 3, 6][..], &[9, 9, 9, 9][..]] {
                    assert_eq!(
                        resolve(ext, fp, Some(version), None),
                        FeatureGate::Unsupported
                    );
                }
            }
        }
    }

    #[test]
    fn trussed_nitrokey_slot_pin_and_touch_policy_unsupported_at_1_8_3_firmware() {
        for ext in [PivExtension::SlotPinPolicy, PivExtension::SlotTouchPolicy] {
            assert_eq!(
                resolve(
                    ext,
                    AppletFingerprint::Trussed(TrussedVariant::NitroKey),
                    None,
                    Some(&[1, 8, 3]),
                ),
                FeatureGate::Unsupported
            );
            // Backward-extends to earlier, untested firmware too.
            assert_eq!(
                resolve(
                    ext,
                    AppletFingerprint::Trussed(TrussedVariant::NitroKey),
                    None,
                    Some(&[1, 8]),
                ),
                FeatureGate::Unsupported
            );
        }
    }

    #[test]
    fn feitian_slot_pin_and_touch_policy_unsupported_at_v0() {
        // `PivExtension::PinManagementAuth` joins the same row/verdict — see
        // `FEITIAN_APPLET_VERDICTS`'s doc.
        for ext in [
            PivExtension::SlotPinPolicy,
            PivExtension::SlotTouchPolicy,
            PivExtension::PinManagementAuth,
        ] {
            assert_eq!(
                resolve(ext, AppletFingerprint::Feitian, Some(&[0]), None),
                FeatureGate::Unsupported,
                "{ext:?}"
            );
        }
    }

    #[test]
    fn swissbit_ishield2_slot_pin_and_touch_policy_unsupported_at_1_4_1_0() {
        let fp = AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2);
        for ext in [PivExtension::SlotPinPolicy, PivExtension::SlotTouchPolicy] {
            assert_eq!(
                resolve(ext, fp, Some(&[1, 4, 1, 0]), None),
                FeatureGate::Unsupported
            );
        }
    }

    #[test]
    fn openfips201_generic_slot_pin_and_touch_policy_unsupported_since() {
        let fp = AppletFingerprint::OpenFips201(OpenFips201Variant::Generic);
        for ext in [PivExtension::SlotPinPolicy, PivExtension::SlotTouchPolicy] {
            for version in [&[0][..], &[9, 9, 9][..]] {
                assert_eq!(
                    resolve(ext, fp, Some(version), None),
                    FeatureGate::Unsupported
                );
            }
        }
    }

    #[test]
    fn hid_crescendo_reset_unsupported_at_any_version_including_generic() {
        // Same `KnownUnsupportedSince` shape as `HID_CRESCENDO_C2300_APPLET_VERDICTS`'s
        // GetMetadata/Attest HID Crescendo rows, but — unlike those two —
        // also covers `Generic`; see that table's Reset bullets for why.
        for variant in [
            HidCrescendoVariant::C2300,
            HidCrescendoVariant::C4000,
            HidCrescendoVariant::Generic,
        ] {
            let fp = AppletFingerprint::HidCrescendo(variant);
            for version in [&[0][..], &[3, 0, 3, 6][..], &[9, 9, 9, 9][..]] {
                assert_eq!(
                    resolve(PivExtension::Reset, fp, Some(version), None),
                    FeatureGate::Unsupported
                );
            }
            // The not-yet-implemented replacement mechanism's quirk is
            // already in place, ready for the workaround to key off of.
            assert!(
                resolve_quirks(fp, Some(&[0]), None).contains(&PivQuirk::ResetNeedsManagementAuth)
            );
        }
    }

    #[test]
    fn reset_data_does_not_leak_to_other_fingerprints() {
        assert_eq!(
            resolve(PivExtension::Reset, AppletFingerprint::Generic, None, None),
            FeatureGate::Unverified
        );
        // Feitian carries a `ResetGlobal` row and several others (see
        // `FEITIAN_APPLET_VERDICTS`'s doc) but no `PivExtension::Reset` row at
        // all — proving a fingerprint with genuine data on one extension
        // carries none of it over to a sibling extension it hasn't recorded.
        // (Neither Thetis nor Token2 demonstrate this themselves any more:
        // both now have their own genuine `KnownSupported` Reset rows at
        // 5.112.0 — see
        // `thetis_5_112_0_reset_and_set_pin_puk_retries_are_supported` and
        // `token2_5_112_0_reset_is_supported` instead.)
        assert_eq!(
            resolve(
                PivExtension::Reset,
                AppletFingerprint::Feitian,
                Some(&[0]),
                None,
            ),
            FeatureGate::Unverified
        );
        assert!(
            !resolve_quirks(AppletFingerprint::Feitian, Some(&[0]), None)
                .contains(&PivQuirk::ResetNeedsManagementAuth)
        );
    }

    #[test]
    fn thetis_5_112_0_reset_and_set_pin_puk_retries_are_supported() {
        // Hardware-observed known-supported verdicts, pinned to exactly the
        // version keyroost has evidence for — see the Reset and
        // SetPinPukRetries bullets in `THETIS_APPLET_VERDICTS`'s doc. As with
        // the Token2 rows, a version above 5.112.0 still resolves `Supported`
        // only via `KnownSupported`'s ordinary forward no-regression
        // assumption, not because either row itself covers every version.
        for ext in [PivExtension::Reset, PivExtension::SetPinPukRetries] {
            for version in [&[5, 112, 0][..], &[5, 113, 0][..], &[9, 9, 9][..]] {
                assert_eq!(
                    resolve(ext, AppletFingerprint::Thetis, Some(version), None),
                    FeatureGate::Supported,
                    "{ext:?} at {version:?}"
                );
            }
            // No known-unsupported floor recorded below 5.112.0 (unlike
            // `THETIS_APPLET_VERDICTS`'s MoveKey/DeleteKey rows, which are
            // `KnownUnsupported` at this same version and so extend
            // backward): an older reported version falls off either row
            // entirely and resolves `Unverified`, not `Supported` or
            // `Unsupported`.
            for version in [&[5, 111, 0][..], &[0][..]] {
                assert_eq!(
                    resolve(ext, AppletFingerprint::Thetis, Some(version), None),
                    FeatureGate::Unverified,
                    "{ext:?} at {version:?}"
                );
            }
            assert_eq!(
                resolve(ext, AppletFingerprint::Thetis, None, None),
                FeatureGate::Unverified
            );
        }
        // No `ResetNeedsManagementAuth` entry on `THETIS_APPLET_QUIRKS` —
        // RESET doesn't need an authenticated management-key session here,
        // same as YubiKey and Token2.
        assert!(
            !resolve_quirks(AppletFingerprint::Thetis, Some(&[5, 112, 0]), None)
                .contains(&PivQuirk::ResetNeedsManagementAuth)
        );
    }

    #[test]
    fn token2_5_112_0_reset_is_supported() {
        // Hardware-observed known-supported verdict, pinned to exactly the
        // version keyroost has evidence for — see the Token2 bullet in
        // `TOKEN2_APPLET_VERDICTS`'s doc. As with the YubiKey row, a version above
        // 5.112.0 still resolves `Supported` only via `KnownSupported`'s
        // ordinary forward no-regression assumption, not because the row
        // itself covers every version.
        for version in [&[5, 112, 0][..], &[5, 113, 0][..], &[9, 9, 9][..]] {
            assert_eq!(
                resolve(
                    PivExtension::Reset,
                    AppletFingerprint::Token2,
                    Some(version),
                    None
                ),
                FeatureGate::Supported,
                "{version:?}"
            );
        }
        // No known-unsupported floor recorded below 5.112.0 (unlike
        // `TOKEN2_APPLET_VERDICTS`'s MoveKey/DeleteKey rows, which
        // are `KnownUnsupported` at this same version and so extend
        // backward): an older reported version falls off this row entirely
        // and resolves `Unverified`, not `Supported` or `Unsupported`.
        for version in [&[5, 111, 0][..], &[0][..]] {
            assert_eq!(
                resolve(
                    PivExtension::Reset,
                    AppletFingerprint::Token2,
                    Some(version),
                    None
                ),
                FeatureGate::Unverified,
                "{version:?}"
            );
        }
        assert_eq!(
            resolve(PivExtension::Reset, AppletFingerprint::Token2, None, None),
            FeatureGate::Unverified
        );
        // No `ResetNeedsManagementAuth` entry on
        // `TOKEN2_APPLET_QUIRKS` — RESET doesn't need an authenticated
        // management-key session here. Unlike YubiKey, that absence doesn't
        // mean it falls back to the PIN/PUK-burn convention either: hardware
        // testing showed a live 5.112.0 unit accepts RESET unconditionally.
        // See `PivQuirk::ResetNeedsManagementAuth`'s own doc.
        assert!(
            !resolve_quirks(AppletFingerprint::Token2, Some(&[5, 112, 0]), None)
                .contains(&PivQuirk::ResetNeedsManagementAuth)
        );
    }

    // --- PIV RESET_GLOBAL: HID Crescendo C2300/C4000 only, not Generic ---

    #[test]
    fn hid_crescendo_c2300_c4000_reset_global_supported_at_any_version() {
        for variant in [HidCrescendoVariant::C2300, HidCrescendoVariant::C4000] {
            let fp = AppletFingerprint::HidCrescendo(variant);
            for version in [&[0][..], &[3, 0, 3, 6][..], &[9, 9, 9, 9][..]] {
                assert_eq!(
                    resolve(PivExtension::ResetGlobal, fp, Some(version), None),
                    FeatureGate::Supported
                );
            }
            // Neither axis reported at all: `resolve` substitutes the
            // universal `[]` sentinel on both, so this still matches the
            // same `KnownSupported` row as every version above.
            assert_eq!(
                resolve(PivExtension::ResetGlobal, fp, None, None),
                FeatureGate::Supported
            );
        }
    }

    #[test]
    fn hid_crescendo_generic_has_no_reset_global_data() {
        // Unlike `PivExtension::Reset`'s known-unsupported row, `ResetGlobal`'s
        // known-supported claim deliberately isn't extended to `Generic` — see
        // `GENERIC_APPLET_VERDICTS`'s doc for why.
        assert_eq!(
            resolve(
                PivExtension::ResetGlobal,
                AppletFingerprint::HidCrescendo(HidCrescendoVariant::Generic),
                Some(&[3, 0, 3, 6]),
                None,
            ),
            FeatureGate::Unverified
        );
    }

    /// Every fingerprint that isn't `HidCrescendo` carries its own explicit
    /// `Verdict::KnownUnsupportedSince` row (see `RESET_GLOBAL_VERDICTS`'s
    /// doc for why an explicit "no" beats leaving these absent) -- a flat
    /// `Unsupported` at any reported version, not the `Unverified` an absent
    /// row would give -- including when *no* version is reported on either
    /// axis at all, since `resolve` substitutes the universal `[]` sentinel
    /// for both in that case, and this row is pinned exactly there. Covers
    /// every `AppletFingerprint` variant currently defined outside
    /// `HidCrescendo`, one representative version each plus a second to
    /// prove it's not just the exact-match version that resolves this way.
    #[test]
    fn reset_global_is_known_unsupported_for_every_non_hid_crescendo_fingerprint() {
        let non_hid_crescendo = [
            AppletFingerprint::Generic,
            AppletFingerprint::ArekinathPivApplet(ArekinathVariant::Generic),
            AppletFingerprint::ArekinathPivApplet(ArekinathVariant::SwissbitIShield1),
            AppletFingerprint::AuthentrendATKey,
            AppletFingerprint::Feitian,
            AppletFingerprint::IdPrime,
            AppletFingerprint::Trussed(TrussedVariant::NitroKey),
            AppletFingerprint::OpenFips201(OpenFips201Variant::Generic),
            AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2),
            AppletFingerprint::Thetis,
            AppletFingerprint::Token2,
            AppletFingerprint::UTrust(UTrustVariant::Generic),
            AppletFingerprint::UTrust(UTrustVariant::Gov),
            AppletFingerprint::YubiKey,
        ];
        for fp in non_hid_crescendo {
            for version in [&[0][..], &[9, 9, 9][..]] {
                assert_eq!(
                    resolve(PivExtension::ResetGlobal, fp, Some(version), None),
                    FeatureGate::Unsupported,
                    "{fp:?} at {version:?}"
                );
            }
            // No reported version at all on either axis: `resolve`
            // substitutes the universal `[]` sentinel for both, so this
            // still matches each fingerprint's `KnownUnsupportedSince` row.
            assert_eq!(
                resolve(PivExtension::ResetGlobal, fp, None, None),
                FeatureGate::Unsupported,
                "{fp:?} with no reported version"
            );
        }
    }

    #[test]
    fn trussed_nitrokey_reset_global_row_is_duplicated_on_both_axes() {
        // Unlike every other fingerprint in the loop above,
        // `Trussed(NitroKey)` carries this same `KnownUnsupportedSince` row
        // on *both* `TRUSSED_NITROKEY_APPLET_VERDICTS` and
        // `TRUSSED_NITROKEY_FIRMWARE_VERDICTS` — see either const's own doc
        // for why. Reporting a version on only one axis at a time still
        // resolves `Unsupported`, proving each axis' row stands on its own
        // rather than one silently depending on the other.
        let fp = AppletFingerprint::Trussed(TrussedVariant::NitroKey);
        for version in [&[0][..], &[9, 9, 9][..]] {
            assert_eq!(
                resolve(PivExtension::ResetGlobal, fp, Some(version), None),
                FeatureGate::Unsupported,
                "{version:?} reported on the applet axis alone"
            );
            assert_eq!(
                resolve(PivExtension::ResetGlobal, fp, None, Some(version)),
                FeatureGate::Unsupported,
                "{version:?} reported on the firmware axis alone"
            );
        }
    }

    // --- PIV SET_PIN_PUK_RETRIES: YubiKey always, Token2 at 5.112.0, HID
    // --- Crescendo never ---------------------------------------------------

    #[test]
    fn yubikey_set_pin_puk_retries_always_supported() {
        // No known-unsupported floor, same shape as `RESET_VERDICTS`'s YubiKey
        // row — SET PIN RETRIES didn't arrive in a specific later firmware,
        // unlike MOVE KEY/DELETE KEY's YubiKey row.
        for version in [&[0][..], &[1, 0][..], &[9, 9, 9][..]] {
            assert_eq!(
                resolve(
                    PivExtension::SetPinPukRetries,
                    AppletFingerprint::YubiKey,
                    Some(version),
                    None
                ),
                FeatureGate::Supported
            );
        }
        // Neither axis reported at all: `resolve` substitutes the universal
        // `[]` sentinel on both, so this still matches the same
        // `KnownSupported` row as every version above.
        assert_eq!(
            resolve(
                PivExtension::SetPinPukRetries,
                AppletFingerprint::YubiKey,
                None,
                None
            ),
            FeatureGate::Supported
        );
    }

    #[test]
    fn token2_5_112_0_set_pin_puk_retries_is_supported() {
        // Hardware-observed known-supported verdict, pinned to exactly the
        // version keyroost has evidence for — see the Token2 bullet in
        // `SET_PIN_PUK_RETRIES_VERDICTS`'s doc. Unlike the YubiKey row above,
        // there's no universal `[]` verdict here, so a version above 5.112.0
        // still resolves `Supported` only via `KnownSupported`'s ordinary
        // forward no-regression assumption, not because the row itself
        // covers every version.
        for version in [&[5, 112, 0][..], &[5, 113, 0][..], &[9, 9, 9][..]] {
            assert_eq!(
                resolve(
                    PivExtension::SetPinPukRetries,
                    AppletFingerprint::Token2,
                    Some(version),
                    None
                ),
                FeatureGate::Supported,
                "{version:?}"
            );
        }
        // No known-unsupported floor recorded below 5.112.0 (unlike
        // `MOVE_KEY_VERDICTS`'s/`DELETE_KEY_VERDICTS`'s Token2 rows, which
        // are `KnownUnsupported` at this same version and so extend
        // backward): an older reported version falls off this row entirely
        // and resolves `Unverified`, not `Supported` or `Unsupported`.
        for version in [&[5, 111, 0][..], &[0][..]] {
            assert_eq!(
                resolve(
                    PivExtension::SetPinPukRetries,
                    AppletFingerprint::Token2,
                    Some(version),
                    None
                ),
                FeatureGate::Unverified,
                "{version:?}"
            );
        }
        assert_eq!(
            resolve(
                PivExtension::SetPinPukRetries,
                AppletFingerprint::Token2,
                None,
                None
            ),
            FeatureGate::Unverified
        );
    }

    #[test]
    fn hid_crescendo_set_pin_puk_retries_unsupported_at_any_version_including_generic() {
        // Same `KnownUnsupportedSince` shape as `RESET_VERDICTS`'s HID
        // Crescendo rows, and likewise covers `Generic` alongside the two
        // named models — see `SET_PIN_PUK_RETRIES_VERDICTS`'s doc. C4000 in
        // particular is blocked for lack of a documented APDU, not lack of
        // any HID mechanism — see that row's comment.
        for variant in [
            HidCrescendoVariant::C2300,
            HidCrescendoVariant::C4000,
            HidCrescendoVariant::Generic,
        ] {
            let fp = AppletFingerprint::HidCrescendo(variant);
            for version in [&[0][..], &[3, 0, 3, 6][..], &[9, 9, 9, 9][..]] {
                assert_eq!(
                    resolve(PivExtension::SetPinPukRetries, fp, Some(version), None),
                    FeatureGate::Unsupported,
                    "{fp:?} at {version:?}"
                );
            }
            // Neither axis reported at all: `resolve` substitutes the
            // universal `[]` sentinel on both, so this still matches each
            // variant's `KnownUnsupportedSince` row.
            assert_eq!(
                resolve(PivExtension::SetPinPukRetries, fp, None, None),
                FeatureGate::Unsupported,
                "{fp:?} with no reported version"
            );
        }
    }

    #[test]
    fn set_pin_puk_retries_data_does_not_leak_to_other_fingerprints() {
        assert_eq!(
            resolve(
                PivExtension::SetPinPukRetries,
                AppletFingerprint::Generic,
                None,
                None
            ),
            FeatureGate::Unverified
        );
        // AuthentrendATKey has a `ResetGlobal` row in
        // `AUTHENTREND_ATKEY_APPLET_VERDICTS`, and now a genuine
        // `KnownSupported` SetPinPukRetries row of its own too — but that
        // row is floored at `[6]` (the whole v6 lineup is assumed to share
        // support hardware-observed on one v6.0.1 unit, not just that exact
        // build), and says nothing about versions before it. Querying at
        // `[0]`, well below that floor, still falls off the row entirely
        // and resolves `Unverified` — proving the `ResetGlobal` row's own
        // `KnownUnsupportedSince` verdict (which *would* apply at `[0]`)
        // doesn't leak across to this extension. See
        // `authentrend_atkey_yubico_extension_set_is_known_supported_at_v6`
        // for the floor-and-above case.
        // (Neither Thetis nor Token2 demonstrate this themselves any more:
        // both now have their own genuine `KnownSupported` row here at the
        // same version — see
        // `thetis_5_112_0_reset_and_set_pin_puk_retries_are_supported` and
        // `token2_5_112_0_set_pin_puk_retries_is_supported` instead. Feitian
        // doesn't demonstrate this either any more: it now has its own
        // genuine `KnownUnsupported` SetPinPukRetries row — see
        // `feitian_yubico_extensions_are_known_unsupported_at_v0` instead.)
        assert_eq!(
            resolve(
                PivExtension::SetPinPukRetries,
                AppletFingerprint::AuthentrendATKey,
                Some(&[0]),
                None,
            ),
            FeatureGate::Unverified
        );
    }

    // --- UTrust: DeleteKey/MoveKey/SetPinPukRetries/Reset/GetMetadata/ -----
    // --- SetManagementKey are KnownUnsupported on both variants, one -------
    // --- observed, one guessed ----------------------------------------------

    #[test]
    fn utrust_generic_and_gov_yubico_extensions_are_known_unsupported() {
        // Hardware-observed on Generic (see `UTRUST_GENERIC_APPLET_VERDICTS`'s
        // doc) and guessed on Gov, pending an actual Gov-unit probe (see
        // `UTRUST_GOV_APPLET_VERDICTS`'s doc) — but both variants carry the
        // same six `Verdict::KnownUnsupported` rows at the universal
        // `version: &[]` sentinel, so they resolve identically here.
        for fp in [
            AppletFingerprint::UTrust(UTrustVariant::Generic),
            AppletFingerprint::UTrust(UTrustVariant::Gov),
        ] {
            for ext in [
                PivExtension::DeleteKey,
                PivExtension::MoveKey,
                PivExtension::SetPinPukRetries,
                PivExtension::Reset,
                PivExtension::GetMetadata,
                PivExtension::SetManagementKey,
            ] {
                // Neither axis reported at all: `resolve` substitutes the
                // universal `[]` sentinel on both, exactly matching each row.
                assert_eq!(
                    resolve(ext, fp, None, None),
                    FeatureGate::Unsupported,
                    "{fp:?} {ext:?} with no reported version"
                );
                // A genuinely reported version falls off the row entirely —
                // `KnownUnsupported` at `[]`, unlike `KnownUnsupportedSince`,
                // doesn't extend forward past its own last (and only) entry
                // — so it softens to `Unverified` rather than staying
                // `Unsupported`.
                assert_eq!(
                    resolve(ext, fp, Some(&[5, 7, 4]), Some(&[5, 7, 4])),
                    FeatureGate::Unverified,
                    "{fp:?} {ext:?} at a reported version"
                );
            }
        }
    }

    // --- Feitian: SetManagementKey/SetPinPukRetries/MoveKey/DeleteKey/ -----
    // --- GetMetadata are hardware-observed KnownUnsupported at v[0] --------

    #[test]
    fn feitian_yubico_extensions_are_known_unsupported_at_v0() {
        // Hardware-observed on a live unit at applet version `[0]` — see
        // `FEITIAN_APPLET_VERDICTS`'s doc.
        for ext in [
            PivExtension::SetManagementKey,
            PivExtension::SetPinPukRetries,
            PivExtension::MoveKey,
            PivExtension::DeleteKey,
            PivExtension::GetMetadata,
        ] {
            // Neither axis reported at all: `resolve` substitutes the
            // universal `[]` sentinel on both, which orders *below* the
            // row's only verdict at `[0]` — the reported version is older
            // than every verdict on record, so `resolve` falls back to that
            // (lowest) verdict, and a `KnownUnsupported` fallback is assumed
            // to hold at every earlier, untested version too.
            assert_eq!(
                resolve(ext, AppletFingerprint::Feitian, None, None),
                FeatureGate::Unsupported,
                "{ext:?} with no reported version"
            );
            // An exact version match against the row's only verdict.
            assert_eq!(
                resolve(ext, AppletFingerprint::Feitian, Some(&[0]), None),
                FeatureGate::Unsupported,
                "{ext:?} at v[0]"
            );
            // A version above the row's only (and therefore last/highest)
            // verdict softens to `Unverified` — `KnownUnsupported`, unlike
            // `KnownUnsupportedSince`, doesn't extend forward past itself:
            // a later firmware may simply have added the extension.
            assert_eq!(
                resolve(ext, AppletFingerprint::Feitian, Some(&[1]), None),
                FeatureGate::Unverified,
                "{ext:?} above v[0]"
            );
            assert_eq!(
                resolve(
                    ext,
                    AppletFingerprint::Feitian,
                    Some(&[5, 7, 4]),
                    Some(&[5, 7, 4]),
                ),
                FeatureGate::Unverified,
                "{ext:?} at a reported version well above v[0]"
            );
        }
    }

    #[test]
    fn feitian_algorithm_support_at_v0_covers_rsa1024_rsa2048_eccp256_eccp384_only() {
        // Hardware-observed on the same live v0 unit as
        // `feitian_yubico_extensions_are_known_unsupported_at_v0` — see
        // `FEITIAN_APPLET_VERDICTS`'s doc.
        let fp = AppletFingerprint::Feitian;
        for alg in [
            KeyAlg::Rsa1024,
            KeyAlg::Rsa2048,
            KeyAlg::EccP256,
            KeyAlg::EccP384,
        ] {
            assert_eq!(
                resolve(PivExtension::SlotKeyAlgorithm(alg), fp, Some(&[0]), None),
                FeatureGate::Supported,
                "{alg:?}"
            );
        }
        for alg in [
            KeyAlg::Rsa3072,
            KeyAlg::Rsa4096,
            KeyAlg::EccP521,
            KeyAlg::Ed25519,
            KeyAlg::X25519,
        ] {
            assert_eq!(
                resolve(PivExtension::SlotKeyAlgorithm(alg), fp, Some(&[0]), None),
                FeatureGate::Unsupported,
                "{alg:?}"
            );
        }
    }

    #[test]
    fn utrust_generic_pin_management_auth_is_known_unsupported() {
        // Hardware-observed on the same live Generic unit as
        // `utrust_generic_and_gov_yubico_extensions_are_known_unsupported` —
        // see `UTRUST_GENERIC_APPLET_VERDICTS`'s doc. Unlike that shared test,
        // this row isn't seeded on `UTrustVariant::Gov` yet, so it's checked
        // on `Generic` alone. `PivExtension::SlotPinPolicy`/
        // `PivExtension::SlotTouchPolicy` join the same row/verdict — see
        // `UTRUST_GENERIC_APPLET_VERDICTS`'s doc.
        for ext in [
            PivExtension::PinManagementAuth,
            PivExtension::SlotPinPolicy,
            PivExtension::SlotTouchPolicy,
        ] {
            assert_eq!(
                resolve(
                    ext,
                    AppletFingerprint::UTrust(UTrustVariant::Generic),
                    None,
                    None,
                ),
                FeatureGate::Unsupported,
                "{ext:?}"
            );
        }
    }

    #[test]
    fn utrust_generic_algorithm_support_covers_rsa1024_and_rsa2048_only() {
        // Hardware-observed at the universal `[]` sentinel — this device
        // can't report a version at all — see `UTRUST_GENERIC_APPLET_VERDICTS`'s
        // doc. Unlike Feitian above, ECC is rejected entirely, not just the
        // P-521/Ed25519/X25519 tail.
        let fp = AppletFingerprint::UTrust(UTrustVariant::Generic);
        for alg in [KeyAlg::Rsa1024, KeyAlg::Rsa2048] {
            assert_eq!(
                resolve(PivExtension::SlotKeyAlgorithm(alg), fp, None, None),
                FeatureGate::Supported,
                "{alg:?}"
            );
        }
        for alg in [
            KeyAlg::Rsa3072,
            KeyAlg::Rsa4096,
            KeyAlg::EccP256,
            KeyAlg::EccP384,
            KeyAlg::EccP521,
            KeyAlg::Ed25519,
            KeyAlg::X25519,
        ] {
            assert_eq!(
                resolve(PivExtension::SlotKeyAlgorithm(alg), fp, None, None),
                FeatureGate::Unsupported,
                "{alg:?}"
            );
        }
    }

    // --- IdPrime / OpenFIPS201::Generic: Reset/SetManagementKey/-----------
    // --- SetPinPukRetries/MoveKey/DeleteKey are KnownUnsupportedSince — ----
    // --- neither vendor mimics these Yubico vendor-extension APDUs; each --
    // --- ships its own proprietary commands instead, none implemented in --
    // --- keyroost yet (Reset: not even the widely-mimicked `INS 0xFB`) ----

    #[test]
    fn idprime_and_openfips201_generic_yubico_extensions_are_known_unsupported_since() {
        // See `IDPRIME_APPLET_VERDICTS`'s/`OPENFIPS201_GENERIC_APPLET_VERDICTS`'s
        // own docs. `Verdict::KnownUnsupportedSince` at the universal `[]`
        // version: unlike the Feitian/UTrust rows above (plain
        // `Verdict::KnownUnsupported`), this doesn't soften to `Unverified`
        // for a version newer than anything on the row — every *reported*
        // version matches it, same shape as
        // `hid_crescendo_move_key_is_known_unsupported_since_regardless_of_version`.
        for fp in [
            AppletFingerprint::IdPrime,
            AppletFingerprint::OpenFips201(OpenFips201Variant::Generic),
        ] {
            for ext in [
                PivExtension::Reset,
                PivExtension::SetManagementKey,
                PivExtension::SetPinPukRetries,
                PivExtension::MoveKey,
                PivExtension::DeleteKey,
            ] {
                for version in [&[0][..], &[9, 9, 9][..]] {
                    assert_eq!(
                        resolve(ext, fp, Some(version), None),
                        FeatureGate::Unsupported,
                        "{fp:?} {ext:?} at {version:?}"
                    );
                }
                // Neither axis reported at all: `resolve` substitutes the
                // universal `[]` sentinel on both, matching the same row.
                assert_eq!(
                    resolve(ext, fp, None, None),
                    FeatureGate::Unsupported,
                    "{fp:?} {ext:?} with no reported version"
                );
            }
        }
    }

    // --- IdPrime: SlotPinPolicy/SlotTouchPolicy/PinManagementAuth are --------
    // --- KnownUnsupported at the unbracketed `[]` floor — softens to --------
    // --- Unverified off the exact match --------------------------------------

    #[test]
    fn idprime_slot_pin_touch_policy_known_unsupported_only_at_the_exact_floor() {
        // See `IDPRIME_APPLET_VERDICTS`'s doc for the bracketing distinction
        // this exercises: `Verdict::KnownUnsupported` with nothing above it
        // on the row only blocks a query that resolves to version `[]` — the
        // exact floor, or (per `resolve`'s "both axes unset" substitution)
        // no reported version on either axis at all. An actually-reported,
        // non-`[]` version softens straight to `Unverified` instead.
        for ext in [
            PivExtension::SlotPinPolicy,
            PivExtension::SlotTouchPolicy,
            PivExtension::PinManagementAuth,
        ] {
            assert_eq!(
                resolve(ext, AppletFingerprint::IdPrime, Some(&[]), None),
                FeatureGate::Unsupported,
                "{ext:?} at the exact `[]` floor"
            );
            assert_eq!(
                resolve(ext, AppletFingerprint::IdPrime, Some(&[5, 7]), None),
                FeatureGate::Unverified,
                "{ext:?} at an actually-reported version, unbracketed"
            );
            assert_eq!(
                resolve(ext, AppletFingerprint::IdPrime, None, None),
                FeatureGate::Unsupported,
                "{ext:?} with no reported version on either axis — substitutes `[]`"
            );
        }
    }

    #[test]
    fn idprime_slot_key_algorithm_rsa2048_is_known_supported() {
        // Hardware-observed on the same live unit as the pin/touch-policy
        // row above — see `IDPRIME_APPLET_VERDICTS`'s doc. Seeded at the
        // universal `[]` floor, so `Verdict::KnownSupported`'s forward
        // no-regression assumption makes this resolve `Supported` at `[]`
        // itself and at every later version too, unlike the
        // `KnownUnsupported` row right above it. No other algorithm has been
        // probed on this fingerprint, so it stays `Unverified`.
        let fp = AppletFingerprint::IdPrime;
        for version in [&[][..], &[5, 7][..]] {
            assert_eq!(
                resolve(
                    PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa2048),
                    fp,
                    Some(version),
                    None
                ),
                FeatureGate::Supported,
                "Rsa2048 at {version:?}"
            );
        }
        assert_eq!(
            resolve(
                PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa2048),
                fp,
                None,
                None
            ),
            FeatureGate::Supported,
            "Rsa2048 with no reported version on either axis — substitutes `[]`"
        );
        for alg in [KeyAlg::Rsa1024, KeyAlg::EccP256, KeyAlg::EccP384] {
            assert_eq!(
                resolve(PivExtension::SlotKeyAlgorithm(alg), fp, Some(&[]), None),
                FeatureGate::Unverified,
                "{alg:?} hasn't been probed on this fingerprint"
            );
        }
    }

    // --- PIV SET_MANAGEMENT_KEY: YubiKey/HID Crescendo always, Token2/Thetis
    // --- at 5.112.0, Arekinath from v4, SwissbitIShield2 from v1, Trussed
    // --- Nitrokey from firmware 1.8 -----------------------------------------

    #[test]
    fn yubikey_set_management_key_always_supported() {
        // No known-unsupported floor, same shape as `PivExtension::Reset`'s
        // YubiKey row — this is core key management, not a firmware-5.7
        // addition the way MOVE KEY/DELETE KEY's row is.
        for version in [&[0][..], &[1, 0][..], &[9, 9, 9][..]] {
            assert_eq!(
                resolve(
                    PivExtension::SetManagementKey,
                    AppletFingerprint::YubiKey,
                    Some(version),
                    None
                ),
                FeatureGate::Supported,
                "{version:?}"
            );
        }
        assert_eq!(
            resolve(
                PivExtension::SetManagementKey,
                AppletFingerprint::YubiKey,
                None,
                None
            ),
            FeatureGate::Supported
        );
    }

    #[test]
    fn token2_and_thetis_5_112_0_set_management_key_is_supported() {
        // Hardware-observed known-supported verdict, pinned to exactly the
        // version keyroost has evidence for on each fingerprint — same
        // single-verdict shape as their `Reset`/`SetPinPukRetries` rows.
        for fp in [AppletFingerprint::Token2, AppletFingerprint::Thetis] {
            for version in [&[5, 112, 0][..], &[5, 113, 0][..], &[9, 9, 9][..]] {
                assert_eq!(
                    resolve(PivExtension::SetManagementKey, fp, Some(version), None),
                    FeatureGate::Supported,
                    "{fp:?} at {version:?}"
                );
            }
            // No known-unsupported floor recorded below 5.112.0: an older
            // reported version falls off the row entirely and resolves
            // `Unverified`, not `Supported` or `Unsupported`.
            for version in [&[5, 111, 0][..], &[0][..]] {
                assert_eq!(
                    resolve(PivExtension::SetManagementKey, fp, Some(version), None),
                    FeatureGate::Unverified,
                    "{fp:?} at {version:?}"
                );
            }
            assert_eq!(
                resolve(PivExtension::SetManagementKey, fp, None, None),
                FeatureGate::Unverified,
                "{fp:?} with no reported version"
            );
        }
    }

    #[test]
    fn token2_and_thetis_5_112_0_slot_pin_policy_supported_touch_policy_unsupported() {
        // Same hardware-observed, single-verdict-pinned-to-5.112.0 shape as
        // `SetManagementKey`'s row above, except the two policies disagree
        // with each other on this fingerprint.
        for fp in [AppletFingerprint::Token2, AppletFingerprint::Thetis] {
            for version in [&[5, 112, 0][..], &[5, 113, 0][..], &[9, 9, 9][..]] {
                assert_eq!(
                    resolve(PivExtension::SlotPinPolicy, fp, Some(version), None),
                    FeatureGate::Supported,
                    "{fp:?} at {version:?}"
                );
            }
            // Exact match only — a version above 5.112.0 with no verdict of
            // its own softens to `Unverified` rather than staying blocked.
            assert_eq!(
                resolve(PivExtension::SlotTouchPolicy, fp, Some(&[5, 112, 0]), None),
                FeatureGate::Unsupported,
                "{fp:?}"
            );
            for version in [&[5, 113, 0][..], &[9, 9, 9][..]] {
                assert_eq!(
                    resolve(PivExtension::SlotTouchPolicy, fp, Some(version), None),
                    FeatureGate::Unverified,
                    "{fp:?} at {version:?}"
                );
            }
        }
    }

    #[test]
    fn arekinath_generic_and_swissbit_ishield1_set_management_key_supported_from_v4() {
        for fp in [
            AppletFingerprint::ArekinathPivApplet(ArekinathVariant::Generic),
            AppletFingerprint::ArekinathPivApplet(ArekinathVariant::SwissbitIShield1),
        ] {
            for version in [&[4][..], &[5, 0, 0][..], &[9, 9, 9][..]] {
                assert_eq!(
                    resolve(PivExtension::SetManagementKey, fp, Some(version), None),
                    FeatureGate::Supported,
                    "{fp:?} at {version:?}"
                );
            }
            // Below the only recorded verdict: `KnownSupported` says nothing
            // about versions before it (unlike a `KnownUnsupported` floor),
            // so an older reported version falls off the row entirely.
            assert_eq!(
                resolve(PivExtension::SetManagementKey, fp, Some(&[3]), None),
                FeatureGate::Unverified,
                "{fp:?} below v4"
            );
            assert_eq!(
                resolve(PivExtension::SetManagementKey, fp, None, None),
                FeatureGate::Unverified,
                "{fp:?} with no reported version"
            );
        }
    }

    #[test]
    fn swissbit_ishield2_set_management_key_supported_from_v1() {
        let fp = AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2);
        for version in [
            &[1][..],
            &[1, 0, 0, 0][..],
            &[1, 4, 1, 0][..],
            &[2, 0, 0, 0][..],
        ] {
            assert_eq!(
                resolve(PivExtension::SetManagementKey, fp, Some(version), None),
                FeatureGate::Supported,
                "{version:?}"
            );
        }
        // `[0]` orders below the `[1]` sentinel (shorter is a prefix match,
        // and `0 < 1`), falling off the row entirely.
        assert_eq!(
            resolve(PivExtension::SetManagementKey, fp, Some(&[0]), None),
            FeatureGate::Unverified
        );
        assert_eq!(
            resolve(PivExtension::SetManagementKey, fp, None, None),
            FeatureGate::Unverified
        );
    }

    #[test]
    fn hid_crescendo_set_management_key_supported_at_any_version_including_generic() {
        // Unlike most other HID Crescendo rows, this one is a genuine
        // presence claim (PUT XAUTH KEY), so — like `GetSlotKeyStatus` —
        // it extends to `Generic` too; see `HID_CRESCENDO_C2300_APPLET_VERDICTS`'s
        // doc.
        for variant in [
            HidCrescendoVariant::C2300,
            HidCrescendoVariant::C4000,
            HidCrescendoVariant::Generic,
        ] {
            let fp = AppletFingerprint::HidCrescendo(variant);
            for version in [&[0][..], &[3, 0, 3, 6][..], &[9, 9, 9, 9][..]] {
                assert_eq!(
                    resolve(PivExtension::SetManagementKey, fp, Some(version), None),
                    FeatureGate::Supported,
                    "{fp:?} at {version:?}"
                );
            }
            assert_eq!(
                resolve(PivExtension::SetManagementKey, fp, None, None),
                FeatureGate::Supported,
                "{fp:?} with no reported version"
            );
        }
    }

    // `Trussed(NitroKey)`'s `SetManagementKey` row lives entirely on the
    // firmware axis now — see `trussed_nitrokey_1_8_set_management_key_reset_get_metadata_are_supported`
    // below, and `TRUSSED_NITROKEY_FIRMWARE_VERDICTS`'s own doc for why.

    #[test]
    fn set_management_key_data_does_not_leak_to_other_fingerprints() {
        // `AppletFingerprint::Generic` carries no `SetManagementKey` row,
        // proving the seeded fingerprints above don't leak their verdict
        // elsewhere. Feitian and both UTrust variants don't belong in this
        // list any more — each now has its own genuine `KnownUnsupported`
        // SetManagementKey row, see
        // `feitian_yubico_extensions_are_known_unsupported_at_v0` and
        // `utrust_generic_and_gov_yubico_extensions_are_known_unsupported`.
        // `IdPrime`/`OpenFips201::Generic` don't belong here either any
        // more — each now has its own genuine `KnownUnsupportedSince` row,
        // see
        // `idprime_and_openfips201_generic_yubico_extensions_are_known_unsupported_since`.
        assert_eq!(
            resolve(
                PivExtension::SetManagementKey,
                AppletFingerprint::Generic,
                None,
                None,
            ),
            FeatureGate::Unverified
        );
    }

    // --- Trussed Nitrokey firmware-axis table: SetManagementKey/Reset/
    // --- GetMetadata KnownSupported at 1.8, SetPinPukRetries/MoveKey/
    // --- DeleteKey/Attest KnownUnsupported at 1.8.3 ------------------------

    #[test]
    fn trussed_nitrokey_1_8_set_management_key_reset_get_metadata_are_supported() {
        // Confirmed against the Trussed `piv-authenticator` source and a
        // live unit at firmware 1.8.3 — see `TRUSSED_NITROKEY_FIRMWARE_VERDICTS`'s
        // doc.
        let fp = AppletFingerprint::Trussed(TrussedVariant::NitroKey);
        for ext in [
            PivExtension::SetManagementKey,
            PivExtension::Reset,
            PivExtension::GetMetadata,
        ] {
            for version in [&[1, 8][..], &[1, 8, 3][..], &[9, 9, 9][..]] {
                assert_eq!(
                    resolve(ext, fp, None, Some(version)),
                    FeatureGate::Supported,
                    "{ext:?} at firmware {version:?}"
                );
            }
            // No known-supported floor recorded below 1.8: an older reported
            // firmware version falls off the row entirely and resolves
            // `Unverified`, not `Supported`.
            assert_eq!(
                resolve(ext, fp, None, Some(&[1, 7, 9])),
                FeatureGate::Unverified,
                "{ext:?} below firmware 1.8"
            );
            // None of these three has an applet-axis row for this
            // fingerprint any more — `TRUSSED_NITROKEY_APPLET_VERDICTS`
            // carries only `ResetGlobal` now — so reporting only an applet
            // version, with no firmware version at all, falls back to
            // `Unverified`.
            assert_eq!(
                resolve(ext, fp, Some(&[0]), None),
                FeatureGate::Unverified,
                "{ext:?} with only an applet version reported"
            );
        }
    }

    #[test]
    fn trussed_nitrokey_1_8_3_move_delete_attest_set_pin_puk_retries_are_unsupported() {
        // Hardware-observed known-unsupported verdicts, pinned to exactly the
        // firmware version keyroost has evidence for — see
        // `TRUSSED_NITROKEY_FIRMWARE_VERDICTS`'s doc.
        let fp = AppletFingerprint::Trussed(TrussedVariant::NitroKey);
        for ext in [
            PivExtension::SetPinPukRetries,
            PivExtension::MoveKey,
            PivExtension::DeleteKey,
            PivExtension::Attest,
        ] {
            assert_eq!(
                resolve(ext, fp, None, Some(&[1, 8, 3])),
                FeatureGate::Unsupported,
                "{ext:?} at exactly 1.8.3"
            );
            // `Verdict::KnownUnsupported`'s backward-extension rule: an
            // earlier, untested firmware version — including 1.8 itself — is
            // assumed unsupported too, with no separate `[1, 8]` entry needed
            // on these rows.
            for version in [&[1, 8][..], &[1, 0][..], &[0][..]] {
                assert_eq!(
                    resolve(ext, fp, None, Some(version)),
                    FeatureGate::Unsupported,
                    "{ext:?} at firmware {version:?}, backward from 1.8.3"
                );
            }
            // A firmware newer than 1.8.3 with no verdict of its own softens
            // to `Unverified` — a later firmware may have added the
            // extension — unlike `ResetGlobal`'s `KnownUnsupportedSince` row
            // on this same table, which stays `Unsupported` at any version.
            assert_eq!(
                resolve(ext, fp, None, Some(&[1, 9])),
                FeatureGate::Unverified,
                "{ext:?} above 1.8.3"
            );
        }
    }

    // --- SlotKeyAlgorithm -------------------------------------------------

    #[test]
    fn slot_key_algorithm_with_no_table_data_is_unverified() {
        // `Generic` (no more specific fingerprint matched) seeds no
        // `SlotKeyAlgorithm` row, so every algorithm resolves unverified —
        // the same "no data" default every other extension gets.
        // `OpenFips201::Generic` deliberately carries none either, even
        // though upstream OpenFIPS201 documents a different algorithm set
        // per release line (v1/v1.10/v2/…): this fingerprint has no way to
        // read which line a given unit is running, so a version-gated
        // verdict here would assume a release line no evidence actually
        // pins it to — see `OPENFIPS201_GENERIC_APPLET_VERDICTS`'s own doc.
        for fp in [
            AppletFingerprint::Generic,
            AppletFingerprint::OpenFips201(OpenFips201Variant::Generic),
        ] {
            for alg in KeyAlg::ALL {
                assert_eq!(
                    resolve(PivExtension::SlotKeyAlgorithm(alg), fp, None, None),
                    FeatureGate::Unverified,
                    "{fp:?} {alg:?}"
                );
            }
        }
    }

    #[test]
    fn authentrend_atkey_yubico_extension_set_is_known_supported_at_v6() {
        // Hardware-observed on a live applet v6.0.1 unit, but the
        // `Verdict::KnownSupported` row is deliberately floored at `[6]`
        // rather than the exact tested build: the whole v6 lineup is
        // assumed to share this support — see `AUTHENTREND_ATKEY_APPLET_VERDICTS`'s
        // own doc. Every one of the nine plain extensions, RSA-1024/2048 and
        // ECC P-256/P-384 as slot key algorithms, and all four real
        // `MgmtAlgChoice` values as the management key's algorithm, resolves
        // `Supported` at `[6]` itself and at every version at or above it
        // (`[6, 0, 0]` included, despite predating the actual tested build,
        // and `[6, 0, 1]`/`[6, 1, 0]`/`[7]`), per `Verdict::KnownSupported`'s
        // forward no-regression assumption — but *not* below `[6]`, since
        // that verdict says nothing about versions before it.
        let fp = AppletFingerprint::AuthentrendATKey;
        let extensions = [
            PivExtension::SetPinPukRetries,
            PivExtension::SetManagementKey,
            PivExtension::DeleteKey,
            PivExtension::MoveKey,
            PivExtension::GetMetadata,
            PivExtension::PinManagementAuth,
            PivExtension::SlotPinPolicy,
            PivExtension::SlotTouchPolicy,
            PivExtension::Reset,
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa1024),
            PivExtension::SlotKeyAlgorithm(KeyAlg::Rsa2048),
            PivExtension::SlotKeyAlgorithm(KeyAlg::EccP256),
            PivExtension::SlotKeyAlgorithm(KeyAlg::EccP384),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::TripleDes),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Aes128),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Aes192),
            PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Aes256),
        ];
        for ext in extensions {
            for version in [
                &[6][..],
                &[6, 0, 0][..],
                &[6, 0, 1][..],
                &[6, 1, 0][..],
                &[7][..],
            ] {
                assert_eq!(
                    resolve(ext, fp, Some(version), None),
                    FeatureGate::Supported,
                    "{ext:?} at {version:?}"
                );
            }
            assert_eq!(
                resolve(ext, fp, Some(&[5, 9, 9]), None),
                FeatureGate::Unverified,
                "{ext:?} below v6"
            );
        }
        // RSA-3072/4096, ECC P-521, and Ed25519/X25519 were rejected on the
        // same unit — kept at the exact tested version, `[6, 0, 1]`, rather
        // than widened to `[6]` the same way: nothing here assumes the rest
        // of the v6 lineup shares an *absence*. `Verdict::KnownUnsupported`,
        // not `...Since`: it extends backward to every earlier untested
        // version (assumed to lack it too) but softens back to `Unverified`
        // for any version newer than the row, rather than being asserted
        // unsupported forever — see `AUTHENTREND_ATKEY_APPLET_VERDICTS`'s
        // own doc for why.
        for alg in [
            KeyAlg::Rsa3072,
            KeyAlg::Rsa4096,
            KeyAlg::EccP521,
            KeyAlg::Ed25519,
            KeyAlg::X25519,
        ] {
            for version in [&[0][..], &[6, 0, 0][..], &[6, 0, 1][..]] {
                assert_eq!(
                    resolve(PivExtension::SlotKeyAlgorithm(alg), fp, Some(version), None),
                    FeatureGate::Unsupported,
                    "{alg:?} at {version:?}"
                );
            }
            assert_eq!(
                resolve(
                    PivExtension::SlotKeyAlgorithm(alg),
                    fp,
                    Some(&[6, 1, 0]),
                    None
                ),
                FeatureGate::Unverified,
                "{alg:?} above 6.0.1"
            );
        }
    }

    #[test]
    fn yubikey_algorithm_support_gains_rsa4096_ed25519_x25519_at_5_7() {
        let fp = AppletFingerprint::YubiKey;
        // Supported at every firmware, pre-5.7 included.
        for alg in [
            KeyAlg::Rsa1024,
            KeyAlg::Rsa2048,
            KeyAlg::EccP256,
            KeyAlg::EccP384,
        ] {
            assert_eq!(
                resolve(PivExtension::SlotKeyAlgorithm(alg), fp, Some(&[]), None),
                FeatureGate::Supported,
                "{alg:?} at []"
            );
            assert_eq!(
                resolve(PivExtension::SlotKeyAlgorithm(alg), fp, Some(&[5, 7]), None),
                FeatureGate::Supported,
                "{alg:?} at 5.7"
            );
        }
        // RSA-4096/Ed25519/X25519 arrive together at 5.7, same as MOVE
        // KEY/DELETE KEY.
        for alg in [KeyAlg::Rsa4096, KeyAlg::Ed25519, KeyAlg::X25519] {
            assert_eq!(
                resolve(PivExtension::SlotKeyAlgorithm(alg), fp, Some(&[5, 6]), None),
                FeatureGate::Unsupported,
                "{alg:?} below 5.7"
            );
            assert_eq!(
                resolve(PivExtension::SlotKeyAlgorithm(alg), fp, Some(&[5, 7]), None),
                FeatureGate::Supported,
                "{alg:?} at 5.7"
            );
        }
        // ECC P-521 never arrives.
        assert_eq!(
            resolve(
                PivExtension::SlotKeyAlgorithm(KeyAlg::EccP521),
                fp,
                Some(&[5, 7]),
                None
            ),
            FeatureGate::Unsupported
        );
    }

    #[test]
    fn slot_key_algorithm_apdu_id_falls_back_to_key_alg_id_with_no_override() {
        // YubiKey has no confirmed override, so every algorithm resolves to
        // `KeyAlg::id()`'s own default, regardless of firmware version.
        for alg in KeyAlg::ALL {
            assert_eq!(
                slot_key_algorithm_apdu_id(alg, AppletFingerprint::YubiKey, None),
                alg.id()
            );
            assert_eq!(
                slot_key_algorithm_apdu_id(alg, AppletFingerprint::YubiKey, Some(&[5, 7])),
                alg.id()
            );
        }
    }

    #[test]
    fn key_alg_from_apdu_id_falls_back_to_the_default_table_with_no_override() {
        for alg in KeyAlg::ALL {
            assert_eq!(
                key_alg_from_apdu_id(alg.id(), AppletFingerprint::YubiKey, None),
                Some(alg)
            );
        }
        // A byte no `KeyAlg` claims by default, and no override claims
        // either, resolves to nothing either way.
        assert_eq!(
            key_alg_from_apdu_id(0xFF, AppletFingerprint::YubiKey, None),
            None
        );
    }

    #[test]
    fn arekinath_algorithm_support_matches_yubikey_pre_5_7_at_every_version() {
        // Both sub-fingerprints share one upstream codebase and one
        // unconditional, never-version-gated algorithm list.
        for fp in [
            AppletFingerprint::ArekinathPivApplet(ArekinathVariant::Generic),
            AppletFingerprint::ArekinathPivApplet(ArekinathVariant::SwissbitIShield1),
        ] {
            for alg in [
                KeyAlg::Rsa1024,
                KeyAlg::Rsa2048,
                KeyAlg::EccP256,
                KeyAlg::EccP384,
            ] {
                assert_eq!(
                    resolve(PivExtension::SlotKeyAlgorithm(alg), fp, None, None),
                    FeatureGate::Supported,
                    "{fp:?} {alg:?}"
                );
            }
            for alg in [
                KeyAlg::Rsa3072,
                KeyAlg::Rsa4096,
                KeyAlg::EccP521,
                KeyAlg::Ed25519,
                KeyAlg::X25519,
            ] {
                assert_eq!(
                    resolve(PivExtension::SlotKeyAlgorithm(alg), fp, None, None),
                    FeatureGate::Unsupported,
                    "{fp:?} {alg:?}"
                );
            }
        }
    }

    #[test]
    fn swissbit_ishield2_algorithm_support_gains_rsa3072_rsa4096_eccp521_at_1_4() {
        let fp = AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2);
        for alg in [KeyAlg::Rsa2048, KeyAlg::EccP256, KeyAlg::EccP384] {
            assert_eq!(
                resolve(
                    PivExtension::SlotKeyAlgorithm(alg),
                    fp,
                    Some(&[1, 0, 0, 0]),
                    None
                ),
                FeatureGate::Supported,
                "{alg:?} at 1.0.0.0"
            );
            assert_eq!(
                resolve(
                    PivExtension::SlotKeyAlgorithm(alg),
                    fp,
                    Some(&[1, 4, 1, 0]),
                    None
                ),
                FeatureGate::Supported,
                "{alg:?} at 1.4.1.0"
            );
        }
        for alg in [KeyAlg::Rsa3072, KeyAlg::Rsa4096, KeyAlg::EccP521] {
            assert_eq!(
                resolve(
                    PivExtension::SlotKeyAlgorithm(alg),
                    fp,
                    Some(&[1, 0, 0, 0]),
                    None
                ),
                FeatureGate::Unsupported,
                "{alg:?} at 1.0.0.0"
            );
            assert_eq!(
                resolve(
                    PivExtension::SlotKeyAlgorithm(alg),
                    fp,
                    Some(&[1, 4, 1, 0]),
                    None
                ),
                FeatureGate::Supported,
                "{alg:?} at 1.4.1.0"
            );
        }
        for alg in [KeyAlg::Rsa1024, KeyAlg::Ed25519, KeyAlg::X25519] {
            assert_eq!(
                resolve(
                    PivExtension::SlotKeyAlgorithm(alg),
                    fp,
                    Some(&[1, 4, 1, 0]),
                    None
                ),
                FeatureGate::Unsupported,
                "{alg:?}"
            );
        }
    }

    #[test]
    fn token2_and_thetis_support_every_algorithm_except_eccp521_at_5_112_0() {
        for fp in [AppletFingerprint::Token2, AppletFingerprint::Thetis] {
            for alg in [
                KeyAlg::Rsa1024,
                KeyAlg::Rsa2048,
                KeyAlg::Rsa3072,
                KeyAlg::Rsa4096,
                KeyAlg::EccP256,
                KeyAlg::EccP384,
                KeyAlg::Ed25519,
                KeyAlg::X25519,
            ] {
                assert_eq!(
                    resolve(
                        PivExtension::SlotKeyAlgorithm(alg),
                        fp,
                        Some(&[5, 112, 0]),
                        None
                    ),
                    FeatureGate::Supported,
                    "{fp:?} {alg:?}"
                );
            }
            assert_eq!(
                resolve(
                    PivExtension::SlotKeyAlgorithm(KeyAlg::EccP521),
                    fp,
                    Some(&[5, 112, 0]),
                    None
                ),
                FeatureGate::Unsupported,
                "{fp:?} EccP521"
            );
        }
    }

    #[test]
    fn nitrokey_algorithm_support_gains_rsa3072_eccp384_at_firmware_1_8_2() {
        let fp = AppletFingerprint::Trussed(TrussedVariant::NitroKey);
        // Supported on every firmware, old and new alike.
        for alg in [KeyAlg::Rsa2048, KeyAlg::Rsa4096, KeyAlg::EccP256] {
            assert_eq!(
                resolve(
                    PivExtension::SlotKeyAlgorithm(alg),
                    fp,
                    None,
                    Some(&[1, 8, 1])
                ),
                FeatureGate::Supported,
                "{alg:?} pre-1.8.2"
            );
            assert_eq!(
                resolve(
                    PivExtension::SlotKeyAlgorithm(alg),
                    fp,
                    None,
                    Some(&[1, 8, 2])
                ),
                FeatureGate::Supported,
                "{alg:?} at 1.8.2"
            );
        }
        // New at 1.8.2.
        for alg in [KeyAlg::Rsa3072, KeyAlg::EccP384] {
            assert_eq!(
                resolve(
                    PivExtension::SlotKeyAlgorithm(alg),
                    fp,
                    None,
                    Some(&[1, 8, 1])
                ),
                FeatureGate::Unsupported,
                "{alg:?} pre-1.8.2"
            );
            assert_eq!(
                resolve(
                    PivExtension::SlotKeyAlgorithm(alg),
                    fp,
                    None,
                    Some(&[1, 8, 2])
                ),
                FeatureGate::Supported,
                "{alg:?} at 1.8.2"
            );
        }
        // Never supported.
        for alg in [
            KeyAlg::Rsa1024,
            KeyAlg::EccP521,
            KeyAlg::Ed25519,
            KeyAlg::X25519,
        ] {
            assert_eq!(
                resolve(
                    PivExtension::SlotKeyAlgorithm(alg),
                    fp,
                    None,
                    Some(&[1, 8, 3])
                ),
                FeatureGate::Unsupported,
                "{alg:?}"
            );
        }
    }

    #[test]
    fn nitrokey_rsa4096_apdu_id_switches_at_firmware_1_8_2() {
        let fp = AppletFingerprint::Trussed(TrussedVariant::NitroKey);
        // Pre-1.8.2: the collision byte with `KeyAlg::id()`'s own X25519
        // default.
        assert_eq!(
            slot_key_algorithm_apdu_id(KeyAlg::Rsa4096, fp, Some(&[1, 8, 1])),
            0xE1
        );
        assert_eq!(
            key_alg_from_apdu_id(0xE1, fp, Some(&[1, 8, 1])),
            Some(KeyAlg::Rsa4096)
        );
        // 1.8.2 and later: back to Yubico's own default byte.
        assert_eq!(
            slot_key_algorithm_apdu_id(KeyAlg::Rsa4096, fp, Some(&[1, 8, 2])),
            0x16
        );
        assert_eq!(
            key_alg_from_apdu_id(0x16, fp, Some(&[1, 8, 2])),
            Some(KeyAlg::Rsa4096)
        );
        // Unknown firmware defaults to the new (non-overridden) byte rather
        // than guessing the older one.
        assert_eq!(slot_key_algorithm_apdu_id(KeyAlg::Rsa4096, fp, None), 0x16);
        // Every other algorithm is unaffected, at any firmware.
        for alg in KeyAlg::ALL {
            if alg == KeyAlg::Rsa4096 {
                continue;
            }
            assert_eq!(
                slot_key_algorithm_apdu_id(alg, fp, Some(&[1, 8, 1])),
                alg.id(),
                "{alg:?}"
            );
        }
    }

    #[test]
    fn hid_crescendo_c4000_algorithm_support_matches_its_generate_key_pair_reference() {
        let fp = AppletFingerprint::HidCrescendo(HidCrescendoVariant::C4000);
        for alg in [
            KeyAlg::Rsa2048,
            KeyAlg::Rsa3072,
            KeyAlg::Rsa4096,
            KeyAlg::EccP256,
            KeyAlg::EccP384,
        ] {
            assert_eq!(
                resolve(PivExtension::SlotKeyAlgorithm(alg), fp, None, None),
                FeatureGate::Supported,
                "{alg:?}"
            );
        }
        for alg in [
            KeyAlg::Rsa1024,
            KeyAlg::EccP521,
            KeyAlg::Ed25519,
            KeyAlg::X25519,
        ] {
            assert_eq!(
                resolve(PivExtension::SlotKeyAlgorithm(alg), fp, None, None),
                FeatureGate::Unsupported,
                "{alg:?}"
            );
        }
    }

    #[test]
    fn hid_crescendo_c2300_algorithm_support_is_narrower_than_c4000() {
        // C2300's own GENERATE KEY PAIR reference documents a strictly
        // smaller closed list than C4000's — RSA-3072/4096 are confirmed
        // unsupported here even though C4000 supports them.
        let fp = AppletFingerprint::HidCrescendo(HidCrescendoVariant::C2300);
        for alg in [KeyAlg::Rsa2048, KeyAlg::EccP256, KeyAlg::EccP384] {
            assert_eq!(
                resolve(PivExtension::SlotKeyAlgorithm(alg), fp, None, None),
                FeatureGate::Supported,
                "{alg:?}"
            );
        }
        for alg in [
            KeyAlg::Rsa1024,
            KeyAlg::Rsa3072,
            KeyAlg::Rsa4096,
            KeyAlg::EccP521,
            KeyAlg::Ed25519,
            KeyAlg::X25519,
        ] {
            assert_eq!(
                resolve(PivExtension::SlotKeyAlgorithm(alg), fp, None, None),
                FeatureGate::Unsupported,
                "{alg:?}"
            );
        }
    }

    #[test]
    fn hid_crescendo_generic_has_no_algorithm_support_data() {
        // The two named families' closed lists genuinely differ, so an
        // unclassified unit gets no known-support claim either way.
        let fp = AppletFingerprint::HidCrescendo(HidCrescendoVariant::Generic);
        for alg in KeyAlg::ALL {
            assert_eq!(
                resolve(PivExtension::SlotKeyAlgorithm(alg), fp, None, None),
                FeatureGate::Unverified,
                "{alg:?}"
            );
        }
    }

    #[test]
    fn hid_crescendo_apdu_id_override_matches_its_confirmed_byte_table() {
        // Every HID Crescendo variant shares one wire-byte table — the same
        // one `hid_crescendo_c4000_algorithm_id` already carries for GET PIV
        // PROPERTIES / INJECT PKI KEY — regardless of whether that variant's
        // own GENERATE KEY PAIR reference confirms support for the algorithm
        // (RSA-4096 on C2300, say): the byte and the support gate are
        // separate axes.
        for variant in [
            HidCrescendoVariant::C2300,
            HidCrescendoVariant::C4000,
            HidCrescendoVariant::Generic,
        ] {
            let fp = AppletFingerprint::HidCrescendo(variant);
            assert_eq!(slot_key_algorithm_apdu_id(KeyAlg::Rsa4096, fp, None), 0x04);
            assert_eq!(slot_key_algorithm_apdu_id(KeyAlg::Rsa3072, fp, None), 0x05);
            assert_eq!(slot_key_algorithm_apdu_id(KeyAlg::Rsa2048, fp, None), 0x07);
            assert_eq!(slot_key_algorithm_apdu_id(KeyAlg::EccP256, fp, None), 0x11);
            assert_eq!(slot_key_algorithm_apdu_id(KeyAlg::EccP384, fp, None), 0x14);
            // No confirmed byte for these four — falls back to
            // `KeyAlg::id()`'s default, same as any other fingerprint. HID
            // Crescendo has no byte of its own for EccP521 either way (its
            // own GENERATE KEY PAIR references stop at 384-bit EC), unlike
            // `OpenFips201::SwissbitIShield2` below.
            assert_eq!(
                slot_key_algorithm_apdu_id(KeyAlg::Rsa1024, fp, None),
                KeyAlg::Rsa1024.id()
            );
            assert_eq!(
                slot_key_algorithm_apdu_id(KeyAlg::EccP521, fp, None),
                KeyAlg::EccP521.id()
            );
            assert_eq!(
                slot_key_algorithm_apdu_id(KeyAlg::Ed25519, fp, None),
                KeyAlg::Ed25519.id()
            );
            assert_eq!(
                slot_key_algorithm_apdu_id(KeyAlg::X25519, fp, None),
                KeyAlg::X25519.id()
            );
            // And the reverse lookup round-trips through the same table.
            assert_eq!(key_alg_from_apdu_id(0x04, fp, None), Some(KeyAlg::Rsa4096));
            assert_eq!(key_alg_from_apdu_id(0x05, fp, None), Some(KeyAlg::Rsa3072));
        }
    }

    #[test]
    fn swissbit_ishield2_eccp521_apdu_id_override_is_narrow() {
        let fp = AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2);
        // The one confirmed divergence: 0x32, not INCITS 504-1's 0x15.
        assert_eq!(slot_key_algorithm_apdu_id(KeyAlg::EccP521, fp, None), 0x32);
        assert_eq!(key_alg_from_apdu_id(0x32, fp, None), Some(KeyAlg::EccP521));
        // Every other algorithm on this sub-fingerprint still falls back to
        // `KeyAlg::id()`'s own default — the override is scoped to EccP521
        // alone, not a blanket remap.
        for alg in KeyAlg::ALL {
            if alg == KeyAlg::EccP521 {
                continue;
            }
            assert_eq!(
                slot_key_algorithm_apdu_id(alg, fp, None),
                alg.id(),
                "{alg:?}"
            );
        }
        // `0x32` is specific to this one sub-fingerprint — it must not leak
        // into the default table other fingerprints (or `KeyAlg::id` itself)
        // resolve through.
        assert_eq!(KeyAlg::EccP521.id(), 0x15);
        assert_eq!(KeyAlg::from_id(0x32), None);
        assert_eq!(
            slot_key_algorithm_apdu_id(KeyAlg::EccP521, AppletFingerprint::YubiKey, None),
            0x15
        );
        // Nor does it apply to the other Swissbit applet/sub-fingerprint on
        // the same vendor's hardware.
        assert_eq!(
            slot_key_algorithm_apdu_id(
                KeyAlg::EccP521,
                AppletFingerprint::ArekinathPivApplet(ArekinathVariant::SwissbitIShield1),
                None
            ),
            0x15
        );
    }

    // --- ManagementKeyAlgorithm / MgmtAlgChoice ---------------------------

    #[test]
    fn mgmt_alg_choice_to_mgmt_alg_is_none_only_for_delete() {
        assert_eq!(
            MgmtAlgChoice::TripleDes.to_mgmt_alg(),
            Some(crate::MgmtAlg::TripleDes)
        );
        assert_eq!(
            MgmtAlgChoice::Aes128.to_mgmt_alg(),
            Some(crate::MgmtAlg::Aes128)
        );
        assert_eq!(
            MgmtAlgChoice::Aes192.to_mgmt_alg(),
            Some(crate::MgmtAlg::Aes192)
        );
        assert_eq!(
            MgmtAlgChoice::Aes256.to_mgmt_alg(),
            Some(crate::MgmtAlg::Aes256)
        );
        assert_eq!(MgmtAlgChoice::Delete.to_mgmt_alg(), None);
        assert_eq!(MgmtAlgChoice::Delete.label(), "Delete");
        assert_eq!(
            MgmtAlgChoice::Aes192.label(),
            crate::MgmtAlg::Aes192.label()
        );
    }

    #[test]
    fn yubikey_token2_thetis_arekinath_openfips201_support_every_real_mgmt_alg() {
        // Every fingerprint seeded with `Verdict::KnownSupported` for the four
        // real `MgmtAlgChoice` variants at the universal `[]` version —
        // reported version shouldn't matter for any of them.
        for fp in [
            AppletFingerprint::YubiKey,
            AppletFingerprint::Token2,
            AppletFingerprint::Thetis,
            AppletFingerprint::ArekinathPivApplet(ArekinathVariant::Generic),
            AppletFingerprint::ArekinathPivApplet(ArekinathVariant::SwissbitIShield1),
            AppletFingerprint::OpenFips201(OpenFips201Variant::Generic),
            AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2),
        ] {
            for alg in [
                MgmtAlgChoice::TripleDes,
                MgmtAlgChoice::Aes128,
                MgmtAlgChoice::Aes192,
                MgmtAlgChoice::Aes256,
            ] {
                assert_eq!(
                    resolve(
                        PivExtension::ManagementKeyAlgorithm(alg),
                        fp,
                        Some(&[9, 9, 9]),
                        None
                    ),
                    FeatureGate::Supported,
                    "{fp:?} {alg:?}"
                );
            }
            // `Delete` has no standard PIV equivalent on any of these.
            assert_eq!(
                resolve(
                    PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Delete),
                    fp,
                    Some(&[9, 9, 9]),
                    None
                ),
                FeatureGate::Unsupported,
                "{fp:?}"
            );
        }
    }

    #[test]
    fn hid_crescendo_supports_only_tdes_aes128_and_delete() {
        for fp in [
            AppletFingerprint::HidCrescendo(HidCrescendoVariant::Generic),
            AppletFingerprint::HidCrescendo(HidCrescendoVariant::C2300),
            AppletFingerprint::HidCrescendo(HidCrescendoVariant::C4000),
        ] {
            for alg in [
                MgmtAlgChoice::TripleDes,
                MgmtAlgChoice::Aes128,
                MgmtAlgChoice::Delete,
            ] {
                assert_eq!(
                    resolve(PivExtension::ManagementKeyAlgorithm(alg), fp, None, None),
                    FeatureGate::Supported,
                    "{fp:?} {alg:?}"
                );
            }
            for alg in [MgmtAlgChoice::Aes192, MgmtAlgChoice::Aes256] {
                assert_eq!(
                    resolve(PivExtension::ManagementKeyAlgorithm(alg), fp, None, None),
                    FeatureGate::Unsupported,
                    "{fp:?} {alg:?}"
                );
            }
        }
    }

    #[test]
    fn generic_fingerprint_has_no_mgmt_alg_data_except_delete() {
        // No known-support data for the four real algorithms — each resolves
        // Unverified rather than being asserted one way or the other — but
        // `Delete` still resolves Unsupported, since the "every fingerprint
        // except HidCrescendo" rule doesn't exempt the fallback fingerprint.
        for alg in [
            MgmtAlgChoice::TripleDes,
            MgmtAlgChoice::Aes128,
            MgmtAlgChoice::Aes192,
            MgmtAlgChoice::Aes256,
        ] {
            assert_eq!(
                resolve(
                    PivExtension::ManagementKeyAlgorithm(alg),
                    AppletFingerprint::Generic,
                    None,
                    None
                ),
                FeatureGate::Unverified,
                "{alg:?}"
            );
        }
        assert_eq!(
            resolve(
                PivExtension::ManagementKeyAlgorithm(MgmtAlgChoice::Delete),
                AppletFingerprint::Generic,
                None,
                None
            ),
            FeatureGate::Unsupported
        );
    }

    #[test]
    fn nitrokey_firmware_axis_gates_mgmt_alg_by_firmware_1_8_3() {
        let fp = AppletFingerprint::Trussed(TrussedVariant::NitroKey);
        // 3DES/AES-256 supported at any reported firmware.
        for alg in [MgmtAlgChoice::TripleDes, MgmtAlgChoice::Aes256] {
            assert_eq!(
                resolve(
                    PivExtension::ManagementKeyAlgorithm(alg),
                    fp,
                    None,
                    Some(&[1, 2, 0])
                ),
                FeatureGate::Supported,
                "{alg:?}"
            );
        }
        // AES-128/AES-192 known-unsupported up to and including 1.8.3 —
        // extended backward to an earlier firmware too.
        for alg in [MgmtAlgChoice::Aes128, MgmtAlgChoice::Aes192] {
            for fw in [&[1u8, 8, 3][..], &[1, 2, 0][..]] {
                assert_eq!(
                    resolve(
                        PivExtension::ManagementKeyAlgorithm(alg),
                        fp,
                        None,
                        Some(fw)
                    ),
                    FeatureGate::Unsupported,
                    "{alg:?} {fw:?}"
                );
            }
            // A firmware newer than every verdict on the row softens to
            // Unverified rather than staying Unsupported.
            assert_eq!(
                resolve(
                    PivExtension::ManagementKeyAlgorithm(alg),
                    fp,
                    None,
                    Some(&[1, 9, 0])
                ),
                FeatureGate::Unverified,
                "{alg:?}"
            );
        }
    }
}
