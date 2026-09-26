//! PIV (NIST SP 800-73-4) over PC/SC.
//!
//! Drives the PIV smartcard application using the pure-byte builders/parsers in
//! [`keyroost_piv`]. Like the OATH and OpenPGP sessions, this adds the card
//! transmit, the `61xx` / GET RESPONSE reassembly loop, reader discovery, the
//! status view (version/serial/PIN-retries/per-slot certs), and the full
//! management surface: management-key mutual authentication (the AES/3DES
//! witness/challenge round — the only place this crate does block-cipher math),
//! PIN/PUK change and unblock, set-pin-retries, set-management-key, key
//! generation, certificate import/export, and applet reset.

use crate::gzip::gunzip_capped;
use crate::{trace, TransportError};
use keyroost_piv as piv;
use keyroost_piv::{KeyAlg, Metadata, MgmtAlg, PinPolicy, PublicKey, Slot, TouchPolicy};
use pcsc::{
    Card, Context, Error as PcscError, Protocols, ReaderState, Scope, ShareMode, State, Transaction,
};
use std::collections::{BTreeSet, HashMap};
use zeroize::Zeroizing;

/// How many wrong-credential attempts to make when intentionally blocking a
/// PIN or PUK during a factory reset: always more than the card's reported
/// retry count so a block is guaranteed, but hard-capped so a card that
/// misreports (or never decrements) cannot loop forever.
fn block_attempts_cap(reported: Option<u8>) -> u32 {
    reported.map(u32::from).unwrap_or(10).min(20) + 2
}

/// A throwaway 8-ASCII-digit credential for the loops that deliberately block a
/// PIN/PUK during a factory reset, drawn fresh from the host RNG and never equal
/// to `previous`.
///
/// Eight digits is a legal PIV **and** OpenPGP credential (both store 6–8
/// bytes), so the card evaluates the attempt and decrements its counter instead
/// of rejecting it on length. Drawing it fresh matters: any constant compiled in
/// here is also a value a card may legitimately hold, and this source is
/// published — a "wrong" guess that turns out to be right consumes no try at
/// all, and on the PUK path it rewrites the PIN. `previous` is excluded because
/// some applets refuse an unchanged credential without counting the attempt.
/// Shared with the OpenPGP applet's factory reset.
pub(crate) fn random_credential_guess(
    previous: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>, TransportError> {
    let mut raw = Zeroizing::new([0u8; GUESS_LEN]);
    // No fallback to a constant: a factory reset that can't draw fresh entropy
    // has to stop, not go back to guessing something predictable.
    getrandom::getrandom(&mut raw[..]).map_err(|_| TransportError::HostRngFailed)?;
    Ok(credential_guess_from(&raw, previous))
}

/// Length of a blocking-loop guess, in ASCII digits.
const GUESS_LEN: usize = 8;

/// The deterministic half of [`random_credential_guess`]: fold raw entropy into
/// ASCII digits, then step off `previous` if the draw happened to collide with
/// it. (Split out so the collision path is testable without stubbing the RNG.)
fn credential_guess_from(raw: &[u8; GUESS_LEN], previous: Option<&[u8]>) -> Zeroizing<Vec<u8>> {
    let mut guess = Zeroizing::new(Vec::with_capacity(GUESS_LEN));
    for byte in raw.iter() {
        guess.push(b'0' + byte % 10);
    }
    // A repeat is astronomically unlikely but would waste an attempt on an
    // applet that ignores an unchanged credential; bump the last digit rather
    // than re-rolling so this can never spin.
    if previous == Some(guess.as_slice()) {
        let last = GUESS_LEN - 1;
        guess[last] = b'0' + (guess[last] - b'0' + 1) % 10;
    }
    guess
}

/// Re-map an error raised by the final RESET step of [`PivSession::factory_reset`]
/// onto what the card is actually left holding.
///
/// By that point the PIN and the PUK are deliberately blocked, so a card that
/// *permanently* refuses RESET is a card keyroost can no longer finish: the
/// single-applet `piv reset` sends the identical instruction and gets the
/// identical refusal. Only the permanent refusals are rewritten — a transport
/// fault (card pulled, reader gone) and an unspecific or transient status word
/// are not the card saying "this instruction does not exist", and re-running
/// the factory reset against a quiescent applet is still right there. The
/// callers append that re-run hint to everything left falling through.
fn map_reset_stage_error(e: TransportError) -> TransportError {
    match e {
        // Two refusals, and only two, are the card's final word.
        //
        // 6982, 6983, or 6985 (all three mapped by `PivSession::reset` onto
        // PivResetNotAllowed): the card checked the one precondition RESET
        // has and says it is unmet — with the PIN and PUK already blocked, a
        // second run reaches the same check and gets the same answer, so
        // there is nothing left to retry.
        //
        // 6D00 (INS not supported) / 6A81 (function not supported): the
        // vendor-extension RESET instruction is not implemented at all. No
        // amount of retrying conjures it.
        //
        // Everything else the card can answer under this label — 6F00 (no
        // precise diagnosis), 6881, a 6A82 from an applet that momentarily
        // lost its selection after the blocking loops — says nothing about
        // RESET being unavailable, so it must NOT be rewritten into a verdict
        // of "permanently unusable". Those never surface as
        // PivResetNotAllowed in the first place (`reset` only maps 6982/
        // 6983/6985 onto it), so nothing here needs to single them out.
        TransportError::PivResetNotAllowed
        | TransportError::Apdu {
            label: "piv reset",
            sw1: 0x6D,
            sw2: 0x00,
        }
        | TransportError::Apdu {
            label: "piv reset",
            sw1: 0x6A,
            sw2: 0x81,
        } => TransportError::PivResetIncomplete(
            "the PIN and the PUK are now both blocked, but the card refused the \
             RESET instruction, so the PIV applet was NOT wiped. Its keys and \
             certificates are still on the card and there is no keyroost command \
             that can finish this — `keyroostctl piv reset` sends the very \
             instruction the card just refused. The PIV part of the card is \
             unusable until whoever issued or made it resets it with their own \
             tooling. Any non-PIV applets on the same key (FIDO, OATH, OpenPGP) \
             are unaffected.",
        ),
        other => other,
    }
}

/// A read-only snapshot of a PIV application's state.
#[non_exhaustive]
#[derive(Debug, Clone, Default)]
pub struct PivStatus {
    /// The PIV applet's own version. Ordinarily the reply to Yubico's
    /// proprietary `GET VERSION` extension (`INS FD`), raw bytes, any
    /// non-empty length — real Yubico firmware answers with exactly 3
    /// (`major.minor.patch`), but this extension is implemented by many
    /// devices beyond genuine YubiKeys (observed: a Swissbit iShield Key 2
    /// Pro, an OpenFIPS201 build, answering `9000` with 4 bytes that don't
    /// trace back to anything in OpenFIPS201's own source), so a reply here
    /// means "answers this Yubico extension," not "is a YubiKey." When a
    /// specific fingerprint's own probe supplies an applet version instead
    /// (currently: HID Crescendo, via its GET PIV PROPERTIES response's own
    /// "Applet Version Block" — that fingerprint never answers the Yubico
    /// extension at all), that one is used instead. `None` when neither
    /// source answers. [`PivSession::feature_gate`] (via [`keyroost_piv::compat`])
    /// compares this directly as a byte slice rather than requiring an exact
    /// 3-byte shape. See [`keyroost_piv::format_version_bytes`] for display
    /// formatting.
    pub version: Option<Vec<u8>>,
    /// The applet's own firmware version, when a specific fingerprint's probe
    /// discovered one — a Nitrokey (`Trussed(NitroKey)`, via Trussed's admin
    /// application) or a Token2 (`AppletFingerprint::Token2` only, not
    /// `Thetis`). Not necessarily equal to [`Self::version`]: that field is
    /// the *PIV applet's* own version (Yubico's `GET VERSION` extension,
    /// when the card answers it at all), a different number on cards where
    /// this one is populated. `None` when no such probe applies to this
    /// fingerprint, or the probe ran and found nothing parseable — same
    /// best-effort degradation as [`Self::applet_name`].
    ///
    /// The two populated fingerprints differ in kind, not just source: a
    /// Nitrokey's value is genuinely device-reported (its admin
    /// application's own `GET_VERSION`), while Token2's is *derived* — its
    /// applet never answers a real firmware-version query at all, so this is
    /// instead [`keyroost_piv::fingerprint::token2_firmware_from_serial`]'s
    /// fixed encoding of the hardware generation (`[3, 3]`/`[3, 4]`) its
    /// serial prefix identifies, read via the same on-device OTP-applet
    /// probe that supplies [`Self::serial`] for this fingerprint (see
    /// `PivSession::probe_token2_otp_serial`) — nothing Token2's firmware
    /// itself ever puts on the wire.
    pub version_firmware: Option<Vec<u8>>,
    /// Device serial number. Ordinarily the Yubico GET SERIAL extension
    /// (widened to `u128` — see [`keyroost_piv::parse_serial`]); when a
    /// specific fingerprint's own probe supplies a serial instead — a
    /// Nitrokey's admin application, or a HID Crescendo unit's GlobalPlatform
    /// CPLC read (see `PivSession::probe_hid_crescendo_cplc_serial`) —
    /// that one is used and GET SERIAL is skipped entirely: a Nitrokey
    /// answers that Yubico extension too, but with a number that isn't its
    /// real serial, and HID Crescendo doesn't answer it at all. `None` when
    /// neither source answers.
    pub serial: Option<u128>,
    /// Remaining PIN tries from a no-op VERIFY (`63 Cx`); `Some(0)` when blocked,
    /// `None` when the card didn't report a count.
    pub pin_retries: Option<u8>,
    /// Per-slot certificate presence, in canonical slot order.
    pub slots: Vec<PivSlotStatus>,
    /// The card's CHUID (FASC-N, GUID, expiration), when it has one. A
    /// read-only, best-effort read: a transport failure degrades to `None`
    /// rather than failing the whole status snapshot (see [`PivSession::status`]).
    pub chuid: Option<keyroost_piv::Chuid>,
    /// Best-effort fingerprint of the PIV applet implementation — from ATR
    /// and SELECT-response text, but also from whether a specific applet can
    /// be selected by AID at all (e.g. Feitian's registered RID) and, in
    /// general, from whether the card supports a particular instruction; see
    /// [`keyroost_piv::fingerprint`] for the full scheme. `Generic` when
    /// nothing more specific matched, not when fingerprinting itself failed.
    pub applet_fingerprint: keyroost_piv::fingerprint::AppletFingerprint,
    /// The token's own name, when a specific one was actually discovered:
    /// currently a Nitrokey's admin application (for
    /// [`AppletFingerprint::Trussed`](keyroost_piv::fingerprint::AppletFingerprint::Trussed)`(`[`NitroKey`](keyroost_piv::fingerprint::TrussedVariant::NitroKey)`)`),
    /// a YubiKey's own major version (for
    /// [`AppletFingerprint::YubiKey`](keyroost_piv::fingerprint::AppletFingerprint::YubiKey)),
    /// or HID Crescendo's SELECT response Application Label (for
    /// [`AppletFingerprint::HidCrescendo`](keyroost_piv::fingerprint::AppletFingerprint::HidCrescendo)`(`[`C2300`](keyroost_piv::fingerprint::HidCrescendoVariant::C2300)`)`/[`C4000`](keyroost_piv::fingerprint::HidCrescendoVariant::C4000)`)`).
    /// Empty otherwise — deliberately not backfilled with the generic
    /// [`keyroost_piv::fingerprint::AppletFingerprint::applet_name`] for
    /// `applet_fingerprint`, so a caller can tell "this card told us its own
    /// name" apart from "we only classified the applet family". A caller
    /// wanting something to show either way falls back to `applet_fingerprint`
    /// itself (its `Display` impl, or `applet_fingerprint.applet_name()`).
    pub applet_name: String,
}

/// Whether a given PIV key slot holds a certificate (and its size).
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct PivSlotStatus {
    pub slot: piv::Slot,
    /// True when GET DATA returned a certificate object for the slot —
    /// including one that cannot be read (see [`Self::cert_unreadable`]).
    pub cert_present: bool,
    /// Length in bytes of the certificate's DER encoding, as read from the
    /// card, when present. This is the DER itself — the card's own `0x53`
    /// object framing (the `70`/`71`/`FE` TLVs wrapping it) is not counted.
    /// `0` when the certificate is unreadable.
    pub cert_len: usize,
    /// `Some` when the slot holds a certificate that cannot be read, and why.
    /// The slot is not empty: writing a new certificate replaces it.
    pub cert_unreadable: Option<CertUnreadable>,
}

/// Why a slot's certificate object holds a certificate that cannot be read.
/// Both cases are a certificate flagged gzip-compressed (CertInfo `71 01 01`,
/// as the tool that wrote the object may choose) whose compressed data won't
/// inflate.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertUnreadable {
    /// Not a gzip stream, or its compressed data is corrupt or cut off.
    Damaged,
    /// It inflates past the 64 KiB host ceiling on a certificate's size.
    TooLarge,
}

impl CertUnreadable {
    /// A stable machine-readable token (`damaged` / `too_large`).
    pub fn code(self) -> &'static str {
        match self {
            CertUnreadable::Damaged => "damaged",
            CertUnreadable::TooLarge => "too_large",
        }
    }
}

impl std::fmt::Display for CertUnreadable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CertUnreadable::Damaged => "its compressed data is damaged",
            CertUnreadable::TooLarge => "it decompresses to more than 64 KiB",
        })
    }
}

/// [`PivStatus`] plus the per-slot key/certificate detail a status pane
/// shows, gathered in the single pass [`PivSession::status_detailed`] makes.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct PivStatusDetailed {
    /// The plain status snapshot — version, serial, PIN retries, CHUID, and
    /// per-slot certificate occupancy.
    pub status: PivStatus,
    /// Per-slot detail, in the same canonical slot order as `status.slots`.
    pub slots: Vec<PivSlotDetail>,
}

/// One slot's key algorithm, certificate Subject DN, and PIN/touch policy —
/// what [`PivSession::slot_key_algorithm`] and [`PivSession::slot_policy`]
/// each return, but read together so the slot's one GET METADATA and one
/// certificate GET DATA are shared rather than repeated.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct PivSlotDetail {
    pub slot: piv::Slot,
    /// Key algorithm, or `None` when this card names no key for the slot (GET
    /// METADATA silent, nothing generated in this session, no certificate to
    /// parse). Same three-step fallback as [`PivSession::slot_key_algorithm`].
    pub algorithm: Option<KeyAlg>,
    /// The slot certificate's Subject DN, formatted; `None` when the slot has
    /// no certificate or its DN did not parse (degraded silently, as in the
    /// pane this feeds).
    pub subject: Option<String>,
    /// PIN and touch policy, or `None` when unavailable — not necessarily an
    /// empty slot; see [`PivSession::slot_policy`].
    pub policy: Option<(PinPolicy, TouchPolicy)>,
}

/// [`PivSession::identity`]'s resolved shape: this applet's
/// [`keyroost_piv::fingerprint::AppletFingerprint`] plus its reported
/// applet-version and firmware-version byte strings (either or both `None`
/// when the card never reported one) — everything
/// [`keyroost_piv::compat::resolve`]/[`keyroost_piv::compat::resolve_quirks`]
/// need to gate a [`keyroost_piv::compat::PivExtension`] or resolve a
/// [`keyroost_piv::compat::PivQuirk`]. Named fields rather than a tuple on
/// purpose: `version` vs. `version_firmware` is exactly the distinction that
/// went wrong when HID Crescendo's applet version was first wired up
/// (landed in the wrong axis, caught only in review) — a positional
/// `.0`/`.1`/`.2` (or a same-shaped tuple destructured in the wrong order)
/// can't fail that same way, since the compiler checks the field name at
/// every use.
#[derive(Clone)]
struct SessionIdentity {
    fingerprint: keyroost_piv::fingerprint::AppletFingerprint,
    version: Option<Vec<u8>>,
    version_firmware: Option<Vec<u8>>,
}

/// [`PivSession::applet_fingerprint`]'s resolved shape — see that method's
/// doc for what each field means. Named fields for the same reason as
/// [`SessionIdentity`]'s. `Clone` so [`PivSession::identity`] (the field) can
/// cache one of these and hand out copies without re-resolving — see that
/// field's doc.
#[derive(Clone)]
struct AppletFingerprintResult {
    fingerprint: keyroost_piv::fingerprint::AppletFingerprint,
    name: String,
    version: Option<Vec<u8>>,
    version_firmware: Option<Vec<u8>>,
    serial: Option<u128>,
}

/// How a caller is currently authorized to change the card-management key,
/// passed to [`PivSession::set_management_key`]/
/// [`PivSession::delete_management_key_hid_crescendo`]. Every fingerprint but
/// one ignores this — the standard SET MANAGEMENT KEY round relies on the
/// ordinary 9B security status a prior [`PivSession::authenticate_management`]/
/// [`PivSession::authenticate_management_via_pin`] call already established,
/// same as every other admin write in this module. The one exception is a
/// HID Crescendo unit whose "management key" isn't a real PIV object at all
/// (see `PivSession::hid_crescendo_reports_management_key`): there,
/// installing or deleting a key happens on a *different* applet instance
/// (the ACA), which needs its own unlock run fresh rather than assumed to
/// still be in force — see
/// `PivSession::hid_crescendo_aca_put_xauth_key_op`.
#[derive(Debug, Clone, Copy)]
pub enum CurrentMgmtAuth<'a> {
    /// The current management key, for the standard round or ACA XAUTH's
    /// GET CHALLENGE / EXTERNAL AUTHENTICATE round.
    Key(&'a [u8]),
    /// A PIN, for a device with
    /// [`keyroost_piv::compat::PivExtension::PinManagementAuth`].
    Pin(&'a [u8]),
}

/// [`PivSession::set_management_key_pin_protected`]'s outcome.
#[derive(Debug)]
pub enum PinProtectMaintenance {
    /// The device is HID Crescendo, which unlocks management directly off
    /// the PIN with no key material of its own to store — the whole
    /// maintenance step was skipped, not attempted and failed.
    NotApplicable,
    /// The maintenance step ran. The Admin Data bookkeeping bit
    /// (`keyroost_piv::OBJECT_ADMIN_DATA`) is always best-effort — see
    /// `PivSession::update_admin_data_pin_protected_flag`'s doc — and
    /// never surfaces here; `printed_data` is the outcome of the
    /// substantive write/clear against
    /// `keyroost_piv::OBJECT_PIN_PROTECTED_DATA`, the object
    /// [`PivSession::authenticate_management_via_pin`] actually reads back.
    ///
    /// A caller deciding how to react to `printed_data` being `Err` should
    /// weigh it against
    /// [`keyroost_piv::compat::PivExtension::PinManagementAuth`]'s gate for
    /// this device: at `Supported`, PIN-protected storage is confirmed to
    /// work here, so a failure is a real problem worth erroring on; at
    /// anything less certain (`Unverified`, or `Unsupported` overridden by
    /// `keyroostctl`'s `--force`), this device was never confirmed to
    /// support the write at all, so a failure is expected background noise
    /// — worth a warning, not an error, especially since
    /// [`PivSession::set_management_key`] has already succeeded by this
    /// point regardless.
    Ran {
        printed_data: Result<(), TransportError>,
    },
}

/// What [`PivSession::factory_reset`] does for the PIV-only path, resolved
/// purely from this applet's [`keyroost_piv::compat::PivExtension::Reset`]
/// gate and [`keyroost_piv::compat::PivQuirk`]s — see
/// [`PivSession::plan_factory_reset`], which resolves this, and
/// [`PivResetPreview`], which wraps it alongside the device-wide
/// [`keyroost_piv::compat::PivExtension::ResetGlobal`] alternative
/// [`PivSession::factory_reset`] prefers when it's available (this type says
/// nothing about that axis on its own — see [`PivResetPreview::Global`]).
/// Exposed as its own public type — not just an internal branch inside
/// [`PivSession::factory_reset`] — so a whole-device factory reset can preview
/// the PIV-only shape up front and decide how to report the step (e.g.
/// "skipped: not supported" vs. a real failure) without duplicating the
/// decision or having to parse it back out of a [`TransportError`] variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactoryResetPlan {
    /// [`keyroost_piv::compat::FeatureGate::Unsupported`]: this fingerprint
    /// is known not to implement RESET at all. Deliberately blocking the
    /// PIN and PUK would have no way back, so [`PivSession::factory_reset`]
    /// refuses before touching either counter — unless
    /// [`keyroost_piv::compat::PivExtension::ResetGlobal`] offers something
    /// instead, in which case [`PivResetPreview::Global`] wins before this
    /// variant is even reached.
    Unsupported,
    /// RESET needs an authenticated management-key session on this
    /// fingerprint ([`keyroost_piv::compat::PivQuirk::ResetNeedsManagementAuth`]),
    /// not the PIN/PUK-blocked precondition [`PivSession::factory_reset`]
    /// otherwise automates. It authenticates with the
    /// `current` credential its caller supplied, then sends RESET —
    /// refusing instead, with [`TransportError::PivResetNeedsManagementAuth`],
    /// only when no credential was supplied at all.
    NeedsManagementAuth,
    /// [`keyroost_piv::compat::FeatureGate::Unverified`]: support can't be
    /// confirmed, so [`PivSession::factory_reset`] skips its usual PIN/PUK
    /// pre-blocking (blocking both blindly on a device that might not
    /// implement RESET risks a permanent lock) and sends a bare
    /// [`PivSession::reset`] instead, succeeding or failing on the card's
    /// own terms.
    Unverified,
    /// [`keyroost_piv::compat::FeatureGate::Supported`] with no
    /// [`keyroost_piv::compat::PivQuirk::ResetNeedsManagementAuth`] — the
    /// YubiKey convention, and the most-automated mechanism
    /// [`PivSession::factory_reset`] runs: burn the PIN, then the PUK, then
    /// RESET.
    BurnPinPukThenReset,
}

/// What [`PivSession::factory_reset`] will attempt for this applet's current
/// fingerprint, resolved read-only by [`PivSession::preview_factory_reset`] —
/// [`keyroost_piv::compat::PivExtension::ResetGlobal`] checked first (a
/// device-wide mechanism wins over a PIV-only one whenever it's available),
/// [`FactoryResetPlan`] (`PivExtension::Reset`'s own shape) as the fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PivResetPreview {
    /// Neither `PivExtension::ResetGlobal` nor `PivExtension::Reset` is
    /// anything but a confirmed dead end: [`PivSession::factory_reset`] would
    /// refuse outright with [`TransportError::PivResetUnsupported`]. A
    /// whole-device factory reset should not even plan a PIV step for this
    /// device (`keyroost_resolve::exclude_unresettable_piv`).
    Unsupported,
    /// `PivExtension::ResetGlobal` resolves
    /// [`keyroost_piv::compat::FeatureGate::Supported`] or
    /// [`keyroost_piv::compat::FeatureGate::Unverified`]:
    /// [`PivSession::factory_reset`] will attempt
    /// the device-wide mechanism (HID Crescendo's ACA RESET CARD today),
    /// which takes PIV down with it alongside at least one other applet.
    /// Wins over [`Self::Piv`] even when `PivExtension::Reset` also offers
    /// something — a device-wide mechanism, once available, is the more
    /// complete reset.
    Global,
    /// `PivExtension::ResetGlobal` is a confirmed dead end but
    /// `PivExtension::Reset` isn't: [`PivSession::factory_reset`] will attempt
    /// a PIV-only reset, per this nested [`FactoryResetPlan`].
    Piv(FactoryResetPlan),
}

/// Outcome of a successful [`PivSession::factory_reset`]. Both variants mean
/// the applet (and, on the device-wide path, whatever else that mechanism
/// covers) was actually wiped — [`Self::WipedKeyRestoreFailed`] only
/// distinguishes a courtesy follow-up step that failed afterward, never
/// reachable unless the wipe itself already succeeded. Named for the outcome
/// generally, not just the device-wide path: every other path `factory_reset`
/// can take (the PIN/PUK burn dance, a bare unverified RESET, an
/// authenticated management-key RESET) only ever produces [`Self::Wiped`] on
/// success, since none of them has an equivalent courtesy follow-up step to
/// fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactoryResetOutcome {
    /// The PIV applet was wiped by one of the mechanisms confined to PIV
    /// itself ([`FactoryResetPlan`]'s shapes) — nothing outside PIV was
    /// touched. See [`Self::WipedGlobal`] for the device-wide counterpart.
    Wiped,
    /// `PivSession::hid_crescendo_aca_reset_card`-specific: the device-wide
    /// `PivExtension::ResetGlobal` mechanism ran cleanly — RESET CARD
    /// succeeded and XAUTH key 1 was restored to HID's documented
    /// factory-delivery value. This took at least one other applet down with
    /// PIV, so a caller building a report line should name the whole device,
    /// not just PIV (`keyroost_resolve`'s `PIV_GLOBAL_RESET_LABEL`) — unlike
    /// [`Self::Wiped`], which is confined to PIV alone.
    WipedGlobal,
    /// `PivSession::hid_crescendo_aca_reset_card`-specific: RESET CARD
    /// succeeded — the device IS wiped — but restoring XAUTH key 1 to HID's
    /// documented factory-delivery value afterward failed. XAUTH key 1 is
    /// left cleared (RESET CARD's own effect) rather than at the factory
    /// default; a caller should tell the user this distinctly from a hard
    /// failure, since the reset itself worked. Same device-wide scope as
    /// [`Self::WipedGlobal`] — only the courtesy restore is what's soft here.
    WipedKeyRestoreFailed,
}

/// What `PivSession::hid_crescendo_aca_put_xauth_key_op` should do to XAUTH
/// key 1 once unlocked — install a new key ([`Self::Set`], from
/// [`PivSession::set_management_key`]) or delete it outright ([`Self::Delete`],
/// from [`PivSession::delete_management_key_hid_crescendo`]). Private: an
/// implementation detail of how those two public methods share one
/// select/unlock/reselect sequence, not something a caller constructs
/// directly.
enum HidCrescendoXauthKeyOp<'a> {
    Set(MgmtAlg, &'a [u8]),
    Delete,
}

/// Everything about a [`PivSession`] that's expensive to resolve and safe to
/// carry to a *later* session on the same physical card: the resolved
/// applet identity, the applet-specific byte cache, and the in-session
/// public-key cache — plus, meaningful only on a copy a caller is holding
/// between sessions, the raw signals [`PivSession::with_cached_transaction`] diffs a
/// reconnect against to prove that later session really is still talking to
/// the same card before trusting any of the rest.
///
/// A fresh [`PivSession::with_transaction`]/[`PivSession::with_transaction_traced`] always
/// starts from [`Self::default`] and resolves everything from nothing —
/// there is still no on-disk or cross-process persistence.
/// [`PivSession::with_cached_transaction`] is the one constructor where a caller-held
/// copy of this (typically kept in process-lifetime UI state, one per
/// reader) can skip that resolution — and only after its own checks prove
/// the card hasn't changed since this copy was captured. A caller that
/// doesn't keep one around loses nothing beyond that shortcut: `with_transaction`/
/// `with_transaction_traced` behave exactly as before.
#[derive(Clone, Default)]
pub struct PivSessionState {
    /// The PC/SC-layer identity (reader name, card insertion/removal
    /// generation, ATR) this state was captured against — checked first and
    /// unconditionally by [`PivSession::with_cached_transaction`], before anything else:
    /// every other field here is only meaningful once this is confirmed
    /// unchanged. See `PcscIdentity` for what each of its three parts
    /// checks and why.
    pcsc_identity: PcscIdentity,
    /// Raw response body of the most recent SELECT (full or short AID) —
    /// the FCI a spec-compliant card returns since both builders request it
    /// via a case-4 `Le`. Feeds [`keyroost_piv::fingerprint::select_identity`]
    /// during fingerprint resolution. No longer part of
    /// [`PivSession::with_cached_transaction`]'s reuse decision — see `PcscIdentity`'s
    /// doc for why comparing it stopped earning its keep — so a value
    /// carried over from a cache hit is trusted as-is, unconfirmed against
    /// this connection's own card, until whatever real SELECT
    /// [`PivSession::ensure_selected`] eventually issues overwrites it (or a
    /// stale-cache miss resolves fresh immediately instead). Empty when
    /// SELECT never returned a body (a card that answers `9000` with
    /// nothing) or hasn't run yet this connection, never absent otherwise:
    /// fingerprint resolution treats empty and never-resolved the same way —
    /// a definite, comparable value.
    select_response: Vec<u8>,
    /// [`PivSession::applet_fingerprint`]'s cache: `None` until first
    /// resolved, then that method's full result — fingerprint, name,
    /// version, version/firmware bytes, serial. [`PivSession::identity`] is
    /// a thinner view over the same cached value. Safe to cache
    /// unconditionally — unlike `pubkey_cache`/`policy_cache`/`cert_cache`/
    /// `chuid_cache`/`pin_retries_cache` below, each of which needs its own
    /// write path to keep it honest as the underlying card state actually
    /// changes — because the applet's identity and reported versions cannot
    /// change while the physical card stays the same, which is exactly what
    /// [`PivSession::with_cached_transaction`]'s three checks exist to prove before this
    /// field is trusted across a reconnect at all. Resolving it from
    /// scratch can cost a handful of extra APDUs (some fingerprints need a
    /// live SELECT probe or a second applet's worth of round trips), so
    /// skipping that on a proven-unchanged reconnect is the entire point of
    /// this type.
    identity: Option<AppletFingerprintResult>,
    /// Algorithm + public key of any slot this lineage has resolved, keyed
    /// by key reference, from either of two provenances — see
    /// `PubkeyCache` for the full lifecycle and why they're not kept
    /// distinguishable once stored:
    ///
    /// * self-known: `generate_key` (the key it just minted) or
    ///   [`PivSession::remember_pubkey`] (a caller vouching for a value from
    ///   outside this session) — never verified against the card, so exactly
    ///   as trustworthy as whoever put it there;
    /// * device-reported: [`PivSession::resolve_slot_from_device`]'s GET
    ///   METADATA decode, feeding [`PivSession::cached_slot_key`] (the
    ///   cache-preferring reads `status_detailed`/`slot_key_algorithm`/
    ///   `slot_has_key` use) and [`PivSession::confirmed_slot_key`] (the
    ///   always-reconfirm-live read `slot_key` uses for `generate_csr`/
    ///   `self_signed_certificate`, which — unlike the display paths — must
    ///   not trust a possibly-stale cached value: it mints a certificate
    ///   whose declared public key needs to match what actually signs it).
    ///
    /// Cleared by [`PivSession::refresh`] (and so, transitively, by a fresh
    /// [`PivSession::with_transaction`]/[`with_transaction_traced`], both of which call it), and
    /// any operation that changes what's in a slot (`delete_key`,
    /// `move_key`, `reset`) invalidates the corresponding entries. Living in
    /// `PivSessionState` rather than a [`PivSession`] field of its own is
    /// what lets a caller hand this straight to [`PivSession::with_cached_transaction`]
    /// instead of re-seeding each slot one at a time via `remember_pubkey`
    /// after the fact.
    pubkey_cache: PubkeyCache,
    /// PIN/touch policy of any slot this lineage has resolved, keyed by key
    /// reference, from either a GET METADATA reply's own `policy` field
    /// ([`PivSession::resolve_slot_from_device`], sharing the one round trip
    /// `pubkey_cache` resolves from) or the ATTEST-certificate fallback for
    /// cards whose GET METADATA (supported or not) never reports one at all
    /// — see `PolicyCache` for the full lifecycle. [`PivSession::slot_policy`]
    /// is the sole writer, and always leaves this resolved one way or the
    /// other, so a card needing the ATTEST fallback doesn't pay for another
    /// APDU plus a certificate parse on every single `status_detailed` call.
    policy_cache: PolicyCache,
    /// DER certificates read from each slot's data object, keyed by key
    /// reference — see `CertCache`. A slot's certificate only changes on
    /// an explicit [`PivSession::import_certificate`]/
    /// [`PivSession::clear_certificate`] (or a `generate_key` that clears
    /// the old one first), all of which keep this cache in step, so a plain
    /// read is free to reuse it rather than paying a GET DATA round trip on
    /// every status read and every `slot_key_algorithm` certificate
    /// fallback.
    cert_cache: CertCache,
    /// The card's CHUID, once read this session (and, via `with_cached_transaction`, any
    /// later session on a proven-same card) — `None` until the first
    /// [`PivSession::read_chuid`] call, then that call's own result cached
    /// for the rest of the lineage. [`PivSession::new_chuid`] invalidates
    /// this back to `None` on a successful write, the same "evict, let the
    /// next read resolve it fresh" treatment as every other cache here gets
    /// on the operation that invalidates it — there's exactly one CHUID
    /// object, so a scalar `Option` is enough; no per-key-reference map like
    /// `cert_cache` needed.
    chuid_cache: Option<Option<keyroost_piv::Chuid>>,
    /// Remaining PIV application-PIN tries, resolved via a no-op VERIFY —
    /// see [`PivSession::pin_retries`]. `None` until first resolved this
    /// lineage; the inner `Option<u8>` mirrors that method's own return
    /// value (`None` there means "already verified" or "not reportable",
    /// not "unresolved" — this outer `Option` is what distinguishes the
    /// two). Invalidated by [`PivSession::verify_pin`],
    /// [`PivSession::change_pin`], [`PivSession::unblock_pin`], and
    /// [`PivSession::set_pin_retries`] — every operation that can move the
    /// counter, whether by consuming a try or resetting it — so a stale
    /// count never survives past the call that changed it. Deliberately
    /// *not* touched by [`PivSession::verify_pin_hid_crescendo_aca`], which
    /// authenticates a wholly different PIN reference (HID Crescendo's ACA
    /// instance, not the standard PIV application PIN this cache tracks).
    pin_retries_cache: Option<Option<u8>>,
    /// Applet-specific data resolved once and reused for the rest of a
    /// session's lineage — see [`AppletCache`]/[`AppletCacheKey`] for what's
    /// stored and why this is a dict keyed by enum rather than a dedicated
    /// field per value. Today's sole entry: [`PivSession::hid_crescendo_properties_raw`]'s
    /// cache (the raw response body of a HID Crescendo GET PIV PROPERTIES
    /// read — C2300 or C4000, both expose this over differently-framed
    /// requests but a compatible response structure — one read serves both
    /// the per-slot algorithm list, [`PivSession::hid_crescendo_slot_key_algorithms`],
    /// and this applet's own version, [`PivSession::hid_crescendo_version`]/
    /// [`PivSession::applet_fingerprint`]'s HID Crescendo branch, including
    /// once per slot [`PivSession::status_detailed`] asks about — so this
    /// exists purely to avoid re-issuing that read for each of those; a
    /// failed read caches as an empty `Vec`, same "resolved, with or without
    /// data" convention as `identity`. The CPLC serial
    /// `PivSession::probe_hid_crescendo_cplc_serial` reads doesn't need a
    /// second entry here: it's called directly from
    /// [`PivSession::applet_fingerprint`]'s `HidCrescendo` arms, so its
    /// result already rides along in the [`AppletFingerprintResult`]
    /// `identity` caches — storing it a second time here would just be the
    /// same value kept in two places.
    applet_cache: AppletCache,
}

impl PivSessionState {
    /// Algorithm + public key this state has cached for `slot`, if any — the
    /// same cache [`PivSession::slot_key`] consults internally, exposed so a
    /// caller holding a `PivSessionState` between sessions (e.g. to show a
    /// just-generated key's PEM again after reconnecting to the same card)
    /// doesn't need a live session just to read it back. Flattens away the
    /// "never asked" vs. "asked, confirmed empty" distinction the cache
    /// itself tracks (see `PubkeyCache`) — both look like "nothing to
    /// show" from here.
    pub fn cached_pubkey(&self, slot: Slot) -> Option<(KeyAlg, &PublicKey)> {
        self.pubkey_cache
            .get(slot.key_ref())
            .flatten()
            .map(|(alg, key)| (*alg, key))
    }
}

/// The PC/SC-layer identity [`PivSession::with_cached_transaction`] diffs a reconnect
/// against, *before* ever talking to the PIV applet: which reader, which
/// card-presence generation on that reader, and what ATR it answered with.
/// Grouped into one type because the three are always read and compared
/// together, in that order — a mismatch on an earlier field makes checking
/// a later one pointless. This is `with_cached_transaction`'s *entire* reuse check now —
/// a raw SELECT-response diff used to run alongside it, but comparing that
/// meant issuing a real SELECT PIV on every reconnect just to have something
/// to compare, which defeated the point of a cache hit skipping SELECT
/// entirely; it was dropped once its only genuine catch — cards from the
/// same production batch sharing an ATR byte-for-byte — was judged not
/// worth paying that cost on every reconnect for. That gap is real but
/// narrow (a same-model swap PC/SC's own event counter would also have
/// missed), and everything downstream still runs against whatever card
/// actually answers once [`PivSession::ensure_selected`] issues its lazy
/// SELECT.
#[derive(Clone, Default)]
struct PcscIdentity {
    /// The PC/SC reader name this identity was captured on. Checked first
    /// and unconditionally: `event_count`/`atr` are each only meaningful
    /// when compared against a *previous reading from that same reader* —
    /// nothing about them ties a [`PivSessionState`] to a reader on its own,
    /// since it's a plain, freely-movable value, and a caller's own
    /// key-value store might not key by reader name at all (`keyroost`'s
    /// GUI keys by device identity, which can outlive a reader-name change
    /// across a replug — e.g. when that identity resolves through an
    /// effective serial number rather than the reader string). Without this
    /// check, two different readers whose event counters happened to
    /// coincide (both untouched since `pcscd` started, for instance — an
    /// easy coincidence with small counts) would look "unchanged" against
    /// each other despite being unrelated hardware. Empty on a
    /// [`Self::default`] (never resolved), which a bare `String` comparison
    /// rejects as a mismatch against any real reader name, same as this
    /// type's other never-resolved fields (`event_count: None`, empty
    /// `atr`) fail their own checks by construction.
    reader_name: String,
    /// PC/SC's own per-reader card insertion/removal counter
    /// (`ReaderState::event_count` — the high word of `dwEventState`,
    /// incremented only by an actual insertion or removal, per that
    /// method's own doc), observed (via `Context::get_status_change`, no
    /// card connection needed) at the moment this identity was last
    /// confirmed current. Compared against a fresh reading on the next
    /// [`PivSession::with_cached_transaction`] call for the same reader: any difference
    /// means a card was inserted or removed on this reader since, however
    /// briefly — including a removal immediately followed by a reinsertion
    /// that settles back into an outwardly identical `PRESENT` state.
    ///
    /// Deliberately *not* the `SCARD_STATE_CHANGED` flag bit
    /// ([`State::CHANGED`]) this crate used here originally: that flag also
    /// trips on reader-state churn unrelated to the card itself —
    /// `SCARD_STATE_INUSE`/`EXCLUSIVE` toggling from *any* connection to
    /// this reader, including this app's own previous PIV session, or a
    /// completely different applet's session sharing the same physical
    /// multi-applet token — which made it read "changed" on essentially
    /// every call in practice, defeating the cache entirely. The event
    /// counter is the signal actually documented for "did the card
    /// change", and [`State`]'s own bitflags definition tops out well under
    /// `0x1_0000` (see [`ReaderState::event_state`]'s use of
    /// `from_bits_truncate`), so the counter — the *high* word — isn't
    /// even reachable through a stored [`State`] value; it has to be read
    /// via `event_count()` directly and kept as its own field.
    ///
    /// `None` before this identity has ever been through `with_cached_transaction` (a
    /// fresh [`Self::default`]) — treated there as "nothing to compare
    /// against", which just means this check can't vouch for reuse, same
    /// outcome as any other failed check.
    event_count: Option<u32>,
    /// ATR observed at that same moment. A third, independent corroborating
    /// check: even in the unexpected case a presence transition went
    /// unreported in `event_count`, a different ATR here still proves a
    /// different card. Not sufficient by itself the other way around — cards
    /// from the same production batch can share an ATR byte-for-byte — which
    /// is why every check here has to agree, not just this one.
    atr: Vec<u8>,
}

impl PcscIdentity {
    /// Whether `fresh` — a reading just taken, on the reader named by
    /// `fresh.reader_name` — proves the card `self` was captured from is
    /// still the one connected: every field must agree. See each field's
    /// own doc for why it's checked and what it catches; `event_count`'s
    /// comparison specifically goes through [`pcsc_event_count_unchanged`]
    /// rather than plain equality, since two never-resolved (`None`)
    /// counters must not read as "unchanged".
    fn matches(&self, fresh: &Self) -> bool {
        self.reader_name == fresh.reader_name
            && pcsc_event_count_unchanged(self.event_count, fresh.event_count)
            && self.atr == fresh.atr
    }
}

/// An open PIV applet session on one PC/SC reader — for exactly the
/// duration of one [`Self::with_transaction_traced`]/
/// [`Self::with_cached_transaction_traced`] call. `'tx` ties this session to
/// the single PC/SC transaction that call holds open around it: every APDU
/// this session issues, from the initial SELECT PIV through whatever the
/// caller's closure goes on to do, is exclusive-access-locked against every
/// other process (and every other thread's own session) on the same card.
/// A session can no longer outlive that one call — see
/// [`Self::with_transaction_traced`]'s doc for why that's the trade-off for
/// getting a transaction-scoped `card` field at all, `pcsc::Transaction`
/// being a borrow guard rather than an owned handle.
pub struct PivSession<'tx> {
    card: Transaction<'tx>,
    traced: bool,
    /// True when the reader negotiated T=0 with the card. T=0 cannot carry
    /// extended-length APDUs at all (ISO 7816-3 — the protocol has no way to
    /// frame them), so every large-payload command must be chained from the
    /// start on such links. Learned from the connection, never from the
    /// card's make: a T=0 contact card that receives an extended-length APDU
    /// may simply go silent (issue #103 — the reader reported "transaction
    /// failed" and the #101 status-word fallback never got a status word to
    /// act on), so waiting for a refusal is not a strategy there.
    t0: bool,
    /// Whether this *connection* has actually sent SELECT PIV yet — distinct
    /// from anything in [`PivSessionState`], which can carry a
    /// `select_response`/`identity` restored from a cache hit without this
    /// connection itself having sent the APDU that produced them. Starts
    /// `false` on every fresh [`Self::from_transaction`]; set only by the
    /// outcome of an actual [`Self::select`] call. `Self::ensure_selected`
    /// is the sole reader — every real PIV command reaches the card through
    /// [`Self::transmit_full`], which checks this first and issues the
    /// actual SELECT lazily, once, the first time it's `false`.
    applet_selected: bool,
    /// Everything about this session that's expensive to resolve and safe to
    /// carry to a later session on the same card — see [`PivSessionState`].
    /// [`Self::with_transaction`]/[`Self::with_transaction_traced`] always
    /// start this from [`PivSessionState::default`]; [`Self::with_cached_transaction`]
    /// is the one constructor that can seed it from a caller-held copy
    /// instead of resolving from scratch.
    state: PivSessionState,
}

/// The in-session key-material cache behind `PivSession`, keyed by PIV key
/// reference — the single per-slot source of "what's `slot`'s current
/// algorithm and public key", regardless of *how* that came to be known.
/// Two provenances feed it, deliberately without distinguishing between them
/// once stored, and a handful of transitions exist, each mirroring the card
/// operation that makes it true; the session methods are one-line callers so
/// the unit tests below can pin the semantics without a live card:
///
/// * a fresh cache starts empty (`Default` — deliberately no persistence),
/// * self-known: `generate_key` (the key it just minted, straight from the
///   GENERATE response) and `remember_pubkey` (a caller vouching for a value
///   from outside this session) both write `Some((alg, key))` — see
///   [`PivSession::remember_pubkey`]'s own doc for why that one is "not
///   verified against the card in any way",
/// * device-reported: [`PivSession::resolve_slot_from_device`] writes
///   whatever GET METADATA decoded — `Some((alg, key))` when it named both,
///   or `None` once a live read comes back with neither, so a confirmed-empty
///   slot doesn't cost another round trip on the next read. This is what
///   lets [`PivSession::cached_slot_key`]'s callers (`status_detailed`,
///   `slot_key_algorithm`, `slot_has_key`) skip the APDU on repeat calls —
///   including for a slot that's genuinely empty, the common case, not an
///   edge case: most standard and retired slots on any real device never
///   hold a key,
/// * neither provenance is preferred over the other once stored — whichever
///   wrote most recently wins, matching the two facts they establish (this
///   session made or was told this key; the device just confirmed something)
///   never being expected to disagree in the same lineage. The one place
///   that needs an *independent*, never-self-vouched channel
///   ([`PivSession::slot_key_status_algorithm`], backing
///   [`PivSession::reject_certificate_key_mismatch`]'s fallback check) never
///   reads this cache at all, by design — see that method's own doc,
/// * [`PivSession::slot_key`] (via [`PivSession::confirmed_slot_key`]) always
///   re-confirms live before trusting a cached value for `generate_csr`/
///   `self_signed_certificate` — a stale value there wouldn't just be an
///   outdated display, it would mint a certificate whose declared public key
///   doesn't match what actually signs it — but a device that answers
///   nothing new doesn't get to *erase* an existing entry: see
///   [`PivSession::confirmed_slot_key`]'s doc,
/// * `delete_key` leaves nothing to fall back to (`evict`),
/// * `move_key` relocates the key material, so its entry follows (`migrate`),
/// * `reset` wipes every slot — via `PivSessionState::default`, which drops
///   this whole cache along with everything else `refresh` rebuilds, not a
///   dedicated method here.
#[derive(Clone, Default)]
struct PubkeyCache(HashMap<u8, Option<(KeyAlg, PublicKey)>>);

impl PubkeyCache {
    /// The slot's key material is now known to be exactly `value` — a
    /// self-known write's `Some(_)`, or a device-reported resolution's
    /// verdict either way (`None` meaning "asked, card names neither
    /// algorithm nor public key for this slot"). Replaces any previous
    /// entry: after a regenerate, the old pubkey must not survive to
    /// describe the new private key.
    fn remember(&mut self, key_ref: u8, value: Option<(KeyAlg, PublicKey)>) {
        self.0.insert(key_ref, value);
    }

    /// The slot's key material is gone (`delete_key` succeeded): a stale
    /// entry here would produce a CSR/self-signed cert for a key that no
    /// longer exists. Evicting an uncached slot is a no-op. Distinct from
    /// `remember(key_ref, None)`: eviction means "we no longer know",
    /// forcing the next read to ask again; `remember(_, None)` means "we
    /// asked, and confirmed there's nothing here."
    fn evict(&mut self, key_ref: u8) {
        self.0.remove(&key_ref);
    }

    /// The key itself relocated (`move_key` succeeded), not just its
    /// reference — carry a cached entry along with it rather than dropping
    /// it, so a subsequent CSR/self-sign at `dest` still works on
    /// metadata-less firmware, and leave nothing behind at `src`. An uncached
    /// `src` carries nothing and, crucially, invents nothing at `dest`.
    fn migrate(&mut self, src: u8, dest: u8) {
        if let Some(cached) = self.0.remove(&src) {
            self.0.insert(dest, cached);
        }
    }

    /// `Some(_)` — with an inner `None` or `Some((alg, key))` — when `slot`
    /// has already been resolved this lineage, by either provenance; bare
    /// `None` means "never asked", the caller's cue to issue a real APDU.
    fn get(&self, key_ref: u8) -> Option<Option<&(KeyAlg, PublicKey)>> {
        self.0.get(&key_ref).map(Option::as_ref)
    }
}

/// The in-session PIN/touch-policy cache behind `PivSession`, keyed by PIV
/// key reference — the single per-slot source of "what's `slot`'s current
/// policy", from whichever channel resolves it: a GET METADATA reply's own
/// `policy` field (decoded by [`PivSession::resolve_slot_from_device`], the
/// same call `PubkeyCache` shares its one round trip with), or — only once
/// that channel has nothing to say — the ATTEST certificate's key-policy
/// extension. `Option<(PinPolicy, TouchPolicy)>` values, not a bare pair, so
/// "resolved: neither channel reports a policy for this slot" is itself a
/// cacheable fact, same reason `PubkeyCache`/`CertCache` use the same
/// shape: without it, a card whose GET METADATA never carries policy at all
/// (pre-5.3 firmware, non-Yubico PIV) would re-pay for a full ATTEST APDU
/// plus a certificate parse on every single `status_detailed`/`slot_policy`
/// call, forever.
///
/// * a fresh cache starts empty (`Default`),
/// * `generate_key` does *not* seed this from its own `pin_policy`/
///   `touch_policy` arguments — a request, not a result: the card is free to
///   translate or normalize what was asked for — it calls `slot_policy`
///   afterward instead, which resolves (and caches) the policy the card
///   actually ended up applying,
/// * [`PivSession::slot_policy`] is this cache's sole writer: directly from
///   [`PivSession::resolve_slot_from_device`]'s decode when the reply
///   carries a policy, or from a successful (or exhausted) ATTEST fallback
///   otherwise — either way, every call through `slot_policy` leaves this
///   cache resolved one way or another, so the *next* slot read never pays
///   for either APDU again,
/// * `delete_key` leaves nothing to fall back to (`evict`),
/// * `move_key` relocates the key material, so its entry follows (`migrate`),
/// * `reset` wipes every slot — via `PivSessionState::default`, same as
///   `PubkeyCache`, not a dedicated method here.
#[derive(Clone, Default)]
struct PolicyCache(HashMap<u8, Option<(PinPolicy, TouchPolicy)>>);

impl PolicyCache {
    /// The slot's policy is now known to be exactly `value` (`None` meaning
    /// "resolved: neither GET METADATA nor ATTEST names one"). Replaces any
    /// previous entry: after a regenerate, a stale policy must not survive
    /// to describe the new key.
    fn remember(&mut self, key_ref: u8, value: Option<(PinPolicy, TouchPolicy)>) {
        self.0.insert(key_ref, value);
    }

    /// The slot's key material is gone (`delete_key` succeeded): a stale
    /// entry here would misreport the (now nonexistent) key's policy.
    /// Evicting an uncached slot is a no-op.
    fn evict(&mut self, key_ref: u8) {
        self.0.remove(&key_ref);
    }

    /// The key itself relocated (`move_key` succeeded) — its policy travels
    /// with it, same as [`PubkeyCache::migrate`]. An uncached `src` carries
    /// nothing and invents nothing at `dest`.
    fn migrate(&mut self, src: u8, dest: u8) {
        if let Some(cached) = self.0.remove(&src) {
            self.0.insert(dest, cached);
        }
    }

    /// `Some(_)` — with an inner `None` or `Some((pin, touch))` — when
    /// `slot`'s policy has already been resolved this lineage; bare `None`
    /// means "never asked", the caller's cue to resolve it for real.
    fn get(&self, key_ref: u8) -> Option<Option<(PinPolicy, TouchPolicy)>> {
        self.0.get(&key_ref).copied()
    }
}

/// The in-session certificate cache behind [`PivSession::cert_object`],
/// keyed by PIV key reference — same shape as `PubkeyCache`, for the
/// same reason: a slot's certificate object only changes via an explicit
/// write this crate already intercepts.
///
/// * a fresh cache starts empty (`Default`),
/// * [`PivSession::cert_object`] is the sole writer on a plain read
///   (`remember`, `Ok(None)` meaning "asked, slot has no certificate
///   object"; `Err(reason)` meaning "asked, slot holds a certificate that
///   can't be read" — see [`CertUnreadable`]),
/// * [`PivSession::import_certificate`] remembers the exact DER it just
///   wrote, for free — no need to read it back,
/// * [`PivSession::clear_certificate`] remembers `Ok(None)` — again for free,
/// * `move_key`/`delete_key` leave this cache alone: neither operation
///   touches a slot's certificate object (a private key relocating or
///   disappearing says nothing about what's stored on top of it),
/// * `reset` wipes every slot — via [`PivSessionState::default`], same as
///   every other cache here, not a dedicated method here.
#[derive(Clone, Default)]
struct CertCache(HashMap<u8, Result<Option<Vec<u8>>, CertUnreadable>>);

impl CertCache {
    /// `slot`'s certificate object is now known to resolve to exactly `cert`
    /// (`Ok(None)` meaning "asked (or just cleared), slot has no
    /// certificate"; `Err(reason)` meaning "asked, slot's certificate can't
    /// be read").
    fn remember(&mut self, key_ref: u8, cert: Result<Option<Vec<u8>>, CertUnreadable>) {
        self.0.insert(key_ref, cert);
    }

    /// `Some(_)` when `slot`'s certificate has already been resolved this
    /// lineage; bare `None` means "never asked", the caller's cue to issue a
    /// real APDU.
    fn get(&self, key_ref: u8) -> Option<Result<Option<Vec<u8>>, CertUnreadable>> {
        self.0.get(&key_ref).cloned()
    }
}

/// Key into [`AppletCache`] — one per applet-specific value `PivSession`
/// resolves once and reuses for the rest of a session. Add a variant here
/// instead of a new dedicated `PivSession` field the next time some applet
/// needs this same "resolve once, reuse for the rest of the session"
/// treatment — see [`PivSession::applet_cache`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum AppletCacheKey {
    /// [`PivSession::hid_crescendo_properties_raw`]'s cache.
    HidCrescendoPropertiesRaw,
}

/// Session-lifetime cache for applet-specific byte blobs that don't fit
/// `PivSession`'s other dedicated caches (`PubkeyCache`, `identity`) — see
/// [`AppletCacheKey`] for what's stored today. A dict keyed by enum rather
/// than one `Option<Vec<u8>>` `PivSession` field per value: today's sole
/// entry happens to be HID Crescendo-specific, but nothing here is — the
/// next applet-specific quirk that needs a "resolve once, reuse for the rest
/// of the session" slot gets a new [`AppletCacheKey`] variant, not a new
/// struct field. A value that isn't a byte blob (see
/// `PivSession::probe_hid_crescendo_cplc_serial`'s doc for why a serial
/// doesn't belong here) has nowhere to fit until one actually needs this
/// treatment — no speculative value-type abstraction ahead of that.
#[derive(Clone, Default)]
struct AppletCache(HashMap<AppletCacheKey, Vec<u8>>);

impl AppletCache {
    /// `key`'s cached bytes, if resolved. `None` means only "never
    /// resolved" — a caller that caches a failed read as an empty `Vec`
    /// (see [`PivSession::hid_crescendo_properties_raw`]) gets `Some(&[])`
    /// back, distinguishable from `None`.
    fn bytes(&self, key: AppletCacheKey) -> Option<&[u8]> {
        self.0.get(&key).map(Vec::as_slice)
    }

    fn set_bytes(&mut self, key: AppletCacheKey, value: Vec<u8>) {
        self.0.insert(key, value);
    }
}

/// The management-key algorithms whose key is exactly `key_len` bytes, 3DES
/// first. Empty when no algorithm uses that length.
///
/// [`PivSession::resolve_management_key_algorithm`] uses this as its fallback
/// when GET METADATA is absent *and* the card accepts no GENERAL AUTHENTICATE
/// probe — i.e. when only the key length is left to go on. Only 24 bytes is
/// ambiguous (3DES and AES-192 share it); 3DES leads because it was the sole
/// pre-metadata option. 16 → AES-128 and 32 → AES-256 are unique; 8
/// (single-DES) and everything else map to nothing.
fn mgmt_algs_for_key_len(key_len: usize) -> &'static [MgmtAlg] {
    match key_len {
        16 => &[MgmtAlg::Aes128],
        24 => &[MgmtAlg::TripleDes, MgmtAlg::Aes192],
        32 => &[MgmtAlg::Aes256],
        _ => &[],
    }
}

/// Pick the management-key algorithm to authenticate with from the set the
/// card accepted a GENERAL AUTHENTICATE witness request for (`accepted`), given
/// the length of the key in hand. `None` when nothing fits `key_len`.
///
/// * `accepted` empty → the probe told us nothing; fall back to the
///   length-only table ([`mgmt_algs_for_key_len`]).
/// * otherwise keep only accepted algorithms whose key is `key_len` bytes.
/// * if that still leaves more than one — which can only be 3DES + AES-192,
///   the sole length collision (both 24 bytes) — prefer 3DES, the historical
///   pre-GET-METADATA default.
fn pick_mgmt_alg(accepted: &[MgmtAlg], key_len: usize) -> Option<MgmtAlg> {
    let by_len: Vec<MgmtAlg> = if accepted.is_empty() {
        mgmt_algs_for_key_len(key_len).to_vec()
    } else {
        accepted
            .iter()
            .copied()
            .filter(|a| a.key_len() == key_len)
            .collect()
    };
    if by_len.contains(&MgmtAlg::TripleDes) {
        return Some(MgmtAlg::TripleDes);
    }
    by_len.first().copied()
}

/// A fresh, random 16-byte CHUID GUID — host-side only, no card I/O. For
/// pre-filling (and, via a "refresh" action, regenerating) a "New CHUID"
/// GUID input before [`PivSession::new_chuid`] writes whatever the user
/// settled on — their own manual value included — to the card.
pub fn random_chuid_guid() -> Result<[u8; 16], TransportError> {
    let mut guid = [0u8; 16];
    getrandom::getrandom(&mut guid).map_err(|_| TransportError::HostRngFailed)?;
    Ok(guid)
}

/// A fresh, random management key sized for `alg` — host-side only, no card
/// I/O. For a "Generate Random & Copy" action in the "Change management key"
/// flow; the caller still has to write it via
/// [`PivSession::set_management_key`] (or
/// [`PivSession::set_management_key_pin_protected`]) like any other new key
/// the user typed by hand. Wipe-on-drop like every other key-bearing buffer
/// in this crate.
pub fn random_management_key(alg: MgmtAlg) -> Result<zeroize::Zeroizing<Vec<u8>>, TransportError> {
    let mut key = zeroize::Zeroizing::new(vec![0u8; alg.key_len()]);
    getrandom::getrandom(&mut key).map_err(|_| TransportError::HostRngFailed)?;
    Ok(key)
}

/// Run [`crate::decode_bcd_serial`] over `serial`, but only when
/// [`keyroost_piv::compat::resolve_quirks`] finds
/// [`keyroost_piv::compat::PivQuirk::InsF8SerialIsBcd`] active for
/// `fingerprint` at `applet_version`/`firmware_version` — Token2 is the only
/// device seeded with that quirk so far; others may be discovered and added
/// to `keyroost_piv::compat`'s quirk tables later. Every other vendor's
/// serial is a plain integer already, and BCD-decoding one would corrupt it.
/// Shared by [`PivSession::status`] and [`PivSession::status_detailed`].
fn decode_serial_if_bcd(
    fingerprint: keyroost_piv::fingerprint::AppletFingerprint,
    applet_version: Option<&[u8]>,
    firmware_version: Option<&[u8]>,
    serial: Option<u128>,
) -> Option<u128> {
    let reports_bcd_serial =
        keyroost_piv::compat::resolve_quirks(fingerprint, applet_version, firmware_version)
            .contains(&keyroost_piv::compat::PivQuirk::InsF8SerialIsBcd);
    if reports_bcd_serial {
        serial.map(crate::decode_bcd_serial)
    } else {
        serial
    }
}

/// Strip `md`'s algorithm identifier (tag `0x01`) and public key (tag `0x04`)
/// when `quirks` contains
/// [`keyroost_piv::compat::PivQuirk::InsF7MetadataAlgorithmInvalid`] — on an
/// applet with that quirk, GET METADATA's algorithm byte has been observed
/// stuck and never reflecting the slot's actual key state, and the public key
/// goes with it: a raw key blob is meaningless without a trustworthy
/// algorithm to interpret it against (RSA vs. EC changes how those bytes are
/// structured, e.g. in `metadata_key_material`). Separately, strip `md`'s
/// PIN/touch policy (tag `0x02`) when `quirks` contains
/// [`keyroost_piv::compat::PivQuirk::InsF7MetadataPinTouchPolicyInvalid`] — same
/// "always ignore, never trust a lucky-looking value" treatment, kept as its
/// own `if` because the two quirks have been observed to apply independently
/// (see that quirk's own doc). Every other field (`origin`, `is_default`,
/// `retries`) is untouched by either quirk — each is specific to the tags
/// named above. [`PivSession::metadata`] is the sole caller; split out as a
/// pure function, same seam style as [`decode_serial_if_bcd`], so the
/// stripping rules are unit-testable without a card.
fn clear_metadata_if_quirky(
    quirks: &BTreeSet<keyroost_piv::compat::PivQuirk>,
    mut md: Metadata,
) -> Metadata {
    if quirks.contains(&keyroost_piv::compat::PivQuirk::InsF7MetadataAlgorithmInvalid) {
        md.algorithm = None;
        md.public_key = None;
    }
    if quirks.contains(&keyroost_piv::compat::PivQuirk::InsF7MetadataPinTouchPolicyInvalid) {
        md.policy = None;
    }
    md
}

/// Whether a fresh PC/SC reading, `event_count` and all, is even usable —
/// `false` when the query outright failed (`state` is `None`) or the reader
/// itself is reporting a state this crate has no business trusting
/// (`UNKNOWN`/`UNAVAILABLE`/`MUTE`), regardless of what the event counter
/// says. Split out as a pure function over [`State`] so this rule is
/// testable without hardware.
fn pcsc_reading_usable(state: Option<State>) -> bool {
    matches!(
        state,
        Some(st) if !st.intersects(State::UNKNOWN | State::UNAVAILABLE | State::MUTE)
    )
}

/// Whether PC/SC's per-reader insertion/removal counter proves no card
/// change happened between `cached` (what [`PcscIdentity::event_count`]
/// held) and `fresh` (a reading just taken): both present and numerically
/// equal. `None` on either side — never resolved before, or this reading's
/// query failed — can't prove anything, so it doesn't count as unchanged.
/// See `PcscIdentity::matches` for the rule this feeds into, and
/// [`PcscIdentity::event_count`]'s doc for why the counter, not the
/// `CHANGED` flag bit, is what's compared here.
fn pcsc_event_count_unchanged(cached: Option<u32>, fresh: Option<u32>) -> bool {
    matches!((cached, fresh), (Some(c), Some(f)) if c == f)
}

/// [`PivSession::with_cached_transaction`]'s reuse decision as a pure function: both of
/// its independent checks must agree, or the cache is not trusted —
/// `pcsc_trustworthy` (is this fresh PC/SC reading even usable, via
/// [`pcsc_reading_usable`]) and `pcsc_identity_matches` (reader name, event
/// counter, and ATR all agree, via `PcscIdentity::matches`). Kept separate
/// from those so the *combining* rule (currently a flat AND, but the one
/// place that could change if a future check needed different weighting) is
/// pinned by a test independent of how each individual check is computed. A
/// raw SELECT-response diff used to be a third input here — see
/// `PcscIdentity`'s doc for why it was dropped.
fn piv_session_cache_reusable(pcsc_trustworthy: bool, pcsc_identity_matches: bool) -> bool {
    pcsc_trustworthy && pcsc_identity_matches
}

impl<'tx> PivSession<'tx> {
    /// Connect to `reader_name`, SELECT the PIV application, and run `f` —
    /// the entire session — with every APDU it issues, from that initial
    /// SELECT through whatever `f` goes on to do, wrapped in one PC/SC
    /// transaction. Returns [`TransportError::NoPivApplet`] when the card has
    /// no PIV applet. Equivalent to [`Self::with_transaction_traced`]`(reader_name,
    /// false, f)` — see that constructor's doc for why a caller that wants
    /// `--debug`-style tracing of *this very SELECT* has to ask for it here,
    /// up front, rather than via [`Self::set_traced`] inside `f`, and for why
    /// a session can no longer outlive this one call.
    ///
    /// `f`'s error type `E` only needs [`From<TransportError>`] — not to be
    /// `TransportError` itself — so a caller whose own error type already
    /// covers other failures (a CLI command's `Box<dyn std::error::Error>`,
    /// say) can freely mix `?` on session methods with `?` on anything else
    /// inside `f`, exactly as it could before this session lived inside a
    /// closure.
    pub fn with_transaction<R, E: From<TransportError>>(
        reader_name: &str,
        f: impl FnOnce(&mut PivSession<'_>) -> Result<R, E>,
    ) -> Result<R, E> {
        Self::with_transaction_traced(reader_name, false, f)
    }

    /// [`Self::with_transaction`], but with per-APDU stderr tracing already
    /// enabled for the initial SELECT this constructor itself issues.
    /// `with_transaction` followed by [`Self::set_traced`] inside `f` — the
    /// only other way to turn tracing on — is always one APDU too late for
    /// that: the SELECT has already happened by the time `f` runs, so it
    /// silently never appears in a `--debug` trace. Front ends that know
    /// their debug flag before opening (which is all of them — it comes from
    /// a CLI flag or a GUI setting, not from anything the card says) should
    /// call this instead of `with_transaction` plus a `set_traced` inside `f`.
    ///
    /// A session can no longer outlive a single call the way it once could:
    /// `pcsc::Transaction` is a borrow guard over `&mut Card`, not an owned
    /// handle, so the only way for a `PivSession` to hold one for its entire
    /// life is for that life to be exactly the span of one function call —
    /// this one. The `Card` itself, and the [`Transaction`] begun on it, live
    /// here as locals; `session` only ever borrows the transaction, and `f`
    /// only ever borrows `session`. The transaction begins right after
    /// connecting, before the first APDU (SELECT included), and is
    /// guaranteed to end before this function returns — successfully,
    /// erroring out of `f`, or unwinding through it — because
    /// [`pcsc::Transaction`]'s own `Drop` issues `SCardEndTransaction`
    /// unconditionally when `session` goes out of scope, which happens no
    /// matter how `f` exits. That closes the gap the old
    /// open-then-drop-whenever-the-caller-feels-like-it shape left open:
    /// another process (or another thread's own Molto2/OATH/PIV session)
    /// could otherwise interleave a command between two of this session's
    /// own APDUs.
    pub fn with_transaction_traced<R, E: From<TransportError>>(
        reader_name: &str,
        traced: bool,
        f: impl FnOnce(&mut PivSession<'_>) -> Result<R, E>,
    ) -> Result<R, E> {
        let ctx = Context::establish(Scope::User).map_err(TransportError::PcscUnavailable)?;
        let cstr = std::ffi::CString::new(reader_name)
            .map_err(|_| TransportError::MalformedResponse("reader name contained NUL"))?;
        let mut card = ctx
            .connect(&cstr, ShareMode::Shared, Protocols::ANY)
            .map_err(TransportError::from)?;
        let txn = card.transaction().map_err(TransportError::from)?;
        let mut session = Self::from_transaction(txn, reader_name, traced);
        session.select()?;
        session.fingerprint();
        f(&mut session)
    }

    /// Build a fresh, unselected [`PivSession`] around `txn` — an
    /// already-begun transaction on an already-connected card — starting
    /// from a wholly fresh [`PivSessionState`] except for
    /// `state.pcsc_identity.reader_name`, seeded with `reader_name` right
    /// away so it's correct even if a caller never goes on to populate the
    /// rest (see [`PcscIdentity::reader_name`]'s doc for why it's checked
    /// ahead of everything else). The shared second half of
    /// [`Self::with_transaction_traced`] and
    /// [`Self::with_cached_transaction_traced`], both of which begin the
    /// transaction themselves — before this runs, so it covers the SELECT
    /// too — and connect the card that backs it.
    ///
    /// Deliberately does *not* SELECT PIV — that decision belongs to each
    /// caller: [`Self::with_transaction_traced`] always wants a fresh
    /// identity, so it selects and fingerprints right after this returns; a
    /// plain `let mut session = Self::from_transaction(...);` at the top of
    /// [`Self::with_cached_transaction_traced`] does the same. That one,
    /// though, only when its own cheap PC/SC-layer check doesn't pan out —
    /// otherwise it leaves SELECT for `Self::ensure_selected` to issue
    /// lazily, on whatever real PIV command actually needs it first (still
    /// inside the very same transaction — that guard was already begun
    /// before this call, regardless of which path the caller takes next).
    /// `applet_selected` starts `false` here regardless, too — it's set only
    /// by an actual, successful [`Self::select`] call.
    fn from_transaction<'a>(
        txn: Transaction<'a>,
        reader_name: &str,
        traced: bool,
    ) -> PivSession<'a> {
        let t0 = negotiated_t0(&txn);
        PivSession {
            card: txn,
            traced,
            t0,
            applet_selected: false,
            state: PivSessionState {
                pcsc_identity: PcscIdentity {
                    reader_name: reader_name.to_owned(),
                    ..Default::default()
                },
                ..Default::default()
            },
        }
    }

    /// [`Self::with_transaction`], but first try to reuse `cached` — a
    /// [`PivSessionState`] a caller is holding from an earlier session on
    /// the same reader — instead of resolving the applet identity from
    /// scratch. Equivalent to [`Self::with_cached_transaction_traced`]`(reader_name,
    /// cached, false, f)` — see that constructor's doc for the full
    /// validation story and [`Self::with_transaction_traced`]'s doc for why
    /// `--debug` tracing has to be requested here rather than via
    /// [`Self::set_traced`] inside `f`.
    pub fn with_cached_transaction<R, E: From<TransportError>>(
        reader_name: &str,
        cached: PivSessionState,
        f: impl FnOnce(&mut PivSession<'_>) -> Result<R, E>,
    ) -> Result<R, E> {
        Self::with_cached_transaction_traced(reader_name, cached, false, f)
    }

    /// This session's current [`PivSessionState`] — everything cached or
    /// resolved so far (identity, applet cache, public-key cache) plus
    /// whatever validity anchors [`Self::with_cached_transaction`] last
    /// recorded (unset on a session opened via the plain
    /// [`Self::with_transaction`]/[`Self::with_transaction_traced`], which
    /// never populates them). A caller that wants a later session on this
    /// same reader to be able to skip re-resolving identity should read this
    /// from inside `f`, before it returns, and hand it to
    /// `with_cached_transaction` next time.
    pub fn state(&self) -> PivSessionState {
        self.state.clone()
    }

    /// Whether this session has actually sent SELECT PIV to the card yet —
    /// the public face of `applet_selected`. `false` means every accessor
    /// called on this session so far ([`Self::status_detailed`]/
    /// [`Self::status`] included) was answered entirely out of the state
    /// [`Self::with_cached_transaction`] carried in, with no live APDU
    /// exchanged; a caller that wants to tell a genuine card read apart from
    /// a fully cache-served one (for logging, say) reads this right after
    /// making its calls, before anything later might trigger the lazy SELECT
    /// `Self::ensure_selected` issues. Once true, it stays true for the
    /// life of the session — there's no way to "un-select" PIV, so a caller
    /// checking this after a mixed session (some fields cached, one not)
    /// correctly sees a real read happened, not a cache hit.
    pub fn touched_card(&self) -> bool {
        self.applet_selected
    }

    /// [`Self::with_cached_transaction`], but with per-APDU stderr tracing
    /// already enabled for whatever APDUs this call and the session it hands
    /// to `f` go on to issue.
    ///
    /// One cheap check gates reuse of `cached`, proxying "is this reconnect
    /// still talking to the same physical card, on the same reader, that
    /// `cached` was captured from": **PC/SC-layer identity** — reader name,
    /// insertion/removal counter, and ATR, via `PcscIdentity::matches` on
    /// `cached.pcsc_identity` against a fresh reading
    /// (`Context::get_status_change` with zero timeout for the first two —
    /// no APDU, no connection — plus this call's own connect for the ATR).
    /// See that type's own doc for what each of its three parts catches, why
    /// the reader name is checked ahead of the other two, and why a second
    /// check — diffing the raw SELECT response — used to run alongside this
    /// one and no longer does: that comparison forced a real SELECT PIV on
    /// every single reconnect just to have something to diff, which defeated
    /// the entire point of a cache hit being allowed to skip SELECT.
    ///
    /// A stale check falls back to exactly the same resolution
    /// [`Self::with_transaction_traced`] always does — SELECT, then
    /// fingerprint, right here, immediately — so a caller can always reach
    /// for this instead of `with_transaction`, with no downside beyond the
    /// (cheap) validation check when the cache turns out to be stale, and no
    /// risk of ever trusting a different card's identity because the reader
    /// name happened to match.
    ///
    /// A check that *does* pass skips SELECT entirely for now: `cached` —
    /// its `select_response`/`identity`/every other read cache — is trusted
    /// as-is, unconfirmed against this connection's own card, and the real
    /// SELECT PIV this session eventually needs is left for
    /// `Self::ensure_selected` to issue lazily, immediately before
    /// whatever the first genuine PIV command this session runs turns out to
    /// be. A caller whose `f` only reads already-cached state (or does
    /// nothing at all with the session) never pays for that SELECT.
    ///
    /// Runs `f` against the opened session, same as
    /// [`Self::with_transaction_traced`] — its [`Self::state`] is `cached`
    /// unchanged (validation anchors refreshed to this connection's own
    /// readings) when reused, or a freshly resolved one when it wasn't. A
    /// caller that wants to keep caching across sessions should read
    /// `state()` from inside `f`, right before `f` returns — after whatever
    /// authenticate/write/status calls it went on to make, since those
    /// mutate `state` further (e.g. `generate_key`'s own `pubkey_cache`
    /// update), so the state worth keeping is whatever the session ends
    /// with, not the snapshot from the moment it opened — and store that
    /// back over whatever it held before, so the *next*
    /// `with_cached_transaction` call has an up-to-date anchor to diff
    /// against either way — even on this same, unchanged card, letting
    /// `cached` go stale here would just mean the next call re-validates
    /// from an older baseline than it needs to.
    pub fn with_cached_transaction_traced<R, E: From<TransportError>>(
        reader_name: &str,
        cached: PivSessionState,
        traced: bool,
        f: impl FnOnce(&mut PivSession<'_>) -> Result<R, E>,
    ) -> Result<R, E> {
        let ctx = Context::establish(Scope::User).map_err(TransportError::PcscUnavailable)?;
        let cstr = std::ffi::CString::new(reader_name)
            .map_err(|_| TransportError::MalformedResponse("reader name contained NUL"))?;

        // Card-free. The input baseline here doesn't matter for what's
        // actually compared (the event counter, read unconditionally below)
        // — `State::UNAWARE` just asks for "current state, no diffing",
        // which a zero timeout returns immediately either way.
        let mut states = [ReaderState::new(cstr.clone(), State::UNAWARE)];
        let (fresh_state, fresh_event_count) =
            match ctx.get_status_change(std::time::Duration::ZERO, &mut states) {
                Ok(()) | Err(PcscError::Timeout) => {
                    (Some(states[0].event_state()), Some(states[0].event_count()))
                }
                // Can't ask PC/SC at all (service hiccup, reader mid-teardown) —
                // the connect just below surfaces the real error if the reader
                // is genuinely gone; here, just don't trust the cache.
                Err(_) => (None, None),
            };
        let pcsc_trustworthy = pcsc_reading_usable(fresh_state);

        // The ATR needs a live connection either way, so make one regardless
        // of what the card-free check found, and begin the transaction on it
        // immediately — before either branch below sends anything, SELECT
        // included, so the transaction genuinely covers the whole session
        // regardless of which branch runs.
        let mut card = ctx
            .connect(&cstr, ShareMode::Shared, Protocols::ANY)
            .map_err(TransportError::from)?;
        let txn = card.transaction().map_err(TransportError::from)?;
        let mut session = Self::from_transaction(txn, reader_name, traced);
        let fresh_identity = PcscIdentity {
            reader_name: reader_name.to_owned(),
            event_count: fresh_event_count,
            atr: session.atr(),
        };

        if piv_session_cache_reusable(
            pcsc_trustworthy,
            cached.pcsc_identity.matches(&fresh_identity),
        ) {
            session.state = cached;
        } else {
            session.select()?;
            session.fingerprint();
        }
        // Whichever branch ran, this connect's own readings are the
        // freshest anchor available for the *next* `with_cached_transaction`
        // call on this reader — store them regardless of whether this call
        // reused `cached` or resolved fresh.
        session.state.pcsc_identity = fresh_identity;

        f(&mut session)
    }

    /// Rebuild every piece of in-session state this session caches or
    /// resolves from the card, from nothing — the same "start over"
    /// sequence [`Self::with_transaction_traced`] itself runs to build a
    /// session in the first place, just replayed on the existing PC/SC
    /// connection and transaction (`card`/`t0`/`traced` are per-connection,
    /// not per-selected-applet state, so they're untouched here) rather than
    /// reconnecting. This is exactly what every front end's "Refresh" action
    /// already does today by discarding its whole [`PivSession`] and calling
    /// [`Self::with_transaction`]/[`Self::with_transaction_traced`] again (see
    /// e.g. `keyroost`'s `App::load_piv_status`) — this method is that same
    /// rebuild, available to run in place on a session a caller is already
    /// holding.
    ///
    /// Replaces [`Self::state`](`PivSessionState`) with a fresh
    /// [`PivSessionState::default`] — dropping `pubkey_cache`,
    /// `select_response`, `identity`, `applet_cache`, every other read cache
    /// (`policy_cache`, `cert_cache`, `chuid_cache`, `pin_retries_cache`),
    /// and the `PcscIdentity` validation anchor (`pcsc_identity`) all at
    /// once — then re-`SELECT`s PIV and resolves the
    /// fingerprint fresh (via `Self::fingerprint`, caching it in
    /// `state.identity` the same as any
    /// other first resolution): genuinely starting over, the applet's
    /// identity included, rather than carrying forward what an earlier
    /// resolution in this same session found, or what a caller-supplied
    /// [`PivSessionState`] held. Also drops any management-key
    /// authentication in force, same as a bare re-`select()` always has —
    /// this rebuilds, it doesn't preserve.
    ///
    /// Leaving `pcsc_identity` at its reset-away default (rather than, say,
    /// re-querying it here to seed a fully-populated state) costs nothing
    /// beyond a guaranteed cache miss on whichever `with_cached_transaction`
    /// call is the very next one to see a [`PivSessionState`] extracted from
    /// this session: that call always records a fresh reading itself
    /// regardless of what it found (see its doc), so the miss is a one-time
    /// thing, not a standing inefficiency.
    ///
    /// That one resolution already covers a `HidCrescendo` fingerprint's own
    /// serial: `Self::applet_fingerprint`'s `HidCrescendo` arms call
    /// `Self::probe_hid_crescendo_cplc_serial` themselves, exactly the way
    /// the Nitrokey arm calls `Self::probe_nitrokey_admin`, so there's no
    /// separate decision to make here — every other fingerprint's serial
    /// comes from Yubico's own GET SERIAL extension instead (see
    /// [`Self::status`]).
    ///
    /// [`Self::reset`] calls this directly so a caller that keeps reading
    /// from the very session it just reset sees the same fully-rebuilt state
    /// a reopen would have given it, without actually reopening.
    pub fn refresh(&mut self) -> Result<(), TransportError> {
        self.state = PivSessionState::default();

        self.select()?;
        self.fingerprint();
        Ok(())
    }

    /// Enable per-APDU stderr tracing. Only affects APDUs sent *after* this
    /// call — [`Self::with_transaction_traced`] is the way to also trace the
    /// initial SELECT [`Self::with_transaction`]/that constructor issues
    /// before `f` ever runs.
    pub fn set_traced(&mut self, on: bool) {
        self.traced = on;
    }

    /// Read a HID Crescendo unit's on-card printed serial number via
    /// GlobalPlatform CPLC
    /// ([`keyroost_piv::fingerprint::GLOBAL_PLATFORM_ISD_AID`]/
    /// [`keyroost_piv::fingerprint::GLOBAL_PLATFORM_GET_CPLC`]) — called
    /// directly from `Self::applet_fingerprint`'s `HidCrescendo` arms, once
    /// classification already says this session's applet is one, so this
    /// never runs blind against a device with no reason to answer it. Its
    /// result becomes part of the [`AppletFingerprintResult`] that
    /// `applet_fingerprint` caches in `identity`, the same "resolve once,
    /// reuse for the session" treatment as every other field there — no
    /// separate cache slot of its own.
    ///
    /// Same self-contained shape as every other mid-session identification
    /// probe in this file (Feitian, Swissbit, IdPrime, Nitrokey's admin
    /// app — see e.g. [`Self::probe_feitian_rid`]/`Self::probe_nitrokey_admin`):
    /// SELECTs a second applet, reads what it needs, then unconditionally
    /// re-SELECTs PIV before returning, so the caller gets the session back
    /// exactly as any caller of [`Self::status`]/[`Self::status_detailed`]
    /// expects. Safe to call this deep into `applet_fingerprint`'s own
    /// resolution — after PIV is already selected, possibly after other
    /// fingerprint probes ran — because nothing in that resolution
    /// authenticates the management key first; there is no authenticated
    /// state left here for switching applets to silently undo.
    ///
    /// `None` when the Issuer Security Domain doesn't SELECT (`SW != 9000` —
    /// possible even on a confirmed HID Crescendo unit if its ISD AID
    /// differs), when GET DATA CPLC is refused, or when
    /// [`keyroost_piv::fingerprint::parse_cplc_serial`] can't make sense of
    /// the reply.
    fn probe_hid_crescendo_cplc_serial(&mut self) -> Option<u128> {
        use keyroost_piv::fingerprint;

        let selected = matches!(
            self.transmit_full_raw(&piv::select_by_aid(&fingerprint::GLOBAL_PLATFORM_ISD_AID)),
            Ok((_, sw)) if sw == piv::SW_OK
        );
        let serial = if selected {
            self.transmit_full_raw(&fingerprint::GLOBAL_PLATFORM_GET_CPLC)
                .ok()
                .filter(|(_, sw)| *sw == piv::SW_OK)
                .and_then(|(data, _)| fingerprint::parse_cplc_serial(&data))
        } else {
            None
        };
        // Restore PIV as the selected applet before returning — see this
        // method's doc for why that's always required now, unlike when this
        // ran before PIV was ever selected in the first place.
        let _ = self.select();
        serial
    }

    /// Read a Token2 or Thetis unit's full serial via the on-device OTP applet
    /// (`keyroost_token2otp::OTP_APPLET_AID`) — SELECTs it, issues its
    /// `GET_INFO` serial request (`keyroost_token2otp::read_serial_request`),
    /// then decodes the reply via
    /// [`keyroost_token2otp::parse_otp_serial`]. Unlike the FIDO applet's
    /// answer to the same request (double-encoded ASCII-hex, decoded via
    /// `keyroost_token2otp::parse_serial`), the OTP applet's reply is the
    /// serial itself in plain ASCII decimal — `parse_otp_serial` parses that
    /// text directly rather than hex-decoding it. Called directly from
    /// `Self::applet_fingerprint`'s arm matching `Token2` or `Thetis`, once
    /// classification already narrowed the fingerprint to one of those, so
    /// this never runs blind against a device with no reason to answer it.
    ///
    /// Same self-contained shape as every other mid-session identification
    /// probe in this file (see e.g. `Self::probe_hid_crescendo_cplc_serial`):
    /// SELECTs a second applet, reads what it needs, then unconditionally
    /// re-SELECTs PIV before returning, so the caller gets the session back
    /// exactly as any caller of [`Self::status`]/[`Self::status_detailed`]
    /// expects.
    ///
    /// `None` when the OTP applet doesn't SELECT (`SW != 9000`), when
    /// `GET_INFO` is refused, or when the reply doesn't parse as
    /// `D1 len ascii-decimal...` — callers fall back to the BCD-decoded
    /// `GET SERIAL` reply ([`decode_serial_if_bcd`]) in that case.
    fn probe_token2_otp_serial(&mut self) -> Option<u128> {
        let selected = matches!(
            self.transmit_full_raw(&piv::select_by_aid(&keyroost_token2otp::OTP_APPLET_AID)),
            Ok((_, sw)) if sw == piv::SW_OK
        );
        let serial = if selected {
            self.transmit_full_raw(&keyroost_token2otp::read_serial_request())
                .ok()
                .filter(|(_, sw)| *sw == piv::SW_OK)
                .and_then(|(data, _)| keyroost_token2otp::parse_otp_serial(&data).ok())
        } else {
            None
        };
        // Restore PIV as the selected applet before returning — mirrors
        // `probe_hid_crescendo_cplc_serial`.
        let _ = self.select();
        serial
    }

    /// Names of connected readers whose PIV applet answers `SELECT` with `9000`.
    pub fn list_piv_readers() -> Result<Vec<String>, TransportError> {
        let ctx = Context::establish(Scope::User).map_err(TransportError::PcscUnavailable)?;
        let mut buf = [0u8; 4096];
        let names: Vec<std::ffi::CString> = ctx
            .list_readers(&mut buf)
            .map_err(TransportError::PcscUnavailable)?
            .map(|r| r.to_owned())
            .collect();
        let mut out = Vec::new();
        for name in names {
            if let Ok(mut card) = ctx.connect(name.as_c_str(), ShareMode::Shared, Protocols::ANY) {
                if let Ok(txn) = card.transaction() {
                    let mut session = Self::from_transaction(txn, &name.to_string_lossy(), false);
                    if session.select().is_ok() {
                        out.push(name.to_string_lossy().into_owned());
                    }
                    // `session` — and the transaction it holds — drops here,
                    // at the end of this block. `Transaction`'s own `Drop`
                    // always ends it with `LeaveCard`, before the disconnect
                    // below runs.
                }
                // Release without resetting (pcsc's `Drop` hard-codes
                // ResetCard) — probing must not disturb cards other sessions
                // hold open.
                let _ = card.disconnect(pcsc::Disposition::LeaveCard);
            }
        }
        Ok(out)
    }

    /// Issues the actual SELECT APDU(s) unconditionally — a caller that only
    /// wants this to run once per connection goes through
    /// `Self::ensure_selected` instead. Sets `applet_selected` to match the
    /// outcome: `true` on a confirmed PIV select, `false` on anything else
    /// (no applet, or a transport failure), so a failed attempt here can't
    /// leave a later `Self::ensure_selected` wrongly convinced there's
    /// nothing left to do.
    fn select(&mut self) -> Result<(), TransportError> {
        // Try the full, spec-mandated AID first — some PIV implementations
        // (Nitrokey's `piv-authenticator`) only answer an exact-length AID
        // match and reject the short RID-only prefix `select()` sends. Fall
        // back to the short prefix only on a specific "not found", so a real
        // fault on the full-AID attempt still surfaces immediately rather
        // than being masked by a second, unrelated SELECT. See `piv::AID`'s
        // doc comment for the full story.
        let (data, sw) = self.transmit_full_raw(&piv::select_full())?;
        if sw == piv::SW_NOT_FOUND {
            let (data, sw) = self.transmit_full_raw(&piv::select())?;
            if sw == piv::SW_NOT_FOUND {
                self.state.select_response.clear();
                self.applet_selected = false;
                return Err(TransportError::NoPivApplet);
            }
            self.state.select_response = data;
            let result = ok_or_apdu("select piv applet (short aid)", sw);
            self.applet_selected = result.is_ok();
            return result;
        }
        self.state.select_response = data;
        let result = ok_or_apdu("select piv applet", sw);
        self.applet_selected = result.is_ok();
        result
    }

    /// Issue the real SELECT PIV APDU if this connection hasn't already sent
    /// one — the lazy half of [`Self::with_cached_transaction_traced`]'s validity
    /// check: the cheap PC/SC-layer identity comparison runs immediately at
    /// connect time, but the SELECT itself (and the round trip it costs) is
    /// deferred until something actually needs PIV selected.
    /// [`Self::transmit_full`] calls this first, so every genuine PIV
    /// command pays for the SELECT on whichever call turns out to be first
    /// in a session's life, and every later one on the same connection is
    /// free. A caller that opens a session and never issues a real command
    /// never pays for it at all.
    fn ensure_selected(&mut self) -> Result<(), TransportError> {
        if self.applet_selected {
            return Ok(());
        }
        self.select()
    }

    /// The connected card's raw ATR (contact) or PC/SC-synthesised
    /// pseudo-ATR (contactless), via `SCardStatus`. Empty on any transport
    /// failure — this backs a best-effort fingerprinting read (see
    /// `Self::applet_fingerprint`), not a precondition for anything else, so
    /// there is no error variant to plumb through.
    fn atr(&self) -> Vec<u8> {
        let mut names = [0u8; 256];
        let mut atr = [0u8; pcsc::MAX_ATR_SIZE];
        match self.card.status2(&mut names, &mut atr) {
            Ok(status) => status.atr().to_vec(),
            Err(_) => Vec::new(),
        }
    }

    /// Resolve this session's [`keyroost_piv::fingerprint::AppletFingerprint`],
    /// the token's own name when one was actually discovered (see
    /// [`PivStatus::applet_name`]), its firmware version (see
    /// [`PivStatus::version_firmware`]), and — only for identities whose own
    /// probe supplies one — its serial number, so [`Self::status`] /
    /// [`Self::status_detailed`] can skip the Yubico GET SERIAL extension
    /// entirely when it would just get a fake answer (observed: a Nitrokey
    /// answers that extension too, with a serial that isn't its real one; HID
    /// Crescendo simply doesn't answer it at all — every `HidCrescendo`
    /// variant's arm below calls `Self::probe_hid_crescendo_cplc_serial`
    /// directly, once classification already says the fingerprint is one,
    /// same as the Nitrokey arm calling `Self::probe_nitrokey_admin`; the
    /// result becomes part of this method's own cached result, so later
    /// callers — `Self::status`, `Self::status_detailed` — get it for free
    /// from that cache rather than re-probing. The rest — from the ATR read
    /// just now plus the SELECT response
    /// captured by [`Self::select`]. When the select identity names
    /// OpenFIPS201, also probes for Swissbit's registered RID
    /// ([`keyroost_piv::fingerprint::wants_swissbit_probe`]); when neither
    /// that nor any text-based criterion fingerprints the applet at all, also
    /// probes [`keyroost_piv::fingerprint::FEITIAN_RID`]
    /// ([`Self::probe_feitian_rid`]) and, if that still leaves `Generic`,
    /// [`keyroost_piv::fingerprint::IDPRIME_SECONDARY_PIV_AID`]
    /// ([`Self::probe_idprime_aid`]) as two last resorts, each cheaper to
    /// skip than to run, tried in that order before finally settling for
    /// `Generic`. Once the fingerprint itself is resolved, at most one
    /// further, fingerprint-specific step produces `applet_name`/version/
    /// serial: a Nitrokey (`Trussed(NitroKey)`) gets
    /// `Self::probe_nitrokey_admin` for its firmware, hardware variant, and
    /// serial; a YubiKey names itself from its own `GET VERSION` reply; HID
    /// Crescendo (C2300 and C4000) names itself from its SELECT response's
    /// Application Label (already read above as `select_identity`) and,
    /// since neither family answers the Yubico extension at all, gets its
    /// *applet* version from its own GET PIV PROPERTIES response instead —
    /// see [`Self::hid_crescendo_version`]'s doc; and Token2 or Thetis get
    /// [`Self::probe_token2_otp_serial`] for their serial (the PIV applet's
    /// own `GET SERIAL` answers with a BCD-truncated one), with Token2 alone
    /// (not Thetis) additionally deriving `version_firmware` from that same
    /// probed serial — see [`PivStatus::version_firmware`]'s doc. Every
    /// probe here always re-selects PIV afterward so the session is left
    /// exactly as any other caller of [`Self::status`] expects, whether or
    /// not the probe itself succeeded.
    ///
    /// Returns `(fingerprint, name, version, version_firmware, serial)`:
    /// `version` fetches Yubico's own `GET VERSION` extension itself (no
    /// caller needs to pass one in — this is the sole place that issues it),
    /// except where a fingerprint's own probe supplies a better source
    /// instead (HID Crescendo — see above), in which case that replaces it;
    /// the two are never both meaningful for the same fingerprint, so there
    /// is nothing to merge, only to prefer, and this method does that
    /// itself rather than handing a caller two values to reconcile.
    /// `version_firmware` is the separate, genuinely-distinct-from-the-applet
    /// firmware version axis (Nitrokey, genuinely device-reported, or Token2,
    /// derived from its serial prefix) — see [`PivStatus::version_firmware`]'s
    /// doc for why the two axes aren't interchangeable, and for the
    /// device-reported/derived distinction between Token2 and Nitrokey's own
    /// values on this same axis. `serial` is resolved here too, by whichever
    /// source is right for the matched fingerprint (a dedicated probe, or —
    /// `YubiKey` and the generic catch-all only — Yubico's GET SERIAL,
    /// BCD-decoded when this fingerprint's quirks call for it): unlike
    /// `version`, there's no single shared call site that fits every arm, so
    /// each arm resolves its own rather than this method doing it once
    /// afterward. Resolving it here rather than lazily in
    /// [`Self::status`]/[`Self::status_detailed`] is what lets it ride along
    /// in this method's own unconditional cache instead of paying for a live
    /// GET SERIAL round trip on every single status read.
    fn applet_fingerprint(&mut self) -> AppletFingerprintResult {
        // Cached from an earlier call in this same session — most callers
        // reach this via `Self::refresh`'s own resolution already having run
        // once; re-resolving would mean re-issuing every probe below,
        // including a GET VERSION a HidCrescendo never answers and a second
        // applet-select round trip for the fingerprints that need one
        // (Nitrokey's admin app, Swissbit/Feitian/IdPrime's RID/AID probes).
        if let Some(cached) = &self.state.identity {
            return cached.clone();
        }

        use keyroost_piv::fingerprint;

        let atr = self.atr();
        let atr_identity =
            fingerprint::atr_historical_bytes(&atr).and_then(fingerprint::atr_identity);
        let select_identity = fingerprint::select_identity(&self.state.select_response);

        let swissbit_rid_selectable = fingerprint::wants_swissbit_probe(select_identity.as_deref())
            && self.probe_swissbit_rid();

        // `feitian_rid_selectable` and `idprime_aid_selectable` are each the
        // sole criterion for their own identity, so they're only worth their
        // own SELECT round trip when nothing else already fingerprints the
        // applet — check with both probe bits false first, and only run each
        // probe (then re-classify) when that still leaves `Generic`, Feitian
        // before IdPrime.
        let id = fingerprint::classify(
            atr_identity.as_deref(),
            select_identity.as_deref(),
            swissbit_rid_selectable,
            false,
            false,
        );
        let id = if id == fingerprint::AppletFingerprint::Generic {
            fingerprint::classify(
                atr_identity.as_deref(),
                select_identity.as_deref(),
                swissbit_rid_selectable,
                self.probe_feitian_rid(),
                false,
            )
        } else {
            id
        };
        let id = if id == fingerprint::AppletFingerprint::Generic {
            fingerprint::classify(
                atr_identity.as_deref(),
                select_identity.as_deref(),
                swissbit_rid_selectable,
                false,
                self.probe_idprime_aid(),
            )
        } else {
            id
        };
        // Yubico's GET VERSION extension, fetched only now that `id` is
        // classified — a HID Crescendo (either family) is documented and
        // observed to never answer it at all (see the `HidCrescendo` match
        // arms below), so skip the round trip entirely rather than issuing it
        // speculatively before the fingerprint is even known, the way every
        // other identity here still needs to (nothing else about `id` is
        // resolvable without at least one live probe, so there's no way to
        // skip it generally — HidCrescendo is the sole identity that answers
        // a plain SELECT/ATR alone and never needs this extension).
        let version = if matches!(id, fingerprint::AppletFingerprint::HidCrescendo(_)) {
            None
        } else {
            self.version()
        };
        // No generic name fallback here — an undiscovered name stays empty,
        // per `PivStatus::applet_name`'s doc; `id`/its `Display`/
        // `applet_name()` are the generic fallback for a caller that wants
        // one regardless. Each arm builds the final `AppletFingerprintResult`
        // directly rather than a same-shaped tuple that then gets wrapped
        // afterward — named fields read a lot easier here than four
        // positional ones would, especially once `Option<String>` `name` and
        // `Option<Vec<u8>>` `version`/`version_firmware` sit next to each
        // other.
        let result = match id {
            fingerprint::AppletFingerprint::Trussed(fingerprint::TrussedVariant::NitroKey) => {
                self.probe_nitrokey_admin(id, version)
            }
            fingerprint::AppletFingerprint::YubiKey => {
                // Yubico's own GET SERIAL, resolved right here rather than
                // lazily in `Self::status`/`Self::status_detailed`: a real
                // YubiKey's answer is directly trustworthy (unlike a
                // Nitrokey's, which fakes this same extension — see
                // `Self::status`'s doc for that trap), so there's no reason
                // to defer it, and resolving it now means it rides along in
                // `identity`'s own unconditional cache instead of needing
                // one of its own that every status read would otherwise
                // have to check.
                let serial = decode_serial_if_bcd(id, version.as_deref(), None, self.serial());
                AppletFingerprintResult {
                    fingerprint: id,
                    name: version
                        .as_deref()
                        .and_then(fingerprint::format_yubikey_name)
                        .unwrap_or_default(),
                    version,
                    version_firmware: None,
                    serial,
                }
            }
            // HID Crescendo (either family — both are documented/observed to
            // answer a standard PIV SELECT, so there's no reason to expect
            // this to differ between them) names itself in its SELECT
            // response's Application Label (tag `0x50`) — already captured
            // above as `select_identity` (the same text `classify` matched
            // the generic `HidCrescendo` variant on, when the ATR didn't
            // already narrow it to a specific model): confirmed against a
            // live C2300 unit answering "HID Global ActivID Applet 3.0.3".
            // See <https://docs.hidglobal.com/crescendo/api/low-level/select.htm>
            // ("Data Field Returned in the Response Message for SELECT of
            // PIV Instance" — tag `0x50`, "Application Label"). It also
            // doesn't answer Yubico's own GET VERSION extension (`version`
            // above is always `None` for it), so its GET PIV PROPERTIES
            // response's own *applet* version block — HID's own
            // documentation names it "Applet Version Block" — is the only
            // applet-version source keyroost has for it, replacing the
            // empty Yubico reply as this fingerprint's `version`. Not
            // `version_firmware`: it's the same axis `version` represents
            // for any other fingerprint, just sourced differently, which is
            // also what `compat`'s `GetMetadata`/`Attest` C2300 known-
            // unsupported row is keyed on. See `Self::hid_crescendo_version`'s
            // doc.
            //
            // The Application Label already embeds a truncated copy of that
            // same version (the "3.0.3" tail above, versus GET PIV
            // PROPERTIES' fuller "3.0.3.6") — once the real version is known,
            // repeating a stale truncated one inside the name is just noise,
            // so it's stripped via
            // `fingerprint::strip_redundant_applet_version_suffix`.
            fingerprint::AppletFingerprint::HidCrescendo(
                variant @ (fingerprint::HidCrescendoVariant::C2300
                | fingerprint::HidCrescendoVariant::C4000),
            ) => {
                let hid_version = self.hid_crescendo_version(variant);
                let name = match (select_identity, &hid_version) {
                    (Some(name), Some(v)) => {
                        Some(fingerprint::strip_redundant_applet_version_suffix(&name, v))
                    }
                    (name, _) => name,
                };
                AppletFingerprintResult {
                    fingerprint: id,
                    name: name.unwrap_or_default(),
                    version: hid_version,
                    version_firmware: None,
                    serial: self.probe_hid_crescendo_cplc_serial(),
                }
            }
            // The generic HidCrescendo identity (matched via select text
            // alone, neither ATR narrowed it to C2300 nor C4000) gets the
            // same CPLC probe as its two more specific siblings — the
            // Issuer Security Domain answers it regardless of which HID
            // Crescendo family is behind it.
            fingerprint::AppletFingerprint::HidCrescendo(
                fingerprint::HidCrescendoVariant::Generic,
            ) => AppletFingerprintResult {
                fingerprint: id,
                name: String::new(),
                version,
                version_firmware: None,
                serial: self.probe_hid_crescendo_cplc_serial(),
            },
            // Token2 and Thetis both answer GET SERIAL (`Self::serial`) with
            // a packed-BCD value truncated to 4 bytes
            // (`PivQuirk::InsF8SerialIsBcd`), and both expose the same
            // on-device OTP applet whose own GET_INFO reports the full
            // serial instead. That full serial is preferred here exactly
            // like HidCrescendo's CPLC probe above; `None` falls through to
            // the BCD-decoded GET SERIAL fallback in
            // `Self::status`/`Self::status_detailed`.
            //
            // Token2 alone additionally derives `version_firmware` from that
            // same probed serial, via
            // `keyroost_piv::fingerprint::token2_firmware_from_serial`'s
            // prefix lookup (Token2's own published serial-number-prefix
            // reference — that function's doc has the source and the
            // derived-not-reported caveat). Thetis does not get this: its
            // serial numbering is its own, independent scheme, not Token2's.
            fingerprint::AppletFingerprint::Token2 => {
                let serial = self.probe_token2_otp_serial();
                AppletFingerprintResult {
                    fingerprint: id,
                    name: String::new(),
                    version,
                    version_firmware: serial
                        .and_then(keyroost_piv::fingerprint::token2_firmware_from_serial)
                        .map(<[u8]>::to_vec),
                    serial,
                }
            }
            fingerprint::AppletFingerprint::Thetis => AppletFingerprintResult {
                fingerprint: id,
                name: String::new(),
                version,
                version_firmware: None,
                serial: self.probe_token2_otp_serial(),
            },
            // Unclassified/generic PIV applet — plenty of non-Yubico
            // implementations answer this extension too (see
            // `PivStatus::version`'s own doc), and there's no dedicated
            // probe to prefer over it here, so resolve it the same way the
            // `YubiKey` arm above does, for the same reason: it rides along
            // in `identity`'s own unconditional cache instead of needing one
            // of its own.
            _ => {
                let serial = decode_serial_if_bcd(id, version.as_deref(), None, self.serial());
                AppletFingerprintResult {
                    fingerprint: id,
                    name: String::new(),
                    version,
                    version_firmware: None,
                    serial,
                }
            }
        };
        self.state.identity = Some(result.clone());
        result
    }

    /// SELECT [`keyroost_piv::fingerprint::FEITIAN_RID`] and report whether the
    /// card accepted it, then unconditionally re-SELECT PIV afterward. Only
    /// called when nothing else already fingerprinted the applet — see the
    /// call site in `Self::applet_fingerprint` — since a Feitian RID match
    /// is the lowest-priority, catch-all criterion and every other one is
    /// cheaper to check first.
    fn probe_feitian_rid(&mut self) -> bool {
        let selectable = matches!(
            self.transmit_full_raw(&piv::select_by_aid(&keyroost_piv::fingerprint::FEITIAN_RID)),
            Ok((_, sw)) if sw == piv::SW_OK
        );
        let _ = self.select();
        selectable
    }

    /// SELECT [`keyroost_piv::fingerprint::IDPRIME_SECONDARY_PIV_AID`] and report whether
    /// the card accepted it — either the standard `SW = 9000`, or the
    /// non-standard `SW = 6999` this obscure applet instance is documented
    /// to also answer with — then unconditionally re-SELECT PIV afterward
    /// (mirrors [`Self::probe_feitian_rid`], against a full AID rather than a
    /// bare RID). Only called when nothing else, not even Feitian's own
    /// probe, already fingerprinted the applet — see the call site in
    /// `Self::applet_fingerprint`.
    fn probe_idprime_aid(&mut self) -> bool {
        let selectable = matches!(
            self.transmit_full_raw(&piv::select_by_aid(&keyroost_piv::fingerprint::IDPRIME_SECONDARY_PIV_AID)),
            Ok((_, sw)) if sw == piv::SW_OK || sw == 0x6999
        );
        let _ = self.select();
        selectable
    }

    /// SELECT [`keyroost_piv::fingerprint::SWISSBIT_RID`] and report whether
    /// the card accepted it, then unconditionally re-SELECT PIV afterward
    /// (mirrors [`Self::probe_feitian_rid`], against Swissbit's registered
    /// RID). The re-select's own result is deliberately swallowed: a card
    /// that answered the PIV re-select badly here would have to fail the
    /// very next command this session issues anyway, with a clearer error at
    /// the point of use than anything this fingerprinting probe could add.
    fn probe_swissbit_rid(&mut self) -> bool {
        let selectable = matches!(
            self.transmit_full_raw(&piv::select_by_aid(&keyroost_piv::fingerprint::SWISSBIT_RID)),
            Ok((_, sw)) if sw == piv::SW_OK
        );
        let _ = self.select();
        selectable
    }

    /// SELECT [`keyroost_piv::fingerprint::NITROKEY_ADMIN_AID`] (Trussed's admin
    /// application) and, if accepted, read the hardware variant via its
    /// `GET STATUS` management command
    /// ([`keyroost_piv::fingerprint::NITROKEY_GET_ADMIN_STATUS`], for
    /// `applet_name`), the firmware version via its `GET_VERSION` management
    /// command in string-output mode
    /// ([`keyroost_piv::fingerprint::NITROKEY_GET_VERSION_STRING`], split into
    /// byte components for [`PivStatus::version_firmware`]), and the device
    /// serial via [`keyroost_piv::fingerprint::NITROKEY_GET_SERIAL`] (its own
    /// 128-bit value, not the Yubico GET SERIAL extension a Nitrokey answers
    /// with an unrelated, made-up number) — then unconditionally re-SELECT
    /// PIV on every path (mirrors [`Self::probe_feitian_rid`] against yet
    /// another applet, but reading three commands' worth of reply instead of
    /// just the SELECT result). The three commands degrade independently: no
    /// `name` when SELECT itself is refused (no admin application on this
    /// build) or the status command is refused/too short/names an
    /// unrecognised variant byte, no `version_firmware` when the version
    /// command is refused, empty, or not a dotted-`u8` string, no `serial`
    /// when the serial command is refused or too long to fit a `u128` —
    /// either way, a Nitrokey that can't answer one of these simply reports
    /// nothing for that field rather than an error.
    ///
    /// `id` and `version` are folded straight into the returned
    /// [`AppletFingerprintResult`] unchanged — this probe doesn't produce
    /// either of them itself (`id` is already known to be `Trussed(NitroKey)`
    /// by the time `Self::applet_fingerprint` calls this; `version` is
    /// Yubico's own GET VERSION reply, which a Nitrokey answers same as any
    /// other applet) — so the caller doesn't have to unpack a probe-shaped
    /// tuple and re-wrap it into the struct itself.
    fn probe_nitrokey_admin(
        &mut self,
        id: keyroost_piv::fingerprint::AppletFingerprint,
        version: Option<Vec<u8>>,
    ) -> AppletFingerprintResult {
        use keyroost_piv::fingerprint;

        let selected = matches!(
            self.transmit_full_raw(&piv::select_by_aid(&fingerprint::NITROKEY_ADMIN_AID)),
            Ok((_, sw)) if sw == piv::SW_OK
        );
        let (name, version_firmware, serial) = if selected {
            let name = self
                .transmit_full_raw(&fingerprint::NITROKEY_GET_ADMIN_STATUS)
                .ok()
                .filter(|(_, sw)| *sw == piv::SW_OK)
                .and_then(|(data, _)| fingerprint::parse_nitrokey_variant(&data))
                .map(fingerprint::format_nitrokey_name);
            let version_firmware = self
                .transmit_full_raw(&fingerprint::NITROKEY_GET_VERSION_STRING)
                .ok()
                .filter(|(_, sw)| *sw == piv::SW_OK)
                .and_then(|(data, _)| fingerprint::parse_ascii_text(&data))
                .and_then(|s| fingerprint::parse_dotted_version(&s));
            let serial = self
                .transmit_full_raw(&fingerprint::NITROKEY_GET_SERIAL)
                .ok()
                .filter(|(_, sw)| *sw == piv::SW_OK)
                .and_then(|(data, _)| keyroost_piv::parse_serial(&data).ok());
            (name, version_firmware, serial)
        } else {
            (None, None, None)
        };
        let _ = self.select();
        AppletFingerprintResult {
            fingerprint: id,
            name: name.unwrap_or_default(),
            version,
            version_firmware,
            serial,
        }
    }

    /// Read a read-only status snapshot: version, serial, PIN retries, CHUID,
    /// and which slots hold a certificate. No PIN, no touch.
    pub fn status(&mut self) -> Result<PivStatus, TransportError> {
        // Fingerprint resolution (which also resolves `version` and
        // `serial` — see `Self::applet_fingerprint`'s doc) runs first and is
        // fully cached in `identity`: a card's serial can't change while the
        // physical card stays the same, so there's nothing left to resolve
        // here — no live GET SERIAL round trip on a repeat call.
        let AppletFingerprintResult {
            fingerprint: applet_fingerprint,
            name: applet_name,
            version,
            version_firmware,
            serial,
        } = self.applet_fingerprint();
        let pin_retries = self.pin_retries();
        // Best-effort: a transport hiccup reading the CHUID shouldn't fail
        // the whole status snapshot, any more than an unsupported GET
        // VERSION/SERIAL does above.
        let chuid = self.read_chuid().unwrap_or_default();
        let mut slots = Vec::with_capacity(4);
        for slot in piv::Slot::all() {
            slots.push(self.slot_status(slot)?);
        }
        Ok(PivStatus {
            version,
            version_firmware,
            serial,
            pin_retries,
            slots,
            chuid,
            applet_fingerprint,
            applet_name,
        })
    }

    /// Resolve the per-fingerprint known-support table ([`keyroost_piv::compat`])
    /// for one of the vendor-extension operations this session exposes
    /// ([`Self::move_key`], [`Self::delete_key`]), from the applet's own
    /// fingerprint and reported version.
    ///
    /// Purely advisory: neither `move_key` nor `delete_key` version-gates
    /// itself any more (an unsupported card refuses the APDU on its own). A
    /// caller that wants to warn — or refuse — *before* the card sees the
    /// command calls this and acts on the [`FeatureGate`]. It runs the same
    /// fingerprint probes as [`Self::status`] and re-SELECTs PIV at the end,
    /// which clears any management-key authentication, so call it **before**
    /// [`Self::authenticate_management`].
    ///
    /// [`FeatureGate`]: keyroost_piv::compat::FeatureGate
    pub fn feature_gate(
        &mut self,
        feature: keyroost_piv::compat::PivExtension,
    ) -> keyroost_piv::compat::FeatureGate {
        let AppletFingerprintResult {
            fingerprint,
            version,
            version_firmware,
            ..
        } = self.applet_fingerprint();
        keyroost_piv::compat::resolve(
            feature,
            fingerprint,
            version.as_deref(),
            version_firmware.as_deref(),
        )
    }

    /// [`Self::status`] plus each slot's key algorithm, certificate Subject
    /// DN, and PIN/touch policy — the full per-slot view a status pane draws.
    ///
    /// The saving over calling `status()` and then `slot_key_algorithm` +
    /// `read_certificate` + `slot_policy` per slot is that each slot here
    /// costs exactly **one GET METADATA and one [`Self::read_certificate`]**
    /// on a session seeing this slot for the first time (plus an ATTEST only
    /// as the pre-5.3-firmware policy fallback): that one certificate read
    /// feeds occupancy, the Subject DN, and the algorithm's step-3 fallback
    /// together, and the GET METADATA feeds both the algorithm and the
    /// policy — calling the methods separately would otherwise re-read the
    /// certificate two or three times and GET METADATA twice.
    ///
    /// On a *later* call — another slot method reusing what this one just
    /// resolved, a tab reselect, or a whole new session on the same card via
    /// [`Self::with_cached_transaction`] — even that one read each may not happen at
    /// all: [`Self::read_certificate`]/`Self::cached_slot_key`/
    /// [`Self::slot_policy`] each check `CertCache`/`PubkeyCache`/
    /// `PolicyCache` first, so a slot whose key and certificate haven't
    /// changed since costs no APDU here whatsoever.
    ///
    /// Algorithm and policy fall back exactly as [`Self::slot_key_algorithm`]
    /// and [`Self::slot_policy`] do (they share the resolvers), so a caller
    /// that generated a key in this session should [`Self::remember_pubkey`]
    /// it first to have that key named for a slot with no certificate yet.
    pub fn status_detailed(&mut self) -> Result<PivStatusDetailed, TransportError> {
        // See the identical reasoning in `status`: `serial` is already
        // fully resolved as part of `identity`, cached, no live GET SERIAL
        // round trip here.
        let AppletFingerprintResult {
            fingerprint: applet_fingerprint,
            name: applet_name,
            version,
            version_firmware,
            serial,
        } = self.applet_fingerprint();
        let pin_retries = self.pin_retries();
        let chuid = self.read_chuid().unwrap_or_default();

        let mut slots = Vec::with_capacity(4);
        let mut detail = Vec::with_capacity(4);
        for slot in piv::Slot::all() {
            // The slot's one certificate read — its occupancy fields, its
            // Subject DN, and the algorithm's cert fallback all come off this.
            let cert = self.cert_object(slot)?;
            let cert_der = cert.as_ref().ok().and_then(Option::as_deref);
            // The slot's one GET METADATA — `cached_slot_key` shares it with
            // `slot_policy` below (its own resolution goes through
            // `cached_slot_key` too, so a slot needing both facts never
            // costs the round trip twice).
            let algorithm = self
                .cached_slot_key(slot)
                .map(|(alg, _)| alg)
                .or_else(|| self.hid_crescendo_slot_algorithm(slot))
                .or_else(|| {
                    cert_der
                        .and_then(|der| piv::x509_parse::parse_key_algorithm(der).ok().flatten())
                });
            let subject = cert_der
                .and_then(|der| piv::x509_parse::parse_subject_dn(der).ok())
                .map(|dn| dn.to_string());
            let policy = self.slot_policy(slot);

            slots.push(slot_occupancy(
                slot,
                cert.as_ref().map(Option::as_deref).map_err(|e| *e),
            ));
            detail.push(PivSlotDetail {
                slot,
                algorithm,
                subject,
                policy,
            });
        }
        Ok(PivStatusDetailed {
            status: PivStatus {
                version,
                version_firmware,
                serial,
                pin_retries,
                slots,
                chuid,
                applet_fingerprint,
                applet_name,
            },
            slots: detail,
        })
    }

    /// Yubico's proprietary GET VERSION extension (`INS FD`), raw reply
    /// bytes, tolerant of any non-empty length — see [`PivStatus::version`]
    /// for why. `None` if the command errors, the card answers a non-`9000`
    /// status, or the reply is empty. [`Self::feature_gate`] passes the raw
    /// bytes straight to [`keyroost_piv::compat::resolve`], which compares
    /// them as a slice rather than requiring an exact 3-byte shape like real
    /// Yubico firmware's.
    fn version(&mut self) -> Option<Vec<u8>> {
        let (data, sw) = self.transmit_full(&piv::get_version()).ok()?;
        (sw == piv::SW_OK && !data.is_empty()).then_some(data)
    }

    /// Yubico GET SERIAL; `None` if unsupported (older firmware / non-Yubico).
    /// Widened to `u128` — see [`keyroost_piv::parse_serial`] for why the
    /// reply isn't always the standard 4-byte `u32`. Called at most once per
    /// lineage, from `Self::applet_fingerprint`'s `YubiKey` and generic
    /// catch-all arms only — every fingerprint with its own dedicated serial
    /// probe (Token2, Thetis, Nitrokey, HID Crescendo) never calls this at
    /// all. Resolving it during fingerprinting rather than lazily in
    /// [`Self::status`]/[`Self::status_detailed`] means it rides along in
    /// `identity`'s own unconditional cache — safe, because a card's serial
    /// cannot change while the physical card stays the same, exactly like
    /// the rest of `identity` — instead of needing a cache of its own that
    /// every status read would otherwise have to check.
    fn serial(&mut self) -> Option<u128> {
        let (data, sw) = self.transmit_full(&piv::get_serial()).ok()?;
        if sw != piv::SW_OK {
            return None;
        }
        piv::parse_serial(&data).ok()
    }

    /// Remaining PIN tries via a no-op VERIFY (consumes no try itself — the
    /// query the card answers is distinct from an actual PIN presentation).
    /// `63 Cx` → `Some(x)`, `6983` (blocked) → `Some(0)`, `9000` (already
    /// verified) / anything else → `None`.
    ///
    /// Cached in `PivSessionState::pin_retries_cache` for the rest of this
    /// lineage once a real status word comes back — a transport-level
    /// failure (the early `?` below) is never cached, same as every other
    /// cache here. [`Self::verify_pin`]/[`Self::change_pin`]/
    /// [`Self::unblock_pin`]/[`Self::set_pin_retries`] each invalidate this
    /// on the way out, since each is the one thing that can actually move
    /// the counter this method itself never touches.
    fn pin_retries(&mut self) -> Option<u8> {
        if let Some(cached) = self.state.pin_retries_cache {
            return cached;
        }
        let Ok((_, sw)) = self.transmit_full(&piv::verify_pin_status()) else {
            return None;
        };
        let retries = if let Some(n) = crate::sw_tries_remaining(sw) {
            Some(n)
        } else if sw == 0x6983 {
            Some(0)
        } else {
            None
        };
        self.state.pin_retries_cache = Some(retries);
        retries
    }

    /// This session's [`keyroost_piv::fingerprint::AppletFingerprint`] plus
    /// its reported applet/firmware version bytes, resolved together once —
    /// via [`Self::version`] and `Self::applet_fingerprint`, the same
    /// sources [`Self::status`] and [`Self::status_detailed`] use — and
    /// cached in `Self::identity` (the field) for the rest of the session;
    /// see that field's doc for why caching this particular resolution is
    /// safe. `Self::fingerprint`, [`Self::quirks`], and
    /// [`Self::extension_gate`] are thin accessors over this. The caching
    /// itself lives in `Self::applet_fingerprint` now (shared with
    /// [`Self::status`]/[`Self::status_detailed`]/[`Self::feature_gate`],
    /// which need its `name`/`serial` fields too) — this is just the
    /// narrower view over the same cached value.
    fn identity(&mut self) -> SessionIdentity {
        let AppletFingerprintResult {
            fingerprint,
            version,
            version_firmware,
            ..
        } = self.applet_fingerprint();
        SessionIdentity {
            fingerprint,
            version,
            version_firmware,
        }
    }

    /// This session's [`keyroost_piv::fingerprint::AppletFingerprint`] — see
    /// `Self::identity`. Used by `Self::hid_crescendo_slot_algorithm` to
    /// find which HID Crescendo sub-variant (if any) it's talking to.
    fn fingerprint(&mut self) -> keyroost_piv::fingerprint::AppletFingerprint {
        self.identity().fingerprint
    }

    /// The [`keyroost_piv::compat::PivQuirk`]s active for this session's
    /// applet — see `Self::identity`. [`Self::metadata`] consumes this
    /// internally; `keyroostctl`'s `piv reset` also calls it directly (it's
    /// `pub` for that) to decide whether to print
    /// [`keyroost_piv::compat::PivQuirk::RESET_LONG_RUNNING_HINT`] before
    /// running RESET. Cached via `Self::identity`, so calling it costs no
    /// extra round trip once the fingerprint has already been probed this
    /// session.
    pub fn quirks(&mut self) -> BTreeSet<keyroost_piv::compat::PivQuirk> {
        let SessionIdentity {
            fingerprint,
            version,
            version_firmware,
        } = self.identity();
        keyroost_piv::compat::resolve_quirks(
            fingerprint,
            version.as_deref(),
            version_firmware.as_deref(),
        )
    }

    /// The [`keyroost_piv::compat::FeatureGate`] for one of this session's
    /// *internally* consumed [`keyroost_piv::compat::PivExtension`]s
    /// ([`keyroost_piv::compat::PivExtension::GetMetadata`]/[`Attest`] —
    /// see [`Self::metadata`]/[`Self::attest`]) — see `Self::identity` for
    /// where the fingerprint/version data comes from. Distinct from the
    /// public [`Self::feature_gate`], which resolves the same way but always
    /// live (never cached) for the UI-facing extensions
    /// ([`MoveKey`](keyroost_piv::compat::PivExtension::MoveKey)/
    /// [`DeleteKey`](keyroost_piv::compat::PivExtension::DeleteKey)) — a
    /// caller of that one relies on the live re-SELECT it performs as a side
    /// effect (see its doc), which caching here would silently drop after
    /// the first call.
    fn extension_gate(
        &mut self,
        extension: keyroost_piv::compat::PivExtension,
    ) -> keyroost_piv::compat::FeatureGate {
        let SessionIdentity {
            fingerprint,
            version,
            version_firmware,
        } = self.identity();
        keyroost_piv::compat::resolve(
            extension,
            fingerprint,
            version.as_deref(),
            version_firmware.as_deref(),
        )
    }

    /// The wire algorithm-identifier byte to send for `alg` in this session's
    /// GENERATE ASYMMETRIC KEY PAIR / GENERAL AUTHENTICATE APDUs: this
    /// fingerprint's own override if it has one, or [`KeyAlg::id`]'s
    /// Yubico-default byte otherwise. See
    /// [`keyroost_piv::compat::slot_key_algorithm_apdu_id`] — passed this
    /// session's firmware version too, via `Self::identity`, since that
    /// function's `Trussed`/`NitroKey` entry is gated by it. Cached via
    /// `Self::identity`, so this costs no extra round trip once the
    /// fingerprint has already been probed this session.
    fn slot_key_algorithm_apdu_id(&mut self, alg: KeyAlg) -> u8 {
        let SessionIdentity {
            fingerprint,
            version_firmware,
            ..
        } = self.identity();
        keyroost_piv::compat::slot_key_algorithm_apdu_id(
            alg,
            fingerprint,
            version_firmware.as_deref(),
        )
    }

    /// The inverse of [`Self::slot_key_algorithm_apdu_id`]: resolve a
    /// device-reported algorithm-identifier byte (GET METADATA tag `0x01`)
    /// back to a [`KeyAlg`], preferring this fingerprint's own override over
    /// [`KeyAlg::from_id`]'s Yubico-default table. See
    /// [`keyroost_piv::compat::key_alg_from_apdu_id`] — same firmware-version
    /// pass-through as [`Self::slot_key_algorithm_apdu_id`] above.
    fn key_alg_from_apdu_id(&mut self, id: u8) -> Option<KeyAlg> {
        let SessionIdentity {
            fingerprint,
            version_firmware,
            ..
        } = self.identity();
        keyroost_piv::compat::key_alg_from_apdu_id(id, fingerprint, version_firmware.as_deref())
    }

    /// GET METADATA for a key/PIN reference (`0x9B`, `0x80`, `0x81`, or a slot
    /// key ref). `None` when the firmware predates the extension (5.3-), or
    /// this fingerprint/version is known to never answer it at all
    /// ([`keyroost_piv::compat::PivExtension::GetMetadata`] resolving
    /// [`keyroost_piv::compat::FeatureGate::Unsupported`] — the HID
    /// Crescendo C2300 family at its observed GET PIV PROPERTIES version) —
    /// checked *before* sending anything, so this never puts the unsupported
    /// extension APDU on the wire for those devices at all, unlike
    /// [`keyroost_piv::compat::PivQuirk::InsF7MetadataAlgorithmInvalid`]
    /// below, which needs the reply in hand to know what to strip from it.
    ///
    /// Runs `clear_metadata_if_quirky` over the parsed reply before
    /// returning it — see that function's doc for what it strips and why.
    /// This is the sole place that needs to know about either check: every
    /// caller — direct, or through `Self::resolve_slot_from_device`'s
    /// decode — already treats a missing algorithm/public key as "fall back
    /// to another source", which is exactly the right behavior on a device
    /// where GET METADATA can't be trusted, or isn't there at all.
    ///
    /// Always a live round trip, deliberately uncached here: a PIN/PUK/
    /// management-key reference's `retries`/`is_default` answer can change
    /// on essentially every VERIFY/CHANGE REFERENCE DATA/SET MANAGEMENT KEY
    /// call, so this crate never caches *this* method's raw result — a
    /// caller with an actual [`Slot`] in hand decodes and caches the *final*
    /// facts it actually needs (`Self::resolve_slot_from_device` for
    /// algorithm/key/policy) rather than the reply itself; see that
    /// method's doc for why.
    pub fn metadata(&mut self, key_ref: u8) -> Option<Metadata> {
        if self.extension_gate(keyroost_piv::compat::PivExtension::GetMetadata)
            == keyroost_piv::compat::FeatureGate::Unsupported
        {
            return None;
        }
        let (data, sw) = self.transmit_full(&piv::get_metadata(key_ref)).ok()?;
        if sw != piv::SW_OK {
            return None;
        }
        let md = piv::parse_metadata(&data).ok()?;
        Some(clear_metadata_if_quirky(&self.quirks(), md))
    }

    /// One live [`Self::metadata`]`(slot.key_ref())` read, decoded straight
    /// into the *final* facts a caller actually wants — never kept around as
    /// an intermediate [`Metadata`] value:
    ///
    /// * whenever the reply carries a `policy` tag, decodes and writes
    ///   `PolicyCache` directly — sharing this one round trip with
    ///   whatever else needed it, so a slot wanting both algorithm/key *and*
    ///   policy (`status_detailed`'s per-slot loop) never pays for it twice.
    ///   Deliberately never writes a *negative* answer there: an absent tag
    ///   means "try the ATTEST fallback next", a decision [`Self::slot_policy`]
    ///   — not this method — gets to make once it's tried that too;
    /// * returns the decoded `(algorithm, key)` when the reply names both
    ///   (via `metadata_key_material`), `None` otherwise. Callers write
    ///   that into `PubkeyCache` however fits their own read policy — see
    ///   `Self::cached_slot_key` (cache-preferring) and
    ///   `Self::confirmed_slot_key` (always re-confirms live).
    ///
    /// Never itself consults or writes `pubkey_cache`/`policy_cache`'s
    /// "already resolved" state — that's each caller's own job, precisely
    /// so `Self::slot_key_status_algorithm` can use this same decode path
    /// for its algorithm-only reply without going anywhere near
    /// `pubkey_cache` at all (see that method's doc for why it must not).
    fn resolve_slot_from_device(&mut self, slot: Slot) -> Option<(KeyAlg, PublicKey)> {
        let key_ref = slot.key_ref();
        let md = self.metadata(key_ref);
        if let Some((pin, touch)) = md.as_ref().and_then(|m| m.policy) {
            if let (Some(pin), Some(touch)) = (PinPolicy::from_id(pin), TouchPolicy::from_id(touch))
            {
                self.state
                    .policy_cache
                    .remember(key_ref, Some((pin, touch)));
            }
        }
        md.as_ref()
            .and_then(|m| metadata_key_material(m, |id| self.key_alg_from_apdu_id(id)))
            .and_then(|(alg, raw)| public_key_from_metadata(raw).ok().map(|key| (alg, key)))
    }

    /// `slot`'s algorithm + public key from `PubkeyCache` if this lineage
    /// has already resolved it (by either provenance — see that type's
    /// doc), else one live `Self::resolve_slot_from_device` read, cached
    /// for next time either way (including a confirmed-empty slot, so a
    /// slot that's genuinely empty — the common case — doesn't cost another
    /// APDU on the next tab reselect). Backs the display/status paths that
    /// call repeatedly and can tolerate a value that's a moment stale:
    /// [`Self::status_detailed`], [`Self::slot_key_algorithm`],
    /// [`Self::slot_has_key`]. `Self::confirmed_slot_key` is the
    /// always-fresh counterpart for the two callers that can't.
    fn cached_slot_key(&mut self, slot: Slot) -> Option<(KeyAlg, PublicKey)> {
        let key_ref = slot.key_ref();
        if let Some(resolved) = self.state.pubkey_cache.get(key_ref) {
            return resolved.cloned();
        }
        let resolved = self.resolve_slot_from_device(slot);
        self.state.pubkey_cache.remember(key_ref, resolved.clone());
        resolved
    }

    /// `slot`'s algorithm + public key, always re-confirmed live against the
    /// device first — bypassing whatever `PubkeyCache` already holds —
    /// and preferring what the device reports whenever it reports anything.
    /// Backs [`Self::slot_key`], the shared source [`Self::generate_csr`]/
    /// [`Self::self_signed_certificate`] use: both mint an SPKI that then
    /// gets signed by the card's *actual* current private key, so trusting a
    /// stale cached value here wouldn't just show outdated info — it would
    /// produce a certificate whose declared public key doesn't match what
    /// signed it. Worth the extra APDU on an operation already doing a PIN
    /// verify and a signature.
    ///
    /// A device that answers nothing new proves nothing about whether an
    /// existing entry — self-known via [`Self::remember_pubkey`], or a
    /// previous confirmation — is still right, so that case falls back to
    /// whatever's already cached instead of erasing it: a metadata-less
    /// card's silence is *expected*, not a "this key is gone" signal.
    fn confirmed_slot_key(&mut self, slot: Slot) -> Option<(KeyAlg, PublicKey)> {
        let key_ref = slot.key_ref();
        match self.resolve_slot_from_device(slot) {
            Some(kv) => {
                self.state.pubkey_cache.remember(key_ref, Some(kv.clone()));
                Some(kv)
            }
            None => self
                .state
                .pubkey_cache
                .get(key_ref)
                .and_then(|cached| cached.cloned()),
        }
    }

    /// The raw response body of a HID Crescendo GET PIV PROPERTIES read for
    /// `variant` (must be [`HidCrescendoVariant::C2300`] or
    /// [`HidCrescendoVariant::C4000`] — the two families this crate knows a
    /// request for; [`HidCrescendoVariant::Generic`] sends nothing and
    /// yields an empty read, since keyroost has no confirmed request shape
    /// for an unidentified HID Crescendo model), cached once per session —
    /// see [`Self::hid_crescendo_properties_raw`] (the field) for why this
    /// is the single fetch both `Self::hid_crescendo_slot_key_algorithms` (the
    /// per-slot algorithm list) and [`Self::hid_crescendo_version`] (this
    /// applet's own version, consulted by `Self::applet_fingerprint`)
    /// derive from, rather than each issuing its own read.
    ///
    /// `variant` is a parameter rather than resolved internally via
    /// `Self::fingerprint` on purpose: `Self::applet_fingerprint` (via
    /// `Self::identity`) is what determines the fingerprint in the first
    /// place, and its own HID Crescendo branch is a caller of this method —
    /// calling back into `Self::fingerprint`/`Self::identity` from here
    /// would recurse into a resolution that hasn't finished yet. Every
    /// caller already has the variant in hand from its own match on
    /// [`keyroost_piv::fingerprint::AppletFingerprint`].
    ///
    /// Issues the read on first call; every later call in the same session
    /// reuses the cache regardless of which `variant` is passed (a session's
    /// fingerprint can't change mid-connection, so this is never asked for
    /// two different variants in the same session). A read that errors or
    /// answers a non-`9000` status caches as an empty `Vec` — both derived
    /// parses already treat that the same as "nothing to report".
    fn hid_crescendo_properties_raw(
        &mut self,
        variant: keyroost_piv::fingerprint::HidCrescendoVariant,
    ) -> Vec<u8> {
        use keyroost_piv::fingerprint::{self, HidCrescendoVariant};

        if let Some(raw) = self
            .state
            .applet_cache
            .bytes(AppletCacheKey::HidCrescendoPropertiesRaw)
        {
            return raw.to_vec();
        }
        let apdu = match variant {
            HidCrescendoVariant::C2300 => Some(piv::get_data(
                &fingerprint::HID_CRESCENDO_C2300_PROPERTIES_TAG,
            )),
            HidCrescendoVariant::C4000 => {
                Some(fingerprint::HID_CRESCENDO_C4000_GET_PROPERTIES.to_vec())
            }
            // `Generic` (no confirmed request shape) and any future variant
            // this crate doesn't know a GET PIV PROPERTIES request for yet.
            _ => None,
        };
        let raw = apdu
            .and_then(|apdu| self.transmit_full(&apdu).ok())
            .filter(|(_, sw)| *sw == piv::SW_OK)
            .map(|(data, _)| data)
            .unwrap_or_default();
        self.state
            .applet_cache
            .set_bytes(AppletCacheKey::HidCrescendoPropertiesRaw, raw.clone());
        raw
    }

    /// This session's parsed `(key_ref, algorithm_id)` pairs from a HID
    /// Crescendo GET PIV PROPERTIES read, one pair per slot that actually
    /// has a key loaded (a slot whose PKI container exists but reports no
    /// key generated/injected is excluded — see
    /// [`keyroost_piv::fingerprint::parse_hid_crescendo_slot_key_algorithms`]'s doc)
    /// — see [`Self::hid_crescendo_properties_raw`] for the shared,
    /// once-per-session fetch this derives from. An empty list either way a
    /// read can come up empty: the read itself failing, or a well-formed
    /// response simply naming no slot with a key loaded.
    fn hid_crescendo_slot_key_algorithms(
        &mut self,
        variant: keyroost_piv::fingerprint::HidCrescendoVariant,
    ) -> Vec<(u8, u8)> {
        let raw = self.hid_crescendo_properties_raw(variant);
        keyroost_piv::fingerprint::parse_hid_crescendo_slot_key_algorithms(&raw)
    }

    /// This applet's own version, from the same HID Crescendo GET PIV
    /// PROPERTIES read `Self::hid_crescendo_slot_key_algorithms` uses — see
    /// [`Self::hid_crescendo_properties_raw`]. `Self::applet_fingerprint`
    /// feeds this into the "firmware version" axis
    /// [`keyroost_piv::compat::resolve`]/[`keyroost_piv::compat::resolve_quirks`]
    /// compare against [`keyroost_piv::compat::PivExtension::GetMetadata`]/
    /// [`Attest`](keyroost_piv::compat::PivExtension::Attest)'s HID-specific
    /// known-unsupported row, since this fingerprint never answers Yubico's
    /// own GET VERSION extension the applet axis elsewhere keys on. `None`
    /// when the read fails or doesn't carry a version block.
    fn hid_crescendo_version(
        &mut self,
        variant: keyroost_piv::fingerprint::HidCrescendoVariant,
    ) -> Option<Vec<u8>> {
        let raw = self.hid_crescendo_properties_raw(variant);
        keyroost_piv::fingerprint::parse_hid_crescendo_version(&raw)
    }

    /// Whether this HID Crescendo's GET PIV PROPERTIES read names the PIV
    /// management key (`0x9B`) as a real slot object at all — see
    /// [`keyroost_piv::fingerprint::hid_crescendo_reports_slot`]'s doc. The
    /// sole consumer, [`Self::authenticate_management`], uses this to decide
    /// between the standard `0x9B` `GENERAL AUTHENTICATE` round (most PIV
    /// applets, and the minority of HID Crescendo units HID's own Crescendo
    /// Manager documentation says do expose `0x9B`:
    /// <https://docs.hidglobal.com/crescendo-manager/CM/about-cm.htm>) and
    /// the vendor ACA XAUTH fallback (most HID Crescendo units, including
    /// every unit this crate has actually been tested against).
    fn hid_crescendo_reports_management_key(
        &mut self,
        variant: keyroost_piv::fingerprint::HidCrescendoVariant,
    ) -> bool {
        let raw = self.hid_crescendo_properties_raw(variant);
        keyroost_piv::fingerprint::hid_crescendo_reports_slot(&raw, piv::KEY_REF_MANAGEMENT)
    }

    /// HID Crescendo's substitute for GET METADATA's algorithm field: this
    /// fingerprint/version resolves
    /// [`keyroost_piv::compat::PivExtension::GetMetadata`] to
    /// [`keyroost_piv::compat::FeatureGate::Unsupported`] (see
    /// [`Self::metadata`]'s doc — today only confirmed for C2300, but C4000
    /// exposes the same GET PIV PROPERTIES data too), so this reads the
    /// vendor's own data object instead via `Self::hid_crescendo_slot_key_algorithms`.
    /// `None` on any other fingerprint (nothing to try), or when the read
    /// doesn't name `slot`'s key at all.
    ///
    /// Decodes the reported byte via [`Self::key_alg_from_apdu_id`] rather
    /// than [`keyroost_piv::fingerprint::hid_crescendo_algorithm_from_id`]
    /// directly — the same per-fingerprint override table now backs both,
    /// see [`keyroost_piv::compat::PivExtension::SlotKeyAlgorithm`]'s doc.
    fn hid_crescendo_slot_algorithm(&mut self, slot: Slot) -> Option<KeyAlg> {
        let keyroost_piv::fingerprint::AppletFingerprint::HidCrescendo(variant) =
            self.fingerprint()
        else {
            return None;
        };
        let key_ref = slot.key_ref();
        let id = self
            .hid_crescendo_slot_key_algorithms(variant)
            .into_iter()
            .find(|&(kr, _)| kr == key_ref)?
            .1;
        self.key_alg_from_apdu_id(id)
    }

    /// The card-management (9B) key's algorithm *as the card reports it* via
    /// GET METADATA, or `None` when the card doesn't answer the extension
    /// (pre-5.3 YubiKey firmware, and non-Yubico applets that stub it out).
    /// It makes no assumption about what an absent answer means — see
    /// [`Self::resolve_management_key_algorithm`].
    pub fn reported_management_key_algorithm(&mut self) -> Option<MgmtAlg> {
        self.metadata(piv::KEY_REF_MANAGEMENT)
            .and_then(|m| m.algorithm)
            .and_then(MgmtAlg::from_id)
    }

    /// Decide which algorithm to run management-key authentication under, given
    /// the length of the key the caller holds.
    ///
    /// 1. If GET METADATA reports an algorithm, that wins (its expected key
    ///    length is checked against `key_len`).
    /// 2. Otherwise, probe **every** algorithm — regardless of `key_len` — with
    ///    GENERAL AUTHENTICATE step 1 (request witness only; no key-derived
    ///    material reaches the card) and collect the ones the card accepts with
    ///    `SW 9000`. Then:
    ///    * narrow that accepted set to the algorithms whose key is `key_len`
    ///      bytes;
    ///    * if one remains, use it;
    ///    * if several remain and 3DES is among them, use 3DES (the historical
    ///      pre-metadata default — only 3DES and AES-192 can collide on length);
    ///    * if the card accepted nothing, fall back to `key_len` alone.
    ///
    /// The chosen algorithm is only *returned*; the caller still runs
    /// [`Self::authenticate_management`] with it to actually authenticate.
    ///
    /// Returns [`TransportError::PivBadKeyLength`] when nothing the card
    /// accepts (or, on an empty probe, no algorithm at all) matches `key_len`.
    pub fn resolve_management_key_algorithm(
        &mut self,
        key_len: usize,
    ) -> Result<MgmtAlg, TransportError> {
        if let Some(alg) = self.reported_management_key_algorithm() {
            if alg.key_len() != key_len {
                return Err(TransportError::PivBadKeyLength);
            }
            return Ok(alg);
        }

        // No GET METADATA. Probe each algorithm's GENERAL AUTHENTICATE P1 with a
        // bare witness request and see which the card is willing to start.
        const ALL: [MgmtAlg; 4] = [
            MgmtAlg::TripleDes,
            MgmtAlg::Aes128,
            MgmtAlg::Aes192,
            MgmtAlg::Aes256,
        ];
        trace::line(self.traced, || {
            "piv mgmt-key: GET METADATA unsupported; probing every GENERAL \
             AUTHENTICATE P1 with a witness request"
                .to_string()
        });
        let mut accepted: Vec<MgmtAlg> = Vec::with_capacity(ALL.len());
        for alg in ALL {
            // A transport failure (card pulled, reader gone) is fatal for every
            // candidate — propagate it rather than mislabel it "bad key
            // length". Only a non-9000 status word means "not this P1".
            let (_, sw) = self.transmit_full(&piv::general_auth_request_witness(
                alg,
                piv::KEY_REF_MANAGEMENT,
            ))?;
            let ok = sw == piv::SW_OK;
            trace::line(self.traced, || {
                format!(
                    "piv mgmt-key: probe {} (P1={:#04x}) -> {}",
                    alg.label(),
                    alg.id(),
                    if ok {
                        "accepted".to_string()
                    } else {
                        format!("rejected (SW {sw:04X})")
                    }
                )
            });
            if ok {
                accepted.push(alg);
            }
        }

        if accepted.is_empty() {
            trace::line(self.traced, || {
                "piv mgmt-key: card accepted no probe; falling back to key length".to_string()
            });
        }
        let chosen = pick_mgmt_alg(&accepted, key_len).ok_or(TransportError::PivBadKeyLength)?;
        trace::line(self.traced, || {
            format!("piv mgmt-key: selected {}", chosen.label())
        });
        Ok(chosen)
    }

    /// Authenticate to unlock PIV admin operations (key generation,
    /// certificate import, set-management-key, set-pin-retries). `alg` must
    /// match the card's stored management-key algorithm (see
    /// [`Self::resolve_management_key_algorithm`]) on the standard path below; the
    /// HID Crescendo ACA path further down instead reads the real algorithm
    /// off the card at auth time, so `alg` only bounds the initial
    /// key-length check there.
    ///
    /// Two mechanisms, picked per fingerprint and per device:
    ///
    /// 1. **Standard PIV** — every applet except HID Crescendo, plus the
    ///    minority of HID Crescendo units that *do* expose the management
    ///    key (`0x9B`) as a real slot object (HID's own Crescendo Manager
    ///    documentation: <https://docs.hidglobal.com/crescendo-manager/CM/about-cm.htm>
    ///    — see `Self::hid_crescendo_reports_management_key`): the
    ///    GENERAL AUTHENTICATE witness/challenge round below, unchanged
    ///    from before this method knew HID Crescendo existed.
    /// 2. **HID Crescendo ACA XAUTH** — every other HID Crescendo unit (the
    ///    majority; every unit this crate has actually been tested against),
    ///    which doesn't model `0x9B` as a PIV object at all (confirmed on a
    ///    live C2300 unit: `SW = 6D 00` to a standard GENERAL AUTHENTICATE on
    ///    `0x9B`), so the standard round has nothing to authenticate
    ///    against. Delegates to
    ///    `Self::authenticate_management_hid_crescendo_aca` — see its doc
    ///    for the sequence and for why switching back to PIV at the end
    ///    doesn't throw the resulting authentication away the way it would
    ///    for the standard mechanism.
    ///
    /// Neither path implements HID Crescendo's separate PIN-only unlock for
    /// most management operations (documented e.g. at
    /// <https://docs.hidglobal.com/hid-crescendo-sdk-v1.2/API%20references/html/md_Documentation_204_8EXAMPLES.html>).
    /// That's a different mechanism from Yubico's own PIN-unlock extension,
    /// which retrieves the actual management key via the PIN and then still
    /// runs the standard round below — and Yubico's own version isn't
    /// implemented here either yet, so HID Crescendo's is left out for the
    /// same reason, not a HID-specific gap.
    pub fn authenticate_management(
        &mut self,
        alg: MgmtAlg,
        key: &[u8],
    ) -> Result<(), TransportError> {
        if key.len() != alg.key_len() {
            return Err(TransportError::PivBadKeyLength);
        }

        if let keyroost_piv::fingerprint::AppletFingerprint::HidCrescendo(variant) =
            self.fingerprint()
        {
            if !self.hid_crescendo_reports_management_key(variant) {
                return self.authenticate_management_hid_crescendo_aca(key);
            }
        }

        // Step 1: ask the card for an encrypted witness.
        let (resp, sw) = self.transmit_full(&piv::general_auth_request_witness(
            alg,
            piv::KEY_REF_MANAGEMENT,
        ))?;
        ok_or_apdu("piv authenticate (request witness)", sw)?;
        let z1 = piv::parse_general_auth(&resp, 0x80).map_err(TransportError::PivParse)?;
        // Decrypt it with the management key — proves we hold the key.
        let witness = Zeroizing::new(block_crypt(alg, key, z1, CryptOp::Decrypt)?);

        // Step 2: return the decrypted witness plus our own random challenge.
        let mut challenge = vec![0u8; alg.block_size()];
        getrandom::getrandom(&mut challenge).map_err(|_| TransportError::HostRngFailed)?;
        let apdu = Zeroizing::new(piv::general_auth_mutual(
            alg,
            piv::KEY_REF_MANAGEMENT,
            &witness,
            &challenge,
        ));
        let (resp2, sw2) = self.transmit_full(&apdu)?;
        // A wrong key makes the card reject our witness here.
        if sw2 != piv::SW_OK {
            return Err(TransportError::PivManagementAuthFailed);
        }
        // Some cards (observed: Identiv uTrust FIDO2 Security Key) answer this
        // step with `SW_OK` and an empty body instead of a `7C` template
        // carrying the encrypted-challenge tag `0x82` — they verify our
        // witness (a wrong one is rejected with a non-success status, same as
        // above) but never implement the card-to-host half of mutual auth.
        //
        // This is NIST SP 800-73's "client (application) authentication" —
        // only the client proves possession of the management key — versus
        // the fuller "mutual authentication" that also has the card prove
        // itself back to the client via 0x82. Client auth is the half that
        // actually gates PIV admin operations, so it's sufficient on its own;
        // we still *request* the mutual exchange up front (same step-1 APDU,
        // same 0x80+0x81 step-2 APDU either way) because it's a strict
        // superset — cards that only implement client auth answer exactly as
        // they do here, and cards that implement the full round give us extra
        // assurance, before writing new key material, that the "OK" we got
        // back came from something that actually holds the key rather than a
        // card that blindly answers success. So: treat this as authenticated
        // rather than erroring on an 0x82 template that was never coming.
        if resp2.is_empty() {
            // Say so in the trace: the assurance on this card is one-sided,
            // and a reviewer (or a user wondering why a swapped card was
            // accepted) should be able to see that the weaker path was taken.
            trace::line(self.traced, || {
                "! piv authenticate: card returned no 0x82 challenge response; \
                 accepting host-only (client) authentication — this card cannot \
                 prove it holds the management key"
                    .to_string()
            });
            return Ok(());
        }
        // Verify the card encrypted our challenge correctly (authenticates the
        // card to us, completing mutual auth). Constant-time out of principle —
        // both sides are fresh per attempt, so the timing leaks nothing useful,
        // but secret-adjacent comparisons shouldn't short-circuit.
        //
        // Hardware-observed (IdPrime PIV Applet): this step's reply carries
        // the correct encrypted challenge, but under tag 0x80 (the witness
        // tag from step 1) instead of 0x82 — see
        // `keyroost_piv::compat::PivQuirk::HostChallengeResponsePermissiveTag`'s
        // doc. On a fingerprint carrying that quirk, accept whichever single
        // tag the reply's sole TLV element actually uses rather than
        // requiring 0x82.
        let z2 = if self
            .quirks()
            .contains(&keyroost_piv::compat::PivQuirk::HostChallengeResponsePermissiveTag)
        {
            piv::parse_general_auth_permissive(&resp2).map_err(TransportError::PivParse)?
        } else {
            piv::parse_general_auth(&resp2, 0x82).map_err(TransportError::PivParse)?
        };
        let expected = Zeroizing::new(block_crypt(alg, key, &challenge, CryptOp::Encrypt)?);
        if !ct_eq(z2, &expected) {
            return Err(TransportError::PivManagementAuthFailed);
        }
        Ok(())
    }

    /// The vendor fallback [`Self::authenticate_management`] uses for a HID
    /// Crescendo unit whose GET PIV PROPERTIES read doesn't name the PIV
    /// management key (`0x9B`) as a real slot object (see
    /// `Self::hid_crescendo_reports_management_key`) — HID's External
    /// Authentication sequence against the ACA (Access Control Applet)
    /// instance's XAUTH key 1:
    /// <https://docs.hidglobal.com/crescendo/api/low-level/external-auth-xauth.htm>.
    ///
    /// 1. Temporarily SELECT the ACA instance
    ///    ([`keyroost_piv::fingerprint::HID_CRESCENDO_ACA_AID`]).
    /// 2. GET CHALLENGE, and read XAUTH key 1's algorithm off the response's
    ///    own length
    ///    ([`keyroost_piv::fingerprint::hid_crescendo_xauth_key_alg`]) — the
    ///    ground truth for what this specific card's XAUTH key actually is,
    ///    regardless of what [`Self::authenticate_management`]'s caller
    ///    believed when it chose the `alg` it was called with (typically a
    ///    length-only guess here, since a card that reaches this path has
    ///    already been established not to answer GET METADATA on `0x9B` —
    ///    there's nothing on this path *to* report). `key`'s length must
    ///    match this algorithm, independent of the caller's `alg`.
    /// 3. EXTERNAL AUTHENTICATE, `key` block-encrypting the challenge
    ///    (single-block, ECB-style — the same primitive [`block_crypt`]
    ///    already runs for standard PIV management-key auth).
    /// 4. Unconditionally re-SELECT PIV, success or failure — same
    ///    discipline as every other temporary-SELECT probe in this file
    ///    (e.g. [`Self::probe_swissbit_rid`]). Unlike those probes, though,
    ///    this re-select isn't discarding anything: per NIST GSC-IS 2.1's
    ///    access-condition model, the ACA's "External Authentication"
    ///    access condition, once satisfied, is a *card-wide* grant rather
    ///    than one scoped to the ACA instance — see
    ///    [`keyroost_piv::fingerprint::HID_CRESCENDO_ACA_AID`]'s doc — so
    ///    the PIV applet is left authenticated for the same admin
    ///    operations the standard `0x9B` round would have unlocked. Callers
    ///    still need to run this (or the standard round) immediately before
    ///    the admin operation it gates, same as always: any *later*
    ///    re-select — including this method's own step 1 SELECT, on a
    ///    second call — clears it again.
    fn authenticate_management_hid_crescendo_aca(
        &mut self,
        key: &[u8],
    ) -> Result<(), TransportError> {
        use keyroost_piv::fingerprint;

        let result: Result<(), TransportError> = (|| {
            let (_, sw) =
                self.transmit_full_raw(&piv::select_by_aid(&fingerprint::HID_CRESCENDO_ACA_AID))?;
            ok_or_apdu("piv aca select", sw)?;
            self.aca_xauth_unlock(key)
        })();

        // Step 4: always switch back to PIV — see this method's doc.
        let _ = self.select();
        result
    }

    /// Steps 2–3 of the External Authentication sequence
    /// `Self::authenticate_management_hid_crescendo_aca`'s doc describes:
    /// GET CHALLENGE, then EXTERNAL AUTHENTICATE with `key` block-encrypting
    /// that challenge. Factored out (unlike that method) so
    /// `Self::hid_crescendo_aca_put_xauth_key_op` can run the same
    /// unlock immediately before PUT XAUTH KEY *without* an intervening
    /// re-SELECT back to PIV and forward to ACA again — the caller is
    /// responsible for having already SELECTed
    /// [`keyroost_piv::fingerprint::HID_CRESCENDO_ACA_AID`], and for
    /// switching back to PIV afterward, same discipline as every other
    /// temporary-SELECT probe in this file.
    fn aca_xauth_unlock(&mut self, key: &[u8]) -> Result<(), TransportError> {
        use keyroost_piv::fingerprint;

        let (challenge, sw) =
            self.transmit_full_raw(&fingerprint::HID_CRESCENDO_ACA_GET_CHALLENGE)?;
        ok_or_apdu("piv aca get challenge", sw)?;
        let alg = fingerprint::hid_crescendo_xauth_key_alg(challenge.len())
            .ok_or(TransportError::PivBadKeyLength)?;
        if key.len() != alg.key_len() {
            return Err(TransportError::PivBadKeyLength);
        }

        let cryptogram = Zeroizing::new(block_crypt(alg, key, &challenge, CryptOp::Encrypt)?);
        let apdu = Zeroizing::new(fingerprint::hid_crescendo_aca_external_authenticate(
            &cryptogram,
        ));
        let (_, sw) = self.transmit_full_raw(&apdu)?;
        if sw != piv::SW_OK {
            // Per HID's documentation, `SW = 6A 88` ("XAUTH 1 key has
            // not been initialized"), `SW = 69 85` ("Get Challenge not
            // sent before this command" — can't happen here, since the
            // GET CHALLENGE above always runs first), and `SW = 63 00`
            // ("invalid cryptogram") are all distinguished from success;
            // none gets special handling — they all just mean
            // "authentication did not succeed" — but the raw status
            // word still reaches `--debug` output here, for whoever's
            // diagnosing a real device against this.
            trace::line(self.traced, || {
                format!("piv aca external authenticate: rejected (SW {sw:04X})")
            });
            return Err(TransportError::PivManagementAuthFailed);
        }
        Ok(())
    }

    /// Present the PIV application PIN. Required before private-key use and
    /// set-pin-retries. The PIN must be 6–8 bytes — the byte layer returns a
    /// typed error on anything else rather than pad/truncate, so an unchecked
    /// over-length PIN can never silently verify (and store) something other
    /// than what the user typed, and no retry counter is consumed.
    ///
    /// Invalidates `PivSessionState::pin_retries_cache` once the card has
    /// actually answered — success resets the counter, a wrong PIN
    /// decrements it, so either way a cached count from before this call is
    /// stale. Left untouched on a transport-level failure (the early `?`
    /// below): nothing reached the card, so nothing changed.
    pub fn verify_pin(&mut self, pin: &[u8]) -> Result<(), TransportError> {
        let apdu =
            Zeroizing::new(piv::verify_pin(pin).map_err(|_| TransportError::PivBadPinLength)?);
        let (_, sw) = self.transmit_full(&apdu)?;
        self.state.pin_retries_cache = None;
        map_pin_sw(sw)
    }

    /// [`Self::verify_pin`], but against HID Crescendo's ACA (Access Control
    /// Applet) instance's own VERIFY PIN reference
    /// ([`keyroost_piv::fingerprint::HID_CRESCENDO_ACA_PIN_REF`], `P2 = 0x00`)
    /// instead of the standard PIV application-PIN reference
    /// (`PIN_REF_APPLICATION`, `P2 = 0x80`) [`Self::verify_pin`] always uses.
    /// Callers must have already SELECTed
    /// [`keyroost_piv::fingerprint::HID_CRESCENDO_ACA_AID`] — sending the
    /// standard reference while ACA is selected is not this command, and
    /// sending this one while PIV is selected wouldn't be either.
    /// `Self::hid_crescendo_aca_put_xauth_key_op`'s `Pin` branch is the
    /// sole caller.
    fn verify_pin_hid_crescendo_aca(&mut self, pin: &[u8]) -> Result<(), TransportError> {
        let apdu = Zeroizing::new(
            piv::verify_pin_at(keyroost_piv::fingerprint::HID_CRESCENDO_ACA_PIN_REF, pin)
                .map_err(|_| TransportError::PivBadPinLength)?,
        );
        let (_, sw) = self.transmit_full_raw(&apdu)?;
        map_pin_sw(sw)
    }

    /// Unlock PIV management via
    /// [`keyroost_piv::compat::PivExtension::PinManagementAuth`] instead of
    /// the standard `0x9B` management-key round: [`Self::verify_pin`], then —
    /// on every fingerprint except HID Crescendo, the one family confirmed
    /// to unlock management directly off PIN VERIFY alone — read the
    /// PIN-protected management key
    /// ([`keyroost_piv::OBJECT_PIN_PROTECTED_DATA`],
    /// [`keyroost_piv::parse_pin_protected_management_key`]) and run
    /// [`Self::authenticate_management`] with it, exactly as if the user had
    /// typed that key directly.
    ///
    /// Branches on `Self::fingerprint` directly — HID Crescendo or not —
    /// rather than on a *version*-scoped confirmation of which specific
    /// applet build actually needs the indirect read: a device whose
    /// version this crate couldn't read, or hasn't seen before, or any
    /// non-YubiKey fingerprint
    /// [`keyroost_piv::compat::PivExtension::PinManagementAuth`] still
    /// resolves `Unverified` or `Supported` for should still get the
    /// indirect read attempted, not silently skipped as if it were a
    /// *confirmed* direct-unlock device — this method would otherwise
    /// return `Ok` without ever authenticating management on exactly the
    /// devices `Unverified` exists to let a caller still try. The read
    /// below is cheap and fails cleanly
    /// ([`TransportError::PivPinProtectedKeyNotSet`]) on a card that
    /// genuinely has nothing stored there, so attempting it on everything
    /// but a *confirmed*-direct fingerprint is the safe direction to default
    /// toward.
    ///
    /// Callers should check
    /// [`keyroost_piv::compat::PivExtension::PinManagementAuth`] via
    /// [`Self::feature_gate`] before offering this at all; this method itself
    /// doesn't gate on it — a PIN VERIFY that the card accepts is taken as
    /// license to try, on the same "let the card refuse it" principle
    /// [`Self::authenticate_management`]'s own callers already follow for
    /// MOVE KEY/DELETE KEY.
    ///
    /// Errors: whatever [`Self::verify_pin`] returns for a wrong/blocked PIN;
    /// on every non-HID-Crescendo fingerprint,
    /// [`TransportError::PivPinProtectedKeyNotSet`] if no management key
    /// comes back from the read (the read failed, or succeeded with no tag
    /// `0x88` / subtag `0x89` — PIN management auth was never set up on this
    /// card); otherwise whatever [`Self::authenticate_management`] returns
    /// for the retrieved key.
    ///
    /// Deliberately does **not** consult Yubico Admin Data's tag-`0x81`
    /// PIN-protected bookkeeping bit
    /// ([`keyroost_piv::set_admin_data_pin_protected_flag`],
    /// [`keyroost_piv::OBJECT_ADMIN_DATA`]) to decide whether to attempt the
    /// read above — that bit is `ykman`'s own bookkeeping for *its* UI, not
    /// an access condition the card enforces, and a caller here (the "Use
    /// PIN" checkbox/flag) decides on its own whether to try this path,
    /// independent of whatever that bit currently says. This is intentional:
    /// it means a management key that's still sitting in
    /// [`keyroost_piv::OBJECT_PIN_PROTECTED_DATA`] can always be recovered
    /// via the PIN, even if the bit was never set, got cleared, or otherwise
    /// drifted out of sync with the object it's meant to describe — see
    /// [`Self::set_management_key_pin_protected`] for the write side that
    /// normally keeps the two in step.
    pub fn authenticate_management_via_pin(&mut self, pin: &[u8]) -> Result<(), TransportError> {
        // Resolved *before* the VERIFY below, not after: `self.fingerprint()`
        // re-SELECTs PIV when identity isn't already cached (same reasoning
        // `keyroostctl`'s own management-key flows gate on fingerprint before
        // authenticating for), which would otherwise risk dropping the PIN's
        // just-established security status before the GET DATA below gets to
        // rely on it.
        let is_hid_crescendo = matches!(
            self.fingerprint(),
            keyroost_piv::fingerprint::AppletFingerprint::HidCrescendo(_)
        );
        self.verify_pin(pin)?;
        if is_hid_crescendo {
            return Ok(());
        }
        let (data, sw) =
            self.transmit_full(&piv::get_data(&keyroost_piv::OBJECT_PIN_PROTECTED_DATA))?;
        if sw != piv::SW_OK {
            return Err(TransportError::PivPinProtectedKeyNotSet);
        }
        let key = keyroost_piv::parse_pin_protected_management_key(&data)
            .ok_or(TransportError::PivPinProtectedKeyNotSet)?;
        let alg = self.resolve_management_key_algorithm(key.len())?;
        self.authenticate_management(alg, &key)
    }

    /// Change the PIV PIN. A wrong `old` PIN consumes a try and reports the
    /// remaining count. Both PINs must be 6–8 bytes. Invalidates
    /// `PivSessionState::pin_retries_cache` the same way, and for the same
    /// reason, [`Self::verify_pin`] does.
    pub fn change_pin(&mut self, old: &[u8], new: &[u8]) -> Result<(), TransportError> {
        let apdu = Zeroizing::new(
            piv::change_reference(piv::PIN_REF_APPLICATION, old, new)
                .map_err(|_| TransportError::PivBadPinLength)?,
        );
        let (_, sw) = self.transmit_full(&apdu)?;
        self.state.pin_retries_cache = None;
        map_pin_sw(sw)
    }

    /// Change the PUK. A wrong `old` PUK consumes a try and reports the count.
    /// Both PUKs must be 6–8 bytes.
    pub fn change_puk(&mut self, old: &[u8], new: &[u8]) -> Result<(), TransportError> {
        let apdu = Zeroizing::new(
            piv::change_reference(piv::PIN_REF_PUK, old, new)
                .map_err(|_| TransportError::PivBadPinLength)?,
        );
        let (_, sw) = self.transmit_full(&apdu)?;
        map_pin_sw(sw)
    }

    /// Unblock a blocked PIN using the PUK, setting a new PIN. A wrong PUK
    /// consumes a try and reports the remaining count; a successful unblock
    /// resets the *PIN's* counter too (it's the PUK's own counter that isn't
    /// tracked here — see `PivSessionState::pin_retries_cache`'s doc for
    /// why this crate never caches that one). Both must be 6–8 bytes.
    /// Invalidates `PivSessionState::pin_retries_cache` the same way, and
    /// for the same reason, [`Self::verify_pin`] does.
    pub fn unblock_pin(&mut self, puk: &[u8], new_pin: &[u8]) -> Result<(), TransportError> {
        let apdu = Zeroizing::new(
            piv::unblock_pin(puk, new_pin).map_err(|_| TransportError::PivBadPinLength)?,
        );
        let (_, sw) = self.transmit_full(&apdu)?;
        self.state.pin_retries_cache = None;
        map_pin_sw(sw)
    }

    /// Set the PIN and PUK retry counts (resetting both to their defaults).
    /// Requires prior management-key auth **and** a verified PIN. Invalidates
    /// `PivSessionState::pin_retries_cache`: this resets the PIN counter to
    /// its (possibly new) default, same as a successful [`Self::verify_pin`]
    /// would, just without presenting a PIN to do it.
    pub fn set_pin_retries(&mut self, pin_tries: u8, puk_tries: u8) -> Result<(), TransportError> {
        let (_, sw) = self.transmit_full(&piv::set_pin_retries(pin_tries, puk_tries))?;
        ok_or_write("piv set pin retries", sw)?;
        self.state.pin_retries_cache = None;
        Ok(())
    }

    /// Replace the card-management key with `(alg, key)`. Requires prior
    /// management-key auth ([`Self::authenticate_management`] /
    /// [`Self::authenticate_management_via_pin`]) — **except** on a HID
    /// Crescendo unit whose GET PIV PROPERTIES read doesn't name `0x9B` as a
    /// real slot object (see `Self::hid_crescendo_reports_management_key`):
    /// there, the "management key" is the ACA's XAUTH key 1, not a real PIV
    /// object, changed with HID's own PUT XAUTH KEY command instead of the
    /// standard SET MANAGEMENT KEY extension — see
    /// `Self::hid_crescendo_aca_put_xauth_key_op` for that path, which
    /// takes `current` to run its own self-contained unlock rather than
    /// relying on a prior call's access condition still being in force.
    /// Every other fingerprint ignores `current` entirely.
    pub fn set_management_key(
        &mut self,
        current: CurrentMgmtAuth<'_>,
        alg: MgmtAlg,
        key: &[u8],
        require_touch: bool,
    ) -> Result<(), TransportError> {
        if key.len() != alg.key_len() {
            return Err(TransportError::PivBadKeyLength);
        }
        if let keyroost_piv::fingerprint::AppletFingerprint::HidCrescendo(variant) =
            self.fingerprint()
        {
            if !self.hid_crescendo_reports_management_key(variant) {
                return self.hid_crescendo_aca_put_xauth_key_op(
                    current,
                    HidCrescendoXauthKeyOp::Set(alg, key),
                );
            }
        }
        let apdu = Zeroizing::new(piv::set_management_key(alg, key, require_touch));
        let (_, sw) = self.transmit_full(&apdu)?;
        ok_or_write("piv set management key", sw)
    }

    /// Delete HID Crescendo's ACA XAUTH key 1 outright, rather than
    /// replacing it — the "Delete" option in the management-key rotation UI,
    /// offered only when `Self::fingerprint` resolves to
    /// [`keyroost_piv::fingerprint::AppletFingerprint::HidCrescendo`] with no
    /// real `0x9B` slot object (see
    /// `Self::hid_crescendo_reports_management_key`) — every other applet
    /// has no equivalent operation, since a standard PIV management key is
    /// mandatory and can only be *replaced*, never removed. Returns
    /// [`TransportError::PivManagementKeyDeleteUnsupported`] if `self` isn't
    /// that specific device; a caller that only offers this option when
    /// `Self::fingerprint` already says so should never actually hit that
    /// error unless the card was swapped mid-flow.
    ///
    /// Runs the same select/unlock/reselect sequence
    /// `Self::hid_crescendo_aca_put_xauth_key_op` documents, with
    /// `HidCrescendoXauthKeyOp::Delete` in place of `Set`.
    pub fn delete_management_key_hid_crescendo(
        &mut self,
        current: CurrentMgmtAuth<'_>,
    ) -> Result<(), TransportError> {
        let keyroost_piv::fingerprint::AppletFingerprint::HidCrescendo(variant) =
            self.fingerprint()
        else {
            return Err(TransportError::PivManagementKeyDeleteUnsupported);
        };
        if self.hid_crescendo_reports_management_key(variant) {
            return Err(TransportError::PivManagementKeyDeleteUnsupported);
        }
        self.hid_crescendo_aca_put_xauth_key_op(current, HidCrescendoXauthKeyOp::Delete)
    }

    /// Read Yubico Admin Data ([`keyroost_piv::OBJECT_ADMIN_DATA`]) with the
    /// outer `0x53` template stripped, or an empty `Vec` if GET DATA fails —
    /// the object is created lazily by Yubico's own tooling on first write,
    /// so "not found" here just means "never configured", not a transport
    /// error. Only a genuine transport failure (the `?` below) propagates.
    fn read_admin_data_inner(&mut self) -> Result<Vec<u8>, TransportError> {
        let (data, sw) = self.transmit_full(&piv::get_data(&keyroost_piv::OBJECT_ADMIN_DATA))?;
        if sw != piv::SW_OK {
            return Ok(Vec::new());
        }
        Ok(keyroost_piv::unwrap_data_object(&data)
            .map(<[u8]>::to_vec)
            .unwrap_or_default())
    }

    /// Set or clear the PIN-protected-management-key bit in Admin Data — see
    /// [`keyroost_piv::set_admin_data_pin_protected_flag`] for exactly what
    /// changes and what's preserved (every other bit of the same flags
    /// byte, every other subtag, every other top-level object byte). A true
    /// no-op — nothing sent to the card — when `set = false` and the bit
    /// was never configured, per that function's own contract.
    ///
    /// Best-effort on the write: Admin Data (`keyroost_piv::OBJECT_ADMIN_DATA`)
    /// is a Yubico proprietary extension, not something SP 800-73-4 obligates
    /// every PIV implementation to carry — a PUT DATA rejection (any `SW !=
    /// 9000`) is traced and treated as "this device doesn't have this
    /// object," not propagated as an error. The bit is bookkeeping for
    /// `ykman`-style UIs; [`Self::authenticate_management_via_pin`] never
    /// reads it back (see that method's own doc), so a caller here — via
    /// [`Self::set_management_key_pin_protected`] — still has the
    /// substantive [`keyroost_piv::OBJECT_PIN_PROTECTED_DATA`] write left to
    /// run regardless of whether this one lands. Only a genuine transport
    /// failure (the `?`s below, before a status word is even in hand)
    /// propagates.
    fn update_admin_data_pin_protected_flag(&mut self, set: bool) -> Result<(), TransportError> {
        let existing = self.read_admin_data_inner()?;
        let Some(patched) = keyroost_piv::set_admin_data_pin_protected_flag(&existing, set) else {
            return Ok(());
        };
        let apdu = piv::put_data(&keyroost_piv::OBJECT_ADMIN_DATA, &patched);
        let (_, sw) = self.transmit_full(&apdu)?;
        if sw != piv::SW_OK {
            trace::line(self.traced, || {
                format!(
                    "piv put admin data: rejected (SW {sw:04X}) — treating as \
                     unsupported on this device, not an error"
                )
            });
        }
        Ok(())
    }

    /// Store `key` in Yubico's PIN-protected management-key object
    /// ([`keyroost_piv::OBJECT_PIN_PROTECTED_DATA`]) — the write-side
    /// counterpart of what [`Self::authenticate_management_via_pin`] reads
    /// back after a bare PIN VERIFY. Requires the same management-key auth
    /// [`Self::set_management_key`] does.
    fn write_pin_protected_management_key(&mut self, key: &[u8]) -> Result<(), TransportError> {
        let inner = keyroost_piv::build_pin_protected_management_key(key);
        let apdu = Zeroizing::new(piv::put_data(
            &keyroost_piv::OBJECT_PIN_PROTECTED_DATA,
            &inner,
        ));
        let (_, sw) = self.transmit_full(&apdu)?;
        ok_or_write("piv put pin-protected management key", sw)
    }

    /// Erase Yubico's PIN-protected management-key object
    /// ([`keyroost_piv::OBJECT_PIN_PROTECTED_DATA`]) — `Self::write_pin_protected_management_key`'s
    /// undo, written back with a zero-length value, the same "PUT DATA with
    /// an empty `0x53`" convention [`keyroost_piv::clear_certificate`]
    /// already uses to wipe an optional PIV data object. Unconditional: run
    /// whether or not anything was actually stored there — an empty PUT
    /// DATA against an object that was already empty is a harmless no-op on
    /// the card.
    fn clear_pin_protected_management_key(&mut self) -> Result<(), TransportError> {
        let apdu = piv::put_data(&keyroost_piv::OBJECT_PIN_PROTECTED_DATA, &[]);
        let (_, sw) = self.transmit_full(&apdu)?;
        ok_or_write("piv clear pin-protected management key", sw)
    }

    /// [`Self::set_management_key`], plus — on every fingerprint except HID
    /// Crescendo, which already unlocks management off a bare PIN VERIFY
    /// with no key material to store (see
    /// [`keyroost_piv::compat::PivExtension::PinManagementAuth`]'s doc) —
    /// maintaining Yubico's PIN-protected management-key storage (`ykman
    /// piv access change-management-key --protect`'s equivalent):
    ///
    /// - `allow_pin_unlock = false`: best-effort clear the Admin Data
    ///   PIN-protected bit (`Self::update_admin_data_pin_protected_flag`);
    ///   left alone if it was never configured. Then erase
    ///   [`keyroost_piv::OBJECT_PIN_PROTECTED_DATA`] itself
    ///   (`Self::clear_pin_protected_management_key`) — a key this
    ///   caller is deliberately marking as no longer PIN-unlockable
    ///   shouldn't keep sitting recoverable-via-PIN on the card.
    /// - `allow_pin_unlock = true`: set the bit, then
    ///   `Self::write_pin_protected_management_key` with the new `key`,
    ///   so [`Self::authenticate_management_via_pin`] can retrieve it after
    ///   a bare PIN VERIFY.
    ///
    /// [`Self::authenticate_management_via_pin`] never reads the Admin Data
    /// bit back — see that method's own doc for why — so it's
    /// [`keyroost_piv::OBJECT_PIN_PROTECTED_DATA`]'s own content, not the
    /// bit, that actually decides whether the PIN can unlock management.
    /// Both branches above try to keep the two in step, but
    /// `Self::update_admin_data_pin_protected_flag` is best-effort — a
    /// device with no Admin Data object at all (see that method's own doc)
    /// simply keeps whatever it never had, while
    /// [`keyroost_piv::OBJECT_PIN_PROTECTED_DATA`] itself still gets
    /// written/cleared either way — so this is a "try to stay in step, but
    /// the actual behavior is governed by the object that matters" contract,
    /// not a guarantee. A caller that only wants the bookkeeping bit changed
    /// without touching the stored key either way has no method here for
    /// that — this one always attempts both together.
    ///
    /// `current`/`alg`/`key`/`require_touch` are exactly
    /// [`Self::set_management_key`]'s own parameters, threaded through
    /// unchanged — including to the HID Crescendo XAUTH path, which runs its
    /// own self-contained unlock from `current` rather than relying on prior
    /// auth still being in force (see [`Self::set_management_key`]'s doc).
    ///
    /// This method itself doesn't gate `allow_pin_unlock` on
    /// [`keyroost_piv::compat::PivExtension::PinManagementAuth`] — callers
    /// (`keyroostctl`, the GUI) each already resolve that gate to drive
    /// their own UI/CLI messaging (a disabled checkbox, a `--force`
    /// requirement) and are expected to have decided whether to call this
    /// at all — with `allow_pin_unlock` true *or* false — before reaching
    /// here, rather than relying on this method to refuse anything.
    ///
    /// Returns a [`PinProtectMaintenance`] describing whether the
    /// maintenance step ran at all, and — if it did — how the substantive
    /// [`keyroost_piv::OBJECT_PIN_PROTECTED_DATA`] write/clear went; see
    /// that type's own doc for how a caller should weigh a failure there
    /// against [`keyroost_piv::compat::PivExtension::PinManagementAuth`]'s
    /// gate. This method itself doesn't make that call — it always returns
    /// the outcome rather than turning a failed write into an `Err` here,
    /// since only the caller knows whether this device's gate makes that
    /// failure expected or alarming.
    pub fn set_management_key_pin_protected(
        &mut self,
        current: CurrentMgmtAuth<'_>,
        alg: MgmtAlg,
        key: &[u8],
        require_touch: bool,
        allow_pin_unlock: bool,
    ) -> Result<PinProtectMaintenance, TransportError> {
        self.set_management_key(current, alg, key, require_touch)?;
        // `self.fingerprint()` is a cached read at this point — the same
        // call inside `set_management_key` above already resolved and
        // cached session identity, so this doesn't re-SELECT and drop the
        // management-key authentication the writes below still need.
        if let keyroost_piv::fingerprint::AppletFingerprint::HidCrescendo(_) = self.fingerprint() {
            return Ok(PinProtectMaintenance::NotApplicable);
        }
        // Best-effort regardless of outcome (see its own doc) — never
        // propagated as the reason the overall maintenance step failed.
        self.update_admin_data_pin_protected_flag(allow_pin_unlock)?;
        let printed_data = if allow_pin_unlock {
            self.write_pin_protected_management_key(key)
        } else {
            self.clear_pin_protected_management_key()
        };
        Ok(PinProtectMaintenance::Ran { printed_data })
    }

    /// The vendor fallback [`Self::set_management_key`]/
    /// [`Self::delete_management_key_hid_crescendo`] use for a HID Crescendo
    /// unit that doesn't model the PIV management key (`0x9B`) as a real slot
    /// object (see `Self::hid_crescendo_reports_management_key`): PUT XAUTH
    /// KEY against the ACA (Access Control Applet) instance's XAUTH key 1,
    /// per the user-provided sequence:
    ///
    /// 1. Temporarily SELECT the ACA instance
    ///    ([`keyroost_piv::fingerprint::HID_CRESCENDO_ACA_AID`]).
    /// 2. Unlock: [`Self::verify_pin_hid_crescendo_aca`] for
    ///    [`CurrentMgmtAuth::Pin`] — **not** [`Self::verify_pin`], which
    ///    uses the standard PIV application-PIN reference rather than the
    ///    one ACA's own VERIFY PIN answers at — or
    ///    [`Self::aca_xauth_unlock`] (the same GET CHALLENGE / EXTERNAL
    ///    AUTHENTICATE round `Self::authenticate_management_hid_crescendo_aca`
    ///    runs) for [`CurrentMgmtAuth::Key`] — this method's own unlock,
    ///    run fresh rather than assumed still in force from an earlier
    ///    [`Self::authenticate_management`] /
    ///    [`Self::authenticate_management_via_pin`] call, since installing or
    ///    deleting a XAUTH key happens on the ACA instance itself and this
    ///    method has no way to know whether an unlock elsewhere actually
    ///    persisted this far.
    /// 3. [`HidCrescendoXauthKeyOp::Set`] runs
    ///    [`keyroost_piv::fingerprint::hid_crescendo_aca_put_xauth_key`] with
    ///    the new `(alg, key)` — `alg` must be
    ///    [`MgmtAlg::TripleDes`]/[`MgmtAlg::Aes128`] — the only two
    ///    algorithms ACA XAUTH supports —
    ///    [`TransportError::PivBadKeyLength`] for anything else, same error
    ///    the length mismatch in [`Self::set_management_key`] already uses.
    ///    `HidCrescendoXauthKeyOp::Delete` runs
    ///    [`keyroost_piv::fingerprint::hid_crescendo_aca_put_xauth_key_remove`]
    ///    instead, unconditionally.
    /// 4. Unconditionally re-SELECT PIV, success or failure — same
    ///    discipline as `Self::authenticate_management_hid_crescendo_aca`
    ///    and every other temporary-SELECT probe in this file.
    fn hid_crescendo_aca_put_xauth_key_op(
        &mut self,
        current: CurrentMgmtAuth<'_>,
        op: HidCrescendoXauthKeyOp<'_>,
    ) -> Result<(), TransportError> {
        use keyroost_piv::fingerprint;

        let result: Result<(), TransportError> = (|| {
            let (_, sw) =
                self.transmit_full_raw(&piv::select_by_aid(&fingerprint::HID_CRESCENDO_ACA_AID))?;
            ok_or_apdu("piv aca select", sw)?;

            match current {
                CurrentMgmtAuth::Pin(pin) => self.verify_pin_hid_crescendo_aca(pin)?,
                CurrentMgmtAuth::Key(current_key) => self.aca_xauth_unlock(current_key)?,
            }

            let apdu = Zeroizing::new(match op {
                HidCrescendoXauthKeyOp::Set(alg, key) => {
                    fingerprint::hid_crescendo_aca_put_xauth_key(alg, key)
                        .ok_or(TransportError::PivBadKeyLength)?
                }
                HidCrescendoXauthKeyOp::Delete => {
                    fingerprint::hid_crescendo_aca_put_xauth_key_remove()
                }
            });
            let (_, sw) = self.transmit_full_raw(&apdu)?;
            ok_or_write("piv aca put xauth key", sw)
        })();

        // Step 4: always switch back to PIV — see this method's doc.
        let _ = self.select();
        result
    }

    /// HID Crescendo's device-wide reset — the mechanism behind
    /// [`keyroost_piv::compat::PivExtension::ResetGlobal`]: SELECT the ACA
    /// instance, authenticate with `pre_reset_mgmt_auth` (PIN or XAUTH key — the same
    /// choice `Self::hid_crescendo_aca_put_xauth_key_op` takes, run fresh
    /// here for the same reason that method's doc gives), send RESET CARD
    /// ([`keyroost_piv::fingerprint::HID_CRESCENDO_ACA_RESET_CARD`]), then
    /// restore XAUTH key 1 to HID's documented factory-delivery value —
    /// read via [`keyroost_piv::compat::default_9b_management_key`] off this
    /// fingerprint's [`keyroost_piv::compat::PivQuirk::Default9bManagementKey`]
    /// row (seeded with
    /// [`keyroost_piv::fingerprint::HID_CRESCENDO_ACA_FACTORY_XAUTH_KEY`],
    /// the single source of truth for the value) rather than the constant
    /// hard-coded a second time — RESET CARD clears the key outright, but
    /// the as-delivered state ships with it already set to this all-zero
    /// key, and restoring it is also what keeps the device recoverable by
    /// XAUTH alone if a later mistake ever blocks the ACA's own PIN. See
    /// [`keyroost_piv::fingerprint::HID_CRESCENDO_ACA_RESET_CARD`]'s doc for
    /// exactly what gets wiped (PIV's PKI keys and data containers always;
    /// OATH and, on C4000 only as documented, FIDO — family-dependent).
    ///
    /// **Confirmed on hardware:** the ACA's authenticated security status
    /// does *not* survive RESET CARD, so the PUT XAUTH KEY restore step
    /// right after it re-authenticates first — against
    /// [`keyroost_piv::fingerprint::HID_CRESCENDO_ACA_PIN_AFTER_RESET`], the
    /// PIN RESET CARD itself just rewrote the card to, not against
    /// `pre_reset_mgmt_auth` (which no longer verifies once the reset has
    /// run). If that
    /// re-authentication or the restore itself fails, RESET CARD still
    /// succeeded (the device is fully reset), which reports as
    /// [`FactoryResetOutcome::WipedKeyRestoreFailed`] rather than a hard
    /// error — a caller must not read that as "nothing happened."
    ///
    /// Only the restore step's failure is soft. Every earlier failure — the
    /// SELECT, the authentication, or RESET CARD itself (`SW = 69 82`,
    /// mapped by [`ok_or_write`] to [`TransportError::PivSecurityNotSatisfied`],
    /// same status word and same mapping `Self::hid_crescendo_aca_put_xauth_key_op`
    /// relies on) — means the device was never touched, and propagates as a
    /// normal `Err`.
    ///
    /// Always re-SELECTs PIV afterward, whatever the outcome — same
    /// discipline as `Self::hid_crescendo_aca_put_xauth_key_op` and every
    /// other temporary-SELECT probe in this file.
    ///
    /// Private: [`Self::factory_reset`] is the one public entry point for
    /// every `PivExtension::Reset`/`ResetGlobal` mechanism this crate
    /// implements — it decides on its own, from the live fingerprint,
    /// whether this method is even the right one to reach for, and wraps
    /// whatever `Err` it returns in [`TransportError::PivResetGlobalFailed`]
    /// so a caller can tell a device-wide-mechanism failure apart from a
    /// burn-dance one. A caller that wants this specific mechanism without
    /// that fingerprint check has no way to ask for it directly any more —
    /// by design, since bypassing the check is exactly what let a caller
    /// attempt HID's ACA RESET CARD against a device that was never
    /// confirmed to have one.
    fn hid_crescendo_aca_reset_card(
        &mut self,
        pre_reset_mgmt_auth: CurrentMgmtAuth<'_>,
    ) -> Result<FactoryResetOutcome, TransportError> {
        use keyroost_piv::fingerprint;

        // Resolved up front, before the ACA gets SELECTed below: this reads
        // `Self::quirks`, which (via `Self::identity`) may itself need to
        // talk to the card the first time it's called in a session, and that
        // has to happen against the currently selected PIV applet, not mid
        // ACA sequence. `PivQuirk::Default9bManagementKey` on this
        // fingerprint's row is always seeded with
        // `fingerprint::HID_CRESCENDO_ACA_FACTORY_XAUTH_KEY` — see that
        // quirk's doc — so the fallback below is purely defensive, never
        // actually reached for a fingerprint that got this far at all.
        let restore_key = keyroost_piv::compat::default_9b_management_key(&self.quirks())
            .unwrap_or(&fingerprint::HID_CRESCENDO_ACA_FACTORY_XAUTH_KEY);

        let result: Result<FactoryResetOutcome, TransportError> = (|| {
            let (_, sw) =
                self.transmit_full_raw(&piv::select_by_aid(&fingerprint::HID_CRESCENDO_ACA_AID))?;
            ok_or_apdu("piv aca select", sw)?;

            match pre_reset_mgmt_auth {
                CurrentMgmtAuth::Pin(pin) => self.verify_pin_hid_crescendo_aca(pin)?,
                CurrentMgmtAuth::Key(current_key) => self.aca_xauth_unlock(current_key)?,
            }

            let (_, sw) = self.transmit_full_raw(&fingerprint::HID_CRESCENDO_ACA_RESET_CARD)?;
            ok_or_write("piv aca reset card", sw)?;

            // Wiped. Everything from here on is the factory-XAUTH-key
            // courtesy restore, not the reset itself — its failure must not
            // read as if RESET CARD had failed.
            //
            // RESET CARD drops the ACA's authenticated security status
            // (confirmed on hardware — see this method's doc) and rewrites
            // its PIN to HID's documented reset-default, so PUT XAUTH KEY
            // below needs a fresh authenticated session against that
            // default, not against `pre_reset_mgmt_auth`. A failure here is
            // folded into the same soft `WipedKeyRestoreFailed` as the
            // restore itself: the device is wiped either way.
            if let Err(e) =
                self.verify_pin_hid_crescendo_aca(fingerprint::HID_CRESCENDO_ACA_PIN_AFTER_RESET)
            {
                trace::line(self.traced, || {
                    format!(
                        "piv aca reauth after reset card (restore factory default): \
                         failed ({e})"
                    )
                });
                return Ok(FactoryResetOutcome::WipedKeyRestoreFailed);
            }

            // `hid_crescendo_aca_put_xauth_key` returning `None` can't
            // actually happen (`restore_key` is 24 bytes, matching
            // `MgmtAlg::TripleDes` exactly), but it's treated as a restore
            // failure rather than unwrapped, so an internal slip here can
            // never panic a destructive device operation.
            let outcome = match fingerprint::hid_crescendo_aca_put_xauth_key(
                keyroost_piv::MgmtAlg::TripleDes,
                restore_key,
            ) {
                Some(apdu) => match self.transmit_full_raw(&apdu) {
                    Ok((_, sw)) if sw == piv::SW_OK => FactoryResetOutcome::WipedGlobal,
                    Ok((_, sw)) => {
                        trace::line(self.traced, || {
                            format!(
                                "piv aca put xauth key (restore factory default): \
                                 rejected (SW {sw:04X})"
                            )
                        });
                        FactoryResetOutcome::WipedKeyRestoreFailed
                    }
                    Err(_) => FactoryResetOutcome::WipedKeyRestoreFailed,
                },
                None => FactoryResetOutcome::WipedKeyRestoreFailed,
            };
            Ok(outcome)
        })();

        // Always switch back to PIV — see this method's doc.
        let _ = self.select();
        result
    }

    /// Generate a fresh asymmetric key pair in `slot`, returning its public key.
    /// Requires prior management-key auth. Overwrites any existing key in the
    /// slot. May require a touch if the slot's touch policy demands it.
    ///
    /// Also clears `slot`'s certificate object, if any: a certificate left
    /// over from the key this just overwrote would still carry the *old*
    /// public key, silently mismatching the slot's new private key. Standard
    /// PIV's empty-PUT-DATA clear ([`Self::clear_certificate`]) is universal
    /// across firmware, so this runs unconditionally rather than only when a
    /// certificate happens to be present.
    ///
    /// On success, also caches `(alg, public key)` for `slot` in this
    /// session's in-memory key cache, since [`Self::slot_key`] and
    /// [`Self::slot_key_algorithm`]'s only other source for a key this fresh
    /// (the slot's certificate) doesn't exist yet on cards that don't answer
    /// GET METADATA. That only covers later calls *within this same
    /// session* — a caller that needs the key material to outlive this
    /// session (a separate `keyroostctl` invocation, or the GUI's
    /// fresh-session-per-action pattern) has to carry it forward itself and
    /// hand it to a later session via [`Self::remember_pubkey`]; see that
    /// method's doc comment for why this deliberately doesn't do that on its
    /// own.
    ///
    /// Also evicts any `PolicyCache` entry already cached for `slot` — it
    /// describes the *old* key, if this slot held one — before reseeding it
    /// with whatever [`Self::slot_policy`] reads back afterward: not with
    /// `pin_policy`/`touch_policy` themselves (a request, not a result: this
    /// instruction's response is the public key blob alone, no policy
    /// confirmation, and a card is free to translate a requested policy into
    /// something else on its own terms — e.g. a `Default` axis becomes *some*
    /// concrete native default only the card knows, but nothing rules out a
    /// card normalizing even an explicit request to a value of its own
    /// choosing either), but with the real GET METADATA/ATTEST resolution,
    /// exactly like any other [`Self::slot_policy`] call. That method always
    /// leaves the slot resolved one way or another, including "neither
    /// channel names a policy", so this never leaves a slot uncached even on
    /// a card with no policy-reporting channel at all.
    pub fn generate_key(
        &mut self,
        slot: Slot,
        alg: KeyAlg,
        pin_policy: PinPolicy,
        touch_policy: TouchPolicy,
    ) -> Result<PublicKey, TransportError> {
        let alg_id = self.slot_key_algorithm_apdu_id(alg);
        let (data, sw) =
            self.transmit_full(&piv::generate_key(slot, alg_id, pin_policy, touch_policy))?;
        ok_or_write("piv generate key", sw)?;
        let key = piv::parse_public_key(&data).map_err(TransportError::PivParse)?;
        // The new key just overwrote whatever was in `slot`; any existing
        // certificate now names a public key that no longer matches it.
        self.clear_certificate(slot)?;
        // Whatever policy was cached for `slot` before this call describes
        // the *old* key, not this one. Evict before `slot_policy` below
        // reads it back, so that read sees the card's actual answer for the
        // new key instead of a stale cached one for the old.
        self.state.policy_cache.evict(slot.key_ref());
        // Likewise evict `pubkey_cache` — and do it *before* `slot_policy`
        // below, not just before returning. Whatever this slot resolved to
        // before (an old key here already, or a confirmed-empty `None` for
        // a slot that just got its first key) is exactly the kind of
        // "already resolved" entry `cached_slot_key` trusts without a device
        // round trip. `slot_policy`'s GET METADATA step goes through
        // `cached_slot_key`, so a stale entry here — not just a stale
        // `policy_cache` entry — makes it skip the live metadata read (and
        // its policy tag) entirely, forcing every generate onto the ATTEST
        // fallback, and on firmware/quirks where that fallback comes up
        // empty, permanently caching "no policy" for a slot GET METADATA
        // could have answered correctly. This is the common case, not an
        // edge one: a slot's key/policy is typically already resolved (an
        // earlier status read, or an old key being regenerated) by the time
        // `generate_key` runs on it.
        self.state.pubkey_cache.evict(slot.key_ref());
        // `slot_policy` reads (and caches) the policy the card actually
        // ended up applying — the *request* above is not trustworthy enough
        // to cache directly, so this doesn't try to shortcut from
        // `pin_policy`/`touch_policy`.
        let _ = self.slot_policy(slot);
        // Seed (or, on firmware with GET METADATA, re-confirm) the new
        // key's material from GENERATE's own response — the one source
        // that's authoritative even when the metadata read `slot_policy`
        // just did above found nothing (pre-5.3 firmware), where
        // `cached_slot_key` would otherwise have left this slot cached as
        // `None`.
        self.state
            .pubkey_cache
            .remember(slot.key_ref(), Some((alg, key.clone())));
        Ok(key)
    }

    /// Seed this session's key-material cache for `slot` with `(alg, key)`
    /// directly, without a card round-trip — the same `PubkeyCache`
    /// [`Self::generate_key`] populates, and the same one [`Self::slot_key`]/
    /// [`Self::slot_key_algorithm`] read when the device hasn't (yet, or
    /// ever) reported anything better.
    ///
    /// This is the deliberately-explicit replacement for what used to be an
    /// automatic on-disk cache: `PivSession` itself keeps no persistence
    /// (no file, nothing cross-process) — a fresh `open()` always starts
    /// empty, by design, so key material a caller isn't actively using never
    /// sits on disk. A caller that needs a metadata-less card's freshly
    /// generated key to survive past this session (a later `keyroostctl`
    /// invocation, or the GUI reopening a session for a later action) has to
    /// hold onto `(alg, key)` itself — in its own process-lifetime state, or
    /// wherever the user chose to put it — and call this before the call that
    /// needs it (`generate_csr`, `self_signed_certificate`, or checking
    /// `slot_key_algorithm` for display). Not verified against the card in
    /// any way when written — but [`Self::slot_key`] (via
    /// `Self::confirmed_slot_key`) always re-confirms live before trusting
    /// it for a signing operation, so a caller handing over the wrong slot's
    /// key gets caught there whenever the device has any channel to check
    /// against; only a genuinely metadata-less card leaves this exactly as
    /// trustworthy as whoever called this.
    pub fn remember_pubkey(&mut self, slot: Slot, alg: KeyAlg, key: PublicKey) {
        self.state
            .pubkey_cache
            .remember(slot.key_ref(), Some((alg, key)));
    }

    /// Import a DER-encoded X.509 certificate into `slot`. Requires prior
    /// management-key auth.
    ///
    /// Refuses outright — before any APDU reaches the card — on either of two
    /// independent checks, primary then secondary:
    ///
    /// 1. **Full key material.** When this session already knows `slot`'s
    ///    current public key ([`Self::slot_key`]: GET METADATA, or this
    ///    session's generate/`remember_pubkey` cache) and the certificate
    ///    carries a different one, byte for byte — see
    ///    [`TransportError::PivImportCertificateKeyMismatch`].
    /// 2. **Algorithm only**, when step 1 couldn't run at all (`slot_key`
    ///    failed — metadata-less firmware with nothing cached this session).
    ///    [`keyroost_piv::compat::PivExtension::GetSlotKeyStatus`] resolving
    ///    [`FeatureGate::Supported`](keyroost_piv::compat::FeatureGate::Supported)
    ///    for this fingerprint means its own live, device-reported channel
    ///    (GET METADATA's `algorithm` field, or HID Crescendo's GET PIV
    ///    PROPERTIES) can still name the slot's algorithm even without full
    ///    key material — see `Self::slot_key_status_algorithm`. An RSA slot
    ///    receiving an ECC certificate (or any other algorithm mismatch)
    ///    fails here even though the exact key bytes were never compared —
    ///    see [`TransportError::PivImportCertificateAlgorithmMismatch`].
    ///
    /// Neither check is the same as "is the slot empty" — a caller wanting to
    /// block import on a confirmed-empty slot needs `GetSlotKeyStatus`'s gate
    /// directly, same as [`Self::delete_key`]'s UI-side dimming does; both
    /// checks above only ever fire when there is something to actually
    /// compare, and never on an empty slot (there is nothing to mismatch
    /// against there). Every remaining "unknowable" case — `GetSlotKeyStatus`
    /// not resolving `Supported` either, or a certificate whose
    /// `SubjectPublicKeyInfo` this crate's minimal X.509 reader can't parse —
    /// falls through to allowing the import: absence of information is not
    /// evidence of a mismatch.
    ///
    /// Tries a single extended-length PUT DATA first; a cert big enough to
    /// need one (any real X.509 cert typically is) that gets rejected falls
    /// back to ISO 7816-4 command chaining — see [`Self::sign`] for why. The
    /// fallback also runs when the extended APDU fails at the PC/SC layer
    /// before any status word comes back (seen with certificates of a few
    /// KB). A card that refuses the certificate's length or has no room for
    /// it yields [`TransportError::PivCertTooLarge`] /
    /// [`TransportError::PivCardFull`].
    pub fn import_certificate(&mut self, slot: Slot, der: &[u8]) -> Result<(), TransportError> {
        self.reject_certificate_key_mismatch(slot, der)?;
        let value = piv::encode_certificate(der);
        let tag = slot.cert_object_tag();
        let apdu = piv::put_data(&tag, &value);
        let sw = if self.chain_upfront() {
            trace::line(self.traced, || {
                format!(
                    "! piv import certificate: command chaining up front ({})",
                    self.chain_reason()
                )
            });
            chained_cert_sw(self.transmit_chain(
                "piv import certificate",
                &piv::put_data_chained(&tag, &value, CHAIN_CHUNK),
            ))?
        } else {
            let extended = uses_extended_length(&apdu);
            let direct = self.transmit_full(&apdu);
            if retry_chained_after(&direct, extended) {
                if let Err(e) = &direct {
                    trace::line(self.traced, || {
                        format!(
                            "! piv import certificate: extended length failed at the PC/SC \
                             layer ({e}); retrying with command chaining"
                        )
                    });
                }
                chained_cert_sw(self.transmit_chain(
                    "piv import certificate",
                    &piv::put_data_chained(&tag, &value, CHAIN_CHUNK),
                ))?
            } else {
                let (_, sw) = direct?;
                if sw == piv::SW_OK || !extended {
                    sw
                } else {
                    trace::line(self.traced, || {
                        format!(
                            "! piv import certificate: extended length rejected (SW={sw:04X}); \
                             retrying with command chaining"
                        )
                    });
                    chained_cert_sw(self.transmit_chain(
                        "piv import certificate",
                        &piv::put_data_chained(&tag, &value, CHAIN_CHUNK),
                    ))?
                }
            }
        };
        cert_write_result(slot, der.len(), sw)?;
        // Written; no need to read it back — this is exactly what
        // `Self::read_certificate` would resolve to now.
        self.state
            .cert_cache
            .remember(slot.key_ref(), Ok(Some(der.to_vec())));
        Ok(())
    }

    /// [`Self::import_certificate`]'s pre-flight key check — see that
    /// method's doc for what triggers each of its two refusals versus what
    /// falls through to "allow". Split out so the early-returns (`slot_key`
    /// failing, either side's algorithm/key parse failing) read as the
    /// "can't verify" cases they are, not folded into `import_certificate`'s
    /// own control flow.
    fn reject_certificate_key_mismatch(
        &mut self,
        slot: Slot,
        der: &[u8],
    ) -> Result<(), TransportError> {
        let Ok((slot_alg, slot_key)) = self.slot_key(slot) else {
            // Full key material unknowable here — fall back to the weaker,
            // algorithm-only check below rather than giving up entirely.
            let gate = self.extension_gate(keyroost_piv::compat::PivExtension::GetSlotKeyStatus);
            let status_alg = self.slot_key_status_algorithm(slot);
            let cert_only_alg = keyroost_piv::x509_parse::parse_key_algorithm(der)
                .ok()
                .flatten();
            return match algorithm_only_mismatch(gate, status_alg, cert_only_alg) {
                Some((slot_algorithm, certificate_algorithm)) => {
                    Err(TransportError::PivImportCertificateAlgorithmMismatch {
                        slot,
                        slot_algorithm,
                        certificate_algorithm,
                    })
                }
                None => Ok(()),
            };
        };
        let Ok((cert_alg, cert_key)) = keyroost_piv::x509_parse::parse_certificate_public_key(der)
        else {
            return Ok(());
        };
        if certificate_key_mismatches(slot_alg, &slot_key, cert_alg, &cert_key) {
            return Err(TransportError::PivImportCertificateKeyMismatch(slot));
        }
        Ok(())
    }

    /// `slot`'s algorithm via [`keyroost_piv::compat::PivExtension::GetSlotKeyStatus`]'s
    /// own live, device-reported channel — GET METADATA's `algorithm` field
    /// alone (no public key required, unlike [`Self::slot_key`]/
    /// `metadata_key_material`) for any Yubico-compatible fingerprint, or HID
    /// Crescendo's own GET PIV PROPERTIES read
    /// (`Self::hid_crescendo_slot_algorithm`) for that family. Deliberately
    /// *not* [`Self::slot_key_algorithm`], and deliberately calling
    /// [`Self::metadata`] directly rather than going through `PubkeyCache`
    /// (via `Self::cached_slot_key`/`Self::confirmed_slot_key`) at all:
    /// this must never fall back to — or get confused with — the
    /// self-known slice of that cache (not device-reported — a caller of
    /// [`Self::reject_certificate_key_mismatch`] already tried the full
    /// cache, via [`Self::slot_key`], before reaching here, precisely
    /// because *that* check needs an independent, never-self-vouched
    /// corroborating source) nor to the slot's existing certificate (not
    /// independent evidence — it's exactly the object about to be
    /// overwritten, and may itself be stale). A caller can trust a `Some`
    /// here as much as `GetSlotKeyStatus`'s own gate for this fingerprint —
    /// check that gate too before treating a `None` as "confirmed empty"
    /// rather than merely "this channel came up empty". Uncached: this path
    /// is reached only when the primary check already failed, rare enough
    /// that a live round trip here is cheap insurance rather than a hot-path
    /// cost.
    fn slot_key_status_algorithm(&mut self, slot: Slot) -> Option<KeyAlg> {
        let alg_id = self.metadata(slot.key_ref()).and_then(|m| m.algorithm);
        alg_id
            .and_then(|id| self.key_alg_from_apdu_id(id))
            .or_else(|| self.hid_crescendo_slot_algorithm(slot))
    }

    /// Write a CHUID (Card Holder Unique Identifier) to the card: `guid` is
    /// the 16-byte GUID (tag `0x34`) — see [`random_chuid_guid`] for a
    /// host-side-only, no-card-I/O way to generate one a caller can pre-fill
    /// an input with and let the user overwrite — and `expiration` is the
    /// `YYYYMMDD` expiration date (tag `0x35`; see
    /// [`keyroost_piv::chuid_expiration_in_days`]). Requires prior
    /// management-key auth ([`authenticate_management`]).
    ///
    /// Mirrors `yubico-piv-tool`'s `set-chuid` (see [`keyroost_piv::encode_chuid`]
    /// for the byte-for-byte template match): Windows' PIV minidriver caches
    /// a card's contents by its CHUID, so after writing a new certificate or
    /// key it may keep showing stale data until the CHUID changes — this is
    /// the standard fix, not a workaround specific to any one vendor's card.
    ///
    /// [`authenticate_management`]: PivSession::authenticate_management
    ///
    /// Invalidates `PivSessionState::chuid_cache` back to "unresolved" on
    /// success, so the next [`Self::read_chuid`] — this session or, via
    /// `with_cached_transaction`, a later one on the same card — sees the value just
    /// written instead of whatever was cached before it.
    pub fn new_chuid(
        &mut self,
        guid: &[u8; 16],
        expiration: &[u8; 8],
    ) -> Result<(), TransportError> {
        let value = piv::encode_chuid(guid, expiration);
        let (_, sw) = self.transmit_full(&piv::put_data(&piv::OBJECT_CHUID, &value))?;
        ok_or_write("piv new chuid", sw)?;
        self.state.chuid_cache = None;
        Ok(())
    }

    /// Read the card's CHUID: FASC-N, GUID, and expiration date (the
    /// signature and LRC fields are parsed away — see
    /// [`keyroost_piv::parse_chuid`]). `None` when the object is empty/absent
    /// or doesn't parse as a CHUID. No PIN required — CHUID is a public data
    /// object, like a certificate.
    ///
    /// Cached in `PivSessionState::chuid_cache` for the rest of this
    /// lineage — [`Self::new_chuid`] is the only thing that invalidates it.
    /// A transport- or parse-level failure (either `?` below) is never
    /// cached, same as every other cache here.
    pub fn read_chuid(&mut self) -> Result<Option<keyroost_piv::Chuid>, TransportError> {
        if let Some(cached) = self.state.chuid_cache.clone() {
            return Ok(cached);
        }
        let (data, sw) = self.transmit_full(&piv::get_data(&piv::OBJECT_CHUID))?;
        if sw != piv::SW_OK {
            self.state.chuid_cache = Some(None);
            return Ok(None);
        }
        let inner = piv::unwrap_data_object(&data).map_err(TransportError::PivParse)?;
        let chuid = piv::parse_chuid(inner);
        self.state.chuid_cache = Some(chuid.clone());
        Ok(chuid)
    }

    /// Clear `slot`'s certificate object (standard PIV; universal across
    /// firmware). Removes only the X.509 certificate; the slot's private key
    /// persists. Requires prior management-key auth ([`authenticate_management`]).
    ///
    /// [`authenticate_management`]: PivSession::authenticate_management
    pub fn clear_certificate(&mut self, slot: Slot) -> Result<(), TransportError> {
        let (_, sw) = self.transmit_full(&piv::clear_certificate(slot))?;
        ok_or_write("piv clear certificate", sw)?;
        // Cleared; no need to read it back to know it's gone now.
        self.state.cert_cache.remember(slot.key_ref(), Ok(None));
        Ok(())
    }

    /// Delete `slot`'s private key. Permanently erases the key material; the
    /// certificate object is untouched. Requires prior management-key auth
    /// ([`authenticate_management`]) either way.
    ///
    /// On most fingerprints this is the Yubico MOVE-to-`0xFF` extension
    /// (YubiKey firmware 5.7+); **not** version-gated here — a card that
    /// doesn't implement it refuses the APDU, and [`Self::feature_gate`] is
    /// the way to check ahead of that. HID Crescendo has no such extension
    /// (see `keyroost_piv::compat`'s `MOVE_KEY_VERDICTS` doc — MOVE KEY
    /// fares differently), but does have its own INJECT PKI KEY (`INS
    /// 0xD8`) removal form, which this dispatches to instead:
    ///
    /// * [`C2300`](keyroost_piv::fingerprint::HidCrescendoVariant::C2300)/
    ///   [`C4000`](keyroost_piv::fingerprint::HidCrescendoVariant::C4000) —
    ///   the matching family-specific sequence
    ///   ([`keyroost_piv::fingerprint::hid_crescendo_c2300_delete_key`]/
    ///   [`hid_crescendo_c4000_delete_key`](keyroost_piv::fingerprint::hid_crescendo_c4000_delete_key)),
    ///   which needs the slot's *current* algorithm
    ///   (`Self::hid_crescendo_slot_algorithm`, from the same GET PIV
    ///   PROPERTIES read `Self::hid_crescendo_slot_key_algorithms` uses) —
    ///   [`TransportError::PivDeleteKeyAlgorithmUnknown`] if that read never
    ///   named this slot at all.
    /// * [`Generic`](keyroost_piv::fingerprint::HidCrescendoVariant::Generic)
    ///   — the exact family is unconfirmed, so this tries the C4000
    ///   sequence first, and only if that's refused falls back to the
    ///   C2300 one — [`TransportError::PivDeleteKeyHidCrescendoGenericFailed`]
    ///   if both are. Safe to try in sequence: neither builder's command
    ///   has a partial-apply failure mode (see each one's own doc for how
    ///   confident this crate actually is in its bytes) — a refusal means
    ///   the slot's key is untouched, not partially deleted.
    ///
    /// [`authenticate_management`]: PivSession::authenticate_management
    pub fn delete_key(&mut self, slot: Slot) -> Result<(), TransportError> {
        if let keyroost_piv::fingerprint::AppletFingerprint::HidCrescendo(variant) =
            self.fingerprint()
        {
            self.delete_key_hid_crescendo(variant, slot)?;
        } else {
            let (_, sw) = self.transmit_full(&piv::delete_key(slot))?;
            ok_or_write("piv delete key", sw)?;
        }
        self.state.pubkey_cache.evict(slot.key_ref());
        self.state.policy_cache.evict(slot.key_ref());
        Ok(())
    }

    /// [`Self::delete_key`]'s HID Crescendo dispatch — see that method's doc
    /// for the overall shape. Split out so the cache-evict + `Ok(())` tail
    /// in `delete_key` isn't duplicated across the C2300/C4000/`Generic`
    /// branches.
    fn delete_key_hid_crescendo(
        &mut self,
        variant: keyroost_piv::fingerprint::HidCrescendoVariant,
        slot: Slot,
    ) -> Result<(), TransportError> {
        use keyroost_piv::fingerprint::HidCrescendoVariant;

        let alg = self
            .hid_crescendo_slot_algorithm(slot)
            .ok_or(TransportError::PivDeleteKeyAlgorithmUnknown(slot))?;
        match variant {
            HidCrescendoVariant::C2300 => self.delete_key_hid_crescendo_c2300(alg, slot),
            HidCrescendoVariant::C4000 => self.delete_key_hid_crescendo_c4000(alg, slot),
            // `HidCrescendoVariant::Generic`, and any future variant this
            // crate doesn't have a named branch for yet — same "unconfirmed
            // identity, try the more commonly encountered family first"
            // fallback either way.
            _ => {
                match self.delete_key_hid_crescendo_c4000(alg, slot) {
                    Ok(()) => Ok(()),
                    // Wrong guess, not necessarily a real failure -- see
                    // `Self::delete_key`'s doc for why trying the other
                    // sequence next is safe.
                    Err(_) => self.delete_key_hid_crescendo_c2300(alg, slot).map_err(|e| {
                        TransportError::PivDeleteKeyHidCrescendoGenericFailed(Box::new(e))
                    }),
                }
            }
        }
    }

    /// One attempt at [`Self::delete_key`]'s C2300 sequence — see
    /// [`keyroost_piv::fingerprint::hid_crescendo_c2300_delete_key`]'s doc
    /// for the APDU itself. `alg` not matching anything that function
    /// recognizes surfaces as the same [`TransportError::PivDeleteKeyAlgorithmUnknown`]
    /// the caller already checked for before either sequence runs — that
    /// function's `None` cases ([`KeyAlg::Ed25519`]/[`KeyAlg::X25519`])
    /// can't actually be reached from `Self::hid_crescendo_slot_algorithm`
    /// in practice (see its doc), so this is unreachable defensiveness, not
    /// a real path.
    fn delete_key_hid_crescendo_c2300(
        &mut self,
        alg: KeyAlg,
        slot: Slot,
    ) -> Result<(), TransportError> {
        let apdu = keyroost_piv::fingerprint::hid_crescendo_c2300_delete_key(alg, slot.key_ref())
            .ok_or(TransportError::PivDeleteKeyAlgorithmUnknown(slot))?;
        let (_, sw) = self.transmit_full(&apdu)?;
        ok_or_write("piv delete key (HID Crescendo C2300)", sw)
    }

    /// One attempt at [`Self::delete_key`]'s C4000 sequence — see
    /// [`keyroost_piv::fingerprint::hid_crescendo_c4000_delete_key`]'s doc
    /// for the APDU itself. Same unreachable-in-practice `None` caveat as
    /// [`Self::delete_key_hid_crescendo_c2300`], now also covering
    /// [`KeyAlg::Rsa1024`].
    fn delete_key_hid_crescendo_c4000(
        &mut self,
        alg: KeyAlg,
        slot: Slot,
    ) -> Result<(), TransportError> {
        let apdu = keyroost_piv::fingerprint::hid_crescendo_c4000_delete_key(alg, slot.key_ref())
            .ok_or(TransportError::PivDeleteKeyAlgorithmUnknown(slot))?;
        let (_, sw) = self.transmit_full(&apdu)?;
        ok_or_write("piv delete key (HID Crescendo C4000)", sw)
    }

    /// Read the DER-encoded certificate stored in `slot`, or `None` when the
    /// slot has none — `6A82` (no object), an empty `53 00` template, or a
    /// body that isn't a `0x53` data object at all. A read-only public
    /// object: no PIN, and a malformed body is reported as absent rather than
    /// erroring the call (a real card doesn't produce one; `slot_status` and
    /// `status_detailed` derive occupancy straight from this).
    ///
    /// A thin wrapper over `Self::cert_object` — see that method's doc for
    /// the caching behaviour — that turns an unreadable certificate into
    /// [`TransportError::PivCertUnreadable`] instead of the tri-state
    /// `Result` `Self::cert_object` returns.
    pub fn read_certificate(&mut self, slot: Slot) -> Result<Option<Vec<u8>>, TransportError> {
        self.cert_object(slot)?
            .map_err(|reason| TransportError::PivCertUnreadable { slot, reason })
    }

    /// One GET DATA of `slot`'s certificate object, decoded: the outer
    /// `Result` is the card exchange, the inner one whether a certificate
    /// that is there can be read. Status views use this directly so one
    /// unreadable slot is reported, not fatal to the whole snapshot.
    ///
    /// Cached in `CertCache` for the rest of this lineage — see that
    /// type's doc for the full invalidation lifecycle. A transport-level
    /// failure (the `?` below) is never cached, same as every other cache
    /// here: only an actual answer from the card, `9000` or not, counts as
    /// resolved.
    fn cert_object(
        &mut self,
        slot: Slot,
    ) -> Result<Result<Option<Vec<u8>>, CertUnreadable>, TransportError> {
        let key_ref = slot.key_ref();
        if let Some(cached) = self.state.cert_cache.get(key_ref) {
            return Ok(cached);
        }
        let (data, sw) = self.transmit_full(&piv::get_data(&slot.cert_object_tag()))?;
        let cert = if sw == piv::SW_OK {
            cert_object_der(&data)
        } else {
            Ok(None)
        };
        self.state.cert_cache.remember(key_ref, cert.clone());
        Ok(cert)
    }

    /// Yubico ATTEST: the self-signed attestation certificate for `slot`'s key
    /// (DER), proving it was generated on-card. Firmware 4.3+ (older firmware,
    /// and non-Yubico PIV cards, refuse this instruction). No PIN required.
    ///
    /// Checks [`keyroost_piv::compat::PivExtension::Attest`] before sending
    /// anything, same reasoning as [`Self::metadata`]'s
    /// [`GetMetadata`](keyroost_piv::compat::PivExtension::GetMetadata)
    /// check — so a caller doesn't pay for a guaranteed-refused round trip
    /// (and [`Self::slot_policy`]'s ATTEST fallback, which every one of
    /// this fingerprint's slots hits since GET METADATA never names a
    /// policy either, doesn't send four of them per status read). The
    /// synthetic `SW = 6D 00` this returns without any card I/O matches
    /// exactly what a real unsupported-instruction refusal looks like, so
    /// every caller of `attest` sees the same error shape either way.
    pub fn attest(&mut self, slot: Slot) -> Result<Vec<u8>, TransportError> {
        if self.extension_gate(keyroost_piv::compat::PivExtension::Attest)
            == keyroost_piv::compat::FeatureGate::Unsupported
        {
            // `6D 00` (instruction not supported) is exactly what this
            // fingerprint's real refusal looks like — see `Self::attest`'s
            // doc for why this is worth faking rather than sending anything.
            return Err(TransportError::Apdu {
                label: "piv attest",
                sw1: 0x6D,
                sw2: 0x00,
            });
        }
        let (data, sw) = self.transmit_full(&piv::attest(slot.key_ref()))?;
        ok_or_write("piv attest", sw)?;
        Ok(data)
    }

    /// Read `slot`'s PIN/touch policy for display:
    ///
    /// 1. `PolicyCache` — already resolved this lineage, by either of the
    ///    two channels below, this session or an earlier one carried in via
    ///    [`Self::with_cached_transaction`]. Skips both remaining steps for a value
    ///    that's fixed for the life of the slot's current key.
    /// 2. GET METADATA's own `policy` field, via `Self::cached_slot_key` —
    ///    shares that method's one live round trip (and its own
    ///    `PubkeyCache` cache check) rather than issuing a second GET
    ///    METADATA, so a slot [`Self::status_detailed`] just resolved the
    ///    algorithm for costs nothing extra here.
    /// 3. The ATTEST certificate's Yubico key-policy extension
    ///    (`1.3.6.1.4.1.41482.3.8`) — GET METADATA predates policy reporting,
    ///    but ATTEST itself has existed since 4.3. ATTEST is itself a Yubico
    ///    vendor instruction, so a non-Yubico PIV card refuses it too; that
    ///    refusal is handled the same as everything else here, not specially.
    ///
    /// Whatever step 2 or 3 settles on — including "neither channel names
    /// one" — is written to `PolicyCache` before returning, so a slot that
    /// genuinely has no reportable policy doesn't pay for both APDUs again
    /// on the next call.
    ///
    /// `None` throughout means "not available for display", not a wire
    /// error — this is an informational read, not a precondition for a write,
    /// so every failure mode (missing extension, unparsable metadata, ATTEST
    /// itself being unsupported) collapses to the same answer.
    pub fn slot_policy(&mut self, slot: Slot) -> Option<(PinPolicy, TouchPolicy)> {
        let key_ref = slot.key_ref();
        if let Some(resolved) = self.state.policy_cache.get(key_ref) {
            return resolved;
        }
        // `cached_slot_key` writes `policy_cache` directly whenever its own
        // GET METADATA reply carries a policy tag — check again after it,
        // rather than inspecting its return value, since that's the key
        // material, not the policy.
        self.cached_slot_key(slot);
        if let Some(resolved) = self.state.policy_cache.get(key_ref) {
            return resolved;
        }
        // Non-Yubico PIV cards refuse this vendor instruction outright (a
        // status word, not `9000`) — folded into the same `None` as every
        // other failure mode here via `.ok()` / `.flatten()`.
        let policy = self
            .attest(slot)
            .ok()
            .and_then(|cert| {
                keyroost_piv::x509_parse::parse_key_policy_extension(&cert)
                    .ok()
                    .flatten()
            })
            .and_then(|(pin, touch)| {
                Some((PinPolicy::from_id(pin)?, TouchPolicy::from_id(touch)?))
            });
        self.state.policy_cache.remember(key_ref, policy);
        policy
    }

    /// Read `slot`'s key algorithm for display, compatible with any PIV
    /// token — not just a YubiKey new enough for GET METADATA (5.3+):
    ///
    /// 1. `Self::cached_slot_key` — GET METADATA's algorithm when it names
    ///    one (authoritative), else this session's self-known key cache
    ///    (populated by [`Self::generate_key`], or seeded explicitly via
    ///    [`Self::remember_pubkey`]) — either way, `PubkeyCache`. This is
    ///    what makes a freshly generated key show up immediately on
    ///    metadata-less firmware: there's no certificate yet for step 3 to
    ///    read (self-sign/import hasn't run), and GET METADATA's silence on
    ///    such firmware doesn't mean "empty" — it means "doesn't exist", so
    ///    without this step a slot that was *just* populated would still
    ///    display as empty. A caller reading status in a fresh session has
    ///    to `remember_pubkey` first if it wants this step to see anything.
    /// 2. HID Crescendo C2300's live substitute for GET METADATA, which that
    ///    fingerprint never answers at all — see
    ///    `Self::hid_crescendo_slot_algorithm`'s doc.
    /// 3. Otherwise, fall back to the slot's certificate (a standard PIV data
    ///    object every card serves) and parse the algorithm out of its
    ///    SubjectPublicKeyInfo directly.
    ///
    /// Unlike [`Self::slot_key`] — which this does *not* replace — this never
    /// needs the actual public key bytes, only the algorithm, so the
    /// certificate fallback is enough; `slot_key`'s callers (CSR/self-sign)
    /// need the raw key material and always re-confirm it live instead of
    /// trusting this cache (see `Self::confirmed_slot_key`).
    pub fn slot_key_algorithm(&mut self, slot: Slot) -> Option<KeyAlg> {
        if let Some((alg, _)) = self.cached_slot_key(slot) {
            return Some(alg);
        }
        if let Some(alg) = self.hid_crescendo_slot_algorithm(slot) {
            return Some(alg);
        }
        self.read_certificate(slot)
            .ok()
            .flatten()
            .and_then(|der| piv::x509_parse::parse_key_algorithm(&der).ok().flatten())
    }

    /// Ask `slot`'s private key to sign a *prepared* block via GENERAL
    /// AUTHENTICATE: a full PKCS#1 v1.5 padded block for RSA, the raw hash for
    /// ECDSA, or the raw message for Ed25519 (see
    /// [`keyroost_piv::x509::signature_hash`]). Requires a verified PIN —
    /// immediately prior for the signature slot (9C), whose policy is
    /// PIN-per-use. ECDSA signatures come back DER-encoded (`SEQUENCE{r,s}`),
    /// RSA/Ed25519 as raw blocks — either drops verbatim into an X.509
    /// signature BIT STRING.
    ///
    /// Tries a single extended-length GENERAL AUTHENTICATE first; for a key
    /// large enough to need one (RSA-2048+, or Ed25519 with a long enough
    /// TBS) that gets rejected falls back to ISO 7816-4 command chaining —
    /// confirmed necessary on a Token2 PIV token's contact interface, which
    /// answers a well-formed extended-`Lc` GENERAL AUTHENTICATE/PUT DATA with
    /// `SW=6A80` (unlike the `6700`/`6883` YubiKey's OpenPGP applet uses for
    /// the same condition — see
    /// [`OpenPgpSession::import_key`](crate::OpenPgpSession::import_key)) but
    /// accepts the identical data chained. The fallback only fires when the
    /// first attempt actually used extended-length encoding, so a genuine
    /// error on a short-form command (bad PIN state, wrong key, …) isn't
    /// retried.
    pub fn sign(
        &mut self,
        slot: Slot,
        alg: KeyAlg,
        prepared: &[u8],
    ) -> Result<Vec<u8>, TransportError> {
        let key_ref = slot.key_ref();
        let alg_id = self.slot_key_algorithm_apdu_id(alg);
        self.general_auth_dyn_auth(
            "piv sign",
            &piv::general_auth_sign(alg_id, key_ref, prepared),
            &piv::general_auth_sign_chained(alg_id, key_ref, prepared, CHAIN_CHUNK),
        )
    }

    /// Ask `slot`'s RSA private key to raw-decrypt `ciphertext` (a `k`-byte
    /// PKCS#1 block) via GENERAL AUTHENTICATE. Wire-identical to [`Self::sign`]
    /// — the card does the same raw RSA private-key operation for both, and
    /// the input rides the same dynamic-auth `0x81` field — but named
    /// separately so a decrypt call site reads as one. Needs a verified PIN
    /// immediately prior, same as `sign`.
    pub fn decrypt(
        &mut self,
        slot: Slot,
        alg: KeyAlg,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, TransportError> {
        let key_ref = slot.key_ref();
        let alg_id = self.slot_key_algorithm_apdu_id(alg);
        self.general_auth_dyn_auth(
            "piv decrypt",
            &piv::general_auth_sign(alg_id, key_ref, ciphertext),
            &piv::general_auth_sign_chained(alg_id, key_ref, ciphertext, CHAIN_CHUNK),
        )
    }

    /// Run ECDH on `slot`'s private key against `peer_public_key` via GENERAL
    /// AUTHENTICATE key-establishment (dynamic-auth tag `0x85`).
    /// `peer_public_key` is `04 || X || Y` for P-256/P-384 or the raw 32-byte
    /// point for X25519; the reply is the raw shared secret `Z` (the
    /// x-coordinate for the NIST curves). Needs a verified PIN immediately
    /// prior, same as [`Self::sign`].
    pub fn key_agree(
        &mut self,
        slot: Slot,
        alg: KeyAlg,
        peer_public_key: &[u8],
    ) -> Result<Vec<u8>, TransportError> {
        let key_ref = slot.key_ref();
        let alg_id = self.slot_key_algorithm_apdu_id(alg);
        self.general_auth_dyn_auth(
            "piv key-agree",
            &piv::general_auth_key_agree(alg_id, key_ref, peer_public_key),
            &piv::general_auth_key_agree_chained(alg_id, key_ref, peer_public_key, CHAIN_CHUNK),
        )
    }

    /// The GENERAL AUTHENTICATE transmit shared by [`Self::sign`],
    /// [`Self::decrypt`], and [`Self::key_agree`]: send `single` once, and if
    /// it used extended-length encoding and the card rejected it (`SW != 9000`),
    /// retry with the `chained` APDU sequence. Returns the response's `0x82`
    /// dynamic-auth value. The fallback only fires when the first attempt
    /// actually used extended-length encoding, so a genuine error on a
    /// short-form command (bad PIN state, wrong key, …) isn't retried.
    fn general_auth_dyn_auth(
        &mut self,
        label: &'static str,
        single: &[u8],
        chained: &[Vec<u8>],
    ) -> Result<Vec<u8>, TransportError> {
        let (data, sw) = if self.chain_upfront() {
            trace::line(self.traced, || {
                format!(
                    "! {label}: command chaining up front ({})",
                    self.chain_reason()
                )
            });
            self.transmit_chain(label, chained)?
        } else {
            let (data, sw) = self.transmit_full(single)?;
            if sw == piv::SW_OK || !uses_extended_length(single) {
                (data, sw)
            } else {
                trace::line(self.traced, || {
                    format!(
                        "! {label}: extended length rejected (SW={sw:04X}); retrying with \
                         command chaining"
                    )
                });
                self.transmit_chain(label, chained)?
            }
        };
        ok_or_write(label, sw)?;
        piv::parse_general_auth(&data, 0x82)
            .map(<[u8]>::to_vec)
            .map_err(TransportError::PivParse)
    }

    /// The algorithm and public key of the key stored in `slot`, via
    /// `Self::confirmed_slot_key`: always re-confirmed live against GET
    /// METADATA first (firmware 5.3+, when the card actually names both
    /// algorithm and public key — `metadata_key_material` is the gate for
    /// "does this reply actually name the key", since some implementations,
    /// e.g. Nitrokey's `piv-authenticator`, answer `SW_OK` with an empty body
    /// for slots they haven't wired reporting up for yet, functionally
    /// identical to "no GET METADATA support" here), falling back to
    /// whatever `PubkeyCache` already holds only when the device answers
    /// nothing new — self-known, from a prior [`Self::generate_key`] on
    /// `slot` in *this* session, or a caller explicitly carrying key
    /// material forward via [`Self::remember_pubkey`]. That's what lets
    /// CSR/self-sign work right after generation on cards that don't
    /// support GET METADATA (older YubiKeys, non-Yubico PIV tokens): the
    /// card refuses to name the key material any other way, and this crate
    /// keeps no on-disk or cross-process copy of it on its own (see
    /// [`Self::remember_pubkey`]).
    ///
    /// Called by [`Self::generate_csr`]/[`Self::self_signed_certificate`]
    /// *before* they verify the PIN — GET METADATA is an unauthenticated
    /// read (confirmed against real hardware: it succeeds before any PIN
    /// VERIFY in the same session), so resolving the key first and verifying
    /// right before the signing GENERAL AUTHENTICATE keeps that VERIFY the
    /// last command before the signature on every card, rather than risking
    /// a metadata probe sitting in between — some cards (Nitrokey's
    /// `piv-authenticator` observed so far) don't tolerate any intervening
    /// APDU between a PIN verify and the signing operation it authorizes.
    ///
    /// Errors when the slot is empty, GET METADATA doesn't name this slot's
    /// key *and* nothing was generated into `slot` in this session (nor
    /// handed to it via `remember_pubkey`), or a cached entry was invalidated
    /// by a later delete/move/reset.
    pub fn slot_key(&mut self, slot: Slot) -> Result<(KeyAlg, PublicKey), TransportError> {
        self.confirmed_slot_key(slot)
            .ok_or(TransportError::MalformedResponse(
                "slot has no key, or GET METADATA doesn't name this slot's key and \
             the key material wasn't handed to this session — run `piv generate-key` \
             on this slot in this same session, or pass its previously saved \
             key material to this command, so it can be cached for \
             CSR/self-sign",
            ))
    }

    /// Build a PKCS#10 certificate-signing request for the key in `slot`,
    /// signed on the card, returned as PEM. The slot must hold a key
    /// (generated or imported). Verifies `pin` itself, deliberately placed
    /// *after* resolving the slot's key material ([`Self::slot_key`]) and
    /// *immediately* before the signing [`Self::sign`] call — see
    /// `slot_key`'s doc comment for why that ordering matters.
    pub fn generate_csr(
        &mut self,
        slot: Slot,
        subject: &str,
        pin: &[u8],
    ) -> Result<String, TransportError> {
        let (alg, key) = self.slot_key(slot)?;
        let subject = piv::x509::SubjectName::parse(subject).map_err(TransportError::X509)?;
        let spki = piv::spki::subject_public_key_info(&key, alg)
            .map_err(|_| TransportError::MalformedResponse("slot key/algorithm mismatch"))?;
        let cri = piv::x509::csr_info(&subject, &spki);
        let prepared = prepared_block(alg, &cri)?;
        self.verify_pin(pin)?;
        let sig = self.sign(slot, alg, &prepared)?;
        let der = piv::x509::assemble(&cri, alg, &sig).map_err(TransportError::X509)?;
        Ok(piv::x509::pem_csr(&der))
    }

    /// Create a self-signed certificate for the key in `slot` (validity in
    /// unix seconds), sign it on the card, **import it into the slot**, and
    /// return the DER. Requires prior management-key auth (for the import).
    /// Verifies `pin` itself, deliberately placed *after* resolving the
    /// slot's key material ([`Self::slot_key`]) and *immediately* before the
    /// signing [`Self::sign`] call — see `slot_key`'s doc comment for why
    /// that ordering matters.
    pub fn self_signed_certificate(
        &mut self,
        slot: Slot,
        subject: &str,
        not_before: i64,
        not_after: i64,
        pin: &[u8],
    ) -> Result<Vec<u8>, TransportError> {
        let (alg, key) = self.slot_key(slot)?;
        let subject = piv::x509::SubjectName::parse(subject).map_err(TransportError::X509)?;
        let spki = piv::spki::subject_public_key_info(&key, alg)
            .map_err(|_| TransportError::MalformedResponse("slot key/algorithm mismatch"))?;
        // 16 random bytes keep the serial unique and well under RFC 5280's
        // 20-octet ceiling even after the positive-INTEGER zero prefix.
        let mut serial = [0u8; 16];
        getrandom::getrandom(&mut serial).map_err(|_| TransportError::HostRngFailed)?;
        let tbs = piv::x509::tbs_certificate(&serial, alg, &subject, not_before, not_after, &spki)
            .map_err(TransportError::X509)?;
        let prepared = prepared_block(alg, &tbs)?;
        self.verify_pin(pin)?;
        let sig = self.sign(slot, alg, &prepared)?;
        let der = piv::x509::assemble(&tbs, alg, &sig).map_err(TransportError::X509)?;
        self.import_certificate(slot, &der)?;
        Ok(der)
    }

    /// Relocate a slot's private key to another slot (Yubico MOVE KEY). Refuses
    /// a same-slot move and an occupied destination (GET METADATA pre-check —
    /// the card also refuses, this gives a clear error first). Moves ONLY the
    /// key; the source slot's certificate stays put. Requires prior
    /// management-key auth ([`authenticate_management`]), same as
    /// [`delete_key`].
    ///
    /// This is a Yubico vendor extension (YubiKey firmware 5.7+) and is
    /// **not** version-gated here — an older card refuses the APDU itself.
    /// Use [`Self::feature_gate`] to check ahead of that.
    ///
    /// [`authenticate_management`]: PivSession::authenticate_management
    /// [`delete_key`]: PivSession::delete_key
    pub fn move_key(&mut self, src: Slot, dest: Slot) -> Result<(), TransportError> {
        if src.key_ref() == dest.key_ref() {
            return Err(TransportError::MalformedResponse(
                "source and destination slots are the same",
            ));
        }
        if self.slot_has_key(dest)? {
            return Err(TransportError::PivDestinationOccupied(dest));
        }
        let (_, sw) = self.transmit_full(&piv::move_key(src, dest))?;
        ok_or_write("piv move key", sw)?;
        // The key itself relocated, not just its reference — carry both
        // cached entries along with it rather than dropping them, so a
        // subsequent CSR/self-sign or policy display at `dest` still works
        // (or, on metadata-full firmware, still skips the round trip)
        // without paying to re-resolve either. `cert_cache` is deliberately
        // *not* migrated here — MOVE KEY never touches the certificate
        // object, which stays exactly where it was at `src` (see this
        // method's own doc).
        self.state
            .pubkey_cache
            .migrate(src.key_ref(), dest.key_ref());
        self.state
            .policy_cache
            .migrate(src.key_ref(), dest.key_ref());
        Ok(())
    }

    /// Whether `slot` holds a private key, via GET METADATA. Works for retired
    /// slots too — it just reads whatever key reference `slot` maps to. This is
    /// the on-demand occupancy check (not part of [`status`]'s snapshot, which
    /// stays 4 GET DATA calls rather than 24 by never touching retired slots).
    ///
    /// Derives occupancy from `Self::cached_slot_key` — cache-preferring,
    /// same as `status_detailed`'s own use, since this backs a UI dimming
    /// check as often as it backs [`Self::move_key`]'s destination-occupied
    /// precondition — which folds a transient/comms error into the same
    /// `None` as a genuinely empty slot, so a rare transient failure here is
    /// reported as an empty slot; the card's own refusal to write over an
    /// occupied destination is the backstop.
    ///
    /// A GET METADATA reply naming *something* is not by itself "occupied":
    /// some implementations (Nitrokey's `piv-authenticator`, and PivApplet as
    /// seen on a Token2 fingerprint trace) answer `SW_OK` for every retired
    /// key reference whether or not a key was ever generated there, with an
    /// empty or key-less body for the ones that weren't. That reply is
    /// indistinguishable from "no key" and would otherwise mark every retired
    /// slot present — so `Self::resolve_slot_from_device` gates on
    /// `metadata_key_material`, the same "does this reply actually name the
    /// key" check [`Self::slot_key`] uses, rather than on the GET METADATA
    /// status word alone.
    ///
    /// [`status`]: PivSession::status
    pub fn slot_has_key(&mut self, slot: Slot) -> Result<bool, TransportError> {
        Ok(self.cached_slot_key(slot).is_some())
    }

    /// Reset the PIV application to factory defaults. Always sends the bare
    /// RESET APDU and reports whatever the card says — this method does
    /// nothing to detect or satisfy either precondition below itself:
    ///
    /// * The widespread YubiKey-mimicking convention: succeeds only when
    ///   **both** the PIN and PUK are already blocked (the card enforces
    ///   this); otherwise it returns `6983` or `6985` (a genuine YubiKey's own
    ///   choice, per Yubico's docs) — or, on some other fingerprints, `6982`
    ///   — any of the three mapped to [`TransportError::PivResetNotAllowed`].
    /// * Some fingerprints instead require an authenticated management-key
    ///   session before RESET is accepted — flagged by
    ///   [`keyroost_piv::compat::PivQuirk::ResetNeedsManagementAuth`] — with
    ///   no PIN/PUK blocking involved at all. This method itself still does
    ///   nothing to satisfy that: it never authenticates, so called directly
    ///   on a quirked device with no prior authenticated session in force,
    ///   this call is expected to fail (however the card reports "management
    ///   auth needed" — unverified, since no such session gets attempted
    ///   here). [`Self::factory_reset`] is what actually authenticates first
    ///   on such a device (`Self::authenticate_management_current`) before
    ///   reaching this same method.
    ///
    /// A caller that wants to know which convention a device follows ahead
    /// of time should check `self.quirks()` for the quirk above, or go
    /// through [`Self::plan_factory_reset`]/[`Self::factory_reset`], which
    /// already do and route around this method's PIN/PUK-blocking assumption
    /// accordingly.
    ///
    /// Unlike the two preconditions above, this method *does* actively guard
    /// against [`keyroost_piv::compat::PivQuirk::ResetFailsIfManagementKeyIsAes`]
    /// (every known `ArekinathPivApplet` version): a bug in that applet's own
    /// RESET handler throws when the `0x9B` key object is an AES key instead
    /// of a 3DES one, and reports the exception back as a non-success status
    /// word rather than completing. There's no way to recover from that
    /// on-device — the fix is changing the management key back to 3DES
    /// first — so a quirked fingerprint has its current management-key
    /// algorithm checked (the same [`Self::reported_management_key_algorithm`]
    /// a standard authentication round already relies on) and this call
    /// refuses with [`TransportError::PivResetManagementKeyMustBe3Des`]
    /// *before* sending anything, rather than let the card fail partway and
    /// (on the [`Self::force_reset`] path) burn PIN/PUK retries for nothing.
    ///
    /// `pre_reset_mgmt_auth` takes the same [`CurrentMgmtAuth`] shape
    /// [`Self::factory_reset`] does, for signature parity with it and
    /// [`Self::force_reset`]/[`Self::force_reset_if_known_supported`] — but
    /// is a dead end here today: this method still never authenticates,
    /// exactly as documented above. It exists now so a future fingerprint
    /// found to need
    /// [`keyroost_piv::compat::PivQuirk::ResetNeedsManagementAuth`] on the
    /// *plain* PIV-only RESET (not just the `NeedsManagementAuth` shape
    /// [`Self::factory_reset`] already handles) doesn't need every caller's
    /// signature reworked to supply one.
    pub fn reset(
        &mut self,
        pre_reset_mgmt_auth: Option<CurrentMgmtAuth<'_>>,
    ) -> Result<(), TransportError> {
        // Dead end today -- see the doc above. Named `let _ =`, not an
        // `_`-prefixed parameter, so the signature stays self-documenting
        // for whoever wires this up for real.
        let _ = pre_reset_mgmt_auth;
        // Only bother reading the management-key algorithm back off the card
        // (a GET METADATA round trip) when this fingerprint's own quirk says
        // RESET can actually fail over it — every other fingerprint's RESET
        // is unaffected by the algorithm, so skip the extra APDU for them.
        if self
            .quirks()
            .contains(&keyroost_piv::compat::PivQuirk::ResetFailsIfManagementKeyIsAes)
        {
            if let Some(alg) = self.reported_management_key_algorithm() {
                if alg != MgmtAlg::TripleDes {
                    return Err(TransportError::PivResetManagementKeyMustBe3Des(alg));
                }
            }
        }
        let (_, sw) = self.transmit_full(&piv::reset())?;
        // A YubiKey answers RESET's "PIN and PUK must already be blocked"
        // precondition with 6985 (conditions of use not satisfied), not 6983
        // per Yubico's own docs — see SW_CONDITIONS_NOT_SATISFIED. Other
        // fingerprints have been observed using 6983 for the identical
        // precondition, and others still 6982 (security status not
        // satisfied) — all three map to the same outcome here.
        if sw == piv::SW_AUTH_BLOCKED
            || sw == piv::SW_CONDITIONS_NOT_SATISFIED
            || sw == piv::SW_SECURITY_NOT_SATISFIED
        {
            return Err(TransportError::PivResetNotAllowed);
        }
        ok_or_write("piv reset", sw)?;
        // Wipes every slot; nothing cached survives it — rebuild in-session
        // state from scratch exactly as `Self::refresh` documents, rather
        // than hand-picking which caches this particular wipe invalidates.
        // Its own re-`select()` failing is folded in as best-effort, not
        // propagated as this method's own error: the RESET APDU itself
        // already succeeded above, so a caller must still hear that as
        // success — the same "the real operation is done, a courtesy
        // follow-up failing is a separate concern" split
        // `Self::hid_crescendo_aca_reset_card`'s `WipedKeyRestoreFailed`
        // makes explicit for its own follow-up step. A refresh failure here
        // leaves the session in a state any later call will fail loudly on
        // its own, so nothing is silently swallowed forever.
        let _ = self.refresh();
        Ok(())
    }

    /// The raw [`keyroost_piv::compat::PivExtension::ResetGlobal`] gate for
    /// this session's applet — exposed on its own because nothing else here
    /// already surfaces it standalone: [`Self::plan_factory_reset`] resolves
    /// only [`keyroost_piv::compat::PivExtension::Reset`], and
    /// [`Self::global_reset_available`]
    /// folds this gate together with `Reset`'s (via OR) and the
    /// [`keyroost_piv::compat::PivQuirk::ResetNeedsManagementAuth`] quirk (via AND) into one
    /// `bool`, losing this gate's own value along the way. A caller that
    /// needs to tell "`Reset` is `Unsupported` AND `ResetGlobal` is also
    /// `Unsupported`" apart from "`Reset` is `Unsupported` but `ResetGlobal`
    /// might still offer something" needs this method alongside
    /// `plan_factory_reset`'s [`FactoryResetPlan::Unsupported`] (which alone
    /// only proves the first half).
    ///
    /// Read-only, same cost as [`Self::plan_factory_reset`]: no APDU beyond
    /// `Self::identity`'s fingerprint probe, cached after the first call
    /// this session.
    #[must_use]
    pub fn reset_global_gate(&mut self) -> keyroost_piv::compat::FeatureGate {
        self.extension_gate(keyroost_piv::compat::PivExtension::ResetGlobal)
    }

    /// The raw [`keyroost_piv::compat::PivExtension::PinManagementAuth`] gate
    /// for this session's applet — exposed standalone for a caller that needs
    /// to know whether a PIN is even a candidate credential *before* asking
    /// for one, e.g. `keyroostctl factory-reset`'s (and `keyroostctl piv
    /// reset`'s) abort-early message when [`Self::global_reset_available`]
    /// (respectively [`Self::plan_factory_reset`] resolving
    /// [`FactoryResetPlan::NeedsManagementAuth`]) is true: it names the PIN
    /// option only when this gate says it applies, and flags it as
    /// unverified when that's all this gate can confirm.
    ///
    /// Read-only, same cost as [`Self::reset_global_gate`]: no APDU beyond
    /// `Self::identity`'s fingerprint probe, cached after the first call
    /// this session.
    #[must_use]
    pub fn pin_management_auth_gate(&mut self) -> keyroost_piv::compat::FeatureGate {
        self.extension_gate(keyroost_piv::compat::PivExtension::PinManagementAuth)
    }

    /// Resolve [`FactoryResetPlan`] for this session's applet — the PIV-only
    /// shape, from [`keyroost_piv::compat::PivExtension::Reset`] alone.
    /// Read-only: costs no PIN/PUK attempt, and no APDU at all beyond
    /// `Self::identity`'s fingerprint probe (itself cached after the first
    /// call this session).
    ///
    /// Most callers want [`Self::preview_factory_reset`] instead, which
    /// additionally checks
    /// [`keyroost_piv::compat::PivExtension::ResetGlobal`] first — the same
    /// order [`Self::factory_reset`] itself checks in. This method alone says
    /// nothing about that axis; call it directly only when the PIV-only
    /// shape specifically is what's needed (e.g. a caller that already knows
    /// `ResetGlobal` doesn't apply here).
    #[must_use]
    pub fn plan_factory_reset(&mut self) -> FactoryResetPlan {
        use keyroost_piv::compat::{FeatureGate, PivExtension, PivQuirk};
        match self.extension_gate(PivExtension::Reset) {
            FeatureGate::Unsupported => FactoryResetPlan::Unsupported,
            FeatureGate::Unverified => FactoryResetPlan::Unverified,
            FeatureGate::Supported => {
                if self.quirks().contains(&PivQuirk::ResetNeedsManagementAuth) {
                    FactoryResetPlan::NeedsManagementAuth
                } else {
                    FactoryResetPlan::BurnPinPukThenReset
                }
            }
        }
    }

    /// Resolve [`PivResetPreview`] for this session's applet: what
    /// [`Self::factory_reset`] will attempt *first*, checking
    /// [`keyroost_piv::compat::PivExtension::ResetGlobal`] first (a
    /// device-wide mechanism wins when available) and falling back to
    /// [`Self::plan_factory_reset`]'s PIV-only shape otherwise — the exact
    /// order [`Self::factory_reset`] itself dispatches on. Read-only, same
    /// cost as [`Self::plan_factory_reset`]: no APDU beyond
    /// `Self::identity`'s fingerprint probe, cached after the first call
    /// this session.
    ///
    /// "First" because it can't predict [`Self::factory_reset`]'s one
    /// runtime fallback: when this resolves [`PivResetPreview::Global`] off
    /// an *unverified* `ResetGlobal` gate and that attempt then fails,
    /// `factory_reset` tries the PIV-only shape next rather than giving up
    /// (see its doc) — something this method has no way to predict without
    /// actually attempting the device-wide mechanism first. Still the right
    /// preview to show ahead of time: `Global` is what actually runs in the
    /// overwhelmingly common case (the attempt succeeds), and a caller
    /// describing what's about to happen shouldn't hedge across a fallback
    /// that only matters when that attempt fails.
    #[must_use]
    pub fn preview_factory_reset(&mut self) -> PivResetPreview {
        use keyroost_piv::compat::FeatureGate;
        if self.reset_global_gate() != FeatureGate::Unsupported {
            return PivResetPreview::Global;
        }
        match self.plan_factory_reset() {
            FactoryResetPlan::Unsupported => PivResetPreview::Unsupported,
            other => PivResetPreview::Piv(other),
        }
    }

    /// Whether either reset extension — [`keyroost_piv::compat::PivExtension::Reset`] or
    /// [`keyroost_piv::compat::PivExtension::ResetGlobal`] — resolves anything other than
    /// [`keyroost_piv::compat::FeatureGate::Unsupported`] (i.e. `Supported` *or* `Unverified` on
    /// at least one of the two) **and** this fingerprint carries
    /// [`keyroost_piv::compat::PivQuirk::ResetNeedsManagementAuth`]. `false`
    /// otherwise.
    ///
    /// Deliberately not narrowed to `ResetGlobal == Supported`: that would
    /// exclude [`HidCrescendoVariant::Generic`][generic], the one real
    /// fingerprint this matters for today where it actually bites —
    /// `RESET_GLOBAL_VERDICTS` carries no row for `Generic` (see that
    /// table's doc for why: RESET CARD's own documentation names only
    /// C2300/C4000, so there's no basis to *claim* Generic supports it), so
    /// `ResetGlobal` resolves `Unverified` there, not `Supported` — yet the
    /// underlying ACA mechanism is expected to work on Generic too, the same
    /// way [`Self::set_management_key`]/
    /// [`Self::delete_management_key_hid_crescendo`]'s HID Crescendo
    /// fallback already matches on the fingerprint generically (`let
    /// AppletFingerprint::HidCrescendo(variant) = self.fingerprint()`, any
    /// variant) rather than singling out named models. `Reset` is checked
    /// too, alongside `ResetGlobal`, for the same "don't require `Supported`
    /// specifically" reasoning — either extension being anything but a
    /// confirmed dead end is enough to justify collecting a credential the
    /// quirk says is needed; `Self::hid_crescendo_aca_reset_card` itself
    /// still decides whether the attempt actually succeeds.
    ///
    /// Read-only, same cost profile as [`Self::plan_factory_reset`]: no APDU
    /// beyond `Self::identity`'s fingerprint probe, cached after the first
    /// call this session — resolving both gates plus the quirk costs exactly
    /// one fingerprint, not three.
    ///
    /// [generic]: keyroost_piv::fingerprint::HidCrescendoVariant::Generic
    #[must_use]
    pub fn global_reset_available(&mut self) -> bool {
        use keyroost_piv::compat::{FeatureGate, PivExtension, PivQuirk};
        let reset = self.extension_gate(PivExtension::Reset);
        let reset_global = self.extension_gate(PivExtension::ResetGlobal);
        (reset != FeatureGate::Unsupported || reset_global != FeatureGate::Unsupported)
            && self.quirks().contains(&PivQuirk::ResetNeedsManagementAuth)
    }

    /// The well-known factory-default management-key bytes for this
    /// session's applet, if keyroost has one on record —
    /// [`keyroost_piv::compat::default_9b_management_key`] over
    /// [`Self::quirks`]. `None` means keyroost has no known default for
    /// this fingerprint/version, the same signal
    /// [`Self::global_reset_available`]'s caller uses to disable its "use
    /// the default" convenience. Whichever mechanism
    /// [`Self::factory_reset`] ends up running when
    /// [`Self::global_reset_available`] is true — the device-wide ACA XAUTH
    /// round or the PIV-only management-key round — resolves its credential
    /// from this same quirk (HID Crescendo has no standard PIV management
    /// key at all; see [`keyroost_piv::compat::PivQuirk::Default9bManagementKey`]'s
    /// doc), so one accessor serves both. Read-only, same cost profile as
    /// [`Self::global_reset_available`]: no APDU beyond the identity probe,
    /// cached after the first call this session.
    #[must_use]
    pub fn default_management_key(&mut self) -> Option<&'static [u8]> {
        keyroost_piv::compat::default_9b_management_key(&self.quirks())
    }

    /// Authenticate PIV management via whichever `current` credential a
    /// caller supplied — [`CurrentMgmtAuth::Key`] runs the standard round
    /// with the algorithm inferred from the key's own length (the same
    /// inference [`Self::authenticate_management_via_pin`]'s
    /// PIN-protected-key path already uses),
    /// [`CurrentMgmtAuth::Pin`] runs [`Self::authenticate_management_via_pin`]
    /// itself. Used by [`Self::factory_reset`]'s
    /// [`FactoryResetPlan::NeedsManagementAuth`] path, where — unlike
    /// [`Self::authenticate_management_via_pin`]'s own callers, which already
    /// know PIN-based auth is what a given fingerprint offers — the caller
    /// may be handed either kind of credential without knowing ahead of time
    /// which one this fingerprint actually wants. Public so `keyroostctl
    /// piv reset` can run the exact same round in front of a *plain*
    /// [`Self::reset`] — unlike [`Self::factory_reset`], it must never reach
    /// for the device-wide [`keyroost_piv::compat::PivExtension::ResetGlobal`] mechanism, so it
    /// authenticates here and sends [`Self::reset`] itself rather than
    /// calling [`Self::factory_reset`].
    pub fn authenticate_management_current(
        &mut self,
        current: CurrentMgmtAuth<'_>,
    ) -> Result<(), TransportError> {
        match current {
            CurrentMgmtAuth::Key(key) => {
                let alg = self.resolve_management_key_algorithm(key.len())?;
                self.authenticate_management(alg, key)
            }
            CurrentMgmtAuth::Pin(pin) => self.authenticate_management_via_pin(pin),
        }
    }

    /// Factory-reset PIV the manufacturer-intended way, whichever mechanism
    /// this fingerprint actually offers — the one method every reset path
    /// this crate implements funnels through, so a caller never has to
    /// decide between them itself:
    ///
    /// 1. [`keyroost_piv::compat::PivExtension::ResetGlobal`] resolves
    ///    anything but `Unsupported` → the device-wide mechanism (HID
    ///    Crescendo's ACA RESET CARD today), which takes PIV down with it
    ///    alongside at least one other applet. Always needs
    ///    `pre_reset_mgmt_auth` — the ACA's own protocol requires an
    ///    authenticated session regardless of any quirk;
    ///    [`TransportError::PivResetNeedsManagementAuth`] if
    ///    `pre_reset_mgmt_auth` is `None`.
    ///
    ///    If this fails and the gate was only
    ///    [`keyroost_piv::compat::FeatureGate::Unverified`] (never a confirmed
    ///    [`keyroost_piv::compat::FeatureGate::Supported`]) — falls through to
    ///    step 2 instead of returning [`TransportError::PivResetGlobalFailed`]
    ///    outright: an unverified gate's claim that the mechanism applies here
    ///    was never confirmed, so the failure could just as easily be "wrong
    ///    guess" as "real fault", and `Self::hid_crescendo_aca_reset_card`
    ///    only ever fails before it has touched anything (see that method's
    ///    doc), so nothing is lost by trying something else. A `Supported`
    ///    gate skips this: a confirmed-good mechanism failing means something
    ///    is actually wrong, not that the wrong mechanism was tried, so that
    ///    case returns the failure as-is rather than guessing further.
    /// 2. Otherwise (or as the above fallback), [`Self::plan_factory_reset`]
    ///    resolves the PIV-only shape:
    ///    [`FactoryResetPlan::Unsupported`] refuses outright (deliberately
    ///    blocking the PIN and PUK would have no way back);
    ///    [`FactoryResetPlan::NeedsManagementAuth`] authenticates with
    ///    `pre_reset_mgmt_auth` (same `PivResetNeedsManagementAuth` refusal if
    ///    `None`) then sends [`Self::reset`]; [`FactoryResetPlan::Unverified`] sends a
    ///    bare [`Self::reset`] with no pre-blocking; and
    ///    [`FactoryResetPlan::BurnPinPukThenReset`] deliberately exhausts the
    ///    PIN retry counter with wrong values, then the PUK counter, then
    ///    sends RESET (which the card only accepts once BOTH are blocked) —
    ///    the documented decommission path for a card whose PIN/PUK are
    ///    unknown.
    ///
    /// Every path wipes all PIV keys, certificates, and PINs (plus, on the
    /// device-wide path, whatever else that mechanism covers) and leaves the
    /// applet at defaults. [`Self::preview_factory_reset`] resolves which of
    /// the above a caller is about to get *before* any fallback is known to
    /// be needed, read-only, ahead of the call — see its doc for why that's
    /// still the right preview to show even though this method might not
    /// end up matching it exactly.
    pub fn factory_reset(
        &mut self,
        pre_reset_mgmt_auth: Option<CurrentMgmtAuth<'_>>,
    ) -> Result<FactoryResetOutcome, TransportError> {
        use keyroost_piv::compat::FeatureGate;

        let reset_global_gate = self.reset_global_gate();
        if reset_global_gate != FeatureGate::Unsupported {
            let global_current =
                pre_reset_mgmt_auth.ok_or(TransportError::PivResetNeedsManagementAuth)?;
            match self.hid_crescendo_aca_reset_card(global_current) {
                Ok(outcome) => return Ok(outcome),
                Err(e) if reset_global_gate != FeatureGate::Unverified => {
                    // `Supported`: a confirmed-good mechanism failing is a
                    // real failure, not "wrong mechanism" -- don't go
                    // guessing at a completely different one.
                    return Err(TransportError::PivResetGlobalFailed(Box::new(e)));
                }
                // `Unverified`: this gate's own claim that the device-wide
                // mechanism applies here was never confirmed, so a failure
                // could just as easily mean "wrong guess" as "real fault" --
                // fall through to `PivExtension::Reset`'s own shape below
                // instead of giving up on the one unverified guess.
                // `hid_crescendo_aca_reset_card` only ever returns `Err`
                // before RESET CARD itself has run (see its doc), so nothing
                // was touched by this attempt -- safe to try a completely
                // different mechanism next. Always re-SELECTs PIV before
                // returning, success or failure, so the session is already
                // in the right state for what follows.
                Err(_) => {}
            }
        }

        match self.plan_factory_reset() {
            FactoryResetPlan::Unsupported => Err(TransportError::PivResetUnsupported),
            FactoryResetPlan::NeedsManagementAuth => {
                let pre_reset_mgmt_auth =
                    pre_reset_mgmt_auth.ok_or(TransportError::PivResetNeedsManagementAuth)?;
                (|| {
                    self.authenticate_management_current(pre_reset_mgmt_auth)?;
                    self.reset(Some(pre_reset_mgmt_auth))
                })()
                .map(|()| FactoryResetOutcome::Wiped)
                .map_err(|e| TransportError::PivResetManagementAuthFailed(Box::new(e)))
            }
            FactoryResetPlan::Unverified => self
                .reset(pre_reset_mgmt_auth)
                .map(|()| FactoryResetOutcome::Wiped)
                .map_err(|e| TransportError::PivResetUnverifiedFailed(Box::new(e))),
            FactoryResetPlan::BurnPinPukThenReset => self.force_reset(pre_reset_mgmt_auth),
        }
    }

    /// Burn the PIV PIN and PUK retry counters and RESET — the documented
    /// decommission path for a card whose PIN/PUK are unknown.
    ///
    /// Tries a bare [`Self::reset`] first, before touching either counter:
    /// if the card accepts it outright (e.g. a previous run already blocked
    /// both and got interrupted before RESET), this succeeds immediately
    /// with nothing further to burn. Only when that bare attempt comes back
    /// [`TransportError::PivResetNotAllowed`] — RESET's `SW_AUTH_BLOCKED`,
    /// `SW_CONDITIONS_NOT_SATISFIED`, or `SW_SECURITY_NOT_SATISFIED` — does
    /// this fall through to deliberately exhausting the PIN retry counter
    /// with wrong values, then trying RESET again *before* touching the PUK
    /// at all: not every applet's precondition is YubiKey's "PIN and PUK
    /// must already be blocked" — the Trussed `piv-authenticator` Nitrokey
    /// runs (<https://github.com/trussed-dev/piv-authenticator>) checks only
    /// `remaining_pin_retries() == 0`, so RESET already succeeds at this
    /// point and the PUK is never touched. Only when that second attempt
    /// also comes back `PivResetNotAllowed` does this burn the PUK counter
    /// too and send RESET a third time. Any other error from any of the
    /// three attempts is returned as-is — this method only keeps going on
    /// the strength of the one error it knows how to work around.
    ///
    /// [`Self::factory_reset`] is what decides this mechanism is the right
    /// one for this fingerprint ([`FactoryResetPlan::BurnPinPukThenReset`])
    /// and calls here; this method itself doesn't consult that plan.
    ///
    /// `pre_reset_mgmt_auth` is threaded straight through to every
    /// [`Self::reset`] call this method makes (the initial bare attempt and
    /// the final one after both counters are burned) — see that method's
    /// doc for why it's a dead end today rather than actually used here.
    pub fn force_reset(
        &mut self,
        pre_reset_mgmt_auth: Option<CurrentMgmtAuth<'_>>,
    ) -> Result<FactoryResetOutcome, TransportError> {
        match self.reset(pre_reset_mgmt_auth) {
            Ok(()) => return Ok(FactoryResetOutcome::Wiped),
            Err(TransportError::PivResetNotAllowed) => {}
            Err(e) => return Err(e),
        }

        // The PIN a successful PUK guess would leave behind: RESET RETRY COUNTER
        // rewrites the PIN when it succeeds, so this has to be a value we can
        // name back to the user (see PivPukGuessAccepted) rather than something
        // random nobody could recover. The PIV default is the friendliest choice.
        const RECOVERY_PIN: &[u8] = b"123456";

        let st = self.status()?;

        // 1. Block the PIN.
        let mut blocked = false;
        let mut previous: Option<Zeroizing<Vec<u8>>> = None;
        for _ in 0..block_attempts_cap(st.pin_retries) {
            let guess = random_credential_guess(previous.as_ref().map(|g| g.as_slice()))?;
            match self.verify_pin(&guess) {
                // The guess matched the live PIN: VERIFY changes nothing, it just
                // costs us an attempt that didn't decrement. Draw another.
                Ok(()) => {}
                Err(TransportError::PivPinRejected {
                    tries_remaining: Some(0),
                }) => {
                    blocked = true;
                    break;
                }
                Err(TransportError::PivPinRejected { .. }) => {}
                Err(e) => return Err(e),
            }
            previous = Some(guess);
        }
        if !blocked {
            return Err(TransportError::PivResetIncomplete(
                "the PIV PIN would not report itself blocked within the attempt cap, \
                 so the card was NOT wiped — its keys and certificates are still \
                 there and its PIN retry counter has been spent down. Re-run the \
                 factory reset to finish.",
            ));
        }

        // The PIN is blocked — try RESET again right away. On a fingerprint
        // whose precondition is "PIN blocked" alone (Trussed's
        // `piv-authenticator`, confirmed against its own source: RESET's
        // handler rejects with `ConditionsOfUseNotSatisfied` purely on
        // `remaining_pin_retries() != 0`, never consulting the PUK) this
        // already succeeds — done, with the PUK never guessed at and no
        // dependence on GET METADATA reporting real PUK retry counts (this
        // same applet's GET METADATA is an unimplemented stub for the PUK
        // reference, always answering empty `9000`). A card that really does
        // need the PUK blocked too (YubiKey's convention) answers the same
        // `PivResetNotAllowed` here as it did above, and step 2 below still
        // runs exactly as before.
        match self.reset(pre_reset_mgmt_auth) {
            Ok(()) => return Ok(FactoryResetOutcome::Wiped),
            Err(TransportError::PivResetNotAllowed) => {}
            Err(e) => return Err(e),
        }

        // 2. Block the PUK (via unblock-pin, whose wrong PUK decrements the PUK
        //    counter). Size the loop from the card's real PUK count — `piv
        //    set-retries` can raise it past the default cap, and a loop that
        //    stops short leaves the PIN blocked and the card un-wiped. GET
        //    METADATA is firmware 5.3+, so `None` (the conservative default)
        //    stays the fallback.
        let puk_tries = self
            .metadata(piv::PIN_REF_PUK)
            .and_then(|m| m.retries)
            .map(|(remaining, _total)| remaining);
        let mut puk_blocked = false;
        let mut previous: Option<Zeroizing<Vec<u8>>> = None;
        for _ in 0..block_attempts_cap(puk_tries) {
            let guess = random_credential_guess(previous.as_ref().map(|g| g.as_slice()))?;
            match self.unblock_pin(&guess, RECOVERY_PIN) {
                // The guess *was* the PUK, so RESET RETRY COUNTER really ran: the
                // PIN is now RECOVERY_PIN and unblocked. That is a card-state
                // change the user has to be told about, and on cards that restore
                // the retry counter on success the loop would never end.
                Ok(()) => return Err(TransportError::PivPukGuessAccepted),
                Err(TransportError::PivPinRejected {
                    tries_remaining: Some(0),
                }) => {
                    puk_blocked = true;
                    break;
                }
                Err(TransportError::PivPinRejected { .. }) => {}
                Err(e) => return Err(e),
            }
            previous = Some(guess);
        }
        if !puk_blocked {
            return Err(TransportError::PivResetIncomplete(
                "the PIV PUK would not report itself blocked within the attempt cap. \
                 The PIN is now blocked but the card was NOT wiped — re-run the \
                 factory reset to finish, or unblock the PIN with the PUK if you \
                 know it.",
            ));
        }

        // 3. Both blocked — RESET should now succeed. If the card refuses it
        //    for good (the capability pre-check passes on either GET VERSION or
        //    GET SERIAL, so a card can clear it and still have no RESET), say
        //    so honestly: that is the one exit that leaves a card nothing here
        //    can rescue. An unspecific status word is not that exit and keeps
        //    the caller's "re-run the factory reset" hint.
        self.reset(pre_reset_mgmt_auth)
            .map(|()| FactoryResetOutcome::Wiped)
            .map_err(map_reset_stage_error)
    }

    /// Reset PIV via whichever mechanism this fingerprint's
    /// [`keyroost_piv::compat::PivExtension::Reset`] gate actually backs up —
    /// unlike [`Self::factory_reset`], this never reaches for the
    /// device-wide [`keyroost_piv::compat::PivExtension::ResetGlobal`]
    /// mechanism; it only ever ends up sending the bare PIV RESET APDU,
    /// optionally after burning the PIN/PUK retry counters first:
    ///
    /// * [`FeatureGate::Supported`] — [`Self::force_reset`]: a confirmed
    ///   YubiKey-convention fingerprint, so the PIN/PUK burn-then-RESET dance
    ///   is known to be the right recovery path and is run automatically —
    ///   nothing needs to already be blocked going in.
    /// * [`FeatureGate::Unverified`] — a bare [`Self::reset`]: nothing here
    ///   confirms this fingerprint's actual precondition, so no PIN/PUK is
    ///   burned on its behalf; the card may still refuse with
    ///   [`TransportError::PivResetNotAllowed`] if it turns out to need both
    ///   blocked first.
    /// * [`FeatureGate::Unsupported`] — fails immediately with
    ///   [`TransportError::PivResetUnsupported`], without sending anything to
    ///   the card: `PivExtension::Reset` is a confirmed dead end here.
    ///
    /// `pre_reset_mgmt_auth` takes the same [`CurrentMgmtAuth`] shape
    /// [`Self::factory_reset`] does and is threaded straight through to
    /// whichever of [`Self::force_reset`]/[`Self::reset`] this ends up
    /// calling — a dead end today (see [`Self::reset`]'s doc), kept here
    /// only so this signature won't need reworking once a fingerprint is
    /// found where the plain PIV-only RESET also needs
    /// [`keyroost_piv::compat::PivQuirk::ResetNeedsManagementAuth`].
    ///
    /// [`FeatureGate::Supported`]: keyroost_piv::compat::FeatureGate::Supported
    /// [`FeatureGate::Unverified`]: keyroost_piv::compat::FeatureGate::Unverified
    /// [`FeatureGate::Unsupported`]: keyroost_piv::compat::FeatureGate::Unsupported
    pub fn force_reset_if_known_supported(
        &mut self,
        pre_reset_mgmt_auth: Option<CurrentMgmtAuth<'_>>,
    ) -> Result<FactoryResetOutcome, TransportError> {
        use keyroost_piv::compat::{FeatureGate, PivExtension};
        match self.extension_gate(PivExtension::Reset) {
            FeatureGate::Unsupported => Err(TransportError::PivResetUnsupported),
            FeatureGate::Unverified => self
                .reset(pre_reset_mgmt_auth)
                .map(|()| FactoryResetOutcome::Wiped)
                .map_err(|e| TransportError::PivResetUnverifiedFailed(Box::new(e))),
            FeatureGate::Supported => self.force_reset(pre_reset_mgmt_auth),
        }
    }

    /// Whether `slot` holds a certificate (GET DATA), and its size if so.
    fn slot_status(&mut self, slot: piv::Slot) -> Result<PivSlotStatus, TransportError> {
        let cert = self.cert_object(slot)?;
        Ok(slot_occupancy(
            slot,
            cert.as_ref().map(Option::as_deref).map_err(|e| *e),
        ))
    }

    /// Transmit one APDU and reassemble a response the card splits across
    /// `61xx` continuations (GET RESPONSE), returning `(payload, sw)`.
    /// Lazily issues a real SELECT PIV first via `Self::ensure_selected` if
    /// this connection hasn't sent one yet — every genuine PIV command in
    /// this file reaches the card through here. Anything that needs to talk
    /// to a *different* applet (an AID-hopping fingerprint probe, HID
    /// Crescendo's ACA sequences, SELECT PIV itself) calls
    /// [`Self::transmit_full_raw`] instead, bypassing this gate — see that
    /// method's doc for why going through this one there would be wrong, not
    /// just redundant.
    fn transmit_full(&mut self, apdu: &[u8]) -> Result<(Vec<u8>, u16), TransportError> {
        self.ensure_selected()?;
        self.transmit_full_raw(apdu)
    }

    /// The actual APDU transmission [`Self::transmit_full`] wraps with a
    /// lazy SELECT. Call this directly only when `apdu` itself selects an
    /// applet (PIV or otherwise) or is addressed to an applet other than PIV
    /// that the caller has already explicitly SELECTed — every such spot in
    /// this file unconditionally re-SELECTs PIV before returning, per its
    /// own doc. Reaching this for a genuine PIV command would skip
    /// [`Self::transmit_full`]'s lazy-select guarantee and could send it to
    /// whatever applet happens to be selected instead of PIV.
    fn transmit_full_raw(&mut self, apdu: &[u8]) -> Result<(Vec<u8>, u16), TransportError> {
        let cmd_sensitive = piv_cmd_sensitive(apdu);
        // GENERAL AUTHENTICATE responses today are only ciphertext (witness /
        // encrypted challenge), but the same INS in signing/decrypt mode
        // returns recovered plaintext — redact uniformly so a future caller
        // can't leak through a trace.
        let resp_sensitive = apdu.get(1) == Some(&0x87);
        // `describe` makes `transmit_applet` bracket every transmitted APDU —
        // the caller's command and each GET RESPONSE / Le-corrected reissue —
        // with a `>` line naming the command and a `<` line reading its status
        // word. The CLI's `--debug` output and the GUI activity log both take
        // this straight from `trace`, so it covers both.
        const IO: crate::AppletIo = crate::AppletIo {
            label: "piv",
            more_data_sw: piv::SW_MORE_DATA,
            get_response: piv::get_response,
            describe: Some(describe_apdu),
        };
        crate::transmit_applet(
            &self.card,
            self.traced,
            &IO,
            apdu,
            cmd_sensitive,
            resp_sensitive,
        )
    }

    /// Transmit an ISO 7816-4 command-chaining sequence (see
    /// [`keyroost_piv::general_auth_sign_chained`] /
    /// [`keyroost_piv::put_data_chained`]): every intermediate chunk must be
    /// accepted with `9000` or the chain aborts; the final chunk's status
    /// word and (already `61xx`-reassembled) response payload are returned
    /// as-is for the caller to interpret. Mirrors
    /// [`OpenPgpSession::transmit_chain`](crate::OpenPgpSession), added here
    /// for the same reason: extended-length rejection ([`Self::sign`],
    /// [`Self::import_certificate`]).
    fn transmit_chain(
        &mut self,
        label: &'static str,
        chunks: &[Vec<u8>],
    ) -> Result<(Vec<u8>, u16), TransportError> {
        let last = chunks.len().saturating_sub(1);
        for (i, chunk) in chunks.iter().enumerate() {
            let (data, sw) = self.transmit_full(chunk)?;
            if i == last {
                return Ok((data, sw));
            }
            // An intermediate chain link the card didn't accept (anything but
            // 9000) aborts the chain.
            if sw != piv::SW_OK {
                return Err(TransportError::Apdu {
                    label,
                    sw1: (sw >> 8) as u8,
                    sw2: sw as u8,
                });
            }
        }
        Ok((Vec::new(), piv::SW_OK)) // unreachable: chunk builders never return an empty list
    }
}

/// Whether a direct (single-APDU) certificate PUT DATA that came back as
/// `result` should be retried with command chaining *because of a PC/SC-layer
/// failure*: only a [`TransportError::Pcsc`] error on an extended-length APDU
/// qualifies. Some reader/card paths fail an extended APDU of a few KB below
/// the card, before any status word; chaining sends short APDUs instead. A
/// status word (success or not) is left to the SW-driven fallback, and every
/// other error propagates.
fn retry_chained_after(result: &Result<(Vec<u8>, u16), TransportError>, extended: bool) -> bool {
    extended && matches!(result, Err(TransportError::Pcsc(_)))
}

/// The status word a chained certificate PUT DATA ended on. `transmit_chain`
/// reports an intermediate chunk's non-`9000` as a generic
/// [`TransportError::Apdu`]; a `6700` or `6A84` there is handed back as a
/// status word instead, so [`cert_write_result`] names it the same way as on
/// the final chunk. Every other error propagates unchanged.
fn chained_cert_sw(result: Result<(Vec<u8>, u16), TransportError>) -> Result<u16, TransportError> {
    match result {
        Ok((_, sw)) => Ok(sw),
        Err(TransportError::Apdu { sw1, sw2, .. })
            if matches!(
                u16::from_be_bytes([sw1, sw2]),
                piv::SW_WRONG_LENGTH | piv::SW_NOT_ENOUGH_MEMORY
            ) =>
        {
            Ok(u16::from_be_bytes([sw1, sw2]))
        }
        Err(e) => Err(e),
    }
}

/// Map the final status word of a certificate PUT DATA: `6700` (wrong
/// length) → [`TransportError::PivCertTooLarge`] with the DER length,
/// `6A84` (not enough memory) → [`TransportError::PivCardFull`], anything
/// else as any PIV write ([`ok_or_write`]).
fn cert_write_result(slot: Slot, len: usize, sw: u16) -> Result<(), TransportError> {
    match sw {
        piv::SW_WRONG_LENGTH => Err(TransportError::PivCertTooLarge { slot, len }),
        piv::SW_NOT_ENOUGH_MEMORY => Err(TransportError::PivCardFull { slot }),
        _ => ok_or_write("piv import certificate", sw),
    }
}

/// Chunk size for the command-chaining fallback, matching the 254-byte chunks
/// [`keyroost-openpgp`](keyroost_openpgp)'s equivalent fallback uses (GnuPG's
/// `exmode = -254`, one byte short of the short-form `Lc` ceiling).
const CHAIN_CHUNK: usize = 254;

/// Whether `apdu` — built by [`piv::general_auth_sign`] or [`piv::put_data`],
/// whose data field is never empty — used extended-length encoding. Both
/// always emit a non-zero short-form `Lc` for a body that fits in one byte,
/// so byte 4 being the `0x00` extended-length marker is unambiguous.
fn uses_extended_length(apdu: &[u8]) -> bool {
    apdu.get(4) == Some(&0x00)
}

/// A short, human-readable name for one of the AIDs/RIDs this crate SELECTs
/// — the standard PIV applet itself (either AID form [`Self::select`] tries),
/// this crate's own fingerprinting probes, and the GlobalPlatform Issuer
/// Security Domain `PivSession::probe_hid_crescendo_cplc_serial` SELECTs up
/// front to read CPLC — for [`describe_apdu`]'s trace label. E.g. `"Feitian
/// RID"` for [`keyroost_piv::fingerprint::FEITIAN_RID`]. `None` for anything
/// else this crate doesn't recognize.
fn known_aid_name(aid: &[u8]) -> Option<&'static str> {
    use keyroost_piv::fingerprint;
    match aid {
        _ if aid == piv::AID_FULL => Some("NIST PIV Card Application"),
        _ if aid == piv::AID => Some("NIST PIV Card Application"),
        _ if aid == fingerprint::FEITIAN_RID => Some("Feitian RID"),
        _ if aid == fingerprint::SWISSBIT_RID => Some("Swissbit RID"),
        _ if aid == fingerprint::IDPRIME_SECONDARY_PIV_AID => Some("IdPrime secondary PIV AID"),
        _ if aid == fingerprint::NITROKEY_ADMIN_AID => Some("Nitrokey admin AID"),
        _ if aid == fingerprint::HID_CRESCENDO_ACA_AID => Some("HID ActivID ACA"),
        _ if aid == fingerprint::GLOBAL_PLATFORM_ISD_AID => {
            Some("GlobalPlatform Issuer Security Domain")
        }
        _ if aid == keyroost_token2otp::OTP_APPLET_AID => Some("Token2 OTP applet"),
        _ => None,
    }
}

/// Whether `apdu`'s command body carries secret material and must be
/// redacted from a `--debug` trace ([`crate::dump_cmd`]) — the 5-byte header
/// (CLA INS P1 P2 Lc) stays visible either way. VERIFY (`0x20`), CHANGE
/// REFERENCE DATA (`0x24`), RESET RETRY COUNTER (`0x2C`) carry PINs/PUKs;
/// GENERAL AUTHENTICATE (`0x87`) carries the decrypted witness/challenge;
/// SET MANAGEMENT KEY (`0xFF`) carries the raw new key. The same VERIFY
/// (`0x20`) INS covers HID Crescendo's ACA VERIFY PIN
/// ([`PivSession::verify_pin_hid_crescendo_aca`]) too, just at a different
/// P2 — see [`keyroost_piv::fingerprint::HID_CRESCENDO_ACA_PIN_REF`]. The
/// ACA's own XAUTH sequence adds two more: EXTERNAL AUTHENTICATE (`0x82`)
/// carries the host cryptogram, a value derived from XAUTH key 1 exactly
/// like GENERAL AUTHENTICATE's witness; PUT XAUTH KEY (`0xD8`) carries the
/// raw new key value when it *installs* one — but not when `Lc = 0x04`,
/// HID's documented "delete" short form
/// ([`keyroost_piv::fingerprint::hid_crescendo_aca_put_xauth_key_remove`]),
/// whose body is four fixed, publicly-known bytes with no key material in
/// it at all (see that function's doc) — nothing to redact there, same
/// reasoning as GET CHALLENGE (`0x84`) below. GET CHALLENGE itself is
/// **not** included — its command body is empty and its response is a
/// public nonce, not a secret.
#[must_use]
fn piv_cmd_sensitive(apdu: &[u8]) -> bool {
    match (apdu.first(), apdu.get(1)) {
        // HID Crescendo's PIV-applet-level INJECT PKI KEY (CLA 0x80) —
        // distinct from the ACA's own PUT XAUTH KEY below, which shares the
        // same INS byte but under CLA 0x00. This crate only ever builds
        // INJECT PKI KEY's "delete" form
        // (`keyroost_piv::fingerprint::hid_crescendo_c2300_delete_key`/
        // `hid_crescendo_c4000_delete_key`) — a fixed, publicly-known data
        // field with no key material in it at all — so nothing to redact
        // here, regardless of `Lc`.
        (Some(0x80), Some(0xD8)) => false,
        (_, Some(0xD8)) => apdu.get(4) != Some(&0x04),
        (_, ins) => matches!(
            ins,
            Some(0x20) | Some(0x24) | Some(0x2C) | Some(0x87) | Some(0xFF) | Some(0x82)
        ),
    }
}

/// The command-name string that precedes a PIV APDU in a `--debug` /
/// activity-log trace. Resolves `apdu[1]` via [`piv::Instruction`], names the
/// data object GET DATA / PUT DATA is aimed at, names the AID/RID a SELECT
/// targets whenever it's one this crate recognizes (the PIV applet itself,
/// or one of its own fingerprinting probes), sharpens two more cases the INS
/// byte alone leaves ambiguous, separately names HID Crescendo's own
/// proprietary instructions — the ACA (Access Control Applet)'s GSC-IS/HID
/// vendor extensions, and HID's PIV-applet-level INJECT PKI KEY, told apart
/// from each other by CLA despite sharing INS `0xD8` — none of which are
/// modeled in [`piv::Instruction`] at all, and falls back to the raw INS for
/// anything else this crate never builds.
fn describe_apdu(apdu: &[u8]) -> String {
    let Some(&ins) = apdu.get(1) else {
        return "(malformed APDU)".to_string();
    };
    match piv::Instruction::from_code(ins) {
        // A SELECT's data field is the raw AID/RID itself (no `5C` wrapper,
        // unlike GET DATA / PUT DATA below) — name it whenever it's an AID
        // this crate recognizes; an unrecognized one stays plain `SELECT`.
        Some(piv::Instruction::Select) => match command_data(apdu).and_then(known_aid_name) {
            Some(name) => format!("SELECT ({name})"),
            None => "SELECT".to_string(),
        },
        // GET DATA / PUT DATA both open their body with a `5C <len> <tag>`
        // object selector — name what's being read/written, or show the raw
        // tag when it's one we don't have a name for. (A chained PUT DATA's
        // continuation chunks carry no selector and stay bare.)
        Some(verb @ (piv::Instruction::GetData | piv::Instruction::PutData)) => {
            let verb = verb.name();
            match object_selector_tag(apdu) {
                Some(tag) => {
                    let hex = crate::hex_dump(tag);
                    match piv::data_object_name(tag) {
                        // Raw tag first, then its name — the tag is always shown
                        // so an unfamiliar reader can cross-check the spec.
                        Some(name) => format!("{verb} ({hex} \u{2192} {name})"),
                        None => format!("{verb} ({hex})"),
                    }
                }
                None => verb.to_string(),
            }
        }
        // 0xF6 is MOVE KEY, or DELETE KEY when P1 is the 0xFF sentinel
        // (`piv::delete_key` builds `00 F6 FF <slot>`).
        Some(piv::Instruction::MoveKey) if apdu.get(2) == Some(&0xFF) => {
            "DELETE KEY (yubico extension)".to_string()
        }
        // A bodyless VERIFY (`00 20 00 80`, no Lc) queries the PIN retry
        // counter rather than presenting a PIN.
        Some(piv::Instruction::Verify) if apdu.len() <= 4 => {
            "VERIFY (retry-counter query)".to_string()
        }
        Some(known) => known.name().to_string(),
        // HID Crescendo's ACA (Access Control Applet) instructions — GSC-IS/
        // HID vendor extensions, not PIV at all, so none of the three is
        // modeled in `piv::Instruction` and `from_code` answers `None` for
        // every one of them; matched here by raw INS instead. Naming them
        // keeps a `--debug` trace legible while
        // `authenticate_management_hid_crescendo_aca`/
        // `hid_crescendo_aca_put_xauth_key_op` temporarily switch to the ACA
        // applet, instead of falling through to a bare "INS 0x82"/"INS 0xD8".
        None if ins == 0x84 => "GET CHALLENGE (HID ACA XAUTH)".to_string(),
        None if ins == 0x82 => "EXTERNAL AUTHENTICATE (HID ACA XAUTH)".to_string(),
        // HID Crescendo's PIV-applet-level INJECT PKI KEY (CLA 0x80) — this
        // crate only ever builds its "delete" form (see `piv_cmd_sensitive`'s
        // matching arm for why that's also why it's never redacted); told
        // apart from the ACA's own PUT XAUTH KEY below by CLA, since both
        // share INS 0xD8.
        None if ins == 0xD8 && apdu.first() == Some(&0x80) => {
            "INJECT PKI KEY (HID Crescendo, delete)".to_string()
        }
        // `Lc` alone tells PUT XAUTH KEY's two forms apart: `0x04` is the
        // documented "remove" short form
        // ([`keyroost_piv::fingerprint::hid_crescendo_aca_put_xauth_key_remove`]);
        // every other `Lc` (`0x1D` TDES, `0x15` AES-128) installs a new key
        // ([`keyroost_piv::fingerprint::hid_crescendo_aca_put_xauth_key`]).
        None if ins == 0xD8 => match apdu.get(4) {
            Some(0x04) => "PUT XAUTH KEY (HID ACA, delete)".to_string(),
            _ => "PUT XAUTH KEY (HID ACA)".to_string(),
        },
        // GlobalPlatform `GET DATA` for CPLC (Card Production Life Cycle)
        // data ([`keyroost_piv::fingerprint::GLOBAL_PLATFORM_GET_CPLC`]) —
        // ISO 7816-4's plain GET DATA, with the tag folded straight into
        // P1P2 (`9F 7F`) rather than PIV's `5C`-wrapped selector, and CLA
        // 0x80 against GlobalPlatform's ISD rather than the PIV applet. Its
        // INS 0xCA isn't one `piv::Instruction` models (PIV's own GET DATA
        // is 0xCB), so `from_code` answers `None` and this would otherwise
        // print as a bare "INS 0xCA". Only used today by
        // `PivSession::probe_hid_crescendo_cplc_serial` to derive HID
        // Crescendo's serial before PIV is ever selected.
        None if apdu == piv::fingerprint::GLOBAL_PLATFORM_GET_CPLC => {
            "GET DATA (GlobalPlatform CPLC)".to_string()
        }
        // Token2's own `GET_INFO` (INS 0x33, vendor's name — see
        // `keyroost_token2otp::cmd::READ_SERIAL_INS`'s doc) against the OTP
        // applet: not a `piv::Instruction` (it's a Token2 vendor command, not
        // PIV), so `from_code` answers `None` and this would otherwise print
        // as a bare "INS 0x33". Only used today by
        // `PivSession::probe_token2_otp_serial` to read a Token2 or Thetis
        // unit's full serial, after that probe has already SELECTed the OTP
        // applet.
        None if ins == 0x33 => "GET_INFO (Token2 OTP applet)".to_string(),
        None => format!("INS {ins:#04X}"),
    }
}

/// The data field of an APDU, handling both the short (`Lc` in one byte) and
/// extended (`00 Lc_hi Lc_lo`) length encodings. Any trailing `Le` is ignored.
fn command_data(apdu: &[u8]) -> Option<&[u8]> {
    match apdu.get(4..)? {
        [] => None,
        // Extended length: 0x00 marker, then a two-byte Lc, then the body.
        [0x00, hi, lo, rest @ ..] if !rest.is_empty() => {
            rest.get(..(usize::from(*hi) << 8 | usize::from(*lo)))
        }
        // Short form: one Lc byte, then the body (possibly with a trailing Le).
        [lc, rest @ ..] => rest.get(..usize::from(*lc)).or(Some(rest)),
    }
}

/// The `5C <len> <tag>` object selector at the head of a GET DATA / PUT DATA
/// body, if present.
fn object_selector_tag(apdu: &[u8]) -> Option<&[u8]> {
    match command_data(apdu)? {
        [0x5C, len, rest @ ..] => rest.get(..usize::from(*len)),
        _ => None,
    }
}

/// `KEYROOST_PIV_FORCE_CHAINING` forces the command-chaining path (so the
/// fallback can be exercised on a card that also accepts extended length —
/// mirrors `KEYROOST_OPENPGP_FORCE_CHAINING`).
fn force_chaining() -> bool {
    std::env::var_os("KEYROOST_PIV_FORCE_CHAINING").is_some()
}

/// Whether the connection to `card` negotiated T=0. Fails open: if the
/// status query itself fails, report "not T=0" so behaviour stays exactly
/// what it was before this check existed (extended-length first, status-word
/// fallback second) — a wrong "T=0" answer would silently downgrade every
/// large command on a perfectly good T=1 link.
fn negotiated_t0(card: &Card) -> bool {
    let mut names = [0u8; 256];
    let mut atr = [0u8; pcsc::MAX_ATR_SIZE];
    match card.status2(&mut names, &mut atr) {
        Ok(status) => status.protocol2() == Some(pcsc::Protocol::T0),
        Err(_) => false,
    }
}

/// The chain-up-front decision as a pure function, so the rule is testable
/// without a card: chain when the operator forces it, or when the link is
/// T=0 and therefore cannot carry extended-length APDUs at all.
fn chain_upfront_for(t0: bool, forced: bool) -> bool {
    forced || t0
}

impl<'tx> PivSession<'tx> {
    fn chain_upfront(&self) -> bool {
        chain_upfront_for(self.t0, force_chaining())
    }

    fn chain_reason(&self) -> &'static str {
        if force_chaining() {
            "env override"
        } else {
            "T=0 link: extended-length APDUs are not possible on this protocol"
        }
    }
}

/// Turn to-be-signed bytes into the block the card's GENERAL AUTHENTICATE
/// expects: PKCS#1 v1.5 over SHA-256 for RSA (the card does raw RSA), the bare
/// SHA-256/384/512 digest for ECDSA, and the unhashed message for Ed25519.
fn prepared_block(alg: KeyAlg, tbs: &[u8]) -> Result<Vec<u8>, TransportError> {
    use keyroost_piv::x509::{self, SigHash};
    match x509::signature_hash(alg).map_err(TransportError::X509)? {
        SigHash::Sha256 => {
            let digest = keyroost_proto::sha256::sha256(tbs);
            let rsa_k = match alg {
                KeyAlg::Rsa1024 => Some(128),
                KeyAlg::Rsa2048 => Some(256),
                KeyAlg::Rsa3072 => Some(384),
                KeyAlg::Rsa4096 => Some(512),
                _ => None,
            };
            Ok(match rsa_k {
                Some(k) => x509::pkcs1_v15_sha256(&digest, k),
                None => digest.to_vec(),
            })
        }
        SigHash::Sha384 => Ok(keyroost_proto::sha512::sha384(tbs).to_vec()),
        SigHash::Sha512 => Ok(keyroost_proto::sha512::sha512(tbs).to_vec()),
        SigHash::None => Ok(tbs.to_vec()),
    }
}

/// `(algorithm, raw public key)` from a GET METADATA response, only when it
/// actually carries both — the single gate [`PivSession::slot_key`] uses to
/// decide whether a metadata reply is usable or whether to fall back to the
/// session's pubkey cache. Split out as a pure, card-free function (same seam
/// style as `PubkeyCache`) so the "is this metadata usable" rule is
/// unit-testable without a card: some PIV implementations answer GET METADATA
/// with `SW_OK` but an empty or partial body for slots they haven't wired
/// reporting up for yet (observed on Nitrokey's `piv-authenticator`, whose
/// `GetMetadata` handler is a stub for every slot but card-authentication) —
/// functionally the same as "no GET METADATA support" for our purposes, not a
/// malformed response worth erroring the caller over.
///
/// `resolve_alg` decodes the metadata's raw algorithm-identifier byte: a real
/// call site passes [`PivSession::key_alg_from_apdu_id`] (this fingerprint's
/// own wire-byte override, falling back to [`KeyAlg::from_id`]'s
/// Yubico-default table), while the unit tests below pass [`KeyAlg::from_id`]
/// directly — keeping this pure and card-free/session-free rather than
/// threading a `&mut PivSession` through it just to resolve one byte.
fn metadata_key_material(
    md: &Metadata,
    resolve_alg: impl FnMut(u8) -> Option<KeyAlg>,
) -> Option<(KeyAlg, &[u8])> {
    let alg = md.algorithm.and_then(resolve_alg)?;
    let raw = md.public_key.as_deref()?;
    Some((alg, raw))
}

/// The certificate DER inside a `9000` GET DATA body for a slot's cert
/// object: the `0x70` TLV's value. `None` when the body carries no
/// certificate — a `53 00` empty template (Nitrokey's `piv-authenticator`
/// answers a deleted slot this way instead of `6A82`), a `0x53` object with
/// no `0x70`, or a body that isn't a `0x53` data template at all (not
/// expected from a real card, and degraded rather than errored — this feeds
/// read-only status calls). `Err` when there IS a certificate, flagged
/// compressed, that won't inflate — reported as unreadable, never as empty.
/// Pure, so the byte cases stay unit-tested.
fn cert_object_der(body: &[u8]) -> Result<Option<Vec<u8>>, CertUnreadable> {
    let Some((der, gzip)) = piv::unwrap_data_object(body)
        .ok()
        .and_then(piv::cert_object_parts)
    else {
        return Ok(None);
    };
    if gzip {
        // The object holds the cert gzip-compressed (CertInfo bit 0, which
        // the writing tool chose). Inflate it before anyone parses it as DER;
        // never hand the compressed bytes on.
        gunzip_capped(der).map(Some)
    } else {
        Ok(Some(der.to_vec()))
    }
}

/// A slot's [`PivSlotStatus`] from its decoded certificate object: present
/// (with its DER byte length) when non-empty, present-but-unreadable when a
/// certificate is there that won't decode, absent otherwise.
fn slot_occupancy(slot: piv::Slot, cert: Result<Option<&[u8]>, CertUnreadable>) -> PivSlotStatus {
    match cert {
        Err(reason) => PivSlotStatus {
            slot,
            cert_present: true,
            cert_len: 0,
            cert_unreadable: Some(reason),
        },
        Ok(der) => {
            let len = der.map_or(0, <[u8]>::len);
            PivSlotStatus {
                slot,
                cert_present: len > 0,
                cert_len: len,
                cert_unreadable: None,
            }
        }
    }
}

/// Behind [`PivSession::reject_certificate_key_mismatch`]: true when a slot's
/// known key and a certificate's key are for different algorithms or
/// different key material. Split out as a pure function (no card I/O) so the
/// actual comparison stays unit-tested without a mock session.
fn certificate_key_mismatches(
    slot_alg: KeyAlg,
    slot_key: &PublicKey,
    cert_alg: KeyAlg,
    cert_key: &PublicKey,
) -> bool {
    slot_alg != cert_alg || slot_key != cert_key
}

/// Behind [`PivSession::reject_certificate_key_mismatch`]'s secondary,
/// algorithm-only path: `Some((slot_algorithm, certificate_algorithm))` when
/// `get_slot_key_status_gate` resolves
/// [`FeatureGate::Supported`](keyroost_piv::compat::FeatureGate::Supported)
/// *and* both algorithms are actually known *and* they differ; `None`
/// otherwise (gate not `Supported`, or either side unknowable, or they
/// agree) — every one of those is "nothing to refuse on", same "absence of
/// information is not evidence of a mismatch" standard the primary,
/// full-key path applies. Split out as a pure function (no card I/O) so the
/// decision table is unit-tested without a mock session, same as
/// [`certificate_key_mismatches`] above.
fn algorithm_only_mismatch(
    get_slot_key_status_gate: keyroost_piv::compat::FeatureGate,
    slot_algorithm: Option<KeyAlg>,
    cert_algorithm: Option<KeyAlg>,
) -> Option<(KeyAlg, KeyAlg)> {
    if get_slot_key_status_gate != keyroost_piv::compat::FeatureGate::Supported {
        return None;
    }
    match (slot_algorithm, cert_algorithm) {
        (Some(s), Some(c)) if s != c => Some((s, c)),
        _ => None,
    }
}

/// Decode the public key carried in GET METADATA tag `0x04`. Yubico encodes it
/// as the same TLVs a GENERATE response carries — observed both with and
/// without the outer `7F49` template across firmware, so accept either shape.
fn public_key_from_metadata(raw: &[u8]) -> Result<PublicKey, keyroost_piv::ParseError> {
    if raw.starts_with(&[0x7F, 0x49]) {
        return piv::parse_public_key(raw);
    }
    // Bare inner TLVs: 86 (EC point) or 81/82 (RSA modulus/exponent).
    if let Some(point) = piv::find_tlv(raw, 0x86) {
        return Ok(PublicKey::Ecc {
            point: point.to_vec(),
        });
    }
    match (piv::find_tlv(raw, 0x81), piv::find_tlv(raw, 0x82)) {
        (Some(m), Some(e)) => Ok(PublicKey::Rsa {
            modulus: m.to_vec(),
            exponent: e.to_vec(),
        }),
        _ => Err(keyroost_piv::ParseError::NotPublicKey),
    }
}

/// Constant-time slice equality (fold-XOR; no early exit on the bytes).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Map a PIV status word to success or a labelled APDU error.
fn ok_or_apdu(label: &'static str, sw: u16) -> Result<(), TransportError> {
    if sw == piv::SW_OK {
        Ok(())
    } else {
        Err(TransportError::Apdu {
            label,
            sw1: (sw >> 8) as u8,
            sw2: sw as u8,
        })
    }
}

/// Like [`ok_or_apdu`] but maps the "security status not satisfied" word a write
/// returns when management-key auth or the PIN hasn't been presented.
fn ok_or_write(label: &'static str, sw: u16) -> Result<(), TransportError> {
    if sw == piv::SW_SECURITY_NOT_SATISFIED {
        Err(TransportError::PivSecurityNotSatisfied)
    } else {
        ok_or_apdu(label, sw)
    }
}

/// Map a PIN/PUK-verification status word: `9000` ok, `63 Cx` / `6983` rejected
/// with the remaining-try count, anything else a generic APDU error.
fn map_pin_sw(sw: u16) -> Result<(), TransportError> {
    if sw == piv::SW_OK {
        Ok(())
    } else if let Some(n) = crate::sw_tries_remaining(sw) {
        Err(TransportError::PivPinRejected {
            tries_remaining: Some(n),
        })
    } else if sw == piv::SW_AUTH_BLOCKED {
        Err(TransportError::PivPinRejected {
            tries_remaining: Some(0),
        })
    } else {
        Err(TransportError::Apdu {
            label: "piv pin/puk",
            sw1: (sw >> 8) as u8,
            sw2: sw as u8,
        })
    }
}

/// What [`block_crypt`] should do with a block.
#[derive(Clone, Copy)]
enum CryptOp {
    Encrypt,
    Decrypt,
}

/// AES / 3DES ECB single-block (or block-aligned) transform for the
/// management-key witness/challenge round. `data` must be a non-empty multiple
/// of the cipher block size — the witness comes from the card, and an unaligned
/// length would otherwise panic in the block conversion below.
fn block_crypt(
    alg: MgmtAlg,
    key: &[u8],
    data: &[u8],
    op: CryptOp,
) -> Result<Vec<u8>, TransportError> {
    use cipher::generic_array::GenericArray;
    use cipher::{BlockDecrypt, BlockEncrypt, KeyInit};

    if data.is_empty() || data.len() % alg.block_size() != 0 {
        return Err(TransportError::MalformedResponse(
            "PIV witness/challenge length is not a whole cipher block",
        ));
    }

    fn run<C: BlockEncrypt + BlockDecrypt>(c: &C, data: &[u8], op: CryptOp, bs: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len());
        for chunk in data.chunks(bs) {
            let mut block = GenericArray::clone_from_slice(chunk);
            match op {
                CryptOp::Encrypt => c.encrypt_block(&mut block),
                CryptOp::Decrypt => c.decrypt_block(&mut block),
            }
            out.extend_from_slice(&block);
        }
        out
    }

    let bad = |_| TransportError::PivBadKeyLength;
    match alg {
        MgmtAlg::TripleDes => {
            let c = des::TdesEde3::new_from_slice(key).map_err(bad)?;
            Ok(run(&c, data, op, 8))
        }
        MgmtAlg::Aes128 => {
            let c = aes::Aes128::new_from_slice(key).map_err(bad)?;
            Ok(run(&c, data, op, 16))
        }
        MgmtAlg::Aes192 => {
            let c = aes::Aes192::new_from_slice(key).map_err(bad)?;
            Ok(run(&c, data, op, 16))
        }
        MgmtAlg::Aes256 => {
            let c = aes::Aes256::new_from_slice(key).map_err(bad)?;
            Ok(run(&c, data, op, 16))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gzip::MAX_CERT_DECOMPRESSED;

    #[test]
    fn decode_serial_if_bcd_applies_only_when_the_quirk_resolves() {
        use keyroost_piv::fingerprint::AppletFingerprint;

        // Token2 carries `InsF8SerialIsBcd` for any reported applet version
        // (see `keyroost_piv::compat`'s `QUIRKS_BY_APPLET_TABLE`) — 0x1234
        // read as packed BCD is decimal 1234.
        assert_eq!(
            decode_serial_if_bcd(AppletFingerprint::Token2, Some(&[1, 0]), None, Some(0x1234)),
            Some(1234)
        );
        // Neither applet_version nor firmware_version reported at all:
        // `resolve_quirks` substitutes the universal `[]` sentinel on both
        // (see its own "Both axes unset" doc), so the quirk still resolves.
        assert_eq!(
            decode_serial_if_bcd(AppletFingerprint::Token2, None, None, Some(0x1234)),
            Some(1234)
        );
        // A fingerprint with no quirk-table entry at all: unchanged.
        assert_eq!(
            decode_serial_if_bcd(
                AppletFingerprint::YubiKey,
                Some(&[5, 7]),
                None,
                Some(0x1234)
            ),
            Some(0x1234)
        );
        // No serial to begin with: still `None`, quirk or not.
        assert_eq!(
            decode_serial_if_bcd(AppletFingerprint::Token2, Some(&[1, 0]), None, None),
            None
        );
    }

    #[test]
    fn clear_metadata_if_quirky_strips_algorithm_and_public_key_together() {
        use keyroost_piv::compat::PivQuirk;

        let md = Metadata {
            algorithm: Some(0x07),
            policy: Some((0x01, 0x02)),
            origin: Some(1),
            public_key: Some(vec![0xAB, 0xCD]),
            is_default: Some(false),
            retries: None,
        };

        // The quirk active: algorithm and public key are gone, every other
        // field survives untouched.
        let quirky = BTreeSet::from([PivQuirk::InsF7MetadataAlgorithmInvalid]);
        let cleared = clear_metadata_if_quirky(&quirky, md.clone());
        assert_eq!(
            cleared,
            Metadata {
                algorithm: None,
                public_key: None,
                ..md.clone()
            }
        );

        // No quirk active (empty set, or a set with an unrelated quirk):
        // passed through unchanged.
        assert_eq!(clear_metadata_if_quirky(&BTreeSet::new(), md.clone()), md);
        let other = BTreeSet::from([PivQuirk::InsF8SerialIsBcd]);
        assert_eq!(clear_metadata_if_quirky(&other, md.clone()), md);
    }

    #[test]
    fn clear_metadata_if_quirky_strips_pin_touch_policy_independently_of_algorithm() {
        use keyroost_piv::compat::PivQuirk;

        let md = Metadata {
            algorithm: Some(0x07),
            policy: Some((0x01, 0x02)),
            origin: Some(1),
            public_key: Some(vec![0xAB, 0xCD]),
            is_default: Some(false),
            retries: None,
        };

        // Only the policy quirk active: policy is gone, algorithm/public key
        // (guarded by the *other* quirk) survive untouched.
        let quirky = BTreeSet::from([PivQuirk::InsF7MetadataPinTouchPolicyInvalid]);
        let cleared = clear_metadata_if_quirky(&quirky, md.clone());
        assert_eq!(
            cleared,
            Metadata {
                policy: None,
                ..md.clone()
            }
        );

        // Both quirks active together: both fields are gone, independently.
        let both = BTreeSet::from([
            PivQuirk::InsF7MetadataPinTouchPolicyInvalid,
            PivQuirk::InsF7MetadataAlgorithmInvalid,
        ]);
        assert_eq!(
            clear_metadata_if_quirky(&both, md.clone()),
            Metadata {
                algorithm: None,
                public_key: None,
                policy: None,
                ..md
            }
        );
    }

    #[test]
    fn describe_apdu_names_the_command() {
        assert_eq!(
            describe_apdu(&piv::select_full()),
            "SELECT (NIST PIV Card Application)"
        );
        // The short RID-only PIV AID names the same application.
        assert_eq!(
            describe_apdu(&piv::select()),
            "SELECT (NIST PIV Card Application)"
        );
        assert_eq!(
            describe_apdu(&piv::get_version()),
            "GET VERSION (yubico extension)"
        );
        // GET DATA / PUT DATA name the object in their 5C selector; an
        // unknown tag falls back to raw hex; both length encodings parse.
        assert_eq!(
            describe_apdu(&piv::get_data(&Slot::Authentication.cert_object_tag())),
            "GET DATA (5F C1 05 \u{2192} X.509 Certificate for PIV Authentication)"
        );
        assert_eq!(
            describe_apdu(&piv::get_data(&[0x5F, 0xC1, 0x99])),
            "GET DATA (5F C1 99)"
        );
        assert_eq!(
            describe_apdu(&piv::put_data(
                &Slot::Signature.cert_object_tag(),
                &[0x53, 0x00]
            )),
            "PUT DATA (5F C1 0A \u{2192} X.509 Certificate for Digital Signature)"
        );
        assert_eq!(
            describe_apdu(&piv::put_data_chained(&[0x5F, 0xC1, 0x0C], &[0x01], 254)[0]),
            "PUT DATA (5F C1 0C \u{2192} Key History Object)"
        );
        // 0xF6 with the P1 == 0xFF sentinel is DELETE, not MOVE.
        assert_eq!(
            describe_apdu(&piv::delete_key(Slot::Signature)),
            "DELETE KEY (yubico extension)"
        );
        assert_eq!(
            describe_apdu(&piv::move_key(Slot::Retired(1), Slot::Authentication)),
            "MOVE KEY (yubico extension)"
        );
        // Bodyless VERIFY is a retry-counter query.
        assert_eq!(
            describe_apdu(&piv::verify_pin_status()),
            "VERIFY (retry-counter query)"
        );
        assert!(describe_apdu(&piv::verify_pin(b"12345678").unwrap()).starts_with("VERIFY"));
        // Unknown / malformed fall back rather than panic.
        assert_eq!(describe_apdu(&[0x00, 0x99, 0x00, 0x00]), "INS 0x99");
        assert_eq!(describe_apdu(&[]), "(malformed APDU)");
    }

    #[test]
    fn describe_apdu_names_fingerprinting_probe_aids() {
        assert_eq!(
            describe_apdu(&piv::select_by_aid(&keyroost_piv::fingerprint::FEITIAN_RID)),
            "SELECT (Feitian RID)"
        );
        assert_eq!(
            describe_apdu(&piv::select_by_aid(
                &keyroost_piv::fingerprint::SWISSBIT_RID
            )),
            "SELECT (Swissbit RID)"
        );
        assert_eq!(
            describe_apdu(&piv::select_by_aid(
                &keyroost_piv::fingerprint::IDPRIME_SECONDARY_PIV_AID
            )),
            "SELECT (IdPrime secondary PIV AID)"
        );
        assert_eq!(
            describe_apdu(&piv::select_by_aid(
                &keyroost_piv::fingerprint::NITROKEY_ADMIN_AID
            )),
            "SELECT (Nitrokey admin AID)"
        );
        assert_eq!(
            describe_apdu(&piv::select_by_aid(&keyroost_token2otp::OTP_APPLET_AID)),
            "SELECT (Token2 OTP applet)"
        );
        // An AID none of the probes use stays plain, unlabeled SELECT.
        assert_eq!(
            describe_apdu(&piv::select_by_aid(&[0xA0, 0x00, 0x00, 0x00, 0x03])),
            "SELECT"
        );
    }

    #[test]
    fn describe_apdu_names_the_token2_otp_get_info() {
        // Token2's own GET_INFO (INS 0x33) isn't a `piv::Instruction` at
        // all — `PivSession::probe_token2_otp_serial`'s only use of it — so
        // without this it would fall through to the bare "INS 0x33".
        assert_eq!(
            describe_apdu(&keyroost_token2otp::read_serial_request()),
            "GET_INFO (Token2 OTP applet)"
        );
    }

    #[test]
    fn describe_apdu_names_the_hid_aca_select() {
        // Not a fingerprinting probe like the AIDs above — the ACA instance
        // `authenticate_management_hid_crescendo_aca`/
        // `hid_crescendo_aca_put_xauth_key_op` temporarily SELECT into for
        // the XAUTH unlock / PUT XAUTH KEY sequence, so a trace reader can
        // tell it apart from an unrecognized SELECT at a glance.
        assert_eq!(
            describe_apdu(&piv::select_by_aid(
                &keyroost_piv::fingerprint::HID_CRESCENDO_ACA_AID
            )),
            "SELECT (HID ActivID ACA)"
        );
    }

    #[test]
    fn describe_apdu_names_the_hid_aca_xauth_instructions() {
        // GET CHALLENGE and EXTERNAL AUTHENTICATE aren't PIV at all — not
        // modeled in `piv::Instruction` — so without this they'd fall
        // through to a bare "INS 0x84"/"INS 0x82".
        assert_eq!(
            describe_apdu(&keyroost_piv::fingerprint::HID_CRESCENDO_ACA_GET_CHALLENGE),
            "GET CHALLENGE (HID ACA XAUTH)"
        );
        assert_eq!(
            describe_apdu(
                &keyroost_piv::fingerprint::hid_crescendo_aca_external_authenticate(&[0xAAu8; 8])
            ),
            "EXTERNAL AUTHENTICATE (HID ACA XAUTH)"
        );
        // PUT XAUTH KEY's two forms are told apart by Lc alone: installing a
        // key (any algorithm) vs. HID's documented Lc=04h "delete" form.
        assert_eq!(
            describe_apdu(
                &keyroost_piv::fingerprint::hid_crescendo_aca_put_xauth_key(
                    MgmtAlg::TripleDes,
                    &[0u8; 24]
                )
                .unwrap()
            ),
            "PUT XAUTH KEY (HID ACA)"
        );
        assert_eq!(
            describe_apdu(
                &keyroost_piv::fingerprint::hid_crescendo_aca_put_xauth_key(
                    MgmtAlg::Aes128,
                    &[0u8; 16]
                )
                .unwrap()
            ),
            "PUT XAUTH KEY (HID ACA)"
        );
        assert_eq!(
            describe_apdu(&keyroost_piv::fingerprint::hid_crescendo_aca_put_xauth_key_remove()),
            "PUT XAUTH KEY (HID ACA, delete)"
        );
    }

    #[test]
    fn describe_apdu_names_hid_inject_pki_key_and_tells_it_apart_from_aca_put_xauth_key() {
        // Both INJECT PKI KEY (CLA 0x80) and the ACA's PUT XAUTH KEY (CLA
        // 0x00) share INS 0xD8 — CLA alone tells them apart.
        assert_eq!(
            describe_apdu(
                &keyroost_piv::fingerprint::hid_crescendo_c2300_delete_key(KeyAlg::Rsa2048, 0x9A)
                    .unwrap()
            ),
            "INJECT PKI KEY (HID Crescendo, delete)"
        );
        assert_eq!(
            describe_apdu(
                &keyroost_piv::fingerprint::hid_crescendo_c4000_delete_key(KeyAlg::EccP256, 0x9C)
                    .unwrap()
            ),
            "INJECT PKI KEY (HID Crescendo, delete)"
        );
        // The ACA's own PUT XAUTH KEY (CLA 0x00) still names itself, not
        // this — regression guard for the CLA disambiguation.
        assert_eq!(
            describe_apdu(&keyroost_piv::fingerprint::hid_crescendo_aca_put_xauth_key_remove()),
            "PUT XAUTH KEY (HID ACA, delete)"
        );
    }

    #[test]
    fn describe_apdu_names_the_globalplatform_cplc_read() {
        // `80 CA 9F 7F 00` — GlobalPlatform's plain GET DATA for CPLC, tag
        // folded into P1P2 rather than PIV's `5C`-wrapped selector. INS
        // 0xCA isn't modeled in `piv::Instruction` (PIV's own GET DATA is
        // 0xCB), so without this arm it falls through to a bare "INS 0xCA".
        assert_eq!(
            describe_apdu(&keyroost_piv::fingerprint::GLOBAL_PLATFORM_GET_CPLC),
            "GET DATA (GlobalPlatform CPLC)"
        );
        // A lookalike with a different P1P2 stays unnamed — only the exact
        // CPLC read is recognized.
        assert_eq!(describe_apdu(&[0x80, 0xCA, 0x00, 0x00, 0x00]), "INS 0xCA");
    }

    #[test]
    fn describe_apdu_names_the_globalplatform_isd_select() {
        // The SELECT that has to precede `GLOBAL_PLATFORM_GET_CPLC` above —
        // without a `known_aid_name` entry for it, this fell through to a
        // bare "SELECT" in the trace, same as any AID this crate doesn't
        // recognize.
        assert_eq!(
            describe_apdu(&piv::select_by_aid(
                &keyroost_piv::fingerprint::GLOBAL_PLATFORM_ISD_AID
            )),
            "SELECT (GlobalPlatform Issuer Security Domain)"
        );
    }

    #[test]
    fn piv_cmd_sensitive_covers_every_secret_bearing_ins_including_hid_aca() {
        // Secret-bearing: PINs/PUKs, GENERAL AUTHENTICATE, SET MANAGEMENT
        // KEY, and the two HID ACA instructions that carry key-derived or
        // raw key material.
        for ins in [0x20u8, 0x24, 0x2C, 0x87, 0xFF, 0x82, 0xD8] {
            assert!(
                piv_cmd_sensitive(&[0x00, ins, 0x00, 0x00, 0x08, 0, 0, 0, 0, 0, 0, 0, 0]),
                "INS {ins:#04X} should be redacted"
            );
        }
        // GET CHALLENGE: empty body, public-nonce response — nothing to hide.
        assert!(!piv_cmd_sensitive(
            &keyroost_piv::fingerprint::HID_CRESCENDO_ACA_GET_CHALLENGE
        ));
        // An unrelated INS (SELECT) is never sensitive either.
        assert!(!piv_cmd_sensitive(&piv::select_full()));
        // A real PUT XAUTH KEY install still redacts its body...
        assert!(piv_cmd_sensitive(
            &keyroost_piv::fingerprint::hid_crescendo_aca_put_xauth_key(
                MgmtAlg::TripleDes,
                &[0u8; 24]
            )
            .unwrap()
        ));
        // ...but the Lc=04h "delete" form carries no key material at all —
        // four fixed, publicly-known bytes — so it must not be redacted.
        assert!(!piv_cmd_sensitive(
            &keyroost_piv::fingerprint::hid_crescendo_aca_put_xauth_key_remove()
        ));
        // HID Crescendo's own INJECT PKI KEY delete (CLA 0x80, same INS
        // 0xD8) never carries key material either — always the fixed
        // "delete" data field — so it must not be redacted regardless of
        // algorithm/Lc.
        assert!(!piv_cmd_sensitive(
            &keyroost_piv::fingerprint::hid_crescendo_c2300_delete_key(KeyAlg::Rsa2048, 0x9A)
                .unwrap()
        ));
        assert!(!piv_cmd_sensitive(
            &keyroost_piv::fingerprint::hid_crescendo_c4000_delete_key(KeyAlg::EccP256, 0x9C)
                .unwrap()
        ));
    }

    #[test]
    fn mgmt_algs_for_key_len_disambiguates_by_length() {
        use MgmtAlg::*;
        // Unique lengths pin a single algorithm.
        assert_eq!(mgmt_algs_for_key_len(16), &[Aes128]);
        assert_eq!(mgmt_algs_for_key_len(32), &[Aes256]);
        // 24 bytes fits both 3DES and AES-192 — 3DES first (the historical
        // pre-GET-METADATA default), then the P1 probe decides.
        assert_eq!(mgmt_algs_for_key_len(24), &[TripleDes, Aes192]);
        // Every candidate's own key_len() must round-trip back to a list that
        // contains it — the table and MgmtAlg::key_len() must not drift apart.
        for alg in [TripleDes, Aes128, Aes192, Aes256] {
            assert!(mgmt_algs_for_key_len(alg.key_len()).contains(&alg));
        }
        // Nothing plausible-looking (single-DES) or absurd resolves.
        assert!(mgmt_algs_for_key_len(8).is_empty());
        assert!(mgmt_algs_for_key_len(0).is_empty());
        assert!(mgmt_algs_for_key_len(20).is_empty());
    }

    #[test]
    fn pick_mgmt_alg_narrows_probe_results_by_length() {
        use MgmtAlg::*;

        // One probe accepted, right length -> that one.
        assert_eq!(pick_mgmt_alg(&[Aes128], 16), Some(Aes128));
        // One probe accepted, wrong length for the key in hand -> nothing.
        assert_eq!(pick_mgmt_alg(&[Aes256], 24), None);

        // A lax card accepts every P1. The 24-byte key narrows it to 3DES +
        // AES-192, and 3DES wins the tie.
        assert_eq!(
            pick_mgmt_alg(&[TripleDes, Aes128, Aes192, Aes256], 24),
            Some(TripleDes)
        );
        // Same lax card, 16-byte key -> unambiguously AES-128.
        assert_eq!(
            pick_mgmt_alg(&[TripleDes, Aes128, Aes192, Aes256], 16),
            Some(Aes128)
        );
        // 24-byte key, but only AES-192 was accepted -> no 3DES to prefer.
        assert_eq!(pick_mgmt_alg(&[Aes192], 24), Some(Aes192));
        // 24-byte key, both 24-byte algs accepted but in the other order ->
        // still 3DES (preference, not position).
        assert_eq!(pick_mgmt_alg(&[Aes192, TripleDes], 24), Some(TripleDes));

        // Empty accepted set = probe learned nothing -> fall back to length
        // alone (same as the pre-probe behaviour).
        assert_eq!(pick_mgmt_alg(&[], 16), Some(Aes128));
        assert_eq!(pick_mgmt_alg(&[], 24), Some(TripleDes));
        assert_eq!(pick_mgmt_alg(&[], 32), Some(Aes256));
        assert_eq!(pick_mgmt_alg(&[], 20), None);
    }

    // --- pubkey-cache transitions ---------------------------------------
    //
    // The session methods that drive these transitions need a live card, so
    // what gets pinned here is the PubkeyCache transition each of them is a
    // one-line caller of. What these defend: whether the entry came from a
    // self-known write or a device-reported one, a stale entry silently
    // produces a certificate whose SPKI doesn't match the private key on the
    // card, and a confirmed-empty slot must not cost another APDU on the
    // next read (the common case — most slots are empty on any real device).

    fn ecc(byte: u8) -> PublicKey {
        PublicKey::Ecc {
            point: vec![0x04, byte],
        }
    }

    fn rsa(byte: u8) -> PublicKey {
        PublicKey::Rsa {
            modulus: vec![byte],
            exponent: vec![0x01, 0x00, 0x01],
        }
    }

    #[test]
    fn pubkey_cache_starts_empty_and_get_distinguishes_unasked_from_empty() {
        // A fresh open() has nothing to fall back to — there is deliberately
        // no on-disk or cross-process persistence.
        let mut cache = PubkeyCache::default();
        assert!(cache.0.is_empty());
        // Never asked about 0x9A at all.
        assert_eq!(cache.get(0x9A), None);
        // Asked (a live GET METADATA decode), and the card names neither
        // algorithm nor public key for this slot — a real answer, distinct
        // from "never asked", so the next read skips the APDU.
        cache.remember(0x9A, None);
        assert_eq!(cache.get(0x9A), Some(None));
    }

    #[test]
    fn pubkey_remember_replaces_the_slots_previous_entry() {
        // generate_key over an occupied slot mints a new keypair: the old
        // cached pubkey must not survive to describe the new private key.
        let mut cache = PubkeyCache::default();
        cache.remember(0x9A, Some((KeyAlg::EccP256, ecc(1))));
        cache.remember(0x9A, Some((KeyAlg::Rsa2048, rsa(2))));
        assert_eq!(cache.0.len(), 1);
        assert_eq!(cache.get(0x9A), Some(Some(&(KeyAlg::Rsa2048, rsa(2)))));
    }

    #[test]
    fn pubkey_evict_forgets_only_the_deleted_slot() {
        let mut cache = PubkeyCache::default();
        cache.remember(0x9A, Some((KeyAlg::EccP256, ecc(1))));
        cache.remember(0x9C, Some((KeyAlg::EccP384, ecc(2))));
        cache.evict(0x9A);
        // Evicted back to "never asked", not to "asked, empty" — the next
        // read must issue a real APDU, not trust a synthesized empty answer.
        // The deleted slot's key material is gone from the card either way;
        // a bystander slot's entry is still good.
        assert_eq!(cache.get(0x9A), None);
        assert_eq!(cache.get(0x9C), Some(Some(&(KeyAlg::EccP384, ecc(2)))));
        // Deleting a slot this session never cached is a quiet no-op.
        cache.evict(0x82);
        assert_eq!(cache.0.len(), 1);
    }

    #[test]
    fn pubkey_migrate_carries_the_entry_and_leaves_nothing_at_src() {
        let mut cache = PubkeyCache::default();
        cache.remember(0x9A, Some((KeyAlg::EccP256, ecc(1))));
        cache.remember(0x9C, Some((KeyAlg::EccP384, ecc(2))));
        cache.migrate(0x9A, 0x82);
        // The key relocated: its entry follows it to dest — that's what keeps
        // CSR/self-sign working at dest on metadata-less firmware — and src
        // no longer holds anything to describe.
        assert_eq!(cache.get(0x9A), None);
        assert_eq!(cache.get(0x82), Some(Some(&(KeyAlg::EccP256, ecc(1)))));
        // A bystander slot is untouched.
        assert_eq!(cache.get(0x9C), Some(Some(&(KeyAlg::EccP384, ecc(2)))));
    }

    #[test]
    fn pubkey_migrate_of_an_uncached_src_changes_nothing() {
        // Moving a key this session never generated: there is nothing to
        // carry, and crucially nothing gets invented at dest.
        let mut cache = PubkeyCache::default();
        cache.remember(0x9C, Some((KeyAlg::EccP384, ecc(2))));
        cache.migrate(0x9A, 0x82);
        assert_eq!(cache.get(0x82), None);
        assert_eq!(cache.get(0x9C), Some(Some(&(KeyAlg::EccP384, ecc(2)))));
        assert_eq!(cache.0.len(), 1);
    }

    #[test]
    fn pubkey_migrate_replaces_a_stale_dest_entry() {
        // The card refuses MOVE KEY into an occupied slot, so any dest entry
        // present here is stale by definition (e.g. remember_pubkey of a slot
        // that was later emptied out-of-session) — the key that actually
        // arrived must win.
        let mut cache = PubkeyCache::default();
        cache.remember(0x9A, Some((KeyAlg::EccP256, ecc(1))));
        cache.remember(0x82, Some((KeyAlg::EccP384, ecc(9))));
        cache.migrate(0x9A, 0x82);
        assert_eq!(cache.get(0x82), Some(Some(&(KeyAlg::EccP256, ecc(1)))));
        assert_eq!(cache.get(0x9A), None);
        assert_eq!(cache.0.len(), 1);
    }

    #[test]
    fn pubkey_cache_default_starts_empty() {
        assert!(PubkeyCache::default().0.is_empty());
    }

    // --- policy cache transitions — mirrors the pubkey cache tests above,
    // same lifecycle and "never asked" vs. "asked, got nothing" distinction,
    // different value shape -----------------------------------------------

    #[test]
    fn policy_cache_starts_empty_and_get_distinguishes_unasked_from_empty() {
        let mut cache = PolicyCache::default();
        assert!(cache.0.is_empty());
        assert_eq!(cache.get(0x9A), None);
        // Resolved: neither GET METADATA nor ATTEST names a policy.
        cache.remember(0x9A, None);
        assert_eq!(cache.get(0x9A), Some(None));
    }

    #[test]
    fn policy_remember_replaces_the_slots_previous_entry() {
        // A regenerate mints a new keypair with a (possibly different)
        // policy: the old cached policy must not survive to describe it.
        let mut cache = PolicyCache::default();
        cache.remember(0x9A, Some((PinPolicy::Once, TouchPolicy::Always)));
        cache.remember(0x9A, Some((PinPolicy::Never, TouchPolicy::Cached)));
        assert_eq!(cache.0.len(), 1);
        assert_eq!(
            cache.get(0x9A),
            Some(Some((PinPolicy::Never, TouchPolicy::Cached)))
        );
    }

    #[test]
    fn policy_evict_forgets_only_the_deleted_slot() {
        let mut cache = PolicyCache::default();
        cache.remember(0x9A, Some((PinPolicy::Once, TouchPolicy::Always)));
        cache.remember(0x9C, Some((PinPolicy::Always, TouchPolicy::Never)));
        cache.evict(0x9A);
        assert_eq!(cache.get(0x9A), None);
        assert_eq!(
            cache.get(0x9C),
            Some(Some((PinPolicy::Always, TouchPolicy::Never)))
        );
        // Deleting a slot this session never cached is a quiet no-op.
        cache.evict(0x82);
        assert_eq!(cache.0.len(), 1);
    }

    #[test]
    fn policy_migrate_carries_the_entry_and_leaves_nothing_at_src() {
        let mut cache = PolicyCache::default();
        cache.remember(0x9A, Some((PinPolicy::Once, TouchPolicy::Always)));
        cache.remember(0x9C, Some((PinPolicy::Always, TouchPolicy::Never)));
        cache.migrate(0x9A, 0x82);
        assert_eq!(cache.get(0x9A), None);
        assert_eq!(
            cache.get(0x82),
            Some(Some((PinPolicy::Once, TouchPolicy::Always)))
        );
        assert_eq!(
            cache.get(0x9C),
            Some(Some((PinPolicy::Always, TouchPolicy::Never)))
        );
    }

    #[test]
    fn policy_migrate_of_an_uncached_src_changes_nothing() {
        let mut cache = PolicyCache::default();
        cache.remember(0x9C, Some((PinPolicy::Always, TouchPolicy::Never)));
        cache.migrate(0x9A, 0x82);
        assert_eq!(cache.get(0x82), None);
        assert_eq!(
            cache.get(0x9C),
            Some(Some((PinPolicy::Always, TouchPolicy::Never)))
        );
        assert_eq!(cache.0.len(), 1);
    }

    #[test]
    fn policy_migrate_replaces_a_stale_dest_entry() {
        let mut cache = PolicyCache::default();
        cache.remember(0x9A, Some((PinPolicy::Once, TouchPolicy::Always)));
        cache.remember(0x82, Some((PinPolicy::Always, TouchPolicy::Never)));
        cache.migrate(0x9A, 0x82);
        assert_eq!(
            cache.get(0x82),
            Some(Some((PinPolicy::Once, TouchPolicy::Always)))
        );
        assert_eq!(cache.get(0x9A), None);
        assert_eq!(cache.0.len(), 1);
    }

    #[test]
    fn policy_cache_default_starts_empty() {
        assert!(PolicyCache::default().0.is_empty());
    }

    // --- certificate cache transitions — same "never asked" vs. "asked,
    // empty" shape as the metadata cache above, but never touched by
    // move_key/delete_key: neither relocates or erases a certificate object. -

    #[test]
    fn cert_cache_starts_empty_and_get_distinguishes_unasked_from_empty() {
        let mut cache = CertCache::default();
        assert!(cache.0.is_empty());
        assert_eq!(cache.get(0x9A), None);
        // clear_certificate's write: asked (or just cleared), no certificate.
        cache.remember(0x9A, Ok(None));
        assert_eq!(cache.get(0x9A), Some(Ok(None)));
    }

    #[test]
    fn cert_remember_replaces_the_slots_previous_entry() {
        // import_certificate over an occupied slot: the old DER must not
        // survive to be handed back as this slot's current certificate.
        let mut cache = CertCache::default();
        cache.remember(0x9A, Ok(Some(vec![0x01])));
        cache.remember(0x9A, Ok(Some(vec![0x02])));
        assert_eq!(cache.0.len(), 1);
        assert_eq!(cache.get(0x9A), Some(Ok(Some(vec![0x02]))));
    }

    #[test]
    fn cert_cache_default_starts_empty() {
        assert!(CertCache::default().0.is_empty());
    }

    // --- metadata-vs-cache fallback gate ---------------------------------
    //
    // `slot_key` treats GET METADATA as usable only when it actually names
    // both the algorithm and the public key; anything short of that (empty,
    // algorithm-only, pubkey-only — e.g. Nitrokey's piv-authenticator, whose
    // GetMetadata handler is a stub for every slot but card-authentication
    // and answers SW_OK with nothing) must fall through to the pubkey cache
    // instead of erroring the caller.

    #[test]
    fn metadata_with_neither_field_is_not_usable() {
        // The stub-firmware case: SW_OK, empty body.
        assert_eq!(
            metadata_key_material(&Metadata::default(), KeyAlg::from_id),
            None
        );
    }

    #[test]
    fn metadata_with_only_algorithm_is_not_usable() {
        let md = Metadata {
            algorithm: Some(KeyAlg::EccP256.id()),
            ..Metadata::default()
        };
        assert_eq!(metadata_key_material(&md, KeyAlg::from_id), None);
    }

    #[test]
    fn metadata_with_only_public_key_is_not_usable() {
        let md = Metadata {
            public_key: Some(vec![0x86, 0x01, 0x04]),
            ..Metadata::default()
        };
        assert_eq!(metadata_key_material(&md, KeyAlg::from_id), None);
    }

    #[test]
    fn metadata_with_an_unrecognized_algorithm_id_is_not_usable() {
        // A byte GET METADATA reported that this crate's KeyAlg doesn't cover.
        let md = Metadata {
            algorithm: Some(0xFF),
            public_key: Some(vec![0x86, 0x01, 0x04]),
            ..Metadata::default()
        };
        assert_eq!(metadata_key_material(&md, KeyAlg::from_id), None);
    }

    #[test]
    fn metadata_with_both_fields_is_usable() {
        let md = Metadata {
            algorithm: Some(KeyAlg::EccP256.id()),
            public_key: Some(vec![0x86, 0x01, 0x04]),
            ..Metadata::default()
        };
        assert_eq!(
            metadata_key_material(&md, KeyAlg::from_id),
            Some((KeyAlg::EccP256, &[0x86, 0x01, 0x04][..]))
        );
    }

    // --- certificate DER out of a GET DATA reply --------------------------
    //
    // `cert_object_der` is what `read_certificate` (and, through it,
    // `slot_status` / `status_detailed`) uses to decide whether a slot holds
    // a certificate. The regression this guards: a deleted slot answering
    // SW_OK with an empty `53 00` template (Nitrokey's piv-authenticator,
    // observed with `piv status` after `piv delete-cert`) must read as empty,
    // not "cert present (0 bytes)".

    #[test]
    fn cert_object_der_empty_template_is_none() {
        // `53 00`: object present, zero-length value — the Nitrokey case.
        assert_eq!(cert_object_der(&[0x53, 0x00]), Ok(None));
    }

    #[test]
    fn cert_object_der_populated_template_yields_the_inner_value() {
        // `53 03 70 01 AB`: a (fake, minimal) `70` TLV wrapping one byte,
        // CertInfo absent so it reads as uncompressed and passes through.
        assert_eq!(
            cert_object_der(&[0x53, 0x03, 0x70, 0x01, 0xAB]),
            Ok(Some(vec![0xAB]))
        );
    }

    /// gzip-wrap `payload` (minimal RFC 1952 header, raw-DEFLATE body, and
    /// the real CRC32 + ISIZE trailer the reader verifies).
    fn gzip(payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0xFF];
        v.extend_from_slice(&miniz_oxide::deflate::compress_to_vec(payload, 6));
        v.extend_from_slice(&crate::gzip::crc32(payload).to_le_bytes());
        v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        v
    }

    #[test]
    fn gunzip_capped_round_trips() {
        let der = b"\x30\x82\x01\x0a hello certificate bytes";
        assert_eq!(gunzip_capped(&gzip(der)).as_deref(), Ok(&der[..]));
        // Not gzip -> Damaged, no panic.
        assert_eq!(
            gunzip_capped(b"\x30\x03\x01\x01\xff"),
            Err(CertUnreadable::Damaged)
        );
        assert_eq!(gunzip_capped(&[]), Err(CertUnreadable::Damaged));
    }

    #[test]
    fn cert_object_der_inflates_a_gzip_compressed_cert() {
        // The exact shape that broke #147: CertInfo 0x01 (gzip) with the cert
        // stored compressed. cert_object_der must return the ORIGINAL DER.
        let der = b"\x30\x82\x01\x0a a yubikey attestation cert (stand-in)";
        let gz = gzip(der);
        // Build 53 { 70 <gz> 71 01 01 FE 00 } with short-form lengths.
        assert!(gz.len() < 0x80, "test vector must stay short-form");
        let mut inner = vec![0x70, gz.len() as u8];
        inner.extend_from_slice(&gz);
        inner.extend_from_slice(&[0x71, 0x01, 0x01, 0xFE, 0x00]);
        let mut obj = vec![0x53, inner.len() as u8];
        obj.extend_from_slice(&inner);
        assert_eq!(cert_object_der(&obj), Ok(Some(der.to_vec())));
    }

    /// `53 { 70 <payload> 71 01 01 FE 00 }` — a cert object flagged
    /// gzip-compressed, with long-form lengths so large payloads fit.
    fn compressed_cert_object(payload: &[u8]) -> Vec<u8> {
        fn tlv(tag: u8, val: &[u8]) -> Vec<u8> {
            let n = val.len();
            let mut v = vec![tag];
            match n {
                0..=0x7F => v.push(n as u8),
                0x80..=0xFF => v.extend_from_slice(&[0x81, n as u8]),
                _ => v.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]),
            }
            v.extend_from_slice(val);
            v
        }
        let mut inner = tlv(0x70, payload);
        inner.extend_from_slice(&[0x71, 0x01, 0x01, 0xFE, 0x00]);
        tlv(0x53, &inner)
    }

    // A slot whose certificate is flagged compressed but will not inflate
    // holds *something* — it must read as unreadable, never as empty, so
    // `piv status` doesn't invite overwriting it and `export-cert` doesn't
    // report "no certificate" (#147 follow-up; seen on a YubiKey 5.7).

    #[test]
    fn cert_object_der_flagged_compressed_but_not_gzip_is_damaged() {
        let obj = compressed_cert_object(b"\x30\x82\x01\x0a plain DER, wrongly flagged");
        assert_eq!(cert_object_der(&obj), Err(CertUnreadable::Damaged));
    }

    #[test]
    fn cert_object_der_invalid_deflate_body_is_damaged() {
        // A gzip header, then a DEFLATE block of reserved type (BTYPE = 11),
        // which no decoder accepts, then the 8-byte trailer.
        let mut gz = vec![0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0xFF];
        gz.extend_from_slice(&[0x07, 0x00, 0x00]);
        gz.extend_from_slice(&[0u8; 8]);
        let obj = compressed_cert_object(&gz);
        assert_eq!(cert_object_der(&obj), Err(CertUnreadable::Damaged));
    }

    #[test]
    fn cert_object_der_truncated_gzip_is_damaged() {
        let der: Vec<u8> = (0..400u32).map(|i| (i * 7 % 251) as u8).collect();
        let gz = gzip(&der);
        let obj = compressed_cert_object(&gz[..gz.len() / 2]);
        assert_eq!(cert_object_der(&obj), Err(CertUnreadable::Damaged));
    }

    #[test]
    fn cert_object_der_over_the_inflate_cap_is_too_large() {
        let obj = compressed_cert_object(&gzip(&vec![0u8; MAX_CERT_DECOMPRESSED + 1]));
        assert_eq!(cert_object_der(&obj), Err(CertUnreadable::TooLarge));
    }

    #[test]
    fn cert_object_der_exactly_at_the_inflate_cap_is_read() {
        let der = vec![0u8; MAX_CERT_DECOMPRESSED];
        let obj = compressed_cert_object(&gzip(&der));
        assert_eq!(cert_object_der(&obj), Ok(Some(der)));
    }

    #[test]
    fn slot_occupancy_marks_an_unreadable_cert_present_not_empty() {
        let occ = slot_occupancy(piv::Slot::KeyManagement, Err(CertUnreadable::Damaged));
        assert!(occ.cert_present);
        assert_eq!(occ.cert_len, 0);
        assert_eq!(occ.cert_unreadable, Some(CertUnreadable::Damaged));
        let ok = slot_occupancy(piv::Slot::KeyManagement, Ok(Some(&[0xAB][..])));
        assert_eq!(ok.cert_unreadable, None);
    }

    #[test]
    fn unreadable_cert_error_names_the_slot_and_the_reason() {
        let e = TransportError::PivCertUnreadable {
            slot: piv::Slot::KeyManagement,
            reason: CertUnreadable::Damaged,
        };
        let msg = e.to_string();
        assert!(msg.contains(&piv::Slot::KeyManagement.label()), "{msg}");
        assert!(msg.contains("compressed data is damaged"), "{msg}");
        let e = TransportError::PivCertUnreadable {
            slot: piv::Slot::KeyManagement,
            reason: CertUnreadable::TooLarge,
        };
        assert!(e.to_string().contains("64 KiB"), "{e}");
    }

    #[test]
    fn a_pcsc_failure_of_an_extended_apdu_retries_chained() {
        let pcsc = Err(TransportError::Pcsc(pcsc::Error::NotTransacted));
        assert!(retry_chained_after(&pcsc, true));
        // A short APDU has nothing to gain from chaining.
        assert!(!retry_chained_after(&pcsc, false));
        // Any other error propagates.
        assert!(!retry_chained_after(
            &Err(TransportError::HostRngFailed),
            true
        ));
        // A status word, success or not, is the SW-driven fallback's call.
        assert!(!retry_chained_after(&Ok((Vec::new(), piv::SW_OK)), true));
        assert!(!retry_chained_after(&Ok((Vec::new(), 0x6700)), true));
    }

    #[test]
    fn cert_write_status_names_too_large_and_card_full() {
        let slot = piv::Slot::Signature;
        assert!(matches!(
            cert_write_result(slot, 3087, piv::SW_WRONG_LENGTH),
            Err(TransportError::PivCertTooLarge { len: 3087, .. })
        ));
        assert!(matches!(
            cert_write_result(slot, 3087, piv::SW_NOT_ENOUGH_MEMORY),
            Err(TransportError::PivCardFull { .. })
        ));
        assert!(cert_write_result(slot, 10, piv::SW_OK).is_ok());
        assert!(matches!(
            cert_write_result(slot, 10, piv::SW_SECURITY_NOT_SATISFIED),
            Err(TransportError::PivSecurityNotSatisfied)
        ));
    }

    #[test]
    fn a_mid_chain_length_or_memory_refusal_reaches_the_cert_mapping() {
        let apdu = |sw1, sw2| {
            Err(TransportError::Apdu {
                label: "piv import certificate",
                sw1,
                sw2,
            })
        };
        assert_eq!(chained_cert_sw(apdu(0x67, 0x00)).ok(), Some(0x6700));
        assert_eq!(chained_cert_sw(apdu(0x6A, 0x84)).ok(), Some(0x6A84));
        assert_eq!(chained_cert_sw(Ok((Vec::new(), 0x9000))).ok(), Some(0x9000));
        // Other intermediate refusals keep their generic error.
        assert!(matches!(
            chained_cert_sw(apdu(0x69, 0x82)),
            Err(TransportError::Apdu { sw1: 0x69, .. })
        ));
    }

    #[test]
    fn too_large_and_card_full_errors_name_the_slot_and_size() {
        let slot = piv::Slot::Signature;
        let msg = TransportError::PivCertTooLarge { slot, len: 3087 }.to_string();
        assert!(msg.contains(&slot.label()), "{msg}");
        assert!(msg.contains("3087 bytes"), "{msg}");
        assert!(msg.contains("too large"), "{msg}");
        let msg = TransportError::PivCardFull { slot }.to_string();
        assert!(msg.contains(&slot.label()), "{msg}");
        assert!(msg.contains("no room left"), "{msg}");
    }

    #[test]
    fn cert_object_der_template_without_70_is_none() {
        // `53 02 71 00`: a `0x53` object carrying only a cert-info `71` TLV.
        assert_eq!(cert_object_der(&[0x53, 0x02, 0x71, 0x00]), Ok(None));
    }

    #[test]
    fn cert_object_der_unparseable_body_is_none_not_a_panic() {
        // Not a `0x53` template at all — shouldn't happen on a real card, but
        // a read-only status call must degrade gracefully, not panic or error.
        assert_eq!(cert_object_der(&[0xFF, 0x00]), Ok(None));
    }

    #[test]
    fn slot_occupancy_reads_present_only_for_a_non_empty_cert() {
        let slot = piv::Slot::Authentication;
        assert!(!slot_occupancy(slot, Ok(None)).cert_present);
        assert!(!slot_occupancy(slot, Ok(Some(&[]))).cert_present);
        let occ = slot_occupancy(slot, Ok(Some(&[0xAB, 0xCD])));
        assert!(occ.cert_present);
        assert_eq!(occ.cert_len, 2);
    }

    // --- cert_len is the DER length, not the `0x53` object's value length -
    //
    // `PivSlotStatus::cert_len` documents the certificate's DER length as
    // read from the card, not the size of the object wrapping it. These
    // pin that end-to-end through the same two pure helpers `read_certificate`
    // and `status_detailed` share: `cert_object_der` (strip the framing) then
    // `slot_occupancy` (measure what's left).

    #[test]
    fn slot_occupancy_cert_len_is_der_length_not_object_length() {
        // `53 <len> 70 <len> <der> 71 01 00 FE 00`: a YubiKey-shaped object —
        // DER wrapped in `70`, followed by the `71` CertInfo and `FE`
        // error-detection TLVs. `cert_len` must be the DER's own length (4),
        // not the larger `70`..`FE` object span.
        let der = [0xAA, 0xBB, 0xCC, 0xDD];
        let inner = [
            0x70, 0x04, 0xAA, 0xBB, 0xCC, 0xDD, // `70` cert DER
            0x71, 0x01, 0x00, // CertInfo
            0xFE, 0x00, // error detection
        ];
        let mut body = vec![0x53, inner.len() as u8];
        body.extend_from_slice(&inner);

        let cert_der = cert_object_der(&body);
        assert_eq!(cert_der, Ok(Some(der.to_vec())));
        let occ = slot_occupancy(
            piv::Slot::Authentication,
            cert_der.as_ref().map(Option::as_deref).map_err(|e| *e),
        );
        assert!(occ.cert_present);
        assert_eq!(occ.cert_len, der.len());
    }

    #[test]
    fn slot_occupancy_cert_len_is_der_length_when_71_and_fe_are_absent() {
        // `53 <len> 70 <len> <der>`: some non-YubiKey PIV applets omit the
        // `71`/`FE` TLVs entirely. `cert_len` is still just the DER length.
        let der = [0x01, 0x02, 0x03, 0x04, 0x05];
        let mut inner = vec![0x70, der.len() as u8];
        inner.extend_from_slice(&der);
        let mut body = vec![0x53, inner.len() as u8];
        body.extend_from_slice(&inner);

        let cert_der = cert_object_der(&body);
        assert_eq!(cert_der, Ok(Some(der.to_vec())));
        let occ = slot_occupancy(
            piv::Slot::Authentication,
            cert_der.as_ref().map(Option::as_deref).map_err(|e| *e),
        );
        assert!(occ.cert_present);
        assert_eq!(occ.cert_len, der.len());
    }

    // --- certificate_key_mismatches: the pure comparison behind
    // `PivSession::reject_certificate_key_mismatch` — see that method's
    // (and `PivSession::import_certificate`'s) doc for what feeds it.

    #[test]
    fn certificate_key_mismatches_same_alg_and_material_is_not_a_mismatch() {
        let key = PublicKey::Rsa {
            modulus: vec![0xAA; 256],
            exponent: vec![0x01, 0x00, 0x01],
        };
        assert!(!certificate_key_mismatches(
            KeyAlg::Rsa2048,
            &key,
            KeyAlg::Rsa2048,
            &key
        ));
    }

    #[test]
    fn certificate_key_mismatches_differing_key_material_is_a_mismatch() {
        let slot_key = PublicKey::Rsa {
            modulus: vec![0xAA; 256],
            exponent: vec![0x01, 0x00, 0x01],
        };
        let cert_key = PublicKey::Rsa {
            modulus: vec![0xBB; 256],
            exponent: vec![0x01, 0x00, 0x01],
        };
        assert!(certificate_key_mismatches(
            KeyAlg::Rsa2048,
            &slot_key,
            KeyAlg::Rsa2048,
            &cert_key
        ));
    }

    #[test]
    fn certificate_key_mismatches_differing_algorithm_is_a_mismatch_even_with_equal_bytes() {
        // Same `PublicKey` bytes under two different `KeyAlg`s (an EC point at
        // the wrong curve) must still count as a mismatch — the algorithm
        // itself is part of what has to agree.
        let point = PublicKey::Ecc {
            point: vec![0xCC; 97],
        };
        assert!(certificate_key_mismatches(
            KeyAlg::EccP256,
            &point,
            KeyAlg::EccP384,
            &point
        ));
    }

    // --- algorithm_only_mismatch: the pure comparison behind
    // `PivSession::reject_certificate_key_mismatch`'s secondary,
    // algorithm-only path — see that method's (and
    // `PivSession::import_certificate`'s) doc for what feeds it.

    #[test]
    fn algorithm_only_mismatch_fires_only_when_the_gate_is_supported() {
        use keyroost_piv::compat::FeatureGate;

        // The one case that actually refuses: gate `Supported`, both
        // algorithms known, and they differ (an RSA slot, an ECC cert).
        assert_eq!(
            algorithm_only_mismatch(
                FeatureGate::Supported,
                Some(KeyAlg::Rsa2048),
                Some(KeyAlg::EccP256)
            ),
            Some((KeyAlg::Rsa2048, KeyAlg::EccP256))
        );
        // Same disagreement, but the gate isn't `Supported` -> not trustworthy
        // enough to refuse on, same standard `slot_confirmed_empty` (GUI) and
        // the primary key check apply elsewhere.
        assert_eq!(
            algorithm_only_mismatch(
                FeatureGate::Unverified,
                Some(KeyAlg::Rsa2048),
                Some(KeyAlg::EccP256)
            ),
            None
        );
        assert_eq!(
            algorithm_only_mismatch(
                FeatureGate::Unsupported,
                Some(KeyAlg::Rsa2048),
                Some(KeyAlg::EccP256)
            ),
            None
        );
    }

    #[test]
    fn algorithm_only_mismatch_requires_both_sides_known() {
        use keyroost_piv::compat::FeatureGate;

        // Slot's algorithm unknowable (e.g. GetSlotKeyStatus's own channel
        // came up empty too) -> nothing to compare, not a mismatch.
        assert_eq!(
            algorithm_only_mismatch(FeatureGate::Supported, None, Some(KeyAlg::EccP256)),
            None
        );
        // Certificate's algorithm unparsable -> same "can't verify" outcome.
        assert_eq!(
            algorithm_only_mismatch(FeatureGate::Supported, Some(KeyAlg::Rsa2048), None),
            None
        );
    }

    #[test]
    fn algorithm_only_mismatch_agreeing_algorithms_is_not_a_mismatch() {
        use keyroost_piv::compat::FeatureGate;

        assert_eq!(
            algorithm_only_mismatch(
                FeatureGate::Supported,
                Some(KeyAlg::EccP256),
                Some(KeyAlg::EccP256)
            ),
            None
        );
    }

    #[test]
    fn block_attempts_cap_exceeds_reported_but_is_bounded() {
        // A card reporting 3 tries: we try a few more than 3 to guarantee a block.
        assert_eq!(block_attempts_cap(Some(3)), 5);
        // Unknown count: default to 10 (max PIV retry the spec allows) + margin.
        assert_eq!(block_attempts_cap(None), 12);
        // A pathological huge count is clamped so the loop can't run away.
        assert_eq!(block_attempts_cap(Some(200)), 22);
        // A raised PUK count (set-retries allows more than the old hardcoded 12)
        // still outlasts the card.
        assert_eq!(block_attempts_cap(Some(15)), 17);
    }

    #[test]
    fn credential_guess_is_eight_digits_and_varies() {
        let mut previous: Option<Zeroizing<Vec<u8>>> = None;
        for _ in 0..64 {
            let guess = random_credential_guess(previous.as_ref().map(|g| g.as_slice())).unwrap();
            // 8 bytes keeps it inside the 6-8 range PIV and OpenPGP store, so
            // the card evaluates it instead of rejecting it on length.
            assert_eq!(guess.len(), 8);
            assert!(guess.iter().all(u8::is_ascii_digit));
            // Never the same twice running: an applet that ignores an unchanged
            // credential would not count the attempt.
            assert_ne!(previous.as_ref().map(|g| g.to_vec()), Some(guess.to_vec()));
            previous = Some(guess);
        }
    }

    #[test]
    fn credential_guess_steps_off_a_collision() {
        // Entropy that maps straight onto "01234567".
        let raw = [0u8, 1, 2, 3, 4, 5, 6, 7];
        assert_eq!(credential_guess_from(&raw, None).as_slice(), b"01234567");
        // Same draw, but that's what we just sent: last digit moves on.
        assert_eq!(
            credential_guess_from(&raw, Some(b"01234567")).as_slice(),
            b"01234568"
        );
        // The bump wraps rather than running past '9'.
        let nines = [9u8; 8];
        assert_eq!(
            credential_guess_from(&nines, Some(b"99999999")).as_slice(),
            b"99999990"
        );
    }

    #[test]
    fn reset_refusals_report_an_unrecoverable_card() {
        // The card's final word on RESET, once the PIN and PUK are already
        // blocked: PivResetNotAllowed (`PivSession::reset` folds 6982, 6983,
        // and 6985 into this one variant — the precondition RESET has,
        // re-checked identically on a re-run) and the 6D00 / 6A81 pair that
        // means the instruction does not exist.
        for e in [
            TransportError::PivResetNotAllowed,
            TransportError::Apdu {
                label: "piv reset",
                sw1: 0x6D,
                sw2: 0x00,
            },
            TransportError::Apdu {
                label: "piv reset",
                sw1: 0x6A,
                sw2: 0x81,
            },
        ] {
            let mapped = map_reset_stage_error(e);
            assert!(matches!(mapped, TransportError::PivResetIncomplete(_)));
            let text = mapped.to_string();
            // The message has to say what is true and never point back at the
            // command that just failed.
            assert!(text.contains("NOT wiped"));
            assert!(text.contains("no keyroost command"));
            assert!(!text.contains("re-run"));
        }
    }

    #[test]
    fn reset_transient_refusals_fall_through() {
        // Status words the card can answer under the RESET label that say
        // nothing about RESET being unavailable: 6F00 (no precise diagnosis),
        // 6881, and a 6A82 from an applet that momentarily lost its selection
        // after the blocking loops. The PIN and PUK really are blocked by then,
        // but the applet is still resettable — re-running the factory reset
        // against a quiescent applet succeeds — so calling the card
        // permanently unusable would steer the user away from the fix. These
        // pass through untouched and pick up the caller's re-run hint.
        //
        // PivSecurityNotSatisfied (6982) is covered here defensively rather
        // than because it's reachable: `PivSession::reset` now maps a live
        // 6982 straight onto PivResetNotAllowed itself (the same terminal
        // bucket as 6983/6985 — some fingerprints answer RESET's "PIN/PUK
        // must already be blocked" precondition with 6982 instead), so
        // `ok_or_write`'s own 6982-to-PivSecurityNotSatisfied mapping never
        // actually fires for a RESET response any more. Kept here so this
        // function still degrades safely — falling through, not declaring
        // the card permanently unusable — if this variant ever reaches it by
        // some other route.
        for e in [
            TransportError::Apdu {
                label: "piv reset",
                sw1: 0x6F,
                sw2: 0x00,
            },
            TransportError::Apdu {
                label: "piv reset",
                sw1: 0x68,
                sw2: 0x81,
            },
            TransportError::Apdu {
                label: "piv reset",
                sw1: 0x6A,
                sw2: 0x82,
            },
            TransportError::PivSecurityNotSatisfied,
        ] {
            let before = e.to_string();
            let mapped = map_reset_stage_error(e);
            assert!(!matches!(mapped, TransportError::PivResetIncomplete(_)));
            assert_eq!(mapped.to_string(), before);
        }
    }

    #[test]
    fn transport_faults_at_reset_are_left_alone() {
        // A card that stopped answering is not a card refusing RESET — the wipe
        // may still be finishable, so these must pass through unchanged.
        for e in [
            TransportError::ShortResponse {
                label: "piv",
                got: 1,
                expected_min: 2,
            },
            TransportError::MalformedResponse("applet continuation exceeded the chunk limit"),
            // A label from some other command can only mean an error that did
            // not originate at the RESET step.
            TransportError::Apdu {
                label: "piv pin/puk",
                sw1: 0x6A,
                sw2: 0x81,
            },
        ] {
            let before = e.to_string();
            assert_eq!(map_reset_stage_error(e).to_string(), before);
        }
    }
}

/// Issue #103: a T=0 contact card cannot receive extended-length APDUs and
/// may go silent when handed one, so the status-word fallback (#101) never
/// gets a status word to act on. On T=0 links, chaining must be the FIRST
/// choice, not the fallback.
#[cfg(test)]
mod chain_upfront_rule {
    use super::chain_upfront_for;

    #[test]
    fn t0_links_chain_from_the_start() {
        assert!(chain_upfront_for(true, false));
    }

    #[test]
    fn the_env_override_still_forces_chaining_on_any_link() {
        assert!(chain_upfront_for(false, true));
        assert!(chain_upfront_for(true, true));
    }

    #[test]
    fn t1_links_keep_extended_length_first() {
        // The #101 fallback covers a T=1 card that refuses extended length
        // with a status word; nothing here may pre-empt that path.
        assert!(!chain_upfront_for(false, false));
    }
}

/// [`with_cached_transaction`](PivSession::with_cached_transaction)'s cache-validity rules, pinned
/// without a card via the pure functions the live checks feed into — see
/// [`pcsc_reading_usable`], [`pcsc_event_count_unchanged`], and
/// [`piv_session_cache_reusable`].
#[cfg(test)]
mod open_cached_validity_rules {
    use super::{
        pcsc_event_count_unchanged, pcsc_reading_usable, piv_session_cache_reusable, State,
    };

    #[test]
    fn an_unreadable_reader_status_is_never_usable() {
        // `None` stands for "the status query itself failed" — indistinguishable
        // from "don't trust it" to every caller.
        assert!(!pcsc_reading_usable(None));
    }

    #[test]
    fn a_plain_present_reading_is_usable() {
        assert!(pcsc_reading_usable(Some(State::PRESENT)));
    }

    #[test]
    fn a_changed_bit_alone_does_not_disqualify_a_reading() {
        // This is the exact fix, pinned so it can't regress: `CHANGED` also
        // trips on reader-state churn that has nothing to do with the card
        // (INUSE/EXCLUSIVE toggling from *any* connection to the reader,
        // including this crate's own previous session) — relying on it here
        // made every reconnect look "changed" and defeated the cache
        // entirely. `pcsc_event_count_unchanged` is what actually decides
        // whether the card itself changed; this function only screens out
        // readings PC/SC says are outright unusable.
        assert!(pcsc_reading_usable(Some(State::PRESENT | State::CHANGED)));
    }

    #[test]
    fn unknown_unavailable_and_mute_are_never_usable() {
        assert!(!pcsc_reading_usable(Some(State::UNKNOWN)));
        assert!(!pcsc_reading_usable(Some(State::UNAVAILABLE)));
        assert!(!pcsc_reading_usable(Some(State::MUTE)));
    }

    #[test]
    fn matching_event_counts_are_unchanged() {
        assert!(pcsc_event_count_unchanged(Some(5), Some(5)));
        assert!(pcsc_event_count_unchanged(Some(0), Some(0)));
    }

    #[test]
    fn a_different_event_count_is_a_change() {
        // The exact case `with_cached_transaction` exists to catch: a removal — even one
        // immediately followed by a reinsertion that settles back into an
        // outwardly identical `PRESENT` state — always bumps this counter.
        assert!(!pcsc_event_count_unchanged(Some(5), Some(6)));
    }

    #[test]
    fn a_missing_count_on_either_side_proves_nothing() {
        // Never resolved before, or this reading's query failed: neither is
        // "proof of no change".
        assert!(!pcsc_event_count_unchanged(None, Some(5)));
        assert!(!pcsc_event_count_unchanged(Some(5), None));
        assert!(!pcsc_event_count_unchanged(None, None));
    }

    #[test]
    fn reuse_requires_every_check_to_agree() {
        assert!(piv_session_cache_reusable(true, true));
        assert!(!piv_session_cache_reusable(false, true));
        assert!(!piv_session_cache_reusable(true, false));
        assert!(!piv_session_cache_reusable(false, false));
    }
}

/// `PcscIdentity::matches`'s field-by-field rules, pinned without a card —
/// see [`open_cached_validity_rules`] for the lower-level pieces
/// (`pcsc_event_count_unchanged`) this builds on.
#[cfg(test)]
mod pcsc_identity_matching {
    use super::PcscIdentity;

    fn identity(reader_name: &str, event_count: u32, atr: &[u8]) -> PcscIdentity {
        PcscIdentity {
            reader_name: reader_name.to_owned(),
            event_count: Some(event_count),
            atr: atr.to_vec(),
        }
    }

    #[test]
    fn an_identical_reading_matches() {
        let a = identity("Reader 0", 3, &[0x3B, 0x00]);
        let b = identity("Reader 0", 3, &[0x3B, 0x00]);
        assert!(a.matches(&b));
    }

    #[test]
    fn a_different_reader_name_never_matches() {
        // The exact case this whole type exists to catch: two readers whose
        // event counter and ATR both happen to agree (an easy coincidence —
        // both untouched since `pcscd` started, say, or two of the same
        // card model in two different ports) must never be trusted for each
        // other just because a caller's own storage isn't keyed by reader
        // name.
        let a = identity("Reader 0", 0, &[0x3B, 0x00]);
        let b = identity("Reader 1", 0, &[0x3B, 0x00]);
        assert!(!a.matches(&b));
    }

    #[test]
    fn a_different_event_count_never_matches() {
        let a = identity("Reader 0", 3, &[0x3B, 0x00]);
        let b = identity("Reader 0", 4, &[0x3B, 0x00]);
        assert!(!a.matches(&b));
    }

    #[test]
    fn a_different_atr_never_matches() {
        let a = identity("Reader 0", 3, &[0x3B, 0x00]);
        let b = identity("Reader 0", 3, &[0x3B, 0xFF]);
        assert!(!a.matches(&b));
    }

    #[test]
    fn two_never_resolved_identities_do_not_match() {
        // Both `PcscIdentity::default()`: same (empty) reader name, same
        // (empty) ATR, but neither has a real event count — `None` on both
        // sides must not read as "unchanged" (see
        // `pcsc_event_count_unchanged`'s own tests), so this must not match
        // either, even though the surface fields line up.
        assert!(!PcscIdentity::default().matches(&PcscIdentity::default()));
    }
}
