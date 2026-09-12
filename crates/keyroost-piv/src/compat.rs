//! Per-fingerprint white/blacklist for the non-standard PIV commands keyroost
//! exposes.
//!
//! A handful of management operations in this crate are vendor extensions, not
//! SP 800-73-4: Yubico's MOVE KEY and DELETE KEY, which landed in YubiKey
//! firmware 5.7. "Speaks PIV" says nothing about whether a given applet
//! implements them, and the answer can differ between firmware versions of the
//! same product. This module encodes what keyroost has actually observed,
//! keyed by [`AppletFingerprint`], as a **combined white/blacklist**: for each
//! fingerprint it knows about, a list of per-version verdicts each either
//! [`Verdict::Whitelisted`] ("extension known to be supported at this version")
//! or [`Verdict::Blacklisted`] ("extension known to be unsupported at this
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
//! versions adjacent to it, in both directions: a whitelist verdict extends
//! *forward* ("known to work at this version, assumed to still work at any
//! later, untested version") and, symmetrically, a blacklist verdict extends
//! *backward* ("known not to work at this version, assumed not to work at any
//! earlier, untested version either"). Anything less certain — no verdicts
//! for the fingerprint at all, no reported version, or a blacklist verdict old
//! enough that a later firmware might have added the extension — resolves to
//! [`FeatureGate::Unverified`] on that axis, which keeps the control usable
//! unless the other axis disagrees.
//!
//! The same per-version rows also carry [`PivQuirk`]s — observed behavioral
//! wrinkles that need a workaround rather than gating a control. Quirks are
//! resolved separately by [`resolve_quirks`], with simpler semantics than
//! [`resolve`]: no whitelist/blacklist, just "take the current entry on each
//! axis and merge whatever quirks it lists."

use std::collections::BTreeSet;

use crate::fingerprint::{AppletFingerprint, OpenFips201Variant};

/// One of the non-standard, vendor-extension PIV commands keyroost exposes —
/// nothing in SP 800-73-4 defines it, so support varies by applet and is
/// gated by device fingerprint through [`resolve`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PivExtension {
    /// Yubico MOVE KEY — relocate a slot's private key into another slot.
    MoveKey,
    /// Yubico DELETE KEY — erase a slot's private key in place.
    DeleteKey,
}

impl PivExtension {
    /// This extension's white/blacklist keyed by the PIV **applet's own**
    /// version (Yubico's `GET VERSION` extension reply): one
    /// [`FingerprintVerdicts`] row per fingerprint keyroost has data for on
    /// this axis. A fingerprint absent from the slice means "no data" and
    /// [`resolve`] treats this axis as [`FeatureGate::Unverified`].
    #[must_use]
    fn applet_verdicts(self) -> &'static [FingerprintVerdicts] {
        match self {
            // MOVE KEY and DELETE KEY shipped together in YubiKey firmware
            // 5.7: unsupported at every earlier version, supported from 5.7
            // on. Token2 applet 5.112.0 has separately been observed to
            // reject both, so it carries its own blacklist row in the same
            // table — as does the Swissbit iShield 2 Pro (fingerprinted
            // `OpenFips201::SwissbitIShield2`) at applet version 1.4.1.0 and
            // below, and the Thetis PRO FIDO2 Security Key with PinPlex
            // (`AppletFingerprint::Thetis`) at applet version 5.112.0 and
            // below.
            PivExtension::MoveKey | PivExtension::DeleteKey => KEY_OPS_VERDICTS,
        }
    }

    /// This extension's white/blacklist keyed by the device's **firmware**
    /// version, same shape and lookup rules as [`Self::applet_verdicts`] but a
    /// separate axis — a fingerprint can have data on one and not the other.
    /// No fingerprint has firmware-version data yet, so every extension
    /// resolves this axis to [`FeatureGate::Unverified`] today.
    #[must_use]
    fn firmware_verdicts(self) -> &'static [FingerprintVerdicts] {
        match self {
            PivExtension::MoveKey | PivExtension::DeleteKey => &[],
        }
    }

    /// A one-sentence statement of what running this extension needs, phrased
    /// for the user. A UI or the CLI follows it with a state-specific suffix —
    /// [`FeatureGate::UNVERIFIED_SUFFIX`] or [`FeatureGate::INCOMPATIBLE_SUFFIX`]
    /// — so both surfaces say the same thing.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        match self {
            PivExtension::MoveKey => {
                "Moving keys between slots needs YubiKey 5.7+ or a compatible third-party device."
            }
            PivExtension::DeleteKey => {
                "Key deletion needs YubiKey 5.7+ or a compatible third-party device."
            }
        }
    }
}

/// A version-gated behavioral wrinkle keyroost has observed on some PIV
/// devices — distinct from [`PivExtension`]: an extension is "supported or
/// not", a quirk is "present and needs a workaround" regardless of support.
/// Carried on [`VersionQuirks::quirks`] and surfaced by [`resolve_quirks`].
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
    /// METADATA (`INS 0xF7`) response never updates on this device — it does
    /// not reflect the slot's actual key state — and must always be ignored
    /// when this quirk is set, regardless of what value is read.
    InsF7MetadataAlgorithmInvalid,
}

/// The white/blacklist shared by [`PivExtension::MoveKey`] and
/// [`PivExtension::DeleteKey`], one row per fingerprint keyroost has data for:
///
/// * YubiKey — the operation is unsupported before firmware 5.7 and supported
///   from 5.7 onward. The empty-slice version on the blacklist verdict is a
///   "from the very first version" sentinel — it orders below every real
///   version (`[] < [5, 7]`), so that verdict is the one that applies to
///   anything older than 5.7. Unlike the rows below, this sentinel is load-
///   bearing and not implied by [`resolve_in`]'s backward-extension rule: the
///   verdict *above* it is a whitelist ([5, 7]), not a blacklist, and a
///   whitelist verdict says nothing about versions before it.
/// * Token2 — applet version 5.112.0 has been observed to reject both
///   extensions outright, and every version below it is assumed to as well
///   per [`resolve_in`]'s backward-extension rule (no earlier hardware has
///   been available to test, but a feature known not to work at 5.112.0 is
///   presumed not to work in any older, untested version either). There is
///   no whitelist verdict on this row, so a version *above* 5.112.0 resolves
///   [`FeatureGate::Unverified`], not [`FeatureGate::Unsupported`] — a
///   blacklist verdict is deliberately never treated as covering a version
///   it hasn't actually observed on the other side either. Unlike the
///   YubiKey row above, this one needs no explicit `[]` sentinel: the single
///   `[5, 112, 0]` blacklist verdict is enough for [`resolve_in`] to extend
///   backward on its own.
/// * Swissbit iShield 2 Pro (`OpenFips201::SwissbitIShield2`) — applet
///   version 1.4.1.0 and every earlier version have been observed to reject
///   both extensions. Same single-verdict shape as Token2's row above, just
///   with `[1, 4, 1, 0]` as the observed/backward-extending version instead
///   of `[5, 112, 0]`. A version above 1.4.1.0 falls off the end of the row
///   and resolves [`FeatureGate::Unverified`] — the blacklist deliberately
///   doesn't extend to a future, untested version.
/// * Thetis PRO FIDO2 Security Key with PinPlex ([`AppletFingerprint::Thetis`])
///   — applet version 5.112.0 and every earlier version have been observed
///   to reject both extensions. Same single-verdict shape as the rows above:
///   `[5, 112, 0]` is both the exact-match verdict and the one
///   [`resolve_in`] extends backward from. A version above 5.112.0 falls off
///   the end of the row and resolves [`FeatureGate::Unverified`] — the
///   blacklist deliberately doesn't extend to a future, untested version.
const KEY_OPS_VERDICTS: &[FingerprintVerdicts] = &[
    FingerprintVerdicts {
        fingerprint: AppletFingerprint::YubiKey,
        verdicts: &[
            VersionVerdict {
                version: &[],
                verdict: Verdict::Blacklisted,
            },
            VersionVerdict {
                version: &[5, 7],
                verdict: Verdict::Whitelisted,
            },
        ],
    },
    FingerprintVerdicts {
        fingerprint: AppletFingerprint::Token2,
        verdicts: &[VersionVerdict {
            version: &[5, 112, 0],
            verdict: Verdict::Blacklisted,
        }],
    },
    FingerprintVerdicts {
        fingerprint: AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2),
        verdicts: &[VersionVerdict {
            version: &[1, 4, 1, 0],
            verdict: Verdict::Blacklisted,
        }],
    },
    FingerprintVerdicts {
        fingerprint: AppletFingerprint::Thetis,
        // See this row's bullet in the doc comment on this table.
        verdicts: &[VersionVerdict {
            version: &[5, 112, 0],
            verdict: Verdict::Blacklisted,
        }],
    },
];

/// One fingerprint's row in an extension's white/blacklist.
struct FingerprintVerdicts {
    fingerprint: AppletFingerprint,
    /// This fingerprint's per-version verdicts, **ascending by
    /// [`VersionVerdict::version`]** and non-empty.
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

/// One recorded white/blacklist verdict, carried by a [`VersionVerdict`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// Extension known to be supported at this version (and, by the
    /// no-regression assumption in [`resolve`], at every later one until a
    /// contrary verdict).
    Whitelisted,
    /// Extension known to be unsupported at this version.
    Blacklisted,
}

/// The UI-facing resolution of a [`PivExtension`] against a live applet,
/// produced by [`resolve`]. Not `#[non_exhaustive]`: it is a closed
/// three-way outcome and every caller is expected to render all three
/// (enable / enable-and-flag / dim) rather than fall through a wildcard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeatureGate {
    /// Enable the control, no warning: the extension is whitelisted at the
    /// reported version, or at an earlier one and assumed not to have
    /// regressed.
    Supported,
    /// Enable the control, but flag it: keyroost has no white/blacklist for
    /// this fingerprint, none at or below the reported version, no reported
    /// version to match, or only a blacklist verdict old enough that a later
    /// firmware may have added the extension. See [`Self::UNVERIFIED_SUFFIX`].
    Unverified,
    /// Disable the control (dimmed): a blacklist verdict covers the reported
    /// version, so the extension is known to be unsupported here.
    Unsupported,
}

impl FeatureGate {
    /// Sentence that follows [`PivExtension::requirement`] when a control is
    /// gated [`Unverified`](Self::Unverified): the device isn't on the
    /// white/blacklist, so support can't be confirmed either way.
    pub const UNVERIFIED_SUFFIX: &'static str =
        "This device is unverified; the operation may fail.";
    /// Sentence that follows [`PivExtension::requirement`] when a control is
    /// gated [`Unsupported`](Self::Unsupported): a blacklist verdict covers
    /// this device's version.
    pub const INCOMPATIBLE_SUFFIX: &'static str = "This device is known to be incompatible.";
}

/// Resolve `extension` for an applet fingerprinted as `fingerprint`, reporting
/// `applet_version` (the PIV applet's own version bytes) and/or
/// `firmware_version` (the device firmware's version bytes) — either or both
/// `None` when the card never reported that one.
///
/// `applet_version` is queried against [`PivExtension::applet_verdicts`] and
/// `firmware_version` against [`PivExtension::firmware_verdicts`], **with
/// identical per-axis lookup semantics**:
///
/// 1. The version is `None` → that axis is [`FeatureGate::Unverified`]
///    (nothing to version-match).
/// 2. No white/blacklist row for `fingerprint` on that axis →
///    [`FeatureGate::Unverified`] (support unknown; don't block).
/// 3. A row exists: take the verdict with the greatest version `<=` the
///    reported version. If there is none — the reported version is older
///    than every verdict on record — fall back to the row's *first* (lowest)
///    verdict, i.e. the nearest one *above* the reported version:
///    * blacklisted → [`FeatureGate::Unsupported`]: a feature known not to
///      work at that version is assumed not to work at any earlier, untested
///      version either — the backward mirror of the "assumed not to have
///      regressed" forward extension a whitelist verdict gets below;
///    * whitelisted → [`FeatureGate::Unverified`]: a whitelist verdict says
///      nothing about the versions before it, so there's nothing to extend.
///
///    Otherwise, with a verdict at or below the reported version in hand:
///    * whitelisted → [`FeatureGate::Supported`] (covers both an exact-version
///      match and an earlier whitelist assumed not to have regressed);
///    * blacklisted, verdict version **equals** the reported version →
///      [`FeatureGate::Unsupported`];
///    * blacklisted, verdict version **below** the reported version, and it is
///      the last (highest) verdict in the row → [`FeatureGate::Unverified`]:
///      the blacklist may predate a firmware that added the extension;
///    * blacklisted, verdict version **below** the reported version, but a
///      later verdict exists (for a version above this one's) → the row's
///      blacklist knowledge brackets this version, so it is treated as
///      authoritative: [`FeatureGate::Unsupported`].
///
/// The two per-axis outcomes are then combined, in order:
///
/// 1. Either axis is [`FeatureGate::Unsupported`] → combined result is
///    [`FeatureGate::Unsupported`] (a known-incompatible verdict on either
///    axis blocks the control).
/// 2. Else, either axis is [`FeatureGate::Supported`] → combined result is
///    [`FeatureGate::Supported`].
/// 3. Else → combined result is [`FeatureGate::Unverified`].
///
/// This means when only one of `applet_version`/`firmware_version` carries
/// data for `fingerprint`, the other axis resolves to
/// [`FeatureGate::Unverified`] and — per the rule above — simply doesn't
/// change the outcome, so the combined result equals the one axis that has an
/// opinion.
#[must_use]
pub fn resolve(
    extension: PivExtension,
    fingerprint: AppletFingerprint,
    applet_version: Option<&[u8]>,
    firmware_version: Option<&[u8]>,
) -> FeatureGate {
    let applet_gate = resolve_in(extension.applet_verdicts(), fingerprint, applet_version);
    let firmware_gate = resolve_in(extension.firmware_verdicts(), fingerprint, firmware_version);
    combine(applet_gate, firmware_gate)
}

/// Combine the two per-axis [`FeatureGate`]s into one, per the rule documented
/// on [`resolve`]: [`FeatureGate::Unsupported`] wins outright; otherwise
/// [`FeatureGate::Supported`] wins; otherwise [`FeatureGate::Unverified`].
#[must_use]
fn combine(a: FeatureGate, b: FeatureGate) -> FeatureGate {
    match (a, b) {
        (FeatureGate::Unsupported, _) | (_, FeatureGate::Unsupported) => FeatureGate::Unsupported,
        (FeatureGate::Supported, _) | (_, FeatureGate::Supported) => FeatureGate::Supported,
        (FeatureGate::Unverified, FeatureGate::Unverified) => FeatureGate::Unverified,
    }
}

/// [`resolve`] against an explicit set of white/blacklist rows, so a test can
/// supply its own without wiring one into the const tables.
fn resolve_in(
    rows: &[FingerprintVerdicts],
    fingerprint: AppletFingerprint,
    applet_version: Option<&[u8]>,
) -> FeatureGate {
    let Some(version) = applet_version else {
        return FeatureGate::Unverified;
    };
    let Some(row) = rows.iter().find(|row| row.fingerprint == fingerprint) else {
        return FeatureGate::Unverified;
    };
    let Some(idx) = row.verdicts.iter().rposition(|v| v.version <= version) else {
        // The reported version is older than every verdict on record. Fall
        // back to the nearest one *above* it — `verdicts[0]`, since rows are
        // sorted ascending — and, if that verdict is a blacklist, extend it
        // backward: a feature known not to work at that version is assumed
        // not to work at any earlier, untested version either. A whitelist
        // verdict, by contrast, says nothing about versions before it.
        return match row.verdicts.first() {
            Some(VersionVerdict {
                verdict: Verdict::Blacklisted,
                ..
            }) => FeatureGate::Unsupported,
            _ => FeatureGate::Unverified,
        };
    };
    let chosen = &row.verdicts[idx];
    match chosen.verdict {
        // Known supported at or below the reported version — and assumed not
        // to have regressed in any newer version we have no verdict for.
        Verdict::Whitelisted => FeatureGate::Supported,
        // Blacklist verdict for exactly this version: a direct observation
        // that this build lacks the extension. Nothing softens that.
        Verdict::Blacklisted if chosen.version == version => FeatureGate::Unsupported,
        // Blacklist verdict from an *older* version with nothing newer on
        // record: the extension may have been added in a firmware we haven't
        // observed, so warn rather than block.
        Verdict::Blacklisted if idx + 1 == row.verdicts.len() => FeatureGate::Unverified,
        // Blacklist verdict from an older version, but a later verdict exists
        // (for a version above this applet's): our blacklist knowledge
        // brackets this version, so treat it as authoritative and block.
        Verdict::Blacklisted => FeatureGate::Unsupported,
    }
}

/// One fingerprint's row in a [`PivQuirk`] table — the quirks counterpart to
/// [`FingerprintVerdicts`], but deliberately a separate type: a quirk row has
/// no whitelist/blacklist [`Verdict`] to carry, only a list of quirks active
/// from each entry's version onward, so reusing [`VersionVerdict`] would
/// leave a `verdict` field with no meaning on this axis.
struct FingerprintQuirks {
    fingerprint: AppletFingerprint,
    /// This fingerprint's per-version quirks, **ascending by
    /// [`VersionQuirks::version`]** and non-empty.
    quirks: &'static [VersionQuirks],
}

/// "At [`Self::version`] (and, until a later entry, above it) these quirks
/// are active." Same version-ordering convention as [`VersionVerdict`], but
/// purely additive: there's no whitelisted/blacklisted state, so a quirk
/// entry can never suppress a quirk an earlier entry already reported.
struct VersionQuirks {
    version: &'static [u8],
    quirks: &'static [PivQuirk],
}

/// [`PivQuirk`] table keyed by the PIV applet's own version — same row shape
/// as [`PivExtension::applet_verdicts`], but not scoped to any one
/// extension: every fingerprint's known version-gated quirks live directly
/// in this one table rather than being duplicated per extension.
const QUIRKS_BY_APPLET_TABLE: &[FingerprintQuirks] = &[
    FingerprintQuirks {
        fingerprint: AppletFingerprint::Token2,
        // The empty-slice version is the "from the very first version"
        // sentinel also used by `KEY_OPS_VERDICTS`'s YubiKey row: it orders
        // at or below every real version (`[] <= anything`), so this entry
        // matches regardless of which applet version Token2 reports.
        quirks: &[VersionQuirks {
            version: &[],
            quirks: &[PivQuirk::InsF8SerialIsBcd],
        }],
    },
    FingerprintQuirks {
        fingerprint: AppletFingerprint::Thetis,
        // Observed on the Thetis PRO FIDO2 Security Key with PinPlex at
        // applet version 5.112.0, the only version tested so far. Earlier
        // versions are assumed to encode GET SERIAL's reply the same way
        // rather than confirmed to — no earlier-version hardware has been
        // available to test — so the empty-slice version below is a
        // deliberate "from the very first version" assumption, not a direct
        // observation, using the same sentinel as the row above.
        quirks: &[VersionQuirks {
            version: &[],
            quirks: &[PivQuirk::InsF8SerialIsBcd],
        }],
    },
    FingerprintQuirks {
        fingerprint: AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2),
        // Older Swissbit iShield 2 Pro devices have been observed to never
        // update GET METADATA's algorithm identifier (tag 0x01): it's stuck
        // at whatever it first reported and doesn't reflect the slot's
        // actual key state, so it must always be ignored while this quirk is
        // set. The empty-slice version is the "from the very first version"
        // sentinel (see the Token2 row above) rather than a specific version
        // this was first observed on — the issue might already have been
        // fixed in an earlier version than what's on record here, but no
        // older test hardware has been available to confirm either way, so
        // this deliberately claims no lower bound. The device actually
        // confirmed clear of it reports applet version 1.4.1.0, but the
        // clearing entry below is keyed to the shorter `[1, 4, 1]` on
        // purpose: under this crate's slice-prefix version ordering a
        // shorter version like `[1, 4, 1]` is "less than" any longer one
        // starting with the same elements (`[1, 4, 1] < [1, 4, 1, 0]`), so
        // `[1, 4, 1]` as a threshold covers both a bare 3-component "1.4.1"
        // report and any of its patch releases, whereas `[1, 4, 1, 0]`
        // itself would not match a device reporting the shorter "1.4.1".
        // Per `latest_quirks`, entries don't accumulate across each other,
        // only across the two axes, so a version at or above `[1, 4, 1]`
        // picks up this entry's empty quirk list instead and reports no
        // quirk.
        quirks: &[
            VersionQuirks {
                version: &[],
                quirks: &[PivQuirk::InsF7MetadataAlgorithmInvalid],
            },
            VersionQuirks {
                version: &[1, 4, 1],
                quirks: &[],
            },
        ],
    },
];

/// [`PivQuirk`] table keyed by the device's firmware version, same shape and
/// caveats as [`QUIRKS_BY_APPLET_TABLE`] but the firmware axis.
const QUIRKS_BY_FIRMWARE_TABLE: &[FingerprintQuirks] = &[];

/// The row entry in `rows` for `fingerprint` with the greatest
/// [`VersionQuirks::version`] `<=` `version`, if any — the "current" quirks
/// entry for that version, ignoring anything with a higher version on
/// record. Same lookup rule as step 3 of [`resolve_in`], but there's no
/// whitelist/blacklist reasoning to apply once the entry is found: quirks
/// are taken as-is.
fn latest_quirks<'a>(
    rows: &'a [FingerprintQuirks],
    fingerprint: AppletFingerprint,
    version: &[u8],
) -> Option<&'a VersionQuirks> {
    let row = rows.iter().find(|row| row.fingerprint == fingerprint)?;
    let idx = row.quirks.iter().rposition(|v| v.version <= version)?;
    Some(&row.quirks[idx])
}

/// Resolve the set of [`PivQuirk`]s active for an applet fingerprinted as
/// `fingerprint`, reporting `applet_version` and/or `firmware_version` —
/// either or both `None` when the card never reported that one:
///
/// 1. If `applet_version` is available, take the [`QUIRKS_BY_APPLET_TABLE`]
///    entry for `fingerprint` with the highest version `<=` `applet_version`
///    (if any).
/// 2. If `firmware_version` is available, take the [`QUIRKS_BY_FIRMWARE_TABLE`]
///    entry for `fingerprint` with the highest version `<=`
///    `firmware_version` (if any).
/// 3. Merge the [`VersionQuirks::quirks`] from whichever of (1)/(2) matched
///    into a single set.
///
/// Unlike [`resolve`], there's no whitelist/blacklist reasoning here: each
/// axis contributes at most one entry's quirks, and quirks only ever
/// accumulate — nothing in this table can suppress a quirk another entry
/// added.
#[must_use]
pub fn resolve_quirks(
    fingerprint: AppletFingerprint,
    applet_version: Option<&[u8]>,
    firmware_version: Option<&[u8]>,
) -> BTreeSet<PivQuirk> {
    resolve_quirks_in(
        QUIRKS_BY_APPLET_TABLE,
        QUIRKS_BY_FIRMWARE_TABLE,
        fingerprint,
        applet_version,
        firmware_version,
    )
}

/// [`resolve_quirks`] against explicit applet/firmware quirk tables, so a
/// test can supply its own without wiring one into the const tables — same
/// role [`resolve_in`] plays for [`resolve`].
fn resolve_quirks_in(
    applet_rows: &[FingerprintQuirks],
    firmware_rows: &[FingerprintQuirks],
    fingerprint: AppletFingerprint,
    applet_version: Option<&[u8]>,
    firmware_version: Option<&[u8]>,
) -> BTreeSet<PivQuirk> {
    let mut quirks = BTreeSet::new();
    if let Some(version) = applet_version {
        if let Some(entry) = latest_quirks(applet_rows, fingerprint, version) {
            quirks.extend(entry.quirks.iter().copied());
        }
    }
    if let Some(version) = firmware_version {
        if let Some(entry) = latest_quirks(firmware_rows, fingerprint, version) {
            quirks.extend(entry.quirks.iter().copied());
        }
    }
    quirks
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- User-facing wording: requirement() + a suffix -------------------

    #[test]
    fn requirement_is_distinct_per_extension_and_composes_with_a_suffix() {
        let move_req = PivExtension::MoveKey.requirement();
        let del_req = PivExtension::DeleteKey.requirement();
        assert_ne!(move_req, del_req);
        for req in [move_req, del_req] {
            // Ends a sentence, so "<req> <suffix>" reads as two.
            assert!(req.ends_with('.'), "{req:?}");
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
            // Matches the blacklist sentinel verdict (version `[]`), which is
            // not the last verdict, so the blacklist is authoritative.
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
            // whitelist, assumed not to have regressed.
            assert_eq!(
                resolve(ext, AppletFingerprint::YubiKey, Some(&[6, 0, 0]), None),
                FeatureGate::Supported
            );
        }
    }

    #[test]
    fn yubikey_without_a_reported_version_is_unverified() {
        assert_eq!(
            resolve(
                PivExtension::MoveKey,
                AppletFingerprint::YubiKey,
                None,
                None
            ),
            FeatureGate::Unverified
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

    // --- Token2: the seeded 5.112.0 blacklist, both extensions -----------

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
        // 5.112.0 blacklist, extended backward.
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
    fn token2_newer_versions_are_unverified_not_blacklisted() {
        // No whitelist verdict on this row, and 5.112.0 is the last (highest)
        // entry, so — per `resolve_in`'s "trailing stale blacklist" rule — a
        // version above it doesn't inherit the verdict: the blacklist is
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
    // --- blacklist, both extensions ---------------------------------------

    #[test]
    fn thetis_5_112_0_is_unsupported() {
        for ext in [PivExtension::MoveKey, PivExtension::DeleteKey] {
            assert_eq!(
                resolve(ext, AppletFingerprint::Thetis, Some(&[5, 112, 0]), None),
                FeatureGate::Unsupported
            );
            // No verdict at or below this version, so `resolve_in` falls
            // back to the row's only verdict — the 5.112.0 blacklist,
            // extended backward.
            assert_eq!(
                resolve(ext, AppletFingerprint::Thetis, Some(&[0]), None),
                FeatureGate::Unsupported
            );
            // Same trailing-blacklist softening above the highest verdict.
            assert_eq!(
                resolve(ext, AppletFingerprint::Thetis, Some(&[5, 113, 0]), None),
                FeatureGate::Unverified
            );
        }
    }

    // --- Swissbit iShield 2 Pro: the bracketed <= 1.4.1.0 blacklist -------

    #[test]
    fn swissbit_ishield2_at_or_below_1_4_1_0_is_unsupported() {
        for ext in [PivExtension::MoveKey, PivExtension::DeleteKey] {
            let fp = AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2);
            // The exact observed version: blacklisted via the direct-match
            // rule.
            assert_eq!(
                resolve(ext, fp, Some(&[1, 4, 1, 0]), None),
                FeatureGate::Unsupported
            );
            // Anything older: no verdict at or below it, so `resolve_in`
            // falls back to the row's only verdict — the `[1, 4, 1, 0]`
            // blacklist, extended backward rather than softening to
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
    fn swissbit_ishield2_above_1_4_1_0_is_unverified_not_blacklisted() {
        // The blacklist deliberately doesn't extend to a version keyroost
        // hasn't actually observed: `[1, 4, 1, 0]` is the last verdict in
        // the row, so anything strictly newer softens to `Unverified` per
        // `resolve_in`'s trailing-blacklist rule.
        for ext in [PivExtension::MoveKey, PivExtension::DeleteKey] {
            let fp = AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2);
            for newer in [&[1, 4, 1, 1][..], &[1, 5, 0][..], &[2, 0][..]] {
                assert_eq!(resolve(ext, fp, Some(newer), None), FeatureGate::Unverified);
            }
        }
    }

    #[test]
    fn swissbit_ishield2_other_openfips201_variant_is_unverified() {
        // The row is keyed to the SwissbitIShield2 sub-fingerprint
        // specifically — the generic OpenFIPS201 variant carries no data.
        for ext in [PivExtension::MoveKey, PivExtension::DeleteKey] {
            assert_eq!(
                resolve(
                    ext,
                    AppletFingerprint::OpenFips201(OpenFips201Variant::Generic),
                    Some(&[1, 4, 1, 0]),
                    None,
                ),
                FeatureGate::Unverified
            );
        }
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
            // A second, real fingerprint that genuinely carries no row in
            // `KEY_OPS_VERDICTS` at all — unlike `AppletFingerprint::Token2`,
            // whose row's single blacklist verdict extends backward to
            // resolve `Unsupported` for these same low versions; see
            // `token2_older_versions_are_also_unsupported`.
            assert_eq!(
                resolve(
                    PivExtension::MoveKey,
                    AppletFingerprint::UTrust,
                    version,
                    version,
                ),
                FeatureGate::Unverified
            );
        }
    }

    // --- combine(): the cross-axis rule -----------------------------------

    #[test]
    fn combine_prefers_unsupported_over_anything_else() {
        assert_eq!(
            combine(FeatureGate::Unsupported, FeatureGate::Supported),
            FeatureGate::Unsupported
        );
        assert_eq!(
            combine(FeatureGate::Supported, FeatureGate::Unsupported),
            FeatureGate::Unsupported
        );
        assert_eq!(
            combine(FeatureGate::Unverified, FeatureGate::Unsupported),
            FeatureGate::Unsupported
        );
        assert_eq!(
            combine(FeatureGate::Unsupported, FeatureGate::Unverified),
            FeatureGate::Unsupported
        );
    }

    #[test]
    fn combine_prefers_supported_over_unverified() {
        assert_eq!(
            combine(FeatureGate::Supported, FeatureGate::Unverified),
            FeatureGate::Supported
        );
        assert_eq!(
            combine(FeatureGate::Unverified, FeatureGate::Supported),
            FeatureGate::Supported
        );
    }

    #[test]
    fn combine_of_only_unverified_is_unverified() {
        assert_eq!(
            combine(FeatureGate::Unverified, FeatureGate::Unverified),
            FeatureGate::Unverified
        );
    }

    #[test]
    fn combine_is_symmetric_and_idempotent() {
        for gate in [
            FeatureGate::Supported,
            FeatureGate::Unverified,
            FeatureGate::Unsupported,
        ] {
            // Combining a gate with itself is that gate again...
            assert_eq!(combine(gate, gate), gate);
            for other in [
                FeatureGate::Supported,
                FeatureGate::Unverified,
                FeatureGate::Unsupported,
            ] {
                // ...and argument order never matters.
                assert_eq!(combine(gate, other), combine(other, gate));
            }
        }
    }

    // --- The resolve() rules, exercised against a synthetic row ---------

    fn gate(verdicts: &'static [VersionVerdict], version: Option<&[u8]>) -> FeatureGate {
        let rows = [FingerprintVerdicts {
            fingerprint: AppletFingerprint::Generic,
            verdicts,
        }];
        resolve_in(&rows, AppletFingerprint::Generic, version)
    }

    #[test]
    fn applet_older_than_every_whitelisted_verdict_is_unverified() {
        // The nearest verdict above is a whitelist, which says nothing about
        // versions before it, so there's nothing to extend backward.
        assert_eq!(
            gate(
                &[VersionVerdict {
                    version: &[5, 0],
                    verdict: Verdict::Whitelisted,
                }],
                Some(&[4, 9]),
            ),
            FeatureGate::Unverified
        );
    }

    #[test]
    fn applet_older_than_every_blacklisted_verdict_is_unsupported() {
        // The nearest verdict above is a blacklist: a feature known not to
        // work at that version is assumed not to work at any earlier,
        // untested version either — the backward mirror of
        // `earlier_whitelist_is_assumed_not_to_regress` below.
        assert_eq!(
            gate(
                &[VersionVerdict {
                    version: &[5, 0],
                    verdict: Verdict::Blacklisted,
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
        // entry — so a blacklist further above doesn't leak backward past a
        // whitelist that's nearer.
        assert_eq!(
            gate(
                &[
                    VersionVerdict {
                        version: &[5, 0],
                        verdict: Verdict::Whitelisted,
                    },
                    VersionVerdict {
                        version: &[6, 0],
                        verdict: Verdict::Blacklisted,
                    },
                ],
                Some(&[4, 9]),
            ),
            FeatureGate::Unverified
        );
    }

    #[test]
    fn exact_version_blacklist_match_is_unsupported() {
        assert_eq!(
            gate(
                &[VersionVerdict {
                    version: &[5, 7],
                    verdict: Verdict::Blacklisted,
                }],
                Some(&[5, 7]),
            ),
            FeatureGate::Unsupported
        );
    }

    #[test]
    fn trailing_stale_blacklist_is_unverified() {
        // Only a blacklist, from a version below the applet's, and it is the
        // last verdict — the extension might have been added since.
        assert_eq!(
            gate(
                &[VersionVerdict {
                    version: &[5, 0],
                    verdict: Verdict::Blacklisted,
                }],
                Some(&[5, 4]),
            ),
            FeatureGate::Unverified
        );
    }

    #[test]
    fn bracketed_blacklist_stays_authoritative() {
        // A blacklist below the applet's version, with a later verdict above
        // it: keyroost's blacklist knowledge brackets the applet version.
        assert_eq!(
            gate(
                &[
                    VersionVerdict {
                        version: &[5, 0],
                        verdict: Verdict::Blacklisted,
                    },
                    VersionVerdict {
                        version: &[6, 0],
                        verdict: Verdict::Whitelisted,
                    },
                ],
                Some(&[5, 4]),
            ),
            FeatureGate::Unsupported
        );
    }

    #[test]
    fn earlier_whitelist_is_assumed_not_to_regress() {
        assert_eq!(
            gate(
                &[VersionVerdict {
                    version: &[5, 7],
                    verdict: Verdict::Whitelisted,
                }],
                Some(&[9, 1, 2]),
            ),
            FeatureGate::Supported
        );
    }

    // --- resolve_quirks(): the separate, non-gating quirks axis ----------

    fn quirks(
        applet_entries: &'static [VersionQuirks],
        firmware_entries: &'static [VersionQuirks],
        applet_version: Option<&[u8]>,
        firmware_version: Option<&[u8]>,
    ) -> BTreeSet<PivQuirk> {
        let applet_rows = [FingerprintQuirks {
            fingerprint: AppletFingerprint::Generic,
            quirks: applet_entries,
        }];
        let firmware_rows = [FingerprintQuirks {
            fingerprint: AppletFingerprint::Generic,
            quirks: firmware_entries,
        }];
        resolve_quirks_in(
            &applet_rows,
            &firmware_rows,
            AppletFingerprint::Generic,
            applet_version,
            firmware_version,
        )
    }

    #[test]
    fn no_data_on_either_axis_resolves_to_no_quirks() {
        assert_eq!(
            resolve_quirks(AppletFingerprint::YubiKey, Some(&[5, 7]), Some(&[5, 7])),
            BTreeSet::new()
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
        assert_eq!(
            resolve_quirks(AppletFingerprint::Generic, Some(&[1, 0]), Some(&[1, 0])),
            BTreeSet::new()
        );
    }

    // --- Token2: the seeded BCD-serial quirk ------------------------------

    #[test]
    fn token2_bcd_serial_quirk_matches_any_reported_applet_version() {
        // The `[]` sentinel orders at or below every real version, so this
        // fires regardless of how old or new the reported version is.
        for version in [&[0, 0][..], &[1, 0][..], &[9, 9, 9][..]] {
            assert_eq!(
                resolve_quirks(AppletFingerprint::Token2, Some(version), None),
                BTreeSet::from([PivQuirk::InsF8SerialIsBcd])
            );
        }
    }

    #[test]
    fn token2_bcd_serial_quirk_needs_a_reported_applet_version() {
        // No applet_version → nothing to version-match against, so the
        // applet axis contributes nothing (same "None → skip" rule as the
        // FeatureGate axis); the firmware axis has no Token2 data at all.
        assert_eq!(
            resolve_quirks(AppletFingerprint::Token2, None, None),
            BTreeSet::new()
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
        // observation.
        for version in [&[0, 0][..], &[1, 0][..], &[9, 9, 9][..]] {
            assert_eq!(
                resolve_quirks(AppletFingerprint::Thetis, Some(version), None),
                BTreeSet::from([PivQuirk::InsF8SerialIsBcd])
            );
        }
        assert_eq!(
            resolve_quirks(AppletFingerprint::Thetis, None, None),
            BTreeSet::new()
        );
    }

    // --- Swissbit iShield 2 Pro (OpenFips201): the seeded, then-cleared, -
    // --- GET METADATA algorithm-identifier quirk -------------------------

    #[test]
    fn swissbit_ishield2_metadata_quirk_below_1_4_1() {
        // The sentinel version `[]` matches regardless of how old the
        // reported version is, so this is active from the very first
        // version on record.
        for version in [&[0][..], &[1][..], &[1, 3, 9][..], &[1, 4, 0][..]] {
            assert_eq!(
                resolve_quirks(
                    AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2),
                    Some(version),
                    None,
                ),
                BTreeSet::from([PivQuirk::InsF7MetadataAlgorithmInvalid])
            );
        }
    }

    #[test]
    fn swissbit_ishield2_metadata_quirk_cleared_at_1_4_1() {
        // `[1, 4, 1]` covers both a bare 3-component "1.4.1" report and the
        // actually-confirmed-clear 4-component "1.4.1.0" — `[1, 4, 1]`
        // orders below both under slice-prefix comparison.
        for version in [
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
                BTreeSet::new()
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
}
