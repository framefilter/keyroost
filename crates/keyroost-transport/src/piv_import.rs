//! Pre-flight for importing a PKCS#12 key into a PIV slot: pure checks, no
//! card I/O. The CLI and the app both run [`plan_import`] before asking for a
//! management key or touching the card, so a file the device can't take is
//! refused up front with a plain reason. [`run_import`] then does the card
//! writes in an order that never leaves a key next to a certificate that isn't
//! its own.

use core::fmt;

use keyroost_p12::{Contents, Entry, KeyParts};
use keyroost_piv::compat::{self, FeatureGate, PivExtension, PivQuirk};
use keyroost_piv::fingerprint::{AppletFingerprint, TrussedVariant};
use keyroost_piv::{
    ImportBodyError, ImportKey, ImportLayout, ImportParts, KeyAlg, PinPolicy, PublicKey, Slot,
    TouchPolicy,
};
use keyroost_pivtest::{Outcome, SelfTest};

use zeroize::Zeroizing;

use crate::{CertCompression, CertImport, PivSession, TransportError};

/// What [`plan_import`] decided: which entry goes where, and how the applet
/// wants the key laid out.
#[derive(Debug)]
pub struct ImportPlan<'a> {
    /// The chosen key (and its certificate, if the file had a matching one).
    pub entry: &'a Entry,
    pub slot: Slot,
    pub layout: ImportLayout,
    /// The PIN and touch policies [`plan_import`] checked against the applet;
    /// [`run_import`] sends exactly these.
    pub pin_policy: PinPolicy,
    pub touch_policy: TouchPolicy,
    /// CA certificates in the file that are not written to the card.
    pub skipped_authorities: usize,
}

/// Why an import can't go ahead. Every variant is reached before any write.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportRefusal {
    /// The file holds no private key.
    NoKey,
    /// The file holds several keys and none was picked; the labels are in
    /// file order (numbered from 1 in messages). The labels are untrusted
    /// text from the file, and `Display` prints them as they are: a caller
    /// sanitizes them (or this message) before showing them.
    ChooseEntry(Vec<String>),
    /// The pick (1-based) is not one of the file's entries.
    EntryOutOfRange {
        asked: usize,
        available: usize,
    },
    /// The device takes no key of any type ([`import_blocked`]).
    ImportNotSupported,
    /// The device's version is too old to import (keys of type `alg`, or any
    /// key when `None`); `floor` is the version keyroost's list says it
    /// works from ([`compat::supported_from`]).
    NeedsNewerVersion {
        alg: Option<KeyAlg>,
        fingerprint: AppletFingerprint,
        floor: compat::VersionFloor,
    },
    KeyTypeNotSupported(KeyAlg),
    SlotNotSupported(Slot),
    /// The device only takes RSA keys with public exponent 65537.
    RsaExponentNot65537,
    /// The certificate does not belong to the key. [`plan_import`] never
    /// returns this (`keyroost-p12` pairs a certificate with a key only when
    /// they match); the card-writing step uses it for its own self-check.
    KeyCertificateMismatch,
    /// The key can't be put in the form the device takes (a value too long
    /// for its field). [`plan_import`] never returns this; [`run_import`]
    /// checks it before the first write.
    KeyNotEncodable(ImportBodyError),
    TouchPolicyNotSupported,
    PinPolicyNotSupported,
    /// The device takes PIN policies, but not "once" (a quirk of some
    /// firmware).
    PinPolicyOnceNotSupported,
    /// The device takes touch policies, but not "cached" (a quirk of some
    /// firmware).
    TouchPolicyCachedNotSupported,
}

impl fmt::Display for ImportRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoKey => f.write_str("The file has no private key to import."),
            Self::ChooseEntry(labels) => {
                f.write_str("The file has several keys; pick one:")?;
                for (i, label) in labels.iter().enumerate() {
                    write!(f, " {}) {label}", i + 1)?;
                }
                Ok(())
            }
            Self::EntryOutOfRange { asked, available } => {
                write!(f, "Key {asked} isn't in the file, which has {available}.")
            }
            Self::ImportNotSupported => f.write_str("This device can't import keys."),
            Self::NeedsNewerVersion {
                alg,
                fingerprint,
                floor,
            } => {
                f.write_str("Importing ")?;
                if let Some(alg) = alg {
                    write!(f, "{} ", alg.label())?;
                }
                let what = match floor.axis {
                    compat::VersionAxis::Firmware => "firmware",
                    compat::VersionAxis::Applet => "PIV applet",
                };
                write!(
                    f,
                    "keys needs {} {what} {} or later.",
                    product_name(*fingerprint),
                    keyroost_piv::format_version_bytes(floor.version)
                )
            }
            Self::KeyTypeNotSupported(alg) => {
                write!(f, "This device can't import {} keys.", alg.label())
            }
            Self::SlotNotSupported(slot) => {
                write!(
                    f,
                    "This device can't import into slot {:02X}.",
                    slot.key_ref()
                )
            }
            Self::RsaExponentNot65537 => {
                f.write_str("This device only imports RSA keys with public exponent 65537.")
            }
            Self::KeyCertificateMismatch => {
                f.write_str("The certificate doesn't belong to the key.")
            }
            Self::KeyNotEncodable(e) => write!(f, "The key can't be sent to this device: {e}."),
            Self::TouchPolicyNotSupported => {
                f.write_str("This device doesn't support a touch policy for imported keys.")
            }
            Self::PinPolicyNotSupported => {
                f.write_str("This device doesn't support a PIN policy for imported keys.")
            }
            Self::PinPolicyOnceNotSupported => {
                f.write_str("This device doesn't support PIN policy \"once\".")
            }
            Self::TouchPolicyCachedNotSupported => {
                f.write_str("This device doesn't support touch policy \"cached\".")
            }
        }
    }
}

impl std::error::Error for ImportRefusal {}

/// The device as a refusal names it: the product where the fingerprint's
/// label is the applet's (the Trussed applet keyroost knows ships on the
/// Nitrokey 3), else that label.
fn product_name(fp: AppletFingerprint) -> &'static str {
    match fp {
        AppletFingerprint::Trussed(TrussedVariant::Nitrokey) => "Nitrokey 3",
        other => other.applet_name(),
    }
}

/// The common name of a certificate's subject, else the whole subject, else
/// `(unreadable subject)`: how an entry's or an authority certificate's
/// owner is named. The text comes from the file: a caller sanitizes it
/// before showing it.
#[must_use]
pub fn certificate_name(der: &[u8]) -> String {
    use keyroost_piv::x509_parse::{parse_subject_dn, DnAttr};
    match parse_subject_dn(der) {
        Ok(dn) => dn
            .rdns
            .iter()
            .find(|(attr, v)| *attr == DnAttr::CommonName && !v.is_empty())
            .map_or_else(|| dn.to_string(), |(_, v)| v.clone()),
        Err(_) => "(unreadable subject)".to_string(),
    }
}

/// Why [`read_key_file`] returned no bytes.
#[derive(Debug)]
pub enum KeyFileError {
    /// The file is over [`keyroost_p12::MAX_FILE_BYTES`].
    TooLarge,
    /// The file couldn't be read.
    Io(std::io::Error),
}

impl fmt::Display for KeyFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => f.write_str(&too_large_message()),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for KeyFileError {}

/// A file over [`keyroost_p12::MAX_FILE_BYTES`], in the words the CLI and the
/// app use whether [`read_key_file`] or [`keyroost_p12::open`] refused it.
fn too_large_message() -> String {
    format!(
        "This file is larger than a .p12/.pfx key file should be (over {}).",
        keyroost_p12::max_file_size()
    )
}

/// Read a .p12/.pfx file for [`keyroost_p12::open`], the same in the CLI and
/// the app: at most [`keyroost_p12::MAX_FILE_BYTES`] (the most `open` takes),
/// into a buffer that is wiped when dropped (the file holds an encrypted
/// private key).
///
/// # Errors
/// [`KeyFileError::TooLarge`] past the limit (nothing more is read), else
/// [`KeyFileError::Io`].
pub fn read_key_file(path: &std::path::Path) -> Result<Zeroizing<Vec<u8>>, KeyFileError> {
    let file = std::fs::File::open(path).map_err(KeyFileError::Io)?;
    read_key_file_from(file, keyroost_p12::MAX_FILE_BYTES)
}

/// [`read_key_file`] on any reader, with the limit given.
fn read_key_file_from(
    reader: impl std::io::Read,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>, KeyFileError> {
    use std::io::Read as _;
    // Room for one byte past the limit up front, so reading never grows
    // (and copies) the buffer, which would leave unwiped copies behind.
    let mut bytes = Zeroizing::new(Vec::with_capacity(limit + 1));
    reader
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(KeyFileError::Io)?;
    if bytes.len() > limit {
        return Err(KeyFileError::TooLarge);
    }
    Ok(bytes)
}

/// A PKCS#12 reading error as a plain sentence, the same in the CLI and the
/// app.
#[must_use]
pub fn file_error_message(e: keyroost_p12::P12Error) -> String {
    use keyroost_p12::P12Error;
    match e {
        P12Error::WrongPassword => "Wrong password for this file.".to_string(),
        P12Error::NoKey => "The file has no private key to import.".to_string(),
        P12Error::TooLarge => too_large_message(),
        P12Error::Malformed(what) => {
            format!("This isn't a .p12/.pfx file keyroost can read ({what}).")
        }
        P12Error::Unsupported("PBMAC1") => "This file uses a newer integrity check (PBMAC1) \
            that keyroost can't read yet. Export it again with the default or the legacy \
            PKCS#12 settings."
            .to_string(),
        P12Error::Unsupported("file has no integrity check") => "This file has no integrity \
            check and holds an unencrypted key, so keyroost won't import it. Export it again \
            with a password."
            .to_string(),
        P12Error::Unsupported(what) if what == keyroost_p12::TOO_MUCH_WORK => {
            "This file asks for more password-hashing work than keyroost allows.".to_string()
        }
        P12Error::Unsupported(what) => {
            format!("This file uses something keyroost can't import yet: {what}.")
        }
        e => format!("This file can't be imported: {e}."),
    }
}

/// The file's authority certificates as PEM, one after another, for saving
/// next to an import.
#[must_use]
pub fn authorities_pem(contents: &Contents) -> String {
    contents
        .authorities
        .iter()
        .map(|der| keyroost_piv::x509::pem_certificate(der))
        .collect()
}

/// How an entry is shown when there is a choice to make: the file's own
/// label, the key type, and the certificate's subject, e.g.
/// `first (RSA-2048; certificate: Alice)`. Two keys of one type with no
/// label still differ by their certificates. The text comes from the file:
/// a terminal caller sanitizes it before printing.
fn entry_label(index: usize, entry: &Entry) -> String {
    let name = match &entry.label {
        Some(label) if !label.is_empty() => label.clone(),
        _ => format!("entry {}", index + 1),
    };
    let cert = entry.certificate.as_deref().map_or_else(
        || "no certificate".to_string(),
        |der| format!("certificate: {}", certificate_name(der)),
    );
    format!("{name} ({}; {cert})", entry.key.alg().label())
}

/// Every entry as shown when there is a choice to make, in file order
/// (numbered from 1 when shown): the file's own label, the key type and the
/// certificate's subject, e.g. `first (RSA-2048; certificate: Alice)`. The
/// text comes from the file: a terminal caller sanitizes it before printing.
#[must_use]
pub fn entry_labels(contents: &Contents) -> Vec<String> {
    contents
        .entries
        .iter()
        .enumerate()
        .map(|(i, e)| entry_label(i, e))
        .collect()
}

/// The entry `choice` (1-based) picks, or the only one when there is no
/// choice to make. Needs no card, so a caller can ask before selecting one.
///
/// # Errors
/// [`ImportRefusal::NoKey`], [`ImportRefusal::EntryOutOfRange`], or
/// [`ImportRefusal::ChooseEntry`] (with [`entry_labels`]) for several
/// entries and no choice.
pub fn choose_entry(contents: &Contents, choice: Option<usize>) -> Result<&Entry, ImportRefusal> {
    let entries = &contents.entries;
    match (entries.len(), choice) {
        (0, _) => Err(ImportRefusal::NoKey),
        (n, Some(c)) if c == 0 || c > n => Err(ImportRefusal::EntryOutOfRange {
            asked: c,
            available: n,
        }),
        (_, Some(c)) => Ok(&entries[c - 1]),
        (1, None) => Ok(&entries[0]),
        (_, None) => Err(ImportRefusal::ChooseEntry(entry_labels(contents))),
    }
}

/// Why this applet can't import a key of any type, before a file is picked:
/// [`ImportRefusal::NeedsNewerVersion`] when keyroost's list names a version
/// that would lift the refusal (the lowest one, for whichever key type it
/// comes first), else [`ImportRefusal::ImportNotSupported`]. `None` when some
/// key type may import. [`plan_import`] runs this first, so the CLI and the
/// app say the same thing.
#[must_use]
pub fn import_blocked(
    fp: AppletFingerprint,
    applet_version: Option<&[u8]>,
    firmware_version: Option<&[u8]>,
) -> Option<ImportRefusal> {
    let gate = |alg| {
        compat::resolve(
            PivExtension::ImportKey(alg),
            fp,
            applet_version,
            firmware_version,
        )
    };
    if !KeyAlg::ALL
        .into_iter()
        .all(|alg| gate(alg) == FeatureGate::Unsupported)
    {
        return None;
    }
    let floors: Vec<compat::VersionFloor> = KeyAlg::ALL
        .into_iter()
        .filter_map(|alg| {
            compat::supported_from(
                PivExtension::ImportKey(alg),
                fp,
                applet_version,
                firmware_version,
            )
        })
        .collect();
    // Floors on different axes don't compare; say only that it can't.
    let one_axis = floors.windows(2).all(|w| w[0].axis == w[1].axis);
    let lowest = floors.iter().min_by_key(|f| f.version).filter(|_| one_axis);
    Some(lowest.map_or(ImportRefusal::ImportNotSupported, |&floor| {
        ImportRefusal::NeedsNewerVersion {
            alg: None,
            fingerprint: fp,
            floor,
        }
    }))
}

/// Check a parsed PKCS#12 file against the target applet and slot.
///
/// `choice` is 1-based (as typed, or a dropdown index plus one). Checks run in
/// this order so the most useful message wins: a device that imports nothing
/// ([`import_blocked`]), entry choice, key type, slot,
/// RSA exponent, then policies (the extension, then a value the firmware is
/// known to refuse). A non-default PIN or touch policy is refused
/// where the applet is known not to take it; where support is merely unverified
/// it is allowed, as `piv key generate` does.
#[allow(clippy::too_many_arguments)]
pub fn plan_import<'a>(
    contents: &'a Contents,
    choice: Option<usize>,
    slot: Slot,
    fp: AppletFingerprint,
    applet_version: Option<&[u8]>,
    firmware_version: Option<&[u8]>,
    pin_policy: PinPolicy,
    touch_policy: TouchPolicy,
) -> Result<ImportPlan<'a>, ImportRefusal> {
    if let Some(refusal) = import_blocked(fp, applet_version, firmware_version) {
        return Err(refusal);
    }
    let entry = choose_entry(contents, choice)?;

    let alg = entry.key.alg();
    let gate = |ext| compat::resolve(ext, fp, applet_version, firmware_version);
    if gate(PivExtension::ImportKey(alg)) == FeatureGate::Unsupported {
        let floor = compat::supported_from(
            PivExtension::ImportKey(alg),
            fp,
            applet_version,
            firmware_version,
        );
        return Err(
            floor.map_or(ImportRefusal::KeyTypeNotSupported(alg), |floor| {
                ImportRefusal::NeedsNewerVersion {
                    alg: Some(alg),
                    fingerprint: fp,
                    floor,
                }
            }),
        );
    }
    if !compat::import_slot_allowed(fp, slot) {
        return Err(ImportRefusal::SlotNotSupported(slot));
    }
    let layout = compat::import_layout(fp);
    if layout == ImportLayout::Yubico {
        if let KeyParts::Rsa { e, .. } = &entry.key {
            if e.as_slice() != [1, 0, 1] {
                return Err(ImportRefusal::RsaExponentNot65537);
            }
        }
    }
    if pin_policy != PinPolicy::Default
        && gate(PivExtension::SlotPinPolicy) == FeatureGate::Unsupported
    {
        return Err(ImportRefusal::PinPolicyNotSupported);
    }
    if touch_policy != TouchPolicy::Default
        && gate(PivExtension::SlotTouchPolicy) == FeatureGate::Unsupported
    {
        return Err(ImportRefusal::TouchPolicyNotSupported);
    }
    // Narrower than the gates above, as `piv key generate` checks: a device
    // can take policies in general yet refuse one value.
    let quirks = compat::resolve_quirks(fp, applet_version, firmware_version);
    if pin_policy == PinPolicy::Once && quirks.contains(&PivQuirk::SlotPinPolicyOnceNotSupported) {
        return Err(ImportRefusal::PinPolicyOnceNotSupported);
    }
    if touch_policy == TouchPolicy::Cached
        && quirks.contains(&PivQuirk::SlotTouchPolicyCachedNotSupported)
    {
        return Err(ImportRefusal::TouchPolicyCachedNotSupported);
    }

    Ok(ImportPlan {
        entry,
        slot,
        layout,
        pin_policy,
        touch_policy,
        skipped_authorities: contents.authorities.len(),
    })
}

/// [`plan_import`] for the applet on `session`, using its fingerprint and
/// reported versions. Read-only. The fingerprint probe re-SELECTs PIV, so call
/// this before authenticating the management key.
///
/// # Errors
/// [`ImportRefusal`], as [`plan_import`].
pub fn plan_import_on<'a>(
    session: &mut PivSession<'_>,
    contents: &'a Contents,
    choice: Option<usize>,
    slot: Slot,
    pin_policy: PinPolicy,
    touch_policy: TouchPolicy,
) -> Result<ImportPlan<'a>, ImportRefusal> {
    let id = session.identity();
    plan_import(
        contents,
        choice,
        slot,
        id.fingerprint,
        id.version.as_deref(),
        id.version_firmware.as_deref(),
        pin_policy,
        touch_policy,
    )
}

/// The key values of `parts` in the form `layout` sends. Borrows from `parts`
/// (which wipes itself on drop), so nothing secret is copied.
#[must_use]
pub fn import_parts(parts: &KeyParts, layout: ImportLayout) -> ImportParts<'_> {
    match (parts, layout) {
        (KeyParts::Rsa { p, q, e, .. }, ImportLayout::NitrokeyRsa) => {
            ImportParts::RsaPrimes { p, q, e }
        }
        (
            KeyParts::Rsa {
                p, q, dp, dq, qinv, ..
            },
            ImportLayout::Yubico,
        ) => ImportParts::RsaCrt { p, q, dp, dq, qinv },
        (KeyParts::Ec { scalar, .. }, _) => ImportParts::Ec { scalar },
        (KeyParts::Ed25519 { seed, .. }, _) => ImportParts::Ed25519 { seed },
        (KeyParts::X25519 { scalar, .. }, _) => ImportParts::X25519 { scalar },
    }
}

/// What [`run_import`] wrote, and how the self-test went.
#[derive(Debug)]
pub struct ImportReport {
    pub slot: Slot,
    /// How the certificate was stored; `None` for a key-only entry, whose
    /// slot's old certificate was deleted instead.
    pub cert: Option<CertImport>,
    /// The self-test against the entry's public key, one entry per
    /// [`SelfTest`].
    pub self_test: Vec<(SelfTest, Outcome)>,
}

/// Why [`run_import`] stopped. Each variant says what the slot holds now.
#[derive(Debug)]
pub enum ImportFailure {
    /// A last check before the first write failed; nothing was written.
    Refused(ImportRefusal),
    /// The PIN, checked before the first write so a wrong one costs nothing
    /// on the card, was not accepted; nothing was written.
    PinNotVerified(TransportError),
    /// The certificate step failed, so the key was not written. The step is
    /// storing the entry's certificate (`storing_certificate`), or for a
    /// key-only entry deleting the slot's old one. The slot's key is
    /// unchanged: the key is written only after this step succeeds.
    ///
    /// `certificate_cleared` is `None` when the card refused the step outright
    /// (the slot's old certificate is still there). Otherwise the exchange may
    /// not have finished: a store may have left the new certificate next to
    /// the old key, so it was deleted (`Some(true)` when that worked); for a
    /// key-only entry it is `Some(false)`, the old certificate perhaps gone.
    CertificateNotStored {
        slot: Slot,
        error: TransportError,
        storing_certificate: bool,
        certificate_cleared: Option<bool>,
    },
    /// The key write failed after the certificate step. The certificate is
    /// deleted again (a key-only entry's was deleted already);
    /// `certificate_cleared` says whether the slot now has none.
    KeyNotWritten {
        slot: Slot,
        error: TransportError,
        certificate_cleared: bool,
    },
    /// The key (and certificate) are written, but the self-test couldn't
    /// start, e.g. the PIN was refused. Nothing is rolled back.
    SelfTestNotRun {
        report: ImportReport,
        error: TransportError,
    },
    /// The key (and certificate) are written, but a self-test operation
    /// failed. Nothing is rolled back.
    SelfTestFailed(ImportReport),
}

/// Whether `e` is the card refusing a command (the command had no effect),
/// as opposed to an exchange that may not have finished.
fn card_refused(e: &TransportError) -> bool {
    matches!(
        e,
        TransportError::Apdu { .. }
            | TransportError::PivSecurityNotSatisfied
            | TransportError::PivCertTooLarge { .. }
            | TransportError::PivCardFull { .. }
    )
}

fn slot_hex(slot: Slot) -> String {
    format!("{:02X}", slot.key_ref())
}

/// The command that deletes `slot`'s certificate, as a user types it.
fn cert_delete_command(slot: Slot) -> String {
    format!(
        "`keyroostctl piv cert delete --slot {:02x}`",
        slot.key_ref()
    )
}

/// "The new key and certificate are on the card" (or the key-only form).
fn written_lead(report: &ImportReport) -> String {
    if report.cert.is_some() {
        "The new key and certificate are on the card".to_string()
    } else {
        format!(
            "The new key is on the card (slot {} has no certificate)",
            slot_hex(report.slot)
        )
    }
}

impl fmt::Display for ImportFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(r) => write!(f, "{r} Nothing was changed on the card."),
            Self::PinNotVerified(error) => {
                match error {
                    TransportError::PivPinRejected {
                        tries_remaining: Some(0),
                    } => f.write_str("The PIN is blocked.")?,
                    TransportError::PivPinRejected {
                        tries_remaining: Some(1),
                    } => f.write_str("Wrong PIN (1 try left).")?,
                    TransportError::PivPinRejected {
                        tries_remaining: Some(n),
                    } => write!(f, "Wrong PIN ({n} tries left).")?,
                    TransportError::PivPinRejected {
                        tries_remaining: None,
                    } => f.write_str("The PIN was refused; it may be blocked.")?,
                    TransportError::PivBadPinLength => {
                        f.write_str("The PIN must be 6 to 8 characters.")?
                    }
                    e => write!(f, "The PIN couldn't be checked: {e}.")?,
                }
                f.write_str(" Nothing was written.")
            }
            Self::CertificateNotStored {
                slot,
                error,
                storing_certificate,
                certificate_cleared,
                ..
            } => {
                let s = slot_hex(*slot);
                match (storing_certificate, certificate_cleared) {
                    (_, None) => {
                        if matches!(
                            error,
                            TransportError::PivCertTooLarge { .. }
                                | TransportError::PivCardFull { .. }
                        ) {
                            f.write_str("The certificate didn't fit on the key.")?;
                        } else if *storing_certificate {
                            write!(f, "The certificate couldn't be stored: {error}.")?;
                        } else {
                            write!(
                                f,
                                "The slot's old certificate couldn't be deleted: {error}."
                            )?;
                        }
                        write!(
                            f,
                            " Nothing was changed; slot {s} keeps its old key and certificate."
                        )
                    }
                    (false, Some(_)) => write!(
                        f,
                        "Deleting the slot's old certificate didn't finish: {error}. The new \
                         key wasn't written; slot {s} keeps its old key, and may or may not \
                         still have its old certificate."
                    ),
                    (true, Some(true)) => write!(
                        f,
                        "The certificate couldn't be stored: {error}. \
                         Slot {s} keeps its old key and now has no certificate."
                    ),
                    (true, Some(false)) => write!(
                        f,
                        "The certificate couldn't be stored: {error}. Slot {s} keeps its \
                         old key, but its certificate may not match it; delete it with {}.",
                        cert_delete_command(*slot)
                    ),
                }
            }
            Self::KeyNotWritten {
                slot,
                error,
                certificate_cleared,
            } => {
                let s = slot_hex(*slot);
                let delete = cert_delete_command(*slot);
                match (card_refused(error), certificate_cleared) {
                    (true, true) => write!(
                        f,
                        "The key couldn't be written: {error}. \
                         Slot {s} keeps its old key and now has no certificate."
                    ),
                    (true, false) => write!(
                        f,
                        "The key couldn't be written: {error}, and the new certificate is \
                         still stored next to the old key; delete it with {delete}."
                    ),
                    (false, true) => write!(
                        f,
                        "The key write didn't finish: {error}. Slot {s} now has no \
                         certificate and may hold its old key or the new one; import \
                         again to be sure."
                    ),
                    (false, false) => write!(
                        f,
                        "The key write didn't finish: {error}, and the certificate couldn't \
                         be deleted afterwards. Slot {s} may hold its old key or the new \
                         one next to the new certificate; delete the certificate with \
                         {delete}, or import again."
                    ),
                }
            }
            Self::SelfTestNotRun { report, error } => write!(
                f,
                "{}, but the self-test couldn't run: {error}.",
                written_lead(report)
            ),
            Self::SelfTestFailed(report) => {
                write!(f, "{}, but the self-test failed: ", written_lead(report))?;
                let failed: Vec<String> = report
                    .self_test
                    .iter()
                    .filter_map(|(op, outcome)| match outcome {
                        Outcome::Failed(why) => Some(format!("{}: {why}", op.label())),
                        _ => None,
                    })
                    .collect();
                write!(f, "{}.", failed.join("; "))
            }
        }
    }
}

impl std::error::Error for ImportFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Refused(r) => Some(r),
            Self::PinNotVerified(error)
            | Self::CertificateNotStored { error, .. }
            | Self::KeyNotWritten { error, .. }
            | Self::SelfTestNotRun { error, .. } => Some(error),
            Self::SelfTestFailed(_) => None,
        }
    }
}

/// The card operations [`run_import`] needs, so its write order is tested
/// against a scripted card. [`PivSession`] is the real one.
pub(crate) trait ImportCard {
    /// The algorithm byte this applet takes for `alg` in P1.
    fn algorithm_id(&mut self, alg: KeyAlg) -> u8;
    /// Store a certificate without comparing it to the slot's current key.
    fn store_certificate_unchecked(
        &mut self,
        slot: Slot,
        der: &[u8],
        compression: CertCompression,
    ) -> Result<CertImport, TransportError>;
    fn clear_certificate(&mut self, slot: Slot) -> Result<(), TransportError>;
    fn verify_pin(&mut self, pin: &[u8]) -> Result<(), TransportError>;
    /// Send an IMPORT ASYMMETRIC KEY body.
    fn write_key(&mut self, slot: Slot, alg_id: u8, body: &[u8]) -> Result<(), TransportError>;
    /// Note the key just written, for firmware that can't report it.
    fn remember_key(&mut self, slot: Slot, alg: KeyAlg, public: PublicKey);
    fn self_test(
        &mut self,
        slot: Slot,
        alg: KeyAlg,
        pubkey: &PublicKey,
        pin: Option<&[u8]>,
    ) -> Result<Vec<(SelfTest, Outcome)>, TransportError>;
}

impl ImportCard for PivSession<'_> {
    fn algorithm_id(&mut self, alg: KeyAlg) -> u8 {
        PivSession::slot_key_algorithm_apdu_id(self, alg)
    }

    fn store_certificate_unchecked(
        &mut self,
        slot: Slot,
        der: &[u8],
        compression: CertCompression,
    ) -> Result<CertImport, TransportError> {
        PivSession::store_certificate_unchecked(self, slot, der, compression)
    }

    fn clear_certificate(&mut self, slot: Slot) -> Result<(), TransportError> {
        PivSession::clear_certificate(self, slot)
    }

    fn verify_pin(&mut self, pin: &[u8]) -> Result<(), TransportError> {
        PivSession::verify_pin(self, pin)
    }

    fn write_key(&mut self, slot: Slot, alg_id: u8, body: &[u8]) -> Result<(), TransportError> {
        PivSession::write_import_key(self, slot, alg_id, body)
    }

    fn remember_key(&mut self, slot: Slot, alg: KeyAlg, public: PublicKey) {
        self.remember_pubkey(slot, alg, public);
    }

    fn self_test(
        &mut self,
        slot: Slot,
        alg: KeyAlg,
        pubkey: &PublicKey,
        pin: Option<&[u8]>,
    ) -> Result<Vec<(SelfTest, Outcome)>, TransportError> {
        PivSession::self_test(self, slot, alg, pubkey, pin)
    }
}

/// Write `plan` to the card: the entry's certificate, then its key, then the
/// self-test against the entry's public key, with the PIN and touch policies
/// the plan was checked for. The management key must already be
/// authenticated; `pin`, when given, is used for the self-test only.
///
/// The order keeps the slot consistent at every step:
/// 1. Checks with no card writes: the certificate belongs to the key, the
///    key fits the applet's layout, and the PIN (when given) is accepted, so
///    a wrong PIN stops the import before anything is written.
/// 2. The certificate is stored without the old-key match guard of
///    [`PivSession::import_certificate`] (it belongs to the new key). For a
///    key-only entry the slot's old certificate is deleted instead. On
///    failure the key is not written.
/// 3. The key is written. On failure the certificate from step 2 is deleted,
///    so the old key is never left next to the new certificate.
/// 4. The self-test. A failure is reported; nothing is rolled back.
///
/// # Errors
/// [`ImportFailure`], which says what the slot holds.
pub fn run_import(
    session: &mut PivSession<'_>,
    plan: &ImportPlan<'_>,
    compression: CertCompression,
    pin: Option<&[u8]>,
) -> Result<ImportReport, ImportFailure> {
    run_import_with(session, plan, compression, pin)
}

/// Whether `entry`'s certificate (if any) carries the key's own public key.
/// A certificate whose key can't be read counts as not belonging.
fn certificate_belongs(entry: &Entry, alg: KeyAlg, public: &PublicKey) -> bool {
    entry.certificate.as_deref().is_none_or(|der| {
        keyroost_piv::x509_parse::parse_certificate_public_key(der)
            .is_ok_and(|(cert_alg, cert_key)| cert_alg == alg && cert_key == *public)
    })
}

fn run_import_with(
    card: &mut impl ImportCard,
    plan: &ImportPlan<'_>,
    compression: CertCompression,
    pin: Option<&[u8]>,
) -> Result<ImportReport, ImportFailure> {
    let slot = plan.slot;
    let entry = plan.entry;

    // 1. Nothing is written until both checks pass.
    let alg = entry.key.alg();
    let public = entry.key.public_key();
    if !certificate_belongs(entry, alg, &public) {
        return Err(ImportFailure::Refused(
            ImportRefusal::KeyCertificateMismatch,
        ));
    }
    let key = ImportKey {
        alg,
        alg_id: card.algorithm_id(alg),
        parts: import_parts(&entry.key, plan.layout),
    };
    let body =
        crate::piv::import_key_body_for(&key, plan.pin_policy, plan.touch_policy, plan.layout)
            .map_err(|e| ImportFailure::Refused(ImportRefusal::KeyNotEncodable(e)))?;
    // A correct VERIFY costs no try; the self-test verifies again as it goes.
    if let Some(pin) = pin {
        card.verify_pin(pin)
            .map_err(ImportFailure::PinNotVerified)?;
    }

    // 2. The certificate (or, for a key-only entry, no certificate).
    let cert = match &entry.certificate {
        Some(der) => match card.store_certificate_unchecked(slot, der, compression) {
            Ok(done) => Some(done),
            Err(error) => {
                // A plain refusal left the old certificate alone. Anything
                // else may have stored the new one next to the old key.
                let certificate_cleared =
                    (!card_refused(&error)).then(|| card.clear_certificate(slot).is_ok());
                return Err(ImportFailure::CertificateNotStored {
                    slot,
                    error,
                    storing_certificate: true,
                    certificate_cleared,
                });
            }
        },
        None => {
            // A refused delete changed nothing; an unfinished one may have
            // deleted the old certificate. Either way the old key stays.
            card.clear_certificate(slot)
                .map_err(|error| ImportFailure::CertificateNotStored {
                    slot,
                    certificate_cleared: (!card_refused(&error)).then_some(false),
                    error,
                    storing_certificate: false,
                })?;
            None
        }
    };

    // 3. The key. Its certificate goes again if the key didn't make it.
    if let Err(error) = card.write_key(slot, key.alg_id, &body) {
        let certificate_cleared = cert.is_none() || card.clear_certificate(slot).is_ok();
        return Err(ImportFailure::KeyNotWritten {
            slot,
            error,
            certificate_cleared,
        });
    }
    // Like `generate_key`'s seeding: firmware without GET METADATA can't
    // report the new key itself.
    card.remember_key(slot, alg, public.clone());

    // 4. The self-test, against the key just written.
    let mut report = ImportReport {
        slot,
        cert,
        self_test: Vec::new(),
    };
    match card.self_test(slot, alg, &public, pin) {
        Ok(results) => {
            let failed = results.iter().any(|(_, outcome)| outcome.is_failure());
            report.self_test = results;
            if failed {
                Err(ImportFailure::SelfTestFailed(report))
            } else {
                Ok(report)
            }
        }
        Err(error) => Err(ImportFailure::SelfTestNotRun { report, error }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PW: &str = "keyroost-test";

    fn load(name: &str) -> Contents {
        let path = format!(
            "{}/../keyroost-p12/tests/fixtures/{name}.p12",
            env!("CARGO_MANIFEST_DIR")
        );
        let bytes = std::fs::read(path).unwrap();
        keyroost_p12::open(&bytes, Some(PW)).unwrap()
    }

    const NK: AppletFingerprint = AppletFingerprint::Trussed(TrussedVariant::Nitrokey);
    const NK_FW: Option<&[u8]> = Some(&[1, 9, 1]);
    const YK_APPLET: Option<&[u8]> = Some(&[5, 7, 1]);

    fn yk(
        c: &Contents,
        choice: Option<usize>,
        slot: Slot,
    ) -> Result<ImportPlan<'_>, ImportRefusal> {
        plan_import(
            c,
            choice,
            slot,
            AppletFingerprint::YubiKey,
            YK_APPLET,
            None,
            PinPolicy::Default,
            TouchPolicy::Default,
        )
    }

    fn nk(c: &Contents, slot: Slot) -> Result<ImportPlan<'_>, ImportRefusal> {
        plan_import(
            c,
            None,
            slot,
            NK,
            None,
            NK_FW,
            PinPolicy::Default,
            TouchPolicy::Default,
        )
    }

    #[test]
    fn single_entry_plans_without_choice() {
        let c = load("rsa2048-modern");
        let plan = yk(&c, None, Slot::Authentication).unwrap();
        assert_eq!(plan.layout, ImportLayout::Yubico);
        assert_eq!(plan.slot, Slot::Authentication);
        assert_eq!(plan.skipped_authorities, 0);
        assert!(plan.entry.certificate.is_some());
    }

    #[test]
    fn two_entries_need_a_choice_listing_labels() {
        let c = load("two-entries");
        match yk(&c, None, Slot::Authentication).unwrap_err() {
            ImportRefusal::ChooseEntry(labels) => {
                assert_eq!(labels, entry_labels(&c));
                assert!(
                    labels[0].starts_with("first (RSA-2048; certificate: ")
                        && labels[1].starts_with("second (ECC P-256; certificate: "),
                    "{labels:?}"
                );
            }
            other => panic!("{other:?}"),
        }
        assert!(yk(&c, Some(2), Slot::Authentication).is_ok());
    }

    #[test]
    fn unlabeled_entries_differ_by_their_certificates() {
        let mut c = load("two-entries");
        for e in &mut c.entries {
            e.label = None;
        }
        let labels = entry_labels(&c);
        assert!(
            labels[0].starts_with("entry 1 (RSA-2048; certificate: "),
            "{labels:?}"
        );
        assert!(
            labels[1].starts_with("entry 2 (ECC P-256; certificate: "),
            "{labels:?}"
        );
        let subjects: Vec<&str> = labels
            .iter()
            .map(|l| l.split("certificate: ").nth(1).unwrap())
            .collect();
        assert_ne!(subjects[0], subjects[1], "{labels:?}");
        c.entries[1].certificate = None;
        assert_eq!(entry_labels(&c)[1], "entry 2 (ECC P-256; no certificate)");
    }

    /// Below firmware 1.8 a Nitrokey has no import command: the refusal names
    /// the firmware that has one, before any entry choice, and is the same
    /// text the app shows before a file is picked.
    #[test]
    fn nitrokey_below_1_8_is_told_the_firmware_it_needs() {
        let old_fw: Option<&[u8]> = Some(&[1, 7, 2]);
        let blocked = import_blocked(NK, None, old_fw).expect("refused");
        assert_eq!(
            blocked,
            ImportRefusal::NeedsNewerVersion {
                alg: None,
                fingerprint: NK,
                floor: compat::VersionFloor {
                    axis: compat::VersionAxis::Firmware,
                    version: &[1, 8],
                },
            }
        );
        assert_eq!(
            blocked.to_string(),
            "Importing keys needs Nitrokey 3 firmware 1.8 or later."
        );
        for (file, slot) in [
            ("rsa2048-modern", Slot::Authentication),
            ("two-entries", Slot::Authentication),
            ("p256-modern", Slot::Signature),
        ] {
            let c = load(file);
            let got = plan_import(
                &c,
                None,
                slot,
                NK,
                None,
                old_fw,
                PinPolicy::Default,
                TouchPolicy::Default,
            )
            .unwrap_err();
            assert_eq!(got, blocked, "{file}");
        }
        assert_eq!(import_blocked(NK, None, Some(&[1, 8])), None);
        assert_eq!(import_blocked(NK, None, NK_FW), None);
    }

    #[test]
    fn needs_newer_version_names_the_key_type_and_axis() {
        let r = ImportRefusal::NeedsNewerVersion {
            alg: Some(KeyAlg::Rsa3072),
            fingerprint: NK,
            floor: compat::VersionFloor {
                axis: compat::VersionAxis::Firmware,
                version: &[1, 8, 2],
            },
        };
        assert_eq!(
            r.to_string(),
            format!(
                "Importing {} keys needs Nitrokey 3 firmware 1.8.2 or later.",
                KeyAlg::Rsa3072.label()
            )
        );
        let r = ImportRefusal::NeedsNewerVersion {
            alg: None,
            fingerprint: AppletFingerprint::YubiKey,
            floor: compat::VersionFloor {
                axis: compat::VersionAxis::Applet,
                version: &[5, 7],
            },
        };
        assert_eq!(
            r.to_string(),
            format!(
                "Importing keys needs {} PIV applet 5.7 or later.",
                AppletFingerprint::YubiKey.applet_name()
            )
        );
        assert_eq!(
            ImportRefusal::ImportNotSupported.to_string(),
            "This device can't import keys."
        );
    }

    #[test]
    fn choose_entry_is_the_plans_choice() {
        let c = load("two-entries");
        assert!(std::ptr::eq(
            choose_entry(&c, Some(2)).unwrap(),
            yk(&c, Some(2), Slot::Authentication).unwrap().entry
        ));
        assert_eq!(
            choose_entry(&c, None).unwrap_err(),
            ImportRefusal::ChooseEntry(entry_labels(&c))
        );
        let one = load("rsa2048-modern");
        assert!(std::ptr::eq(
            choose_entry(&one, None).unwrap(),
            &one.entries[0]
        ));
    }

    #[test]
    fn a_policy_value_the_firmware_refuses_is_refused() {
        let c = load("rsa2048-modern");
        let plan = |applet: &'static [u8], pin, touch| {
            plan_import(
                &c,
                None,
                Slot::Authentication,
                AppletFingerprint::YubiKey,
                Some(applet),
                None,
                pin,
                touch,
            )
        };
        // YubiKey firmware 4.0-4.2 takes touch policies, but not "cached".
        assert_eq!(
            plan(&[4, 1], PinPolicy::Default, TouchPolicy::Cached).unwrap_err(),
            ImportRefusal::TouchPolicyCachedNotSupported
        );
        assert!(plan(&[4, 1], PinPolicy::Default, TouchPolicy::Always).is_ok());
        assert!(plan(&[5, 7, 1], PinPolicy::Default, TouchPolicy::Cached).is_ok());
        assert_eq!(
            ImportRefusal::TouchPolicyCachedNotSupported.to_string(),
            "This device doesn't support touch policy \"cached\"."
        );
    }

    #[test]
    fn choice_out_of_range() {
        let c = load("two-entries");
        for asked in [0, 3] {
            assert_eq!(
                yk(&c, Some(asked), Slot::Authentication).unwrap_err(),
                ImportRefusal::EntryOutOfRange {
                    asked,
                    available: 2
                }
            );
        }
    }

    #[test]
    fn nitrokey_refuses_p256() {
        let c = load("p256-modern");
        assert_eq!(
            nk(&c, Slot::Authentication).unwrap_err(),
            ImportRefusal::KeyTypeNotSupported(KeyAlg::EccP256)
        );
    }

    #[test]
    fn nitrokey_refuses_slot_9c() {
        let c = load("rsa2048-modern");
        assert_eq!(
            nk(&c, Slot::Signature).unwrap_err(),
            ImportRefusal::SlotNotSupported(Slot::Signature)
        );
    }

    #[test]
    fn nitrokey_rsa2048_9a_uses_nitrokey_layout() {
        let c = load("rsa2048-modern");
        let plan = nk(&c, Slot::Authentication).unwrap();
        assert_eq!(plan.layout, ImportLayout::NitrokeyRsa);
    }

    #[test]
    fn yubikey_refuses_exponent_3() {
        let c = load("rsa-e3");
        assert_eq!(
            yk(&c, None, Slot::Authentication).unwrap_err(),
            ImportRefusal::RsaExponentNot65537
        );
    }

    #[test]
    fn token2_rsa_is_allowed_unverified() {
        let c = load("rsa2048-modern");
        let plan = plan_import(
            &c,
            None,
            Slot::Authentication,
            AppletFingerprint::Token2,
            None,
            None,
            PinPolicy::Default,
            TouchPolicy::Default,
        )
        .unwrap();
        assert_eq!(plan.layout, ImportLayout::Yubico);
    }

    /// A Token2's touch policy goes through its compat row like any other
    /// device: refused up to the newest applet version on record (5.112.0),
    /// unverified (allowed, with the usual warning) past it — the same
    /// answer `piv key generate` gets.
    #[test]
    fn token2_touch_policy_follows_its_compat_row() {
        let c = load("rsa2048-modern");
        let plan = |version: Option<&[u8]>, touch| {
            plan_import(
                &c,
                None,
                Slot::Authentication,
                AppletFingerprint::Token2,
                version,
                None,
                PinPolicy::Default,
                touch,
            )
        };
        let gate = |version| {
            compat::resolve(
                PivExtension::SlotTouchPolicy,
                AppletFingerprint::Token2,
                version,
                None,
            )
        };
        for version in [None, Some(&[5u8, 112, 0][..]), Some(&[5, 100, 0])] {
            assert_eq!(gate(version), FeatureGate::Unsupported, "{version:?}");
            assert_eq!(
                plan(version, TouchPolicy::Always).unwrap_err(),
                ImportRefusal::TouchPolicyNotSupported,
                "{version:?}"
            );
            assert!(plan(version, TouchPolicy::Default).is_ok(), "{version:?}");
        }
        for version in [&[5u8, 113, 0][..], &[6, 0, 0]] {
            assert_eq!(gate(Some(version)), FeatureGate::Unverified, "{version:?}");
            for touch in [TouchPolicy::Always, TouchPolicy::Cached, TouchPolicy::Never] {
                assert_eq!(
                    plan(Some(version), touch).unwrap().touch_policy,
                    touch,
                    "{version:?} {touch:?}"
                );
            }
        }
    }

    /// A Nitrokey never applies a PIN or touch policy (its compat rows, known
    /// unsupported through firmware 1.9.1): import refuses a non-default one.
    #[test]
    fn nitrokey_policies_refused_through_1_9_1() {
        let c = load("rsa2048-modern");
        let plan = |fw: &[u8], pin, touch| {
            plan_import(
                &c,
                None,
                Slot::Authentication,
                NK,
                None,
                Some(fw),
                pin,
                touch,
            )
        };
        for fw in [&[1u8, 8, 3][..], &[1, 9, 1]] {
            assert_eq!(
                plan(fw, PinPolicy::Always, TouchPolicy::Default).unwrap_err(),
                ImportRefusal::PinPolicyNotSupported,
                "{fw:?}"
            );
            assert_eq!(
                plan(fw, PinPolicy::Default, TouchPolicy::Always).unwrap_err(),
                ImportRefusal::TouchPolicyNotSupported,
                "{fw:?}"
            );
            assert!(plan(fw, PinPolicy::Default, TouchPolicy::Default).is_ok());
        }
        // Newer than the newest source read: unverified, so allowed, as
        // `piv key generate` does.
        assert!(plan(&[1, 9, 2], PinPolicy::Always, TouchPolicy::Always).is_ok());
    }

    #[test]
    fn yubikey_policies_allowed() {
        let c = load("rsa2048-modern");
        assert!(plan_import(
            &c,
            None,
            Slot::Authentication,
            AppletFingerprint::YubiKey,
            YK_APPLET,
            None,
            PinPolicy::Always,
            TouchPolicy::Cached
        )
        .is_ok());
    }

    #[test]
    fn import_parts_rsa_layouts() {
        let c = load("rsa2048-modern");
        let key = &c.entries[0].key;
        let KeyParts::Rsa {
            p, q, e, dp, qinv, ..
        } = key
        else {
            panic!()
        };
        match import_parts(key, ImportLayout::Yubico) {
            ImportParts::RsaCrt {
                p: gp,
                q: gq,
                dp: gdp,
                qinv: gqi,
                ..
            } => {
                assert_eq!((gp, gq, gdp, gqi), (&p[..], &q[..], &dp[..], &qinv[..]));
            }
            other => panic!("{other:?}"),
        }
        match import_parts(key, ImportLayout::NitrokeyRsa) {
            ImportParts::RsaPrimes {
                p: gp,
                q: gq,
                e: ge,
            } => {
                assert_eq!((gp, gq, ge), (&p[..], &q[..], &e[..]));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn chain_counts_skipped_authorities() {
        let c = load("rsa2048-chain");
        let plan = yk(&c, None, Slot::Authentication).unwrap();
        assert_eq!(plan.skipped_authorities, c.authorities.len());
        assert!(plan.skipped_authorities >= 1);
    }
}

#[cfg(test)]
mod run_tests {
    //! The write order of [`run_import_with`], against a scripted card that
    //! records every call. Certificate stores go through the real
    //! compression decision (`store_certificate`), so a card refusing every
    //! length shows both the uncompressed and the compressed attempt.
    use super::*;
    use crate::piv::{
        cert_write_result, send_certificate, send_import_key, store_certificate, LongLink,
    };
    use crate::{CertCompression, CertImport, TransportError};
    use keyroost_piv::{CertInfo, PublicKey};
    use keyroost_pivtest::{Outcome, SelfTest};
    use std::collections::VecDeque;

    const PW: &str = "keyroost-test";
    const PIN: &[u8] = b"123456";

    fn load(name: &str) -> Contents {
        let path = format!(
            "{}/../keyroost-p12/tests/fixtures/{name}.p12",
            env!("CARGO_MANIFEST_DIR")
        );
        let bytes = std::fs::read(path).unwrap();
        keyroost_p12::open(&bytes, Some(PW)).unwrap()
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Call {
        PutCert {
            compressed: bool,
        },
        ClearCert,
        WriteKey {
            alg_id: u8,
            body: Vec<u8>,
        },
        RememberKey {
            alg: KeyAlg,
            public: PublicKey,
        },
        SelfTest {
            alg: KeyAlg,
            pubkey: PublicKey,
            pin: Option<Vec<u8>>,
        },
    }

    struct FakeCard {
        calls: Vec<Call>,
        /// Status word for every certificate PUT DATA.
        cert_sw: u16,
        /// A compressed store reads back as something else.
        readback_mismatch: bool,
        clear_ok: bool,
        key_sw: u16,
        alg_id: u8,
        self_test: Result<Vec<(SelfTest, Outcome)>, ()>,
        /// When set, certificate stores and key writes go through the real
        /// APDU-level send path, each APDU answered from here in order
        /// (`9000` once it runs out).
        apdus: Option<VecDeque<Answer>>,
        /// PINs presented to VERIFY before the writes (kept apart from
        /// `calls`, which are the slot's operations).
        pins_verified: Vec<Vec<u8>>,
        /// `Some(tries)`: VERIFY answers "wrong PIN".
        pin_rejected: Option<Option<u8>>,
    }

    /// One scripted answer to an APDU.
    type Answer = Result<(Vec<u8>, u16), TransportError>;

    const LINK: LongLink = LongLink {
        traced: false,
        chain_upfront: None,
    };

    impl FakeCard {
        fn send(&mut self) -> impl FnMut(&[u8]) -> Result<(Vec<u8>, u16), TransportError> + '_ {
            let script = self.apdus.as_mut().unwrap();
            move |_apdu| script.pop_front().unwrap_or(Ok((Vec::new(), 0x9000)))
        }
    }

    impl Default for FakeCard {
        fn default() -> Self {
            Self {
                calls: Vec::new(),
                cert_sw: 0x9000,
                readback_mismatch: false,
                clear_ok: true,
                key_sw: 0x9000,
                alg_id: 0x07,
                self_test: Ok(vec![
                    (SelfTest::Decrypt, Outcome::Passed),
                    (SelfTest::KeyAgree, Outcome::Skipped(KeyAlg::Rsa2048)),
                    (SelfTest::Sign, Outcome::Passed),
                ]),
                apdus: None,
                pins_verified: Vec::new(),
                pin_rejected: None,
            }
        }
    }

    fn apdu_err(label: &'static str, sw: u16) -> TransportError {
        TransportError::Apdu {
            label,
            sw1: (sw >> 8) as u8,
            sw2: sw as u8,
        }
    }

    impl ImportCard for FakeCard {
        fn algorithm_id(&mut self, _alg: KeyAlg) -> u8 {
            self.alg_id
        }

        fn store_certificate_unchecked(
            &mut self,
            slot: Slot,
            der: &[u8],
            compression: CertCompression,
        ) -> Result<CertImport, TransportError> {
            if self.apdus.is_some() {
                self.calls.push(Call::PutCert { compressed: false });
                return send_certificate(LINK, slot, der, compression, &mut self.send());
            }
            let sw = self.cert_sw;
            let calls = &mut self.calls;
            let done = store_certificate(slot, der, compression, |info, _payload| {
                calls.push(Call::PutCert {
                    compressed: info == CertInfo::Gzip,
                });
                cert_write_result(slot, der.len(), sw)
            })?;
            if done.compressed && self.readback_mismatch {
                return Err(TransportError::PivCertReadbackMismatch { slot });
            }
            Ok(done)
        }

        fn clear_certificate(&mut self, _slot: Slot) -> Result<(), TransportError> {
            self.calls.push(Call::ClearCert);
            if self.clear_ok {
                Ok(())
            } else {
                Err(apdu_err("piv clear certificate", 0x6A80))
            }
        }

        fn verify_pin(&mut self, pin: &[u8]) -> Result<(), TransportError> {
            self.pins_verified.push(pin.to_vec());
            match self.pin_rejected {
                Some(tries_remaining) => Err(TransportError::PivPinRejected { tries_remaining }),
                None => Ok(()),
            }
        }

        fn write_key(&mut self, slot: Slot, alg_id: u8, body: &[u8]) -> Result<(), TransportError> {
            self.calls.push(Call::WriteKey {
                alg_id,
                body: body.to_vec(),
            });
            if self.apdus.is_some() {
                return send_import_key(LINK, slot, alg_id, body, &mut self.send());
            }
            if self.key_sw == 0x9000 {
                Ok(())
            } else {
                Err(apdu_err("piv import key", self.key_sw))
            }
        }

        fn remember_key(&mut self, _slot: Slot, alg: KeyAlg, public: PublicKey) {
            self.calls.push(Call::RememberKey { alg, public });
        }

        fn self_test(
            &mut self,
            _slot: Slot,
            alg: KeyAlg,
            pubkey: &PublicKey,
            pin: Option<&[u8]>,
        ) -> Result<Vec<(SelfTest, Outcome)>, TransportError> {
            self.calls.push(Call::SelfTest {
                alg,
                pubkey: pubkey.clone(),
                pin: pin.map(<[u8]>::to_vec),
            });
            self.self_test
                .clone()
                .map_err(|()| TransportError::PivPinRejected {
                    tries_remaining: Some(2),
                })
        }
    }

    fn yk_plan(c: &Contents) -> ImportPlan<'_> {
        plan_import(
            c,
            None,
            Slot::Authentication,
            AppletFingerprint::YubiKey,
            Some(&[5, 7, 1]),
            None,
            PinPolicy::Default,
            TouchPolicy::Default,
        )
        .unwrap()
    }

    fn run(card: &mut FakeCard, plan: &ImportPlan<'_>) -> Result<ImportReport, ImportFailure> {
        run_import_with(card, plan, CertCompression::Auto, Some(PIN))
    }

    fn kinds(calls: &[Call]) -> Vec<&'static str> {
        calls
            .iter()
            .map(|c| match c {
                Call::PutCert { .. } => "put-cert",
                Call::ClearCert => "clear-cert",
                Call::WriteKey { .. } => "write-key",
                Call::RememberKey { .. } => "remember-key",
                Call::SelfTest { .. } => "self-test",
            })
            .collect()
    }

    #[test]
    fn key_file_reads_up_to_the_limit_and_no_further() {
        let at_limit = [7u8; 64];
        assert_eq!(
            &read_key_file_from(&at_limit[..], 64).unwrap()[..],
            &at_limit[..]
        );
        let over = [7u8; 65];
        let e = read_key_file_from(&over[..], 64).unwrap_err();
        assert!(matches!(e, KeyFileError::TooLarge));
        assert_eq!(
            e.to_string(),
            "This file is larger than a .p12/.pfx key file should be (over 1 MiB)."
        );
        // `open`'s own refusal, for a caller that skipped `read_key_file`,
        // reads the same.
        assert_eq!(
            file_error_message(keyroost_p12::P12Error::TooLarge),
            e.to_string()
        );
        // An endless reader stops one byte past the limit.
        let e = read_key_file_from(std::io::repeat(1), keyroost_p12::MAX_FILE_BYTES).unwrap_err();
        assert!(matches!(e, KeyFileError::TooLarge));
    }

    #[test]
    fn missing_key_file_is_an_io_error() {
        let e = read_key_file(std::path::Path::new("tests/fixtures/no-such-file.p12")).unwrap_err();
        assert!(matches!(e, KeyFileError::Io(_)));
    }

    #[test]
    fn too_much_work_reads_plainly() {
        assert_eq!(
            file_error_message(keyroost_p12::P12Error::Unsupported(
                keyroost_p12::TOO_MUCH_WORK
            )),
            "This file asks for more password-hashing work than keyroost allows."
        );
    }

    #[test]
    fn a_wrong_pin_stops_before_any_write() {
        for (name, tries, want) in [
            (
                "rsa2048-modern",
                Some(2),
                "Wrong PIN (2 tries left). Nothing was written.",
            ),
            (
                "key-only",
                Some(1),
                "Wrong PIN (1 try left). Nothing was written.",
            ),
            (
                "rsa2048-modern",
                None,
                "The PIN was refused; it may be blocked. Nothing was written.",
            ),
            (
                "rsa2048-modern",
                Some(0),
                "The PIN is blocked. Nothing was written.",
            ),
        ] {
            let c = load(name);
            let plan = yk_plan(&c);
            let mut card = FakeCard {
                pin_rejected: Some(tries),
                ..FakeCard::default()
            };
            let e = run(&mut card, &plan).unwrap_err();
            assert!(matches!(e, ImportFailure::PinNotVerified(_)), "{e:?}");
            assert_eq!(e.to_string(), want);
            // No certificate stored or cleared, no key written, no test.
            assert!(card.calls.is_empty(), "{name}: {:?}", card.calls);
            assert_eq!(card.pins_verified, [PIN.to_vec()]);
        }
    }

    #[test]
    fn the_pin_is_checked_before_the_writes_and_again_in_the_test() {
        let c = load("rsa2048-modern");
        let plan = yk_plan(&c);
        let mut card = FakeCard::default();
        run(&mut card, &plan).unwrap();
        assert_eq!(card.pins_verified, [PIN.to_vec()]);
        assert!(matches!(
            card.calls.last(),
            Some(Call::SelfTest { pin: Some(p), .. }) if p == PIN
        ));
        // Without a PIN nothing is verified up front.
        let mut card = FakeCard::default();
        run_import_with(&mut card, &plan, CertCompression::Auto, None).unwrap();
        assert!(card.pins_verified.is_empty());
    }

    #[test]
    fn writes_certificate_then_key_then_tests() {
        let c = load("rsa2048-modern");
        let plan = yk_plan(&c);
        let mut card = FakeCard::default();
        let report = run(&mut card, &plan).unwrap();
        assert_eq!(
            kinds(&card.calls),
            ["put-cert", "write-key", "remember-key", "self-test"],
            "{:?}",
            card.calls
        );
        assert_eq!(card.calls[0], Call::PutCert { compressed: false });
        // The self-test runs against the entry's own public key, with the PIN.
        assert_eq!(
            card.calls[2],
            Call::RememberKey {
                alg: KeyAlg::Rsa2048,
                public: c.entries[0].key.public_key(),
            }
        );
        assert_eq!(
            card.calls[3],
            Call::SelfTest {
                alg: KeyAlg::Rsa2048,
                pubkey: c.entries[0].key.public_key(),
                pin: Some(PIN.to_vec()),
            }
        );
        let cert = report.cert.unwrap();
        assert!(!cert.compressed);
        assert_eq!(report.slot, Slot::Authentication);
        assert_eq!(report.self_test.len(), 3);
    }

    #[test]
    fn key_body_uses_the_resolved_algorithm_byte() {
        let c = load("rsa2048-modern");
        let mut card = FakeCard {
            alg_id: 0x16,
            ..FakeCard::default()
        };
        run(&mut card, &yk_plan(&c)).unwrap();
        let Call::WriteKey { alg_id, body } = &card.calls[1] else {
            panic!("{:?}", card.calls)
        };
        assert_eq!(*alg_id, 0x16);
        // Yubico layout: five CRT parts, tags 01..05, 128 bytes each.
        let tags: Vec<u8> = tlv_tags(body);
        assert_eq!(tags, [1, 2, 3, 4, 5]);
    }

    /// The tags of a flat TLV run (one-byte tags, BER lengths up to 0x82).
    fn tlv_tags(mut body: &[u8]) -> Vec<u8> {
        let mut tags = Vec::new();
        while let [tag, rest @ ..] = body {
            let (len, rest) = match rest {
                [0x81, l, rest @ ..] => (usize::from(*l), rest),
                [0x82, h, l, rest @ ..] => (usize::from(*h) << 8 | usize::from(*l), rest),
                [l, rest @ ..] => (usize::from(*l), rest),
                [] => panic!("truncated TLV"),
            };
            tags.push(*tag);
            body = &rest[len..];
        }
        tags
    }

    #[test]
    fn oversized_certificate_writes_no_key() {
        let c = load("rsa2048-modern");
        let plan = yk_plan(&c);
        // 6700 to every length: Auto tries uncompressed, then compressed.
        let mut card = FakeCard {
            cert_sw: 0x6700,
            ..FakeCard::default()
        };
        let err = run(&mut card, &plan).unwrap_err();
        assert_eq!(
            card.calls,
            [
                Call::PutCert { compressed: false },
                Call::PutCert { compressed: true }
            ]
        );
        match &err {
            ImportFailure::CertificateNotStored {
                error: TransportError::PivCertTooLarge { .. },
                certificate_cleared: None,
                ..
            } => {}
            other => panic!("{other:?}"),
        }
        assert_eq!(
            err.to_string(),
            "The certificate didn't fit on the key. Nothing was changed; \
             slot 9A keeps its old key and certificate."
        );

        // 6A84 (no room): not a length refusal, so no compressed retry.
        let mut card = FakeCard {
            cert_sw: 0x6A84,
            ..FakeCard::default()
        };
        let err = run(&mut card, &plan).unwrap_err();
        assert_eq!(card.calls, [Call::PutCert { compressed: false }]);
        assert!(matches!(
            err,
            ImportFailure::CertificateNotStored {
                error: TransportError::PivCardFull { .. },
                certificate_cleared: None,
                ..
            }
        ));
    }

    #[test]
    fn unconfirmed_certificate_store_is_cleared_and_no_key_written() {
        // Stored compressed, but the card reads back something else: the slot
        // may now hold a certificate next to the old key, so it is cleared.
        let c = load("rsa2048-modern");
        let plan = yk_plan(&c);
        let mut card = FakeCard {
            readback_mismatch: true,
            ..FakeCard::default()
        };
        let err = run_import_with(&mut card, &plan, CertCompression::Always, None).unwrap_err();
        assert_eq!(kinds(&card.calls), ["put-cert", "clear-cert"]);
        assert!(matches!(
            err,
            ImportFailure::CertificateNotStored {
                certificate_cleared: Some(true),
                ..
            }
        ));
        assert!(
            err.to_string()
                .ends_with("Slot 9A keeps its old key and now has no certificate."),
            "{err}"
        );

        card = FakeCard {
            readback_mismatch: true,
            clear_ok: false,
            ..FakeCard::default()
        };
        let err = run_import_with(&mut card, &plan, CertCompression::Always, None).unwrap_err();
        assert!(matches!(
            err,
            ImportFailure::CertificateNotStored {
                certificate_cleared: Some(false),
                ..
            }
        ));
        assert!(
            err.to_string()
                .contains("keyroostctl piv cert delete --slot 9a"),
            "{err}"
        );
    }

    #[test]
    fn key_write_failure_clears_new_certificate() {
        let c = load("rsa2048-modern");
        let plan = yk_plan(&c);
        let mut card = FakeCard {
            key_sw: 0x6A80,
            ..FakeCard::default()
        };
        let err = run(&mut card, &plan).unwrap_err();
        assert_eq!(kinds(&card.calls), ["put-cert", "write-key", "clear-cert"]);
        assert!(matches!(
            err,
            ImportFailure::KeyNotWritten {
                certificate_cleared: true,
                ..
            }
        ));
        let msg = err.to_string();
        assert!(msg.starts_with("The key couldn't be written: "), "{msg}");
        assert!(
            msg.ends_with("Slot 9A keeps its old key and now has no certificate."),
            "{msg}"
        );

        // The clear fails too: say so, and how to finish the job.
        let mut card = FakeCard {
            key_sw: 0x6A80,
            clear_ok: false,
            ..FakeCard::default()
        };
        let err = run(&mut card, &plan).unwrap_err();
        assert_eq!(kinds(&card.calls), ["put-cert", "write-key", "clear-cert"]);
        assert!(matches!(
            err,
            ImportFailure::KeyNotWritten {
                certificate_cleared: false,
                ..
            }
        ));
        let msg = err.to_string();
        assert!(
            msg.contains("the new certificate is still stored next to the old key"),
            "{msg}"
        );
        assert!(
            msg.contains("`keyroostctl piv cert delete --slot 9a`"),
            "{msg}"
        );
    }

    #[test]
    fn key_only_entry_clears_old_certificate_first() {
        let c = load("key-only");
        let plan = yk_plan(&c);
        assert!(plan.entry.certificate.is_none());
        let mut card = FakeCard::default();
        let report = run(&mut card, &plan).unwrap();
        assert_eq!(
            kinds(&card.calls),
            ["clear-cert", "write-key", "remember-key", "self-test"]
        );
        assert!(report.cert.is_none());

        // Can't clear the old certificate: stop before the key.
        let mut card = FakeCard {
            clear_ok: false,
            ..FakeCard::default()
        };
        let err = run(&mut card, &plan).unwrap_err();
        assert_eq!(kinds(&card.calls), ["clear-cert"]);
        assert!(matches!(
            err,
            ImportFailure::CertificateNotStored {
                certificate_cleared: None,
                ..
            }
        ));
    }

    #[test]
    fn nitrokey_layout_sent_for_trussed() {
        let c = load("rsa2048-modern");
        let plan = plan_import(
            &c,
            None,
            Slot::Authentication,
            AppletFingerprint::Trussed(TrussedVariant::Nitrokey),
            None,
            Some(&[1, 9, 1]),
            PinPolicy::Default,
            TouchPolicy::Default,
        )
        .unwrap();
        let mut card = FakeCard::default();
        run(&mut card, &plan).unwrap();
        let Call::WriteKey { body, .. } = &card.calls[1] else {
            panic!("{:?}", card.calls)
        };
        let KeyParts::Rsa { p, q, e, .. } = &c.entries[0].key else {
            panic!()
        };
        let pad = |v: &[u8]| {
            let mut out = vec![0u8; 128 - v.len()];
            out.extend_from_slice(v);
            out
        };
        let mut want = vec![0x01, 0x81, 0x80];
        want.extend(pad(p));
        want.extend([0x02, 0x81, 0x80]);
        want.extend(pad(q));
        want.push(0x03);
        want.push(e.len() as u8);
        want.extend_from_slice(e);
        assert_eq!(*body, want);
        assert_eq!(tlv_tags(body), [1, 2, 3]);
    }

    #[test]
    fn self_test_failure_is_reported_with_slot_state() {
        let c = load("rsa2048-modern");
        let plan = yk_plan(&c);
        let mut card = FakeCard {
            self_test: Ok(vec![
                (SelfTest::Decrypt, Outcome::Passed),
                (SelfTest::KeyAgree, Outcome::Skipped(KeyAlg::Rsa2048)),
                (SelfTest::Sign, Outcome::Failed("bad signature".into())),
            ]),
            ..FakeCard::default()
        };
        let err = run(&mut card, &plan).unwrap_err();
        // No rollback: the written key and certificate stay.
        assert_eq!(
            kinds(&card.calls),
            ["put-cert", "write-key", "remember-key", "self-test"]
        );
        let ImportFailure::SelfTestFailed(report) = &err else {
            panic!("{err:?}")
        };
        assert!(report.cert.is_some());
        assert_eq!(report.self_test.len(), 3);
        assert_eq!(
            err.to_string(),
            "The new key and certificate are on the card, but the self-test \
             failed: Sign: bad signature."
        );

        // A self-test that can't start (wrong PIN) is reported the same way.
        let mut card = FakeCard {
            self_test: Err(()),
            ..FakeCard::default()
        };
        let err = run(&mut card, &plan).unwrap_err();
        assert!(
            matches!(err, ImportFailure::SelfTestNotRun { .. }),
            "{err:?}"
        );
        assert!(
            err.to_string().starts_with(
                "The new key and certificate are on the card, but the self-test couldn't run: "
            ),
            "{err}"
        );

        // Key-only entry: the message doesn't claim a certificate.
        let k = load("key-only");
        let mut card = FakeCard {
            self_test: Ok(vec![(SelfTest::Sign, Outcome::Failed("no".into()))]),
            ..FakeCard::default()
        };
        let err = run(&mut card, &yk_plan(&k)).unwrap_err();
        assert!(
            err.to_string()
                .starts_with("The new key is on the card (slot 9A has no certificate), but"),
            "{err}"
        );
    }

    #[test]
    fn certificate_of_another_key_is_refused_before_any_write() {
        let mut rsa = load("rsa2048-modern");
        let p256 = load("p256-modern");
        let entry = Entry {
            key: rsa.entries.remove(0).key,
            certificate: p256.entries[0].certificate.clone(),
            label: None,
        };
        let plan = ImportPlan {
            entry: &entry,
            slot: Slot::Authentication,
            layout: ImportLayout::Yubico,
            pin_policy: PinPolicy::Default,
            touch_policy: TouchPolicy::Default,
            skipped_authorities: 0,
        };
        let mut card = FakeCard::default();
        let err = run(&mut card, &plan).unwrap_err();
        assert!(card.calls.is_empty(), "{:?}", card.calls);
        assert!(matches!(
            err,
            ImportFailure::Refused(ImportRefusal::KeyCertificateMismatch)
        ));
        assert_eq!(
            err.to_string(),
            "The certificate doesn't belong to the key. Nothing was changed on the card."
        );
    }

    #[test]
    fn every_paired_fixture_certificate_belongs_to_its_key() {
        let dir = format!(
            "{}/../keyroost-p12/tests/fixtures",
            env!("CARGO_MANIFEST_DIR")
        );
        let mut checked = 0;
        for f in std::fs::read_dir(dir).unwrap() {
            let path = f.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("p12") {
                continue;
            }
            let bytes = std::fs::read(&path).unwrap();
            let pw = if path.ends_with("empty-password.p12") {
                Some("")
            } else {
                Some(PW)
            };
            let Ok(c) = keyroost_p12::open(&bytes, pw) else {
                continue; // the MAC-less files need an explicit opt-in
            };
            for e in &c.entries {
                if e.certificate.is_some() {
                    assert!(
                        certificate_belongs(e, e.key.alg(), &e.key.public_key()),
                        "{}",
                        path.display()
                    );
                    checked += 1;
                }
            }
        }
        assert!(checked >= 10, "{checked}");
    }

    fn reader_failure() -> Result<(Vec<u8>, u16), TransportError> {
        Err(TransportError::Pcsc(pcsc::Error::CommError))
    }

    fn sw(sw: u16) -> Result<(Vec<u8>, u16), TransportError> {
        Ok((Vec::new(), sw))
    }

    #[test]
    fn certificate_refused_after_a_reader_failure_is_cleared_and_hedged() {
        // The extended PUT DATA fails at the reader (it may have landed), the
        // chained retry is refused at its first link: the slot may hold the
        // new certificate next to the old key, so it is deleted.
        let c = load("rsa2048-modern");
        let plan = yk_plan(&c);
        let mut card = FakeCard {
            apdus: Some(VecDeque::from([reader_failure(), sw(0x6A80)])),
            ..FakeCard::default()
        };
        let err = run_import_with(&mut card, &plan, CertCompression::Never, None).unwrap_err();
        assert_eq!(kinds(&card.calls), ["put-cert", "clear-cert"]);
        match &err {
            ImportFailure::CertificateNotStored {
                error: TransportError::PivWriteUnconfirmed(_),
                certificate_cleared: Some(true),
                ..
            } => {}
            other => panic!("{other:?}"),
        }
        let msg = err.to_string();
        assert!(!msg.contains("Nothing was changed"), "{msg}");
        assert!(
            msg.ends_with("Slot 9A keeps its old key and now has no certificate."),
            "{msg}"
        );
    }

    #[test]
    fn key_refused_after_a_reader_failure_is_hedged() {
        let c = load("rsa2048-modern");
        let plan = yk_plan(&c);
        // Certificate: one extended PUT DATA, accepted. Key: the extended APDU
        // fails at the reader, then the first chained link is refused.
        let mut card = FakeCard {
            apdus: Some(VecDeque::from([sw(0x9000), reader_failure(), sw(0x6A80)])),
            ..FakeCard::default()
        };
        let err = run_import_with(&mut card, &plan, CertCompression::Never, None).unwrap_err();
        assert_eq!(kinds(&card.calls), ["put-cert", "write-key", "clear-cert"]);
        match &err {
            ImportFailure::KeyNotWritten {
                error: TransportError::PivWriteUnconfirmed(_),
                certificate_cleared: true,
                ..
            } => {}
            other => panic!("{other:?}"),
        }
        let msg = err.to_string();
        assert!(msg.starts_with("The key write didn't finish: "), "{msg}");
        assert!(msg.contains("may hold its old key or the new one"), "{msg}");
    }

    #[test]
    fn key_only_delete_failures_say_what_the_slot_holds() {
        let c = load("key-only");
        let plan = yk_plan(&c);
        // A refused delete: nothing changed.
        let mut card = FakeCard {
            clear_ok: false,
            ..FakeCard::default()
        };
        let err = run(&mut card, &plan).unwrap_err();
        assert!(matches!(
            err,
            ImportFailure::CertificateNotStored {
                storing_certificate: false,
                certificate_cleared: None,
                ..
            }
        ));
        assert_eq!(
            err.to_string(),
            "The slot's old certificate couldn't be deleted: device rejected piv clear \
             certificate: SW=6A80 (incorrect parameters in the command data field). Nothing \
             was changed; slot 9A keeps its old key and certificate."
        );

        // An unfinished delete (reader failure): hedged.
        let err = ImportFailure::CertificateNotStored {
            slot: Slot::Authentication,
            error: TransportError::Pcsc(pcsc::Error::CommError),
            storing_certificate: false,
            certificate_cleared: Some(false),
        };
        let msg = err.to_string();
        assert!(!msg.contains("Nothing was changed"), "{msg}");
        assert!(
            msg.contains("may or may not still have its old certificate"),
            "{msg}"
        );
    }

    #[test]
    fn plan_carries_the_checked_policies_to_the_key_body() {
        let c = load("p256-modern");
        let plan = plan_import(
            &c,
            None,
            Slot::Signature,
            AppletFingerprint::YubiKey,
            Some(&[5, 7, 1]),
            None,
            PinPolicy::Always,
            TouchPolicy::Cached,
        )
        .unwrap();
        let mut card = FakeCard {
            self_test: Ok(vec![(SelfTest::Sign, Outcome::Passed)]),
            ..FakeCard::default()
        };
        run(&mut card, &plan).unwrap();
        let Call::WriteKey { body, .. } = &card.calls[1] else {
            panic!("{:?}", card.calls)
        };
        assert!(
            body.ends_with(&[0xAA, 0x01, 0x03, 0xAB, 0x01, 0x03]),
            "{body:02X?}"
        );
    }

    #[test]
    fn unencodable_key_refusal_says_nothing_changed() {
        let err =
            ImportFailure::Refused(ImportRefusal::KeyNotEncodable(ImportBodyError::PartTooLong));
        assert_eq!(
            err.to_string(),
            "The key can't be sent to this device: a key value is longer than its \
             field. Nothing was changed on the card."
        );
    }
}
