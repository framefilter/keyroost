//! Pre-flight for importing a PKCS#12 key into a PIV slot: pure checks, no
//! card I/O. The CLI and the app both run [`plan_import`] before asking for a
//! management key or touching the card, so a file the device can't take is
//! refused up front with a plain reason. [`run_import`] then does the card
//! writes in an order that never leaves a key next to a certificate that isn't
//! its own.

use core::fmt;

use keyroost_p12::{Contents, Entry, KeyParts};
use keyroost_piv::compat::{self, FeatureGate, PivExtension};
use keyroost_piv::fingerprint::AppletFingerprint;
use keyroost_piv::{
    ImportBodyError, ImportKey, ImportLayout, ImportParts, KeyAlg, PinPolicy, PublicKey, Slot,
    TouchPolicy,
};
use keyroost_pivtest::{Outcome, SelfTest};

use crate::{CertCompression, CertImport, PivSession, TransportError};

/// What [`plan_import`] decided: which entry goes where, and how the applet
/// wants the key laid out.
#[derive(Debug)]
pub struct ImportPlan<'a> {
    /// The chosen key (and its certificate, if the file had a matching one).
    pub entry: &'a Entry,
    pub slot: Slot,
    pub layout: ImportLayout,
    /// CA certificates in the file that are not written to the card.
    pub skipped_authorities: usize,
}

/// Why an import can't go ahead. Every variant is reached before any write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportRefusal {
    /// The file holds no private key.
    NoKey,
    /// The file holds several keys and none was picked; the labels are in
    /// file order (numbered from 1 in messages).
    ChooseEntry(Vec<String>),
    /// The pick (1-based) is not one of the file's entries.
    EntryOutOfRange {
        asked: usize,
        available: usize,
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
        }
    }
}

impl std::error::Error for ImportRefusal {}

fn entry_label(index: usize, entry: &Entry) -> String {
    match &entry.label {
        Some(label) if !label.is_empty() => label.clone(),
        _ => format!("entry {} ({})", index + 1, entry.key.alg().label()),
    }
}

/// Check a parsed PKCS#12 file against the target applet and slot.
///
/// `choice` is 1-based (as typed, or a dropdown index plus one). Checks run in
/// this order so the most useful message wins: entry choice, key type, slot,
/// RSA exponent, then policies. A non-default PIN or touch policy is refused
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
    let entries = &contents.entries;
    let entry = match (entries.len(), choice) {
        (0, _) => return Err(ImportRefusal::NoKey),
        (n, Some(c)) if c == 0 || c > n => {
            return Err(ImportRefusal::EntryOutOfRange {
                asked: c,
                available: n,
            })
        }
        (_, Some(c)) => &entries[c - 1],
        (1, None) => &entries[0],
        (_, None) => {
            return Err(ImportRefusal::ChooseEntry(
                entries
                    .iter()
                    .enumerate()
                    .map(|(i, e)| entry_label(i, e))
                    .collect(),
            ))
        }
    };

    let alg = entry.key.alg();
    let gate = |ext| compat::resolve(ext, fp, applet_version, firmware_version);
    if gate(PivExtension::ImportKey(alg)) == FeatureGate::Unsupported {
        return Err(ImportRefusal::KeyTypeNotSupported(alg));
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

    Ok(ImportPlan {
        entry,
        slot,
        layout,
        skipped_authorities: contents.authorities.len(),
    })
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
    /// The certificate step failed (storing the entry's certificate, or for a
    /// key-only entry deleting the slot's old one), so the key was not
    /// written. `slot_key_unchanged` is always true: the key is written only
    /// after this step succeeds. `certificate_cleared` is `None` when the
    /// card refused the step outright (the slot's old certificate is still
    /// there); otherwise the store may have left the new certificate next to
    /// the old key, so it was deleted: `Some(true)` when that worked.
    CertificateNotStored {
        slot: Slot,
        error: TransportError,
        slot_key_unchanged: bool,
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
            Self::CertificateNotStored {
                slot,
                error,
                certificate_cleared,
                ..
            } => {
                let s = slot_hex(*slot);
                match certificate_cleared {
                    None => {
                        if matches!(
                            error,
                            TransportError::PivCertTooLarge { .. }
                                | TransportError::PivCardFull { .. }
                        ) {
                            f.write_str("The certificate didn't fit on the key.")?;
                        } else {
                            write!(f, "The slot's certificate couldn't be updated: {error}.")?;
                        }
                        write!(
                            f,
                            " Nothing was changed; slot {s} keeps its old key and certificate."
                        )
                    }
                    Some(true) => write!(
                        f,
                        "The certificate couldn't be stored: {error}. \
                         Slot {s} keeps its old key and now has no certificate."
                    ),
                    Some(false) => write!(
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
            Self::CertificateNotStored { error, .. }
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
    /// Send an IMPORT ASYMMETRIC KEY body.
    fn write_key(&mut self, slot: Slot, alg_id: u8, body: &[u8]) -> Result<(), TransportError>;
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

    fn write_key(&mut self, slot: Slot, alg_id: u8, body: &[u8]) -> Result<(), TransportError> {
        PivSession::write_import_key(self, slot, alg_id, body)
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
/// self-test against the entry's public key. The management key must already
/// be authenticated; `pin`, when given, is used for the self-test only.
///
/// The order keeps the slot consistent at every step:
/// 1. Checks with no card writes: the certificate belongs to the key, and the
///    key fits the applet's layout.
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
    pin_policy: PinPolicy,
    touch_policy: TouchPolicy,
    pin: Option<&[u8]>,
) -> Result<ImportReport, ImportFailure> {
    run_import_with(session, plan, compression, pin_policy, touch_policy, pin)
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
    pin_policy: PinPolicy,
    touch_policy: TouchPolicy,
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
    let body = keyroost_piv::import_key_body(&key, pin_policy, touch_policy)
        .map_err(|e| ImportFailure::Refused(ImportRefusal::KeyNotEncodable(e)))?;

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
                    slot_key_unchanged: true,
                    certificate_cleared,
                });
            }
        },
        None => {
            card.clear_certificate(slot)
                .map_err(|error| ImportFailure::CertificateNotStored {
                    slot,
                    error,
                    slot_key_unchanged: true,
                    certificate_cleared: None,
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
    use keyroost_piv::fingerprint::TrussedVariant;

    const PW: &str = "keyroost-test";

    fn load(name: &str) -> Contents {
        let path = format!(
            "{}/../keyroost-p12/tests/fixtures/{name}.p12",
            env!("CARGO_MANIFEST_DIR")
        );
        let bytes = std::fs::read(path).unwrap();
        keyroost_p12::open(&bytes, Some(PW)).unwrap()
    }

    const NK: AppletFingerprint = AppletFingerprint::Trussed(TrussedVariant::NitroKey);
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
            ImportRefusal::ChooseEntry(labels) => assert_eq!(labels.len(), 2),
            other => panic!("{other:?}"),
        }
        assert!(yk(&c, Some(2), Slot::Authentication).is_ok());
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

    #[test]
    fn token2_touch_policy_refused() {
        let c = load("rsa2048-modern");
        assert_eq!(
            plan_import(
                &c,
                None,
                Slot::Authentication,
                AppletFingerprint::Token2,
                None,
                None,
                PinPolicy::Default,
                TouchPolicy::Always
            )
            .unwrap_err(),
            ImportRefusal::TouchPolicyNotSupported
        );
    }

    #[test]
    fn nitrokey_pin_policy_refused() {
        let c = load("rsa2048-modern");
        assert_eq!(
            plan_import(
                &c,
                None,
                Slot::Authentication,
                NK,
                None,
                Some(&[1, 8, 3]),
                PinPolicy::Always,
                TouchPolicy::Default
            )
            .unwrap_err(),
            ImportRefusal::PinPolicyNotSupported
        );
    }

    #[test]
    fn nitrokey_newer_firmware_pin_policy_is_unverified_not_refused() {
        // Newer than the firmware the refusal was observed on: like
        // `piv key generate`, warn-level (unverified), so allowed here.
        let c = load("rsa2048-modern");
        assert!(plan_import(
            &c,
            None,
            Slot::Authentication,
            NK,
            None,
            NK_FW,
            PinPolicy::Always,
            TouchPolicy::Always
        )
        .is_ok());
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
    use crate::piv::{cert_write_result, store_certificate};
    use crate::{CertCompression, CertImport, TransportError};
    use keyroost_piv::fingerprint::TrussedVariant;
    use keyroost_piv::{CertInfo, PublicKey};
    use keyroost_pivtest::{Outcome, SelfTest};

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

        fn write_key(
            &mut self,
            _slot: Slot,
            alg_id: u8,
            body: &[u8],
        ) -> Result<(), TransportError> {
            self.calls.push(Call::WriteKey {
                alg_id,
                body: body.to_vec(),
            });
            if self.key_sw == 0x9000 {
                Ok(())
            } else {
                Err(apdu_err("piv import key", self.key_sw))
            }
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
        run_import_with(
            card,
            plan,
            CertCompression::Auto,
            PinPolicy::Default,
            TouchPolicy::Default,
            Some(PIN),
        )
    }

    fn kinds(calls: &[Call]) -> Vec<&'static str> {
        calls
            .iter()
            .map(|c| match c {
                Call::PutCert { .. } => "put-cert",
                Call::ClearCert => "clear-cert",
                Call::WriteKey { .. } => "write-key",
                Call::SelfTest { .. } => "self-test",
            })
            .collect()
    }

    #[test]
    fn writes_certificate_then_key_then_tests() {
        let c = load("rsa2048-modern");
        let plan = yk_plan(&c);
        let mut card = FakeCard::default();
        let report = run(&mut card, &plan).unwrap();
        assert_eq!(
            kinds(&card.calls),
            ["put-cert", "write-key", "self-test"],
            "{:?}",
            card.calls
        );
        assert_eq!(card.calls[0], Call::PutCert { compressed: false });
        // The self-test runs against the entry's own public key, with the PIN.
        assert_eq!(
            card.calls[2],
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
                slot_key_unchanged: true,
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
        let err = run_import_with(
            &mut card,
            &plan,
            CertCompression::Always,
            PinPolicy::Default,
            TouchPolicy::Default,
            None,
        )
        .unwrap_err();
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
        let err = run_import_with(
            &mut card,
            &plan,
            CertCompression::Always,
            PinPolicy::Default,
            TouchPolicy::Default,
            None,
        )
        .unwrap_err();
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
        assert_eq!(kinds(&card.calls), ["clear-cert", "write-key", "self-test"]);
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
                slot_key_unchanged: true,
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
            AppletFingerprint::Trussed(TrussedVariant::NitroKey),
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
        assert_eq!(kinds(&card.calls), ["put-cert", "write-key", "self-test"]);
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
