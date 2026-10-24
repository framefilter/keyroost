//! Pre-flight for importing a PKCS#12 key into a PIV slot: pure checks, no
//! card I/O. The CLI and the app both run [`plan_import`] before asking for a
//! management key or touching the card, so a file the device can't take is
//! refused up front with a plain reason.

use core::fmt;

use keyroost_p12::{Contents, Entry, KeyParts};
use keyroost_piv::compat::{self, FeatureGate, PivExtension};
use keyroost_piv::fingerprint::AppletFingerprint;
use keyroost_piv::{ImportLayout, ImportParts, KeyAlg, PinPolicy, Slot, TouchPolicy};

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
