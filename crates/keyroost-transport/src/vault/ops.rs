//! Unlocking the vaults on a key, and choosing among them by name.
//!
//! One touch unlocks every vault: a single getAssertion without an allow
//! list returns each vault credential's hmac-secret output and largeBlobKey,
//! and one read of the largeBlob array holds every vault's data. Each vault
//! is then judged on its own, so one that won't open is reported next to the
//! others instead of hiding them, and never read as empty.

use std::fmt;

use keyroost_ctap::client_pin::permissions::{GET_ASSERTION, LARGE_BLOB_WRITE};
use keyroost_ctap::large_blobs::{BlobCapacity, CredentialData};
use keyroost_vault::{open, Vault, VaultError, RP_ID};
use zeroize::Zeroizing;

use super::{
    check_support, vault_name, VaultAuth, VaultKey, VaultKeyError, VaultProblem, VaultRef,
    VaultStep,
};

/// What a vault is sealed with and found by.
struct VaultSecrets {
    /// The credential's hmac-secret output: seals the vault.
    hmac: Zeroizing<[u8; 32]>,
    /// The credential's largeBlobKey: finds its entry in the array.
    lbk: Zeroizing<[u8; 32]>,
}

/// A vault that opened: its contents and what it takes to write it back.
pub struct OpenVault {
    pub vault_ref: VaultRef,
    /// The entries, as read at unlock (or as last saved).
    pub contents: Vault,
    /// Whether the key holds data for this vault. `false` opens empty: a
    /// credential whose data was never written is an empty vault, as
    /// FidoParole reads it.
    pub stored: bool,
    secrets: VaultSecrets,
}

impl OpenVault {
    pub(super) fn new(
        vault_ref: VaultRef,
        contents: Vault,
        stored: bool,
        hmac: Zeroizing<[u8; 32]>,
        lbk: Zeroizing<[u8; 32]>,
    ) -> Self {
        OpenVault {
            vault_ref,
            contents,
            stored,
            secrets: VaultSecrets { hmac, lbk },
        }
    }

    /// The hmac-secret output and the largeBlobKey, in that order.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "save and the vault lifecycle come next")
    )]
    pub(super) fn secrets(&self) -> (&[u8; 32], &[u8; 32]) {
        (&self.secrets.hmac, &self.secrets.lbk)
    }
}

// Hand-written so the vault's secrets never land in a log (entries already
// hide their passwords).
impl fmt::Debug for OpenVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenVault")
            .field("vault_ref", &self.vault_ref)
            .field("contents", &self.contents)
            .field("stored", &self.stored)
            .field("secrets", &"<redacted>")
            .finish()
    }
}

/// What the data stored for a vault opens to: its contents and whether
/// anything was stored. No data is an empty vault; data that is there but
/// does not open is a problem, never an empty vault, so nothing writes over
/// it.
pub(crate) fn vault_state(
    data: CredentialData,
    hmac: &[u8; 32],
) -> Result<(Vault, bool), VaultProblem> {
    match data {
        CredentialData::Absent => Ok((Vault::default(), false)),
        CredentialData::Present(blob) => open(&blob, hmac)
            .map(|v| (v, true))
            .map_err(VaultProblem::Damaged),
        CredentialData::Unreadable => Err(VaultProblem::Damaged(VaultError::Corrupt(
            "the stored data does not decompress",
        ))),
    }
}

/// One vault credential on the key, open or with the reason it isn't.
#[derive(Debug)]
pub struct VaultOnKey {
    pub vault_ref: VaultRef,
    pub state: Result<OpenVault, VaultProblem>,
}

impl AsRef<VaultRef> for VaultOnKey {
    fn as_ref(&self) -> &VaultRef {
        &self.vault_ref
    }
}

impl VaultOnKey {
    /// How many entries the vault holds; `None` when it did not open.
    pub fn entry_count(&self) -> Option<usize> {
        self.state.as_ref().ok().map(|o| o.contents.entries.len())
    }

    /// The open vault, to read or change; a vault that did not open is
    /// refused with its reason.
    pub fn open_mut(&mut self) -> Result<&mut OpenVault, VaultKeyError> {
        self.state
            .as_mut()
            .map_err(|p| VaultKeyError::CannotOpen(p.clone()))
    }
}

/// Every vault on a key after one unlock, in the key's order, and how full
/// its largeBlob store is.
#[derive(Debug)]
pub struct Unlocked {
    pub vaults: Vec<VaultOnKey>,
    pub capacity: BlobCapacity,
}

/// Unlock every vault on the key with one touch.
///
/// The key is checked first ([`check_support`](super::check_support)), so a
/// key that cannot hold a vault is refused before the PIN is sent. Then one
/// token (getAssertion and largeBlobWrite, bound to the vault RP), a
/// [`VaultStep::UnlockTouch`], one getAssertion over every vault credential
/// and one read of the largeBlob array. A vault the key gives no secret for,
/// or whose data does not open, is listed with its [`VaultProblem`]; the
/// others open regardless. No vault credential is an empty list.
pub fn unlock(
    key: &mut impl VaultKey,
    auth: &mut VaultAuth,
    on_step: &mut dyn FnMut(VaultStep),
) -> Result<Unlocked, VaultKeyError> {
    check_support(key.info())?;
    let asserted = {
        let token = auth.fresh_token(key, GET_ASSERTION | LARGE_BLOB_WRITE, Some(RP_ID))?;
        on_step(VaultStep::UnlockTouch);
        key.assertions(token, None)
    };
    auth.after_presence();
    let asserted = asserted?;
    let array = key.read_blobs()?;
    let capacity = array.capacity(key.info());

    let vaults = asserted
        .into_iter()
        .map(|a| {
            let vault_ref = VaultRef {
                credential_id: a.credential_id,
                name: vault_name(a.user_id.as_deref(), a.user_name.as_deref()),
            };
            let state = match (a.hmac_output, a.large_blob_key) {
                (Some(hmac), Some(lbk)) => {
                    vault_state(array.credential_data(&lbk), &hmac).map(|(contents, stored)| {
                        OpenVault::new(vault_ref.clone(), contents, stored, hmac, lbk)
                    })
                }
                _ => Err(VaultProblem::NoSecret),
            };
            VaultOnKey { vault_ref, state }
        })
        .collect();
    Ok(Unlocked { vaults, capacity })
}

/// How a command names the vault it means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultPick<'a> {
    /// No name given: every vault qualifies (the front end asks or refuses
    /// when there are several).
    Only,
    /// The vaults with exactly this name.
    Name(&'a str),
}

/// The indices of `items` that `how` picks, in order. `Only` on a key with
/// no vault is [`VaultKeyError::NoVaults`]; a name no vault has is
/// [`VaultKeyError::NotFound`]. Several matches are all returned: choosing
/// among them is the front end's job.
pub fn matching<T: AsRef<VaultRef>>(
    items: &[T],
    how: &VaultPick,
) -> Result<Vec<usize>, VaultKeyError> {
    let found: Vec<usize> = items
        .iter()
        .enumerate()
        .filter(|(_, item)| match how {
            VaultPick::Only => true,
            VaultPick::Name(name) => item.as_ref().name.as_deref() == Some(*name),
        })
        .map(|(i, _)| i)
        .collect();
    if !found.is_empty() {
        return Ok(found);
    }
    Err(match how {
        VaultPick::Only => VaultKeyError::NoVaults,
        VaultPick::Name(name) => VaultKeyError::NotFound((*name).to_owned()),
    })
}

#[cfg(test)]
mod tests {
    use super::super::fake::{Call, FakeKey};
    use super::super::VaultCredential;
    use super::*;
    use keyroost_ctap::client_pin::permissions::{GET_ASSERTION as GA, LARGE_BLOB_WRITE as LBW};
    use keyroost_ctap::CtapError;
    use keyroost_vault::{seal, user_handle, Entry, Vault, VaultError, RP_ID};
    use zeroize::Zeroizing;

    fn entry(title: &str) -> Entry {
        Entry {
            id: keyroost_vault::new_id(),
            title: title.into(),
            username: "alice".into(),
            password: Zeroizing::new("hunter22".into()),
            url: String::new(),
            notes: String::new(),
            modified_minutes: 29_000_000,
        }
    }

    fn pin() -> VaultAuth {
        VaultAuth::pin(Zeroizing::new(FakeKey::PIN.to_owned()))
    }

    /// Unlock `key`, returning the result and the steps reported.
    fn run(
        key: &mut FakeKey,
        auth: &mut VaultAuth,
    ) -> (Result<Unlocked, VaultKeyError>, Vec<VaultStep>) {
        let mut steps = Vec::new();
        let r = unlock(key, auth, &mut |s| steps.push(s));
        (r, steps)
    }

    fn unlocked(key: &mut FakeKey) -> Unlocked {
        let (r, _) = run(key, &mut pin());
        r.unwrap_or_else(|e| panic!("{e}"))
    }

    fn opened(v: &VaultOnKey) -> &OpenVault {
        v.state.as_ref().unwrap_or_else(|p| panic!("{p}"))
    }

    fn named(name: &str) -> VaultRef {
        VaultRef {
            credential_id: name.as_bytes().to_vec(),
            name: Some(name.into()),
        }
    }

    #[test]
    fn unlock_opens_every_vault_with_one_touch() {
        let mut key = FakeKey::new();
        key.add_foreign_entries();
        let personal = Vault {
            entries: vec![entry("GitHub"), entry("Mail")],
        };
        let p = key.add_vault("Personal", &personal);
        let w = key.add_vault("Work", &Vault::default());

        let mut auth = pin();
        let (r, steps) = run(&mut key, &mut auth);
        let u = r.unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(steps, vec![VaultStep::UnlockTouch]);
        assert_eq!(
            key.log,
            vec![
                Call::Token {
                    perms: GA | LBW,
                    rp: Some(RP_ID.into())
                },
                Call::Assertions(None),
                Call::Read,
            ]
        );

        assert_eq!(u.vaults.len(), 2);
        let names: Vec<_> = u
            .vaults
            .iter()
            .map(|v| v.vault_ref.name.as_deref())
            .collect();
        assert_eq!(names, vec![Some("Personal"), Some("Work")]);
        assert_eq!(u.vaults[0].vault_ref.credential_id, p);
        assert_eq!(u.vaults[1].as_ref().credential_id, w);
        assert_eq!(u.vaults[0].entry_count(), Some(2));
        assert_eq!(u.vaults[1].entry_count(), Some(0));
        let o = opened(&u.vaults[0]);
        assert_eq!(o.contents, personal);
        assert!(o.stored);
        assert_eq!(o.vault_ref, u.vaults[0].vault_ref);
        assert!(opened(&u.vaults[1]).stored);
        assert_eq!(u.capacity, key.array().capacity(&key.info));
        assert_eq!(
            u.capacity.entry_count, 5,
            "three foreign entries and two vaults"
        );
    }

    #[test]
    fn one_bad_vault_does_not_hide_the_others() {
        let mut key = FakeKey::new();
        let good = Vault {
            entries: vec![entry("GitHub")],
        };
        key.add_vault("First", &good);
        let no_lbk = key.add_vault("NoKey", &good);
        key.creds.iter_mut().find(|c| c.id == no_lbk).unwrap().lbk = None;
        let foreign = key.add_credential(user_handle("Sealed elsewhere").unwrap(), None);
        key.put_blob(&foreign, &seal(&good, &[0x99; 32]).unwrap());
        key.add_vault("Last", &good);

        let u = unlocked(&mut key);
        assert_eq!(u.vaults.len(), 4);
        assert_eq!(opened(&u.vaults[0]).contents, good);
        assert_eq!(
            u.vaults[1].state.as_ref().err(),
            Some(&VaultProblem::NoSecret)
        );
        assert_eq!(u.vaults[1].entry_count(), None);
        assert_eq!(
            u.vaults[2].state.as_ref().err(),
            Some(&VaultProblem::Damaged(VaultError::Decrypt))
        );
        assert_eq!(
            u.vaults[2].vault_ref.name.as_deref(),
            Some("Sealed elsewhere")
        );
        assert_eq!(opened(&u.vaults[3]).contents, good);
    }

    #[test]
    fn undecompressable_entry_is_damaged_not_empty() {
        assert!(matches!(
            vault_state(CredentialData::Unreadable, &[1; 32]),
            Err(VaultProblem::Damaged(VaultError::Corrupt(_)))
        ));
        // Data that decompresses but is not a vault is damaged too.
        assert!(matches!(
            vault_state(
                CredentialData::Present(Zeroizing::new(b"x".to_vec())),
                &[1; 32]
            ),
            Err(VaultProblem::Damaged(VaultError::NotAVault))
        ));
        // Only no data at all opens empty.
        let (v, stored) = vault_state(CredentialData::Absent, &[1; 32]).unwrap();
        assert_eq!(v, Vault::default());
        assert!(!stored);
        let vault = Vault {
            entries: vec![entry("GitHub")],
        };
        let blob = seal(&vault, &[1; 32]).unwrap();
        let (v, stored) =
            vault_state(CredentialData::Present(Zeroizing::new(blob)), &[1; 32]).unwrap();
        assert_eq!(v, vault);
        assert!(stored);
    }

    #[test]
    fn vault_without_data_opens_empty() {
        let mut key = FakeKey::new();
        key.add_credential(user_handle("Work").unwrap(), Some("Work"));
        let u = unlocked(&mut key);
        assert_eq!(u.vaults.len(), 1);
        let o = opened(&u.vaults[0]);
        assert!(!o.stored);
        assert_eq!(o.contents, Vault::default());
        assert_eq!(u.vaults[0].entry_count(), Some(0));
    }

    #[test]
    fn no_vault_credentials_is_an_empty_list() {
        let mut key = FakeKey::new();
        key.add_foreign_entries();
        let u = unlocked(&mut key);
        assert!(u.vaults.is_empty());
        assert_eq!(u.capacity.entry_count, 3);
        assert!(matches!(
            matching(&u.vaults, &VaultPick::Only),
            Err(VaultKeyError::NoVaults)
        ));
    }

    #[test]
    fn name_falls_back_to_user_name_then_none() {
        let mut key = FakeKey::new();
        key.add_credential(user_handle("Handle").unwrap(), Some("ignored"));
        key.add_credential(b"plain-id".to_vec(), Some("Work"));
        key.add_credential(b"other-id".to_vec(), None);
        let u = unlocked(&mut key);
        let names: Vec<_> = u.vaults.iter().map(|v| v.vault_ref.name.clone()).collect();
        assert_eq!(
            names,
            vec![Some("Handle".to_owned()), Some("Work".to_owned()), None]
        );
        // The open vault carries the same name.
        assert_eq!(opened(&u.vaults[1]).vault_ref.name.as_deref(), Some("Work"));
    }

    #[test]
    fn unsupported_key_is_refused_before_the_pin() {
        let mut key = FakeKey::new();
        key.add_vault("Personal", &Vault::default());
        key.info.extensions.retain(|e| e != "hmac-secret");
        let (r, steps) = run(&mut key, &mut pin());
        assert!(matches!(r, Err(VaultKeyError::Unsupported(_))));
        assert!(key.log.is_empty());
        assert!(steps.is_empty());
    }

    #[test]
    fn a_failed_assertion_is_an_error_not_an_empty_key() {
        let mut key = FakeKey::new();
        key.add_vault("Personal", &Vault::default());
        let (r, steps) = run(&mut key, &mut VaultAuth::pin(Zeroizing::new("0000".into())));
        assert!(matches!(
            r,
            Err(VaultKeyError::Ctap(CtapError::StatusCode(0x31)))
        ));
        assert!(steps.is_empty(), "no touch asked for when the PIN fails");
    }

    #[test]
    fn after_unlock_only_the_write_permission_is_reused() {
        // The key keeps only largeBlobWrite after the assertion (CTAP 2.1),
        // and the auth must know it.
        let mut key = FakeKey::new();
        let id = key.add_vault("Personal", &Vault::default());
        let mut auth = pin();
        let u = run(&mut key, &mut auth).0.unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(u.vaults.len(), 1);
        assert!(auth.current_for(GA).is_none());
        assert!(auth.current_for(GA | LBW).is_none());

        // The write permission is still good on the key.
        let lbw = auth
            .current_for(LBW)
            .expect("the write permission stays")
            .clone();
        let bytes = key.stored().to_vec();
        key.write_blobs(&lbw, &bytes).unwrap();

        // A call needing getAssertion takes a fresh token.
        let before = key.log.len();
        let ga = match auth.current_for(GA) {
            Some(t) => t.clone(),
            None => auth
                .fresh_token(&mut key, GA, Some(RP_ID))
                .unwrap_or_else(|e| panic!("{e}"))
                .clone(),
        };
        assert_eq!(
            key.log[before],
            Call::Token {
                perms: GA,
                rp: Some(RP_ID.into())
            }
        );
        assert_eq!(key.assertions(&ga, Some(&id)).unwrap().len(), 1);
    }

    #[test]
    fn open_vault_debug_hides_the_secrets() {
        let o = OpenVault::new(
            named("Personal"),
            Vault {
                entries: vec![entry("GitHub")],
            },
            true,
            Zeroizing::new([0xAB; 32]),
            Zeroizing::new([0xCD; 32]),
        );
        assert_eq!(o.secrets(), (&[0xAB; 32], &[0xCD; 32]));
        let shown = format!("{o:?}");
        assert!(!shown.contains("171") && !shown.contains("205"), "{shown}");
        assert!(!shown.contains("hunter22"), "{shown}");
        assert!(shown.contains("redacted"), "{shown}");
    }

    #[test]
    fn open_mut_refuses_a_vault_that_cannot_open() {
        let mut ok = VaultOnKey {
            vault_ref: named("Personal"),
            state: Ok(OpenVault::new(
                named("Personal"),
                Vault::default(),
                false,
                Zeroizing::new([1; 32]),
                Zeroizing::new([2; 32]),
            )),
        };
        ok.open_mut()
            .unwrap()
            .contents
            .entries
            .push(entry("GitHub"));
        assert_eq!(ok.entry_count(), Some(1));

        let mut bad = VaultOnKey {
            vault_ref: named("Work"),
            state: Err(VaultProblem::Damaged(VaultError::UnsupportedVersion(2))),
        };
        assert!(matches!(
            bad.open_mut(),
            Err(VaultKeyError::CannotOpen(VaultProblem::Damaged(
                VaultError::UnsupportedVersion(2)
            )))
        ));
        let mut none = VaultOnKey {
            vault_ref: named("Mail"),
            state: Err(VaultProblem::NoSecret),
        };
        assert!(matches!(
            none.open_mut(),
            Err(VaultKeyError::CannotOpen(VaultProblem::NoSecret))
        ));
    }

    #[test]
    fn matching_rules() {
        // Over credentials as credential management lists them (what
        // delete matches against); unlocked vaults are below.
        let cred = |vault: VaultRef| VaultCredential {
            vault,
            large_blob_key: None,
            stored_bytes: None,
        };
        let none: Vec<VaultCredential> = Vec::new();
        assert!(matches!(
            matching(&none, &VaultPick::Only),
            Err(VaultKeyError::NoVaults)
        ));
        assert!(matches!(
            matching(&none, &VaultPick::Name("Personal")),
            Err(VaultKeyError::NotFound(n)) if n == "Personal"
        ));

        let one = vec![cred(named("Personal"))];
        assert_eq!(matching(&one, &VaultPick::Only).unwrap(), vec![0]);
        assert_eq!(
            matching(&one, &VaultPick::Name("Personal")).unwrap(),
            vec![0]
        );

        let two = vec![cred(named("Personal")), cred(named("Work"))];
        assert_eq!(matching(&two, &VaultPick::Only).unwrap(), vec![0, 1]);
        assert_eq!(matching(&two, &VaultPick::Name("Work")).unwrap(), vec![1]);

        // An interrupted rotate leaves two of a name: both are returned.
        let unnamed = VaultRef {
            credential_id: vec![9],
            name: None,
        };
        let dup = vec![
            cred(named("Personal")),
            cred(unnamed),
            cred(named("Work")),
            cred(named("Personal")),
        ];
        assert_eq!(
            matching(&dup, &VaultPick::Name("Personal")).unwrap(),
            vec![0, 3]
        );
        assert_eq!(matching(&dup, &VaultPick::Only).unwrap(), vec![0, 1, 2, 3]);

        // Names match exactly.
        for other in ["personal", "Personal ", "Person", "Mail"] {
            assert!(
                matches!(
                    matching(&dup, &VaultPick::Name(other)),
                    Err(VaultKeyError::NotFound(ref n)) if n == other
                ),
                "{other:?}"
            );
        }
    }

    #[test]
    fn matching_works_over_unlocked_vaults() {
        let mut key = FakeKey::new();
        key.add_vault("Personal", &Vault::default());
        key.add_vault("Work", &Vault::default());
        key.add_vault("Personal", &Vault::default());
        let u = unlocked(&mut key);
        assert_eq!(
            matching(&u.vaults, &VaultPick::Name("Personal")).unwrap(),
            vec![0, 2]
        );
    }
}
