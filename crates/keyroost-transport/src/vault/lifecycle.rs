//! Making and removing whole vaults.
//!
//! Creating takes two touches: makeCredential makes the vault's credential,
//! and a getAssertion on it returns the hmac-secret output that seals the
//! vault (makeCredential does not return it). Any failure once the
//! credential exists deletes it again, so a failed create never leaves a
//! vault behind that holds nothing.
//!
//! Deleting takes no touch: credential management lists the vault
//! credentials with their largeBlobKeys, which is all it takes to find and
//! remove a vault's data. The data goes first and the credential second, so
//! an interruption leaves at worst a credential with no data, which reads
//! as an empty vault and can be deleted again, never data no credential
//! can find.

use keyroost_ctap::client_pin::permissions::{
    CREDENTIAL_MANAGEMENT, GET_ASSERTION, LARGE_BLOB_WRITE, MAKE_CREDENTIAL,
};
use keyroost_ctap::large_blobs::{CredentialData, LargeBlobArray};
use keyroost_vault::{seal, user_handle, Vault};
use zeroize::Zeroizing;

use super::ops::{check_fits, stale_token, write_array, OpenVault};
use super::{
    check_support, VaultAuth, VaultCredential, VaultKey, VaultKeyError, VaultProblem, VaultRef,
    VaultStep,
};
use crate::ct_eq;

/// The vault credentials, with how much data each holds, and the array
/// that was read for it.
fn credentials_and_array(
    key: &mut impl VaultKey,
    auth: &mut VaultAuth,
) -> Result<(Vec<VaultCredential>, LargeBlobArray), VaultKeyError> {
    check_support(key.info())?;
    // largeBlobWrite too, so a delete that follows needs no second token.
    let token = auth.fresh_token(key, CREDENTIAL_MANAGEMENT | LARGE_BLOB_WRITE, None)?;
    let mut creds = key.credentials(token)?;
    let array = key.read_blobs()?;
    for c in &mut creds {
        c.stored_bytes =
            c.large_blob_key
                .as_ref()
                .and_then(|lbk| match array.credential_data(lbk) {
                    CredentialData::Present(data) => Some(data.len()),
                    CredentialData::Absent | CredentialData::Unreadable => None,
                });
    }
    Ok((creds, array))
}

/// The vault credentials on the key, through credential management: no
/// touch. Each carries how many bytes of data the key holds for it (one
/// read of the largeBlob array), which tells apart vaults that share a name
/// without unlocking them.
///
/// The token it takes also allows the largeBlob write and credential delete
/// of a [`delete`] that follows, so that needs no second PIN exchange.
pub fn list_credentials(
    key: &mut impl VaultKey,
    auth: &mut VaultAuth,
) -> Result<Vec<VaultCredential>, VaultKeyError> {
    credentials_and_array(key, auth).map(|(creds, _)| creds)
}

/// Create a vault named `name` holding `initial`, and return it open.
///
/// Refused before anything is sent: a name that is empty or longer than
/// [`keyroost_vault::MAX_NAME_BYTES`]. Refused before any touch: a name a
/// vault on the key already has ([`VaultKeyError::DuplicateName`]), and a
/// vault the largeBlob store has no room for ([`VaultKeyError::Full`]).
/// Then two touches ([`VaultStep::CreateTouch`], [`VaultStep::UnlockTouch`])
/// and a [`VaultStep::Write`]. When anything fails after the credential was
/// made, the credential is deleted again and the error is
/// [`VaultKeyError::CreateUndone`] with the cause; `left_over` says the
/// delete failed too.
pub fn create(
    key: &mut impl VaultKey,
    auth: &mut VaultAuth,
    name: &str,
    initial: &Vault,
    on_step: &mut dyn FnMut(VaultStep),
) -> Result<OpenVault, VaultKeyError> {
    user_handle(name)?;
    let (existing, array) = credentials_and_array(key, auth)?;
    if existing
        .iter()
        .any(|c| c.vault.name.as_deref() == Some(name))
    {
        return Err(VaultKeyError::DuplicateName(name.to_owned()));
    }
    // The size the array would have: sealing under a stand-in secret and
    // key gives the same length as the real ones. The write checks again.
    let stand_in = [0u8; 32];
    let blob = seal(initial, &stand_in)?;
    check_fits(&array.with_credential_blob(&stand_in, &blob)?, key.info())?;
    create_unchecked(key, auth, name, initial, on_step)
}

/// [`create`] without the name and size checks: make the credential, unlock
/// it, seal `initial` and write it, deleting the credential again on any
/// failure. A rotate uses it to make a vault of the same name.
pub(crate) fn create_unchecked(
    key: &mut impl VaultKey,
    auth: &mut VaultAuth,
    name: &str,
    initial: &Vault,
    on_step: &mut dyn FnMut(VaultStep),
) -> Result<OpenVault, VaultKeyError> {
    let user_id = user_handle(name)?;
    let made = auth.with_touch(
        key,
        MAKE_CREDENTIAL,
        VaultStep::CreateTouch,
        on_step,
        |k, token| k.make_credential(token, &user_id, name),
    )?;
    let id = made.credential_id;
    let filled = match made.large_blob_key {
        None => Err(VaultKeyError::NoLargeBlobKey),
        Some(lbk) => fill(key, auth, &id, name, lbk, initial, on_step),
    };
    filled.map_err(|cause| undo(key, auth, &id, cause))
}

/// Unlock the new credential `id`, check it is the one just made, and
/// store `initial` sealed under its secret.
fn fill(
    key: &mut impl VaultKey,
    auth: &mut VaultAuth,
    id: &[u8],
    name: &str,
    lbk: Zeroizing<[u8; 32]>,
    initial: &Vault,
    on_step: &mut dyn FnMut(VaultStep),
) -> Result<OpenVault, VaultKeyError> {
    let asserted = auth.with_touch(
        key,
        GET_ASSERTION | LARGE_BLOB_WRITE,
        VaultStep::UnlockTouch,
        on_step,
        |k, token| k.assertions(token, Some(id)),
    )?;
    let mut asserted = asserted.into_iter();
    let a = match (asserted.next(), asserted.next()) {
        (Some(a), None) if a.credential_id == id => a,
        _ => return Err(VaultKeyError::CannotOpen(VaultProblem::NoSecret)),
    };
    let unlocked_lbk = a.large_blob_key.ok_or(VaultKeyError::NoLargeBlobKey)?;
    let hmac = a
        .hmac_output
        .ok_or(VaultKeyError::CannotOpen(VaultProblem::NoSecret))?;
    if !ct_eq(&unlocked_lbk[..], &lbk[..]) {
        return Err(VaultKeyError::KeyMismatch);
    }
    let blob = seal(initial, &hmac)?;
    write_array(
        key,
        auth,
        &mut |array| Ok(Some(array.with_credential_blob(&lbk, &blob)?)),
        on_step,
    )?;
    Ok(OpenVault::new(
        VaultRef {
            credential_id: id.to_vec(),
            name: Some(name.to_owned()),
        },
        initial.clone(),
        true,
        hmac,
        lbk,
    ))
}

/// Delete the credential a failed create made, and say why the create
/// failed.
fn undo(
    key: &mut impl VaultKey,
    auth: &mut VaultAuth,
    id: &[u8],
    cause: VaultKeyError,
) -> VaultKeyError {
    let left_over = delete_credential(key, auth, id).is_err();
    VaultKeyError::CreateUndone {
        cause: Box::new(cause),
        left_over,
    }
}

/// Delete credential `id` with the current token when it allows credential
/// management, else a fresh one; once more with a fresh token when the key
/// dropped it or let it expire.
fn delete_credential(
    key: &mut impl VaultKey,
    auth: &mut VaultAuth,
    id: &[u8],
) -> Result<(), VaultKeyError> {
    let token = match auth.current_for(CREDENTIAL_MANAGEMENT) {
        Some(token) => token.clone(),
        None => auth.fresh_token(key, CREDENTIAL_MANAGEMENT, None)?.clone(),
    };
    match key.delete_credential(&token, id) {
        Err(e) if stale_token(&e) => {
            let token = auth.fresh_token(key, CREDENTIAL_MANAGEMENT, None)?;
            Ok(key.delete_credential(token, id)?)
        }
        r => Ok(r?),
    }
}

/// Delete the vault `target` (as [`list_credentials`] listed it): its data
/// first, then its credential. No touch: the largeBlobKey credential
/// management listed finds the data. Only a key that listed no
/// largeBlobKey for it needs one touch ([`VaultStep::UnlockTouch`]) to get
/// it from the credential itself.
///
/// Other entries in the largeBlob array are written back as they were. A
/// vault with no data skips the write. Should the credential delete fail,
/// the data is already gone and the credential is left as an empty vault.
pub fn delete(
    key: &mut impl VaultKey,
    auth: &mut VaultAuth,
    target: &VaultCredential,
    on_step: &mut dyn FnMut(VaultStep),
) -> Result<(), VaultKeyError> {
    let id = &target.vault.credential_id[..];
    let lbk = match &target.large_blob_key {
        Some(lbk) => lbk.clone(),
        None => {
            let asserted = auth.with_touch(
                key,
                GET_ASSERTION | LARGE_BLOB_WRITE,
                VaultStep::UnlockTouch,
                on_step,
                |k, token| k.assertions(token, Some(id)),
            )?;
            match asserted.into_iter().find(|a| a.credential_id == id) {
                Some(a) => a.large_blob_key.ok_or(VaultKeyError::NoLargeBlobKey)?,
                None => {
                    return Err(VaultKeyError::NotFound(
                        target.vault.name.clone().unwrap_or_default(),
                    ))
                }
            }
        }
    };
    delete_known(key, auth, id, &lbk)
}

/// Delete the vault whose credential is `id` and whose largeBlobKey is
/// `lbk`: remove its data from the array (no write when there is none),
/// then delete the credential. A rotate uses it for the old vault.
pub(crate) fn delete_known(
    key: &mut impl VaultKey,
    auth: &mut VaultAuth,
    id: &[u8],
    lbk: &[u8; 32],
) -> Result<(), VaultKeyError> {
    write_array(
        key,
        auth,
        &mut |array| {
            Ok(match array.credential_data(lbk) {
                CredentialData::Absent => None,
                CredentialData::Present(_) | CredentialData::Unreadable => {
                    Some(array.without_credential_blob(lbk))
                }
            })
        },
        // Removing data is not a step a front end reports.
        &mut |_| {},
    )?;
    delete_credential(key, auth, id)
}

#[cfg(test)]
mod tests {
    use super::super::fake::{Call, FakeKey};
    use super::*;
    use keyroost_ctap::client_pin::permissions::{
        CREDENTIAL_MANAGEMENT as CM, GET_ASSERTION as GA, LARGE_BLOB_WRITE as LBW,
        MAKE_CREDENTIAL as MC,
    };
    use keyroost_ctap::CtapError;
    use keyroost_vault::{user_handle, Entry, Vault, VaultError, RP_ID};
    use zeroize::Zeroizing;

    use super::super::{VaultAuth, VaultCredential, VaultKeyError, VaultRef, VaultStep};

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

    fn token(perms: u32, rp: Option<&str>) -> Call {
        Call::Token {
            perms,
            rp: rp.map(str::to_owned),
        }
    }

    /// `create` on `key`, returning the result and the steps reported.
    fn run_create(
        key: &mut FakeKey,
        auth: &mut VaultAuth,
        name: &str,
        initial: &Vault,
    ) -> (Result<OpenVault, VaultKeyError>, Vec<VaultStep>) {
        let mut steps = Vec::new();
        let r = create(key, auth, name, initial, &mut |s| steps.push(s));
        (r, steps)
    }

    fn listed(key: &mut FakeKey, auth: &mut VaultAuth) -> Vec<VaultCredential> {
        list_credentials(key, auth).unwrap_or_else(|e| panic!("{e}"))
    }

    /// `list_credentials`, then `delete` of the vault named `name`; the
    /// result and the steps reported.
    fn run_delete(
        key: &mut FakeKey,
        auth: &mut VaultAuth,
        name: &str,
    ) -> (Result<(), VaultKeyError>, Vec<VaultStep>) {
        let creds = listed(key, auth);
        let target = creds
            .iter()
            .find(|c| c.vault.name.as_deref() == Some(name))
            .expect("the test's vault is listed");
        let mut steps = Vec::new();
        let r = delete(key, auth, target, &mut |s| steps.push(s));
        (r, steps)
    }

    /// The cause and `left_over` of a `CreateUndone`.
    fn undone(r: Result<OpenVault, VaultKeyError>) -> (VaultKeyError, bool) {
        match r {
            Err(VaultKeyError::CreateUndone { cause, left_over }) => (*cause, left_over),
            other => panic!("expected CreateUndone, got {other:?}"),
        }
    }

    /// A vault whose sealed size is roughly `chars` bytes: random hex notes
    /// that compression can't shrink much.
    fn big_vault(chars: usize) -> Vault {
        let mut notes = String::new();
        while notes.len() < chars {
            notes.push_str(&keyroost_vault::new_id());
        }
        let mut e = entry("Big");
        e.notes = notes;
        Vault { entries: vec![e] }
    }

    // ----- create -----

    #[test]
    fn create_makes_and_fills_a_vault() {
        let mut key = FakeKey::new();
        key.add_foreign_entries();
        let initial = Vault {
            entries: vec![entry("GitHub")],
        };
        let mut auth = pin();
        let (r, steps) = run_create(&mut key, &mut auth, "Personal", &initial);
        let open = r.unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            steps,
            vec![
                VaultStep::CreateTouch,
                VaultStep::UnlockTouch,
                VaultStep::Write
            ]
        );

        assert_eq!(key.creds.len(), 1);
        let cred = key.creds[0].clone();
        // makeCredential's user id: 0x01, 8 random bytes, the name.
        assert_eq!(cred.user_id[0], 0x01);
        assert_eq!(cred.user_id.len(), 1 + 8 + "Personal".len());
        assert_eq!(&cred.user_id[9..], b"Personal");

        assert_eq!(
            open.vault_ref,
            VaultRef {
                credential_id: cred.id.clone(),
                name: Some("Personal".into()),
            }
        );
        assert_eq!(open.contents, initial);
        assert!(open.stored);
        assert_eq!(open.secrets(), (&cred.hmac, &cred.lbk.unwrap()));
        assert_eq!(key.vault_on_key(&cred.id), Some(initial));
        assert_eq!(key.array().len(), 4, "three foreign entries and the vault");

        assert_eq!(
            key.log,
            vec![
                token(CM | LBW, None),
                Call::Credentials,
                Call::Read,
                token(MC, Some(RP_ID)),
                Call::MakeCredential,
                token(GA | LBW, Some(RP_ID)),
                Call::Assertions(Some(cred.id.clone())),
                Call::Read,
                Call::Write,
            ]
        );
        // After the touches the key keeps only the write permission, and so
        // does the auth.
        assert!(auth.current_for(GA).is_none());
        assert!(auth.current_for(LBW).is_some());
    }

    #[test]
    fn an_empty_vault_is_stored_too() {
        let mut key = FakeKey::new();
        let (r, _) = run_create(&mut key, &mut pin(), "Work", &Vault::default());
        let open = r.unwrap_or_else(|e| panic!("{e}"));
        assert!(open.stored);
        assert_eq!(
            key.vault_on_key(&open.vault_ref.credential_id),
            Some(Vault::default())
        );
    }

    #[test]
    fn missing_large_blob_key_deletes_the_new_credential() {
        let mut key = FakeKey::new();
        key.mc_without_lbk = true;
        let before = key.stored().to_vec();
        let (r, steps) = run_create(&mut key, &mut pin(), "Personal", &Vault::default());
        let (cause, left_over) = undone(r);
        assert!(matches!(cause, VaultKeyError::NoLargeBlobKey), "{cause:?}");
        assert!(!left_over);
        assert!(key.creds.is_empty(), "no credential left");
        assert_eq!(steps, vec![VaultStep::CreateTouch]);
        assert_eq!(key.stored(), &before[..]);

        assert!(!key.log.iter().any(|c| matches!(c, Call::Assertions(_))));
        let made = key
            .log
            .iter()
            .position(|c| *c == Call::MakeCredential)
            .unwrap();
        assert_eq!(
            key.log[made - 1..made + 2].to_vec(),
            vec![
                token(MC, Some(RP_ID)),
                Call::MakeCredential,
                token(CM, None)
            ]
        );
        assert!(matches!(key.log[made + 2..], [Call::Delete(_)]));
    }

    #[test]
    fn failed_write_deletes_the_new_credential() {
        let mut key = FakeKey::new();
        key.add_foreign_entries();
        let before = key.stored().to_vec();
        key.write_refusals.extend([0x33, 0x33]);
        let initial = Vault {
            entries: vec![entry("GitHub")],
        };
        let (r, steps) = run_create(&mut key, &mut pin(), "Personal", &initial);
        let (cause, left_over) = undone(r);
        assert!(
            matches!(cause, VaultKeyError::Ctap(CtapError::StatusCode(0x33))),
            "{cause:?}"
        );
        assert!(!left_over);
        assert_eq!(key.stored(), &before[..], "array unchanged");
        assert!(key.creds.is_empty(), "credential gone");
        assert_eq!(
            steps,
            vec![
                VaultStep::CreateTouch,
                VaultStep::UnlockTouch,
                VaultStep::Write,
                VaultStep::Write
            ]
        );
        assert!(matches!(key.log.last(), Some(Call::Delete(_))));
    }

    #[test]
    fn failed_cleanup_reports_the_left_over_credential() {
        // Missing largeBlobKey, then a delete the key refuses.
        let mut key = FakeKey::new();
        key.mc_without_lbk = true;
        key.delete_fails = true;
        let (r, _) = run_create(&mut key, &mut pin(), "Personal", &Vault::default());
        let (cause, left_over) = undone(r);
        assert!(matches!(cause, VaultKeyError::NoLargeBlobKey), "{cause:?}");
        assert!(left_over);
        assert_eq!(key.creds.len(), 1, "the credential is left on the key");
        assert_eq!(
            key.log
                .iter()
                .filter(|c| matches!(c, Call::Delete(_)))
                .count(),
            1,
            "a refusal that isn't a stale token is not retried"
        );

        // A failed write, then the same refused delete.
        let mut key = FakeKey::new();
        key.write_refusals.extend([0x33, 0x33]);
        key.delete_fails = true;
        let (r, _) = run_create(&mut key, &mut pin(), "Personal", &Vault::default());
        let (_, left_over) = undone(r);
        assert!(left_over);
        assert_eq!(key.creds.len(), 1);
    }

    #[test]
    fn cleanup_retries_once_on_a_stale_token() {
        let mut key = FakeKey::new();
        key.mc_without_lbk = true;
        key.delete_refusals.extend([0x38]);
        let (r, _) = run_create(&mut key, &mut pin(), "Personal", &Vault::default());
        let (_, left_over) = undone(r);
        assert!(!left_over);
        assert!(key.creds.is_empty());
        let n = key.log.len();
        assert_eq!(key.log[n - 2], token(CM, None));
        assert!(matches!(key.log[n - 3], Call::Delete(_)));
    }

    #[test]
    fn duplicate_name_is_refused_before_the_touch() {
        let mut key = FakeKey::new();
        key.add_vault("Personal", &Vault::default());
        let (r, steps) = run_create(&mut key, &mut pin(), "Personal", &Vault::default());
        assert!(
            matches!(&r, Err(VaultKeyError::DuplicateName(n)) if n == "Personal"),
            "{r:?}"
        );
        assert!(steps.is_empty());
        assert!(!key.log.contains(&Call::MakeCredential));
        assert_eq!(key.creds.len(), 1);
    }

    #[test]
    fn too_long_name_is_refused_before_anything() {
        for name in ["é".repeat(17), String::new()] {
            let mut key = FakeKey::new();
            let (r, steps) = run_create(&mut key, &mut pin(), &name, &Vault::default());
            assert!(
                matches!(r, Err(VaultKeyError::Vault(VaultError::NameLength))),
                "{name:?}: {r:?}"
            );
            assert!(steps.is_empty());
            assert!(key.log.is_empty(), "{:?}", key.log);
        }
    }

    #[test]
    fn create_refuses_what_cannot_fit_before_the_touch() {
        let mut key = FakeKey::new();
        key.set_max_bytes(1024);
        let (r, steps) = run_create(&mut key, &mut pin(), "Personal", &big_vault(4000));
        match r {
            Err(VaultKeyError::Full { needed, max }) => {
                assert_eq!(max, 1024);
                assert!(needed > max, "{needed}");
            }
            other => panic!("expected Full, got {other:?}"),
        }
        assert!(steps.is_empty());
        assert_eq!(
            key.log,
            vec![token(CM | LBW, None), Call::Credentials, Call::Read]
        );
        assert!(key.creds.is_empty());
    }

    // ----- list_credentials -----

    #[test]
    fn list_credentials_reports_stored_sizes() {
        let mut key = FakeKey::new();
        key.add_foreign_entries();
        let p = key.add_vault(
            "Personal",
            &Vault {
                entries: vec![entry("GitHub"), entry("Mail")],
            },
        );
        let e = key.add_credential(user_handle("Empty").unwrap(), Some("Empty"));

        let creds = listed(&mut key, &mut pin());
        assert_eq!(creds.len(), 2);
        assert_eq!(creds[0].vault.credential_id, p);
        assert_eq!(creds[0].vault.name.as_deref(), Some("Personal"));
        let lbk = key.creds[0].lbk.unwrap();
        let sealed = key.array().credential_blob(&lbk).unwrap().len();
        assert_eq!(creds[0].stored_bytes, Some(sealed));
        assert_eq!(creds[1].vault.credential_id, e);
        assert_eq!(creds[1].stored_bytes, None);
        assert_eq!(
            key.log,
            vec![token(CM | LBW, None), Call::Credentials, Call::Read]
        );

        // Without a largeBlobKey the data can't be found: no size.
        key.credmgmt_without_lbk = true;
        let creds = listed(&mut key, &mut pin());
        assert!(creds.iter().all(|c| c.stored_bytes.is_none()));
    }

    // ----- delete -----

    #[test]
    fn delete_removes_data_then_credential_with_one_token() {
        let mut key = FakeKey::new();
        key.add_foreign_entries();
        let work = Vault {
            entries: vec![entry("Jira")],
        };
        let w = key.add_vault("Work", &work);
        let kept = key.stored().to_vec();
        let p = key.add_vault(
            "Personal",
            &Vault {
                entries: vec![entry("GitHub")],
            },
        );

        let mut auth = pin();
        let (r, steps) = run_delete(&mut key, &mut auth, "Personal");
        r.unwrap_or_else(|e| panic!("{e}"));
        assert!(steps.is_empty(), "no touch, nothing to tell: {steps:?}");
        assert_eq!(
            key.log,
            vec![
                token(CM | LBW, None),
                Call::Credentials,
                Call::Read,
                Call::Read,
                Call::Write,
                Call::Delete(p),
            ]
        );
        assert_eq!(key.write_perms, vec![CM | LBW]);
        assert_eq!(key.stored(), &kept[..], "every other entry byte for byte");
        assert_eq!(key.creds.len(), 1);
        assert_eq!(key.vault_on_key(&w), Some(work));
    }

    #[test]
    fn delete_removes_data_that_does_not_open() {
        let mut key = FakeKey::new();
        let id = key.add_credential(user_handle("Odd").unwrap(), Some("Odd"));
        key.put_blob(&id, b"not a vault");
        let (r, _) = run_delete(&mut key, &mut pin(), "Odd");
        r.unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(key.array().len(), 0);
        assert!(key.creds.is_empty());
    }

    #[test]
    fn delete_without_a_credmgmt_key_unlocks_for_it() {
        let mut key = FakeKey::new();
        key.credmgmt_without_lbk = true;
        let p = key.add_vault(
            "Personal",
            &Vault {
                entries: vec![entry("GitHub")],
            },
        );
        let (r, steps) = run_delete(&mut key, &mut pin(), "Personal");
        r.unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(steps, vec![VaultStep::UnlockTouch]);
        assert_eq!(
            key.log,
            vec![
                token(CM | LBW, None),
                Call::Credentials,
                Call::Read,
                token(GA | LBW, Some(RP_ID)),
                Call::Assertions(Some(p.clone())),
                Call::Read,
                Call::Write,
                token(CM, None),
                Call::Delete(p),
            ]
        );
        assert_eq!(key.array().len(), 0);
        assert!(key.creds.is_empty());
    }

    #[test]
    fn delete_retries_once_on_a_stale_token() {
        for code in [0x33, 0x38] {
            let mut key = FakeKey::new();
            let p = key.add_vault("Personal", &Vault::default());
            key.delete_refusals.extend([code]);
            let (r, _) = run_delete(&mut key, &mut pin(), "Personal");
            r.unwrap_or_else(|e| panic!("{code:#x}: {e}"));
            assert_eq!(
                key.log,
                vec![
                    token(CM | LBW, None),
                    Call::Credentials,
                    Call::Read,
                    Call::Read,
                    Call::Write,
                    Call::Delete(p.clone()),
                    token(CM, None),
                    Call::Delete(p),
                ],
                "{code:#x}"
            );
            assert!(key.creds.is_empty());
        }

        // A second refusal is an error; the data is already gone.
        let mut key = FakeKey::new();
        key.add_vault("Personal", &Vault::default());
        key.delete_refusals.extend([0x33, 0x33]);
        let (r, _) = run_delete(&mut key, &mut pin(), "Personal");
        assert!(
            matches!(r, Err(VaultKeyError::Ctap(CtapError::StatusCode(0x33)))),
            "{r:?}"
        );
        assert_eq!(
            key.log
                .iter()
                .filter(|c| matches!(c, Call::Delete(_)))
                .count(),
            2
        );
        assert_eq!(key.array().len(), 0);
        assert_eq!(key.creds.len(), 1);
    }

    #[test]
    fn delete_of_a_vault_without_data_skips_the_write() {
        let mut key = FakeKey::new();
        key.add_foreign_entries();
        let e = key.add_credential(user_handle("Empty").unwrap(), Some("Empty"));
        let before = key.stored().to_vec();
        let (r, steps) = run_delete(&mut key, &mut pin(), "Empty");
        r.unwrap_or_else(|e| panic!("{e}"));
        assert!(steps.is_empty());
        assert_eq!(
            key.log,
            vec![
                token(CM | LBW, None),
                Call::Credentials,
                Call::Read,
                Call::Read,
                Call::Delete(e),
            ]
        );
        assert_eq!(key.stored(), &before[..]);
        assert!(key.creds.is_empty());
    }
}
