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
//!
//! Rotating a vault's key (after unlocking it somewhere untrusted) makes a
//! new vault of the same name, copies what the old one holds, reads the
//! copy back, and only then deletes the old vault, data first: anyone who
//! learned the old vault's secret can read the largeBlob store without a
//! PIN, so its data must not outlive its credential.

use keyroost_ctap::client_pin::permissions::{
    CREDENTIAL_MANAGEMENT, GET_ASSERTION, LARGE_BLOB_WRITE, MAKE_CREDENTIAL,
};
use keyroost_ctap::large_blobs::{BlobCapacity, CredentialData, LargeBlobArray};
use keyroost_ctap::{AuthenticatorInfo, CtapError};
use keyroost_vault::{seal, unnamed_user_handle, user_handle, Vault};
use zeroize::Zeroizing;

use super::ops::{check_fits, stale_token, vault_state, write_array, OpenVault};
use super::{
    check_support, LeftOver, OldVault, StoredData, VaultAuth, VaultCredential, VaultKey,
    VaultKeyError, VaultProblem, VaultRef, VaultStep,
};
use crate::ct_eq;

/// The vault credentials, with how much data each holds, and the array
/// that was read for it.
fn credentials_and_array(
    key: &mut impl VaultKey,
    auth: &mut VaultAuth,
) -> Result<(Vec<VaultCredential>, LargeBlobArray), VaultKeyError> {
    check_support(key.info())?;
    // largeBlobWrite too, so a delete that follows needs no second token. A
    // fingerprint reuses the token it holds when that still allows both.
    let mut creds = auth.with_listing(key, CREDENTIAL_MANAGEMENT | LARGE_BLOB_WRITE, |k, t| {
        k.credentials(t)
    })?;
    let array = key.read_blobs()?;
    for c in &mut creds {
        c.stored = match &c.large_blob_key {
            None => StoredData::Unknown,
            Some(lbk) => match array.credential_data(lbk) {
                CredentialData::Absent => StoredData::Empty,
                CredentialData::Present(data) => StoredData::Bytes(data.len()),
                CredentialData::Unreadable => StoredData::Unreadable,
            },
        };
    }
    Ok((creds, array))
}

/// The vault credentials on the key, through credential management: no
/// touch. Each carries what the key holds for it ([`StoredData`], from one
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

/// A vault [`create`] or [`rotate`] made, open, and how full the
/// largeBlob store is after their writes.
#[derive(Debug)]
pub struct Created {
    pub open: OpenVault,
    pub capacity: BlobCapacity,
}

/// Create a vault named `name` holding `initial`, and return it open with
/// how full the largeBlob store is now.
///
/// Refused before anything is sent: a name that is empty or longer than
/// [`keyroost_vault::MAX_NAME_BYTES`]. Refused before any touch: a name a
/// vault on the key already has ([`VaultKeyError::DuplicateName`]), and a
/// vault the largeBlob store has no room for ([`VaultKeyError::Full`]).
/// Then two touches ([`VaultStep::CreateTouch`], [`VaultStep::UnlockTouch`])
/// and a [`VaultStep::Write`]. When anything fails after the credential was
/// made, the credential and any data written for it are removed again and
/// the error is [`VaultKeyError::CreateUndone`] with the cause; its
/// `left_over` names whatever could not be removed.
pub fn create(
    key: &mut impl VaultKey,
    auth: &mut VaultAuth,
    name: &str,
    initial: &Vault,
    on_step: &mut dyn FnMut(VaultStep),
) -> Result<Created, VaultKeyError> {
    user_handle(name)?;
    let (existing, array) = credentials_and_array(key, auth)?;
    if existing
        .iter()
        .any(|c| c.vault.name.as_deref() == Some(name))
    {
        return Err(VaultKeyError::DuplicateName(name.to_owned()));
    }
    check_room(&array, initial, key.info())?;
    create_unchecked(key, auth, Some(name), initial, on_step)
}

/// [`VaultKeyError::Full`] when `array` has no room for one more vault
/// holding `initial`. Sealing under a stand-in secret and key gives the
/// same length as the real ones; the write checks again.
fn check_room(
    array: &LargeBlobArray,
    initial: &Vault,
    info: &AuthenticatorInfo,
) -> Result<(), VaultKeyError> {
    let stand_in = [0u8; 32];
    let blob = seal(initial, &stand_in)?;
    check_fits(&array.with_credential_blob(&stand_in, &blob)?, info)
}

/// [`create`] without the name and size checks: make the credential, unlock
/// it, seal `initial` and write it, removing the credential (and any data
/// written for it) again on any failure. A rotate uses it to make a vault of
/// the same name, or one with no name (`None`) for a vault that had none.
pub(crate) fn create_unchecked(
    key: &mut impl VaultKey,
    auth: &mut VaultAuth,
    name: Option<&str>,
    initial: &Vault,
    on_step: &mut dyn FnMut(VaultStep),
) -> Result<Created, VaultKeyError> {
    let user_id = match name {
        Some(name) => user_handle(name)?,
        None => unnamed_user_handle()?,
    };
    let made = auth.with_touch(
        key,
        MAKE_CREDENTIAL,
        VaultStep::CreateTouch,
        on_step,
        |k, token| k.make_credential(token, &user_id, name.unwrap_or_default()),
    )?;
    let id = made.credential_id;
    let Some(lbk) = made.large_blob_key else {
        return Err(undo(key, auth, &id, None, VaultKeyError::NoLargeBlobKey));
    };
    let sealed = unlock_new(key, auth, &id, &lbk, on_step)
        .and_then(|hmac| Ok((seal(initial, &hmac)?, hmac)));
    let (blob, hmac) = match sealed {
        Ok(sealed) => sealed,
        Err(cause) => return Err(undo(key, auth, &id, None, cause)),
    };
    let written = match write_array(
        key,
        auth,
        &mut |array| Ok(Some(array.with_credential_blob(&lbk, &blob)?)),
        on_step,
    ) {
        Ok(array) => array,
        // The write may have landed even though it failed (a lost reply),
        // so the data is looked for too.
        Err(cause) => return Err(undo(key, auth, &id, Some(&lbk), cause)),
    };
    Ok(Created {
        open: OpenVault::new(
            VaultRef {
                credential_id: id,
                name: name.map(str::to_owned),
            },
            initial.clone(),
            true,
            hmac,
            lbk,
        ),
        capacity: written.capacity(key.info()),
    })
}

/// Unlock the new credential `id` and check it is the one just made (its
/// largeBlobKey `lbk` from makeCredential); its hmac-secret output.
fn unlock_new(
    key: &mut impl VaultKey,
    auth: &mut VaultAuth,
    id: &[u8],
    lbk: &[u8; 32],
    on_step: &mut dyn FnMut(VaultStep),
) -> Result<Zeroizing<[u8; 32]>, VaultKeyError> {
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
    Ok(hmac)
}

/// Clean up after a create that failed with `cause` once credential `id`
/// was made: remove its data when the write stage was reached (`written`,
/// the largeBlobKey), then delete the credential, attempted whatever the
/// data removal did. `left_over` names what is still on the key.
fn undo(
    key: &mut impl VaultKey,
    auth: &mut VaultAuth,
    id: &[u8],
    written: Option<&[u8; 32]>,
    cause: VaultKeyError,
) -> VaultKeyError {
    let data_left = written.is_some_and(|lbk| remove_data(key, auth, lbk).is_err());
    let credential_left = delete_credential(key, auth, id).is_err();
    VaultKeyError::CreateUndone {
        cause: Box::new(cause),
        left_over: LeftOver {
            credential: credential_left,
            data: data_left,
        },
    }
}

/// Remove the data sealed under `lbk` from the largeBlob array: one read,
/// and a write only when there is some (damaged data included).
fn remove_data(
    key: &mut impl VaultKey,
    auth: &mut VaultAuth,
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
    )
    .map(drop)
}

/// Delete credential `id` with the current token when it allows credential
/// management, else a fresh one; once more with a renewed token when the
/// key dropped it or let it expire.
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
            let token = auth.renewed_token(key, CREDENTIAL_MANAGEMENT, None)?;
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
    remove_data(key, auth, lbk)?;
    delete_credential(key, auth, id)
}

/// Give the vault `old` a new key: make a new vault of the same name,
/// copy into it what `old` holds on the key now, read both back, and only
/// then delete `old`. Returns the new vault, open, under the old one's name
/// (an unnamed vault stays unnamed), with how full the largeBlob store is
/// once the old vault's data is gone.
///
/// What is copied is read from the key first, so an entry another writer
/// saved since unlock comes along. Refused before any touch: data that no
/// longer opens ([`VaultKeyError::CannotOpen`]), data that was there at
/// unlock and is gone ([`VaultKeyError::VaultGone`]: the vault was deleted
/// or rotated elsewhere), and a store with no room for a second copy
/// ([`VaultKeyError::Full`]). Then the two touches and the write of a
/// create ([`VaultStep::CreateTouch`], [`VaultStep::UnlockTouch`],
/// [`VaultStep::Write`]); a create that fails is undone as [`create`]
/// undoes it.
///
/// One read then checks both: the new vault must open to exactly what was
/// copied ([`VaultKeyError::RotateNotVerified`]) and the old one must
/// still hold it ([`VaultKeyError::ChangedDuringRotate`]); otherwise the new
/// vault is removed again ([`VaultKeyError::CreateUndone`] with that
/// cause) and the old one is left as it is. The old vault's data is removed
/// in the write that follows that same read, so nothing it checked can
/// change before the data goes (a retry with a fresh token checks again).
/// Then the old credential is deleted. When removing the old vault fails,
/// the new one stays and the error is [`VaultKeyError::OldNotDeleted`],
/// saying what is left of the old one ([`OldVault`]).
pub fn rotate(
    key: &mut impl VaultKey,
    auth: &mut VaultAuth,
    old: &OpenVault,
    on_step: &mut dyn FnMut(VaultStep),
) -> Result<Created, VaultKeyError> {
    let (old_hmac, old_lbk) = old.secrets();
    let array = key.read_blobs()?;
    let (now, stored) =
        vault_state(array.credential_data(old_lbk), old_hmac).map_err(VaultKeyError::CannotOpen)?;
    if old.stored && !stored {
        return Err(VaultKeyError::VaultGone {
            name: old.vault_ref.name.clone(),
        });
    }
    check_room(&array, &now, key.info())?;

    // The new vault takes the old one's name; one with no name stays
    // unnamed rather than get a made-up one.
    let Created { open: new, .. } =
        create_unchecked(key, auth, old.vault_ref.name.as_deref(), &now, on_step)?;
    let new_id = &new.vault_ref.credential_id[..];
    let (new_hmac, new_lbk) = new.secrets();

    // The check and the old data's removal share one read. `checked`: the
    // copy passed the check at least once; `sent`: a write went out.
    let mut checked = false;
    let mut sent = false;
    let removed = write_array(
        key,
        auth,
        &mut |array| {
            match vault_state(array.credential_data(new_lbk), new_hmac) {
                Ok((copy, true)) if copy == now => {}
                _ => return Err(VaultKeyError::RotateNotVerified),
            }
            let old_data = array.credential_data(old_lbk);
            let has_data = !matches!(old_data, CredentialData::Absent);
            match vault_state(old_data, old_hmac) {
                Ok((still, s)) if still == now && s == stored => {}
                _ => return Err(VaultKeyError::ChangedDuringRotate),
            }
            checked = true;
            Ok(has_data.then(|| array.without_credential_blob(old_lbk)))
        },
        // Removing data is not a step a front end reports; this only notes
        // that a write went out.
        &mut |_| sent = true,
    );
    let not_deleted = |cause, old| VaultKeyError::OldNotDeleted {
        name: new.vault_ref.name.clone(),
        cause: Box::new(cause),
        old,
    };
    let after = match removed {
        Ok(array) => array,
        Err(cause) if !checked || is_rotate_check(&cause) => {
            return Err(undo(key, auth, new_id, Some(new_lbk), cause));
        }
        Err(cause) => {
            // A refusal stores nothing, nor does a failure before any write
            // went out; anything else may have landed.
            let refused = matches!(cause, VaultKeyError::Ctap(CtapError::StatusCode(_)));
            let left = if refused || !sent {
                OldVault::Kept
            } else {
                OldVault::Unknown
            };
            return Err(not_deleted(cause, left));
        }
    };
    if let Err(cause) = delete_credential(key, auth, &old.vault_ref.credential_id) {
        // With no data to remove, both are the same empty vault.
        let left = if stored {
            OldVault::Emptied
        } else {
            OldVault::Kept
        };
        return Err(not_deleted(cause, left));
    }
    Ok(Created {
        capacity: after.capacity(key.info()),
        open: new,
    })
}

/// Whether `e` is one of rotate's own checks failing.
fn is_rotate_check(e: &VaultKeyError) -> bool {
    matches!(
        e,
        VaultKeyError::RotateNotVerified | VaultKeyError::ChangedDuringRotate
    )
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

    use super::super::{
        unlock, OldVault, VaultAuth, VaultCredential, VaultKeyError, VaultRef, VaultStep,
    };

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
    ) -> (Result<Created, VaultKeyError>, Vec<VaultStep>) {
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
    fn undone(r: Result<Created, VaultKeyError>) -> (VaultKeyError, LeftOver) {
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
        let made = r.unwrap_or_else(|e| panic!("{e}"));
        // How full the store is after the write, as the key now holds it.
        assert_eq!(made.capacity, key.array().capacity(&key.info));
        assert_eq!(made.capacity.entry_count, 4, "three foreign, the vault");
        let open = made.open;
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
        let open = r.unwrap_or_else(|e| panic!("{e}")).open;
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
        assert_eq!(left_over, LeftOver::NONE);
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
        assert_eq!(left_over, LeftOver::NONE);
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
    fn a_write_whose_reply_is_lost_is_undone() {
        // The write lands, but its reply does not arrive: the undo finds
        // the data and removes it, then deletes the credential.
        let mut key = FakeKey::new();
        key.add_foreign_entries();
        let before = key.stored().to_vec();
        key.lost_write_replies = 1;
        let (r, steps) = run_create(&mut key, &mut pin(), "Personal", &Vault::default());
        let (cause, left_over) = undone(r);
        assert!(
            matches!(cause, VaultKeyError::Ctap(CtapError::Transport(_))),
            "{cause:?}"
        );
        assert_eq!(left_over, LeftOver::NONE);
        assert_eq!(key.stored(), &before[..], "the blob is removed");
        assert!(key.creds.is_empty(), "the credential is removed");
        assert_eq!(
            steps,
            vec![
                VaultStep::CreateTouch,
                VaultStep::UnlockTouch,
                VaultStep::Write
            ],
            "removing the data reports no step"
        );
        let n = key.log.len();
        assert_eq!(
            key.log[n - 6..n - 1].to_vec(),
            vec![
                Call::Read,
                Call::Write,
                Call::Read,
                Call::Write,
                token(CM, None)
            ]
        );
        assert!(matches!(key.log[n - 1], Call::Delete(_)));
    }

    #[test]
    fn failed_data_removal_still_deletes_the_credential() {
        let mut key = FakeKey::new();
        key.lost_write_replies = 1;
        // The undo's read is the third (listing, create's write, undo):
        // refuse the write that follows it.
        key.hook = Some((
            3,
            Box::new(|k: &mut FakeKey| k.write_refusals.push_back(0x30)),
        ));
        let (r, _) = run_create(&mut key, &mut pin(), "Personal", &Vault::default());
        let (_, left_over) = undone(r);
        assert_eq!(
            left_over,
            LeftOver {
                credential: false,
                data: true
            },
            "only the data is left"
        );
        assert!(key.creds.is_empty(), "the credential delete still ran");
        assert!(matches!(key.log.last(), Some(Call::Delete(_))));
        // No vault lists any more; the data is one entry in the store.
        assert!(listed(&mut key, &mut pin()).is_empty());
        assert_eq!(key.array().len(), 1);
    }

    #[test]
    fn failed_cleanup_of_both_reports_both_and_a_vault_delete_clears_them() {
        // The write lands with its reply lost, removing the data is refused,
        // and so is the credential delete.
        let mut key = FakeKey::new();
        key.lost_write_replies = 1;
        key.delete_fails = true;
        key.hook = Some((
            3,
            Box::new(|k: &mut FakeKey| k.write_refusals.push_back(0x30)),
        ));
        let (r, _) = run_create(&mut key, &mut pin(), "Personal", &Vault::default());
        let (_, left_over) = undone(r);
        assert_eq!(
            left_over,
            LeftOver {
                credential: true,
                data: true
            }
        );
        assert_eq!(key.creds.len(), 1);
        assert_eq!(key.array().len(), 1);

        // The fix the error points to: the vault lists with its data, and
        // deleting it removes both.
        key.delete_fails = false;
        let creds = listed(&mut key, &mut pin());
        assert_eq!(creds.len(), 1);
        assert!(matches!(creds[0].stored, StoredData::Bytes(_)));
        let (r, _) = run_delete(&mut key, &mut pin(), "Personal");
        r.unwrap_or_else(|e| panic!("{e}"));
        assert!(key.creds.is_empty());
        assert_eq!(key.array().len(), 0);
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
        assert_eq!(
            left_over,
            LeftOver {
                credential: true,
                data: false
            }
        );
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
        assert_eq!(
            left_over,
            LeftOver {
                credential: true,
                data: false
            },
            "the refused writes stored nothing"
        );
        assert_eq!(key.creds.len(), 1);
    }

    #[test]
    fn cleanup_retries_once_on_a_stale_token() {
        let mut key = FakeKey::new();
        key.mc_without_lbk = true;
        key.delete_refusals.extend([0x38]);
        let (r, _) = run_create(&mut key, &mut pin(), "Personal", &Vault::default());
        let (_, left_over) = undone(r);
        assert_eq!(left_over, LeftOver::NONE);
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
    fn list_credentials_reports_what_each_vault_stores() {
        let mut key = FakeKey::new();
        key.add_foreign_entries();
        let p = key.add_vault(
            "Personal",
            &Vault {
                entries: vec![entry("GitHub"), entry("Mail")],
            },
        );
        let e = key.add_credential(user_handle("Empty").unwrap(), Some("Empty"));
        let d = key.add_credential(user_handle("Damaged").unwrap(), Some("Damaged"));
        key.put_unreadable(&d);

        let creds = listed(&mut key, &mut pin());
        assert_eq!(creds.len(), 3);
        assert_eq!(creds[0].vault.credential_id, p);
        assert_eq!(creds[0].vault.name.as_deref(), Some("Personal"));
        let lbk = key.creds[0].lbk.unwrap();
        let sealed = key.array().credential_blob(&lbk).unwrap().len();
        assert_eq!(creds[0].stored, StoredData::Bytes(sealed));
        assert_eq!(creds[1].vault.credential_id, e);
        assert_eq!(creds[1].stored, StoredData::Empty);
        // Damaged data is never reported as no data.
        assert_eq!(creds[2].vault.credential_id, d);
        assert_eq!(creds[2].stored, StoredData::Unreadable);
        assert_eq!(
            key.log,
            vec![token(CM | LBW, None), Call::Credentials, Call::Read]
        );

        // Without a largeBlobKey the data can't be looked for.
        key.credmgmt_without_lbk = true;
        let creds = listed(&mut key, &mut pin());
        assert!(creds.iter().all(|c| c.stored == StoredData::Unknown));
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
    fn delete_removes_unreadable_data() {
        let mut key = FakeKey::new();
        key.add_foreign_entries();
        let kept = key.stored().to_vec();
        let id = key.add_credential(user_handle("Damaged").unwrap(), Some("Damaged"));
        key.put_unreadable(&id);
        let (r, _) = run_delete(&mut key, &mut pin(), "Damaged");
        r.unwrap_or_else(|e| panic!("{e}"));
        assert!(
            key.log.contains(&Call::Write),
            "the damaged entry is removed"
        );
        assert_eq!(key.stored(), &kept[..]);
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
    fn a_fingerprint_delete_asks_again_on_a_stale_token() {
        use super::super::fake::asks;
        use keyroost_ctap::client_pin::FingerAsk;
        let mut key = FakeKey::with_fingerprint();
        let p = key.add_vault("Personal", &Vault::default());
        key.delete_refusals.extend([0x33]);
        let (asked, ask) = asks();
        let (r, _) = run_delete(&mut key, &mut VaultAuth::fingerprint(ask), "Personal");
        r.unwrap_or_else(|e| panic!("{e}"));
        let finger = Call::UvToken {
            perms: CM | GA | MC | LBW,
            rp: Some(RP_ID.into()),
        };
        assert_eq!(
            key.log,
            vec![
                finger.clone(),
                Call::Credentials,
                Call::Read,
                Call::Read,
                Call::Write,
                Call::Delete(p.clone()),
                finger,
                Call::Delete(p),
            ]
        );
        assert_eq!(
            *asked.lock().unwrap(),
            [FingerAsk::Unlock, FingerAsk::Again]
        );
        assert!(key.creds.is_empty());
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

    // ----- rotate -----

    /// Unlock `key` and return the vault named `name`, open.
    fn opened(key: &mut FakeKey, auth: &mut VaultAuth, name: &str) -> OpenVault {
        let unlocked = unlock(key, auth, &mut |_| {}).unwrap_or_else(|e| panic!("{e}"));
        unlocked
            .vaults
            .into_iter()
            .find(|v| v.vault_ref.name.as_deref() == Some(name))
            .expect("the test's vault is on the key")
            .state
            .unwrap_or_else(|p| panic!("{p}"))
    }

    /// `rotate` of `old`, returning the result and the steps reported.
    fn run_rotate(
        key: &mut FakeKey,
        auth: &mut VaultAuth,
        old: &OpenVault,
    ) -> (Result<Created, VaultKeyError>, Vec<VaultStep>) {
        let mut steps = Vec::new();
        let r = rotate(key, auth, old, &mut |s| steps.push(s));
        (r, steps)
    }

    /// The IDs of the credentials named `name`.
    fn ids_named(key: &FakeKey, name: &str) -> Vec<Vec<u8>> {
        key.creds
            .iter()
            .filter(|c| c.user_name.as_deref() == Some(name))
            .map(|c| c.id.clone())
            .collect()
    }

    fn lbk_of(key: &FakeKey, id: &[u8]) -> [u8; 32] {
        key.creds
            .iter()
            .find(|c| c.id == id)
            .and_then(|c| c.lbk)
            .expect("a credential with a largeBlobKey")
    }

    fn two_entries() -> Vault {
        Vault {
            entries: vec![entry("GitHub"), entry("Mail")],
        }
    }

    /// A key with foreign entries, a Work vault and a Personal vault holding
    /// `two_entries()`; the Personal vault unlocked, and the log cleared.
    struct Rotating {
        key: FakeKey,
        auth: VaultAuth,
        old: OpenVault,
        old_id: Vec<u8>,
        contents: Vault,
    }

    fn rotating() -> Rotating {
        let mut key = FakeKey::new();
        key.add_foreign_entries();
        key.add_vault(
            "Work",
            &Vault {
                entries: vec![entry("Jira")],
            },
        );
        let contents = two_entries();
        let old_id = key.add_vault("Personal", &contents);
        let mut auth = pin();
        let old = opened(&mut key, &mut auth, "Personal");
        key.log.clear();
        Rotating {
            key,
            auth,
            old,
            old_id,
            contents,
        }
    }

    #[test]
    fn rotate_keeps_an_unnamed_vault_unnamed() {
        let mut key = FakeKey::new();
        // A vault credential whose handle carries no name, and no user
        // name: it lists as unnamed.
        let old_id = key.add_credential(vec![0x07; 12], None);
        let contents = two_entries();
        key.put_vault(&old_id, &contents);
        let mut auth = pin();
        let unlocked = unlock(&mut key, &mut auth, &mut |_| {}).unwrap_or_else(|e| panic!("{e}"));
        let old = unlocked
            .vaults
            .into_iter()
            .next()
            .expect("the vault")
            .state
            .unwrap_or_else(|p| panic!("{p}"));
        assert_eq!(old.vault_ref.name, None);

        let (r, _) = run_rotate(&mut key, &mut auth, &old);
        let new = r.unwrap_or_else(|e| panic!("{e}")).open;
        // No name made up for it: it stays unnamed, open and as listed.
        assert_eq!(new.vault_ref.name, None);
        assert_eq!(new.contents, contents);
        let listed = list_credentials(&mut key, &mut auth).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].vault.credential_id, new.vault_ref.credential_id);
        assert_eq!(listed[0].vault.name, None);
    }

    #[test]
    fn rotate_copies_checks_then_deletes_the_old() {
        let Rotating {
            mut key,
            mut auth,
            old,
            old_id,
            contents,
        } = rotating();
        let old_lbk = lbk_of(&key, &old_id);
        let work = ids_named(&key, "Work").remove(0);
        let work_before = key.vault_on_key(&work);

        let (r, steps) = run_rotate(&mut key, &mut auth, &old);
        let made = r.unwrap_or_else(|e| panic!("{e}"));
        // How full the store is once the old vault's data is gone.
        assert_eq!(made.capacity, key.array().capacity(&key.info));
        assert_eq!(made.capacity.entry_count, 5);
        let new = made.open;
        assert_eq!(
            steps,
            vec![
                VaultStep::CreateTouch,
                VaultStep::UnlockTouch,
                VaultStep::Write
            ]
        );

        // One vault of that name, a different credential, the same entries.
        let named = ids_named(&key, "Personal");
        assert_eq!(named.len(), 1);
        let new_id = named[0].clone();
        assert_ne!(new_id, old_id);
        assert_eq!(new.vault_ref.credential_id, new_id);
        assert_eq!(new.vault_ref.name.as_deref(), Some("Personal"));
        assert_eq!(new.contents, contents);
        assert!(new.stored);
        assert_eq!(key.vault_on_key(&new_id), Some(contents));
        assert_ne!(new.secrets(), old.secrets());

        // The old credential and its data are gone; everything else stays.
        assert!(!key.creds.iter().any(|c| c.id == old_id));
        assert!(key.array().credential_blob(&old_lbk).is_none());
        assert_eq!(key.vault_on_key(&work), work_before);
        assert_eq!(key.array().len(), 5, "three foreign, Work, the new vault");

        assert_eq!(
            key.log,
            vec![
                // What the old vault holds now.
                Call::Read,
                token(MC, Some(RP_ID)),
                Call::MakeCredential,
                token(GA | LBW, Some(RP_ID)),
                Call::Assertions(Some(new_id.clone())),
                Call::Read,
                Call::Write,
                // The verifying read, then the old data's removal.
                Call::Read,
                Call::Write,
                token(CM, None),
                Call::Delete(old_id.clone()),
            ]
        );
        let verifying = key.log.iter().rposition(|c| *c == Call::Read).unwrap();
        let deleted = key
            .log
            .iter()
            .position(|c| *c == Call::Delete(old_id.clone()))
            .unwrap();
        assert!(verifying < deleted);
    }

    #[test]
    fn rotate_copies_what_is_on_the_key_now() {
        let Rotating {
            mut key,
            mut auth,
            old,
            old_id,
            contents,
        } = rotating();
        // Another writer adds an entry after the unlock.
        let mut now = contents.clone();
        now.entries.push(entry("Bank"));
        key.put_vault(&old_id, &now);

        let (r, _) = run_rotate(&mut key, &mut auth, &old);
        let new = r.unwrap_or_else(|e| panic!("{e}")).open;
        assert_eq!(new.contents, now);
        assert_eq!(key.vault_on_key(&new.vault_ref.credential_id), Some(now));
        assert_eq!(ids_named(&key, "Personal").len(), 1);
    }

    #[test]
    fn rotating_a_vault_without_data_skips_the_removal_write() {
        let mut key = FakeKey::new();
        let old_id = key.add_credential(user_handle("Empty").unwrap(), Some("Empty"));
        let mut auth = pin();
        let old = opened(&mut key, &mut auth, "Empty");
        assert!(!old.stored);
        key.log.clear();
        let (r, _) = run_rotate(&mut key, &mut auth, &old);
        let new = r.unwrap_or_else(|e| panic!("{e}")).open;
        assert_eq!(new.contents, Vault::default());
        assert_eq!(
            key.vault_on_key(&new.vault_ref.credential_id),
            Some(Vault::default())
        );
        assert!(!key.creds.iter().any(|c| c.id == old_id));
        let n = key.log.len();
        assert_eq!(
            key.log[n - 4..].to_vec(),
            vec![
                Call::Write,
                Call::Read,
                token(CM, None),
                Call::Delete(old_id)
            ],
            "one write (the new vault's), then the delete"
        );
    }

    #[test]
    fn unverified_copy_is_removed_and_old_kept() {
        // The new entry, right after it is written: data that does not
        // open, then a vault that opens to other entries.
        let corruptions: [fn(&mut FakeKey); 2] = [
            |k| {
                let id = k.creds.last().unwrap().id.clone();
                k.put_blob(&id, b"not a vault");
            },
            |k| {
                let id = k.creds.last().unwrap().id.clone();
                k.put_vault(
                    &id,
                    &Vault {
                        entries: vec![entry("Other")],
                    },
                );
            },
        ];
        for corrupt in corruptions {
            let Rotating {
                mut key,
                mut auth,
                old,
                old_id,
                contents,
            } = rotating();
            let before = key.stored().to_vec();
            key.after_write = Some((1, Box::new(corrupt)));
            let (r, _) = run_rotate(&mut key, &mut auth, &old);
            let (cause, left_over) = undone(r);
            assert!(
                matches!(cause, VaultKeyError::RotateNotVerified),
                "{cause:?}"
            );
            assert_eq!(left_over, LeftOver::NONE);
            assert_eq!(ids_named(&key, "Personal"), vec![old_id.clone()]);
            assert_eq!(key.vault_on_key(&old_id), Some(contents));
            assert_eq!(key.stored(), &before[..], "the copy's data is removed");
            assert!(!key.log.contains(&Call::Delete(old_id)));
        }
    }

    #[test]
    fn old_changed_during_rotate_removes_the_copy() {
        let Rotating {
            mut key,
            mut auth,
            old,
            old_id,
            contents,
        } = rotating();
        let before_ids = key.creds.len();
        let mut changed = contents;
        changed.entries.pop();
        let theirs = changed.clone();
        // Reads: 1 unlock, 2 rotate's, 3 the new vault's write. Another
        // writer changes the old vault after the rotate read it.
        key.hook = Some((
            2,
            Box::new(move |k: &mut FakeKey| {
                let id = ids_named(k, "Personal").remove(0);
                k.put_vault(&id, &theirs);
            }),
        ));
        let (r, _) = run_rotate(&mut key, &mut auth, &old);
        let (cause, left_over) = undone(r);
        assert!(
            matches!(cause, VaultKeyError::ChangedDuringRotate),
            "{cause:?}"
        );
        assert_eq!(left_over, LeftOver::NONE);
        assert_eq!(key.creds.len(), before_ids, "the copy is gone");
        assert_eq!(key.vault_on_key(&old_id), Some(changed), "theirs is kept");
    }

    #[test]
    fn a_change_before_the_old_data_goes_is_caught_on_the_retry() {
        // The verifying read (4) passes, the removal's write is refused as
        // stale, and before the retry reads again another writer changes
        // the old vault: the retry checks again and keeps their change.
        let Rotating {
            mut key,
            mut auth,
            old,
            old_id,
            contents,
        } = rotating();
        let mut changed = contents;
        changed.entries.push(entry("Bank"));
        let theirs = changed.clone();
        key.hook = Some((
            4,
            Box::new(move |k: &mut FakeKey| {
                k.write_refusals.push_back(0x33);
                let id = ids_named(k, "Personal").remove(0);
                k.put_vault(&id, &theirs);
            }),
        ));
        let (r, _) = run_rotate(&mut key, &mut auth, &old);
        let (cause, _) = undone(r);
        assert!(
            matches!(cause, VaultKeyError::ChangedDuringRotate),
            "{cause:?}"
        );
        assert_eq!(ids_named(&key, "Personal"), vec![old_id.clone()]);
        assert_eq!(key.vault_on_key(&old_id), Some(changed));
    }

    /// The `OldNotDeleted` parts of `r`.
    fn not_deleted(r: Result<Created, VaultKeyError>) -> (Option<String>, VaultKeyError, OldVault) {
        match r {
            Err(VaultKeyError::OldNotDeleted { name, cause, old }) => (name, *cause, old),
            other => panic!("expected OldNotDeleted, got {other:?}"),
        }
    }

    #[test]
    fn failed_old_delete_is_reported_with_both_vaults_kept() {
        let Rotating {
            mut key,
            mut auth,
            old,
            old_id,
            contents,
        } = rotating();
        // The key refuses the write that removes the old vault's data.
        key.hook = Some((
            4,
            Box::new(|k: &mut FakeKey| k.write_refusals.push_back(0x30)),
        ));
        let (r, _) = run_rotate(&mut key, &mut auth, &old);
        let (name, cause, left) = not_deleted(r);
        assert_eq!(name.as_deref(), Some("Personal"));
        assert!(
            matches!(cause, VaultKeyError::Ctap(CtapError::StatusCode(0x30))),
            "{cause:?}"
        );
        assert_eq!(left, OldVault::Kept);

        // Both vaults stay, hold the same entries, and the new one opens.
        let named = ids_named(&key, "Personal");
        assert_eq!(named.len(), 2);
        assert!(named.contains(&old_id));
        let unlocked = unlock(&mut key, &mut pin(), &mut |_| {}).unwrap();
        let personal: Vec<_> = unlocked
            .vaults
            .iter()
            .filter(|v| v.vault_ref.name.as_deref() == Some("Personal"))
            .collect();
        assert_eq!(personal.len(), 2);
        for v in personal {
            let open = v.state.as_ref().unwrap_or_else(|p| panic!("{p}"));
            assert_eq!(open.contents, contents);
            assert!(open.stored);
        }
    }

    #[test]
    fn old_credential_left_without_data_is_reported_as_emptied() {
        let Rotating {
            mut key,
            mut auth,
            old,
            old_id,
            contents,
        } = rotating();
        key.delete_fails = true;
        let (r, _) = run_rotate(&mut key, &mut auth, &old);
        let (_, cause, left) = not_deleted(r);
        assert!(
            matches!(cause, VaultKeyError::Ctap(CtapError::StatusCode(0x30))),
            "{cause:?}"
        );
        assert_eq!(left, OldVault::Emptied);
        // The old one lists with no data; the new one holds the entries.
        let creds = listed(&mut key, &mut pin());
        let old_listed = creds
            .iter()
            .find(|c| c.vault.credential_id == old_id)
            .unwrap();
        assert_eq!(old_listed.stored, StoredData::Empty);
        let new_id = ids_named(&key, "Personal")
            .into_iter()
            .find(|id| *id != old_id)
            .unwrap();
        assert_eq!(key.vault_on_key(&new_id), Some(contents));
    }

    #[test]
    fn a_lost_reply_on_the_old_data_is_reported_as_unknown() {
        let Rotating {
            mut key,
            mut auth,
            old,
            old_id,
            contents,
        } = rotating();
        key.hook = Some((4, Box::new(|k: &mut FakeKey| k.lost_write_replies = 1)));
        let (r, _) = run_rotate(&mut key, &mut auth, &old);
        let (_, cause, left) = not_deleted(r);
        assert!(
            matches!(cause, VaultKeyError::Ctap(CtapError::Transport(_))),
            "{cause:?}"
        );
        assert_eq!(left, OldVault::Unknown);
        assert!(key.creds.iter().any(|c| c.id == old_id), "not deleted");
        let new_id = ids_named(&key, "Personal")
            .into_iter()
            .find(|id| *id != old_id)
            .unwrap();
        assert_eq!(key.vault_on_key(&new_id), Some(contents));
    }

    #[test]
    fn failed_delete_of_an_old_vault_without_data_is_kept() {
        // Nothing to remove, so both are the same empty vault.
        let mut key = FakeKey::new();
        key.add_credential(user_handle("Empty").unwrap(), Some("Empty"));
        let mut auth = pin();
        let old = opened(&mut key, &mut auth, "Empty");
        key.delete_fails = true;
        let (r, _) = run_rotate(&mut key, &mut auth, &old);
        let (_, _, left) = not_deleted(r);
        assert_eq!(left, OldVault::Kept);
    }

    #[test]
    fn rotate_refuses_what_cannot_fit_before_the_touch() {
        let Rotating {
            mut key,
            mut auth,
            old,
            ..
        } = rotating();
        // Room for what is there now, not for a second copy.
        key.set_max_bytes(key.stored().len() as u64 + 16);
        let before = key.stored().to_vec();
        let (r, steps) = run_rotate(&mut key, &mut auth, &old);
        assert!(matches!(r, Err(VaultKeyError::Full { .. })), "{r:?}");
        assert!(steps.is_empty());
        assert_eq!(key.log, vec![Call::Read]);
        assert_eq!(key.stored(), &before[..]);
    }

    #[test]
    fn rotate_refuses_a_vault_whose_data_went_since_unlock() {
        // Another writer deleted (or rotated) it: copying "nothing" would
        // make an empty vault, so nothing is made.
        let Rotating {
            mut key,
            mut auth,
            old,
            old_id,
            ..
        } = rotating();
        let lbk = lbk_of(&key, &old_id);
        let without = key.array().without_credential_blob(&lbk);
        key.set_array(&without);
        let (r, steps) = run_rotate(&mut key, &mut auth, &old);
        assert!(
            matches!(&r, Err(VaultKeyError::VaultGone { name: Some(n) }) if n == "Personal"),
            "{r:?}"
        );
        assert!(steps.is_empty());
        assert_eq!(key.log, vec![Call::Read]);
    }

    #[test]
    fn rotate_refuses_a_vault_that_no_longer_opens() {
        let Rotating {
            mut key,
            mut auth,
            old,
            old_id,
            ..
        } = rotating();
        key.put_blob(&old_id, b"not a vault");
        let (r, steps) = run_rotate(&mut key, &mut auth, &old);
        assert!(
            matches!(r, Err(VaultKeyError::CannotOpen(VaultProblem::Damaged(_)))),
            "{r:?}"
        );
        assert!(steps.is_empty());
        assert_eq!(key.log, vec![Call::Read]);
    }

    // ----- finger asks per command -----

    use super::super::fake::asks;
    use super::super::{save, Change};
    use keyroost_ctap::client_pin::FingerAsk;
    use std::sync::{Arc, Mutex};

    /// What one fingerprint token carries in a vault flow.
    const FINGER: u32 = CM | GA | MC | LBW;

    /// The key calls of each `fido vault` command, as `vault_cmd.rs` makes
    /// them; the app's jobs are the same calls without the unlock in front.
    #[derive(Debug, Clone, Copy)]
    enum Command {
        /// `list`, `export`, `entry list`, `entry show`: the unlock.
        List,
        /// `entry add|edit|delete`: the unlock and one save.
        EntryAdd,
        /// `add`: a create.
        Add,
        /// `delete`: the listing and the delete.
        Delete,
        /// `rotate`: the unlock and the rotate.
        Rotate,
        /// `import` into a vault on the key: listing, unlock, one save.
        ImportExisting,
        /// `import` into a new vault: listing, then a create.
        ImportNew,
    }

    fn first_open(key: &mut FakeKey, auth: &mut VaultAuth) -> OpenVault {
        let mut u = unlock(key, auth, &mut |_| {}).unwrap_or_else(|e| panic!("{e}"));
        u.vaults.remove(0).state.unwrap_or_else(|p| panic!("{p}"))
    }

    fn run_command(key: &mut FakeKey, auth: &mut VaultAuth, command: Command) {
        fn ok<T>(r: Result<T, VaultKeyError>, command: Command) -> T {
            r.unwrap_or_else(|e| panic!("{command:?}: {e}"))
        }
        let quiet = &mut |_| {};
        match command {
            Command::List => drop(ok(unlock(key, auth, quiet), command)),
            Command::EntryAdd => {
                let mut open = first_open(key, auth);
                let change = Change::Add(entry("A"));
                ok(save(key, auth, &mut open, &change, quiet), command);
            }
            Command::Add => {
                let made = create(key, auth, "Travel", &Vault::default(), quiet);
                drop(ok(made, command));
            }
            Command::Delete => {
                let creds = ok(list_credentials(key, auth), command);
                ok(delete(key, auth, &creds[0], quiet), command);
            }
            Command::Rotate => {
                let old = first_open(key, auth);
                drop(ok(rotate(key, auth, &old, quiet), command));
            }
            Command::ImportExisting => {
                ok(list_credentials(key, auth), command);
                let mut open = first_open(key, auth);
                let change = Change::Import {
                    incoming: Vault {
                        entries: vec![entry("B")],
                    },
                    chosen: vec![0],
                };
                ok(save(key, auth, &mut open, &change, quiet), command);
            }
            Command::ImportNew => {
                ok(list_credentials(key, auth), command);
                let made = create(key, auth, "New", &two_entries(), quiet);
                drop(ok(made, command));
            }
        }
    }

    /// `command` under a fingerprint on a key holding a Personal vault; the
    /// asks it made, and every fingerprint token request.
    fn fingers_for(command: Command, drops: bool) -> (Vec<FingerAsk>, Vec<Call>) {
        fingers_on(command, drops, false)
    }

    /// [`fingers_for`] on a key that lists only under an unbound token
    /// (`strict`, CTAP 2.2's 6.8.4 as written) or not.
    fn fingers_on(command: Command, drops: bool, strict: bool) -> (Vec<FingerAsk>, Vec<Call>) {
        let mut key = FakeKey::with_fingerprint();
        key.drops_token_after_presence = drops;
        key.strict_listing = strict;
        key.add_vault("Personal", &two_entries());
        let (asked, ask) = asks();
        let mut auth = VaultAuth::fingerprint(ask);
        run_command(&mut key, &mut auth, command);
        assert!(
            !key.log.iter().any(|c| matches!(c, Call::Token { .. })),
            "{command:?}: no PIN"
        );
        let requests = key
            .log
            .into_iter()
            .filter(|c| matches!(c, Call::UvToken { .. }))
            .collect();
        let asked = asked.lock().unwrap().clone();
        (asked, requests)
    }

    /// One finger per command, except where a touch of the key ends what the
    /// token allows (CTAP 2.1 6.5.5.7: a makeCredential or getAssertion
    /// leaves it only largeBlobWrite) and a later step needs more: a create
    /// asks again before its getAssertion, a rotate before its
    /// makeCredential, its getAssertion and its credential delete. Each
    /// token carries every permission a vault step needs, bound to the
    /// vault RP. A key that drops the token after a touch adds one "asked
    /// again" where a write follows the touch, never more.
    #[test]
    fn a_fingerprint_command_asks_for_the_finger_once_where_ctap_allows() {
        use FingerAsk::{Again as G, Unlock as U};
        for (command, keeps, drops) in [
            (Command::List, vec![U], vec![U]),
            (Command::EntryAdd, vec![U], vec![U, G]),
            (Command::Add, vec![U, U], vec![U, U, G]),
            (Command::Delete, vec![U], vec![U]),
            (Command::Rotate, vec![U, U, U, U], vec![U, U, U, G]),
            (Command::ImportExisting, vec![U], vec![U, G]),
            (Command::ImportNew, vec![U, U], vec![U, U, G]),
        ] {
            for (drops_token, expected) in [(false, keeps), (true, drops)] {
                let (asked, requests) = fingers_for(command, drops_token);
                assert_eq!(asked, expected, "{command:?}, drops = {drops_token}");
                assert_eq!(requests.len(), asked.len(), "{command:?}");
                for r in &requests {
                    assert_eq!(
                        *r,
                        Call::UvToken {
                            perms: FINGER,
                            rp: Some(RP_ID.into())
                        },
                        "{command:?}"
                    );
                }
            }
        }

        // A key with no vault: the listing's finger only, and no touch.
        let mut key = FakeKey::with_fingerprint();
        let (asked, ask) = asks();
        let mut auth = VaultAuth::fingerprint(ask);
        let u = unlock(&mut key, &mut auth, &mut |_| {}).unwrap_or_else(|e| panic!("{e}"));
        assert!(u.vaults.is_empty());
        assert_eq!(*asked.lock().unwrap(), [FingerAsk::Unlock]);
        assert!(!key.log.iter().any(|c| matches!(c, Call::Assertions(_))));
    }

    /// A key that lists only under an unbound token (CTAP 2.2's 6.8.4 as
    /// written) refuses the vault-RP-bound token for the listing: the flow
    /// asks once more for an unbound listing token, saying why, and every
    /// later listing of the same auth takes an unbound token straight away.
    /// Every command works; no "refused" reaches the person. A new token
    /// replaces the one held (CTAP 2.1 6.5.5.7.3), so the getAssertion or
    /// makeCredential after an unbound listing takes its own finger.
    #[test]
    fn a_strict_key_lists_under_an_unbound_token_and_every_command_works() {
        use FingerAsk::{ListVaults as L, Unlock as U};
        let bound = Call::UvToken {
            perms: FINGER,
            rp: Some(RP_ID.into()),
        };
        let unbound = Call::UvToken {
            perms: CM | LBW,
            rp: None,
        };
        for (command, expected) in [
            (Command::List, vec![U, L, U]),
            (Command::EntryAdd, vec![U, L, U]),
            (Command::Add, vec![U, L, U, U]),
            (Command::Delete, vec![U, L]),
            (Command::Rotate, vec![U, L, U, U, U, U]),
            (Command::ImportExisting, vec![U, L, U]),
            (Command::ImportNew, vec![U, L, U, U]),
        ] {
            let (asked, requests) = fingers_on(command, false, true);
            assert_eq!(asked, expected, "{command:?}");
            assert_eq!(requests.len(), asked.len(), "{command:?}");
            for (ask, request) in asked.iter().zip(&requests) {
                let want = if *ask == L { &unbound } else { &bound };
                assert_eq!(request, want, "{command:?}");
            }
            // A key that takes the bound token never asks for an unbound one.
            let (lenient, _) = fingers_on(command, false, false);
            assert!(!lenient.contains(&L), "{command:?}");
        }
    }

    /// The fallback is one more token, never a loop: a finger refused for
    /// it ends the flow there, and a held bound token the strict key
    /// refuses is renewed once before the unbound one.
    #[test]
    fn the_unbound_listing_fallback_asks_once() {
        let mut key = FakeKey::with_fingerprint();
        key.strict_listing = true;
        key.add_vault("Personal", &two_entries());
        let (asked, ask) = asks();
        let mut auth = VaultAuth::fingerprint(ask);
        // The first (bound) token is given; the unbound one is refused.
        let mut steps = Vec::new();
        let r = unlock_with_second_refused(&mut key, &mut auth, &mut steps);
        assert!(
            matches!(
                r,
                Err(VaultKeyError::Ctap(CtapError::Fingerprint(
                    keyroost_ctap::FingerprintError::Refused(0x3F)
                )))
            ),
            "{r:?}"
        );
        assert!(steps.is_empty(), "no touch asked for");
        assert_eq!(
            *asked.lock().unwrap(),
            [FingerAsk::Unlock, FingerAsk::ListVaults]
        );

        // A held bound token (here a delete's, which saw no touch) on a
        // strict key: renewed once, then the unbound token.
        let mut key = FakeKey::with_fingerprint();
        key.strict_listing = true;
        key.add_vault("Personal", &two_entries());
        let (asked, ask) = asks();
        let mut auth = VaultAuth::fingerprint(ask);
        auth.fresh_token(&mut key, LBW, None)
            .unwrap_or_else(|e| panic!("{e}"));
        let creds = listed(&mut key, &mut auth);
        assert_eq!(creds.len(), 1);
        assert_eq!(
            *asked.lock().unwrap(),
            [FingerAsk::Unlock, FingerAsk::Again, FingerAsk::ListVaults]
        );
    }

    /// Unlock with the key refusing the second finger it is asked for.
    fn unlock_with_second_refused(
        key: &mut FakeKey,
        auth: &mut VaultAuth,
        steps: &mut Vec<VaultStep>,
    ) -> Result<super::super::Unlocked, VaultKeyError> {
        // The fake pops one scripted refusal per request, so the refusal is
        // scripted only once the first request has been given its token.
        struct Second<'a>(&'a mut FakeKey, usize);
        impl VaultKey for Second<'_> {
            fn info(&self) -> &keyroost_ctap::AuthenticatorInfo {
                self.0.info()
            }
            fn pin_token(
                &mut self,
                pin: &str,
                permissions: u32,
                rp_id: Option<&str>,
            ) -> Result<keyroost_ctap::client_pin::PinUvAuthToken, CtapError> {
                self.0.pin_token(pin, permissions, rp_id)
            }
            fn uv_token(
                &mut self,
                permissions: u32,
                rp_id: Option<&str>,
                on_finger: &mut dyn FnMut(),
            ) -> Result<keyroost_ctap::client_pin::PinUvAuthToken, CtapError> {
                self.1 += 1;
                if self.1 == 2 {
                    self.0.uv_refusals.push_back(0x3F);
                }
                self.0.uv_token(permissions, rp_id, on_finger)
            }
            fn make_credential(
                &mut self,
                token: &keyroost_ctap::client_pin::PinUvAuthToken,
                user_id: &[u8],
                name: &str,
            ) -> Result<keyroost_ctap::make_credential::MadeCredential, CtapError> {
                self.0.make_credential(token, user_id, name)
            }
            fn assertions(
                &mut self,
                token: &keyroost_ctap::client_pin::PinUvAuthToken,
                allow: Option<&[u8]>,
            ) -> Result<Vec<keyroost_ctap::get_assertion::Assertion>, CtapError> {
                self.0.assertions(token, allow)
            }
            fn credentials(
                &mut self,
                token: &keyroost_ctap::client_pin::PinUvAuthToken,
            ) -> Result<Vec<VaultCredential>, CtapError> {
                self.0.credentials(token)
            }
            fn delete_credential(
                &mut self,
                token: &keyroost_ctap::client_pin::PinUvAuthToken,
                credential_id: &[u8],
            ) -> Result<(), CtapError> {
                self.0.delete_credential(token, credential_id)
            }
            fn read_blobs(&mut self) -> Result<LargeBlobArray, CtapError> {
                self.0.read_blobs()
            }
            fn write_blobs(
                &mut self,
                token: &keyroost_ctap::client_pin::PinUvAuthToken,
                serialized: &[u8],
            ) -> Result<(), CtapError> {
                self.0.write_blobs(token, serialized)
            }
        }
        unlock(&mut Second(key, 0), auth, &mut |s| steps.push(s))
    }

    /// The PIN path keeps its own tokens: each step asks for what it needs,
    /// with no rpId for credential management.
    #[test]
    fn a_pin_command_takes_its_tokens_as_before() {
        let mut key = FakeKey::new();
        key.add_vault("Personal", &two_entries());
        run_command(&mut key, &mut pin(), Command::Rotate);
        let tokens: Vec<Call> = key
            .log
            .into_iter()
            .filter(|c| matches!(c, Call::Token { .. }))
            .collect();
        assert_eq!(
            tokens,
            vec![
                token(CM | LBW, None),
                token(GA | LBW, Some(RP_ID)),
                token(MC, Some(RP_ID)),
                token(GA | LBW, Some(RP_ID)),
                token(CM, None),
            ]
        );
    }

    /// A held fingerprint token the key refuses at a touch (here another
    /// token replaced it while a question waited) is renewed once, asking
    /// again and saying why; the touch is reported once.
    #[test]
    fn a_stale_held_token_at_a_touch_asks_again_once() {
        let mut key = FakeKey::with_fingerprint();
        key.credmgmt_without_lbk = true;
        let id = key.add_vault("Personal", &two_entries());
        let (asked, ask) = asks();
        let mut auth = VaultAuth::fingerprint(ask);
        let creds = listed(&mut key, &mut auth);
        key.pin_token(FakeKey::PIN, LBW, None).unwrap();
        let mut steps = Vec::new();
        delete(&mut key, &mut auth, &creds[0], &mut |s| steps.push(s))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(steps, vec![VaultStep::UnlockTouch]);
        assert_eq!(
            key.log
                .iter()
                .filter(|c| matches!(c, Call::Assertions(_)))
                .count(),
            2
        );
        assert_eq!(
            *asked.lock().unwrap(),
            [FingerAsk::Unlock, FingerAsk::Again, FingerAsk::Unlock],
            "the listing, the renewal, the delete after the touch"
        );
        assert!(!key.creds.iter().any(|c| c.id == id));

        // Refused again: no third token.
        let mut key = FakeKey::with_fingerprint();
        key.credmgmt_without_lbk = true;
        key.add_vault("Personal", &two_entries());
        let (asked, ask) = asks();
        let mut auth = VaultAuth::fingerprint(ask);
        listed(&mut key, &mut auth);
        key.pin_token(FakeKey::PIN, LBW, None).unwrap();
        let stale = Arc::new(Mutex::new(0));
        let count = Arc::clone(&stale);
        let r = auth.with_touch(
            &mut key,
            GA | LBW,
            VaultStep::UnlockTouch,
            &mut |_| {},
            |_, _| -> Result<(), CtapError> {
                *count.lock().unwrap() += 1;
                Err(CtapError::StatusCode(0x33))
            },
        );
        assert!(
            matches!(r, Err(VaultKeyError::Ctap(CtapError::StatusCode(0x33)))),
            "{r:?}"
        );
        assert_eq!(*stale.lock().unwrap(), 2, "one retry");
        assert_eq!(
            *asked.lock().unwrap(),
            [FingerAsk::Unlock, FingerAsk::Again]
        );
    }
}
