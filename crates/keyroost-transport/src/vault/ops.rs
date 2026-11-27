//! Unlocking the vaults on a key, choosing among them by name, and saving a
//! change to one.
//!
//! One touch unlocks every vault: a single getAssertion without an allow
//! list returns each vault credential's hmac-secret output and largeBlobKey,
//! and one read of the largeBlob array holds every vault's data. Each vault
//! is then judged on its own, so one that won't open is reported next to the
//! others instead of hiding them, and never read as empty.
//!
//! A save never writes back the vault as it was read at unlock: it re-reads
//! the array right before writing and applies only its one [`Change`] to
//! what the key holds then, so another writer's change to a different entry
//! survives, and a change to the same entry is refused rather than guessed.

use std::fmt;

use keyroost_ctap::client_pin::permissions::{
    CREDENTIAL_MANAGEMENT, GET_ASSERTION, LARGE_BLOB_WRITE,
};
use keyroost_ctap::large_blobs::{BlobCapacity, CredentialData, LargeBlobArray, LargeBlobEntry};
use keyroost_ctap::{AuthenticatorInfo, CtapError};
use keyroost_vault::{apply_import, canon_id, open, seal, Entry, Vault, VaultError};
use zeroize::Zeroizing;

use super::{
    check_support, vault_name, VaultAuth, VaultKey, VaultKeyError, VaultProblem, VaultRef,
    VaultStep,
};

/// What a vault is sealed with and found by. A clone is wiped on drop like
/// the original.
#[derive(Clone)]
struct VaultSecrets {
    /// The credential's hmac-secret output: seals the vault.
    hmac: Zeroizing<[u8; 32]>,
    /// The credential's largeBlobKey: finds its entry in the array.
    lbk: Zeroizing<[u8; 32]>,
}

/// A vault that opened: its contents and what it takes to write it back.
/// A clone carries the same secrets (wiped on drop) and saves like the
/// original; each copy's `contents` changes only with its own saves.
#[derive(Clone)]
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
    pub(super) fn secrets(&self) -> (&[u8; 32], &[u8; 32]) {
        (&self.secrets.hmac, &self.secrets.lbk)
    }

    /// Whether `entry` of the key's largeBlob array is this vault's data:
    /// sealed under its largeBlobKey. A front end that lists the store uses
    /// it to tell a vault's entry from other entries, without decrypting
    /// anything.
    pub fn holds_entry(&self, entry: &LargeBlobEntry) -> bool {
        entry.is_sealed_under(&self.secrets.lbk)
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
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
pub struct Unlocked {
    pub vaults: Vec<VaultOnKey>,
    pub capacity: BlobCapacity,
}

/// Unlock every vault on the key with one touch.
///
/// The key is checked first ([`check_support`](super::check_support)), so a
/// key that cannot hold a vault is refused before the PIN is sent. Then
/// credential management looks for vault credentials, which needs no touch
/// (every key that passes the check has it): with none, the result is an
/// empty list after one read of the largeBlob array, and no touch is asked
/// for. Otherwise one token (getAssertion and largeBlobWrite, bound to the
/// vault RP; a fingerprint's listing token covers it, so one finger serves
/// both), a [`VaultStep::UnlockTouch`], one getAssertion over every
/// vault credential and one read of the largeBlob array. A vault the key
/// gives no secret for, or whose data does not open, is listed with its
/// [`VaultProblem`]; the others open regardless.
pub fn unlock(
    key: &mut impl VaultKey,
    auth: &mut VaultAuth,
    on_step: &mut dyn FnMut(VaultStep),
) -> Result<Unlocked, VaultKeyError> {
    check_support(key.info())?;
    if !has_vault_credential(key, auth)? {
        let array = key.read_blobs()?;
        let capacity = array.capacity(key.info());
        return Ok(Unlocked {
            vaults: Vec::new(),
            capacity,
        });
    }
    let asserted = auth.with_touch(
        key,
        GET_ASSERTION | LARGE_BLOB_WRITE,
        VaultStep::UnlockTouch,
        on_step,
        |k, token| k.assertions(token, None),
    )?;
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

/// Read every unlocked vault again from the key: no PIN and no touch, one
/// read of the largeBlob array, opened with the secrets the unlock kept.
///
/// Each vault that is open takes what the key holds for it now: another
/// writer's change shows, and data that no longer opens (damaged, or saved
/// by a newer app) turns that vault into a [`VaultProblem`] whose secrets
/// are dropped. A vault that did not open stays as it is. `capacity` is
/// updated to the array as read.
///
/// A vault whose data was there and is gone now (another writer deleted or
/// rotated it) is [`VaultKeyError::VaultGone`], and then `unlocked` is left
/// exactly as it was: every vault is checked before any is changed. Unlock
/// again to see what the key holds then.
///
/// Only the vaults this unlock found are read: one created elsewhere since,
/// or the new vault a rotate elsewhere made, appears only after a new
/// [`unlock`].
pub fn reload(key: &mut impl VaultKey, unlocked: &mut Unlocked) -> Result<(), VaultKeyError> {
    let array = key.read_blobs()?;
    // Read every vault first, so a vanished one leaves `unlocked` untouched.
    let mut read = Vec::with_capacity(unlocked.vaults.len());
    for vault in &unlocked.vaults {
        let Ok(open) = &vault.state else {
            read.push(None);
            continue;
        };
        let (hmac, lbk) = open.secrets();
        let state = vault_state(array.credential_data(lbk), hmac);
        if matches!(state, Ok((_, false))) && open.stored {
            return Err(VaultKeyError::VaultGone {
                name: open.vault_ref.name.clone(),
            });
        }
        read.push(Some(state));
    }
    for (vault, state) in unlocked.vaults.iter_mut().zip(read) {
        match state {
            None => {}
            Some(Ok((contents, stored))) => {
                if let Ok(open) = &mut vault.state {
                    open.contents = contents;
                    open.stored = stored;
                }
            }
            Some(Err(problem)) => vault.state = Err(problem),
        }
    }
    unlocked.capacity = array.capacity(key.info());
    Ok(())
}

/// Whether credential management lists any vault credential: no touch.
/// The current token serves when it allows credential management (a listing
/// just made took one); otherwise a fresh one, with largeBlobWrite too as
/// [`list_credentials`](super::list_credentials) takes it. A held token the
/// key dropped or let expire gets one renewed token (a finger is asked for
/// again, saying why) and one more try.
fn has_vault_credential(
    key: &mut impl VaultKey,
    auth: &mut VaultAuth,
) -> Result<bool, VaultKeyError> {
    let perms = CREDENTIAL_MANAGEMENT | LARGE_BLOB_WRITE;
    if auth.is_fingerprint() {
        let creds = auth.with_listing(key, perms, |k, t| k.credentials(t))?;
        return Ok(!creds.is_empty());
    }
    let token = match auth.current_for(CREDENTIAL_MANAGEMENT).cloned() {
        None => auth.fresh_token(key, perms, None)?.clone(),
        Some(token) => match key.credentials(&token) {
            Ok(creds) => return Ok(!creds.is_empty()),
            Err(e) if stale_token(&e) => auth.renewed_token(key, perms, None)?.clone(),
            Err(e) => return Err(e.into()),
        },
    };
    Ok(!key.credentials(&token)?.is_empty())
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

/// One change to a vault. A save applies it to the vault as the key holds it
/// at the moment of writing, not to the copy read at unlock; the entries it
/// names as `before` are as they were read, so a change made on the key in
/// between is noticed. Callers stamp `modified_minutes` themselves.
#[derive(Debug, Clone)]
pub enum Change {
    /// A new entry.
    Add(Entry),
    /// `before` becomes `after`; the entry keeps its id whatever id `after`
    /// carries.
    Edit { before: Entry, after: Entry },
    /// `before` is removed.
    Delete { before: Entry },
    /// The `incoming` entries at the `chosen` indices are imported
    /// ([`keyroost_vault::apply_import`]).
    Import { incoming: Vault, chosen: Vec<usize> },
}

/// What a save wrote: how many entries it added, replaced and removed, and
/// how full the largeBlob store is now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Saved {
    pub added: usize,
    pub replaced: usize,
    pub removed: usize,
    pub capacity: BlobCapacity,
}

/// The index of the entry with `id`, matched in canonical form (a format-1
/// UUID id is the same entry as its shortened form).
fn position(vault: &Vault, id: &str) -> Option<usize> {
    let id = canon_id(id);
    vault.entries.iter().position(|e| canon_id(&e.id) == id)
}

fn find<'a>(vault: &'a Vault, id: &str) -> Option<&'a Entry> {
    position(vault, id).map(|i| &vault.entries[i])
}

/// `current` (what the key holds now) with `change` applied, and how many
/// entries were added, replaced and removed. `base` is the vault as it was
/// read at unlock. An entry the change touches that is no longer as it was
/// read is [`VaultKeyError::Conflict`]: another writer changed it, and
/// keeping either side would be a guess. Entries are compared with `==` to
/// detect a change, not to check a secret.
pub(crate) fn apply_change(
    base: &Vault,
    current: &Vault,
    change: &Change,
) -> Result<(Vault, usize, usize, usize), VaultKeyError> {
    let mut next = current.clone();
    match change {
        Change::Add(entry) => {
            if position(&next, &entry.id).is_some() {
                return Err(VaultKeyError::Conflict);
            }
            next.entries.push(entry.clone());
            Ok((next, 1, 0, 0))
        }
        Change::Edit { before, after } => match position(&next, &before.id) {
            Some(i) if next.entries[i] == *before => {
                let mut edited = after.clone();
                // The entry keeps its id, whatever `after` carries.
                edited.id.clone_from(&next.entries[i].id);
                next.entries[i] = edited;
                Ok((next, 0, 1, 0))
            }
            _ => Err(VaultKeyError::Conflict),
        },
        Change::Delete { before } => match position(&next, &before.id) {
            // Already gone: what was asked for is done.
            None => Ok((next, 0, 0, 0)),
            Some(i) if next.entries[i] == *before => {
                next.entries.remove(i);
                Ok((next, 0, 0, 1))
            }
            Some(_) => Err(VaultKeyError::Conflict),
        },
        Change::Import { incoming, chosen } => {
            // Every chosen entry's id must hold what it held at unlock (or
            // still be absent), so the add / replace the user was shown is
            // what happens.
            for inc in chosen.iter().filter_map(|&i| incoming.entries.get(i)) {
                if find(base, &inc.id) != find(&next, &inc.id) {
                    return Err(VaultKeyError::Conflict);
                }
            }
            let (added, replaced) = apply_import(&mut next, incoming, chosen);
            Ok((next, added, replaced, 0))
        }
    }
}

/// `CTAP2_ERR_PIN_AUTH_INVALID`: the key no longer accepts the token, or
/// not for this call.
pub(super) const PIN_AUTH_INVALID: u8 = 0x33;
/// `CTAP2_ERR_PIN_TOKEN_EXPIRED`.
const PIN_TOKEN_EXPIRED: u8 = 0x38;

/// Whether the key refused a call because it dropped the token or let it
/// expire: worth one fresh token and one more try, nothing else is.
pub(super) fn stale_token(e: &CtapError) -> bool {
    matches!(
        e,
        CtapError::StatusCode(PIN_AUTH_INVALID | PIN_TOKEN_EXPIRED)
    )
}

/// [`VaultKeyError::Full`] when `array` would not fit the key's store.
pub(super) fn check_fits(
    array: &LargeBlobArray,
    info: &AuthenticatorInfo,
) -> Result<(), VaultKeyError> {
    let capacity = array.capacity(info);
    if capacity.used_bytes > capacity.max_bytes {
        return Err(VaultKeyError::Full {
            needed: capacity.used_bytes,
            max: capacity.max_bytes,
        });
    }
    Ok(())
}

/// Write the largeBlob array that `build` makes from the array as the key
/// holds it right now, and return what was written. `build` returns `None`
/// when the array needs no change: then nothing is written (no
/// [`VaultStep::Write`]) and the array as read is returned.
///
/// The token is the current one when it carries largeBlobWrite, else a
/// fresh largeBlobWrite token. Then the array is read, `build` runs on it,
/// the result is checked against the store's size ([`VaultKeyError::Full`],
/// nothing written), [`VaultStep::Write`] is reported and the array is
/// written. Nothing else runs between that read and the write, so a change
/// another writer saved before it is kept.
///
/// A key can drop a token between unlock and write, or let it expire while
/// a question waits: on the first `PIN_AUTH_INVALID` or `PIN_TOKEN_EXPIRED`
/// a renewed token is taken (a finger is asked for again, saying why) and
/// the array is read, built and written once
/// more. A second refusal, or any other error, is returned.
pub(crate) fn write_array(
    key: &mut impl VaultKey,
    auth: &mut VaultAuth,
    build: &mut dyn FnMut(&LargeBlobArray) -> Result<Option<LargeBlobArray>, VaultKeyError>,
    on_step: &mut dyn FnMut(VaultStep),
) -> Result<LargeBlobArray, VaultKeyError> {
    let mut token = match auth.current_for(LARGE_BLOB_WRITE) {
        Some(token) => token.clone(),
        None => auth.fresh_token(key, LARGE_BLOB_WRITE, None)?.clone(),
    };
    let mut retried = false;
    loop {
        let array = key.read_blobs()?;
        let Some(next) = build(&array)? else {
            return Ok(array);
        };
        check_fits(&next, key.info())?;
        let bytes = next.serialize_with_checksum()?;
        on_step(VaultStep::Write);
        match key.write_blobs(&token, &bytes) {
            Ok(()) => return Ok(next),
            Err(e) if stale_token(&e) && !retried => {
                retried = true;
                token = auth.renewed_token(key, LARGE_BLOB_WRITE, None)?.clone();
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// Save one change to an open vault.
///
/// Right before writing, the vault is read again from the key and `change`
/// is applied to what it holds then: another writer's change to a different
/// entry is kept, and a change to an entry this one touches is refused with
/// [`VaultKeyError::Conflict`], nothing written, and `open.contents`
/// reloaded with what the key holds now. A vault whose data was there at
/// unlock and is gone now (another writer deleted or rotated it) is
/// [`VaultKeyError::VaultGone`], nothing written and `open` left as it was,
/// so every later save on it is refused too. Data that no
/// longer opens (damaged, or saved by a newer app) is refused with
/// [`VaultKeyError::CannotOpen`] and never written over. A store too small
/// for the result is [`VaultKeyError::Full`], nothing written. Every other
/// entry in the largeBlob array is written back as it was read.
///
/// On success `open.contents` is what was written.
pub fn save(
    key: &mut impl VaultKey,
    auth: &mut VaultAuth,
    open: &mut OpenVault,
    change: &Change,
    on_step: &mut dyn FnMut(VaultStep),
) -> Result<Saved, VaultKeyError> {
    let mut applied = None;
    let mut on_key = None;
    let written = {
        let (hmac, lbk) = open.secrets();
        let base = &open.contents;
        let was_stored = open.stored;
        let vault_name = &open.vault_ref.name;
        write_array(
            key,
            auth,
            &mut |array| {
                let (current, stored) = vault_state(array.credential_data(lbk), hmac)
                    .map_err(VaultKeyError::CannotOpen)?;
                // Data that was there at unlock and is gone now means
                // another writer deleted or rotated this vault: writing
                // would leave a blob no credential finds and lose the
                // change, so it is refused, never an empty vault. The open
                // vault is left as it was (still `stored`), so a retried
                // save on it is refused the same way.
                if was_stored && !stored {
                    return Err(VaultKeyError::VaultGone {
                        name: vault_name.clone(),
                    });
                }
                match apply_change(base, &current, change) {
                    Ok((next, added, replaced, removed)) => {
                        let blob = seal(&next, hmac)?;
                        let array = array.with_credential_blob(lbk, &blob)?;
                        applied = Some((next, added, replaced, removed));
                        Ok(Some(array))
                    }
                    Err(e) => {
                        on_key = Some((current, stored));
                        Err(e)
                    }
                }
            },
            on_step,
        )
    };
    match written {
        Ok(array) => {
            let (next, added, replaced, removed) =
                applied.expect("build ran for the array that was written");
            open.contents = next;
            open.stored = true;
            Ok(Saved {
                added,
                replaced,
                removed,
                capacity: array.capacity(key.info()),
            })
        }
        Err(e) => {
            if let (VaultKeyError::Conflict, Some((current, stored))) = (&e, on_key) {
                open.contents = current;
                open.stored = stored;
            }
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::fake::{Call, FakeKey};
    use super::super::{StoredData, VaultCredential};
    use super::*;
    use keyroost_ctap::client_pin::permissions::{GET_ASSERTION as GA, LARGE_BLOB_WRITE as LBW};
    use keyroost_ctap::CtapError;
    use keyroost_vault::{canon_id, seal, user_handle, Entry, Vault, VaultError, RP_ID};
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
        // One PIN exchange per token, the PIN read once: credential
        // management to see there is a vault, then the touch's own token.
        assert_eq!(
            key.log,
            vec![
                Call::Token {
                    perms: CM | LBW,
                    rp: None
                },
                Call::Credentials,
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
        let (r, steps) = run(&mut key, &mut pin());
        let u = r.unwrap_or_else(|e| panic!("{e}"));
        // Credential management shows there is nothing to unlock: no touch
        // is asked for and no assertion is sent.
        assert!(steps.is_empty(), "{steps:?}");
        assert_eq!(
            key.log,
            vec![
                Call::Token {
                    perms: CM | LBW,
                    rp: None
                },
                Call::Credentials,
                Call::Read,
            ]
        );
        assert!(u.vaults.is_empty());
        assert_eq!(u.capacity.entry_count, 3);
        assert!(matches!(
            matching(&u.vaults, &VaultPick::Only),
            Err(VaultKeyError::NoVaults)
        ));
    }

    #[test]
    fn unlock_after_a_listing_reuses_its_token_for_the_check() {
        let mut key = FakeKey::new();
        key.add_vault("Personal", &Vault::default());
        let mut auth = pin();
        let listed =
            super::super::list_credentials(&mut key, &mut auth).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(listed.len(), 1);
        let before = key.log.len();
        let (r, steps) = run(&mut key, &mut auth);
        assert_eq!(r.unwrap_or_else(|e| panic!("{e}")).vaults.len(), 1);
        assert_eq!(steps, vec![VaultStep::UnlockTouch]);
        assert_eq!(
            key.log[before..],
            [
                Call::Credentials,
                Call::Token {
                    perms: GA | LBW,
                    rp: Some(RP_ID.into())
                },
                Call::Assertions(None),
                Call::Read,
            ]
        );
    }

    #[test]
    fn a_dropped_listing_token_is_replaced_once() {
        let mut key = FakeKey::new();
        key.add_foreign_entries();
        let mut auth = pin();
        super::super::list_credentials(&mut key, &mut auth).unwrap_or_else(|e| panic!("{e}"));
        // Another token makes the held one stale on the key.
        pin()
            .fresh_token(&mut key, LBW, None)
            .unwrap_or_else(|e| panic!("{e}"));
        let before = key.log.len();
        let (r, steps) = run(&mut key, &mut auth);
        assert!(r.unwrap_or_else(|e| panic!("{e}")).vaults.is_empty());
        assert!(steps.is_empty());
        assert_eq!(
            key.log[before..],
            [
                Call::Credentials,
                Call::Token {
                    perms: CM | LBW,
                    rp: None
                },
                Call::Credentials,
                Call::Read,
            ]
        );
    }

    #[test]
    fn a_refused_pin_on_a_key_without_vaults_asks_for_no_touch() {
        let mut key = FakeKey::new();
        let (r, steps) = run(&mut key, &mut VaultAuth::pin(Zeroizing::new("0000".into())));
        assert!(matches!(
            r,
            Err(VaultKeyError::Ctap(CtapError::StatusCode(0x31)))
        ));
        assert!(steps.is_empty());
        assert!(!key.log.iter().any(|c| matches!(c, Call::Assertions(_))));
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
            stored: StoredData::Unknown,
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

    // ----- saving -----

    use keyroost_ctap::client_pin::permissions::CREDENTIAL_MANAGEMENT as CM;

    /// Unlock `key` and return the auth that did it and the first vault,
    /// open.
    fn open_first(key: &mut FakeKey) -> (VaultAuth, OpenVault) {
        let mut auth = pin();
        let mut u = unlock(key, &mut auth, &mut |_| {}).unwrap_or_else(|e| panic!("{e}"));
        let open = u.vaults.remove(0).state.unwrap_or_else(|p| panic!("{p}"));
        (auth, open)
    }

    /// Save `change`, returning the result and the steps reported.
    fn save_with(
        key: &mut FakeKey,
        auth: &mut VaultAuth,
        open: &mut OpenVault,
        change: &Change,
    ) -> (Result<Saved, VaultKeyError>, Vec<VaultStep>) {
        let mut steps = Vec::new();
        let r = save(key, auth, open, change, &mut |s| steps.push(s));
        (r, steps)
    }

    fn saved(key: &mut FakeKey, auth: &mut VaultAuth, open: &mut OpenVault, c: &Change) -> Saved {
        save_with(key, auth, open, c)
            .0
            .unwrap_or_else(|e| panic!("{e}"))
    }

    /// `e` with a new password, a minute later.
    fn edited(e: &Entry, password: &str) -> Entry {
        let mut n = e.clone();
        n.password = Zeroizing::new(password.into());
        n.modified_minutes += 1;
        n
    }

    /// Run `f` on credential `id`'s vault right after the first read (the
    /// unlock's): another writer saving between unlock and our save.
    fn other_writer(key: &mut FakeKey, id: &[u8], f: impl FnOnce(&mut Vault) + 'static) {
        let id = id.to_vec();
        key.hook = Some((
            1,
            Box::new(move |k: &mut FakeKey| {
                let mut v = k.vault_on_key(&id).expect("the vault opens");
                f(&mut v);
                k.put_vault(&id, &v);
            }),
        ));
    }

    fn writes(key: &FakeKey) -> usize {
        key.log.iter().filter(|c| **c == Call::Write).count()
    }

    fn lbk_of(key: &FakeKey, id: &[u8]) -> [u8; 32] {
        key.creds
            .iter()
            .find(|c| c.id == id)
            .and_then(|c| c.lbk)
            .expect("a credential with a largeBlobKey")
    }

    /// Everything in the store except credential `id`'s data, serialized.
    fn all_but(key: &FakeKey, id: &[u8]) -> Vec<u8> {
        key.array()
            .without_credential_blob(&lbk_of(key, id))
            .serialize_with_checksum()
            .unwrap()
    }

    #[test]
    fn add_edit_delete_apply_to_current_contents() {
        let mut key = FakeKey::new();
        let (a, b) = (entry("GitHub"), entry("Mail"));
        let id = key.add_vault(
            "Personal",
            &Vault {
                entries: vec![a.clone(), b.clone()],
            },
        );
        let (mut auth, mut open) = open_first(&mut key);
        let unlocked_at = key.log.len();

        let c = entry("Bank");
        let (r, steps) = save_with(&mut key, &mut auth, &mut open, &Change::Add(c.clone()));
        let s = r.unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(steps, vec![VaultStep::Write]);
        assert_eq!((s.added, s.replaced, s.removed), (1, 0, 0));
        let want = Vault {
            entries: vec![a.clone(), b.clone(), c.clone()],
        };
        assert_eq!(key.vault_on_key(&id), Some(want.clone()));
        assert_eq!(open.contents, want);
        assert_eq!(s.capacity, key.array().capacity(&key.info));

        let a2 = edited(&a, "new password");
        let s = saved(
            &mut key,
            &mut auth,
            &mut open,
            &Change::Edit {
                before: a.clone(),
                after: a2.clone(),
            },
        );
        assert_eq!((s.added, s.replaced, s.removed), (0, 1, 0));
        let want = Vault {
            entries: vec![a2.clone(), b.clone(), c.clone()],
        };
        assert_eq!(key.vault_on_key(&id), Some(want.clone()));
        assert_eq!(open.contents, want);

        let s = saved(
            &mut key,
            &mut auth,
            &mut open,
            &Change::Delete { before: b.clone() },
        );
        assert_eq!((s.added, s.replaced, s.removed), (0, 0, 1));
        let want = Vault {
            entries: vec![a2, c],
        };
        assert_eq!(key.vault_on_key(&id), Some(want.clone()));
        assert_eq!(open.contents, want);
        // The unlock's token served every write: none was taken after it.
        assert_eq!(
            key.log[unlocked_at..]
                .iter()
                .filter(|c| matches!(c, Call::Token { .. }))
                .count(),
            0
        );
    }

    #[test]
    fn saving_into_a_vault_without_data_stores_it() {
        let mut key = FakeKey::new();
        let id = key.add_credential(user_handle("Work").unwrap(), Some("Work"));
        let (mut auth, mut open) = open_first(&mut key);
        assert!(!open.stored);
        let e = entry("GitHub");
        saved(&mut key, &mut auth, &mut open, &Change::Add(e.clone()));
        assert!(open.stored);
        assert_eq!(key.vault_on_key(&id), Some(Vault { entries: vec![e] }));
    }

    #[test]
    fn vault_data_gone_since_unlock_is_refused_on_every_save() {
        let a = entry("GitHub");
        let seeded = Vault {
            entries: vec![a.clone()],
        };
        for change in [
            Change::Add(entry("Mail")),
            Change::Import {
                incoming: Vault {
                    entries: vec![entry("Bank")],
                },
                chosen: vec![0],
            },
            Change::Delete { before: a.clone() },
        ] {
            let mut key = FakeKey::new();
            key.add_foreign_entries();
            let id = key.add_vault("Personal", &seeded);
            // Another writer deletes or rotates this vault after our unlock:
            // its data leaves the store.
            let lbk = lbk_of(&key, &id);
            key.hook = Some((
                1,
                Box::new(move |k: &mut FakeKey| {
                    let rest = k.array().without_credential_blob(&lbk);
                    k.set_array(&rest);
                }),
            ));
            let (mut auth, mut open) = open_first(&mut key);
            assert!(open.stored);
            let stored = key.stored().to_vec();

            let before = open.contents.clone();

            // Saved twice on the same open vault (a front end's retry): the
            // vault is still gone, so both are refused and nothing is
            // written, never an empty vault no credential finds.
            for attempt in 1..=2 {
                let (r, steps) = save_with(&mut key, &mut auth, &mut open, &change);
                assert!(
                    matches!(&r, Err(VaultKeyError::VaultGone { name: Some(n) }) if n == "Personal"),
                    "{change:?} attempt {attempt}: {r:?}"
                );
                assert_eq!(writes(&key), 0, "{change:?} attempt {attempt}");
                assert!(steps.is_empty());
                assert_eq!(key.stored(), &stored[..], "no orphan blob");
                // Not reloaded as an empty vault.
                assert!(open.stored);
                assert_eq!(open.contents, before);
            }
        }
    }

    #[test]
    fn an_edit_keeps_the_entry_id() {
        let a = entry("GitHub");
        let base = Vault {
            entries: vec![a.clone()],
        };
        let mut after = edited(&a, "x");
        after.id = keyroost_vault::new_id();
        let (v, _, replaced, _) = apply_change(
            &base,
            &base,
            &Change::Edit {
                before: a.clone(),
                after: after.clone(),
            },
        )
        .unwrap();
        assert_eq!(replaced, 1);
        assert_eq!(v.entries.len(), 1);
        assert_eq!(v.entries[0].id, a.id);
        assert_eq!(*v.entries[0].password, "x");
        assert_eq!(v.entries[0].modified_minutes, after.modified_minutes);
    }

    #[test]
    fn apply_change_rules() {
        let (a, b) = (entry("GitHub"), entry("Mail"));
        let base = Vault {
            entries: vec![a.clone(), b.clone()],
        };
        let conflict = |r: Result<(Vault, usize, usize, usize), VaultKeyError>| {
            matches!(r, Err(VaultKeyError::Conflict))
        };

        // Add: an id already there is a conflict.
        assert!(conflict(apply_change(
            &base,
            &base,
            &Change::Add(a.clone())
        )));

        // Edit: the entry must still be as it was read.
        let a2 = edited(&a, "x");
        let edit = Change::Edit {
            before: a.clone(),
            after: a2.clone(),
        };
        let (v, ..) = apply_change(&base, &base, &edit).unwrap();
        assert_eq!(v.entries, vec![a2.clone(), b.clone()], "replaced in place");
        let gone = Vault {
            entries: vec![b.clone()],
        };
        assert!(
            conflict(apply_change(&base, &gone, &edit)),
            "deleted meanwhile"
        );
        let changed = Vault {
            entries: vec![edited(&a, "y"), b.clone()],
        };
        assert!(conflict(apply_change(&base, &changed, &edit)));

        // Delete: gone already is nothing to do; changed is a conflict.
        let delete = Change::Delete { before: a.clone() };
        let (v, added, replaced, removed) = apply_change(&base, &gone, &delete).unwrap();
        assert_eq!((v, added, replaced, removed), (gone.clone(), 0, 0, 0));
        assert!(conflict(apply_change(&base, &changed, &delete)));

        // Ids match in their canonical form: a format-1 UUID id is the same
        // entry as its shortened form.
        let mut uuid = entry("Old");
        uuid.id = "01234567-89ab-cdef-0123-456789abcdef".into();
        let mut short = uuid.clone();
        short.id = canon_id(&uuid.id);
        let current = Vault {
            entries: vec![uuid.clone()],
        };
        assert!(conflict(apply_change(
            &current,
            &current,
            &Change::Add(short.clone())
        )));
        let (v, _, replaced, _) = apply_change(
            &current,
            &current,
            &Change::Edit {
                before: uuid.clone(),
                after: edited(&uuid, "z"),
            },
        )
        .unwrap();
        assert_eq!(replaced, 1);
        assert_eq!(v.entries.len(), 1);
    }

    #[test]
    fn another_writers_change_to_a_different_entry_is_kept() {
        let mut key = FakeKey::new();
        let (a, b) = (entry("GitHub"), entry("Mail"));
        let id = key.add_vault(
            "Personal",
            &Vault {
                entries: vec![a.clone(), b.clone()],
            },
        );
        let b2 = edited(&b, "theirs");
        let theirs = b2.clone();
        other_writer(&mut key, &id, move |v| v.entries[1] = theirs);
        let (mut auth, mut open) = open_first(&mut key);
        assert_eq!(open.contents.entries[1], b, "unlock read before the hook");

        let a2 = edited(&a, "ours");
        saved(
            &mut key,
            &mut auth,
            &mut open,
            &Change::Edit {
                before: a,
                after: a2.clone(),
            },
        );
        let want = Vault {
            entries: vec![a2, b2],
        };
        assert_eq!(key.vault_on_key(&id), Some(want.clone()));
        assert_eq!(open.contents, want);
    }

    #[test]
    fn same_entry_changed_on_both_sides_is_a_conflict() {
        let mut key = FakeKey::new();
        let (a, b) = (entry("GitHub"), entry("Mail"));
        let id = key.add_vault(
            "Personal",
            &Vault {
                entries: vec![a.clone(), b.clone()],
            },
        );
        let theirs = edited(&a, "theirs");
        let t = theirs.clone();
        other_writer(&mut key, &id, move |v| v.entries[0] = t);
        let (mut auth, mut open) = open_first(&mut key);
        let stored = key.stored().to_vec();

        let (r, steps) = save_with(
            &mut key,
            &mut auth,
            &mut open,
            &Change::Edit {
                before: a.clone(),
                after: edited(&a, "ours"),
            },
        );
        assert!(matches!(r, Err(VaultKeyError::Conflict)), "{r:?}");
        assert_eq!(writes(&key), 0);
        assert!(steps.is_empty());
        assert_eq!(key.stored(), &stored[..], "nothing written");
        // Refuse and reload: the open vault now holds what the key holds.
        let on_key = key.vault_on_key(&id).unwrap();
        assert_eq!(on_key.entries, vec![theirs, b]);
        assert_eq!(open.contents, on_key);
    }

    #[test]
    fn rereads_immediately_before_writing() {
        let mut key = FakeKey::new();
        let a = entry("GitHub");
        key.add_vault(
            "Personal",
            &Vault {
                entries: vec![a.clone()],
            },
        );
        let (mut auth, mut open) = open_first(&mut key);
        saved(&mut key, &mut auth, &mut open, &Change::Add(entry("Mail")));
        key.write_refusals.push_back(0x33);
        let a2 = edited(&a, "x");
        saved(
            &mut key,
            &mut auth,
            &mut open,
            &Change::Edit {
                before: a,
                after: a2.clone(),
            },
        );
        saved(
            &mut key,
            &mut auth,
            &mut open,
            &Change::Delete { before: a2 },
        );
        assert_eq!(writes(&key), 4);
        for (i, call) in key.log.iter().enumerate() {
            if *call == Call::Write {
                assert_eq!(key.log[i - 1], Call::Read, "call {i} in {:?}", key.log);
            }
        }
    }

    #[test]
    fn other_entries_in_the_array_survive_every_save() {
        let mut key = FakeKey::new();
        key.add_foreign_entries();
        let work = key.add_vault(
            "Work",
            &Vault {
                entries: vec![entry("Jira")],
            },
        );
        let a = entry("GitHub");
        let id = key.add_vault(
            "Personal",
            &Vault {
                entries: vec![a.clone()],
            },
        );
        let (mut auth, mut u) = {
            let mut auth = pin();
            let u = unlock(&mut key, &mut auth, &mut |_| {}).unwrap_or_else(|e| panic!("{e}"));
            (auth, u)
        };
        let open = u.vaults[1].open_mut().unwrap();
        assert_eq!(open.vault_ref.credential_id, id);
        let rest = all_but(&key, &id);
        let work_before = key.vault_on_key(&work);

        let b = entry("Mail");
        let a2 = edited(&a, "x");
        for change in [
            Change::Add(b.clone()),
            Change::Edit {
                before: a.clone(),
                after: a2.clone(),
            },
            Change::Delete { before: b },
        ] {
            saved(&mut key, &mut auth, open, &change);
            assert_eq!(all_but(&key, &id), rest, "after {change:?}");
            assert_eq!(key.vault_on_key(&work), work_before);
        }
        assert_eq!(key.vault_on_key(&id), Some(Vault { entries: vec![a2] }));
        assert_eq!(key.array().len(), 5, "three foreign entries, two vaults");
    }

    /// A first write the key refuses with `code` gets one fresh
    /// largeBlobWrite token, a re-read and one more write.
    fn refused_once_then_saved(code: u8) {
        let mut key = FakeKey::new();
        let a = entry("GitHub");
        let id = key.add_vault(
            "Personal",
            &Vault {
                entries: vec![a.clone()],
            },
        );
        let (mut auth, mut open) = open_first(&mut key);
        let from = key.log.len();
        key.write_refusals.push_back(code);
        let a2 = edited(&a, "x");
        let (r, steps) = save_with(
            &mut key,
            &mut auth,
            &mut open,
            &Change::Edit {
                before: a,
                after: a2.clone(),
            },
        );
        r.unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            key.log[from..],
            [
                Call::Read,
                Call::Write,
                Call::Token {
                    perms: LBW,
                    rp: None
                },
                Call::Read,
                Call::Write,
            ]
        );
        assert_eq!(steps, vec![VaultStep::Write, VaultStep::Write]);
        assert_eq!(key.vault_on_key(&id), Some(Vault { entries: vec![a2] }));
        assert_eq!(key.write_perms.last(), Some(&LBW));
    }

    #[test]
    fn stale_pin_auth_gets_one_fresh_token() {
        refused_once_then_saved(0x33);
    }

    #[test]
    fn expired_token_gets_one_fresh_token() {
        refused_once_then_saved(0x38);
    }

    #[test]
    fn second_refusal_is_an_error() {
        let mut key = FakeKey::new();
        let id = key.add_vault("Personal", &Vault::default());
        let (mut auth, mut open) = open_first(&mut key);
        key.write_refusals.extend([0x33, 0x33]);
        let (r, _) = save_with(&mut key, &mut auth, &mut open, &Change::Add(entry("A")));
        assert!(
            matches!(r, Err(VaultKeyError::Ctap(CtapError::StatusCode(0x33)))),
            "{r:?}"
        );
        assert_eq!(writes(&key), 2);
        assert_eq!(key.vault_on_key(&id), Some(Vault::default()));
        assert_eq!(open.contents, Vault::default(), "nothing was saved");
    }

    #[test]
    fn wrong_pin_status_is_not_retried() {
        let mut key = FakeKey::new();
        key.add_vault("Personal", &Vault::default());
        let (mut auth, mut open) = open_first(&mut key);
        let from = key.log.len();
        key.write_refusals.push_back(0x31);
        let (r, _) = save_with(&mut key, &mut auth, &mut open, &Change::Add(entry("A")));
        assert!(
            matches!(r, Err(VaultKeyError::Ctap(CtapError::StatusCode(0x31)))),
            "{r:?}"
        );
        assert_eq!(key.log[from..], [Call::Read, Call::Write]);
    }

    #[test]
    fn token_without_the_permission_is_not_used() {
        let mut key = FakeKey::new();
        let id = key.add_vault("Personal", &Vault::default());
        let (mut auth, mut open) = open_first(&mut key);
        auth.fresh_token(&mut key, CM, None)
            .unwrap_or_else(|e| panic!("{e}"));
        let from = key.log.len();
        let e = entry("A");
        saved(&mut key, &mut auth, &mut open, &Change::Add(e.clone()));
        assert_eq!(
            key.log[from..],
            [
                Call::Token {
                    perms: LBW,
                    rp: None
                },
                Call::Read,
                Call::Write,
            ]
        );
        assert_eq!(key.write_perms, vec![LBW], "no refused write spent");
        assert_eq!(key.vault_on_key(&id), Some(Vault { entries: vec![e] }));
    }

    #[test]
    fn full_store_refuses_before_writing() {
        let mut key = FakeKey::new();
        key.set_max_bytes(1024);
        let a = entry("GitHub");
        let id = key.add_vault(
            "Personal",
            &Vault {
                entries: vec![a.clone()],
            },
        );
        let (mut auth, mut open) = open_first(&mut key);
        let stored = key.stored().to_vec();
        let mut big = entry("Recovery codes");
        // Random text, so it does not compress below the limit.
        big.notes = (0..250).map(|_| keyroost_vault::new_id()).collect();

        let (r, steps) = save_with(&mut key, &mut auth, &mut open, &Change::Add(big));
        match r {
            Err(VaultKeyError::Full { needed, max }) => {
                assert_eq!(max, 1024);
                assert!(needed > 1024, "{needed}");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(writes(&key), 0);
        assert!(steps.is_empty());
        assert_eq!(key.stored(), &stored[..]);
        assert_eq!(open.contents.entries, vec![a.clone()]);
        assert_eq!(key.vault_on_key(&id), Some(Vault { entries: vec![a] }));
    }

    #[test]
    fn save_refuses_a_vault_it_cannot_open() {
        let mut key = FakeKey::new();
        key.add_foreign_entries();
        let id = key.add_vault(
            "Personal",
            &Vault {
                entries: vec![entry("GitHub")],
            },
        );
        // A newer app saves the vault in a format version this one can't
        // read, between our unlock and our save.
        let target = id.clone();
        key.hook = Some((
            1,
            Box::new(move |k: &mut FakeKey| {
                let hmac = k.creds.iter().find(|c| c.id == target).unwrap().hmac;
                let mut blob = seal(&Vault::default(), &hmac).unwrap();
                blob[5] = 2;
                k.put_blob(&target, &blob);
            }),
        ));
        let (mut auth, mut open) = open_first(&mut key);
        let stored = key.stored().to_vec();
        let before = open.contents.clone();

        let (r, steps) = save_with(&mut key, &mut auth, &mut open, &Change::Add(entry("A")));
        assert!(
            matches!(
                r,
                Err(VaultKeyError::CannotOpen(VaultProblem::Damaged(
                    VaultError::UnsupportedVersion(2)
                )))
            ),
            "{r:?}"
        );
        assert_eq!(writes(&key), 0);
        assert!(steps.is_empty());
        assert_eq!(key.stored(), &stored[..], "the newer data is untouched");
        assert_eq!(open.contents, before);
    }

    #[test]
    fn import_applies_only_chosen() {
        let mut key = FakeKey::new();
        let (a, b) = (entry("GitHub"), entry("Mail"));
        let id = key.add_vault(
            "Personal",
            &Vault {
                entries: vec![a.clone(), b.clone()],
            },
        );
        let (mut auth, mut open) = open_first(&mut key);
        let (a2, b2) = (edited(&a, "backup"), edited(&b, "backup"));
        let (c, d) = (entry("Bank"), entry("Shop"));
        let incoming = Vault {
            entries: vec![a2.clone(), b2, c.clone(), d],
        };
        let s = saved(
            &mut key,
            &mut auth,
            &mut open,
            &Change::Import {
                incoming,
                chosen: vec![0, 2],
            },
        );
        assert_eq!((s.added, s.replaced, s.removed), (1, 1, 0));
        let want = Vault {
            entries: vec![a2, b, c],
        };
        assert_eq!(key.vault_on_key(&id), Some(want.clone()));
        assert_eq!(open.contents, want);
    }

    #[test]
    fn import_conflicts_when_a_chosen_entry_changed_on_the_key() {
        let (a, b) = (entry("GitHub"), entry("Mail"));
        let seeded = Vault {
            entries: vec![a.clone(), b.clone()],
        };
        let c = entry("Bank");
        let incoming = Vault {
            entries: vec![edited(&a, "backup"), c.clone()],
        };
        let import = |chosen: Vec<usize>| Change::Import {
            incoming: incoming.clone(),
            chosen,
        };

        // A chosen entry edited on the key meanwhile: refused and reloaded.
        let mut key = FakeKey::new();
        let id = key.add_vault("Personal", &seeded);
        let theirs = edited(&a, "theirs");
        let t = theirs.clone();
        other_writer(&mut key, &id, move |v| v.entries[0] = t);
        let (mut auth, mut open) = open_first(&mut key);
        let (r, _) = save_with(&mut key, &mut auth, &mut open, &import(vec![0, 1]));
        assert!(matches!(r, Err(VaultKeyError::Conflict)), "{r:?}");
        assert_eq!(writes(&key), 0);
        assert_eq!(open.contents.entries, vec![theirs.clone(), b.clone()]);

        // A chosen entry new at unlock that another writer added since (the
        // same backup imported elsewhere, say): what the plan said would be
        // added is no longer new, so it is refused too.
        let mut key = FakeKey::new();
        let id = key.add_vault("Personal", &seeded);
        let mut c_theirs = edited(&c, "theirs");
        c_theirs.title = "Bank (theirs)".into();
        let ct = c_theirs.clone();
        other_writer(&mut key, &id, move |v| v.entries.push(ct));
        let (mut auth, mut open) = open_first(&mut key);
        let (r, _) = save_with(&mut key, &mut auth, &mut open, &import(vec![1]));
        assert!(matches!(r, Err(VaultKeyError::Conflict)), "{r:?}");
        assert_eq!(writes(&key), 0);

        // An entry changed on the key but not chosen does not matter.
        let mut key = FakeKey::new();
        let id = key.add_vault("Personal", &seeded);
        let b_theirs = edited(&b, "theirs");
        let bt = b_theirs.clone();
        other_writer(&mut key, &id, move |v| v.entries[1] = bt);
        let (mut auth, mut open) = open_first(&mut key);
        let s = saved(&mut key, &mut auth, &mut open, &import(vec![0]));
        assert_eq!((s.added, s.replaced), (0, 1));
        assert_eq!(
            key.vault_on_key(&id).unwrap().entries,
            vec![edited(&a, "backup"), b_theirs]
        );
    }

    // ----- which entry is a vault's, clones, reloading -----

    #[test]
    fn holds_entry_finds_only_its_own_entry() {
        let mut key = FakeKey::new();
        key.add_vault(
            "Personal",
            &Vault {
                entries: vec![entry("GitHub")],
            },
        );
        key.add_foreign_entries();
        key.add_vault("Work", &Vault::default());
        let u = unlocked(&mut key);
        let array = key.array();
        let entries = array.entries();
        assert_eq!(entries.len(), 5, "two vaults and three foreign entries");
        let mut held_by = vec![Vec::new(); entries.len()];
        for (v, vault) in u.vaults.iter().enumerate() {
            let open = opened(vault);
            let held: Vec<usize> = (0..entries.len())
                .filter(|&i| open.holds_entry(entries[i]))
                .collect();
            assert_eq!(held.len(), 1, "{:?}: {held:?}", vault.vault_ref.name);
            held_by[held[0]].push(v);
        }
        // Personal's entry first, then the three foreign ones, then Work's.
        assert_eq!(
            held_by,
            vec![vec![0], vec![], vec![], vec![], vec![1]],
            "never a foreign entry"
        );
    }

    #[test]
    fn a_cloned_open_vault_saves_like_the_original() {
        let mut key = FakeKey::new();
        let a = entry("GitHub");
        let id = key.add_vault(
            "Personal",
            &Vault {
                entries: vec![a.clone()],
            },
        );
        let (mut auth, open) = open_first(&mut key);
        let mut copy = open.clone();
        let b = entry("Mail");
        let s = saved(&mut key, &mut auth, &mut copy, &Change::Add(b.clone()));
        assert_eq!(s.added, 1);
        let both = Vault {
            entries: vec![a.clone(), b],
        };
        assert_eq!(key.vault_on_key(&id), Some(both.clone()));
        assert_eq!(copy.contents, both);
        assert_eq!(open.contents.entries, vec![a], "the original is unchanged");
        // A whole unlock clones too, secrets and all.
        let mut u = unlocked(&mut key);
        let again = u.clone();
        assert_eq!(
            opened(&again.vaults[0]).secrets(),
            opened(&u.vaults[0]).secrets()
        );
        u.vaults.clear();
        assert_eq!(again.vaults.len(), 1);
    }

    /// What a reload may change, for comparing before and after.
    type View = (Vec<Result<(Vault, bool), VaultProblem>>, BlobCapacity);

    fn view(u: &Unlocked) -> View {
        let vaults = u
            .vaults
            .iter()
            .map(|v| match &v.state {
                Ok(o) => Ok((o.contents.clone(), o.stored)),
                Err(p) => Err(p.clone()),
            })
            .collect();
        (vaults, u.capacity)
    }

    /// Personal (with GitHub) and Work (with Mail), and their IDs.
    fn two_vaults(key: &mut FakeKey) -> (Vec<u8>, Vec<u8>) {
        let p = key.add_vault(
            "Personal",
            &Vault {
                entries: vec![entry("GitHub")],
            },
        );
        let w = key.add_vault(
            "Work",
            &Vault {
                entries: vec![entry("Mail")],
            },
        );
        (p, w)
    }

    #[test]
    fn reload_reads_another_writers_change_without_pin_or_touch() {
        let mut key = FakeKey::new();
        let (p, _) = two_vaults(&mut key);
        other_writer(&mut key, &p, |v| {
            v.entries[0].username = "bob".into();
        });
        let mut u = unlocked(&mut key);
        assert_eq!(opened(&u.vaults[0]).contents.entries[0].username, "alice");
        let work = opened(&u.vaults[1]).contents.clone();
        key.log.clear();

        reload(&mut key, &mut u).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(key.log, vec![Call::Read], "no token, no assertion");
        assert_eq!(opened(&u.vaults[0]).contents.entries[0].username, "bob");
        assert_eq!(
            Some(&opened(&u.vaults[0]).contents),
            key.vault_on_key(&p).as_ref()
        );
        assert_eq!(opened(&u.vaults[1]).contents, work);
    }

    #[test]
    fn reload_reports_a_vanished_vault_and_changes_nothing() {
        let mut key = FakeKey::new();
        let (p, w) = two_vaults(&mut key);
        // After the unlock's read: Personal is edited, Work deleted
        // elsewhere. Personal comes first, so a reload that changed vaults
        // as it went would already have taken the edit.
        let lbk = lbk_of(&key, &w);
        key.hook = Some((
            1,
            Box::new(move |k: &mut FakeKey| {
                let mut v = k.vault_on_key(&p).expect("the vault opens");
                v.entries[0].username = "bob".into();
                k.put_vault(&p, &v);
                let rest = k.array().without_credential_blob(&lbk);
                k.set_array(&rest);
            }),
        ));
        let mut u = unlocked(&mut key);
        let before = view(&u);
        key.log.clear();

        let r = reload(&mut key, &mut u);
        assert!(
            matches!(&r, Err(VaultKeyError::VaultGone { name: Some(n) }) if n == "Work"),
            "{r:?}"
        );
        assert_eq!(key.log, vec![Call::Read]);
        assert_eq!(view(&u), before, "nothing changed");
    }

    #[test]
    fn reload_marks_a_damaged_vault() {
        let mut key = FakeKey::new();
        let (p, w) = two_vaults(&mut key);
        // A newer app saves Work in a format version this one can't read.
        let target = w.clone();
        key.hook = Some((
            1,
            Box::new(move |k: &mut FakeKey| {
                let hmac = k.creds.iter().find(|c| c.id == target).unwrap().hmac;
                let mut blob = seal(&Vault::default(), &hmac).unwrap();
                blob[5] = 2;
                k.put_blob(&target, &blob);
            }),
        ));
        let mut u = unlocked(&mut key);
        let personal = opened(&u.vaults[0]).contents.clone();

        reload(&mut key, &mut u).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(opened(&u.vaults[0]).contents, personal);
        assert_eq!(key.vault_on_key(&p), Some(personal));
        assert_eq!(
            u.vaults[1].state.as_ref().err(),
            Some(&VaultProblem::Damaged(VaultError::UnsupportedVersion(2)))
        );
        // A vault that is already a problem stays one.
        reload(&mut key, &mut u).unwrap_or_else(|e| panic!("{e}"));
        assert!(u.vaults[0].state.is_ok());
        assert_eq!(
            u.vaults[1].state.as_ref().err(),
            Some(&VaultProblem::Damaged(VaultError::UnsupportedVersion(2)))
        );
    }

    #[test]
    fn reload_updates_capacity() {
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        key.hook = Some((
            1,
            Box::new(|k: &mut FakeKey| {
                k.add_foreign_entries();
            }),
        ));
        let mut u = unlocked(&mut key);
        assert_eq!(u.capacity.entry_count, 2);

        reload(&mut key, &mut u).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(u.capacity, key.array().capacity(&key.info));
        assert_eq!(u.capacity.entry_count, 5);
        assert!(u.vaults.iter().all(|v| v.state.is_ok()));
    }

    #[test]
    fn changes_and_results_are_send() {
        fn send<T: Send>() {}
        send::<Change>();
        send::<Saved>();
    }

    // ----- fingerprint -----

    use super::super::fake::asks;
    use keyroost_ctap::client_pin::{FingerAsk, Verified};
    use keyroost_ctap::FingerprintError;

    use keyroost_ctap::client_pin::permissions::MAKE_CREDENTIAL as MC;

    /// What one fingerprint token carries in a vault flow.
    const FINGER: u32 = CM | GA | MC | LBW;

    fn no_pin_token(key: &FakeKey) -> bool {
        key.log.iter().all(|c| !matches!(c, Call::Token { .. }))
    }

    #[test]
    fn a_fingerprint_unlock_takes_uv_tokens_only_and_opens_the_vaults() {
        let mut key = FakeKey::with_fingerprint();
        let personal = Vault {
            entries: vec![entry("GitHub"), entry("Mail")],
        };
        key.add_vault("Personal", &personal);
        key.add_vault("Work", &Vault::default());
        let (asked, ask) = asks();
        let mut auth = VaultAuth::fingerprint(ask);

        let (r, steps) = run(&mut key, &mut auth);
        let u = r.unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(steps, vec![VaultStep::UnlockTouch]);
        assert!(no_pin_token(&key), "{:?}", key.log);
        // One token for the listing and the touch: every permission a
        // vault step needs, bound to the vault RP.
        assert_eq!(
            key.log,
            vec![
                Call::UvToken {
                    perms: FINGER,
                    rp: Some(RP_ID.into())
                },
                Call::Credentials,
                Call::Assertions(None),
                Call::Read,
            ]
        );
        assert_eq!(*asked.lock().unwrap(), [FingerAsk::Unlock]);
        assert_eq!(key.fingers, 1);
        // The same hmac-secret whichever way the token came, so the vault
        // a PIN unlock sealed opens.
        assert_eq!(opened(&u.vaults[0]).contents, personal);
        assert_eq!(opened(&u.vaults[1]).contents, Vault::default());
        assert_eq!(auth.verified(), Some(Verified::Fingerprint));
    }

    #[test]
    fn a_key_that_drops_the_token_asks_the_finger_again_and_says_why() {
        let mut key = FakeKey::with_fingerprint();
        key.drops_token_after_presence = true;
        let id = key.add_vault("Personal", &Vault::default());
        let (asked, ask) = asks();
        let mut auth = VaultAuth::fingerprint(ask);
        let mut u = unlock(&mut key, &mut auth, &mut |_| {}).unwrap_or_else(|e| panic!("{e}"));
        let mut open = u.vaults.remove(0).state.unwrap_or_else(|p| panic!("{p}"));
        let from = key.log.len();

        let a = entry("GitHub");
        let (r, steps) = save_with(&mut key, &mut auth, &mut open, &Change::Add(a.clone()));
        r.unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            key.log[from..],
            [
                Call::Read,
                Call::Write,
                Call::UvToken {
                    perms: FINGER,
                    rp: Some(RP_ID.into())
                },
                Call::Read,
                Call::Write,
            ]
        );
        assert_eq!(steps, vec![VaultStep::Write, VaultStep::Write]);
        assert_eq!(
            *asked.lock().unwrap(),
            [FingerAsk::Unlock, FingerAsk::Again]
        );
        assert!(no_pin_token(&key));
        assert_eq!(key.vault_on_key(&id), Some(Vault { entries: vec![a] }));
        assert_eq!(auth.verified(), Some(Verified::Fingerprint));
    }

    #[test]
    fn a_stale_listing_token_asks_the_finger_again() {
        let mut key = FakeKey::with_fingerprint();
        key.add_vault("Personal", &Vault::default());
        let (asked, ask) = asks();
        let mut auth = VaultAuth::fingerprint(ask);
        auth.fresh_token(&mut key, CM, None)
            .unwrap_or_else(|e| panic!("{e}"));
        // Another token from elsewhere invalidates the one held.
        key.pin_token(FakeKey::PIN, LBW, None).unwrap();
        key.log.clear();
        run(&mut key, &mut auth).0.unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            key.log,
            [
                Call::Credentials,
                Call::UvToken {
                    perms: FINGER,
                    rp: Some(RP_ID.into())
                },
                Call::Credentials,
                Call::Assertions(None),
                Call::Read,
            ]
        );
        assert_eq!(
            *asked.lock().unwrap(),
            [FingerAsk::Unlock, FingerAsk::Again]
        );
    }

    #[test]
    fn auto_uses_the_pin_on_a_key_without_a_fingerprint() {
        let mut key = FakeKey::new();
        key.add_vault("Personal", &Vault::default());
        let (asked, ask) = asks();
        let mut auth = VaultAuth::auto(Some(Zeroizing::new(FakeKey::PIN.to_owned())), ask);
        let (r, _) = run(&mut key, &mut auth);
        r.unwrap_or_else(|e| panic!("{e}"));
        assert!(
            key.log.iter().all(|c| !matches!(c, Call::UvToken { .. })),
            "{:?}",
            key.log
        );
        assert_eq!(
            key.log
                .iter()
                .filter(|c| matches!(c, Call::Token { .. }))
                .count(),
            2
        );
        assert!(asked.lock().unwrap().is_empty());
        assert_eq!(key.fingers, 0);
        assert_eq!(auth.verified(), Some(Verified::Pin));
    }

    #[test]
    fn auto_falls_back_to_the_pin_after_a_refusal_and_keeps_it() {
        let mut key = FakeKey::with_fingerprint();
        key.add_vault("Personal", &Vault::default());
        key.uv_refusals.push_back(0x3F);
        let (asked, ask) = asks();
        let mut auth = VaultAuth::auto(Some(Zeroizing::new(FakeKey::PIN.to_owned())), ask);
        let mut u = unlock(&mut key, &mut auth, &mut |_| {}).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            key.log[..3],
            [
                Call::UvToken {
                    perms: FINGER,
                    rp: Some(RP_ID.into())
                },
                Call::Token {
                    perms: CM | LBW,
                    rp: None
                },
                Call::Credentials,
            ]
        );
        assert_eq!(key.uv_retries, 4);
        assert_eq!(auth.verified(), Some(Verified::Pin));
        // Every later token, in this flow and the next, comes from the PIN.
        let mut open = u.vaults.remove(0).state.unwrap_or_else(|p| panic!("{p}"));
        key.write_refusals.push_back(0x33);
        saved(&mut key, &mut auth, &mut open, &Change::Add(entry("A")));
        let uv = key
            .log
            .iter()
            .filter(|c| matches!(c, Call::UvToken { .. }))
            .count();
        assert_eq!(uv, 1, "{:?}", key.log);
        assert_eq!(
            key.log
                .iter()
                .filter(|c| matches!(c, Call::Token { .. }))
                .count(),
            3,
            "credential management, the touch, the renewed write token"
        );
        assert_eq!(*asked.lock().unwrap(), [FingerAsk::Unlock]);
        assert_eq!(auth.verified(), Some(Verified::Pin));
    }

    #[test]
    fn a_refused_fingerprint_without_a_pin_says_use_the_pin() {
        let mut key = FakeKey::with_fingerprint();
        key.add_vault("Personal", &Vault::default());
        key.uv_refusals.push_back(0x3F);
        let (asked, ask) = asks();
        let mut auth = VaultAuth::fingerprint(ask);
        let (r, steps) = run(&mut key, &mut auth);
        let Err(err) = r else { panic!("refused") };
        assert!(
            matches!(
                err,
                VaultKeyError::Ctap(CtapError::Fingerprint(FingerprintError::Refused(0x3F)))
            ),
            "{err:?}"
        );
        assert!(err.to_string().contains("use the PIN instead"), "{err}");
        assert!(steps.is_empty());
        assert!(no_pin_token(&key));
        assert_eq!(*asked.lock().unwrap(), [FingerAsk::Unlock]);
        assert_eq!(auth.verified(), None);
        assert!(auth.current_for(CM).is_none());
    }

    #[test]
    fn auto_without_a_pin_on_a_key_without_a_fingerprint_is_the_fingerprint_error() {
        let mut key = FakeKey::new();
        key.add_vault("Personal", &Vault::default());
        let (asked, ask) = asks();
        let mut auth = VaultAuth::auto(None, ask);
        let Err(err) = run(&mut key, &mut auth).0 else {
            panic!("refused")
        };
        assert!(
            matches!(
                err,
                VaultKeyError::Ctap(CtapError::Fingerprint(FingerprintError::NotOffered))
            ),
            "{err:?}"
        );
        assert!(key.log.is_empty(), "{:?}", key.log);
        assert!(asked.lock().unwrap().is_empty());
    }

    #[test]
    fn zero_retries_refuse_before_any_finger() {
        let mut key = FakeKey::with_fingerprint();
        key.add_vault("Personal", &Vault::default());
        key.uv_retries = 0;
        let (asked, ask) = asks();
        let mut auth = VaultAuth::fingerprint(ask);
        let Err(err) = run(&mut key, &mut auth).0 else {
            panic!("refused")
        };
        assert!(
            matches!(
                err,
                VaultKeyError::Ctap(CtapError::Fingerprint(FingerprintError::Blocked {
                    status: None
                }))
            ),
            "{err:?}"
        );
        assert!(asked.lock().unwrap().is_empty());
        assert_eq!(key.fingers, 0);
        assert!(no_pin_token(&key));
    }

    #[test]
    fn the_last_refusal_blocks_the_next_ask() {
        let mut key = FakeKey::with_fingerprint();
        key.add_vault("Personal", &Vault::default());
        key.uv_retries = 1;
        key.uv_refusals.push_back(0x3F);
        let (asked, ask) = asks();
        let mut auth = VaultAuth::fingerprint(ask);
        assert!(run(&mut key, &mut auth).0.is_err());
        assert_eq!(key.uv_retries, 0);
        let Err(err) = run(&mut key, &mut auth).0 else {
            panic!("blocked")
        };
        assert!(
            matches!(
                err,
                VaultKeyError::Ctap(CtapError::Fingerprint(FingerprintError::Blocked { .. }))
            ),
            "{err:?}"
        );
        assert_eq!(*asked.lock().unwrap(), [FingerAsk::Unlock]);
    }
}
