//! FIDO2 password vault sessions on a key.
//!
//! A vault is a discoverable credential under the vault relying party
//! ([`keyroost_vault::RP_ID`]) whose `hmac-secret` output seals the vault
//! and whose `largeBlobKey` finds its sealed entry in the key's largeBlob
//! array. The formats live in `keyroost-vault`; this module talks to the key.
//!
//! Every flow runs over the [`VaultKey`] seam: [`CtapVaultKey`] is the real
//! key, and the tests drive the same flows against an in-memory fake, so no
//! flow needs hardware to be checked. Nothing here prints or reads a
//! terminal: progress goes to the caller as [`VaultStep`]s and failures as
//! [`VaultKeyError`]s, both in plain words.

use std::fmt;

use keyroost_ctap::client_pin::permissions::LARGE_BLOB_WRITE;
use keyroost_ctap::client_pin::{FingerAsk, PinUvAuthToken, Verified};
use keyroost_ctap::get_assertion::vault_name_from_user_id;
use keyroost_ctap::{AuthenticatorInfo, CtapError};
use keyroost_vault::{VaultError, RP_ID};
use zeroize::Zeroizing;

mod key;
pub use key::{CtapVaultKey, VaultKey};

mod ops;
pub use ops::{
    matching, reload, save, unlock, Change, OpenVault, Saved, Unlocked, VaultOnKey, VaultPick,
};

mod lifecycle;
pub use lifecycle::{create, delete, list_credentials, rotate, Created};

#[cfg(any(test, feature = "vault-fake"))]
#[doc(hidden)]
pub mod fake;

/// Which vault, as the key names it. Front ends tell vaults apart by
/// `name`; the credential ID is carried for JSON output and for the calls
/// that act on one credential, never offered as a selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultRef {
    pub credential_id: Vec<u8>,
    /// The vault's name ([`vault_name`]); `None` when the credential
    /// carries none.
    pub name: Option<String>,
}

/// A vault credential as credential management lists it (no touch).
#[derive(Clone)]
pub struct VaultCredential {
    pub vault: VaultRef,
    /// The credential's largeBlobKey, when the key returned it.
    pub large_blob_key: Option<Zeroizing<[u8; 32]>>,
    /// What the key holds for this vault, told without unlocking it.
    pub stored: StoredData,
}

/// What the key holds for one vault credential, as far as can be told
/// without unlocking it: how vaults that share a name are told apart.
/// Deliberately exhaustive, so a front end handles every state and never
/// shows damaged data as no data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoredData {
    /// No data: the vault opens empty.
    Empty,
    /// Data of this many bytes (decrypted).
    Bytes(usize),
    /// Data sealed under the vault's largeBlobKey that does not decompress:
    /// damaged, never empty.
    Unreadable,
    /// Credential management gave no largeBlobKey for it, so the data could
    /// not be looked for.
    Unknown,
}

impl AsRef<VaultRef> for VaultCredential {
    fn as_ref(&self) -> &VaultRef {
        &self.vault
    }
}

// Hand-written so the largeBlobKey never lands in a log.
impl fmt::Debug for VaultCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultCredential")
            .field("vault", &self.vault)
            .field(
                "large_blob_key",
                &self.large_blob_key.as_ref().map(|_| "<redacted>"),
            )
            .field("stored", &self.stored)
            .finish()
    }
}

/// A step that waits on the person at the key, reported just before the
/// call that waits for it, so a front end can say what to do.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultStep {
    /// Touch to create the vault's credential (makeCredential).
    CreateTouch,
    /// Touch to unlock (getAssertion for the vault secret).
    UnlockTouch,
    /// The vault data is about to be written to the key.
    Write,
}

/// Why one vault on a key cannot be opened. Reported per vault, so one
/// that won't open never hides the others.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultProblem {
    /// The key returned no hmac-secret output or no largeBlobKey for it.
    NoSecret,
    /// Its stored data does not open (damaged, sealed under another secret,
    /// or written by a newer app).
    Damaged(VaultError),
}

impl fmt::Display for VaultProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultProblem::NoSecret => {
                f.write_str("the key did not return this vault's secret or its largeBlobKey")
            }
            VaultProblem::Damaged(e) => write!(f, "{e}"),
        }
    }
}

/// What a failed create could not remove again
/// ([`VaultKeyError::CreateUndone`]), so a front end can name the fix.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LeftOver {
    /// The new vault's credential is still on the key. It lists as a vault
    /// of the name asked for (with or without data, as `data` says), and
    /// deleting that vault removes it and its data:
    /// `keyroostctl fido vault delete NAME`.
    pub credential: bool,
    /// Data written for the new vault is still in the key's largeBlob store.
    /// With `credential` the vault delete above removes it too. Without, no
    /// credential can open or find it any more: `keyroostctl fido blob list`
    /// shows it as an opaque entry and `keyroostctl fido blob delete INDEX`
    /// removes it. Nothing tells it apart from another relying party's
    /// opaque entry, so a front end says so rather than guess an index.
    pub data: bool,
}

impl LeftOver {
    /// Nothing is left: the failed create was fully undone.
    pub const NONE: LeftOver = LeftOver {
        credential: false,
        data: false,
    };

    /// Whether anything is left on the key.
    pub fn any(&self) -> bool {
        self.credential || self.data
    }
}

/// What is left of the old vault after a rotate that made and checked the
/// new vault but could not delete the old one
/// ([`VaultKeyError::OldNotDeleted`]). The two share a name; the new one
/// always holds every checked entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OldVault {
    /// The old vault still holds the same checked entries as the new one
    /// (or both hold none), but one of the two still uses the old key and
    /// nothing tells which: delete either, then rotate the one left again
    /// so it ends up on a fresh key.
    Kept,
    /// The old vault's data is removed but its credential is left: it lists
    /// as a vault of the same name with no data, and that is the one to
    /// delete. Deleting the other would lose the entries.
    Emptied,
    /// The key stopped answering while the old data was being removed, so
    /// whether it is still there is not known. The copy with no data, if
    /// there is one, is the one to delete; when both hold data it is as
    /// [`OldVault::Kept`]: delete either, then rotate the one left again.
    Unknown,
}

impl OldVault {
    /// What to do about the copy left, in plain words that name no command
    /// (ruling: never "delete either" without rotating the one left again).
    pub fn next_step(self) -> &'static str {
        match self {
            OldVault::Kept => BOTH_COPIES,
            OldVault::Emptied => "the old copy is left with no data: delete the copy with no data",
            OldVault::Unknown => concat!(
                "whether the old copy still holds its data is not known: if a copy holds no data, ",
                "delete that one; otherwise both copies hold the same checked entries, but one ",
                "still uses the old key: delete either, then rotate the one left again so it ",
                "gets a fresh key"
            ),
        }
    }
}

/// [`OldVault::Kept`]'s next step, also the end of [`OldVault::Unknown`]'s.
const BOTH_COPIES: &str = "both copies hold the same checked entries, but one still uses the \
     old key: delete either, then rotate the one left again so it gets a fresh key";

/// Why a vault operation on a key failed.
#[non_exhaustive]
#[derive(Debug)]
pub enum VaultKeyError {
    /// The key refused or failed a command.
    Ctap(CtapError),
    /// The vault data or a vault name was refused.
    Vault(VaultError),
    /// The key lacks a capability a vault needs (named in the text).
    Unsupported(&'static str),
    /// The key supports a PIN but has none set; a vault needs one.
    PinNotSet,
    /// The key holds no vault.
    NoVaults,
    /// No vault on the key has this name.
    NotFound(String),
    /// A vault of this name is already on the key.
    DuplicateName(String),
    /// The key gave no largeBlobKey for the vault credential, so its data
    /// can be neither stored nor found.
    NoLargeBlobKey,
    /// The key returned a different largeBlobKey for the new credential at
    /// unlock than when it made it.
    KeyMismatch,
    /// Creating a vault failed after its credential was made; the
    /// credential and any data written for it were removed again, except
    /// what `left_over` names.
    CreateUndone {
        cause: Box<VaultKeyError>,
        left_over: LeftOver,
    },
    /// What this change touches was changed on the key since the vault was
    /// opened; nothing was written.
    Conflict,
    /// The vault's data, there when it was unlocked, is no longer on the
    /// key: another writer deleted or rotated the vault. Nothing was
    /// written, and every later save or rotate of the same open vault is
    /// refused the same way; unlock again to see what the key holds now.
    VaultGone { name: Option<String> },
    /// The large-blob store is too small for the result; nothing was
    /// written.
    Full { needed: u64, max: u64 },
    /// The vault cannot be opened, so it is not changed.
    CannotOpen(VaultProblem),
    /// A rotate's new vault did not read back with the old vault's entries.
    RotateNotVerified,
    /// The old vault changed on the key while its key was being rotated.
    ChangedDuringRotate,
    /// A rotate made and checked the new vault but could not delete the old
    /// one; `old` says what is left of it.
    OldNotDeleted {
        name: Option<String>,
        cause: Box<VaultKeyError>,
        old: OldVault,
    },
}

impl fmt::Display for VaultKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultKeyError::Ctap(e) => write!(f, "{e}"),
            VaultKeyError::Vault(e) => write!(f, "{e}"),
            VaultKeyError::Unsupported(what) => write!(
                f,
                "this key cannot hold a password vault: it does not support {what}"
            ),
            VaultKeyError::PinNotSet => {
                f.write_str("this key has no PIN set; a password vault needs one")
            }
            VaultKeyError::NoVaults => f.write_str("this key holds no vaults"),
            VaultKeyError::NotFound(name) => write!(f, "no vault named \"{name}\" on this key"),
            VaultKeyError::DuplicateName(name) => {
                write!(f, "this key already holds a vault named \"{name}\"")
            }
            VaultKeyError::NoLargeBlobKey => f.write_str(
                "the key did not return the vault's largeBlobKey, so its data cannot be stored or found",
            ),
            VaultKeyError::KeyMismatch => f.write_str(
                "the key returned a different largeBlobKey for the new vault than when it made it",
            ),
            VaultKeyError::CreateUndone { cause, left_over } => {
                write!(f, "the vault was not created: {cause}; ")?;
                f.write_str(match (left_over.credential, left_over.data) {
                    (false, false) => "its new credential was removed again",
                    (true, false) => {
                        "removing its new credential failed too, so it is left on the key with no data"
                    }
                    (false, true) => {
                        "its new credential was removed, but removing its data failed, so that data is left in the key's large-blob store with nothing to open it"
                    }
                    (true, true) => {
                        "cleaning up failed too, so its new credential and its data are still on the key"
                    }
                })
            }
            VaultKeyError::Conflict => f.write_str(
                "this changed on the key since the vault was opened; nothing was written",
            ),
            VaultKeyError::VaultGone { name } => {
                match name {
                    Some(n) => write!(f, "vault \"{n}\" is no longer on the key")?,
                    None => f.write_str("this vault is no longer on the key")?,
                }
                f.write_str("; it was deleted or rotated elsewhere, and nothing was written")
            }
            VaultKeyError::Full { needed, max } => write!(
                f,
                "the key's large-blob store is too small: this needs {needed} bytes, and it holds {max}; nothing was written"
            ),
            VaultKeyError::CannotOpen(p) => write!(f, "this vault cannot be opened: {p}"),
            VaultKeyError::RotateNotVerified => {
                f.write_str("the new vault did not read back with the same entries")
            }
            VaultKeyError::ChangedDuringRotate => {
                f.write_str("the vault changed on the key while its key was being rotated")
            }
            VaultKeyError::OldNotDeleted { name, cause, old } => {
                let which = match name {
                    Some(n) => format!("vault \"{n}\""),
                    None => "vault".to_owned(),
                };
                write!(
                    f,
                    "the new {which} is in place with every entry checked, but deleting the old one failed: {cause}; "
                )?;
                f.write_str(old.next_step())
            }
        }
    }
}

impl std::error::Error for VaultKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            VaultKeyError::Ctap(e) => Some(e),
            VaultKeyError::Vault(e) => Some(e),
            _ => None,
        }
    }
}

impl From<CtapError> for VaultKeyError {
    fn from(e: CtapError) -> Self {
        VaultKeyError::Ctap(e)
    }
}

impl From<VaultError> for VaultKeyError {
    fn from(e: VaultError) -> Self {
        VaultKeyError::Vault(e)
    }
}

/// How a vault flow proves the person may use the key. Holds the secret
/// (or the way to ask for a finger) and the pinUvAuthToken it last
/// obtained, with that token's permissions, so a flow can reuse a token
/// that still covers what it needs.
pub struct VaultAuth {
    method: Method,
    /// The current token, its permissions and the RP it was bound to.
    token: Option<(PinUvAuthToken, u32, Option<String>)>,
    /// How the last token obtained was obtained.
    verified: Option<Verified>,
}

/// The ways to obtain a token. Each method is a variant and a constructor;
/// the flows don't change, they only ask [`VaultAuth`] for a token.
enum Method {
    Pin(Zeroizing<String>),
    /// A fingerprint, asking through `ask` before each finger. With a
    /// `fallback` PIN, the first fingerprint error turns the method into
    /// `Pin(fallback)` for the life of this `VaultAuth`: every later token
    /// it obtains, in this flow and any later one, comes from the PIN. A new
    /// `VaultAuth` tries the finger again.
    Fingerprint {
        fallback: Option<Zeroizing<String>>,
        ask: Box<dyn FnMut(FingerAsk) + Send>,
    },
}

impl VaultAuth {
    fn with(method: Method) -> Self {
        VaultAuth {
            method,
            token: None,
            verified: None,
        }
    }

    /// Authenticate with the key's PIN.
    pub fn pin(pin: Zeroizing<String>) -> Self {
        VaultAuth::with(Method::Pin(pin))
    }

    /// Authenticate with a fingerprint only. `ask` runs right before the
    /// key waits for each finger, saying why it is asked
    /// ([`FingerAsk::Unlock`], or [`FingerAsk::Again`] when the key dropped
    /// the token it gave). A key that cannot take a finger, or refuses it,
    /// fails the flow with a [`CtapError::Fingerprint`] that points at the
    /// PIN.
    pub fn fingerprint(ask: Box<dyn FnMut(FingerAsk) + Send>) -> Self {
        VaultAuth::with(Method::Fingerprint {
            fallback: None,
            ask,
        })
    }

    /// A fingerprint, and the PIN when one is given and the finger is
    /// refused or cannot be asked (no fingerprint on the key, no tries
    /// left): from then on every token this `VaultAuth` obtains comes from
    /// the PIN; a new one tries the finger again. With no PIN, the same as
    /// [`fingerprint`](Self::fingerprint).
    pub fn auto(pin: Option<Zeroizing<String>>, ask: Box<dyn FnMut(FingerAsk) + Send>) -> Self {
        VaultAuth::with(Method::Fingerprint { fallback: pin, ask })
    }

    /// How the last token was obtained; `None` before the first one.
    pub fn verified(&self) -> Option<Verified> {
        self.verified
    }

    /// Obtain a new token with `permissions` (bound to `rp_id` when given)
    /// and keep it as the current one. A key that demands a PIN change is
    /// refused before the PIN is sent or a finger is asked for. A finger is
    /// asked for as [`FingerAsk::Unlock`]; after the key dropped a token,
    /// use [`renewed_token`](Self::renewed_token).
    pub(crate) fn fresh_token(
        &mut self,
        key: &mut impl VaultKey,
        permissions: u32,
        rp_id: Option<&str>,
    ) -> Result<&PinUvAuthToken, VaultKeyError> {
        self.obtain(key, permissions, rp_id, FingerAsk::Unlock)
    }

    /// [`fresh_token`](Self::fresh_token) after the key refused the held
    /// token (dropped or expired): a finger is asked for as
    /// [`FingerAsk::Again`], so the person learns why. The PIN path is the
    /// same as a fresh token.
    pub(crate) fn renewed_token(
        &mut self,
        key: &mut impl VaultKey,
        permissions: u32,
        rp_id: Option<&str>,
    ) -> Result<&PinUvAuthToken, VaultKeyError> {
        self.obtain(key, permissions, rp_id, FingerAsk::Again)
    }

    fn obtain(
        &mut self,
        key: &mut impl VaultKey,
        permissions: u32,
        rp_id: Option<&str>,
        why: FingerAsk,
    ) -> Result<&PinUvAuthToken, VaultKeyError> {
        if key.info().force_pin_change == Some(true) {
            return Err(CtapError::PinChangeRequired.into());
        }
        // A new token invalidates the old one on the key; drop ours first so
        // a failed request never leaves a stale one looking current.
        self.token = None;
        let got = match &mut self.method {
            Method::Pin(pin) => key
                .pin_token(pin, permissions, rp_id)
                .map(|t| (t, Verified::Pin)),
            Method::Fingerprint { ask, .. } => key
                .uv_token(permissions, rp_id, &mut || ask(why))
                .map(|t| (t, Verified::Fingerprint)),
        };
        let (token, verified) = match got {
            Err(CtapError::Fingerprint(e)) => match self.fall_back_to_pin() {
                Some(pin) => (key.pin_token(pin, permissions, rp_id)?, Verified::Pin),
                None => return Err(CtapError::Fingerprint(e).into()),
            },
            got => got?,
        };
        self.verified = Some(verified);
        let (token, _, _) = self
            .token
            .insert((token, permissions, rp_id.map(str::to_owned)));
        Ok(token)
    }

    /// Turn a fingerprint method with a fallback PIN into the PIN method for
    /// the life of this `VaultAuth`, and return that PIN. `None` when there
    /// is no PIN to fall back to, and always for the PIN method: a PIN that
    /// was just sent is never sent again as a fallback.
    fn fall_back_to_pin(&mut self) -> Option<&Zeroizing<String>> {
        let Method::Fingerprint { fallback, .. } = &mut self.method else {
            return None;
        };
        let pin = fallback.take()?;
        self.method = Method::Pin(pin);
        match &self.method {
            Method::Pin(pin) => Some(pin),
            Method::Fingerprint { .. } => unreachable!("just set to the PIN"),
        }
    }

    /// The current token, only when its permissions include every bit of
    /// `permissions`. The stored RP is not checked: largeBlobWrite and
    /// credential-management tokens are requested without one.
    pub(crate) fn current_for(&self, permissions: u32) -> Option<&PinUvAuthToken> {
        match &self.token {
            Some((token, held, _)) if held & permissions == permissions => Some(token),
            _ => None,
        }
    }

    /// Run one call that waits for a touch (makeCredential or getAssertion):
    /// a fresh token with `permissions`, bound to the vault RP, then `step`
    /// reported, then `call`, then the token cut as the key cuts it
    /// ([`after_presence`](Self::after_presence)), whatever `call` returned.
    /// Every touch in the vault flows goes through here, so no flow can
    /// forget the cut. A refused PIN or finger reports no step and makes no
    /// call.
    pub(crate) fn with_touch<K: VaultKey, T>(
        &mut self,
        key: &mut K,
        permissions: u32,
        step: VaultStep,
        on_step: &mut dyn FnMut(VaultStep),
        call: impl FnOnce(&mut K, &PinUvAuthToken) -> Result<T, CtapError>,
    ) -> Result<T, VaultKeyError> {
        let result = {
            let token = self.fresh_token(key, permissions, Some(RP_ID))?;
            on_step(step);
            call(key, token)
        };
        self.after_presence();
        Ok(result?)
    }

    /// Mirror the key after a makeCredential or getAssertion was sent with
    /// the current token: a CTAP 2.1 key then keeps only the token's
    /// largeBlobWrite permission (`clearPinUvAuthTokenPermissionsExceptLbw`),
    /// so [`current_for`](Self::current_for) must not offer it for anything
    /// else. Called whatever the call returned: an error does not say
    /// whether the key got that far, and a fresh token is the safe side.
    /// Only [`with_touch`](Self::with_touch) calls it.
    fn after_presence(&mut self) {
        if let Some((_, held, _)) = &mut self.token {
            *held &= LARGE_BLOB_WRITE;
        }
    }
}

// Hand-written so the PIN, the token and the ask callback never land in a
// log.
impl fmt::Debug for VaultAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let method = match &self.method {
            Method::Pin(_) => "pin <redacted>",
            Method::Fingerprint { fallback: None, .. } => "fingerprint",
            Method::Fingerprint {
                fallback: Some(_), ..
            } => "fingerprint, pin fallback <redacted>",
        };
        let token = self
            .token
            .as_ref()
            .map(|(_, perms, rp)| format!("<redacted> permissions {perms:#04x} rp {rp:?}"));
        f.debug_struct("VaultAuth")
            .field("method", &method)
            .field("token", &token)
            .field("verified", &self.verified)
            .finish()
    }
}

/// A vault credential's name: the one its user handle carries, else the
/// credential's user name, else none; an empty name is none. The one
/// naming rule for listing credentials and for unlocking.
pub fn vault_name(user_id: Option<&[u8]>, user_name: Option<&str>) -> Option<String> {
    user_id
        .and_then(vault_name_from_user_id)
        .or_else(|| user_name.map(str::to_owned))
        .filter(|n| !n.is_empty())
}

/// Whether `info` describes a key that can hold a vault: the `hmac-secret`,
/// `largeBlobKey` and `credProtect` extensions, largeBlobs, permission
/// tokens and credential management, and a PIN that is set.
pub fn check_support(info: &AuthenticatorInfo) -> Result<(), VaultKeyError> {
    for ext in ["hmac-secret", "largeBlobKey", "credProtect"] {
        if !info.extensions.iter().any(|e| e == ext) {
            return Err(VaultKeyError::Unsupported(ext));
        }
    }
    for (option, what) in [
        ("largeBlobs", "the large-blob store"),
        ("pinUvAuthToken", "CTAP 2.1 permission tokens"),
        ("credMgmt", "credential management"),
    ] {
        if info.option(option) != Some(true) {
            return Err(VaultKeyError::Unsupported(what));
        }
    }
    match info.option("clientPin") {
        Some(true) => Ok(()),
        Some(false) => Err(VaultKeyError::PinNotSet),
        None => Err(VaultKeyError::Unsupported("a PIN")),
    }
}

/// Now, in minutes since the Unix epoch: what an entry's
/// `modified_minutes` is stamped with.
pub fn now_minutes() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| (d.as_secs() / 60) as i64)
}

#[cfg(test)]
mod tests {
    use super::fake::{Call, FakeKey};
    use super::key::no_credentials_as_empty;
    use super::*;
    use keyroost_ctap::client_pin::permissions::{
        CREDENTIAL_MANAGEMENT as CM, GET_ASSERTION as GA, LARGE_BLOB_WRITE as LBW,
        MAKE_CREDENTIAL as MC,
    };
    use keyroost_ctap::client_pin::{PinUvAuthToken, Verified};
    use keyroost_ctap::get_assertion::Assertion;
    use keyroost_ctap::large_blobs::LargeBlobArray;
    use keyroost_ctap::FingerprintError;
    use keyroost_vault::{open, user_handle, Entry, Vault, RP_ID};
    use std::error::Error as _;

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

    /// `fresh_token`, a copy of the token on success (the token has no
    /// `Debug`, so `unwrap` is out).
    fn fresh(
        auth: &mut VaultAuth,
        key: &mut FakeKey,
        perms: u32,
        rp: Option<&str>,
    ) -> Result<PinUvAuthToken, VaultKeyError> {
        auth.fresh_token(key, perms, rp).cloned()
    }

    fn token(
        auth: &mut VaultAuth,
        key: &mut FakeKey,
        perms: u32,
        rp: Option<&str>,
    ) -> PinUvAuthToken {
        fresh(auth, key, perms, rp).unwrap_or_else(|e| panic!("{e}"))
    }

    #[test]
    fn support_requires_every_capability() {
        let full = FakeKey::new().info().clone();
        assert!(check_support(&full).is_ok());

        for ext in ["hmac-secret", "largeBlobKey", "credProtect"] {
            let mut info = full.clone();
            info.extensions.retain(|e| e != ext);
            assert!(
                matches!(check_support(&info), Err(VaultKeyError::Unsupported(_))),
                "without {ext}"
            );
        }
        for opt in ["largeBlobs", "pinUvAuthToken", "credMgmt", "clientPin"] {
            for missing in [None, Some(false)] {
                if opt == "clientPin" && missing == Some(false) {
                    continue;
                }
                let mut info = full.clone();
                info.options.retain(|(k, _)| k != opt);
                if let Some(v) = missing {
                    info.options.push((opt.into(), v));
                }
                assert!(
                    matches!(check_support(&info), Err(VaultKeyError::Unsupported(_))),
                    "{opt} = {missing:?}"
                );
            }
        }

        let mut no_pin = full.clone();
        no_pin.options.retain(|(k, _)| k != "clientPin");
        no_pin.options.push(("clientPin".into(), false));
        assert!(matches!(
            check_support(&no_pin),
            Err(VaultKeyError::PinNotSet)
        ));
    }

    #[test]
    fn forced_pin_change_is_refused_before_the_pin_is_sent() {
        let mut key = FakeKey::new();
        key.info.force_pin_change = Some(true);
        let mut auth = pin();
        let err = fresh(&mut auth, &mut key, GA, Some(RP_ID)).err().unwrap();
        assert!(matches!(
            err,
            VaultKeyError::Ctap(CtapError::PinChangeRequired)
        ));
        assert!(!key.log.iter().any(|c| matches!(c, Call::Token { .. })));
        assert!(auth.current_for(GA).is_none());
    }

    #[test]
    fn current_for_checks_permissions() {
        let mut key = FakeKey::new();
        let mut auth = pin();
        assert!(auth.current_for(LBW).is_none());
        token(&mut auth, &mut key, CM | LBW, None);
        assert_eq!(
            key.log,
            vec![Call::Token {
                perms: CM | LBW,
                rp: None
            }]
        );
        assert!(auth.current_for(LBW).is_some());
        assert!(auth.current_for(CM).is_some());
        assert!(auth.current_for(CM | LBW).is_some());
        assert!(auth.current_for(GA).is_none());
        assert!(auth.current_for(GA | LBW).is_none());
    }

    #[test]
    fn a_touch_cuts_the_token_on_success_and_on_failure() {
        for fail in [false, true] {
            let mut key = FakeKey::new();
            key.add_vault("Personal", &Vault::default());
            let mut auth = pin();
            let mut steps = Vec::new();
            let r = auth.with_touch(
                &mut key,
                GA | LBW,
                VaultStep::UnlockTouch,
                &mut |s| steps.push(s),
                |k, t| {
                    if fail {
                        Err(CtapError::StatusCode(0x2F))
                    } else {
                        k.assertions(t, None).map(|a| a.len())
                    }
                },
            );
            assert_eq!(r.ok(), (!fail).then_some(1), "fail = {fail}");
            assert_eq!(steps, vec![VaultStep::UnlockTouch]);
            assert_eq!(
                key.log[0],
                Call::Token {
                    perms: GA | LBW,
                    rp: Some(RP_ID.into())
                }
            );
            // Only the write permission is offered afterwards, whatever the
            // call returned.
            assert!(auth.current_for(GA).is_none(), "fail = {fail}");
            assert!(auth.current_for(LBW).is_some(), "fail = {fail}");
        }
    }

    #[test]
    fn a_touch_is_not_asked_for_when_the_pin_fails() {
        let mut key = FakeKey::new();
        let mut auth = VaultAuth::pin(Zeroizing::new("wrong-pin".into()));
        let mut steps = Vec::new();
        let mut called = false;
        let r = auth.with_touch(
            &mut key,
            MC,
            VaultStep::CreateTouch,
            &mut |s| steps.push(s),
            |_, _| {
                called = true;
                Ok(())
            },
        );
        assert!(matches!(
            r,
            Err(VaultKeyError::Ctap(CtapError::StatusCode(0x31)))
        ));
        assert!(steps.is_empty());
        assert!(!called);
    }

    #[test]
    fn a_fresh_token_replaces_the_stored_one() {
        let mut key = FakeKey::new();
        let mut auth = pin();
        token(&mut auth, &mut key, CM, None);
        token(&mut auth, &mut key, GA | LBW, Some(RP_ID));
        assert!(auth.current_for(CM).is_none());
        assert!(auth.current_for(LBW).is_some());
        assert_eq!(
            key.log.last(),
            Some(&Call::Token {
                perms: GA | LBW,
                rp: Some(RP_ID.into())
            })
        );
    }

    #[test]
    fn a_refused_pin_leaves_no_token() {
        let mut key = FakeKey::new();
        let mut auth = VaultAuth::pin(Zeroizing::new("wrong-pin".into()));
        let err = fresh(&mut auth, &mut key, LBW, None).err().unwrap();
        assert!(matches!(
            err,
            VaultKeyError::Ctap(CtapError::StatusCode(0x31))
        ));
        assert!(auth.current_for(LBW).is_none());
    }

    #[test]
    fn auth_debug_hides_the_pin_and_token() {
        let mut key = FakeKey::new();
        let mut auth = pin();
        token(&mut auth, &mut key, LBW, None);
        let shown = format!("{auth:?}");
        assert!(!shown.contains(FakeKey::PIN), "{shown}");
        assert!(shown.contains("redacted"), "{shown}");
    }

    #[test]
    fn a_fingerprint_auth_never_prints_a_pin() {
        let (_, ask) = super::fake::asks();
        let auto = VaultAuth::auto(Some(Zeroizing::new("123456".into())), ask);
        let shown = format!("{auto:?}");
        assert!(!shown.contains("123456"), "{shown}");
        assert!(
            shown.contains("\"fingerprint, pin fallback <redacted>\""),
            "{shown}"
        );

        let (_, ask) = super::fake::asks();
        let shown = format!("{:?}", VaultAuth::fingerprint(ask));
        assert!(shown.contains("\"fingerprint\""), "{shown}");
        let (_, ask) = super::fake::asks();
        let shown = format!("{:?}", VaultAuth::auto(None, ask));
        assert!(shown.contains("\"fingerprint\""), "{shown}");
        assert!(format!("{:?}", pin()).contains("\"pin <redacted>\""));
    }

    /// A key whose PIN token request answers with a fingerprint error.
    struct FingerErrOnPin(FakeKey);

    impl VaultKey for FingerErrOnPin {
        fn info(&self) -> &AuthenticatorInfo {
            self.0.info()
        }
        fn pin_token(
            &mut self,
            pin: &str,
            permissions: u32,
            rp_id: Option<&str>,
        ) -> Result<PinUvAuthToken, CtapError> {
            self.0.pin_token(pin, permissions, rp_id)?;
            Err(CtapError::Fingerprint(FingerprintError::Refused(0x3F)))
        }
        fn uv_token(
            &mut self,
            permissions: u32,
            rp_id: Option<&str>,
            on_finger: &mut dyn FnMut(),
        ) -> Result<PinUvAuthToken, CtapError> {
            self.0.uv_token(permissions, rp_id, on_finger)
        }
        fn make_credential(
            &mut self,
            token: &PinUvAuthToken,
            user_id: &[u8],
            name: &str,
        ) -> Result<keyroost_ctap::make_credential::MadeCredential, CtapError> {
            self.0.make_credential(token, user_id, name)
        }
        fn assertions(
            &mut self,
            token: &PinUvAuthToken,
            allow: Option<&[u8]>,
        ) -> Result<Vec<Assertion>, CtapError> {
            self.0.assertions(token, allow)
        }
        fn credentials(
            &mut self,
            token: &PinUvAuthToken,
        ) -> Result<Vec<VaultCredential>, CtapError> {
            self.0.credentials(token)
        }
        fn delete_credential(
            &mut self,
            token: &PinUvAuthToken,
            credential_id: &[u8],
        ) -> Result<(), CtapError> {
            self.0.delete_credential(token, credential_id)
        }
        fn read_blobs(&mut self) -> Result<LargeBlobArray, CtapError> {
            self.0.read_blobs()
        }
        fn write_blobs(
            &mut self,
            token: &PinUvAuthToken,
            serialized: &[u8],
        ) -> Result<(), CtapError> {
            self.0.write_blobs(token, serialized)
        }
    }

    #[test]
    fn a_pin_is_never_sent_twice_as_its_own_fallback() {
        let pin_requests = |key: &FingerErrOnPin| {
            key.0
                .log
                .iter()
                .filter(|c| matches!(c, Call::Token { .. }))
                .count()
        };
        let is_finger_err = |r: &Result<_, VaultKeyError>| {
            matches!(r, Err(VaultKeyError::Ctap(CtapError::Fingerprint(_))))
        };

        // The PIN method: one request, its error returned as is.
        let mut key = FingerErrOnPin(FakeKey::new());
        let mut auth = pin();
        let r = auth.fresh_token(&mut key, LBW, None).map(drop);
        assert!(is_finger_err(&r), "{r:?}");
        assert_eq!(pin_requests(&key), 1);
        assert!(auth.current_for(LBW).is_none());

        // auto: the refused finger falls back once; the fallback's own
        // fingerprint error is not a reason to send the PIN again.
        let mut key = FingerErrOnPin(FakeKey::with_fingerprint());
        key.0.uv_refusals.push_back(0x3F);
        let (_, ask) = super::fake::asks();
        let mut auth = VaultAuth::auto(Some(Zeroizing::new(FakeKey::PIN.to_owned())), ask);
        let r = auth.fresh_token(&mut key, LBW, None).map(drop);
        assert!(is_finger_err(&r), "{r:?}");
        assert_eq!(pin_requests(&key), 1);
        let r = auth.fresh_token(&mut key, LBW, None).map(drop);
        assert!(is_finger_err(&r), "{r:?}");
        assert_eq!(pin_requests(&key), 2, "one PIN request per token asked for");
    }

    #[test]
    fn a_renewed_pin_token_is_a_fresh_one() {
        let mut key = FakeKey::new();
        let mut auth = pin();
        token(&mut auth, &mut key, CM, None);
        assert_eq!(auth.verified(), Some(Verified::Pin));
        auth.renewed_token(&mut key, LBW, None)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            key.log,
            vec![
                Call::Token {
                    perms: CM,
                    rp: None
                },
                Call::Token {
                    perms: LBW,
                    rp: None
                }
            ]
        );
        assert!(auth.current_for(LBW).is_some());
        assert!(auth.current_for(CM).is_none());
    }

    #[test]
    fn vault_name_fallbacks() {
        let handle = user_handle("Personal").unwrap();
        assert_eq!(
            vault_name(Some(&handle), Some("ignored")).as_deref(),
            Some("Personal")
        );
        // Not a vault handle: the user name stands in.
        assert_eq!(
            vault_name(Some(b"plain-id"), Some("Work")).as_deref(),
            Some("Work")
        );
        assert_eq!(vault_name(None, Some("Work")).as_deref(), Some("Work"));
        assert_eq!(vault_name(Some(b"plain-id"), None), None);
        assert_eq!(vault_name(None, None), None);
        // An empty name is no name: what a rotate of an unnamed vault makes.
        let unnamed = keyroost_vault::unnamed_user_handle().unwrap();
        assert_eq!(vault_name(Some(&unnamed), Some("")), None);
        assert_eq!(vault_name(None, Some("")), None);
    }

    #[test]
    fn no_credentials_reads_as_none() {
        let empty: Vec<Assertion> = no_credentials_as_empty(Err(CtapError::NoCredentials)).unwrap();
        assert!(empty.is_empty());
        let kept = no_credentials_as_empty(Ok(vec![1u8, 2])).unwrap();
        assert_eq!(kept, vec![1, 2]);
        let other = no_credentials_as_empty::<u8>(Err(CtapError::StatusCode(0x33))).unwrap_err();
        assert!(matches!(other, CtapError::StatusCode(0x33)));
    }

    #[test]
    fn wrapped_errors_display_the_inner_message() {
        for e in [
            CtapError::StatusCode(0x31),
            CtapError::PinChangeRequired,
            CtapError::NoCredentials,
        ] {
            let inner = e.to_string();
            let wrapped = VaultKeyError::from(e);
            assert_eq!(wrapped.to_string(), inner);
            assert_eq!(wrapped.source().unwrap().to_string(), inner);
        }
        for e in [VaultError::Decrypt, VaultError::NameLength] {
            let inner = e.to_string();
            let wrapped = VaultKeyError::from(e);
            assert_eq!(wrapped.to_string(), inner);
            assert_eq!(wrapped.source().unwrap().to_string(), inner);
        }
        assert!(VaultKeyError::Conflict.source().is_none());
    }

    #[test]
    fn every_error_has_plain_words() {
        let all = [
            VaultKeyError::Unsupported("hmac-secret"),
            VaultKeyError::PinNotSet,
            VaultKeyError::NoVaults,
            VaultKeyError::NotFound("Personal".into()),
            VaultKeyError::DuplicateName("Personal".into()),
            VaultKeyError::NoLargeBlobKey,
            VaultKeyError::KeyMismatch,
            VaultKeyError::CreateUndone {
                cause: Box::new(VaultKeyError::NoLargeBlobKey),
                left_over: LeftOver::NONE,
            },
            VaultKeyError::CreateUndone {
                cause: Box::new(VaultKeyError::NoLargeBlobKey),
                left_over: LeftOver {
                    credential: true,
                    data: false,
                },
            },
            VaultKeyError::Conflict,
            VaultKeyError::Full {
                needed: 2048,
                max: 1024,
            },
            VaultKeyError::CannotOpen(VaultProblem::NoSecret),
            VaultKeyError::CannotOpen(VaultProblem::Damaged(VaultError::Decrypt)),
            VaultKeyError::RotateNotVerified,
            VaultKeyError::ChangedDuringRotate,
            VaultKeyError::OldNotDeleted {
                name: Some("Personal".into()),
                cause: Box::new(VaultKeyError::Ctap(CtapError::StatusCode(0x30))),
                old: OldVault::Kept,
            },
            VaultKeyError::VaultGone {
                name: Some("Personal".into()),
            },
        ];
        for e in &all {
            let s = e.to_string();
            assert!(!s.is_empty());
            // No CLI flag in a transport message.
            assert!(!s.contains("--"), "{s}");
        }
        assert!(all[3].to_string().contains("\"Personal\""));
        let full = all[10].to_string();
        assert!(
            full.contains("needs 2048 bytes") && full.contains("holds 1024"),
            "{full}"
        );
        assert!(all[7]
            .to_string()
            .contains(&VaultKeyError::NoLargeBlobKey.to_string()));
        assert_ne!(all[7].to_string(), all[8].to_string());
        let old = all[15].to_string();
        assert!(old.contains("same checked entries"), "{old}");
        assert!(old.contains("one still uses the old key"), "{old}");
        assert!(old.contains("rotate the one left again"), "{old}");
        assert!(!old.contains("is safe"), "{old}");
        let gone = all[16].to_string();
        assert!(
            gone.contains("\"Personal\" is no longer on the key"),
            "{gone}"
        );
        assert!(gone.contains("deleted or rotated elsewhere"), "{gone}");
        assert!(all[10].to_string().contains("large-blob store"), "{full}");
        for e in &all {
            assert!(!e.to_string().contains("largeBlob st"), "{e}");
        }
        assert!(all[12]
            .to_string()
            .contains(&VaultError::Decrypt.to_string()));
    }

    #[test]
    fn each_left_over_case_has_its_own_words() {
        let text = |credential, data| {
            VaultKeyError::CreateUndone {
                cause: Box::new(VaultKeyError::NoLargeBlobKey),
                left_over: LeftOver { credential, data },
            }
            .to_string()
        };
        let none = text(false, false);
        let cred = text(true, false);
        let data = text(false, true);
        let both = text(true, true);
        assert!(none.contains("removed again"), "{none}");
        assert!(
            cred.contains("credential") && cred.contains("no data"),
            "{cred}"
        );
        assert!(data.contains("nothing to open it"), "{data}");
        assert!(both.contains("credential and its data"), "{both}");
        let all = [&none, &cred, &data, &both];
        for (i, a) in all.iter().enumerate() {
            assert!(a.starts_with("the vault was not created: "), "{a}");
            assert!(!a.contains("--"), "{a}");
            for b in &all[i + 1..] {
                assert_ne!(a, b);
            }
        }
        assert!(!LeftOver::NONE.any());
        assert!(LeftOver {
            credential: false,
            data: true
        }
        .any());
    }

    #[test]
    fn each_old_vault_case_has_its_own_words() {
        let text = |old| {
            VaultKeyError::OldNotDeleted {
                name: Some("Personal".into()),
                cause: Box::new(VaultKeyError::Ctap(CtapError::StatusCode(0x30))),
                old,
            }
            .to_string()
        };
        let kept = text(OldVault::Kept);
        let emptied = text(OldVault::Emptied);
        let unknown = text(OldVault::Unknown);
        for t in [&kept, &emptied, &unknown] {
            assert!(t.contains("new vault \"Personal\""), "{t}");
            assert!(t.contains("every entry checked"), "{t}");
            assert!(!t.contains("--"), "{t}");
        }
        // Never "deleting either is safe" on its own: the copy left may
        // be the one still on the old key, so it is rotated again.
        let rotate_again = "delete either, then rotate the one left again so it gets a fresh key";
        assert!(kept.contains("one still uses the old key"), "{kept}");
        assert!(kept.ends_with(rotate_again), "{kept}");
        for t in [&kept, &emptied, &unknown] {
            assert!(!t.contains("is safe"), "{t}");
        }
        assert!(!emptied.contains("either"), "{emptied}");
        assert!(
            emptied.contains("delete the copy with no data"),
            "{emptied}"
        );
        assert!(unknown.contains("not known"), "{unknown}");
        assert!(
            unknown.contains("if a copy holds no data, delete that one"),
            "{unknown}"
        );
        assert!(unknown.ends_with(rotate_again), "{unknown}");
        let unnamed = VaultKeyError::OldNotDeleted {
            name: None,
            cause: Box::new(VaultKeyError::Conflict),
            old: OldVault::Kept,
        }
        .to_string();
        assert!(
            unnamed.starts_with("the new vault is in place"),
            "{unnamed}"
        );
    }

    #[test]
    fn fake_round_trips_a_seeded_vault() {
        let mut key = FakeKey::new();
        key.add_foreign_entries();
        let vault = Vault {
            entries: vec![entry("GitHub"), entry("Mail")],
        };
        let id = key.add_vault("Personal", &vault);
        assert_eq!(key.vault_on_key(&id), Some(vault.clone()));
        assert!(key.log.is_empty(), "seeding is not a key call");

        // The same vault through the VaultKey calls a flow would make.
        let mut auth = pin();
        let ga = token(&mut auth, &mut key, GA | LBW, Some(RP_ID));
        let found = key.assertions(&ga, None).unwrap();
        assert_eq!(found.len(), 1);
        let a = &found[0];
        assert_eq!(a.credential_id, id);
        assert_eq!(
            vault_name(a.user_id.as_deref(), a.user_name.as_deref()).as_deref(),
            Some("Personal")
        );
        let array = key.read_blobs().unwrap();
        assert_eq!(array.len(), 4, "three foreign entries and the vault");
        let blob = array
            .credential_blob(a.large_blob_key.as_ref().unwrap())
            .unwrap();
        assert_eq!(open(&blob, a.hmac_output.as_ref().unwrap()).unwrap(), vault);

        let cm = token(&mut auth, &mut key, CM, None);
        let creds = key.credentials(&cm).unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].vault.name.as_deref(), Some("Personal"));
        assert_eq!(creds[0].as_ref().credential_id, id);
        assert!(creds[0].large_blob_key.is_some());
        assert_eq!(creds[0].stored, StoredData::Unknown);
        assert_eq!(
            key.log,
            vec![
                Call::Token {
                    perms: GA | LBW,
                    rp: Some(RP_ID.into())
                },
                Call::Assertions(None),
                Call::Read,
                Call::Token {
                    perms: CM,
                    rp: None
                },
                Call::Credentials,
            ]
        );
    }

    #[test]
    fn credential_debug_hides_the_large_blob_key() {
        let c = VaultCredential {
            vault: VaultRef {
                credential_id: vec![1, 2],
                name: Some("Personal".into()),
            },
            large_blob_key: Some(Zeroizing::new([0xAB; 32])),
            stored: StoredData::Bytes(10),
        };
        let shown = format!("{c:?}");
        assert!(!shown.contains("171"), "{shown}");
        assert!(!shown.to_lowercase().contains("ab, ab"), "{shown}");
        assert!(shown.contains("redacted"), "{shown}");
    }

    #[test]
    fn now_minutes_is_after_2024() {
        // 2024-01-01T00:00Z in minutes since the epoch.
        assert!(now_minutes() > 28_401_120);
    }

    #[test]
    fn public_types_are_send() {
        fn send<T: Send>() {}
        send::<VaultAuth>();
        send::<VaultRef>();
        send::<VaultCredential>();
        send::<VaultKeyError>();
        send::<VaultStep>();
        send::<VaultProblem>();
        send::<StoredData>();
        send::<LeftOver>();
        send::<OpenVault>();
        send::<VaultOnKey>();
        send::<Unlocked>();
        send::<VaultPick<'static>>();
    }
}
