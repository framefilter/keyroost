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
use keyroost_ctap::client_pin::PinUvAuthToken;
use keyroost_ctap::get_assertion::vault_name_from_user_id;
use keyroost_ctap::{AuthenticatorInfo, CtapError};
use keyroost_vault::VaultError;
use zeroize::Zeroizing;

mod key;
pub use key::{CtapVaultKey, VaultKey};

mod ops;
pub use ops::{matching, unlock, OpenVault, Unlocked, VaultOnKey, VaultPick};

#[cfg(test)]
mod fake;

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
    /// How many bytes of data the key holds for this vault (the length of
    /// its decrypted largeBlob entry); `None` when there is none, or no
    /// largeBlobKey to find it with.
    pub stored_bytes: Option<usize>,
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
            .field("stored_bytes", &self.stored_bytes)
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
    /// credential was deleted again, unless `left_over`.
    CreateUndone {
        cause: Box<VaultKeyError>,
        left_over: bool,
    },
    /// What this change touches was changed on the key since the vault was
    /// opened; nothing was written.
    Conflict,
    /// The largeBlob store is too small for the result; nothing was written.
    Full { needed: u64, max: u64 },
    /// The vault cannot be opened, so it is not changed.
    CannotOpen(VaultProblem),
    /// A rotate's new vault did not read back with the old vault's entries.
    RotateNotVerified,
    /// The old vault changed on the key while its key was being rotated.
    ChangedDuringRotate,
    /// A rotate made and checked the new vault but could not delete the old
    /// one: both hold the same checked entries.
    OldNotDeleted {
        name: Option<String>,
        cause: Box<VaultKeyError>,
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
            VaultKeyError::CreateUndone {
                cause,
                left_over: false,
            } => write!(
                f,
                "the vault was not created: {cause}; its new credential was removed again"
            ),
            VaultKeyError::CreateUndone {
                cause,
                left_over: true,
            } => write!(
                f,
                "the vault was not created: {cause}; removing its new credential failed too, so it is left on the key with no data"
            ),
            VaultKeyError::Conflict => f.write_str(
                "this changed on the key since the vault was opened; nothing was written",
            ),
            VaultKeyError::Full { needed, max } => write!(
                f,
                "the key's largeBlob storage is too small: this needs {needed} bytes, and it holds {max}; nothing was written"
            ),
            VaultKeyError::CannotOpen(p) => write!(f, "this vault cannot be opened: {p}"),
            VaultKeyError::RotateNotVerified => {
                f.write_str("the new vault did not read back with the same entries")
            }
            VaultKeyError::ChangedDuringRotate => {
                f.write_str("the vault changed on the key while its key was being rotated")
            }
            VaultKeyError::OldNotDeleted { name, cause } => {
                let which = match name {
                    Some(n) => format!("vault \"{n}\""),
                    None => "vault".to_owned(),
                };
                write!(
                    f,
                    "the new {which} is in place, but deleting the old one failed: {cause}; both vaults hold the same checked entries, so deleting either is safe"
                )
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
/// and the pinUvAuthToken it last obtained, with that token's permissions,
/// so a flow can reuse a token that still covers what it needs.
pub struct VaultAuth {
    method: Method,
    /// The current token, its permissions and the RP it was bound to.
    token: Option<(PinUvAuthToken, u32, Option<String>)>,
}

/// The ways to obtain a token. A later method (fingerprint) adds a variant
/// and a constructor; the flows don't change.
enum Method {
    Pin(Zeroizing<String>),
}

impl VaultAuth {
    /// Authenticate with the key's PIN.
    pub fn pin(pin: Zeroizing<String>) -> Self {
        VaultAuth {
            method: Method::Pin(pin),
            token: None,
        }
    }

    /// Obtain a new token with `permissions` (bound to `rp_id` when given)
    /// and keep it as the current one. A key that demands a PIN change is
    /// refused before the PIN is sent.
    pub(crate) fn fresh_token(
        &mut self,
        key: &mut impl VaultKey,
        permissions: u32,
        rp_id: Option<&str>,
    ) -> Result<&PinUvAuthToken, VaultKeyError> {
        if key.info().force_pin_change == Some(true) {
            return Err(CtapError::PinChangeRequired.into());
        }
        // A new token invalidates the old one on the key; drop ours first so
        // a failed request never leaves a stale one looking current.
        self.token = None;
        let token = match &self.method {
            Method::Pin(pin) => key.pin_token(pin, permissions, rp_id)?,
        };
        let (token, _, _) = self
            .token
            .insert((token, permissions, rp_id.map(str::to_owned)));
        Ok(token)
    }

    /// The current token, only when its permissions include every bit of
    /// `permissions`. The stored RP is not checked: largeBlobWrite and
    /// credential-management tokens are requested without one.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the vault flows that call it come next")
    )]
    pub(crate) fn current_for(&self, permissions: u32) -> Option<&PinUvAuthToken> {
        match &self.token {
            Some((token, held, _)) if held & permissions == permissions => Some(token),
            _ => None,
        }
    }

    /// Mirror the key after a makeCredential or getAssertion was sent with
    /// the current token: a CTAP 2.1 key then keeps only the token's
    /// largeBlobWrite permission (`clearPinUvAuthTokenPermissionsExceptLbw`),
    /// so [`current_for`](Self::current_for) must not offer it for anything
    /// else. Called whatever the call returned: an error does not say
    /// whether the key got that far, and a fresh token is the safe side.
    pub(crate) fn after_presence(&mut self) {
        if let Some((_, held, _)) = &mut self.token {
            *held &= LARGE_BLOB_WRITE;
        }
    }
}

// Hand-written so the PIN and the token never land in a log.
impl fmt::Debug for VaultAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let method = match self.method {
            Method::Pin(_) => "pin <redacted>",
        };
        let token = self
            .token
            .as_ref()
            .map(|(_, perms, rp)| format!("<redacted> permissions {perms:#04x} rp {rp:?}"));
        f.debug_struct("VaultAuth")
            .field("method", &method)
            .field("token", &token)
            .finish()
    }
}

/// A vault credential's name: the one its user handle carries, else the
/// credential's user name, else none. The one naming rule for listing
/// credentials and for unlocking.
pub fn vault_name(user_id: Option<&[u8]>, user_name: Option<&str>) -> Option<String> {
    user_id
        .and_then(vault_name_from_user_id)
        .or_else(|| user_name.map(str::to_owned))
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
        ("largeBlobs", "largeBlob storage"),
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
    };
    use keyroost_ctap::client_pin::PinUvAuthToken;
    use keyroost_ctap::get_assertion::Assertion;
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
                left_over: false,
            },
            VaultKeyError::CreateUndone {
                cause: Box::new(VaultKeyError::NoLargeBlobKey),
                left_over: true,
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
        assert!(old.contains("deleting either is safe"), "{old}");
        assert!(all[12]
            .to_string()
            .contains(&VaultError::Decrypt.to_string()));
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
        assert_eq!(creds[0].stored_bytes, None);
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
            stored_bytes: Some(10),
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
        send::<OpenVault>();
        send::<VaultOnKey>();
        send::<Unlocked>();
        send::<VaultPick<'static>>();
    }
}
