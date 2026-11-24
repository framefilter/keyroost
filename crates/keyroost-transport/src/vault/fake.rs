//! An in-memory key for the vault flow tests: credentials, a largeBlob
//! store, tokens with permissions, and a log of every call, plus knobs to
//! script what a real key does at its worst (refused writes, a second
//! writer, missing largeBlobKeys, a delete that fails).
//!
//! It behaves like a CTAP 2.1 key where it matters to the flows: one token
//! is current at a time (a new one invalidates the old), a token must carry
//! the permission a call needs, and a write larger than the store is
//! refused.

use std::collections::VecDeque;

use keyroost_ctap::client_pin::permissions::{
    CREDENTIAL_MANAGEMENT, GET_ASSERTION, LARGE_BLOB_WRITE, MAKE_CREDENTIAL,
};
use keyroost_ctap::client_pin::PinUvAuthToken;
use keyroost_ctap::device_label::DeviceLabel;
use keyroost_ctap::get_assertion::Assertion;
use keyroost_ctap::large_blobs::{empty_array_serialized, LargeBlobArray};
use keyroost_ctap::make_credential::MadeCredential;
use keyroost_ctap::{AuthenticatorInfo, CtapError};
use keyroost_vault::{open, seal, user_handle, Vault};
use zeroize::Zeroizing;

use super::{vault_name, VaultCredential, VaultKey, VaultRef};

/// `CTAP2_ERR_PIN_INVALID`.
const PIN_INVALID: u8 = 0x31;
/// `CTAP2_ERR_PIN_AUTH_INVALID`: a stale token, or one without the
/// permission the call needs.
const PIN_AUTH_INVALID: u8 = 0x33;
/// `CTAP2_ERR_NOT_ALLOWED`: what a failing delete answers.
const NOT_ALLOWED: u8 = 0x30;
/// `CTAP2_ERR_NO_CREDENTIALS`.
const NO_CREDENTIALS: u8 = 0x2E;
/// `CTAP2_ERR_LARGE_BLOB_STORAGE_FULL`.
const STORAGE_FULL: u8 = 0x3B;
/// The checksum trailer after a serialized largeBlob array.
const CHECKSUM_LEN: usize = 16;

/// One credential on the fake key.
#[derive(Clone)]
pub(crate) struct FakeCred {
    pub id: Vec<u8>,
    pub user_id: Vec<u8>,
    pub user_name: Option<String>,
    pub hmac: [u8; 32],
    pub lbk: Option<[u8; 32]>,
}

/// A call a flow made, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Call {
    Token { perms: u32, rp: Option<String> },
    MakeCredential,
    Assertions(Option<Vec<u8>>),
    Credentials,
    Delete(Vec<u8>),
    Read,
    Write,
}

/// Run once, between the `n`th `Read` (counting from 1) and whatever comes
/// next: another writer changing the store under the flow.
pub(crate) type Hook = Box<dyn FnOnce(&mut FakeKey)>;

pub(crate) struct FakeKey {
    pub info: AuthenticatorInfo,
    pub creds: Vec<FakeCred>,
    pub log: Vec<Call>,
    /// Status codes the next writes answer, one per write, before anything
    /// else is checked (the store is left as it was).
    pub write_refusals: VecDeque<u8>,
    /// The permissions of the token every write was sent with (0 for a
    /// token this key never issued).
    pub write_perms: Vec<u32>,
    /// `(n, hook)`: run `hook` right after the `n`th read.
    pub hook: Option<(usize, Hook)>,
    /// makeCredential returns no largeBlobKey (the credential has none).
    pub mc_without_lbk: bool,
    /// Credential management lists no largeBlobKeys.
    pub credmgmt_without_lbk: bool,
    /// Every credential delete fails (`NOT_ALLOWED`).
    pub delete_fails: bool,
    /// The serialized array with its checksum.
    stored: Vec<u8>,
    /// Every token issued: its bytes and permissions.
    issued: Vec<(Vec<u8>, u32)>,
    /// The bytes of the one token the key accepts now.
    current: Option<Vec<u8>>,
    reads: usize,
    next: u8,
}

/// getInfo of a key that can hold a vault, with a 4096-byte store.
fn full_info() -> AuthenticatorInfo {
    let s = |v: &[&str]| v.iter().map(|x| (*x).to_owned()).collect();
    AuthenticatorInfo {
        versions: s(&["FIDO_2_0", "FIDO_2_1"]),
        extensions: s(&["credProtect", "hmac-secret", "largeBlobKey"]),
        options: [
            "rk",
            "up",
            "clientPin",
            "pinUvAuthToken",
            "credMgmt",
            "largeBlobs",
        ]
        .iter()
        .map(|o| ((*o).to_owned(), true))
        .collect(),
        pin_uv_auth_protocols: vec![2, 1],
        max_serialized_large_blob_array: Some(4096),
        ..AuthenticatorInfo::default()
    }
}

impl FakeKey {
    /// The PIN the fake accepts.
    pub const PIN: &'static str = "123456";

    pub fn new() -> Self {
        FakeKey {
            info: full_info(),
            creds: Vec::new(),
            log: Vec::new(),
            write_refusals: VecDeque::new(),
            write_perms: Vec::new(),
            hook: None,
            mc_without_lbk: false,
            credmgmt_without_lbk: false,
            delete_fails: false,
            stored: empty_array_serialized(),
            issued: Vec::new(),
            current: None,
            reads: 0,
            next: 0,
        }
    }

    /// Set the store's size (`maxSerializedLargeBlobArray`).
    pub fn set_max_bytes(&mut self, max: u64) {
        self.info.max_serialized_large_blob_array = Some(max);
    }

    // ----- seeding and inspecting; none of these is a logged key call -----

    /// The stored array, serialized with its checksum.
    pub fn stored(&self) -> &[u8] {
        &self.stored
    }

    /// The stored array.
    pub fn array(&self) -> LargeBlobArray {
        LargeBlobArray::parse(&self.stored[..self.stored.len() - CHECKSUM_LEN])
            .expect("the fake only stores valid arrays")
    }

    /// Replace the stored array.
    pub fn set_array(&mut self, array: &LargeBlobArray) {
        self.stored = array
            .serialize_with_checksum()
            .expect("an array built in a test serializes");
    }

    /// Add a credential with no data; returns its ID.
    pub fn add_credential(&mut self, user_id: Vec<u8>, user_name: Option<&str>) -> Vec<u8> {
        self.next += 1;
        let n = self.next;
        let id = vec![0xC0, n, 0x5A, n];
        self.creds.push(FakeCred {
            id: id.clone(),
            user_id,
            user_name: user_name.map(str::to_owned),
            hmac: [0x40 ^ n; 32],
            lbk: Some([0x80 ^ n; 32]),
        });
        id
    }

    /// Add a vault named `name` holding `vault`; returns its credential ID.
    pub fn add_vault(&mut self, name: &str, vault: &Vault) -> Vec<u8> {
        let id = self.add_credential(user_handle(name).unwrap(), Some(name));
        self.put_vault(&id, vault);
        id
    }

    fn cred(&self, id: &[u8]) -> &FakeCred {
        self.creds
            .iter()
            .find(|c| c.id == id)
            .expect("a credential the test made")
    }

    /// Store `blob` as credential `id`'s data, as a writer would.
    pub fn put_blob(&mut self, id: &[u8], blob: &[u8]) {
        let lbk = self.cred(id).lbk.expect("a credential with a largeBlobKey");
        let array = self.array().with_credential_blob(&lbk, blob).unwrap();
        self.set_array(&array);
    }

    /// Seal `vault` under credential `id` and store it.
    pub fn put_vault(&mut self, id: &[u8], vault: &Vault) {
        let blob = seal(vault, &self.cred(id).hmac).unwrap();
        self.put_blob(id, &blob);
    }

    /// Add what other tools keep in the store: another relying party's
    /// entry, a keyroost note and the key's name.
    pub fn add_foreign_entries(&mut self) {
        let array = self
            .array()
            .with_credential_blob(&[0x77; 32], b"another site's data")
            .unwrap()
            .with_text_note("a keyroost note")
            .with_label(
                Some(&DeviceLabel {
                    label: "Test key".into(),
                    writer: Some("keyroost".into()),
                }),
                [9; 12],
            )
            .unwrap();
        self.set_array(&array);
    }

    /// The vault credential `id` holds now, when its data opens.
    pub fn vault_on_key(&self, id: &[u8]) -> Option<Vault> {
        let c = self.creds.iter().find(|c| c.id == id)?;
        let blob = self.array().credential_blob(c.lbk.as_ref()?)?;
        open(&blob, &c.hmac).ok()
    }

    // ----- token checks -----

    /// The permissions of `token` when the key issued it, else 0.
    fn perms_of(&self, token: &PinUvAuthToken) -> u32 {
        self.issued
            .iter()
            .find(|(t, _)| *t == token.token)
            .map_or(0, |(_, p)| *p)
    }

    /// Accept `token` for a call needing `needed`: it must be the current
    /// token and carry the permission.
    fn check(&self, token: &PinUvAuthToken, needed: u32) -> Result<(), CtapError> {
        let current = self.current.as_deref() == Some(&token.token[..]);
        if current && self.perms_of(token) & needed == needed {
            Ok(())
        } else {
            Err(CtapError::StatusCode(PIN_AUTH_INVALID))
        }
    }
}

impl VaultKey for FakeKey {
    fn info(&self) -> &AuthenticatorInfo {
        &self.info
    }

    fn pin_token(
        &mut self,
        pin: &str,
        permissions: u32,
        rp_id: Option<&str>,
    ) -> Result<PinUvAuthToken, CtapError> {
        self.log.push(Call::Token {
            perms: permissions,
            rp: rp_id.map(str::to_owned),
        });
        if pin != Self::PIN {
            return Err(CtapError::StatusCode(PIN_INVALID));
        }
        let mut bytes = vec![0x70; 32];
        bytes[0] = self.issued.len() as u8;
        self.issued.push((bytes.clone(), permissions));
        self.current = Some(bytes.clone());
        Ok(PinUvAuthToken {
            protocol: 2,
            token: bytes,
        })
    }

    fn make_credential(
        &mut self,
        token: &PinUvAuthToken,
        user_id: &[u8],
        name: &str,
    ) -> Result<MadeCredential, CtapError> {
        self.log.push(Call::MakeCredential);
        self.check(token, MAKE_CREDENTIAL)?;
        let id = self.add_credential(user_id.to_vec(), Some(name));
        if self.mc_without_lbk {
            self.creds.last_mut().expect("just added").lbk = None;
        }
        Ok(MadeCredential {
            credential_id: id.clone(),
            large_blob_key: self.cred(&id).lbk.map(Zeroizing::new),
            cred_protect: Some(3),
        })
    }

    fn assertions(
        &mut self,
        token: &PinUvAuthToken,
        allow: Option<&[u8]>,
    ) -> Result<Vec<Assertion>, CtapError> {
        self.log.push(Call::Assertions(allow.map(<[u8]>::to_vec)));
        self.check(token, GET_ASSERTION)?;
        let matching: Vec<&FakeCred> = self
            .creds
            .iter()
            .filter(|c| allow.is_none_or(|id| c.id == id))
            .collect();
        let count = matching.len() as u32;
        Ok(matching
            .into_iter()
            .enumerate()
            .map(|(i, c)| Assertion {
                credential_id: c.id.clone(),
                user_id: Some(c.user_id.clone()),
                user_name: c.user_name.clone(),
                hmac_output: Some(Zeroizing::new(c.hmac)),
                large_blob_key: c.lbk.map(Zeroizing::new),
                number_of_credentials: (i == 0).then_some(count),
            })
            .collect())
    }

    fn credentials(&mut self, token: &PinUvAuthToken) -> Result<Vec<VaultCredential>, CtapError> {
        self.log.push(Call::Credentials);
        self.check(token, CREDENTIAL_MANAGEMENT)?;
        Ok(self
            .creds
            .iter()
            .map(|c| VaultCredential {
                vault: VaultRef {
                    credential_id: c.id.clone(),
                    name: vault_name(Some(&c.user_id), c.user_name.as_deref()),
                },
                large_blob_key: if self.credmgmt_without_lbk {
                    None
                } else {
                    c.lbk.map(Zeroizing::new)
                },
                stored_bytes: None,
            })
            .collect())
    }

    fn delete_credential(
        &mut self,
        token: &PinUvAuthToken,
        credential_id: &[u8],
    ) -> Result<(), CtapError> {
        self.log.push(Call::Delete(credential_id.to_vec()));
        self.check(token, CREDENTIAL_MANAGEMENT)?;
        if self.delete_fails {
            return Err(CtapError::StatusCode(NOT_ALLOWED));
        }
        let before = self.creds.len();
        self.creds.retain(|c| c.id != credential_id);
        if self.creds.len() == before {
            return Err(CtapError::StatusCode(NO_CREDENTIALS));
        }
        Ok(())
    }

    fn read_blobs(&mut self) -> Result<LargeBlobArray, CtapError> {
        self.log.push(Call::Read);
        self.reads += 1;
        let array = self.array();
        if self.hook.as_ref().is_some_and(|(n, _)| *n == self.reads) {
            let (_, hook) = self.hook.take().expect("checked above");
            hook(self);
        }
        Ok(array)
    }

    fn write_blobs(&mut self, token: &PinUvAuthToken, serialized: &[u8]) -> Result<(), CtapError> {
        self.log.push(Call::Write);
        self.write_perms.push(self.perms_of(token));
        if let Some(code) = self.write_refusals.pop_front() {
            return Err(CtapError::StatusCode(code));
        }
        self.check(token, LARGE_BLOB_WRITE)?;
        let max = self.info.max_serialized_large_blob_array.unwrap_or(1024);
        if serialized.len() as u64 > max {
            return Err(CtapError::StatusCode(STORAGE_FULL));
        }
        let body = serialized
            .len()
            .checked_sub(CHECKSUM_LEN)
            .ok_or(CtapError::InvalidArgument("no checksum"))?;
        LargeBlobArray::parse(&serialized[..body])?;
        self.stored = serialized.to_vec();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyroost_ctap::large_blobs::EntryKind;

    fn token(key: &mut FakeKey, perms: u32) -> PinUvAuthToken {
        key.pin_token(FakeKey::PIN, perms, None).unwrap()
    }

    #[test]
    fn a_new_token_invalidates_the_old_one() {
        let mut key = FakeKey::new();
        let old = token(&mut key, CREDENTIAL_MANAGEMENT);
        let _new = token(&mut key, CREDENTIAL_MANAGEMENT);
        assert!(matches!(
            key.credentials(&old),
            Err(CtapError::StatusCode(PIN_AUTH_INVALID))
        ));
    }

    #[test]
    fn a_token_needs_the_permission() {
        let mut key = FakeKey::new();
        let cm = token(&mut key, CREDENTIAL_MANAGEMENT);
        let bytes = key.stored().to_vec();
        assert!(matches!(
            key.write_blobs(&cm, &bytes),
            Err(CtapError::StatusCode(PIN_AUTH_INVALID))
        ));
        assert_eq!(key.write_perms, vec![CREDENTIAL_MANAGEMENT]);
        let lbw = token(&mut key, LARGE_BLOB_WRITE | CREDENTIAL_MANAGEMENT);
        key.write_blobs(&lbw, &bytes).unwrap();
        assert!(key.credentials(&lbw).unwrap().is_empty());
    }

    #[test]
    fn scripted_refusals_come_first_and_leave_the_store() {
        let mut key = FakeKey::new();
        key.write_refusals.extend([0x33, 0x38]);
        let t = token(&mut key, LARGE_BLOB_WRITE);
        let note = key
            .array()
            .with_text_note("x")
            .serialize_with_checksum()
            .unwrap();
        for code in [0x33, 0x38] {
            assert!(matches!(
                key.write_blobs(&t, &note),
                Err(CtapError::StatusCode(c)) if c == code
            ));
        }
        assert_eq!(key.array().len(), 0);
        key.write_blobs(&t, &note).unwrap();
        assert_eq!(key.array().len(), 1);
        assert_eq!(key.log.iter().filter(|c| **c == Call::Write).count(), 3);
    }

    #[test]
    fn a_write_past_the_store_is_refused() {
        let mut key = FakeKey::new();
        key.set_max_bytes(64);
        let t = token(&mut key, LARGE_BLOB_WRITE);
        let big = key
            .array()
            .with_text_note(&"x".repeat(100))
            .serialize_with_checksum()
            .unwrap();
        assert!(matches!(
            key.write_blobs(&t, &big),
            Err(CtapError::StatusCode(STORAGE_FULL))
        ));
    }

    #[test]
    fn the_hook_runs_after_its_read() {
        let mut key = FakeKey::new();
        let id = key.add_vault("Personal", &Vault::default());
        key.hook = Some((
            2,
            Box::new(|k: &mut FakeKey| {
                k.add_foreign_entries();
            }),
        ));
        let first = key.read_blobs().unwrap();
        assert_eq!(first.len(), 1);
        let second = key.read_blobs().unwrap();
        assert_eq!(second.len(), 1, "the read before the hook ran");
        assert_eq!(key.read_blobs().unwrap().len(), 4);
        assert!(key.hook.is_none());
        assert_eq!(key.vault_on_key(&id), Some(Vault::default()));
    }

    #[test]
    fn foreign_entries_are_what_other_tools_store() {
        let mut key = FakeKey::new();
        key.add_foreign_entries();
        let kinds: Vec<EntryKind> = key.array().entries().iter().map(|e| e.classify()).collect();
        assert!(matches!(kinds[0], EntryKind::Opaque));
        assert!(matches!(kinds[1], EntryKind::Note(_)));
        assert!(matches!(kinds[2], EntryKind::KeyName(_)));
    }

    #[test]
    fn switches_shape_what_the_key_returns() {
        let mut key = FakeKey::new();
        key.mc_without_lbk = true;
        let mc = token(&mut key, MAKE_CREDENTIAL);
        let made = key
            .make_credential(&mc, &user_handle("A").unwrap(), "A")
            .unwrap();
        assert!(made.large_blob_key.is_none());
        assert!(key.vault_on_key(&made.credential_id).is_none());

        key.mc_without_lbk = false;
        let made = key
            .make_credential(&mc, &user_handle("B").unwrap(), "B")
            .unwrap();
        assert!(made.large_blob_key.is_some());

        let ga = token(&mut key, GET_ASSERTION);
        let only = key.assertions(&ga, Some(&made.credential_id)).unwrap();
        assert_eq!(only.len(), 1);
        assert_eq!(only[0].number_of_credentials, Some(1));
        let none = key.assertions(&ga, Some(b"nope")).unwrap();
        assert!(none.is_empty());

        key.credmgmt_without_lbk = true;
        let cm = token(&mut key, CREDENTIAL_MANAGEMENT);
        let listed = key.credentials(&cm).unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed.iter().all(|c| c.large_blob_key.is_none()));
        assert_eq!(listed[1].vault.name.as_deref(), Some("B"));

        key.delete_fails = true;
        assert!(matches!(
            key.delete_credential(&cm, &made.credential_id),
            Err(CtapError::StatusCode(NOT_ALLOWED))
        ));
        key.delete_fails = false;
        key.delete_credential(&cm, &made.credential_id).unwrap();
        assert!(matches!(
            key.delete_credential(&cm, &made.credential_id),
            Err(CtapError::StatusCode(NO_CREDENTIALS))
        ));
        assert_eq!(key.creds.len(), 1);
    }

    #[test]
    fn a_wrong_pin_is_refused() {
        let mut key = FakeKey::new();
        assert!(matches!(
            key.pin_token("0000", LARGE_BLOB_WRITE, None),
            Err(CtapError::StatusCode(PIN_INVALID))
        ));
    }

    #[test]
    fn put_blob_and_vault_on_key() {
        let mut key = FakeKey::new();
        let id = key.add_credential(b"plain".to_vec(), None);
        assert!(key.vault_on_key(&id).is_none());
        key.put_blob(&id, b"not a vault");
        assert!(key.vault_on_key(&id).is_none());
        key.put_vault(&id, &Vault::default());
        assert_eq!(key.vault_on_key(&id), Some(Vault::default()));
        assert_eq!(key.array().len(), 1, "replaced in place");
        let _ = key.stored();
    }
}
