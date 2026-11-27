//! An in-memory key for the vault flow tests: credentials, a largeBlob
//! store, tokens with permissions, and a log of every call, plus knobs to
//! script what a real key does at its worst (refused writes, a second
//! writer, missing largeBlobKeys, a delete that fails).
//!
//! It behaves like a CTAP 2.1 key where it matters to the flows: one token
//! is current at a time (a new one invalidates the old), a token must carry
//! the permission a call needs, a successful makeCredential or
//! getAssertion leaves the token only its largeBlobWrite permission (CTAP
//! 2.1 `clearPinUvAuthTokenPermissionsExceptLbw`), and a write larger than
//! the store is refused. A token bound to a relying party (its permissions
//! RP ID) serves only that RP: credential management of the vault RP's
//! credentials, and makeCredential / getAssertion for it, are refused under a
//! token bound to another RP, and a token with none is bound to the vault RP
//! by its first makeCredential or getAssertion; largeBlobWrite ignores the RP
//! (CTAP 2.1 §6.5.5.7, §6.8.4, §6.8.5); with
//! [`strict_listing`](FakeKey::strict_listing) it lists only under a token
//! bound to no RP, as CTAP 2.2's §6.8.4 is written. A key made
//! [`FakeKey::with_fingerprint`] also gives
//! tokens for a finger, with scripted refusals and tries left, and can drop
//! a token entirely after a touch, as some keys do.
//!
//! Built for this crate's tests, and for a front end's tests through the
//! `vault-fake` feature, which only a `[dev-dependencies]` entry enables.
//! Not part of the crate's API: hidden from its docs, and free to change.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use keyroost_ctap::client_pin::permissions::{
    CREDENTIAL_MANAGEMENT, GET_ASSERTION, LARGE_BLOB_WRITE, MAKE_CREDENTIAL,
};
use keyroost_ctap::client_pin::{uv_precheck, FingerAsk, PinUvAuthToken};
use keyroost_ctap::cmd::fingerprint_refusal;
use keyroost_ctap::device_label::DeviceLabel;
use keyroost_ctap::get_assertion::Assertion;
use keyroost_ctap::large_blobs::{empty_array_serialized, LargeBlobArray};
use keyroost_ctap::make_credential::MadeCredential;
use keyroost_ctap::{AuthenticatorInfo, CtapError, FingerprintError};
use keyroost_vault::{open, seal, user_handle, Vault, RP_ID};
use zeroize::Zeroizing;

use super::{vault_name, StoredData, VaultCredential, VaultKey, VaultRef};

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
const STORAGE_FULL: u8 = 0x18;
/// `CTAP2_ERR_UV_INVALID`: the finger was not recognized; one try spent.
const UV_INVALID: u8 = 0x3F;
/// `CTAP2_ERR_UV_BLOCKED`.
#[cfg(test)]
const UV_BLOCKED: u8 = 0x3C;
/// The fingerprint tries a fresh key has.
const UV_TRIES: u32 = 5;
/// The checksum trailer after a serialized largeBlob array.
const CHECKSUM_LEN: usize = 16;

/// The largeBlobKey the damaged entry [`FakeKey::put_unreadable`] stores
/// is sealed under.
pub const UNREADABLE_LBK: [u8; 32] = [0x5E; 32];

/// A largeBlob entry whose GCM tag verifies under [`UNREADABLE_LBK`] but
/// whose plaintext is not DEFLATE, so it never inflates: `{1: ciphertext,
/// 2: nonce, 3: origSize}` with AES-256-GCM under `[0x5E; 32]`, nonce
/// `[0x22; 12]`, AAD `b"blob" || u64le(32)`, plaintext
/// `b"\xff\xff not deflate"` (0xFF opens a block of the reserved type), as
/// keyroost-ctap's own `credential_data` test seals it. Precomputed because
/// this crate has no AES-GCM of its own.
const UNREADABLE_ENTRY: &[u8] = &[
    0xa3, 0x01, 0x58, 0x1e, 0xb0, 0xba, 0xb0, 0xf7, 0x17, 0xa7, 0x4a, 0x1f, 0xa1, 0xa1, 0xba, 0x83,
    0x8f, 0x01, 0xf6, 0x21, 0x61, 0xa7, 0x1e, 0x9f, 0xf5, 0x65, 0xb4, 0x8d, 0x10, 0xa5, 0x3c, 0x1f,
    0x4a, 0x1b, 0x02, 0x4c, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x03, 0x18, 0x20,
];

/// One credential on the fake key.
#[derive(Clone)]
pub struct FakeCred {
    pub id: Vec<u8>,
    pub user_id: Vec<u8>,
    pub user_name: Option<String>,
    pub hmac: [u8; 32],
    pub lbk: Option<[u8; 32]>,
}

/// A call a flow made, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    /// A PIN token request.
    Token {
        perms: u32,
        rp: Option<String>,
    },
    /// A fingerprint token request that reached the key (getInfo allowed
    /// it).
    UvToken {
        perms: u32,
        rp: Option<String>,
    },
    MakeCredential,
    Assertions(Option<Vec<u8>>),
    Credentials,
    Delete(Vec<u8>),
    Read,
    Write,
}

/// A token the key issued.
struct Issued {
    bytes: Vec<u8>,
    perms: u32,
    /// Its permissions RP ID: the `rpId` it was asked for with, or the RP
    /// of its first makeCredential or getAssertion.
    rp: Option<String>,
}

/// What a call asks of the token's permissions RP ID (CTAP 2.1).
#[derive(Clone, Copy)]
enum RpUse {
    /// largeBlobWrite: the RP is ignored.
    Ignored,
    /// Credential management of the vault RP's credentials (enumerating
    /// them, deleting one): a token bound to another RP is refused.
    VaultCredentials,
    /// makeCredential / getAssertion for the vault RP: a token bound to
    /// another RP is refused, and one bound to none is bound to the vault
    /// RP.
    VaultRequest,
}

/// Run once, between the `n`th `Read` (counting from 1) and whatever comes
/// next: another writer changing the store under the flow.
pub type Hook = Box<dyn FnOnce(&mut FakeKey)>;

pub struct FakeKey {
    pub info: AuthenticatorInfo,
    pub creds: Vec<FakeCred>,
    pub log: Vec<Call>,
    /// Status codes the next writes answer, one per write, before anything
    /// else is checked (the store is left as it was).
    pub write_refusals: VecDeque<u8>,
    /// How many of the next writes store the array and then fail anyway,
    /// as a write whose reply was lost.
    pub lost_write_replies: usize,
    /// Status codes the next credential deletes answer, one per delete,
    /// before anything else is checked (the credential stays).
    pub delete_refusals: VecDeque<u8>,
    /// The permissions of the token every write was sent with (0 for a
    /// token this key never issued).
    pub write_perms: Vec<u32>,
    /// `(n, hook)`: run `hook` right after the `n`th read.
    pub hook: Option<(usize, Hook)>,
    /// `(n, hook)`: run `hook` right after the `n`th write that stored the
    /// array (counting from 1), before its reply: another writer changing
    /// the store between a flow's write and its next read.
    pub after_write: Option<(usize, Hook)>,
    /// makeCredential returns no largeBlobKey (the credential has none).
    pub mc_without_lbk: bool,
    /// Credential management lists no largeBlobKeys.
    pub credmgmt_without_lbk: bool,
    /// Every credential delete fails (`NOT_ALLOWED`).
    pub delete_fails: bool,
    /// Fingerprint tries left (getUVRetries). At 0 a fingerprint token is
    /// refused as blocked before the finger is asked for.
    pub uv_retries: u32,
    /// Status codes the next fingerprint token requests answer, one per
    /// request, after the finger was asked for. `0x3F` (not recognized)
    /// spends one of [`uv_retries`](Self::uv_retries).
    pub uv_refusals: VecDeque<u8>,
    /// A makeCredential or getAssertion leaves its token no permission at
    /// all, not even largeBlobWrite: a key that drops the token after a
    /// touch.
    pub drops_token_after_presence: bool,
    /// Credential listing (enumerateCredentialsBegin) refuses any token
    /// bound to an RP, as CTAP 2.2's 6.8.4 is written ("the cm permission
    /// and no associated permissions RP ID"); deleteCredential still takes
    /// one bound to the vault RP. Off: CTAP 2.1, which takes a token bound
    /// to the RP listed.
    pub strict_listing: bool,
    /// How many times a finger was asked for.
    pub fingers: usize,
    /// The serialized array with its checksum.
    stored: Vec<u8>,
    /// Every token issued: its bytes, permissions and permissions RP ID.
    issued: Vec<Issued>,
    /// The bytes of the one token the key accepts now.
    current: Option<Vec<u8>>,
    reads: usize,
    /// Writes that stored the array.
    writes: usize,
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
            delete_refusals: VecDeque::new(),
            lost_write_replies: 0,
            write_perms: Vec::new(),
            hook: None,
            after_write: None,
            mc_without_lbk: false,
            credmgmt_without_lbk: false,
            delete_fails: false,
            uv_retries: UV_TRIES,
            uv_refusals: VecDeque::new(),
            drops_token_after_presence: false,
            strict_listing: false,
            fingers: 0,
            stored: empty_array_serialized(),
            issued: Vec::new(),
            current: None,
            reads: 0,
            writes: 0,
            next: 0,
        }
    }

    /// A key with a fingerprint enrolled: getInfo `uv` and `bioEnroll` are
    /// true, so built-in UV is ready.
    pub fn with_fingerprint() -> Self {
        let mut key = FakeKey::new();
        key.info
            .options
            .extend([("uv".to_owned(), true), ("bioEnroll".to_owned(), true)]);
        key
    }

    /// Make this a CTAP 2.2 key that lists as 2.2's 6.8.4 is written:
    /// getInfo `versions` gains `FIDO_2_2`, and
    /// [`strict_listing`](Self::strict_listing) is on.
    pub fn as_ctap22(&mut self) {
        self.info.versions.push("FIDO_2_2".to_owned());
        self.strict_listing = true;
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

    /// Give credential `id` the largeBlobKey [`UNREADABLE_LBK`] and store
    /// [`UNREADABLE_ENTRY`] as its data: sealed under its key, but damaged.
    pub fn put_unreadable(&mut self, id: &[u8]) {
        self.creds
            .iter_mut()
            .find(|c| c.id == id)
            .expect("a credential the test made")
            .lbk = Some(UNREADABLE_LBK);
        let serialized = self.array().serialize_with_checksum().unwrap();
        let body = &serialized[..serialized.len() - CHECKSUM_LEN];
        // A short array's header is one byte, 0x80 + its length.
        assert!((0x80..0x97).contains(&body[0]), "a short array");
        let mut grown = vec![body[0] + 1];
        grown.extend_from_slice(&body[1..]);
        grown.extend_from_slice(UNREADABLE_ENTRY);
        self.set_array(&LargeBlobArray::parse(&grown).unwrap());
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

    fn issued_mut(&mut self, token: &PinUvAuthToken) -> Option<&mut Issued> {
        self.issued.iter_mut().find(|i| i.bytes == token.token)
    }

    /// The permissions of `token` when the key issued it, else 0.
    fn perms_of(&self, token: &PinUvAuthToken) -> u32 {
        self.issued
            .iter()
            .find(|i| i.bytes == token.token)
            .map_or(0, |i| i.perms)
    }

    /// The permissions RP ID of `token`, when the key issued it with one or
    /// has bound it since.
    pub fn rp_of(&self, token: &PinUvAuthToken) -> Option<String> {
        self.issued
            .iter()
            .find(|i| i.bytes == token.token)
            .and_then(|i| i.rp.clone())
    }

    /// Accept `token` for a call needing `needed` as `rp` says: it must be
    /// the current token, carry the permission, and be bound to no RP or to
    /// the vault RP where the call is about the vault RP (then a
    /// makeCredential or getAssertion binds an unbound one).
    fn check(&mut self, token: &PinUvAuthToken, needed: u32, rp: RpUse) -> Result<(), CtapError> {
        let refused = Err(CtapError::StatusCode(PIN_AUTH_INVALID));
        let current = self.current.as_deref() == Some(&token.token[..]);
        if !current || self.perms_of(token) & needed != needed {
            return refused;
        }
        let Some(issued) = self.issued_mut(token) else {
            return refused;
        };
        match (rp, issued.rp.as_deref()) {
            (RpUse::Ignored, _) | (_, Some(RP_ID)) => Ok(()),
            (RpUse::VaultCredentials, None) => Ok(()),
            (RpUse::VaultRequest, None) => {
                issued.rp = Some(RP_ID.to_owned());
                Ok(())
            }
            (_, Some(_)) => refused,
        }
    }

    /// CTAP 2.1 `clearPinUvAuthTokenPermissionsExceptLbw`: after a
    /// makeCredential or getAssertion with user presence, `token` keeps only
    /// its largeBlobWrite permission, or none with
    /// [`drops_token_after_presence`](Self::drops_token_after_presence).
    fn keep_only_lbw(&mut self, token: &PinUvAuthToken) {
        let keep = if self.drops_token_after_presence {
            0
        } else {
            LARGE_BLOB_WRITE
        };
        if let Some(issued) = self.issued_mut(token) {
            issued.perms &= keep;
        }
    }

    /// Issue a new token with `permissions`, bound to `rp_id` when given;
    /// it invalidates the old one.
    fn issue(&mut self, permissions: u32, rp_id: Option<&str>) -> PinUvAuthToken {
        let mut bytes = vec![0x70; 32];
        bytes[0] = self.issued.len() as u8;
        self.issued.push(Issued {
            bytes: bytes.clone(),
            perms: permissions,
            rp: rp_id.map(str::to_owned),
        });
        self.current = Some(bytes.clone());
        PinUvAuthToken {
            protocol: 2,
            token: bytes,
        }
    }
}

impl Default for FakeKey {
    fn default() -> Self {
        FakeKey::new()
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
        Ok(self.issue(permissions, rp_id))
    }

    /// The rules `get_token` follows for a fingerprint: what getInfo rules
    /// out is refused with no exchange (no [`Call::UvToken`]); no tries
    /// left is refused before the finger; then the finger is asked for and
    /// a scripted refusal, if any, answers.
    fn uv_token(
        &mut self,
        permissions: u32,
        rp_id: Option<&str>,
        on_finger: &mut dyn FnMut(),
    ) -> Result<PinUvAuthToken, CtapError> {
        let refuse = |why| Err(CtapError::Fingerprint(why));
        uv_precheck(&self.info, permissions).map_err(CtapError::Fingerprint)?;
        self.log.push(Call::UvToken {
            perms: permissions,
            rp: rp_id.map(str::to_owned),
        });
        if self.uv_retries == 0 {
            return refuse(FingerprintError::Blocked { status: None });
        }
        on_finger();
        self.fingers += 1;
        if let Some(code) = self.uv_refusals.pop_front() {
            if code == UV_INVALID {
                self.uv_retries -= 1;
            }
            return match fingerprint_refusal(code) {
                Some(why) => refuse(why),
                None => Err(CtapError::StatusCode(code)),
            };
        }
        Ok(self.issue(permissions, rp_id))
    }

    fn make_credential(
        &mut self,
        token: &PinUvAuthToken,
        user_id: &[u8],
        name: &str,
    ) -> Result<MadeCredential, CtapError> {
        self.log.push(Call::MakeCredential);
        self.check(token, MAKE_CREDENTIAL, RpUse::VaultRequest)?;
        let id = self.add_credential(user_id.to_vec(), Some(name));
        if self.mc_without_lbk {
            self.creds.last_mut().expect("just added").lbk = None;
        }
        self.keep_only_lbw(token);
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
        self.check(token, GET_ASSERTION, RpUse::VaultRequest)?;
        let matching: Vec<&FakeCred> = self
            .creds
            .iter()
            .filter(|c| allow.is_none_or(|id| c.id == id))
            .collect();
        let count = matching.len() as u32;
        let found: Vec<Assertion> = matching
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
            .collect();
        // A key with no matching credential answers NO_CREDENTIALS before
        // any touch, so the token keeps its permissions then.
        if !found.is_empty() {
            self.keep_only_lbw(token);
        }
        Ok(found)
    }

    fn credentials(&mut self, token: &PinUvAuthToken) -> Result<Vec<VaultCredential>, CtapError> {
        self.log.push(Call::Credentials);
        self.check(token, CREDENTIAL_MANAGEMENT, RpUse::VaultCredentials)?;
        if self.strict_listing && self.rp_of(token).is_some() {
            return Err(CtapError::StatusCode(PIN_AUTH_INVALID));
        }
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
                stored: StoredData::Unknown,
            })
            .collect())
    }

    fn delete_credential(
        &mut self,
        token: &PinUvAuthToken,
        credential_id: &[u8],
    ) -> Result<(), CtapError> {
        self.log.push(Call::Delete(credential_id.to_vec()));
        if let Some(code) = self.delete_refusals.pop_front() {
            return Err(CtapError::StatusCode(code));
        }
        self.check(token, CREDENTIAL_MANAGEMENT, RpUse::VaultCredentials)?;
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
        self.check(token, LARGE_BLOB_WRITE, RpUse::Ignored)?;
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
        self.writes += 1;
        if self
            .after_write
            .as_ref()
            .is_some_and(|(n, _)| *n == self.writes)
        {
            let (_, hook) = self.after_write.take().expect("checked above");
            hook(self);
        }
        if self.lost_write_replies > 0 {
            self.lost_write_replies -= 1;
            return Err(CtapError::Transport("the reply was lost".into()));
        }
        Ok(())
    }
}

/// A finger-ask callback for `VaultAuth::fingerprint` / `VaultAuth::auto`
/// that records every ask, and the record to check.
#[allow(clippy::type_complexity)]
pub fn asks() -> (Arc<Mutex<Vec<FingerAsk>>>, Box<dyn FnMut(FingerAsk) + Send>) {
    let asked = Arc::new(Mutex::new(Vec::new()));
    let record = Arc::clone(&asked);
    (
        asked,
        Box::new(move |why| record.lock().expect("not poisoned").push(why)),
    )
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
    fn the_after_write_hook_runs_after_its_stored_write() {
        let mut key = FakeKey::new();
        key.write_refusals.push_back(0x30);
        key.after_write = Some((
            1,
            Box::new(|k: &mut FakeKey| {
                k.add_foreign_entries();
            }),
        ));
        let t = token(&mut key, LARGE_BLOB_WRITE);
        let note = key
            .array()
            .with_text_note("x")
            .serialize_with_checksum()
            .unwrap();
        // A refused write stores nothing and is not counted.
        assert!(key.write_blobs(&t, &note).is_err());
        assert!(key.after_write.is_some());
        key.write_blobs(&t, &note).unwrap();
        assert!(key.after_write.is_none());
        assert_eq!(key.array().len(), 4, "the note, then the hook's three");
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
        let mc = token(&mut key, MAKE_CREDENTIAL);
        let made = key
            .make_credential(&mc, &user_handle("B").unwrap(), "B")
            .unwrap();
        assert!(made.large_blob_key.is_some());

        let ga = token(&mut key, GET_ASSERTION);
        let only = key.assertions(&ga, Some(&made.credential_id)).unwrap();
        assert_eq!(only.len(), 1);
        assert_eq!(only[0].number_of_credentials, Some(1));
        let ga = token(&mut key, GET_ASSERTION);
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
    fn makecredential_and_getassertion_leave_only_lbw() {
        let mut key = FakeKey::new();
        let id = key.add_vault("Personal", &Vault::default());
        let t = token(&mut key, GET_ASSERTION | LARGE_BLOB_WRITE);
        assert_eq!(key.assertions(&t, None).unwrap().len(), 1);
        assert_eq!(key.perms_of(&t), LARGE_BLOB_WRITE);
        assert!(matches!(
            key.assertions(&t, Some(&id)),
            Err(CtapError::StatusCode(PIN_AUTH_INVALID))
        ));
        let bytes = key.stored().to_vec();
        key.write_blobs(&t, &bytes).unwrap();
        assert_eq!(key.write_perms, vec![LARGE_BLOB_WRITE]);

        let t = token(&mut key, MAKE_CREDENTIAL | LARGE_BLOB_WRITE);
        key.make_credential(&t, &user_handle("Work").unwrap(), "Work")
            .unwrap();
        assert_eq!(key.perms_of(&t), LARGE_BLOB_WRITE);
        assert!(matches!(
            key.make_credential(&t, &user_handle("Other").unwrap(), "Other"),
            Err(CtapError::StatusCode(PIN_AUTH_INVALID))
        ));
        key.write_blobs(&t, &bytes).unwrap();

        // No credential matched: nothing was touched, nothing cleared.
        let t = token(&mut key, GET_ASSERTION);
        assert!(key.assertions(&t, Some(b"nope")).unwrap().is_empty());
        assert_eq!(key.perms_of(&t), GET_ASSERTION);
    }

    #[test]
    fn the_unreadable_entry_is_sealed_under_its_key_and_damaged() {
        use keyroost_ctap::large_blobs::CredentialData;
        let mut key = FakeKey::new();
        key.add_foreign_entries();
        let id = key.add_credential(b"plain".to_vec(), None);
        key.put_unreadable(&id);
        let array = key.array();
        assert_eq!(array.len(), 4);
        assert!(matches!(
            array.credential_data(&UNREADABLE_LBK),
            CredentialData::Unreadable
        ));
        assert_eq!(array.without_credential_blob(&UNREADABLE_LBK).len(), 3);
    }

    #[test]
    fn a_lost_reply_still_stores() {
        let mut key = FakeKey::new();
        key.lost_write_replies = 1;
        let t = token(&mut key, LARGE_BLOB_WRITE);
        let note = key
            .array()
            .with_text_note("x")
            .serialize_with_checksum()
            .unwrap();
        assert!(matches!(
            key.write_blobs(&t, &note),
            Err(CtapError::Transport(_))
        ));
        assert_eq!(key.array().len(), 1);
        key.write_blobs(&t, &note).unwrap();
    }

    fn finger(key: &mut FakeKey, perms: u32) -> Result<PinUvAuthToken, CtapError> {
        key.uv_token(perms, None, &mut || {})
    }

    #[test]
    fn a_finger_token_follows_getinfo_and_the_tries_left() {
        use keyroost_ctap::client_pin::permissions::BIO_ENROLLMENT;
        // No fingerprint: refused with no exchange and no finger.
        let mut key = FakeKey::new();
        assert!(matches!(
            finger(&mut key, LARGE_BLOB_WRITE),
            Err(CtapError::Fingerprint(FingerprintError::NotOffered))
        ));
        key.info.options.push(("uv".into(), false));
        assert!(matches!(
            finger(&mut key, LARGE_BLOB_WRITE),
            Err(CtapError::Fingerprint(FingerprintError::NoneEnrolled))
        ));
        assert!(key.log.is_empty());
        assert_eq!(key.fingers, 0);

        let mut key = FakeKey::with_fingerprint();
        assert!(matches!(
            finger(&mut key, BIO_ENROLLMENT),
            Err(CtapError::Fingerprint(FingerprintError::NotForThis))
        ));
        assert!(key.log.is_empty());

        key.uv_retries = 2;
        key.uv_refusals.extend([0x2F, UV_INVALID, UV_INVALID, 0x2F]);
        assert!(matches!(
            finger(&mut key, LARGE_BLOB_WRITE),
            Err(CtapError::Fingerprint(FingerprintError::Refused(0x2F)))
        ));
        assert_eq!(key.uv_retries, 2, "a timeout spends no try");
        for left in [1, 0] {
            assert!(matches!(
                finger(&mut key, LARGE_BLOB_WRITE),
                Err(CtapError::Fingerprint(FingerprintError::Refused(
                    UV_INVALID
                )))
            ));
            assert_eq!(key.uv_retries, left);
        }
        let mut asked = false;
        assert!(matches!(
            key.uv_token(LARGE_BLOB_WRITE, None, &mut || asked = true),
            Err(CtapError::Fingerprint(FingerprintError::Blocked {
                status: None
            }))
        ));
        assert!(!asked, "no finger once no try is left");
        assert_eq!(key.fingers, 3);
        assert_eq!(key.uv_refusals.len(), 1, "the blocked request popped none");

        key.uv_retries = 5;
        key.uv_refusals = [UV_BLOCKED, 0x37].into();
        assert!(matches!(
            finger(&mut key, LARGE_BLOB_WRITE),
            Err(CtapError::Fingerprint(FingerprintError::Blocked {
                status: Some(UV_BLOCKED)
            }))
        ));
        assert!(matches!(
            finger(&mut key, LARGE_BLOB_WRITE),
            Err(CtapError::StatusCode(0x37))
        ));

        let t = key
            .uv_token(CREDENTIAL_MANAGEMENT, Some(RP_ID), &mut || {})
            .unwrap();
        assert_eq!(
            key.log.last(),
            Some(&Call::UvToken {
                perms: CREDENTIAL_MANAGEMENT,
                rp: Some(RP_ID.into())
            })
        );
        assert!(key.credentials(&t).is_ok());
        assert_eq!(key.rp_of(&t).as_deref(), Some(RP_ID));
    }

    /// CTAP 2.1: a token's permissions RP ID limits credential management to
    /// that RP's credentials (6.8.4 enumerateCredentialsBegin, 6.8.5
    /// deleteCredential) and makeCredential / getAssertion to that RP; the
    /// largeBlob write ignores it, and a token with none is bound by its
    /// first makeCredential or getAssertion.
    #[test]
    fn a_token_bound_to_an_rp_serves_only_that_rp() {
        let all = CREDENTIAL_MANAGEMENT | GET_ASSERTION | MAKE_CREDENTIAL | LARGE_BLOB_WRITE;
        let refused =
            |r: Result<(), CtapError>| matches!(r, Err(CtapError::StatusCode(PIN_AUTH_INVALID)));
        let bytes = FakeKey::new().stored().to_vec();
        for fingerprint in [false, true] {
            let mut key = FakeKey::with_fingerprint();
            let id = key.add_vault("Personal", &Vault::default());
            let bound = |key: &mut FakeKey, rp| {
                if fingerprint {
                    key.uv_token(all, rp, &mut || {}).unwrap()
                } else {
                    key.pin_token(FakeKey::PIN, all, rp).unwrap()
                }
            };

            let other = bound(&mut key, Some("example.com"));
            assert!(refused(key.credentials(&other).map(drop)));
            assert!(refused(key.delete_credential(&other, &id)));
            assert!(refused(key.assertions(&other, None).map(drop)));
            assert!(refused(
                key.make_credential(&other, &user_handle("W").unwrap(), "W")
                    .map(drop)
            ));
            key.write_blobs(&other, &bytes).unwrap();
            assert_eq!(key.creds.len(), 1, "nothing made or deleted");

            let vault = bound(&mut key, Some(RP_ID));
            assert_eq!(key.credentials(&vault).unwrap().len(), 1);
            let made = key
                .make_credential(&vault, &user_handle("W").unwrap(), "W")
                .unwrap();
            let vault = bound(&mut key, Some(RP_ID));
            assert_eq!(key.assertions(&vault, None).unwrap().len(), 2);
            let vault = bound(&mut key, Some(RP_ID));
            key.delete_credential(&vault, &made.credential_id).unwrap();

            // No RP: credential management of the vault RP serves, and the
            // first getAssertion binds it to the vault RP.
            let unbound = bound(&mut key, None);
            assert_eq!(key.rp_of(&unbound), None);
            assert_eq!(key.credentials(&unbound).unwrap().len(), 1);
            assert_eq!(key.assertions(&unbound, None).unwrap().len(), 1);
            assert_eq!(key.rp_of(&unbound).as_deref(), Some(RP_ID));
        }
    }

    /// CTAP 2.2's 6.8.4 as written: no listing under a token bound to an
    /// RP, the vault RP's included; an unbound one lists, and a bound one
    /// still deletes (6.8.5).
    #[test]
    fn a_strict_key_lists_only_under_an_unbound_token() {
        let mut key = FakeKey::with_fingerprint();
        key.strict_listing = true;
        let id = key.add_vault("Personal", &Vault::default());
        let cm = CREDENTIAL_MANAGEMENT;
        let bound = key.uv_token(cm, Some(RP_ID), &mut || {}).unwrap();
        assert!(matches!(
            key.credentials(&bound),
            Err(CtapError::StatusCode(PIN_AUTH_INVALID))
        ));
        let unbound = key.uv_token(cm, None, &mut || {}).unwrap();
        assert_eq!(key.credentials(&unbound).unwrap().len(), 1);
        let bound = key.uv_token(cm, Some(RP_ID), &mut || {}).unwrap();
        key.delete_credential(&bound, &id).unwrap();
        assert!(key.creds.is_empty());
    }

    #[test]
    fn a_dropping_key_leaves_the_token_nothing_after_a_touch() {
        let mut key = FakeKey::with_fingerprint();
        key.drops_token_after_presence = true;
        key.add_vault("Personal", &Vault::default());
        let t = finger(&mut key, GET_ASSERTION | LARGE_BLOB_WRITE).unwrap();
        assert_eq!(key.assertions(&t, None).unwrap().len(), 1);
        assert_eq!(key.perms_of(&t), 0);
        let bytes = key.stored().to_vec();
        assert!(matches!(
            key.write_blobs(&t, &bytes),
            Err(CtapError::StatusCode(PIN_AUTH_INVALID))
        ));
    }

    #[test]
    fn asks_records_every_ask() {
        let (asked, mut ask) = asks();
        ask(FingerAsk::Unlock);
        ask(FingerAsk::Again);
        assert_eq!(
            *asked.lock().unwrap(),
            [FingerAsk::Unlock, FingerAsk::Again]
        );
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
