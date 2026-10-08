//! `authenticatorLargeBlobs` (0x0C) — read and write the serialized large-blob
//! array stored on a FIDO2 authenticator.
//!
//! # What this is (and is not)
//!
//! The large-blob array is a key-global store that any platform can **read
//! without a PIN or user verification**. It is explicitly NOT a confidential
//! vault: a Relying Party encrypts its own per-credential data before storing
//! it here, and the array as a whole is world-readable to anyone holding the
//! key. Treat the contents as opaque, possibly-encrypted bytes — never as a
//! place to put plaintext secrets.
//!
//! # Serialized format (CTAP §6.10.2)
//!
//! The stored bytes are a CTAP2-canonical **CBOR array** of per-credential
//! maps, immediately followed by a **16-byte truncated SHA-256** checksum over
//! the serialized array bytes:
//!
//! ```text
//! stored = cbor(array_of_entry_maps) || left16( SHA-256(cbor(array_of_entry_maps)) )
//! ```
//!
//! Each entry map has the shape `{1: ciphertext (bstr), 2: nonce (bstr, 12
//! bytes), 3: origSize (uint)}`; other keys are allowed. We parse entries
//! structurally so that edits re-serialize cleanly and the trailing checksum is
//! always recomputed — a naive raw-byte edit that left a stale checksum would
//! make the key reject the whole array (or fail future credential writes) until
//! a reset. An element that isn't such a map is skipped on read (§6.10.4) and
//! kept, unchanged and in place, on every write.
//!
//! # Reading
//!
//! `get` is chunked by `offset`; we reassemble fragments until the declared
//! length is reached, then verify the checksum trailer.
//!
//! # Writing
//!
//! `set` is chunked by `maxFragmentLength = maxMsgSize - 64`. Every fragment
//! carries a `pinUvAuthParam` computed specially (see `write_auth_param`):
//!
//! ```text
//! authenticate( token, 0xff*32 || 0x0c 0x00 || uint32LE(offset) || SHA-256(fragment) )
//! ```
//!
//! and requires the `lbw` (Large Blob Write, 0x10) permission on the token. The
//! authenticator keeps a short-lived (~30s) write state machine: the first
//! fragment carries `length` (the total) at `offset = 0`, and subsequent
//! fragments must follow immediately at increasing offsets.

use crate::cbor::{self, Value};
use crate::client_pin::PinUvAuthToken;
use crate::cmd::{AuthenticatorInfo, CtapError};
use crate::hid::CTAPHID_CBOR;
use crate::pin::left16_sha256;
use crate::ssh_cert;
use crate::transport::CtapTransport;

/// CTAP command byte for `authenticatorLargeBlobs`.
const CTAP2_LARGE_BLOBS: u8 = 0x0C;

// Request map keys.
const KEY_GET: u64 = 0x01;
const KEY_SET: u64 = 0x02;
const KEY_OFFSET: u64 = 0x03;
const KEY_LENGTH: u64 = 0x04;
const KEY_PIN_UV_AUTH_PARAM: u64 = 0x05;
const KEY_PIN_UV_AUTH_PROTOCOL: u64 = 0x06;

// Response map key for the returned fragment.
const RESP_CONFIG: u64 = 0x01;

// Entry map keys within the serialized array.
const ENTRY_CIPHERTEXT: u64 = 0x01;
const ENTRY_NONCE: u64 = 0x02;
const ENTRY_ORIG_SIZE: u64 = 0x03;

/// Length of the truncated SHA-256 checksum trailer.
const CHECKSUM_LEN: usize = 16;

/// Conservative fall-back fragment size when the authenticator does not report
/// `maxMsgSize` (the spec floor is 1024 bytes; we subtract the 64-byte
/// allowance the spec reserves for the rest of the message).
const DEFAULT_MAX_MSG_SIZE: u64 = 1024;
const MSG_SIZE_OVERHEAD: u64 = 64;

/// Spec floor for `maxSerializedLargeBlobArray` when the authenticator
/// supports large blobs but does not advertise the key (CTAP 2.1 §6.10).
const SPEC_MIN_SERIALIZED_ARRAY: u64 = 1024;

/// Space accounting for a large-blob array against an authenticator's
/// advertised (or spec-minimum) storage. Sizes count the full serialized
/// form — CBOR array plus the 16-byte checksum trailer — because that is
/// what `maxSerializedLargeBlobArray` bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobCapacity {
    pub max_bytes: u64,
    pub used_bytes: u64,
    pub free_bytes: u64,
    pub entry_count: usize,
}

/// The empty large-blob array: an empty CBOR array (`0x80`) followed by the
/// 16-byte checksum of that single byte. Writing this effectively clears the
/// store. Computed lazily to avoid a const-fn hash.
pub fn empty_array_serialized() -> Vec<u8> {
    let array = cbor::encode(&Value::Array(Vec::new()));
    let mut out = array.clone();
    out.extend_from_slice(&left16_sha256(&array));
    out
}

/// One decoded entry from the large-blob array. Fields are the raw, still-
/// encrypted bytes as stored; we do not (and cannot) decrypt them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LargeBlobEntry {
    /// RP-encrypted payload (AEAD ciphertext + tag).
    pub ciphertext: Vec<u8>,
    /// AEAD nonce (typically 12 bytes).
    pub nonce: Vec<u8>,
    /// Declared size of the plaintext before encryption/compression.
    pub orig_size: u64,
    /// The exact CBOR this entry was read as; `None` for an entry built here.
    /// Re-emitted unchanged so unknown map keys survive a rewrite.
    original: Option<Vec<u8>>,
}

/// Magic prefix that marks an entry as a keyroost-authored plaintext note,
/// rather than a genuine relying-party AEAD record. `KR` + format version `1` +
/// a NUL separator. Real RP entries will (essentially) never begin with this,
/// so it lets read-back tell keyroost's own notes apart from data it must not
/// try to interpret.
pub const KR_NOTE_MAGIC: &[u8] = b"KR1\0";

impl LargeBlobEntry {
    /// Build an entry that stores `text` as a keyroost note. The text is placed,
    /// UTF-8 encoded and prefixed with [`KR_NOTE_MAGIC`], in the `ciphertext`
    /// field. This is NOT encryption — it is a structurally-valid container so
    /// the byte string round-trips through the array intact and is recognizable
    /// on read. The nonce is a fixed all-zero 12-byte value (there is no AEAD).
    pub fn from_text(text: &str) -> Self {
        let mut ciphertext = Vec::with_capacity(KR_NOTE_MAGIC.len() + text.len());
        ciphertext.extend_from_slice(KR_NOTE_MAGIC);
        ciphertext.extend_from_slice(text.as_bytes());
        LargeBlobEntry {
            ciphertext,
            nonce: vec![0u8; 12],
            orig_size: text.len() as u64,
            original: None,
        }
    }

    /// If this entry is a keyroost note (its ciphertext starts with
    /// [`KR_NOTE_MAGIC`] and the remainder is valid UTF-8), return the stored
    /// text. Returns `None` for genuine RP entries, which must be shown only as
    /// raw bytes and never interpreted as text.
    pub fn as_text(&self) -> Option<String> {
        let body = self.ciphertext.strip_prefix(KR_NOTE_MAGIC)?;
        std::str::from_utf8(body).ok().map(|s| s.to_owned())
    }

    /// Whether this entry was authored by keyroost (carries the note magic).
    pub fn is_kr_note(&self) -> bool {
        self.ciphertext.starts_with(KR_NOTE_MAGIC)
    }

    /// Classify this entry. Conservative by construction: the keyroost note
    /// magic wins outright, certificate recognition requires a complete,
    /// well-formed parse, and everything else is opaque.
    pub fn classify(&self) -> EntryKind {
        if let Some(text) = self.as_text() {
            return EntryKind::Note(text);
        }
        if let Some(info) = ssh_cert::parse_wire(&self.ciphertext) {
            return EntryKind::SshCert {
                info,
                wire: self.ciphertext.clone(),
            };
        }
        if let Ok(s) = std::str::from_utf8(&self.ciphertext) {
            if let Some((info, wire)) = ssh_cert::parse_text(s.trim()) {
                return EntryKind::SshCert { info, wire };
            }
        }
        EntryKind::Opaque
    }
}

/// What a large-blob entry *is*, as far as keyroost can honestly tell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
    /// keyroost plaintext note (magic-prefixed).
    Note(String),
    /// A recognized OpenSSH certificate. `wire` holds the canonical binary
    /// certificate (decoded from base64 when the entry stored the text form),
    /// ready for export as a `-cert.pub`.
    SshCert {
        info: ssh_cert::SshCertInfo,
        wire: Vec<u8>,
    },
    /// Anything unrecognized — treated as RP-owned AEAD data: shown raw,
    /// never reinterpreted, never rewritten.
    Opaque,
}

/// One element of the serialized array, with the bytes it was read as.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Item {
    /// A conforming large-blob map (§6.10.3): key 1 bstr, key 2 bstr of
    /// exactly 12 bytes, key 3 uint; other keys allowed.
    Entry(LargeBlobEntry),
    /// Any other element. Skipped by every reader, kept by every writer.
    Skipped(Vec<u8>),
}

/// A parsed large-blob array: its elements in stored order plus the exact raw
/// bytes they were decoded from (handy for a hex/ASCII view and for diffing).
///
/// Elements that are not a conforming entry map are *skipped* (CTAP 2.1
/// §6.10.4: readers ignore them) but never dropped: every rewrite emits them
/// again, unchanged and in place. Entry indices ([`entries`](Self::entries),
/// [`entry`](Self::entry), [`with_replaced_note`](Self::with_replaced_note),
/// [`without_entry`](Self::without_entry)) count conforming entries only.
#[derive(Debug, Clone)]
pub struct LargeBlobArray {
    items: Vec<Item>,
    /// The serialized array WITHOUT the checksum trailer.
    raw_array: Vec<u8>,
}

impl LargeBlobArray {
    /// Parse a serialized array (without the checksum trailer).
    ///
    /// Fails only when the array itself is unreadable (not a definite-length
    /// array, truncated, or an element whose extent can't be measured) —
    /// then nothing in it can be kept safely. A single element that isn't a
    /// conforming entry is skipped instead.
    pub fn parse(array_bytes: &[u8]) -> Result<LargeBlobArray, CtapError> {
        let items = parse_items(array_bytes)?;
        Ok(LargeBlobArray {
            items,
            raw_array: array_bytes.to_vec(),
        })
    }

    /// Conforming entries in array order; indices used by `fido blob` and the GUI.
    pub fn entries(&self) -> Vec<&LargeBlobEntry> {
        self.entry_iter().collect()
    }

    /// The conforming entry at `idx` (counting conforming entries only).
    pub fn entry(&self, idx: usize) -> Option<&LargeBlobEntry> {
        self.entry_iter().nth(idx)
    }

    /// Number of conforming entries.
    pub fn len(&self) -> usize {
        self.entry_iter().count()
    }

    /// Whether there are no conforming entries (skipped elements may remain).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Elements skipped because they don't conform (kept on every write).
    pub fn skipped_count(&self) -> usize {
        self.items
            .iter()
            .filter(|i| matches!(i, Item::Skipped(_)))
            .count()
    }

    /// The bytes read from the key (empty for an array changed here).
    pub fn raw_array(&self) -> &[u8] {
        &self.raw_array
    }

    fn entry_iter(&self) -> impl Iterator<Item = &LargeBlobEntry> {
        self.items.iter().filter_map(|i| match i {
            Item::Entry(e) => Some(e),
            Item::Skipped(_) => None,
        })
    }

    /// Position in `items` of the conforming entry numbered `idx`.
    fn item_index(&self, idx: usize) -> Option<usize> {
        self.items
            .iter()
            .enumerate()
            .filter(|(_, i)| matches!(i, Item::Entry(_)))
            .nth(idx)
            .map(|(pos, _)| pos)
    }

    fn changed(items: Vec<Item>) -> LargeBlobArray {
        LargeBlobArray {
            items,
            raw_array: Vec::new(),
        }
    }

    /// Re-serialize the current elements and append a freshly-computed
    /// checksum, yielding bytes ready to hand to [`write()`].
    ///
    /// Every element read from the key is emitted exactly as it was read —
    /// an entry's unknown map keys (§6.10.3 allows them) and skipped elements
    /// survive byte-for-byte. Only entries built here are encoded fresh.
    pub fn serialize_with_checksum(&self) -> Vec<u8> {
        let mut array = cbor::array_header(self.items.len());
        for item in &self.items {
            match item {
                Item::Entry(LargeBlobEntry {
                    original: Some(raw),
                    ..
                })
                | Item::Skipped(raw) => array.extend_from_slice(raw),
                Item::Entry(e) => array.extend_from_slice(&encode_entry(e)),
            }
        }
        let mut out = array.clone();
        out.extend_from_slice(&left16_sha256(&array));
        out
    }

    /// Return a copy of this array with a new keyroost text note appended.
    pub fn with_text_note(&self, text: &str) -> LargeBlobArray {
        let mut items = self.items.clone();
        items.push(Item::Entry(LargeBlobEntry::from_text(text)));
        Self::changed(items)
    }

    /// Return a copy of this array with the keyroost note at `idx` replaced by
    /// `text`. Refuses (returns `None`) if `idx` is out of range or the target
    /// is NOT a keyroost note — relying-party entries are AEAD-encrypted by
    /// their owner and must never be rewritten as plaintext.
    pub fn with_replaced_note(&self, idx: usize, text: &str) -> Option<LargeBlobArray> {
        if !self.entry(idx)?.is_kr_note() {
            return None;
        }
        let pos = self.item_index(idx)?;
        let mut items = self.items.clone();
        items[pos] = Item::Entry(LargeBlobEntry::from_text(text));
        Some(Self::changed(items))
    }

    /// Return a copy of this array without the conforming entry at `idx`
    /// (counting conforming entries only). `None` if `idx` is out of range.
    pub fn without_entry(&self, idx: usize) -> Option<LargeBlobArray> {
        let pos = self.item_index(idx)?;
        let mut items = self.items.clone();
        items.remove(pos);
        Some(Self::changed(items))
    }

    /// Compute capacity from the elements as currently held (re-serialized,
    /// so it stays correct after local adds/edits that haven't been written).
    pub fn capacity(&self, info: &AuthenticatorInfo) -> BlobCapacity {
        let used = self.serialize_with_checksum().len() as u64;
        let max = info
            .max_serialized_large_blob_array
            .unwrap_or(SPEC_MIN_SERIALIZED_ARRAY);
        BlobCapacity {
            max_bytes: max,
            used_bytes: used,
            free_bytes: max.saturating_sub(used),
            entry_count: self.len(),
        }
    }
}

/// The canonical `{1: ciphertext, 2: nonce, 3: origSize}` map for `e`.
fn encode_entry(e: &LargeBlobEntry) -> Vec<u8> {
    cbor::encode(&Value::Map(vec![
        (
            Value::UInt(ENTRY_CIPHERTEXT),
            Value::Bytes(e.ciphertext.clone()),
        ),
        (Value::UInt(ENTRY_NONCE), Value::Bytes(e.nonce.clone())),
        (Value::UInt(ENTRY_ORIG_SIZE), Value::UInt(e.orig_size)),
    ]))
}

/// Effective maximum `set`/`get` fragment length for this authenticator.
pub fn max_fragment_length(info: &AuthenticatorInfo) -> usize {
    let max = info.max_msg_size.unwrap_or(DEFAULT_MAX_MSG_SIZE);
    max.saturating_sub(MSG_SIZE_OVERHEAD).max(1) as usize
}

fn dispatch(dev: &mut impl CtapTransport, params: Value) -> Result<Value, CtapError> {
    let mut payload = Vec::new();
    payload.push(CTAP2_LARGE_BLOBS);
    payload.extend_from_slice(&cbor::encode(&params));
    let resp = dev.transact(CTAPHID_CBOR, &payload)?;
    let (status, body) = resp.split_first().ok_or(CtapError::EmptyResponse)?;
    if *status != 0 {
        return Err(CtapError::StatusCode(*status));
    }
    if body.is_empty() {
        // `set` returns an empty success payload.
        return Ok(Value::Null);
    }
    let (value, _) = cbor::decode(body)?;
    Ok(value)
}

/// Read one fragment beginning at `offset`, asking for at most `count` bytes.
fn read_fragment(
    dev: &mut impl CtapTransport,
    offset: u64,
    count: u64,
) -> Result<Vec<u8>, CtapError> {
    let params = Value::Map(vec![
        (Value::UInt(KEY_GET), Value::UInt(count)),
        (Value::UInt(KEY_OFFSET), Value::UInt(offset)),
    ]);
    let resp = dispatch(dev, params)?;
    let Value::Map(entries) = resp else {
        return Err(CtapError::InvalidResponseShape("largeBlobs get: not a map"));
    };
    for (k, v) in entries {
        if matches!(k, Value::UInt(RESP_CONFIG)) {
            if let Value::Bytes(b) = v {
                return Ok(b);
            }
            return Err(CtapError::InvalidResponseShape(
                "largeBlobs get: config not a byte string",
            ));
        }
    }
    Err(CtapError::InvalidResponseShape(
        "largeBlobs get: missing config",
    ))
}

/// Read the entire serialized large-blob array, verify its checksum, and parse
/// the entries. Requires no PIN/UV.
pub fn read(
    dev: &mut impl CtapTransport,
    info: &AuthenticatorInfo,
) -> Result<LargeBlobArray, CtapError> {
    let frag = max_fragment_length(info) as u64;

    // First read tells us how much there is by simply continuing until a short
    // fragment arrives (the authenticator returns fewer bytes than asked once
    // it hits the end).
    let mut data = Vec::new();
    let mut offset = 0u64;
    loop {
        let chunk = read_fragment(dev, offset, frag)?;
        let got = chunk.len() as u64;
        data.extend_from_slice(&chunk);
        if got < frag {
            break; // reached the end
        }
        offset += got;
        // Safety valve: large-blob stores are small; refuse to loop forever.
        if data.len() > 64 * 1024 {
            return Err(CtapError::InvalidResponseShape(
                "largeBlobs: array too large",
            ));
        }
    }

    if data.len() < CHECKSUM_LEN {
        return Err(CtapError::InvalidResponseShape(
            "largeBlobs: array shorter than checksum",
        ));
    }
    let (array_bytes, trailer) = data.split_at(data.len() - CHECKSUM_LEN);
    let expected = left16_sha256(array_bytes);
    if trailer != expected {
        return Err(CtapError::InvalidResponseShape(
            "largeBlobs: checksum mismatch",
        ));
    }

    LargeBlobArray::parse(array_bytes)
}

fn parse_items(array_bytes: &[u8]) -> Result<Vec<Item>, CtapError> {
    if array_bytes.first().map(|b| b >> 5) != Some(4) {
        return Err(CtapError::InvalidResponseShape("largeBlobs: not an array"));
    }
    let (elements, _) = cbor::split_array(array_bytes)?;
    // CTAP 2.1 §6.10.4 step 6: readers skip elements that don't conform.
    // They are kept as read, so a rewrite emits them again unchanged.
    Ok(elements
        .into_iter()
        .map(|raw| match conforming_entry(raw) {
            Some(entry) => Item::Entry(entry),
            None => Item::Skipped(raw.to_vec()),
        })
        .collect())
}

/// `raw` as a large-blob entry if it is a conforming entry map (§6.10.3):
/// key 1 a byte string, key 2 a 12-byte byte string, key 3 an unsigned
/// integer, each exactly once; other keys are allowed and kept in `original`.
fn conforming_entry(raw: &[u8]) -> Option<LargeBlobEntry> {
    let (Value::Map(map), rest) = cbor::decode(raw).ok()? else {
        return None;
    };
    if !rest.is_empty() {
        return None;
    }
    let mut ciphertext = None;
    let mut nonce = None;
    let mut orig_size = None;
    for (k, v) in map {
        let slot_taken = match (k, v) {
            (Value::UInt(ENTRY_CIPHERTEXT), Value::Bytes(b)) => ciphertext.replace(b).is_some(),
            (Value::UInt(ENTRY_NONCE), Value::Bytes(b)) if b.len() == 12 => {
                nonce.replace(b).is_some()
            }
            (Value::UInt(ENTRY_ORIG_SIZE), Value::UInt(n)) => orig_size.replace(n).is_some(),
            (Value::UInt(ENTRY_CIPHERTEXT | ENTRY_NONCE | ENTRY_ORIG_SIZE), _) => return None,
            _ => false,
        };
        if slot_taken {
            return None; // a duplicate required key: ambiguous, never guess
        }
    }
    Some(LargeBlobEntry {
        ciphertext: ciphertext?,
        nonce: nonce?,
        orig_size: orig_size?,
        original: Some(raw.to_vec()),
    })
}

/// The `pinUvAuthParam` for a `set` fragment at `offset`:
/// `authenticate( token, 0xff*32 || 0x0c 0x00 || uint32LE(offset) || SHA-256(fragment) )`.
fn write_auth_param(token: &PinUvAuthToken, offset: u32, fragment: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let frag_hash = Sha256::digest(fragment);
    let mut msg = Vec::with_capacity(32 + 2 + 4 + 32);
    msg.extend_from_slice(&[0xffu8; 32]);
    msg.push(CTAP2_LARGE_BLOBS); // 0x0c
    msg.push(0x00);
    msg.extend_from_slice(&offset.to_le_bytes());
    msg.extend_from_slice(&frag_hash);
    token.authenticate(&msg)
}

/// Overwrite the entire large-blob array with `serialized` (which MUST already
/// include its 16-byte checksum trailer — use
/// [`LargeBlobArray::serialize_with_checksum`] or [`empty_array_serialized`]).
///
/// Requires a `pinUvAuthToken` carrying the `lbw` permission. Writes the data
/// in `maxFragmentLength`-sized fragments, honoring the authenticator's stateful
/// write protocol (length declared once at offset 0).
pub fn write(
    dev: &mut impl CtapTransport,
    info: &AuthenticatorInfo,
    token: &PinUvAuthToken,
    serialized: &[u8],
) -> Result<(), CtapError> {
    let frag_len = max_fragment_length(info);
    let total = serialized.len() as u64;
    let mut offset: usize = 0;

    while offset < serialized.len() {
        let end = (offset + frag_len).min(serialized.len());
        let fragment = &serialized[offset..end];
        let auth = write_auth_param(token, offset as u32, fragment);

        let mut entries: Vec<(Value, Value)> = vec![
            (Value::UInt(KEY_SET), Value::Bytes(fragment.to_vec())),
            (Value::UInt(KEY_OFFSET), Value::UInt(offset as u64)),
        ];
        // `length` (the total) is sent only on the first fragment (offset 0).
        if offset == 0 {
            entries.push((Value::UInt(KEY_LENGTH), Value::UInt(total)));
        }
        // CTAP 2.1 §6 canonical CBOR: map keys MUST be ascending. For
        // authenticatorLargeBlobs, pinUvAuthParam is 0x05 and pinUvAuthProtocol
        // is 0x06 (the param has the LOWER key here, unlike other CTAP commands),
        // so param must be pushed before protocol — else spec-strict
        // authenticators reject the write with CTAP2_ERR_INVALID_CBOR.
        entries.push((Value::UInt(KEY_PIN_UV_AUTH_PARAM), Value::Bytes(auth)));
        entries.push((
            Value::UInt(KEY_PIN_UV_AUTH_PROTOCOL),
            Value::UInt(token.protocol as u64),
        ));

        dispatch(dev, Value::Map(entries))?;
        offset = end;
    }
    Ok(())
}

/// AES-256-GCM decrypt of one largeBlob entry (CTAP §6.10.4). AAD is
/// `b"blob"` followed by the 8-byte little-endian original (uncompressed)
/// size. `ciphertext` includes the trailing 16-byte GCM tag. Returns None on
/// any authentication failure — the caller trial-decrypts entries and treats
/// None as "not this credential's blob".
pub(crate) fn gcm_decrypt(
    key: &[u8; 32],
    nonce: &[u8],
    ciphertext: &[u8],
    orig_size: u64,
) -> Option<Vec<u8>> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};

    if nonce.len() != 12 {
        return None;
    }
    let mut aad = Vec::with_capacity(12);
    aad.extend_from_slice(b"blob");
    aad.extend_from_slice(&orig_size.to_le_bytes());
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .ok()
}

/// Host-side ceiling on the inflated plaintext of a single largeBlob entry.
///
/// `origSize` is chosen by the authenticator, so without a ceiling of our own
/// the key decides how much work and memory the host spends inflating — and
/// `cred_mgmt` will happily hand us one entry per credential. The array-level
/// valve in [`read()`] bounds the *compressed* side (64 KiB), but DEFLATE
/// expands, so it does not bound this side at all.
///
/// 1 MiB is far above anything an honest entry can hold: authenticators
/// advertise `maxSerializedLargeBlobArray` in the low kilobytes (spec floor
/// 1024 bytes, typical keys 1–4 KiB for the *whole* array), and the payload
/// we actually decode — an OpenSSH certificate — is ~2 KB. Even a 4 KiB entry
/// of pathologically compressible data would have to hit a 256:1 ratio to
/// reach this cap, so no legitimate blob is rejected; a hostile key is capped
/// at ~1 MiB per credential instead of the ~70 MB the compressed valve allows.
const MAX_BLOB_PLAINTEXT: usize = 1024 * 1024;

/// Raw-DEFLATE inflate (RFC 1951 — NOT zlib-wrapped) of the decrypted
/// plaintext, bounded by `orig_size`. Returns None when `orig_size` exceeds
/// [`MAX_BLOB_PLAINTEXT`] (checked before any decompression runs), on
/// malformed input, or when the inflated length does not equal `orig_size`.
pub(crate) fn inflate_raw(compressed: &[u8], orig_size: u64) -> Option<Vec<u8>> {
    let limit = usize::try_from(orig_size).ok()?;
    // Clamp against our own ceiling BEFORE handing the size to the
    // decompressor — the device does not get to pick how much we allocate.
    if limit > MAX_BLOB_PLAINTEXT {
        return None;
    }
    // The RAW (non-zlib) limited inflate. `decompress_to_vec_with_limit` is
    // raw DEFLATE with a size cap; the `_zlib` variants expect a zlib header,
    // which the largeBlob plaintext does NOT have.
    let out = miniz_oxide::inflate::decompress_to_vec_with_limit(compressed, limit).ok()?;
    (out.len() as u64 == orig_size).then_some(out)
}

/// Find and decode this credential's SSH certificate from the largeBlob
/// array. Trial-decrypts each entry with the credential's largeBlobKey (the
/// GCM tag identifies the matching entry), inflates the raw-DEFLATE plaintext,
/// and returns the certificate **wire bytes** when the result parses as an
/// OpenSSH certificate. None when no entry is this credential's, or the
/// decrypted blob is not a certificate. Pure over an already-read array;
/// skipped (non-conforming) elements are never tried.
pub fn extract_cert_from_entries(
    large_blob_key: &[u8; 32],
    array: &LargeBlobArray,
) -> Option<Vec<u8>> {
    for e in array.entry_iter() {
        let Some(plain) = gcm_decrypt(large_blob_key, &e.nonce, &e.ciphertext, e.orig_size) else {
            continue; // not this credential's entry (tag failed)
        };
        let Some(wire) = inflate_raw(&plain, e.orig_size) else {
            continue; // decrypted but not valid DEFLATE / size mismatch
        };
        if ssh_cert::parse_wire(&wire).is_some() {
            return Some(wire);
        }
        // Decrypted + inflated but not a cert: it's this credential's blob but
        // holds non-cert data. Stop — this IS the credential's entry.
        return None;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gcm_roundtrip_and_wrong_key_fails() {
        use aes_gcm::{
            aead::{Aead, KeyInit, Payload},
            Aes256Gcm, Nonce,
        };
        let key = [7u8; 32];
        let nonce = [3u8; 12];
        let plaintext = b"hello blob";
        let orig_size = plaintext.len() as u64;
        let mut aad = b"blob".to_vec();
        aad.extend_from_slice(&orig_size.to_le_bytes());
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .unwrap();
        // Right key decrypts.
        assert_eq!(
            gcm_decrypt(&key, &nonce, &ct, orig_size).as_deref(),
            Some(&plaintext[..])
        );
        // Wrong key fails the tag.
        assert_eq!(gcm_decrypt(&[9u8; 32], &nonce, &ct, orig_size), None);
        // Wrong orig_size changes the AAD → tag fails.
        assert_eq!(gcm_decrypt(&key, &nonce, &ct, orig_size + 1), None);
    }

    #[test]
    fn inflate_raw_roundtrip_and_bounds() {
        let data = b"the quick brown fox ".repeat(50);
        let compressed = miniz_oxide::deflate::compress_to_vec(&data, 6);
        assert_eq!(
            inflate_raw(&compressed, data.len() as u64).as_deref(),
            Some(&data[..])
        );
        // Garbage input → None, not a panic.
        assert_eq!(inflate_raw(&[0xff, 0x00, 0x13, 0x37], 100), None);
        // A declared orig_size the inflated data doesn't match → None.
        assert_eq!(inflate_raw(&compressed, (data.len() + 1) as u64), None);
    }

    #[test]
    fn inflate_raw_rejects_orig_size_above_ceiling() {
        // Genuinely valid DEFLATE that really does inflate to ceiling+1: the
        // rejection can only come from the ceiling check, not from the
        // after-the-fact length comparison. Highly compressible, so building
        // the fixture is cheap.
        let oversize = vec![0u8; MAX_BLOB_PLAINTEXT + 1];
        let compressed = miniz_oxide::deflate::compress_to_vec(&oversize, 6);
        assert_eq!(inflate_raw(&compressed, oversize.len() as u64), None);

        // Exactly at the ceiling still works, so the bound is inclusive and
        // nothing legitimate sits on the wrong side of it.
        let at_limit = vec![0u8; MAX_BLOB_PLAINTEXT];
        let compressed_at = miniz_oxide::deflate::compress_to_vec(&at_limit, 6);
        assert_eq!(
            inflate_raw(&compressed_at, at_limit.len() as u64).map(|v| v.len()),
            Some(MAX_BLOB_PLAINTEXT)
        );

        // An absurd device-claimed size is refused without allocating for it.
        assert_eq!(inflate_raw(&compressed, u64::MAX), None);
        assert_eq!(inflate_raw(&compressed, 4 * 1024 * 1024 * 1024), None);
    }

    #[test]
    fn inflate_raw_accepts_a_realistic_ssh_certificate() {
        // The payload this path actually decodes: a real OpenSSH certificate,
        // raw-DEFLATE compressed exactly as fido2-token stores it. Must round
        // trip unaffected by the ceiling.
        let cert_pub = crate::ssh_cert::tests_fixture::FIXTURE_CERT_PUB;
        let (_, wire) = crate::ssh_cert::parse_text(cert_pub.trim()).unwrap();
        assert!(wire.len() < MAX_BLOB_PLAINTEXT);
        let compressed = miniz_oxide::deflate::compress_to_vec(&wire, 6);
        assert_eq!(
            inflate_raw(&compressed, wire.len() as u64).as_deref(),
            Some(&wire[..])
        );
        // And a size mismatch on that same legitimate blob is still refused.
        assert_eq!(inflate_raw(&compressed, (wire.len() - 1) as u64), None);
    }

    fn sample_entry(seed: u8) -> LargeBlobEntry {
        LargeBlobEntry {
            ciphertext: vec![seed; 20],
            nonce: vec![seed.wrapping_add(1); 12],
            orig_size: seed as u64 + 4,
            original: None,
        }
    }

    /// An array holding `entries` as built here (no bytes read from a key).
    fn array_of(entries: Vec<LargeBlobEntry>) -> LargeBlobArray {
        LargeBlobArray::changed(entries.into_iter().map(Item::Entry).collect())
    }

    /// The entries of `arr` with the read-back bytes forgotten, for comparing
    /// the decoded fields against entries built here.
    fn fields(arr: &LargeBlobArray) -> Vec<LargeBlobEntry> {
        arr.entries()
            .into_iter()
            .map(|e| LargeBlobEntry {
                original: None,
                ..e.clone()
            })
            .collect()
    }

    /// An array of the given raw elements, behind a canonical header.
    fn raw_array_of(elements: &[&[u8]]) -> Vec<u8> {
        let mut out = cbor::array_header(elements.len());
        for e in elements {
            out.extend_from_slice(e);
        }
        out
    }

    fn map_bytes(pairs: Vec<(Value, Value)>) -> Vec<u8> {
        cbor::encode(&Value::Map(pairs))
    }

    #[test]
    fn parse_skips_non_conforming_elements() {
        let missing_size = map_bytes(vec![
            (Value::UInt(1), Value::Bytes(vec![0xaa])),
            (Value::UInt(2), Value::Bytes(vec![0x22; 12])),
        ]);
        let short_nonce = map_bytes(vec![
            (Value::UInt(1), Value::Bytes(vec![0xaa])),
            (Value::UInt(2), Value::Bytes(vec![0x22; 11])),
            (Value::UInt(3), Value::UInt(1)),
        ]);
        let note = encode_entry(&LargeBlobEntry::from_text("kept"));
        let bytes = raw_array_of(&[
            &[0x61, 0x78],
            &missing_size,
            &short_nonce,
            &[0xc1, 0x01],
            &[0xf9, 0x3c, 0x00],
            &note,
        ]);
        let arr = LargeBlobArray::parse(&bytes).expect("odd elements are skipped, not fatal");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr.skipped_count(), 5);
        assert_eq!(arr.entry(0).unwrap().as_text().as_deref(), Some("kept"));
        assert!(arr.entry(1).is_none());
        assert_eq!(arr.raw_array(), &bytes[..]);
    }

    #[test]
    fn parse_skips_ambiguous_and_mistyped_entry_maps() {
        let dup_key = map_bytes(vec![
            (Value::UInt(1), Value::Bytes(vec![0xaa])),
            (Value::UInt(1), Value::Bytes(vec![0xbb])),
            (Value::UInt(2), Value::Bytes(vec![0x22; 12])),
            (Value::UInt(3), Value::UInt(1)),
        ]);
        let text_ciphertext = map_bytes(vec![
            (Value::UInt(1), Value::Text("x".into())),
            (Value::UInt(2), Value::Bytes(vec![0x22; 12])),
            (Value::UInt(3), Value::UInt(1)),
        ]);
        let arr = LargeBlobArray::parse(&raw_array_of(&[&dup_key, &text_ciphertext])).unwrap();
        assert_eq!((arr.len(), arr.skipped_count()), (0, 2));
        assert!(arr.is_empty());
    }

    #[test]
    fn parse_still_fails_on_a_broken_array() {
        // Truncated: declares two elements, holds one.
        assert!(LargeBlobArray::parse(&[0x82, 0x01]).is_err());
        // An element with an indefinite length can't be measured.
        assert!(LargeBlobArray::parse(&[0x81, 0x5f, 0x41, 0x00, 0xff]).is_err());
        // Not an array at all.
        assert!(LargeBlobArray::parse(&[0xa0]).is_err());
        assert!(LargeBlobArray::parse(&[]).is_err());
    }

    /// Canned-response transport: answers each transact() with the next
    /// queued response.
    struct ScriptedTransport {
        responses: Vec<Vec<u8>>,
    }

    impl CtapTransport for ScriptedTransport {
        fn transact(&mut self, _cmd: u8, _payload: &[u8]) -> Result<Vec<u8>, CtapError> {
            if self.responses.is_empty() {
                return Err(CtapError::EmptyResponse);
            }
            Ok(self.responses.remove(0))
        }
    }

    /// An RP entry carrying an extra map key (4: "x") that §6.10.3 allows.
    fn rp_entry_with_unknown_key() -> Vec<u8> {
        let mut b = vec![0xa4, 0x01, 0x54];
        b.extend_from_slice(&[0x11; 20]);
        b.extend_from_slice(&[0x02, 0x4c]);
        b.extend_from_slice(&[0x22; 12]);
        b.extend_from_slice(&[0x03, 0x05, 0x04, 0x61, 0x78]);
        b
    }

    /// [RP entry with key 4, keyroost note, tagged item, non-map].
    fn mixed_fixture() -> (Vec<Vec<u8>>, Vec<u8>) {
        let elements = vec![
            rp_entry_with_unknown_key(),
            encode_entry(&LargeBlobEntry::from_text("note")),
            vec![0xc1, 0x01],
            vec![0x61, 0x78],
        ];
        let refs: Vec<&[u8]> = elements.iter().map(|e| e.as_slice()).collect();
        let bytes = raw_array_of(&refs);
        (elements, bytes)
    }

    /// Split a serialized array (with checksum) into its raw elements,
    /// checking the checksum and that it parses with `skipped` skipped.
    fn split_checked(serialized: &[u8], skipped: usize) -> Vec<Vec<u8>> {
        let (array, trailer) = serialized.split_at(serialized.len() - CHECKSUM_LEN);
        assert_eq!(trailer, left16_sha256(array));
        assert_eq!(
            LargeBlobArray::parse(array).unwrap().skipped_count(),
            skipped
        );
        let (items, rest) = cbor::split_array(array).unwrap();
        assert!(rest.is_empty());
        items.into_iter().map(|i| i.to_vec()).collect()
    }

    #[test]
    fn rewrite_keeps_every_other_item_byte_identical() {
        let (input, bytes) = mixed_fixture();
        assert_eq!(
            hex(&input[0]),
            "a401541111111111111111111111111111111111111111024c2222222222222222222222220305046178"
        );
        let arr = LargeBlobArray::parse(&bytes).unwrap();
        assert_eq!((arr.len(), arr.skipped_count()), (2, 2));

        let added = split_checked(&arr.with_text_note("n").serialize_with_checksum(), 2);
        assert_eq!(added.len(), 5);
        assert_eq!(&added[..4], &input[..]);

        let edited = split_checked(
            &arr.with_replaced_note(1, "m")
                .unwrap()
                .serialize_with_checksum(),
            2,
        );
        assert_eq!(edited.len(), 4);
        assert_eq!(edited[0], input[0]);
        assert_ne!(edited[1], input[1]);
        assert_eq!(&edited[2..], &input[2..]);

        let removed = split_checked(&arr.without_entry(1).unwrap().serialize_with_checksum(), 2);
        assert_eq!(
            removed,
            vec![input[0].clone(), input[2].clone(), input[3].clone()]
        );
    }

    #[test]
    fn without_entry_counts_only_conforming_entries() {
        let (_, bytes) = mixed_fixture();
        let arr = LargeBlobArray::parse(&bytes).unwrap();
        let removed = arr.without_entry(1).unwrap();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed.skipped_count(), 2);
        assert!(!removed.entry(0).unwrap().is_kr_note());
        assert!(removed.raw_array().is_empty());
        // Index 2 would be a skipped element by position; it is out of range.
        assert!(arr.without_entry(2).is_none());
    }

    #[test]
    fn unmodified_array_reserializes_identically() {
        // A non-shortest uint (`18 05`) inside an entry and a tagged element
        // must come back exactly as stored when nothing was changed.
        let mut odd_entry = vec![0xa3, 0x01, 0x41, 0xaa, 0x02, 0x4c];
        odd_entry.extend_from_slice(&[0x33; 12]);
        odd_entry.extend_from_slice(&[0x03, 0x18, 0x05]);
        let (_, mixed) = mixed_fixture();
        for x in [
            mixed,
            raw_array_of(&[&odd_entry, &[0xc1, 0x01]]),
            vec![0x80],
        ] {
            let mut want = x.clone();
            want.extend_from_slice(&left16_sha256(&x));
            assert_eq!(
                LargeBlobArray::parse(&x).unwrap().serialize_with_checksum(),
                want
            );
        }
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn read_skips_instead_of_failing() {
        let note = encode_entry(&LargeBlobEntry::from_text("still here"));
        let array = raw_array_of(&[&[0xc1, 0x01], &note]);
        let mut stored = array.clone();
        stored.extend_from_slice(&left16_sha256(&array));
        let mut response = vec![0x00];
        response.extend_from_slice(&cbor::encode(&Value::Map(vec![(
            Value::UInt(RESP_CONFIG),
            Value::Bytes(stored),
        )])));
        let mut dev = ScriptedTransport {
            responses: vec![response],
        };
        let arr = read(&mut dev, &AuthenticatorInfo::default()).expect("read succeeds");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr.skipped_count(), 1);
        assert_eq!(
            arr.entry(0).unwrap().as_text().as_deref(),
            Some("still here")
        );
        assert_eq!(arr.raw_array(), &array[..]);
    }

    #[test]
    fn empty_array_roundtrips_and_checksums() {
        let bytes = empty_array_serialized();
        // 0x80 (empty array) + 16-byte checksum.
        assert_eq!(bytes.len(), 1 + CHECKSUM_LEN);
        assert_eq!(bytes[0], 0x80);
        let (array, trailer) = bytes.split_at(bytes.len() - CHECKSUM_LEN);
        assert_eq!(trailer, left16_sha256(array));
        // Parsing the array part yields zero entries.
        assert!(LargeBlobArray::parse(array).unwrap().is_empty());
    }

    #[test]
    fn entries_encode_parse_roundtrip() {
        let entries = vec![sample_entry(1), sample_entry(2), sample_entry(3)];
        let serialized = array_of(entries.clone()).serialize_with_checksum();
        let encoded = &serialized[..serialized.len() - CHECKSUM_LEN];
        let parsed = LargeBlobArray::parse(encoded).unwrap();
        assert_eq!(fields(&parsed), entries);
    }

    #[test]
    fn serialize_with_checksum_is_verifiable() {
        let arr = array_of(vec![sample_entry(7), sample_entry(9)]);
        let serialized = arr.serialize_with_checksum();
        let (array, trailer) = serialized.split_at(serialized.len() - CHECKSUM_LEN);
        assert_eq!(trailer, left16_sha256(array));
        // And the array round-trips back to the same entries.
        assert_eq!(
            fields(&LargeBlobArray::parse(array).unwrap()),
            vec![sample_entry(7), sample_entry(9)]
        );
    }

    #[test]
    fn checksum_detects_corruption() {
        let mut serialized = empty_array_serialized();
        // Flip a byte in the checksum trailer.
        let last = serialized.len() - 1;
        serialized[last] ^= 0xff;
        let (array, trailer) = serialized.split_at(serialized.len() - CHECKSUM_LEN);
        assert_ne!(trailer, left16_sha256(array));
    }

    #[test]
    fn max_fragment_length_respects_msg_size() {
        let info = AuthenticatorInfo {
            max_msg_size: Some(1200),
            ..Default::default()
        };
        assert_eq!(max_fragment_length(&info), (1200 - 64) as usize);
        // Falls back to the 1024 floor when unset.
        let info2 = AuthenticatorInfo::default();
        assert_eq!(max_fragment_length(&info2), (1024 - 64) as usize);
    }

    #[test]
    fn text_note_roundtrips_through_serialization() {
        let text = "hello \u{1f511} keyroost note — 123";
        let arr = array_of(vec![LargeBlobEntry::from_text(text)]);
        // Serialize (with checksum), strip the trailer, re-parse, decode text.
        let serialized = arr.serialize_with_checksum();
        let (array, _trailer) = serialized.split_at(serialized.len() - CHECKSUM_LEN);
        let parsed = LargeBlobArray::parse(array).unwrap();
        assert_eq!(parsed.len(), 1);
        let note = parsed.entry(0).unwrap();
        assert!(note.is_kr_note());
        assert_eq!(note.as_text().as_deref(), Some(text));
        assert_eq!(note.orig_size, text.len() as u64);
    }

    #[test]
    fn extract_cert_from_entries_roundtrips_a_real_cert() {
        use aes_gcm::{
            aead::{Aead, KeyInit, Payload},
            Aes256Gcm, Nonce,
        };
        // A known-good OpenSSH cert fixture already exists for the ssh_cert tests.
        let cert_pub = crate::ssh_cert::tests_fixture::FIXTURE_CERT_PUB;
        let (_, wire) = crate::ssh_cert::parse_text(cert_pub.trim()).unwrap();

        // Build the largeBlob entry the way fido2-token would: raw-DEFLATE then
        // AES-256-GCM with AAD = "blob" || origSize LE.
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 12];
        let orig_size = wire.len() as u64;
        let compressed = miniz_oxide::deflate::compress_to_vec(&wire, 6);
        let mut aad = b"blob".to_vec();
        aad.extend_from_slice(&orig_size.to_le_bytes());
        let ct = Aes256Gcm::new_from_slice(&key)
            .unwrap()
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &compressed,
                    aad: &aad,
                },
            )
            .unwrap();
        let entry = LargeBlobEntry {
            ciphertext: ct,
            nonce: nonce.to_vec(),
            orig_size,
            original: None,
        };
        // A decoy entry encrypted with a different key must be skipped.
        let decoy = LargeBlobEntry {
            ciphertext: vec![0u8; 40],
            nonce: vec![0u8; 12],
            orig_size: 8,
            original: None,
        };

        let both = array_of(vec![decoy, entry]);
        let got = extract_cert_from_entries(&key, &both).expect("cert found");
        assert_eq!(got, wire);
        // Full round trip back to -cert.pub reproduces the original type +
        // base64 body (the comment is not part of the certificate, so it is
        // not preserved — matches ssh_cert's own round-trip test).
        let line = crate::ssh_cert::to_cert_pub(&got).unwrap();
        let mut parts = line.split_ascii_whitespace();
        let mut orig_parts = cert_pub.split_ascii_whitespace();
        assert_eq!(parts.next(), orig_parts.next());
        assert_eq!(parts.next(), orig_parts.next());
        // Wrong key → nothing.
        assert!(extract_cert_from_entries(&[0x99u8; 32], &both).is_none());
    }

    #[test]
    fn rp_entries_are_not_decoded_as_text() {
        // An entry without the magic prefix must never be read as a note.
        let rp = LargeBlobEntry {
            ciphertext: vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x99],
            nonce: vec![1u8; 12],
            orig_size: 4,
            original: None,
        };
        assert!(!rp.is_kr_note());
        assert_eq!(rp.as_text(), None);
    }

    #[test]
    fn with_text_note_appends_without_disturbing_existing() {
        let arr = array_of(vec![sample_entry(5)]);
        let updated = arr.with_text_note("note");
        assert_eq!(updated.len(), 2);
        // Original (RP) entry untouched and still not a note.
        assert_eq!(updated.entry(0), Some(&sample_entry(5)));
        assert!(!updated.entry(0).unwrap().is_kr_note());
        // New entry decodes back to the text.
        assert_eq!(updated.entry(1).unwrap().as_text().as_deref(), Some("note"));
    }

    #[test]
    fn replace_note_swaps_only_keyroost_notes() {
        let arr = array_of(vec![
            sample_entry(5),                       // RP entry
            LargeBlobEntry::from_text("original"), // kr note
        ]);
        // Editing the note succeeds and changes only that entry.
        let edited = arr.with_replaced_note(1, "updated").unwrap();
        assert_eq!(edited.len(), 2);
        assert_eq!(edited.entry(0), Some(&sample_entry(5)));
        assert_eq!(
            edited.entry(1).unwrap().as_text().as_deref(),
            Some("updated")
        );
        // Attempting to edit the RP entry is refused.
        assert!(arr.with_replaced_note(0, "hack").is_none());
        // Out-of-range index is refused.
        assert!(arr.with_replaced_note(9, "x").is_none());
    }

    #[test]
    fn capacity_of_empty_array() {
        let arr = array_of(Vec::new());
        let info = AuthenticatorInfo::default(); // no 0x0B advertised -> spec minimum
        let cap = arr.capacity(&info);
        // Empty CBOR array (0x80, 1 byte) + 16-byte checksum trailer.
        assert_eq!(cap.used_bytes, 17);
        assert_eq!(cap.max_bytes, 1024);
        assert_eq!(cap.free_bytes, 1024 - 17);
        assert_eq!(cap.entry_count, 0);
    }

    #[test]
    fn capacity_uses_advertised_max_and_saturates() {
        let arr = array_of(vec![LargeBlobEntry::from_text("hello")]);
        let info = AuthenticatorInfo {
            max_serialized_large_blob_array: Some(4096),
            ..Default::default()
        };
        let cap = arr.capacity(&info);
        assert_eq!(cap.max_bytes, 4096);
        assert_eq!(cap.used_bytes, arr.serialize_with_checksum().len() as u64);
        assert_eq!(cap.free_bytes, cap.max_bytes - cap.used_bytes);
        assert_eq!(cap.entry_count, 1);

        // A max smaller than what's stored must not underflow.
        let info_small = AuthenticatorInfo {
            max_serialized_large_blob_array: Some(10),
            ..Default::default()
        };
        assert_eq!(arr.capacity(&info_small).free_bytes, 0);
    }

    #[test]
    fn classify_note_ssh_cert_and_opaque() {
        use crate::ssh_cert::tests_fixture::FIXTURE_CERT_PUB;
        use keyroost_proto::codec::base64_decode;

        // Note wins (even if a note happens to contain a cert line).
        let note = LargeBlobEntry::from_text("hello");
        assert!(matches!(note.classify(), EntryKind::Note(t) if t == "hello"));

        // A note whose body IS a cert line still classifies as a note.
        let cert_note = LargeBlobEntry::from_text(FIXTURE_CERT_PUB);
        assert!(matches!(cert_note.classify(), EntryKind::Note(t) if t == FIXTURE_CERT_PUB));

        // Wire-format certificate.
        let wire =
            base64_decode(FIXTURE_CERT_PUB.split_ascii_whitespace().nth(1).unwrap()).unwrap();
        let wire_entry = LargeBlobEntry {
            ciphertext: wire.clone(),
            nonce: vec![0; 12],
            orig_size: wire.len() as u64,
            original: None,
        };
        match wire_entry.classify() {
            EntryKind::SshCert { info, wire: w } => {
                assert_eq!(info.key_id, "test-key-id");
                assert_eq!(w, wire);
            }
            other => panic!("expected SshCert, got {other:?}"),
        }

        // Text-form certificate (a -cert.pub file dropped in verbatim).
        let text_entry = LargeBlobEntry {
            ciphertext: FIXTURE_CERT_PUB.as_bytes().to_vec(),
            nonce: vec![0; 12],
            orig_size: FIXTURE_CERT_PUB.len() as u64,
            original: None,
        };
        match text_entry.classify() {
            EntryKind::SshCert { info, wire: w } => {
                assert_eq!(info.serial, 42);
                assert_eq!(w, wire); // canonical wire bytes, not the text
            }
            other => panic!("expected SshCert, got {other:?}"),
        }

        // Random RP bytes stay opaque.
        let rp = LargeBlobEntry {
            ciphertext: vec![0xde, 0xad, 0xbe, 0xef],
            nonce: vec![1; 12],
            orig_size: 4,
            original: None,
        };
        assert!(matches!(rp.classify(), EntryKind::Opaque));
    }
}
