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
//! bytes), 3: origSize (uint)}`. We parse entries structurally so that edits
//! re-serialize cleanly and the trailing checksum is always recomputed — a
//! naive raw-byte edit that left a stale checksum would make the key reject the
//! whole array (or fail future credential writes) until a reset.
//!
//! # Reading
//!
//! `get` is chunked by `offset`; we reassemble fragments until the declared
//! length is reached, then verify the checksum trailer.
//!
//! # Writing
//!
//! `set` is chunked by `maxFragmentLength = maxMsgSize - 64`. Every fragment
//! carries a `pinUvAuthParam` computed specially (see [`write_auth_param`]):
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
use crate::transport::CtapTransport;
use crate::pin::left16_sha256;

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
}

/// A parsed large-blob array: the structured entries plus the exact raw bytes
/// they were decoded from (handy for a hex/ASCII view and for diffing).
#[derive(Debug, Clone)]
pub struct LargeBlobArray {
    pub entries: Vec<LargeBlobEntry>,
    /// The serialized array WITHOUT the checksum trailer.
    pub raw_array: Vec<u8>,
}

impl LargeBlobArray {
    /// Re-serialize the current entries and append a freshly-computed checksum,
    /// yielding bytes ready to hand to [`write`].
    pub fn serialize_with_checksum(&self) -> Vec<u8> {
        let array = encode_entries(&self.entries);
        let mut out = array.clone();
        out.extend_from_slice(&left16_sha256(&array));
        out
    }

    /// Return a copy of this array with a new keyroost text note appended.
    pub fn with_text_note(&self, text: &str) -> LargeBlobArray {
        let mut entries = self.entries.clone();
        entries.push(LargeBlobEntry::from_text(text));
        LargeBlobArray {
            entries,
            raw_array: Vec::new(),
        }
    }

    /// Return a copy of this array with the keyroost note at `idx` replaced by
    /// `text`. Refuses (returns `None`) if `idx` is out of range or the target
    /// is NOT a keyroost note — relying-party entries are AEAD-encrypted by
    /// their owner and must never be rewritten as plaintext.
    pub fn with_replaced_note(&self, idx: usize, text: &str) -> Option<LargeBlobArray> {
        let target = self.entries.get(idx)?;
        if !target.is_kr_note() {
            return None;
        }
        let mut entries = self.entries.clone();
        entries[idx] = LargeBlobEntry::from_text(text);
        Some(LargeBlobArray {
            entries,
            raw_array: Vec::new(),
        })
    }
}

fn encode_entries(entries: &[LargeBlobEntry]) -> Vec<u8> {
    let items = entries
        .iter()
        .map(|e| {
            Value::Map(vec![
                (
                    Value::UInt(ENTRY_CIPHERTEXT),
                    Value::Bytes(e.ciphertext.clone()),
                ),
                (Value::UInt(ENTRY_NONCE), Value::Bytes(e.nonce.clone())),
                (Value::UInt(ENTRY_ORIG_SIZE), Value::UInt(e.orig_size)),
            ])
        })
        .collect();
    cbor::encode(&Value::Array(items))
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
fn read_fragment(dev: &mut impl CtapTransport, offset: u64, count: u64) -> Result<Vec<u8>, CtapError> {
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

    let entries = parse_entries(array_bytes)?;
    Ok(LargeBlobArray {
        entries,
        raw_array: array_bytes.to_vec(),
    })
}

fn parse_entries(array_bytes: &[u8]) -> Result<Vec<LargeBlobEntry>, CtapError> {
    let (value, _) = cbor::decode(array_bytes)?;
    let Value::Array(items) = value else {
        return Err(CtapError::InvalidResponseShape("largeBlobs: not an array"));
    };
    let mut entries = Vec::with_capacity(items.len());
    for item in items {
        let Value::Map(map) = item else {
            return Err(CtapError::InvalidResponseShape(
                "largeBlobs: entry not a map",
            ));
        };
        let mut ciphertext = None;
        let mut nonce = None;
        let mut orig_size = None;
        for (k, v) in map {
            match k {
                Value::UInt(ENTRY_CIPHERTEXT) => {
                    if let Value::Bytes(b) = v {
                        ciphertext = Some(b);
                    }
                }
                Value::UInt(ENTRY_NONCE) => {
                    if let Value::Bytes(b) = v {
                        nonce = Some(b);
                    }
                }
                Value::UInt(ENTRY_ORIG_SIZE) => {
                    if let Value::UInt(n) = v {
                        orig_size = Some(n);
                    }
                }
                _ => {}
            }
        }
        match (ciphertext, nonce, orig_size) {
            (Some(ciphertext), Some(nonce), Some(orig_size)) => entries.push(LargeBlobEntry {
                ciphertext,
                nonce,
                orig_size,
            }),
            _ => {
                return Err(CtapError::InvalidResponseShape(
                    "largeBlobs: entry missing required field",
                ))
            }
        }
    }
    Ok(entries)
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
        entries.push((
            Value::UInt(KEY_PIN_UV_AUTH_PROTOCOL),
            Value::UInt(token.protocol as u64),
        ));
        entries.push((Value::UInt(KEY_PIN_UV_AUTH_PARAM), Value::Bytes(auth)));

        dispatch(dev, Value::Map(entries))?;
        offset = end;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry(seed: u8) -> LargeBlobEntry {
        LargeBlobEntry {
            ciphertext: vec![seed; 20],
            nonce: vec![seed.wrapping_add(1); 12],
            orig_size: seed as u64 + 4,
        }
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
        assert!(parse_entries(array).unwrap().is_empty());
    }

    #[test]
    fn entries_encode_parse_roundtrip() {
        let entries = vec![sample_entry(1), sample_entry(2), sample_entry(3)];
        let encoded = encode_entries(&entries);
        let parsed = parse_entries(&encoded).unwrap();
        assert_eq!(parsed, entries);
    }

    #[test]
    fn serialize_with_checksum_is_verifiable() {
        let arr = LargeBlobArray {
            entries: vec![sample_entry(7), sample_entry(9)],
            raw_array: Vec::new(),
        };
        let serialized = arr.serialize_with_checksum();
        let (array, trailer) = serialized.split_at(serialized.len() - CHECKSUM_LEN);
        assert_eq!(trailer, left16_sha256(array));
        // And the array round-trips back to the same entries.
        assert_eq!(parse_entries(array).unwrap(), arr.entries);
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
        let mut info = AuthenticatorInfo::default();
        info.max_msg_size = Some(1200);
        assert_eq!(max_fragment_length(&info), (1200 - 64) as usize);
        // Falls back to the 1024 floor when unset.
        let info2 = AuthenticatorInfo::default();
        assert_eq!(max_fragment_length(&info2), (1024 - 64) as usize);
    }

    #[test]
    fn text_note_roundtrips_through_serialization() {
        let text = "hello \u{1f511} keyroost note — 123";
        let arr = LargeBlobArray {
            entries: vec![LargeBlobEntry::from_text(text)],
            raw_array: Vec::new(),
        };
        // Serialize (with checksum), strip the trailer, re-parse, decode text.
        let serialized = arr.serialize_with_checksum();
        let (array, _trailer) = serialized.split_at(serialized.len() - CHECKSUM_LEN);
        let parsed = parse_entries(array).unwrap();
        assert_eq!(parsed.len(), 1);
        assert!(parsed[0].is_kr_note());
        assert_eq!(parsed[0].as_text().as_deref(), Some(text));
        assert_eq!(parsed[0].orig_size, text.len() as u64);
    }

    #[test]
    fn rp_entries_are_not_decoded_as_text() {
        // An entry without the magic prefix must never be read as a note.
        let rp = LargeBlobEntry {
            ciphertext: vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x99],
            nonce: vec![1u8; 12],
            orig_size: 4,
        };
        assert!(!rp.is_kr_note());
        assert_eq!(rp.as_text(), None);
    }

    #[test]
    fn with_text_note_appends_without_disturbing_existing() {
        let arr = LargeBlobArray {
            entries: vec![sample_entry(5)],
            raw_array: Vec::new(),
        };
        let updated = arr.with_text_note("note");
        assert_eq!(updated.entries.len(), 2);
        // Original (RP) entry untouched and still not a note.
        assert_eq!(updated.entries[0], sample_entry(5));
        assert!(!updated.entries[0].is_kr_note());
        // New entry decodes back to the text.
        assert_eq!(updated.entries[1].as_text().as_deref(), Some("note"));
    }

    #[test]
    fn replace_note_swaps_only_keyroost_notes() {
        let arr = LargeBlobArray {
            entries: vec![
                sample_entry(5),                       // RP entry
                LargeBlobEntry::from_text("original"), // kr note
            ],
            raw_array: Vec::new(),
        };
        // Editing the note succeeds and changes only that entry.
        let edited = arr.with_replaced_note(1, "updated").unwrap();
        assert_eq!(edited.entries.len(), 2);
        assert_eq!(edited.entries[0], sample_entry(5));
        assert_eq!(edited.entries[1].as_text().as_deref(), Some("updated"));
        // Attempting to edit the RP entry is refused.
        assert!(arr.with_replaced_note(0, "hack").is_none());
        // Out-of-range index is refused.
        assert!(arr.with_replaced_note(9, "x").is_none());
    }
}
