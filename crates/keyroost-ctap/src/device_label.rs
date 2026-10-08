//! A key's own name, stored as one entry in its large-blob array.
//!
//! The name is not secret: the large-blob array is readable by anyone who
//! has the key, with no PIN. It is encrypted only so the entry has the shape
//! of every other large-blob entry (CTAP 2.1 §6.10.3): a fixed, published
//! key `K` lets any tool find and read it, and other tools' readers skip it
//! like any entry that isn't theirs.
//!
//! # Format (version 1)
//!
//! ```text
//! K         = SHA-256("FIDO2 large-blob device label v1")
//! P         = canonical CBOR {1: 1, 2: label (text, 1-64 chars), 3?: writer (text)}
//! origSize  = len(P)
//! compressed= raw DEFLATE of P (writers: one stored block; readers: any)
//! entry     = {1: AES-256-GCM(K, nonce, compressed, aad = "blob" || u64le(origSize)),
//!              2: nonce (12 random bytes), 3: origSize}
//! ```
//!
//! Key 4 of `P` is reserved; readers ignore keys they don't know. An array
//! holds at most one version-1 name entry: writers remove every one and
//! append one, readers take the last. An entry under `K` that is not a valid
//! version-1 name (a later version, or a malformed one) is not a name to
//! this reader: it is kept untouched like any other entry. The label is
//! stored exactly as given, with no Unicode normalization. Callers validate
//! the label's text (keyroost uses `keyroost_keyring::validate_name`); this
//! module checks only its type and length, and holds the writer tag to the
//! same 1–64 character rule on both sides.
//!
//! # Reading and writing
//!
//! [`read_label`] needs no PIN. A change is planned from an array already
//! read ([`plan_label_change`], pure, which refuses rather than evicting
//! anything to make room) and then written with [`apply_label_plan`], which
//! re-reads the array first and sends nothing if it changed meanwhile, so
//! another tool's entry written in between is never lost.

use crate::cbor::{self, Value};
use crate::client_pin::PinUvAuthToken;
use crate::cmd::{AuthenticatorInfo, CtapError};
use crate::large_blobs::{
    self, gcm_decrypt, gcm_encrypt, inflate_raw, LargeBlobArray, LargeBlobEntry,
};
use crate::transport::CtapTransport;

/// The string hashed to the fixed key every name entry is encrypted under.
pub const LABEL_KEY_INFO: &[u8] = b"FIDO2 large-blob device label v1";
/// Value of key 1 in the plaintext map.
pub const LABEL_FORMAT_VERSION: u64 = 1;
/// Longest label, in Unicode scalar values.
pub const MAX_LABEL_CHARS: usize = 64;
/// Writer tag keyroost stores in key 3.
pub const WRITER_KEYROOST: &str = "keyroost";

// Plaintext map keys.
const P_VERSION: u64 = 1;
const P_LABEL: u64 = 2;
const P_WRITER: u64 = 3;

/// A key's name as stored on the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceLabel {
    pub label: String,
    /// The tool that wrote it, if it said.
    pub writer: Option<String>,
}

/// Why a name could not be built, planned or written. (Not `Clone`/`Eq`:
/// the wrapped [`CtapError`] is neither.)
#[derive(Debug)]
pub enum LabelError {
    /// The label (or writer) is empty or longer than 64 characters.
    InvalidLabel,
    /// The key does not advertise large-blob storage.
    Unsupported,
    /// The key has no FIDO PIN, so nothing can be written to its storage.
    NoPin,
    /// The array would be `size` bytes (with its checksum), over the key's
    /// `max` (`maxSerializedLargeBlobArray`, or the spec floor of 1024).
    TooLarge {
        size: u64,
        max: u64,
    },
    /// The array on the key changed between planning and writing.
    Changed,
    Ctap(CtapError),
}

impl std::fmt::Display for LabelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LabelError::InvalidLabel => write!(
                f,
                "a key name must be 1 to {MAX_LABEL_CHARS} characters long"
            ),
            LabelError::Unsupported => {
                write!(f, "this key has no large-blob storage to hold a name")
            }
            LabelError::NoPin => write!(
                f,
                "this key has no FIDO PIN, which writing its storage needs; \
                 set one first with `keyroostctl fido pin set`"
            ),
            LabelError::TooLarge { size, max } => write!(
                f,
                "not enough large-blob space: the key's storage would hold {size} \
                 bytes, {} bytes over its {max}-byte limit",
                size.saturating_sub(*max)
            ),
            LabelError::Changed => write!(
                f,
                "the key's large-blob storage changed since it was read; \
                 nothing was written, try again"
            ),
            LabelError::Ctap(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for LabelError {}

impl From<CtapError> for LabelError {
    fn from(e: CtapError) -> Self {
        LabelError::Ctap(e)
    }
}

/// `K = SHA-256(LABEL_KEY_INFO)`.
pub fn label_key() -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(LABEL_KEY_INFO).into()
}

/// Whether `s` has 1..=`MAX_LABEL_CHARS` Unicode scalar values.
fn fits(s: &str) -> bool {
    (1..=MAX_LABEL_CHARS).contains(&s.chars().count())
}

/// The canonical CBOR plaintext for `l`: `{1: 1, 2: label, 3?: writer}`.
/// Refuses a label (or writer) that is empty or over 64 characters.
pub fn plaintext(l: &DeviceLabel) -> Result<Vec<u8>, LabelError> {
    if !fits(&l.label) || l.writer.as_deref().is_some_and(|w| !fits(w)) {
        return Err(LabelError::InvalidLabel);
    }
    let mut map = vec![
        (Value::UInt(P_VERSION), Value::UInt(LABEL_FORMAT_VERSION)),
        (Value::UInt(P_LABEL), Value::Text(l.label.clone())),
    ];
    if let Some(w) = &l.writer {
        map.push((Value::UInt(P_WRITER), Value::Text(w.clone())));
    }
    Ok(cbor::encode(&Value::Map(map)))
}

/// `data` as a single final stored (uncompressed) DEFLATE block (RFC 1951
/// §3.2.4): `01 || u16le(len) || u16le(!len) || data`. Callers keep `data`
/// within one block (64 KiB); a name's plaintext is under 300 bytes.
pub fn stored_deflate(data: &[u8]) -> Vec<u8> {
    debug_assert!(
        data.len() <= 0xffff,
        "one stored block holds at most 64 KiB"
    );
    let len = data.len() as u16;
    let mut out = Vec::with_capacity(5 + data.len());
    out.push(0x01); // BFINAL = 1, BTYPE = 00 (stored)
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&(!len).to_le_bytes());
    out.extend_from_slice(data);
    out
}

/// The large-blob entry holding `l`, encrypted under [`label_key`] with
/// `nonce` (use [`random_nonce`] outside tests).
pub fn encode_entry(l: &DeviceLabel, nonce: [u8; 12]) -> Result<LargeBlobEntry, LabelError> {
    let p = plaintext(l)?;
    let orig_size = p.len() as u64;
    let ciphertext = gcm_encrypt(&label_key(), &nonce, &stored_deflate(&p), orig_size);
    Ok(LargeBlobEntry::built(ciphertext, nonce.to_vec(), orig_size))
}

/// The name `e` holds, or `None` when `e` is not a name entry: its tag must
/// verify under [`label_key`], it must inflate to exactly `origSize` bytes
/// of one CBOR map with version 1 and a 1–64 character text label. A writer
/// that isn't 1–64 characters of text is dropped; unknown keys are
/// ignored; of duplicate keys the first wins.
pub fn decode_entry(e: &LargeBlobEntry) -> Option<DeviceLabel> {
    let compressed = gcm_decrypt(&label_key(), &e.nonce, &e.ciphertext, e.orig_size)?;
    let p = inflate_raw(&compressed, e.orig_size)?;
    let (map, rest) = cbor::decode(&p).ok()?;
    if !rest.is_empty() || map.as_map().is_none() {
        return None;
    }
    if map.get_uint_key(P_VERSION)?.as_uint()? != LABEL_FORMAT_VERSION {
        return None;
    }
    let label = map.get_uint_key(P_LABEL)?.as_text().filter(|l| fits(l))?;
    let writer = map
        .get_uint_key(P_WRITER)
        .and_then(Value::as_text)
        .filter(|w| fits(w));
    Some(DeviceLabel {
        label: label.to_owned(),
        writer: writer.map(str::to_owned),
    })
}

/// What a key says about its own name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabelState {
    /// The key has no large-blob storage.
    Unsupported,
    /// The key has storage but no name entry.
    Absent,
    Present(DeviceLabel),
}

/// Read the key's name. Needs no PIN: the large-blob array is readable by
/// anyone. `Unsupported` when getInfo lacks `largeBlobs: true`.
pub fn read_label(
    dev: &mut impl CtapTransport,
    info: &AuthenticatorInfo,
) -> Result<LabelState, CtapError> {
    if info.option("largeBlobs") != Some(true) {
        return Ok(LabelState::Unsupported);
    }
    Ok(match large_blobs::read(dev, info)?.label() {
        Some((_, label)) => LabelState::Present(label),
        None => LabelState::Absent,
    })
}

/// A checked change to the key's name, ready to write with
/// [`apply_label_plan`].
#[derive(Debug, Clone)]
pub struct LabelPlan {
    /// The array the plan was made from, as read (without the checksum).
    before_raw: Vec<u8>,
    /// What will be written (with the checksum).
    serialized: Vec<u8>,
    /// The name the key had when the plan was made.
    pub previous: Option<DeviceLabel>,
    /// The array as it will be after the write.
    pub after: LargeBlobArray,
}

/// Plan setting (`Some`) or clearing (`None`) the name on an array read
/// from the key. Pure: nothing is sent. Refuses with `Unsupported` when the
/// key has no large-blob storage, `NoPin` when it has no FIDO PIN set (the
/// write needs a PIN token), `InvalidLabel`, and `TooLarge` when the result
/// would not fit `maxSerializedLargeBlobArray` (the spec floor of 1024 bytes
/// when the key doesn't say). Never evicts other entries to make room.
pub fn plan_label_change(
    current: &LargeBlobArray,
    info: &AuthenticatorInfo,
    label: Option<&DeviceLabel>,
    nonce: [u8; 12],
) -> Result<LabelPlan, LabelError> {
    if info.option("largeBlobs") != Some(true) {
        return Err(LabelError::Unsupported);
    }
    if info.option("clientPin") != Some(true) {
        return Err(LabelError::NoPin);
    }
    let after = current.with_label(label, nonce)?;
    let serialized = after.serialize_with_checksum()?;
    let size = serialized.len() as u64;
    let max = current.capacity(info).max_bytes;
    if size > max {
        return Err(LabelError::TooLarge { size, max });
    }
    Ok(LabelPlan {
        before_raw: current.raw_array().to_vec(),
        serialized,
        previous: current.label().map(|(_, l)| l),
        after,
    })
}

/// Write `plan`, but only over the array it was made from: re-read the
/// array and refuse with `Changed`, sending nothing, unless its bytes equal
/// the ones planned from. `token` needs the large-blob-write permission.
pub fn apply_label_plan(
    dev: &mut impl CtapTransport,
    info: &AuthenticatorInfo,
    token: &PinUvAuthToken,
    plan: &LabelPlan,
) -> Result<(), LabelError> {
    let now = large_blobs::read(dev, info)?;
    if now.raw_array() != plan.before_raw.as_slice() {
        return Err(LabelError::Changed);
    }
    large_blobs::write(dev, info, token, &plan.serialized)?;
    Ok(())
}

/// A fresh random 12-byte nonce for [`encode_entry`].
pub fn random_nonce() -> [u8; 12] {
    use rand_core::{OsRng, RngCore};
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::large_blobs::{EntryKind, LargeBlobArray};

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    const NONCE: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

    fn v1() -> DeviceLabel {
        DeviceLabel {
            label: "Work YubiKey".into(),
            writer: None,
        }
    }

    fn v2() -> DeviceLabel {
        DeviceLabel {
            label: "Cl\u{e9} de bureau".into(),
            writer: Some(WRITER_KEYROOST.into()),
        }
    }

    const V1_P: &str = "a20101026c576f726b20597562694b6579";
    const V1_CT: &str =
        "fa202b3626a9c13b79e236fa5b1288777aa854baa7b9071106da74af6ca22511f5913dab35ed";
    const V1_ENTRY: &str = "a3015826fa202b3626a9c13b79e236fa5b1288777aa854baa7b9071106da74af6ca22511f5913dab35ed024c000102030405060708090a0b0311";
    const V1_SUM: &str = "9527ae20c7a00a231f6800e4e319d611";
    const V2_P: &str = "a30101026e436cc3a92064652062757265617503686b6579726f6f7374";
    const V2_CT: &str = "fa2c2b3a26a8c13b79e022f9ead0884a6aea5f84b0a5ecf7beaca35fe4c4b10d0234607c0eddb263c942a581932e707b715e";
    const V2_ENTRY: &str = "a3015832fa2c2b3a26a8c13b79e022f9ead0884a6aea5f84b0a5ecf7beaca35fe4c4b10d0234607c0eddb263c942a581932e707b715e024c000102030405060708090a0b03181d";
    const V2_SUM: &str = "80f2ff1c1dddfa8eb409d589b6ff287b";

    /// One-entry array (with checksum) holding `e`.
    fn one_entry_array(e: LargeBlobEntry) -> Vec<u8> {
        LargeBlobArray::parse(&[0x80])
            .unwrap()
            .with_entry_for_test(e)
            .serialize_with_checksum()
            .unwrap()
    }

    /// Encrypt `plain` (already the CBOR map) into an entry as a writer
    /// would, but declaring `orig_size` and using `key`.
    fn seal(plain: &[u8], key: &[u8; 32], orig_size: u64) -> LargeBlobEntry {
        let ct = gcm_encrypt(key, &NONCE, &stored_deflate(plain), orig_size);
        LargeBlobEntry::built(ct, NONCE.to_vec(), orig_size)
    }

    fn seal_value(v: &Value) -> LargeBlobEntry {
        let p = cbor::encode(v);
        seal(&p, &label_key(), p.len() as u64)
    }

    fn label_map(extra: Vec<(Value, Value)>) -> Vec<(Value, Value)> {
        let mut m = vec![
            (Value::UInt(1), Value::UInt(1)),
            (Value::UInt(2), Value::Text("Work YubiKey".into())),
        ];
        m.extend(extra);
        m
    }

    #[test]
    fn label_key_matches_published_constant() {
        assert_eq!(
            hex(&label_key()),
            "2d90176240c249e3f7aaeabd444093437d2f595dc778bf45d3cc0554f326b639"
        );
    }

    #[test]
    fn v1_v2_entries_match_vectors() {
        for (l, p, deflate_head, ct, entry, sum, orig) in [
            (v1(), V1_P, "011100eeff", V1_CT, V1_ENTRY, V1_SUM, 17u64),
            (v2(), V2_P, "011d00e2ff", V2_CT, V2_ENTRY, V2_SUM, 29),
        ] {
            assert_eq!(hex(&plaintext(&l).unwrap()), p);
            assert_eq!(
                hex(&stored_deflate(&unhex(p))),
                format!("{deflate_head}{p}")
            );
            let e = encode_entry(&l, NONCE).unwrap();
            assert_eq!(hex(&e.ciphertext), ct);
            assert_eq!(e.nonce, NONCE.to_vec());
            assert_eq!(e.orig_size, orig);
            let array = one_entry_array(e.clone());
            assert_eq!(hex(&array), format!("81{entry}{sum}"));
            // Read back from the stored bytes, the entry decodes to `l`.
            let parsed = LargeBlobArray::parse(&array[..array.len() - 16]).unwrap();
            assert_eq!(decode_entry(parsed.entry(0).unwrap()), Some(l));
        }
    }

    #[test]
    fn v3_compressed_entry_decodes() {
        let raw = unhex("a301582371eda327a400c713df95d9f1d5fab5675779cad37fb437982c7a5dda50d98d583dc030024ca0a1a2a3a4a5a6a7a8a9aaab0311");
        let mut array = vec![0x81];
        array.extend_from_slice(&raw);
        let parsed = LargeBlobArray::parse(&array).unwrap();
        assert_eq!(decode_entry(parsed.entry(0).unwrap()), Some(v1()));
        // The vector really is compressed: it differs from a stored block.
        let plain = gcm_decrypt(
            &label_key(),
            &parsed.entry(0).unwrap().nonce,
            &parsed.entry(0).unwrap().ciphertext,
            17,
        )
        .unwrap();
        assert_eq!(hex(&plain), "5bc4c8c894139e5f94ad10599a94e99d5a0900");
    }

    #[test]
    fn stored_deflate_shape() {
        assert_eq!(hex(&stored_deflate(&[])), "010000ffff");
        for n in [0usize, 17, 29, 300] {
            let data: Vec<u8> = (0..n).map(|i| i as u8).collect();
            let block = stored_deflate(&data);
            assert_eq!(block[0], 0x01);
            assert_eq!(u16::from_le_bytes([block[1], block[2]]) as usize, n);
            assert_eq!(u16::from_le_bytes([block[3], block[4]]), !(n as u16));
            assert_eq!(&block[5..], &data[..]);
            assert_eq!(inflate_raw(&block, n as u64), Some(data));
        }
        assert_eq!(hex(&stored_deflate(&[0; 17])[..5]), "011100eeff");
        assert_eq!(hex(&stored_deflate(&[0; 29])[..5]), "011d00e2ff");
    }

    #[test]
    fn decode_rejects_bad_entries() {
        let good = encode_entry(&v1(), NONCE).unwrap();
        let p = plaintext(&v1()).unwrap();
        let mut flipped = good.clone();
        flipped.ciphertext[0] ^= 0x01;
        let mut tag_flipped = good.clone();
        *tag_flipped.ciphertext.last_mut().unwrap() ^= 0x80;
        let mut trailing = p.clone();
        trailing.push(0x00);
        let mut off_by_one = good.clone();
        off_by_one.orig_size += 1;
        let cases: Vec<(&str, LargeBlobEntry)> = vec![
            ("ciphertext bit flipped", flipped),
            ("tag bit flipped", tag_flipped),
            ("wrong key", seal(&p, &[0x42; 32], p.len() as u64)),
            (
                "version 2",
                seal_value(&Value::Map(vec![
                    (Value::UInt(1), Value::UInt(2)),
                    (Value::UInt(2), Value::Text("Work YubiKey".into())),
                ])),
            ),
            (
                "label 65 chars",
                seal_value(&Value::Map(vec![
                    (Value::UInt(1), Value::UInt(1)),
                    (Value::UInt(2), Value::Text("\u{e9}".repeat(65))),
                ])),
            ),
            (
                "empty label",
                seal_value(&Value::Map(vec![
                    (Value::UInt(1), Value::UInt(1)),
                    (Value::UInt(2), Value::Text(String::new())),
                ])),
            ),
            (
                "label not text",
                seal_value(&Value::Map(vec![
                    (Value::UInt(1), Value::UInt(1)),
                    (Value::UInt(2), Value::Bytes(b"Work YubiKey".to_vec())),
                ])),
            ),
            (
                "no label",
                seal_value(&Value::Map(vec![(Value::UInt(1), Value::UInt(1))])),
            ),
            ("not a map", seal_value(&Value::Array(vec![Value::UInt(1)]))),
            (
                "trailing byte after the map",
                seal(&trailing, &label_key(), trailing.len() as u64),
            ),
            ("origSize off by one", off_by_one),
            ("origSize 2 MiB", seal(&p, &label_key(), 2 * 1024 * 1024)),
            (
                "nonce 11 bytes",
                LargeBlobEntry::built(good.ciphertext.clone(), NONCE[..11].to_vec(), 17),
            ),
        ];
        for (what, e) in cases {
            assert_eq!(decode_entry(&e), None, "{what}");
        }
        // The 64-char boundary is accepted.
        let at_limit = seal_value(&Value::Map(vec![
            (Value::UInt(1), Value::UInt(1)),
            (Value::UInt(2), Value::Text("\u{e9}".repeat(64))),
        ]));
        assert_eq!(decode_entry(&at_limit).unwrap().label.chars().count(), 64);
    }

    #[test]
    fn decode_ignores_unknown_and_bad_writer() {
        let extra = seal_value(&Value::Map(label_map(vec![(
            Value::UInt(9),
            Value::Array(vec![Value::Null, Value::Bool(true)]),
        )])));
        assert_eq!(decode_entry(&extra), Some(v1()));
        let uint_writer = seal_value(&Value::Map(label_map(vec![(
            Value::UInt(3),
            Value::UInt(7),
        )])));
        assert_eq!(decode_entry(&uint_writer), Some(v1()));
        let long_writer = seal_value(&Value::Map(label_map(vec![(
            Value::UInt(3),
            Value::Text("w".repeat(65)),
        )])));
        assert_eq!(decode_entry(&long_writer), Some(v1()));
        // Readers apply the writers' rule: an empty writer is dropped.
        let empty_writer = seal_value(&Value::Map(label_map(vec![(
            Value::UInt(3),
            Value::Text(String::new()),
        )])));
        assert_eq!(decode_entry(&empty_writer), Some(v1()));
        // Duplicate keys: the first one wins.
        let dup = seal_value(&Value::Map(label_map(vec![(
            Value::UInt(2),
            Value::Text("Other".into()),
        )])));
        assert_eq!(decode_entry(&dup), Some(v1()));
    }

    #[test]
    fn plaintext_refuses_bad_lengths() {
        let mk = |label: String, writer: Option<String>| DeviceLabel { label, writer };
        let invalid = |r: Result<Vec<u8>, LabelError>| matches!(r, Err(LabelError::InvalidLabel));
        assert!(invalid(plaintext(&mk(String::new(), None))));
        assert!(invalid(plaintext(&mk("x".repeat(65), None))));
        assert!(plaintext(&mk("\u{1f511}".repeat(64), None)).is_ok());
        assert!(invalid(plaintext(&mk("x".into(), Some("w".repeat(65))))));
        assert!(invalid(plaintext(&mk("x".into(), Some(String::new())))));
        assert!(matches!(
            encode_entry(&mk(String::new(), None), NONCE),
            Err(LabelError::InvalidLabel)
        ));
    }

    #[test]
    fn classify_recognizes_key_name_and_not_notes() {
        let e = encode_entry(&v2(), NONCE).unwrap();
        assert_eq!(e.classify(), EntryKind::KeyName(v2()));
        // A keyroost note is never a name, whatever it says.
        let note = LargeBlobEntry::from_text("Work YubiKey");
        assert_eq!(decode_entry(&note), None);
        assert_eq!(note.classify(), EntryKind::Note("Work YubiKey".into()));
        // Nor is an entry under another key.
        let p = plaintext(&v1()).unwrap();
        let foreign = seal(&p, &[0x11; 32], p.len() as u64);
        assert_eq!(foreign.classify(), EntryKind::Opaque);
    }

    fn label_nonce(seed: u8) -> [u8; 12] {
        [seed; 12]
    }

    fn named(label: &str) -> DeviceLabel {
        DeviceLabel {
            label: label.into(),
            writer: Some(WRITER_KEYROOST.into()),
        }
    }

    /// [RP entry with key 4, label A, note, tagged item, label B, non-map].
    fn fixture() -> (Vec<Vec<u8>>, LargeBlobArray) {
        let mut rp = vec![0xa4, 0x01, 0x54];
        rp.extend_from_slice(&[0x11; 20]);
        rp.extend_from_slice(&[0x02, 0x4c]);
        rp.extend_from_slice(&[0x22; 12]);
        rp.extend_from_slice(&[0x03, 0x05, 0x04, 0x61, 0x78]);
        let label_bytes = |l: &str, n: u8| {
            let one = one_entry_array(encode_entry(&named(l), label_nonce(n)).unwrap());
            one[1..one.len() - 16].to_vec()
        };
        let note = {
            let one = one_entry_array(LargeBlobEntry::from_text("note"));
            one[1..one.len() - 16].to_vec()
        };
        let elements = vec![
            rp,
            label_bytes("Old A", 1),
            note,
            vec![0xc1, 0x01],
            label_bytes("Old B", 2),
            vec![0x61, 0x78],
        ];
        let mut bytes = cbor::array_header(elements.len());
        for e in &elements {
            bytes.extend_from_slice(e);
        }
        (elements, LargeBlobArray::parse(&bytes).unwrap())
    }

    /// The raw elements of a serialized array (checksum stripped).
    fn elements_of(serialized: &[u8]) -> Vec<Vec<u8>> {
        let (items, rest) = cbor::split_array(&serialized[..serialized.len() - 16]).unwrap();
        assert!(rest.is_empty());
        items.into_iter().map(|i| i.to_vec()).collect()
    }

    #[test]
    fn with_label_appends_one_and_keeps_the_rest_byte_identical() {
        let (input, arr) = fixture();
        assert_eq!((arr.len(), arr.skipped_count()), (4, 2));
        let others = vec![
            input[0].clone(),
            input[2].clone(),
            input[3].clone(),
            input[5].clone(),
        ];

        let new = named("Work YubiKey");
        let set = arr.with_label(Some(&new), label_nonce(9)).unwrap();
        let bytes = set.serialize_with_checksum().unwrap();
        let out = elements_of(&bytes);
        assert_eq!(out.len(), 5);
        assert_eq!(&out[..4], &others[..]);
        let parsed = LargeBlobArray::parse(&bytes[..bytes.len() - 16]).unwrap();
        let (idx, got) = parsed.label().unwrap();
        assert_eq!((idx, got), (2, new.clone()));
        assert_eq!(parsed.entry(2).unwrap().nonce, label_nonce(9).to_vec());
        let label_count = parsed
            .entries()
            .into_iter()
            .filter(|e| decode_entry(e).is_some())
            .count();
        assert_eq!(label_count, 1);

        let cleared = arr.with_label(None, label_nonce(9)).unwrap();
        assert_eq!(
            elements_of(&cleared.serialize_with_checksum().unwrap()),
            others
        );
        assert_eq!(cleared.label(), None);

        assert!(matches!(
            arr.with_label(Some(&named("")), label_nonce(9)),
            Err(LabelError::InvalidLabel)
        ));
    }

    #[test]
    fn last_label_wins_and_write_collapses() {
        let (_, arr) = fixture();
        // Entry indices: 0 RP, 1 Old A, 2 note, 3 Old B.
        assert_eq!(arr.label(), Some((3, named("Old B"))));
        let rewritten = arr.with_label(Some(&named("New")), label_nonce(3)).unwrap();
        let labels: Vec<DeviceLabel> = rewritten
            .entries()
            .into_iter()
            .filter_map(decode_entry)
            .collect();
        assert_eq!(labels, vec![named("New")]);
        assert_eq!(LargeBlobArray::parse(&[0x80]).unwrap().label(), None);
    }

    #[test]
    fn only_label_keeps_the_label_bytes() {
        let (input, arr) = fixture();
        let kept = arr.only_label();
        assert_eq!(
            elements_of(&kept.serialize_with_checksum().unwrap()),
            vec![input[1].clone(), input[4].clone()]
        );
        assert_eq!(kept.label(), Some((1, named("Old B"))));
        let none = LargeBlobArray::parse(&[0x81, 0x61, 0x78])
            .unwrap()
            .only_label();
        assert_eq!(hex(&none.serialize_with_checksum().unwrap()[..1]), "80");
    }

    // ---- reading and writing through a scripted key ----

    use crate::client_pin::PinUvAuthToken;
    use crate::pin::PIN_PROTOCOL_V1;

    /// A key that answers `get` from a stored array and records every
    /// `set`. Each full read (a `get` at offset 0) takes the next array in
    /// `reads`; once they run out the last one keeps answering.
    struct FakeKey {
        reads: Vec<Vec<u8>>,
        current: Vec<u8>,
        sets: Vec<(u64, Vec<u8>, Option<u64>)>,
        calls: usize,
    }

    impl FakeKey {
        fn new(reads: Vec<Vec<u8>>) -> Self {
            FakeKey {
                reads,
                current: Vec::new(),
                sets: Vec::new(),
                calls: 0,
            }
        }

        /// The recorded `set` fragments, reassembled.
        fn written(&self) -> Vec<u8> {
            let mut out = Vec::new();
            for (offset, fragment, _) in &self.sets {
                assert_eq!(*offset as usize, out.len(), "fragments are contiguous");
                out.extend_from_slice(fragment);
            }
            out
        }
    }

    impl CtapTransport for FakeKey {
        fn transact(&mut self, cmd: u8, payload: &[u8]) -> Result<Vec<u8>, CtapError> {
            self.calls += 1;
            assert_eq!(cmd, crate::hid::CTAPHID_CBOR);
            assert_eq!(payload[0], 0x0c, "authenticatorLargeBlobs");
            let (req, _) = cbor::decode(&payload[1..]).unwrap();
            let offset = req.get_uint_key(3).and_then(Value::as_uint).unwrap();
            if let Some(count) = req.get_uint_key(1).and_then(Value::as_uint) {
                if offset == 0 && !self.reads.is_empty() {
                    self.current = self.reads.remove(0);
                }
                let from = (offset as usize).min(self.current.len());
                let to = (from + count as usize).min(self.current.len());
                let mut resp = vec![0x00];
                resp.extend_from_slice(&cbor::encode(&Value::Map(vec![(
                    Value::UInt(1),
                    Value::Bytes(self.current[from..to].to_vec()),
                )])));
                return Ok(resp);
            }
            let fragment = req.get_uint_key(2).and_then(Value::as_bytes).unwrap();
            let length = req.get_uint_key(4).and_then(Value::as_uint);
            self.sets.push((offset, fragment.to_vec(), length));
            Ok(vec![0x00])
        }
    }

    fn token() -> PinUvAuthToken {
        PinUvAuthToken {
            protocol: PIN_PROTOCOL_V1,
            token: vec![0x42; 16],
        }
    }

    fn info(large_blobs: bool, client_pin: Option<bool>) -> AuthenticatorInfo {
        let mut info = AuthenticatorInfo::default();
        if large_blobs {
            info.options.push(("largeBlobs".into(), true));
        }
        if let Some(set) = client_pin {
            info.options.push(("clientPin".into(), set));
        }
        info
    }

    /// The array (without checksum) and its stored form (with).
    fn stored(arr: &LargeBlobArray) -> (LargeBlobArray, Vec<u8>) {
        let bytes = arr.serialize_with_checksum().unwrap();
        let parsed = LargeBlobArray::parse(&bytes[..bytes.len() - 16]).unwrap();
        (parsed, bytes)
    }

    fn empty() -> LargeBlobArray {
        LargeBlobArray::parse(&[0x80]).unwrap()
    }

    /// An array holding one keyroost note, `total` bytes stored.
    fn array_of_size(total: usize) -> LargeBlobArray {
        (0..total)
            .map(|n| empty().with_text_note(&"x".repeat(n)))
            .find(|a| a.serialize_with_checksum().unwrap().len() == total)
            .expect("a note size that lands exactly on the total")
    }

    #[test]
    fn read_label_unsupported_without_largeblobs_option() {
        let mut key = FakeKey::new(vec![]);
        assert_eq!(
            read_label(&mut key, &info(false, Some(true))).unwrap(),
            LabelState::Unsupported
        );
        assert_eq!(key.calls, 0, "nothing is sent to a key without storage");
    }

    #[test]
    fn read_label_absent_and_present() {
        let (_, none) = stored(&empty().with_text_note("note"));
        let (_, some) = stored(
            &empty()
                .with_text_note("note")
                .with_label(Some(&v2()), NONCE)
                .unwrap(),
        );
        let mut key = FakeKey::new(vec![none, some]);
        let i = info(true, None); // no PIN needed to read
        assert_eq!(read_label(&mut key, &i).unwrap(), LabelState::Absent);
        assert_eq!(read_label(&mut key, &i).unwrap(), LabelState::Present(v2()));
        assert!(key.sets.is_empty());
    }

    #[test]
    fn plan_refuses_when_full() {
        let current = array_of_size(1000);
        // The V1 entry is 58 bytes; the array header stays one byte.
        for max in [Some(1024), None] {
            let mut i = info(true, Some(true));
            i.max_serialized_large_blob_array = max;
            match plan_label_change(&current, &i, Some(&v1()), NONCE) {
                Err(LabelError::TooLarge { size, max }) => assert_eq!((size, max), (1058, 1024)),
                other => panic!("expected TooLarge, got {other:?}"),
            }
        }
        // An array already over the limit reports its total, never "0 more".
        let over = array_of_size(1100);
        let i = info(true, Some(true));
        match plan_label_change(&over, &i, None, NONCE) {
            Err(
                e @ LabelError::TooLarge {
                    size: 1100,
                    max: 1024,
                },
            ) => {
                assert!(e.to_string().contains("76 bytes over"), "{e}")
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
        // It fits exactly when the key has the room.
        let mut i = info(true, Some(true));
        i.max_serialized_large_blob_array = Some(1058);
        let plan = plan_label_change(&current, &i, Some(&v1()), NONCE).unwrap();
        assert_eq!(plan.serialized.len(), 1058);
    }

    #[test]
    fn plan_refuses_without_pin() {
        for pin in [None, Some(false)] {
            assert!(matches!(
                plan_label_change(&empty(), &info(true, pin), Some(&v1()), NONCE),
                Err(LabelError::NoPin)
            ));
        }
    }

    #[test]
    fn plan_refuses_unsupported() {
        assert!(matches!(
            plan_label_change(&empty(), &info(false, Some(true)), Some(&v1()), NONCE),
            Err(LabelError::Unsupported)
        ));
    }

    #[test]
    fn plan_refuses_an_invalid_label_and_a_trailing_array() {
        let i = info(true, Some(true));
        let bad = DeviceLabel {
            label: "x".repeat(65),
            writer: None,
        };
        assert!(matches!(
            plan_label_change(&empty(), &i, Some(&bad), NONCE),
            Err(LabelError::InvalidLabel)
        ));
        // Bytes after the array would be dropped by the rewrite.
        let trailing = LargeBlobArray::parse(&[0x80, 0x00]).unwrap();
        assert!(matches!(
            plan_label_change(&trailing, &i, Some(&v1()), NONCE),
            Err(LabelError::Ctap(_))
        ));
    }

    #[test]
    fn plan_reports_previous_and_keeps_other_entries() {
        let (current, _) = stored(
            &empty()
                .with_label(Some(&v2()), NONCE)
                .unwrap()
                .with_text_note("note"),
        );
        let plan =
            plan_label_change(&current, &info(true, Some(true)), Some(&v1()), NONCE).unwrap();
        assert_eq!(plan.previous, Some(v2()));
        assert_eq!(plan.before_raw, current.raw_array());
        assert_eq!(plan.after.label(), Some((1, v1())));
        assert_eq!(
            plan.after.entry(0).unwrap().as_text().as_deref(),
            Some("note")
        );
        assert_eq!(
            plan.serialized,
            plan.after.serialize_with_checksum().unwrap()
        );
        let cleared = plan_label_change(&current, &info(true, Some(true)), None, NONCE).unwrap();
        assert_eq!(cleared.after.label(), None);
        assert_eq!(cleared.after.len(), 1);
    }

    #[test]
    fn apply_refuses_when_the_array_changed_and_sends_no_set() {
        let (current, before) = stored(&empty().with_text_note("note"));
        let (_, changed) = stored(&empty().with_text_note("note 2"));
        let i = info(true, Some(true));
        let plan = plan_label_change(&current, &i, Some(&v1()), NONCE).unwrap();
        let mut key = FakeKey::new(vec![changed]);
        assert!(matches!(
            apply_label_plan(&mut key, &i, &token(), &plan),
            Err(LabelError::Changed)
        ));
        assert!(key.sets.is_empty());
        // Unchanged, the same plan goes through.
        let mut key = FakeKey::new(vec![before]);
        apply_label_plan(&mut key, &i, &token(), &plan).unwrap();
        assert_eq!(key.written(), plan.serialized);
    }

    #[test]
    fn apply_writes_exactly_the_planned_bytes() {
        // Single fragment (default maxMsgSize) and several (1536 → 1472-byte
        // fragments over a ~2000-byte array).
        let small = empty().with_text_note("note");
        let big = empty().with_text_note(&"y".repeat(2000));
        for (arr, max_msg, fragments) in [(small, None, 1), (big, Some(1536), 2)] {
            let (current, before) = stored(&arr);
            let mut i = info(true, Some(true));
            i.max_msg_size = max_msg;
            i.max_serialized_large_blob_array = Some(4096);
            let plan = plan_label_change(&current, &i, Some(&v2()), NONCE).unwrap();
            let mut key = FakeKey::new(vec![before]);
            apply_label_plan(&mut key, &i, &token(), &plan).unwrap();
            assert_eq!(key.sets.len(), fragments);
            assert_eq!(key.written(), plan.serialized);
            // Only the first fragment declares the total length.
            assert_eq!(key.sets[0].2, Some(plan.serialized.len() as u64));
            assert!(key.sets[1..].iter().all(|s| s.2.is_none()));
        }
    }

    #[test]
    fn random_nonces_differ() {
        assert_ne!(random_nonce(), random_nonce());
    }
}
