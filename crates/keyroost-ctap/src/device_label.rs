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
//! holds at most one name entry: writers remove every one and append one,
//! readers take the last. The label is stored exactly as given; writers
//! SHOULD use Unicode NFC. Callers validate the label's text (keyroost uses
//! `keyroost_keyring::validate_name`); this module checks only its type and
//! length.

use crate::cbor::{self, Value};
use crate::cmd::CtapError;
use crate::large_blobs::{gcm_decrypt, gcm_encrypt, inflate_raw, LargeBlobEntry};

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
    /// The change needs `need` more bytes; the key has `free`.
    TooLarge {
        need: u64,
        free: u64,
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
            LabelError::TooLarge { need, free } => write!(
                f,
                "not enough large-blob space for the name: it needs {need} more \
                 bytes and {free} are free"
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

/// The label text as it is stored. Version 1 stores it exactly as given
/// (writers SHOULD pass NFC); this is the one place a normalization step
/// would go.
fn stored_label(label: &str) -> String {
    label.to_owned()
}

/// The canonical CBOR plaintext for `l`: `{1: 1, 2: label, 3?: writer}`.
/// Refuses a label (or writer) that is empty or over 64 characters.
pub fn plaintext(l: &DeviceLabel) -> Result<Vec<u8>, LabelError> {
    let label = stored_label(&l.label);
    if !fits(&label) || l.writer.as_deref().is_some_and(|w| !fits(w)) {
        return Err(LabelError::InvalidLabel);
    }
    let mut map = vec![
        (Value::UInt(P_VERSION), Value::UInt(LABEL_FORMAT_VERSION)),
        (Value::UInt(P_LABEL), Value::Text(label)),
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
/// `nonce`, which must be fresh and random outside tests.
pub fn encode_entry(l: &DeviceLabel, nonce: [u8; 12]) -> Result<LargeBlobEntry, LabelError> {
    let p = plaintext(l)?;
    let orig_size = p.len() as u64;
    let ciphertext = gcm_encrypt(&label_key(), &nonce, &stored_deflate(&p), orig_size);
    Ok(LargeBlobEntry::built(ciphertext, nonce.to_vec(), orig_size))
}

/// The name `e` holds, or `None` when `e` is not a name entry: its tag must
/// verify under [`label_key`], it must inflate to exactly `origSize` bytes
/// of one CBOR map with version 1 and a 1–64 character text label. A writer
/// that isn't text of at most 64 characters is dropped; unknown keys are
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
        .filter(|w| w.chars().count() <= MAX_LABEL_CHARS);
    Some(DeviceLabel {
        label: label.to_owned(),
        writer: writer.map(str::to_owned),
    })
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
}
