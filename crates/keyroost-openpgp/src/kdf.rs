//! The card's KDF setting (`KDF-DO`, tag `F9`; OpenPGP Card spec v3.4.1
//! §4.3.2): when it is on, every PIN and the resetting code reach the card
//! as a salted, iterated hash instead of as typed.
//!
//! The card never evaluates the setting itself; it compares whatever bytes
//! it is sent. A host that sends the typed PIN to a card whose PINs were
//! stored hashed (GnuPG's `kdf-setup` does that) spends a retry on every
//! attempt. So the host reads `F9` (no PIN needed, no counter touched), and
//! derives each PIN with the OpenPGP iterated and salted S2K (RFC 4880
//! §3.7.1.3) before framing VERIFY, CHANGE REFERENCE DATA or RESET RETRY
//! COUNTER.
//!
//! Layout of the `F9` value (any order; unknown tags are ignored):
//!
//! ```text
//! 81 01  algorithm: 00 = none (PINs as typed), 03 = iterated+salted S2K
//! 82 01  hash: 08 = SHA-256, 0A = SHA-512
//! 83 04  bytes to hash, big-endian (the raw count, not RFC 4880's coded byte)
//! 84 xx  salt for PW1 (the user PIN, both contexts)
//! 85 xx  salt for the resetting code (absent: the PW1 salt)
//! 86 xx  salt for PW3 (the admin PIN; absent: the PW1 salt)
//! 87 xx  initial hash of PW1 (the default 123456, derived)
//! 88 xx  initial hash of PW3 (the default 12345678, derived)
//! ```
//!
//! GnuPG writes the 90-byte form (one salt, `84`) and the 110-byte form
//! (three salts); both parse here, as does any other order or salt length.
//! A setting this module doesn't recognize is an error, never "send the
//! PIN as typed": a guess there costs a retry.

use crate::{parse_tlvs, ParseError, PW3_ADMIN};
use keyroost_proto::{sha256::Sha256, sha512::Sha512};
use zeroize::{Zeroize, Zeroizing};

/// The KDF data object (`F9`): read it with [`get_kdf`], parse it with
/// [`parse_kdf`].
pub const TAG_KDF: u16 = 0x00F9;

/// Extended Capabilities (`C0`) byte 0, bit 1: the card has a KDF-DO (`F9`)
/// and supports PINs in the derived format.
pub const EXT_CAP_KDF: u8 = 0x01;

/// The most bytes a KDF setting may ask to hash: 65,011,712, the largest
/// count RFC 4880's one-byte coded count expresses (`0xFF`), and the most
/// GnuPG's `kdf-setup` writes. A setting asking for more is refused, so a
/// broken card can't stall a PIN entry for minutes.
pub const KDF_MAX_COUNT: u32 = 65_011_712;

/// `GET DATA 00F9` — the KDF setting: `00 CA 00 F9 00`. Readable without a
/// PIN (access "Always").
#[must_use]
pub fn get_kdf() -> Vec<u8> {
    crate::get_data(TAG_KDF)
}

/// The hash a KDF setting names (`82`).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfHash {
    /// `08`
    Sha256,
    /// `0A`
    Sha512,
}

impl KdfHash {
    /// The name as GnuPG and the spec write it: `SHA-256`, `SHA-512`.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            KdfHash::Sha256 => "SHA-256",
            KdfHash::Sha512 => "SHA-512",
        }
    }

    /// Length of a derived PIN: the digest length.
    #[must_use]
    pub fn digest_len(self) -> usize {
        match self {
            KdfHash::Sha256 => 32,
            KdfHash::Sha512 => 64,
        }
    }

    fn from_id(id: u8) -> Option<KdfHash> {
        match id {
            0x08 => Some(KdfHash::Sha256),
            0x0A => Some(KdfHash::Sha512),
            _ => None,
        }
    }
}

/// Which secret is being derived; picks the salt.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinRole {
    /// PW1, the user PIN (VERIFY `81` and `82` alike).
    User,
    /// The resetting code.
    ResetCode,
    /// PW3, the admin PIN.
    Admin,
}

impl PinRole {
    /// The role of the password a VERIFY / CHANGE REFERENCE DATA reference
    /// names: [`PW3_ADMIN`] is the admin PIN, `81` and `82` the user PIN.
    #[must_use]
    pub fn for_pw_ref(pw_ref: u8) -> PinRole {
        if pw_ref == PW3_ADMIN {
            PinRole::Admin
        } else {
            PinRole::User
        }
    }

    /// The shortest the spec allows: PW1 6 bytes and PW3 8 (§7.2.2), the
    /// resetting code 8. With the KDF setting on, the card sees only the
    /// hash and can't check this, so the host does.
    #[must_use]
    pub fn min_len(self) -> usize {
        match self {
            PinRole::User => 6,
            PinRole::ResetCode | PinRole::Admin => 8,
        }
    }

    /// The name used in messages: `user PIN`, `reset code`, `admin PIN`.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            PinRole::User => "user PIN",
            PinRole::ResetCode => "reset code",
            PinRole::Admin => "admin PIN",
        }
    }
}

/// The parameters of an on KDF setting (algorithm `03`). Salts and the
/// initial hashes are public (anyone holding the card can read them), but
/// `Debug` leaves them out anyway: they have no business in a log.
#[derive(Clone, PartialEq, Eq)]
pub struct KdfParams {
    hash: KdfHash,
    count: u32,
    salt_user: Vec<u8>,
    salt_reset: Option<Vec<u8>>,
    salt_admin: Option<Vec<u8>>,
    initial_user: Option<Vec<u8>>,
    initial_admin: Option<Vec<u8>>,
}

impl core::fmt::Debug for KdfParams {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KdfParams")
            .field("hash", &self.hash)
            .field("count", &self.count)
            .field("separate_salts", &self.separate_salts())
            .finish_non_exhaustive()
    }
}

impl KdfParams {
    /// The hash (`82`).
    #[must_use]
    pub fn hash(&self) -> KdfHash {
        self.hash
    }

    /// Bytes hashed per derivation (`83`).
    #[must_use]
    pub fn count(&self) -> u32 {
        self.count
    }

    /// Whether the admin PIN or the resetting code has a salt of its own
    /// (GnuPG's 110-byte form) rather than sharing the user PIN's.
    #[must_use]
    pub fn separate_salts(&self) -> bool {
        self.salt_reset.is_some() || self.salt_admin.is_some()
    }

    /// The derived default PIN the setting records for `role` (`87` for the
    /// user PIN, `88` for the admin PIN), if present. The resetting code has
    /// none.
    #[must_use]
    pub fn initial_hash(&self, role: PinRole) -> Option<&[u8]> {
        match role {
            PinRole::User => self.initial_user.as_deref(),
            PinRole::Admin => self.initial_admin.as_deref(),
            PinRole::ResetCode => None,
        }
    }

    /// The salt for `role`, per §4.3.2: the user PIN's for PW1; the admin
    /// PIN's or the resetting code's own when present, else the user PIN's.
    fn salt(&self, role: PinRole) -> &[u8] {
        let own = match role {
            PinRole::User => None,
            PinRole::ResetCode => self.salt_reset.as_deref(),
            PinRole::Admin => self.salt_admin.as_deref(),
        };
        own.unwrap_or(&self.salt_user)
    }
}

/// A card's KDF setting.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kdf {
    /// No KDF (algorithm `00`, an empty object, or a card without one): PINs
    /// go to the card as typed.
    Off,
    /// Iterated and salted S2K (algorithm `03`).
    IterSaltedS2k(KdfParams),
}

impl Kdf {
    /// Whether PINs are derived before they reach the card.
    #[must_use]
    pub fn is_on(&self) -> bool {
        matches!(self, Kdf::IterSaltedS2k(_))
    }

    /// The bytes to send for `pin` in `role`: the derived value with the
    /// setting on, a copy of `pin` with it off.
    #[must_use]
    pub fn derive(&self, role: PinRole, pin: &[u8]) -> Zeroizing<Vec<u8>> {
        match self {
            Kdf::Off => Zeroizing::new(pin.to_vec()),
            Kdf::IterSaltedS2k(p) => iter_salted_s2k(p.hash, p.count, p.salt(role), pin),
        }
    }
}

/// Why a KDF setting was not recognized. `Display` is a short noun phrase
/// ("hash 0x09") for "unrecognized setting (…)" messages.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KdfError {
    /// The object isn't valid BER-TLV.
    Tlv(ParseError),
    /// An algorithm (`81`) other than `00` and `03`.
    UnknownAlgorithm(u8),
    /// A hash (`82`) other than SHA-256 (`08`) and SHA-512 (`0A`).
    UnknownHash(u8),
    /// A field the algorithm needs is absent (the tag).
    MissingField(u8),
    /// A field has a length it can't have (the tag and the length).
    FieldLength { tag: u8, len: usize },
    /// A field appears more than once (the tag).
    DuplicateField(u8),
    /// An iteration count of 0 or above [`KDF_MAX_COUNT`].
    Count(u32),
}

impl core::fmt::Display for KdfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            KdfError::Tlv(_) => write!(f, "malformed data"),
            KdfError::UnknownAlgorithm(a) => write!(f, "algorithm 0x{a:02X}"),
            KdfError::UnknownHash(h) => write!(f, "hash 0x{h:02X}"),
            KdfError::MissingField(t) => write!(f, "no field {t:02X}"),
            KdfError::FieldLength { tag, len } => write!(f, "field {tag:02X} of {len} bytes"),
            KdfError::DuplicateField(t) => write!(f, "field {t:02X} twice"),
            KdfError::Count(c) => write!(f, "iteration count {c}"),
        }
    }
}

impl std::error::Error for KdfError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            KdfError::Tlv(e) => Some(e),
            _ => None,
        }
    }
}

/// Parse a `GET DATA 00F9` reply: the bare value, or one `F9` envelope
/// around it. Empty, or algorithm `00`, is [`Kdf::Off`]; anything not
/// recognized is an error (see [`KdfError`]).
pub fn parse_kdf(buf: &[u8]) -> Result<Kdf, KdfError> {
    let top = parse_tlvs(buf).map_err(KdfError::Tlv)?;
    let inner = match top.as_slice() {
        [one] if one.tag == TAG_KDF => one.value,
        _ => buf,
    };
    if inner.is_empty() {
        return Ok(Kdf::Off);
    }
    let tlvs = parse_tlvs(inner).map_err(KdfError::Tlv)?;
    // One value per field, by its one-byte tag.
    let mut fields: [Option<&[u8]>; 8] = [None; 8];
    for t in &tlvs {
        if let Some(i) = t.tag.checked_sub(0x81).filter(|&i| i < 8) {
            let slot = &mut fields[usize::from(i)];
            if slot.is_some() {
                return Err(KdfError::DuplicateField(t.tag as u8));
            }
            *slot = Some(t.value);
        }
    }
    let field = |tag: u8| fields[usize::from(tag - 0x81)];
    let required = |tag: u8| field(tag).ok_or(KdfError::MissingField(tag));
    let exact = |tag: u8, v: &[u8], len: usize| {
        if v.len() == len {
            Ok(())
        } else {
            Err(KdfError::FieldLength { tag, len: v.len() })
        }
    };

    let alg = required(0x81)?;
    exact(0x81, alg, 1)?;
    match alg[0] {
        0x00 => return Ok(Kdf::Off),
        0x03 => {}
        other => return Err(KdfError::UnknownAlgorithm(other)),
    }
    let hash = required(0x82)?;
    exact(0x82, hash, 1)?;
    let hash = KdfHash::from_id(hash[0]).ok_or(KdfError::UnknownHash(hash[0]))?;
    let count = required(0x83)?;
    exact(0x83, count, 4)?;
    let count = u32::from_be_bytes([count[0], count[1], count[2], count[3]]);
    if count == 0 || count > KDF_MAX_COUNT {
        return Err(KdfError::Count(count));
    }
    let salt = |tag: u8| -> Result<Option<Vec<u8>>, KdfError> {
        match field(tag) {
            None => Ok(None),
            Some([]) => Err(KdfError::FieldLength { tag, len: 0 }),
            Some(v) => Ok(Some(v.to_vec())),
        }
    };
    let salt_user = salt(0x84)?.ok_or(KdfError::MissingField(0x84))?;
    let initial = |tag: u8| -> Result<Option<Vec<u8>>, KdfError> {
        match field(tag) {
            None => Ok(None),
            Some(v) => exact(tag, v, hash.digest_len()).map(|()| Some(v.to_vec())),
        }
    };
    Ok(Kdf::IterSaltedS2k(KdfParams {
        hash,
        count,
        salt_user,
        salt_reset: salt(0x85)?,
        salt_admin: salt(0x86)?,
        initial_user: initial(0x87)?,
        initial_admin: initial(0x88)?,
    }))
}

/// Bytes fed to the hasher per call: whole `salt || pin` repeats adding up
/// to about this much, so a large count is a few thousand calls, not
/// millions.
const CHUNK: usize = 1024;

/// RFC 4880 §3.7.1.3 iterated and salted S2K with `count` as the raw byte
/// count: hash `salt || pin` repeated and cut to `max(count, len)` bytes,
/// so at least one whole `salt || pin` is hashed.
fn iter_salted_s2k(hash: KdfHash, count: u32, salt: &[u8], pin: &[u8]) -> Zeroizing<Vec<u8>> {
    let unit_len = salt.len() + pin.len();
    // Exact capacities: a Vec that grew would leave its old copy behind.
    let mut unit = Zeroizing::new(Vec::with_capacity(unit_len));
    unit.extend_from_slice(salt);
    unit.extend_from_slice(pin);
    let reps = (CHUNK / unit_len.max(1)).max(1);
    let mut chunk = Zeroizing::new(Vec::with_capacity(reps * unit_len));
    for _ in 0..reps {
        chunk.extend_from_slice(&unit);
    }
    let total = (count as usize).max(unit_len);
    // The chunk is whole repeats, so a prefix of it continues the stream
    // exactly where the previous chunk ended.
    let feed = |update: &mut dyn FnMut(&[u8])| {
        let mut left = total;
        while left > 0 {
            let n = left.min(chunk.len());
            update(&chunk[..n]);
            left -= n;
        }
    };
    match hash {
        KdfHash::Sha256 => {
            let mut h = Sha256::new();
            feed(&mut |d| h.update(d));
            let mut out = h.finalize();
            let v = Zeroizing::new(out.to_vec());
            out.zeroize();
            v
        }
        KdfHash::Sha512 => {
            let mut h = Sha512::new();
            feed(&mut |d| h.update(d));
            let mut out = h.finalize();
            let v = Zeroizing::new(out.to_vec());
            out.zeroize();
            v
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hexbytes(s: &str) -> Vec<u8> {
        let clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        (0..clean.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap())
            .collect()
    }

    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut v = vec![tag, value.len() as u8];
        v.extend_from_slice(value);
        v
    }

    /// The spec's example initial hashes (§4.3.2): "123456" under salt
    /// "01234567" and "12345678" under salt "ABCDEFGH", SHA-256, 100000.
    const SPEC_87: &str = "773784A602B6C81E3F092F4D7D00E17CC822D88F7360FCF2D2EF2D9D901F44B6";
    const SPEC_88: &str = "2675D6164A0D4827D1D00C7EEA620D015C00030A1CAB38B4D0DD600B27DC9630";

    /// The spec's example KDF-DO, in GnuPG's 110-byte three-salt form.
    fn spec_do() -> Vec<u8> {
        [
            tlv(0x81, &[0x03]),
            tlv(0x82, &[0x08]),
            tlv(0x83, &[0x00, 0x01, 0x86, 0xA0]),
            tlv(0x84, b"01234567"),
            tlv(0x85, &[0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17]),
            tlv(0x86, b"ABCDEFGH"),
            tlv(0x87, &hexbytes(SPEC_87)),
            tlv(0x88, &hexbytes(SPEC_88)),
        ]
        .concat()
    }

    /// GnuPG's 90-byte single-salt form of the same setting.
    fn single_salt_do() -> Vec<u8> {
        [
            tlv(0x81, &[0x03]),
            tlv(0x82, &[0x08]),
            tlv(0x83, &[0x00, 0x01, 0x86, 0xA0]),
            tlv(0x84, b"01234567"),
            tlv(0x87, &hexbytes(SPEC_87)),
            tlv(0x88, &hexbytes(SPEC_87)),
        ]
        .concat()
    }

    fn params(kdf: &Kdf) -> &KdfParams {
        match kdf {
            Kdf::IterSaltedS2k(p) => p,
            Kdf::Off => panic!("expected an on setting"),
        }
    }

    /// The derivation spelled out the slow way: the whole repeated buffer
    /// in one update.
    fn reference(hash: KdfHash, count: u32, salt: &[u8], pin: &[u8]) -> Vec<u8> {
        let unit = [salt, pin].concat();
        let n = (count as usize).max(unit.len());
        let data: Vec<u8> = unit.iter().copied().cycle().take(n).collect();
        match hash {
            KdfHash::Sha256 => keyroost_proto::sha256::sha256(&data).to_vec(),
            KdfHash::Sha512 => keyroost_proto::sha512::sha512(&data).to_vec(),
        }
    }

    #[test]
    fn spec_example_initial_hashes() {
        let do_bytes = spec_do();
        assert_eq!(do_bytes.len(), 110);
        let kdf = parse_kdf(&do_bytes).unwrap();
        assert!(kdf.is_on());
        assert_eq!(
            kdf.derive(PinRole::User, b"123456").as_slice(),
            hexbytes(SPEC_87)
        );
        // The admin PIN takes the admin salt (86), not the user one: this
        // value only comes out of "ABCDEFGH".
        assert_eq!(
            kdf.derive(PinRole::Admin, b"12345678").as_slice(),
            hexbytes(SPEC_88)
        );
        let p = params(&kdf);
        assert_eq!(p.initial_hash(PinRole::User), Some(&hexbytes(SPEC_87)[..]));
        assert_eq!(p.initial_hash(PinRole::Admin), Some(&hexbytes(SPEC_88)[..]));
        assert_eq!(p.initial_hash(PinRole::ResetCode), None);
        assert_eq!(p.count(), 100_000);
        assert_eq!(p.hash(), KdfHash::Sha256);
        assert!(p.separate_salts());
    }

    // The expected values below were computed independently with Python's
    // hashlib (repeat salt||PIN, cut to max(count, len), hash once).

    #[test]
    fn sha512_value() {
        let do_bytes = [
            tlv(0x81, &[0x03]),
            tlv(0x82, &[0x0A]),
            tlv(0x83, &[0x00, 0x01, 0x86, 0xA0]),
            tlv(0x84, b"01234567"),
        ]
        .concat();
        let kdf = parse_kdf(&do_bytes).unwrap();
        assert_eq!(params(&kdf).hash(), KdfHash::Sha512);
        let d = kdf.derive(PinRole::User, b"123456");
        assert_eq!(d.len(), 64);
        assert_eq!(
            d.as_slice(),
            hexbytes(
                "9CB102D4452E431F9338C837AC67D713794D3CA93B03D53F9E08216A83B61EC6\
                 C0FCAE8F416CB8AD7D180A46DAB0C48E7E6A5F2A533D62555FD66F99F0DCE34F"
            )
        );
        assert_eq!(
            iter_salted_s2k(KdfHash::Sha512, 1027, b"ABCDEFGH", b"12345678").as_slice(),
            hexbytes(
                "5433D410C8AC1FAEA82299F0079282F34FDBE24A5A37DEBFDF71E0B560E3C8C8\
                 5B55D79E2D6405840D8BD423A51C1F101ECA53441B78B89C449EE7BD704C44DA"
            )
        );
    }

    #[test]
    fn odd_counts() {
        // A count below len(salt||PIN) (14) still hashes it whole, once.
        let once = hexbytes("E4B90D63237D4E6F88E6E894D473B8763673BA0B23D6E4760FB1FE0D719BDDBC");
        for count in [1, 13, 14] {
            assert_eq!(
                iter_salted_s2k(KdfHash::Sha256, count, b"01234567", b"123456").as_slice(),
                once,
                "count {count}"
            );
        }
        // A count that isn't a multiple of 14 cuts the last repeat short.
        assert_eq!(
            iter_salted_s2k(KdfHash::Sha256, 29, b"01234567", b"123456").as_slice(),
            hexbytes("3DDCDE6F598FAA9D5B87E5BC6516D9A1F2618F34EC493E2EE9793C13812AB3C6")
        );
    }

    #[test]
    fn non_ascii_pin_is_hashed_as_utf8() {
        assert_eq!(
            iter_salted_s2k(KdfHash::Sha256, 1000, b"01234567", "12345é".as_bytes()).as_slice(),
            hexbytes("6EDAEEF61BAD8EF046627F4E43BA16C7C08610AD702485A6582F029B19DF20A5")
        );
    }

    #[test]
    fn chunked_feed_matches_the_whole_buffer() {
        // Counts around the chunk and repeat boundaries, short and long
        // PINs, both hashes.
        let salts: [&[u8]; 2] = [b"01234567", &[0x5A; 37]];
        let pins: [&[u8]; 3] = [b"123456", "12345é".as_bytes(), &[b'x'; 300]];
        for hash in [KdfHash::Sha256, KdfHash::Sha512] {
            for salt in salts {
                for pin in pins {
                    for count in [
                        0, 1, 7, 8, 9, 13, 14, 15, 16, 27, 28, 29, 1023, 1024, 1025, 3000,
                    ] {
                        assert_eq!(
                            iter_salted_s2k(hash, count, salt, pin).as_slice(),
                            reference(hash, count, salt, pin),
                            "{hash:?} salt {} pin {} count {count}",
                            salt.len(),
                            pin.len()
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn salt_routing() {
        // Three salts: PW1 takes 84, the resetting code 85, PW3 86.
        let three = parse_kdf(&spec_do()).unwrap();
        assert_eq!(
            three.derive(PinRole::ResetCode, b"87654321").as_slice(),
            hexbytes("66E950AA2EBD84A6446DBD1C5EC02906136B4359A7182D052A33B8018C45771A")
        );
        // One salt: every role takes 84, so the admin's "12345678" no longer
        // gives the spec's 88 value, and the reset code hashes like PW1.
        let one = parse_kdf(&single_salt_do()).unwrap();
        assert_eq!(single_salt_do().len(), 90);
        assert!(!params(&one).separate_salts());
        let admin = one.derive(PinRole::Admin, b"12345678");
        assert_eq!(
            admin.as_slice(),
            reference(KdfHash::Sha256, 100_000, b"01234567", b"12345678")
        );
        assert_ne!(admin.as_slice(), hexbytes(SPEC_88));
        assert_eq!(
            one.derive(PinRole::ResetCode, b"87654321").as_slice(),
            one.derive(PinRole::User, b"87654321").as_slice()
        );
        // Both PW1 references are the user PIN; 83 is the admin PIN.
        assert_eq!(PinRole::for_pw_ref(0x81), PinRole::User);
        assert_eq!(PinRole::for_pw_ref(0x82), PinRole::User);
        assert_eq!(PinRole::for_pw_ref(0x83), PinRole::Admin);
    }

    #[test]
    fn off_sends_the_pin_as_typed() {
        for bytes in [
            &[][..],
            &[0x81, 0x01, 0x00],
            &[0xF9, 0x03, 0x81, 0x01, 0x00],
        ] {
            let kdf = parse_kdf(bytes).unwrap();
            assert_eq!(kdf, Kdf::Off);
            assert!(!kdf.is_on());
            assert_eq!(
                kdf.derive(PinRole::Admin, b"12345678").as_slice(),
                b"12345678"
            );
        }
        // An F9 envelope around nothing is off too.
        assert_eq!(parse_kdf(&[0xF9, 0x00]).unwrap(), Kdf::Off);
    }

    #[test]
    fn parser_takes_the_envelope_and_any_order() {
        let bare = spec_do();
        let mut wrapped = vec![0xF9, 0x6E];
        wrapped.extend_from_slice(&bare);
        assert_eq!(parse_kdf(&wrapped).unwrap(), parse_kdf(&bare).unwrap());
        // Reordered, with an unknown tag in the middle.
        let reordered = [
            tlv(0x88, &hexbytes(SPEC_88)),
            tlv(0x86, b"ABCDEFGH"),
            tlv(0x84, b"01234567"),
            tlv(0x99, &[0x01, 0x02]),
            tlv(0x83, &[0x00, 0x01, 0x86, 0xA0]),
            tlv(0x82, &[0x08]),
            tlv(0x81, &[0x03]),
        ]
        .concat();
        let kdf = parse_kdf(&reordered).unwrap();
        assert_eq!(
            kdf.derive(PinRole::Admin, b"12345678").as_slice(),
            hexbytes(SPEC_88)
        );
        // No 87: optional.
        assert_eq!(params(&kdf).initial_hash(PinRole::User), None);
    }

    #[test]
    fn parser_refuses_what_it_does_not_recognize() {
        let with = |replace: u8, value: &[u8]| -> Vec<u8> {
            let mut out = Vec::new();
            for (tag, v) in [
                (0x81u8, &[0x03][..]),
                (0x82, &[0x08]),
                (0x83, &[0x00, 0x01, 0x86, 0xA0]),
                (0x84, b"01234567"),
            ] {
                if tag == replace {
                    out.extend(tlv(tag, value));
                } else {
                    out.extend(tlv(tag, v));
                }
            }
            out
        };
        let without = |drop: u8| -> Vec<u8> {
            let mut out = Vec::new();
            for (tag, v) in [
                (0x81u8, &[0x03][..]),
                (0x82, &[0x08]),
                (0x83, &[0x00, 0x01, 0x86, 0xA0]),
                (0x84, b"01234567"),
            ] {
                if tag != drop {
                    out.extend(tlv(tag, v));
                }
            }
            out
        };
        assert_eq!(
            parse_kdf(&with(0x81, &[0x05])),
            Err(KdfError::UnknownAlgorithm(0x05))
        );
        assert_eq!(
            parse_kdf(&with(0x82, &[0x09])),
            Err(KdfError::UnknownHash(0x09))
        );
        assert_eq!(
            parse_kdf(&with(0x83, &[0x01, 0x86, 0xA0])),
            Err(KdfError::FieldLength { tag: 0x83, len: 3 })
        );
        assert_eq!(
            parse_kdf(&with(0x83, &[0, 0, 0, 0])),
            Err(KdfError::Count(0))
        );
        assert_eq!(
            parse_kdf(&with(0x83, &(KDF_MAX_COUNT + 1).to_be_bytes())),
            Err(KdfError::Count(KDF_MAX_COUNT + 1))
        );
        assert!(parse_kdf(&with(0x83, &KDF_MAX_COUNT.to_be_bytes())).is_ok());
        assert_eq!(
            parse_kdf(&with(0x84, &[])),
            Err(KdfError::FieldLength { tag: 0x84, len: 0 })
        );
        assert_eq!(
            parse_kdf(&with(0x81, &[0x03, 0x00])),
            Err(KdfError::FieldLength { tag: 0x81, len: 2 })
        );
        for tag in [0x81, 0x82, 0x83, 0x84] {
            assert_eq!(parse_kdf(&without(tag)), Err(KdfError::MissingField(tag)));
        }
        // An initial hash that isn't a digest long.
        let mut short87 = without(0);
        short87.extend(tlv(0x87, &[0xAA; 20]));
        assert_eq!(
            parse_kdf(&short87),
            Err(KdfError::FieldLength { tag: 0x87, len: 20 })
        );
        // The same field twice.
        let mut twice = without(0);
        twice.extend(tlv(0x84, b"other"));
        assert_eq!(parse_kdf(&twice), Err(KdfError::DuplicateField(0x84)));
        // Truncated TLV, in and out of an envelope.
        let mut cut = spec_do();
        cut.truncate(50);
        assert_eq!(parse_kdf(&cut), Err(KdfError::Tlv(ParseError::Truncated)));
        assert_eq!(
            parse_kdf(&[0xF9, 0x05, 0x81, 0x01]),
            Err(KdfError::Tlv(ParseError::Truncated))
        );
        // An off algorithm byte doesn't need the other fields.
        assert_eq!(parse_kdf(&with(0x81, &[0x00])), Ok(Kdf::Off));
    }

    #[test]
    fn errors_read_as_short_phrases() {
        assert_eq!(KdfError::UnknownAlgorithm(5).to_string(), "algorithm 0x05");
        assert_eq!(KdfError::UnknownHash(9).to_string(), "hash 0x09");
        assert_eq!(KdfError::Count(0).to_string(), "iteration count 0");
        assert_eq!(
            KdfError::Tlv(ParseError::Truncated).to_string(),
            "malformed data"
        );
    }

    #[test]
    fn debug_never_shows_salts_or_hashes() {
        let kdf = parse_kdf(&spec_do()).unwrap();
        let shown = format!("{kdf:?}");
        assert!(
            shown.contains("Sha256") && shown.contains("100000"),
            "{shown}"
        );
        for secretish in ["01234567", "ABCDEFGH", "48, 49", "65, 66", "119, 55"] {
            assert!(!shown.contains(secretish), "{shown}");
        }
    }

    #[test]
    fn pin_roles() {
        assert_eq!(PinRole::User.min_len(), 6);
        assert_eq!(PinRole::Admin.min_len(), 8);
        assert_eq!(PinRole::ResetCode.min_len(), 8);
        assert_eq!(PinRole::Admin.label(), "admin PIN");
        assert_eq!(KdfHash::Sha512.label(), "SHA-512");
    }

    #[test]
    fn get_kdf_apdu() {
        assert_eq!(get_kdf(), vec![0x00, 0xCA, 0x00, 0xF9, 0x00]);
    }
}
