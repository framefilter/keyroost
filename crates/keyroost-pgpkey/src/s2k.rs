//! String-to-key derivation and secret-key protection (RFC 4880 sections
//! 3.7 and 5.5.3), in the form GnuPG reads and writes.

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use keyroost_proto::sha1::Sha1;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256, Sha384, Sha512};
use zeroize::Zeroizing;

use crate::packet::Reader;
use crate::Error;

type Result<T> = std::result::Result<T, Error>;

/// Count byte written for new keys: 16,777,216 octets hashed.
pub(crate) const WRITE_COUNT: u8 = 0xE0;

/// Symmetric ciphers for secret-key protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cipher {
    Aes128 = 7,
    Aes192 = 8,
    Aes256 = 9,
}

impl Cipher {
    pub(crate) fn key_len(self) -> usize {
        match self {
            Cipher::Aes128 => 16,
            Cipher::Aes192 => 24,
            Cipher::Aes256 => 32,
        }
    }

    fn from_id(id: u8) -> Result<Cipher> {
        match id {
            7 => Ok(Cipher::Aes128),
            8 => Ok(Cipher::Aes192),
            9 => Ok(Cipher::Aes256),
            _ => Err(Error::Unsupported("secret-key cipher")),
        }
    }
}

/// Hash algorithms: the S2K's, and the ones a [`Signer`](crate::sig::Signer)
/// is asked to sign a digest of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Hash {
    Sha1 = 2,
    Sha256 = 8,
    Sha384 = 9,
    Sha512 = 10,
}

impl Hash {
    fn from_id(id: u8) -> Result<Hash> {
        match id {
            2 => Ok(Hash::Sha1),
            8 => Ok(Hash::Sha256),
            9 => Ok(Hash::Sha384),
            10 => Ok(Hash::Sha512),
            _ => Err(Error::Unsupported("S2K hash")),
        }
    }
}

enum Hasher {
    Sha1(Sha1),
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

impl Hasher {
    fn new(h: Hash) -> Self {
        match h {
            Hash::Sha1 => Hasher::Sha1(Sha1::new()),
            Hash::Sha256 => Hasher::Sha256(Sha256::new()),
            Hash::Sha384 => Hasher::Sha384(Sha384::new()),
            Hash::Sha512 => Hasher::Sha512(Sha512::new()),
        }
    }
    fn update(&mut self, d: &[u8]) {
        match self {
            Hasher::Sha1(x) => x.update(d),
            Hasher::Sha256(x) => Digest::update(x, d),
            Hasher::Sha384(x) => Digest::update(x, d),
            Hasher::Sha512(x) => Digest::update(x, d),
        }
    }
    fn finish(self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(match self {
            Hasher::Sha1(x) => x.finalize().to_vec(),
            Hasher::Sha256(x) => x.finalize().to_vec(),
            Hasher::Sha384(x) => x.finalize().to_vec(),
            Hasher::Sha512(x) => x.finalize().to_vec(),
        })
    }
}

/// Octets hashed for a count byte (RFC 4880 section 3.7.1.3).
pub(crate) fn decode_count(c: u8) -> u32 {
    (16 + (c & 15) as u32) << ((c >> 4) + 6)
}

/// A string-to-key specifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Spec {
    Simple(Hash),
    Salted(Hash, [u8; 8]),
    Iterated(Hash, [u8; 8], u8),
}

impl Spec {
    pub(crate) fn write(&self, out: &mut Vec<u8>) {
        match *self {
            Spec::Simple(h) => out.extend_from_slice(&[0, h as u8]),
            Spec::Salted(h, salt) => {
                out.extend_from_slice(&[1, h as u8]);
                out.extend_from_slice(&salt);
            }
            Spec::Iterated(h, salt, c) => {
                out.extend_from_slice(&[3, h as u8]);
                out.extend_from_slice(&salt);
                out.push(c);
            }
        }
    }

    pub(crate) fn read(r: &mut Reader) -> Result<Spec> {
        let kind = r.u8()?;
        match kind {
            0 => Ok(Spec::Simple(Hash::from_id(r.u8()?)?)),
            1 => {
                let h = Hash::from_id(r.u8()?)?;
                Ok(Spec::Salted(h, salt(r)?))
            }
            3 => {
                let h = Hash::from_id(r.u8()?)?;
                let s = salt(r)?;
                // A count byte always decodes to at most decode_count(0xFF).
                Ok(Spec::Iterated(h, s, r.u8()?))
            }
            // GnuPG extension: hash id, "GNU", then the mode — 1 means the
            // secret was left out (gnu-dummy), 2 that it lives on a card.
            101 => {
                r.u8()?;
                if r.take(3)? != b"GNU" {
                    return Err(Error::Unsupported("S2K type"));
                }
                match r.u8()? {
                    1 => Err(Error::NoSecretPart),
                    2 => Err(Error::CardStubs),
                    _ => Err(Error::Unsupported("GnuPG S2K extension")),
                }
            }
            _ => Err(Error::Unsupported("S2K type")),
        }
    }

    /// Derive `key_len` bytes from a passphrase.
    pub(crate) fn derive(&self, pass: &[u8], key_len: usize) -> Zeroizing<Vec<u8>> {
        let (hash, salt, total): (Hash, &[u8], usize) = match self {
            Spec::Simple(h) => (*h, &[], pass.len()),
            Spec::Salted(h, s) => (*h, &s[..], 8 + pass.len()),
            Spec::Iterated(h, s, c) => {
                (*h, &s[..], (decode_count(*c) as usize).max(8 + pass.len()))
            }
        };
        let mut unit = Zeroizing::new(Vec::with_capacity(salt.len() + pass.len()));
        unit.extend_from_slice(salt);
        unit.extend_from_slice(pass);
        let mut key = Zeroizing::new(Vec::with_capacity(key_len + 64));
        let mut preload = 0usize;
        while key.len() < key_len {
            let mut h = Hasher::new(hash);
            h.update(&vec![0u8; preload]);
            let mut left = total;
            while left > 0 && !unit.is_empty() {
                let n = left.min(unit.len());
                h.update(&unit[..n]);
                left -= n;
            }
            key.extend_from_slice(&h.finish());
            preload += 1;
        }
        key.truncate(key_len);
        key
    }
}

fn salt(r: &mut Reader) -> Result<[u8; 8]> {
    let mut s = [0u8; 8];
    s.copy_from_slice(r.take(8)?);
    Ok(s)
}

/// One AES block cipher with its key schedule, for [`cfb`].
enum Block {
    Aes128(Aes128),
    Aes192(Aes192),
    Aes256(Aes256),
}

impl Block {
    fn new(cipher: Cipher, key: &[u8]) -> Result<Block> {
        let bad = |_| Error::Crypto("wrong key length for the cipher".into());
        Ok(match cipher {
            Cipher::Aes128 => Block::Aes128(Aes128::new_from_slice(key).map_err(bad)?),
            Cipher::Aes192 => Block::Aes192(Aes192::new_from_slice(key).map_err(bad)?),
            Cipher::Aes256 => Block::Aes256(Aes256::new_from_slice(key).map_err(bad)?),
        })
    }

    fn encrypt(&self, block: &mut [u8; 16]) {
        let b = aes::Block::from_mut_slice(block);
        match self {
            Block::Aes128(c) => c.encrypt_block(b),
            Block::Aes192(c) => c.encrypt_block(b),
            Block::Aes256(c) => c.encrypt_block(b),
        }
    }
}

/// Plain CFB-128 (no resync). `key` must be `cipher.key_len()` bytes and
/// `iv` one 16-byte block; anything else is an error, not a panic.
fn cfb(cipher: Cipher, key: &[u8], iv: &[u8], data: &[u8], decrypt: bool) -> Result<Vec<u8>> {
    let block = Block::new(cipher, key)?;
    let mut fb: [u8; 16] = iv
        .try_into()
        .map_err(|_| Error::Crypto("the IV is not one 16-byte block".into()))?;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let mut ks = fb;
        block.encrypt(&mut ks);
        let start = out.len();
        out.extend(chunk.iter().zip(ks.iter()).map(|(a, b)| a ^ b));
        let ct = if decrypt { chunk } else { &out[start..] };
        fb = [0u8; 16];
        fb[..ct.len()].copy_from_slice(ct);
    }
    Ok(out)
}

/// Plain CFB-128 encryption (no resync).
pub(crate) fn cfb_encrypt(cipher: Cipher, key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    cfb(cipher, key, iv, data, false)
}

/// Plain CFB-128 decryption (no resync).
pub(crate) fn cfb_decrypt(cipher: Cipher, key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    cfb(cipher, key, iv, data, true)
}

fn sum16(d: &[u8]) -> u16 {
    d.iter().fold(0u16, |a, &b| a.wrapping_add(b as u16))
}

/// Protect plaintext secret MPIs for a secret-key packet: returns the bytes
/// after the public part (usage 254, AES-256, iterated SHA-256, SHA-1 check).
pub(crate) fn protect(secret_mpis: &[u8], pass: &[u8]) -> Result<Vec<u8>> {
    let mut salt = [0u8; 8];
    OsRng.fill_bytes(&mut salt);
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);
    let spec = Spec::Iterated(Hash::Sha256, salt, WRITE_COUNT);
    let key = spec.derive(pass, Cipher::Aes256.key_len());
    let mut plain = Zeroizing::new(Vec::with_capacity(secret_mpis.len() + 20));
    plain.extend_from_slice(secret_mpis);
    plain.extend_from_slice(&keyroost_proto::sha1::sha1(secret_mpis));
    let ct = cfb_encrypt(Cipher::Aes256, &key, &iv, &plain)?;
    let mut out = vec![254, Cipher::Aes256 as u8];
    spec.write(&mut out);
    out.extend_from_slice(&iv);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Read the protection fields following a secret key's public part and
/// return the plaintext secret MPIs, checking the integrity value.
pub(crate) fn unprotect(r: &mut Reader, pass: Option<&[u8]>) -> Result<Zeroizing<Vec<u8>>> {
    let usage = r.u8()?;
    match usage {
        0 => {
            let rest = r.rest()?;
            split_sum(rest).map(|d| Zeroizing::new(d.to_vec()))
        }
        253 => Err(Error::Unsupported("AEAD-protected keys")),
        254 | 255 => {
            let cipher_id = r.u8()?;
            let spec = Spec::read(r)?;
            let cipher = Cipher::from_id(cipher_id)?;
            let pass = pass.ok_or(Error::NeedsPassphrase)?;
            let iv = r.take(16)?;
            let ct = r.rest()?;
            let key = spec.derive(pass, cipher.key_len());
            let plain = Zeroizing::new(cfb_decrypt(cipher, &key, iv, ct)?);
            if usage == 254 {
                let split = plain.len().checked_sub(20).ok_or(Error::Truncated)?;
                let (data, mac) = plain.split_at(split);
                if keyroost_proto::sha1::sha1(data)[..] != *mac {
                    return Err(Error::WrongPassphrase);
                }
                Ok(Zeroizing::new(data.to_vec()))
            } else {
                match split_sum(&plain) {
                    Ok(d) => Ok(Zeroizing::new(d.to_vec())),
                    Err(Error::BadChecksum) => Err(Error::WrongPassphrase),
                    Err(e) => Err(e),
                }
            }
        }
        // A cipher id used directly as usage (legacy, MD5 S2K).
        _ => Err(Error::Unsupported("legacy secret-key protection")),
    }
}

fn split_sum(d: &[u8]) -> Result<&[u8]> {
    let split = d.len().checked_sub(2).ok_or(Error::Truncated)?;
    let (data, sum) = d.split_at(split);
    if sum16(data).to_be_bytes() != *sum {
        return Err(Error::BadChecksum);
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Reader;
    use crate::Error;
    use sha2::{Digest, Sha256};

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }
    fn sha256(d: &[u8]) -> Vec<u8> {
        Sha256::digest(d).to_vec()
    }

    #[test]
    fn count_decoding_matches_rfc4880() {
        assert_eq!(decode_count(0x00), 1024);
        assert_eq!(decode_count(0x60), 65536);
        assert_eq!(decode_count(0xE0), 16_777_216);
        assert_eq!(decode_count(0xFF), 65_011_712);
    }
    #[test]
    fn cfb128_aes128_nist_sp800_38a_f_3_13() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex("000102030405060708090a0b0c0d0e0f");
        let pt = hex("6bc1bee22e409f96e93d7e117393172a");
        assert_eq!(
            cfb_encrypt(Cipher::Aes128, &key, &iv, &pt).unwrap(),
            hex("3b3fd92eb72dad20333449f8e83cfb4a")
        );
        assert_eq!(
            cfb_decrypt(
                Cipher::Aes128,
                &key,
                &iv,
                &hex("3b3fd92eb72dad20333449f8e83cfb4a")
            )
            .unwrap(),
            pt
        );
    }

    #[test]
    fn cfb_refuses_a_wrong_key_or_iv_length() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        assert!(matches!(
            cfb_encrypt(Cipher::Aes256, &key, &iv, b"x"),
            Err(Error::Crypto(_))
        ));
        assert!(matches!(
            cfb_decrypt(Cipher::Aes128, &key, &iv[..8], b"x"),
            Err(Error::Crypto(_))
        ));
        assert!(cfb_decrypt(Cipher::Aes128, &key, &iv, b"x").is_ok());
    }
    #[test]
    fn iterated_s2k_hashes_count_octets_of_salt_then_pass() {
        // 0x00 means 1024 octets: the repeated salt||pass, cut at the count.
        let s = Spec::Iterated(Hash::Sha256, *b"saltsalt", 0x00);
        let mut buf = b"saltsaltpw".repeat(103);
        buf.truncate(1024);
        assert_eq!(&s.derive(b"pw", 32)[..], &sha256(&buf)[..]);
        // Count smaller than salt+pass: the whole salt||pass is hashed once.
        let long = vec![b'p'; 2000];
        let mut once = b"saltsalt".to_vec();
        once.extend_from_slice(&long);
        assert_eq!(&s.derive(&long, 32)[..], &sha256(&once)[..]);
        // Longer key than the hash: second context is preloaded with a zero.
        let s = Spec::Salted(Hash::Sha256, *b"saltsalt");
        let k = s.derive(b"pw", 40);
        assert_eq!(&k[..32], &sha256(b"saltsaltpw")[..]);
        assert_eq!(&k[32..], &sha256(b"\0saltsaltpw")[..8]);
    }
    #[test]
    fn protect_unprotect_round_trip_and_wrong_pass() {
        let secret = vec![0x00, 0x08, 0x42];
        let blob = protect(&secret, b"correct horse").unwrap();
        let mut r = Reader::new(&blob);
        assert_eq!(
            &unprotect(&mut r, Some(b"correct horse")).unwrap()[..],
            &secret[..]
        );
        let mut r = Reader::new(&blob);
        assert!(matches!(
            unprotect(&mut r, Some(b"nope")),
            Err(Error::WrongPassphrase)
        ));
        let mut r = Reader::new(&blob);
        assert!(matches!(
            unprotect(&mut r, None),
            Err(Error::NeedsPassphrase)
        ));
    }
    #[test]
    fn gnu_dummy_stub_is_reported_as_card_stubs() {
        let blob = [254u8, 0, 101, 0, b'G', b'N', b'U', 2];
        assert!(matches!(
            unprotect(&mut Reader::new(&blob), Some(b"x")),
            Err(Error::CardStubs)
        ));
    }
    #[test]
    fn gnu_dummy_without_a_card_is_a_missing_secret() {
        let blob = [254u8, 0, 101, 0, b'G', b'N', b'U', 1];
        assert!(matches!(
            unprotect(&mut Reader::new(&blob), Some(b"x")),
            Err(Error::NoSecretPart)
        ));
        let odd = [254u8, 0, 101, 0, b'G', b'N', b'U', 7];
        assert!(matches!(
            unprotect(&mut Reader::new(&odd), Some(b"x")),
            Err(Error::Unsupported(_))
        ));
    }
    #[test]
    fn plain_usage_zero_and_garbage() {
        let mut blob = vec![0u8, 0x00, 0x08, 0x42];
        let sum = (8u16 + 0x42).to_be_bytes();
        blob.extend_from_slice(&sum);
        let got = unprotect(&mut Reader::new(&blob), None).unwrap();
        assert_eq!(&got[..], &[0x00, 0x08, 0x42]);
        for n in 0..40u8 {
            let junk: Vec<u8> = (0..n).map(|i| i.wrapping_mul(37) ^ 0xFE).collect();
            let _ = unprotect(&mut Reader::new(&junk), Some(b"x"));
            let _ = Spec::read(&mut Reader::new(&junk));
        }
        assert!(matches!(
            unprotect(&mut Reader::new(&[253u8, 9, 3]), Some(b"x")),
            Err(Error::Unsupported(_))
        ));
        assert!(matches!(
            unprotect(&mut Reader::new(&[7u8, 1, 2, 3]), Some(b"x")),
            Err(Error::Unsupported(_))
        ));
    }
}
