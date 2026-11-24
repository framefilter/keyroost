//! The `T2VLT` key blob: the vault, deflated and sealed with AES-256-GCM under
//! a key derived from the key's hmac-secret output.
//!
//! Layout: `"T2VLT" || version(1) || kdf_salt(16) || nonce(12) || ciphertext+tag`.
//! The 34-byte header is the AEAD associated data.

use crate::error::VaultError;
use crate::kdf::hkdf_sha256;
use crate::model::{from_json, to_json, Vault};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 5] = b"T2VLT";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 34;
const TAG_LEN: usize = 16;
const KDF_INFO: &[u8] = b"Token2 fido2-vault v1 / AES-256-GCM";
const MAX_INFLATED: usize = 16 * 1024 * 1024;

/// Raw DEFLATE at level 9 (byte-identical to fidoparole's output).
pub(crate) fn deflate(b: &[u8]) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec(b, 9)
}

/// Raw inflate, refusing to produce more than 16 MiB.
pub(crate) fn inflate(b: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    match miniz_oxide::inflate::decompress_to_vec_with_limit(b, MAX_INFLATED) {
        Ok(v) => Ok(Zeroizing::new(v)),
        Err(mut e) => Err(inflate_error(&mut e)),
    }
}

/// Map a failed inflate to its error, wiping the partial output first: the
/// input passed the AEAD tag, so that output is decrypted vault JSON.
fn inflate_error(e: &mut miniz_oxide::inflate::DecompressError) -> VaultError {
    e.output.zeroize();
    if e.status == miniz_oxide::inflate::TINFLStatus::HasMoreOutput {
        VaultError::TooLarge
    } else {
        VaultError::Corrupt("decompression failed")
    }
}

fn derive_key(hmac_secret: &[u8; 32], salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut k = Zeroizing::new([0u8; 32]);
    hkdf_sha256(hmac_secret, salt, KDF_INFO, &mut k[..]);
    k
}

/// AES-256-GCM seal with `aad`; shared with the backup format.
pub(crate) fn aead_seal(
    key: &[u8; 32],
    nonce: [u8; 12],
    aad: &[u8],
    plain: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| VaultError::Decrypt)?;
    cipher
        .encrypt(&Nonce::from(nonce), Payload { msg: plain, aad })
        .map_err(|_| VaultError::Decrypt)
}

/// AES-256-GCM open with `aad`; shared with the backup format.
pub(crate) fn aead_open(
    key: &[u8; 32],
    nonce: [u8; 12],
    aad: &[u8],
    ct: &[u8],
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| VaultError::Decrypt)?;
    cipher
        .decrypt(&Nonce::from(nonce), Payload { msg: ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| VaultError::Decrypt)
}

pub(crate) fn seal_with(
    v: &Vault,
    hmac_secret: &[u8; 32],
    salt: [u8; 16],
    nonce: [u8; 12],
) -> Result<Vec<u8>, VaultError> {
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);
    let key = derive_key(hmac_secret, &salt);
    let plain = Zeroizing::new(deflate(&to_json(v)));
    let ct = aead_seal(&key, nonce, &header, &plain)?;
    header.extend_from_slice(&ct);
    Ok(header)
}

/// Encrypt the vault for the key with fresh random salt and nonce.
pub fn seal(v: &Vault, hmac_secret: &[u8; 32]) -> Result<Vec<u8>, VaultError> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut salt).map_err(|_| VaultError::Random)?;
    getrandom::fill(&mut nonce).map_err(|_| VaultError::Random)?;
    seal_with(v, hmac_secret, salt, nonce)
}

/// Decrypt a blob read from the key.
pub fn open(blob: &[u8], hmac_secret: &[u8; 32]) -> Result<Vault, VaultError> {
    if blob.len() < HEADER_LEN + TAG_LEN || &blob[..5] != MAGIC {
        return Err(VaultError::NotAVault);
    }
    if blob[5] != VERSION {
        return Err(VaultError::UnsupportedVersion(blob[5]));
    }
    let (header, ct) = blob.split_at(HEADER_LEN);
    let nonce: [u8; 12] = header[22..34]
        .try_into()
        .map_err(|_| VaultError::NotAVault)?;
    let key = derive_key(hmac_secret, &header[6..22]);
    let plain = aead_open(&key, nonce, header, ct)?;
    from_json(&inflate(&plain)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_vectors::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    fn sample() -> Vault {
        from_json(SAMPLE_JSON_V2.as_bytes()).unwrap()
    }

    #[test]
    fn opens_fidoparole_vector() {
        let v = open(&unhex(SEALED_BLOB_HEX), &HMAC_SECRET).unwrap();
        assert_eq!(v, sample());
    }

    #[test]
    fn seal_matches_fidoparole_vector() {
        let b = seal_with(&sample(), &HMAC_SECRET, BLOB_SALT, BLOB_NONCE).unwrap();
        assert_eq!(b, unhex(SEALED_BLOB_HEX));
    }

    #[test]
    fn deflate_matches_fidoparole_vector() {
        assert_eq!(
            deflate(SAMPLE_JSON_V2.as_bytes()),
            unhex(SAMPLE_COMPRESSED_HEX)
        );
        let back = inflate(&unhex(SAMPLE_COMPRESSED_HEX)).unwrap();
        assert_eq!(&back[..], SAMPLE_JSON_V2.as_bytes());
    }

    #[test]
    fn inflate_caps_and_rejects() {
        let big = deflate(&vec![0u8; MAX_INFLATED + 1]);
        assert_eq!(inflate(&big).unwrap_err(), VaultError::TooLarge);
        let ok = deflate(&vec![0u8; MAX_INFLATED]);
        assert_eq!(inflate(&ok).unwrap().len(), MAX_INFLATED);
        assert_eq!(
            inflate(&[0xff, 0xff, 0xff]).unwrap_err(),
            VaultError::Corrupt("decompression failed")
        );
    }

    #[test]
    fn inflate_error_wipes_the_partial_output() {
        let big = deflate(&vec![b'x'; MAX_INFLATED + 1]);
        let mut e =
            miniz_oxide::inflate::decompress_to_vec_with_limit(&big, MAX_INFLATED).unwrap_err();
        assert!(
            !e.output.is_empty(),
            "the fixture must carry partial output"
        );
        assert_eq!(inflate_error(&mut e), VaultError::TooLarge);
        assert!(e.output.is_empty());
    }

    #[test]
    fn wrong_secret_is_decrypt_error() {
        let r = open(&unhex(SEALED_BLOB_HEX), &[0x12; 32]);
        assert_eq!(r.unwrap_err(), VaultError::Decrypt);
    }

    #[test]
    fn bad_magic_is_not_a_vault() {
        let mut b = unhex(SEALED_BLOB_HEX);
        b[0] = b'X';
        assert_eq!(open(&b, &HMAC_SECRET).unwrap_err(), VaultError::NotAVault);
    }

    #[test]
    fn version_2_unsupported() {
        let mut b = unhex(SEALED_BLOB_HEX);
        b[5] = 2;
        assert_eq!(
            open(&b, &HMAC_SECRET).unwrap_err(),
            VaultError::UnsupportedVersion(2)
        );
    }

    #[test]
    fn truncated_header_is_not_a_vault() {
        let b = unhex(SEALED_BLOB_HEX);
        for n in 0..50 {
            assert_eq!(
                open(&b[..n], &HMAC_SECRET).unwrap_err(),
                VaultError::NotAVault,
                "len {n}"
            );
        }
        // Any longer truncation must also fail without panicking.
        for n in 50..b.len() {
            assert!(open(&b[..n], &HMAC_SECRET).is_err(), "len {n}");
        }
    }

    #[test]
    fn tampered_byte_is_decrypt_error() {
        let good = unhex(SEALED_BLOB_HEX);
        for i in [6, 22, 34, 60, good.len() - 1] {
            let mut b = good.clone();
            b[i] ^= 1;
            assert_eq!(
                open(&b, &HMAC_SECRET).unwrap_err(),
                VaultError::Decrypt,
                "byte {i}"
            );
        }
    }

    #[test]
    fn fresh_salt_and_nonce_each_seal() {
        let a = seal(&sample(), &HMAC_SECRET).unwrap();
        let b = seal(&sample(), &HMAC_SECRET).unwrap();
        assert_ne!(a[6..34], b[6..34]);
        assert_ne!(a, b);
        assert_eq!(open(&a, &HMAC_SECRET).unwrap(), sample());
    }
}
