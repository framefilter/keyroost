//! The `T2VBK` backup file: the vault, deflated and sealed with AES-256-GCM
//! under a key stretched from a passphrase with Argon2id.
//!
//! Layout: `"T2VBK" || version(1) || m_kib u32 LE || t u32 LE || p u32 LE ||
//! salt(16) || nonce(12) || ciphertext+tag`. The 46-byte header is the AEAD
//! associated data.

use crate::blob::{aead_open, aead_seal, deflate, inflate};
use crate::error::VaultError;
use crate::model::{from_json, to_json, Vault};
use zeroize::Zeroizing;

const MAGIC: &[u8; 5] = b"T2VBK";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 46;
const TAG_LEN: usize = 16;
const MIN_PASSPHRASE_CHARS: usize = 10;

/// Upper bounds on what a file may ask of us, so a crafted backup cannot
/// demand absurd memory or time. Lower under fuzzing to keep runs fast.
const MAX_M_KIB: u32 = if cfg!(fuzzing) { 64 } else { 256 * 1024 };
const MAX_T: u32 = if cfg!(fuzzing) { 2 } else { 16 };
const MAX_P: u32 = if cfg!(fuzzing) { 1 } else { 8 };

/// Argon2id cost settings (memory in KiB, passes, lanes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

/// 64 MiB, 3 passes: a deliberate fraction of a second per guess.
pub const BACKUP_KDF: KdfParams = KdfParams {
    m_kib: 65536,
    t: 3,
    p: 1,
};

/// Stretch the passphrase into a 32-byte key. The bounds are checked before
/// any hashing; Argon2's own minimums are enforced by `Params::new`.
fn argon2_key(pass: &str, salt: &[u8], p: &KdfParams) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    if p.m_kib > MAX_M_KIB || p.t > MAX_T || p.p > MAX_P {
        return Err(VaultError::KdfParams);
    }
    let params =
        argon2::Params::new(p.m_kib, p.t, p.p, Some(32)).map_err(|_| VaultError::KdfParams)?;
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut k = Zeroizing::new([0u8; 32]);
    a.hash_password_into(pass.as_bytes(), salt, &mut k[..])
        .map_err(|_| VaultError::KdfParams)?;
    Ok(k)
}

/// Encrypt the vault under a passphrase with fresh salt and nonce.
pub fn export_backup(v: &Vault, passphrase: &str) -> Result<Vec<u8>, VaultError> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut salt).map_err(|_| VaultError::Random)?;
    getrandom::fill(&mut nonce).map_err(|_| VaultError::Random)?;
    export_backup_with(v, passphrase, &BACKUP_KDF, salt, nonce)
}

/// Decrypt a backup file.
pub fn import_backup(bytes: &[u8], passphrase: &str) -> Result<Vault, VaultError> {
    if bytes.len() < HEADER_LEN + TAG_LEN || &bytes[..5] != MAGIC {
        return Err(VaultError::NotABackup);
    }
    if bytes[5] != VERSION {
        return Err(VaultError::UnsupportedVersion(bytes[5]));
    }
    let word = |o: usize| -> Result<u32, VaultError> {
        let b: [u8; 4] = bytes[o..o + 4]
            .try_into()
            .map_err(|_| VaultError::NotABackup)?;
        Ok(u32::from_le_bytes(b))
    };
    let params = KdfParams {
        m_kib: word(6)?,
        t: word(10)?,
        p: word(14)?,
    };
    let nonce: [u8; 12] = bytes[34..46]
        .try_into()
        .map_err(|_| VaultError::NotABackup)?;
    let (header, ct) = bytes.split_at(HEADER_LEN);
    let key = argon2_key(passphrase, &header[18..34], &params)?;
    let plain = aead_open(&key, nonce, header, ct)?;
    from_json(&inflate(&plain)?)
}

/// The rule a new backup's passphrase must meet: at least 10 characters
/// (Unicode scalar values, not bytes). [`export_backup`] applies it; a front
/// end can check it before the key is used.
pub fn check_passphrase(pass: &str) -> Result<(), VaultError> {
    if pass.chars().count() < MIN_PASSPHRASE_CHARS {
        return Err(VaultError::ShortPassphrase);
    }
    Ok(())
}

pub(crate) fn export_backup_with(
    v: &Vault,
    pass: &str,
    p: &KdfParams,
    salt: [u8; 16],
    nonce: [u8; 12],
) -> Result<Vec<u8>, VaultError> {
    check_passphrase(pass)?;
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.extend_from_slice(&p.m_kib.to_le_bytes());
    header.extend_from_slice(&p.t.to_le_bytes());
    header.extend_from_slice(&p.p.to_le_bytes());
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);
    let key = argon2_key(pass, &salt, p)?;
    let plain = Zeroizing::new(deflate(&to_json(v)));
    let ct = aead_seal(&key, nonce, &header, &plain)?;
    header.extend_from_slice(&ct);
    Ok(header)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::from_json;
    use crate::test_vectors::*;
    use std::time::Instant;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }
    fn sample() -> Vault {
        from_json(SAMPLE_JSON_V2.as_bytes()).unwrap()
    }
    const P: KdfParams = KdfParams {
        m_kib: BACKUP_PARAMS.0,
        t: BACKUP_PARAMS.1,
        p: BACKUP_PARAMS.2,
    };

    #[test]
    fn opens_fidoparole_backup_vector() {
        let v = import_backup(&unhex(BACKUP_HEX), BACKUP_PASS).unwrap();
        assert_eq!(v, sample());
    }

    #[test]
    fn export_matches_vector() {
        let b = export_backup_with(&sample(), BACKUP_PASS, &P, BACKUP_SALT, BACKUP_NONCE).unwrap();
        assert_eq!(b, unhex(BACKUP_HEX));
    }

    #[test]
    fn wrong_passphrase_is_decrypt_error() {
        let r = import_backup(&unhex(BACKUP_HEX), "wrong horse battery");
        assert_eq!(r.unwrap_err(), VaultError::Decrypt);
    }

    #[test]
    fn check_passphrase_matches_export_rule() {
        assert_eq!(
            check_passphrase("123456789").unwrap_err(),
            VaultError::ShortPassphrase
        );
        assert_eq!(check_passphrase("1234567890"), Ok(()));
        // Characters, not bytes, as the export counts them.
        assert_eq!(check_passphrase("ééééé"), Err(VaultError::ShortPassphrase));
        assert_eq!(check_passphrase("ééééééééél"), Ok(()));
    }

    #[test]
    fn short_passphrase_refused_on_export_only() {
        assert_eq!(
            export_backup(&sample(), "123456789").unwrap_err(),
            VaultError::ShortPassphrase
        );
        // Ten scalar values count, even when they are multi-byte.
        let ten = "ééééééééél";
        assert_eq!(ten.chars().count(), 10);
        assert!(export_backup_with(&sample(), ten, &P, BACKUP_SALT, BACKUP_NONCE).is_ok());
        assert!(export_backup_with(&sample(), "123456789", &P, BACKUP_SALT, BACKUP_NONCE).is_err());
    }

    fn with_params(m: u32, t: u32, p: u32) -> Vec<u8> {
        let mut b = unhex(BACKUP_HEX);
        b[6..10].copy_from_slice(&m.to_le_bytes());
        b[10..14].copy_from_slice(&t.to_le_bytes());
        b[14..18].copy_from_slice(&p.to_le_bytes());
        b
    }

    #[test]
    fn refuses_unreasonable_kdf_params() {
        let start = Instant::now();
        for (m, t, p) in [
            (262_145, 1, 1),
            (u32::MAX, 1, 1),
            (8, 17, 1),
            (8, 1, 9),
            (0, 1, 1),
            (8, 0, 1),
            (8, 1, 0),
            (1, 1, 1),
        ] {
            assert_eq!(
                import_backup(&with_params(m, t, p), BACKUP_PASS).unwrap_err(),
                VaultError::KdfParams,
                "{m} {t} {p}"
            );
        }
        assert!(start.elapsed().as_millis() < 1000);
    }

    #[test]
    fn bad_magic_short_and_version() {
        let good = unhex(BACKUP_HEX);
        let mut b = good.clone();
        b[0] = b'X';
        assert_eq!(
            import_backup(&b, BACKUP_PASS).unwrap_err(),
            VaultError::NotABackup
        );
        for n in 0..62 {
            assert_eq!(
                import_backup(&good[..n], BACKUP_PASS).unwrap_err(),
                VaultError::NotABackup,
                "len {n}"
            );
        }
        let mut b = good;
        b[5] = 2;
        assert_eq!(
            import_backup(&b, BACKUP_PASS).unwrap_err(),
            VaultError::UnsupportedVersion(2)
        );
    }

    #[test]
    fn tampered_header_or_body_is_decrypt_error() {
        let good = unhex(BACKUP_HEX);
        // A within-bounds parameter change (t 1 -> 2) is still refused: the
        // parameters are part of the AAD and change the derived key.
        assert_eq!(
            import_backup(&with_params(8, 2, 1), BACKUP_PASS).unwrap_err(),
            VaultError::Decrypt
        );
        // Salt, nonce, body and tag flips fail the tag.
        for i in [18, 34, 46, 60, good.len() - 1] {
            let mut b = good.clone();
            b[i] ^= 1;
            assert_eq!(
                import_backup(&b, BACKUP_PASS).unwrap_err(),
                VaultError::Decrypt,
                "byte {i}"
            );
        }
        for n in 62..good.len() {
            assert!(import_backup(&good[..n], BACKUP_PASS).is_err(), "len {n}");
        }
    }

    #[test]
    fn default_params_roundtrip() {
        let start = Instant::now();
        let b = export_backup(&sample(), BACKUP_PASS).unwrap();
        assert_eq!(&b[..5], b"T2VBK");
        assert_eq!(b[6..10], 65536u32.to_le_bytes());
        assert_eq!(import_backup(&b, BACKUP_PASS).unwrap(), sample());
        eprintln!("default_params_roundtrip took {:?}", start.elapsed());
    }
}
