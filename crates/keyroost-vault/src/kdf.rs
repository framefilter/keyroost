//! HKDF-SHA256 (RFC 5869) built on `hmac` + `sha2`.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const HASH_LEN: usize = 32;

fn mac(key: &[u8]) -> HmacSha256 {
    // HMAC accepts keys of any length.
    <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC takes any key length")
}

/// HKDF-SHA256: extract with `salt` (32 zero bytes when empty), then expand
/// `info` into `out`. Panics only if `out.len() > 255 * 32`; callers use 32.
pub(crate) fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) {
    assert!(out.len() <= 255 * HASH_LEN, "HKDF output too long");
    let zero_salt = [0u8; HASH_LEN];
    let salt = if salt.is_empty() {
        &zero_salt[..]
    } else {
        salt
    };
    let mut extract = mac(salt);
    extract.update(ikm);
    let prk = extract.finalize().into_bytes();

    let mut prev: Vec<u8> = Vec::new();
    for (i, chunk) in out.chunks_mut(HASH_LEN).enumerate() {
        let mut m = mac(&prk);
        m.update(&prev);
        m.update(info);
        m.update(&[(i + 1) as u8]);
        prev = m.finalize().into_bytes().to_vec();
        chunk.copy_from_slice(&prev[..chunk.len()]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn rfc5869_case1() {
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0u8..=0x0c).collect();
        let info: Vec<u8> = (0xf0u8..=0xf9).collect();
        let mut out = [0u8; 42];
        hkdf_sha256(&ikm, &salt, &info, &mut out);
        assert_eq!(
            out.to_vec(),
            unhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
        );
    }

    #[test]
    fn rfc5869_case3() {
        let ikm = [0x0bu8; 22];
        let mut out = [0u8; 42];
        hkdf_sha256(&ikm, &[], &[], &mut out);
        assert_eq!(
            out.to_vec(),
            unhex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
        );
    }
}
