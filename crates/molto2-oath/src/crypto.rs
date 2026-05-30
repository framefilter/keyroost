//! Minimal HMAC-SHA1 and PBKDF2-HMAC-SHA1, built on the in-tree SHA-1.
//!
//! The OATH password handshake (`SET_CODE` / `VALIDATE`) derives a 16-byte
//! access key as `PBKDF2-HMAC-SHA1(password, salt = device id, 1000, 16)` and
//! answers an 8-byte challenge with `HMAC-SHA1(key, challenge)` (Yubico OATH).
//! Per the repo's "vendor over depend" rule we build these two primitives on
//! `molto2_proto::sha1` rather than pulling in `hmac` / `pbkdf2` crates — they're
//! small, and locked down by RFC 2202 / RFC 6070 known-answer tests.

use molto2_proto::sha1::sha1;

const BLOCK: usize = 64;
const OUT: usize = 20;

/// HMAC-SHA1 of `data` under `key` (RFC 2104).
#[must_use]
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; OUT] {
    // Keys longer than the block size are first hashed down.
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..OUT].copy_from_slice(&sha1(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }

    let mut inner = Vec::with_capacity(BLOCK + data.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(data);
    let inner_hash = sha1(&inner);

    let mut outer = Vec::with_capacity(BLOCK + OUT);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    sha1(&outer)
}

/// PBKDF2-HMAC-SHA1 (RFC 2898) producing `dk_len` bytes.
///
/// Generic over output length so the same code serves the OATH 16-byte access
/// key and the RFC 6070 20-byte test vectors.
#[must_use]
pub fn pbkdf2_hmac_sha1(password: &[u8], salt: &[u8], iterations: u32, dk_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(dk_len);
    let mut block_index: u32 = 1;
    while out.len() < dk_len {
        // U1 = PRF(password, salt || INT_BE(block_index))
        let mut salted = Vec::with_capacity(salt.len() + 4);
        salted.extend_from_slice(salt);
        salted.extend_from_slice(&block_index.to_be_bytes());
        let mut u = hmac_sha1(password, &salted);
        let mut t = u;
        // T = U1 ^ U2 ^ ... ^ Uc
        for _ in 1..iterations {
            u = hmac_sha1(password, &u);
            for (t_b, u_b) in t.iter_mut().zip(u.iter()) {
                *t_b ^= *u_b;
            }
        }
        out.extend_from_slice(&t);
        block_index += 1;
    }
    out.truncate(dk_len);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn hmac_sha1_rfc2202() {
        // Case 1: key = 0x0b*20, data = "Hi There".
        assert_eq!(
            hex(&hmac_sha1(&[0x0b; 20], b"Hi There")),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        );
        // Case 2: key = "Jefe", data = "what do ya want for nothing?".
        assert_eq!(
            hex(&hmac_sha1(b"Jefe", b"what do ya want for nothing?")),
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
        );
    }

    #[test]
    fn hmac_sha1_long_key_is_hashed() {
        // Key longer than the 64-byte block must be pre-hashed; compare to the
        // independently-computed value (RFC 2202 case 5 uses key = 0xaa*80).
        let key = [0xaa; 80];
        assert_eq!(
            hex(&hmac_sha1(&key, b"Test Using Larger Than Block-Size Key - Hash Key First")),
            "aa4ae5e15272d00e95705637ce8a3b55ed402112"
        );
    }

    #[test]
    fn pbkdf2_rfc6070() {
        assert_eq!(
            hex(&pbkdf2_hmac_sha1(b"password", b"salt", 1, 20)),
            "0c60c80f961f0e71f3a9b524af6012062fe037a6"
        );
        assert_eq!(
            hex(&pbkdf2_hmac_sha1(b"password", b"salt", 2, 20)),
            "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"
        );
        assert_eq!(
            hex(&pbkdf2_hmac_sha1(b"password", b"salt", 4096, 20)),
            "4b007901b765489abead49d926f721d065a429c1"
        );
    }
}
