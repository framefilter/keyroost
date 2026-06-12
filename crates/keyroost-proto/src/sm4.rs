//! SM4 block cipher (GB/T 32907-2016).
//!
//! 128-bit block, 128-bit key, 32 rounds. Pure Rust, no_std friendly.
//! Verified against the standard test vector in the unit tests below.

const BLOCK_SIZE: usize = 16;

const SBOX: [u8; 256] = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
];

const FK: [u32; 4] = [0xa3b1_bac6, 0x56aa_3350, 0x677d_9197, 0xb270_22dc];

// CK[i,j] = ((4*i + j) * 7) mod 256, packed as a big-endian u32 per i.
// Computed at compile time so we can never typo a single byte.
const CK: [u32; 32] = {
    let mut ck = [0u32; 32];
    let mut i = 0;
    while i < 32 {
        let b0 = (((4 * i) * 7) & 0xff) as u32;
        let b1 = (((4 * i + 1) * 7) & 0xff) as u32;
        let b2 = (((4 * i + 2) * 7) & 0xff) as u32;
        let b3 = (((4 * i + 3) * 7) & 0xff) as u32;
        ck[i] = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
        i += 1;
    }
    ck
};

#[inline]
fn tau(a: u32) -> u32 {
    let b0 = SBOX[((a >> 24) & 0xff) as usize] as u32;
    let b1 = SBOX[((a >> 16) & 0xff) as usize] as u32;
    let b2 = SBOX[((a >> 8) & 0xff) as usize] as u32;
    let b3 = SBOX[(a & 0xff) as usize] as u32;
    (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
}

#[inline]
fn l_round(b: u32) -> u32 {
    b ^ b.rotate_left(2) ^ b.rotate_left(10) ^ b.rotate_left(18) ^ b.rotate_left(24)
}

#[inline]
fn l_key(b: u32) -> u32 {
    b ^ b.rotate_left(13) ^ b.rotate_left(23)
}

#[inline]
fn t_round(x: u32) -> u32 {
    l_round(tau(x))
}

#[inline]
fn t_key(x: u32) -> u32 {
    l_key(tau(x))
}

/// SM4 round keys, derived once from a 16-byte key.
#[derive(Clone)]
pub struct Sm4 {
    rk: [u32; 32],
}

// The expanded schedule is key-equivalent material (the customer key protects
// seed confidentiality on the wire); scrub it on drop. Best-effort without
// `unsafe` (forbidden workspace-wide) or a `zeroize` dependency (this crate is
// deliberately dependency-free): `black_box` keeps the store from being
// optimized away in practice.
impl Drop for Sm4 {
    fn drop(&mut self) {
        self.rk = [0u32; 32];
        std::hint::black_box(&self.rk);
    }
}

impl Sm4 {
    pub fn new(key: &[u8; BLOCK_SIZE]) -> Self {
        let mut k = [0u32; 36];
        for i in 0..4 {
            k[i] = u32::from_be_bytes(key[i * 4..i * 4 + 4].try_into().unwrap()) ^ FK[i];
        }
        for i in 0..32 {
            k[i + 4] = k[i] ^ t_key(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i]);
        }
        let mut rk = [0u32; 32];
        rk.copy_from_slice(&k[4..36]);
        // The scratch schedule holds key-equivalent material; wipe it before
        // the stack frame is reused (best-effort — see `Drop` below).
        k = [0u32; 36];
        std::hint::black_box(&k);
        Self { rk }
    }

    pub fn encrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
        let mut x = [0u32; 36];
        for i in 0..4 {
            x[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 0..32 {
            x[i + 4] = x[i] ^ t_round(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ self.rk[i]);
        }
        for i in 0..4 {
            block[i * 4..i * 4 + 4].copy_from_slice(&x[35 - i].to_be_bytes());
        }
    }

    pub fn decrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
        let mut x = [0u32; 36];
        for i in 0..4 {
            x[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 0..32 {
            x[i + 4] = x[i] ^ t_round(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ self.rk[31 - i]);
        }
        for i in 0..4 {
            block[i * 4..i * 4 + 4].copy_from_slice(&x[35 - i].to_be_bytes());
        }
    }

    /// SM4-ECB on whole blocks. Caller is responsible for padding.
    pub fn encrypt_ecb(&self, data: &mut [u8]) {
        assert!(
            data.len() % BLOCK_SIZE == 0,
            "ECB requires block-aligned input"
        );
        for chunk in data.chunks_exact_mut(BLOCK_SIZE) {
            let block: &mut [u8; BLOCK_SIZE] = chunk.try_into().unwrap();
            self.encrypt_block(block);
        }
    }

    /// SM4-CBC encrypt with caller-supplied IV. Whole blocks only.
    pub fn encrypt_cbc(&self, iv: &[u8; BLOCK_SIZE], data: &mut [u8]) {
        assert!(
            data.len() % BLOCK_SIZE == 0,
            "CBC requires block-aligned input"
        );
        let mut prev = *iv;
        for chunk in data.chunks_exact_mut(BLOCK_SIZE) {
            for i in 0..BLOCK_SIZE {
                chunk[i] ^= prev[i];
            }
            let block: &mut [u8; BLOCK_SIZE] = chunk.try_into().unwrap();
            self.encrypt_block(block);
            prev.copy_from_slice(chunk);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// GB/T 32907-2016 standard test vector.
    /// Key and plaintext both = 0123456789abcdeffedcba9876543210
    /// Ciphertext after one encryption: 681edf34d206965e86b3e94f536e4246
    #[test]
    fn standard_vector_one_round() {
        let key: [u8; 16] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let mut block = key;
        let cipher = Sm4::new(&key);
        cipher.encrypt_block(&mut block);
        assert_eq!(
            block,
            [
                0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e,
                0x42, 0x46,
            ]
        );
    }

    /// Same vector encrypted 1,000,000 times = 595298c7c6fd271f0402f804c33d3f66.
    #[test]
    fn standard_vector_one_million_rounds() {
        let key: [u8; 16] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let mut block = key;
        let cipher = Sm4::new(&key);
        for _ in 0..1_000_000 {
            cipher.encrypt_block(&mut block);
        }
        assert_eq!(
            block,
            [
                0x59, 0x52, 0x98, 0xc7, 0xc6, 0xfd, 0x27, 0x1f, 0x04, 0x02, 0xf8, 0x04, 0xc3, 0x3d,
                0x3f, 0x66,
            ]
        );
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key: [u8; 16] = *b"YELLOW SUBMARINE";
        let original = *b"sixteen bytes!!!";
        let mut block = original;
        let cipher = Sm4::new(&key);
        cipher.encrypt_block(&mut block);
        assert_ne!(block, original);
        cipher.decrypt_block(&mut block);
        assert_eq!(block, original);
    }
}
