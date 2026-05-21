//! SHA-1 (RFC 3174). Pure Rust, no_std friendly.
//!
//! Used by the Molto2 protocol only for key derivation:
//!   sm4_key = SHA1(customer_key)[..16]
//! The TOTP HMAC-SHA1 happens on the device, not the host.

const BLOCK_SIZE: usize = 64;

#[derive(Clone)]
pub struct Sha1 {
    h: [u32; 5],
    buf: [u8; BLOCK_SIZE],
    buf_len: usize,
    total_bits: u64,
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha1 {
    pub const fn new() -> Self {
        Self {
            h: [
                0x6745_2301,
                0xefcd_ab89,
                0x98ba_dcfe,
                0x1032_5476,
                0xc3d2_e1f0,
            ],
            buf: [0u8; BLOCK_SIZE],
            buf_len: 0,
            total_bits: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total_bits = self.total_bits.wrapping_add((data.len() as u64) * 8);

        if self.buf_len > 0 {
            let take = (BLOCK_SIZE - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == BLOCK_SIZE {
                let block = self.buf;
                self.process_block(&block);
                self.buf_len = 0;
            }
        }

        while data.len() >= BLOCK_SIZE {
            let (block, rest) = data.split_at(BLOCK_SIZE);
            self.process_block(block.try_into().unwrap());
            data = rest;
        }

        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    pub fn finalize(mut self) -> [u8; 20] {
        let bit_len = self.total_bits;
        // append 0x80, pad zeros, append 8-byte big-endian length
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;
        if self.buf_len > BLOCK_SIZE - 8 {
            for i in self.buf_len..BLOCK_SIZE {
                self.buf[i] = 0;
            }
            let block = self.buf;
            self.process_block(&block);
            self.buf_len = 0;
        }
        for i in self.buf_len..BLOCK_SIZE - 8 {
            self.buf[i] = 0;
        }
        self.buf[BLOCK_SIZE - 8..].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buf;
        self.process_block(&block);

        let mut out = [0u8; 20];
        for (i, word) in self.h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    #[allow(clippy::needless_range_loop)] // RFC-3174 style is clearer than enumerate() here
    fn process_block(&mut self, block: &[u8; BLOCK_SIZE]) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) =
            (self.h[0], self.h[1], self.h[2], self.h[3], self.h[4]);

        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
    }
}

pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(data);
    h.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    #[test]
    fn empty() {
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[test]
    fn abc() {
        // Canonical RFC 3174 vector.
        assert_eq!(
            hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }

    #[test]
    fn rfc_long() {
        assert_eq!(
            hex(&sha1(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
    }

    #[test]
    fn million_a() {
        let mut h = Sha1::new();
        let chunk = vec![b'a'; 1000];
        for _ in 0..1000 {
            h.update(&chunk);
        }
        assert_eq!(
            hex(&h.finalize()),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
        );
    }

    /// The Molto2 default customer key derives this SM4 key.
    /// customer_key = "TOKEN2MOLTO1-KEY" (16 ASCII bytes)
    /// sm4_key = SHA1(customer_key)[..16]
    #[test]
    fn molto2_default_key_derivation() {
        let digest = sha1(b"TOKEN2MOLTO1-KEY");
        // First 16 bytes are what SM4 will use as its key.
        // (Exact value just locks in the algorithm — verified once against `hashlib.sha1`.)
        assert_eq!(hex(&digest), "099250fdb017f442da429ecbbee17f79872d4a7d");
    }
}
