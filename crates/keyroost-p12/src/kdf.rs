//! The PKCS#12 key-derivation function (RFC 7292 appendix B.2) and the
//! BMPString password encoding it takes.

use keyroost_proto::sha1::sha1;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

/// The hash behind the KDF (and the file MAC).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Hash {
    Sha1,
    Sha256,
}

impl Hash {
    /// Hash output length in bytes (`u` in RFC 7292).
    pub(crate) fn output_len(self) -> usize {
        match self {
            Hash::Sha1 => 20,
            Hash::Sha256 => 32,
        }
    }

    /// Hash input block length in bytes (`v` in RFC 7292).
    fn block_len(self) -> usize {
        64
    }

    fn digest(self, data: &[u8]) -> Zeroizing<Vec<u8>> {
        match self {
            Hash::Sha1 => Zeroizing::new(sha1(data).to_vec()),
            Hash::Sha256 => Zeroizing::new(Sha256::digest(data).to_vec()),
        }
    }
}

/// Encode a password as the PKCS#12 BMPString: UTF-16BE plus a 2-byte NUL
/// terminator. `None` (no password) is the empty string; `Some("")` is just
/// the terminator, as the two are different keys in PKCS#12.
pub(crate) fn bmp_password(pw: Option<&str>) -> Zeroizing<Vec<u8>> {
    // Sized up front: a growing buffer would leave freed copies of the
    // password in the heap. UTF-8 bytes >= UTF-16 units, so this suffices.
    let mut out = Zeroizing::new(Vec::with_capacity(pw.map_or(0, |p| p.len() * 2 + 2)));
    if let Some(pw) = pw {
        for unit in pw.encode_utf16() {
            out.extend_from_slice(&unit.to_be_bytes());
        }
        out.extend_from_slice(&[0, 0]);
    }
    out
}

/// Repeat `data` to the next multiple of `v` bytes (empty stays empty).
fn fill(data: &[u8], v: usize) -> Zeroizing<Vec<u8>> {
    if data.is_empty() {
        return Zeroizing::new(Vec::new());
    }
    let total = v * data.len().div_ceil(v);
    let mut out = Zeroizing::new(Vec::with_capacity(total));
    out.extend(data.iter().cycle().take(total));
    out
}

/// PKCS#12 KDF (RFC 7292 B.2). `password` is already BMPString-encoded; `id`
/// is 1 (encryption key), 2 (IV) or 3 (MAC key).
pub(crate) fn pkcs12_kdf(
    hash: Hash,
    password: &Zeroizing<Vec<u8>>,
    salt: &[u8],
    id: u8,
    iterations: u32,
    out_len: usize,
) -> Zeroizing<Vec<u8>> {
    let u = hash.output_len();
    let v = hash.block_len();

    // I = S || P, each padded by repetition to a multiple of v bytes.
    let s_part = fill(salt, v);
    let p_part = fill(password, v);
    let mut i_buf = Zeroizing::new(Vec::with_capacity(s_part.len() + p_part.len()));
    i_buf.extend_from_slice(&s_part);
    i_buf.extend_from_slice(&p_part);

    let mut out = Zeroizing::new(Vec::with_capacity(out_len + u));
    while out.len() < out_len {
        // A = H^iterations(D || I)
        let mut input = Zeroizing::new(Vec::with_capacity(v + i_buf.len()));
        input.resize(v, id);
        input.extend_from_slice(&i_buf);
        let mut a = hash.digest(&input);
        for _ in 1..iterations {
            a = hash.digest(&a);
        }
        out.extend_from_slice(&a);
        if out.len() >= out_len {
            break;
        }

        // B = A repeated to v bytes; I_j = (I_j + B + 1) mod 2^(8v).
        let b: Vec<u8> = a.iter().cycle().take(v).copied().collect();
        for block in i_buf.chunks_mut(v) {
            let mut carry = 1u16;
            for (x, y) in block.iter_mut().zip(&b).rev() {
                let sum = u16::from(*x) + u16::from(*y) + carry;
                *x = sum as u8;
                carry = sum >> 8;
            }
        }
        let mut b = b;
        b.zeroize();
    }
    out.truncate(out_len);
    out
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
    fn bmp_password_encodes_utf16be_with_terminator() {
        assert_eq!(*bmp_password(Some("ab")), [0, 0x61, 0, 0x62, 0, 0]);
        assert_eq!(*bmp_password(Some("")), [0, 0]);
        assert!(bmp_password(None).is_empty());
        // Sized once: a growing buffer would leave password copies in freed memory.
        for pw in ["password", "\u{1F511}\u{1F511}", "h\u{e9}llo"] {
            assert_eq!(bmp_password(Some(pw)).capacity(), pw.len() * 2 + 2, "{pw}");
        }
        // Outside the BMP: a surrogate pair.
        assert_eq!(
            *bmp_password(Some("\u{1F511}")),
            [0xD8, 0x3D, 0xDD, 0x11, 0, 0]
        );
    }

    // Reference values come from `openssl kdf ... PKCS12KDF` with the BMP
    // password "password", salt 0102030405060708.
    #[test]
    fn kdf_matches_reference() {
        let pw = Zeroizing::new(unhex("00700061007300730077006f007200640000"));
        let salt = unhex("0102030405060708");
        let cases: &[(Hash, u32, u8, usize, &str)] = &[
            (
                Hash::Sha1,
                1,
                1,
                24,
                "be7f5f21b43a293a45aa36715521dcc91d0554d5b1b1a5d6",
            ),
            (Hash::Sha1, 1, 2, 8, "2a33c610694e223f"),
            (
                Hash::Sha1,
                1,
                3,
                20,
                "83681bc488a5208c09b06bc47035d9d390e84fc4",
            ),
            (
                Hash::Sha1,
                2048,
                1,
                24,
                "2a3a9c95b6ac4c49ebbf7a65976b1bbd5f0ffa69a1be2427",
            ),
            (Hash::Sha1, 2048, 2, 8, "995815de47373a76"),
            (
                Hash::Sha1,
                2048,
                3,
                20,
                "e41bf25c2ea77685923a7b4bb231021e7e045ee4",
            ),
            (
                Hash::Sha256,
                2048,
                1,
                24,
                "d8fb52dd9042c1031f9a18e5957a3be69ead00cf867836e8",
            ),
            (Hash::Sha256, 2048, 2, 8, "30938f79be0bc0f6"),
            (
                Hash::Sha256,
                2048,
                3,
                32,
                "4f510e1b5428cb3a1b784ceee7b1a95670f60e825199c121bd1752ee9e1c83f2",
            ),
        ];
        for &(hash, iter, id, len, want) in cases {
            let got = pkcs12_kdf(hash, &pw, &salt, id, iter, len);
            assert_eq!(*got, unhex(want), "{hash:?} iter {iter} id {id}");
        }
    }
}
