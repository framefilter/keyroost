//! The one source of every value a self-test feeds the card.
//!
//! No RNG: reproducibility matters more than unpredictability here (this is a
//! functional check, not a KAT and not a security operation). Everything is
//! sliced or cycled out of a single 640-bit array whose only real constraint
//! is that **no byte is zero** — the RSA PKCS#1 v1.5 padding string must be
//! all-nonzero, and a zero in an EC scalar's high bytes would just be wasted
//! entropy.

/// 80 bytes (640 bits), every byte non-zero, in five distinct 16-byte lines
/// so a hex dump is easy to eyeball in an APDU trace. The first 64 bytes were
/// the whole array before EccP521 support needed a 66-byte scalar
/// ([`ec_scalar`]'s `N`) — the fifth line is exactly that headroom, not used
/// by anything narrower.
pub const TEST_INPUT: [u8; 80] = [
    0xCA, 0xFE, 0xF0, 0x0D, 0xDE, 0xAD, 0xBE, 0xEF, 0xC0, 0xFF, 0xEE, 0x15, 0xBA, 0x5E, 0xBA, 0x11,
    0x1D, 0xEA, 0xD1, 0xCE, 0xF1, 0x5C, 0xA1, 0x1F, 0x5E, 0xED, 0xFA, 0xCE, 0xB0, 0xA7, 0xC1, 0xA5,
    0xD0, 0xD0, 0xCA, 0xCA, 0x0F, 0xF1, 0xCE, 0xB0, 0x07, 0x1E, 0xAD, 0xEF, 0x1E, 0x1D, 0x0F, 0xED,
    0xFE, 0xED, 0xC0, 0xDE, 0x5A, 0x1A, 0xD1, 0x5C, 0x0D, 0xEF, 0xEC, 0xAB, 0x1E, 0xB1, 0x05, 0xC0,
    0xFA, 0xCA, 0xDE, 0xB1, 0x0B, 0xA5, 0x5E, 0xED, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x1D, 0xEA,
];

/// The plaintext the Decrypt self-test round-trips through the card.
pub const DECRYPT_PLAINTEXT: &[u8] = b"Hello World!";

/// ASN.1 `DigestInfo` prefix for SHA-512 (`SEQUENCE { SEQUENCE { OID
/// sha-512, NULL }, OCTET STRING (64) }` header) — the 19 bytes that precede
/// the 64 hash bytes in a PKCS#1 v1.5 signature block. Kept as a literal so
/// this crate needs no `sha2` dependency just to name a constant.
pub const SHA512_DIGESTINFO_PREFIX: [u8; 19] = [
    0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];

/// "Their" 32-byte private scalar for a P-256 / X25519 key-agree, and the
/// first 48 / 66 bytes of a P-384 / P-521 one. For the NIST curves byte 0 is
/// forced to `0x00` by [`ec_scalar`] so the value is unconditionally in
/// `1..n`; X25519 clamps internally so it takes the bytes as-is.
#[must_use]
pub fn ec_scalar<const N: usize>(clamp_high_byte: bool) -> [u8; N] {
    let mut s = [0u8; N];
    s.copy_from_slice(&TEST_INPUT[..N]);
    if clamp_high_byte {
        s[0] = 0x00;
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_input_has_no_zero_byte() {
        assert!(TEST_INPUT.iter().all(|&b| b != 0));
    }
}
