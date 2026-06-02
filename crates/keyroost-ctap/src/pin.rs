//! CTAP2 PIN protocol primitives (v1 and v2).
//!
//! The PIN protocol exists so the host can prove knowledge of the user's
//! PIN to the authenticator without sending the PIN itself, and so all
//! subsequent commands can be authenticated against a short-lived token
//! the authenticator hands back. There are two wire-compatible variants:
//!
//! - **v1** (the original): the shared secret is `SHA-256(ECDH-X)` and is
//!   used both as the AES-CBC key (with a zero IV) and as the HMAC key,
//!   with authenticators returning only the leftmost 16 bytes of HMAC.
//! - **v2** (CTAP 2.1): the shared secret is split into a 32-byte AES key
//!   and a 32-byte HMAC key derived via HKDF-SHA-256, each AES message
//!   carries a random IV prepended to the ciphertext, and the full 32-byte
//!   HMAC tag is returned.
//!
//! This module exposes the primitives. The wire commands that compose them
//! (`clientPin` subcommands, getting a pinUvAuthToken, etc.) live in
//! [`crate::client_pin`].

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes::Aes256;
use hmac::{Hmac, Mac};
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{AffinePoint, EncodedPoint, PublicKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;

/// Identifier the authenticator expects in the `clientPin` request map.
pub const PIN_PROTOCOL_V1: u32 = 1;
pub const PIN_PROTOCOL_V2: u32 = 2;

#[derive(Debug)]
pub enum PinError {
    InvalidPublicKey,
    InvalidCiphertextLength,
    AesError,
}

impl std::fmt::Display for PinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PinError::InvalidPublicKey => {
                write!(f, "authenticator returned an invalid P-256 point")
            }
            PinError::InvalidCiphertextLength => {
                write!(f, "PIN protocol ciphertext was not block-aligned")
            }
            PinError::AesError => write!(f, "AES-CBC operation failed"),
        }
    }
}

impl std::error::Error for PinError {}

/// One half of the ECDH key exchange, generated locally and consumed once.
pub struct EphemeralKey {
    secret: EphemeralSecret,
}

impl EphemeralKey {
    /// Generate a fresh P-256 keypair backed by the OS RNG.
    pub fn generate() -> Self {
        Self {
            secret: EphemeralSecret::random(&mut OsRng),
        }
    }

    /// `(x, y)` coordinates of the public key, suitable for wire encoding
    /// in the COSE_Key map the authenticator expects.
    pub fn public_xy(&self) -> ([u8; 32], [u8; 32]) {
        let pk: PublicKey = self.secret.public_key();
        let point = pk.to_encoded_point(false);
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(point.x().expect("uncompressed point has x"));
        y.copy_from_slice(point.y().expect("uncompressed point has y"));
        (x, y)
    }

    /// Complete the v1 exchange: `sharedSecret = SHA-256(ECDH(self, peer).x)`.
    pub fn shared_secret_v1(
        &self,
        peer_x: &[u8; 32],
        peer_y: &[u8; 32],
    ) -> Result<SharedSecretV1, PinError> {
        let z = self.raw_ecdh(peer_x, peer_y)?;
        let digest = Sha256::digest(z);
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Ok(SharedSecretV1(out))
    }

    /// Complete the v2 exchange: HKDF-SHA-256 derives separate HMAC and AES
    /// keys from the ECDH X-coordinate, per CTAP 2.1 §6.5.7.
    pub fn shared_secret_v2(
        &self,
        peer_x: &[u8; 32],
        peer_y: &[u8; 32],
    ) -> Result<SharedSecretV2, PinError> {
        let z = self.raw_ecdh(peer_x, peer_y)?;
        let hmac_key = hkdf_sha256_l32(&[0u8; 32], &z, b"CTAP2 HMAC key");
        let aes_key = hkdf_sha256_l32(&[0u8; 32], &z, b"CTAP2 AES key");
        Ok(SharedSecretV2 { hmac_key, aes_key })
    }

    fn raw_ecdh(&self, peer_x: &[u8; 32], peer_y: &[u8; 32]) -> Result<[u8; 32], PinError> {
        let encoded = EncodedPoint::from_affine_coordinates(peer_x.into(), peer_y.into(), false);
        let affine: Option<AffinePoint> = AffinePoint::from_encoded_point(&encoded).into();
        let affine = affine.ok_or(PinError::InvalidPublicKey)?;
        let peer = PublicKey::from_affine(affine).map_err(|_| PinError::InvalidPublicKey)?;
        let shared = self.secret.diffie_hellman(&peer);
        let mut x = [0u8; 32];
        x.copy_from_slice(shared.raw_secret_bytes());
        Ok(x)
    }
}

/// Single-key shared secret used by PIN protocol v1.
#[derive(Clone)]
pub struct SharedSecretV1(pub [u8; 32]);

/// Split shared secret used by PIN protocol v2.
#[derive(Clone)]
pub struct SharedSecretV2 {
    pub hmac_key: [u8; 32],
    pub aes_key: [u8; 32],
}

/// Behaviour common to the two PIN protocols. The two variants share the
/// shape of `encrypt`/`decrypt`/`authenticate` but use different keys and
/// IV strategies under the hood.
pub trait PinProtocol {
    fn version(&self) -> u32;
    /// Encrypt a block-aligned plaintext. v1 prepends nothing; v2 prepends
    /// a random 16-byte IV that is also returned as part of the ciphertext.
    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8>;
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, PinError>;
    /// HMAC tag returned by the authenticator. v1 truncates to 16 bytes,
    /// v2 returns the full 32-byte tag.
    fn authenticate(&self, data: &[u8]) -> Vec<u8>;
}

/// PIN protocol v1 wrapper carrying its shared secret.
pub struct ProtocolV1 {
    pub secret: SharedSecretV1,
}

impl PinProtocol for ProtocolV1 {
    fn version(&self) -> u32 {
        PIN_PROTOCOL_V1
    }
    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        aes256_cbc_encrypt(&self.secret.0, &[0u8; 16], plaintext)
    }
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, PinError> {
        aes256_cbc_decrypt(&self.secret.0, &[0u8; 16], ciphertext)
    }
    fn authenticate(&self, data: &[u8]) -> Vec<u8> {
        let full = hmac_sha256(&self.secret.0, data);
        full[..16].to_vec()
    }
}

/// PIN protocol v2 wrapper carrying its split shared secret.
pub struct ProtocolV2 {
    pub secret: SharedSecretV2,
}

impl PinProtocol for ProtocolV2 {
    fn version(&self) -> u32 {
        PIN_PROTOCOL_V2
    }
    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut iv = [0u8; 16];
        getrandom_iv(&mut iv);
        let body = aes256_cbc_encrypt(&self.secret.aes_key, &iv, plaintext);
        let mut out = Vec::with_capacity(16 + body.len());
        out.extend_from_slice(&iv);
        out.extend_from_slice(&body);
        out
    }
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, PinError> {
        if ciphertext.len() < 16 {
            return Err(PinError::InvalidCiphertextLength);
        }
        let (iv, body) = ciphertext.split_at(16);
        let iv: &[u8; 16] = iv.try_into().expect("16 bytes");
        aes256_cbc_decrypt(&self.secret.aes_key, iv, body)
    }
    fn authenticate(&self, data: &[u8]) -> Vec<u8> {
        hmac_sha256(&self.secret.hmac_key, data).to_vec()
    }
}

/// AES-256-CBC with no padding. The PIN protocol always passes
/// block-aligned plaintext (padded SHA-256 hashes, pre-padded UTF-8 PINs)
/// so we skip PKCS#7 entirely — adding padding here would corrupt the wire
/// format.
fn aes256_cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    assert!(
        plaintext.len() % 16 == 0,
        "PIN protocol plaintext must be block-aligned"
    );
    let mut out = plaintext.to_vec();
    let mut enc = Aes256CbcEnc::new(key.into(), iv.into());
    for chunk in out.chunks_exact_mut(16) {
        let block = GenericArray::from_mut_slice(chunk);
        enc.encrypt_block_mut(block);
    }
    out
}

fn aes256_cbc_decrypt(
    key: &[u8; 32],
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Vec<u8>, PinError> {
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return Err(PinError::InvalidCiphertextLength);
    }
    let mut out = ciphertext.to_vec();
    let mut dec = Aes256CbcDec::new(key.into(), iv.into());
    for chunk in out.chunks_exact_mut(16) {
        let block = GenericArray::from_mut_slice(chunk);
        dec.decrypt_block_mut(block);
    }
    Ok(out)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&out);
    buf
}

/// HKDF-SHA-256 reduced to the single-block expand case (L=32) we actually
/// use in CTAP. Avoids pulling the full `hkdf` crate for a 30-line helper.
fn hkdf_sha256_l32(salt: &[u8; 32], ikm: &[u8], info: &[u8]) -> [u8; 32] {
    // Extract: PRK = HMAC(salt, IKM)
    let prk = hmac_sha256(salt, ikm);
    // Expand to one block: T(1) = HMAC(PRK, info || 0x01)
    let mut mac = HmacSha256::new_from_slice(&prk).expect("HMAC accepts any key length");
    mac.update(info);
    mac.update(&[0x01]);
    let out = mac.finalize().into_bytes();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&out);
    buf
}

/// Fill an IV from the OS RNG. CTAP doesn't allow IV reuse with the same
/// key, but we generate a fresh ephemeral keypair per session anyway, so a
/// counter would also be fine — using OsRng keeps it simple.
fn getrandom_iv(iv: &mut [u8; 16]) {
    use rand_core::RngCore;
    OsRng.fill_bytes(iv);
}

/// Helper for callers building the `getPinHash` flow: the CTAP spec asks
/// for `LEFT(SHA-256(pin), 16)` as the value that's encrypted on the wire.
pub fn left16_sha256(input: &[u8]) -> [u8; 16] {
    let digest = Sha256::digest(input);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

/// Helper for the `setPin` / `changePin` flow: UTF-8 PIN padded with
/// trailing zeros to 64 bytes. Caller must already have validated the PIN
/// length (4–63 UTF-8 bytes per CTAP).
pub fn pad_pin_to_64(pin: &str) -> [u8; 64] {
    let bytes = pin.as_bytes();
    assert!(
        bytes.len() < 64,
        "pin must be < 64 bytes (caller validates)"
    );
    let mut out = [0u8; 64];
    out[..bytes.len()].copy_from_slice(bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ephemeral_keys_distinct_and_consistent() {
        let a = EphemeralKey::generate();
        let b = EphemeralKey::generate();
        let (ax, _ay) = a.public_xy();
        let (bx, _by) = b.public_xy();
        assert_ne!(ax, bx);
        // Same key reports the same public key twice.
        let (ax2, _) = a.public_xy();
        assert_eq!(ax, ax2);
    }

    #[test]
    fn ecdh_round_trips_between_two_parties() {
        let alice = EphemeralKey::generate();
        let bob = EphemeralKey::generate();
        let (bx, by) = bob.public_xy();
        let (ax, ay) = alice.public_xy();
        let shared_a = alice.shared_secret_v1(&bx, &by).unwrap();
        let shared_b = bob.shared_secret_v1(&ax, &ay).unwrap();
        assert_eq!(shared_a.0, shared_b.0);
    }

    #[test]
    fn ecdh_v2_keys_match_between_parties_and_differ_between_purposes() {
        let alice = EphemeralKey::generate();
        let bob = EphemeralKey::generate();
        let (bx, by) = bob.public_xy();
        let (ax, ay) = alice.public_xy();
        let a = alice.shared_secret_v2(&bx, &by).unwrap();
        let b = bob.shared_secret_v2(&ax, &ay).unwrap();
        assert_eq!(a.aes_key, b.aes_key);
        assert_eq!(a.hmac_key, b.hmac_key);
        assert_ne!(a.aes_key, a.hmac_key);
    }

    #[test]
    fn invalid_peer_point_rejected() {
        let alice = EphemeralKey::generate();
        let bad = [0u8; 32];
        assert!(matches!(
            alice.shared_secret_v1(&bad, &bad),
            Err(PinError::InvalidPublicKey)
        ));
    }

    #[test]
    fn v1_encrypt_decrypt_round_trip() {
        let p = ProtocolV1 {
            secret: SharedSecretV1([0xAB; 32]),
        };
        let plaintext = [0x42u8; 32];
        let ct = p.encrypt(&plaintext);
        assert_eq!(ct.len(), 32);
        assert_ne!(ct, plaintext);
        let pt = p.decrypt(&ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn v2_encrypt_prepends_random_iv_and_decrypt_round_trips() {
        let p = ProtocolV2 {
            secret: SharedSecretV2 {
                hmac_key: [0x11; 32],
                aes_key: [0x22; 32],
            },
        };
        let plaintext = [0x42u8; 16];
        let ct1 = p.encrypt(&plaintext);
        let ct2 = p.encrypt(&plaintext);
        // Random IV makes successive ciphertexts differ on the IV bytes.
        assert_ne!(ct1[..16], ct2[..16]);
        assert_eq!(ct1.len(), 16 + 16); // IV + one block
        let pt = p.decrypt(&ct1).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn v1_authenticate_truncates_to_16_bytes() {
        let p = ProtocolV1 {
            secret: SharedSecretV1([0u8; 32]),
        };
        assert_eq!(p.authenticate(b"hello").len(), 16);
    }

    #[test]
    fn v2_authenticate_returns_full_32_bytes() {
        let p = ProtocolV2 {
            secret: SharedSecretV2 {
                hmac_key: [0u8; 32],
                aes_key: [0u8; 32],
            },
        };
        assert_eq!(p.authenticate(b"hello").len(), 32);
    }

    #[test]
    fn hmac_sha256_known_answer() {
        // RFC 4231 test case 1: key=0x0b*20, data="Hi There"
        let key = [0x0b; 20];
        let want_hex = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
        let got = hmac_sha256(&key, b"Hi There");
        let got_hex: String = got.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(got_hex, want_hex);
    }

    #[test]
    fn left16_sha256_basic() {
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let got = left16_sha256(b"abc");
        let got_hex: String = got.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(got_hex, "ba7816bf8f01cfea414140de5dae2223");
    }

    #[test]
    fn pad_pin_zero_extends() {
        let p = pad_pin_to_64("1234");
        assert_eq!(&p[..4], b"1234");
        assert!(p[4..].iter().all(|&b| b == 0));
    }
}
