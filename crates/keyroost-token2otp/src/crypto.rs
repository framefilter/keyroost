//! ECDH + AES-CBC payload encryption for the seed-bearing commands `WRITE_SEED`
//! and `WRITE_HOTP_SEED` (spec §7).
//!
//! Flow (spec §7.3):
//! 1. The device's `GET_ECDH_PUBKEY` reply is 64 bytes `X || Y` (no `0x04`).
//! 2. Generate a fresh ephemeral P-256 keypair per command.
//! 3. `shared = ECDH(host_priv, device_pub)`, take the 32-byte X coordinate.
//! 4. `key = SHA256(shared)` (32 bytes).
//! 5. AES-256-CBC encrypt PKCS#7-padded cleartext with one of the two constant
//!    IVs. Freshness comes from the ephemeral keypair, not the IV.
//! 6. On-wire blob = `host_pub_xy (64) || ciphertext`.
//!
//! The two IVs are **constants** by design (spec §7.2). Randomizing them breaks
//! device-side decryption.

use crate::cmd::{PIN_ALG_AES256, PIN_DEFAULT_MAX_RETRY};
use aes::Aes256;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, PublicKey, SecretKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;

/// IV-1 — used when writing or deleting OTP entries (`WRITE_SEED`, spec §7.2).
pub const IV_OTP: [u8; 16] = [
    0x9D, 0xD8, 0x91, 0x8E, 0x34, 0xF3, 0xCC, 0xAB, 0x08, 0xCB, 0x75, 0x18, 0xF7, 0x19, 0x38, 0xF1,
];

/// IV-2 — used for the HOTP-on-button seed (`WRITE_HOTP_SEED`, spec §7.2). All
/// zeros.
pub const IV_HOTP: [u8; 16] = [0u8; 16];

/// Errors from the ECDH+AES seal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncryptError {
    /// The device pubkey was not a valid 64-byte (`X || Y`) P-256 point.
    BadDevicePubkey,
    /// The OS RNG failed while generating the ephemeral keypair.
    RngFailed,
    /// A session ciphertext failed to decrypt (bad length / padding).
    BadCiphertext,
    /// A session HMAC authentication tag did not match.
    BadAuthTag,
    /// An input to a PIN-proof builder was the wrong size: a PIN longer than
    /// the single length byte the block format carries, or a challenge that is
    /// not a whole number of AES blocks. Returned rather than panicking,
    /// because both values can arrive from a device on the other end of a
    /// cable and these builders are public API.
    BadLength,
}

impl std::fmt::Display for EncryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncryptError::BadDevicePubkey => {
                write!(f, "device ECDH public key was not a valid P-256 point")
            }
            EncryptError::RngFailed => write!(f, "host RNG failed generating ephemeral key"),
            EncryptError::BadCiphertext => write!(f, "session ciphertext failed to decrypt"),
            EncryptError::BadAuthTag => write!(f, "session HMAC authentication tag mismatch"),
            EncryptError::BadLength => {
                write!(
                    f,
                    "PIN or challenge length is out of range for this command"
                )
            }
        }
    }
}

impl std::error::Error for EncryptError {}

/// Seal `cleartext` into the on-wire `host_pub_xy || ciphertext` blob for a
/// seed-bearing command (spec §7).
///
/// `device_pub_xy` is the raw 64-byte key from `GET_ECDH_PUBKEY` (no leading
/// `0x04`). `iv` is [`IV_OTP`] for entry writes/deletes or [`IV_HOTP`] for the
/// button-HOTP seed. A fresh ephemeral keypair is generated per call.
pub fn encrypt_seed_payload(
    device_pub_xy: &[u8],
    cleartext: &[u8],
    iv: &[u8; 16],
) -> Result<Vec<u8>, EncryptError> {
    if device_pub_xy.len() != 64 {
        return Err(EncryptError::BadDevicePubkey);
    }

    // Prepend the uncompressed-point tag the way most libraries expect (spec §7.1,
    // §11 "pubkey representation").
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..].copy_from_slice(device_pub_xy);
    let device_point = EncodedPoint::from_bytes(sec1).map_err(|_| EncryptError::BadDevicePubkey)?;
    let device_pub = Option::<PublicKey>::from(PublicKey::from_encoded_point(&device_point))
        .ok_or(EncryptError::BadDevicePubkey)?;

    // Fresh ephemeral host keypair (spec §7: per-command).
    let host_secret = SecretKey::random(&mut OsRng);
    let host_pub = host_secret.public_key();

    // shared X coordinate -> SHA-256 -> 32-byte AES-256 key.
    let shared = diffie_hellman(host_secret.to_nonzero_scalar(), device_pub.as_affine());
    let session_key = Zeroizing::new({
        let mut h = Sha256::new();
        h.update(shared.raw_secret_bytes());
        h.finalize()
    });

    // AES-256-CBC + PKCS#7 over the cleartext.
    let mut work = Zeroizing::new(cleartext.to_vec());
    let pad_room = 16 - (cleartext.len() % 16);
    work.resize(cleartext.len() + pad_room, 0);
    let ct_len = cleartext.len();
    let ciphertext = Aes256CbcEnc::new(session_key.as_slice().into(), iv.into())
        .encrypt_padded_mut::<Pkcs7>(&mut work, ct_len)
        .expect("buffer sized for PKCS7 padding above")
        .to_vec();

    // Host pubkey as raw X || Y (strip the 0x04 SEC1 tag) per spec §7.1.
    let host_point = host_pub.to_encoded_point(false);
    let host_xy = &host_point.as_bytes()[1..];

    let mut blob = Vec::with_capacity(64 + ciphertext.len());
    blob.extend_from_slice(host_xy);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdh::diffie_hellman;
    use p256::SecretKey;

    #[test]
    fn rejects_wrong_length_pubkey() {
        assert_eq!(
            encrypt_seed_payload(&[0u8; 63], b"x", &IV_OTP),
            Err(EncryptError::BadDevicePubkey)
        );
    }

    #[test]
    fn rejects_non_point_pubkey() {
        // 64 bytes that aren't a valid curve point.
        assert_eq!(
            encrypt_seed_payload(&[0xFFu8; 64], b"x", &IV_OTP),
            Err(EncryptError::BadDevicePubkey)
        );
    }

    #[test]
    fn blob_shape_and_block_alignment() {
        // Stand in for the device with a known keypair so we can validate shape
        // and that the ciphertext is a whole number of AES blocks.
        let device_secret = SecretKey::random(&mut OsRng);
        let device_xy = {
            let pt = device_secret.public_key().to_encoded_point(false);
            pt.as_bytes()[1..].to_vec()
        };
        // 23-byte cleartext (spec §10.2) -> PKCS7 pads to 32 -> two AES blocks.
        let cleartext = [0xABu8; 23];
        let blob = encrypt_seed_payload(&device_xy, &cleartext, &IV_OTP).unwrap();
        assert_eq!(blob.len(), 64 + 32);
        assert_eq!((blob.len() - 64) % 16, 0);
    }

    #[test]
    fn roundtrip_decrypts_on_device_side() {
        // Full end-to-end: act as the device, derive the same key, and decrypt
        // the host's ciphertext back to the cleartext. Proves the ECDH + key
        // derivation + IV usage all agree with the spec.
        use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
        type Dec = cbc::Decryptor<aes::Aes256>;

        let device_secret = SecretKey::random(&mut OsRng);
        let device_pub = device_secret.public_key();
        let device_xy = {
            let pt = device_pub.to_encoded_point(false);
            pt.as_bytes()[1..].to_vec()
        };

        let cleartext = b"01\xC1\x00\x1E\x06\x00\x04Test\x05alice\x05Hello";
        let blob = encrypt_seed_payload(&device_xy, cleartext, &IV_OTP).unwrap();

        // Device side: split blob, recompute shared key from host pubkey.
        let host_xy = &blob[..64];
        let ciphertext = &blob[64..];
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..].copy_from_slice(host_xy);
        let host_pub = p256::PublicKey::from_sec1_bytes(&sec1).unwrap();
        let shared = diffie_hellman(device_secret.to_nonzero_scalar(), host_pub.as_affine());
        let key = {
            let mut h = Sha256::new();
            h.update(shared.raw_secret_bytes());
            h.finalize()
        };
        let mut buf = ciphertext.to_vec();
        let plain = Dec::new(key.as_slice().into(), (&IV_OTP).into())
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .unwrap();
        assert_eq!(plain, cleartext);
    }
}

// --- OTP PIN session crypto (R3.4 privacy protection) -----------------------
// Ported from the Token2 reference client. ECDH-P256 session keys + the
// AES-CBC/HMAC PIN proof builders used by SET/VERIFY/CHANGE_OTP_PIN.

/// The two 32-byte session keys derived from a `READ_AGREEMENT_PUBKEY` exchange.
///
/// Derivation (all HMAC-SHA256), per the protocol document:
/// ```text
/// shared        = ECDH-P256(hostPriv, devPub).X          (32 bytes)
/// pu1PRKey      = HMAC(key = 0x00*32, data = shared)
/// SessionMacKey = HMAC(key = pu1PRKey, data = "TOTP HMAC key" || 0x01)
/// SessionEncKey = HMAC(key = pu1PRKey, data = "TOTP AES key"  || 0x01)
/// ```
pub struct SessionKeys {
    pub enc: Zeroizing<[u8; 32]>,
    pub mac: Zeroizing<[u8; 32]>,
}

fn hmac256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(data);
    m.finalize().into_bytes().into()
}

/// Derive the session keys from an existing host secret and the device's
/// 64-byte agreement pubkey (`X || Y`, no leading `0x04`).
pub fn derive_session_keys(
    host_secret: &SecretKey,
    device_agreement_xy: &[u8],
) -> Result<SessionKeys, EncryptError> {
    if device_agreement_xy.len() != 64 {
        return Err(EncryptError::BadDevicePubkey);
    }
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..].copy_from_slice(device_agreement_xy);
    let dev_point = EncodedPoint::from_bytes(sec1).map_err(|_| EncryptError::BadDevicePubkey)?;
    let dev_pub = Option::<PublicKey>::from(PublicKey::from_encoded_point(&dev_point))
        .ok_or(EncryptError::BadDevicePubkey)?;

    let shared = diffie_hellman(host_secret.to_nonzero_scalar(), dev_pub.as_affine());
    let pu1_pr = Zeroizing::new(hmac256(&[0u8; 32], shared.raw_secret_bytes()));
    // Session-key ladder per the Token2 reference client (token2-otp-cli):
    //   pu1PRKey      = HMAC(0x00*32, sharedX)
    //   SessionMacKey = HMAC(pu1PRKey, "TOTP HMAC key" || 0x01)
    //   SessionEncKey = HMAC(pu1PRKey, "TOTP AES key"  || 0x01)
    let mut mac_info = b"TOTP HMAC key".to_vec();
    mac_info.push(0x01);
    let mut enc_info = b"TOTP AES key".to_vec();
    enc_info.push(0x01);
    Ok(SessionKeys {
        enc: Zeroizing::new(hmac256(pu1_pr.as_slice(), &enc_info)),
        mac: Zeroizing::new(hmac256(pu1_pr.as_slice(), &mac_info)),
    })
}

/// A host-side ephemeral keypair for one PIN session, held across the two
/// halves of the `READ_AGREEMENT_PUBKEY` exchange.
///
/// The exchange is inherently two-step — the host must send its public half
/// *before* the device answers with its own — so a one-shot "generate and
/// derive" function cannot express it: the keys would be derived against a
/// different keypair than the one the device saw. Keeping the secret here lets
/// the transport stay free of any curve arithmetic; it holds an opaque handle
/// between the two transmits.
pub struct HostAgreement {
    secret: SecretKey,
    public_xy: [u8; 64],
}

impl HostAgreement {
    /// Generate a fresh ephemeral P-256 keypair for one session.
    pub fn new() -> Self {
        let secret = SecretKey::random(&mut OsRng);
        let point = secret.public_key().to_encoded_point(false);
        let mut public_xy = [0u8; 64];
        public_xy.copy_from_slice(&point.as_bytes()[1..]);
        Self { secret, public_xy }
    }

    /// The host public key as raw `X || Y` — the body of the
    /// `READ_AGREEMENT_PUBKEY` command.
    pub fn public_xy(&self) -> &[u8; 64] {
        &self.public_xy
    }

    /// Finish the exchange: derive the session keys against the device's
    /// 64-byte agreement pubkey from the same round trip.
    pub fn establish_session(
        &self,
        device_agreement_xy: &[u8],
    ) -> Result<SessionKeys, EncryptError> {
        derive_session_keys(&self.secret, device_agreement_xy)
    }
}

impl Default for HostAgreement {
    fn default() -> Self {
        Self::new()
    }
}

/// AES-256-CBC encrypt `cleartext` (PKCS#7) under the session key with an
/// explicit `iv`.
pub fn session_encrypt(key: &[u8; 32], iv: &[u8; 16], cleartext: &[u8]) -> Vec<u8> {
    let mut work = Zeroizing::new(cleartext.to_vec());
    let pad_room = 16 - (cleartext.len() % 16);
    work.resize(cleartext.len() + pad_room, 0);
    let ct_len = cleartext.len();
    Aes256CbcEnc::new(key.into(), iv.into())
        .encrypt_padded_mut::<Pkcs7>(&mut work, ct_len)
        .expect("buffer sized for PKCS7 padding above")
        .to_vec()
}

/// AES-256-CBC decrypt WITHOUT unpadding.
///
/// The PIN challenge (`Rand`) is exactly one block and carries no PKCS#7
/// trailer, so unpadding would reject it; this is the production path that
/// recovers it, not a debug aid. Returns an empty vector for input that is not
/// a whole number of blocks — callers check the recovered length.
pub fn session_decrypt_raw(key: &[u8; 32], iv: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return Vec::new();
    }
    let mut buf = ciphertext.to_vec();
    Aes256CbcDec::new(key.into(), iv.into())
        .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf)
        .map(|s| s.to_vec())
        .unwrap_or_default()
}

/// AES-256-CBC decrypt+unpad a session ciphertext under the session key.
pub fn session_decrypt(
    key: &[u8; 32],
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, EncryptError> {
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return Err(EncryptError::BadCiphertext);
    }
    let mut buf = Zeroizing::new(ciphertext.to_vec());
    let plain = Aes256CbcDec::new(key.into(), iv.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|_| EncryptError::BadCiphertext)?;
    Ok(Zeroizing::new(plain.to_vec()))
}

/// The first 16 bytes of `HMAC(mac_key, data)` — the auth-tag form the PIN
/// commands use (`NewPinAuth`, `EncDataAuth`).
pub fn session_auth_tag(mac_key: &[u8; 32], data: &[u8]) -> [u8; 16] {
    let full = hmac256(mac_key, data);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&full[..16]);
    tag
}

/// Check a 16-byte session auth tag with a branch-free byte compare: every byte
/// is XOR-folded into one accumulator, so the comparison takes the same path
/// whatever the tag is. Rust makes no guarantee the optimizer keeps it that
/// way, hence "branch-free as written" rather than a hard constant-time claim —
/// the tag is over device-supplied ciphertext, so a timing leak reveals nothing
/// secret either way.
pub fn verify_auth_tag(mac_key: &[u8; 32], data: &[u8], tag: &[u8]) -> Result<(), EncryptError> {
    if tag.len() != 16 {
        return Err(EncryptError::BadAuthTag);
    }
    let expect = session_auth_tag(mac_key, data);
    let mut diff = 0u8;
    for (a, b) in expect.iter().zip(tag.iter()) {
        diff |= a ^ b;
    }
    if diff == 0 {
        Ok(())
    } else {
        Err(EncryptError::BadAuthTag)
    }
}

/// Build the data field for a **PIN-protected seed write** (`WRITE_SEED` while a
/// PIN window is open). Unlike an unprotected write — which is an ECDH blob keyed
/// by a fresh `GET_ECDH_PUBKEY` — a protected write reuses the verified PIN
/// session keys, exactly like PIN-mode reads in reverse:
///
///   `IV(16) || AES-CBC(SessionEncKey, IV, cleartext) || HMAC(SessionMacKey, EncData)[:16]`
///
/// (`GET_ECDH_PUBKEY` is rejected with 6A81 on a protected key, so no ECDH blob
/// is possible; this session-key format is what the Token2 companion app sends.)
pub fn build_protected_write_data(keys: &SessionKeys, cleartext: &[u8]) -> Vec<u8> {
    let iv = random_iv();
    let enc = session_encrypt(&keys.enc, &iv, cleartext);
    let auth = session_auth_tag(&keys.mac, &enc);
    let mut out = Vec::with_capacity(16 + enc.len() + 16);
    out.extend_from_slice(&iv);
    out.extend_from_slice(&enc);
    out.extend_from_slice(&auth);
    out
}

/// Build the `SET_OTP_PIN` data field: `IV || NewPinEnc || NewPinAuth`, where
/// `NewPin = alg(0x07) || retry || pinLen || pin`, PKCS#7-padded to 16 by
/// [`session_encrypt`].
///
/// The cleartext `NewPin` block is held in a [`Zeroizing`] buffer: it is the
/// only place the PIN exists in the clear on this side of the wire.
pub fn build_set_pin_data(
    keys: &SessionKeys,
    pin: &[u8],
    retry: u8,
) -> Result<Vec<u8>, EncryptError> {
    // The block carries the PIN length in one byte; a longer PIN cannot be
    // expressed and must not be silently truncated into a different PIN.
    let pin_len = u8::try_from(pin.len()).map_err(|_| EncryptError::BadLength)?;
    let iv = random_iv();
    let mut newpin = Zeroizing::new(Vec::with_capacity(3 + pin.len()));
    newpin.push(PIN_ALG_AES256);
    newpin.push(retry);
    newpin.push(pin_len);
    newpin.extend_from_slice(pin);
    let enc = session_encrypt(&keys.enc, &iv, &newpin);
    let auth = session_auth_tag(&keys.mac, &enc);
    let mut out = Vec::with_capacity(16 + enc.len() + 16);
    out.extend_from_slice(&iv);
    out.extend_from_slice(&enc);
    out.extend_from_slice(&auth);
    Ok(out)
}

/// Build the `VERIFY_OTP_PIN` data field, matching the Token2 reference client:
///
/// ```text
/// PinHash      = SHA256(pin)                         # 32 bytes
/// IV2          = SHA256(Rand)[0:16]
/// PinHashEnc   = AES-256-CBC(key = PinHash, IV2, data = Rand)   # inner, keyed by PIN
/// IV           = random(16)
/// PinHashEnc2  = AES-256-CBC(SessionEncKey, IV, PinHashEnc)     # outer, session key
/// data field   = IV || PinHashEnc2
/// ```
///
/// `rand` is the 16-byte challenge recovered from the `Lc=0x29` flag read
/// (`Rand = AES-256-CBC-dec(SessionEncKey, flag.IV, flag.EncRand)`). A `rand`
/// that is not a whole number of blocks is rejected with
/// [`EncryptError::BadLength`] — it arrives from the device, so it is not a
/// caller bug to assert on.
pub fn build_verify_pin_data(
    keys: &SessionKeys,
    pin: &[u8],
    rand: &[u8],
) -> Result<Vec<u8>, EncryptError> {
    // Inner layer: key = SHA256(pin) (32 bytes => AES-256), IV = SHA256(rand)[:16].
    // Both derive straight from the PIN, so both are wiped on the way out.
    let pin_hash = Zeroizing::new(sha256(pin));
    let iv2_full = sha256(rand);
    let mut iv2 = [0u8; 16];
    iv2.copy_from_slice(&iv2_full[..16]);
    // Encrypt exactly the 16-byte Rand (no padding: it is already one block).
    let inner = aes256_cbc_encrypt_nopad(&pin_hash, &iv2, rand)?;

    // Outer layer under the session key with a fresh IV.
    let iv = random_iv();
    let outer = aes256_cbc_encrypt_nopad(&keys.enc, &iv, &inner)?;

    let mut out = Vec::with_capacity(16 + outer.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(&outer);
    Ok(out)
}

/// Build the `CHANGE_OTP_PIN` data field, matching the Token2 reference client:
///
/// ```text
/// body           = 0x07 || max_retry || len(newPin) || newPin      # newPin empty => remove
/// body           = PKCS#7 pad to 16
/// IV             = random(16)
/// NewPinEnc      = AES-256-CBC(SessionEncKey, IV, body)
/// OldPinHash     = SHA256(oldPin)[0:16]
/// OldPinHashEnc  = AES-256-CBC(SessionEncKey, IV, OldPinHash)       # SAME IV
/// NewPinAuth     = HMAC(SessionMacKey, NewPinEnc || OldPinHashEnc)[0:16]
/// data field     = IV || NewPinEnc || NewPinAuth || OldPinHashEnc
/// ```
///
/// Note the single IV shared by `NewPinEnc` and `OldPinHashEnc`: that is what
/// the reference client sends and what the applet expects, so it is not a
/// choice we can make differently. It is recorded here as a protocol caveat —
/// CBC under one key with one IV means identical first blocks encrypt
/// identically, which is why the *old* PIN is hashed before it is encrypted.
///
/// `rand` is read from the same `Lc=0x29` challenge round trip that `verify`
/// uses, but nothing in the block above binds it: the change proof authenticates
/// the new PIN block and the old PIN hash, not the device's fresh challenge.
/// The argument is kept so the signature does not have to change if the binding
/// turns out to be required.
// TODO(token2): confirm whether the change proof must bind Rand. If it must,
// the block layout above is incomplete and CHANGE is replayable within a
// session; if it must not, the transport's challenge read before a change can
// go away entirely.
pub fn build_change_pin_data(
    keys: &SessionKeys,
    new_pin: &[u8],
    current_pin: &[u8],
    _rand: &[u8],
) -> Result<Vec<u8>, EncryptError> {
    // One length byte, as in SET: a longer PIN cannot be expressed here.
    let new_len = u8::try_from(new_pin.len()).map_err(|_| EncryptError::BadLength)?;
    let mut body = Zeroizing::new(Vec::with_capacity(3 + new_pin.len()));
    body.push(PIN_ALG_AES256);
    // The max-retry byte is rewritten by every change, so a device configured
    // with a non-default counter is reset to the default here. We keep the
    // reference client's fixed value because nothing in the protocol material
    // we have says whether the applet would honour a different one, and a wrong
    // guess writes a smaller retry budget onto a live key. See TODO above.
    body.push(PIN_DEFAULT_MAX_RETRY);
    body.push(new_len);
    body.extend_from_slice(new_pin);
    let body = pkcs7_pad16(&body);

    let iv = random_iv();
    let new_pin_enc = aes256_cbc_encrypt_nopad(&keys.enc, &iv, &body)?;

    let old_hash_full = Zeroizing::new(sha256(current_pin));
    let old_pin_hash = &old_hash_full[..16]; // 16 bytes, one block
    let old_pin_hash_enc = aes256_cbc_encrypt_nopad(&keys.enc, &iv, old_pin_hash)?;

    let mut mac_input = Vec::with_capacity(new_pin_enc.len() + old_pin_hash_enc.len());
    mac_input.extend_from_slice(&new_pin_enc);
    mac_input.extend_from_slice(&old_pin_hash_enc);
    let new_pin_auth = session_auth_tag(&keys.mac, &mac_input);

    let mut out = Vec::new();
    out.extend_from_slice(&iv);
    out.extend_from_slice(&new_pin_enc);
    out.extend_from_slice(&new_pin_auth);
    out.extend_from_slice(&old_pin_hash_enc);
    Ok(out)
}

/// SHA-256 convenience.
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// AES-256-CBC encrypt data that is already a whole number of 16-byte blocks,
/// with NO padding added. Misaligned or empty input is an
/// [`EncryptError::BadLength`], not a panic: one caller feeds this a challenge
/// the device chose.
fn aes256_cbc_encrypt_nopad(
    key: &[u8; 32],
    iv: &[u8; 16],
    data: &[u8],
) -> Result<Vec<u8>, EncryptError> {
    if data.is_empty() || data.len() % 16 != 0 {
        return Err(EncryptError::BadLength);
    }
    let mut buf = data.to_vec();
    let n = buf.len();
    // encrypt_padded_mut with NoPadding requires buf already block-aligned.
    Ok(Aes256CbcEnc::new(key.into(), iv.into())
        .encrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf, n)
        .map_err(|_| EncryptError::BadLength)?
        .to_vec())
}

/// PKCS#7 pad to a 16-byte boundary (always adds 1..=16 bytes). The result is
/// wiped on drop — its only caller pads a block holding a cleartext PIN.
fn pkcs7_pad16(data: &[u8]) -> Zeroizing<Vec<u8>> {
    let n = 16 - (data.len() % 16);
    let mut out = Zeroizing::new(data.to_vec());
    out.extend(std::iter::repeat_n(n as u8, n));
    out
}

fn random_iv() -> [u8; 16] {
    use rand_core::RngCore;
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);
    iv
}

/// The PIN session crypto, pinned byte-for-byte.
///
/// No R3.4 key was available while this was written, so these tests are the
/// only oracle the layout has: they fix what keyroost sends, so a later change
/// to the ladder or to any data field has to be a deliberate, argued one rather
/// than a silent re-framing. Each builder is checked by taking the device's
/// side — deriving the same keys, decrypting what was sent, and comparing the
/// recovered plaintext against the exact bytes the protocol calls for.
#[cfg(test)]
mod pin_crypto_tests {
    use super::*;
    use cbc::cipher::block_padding::NoPadding;

    /// Two fixed scalars, so the whole ladder is deterministic. Values chosen
    /// only for being valid, in-range P-256 private keys.
    const HOST_SCALAR: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ];
    const DEVICE_SCALAR: [u8; 32] = [
        0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE,
        0xBF, 0xC0,
    ];

    fn fixed_pair() -> (SecretKey, Vec<u8>) {
        let host = SecretKey::from_slice(&HOST_SCALAR).expect("valid P-256 scalar");
        let device = SecretKey::from_slice(&DEVICE_SCALAR).expect("valid P-256 scalar");
        let pt = device.public_key().to_encoded_point(false);
        (host, pt.as_bytes()[1..].to_vec())
    }

    fn fixed_keys() -> SessionKeys {
        let (host, device_xy) = fixed_pair();
        derive_session_keys(&host, &device_xy).expect("fixed vector must derive")
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Decrypt as the device would: session key, caller's IV, no unpadding.
    fn dec_nopad(key: &[u8; 32], iv: &[u8; 16], ct: &[u8]) -> Vec<u8> {
        let mut buf = ct.to_vec();
        Aes256CbcDec::new(key.into(), iv.into())
            .decrypt_padded_mut::<NoPadding>(&mut buf)
            .expect("block-aligned")
            .to_vec()
    }

    #[test]
    fn session_key_ladder_against_a_fixed_ecdh_vector() {
        let keys = fixed_keys();
        // Pinned from the ladder as documented on `SessionKeys`:
        //   pu1PRKey      = HMAC(0x00*32, sharedX)
        //   SessionEncKey = HMAC(pu1PRKey, "TOTP AES key"  || 0x01)
        //   SessionMacKey = HMAC(pu1PRKey, "TOTP HMAC key" || 0x01)
        assert_eq!(
            hex(&*keys.enc),
            "6dd62146130f4f4a162b48ac4e222a6536eccdaac56008d020390e74c5efa9b8"
        );
        assert_eq!(
            hex(&*keys.mac),
            "175cdcb14128c03413a80403459b512fd5f23d71533276e991a25503ac77a091"
        );
    }

    #[test]
    fn the_ladder_is_a_real_ecdh_both_sides_can_walk() {
        // The device runs the same ladder from its own private key and the
        // host's public half; if the two disagree, nothing decrypts on-device.
        let (host, device_xy) = fixed_pair();
        let device = SecretKey::from_slice(&DEVICE_SCALAR).unwrap();
        let host_pt = host.public_key().to_encoded_point(false);
        let host_xy = &host_pt.as_bytes()[1..];

        let from_host = derive_session_keys(&host, &device_xy).unwrap();
        let from_device = derive_session_keys(&device, host_xy).unwrap();
        assert_eq!(*from_host.enc, *from_device.enc);
        assert_eq!(*from_host.mac, *from_device.mac);
    }

    #[test]
    fn agreement_public_half_is_the_raw_xy_the_command_wants() {
        let a = HostAgreement::new();
        // 64 bytes, no SEC1 0x04 tag, and a real point (the device rebuilds it).
        assert_eq!(a.public_xy().len(), 64);
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..].copy_from_slice(a.public_xy());
        assert!(PublicKey::from_sec1_bytes(&sec1).is_ok());
        // A wrong-length device answer is rejected, not assumed. (SessionKeys
        // has no Debug/PartialEq on purpose — key material does not print.)
        assert!(matches!(
            a.establish_session(&[0u8; 63]),
            Err(EncryptError::BadDevicePubkey)
        ));
    }

    #[test]
    fn set_pin_data_field_layout() {
        let keys = fixed_keys();
        let pin = b"246813";
        let out = build_set_pin_data(&keys, pin, PIN_DEFAULT_MAX_RETRY).unwrap();

        // IV(16) || NewPinEnc(32: a 9-byte block PKCS#7-padded to 16 -> 16) || auth(16)
        assert_eq!(out.len(), 16 + 16 + 16, "IV || NewPinEnc || NewPinAuth");
        let iv: [u8; 16] = out[..16].try_into().unwrap();
        let enc = &out[16..32];
        let auth = &out[32..];

        // The cleartext block, byte for byte: AlgId, retry, len, pin, PKCS#7.
        let plain = dec_nopad(&keys.enc, &iv, enc);
        assert_eq!(
            plain,
            vec![
                0x07, // AlgId = AES256
                0x64, // max retry
                0x06, // pin length
                b'2', b'4', b'6', b'8', b'1', b'3', // the PIN
                0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, // PKCS#7 to 16
            ]
        );
        assert_eq!(auth, session_auth_tag(&keys.mac, enc));
    }

    #[test]
    fn verify_pin_data_field_is_the_two_layer_proof() {
        let keys = fixed_keys();
        let pin = b"246813";
        let rand = [0x5Au8; 16];
        let out = build_verify_pin_data(&keys, pin, &rand).unwrap();

        assert_eq!(out.len(), 16 + 16, "IV || PinHashEnc2");
        let iv: [u8; 16] = out[..16].try_into().unwrap();

        // Outer layer off with the session key…
        let inner = dec_nopad(&keys.enc, &iv, &out[16..]);
        // …inner layer off with the key the PIN itself derives, IV = SHA256(Rand)[:16].
        let pin_key = sha256(pin);
        let iv2_full = sha256(&rand);
        let iv2: [u8; 16] = iv2_full[..16].try_into().unwrap();
        let recovered = dec_nopad(&pin_key, &iv2, &inner);
        // What the device gets back is exactly its own challenge — the proof.
        assert_eq!(recovered, rand.to_vec());
    }

    #[test]
    fn change_pin_data_field_layout() {
        let keys = fixed_keys();
        let out = build_change_pin_data(&keys, b"975312", b"246813", &[0u8; 16]).unwrap();

        // IV(16) || NewPinEnc(16) || NewPinAuth(16) || OldPinHashEnc(16)
        assert_eq!(out.len(), 64);
        let iv: [u8; 16] = out[..16].try_into().unwrap();
        let new_pin_enc = &out[16..32];
        let auth = &out[32..48];
        let old_hash_enc = &out[48..64];

        assert_eq!(
            dec_nopad(&keys.enc, &iv, new_pin_enc),
            vec![
                0x07, 0x64, 0x06, b'9', b'7', b'5', b'3', b'1', b'2', //
                0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
            ]
        );
        // The old PIN goes over as SHA256(old)[:16], never in the clear.
        assert_eq!(
            dec_nopad(&keys.enc, &iv, old_hash_enc),
            sha256(b"246813")[..16].to_vec()
        );
        // The tag covers both ciphertexts, in that order.
        let mut mac_input = new_pin_enc.to_vec();
        mac_input.extend_from_slice(old_hash_enc);
        assert_eq!(auth, session_auth_tag(&keys.mac, &mac_input));
    }

    #[test]
    fn removing_a_pin_is_a_change_to_length_zero() {
        let keys = fixed_keys();
        let out = build_change_pin_data(&keys, b"", b"246813", &[0u8; 16]).unwrap();
        let iv: [u8; 16] = out[..16].try_into().unwrap();
        // 3-byte body pads to one block; length byte says 0 => no PIN.
        assert_eq!(
            dec_nopad(&keys.enc, &iv, &out[16..32]),
            vec![0x07, 0x64, 0x00, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13]
        );
    }

    #[test]
    fn the_change_proof_does_not_bind_rand() {
        // Pins the behaviour the code actually has, so the open question stays
        // visible: two changes differing only in the device challenge produce
        // the same protected content. See the TODO on `build_change_pin_data`.
        let keys = fixed_keys();
        let a = build_change_pin_data(&keys, b"975312", b"246813", &[0x11u8; 16]).unwrap();
        let b = build_change_pin_data(&keys, b"975312", b"246813", &[0x22u8; 16]).unwrap();
        // The IVs differ (they are random), so compare what is under them.
        let iv_a: [u8; 16] = a[..16].try_into().unwrap();
        let iv_b: [u8; 16] = b[..16].try_into().unwrap();
        assert_eq!(
            dec_nopad(&keys.enc, &iv_a, &a[16..32]),
            dec_nopad(&keys.enc, &iv_b, &b[16..32]),
        );
    }

    #[test]
    fn protected_write_data_field_layout() {
        let keys = fixed_keys();
        let cleartext = [0xABu8; 23];
        let out = build_protected_write_data(&keys, &cleartext);

        // IV(16) || AES-CBC(EncKey, IV, pt)(32 after PKCS#7) || HMAC[:16]
        assert_eq!(out.len(), 16 + 32 + 16);
        let iv: [u8; 16] = out[..16].try_into().unwrap();
        let enc = &out[16..48];
        assert_eq!(&out[48..], &session_auth_tag(&keys.mac, enc)[..]);
        let plain = session_decrypt(&keys.enc, &iv, enc).unwrap();
        assert_eq!(&*plain, &cleartext[..]);
    }

    #[test]
    fn a_tag_over_other_bytes_does_not_verify() {
        let keys = fixed_keys();
        let tag = session_auth_tag(&keys.mac, b"page");
        assert!(verify_auth_tag(&keys.mac, b"page", &tag).is_ok());
        assert_eq!(
            verify_auth_tag(&keys.mac, b"pagf", &tag),
            Err(EncryptError::BadAuthTag)
        );
        // A short tag is refused rather than compared against a prefix.
        assert_eq!(
            verify_auth_tag(&keys.mac, b"page", &tag[..15]),
            Err(EncryptError::BadAuthTag)
        );
    }

    #[test]
    fn out_of_range_inputs_are_errors_not_panics() {
        // These builders are public API on a published crate, and both of the
        // values below can arrive from the other end of a cable.
        let keys = fixed_keys();
        let long = vec![b'1'; 256];
        assert_eq!(
            build_set_pin_data(&keys, &long, 0x64),
            Err(EncryptError::BadLength)
        );
        assert_eq!(
            build_change_pin_data(&keys, &long, b"246813", &[0u8; 16]),
            Err(EncryptError::BadLength)
        );
        // A challenge that is not a whole AES block (device-supplied).
        for bad in [&[][..], &[0u8; 15][..], &[0u8; 17][..]] {
            assert_eq!(
                build_verify_pin_data(&keys, b"246813", bad),
                Err(EncryptError::BadLength)
            );
        }
    }

    #[test]
    fn session_decrypt_rejects_misaligned_or_empty_input() {
        let keys = fixed_keys();
        assert_eq!(
            session_decrypt(&keys.enc, &[0u8; 16], &[]),
            Err(EncryptError::BadCiphertext)
        );
        assert_eq!(
            session_decrypt(&keys.enc, &[0u8; 16], &[0u8; 17]),
            Err(EncryptError::BadCiphertext)
        );
        // The unpadded form used for Rand answers empty rather than panicking.
        assert!(session_decrypt_raw(&keys.enc, &[0u8; 16], &[0u8; 17]).is_empty());
    }
}
