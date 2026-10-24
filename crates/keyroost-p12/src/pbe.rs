//! Decryption of the password-based encryption schemes found in PKCS#12
//! files: the legacy PKCS#12 PBEs (3DES, RC2-40, RC2-128 under the SHA-1 KDF)
//! and PBES2 (PBKDF2 with AES-CBC).

use aes::{Aes128, Aes192, Aes256};
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::typenum::Unsigned;
use cbc::cipher::{BlockCipher, BlockDecryptMut, InnerIvInit, KeyIvInit};
use des::TdesEde3;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::ber::{children, Tlv};
use crate::kdf::{bmp_password, pkcs12_kdf, Hash};
use crate::P12Error;

/// Most KDF iterations accepted for one derivation; a hostile file could
/// otherwise stall us.
pub(crate) const MAX_ITERATIONS: u32 = if cfg!(fuzzing) { 1_000 } else { 10_000_000 };

/// Most KDF iterations one [`crate::open`] call runs in total, across every
/// encrypted part, the MAC and both empty-password candidates: a file with
/// many bags must not add up to a stall either.
pub(crate) const WORK_BUDGET: u64 = if cfg!(fuzzing) { 10_000 } else { 20_000_000 };

/// The [`P12Error::Unsupported`] text for a file that asks for more key
/// derivation than one [`crate::open`] call runs (20,000,000 iterations in
/// all).
pub const TOO_MUCH_WORK: &str = "too much password-hashing work";

/// What is left of [`WORK_BUDGET`]. Each derivation is charged before it
/// runs, so an over-budget file is refused without doing the work.
pub(crate) struct Work {
    left: u64,
}

impl Work {
    pub(crate) fn new() -> Self {
        Self::with_budget(WORK_BUDGET)
    }

    pub(crate) fn with_budget(left: u64) -> Self {
        Self { left }
    }

    /// How much of the budget is left.
    #[cfg(test)]
    pub(crate) fn left(&self) -> u64 {
        self.left
    }

    /// Charge one derivation of `iterations` rounds.
    pub(crate) fn spend(&mut self, iterations: u32) -> Result<(), P12Error> {
        let n = u64::from(iterations);
        if n > self.left {
            return Err(P12Error::Unsupported(TOO_MUCH_WORK));
        }
        self.left -= n;
        Ok(())
    }
}

// DER-encoded OID contents.
const PBE_3DES: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x03];
const PBE_RC2_128: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x05];
const PBE_RC2_40: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x06];
const PBES2: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d];
const PBKDF2: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c];
const HMAC_SHA1: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x07];
const HMAC_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09];
const AES128_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02];
const AES192_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x16];
const AES256_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a];

const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;

/// An OCTET STRING, primitive or BER-constructed (already joined by the reader).
fn is_octets(t: &Tlv<'_>) -> bool {
    t.tag == TAG_OCTET_STRING || t.tag == 0x24
}
const TAG_OID: u8 = 0x06;
const TAG_SEQUENCE: u8 = 0x30;

fn bad(what: &'static str) -> P12Error {
    P12Error::Malformed(what)
}

/// An AlgorithmIdentifier: its OID bytes and its parameters, if any.
struct AlgId<'a> {
    oid: &'a [u8],
    params: Option<&'a Tlv<'a>>,
}

fn alg_id<'a>(kids: &'a [Tlv<'a>]) -> Result<AlgId<'a>, P12Error> {
    let oid = kids
        .first()
        .ok_or_else(|| bad("empty algorithm identifier"))?;
    if oid.tag != TAG_OID {
        return Err(bad("algorithm identifier does not start with an OID"));
    }
    if kids.len() > 2 {
        return Err(bad("algorithm identifier has extra fields"));
    }
    Ok(AlgId {
        oid: &oid.value,
        params: kids.get(1),
    })
}

/// A small non-negative INTEGER as `u32` (values past `u32::MAX` clamp to it,
/// which the callers' limits then reject).
fn small_uint(t: &Tlv<'_>) -> Result<u32, P12Error> {
    if t.tag != TAG_INTEGER || t.value.is_empty() {
        return Err(bad("expected an INTEGER"));
    }
    if t.value[0] & 0x80 != 0 {
        return Err(bad("negative INTEGER"));
    }
    let mut n: u64 = 0;
    for &b in t.value.iter() {
        n = (n << 8) | u64::from(b);
        if n > u64::from(u32::MAX) {
            return Ok(u32::MAX);
        }
    }
    Ok(n as u32)
}

fn check_iterations(n: u32) -> Result<u32, P12Error> {
    if n == 0 {
        return Err(bad("zero iteration count"));
    }
    if n > MAX_ITERATIONS {
        return Err(P12Error::Unsupported("iteration count above 10,000,000"));
    }
    Ok(n)
}

/// Decrypt `ciphertext` under the scheme named by `alg` (an AlgorithmIdentifier
/// SEQUENCE), charging the key derivation to `work`. A padding failure reads
/// as a wrong password.
pub(crate) fn decrypt(
    alg: &Tlv<'_>,
    ciphertext: &[u8],
    password: Option<&str>,
    work: &mut Work,
) -> Result<Zeroizing<Vec<u8>>, P12Error> {
    if alg.tag != TAG_SEQUENCE {
        return Err(bad("algorithm identifier is not a SEQUENCE"));
    }
    let kids = children(&alg.value)?;
    let id = alg_id(&kids)?;
    if id.oid == PBES2 {
        return decrypt_pbes2(id.params, ciphertext, password, work);
    }
    let legacy = match id.oid {
        o if o == PBE_3DES => Legacy::TripleDes,
        o if o == PBE_RC2_128 => Legacy::Rc2(128),
        o if o == PBE_RC2_40 => Legacy::Rc2(40),
        _ => return Err(P12Error::Unsupported("encryption algorithm")),
    };
    decrypt_legacy(legacy, id.params, ciphertext, password, work)
}

#[derive(Clone, Copy)]
enum Legacy {
    TripleDes,
    /// RC2 with this many effective (and key) bits.
    Rc2(usize),
}

fn decrypt_legacy(
    scheme: Legacy,
    params: Option<&Tlv<'_>>,
    ciphertext: &[u8],
    password: Option<&str>,
    work: &mut Work,
) -> Result<Zeroizing<Vec<u8>>, P12Error> {
    let params = params.ok_or_else(|| bad("missing PBE parameters"))?;
    if params.tag != TAG_SEQUENCE {
        return Err(bad("PBE parameters are not a SEQUENCE"));
    }
    let kids = children(&params.value)?;
    let (salt, iter) = match kids.as_slice() {
        [salt, iter] if is_octets(salt) => (salt, iter),
        _ => return Err(bad("PBE parameters are not (salt, iterations)")),
    };
    let iterations = check_iterations(small_uint(iter)?)?;

    let key_len = match scheme {
        Legacy::TripleDes => 24,
        Legacy::Rc2(bits) => bits / 8,
    };
    // Two derivations: the key and the IV.
    work.spend(iterations)?;
    work.spend(iterations)?;
    let pw = bmp_password(password);
    let key = pkcs12_kdf(Hash::Sha1, &pw, &salt.value, 1, iterations, key_len);
    let iv = pkcs12_kdf(Hash::Sha1, &pw, &salt.value, 2, iterations, 8);

    match scheme {
        Legacy::TripleDes => cbc_decrypt::<TdesEde3>(&key, &iv, ciphertext),
        Legacy::Rc2(bits) => {
            let cipher = rc2::Rc2::new_with_eff_key_len(&key, bits);
            let dec = cbc::Decryptor::<rc2::Rc2>::inner_iv_slice_init(cipher, &iv)
                .map_err(|_| bad("bad IV length"))?;
            finish(dec, ciphertext)
        }
    }
}

fn decrypt_pbes2(
    params: Option<&Tlv<'_>>,
    ciphertext: &[u8],
    password: Option<&str>,
    work: &mut Work,
) -> Result<Zeroizing<Vec<u8>>, P12Error> {
    let params = params.ok_or_else(|| bad("missing PBES2 parameters"))?;
    if params.tag != TAG_SEQUENCE {
        return Err(bad("PBES2 parameters are not a SEQUENCE"));
    }
    let kids = children(&params.value)?;
    let [kdf_alg, enc_alg] = kids.as_slice() else {
        return Err(bad("PBES2 parameters are not (kdf, cipher)"));
    };
    if kdf_alg.tag != TAG_SEQUENCE || enc_alg.tag != TAG_SEQUENCE {
        return Err(bad("PBES2 algorithm is not a SEQUENCE"));
    }

    // Cipher: AES-CBC with a 16-byte IV.
    let enc_kids = children(&enc_alg.value)?;
    let enc = alg_id(&enc_kids)?;
    let aes_key_len = match enc.oid {
        o if o == AES128_CBC => 16,
        o if o == AES192_CBC => 24,
        o if o == AES256_CBC => 32,
        _ => return Err(P12Error::Unsupported("PBES2 cipher")),
    };
    let iv = match enc.params {
        Some(t) if is_octets(t) && t.value.len() == 16 => &t.value,
        _ => return Err(bad("PBES2 cipher IV is not 16 bytes")),
    };

    // Key derivation: PBKDF2 with hmacWithSHA1 (default) or hmacWithSHA256.
    let kdf_kids = children(&kdf_alg.value)?;
    let kdf = alg_id(&kdf_kids)?;
    if kdf.oid != PBKDF2 {
        return Err(P12Error::Unsupported("PBES2 key derivation"));
    }
    let kp = kdf.params.ok_or_else(|| bad("missing PBKDF2 parameters"))?;
    if kp.tag != TAG_SEQUENCE {
        return Err(bad("PBKDF2 parameters are not a SEQUENCE"));
    }
    let kp_kids = children(&kp.value)?;
    let mut fields = kp_kids.iter();
    let salt = fields
        .next()
        .filter(|t| is_octets(t))
        .ok_or_else(|| bad("PBKDF2 salt missing"))?;
    let iterations = check_iterations(small_uint(
        fields
            .next()
            .ok_or_else(|| bad("PBKDF2 iterations missing"))?,
    )?)?;
    let mut rest = fields.peekable();
    if let Some(t) = rest.next_if(|t| t.tag == TAG_INTEGER) {
        if usize::try_from(small_uint(t)?).ok() != Some(aes_key_len) {
            return Err(bad("PBKDF2 key length does not match the cipher"));
        }
    }
    let mut prf = Hash::Sha1;
    if let Some(t) = rest.next_if(|t| t.tag == TAG_SEQUENCE) {
        let prf_kids = children(&t.value)?;
        let p = alg_id(&prf_kids)?;
        prf = match p.oid {
            o if o == HMAC_SHA1 => Hash::Sha1,
            o if o == HMAC_SHA256 => Hash::Sha256,
            _ => return Err(P12Error::Unsupported("PBKDF2 hash")),
        };
    }
    if rest.next().is_some() {
        return Err(bad("unexpected PBKDF2 parameter"));
    }

    work.spend(iterations)?;
    // PBES2 uses the password as plain UTF-8, not a BMPString.
    let pw = Zeroizing::new(password.unwrap_or("").as_bytes().to_vec());
    let key = match prf {
        Hash::Sha1 => Zeroizing::new(keyroost_oath::crypto::pbkdf2_hmac_sha1(
            &pw,
            &salt.value,
            iterations,
            aes_key_len,
        )),
        Hash::Sha256 => {
            let mut k = Zeroizing::new(vec![0u8; aes_key_len]);
            pbkdf2::pbkdf2_hmac::<Sha256>(&pw, &salt.value, iterations, &mut k);
            k
        }
    };
    match aes_key_len {
        16 => cbc_decrypt::<Aes128>(&key, iv, ciphertext),
        24 => cbc_decrypt::<Aes192>(&key, iv, ciphertext),
        _ => cbc_decrypt::<Aes256>(&key, iv, ciphertext),
    }
}

fn cbc_decrypt<C>(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, P12Error>
where
    C: BlockCipher + cbc::cipher::BlockDecrypt + cbc::cipher::KeyInit,
{
    let dec =
        cbc::Decryptor::<C>::new_from_slices(key, iv).map_err(|_| bad("bad key or IV length"))?;
    finish(dec, ciphertext)
}

/// Run CBC decryption and strip PKCS#7 padding into a zeroizing buffer.
fn finish<D>(dec: D, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, P12Error>
where
    D: BlockDecryptMut,
{
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(D::BlockSize::USIZE) {
        return Err(bad("ciphertext is not a whole number of blocks"));
    }
    let mut buf = Zeroizing::new(ciphertext.to_vec());
    let len = dec
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|_| P12Error::WrongPassword)?
        .len();
    buf.truncate(len);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ber::read_tlv;
    use rc2::cipher::generic_array::GenericArray;
    use rc2::cipher::{BlockDecrypt, BlockEncrypt};

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    const PLAIN: &[u8] = b"hello pkcs12 world";

    fn run(alg_hex: &str, ct_hex: &str, pw: Option<&str>) -> Result<Vec<u8>, P12Error> {
        let alg = unhex(alg_hex);
        let (tlv, _) = read_tlv(&alg).unwrap();
        decrypt(&tlv, &unhex(ct_hex), pw, &mut Work::new()).map(|z| z.to_vec())
    }

    // RFC 2268 section 5: key 88bca90e90875a, 64 effective bits.
    #[test]
    fn rc2_matches_rfc2268_vector() {
        let key = unhex("88bca90e90875a");
        let cipher = rc2::Rc2::new_with_eff_key_len(&key, 64);
        let mut block = GenericArray::clone_from_slice(&[0u8; 8]);
        cipher.encrypt_block(&mut block);
        assert_eq!(block.as_slice(), unhex("6ccf4308974c267f"));
        cipher.decrypt_block(&mut block);
        assert_eq!(block.as_slice(), [0u8; 8]);
    }

    // The ciphertexts below were made with `openssl enc` using keys and IVs
    // from `openssl kdf ... PKCS12KDF` / `PBKDF2`; password "password",
    // salt 0102030405060708, 2048 iterations.
    #[test]
    fn pkcs12_3des_decrypts_openssl_ciphertext() {
        let got = run(
            "301c060a2a864886f70d010c0103300e0408010203040506070802020800",
            "1e0f7d6f125a3a2f5e7f62e8c54a6017dd4a30376431470e",
            Some("password"),
        );
        assert_eq!(got.unwrap(), PLAIN);
    }

    #[test]
    fn pkcs12_rc2_40_decrypts_openssl_ciphertext() {
        let got = run(
            "301c060a2a864886f70d010c0106300e0408010203040506070802020800",
            "2b4e87160dd6e0375b70820e2b5549b6a2f97bcb6bd2d038",
            Some("password"),
        );
        assert_eq!(got.unwrap(), PLAIN);
    }

    #[test]
    fn pkcs12_rc2_128_decrypts_openssl_ciphertext() {
        let got = run(
            "301c060a2a864886f70d010c0105300e0408010203040506070802020800",
            "feee1459dba07351b9cffcb4fe3762991739fd46e1302b3e",
            Some("password"),
        );
        assert_eq!(got.unwrap(), PLAIN);
    }

    const AES128_SHA1: &str = "304906092a864886f70d01050d303c301b06092a864886f70d01050c300e0408010203040506070802020800301d06096086480165030401020410101112131415161718191a1b1c1d1e1f";
    const AES128_SHA1_CT: &str = "12ede7d7d6a368bd63f9f90480fc142fb7f0c6de095d3aa8b0aa6956c63535ab";

    #[test]
    fn pbes2_aes128_hmac_sha1_decrypts_openssl_ciphertext() {
        assert_eq!(
            run(AES128_SHA1, AES128_SHA1_CT, Some("password")).unwrap(),
            PLAIN
        );
    }

    #[test]
    fn pbes2_aes192_hmac_sha1_decrypts_openssl_ciphertext() {
        let got = run(
            "304906092a864886f70d01050d303c301b06092a864886f70d01050c300e0408010203040506070802020800301d06096086480165030401160410101112131415161718191a1b1c1d1e1f",
            "ffd06ddfc9e8a74b78909d98c0c55152a6e43e572c1d483309c592ea22e8e419",
            Some("password"),
        );
        assert_eq!(got.unwrap(), PLAIN);
    }

    #[test]
    fn pbes2_aes256_hmac_sha256_decrypts_openssl_ciphertext() {
        let got = run(
            "305706092a864886f70d01050d304a302906092a864886f70d01050c301c0408010203040506070802020800300c06082a864886f70d02090500301d060960864801650304012a0410101112131415161718191a1b1c1d1e1f",
            "bc42349dc7556b781455e5f3f2bb421f8dcbd2493624decd7cbbc0415a72030e",
            Some("password"),
        );
        assert_eq!(got.unwrap(), PLAIN);
    }

    #[test]
    fn bad_padding_reads_as_wrong_password() {
        // Same 3DES input, wrong password: the padding check fails (a
        // one-in-256 false pass is ruled out by this fixed input).
        let got = run(
            "301c060a2a864886f70d010c0103300e0408010203040506070802020800",
            "1e0f7d6f125a3a2f5e7f62e8c54a6017dd4a30376431470e",
            Some("wrong"),
        );
        assert_eq!(got, Err(P12Error::WrongPassword));
        let got = run(AES128_SHA1, AES128_SHA1_CT, Some("wrong"));
        assert_eq!(got, Err(P12Error::WrongPassword));
    }

    #[test]
    fn unknown_oid_is_unsupported() {
        // 1.2.840.113549.1.12.1.2 (RC4-128), parameters as for the others.
        let got = run(
            "301c060a2a864886f70d010c0102300e0408010203040506070802020800",
            "00",
            Some("password"),
        );
        assert!(matches!(got, Err(P12Error::Unsupported(_))), "{got:?}");
    }

    #[test]
    fn iteration_cap_is_enforced() {
        // 3DES with 10,000,001 iterations (0x00989681).
        let got = run(
            "301e060a2a864886f70d010c0103301004080102030405060708020400989681",
            "0000000000000000",
            Some("password"),
        );
        assert_eq!(
            got,
            Err(P12Error::Unsupported("iteration count above 10,000,000"))
        );
        // PBES2 with the same count.
        let alg = AES128_SHA1.replace("02020800", "020400989681");
        let alg = fix_lengths(&alg);
        let got = run(&alg, AES128_SHA1_CT, Some("password"));
        assert_eq!(
            got,
            Err(P12Error::Unsupported("iteration count above 10,000,000"))
        );
    }

    #[test]
    fn work_is_charged_before_the_derivation_runs() {
        // 3DES at 2048 iterations costs 4096 (key and IV): one short of that
        // is refused, and nothing is left over afterwards.
        let alg = unhex("301c060a2a864886f70d010c0103300e0408010203040506070802020800");
        let (tlv, _) = read_tlv(&alg).unwrap();
        let ct = unhex("1e0f7d6f125a3a2f5e7f62e8c54a6017dd4a30376431470e");
        let pw = Some("password");
        assert_eq!(
            decrypt(&tlv, &ct, pw, &mut Work::with_budget(4095)).err(),
            Some(P12Error::Unsupported(TOO_MUCH_WORK))
        );
        let mut work = Work::with_budget(4096);
        assert_eq!(decrypt(&tlv, &ct, pw, &mut work).unwrap().to_vec(), PLAIN);
        assert_eq!(
            decrypt(&tlv, &ct, pw, &mut work).err(),
            Some(P12Error::Unsupported(TOO_MUCH_WORK))
        );
        // PBES2 at 2048 costs 2048.
        let alg = unhex(AES128_SHA1);
        let (tlv, _) = read_tlv(&alg).unwrap();
        let ct = unhex(AES128_SHA1_CT);
        assert_eq!(
            decrypt(&tlv, &ct, pw, &mut Work::with_budget(2047)).err(),
            Some(P12Error::Unsupported(TOO_MUCH_WORK))
        );
        assert!(decrypt(&tlv, &ct, pw, &mut Work::with_budget(2048)).is_ok());
    }

    /// Re-encode the fixed PBES2 shape after the iteration INTEGER grew by
    /// two bytes: every enclosing length (0x49, 0x3c, 0x1b, 0x0e) goes up by 2.
    fn fix_lengths(hex: &str) -> String {
        hex.replacen("3049", "304b", 1)
            .replacen("303c", "303e", 1)
            .replacen("301b", "301d", 1)
            .replacen("300e", "3010", 1)
    }
}
