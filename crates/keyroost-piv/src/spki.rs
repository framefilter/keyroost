//! Build a DER `SubjectPublicKeyInfo` from a card-returned [`PublicKey`].
//!
//! GENERATE ASYMMETRIC KEY PAIR returns a raw public key (RSA modulus/exponent,
//! or an EC point). To be useful — handed to a CA, fed to `openssl`, turned into
//! a self-signed cert — it needs wrapping in the standard `SubjectPublicKeyInfo`
//! ASN.1 structure. This is a tiny, dependency-free DER encoder for exactly that
//! shape; PEM wrapping (base64 + armor) is the caller's job.

use crate::{KeyAlg, PublicKey};

/// Errors building an SPKI.
#[derive(Debug, PartialEq, Eq)]
pub enum SpkiError {
    /// The [`PublicKey`] variant doesn't match the [`KeyAlg`] (e.g. an EC point
    /// for an RSA algorithm).
    KeyTypeMismatch,
}

impl core::fmt::Display for SpkiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SpkiError::KeyTypeMismatch => write!(f, "public key type does not match algorithm"),
        }
    }
}

impl std::error::Error for SpkiError {}

/// Encode a DER definite length.
fn der_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let mut tmp = Vec::new();
        let mut n = len;
        while n > 0 {
            tmp.push((n & 0xFF) as u8);
            n >>= 8;
        }
        tmp.reverse();
        out.push(0x80 | tmp.len() as u8);
        out.extend_from_slice(&tmp);
    }
}

/// Encode a DER `tag length value` element.
fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 4);
    out.push(tag);
    der_len(&mut out, value.len());
    out.extend_from_slice(value);
    out
}

/// DER SEQUENCE (tag 0x30) over already-encoded members.
fn der_seq(members: &[&[u8]]) -> Vec<u8> {
    let mut body = Vec::new();
    for m in members {
        body.extend_from_slice(m);
    }
    der_tlv(0x30, &body)
}

/// DER unsigned INTEGER (tag 0x02): strip leading zeros, then prepend one `0x00`
/// if the top bit is set so the value stays positive.
fn der_uint(bytes: &[u8]) -> Vec<u8> {
    let mut v = bytes;
    while v.len() > 1 && v[0] == 0 {
        v = &v[1..];
    }
    // A card could hand back an empty key component; DER has no zero-length
    // INTEGER, so encode the canonical zero rather than emit invalid DER.
    if v.is_empty() {
        v = &[0x00];
    }
    let mut value = Vec::with_capacity(v.len() + 1);
    if v.first().is_some_and(|&b| b & 0x80 != 0) {
        value.push(0x00);
    }
    value.extend_from_slice(v);
    der_tlv(0x02, &value)
}

/// DER BIT STRING (tag 0x03) with zero unused bits.
fn der_bitstring(bytes: &[u8]) -> Vec<u8> {
    let mut value = Vec::with_capacity(bytes.len() + 1);
    value.push(0x00); // unused-bits count
    value.extend_from_slice(bytes);
    der_tlv(0x03, &value)
}

// Pre-encoded OBJECT IDENTIFIER DER (tag 0x06 included).
const OID_RSA_ENCRYPTION: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
];
const OID_EC_PUBLIC_KEY: &[u8] = &[0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const OID_P256: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const OID_P384: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];
const OID_ED25519: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x70];
const OID_X25519: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x6E];
const DER_NULL: &[u8] = &[0x05, 0x00];

/// Build the DER `SubjectPublicKeyInfo` for a card-returned public key.
pub fn subject_public_key_info(key: &PublicKey, alg: KeyAlg) -> Result<Vec<u8>, SpkiError> {
    match (key, alg) {
        (PublicKey::Rsa { modulus, exponent }, KeyAlg::Rsa1024)
        | (PublicKey::Rsa { modulus, exponent }, KeyAlg::Rsa2048)
        | (PublicKey::Rsa { modulus, exponent }, KeyAlg::Rsa3072)
        | (PublicKey::Rsa { modulus, exponent }, KeyAlg::Rsa4096) => {
            let alg_id = der_seq(&[OID_RSA_ENCRYPTION, DER_NULL]);
            let rsa_pub = der_seq(&[&der_uint(modulus), &der_uint(exponent)]);
            let spk = der_bitstring(&rsa_pub);
            Ok(der_seq(&[&alg_id, &spk]))
        }
        (PublicKey::Ecc { point }, KeyAlg::EccP256) => Ok(ec_spki(OID_P256, point)),
        (PublicKey::Ecc { point }, KeyAlg::EccP384) => Ok(ec_spki(OID_P384, point)),
        (PublicKey::Ecc { point }, KeyAlg::Ed25519) => Ok(eddsa_spki(OID_ED25519, point)),
        (PublicKey::Ecc { point }, KeyAlg::X25519) => Ok(eddsa_spki(OID_X25519, point)),
        _ => Err(SpkiError::KeyTypeMismatch),
    }
}

/// SPKI for a NIST EC key: AlgorithmIdentifier { ecPublicKey, namedCurve }.
fn ec_spki(curve_oid: &[u8], point: &[u8]) -> Vec<u8> {
    let alg_id = der_seq(&[OID_EC_PUBLIC_KEY, curve_oid]);
    let spk = der_bitstring(point);
    der_seq(&[&alg_id, &spk])
}

/// SPKI for Ed25519/X25519: AlgorithmIdentifier { curveOid } (no params).
fn eddsa_spki(oid: &[u8], point: &[u8]) -> Vec<u8> {
    let alg_id = der_seq(&[oid]);
    let spk = der_bitstring(point);
    der_seq(&[&alg_id, &spk])
}

/// PEM-armor a DER `SubjectPublicKeyInfo` as a `PUBLIC KEY` block.
pub fn to_pem(spki_der: &[u8]) -> String {
    let b64 = keyroost_proto::codec::base64_encode(spki_der);
    let mut out = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(core::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str("-----END PUBLIC KEY-----\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_uint_prepends_zero_for_high_bit() {
        assert_eq!(der_uint(&[0xFF, 0x01]), vec![0x02, 0x03, 0x00, 0xFF, 0x01]);
        assert_eq!(der_uint(&[0x7F]), vec![0x02, 0x01, 0x7F]);
        // strips leading zeros
        assert_eq!(der_uint(&[0x00, 0x00, 0x01]), vec![0x02, 0x01, 0x01]);
    }

    #[test]
    fn der_uint_empty_and_zero_encode_canonical_zero() {
        // An empty component (possible from a malformed card response) must not
        // produce a zero-length INTEGER, which is invalid DER.
        assert_eq!(der_uint(&[]), vec![0x02, 0x01, 0x00]);
        assert_eq!(der_uint(&[0x00]), vec![0x02, 0x01, 0x00]);
        assert_eq!(der_uint(&[0x00, 0x00]), vec![0x02, 0x01, 0x00]);
    }

    #[test]
    fn ed25519_spki_known_answer() {
        // AlgorithmIdentifier { 1.3.101.112 }, BIT STRING over a 32-byte point.
        let point = vec![0x11u8; 32];
        let der = subject_public_key_info(
            &PublicKey::Ecc {
                point: point.clone(),
            },
            KeyAlg::Ed25519,
        )
        .unwrap();
        let mut expected = vec![0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70];
        expected.extend_from_slice(&[0x03, 0x21, 0x00]);
        expected.extend_from_slice(&point);
        assert_eq!(der, expected);
    }

    #[test]
    fn x25519_spki_uses_x25519_oid() {
        let der = subject_public_key_info(
            &PublicKey::Ecc {
                point: vec![0x22; 32],
            },
            KeyAlg::X25519,
        )
        .unwrap();
        assert!(der.windows(OID_X25519.len()).any(|w| w == OID_X25519));
        assert!(!der.windows(OID_ED25519.len()).any(|w| w == OID_ED25519));
    }

    #[test]
    fn pem_known_answer() {
        // base64("hello") == "aGVsbG8=" — locks alphabet, padding, and armor.
        assert_eq!(
            to_pem(b"hello"),
            "-----BEGIN PUBLIC KEY-----\naGVsbG8=\n-----END PUBLIC KEY-----\n"
        );
    }

    #[test]
    fn der_len_long_form() {
        let mut out = Vec::new();
        der_len(&mut out, 256);
        assert_eq!(out, vec![0x82, 0x01, 0x00]);
        let mut out = Vec::new();
        der_len(&mut out, 200);
        assert_eq!(out, vec![0x81, 0xC8]);
    }

    #[test]
    fn rsa_spki_structure() {
        // tiny modulus/exponent to check the framing, not a real key
        let key = PublicKey::Rsa {
            modulus: vec![0xC1, 0x00, 0x05],
            exponent: vec![0x01, 0x00, 0x01],
        };
        let der = subject_public_key_info(&key, KeyAlg::Rsa2048).unwrap();
        assert_eq!(der[0], 0x30); // outer SEQUENCE
                                  // contains the rsaEncryption OID
        assert!(der
            .windows(OID_RSA_ENCRYPTION.len())
            .any(|w| w == OID_RSA_ENCRYPTION));
    }

    #[test]
    fn ec_p256_spki_contains_curve_oid_and_point() {
        let point = {
            let mut p = vec![0x04];
            p.extend(std::iter::repeat(0xAB).take(64));
            p
        };
        let der = subject_public_key_info(
            &PublicKey::Ecc {
                point: point.clone(),
            },
            KeyAlg::EccP256,
        )
        .unwrap();
        assert!(der.windows(OID_P256.len()).any(|w| w == OID_P256));
        assert!(der
            .windows(OID_EC_PUBLIC_KEY.len())
            .any(|w| w == OID_EC_PUBLIC_KEY));
        // the uncompressed point appears verbatim
        assert!(der.windows(point.len()).any(|w| w == point.as_slice()));
    }

    #[test]
    fn mismatch_is_error() {
        let key = PublicKey::Ecc {
            point: vec![0x04, 1, 2],
        };
        assert_eq!(
            subject_public_key_info(&key, KeyAlg::Rsa2048),
            Err(SpkiError::KeyTypeMismatch)
        );
    }

    #[test]
    fn pem_armor_wraps_64_columns() {
        let pem = to_pem(&[0xAB; 100]);
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert!(pem.trim_end().ends_with("-----END PUBLIC KEY-----"));
        for line in pem.lines().filter(|l| !l.starts_with("-----")) {
            assert!(line.len() <= 64);
        }
    }
}
