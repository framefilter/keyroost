//! PKCS#8 PrivateKeyInfo to key parts.
//!
//! A fixed-shape walk over the BER reader: PrivateKeyInfo, then one level
//! into RSAPrivateKey or ECPrivateKey. A plaintext key bag may keep BER
//! indefinite lengths, so the reader is not DER-only.

use core::fmt;

use keyroost_piv::{KeyAlg, PublicKey};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{BigUint, RsaPrivateKey};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::ber::{children, read_tlv, Tlv};
use crate::P12Error;

const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_OID: u8 = 0x06;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_CONTEXT_0: u8 = 0xA0;

// DER-encoded OID contents.
const RSA_ENCRYPTION_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const EC_PUBLIC_KEY_OID: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const P256_OID: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const P384_OID: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const ED25519_OID: &[u8] = &[0x2b, 0x65, 0x70];
const X25519_OID: &[u8] = &[0x2b, 0x65, 0x6e];

/// The private key material of one entry, as the bytes a card import needs.
///
/// All integers are minimal big-endian (no leading zero bytes). The secret
/// fields are cleared on drop, and `Debug` prints only the algorithm.
pub enum KeyParts {
    /// An RSA key: public modulus and exponent plus the CRT parts.
    #[non_exhaustive]
    Rsa {
        n: Vec<u8>,
        e: Vec<u8>,
        p: Vec<u8>,
        q: Vec<u8>,
        dp: Vec<u8>,
        dq: Vec<u8>,
        qinv: Vec<u8>,
    },
    /// A NIST P-256 or P-384 key: the scalar, left-padded to the field size.
    #[non_exhaustive]
    Ec { alg: KeyAlg, scalar: Vec<u8> },
    /// An Ed25519 key: the 32-byte seed.
    #[non_exhaustive]
    Ed25519 { seed: [u8; 32] },
    /// An X25519 key: the 32-byte scalar.
    #[non_exhaustive]
    X25519 { scalar: [u8; 32] },
}

impl Drop for KeyParts {
    fn drop(&mut self) {
        match self {
            KeyParts::Rsa {
                n,
                e,
                p,
                q,
                dp,
                dq,
                qinv,
            } => {
                n.zeroize();
                e.zeroize();
                p.zeroize();
                q.zeroize();
                dp.zeroize();
                dq.zeroize();
                qinv.zeroize();
            }
            KeyParts::Ec { scalar, .. } => scalar.zeroize(),
            KeyParts::Ed25519 { seed } => seed.zeroize(),
            KeyParts::X25519 { scalar } => scalar.zeroize(),
        }
    }
}

impl ZeroizeOnDrop for KeyParts {}

impl fmt::Debug for KeyParts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            KeyParts::Rsa { .. } => "Rsa",
            KeyParts::Ec { .. } => "Ec",
            KeyParts::Ed25519 { .. } => "Ed25519",
            KeyParts::X25519 { .. } => "X25519",
        };
        write!(f, "KeyParts::{variant}({:?})", self.alg())
    }
}

/// Bit length of a minimal big-endian integer.
fn bit_len(be: &[u8]) -> usize {
    match be.first() {
        Some(&b) => (be.len() - 1) * 8 + (8 - b.leading_zeros() as usize),
        None => 0,
    }
}

fn rsa_alg(n: &[u8]) -> Option<KeyAlg> {
    match bit_len(n) {
        1024 => Some(KeyAlg::Rsa1024),
        2048 => Some(KeyAlg::Rsa2048),
        3072 => Some(KeyAlg::Rsa3072),
        4096 => Some(KeyAlg::Rsa4096),
        _ => None,
    }
}

impl KeyParts {
    /// The PIV algorithm for this key.
    ///
    /// Variants cannot be built outside this crate, and RSA sizes other than
    /// 1024/2048/3072/4096 are refused when a key is read, so the RSA fallback
    /// below is unreachable.
    pub fn alg(&self) -> KeyAlg {
        match self {
            KeyParts::Rsa { n, .. } => rsa_alg(n).unwrap_or(KeyAlg::Rsa2048),
            KeyParts::Ec { alg, .. } => *alg,
            KeyParts::Ed25519 { .. } => KeyAlg::Ed25519,
            KeyParts::X25519 { .. } => KeyAlg::X25519,
        }
    }

    /// The matching public key, in the form `parse_certificate_public_key`
    /// returns: RSA modulus/exponent, an uncompressed `04 || X || Y` point,
    /// or the raw 32-byte Ed25519/X25519 point.
    pub fn public_key(&self) -> PublicKey {
        match self {
            KeyParts::Rsa { n, e, .. } => PublicKey::Rsa {
                modulus: n.clone(),
                exponent: e.clone(),
            },
            KeyParts::Ec { alg, scalar } => PublicKey::Ecc {
                point: ec_point(*alg, scalar).unwrap_or_default(),
            },
            KeyParts::Ed25519 { seed } => PublicKey::Ecc {
                point: ed25519_dalek::SigningKey::from_bytes(seed)
                    .verifying_key()
                    .to_bytes()
                    .to_vec(),
            },
            KeyParts::X25519 { scalar } => PublicKey::Ecc {
                point: x25519_dalek::x25519(
                    *Zeroizing::new(*scalar),
                    x25519_dalek::X25519_BASEPOINT_BYTES,
                )
                .to_vec(),
            },
        }
    }
}

/// Uncompressed public point for a P-256/P-384 scalar; `None` if the scalar
/// is not a valid private key for the curve.
fn ec_point(alg: KeyAlg, scalar: &[u8]) -> Option<Vec<u8>> {
    match alg {
        KeyAlg::EccP256 => {
            use p256::elliptic_curve::sec1::ToSec1Point;
            let sk = p256::SecretKey::from_slice(scalar).ok()?;
            Some(sk.public_key().to_sec1_point(false).as_bytes().to_vec())
        }
        KeyAlg::EccP384 => {
            use p384::elliptic_curve::sec1::ToSec1Point;
            let sk = p384::SecretKey::from_slice(scalar).ok()?;
            Some(sk.public_key().to_sec1_point(false).as_bytes().to_vec())
        }
        _ => None,
    }
}

fn bad(what: &'static str) -> P12Error {
    P12Error::Malformed(what)
}

fn expect(t: &Tlv<'_>, tag: u8, what: &'static str) -> Result<(), P12Error> {
    if t.tag == tag {
        Ok(())
    } else {
        Err(bad(what))
    }
}

/// A non-negative INTEGER as minimal big-endian bytes (at least one byte).
fn uint_bytes(t: &Tlv<'_>) -> Result<Zeroizing<Vec<u8>>, P12Error> {
    expect(t, TAG_INTEGER, "expected an INTEGER")?;
    let v: &[u8] = &t.value;
    let first = *v.first().ok_or_else(|| bad("empty INTEGER"))?;
    if first & 0x80 != 0 {
        return Err(bad("negative INTEGER in a key"));
    }
    let skip = v
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(v.len().saturating_sub(1));
    Ok(Zeroizing::new(v.get(skip..).unwrap_or(&[]).to_vec()))
}

/// Read a PKCS#8 PrivateKeyInfo (plaintext) into key parts.
pub(crate) fn parse(pkcs8: &[u8]) -> Result<KeyParts, P12Error> {
    let (info, _) = read_tlv(pkcs8)?;
    expect(&info, TAG_SEQUENCE, "PrivateKeyInfo is not a SEQUENCE")?;
    let kids = children(&info.value)?;
    let (alg_id, private_key) = match kids.as_slice() {
        [_version, a, k, ..] => (a, k),
        _ => return Err(bad("PrivateKeyInfo has too few fields")),
    };
    expect(
        alg_id,
        TAG_SEQUENCE,
        "AlgorithmIdentifier is not a SEQUENCE",
    )?;
    expect(
        private_key,
        TAG_OCTET_STRING,
        "privateKey is not an OCTET STRING",
    )?;
    let alg_kids = children(&alg_id.value)?;
    let oid = alg_kids
        .first()
        .ok_or_else(|| bad("empty AlgorithmIdentifier"))?;
    expect(oid, TAG_OID, "AlgorithmIdentifier has no OID")?;
    let inner: &[u8] = &private_key.value;

    if *oid.value == *RSA_ENCRYPTION_OID {
        parse_rsa(inner)
    } else if *oid.value == *EC_PUBLIC_KEY_OID {
        let curve = match alg_kids.get(1) {
            Some(p) if p.tag == TAG_OID => Some(p.value.to_vec()),
            _ => None,
        };
        parse_ec(inner, curve)
    } else if *oid.value == *ED25519_OID {
        Ok(KeyParts::Ed25519 {
            seed: *curve25519_scalar(inner)?,
        })
    } else if *oid.value == *X25519_OID {
        Ok(KeyParts::X25519 {
            scalar: *curve25519_scalar(inner)?,
        })
    } else {
        Err(P12Error::Unsupported("private key algorithm"))
    }
}

fn parse_rsa(inner: &[u8]) -> Result<KeyParts, P12Error> {
    let (seq, _) = read_tlv(inner)?;
    expect(&seq, TAG_SEQUENCE, "RSAPrivateKey is not a SEQUENCE")?;
    let kids = children(&seq.value)?;
    let [version, n, e, d, p, q, dp, dq, qinv, rest @ ..] = kids.as_slice() else {
        return Err(bad("RSAPrivateKey has too few fields"));
    };
    // Version 1 (or trailing otherPrimeInfos) means more than two primes.
    if !rest.is_empty() || *uint_bytes(version)? != [0u8] {
        return Err(P12Error::Unsupported("multi-prime RSA"));
    }
    let mut n = uint_bytes(n)?;
    let mut e = uint_bytes(e)?;
    let d = uint_bytes(d)?;
    let mut p = uint_bytes(p)?;
    let mut q = uint_bytes(q)?;
    let mut dp = uint_bytes(dp)?;
    let mut dq = uint_bytes(dq)?;
    let mut qinv = uint_bytes(qinv)?;
    if rsa_alg(&n).is_none() {
        return Err(P12Error::Unsupported("RSA key size"));
    }
    check_rsa_consistent(&n, &e, &d, &p, &q, &dp, &dq, &qinv)?;
    Ok(KeyParts::Rsa {
        n: core::mem::take(&mut *n),
        e: core::mem::take(&mut *e),
        p: core::mem::take(&mut *p),
        q: core::mem::take(&mut *q),
        dp: core::mem::take(&mut *dp),
        dq: core::mem::take(&mut *dq),
        qinv: core::mem::take(&mut *qinv),
    })
}

/// The file's RSA parts must agree: `p * q == n`, `e * d == 1` modulo each
/// prime minus one, and the stored CRT values equal those derived from
/// `d`, `p` and `q` (they are sent to the card as given).
#[allow(clippy::too_many_arguments)]
fn check_rsa_consistent(
    n: &[u8],
    e: &[u8],
    d: &[u8],
    p: &[u8],
    q: &[u8],
    dp: &[u8],
    dq: &[u8],
    qinv: &[u8],
) -> Result<(), P12Error> {
    const DISAGREE: P12Error = P12Error::Malformed("RSA key parts don't agree");
    let key = RsaPrivateKey::from_components(
        BigUint::from_bytes_be(n),
        BigUint::from_bytes_be(e),
        BigUint::from_bytes_be(d),
        vec![BigUint::from_bytes_be(p), BigUint::from_bytes_be(q)],
    )
    .map_err(|_| DISAGREE)?;
    let same = |derived: Option<BigUint>, stored: &[u8]| {
        derived.is_some_and(|v| v.to_bytes_be() == stored)
    };
    if same(key.dp().cloned(), dp)
        && same(key.dq().cloned(), dq)
        && same(key.crt_coefficient(), qinv)
        && key.n().to_bytes_be() == n
    {
        Ok(())
    } else {
        Err(DISAGREE)
    }
}

fn parse_ec(inner: &[u8], alg_curve: Option<Vec<u8>>) -> Result<KeyParts, P12Error> {
    let (seq, _) = read_tlv(inner)?;
    expect(&seq, TAG_SEQUENCE, "ECPrivateKey is not a SEQUENCE")?;
    let kids = children(&seq.value)?;
    let [_version, scalar, rest @ ..] = kids.as_slice() else {
        return Err(bad("ECPrivateKey has too few fields"));
    };
    expect(
        scalar,
        TAG_OCTET_STRING,
        "EC private key is not an OCTET STRING",
    )?;
    // The curve is normally in the AlgorithmIdentifier; some writers repeat it
    // (or only give it) in the ECPrivateKey's [0] parameters. Both must agree.
    let mut inner_curve = None;
    if let Some(params) = rest.iter().find(|t| t.tag == TAG_CONTEXT_0) {
        let oids = children(&params.value)?;
        if let Some(o) = oids.first().filter(|o| o.tag == TAG_OID) {
            inner_curve = Some(o.value.to_vec());
        }
    }
    let curve = match (alg_curve, inner_curve) {
        (Some(a), Some(b)) if a != b => return Err(bad("EC key names two different curves")),
        (a, b) => a.or(b),
    };
    let curve = curve.ok_or_else(|| bad("EC key names no curve"))?;
    let (alg, size) = if curve == P256_OID {
        (KeyAlg::EccP256, 32)
    } else if curve == P384_OID {
        (KeyAlg::EccP384, 48)
    } else {
        return Err(P12Error::Unsupported("EC curve"));
    };
    let raw: &[u8] = &scalar.value;
    if raw.is_empty() || raw.len() > size {
        return Err(bad("EC private key has the wrong length"));
    }
    let mut padded = Zeroizing::new(vec![0u8; size]);
    padded[size - raw.len()..].copy_from_slice(raw);
    if ec_point(alg, &padded).is_none() {
        return Err(bad("EC private key is out of range"));
    }
    Ok(KeyParts::Ec {
        alg,
        scalar: core::mem::take(&mut *padded),
    })
}
/// RFC 8410: the privateKey OCTET STRING wraps an inner OCTET STRING of 32 bytes.
fn curve25519_scalar(inner: &[u8]) -> Result<Zeroizing<[u8; 32]>, P12Error> {
    let (octets, _) = read_tlv(inner)?;
    expect(
        &octets,
        TAG_OCTET_STRING,
        "CurvePrivateKey is not an OCTET STRING",
    )?;
    let bytes = <[u8; 32]>::try_from(&*octets.value)
        .map_err(|_| bad("curve private key is not 32 bytes"))?;
    Ok(Zeroizing::new(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A P-521 PKCS#8 with a one-byte scalar (structure is all that matters).
    #[test]
    fn p521_key_is_unsupported() {
        let der = [
            0x30, 0x1e, 0x02, 0x01, 0x00, // version
            0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // ecPublicKey
            0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23, // secp521r1
            0x04, 0x07, 0x30, 0x05, 0x02, 0x01, 0x01, 0x04, 0x00,
        ];
        assert_eq!(parse(&der).err(), Some(P12Error::Unsupported("EC curve")));
    }

    #[test]
    fn negative_integer_is_malformed() {
        let neg = Tlv {
            tag: TAG_INTEGER,
            constructed: false,
            value: std::borrow::Cow::Borrowed(&[0x80]),
        };
        assert!(matches!(uint_bytes(&neg), Err(P12Error::Malformed(_))));
        let padded = Tlv {
            tag: TAG_INTEGER,
            constructed: false,
            value: std::borrow::Cow::Borrowed(&[0x00, 0x00, 0x91]),
        };
        assert_eq!(*uint_bytes(&padded).unwrap(), vec![0x91]);
        let zero = Tlv {
            tag: TAG_INTEGER,
            constructed: false,
            value: std::borrow::Cow::Borrowed(&[0x00]),
        };
        assert_eq!(*uint_bytes(&zero).unwrap(), vec![0]);
    }

    #[test]
    fn odd_rsa_size_is_unsupported() {
        // n = 2^7 (8 bits) inside an otherwise well-formed RSAPrivateKey.
        let int = |v: u8| [0x02, 0x01, v];
        let mut seq = Vec::new();
        for v in [0u8, 0x80, 3, 1, 1, 1, 1, 1, 1] {
            seq.extend_from_slice(
                &if v == 0x80 {
                    [0x02, 0x02, 0x00]
                } else {
                    int(v)
                }[..],
            );
            if v == 0x80 {
                seq.push(0x80);
            }
        }
        let mut rsa = vec![0x30, seq.len() as u8];
        rsa.extend_from_slice(&seq);
        assert_eq!(
            parse_rsa(&rsa).err(),
            Some(P12Error::Unsupported("RSA key size"))
        );
    }
}

#[cfg(test)]
mod rsa_tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        std::fs::read("tests/fixtures/rsa2048-modern.key.der").unwrap()
    }

    /// Offset of the value of the `index`th (0-based) INTEGER of the
    /// RSAPrivateKey inside the fixture's PKCS#8, found by walking the DER.
    fn integer_offset(der: &[u8], index: usize) -> (usize, usize) {
        // The RSAPrivateKey SEQUENCE starts at the first `30 82` after the
        // AlgorithmIdentifier's NULL; its header is 4 bytes.
        let start = der
            .windows(2)
            .skip(20)
            .position(|w| w == [0x30, 0x82])
            .unwrap()
            + 20
            + 4;
        let mut pos = start;
        for _ in 0..index {
            let (len, hdr) = der_len(&der[pos + 1..]);
            pos += 1 + hdr + len;
        }
        let (len, hdr) = der_len(&der[pos + 1..]);
        (pos + 1 + hdr, len)
    }

    fn der_len(b: &[u8]) -> (usize, usize) {
        if b[0] < 0x80 {
            (usize::from(b[0]), 1)
        } else {
            let n = usize::from(b[0] & 0x7f);
            (
                b[1..=n].iter().fold(0, |a, &x| (a << 8) | usize::from(x)),
                1 + n,
            )
        }
    }

    #[test]
    fn intact_rsa_key_parses() {
        assert!(parse(&fixture()).is_ok());
    }

    #[test]
    fn rsa_inconsistent_parts_are_refused() {
        // INTEGER indexes: 0 version, 1 n, 2 e, 3 d, 4 p, 5 q, 6 dp, 7 dq, 8 qinv.
        for (index, name) in [(6, "dp"), (7, "dq"), (8, "qinv"), (4, "p"), (3, "d")] {
            let mut der = fixture();
            let (off, len) = integer_offset(&der, index);
            der[off + len - 1] ^= 0x02;
            assert_eq!(
                parse(&der).err(),
                Some(P12Error::Malformed("RSA key parts don't agree")),
                "corrupted {name}"
            );
        }
    }

    #[test]
    fn prime_equal_to_one_is_refused_not_a_panic() {
        // p = 1 and q = n multiply to n; `rsa` before 0.9.10 panicked on it.
        let der = fixture();
        let int = |index| {
            let (off, len) = integer_offset(&der, index);
            der[off..off + len].to_vec()
        };
        let (n, e, d) = (int(1), int(2), int(3));
        let (dp, dq, qinv) = (int(6), int(7), int(8));
        for (p, q) in [(&[1u8][..], &n[..]), (&n[..], &[1u8][..])] {
            assert_eq!(
                check_rsa_consistent(&n, &e, &d, p, q, &dp, &dq, &qinv).err(),
                Some(P12Error::Malformed("RSA key parts don't agree"))
            );
        }
    }

    #[test]
    fn multi_prime_rsa_is_unsupported() {
        let mut der = fixture();
        let (off, _) = integer_offset(&der, 0);
        der[off] = 1; // version 1 = multi-prime
        assert_eq!(
            parse(&der).err(),
            Some(P12Error::Unsupported("multi-prime RSA"))
        );
    }
}
