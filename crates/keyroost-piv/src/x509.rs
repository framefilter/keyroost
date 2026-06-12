//! Minimal X.509 / PKCS#10 DER assembly for card-signed certificates.
//!
//! GENERATE ASYMMETRIC KEY PAIR leaves a key on the card with no certificate.
//! To make the slot usable end-to-end the host needs to build the
//! *to-be-signed* bytes — a PKCS#10 CertificationRequestInfo (for a CA) or an
//! X.509 TBSCertificate (self-signed) — have the card sign them via GENERAL
//! AUTHENTICATE, and assemble the final structure around the returned
//! signature. This module is the pure DER half of that: no card I/O, no
//! hashing, no crypto — `keyroost-transport` drives the card and supplies the
//! signature; the SHA digests come from `keyroost-proto`.
//!
//! Scope is deliberately narrow: subjects limited to the common attributes
//! (CN/O/OU/C/L/ST), v3 certificates without extensions, one signature
//! algorithm per key type (SHA-256 for RSA and P-256, SHA-384 for P-384,
//! pure Ed25519). X25519 cannot sign and is rejected.

use crate::spki::{der_bitstring, der_seq, der_tlv, der_uint, pem};
use crate::KeyAlg;

/// Errors building certificate structures.
#[derive(Debug, PartialEq, Eq)]
pub enum X509Error {
    /// The key algorithm cannot produce signatures (X25519).
    UnsupportedAlgorithm,
    /// The subject string didn't parse (`reason` says why).
    BadSubject(&'static str),
    /// `not_after` was not later than `not_before`.
    BadValidity,
}

impl core::fmt::Display for X509Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            X509Error::UnsupportedAlgorithm => {
                write!(f, "this key algorithm cannot sign certificates")
            }
            X509Error::BadSubject(r) => write!(f, "invalid subject: {r}"),
            X509Error::BadValidity => write!(f, "certificate expiry must be after its start"),
        }
    }
}

impl std::error::Error for X509Error {}

/// Which digest the host must apply to the to-be-signed bytes before handing
/// them to the card (the card's GENERAL AUTHENTICATE signs a prepared block,
/// not the raw message — except Ed25519, which signs the message itself).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigHash {
    Sha256,
    Sha384,
    /// Ed25519: pass the raw to-be-signed bytes to the card unhashed.
    None,
}

/// The digest paired with each signing algorithm.
pub fn signature_hash(alg: KeyAlg) -> Result<SigHash, X509Error> {
    match alg {
        KeyAlg::Rsa1024 | KeyAlg::Rsa2048 | KeyAlg::Rsa3072 | KeyAlg::Rsa4096 => {
            Ok(SigHash::Sha256)
        }
        KeyAlg::EccP256 => Ok(SigHash::Sha256),
        KeyAlg::EccP384 => Ok(SigHash::Sha384),
        KeyAlg::Ed25519 => Ok(SigHash::None),
        KeyAlg::X25519 => Err(X509Error::UnsupportedAlgorithm),
    }
}

/// Pre-encoded signature AlgorithmIdentifier DER for the key type.
pub fn signature_algorithm(alg: KeyAlg) -> Result<&'static [u8], X509Error> {
    match alg {
        // sha256WithRSAEncryption (1.2.840.113549.1.1.11) with NULL params.
        KeyAlg::Rsa1024 | KeyAlg::Rsa2048 | KeyAlg::Rsa3072 | KeyAlg::Rsa4096 => Ok(&[
            0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05,
            0x00,
        ]),
        // ecdsa-with-SHA256 (1.2.840.10045.4.3.2), params absent.
        KeyAlg::EccP256 => Ok(&[
            0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02,
        ]),
        // ecdsa-with-SHA384 (1.2.840.10045.4.3.3), params absent.
        KeyAlg::EccP384 => Ok(&[
            0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03,
        ]),
        // id-Ed25519 (1.3.101.112), params absent.
        KeyAlg::Ed25519 => Ok(&[0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70]),
        KeyAlg::X25519 => Err(X509Error::UnsupportedAlgorithm),
    }
}

/// A parsed distinguished name: ordered `(attribute, value)` pairs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectName(Vec<(NameAttr, String)>);

/// The subject attributes this module supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameAttr {
    CommonName,
    Organization,
    OrganizationalUnit,
    Country,
    Locality,
    StateOrProvince,
}

impl NameAttr {
    /// Pre-encoded attribute-type OID (tag 0x06 included).
    const fn oid(self) -> &'static [u8] {
        match self {
            NameAttr::CommonName => &[0x06, 0x03, 0x55, 0x04, 0x03], // 2.5.4.3
            NameAttr::Country => &[0x06, 0x03, 0x55, 0x04, 0x06],    // 2.5.4.6
            NameAttr::Locality => &[0x06, 0x03, 0x55, 0x04, 0x07],   // 2.5.4.7
            NameAttr::StateOrProvince => &[0x06, 0x03, 0x55, 0x04, 0x08], // 2.5.4.8
            NameAttr::Organization => &[0x06, 0x03, 0x55, 0x04, 0x0A], // 2.5.4.10
            NameAttr::OrganizationalUnit => &[0x06, 0x03, 0x55, 0x04, 0x0B], // 2.5.4.11
        }
    }
}

impl SubjectName {
    /// Parse a comma-separated `TYPE=value` subject string, e.g.
    /// `"CN=Alice Example,O=Example Corp,C=US"`. Types are case-insensitive;
    /// supported: CN, O, OU, C, L, ST. Values are taken literally (no RFC 4514
    /// escaping — a value cannot contain a comma).
    pub fn parse(s: &str) -> Result<Self, X509Error> {
        let mut parts = Vec::new();
        for raw in s.split(',') {
            let raw = raw.trim();
            if raw.is_empty() {
                continue;
            }
            let (typ, value) = raw
                .split_once('=')
                .ok_or(X509Error::BadSubject("expected TYPE=value pairs"))?;
            let value = value.trim();
            if value.is_empty() {
                return Err(X509Error::BadSubject("empty attribute value"));
            }
            let attr = match typ.trim().to_ascii_uppercase().as_str() {
                "CN" => NameAttr::CommonName,
                "O" => NameAttr::Organization,
                "OU" => NameAttr::OrganizationalUnit,
                "C" => NameAttr::Country,
                "L" => NameAttr::Locality,
                "ST" => NameAttr::StateOrProvince,
                _ => {
                    return Err(X509Error::BadSubject(
                        "unsupported attribute (use CN, O, OU, C, L, ST)",
                    ))
                }
            };
            if attr == NameAttr::Country && (value.len() != 2 || !value.is_ascii()) {
                return Err(X509Error::BadSubject("country (C) must be a 2-letter code"));
            }
            parts.push((attr, value.to_owned()));
        }
        if parts.is_empty() {
            return Err(X509Error::BadSubject("subject is empty (need e.g. CN=…)"));
        }
        Ok(SubjectName(parts))
    }

    /// DER `Name` (RDNSequence; one RDN per attribute, in the given order).
    /// Values encode as UTF8String, except country which uses PrintableString
    /// per convention (RFC 5280 strongly prefers it for `C`).
    fn to_der(&self) -> Vec<u8> {
        let mut body = Vec::new();
        for (attr, value) in &self.0 {
            let string_tag = if *attr == NameAttr::Country {
                0x13 // PrintableString
            } else {
                0x0C // UTF8String
            };
            let atv = der_seq(&[attr.oid(), &der_tlv(string_tag, value.as_bytes())]);
            body.extend_from_slice(&der_tlv(0x31, &atv)); // SET (one ATV)
        }
        der_tlv(0x30, &body)
    }
}

/// `Time` per RFC 5280: UTCTime (`YYMMDDHHMMSSZ`) for dates through 2049,
/// GeneralizedTime (`YYYYMMDDHHMMSSZ`) from 2050 on.
fn der_time(unix_secs: i64) -> Vec<u8> {
    let (y, mo, d, h, mi, s) = civil_from_unix(unix_secs);
    if (1950..2050).contains(&y) {
        let yy = (y % 100) as u32;
        der_tlv(
            0x17,
            format!("{yy:02}{mo:02}{d:02}{h:02}{mi:02}{s:02}Z").as_bytes(),
        )
    } else {
        der_tlv(
            0x18,
            format!("{y:04}{mo:02}{d:02}{h:02}{mi:02}{s:02}Z").as_bytes(),
        )
    }
}

/// Unix seconds → (year, month, day, hour, minute, second) in UTC. Days-to-
/// civil conversion per Howard Hinnant's algorithm (proleptic Gregorian).
fn civil_from_unix(unix_secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = unix_secs.div_euclid(86_400);
    let secs = unix_secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let mo = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let y = if mo <= 2 { y + 1 } else { y };
    (
        y,
        mo,
        d,
        (secs / 3600) as u32,
        (secs % 3600 / 60) as u32,
        (secs % 60) as u32,
    )
}

/// PKCS#10 `CertificationRequestInfo`: version 0, subject, SPKI, and the
/// mandatory (empty) `attributes [0]`.
pub fn csr_info(subject: &SubjectName, spki_der: &[u8]) -> Vec<u8> {
    der_seq(&[
        &der_uint(&[0x00]), // version: v1(0)
        &subject.to_der(),  // subject
        spki_der,           // subjectPKInfo
        &[0xA0, 0x00][..],  // attributes [0] IMPLICIT SET — present but empty
    ])
}

/// X.509 `TBSCertificate`: v3, no extensions, issuer = subject (self-signed).
/// `serial` is raw big-endian bytes (the encoder keeps it a positive INTEGER);
/// validity bounds are unix seconds.
pub fn tbs_certificate(
    serial: &[u8],
    alg: KeyAlg,
    subject: &SubjectName,
    not_before: i64,
    not_after: i64,
    spki_der: &[u8],
) -> Result<Vec<u8>, X509Error> {
    if not_after <= not_before {
        return Err(X509Error::BadValidity);
    }
    let sig_alg = signature_algorithm(alg)?;
    let name = subject.to_der();
    let validity = der_seq(&[&der_time(not_before), &der_time(not_after)]);
    // version [0] EXPLICIT INTEGER 2 (v3). v3 without an extensions field is
    // legal; this keeps the encoder small and the cert maximally compatible.
    let version = der_tlv(0xA0, &der_uint(&[0x02]));
    Ok(der_seq(&[
        &version,
        &der_uint(serial),
        sig_alg,
        &name, // issuer == subject for self-signed
        &validity,
        &name,
        spki_der,
    ]))
}

/// Wrap to-be-signed bytes and the card's signature into the final structure —
/// the same `SEQUENCE { tbs, sigAlg, BIT STRING }` shape serves both a
/// certificate and a PKCS#10 request. ECDSA signatures arrive from the card
/// already DER-encoded (`SEQUENCE { r, s }`); RSA and Ed25519 are raw blocks.
/// Either way the bytes drop into the BIT STRING verbatim.
pub fn assemble(tbs: &[u8], alg: KeyAlg, signature: &[u8]) -> Result<Vec<u8>, X509Error> {
    let sig_alg = signature_algorithm(alg)?;
    Ok(der_seq(&[tbs, sig_alg, &der_bitstring(signature)]))
}

/// PEM-armor a DER certificate.
pub fn pem_certificate(der: &[u8]) -> String {
    pem("CERTIFICATE", der)
}

/// PEM-armor a DER PKCS#10 request.
pub fn pem_csr(der: &[u8]) -> String {
    pem("CERTIFICATE REQUEST", der)
}

/// `DigestInfo` prefixes (DER `SEQUENCE { AlgorithmIdentifier, OCTET STRING }`
/// minus the digest bytes) for PKCS#1 v1.5 (RFC 8017 §9.2 notes).
const DIGEST_INFO_SHA256: &[u8] = &[
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// PKCS#1 v1.5 signature padding for an RSA card slot: the card does raw RSA,
/// so the host must present the full `k`-byte block
/// `00 01 FF…FF 00 DigestInfo(SHA-256 digest)`. `k` is the modulus length in
/// bytes (128/256/384/512 for RSA-1024/2048/3072/4096).
pub fn pkcs1_v15_sha256(digest: &[u8; 32], k: usize) -> Vec<u8> {
    let t_len = DIGEST_INFO_SHA256.len() + digest.len();
    assert!(k >= t_len + 11, "RSA modulus too small for the digest");
    let mut em = Vec::with_capacity(k);
    em.push(0x00);
    em.push(0x01);
    em.resize(k - t_len - 1, 0xFF);
    em.push(0x00);
    em.extend_from_slice(DIGEST_INFO_SHA256);
    em.extend_from_slice(digest);
    em
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subject_parse_and_der() {
        // CN=Test → 30 0F 31 0D 30 0B (06 03 55 04 03) (0C 04 "Test")
        let name = SubjectName::parse("CN=Test").unwrap();
        assert_eq!(
            name.to_der(),
            vec![
                0x30, 0x0F, 0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x04, b'T',
                b'e', b's', b't',
            ]
        );
        // Country uses PrintableString (0x13) and must be 2 chars.
        let name = SubjectName::parse("C=US").unwrap();
        assert_eq!(
            name.to_der(),
            vec![
                0x30, 0x0D, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, b'U',
                b'S',
            ]
        );
        assert!(SubjectName::parse("C=USA").is_err());
        assert!(SubjectName::parse("").is_err());
        assert!(SubjectName::parse("CN=").is_err());
        assert!(SubjectName::parse("UID=x").is_err());
        // Order and multiple attributes survive.
        let multi = SubjectName::parse("CN=A, O=B, OU=C").unwrap();
        assert_eq!(multi.0.len(), 3);
    }

    #[test]
    fn time_encodings() {
        // Unix epoch → UTCTime "700101000000Z".
        assert_eq!(der_time(0), der_tlv(0x17, b"700101000000Z"));
        // 2026-06-12 00:00:00 UTC = 1781222400.
        assert_eq!(der_time(1_781_222_400), der_tlv(0x17, b"260612000000Z"));
        // 2050-01-01 00:00:00 UTC = 2524608000 → GeneralizedTime.
        assert_eq!(der_time(2_524_608_000), der_tlv(0x18, b"20500101000000Z"));
    }

    #[test]
    fn civil_conversion_spot_checks() {
        assert_eq!(civil_from_unix(0), (1970, 1, 1, 0, 0, 0));
        // Leap-day handling: 2024-02-29 12:34:56 = 1709210096.
        assert_eq!(civil_from_unix(1_709_210_096), (2024, 2, 29, 12, 34, 56));
        // End-of-year: 1999-12-31 23:59:59 = 946684799.
        assert_eq!(civil_from_unix(946_684_799), (1999, 12, 31, 23, 59, 59));
    }

    #[test]
    fn csr_info_shape() {
        let name = SubjectName::parse("CN=Test").unwrap();
        let spki = vec![0x30, 0x03, 0x02, 0x01, 0x05]; // placeholder SEQUENCE
        let cri = csr_info(&name, &spki);
        // SEQUENCE { INTEGER 0, Name, spki, [0] empty }
        assert_eq!(cri[0], 0x30);
        assert_eq!(&cri[2..5], &[0x02, 0x01, 0x00]); // version 0
        assert!(cri.windows(spki.len()).any(|w| w == spki));
        assert_eq!(&cri[cri.len() - 2..], &[0xA0, 0x00]); // attributes
    }

    #[test]
    fn tbs_and_assemble_shape() {
        let name = SubjectName::parse("CN=Test").unwrap();
        let spki = vec![0x30, 0x03, 0x02, 0x01, 0x05];
        let tbs = tbs_certificate(&[0x01, 0x02], KeyAlg::EccP256, &name, 0, 86_400, &spki).unwrap();
        // version [0] { INTEGER 2 } then serial INTEGER 0102.
        assert_eq!(&tbs[2..9], &[0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02]);
        // Two identical Name encodings (issuer == subject).
        let name_der = vec![
            0x30, 0x0F, 0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x04, b'T',
            b'e', b's', b't',
        ];
        assert_eq!(
            tbs.windows(name_der.len())
                .filter(|w| *w == name_der.as_slice())
                .count(),
            2
        );
        // Expiry must follow start.
        assert_eq!(
            tbs_certificate(&[0x01], KeyAlg::EccP256, &name, 100, 100, &spki),
            Err(X509Error::BadValidity)
        );
        // Assembly: SEQUENCE { tbs, alg, BIT STRING sig }.
        let cert = assemble(&tbs, KeyAlg::EccP256, &[0xAA, 0xBB]).unwrap();
        assert_eq!(cert[0], 0x30);
        assert!(cert.windows(tbs.len()).any(|w| w == tbs));
        assert_eq!(&cert[cert.len() - 5..], &[0x03, 0x03, 0x00, 0xAA, 0xBB]);
        // X25519 can't sign.
        assert_eq!(
            assemble(&tbs, KeyAlg::X25519, &[0u8; 64]),
            Err(X509Error::UnsupportedAlgorithm)
        );
    }

    #[test]
    fn pkcs1_padding_shape() {
        let digest = [0xCD; 32];
        let em = pkcs1_v15_sha256(&digest, 256);
        assert_eq!(em.len(), 256);
        assert_eq!(&em[..2], &[0x00, 0x01]);
        let di_start = 256 - (DIGEST_INFO_SHA256.len() + 32);
        assert!(em[2..di_start - 1].iter().all(|&b| b == 0xFF));
        assert_eq!(em[di_start - 1], 0x00);
        assert_eq!(
            &em[di_start..di_start + DIGEST_INFO_SHA256.len()],
            DIGEST_INFO_SHA256
        );
        assert_eq!(&em[256 - 32..], &digest);
    }

    #[test]
    fn signature_metadata() {
        assert_eq!(signature_hash(KeyAlg::Rsa2048), Ok(SigHash::Sha256));
        assert_eq!(signature_hash(KeyAlg::EccP384), Ok(SigHash::Sha384));
        assert_eq!(signature_hash(KeyAlg::Ed25519), Ok(SigHash::None));
        assert_eq!(
            signature_hash(KeyAlg::X25519),
            Err(X509Error::UnsupportedAlgorithm)
        );
        assert!(signature_algorithm(KeyAlg::Rsa4096).is_ok());
    }

    #[test]
    fn pem_labels() {
        let pem_c = pem_certificate(b"x");
        assert!(pem_c.starts_with("-----BEGIN CERTIFICATE-----\n"));
        let pem_r = pem_csr(b"x");
        assert!(pem_r.starts_with("-----BEGIN CERTIFICATE REQUEST-----\n"));
    }
}
