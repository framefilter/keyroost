//! Pairing keys with certificates into entries.

use keyroost_piv::x509_parse::{parse_certificate_public_key, parse_subject_dn, DnAttr};
use keyroost_piv::{KeyAlg, PublicKey};

use crate::pfx::{read_bags, BagKind};
use crate::pkcs8::{self, KeyParts};
use crate::P12Error;

/// One private key with its certificate, if the file has one for it.
#[derive(Debug)]
pub struct Entry {
    pub key: KeyParts,
    /// The certificate (DER) whose public key matches, if any.
    pub certificate: Option<Vec<u8>>,
    /// The key's friendly name, else the certificate's, else its subject CN.
    pub label: Option<String>,
}

/// Everything usable in a PKCS#12 file.
#[derive(Debug)]
pub struct Contents {
    /// One per private key, in file order.
    pub entries: Vec<Entry>,
    /// Certificates that belong to no key (CA certificates), in file order.
    pub authorities: Vec<Vec<u8>>,
}

fn non_empty(s: &Option<String>) -> Option<String> {
    s.clone().filter(|s| !s.is_empty())
}

fn common_name(cert: &[u8]) -> Option<String> {
    let dn = parse_subject_dn(cert).ok()?;
    dn.rdns
        .into_iter()
        .find(|(attr, v)| *attr == DnAttr::CommonName && !v.is_empty())
        .map(|(_, v)| v)
}

/// A parsed key bag, ready to pair.
pub(crate) struct KeyIn {
    pub parts: KeyParts,
    pub local_key_id: Option<Vec<u8>>,
    pub friendly_name: Option<String>,
}

/// A certificate bag with its public key (if it could be read).
pub(crate) struct CertIn {
    pub der: Vec<u8>,
    pub public: Option<(KeyAlg, PublicKey)>,
    pub local_key_id: Option<Vec<u8>>,
    pub friendly_name: Option<String>,
}

/// Pair certificates with keys.
///
/// A certificate belongs to a key only if both the algorithm and the public
/// key agree (Ed25519 and X25519 points are both 32 raw bytes, so the point
/// alone is not enough). A matching `localKeyId` only breaks a tie between
/// several certificates that match. Unclaimed certificates are returned as
/// authorities in file order.
pub(crate) fn pair(keys: Vec<KeyIn>, certs: Vec<CertIn>) -> Contents {
    let mut claimed = vec![false; certs.len()];
    let mut entries = Vec::new();
    for key in keys {
        let alg = key.parts.alg();
        let public = key.parts.public_key();
        let matches = |i: usize, c: &CertIn| {
            claimed.get(i) == Some(&false)
                && c.public
                    .as_ref()
                    .is_some_and(|(a, pk)| *a == alg && *pk == public)
        };
        let by_id = key.local_key_id.as_ref().and_then(|id| {
            certs
                .iter()
                .enumerate()
                .position(|(i, c)| matches(i, c) && c.local_key_id.as_ref() == Some(id))
        });
        let found = by_id.or_else(|| certs.iter().enumerate().position(|(i, c)| matches(i, c)));
        let cert = found.and_then(|i| {
            if let Some(slot) = claimed.get_mut(i) {
                *slot = true;
            }
            certs.get(i)
        });
        let label = non_empty(&key.friendly_name)
            .or_else(|| cert.and_then(|c| non_empty(&c.friendly_name)))
            .or_else(|| cert.and_then(|c| common_name(&c.der)));
        entries.push(Entry {
            key: key.parts,
            certificate: cert.map(|c| c.der.clone()),
            label,
        });
    }
    let authorities = certs
        .into_iter()
        .zip(claimed)
        .filter(|(_, used)| !used)
        .map(|(c, _)| c.der)
        .collect();
    Contents {
        entries,
        authorities,
    }
}

/// Read a PKCS#12 file into entries and CA certificates.
///
/// Certificates pair to keys by algorithm and public key (a `localKeyId` only
/// breaks a tie between several that match), so a missing or wrong
/// `localKeyId` cannot attach a certificate to a key that is not its own, and
/// CA flags are never consulted. A key with no matching certificate becomes an
/// entry without one.
///
/// # Errors
/// [`P12Error::TooLarge`] for a file over [`crate::MAX_FILE_BYTES`], checked
/// before anything is parsed; otherwise [`P12Error`] if the file cannot be
/// read, the password is wrong, a key is of an unsupported kind or
/// inconsistent, or the file holds no private key.
pub fn open(file: &[u8], password: Option<&str>) -> Result<Contents, P12Error> {
    if file.len() > crate::MAX_FILE_BYTES {
        return Err(P12Error::TooLarge);
    }
    let mut keys = Vec::new();
    let mut certs = Vec::new();
    for bag in read_bags(file, password)? {
        match bag.kind {
            BagKind::Key => keys.push(KeyIn {
                parts: pkcs8::parse(&bag.value)?,
                local_key_id: bag.local_key_id,
                friendly_name: bag.friendly_name,
            }),
            BagKind::Certificate => certs.push(CertIn {
                public: parse_certificate_public_key(&bag.value).ok(),
                der: bag.value.to_vec(),
                local_key_id: bag.local_key_id,
                friendly_name: bag.friendly_name,
            }),
        }
    }
    if keys.is_empty() {
        return Err(P12Error::NoKey);
    }
    Ok(pair(keys, certs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_refuses_a_file_over_the_limit_before_parsing() {
        // Zero bytes are no PKCS#12 file: at the limit that's what parsing
        // says; one byte past it, parsing never starts.
        let mut file = vec![0u8; crate::MAX_FILE_BYTES];
        assert!(matches!(open(&file, None), Err(P12Error::Malformed(_))));
        file.push(0);
        assert_eq!(open(&file, None).unwrap_err(), P12Error::TooLarge);
    }

    #[test]
    fn too_large_message_names_the_limit() {
        assert_eq!(
            crate::max_file_size(),
            format!("{} MiB", crate::MAX_FILE_BYTES / (1024 * 1024))
        );
        assert_eq!(crate::max_file_size(), "1 MiB");
        assert_eq!(P12Error::TooLarge.to_string(), "the file is over 1 MiB");
    }

    fn ed_key() -> KeyIn {
        KeyIn {
            parts: KeyParts::Ed25519 { seed: [7; 32] },
            local_key_id: None,
            friendly_name: None,
        }
    }

    fn cert(alg: KeyAlg, point: Vec<u8>, tag: u8) -> CertIn {
        CertIn {
            der: vec![tag],
            public: Some((alg, PublicKey::Ecc { point })),
            local_key_id: None,
            friendly_name: None,
        }
    }

    fn ed_point() -> Vec<u8> {
        match (KeyParts::Ed25519 { seed: [7; 32] }).public_key() {
            PublicKey::Ecc { point } => point,
            PublicKey::Rsa { .. } => Vec::new(),
        }
    }

    #[test]
    fn ed25519_key_does_not_pair_with_x25519_cert() {
        // Same 32 bytes, different algorithm: not this key's certificate.
        let c = pair(vec![ed_key()], vec![cert(KeyAlg::X25519, ed_point(), 1)]);
        assert_eq!(c.entries.len(), 1);
        assert!(c.entries[0].certificate.is_none());
        assert_eq!(c.authorities, vec![vec![1]]);
        // Control: the Ed25519 certificate with the same point does pair.
        let c = pair(vec![ed_key()], vec![cert(KeyAlg::Ed25519, ed_point(), 2)]);
        assert_eq!(c.entries[0].certificate, Some(vec![2]));
        assert!(c.authorities.is_empty());
    }

    #[test]
    fn non_matching_candidate_goes_to_authorities() {
        let mut other = cert(KeyAlg::Ed25519, vec![9; 32], 3);
        other.local_key_id = Some(vec![1]);
        let mut key = ed_key();
        key.local_key_id = Some(vec![1]);
        let c = pair(vec![key], vec![other]);
        assert!(c.entries[0].certificate.is_none());
        assert_eq!(c.authorities, vec![vec![3]]);
    }

    #[test]
    fn local_key_id_breaks_ties_between_matching_certs() {
        let mut a = cert(KeyAlg::Ed25519, ed_point(), 1);
        let mut b = cert(KeyAlg::Ed25519, ed_point(), 2);
        a.local_key_id = Some(vec![1]);
        b.local_key_id = Some(vec![2]);
        let mut key = ed_key();
        key.local_key_id = Some(vec![2]);
        let c = pair(vec![key], vec![a, b]);
        assert_eq!(c.entries[0].certificate, Some(vec![2]));
        assert_eq!(c.authorities, vec![vec![1]]);
    }
}
