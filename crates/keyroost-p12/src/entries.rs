//! Pairing keys with certificates into entries.

use keyroost_piv::x509_parse::{parse_certificate_public_key, parse_subject_dn, DnAttr};

use crate::pfx::{read_bags, BagKind, RawBag};
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

/// Read a PKCS#12 file into entries and CA certificates.
///
/// Certificates pair to keys by public key (a certificate's `localKeyId` only
/// breaks a tie between several that match), so a missing or wrong
/// `localKeyId` cannot attach a certificate to a key that is not its own, and
/// CA flags are never consulted. A key with no matching certificate becomes an
/// entry without one.
///
/// # Errors
/// [`P12Error`] if the file cannot be read, the password is wrong, a key is of
/// an unsupported kind, or the file holds no private key.
pub fn open(file: &[u8], password: Option<&str>) -> Result<Contents, P12Error> {
    let bags = read_bags(file, password)?;
    let mut keys = Vec::new();
    let mut certs: Vec<(RawBag, Option<keyroost_piv::PublicKey>, bool)> = Vec::new();
    for bag in bags {
        match bag.kind {
            BagKind::Key => keys.push((pkcs8::parse(&bag.value)?, bag)),
            BagKind::Certificate => {
                let public = parse_certificate_public_key(&bag.value)
                    .ok()
                    .map(|(_, p)| p);
                certs.push((bag, public, false));
            }
        }
    }
    if keys.is_empty() {
        return Err(P12Error::NoKey);
    }

    let mut entries = Vec::new();
    for (key, key_bag) in keys {
        let public = key.public_key();
        let matches = |c: &(RawBag, Option<keyroost_piv::PublicKey>, bool)| {
            !c.2 && c.1.as_ref() == Some(&public)
        };
        let by_id = key_bag.local_key_id.as_ref().and_then(|id| {
            certs
                .iter()
                .position(|c| matches(c) && c.0.local_key_id.as_ref() == Some(id))
        });
        let found = by_id.or_else(|| certs.iter().position(matches));
        let (certificate, cert_name) = match found.and_then(|i| certs.get_mut(i)) {
            Some(c) => {
                c.2 = true;
                (Some(c.0.value.to_vec()), non_empty(&c.0.friendly_name))
            }
            None => (None, None),
        };
        let label = non_empty(&key_bag.friendly_name)
            .or(cert_name)
            .or_else(|| certificate.as_deref().and_then(common_name));
        entries.push(Entry {
            key,
            certificate,
            label,
        });
    }
    let authorities = certs
        .into_iter()
        .filter(|c| !c.2)
        .map(|c| c.0.value.to_vec())
        .collect();
    Ok(Contents {
        entries,
        authorities,
    })
}
