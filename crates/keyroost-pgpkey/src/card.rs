//! Restore key sets onto an OpenPGP card (cargo feature `card`).
//!
//! The one place that turns this crate's keys into the transport's import
//! requests, so the core stays free of PC/SC. Each key goes into its slot
//! with its own creation time and the file's fingerprint; the transport
//! checks the card's public key against the file's before registering it.

use keyroost_openpgp::{EccPrivateKeyParts, KeyCrt, PublicKey, RsaPrivateKeyParts};
use keyroost_transport::{ImportKey, KeyImport, OpenPgpSession, TransportError};

use crate::cert::KeySet;
use crate::keys::{CardKey, KeyPart, Material};
use crate::read::{self, Loaded, Slot};

/// Borrow a [`CardKey`] as the transport's import form. ECC keys carry
/// their public point (sent only to cards that ask for it).
#[must_use]
pub fn to_import(k: &CardKey) -> ImportKey<'_> {
    match k {
        CardKey::Rsa {
            e,
            p,
            q,
            u,
            dp,
            dq,
            n,
        } => ImportKey::Rsa(RsaPrivateKeyParts {
            e,
            p,
            q,
            u,
            dp,
            dq,
            n,
        }),
        CardKey::Ecc { scalar, point } => ImportKey::Ecc(EccPrivateKeyParts {
            scalar,
            public: Some(point),
        }),
        CardKey::Ed25519 { seed } => ImportKey::Ecc(EccPrivateKeyParts {
            scalar: seed,
            public: None,
        }),
    }
}

/// Import a freshly created set: the primary into the signature slot, the
/// subkeys into decryption and authentication. Requires the admin PIN
/// verified on `session` first. Returns the fingerprints written.
pub fn import_set(
    session: &mut OpenPgpSession,
    set: &KeySet,
) -> Result<Vec<[u8; 20]>, TransportError> {
    let [s, d, a] = &set.parts;
    import_parts(
        session,
        &[(KeyCrt::Sign, s), (KeyCrt::Decrypt, d), (KeyCrt::Auth, a)],
    )
}

/// Import the keys of a backup read with [`read::open`] that belong in
/// `slots`, each into its slot. A slot no key of the file fills is
/// skipped, so the result has one fingerprint per key imported, in
/// `slots` order. Requires the admin PIN verified on `session` first.
pub fn import_loaded(
    session: &mut OpenPgpSession,
    loaded: &Loaded,
    slots: &[Slot],
) -> Result<Vec<[u8; 20]>, TransportError> {
    let parts: Vec<(KeyCrt, &KeyPart)> = slots
        .iter()
        .filter_map(|&slot| {
            loaded
                .keys
                .iter()
                .find(|k| k.slot == Some(slot))
                .map(|k| (slot_crt(slot), &k.part))
        })
        .collect();
    import_parts(session, &parts)
}

fn slot_crt(slot: Slot) -> KeyCrt {
    match slot {
        Slot::Sign => KeyCrt::Sign,
        Slot::Decrypt => KeyCrt::Decrypt,
        Slot::Auth => KeyCrt::Auth,
    }
}

fn slot_name(crt: KeyCrt) -> &'static str {
    match crt {
        KeyCrt::Sign => "signature",
        KeyCrt::Decrypt => "decryption",
        KeyCrt::Auth => "authentication",
    }
}

/// The public key as the card reports it after the import.
fn expected_public(part: &KeyPart) -> PublicKey {
    match &part.material {
        Material::Rsa { n, e, .. } => PublicKey::Rsa {
            modulus: n.clone(),
            exponent: e.clone(),
        },
        Material::Ecdsa { point, .. } | Material::Ecdh { point, .. } => PublicKey::Ecc {
            point: point.clone(),
        },
        Material::EdDsa { point, .. } => PublicKey::Ecc {
            point: point.to_vec(),
        },
    }
}

fn import_parts(
    session: &mut OpenPgpSession,
    parts: &[(KeyCrt, &KeyPart)],
) -> Result<Vec<[u8; 20]>, TransportError> {
    let mut algs = Vec::with_capacity(parts.len());
    for &(crt, part) in parts {
        let alg = read::key_type(part)
            .ok_or(TransportError::OpenPgpKeyNotForAlgorithm {
                slot: slot_name(crt),
                label: "RSA (2048, 3072 or 4096 bits)",
            })?
            .card_alg(crt);
        algs.push(alg);
    }
    // Owned card-form keys first; the import requests borrow them.
    let keys: Vec<CardKey> = parts.iter().map(|(_, p)| p.card_key()).collect();
    let imports: Vec<KeyImport<'_>> = parts
        .iter()
        .zip(&keys)
        .zip(algs)
        .map(|((&(crt, part), key), alg)| KeyImport {
            crt,
            alg,
            key: to_import(key),
            created: part.created,
            expect_fpr: part.fingerprint(),
            expect_public: expected_public(part),
        })
        .collect();
    session.import_key_set(&imports)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::{create, Expiry, Identity};
    use crate::keys::KeyType;

    fn set(t: KeyType) -> KeySet {
        let id = Identity {
            name: "Card Test".into(),
            email: "card@example.org".into(),
        };
        create(t, &id, Expiry::Never, 1_700_000_000).unwrap()
    }

    #[test]
    fn ecc_keys_carry_scalar_and_point() {
        let s = set(KeyType::NistP256);
        let k = s.parts[1].card_key();
        match to_import(&k) {
            ImportKey::Ecc(p) => {
                assert_eq!(p.scalar.len(), 32);
                assert_eq!(p.public.map(<[u8]>::len), Some(65));
            }
            ImportKey::Rsa(_) => panic!("P-256 imported as RSA"),
        }
        assert!(matches!(
            expected_public(&s.parts[1]),
            PublicKey::Ecc { point } if point.len() == 65 && point[0] == 0x04
        ));
    }

    #[test]
    fn ed25519_sends_the_seed() {
        let s = set(KeyType::Cv25519);
        let k = s.parts[0].card_key();
        match to_import(&k) {
            ImportKey::Ecc(p) => {
                assert_eq!(p.scalar.len(), 32);
                assert_eq!(p.public, None);
            }
            ImportKey::Rsa(_) => panic!("Ed25519 imported as RSA"),
        }
        assert!(matches!(
            expected_public(&s.parts[1]),
            PublicKey::Ecc { point } if point.len() == 32
        ));
    }
}
