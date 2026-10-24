//! Restore key sets onto an OpenPGP card (cargo feature `card`).
//!
//! The one place that turns this crate's keys into the transport's import
//! requests, so the core stays free of PC/SC. Each key goes into its slot
//! with its own creation time and the file's fingerprint; the transport
//! checks the card's public key against the file's before registering it.

use keyroost_openpgp::{EccPrivateKeyParts, KeyCrt, PublicKey, RsaPrivateKeyParts};
use keyroost_transport::{ImportKey, KeyImport, OpenPgpSession, TransportError};

use keyroost_openpgp::PW1_SIGN;
use zeroize::Zeroizing;

use crate::cert::KeySet;
use crate::keys::{CardKey, KeyPart, Material};
use crate::read::{self, Loaded, PublicCert, Slot};
use crate::s2k::Hash;
use crate::sig::Signer;
use crate::Error;

/// Borrow a [`CardKey`] as the transport's import form. ECC keys carry
/// their public point (sent only to cards that ask for it).
#[must_use]
pub(crate) fn to_import(k: &CardKey) -> ImportKey<'_> {
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
        .map(|((&(crt, part), key), alg)| {
            KeyImport::new(
                crt,
                alg,
                to_import(key),
                part.created,
                part.fingerprint(),
                expected_public(part),
            )
        })
        .collect();
    session.import_key_set(&imports)
}

/// PKCS#1 v1.5 DigestInfo prefixes (RFC 8017 section 9.2).
const DIGEST_INFO_SHA256: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
const DIGEST_INFO_SHA384: [u8; 19] = [
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30,
];
const DIGEST_INFO_SHA512: [u8; 19] = [
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];

const ALGO_RSA: u8 = 1;
const ALGO_ECDSA: u8 = 19;
const ALGO_EDDSA: u8 = 22;

/// Signs with the card's signature key (PSO: COMPUTE DIGITAL SIGNATURE),
/// so an expiry change never needs the primary key's secret on the host.
///
/// The user PIN (PW1, reference 0x81) is verified again before every
/// signature: a card in its default "PIN once per signature" mode accepts
/// only one signature per verification, and an expiry change makes one
/// signature per user ID and subkey. A card with touch enabled asks for a
/// touch each time.
pub struct CardSigner<'s> {
    session: &'s mut OpenPgpSession,
    algo: u8,
    pin: Zeroizing<Vec<u8>>,
}

impl<'s> CardSigner<'s> {
    /// A signer for `cert`'s primary key. Refuses a card whose signature
    /// slot holds a different key (by fingerprint) before anything is
    /// signed.
    pub fn new(
        session: &'s mut OpenPgpSession,
        cert: &PublicCert,
        pin: &[u8],
    ) -> Result<Self, Error> {
        let status = session.status().map_err(card_error)?;
        if status.fingerprint_sig != cert.primary.fpr {
            return Err(Error::Refused(
                "This card's signature key is not this public key's primary key.",
            ));
        }
        Ok(CardSigner {
            session,
            algo: cert.primary.algo,
            pin: Zeroizing::new(pin.to_vec()),
        })
    }
}

fn card_error(e: TransportError) -> Error {
    Error::Crypto(e.to_string())
}

impl Signer for CardSigner<'_> {
    fn algo_id(&self) -> u8 {
        self.algo
    }

    fn sign_digest(&mut self, hash: Hash, digest: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        let input = card_input(self.algo, hash, digest)?;
        self.session
            .verify_pin(PW1_SIGN, &self.pin)
            .map_err(card_error)?;
        let sig = self.session.sign(&input).map_err(card_error)?;
        split_signature(self.algo, sig)
    }
}

/// What the card signs: an RSA key wraps the digest in its DigestInfo,
/// ECDSA and EdDSA keys take the bare digest.
fn card_input(algo: u8, hash: Hash, digest: &[u8]) -> Result<Vec<u8>, Error> {
    match algo {
        ALGO_RSA => {
            let prefix = match hash {
                Hash::Sha256 => &DIGEST_INFO_SHA256,
                Hash::Sha384 => &DIGEST_INFO_SHA384,
                Hash::Sha512 => &DIGEST_INFO_SHA512,
                Hash::Sha1 => return Err(Error::Unsupported("SHA-1 signatures")),
            };
            Ok([prefix.as_slice(), digest].concat())
        }
        ALGO_ECDSA | ALGO_EDDSA => Ok(digest.to_vec()),
        _ => Err(Error::Unsupported("signing with this card key's algorithm")),
    }
}

/// The card's signature as OpenPGP MPI values: RSA `[s]`, ECDSA and EdDSA
/// `r || s` split in halves.
fn split_signature(algo: u8, sig: Vec<u8>) -> Result<Vec<Vec<u8>>, Error> {
    match algo {
        ALGO_RSA if !sig.is_empty() => Ok(vec![sig]),
        ALGO_EDDSA if sig.len() == 64 => Ok(vec![sig[..32].to_vec(), sig[32..].to_vec()]),
        ALGO_ECDSA if !sig.is_empty() && sig.len().is_multiple_of(2) => {
            let (r, s) = sig.split_at(sig.len() / 2);
            Ok(vec![r.to_vec(), s.to_vec()])
        }
        _ => Err(Error::Malformed(
            "the card's signature has an unexpected length",
        )),
    }
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
            other => panic!("P-256 imported as {other:?}"),
        }
        assert!(matches!(
            expected_public(&s.parts[1]),
            PublicKey::Ecc { point } if point.len() == 65 && point[0] == 0x04
        ));
    }

    #[test]
    fn rsa_card_input_is_the_digest_info() {
        let d = [0xAB; 32];
        let got = card_input(ALGO_RSA, Hash::Sha256, &d).unwrap();
        let hex: String = got[..19].iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "3031300d060960864801650304020105000420");
        assert_eq!(&got[19..], d);
        for (h, n, want) in [
            (Hash::Sha384, 48, "3041300d060960864801650304020205000430"),
            (Hash::Sha512, 64, "3051300d060960864801650304020305000440"),
        ] {
            let got = card_input(ALGO_RSA, h, &vec![1; n]).unwrap();
            let hex: String = got[..19].iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(hex, want);
            assert_eq!(got.len(), 19 + n);
        }
        assert_eq!(card_input(ALGO_ECDSA, Hash::Sha256, &d).unwrap(), d);
        assert_eq!(card_input(ALGO_EDDSA, Hash::Sha256, &d).unwrap(), d);
        assert!(card_input(18, Hash::Sha256, &d).is_err());
    }

    #[test]
    fn card_signatures_split_into_mpis() {
        let rs: Vec<u8> = (0..64).collect();
        let ed = split_signature(ALGO_EDDSA, rs.clone()).unwrap();
        assert_eq!((ed[0].as_slice(), ed[1].as_slice()), (&rs[..32], &rs[32..]));
        let p384: Vec<u8> = (0..96).collect();
        let ec = split_signature(ALGO_ECDSA, p384.clone()).unwrap();
        assert_eq!(
            (ec[0].as_slice(), ec[1].as_slice()),
            (&p384[..48], &p384[48..])
        );
        assert_eq!(
            split_signature(ALGO_RSA, vec![7; 256]).unwrap(),
            [vec![7; 256]]
        );
        assert!(split_signature(ALGO_EDDSA, vec![0; 63]).is_err());
        assert!(split_signature(ALGO_ECDSA, vec![0; 65]).is_err());
        assert!(split_signature(ALGO_RSA, Vec::new()).is_err());
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
            other => panic!("Ed25519 imported as {other:?}"),
        }
        assert!(matches!(
            expected_public(&s.parts[1]),
            PublicKey::Ecc { point } if point.len() == 32
        ));
    }
}
