//! Round-trip tests: take a fixed "card" key of each type, play the card's
//! private-key op against [`prepare`]'s output, and check
//! [`Challenge::verify`] passes — then that a corrupted reply fails.
//!
//! No RNG here either. The elliptic-curve "card" keys are fixed scalars
//! derived from [`TEST_INPUT`] (read back-to-front, so they differ from the
//! challenge's own ephemeral key); the RSA "card" key is one throwaway
//! PKCS#8 constant, since an RSA key can't be built from a scalar.

use super::*;
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};

/// A fixed "card" private scalar for the round-trip tests, distinct from the
/// challenge's ephemeral key (which reads [`TEST_INPUT`] front-to-back) so a
/// key-agreement test exercises two genuinely different keys. Byte 0 is `0x01`
/// so the value is a valid, small scalar on every NIST curve; X25519 clamps
/// internally and Ed25519 accepts any 32 bytes.
fn card_scalar<const N: usize>() -> [u8; N] {
    let mut s = [0u8; N];
    for (i, b) in s.iter_mut().enumerate() {
        *b = TEST_INPUT[TEST_INPUT.len() - 1 - i];
    }
    s[0] = 0x01;
    s
}

// --- RSA -----------------------------------------------------------------

/// One throwaway RSA-1024 key (PKCS#8), generated once for these tests. Not
/// used anywhere near real key material — it exists only to play the card's
/// `x^d mod n` in the decrypt / sign round trips.
const CARD_RSA_1024_PKCS8: &str = "\
-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAK2p0JyMO9AViq/C
tx75dMJJbh/zP+BRzY24JN9hCZH5OB2TNCRm5F99o4LBNVfWFl7jzM0ujmfbLdVw
1j+8UAfVzRPcn0ZBUB9BkWUEQIJLKMhgb5vQ1EsNdVkZ22tzym5r9PE7dMPI39aH
4qxP9ya0d9ojW8wM7qjDHZukQqC3AgMBAAECgYB4G3BqNRrRCXUHpjWcOI8mKD7/
3e6ZqDnwACGQVL6XtLO40KxJWNgtqulBb3sDKtACBK8KYV6gOZhzfDzRi94UyYOn
qM0Vm+hJBuulbMdzZb8eu7i6r4dan2pYwfa5r1Y2ANbdr9gnkfSMAuggbGi4kzgJ
G6ZnyDzYeG6ESxv38QJBANLoaBauYqlsFQYXJCueGtebzJWtJHiRs61eGaOokt0x
gDfz3IG5ldaV267ct8RB4Rgd47dMhikwzGgHHG+Mq/UCQQDSyujb7hLznUyrE+Mz
UDPYQErtOgJFqrGiUyNVQzdCXTZphP31zcxqqGzq0ywnE81X2W97hsxxesgMvrNi
TLp7AkA5kci/0DAMMP14IR71bP3EtrlcbduTsanK+/Ghs6ULDbUDEOSy4FafMV66
13Kt9pGbxKTg5tmEKtbQ2ogPhuV1AkEAraSvTDUDcaGbvbZFTEj+XF8iGefWZVNm
v0Rjb+JODCJDJ4uBtVIR2a7jAlJxJcO/PWYF2ylBEx5E25LgrNJuLwJAVZzywiC+
BtVqYRn838qTnnlTryNJ4D4djKEftqgTCyQeZHjJ5293fy/zAkUrfrDqHm+ueeY9
O/jnL7juIyD8/g==
-----END PRIVATE KEY-----";

fn card_rsa() -> rsa::RsaPrivateKey {
    rsa::RsaPrivateKey::from_pkcs8_pem(CARD_RSA_1024_PKCS8).expect("fixed test RSA key parses")
}

fn rsa_pub(key: &rsa::RsaPrivateKey) -> PublicKey {
    PublicKey::Rsa {
        modulus: key.n().to_bytes_be(),
        exponent: key.e().to_bytes_be(),
    }
}

/// Raw RSA primitive `x^exp mod n`, left-padded to `k` — the operation a PIV
/// card performs for both decrypt and sign.
fn rsa_raw(x: &[u8], exp: &rsa::BigUint, n: &rsa::BigUint, k: usize) -> Vec<u8> {
    let y = rsa::BigUint::from_bytes_be(x).modpow(exp, n);
    let be = y.to_bytes_be();
    if be.len() >= k {
        be
    } else {
        let mut out = vec![0u8; k - be.len()];
        out.extend_from_slice(&be);
        out
    }
}

#[test]
fn decrypt_round_trips_rsa() {
    let key = card_rsa();
    let k = key.n().to_bytes_be().len();
    let ch = prepare(SelfTest::Decrypt, KeyAlg::Rsa1024, &rsa_pub(&key)).unwrap();
    let reply = rsa_raw(&ch.card_input, key.d(), key.n(), k);
    ch.verify(&reply).unwrap();

    let mut bad = reply.clone();
    *bad.last_mut().unwrap() ^= 0x01;
    assert!(matches!(
        ch.verify(&bad),
        Err(TestError::Mismatch(_) | TestError::CardReply(_))
    ));
}

#[test]
fn sign_round_trips_rsa() {
    let key = card_rsa();
    let k = key.n().to_bytes_be().len();
    let ch = prepare(SelfTest::Sign, KeyAlg::Rsa1024, &rsa_pub(&key)).unwrap();
    let sig = rsa_raw(&ch.card_input, key.d(), key.n(), k);
    ch.verify(&sig).unwrap();

    let mut bad = sig.clone();
    bad[k / 2] ^= 0x01;
    assert!(matches!(ch.verify(&bad), Err(TestError::Mismatch(_))));
}

// --- Key agreement -----------------------------------------------------

#[test]
fn key_agree_round_trips_p256() {
    let card = p256::SecretKey::from_slice(&card_scalar::<32>()).unwrap();
    let pubkey = PublicKey::Ecc {
        point: card
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec(),
    };
    let ch = prepare(SelfTest::KeyAgree, KeyAlg::EccP256, &pubkey).unwrap();
    let their = p256::PublicKey::from_sec1_bytes(&ch.card_input).unwrap();
    let reply = p256::ecdh::diffie_hellman(card.to_nonzero_scalar(), their.as_affine())
        .raw_secret_bytes()
        .to_vec();
    ch.verify(&reply).unwrap();
    assert!(ch.verify(&reply[..reply.len() - 1]).is_err());
}

#[test]
fn key_agree_round_trips_p384() {
    let card = p384::SecretKey::from_slice(&card_scalar::<48>()).unwrap();
    let pubkey = PublicKey::Ecc {
        point: card
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec(),
    };
    let ch = prepare(SelfTest::KeyAgree, KeyAlg::EccP384, &pubkey).unwrap();
    let their = p384::PublicKey::from_sec1_bytes(&ch.card_input).unwrap();
    let reply = p384::ecdh::diffie_hellman(card.to_nonzero_scalar(), their.as_affine())
        .raw_secret_bytes()
        .to_vec();
    ch.verify(&reply).unwrap();
}

#[test]
fn key_agree_round_trips_p521() {
    // See `prepare_key_agree`'s `KeyAlg::EccP521` arm on why this needs its
    // own SEC1-encoding trait import.
    use p521::elliptic_curve::sec1::ToSec1Point;
    let card = p521::SecretKey::from_slice(&card_scalar::<66>()).unwrap();
    let pubkey = PublicKey::Ecc {
        point: card.public_key().to_sec1_point(false).as_bytes().to_vec(),
    };
    let ch = prepare(SelfTest::KeyAgree, KeyAlg::EccP521, &pubkey).unwrap();
    let their = p521::PublicKey::from_sec1_bytes(&ch.card_input).unwrap();
    let reply = p521::ecdh::diffie_hellman(card.to_nonzero_scalar(), their.as_affine())
        .raw_secret_bytes()
        .to_vec();
    ch.verify(&reply).unwrap();
    assert!(ch.verify(&reply[..reply.len() - 1]).is_err());
}

#[test]
fn key_agree_round_trips_x25519() {
    let card_scalar = card_scalar::<32>();
    let pubkey = PublicKey::Ecc {
        point: x25519_dalek::x25519(card_scalar, x25519_dalek::X25519_BASEPOINT_BYTES).to_vec(),
    };
    let ch = prepare(SelfTest::KeyAgree, KeyAlg::X25519, &pubkey).unwrap();
    let their: [u8; 32] = ch.card_input.clone().try_into().unwrap();
    let reply = x25519_dalek::x25519(card_scalar, their).to_vec();
    ch.verify(&reply).unwrap();

    let mut bad = reply.clone();
    bad[0] ^= 0x01;
    assert!(matches!(ch.verify(&bad), Err(TestError::Mismatch(_))));
}

// --- Sign ------------------------------------------------------------

#[test]
fn sign_round_trips_p256() {
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    let sk = p256::ecdsa::SigningKey::from_slice(&card_scalar::<32>()).unwrap();
    let pubkey = PublicKey::Ecc {
        point: sk
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec(),
    };
    let ch = prepare(SelfTest::Sign, KeyAlg::EccP256, &pubkey).unwrap();
    let sig: p256::ecdsa::Signature = sk.sign_prehash(&ch.card_input).unwrap();
    ch.verify(sig.to_der().as_bytes()).unwrap();

    // A signature over a different digest is well-formed DER but must not verify.
    let other: p256::ecdsa::Signature = sk.sign_prehash(&[0x11; 32]).unwrap();
    assert!(matches!(
        ch.verify(other.to_der().as_bytes()),
        Err(TestError::Mismatch(_))
    ));
}

#[test]
fn sign_round_trips_p384() {
    use p384::ecdsa::signature::hazmat::PrehashSigner;
    let sk = p384::ecdsa::SigningKey::from_slice(&card_scalar::<48>()).unwrap();
    let pubkey = PublicKey::Ecc {
        point: sk
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec(),
    };
    let ch = prepare(SelfTest::Sign, KeyAlg::EccP384, &pubkey).unwrap();
    let sig: p384::ecdsa::Signature = sk.sign_prehash(&ch.card_input).unwrap();
    ch.verify(sig.to_der().as_bytes()).unwrap();
}

#[test]
fn sign_round_trips_p521() {
    use p521::ecdsa::signature::hazmat::PrehashSigner;
    let sk = p521::ecdsa::SigningKey::from_slice(&card_scalar::<66>()).unwrap();
    let pubkey = PublicKey::Ecc {
        point: sk.verifying_key().to_sec1_point(false).as_bytes().to_vec(),
    };
    let ch = prepare(SelfTest::Sign, KeyAlg::EccP521, &pubkey).unwrap();
    let sig: p521::ecdsa::Signature = sk.sign_prehash(&ch.card_input).unwrap();
    ch.verify(sig.to_der().as_bytes()).unwrap();

    // A signature over a different digest is well-formed DER but must not verify.
    let other: p521::ecdsa::Signature = sk.sign_prehash(&[0x11; 64]).unwrap();
    assert!(matches!(
        ch.verify(other.to_der().as_bytes()),
        Err(TestError::Mismatch(_))
    ));
}

#[test]
fn sign_round_trips_ed25519() {
    use ed25519_dalek::Signer;
    let sk = ed25519_dalek::SigningKey::from_bytes(&card_scalar::<32>());
    let pubkey = PublicKey::Ecc {
        point: sk.verifying_key().to_bytes().to_vec(),
    };
    let ch = prepare(SelfTest::Sign, KeyAlg::Ed25519, &pubkey).unwrap();
    // Ed25519 signs the whole message, which is exactly `card_input`.
    let sig = sk.sign(&ch.card_input);
    ch.verify(&sig.to_bytes()).unwrap();

    let mut bad = sig.to_bytes();
    bad[0] ^= 0x01;
    assert!(matches!(ch.verify(&bad), Err(TestError::Mismatch(_))));
}

// --- Gating --------------------------------------------------------

#[test]
fn supports_matrix() {
    assert!(supports(SelfTest::Decrypt, KeyAlg::Rsa2048));
    assert!(!supports(SelfTest::Decrypt, KeyAlg::EccP256));
    assert!(supports(SelfTest::KeyAgree, KeyAlg::EccP384));
    assert!(supports(SelfTest::KeyAgree, KeyAlg::EccP521));
    assert!(supports(SelfTest::KeyAgree, KeyAlg::X25519));
    assert!(!supports(SelfTest::KeyAgree, KeyAlg::Ed25519));
    assert!(supports(SelfTest::Sign, KeyAlg::EccP521));
    assert!(supports(SelfTest::Sign, KeyAlg::Ed25519));
    assert!(!supports(SelfTest::Sign, KeyAlg::X25519));
    assert!(!supports(SelfTest::Decrypt, KeyAlg::EccP521));
}

#[test]
fn prepare_rejects_unsupported_combo() {
    let pubkey = PublicKey::Ecc {
        point: vec![0x04; 65],
    };
    assert!(matches!(
        prepare(SelfTest::Decrypt, KeyAlg::EccP256, &pubkey),
        Err(TestError::Unsupported(SelfTest::Decrypt, KeyAlg::EccP256))
    ));
}

// --- full run: every applicable op, others skipped --------------------

#[test]
fn run_rsa_covers_decrypt_and_sign_skips_key_agree() {
    let key = card_rsa();
    let n = key.n().clone();
    let d = key.d().clone();
    let k = key.n().to_bytes_be().len();
    let results = run(
        KeyAlg::Rsa1024,
        &rsa_pub(&key),
        |_op, input| -> Result<Vec<u8>, String> { Ok(rsa_raw(input, &d, &n, k)) },
    );
    assert_eq!(
        results,
        vec![
            (SelfTest::Decrypt, Outcome::Passed),
            (SelfTest::KeyAgree, Outcome::Skipped(KeyAlg::Rsa1024)),
            (SelfTest::Sign, Outcome::Passed),
        ]
    );
    let report = format_report(&results);
    assert!(report.contains("Decrypt: passed"));
    assert!(report.contains("Key Agree: skipped \u{2014} not supported for RSA-1024 keys"));
    assert!(!results.iter().any(|(_, r)| r.is_failure()));
}

#[test]
fn run_p256_covers_key_agree_and_sign_skips_decrypt() {
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    let secret = p256::SecretKey::from_slice(&card_scalar::<32>()).unwrap();
    let sk = p256::ecdsa::SigningKey::from_slice(&card_scalar::<32>()).unwrap();
    let pubkey = PublicKey::Ecc {
        point: secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec(),
    };
    let results = run(
        KeyAlg::EccP256,
        &pubkey,
        |op, input| -> Result<Vec<u8>, String> {
            if op.is_key_agreement() {
                let their = p256::PublicKey::from_sec1_bytes(input).unwrap();
                Ok(
                    p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), their.as_affine())
                        .raw_secret_bytes()
                        .to_vec(),
                )
            } else {
                let sig: p256::ecdsa::Signature = sk.sign_prehash(input).unwrap();
                Ok(sig.to_der().as_bytes().to_vec())
            }
        },
    );
    assert_eq!(
        results,
        vec![
            (SelfTest::Decrypt, Outcome::Skipped(KeyAlg::EccP256)),
            (SelfTest::KeyAgree, Outcome::Passed),
            (SelfTest::Sign, Outcome::Passed),
        ]
    );
}

#[test]
fn run_reports_a_card_failure_as_failed_not_a_panic() {
    let key = card_rsa();
    let results = run(
        KeyAlg::Rsa1024,
        &rsa_pub(&key),
        |_op, _input| -> Result<Vec<u8>, String> { Err("card said no".to_string()) },
    );
    assert!(matches!(
        results[0],
        (SelfTest::Decrypt, Outcome::Failed(_))
    ));
    assert_eq!(
        results[1],
        (SelfTest::KeyAgree, Outcome::Skipped(KeyAlg::Rsa1024))
    );
    assert!(results.iter().any(|(_, r)| r.is_failure()));
}
