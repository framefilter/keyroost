//! Host-side round-trip self-tests for a PIV slot's private key.
//!
//! Each [`SelfTest`] exercises one private-key operation end to end: build a
//! fixed challenge ([`prepare`]), hand its `card_input` to the card's GENERAL
//! AUTHENTICATE (that part lives in `keyroost-transport`), then check the
//! reply with [`Challenge::verify`] against the *public* key from the slot's
//! certificate. A pass means the card really can decrypt / key-agree / sign
//! with that slot and the matching public key accepts the result.
//!
//! This is a **functional** check, not a known-answer test and not a security
//! operation: every input is a compile-time constant (see the private `data` module), so
//! there is no RNG anywhere in this crate.
//!
//! Supported per operation:
//!
//! | operation   | RSA | P-256 | P-384 | P-521 | Ed25519 | X25519 |
//! |-------------|-----|-------|-------|-------|---------|--------|
//! | [`SelfTest::Decrypt`]  | ✔ |   |   |   |   |   |
//! | [`SelfTest::KeyAgree`] |   | ✔ | ✔ | ✔ |   | ✔ |
//! | [`SelfTest::Sign`]     | ✔ | ✔ | ✔ | ✔ | ✔ |   |

#![forbid(unsafe_code)]

mod data;

use core::fmt;

use data::{ec_scalar, DECRYPT_PLAINTEXT, SHA512_DIGESTINFO_PREFIX, TEST_INPUT};
// `elliptic_curve` is shared by p256, p384, and p521; one import covers all three curves.
pub use keyroost_piv::{KeyAlg, PublicKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;

/// One private-key operation a PIV slot can be tested against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfTest {
    /// RSA: PKCS#1 v1.5-encrypt a known string to the slot's public key, have
    /// the card decrypt it, check the plaintext comes back.
    Decrypt,
    /// ECDH (P-256 / P-384 / P-521 / X25519): agree a shared secret two ways — the
    /// card's private key against a fixed peer public key, and this host's
    /// fixed peer private key against the slot's public key — and check they
    /// match.
    KeyAgree,
    /// Sign a fixed digest / message on the card, verify the signature with
    /// the slot's public key.
    Sign,
}

impl SelfTest {
    /// Short button/label text.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            SelfTest::Decrypt => "Decrypt",
            SelfTest::KeyAgree => "Key Agree",
            SelfTest::Sign => "Sign",
        }
    }

    /// All three, in display order.
    #[must_use]
    pub const fn all() -> [SelfTest; 3] {
        [SelfTest::Decrypt, SelfTest::KeyAgree, SelfTest::Sign]
    }

    /// Whether this operation reads the card reply out of the key-agreement
    /// exponentiation field (GENERAL AUTHENTICATE dynamic-auth tag `0x85`)
    /// rather than the plain data field (`0x81`). The transport layer uses
    /// this to pick the right builder.
    #[must_use]
    pub const fn is_key_agreement(self) -> bool {
        matches!(self, SelfTest::KeyAgree)
    }
}

/// Whether [`prepare`] can build a challenge for `op` against a key of `alg`.
/// The GUI gates its buttons on this; [`prepare`] enforces it too.
#[must_use]
pub fn supports(op: SelfTest, alg: KeyAlg) -> bool {
    let rsa = matches!(
        alg,
        KeyAlg::Rsa1024 | KeyAlg::Rsa2048 | KeyAlg::Rsa3072 | KeyAlg::Rsa4096
    );
    match op {
        SelfTest::Decrypt => rsa,
        SelfTest::KeyAgree => matches!(
            alg,
            KeyAlg::EccP256 | KeyAlg::EccP384 | KeyAlg::EccP521 | KeyAlg::X25519
        ),
        SelfTest::Sign => {
            rsa || matches!(
                alg,
                KeyAlg::EccP256 | KeyAlg::EccP384 | KeyAlg::EccP521 | KeyAlg::Ed25519
            )
        }
    }
}

/// Why a self-test could not be built or did not pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestError {
    /// `op` is not defined for a key of this algorithm (see [`supports`]).
    Unsupported(SelfTest, KeyAlg),
    /// The slot's public key (from its certificate) is the wrong type or
    /// malformed for this operation.
    BadPublicKey(&'static str),
    /// The card answered, but its reply is structurally wrong (not a PKCS#1
    /// block, not DER, wrong length, …).
    CardReply(&'static str),
    /// The operation ran and produced a well-formed result that does **not**
    /// match what the public key expects — the slot's key does not verify.
    Mismatch(SelfTest),
}

impl fmt::Display for TestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TestError::Unsupported(op, alg) => {
                write!(
                    f,
                    "{} self-test is not available for {} keys",
                    op.label(),
                    alg.label()
                )
            }
            TestError::BadPublicKey(why) => write!(f, "slot public key unusable: {why}"),
            TestError::CardReply(why) => write!(f, "card reply malformed: {why}"),
            TestError::Mismatch(op) => {
                write!(
                    f,
                    "{} self-test failed: the result did not verify against the slot's public key",
                    op.label()
                )
            }
        }
    }
}

impl std::error::Error for TestError {}

/// A prepared self-test: what to send the card, plus what to check.
pub struct Challenge {
    op: SelfTest,
    /// Bytes for the card's GENERAL AUTHENTICATE dynamic-authentication
    /// template value — the data field (`0x81`) for [`SelfTest::Decrypt`] /
    /// [`SelfTest::Sign`], the exponentiation field (`0x85`) for
    /// [`SelfTest::KeyAgree`]. See [`SelfTest::is_key_agreement`].
    pub card_input: Vec<u8>,
    verifier: Verifier,
}

impl Challenge {
    /// The operation this challenge is for.
    #[must_use]
    pub const fn op(&self) -> SelfTest {
        self.op
    }

    /// Check the card's GENERAL AUTHENTICATE reply. `Ok(())` = the self-test
    /// passed.
    pub fn verify(&self, card_reply: &[u8]) -> Result<(), TestError> {
        match &self.verifier {
            Verifier::RsaEme => verify_rsa_eme(card_reply),
            Verifier::Exact(want) => (card_reply == want.as_slice())
                .then_some(())
                .ok_or(TestError::Mismatch(SelfTest::KeyAgree)),
            Verifier::RsaSig { modulus, exponent } => verify_rsa_sig(modulus, exponent, card_reply),
            Verifier::EcdsaSig {
                curve,
                point,
                digest_len,
            } => verify_ecdsa(*curve, point, *digest_len, card_reply),
            Verifier::Ed25519Sig { pubkey } => verify_ed25519(pubkey, card_reply),
        }
    }
}

enum Verifier {
    /// Card returns `c^d mod n` = our PKCS#1 v1.5 EME block; strip the padding
    /// and match the tail against [`DECRYPT_PLAINTEXT`].
    RsaEme,
    /// Card reply must equal these bytes verbatim (ECDH shared secret).
    Exact(Vec<u8>),
    /// RSA signature over `PKCS1v15(DigestInfo(SHA-512, TEST_INPUT[..64]))`.
    RsaSig { modulus: Vec<u8>, exponent: Vec<u8> },
    /// DER ECDSA signature over `TEST_INPUT[..digest_len]` as a prehash.
    EcdsaSig {
        curve: EcCurve,
        point: Vec<u8>,
        digest_len: usize,
    },
    /// Ed25519 signature over the whole of `TEST_INPUT`.
    Ed25519Sig { pubkey: [u8; 32] },
}

#[derive(Clone, Copy)]
enum EcCurve {
    P256,
    P384,
    P521,
}

/// Build the challenge for `op` against a slot holding `(alg, pubkey)`, where
/// `pubkey` is the slot certificate's public key.
///
/// # Errors
/// [`TestError::Unsupported`] if `op` is not defined for `alg`;
/// [`TestError::BadPublicKey`] if `pubkey` is the wrong type or malformed.
pub fn prepare(op: SelfTest, alg: KeyAlg, pubkey: &PublicKey) -> Result<Challenge, TestError> {
    if !supports(op, alg) {
        return Err(TestError::Unsupported(op, alg));
    }
    match op {
        SelfTest::Decrypt => prepare_decrypt(pubkey),
        SelfTest::KeyAgree => prepare_key_agree(alg, pubkey),
        SelfTest::Sign => prepare_sign(alg, pubkey),
    }
}

// --- Decrypt --------------------------------------------------------------

fn prepare_decrypt(pubkey: &PublicKey) -> Result<Challenge, TestError> {
    let (modulus, exponent) = rsa_parts(pubkey)?;
    let k = modulus.len();
    let msg = DECRYPT_PLAINTEXT;
    // EME-PKCS1-v1_5: 00 02 || PS (>= 8 non-zero bytes) || 00 || M
    let ps_len =
        k.checked_sub(msg.len() + 3)
            .filter(|&l| l >= 8)
            .ok_or(TestError::BadPublicKey(
                "RSA modulus too small for the test message",
            ))?;
    let mut em = Vec::with_capacity(k);
    em.push(0x00);
    em.push(0x02);
    em.extend(TEST_INPUT.iter().copied().cycle().take(ps_len)); // every byte non-zero
    em.push(0x00);
    em.extend_from_slice(msg);
    debug_assert_eq!(em.len(), k);
    let ciphertext = rsa_public_op(modulus, exponent, &em, k)?;
    Ok(Challenge {
        op: SelfTest::Decrypt,
        card_input: ciphertext,
        verifier: Verifier::RsaEme,
    })
}

fn verify_rsa_eme(reply: &[u8]) -> Result<(), TestError> {
    // Card returns c^d mod n = the EME block we built; some implementations
    // drop the leading 0x00.
    let body = match reply.first() {
        Some(0x00) => &reply[1..],
        _ => reply,
    };
    let body = body.strip_prefix(&[0x02]).ok_or(TestError::CardReply(
        "decrypt result is not a PKCS#1 v1.5 block",
    ))?;
    let sep = body
        .iter()
        .position(|&b| b == 0x00)
        .ok_or(TestError::CardReply(
            "decrypt result has no padding separator",
        ))?;
    if sep < 8 {
        return Err(TestError::CardReply("decrypt result padding too short"));
    }
    (&body[sep + 1..] == DECRYPT_PLAINTEXT)
        .then_some(())
        .ok_or(TestError::Mismatch(SelfTest::Decrypt))
}

// --- Key agreement ------------------------------------------------------

fn prepare_key_agree(alg: KeyAlg, pubkey: &PublicKey) -> Result<Challenge, TestError> {
    let point = ecc_point(pubkey)?;
    let (card_input, shared) = match alg {
        KeyAlg::EccP256 => {
            let our = p256::PublicKey::from_sec1_bytes(point)
                .map_err(|_| TestError::BadPublicKey("malformed P-256 public point"))?;
            let their = p256::SecretKey::from_slice(&ec_scalar::<32>(true))
                .map_err(|_| TestError::BadPublicKey("derived P-256 scalar out of range"))?;
            let secret = p256::ecdh::diffie_hellman(their.to_nonzero_scalar(), our.as_affine());
            (
                their
                    .public_key()
                    .to_encoded_point(false)
                    .as_bytes()
                    .to_vec(),
                secret.raw_secret_bytes().to_vec(),
            )
        }
        KeyAlg::EccP384 => {
            let our = p384::PublicKey::from_sec1_bytes(point)
                .map_err(|_| TestError::BadPublicKey("malformed P-384 public point"))?;
            let their = p384::SecretKey::from_slice(&ec_scalar::<48>(true))
                .map_err(|_| TestError::BadPublicKey("derived P-384 scalar out of range"))?;
            let secret = p384::ecdh::diffie_hellman(their.to_nonzero_scalar(), our.as_affine());
            (
                their
                    .public_key()
                    .to_encoded_point(false)
                    .as_bytes()
                    .to_vec(),
                secret.raw_secret_bytes().to_vec(),
            )
        }
        KeyAlg::EccP521 => {
            // p521 is on a newer major `elliptic-curve` than p256/p384 (no
            // 0.13-series release of it exists), so its SEC1-encoding trait
            // is `ToSec1Point`/`to_sec1_point`, not the `ToEncodedPoint`/
            // `to_encoded_point` the top-of-file import covers for the other
            // two curves — imported locally rather than at module scope so
            // it doesn't collide with (or get mistaken for) that one.
            use p521::elliptic_curve::sec1::ToSec1Point;
            let our = p521::PublicKey::from_sec1_bytes(point)
                .map_err(|_| TestError::BadPublicKey("malformed P-521 public point"))?;
            let their = p521::SecretKey::from_slice(&ec_scalar::<66>(true))
                .map_err(|_| TestError::BadPublicKey("derived P-521 scalar out of range"))?;
            let secret = p521::ecdh::diffie_hellman(their.to_nonzero_scalar(), our.as_affine());
            (
                their.public_key().to_sec1_point(false).as_bytes().to_vec(),
                secret.raw_secret_bytes().to_vec(),
            )
        }
        KeyAlg::X25519 => {
            let our: [u8; 32] = point
                .try_into()
                .map_err(|_| TestError::BadPublicKey("X25519 public key must be 32 bytes"))?;
            let scalar = ec_scalar::<32>(false);
            (
                x25519_dalek::x25519(scalar, x25519_dalek::X25519_BASEPOINT_BYTES).to_vec(),
                x25519_dalek::x25519(scalar, our).to_vec(),
            )
        }
        _ => return Err(TestError::Unsupported(SelfTest::KeyAgree, alg)),
    };
    Ok(Challenge {
        op: SelfTest::KeyAgree,
        card_input,
        verifier: Verifier::Exact(shared),
    })
}

// --- Sign --------------------------------------------------------------

fn prepare_sign(alg: KeyAlg, pubkey: &PublicKey) -> Result<Challenge, TestError> {
    match alg {
        KeyAlg::Rsa1024 | KeyAlg::Rsa2048 | KeyAlg::Rsa3072 | KeyAlg::Rsa4096 => {
            let (modulus, exponent) = rsa_parts(pubkey)?;
            let k = modulus.len();
            let mut t = Vec::with_capacity(SHA512_DIGESTINFO_PREFIX.len() + 64);
            t.extend_from_slice(&SHA512_DIGESTINFO_PREFIX);
            t.extend_from_slice(&TEST_INPUT[..64]);
            // EMSA-PKCS1-v1_5: 00 01 || FF … (>= 8) || 00 || T
            let pad =
                k.checked_sub(t.len() + 3)
                    .filter(|&l| l >= 8)
                    .ok_or(TestError::BadPublicKey(
                        "RSA modulus too small for a SHA-512 signature block",
                    ))?;
            let mut em = Vec::with_capacity(k);
            em.push(0x00);
            em.push(0x01);
            em.resize(2 + pad, 0xFF);
            em.push(0x00);
            em.extend_from_slice(&t);
            debug_assert_eq!(em.len(), k);
            Ok(Challenge {
                op: SelfTest::Sign,
                card_input: em,
                verifier: Verifier::RsaSig {
                    modulus: modulus.to_vec(),
                    exponent: exponent.to_vec(),
                },
            })
        }
        KeyAlg::EccP256 | KeyAlg::EccP384 | KeyAlg::EccP521 => {
            let point = ecc_point(pubkey)?;
            // Digest length is SHA-256/384 for P-256/384 (matching the curve's
            // own field size), and SHA-512 for P-521 (64 bytes — shorter than
            // the 66-byte field, per the conventional NIST/PIV pairing;
            // `keyroost_piv::x509::SigHash::Sha512` uses the same digest for
            // the same reason).
            let (curve, digest_len) = match alg {
                KeyAlg::EccP256 => (EcCurve::P256, 32usize),
                KeyAlg::EccP384 => (EcCurve::P384, 48usize),
                _ => (EcCurve::P521, 64usize),
            };
            // Validate the point up front so a bad cert fails at prepare time.
            match curve {
                EcCurve::P256 => {
                    p256::ecdsa::VerifyingKey::from_sec1_bytes(point)
                        .map_err(|_| TestError::BadPublicKey("malformed P-256 public point"))?;
                }
                EcCurve::P384 => {
                    p384::ecdsa::VerifyingKey::from_sec1_bytes(point)
                        .map_err(|_| TestError::BadPublicKey("malformed P-384 public point"))?;
                }
                EcCurve::P521 => {
                    p521::ecdsa::VerifyingKey::from_sec1_bytes(point)
                        .map_err(|_| TestError::BadPublicKey("malformed P-521 public point"))?;
                }
            }
            Ok(Challenge {
                op: SelfTest::Sign,
                card_input: TEST_INPUT[..digest_len].to_vec(),
                verifier: Verifier::EcdsaSig {
                    curve,
                    point: point.to_vec(),
                    digest_len,
                },
            })
        }
        KeyAlg::Ed25519 => {
            let point = ecc_point(pubkey)?;
            let pk: [u8; 32] = point
                .try_into()
                .map_err(|_| TestError::BadPublicKey("Ed25519 public key must be 32 bytes"))?;
            ed25519_dalek::VerifyingKey::from_bytes(&pk)
                .map_err(|_| TestError::BadPublicKey("invalid Ed25519 public key"))?;
            Ok(Challenge {
                op: SelfTest::Sign,
                card_input: TEST_INPUT.to_vec(),
                verifier: Verifier::Ed25519Sig { pubkey: pk },
            })
        }
        _ => Err(TestError::Unsupported(SelfTest::Sign, alg)),
    }
}

fn verify_rsa_sig(modulus: &[u8], exponent: &[u8], sig: &[u8]) -> Result<(), TestError> {
    let key = rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(modulus),
        rsa::BigUint::from_bytes_be(exponent),
    )
    .map_err(|_| TestError::BadPublicKey("invalid RSA public key"))?;
    let scheme = rsa::Pkcs1v15Sign {
        hash_len: Some(64),
        prefix: SHA512_DIGESTINFO_PREFIX.to_vec().into_boxed_slice(),
    };
    key.verify(scheme, &TEST_INPUT[..64], sig)
        .map_err(|_| TestError::Mismatch(SelfTest::Sign))
}

fn verify_ecdsa(
    curve: EcCurve,
    point: &[u8],
    digest_len: usize,
    sig: &[u8],
) -> Result<(), TestError> {
    let digest = &TEST_INPUT[..digest_len];
    match curve {
        EcCurve::P256 => {
            use p256::ecdsa::signature::hazmat::PrehashVerifier;
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(point)
                .map_err(|_| TestError::BadPublicKey("malformed P-256 public point"))?;
            let s = p256::ecdsa::Signature::from_der(sig)
                .map_err(|_| TestError::CardReply("ECDSA signature is not valid DER"))?;
            vk.verify_prehash(digest, &s)
                .map_err(|_| TestError::Mismatch(SelfTest::Sign))
        }
        EcCurve::P384 => {
            use p384::ecdsa::signature::hazmat::PrehashVerifier;
            let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(point)
                .map_err(|_| TestError::BadPublicKey("malformed P-384 public point"))?;
            let s = p384::ecdsa::Signature::from_der(sig)
                .map_err(|_| TestError::CardReply("ECDSA signature is not valid DER"))?;
            vk.verify_prehash(digest, &s)
                .map_err(|_| TestError::Mismatch(SelfTest::Sign))
        }
        EcCurve::P521 => {
            use p521::ecdsa::signature::hazmat::PrehashVerifier;
            let vk = p521::ecdsa::VerifyingKey::from_sec1_bytes(point)
                .map_err(|_| TestError::BadPublicKey("malformed P-521 public point"))?;
            let s = p521::ecdsa::Signature::from_der(sig)
                .map_err(|_| TestError::CardReply("ECDSA signature is not valid DER"))?;
            vk.verify_prehash(digest, &s)
                .map_err(|_| TestError::Mismatch(SelfTest::Sign))
        }
    }
}

fn verify_ed25519(pubkey: &[u8; 32], sig: &[u8]) -> Result<(), TestError> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(pubkey)
        .map_err(|_| TestError::BadPublicKey("invalid Ed25519 public key"))?;
    let s = ed25519_dalek::Signature::from_slice(sig)
        .map_err(|_| TestError::CardReply("Ed25519 signature must be 64 bytes"))?;
    vk.verify_strict(&TEST_INPUT, &s)
        .map_err(|_| TestError::Mismatch(SelfTest::Sign))
}

// --- shared helpers ---------------------------------------------------

fn rsa_parts(pk: &PublicKey) -> Result<(&[u8], &[u8]), TestError> {
    match pk {
        PublicKey::Rsa { modulus, exponent } => Ok((modulus, exponent)),
        PublicKey::Ecc { .. } => Err(TestError::BadPublicKey("expected an RSA public key")),
    }
}

fn ecc_point(pk: &PublicKey) -> Result<&[u8], TestError> {
    match pk {
        PublicKey::Ecc { point } => Ok(point),
        PublicKey::Rsa { .. } => Err(TestError::BadPublicKey("expected an EC public key")),
    }
}

/// `m^e mod n`, left-padded to `k` bytes. Validates the key shape through
/// [`rsa::RsaPublicKey::new`] first.
fn rsa_public_op(
    modulus: &[u8],
    exponent: &[u8],
    m: &[u8],
    k: usize,
) -> Result<Vec<u8>, TestError> {
    let n = rsa::BigUint::from_bytes_be(modulus);
    let e = rsa::BigUint::from_bytes_be(exponent);
    rsa::RsaPublicKey::new(n.clone(), e.clone())
        .map_err(|_| TestError::BadPublicKey("invalid RSA public key"))?;
    let c = rsa::BigUint::from_bytes_be(m).modpow(&e, &n);
    let be = c.to_bytes_be();
    Ok(if be.len() >= k {
        be
    } else {
        let mut out = vec![0u8; k - be.len()];
        out.extend_from_slice(&be);
        out
    })
}

// --- full run: every applicable operation -----------------------------

/// How one operation went in a [`run`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Ran, and the reply verified against the slot's public key.
    Passed,
    /// Ran, but the reply did not verify (or the card / challenge errored) —
    /// carries a short reason.
    Failed(String),
    /// Not run: this operation doesn't apply to the slot key's algorithm
    /// (carried so a report can name it).
    Skipped(KeyAlg),
}

impl Outcome {
    /// Whether this is a real failure (a `Skipped` op is not).
    #[must_use]
    pub fn is_failure(&self) -> bool {
        matches!(self, Outcome::Failed(_))
    }
}

/// Run every [`SelfTest`] against a slot holding `(alg, pubkey)` — `pubkey`
/// being the slot certificate's public key — in `Decrypt` → `KeyAgree` →
/// `Sign` order.
///
/// For each *applicable* operation, [`prepare`] builds the GENERAL
/// AUTHENTICATE input, `card(op, input)` performs the card's private-key op
/// and returns the raw reply, and [`Challenge::verify`] checks it. `card` also
/// owns any per-op PIN dance (a PIN-per-use slot needs a fresh VERIFY before
/// each op). Operations the key algorithm doesn't support are returned as
/// [`Outcome::Skipped`] and `card` is not called for them.
///
/// Always returns one entry per [`SelfTest::all`]; never errors (a card error
/// mid-op becomes that op's [`Outcome::Failed`]).
pub fn run<F, E>(alg: KeyAlg, pubkey: &PublicKey, mut card: F) -> Vec<(SelfTest, Outcome)>
where
    F: FnMut(SelfTest, &[u8]) -> Result<Vec<u8>, E>,
    E: core::fmt::Display,
{
    SelfTest::all()
        .into_iter()
        .map(|op| {
            if !supports(op, alg) {
                return (op, Outcome::Skipped(alg));
            }
            let outcome = (|| -> Result<(), String> {
                let ch = prepare(op, alg, pubkey).map_err(|e| e.to_string())?;
                let reply = card(op, &ch.card_input).map_err(|e| e.to_string())?;
                ch.verify(&reply).map_err(|e| e.to_string())
            })();
            (
                op,
                match outcome {
                    Ok(()) => Outcome::Passed,
                    Err(e) => Outcome::Failed(e),
                },
            )
        })
        .collect()
}

/// One human-readable line per operation:
/// `<op>: passed`, `<op>: FAILED \u{2014} <reason>`, or
/// `<op>: skipped \u{2014} not supported for <alg> keys`.
#[must_use]
pub fn format_report(results: &[(SelfTest, Outcome)]) -> String {
    results
        .iter()
        .map(|(op, r)| match r {
            Outcome::Passed => format!("{}: passed", op.label()),
            Outcome::Failed(e) => format!("{}: FAILED \u{2014} {e}", op.label()),
            Outcome::Skipped(alg) => format!(
                "{}: skipped \u{2014} not supported for {} keys",
                op.label(),
                alg.label()
            ),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests;
