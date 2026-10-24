//! Key types, key generation and OpenPGP v4 public-key bodies.
//!
//! A key set is three keys — sign (the primary), decrypt, authenticate — of
//! one [`KeyType`]. Each [`KeyPart`] knows how to write its public-key packet
//! body (byte-identical to what `keyroost-openpgp` hashes for the card's
//! fingerprint), its secret MPIs in GnuPG's layout, and the neutral
//! form the card import takes.

use keyroost_openpgp::{ecdh_kdf_params, AlgorithmInformation, Curve, EccKind, KeyAlg, KeyCrt};
use rand_core::{OsRng, RngCore};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{BigUint, RsaPrivateKey};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::packet::{push_mpi, Reader};
use crate::Error;

type Result<T> = std::result::Result<T, Error>;

/// OpenPGP public-key algorithm ids (RFC 4880 §9.1, RFC 6637, RFC 8032 draft).
const ALGO_RSA: u8 = 1;
const ALGO_ECDH: u8 = 18;
const ALGO_ECDSA: u8 = 19;
const ALGO_EDDSA: u8 = 22;

/// The key types keyroost can create and back up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyType {
    Rsa2048,
    Rsa3072,
    Rsa4096,
    NistP256,
    NistP384,
    NistP521,
    Secp256k1,
    /// Ed25519 for signing and authentication, X25519 for decryption.
    Cv25519,
}

impl KeyType {
    /// Every key type, in menu order.
    pub const ALL: [KeyType; 8] = [
        KeyType::Rsa2048,
        KeyType::Rsa3072,
        KeyType::Rsa4096,
        KeyType::NistP256,
        KeyType::NistP384,
        KeyType::NistP521,
        KeyType::Secp256k1,
        KeyType::Cv25519,
    ];

    /// Human label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            KeyType::Rsa2048 => "RSA-2048",
            KeyType::Rsa3072 => "RSA-3072",
            KeyType::Rsa4096 => "RSA-4096",
            KeyType::NistP256 => "NIST P-256",
            KeyType::NistP384 => "NIST P-384",
            KeyType::NistP521 => "NIST P-521",
            KeyType::Secp256k1 => "secp256k1",
            KeyType::Cv25519 => "Curve 25519",
        }
    }

    /// The word the CLI accepts for this type.
    #[must_use]
    pub const fn cli_name(self) -> &'static str {
        match self {
            KeyType::Rsa2048 => "rsa2048",
            KeyType::Rsa3072 => "rsa3072",
            KeyType::Rsa4096 => "rsa4096",
            KeyType::NistP256 => "nistp256",
            KeyType::NistP384 => "nistp384",
            KeyType::NistP521 => "nistp521",
            KeyType::Secp256k1 => "secp256k1",
            KeyType::Cv25519 => "ed25519",
        }
    }

    /// The card algorithm for this type in `crt`'s slot.
    #[must_use]
    pub const fn card_alg(self, crt: KeyCrt) -> KeyAlg {
        match self {
            KeyType::Rsa2048 => KeyAlg::Rsa2048,
            KeyType::Rsa3072 => KeyAlg::Rsa3072,
            KeyType::Rsa4096 => KeyAlg::Rsa4096,
            KeyType::NistP256 => KeyAlg::NistP256,
            KeyType::NistP384 => KeyAlg::NistP384,
            KeyType::NistP521 => KeyAlg::NistP521,
            KeyType::Secp256k1 => KeyAlg::Secp256k1,
            KeyType::Cv25519 => match crt {
                KeyCrt::Decrypt => KeyAlg::X25519,
                KeyCrt::Sign | KeyCrt::Auth => KeyAlg::Ed25519,
            },
        }
    }

    /// The first slot whose Algorithm Information (`FA`) lists algorithms
    /// but not this type's for it — the card would refuse the set there. A
    /// slot that lists nothing counts as unknown, not as a refusal.
    #[must_use]
    pub fn refused_slot(self, fa: &AlgorithmInformation) -> Option<KeyCrt> {
        [KeyCrt::Sign, KeyCrt::Decrypt, KeyCrt::Auth]
            .into_iter()
            .find(|&crt| {
                let algs = fa.key_algs(crt);
                !algs.is_empty() && !algs.contains(&self.card_alg(crt))
            })
    }

    /// The types a card takes in all three slots: every type when it
    /// publishes no Algorithm Information (`None`), otherwise those
    /// [`refused_slot`](Self::refused_slot) finds no slot against, in
    /// [`ALL`](Self::ALL) order.
    #[must_use]
    pub fn offered(fa: Option<&AlgorithmInformation>) -> Vec<KeyType> {
        match fa {
            None => KeyType::ALL.to_vec(),
            Some(fa) => KeyType::ALL
                .into_iter()
                .filter(|t| t.refused_slot(fa).is_none())
                .collect(),
        }
    }

    /// The type to use when none was chosen: Curve 25519 (GnuPG's default)
    /// when `offered` has it, else RSA-3072, else the first offered;
    /// `None` when nothing is offered.
    #[must_use]
    pub fn preferred(offered: &[KeyType]) -> Option<KeyType> {
        [KeyType::Cv25519, KeyType::Rsa3072]
            .into_iter()
            .find(|t| offered.contains(t))
            .or_else(|| offered.first().copied())
    }

    /// The key type a card algorithm belongs to; `None` for the card-only
    /// Brainpool curves.
    #[must_use]
    pub const fn from_key_alg(alg: KeyAlg) -> Option<KeyType> {
        match alg {
            KeyAlg::Rsa2048 => Some(KeyType::Rsa2048),
            KeyAlg::Rsa3072 => Some(KeyType::Rsa3072),
            KeyAlg::Rsa4096 => Some(KeyType::Rsa4096),
            KeyAlg::NistP256 => Some(KeyType::NistP256),
            KeyAlg::NistP384 => Some(KeyType::NistP384),
            KeyAlg::NistP521 => Some(KeyType::NistP521),
            KeyAlg::Secp256k1 => Some(KeyType::Secp256k1),
            KeyAlg::Ed25519 | KeyAlg::X25519 => Some(KeyType::Cv25519),
            KeyAlg::BrainpoolP256r1 | KeyAlg::BrainpoolP384r1 | KeyAlg::BrainpoolP512r1 => None,
        }
    }
}

/// The key material of one key. All integers are big-endian unless noted.
#[derive(Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub enum Material {
    /// RSA with `p < q` (OpenPGP's order). `u_pgp = p⁻¹ mod q` goes in the
    /// OpenPGP file; `u_card = q⁻¹ mod p` (PKCS#1 `qinv`) goes to the card.
    /// `dp = d mod (p-1)`, `dq = d mod (q-1)`.
    Rsa {
        n: Vec<u8>,
        e: Vec<u8>,
        d: Vec<u8>,
        p: Vec<u8>,
        q: Vec<u8>,
        u_pgp: Vec<u8>,
        u_card: Vec<u8>,
        dp: Vec<u8>,
        dq: Vec<u8>,
    },
    /// ECDSA on a Weierstrass curve; `d` padded to the field length, `point`
    /// SEC1 uncompressed `04||X||Y`.
    Ecdsa {
        #[zeroize(skip)]
        curve: Curve,
        d: Vec<u8>,
        point: Vec<u8>,
    },
    /// ECDH. Weierstrass curves as for [`Material::Ecdsa`]; for X25519 `d` is
    /// the 32-byte RFC 7748 (little-endian) scalar and `point` the 32-byte
    /// u-coordinate (no `0x40` prefix). `kdf` is the public body's KDF
    /// field as stored (`03 01 <hash> <cipher>`): keyroost writes
    /// [`ecdh_kdf_params`], but a key read from a file keeps its own
    /// (GnuPG picks AES-256 for P-384, for one), because the fingerprint
    /// hashes it.
    Ecdh {
        #[zeroize(skip)]
        curve: Curve,
        d: Vec<u8>,
        point: Vec<u8>,
        #[zeroize(skip)]
        kdf: [u8; 4],
    },
    /// Ed25519: the 32-byte seed and the 32-byte public key.
    EdDsa { seed: [u8; 32], point: [u8; 32] },
}

/// One key of a set: its material and creation time.
pub struct KeyPart {
    pub material: Material,
    pub created: u32,
}

/// Key material in the form the card import takes, without transport types.
// Only the `card` feature's import uses it (and the tests).
#[cfg_attr(not(feature = "card"), allow(dead_code))]
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) enum CardKey {
    /// PKCS#1 CRT components; `u = q⁻¹ mod p`.
    Rsa {
        e: Vec<u8>,
        p: Vec<u8>,
        q: Vec<u8>,
        u: Vec<u8>,
        dp: Vec<u8>,
        dq: Vec<u8>,
        n: Vec<u8>,
    },
    /// ECC private scalar (big-endian, zero-padded to the field length) and
    /// public point. X25519's scalar is the RFC 7748 bytes reversed here,
    /// the same as the file MPI. A YubiKey 5 (firmware 5.7.4) takes this
    /// order: after importing it, the card's READ PUBLIC KEY returned the
    /// same X25519 point as `point`, and the registered fingerprints
    /// matched (both the extended-length and the command-chaining paths).
    Ecc { scalar: Vec<u8>, point: Vec<u8> },
    /// Ed25519 seed.
    Ed25519 { seed: [u8; 32] },
}

fn mismatch() -> Error {
    Error::Malformed("key does not match its public part")
}

/// Bytes of a field element (and private scalar) on `curve`.
const fn field_len(curve: Curve) -> usize {
    match curve {
        Curve::NistP384 | Curve::BrainpoolP384r1 => 48,
        Curve::NistP521 => 66,
        Curve::BrainpoolP512r1 => 64,
        _ => 32,
    }
}

/// Left-pad a big-endian value to `len` bytes (MPI encoding strips leading
/// zeros).
fn left_pad(v: &[u8], len: usize) -> Result<Zeroizing<Vec<u8>>> {
    let pad = len
        .checked_sub(v.len())
        .ok_or(Error::Malformed("secret value too long for its curve"))?;
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    out.resize(pad, 0);
    out.extend_from_slice(v);
    Ok(out)
}

fn reversed32(v: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    for (o, b) in out.iter_mut().zip(v.iter().rev()) {
        *o = *b;
    }
    out
}

/// SEC1 uncompressed public point for the Weierstrass scalar `d`.
fn ec_point(curve: Curve, d: &[u8]) -> Result<Vec<u8>> {
    // p256, p384, k256 and p521 share one `elliptic-curve`, so this import
    // covers all four curves.
    use p256::elliptic_curve::sec1::ToSec1Point;
    Ok(match curve {
        Curve::NistP256 => p256::SecretKey::from_slice(d)
            .map_err(|_| mismatch())?
            .public_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec(),
        Curve::NistP384 => p384::SecretKey::from_slice(d)
            .map_err(|_| mismatch())?
            .public_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec(),
        Curve::Secp256k1 => k256::SecretKey::from_slice(d)
            .map_err(|_| mismatch())?
            .public_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec(),
        Curve::NistP521 => p521::SecretKey::from_slice(d)
            .map_err(|_| mismatch())?
            .public_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec(),
        _ => return Err(Error::Unsupported("curve")),
    })
}

/// A fresh random private scalar on a Weierstrass curve, field-length bytes.
fn ec_random(curve: Curve) -> Result<Zeroizing<Vec<u8>>> {
    use p256::elliptic_curve::Generate;
    fn take(mut b: impl AsMut<[u8]>) -> Zeroizing<Vec<u8>> {
        let v = Zeroizing::new(b.as_mut().to_vec());
        b.as_mut().zeroize();
        v
    }
    Ok(match curve {
        // The curve crates are on a newer rand_core than `OsRng` here, so
        // they draw from the OS RNG themselves (their `getrandom` feature).
        Curve::NistP256 => take(p256::SecretKey::from(p256::NonZeroScalar::generate()).to_bytes()),
        Curve::NistP384 => take(p384::SecretKey::from(p384::NonZeroScalar::generate()).to_bytes()),
        Curve::Secp256k1 => take(k256::SecretKey::from(k256::NonZeroScalar::generate()).to_bytes()),
        Curve::NistP521 => take(p521::SecretKey::from(p521::NonZeroScalar::generate()).to_bytes()),
        _ => return Err(Error::Unsupported("curve")),
    })
}

/// RSA material from `n, e, d` and the two primes in any order: orders them
/// `p < q`, checks they make a valid key, and derives both CRT coefficients.
fn rsa_material(n: &[u8], e: &[u8], d: &[u8], a: &[u8], b: &[u8]) -> Result<Material> {
    let (a, b) = (
        Zeroizing::new(BigUint::from_bytes_be(a)),
        Zeroizing::new(BigUint::from_bytes_be(b)),
    );
    let (p, q) = if *a < *b { (a, b) } else { (b, a) };
    let n_big = BigUint::from_bytes_be(n);
    let e_big = BigUint::from_bytes_be(e);
    let d_big = Zeroizing::new(BigUint::from_bytes_be(d));
    let key = RsaPrivateKey::from_components(
        n_big,
        e_big,
        (*d_big).clone(),
        vec![(*p).clone(), (*q).clone()],
    )
    .map_err(|_| mismatch())?;
    // Checks n = p*q and that d inverts e modulo each prime minus one.
    key.validate().map_err(|_| mismatch())?;
    let one = BigUint::from(1u32);
    let two = BigUint::from(2u32);
    // Both moduli are prime, so a⁻¹ = a^(m-2) mod m (Fermat).
    let u_pgp = Zeroizing::new(p.modpow(&(&*q - &two), &q));
    let u_card = Zeroizing::new(q.modpow(&(&*p - &two), &p));
    let dp = Zeroizing::new(&*d_big % (&*p - &one));
    let dq = Zeroizing::new(&*d_big % (&*q - &one));
    Ok(Material::Rsa {
        n: key.n().to_bytes_be(),
        e: key.e().to_bytes_be(),
        d: d_big.to_bytes_be(),
        p: p.to_bytes_be(),
        q: q.to_bytes_be(),
        u_pgp: u_pgp.to_bytes_be(),
        u_card: u_card.to_bytes_be(),
        dp: dp.to_bytes_be(),
        dq: dq.to_bytes_be(),
    })
}

fn rsa_generate(bits: usize) -> Result<Material> {
    let mut key = RsaPrivateKey::new(&mut OsRng, bits).map_err(|e| Error::Crypto(e.to_string()))?;
    key.precompute().map_err(|e| Error::Crypto(e.to_string()))?;
    let primes = key.primes();
    let (a, b) = (
        Zeroizing::new(primes[0].to_bytes_be()),
        Zeroizing::new(primes[1].to_bytes_be()),
    );
    let d = Zeroizing::new(key.d().to_bytes_be());
    rsa_material(&key.n().to_bytes_be(), &key.e().to_bytes_be(), &d, &a, &b)
}

fn weierstrass(curve: Curve, ecdh: bool) -> Result<Material> {
    let d = ec_random(curve)?;
    let point = ec_point(curve, &d)?;
    let d = d.to_vec();
    Ok(if ecdh {
        Material::Ecdh {
            curve,
            d,
            point,
            kdf: ecdh_kdf_params(curve),
        }
    } else {
        Material::Ecdsa { curve, d, point }
    })
}

fn ed25519_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(seed)
        .verifying_key()
        .to_bytes()
}

fn ed25519_generate() -> Material {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let point = ed25519_from_seed(&seed);
    Material::EdDsa { seed, point }
}

fn x25519_point(d_le: &[u8; 32]) -> [u8; 32] {
    let secret = x25519_dalek::StaticSecret::from(*d_le);
    x25519_dalek::PublicKey::from(&secret).to_bytes()
}

fn x25519_generate() -> Material {
    let secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let mut d = Zeroizing::new(secret.to_bytes());
    // Store the clamped scalar, as GnuPG does; X25519 clamps anyway, so the
    // public key is unchanged.
    d[0] &= 0xF8;
    d[31] &= 0x7F;
    d[31] |= 0x40;
    let point = x25519_point(&d).to_vec();
    Material::Ecdh {
        curve: Curve::X25519,
        d: d.to_vec(),
        point,
        kdf: ecdh_kdf_params(Curve::X25519),
    }
}

/// Generate a key set of type `t`: index 0 signs (the primary key), 1
/// decrypts, 2 authenticates.
pub(crate) fn generate(t: KeyType, created: u32) -> Result<[KeyPart; 3]> {
    let part = |material| KeyPart { material, created };
    let [s, d, a] = match t {
        KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096 => {
            let bits = usize::from(t.card_alg(KeyCrt::Sign).rsa_bits().unwrap_or(2048));
            [
                rsa_generate(bits)?,
                rsa_generate(bits)?,
                rsa_generate(bits)?,
            ]
        }
        KeyType::Cv25519 => [ed25519_generate(), x25519_generate(), ed25519_generate()],
        _ => {
            let curve = t
                .card_alg(KeyCrt::Sign)
                .curve()
                .ok_or(Error::Unsupported("curve"))?;
            [
                weierstrass(curve, false)?,
                weierstrass(curve, true)?,
                weierstrass(curve, false)?,
            ]
        }
    };
    Ok([part(s), part(d), part(a)])
}

impl KeyPart {
    /// OpenPGP public-key algorithm id: 1 RSA, 18 ECDH, 19 ECDSA, 22 EdDSA.
    #[must_use]
    pub fn algo_id(&self) -> u8 {
        match self.material {
            Material::Rsa { .. } => ALGO_RSA,
            Material::Ecdh { .. } => ALGO_ECDH,
            Material::Ecdsa { .. } => ALGO_ECDSA,
            Material::EdDsa { .. } => ALGO_EDDSA,
        }
    }

    /// The v4 public-key packet body. Byte-identical to what
    /// `keyroost_openpgp::{rsa,ecc}_v4_fingerprint` hash, so the file and the
    /// card agree on the fingerprint.
    #[must_use]
    pub fn public_body(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(16 + 1024);
        v.push(0x04);
        v.extend_from_slice(&self.created.to_be_bytes());
        v.push(self.algo_id());
        let ecc = |v: &mut Vec<u8>, curve: Curve, point: &[u8]| {
            let oid = curve.oid();
            v.push(oid.len() as u8);
            v.extend_from_slice(oid);
            if curve.is_25519() {
                let mut p = Vec::with_capacity(33);
                p.push(0x40);
                p.extend_from_slice(point);
                push_mpi(v, &p);
            } else {
                push_mpi(v, point);
            }
        };
        match &self.material {
            Material::Rsa { n, e, .. } => {
                push_mpi(&mut v, n);
                push_mpi(&mut v, e);
            }
            Material::Ecdsa { curve, point, .. } => ecc(&mut v, *curve, point),
            Material::Ecdh {
                curve, point, kdf, ..
            } => {
                ecc(&mut v, *curve, point);
                v.extend_from_slice(kdf);
            }
            Material::EdDsa { point, .. } => ecc(&mut v, Curve::Ed25519, point),
        }
        v
    }

    /// v4 fingerprint: `SHA1(0x99 || len16 || body)`.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 20] {
        let body = self.public_body();
        let mut h = Vec::with_capacity(3 + body.len());
        h.push(0x99);
        h.extend_from_slice(&(body.len() as u16).to_be_bytes());
        h.extend_from_slice(&body);
        keyroost_proto::sha1::sha1(&h)
    }

    /// The key id: the last 8 bytes of the fingerprint.
    #[must_use]
    pub fn key_id(&self) -> [u8; 8] {
        let f = self.fingerprint();
        let mut id = [0u8; 8];
        id.copy_from_slice(&f[12..]);
        id
    }

    /// The secret MPIs in GnuPG's layout: RSA `d, p, q, u` (`u = p⁻¹ mod q`);
    /// ECDSA/ECDH `d`, with X25519's RFC 7748 scalar byte-reversed
    /// (big-endian), GnuPG's convention; EdDSA the seed.
    #[must_use]
    pub(crate) fn secret_mpis(&self) -> Zeroizing<Vec<u8>> {
        match &self.material {
            Material::Rsa { d, p, q, u_pgp, .. } => {
                let parts = [d, p, q, u_pgp];
                let len = parts.iter().map(|x| 2 + x.len()).sum();
                let mut out = Zeroizing::new(Vec::with_capacity(len));
                for x in parts {
                    push_mpi(&mut out, x);
                }
                out
            }
            Material::Ecdh {
                curve: Curve::X25519,
                d,
                ..
            } => {
                let be = reversed32(d);
                let mut out = Zeroizing::new(Vec::with_capacity(2 + 32));
                push_mpi(&mut out, &be[..]);
                out
            }
            Material::Ecdsa { d, .. } | Material::Ecdh { d, .. } => {
                let mut out = Zeroizing::new(Vec::with_capacity(2 + d.len()));
                push_mpi(&mut out, d);
                out
            }
            Material::EdDsa { seed, .. } => {
                let mut out = Zeroizing::new(Vec::with_capacity(2 + 32));
                push_mpi(&mut out, seed);
                out
            }
        }
    }

    /// Rebuild a key from its public-key packet body and its (decrypted)
    /// secret MPIs — the inverse of [`KeyPart::public_body`] and
    /// [`KeyPart::secret_mpis`]. The public part is recomputed from the
    /// secret and must match the body.
    pub(crate) fn from_secret(algo: u8, public_body: &[u8], secret_mpis: &[u8]) -> Result<KeyPart> {
        let mut r = Reader::new(public_body);
        if r.u8()? != 4 {
            return Err(Error::Unsupported("key version other than 4"));
        }
        let created = r.u32()?;
        if r.u8()? != algo {
            return Err(Error::Malformed("algorithm does not match the public key"));
        }
        let mut s = Reader::new(secret_mpis);
        let material = match algo {
            ALGO_RSA => {
                let (n, e) = (r.mpi()?, r.mpi()?);
                let (d, p, q) = (s.mpi()?, s.mpi()?, s.mpi()?);
                let _u = s.mpi()?; // recomputed from p and q
                rsa_material(n, e, d, p, q)?
            }
            ALGO_ECDH | ALGO_ECDSA | ALGO_EDDSA => {
                let oid_len = usize::from(r.u8()?);
                let curve = Curve::from_oid(r.take(oid_len)?).ok_or(Error::Unsupported("curve"))?;
                let point = r.mpi()?;
                let kind = EccKind::from_id(algo).ok_or(Error::Unsupported("algorithm"))?;
                let kdf = if kind == EccKind::Ecdh {
                    read_kdf(&mut r)?
                } else {
                    [0; 4]
                };
                ecc_material(kind, curve, point, s.mpi()?, kdf)?
            }
            _ => return Err(Error::Unsupported("public-key algorithm")),
        };
        if !r.is_empty() || !s.is_empty() {
            return Err(Error::Malformed("extra data after the key"));
        }
        Ok(KeyPart { material, created })
    }

    /// The key in the card-import form.
    #[must_use]
    #[cfg_attr(not(feature = "card"), allow(dead_code))]
    pub(crate) fn card_key(&self) -> CardKey {
        match &self.material {
            Material::Rsa {
                n,
                e,
                p,
                q,
                u_card,
                dp,
                dq,
                ..
            } => CardKey::Rsa {
                e: e.clone(),
                p: p.clone(),
                q: q.clone(),
                u: u_card.clone(),
                dp: dp.clone(),
                dq: dq.clone(),
                n: n.clone(),
            },
            Material::Ecdh {
                curve: Curve::X25519,
                d,
                point,
                ..
            } => CardKey::Ecc {
                scalar: reversed32(d).to_vec(),
                point: point.clone(),
            },
            Material::Ecdsa { d, point, .. } | Material::Ecdh { d, point, .. } => CardKey::Ecc {
                scalar: d.clone(),
                point: point.clone(),
            },
            Material::EdDsa { seed, .. } => CardKey::Ed25519 { seed: *seed },
        }
    }
}

/// Read the ECDH KDF field (RFC 6637 §9): length 3, reserved 0x01, hash
/// id, cipher id. Any hash and cipher ids are kept as given.
fn read_kdf(r: &mut Reader) -> Result<[u8; 4]> {
    if r.u8()? != 3 {
        return Err(Error::Unsupported("ECDH KDF field of unexpected length"));
    }
    if r.u8()? != 0x01 {
        return Err(Error::Unsupported("ECDH KDF field version"));
    }
    let (hash, cipher) = (r.u8()?, r.u8()?);
    Ok([0x03, 0x01, hash, cipher])
}

/// ECC material from a public point (as the packet carries it) and the
/// secret MPI value, checking that the two belong together.
/// `kdf` is the ECDH KDF field from the body (unused for ECDSA/EdDSA).
fn ecc_material(
    kind: EccKind,
    curve: Curve,
    point: &[u8],
    secret: &[u8],
    kdf: [u8; 4],
) -> Result<Material> {
    let bare25519 = || match point {
        [0x40, rest @ ..] if rest.len() == 32 => Ok(rest),
        _ => Err(Error::Malformed("bad Curve 25519 point")),
    };
    match (kind, curve) {
        (EccKind::EdDsa, Curve::Ed25519) => {
            let want = bare25519()?;
            let padded = left_pad(secret, 32)?;
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&padded);
            let mat = Material::EdDsa {
                seed,
                point: ed25519_from_seed(&seed),
            };
            seed.zeroize();
            match &mat {
                Material::EdDsa { point, .. } if point[..] == *want => Ok(mat),
                _ => Err(mismatch()),
            }
        }
        (EccKind::Ecdh, Curve::X25519) => {
            let want = bare25519()?;
            let be = left_pad(secret, 32)?;
            let d = reversed32(&be);
            let got = x25519_point(&d);
            if got[..] != *want {
                return Err(mismatch());
            }
            Ok(Material::Ecdh {
                curve,
                d: d.to_vec(),
                point: got.to_vec(),
                kdf,
            })
        }
        (
            EccKind::Ecdh | EccKind::Ecdsa,
            Curve::NistP256 | Curve::NistP384 | Curve::NistP521 | Curve::Secp256k1,
        ) => {
            let d = left_pad(secret, field_len(curve))?;
            let got = ec_point(curve, &d)?;
            if got != point {
                return Err(mismatch());
            }
            let d = d.to_vec();
            Ok(if kind == EccKind::Ecdh {
                Material::Ecdh {
                    curve,
                    d,
                    point: got,
                    kdf,
                }
            } else {
                Material::Ecdsa {
                    curve,
                    d,
                    point: got,
                }
            })
        }
        (_, Curve::BrainpoolP256r1 | Curve::BrainpoolP384r1 | Curve::BrainpoolP512r1) => {
            Err(Error::Unsupported("Brainpool curves"))
        }
        _ => Err(Error::Malformed("curve does not fit the key's algorithm")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyroost_openpgp::{Curve, EccKind, KeyCrt};

    /// RSA-3072/4096 keygen is slow; the `#[ignore]` test covers them.
    fn slow_rsa(t: KeyType) -> bool {
        matches!(t, KeyType::Rsa3072 | KeyType::Rsa4096)
    }

    #[test]
    fn gnupg_p384_ecdh_kdf_params_are_kept() {
        // GnuPG writes SHA-384 / AES-256 (03 01 09 09) for P-384 ECDH, where
        // ecdh_kdf_params gives AES-192. The file's bytes must survive.
        let parts = generate(KeyType::NistP384, 1_700_000_000).unwrap();
        let ours = &parts[1];
        let mut body = ours.public_body();
        let n = body.len();
        assert_eq!(body[n - 4..], [0x03, 0x01, 0x09, 0x08]);
        body[n - 1] = 0x09;
        let back = KeyPart::from_secret(ours.algo_id(), &body, &ours.secret_mpis()).unwrap();
        assert!(matches!(
            back.material,
            Material::Ecdh {
                kdf: [0x03, 0x01, 0x09, 0x09],
                ..
            }
        ));
        assert_eq!(back.public_body(), body);
        let mut h = vec![0x99];
        h.extend_from_slice(&(body.len() as u16).to_be_bytes());
        h.extend_from_slice(&body);
        assert_eq!(back.fingerprint(), keyroost_proto::sha1::sha1(&h));
        assert_ne!(back.fingerprint(), ours.fingerprint());
    }

    #[test]
    fn ecdh_kdf_field_with_trailing_or_bad_length_is_refused() {
        let parts = generate(KeyType::NistP256, 1).unwrap();
        let p = &parts[1];
        let mut extra = p.public_body();
        extra.push(0);
        assert!(matches!(
            KeyPart::from_secret(p.algo_id(), &extra, &p.secret_mpis()),
            Err(Error::Malformed("extra data after the key"))
        ));
        let mut bad = p.public_body();
        let n = bad.len();
        bad[n - 4] = 4;
        assert!(KeyPart::from_secret(p.algo_id(), &bad, &p.secret_mpis()).is_err());
    }

    #[test]
    fn fingerprints_agree_with_keyroost_openpgp_for_every_type() {
        for t in KeyType::ALL.into_iter().filter(|t| !slow_rsa(*t)) {
            let parts = generate(t, 1_700_000_000).unwrap();
            for (i, crt) in [KeyCrt::Sign, KeyCrt::Decrypt, KeyCrt::Auth]
                .into_iter()
                .enumerate()
            {
                let p = &parts[i];
                let card_side = match &p.material {
                    Material::Rsa { n, e, .. } => {
                        keyroost_openpgp::rsa_v4_fingerprint(n, e, p.created)
                    }
                    Material::Ecdsa { curve, point, .. } => keyroost_openpgp::ecc_v4_fingerprint(
                        EccKind::Ecdsa,
                        *curve,
                        point,
                        p.created,
                    ),
                    Material::Ecdh { curve, point, .. } => keyroost_openpgp::ecc_v4_fingerprint(
                        EccKind::Ecdh,
                        *curve,
                        point,
                        p.created,
                    ),
                    Material::EdDsa { point, .. } => keyroost_openpgp::ecc_v4_fingerprint(
                        EccKind::EdDsa,
                        Curve::Ed25519,
                        point,
                        p.created,
                    ),
                };
                assert_eq!(p.fingerprint(), card_side, "{t:?} {crt:?}");
                assert!(
                    t.card_alg(crt).ecc_kind(crt).is_ok() || t.card_alg(crt).rsa_bits().is_some()
                );
            }
        }
    }

    #[test]
    fn secret_mpis_round_trip_for_every_type() {
        for t in KeyType::ALL.into_iter().filter(|t| !slow_rsa(*t)) {
            for p in generate(t, 1).unwrap() {
                let body = p.public_body();
                let back = KeyPart::from_secret(p.algo_id(), &body, &p.secret_mpis()).unwrap();
                assert_eq!(back.fingerprint(), p.fingerprint());
            }
        }
    }

    #[test]
    fn rsa_parts_satisfy_both_crt_conventions() {
        use rsa::BigUint;
        let one = BigUint::from(1u32);
        for part in generate(KeyType::Rsa2048, 1).unwrap() {
            let Material::Rsa {
                p,
                q,
                u_pgp,
                u_card,
                dp,
                dq,
                d,
                ..
            } = &part.material
            else {
                panic!("RSA key type gave non-RSA material");
            };
            let (p, q) = (BigUint::from_bytes_be(p), BigUint::from_bytes_be(q));
            let (u_pgp, u_card) = (
                BigUint::from_bytes_be(u_pgp),
                BigUint::from_bytes_be(u_card),
            );
            let d = BigUint::from_bytes_be(d);
            assert!(p < q, "OpenPGP wants p < q");
            assert_eq!((&u_pgp * &p) % &q, one, "u_pgp = p^-1 mod q");
            assert_eq!((&u_card * &q) % &p, one, "u_card = q^-1 mod p");
            assert_eq!(BigUint::from_bytes_be(dp), &d % (&p - &one));
            assert_eq!(BigUint::from_bytes_be(dq), &d % (&q - &one));
        }
    }

    /// Slow (RSA-3072/4096 keygen); run explicitly with `--ignored`.
    #[test]
    #[ignore]
    fn large_rsa_types_round_trip_and_match_the_card() {
        for t in [KeyType::Rsa3072, KeyType::Rsa4096] {
            for p in generate(t, 1_700_000_000).unwrap() {
                let Material::Rsa { n, e, .. } = &p.material else {
                    panic!("RSA key type gave non-RSA material");
                };
                let bits = t.card_alg(KeyCrt::Sign).rsa_bits().unwrap();
                assert_eq!(n.len() * 8, usize::from(bits), "{t:?}");
                assert_eq!(
                    p.fingerprint(),
                    keyroost_openpgp::rsa_v4_fingerprint(n, e, p.created)
                );
                let back =
                    KeyPart::from_secret(p.algo_id(), &p.public_body(), &p.secret_mpis()).unwrap();
                assert_eq!(back.fingerprint(), p.fingerprint());
            }
        }
    }

    #[test]
    fn from_secret_refuses_a_secret_from_another_key() {
        for t in [
            KeyType::Rsa2048,
            KeyType::NistP256,
            KeyType::NistP521,
            KeyType::Cv25519,
        ] {
            let a = generate(t, 1).unwrap();
            let b = generate(t, 1).unwrap();
            for (x, y) in a.iter().zip(b.iter()) {
                let err = KeyPart::from_secret(x.algo_id(), &x.public_body(), &y.secret_mpis());
                assert!(
                    matches!(
                        err,
                        Err(Error::Malformed("key does not match its public part"))
                    ),
                    "{t:?}"
                );
            }
        }
    }

    #[test]
    fn x25519_secret_mpi_is_the_reversed_rfc7748_scalar() {
        let parts = generate(KeyType::Cv25519, 1).unwrap();
        let Material::Ecdh { d, .. } = &parts[1].material else {
            panic!("decrypt key of Curve 25519 is not ECDH");
        };
        let mpis = parts[1].secret_mpis();
        let mut be = d.clone();
        be.reverse();
        assert_eq!(&mpis[2..], &be[..]);
        // Clamped like GnuPG's: the top byte of the big-endian form is 0x40..0x7F.
        assert_eq!(mpis[2] & 0xC0, 0x40);
        let card = parts[1].card_key();
        let CardKey::Ecc { scalar, point } = &card else {
            panic!("X25519 card key is not ECC");
        };
        assert_eq!(*scalar, be);
        assert_eq!(point.len(), 32);
    }

    #[test]
    fn short_secret_mpis_are_padded_back_to_field_length() {
        // A P-521 or Ed25519 secret whose top byte is zero loses it in the
        // MPI; reading must pad it back. Generate until one shows up for
        // P-521 (top byte is 0 or 1, so about half of all keys).
        loop {
            let parts = generate(KeyType::NistP521, 1).unwrap();
            let p = &parts[0];
            let Material::Ecdsa { d, .. } = &p.material else {
                unreachable!()
            };
            if d[0] != 0 {
                continue;
            }
            let back =
                KeyPart::from_secret(p.algo_id(), &p.public_body(), &p.secret_mpis()).unwrap();
            let Material::Ecdsa { d: d2, .. } = &back.material else {
                unreachable!()
            };
            assert_eq!(d2.len(), 66);
            break;
        }
    }

    #[test]
    fn key_type_names_and_card_algorithms() {
        assert_eq!(KeyType::ALL.map(KeyType::label)[7], "Curve 25519");
        assert_eq!(KeyType::Cv25519.cli_name(), "ed25519");
        assert_eq!(KeyType::Cv25519.card_alg(KeyCrt::Decrypt), KeyAlg::X25519);
        assert_eq!(KeyType::Cv25519.card_alg(KeyCrt::Auth), KeyAlg::Ed25519);
        assert_eq!(
            KeyType::from_key_alg(KeyAlg::X25519),
            Some(KeyType::Cv25519)
        );
        assert_eq!(KeyType::from_key_alg(KeyAlg::BrainpoolP384r1), None);
        for t in KeyType::ALL {
            for crt in [KeyCrt::Sign, KeyCrt::Decrypt, KeyCrt::Auth] {
                assert_eq!(KeyType::from_key_alg(t.card_alg(crt)), Some(t));
            }
        }
    }
}
