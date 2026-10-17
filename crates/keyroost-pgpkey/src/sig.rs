//! OpenPGP v4 signatures (RFC 4880 section 5.2.3, 5.2.4): self-certifications,
//! subkey bindings and key revocations, signed on the host or through any
//! other [`Signer`] (the card signs the same digest the host would).

use keyroost_openpgp::Curve;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::keys::{KeyPart, Material};
use crate::packet::Reader;
use crate::read::PublicPart;
pub use crate::s2k::Hash;
use crate::Error;

type Result<T> = std::result::Result<T, Error>;

/// Signature types keyroost writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SigType {
    /// Positive certification of a user id by the primary key.
    PositiveCert = 0x13,
    /// Binding of a subkey to the primary key.
    SubkeyBinding = 0x18,
    /// Revocation of the primary key.
    KeyRevocation = 0x20,
}

/// Key flags for the primary key: certify and sign.
pub(crate) const FLAGS_PRIMARY: u8 = 0x03;
/// Key flags for the decryption subkey: encrypt communications and storage.
pub(crate) const FLAGS_DECRYPT: u8 = 0x0C;
/// Key flags for the authentication subkey.
pub(crate) const FLAGS_AUTH: u8 = 0x20;
/// Preferred symmetric ciphers: AES-256, AES-192, AES-128.
pub(crate) const PREF_SYM: [u8; 3] = [9, 8, 7];
/// Preferred hashes: SHA-512, SHA-384, SHA-256.
pub(crate) const PREF_HASH: [u8; 3] = [10, 9, 8];
/// Preferred compression: uncompressed.
pub(crate) const PREF_COMPRESSION: [u8; 1] = [0];
/// Features: modification detection (SEIPD v1).
pub(crate) const FEATURES: u8 = 0x01;
/// Key server preferences: no-modify.
pub(crate) const KEYSERVER_PREFS: u8 = 0x80;

/// Anything that can sign an OpenPGP digest: the host (from a [`KeyPart`])
/// or a card.
pub trait Signer {
    /// OpenPGP public-key algorithm id of the signing key.
    fn algo_id(&self) -> u8;
    /// Sign `digest` (the bare hash output of `hash`). Returns the signature
    /// MPI values: RSA `[s]`, ECDSA `[r, s]`, EdDSA `[R, S]` (32 bytes each).
    /// RSA signers wrap the digest in its PKCS#1 v1.5 DigestInfo themselves.
    fn sign_digest(&mut self, hash: Hash, digest: &[u8]) -> Result<Vec<Vec<u8>>>;
}

/// Signs with key material held on the host.
pub struct HostSigner<'a>(pub &'a KeyPart);

fn crypto(e: impl std::fmt::Display) -> Error {
    Error::Crypto(e.to_string())
}

impl Signer for HostSigner<'_> {
    fn algo_id(&self) -> u8 {
        self.0.algo_id()
    }

    fn sign_digest(&mut self, hash: Hash, digest: &[u8]) -> Result<Vec<Vec<u8>>> {
        match &self.0.material {
            Material::Rsa { n, e, d, p, q, .. } => {
                use rsa::{BigUint, Pkcs1v15Sign, RsaPrivateKey};
                let b = BigUint::from_bytes_be;
                let key = RsaPrivateKey::from_components(b(n), b(e), b(d), vec![b(p), b(q)])
                    .map_err(crypto)?;
                let scheme = match hash {
                    Hash::Sha256 => Pkcs1v15Sign::new::<Sha256>(),
                    Hash::Sha384 => Pkcs1v15Sign::new::<Sha384>(),
                    Hash::Sha512 => Pkcs1v15Sign::new::<Sha512>(),
                    Hash::Sha1 => return Err(Error::Unsupported("SHA-1 signatures")),
                };
                Ok(vec![key.sign(scheme, digest).map_err(crypto)?])
            }
            Material::Ecdsa { curve, d, .. } => ecdsa_sign(*curve, d, digest),
            Material::EdDsa { seed, .. } => {
                use ed25519_dalek::Signer as _;
                let key = ed25519_dalek::SigningKey::from_bytes(seed);
                let sig = key.sign(digest).to_bytes();
                Ok(vec![sig[..32].to_vec(), sig[32..].to_vec()])
            }
            Material::Ecdh { .. } => Err(Error::Unsupported("signing with a decryption key")),
        }
    }
}

/// RFC 6979 deterministic ECDSA over `digest`; returns `[r, s]`.
fn ecdsa_sign(curve: Curve, d: &[u8], digest: &[u8]) -> Result<Vec<Vec<u8>>> {
    macro_rules! sign013 {
        ($c:ident) => {{
            use $c::ecdsa::signature::hazmat::PrehashSigner;
            let key = $c::ecdsa::SigningKey::from_slice(d).map_err(crypto)?;
            let sig: $c::ecdsa::Signature = key.sign_prehash(digest).map_err(crypto)?;
            let (r, s) = sig.split_bytes();
            Ok(vec![r.to_vec(), s.to_vec()])
        }};
    }
    match curve {
        Curve::NistP256 => sign013!(p256),
        Curve::NistP384 => sign013!(p384),
        Curve::Secp256k1 => sign013!(k256),
        // p521 0.14 is a newer RustCrypto generation (ecdsa 0.17,
        // signature 3); same calls, different trait crate.
        Curve::NistP521 => sign013!(p521),
        _ => Err(Error::Unsupported("signing curve")),
    }
}

/// The hash keyroost signs with for a key set whose primary is `primary`:
/// never shorter than the curve, because GnuPG refuses an ECDSA signature
/// over a shorter digest — SHA-384 for P-384 (GnuPG's own choice there),
/// SHA-512 for P-521, SHA-256 otherwise.
#[must_use]
pub(crate) fn hash_for(primary: &KeyPart) -> Hash {
    match primary.material {
        Material::Ecdsa { curve, .. } => hash_for_curve(curve),
        _ => Hash::Sha256,
    }
}

/// [`hash_for`] for a primary key known only by its public part, as when
/// re-signing a public certificate with a card.
#[must_use]
pub(crate) fn hash_for_public(primary: &PublicPart) -> Hash {
    // v4 key body: version, created (4), algo, then for ECDSA the OID length
    // and the OID.
    const ALGO_ECDSA: u8 = 19;
    let b = &primary.body;
    if primary.algo != ALGO_ECDSA {
        return Hash::Sha256;
    }
    let curve = b
        .get(6)
        .and_then(|&n| b.get(7..7 + usize::from(n)))
        .and_then(Curve::from_oid);
    curve.map_or(Hash::Sha256, hash_for_curve)
}

fn hash_for_curve(curve: Curve) -> Hash {
    match curve {
        Curve::NistP384 => Hash::Sha384,
        Curve::NistP521 => Hash::Sha512,
        _ => Hash::Sha256,
    }
}

fn digest(hash: Hash, data: &[u8]) -> Result<Vec<u8>> {
    match hash {
        Hash::Sha256 => Ok(Sha256::digest(data).to_vec()),
        Hash::Sha384 => Ok(Sha384::digest(data).to_vec()),
        Hash::Sha512 => Ok(Sha512::digest(data).to_vec()),
        Hash::Sha1 => Err(Error::Unsupported("SHA-1 signatures")),
    }
}

/// A run of signature subpackets, built in order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Subpackets(Vec<u8>);

impl Subpackets {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The encoded subpackets.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Append one subpacket; the length (type byte + data) is encoded like a
    /// new-format packet length.
    fn push(mut self, typ: u8, data: &[u8]) -> Self {
        let n = data.len() + 1;
        let v = &mut self.0;
        if n < 192 {
            v.push(n as u8);
        } else if n < 8384 {
            let m = n - 192;
            v.push(((m >> 8) + 192) as u8);
            v.push((m & 0xFF) as u8);
        } else {
            v.push(0xFF);
            v.extend_from_slice(&(n as u32).to_be_bytes());
        }
        v.push(typ);
        v.extend_from_slice(data);
        self
    }

    /// Signature creation time (type 2).
    #[must_use]
    pub fn created(self, t: u32) -> Self {
        self.push(2, &t.to_be_bytes())
    }

    /// Key expiration time (type 9), seconds after key creation; `None`
    /// writes nothing (the key never expires).
    #[must_use]
    pub fn key_expiry(self, secs: Option<u32>) -> Self {
        match secs {
            Some(s) => self.push(9, &s.to_be_bytes()),
            None => self,
        }
    }

    /// Key flags (type 27).
    #[must_use]
    pub fn key_flags(self, flags: u8) -> Self {
        self.push(27, &[flags])
    }

    /// Preferred symmetric algorithms (type 11).
    #[must_use]
    pub fn pref_sym(self, algos: &[u8]) -> Self {
        self.push(11, algos)
    }

    /// Preferred hash algorithms (type 21).
    #[must_use]
    pub fn pref_hash(self, algos: &[u8]) -> Self {
        self.push(21, algos)
    }

    /// Preferred compression algorithms (type 22).
    #[must_use]
    pub fn pref_compression(self, algos: &[u8]) -> Self {
        self.push(22, algos)
    }

    /// Features (type 30).
    #[must_use]
    pub fn features(self, f: u8) -> Self {
        self.push(30, &[f])
    }

    /// Key server preferences (type 23).
    #[must_use]
    pub fn keyserver_prefs(self, p: u8) -> Self {
        self.push(23, &[p])
    }

    /// Issuer fingerprint (type 33), v4.
    #[must_use]
    pub fn issuer_fpr(self, fpr: &[u8; 20]) -> Self {
        let mut d = [0u8; 21];
        d[0] = 4;
        d[1..].copy_from_slice(fpr);
        self.push(33, &d)
    }

    /// Reason for revocation (type 29): a code and a human-readable reason.
    #[must_use]
    pub fn revocation_reason(self, code: u8, reason: &str) -> Self {
        let mut d = Vec::with_capacity(1 + reason.len());
        d.push(code);
        d.extend_from_slice(reason.as_bytes());
        self.push(29, &d)
    }

    /// One subpacket copied as it is: `typ` keeps its critical bit.
    #[must_use]
    pub(crate) fn raw(self, typ: u8, data: &[u8]) -> Self {
        self.push(typ, data)
    }

    /// Issuer key id (type 16), written unhashed.
    #[must_use]
    pub fn issuer_key_id(self, id: &[u8; 8]) -> Self {
        self.push(16, id)
    }
}

/// A v4 signature body's type, hashed and unhashed subpacket areas.
pub(crate) fn sig_areas(body: &[u8]) -> Result<(u8, &[u8], &[u8])> {
    let mut r = Reader::new(body);
    if r.u8()? != 4 {
        return Err(Error::Unsupported("signatures other than version 4"));
    }
    let typ = r.u8()?;
    r.take(2)?;
    let n = usize::from(r.u16()?);
    let hashed = r.take(n)?;
    let n = usize::from(r.u16()?);
    let unhashed = r.take(n)?;
    Ok((typ, hashed, unhashed))
}

/// Split a subpacket area into (type byte with its critical bit, data).
pub(crate) fn split_subpackets(data: &[u8]) -> Result<Vec<(u8, &[u8])>> {
    let mut r = Reader::new(data);
    let mut out = Vec::new();
    while !r.is_empty() {
        let first = usize::from(r.u8()?);
        let len = match first {
            0..=191 => first,
            192..=254 => ((first - 192) << 8) + usize::from(r.u8()?) + 192,
            _ => usize::try_from(r.u32()?).map_err(|_| Error::Truncated)?,
        };
        let sp = r.take(len)?;
        let (&typ, v) = sp
            .split_first()
            .ok_or(Error::Malformed("empty signature subpacket"))?;
        out.push((typ, v));
    }
    Ok(out)
}

/// A public-key body as it enters a signature hash: `0x99 | len16 | body`.
#[must_use]
pub(crate) fn signed_key(pub_body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(3 + pub_body.len());
    v.push(0x99);
    v.extend_from_slice(&(pub_body.len() as u16).to_be_bytes());
    v.extend_from_slice(pub_body);
    v
}

/// A user id as it enters a certification hash: `0xB4 | len32 | uid`.
#[must_use]
pub(crate) fn signed_uid(uid: impl AsRef<[u8]>) -> Vec<u8> {
    let uid = uid.as_ref();
    let mut v = Vec::with_capacity(5 + uid.len());
    v.push(0xB4);
    v.extend_from_slice(&(uid.len() as u32).to_be_bytes());
    v.extend_from_slice(uid);
    v
}

fn len16(n: usize, what: &'static str) -> Result<[u8; 2]> {
    u16::try_from(n)
        .map(u16::to_be_bytes)
        .map_err(|_| Error::Unsupported(what))
}

/// Sign `signed_data` (the [`signed_key`] / [`signed_uid`] concatenation for
/// `sig_type`) and return the v4 signature packet body.
pub(crate) fn sign(
    signer: &mut dyn Signer,
    sig_type: SigType,
    hash: Hash,
    hashed: &Subpackets,
    unhashed: &Subpackets,
    signed_data: &[u8],
) -> Result<Vec<u8>> {
    let hashed = hashed.as_bytes();
    let unhashed = unhashed.as_bytes();
    let mut prefix = vec![0x04, sig_type as u8, signer.algo_id(), hash as u8];
    prefix.extend_from_slice(&len16(hashed.len(), "too many signature subpackets")?);
    prefix.extend_from_slice(hashed);

    let mut data = Vec::with_capacity(signed_data.len() + prefix.len() + 6);
    data.extend_from_slice(signed_data);
    data.extend_from_slice(&prefix);
    data.extend_from_slice(&[0x04, 0xFF]);
    data.extend_from_slice(&(prefix.len() as u32).to_be_bytes());
    let dig = digest(hash, &data)?;

    let mpis = signer.sign_digest(hash, &dig)?;
    let mut body = prefix;
    body.extend_from_slice(&len16(unhashed.len(), "too many signature subpackets")?);
    body.extend_from_slice(unhashed);
    body.extend_from_slice(&dig[..2]);
    for m in &mpis {
        crate::packet::push_mpi(&mut body, m);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{generate, KeyType};

    /// A parsed signature body, read back independently of `sign`.
    struct Parsed {
        sig_type: u8,
        algo: u8,
        hash: u8,
        hashed: Vec<u8>,
        unhashed: Vec<u8>,
        left16: [u8; 2],
        mpis: Vec<Vec<u8>>,
        /// `body[..6 + hashed.len()]`, the hashed prefix.
        prefix_len: usize,
    }

    fn parse(body: &[u8]) -> Parsed {
        let mut r = Reader::new(body);
        assert_eq!(r.u8().unwrap(), 4);
        let sig_type = r.u8().unwrap();
        let algo = r.u8().unwrap();
        let hash = r.u8().unwrap();
        let hl = r.u16().unwrap() as usize;
        let hashed = r.take(hl).unwrap().to_vec();
        let ul = r.u16().unwrap() as usize;
        let unhashed = r.take(ul).unwrap().to_vec();
        let l = r.take(2).unwrap();
        let left16 = [l[0], l[1]];
        let mut mpis = Vec::new();
        while !r.is_empty() {
            mpis.push(r.mpi().unwrap().to_vec());
        }
        Parsed {
            sig_type,
            algo,
            hash,
            hashed,
            unhashed,
            left16,
            mpis,
            prefix_len: 6 + hl,
        }
    }

    /// The digest per RFC 4880 5.2.4, recomputed from the packet bytes.
    fn recompute(body: &[u8], p: &Parsed, signed_data: &[u8]) -> Vec<u8> {
        let mut data = signed_data.to_vec();
        data.extend_from_slice(&body[..p.prefix_len]);
        data.extend_from_slice(&[0x04, 0xFF]);
        data.extend_from_slice(&(p.prefix_len as u32).to_be_bytes());
        match p.hash {
            8 => Sha256::digest(&data).to_vec(),
            9 => Sha384::digest(&data).to_vec(),
            10 => Sha512::digest(&data).to_vec(),
            h => panic!("hash {h}"),
        }
    }

    fn pad(v: &[u8], n: usize) -> Vec<u8> {
        let mut out = vec![0u8; n - v.len()];
        out.extend_from_slice(v);
        out
    }

    /// Verify with each crate's own verifying-key API.
    fn verify(key: &KeyPart, hash: u8, digest: &[u8], mpis: &[Vec<u8>]) {
        match &key.material {
            Material::Rsa { n, e, .. } => {
                use rsa::{BigUint, Pkcs1v15Sign, RsaPublicKey};
                let pk = RsaPublicKey::new(BigUint::from_bytes_be(n), BigUint::from_bytes_be(e))
                    .unwrap();
                assert_eq!(hash, 8);
                assert_eq!(mpis.len(), 1);
                let s = pad(&mpis[0], n.len());
                pk.verify(Pkcs1v15Sign::new::<Sha256>(), digest, &s)
                    .unwrap();
            }
            Material::Ecdsa { curve, point, .. } => {
                assert_eq!(mpis.len(), 2);
                macro_rules! v {
                    ($c:ident, $n:expr) => {{
                        use $c::ecdsa::signature::hazmat::PrehashVerifier;
                        let vk = $c::ecdsa::VerifyingKey::from_sec1_bytes(point).unwrap();
                        let mut rs = pad(&mpis[0], $n);
                        rs.extend_from_slice(&pad(&mpis[1], $n));
                        let sig = $c::ecdsa::Signature::from_slice(&rs).unwrap();
                        vk.verify_prehash(digest, &sig).unwrap();
                    }};
                }
                match curve {
                    Curve::NistP256 => v!(p256, 32),
                    Curve::NistP384 => v!(p384, 48),
                    Curve::NistP521 => v!(p521, 66),
                    Curve::Secp256k1 => v!(k256, 32),
                    c => panic!("{c:?}"),
                }
            }
            Material::EdDsa { point, .. } => {
                use ed25519_dalek::Verifier;
                assert_eq!(mpis.len(), 2);
                let vk = ed25519_dalek::VerifyingKey::from_bytes(point).unwrap();
                let mut rs = [0u8; 64];
                rs[..32].copy_from_slice(&pad(&mpis[0], 32));
                rs[32..].copy_from_slice(&pad(&mpis[1], 32));
                vk.verify(digest, &ed25519_dalek::Signature::from_bytes(&rs))
                    .unwrap();
            }
            Material::Ecdh { .. } => panic!("ECDH cannot sign"),
        }
    }

    fn cert_subpackets(primary: &KeyPart) -> (Subpackets, Subpackets) {
        let hashed = Subpackets::new()
            .created(primary.created)
            .key_expiry(Some(3 * 365 * 86400))
            .key_flags(FLAGS_PRIMARY)
            .pref_sym(&PREF_SYM)
            .pref_hash(&PREF_HASH)
            .pref_compression(&PREF_COMPRESSION)
            .features(FEATURES)
            .keyserver_prefs(KEYSERVER_PREFS)
            .issuer_fpr(&primary.fingerprint());
        let unhashed = Subpackets::new().issuer_key_id(&primary.key_id());
        (hashed, unhashed)
    }

    fn check_self_cert(t: KeyType) {
        let parts = generate(t, 1_700_000_000).unwrap();
        let primary = &parts[0];
        let hash = hash_for(primary);
        let (hashed, unhashed) = cert_subpackets(primary);
        let mut data = signed_key(&primary.public_body());
        data.extend_from_slice(&signed_uid("Test User <test@example.org>"));
        let body = sign(
            &mut HostSigner(primary),
            SigType::PositiveCert,
            hash,
            &hashed,
            &unhashed,
            &data,
        )
        .unwrap();
        let p = parse(&body);
        assert_eq!(p.sig_type, 0x13);
        assert_eq!(p.algo, primary.algo_id());
        assert_eq!(p.hash, hash as u8);
        assert_eq!(p.hashed, hashed.as_bytes());
        assert_eq!(p.unhashed, unhashed.as_bytes());
        let d = recompute(&body, &p, &data);
        assert_eq!(p.left16, [d[0], d[1]], "{t:?} left16");
        verify(primary, p.hash, &d, &p.mpis);
    }

    #[test]
    fn self_cert_rsa2048() {
        check_self_cert(KeyType::Rsa2048);
    }

    #[test]
    fn self_cert_ecc_types() {
        for t in [
            KeyType::NistP256,
            KeyType::NistP384,
            KeyType::NistP521,
            KeyType::Secp256k1,
            KeyType::Cv25519,
        ] {
            check_self_cert(t);
        }
    }

    #[test]
    fn subkey_binding_and_revocation_verify() {
        let parts = generate(KeyType::NistP256, 1_700_000_000).unwrap();
        let primary = &parts[0];
        let pk = signed_key(&primary.public_body());
        let mut bind = pk.clone();
        bind.extend_from_slice(&signed_key(&parts[1].public_body()));
        let hashed = Subpackets::new()
            .created(1_700_000_000)
            .key_flags(FLAGS_DECRYPT)
            .issuer_fpr(&primary.fingerprint());
        let rev = Subpackets::new()
            .created(1_700_000_000)
            .revocation_reason(0, "")
            .issuer_fpr(&primary.fingerprint());
        for (ty, h, data) in [
            (SigType::SubkeyBinding, &hashed, &bind),
            (SigType::KeyRevocation, &rev, &pk),
        ] {
            let body = sign(
                &mut HostSigner(primary),
                ty,
                Hash::Sha256,
                h,
                &Subpackets::new(),
                data,
            )
            .unwrap();
            let p = parse(&body);
            assert_eq!(p.sig_type, ty as u8);
            let d = recompute(&body, &p, data);
            assert_eq!(p.left16, [d[0], d[1]]);
            verify(primary, p.hash, &d, &p.mpis);
        }
    }

    #[test]
    fn ed25519_signature_is_two_32_byte_values() {
        let parts = generate(KeyType::Cv25519, 1_700_000_000).unwrap();
        let mpis = HostSigner(&parts[0])
            .sign_digest(Hash::Sha256, &[0x5A; 32])
            .unwrap();
        assert_eq!(mpis.len(), 2);
        assert!(mpis.iter().all(|m| m.len() == 32));
    }

    #[test]
    fn decryption_key_refuses_to_sign() {
        let parts = generate(KeyType::NistP256, 1_700_000_000).unwrap();
        assert!(HostSigner(&parts[1])
            .sign_digest(Hash::Sha256, &[0; 32])
            .is_err());
    }

    #[test]
    fn hash_for_never_goes_below_the_curve_size() {
        // GnuPG refuses a P-384 signature over a SHA-256 digest ("requires
        // a 384 bit or larger hash").
        for (t, want) in [
            (KeyType::NistP256, Hash::Sha256),
            (KeyType::NistP384, Hash::Sha384),
            (KeyType::NistP521, Hash::Sha512),
            (KeyType::Secp256k1, Hash::Sha256),
            (KeyType::Cv25519, Hash::Sha256),
            (KeyType::Rsa2048, Hash::Sha256),
        ] {
            let parts = generate(t, 1).unwrap();
            assert_eq!(hash_for(&parts[0]), want, "{t:?}");
            let public = PublicPart {
                algo: parts[0].algo_id(),
                body: parts[0].public_body(),
                fpr: parts[0].fingerprint(),
                created: 1,
            };
            assert_eq!(hash_for_public(&public), want, "{t:?} public");
        }
    }

    #[test]
    fn subpacket_lengths_at_the_boundaries() {
        // Length counts the type byte too.
        let one = Subpackets::new().push(29, &[0; 190]);
        assert_eq!(one.as_bytes()[..2], [191, 29]);
        let two = Subpackets::new().push(29, &[0; 191]);
        assert_eq!(two.as_bytes()[..3], [0xC0, 0x00, 29]);
        let top = Subpackets::new().push(29, &[0; 8382]);
        assert_eq!(top.as_bytes()[..3], [0xDF, 0xFF, 29]);
        let five = Subpackets::new().push(29, &[0; 8383]);
        assert_eq!(five.as_bytes()[..6], [0xFF, 0, 0, 0x20, 0xC0, 29]);
        assert_eq!(five.as_bytes().len(), 5 + 8384);
    }

    #[test]
    fn subpacket_encodings() {
        let fpr = [0x11; 20];
        let s = Subpackets::new()
            .created(0x0102_0304)
            .key_expiry(None)
            .key_expiry(Some(0x0A0B_0C0D))
            .key_flags(FLAGS_AUTH)
            .issuer_fpr(&fpr)
            .revocation_reason(3, "x");
        let mut want = vec![5, 2, 1, 2, 3, 4, 5, 9, 0x0A, 0x0B, 0x0C, 0x0D, 2, 27, 0x20];
        want.extend_from_slice(&[22, 33, 4]);
        want.extend_from_slice(&fpr);
        want.extend_from_slice(&[3, 29, 3, b'x']);
        assert_eq!(s.as_bytes(), want);
        let u = Subpackets::new().issuer_key_id(&[7; 8]);
        assert_eq!(u.as_bytes()[..2], [9, 16]);
    }

    #[test]
    fn signed_key_and_uid_framing() {
        assert_eq!(signed_key(&[1, 2, 3]), [0x99, 0, 3, 1, 2, 3]);
        assert_eq!(signed_uid("ab"), [0xB4, 0, 0, 0, 2, b'a', b'b']);
    }
}
