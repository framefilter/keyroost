//! Read key sets back: keyroost backups and GnuPG secret-key exports
//! (`gpg --export-secret-keys`), armored or binary, and public certificates.

use std::borrow::Cow;
use std::time::{SystemTime, UNIX_EPOCH};

use keyroost_openpgp::Curve;

use crate::armor::{self, Kind};
use crate::cert::civil_from_days;
use crate::keys::{KeyPart, KeyType, Material};
use crate::packet::{parse_packets, Packet, Reader, Tag};
use crate::s2k;
use crate::Error;

type Result<T> = std::result::Result<T, Error>;

/// The card slot a loaded key belongs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    Sign,
    Decrypt,
    Auth,
}

/// One secret key read from a file.
pub struct LoadedKey {
    pub slot: Option<Slot>,
    pub part: KeyPart,
    pub flags: u8,
    pub fpr: [u8; 20],
    pub key_type: Option<KeyType>,
}

/// A secret key set read from a file.
pub struct Loaded {
    pub user_ids: Vec<String>,
    pub keys: Vec<LoadedKey>,
    pub expiry: Option<u32>,
    pub primary_fpr: [u8; 20],
    pub notes: Vec<String>,
}

/// The public part of one key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicPart {
    pub algo: u8,
    pub body: Vec<u8>,
    pub fpr: [u8; 20],
    pub created: u32,
}

/// A public certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicCert {
    pub primary: PublicPart,
    pub user_ids: Vec<String>,
    pub subkeys: Vec<PublicPart>,
    pub packets: Vec<(u8, Vec<u8>)>,
}

const ALGO_RSA: u8 = 1;
const ALGO_ECDH: u8 = 18;
const ALGO_ECDSA: u8 = 19;
const ALGO_EDDSA: u8 = 22;

const FLAG_CERTIFY: u8 = 0x01;
const FLAG_SIGN: u8 = 0x02;
const FLAG_ENCRYPT: u8 = 0x0C;
const FLAG_AUTH: u8 = 0x20;

/// Most key packets (primary plus subkeys) one file may hold.
const MAX_KEYS: usize = 16;

const BRAINPOOL: &str = "Brainpool keys can be made on the card but not loaded from a file yet";

/// Read a secret key set (a keyroost backup or `gpg --export-secret-keys`
/// output, armored or binary). `pass` unlocks protected keys.
pub fn open(data: &[u8], pass: Option<&[u8]>) -> Result<Loaded> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u32::try_from(d.as_secs()).unwrap_or(u32::MAX));
    open_at(data, pass, now)
}

/// [`open`] with an explicit "now" for the expiry checks.
pub(crate) fn open_at(data: &[u8], pass: Option<&[u8]>, now: u32) -> Result<Loaded> {
    let (kind, bin) = decode_input(data)?;
    if kind == Some(Kind::PublicKey) {
        return Err(Error::PublicOnly);
    }
    let packets = parse_packets(&bin)?;
    let cert = parse_cert(&packets)?;
    if cert.primary.tag != Tag::SECRET_KEY {
        return Err(Error::PublicOnly);
    }
    let pfpr = cert.primary.fpr;
    let newest = cert
        .uids
        .iter()
        .flat_map(|(_, sigs)| sigs.iter().filter(|s| (0x10..=0x13).contains(&s.typ)))
        .chain(cert.primary.sigs.iter().filter(|s| s.typ == 0x1F))
        .filter(|s| s.by(&pfpr))
        .max_by_key(|s| s.created)
        .ok_or(Error::Malformed("no self-signature"))?;
    let expiry = newest.expiry.filter(|&e| e != 0);

    let mut notes = Vec::new();
    if cert
        .primary
        .sigs
        .iter()
        .any(|s| s.typ == 0x20 && s.by(&pfpr))
    {
        notes.push("This key set has been revoked.".to_string());
    }
    if let Some(end) = ends(cert.primary.created, expiry) {
        if end <= u64::from(now) {
            notes.push(format!("This key set expired on {}.", date(end)));
        }
    }

    let mut chosen: Vec<(&Key, u8)> = vec![(
        &cert.primary,
        newest.flags.unwrap_or(FLAG_CERTIFY | FLAG_SIGN),
    )];
    for sub in &cert.subkeys {
        let id = key_id_hex(&sub.fpr);
        if sub.sigs.iter().any(|s| s.typ == 0x28 && s.by(&pfpr)) {
            notes.push(format!("Subkey {id} is revoked and was skipped."));
            continue;
        }
        let Some(bind) = sub
            .sigs
            .iter()
            .filter(|s| s.typ == 0x18 && s.by(&pfpr))
            .max_by_key(|s| s.created)
        else {
            notes.push(format!(
                "Subkey {id} has no binding signature and was skipped."
            ));
            continue;
        };
        if let Some(end) = ends(sub.created, bind.expiry.filter(|&e| e != 0)) {
            if end <= u64::from(now) {
                notes.push(format!(
                    "Subkey {id} expired on {} and was skipped.",
                    date(end)
                ));
                continue;
            }
        }
        if sub.tag != Tag::SECRET_SUBKEY {
            notes.push(format!(
                "Subkey {id} has no secret part in this file and was skipped."
            ));
            continue;
        }
        let fallback = if sub.algo == ALGO_ECDH || sub.algo == ALGO_RSA {
            FLAG_ENCRYPT
        } else {
            FLAG_SIGN
        };
        chosen.push((sub, bind.flags.unwrap_or(fallback)));
    }

    let mut taken = [false; 3];
    let mut keys = Vec::with_capacity(chosen.len());
    for (key, flags) in chosen {
        let mut r = Reader::new(&key.body[key.pub_len..]);
        let secret = s2k::unprotect(&mut r, pass)?;
        let part = KeyPart::from_secret(key.algo, &key.body[..key.pub_len], &secret)?;
        if part.fingerprint() != key.fpr {
            return Err(Error::Malformed("key does not match its public part"));
        }
        let usable = flags & capabilities(key.algo);
        let slot = [
            (Slot::Sign, FLAG_SIGN),
            (Slot::Decrypt, FLAG_ENCRYPT),
            (Slot::Auth, FLAG_AUTH),
        ]
        .into_iter()
        .enumerate()
        .find(|&(i, (_, f))| usable & f != 0 && !taken[i])
        .map(|(i, (slot, _))| {
            taken[i] = true;
            slot
        });
        keys.push(LoadedKey {
            slot,
            key_type: key_type(&part),
            part,
            flags,
            fpr: key.fpr,
        });
    }

    Ok(Loaded {
        user_ids: cert.uids.into_iter().map(|(u, _)| u).collect(),
        keys,
        expiry,
        primary_fpr: pfpr,
        notes,
    })
}

/// Read a public certificate. A secret file is accepted too; its key
/// packets come back as public ones.
pub fn open_public(data: &[u8]) -> Result<PublicCert> {
    let (_, bin) = decode_input(data)?;
    let packets = parse_packets(&bin)?;
    let cert = parse_cert(&packets)?;
    let public = |k: &Key| PublicPart {
        algo: k.algo,
        body: k.body[..k.pub_len].to_vec(),
        fpr: k.fpr,
        created: k.created,
    };
    let mut out = Vec::with_capacity(packets.len());
    for p in &packets {
        match p.tag {
            10 | 12 => {}
            Tag::SECRET_KEY | Tag::PUBLIC_KEY | Tag::SECRET_SUBKEY | Tag::PUBLIC_SUBKEY => {
                let tag = match p.tag {
                    Tag::SECRET_KEY | Tag::PUBLIC_KEY => Tag::PUBLIC_KEY,
                    _ => Tag::PUBLIC_SUBKEY,
                };
                let n = public_len(p.body)?;
                out.push((tag, p.body[..n].to_vec()));
            }
            tag => out.push((tag, p.body.to_vec())),
        }
    }
    Ok(PublicCert {
        primary: public(&cert.primary),
        user_ids: cert.uids.iter().map(|(u, _)| u.clone()).collect(),
        subkeys: cert.subkeys.iter().map(public).collect(),
        packets: out,
    })
}

/// Armored text or binary packets. Armored input must be a key block.
fn decode_input(data: &[u8]) -> Result<(Option<Kind>, Cow<'_, [u8]>)> {
    match data.first() {
        None => Err(Error::Truncated),
        Some(b) if b & 0x80 != 0 => Ok((None, Cow::Borrowed(data))),
        Some(_) => {
            let text = std::str::from_utf8(data)
                .map_err(|_| Error::Malformed("not an OpenPGP key file"))?;
            let (kind, bin) = armor::decode(text)?;
            if kind == Kind::Signature {
                return Err(Error::Malformed("a signature, not a key"));
            }
            Ok((Some(kind), Cow::Owned(bin)))
        }
    }
}

/// The fields of a signature this reader uses. Creation time, expiry and
/// flags count only from the hashed area.
#[derive(Default)]
struct Sig {
    typ: u8,
    created: u32,
    expiry: Option<u32>,
    flags: Option<u8>,
    issuer_fpr: Option<[u8; 20]>,
    issuer_id: Option<[u8; 8]>,
}

impl Sig {
    /// Whether the signature names `fpr` as its issuer (or names none).
    fn by(&self, fpr: &[u8; 20]) -> bool {
        match (self.issuer_fpr, self.issuer_id) {
            (Some(f), _) => f == *fpr,
            (None, Some(id)) => id[..] == fpr[12..],
            (None, None) => true,
        }
    }
}

/// Parse a signature packet; `None` for versions other than 4.
fn parse_sig(body: &[u8]) -> Result<Option<Sig>> {
    let mut r = Reader::new(body);
    if r.u8()? != 4 {
        return Ok(None);
    }
    let typ = r.u8()?;
    r.take(2)?; // public-key and hash algorithms
    let n = usize::from(r.u16()?);
    let hashed = r.take(n)?;
    let n = usize::from(r.u16()?);
    let unhashed = r.take(n)?;
    r.take(2)?; // hash check bytes; the MPIs follow
    let mut sig = Sig {
        typ,
        ..Sig::default()
    };
    subpackets(hashed, &mut sig, true)?;
    subpackets(unhashed, &mut sig, false)?;
    Ok(Some(sig))
}

fn subpackets(data: &[u8], sig: &mut Sig, hashed: bool) -> Result<()> {
    let mut r = Reader::new(data);
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
        let be32 = |v: &[u8]| <[u8; 4]>::try_from(v).ok().map(u32::from_be_bytes);
        match (typ & 0x7F, hashed) {
            (2, true) => sig.created = be32(v).ok_or(Error::Malformed("bad signature time"))?,
            (9, true) => sig.expiry = Some(be32(v).ok_or(Error::Malformed("bad key expiry"))?),
            (27, true) => sig.flags = Some(v.first().copied().unwrap_or(0)),
            (33, _) => {
                if let [4, rest @ ..] = v {
                    sig.issuer_fpr = <[u8; 20]>::try_from(rest).ok();
                }
            }
            (16, _) => sig.issuer_id = <[u8; 8]>::try_from(v).ok(),
            _ => {}
        }
    }
    Ok(())
}

/// One key packet and the signatures that follow it.
struct Key<'a> {
    tag: u8,
    body: &'a [u8],
    /// Length of the public-key fields at the start of `body`.
    pub_len: usize,
    algo: u8,
    created: u32,
    fpr: [u8; 20],
    sigs: Vec<Sig>,
}

impl<'a> Key<'a> {
    fn new(p: &Packet<'a>) -> Result<Key<'a>> {
        let pub_len = public_len(p.body)?;
        let public = matches!(p.tag, Tag::PUBLIC_KEY | Tag::PUBLIC_SUBKEY);
        if public && pub_len != p.body.len() {
            return Err(Error::Malformed("extra data after the public key"));
        }
        let pub_body = &p.body[..pub_len];
        let len = u16::try_from(pub_len).map_err(|_| Error::Unsupported("oversized keys"))?;
        let mut h = Vec::with_capacity(3 + pub_len);
        h.push(0x99);
        h.extend_from_slice(&len.to_be_bytes());
        h.extend_from_slice(pub_body);
        Ok(Key {
            tag: p.tag,
            body: p.body,
            pub_len,
            algo: pub_body[5],
            created: u32::from_be_bytes([pub_body[1], pub_body[2], pub_body[3], pub_body[4]]),
            fpr: keyroost_proto::sha1::sha1(&h),
            sigs: Vec::new(),
        })
    }
}

/// A certificate's packets, grouped.
struct Cert<'a> {
    primary: Key<'a>,
    uids: Vec<(String, Vec<Sig>)>,
    subkeys: Vec<Key<'a>>,
}

fn parse_cert<'a>(packets: &[Packet<'a>]) -> Result<Cert<'a>> {
    enum At {
        Primary,
        Uid,
        Other,
        Sub,
    }
    let mut it = packets.iter().filter(|p| !matches!(p.tag, 10 | 12));
    let first = it.next().ok_or(Error::Truncated)?;
    if !matches!(first.tag, Tag::SECRET_KEY | Tag::PUBLIC_KEY) {
        return Err(Error::Malformed("the file does not start with a key"));
    }
    let mut cert = Cert {
        primary: Key::new(first)?,
        uids: Vec::new(),
        subkeys: Vec::new(),
    };
    let mut at = At::Primary;
    for p in it {
        match p.tag {
            Tag::SECRET_KEY | Tag::PUBLIC_KEY => {
                return Err(Error::Unsupported("more than one key set in one file"))
            }
            Tag::SECRET_SUBKEY | Tag::PUBLIC_SUBKEY => {
                if cert.subkeys.len() + 1 >= MAX_KEYS {
                    return Err(Error::Malformed("too many keys in one file"));
                }
                cert.subkeys.push(Key::new(p)?);
                at = At::Sub;
            }
            Tag::USER_ID => {
                cert.uids
                    .push((String::from_utf8_lossy(p.body).into_owned(), Vec::new()));
                at = At::Uid;
            }
            Tag::SIGNATURE => {
                let Some(sig) = parse_sig(p.body)? else {
                    continue;
                };
                match at {
                    At::Primary => cert.primary.sigs.push(sig),
                    At::Uid => {
                        if let Some((_, sigs)) = cert.uids.last_mut() {
                            sigs.push(sig);
                        }
                    }
                    At::Sub => {
                        if let Some(k) = cert.subkeys.last_mut() {
                            k.sigs.push(sig);
                        }
                    }
                    At::Other => {}
                }
            }
            // User attributes (photos) and anything else: their
            // signatures are not ours to read.
            _ => at = At::Other,
        }
    }
    if cert.uids.is_empty() {
        return Err(Error::Malformed("no user id"));
    }
    Ok(cert)
}

/// Length of the v4 public-key fields at the start of a key packet body,
/// checking the version, the algorithm and the curve.
fn public_len(body: &[u8]) -> Result<usize> {
    let mut r = Reader::new(body);
    match r.u8()? {
        4 => {}
        5 | 6 => return Err(Error::Unsupported("version 5/6 keys")),
        2 | 3 => return Err(Error::Unsupported("version 3 keys")),
        _ => return Err(Error::Malformed("unknown key version")),
    }
    r.u32()?;
    let algo = r.u8()?;
    match algo {
        ALGO_RSA => {
            r.mpi()?;
            r.mpi()?;
        }
        ALGO_ECDH | ALGO_ECDSA | ALGO_EDDSA => {
            let n = usize::from(r.u8()?);
            if n == 0 || n == 0xFF {
                return Err(Error::Malformed("bad curve id"));
            }
            let curve = curve_for(r.take(n)?)?;
            let fits = match algo {
                ALGO_EDDSA => curve == Curve::Ed25519,
                ALGO_ECDH => curve != Curve::Ed25519,
                _ => !curve.is_25519(),
            };
            if !fits {
                return Err(Error::Malformed("curve does not fit the key's algorithm"));
            }
            r.mpi()?;
            if algo == ALGO_ECDH {
                let kdf = r.take(4)?;
                if kdf[..2] != [0x03, 0x01] {
                    return Err(Error::Unsupported("ECDH KDF field"));
                }
            }
        }
        2 | 3 => return Err(Error::Unsupported("RSA encrypt-only or sign-only keys")),
        16 | 20 => return Err(Error::Unsupported("ElGamal keys")),
        17 => return Err(Error::Unsupported("DSA keys")),
        25..=28 => {
            return Err(Error::Unsupported(
                "X25519/X448/Ed25519/Ed448 keys in the new format",
            ))
        }
        _ => return Err(Error::Unsupported("public-key algorithm")),
    }
    let rest = r.rest()?.len();
    Ok(body.len() - rest)
}

/// The curve for an OID, naming the ones that cannot be loaded.
fn curve_for(oid: &[u8]) -> Result<Curve> {
    match Curve::from_oid(oid) {
        Some(Curve::BrainpoolP256r1 | Curve::BrainpoolP384r1 | Curve::BrainpoolP512r1) => {
            Err(Error::Unsupported(BRAINPOOL))
        }
        Some(c) => Ok(c),
        None => Err(Error::Unsupported(match oid {
            [0x2B, 0x65, 0x71] => "Ed448 keys",
            [0x2B, 0x65, 0x6F] => "X448 keys",
            _ => "keys on this curve",
        })),
    }
}

/// Which key flags an algorithm can serve.
fn capabilities(algo: u8) -> u8 {
    match algo {
        ALGO_RSA => FLAG_SIGN | FLAG_ENCRYPT | FLAG_AUTH,
        ALGO_ECDH => FLAG_ENCRYPT,
        _ => FLAG_SIGN | FLAG_AUTH,
    }
}

fn key_type(part: &KeyPart) -> Option<KeyType> {
    match &part.material {
        Material::Rsa { n, .. } => {
            let start = n.iter().position(|&b| b != 0)?;
            let bits = (n.len() - start - 1) * 8 + (8 - n[start].leading_zeros() as usize);
            match bits {
                2048 => Some(KeyType::Rsa2048),
                3072 => Some(KeyType::Rsa3072),
                4096 => Some(KeyType::Rsa4096),
                _ => None,
            }
        }
        Material::Ecdsa { curve, .. } | Material::Ecdh { curve, .. } => match curve {
            Curve::NistP256 => Some(KeyType::NistP256),
            Curve::NistP384 => Some(KeyType::NistP384),
            Curve::NistP521 => Some(KeyType::NistP521),
            Curve::Secp256k1 => Some(KeyType::Secp256k1),
            Curve::X25519 | Curve::Ed25519 => Some(KeyType::Cv25519),
            _ => None,
        },
        Material::EdDsa { .. } => Some(KeyType::Cv25519),
    }
}

/// When a key with this creation time and expiry stops working.
fn ends(created: u32, expiry: Option<u32>) -> Option<u64> {
    expiry.map(|e| u64::from(created) + u64::from(e))
}

fn date(t: u64) -> String {
    let (y, m, d) = civil_from_days(i64::try_from(t / 86_400).unwrap_or(i64::MAX / 2));
    format!("{y:04}-{m:02}-{d:02}")
}

fn key_id_hex(fpr: &[u8; 20]) -> String {
    fpr[12..].iter().map(|b| format!("{b:02X}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::armor;
    use crate::cert::{create, days_from_civil, export, Expiry, Identity, KeySet};

    #[test]
    fn now_constant_is_the_date() {
        assert_eq!(i64::from(NOW), days_from_civil(2026, 10, 16) * 86_400);
    }
    use crate::packet::{parse_packets, write_packet};

    /// 2026-10-16 00:00 UTC.
    const NOW: u32 = 1_792_108_800;

    fn id() -> Identity {
        Identity {
            name: "Ada".into(),
            email: "ada@example.org".into(),
        }
    }

    fn make(t: KeyType, e: Expiry) -> (KeySet, String) {
        let set = create(t, &id(), e, NOW).unwrap();
        let out = export(&set, b"pw", NOW).unwrap();
        (set, out.secret)
    }

    fn check_round_trip(t: KeyType) {
        let (set, text) = make(t, Expiry::default());
        let got = open_at(text.as_bytes(), Some(b"pw"), NOW).unwrap();
        assert_eq!(got.user_ids, ["Ada <ada@example.org>"]);
        assert_eq!(got.expiry, set.expiry);
        assert_eq!(got.primary_fpr, set.parts[0].fingerprint());
        assert!(got.notes.is_empty(), "{:?}", got.notes);
        let slots = [Slot::Sign, Slot::Decrypt, Slot::Auth];
        assert_eq!(got.keys.len(), 3);
        for (i, k) in got.keys.iter().enumerate() {
            assert_eq!(k.slot, Some(slots[i]), "{t:?} key {i}");
            assert_eq!(k.fpr, set.parts[i].fingerprint());
            assert_eq!(k.part.fingerprint(), k.fpr);
            assert_eq!(k.key_type, Some(t));
        }
        assert_eq!(
            [got.keys[0].flags, got.keys[1].flags, got.keys[2].flags],
            [0x03, 0x0C, 0x20]
        );
        let public = export(&set, b"pw", NOW).unwrap().public;
        let cert = open_public(public.as_bytes()).unwrap();
        assert_eq!(cert.primary.fpr, set.parts[0].fingerprint());
        assert_eq!(cert.primary.body, set.parts[0].public_body());
        assert_eq!(cert.subkeys.len(), 2);
        assert_eq!(cert.subkeys[1].fpr, set.parts[2].fingerprint());
        assert_eq!(cert.packets.len(), 7);
        // A secret file gives the same public certificate.
        let from_secret = open_public(text.as_bytes()).unwrap();
        assert_eq!(from_secret.primary, cert.primary);
        assert_eq!(from_secret.subkeys, cert.subkeys);
        assert_eq!(from_secret.packets[0].0, 6);
        assert_eq!(from_secret.packets[3].0, 14);
    }

    #[test]
    fn export_then_open_round_trips_every_type() {
        for t in KeyType::ALL {
            if !matches!(t, KeyType::Rsa3072 | KeyType::Rsa4096) {
                check_round_trip(t);
            }
        }
    }

    #[test]
    #[ignore = "RSA-3072/4096 keygen is slow"]
    fn export_then_open_round_trips_big_rsa() {
        check_round_trip(KeyType::Rsa3072);
        check_round_trip(KeyType::Rsa4096);
    }

    #[test]
    fn never_expiry_reads_back_as_none() {
        let (_, text) = make(KeyType::Cv25519, Expiry::Never);
        assert_eq!(
            open_at(text.as_bytes(), Some(b"pw"), NOW).unwrap().expiry,
            None
        );
    }

    #[test]
    fn wrong_or_missing_passphrase() {
        let (_, text) = make(KeyType::Cv25519, Expiry::default());
        assert!(matches!(
            open(text.as_bytes(), Some(b"nope")),
            Err(Error::WrongPassphrase)
        ));
        assert!(matches!(
            open(text.as_bytes(), None),
            Err(Error::NeedsPassphrase)
        ));
        assert_eq!(
            Error::NeedsPassphrase.to_string(),
            "This backup needs its passphrase."
        );
    }

    #[test]
    fn binary_input_and_public_file() {
        let set = create(KeyType::NistP256, &id(), Expiry::Never, NOW).unwrap();
        let out = export(&set, b"pw", NOW).unwrap();
        let (_, bin) = armor::decode(&out.secret).unwrap();
        let got = open(&bin, Some(b"pw")).unwrap();
        assert_eq!(got.primary_fpr, set.parts[0].fingerprint());
        assert!(matches!(
            open(out.public.as_bytes(), Some(b"pw")),
            Err(Error::PublicOnly)
        ));
        assert!(open(out.revocation.as_bytes(), Some(b"pw")).is_err());
        assert!(open_public(out.revocation.as_bytes()).is_err());
    }

    #[test]
    fn every_truncation_is_an_error() {
        let (_, text) = make(KeyType::Cv25519, Expiry::default());
        // The final newline is optional; every shorter prefix must fail.
        let text = text.trim_end();
        for n in 0..text.len() {
            assert!(open(&text.as_bytes()[..n], Some(b"pw")).is_err(), "{n}");
            assert!(open_public(&text.as_bytes()[..n]).is_err(), "{n}");
        }
        // Binary: inside a packet always an error; at a packet boundary the
        // prefix can be a valid smaller key set, but it must not panic.
        let (_, bin) = armor::decode(text).unwrap();
        let mut bounds = vec![0];
        let mut at = 0;
        for p in parse_packets(&bin).unwrap() {
            let mut one = Vec::new();
            write_packet(&mut one, p.tag, p.body);
            at += one.len();
            bounds.push(at);
        }
        for n in 0..bin.len() {
            let r = open(&bin[..n], Some(b"pw"));
            if !bounds.contains(&n) {
                assert!(r.is_err(), "binary {n}");
            }
        }
    }

    fn rebuild(bin: &[u8], f: impl Fn(usize, u8, &mut Vec<u8>)) -> Vec<u8> {
        let mut out = Vec::new();
        for (i, p) in parse_packets(bin).unwrap().iter().enumerate() {
            let mut body = p.body.to_vec();
            f(i, p.tag, &mut body);
            write_packet(&mut out, p.tag, &body);
        }
        out
    }

    #[test]
    fn v5_key_is_unsupported() {
        let (_, text) = make(KeyType::Cv25519, Expiry::default());
        let (_, bin) = armor::decode(&text).unwrap();
        let v5 = rebuild(&bin, |i, _, b| {
            if i == 0 {
                b[0] = 5;
            }
        });
        assert!(matches!(
            open(&v5, Some(b"pw")),
            Err(Error::Unsupported("version 5/6 keys"))
        ));
        assert!(matches!(
            open_public(&v5),
            Err(Error::Unsupported("version 5/6 keys"))
        ));
    }

    #[test]
    fn brainpool_and_unknown_algorithms_are_named() {
        let (_, text) = make(KeyType::NistP256, Expiry::default());
        let (_, bin) = armor::decode(&text).unwrap();
        // Swap the P-256 OID for brainpoolP256r1 (same length, 9 bytes vs
        // 8: rebuild the OID field).
        let bp = rebuild(&bin, |i, _, b| {
            if i == 0 {
                let oid_len = usize::from(b[6]);
                let new = keyroost_openpgp::Curve::BrainpoolP256r1.oid();
                b.splice(
                    6..7 + oid_len,
                    std::iter::once(new.len() as u8).chain(new.iter().copied()),
                );
            }
        });
        assert!(matches!(
            open(&bp, Some(b"pw")),
            Err(Error::Unsupported(
                "Brainpool keys can be made on the card but not loaded from a file yet"
            ))
        ));
        let dsa = rebuild(&bin, |i, _, b| {
            if i == 0 {
                b[5] = 17;
            }
        });
        assert!(matches!(
            open(&dsa, Some(b"pw")),
            Err(Error::Unsupported("DSA keys"))
        ));
    }

    #[test]
    fn gnu_dummy_primary_says_the_secret_is_missing() {
        let (set, text) = make(KeyType::Cv25519, Expiry::default());
        let (_, bin) = armor::decode(&text).unwrap();
        let pub_len = set.parts[0].public_body().len();
        let dummy = rebuild(&bin, |i, _, b| {
            if i == 0 {
                b.truncate(pub_len);
                b.extend_from_slice(&[254, 0, 101, 0, b'G', b'N', b'U', 1]);
            }
        });
        let err = open(&dummy, Some(b"pw")).err().unwrap();
        assert!(matches!(err, Error::NoSecretPart), "{err:?}");
        assert_eq!(
            err.to_string(),
            "This file has no secret part for this key (it was exported without it)."
        );
        let stub = rebuild(&bin, |i, _, b| {
            if i == 0 {
                b.truncate(pub_len);
                b.extend_from_slice(&[254, 0, 101, 0, b'G', b'N', b'U', 2, 0]);
            }
        });
        assert!(matches!(open(&stub, Some(b"pw")), Err(Error::CardStubs)));
    }

    #[test]
    fn too_many_keys_are_refused() {
        let (_, text) = make(KeyType::Cv25519, Expiry::default());
        let (_, bin) = armor::decode(&text).unwrap();
        let pk = parse_packets(&bin).unwrap();
        let mut many = bin.clone();
        for _ in 0..8 {
            for p in &pk[3..] {
                write_packet(&mut many, p.tag, p.body);
            }
        }
        assert!(matches!(
            open(&many, Some(b"pw")),
            Err(Error::Malformed("too many keys in one file"))
        ));
    }

    #[test]
    fn revoked_and_expired_subkeys_are_skipped_with_a_note() {
        // Expired: open well after a 1-year expiry.
        let (_, text) = make(KeyType::Cv25519, Expiry::Years(1));
        let later = NOW + 2 * 366 * 86_400;
        let got = open_at(text.as_bytes(), Some(b"pw"), later).unwrap();
        assert!(got.keys.iter().all(|k| k.slot != Some(Slot::Decrypt)));
        assert_eq!(got.keys.len(), 1, "only the primary is kept");
        assert_eq!(got.notes.len(), 3, "{:?}", got.notes);
        // Revoked: turn the decrypt binding into a subkey revocation.
        let (_, text) = make(KeyType::Cv25519, Expiry::default());
        let (_, bin) = armor::decode(&text).unwrap();
        let rev = rebuild(&bin, |i, _, b| {
            if i == 4 {
                b[1] = 0x28;
            }
        });
        let got = open_at(&rev, Some(b"pw"), NOW).unwrap();
        assert_eq!(got.keys.len(), 2);
        assert_eq!(got.keys[1].slot, Some(Slot::Auth));
        assert!(got.notes[0].contains("revoked"), "{:?}", got.notes);
    }

    #[test]
    fn mutated_exports_never_panic() {
        // Without a passphrase the reader goes through every structural
        // check, then stops before the (slow) S2K.
        for t in [KeyType::Cv25519, KeyType::NistP384] {
            let (_, text) = make(t, Expiry::default());
            let (_, bin) = armor::decode(&text).unwrap();
            for i in 0..bin.len() {
                for x in [0x01u8, 0x80, 0xFF] {
                    let mut m = bin.clone();
                    m[i] ^= x;
                    let _ = open(&m, None);
                    let _ = open_public(&m);
                }
            }
        }
    }

    #[test]
    fn garbage_never_panics() {
        let mut seed = 0x1234_5678u32;
        for len in 0..300 {
            let data: Vec<u8> = (0..len)
                .map(|_| {
                    seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                    (seed >> 16) as u8
                })
                .collect();
            assert!(open(&data, Some(b"x")).is_err());
            assert!(open_public(&data).is_err());
        }
    }
}
