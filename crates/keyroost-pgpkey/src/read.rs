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
#[non_exhaustive]
pub enum Slot {
    Sign,
    Decrypt,
    Auth,
}

impl Slot {
    /// The card's key slot.
    #[must_use]
    pub const fn crt(self) -> keyroost_openpgp::KeyCrt {
        use keyroost_openpgp::KeyCrt;
        match self {
            Slot::Sign => KeyCrt::Sign,
            Slot::Decrypt => KeyCrt::Decrypt,
            Slot::Auth => KeyCrt::Auth,
        }
    }

    /// The slot for a card key slot.
    #[must_use]
    pub const fn from_crt(crt: keyroost_openpgp::KeyCrt) -> Slot {
        use keyroost_openpgp::KeyCrt;
        match crt {
            KeyCrt::Sign => Slot::Sign,
            KeyCrt::Decrypt => Slot::Decrypt,
            KeyCrt::Auth => Slot::Auth,
        }
    }
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
    /// Whether the file holds the primary key's secret part (not the
    /// case for `gpg --export-secret-subkeys` output).
    pub primary_secret: bool,
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
    let info = primary_info(&cert, &pfpr)?;
    let expiry = info.expiry;

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

    // (key, flags, newest self-signature or binding time)
    let mut chosen: Vec<(&Key, u8, u32)> = vec![(
        &cert.primary,
        info.flags.unwrap_or(FLAG_CERTIFY | FLAG_SIGN),
        info.time,
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
        chosen.push((sub, bind.flags.unwrap_or(fallback), bind.created));
    }

    let mut primary_secret = true;
    // Keys whose secret lives on a card (GnuPG's S2K 101 mode 2 stub).
    let mut stubs = 0usize;
    let mut keys = Vec::with_capacity(chosen.len());
    // Per loaded key: (usable flags, key creation time, signature time).
    let mut rank = Vec::with_capacity(chosen.len());
    for (n, (key, flags, sig_time)) in chosen.into_iter().enumerate() {
        let mut r = Reader::new(&key.body[key.pub_len..]);
        let secret = match s2k::unprotect(&mut r, pass) {
            Ok(secret) => secret,
            Err(e @ (Error::NoSecretPart | Error::CardStubs)) => {
                let what = if n == 0 {
                    primary_secret = false;
                    format!("The primary key {}", key_id_hex(&key.fpr))
                } else {
                    format!("Subkey {}", key_id_hex(&key.fpr))
                };
                if matches!(e, Error::CardStubs) {
                    stubs += 1;
                    notes.push(format!(
                        "{what} lives on a card; this file has only a placeholder for it."
                    ));
                } else {
                    notes.push(format!("{what} has no secret part in this file."));
                }
                continue;
            }
            Err(e) => return Err(e),
        };
        let part = KeyPart::from_secret(key.algo, &key.body[..key.pub_len], &secret)?;
        if part.fingerprint() != key.fpr {
            return Err(Error::Malformed("key does not match its public part"));
        }
        rank.push((flags & capabilities(key.algo), key.created, sig_time));
        keys.push(LoadedKey {
            slot: None,
            key_type: key_type(&part),
            part,
            flags,
            fpr: key.fpr,
        });
    }
    if keys.is_empty() {
        return Err(if stubs > 0 {
            Error::CardStubs
        } else {
            Error::NoSecretPart
        });
    }
    assign_slots(&mut keys, &rank);

    Ok(Loaded {
        user_ids: info.user_ids,
        keys,
        expiry,
        primary_fpr: pfpr,
        primary_secret,
        notes,
    })
}

/// Give each card slot one key. For a slot, the candidates are the loaded
/// (valid, non-revoked, non-expired, with a secret part) keys whose flags,
/// limited to what their algorithm can do, include the slot's usage. A key
/// for that one usage only beats a multi-purpose key; among equals the
/// newest key wins (latest key creation time, as gpg picks its encryption
/// subkey, then the latest binding or self-signature, then the earlier key
/// in the file). A key fills at most one slot; slots are filled in the
/// order Sign, Decrypt, Auth.
fn assign_slots(keys: &mut [LoadedKey], rank: &[(u8, u32, u32)]) {
    for (slot, usage) in [
        (Slot::Sign, FLAG_SIGN),
        (Slot::Decrypt, FLAG_ENCRYPT),
        (Slot::Auth, FLAG_AUTH),
    ] {
        let best = (0..keys.len())
            .filter(|&i| keys[i].slot.is_none() && rank[i].0 & usage != 0)
            .max_by_key(|&i| {
                let (usable, created, sig_time) = rank[i];
                (
                    usable & !usage == 0,
                    created,
                    sig_time,
                    std::cmp::Reverse(i),
                )
            });
        if let Some(i) = best {
            keys[i].slot = Some(slot);
        }
    }
}

/// What the primary key's self-signatures say.
struct PrimaryInfo {
    flags: Option<u8>,
    /// Seconds after creation; `None` for never.
    expiry: Option<u32>,
    /// Creation time of the self-signature the fields came from.
    time: u32,
    /// User IDs with a valid, unrevoked self-certification.
    user_ids: Vec<String>,
}

/// Resolve the primary's flags and expiry. A user ID's newest
/// self-certification (0x10–0x13) is what counts for that user ID, and a
/// user ID revoked (0x30) at or after it is dropped. Of the remaining
/// user IDs the one flagged primary (subpacket 25) wins, else the one
/// certified last; its self-certification gives flags and expiry, where a
/// missing expiry means never (that is how `gpg --quick-set-expire never`
/// writes it). Only a field that self-certification lacks, or when there is
/// no user ID certification at all, comes from the newest direct-key
/// signature (0x1F) that carries it: GnuPG's designated-revoker
/// signatures, for one, are 0x1F without flags or expiry.
fn newest<'s>(sigs: &'s [Sig], pfpr: &[u8; 20], typ: fn(u8) -> bool) -> Option<&'s Sig> {
    sigs.iter()
        .filter(|s| typ(s.typ) && s.by(pfpr))
        .max_by_key(|s| s.created)
}

/// Each user ID's newest self-certification (0x10–0x13), for the user IDs
/// not revoked (0x30) at or after it, in file order.
fn live_uids<'c>(cert: &'c Cert, pfpr: &[u8; 20]) -> Vec<(&'c str, &'c Sig)> {
    cert.uids
        .iter()
        .filter_map(|(uid, sigs)| live_cert(sigs, pfpr).map(|c| (uid.as_str(), c)))
        .collect()
}

/// A user ID's newest self-certification, unless a revocation at or after
/// it drops the user ID.
fn live_cert<'s>(sigs: &'s [Sig], pfpr: &[u8; 20]) -> Option<&'s Sig> {
    let c = newest(sigs, pfpr, |t| (0x10..=0x13).contains(&t))?;
    let revoked = newest(sigs, pfpr, |t| t == 0x30).is_some_and(|r| r.created >= c.created);
    (!revoked).then_some(c)
}

fn primary_info(cert: &Cert, pfpr: &[u8; 20]) -> Result<PrimaryInfo> {
    let live = live_uids(cert, pfpr);
    let chosen = live
        .iter()
        .filter(|(_, s)| s.primary_uid)
        .max_by_key(|(_, s)| s.created)
        .or_else(|| live.iter().max_by_key(|(_, s)| s.created))
        .map(|&(_, s)| s);
    let direct: Vec<&Sig> = cert
        .primary
        .sigs
        .iter()
        .filter(|s| s.typ == 0x1F && s.by(pfpr))
        .collect();
    let direct_with = |f: fn(&Sig) -> Option<u32>| {
        direct
            .iter()
            .filter(|s| f(s).is_some())
            .max_by_key(|s| s.created)
            .and_then(|s| f(s))
    };
    let time = match (chosen, direct.iter().map(|s| s.created).max()) {
        (Some(c), _) => c.created,
        (None, Some(t)) => t,
        (None, None) => return Err(Error::Malformed("no self-signature")),
    };
    let flags = chosen
        .and_then(|s| s.flags)
        .or_else(|| direct_with(|s| s.flags.map(u32::from)).map(|f| f as u8));
    let expiry = match chosen {
        Some(c) if c.expiry.is_some() => c.expiry,
        _ => direct_with(|s| s.expiry),
    }
    .filter(|&e| e != 0);
    Ok(PrimaryInfo {
        flags,
        expiry,
        time,
        user_ids: live.iter().map(|(u, _)| (*u).to_string()).collect(),
    })
}

/// Whether opening the secret key file `data` needs a passphrase: `false`
/// for a file whose keys are not protected (as `gpg --export-secret-keys`
/// writes a key that has no passphrase). Errors as [`open`] does without a
/// passphrase, other than [`Error::NeedsPassphrase`].
pub fn needs_passphrase(data: &[u8]) -> Result<bool> {
    match open(data, None) {
        Ok(_) => Ok(false),
        Err(Error::NeedsPassphrase) => Ok(true),
        Err(e) => Err(e),
    }
}

/// Whether `data` (armored or binary) is a secret key file — a backup or a
/// GnuPG secret export — rather than a public certificate. Unreadable data
/// is not.
#[must_use]
pub fn is_secret(data: &[u8]) -> bool {
    match decode_input(data) {
        Ok((Some(kind), _)) => kind == Kind::PrivateKey,
        Ok((None, bin)) => {
            parse_packets(&bin)
                .ok()
                .and_then(|p| p.first().map(|p| p.tag))
                == Some(Tag::SECRET_KEY)
        }
        Err(_) => false,
    }
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

/// The self-signatures an expiry change re-signs, read from a public
/// certificate the way [`open`] reads them.
pub(crate) struct SelfSigs {
    /// Per user ID packet, in file order: the body of its newest live
    /// self-certification (`None` for a revoked or uncertified user ID).
    pub uids: Vec<Option<Vec<u8>>>,
    /// Per subkey, in file order: the body of its newest binding (`None`
    /// for a revoked or unbound subkey).
    pub subkeys: Vec<Option<Vec<u8>>>,
    /// Creation time of the newest signature the primary key made.
    pub newest: u32,
    /// The primary key's expiry, seconds after its creation.
    pub expiry: Option<u32>,
}

pub(crate) fn self_sigs(public: &PublicCert) -> Result<SelfSigs> {
    let packets: Vec<Packet<'_>> = public
        .packets
        .iter()
        .map(|(tag, body)| Packet { tag: *tag, body })
        .collect();
    let cert = parse_cert(&packets)?;
    let pfpr = cert.primary.fpr;
    let info = primary_info(&cert, &pfpr)?;
    let uids = cert
        .uids
        .iter()
        .map(|(_, sigs)| live_cert(sigs, &pfpr).map(|s| s.raw.clone()))
        .collect();
    let subkeys = cert
        .subkeys
        .iter()
        .map(|sub| {
            if sub.sigs.iter().any(|s| s.typ == 0x28 && s.by(&pfpr)) {
                return None;
            }
            newest(&sub.sigs, &pfpr, |t| t == 0x18).map(|s| s.raw.clone())
        })
        .collect();
    let all = cert
        .primary
        .sigs
        .iter()
        .chain(cert.uids.iter().flat_map(|(_, s)| s))
        .chain(cert.subkeys.iter().flat_map(|k| &k.sigs));
    let newest = all
        .filter(|s| s.by(&pfpr))
        .map(|s| s.created)
        .max()
        .unwrap_or(0);
    Ok(SelfSigs {
        uids,
        subkeys,
        newest,
        expiry: info.expiry,
    })
}

/// A key file's packets (armored or binary), marker and trust packets left
/// out, secret parts kept.
pub(crate) fn key_packets(data: &[u8]) -> Result<Vec<(u8, Vec<u8>)>> {
    let (_, bin) = decode_input(data)?;
    Ok(parse_packets(&bin)?
        .iter()
        .filter(|p| !matches!(p.tag, 10 | 12))
        .map(|p| (p.tag, p.body.to_vec()))
        .collect())
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
    /// Primary user ID flag (subpacket 25), hashed.
    primary_uid: bool,
    issuer_fpr: Option<[u8; 20]>,
    issuer_id: Option<[u8; 8]>,
    /// The whole signature packet body.
    raw: Vec<u8>,
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
        raw: body.to_vec(),
        ..Sig::default()
    };
    subpackets(hashed, &mut sig, true)?;
    subpackets(unhashed, &mut sig, false)?;
    Ok(Some(sig))
}

fn subpackets(data: &[u8], sig: &mut Sig, hashed: bool) -> Result<()> {
    for (typ, v) in crate::sig::split_subpackets(data)? {
        let be32 = |v: &[u8]| <[u8; 4]>::try_from(v).ok().map(u32::from_be_bytes);
        match (typ & 0x7F, hashed) {
            (2, true) => sig.created = be32(v).ok_or(Error::Malformed("bad signature time"))?,
            (9, true) => sig.expiry = Some(be32(v).ok_or(Error::Malformed("bad key expiry"))?),
            (27, true) => sig.flags = Some(v.first().copied().unwrap_or(0)),
            (25, true) => sig.primary_uid = v.first().is_some_and(|&b| b != 0),
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

pub(crate) fn key_type(part: &KeyPart) -> Option<KeyType> {
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
    fn gnu_dummy_keys_are_noted_and_all_dummy_fails() {
        let (set, text) = make(KeyType::Cv25519, Expiry::default());
        let (_, bin) = armor::decode(&text).unwrap();
        let dummy = |b: &mut Vec<u8>, len: usize| {
            b.truncate(len);
            b.extend_from_slice(&[254, 0, 101, 0, b'G', b'N', b'U', 1]);
        };
        let lens: Vec<usize> = set.parts.iter().map(|p| p.public_body().len()).collect();
        let no_primary = rebuild(&bin, |i, _, b| {
            if i == 0 {
                dummy(b, lens[0]);
            }
        });
        let got = open_at(&no_primary, Some(b"pw"), NOW).unwrap();
        assert!(!got.primary_secret);
        assert_eq!(got.primary_fpr, set.parts[0].fingerprint());
        let slots: Vec<_> = got.keys.iter().map(|k| k.slot).collect();
        assert_eq!(slots, [Some(Slot::Decrypt), Some(Slot::Auth)]);
        assert_eq!(got.notes.len(), 1);
        assert!(got.notes[0].contains("has no secret part in this file"));
        let full = open_at(text.as_bytes(), Some(b"pw"), NOW).unwrap();
        assert!(full.primary_secret);

        let none = rebuild(&bin, |i, _, b| match i {
            0 => dummy(b, lens[0]),
            3 => dummy(b, lens[1]),
            5 => dummy(b, lens[2]),
            _ => {}
        });
        let err = open(&none, Some(b"pw")).err().unwrap();
        assert!(matches!(err, Error::NoSecretPart), "{err:?}");
        assert_eq!(
            err.to_string(),
            "This file has no secret part for this key (it was exported without it)."
        );
    }

    /// GnuPG's placeholder for a key moved to a card with `keytocard`:
    /// S2K 101 ("GNU") mode 2, then the card serial (length-prefixed).
    fn card_stub(b: &mut Vec<u8>, len: usize) {
        b.truncate(len);
        b.extend_from_slice(&[254, 0, 101, 0, b'G', b'N', b'U', 2, 4, 1, 2, 3, 4]);
    }

    #[test]
    fn secret_files_are_told_from_public_ones_armored_or_not() {
        let (_, text) = make(KeyType::Cv25519, Expiry::default());
        let (_, bin) = armor::decode(&text).unwrap();
        assert!(is_secret(text.as_bytes()));
        assert!(is_secret(&bin));
        let public = crate::cert::export(&make(KeyType::Cv25519, Expiry::default()).0, b"pw", NOW)
            .unwrap()
            .public;
        let (_, pub_bin) = armor::decode(&public).unwrap();
        assert!(!is_secret(public.as_bytes()));
        assert!(!is_secret(&pub_bin));
        assert!(!is_secret(b"not a key"));
        assert!(!is_secret(b""));
    }

    #[test]
    fn unprotected_files_need_no_passphrase() {
        let (set, text) = make(KeyType::Cv25519, Expiry::default());
        assert!(needs_passphrase(text.as_bytes()).unwrap());
        let (_, bin) = armor::decode(&text).unwrap();
        let parts: Vec<(usize, usize)> = [(0, 0), (3, 1), (5, 2)]
            .into_iter()
            .map(|(i, k)| (i, set.parts[k].public_body().len()))
            .collect();
        // Usage 0: the secret MPIs in the clear, then their 16-bit sum.
        let plain = rebuild(&bin, |i, _, b| {
            if let Some(&(_, len)) = parts.iter().find(|(at, _)| *at == i) {
                let k = [0, 3, 5].iter().position(|&x| x == i).unwrap();
                let mpis = set.parts[k].secret_mpis();
                let sum = mpis.iter().fold(0u16, |a, &x| a.wrapping_add(u16::from(x)));
                b.truncate(len);
                b.push(0);
                b.extend_from_slice(&mpis);
                b.extend_from_slice(&sum.to_be_bytes());
            }
        });
        assert!(!needs_passphrase(&plain).unwrap());
        assert_eq!(open_at(&plain, None, NOW).unwrap().keys.len(), 3);
        // An expiry change on it signs with an empty passphrase.
        let public = open_public(&plain).unwrap();
        assert!(
            crate::cert::change_expiry_with_backup(&public, &plain, b"", Expiry::Never, NOW)
                .is_ok()
        );
        assert!(needs_passphrase(b"junk").is_err());
    }

    #[test]
    fn card_stubs_are_skipped_per_key() {
        let (set, text) = make(KeyType::Cv25519, Expiry::default());
        let (_, bin) = armor::decode(&text).unwrap();
        let lens: Vec<usize> = set.parts.iter().map(|p| p.public_body().len()).collect();

        // Subkeys on a card, primary in the file (`keytocard` on the
        // subkeys only): the primary loads, each stub is a note.
        let subs_on_card = rebuild(&bin, |i, _, b| match i {
            3 => card_stub(b, lens[1]),
            5 => card_stub(b, lens[2]),
            _ => {}
        });
        let got = open_at(&subs_on_card, Some(b"pw"), NOW).unwrap();
        assert!(got.primary_secret);
        assert_eq!(got.keys.len(), 1);
        assert_eq!(got.keys[0].fpr, set.parts[0].fingerprint());
        assert_eq!(got.keys[0].slot, Some(Slot::Sign));
        assert_eq!(got.notes.len(), 2, "{:?}", got.notes);
        assert!(got
            .notes
            .iter()
            .all(|n| n.ends_with("lives on a card; this file has only a placeholder for it.")));

        // Primary on a card, subkeys in the file.
        let primary_on_card = rebuild(&bin, |i, _, b| {
            if i == 0 {
                card_stub(b, lens[0]);
            }
        });
        let got = open_at(&primary_on_card, Some(b"pw"), NOW).unwrap();
        assert!(!got.primary_secret);
        assert_eq!(got.keys.len(), 2);
        assert!(
            got.notes[0].starts_with("The primary key "),
            "{:?}",
            got.notes
        );

        // Every key on a card: nothing to restore.
        let all = rebuild(&bin, |i, _, b| match i {
            0 => card_stub(b, lens[0]),
            3 => card_stub(b, lens[1]),
            5 => card_stub(b, lens[2]),
            _ => {}
        });
        assert!(matches!(open(&all, Some(b"pw")), Err(Error::CardStubs)));
        // Stubs need no passphrase to be recognized.
        let none = rebuild(&bin, |i, _, b| match i {
            0 => card_stub(b, lens[0]),
            3 => card_stub(b, lens[1]),
            5 => card_stub(b, lens[2]),
            _ => {}
        });
        assert!(matches!(open(&none, None), Err(Error::CardStubs)));
    }

    #[test]
    fn expiry_changes_with_a_file_whose_subkeys_live_on_a_card() {
        let (set, text) = make(KeyType::Cv25519, Expiry::default());
        let (_, bin) = armor::decode(&text).unwrap();
        let lens: Vec<usize> = set.parts.iter().map(|p| p.public_body().len()).collect();
        let subs_on_card = rebuild(&bin, |i, _, b| match i {
            3 => card_stub(b, lens[1]),
            5 => card_stub(b, lens[2]),
            _ => {}
        });
        let armored = armor::encode(Kind::PrivateKey, &subs_on_card);
        let public = open_public(&subs_on_card).unwrap();
        let (secret, new_public) = crate::cert::change_expiry_with_backup(
            &public,
            armored.as_bytes(),
            b"pw",
            Expiry::Never,
            NOW,
        )
        .unwrap();
        let cert = open_public(new_public.as_bytes()).unwrap();
        assert_eq!(crate::cert::current_expiry(&cert), None);
        // The backup keeps its placeholders and gets the new date too.
        let back = open_at(secret.as_bytes(), Some(b"pw"), NOW).unwrap();
        assert_eq!(back.expiry, None);
        assert_eq!(back.keys.len(), 1);
        assert_eq!(back.notes.len(), 2);
    }

    /// A v4 signature body with the given hashed subpackets and no MPIs
    /// (the reader does not verify signatures).
    fn fake_sig(typ: u8, hashed: &[&[u8]]) -> Vec<u8> {
        let h: Vec<u8> = hashed.concat();
        let mut v = vec![4, typ, 22, 8];
        v.extend_from_slice(&(h.len() as u16).to_be_bytes());
        v.extend_from_slice(&h);
        v.extend_from_slice(&[0, 0, 0, 0]);
        v
    }

    fn sp(typ: u8, data: &[u8]) -> Vec<u8> {
        let mut v = vec![data.len() as u8 + 1, typ];
        v.extend_from_slice(data);
        v
    }

    /// Re-emit `bin`'s packets, inserting `extra` after packet `after`.
    fn insert_after(bin: &[u8], after: usize, extra: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (i, p) in parse_packets(bin).unwrap().iter().enumerate() {
            write_packet(&mut out, p.tag, p.body);
            if i == after {
                for (tag, body) in extra {
                    write_packet(&mut out, *tag, body);
                }
            }
        }
        out
    }

    #[test]
    fn newer_direct_key_sig_without_flags_does_not_override_the_uid_cert() {
        // A certify-only primary (flags 01 in its uid self-cert), then a
        // newer 0x1F like GnuPG's addrevoker writes: no flags, no expiry.
        let (set, text) = make(KeyType::Cv25519, Expiry::default());
        let (_, bin) = armor::decode(&text).unwrap();
        let certify_only = rebuild(&bin, |i, _, b| {
            if i == 2 {
                let at = b.windows(3).position(|w| w == [2, 27, 0x03]).unwrap();
                b[at + 2] = 0x01;
            }
        });
        let direct = fake_sig(0x1F, &[&sp(2, &(NOW + 100).to_be_bytes())]);
        let with_direct = insert_after(&certify_only, 0, &[(2, direct)]);
        let got = open_at(&with_direct, Some(b"pw"), NOW).unwrap();
        assert_eq!(got.expiry, set.expiry);
        assert_eq!(got.keys[0].flags, 0x01);
        let slots: Vec<_> = got.keys.iter().map(|k| k.slot).collect();
        assert_eq!(slots, [None, Some(Slot::Decrypt), Some(Slot::Auth)]);

        // Only a 0x1F carrying flags/expiry, no uid cert at all: used.
        let direct = fake_sig(
            0x1F,
            &[
                &sp(2, &NOW.to_be_bytes()),
                &sp(9, &777u32.to_be_bytes()),
                &sp(27, &[0x03]),
            ],
        );
        let mut only_direct = Vec::new();
        for (i, p) in parse_packets(&bin).unwrap().iter().enumerate() {
            match i {
                0 => {
                    write_packet(&mut only_direct, p.tag, p.body);
                    write_packet(&mut only_direct, 2, &direct);
                }
                2 => {}
                _ => write_packet(&mut only_direct, p.tag, p.body),
            }
        }
        let got = open_at(&only_direct, Some(b"pw"), NOW).unwrap();
        assert_eq!(got.expiry, Some(777));
        assert_eq!(got.keys[0].slot, Some(Slot::Sign));
    }

    #[test]
    fn primary_user_id_wins_and_revoked_user_ids_drop_out() {
        let (set, text) = make(KeyType::Cv25519, Expiry::default());
        let (_, bin) = armor::decode(&text).unwrap();
        let pk = parse_packets(&bin).unwrap();
        // An older, primary-flagged user ID with its own expiry.
        let flagged = fake_sig(
            0x13,
            &[
                &sp(2, &(NOW - 10).to_be_bytes()),
                &sp(9, &4242u32.to_be_bytes()),
                &sp(27, &[0x03]),
                &sp(25, &[1]),
            ],
        );
        // A revoked user ID: its (copied) self-cert, then a newer 0x30.
        let revoked = fake_sig(0x30, &[&sp(2, &(NOW + 100).to_be_bytes())]);
        let extra = [
            (13, b"Primary <p@example.org>".to_vec()),
            (2, flagged),
            (13, b"Old <old@example.org>".to_vec()),
            (2, pk[2].body.to_vec()),
            (2, revoked),
        ];
        let got = open_at(&insert_after(&bin, 2, &extra), Some(b"pw"), NOW).unwrap();
        assert_eq!(
            got.user_ids,
            ["Ada <ada@example.org>", "Primary <p@example.org>"]
        );
        assert_eq!(got.expiry, Some(4242));
        assert_ne!(set.expiry, Some(4242));
    }

    #[test]
    fn slot_rule_prefers_single_purpose_then_newest() {
        let mut keys = Vec::new();
        for _ in 0..2 {
            for part in crate::keys::generate(KeyType::Cv25519, NOW).unwrap() {
                keys.push(LoadedKey {
                    slot: None,
                    fpr: part.fingerprint(),
                    part,
                    flags: 0,
                    key_type: None,
                });
            }
        }
        // 0: sign+auth (newest); 1: encrypt, old; 2: auth only, old;
        // 3: encrypt, newer; 4: encrypt, same time as 3; 5: sign, oldest.
        let rank = [
            (FLAG_SIGN | FLAG_AUTH, 300, 300),
            (FLAG_ENCRYPT, 100, 100),
            (FLAG_AUTH, 100, 100),
            (FLAG_ENCRYPT, 200, 200),
            (FLAG_ENCRYPT, 200, 200),
            (FLAG_SIGN, 50, 50),
        ];
        assign_slots(&mut keys, &rank);
        let slots: Vec<_> = keys.iter().map(|k| k.slot).collect();
        assert_eq!(
            slots,
            [
                None,
                None,
                Some(Slot::Auth),
                Some(Slot::Decrypt),
                None,
                Some(Slot::Sign)
            ]
        );
        // Without the single-purpose sign key, the multi-purpose one signs
        // and the auth-only key still authenticates.
        for k in &mut keys {
            k.slot = None;
        }
        assign_slots(&mut keys[..5], &rank[..5]);
        assert_eq!(keys[0].slot, Some(Slot::Sign));
        assert_eq!(keys[2].slot, Some(Slot::Auth));
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
