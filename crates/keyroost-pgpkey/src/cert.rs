//! Assemble a generated key set into a GnuPG-compatible backup, a public
//! certificate and a revocation certificate.

use crate::armor::{self, Kind};
use crate::keys::{generate, KeyPart, KeyType};
use crate::packet::{write_packet, Tag};
use crate::read::{PublicCert, PublicPart, Slot};
use crate::s2k;
use crate::sig::{
    hash_for, hash_for_public, sig_areas, sign, signed_key, signed_uid, split_subpackets,
    HostSigner, SigType, Signer, Subpackets, FEATURES, FLAGS_AUTH, FLAGS_DECRYPT, FLAGS_PRIMARY,
    KEYSERVER_PREFS, PREF_COMPRESSION, PREF_HASH, PREF_SYM,
};
use crate::Error;

const DAY: i64 = 86_400;

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`).
#[must_use]
pub fn days_from_civil(y: i32, m: u8, d: u8) -> i64 {
    let y = i64::from(y) - i64::from(m <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The date for a day count since 1970-01-01 (Howard Hinnant's
/// `civil_from_days`).
#[must_use]
pub fn civil_from_days(z: i64) -> (i32, u8, u8) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    ((y + i64::from(m <= 2)) as i32, m as u8, d as u8)
}

fn is_leap(y: i32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i32, m: u8) -> u8 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if is_leap(y) => 29,
        _ => 28,
    }
}

const DATE_FORMAT: &str = "Enter the date as YYYY-MM-DD.";

/// When a key set stops being valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Expiry {
    Never,
    /// Calendar years after the creation date (1, 2, 3 or 5).
    Years(u8),
    /// Expires at midday UTC on this day, as GnuPG does with a date, so
    /// the date reads the same in nearly every time zone.
    Date {
        y: i32,
        m: u8,
        d: u8,
    },
}

impl Default for Expiry {
    fn default() -> Self {
        Expiry::Years(3)
    }
}

impl Expiry {
    /// Parse `never`, `1y`/`2y`/`3y`/`5y` or `YYYY-MM-DD`.
    pub fn parse(s: &str) -> Result<Expiry, String> {
        let s = s.trim().to_ascii_lowercase();
        if s == "never" {
            return Ok(Expiry::Never);
        }
        if let Some(n) = s.strip_suffix('y') {
            return match n {
                "1" => Ok(Expiry::Years(1)),
                "2" => Ok(Expiry::Years(2)),
                "3" => Ok(Expiry::Years(3)),
                "5" => Ok(Expiry::Years(5)),
                _ => Err("Choose never, 1y, 2y, 3y, 5y or a date (YYYY-MM-DD).".into()),
            };
        }
        Expiry::parse_date(&s).map_err(String::from)
    }

    /// Parse a typed `YYYY-MM-DD` date: the one check, and the one set of
    /// messages, the CLI's `--expires` and the GUI's date field share.
    /// Whether the date is still ahead is [`end_time`](Self::end_time)'s
    /// check ("That date is in the past.").
    pub fn parse_date(s: &str) -> Result<Expiry, &'static str> {
        let parts: Vec<&str> = s.trim().split('-').collect();
        let well_formed = matches!(parts[..], [y, m, d] if y.len() == 4 && m.len() == 2 && d.len() == 2)
            && parts.iter().all(|p| p.bytes().all(|b| b.is_ascii_digit()));
        if !well_formed {
            return Err(DATE_FORMAT);
        }
        let num = |p: &str| p.parse::<u16>().map_err(|_| DATE_FORMAT);
        let (y, m, d) = (i32::from(num(parts[0])?), num(parts[1])?, num(parts[2])?);
        if !(1..=12).contains(&m) || d == 0 || d > u16::from(days_in_month(y, m as u8)) {
            return Err("That date does not exist.");
        }
        if y > 2105 {
            return Err("Pick a date before 2106.");
        }
        if y < 1970 {
            return Err("That date is in the past.");
        }
        Ok(Expiry::Date {
            y,
            m: m as u8,
            d: d as u8,
        })
    }

    /// Seconds after `created` at which the key expires, or `None` for
    /// never. Whole-year and date choices both resolve to midday UTC of the
    /// target date.
    pub fn seconds_after(self, created: u32) -> Result<Option<u32>, String> {
        Ok(self.end_time(created)?.map(|end| end - created))
    }

    /// The moment (seconds since 1970) the key stops working, or `None` for
    /// never: midday UTC of the target date, whole years counting from
    /// `from`. A date must be after the day `from` falls on.
    pub fn end_time(self, from: u32) -> Result<Option<u32>, String> {
        let (y, m, d) = match self {
            Expiry::Never => return Ok(None),
            Expiry::Years(n) => {
                let (cy, cm, cd) = civil_from_days(i64::from(from) / DAY);
                let y = cy + i32::from(n);
                (y, cm, cd.min(days_in_month(y, cm)))
            }
            Expiry::Date { y, m, d } => {
                let (day, today) = (days_from_civil(y, m, d), i64::from(from) / DAY);
                if day < today {
                    return Err("That date is in the past.".into());
                }
                if day == today {
                    return Err("Pick a date after today.".into());
                }
                (y, m, d)
            }
        };
        let end = days_from_civil(y, m, d) * DAY + DAY / 2;
        if end <= i64::from(from) {
            return Err("That date is in the past.".into());
        }
        u32::try_from(end)
            .map(Some)
            .map_err(|_| "That date is too far in the future.".into())
    }
}

/// Who a key set belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub name: String,
    pub email: String,
}

impl Identity {
    /// `Name <email>`, just the name when there is no email.
    pub fn user_id(&self) -> Result<String, String> {
        let (name, email) = (self.name.trim(), self.email.trim());
        match (name.is_empty(), email.is_empty()) {
            (true, true) => Err("Enter a name or an email address.".into()),
            (false, true) => Ok(name.to_string()),
            (true, false) => Ok(format!("<{email}>")),
            (false, false) => Ok(format!("{name} <{email}>")),
        }
    }
}

/// A generated key set: signing primary, decrypt subkey, authenticate subkey.
pub struct KeySet {
    pub parts: [KeyPart; 3],
    pub user_id: String,
    /// Seconds after `created`, or `None` for never.
    pub expiry: Option<u32>,
    pub created: u32,
}

/// Generate a key set of type `t` created at `now`.
pub fn create(t: KeyType, id: &Identity, expiry: Expiry, now: u32) -> Result<KeySet, Error> {
    let user_id = id
        .user_id()
        .map_err(|e| Error::Crypto(e.trim_end_matches('.').to_string()))?;
    let expiry = expiry.seconds_after(now).map_err(Error::Crypto)?;
    Ok(KeySet {
        parts: generate(t, now)?,
        user_id,
        expiry,
        created: now,
    })
}

/// The three armored outputs.
pub struct Outputs {
    pub secret: String,
    pub public: String,
    pub revocation: String,
}

fn sub_binding(set: &KeySet, idx: usize, flags: u8, signer_now: u32) -> Result<Vec<u8>, Error> {
    let primary = &set.parts[0];
    let mut data = signed_key(&primary.public_body());
    data.extend(signed_key(&set.parts[idx].public_body()));
    let hashed = Subpackets::new()
        .created(signer_now)
        .key_expiry(set.expiry)
        .key_flags(flags)
        .issuer_fpr(&primary.fingerprint());
    let unhashed = Subpackets::new().issuer_key_id(&primary.key_id());
    sign(
        &mut HostSigner(primary),
        SigType::SubkeyBinding,
        hash_for(primary),
        &hashed,
        &unhashed,
        &data,
    )
}

/// Armor the secret backup, the public certificate and the revocation
/// certificate. `pass` protects every secret key in the backup.
pub fn export(set: &KeySet, pass: &[u8], signer_now: u32) -> Result<Outputs, Error> {
    let primary = &set.parts[0];
    let hash = hash_for(primary);

    let mut data = signed_key(&primary.public_body());
    data.extend(signed_uid(&set.user_id));
    let hashed = Subpackets::new()
        .created(signer_now)
        .key_expiry(set.expiry)
        .key_flags(FLAGS_PRIMARY)
        .pref_sym(&PREF_SYM)
        .pref_hash(&PREF_HASH)
        .pref_compression(&PREF_COMPRESSION)
        .features(FEATURES)
        .keyserver_prefs(KEYSERVER_PREFS)
        .issuer_fpr(&primary.fingerprint());
    let unhashed = Subpackets::new().issuer_key_id(&primary.key_id());
    let self_cert = sign(
        &mut HostSigner(primary),
        SigType::PositiveCert,
        hash,
        &hashed,
        &unhashed,
        &data,
    )?;
    let dec_bind = sub_binding(set, 1, FLAGS_DECRYPT, signer_now)?;
    let auth_bind = sub_binding(set, 2, FLAGS_AUTH, signer_now)?;

    let secret_body = |part: &KeyPart| -> Result<Vec<u8>, Error> {
        let mut b = part.public_body();
        b.extend(s2k::protect(&part.secret_mpis(), pass)?);
        Ok(b)
    };

    let mut secret = Vec::new();
    write_packet(&mut secret, Tag::SECRET_KEY, &secret_body(primary)?);
    write_packet(&mut secret, Tag::USER_ID, set.user_id.as_bytes());
    write_packet(&mut secret, Tag::SIGNATURE, &self_cert);
    write_packet(
        &mut secret,
        Tag::SECRET_SUBKEY,
        &secret_body(&set.parts[1])?,
    );
    write_packet(&mut secret, Tag::SIGNATURE, &dec_bind);
    write_packet(
        &mut secret,
        Tag::SECRET_SUBKEY,
        &secret_body(&set.parts[2])?,
    );
    write_packet(&mut secret, Tag::SIGNATURE, &auth_bind);

    let mut public = Vec::new();
    write_packet(&mut public, Tag::PUBLIC_KEY, &primary.public_body());
    write_packet(&mut public, Tag::USER_ID, set.user_id.as_bytes());
    write_packet(&mut public, Tag::SIGNATURE, &self_cert);
    write_packet(&mut public, Tag::PUBLIC_SUBKEY, &set.parts[1].public_body());
    write_packet(&mut public, Tag::SIGNATURE, &dec_bind);
    write_packet(&mut public, Tag::PUBLIC_SUBKEY, &set.parts[2].public_body());
    write_packet(&mut public, Tag::SIGNATURE, &auth_bind);

    let hashed = Subpackets::new()
        .created(signer_now)
        .revocation_reason(0, "")
        .issuer_fpr(&primary.fingerprint());
    let rev = sign(
        &mut HostSigner(primary),
        SigType::KeyRevocation,
        hash,
        &hashed,
        &unhashed,
        &signed_key(&primary.public_body()),
    )?;
    let mut revocation = Vec::new();
    write_packet(&mut revocation, Tag::SIGNATURE, &rev);

    Ok(Outputs {
        secret: armor::encode(Kind::PrivateKey, &secret),
        public: armor::encode(Kind::PublicKey, &public),
        // GnuPG writes (and only imports) a revocation certificate as a
        // public key block, like its openpgp-revocs.d files.
        revocation: armor::encode_with_comment(
            Kind::PublicKey,
            &revocation,
            Some("This is a revocation certificate"),
        ),
    })
}

const NO_PRIMARY_SECRET: &str = "This backup doesn't contain the main key's secret part, so it can't sign a new date. Use the card instead.";

/// The new signatures of an expiry change: per user ID packet and per
/// subkey, in file order (`None` where nothing is re-signed).
struct NewSigs {
    uids: Vec<Option<Vec<u8>>>,
    subkeys: Vec<Option<Vec<u8>>>,
}

/// A new signature like `old` (same subpackets, in the same order) but made
/// at `t` with key expiry `secs`.
fn resign_like(
    signer: &mut dyn Signer,
    old: &[u8],
    sig_type: SigType,
    hash: crate::s2k::Hash,
    primary: &PublicPart,
    (t, secs): (u32, Option<u32>),
    data: &[u8],
) -> Result<Vec<u8>, Error> {
    let (_, old_hashed, old_unhashed) = sig_areas(old)?;
    let mut hashed = Subpackets::new().created(t).key_expiry(secs);
    let mut has_fpr = false;
    for (typ, v) in split_subpackets(old_hashed)? {
        match typ & 0x7F {
            2 | 9 => {}
            33 => {
                has_fpr = true;
                hashed = hashed.raw(typ, v);
            }
            _ => hashed = hashed.raw(typ, v),
        }
    }
    if !has_fpr {
        hashed = hashed.issuer_fpr(&primary.fpr);
    }
    let mut unhashed = Subpackets::new();
    let mut has_id = false;
    for (typ, v) in split_subpackets(old_unhashed)? {
        has_id |= typ & 0x7F == 16;
        unhashed = unhashed.raw(typ, v);
    }
    if !has_id {
        let mut id = [0u8; 8];
        id.copy_from_slice(&primary.fpr[12..]);
        unhashed = unhashed.issuer_key_id(&id);
    }
    sign(signer, sig_type, hash, &hashed, &unhashed, data)
}

/// Sign the new self-certifications and bindings for an expiry change.
fn resign(
    public: &PublicCert,
    signer: &mut dyn Signer,
    primary_fpr: [u8; 20],
    new: Expiry,
    now: u32,
) -> Result<NewSigs, Error> {
    let primary = &public.primary;
    if primary.fpr != primary_fpr || signer.algo_id() != primary.algo {
        return Err(Error::Refused(
            "The signing key is not this public key's primary key.",
        ));
    }
    let old = crate::read::self_sigs(public)?;
    let end = new.end_time(now).map_err(Error::Crypto)?;
    // Strictly newer than every signature already there, so it wins.
    let t = now.max(
        old.newest
            .checked_add(1)
            .ok_or(Error::Malformed("bad signature time"))?,
    );
    let secs = |created: u32| -> Result<Option<u32>, Error> {
        end.map(|e| {
            e.checked_sub(created)
                .filter(|&s| s > 0)
                .ok_or_else(|| Error::Crypto("That date is in the past.".into()))
        })
        .transpose()
    };
    let hash = hash_for_public(primary);
    let pkey = signed_key(&primary.body);

    let uid_packets = public
        .packets
        .iter()
        .filter(|(tag, _)| *tag == Tag::USER_ID)
        .map(|(_, body)| body);
    let mut uids = Vec::with_capacity(old.uids.len());
    for (uid, old_sig) in uid_packets.zip(&old.uids) {
        uids.push(match old_sig {
            Some(old_sig) => {
                let mut data = pkey.clone();
                data.extend(signed_uid(uid));
                let when = (t, secs(primary.created)?);
                let sig = resign_like(
                    signer,
                    old_sig,
                    SigType::PositiveCert,
                    hash,
                    primary,
                    when,
                    &data,
                )?;
                Some(sig)
            }
            None => None,
        });
    }
    if uids.iter().all(Option::is_none) {
        return Err(Error::Malformed("no user id with a self-signature"));
    }
    let mut subkeys = Vec::with_capacity(old.subkeys.len());
    for (sub, old_sig) in public.subkeys.iter().zip(&old.subkeys) {
        subkeys.push(match old_sig {
            Some(old_sig) => {
                let mut data = pkey.clone();
                data.extend(signed_key(&sub.body));
                let when = (t, secs(sub.created)?);
                let sig = resign_like(
                    signer,
                    old_sig,
                    SigType::SubkeyBinding,
                    hash,
                    primary,
                    when,
                    &data,
                )?;
                Some(sig)
            }
            None => None,
        });
    }
    Ok(NewSigs { uids, subkeys })
}

/// `packets` with each new signature placed after the last signature of
/// its user ID or subkey.
fn with_new_sigs(packets: &[(u8, Vec<u8>)], new: &NewSigs) -> Vec<u8> {
    let mut out = Vec::new();
    let mut pending: Option<&[u8]> = None;
    let (mut ui, mut si) = (0, 0);
    for (tag, body) in packets {
        if *tag != Tag::SIGNATURE {
            if let Some(sig) = pending.take() {
                write_packet(&mut out, Tag::SIGNATURE, sig);
            }
            pending = match *tag {
                Tag::USER_ID => {
                    ui += 1;
                    new.uids.get(ui - 1).and_then(Option::as_deref)
                }
                Tag::PUBLIC_SUBKEY | Tag::SECRET_SUBKEY => {
                    si += 1;
                    new.subkeys.get(si - 1).and_then(Option::as_deref)
                }
                _ => None,
            };
        }
        write_packet(&mut out, *tag, body);
    }
    if let Some(sig) = pending {
        write_packet(&mut out, Tag::SIGNATURE, sig);
    }
    out
}

/// Give a key set a new expiry date: keeps every packet of `public` and
/// adds, signed by `signer` (the primary key `primary_fpr`, on the host or
/// on a card), a new self-certification per user ID and a new binding per
/// subkey. Each keeps the subpackets of the signature it replaces (flags,
/// preferences); only its time (`now`, or one second after the newest
/// signature there) and the key expiry change. [`Expiry::Never`] writes
/// no expiry; whole years count from `now`. Returns the armored public
/// certificate.
pub fn change_expiry(
    public: &PublicCert,
    signer: &mut dyn Signer,
    primary_fpr: [u8; 20],
    new: Expiry,
    now: u32,
) -> Result<String, Error> {
    let sigs = resign(public, signer, primary_fpr, new, now)?;
    Ok(armor::encode(
        Kind::PublicKey,
        &with_new_sigs(&public.packets, &sigs),
    ))
}

/// [`change_expiry`] signed on the host with the primary key of a backup
/// (unlocked with `pass`), the public certificate taken from the backup
/// itself. Returns the new backup and public certificate; the backup's key
/// packets are kept as they are, so the same passphrase still protects
/// them. `secret` is armored or binary; both results are armored.
pub fn change_expiry_in_backup(
    secret: &[u8],
    pass: &[u8],
    new: Expiry,
    now: u32,
) -> Result<(String, String), Error> {
    let public = crate::read::open_public(secret)?;
    change_expiry_with_backup(&public, secret, pass, new, now)
}

/// [`change_expiry`] on `public` (the user's own public key file, with
/// everything it has collected: other people's certifications, user IDs
/// added later, revocations), signed on the host with the primary key of
/// the backup `secret` (unlocked with `pass`). Every packet of `public` is
/// kept. The backup gets the same new signatures for the user IDs and
/// subkeys it has; its key packets are kept as they are, so the same
/// passphrase still protects them (and a GnuPG placeholder for a key that
/// lives on a card stays a placeholder). `secret` is armored or binary;
/// both results are armored. Returns (backup, public).
pub fn change_expiry_with_backup(
    public: &PublicCert,
    secret: &[u8],
    pass: &[u8],
    new: Expiry,
    now: u32,
) -> Result<(String, String), Error> {
    let data = secret;
    let loaded = match crate::read::open(data, Some(pass)) {
        Err(Error::NoSecretPart) => return Err(Error::Refused(NO_PRIMARY_SECRET)),
        r => r?,
    };
    if loaded.primary_fpr != public.primary.fpr {
        return Err(Error::Refused(
            "The backup and the public key belong to different keys.",
        ));
    }
    let primary = loaded
        .keys
        .iter()
        .find(|k| loaded.primary_secret && k.fpr == loaded.primary_fpr)
        .ok_or(Error::Refused(NO_PRIMARY_SECRET))?;
    let sigs = resign(
        public,
        &mut HostSigner(&primary.part),
        loaded.primary_fpr,
        new,
        now,
    )?;
    // The backup's user IDs and subkeys, matched to the public file's by
    // content and fingerprint: either file may hold some the other lacks.
    let mine = crate::read::open_public(data)?;
    let public_uids: Vec<&[u8]> = uid_bodies(&public.packets);
    let for_backup = NewSigs {
        uids: uid_bodies(&mine.packets)
            .into_iter()
            .map(|u| {
                public_uids
                    .iter()
                    .position(|p| *p == u)
                    .and_then(|i| sigs.uids.get(i).cloned().flatten())
            })
            .collect(),
        subkeys: mine
            .subkeys
            .iter()
            .map(|k| {
                public
                    .subkeys
                    .iter()
                    .position(|p| p.fpr == k.fpr)
                    .and_then(|i| sigs.subkeys.get(i).cloned().flatten())
            })
            .collect(),
    };
    let secret = crate::read::key_packets(data)?;
    Ok((
        armor::encode(Kind::PrivateKey, &with_new_sigs(&secret, &for_backup)),
        armor::encode(Kind::PublicKey, &with_new_sigs(&public.packets, &sigs)),
    ))
}

fn uid_bodies(packets: &[(u8, Vec<u8>)]) -> Vec<&[u8]> {
    packets
        .iter()
        .filter(|(tag, _)| *tag == Tag::USER_ID)
        .map(|(_, body)| body.as_slice())
        .collect()
}

/// The last day (UTC) the key set works, as its newest self-signature
/// says, or `None` when it never expires. A key made with
/// [`Expiry::Date`] shows that date again.
#[must_use]
pub fn current_expiry(public: &PublicCert) -> Option<(i32, u8, u8)> {
    let secs = crate::read::self_sigs(public).ok()?.expiry?;
    let end = i64::from(public.primary.created) + i64::from(secs);
    Some(civil_from_days((end - 1).div_euclid(DAY)))
}

/// Re-read a just-written backup with its passphrase and check that it
/// holds `expect`'s three keys in their slots.
pub fn verify_backup(secret_armor: &str, pass: &[u8], expect: &KeySet) -> Result<(), Error> {
    let got = crate::read::open(secret_armor.as_bytes(), Some(pass))?;
    let slots = [Slot::Sign, Slot::Decrypt, Slot::Auth];
    let all_there = got.keys.len() == 3
        && slots.iter().zip(&expect.parts).all(|(slot, part)| {
            let fpr = part.fingerprint();
            got.keys
                .iter()
                .any(|k| k.slot == Some(*slot) && k.fpr == fpr)
        });
    if all_there {
        Ok(())
    } else {
        Err(Error::Malformed(
            "the backup does not hold the keys just made",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::parse_packets;

    fn ts(y: i32, m: u8, d: u8) -> u32 {
        (days_from_civil(y, m, d) * DAY) as u32
    }

    #[test]
    fn civil_round_trip() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        for z in [-1000, 0, 11_016, 19_000, 40_000] {
            let (y, m, d) = civil_from_days(z);
            assert_eq!(days_from_civil(y, m, d), z);
        }
    }

    #[test]
    fn parse_table() {
        assert_eq!(Expiry::parse("never"), Ok(Expiry::Never));
        assert_eq!(Expiry::parse("3y"), Ok(Expiry::Years(3)));
        assert_eq!(Expiry::parse("1y"), Ok(Expiry::Years(1)));
        assert!(Expiry::parse("4y").is_err());
        assert!(Expiry::parse("2029-02-29").is_err());
        assert_eq!(
            Expiry::parse("2028-02-29"),
            Ok(Expiry::Date {
                y: 2028,
                m: 2,
                d: 29
            })
        );
        assert!(Expiry::parse("2029-13-01").is_err());
        assert!(Expiry::parse("soon").is_err());
        // One wording, shared with the GUI's date field.
        for (typed, msg) in [
            ("2027-2-28", "Enter the date as YYYY-MM-DD."),
            ("+202-01-01", "Enter the date as YYYY-MM-DD."),
            ("2027/02/28", "Enter the date as YYYY-MM-DD."),
            ("2027-02-29", "That date does not exist."),
            ("2029-13-01", "That date does not exist."),
            ("2029-01-00", "That date does not exist."),
            ("2106-01-01", "Pick a date before 2106."),
            ("1969-12-31", "That date is in the past."),
        ] {
            assert_eq!(Expiry::parse_date(typed), Err(msg), "{typed}");
            assert_eq!(Expiry::parse(typed), Err(msg.to_string()), "{typed}");
        }
        assert!(Expiry::parse_date("2105-12-31").is_ok());
        assert_eq!(Expiry::default(), Expiry::Years(3));
    }

    #[test]
    fn seconds_after_rules() {
        let created = ts(2024, 2, 29) + 3600;
        let want = ts(2025, 2, 28) + 43_200;
        assert_eq!(
            Expiry::Years(1).seconds_after(created),
            Ok(Some(want - created))
        );
        assert_eq!(Expiry::Never.seconds_after(created), Ok(None));
        let on = Expiry::Date {
            y: 2024,
            m: 3,
            d: 1,
        };
        assert_eq!(
            on.seconds_after(created),
            Ok(Some(ts(2024, 3, 1) + 43_200 - created))
        );
        let past = Expiry::Date {
            y: 2024,
            m: 2,
            d: 28,
        };
        assert_eq!(
            past.seconds_after(created),
            Err("That date is in the past.".to_string())
        );
        // A key that expires today is refused: midday may already be gone.
        let today = Expiry::Date {
            y: 2024,
            m: 2,
            d: 29,
        };
        assert_eq!(
            today.seconds_after(created),
            Err("Pick a date after today.".to_string())
        );
    }

    #[test]
    fn identity_forms() {
        let id = |n: &str, e: &str| Identity {
            name: n.into(),
            email: e.into(),
        };
        assert_eq!(id(" Ada ", " a@x.org ").user_id().unwrap(), "Ada <a@x.org>");
        assert_eq!(id("Ada", "").user_id().unwrap(), "Ada");
        assert!(id(" ", "").user_id().is_err());
    }

    #[test]
    fn export_has_the_expected_packet_layout() {
        let now = ts(2026, 10, 16);
        let id = Identity {
            name: "Ada".into(),
            email: "ada@example.org".into(),
        };
        let set = create(KeyType::Cv25519, &id, Expiry::default(), now).unwrap();
        let out = export(&set, b"pw", now).unwrap();
        let tags = |text: &str, kind: Kind| {
            let (k, bin) = armor::decode(text).unwrap();
            assert_eq!(k, kind);
            parse_packets(&bin)
                .unwrap()
                .iter()
                .map(|p| p.tag)
                .collect::<Vec<_>>()
        };
        assert_eq!(tags(&out.secret, Kind::PrivateKey), [5, 13, 2, 7, 2, 7, 2]);
        assert_eq!(tags(&out.public, Kind::PublicKey), [6, 13, 2, 14, 2, 14, 2]);
        assert_eq!(tags(&out.revocation, Kind::PublicKey), [2]);
        assert!(out
            .revocation
            .contains("Comment: This is a revocation certificate\n\n"));
    }

    fn made(t: KeyType, e: Expiry, now: u32) -> (KeySet, Outputs) {
        let id = Identity {
            name: "Ada".into(),
            email: "ada@example.org".into(),
        };
        let set = create(t, &id, e, now).unwrap();
        let out = export(&set, b"pw", now).unwrap();
        (set, out)
    }

    /// (type, expiry) of every self-signature, in file order, with the
    /// packet tag that precedes its run.
    fn sig_expiries(armored: &str) -> Vec<(u8, u8, Option<u32>, u32)> {
        let (_, bin) = armor::decode(armored).unwrap();
        let mut owner = 0;
        let mut out = Vec::new();
        for p in parse_packets(&bin).unwrap() {
            if p.tag != Tag::SIGNATURE {
                owner = p.tag;
                continue;
            }
            let (typ, hashed, _) = sig_areas(p.body).unwrap();
            let mut exp = None;
            let mut created = 0;
            for (t, v) in crate::sig::split_subpackets(hashed).unwrap() {
                match t & 0x7F {
                    9 => exp = Some(u32::from_be_bytes(v.try_into().unwrap())),
                    2 => created = u32::from_be_bytes(v.try_into().unwrap()),
                    _ => {}
                }
            }
            out.push((owner, typ, exp, created));
        }
        out
    }

    #[test]
    fn change_expiry_on_the_host_appends_one_signature_per_component() {
        let now = ts(2026, 10, 16) + 500;
        let (set, out) = made(KeyType::NistP256, Expiry::Years(1), now);
        let public = crate::read::open_public(out.public.as_bytes()).unwrap();
        assert_eq!(current_expiry(&public), Some((2027, 10, 16)));
        let later = now + 3600;
        let fpr = set.parts[0].fingerprint();
        let five = change_expiry(
            &public,
            &mut HostSigner(&set.parts[0]),
            fpr,
            Expiry::Years(5),
            later,
        )
        .unwrap();
        let end = ts(2031, 10, 16) + 43_200;
        let want = Some(end - now);
        let sigs = sig_expiries(&five);
        // Every old signature kept; a new one right after each.
        assert_eq!(
            sigs.iter().map(|s| (s.0, s.1)).collect::<Vec<_>>(),
            [
                (13, 0x13),
                (13, 0x13),
                (14, 0x18),
                (14, 0x18),
                (14, 0x18),
                (14, 0x18)
            ]
        );
        for pair in sigs.chunks(2) {
            assert_eq!(pair[1].2, want);
            assert_eq!(pair[1].3, later);
        }
        let reread = crate::read::open_public(five.as_bytes()).unwrap();
        assert_eq!(current_expiry(&reread), Some((2031, 10, 16)));
        assert_eq!(reread.primary, public.primary);
        assert_eq!(reread.subkeys, public.subkeys);

        // Never: no key-expiration subpacket; a same-second change still
        // lands after the newest signature.
        let never = change_expiry(
            &reread,
            &mut HostSigner(&set.parts[0]),
            fpr,
            Expiry::Never,
            later,
        )
        .unwrap();
        let sigs = sig_expiries(&never);
        assert_eq!(sigs.len(), 9);
        for i in [2, 5, 8] {
            assert_eq!(sigs[i].2, None);
            assert_eq!(sigs[i].3, later + 1);
        }
        assert_eq!(
            current_expiry(&crate::read::open_public(never.as_bytes()).unwrap()),
            None
        );
    }

    #[test]
    fn change_expiry_keeps_flags_and_preferences() {
        let now = ts(2026, 10, 16);
        let (set, out) = made(KeyType::Cv25519, Expiry::default(), now);
        let public = crate::read::open_public(out.public.as_bytes()).unwrap();
        let on = Expiry::Date {
            y: 2030,
            m: 1,
            d: 31,
        };
        let new = change_expiry(
            &public,
            &mut HostSigner(&set.parts[0]),
            set.parts[0].fingerprint(),
            on,
            now + 10,
        )
        .unwrap();
        assert_eq!(
            current_expiry(&crate::read::open_public(new.as_bytes()).unwrap()),
            Some((2030, 1, 31))
        );
        let (_, bin) = armor::decode(&new).unwrap();
        let pk = parse_packets(&bin).unwrap();
        let strip = |body: &[u8]| {
            let (_, h, _) = sig_areas(body).unwrap();
            crate::sig::split_subpackets(h)
                .unwrap()
                .into_iter()
                .filter(|(t, _)| !matches!(t & 0x7F, 2 | 9))
                .map(|(t, v)| (t, v.to_vec()))
                .collect::<Vec<_>>()
        };
        // Old and new self-cert / bindings differ only in time and expiry.
        for (old, new) in [(2, 3), (5, 6), (8, 9)] {
            assert_eq!(strip(pk[old].body), strip(pk[new].body), "{old}");
        }
    }

    #[test]
    fn change_expiry_refuses_a_past_date_and_a_foreign_signer() {
        let now = ts(2026, 10, 16);
        let (set, out) = made(KeyType::Cv25519, Expiry::default(), now);
        let (other, _) = made(KeyType::Cv25519, Expiry::default(), now);
        let public = crate::read::open_public(out.public.as_bytes()).unwrap();
        let fpr = set.parts[0].fingerprint();
        let past = Expiry::Date {
            y: 2026,
            m: 10,
            d: 15,
        };
        assert!(change_expiry(&public, &mut HostSigner(&set.parts[0]), fpr, past, now).is_err());
        assert!(change_expiry(
            &public,
            &mut HostSigner(&set.parts[0]),
            other.parts[0].fingerprint(),
            Expiry::Never,
            now
        )
        .is_err());
        // An RSA signer for an EdDSA primary.
        let rsa = generate(KeyType::Rsa2048, now).unwrap();
        assert!(change_expiry(&public, &mut HostSigner(&rsa[0]), fpr, Expiry::Never, now).is_err());
    }

    #[test]
    fn change_expiry_in_backup_rewrites_both_files() {
        let now = ts(2026, 10, 16);
        let (set, out) = made(KeyType::Cv25519, Expiry::Years(1), now);
        let (secret, public) =
            change_expiry_in_backup(out.secret.as_bytes(), b"pw", Expiry::Years(2), now + 5)
                .unwrap();
        let want = Some((2028, 10, 16));
        assert_eq!(
            current_expiry(&crate::read::open_public(public.as_bytes()).unwrap()),
            want
        );
        assert_eq!(
            current_expiry(&crate::read::open_public(secret.as_bytes()).unwrap()),
            want
        );
        // Same passphrase, same keys, new expiry.
        let got = crate::read::open(secret.as_bytes(), Some(b"pw")).unwrap();
        assert_eq!(got.expiry, Some(ts(2028, 10, 16) + 43_200 - now));
        verify_backup(&secret, b"pw", &set).unwrap();
        assert!(matches!(
            change_expiry_in_backup(out.secret.as_bytes(), b"nope", Expiry::Never, now + 5),
            Err(Error::WrongPassphrase)
        ));
    }

    /// A public file that collected more than the backup has (another
    /// person's certification, a user ID added later) keeps all of it, and
    /// both files get the new expiry.
    #[test]
    fn change_expiry_with_backup_keeps_what_only_the_public_file_has() {
        let now = ts(2026, 10, 16);
        let (set, out) = made(KeyType::NistP256, Expiry::Years(1), now);
        let primary = &set.parts[0];
        let other = generate(KeyType::Cv25519, now).unwrap();
        let (_, bin) = armor::decode(&out.public).unwrap();
        let packets = parse_packets(&bin).unwrap();
        let pkey = signed_key(&primary.public_body());
        // Someone else's certification of the first user ID.
        let mut data = pkey.clone();
        data.extend(signed_uid(&set.user_id));
        let third = sign(
            &mut HostSigner(&other[0]),
            SigType::PositiveCert,
            hash_for(&other[0]),
            &Subpackets::new()
                .created(now + 1)
                .issuer_fpr(&other[0].fingerprint()),
            &Subpackets::new(),
            &data,
        )
        .unwrap();
        // A second user ID, self-certified, only in the public file.
        let uid2 = "Ada Two <two@example.org>";
        let mut data = pkey.clone();
        data.extend(signed_uid(uid2));
        let uid2_sig = sign(
            &mut HostSigner(primary),
            SigType::PositiveCert,
            hash_for(primary),
            &Subpackets::new()
                .created(now + 1)
                .key_expiry(set.expiry)
                .key_flags(FLAGS_PRIMARY)
                .issuer_fpr(&primary.fingerprint()),
            &Subpackets::new(),
            &data,
        )
        .unwrap();
        let mut grown = Vec::new();
        for (i, p) in packets.iter().enumerate() {
            write_packet(&mut grown, p.tag, p.body);
            if i == 2 {
                // after the user ID's self-certification
                write_packet(&mut grown, Tag::SIGNATURE, &third);
                write_packet(&mut grown, Tag::USER_ID, uid2.as_bytes());
                write_packet(&mut grown, Tag::SIGNATURE, &uid2_sig);
            }
        }
        assert_eq!(packets[1].tag, Tag::USER_ID);
        let grown = armor::encode(Kind::PublicKey, &grown);
        let public = crate::read::open_public(grown.as_bytes()).unwrap();
        let (secret, new_public) = change_expiry_with_backup(
            &public,
            out.secret.as_bytes(),
            b"pw",
            Expiry::Years(2),
            now + 5,
        )
        .unwrap();
        let (_, nb) = armor::decode(&new_public).unwrap();
        let new_packets = parse_packets(&nb).unwrap();
        assert!(new_packets.iter().any(|p| p.body == third.as_slice()));
        assert!(new_packets.iter().any(|p| p.body == uid2.as_bytes()));
        // Every old packet is still there, plus one signature per user ID
        // and subkey.
        for p in &packets {
            assert!(new_packets
                .iter()
                .any(|q| q.tag == p.tag && q.body == p.body));
        }
        assert_eq!(new_packets.len(), packets.len() + 3 + 4);
        let want = Some((2028, 10, 16));
        let reread = crate::read::open_public(new_public.as_bytes()).unwrap();
        assert_eq!(reread.user_ids.len(), 2);
        assert_eq!(current_expiry(&reread), want);
        // The backup gets the new signatures for what it has, nothing else.
        let (_, sb) = armor::decode(&secret).unwrap();
        let secret_packets = parse_packets(&sb).unwrap();
        assert!(!secret_packets.iter().any(|p| p.body == uid2.as_bytes()));
        assert_eq!(
            current_expiry(&crate::read::open_public(secret.as_bytes()).unwrap()),
            want
        );
        verify_backup(&secret, b"pw", &set).unwrap();
        // A backup of another key is refused plainly.
        let (_, other_out) = made(KeyType::NistP256, Expiry::Years(1), now);
        let err = change_expiry_with_backup(
            &public,
            other_out.secret.as_bytes(),
            b"pw",
            Expiry::Never,
            now,
        )
        .err()
        .unwrap();
        assert_eq!(
            err.to_string(),
            "The backup and the public key belong to different keys."
        );
    }

    #[test]
    fn change_expiry_in_backup_needs_the_primary_secret() {
        let now = ts(2026, 10, 16);
        let (set, out) = made(KeyType::Cv25519, Expiry::Years(1), now);
        // Strip the primary's secret the way --export-secret-subkeys does.
        let (_, bin) = armor::decode(&out.secret).unwrap();
        let mut stub = Vec::new();
        for (i, p) in parse_packets(&bin).unwrap().iter().enumerate() {
            let mut body = p.body.to_vec();
            if i == 0 {
                body.truncate(set.parts[0].public_body().len());
                body.extend_from_slice(&[254, 0, 101, 0, b'G', b'N', b'U', 1]);
            }
            write_packet(&mut stub, p.tag, &body);
        }
        // A binary (non-armored) backup works as well as an armored one;
        // the results are armored.
        let (secret, public) =
            change_expiry_in_backup(&bin, b"pw", Expiry::Never, now + 5).unwrap();
        assert!(secret.starts_with("-----BEGIN PGP PRIVATE KEY BLOCK-----"));
        assert!(public.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        let stub = armor::encode(Kind::PrivateKey, &stub);
        let err = change_expiry_in_backup(stub.as_bytes(), b"pw", Expiry::Never, now + 5)
            .err()
            .unwrap();
        assert_eq!(
            err.to_string(),
            "This backup doesn't contain the main key's secret part, so it can't sign a new date. Use the card instead."
        );
    }

    #[test]
    fn current_expiry_round_trips_the_chosen_date() {
        let now = ts(2026, 10, 16) + 43_210;
        for (y, m, d) in [(2026, 10, 17), (2028, 2, 29), (2031, 12, 31)] {
            let (_, out) = made(KeyType::Cv25519, Expiry::Date { y, m, d }, now);
            let public = crate::read::open_public(out.public.as_bytes()).unwrap();
            assert_eq!(current_expiry(&public), Some((y, m, d)));
        }
        let (_, out) = made(KeyType::Cv25519, Expiry::Never, now);
        let public = crate::read::open_public(out.public.as_bytes()).unwrap();
        assert_eq!(current_expiry(&public), None);
    }

    #[test]
    fn verify_backup_accepts_its_own_keys_only() {
        let now = 1_792_108_800;
        let id = Identity {
            name: "Ada".into(),
            email: String::new(),
        };
        let set = create(KeyType::Cv25519, &id, Expiry::default(), now).unwrap();
        let other = create(KeyType::Cv25519, &id, Expiry::default(), now).unwrap();
        let out = export(&set, b"pw", now).unwrap();
        verify_backup(&out.secret, b"pw", &set).unwrap();
        assert!(verify_backup(&out.secret, b"pw", &other).is_err());
        assert!(matches!(
            verify_backup(&out.secret, b"nope", &set),
            Err(Error::WrongPassphrase)
        ));
    }
}
