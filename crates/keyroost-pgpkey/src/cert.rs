//! Assemble a generated key set into a GnuPG-compatible backup, a public
//! certificate and a revocation certificate.

use crate::armor::{self, Kind};
use crate::keys::{generate, KeyPart, KeyType};
use crate::packet::{write_packet, Tag};
use crate::read::Slot;
use crate::s2k;
use crate::sig::{
    hash_for, sign, signed_key, signed_uid, HostSigner, SigType, Subpackets, FEATURES, FLAGS_AUTH,
    FLAGS_DECRYPT, FLAGS_PRIMARY, KEYSERVER_PREFS, PREF_COMPRESSION, PREF_HASH, PREF_SYM,
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

/// When a key set stops being valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expiry {
    Never,
    /// Calendar years after the creation date (1, 2, 3 or 5).
    Years(u8),
    /// Valid through the whole of this day (UTC).
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
        let bad = || "Enter the date as YYYY-MM-DD.".to_string();
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 3 || parts[0].len() != 4 || parts[1].len() != 2 || parts[2].len() != 2 {
            return Err(bad());
        }
        let y: i32 = parts[0].parse().map_err(|_| bad())?;
        let m: u8 = parts[1].parse().map_err(|_| bad())?;
        let d: u8 = parts[2].parse().map_err(|_| bad())?;
        if !(1970..=2105).contains(&y) || !(1..=12).contains(&m) || d == 0 {
            return Err(bad());
        }
        if d > days_in_month(y, m) {
            return Err("That date does not exist.".into());
        }
        Ok(Expiry::Date { y, m, d })
    }

    /// Seconds after `created` at which the key expires, or `None` for
    /// never. Whole-year and date choices both resolve to 00:00:00 UTC of
    /// the day after the target date, so the key works through that day.
    pub fn seconds_after(self, created: u32) -> Result<Option<u32>, String> {
        let (y, m, d) = match self {
            Expiry::Never => return Ok(None),
            Expiry::Years(n) => {
                let (cy, cm, cd) = civil_from_days(i64::from(created) / DAY);
                let y = cy + i32::from(n);
                (y, cm, cd.min(days_in_month(y, cm)))
            }
            Expiry::Date { y, m, d } => (y, m, d),
        };
        let end = (days_from_civil(y, m, d) + 1) * DAY;
        let secs = end - i64::from(created);
        if secs <= 0 {
            return Err("That date is in the past.".into());
        }
        u32::try_from(secs)
            .ok()
            .filter(|_| u32::try_from(end).is_ok())
            .map(Some)
            .ok_or_else(|| "That date is too far in the future.".into())
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

    let secret_body = |part: &KeyPart| {
        let mut b = part.public_body();
        b.extend(s2k::protect(&part.secret_mpis(), pass));
        b
    };

    let mut secret = Vec::new();
    write_packet(&mut secret, Tag::SECRET_KEY, &secret_body(primary));
    write_packet(&mut secret, Tag::USER_ID, set.user_id.as_bytes());
    write_packet(&mut secret, Tag::SIGNATURE, &self_cert);
    write_packet(&mut secret, Tag::SECRET_SUBKEY, &secret_body(&set.parts[1]));
    write_packet(&mut secret, Tag::SIGNATURE, &dec_bind);
    write_packet(&mut secret, Tag::SECRET_SUBKEY, &secret_body(&set.parts[2]));
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
        assert_eq!(Expiry::default(), Expiry::Years(3));
    }

    #[test]
    fn seconds_after_rules() {
        let created = ts(2024, 2, 29) + 3600;
        let want = ts(2025, 2, 28) + 86_400;
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
            Ok(Some(ts(2024, 3, 2) - created))
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
        // Today still works, through the end of today.
        let today = Expiry::Date {
            y: 2024,
            m: 2,
            d: 29,
        };
        assert!(today.seconds_after(created).unwrap().is_some());
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
