//! Vault data model and its JSON (format 2 written, format 1 read).

use crate::error::VaultError;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// One password entry. Every field is wiped when it is dropped: usernames
/// and notes (where people keep recovery codes) are as private as the
/// password.
#[derive(Clone, PartialEq, Eq)]
pub struct Entry {
    pub id: String,
    pub title: String,
    pub username: String,
    pub password: Zeroizing<String>,
    pub url: String,
    pub notes: String,
    /// Last modified, minutes since the Unix epoch.
    pub modified_minutes: i64,
}

impl Zeroize for Entry {
    fn zeroize(&mut self) {
        self.id.zeroize();
        self.title.zeroize();
        self.username.zeroize();
        self.password.zeroize();
        self.url.zeroize();
        self.notes.zeroize();
        self.modified_minutes.zeroize();
    }
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Entry {}

// Debug never prints the password.
impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("id", &self.id)
            .field("title", &self.title)
            .field("password", &"<hidden>")
            .finish_non_exhaustive()
    }
}

/// A whole vault.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Vault {
    pub entries: Vec<Entry>,
}

/// base64url without padding.
fn b64url(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(b.len() * 4 / 3 + 2);
    for c in b.chunks(3) {
        let n = u32::from(c[0]) << 16
            | u32::from(*c.get(1).unwrap_or(&0)) << 8
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..=c.len() {
            out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

/// A new entry id: 48 random bits as 8 base64url characters.
pub fn new_id() -> String {
    let mut b = [0u8; 6];
    if getrandom::fill(&mut b).is_err() {
        // No OS randomness: fall back to the clock so ids stay distinct.
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        b.copy_from_slice(&t.to_le_bytes()[..6]);
    }
    b64url(&b)
}

/// The first 6 bytes of a 36-character UUID string, or `None` if `id` is not one.
fn uuid_prefix(id: &str) -> Option<[u8; 6]> {
    let s = id.as_bytes();
    if s.len() != 36 {
        return None;
    }
    let mut bytes = [0u8; 16];
    let mut n = 0;
    let mut hi: Option<u8> = None;
    for (i, &c) in s.iter().enumerate() {
        if matches!(i, 8 | 13 | 18 | 23) {
            if c != b'-' {
                return None;
            }
            continue;
        }
        let d = (c as char).to_digit(16)? as u8;
        match hi.take() {
            None => hi = Some(d),
            Some(h) => {
                bytes[n] = h << 4 | d;
                n += 1;
            }
        }
    }
    let mut out = [0u8; 6];
    out.copy_from_slice(&bytes[..6]);
    Some(out)
}

/// Format-1 ids were UUIDs; they are shortened to their first 6 bytes as 8
/// base64url characters so an entry keeps its identity across formats.
pub fn canon_id(id: &str) -> String {
    match uuid_prefix(id) {
        Some(p) => b64url(&p),
        None => id.to_string(),
    }
}

mod wire {
    use serde::{Deserialize, Serialize};
    use zeroize::Zeroize;

    pub const FORMAT: u32 = 2;

    fn empty(s: &str) -> bool {
        s.is_empty()
    }

    /// Format 2 entry. Field order is the output key order.
    #[derive(Serialize, Deserialize, Default)]
    pub struct E {
        pub i: String,
        #[serde(default, skip_serializing_if = "empty")]
        pub t: String,
        #[serde(default, skip_serializing_if = "empty")]
        pub u: String,
        #[serde(default, skip_serializing_if = "empty")]
        pub p: String,
        #[serde(default, skip_serializing_if = "empty")]
        pub l: String,
        #[serde(default, skip_serializing_if = "empty")]
        pub n: String,
        #[serde(default)]
        pub m: i64,
    }

    impl Drop for E {
        fn drop(&mut self) {
            self.i.zeroize();
            self.t.zeroize();
            self.u.zeroize();
            self.p.zeroize();
            self.l.zeroize();
            self.n.zeroize();
        }
    }

    #[derive(Serialize, Deserialize)]
    pub struct Vault {
        pub v: u32,
        pub e: Vec<E>,
    }

    /// Format 1 entry; unknown fields are ignored.
    #[derive(Deserialize, Default)]
    pub struct E1 {
        pub id: String,
        #[serde(default)]
        pub title: String,
        #[serde(default)]
        pub username: String,
        #[serde(default)]
        pub password: String,
        #[serde(default)]
        pub url: String,
        #[serde(default)]
        pub notes: String,
        #[serde(default)]
        pub modified: i64,
    }

    impl Drop for E1 {
        fn drop(&mut self) {
            self.id.zeroize();
            self.title.zeroize();
            self.username.zeroize();
            self.password.zeroize();
            self.url.zeroize();
            self.notes.zeroize();
        }
    }

    #[derive(Deserialize)]
    pub struct Vault1 {
        pub entries: Vec<E1>,
    }

    /// Reads only the format marker, copying no secrets.
    #[derive(Deserialize)]
    pub struct Probe {
        pub v: Option<serde_json::Value>,
    }
}

/// Format 2 JSON, as written to the key and to backups. The result holds
/// secrets and is wiped on drop.
pub fn to_json(v: &Vault) -> Zeroizing<Vec<u8>> {
    let w = wire::Vault {
        v: wire::FORMAT,
        e: v.entries
            .iter()
            .map(|x| wire::E {
                i: x.id.clone(),
                t: x.title.clone(),
                u: x.username.clone(),
                p: x.password.to_string(),
                l: x.url.clone(),
                n: x.notes.clone(),
                m: x.modified_minutes,
            })
            .collect(),
    };
    // Serializing plain strings and integers cannot fail.
    Zeroizing::new(serde_json::to_vec(&w).unwrap_or_default())
}

/// Parse format 2 (has a `"v"` key) or format 1 (plain struct, seconds).
pub fn from_json(b: &[u8]) -> Result<Vault, VaultError> {
    let probe: wire::Probe =
        serde_json::from_slice(b).map_err(|_| VaultError::Corrupt("not valid vault JSON"))?;
    match probe.v {
        Some(v) => {
            let n = v
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or(VaultError::Corrupt("bad format number"))?;
            if n > wire::FORMAT {
                return Err(VaultError::NewerFormat(n));
            }
            let mut w: wire::Vault = serde_json::from_slice(b)
                .map_err(|_| VaultError::Corrupt("not valid vault JSON"))?;
            let entries =
                w.e.iter_mut()
                    .map(|x| Entry {
                        id: std::mem::take(&mut x.i),
                        title: std::mem::take(&mut x.t),
                        username: std::mem::take(&mut x.u),
                        password: Zeroizing::new(std::mem::take(&mut x.p)),
                        url: std::mem::take(&mut x.l),
                        notes: std::mem::take(&mut x.n),
                        modified_minutes: x.m,
                    })
                    .collect();
            Ok(Vault { entries })
        }
        None => {
            let mut w: wire::Vault1 = serde_json::from_slice(b)
                .map_err(|_| VaultError::Corrupt("not valid vault JSON"))?;
            let entries = w
                .entries
                .iter_mut()
                .map(|x| Entry {
                    id: canon_id(&x.id),
                    title: std::mem::take(&mut x.title),
                    username: std::mem::take(&mut x.username),
                    password: Zeroizing::new(std::mem::take(&mut x.password)),
                    url: std::mem::take(&mut x.url),
                    notes: std::mem::take(&mut x.notes),
                    modified_minutes: x.modified.div_euclid(60),
                })
                .collect();
            Ok(Vault { entries })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_vectors::{SAMPLE_ENTRIES, SAMPLE_JSON_V2};

    fn entry(url: &str, notes: &str) -> Entry {
        Entry {
            id: "AAAAAAAA".into(),
            title: "Mail".into(),
            username: "emin".into(),
            password: Zeroizing::new("pw".into()),
            url: url.into(),
            notes: notes.into(),
            modified_minutes: 28333343,
        }
    }

    #[test]
    fn json_roundtrip_omits_empty_fields() {
        let v = Vault {
            entries: vec![entry("", "")],
        };
        let j = to_json(&v);
        let s = std::str::from_utf8(&j).unwrap();
        assert!(!s.contains("\"l\"") && !s.contains("\"n\""), "{s}");
        assert_eq!(from_json(&j).unwrap(), v);
    }

    #[test]
    fn opens_format1_and_unknown_fields() {
        let uuid = "6f1f0c3e-6a2b-4c7e-9a3b-0f2c1d4e5a6b";
        let j = format!(
            r#"{{"version":1,"entries":[{{"id":"{uuid}","title":"GitHub","username":"emin","password":"pw","url":"","notes":"","created":1700000000,"modified":1700000600,"extra":true}}],"modified":1700000600}}"#
        );
        let v = from_json(j.as_bytes()).unwrap();
        assert_eq!(v.entries.len(), 1);
        assert_eq!(v.entries[0].id, canon_id(uuid));
        assert_eq!(v.entries[0].id.len(), 8);
        assert_eq!(v.entries[0].modified_minutes, 28333343);
        assert_eq!(v.entries[0].password.as_str(), "pw");
    }

    #[test]
    fn refuses_newer_format() {
        assert_eq!(
            from_json(br#"{"v":3,"e":[]}"#).err(),
            Some(VaultError::NewerFormat(3))
        );
    }

    #[test]
    fn minutes_roundtrip() {
        let v = Vault {
            entries: vec![entry("u", "n")],
        };
        assert_eq!(
            from_json(&to_json(&v)).unwrap().entries[0].modified_minutes,
            28333343
        );
    }

    #[test]
    fn sample_vector_parses_and_reserializes_exactly() {
        let v = from_json(SAMPLE_JSON_V2.as_bytes()).unwrap();
        assert_eq!(v.entries.len(), SAMPLE_ENTRIES.len());
        for (e, s) in v.entries.iter().zip(SAMPLE_ENTRIES.iter()) {
            assert_eq!(
                (
                    e.id.as_str(),
                    e.title.as_str(),
                    e.username.as_str(),
                    e.password.as_str(),
                    e.url.as_str(),
                    e.notes.as_str(),
                    e.modified_minutes
                ),
                (s.0, s.1, s.2, s.3, s.4, s.5, s.6.div_euclid(60))
            );
        }
        assert_eq!(&**to_json(&v), SAMPLE_JSON_V2.as_bytes());
    }

    #[test]
    fn ids() {
        assert_eq!(new_id().len(), 8);
        assert_ne!(new_id(), new_id());
        assert_eq!(canon_id("plain"), "plain");
        assert_eq!(
            canon_id("6f1f0c3e-6a2b-4c7e-9a3b-0f2c1d4e5a6g"),
            "6f1f0c3e-6a2b-4c7e-9a3b-0f2c1d4e5a6g"
        );
        // 6f 1f 0c 3e 6a 2b -> base64url
        assert_eq!(canon_id("6f1f0c3e-6a2b-4c7e-9a3b-0f2c1d4e5a6b"), "bx8MPmor");
    }

    #[test]
    fn zeroize_clears_every_text_field() {
        use zeroize::Zeroize;
        let mut e = entry("https://mail.example", "recovery codes");
        e.zeroize();
        for (name, f) in [
            ("id", e.id.as_str()),
            ("title", e.title.as_str()),
            ("username", e.username.as_str()),
            ("password", e.password.as_str()),
            ("url", e.url.as_str()),
            ("notes", e.notes.as_str()),
        ] {
            assert!(f.is_empty(), "{name} not wiped");
        }
        assert_eq!(e.modified_minutes, 0);
    }

    #[test]
    fn garbage_is_corrupt_not_panic() {
        assert!(matches!(from_json(b"nope"), Err(VaultError::Corrupt(_))));
        assert!(matches!(from_json(b"[]"), Err(VaultError::Corrupt(_))));
        assert!(matches!(
            from_json(br#"{"v":"x"}"#),
            Err(VaultError::Corrupt(_))
        ));
    }
}
