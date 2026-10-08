//! Salted per-computer fingerprints: how `keys.json` recognizes a key without
//! storing its serial number.
//!
//! A fingerprint is `"v1:"` followed by the lowercase hex of
//! HMAC-SHA-256(salt, [`FP_DOMAIN`] || canonical serial). The salt is 32
//! random bytes kept in `keys.salt` beside `keys.json` and never leaves this
//! computer, so the same key gets an unrelated fingerprint on every other
//! computer, and a copy of `keys.json` alone reveals no serial: guessing one
//! needs the salt too.
//!
//! The salt file is created owner-only (0600) on Unix. On Windows it lives in
//! `%APPDATA%\keyroost` and inherits that directory's per-user ACL, the same
//! protection `keys.json` has always had there.

use crate::{strip_control_chars, KeyringError};
use keyroost_proto::sha256::Sha256;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::io;
use std::path::Path;

/// The salt's file name, beside `keys.json`.
pub const SALT_FILE: &str = "keys.salt";

/// Domain separation, so these HMACs can never collide with any other use of
/// the same salt.
const FP_DOMAIN: &[u8] = b"keyroost key fingerprint v1\0";

/// The fingerprint text's version prefix.
const FP_PREFIX: &str = "v1:";

/// SHA-256's block size, for HMAC's key padding (RFC 2104).
const BLOCK: usize = 64;

/// This computer's fingerprint salt: 32 random bytes. `Debug` never shows
/// them.
#[derive(Clone, PartialEq, Eq)]
pub struct Salt([u8; 32]);

impl fmt::Debug for Salt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Salt(..)")
    }
}

/// A key's salted fingerprint as stored in `keys.json`: `"v1:"` + 64
/// lowercase hex characters.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Fingerprint(String);

impl Fingerprint {
    /// The stored text, `"v1:…"`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// HMAC-SHA-256 (RFC 2104) over the in-tree SHA-256.
pub(crate) fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut block = [0u8; BLOCK];
    if key.len() > BLOCK {
        block[..32].copy_from_slice(&keyroost_proto::sha256::sha256(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= block[i];
        opad[i] ^= block[i];
    }
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(msg);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner);
    outer.finalize()
}

/// The serial as fingerprinted: control/spoofing characters removed (the same
/// cleaning older `keys.json` files applied before storing a serial, so a
/// converted record matches the live key), then trimmed and lowercased.
pub fn canonical_serial(serial: &str) -> String {
    let mut s = serial.to_string();
    strip_control_chars(&mut s);
    s.trim().to_lowercase()
}

/// The fingerprint of `serial` under `salt`. See the module docs for the
/// formula; the serial is canonicalized first, so case and surrounding
/// whitespace don't matter.
pub fn fingerprint(salt: &Salt, serial: &str) -> Fingerprint {
    let canon = canonical_serial(serial);
    let mut msg = Vec::with_capacity(FP_DOMAIN.len() + canon.len());
    msg.extend_from_slice(FP_DOMAIN);
    msg.extend_from_slice(canon.as_bytes());
    let mac = hmac_sha256(&salt.0, &msg);
    Fingerprint(format!("{FP_PREFIX}{}", hex(&mac)))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    s
}

fn unhex_32(text: &str) -> Option<[u8; 32]> {
    let raw = text.as_bytes();
    if raw.len() != 64 {
        return None;
    }
    let nibble = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut out = [0u8; 32];
    for (i, pair) in raw.chunks_exact(2).enumerate() {
        out[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(out)
}

/// Read `<dir>/keys.salt`. `Ok(None)` when the file is missing; a malformed
/// file is an error and is left exactly as it is.
pub(crate) fn load_salt(dir: &Path) -> Result<Option<Salt>, KeyringError> {
    let text = match fs::read_to_string(dir.join(SALT_FILE)) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) if e.kind() == io::ErrorKind::InvalidData => {
            return Err(KeyringError::MalformedSalt)
        }
        Err(e) => return Err(KeyringError::Io(e)),
    };
    let body = text.strip_suffix('\n').unwrap_or(&text);
    let body = body.strip_suffix('\r').unwrap_or(body);
    unhex_32(body)
        .map(|b| Some(Salt(b)))
        .ok_or(KeyringError::MalformedSalt)
}

/// Create `<dir>/keys.salt` holding `salt` as 64 hex characters and a newline.
/// Never overwrites: an existing file makes this fail with `AlreadyExists`.
/// Owner-only (0600) on Unix; on Windows the file inherits the config
/// directory's per-user ACL.
pub(crate) fn persist_salt(dir: &Path, salt: &Salt) -> Result<(), KeyringError> {
    fs::create_dir_all(dir)?;
    let mut opts = fs::OpenOptions::new();
    // `create_new`: never replace a salt (every stored fingerprint depends on
    // it), and never follow a symlink planted at the path.
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    use std::io::Write;
    let path = dir.join(SALT_FILE);
    let mut f = opts.open(&path)?;
    let written = f
        .write_all(format!("{}\n", hex(&salt.0)).as_bytes())
        .and_then(|()| f.sync_all());
    if let Err(e) = written {
        // A half-written salt would make the next load fail; remove it.
        drop(f);
        let _ = fs::remove_file(&path);
        return Err(KeyringError::Io(e));
    }
    Ok(())
}

/// A fresh salt from the operating system's random source.
pub(crate) fn generate_salt() -> Result<Salt, KeyringError> {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).map_err(|e| {
        KeyringError::Io(io::Error::other(format!(
            "no OS randomness for the keyring salt: {e}"
        )))
    })?;
    Ok(Salt(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn counting_salt() -> Salt {
        let mut b = [0u8; 32];
        for (i, x) in b.iter_mut().enumerate() {
            *x = i as u8;
        }
        Salt(b)
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "keyroost-fp-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn hmac_sha256_rfc4231() {
        // TC1
        assert_eq!(
            hmac_sha256(&[0x0b; 20], b"Hi There").to_vec(),
            unhex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        );
        // TC2
        assert_eq!(
            hmac_sha256(b"Jefe", b"what do ya want for nothing?").to_vec(),
            unhex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
        // TC6: a key longer than the block is hashed first.
        assert_eq!(
            hmac_sha256(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )
            .to_vec(),
            unhex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
        );
    }

    #[test]
    fn fingerprint_known_answer() {
        assert_eq!(
            fingerprint(&counting_salt(), "12345678").as_str(),
            "v1:25d26983d074853d7ef432dfe2d59c5c1b48c4aed589128d10303e04e8e9be3f"
        );
    }

    #[test]
    fn fingerprint_canonicalizes_case_and_space() {
        let s = counting_salt();
        assert_eq!(fingerprint(&s, " abcdef01 "), fingerprint(&s, "ABCDEF01"));
    }

    #[test]
    fn fingerprints_differ_across_salts() {
        let a = counting_salt();
        let b = Salt([0x5a; 32]);
        assert_ne!(fingerprint(&a, "12345678"), fingerprint(&b, "12345678"));
    }

    #[test]
    fn fingerprint_text_never_contains_the_serial() {
        let s = counting_salt();
        for serial in ["12345678", "ABCDEF01", "00000000"] {
            let fp = fingerprint(&s, serial);
            let text = fp.as_str().to_lowercase();
            assert!(!text.contains(&serial.to_lowercase()), "{serial}");
            assert!(text.starts_with("v1:") && text.len() == 3 + 64);
            assert!(!format!("{fp:?}")
                .to_lowercase()
                .contains(&serial.to_lowercase()));
        }
    }

    #[cfg(unix)]
    #[test]
    fn salt_file_is_0600_and_never_overwritten() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("perm");
        let first = counting_salt();
        persist_salt(&dir, &first).unwrap();
        let path = dir.join(SALT_FILE);
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "keys.salt must be owner-only");
        let text = fs::read_to_string(&path).unwrap();
        assert_eq!(text.len(), 65);
        assert!(text.ends_with('\n'));

        // A second persist never replaces the first salt.
        assert!(persist_salt(&dir, &Salt([0x5a; 32])).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), text);
        assert_eq!(load_salt(&dir).unwrap(), Some(first));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_salt_loads_as_none_and_generated_salts_differ() {
        let dir = temp_dir("missing");
        assert_eq!(load_salt(&dir).unwrap(), None);
        assert_ne!(generate_salt().unwrap(), generate_salt().unwrap());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn malformed_salt_is_an_error_and_untouched() {
        let dir = temp_dir("malformed");
        let path = dir.join(SALT_FILE);
        for bad in [
            "".as_bytes(),
            b"zz".as_slice(),
            "g".repeat(64).as_bytes(),
            "00".repeat(31).as_bytes(),
            "00".repeat(33).as_bytes(),
            &[0xff, 0xfe, 0x00],
        ] {
            fs::write(&path, bad).unwrap();
            assert!(matches!(load_salt(&dir), Err(KeyringError::MalformedSalt)));
            assert_eq!(fs::read(&path).unwrap(), bad);
        }
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn salt_debug_hides_bytes() {
        let s = Salt([0xab; 32]);
        let shown = format!("{s:?}");
        assert_eq!(shown, "Salt(..)");
        assert!(!shown.contains("ab") && !shown.contains("171"));
    }
}
