//! Friendly-name registry for security keys.
//!
//! Lets a user attach a memorable label (e.g. `signing-yubikey`) to a physical
//! key, recognized by its stable **serial number**, so commands can target a
//! key by `--device` instead of a `/dev/hidrawN` path that changes on every
//! replug.
//!
//! This crate is pure config + matching logic: it has no hardware or PC/SC
//! dependencies and never enumerates devices itself. The caller hands in the
//! serial a connected key reported (USB or read over CCID) and asks which
//! record, if any, belongs to it. Front-end concerns (interactive pickers, TTY
//! handling, confirmations) live in the caller, so both the CLI and the GUI
//! reuse this same core.
//!
//! ## What `keys.json` holds
//!
//! Version 2 of the file holds one [`KeyRecord`] per name: the name, the key's
//! salted [`Fingerprint`], and where the name lives ([`NameStore`]): on this
//! computer only, or on the key itself (a name written to the key's large-blob
//! storage, recorded here so this computer knows it saw that key first).
//!
//! ## Privacy
//!
//! **No serial number is ever stored.** A record carries only a fingerprint:
//! HMAC-SHA-256 of the serial under a random salt kept in `keys.salt` beside
//! `keys.json` (see [`fingerprint`]). The salt never leaves this computer, so
//! the file alone reveals no serial and the same key fingerprints differently
//! on every other computer.
//!
//! Writing is opt-in: nothing reaches disk unless the caller invokes
//! [`Keyring::save_to`] / [`Keyring::save_default`]. A name chosen on this
//! computer is saved when the user names a key. A name found on a key is
//! recorded the first time this computer sees it ([`Keyring::record_first_seen`]),
//! so that later a different key showing the same name can be told apart.
//!
//! The one write a load makes is converting an older `keys.json` that still
//! holds plain serials: [`Keyring::load_from`] rewrites it with fingerprints
//! (salt first, through a temporary backup that is removed afterwards), so
//! the serials leave the disk the first time the new version reads the file.

mod fingerprint;

pub use fingerprint::{canonical_serial, fingerprint, Fingerprint, Salt, SALT_FILE};

use fingerprint::{generate_salt, load_salt, persist_salt};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// The `keys.json` format version this crate reads and writes.
pub const FORMAT_VERSION: u64 = 2;

/// How a key's serial is obtained — recorded for display/diagnostics. Matching
/// is always by fingerprint regardless of source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum IdSource {
    /// USB `iSerialNumber` (read from sysfs; SoloKeys, Nitrokey, …).
    #[default]
    Usb,
    /// Serial read from a vendor management applet over CCID (e.g. YubiKey).
    Ccid,
}

/// Where a name lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NameStore {
    /// Only in this computer's `keys.json`.
    Computer,
    /// On the key itself; the record notes that this computer has seen it.
    Key,
}

/// One name in the registry. Names are unique across the file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRecord {
    pub name: String,
    /// The key's salted fingerprint. `None`: the record can't be matched to
    /// any key (there was no serial when it was converted, or the salt file
    /// was lost).
    #[serde(default)]
    pub fingerprint: Option<Fingerprint>,
    pub stored: NameStore,
    #[serde(default)]
    pub source: IdSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aaguid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Descriptive fields for a record written by [`Keyring::set_name`].
#[derive(Debug, Clone, Default)]
pub struct RecordMeta {
    pub source: IdSource,
    pub vendor: Option<String>,
}

/// The registry (`keys.json`) plus this computer's fingerprint salt.
#[derive(Debug, Clone, Default)]
pub struct Keyring {
    pub keys: Vec<KeyRecord>,
    /// `None` until a salt is loaded or first needed.
    salt: Option<Salt>,
    /// Whether `salt` is already in `keys.salt`.
    salt_persisted: bool,
    /// What was on disk when this ring was loaded.
    origin: Origin,
    /// Set when this load converted a version 1 file.
    report: Option<LoadReport>,
}

/// What `keys.json` held when a [`Keyring`] was loaded.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Origin {
    /// No file (or a ring built in memory).
    #[default]
    Fresh,
    /// A version 2 file.
    V2,
    /// A version 1 file (plain serials), converted in memory.
    /// `backup_pending: true`: the file on disk is still version 1; the next
    /// save backs it up, writes the converted file and removes the backup.
    /// `false`: the converted file is on disk and only removing the backup
    /// is left.
    ConvertedFromV1 { backup_pending: bool },
}

/// What converting a version 1 `keys.json` did, for a `--debug` trace:
/// counts only, never a name or serial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadReport {
    /// Records converted.
    pub converted: usize,
    /// Whether the converted file reached disk (else the old file is
    /// untouched and the next save retries).
    pub persisted: bool,
}

/// The old file's backup during conversion, beside `keys.json`.
const V1_BACKUP_SUFFIX: &str = ".v1-backup";

/// `keys.json` as written.
#[derive(Serialize)]
struct FileOut<'a> {
    version: u64,
    keys: &'a [KeyRecord],
}

/// `keys.json` as read (version 2).
#[derive(Deserialize)]
struct FileIn {
    #[serde(default)]
    keys: Vec<KeyRecord>,
}

/// A version 1 file: no `version`, one entry per name with its plain serial.
#[derive(Deserialize)]
struct FileV1 {
    keys: Vec<EntryV1>,
}

#[derive(Deserialize)]
struct EntryV1 {
    name: String,
    serial: String,
    #[serde(default)]
    source: IdSource,
    #[serde(default)]
    vendor: Option<String>,
    #[serde(default)]
    aaguid: Option<String>,
    #[serde(default)]
    note: Option<String>,
}

/// Which `keys.json` format a file holds.
enum Format {
    V1(FileV1),
    V2(FileIn),
    /// Written by a newer keyroost; never read or overwritten.
    Newer(u64),
}

/// Errors loading, saving, or mutating the registry. No variant ever carries a
/// serial number.
#[non_exhaustive]
#[derive(Debug)]
pub enum KeyringError {
    Io(io::Error),
    Parse(String),
    NoConfigDir,
    DuplicateName(String),
    InvalidName(String),
    /// `keys.salt` exists but isn't 64 hex characters; it is left untouched.
    MalformedSalt,
    /// The key reported no serial, so there is nothing to recognize it by.
    NoSerial,
    /// `keys.json` is still in the old format and this ring didn't convert
    /// it; saving would overwrite every name in it.
    Unconverted,
    /// `keys.json` was written by a newer keyroost (this format version);
    /// it is neither read nor overwritten.
    NewerFormat(u64),
    /// `keys.json` can't be read as any keys.json format (the detail never
    /// quotes the file). It is left as it is and never overwritten.
    Damaged(String),
}

impl fmt::Display for KeyringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyringError::Io(e) => write!(f, "keyring I/O error: {}", e),
            KeyringError::Parse(s) => write!(f, "keyring config parse error: {}", s),
            KeyringError::NoConfigDir => {
                write!(
                    f,
                    "could not determine config dir (set HOME or XDG_CONFIG_HOME)"
                )
            }
            KeyringError::DuplicateName(n) => write!(f, "a key named '{}' already exists", n),
            KeyringError::InvalidName(n) => {
                write!(
                    f,
                    "invalid key name '{}': must be 1-64 characters and free of control, zero-width, and bidi-override characters",
                    n
                )
            }
            KeyringError::MalformedSalt => write!(
                f,
                "{} is damaged (expected 64 hex characters); it was left as it is",
                SALT_FILE
            ),
            KeyringError::NoSerial => {
                write!(f, "this key reports no serial number, so it can't be named")
            }
            KeyringError::Unconverted => write!(
                f,
                "keys.json is in the old format and hasn't been converted yet; \
                 not overwriting it"
            ),
            KeyringError::NewerFormat(v) => write!(
                f,
                "keys.json was written by a newer keyroost (format version {}); \
                 not changing it",
                v
            ),
            KeyringError::Damaged(d) => write!(
                f,
                "keys.json can't be read ({}); it was left as it is and won't be \
                 overwritten — fix or remove it by hand",
                d
            ),
        }
    }
}

impl std::error::Error for KeyringError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            KeyringError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for KeyringError {
    fn from(e: io::Error) -> Self {
        KeyringError::Io(e)
    }
}

/// Validate a friendly name. A name is a human-facing label, so the rules are
/// deliberately permissive about content — letters of any case or script,
/// digits, spaces and punctuation are all fine (e.g. `UPPER`, `Emin's Work
/// Key`, `Clé de bureau`). Only three things are rejected:
///
/// * empty (or whitespace-only) names — there must be something after trimming;
/// * names longer than 64 characters;
/// * names containing control / zero-width / bidi-override characters (the
///   spoofing chars [`is_spoofing_char`] guards against — they enable display
///   spoofing in a saved name).
pub fn validate_name(name: &str) -> Result<(), KeyringError> {
    // A friendly name is a human-facing label, so allow normal text — letters
    // (any case, any script), digits, spaces and common punctuation. The only
    // hard rules are: non-empty, a sane length cap, and none of the control /
    // zero-width / bidi-override characters that strip_control_chars guards
    // against (those enable display spoofing in a saved name).
    let trimmed = name.trim();
    let ok =
        !trimmed.is_empty() && name.chars().count() <= 64 && !name.chars().any(is_spoofing_char);
    if ok {
        Ok(())
    } else {
        // The rejected name is echoed in the error message; sanitize it so a
        // hand-edited keys.json can't smuggle terminal escapes through the
        // very rejection meant to stop them.
        let mut shown = name.to_string();
        strip_control_chars(&mut shown);
        Err(KeyringError::InvalidName(shown))
    }
}

/// Control, zero-width, and bidi-override characters that enable display
/// spoofing in a saved name or any device/credential string. The single source
/// of truth for terminal-hostile classification, shared by this crate's name
/// validation/sanitization and the CLI's `sanitize_terminal`/`sanitize_multiline`.
pub fn is_spoofing_char(c: char) -> bool {
    c.is_control() // Cc (includes ESC 0x1b, NUL, and all C0/C1 controls)
        || matches!(c,
            '\u{00AD}' // soft hyphen
            | '\u{061C}' // Arabic letter mark
            | '\u{180E}' // Mongolian vowel separator (zero-width)
            | '\u{200B}'..='\u{200F}' // zero-width space/joiners, LRM/RLM
            | '\u{2028}' // line separator (Zl)
            | '\u{2029}' // paragraph separator (Zp)
            | '\u{202A}'..='\u{202E}' // bidi embeddings + LRO/RLO
            | '\u{2060}'..='\u{2064}' // word joiner + invisible format chars
            | '\u{2066}'..='\u{2069}' // bidi isolates
            | '\u{FEFF}' // BOM / ZWNBSP
            | '\u{E0000}'..='\u{E007F}' // Unicode TAG block (incl. deprecated lang tags)
        )
}

/// Remove control characters in place — terminal-escape hygiene for
/// hand-editable fields that get echoed back to the user. Also strips the
/// Unicode format characters used for display spoofing (`char::is_control`
/// covers only Cc): bidi overrides/isolates (RLO can render "key-live" out
/// of "evil-yek"), line/paragraph separators, zero-width chars, BOM, and the
/// soft/Arabic-letter marks.
fn strip_control_chars(s: &mut String) {
    if s.chars().any(is_spoofing_char) {
        s.retain(|c| !is_spoofing_char(c));
    }
}

/// Default config *directory* for keyroost's per-user state (`keys.json`,
/// and the GUI's `settings.json`). Both files must live in the same place, so
/// the directory rule lives here once.
///
/// * Windows: `%APPDATA%\keyroost` (falling back to `%USERPROFILE%\.config\keyroost`).
/// * Otherwise: `$XDG_CONFIG_HOME/keyroost`, else `$HOME/.config/keyroost`.
pub fn config_dir() -> Option<std::path::PathBuf> {
    // Windows has no HOME/XDG by default; use the standard roaming AppData dir.
    #[cfg(windows)]
    {
        let appdata = std::env::var_os("APPDATA");
        let profile = std::env::var_os("USERPROFILE");
        config_dir_from(appdata.as_deref(), profile.as_deref())
    }
    #[cfg(not(windows))]
    {
        let xdg = std::env::var_os("XDG_CONFIG_HOME");
        let home = std::env::var_os("HOME");
        config_dir_from(xdg.as_deref(), home.as_deref())
    }
}

/// The [`config_dir`] rule as a pure function of the two environment values it
/// reads — `(XDG_CONFIG_HOME, HOME)`, or `(APPDATA, USERPROFILE)` on Windows.
///
/// Split out so the rule can be tested without touching process environment.
/// `setenv` races every other thread that calls `getenv`: it can reallocate the
/// environ array under a concurrent reader, which on macOS kills the process
/// outright. Rust 2024 makes `std::env::set_var` `unsafe` for exactly this
/// reason. A test that mutates env is therefore not just untidy — it is a data
/// race whose blast radius is every other test sharing the binary.
pub fn config_dir_from(
    primary: Option<&std::ffi::OsStr>,
    fallback: Option<&std::ffi::OsStr>,
) -> Option<PathBuf> {
    if let Some(primary) = primary {
        if !primary.is_empty() {
            return Some(PathBuf::from(primary).join("keyroost"));
        }
    }
    let fallback = fallback?;
    if fallback.is_empty() {
        return None;
    }
    // `$HOME/.config/keyroost`, or `%USERPROFILE%\.config\keyroost`.
    Some(PathBuf::from(fallback).join(".config").join("keyroost"))
}

/// Default config path for `keys.json`. See [`config_dir`] for the directory rule.
pub fn config_path() -> Option<PathBuf> {
    config_dir().map(|d| d.join("keys.json"))
}

/// Strip spoofing characters from the free-text fields of a record, the same
/// cleaning on the way in and on the way back out of `keys.json`.
fn sanitize_record(r: &mut KeyRecord) {
    strip_control_chars(&mut r.name);
    for field in [&mut r.vendor, &mut r.aaguid, &mut r.note]
        .into_iter()
        .flatten()
    {
        strip_control_chars(field);
    }
}

impl Keyring {
    /// Load from the default config path. A missing file yields an empty
    /// registry (reading records nothing).
    pub fn load_default() -> Result<Keyring, KeyringError> {
        let path = config_path().ok_or(KeyringError::NoConfigDir)?;
        Self::load_from(&path)
    }

    /// Load from a specific path; the salt is read from `keys.salt` in the
    /// same directory. A missing file yields an empty registry.
    ///
    /// A version 1 file (plain serials) is converted on the spot: the salt is
    /// written first, the old file is backed up, the new one written, and the
    /// backup removed. If any step fails the old file stays as it was, the
    /// converted ring still works in memory, and the next save retries;
    /// [`Keyring::load_report`] says which happened. A leftover backup from an
    /// earlier interrupted conversion holds plain serials and is deleted.
    pub fn load_from(path: &Path) -> Result<Keyring, KeyringError> {
        let dir = salt_dir(path);
        let text = match fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                remove_stale_backup(path);
                let salt = load_salt(dir)?;
                return Ok(Keyring {
                    salt_persisted: salt.is_some(),
                    salt,
                    ..Keyring::default()
                });
            }
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                return Err(KeyringError::Damaged("not text".into()))
            }
            Err(e) => return Err(KeyringError::Io(e)),
        };
        let file = match parse(&text)? {
            Format::V2(file) => file,
            Format::Newer(v) => return Err(KeyringError::NewerFormat(v)),
            Format::V1(old) => return Self::convert(path, &text, old),
        };
        remove_stale_backup(path);
        let mut keys = file.keys;
        // Names are validated before they ever reach disk; on the way back in
        // every field — including the name — is sanitized rather than
        // rejected. Rejecting would make one hand-edited entry render the
        // whole registry unloadable, and callers that fall back to an empty
        // registry on error would then overwrite keys.json and destroy every
        // other entry on the next save.
        for r in &mut keys {
            sanitize_record(r);
        }
        let salt = load_salt(dir)?;
        if salt.is_none() {
            // Without the salt no stored fingerprint can be reproduced: keep
            // the records (their names still list) but unmatched. The next
            // save writes a fresh salt.
            for r in &mut keys {
                r.fingerprint = None;
            }
        }
        Ok(Keyring {
            keys,
            salt_persisted: salt.is_some(),
            salt,
            origin: Origin::V2,
            report: None,
        })
    }

    /// Convert a version 1 file read from `path` (`text`, already parsed as
    /// `old`).
    fn convert(path: &Path, text: &str, old: FileV1) -> Result<Keyring, KeyringError> {
        let dir = salt_dir(path);
        let mut ring = Keyring {
            origin: Origin::ConvertedFromV1 {
                backup_pending: true,
            },
            ..Keyring::default()
        };
        // a. The salt reaches disk before any fingerprint does.
        let salt_on_disk = match load_salt(dir)? {
            Some(salt) => {
                ring.salt = Some(salt);
                ring.salt_persisted = true;
                true
            }
            None => {
                ring.salt = Some(generate_salt()?);
                ring.persist_salt_if_needed(dir).is_ok()
            }
        };
        // b. Records.
        let converted = old.keys.len();
        ring.keys = convert_v1(ring.salt.as_ref().expect("set above"), old);
        // c–e. Backup, write, remove the backup. `persisted` means the
        // converted file reached disk, even if removing the backup failed.
        if salt_on_disk {
            let _ = ring.finish_conversion(path, text.as_bytes());
        }
        let persisted = !matches!(
            ring.origin,
            Origin::ConvertedFromV1 {
                backup_pending: true
            }
        );
        ring.report = Some(LoadReport {
            converted,
            persisted,
        });
        Ok(ring)
    }

    /// Steps c–e of a conversion: back up `original` (the version 1 bytes on
    /// disk), write this ring over it, remove the backup. If the write fails,
    /// the atomic rename never happened and `path` still holds `original`.
    fn finish_conversion(&mut self, path: &Path, original: &[u8]) -> Result<(), KeyringError> {
        let backup = backup_path(path);
        // c.
        let _ = fs::remove_file(&backup);
        write_new_private(&backup, original)?;
        // d.
        let json = self.to_json()?;
        if let Err(e) = write_atomic(path, &json) {
            // Drop the backup only once `path` is confirmed to still hold
            // the original; otherwise it may be the only copy.
            if fs::read(path).ok().as_deref() == Some(original) {
                let _ = fs::remove_file(&backup);
            }
            return Err(e);
        }
        self.origin = Origin::ConvertedFromV1 {
            backup_pending: false,
        };
        // e. The backup holds plain serials; it must not outlive the
        // conversion. Removed only once `path` is confirmed to hold the
        // converted file (write_atomic has synced the directory, so the
        // rename is durable first). If it can't be removed now, the next
        // save or load removes it.
        if fs::read(path).ok().as_deref() != Some(file_bytes(&json).as_slice()) {
            return Err(KeyringError::Io(io::Error::other(
                "keys.json changed during conversion; the backup was kept",
            )));
        }
        fs::remove_file(&backup)?;
        self.origin = Origin::V2;
        Ok(())
    }

    /// What this load's conversion of a version 1 file did; `None` when no
    /// conversion happened.
    pub fn load_report(&self) -> Option<LoadReport> {
        self.report
    }

    /// Persist to the default config path, creating parent dirs. Opt-in: only
    /// call this from an explicit user action. Returns the path written.
    pub fn save_default(&mut self) -> Result<PathBuf, KeyringError> {
        let path = config_path().ok_or(KeyringError::NoConfigDir)?;
        self.save_to(&path)?;
        Ok(path)
    }

    /// Persist to a specific path, creating parent dirs. Opt-in. The salt is
    /// written to `keys.salt` first if it isn't on disk yet, so no
    /// fingerprint is ever saved without the salt that reproduces it.
    ///
    /// Concurrency: this is a load-modify-save with no file lock. The temp-file
    /// and atomic-rename below mean a save can never *corrupt* the registry (a
    /// reader always sees a complete old or new file), but two processes editing
    /// concurrently (e.g. the CLI and GUI both adding a name) are
    /// last-writer-wins, and the earlier edit is lost. That is accepted:
    /// `keys.json` is a per-user convenience registry written rarely and
    /// interactively, so the collision window is tiny and the only loss is one
    /// un-persisted rename, not data integrity. Add advisory locking only if
    /// that assumption stops holding. The salt is the exception: it is created
    /// once and never replaced, and a save refuses rather than pair this
    /// ring's fingerprints with a salt another process wrote meanwhile.
    ///
    /// Two guards keep a ring from destroying names it never read: a file
    /// still in version 1 is overwritten only by the ring that converted it
    /// ([`KeyringError::Unconverted`] otherwise — e.g. an empty ring from
    /// `load_default().unwrap_or_default()`), and a file from a newer
    /// keyroost is never overwritten ([`KeyringError::NewerFormat`]). A file
    /// that can't be read at all is never overwritten either
    /// ([`KeyringError::Damaged`]): no ring can have been loaded from it, so
    /// saving would replace names nobody has seen. A refused save writes
    /// nothing.
    pub fn save_to(&mut self, path: &Path) -> Result<(), KeyringError> {
        let converting = matches!(self.origin, Origin::ConvertedFromV1 { .. });
        let v1_pending = self.origin
            == Origin::ConvertedFromV1 {
                backup_pending: true,
            };
        let mut v1_on_disk = None;
        match fs::read_to_string(path) {
            Ok(text) => match parse(&text)? {
                Format::Newer(v) => return Err(KeyringError::NewerFormat(v)),
                Format::V1(_) if !v1_pending => return Err(KeyringError::Unconverted),
                Format::V1(_) => v1_on_disk = Some(text),
                Format::V2(_) => {}
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            // Not text at all. No ring can have been loaded from it (a load
            // fails the same way), so nothing may overwrite it.
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                return Err(KeyringError::Damaged("not text".into()))
            }
            Err(e) => return Err(KeyringError::Io(e)),
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
            // Owner-only on the directory too, matching the file below. Only
            // tightened when we (may have) just created it — an existing dir
            // the user deliberately opened up is left alone.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = fs::metadata(parent) {
                    let mut perms = meta.permissions();
                    if perms.mode() & 0o077 != 0 && parent.ends_with("keyroost") {
                        perms.set_mode(0o700);
                        let _ = fs::set_permissions(parent, perms);
                    }
                }
            }
        }
        self.persist_salt_if_needed(salt_dir(path))?;
        if let Some(original) = v1_on_disk {
            return self.finish_conversion(path, original.as_bytes());
        }
        write_atomic(path, &self.to_json()?)?;
        if converting {
            // The file was converted, but its backup may have outlived it.
            fs::remove_file(backup_path(path)).or_else(|e| {
                if e.kind() == io::ErrorKind::NotFound {
                    Ok(())
                } else {
                    Err(e)
                }
            })?;
            self.origin = Origin::V2;
        }
        Ok(())
    }

    fn to_json(&self) -> Result<String, KeyringError> {
        serde_json::to_string_pretty(&FileOut {
            version: FORMAT_VERSION,
            keys: &self.keys,
        })
        .map_err(|e| KeyringError::Parse(parse_detail(&e)))
    }

    /// The salt, generated in memory on first need.
    fn ensure_salt(&mut self) -> Result<&Salt, KeyringError> {
        if self.salt.is_none() {
            self.salt = Some(generate_salt()?);
            self.salt_persisted = false;
        }
        Ok(self.salt.as_ref().expect("salt was just set"))
    }

    fn persist_salt_if_needed(&mut self, dir: &Path) -> Result<(), KeyringError> {
        self.ensure_salt()?;
        if self.salt_persisted {
            return Ok(());
        }
        let salt = self.salt.as_ref().expect("ensured above");
        match persist_salt(dir, salt) {
            Ok(()) => {}
            Err(KeyringError::Io(e)) if e.kind() == io::ErrorKind::AlreadyExists => {
                // Another keyroost process created the salt since this ring
                // was loaded. Same salt (it was loaded from there): fine.
                // Different: every fingerprint made here would be wrong.
                if load_salt(dir)?.as_ref() != Some(salt) {
                    return Err(KeyringError::Io(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!(
                            "{SALT_FILE} was created by another keyroost process; \
                             reload and try again"
                        ),
                    )));
                }
            }
            Err(e) => return Err(e),
        }
        self.salt_persisted = true;
        Ok(())
    }

    /// This computer's fingerprint of `serial`. `None` for an empty serial,
    /// or before any salt exists (then no stored record can match anyway).
    pub fn fingerprint_of(&self, serial: &str) -> Option<Fingerprint> {
        if canonical_serial(serial).is_empty() {
            return None;
        }
        self.salt.as_ref().map(|s| fingerprint(s, serial))
    }

    fn is_of(r: &KeyRecord, fp: &Option<Fingerprint>) -> bool {
        fp.is_some() && r.fingerprint == *fp
    }

    /// The record that claims `name`, if any (names are unique in the file).
    pub fn holder(&self, name: &str) -> Option<&KeyRecord> {
        self.keys.iter().find(|r| r.name == name)
    }

    /// This computer's own (`stored = computer`) name for the key with
    /// `serial`.
    pub fn local_name_for(&self, serial: &str) -> Option<&str> {
        let fp = self.fingerprint_of(serial);
        self.keys
            .iter()
            .find(|r| r.stored == NameStore::Computer && Self::is_of(r, &fp))
            .map(|r| r.name.as_str())
    }

    /// Every record of the key with `serial`.
    pub fn records_for(&self, serial: &str) -> Vec<&KeyRecord> {
        let fp = self.fingerprint_of(serial);
        self.keys.iter().filter(|r| Self::is_of(r, &fp)).collect()
    }

    /// Name (or rename) the key with `serial` in `store`. Refuses
    /// [`KeyringError::DuplicateName`] when another key's record holds `name`.
    /// `Computer` replaces this key's computer record; `Key` replaces this
    /// key's key records and drops its computer record (one name, one place).
    /// The new record takes the place of the first one it replaces, so a
    /// rename keeps the file's order.
    pub fn set_name(
        &mut self,
        serial: &str,
        name: &str,
        store: NameStore,
        meta: RecordMeta,
    ) -> Result<(), KeyringError> {
        validate_name(name)?;
        if canonical_serial(serial).is_empty() {
            return Err(KeyringError::NoSerial);
        }
        let fp = Some(fingerprint(self.ensure_salt()?, serial));
        if let Some(h) = self.holder(name) {
            if !Self::is_of(h, &fp) {
                return Err(KeyringError::DuplicateName(name.to_string()));
            }
        }
        let replaced = |r: &KeyRecord| {
            Self::is_of(r, &fp)
                && (store == NameStore::Key || r.stored == NameStore::Computer || r.name == name)
        };
        let mut record = KeyRecord {
            name: name.to_string(),
            fingerprint: fp.clone(),
            stored: store,
            source: meta.source,
            vendor: meta.vendor,
            aaguid: None,
            note: None,
        };
        sanitize_record(&mut record);
        // The new record takes the slot of the first one it replaces; no
        // record before that one is removed, so the index still holds.
        let at = self.keys.iter().position(&replaced);
        self.keys.retain(|r| !replaced(r));
        match at {
            Some(i) => self.keys.insert(i, record),
            None => self.keys.push(record),
        }
        Ok(())
    }

    /// First sight of a name stored on the key with `serial`: record it
    /// (`stored = key`) only if no record holds `name` yet. Returns whether a
    /// record was added.
    pub fn record_first_seen(&mut self, serial: &str, name: &str) -> bool {
        if validate_name(name).is_err()
            || canonical_serial(serial).is_empty()
            || self.holder(name).is_some()
        {
            return false;
        }
        let Ok(salt) = self.ensure_salt() else {
            return false;
        };
        let fp = fingerprint(salt, serial);
        self.keys.push(KeyRecord {
            name: name.to_string(),
            fingerprint: Some(fp),
            stored: NameStore::Key,
            source: IdSource::default(),
            vendor: None,
            aaguid: None,
            note: None,
        });
        true
    }

    /// Drop this key's `stored = key` records whose name differs from
    /// `current` (the name now on the key). Returns how many were dropped.
    pub fn drop_stale_key_records(&mut self, serial: &str, current: &str) -> usize {
        let fp = self.fingerprint_of(serial);
        let before = self.keys.len();
        self.keys
            .retain(|r| !(Self::is_of(r, &fp) && r.stored == NameStore::Key && r.name != current));
        before - self.keys.len()
    }

    /// Remove every record of the key with `serial`, returning them.
    pub fn clear_key(&mut self, serial: &str) -> Vec<KeyRecord> {
        let fp = self.fingerprint_of(serial);
        let (gone, kept) = std::mem::take(&mut self.keys)
            .into_iter()
            .partition(|r| Self::is_of(r, &fp));
        self.keys = kept;
        gone
    }

    /// Remove the record holding `name`.
    pub fn remove(&mut self, name: &str) -> Option<KeyRecord> {
        let i = self.keys.iter().position(|r| r.name == name)?;
        Some(self.keys.remove(i))
    }
}

/// `keys.json.v1-backup` beside `path`.
fn backup_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(V1_BACKUP_SUFFIX);
    path.with_file_name(name)
}

/// Delete a backup left by an interrupted conversion: it holds plain serials.
/// Best effort; the next load tries again.
fn remove_stale_backup(path: &Path) {
    let _ = fs::remove_file(backup_path(path));
}

/// Create `path` owner-only (0600 on Unix) holding `bytes`; never overwrites
/// and never follows a symlink planted there.
fn write_new_private(path: &Path, bytes: &[u8]) -> Result<(), KeyringError> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    use std::io::Write;
    let mut f = opts.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

/// The directory holding `keys.json` (and so `keys.salt`).
fn salt_dir(path: &Path) -> &Path {
    path.parent().unwrap_or_else(|| Path::new("."))
}

/// A parse error's kind and position, without the offending text: serde's
/// messages can quote a value, and a value in keys.json may be a serial
/// number.
fn parse_detail(e: &serde_json::Error) -> String {
    let kind = match e.classify() {
        serde_json::error::Category::Io => "unreadable",
        serde_json::error::Category::Syntax => "invalid JSON",
        serde_json::error::Category::Data => "unexpected contents",
        serde_json::error::Category::Eof => "truncated",
    };
    if e.line() == 0 {
        kind.to_string()
    } else {
        format!("{kind} at line {}, column {}", e.line(), e.column())
    }
}

fn damaged(e: &serde_json::Error) -> KeyringError {
    KeyringError::Damaged(parse_detail(e))
}

/// Tell the formats apart: `version: 2` is v2; no `version` and a `keys`
/// array whose every entry carries a `serial` (or no entries) is v1.
fn parse(text: &str) -> Result<Format, KeyringError> {
    let value: serde_json::Value = serde_json::from_str(text).map_err(|e| damaged(&e))?;
    match value.get("version").map(serde_json::Value::as_u64) {
        Some(Some(FORMAT_VERSION)) => serde_json::from_value(value)
            .map(Format::V2)
            .map_err(|e| damaged(&e)),
        Some(Some(v)) if v > FORMAT_VERSION => Ok(Format::Newer(v)),
        Some(_) => Err(KeyringError::Damaged("unsupported version".into())),
        None if is_v1(&value) => serde_json::from_value(value)
            .map(Format::V1)
            .map_err(|e| damaged(&e)),
        None => Err(KeyringError::Damaged("unrecognized layout".into())),
    }
}

fn is_v1(value: &serde_json::Value) -> bool {
    value
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|keys| {
            keys.iter()
                .all(|k| k.get("serial").is_some_and(serde_json::Value::is_string))
        })
}

/// Version 1 entries as v2 records: the serial becomes this computer's
/// fingerprint (`None` for an empty serial) and every name was this
/// computer's own. Fields are sanitized as a v1 load always did.
fn convert_v1(salt: &Salt, old: FileV1) -> Vec<KeyRecord> {
    old.keys
        .into_iter()
        .map(|e| {
            let mut r = KeyRecord {
                fingerprint: (!canonical_serial(&e.serial).is_empty())
                    .then(|| fingerprint(salt, &e.serial)),
                name: e.name,
                stored: NameStore::Computer,
                source: e.source,
                vendor: e.vendor,
                aaguid: e.aaguid,
                note: e.note,
            };
            sanitize_record(&mut r);
            r
        })
        .collect()
}

/// Write a sibling temp file and rename it into place: a crash mid-write can
/// never corrupt the registry, and the file is created owner-only — which
/// security keys a person owns is their business — instead of inheriting the
/// umask default (typically world-readable).
fn write_atomic(path: &Path, json: &str) -> Result<(), KeyringError> {
    let tmp = path.with_extension("json.tmp");
    // Remove any stale temp file so `create_new` below can succeed.
    // `create_new` (not `create`) matters twice over: a pre-existing file
    // would keep its old permissions (the 0o600 applies only at creation),
    // and a symlink planted at the temp path would otherwise be followed.
    let _ = fs::remove_file(&tmp);
    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        use std::io::Write;
        let mut f = opts.open(&tmp)?;
        f.write_all(&file_bytes(json))?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    // Make the rename itself durable before anything (such as removing a
    // conversion backup) relies on it.
    #[cfg(unix)]
    fs::File::open(salt_dir(path))?.sync_all()?;
    Ok(())
}

/// The exact bytes `keys.json` holds for `json`.
fn file_bytes(json: &str) -> Vec<u8> {
    let mut b = json.as_bytes().to_vec();
    b.push(b'\n');
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh, empty directory under the system temp dir, unique per test.
    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("keyroost-kr-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn meta() -> RecordMeta {
        RecordMeta::default()
    }

    fn names(k: &Keyring) -> Vec<(&str, NameStore)> {
        k.keys.iter().map(|r| (r.name.as_str(), r.stored)).collect()
    }

    #[test]
    fn set_name_computer_renames_in_place() {
        let mut k = Keyring::default();
        k.set_name("12345678", "first", NameStore::Computer, meta())
            .unwrap();
        k.set_name("ABCDEF01", "other", NameStore::Computer, meta())
            .unwrap();
        k.set_name(" 12345678 ", "renamed", NameStore::Computer, meta())
            .unwrap();
        assert_eq!(
            names(&k),
            vec![
                ("renamed", NameStore::Computer),
                ("other", NameStore::Computer)
            ]
        );
        assert_eq!(k.local_name_for("12345678"), Some("renamed"));
        assert_eq!(k.local_name_for("abcdef01"), Some("other"));
        // Setting the same name again is not a duplicate of itself.
        k.set_name("12345678", "renamed", NameStore::Computer, meta())
            .unwrap();
        assert_eq!(k.keys.len(), 2);
    }

    #[test]
    fn set_name_key_drops_the_local_record() {
        let mut k = Keyring::default();
        k.set_name("12345678", "local", NameStore::Computer, meta())
            .unwrap();
        k.set_name("12345678", "on key", NameStore::Key, meta())
            .unwrap();
        assert_eq!(names(&k), vec![("on key", NameStore::Key)]);
        assert_eq!(k.local_name_for("12345678"), None);
        // A second key-store name replaces the first.
        k.set_name("12345678", "on key 2", NameStore::Key, meta())
            .unwrap();
        assert_eq!(names(&k), vec![("on key 2", NameStore::Key)]);
    }

    #[test]
    fn duplicate_name_on_another_key_is_refused() {
        let mut k = Keyring::default();
        k.set_name("12345678", "work", NameStore::Computer, meta())
            .unwrap();
        for store in [NameStore::Computer, NameStore::Key] {
            assert!(matches!(
                k.set_name("ABCDEF01", "work", store, meta()),
                Err(KeyringError::DuplicateName(_))
            ));
        }
        assert!(matches!(
            k.set_name("ABCDEF01", "bad\u{202E}", NameStore::Computer, meta()),
            Err(KeyringError::InvalidName(_))
        ));
        assert!(matches!(
            k.set_name("  ", "fine", NameStore::Computer, meta()),
            Err(KeyringError::NoSerial)
        ));
        assert_eq!(k.keys.len(), 1);
    }

    #[test]
    fn record_first_seen_only_when_unclaimed() {
        let mut k = Keyring::default();
        k.set_name("12345678", "taken", NameStore::Computer, meta())
            .unwrap();
        assert!(!k.record_first_seen("ABCDEF01", "taken"));
        assert!(!k.record_first_seen("", "free"));
        assert!(!k.record_first_seen("ABCDEF01", "bad\u{200B}"));
        assert!(k.record_first_seen("ABCDEF01", "free"));
        assert!(!k.record_first_seen("00000000", "free"));
        let r = k.holder("free").unwrap();
        assert_eq!(r.stored, NameStore::Key);
        assert_eq!(r.fingerprint, k.fingerprint_of("abcdef01"));
    }

    #[test]
    fn drop_stale_key_records_keeps_computer_records() {
        let mut k = Keyring::default();
        k.set_name("12345678", "local", NameStore::Computer, meta())
            .unwrap();
        assert!(k.record_first_seen("12345678", "old label"));
        assert!(k.record_first_seen("12345678", "current"));
        assert!(k.record_first_seen("ABCDEF01", "elsewhere"));
        assert_eq!(k.drop_stale_key_records("12345678", "current"), 1);
        assert_eq!(
            names(&k),
            vec![
                ("local", NameStore::Computer),
                ("current", NameStore::Key),
                ("elsewhere", NameStore::Key)
            ]
        );
    }

    #[test]
    fn clear_key_removes_every_record() {
        let mut k = Keyring::default();
        k.set_name("12345678", "local", NameStore::Computer, meta())
            .unwrap();
        assert!(k.record_first_seen("12345678", "label"));
        assert!(k.record_first_seen("ABCDEF01", "other"));
        let gone = k.clear_key("12345678");
        assert_eq!(gone.len(), 2);
        assert_eq!(names(&k), vec![("other", NameStore::Key)]);
        assert!(k.records_for("12345678").is_empty());
        assert_eq!(k.records_for("ABCDEF01").len(), 1);
        assert_eq!(k.remove("other").map(|r| r.name), Some("other".into()));
        assert!(k.remove("other").is_none());
    }

    #[test]
    fn local_name_for_ignores_key_records() {
        let mut k = Keyring::default();
        assert!(k.record_first_seen("12345678", "label"));
        assert_eq!(k.local_name_for("12345678"), None);
        assert_eq!(k.records_for("12345678").len(), 1);
        assert_eq!(k.local_name_for(""), None);
        assert_eq!(k.fingerprint_of("   "), None);
    }

    #[test]
    fn a_fresh_ring_matches_nothing_and_never_panics() {
        let k = Keyring::default();
        assert_eq!(k.fingerprint_of("12345678"), None);
        assert_eq!(k.local_name_for("12345678"), None);
        assert!(k.records_for("12345678").is_empty());
    }

    #[test]
    fn v2_round_trip_keeps_records_and_matches() {
        let dir = temp_dir("roundtrip");
        let path = dir.join("keys.json");
        let mut k = Keyring::default();
        k.set_name(
            "12345678",
            "signing-yubikey",
            NameStore::Computer,
            RecordMeta {
                source: IdSource::Ccid,
                vendor: Some("yubico".into()),
            },
        )
        .unwrap();
        assert!(k.record_first_seen("ABCDEF01", "lab key"));
        k.save_to(&path).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["version"], 2);
        assert_eq!(v["keys"][0]["stored"], "computer");
        assert_eq!(v["keys"][0]["vendor"], "yubico");
        assert_eq!(v["keys"][1]["stored"], "key");
        assert!(!text.contains("12345678") && !text.to_lowercase().contains("abcdef01"));

        let back = Keyring::load_from(&path).unwrap();
        assert_eq!(back.local_name_for("12345678"), Some("signing-yubikey"));
        assert_eq!(back.keys[0].source, IdSource::Ccid);
        assert_eq!(back.holder("lab key").unwrap().stored, NameStore::Key);
        assert_eq!(back.records_for("abcdef01").len(), 1);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_missing_is_empty() {
        let dir = temp_dir("missing");
        let k = Keyring::load_from(&dir.join("keys.json")).unwrap();
        assert!(k.keys.is_empty());
        // Loading wrote nothing.
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_sanitizes_invalid_names_and_strips_control_chars() {
        let dir = temp_dir("sanitize");
        let path = dir.join("keys.json");

        // A name with an ANSI escape is sanitized, not fatal: one bad
        // hand-edited entry must never make the whole registry unloadable
        // (an unwrap_or_default + save would wipe every other entry).
        fs::write(
            &path,
            "{\"version\":2,\"keys\":[{\"name\":\"evil\\u001b[31m\",\"fingerprint\":null,\"stored\":\"computer\"},{\"name\":\"good\",\"fingerprint\":null,\"stored\":\"key\"}]}",
        )
        .unwrap();
        let k = Keyring::load_from(&path).unwrap();
        assert_eq!(k.keys[0].name, "evil[31m");
        assert_eq!(k.keys[1].name, "good");

        // Control chars in free-text fields are stripped, not fatal.
        fs::write(
            &path,
            "{\"version\":2,\"keys\":[{\"name\":\"ok\",\"stored\":\"computer\",\"vendor\":\"y\\u001b[2Jk\",\"note\":\"a\\u0007b\"}]}",
        )
        .unwrap();
        let k = Keyring::load_from(&path).unwrap();
        assert_eq!(k.keys[0].vendor.as_deref(), Some("y[2Jk"));
        assert_eq!(k.keys[0].note.as_deref(), Some("ab"));
        assert_eq!(k.keys[0].fingerprint, None);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn set_name_sanitizes_device_supplied_fields() {
        let mut k = Keyring::default();
        k.set_name(
            "12345678",
            "weird",
            NameStore::Computer,
            RecordMeta {
                source: IdSource::Usb,
                vendor: Some("v\u{1b}[31m\u{202E}x".into()),
            },
        )
        .unwrap();
        assert_eq!(k.keys[0].vendor.as_deref(), Some("v[31mx"));
        // A serial with spoofing characters matches its cleaned form, as an
        // older file stored it.
        assert_eq!(k.local_name_for("1234\u{200B}5678"), Some("weird"));
    }

    #[cfg(unix)]
    #[test]
    fn save_creates_owner_only_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("perm");
        let path = dir.join("keys.json");
        let mut k = Keyring::default();
        k.set_name("12345678", "test-key", NameStore::Computer, meta())
            .unwrap();
        k.save_to(&path).unwrap();
        for f in [&path, &dir.join(SALT_FILE)] {
            let mode = fs::metadata(f).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "{} must be owner-only", f.display());
        }
        // No temp file left behind.
        assert!(!path.with_extension("json.tmp").exists());
        fs::remove_dir_all(&dir).ok();
    }

    const V1_FIXTURE: &str = r#"{
  "keys": [
    { "name": "yubi", "serial": "12345678", "source": "ccid", "vendor": "yubico" },
    { "name": "solo", "serial": "ABCDEF01", "note": "desk" },
    { "name": "blank", "serial": "" }
  ]
}"#;

    fn backup_of(path: &Path) -> PathBuf {
        path.with_file_name("keys.json.v1-backup")
    }

    #[test]
    fn v1_converts_once_backup_removed_salt_0600() {
        let dir = temp_dir("v1-convert");
        let path = dir.join("keys.json");
        fs::write(&path, V1_FIXTURE).unwrap();
        let k = Keyring::load_from(&path).unwrap();
        let report = k.load_report().expect("a conversion happened");
        assert_eq!((report.converted, report.persisted), (3, true));

        let v: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["version"], 2);
        let keys = v["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 3);
        assert!(keys.iter().all(|r| r["stored"] == "computer"));
        assert_eq!(keys[0]["vendor"], "yubico");
        assert_eq!(keys[1]["note"], "desk");
        assert!(keys[2]["fingerprint"].is_null());
        assert_eq!(k.local_name_for("12345678"), Some("yubi"));
        assert_eq!(k.local_name_for("abcdef01"), Some("solo"));
        assert!(!backup_of(&path).exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.join(SALT_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn conversion_is_idempotent_bytes_unchanged() {
        let dir = temp_dir("v1-idem");
        let path = dir.join("keys.json");
        fs::write(&path, V1_FIXTURE).unwrap();
        Keyring::load_from(&path).unwrap();
        let json = fs::read(&path).unwrap();
        let salt = fs::read(dir.join(SALT_FILE)).unwrap();
        let again = Keyring::load_from(&path).unwrap();
        assert!(again.load_report().is_none());
        assert_eq!(again.local_name_for("12345678"), Some("yubi"));
        assert_eq!(fs::read(&path).unwrap(), json);
        assert_eq!(fs::read(dir.join(SALT_FILE)).unwrap(), salt);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn converted_file_contains_no_serial() {
        let dir = temp_dir("v1-noserial");
        let path = dir.join("keys.json");
        fs::write(&path, V1_FIXTURE).unwrap();
        Keyring::load_from(&path).unwrap();
        for f in [&path, &dir.join(SALT_FILE)] {
            let text = fs::read_to_string(f).unwrap().to_lowercase();
            assert!(!text.contains("12345678"), "{}", f.display());
            assert!(!text.contains("abcdef01"), "{}", f.display());
        }
        // Nothing else is left in the directory.
        let mut left: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(left, vec!["keys.json".to_string(), SALT_FILE.to_string()]);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn stale_backup_is_deleted_on_load() {
        let dir = temp_dir("stale-backup");
        let path = dir.join("keys.json");
        let mut k = Keyring::default();
        k.set_name("12345678", "a", NameStore::Computer, meta())
            .unwrap();
        k.save_to(&path).unwrap();
        fs::write(backup_of(&path), V1_FIXTURE).unwrap();
        Keyring::load_from(&path).unwrap();
        assert!(!backup_of(&path).exists());
        // Also when keys.json itself is gone.
        fs::write(backup_of(&path), V1_FIXTURE).unwrap();
        fs::remove_file(&path).unwrap();
        Keyring::load_from(&path).unwrap();
        assert!(!backup_of(&path).exists());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn default_ring_cannot_overwrite_v1_file() {
        let dir = temp_dir("v1-guard");
        let path = dir.join("keys.json");
        fs::write(&path, V1_FIXTURE).unwrap();
        let mut k = Keyring::default();
        assert!(matches!(k.save_to(&path), Err(KeyringError::Unconverted)));
        k.set_name("00000000", "new", NameStore::Computer, meta())
            .unwrap();
        assert!(matches!(k.save_to(&path), Err(KeyringError::Unconverted)));
        assert_eq!(fs::read_to_string(&path).unwrap(), V1_FIXTURE);
        // A refused save writes nothing else either.
        assert!(!dir.join(SALT_FILE).exists());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn newer_version_is_never_overwritten() {
        let dir = temp_dir("newer");
        let path = dir.join("keys.json");
        let v3 = r#"{"version":3,"keys":[{"whatever":true}]}"#;
        fs::write(&path, v3).unwrap();
        assert!(matches!(
            Keyring::load_from(&path),
            Err(KeyringError::NewerFormat(3))
        ));
        let mut k = Keyring::default();
        assert!(matches!(
            k.save_to(&path),
            Err(KeyringError::NewerFormat(3))
        ));
        assert_eq!(fs::read_to_string(&path).unwrap(), v3);
        fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn failed_persist_keeps_original_and_works_in_memory() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("v1-readonly");
        let path = dir.join("keys.json");
        fs::write(&path, V1_FIXTURE).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
        // Root ignores directory permissions; the test means nothing there.
        let probe = dir.join("probe");
        if fs::write(&probe, b"").is_ok() {
            fs::remove_file(&probe).ok();
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
            fs::remove_dir_all(&dir).ok();
            return;
        }
        let mut k = Keyring::load_from(&path).unwrap();
        let report = k.load_report().unwrap();
        assert_eq!((report.converted, report.persisted), (3, false));
        assert_eq!(k.local_name_for("12345678"), Some("yubi"));
        assert_eq!(fs::read_to_string(&path).unwrap(), V1_FIXTURE);
        assert!(!dir.join(SALT_FILE).exists());
        assert!(!backup_of(&path).exists());

        // Once the directory is writable, the next save finishes the job.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        k.save_to(&path).unwrap();
        let again = Keyring::load_from(&path).unwrap();
        assert!(again.load_report().is_none());
        assert_eq!(again.local_name_for("12345678"), Some("yubi"));
        assert!(!backup_of(&path).exists());
        assert!(!fs::read_to_string(&path).unwrap().contains("12345678"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_salt_unmatches_v2_records() {
        let dir = temp_dir("lost-salt");
        let path = dir.join("keys.json");
        let mut k = Keyring::default();
        k.set_name("12345678", "a", NameStore::Computer, meta())
            .unwrap();
        k.save_to(&path).unwrap();
        fs::remove_file(dir.join(SALT_FILE)).unwrap();

        let mut k = Keyring::load_from(&path).unwrap();
        assert_eq!(k.keys.len(), 1);
        assert_eq!(k.keys[0].fingerprint, None);
        assert_eq!(k.local_name_for("12345678"), None);
        // The name is still held: a key can't silently take it over.
        assert!(k.holder("a").is_some());
        // The next save writes a new salt; the record stays unmatched.
        k.save_to(&path).unwrap();
        assert!(dir.join(SALT_FILE).exists());
        let back = Keyring::load_from(&path).unwrap();
        assert_eq!(back.keys[0].fingerprint, None);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn errors_and_report_never_contain_serials() {
        let dir = temp_dir("no-serial-text");
        let path = dir.join("keys.json");
        fs::write(&path, V1_FIXTURE).unwrap();
        let report = Keyring::load_from(&path).unwrap().load_report().unwrap();
        let mut shown = vec![format!("{report:?}")];
        // Every variant, so a new one has to be added here.
        let all = |e: &KeyringError| match e {
            KeyringError::Io(_)
            | KeyringError::Parse(_)
            | KeyringError::NoConfigDir
            | KeyringError::DuplicateName(_)
            | KeyringError::InvalidName(_)
            | KeyringError::MalformedSalt
            | KeyringError::NoSerial
            | KeyringError::Unconverted
            | KeyringError::NewerFormat(_)
            | KeyringError::Damaged(_) => (),
        };
        let mut errs = vec![
            KeyringError::NoConfigDir,
            KeyringError::MalformedSalt,
            KeyringError::NoSerial,
            KeyringError::Unconverted,
            KeyringError::NewerFormat(3),
            KeyringError::Damaged("invalid JSON".into()),
            KeyringError::Io(io::Error::other("disk full")),
        ];
        let mut k = Keyring::load_from(&path).unwrap();
        errs.push(
            k.set_name("ABCDEF01", "yubi", NameStore::Computer, meta())
                .unwrap_err(),
        );
        errs.push(
            k.set_name("12345678", "x\u{202E}", NameStore::Computer, meta())
                .unwrap_err(),
        );
        for bad in [
            r#"{"keys":[{"name":"x","serial":12345678}]}"#,
            r#"{"keys":[{"name":"x","serial":"ABCDEF01"},{"name":null,"serial":"12345678"}]}"#,
        ] {
            fs::write(&path, bad).unwrap();
            errs.push(Keyring::load_from(&path).unwrap_err());
        }
        for e in &errs {
            all(e);
            shown.push(e.to_string());
            shown.push(format!("{e:?}"));
        }
        for text in shown {
            let t = text.to_lowercase();
            assert!(!t.contains("12345678") && !t.contains("abcdef01"), "{text}");
        }
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn damaged_file_is_never_overwritten() {
        let dir = temp_dir("damaged");
        let path = dir.join("keys.json");
        for bad in [
            b"not json at all".as_slice(),
            br#"{"version":1,"keys":[]}"#,
            br#"{"version":"2","keys":[]}"#,
            br#"{"keys":[{"name":"x"}]}"#,
            br#"{"something":"else"}"#,
            &[0xff, 0xfe, b'{'],
        ] {
            fs::write(&path, bad).unwrap();
            assert!(matches!(
                Keyring::load_from(&path),
                Err(KeyringError::Damaged(_))
            ));
            // The fallback ring a caller builds on a failed load can't save
            // over it, named or not; nothing else is written either.
            let mut empty = Keyring::default();
            assert!(matches!(
                empty.save_to(&path),
                Err(KeyringError::Damaged(_))
            ));
            let mut named = Keyring::default();
            named
                .set_name("12345678", "a", NameStore::Computer, meta())
                .unwrap();
            assert!(matches!(
                named.save_to(&path),
                Err(KeyringError::Damaged(_))
            ));
            assert_eq!(fs::read(&path).unwrap(), bad);
            assert!(!dir.join(SALT_FILE).exists());
        }
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn parse_errors_never_quote_the_file() {
        let dir = temp_dir("parse-err");
        let path = dir.join("keys.json");
        for bad in [
            r#"{"keys":[{"name":"x","serial":12345678}]}"#,
            r#"{"keys":[{"name":"x","serial":"12345678"},{"name":7,"serial":"ABCDEF01"}]}"#,
            r#"{"version":2,"keys":[{"name":"x","stored":"12345678"}]}"#,
            r#"{"keys":[{"name":"x","serial":"12345678""#,
        ] {
            fs::write(&path, bad).unwrap();
            let e = Keyring::load_from(&path).unwrap_err().to_string();
            assert!(matches!(
                Keyring::load_from(&path),
                Err(KeyringError::Damaged(_))
            ));
            assert!(
                !e.contains("12345678") && !e.to_lowercase().contains("abcdef01"),
                "{e}"
            );
        }
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn save_never_pairs_fingerprints_with_a_foreign_salt() {
        let dir = temp_dir("foreign-salt");
        let path = dir.join("keys.json");
        let mut k = Keyring::default();
        k.set_name("12345678", "a", NameStore::Computer, meta())
            .unwrap();
        // Another process writes its own salt first.
        let other = generate_salt().unwrap();
        persist_salt(&dir, &other).unwrap();
        assert!(k.save_to(&path).is_err());
        assert!(!path.exists());
        assert_eq!(load_salt(&dir).unwrap(), Some(other));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn name_validation() {
        // Normal human-facing labels are accepted: any case, spaces, scripts.
        assert!(validate_name("signing-yubikey").is_ok());
        assert!(validate_name("test_solo2").is_ok());
        assert!(validate_name("Emin's Work Key").is_ok());
        assert!(validate_name("UPPER").is_ok());
        assert!(validate_name("Bad Name").is_ok());
        assert!(validate_name("Clé de bureau").is_ok());
        // Empty (or whitespace-only) is still rejected.
        assert!(validate_name("").is_err());
        assert!(validate_name("   ").is_err());
        // Over the length cap is rejected.
        assert!(validate_name(&"x".repeat(65)).is_err());
        // Control / zero-width / bidi-override characters are still rejected.
        assert!(validate_name("bad\u{202E}name").is_err());
        assert!(validate_name("zero\u{200B}width").is_err());
        assert!(validate_name("tab\tname").is_err());
        // Line/paragraph separators and the word-joiner family of invisible
        // format chars (outside the 200B..200F range) are rejected too — they
        // can inject line breaks into or hide content from a terminal listing.
        assert!(validate_name("line\u{2028}sep").is_err());
        assert!(validate_name("para\u{2029}sep").is_err());
        assert!(validate_name("word\u{2060}joiner").is_err());

        // …and the same chars are stripped from a hand-edited field.
        let mut s = "line\u{2028}sep\u{2060}word".to_string();
        strip_control_chars(&mut s);
        assert_eq!(s, "linesepword");
    }

    #[test]
    fn spoofing_char_covers_the_full_hostile_set() {
        // Cc control (ESC), the bidi/zero-width set, and the two gaps the CLI missed:
        // line/paragraph separators, invisible math/format chars, soft hyphen, plus
        // the Mongolian vowel separator and the whole TAG block.
        for c in [
            '\u{001B}', // ESC (Cc)
            '\u{061C}',
            '\u{200B}',
            '\u{200F}',
            '\u{202A}',
            '\u{202E}',
            '\u{2066}',
            '\u{2069}',
            '\u{FEFF}',
            '\u{2028}',
            '\u{2029}',
            '\u{2060}',
            '\u{2064}',
            '\u{00AD}',
            '\u{180E}', // Mongolian vowel separator
            '\u{E0000}',
            '\u{E0020}',
            '\u{E007F}', // TAG block bounds + a tag char
        ] {
            assert!(is_spoofing_char(c), "U+{:04X} must be hostile", c as u32);
        }
        assert!(!is_spoofing_char('a'));
        assert!(!is_spoofing_char('世'));
    }

    #[test]
    fn config_dir_prefers_the_primary_var_and_falls_back_to_the_home_var() {
        use std::ffi::OsStr;
        // Primary set and non-empty wins outright.
        assert_eq!(
            config_dir_from(Some(OsStr::new("/tmp/xdg")), Some(OsStr::new("/home/u"))),
            Some(PathBuf::from("/tmp/xdg").join("keyroost"))
        );
        // Primary unset falls back to <home>/.config/keyroost.
        assert_eq!(
            config_dir_from(None, Some(OsStr::new("/home/u"))),
            Some(PathBuf::from("/home/u").join(".config").join("keyroost"))
        );
        // An EMPTY primary is treated as unset, not as the root directory —
        // otherwise `XDG_CONFIG_HOME=` would resolve to "/keyroost".
        assert_eq!(
            config_dir_from(Some(OsStr::new("")), Some(OsStr::new("/home/u"))),
            Some(PathBuf::from("/home/u").join(".config").join("keyroost"))
        );
        // Nothing usable on either side yields None rather than a relative path.
        assert_eq!(config_dir_from(None, None), None);
        assert_eq!(
            config_dir_from(Some(OsStr::new("")), Some(OsStr::new(""))),
            None
        );
    }

    #[test]
    fn keys_json_and_the_gui_settings_share_one_directory() {
        // The invariant the split must not break: keys.json and settings.json
        // resolve to the same directory, whatever the environment says.
        if let Some(dir) = config_dir() {
            assert_eq!(config_path(), Some(dir.join("keys.json")));
        } else {
            assert_eq!(config_path(), None);
        }
    }
}
