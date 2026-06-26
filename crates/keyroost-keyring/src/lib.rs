//! Friendly-name registry for security keys, plus device-identity resolution.
//!
//! Lets a user attach a memorable label (e.g. `signing-yubikey`) to a physical
//! key, matched by its stable **serial number**, so commands can target a key
//! by `--name` instead of a `/dev/hidrawN` path that changes on every replug.
//!
//! This crate is pure config + matching logic: it has no hardware or PC/SC
//! dependencies and never enumerates devices itself. The caller supplies the
//! list of connected devices (as [`ConnectedKey`]) — for the CLI that's the
//! HID enumeration plus, for keys without a USB serial, a CCID-read serial.
//! Front-end concerns (interactive pickers, TTY handling, confirmations) live
//! in the caller, so both the CLI and the GUI reuse this same core.
//!
//! ## Privacy
//!
//! Persisting a key's serial to disk is **opt-in**: nothing is written unless
//! the caller explicitly invokes [`Keyring::save_to`] / [`Keyring::save_default`]
//! (i.e. the user ran an "add a name" action). Loading and in-memory matching
//! record nothing.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// How a key's serial is obtained — recorded for display/diagnostics. Matching
/// is always by serial-string equality regardless of source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum IdSource {
    /// USB `iSerialNumber` (read from sysfs; SoloKeys, Nitrokey, …).
    #[default]
    Usb,
    /// Serial read from a vendor management applet over CCID (e.g. YubiKey).
    Ccid,
}

/// One named key in the registry. `serial` is the match key; `name` is the
/// unique user-facing label.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEntry {
    pub name: String,
    pub serial: String,
    #[serde(default)]
    pub source: IdSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aaguid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// The on-disk registry (`keys.json`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Keyring {
    #[serde(default)]
    pub keys: Vec<KeyEntry>,
}

/// A currently-connected device as seen by the resolver. The caller builds
/// these from device enumeration; `serial` is the device's effective serial
/// (USB or CCID), `None` if it couldn't be determined.
#[derive(Debug, Clone)]
pub struct ConnectedKey {
    pub path: PathBuf,
    pub serial: Option<String>,
    pub label: String,
}

/// Errors loading, saving, or mutating the registry.
#[derive(Debug)]
pub enum KeyringError {
    Io(io::Error),
    Parse(String),
    NoConfigDir,
    DuplicateName(String),
    DuplicateSerial {
        serial: String,
        existing_name: String,
    },
    InvalidName(String),
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
            KeyringError::DuplicateSerial {
                serial,
                existing_name,
            } => {
                write!(f, "serial {} is already named '{}'", serial, existing_name)
            }
            KeyringError::InvalidName(n) => {
                write!(
                    f,
                    "invalid key name '{}': must be 1-64 characters and free of control, zero-width, and bidi-override characters",
                    n
                )
            }
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

/// Errors resolving a `--name` to a connected device.
#[derive(Debug)]
pub enum ResolveError {
    UnknownName { name: String, known: Vec<String> },
    NotConnected { name: String, serial: String },
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResolveError::UnknownName { name, known } if known.is_empty() => write!(
                f,
                "no key named '{}': no named keys yet — add one with `keyroostctl key-name add`",
                name
            ),
            ResolveError::UnknownName { name, known } => {
                write!(
                    f,
                    "no key named '{}'. Known names: {}",
                    name,
                    known.join(", ")
                )
            }
            ResolveError::NotConnected { name, serial } => {
                write!(f, "key '{}' (serial {}) is not connected", name, serial)
            }
        }
    }
}

impl std::error::Error for ResolveError {}

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
/// spoofing in a saved name. Shared by validation and sanitization.
fn is_spoofing_char(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{200B}'..='\u{200F}' // zero-width space/joiners, LRM/RLM
            | '\u{202A}'..='\u{202E}' // bidi embeddings + LRO/RLO
            | '\u{2028}' // line separator (Zl)
            | '\u{2029}' // paragraph separator (Zp)
            | '\u{2060}'..='\u{2064}' // word joiner + invisible format chars
            | '\u{2066}'..='\u{2069}' // bidi isolates
            | '\u{FEFF}' // BOM / ZWNBSP
            | '\u{00AD}' // soft hyphen
            | '\u{061C}' // Arabic letter mark
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

/// Default config path for `keys.json`.
///
/// * Windows: `%APPDATA%\keyroost\keys.json` (falling back to
///   `%USERPROFILE%\.config\keyroost\keys.json`).
/// * Otherwise: `$XDG_CONFIG_HOME/keyroost/keys.json`, else
///   `$HOME/.config/keyroost/keys.json`.
pub fn config_path() -> Option<PathBuf> {
    // Windows has no HOME/XDG by default; use the standard roaming AppData dir.
    #[cfg(windows)]
    {
        if let Some(appdata) = std::env::var_os("APPDATA") {
            if !appdata.is_empty() {
                return Some(PathBuf::from(appdata).join("keyroost").join("keys.json"));
            }
        }
        if let Some(profile) = std::env::var_os("USERPROFILE") {
            if !profile.is_empty() {
                return Some(
                    PathBuf::from(profile)
                        .join(".config")
                        .join("keyroost")
                        .join("keys.json"),
                );
            }
        }
        None
    }
    #[cfg(not(windows))]
    {
        if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
            if !xdg.is_empty() {
                return Some(PathBuf::from(xdg).join("keyroost").join("keys.json"));
            }
        }
        let home = std::env::var_os("HOME")?;
        if home.is_empty() {
            return None;
        }
        Some(
            PathBuf::from(home)
                .join(".config")
                .join("keyroost")
                .join("keys.json"),
        )
    }
}

impl Keyring {
    /// Load from the default config path. A missing file yields an empty
    /// registry (reading records nothing).
    pub fn load_default() -> Result<Keyring, KeyringError> {
        let path = config_path().ok_or(KeyringError::NoConfigDir)?;
        Self::load_from(&path)
    }

    /// Load from a specific path. A missing file yields an empty registry.
    pub fn load_from(path: &Path) -> Result<Keyring, KeyringError> {
        match fs::read_to_string(path) {
            Ok(s) => {
                let mut ring: Keyring =
                    serde_json::from_str(&s).map_err(|e| KeyringError::Parse(e.to_string()))?;
                // `add` validates names before they ever reach disk; on the
                // way back in every field — including the name — is sanitized
                // rather than rejected. Rejecting would make one hand-edited
                // entry render the whole registry unloadable, and callers
                // that fall back to an empty registry on error would then
                // overwrite keys.json and destroy every other entry on the
                // next save.
                for entry in &mut ring.keys {
                    strip_control_chars(&mut entry.name);
                    strip_control_chars(&mut entry.serial);
                    for field in [&mut entry.vendor, &mut entry.aaguid, &mut entry.note]
                        .into_iter()
                        .flatten()
                    {
                        strip_control_chars(field);
                    }
                }
                Ok(ring)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Keyring::default()),
            Err(e) => Err(KeyringError::Io(e)),
        }
    }

    /// Persist to the default config path, creating parent dirs. Opt-in: only
    /// call this from an explicit user action. Returns the path written.
    pub fn save_default(&self) -> Result<PathBuf, KeyringError> {
        let path = config_path().ok_or(KeyringError::NoConfigDir)?;
        self.save_to(&path)?;
        Ok(path)
    }

    /// Persist to a specific path, creating parent dirs. Opt-in.
    pub fn save_to(&self, path: &Path) -> Result<(), KeyringError> {
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
        let json =
            serde_json::to_string_pretty(self).map_err(|e| KeyringError::Parse(e.to_string()))?;
        // Write a sibling temp file and rename into place: a crash mid-write
        // can no longer corrupt the registry, and the file is created
        // owner-only — which security keys a person owns is their business —
        // instead of inheriting the umask default (typically world-readable).
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
            f.write_all(json.as_bytes())?;
            f.write_all(b"\n")?;
            f.sync_all()?;
        }
        fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Add a new entry. Rejects duplicate names and duplicate serials.
    pub fn add(&mut self, mut entry: KeyEntry) -> Result<(), KeyringError> {
        validate_name(&entry.name)?;
        // Sanitize on the way in with the same rules `load_from` applies on
        // the way out, so a device-reported serial (or note) containing
        // control characters is stored exactly as it will round-trip —
        // otherwise the value would silently mutate on the next load, and
        // duplicate-serial detection would compare against a phantom.
        strip_control_chars(&mut entry.serial);
        for field in [&mut entry.vendor, &mut entry.aaguid, &mut entry.note]
            .into_iter()
            .flatten()
        {
            strip_control_chars(field);
        }
        if self.keys.iter().any(|k| k.name == entry.name) {
            return Err(KeyringError::DuplicateName(entry.name));
        }
        if let Some(existing) = self.keys.iter().find(|k| k.serial == entry.serial) {
            return Err(KeyringError::DuplicateSerial {
                serial: entry.serial.clone(),
                existing_name: existing.name.clone(),
            });
        }
        self.keys.push(entry);
        Ok(())
    }

    /// Remove the entry with `name`. Returns true if one was removed.
    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.keys.len();
        self.keys.retain(|k| k.name != name);
        self.keys.len() != before
    }

    pub fn by_name(&self, name: &str) -> Option<&KeyEntry> {
        self.keys.iter().find(|k| k.name == name)
    }

    pub fn by_serial(&self, serial: &str) -> Option<&KeyEntry> {
        self.keys.iter().find(|k| k.serial == serial)
    }

    /// The friendly name for a connected device's serial, if one is registered.
    /// Used by `list` to annotate devices.
    pub fn name_for(&self, serial: Option<&str>) -> Option<&str> {
        let serial = serial?;
        self.by_serial(serial).map(|k| k.name.as_str())
    }

    /// Resolve a `--name` to a connected device by matching serials.
    pub fn resolve<'a>(
        &self,
        name: &str,
        connected: &'a [ConnectedKey],
    ) -> Result<&'a ConnectedKey, ResolveError> {
        let entry = self
            .by_name(name)
            .ok_or_else(|| ResolveError::UnknownName {
                name: name.to_string(),
                known: self.keys.iter().map(|k| k.name.clone()).collect(),
            })?;
        connected
            .iter()
            .find(|d| d.serial.as_deref() == Some(entry.serial.as_str()))
            .ok_or_else(|| ResolveError::NotConnected {
                name: name.to_string(),
                serial: entry.serial.clone(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, serial: &str) -> KeyEntry {
        KeyEntry {
            name: name.into(),
            serial: serial.into(),
            source: IdSource::Usb,
            vendor: None,
            aaguid: None,
            note: None,
        }
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
    fn add_rejects_duplicates() {
        let mut k = Keyring::default();
        k.add(entry("a", "111")).unwrap();
        assert!(matches!(
            k.add(entry("a", "222")),
            Err(KeyringError::DuplicateName(_))
        ));
        assert!(matches!(
            k.add(entry("b", "111")),
            Err(KeyringError::DuplicateSerial { .. })
        ));
        k.add(entry("b", "222")).unwrap();
        assert_eq!(k.keys.len(), 2);
    }

    #[test]
    fn remove_and_lookup() {
        let mut k = Keyring::default();
        k.add(entry("solo", "ABC")).unwrap();
        assert_eq!(k.by_name("solo").map(|e| e.serial.as_str()), Some("ABC"));
        assert_eq!(k.name_for(Some("ABC")), Some("solo"));
        assert_eq!(k.name_for(Some("XYZ")), None);
        assert_eq!(k.name_for(None), None);
        assert!(k.remove("solo"));
        assert!(!k.remove("solo"));
    }

    #[test]
    fn resolve_matches_by_serial() {
        let mut k = Keyring::default();
        k.add(entry("solo", "ABC")).unwrap();
        let connected = vec![
            ConnectedKey {
                path: "/dev/hidraw5".into(),
                serial: Some("ABC".into()),
                label: "Solo 2".into(),
            },
            ConnectedKey {
                path: "/dev/hidraw9".into(),
                serial: None,
                label: "YubiKey".into(),
            },
        ];
        assert_eq!(
            k.resolve("solo", &connected).unwrap().path,
            PathBuf::from("/dev/hidraw5")
        );
        assert!(matches!(
            k.resolve("nope", &connected),
            Err(ResolveError::UnknownName { .. })
        ));
        assert!(matches!(
            k.resolve("solo", &[]),
            Err(ResolveError::NotConnected { .. })
        ));
    }

    #[test]
    fn json_round_trip_and_defaults() {
        let mut k = Keyring::default();
        k.add(KeyEntry {
            name: "signing-yubikey".into(),
            serial: "37806840".into(),
            source: IdSource::Ccid,
            vendor: Some("yubico".into()),
            aaguid: None,
            note: Some("daily".into()),
        })
        .unwrap();
        let json = serde_json::to_string_pretty(&k).unwrap();
        let back: Keyring = serde_json::from_str(&json).unwrap();
        assert_eq!(back.keys[0].name, "signing-yubikey");
        assert_eq!(back.keys[0].source, IdSource::Ccid);
        assert_eq!(back.keys[0].vendor.as_deref(), Some("yubico"));

        // `source` defaults to Usb when absent in JSON.
        let minimal: Keyring =
            serde_json::from_str(r#"{"keys":[{"name":"x","serial":"S1"}]}"#).unwrap();
        assert_eq!(minimal.keys[0].source, IdSource::Usb);
    }

    #[test]
    fn load_missing_is_empty() {
        let k = Keyring::load_from(Path::new("/nonexistent/keyroost/keys.json")).unwrap();
        assert!(k.keys.is_empty());
    }

    #[test]
    fn load_sanitizes_invalid_names_and_strips_control_chars() {
        let dir = std::env::temp_dir().join(format!("keyroost-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keys.json");

        // A name with an ANSI escape is sanitized, not fatal: one bad
        // hand-edited entry must never make the whole registry unloadable
        // (an unwrap_or_default + save would wipe every other entry).
        std::fs::write(
            &path,
            "{\"keys\":[{\"name\":\"evil\\u001b[31m\",\"serial\":\"S1\"},{\"name\":\"good\",\"serial\":\"S2\"}]}",
        )
        .unwrap();
        let k = Keyring::load_from(&path).unwrap();
        assert_eq!(k.keys[0].name, "evil[31m");
        assert_eq!(k.keys[1].name, "good");

        // Control chars in free-text fields are stripped, not fatal.
        std::fs::write(
            &path,
            "{\"keys\":[{\"name\":\"ok\",\"serial\":\"S\\u001b[2J1\",\"note\":\"a\\u0007b\"}]}",
        )
        .unwrap();
        let k = Keyring::load_from(&path).unwrap();
        assert_eq!(k.keys[0].serial, "S[2J1");
        assert_eq!(k.keys[0].note.as_deref(), Some("ab"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn add_sanitizes_device_supplied_fields() {
        // A device-reported serial with control chars must be stored in the
        // same form load_from would produce, or the entry mutates on reload.
        let mut k = Keyring::default();
        k.add(KeyEntry {
            name: "weird".into(),
            serial: "AB\u{1b}[31mCD".into(),
            source: IdSource::Usb,
            vendor: None,
            aaguid: None,
            note: Some("x\u{7}y".into()),
        })
        .unwrap();
        assert_eq!(k.keys[0].serial, "AB[31mCD");
        assert_eq!(k.keys[0].note.as_deref(), Some("xy"));

        // Unicode format chars (Cf) used for display spoofing go too: RLO
        // would render "evil-yek" as "key-live" in a terminal listing.
        let mut k2 = Keyring::default();
        k2.add(KeyEntry {
            name: "bidi".into(),
            serial: "S\u{202E}9\u{200B}9".into(),
            source: IdSource::Usb,
            vendor: None,
            aaguid: None,
            note: None,
        })
        .unwrap();
        assert_eq!(k2.keys[0].serial, "S99");
    }

    #[cfg(unix)]
    #[test]
    fn save_creates_owner_only_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("keyroost-perm-{}", std::process::id()));
        let path = dir.join("keys.json");
        let mut k = Keyring::default();
        k.add(KeyEntry {
            name: "test-key".into(),
            serial: "S1".into(),
            source: IdSource::Usb,
            vendor: None,
            aaguid: None,
            note: None,
        })
        .unwrap();
        k.save_to(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "keys.json must be owner-only");
        // No temp file left behind.
        assert!(!path.with_extension("json.tmp").exists());
        std::fs::remove_dir_all(&dir).ok();
    }
}
