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
    DuplicateSerial { serial: String, existing_name: String },
    InvalidName(String),
}

impl fmt::Display for KeyringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyringError::Io(e) => write!(f, "keyring I/O error: {}", e),
            KeyringError::Parse(s) => write!(f, "keyring config parse error: {}", s),
            KeyringError::NoConfigDir => {
                write!(f, "could not determine config dir (set HOME or XDG_CONFIG_HOME)")
            }
            KeyringError::DuplicateName(n) => write!(f, "a key named '{}' already exists", n),
            KeyringError::DuplicateSerial { serial, existing_name } => {
                write!(f, "serial {} is already named '{}'", serial, existing_name)
            }
            KeyringError::InvalidName(n) => {
                write!(f, "invalid key name '{}': use 1-64 chars of [a-z0-9_-]", n)
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
                write!(f, "no key named '{}'. Known names: {}", name, known.join(", "))
            }
            ResolveError::NotConnected { name, serial } => {
                write!(f, "key '{}' (serial {}) is not connected", name, serial)
            }
        }
    }
}

impl std::error::Error for ResolveError {}

/// Validate a friendly name: 1-64 chars of lowercase ASCII, digits, `-`, `_`.
pub fn validate_name(name: &str) -> Result<(), KeyringError> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    if ok {
        Ok(())
    } else {
        Err(KeyringError::InvalidName(name.to_string()))
    }
}

/// Default config path: `$XDG_CONFIG_HOME/keyroost/keys.json`, else
/// `$HOME/.config/keyroost/keys.json`.
pub fn config_path() -> Option<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return Some(PathBuf::from(xdg).join("keyroost").join("keys.json"));
        }
    }
    let home = std::env::var_os("HOME")?;
    if home.is_empty() {
        return None;
    }
    Some(PathBuf::from(home).join(".config").join("keyroost").join("keys.json"))
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
            Ok(s) => serde_json::from_str(&s).map_err(|e| KeyringError::Parse(e.to_string())),
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
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| KeyringError::Parse(e.to_string()))?;
        fs::write(path, json + "\n")?;
        Ok(())
    }

    /// Add a new entry. Rejects duplicate names and duplicate serials.
    pub fn add(&mut self, entry: KeyEntry) -> Result<(), KeyringError> {
        validate_name(&entry.name)?;
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
        let entry = self.by_name(name).ok_or_else(|| ResolveError::UnknownName {
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
        assert!(validate_name("signing-yubikey").is_ok());
        assert!(validate_name("test_solo2").is_ok());
        assert!(validate_name("").is_err());
        assert!(validate_name("Bad Name").is_err());
        assert!(validate_name("UPPER").is_err());
    }

    #[test]
    fn add_rejects_duplicates() {
        let mut k = Keyring::default();
        k.add(entry("a", "111")).unwrap();
        assert!(matches!(k.add(entry("a", "222")), Err(KeyringError::DuplicateName(_))));
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
            ConnectedKey { path: "/dev/hidraw5".into(), serial: Some("ABC".into()), label: "Solo 2".into() },
            ConnectedKey { path: "/dev/hidraw9".into(), serial: None, label: "YubiKey".into() },
        ];
        assert_eq!(k.resolve("solo", &connected).unwrap().path, PathBuf::from("/dev/hidraw5"));
        assert!(matches!(k.resolve("nope", &connected), Err(ResolveError::UnknownName { .. })));
        assert!(matches!(k.resolve("solo", &[]), Err(ResolveError::NotConnected { .. })));
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
        let minimal: Keyring = serde_json::from_str(r#"{"keys":[{"name":"x","serial":"S1"}]}"#).unwrap();
        assert_eq!(minimal.keys[0].source, IdSource::Usb);
    }

    #[test]
    fn load_missing_is_empty() {
        let k = Keyring::load_from(Path::new("/nonexistent/keyroost/keys.json")).unwrap();
        assert!(k.keys.is_empty());
    }
}
