//! Persisted UI preferences for the keyroost desktop GUI.
//!
//! eframe's own storage is disabled in this crate (the `persistence` feature is
//! off, to avoid pulling in three extra crates), so `App::save()` never fires.
//! Instead we persist the handful of UI knobs ourselves to a small JSON file,
//! reusing the exact pattern the `keyroost-keyring` crate uses for `keys.json`:
//! the file lives at `$XDG_CONFIG_HOME/keyroost/settings.json` (else
//! `$HOME/.config/keyroost/settings.json`) and is written atomically and
//! owner-only (temp file + rename, mode 0600).
//!
//! Robustness is the rule: a missing *or* corrupt file falls back to defaults
//! and never panics, and a failed write is swallowed — failing to persist a UI
//! preference must never take the app down.

use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::ui::theme::{self, Mode};

/// The on-disk UI settings (`settings.json`). Every field carries a
/// `#[serde(default)]` so a partial or older file still loads — any missing key
/// takes the default rather than failing the whole parse.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Settings {
    /// egui global zoom factor ("Text size"). Clamped via [`theme::clamp_zoom`]
    /// on the way out and on the way in.
    #[serde(default = "default_zoom")]
    pub zoom: f32,
    /// Theme mode. Stored as the strings `"dark"` / `"light"` (matching the old
    /// eframe-storage encoding) so a hand-edit reads naturally; any other value
    /// falls back to dark.
    #[serde(default)]
    pub mode: ModeSetting,
    /// Accent-color index into `Palette::ACCENTS`. Clamped on load.
    #[serde(default)]
    pub accent: usize,
    /// Colorblind-safe palette toggle.
    #[serde(default)]
    pub colorblind: bool,
}

fn default_zoom() -> f32 {
    theme::ZOOM_DEFAULT
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            zoom: theme::ZOOM_DEFAULT,
            mode: ModeSetting::default(),
            accent: 0,
            colorblind: false,
        }
    }
}

/// Serde-friendly mirror of [`Mode`] (which lives in the theme module and does
/// not derive `Serialize`). Encodes as the lowercase strings `"dark"` /
/// `"light"`; an unknown string deserializes to `Dark`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModeSetting {
    #[default]
    Dark,
    Light,
}

impl From<Mode> for ModeSetting {
    fn from(m: Mode) -> Self {
        match m {
            Mode::Dark => ModeSetting::Dark,
            Mode::Light => ModeSetting::Light,
        }
    }
}

impl From<ModeSetting> for Mode {
    fn from(m: ModeSetting) -> Self {
        match m {
            ModeSetting::Dark => Mode::Dark,
            ModeSetting::Light => Mode::Light,
        }
    }
}

/// Default config path: `$XDG_CONFIG_HOME/keyroost/settings.json`, else
/// `$HOME/.config/keyroost/settings.json`. Mirrors `keyroost_keyring::config_path`
/// (plain `std::env`, no path crate) so both files land in the same directory.
pub fn config_path() -> Option<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return Some(PathBuf::from(xdg).join("keyroost").join("settings.json"));
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
            .join("settings.json"),
    )
}

impl Settings {
    /// Load from the default config path. A missing config dir, a missing file,
    /// or a corrupt file all yield defaults — this never returns an error and
    /// never panics.
    pub fn load() -> Settings {
        match config_path() {
            Some(path) => Self::load_from(&path),
            None => Settings::default(),
        }
    }

    /// Load from a specific path. Missing or corrupt → defaults. The loaded
    /// values are sanitized (zoom clamped, accent index left for the caller to
    /// clamp against the live accent count).
    pub fn load_from(path: &Path) -> Settings {
        let mut s = match fs::read_to_string(path) {
            Ok(text) => serde_json::from_str::<Settings>(&text).unwrap_or_default(),
            // Missing file, permission error, corrupt JSON — anything at all —
            // is a non-event: fall back to the shipped defaults.
            Err(_) => Settings::default(),
        };
        // A hand-edited or stale zoom must never escape the supported range.
        s.zoom = theme::clamp_zoom(s.zoom);
        s
    }

    /// Persist to the default config path. Best-effort: any failure (no config
    /// dir, IO error) is swallowed so a UI preference that won't save can't
    /// break the app.
    pub fn save(&self) {
        if let Some(path) = config_path() {
            let _ = self.save_to(&path);
        }
    }

    /// Persist to a specific path, creating parent dirs. Writes a sibling temp
    /// file owner-only (0600) and renames it into place, so a crash mid-write
    /// can't corrupt the file and the file never inherits a world-readable
    /// umask default. Mirrors `keyroost_keyring::Keyring::save_to`.
    pub fn save_to(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
            // Tighten the directory to owner-only too, but only when it looks
            // like ours and is currently group/other-accessible — an existing
            // dir the user deliberately opened up is left alone.
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
        // Clamp the zoom one last time so a corrupt in-memory value never lands
        // on disk.
        let on_disk = Settings {
            zoom: theme::clamp_zoom(self.zoom),
            ..self.clone()
        };
        let json = serde_json::to_string_pretty(&on_disk)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let tmp = path.with_extension("json.tmp");
        // Remove any stale temp file so `create_new` below can succeed.
        // `create_new` (not `create`) matters twice: a pre-existing file would
        // keep its old permissions (0o600 only applies at creation), and a
        // symlink planted at the temp path would otherwise be followed.
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_round_trip() {
        let s = Settings {
            zoom: 1.25,
            mode: ModeSetting::Light,
            accent: 2,
            colorblind: true,
        };
        let json = serde_json::to_string_pretty(&s).unwrap();
        let back: Settings = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
        assert_eq!(back.mode, ModeSetting::Light);
        assert_eq!(back.accent, 2);
        assert!(back.colorblind);
        assert_eq!(back.zoom, 1.25);
    }

    #[test]
    fn mode_encodes_as_lowercase_strings() {
        let dark = serde_json::to_string(&ModeSetting::Dark).unwrap();
        let light = serde_json::to_string(&ModeSetting::Light).unwrap();
        assert_eq!(dark, "\"dark\"");
        assert_eq!(light, "\"light\"");
    }

    #[test]
    fn missing_file_is_defaults() {
        let s = Settings::load_from(Path::new("/nonexistent/keyroost/settings.json"));
        assert_eq!(s, Settings::default());
        assert_eq!(s.mode, ModeSetting::Dark);
        assert_eq!(s.zoom, theme::ZOOM_DEFAULT);
    }

    #[test]
    fn corrupt_json_is_defaults() {
        // Garbage that is not JSON at all, and JSON of the wrong shape, both
        // fall back to defaults rather than panicking.
        let garbage: Settings = serde_json::from_str("not json {{{").unwrap_or_default();
        assert_eq!(garbage, Settings::default());
        let wrong_shape: Settings = serde_json::from_str("[1, 2, 3]").unwrap_or_default();
        assert_eq!(wrong_shape, Settings::default());
    }

    #[test]
    fn partial_json_fills_defaults() {
        // An older/partial file with only some keys loads the rest as defaults.
        let s: Settings = serde_json::from_str(r#"{"accent": 1}"#).unwrap();
        assert_eq!(s.accent, 1);
        assert_eq!(s.mode, ModeSetting::Dark);
        assert_eq!(s.zoom, theme::ZOOM_DEFAULT);
        assert!(!s.colorblind);
    }

    #[test]
    fn bad_zoom_is_clamped_on_load() {
        // A wildly out-of-range or NaN zoom is clamped (clamp_zoom maps junk to
        // the default) — exercised through load_from via a temp file.
        let dir = std::env::temp_dir().join(format!("keyroost-settings-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("settings.json");
        std::fs::write(&path, r#"{"zoom": 999.0, "mode": "light"}"#).unwrap();
        let s = Settings::load_from(&path);
        assert_eq!(s.zoom, theme::ZOOM_MAX);
        assert_eq!(s.mode, ModeSetting::Light);
        std::fs::write(&path, r#"{"zoom": -5.0}"#).unwrap();
        assert_eq!(Settings::load_from(&path).zoom, theme::ZOOM_DEFAULT);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn save_creates_owner_only_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir =
            std::env::temp_dir().join(format!("keyroost-settings-perm-{}", std::process::id()));
        let path = dir.join("settings.json");
        let s = Settings {
            zoom: 1.5,
            mode: ModeSetting::Light,
            accent: 1,
            colorblind: true,
        };
        s.save_to(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "settings.json must be owner-only");
        // It reloads to the same values.
        assert_eq!(Settings::load_from(&path), s);
        // No temp file left behind.
        assert!(!path.with_extension("json.tmp").exists());
        std::fs::remove_dir_all(&dir).ok();
    }
}
