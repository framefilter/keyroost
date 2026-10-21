//! Shared setup for tests that spawn `keyroostctl`: every spawn gets a
//! config directory under the system temp dir, so no test can read,
//! convert or overwrite the person's names file (whatever the platform's
//! config variable is: `XDG_CONFIG_HOME`/`HOME`, or `APPDATA`/`USERPROFILE`),
//! and no PC/SC daemon is reachable.
#![allow(dead_code)]

use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Per-process counter, so no two folders in one test binary share a name.
static SEQ: AtomicUsize = AtomicUsize::new(0);

/// A fresh folder under the system temp dir, removed when dropped: also
/// when the test that made it fails, since a panic still runs the drop.
/// (Folders made by hand were left behind on every run, and on every
/// failure for the ones removed by hand.)
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "kr-it-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Deref for TempDir {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for TempDir {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A `keyroostctl` command with its own empty config folder, which is
/// removed when this is dropped. Derefs to [`Command`], so
/// `keyroostctl().args(..).output()` works as on a `Command`; the folder
/// lives to the end of that statement, after the process has finished.
pub struct Isolated {
    cmd: Command,
    _config: TempDir,
}

impl Deref for Isolated {
    type Target = Command;
    fn deref(&self) -> &Command {
        &self.cmd
    }
}

impl DerefMut for Isolated {
    fn deref_mut(&mut self) -> &mut Command {
        &mut self.cmd
    }
}

/// `keyroostctl`, isolated from the real config and from any card.
pub fn keyroostctl() -> Isolated {
    let config = TempDir::new("config");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_keyroostctl"));
    cmd.config_in(config.path())
        // pcsc-lite: no daemon reachable, so nothing can talk to a card.
        .env("PCSCLITE_CSOCK_NAME", "/nonexistent/keyroost-test-no-pcsc");
    Isolated {
        cmd,
        _config: config,
    }
}

pub trait ConfigIn {
    /// Point every variable the config directory is derived from at
    /// `dir`, which must lie under the system temp dir.
    fn config_in(&mut self, dir: &Path) -> &mut Self;
}

impl ConfigIn for Command {
    fn config_in(&mut self, dir: &Path) -> &mut Self {
        assert!(
            dir.starts_with(std::env::temp_dir()),
            "test config dir {dir:?} must be under the temp dir"
        );
        self.env("XDG_CONFIG_HOME", dir)
            .env("HOME", dir)
            .env("APPDATA", dir)
            .env("USERPROFILE", dir)
    }
}
