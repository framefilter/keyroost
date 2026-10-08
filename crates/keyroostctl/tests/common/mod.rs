//! Shared setup for tests that spawn `keyroostctl`: every spawn gets a
//! config directory under the system temp dir, so no test can read,
//! convert or overwrite the person's names file (whatever the platform's
//! config variable is: `XDG_CONFIG_HOME`/`HOME`, or `APPDATA`/`USERPROFILE`),
//! and no PC/SC daemon is reachable.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// The config directory spawns use unless a test picks its own.
pub fn default_config_home() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("kr-it-config-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `keyroostctl`, isolated from the real config and from any card.
pub fn keyroostctl() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_keyroostctl"));
    cmd.config_in(&default_config_home())
        // pcsc-lite: no daemon reachable, so nothing can talk to a card.
        .env("PCSCLITE_CSOCK_NAME", "/nonexistent/keyroost-test-no-pcsc");
    cmd
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
