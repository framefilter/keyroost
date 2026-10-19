//! Private, self-deleting scratch directories for files that may hold secrets.
//!
//! The macOS QR-from-screen backend has `screencapture` write screenshots to
//! disk, and a screenshot of a 2FA QR is a seed. A fixed name in the shared
//! temp directory could be pre-created (or symlinked) by another local user
//! and is left behind when the capture fails, so each capture gets a fresh
//! directory instead: a unique name, created owner-only (`0700`) with a plain
//! `mkdir` that fails rather than reuse anything already at that path, and
//! removed with everything in it when the guard drops — on every return path.
//!
//! Unix-only (the `0700` mode is a Unix permission). Only the macOS `qr`
//! backend uses it, but it is built and unit-tested on every Unix so Linux CI
//! exercises it too.

#![cfg_attr(not(all(target_os = "macos", feature = "qr")), allow(dead_code))]

use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// How many fresh names to try before giving up. A collision needs another
/// process to have created exactly `<prefix>-<our pid>-<nanos>-<n>`, so more
/// than one retry means something is deliberately squatting on names.
const CREATE_ATTEMPTS: u32 = 16;

/// An owner-only directory that is deleted, contents and all, when dropped.
pub struct PrivateTempDir {
    path: PathBuf,
}

impl PrivateTempDir {
    /// Create a fresh private directory under the system temp directory.
    pub fn new(prefix: &str) -> io::Result<Self> {
        Self::new_in(&std::env::temp_dir(), prefix)
    }

    /// Create a fresh private directory under `parent`. The name combines the
    /// process id, the current time in nanoseconds and a per-process counter;
    /// an existing entry at that name (file, directory or symlink) is never
    /// reused — `mkdir` refuses it and the next name is tried.
    pub fn new_in(parent: &Path, prefix: &str) -> io::Result<Self> {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        for _ in 0..CREATE_ATTEMPTS {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!("{prefix}-{}-{nanos}-{n}", std::process::id()));
            match std::fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not create a unique private temporary directory",
        ))
    }

    /// The directory's path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PrivateTempDir {
    fn drop(&mut self) {
        // Best effort: nothing useful can be done with a failure here.
        // `remove_dir_all` does not follow symlinks inside the directory.
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn creates_an_owner_only_directory() {
        let dir = PrivateTempDir::new("keyroost-test-private-tmp").unwrap();
        let meta = std::fs::symlink_metadata(dir.path()).unwrap();
        assert!(meta.is_dir());
        assert_eq!(meta.permissions().mode() & 0o777, 0o700);
    }

    #[test]
    fn every_directory_is_fresh() {
        let a = PrivateTempDir::new("keyroost-test-private-tmp").unwrap();
        let b = PrivateTempDir::new("keyroost-test-private-tmp").unwrap();
        assert_ne!(a.path(), b.path());
    }

    #[test]
    fn drop_removes_the_directory_and_its_contents() {
        let dir = PrivateTempDir::new("keyroost-test-private-tmp").unwrap();
        let path = dir.path().to_path_buf();
        std::fs::write(path.join("screen-1.png"), b"not really a png").unwrap();
        std::fs::write(path.join("screen-2.png"), b"nor this").unwrap();
        drop(dir);
        assert!(!path.exists());
    }

    #[test]
    fn drop_removes_the_directory_on_an_early_error_return() {
        fn fails_midway(seen: &mut Option<PathBuf>) -> Result<(), String> {
            let dir =
                PrivateTempDir::new("keyroost-test-private-tmp").map_err(|e| e.to_string())?;
            *seen = Some(dir.path().to_path_buf());
            std::fs::write(dir.path().join("screen-1.png"), b"x").map_err(|e| e.to_string())?;
            Err("capture tool failed".into())
        }
        let mut seen = None;
        assert!(fails_midway(&mut seen).is_err());
        assert!(!seen.unwrap().exists());
    }

    #[test]
    fn a_missing_parent_is_an_error_not_a_retry_loop() {
        let parent = PrivateTempDir::new("keyroost-test-private-tmp").unwrap();
        let missing = parent.path().join("does-not-exist");
        let err = PrivateTempDir::new_in(&missing, "x").err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }
}
