//! Writing a file that holds a secret (a vault backup, a decrypted key, a
//! private key's backup): owner-only, never through a link someone planted,
//! never left half-written. The CLI writes its secret outputs with
//! [`write_private_file`] and the app writes vault backups with it, so both
//! refuse the same things (KEY-014).

/// The error text of a [`OutMode::New`] write that found a file at its
/// path: one appeared after the caller checked, and it was left as it is.
/// A front end may match on it to add how to replace it.
pub const APPEARED: &str = "a file appeared there after it was checked and was not replaced";

/// How an output file is written once the caller has checked what is
/// there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutMode {
    /// Nothing was there at check time: create it, and fail with
    /// [`APPEARED`] rather than replace a file that appeared since.
    New,
    /// Replacing whatever is there was agreed.
    Replace,
}

impl OutMode {
    /// Open `path` for writing in this mode. `New` reports a file that
    /// appeared since the check as [`APPEARED`].
    pub fn open(self, path: &std::path::Path) -> std::io::Result<std::fs::File> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true);
        match self {
            OutMode::New => opts.create_new(true),
            OutMode::Replace => opts.create(true).truncate(true),
        };
        opts.open(path).map_err(|e| {
            if self == OutMode::New && e.kind() == std::io::ErrorKind::AlreadyExists {
                std::io::Error::new(std::io::ErrorKind::AlreadyExists, APPEARED)
            } else {
                e
            }
        })
    }

    /// Write `data` to `path` in this mode.
    pub fn write(self, path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
        use std::io::Write;
        self.open(path)?.write_all(data)
    }
}

/// Write `data` to `path` with owner-only permissions (0600) on Unix, failing
/// closed against local path attacks (KEY-014). A local attacker who pre-plants
/// a symlink or a file they own at a predictable secret-output path must not be
/// able to capture the plaintext or have keyroost clobber an arbitrary file.
///
/// Strategy (Unix): reject a pre-existing symlink or non-regular / foreign-owned
/// destination outright, then write the secret only into a fresh `create_new`
/// temp file we exclusively own (0600 enforced as fatal) and atomically rename
/// it over the destination. Because bytes never touch the caller-supplied path
/// directly, no write can be redirected through an attacker's link.
#[cfg(unix)]
pub fn write_private_file(
    path: &std::path::Path,
    data: &[u8],
    mode: OutMode,
) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind, Write};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    // Nothing was there at check time: create it exclusively (O_CREAT|O_EXCL
    // never follows a link and fails if anything appeared since), owner-only
    // from the start.
    if mode == OutMode::New {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true).mode(0o600);
        let f = opts.open(path).map_err(|e| {
            if e.kind() == ErrorKind::AlreadyExists {
                Error::new(ErrorKind::AlreadyExists, APPEARED)
            } else {
                e
            }
        })?;
        return fill_new_file(path, f, data, |f| f.sync_all());
    }

    // 1) Create the temp file first. create_new = O_CREAT|O_EXCL, which refuses
    //    to follow a symlink at the final component and fails if the path already
    //    exists — so this file is unambiguously fresh and owned by our euid.
    let tmp = temp_beside(path)?;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true).mode(0o600);
    let mut f = opts.open(&tmp)?;
    // Our euid, established from a file we just created (owned by us by definition).
    let our_uid = f.metadata()?.uid();

    // 2) Vet the real destination via lstat (no symlink follow). Fail closed on a
    //    symlink, a non-regular file, or a file owned by someone else.
    let vet = |e: Error| {
        let _ = std::fs::remove_file(&tmp);
        e
    };
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            let ft = meta.file_type();
            if ft.is_symlink() {
                return Err(vet(Error::new(
                    ErrorKind::AlreadyExists,
                    "refusing to write secret output through a symlink",
                )));
            }
            if !ft.is_file() {
                return Err(vet(Error::new(
                    ErrorKind::AlreadyExists,
                    "refusing to write secret output to a non-regular file",
                )));
            }
            if meta.uid() != our_uid {
                return Err(vet(Error::new(
                    ErrorKind::PermissionDenied,
                    "refusing to overwrite a secret-output file owned by another user",
                )));
            }
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {} // fresh output is fine
        Err(e) => return Err(vet(e)),
    }

    // 3) Write the secret into the temp, enforcing 0600 as FATAL before any
    //    bytes: never fall through to writing under looser permissions.
    if let Err(e) = f.set_permissions(std::fs::Permissions::from_mode(0o600)) {
        return Err(vet(e));
    }
    if let Err(e) = f.write_all(data).and_then(|_| f.sync_all()) {
        return Err(vet(e));
    }
    drop(f);

    // 4) Atomically replace the destination. rename() operates on the link/name
    //    itself, so even a symlink swapped in after step 2 is replaced rather
    //    than written through.
    if let Err(e) = std::fs::rename(&tmp, path) {
        return Err(vet(e));
    }
    Ok(())
}

/// Non-Unix fallback: a new file is created exclusively; an agreed
/// overwrite goes through a temp file renamed over the old one
/// (`replace_via_temp`), so a failed write never leaves the old file
/// truncated. Windows ACL hardening is out of scope for this helper.
#[cfg(not(unix))]
pub fn write_private_file(
    path: &std::path::Path,
    data: &[u8],
    mode: OutMode,
) -> std::io::Result<()> {
    match mode {
        OutMode::New => fill_new_file(path, mode.open(path)?, data, |f| f.sync_all()),
        OutMode::Replace => replace_via_temp(
            path,
            data,
            |tmp| {
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(tmp)
            },
            |f| f.sync_all(),
        ),
    }
}

/// The temp file a replacing write goes through: hidden, beside `path` (so
/// the rename stays on one file system), named for this process.
fn temp_beside(path: &std::path::Path) -> std::io::Result<std::path::PathBuf> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let fname = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "output path has no file name",
        )
    })?;
    Ok(parent.join(format!(
        ".{}.keyroost-tmp-{}",
        fname.to_string_lossy(),
        std::process::id()
    )))
}

/// Replace `path` with `data` without truncating it in place: `open` makes
/// a fresh temp file beside it (exclusively, so it is this run's own),
/// `data` is written and synced there, then the temp is renamed over
/// `path`. A write or rename that fails removes the temp and leaves the old
/// file whole. A symbolic link at `path` is refused, never written through.
/// The non-Unix replacing write (Unix has its own, with owner and 0600
/// checks); `open` and `sync` are seams for tests.
#[cfg_attr(all(unix, not(test)), allow(dead_code))]
fn replace_via_temp<W: std::io::Write>(
    path: &std::path::Path,
    data: &[u8],
    open: impl FnOnce(&std::path::Path) -> std::io::Result<W>,
    sync: impl FnOnce(&mut W) -> std::io::Result<()>,
) -> std::io::Result<()> {
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "refusing to write secret output through a symlink",
        ));
    }
    let tmp = temp_beside(path)?;
    fill_new_file(&tmp, open(&tmp)?, data, sync)?;
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// Write `data` into `f`, the file this run just created at `path`, then
/// `sync` it. When either fails (a full disk), the partial file is removed
/// before the error is returned: a truncated secret output is worse than
/// none, and a retry would refuse it as a file that is already there. Only
/// for a file created exclusively (`create_new`), so what is removed is
/// this run's own.
fn fill_new_file<W: std::io::Write>(
    path: &std::path::Path,
    mut f: W,
    data: &[u8],
    sync: impl FnOnce(&mut W) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let written = f.write_all(data).and_then(|()| sync(&mut f));
    if written.is_err() {
        drop(f);
        let _ = std::fs::remove_file(path);
    }
    written
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn write_private_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let mut path = std::env::temp_dir();
        path.push(format!("keyroost_priv_{}", std::process::id()));

        // Fresh file is created 0600.
        write_private_file(&path, b"secret plaintext", OutMode::New).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "fresh file should be 0600");

        // A file that appeared after the check is not replaced in New mode.
        let err = write_private_file(&path, b"other", OutMode::New).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(err.to_string(), APPEARED);
        assert_eq!(std::fs::read(&path).unwrap(), b"secret plaintext");

        // Loosen perms, then re-write: the helper must tighten back to 0600.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_private_file(&path, b"new secret", OutMode::Replace).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "re-write should tighten to 0600");

        let _ = std::fs::remove_file(&path);
    }

    /// A new file whose write fails (a full disk, here a writer that
    /// fails partway) is removed, not left truncated; a write that goes
    /// through keeps it.
    #[test]
    fn fill_new_file_removes_a_partial_file() {
        struct Full(usize);
        impl std::io::Write for Full {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                if self.0 == 0 {
                    return Err(std::io::Error::other("no space left on device"));
                }
                let n = b.len().min(self.0);
                self.0 -= n;
                Ok(n)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let dir = std::env::temp_dir().join(format!("keyroost_fill_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("backup.t2vault");

        std::fs::write(&path, b"part").unwrap();
        let err = fill_new_file(&path, Full(4), b"partial data", |_| Ok(())).unwrap_err();
        assert!(err.to_string().contains("no space"), "{err}");
        assert!(!path.exists(), "a partial file was left behind");

        // A failing sync removes it too.
        std::fs::write(&path, b"all").unwrap();
        let err = fill_new_file(&path, Full(100), b"all", |_| {
            Err(std::io::Error::other("sync failed"))
        })
        .unwrap_err();
        assert!(err.to_string().contains("sync failed"), "{err}");
        assert!(!path.exists());

        // Success leaves the file alone.
        std::fs::write(&path, b"kept").unwrap();
        fill_new_file(&path, Full(100), b"kept", |_| Ok(())).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"kept");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An agreed overwrite outside Unix goes through a temp file: a write
    /// that fails partway leaves the old file whole and no temp behind; one
    /// that goes through replaces it; a symbolic link is refused.
    #[test]
    fn replace_via_temp_never_truncates_the_old_file() {
        struct Full(std::fs::File, usize);
        impl std::io::Write for Full {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                if self.1 == 0 {
                    return Err(std::io::Error::other("no space left on device"));
                }
                let n = self.0.write(&b[..b.len().min(self.1)])?;
                self.1 -= n;
                Ok(n)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.0.flush()
            }
        }
        let dir = std::env::temp_dir().join(format!("keyroost_replace_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("backup.t2vault");
        let only_the_file = |dir: &std::path::Path| {
            let names: Vec<_> = std::fs::read_dir(dir)
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect();
            assert_eq!(names, ["backup.t2vault"], "a temp file was left behind");
        };
        let open = |room: usize| {
            move |tmp: &std::path::Path| {
                let f = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(tmp)?;
                Ok(Full(f, room))
            }
        };

        std::fs::write(&path, b"the old backup").unwrap();
        let err =
            replace_via_temp(&path, b"a new backup", open(4), |f| f.0.sync_all()).unwrap_err();
        assert!(err.to_string().contains("no space"), "{err}");
        assert_eq!(std::fs::read(&path).unwrap(), b"the old backup");
        only_the_file(&dir);

        let err = replace_via_temp(&path, b"a new backup", open(100), |_| {
            Err(std::io::Error::other("sync failed"))
        })
        .unwrap_err();
        assert!(err.to_string().contains("sync failed"), "{err}");
        assert_eq!(std::fs::read(&path).unwrap(), b"the old backup");
        only_the_file(&dir);

        replace_via_temp(&path, b"a new backup", open(100), |f| f.0.sync_all()).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"a new backup");
        only_the_file(&dir);

        #[cfg(unix)]
        {
            let link = dir.join("link");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            let err = replace_via_temp(&link, b"x", open(100), |_| Ok(())).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
            assert_eq!(std::fs::read(&path).unwrap(), b"a new backup");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn write_private_file_rejects_symlink_destination() {
        use std::os::unix::fs::symlink;

        let mut base = std::env::temp_dir();
        base.push(format!("keyroost_symtest_{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let victim = base.join("victim");
        let link = base.join("link");
        // Attacker pre-plants a symlink where keyroost will write secret output.
        symlink(&victim, &link).unwrap();

        for mode in [OutMode::New, OutMode::Replace] {
            let err = write_private_file(&link, b"top secret plaintext", mode).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        }

        // No bytes may have been written through the link to the victim target.
        assert!(!victim.exists(), "secret bytes leaked through the symlink");
        // The link itself is left untouched (still a symlink).
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());

        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_dir_all(&base);
    }
}
