//! Backup file naming and never-overwrite writes.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::Error;

/// The three files written for one key set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    pub secret: PathBuf,
    pub public: PathBuf,
    pub revocation: PathBuf,
}

/// Derive the three file names from the one the user chose: strip a single
/// trailing `.asc`, `.gpg` or `.pgp`, then add `.asc`, `.pub.asc`, `.rev.asc`.
#[must_use]
pub fn paths_for(chosen: &Path) -> Paths {
    let mut name = chosen.as_os_str().to_string_lossy().into_owned();
    for ext in [".asc", ".gpg", ".pgp"] {
        if let Some(stem) = name.strip_suffix(ext) {
            name = stem.to_string();
            break;
        }
    }
    let with = |suffix: &str| PathBuf::from(format!("{name}{suffix}"));
    Paths {
        secret: with(".asc"),
        public: with(".pub.asc"),
        revocation: with(".rev.asc"),
    }
}

/// Write `contents` to a file that must not exist yet. On Unix the file is
/// created with mode 0600 when `secret` is set (the backup and the
/// revocation certificate).
pub fn write_new(path: &Path, contents: &str, secret: bool) -> Result<(), Error> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = secret;
    let mut f = opts.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("{} already exists; choose another name", path.display()),
            ))
        } else {
            Error::Io(e)
        }
    })?;
    f.write_all(contents.as_bytes())?;
    f.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("pgpkey-files-{}-{name}", std::process::id()));
        let _ = std::fs::remove_file(&d);
        d
    }

    #[test]
    fn names_derive_from_the_chosen_one() {
        for chosen in ["keys.asc", "keys", "keys.gpg", "keys.pgp"] {
            let p = paths_for(Path::new(chosen));
            assert_eq!(p.secret, Path::new("keys.asc"));
            assert_eq!(p.public, Path::new("keys.pub.asc"));
            assert_eq!(p.revocation, Path::new("keys.rev.asc"));
        }
        assert_eq!(
            paths_for(Path::new("/a/b.asc.asc")).secret,
            Path::new("/a/b.asc.asc")
        );
    }

    #[test]
    fn write_new_refuses_existing_and_names_it() {
        let p = tmp("exists");
        write_new(&p, "one", false).unwrap();
        let err = write_new(&p, "two", false).unwrap_err();
        assert!(err.to_string().contains("pgpkey-files"), "{err}");
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "one");
        std::fs::remove_file(&p).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn secret_files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let p = tmp("mode");
        write_new(&p, "x", true).unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        std::fs::remove_file(&p).unwrap();
    }
}
