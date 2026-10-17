//! Backup file naming, never-overwrite writes, and whole-file replacement.

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
/// trailing `.asc`, `.gpg` or `.pgp` (in any case), then add `.asc`,
/// `.pub.asc`, `.rev.asc`.
#[must_use]
pub fn paths_for(chosen: &Path) -> Paths {
    let mut name = chosen.as_os_str().to_string_lossy().into_owned();
    let cut = name.len().saturating_sub(4);
    if name.is_char_boundary(cut)
        && [".asc", ".gpg", ".pgp"]
            .iter()
            .any(|ext| name[cut..].eq_ignore_ascii_case(ext))
    {
        name.truncate(cut);
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
/// revocation certificate). A write that fails after the file was created
/// removes it again: a cut-off backup must not be left looking like one
/// (and a retry would say it already exists).
pub fn write_new(path: &Path, contents: &str, secret: bool) -> Result<(), Error> {
    create_then(path, secret, |f| {
        f.write_all(contents.as_bytes())?;
        f.flush()?;
        f.sync_all()
    })
}

/// [`write_new`]'s body: create `path` (never over an existing file or a
/// symlink), run `write` on it, and remove the file again if `write` fails.
fn create_then(
    path: &Path,
    secret: bool,
    write: impl FnOnce(&mut std::fs::File) -> std::io::Result<()>,
) -> Result<(), Error> {
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
    let written = write(&mut f);
    drop(f);
    if let Err(e) = written {
        let _ = std::fs::remove_file(path);
        return Err(Error::Io(e));
    }
    Ok(())
}

/// `path` with `.tmp` added, where [`replace`] writes it first.
fn tmp_for(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".tmp");
    PathBuf::from(name)
}

/// Replace existing files, each `(path, contents, secret)`, so that none is
/// ever left half-written: every new version is written to `<path>.tmp`
/// first (0600 on Unix when `secret`, as [`write_new`]), and only when all
/// are written is each renamed over its file, in the order given.
///
/// A `.tmp` file already there (left over from an attempt that was cut
/// off) stops everything before any file changes. If a rename fails after
/// an earlier one went through, the error names the files already
/// replaced, so put the one that matters most to keep consistent (the
/// public key others are sent) first.
pub fn replace(files: &[(&Path, &str, bool)]) -> Result<(), Error> {
    let mut written: Vec<PathBuf> = Vec::new();
    let remove_all = |tmps: &[PathBuf]| {
        for t in tmps {
            let _ = std::fs::remove_file(t);
        }
    };
    for (path, contents, secret) in files {
        let tmp = tmp_for(path);
        if let Err(e) = write_new(&tmp, contents, *secret) {
            remove_all(&written);
            return Err(match e {
                Error::Io(io) if io.kind() == std::io::ErrorKind::AlreadyExists => {
                    Error::Io(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        format!(
                            "{} is left over from an earlier attempt; delete it and try again \
                             (nothing was changed)",
                            tmp.display()
                        ),
                    ))
                }
                e => {
                    // A partly written tmp of our own: don't leave it.
                    let _ = std::fs::remove_file(&tmp);
                    e
                }
            });
        }
        written.push(tmp);
    }
    for (i, ((path, ..), tmp)) in files.iter().zip(&written).enumerate() {
        if let Err(e) = std::fs::rename(tmp, path) {
            remove_all(&written[i..]);
            let done: Vec<String> = files[..i]
                .iter()
                .map(|(p, ..)| p.display().to_string())
                .collect();
            let msg = if done.is_empty() {
                format!(
                    "cannot replace {}: {e} (nothing was changed)",
                    path.display()
                )
            } else {
                format!(
                    "cannot replace {}: {e}; {} was already updated",
                    path.display(),
                    done.join(" and ")
                )
            };
            return Err(Error::Io(std::io::Error::new(e.kind(), msg)));
        }
    }
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
        for chosen in [
            "keys.asc", "keys", "keys.gpg", "keys.pgp", "keys.ASC", "keys.Gpg", "keys.PGP",
        ] {
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

    #[test]
    fn short_and_non_ascii_names_keep_their_ending() {
        assert_eq!(paths_for(Path::new("asc")).secret, Path::new("asc.asc"));
        assert_eq!(
            paths_for(Path::new("k\u{e9}y")).secret,
            Path::new("k\u{e9}y.asc")
        );
        assert_eq!(
            paths_for(Path::new("\u{e9}asc")).secret,
            Path::new("\u{e9}asc.asc")
        );
    }

    #[test]
    fn a_failed_write_leaves_no_file() {
        let d = dir("failwrite");
        let p = d.join("k.asc");
        let err = create_then(&p, true, |f| {
            f.write_all(b"-----BEGIN PGP PRIV")?;
            Err(std::io::Error::other("disk full"))
        })
        .unwrap_err();
        assert!(err.to_string().contains("disk full"), "{err}");
        assert!(
            std::fs::symlink_metadata(&p).is_err(),
            "half-written file left"
        );
        // So a retry is not told the file already exists.
        write_new(&p, "whole", true).unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "whole");
        std::fs::remove_dir_all(&d).unwrap();
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

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("pgpkey-replace-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn replace_swaps_whole_files_and_keeps_secret_ones_private() {
        let d = dir("ok");
        let (pubf, b) = (d.join("k.pub.asc"), d.join("k.asc"));
        std::fs::write(&pubf, "old public").unwrap();
        std::fs::write(&b, "old secret").unwrap();
        replace(&[(&pubf, "new public", false), (&b, "new secret", true)]).unwrap();
        assert_eq!(std::fs::read_to_string(&pubf).unwrap(), "new public");
        assert_eq!(std::fs::read_to_string(&b).unwrap(), "new secret");
        assert!(!d.join("k.pub.asc.tmp").exists() && !d.join("k.asc.tmp").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&b).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_left_over_tmp_changes_nothing() {
        let d = dir("stale");
        let (pubf, b) = (d.join("k.pub.asc"), d.join("k.asc"));
        std::fs::write(&pubf, "public").unwrap();
        std::fs::write(&b, "secret").unwrap();
        std::fs::write(d.join("k.asc.tmp"), "stale").unwrap();
        let err = replace(&[(&pubf, "new", false), (&b, "new", true)]).unwrap_err();
        assert!(err.to_string().contains("k.asc.tmp is left over"), "{err}");
        assert!(err.to_string().contains("nothing was changed"), "{err}");
        assert_eq!(std::fs::read_to_string(&pubf).unwrap(), "public");
        assert_eq!(std::fs::read_to_string(&b).unwrap(), "secret");
        // Our own tmp for the public file is cleaned up; the stale one stays.
        assert!(!d.join("k.pub.asc.tmp").exists());
        assert_eq!(
            std::fs::read_to_string(d.join("k.asc.tmp")).unwrap(),
            "stale"
        );
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_failed_second_rename_says_the_first_file_was_updated() {
        let d = dir("half");
        let pubf = d.join("k.pub.asc");
        std::fs::write(&pubf, "old public").unwrap();
        // A directory where the backup should be: its rename fails.
        let b = d.join("k.asc");
        std::fs::create_dir(&b).unwrap();
        std::fs::write(b.join("keep"), "x").unwrap();
        let err = replace(&[(&pubf, "new public", false), (&b, "new secret", true)]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("cannot replace"), "{msg}");
        assert!(
            msg.contains(&format!("{} was already updated", pubf.display())),
            "{msg}"
        );
        assert_eq!(std::fs::read_to_string(&pubf).unwrap(), "new public");
        assert!(!d.join("k.asc.tmp").exists());
        std::fs::remove_dir_all(&d).unwrap();
    }
}
