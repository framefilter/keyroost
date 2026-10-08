//! Terminal prompts for keyroostctl: the numbered key picker, `[y/N]`
//! confirmations and the typed-word check. They run only when BOTH stdin
//! and stderr are terminals (works on a Windows console, unlike the old
//! /dev/tty picker), so piped stdin — a PIN, a seed — is never read as an
//! answer. All decisions go through [`Term`] and are unit-tested.

use std::io::{BufRead, IsTerminal, Write};

use keyroost_resolve::{Choice, Device, Picker};

use crate::sanitize_terminal;

pub(crate) trait Term {
    fn present(&self) -> bool;
    fn say(&mut self, line: &str);
    fn ask(&mut self, prompt: &str) -> std::io::Result<String>;
}

/// A terminal is present only when stdin AND stderr are both terminals.
pub(crate) fn terminal_present(stdin_is_tty: bool, stderr_is_tty: bool) -> bool {
    stdin_is_tty && stderr_is_tty
}

/// The process's stdin/stderr.
pub(crate) struct RealTerm;
impl Term for RealTerm {
    fn present(&self) -> bool {
        // A unit test must never block on the developer's terminal.
        if cfg!(test) {
            return false;
        }
        terminal_present(
            std::io::stdin().is_terminal(),
            std::io::stderr().is_terminal(),
        )
    }
    fn say(&mut self, line: &str) {
        eprintln!("{line}");
    }
    fn ask(&mut self, prompt: &str) -> std::io::Result<String> {
        let mut err = std::io::stderr();
        write!(err, "{prompt}")?;
        err.flush()?;
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        Ok(line)
    }
}

pub(crate) struct TermPicker<'a> {
    term: &'a mut dyn Term,
}
impl<'a> TermPicker<'a> {
    pub(crate) fn new(term: &'a mut dyn Term) -> Self {
        Self { term }
    }
}
impl Picker for TermPicker<'_> {
    fn interactive(&self) -> bool {
        self.term.present()
    }
    fn pick(&mut self, heading: &str, choices: &[Choice]) -> Result<usize, String> {
        self.term.say(&sanitize_terminal(heading));
        for c in choices {
            self.term.say(&format!(
                "  {:>2}) {:<40} {}",
                c.number,
                sanitize_terminal(&c.label),
                sanitize_terminal(&c.endpoint)
            ));
        }
        let numbers: Vec<String> = choices.iter().map(|c| c.number.to_string()).collect();
        let answer = self
            .term
            .ask(&format!("Select [{}]: ", numbers.join("/")))
            .map_err(|e| e.to_string())?;
        let typed = answer.trim();
        let n: usize = typed.parse().map_err(|_| {
            format!(
                "'{}' is not one of {}",
                sanitize_terminal(typed),
                numbers.join(", ")
            )
        })?;
        choices
            .iter()
            .position(|c| c.number == n)
            .ok_or_else(|| format!("{n} is not one of {}", numbers.join(", ")))
    }
}

fn refusal(action: &str, key: &str) -> String {
    format!("refusing to {action} on {key} without confirmation; add --yes")
}

/// `[y/N]` before erasing or replacing something the host can't restore.
/// `--yes` skips it; without a terminal it refuses with "add --yes".
/// `Ok(true)` means the question was shown and answered yes.
pub(crate) fn confirm(
    term: &mut dyn Term,
    yes: bool,
    action: &str,
    key: &str,
) -> Result<bool, String> {
    if yes {
        return Ok(false);
    }
    if !term.present() {
        return Err(refusal(action, key));
    }
    let answer = term
        .ask(&format!("{action} on {key}? [y/N] "))
        .map_err(|e| e.to_string())?;
    match answer.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => Ok(true),
        _ => Err("canceled; nothing was changed".into()),
    }
}

/// The stronger check (factory-reset, otp interface): a typed word, read
/// from the terminal only. `--yes` skips it deliberately. `Ok(true)` means
/// the question was shown and answered.
pub(crate) fn confirm_typed(
    term: &mut dyn Term,
    yes: bool,
    word: &str,
    action: &str,
    key: &str,
) -> Result<bool, String> {
    if yes {
        return Ok(false);
    }
    if !term.present() {
        return Err(refusal(action, key));
    }
    let answer = term
        .ask(&format!("Type '{word}' to {action} on {key}: "))
        .map_err(|e| e.to_string())?;
    if answer.trim() == word {
        Ok(true)
    } else {
        Err(format!(
            "the confirmation did not match '{word}'; nothing was changed"
        ))
    }
}

/// A file that appeared at an output path after the overwrite check.
pub(crate) const APPEARED: &str =
    "a file appeared there while this command ran and was not replaced; \
     pass --overwrite to replace it";

/// `write PATH: ERROR` for an output written after the card was changed.
/// When the failure is a file that appeared mid-command ([`APPEARED`]),
/// `card_note` follows it to say what is already on the card, so a rerun
/// with `--overwrite` isn't the only way out.
pub(crate) fn write_error(
    path: &std::path::Path,
    e: &std::io::Error,
    card_note: Option<&str>,
) -> String {
    let shown = sanitize_terminal(&path.display().to_string());
    match card_note {
        Some(note)
            if e.kind() == std::io::ErrorKind::AlreadyExists && e.to_string() == APPEARED =>
        {
            format!("write {shown}: {e}; {note}")
        }
        _ => format!("write {shown}: {e}"),
    }
}

/// How an output file that passed [`check_overwrite`] is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OutMode {
    /// Nothing was there at check time: create it, and fail rather than
    /// replace a file that appeared while the command waited on the key.
    New,
    /// Something was there and replacing it was agreed (`--overwrite` or a
    /// "yes" at the terminal).
    Replace,
}

impl OutMode {
    /// Open `path` for writing in this mode. `New` reports a file that
    /// appeared since the check as an error naming --overwrite.
    pub(crate) fn open(self, path: &std::path::Path) -> std::io::Result<std::fs::File> {
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
    pub(crate) fn write(self, path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
        use std::io::Write;
        self.open(path)?.write_all(data)
    }
}

/// Before writing `path`: a file already there is replaced only with
/// `--overwrite` or a "yes" at a terminal; without a terminal it refuses,
/// naming the flag. A path with nothing there passes as [`OutMode::New`]. A
/// dangling symlink counts as something there. A directory, or anything else
/// that isn't a regular file, is refused whatever the flag says: writing to
/// it would fail, and only after the key was used.
pub(crate) fn check_overwrite(
    term: &mut dyn Term,
    path: &std::path::Path,
    overwrite: bool,
) -> Result<OutMode, String> {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return Ok(OutMode::New);
    };
    let shown = sanitize_terminal(&path.display().to_string());
    // Through a link, judge what it points at; a dangling link is treated as
    // a file there to replace.
    let target = if meta.file_type().is_symlink() {
        std::fs::metadata(path).ok()
    } else {
        Some(meta)
    };
    if let Some(t) = target {
        if t.is_dir() {
            return Err(format!(
                "{shown} is a directory; give a file name for the output"
            ));
        }
        if !t.is_file() {
            return Err(format!(
                "{shown} is not a regular file; give a file name for the output"
            ));
        }
    }
    if overwrite {
        return Ok(OutMode::Replace);
    }
    if !term.present() {
        return Err(format!(
            "{shown} already exists; pass --overwrite to replace it"
        ));
    }
    let answer = term
        .ask(&format!("{shown} already exists; overwrite? [y/N] "))
        .map_err(|e| e.to_string())?;
    match answer.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => Ok(OutMode::Replace),
        _ => Err("canceled; nothing was changed".into()),
    }
}

/// [`check_overwrite`] at the real terminal for each output path a command
/// was given, returning each one's [`OutMode`] in the same order (`New` for
/// a path not given). Call it first in the handler: before any secret is
/// read and before any key is selected.
pub(crate) fn check_overwrites<const N: usize>(
    paths: [Option<&std::path::Path>; N],
    overwrite: bool,
) -> Result<[OutMode; N], Box<dyn std::error::Error>> {
    let mut modes = [OutMode::New; N];
    for (mode, p) in modes.iter_mut().zip(paths) {
        if let Some(p) = p {
            *mode = check_overwrite(&mut RealTerm, p, overwrite)?;
        }
    }
    Ok(modes)
}

/// A secret output is never written through a symbolic link (the writer
/// refuses one), so say so before the PIN or the card is used.
pub(crate) fn refuse_link(path: &std::path::Path) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => Err(format!(
            "{} is a symbolic link; this output is secret and is only written to a plain file",
            sanitize_terminal(&path.display().to_string())
        )),
        _ => Ok(()),
    }
}

/// [`check_overwrites`] for one secret output: a symbolic link is refused
/// first, then the overwrite question.
pub(crate) fn check_secret_overwrite(
    path: Option<&std::path::Path>,
    overwrite: bool,
) -> Result<OutMode, Box<dyn std::error::Error>> {
    if let Some(p) = path {
        refuse_link(p)?;
    }
    let [mode] = check_overwrites([path], overwrite)?;
    Ok(mode)
}

/// "yubi-test (serial 12345678)" / model when unnamed / the reader or path
/// as typed for a key that was not detected.
pub(crate) fn key_label(d: &Device) -> String {
    if let Some(typed) = crate::target::typed_value(d) {
        return sanitize_terminal(typed);
    }
    let who = sanitize_terminal(d.name.as_deref().unwrap_or(&d.model));
    if d.serial.is_empty() {
        who
    } else {
        format!("{who} (serial {})", sanitize_terminal(&d.serial))
    }
}

/// Ask only, for a command that must still read a secret (a PIN, a seed)
/// before it reopens `d`. Returns whether the question was actually shown
/// and answered yes. Call [`reverify_if_asked`] with that result right
/// before the reopen — after the secret has been read, so nothing sits
/// between the re-check and the reopen while the person is typing it.
/// `--yes` and scripts return `Ok(false)`.
pub(crate) fn confirm_then_read(
    d: &Device,
    yes: bool,
    action: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    Ok(confirm(&mut RealTerm, yes, action, &key_label(d))?)
}

/// Re-find `d` ([`crate::target::reverify`]) only when the person was kept
/// waiting: callers pass `asked || sec.prompted()` — the question was shown
/// ([`confirm_then_read`]) or a secret was typed at the hidden prompt — since
/// keys may have been swapped meanwhile. A no-op for scripts (`--yes`, env
/// and piped secrets).
pub(crate) fn reverify_if_asked(d: &Device, asked: bool) -> Result<(), Box<dyn std::error::Error>> {
    if asked {
        crate::target::reverify(d)?;
    }
    Ok(())
}

/// Ask before acting on `d`, which the command reopens afterwards by reader
/// name or HID path, with no secret read in between. See
/// [`confirm_then_read`] / [`reverify_if_asked`] for a command that reads a
/// secret first.
pub(crate) fn confirm_on(
    d: &Device,
    yes: bool,
    action: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let asked = confirm_then_read(d, yes, action)?;
    reverify_if_asked(d, asked)
}

/// [`confirm_on`] for a command that holds the key's session or handle open
/// across the question, which already ties it to the key the user saw. No
/// re-enumeration: that would SELECT applets on the held card.
pub(crate) fn confirm_on_held(
    d: &Device,
    yes: bool,
    action: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    confirm(&mut RealTerm, yes, action, &key_label(d))?;
    Ok(())
}

/// The typed-word form of [`confirm_then_read`]: ask only, returning whether
/// the question was shown; the caller reads its secret, then calls
/// [`reverify_if_asked`].
pub(crate) fn confirm_typed_then_read(
    d: &Device,
    yes: bool,
    word: &str,
    action: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    Ok(confirm_typed(
        &mut RealTerm,
        yes,
        word,
        action,
        &key_label(d),
    )?)
}

/// The typed-word form of [`confirm_on`], with the same re-check.
pub(crate) fn confirm_typed_on(
    d: &Device,
    yes: bool,
    word: &str,
    action: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let asked = confirm_typed_then_read(d, yes, word, action)?;
    reverify_if_asked(d, asked)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_error_says_what_the_card_already_holds() {
        let dir = std::env::temp_dir().join(format!("keyroost-we-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cert.pem");
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, b"x").unwrap();
        let e = OutMode::New.write(&path, b"y").unwrap_err();
        let note = "the certificate is stored in slot 9a";
        let msg = write_error(&path, &e, Some(note));
        assert!(
            msg.starts_with(&format!("write {}: ", path.display())),
            "{msg}"
        );
        assert!(msg.contains(APPEARED), "{msg}");
        assert!(msg.ends_with(&format!("; {note}")), "{msg}");
        // Without a note, or for any other write failure, no card note.
        assert!(!write_error(&path, &e, None).contains("slot"));
        let other = std::io::Error::other("disk full");
        assert_eq!(
            write_error(&path, &other, Some(note)),
            format!("write {}: disk full", path.display())
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"x");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    struct FakeTerm {
        present: bool,
        answers: Vec<String>,
        said: Vec<String>,
        asked: Vec<String>,
    }
    impl FakeTerm {
        fn new(present: bool, answers: &[&str]) -> Self {
            Self {
                present,
                answers: answers.iter().rev().map(|s| s.to_string()).collect(),
                said: Vec::new(),
                asked: Vec::new(),
            }
        }
    }
    impl Term for FakeTerm {
        fn present(&self) -> bool {
            self.present
        }
        fn say(&mut self, line: &str) {
            self.said.push(line.to_string());
        }
        fn ask(&mut self, prompt: &str) -> std::io::Result<String> {
            self.asked.push(prompt.to_string());
            Ok(self.answers.pop().unwrap_or_default())
        }
    }

    #[test]
    fn piped_stdin_with_terminal_stderr_is_not_a_terminal() {
        assert!(terminal_present(true, true));
        assert!(!terminal_present(false, true));
        assert!(!terminal_present(true, false));
        assert!(!terminal_present(false, false));
    }

    #[test]
    fn confirm_without_terminal_says_add_yes() {
        let mut t = FakeTerm::new(false, &[]);
        let e = confirm(
            &mut t,
            false,
            "delete OATH credential \"x\"",
            "yubi-test (serial 1)",
        )
        .unwrap_err();
        assert_eq!(
            e,
            "refusing to delete OATH credential \"x\" on yubi-test (serial 1) without confirmation; add --yes"
        );
        assert!(t.asked.is_empty(), "never reads stdin without a terminal");
    }

    #[test]
    fn yes_skips_the_question() {
        let mut t = FakeTerm::new(true, &[]);
        // Ok(false): nothing was asked, so nothing to re-check afterwards.
        assert_eq!(confirm(&mut t, true, "x", "k"), Ok(false));
        assert_eq!(confirm_typed(&mut t, true, "reset", "x", "k"), Ok(false));
        assert!(t.asked.is_empty());
    }

    #[test]
    fn y_n_answers() {
        for (answer, ok) in [
            ("y\n", true),
            ("YES\n", true),
            ("yes", true),
            ("\n", false),
            ("n\n", false),
            ("yep\n", false),
        ] {
            let mut t = FakeTerm::new(true, &[answer]);
            // Ok(true): the question was shown and answered yes.
            assert_eq!(
                confirm(&mut t, false, "wipe PIV", "k") == Ok(true),
                ok,
                "{answer:?}"
            );
            assert_eq!(t.asked, vec!["wipe PIV on k? [y/N] ".to_string()]);
        }
    }

    #[test]
    fn typed_word_must_match_exactly() {
        let mut t = FakeTerm::new(true, &["reset\n"]);
        assert_eq!(
            confirm_typed(&mut t, false, "reset", "factory-reset", "k"),
            Ok(true)
        );
        for wrong in ["RESET\n", "y\n", "\n"] {
            let mut t = FakeTerm::new(true, &[wrong]);
            assert!(
                confirm_typed(&mut t, false, "reset", "factory-reset", "k").is_err(),
                "{wrong:?}"
            );
        }
        let mut t = FakeTerm::new(false, &[]);
        assert!(confirm_typed(&mut t, false, "reset", "factory-reset", "k")
            .unwrap_err()
            .ends_with("add --yes"));
    }

    #[test]
    fn picker_maps_list_numbers_to_choice_indices() {
        use keyroost_resolve::{Choice, Picker};
        let choices = vec![
            Choice {
                number: 2,
                label: "a".into(),
                endpoint: "/dev/hidraw1".into(),
            },
            Choice {
                number: 5,
                label: "b".into(),
                endpoint: "Reader 00".into(),
            },
        ];
        let mut t = FakeTerm::new(true, &["5\n"]);
        assert_eq!(TermPicker::new(&mut t).pick("2 keys:", &choices), Ok(1));
        let mut t = FakeTerm::new(true, &["1\n"]);
        assert!(TermPicker::new(&mut t).pick("2 keys:", &choices).is_err());
        let mut t = FakeTerm::new(true, &["x\n"]);
        assert!(TermPicker::new(&mut t).pick("2 keys:", &choices).is_err());
    }

    #[test]
    fn check_overwrite_rules() {
        let dir = std::env::temp_dir().join(format!("kr-overwrite-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fresh = dir.join("fresh.pem");
        let taken = dir.join("taken.pem");
        std::fs::write(&taken, b"x").unwrap();

        let mut t = FakeTerm::new(true, &[]);
        assert_eq!(check_overwrite(&mut t, &fresh, false), Ok(OutMode::New));
        assert!(t.asked.is_empty(), "nothing to ask about a new file");
        let mut t = FakeTerm::new(true, &[]);
        assert_eq!(check_overwrite(&mut t, &fresh, true), Ok(OutMode::New));
        let mut t = FakeTerm::new(true, &[]);
        assert_eq!(check_overwrite(&mut t, &taken, true), Ok(OutMode::Replace));
        assert!(t.asked.is_empty(), "--overwrite never asks");

        let e = check_overwrite(&mut FakeTerm::new(false, &[]), &taken, false).unwrap_err();
        assert!(e.contains("--overwrite"), "{e}");
        assert_eq!(
            check_overwrite(&mut FakeTerm::new(true, &["y\n"]), &taken, false),
            Ok(OutMode::Replace)
        );
        let e = check_overwrite(&mut FakeTerm::new(true, &["\n"]), &taken, false).unwrap_err();
        assert!(e.contains("canceled"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A directory (or anything else that isn't a plain file) can't be
    /// replaced by writing to it: refused outright, --overwrite or not, and
    /// never asked about.
    #[test]
    fn check_overwrite_refuses_what_is_not_a_file() {
        let dir = std::env::temp_dir().join(format!("kr-overwrite-dir-{}", std::process::id()));
        let sub = dir.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        for overwrite in [false, true] {
            for present in [false, true] {
                let mut t = FakeTerm::new(present, &["y\n"]);
                let e = check_overwrite(&mut t, &sub, overwrite).unwrap_err();
                assert!(e.contains("is a directory"), "{e}");
                assert!(e.contains("sub"), "names the path: {e}");
                assert!(t.asked.is_empty(), "a directory is never offered: {e}");
            }
        }
        #[cfg(unix)]
        {
            let link = dir.join("to-dir");
            std::os::unix::fs::symlink(&sub, &link).unwrap();
            let e = check_overwrite(&mut FakeTerm::new(true, &["y\n"]), &link, true).unwrap_err();
            assert!(e.contains("is a directory"), "{e}");
            let e = check_overwrite(
                &mut FakeTerm::new(true, &["y\n"]),
                std::path::Path::new("/dev/null"),
                true,
            )
            .unwrap_err();
            assert!(e.contains("not a regular file"), "{e}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A file that appears between the check and the write is not replaced
    /// when nothing was there at check time; an agreed replace still is.
    #[test]
    fn out_mode_new_never_replaces() {
        let dir = std::env::temp_dir().join(format!("kr-outmode-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("out.bin");
        OutMode::New.write(&p, b"first").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"first");
        let e = OutMode::New.write(&p, b"second").unwrap_err();
        assert!(e.to_string().contains("--overwrite"), "{e}");
        assert_eq!(std::fs::read(&p).unwrap(), b"first");
        OutMode::Replace.write(&p, b"third").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"third");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Secret outputs refuse a symbolic link before anything is read.
    #[cfg(unix)]
    #[test]
    fn secret_output_refuses_a_link() {
        let dir = std::env::temp_dir().join(format!("kr-secret-link-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("target.bin");
        std::fs::write(&target, b"x").unwrap();
        let link = dir.join("link.bin");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let dangling = dir.join("dangling.bin");
        std::os::unix::fs::symlink(dir.join("missing"), &dangling).unwrap();
        for p in [&link, &dangling] {
            let e = refuse_link(p).unwrap_err();
            assert!(e.contains("symbolic link"), "{e}");
        }
        assert_eq!(refuse_link(&target), Ok(()));
        assert_eq!(refuse_link(&dir.join("fresh.bin")), Ok(()));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
