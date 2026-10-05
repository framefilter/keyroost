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
        _ => Err("cancelled; nothing was changed".into()),
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

/// Re-find `d` ([`crate::target::reverify`]) only when the question was
/// actually shown (`asked`, from [`confirm_then_read`] or
/// `confirm_then_read_pin`): the user may have swapped keys while it was
/// up. A no-op under `--yes` and in scripts.
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

/// The typed-word form of [`confirm_on`], with the same re-check.
pub(crate) fn confirm_typed_on(
    d: &Device,
    yes: bool,
    word: &str,
    action: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let asked = confirm_typed(&mut RealTerm, yes, word, action, &key_label(d))?;
    reverify_if_asked(d, asked)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
