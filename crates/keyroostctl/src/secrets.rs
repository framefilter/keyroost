//! One way to read a secret: a PIN, password, management or customer key,
//! a seed or an otpauth URI. A secret flag names where the secret comes
//! from, never the secret itself: `--X env:NAME` reads the environment
//! variable NAME; `--X stdin` reads one line of standard input, or asks at
//! a hidden prompt when stdin is a terminal; `--mgmt-key default` uses the
//! factory-default key. With no flag, a hidden prompt asks when a terminal
//! is present (stdin AND stderr, the rule every question uses); otherwise
//! the command is refused with a message naming the sources. Any other
//! value given to a secret flag is refused at parsing without being shown
//! (`--X takes env:NAME or stdin — never ... itself`). A new
//! PIN/password/key typed at a prompt is asked twice. Values live in
//! `Zeroizing` buffers and are never echoed, printed or traced.
//!
//! Callers: `check` every required secret before any device I/O, read
//! after any confirmation question, and never while a PC/SC transaction or
//! HID session is held.

use std::io::{BufRead, ErrorKind, IsTerminal};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// Already known to the key (current PIN, password, key). Asked once.
    Current,
    /// Being set, and must be reproduced later. Asked twice at a prompt.
    New,
    /// Written and checked another way (a TOTP seed, an otpauth URI: the
    /// service asks for a code). Asked once.
    Value,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Form {
    Text,
    Hex,
    Base32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Spec {
    /// What the user is asked for: "PIN", "new PIN", "admin PIN (PW3)".
    pub(crate) label: &'static str,
    /// The flag's long name: "pin" means `--pin env:NAME` / `--pin stdin`.
    pub(crate) flag: &'static str,
    pub(crate) kind: Kind,
    pub(crate) form: Form,
    /// The flag also takes `default` (`--mgmt-key default`), named in the
    /// refusal.
    pub(crate) default_ok: bool,
    /// The flag is still an old `--X-env VAR` / `--X-stdin` pair; messages
    /// name those.
    pub(crate) legacy: bool,
    /// Replaces the "--X env:NAME or --X stdin" part (molto import's `-`).
    pub(crate) hint: Option<&'static str>,
    /// Replaces the prompt's label, shown as written (not capitalized).
    pub(crate) prompt: Option<&'static str>,
}

impl Spec {
    const fn base(label: &'static str, flag: &'static str, kind: Kind) -> Spec {
        Spec {
            label,
            flag,
            kind,
            form: Form::Text,
            default_ok: false,
            legacy: false,
            hint: None,
            prompt: None,
        }
    }
    pub(crate) const fn current(label: &'static str, flag: &'static str) -> Spec {
        Spec::base(label, flag, Kind::Current)
    }
    pub(crate) const fn new_secret(label: &'static str, flag: &'static str) -> Spec {
        Spec::base(label, flag, Kind::New)
    }
    pub(crate) const fn value(label: &'static str, flag: &'static str) -> Spec {
        Spec::base(label, flag, Kind::Value)
    }
    pub(crate) const fn hex(self) -> Spec {
        Spec {
            form: Form::Hex,
            ..self
        }
    }
    pub(crate) const fn base32(self) -> Spec {
        Spec {
            form: Form::Base32,
            ..self
        }
    }
    pub(crate) const fn with_default(self) -> Spec {
        Spec {
            default_ok: true,
            ..self
        }
    }
    pub(crate) const fn legacy(self) -> Spec {
        Spec {
            legacy: true,
            ..self
        }
    }
    pub(crate) const fn hint(self, text: &'static str) -> Spec {
        Spec {
            hint: Some(text),
            ..self
        }
    }
    pub(crate) const fn prompt_as(self, text: &'static str) -> Spec {
        Spec {
            prompt: Some(text),
            ..self
        }
    }

    /// "--pin env:NAME or --pin stdin" (plus "or --mgmt-key default"), or the
    /// custom hint.
    pub(crate) fn sources_hint(&self) -> String {
        if let Some(h) = self.hint {
            return h.to_string();
        }
        let f = self.flag;
        if self.legacy {
            if self.default_ok {
                return format!("--{f}-env VAR, --{f}-stdin or --{f}-default");
            }
            return format!("--{f}-env VAR or --{f}-stdin");
        }
        if self.default_ok {
            format!("--{f} env:NAME, --{f} stdin or --{f} default")
        } else {
            format!("--{f} env:NAME or --{f} stdin")
        }
    }

    fn no_source(&self) -> String {
        format!("no {} given: pass {}", self.label, self.sources_hint())
    }

    fn prompt_text(&self, repeat: bool) -> String {
        let suffix = match self.form {
            Form::Text => "",
            Form::Hex => " (hex)",
            Form::Base32 => " (base32)",
        };
        let label = self.prompt.unwrap_or(self.label);
        if repeat {
            return format!("Repeat {label}{suffix}: ");
        }
        // An explicit prompt is shown as written ("otpauth:// URI").
        if self.prompt.is_some() {
            return format!("{label}{suffix}: ");
        }
        let mut chars = label.chars();
        let first: String = chars
            .next()
            .map(|c| c.to_uppercase().collect())
            .unwrap_or_default();
        format!("{first}{}{suffix}: ", chars.as_str())
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Source<'a> {
    pub(crate) env: Option<&'a str>,
    pub(crate) stdin: bool,
}
impl<'a> Source<'a> {
    pub(crate) const NONE: Source<'static> = Source {
        env: None,
        stdin: false,
    };
    pub(crate) fn new(env: Option<&'a str>, stdin: bool) -> Self {
        Source { env, stdin }
    }
    pub(crate) fn env(var: &'a str) -> Self {
        Source {
            env: Some(var),
            stdin: false,
        }
    }
    pub(crate) fn given(&self) -> bool {
        self.env.is_some() || self.stdin
    }
}

/// The value name every secret flag shows in help: `--pin <SOURCE>`.
pub(crate) const SOURCE: &str = "SOURCE";

/// Where a secret flag says to read its secret from.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "no flag reads a secret source yet")
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SecretSource {
    /// `env:NAME`: the named environment variable. NAME is never shown in a
    /// message: a user migrating from the old flags may type the secret
    /// where the name goes.
    Env(String),
    /// `stdin`: one line of standard input; a hidden prompt when stdin is a
    /// terminal.
    Stdin,
    /// `default` (`--mgmt-key` only): the factory-default key keyroost knows
    /// for the selected device.
    Default,
}

/// clap value parser for a secret flag: `env:NAME` or `stdin`. The error
/// text is never shown; [`literal_refusal`] replaces clap's message, which
/// would repeat the value.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "no flag reads a secret source yet")
)]
pub(crate) fn parse_source(s: &str) -> Result<SecretSource, &'static str> {
    parse(s, false)
}

/// [`parse_source`] that also accepts `default` (`--mgmt-key`).
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "no flag reads a secret source yet")
)]
pub(crate) fn parse_source_or_default(s: &str) -> Result<SecretSource, &'static str> {
    parse(s, true)
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "no flag reads a secret source yet")
)]
fn parse(s: &str, default_ok: bool) -> Result<SecretSource, &'static str> {
    match s {
        "stdin" => Ok(SecretSource::Stdin),
        "default" if default_ok => Ok(SecretSource::Default),
        _ => match s.strip_prefix("env:") {
            Some(name) if !name.is_empty() => Ok(SecretSource::Env(name.to_owned())),
            _ => Err("not a secret source"),
        },
    }
}

/// One secret flag: its long name, what it carries (for the refusal), and
/// whether it takes `default`.
pub(crate) struct SecretFlag {
    pub(crate) long: &'static str,
    pub(crate) what: &'static str,
    pub(crate) default_ok: bool,
}

pub(crate) const SECRET_FLAGS: &[SecretFlag] = &[
    SecretFlag {
        long: "pin",
        what: "the PIN",
        default_ok: false,
    },
    SecretFlag {
        long: "new-pin",
        what: "the PIN",
        default_ok: false,
    },
    SecretFlag {
        long: "puk",
        what: "the PUK",
        default_ok: false,
    },
    SecretFlag {
        long: "new-puk",
        what: "the PUK",
        default_ok: false,
    },
    SecretFlag {
        long: "admin-pin",
        what: "the admin PIN",
        default_ok: false,
    },
    SecretFlag {
        long: "mgmt-key",
        what: "the management key",
        default_ok: true,
    },
    SecretFlag {
        long: "new-mgmt-key",
        what: "the management key",
        default_ok: false,
    },
    SecretFlag {
        long: "password",
        what: "the password",
        default_ok: false,
    },
    SecretFlag {
        long: "new-password",
        what: "the password",
        default_ok: false,
    },
    SecretFlag {
        long: "seed",
        what: "the seed",
        default_ok: false,
    },
    SecretFlag {
        long: "customer-key",
        what: "the customer key",
        default_ok: false,
    },
    SecretFlag {
        long: "new-customer-key",
        what: "the customer key",
        default_ok: false,
    },
    SecretFlag {
        long: "uri",
        what: "the otpauth:// URI",
        default_ok: false,
    },
];

/// "--pin takes env:NAME or stdin — never the PIN itself", for a value that
/// is neither. `None` when `long` is not a secret flag.
pub(crate) fn literal_refusal(long: &str) -> Option<String> {
    let f = SECRET_FLAGS.iter().find(|f| f.long == long)?;
    let sources = if f.default_ok {
        "env:NAME, stdin or default"
    } else {
        "env:NAME or stdin"
    };
    Some(format!(
        "--{} takes {sources} — never {} itself",
        f.long, f.what
    ))
}

impl<'a> Source<'a> {
    /// The source a secret flag names; `default` and an absent flag are
    /// [`Source::NONE`] (the caller handles `default` itself).
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "no flag reads a secret source yet")
    )]
    pub(crate) fn from_flag(flag: Option<&'a SecretSource>) -> Source<'a> {
        match flag {
            Some(SecretSource::Env(name)) => Source::env(name),
            Some(SecretSource::Stdin) => Source::new(None, true),
            Some(SecretSource::Default) | None => Source::NONE,
        }
    }
}

/// Whether a secret flag said `default`.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "no flag reads a secret source yet")
)]
pub(crate) fn wants_default(flag: Option<&SecretSource>) -> bool {
    matches!(flag, Some(SecretSource::Default))
}

pub(crate) enum EnvValue {
    Unset,
    NotUnicode,
    Set(Zeroizing<String>),
}

pub(crate) trait SecretIo {
    fn env(&self, var: &str) -> EnvValue;
    fn stdin_is_terminal(&self) -> bool;
    fn stderr_is_terminal(&self) -> bool;
    /// One line from stdin including its line ending; `None` at end of input.
    fn read_line(&mut self) -> std::io::Result<Option<Zeroizing<String>>>;
    /// Show `prompt` on the terminal and read one line without echo.
    fn read_hidden(&mut self, prompt: &str) -> std::io::Result<Zeroizing<String>>;
}

/// The process's environment, stdin and terminal.
pub(crate) struct RealIo;
impl SecretIo for RealIo {
    fn env(&self, var: &str) -> EnvValue {
        match std::env::var(var) {
            Ok(v) => EnvValue::Set(Zeroizing::new(v)),
            Err(std::env::VarError::NotPresent) => EnvValue::Unset,
            Err(std::env::VarError::NotUnicode(os)) => {
                // The lossy bytes may still be the secret; wipe them rather
                // than letting them drop unwiped.
                let mut b = os.into_encoded_bytes();
                zeroize::Zeroize::zeroize(&mut b);
                EnvValue::NotUnicode
            }
        }
    }
    // A unit test must never block on the developer's terminal.
    fn stdin_is_terminal(&self) -> bool {
        !cfg!(test) && std::io::stdin().is_terminal()
    }
    fn stderr_is_terminal(&self) -> bool {
        !cfg!(test) && std::io::stderr().is_terminal()
    }
    fn read_line(&mut self) -> std::io::Result<Option<Zeroizing<String>>> {
        // std's Stdin buffer is shared, so a second call continues at line 2.
        // Pre-sized (4 KiB, room for a long otpauth:// URI with issuer,
        // label and image parameters) so a long secret doesn't grow the
        // buffer through an unwiped reallocation copy; std's own internal
        // BufReader for stdin keeps its own copy of the bytes that we have
        // no way to wipe.
        let mut line = Zeroizing::new(String::with_capacity(4096));
        let n = std::io::stdin().lock().read_line(&mut line)?;
        Ok((n > 0).then_some(line))
    }
    fn read_hidden(&mut self, prompt: &str) -> std::io::Result<Zeroizing<String>> {
        // rpassword prompts on and reads from the controlling terminal
        // (/dev/tty; CONOUT$/CONIN$ on Windows) with echo off.
        rpassword::prompt_password(prompt).map(Zeroizing::new)
    }
}

pub(crate) struct Secrets<I: SecretIo = RealIo> {
    pub(crate) io: I,
    stdin_lines: usize,
    prompted: bool,
}

impl Secrets<RealIo> {
    pub(crate) fn real() -> Self {
        Secrets::new(RealIo)
    }
}

enum Origin {
    Env,
    Stdin(usize),
    Prompt,
}

impl<I: SecretIo> Secrets<I> {
    pub(crate) fn new(io: I) -> Self {
        Secrets {
            io,
            stdin_lines: 0,
            prompted: false,
        }
    }

    /// Whether any secret so far came from a hidden prompt (no flag at a
    /// terminal, or `--X stdin` typed at one). A person typing is a gap of
    /// human length: the caller re-finds the key before opening it.
    pub(crate) fn prompted(&self) -> bool {
        self.prompted
    }

    pub(crate) fn terminal_present(&self) -> bool {
        crate::prompt::terminal_present(self.io.stdin_is_terminal(), self.io.stderr_is_terminal())
    }

    /// Refuse early (no device I/O, nothing read) when a required secret
    /// has no source and no terminal can ask for it, or when an `env:NAME`
    /// source is given but unusable (unset, empty, or not valid UTF-8) — a
    /// bad environment variable is caught before any key is selected, not
    /// after. A variable that disappears between this call and [`Self::read`]
    /// is still caught there.
    pub(crate) fn check(&self, spec: &Spec, src: Source<'_>) -> Result<(), String> {
        if let Some(var) = src.env {
            return match self.io.env(var) {
                EnvValue::Set(v) => finish(spec, v, Origin::Env).map(|_| ()),
                EnvValue::Unset => Err(env_problem(spec, "is not set")),
                EnvValue::NotUnicode => Err(env_problem(spec, "is not valid UTF-8")),
            };
        }
        if src.given() || self.terminal_present() {
            Ok(())
        } else {
            Err(spec.no_source())
        }
    }

    pub(crate) fn check_one_of(
        &self,
        what: &str,
        options: &[(Spec, Source<'_>)],
    ) -> Result<(), String> {
        match options.iter().filter(|(_, s)| s.given()).count() {
            1 => Ok(()),
            0 => Err(format!("no {what} given: pass {}", join_hints(options))),
            _ => Err(format!("give only one {what} source")),
        }
    }

    pub(crate) fn read(
        &mut self,
        spec: &Spec,
        src: Source<'_>,
    ) -> Result<Zeroizing<String>, String> {
        if let Some(var) = src.env {
            let raw = match self.io.env(var) {
                EnvValue::Set(v) => v,
                EnvValue::Unset => return Err(env_problem(spec, "is not set")),
                EnvValue::NotUnicode => return Err(env_problem(spec, "is not valid UTF-8")),
            };
            return finish(spec, raw, Origin::Env);
        }
        if src.stdin && !self.io.stdin_is_terminal() {
            self.stdin_lines += 1;
            let n = self.stdin_lines;
            let line = self
                .io
                .read_line()
                .map_err(|e| format!("could not read the {} from stdin: {e}", spec.label))?
                .ok_or_else(|| {
                    format!(
                        "expected the {} on stdin line {n}, but stdin ended",
                        spec.label
                    )
                })?;
            let trimmed = Zeroizing::new(strip_line_ending(&line).to_owned());
            return finish(spec, trimmed, Origin::Stdin(n));
        }
        // `--X stdin` at a terminal, or no flag with a terminal present.
        if src.stdin || self.terminal_present() {
            return self.prompt(spec);
        }
        Err(spec.no_source())
    }

    pub(crate) fn read_given(
        &mut self,
        spec: &Spec,
        src: Source<'_>,
    ) -> Result<Option<Zeroizing<String>>, String> {
        if src.given() {
            self.read(spec, src).map(Some)
        } else {
            Ok(None)
        }
    }

    pub(crate) fn read_one_of(
        &mut self,
        what: &str,
        options: &[(Spec, Source<'_>)],
    ) -> Result<(usize, Zeroizing<String>), String> {
        self.check_one_of(what, options)?;
        let i = options
            .iter()
            .position(|(_, s)| s.given())
            .expect("checked: exactly one");
        let (spec, src) = &options[i];
        Ok((i, self.read(spec, *src)?))
    }

    fn prompt(&mut self, spec: &Spec) -> Result<Zeroizing<String>, String> {
        let first = finish(spec, self.hidden(spec, false)?, Origin::Prompt)?;
        if spec.kind == Kind::New {
            let again = finish(spec, self.hidden(spec, true)?, Origin::Prompt)?;
            if *again != *first {
                return Err(format!(
                    "the two {} entries did not match; nothing was changed",
                    spec.label
                ));
            }
        }
        Ok(first)
    }

    fn hidden(&mut self, spec: &Spec, repeat: bool) -> Result<Zeroizing<String>, String> {
        self.prompted = true;
        self.io
            .read_hidden(&spec.prompt_text(repeat))
            .map_err(|e| match e.kind() {
                // rpassword turns off ISIG, so Ctrl-C arrives as a plain byte
                // and it raises SIGINT itself before returning — that kills
                // the process outright (and the terminal's echo may stay
                // off unless the shell restores it), so on Unix `Interrupted`
                // here is never actually reached from a live Ctrl-C; only
                // Ctrl-D (UnexpectedEof) reaches this branch. On Windows
                // rpassword calls GenerateConsoleCtrlEvent, which is
                // asynchronous: `Interrupted` can come back and this message
                // may print before the Ctrl-C handler ends the process —
                // the same outcome, nothing changed.
                ErrorKind::Interrupted | ErrorKind::UnexpectedEof => {
                    "canceled; nothing was changed".to_string()
                }
                _ => format!(
                    "could not read the {} at a hidden prompt ({e}); pass {} instead",
                    spec.label,
                    spec.sources_hint()
                ),
            })
    }
}

/// "the environment variable given to --pin is not set" — the flag, never
/// the variable's name, which may be the secret itself: a user migrating
/// from the old command line sometimes passes the secret where the name
/// goes (`--pin env:DEADBEEF` instead of `--pin env:KR_PIN`).
fn env_problem(spec: &Spec, problem: &str) -> String {
    if spec.legacy {
        return format!(
            "the environment variable given to --{}-env {problem}",
            spec.flag
        );
    }
    format!(
        "the environment variable given to --{} {problem}",
        spec.flag
    )
}

fn strip_line_ending(line: &str) -> &str {
    let l = line.strip_suffix('\n').unwrap_or(line);
    l.strip_suffix('\r').unwrap_or(l)
}

/// PINs and passwords are kept exactly; hex and base32 lose surrounding
/// ASCII whitespace (finding 10). An empty result is never a secret.
fn finish(
    spec: &Spec,
    raw: Zeroizing<String>,
    origin: Origin,
) -> Result<Zeroizing<String>, String> {
    let value = match spec.form {
        Form::Text => raw,
        Form::Hex | Form::Base32 => Zeroizing::new(
            raw.trim_matches(|c: char| c.is_ascii_whitespace())
                .to_owned(),
        ),
    };
    if !value.is_empty() {
        return Ok(value);
    }
    Err(match origin {
        Origin::Env => env_problem(spec, "is empty"),
        Origin::Stdin(n) => format!("the {} on stdin line {n} is empty", spec.label),
        Origin::Prompt => format!("no {} entered; nothing was changed", spec.label),
    })
}

fn join_hints(options: &[(Spec, Source<'_>)]) -> String {
    let parts: Vec<String> = options
        .iter()
        .flat_map(|(s, _)| {
            if s.legacy {
                [
                    format!("--{}-env VAR", s.flag),
                    format!("--{}-stdin", s.flag),
                ]
            } else {
                [
                    format!("--{} env:NAME", s.flag),
                    format!("--{} stdin", s.flag),
                ]
            }
        })
        .collect();
    match parts.split_last() {
        Some((last, rest)) if !rest.is_empty() => format!("{} or {last}", rest.join(", ")),
        _ => parts.join(""),
    }
}

#[cfg(test)]
pub(crate) mod fake {
    use super::*;
    use std::collections::{HashMap, VecDeque};

    /// Scripted terminal + environment + stdin for unit tests.
    #[derive(Default)]
    pub(crate) struct FakeIo {
        pub(crate) env: HashMap<String, String>,
        pub(crate) not_unicode: std::collections::HashSet<String>,
        pub(crate) stdin_tty: bool,
        pub(crate) stderr_tty: bool,
        pub(crate) lines: VecDeque<String>,
        pub(crate) line_errors: VecDeque<std::io::ErrorKind>,
        pub(crate) typed: VecDeque<Result<String, std::io::ErrorKind>>,
        pub(crate) prompts: Vec<String>,
        pub(crate) lines_read: usize,
    }
    impl FakeIo {
        pub(crate) fn terminal() -> Self {
            Self {
                stdin_tty: true,
                stderr_tty: true,
                ..Self::default()
            }
        }
        pub(crate) fn piped(lines: &[&str]) -> Self {
            Self {
                lines: lines.iter().map(|l| l.to_string()).collect(),
                ..Self::default()
            }
        }
        pub(crate) fn var(mut self, k: &str, v: &str) -> Self {
            self.env.insert(k.into(), v.into());
            self
        }
        pub(crate) fn not_unicode_var(mut self, k: &str) -> Self {
            self.not_unicode.insert(k.into());
            self
        }
        pub(crate) fn typing(mut self, answers: &[&str]) -> Self {
            self.typed = answers.iter().map(|a| Ok(a.to_string())).collect();
            self
        }
    }
    impl SecretIo for FakeIo {
        fn env(&self, var: &str) -> EnvValue {
            if self.not_unicode.contains(var) {
                return EnvValue::NotUnicode;
            }
            match self.env.get(var) {
                Some(v) => EnvValue::Set(Zeroizing::new(v.clone())),
                None => EnvValue::Unset,
            }
        }
        fn stdin_is_terminal(&self) -> bool {
            self.stdin_tty
        }
        fn stderr_is_terminal(&self) -> bool {
            self.stderr_tty
        }
        fn read_line(&mut self) -> std::io::Result<Option<Zeroizing<String>>> {
            self.lines_read += 1;
            if let Some(kind) = self.line_errors.pop_front() {
                return Err(kind.into());
            }
            Ok(self.lines.pop_front().map(Zeroizing::new))
        }
        fn read_hidden(&mut self, prompt: &str) -> std::io::Result<Zeroizing<String>> {
            self.prompts.push(prompt.to_string());
            match self.typed.pop_front() {
                Some(Ok(s)) => Ok(Zeroizing::new(s)),
                Some(Err(k)) => Err(k.into()),
                None => Err(std::io::ErrorKind::UnexpectedEof.into()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakeIo;
    use super::*;

    const PIN: Spec = Spec::current("PIN", "pin");
    const NEW_PIN: Spec = Spec::new_secret("new PIN", "new-pin");
    const MGMT: Spec = Spec::current("management key", "mgmt-key")
        .hex()
        .with_default();
    const SEED: Spec = Spec::value("seed", "seed").base32();

    fn sec(io: FakeIo) -> Secrets<FakeIo> {
        Secrets::new(io)
    }

    #[test]
    fn env_beats_stdin_beats_prompt() {
        let mut s = sec(FakeIo::terminal().var("KR_P", "1111"));
        s.io.lines.push_back("2222\n".into());
        assert_eq!(
            &*s.read(&PIN, Source::new(Some("KR_P"), true)).unwrap(),
            "1111"
        );
        assert!(s.io.prompts.is_empty() && s.io.lines_read == 0);
        let mut s = sec(FakeIo::piped(&["2222\n"]));
        assert_eq!(&*s.read(&PIN, Source::new(None, true)).unwrap(), "2222");
        let mut s = sec(FakeIo::terminal().typing(&["3333"]));
        assert_eq!(&*s.read(&PIN, Source::NONE).unwrap(), "3333");
        assert_eq!(s.io.prompts, vec!["PIN: ".to_string()]);
        assert_eq!(s.io.lines_read, 0, "the prompt never reads stdin");
    }

    #[test]
    fn unset_env_var_names_the_flag_never_the_variable() {
        let mut s = sec(FakeIo::terminal());
        assert_eq!(
            s.read(&PIN, Source::env("KR_NOPE")).unwrap_err(),
            "the environment variable given to --pin is not set"
        );
        assert!(
            s.io.prompts.is_empty(),
            "an env source never falls back to the prompt"
        );
    }

    /// An env var's *name* is never echoed, however plausible it looks — a
    /// user migrating from the old command line may have passed the secret
    /// itself where the name goes.
    #[test]
    fn an_env_var_name_is_never_repeated_in_an_error() {
        for name in [
            "1234S3CRET",
            "otpauth://totp/x?secret=S3CRET",
            "S3CRET-PASS",
            "S3CRET pass",
            "",
            "PIN",
            "DEADBEEF",
            "_X",
            "KR_PIN_2",
        ] {
            let mut s = sec(FakeIo::terminal());
            let e = s.read(&PIN, Source::env(name)).unwrap_err();
            assert_eq!(
                e, "the environment variable given to --pin is not set",
                "{name:?}"
            );
            assert!(!e.contains(name) || name.is_empty(), "{name:?}: {e}");
        }
        // Empty and non-UTF-8 values are reported the same way, by flag only.
        let mut s = sec(FakeIo::default().var("DEADBEEF", ""));
        assert_eq!(
            s.read(&PIN, Source::env("DEADBEEF")).unwrap_err(),
            "the environment variable given to --pin is empty"
        );
        let mut s = sec(FakeIo::default().not_unicode_var("DEADBEEF"));
        assert_eq!(
            s.read(&PIN, Source::env("DEADBEEF")).unwrap_err(),
            "the environment variable given to --pin is not valid UTF-8"
        );
    }

    #[test]
    fn empty_env_var_is_refused_without_naming_it() {
        let mut s = sec(FakeIo::default().var("KR_E", ""));
        assert_eq!(
            s.read(&PIN, Source::env("KR_E")).unwrap_err(),
            "the environment variable given to --pin is empty"
        );
    }

    #[test]
    fn whitespace_only_hex_is_empty() {
        let mut s = sec(FakeIo::default().var("KR_K", "  \t "));
        assert_eq!(
            s.read(&MGMT, Source::env("KR_K")).unwrap_err(),
            "the environment variable given to --mgmt-key is empty"
        );
    }

    #[test]
    fn no_source_without_terminal_names_the_flags_per_prefix() {
        for (spec, want) in [
            (PIN, "no PIN given: pass --pin env:NAME or --pin stdin"),
            (NEW_PIN, "no new PIN given: pass --new-pin env:NAME or --new-pin stdin"),
            (
                Spec::current("admin PIN (PW3)", "admin-pin"),
                "no admin PIN (PW3) given: pass --admin-pin env:NAME or --admin-pin stdin",
            ),
            (
                MGMT,
                "no management key given: pass --mgmt-key env:NAME, --mgmt-key stdin or --mgmt-key default",
            ),
            (
                Spec::value("otpauth:// URI", "uri").hint("`-` to read it from stdin, --uri-env VAR or --qr IMAGE"),
                "no otpauth:// URI given: pass `-` to read it from stdin, --uri-env VAR or --qr IMAGE",
            ),
        ] {
            let s = sec(FakeIo::default());
            assert_eq!(s.check(&spec, Source::NONE).unwrap_err(), want);
            let mut s = sec(FakeIo::default());
            assert_eq!(s.read(&spec, Source::NONE).unwrap_err(), want);
            assert_eq!(s.io.lines_read, 0);
        }
    }

    #[test]
    fn terminal_stdin_with_piped_stderr_refuses_without_a_flag() {
        let io = FakeIo {
            stdin_tty: true,
            stderr_tty: false,
            ..FakeIo::default()
        };
        let mut s = sec(io);
        assert!(s
            .read(&PIN, Source::NONE)
            .unwrap_err()
            .starts_with("no PIN given"));
        assert!(s.io.prompts.is_empty());
    }

    #[test]
    fn stdin_flag_at_a_terminal_reads_hidden_even_with_piped_stderr() {
        let io = FakeIo {
            stdin_tty: true,
            stderr_tty: false,
            ..FakeIo::default()
        }
        .typing(&["4321"]);
        let mut s = sec(io);
        assert_eq!(&*s.read(&PIN, Source::new(None, true)).unwrap(), "4321");
        assert_eq!(s.io.prompts, vec!["PIN: ".to_string()]);
        assert_eq!(
            s.io.lines_read, 0,
            "never an echoing read_line at a terminal"
        );
    }

    #[test]
    fn new_secret_at_a_prompt_is_asked_twice() {
        let mut s = sec(FakeIo::terminal().typing(&["5678", "5678"]));
        assert_eq!(&*s.read(&NEW_PIN, Source::NONE).unwrap(), "5678");
        assert_eq!(
            s.io.prompts,
            vec!["New PIN: ".to_string(), "Repeat new PIN: ".to_string()]
        );
        let mut s = sec(FakeIo::terminal().typing(&["5678", "5679"]));
        assert_eq!(
            s.read(&NEW_PIN, Source::NONE).unwrap_err(),
            "the two new PIN entries did not match; nothing was changed"
        );
    }

    #[test]
    fn piped_and_env_new_secrets_are_not_repeated() {
        let mut s = sec(FakeIo::piped(&["5678\n"]));
        assert_eq!(&*s.read(&NEW_PIN, Source::new(None, true)).unwrap(), "5678");
        let mut s = sec(FakeIo::terminal().var("KR_N", "5678"));
        assert_eq!(&*s.read(&NEW_PIN, Source::env("KR_N")).unwrap(), "5678");
        assert!(s.io.prompts.is_empty());
    }

    #[test]
    fn value_kind_is_asked_once_with_its_encoding() {
        let mut s = sec(FakeIo::terminal().typing(&["JBSWY3DPEHPK3PXP"]));
        assert_eq!(&*s.read(&SEED, Source::NONE).unwrap(), "JBSWY3DPEHPK3PXP");
        assert_eq!(s.io.prompts, vec!["Seed (base32): ".to_string()]);
    }

    #[test]
    fn pins_keep_spaces_hex_and_base32_are_trimmed() {
        let mut s = sec(FakeIo::piped(&[" 12 34 \r\n"]).var("KR_P", " 99 "));
        assert_eq!(&*s.read(&PIN, Source::new(None, true)).unwrap(), " 12 34 ");
        assert_eq!(&*s.read(&PIN, Source::env("KR_P")).unwrap(), " 99 ");
        let mut s = sec(FakeIo::piped(&["  0a0b \n"]).var("KR_S", "\t JBSW Y3DP \n"));
        assert_eq!(&*s.read(&MGMT, Source::new(None, true)).unwrap(), "0a0b");
        assert_eq!(&*s.read(&SEED, Source::env("KR_S")).unwrap(), "JBSW Y3DP");
    }

    #[test]
    fn two_lines_come_in_order() {
        let mut s = sec(FakeIo::piped(&["old\n", "new\n"]));
        assert_eq!(&*s.read(&PIN, Source::new(None, true)).unwrap(), "old");
        assert_eq!(&*s.read(&NEW_PIN, Source::new(None, true)).unwrap(), "new");
    }

    #[test]
    fn second_line_missing_names_the_line() {
        let mut s = sec(FakeIo::piped(&["old\n"]));
        s.read(&PIN, Source::new(None, true)).unwrap();
        assert_eq!(
            s.read(&NEW_PIN, Source::new(None, true)).unwrap_err(),
            "expected the new PIN on stdin line 2, but stdin ended"
        );
    }

    #[test]
    fn empty_stdin_line_is_refused() {
        let mut s = sec(FakeIo::piped(&["\n"]));
        assert_eq!(
            s.read(&PIN, Source::new(None, true)).unwrap_err(),
            "the PIN on stdin line 1 is empty"
        );
    }

    #[test]
    fn prompt_cancel_and_empty() {
        let mut io = FakeIo::terminal();
        io.typed.push_back(Err(std::io::ErrorKind::Interrupted));
        assert_eq!(
            sec(io).read(&PIN, Source::NONE).unwrap_err(),
            "canceled; nothing was changed"
        );
        let mut io = FakeIo::terminal();
        io.typed.push_back(Err(std::io::ErrorKind::UnexpectedEof));
        assert_eq!(
            sec(io).read(&PIN, Source::NONE).unwrap_err(),
            "canceled; nothing was changed"
        );
        assert_eq!(
            sec(FakeIo::terminal().typing(&[""]))
                .read(&PIN, Source::NONE)
                .unwrap_err(),
            "no PIN entered; nothing was changed"
        );
        let mut io = FakeIo::terminal();
        io.typed.push_back(Err(std::io::ErrorKind::NotFound));
        let e = sec(io).read(&PIN, Source::NONE).unwrap_err();
        assert!(
            e.starts_with("could not read the PIN at a hidden prompt (")
                && e.ends_with("); pass --pin env:NAME or --pin stdin instead"),
            "{e}"
        );
    }

    #[test]
    fn read_given_never_prompts() {
        let mut s = sec(FakeIo::terminal().typing(&["x"]));
        assert!(s.read_given(&PIN, Source::NONE).unwrap().is_none());
        assert!(s.io.prompts.is_empty());
    }

    #[test]
    fn check_is_pure_and_accepts_a_terminal_or_any_flag() {
        let s = sec(FakeIo::terminal());
        assert!(s.check(&PIN, Source::NONE).is_ok());
        let s = sec(FakeIo::default().var("KR_SET", "1111"));
        assert!(
            s.check(&PIN, Source::env("KR_SET")).is_ok(),
            "a usable env source is accepted up front"
        );
        assert!(s.check(&PIN, Source::new(None, true)).is_ok());
        assert_eq!(s.io.lines_read, 0);
    }

    /// `check` validates an `--X-env` source immediately (unset, empty, or
    /// not UTF-8), so a bad environment variable is caught before any key
    /// is selected — not only later, when the secret is actually read.
    #[test]
    fn check_refuses_an_unusable_env_source_before_any_read() {
        let s = sec(FakeIo::default());
        assert_eq!(
            s.check(&PIN, Source::env("KR_NOPE")).unwrap_err(),
            "the environment variable given to --pin is not set"
        );
        let s = sec(FakeIo::default().var("KR_E", ""));
        assert_eq!(
            s.check(&PIN, Source::env("KR_E")).unwrap_err(),
            "the environment variable given to --pin is empty"
        );
        let s = sec(FakeIo::default().not_unicode_var("KR_BAD"));
        assert_eq!(
            s.check(&PIN, Source::env("KR_BAD")).unwrap_err(),
            "the environment variable given to --pin is not valid UTF-8"
        );
        assert_eq!(s.io.lines_read, 0);
    }

    /// A variable that was fine at `check` time and disappears before
    /// [`Secrets::read`] still gets a clear refusal there, naming only the
    /// flag — `check` validating up front doesn't make `read` trust it.
    #[test]
    fn read_still_catches_an_env_var_that_vanishes_after_check() {
        let mut s = sec(FakeIo::default().var("KR_GONE", "1111"));
        assert!(s.check(&PIN, Source::env("KR_GONE")).is_ok());
        s.io.env.remove("KR_GONE");
        assert_eq!(
            s.read(&PIN, Source::env("KR_GONE")).unwrap_err(),
            "the environment variable given to --pin is not set"
        );
    }

    #[test]
    fn exactly_one_of_two_encodings() {
        const HEX: Spec = Spec::value("seed", "hex").hex().legacy();
        const B32: Spec = Spec::value("seed", "base32").base32().legacy();
        let mut s = sec(FakeIo::terminal());
        assert_eq!(
            s.read_one_of("seed", &[(HEX, Source::NONE), (B32, Source::NONE)])
                .unwrap_err(),
            "no seed given: pass --hex-env VAR, --hex-stdin, --base32-env VAR or --base32-stdin"
        );
        assert!(
            s.io.prompts.is_empty(),
            "the encoding can't be guessed, so no prompt"
        );
        let mut s = sec(FakeIo::default().var("A", "00").var("B", "AA"));
        assert_eq!(
            s.read_one_of("seed", &[(HEX, Source::env("A")), (B32, Source::env("B"))])
                .unwrap_err(),
            "give only one seed source"
        );
        let mut s = sec(FakeIo::piped(&[" JBSWY3DP\n"]));
        let (i, v) = s
            .read_one_of(
                "seed",
                &[(HEX, Source::NONE), (B32, Source::new(None, true))],
            )
            .unwrap();
        assert_eq!((i, v.as_str()), (1, "JBSWY3DP"));
    }

    #[test]
    fn not_unicode_env_var_names_the_flag_never_the_variable() {
        let mut s = sec(FakeIo::terminal().not_unicode_var("KR_BAD"));
        assert_eq!(
            s.read(&PIN, Source::env("KR_BAD")).unwrap_err(),
            "the environment variable given to --pin is not valid UTF-8"
        );
        assert!(
            s.io.prompts.is_empty(),
            "an env source never falls back to the prompt"
        );
    }

    #[test]
    fn read_line_io_error_names_the_secret() {
        let mut io = FakeIo::piped(&[]);
        io.line_errors.push_back(std::io::ErrorKind::BrokenPipe);
        let mut s = sec(io);
        let e = s.read(&PIN, Source::new(None, true)).unwrap_err();
        assert!(e.starts_with("could not read the PIN from stdin: "), "{e}");
    }

    #[test]
    fn check_one_of_refuses_two_given_sources() {
        const HEX: Spec = Spec::value("seed", "hex").hex();
        const B32: Spec = Spec::value("seed", "base32").base32();
        let s = sec(FakeIo::default().var("A", "00").var("B", "AA"));
        assert_eq!(
            s.check_one_of("seed", &[(HEX, Source::env("A")), (B32, Source::env("B"))])
                .unwrap_err(),
            "give only one seed source"
        );
    }

    #[test]
    fn prompted_only_after_a_hidden_read() {
        let mut s = sec(FakeIo::piped(&["1234\n"]).var("V", "9"));
        s.read(&PIN, Source::env("V")).unwrap();
        s.read(&PIN, Source::new(None, true)).unwrap();
        assert!(!s.prompted(), "env and piped stdin are not a prompt");
        s.read_given(&PIN, Source::NONE).unwrap();
        assert!(!s.prompted(), "nothing read");

        let mut s = sec(FakeIo::terminal().typing(&["1234"]));
        assert!(!s.prompted());
        s.read(&PIN, Source::NONE).unwrap();
        assert!(s.prompted(), "no flag at a terminal");

        let mut s = sec(FakeIo::terminal().typing(&["1234"]));
        s.read(&PIN, Source::new(None, true)).unwrap();
        assert!(s.prompted(), "--pin-stdin typed at a terminal");

        // A canceled prompt still counts: the person was at the keyboard.
        let mut s = sec(FakeIo::terminal());
        assert!(s.read(&PIN, Source::NONE).is_err());
        assert!(s.prompted());
    }

    #[test]
    fn new_secret_empty_repeat_is_refused() {
        let mut s = sec(FakeIo::terminal().typing(&["5678", ""]));
        assert_eq!(
            s.read(&NEW_PIN, Source::NONE).unwrap_err(),
            "no new PIN entered; nothing was changed"
        );
    }

    #[test]
    fn parse_source_grammar() {
        assert_eq!(parse_source("stdin"), Ok(SecretSource::Stdin));
        assert_eq!(
            parse_source("env:KR_PIN"),
            Ok(SecretSource::Env("KR_PIN".into()))
        );
        assert_eq!(parse_source("env:a:b"), Ok(SecretSource::Env("a:b".into())));
        for bad in [
            "", "123456", "env:", "STDIN", "Stdin", "-", "default", "env", "-123456",
        ] {
            assert!(parse_source(bad).is_err(), "{bad:?}");
        }
        assert_eq!(
            parse_source_or_default("default"),
            Ok(SecretSource::Default)
        );
        assert!(parse_source_or_default("DEFAULT").is_err());
        assert_eq!(parse_source("x").unwrap_err(), "not a secret source");
    }

    #[test]
    fn literal_refusal_text_per_flag() {
        assert_eq!(
            literal_refusal("pin").unwrap(),
            "--pin takes env:NAME or stdin — never the PIN itself"
        );
        assert_eq!(
            literal_refusal("mgmt-key").unwrap(),
            "--mgmt-key takes env:NAME, stdin or default — never the management key itself"
        );
        assert!(literal_refusal("slot").is_none());
        for f in SECRET_FLAGS {
            let m = literal_refusal(f.long).unwrap();
            assert!(m.starts_with(&format!("--{} takes ", f.long)), "{m}");
        }
    }

    #[test]
    fn env_problems_name_the_flag_never_the_variable() {
        const P: Spec = Spec::current("PIN", "pin");
        // Unset, empty, not UTF-8 — at check() and at read().
        let mut s = sec(FakeIo::default()
            .var("EMPTY_S3CRET", "")
            .not_unicode_var("BAD_S3CRET"));
        for (var, want) in [
            (
                "123456",
                "the environment variable given to --pin is not set",
            ),
            (
                "EMPTY_S3CRET",
                "the environment variable given to --pin is empty",
            ),
            (
                "BAD_S3CRET",
                "the environment variable given to --pin is not valid UTF-8",
            ),
        ] {
            let e = s.check(&P, Source::env(var)).unwrap_err();
            assert_eq!(e, want);
            let e = s.read(&P, Source::env(var)).unwrap_err();
            assert_eq!(e, want);
            assert!(!e.contains(var));
        }
    }

    #[test]
    fn sources_hint_new_grammar() {
        assert_eq!(
            Spec::current("PIN", "pin").sources_hint(),
            "--pin env:NAME or --pin stdin"
        );
        assert_eq!(
            Spec::current("management key", "mgmt-key")
                .hex()
                .with_default()
                .sources_hint(),
            "--mgmt-key env:NAME, --mgmt-key stdin or --mgmt-key default"
        );
        assert_eq!(
            Spec::value("seed", "hex").hex().legacy().sources_hint(),
            "--hex-env VAR or --hex-stdin"
        );
    }

    #[test]
    fn from_flag_maps_each_source() {
        let env = SecretSource::Env("V".into());
        assert_eq!(Source::from_flag(Some(&env)).env, Some("V"));
        assert!(Source::from_flag(Some(&SecretSource::Stdin)).stdin);
        assert!(!Source::from_flag(Some(&SecretSource::Default)).given());
        assert!(!Source::from_flag(None).given());
        assert!(wants_default(Some(&SecretSource::Default)) && !wants_default(None));
    }
}
