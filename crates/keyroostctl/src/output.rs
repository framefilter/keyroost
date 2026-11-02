//! Where the CLI's output goes: the `--json` switch, the JSON emitter, the
//! stderr message helpers, the aligned `Key: value` block, and the text
//! behind `outln!` / `out!` / `errln!`.

use std::borrow::Cow;
use std::io::IsTerminal;
use std::sync::OnceLock;

/// Whether stdout / stderr go somewhere other than a console on Windows (a
/// pipe or a file), decided once per stream.
static STDOUT_PIPED: OnceLock<bool> = OnceLock::new();
static STDERR_PIPED: OnceLock<bool> = OnceLock::new();

fn stdout_piped() -> bool {
    *STDOUT_PIPED.get_or_init(|| cfg!(windows) && !std::io::stdout().is_terminal())
}

fn stderr_piped() -> bool {
    *STDERR_PIPED.get_or_init(|| cfg!(windows) && !std::io::stderr().is_terminal())
}

/// `text` with the punctuation keyroost writes itself in ASCII.
///
/// Windows PowerShell 5.1 reads a program's piped or redirected output in the
/// console's legacy code page, not UTF-8, so `→` arrives as `ΓåÆ` and `·` as
/// `┬╖`. A console shows UTF-8 correctly, so this is only for a Windows stream
/// that isn't one. Other characters (a key's name, say) pass through as they
/// are; JSON never comes here.
pub(crate) fn ascii_punctuation(text: &str) -> Cow<'_, str> {
    if text.is_ascii() {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '—' | '–' | '─' => out.push('-'),
            '…' => out.push_str("..."),
            '·' => out.push('|'),
            '→' => out.push_str("->"),
            '✓' => out.push_str("[ok]"),
            '✗' => out.push_str("[x]"),
            '⏵' => out.push('>'),
            c => out.push(c),
        }
    }
    Cow::Owned(out)
}

/// `println!` for the CLI's own text (`outln!`).
pub(crate) fn out_line(args: std::fmt::Arguments<'_>) {
    if stdout_piped() {
        std::println!("{}", ascii_punctuation(&args.to_string()));
    } else {
        std::println!("{args}");
    }
}

/// `print!` for the CLI's own text (`out!`).
pub(crate) fn out_text(args: std::fmt::Arguments<'_>) {
    if stdout_piped() {
        std::print!("{}", ascii_punctuation(&args.to_string()));
    } else {
        std::print!("{args}");
    }
}

/// `eprintln!` for the CLI's own text (`errln!`).
pub(crate) fn err_line(args: std::fmt::Arguments<'_>) {
    if stderr_piped() {
        std::eprintln!("{}", ascii_punctuation(&args.to_string()));
    } else {
        std::eprintln!("{args}");
    }
}

/// Whether the global `--json` flag was set, captured once in `run()` so the
/// status/query handlers can switch output without threading it through.
static JSON_OUTPUT: OnceLock<bool> = OnceLock::new();

/// Record the global `--json` flag. Called once, from `run()`.
pub(crate) fn set_json(on: bool) {
    let _ = JSON_OUTPUT.set(on);
}

/// Whether `--json` was given.
pub(crate) fn json_output() -> bool {
    *JSON_OUTPUT.get().unwrap_or(&false)
}

/// Pretty-print a serializable value as JSON to stdout (the `--json` path for
/// the status/query commands). Written as is, never through
/// [`ascii_punctuation`]: it is data.
pub(crate) fn emit_json<T: serde::Serialize>(value: &T) -> Result<(), Box<dyn std::error::Error>> {
    std::println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

/// A warning on stderr: `warning: <msg>`.
pub(crate) fn warn(msg: &str) {
    errln!("warning: {msg}");
}

/// A note on stderr: `note: <msg>`.
pub(crate) fn note(msg: &str) {
    errln!("note: {msg}");
}

/// A status line on stderr, unprefixed: prompts, progress, "wrote", the
/// target announcement.
pub(crate) fn status(msg: &str) {
    errln!("{msg}");
}

/// One aligned `Key: value` column: every value starts one space after the
/// longest `Key:`. No trailing newline.
pub(crate) fn kv_block(rows: &[(&str, String)]) -> String {
    let w = rows
        .iter()
        .map(|(k, _)| k.chars().count() + 1)
        .max()
        .unwrap_or(0);
    rows.iter()
        .map(|(k, v)| format!("{:<w$} {v}", format!("{k}:")))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn piped_text_keeps_its_meaning_in_ascii() {
        assert_eq!(
            ascii_punctuation("→ key · serial 42 — touch the key…"),
            "-> key | serial 42 - touch the key..."
        );
        assert_eq!(
            ascii_punctuation("✓ ok, ✗ failed, ⏵ wait"),
            "[ok] ok, [x] failed, > wait"
        );
        // Other characters are someone's data: left alone.
        assert_eq!(ascii_punctuation("Clé de José"), "Clé de José");
        assert!(matches!(ascii_punctuation("plain"), Cow::Borrowed("plain")));
    }

    #[test]
    fn kv_block_aligns_one_column() {
        let b = kv_block(&[("Device", "x".into()), ("PIN/UV protocols", "2, 1".into())]);
        assert_eq!(b, "Device:           x\nPIN/UV protocols: 2, 1");
        assert_eq!(kv_block(&[]), "");
    }
}
