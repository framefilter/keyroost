//! Where the CLI's output goes: the `--json` switch, the JSON emitter, the
//! stderr message helpers, and the aligned `Key: value` block.

use std::sync::OnceLock;

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
/// the status/query commands).
pub(crate) fn emit_json<T: serde::Serialize>(value: &T) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

/// A warning on stderr: `warning: <msg>`.
pub(crate) fn warn(msg: &str) {
    eprintln!("warning: {msg}");
}

/// A note on stderr: `note: <msg>`.
pub(crate) fn note(msg: &str) {
    eprintln!("note: {msg}");
}

/// A status line on stderr, unprefixed: prompts, progress, "wrote", the
/// target announcement.
#[allow(dead_code)] // first callers arrive with the text-output pass
pub(crate) fn status(msg: &str) {
    eprintln!("{msg}");
}

/// One aligned `Key: value` column: every value starts one space after the
/// longest `Key:`. No trailing newline.
#[allow(dead_code)] // first callers arrive with the text-output pass
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
    fn kv_block_aligns_one_column() {
        let b = kv_block(&[("Device", "x".into()), ("PIN/UV protocols", "2, 1".into())]);
        assert_eq!(b, "Device:           x\nPIN/UV protocols: 2, 1");
        assert_eq!(kv_block(&[]), "");
    }
}
