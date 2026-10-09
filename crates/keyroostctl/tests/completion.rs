//! `--device` completes saved friendly names from keys.json via the
//! dynamic engine, end to end, without touching hardware.
mod common;
use common::ConfigIn;

use std::sync::atomic::{AtomicUsize, Ordering};

/// Gives every `complete` call its own config directory, so tests running
/// in parallel never share or delete each other's keys.json.
static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);

/// Runs the dynamic completer (fish flavor) for `words` against a keys.json
/// holding two saved names, and returns its stdout. The file is deliberately
/// in the old version 1 format (plain serials): completion loads it, which
/// converts it in its temp directory, and must still offer both names.
fn complete(words: &[&str]) -> String {
    let dir = std::env::temp_dir().join(format!(
        "keyroost-completion-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(dir.join("keyroost")).unwrap();
    std::fs::write(
        dir.join("keyroost/keys.json"),
        r#"{"keys":[{"name":"yubi-test","serial":"1","source":"usb"},{"name":"solo-test","serial":"2","source":"usb"}]}"#,
    )
    .unwrap();
    let out = common::keyroostctl()
        .env("KEYROOSTCTL_COMPLETE", "fish")
        .config_in(&dir)
        .arg("--")
        .args(words)
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(out.status.success(), "{out:?}");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn device_completes_saved_names() {
    let stdout = complete(&["keyroostctl", "--device", ""]);
    assert!(
        stdout.lines().any(|l| l.starts_with("yubi-test")),
        "{stdout}"
    );
    assert!(
        stdout.lines().any(|l| l.starts_with("solo-test")),
        "{stdout}"
    );
}

#[test]
fn device_completes_on_a_nested_path() {
    let out = complete(&["keyroostctl", "fido", "pin", "status", "--device", ""]);
    assert!(out.lines().any(|l| l.starts_with("yubi-test")), "{out}");
}

#[test]
fn fido_completes_the_new_groups() {
    let out = complete(&["keyroostctl", "fido", ""]);
    let first = |g: &str| out.lines().any(|l| l.split_whitespace().next() == Some(g));
    for g in ["pin", "credential", "fingerprint", "config", "blob", "ssh"] {
        assert!(first(g), "{g}: {out}");
    }
    for g in [
        "credentials",
        "fingerprints",
        "large-blob",
        "ssh-cert",
        "pin-set",
        "creds-list",
    ] {
        assert!(!first(g), "{g}: {out}");
    }
}

/// The renamed v0.13 paths complete, and `--device` still completes under
/// them.
#[test]
fn renamed_paths_complete() {
    let first = |out: &str, g: &str| out.lines().any(|l| l.split_whitespace().next() == Some(g));
    for (words, want, gone) in [
        (&["keyroostctl", "molto", ""][..], "list", "slots"),
        (&["keyroostctl", "molto", "seed", ""], "set", ""),
        (&["keyroostctl", "molto", "customer-key", ""], "change", ""),
        (&["keyroostctl", "fido", "pin", ""], "status", "retries"),
        (
            &["keyroostctl", "fido", "credential", ""],
            "status",
            "metadata",
        ),
        (&["keyroostctl", "fido", "blob", ""], "show", "get"),
        (&["keyroostctl", "fido", "ssh", ""], "export", "extract"),
        (&["keyroostctl", "otp", "button", ""], "clear", "delete"),
    ] {
        let out = complete(words);
        assert!(first(&out, want), "{words:?}: {out}");
        assert!(gone.is_empty() || !first(&out, gone), "{words:?}: {out}");
    }
    let out = complete(&["keyroostctl", "molto", "title", "set", "--device", ""]);
    assert!(out.lines().any(|l| l.starts_with("yubi-test")), "{out}");
}

#[test]
fn name_completes_at_the_top_level() {
    let out = complete(&["keyroostctl", ""]);
    let first = |g: &str| out.lines().any(|l| l.split_whitespace().next() == Some(g));
    assert!(first("name"), "{out}");
    assert!(!first("key-name"), "{out}");
}

/// A generic `COMPLETE` left in the environment (other clap-based tools use
/// that name) must not turn a normal run into a completion request.
#[test]
fn generic_complete_var_is_ignored() {
    let out = common::keyroostctl()
        .env("COMPLETE", "fish")
        .arg("--version")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{out:?}");
    assert!(stdout.starts_with("keyroostctl "), "{stdout}");
}
