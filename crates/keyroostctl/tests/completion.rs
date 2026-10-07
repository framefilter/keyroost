//! `--device` completes saved friendly names from keys.json via the
//! dynamic engine, end to end, without touching hardware.

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Gives every `complete` call its own config directory, so tests running
/// in parallel never share or delete each other's keys.json.
static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);

/// Runs the dynamic completer (fish flavor) for `words` against a keys.json
/// holding two saved names, and returns its stdout.
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
    let out = Command::new(env!("CARGO_BIN_EXE_keyroostctl"))
        .env("KEYROOSTCTL_COMPLETE", "fish")
        .env("XDG_CONFIG_HOME", &dir)
        .env("APPDATA", &dir)
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
    let out = complete(&["keyroostctl", "fido", "pin", "retries", "--device", ""]);
    assert!(out.lines().any(|l| l.starts_with("yubi-test")), "{out}");
}

#[test]
fn fido_completes_the_new_groups() {
    let out = complete(&["keyroostctl", "fido", ""]);
    for g in ["pin", "credentials", "fingerprints", "config"] {
        assert!(
            out.lines().any(|l| l.split_whitespace().next() == Some(g)),
            "{g}: {out}"
        );
    }
    assert!(
        !out.contains("pin-set") && !out.contains("creds-list"),
        "{out}"
    );
}

/// A generic `COMPLETE` left in the environment (other clap-based tools use
/// that name) must not turn a normal run into a completion request.
#[test]
fn generic_complete_var_is_ignored() {
    let out = Command::new(env!("CARGO_BIN_EXE_keyroostctl"))
        .env("COMPLETE", "fish")
        .arg("--version")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{out:?}");
    assert!(stdout.starts_with("keyroostctl "), "{stdout}");
}
