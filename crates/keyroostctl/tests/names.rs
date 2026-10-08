//! `name set | clear | list` refusals and help, each run against its own
//! empty config directory: never the real keys.json, never a key's PIN.
mod common;
use common::ConfigIn;

use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);

/// Run keyroostctl with `args` in a fresh config directory: (exit code,
/// stdout, stderr).
fn run(args: &[&str]) -> (i32, String, String) {
    let dir = std::env::temp_dir().join(format!(
        "keyroost-names-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let out = common::keyroostctl()
        .args(args)
        .stdin(Stdio::null())
        .config_in(&dir)
        // pcsc-lite: no daemon reachable, so nothing can talk to a card.
        .env("PCSCLITE_CSOCK_NAME", "/nonexistent/keyroost-test-no-pcsc")
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn clearing_an_unknown_name_fails_naming_it() {
    let (code, _, err) = run(&["name", "clear", "Nope"]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("no name 'Nope' on this computer"), "{err}");
}

#[test]
fn a_name_and_device_together_are_a_usage_error() {
    let (code, _, err) = run(&["-d", "1", "name", "clear", "Nope"]);
    assert_eq!(code, 2, "{err}");
    assert!(
        err.contains("pass a NAME or select the key with -d, not both"),
        "{err}"
    );
}

#[test]
fn an_invalid_name_is_refused_before_any_key() {
    let (code, _, err) = run(&["name", "set", "a\u{200B}b"]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("invalid key name"), "{err}");
    assert!(!err.contains('\u{2192}'), "a key was selected: {err}");
}

#[test]
fn listing_an_empty_registry_succeeds() {
    let (code, out, err) = run(&["name", "list"]);
    assert_eq!(code, 0, "{err}");
    // A connected key may carry a name of its own; otherwise nothing is named.
    assert!(
        out.contains("(no names; add one with: keyroostctl -d <key> name set NAME)")
            || out.contains("on the key"),
        "{out}"
    );
    let (code, out, err) = run(&["--json", "name", "list"]);
    assert_eq!(code, 0, "{err}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert!(v["names"].is_array(), "{out}");
}

#[test]
fn the_retired_key_name_command_points_at_name_set() {
    let (code, _, err) = run(&["key-name", "add", "x"]);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("`key-name add` is now `name set`"), "{err}");
    assert!(
        err.contains("`key-name remove` is now `name clear`"),
        "{err}"
    );
}

#[test]
fn help_says_a_name_on_the_key_is_visible_to_anyone() {
    for args in [&["name", "--help"][..], &["name", "set", "--help"]] {
        let (code, out, err) = run(args);
        assert_eq!(code, 0, "{args:?}: {err}");
        assert!(
            out.contains("visible to anyone who has the key"),
            "{args:?}: {out}"
        );
    }
}
