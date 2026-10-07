//! Output-contract tests: stream, exit-code and shape rules for the CLI.
//! Each runs the real binary with no PC/SC service reachable.

use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Per-call counter so concurrent `run` calls in one test binary never share
/// a config dir.
static RUN_SEQ: AtomicUsize = AtomicUsize::new(0);

/// Run keyroostctl with no PC/SC service, an empty config dir and stdin
/// not a terminal. Returns (exit code, stdout, stderr).
pub fn run(args: &[&str]) -> (i32, String, String) {
    let dir = std::env::temp_dir().join(format!(
        "kr-out-{}-{}",
        std::process::id(),
        RUN_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_keyroostctl"))
        .args(args)
        .env("XDG_CONFIG_HOME", &dir)
        .env("APPDATA", &dir)
        .env("PCSCLITE_CSOCK_NAME", "/nonexistent/keyroost-test-no-pcsc")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn oath_add_digits_9_is_2_like_molto_config() {
    let (code, out, err) = run(&["oath", "add", "x", "--digits", "9"]);
    assert_eq!(code, 2, "{err}");
    assert!(out.is_empty());
    let (code, _, _) = run(&["molto", "config", "-p", "1", "--digits", "9"]);
    assert_eq!(code, 2);
}

#[test]
fn value_parser_errors_name_the_value_once() {
    // clap already prints "invalid value '<v>' for ..."; the parser's own
    // reason must not repeat it.
    for (args, v) in [
        (
            &["molto", "config", "-p", "abc", "--digits", "6"][..],
            "abc",
        ),
        (&["molto", "config", "-p", "120", "--digits", "6"], "120"),
        (&["otp", "button-hotp", "--digits", "7"], "7"),
        (&["piv", "self-sign", "--days", "zz"], "zz"),
        (&["piv", "self-sign", "--years", "zz"], "zz"),
        (&["piv", "self-sign", "--months", "zz"], "zz"),
    ] {
        let (code, _, err) = run(args);
        assert_eq!(code, 2, "{args:?}: {err}");
        let first = err.lines().next().unwrap_or("");
        assert_eq!(first.matches(v).count(), 1, "{args:?}: {first}");
    }
}
