//! Output-contract tests: stream, exit-code and shape rules for the CLI.
//! Each runs the real binary with no PC/SC service reachable.

use std::process::{Command, Stdio};

/// Run keyroostctl with no PC/SC service, an empty config dir and stdin
/// not a terminal. Returns (exit code, stdout, stderr).
pub fn run(args: &[&str]) -> (i32, String, String) {
    let dir = std::env::temp_dir().join(format!(
        "kr-out-{}-{}",
        std::process::id(),
        args.join("_").len()
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
