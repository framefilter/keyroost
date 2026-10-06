//! Removed and renamed secret flags fail with a message naming the
//! replacement, exit 2, and never repeat the value given.
use std::process::{Command, Stdio};

fn run(args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_keyroostctl"))
        .args(args)
        .stdin(Stdio::null())
        // pcsc-lite: no daemon reachable, so nothing can talk to a card.
        .env("PCSCLITE_CSOCK_NAME", "/nonexistent/keyroost-test-no-pcsc")
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn retired_secret_flags_name_their_replacement() {
    for (args, want) in [
        (
            &["molto", "--key", "S3CRETVALUE", "info"][..],
            "--key-env VAR",
        ),
        (
            &["molto", "--key-ascii", "S3CRETVALUE", "info"],
            "--key-ascii-env VAR",
        ),
        (
            &["molto", "seed", "-p", "99", "--hex", "S3CRETVALUE"],
            "--hex-env VAR or --hex-stdin",
        ),
        (
            &["molto", "seed", "-p", "99", "--base32=S3CRETVALUE"],
            "--base32-env VAR or --base32-stdin",
        ),
        (
            &["prog", "seed", "--hex", "S3CRETVALUE"],
            "--hex-env VAR or --hex-stdin",
        ),
        (
            &["molto", "customer-key", "--ascii", "S3CRETVALUE"],
            "--ascii-env VAR or --ascii-stdin",
        ),
        (&["oath", "add", "n", "--secret-env", "V"], "--seed-env"),
        (&["oath", "add", "n", "--secret-stdin"], "--seed-stdin"),
        (&["openpgp", "verify", "--pin", "admin"], "--which"),
        (
            &["otp", "change-pin", "--current-env", "V"],
            "--old-pin-env",
        ),
        (&["otp", "change-pin", "--new-env", "V"], "--new-pin-env"),
        (&["otp", "change-pin", "--pin-stdin"], "--old-pin-stdin"),
    ] {
        let (code, err) = run(args);
        assert_eq!(code, 2, "{args:?}: {err}");
        assert!(err.contains(want), "{args:?}: {err}");
        assert!(
            !err.contains("S3CRETVALUE"),
            "{args:?} echoed the value: {err}"
        );
    }
    let (code, err) = run(&[
        "molto",
        "import",
        "-p",
        "99",
        "otpauth://totp/x?secret=S3CRETVALUE",
        "--yes",
    ]);
    assert_ne!(code, 0);
    assert!(
        err.contains("--uri-env VAR") && !err.contains("S3CRETVALUE"),
        "{err}"
    );
}
