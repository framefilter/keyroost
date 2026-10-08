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

/// `--unlock fingerprint` takes no PIN: giving one is a usage mistake,
/// refused with exit 2 before any key is looked at.
#[test]
fn otp_list_fingerprint_unlock_with_a_pin_flag_is_2() {
    for args in [
        &["otp", "list", "--unlock", "fingerprint", "--pin", "env:V"][..],
        &["otp", "list", "--unlock", "fingerprint", "--pin", "stdin"],
    ] {
        let (code, out, err) = run(args);
        assert_eq!(code, 2, "{args:?}: {err}");
        assert!(out.is_empty(), "{args:?}: {out}");
        assert!(err.contains("--unlock auto"), "{args:?}: {err}");
        assert!(!err.contains('\u{2192}'), "{args:?}: {err}");
    }
}

#[test]
fn oath_add_digits_9_is_2_like_molto_config() {
    let (code, out, err) = run(&["oath", "add", "x", "--digits", "9"]);
    assert_eq!(code, 2, "{err}");
    assert!(out.is_empty());
    let (code, _, _) = run(&["molto", "config", "--slot", "1", "--digits", "9"]);
    assert_eq!(code, 2);
}

#[test]
fn value_parser_errors_name_the_value_once() {
    // clap already prints "invalid value '<v>' for ..."; the parser's own
    // reason must not repeat it.
    for (args, v) in [
        (
            &["molto", "config", "--slot", "abc", "--digits", "6"][..],
            "abc",
        ),
        (
            &["molto", "config", "--slot", "120", "--digits", "6"],
            "120",
        ),
        (&["otp", "set-button-hotp", "--digits", "7"], "7"),
        (&["piv", "self-sign", "--days", "zz"], "zz"),
        (&["piv", "self-sign", "--years", "zz"], "zz"),
        (&["piv", "self-sign", "--months", "zz"], "zz"),
        (&["piv", "self-sign", "--days", "99999999"], "99999999"),
        (&["piv", "self-sign", "--years", "99999"], "99999"),
        (&["piv", "self-sign", "--months", "9999999"], "9999999"),
    ] {
        let (code, _, err) = run(args);
        assert_eq!(code, 2, "{args:?}: {err}");
        let first = err.lines().next().unwrap_or("");
        assert_eq!(first.matches(v).count(), 1, "{args:?}: {first}");
    }
}

#[test]
fn list_json_is_one_object_with_keys() {
    for args in [&["--json", "list"][..], &["--json"]] {
        let (code, out, err) = run(args);
        assert_eq!(code, 0, "{args:?}: {err}");
        let v: serde_json::Value = serde_json::from_str(&out)
            .unwrap_or_else(|e| panic!("{args:?}: stdout is not one JSON document ({e}): {out:?}"));
        assert!(v["keys"].is_array(), "{out}");
    }
}

#[test]
fn an_existing_output_file_is_refused_before_any_key() {
    let dir = std::env::temp_dir().join(format!("kr-out-exists-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("exists.out");
    std::fs::write(&f, b"keep me").unwrap();
    let f = f.to_str().unwrap();
    let fresh = dir.join("fresh.out");
    let fresh = fresh.to_str().unwrap();
    for args in [
        &["piv", "export-cert", "--slot", "9a", "--out", f][..],
        &["openpgp", "authenticate", "--in", f, "--out", f],
        &[
            "piv",
            "request-cert",
            "--slot",
            "9a",
            "--subject",
            "CN=x",
            "--out",
            fresh,
            "--generate-key",
            "--save-pubkey",
            f,
            "--mgmt-key",
            "default",
            "--yes",
        ],
        &[
            "piv",
            "self-sign",
            "--slot",
            "9a",
            "--subject",
            "CN=x",
            "--out",
            fresh,
            "--generate-key",
            "--save-pubkey",
            f,
            "--mgmt-key",
            "default",
            "--yes",
        ],
        &[
            "piv",
            "generate-key",
            "--slot",
            "9a",
            "--save-pubkey",
            f,
            "--mgmt-key",
            "default",
            "--yes",
        ],
        &[
            "piv",
            "self-sign",
            "--slot",
            "9a",
            "--subject",
            "CN=x",
            "--generate-key",
            "--save-pubkey",
            f,
            "--mgmt-key",
            "default",
            "--yes",
        ],
        &[
            "piv",
            "request-cert",
            "--slot",
            "9a",
            "--subject",
            "CN=x",
            "--out",
            f,
        ],
        &["openpgp", "sign", "--in", f, "--out", f],
        &["openpgp", "decrypt", "--in", f, "--out", f],
        &["fido", "large-blob", "export", "0", "--out", f],
        &["fido", "ssh-cert", "extract", "--out", f],
    ] {
        let (code, _out, err) = run(args);
        assert_eq!(code, 1, "{args:?}: {err}");
        assert!(err.contains("--overwrite"), "{args:?}: {err}");
        assert!(
            !err.contains('\u{2192}'),
            "{args:?}: a key was selected first: {err}"
        );
    }
    assert_eq!(std::fs::read(dir.join("exists.out")).unwrap(), b"keep me");
    assert!(!dir.join("fresh.out").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A directory can't be written as an output file: refused before any key
/// is selected, and --overwrite doesn't change that. Secret outputs also
/// refuse a symbolic link up front, before the PIN or the card is used.
#[test]
fn an_output_that_cannot_be_replaced_is_refused_before_any_key() {
    let dir = std::env::temp_dir().join(format!("kr-out-dir-{}", std::process::id()));
    let sub = dir.join("a-dir");
    std::fs::create_dir_all(&sub).unwrap();
    let d = sub.to_str().unwrap();
    let input = dir.join("in.bin");
    std::fs::write(&input, b"data").unwrap();
    let i = input.to_str().unwrap();
    for args in [
        &[
            "piv",
            "export-cert",
            "--slot",
            "9a",
            "--out",
            d,
            "--overwrite",
        ][..],
        &[
            "piv",
            "self-sign",
            "--slot",
            "9a",
            "--subject",
            "CN=x",
            "--generate-key",
            "--save-pubkey",
            d,
            "--mgmt-key",
            "default",
            "--yes",
            "--overwrite",
        ],
        &["openpgp", "sign", "--in", i, "--out", d, "--overwrite"],
        &[
            "fido",
            "large-blob",
            "export",
            "0",
            "--out",
            d,
            "--overwrite",
        ],
        &["fido", "ssh-cert", "extract", "--out", d, "--overwrite"],
    ] {
        let (code, _out, err) = run(args);
        assert_eq!(code, 1, "{args:?}: {err}");
        assert!(err.contains("is a directory"), "{args:?}: {err}");
        assert!(err.contains("a-dir"), "{args:?}: names the path: {err}");
        assert!(
            !err.contains('\u{2192}'),
            "{args:?}: a key was selected first: {err}"
        );
    }
    #[cfg(unix)]
    {
        let link = dir.join("link.bin");
        std::os::unix::fs::symlink(&input, &link).unwrap();
        let l = link.to_str().unwrap();
        for cmd in ["sign", "decrypt", "authenticate"] {
            let args = ["openpgp", cmd, "--in", i, "--out", l, "--overwrite"];
            let (code, _out, err) = run(&args);
            assert_eq!(code, 1, "{args:?}: {err}");
            assert!(err.contains("symbolic link"), "{args:?}: {err}");
            assert!(
                !err.contains('\u{2192}'),
                "{args:?}: a key was selected first: {err}"
            );
        }
        assert_eq!(std::fs::read(&input).unwrap(), b"data");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
