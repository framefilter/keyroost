//! Output-contract tests: stream, exit-code and shape rules for the CLI.
//! Each runs the real binary with no PC/SC service reachable.
mod common;
use common::ConfigIn;

use std::process::Stdio;
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
    let out = common::keyroostctl()
        .args(args)
        .config_in(&dir)
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
    let (code, _, _) = run(&["molto", "config", "set", "--slot", "1", "--digits", "9"]);
    assert_eq!(code, 2);
}

#[test]
fn value_parser_errors_name_the_value_once() {
    // clap already prints "invalid value '<v>' for ..."; the parser's own
    // reason must not repeat it.
    for (args, v) in [
        (
            &["molto", "config", "set", "--slot", "abc", "--digits", "6"][..],
            "abc",
        ),
        (
            &["molto", "config", "set", "--slot", "120", "--digits", "6"],
            "120",
        ),
        (&["otp", "button", "set", "--digits", "7"], "7"),
        (&["piv", "cert", "generate", "--days", "zz"], "zz"),
        (&["piv", "cert", "generate", "--years", "zz"], "zz"),
        (&["piv", "cert", "generate", "--months", "zz"], "zz"),
        (
            &["piv", "cert", "generate", "--days", "99999999"],
            "99999999",
        ),
        (&["piv", "cert", "generate", "--years", "99999"], "99999"),
        (
            &["piv", "cert", "generate", "--months", "9999999"],
            "9999999",
        ),
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
        &["piv", "cert", "export", "--slot", "9a", "--out", f][..],
        &["openpgp", "authenticate", "--in", f, "--out", f],
        &[
            "piv",
            "cert",
            "request",
            "--slot",
            "9a",
            "--subject",
            "CN=x",
            "--out",
            fresh,
            "--generate-key",
            "--pubkey-out",
            f,
            "--mgmt-key",
            "default",
            "--yes",
        ],
        &[
            "piv",
            "cert",
            "generate",
            "--slot",
            "9a",
            "--subject",
            "CN=x",
            "--out",
            fresh,
            "--generate-key",
            "--pubkey-out",
            f,
            "--mgmt-key",
            "default",
            "--yes",
        ],
        &[
            "piv",
            "key",
            "generate",
            "--slot",
            "9a",
            "--out",
            f,
            "--mgmt-key",
            "default",
            "--yes",
        ],
        &[
            "piv",
            "cert",
            "generate",
            "--slot",
            "9a",
            "--subject",
            "CN=x",
            "--generate-key",
            "--pubkey-out",
            f,
            "--mgmt-key",
            "default",
            "--yes",
        ],
        &[
            "piv",
            "cert",
            "request",
            "--slot",
            "9a",
            "--subject",
            "CN=x",
            "--out",
            f,
        ],
        &["openpgp", "sign", "--in", f, "--out", f],
        &["openpgp", "decrypt", "--in", f, "--out", f],
        &["fido", "blob", "export", "0", "--out", f],
        &["fido", "ssh", "export", "--out", f],
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
            "cert",
            "export",
            "--slot",
            "9a",
            "--out",
            d,
            "--overwrite",
        ][..],
        &[
            "piv",
            "cert",
            "generate",
            "--slot",
            "9a",
            "--subject",
            "CN=x",
            "--generate-key",
            "--pubkey-out",
            d,
            "--mgmt-key",
            "default",
            "--yes",
            "--overwrite",
        ],
        &["openpgp", "sign", "--in", i, "--out", d, "--overwrite"],
        &["fido", "blob", "export", "0", "--out", d, "--overwrite"],
        &["fido", "ssh", "export", "--out", d, "--overwrite"],
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

/// The Solo 2 name cap needs the key's vendor, so it runs after the key is
/// chosen and before any secret is read: with no key connected, a too-long
/// name still fails on the missing key, not on the cap.
#[test]
fn oath_add_long_name_without_a_key_fails_on_the_key() {
    let long = "n".repeat(128);
    let (code, out, err) = run(&["oath", "add", &long, "--seed", "stdin"]);
    assert_ne!(code, 0, "{err}");
    assert!(out.is_empty(), "{out}");
    assert!(err.contains("no key with OATH is connected"), "{err}");
    assert!(!err.contains("Solo 2 stores names"), "{err}");
}

/// A fresh directory under the temp dir for one test's input files.
fn input_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("kr-import-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

const PLAIN_AEGIS: &str = r#"{"version":1,"header":{"slots":null,"params":null},"db":{"version":2,"entries":[{"type":"totp","name":"alice","issuer":"Example","info":{"secret":"JBSWY3DPEHPK3PXP","algo":"SHA1","digits":6,"period":30}}]}}"#;

/// The file is read and sorted before any key is looked at: a certificate
/// gets the pointer to where certificates go, a missing file its read
/// error, and an export with no key connected the usual refusal.
#[test]
fn oath_import_reads_the_file_before_any_key() {
    let dir = input_dir("oath");
    let cert = dir.join("certificate.txt");
    std::fs::write(
        &cert,
        "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    let (code, out, err) = run(&["oath", "import", "--in", cert.to_str().unwrap(), "--yes"]);
    assert_eq!(code, 1, "{err}");
    assert!(out.is_empty(), "{out}");
    assert!(err.contains("This looks like a certificate"), "{err}");
    assert!(err.contains("piv cert import"), "{err}");
    assert!(!err.contains('\u{2192}'), "a key was selected first: {err}");

    let missing = dir.join("missing.json");
    let (code, _, err) = run(&["oath", "import", "--in", missing.to_str().unwrap()]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("read "), "{err}");
    assert!(!err.contains('\u{2192}'), "{err}");

    let plain = dir.join("plain.json");
    std::fs::write(&plain, PLAIN_AEGIS).unwrap();
    for cmd in [
        &["oath", "import"][..],
        &["otp", "--transport", "ccid", "import"],
    ] {
        let mut args = cmd.to_vec();
        args.extend(["--in", plain.to_str().unwrap(), "--dry-run"]);
        let (code, out, err) = run(&args);
        assert_eq!(code, 1, "{args:?}: {err}");
        assert!(out.is_empty(), "{out}");
        assert!(err.contains("is connected"), "{args:?}: {err}");
        assert!(!err.contains("JBSWY3DPEHPK3PXP"), "{err}");
    }
    let (_, _, err) = run(&["oath", "import", "--in", plain.to_str().unwrap()]);
    assert!(err.contains("no key with OATH is connected"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn import_help_names_the_shared_flags() {
    for cmd in [&["oath", "import"][..], &["otp", "import"]] {
        let mut args = cmd.to_vec();
        args.push("--help");
        let (code, out, err) = run(&args);
        assert_eq!(code, 0, "{err}");
        for flag in ["--in", "--file-password", "--dry-run", "--yes"] {
            assert!(out.contains(flag), "{cmd:?} {flag}: {out}");
        }
        assert!(out.contains("--replace"), "{cmd:?}: {out}");
        assert!(!out.contains("--overwrite"), "{cmd:?}: {out}");
        assert!(out.contains("skipped unless --replace"), "{cmd:?}: {out}");
        assert!(out.contains("nothing is written"), "{cmd:?}: {out}");
    }
}

/// `molto import` names the export's password the way the other imports
/// do; the old `--password` is gone.
#[test]
fn molto_import_help_names_file_password() {
    let (code, out, err) = run(&["molto", "import", "--help"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("--file-password"), "{out}");
    assert!(!out.contains("--password "), "{out}");
    assert!(!out.contains("--password env"), "{out}");
}

/// `molto import --in` reads the file with the reader `oath import` and
/// `otp import` use (it used to keep its own): recognized key material gets
/// the pointer to where it belongs, anything else the shared "can't import
/// this file" line (formerly "neither a text export nor a PNG/JPEG image").
#[test]
fn molto_import_points_binary_key_material_elsewhere() {
    let dir = input_dir("molto");
    let der = dir.join("cert.der");
    std::fs::write(
        &der,
        include_bytes!("../../keyroost-piv/tests/fixtures/rsa_piv.der"),
    )
    .unwrap();
    let (code, _, err) = run(&[
        "molto",
        "import",
        "--in",
        der.to_str().unwrap(),
        "--dry-run",
    ]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("This looks like a certificate"), "{err}");
    let junk = dir.join("junk.bin");
    std::fs::write(&junk, [0xff, 0xfe, 0x00, 0x01]).unwrap();
    let (code, _, err) = run(&[
        "molto",
        "import",
        "--in",
        junk.to_str().unwrap(),
        "--dry-run",
    ]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("keyroost can't import this file"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}
