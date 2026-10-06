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

const TABLE: &str = include_str!("secret_flags.txt");

/// A well-formed value for a secret supplied by env so a later one is
/// reached. It never reaches a key: one secret is always missing, and every
/// secret is checked before any device is opened.
fn dummy(prefix: &str) -> &'static str {
    match prefix {
        "hex" | "mgmt-key" | "old-mgmt-key" | "new-mgmt-key" => "00",
        "base32" | "seed" => "AAAA",
        _ => "0000",
    }
}

/// A fresh working directory holding the files the table's rows name, so a
/// command that reads its input file first gets past it to the secrets.
fn fixture_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("keyroost-secret-sources-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for (name, body) in [
        ("message.txt", &b"keyroost test message\n"[..]),
        (
            "cert.der",
            include_bytes!("../../keyroost-piv/tests/fixtures/rsa_piv.der"),
        ),
    ] {
        std::fs::write(dir.join(name), body).unwrap();
    }
    dir
}

/// Every required secret, missing with no terminal, is refused before any
/// device I/O, and every flag the refusal names exists in that command's
/// --help. Earlier required secrets are supplied by env so each later one
/// is reached.
#[test]
fn every_required_secret_refuses_without_a_source_and_names_real_flags() {
    let dir = fixture_dir();
    for line in TABLE
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
    {
        let cols: Vec<&str> = line.split('\t').filter(|c| !c.is_empty()).collect();
        let path: Vec<&str> = cols[0].split(' ').collect();
        let extra: Vec<&str> = if cols.len() == 4 {
            cols[1].split(' ').collect()
        } else {
            vec![]
        };
        let required = cols[cols.len() - 1];
        if required == "-" {
            continue;
        }
        let required: Vec<&str> = required.split(' ').collect();
        let help = {
            let mut a = path.clone();
            a.push("--help");
            let out = Command::new(env!("CARGO_BIN_EXE_keyroostctl"))
                .args(&a)
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).into_owned()
                + &String::from_utf8_lossy(&out.stderr)
        };
        for i in 0..required.len() {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_keyroostctl"));
            cmd.args(&path)
                .args(&extra)
                .current_dir(&dir)
                .stdin(Stdio::null())
                .env("PCSCLITE_CSOCK_NAME", "/nonexistent/keyroost-test-no-pcsc");
            for (j, prev) in required[..i].iter().enumerate() {
                let p = prev.split('|').next().unwrap();
                let var = format!("KR_TEST_SECRET_{j}");
                cmd.arg(format!("--{p}-env")).arg(&var).env(&var, dummy(p));
            }
            let out = cmd.output().unwrap();
            let err = String::from_utf8_lossy(&out.stderr);
            assert!(!out.status.success(), "{line} #{i}: {err}");
            assert!(
                err.contains(" given: pass "),
                "{line} #{i}: expected a no-source refusal, got: {err}"
            );
            // The `→ key` announce line comes from device selection: its
            // absence shows the refusal came before any key was looked at.
            assert!(
                !err.contains('\u{2192}'),
                "{line} #{i}: a key was selected before the refusal: {err}"
            );
            for p in required[i].split('|') {
                assert!(
                    err.contains(&format!("--{p}-env VAR")),
                    "{line} #{i}: {err}"
                );
            }
            for flag in err
                .split(|c: char| c.is_whitespace() || c == ',')
                .filter(|w| w.starts_with("--"))
            {
                assert!(
                    help.contains(flag),
                    "{line}: refusal names {flag}, which `--help` doesn't list"
                );
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// `openpgp import-key --in` loads and checks the key file before any key
/// is looked at, so a wrong path or a file that isn't an RSA-2048 key fails
/// before the question and the admin PIN.
#[test]
fn import_key_checks_the_key_file_before_selecting_a_key() {
    let dir = std::env::temp_dir().join(format!("keyroost-import-key-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let junk = dir.join("not-a-key.bin");
    std::fs::write(&junk, b"this is not a key\n").unwrap();
    let missing = dir.join("missing.bin");
    for (path, want) in [
        (&missing, "cannot read key file"),
        (&junk, "could not parse RSA private key"),
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_keyroostctl"))
            .args(["openpgp", "import-key", "--yes", "--admin-pin-env"])
            .arg("KR_TEST_ADMIN_PIN")
            .arg("--in")
            .arg(path)
            .env("KR_TEST_ADMIN_PIN", "12345678")
            .stdin(Stdio::null())
            .env("PCSCLITE_CSOCK_NAME", "/nonexistent/keyroost-test-no-pcsc")
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{path:?}: {err}");
        assert!(err.contains(want), "{path:?}: {err}");
        assert!(
            !err.contains('\u{2192}'),
            "{path:?}: a key was selected before the file was checked: {err}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
