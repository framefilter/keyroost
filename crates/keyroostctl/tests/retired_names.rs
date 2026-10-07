//! Every retired command, flag and positional exits 2 with an error naming
//! its replacement, and never repeats what was typed after it.

use std::process::{Command, Stdio};

fn run(args: &[&str]) -> (i32, String, String) {
    let dir = std::env::temp_dir().join(format!("kr-retired-{}", std::process::id()));
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

/// (argv, text the error must contain). Every case carries S3CRETVALUE
/// after the retired name where the command line allows it.
const CASES: &[(&[&str], &str)] = &[
    (
        &["key-name", "remove", "S3CRETVALUE"],
        "keyroostctl key-name delete",
    ),
    (&["--list-readers", "S3CRETVALUE"], "keyroostctl list"),
    (&["piv", "--list-readers"], "keyroostctl list"),
    (
        &["fido", "pin-set", "--new-pin-env", "S3CRETVALUE"],
        "keyroostctl fido pin set",
    ),
    (
        &["fido", "pin-change", "S3CRETVALUE"],
        "keyroostctl fido pin change",
    ),
    (
        &["fido", "pin-retries", "S3CRETVALUE"],
        "keyroostctl fido pin retries",
    ),
    (
        &["fido", "creds-list", "--pin-env", "S3CRETVALUE"],
        "keyroostctl fido credentials list",
    ),
    (
        &["fido", "creds-delete", "S3CRETVALUE"],
        "keyroostctl fido credentials delete",
    ),
    (
        &["fido", "creds-metadata", "S3CRETVALUE"],
        "keyroostctl fido credentials metadata",
    ),
    (
        &["fido", "fingerprint-list", "S3CRETVALUE"],
        "keyroostctl fido fingerprints list",
    ),
    (
        &["fido", "fingerprint-enroll", "S3CRETVALUE"],
        "keyroostctl fido fingerprints add",
    ),
    (
        &["fido", "fingerprint-rename", "S3CRETVALUE"],
        "keyroostctl fido fingerprints rename",
    ),
    (
        &["fido", "fingerprint-delete", "S3CRETVALUE"],
        "keyroostctl fido fingerprints delete",
    ),
    (
        &["fido", "set-min-pin", "S3CRETVALUE"],
        "keyroostctl fido config set-min-pin-length",
    ),
    (
        &["fido", "force-pin-change", "S3CRETVALUE"],
        "keyroostctl fido config force-pin-change",
    ),
    (
        &["fido", "enterprise-attestation", "S3CRETVALUE"],
        "keyroostctl fido config enable-enterprise-attestation",
    ),
    (&["piv", "status", "S3CRETVALUE"], "keyroostctl piv info"),
    (
        &["openpgp", "status", "S3CRETVALUE"],
        "keyroostctl openpgp info",
    ),
    (&["otp", "config", "S3CRETVALUE"], "keyroostctl otp info"),
    (&["otp", "get", "S3CRETVALUE"], "keyroostctl otp code"),
    (
        &["otp", "button-hotp", "--seed-env", "S3CRETVALUE"],
        "keyroostctl otp set-button-hotp",
    ),
    (
        &["otp", "erase-all", "S3CRETVALUE"],
        "keyroostctl otp reset",
    ),
    (
        &["otp", "remove-pin", "S3CRETVALUE"],
        "keyroostctl otp clear-pin",
    ),
    (
        &["otp", "fp-status", "S3CRETVALUE"],
        "keyroostctl otp fingerprint-status",
    ),
    (
        &["otp", "fp-enable", "S3CRETVALUE"],
        "keyroostctl otp fingerprint-enable",
    ),
    (
        &["otp", "fp-disable", "S3CRETVALUE"],
        "keyroostctl otp fingerprint-disable",
    ),
    (
        &["otp", "fp-list", "S3CRETVALUE"],
        "keyroostctl otp list --unlock fingerprint",
    ),
    (
        &["otp", "unlock-list", "--pin-only", "S3CRETVALUE"],
        "keyroostctl otp list --unlock auto",
    ),
    (
        &["otp", "unlock-list", "--pin-only", "S3CRETVALUE"],
        "--unlock pin",
    ),
    (
        &["otp", "set-pin", "--pin-env", "S3CRETVALUE"],
        "--new-pin-env",
    ),
    (&["otp", "set-pin", "--pin-stdin"], "--new-pin-stdin"),
    (
        &["otp", "list", "--pin-only", "S3CRETVALUE"],
        "--unlock pin",
    ),
    (
        &["--device", "pin-set", "fido", "pin-set"],
        "keyroostctl fido pin set",
    ),
    (
        &["molto", "seed", "-p", "99", "--hex-env", "S3CRETVALUE"],
        "--slot",
    ),
    (
        &["molto", "title", "--profile", "99", "S3CRETVALUE"],
        "--slot",
    ),
    (
        &["molto", "config", "--slot", "99", "--time-step", "60"],
        "--period",
    ),
    (&["prog", "config", "--time-step", "60"], "--period"),
    (&["molto", "sync-time", "-p", "99", "S3CRETVALUE"], "--slot"),
    (&["molto", "delete", "-p", "99", "S3CRETVALUE"], "--slot"),
    (&["molto", "import", "-p", "99", "S3CRETVALUE"], "--slot"),
    (
        &[
            "piv",
            "import-cert",
            "--slot",
            "9a",
            "--file",
            "S3CRETVALUE",
        ],
        "--in",
    ),
    (
        &[
            "piv",
            "export-cert",
            "--slot",
            "9a",
            "--file",
            "S3CRETVALUE",
        ],
        "--out",
    ),
    (
        &[
            "piv",
            "request-cert",
            "--slot",
            "9a",
            "--subject",
            "CN=x",
            "--file",
            "S3CRETVALUE",
        ],
        "--out",
    ),
    (
        &[
            "piv",
            "self-sign",
            "--slot",
            "9a",
            "--subject",
            "CN=x",
            "--file",
            "S3CRETVALUE",
        ],
        "--out",
    ),
    (
        &["fido", "large-blob", "export", "0", "S3CRETVALUE"],
        "--out FILE",
    ),
];

#[test]
fn retired_names_exit_2_and_name_the_replacement() {
    for (args, want) in CASES {
        let (code, out, err) = run(args);
        assert_eq!(code, 2, "{args:?}: {err}");
        assert!(out.is_empty(), "{args:?}: {out}");
        assert!(err.contains(want), "{args:?}: {err}");
        assert!(!err.contains("S3CRETVALUE"), "{args:?} echoed: {err}");
    }
}

/// Every `RETIRED_COMMANDS` row in main.rs has a case above.
#[test]
fn every_retired_command_row_has_a_case() {
    let src = include_str!("../src/main.rs");
    let block = src
        .split("const RETIRED_COMMANDS")
        .nth(1)
        .unwrap()
        .split("];")
        .next()
        .unwrap();
    for row in block.split("RetiredCommand {").skip(1) {
        let field = |name: &str| {
            row.split(&format!("{name}: \""))
                .nth(1)
                .unwrap()
                .split('"')
                .next()
                .unwrap()
        };
        let words: Vec<&str> = field("parent")
            .split(' ')
            .filter(|w| !w.is_empty())
            .chain([field("old")])
            .collect();
        assert!(
            CASES
                .iter()
                .any(|(a, _)| a.windows(words.len()).any(|w| w == words.as_slice())),
            "no case for `{}`",
            words.join(" ")
        );
    }
}
