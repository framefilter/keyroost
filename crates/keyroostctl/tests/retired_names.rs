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
    (&["--list-readers", "S3CRETVALUE"], "keyroostctl list"),
    (&["piv", "--list-readers"], "keyroostctl list"),
    (
        &["openpgp", "status", "S3CRETVALUE"],
        "keyroostctl openpgp info",
    ),
    (
        &["openpgp", "verify", "--which", "S3CRETVALUE"],
        "keyroostctl openpgp pin verify",
    ),
    (
        &["openpgp", "verify", "S3CRETVALUE"],
        "the admin PIN is `--admin`",
    ),
    (
        &["openpgp", "change-pin", "--old-pin-env", "S3CRETVALUE"],
        "keyroostctl openpgp pin change",
    ),
    (
        &[
            "openpgp",
            "change-admin-pin",
            "--old-pin-env",
            "S3CRETVALUE",
        ],
        "keyroostctl openpgp pin change --admin",
    ),
    (
        &["openpgp", "unblock-pin", "S3CRETVALUE"],
        "keyroostctl openpgp pin unblock",
    ),
    (
        &["openpgp", "generate-key", "S3CRETVALUE"],
        "keyroostctl openpgp key generate",
    ),
    (
        &["openpgp", "import-key", "--in", "S3CRETVALUE"],
        "keyroostctl openpgp key import",
    ),
    (
        &["openpgp", "public-key", "S3CRETVALUE"],
        "keyroostctl openpgp key show",
    ),
    (
        &["openpgp", "algorithms", "S3CRETVALUE"],
        "keyroostctl openpgp key algorithms",
    ),
    (
        &["openpgp", "set-name", "S3CRETVALUE"],
        "keyroostctl openpgp name set",
    ),
    (
        &["openpgp", "set-url", "S3CRETVALUE"],
        "keyroostctl openpgp url set",
    ),
    (
        &["openpgp", "pin", "verify", "--which", "S3CRETVALUE"],
        "--admin",
    ),
    (&["otp", "config", "S3CRETVALUE"], "keyroostctl otp info"),
    (&["otp", "get", "S3CRETVALUE"], "keyroostctl otp code"),
    (
        &["otp", "erase-all", "S3CRETVALUE"],
        "keyroostctl otp reset",
    ),
    (
        &["otp", "button-hotp", "--seed-env", "S3CRETVALUE"],
        "keyroostctl otp button set",
    ),
    (
        &["otp", "set-button-hotp", "--seed-env", "S3CRETVALUE"],
        "keyroostctl otp button set",
    ),
    (
        &["otp", "delete-button-hotp", "S3CRETVALUE"],
        "keyroostctl otp button delete",
    ),
    (
        &["otp", "pin-status", "S3CRETVALUE"],
        "keyroostctl otp pin status",
    ),
    (
        &["otp", "set-pin", "--pin-env", "S3CRETVALUE"],
        "keyroostctl otp pin set",
    ),
    (
        &["otp", "verify", "--pin-env", "S3CRETVALUE"],
        "keyroostctl otp pin verify",
    ),
    (
        &["otp", "change-pin", "--current-env", "S3CRETVALUE"],
        "keyroostctl otp pin change",
    ),
    (
        &["otp", "remove-pin", "S3CRETVALUE"],
        "keyroostctl otp pin clear",
    ),
    (
        &["otp", "clear-pin", "S3CRETVALUE"],
        "keyroostctl otp pin clear",
    ),
    (
        &["otp", "fp-status", "S3CRETVALUE"],
        "keyroostctl otp fingerprint status",
    ),
    (
        &["otp", "fp-enable", "S3CRETVALUE"],
        "keyroostctl otp fingerprint enable",
    ),
    (
        &["otp", "fp-disable", "S3CRETVALUE"],
        "keyroostctl otp fingerprint disable",
    ),
    (
        &["otp", "fingerprint-status", "S3CRETVALUE"],
        "keyroostctl otp fingerprint status",
    ),
    (
        &["otp", "fingerprint-enable", "S3CRETVALUE"],
        "keyroostctl otp fingerprint enable",
    ),
    (
        &["otp", "fingerprint-disable", "S3CRETVALUE"],
        "keyroostctl otp fingerprint disable",
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
        &["otp", "pin", "set", "--pin-env", "S3CRETVALUE"],
        "--new-pin env:VAR",
    ),
    (&["otp", "pin", "set", "--pin-stdin"], "--new-pin stdin"),
    (
        &["otp", "pin", "change", "--pin-stdin"],
        "--pin stdin --new-pin stdin",
    ),
    (
        &["otp", "pin", "change", "--current-env", "S3CRETVALUE"],
        "--pin env:VAR",
    ),
    (
        &["otp", "pin", "change", "--new-env", "S3CRETVALUE"],
        "--new-pin env:VAR",
    ),
    (
        &["otp", "list", "--pin-only", "S3CRETVALUE"],
        "--unlock pin",
    ),
    (
        &["oath", "set-password", "--new-password-env", "S3CRETVALUE"],
        "keyroostctl oath password set",
    ),
    (
        &["oath", "clear-password", "S3CRETVALUE"],
        "keyroostctl oath password clear",
    ),
    (
        &["molto", "sync-time", "-p", "99", "S3CRETVALUE"],
        "keyroostctl molto sync",
    ),
    (
        &["molto", "import-file", "S3CRETVALUE"],
        "keyroostctl molto import --file",
    ),
    (
        &["molto", "import-file", "S3CRETVALUE"],
        "`--start` is `--slot`",
    ),
    (
        &[
            "molto",
            "import",
            "--file",
            "v.json",
            "--start",
            "S3CRETVALUE",
        ],
        "--slot",
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
    (&["molto", "sync", "-p", "99", "S3CRETVALUE"], "--slot"),
    (&["molto", "delete", "-p", "99", "S3CRETVALUE"], "--slot"),
    (&["molto", "import", "-p", "99", "S3CRETVALUE"], "--slot"),
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
        "keyroostctl fido credential list",
    ),
    (
        &["fido", "creds-delete", "S3CRETVALUE"],
        "keyroostctl fido credential delete",
    ),
    (
        &["fido", "creds-metadata", "S3CRETVALUE"],
        "keyroostctl fido credential metadata",
    ),
    (
        &["fido", "fingerprint-list", "S3CRETVALUE"],
        "keyroostctl fido fingerprint list",
    ),
    (
        &["fido", "fingerprint-enroll", "S3CRETVALUE"],
        "keyroostctl fido fingerprint add",
    ),
    (
        &["fido", "fingerprint-rename", "S3CRETVALUE"],
        "keyroostctl fido fingerprint rename",
    ),
    (
        &["fido", "fingerprint-delete", "S3CRETVALUE"],
        "keyroostctl fido fingerprint delete",
    ),
    (
        &["fido", "always-uv", "--pin-env", "S3CRETVALUE"],
        "keyroostctl fido config always-uv enable",
    ),
    (
        &["fido", "always-uv", "S3CRETVALUE"],
        "fido config always-uv disable",
    ),
    (
        &["fido", "set-min-pin", "S3CRETVALUE"],
        "keyroostctl fido pin min-length",
    ),
    (
        &["fido", "force-pin-change", "S3CRETVALUE"],
        "keyroostctl fido pin force-change",
    ),
    (
        &["fido", "enterprise-attestation", "S3CRETVALUE"],
        "keyroostctl fido config attestation enable",
    ),
    (
        &["fido", "large-blob", "export", "0", "S3CRETVALUE"],
        "keyroostctl fido blob",
    ),
    (
        &["fido", "ssh-cert", "extract", "S3CRETVALUE"],
        "keyroostctl fido ssh",
    ),
    (
        &["fido", "credentials", "list", "S3CRETVALUE"],
        "keyroostctl fido credential",
    ),
    (
        &["fido", "fingerprints", "list", "S3CRETVALUE"],
        "keyroostctl fido fingerprint",
    ),
    (
        &["fido", "config", "enable-always-uv", "S3CRETVALUE"],
        "keyroostctl fido config always-uv enable",
    ),
    (
        &["fido", "config", "disable-always-uv", "S3CRETVALUE"],
        "keyroostctl fido config always-uv disable",
    ),
    (
        &["fido", "config", "set-min-pin-length", "S3CRETVALUE"],
        "keyroostctl fido pin min-length",
    ),
    (
        &["fido", "config", "force-pin-change", "S3CRETVALUE"],
        "keyroostctl fido pin force-change",
    ),
    (
        &[
            "fido",
            "config",
            "enable-enterprise-attestation",
            "S3CRETVALUE",
        ],
        "keyroostctl fido config attestation enable",
    ),
    (&["key-name", "remove", "S3CRETVALUE"], "keyroostctl name"),
    (
        &["key-name", "list", "S3CRETVALUE"],
        "`key-name remove` is now `name delete`",
    ),
    (
        &["--device", "pin-set", "fido", "pin-set"],
        "keyroostctl fido pin set",
    ),
    (
        &["fido", "credential", "delete", "--cred-id", "S3CRETVALUE"],
        "--id",
    ),
    (
        &["fido", "credentials", "delete", "--cred-id", "S3CRETVALUE"],
        "keyroostctl fido credential",
    ),
    (
        &[
            "fido",
            "fingerprint",
            "rename",
            "--template-id",
            "S3CRETVALUE",
        ],
        "--id",
    ),
    (
        &[
            "fido",
            "fingerprint",
            "delete",
            "--template-id",
            "S3CRETVALUE",
        ],
        "--id",
    ),
    (
        &["fido", "ssh", "extract", "--credential", "S3CRETVALUE"],
        "--id",
    ),
    (&["fido", "ssh", "extract", "--force"], "--overwrite"),
    (
        &["fido", "blob", "export", "0", "S3CRETVALUE"],
        "--out FILE",
    ),
    (&["piv", "status", "S3CRETVALUE"], "keyroostctl piv info"),
    (
        &["piv", "change-pin", "--old-pin-env", "S3CRETVALUE"],
        "keyroostctl piv pin change",
    ),
    (
        &["piv", "unblock-pin", "S3CRETVALUE"],
        "keyroostctl piv pin unblock",
    ),
    (
        &["piv", "change-puk", "S3CRETVALUE"],
        "keyroostctl piv puk change",
    ),
    (
        &["piv", "set-retries", "S3CRETVALUE"],
        "keyroostctl piv retries set",
    ),
    (
        &[
            "piv",
            "change-management-key",
            "--new-algorithm",
            "S3CRETVALUE",
        ],
        "keyroostctl piv mgmt-key change",
    ),
    (
        &["piv", "generate-key", "--save-pubkey", "S3CRETVALUE"],
        "keyroostctl piv key generate",
    ),
    (
        &["piv", "delete-key", "S3CRETVALUE"],
        "keyroostctl piv key delete",
    ),
    (
        &["piv", "move-key", "S3CRETVALUE"],
        "keyroostctl piv key move",
    ),
    (
        &["piv", "import-cert", "--file", "S3CRETVALUE"],
        "keyroostctl piv cert import",
    ),
    (
        &["piv", "export-cert", "--file", "S3CRETVALUE"],
        "keyroostctl piv cert export",
    ),
    (
        &["piv", "delete-cert", "S3CRETVALUE"],
        "keyroostctl piv cert delete",
    ),
    (
        &["piv", "request-cert", "--load-pubkey", "S3CRETVALUE"],
        "keyroostctl piv cert request",
    ),
    (
        &["piv", "self-sign", "S3CRETVALUE"],
        "keyroostctl piv cert generate",
    ),
    (
        &["piv", "new-chuid", "S3CRETVALUE"],
        "keyroostctl piv chuid generate",
    ),
    (
        &[
            "piv",
            "key",
            "generate",
            "--slot",
            "9a",
            "--save-pubkey",
            "S3CRETVALUE",
        ],
        "--out",
    ),
    (
        &[
            "piv",
            "cert",
            "request",
            "--slot",
            "9a",
            "--subject",
            "CN=x",
            "--save-pubkey",
            "S3CRETVALUE",
        ],
        "--pubkey-out",
    ),
    (
        &[
            "piv",
            "cert",
            "generate",
            "--slot",
            "9a",
            "--subject",
            "CN=x",
            "--save-pubkey",
            "S3CRETVALUE",
        ],
        "--pubkey-out",
    ),
    (
        &[
            "piv",
            "cert",
            "generate",
            "--slot",
            "9a",
            "--subject",
            "CN=x",
            "--load-pubkey",
            "S3CRETVALUE",
        ],
        "--pubkey-in",
    ),
    (
        &[
            "piv",
            "cert",
            "request",
            "--slot",
            "9a",
            "--subject",
            "CN=x",
            "--load-pubkey",
            "S3CRETVALUE",
        ],
        "--pubkey-in",
    ),
    (
        &[
            "piv",
            "mgmt-key",
            "change",
            "--new-algorithm",
            "S3CRETVALUE",
        ],
        "--algorithm",
    ),
    (
        &[
            "piv",
            "cert",
            "import",
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
            "cert",
            "export",
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
            "cert",
            "request",
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
            "cert",
            "generate",
            "--slot",
            "9a",
            "--subject",
            "CN=x",
            "--file",
            "S3CRETVALUE",
        ],
        "--out",
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
