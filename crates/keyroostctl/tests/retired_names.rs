//! Every retired command, flag and positional exits 2 with an error naming
//! its replacement, and never repeats what was typed after it.
mod common;
use common::ConfigIn;

use std::process::Stdio;

fn run(args: &[&str]) -> (i32, String, String) {
    let dir = std::env::temp_dir().join(format!("kr-retired-{}", std::process::id()));
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
        "keyroostctl otp button clear",
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
        "keyroostctl molto import --in",
    ),
    (
        &["molto", "import-file", "S3CRETVALUE"],
        "`--start` is `--slot`",
    ),
    (
        &[
            "molto",
            "import",
            "--in",
            "v.json",
            "--start",
            "S3CRETVALUE",
        ],
        "--slot",
    ),
    (
        &[
            "molto",
            "seed",
            "set",
            "-p",
            "99",
            "--hex-env",
            "S3CRETVALUE",
        ],
        "--slot",
    ),
    (
        &["molto", "title", "set", "--profile", "99", "S3CRETVALUE"],
        "--slot",
    ),
    (
        &[
            "molto",
            "config",
            "set",
            "--slot",
            "99",
            "--time-step",
            "60",
        ],
        "--period",
    ),
    (&["prog", "config", "set", "--time-step", "60"], "--period"),
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
        "keyroostctl fido pin status",
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
        "keyroostctl fido credential status",
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
        "keyroostctl fido pin min-length set",
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
        &["fido", "ssh-cert", "extract", "S3CRETVALUE"],
        "`extract` is now `export`, and `--credential` is `--rp`",
    ),
    (
        &["fido", "large-blob", "get", "0", "S3CRETVALUE"],
        "`get` is now `show`",
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
        "keyroostctl fido pin min-length set",
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
        "`key-name remove` is now `name clear`",
    ),
    (
        &["--device", "pin-set", "fido", "pin-set"],
        "keyroostctl fido pin set",
    ),
    (
        &["fido", "credential", "delete", "--cred-id", "S3CRETVALUE"],
        "the credential ID is an argument now",
    ),
    (
        &["fido", "credential", "delete", "--id", "S3CRETVALUE"],
        "the credential ID is an argument now (`fido credential delete ID`)",
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
        "the template ID is an argument now",
    ),
    (
        &[
            "fido",
            "fingerprint",
            "delete",
            "--template-id",
            "S3CRETVALUE",
        ],
        "the template ID is an argument now",
    ),
    (
        &["fido", "fingerprint", "rename", "--id", "S3CRETVALUE"],
        "`fido fingerprint rename ID NAME`",
    ),
    (
        &["fido", "fingerprint", "add", "--name", "S3CRETVALUE"],
        "the name is an argument now (`fido fingerprint add NAME`",
    ),
    (
        &["fido", "ssh", "export", "--credential", "S3CRETVALUE"],
        "--credential is now --rp",
    ),
    (
        &["fido", "ssh", "export", "--id", "S3CRETVALUE"],
        "--id is now --rp",
    ),
    (
        &["fido", "ssh", "extract", "--id", "S3CRETVALUE"],
        "keyroostctl fido ssh export",
    ),
    (&["fido", "ssh", "export", "--force"], "--overwrite"),
    (
        &["fido", "pin", "retries", "S3CRETVALUE"],
        "keyroostctl fido pin status",
    ),
    (
        &["fido", "credential", "metadata", "S3CRETVALUE"],
        "keyroostctl fido credential status",
    ),
    (
        &["fido", "blob", "get", "0", "S3CRETVALUE"],
        "keyroostctl fido blob show",
    ),
    (
        &["otp", "button", "delete", "--yes", "S3CRETVALUE"],
        "keyroostctl otp button clear",
    ),
    (
        &["molto", "slots", "--all", "S3CRETVALUE"],
        "keyroostctl molto list",
    ),
    (
        &["molto", "seed", "--slot", "1", "--seed", "env:S3CRETVALUE"],
        "keyroostctl molto seed set",
    ),
    (
        &["molto", "title", "--slot", "1", "S3CRETVALUE"],
        "keyroostctl molto title set",
    ),
    (
        &["molto", "config", "--slot", "1", "--period", "60"],
        "keyroostctl molto config set",
    ),
    (
        &[
            "molto",
            "customer-key",
            "--new-customer-key",
            "env:S3CRETVALUE",
        ],
        "keyroostctl molto customer-key change",
    ),
    (
        &["prog", "seed", "--seed", "stdin", "S3CRETVALUE"],
        "keyroostctl prog seed set",
    ),
    (
        &["prog", "config", "--period", "60"],
        "keyroostctl prog config set",
    ),
    (
        &["fido", "pin", "min-length", "--length", "6", "S3CRETVALUE"],
        "keyroostctl fido pin min-length set",
    ),
    (
        &["molto", "import", "--slot", "1", "--file", "S3CRETVALUE"],
        "--file was renamed -i/--in",
    ),
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
    (
        &["molto", "--key", "S3CRETVALUE", "info"],
        "--customer-key env:NAME",
    ),
    (
        &["molto", "--key-ascii", "S3CRETVALUE", "info"],
        "--customer-key-encoding ascii",
    ),
    (
        &["molto", "--key-env", "S3CRETVALUE", "info"],
        "--customer-key env:VAR",
    ),
    (
        &["molto", "--key-ascii-env", "S3CRETVALUE", "info"],
        "--customer-key env:VAR --customer-key-encoding ascii",
    ),
    (
        &["molto", "customer-key", "change", "--hex", "S3CRETVALUE"],
        "--new-customer-key env:NAME (hex is the default encoding)",
    ),
    (
        &["molto", "customer-key", "change", "--ascii", "S3CRETVALUE"],
        "--new-customer-key env:NAME --encoding ascii",
    ),
    (
        &[
            "molto",
            "customer-key",
            "change",
            "--hex-env",
            "S3CRETVALUE",
        ],
        "--new-customer-key env:VAR (hex",
    ),
    (
        &[
            "molto",
            "customer-key",
            "change",
            "--hex-stdin",
            "S3CRETVALUE",
        ],
        "--new-customer-key stdin (hex",
    ),
    (
        &[
            "molto",
            "customer-key",
            "change",
            "--ascii-env",
            "S3CRETVALUE",
        ],
        "--new-customer-key env:VAR --encoding ascii",
    ),
    (
        &[
            "molto",
            "customer-key",
            "change",
            "--ascii-stdin",
            "S3CRETVALUE",
        ],
        "--new-customer-key stdin --encoding ascii",
    ),
    (
        &[
            "molto",
            "seed",
            "set",
            "--slot",
            "1",
            "--hex",
            "S3CRETVALUE",
        ],
        "--seed env:NAME --encoding hex",
    ),
    (
        &["prog", "seed", "set", "--base32", "S3CRETVALUE"],
        "--seed env:NAME (base32",
    ),
    (
        &[
            "molto",
            "seed",
            "set",
            "--slot",
            "1",
            "--hex-stdin",
            "S3CRETVALUE",
        ],
        "--seed stdin --encoding hex",
    ),
    (
        &["prog", "seed", "set", "--base32-env", "S3CRETVALUE"],
        "--seed env:VAR (base32",
    ),
    (
        &[
            "molto",
            "seed",
            "set",
            "--slot",
            "1",
            "--base32-stdin",
            "S3CRETVALUE",
        ],
        "--seed stdin (base32",
    ),
    (
        &["oath", "add", "n", "--secret-env", "S3CRETVALUE"],
        "--seed env:VAR",
    ),
    (
        &["oath", "add", "n", "--secret-stdin", "S3CRETVALUE"],
        "--seed stdin",
    ),
    (
        &["piv", "pin", "change", "--old-pin-stdin", "S3CRETVALUE"],
        "--pin stdin (the current PIN)",
    ),
    (
        &["fido", "pin", "set", "--new-pin-stdin", "S3CRETVALUE"],
        "--new-pin stdin",
    ),
    (
        &["piv", "pin", "unblock", "--puk-env", "S3CRETVALUE"],
        "--puk env:VAR",
    ),
    (
        &["piv", "pin", "unblock", "--puk-stdin", "S3CRETVALUE"],
        "--puk stdin",
    ),
    (
        &["piv", "puk", "change", "--old-puk-env", "S3CRETVALUE"],
        "--puk env:VAR (the current PUK)",
    ),
    (
        &["piv", "puk", "change", "--old-puk-stdin", "S3CRETVALUE"],
        "--puk stdin (the current PUK)",
    ),
    (
        &["piv", "puk", "change", "--new-puk-env", "S3CRETVALUE"],
        "--new-puk env:VAR",
    ),
    (
        &["piv", "puk", "change", "--new-puk-stdin", "S3CRETVALUE"],
        "--new-puk stdin",
    ),
    (
        &[
            "openpgp",
            "name",
            "set",
            "x",
            "--admin-pin-env",
            "S3CRETVALUE",
        ],
        "--admin-pin env:VAR",
    ),
    (
        &[
            "openpgp",
            "url",
            "set",
            "x",
            "--admin-pin-stdin",
            "S3CRETVALUE",
        ],
        "--admin-pin stdin",
    ),
    (
        &[
            "openpgp",
            "pin",
            "change",
            "--admin",
            "--admin-pin-env",
            "S3CRETVALUE",
        ],
        "with --admin, --pin is the admin PIN",
    ),
    (
        &[
            "openpgp",
            "pin",
            "change",
            "--admin",
            "--admin-pin-stdin",
            "S3CRETVALUE",
        ],
        "with --admin, --pin is the admin PIN",
    ),
    (
        &["piv", "chuid", "generate", "--mgmt-key-env", "S3CRETVALUE"],
        "--mgmt-key env:VAR",
    ),
    (
        &[
            "piv",
            "key",
            "delete",
            "--slot",
            "9a",
            "--mgmt-key-stdin",
            "S3CRETVALUE",
        ],
        "--mgmt-key stdin",
    ),
    (
        &[
            "piv",
            "cert",
            "delete",
            "--slot",
            "9a",
            "--mgmt-key-default",
            "S3CRETVALUE",
        ],
        "--mgmt-key default",
    ),
    (
        &[
            "piv",
            "mgmt-key",
            "change",
            "--old-mgmt-key-env",
            "S3CRETVALUE",
        ],
        "--mgmt-key env:VAR (the current management key)",
    ),
    (
        &[
            "piv",
            "mgmt-key",
            "change",
            "--old-mgmt-key-stdin",
            "S3CRETVALUE",
        ],
        "--mgmt-key stdin (the current management key)",
    ),
    (
        &[
            "piv",
            "mgmt-key",
            "change",
            "--old-mgmt-key-default",
            "S3CRETVALUE",
        ],
        "--mgmt-key default (the current management key)",
    ),
    (
        &[
            "piv",
            "mgmt-key",
            "change",
            "--new-mgmt-key-env",
            "S3CRETVALUE",
        ],
        "--new-mgmt-key env:VAR",
    ),
    (
        &[
            "piv",
            "mgmt-key",
            "change",
            "--new-mgmt-key-stdin",
            "S3CRETVALUE",
        ],
        "--new-mgmt-key stdin",
    ),
    (
        &["oath", "list", "--password-env", "S3CRETVALUE"],
        "--password env:VAR",
    ),
    (
        &["oath", "list", "--password-stdin", "S3CRETVALUE"],
        "--password stdin",
    ),
    (
        &[
            "oath",
            "password",
            "set",
            "--new-password-stdin",
            "S3CRETVALUE",
        ],
        "--new-password stdin",
    ),
    (
        &["prog", "seed", "set", "--seed-stdin", "S3CRETVALUE"],
        "--seed stdin",
    ),
    (
        &["molto", "import", "--slot", "1", "--uri-env", "S3CRETVALUE"],
        "--uri env:VAR",
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

/// Every `RETIRED_COMMANDS` and `RETIRED_LEAVES` row in main.rs has a case
/// above.
#[test]
fn every_retired_command_row_has_a_case() {
    let src = include_str!("../src/main.rs");
    let table = |name: &str| src.split(name).nth(1).unwrap().split("];").next().unwrap();
    let block = [
        table("const RETIRED_COMMANDS"),
        table("const RETIRED_LEAVES"),
    ]
    .concat();
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

/// Every `RETIRED_FLAGS` row in main.rs has a case above.
#[test]
fn every_retired_flag_row_has_a_case() {
    let src = include_str!("../src/main.rs");
    let block = src
        .split("const RETIRED_FLAGS")
        .nth(1)
        .unwrap()
        .split("];")
        .next()
        .unwrap();
    for row in block.split("RetiredFlag {").skip(1) {
        let flag = row
            .split("flag: \"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        let words: Vec<&str> = row
            .split("words: &[")
            .nth(1)
            .unwrap()
            .split(']')
            .next()
            .unwrap()
            .split(',')
            .map(|w| w.trim().trim_matches('"'))
            .filter(|w| !w.is_empty())
            .collect();
        assert!(
            CASES
                .iter()
                .any(|(a, _)| a.contains(&flag) && words.iter().all(|w| a.contains(w))),
            "no case for {flag} {words:?}"
        );
    }
}
