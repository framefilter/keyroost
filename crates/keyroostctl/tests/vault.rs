//! `fido vault` refusals that need no key, each run against its own empty
//! config directory with no key connected.
mod common;

use std::process::Stdio;

/// Run keyroostctl with `args`, the PIN in `KR_TEST_PIN`, no terminal and
/// no key: (exit code, stdout, stderr).
fn run(args: &[&str]) -> (i32, String, String) {
    run_with(args, &[])
}

/// [`run`] with more environment variables (a passphrase in `KR_PASS`).
fn run_with(args: &[&str], vars: &[(&str, &str)]) -> (i32, String, String) {
    let out = common::keyroostctl()
        .args(args)
        .env("KR_TEST_PIN", "123456")
        .envs(vars.iter().copied())
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
fn vault_list_with_no_key_fails_like_fido_ssh_list() {
    let ssh = run(&["fido", "ssh", "list", "--pin", "env:KR_TEST_PIN"]);
    let vault = run(&["fido", "vault", "list", "--pin", "env:KR_TEST_PIN"]);
    assert_ne!(ssh.0, 0, "{ssh:?}");
    assert!(ssh.2.starts_with("error: "), "{ssh:?}");
    assert_eq!(vault, ssh);
}

#[test]
fn vault_list_without_a_pin_source_is_refused_before_the_key() {
    let (code, out, err) = run(&["fido", "vault", "list"]);
    assert_eq!(code, 1);
    assert!(out.is_empty(), "{out}");
    assert!(
        err.contains("no PIN given: pass --pin env:NAME or --pin stdin"),
        "{err}"
    );
}

/// What `vault add` prints for a name the vault format can't hold: the
/// format's own refusal, before any key is looked for.
fn assert_name_refused_before_the_key(name: &str) {
    let (code, out, err) = run(&["fido", "vault", "add", name, "--pin", "env:KR_TEST_PIN"]);
    assert_eq!(code, 1, "{err}");
    assert!(out.is_empty(), "{out}");
    assert_eq!(
        err,
        format!("error: {}\n", keyroost_vault::VaultError::NameLength),
        "no key message, only the name's"
    );
}

#[test]
fn vault_add_refuses_a_name_over_32_bytes_before_the_key() {
    assert_name_refused_before_the_key(&"é".repeat(17));
}

#[test]
fn vault_add_refuses_an_empty_name() {
    assert_name_refused_before_the_key("");
}

/// `entry add` with no password source, no `--generate-password` and no
/// terminal is refused before any key is looked for, naming both ways out.
#[test]
fn entry_add_without_password_or_terminal_is_refused() {
    let (code, out, err) = run(&[
        "fido",
        "vault",
        "entry",
        "add",
        "Gmail",
        "--pin",
        "env:KR_TEST_PIN",
    ]);
    assert_eq!(code, 1, "{err}");
    assert!(out.is_empty(), "{out}");
    assert_eq!(
        err,
        "error: no password given: pass --password env:NAME, --password stdin or \
         --generate-password\n",
        "no key message, only the refusal"
    );
}

/// `entry add --generate-password` needs no password source and goes on to
/// look for the key.
#[test]
fn entry_add_with_generate_reaches_the_key() {
    let (code, out, err) = run(&[
        "fido",
        "vault",
        "entry",
        "add",
        "Gmail",
        "--generate-password",
        "--pin",
        "env:KR_TEST_PIN",
    ]);
    let ssh = run(&["fido", "ssh", "list", "--pin", "env:KR_TEST_PIN"]);
    assert_eq!((code, out, err), ssh);
}

/// The backup in `tests/fixtures/vault.t2vault`: FidoParole's backup test
/// vector, passphrase `correct horse battery` (cheap KDF settings).
const BACKUP: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/vault.t2vault");
const BACKUP_PASS: &str = "correct horse battery";

fn import(pass: &str) -> (i32, String, String) {
    run_with(
        &[
            "fido",
            "vault",
            "import",
            "-i",
            BACKUP,
            "--passphrase",
            "env:KR_PASS",
            "--pin",
            "env:KR_TEST_PIN",
            "--yes",
        ],
        &[("KR_PASS", pass)],
    )
}

/// A wrong passphrase is refused when the file is read, before any key is
/// looked for.
#[test]
fn import_wrong_passphrase_fails_before_the_key() {
    let (code, out, err) = import("wrong passphrase");
    assert_eq!(code, 1, "{err}");
    assert!(out.is_empty(), "{out}");
    assert_eq!(
        err,
        format!("error: {BACKUP}: {}\n", keyroost_vault::VaultError::Decrypt),
        "no key message, only the file's"
    );
}

/// The right passphrase opens the file; the run then looks for the key.
#[test]
fn import_good_passphrase_reaches_the_key() {
    let ssh = run(&["fido", "ssh", "list", "--pin", "env:KR_TEST_PIN"]);
    assert_eq!(import(BACKUP_PASS), ssh);
}

/// An `--entry` title no backup entry has is refused once the file is
/// open, before any key is looked for.
#[test]
fn import_unknown_entry_is_refused_before_the_key() {
    let (code, out, err) = run_with(
        &[
            "fido",
            "vault",
            "import",
            "-i",
            BACKUP,
            "--entry",
            "Gmial",
            "--passphrase",
            "env:KR_PASS",
            "--pin",
            "env:KR_TEST_PIN",
            "--dry-run",
        ],
        &[("KR_PASS", BACKUP_PASS)],
    );
    assert_eq!(code, 1, "{err}");
    assert!(out.is_empty(), "{out}");
    assert_eq!(err, "error: no entry in the backup is titled \"Gmial\"\n");
}

fn export(out: &std::path::Path, pass: &str) -> (i32, String, String) {
    run_with(
        &[
            "fido",
            "vault",
            "export",
            "Personal",
            "-o",
            out.to_str().unwrap(),
            "--passphrase",
            "env:KR_PASS",
            "--pin",
            "env:KR_TEST_PIN",
        ],
        &[("KR_PASS", pass)],
    )
}

#[test]
fn export_refuses_an_existing_file_before_the_key() {
    let dir = common::TempDir::new("vault-export");
    let out = dir.join("personal.t2vault");
    std::fs::write(&out, b"keep me").unwrap();
    let (code, stdout, err) = export(&out, BACKUP_PASS);
    assert_eq!(code, 1, "{err}");
    assert!(stdout.is_empty(), "{stdout}");
    assert_eq!(
        err,
        format!(
            "error: {} already exists; pass --overwrite to replace it\n",
            out.display()
        )
    );
    assert_eq!(std::fs::read(&out).unwrap(), b"keep me");
}

#[test]
fn export_refuses_a_short_passphrase_before_the_key() {
    let dir = common::TempDir::new("vault-export");
    let out = dir.join("personal.t2vault");
    let (code, stdout, err) = export(&out, "123456789");
    assert_eq!(code, 1, "{err}");
    assert!(stdout.is_empty(), "{stdout}");
    assert_eq!(
        err,
        format!("error: {}\n", keyroost_vault::VaultError::ShortPassphrase)
    );
    assert!(!out.exists());
}
