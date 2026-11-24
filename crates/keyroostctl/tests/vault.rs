//! `fido vault` refusals that need no key, each run against its own empty
//! config directory with no key connected.
mod common;

use std::process::Stdio;

/// Run keyroostctl with `args`, the PIN in `KR_TEST_PIN`, no terminal and
/// no key: (exit code, stdout, stderr).
fn run(args: &[&str]) -> (i32, String, String) {
    let out = common::keyroostctl()
        .args(args)
        .env("KR_TEST_PIN", "123456")
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
