//! Removed and renamed secret flags fail with a message naming the
//! replacement, exit 2, and never repeat the value given.
mod common;
use std::process::Stdio;

fn run(args: &[&str]) -> (i32, String) {
    let out = common::keyroostctl()
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
            "use --customer-key env:NAME",
        ),
        (
            &["molto", "--key-ascii", "S3CRETVALUE", "info"],
            "use --customer-key env:NAME --customer-key-encoding ascii",
        ),
        (
            &[
                "molto",
                "seed",
                "set",
                "--slot",
                "99",
                "--hex",
                "S3CRETVALUE",
            ],
            "use --seed env:NAME --encoding hex",
        ),
        (
            &[
                "molto",
                "seed",
                "set",
                "--slot",
                "99",
                "--base32=S3CRETVALUE",
            ],
            "use --seed env:NAME (base32 is the default encoding)",
        ),
        (
            &["prog", "seed", "set", "--hex", "S3CRETVALUE"],
            "use --seed env:NAME --encoding hex",
        ),
        (
            &["molto", "customer-key", "change", "--ascii", "S3CRETVALUE"],
            "use --new-customer-key env:NAME --encoding ascii",
        ),
        (
            &["molto", "customer-key", "change", "--hex", "S3CRETVALUE"],
            "use --new-customer-key env:NAME (hex is the default encoding)",
        ),
        (
            &["molto", "seed", "set", "--hex-env", "V"],
            "--seed env:VAR --encoding hex",
        ),
        (
            &["molto", "--key-env", "V", "info"],
            "--customer-key env:VAR",
        ),
        (&["molto", "import", "--uri-env", "V"], "--uri env:VAR"),
        (&["oath", "add", "n", "--secret-env", "V"], "--seed env:VAR"),
        (&["oath", "add", "n", "--secret-stdin"], "--seed stdin"),
        (
            &["otp", "pin", "change", "--current-env", "V"],
            "--pin env:VAR",
        ),
        (
            &["otp", "pin", "change", "--new-env", "V"],
            "--new-pin env:VAR",
        ),
        (
            &["otp", "pin", "change", "--pin-stdin"],
            "--pin stdin --new-pin stdin",
        ),
        (
            &["piv", "pin", "change", "--old-pin-env", "S3CRETVALUE"],
            "--pin env:VAR",
        ),
        (
            &["piv", "retries", "set", "--mgmt-key-default"],
            "--mgmt-key default",
        ),
        (
            &["oath", "list", "--password-stdin", "S3CRETVALUE"],
            "--password stdin",
        ),
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
        "--slot",
        "99",
        "otpauth://totp/x?secret=S3CRETVALUE",
        "--yes",
    ]);
    assert_eq!(code, 2, "{err}");
    assert!(
        err.contains("--uri env:NAME") && !err.contains("S3CRETVALUE"),
        "{err}"
    );
}

/// A stray value on a command that takes a secret may be the secret itself
/// (a literal otpauth URI on `molto import`, or a seed after `--seed
/// stdin`): clap's "unexpected argument" message would repeat it, so
/// keyroostctl replaces it with one that doesn't.
#[test]
fn a_stray_value_on_a_secret_command_is_not_repeated() {
    for (args, want) in [
        (
            &[
                "molto",
                "import",
                "--slot",
                "99",
                "otpauth://totp/x?secret=S3CRET",
            ][..],
            "takes the otpauth:// URI as --uri env:NAME or --uri stdin",
        ),
        (
            &[
                "molto", "seed", "set", "--slot", "99", "--seed", "stdin", "S3CRET",
            ],
            "unexpected extra argument (not shown, in case it is a secret); \
             see `keyroostctl molto seed set --help`",
        ),
    ] {
        let (code, err) = run(args);
        assert_eq!(code, 2, "{args:?}: {err}");
        assert!(err.contains(want), "{args:?}: {err}");
        assert!(!err.contains("S3CRET"), "{args:?} echoed the value: {err}");
    }
}

/// A retired `--X-stdin=VALUE` is an unknown flag: the hint names its
/// replacement and never the value, which may be the secret itself.
#[test]
fn a_stdin_flag_given_a_value_is_not_repeated() {
    let (code, err) = run(&["molto", "seed", "set", "--slot", "99", "--hex-stdin=S3CRET"]);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("--seed stdin --encoding hex"), "{err}");
    assert!(!err.contains("S3CRET"), "echoed the value: {err}");

    let (code, err) = run(&[
        "piv",
        "pin",
        "change",
        "--old-pin-stdin",
        "--new-pin-stdin=S3CRET",
    ]);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("--pin stdin"), "{err}");
    assert!(!err.contains("S3CRET"), "echoed the value: {err}");
}

/// A dash-led word right after a stdin source (`--pin stdin -123456`)
/// is hidden the same way as a bare stray value: clap reports only the
/// short-flag prefix it choked on, which isn't the whole word.
#[test]
fn a_dash_led_value_after_a_stdin_flag_is_not_repeated() {
    let (code, err) = run(&["piv", "pin", "change", "--pin", "stdin", "-123456"]);
    assert_eq!(code, 2, "{err}");
    assert!(
        err.contains("unexpected extra argument (not shown, in case it is a secret)"),
        "{err}"
    );
    assert!(!err.contains("123456"), "echoed the value: {err}");
}

/// A genuine typo — a subcommand or a `--`-prefixed flag name made only of
/// letters and dashes — is never a secret, so it still gets clap's own
/// message and "similar" tip, even right after a stdin source.
#[test]
fn a_typo_still_gets_claps_similar_name_tip() {
    let (code, err) = run(&["molto", "sed"]);
    assert_ne!(code, 0, "{err}");
    assert!(err.contains("a similar subcommand exists: 'seed'"), "{err}");

    let (code, err) = run(&[
        "piv", "pin", "change", "--pin", "stdin", "--new-pn", "stdin",
    ]);
    assert_ne!(code, 0, "{err}");
    assert!(
        err.contains("a similar argument exists: '--new-pin'"),
        "{err}"
    );
}

const TABLE: &str = include_str!("secret_flags.txt");

/// A well-formed value for a secret supplied by env so a later one is
/// reached. It never reaches a key: one secret is always missing, and every
/// secret is checked before any device is opened.
fn dummy(prefix: &str) -> &'static str {
    match prefix {
        "mgmt-key" | "new-mgmt-key" | "customer-key" | "new-customer-key" => "00",
        "seed" => "AAAA",
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
/// --help. Earlier required secrets are supplied by env (`--X env:VAR`) so
/// each later one is reached.
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
            let out = common::keyroostctl().args(&a).output().unwrap();
            String::from_utf8_lossy(&out.stdout).into_owned()
                + &String::from_utf8_lossy(&out.stderr)
        };
        for i in 0..required.len() {
            let mut cmd = common::keyroostctl();
            cmd.args(&path)
                .args(&extra)
                .current_dir(&dir)
                .stdin(Stdio::null())
                .env("PCSCLITE_CSOCK_NAME", "/nonexistent/keyroost-test-no-pcsc");
            for (j, prev) in required[..i].iter().enumerate() {
                let p = prev.split('|').next().unwrap();
                let var = format!("KR_TEST_SECRET_{j}");
                cmd.arg(format!("--{p}")).arg(format!("env:{var}"));
                cmd.env(&var, dummy(p));
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
                let want = format!("--{p} env:NAME");
                assert!(err.contains(&want), "{line} #{i}: {err}");
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

/// `openpgp key import --in` loads and checks the key file before any key
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
        let out = common::keyroostctl()
            .args(["openpgp", "key", "import", "--yes", "--admin-pin"])
            .arg("env:KR_TEST_ADMIN_PIN")
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

/// One literal value per secret flag (and a few shapes of it): each is
/// refused with exit 2 and never echoed.
const LITERAL_CASES: &[&[&str]] = &[
    &["piv", "pin", "change", "--pin", "S3CRETVALUE"],
    &["piv", "pin", "change", "--pin=S3CRETVALUE"],
    &["piv", "pin", "change", "--pin", "-S3CRETVALUE"],
    &["piv", "pin", "change", "--new-pin", "env:"],
    &["piv", "puk", "change", "--puk", "STDIN"],
    &["piv", "puk", "change", "--new-puk", "S3CRETVALUE"],
    &["piv", "chuid", "generate", "--mgmt-key", "S3CRETVALUE"],
    &["piv", "mgmt-key", "change", "--new-mgmt-key", "default"],
    &["openpgp", "name", "set", "x", "--admin-pin", "S3CRETVALUE"],
    &["oath", "list", "--password", "S3CRETVALUE"],
    &["oath", "password", "set", "--new-password", "S3CRETVALUE"],
    &["oath", "add", "n", "--seed", "S3CRETVALUE"],
    &["fido", "pin", "change", "--pin", "default"],
    &["molto", "--customer-key", "S3CRETVALUE", "info"],
    &["molto", "info", "--customer-key=S3CRETVALUE"],
    &[
        "molto",
        "customer-key",
        "change",
        "--new-customer-key",
        "S3CRETVALUE",
    ],
    &[
        "molto",
        "seed",
        "set",
        "--slot",
        "1",
        "--seed",
        "S3CRETVALUE",
    ],
    &["prog", "seed", "set", "--seed", "-S3CRETVALUE"],
    &["molto", "import", "--slot", "1", "--uri", "S3CRETVALUE"],
];

/// A literal value given to a secret flag, in any spelling, is refused
/// with exit 2 before any key is looked at, and never repeated.
#[test]
fn a_literal_secret_is_refused_with_exit_2_and_never_echoed() {
    for args in LITERAL_CASES {
        let (code, err) = run(args);
        assert_eq!(code, 2, "{args:?}: {err}");
        assert!(err.contains(" takes env:NAME"), "{args:?}: {err}");
        assert!(!err.contains("S3CRET"), "{args:?} echoed: {err}");
        assert!(
            !err.contains('\u{2192}'),
            "{args:?}: a key was selected: {err}"
        );
    }
    // The retired `-` positional of `molto import` names its replacement.
    let (code, err) = run(&["molto", "import", "--slot", "1", "-"]);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("is now `molto import --uri stdin`"), "{err}");
    // A value after `--pin stdin` is a stray argument, hidden too.
    for args in [
        &["piv", "pin", "change", "--pin", "stdin", "S3CRETVALUE"][..],
        &["piv", "pin", "change", "--pin", "stdin", "-S3CRETVALUE"],
    ] {
        let (code, err) = run(args);
        assert_eq!(code, 2, "{args:?}: {err}");
        assert!(!err.contains("S3CRET"), "{args:?} echoed: {err}");
    }
    // env:NAME with NAME unset: the flag is named, never the NAME.
    let (code, err) = run(&[
        "piv",
        "pin",
        "change",
        "--pin",
        "env:S3CRETVALUE",
        "--new-pin",
        "env:S3CRETVALUE",
    ]);
    assert_eq!(code, 1, "{err}");
    assert!(
        err.contains("given to --pin is not set") && !err.contains("S3CRET"),
        "{err}"
    );
    assert!(!err.contains('\u{2192}'), "{err}");
}

/// A flag-shaped word right after a secret flag (`--pin --yes`) is a
/// missing value, said as such; it is still never repeated.
#[test]
fn a_flag_after_a_secret_flag_is_a_missing_value() {
    for (args, flag) in [
        (&["piv", "pin", "change", "--pin", "--yes"][..], "--pin"),
        (
            &["piv", "pin", "change", "--pin", "--new-pin", "stdin"],
            "--pin",
        ),
        (&["oath", "list", "--password", "--json"], "--password"),
    ] {
        let (code, err) = run(args);
        assert_eq!(code, 2, "{args:?}: {err}");
        assert!(
            err.contains(&format!("{flag} needs a value: env:NAME or stdin")),
            "{args:?}: {err}"
        );
        assert!(
            !err.contains("S3CRET") && !err.contains("--yes"),
            "{args:?}: {err}"
        );
    }
    let (code, err) = run(&["piv", "chuid", "generate", "--mgmt-key", "--yes"]);
    assert_eq!(code, 2, "{err}");
    assert!(
        err.contains("--mgmt-key needs a value: env:NAME, stdin or default"),
        "{err}"
    );
}

/// Every flag in `SECRET_FLAGS` has a literal case in `LITERAL_CASES`.
#[test]
fn every_secret_flag_has_a_literal_case() {
    let src = include_str!("../src/secrets.rs");
    let block = src
        .split("const SECRET_FLAGS")
        .nth(1)
        .unwrap()
        .split("];")
        .next()
        .unwrap();
    let longs: Vec<&str> = block
        .split("long: \"")
        .skip(1)
        .map(|r| r.split('"').next().unwrap())
        .collect();
    assert!(longs.len() > 10, "{longs:?}");
    for long in longs {
        let flag = format!("--{long}");
        let eq = format!("--{long}=");
        assert!(
            LITERAL_CASES
                .iter()
                .any(|a| a.iter().any(|w| *w == flag || w.starts_with(&eq))),
            "no literal case for {flag}"
        );
    }
}
