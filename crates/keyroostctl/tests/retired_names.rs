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
