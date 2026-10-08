//! Piping keyroostctl's stdout into a reader that closes early (like
//! `keyroostctl … | head`) must exit quietly, not dump a panic, a backtrace or
//! a broken-pipe error.
//!
//! The output here comes from shell completion (`KEYROOSTCTL_COMPLETE=fish
//! keyroostctl -- keyroostctl --device ""`) over a keys.json with thousands of
//! saved names, so stdout is far larger than a pipe buffer and the write is
//! guaranteed to hit the closed pipe. Completion reports that as an error
//! rather than a panic, so this guards the closed-pipe handling in
//! `answer_completion_request()`. The panic shapes the guard in `main()` catches
//! (`install_broken_pipe_guard` / `is_broken_pipe_panic`) — std's `println!`
//! `Display` form and clap_complete's `Debug` form — are covered by the
//! `broken_pipe_panic_detection` unit test in `main.rs`.

use std::io::Read;
use std::process::{Command, Stdio};

/// Enough names that the completion output dwarfs any pipe buffer (64 KiB on
/// Linux, smaller elsewhere).
const NAMES: usize = 4000;

#[test]
fn broken_pipe_exits_without_panicking() {
    let dir = std::env::temp_dir().join(format!("keyroost-broken-pipe-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("keyroost")).unwrap();
    let names: Vec<String> = (0..NAMES)
        .map(|i| format!("broken-pipe-test-key-{i:05}-with-some-padding"))
        .collect();
    // Each name is one output line; make sure the total really overflows the pipe.
    let output_len: usize = names.iter().map(|n| n.len() + 1).sum();
    assert!(
        output_len > 2 * 64 * 1024,
        "output too small: {output_len} bytes"
    );
    // Old version 1 entries on purpose: completion converts the file in this
    // temp directory first and must still offer every name.
    let entries: Vec<String> = names
        .iter()
        .enumerate()
        .map(|(i, n)| format!(r#"{{"name":"{n}","serial":"{i}","source":"usb"}}"#))
        .collect();
    std::fs::write(
        dir.join("keyroost/keys.json"),
        format!(r#"{{"keys":[{}]}}"#, entries.join(",")),
    )
    .unwrap();

    // Completion needs no hardware: candidates come from keys.json only.
    let mut child = Command::new(env!("CARGO_BIN_EXE_keyroostctl"))
        .env("KEYROOSTCTL_COMPLETE", "fish")
        .env("XDG_CONFIG_HOME", &dir)
        .env("APPDATA", &dir)
        .args(["--", "keyroostctl", "--device", ""])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn keyroostctl");

    // Read one small chunk, then drop our read end — mimicking `head` closing
    // the pipe. The child's write of the rest then hits a closed pipe.
    {
        let mut out = child.stdout.take().expect("child stdout");
        let mut buf = [0u8; 32];
        let n = out.read(&mut buf).expect("read first chunk");
        assert!(n > 0, "completion wrote nothing");
        // `out` drops here, closing the read end.
    }

    let output = child.wait_with_output().expect("wait for child");
    let _ = std::fs::remove_dir_all(&dir);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !stderr.contains("panicked"),
        "a closed output pipe produced a panic on stderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("Broken pipe"),
        "a closed output pipe leaked a broken-pipe error to stderr:\n{stderr}"
    );
    // 141 (128 + SIGPIPE) is the conventional broken-pipe status, the same one
    // the panic guard uses. Unhandled, completion prints the error and exits
    // 2, so this also distinguishes "handled" from "leaked".
    assert_eq!(
        output.status.code(),
        Some(141),
        "expected exit 141 on a closed pipe, got {:?}\nstderr:\n{stderr}",
        output.status
    );
}
