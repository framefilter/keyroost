//! `--device` completes saved friendly names from keys.json via the
//! dynamic engine, end to end, without touching hardware.

use std::process::Command;

#[test]
fn device_completes_saved_names() {
    let dir = std::env::temp_dir().join(format!("keyroost-completion-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("keyroost")).unwrap();
    std::fs::write(
        dir.join("keyroost/keys.json"),
        r#"{"keys":[{"name":"yubi-test","serial":"1","source":"usb"},{"name":"solo-test","serial":"2","source":"usb"}]}"#,
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_keyroostctl"))
        .env("COMPLETE", "fish")
        .env("XDG_CONFIG_HOME", &dir)
        .env("APPDATA", &dir)
        .args(["--", "keyroostctl", "--device", ""])
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{out:?}");
    assert!(
        stdout.lines().any(|l| l.starts_with("yubi-test")),
        "{stdout}"
    );
    assert!(
        stdout.lines().any(|l| l.starts_with("solo-test")),
        "{stdout}"
    );
}
