//! Aegis encrypted-vault decryption — the JSON-shape parsing, hex/base64
//! decoding, and parameter validation that run on an attacker-supplied vault
//! file, up to (and including) the AEAD attempts.
//!
//! scrypt cost parameters are attacker-controlled and legitimately large
//! (the library caps n at 2^22 ≈ 512 MiB of scratch), so vaults whose
//! parameters exceed a small fuzz budget are skipped after the parse — the
//! KDF math itself is upstream-tested; the format handling is ours.
#![no_main]
use libfuzzer_sys::fuzz_target;

/// Just enough of the Aegis header shape to read the scrypt parameters.
#[derive(serde::Deserialize)]
struct Header {
    slots: Option<Vec<Slot>>,
}
#[derive(serde::Deserialize)]
struct Slot {
    #[serde(default)]
    n: u64,
    #[serde(default)]
    r: u64,
    #[serde(default)]
    p: u64,
}
#[derive(serde::Deserialize)]
struct Root {
    header: Header,
}

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    // Budget check: skip inputs that would make the fuzzer grind real scrypt.
    if let Ok(root) = serde_json::from_str::<Root>(s) {
        if let Some(slots) = root.header.slots {
            if slots.iter().any(|sl| sl.n > 4096 || sl.r > 16 || sl.p > 4) {
                return;
            }
        }
    }
    let _ = keyroost_import::aegis::decrypt(s, b"fuzz-password");
});
