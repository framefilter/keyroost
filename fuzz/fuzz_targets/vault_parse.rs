//! Vault reading — the sealed largeBlob entry header and AEAD envelope, the
//! passphrase-protected backup file, and the decrypted JSON model, all of which
//! parse attacker-supplied bytes (an entry read off a key, a backup file, or
//! the plaintext inside either).
//!
//! A backup chooses its own Argon2 parameters, so `keyroost-vault` lowers its
//! import bounds (m <= 64 KiB, t <= 2, p <= 1) under cargo-fuzz's
//! `--cfg fuzzing`: the same parsing runs without grinding the KDF.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // An all-zero secret mostly fails at the AEAD tag, which still exercises
    // header parsing.
    let _ = keyroost_vault::open(data, &[0u8; 32]);
    let _ = keyroost_vault::import_backup(data, "fuzz-pass-1234");
    if let Ok(v) = keyroost_vault::from_json(data) {
        // Anything we accept must serialize to something we accept again.
        let again = keyroost_vault::to_json(&v);
        assert!(keyroost_vault::from_json(&again).is_ok());
    }
});
