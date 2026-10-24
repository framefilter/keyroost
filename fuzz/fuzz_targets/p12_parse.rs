//! PKCS#12 reading — the BER walk, MAC and bag decryption, PKCS#8 and
//! certificate pairing that run on an attacker-supplied `.p12` file.
//!
//! The file chooses its own KDF iteration count (up to 10,000,000 per
//! derivation, 20,000,000 per file), so `keyroost-p12` lowers those caps to
//! 1,000 and 10,000 under cargo-fuzz's `--cfg fuzzing`: the same parsing runs,
//! without grinding the KDF.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = keyroost_p12::open(data, Some("x"));
    let _ = keyroost_p12::open(data, None);
});
