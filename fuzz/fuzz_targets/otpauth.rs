//! otpauth:// URI parser — attacker-supplied via import files and QR payloads.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = keyroost_import::parse_otpauth(s);
        let _ = keyroost_import::otpauth::parse_entry_labeled(s);
    }
});
