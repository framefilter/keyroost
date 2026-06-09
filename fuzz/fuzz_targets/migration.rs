//! Google Authenticator migration payloads — attacker-supplied via QR images.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = keyroost_import::migration::parse_payload(data);
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = keyroost_import::migration::parse(s);
    }
});
