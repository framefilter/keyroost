//! Aegis / 2FAS / otpauth-list auto-detection path — attacker-supplied files.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Dropped-file classification sees raw bytes, text or not.
    let _ = keyroost_import::classify::classify(data, None);
    let _ = keyroost_import::classify::classify(data, Some("dropped.der"));
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = keyroost_import::parse_bulk_any(s);
        let _ = keyroost_import::aegis::is_encrypted(s);
        // The wide parsers read the same attacker-supplied files.
        let _ = keyroost_import::parse_any_wide(s);
        let _ = keyroost_import::parse_list_wide(s);
        let _ = keyroost_import::aegis::parse_wide(s);
        let _ = keyroost_import::twofas::parse_wide(s);
    }
});
