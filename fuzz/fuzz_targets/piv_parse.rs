//! PIV response parsers — device-supplied BER.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = keyroost_piv::unwrap_data_object(data);
    let _ = keyroost_piv::parse_version(data);
    let _ = keyroost_piv::parse_serial(data);
    // Write-path response parsers: GENERAL AUTHENTICATE templates, generated
    // public keys, and GET METADATA — all carry attacker-influenceable BER.
    let _ = keyroost_piv::parse_general_auth(data, 0x80);
    let _ = keyroost_piv::parse_general_auth(data, 0x82);
    let _ = keyroost_piv::parse_public_key(data);
    let _ = keyroost_piv::parse_metadata(data);
});
