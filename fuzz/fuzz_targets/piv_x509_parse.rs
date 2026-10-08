//! PIV X.509/DER parsers. The SPKI-fallback path (#97) hands these raw
//! certificate bytes read off the card, and `--pubkey-in` (#100) hands
//! `parse_subject_public_key_info` bytes from a user-supplied file — so a
//! hostile or corrupt input must produce an error, never a panic or
//! unbounded allocation.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = keyroost_piv::x509_parse::parse_subject_dn(data);
    let _ = keyroost_piv::x509_parse::parse_key_policy_extension(data);
    let _ = keyroost_piv::x509_parse::parse_key_algorithm(data);
    let _ = keyroost_piv::x509_parse::parse_subject_public_key_info(data);
});
