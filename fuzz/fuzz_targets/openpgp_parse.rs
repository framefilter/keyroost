//! OpenPGP card response parsers — device-supplied BER-TLV.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = keyroost_openpgp::parse_tlvs(data);
    let _ = keyroost_openpgp::parse_application_related_data(data);
    let _ = keyroost_openpgp::parse_pw_status(data);
    let _ = keyroost_openpgp::parse_signature_counter(data);
    let _ = keyroost_openpgp::parse_generated_public_key(data);
    let _ = keyroost_openpgp::parse_rsa_algorithm_attributes(data);
    let _ = keyroost_openpgp::parse_algorithm_attributes(data);
    let _ = keyroost_openpgp::describe_algorithm_attributes(data);
    let _ = keyroost_openpgp::parse_algorithm_information(data);
});
