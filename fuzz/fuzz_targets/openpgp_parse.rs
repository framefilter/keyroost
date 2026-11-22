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
    let _ = keyroost_openpgp::parse_cardholder_related_data(data);
    let _ = keyroost_openpgp::parse_cardholder_name(data);
    let _ = keyroost_openpgp::parse_url(data);
    // The KDF setting decides how PINs are hashed; a parsed one must also
    // derive without panicking. Large counts are skipped to keep each run
    // fast (a setting may ask for 65 MB of hashing).
    if let Ok(kdf) = keyroost_openpgp::parse_kdf(data) {
        let cheap = match &kdf {
            keyroost_openpgp::Kdf::IterSaltedS2k(p) => p.count() <= 4096,
            _ => true,
        };
        if cheap {
            let _ = kdf.derive(keyroost_openpgp::PinRole::Admin, b"12345678");
        }
    }
});
