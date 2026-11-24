//! CTAP typed response parsers — the layer between the CBOR decoder and the
//! structs the app consumes, fed maps from a potentially malicious device.
//! (A capped `with_capacity` bug lived exactly here; keep it covered.)
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Raw device bytes, not a decoded map: authenticator data and the
    // makeCredential and getAssertion response bodies.
    let _ = keyroost_ctap::auth_data::parse_auth_data(data);
    let _ = keyroost_ctap::make_credential::parse_make_credential(data);
    let _ = keyroost_ctap::get_assertion::parse_get_assertion(data, None);
    if let Ok((value, _)) = keyroost_ctap::cbor::decode(data) {
        let _ = keyroost_ctap::cmd::parse_authenticator_info(&value);
        let _ = keyroost_ctap::client_pin::parse_pin_response(&value);
        let _ = keyroost_ctap::cred_mgmt::parse_rp(&value);
        let _ = keyroost_ctap::cred_mgmt::parse_credential(&value);
    }
});
