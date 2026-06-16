//! Token2 OTP-on-FIDO response parsers — fed raw bytes a (possibly malicious
//! or buggy) Token2 key could return: the variable-tail enumerate-page parser,
//! the single-entry read parser, the device-info decoder, and the serial-number
//! decoder. None of these may panic on arbitrary input.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The enumerate-page parser is the interesting one — its conditional code
    // tail makes mis-framing easy; it must never panic on arbitrary input.
    let _ = keyroost_token2otp::parse_enum_page(data);
    let _ = keyroost_token2otp::entry::parse_read_one(data);
    let _ = keyroost_token2otp::DeviceInfo::parse(data);
    let _ = keyroost_token2otp::parse_serial(data);
});
