//! Token2 OTP-on-FIDO response parsers — fed raw bytes a (possibly malicious
//! or buggy) Token2 key could return: the variable-tail enumerate parser, the
//! device-info decoder, and the serial-number decoder.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The enumerate parser is the interesting one — its conditional code tail
    // makes mis-framing easy; it must never panic on arbitrary input.
    let _ = keyroost_token2otp::parse_entries(data, false);
    let _ = keyroost_token2otp::parse_entries(data, true);
    let _ = keyroost_token2otp::parse_device_info(data);
    let _ = keyroost_token2otp::parse_serial(data);
});
