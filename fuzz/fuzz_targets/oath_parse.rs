//! OATH applet response parsers — device-supplied TLV.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = keyroost_oath::parse_tlvs(data);
    let _ = keyroost_oath::parse_select(data);
    let _ = keyroost_oath::parse_list(data);
    let _ = keyroost_oath::parse_calculate(data);
    let _ = keyroost_oath::parse_calculate_all(data);
    let _ = keyroost_oath::parse_truncated_response(data);
});
