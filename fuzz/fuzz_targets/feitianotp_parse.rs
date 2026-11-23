//! Feitian OTP applet response parsers — device-supplied TLV, plus the
//! stored-name splitter, which runs on names a card's LIST answer returns,
//! and the card's serial and device-information answers.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = keyroost_feitianotp::parse_tlvs(data);
    let _ = keyroost_feitianotp::parse_select(data);
    let _ = keyroost_feitianotp::parse_calculate(data);
    let _ = keyroost_feitianotp::parse_device_serial(data);
    let _ = keyroost_feitianotp::parse_device_cos(data);
    for slot in keyroost_feitianotp::Slot::ALL {
        if let Ok(listing) = keyroost_feitianotp::parse_list(data, slot) {
            for c in &listing.credentials {
                let _ = keyroost_feitianotp::parse_name(&c.name, c.oath_type);
                let _ = keyroost_feitianotp::totp_period(&c.name);
            }
        }
    }
});
