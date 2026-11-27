//! CanoKey parsers: the Admin applet's answers (firmware version, hardware
//! variant, serial, device configuration, the PIV algorithm table), and the
//! text a CanoKey's USB serial, product string and reader name are read from.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = keyroost_canokey::parse_firmware_version(data);
    let _ = keyroost_canokey::parse_text(data);
    let _ = keyroost_canokey::parse_serial(data);
    let _ = keyroost_canokey::parse_config(data);
    let _ = keyroost_canokey::parse_piv_algorithm_ids(data);

    let text = String::from_utf8_lossy(data);
    let _ = keyroost_resolve::canokey::serial_from_hex(&text);
    let _ = keyroost_resolve::canokey::row_serial(&text);
    let _ = keyroost_resolve::canokey::model_from_product(&text);
    let _ = keyroost_resolve::canokey::model_from_reader(&text);
    let _ = keyroost_resolve::canokey::is_reader_name(&text);
});
