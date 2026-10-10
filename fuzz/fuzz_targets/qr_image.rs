//! PNG/JPEG → grayscale → QR detection — the image file is attacker-supplied.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = keyroost_qr::entries_from_image(data);
    let _ = keyroost_qr::entries_from_image_wide(data);
    // The shared file reader (no password: never runs the vault KDF).
    let _ = keyroost_qr::open_file(data, None, None);
});
