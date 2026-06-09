//! base32 / hex decoders — fed user-typed and file-supplied secrets.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = keyroost_proto::codec::base32_decode(s);
        let _ = keyroost_proto::codec::hex_decode(s);
        let _ = keyroost_proto::codec::base64_decode(s);
    }
});
