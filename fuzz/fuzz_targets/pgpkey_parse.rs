//! OpenPGP key files — backups and GnuPG exports the user picks.
#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = keyroost_pgpkey::read::open(data, Some(b"x"));
    let _ = keyroost_pgpkey::read::open_public(data);
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = keyroost_pgpkey::armor::decode(s);
    }
});
