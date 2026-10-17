//! OpenPGP key files — backups and GnuPG exports the user picks. No
//! passphrase: with one, every protected input would run the S2K (up to
//! 65M hashed octets), drowning the parser in hashing.
#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = keyroost_pgpkey::read::open(data, None);
    let _ = keyroost_pgpkey::read::open_public(data);
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = keyroost_pgpkey::armor::decode(s);
    }
});
