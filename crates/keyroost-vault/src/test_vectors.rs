//! Known-answer vectors produced by running FidoParole's own `vault.rs`
//! (github.com/token2/fidoparole, `src-tauri/src/vault.rs`, main branch as
//! fetched 2026-11-21) with fixed randomness in a throwaway harness. Later
//! tests must reproduce these bytes exactly.
//!
//! `flate2`'s default backend is `miniz_oxide` at level 9 ("best"), which is
//! why keyroost compresses with `miniz_oxide::deflate::compress_to_vec(.., 9)`.
//! Verified in the harness: compressing `SAMPLE_JSON_V2` with miniz_oxide
//! level 9 directly is byte-identical to flate2's output
//! (`SAMPLE_COMPRESSED_HEX`), so tests may compare compressed bytes exactly.

// Tasks 3-6 use these constants.
#![allow(dead_code)]

/// Fixed hmac-secret output used for the key blob.
pub(crate) const HMAC_SECRET: [u8; 32] = [0x11; 32];
pub(crate) const BLOB_SALT: [u8; 16] = [0x22; 16];
pub(crate) const BLOB_NONCE: [u8; 12] = [0x33; 12];
pub(crate) const BACKUP_PASS: &str = "correct horse battery";
pub(crate) const BACKUP_SALT: [u8; 16] = [0x44; 16];
pub(crate) const BACKUP_NONCE: [u8; 12] = [0x55; 12];
/// Argon2id (m_cost KiB, t_cost, p_cost); small m for test speed.
pub(crate) const BACKUP_PARAMS: (u32, u32, u32) = (8, 1, 1);

/// The 32 bytes of FidoParole's `hmac_salt()`: SHA-256("WebAuthn PRF" || 0x00 || PRF_INPUT).
pub(crate) const PRF_SALT_HEX: &str =
    "2cb008f0aa5722f2396e4a7fb744ff15189d98a932e843cc9a6d65eaaf3726c8";

/// Sample vault, format 2 plain JSON (timestamps in minutes).
pub(crate) const SAMPLE_JSON_V2: &str = r#"{"v":2,"e":[{"i":"AAAAAAAA","t":"Mail","u":"emin","p":"correct horse battery staple","l":"https://mail.example","m":28333343},{"i":"BBBBBBBB","t":"GitHub","u":"alice","p":"pw","n":"2FA on the key","m":28333333}]}"#;

/// `SAMPLE_JSON_V2` deflated (flate2 best == miniz_oxide level 9).
pub(crate) const SAMPLE_COMPRESSED_HEX: &str = concat!(
    "4d8dcb0ac23010457f25ccba58685c487675a16efc027191968104f32299aaa5",
    "e4df1d6816ded519e672cf066f50430708eab1810505630b74407cdeb5758c0b",
    "237a1b1813e31c73c6998489b9a0983411e65514d2c921571c570c512aaaef3d",
    "0f1cf0abfdfef2ac3b49ce51d66e379e5b9af16ae9b64ccda99d9db149d38721",
    "300c9751c420c8a078e1fa3f2a657dd61f",
);

/// `seal()` of the sample with `HMAC_SECRET`, `BLOB_SALT`, `BLOB_NONCE`.
pub(crate) const SEALED_BLOB_HEX: &str = concat!(
    "5432564c54012222222222222222222222222222222233333333333333333333",
    "3333cc14133636d52e65b7546c7ec307fccc725e34027a9032852488f2e05ca9",
    "6202535fd2e73cb8736018dfa535fd11d4c39a542cea232f5d69d8ec04838089",
    "95e6597eea3ad599789b0b647df03ff828348b8840b6fe23bcbc95c0ae32d92a",
    "1ccde9823c5ce9626a1be340466d93a254f7dc1a74cc31b1a8904edc92c795f0",
    "efaed7e6272acafb8ff4dfeac355c6118c423ff43e927fbd782369ed897107c0",
    "760591",
);

/// `export_backup_with()` of the sample with `BACKUP_PASS`, `BACKUP_SALT`, `BACKUP_NONCE`, `BACKUP_PARAMS`.
pub(crate) const BACKUP_HEX: &str = concat!(
    "543256424b010800000001000000010000004444444444444444444444444444",
    "4444555555555555555555555555fbba791dce0612aa8186fcbe8e67c498f3f4",
    "3985f793857925837f11f2b04ddab7d83ba9f6a3f2c04a08fdf6e707db5d11c4",
    "8cb3326581d5ab6935849522596f53542486ad6fd190bbbe557d484a61caef7d",
    "f3f6d79278f69501ba66b63f3afe73b0e4cda204398cf608a935c73a89fcde61",
    "e86d3eb444c67d47fc9537a2045c19992f666d4268fcd851811b3002db7fb8cf",
    "996d8a8dd9f3bee56d98b87f984c57",
);

/// One sample entry: (id, title, username, password, url, notes, modified).
pub(crate) type SampleEntry = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    i64,
);

/// The entries of the sample vault, in order. `modified` is in seconds here;
/// the JSON stores minutes.
pub(crate) const SAMPLE_ENTRIES: [SampleEntry; 2] = [
    (
        "AAAAAAAA",
        "Mail",
        "emin",
        "correct horse battery staple",
        "https://mail.example",
        "",
        1_700_000_600,
    ),
    (
        "BBBBBBBB",
        "GitHub",
        "alice",
        "pw",
        "",
        "2FA on the key",
        1_700_000_000,
    ),
];
