//! Golden tests locking the Molto2 import path's observable behavior.
//!
//! The narrow parsers (`aegis::parse`, `twofas::parse`, `parse_otpauth_list`,
//! `parse_any`, `migration::parse_payload`, `otpauth::parse`) feed the Molto2
//! slot programmer. Wider parsers for other keys are built beside them; this
//! file pins every result the Molto2 path produces today — the exact `Debug`
//! of each accepted entry and the exact text of each error — so any change to
//! what a Molto2 import accepts, skips or reports shows up here first.
//!
//! `Debug` shows a seed only as its length, so each accepted result also
//! carries a SHA-256 fingerprint of its decoded seeds (`seeds=…`): a change
//! to the decoded bytes fails here without any seed ever being printed.

// The suite must never compile to zero tests: the crate's dev-dependency on
// itself turns `bulk` on for `cargo test`, and losing that should be loud.
#[cfg(not(feature = "bulk"))]
compile_error!("molto_golden needs keyroost-import's `bulk` feature (see [dev-dependencies])");

use keyroost_import::migration::Migration;
use keyroost_import::{
    aegis, migration, otpauth, parse_bulk_any, parse_otpauth_list, twofas, BulkEntry, OtpAuth,
};

/// The decoded seeds a parse result carries, in order.
trait Seeds {
    fn seeds(&self) -> Vec<&[u8]>;
}

impl Seeds for Vec<BulkEntry> {
    fn seeds(&self) -> Vec<&[u8]> {
        self.iter().map(|e| &e.secret[..]).collect()
    }
}

impl Seeds for Migration {
    fn seeds(&self) -> Vec<&[u8]> {
        self.entries.seeds()
    }
}

impl Seeds for OtpAuth {
    fn seeds(&self) -> Vec<&[u8]> {
        vec![&self.secret[..]]
    }
}

/// First 8 bytes of SHA-256 over the length-prefixed seeds, as hex. Enough
/// to catch any change; never enough to recover a seed.
fn fingerprint(seeds: &[&[u8]]) -> String {
    let mut buf = Vec::new();
    for s in seeds {
        buf.extend((s.len() as u32).to_be_bytes());
        buf.extend(*s);
    }
    keyroost_proto::sha256::sha256(&buf)[..8]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// Render a parse result: `Ok` as the `Debug` of the value plus its seed
/// fingerprint, `Err` as the error's `Display` text, prefixed so the two
/// can't be confused.
fn render<T: std::fmt::Debug + Seeds, E: std::fmt::Display>(r: Result<T, E>) -> String {
    match r {
        Ok(v) => format!("Ok {:?} seeds={}", v, fingerprint(&v.seeds())),
        Err(e) => format!("Err {}", e),
    }
}

/// Fail with every mismatch at once (the actual value printed in full), so a
/// behavior change shows its whole footprint rather than the first case.
fn assert_no_mismatches(mismatches: &[String]) {
    assert!(mismatches.is_empty(), "\n{}", mismatches.join("\n"));
}

// ---- Aegis ---------------------------------------------------------------

const AEGIS_TOTP: &str = r#"{"type":"totp","name":"alice@example.com","issuer":"GitHub","info":{"secret":"JBSWY3DPEHPK3PXP","algo":"SHA1","digits":6,"period":30}}"#;
const AEGIS_HOTP: &str = r#"{"type":"hotp","name":"counter","issuer":"Bank","info":{"secret":"JBSWY3DPEHPK3PXP","algo":"SHA1","digits":6,"counter":5}}"#;
const AEGIS_STEAM: &str = r#"{"type":"steam","name":"gamer","issuer":"Steam","info":{"secret":"JBSWY3DPEHPK3PXP","algo":"SHA1","digits":5,"period":30}}"#;
const AEGIS_DIGITS7: &str = r#"{"type":"totp","name":"seven","issuer":"Odd","info":{"secret":"JBSWY3DPEHPK3PXP","algo":"SHA1","digits":7,"period":30}}"#;
const AEGIS_PERIOD45: &str = r#"{"type":"totp","name":"slow","issuer":"Slow","info":{"secret":"JBSWY3DPEHPK3PXP","algo":"SHA1","digits":6,"period":45}}"#;
const AEGIS_SHA512: &str = r#"{"type":"totp","name":"wide","issuer":"Wide","info":{"secret":"JBSWY3DPEHPK3PXP","algo":"SHA512","digits":6,"period":30}}"#;
const AEGIS_BAD_B32: &str = r#"{"type":"totp","name":"bad","issuer":"Bad","info":{"secret":"NOT_BASE32!!","algo":"SHA1","digits":6,"period":30}}"#;
// 103 base32 'A's decode to 64 bytes: one past the Molto2's 63-byte cap.
const AEGIS_SECRET64: &str = r#"{"type":"totp","name":"long","issuer":"Long","info":{"secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","algo":"SHA1","digits":6,"period":30}}"#;
const AEGIS_EMPTY_ISSUER: &str = r#"{"type":"totp","name":"bob","issuer":"","info":{"secret":"JBSWY3DPEHPK3PXP","algo":"SHA256","digits":8,"period":60}}"#;

// A repeated `counter` key: ignored by the Molto2 path, which never reads it.
const AEGIS_DUP_COUNTER: &str = r#"{"type":"totp","name":"dup","issuer":"Dup","info":{"secret":"JBSWY3DPEHPK3PXP","algo":"SHA1","digits":6,"period":30,"counter":1,"counter":2}}"#;

fn aegis_doc(entries: &[&str]) -> String {
    format!(
        r#"{{"version":1,"header":{{"slots":null,"params":null}},"db":{{"version":2,"entries":[{}]}}}}"#,
        entries.join(",")
    )
}

/// The full corpus, in this order. The first entry the Molto2 path can't
/// take aborts the whole file (digits 7, at index 3).
fn aegis_corpus() -> String {
    aegis_doc(&[
        AEGIS_TOTP,
        AEGIS_HOTP,
        AEGIS_STEAM,
        AEGIS_DIGITS7,
        AEGIS_PERIOD45,
        AEGIS_SHA512,
        AEGIS_BAD_B32,
        AEGIS_SECRET64,
        AEGIS_EMPTY_ISSUER,
    ])
}

#[test]
fn aegis_golden() {
    let cases: &[(String, &str)] = &[
        (
            aegis_corpus(),
            r#"Err entry #3: digits=7 not supported by Molto2 (4, 6, 8, or 10)"#,
        ),
        (
            aegis_doc(&[AEGIS_TOTP]),
            r#"Ok [BulkEntry { issuer: Some("GitHub"), account: Some("alice@example.com"), secret: [10 bytes], algorithm: Sha1, digits: Six, time_step: Seconds30 }] seeds=28a80c694c646832"#,
        ),
        (aegis_doc(&[AEGIS_HOTP]), r#"Err no entries found"#),
        (aegis_doc(&[AEGIS_STEAM]), r#"Err no entries found"#),
        (
            aegis_doc(&[AEGIS_DIGITS7]),
            r#"Err entry #0: digits=7 not supported by Molto2 (4, 6, 8, or 10)"#,
        ),
        (
            aegis_doc(&[AEGIS_TOTP, AEGIS_HOTP, AEGIS_DIGITS7]),
            r#"Err entry #2: digits=7 not supported by Molto2 (4, 6, 8, or 10)"#,
        ),
        (
            aegis_doc(&[AEGIS_PERIOD45]),
            r#"Err entry #0: period=45s not supported by Molto2 (30 or 60)"#,
        ),
        (
            aegis_doc(&[AEGIS_SHA512]),
            r#"Err entry #0: algorithm "SHA512" not supported by Molto2 (SHA1 or SHA256 only)"#,
        ),
        (
            aegis_doc(&[AEGIS_BAD_B32]),
            r#"Err entry #0: `secret` is not valid base32"#,
        ),
        (
            aegis_doc(&[AEGIS_SECRET64]),
            r#"Err entry #0: `secret` is not valid base32"#,
        ),
        (
            aegis_doc(&[AEGIS_EMPTY_ISSUER]),
            r#"Ok [BulkEntry { issuer: None, account: Some("bob"), secret: [10 bytes], algorithm: Sha256, digits: Eight, time_step: Seconds60 }] seeds=28a80c694c646832"#,
        ),
        (
            aegis_doc(&[AEGIS_TOTP, AEGIS_HOTP, AEGIS_STEAM, AEGIS_EMPTY_ISSUER]),
            r#"Ok [BulkEntry { issuer: Some("GitHub"), account: Some("alice@example.com"), secret: [10 bytes], algorithm: Sha1, digits: Six, time_step: Seconds30 }, BulkEntry { issuer: None, account: Some("bob"), secret: [10 bytes], algorithm: Sha256, digits: Eight, time_step: Seconds60 }] seeds=e9c6ce20dfd4da62"#,
        ),
        (
            aegis_doc(&[AEGIS_DUP_COUNTER]),
            r#"Ok [BulkEntry { issuer: Some("Dup"), account: Some("dup"), secret: [10 bytes], algorithm: Sha1, digits: Six, time_step: Seconds30 }] seeds=28a80c694c646832"#,
        ),
        (
            r#"{"db":"ZW5jcnlwdGVk","header":{}}"#.to_owned(),
            r#"Err encrypted vault: Aegis export is encrypted; supply a password (CLI: --file-password env:NAME or --file-password stdin)"#,
        ),
    ];
    let mut mismatches = Vec::new();
    for (json, want) in cases {
        let got = render(aegis::parse(json));
        if got != *want {
            mismatches.push(format!("aegis::parse({json}) -> {got:?}"));
        }
    }
    assert_no_mismatches(&mismatches);
}

// ---- 2FAS ----------------------------------------------------------------

const TWOFAS_PLAIN: &str = r#"{"services":[{"name":"Stripe","secret":"JBSWY3DPEHPK3PXP","otp":{"account":"ops@example.com","issuer":"Stripe","digits":8,"period":60,"algorithm":"SHA256","tokenType":"TOTP"}},{"name":"NoIssuer","secret":"JBSWY3DPEHPK3PXP","otp":{"account":"me"}}]}"#;
const TWOFAS_ENCRYPTED: &str = r#"{"servicesEncrypted":"c2VjcmV0","services":[]}"#;
const TWOFAS_HOTP: &str = r#"{"services":[{"name":"Bank","secret":"JBSWY3DPEHPK3PXP","otp":{"account":"me","issuer":"Bank","digits":6,"counter":3,"algorithm":"SHA1","tokenType":"HOTP"}}]}"#;
const TWOFAS_DUP_COUNTER: &str = r#"{"services":[{"name":"Dup","secret":"JBSWY3DPEHPK3PXP","otp":{"account":"me","counter":1,"counter":2,"tokenType":"TOTP"}}]}"#;
const TWOFAS_MIXED: &str = r#"{"services":[{"name":"Bank","secret":"JBSWY3DPEHPK3PXP","otp":{"account":"me","issuer":"Bank","counter":3,"tokenType":"HOTP"}},{"name":"Mail","secret":"JBSWY3DPEHPK3PXP","otp":{"account":"you","tokenType":"TOTP"}}]}"#;

#[test]
fn twofas_golden() {
    let cases: &[(&str, &str)] = &[
        (
            TWOFAS_PLAIN,
            r#"Ok [BulkEntry { issuer: Some("Stripe"), account: Some("ops@example.com"), secret: [10 bytes], algorithm: Sha256, digits: Eight, time_step: Seconds60 }, BulkEntry { issuer: Some("NoIssuer"), account: Some("me"), secret: [10 bytes], algorithm: Sha1, digits: Six, time_step: Seconds30 }] seeds=e9c6ce20dfd4da62"#,
        ),
        (
            TWOFAS_ENCRYPTED,
            r#"Err encrypted vault: 2FAS export is encrypted; re-export without a password"#,
        ),
        (TWOFAS_HOTP, r#"Err no entries found"#),
        (
            TWOFAS_MIXED,
            r#"Ok [BulkEntry { issuer: Some("Mail"), account: Some("you"), secret: [10 bytes], algorithm: Sha1, digits: Six, time_step: Seconds30 }] seeds=28a80c694c646832"#,
        ),
        (
            TWOFAS_DUP_COUNTER,
            r#"Ok [BulkEntry { issuer: Some("Dup"), account: Some("me"), secret: [10 bytes], algorithm: Sha1, digits: Six, time_step: Seconds30 }] seeds=28a80c694c646832"#,
        ),
    ];
    let mut mismatches = Vec::new();
    for (json, want) in cases {
        let got = render(twofas::parse(json));
        if got != *want {
            mismatches.push(format!("twofas::parse({json}) -> {got:?}"));
        }
    }
    assert_no_mismatches(&mismatches);
}

// ---- otpauth list ----------------------------------------------------------

const LIST_OK: &str = "# exported list\n\notpauth://totp/GitHub:me@example.com?secret=JBSWY3DPEHPK3PXP\n   \n  # indented comment\notpauth://totp/GitLab?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60\n";
const LIST_HOTP: &str = "# one HOTP line\notpauth://totp/A?secret=JBSWY3DPEHPK3PXP\notpauth://hotp/B?secret=JBSWY3DPEHPK3PXP&counter=2\n";
const LIST_PERIOD45: &str =
    "\n# blank line above\n\notpauth://totp/Slow?secret=JBSWY3DPEHPK3PXP&period=45\n";
const LIST_MIGRATION: &str = "otpauth-migration://offline?data=CgA%3D\n";

#[test]
fn otpauth_list_golden() {
    let cases: &[(&str, &str)] = &[
        (
            LIST_OK,
            r#"Ok [BulkEntry { issuer: Some("GitHub"), account: Some("me@example.com"), secret: [10 bytes], algorithm: Sha1, digits: Six, time_step: Seconds30 }, BulkEntry { issuer: None, account: Some("GitLab"), secret: [10 bytes], algorithm: Sha256, digits: Eight, time_step: Seconds60 }] seeds=e9c6ce20dfd4da62"#,
        ),
        (
            LIST_HOTP,
            r#"Err entry #2: unsupported OTP type "hotp" (only totp is supported)"#,
        ),
        (
            LIST_PERIOD45,
            r#"Err entry #3: period=45s not supported by Molto2 (30 or 60)"#,
        ),
        (LIST_MIGRATION, r#"Err entry #0: not an otpauth:// URI"#),
        ("# only a comment\n\n", r#"Err no entries found"#),
    ];
    let mut mismatches = Vec::new();
    for (text, want) in cases {
        let got = render(parse_otpauth_list(text));
        if got != *want {
            mismatches.push(format!("parse_otpauth_list({text:?}) -> {got:?}"));
        }
    }
    assert_no_mismatches(&mismatches);
}

// ---- parse_any -------------------------------------------------------------

#[test]
fn parse_any_golden() {
    let cases: &[(String, &str)] = &[
        (
            aegis_doc(&[AEGIS_TOTP, AEGIS_HOTP]),
            r#"Ok [BulkEntry { issuer: Some("GitHub"), account: Some("alice@example.com"), secret: [10 bytes], algorithm: Sha1, digits: Six, time_step: Seconds30 }] seeds=28a80c694c646832"#,
        ),
        (aegis_corpus(), r#"Err no entries found"#),
        (
            TWOFAS_PLAIN.to_owned(),
            r#"Ok [BulkEntry { issuer: Some("Stripe"), account: Some("ops@example.com"), secret: [10 bytes], algorithm: Sha256, digits: Eight, time_step: Seconds60 }, BulkEntry { issuer: Some("NoIssuer"), account: Some("me"), secret: [10 bytes], algorithm: Sha1, digits: Six, time_step: Seconds30 }] seeds=e9c6ce20dfd4da62"#,
        ),
        (
            TWOFAS_ENCRYPTED.to_owned(),
            r#"Err encrypted vault: 2FAS export is encrypted; re-export without a password"#,
        ),
        (TWOFAS_HOTP.to_owned(), r#"Err no entries found"#),
        (
            r#"{"db":"ZW5jcnlwdGVk","header":{}}"#.to_owned(),
            r#"Err encrypted vault: Aegis export is encrypted; supply a password (CLI: --file-password env:NAME or --file-password stdin)"#,
        ),
        (r#"{"neither":true}"#.to_owned(), r#"Err no entries found"#),
        (
            LIST_OK.to_owned(),
            r#"Ok [BulkEntry { issuer: Some("GitHub"), account: Some("me@example.com"), secret: [10 bytes], algorithm: Sha1, digits: Six, time_step: Seconds30 }, BulkEntry { issuer: None, account: Some("GitLab"), secret: [10 bytes], algorithm: Sha256, digits: Eight, time_step: Seconds60 }] seeds=e9c6ce20dfd4da62"#,
        ),
        (
            LIST_PERIOD45.to_owned(),
            r#"Err entry #3: period=45s not supported by Molto2 (30 or 60)"#,
        ),
    ];
    let mut mismatches = Vec::new();
    for (text, want) in cases {
        let got = render(parse_bulk_any(text));
        if got != *want {
            mismatches.push(format!("parse_any({text:?}) -> {got:?}"));
        }
    }
    assert_no_mismatches(&mismatches);
}

// ---- Google Authenticator migration payload -------------------------------

/// One `OtpParameters` message, built field by field.
fn otp_params(
    secret: &[u8],
    name: &str,
    issuer: &str,
    algo: u8,
    digits: u8,
    typ: u8,
    counter: u8,
) -> Vec<u8> {
    let mut m = vec![0x0a, secret.len() as u8];
    m.extend(secret);
    m.extend([0x12, name.len() as u8]);
    m.extend(name.as_bytes());
    m.extend([0x1a, issuer.len() as u8]);
    m.extend(issuer.as_bytes());
    m.extend([0x20, algo, 0x28, digits, 0x30, typ, 0x38, counter]);
    m
}

fn payload(params: &[Vec<u8>], batch: Option<(u8, u8)>) -> Vec<u8> {
    let mut p = Vec::new();
    for m in params {
        p.extend([0x0a, m.len() as u8]);
        p.extend(m);
    }
    p.extend([0x10, 1]);
    if let Some((index, size)) = batch {
        p.extend([0x18, size, 0x20, index]);
    }
    p
}

/// TOTP, HOTP (counter 7), SHA-512, 8 digits, MD5 and a 64-byte secret.
fn migration_corpus() -> Vec<u8> {
    payload(
        &[
            otp_params(b"0123456789", "Acme:alice", "Acme", 1, 1, 2, 0),
            otp_params(b"counterkey", "Legacy", "", 1, 1, 1, 7),
            otp_params(b"0123456789", "wide", "Wide", 3, 1, 2, 0),
            otp_params(b"0123456789", "Eight:bob", "", 2, 2, 2, 0),
            otp_params(b"0123456789", "old", "Old", 4, 1, 2, 0),
            otp_params(&[0x41; 64], "long", "", 1, 1, 2, 0),
        ],
        Some((1, 3)),
    )
}

#[test]
fn migration_golden() {
    let cases: &[(Vec<u8>, &str)] = &[
        (
            migration_corpus(),
            r#"Ok Migration { entries: [BulkEntry { issuer: Some("Acme"), account: Some("alice"), secret: [10 bytes], algorithm: Sha1, digits: Six, time_step: Seconds30 }, BulkEntry { issuer: Some("Eight"), account: Some("bob"), secret: [10 bytes], algorithm: Sha256, digits: Eight, time_step: Seconds30 }], skipped: [Skipped { label: "Legacy", reason: "HOTP is not supported by the Molto2" }, Skipped { label: "Wide:wide", reason: "only SHA-1 / SHA-256 are supported" }, Skipped { label: "Old:old", reason: "only SHA-1 / SHA-256 are supported" }, Skipped { label: "long", reason: "secret must be 1..=63 bytes" }], batch: Some((1, 3)) } seeds=706a029dcd81bd50"#,
        ),
        (
            payload(&[otp_params(b"counterkey", "Legacy", "", 1, 1, 1, 7)], None),
            r#"Ok Migration { entries: [], skipped: [Skipped { label: "Legacy", reason: "HOTP is not supported by the Molto2" }], batch: None } seeds=e3b0c44298fc1c14"#,
        ),
        (
            payload(&[], None),
            r#"Err unsupported format: migration payload contains no accounts"#,
        ),
        (
            vec![0x0a, 0xff],
            r#"Err unsupported format: malformed migration protobuf"#,
        ),
    ];
    let mut mismatches = Vec::new();
    for (buf, want) in cases {
        let got = render(migration::parse_payload(buf));
        if got != *want {
            mismatches.push(format!("parse_payload({buf:02x?}) -> {got:?}"));
        }
    }
    assert_no_mismatches(&mismatches);
}

// ---- otpauth:// ------------------------------------------------------------

/// Single URIs and what `otpauth::parse` returns for each.
#[rustfmt::skip]
const OTPAUTH_CASES: &[(&str, &str)] = &[
        ("otpauth://totp/Acme:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Acme+Co&algorithm=SHA256&digits=8&period=60", r#"Ok OtpAuth { issuer: Some("Acme Co"), account: Some("alice@example.com"), secret: [10 bytes], algorithm: Sha256, digits: Eight, time_step: Seconds60 } seeds=28a80c694c646832"#),
        ("otpauth://totp/plain?secret=JBSWY3DPEHPK3PXP", r#"Ok OtpAuth { issuer: None, account: Some("plain"), secret: [10 bytes], algorithm: Sha1, digits: Six, time_step: Seconds30 } seeds=28a80c694c646832"#),
        ("otpauth://totp/:?secret=JBSWY3DPEHPK3PXP&issuer=", r#"Ok OtpAuth { issuer: None, account: None, secret: [10 bytes], algorithm: Sha1, digits: Six, time_step: Seconds30 } seeds=28a80c694c646832"#),
        ("otpauth://hotp/X:a?secret=JBSWY3DPEHPK3PXP&counter=5", r#"Err unsupported OTP type "hotp" (only totp is supported)"#),
        ("otpauth://steam/X?secret=JBSWY3DPEHPK3PXP", r#"Err unsupported OTP type "steam" (only totp is supported)"#),
        ("otpauth://totp/X?secret=JBSWY3DPEHPK3PXP&period=45", r#"Err period=45s not supported by Molto2 (30 or 60)"#),
        ("otpauth://totp/X?secret=JBSWY3DPEHPK3PXP&period=0", r#"Err period=0s not supported by Molto2 (30 or 60)"#),
        ("otpauth://totp/X?secret=JBSWY3DPEHPK3PXP&digits=7", r#"Err digits=7 not supported by Molto2 (4, 6, 8, or 10)"#),
        ("otpauth://totp/X?secret=JBSWY3DPEHPK3PXP&digits=x", r#"Err malformed URI: digits"#),
        ("otpauth://totp/X?secret=JBSWY3DPEHPK3PXP&algorithm=SHA512", r#"Err algorithm "SHA512" not supported by Molto2 (SHA1 or SHA256 only)"#),
        ("otpauth://totp/X?secret=JBSWY3DPEHPK3PXP&algorithm=md5", r#"Err algorithm "MD5" not supported by Molto2 (SHA1 or SHA256 only)"#),
        ("otpauth://totp/X?secret=NOT_BASE32!!", r#"Err `secret` is not valid base32"#),
        ("otpauth://totp/X", r#"Err URI is missing the `secret` parameter"#),
        ("otpauth://totp?secret=JBSWY3DPEHPK3PXP", r#"Err malformed URI: missing label"#),
        ("otpauth://totp/%ZZ?secret=JBSWY3DPEHPK3PXP", r#"Err malformed URI: label percent-encoding"#),
        ("otpauth://totp/X?secret=JBSWY3DPEHPK3PXP&&issuer=%ZZ", r#"Err malformed URI: query value percent-encoding"#),
        ("otpauth://totp/X?secret&secret=JBSWY3DPEHPK3PXP", r#"Ok OtpAuth { issuer: None, account: Some("X"), secret: [10 bytes], algorithm: Sha1, digits: Six, time_step: Seconds30 } seeds=28a80c694c646832"#),
        ("otpauth://totp/X?secret=AAAAAAAA&secret=JBSWY3DPEHPK3PXP", r#"Ok OtpAuth { issuer: None, account: Some("X"), secret: [10 bytes], algorithm: Sha1, digits: Six, time_step: Seconds30 } seeds=28a80c694c646832"#),
        ("otpauth://totp/X?secret=JBSWY3DPEHPK3PXP&secret=AAAAAAAA", r#"Ok OtpAuth { issuer: None, account: Some("X"), secret: [5 bytes], algorithm: Sha1, digits: Six, time_step: Seconds30 } seeds=0c66ac2aebbddaf9"#),
        ("otpauth://totp/X?issuer=A+B%20C&secret=JBSWY3DPEHPK3PXP&image=x&counter=zz", r#"Ok OtpAuth { issuer: Some("A B C"), account: Some("X"), secret: [10 bytes], algorithm: Sha1, digits: Six, time_step: Seconds30 } seeds=28a80c694c646832"#),
        ("otpauth://totp/a/b:c?secret=JBSWY3DPEHPK3PXP", r#"Ok OtpAuth { issuer: Some("a/b"), account: Some("c"), secret: [10 bytes], algorithm: Sha1, digits: Six, time_step: Seconds30 } seeds=28a80c694c646832"#),
        ("otpauth://totp/X?algorithm=SHA512&digits=7&secret=JBSWY3DPEHPK3PXP", r#"Err algorithm "SHA512" not supported by Molto2 (SHA1 or SHA256 only)"#),
        ("otpauth://totp/X?digits=7&algorithm=SHA512&secret=JBSWY3DPEHPK3PXP", r#"Err digits=7 not supported by Molto2 (4, 6, 8, or 10)"#),
        ("otpauth://totp/X?secret=JBSWY3DPEHPK3PXP&period=60&period=45", r#"Err period=45s not supported by Molto2 (30 or 60)"#),
        ("otpauth://TOTP/X?SECRET=JBSWY3DPEHPK3PXP", r#"Err URI is missing the `secret` parameter"#),
        ("otpauth://totp/X?secret=jbswy3dpehpk3pxp&issuer=", r#"Ok OtpAuth { issuer: None, account: Some("X"), secret: [10 bytes], algorithm: Sha1, digits: Six, time_step: Seconds30 } seeds=28a80c694c646832"#),
        ("otpauth://totp/X?secret=JBSWY3DPEHPK3PXP#frag", r#"Err `secret` is not valid base32"#),
        ("https://example.com", r#"Err not an otpauth:// URI"#),
];

#[test]
fn otpauth_golden() {
    let mut mismatches = Vec::new();
    for (uri, want) in OTPAUTH_CASES {
        let got = render(otpauth::parse(uri));
        if got != *want {
            mismatches.push(format!("otpauth::parse({uri}) -> {got:?}"));
        }
    }
    assert_no_mismatches(&mismatches);
}

// ---- the import plan's Molto2 rules ----------------------------------------

/// The plan's Molto2 verdict for a one-entry file read by a wide reader:
/// the slot title when it would be written, `None` otherwise.
fn molto_plan_writes(
    file: Result<keyroost_import::ImportFile, keyroost_import::BulkError>,
) -> Option<String> {
    use keyroost_import::plan::{plan, Existing, Store, StoredName, Target, Verdict};
    let file = file.ok()?;
    assert!(file.items.len() <= 1, "{file:?}");
    let target = Target {
        store: Store::Molto2,
        first_slot: 0,
        existing: Existing::default(),
        replace: false,
    };
    let row = plan(&file, &target).rows.into_iter().next()?;
    match (row.verdict, row.name) {
        (Verdict::Add | Verdict::Replace, Some(StoredName::Molto2 { title, .. })) => Some(title),
        _ => None,
    }
}

/// What the Molto2 path writes from a one-entry file: the title, when the
/// narrow parser accepts it and the slot writer has a title for it
/// (untitled entries are skipped at write time).
fn molto_narrow_writes(r: Result<Vec<BulkEntry>, keyroost_import::BulkError>) -> Option<String> {
    match r {
        Ok(v) if v.len() == 1 => Some(v[0].suggested_title()).filter(|t| !t.is_empty()),
        _ => None,
    }
}

#[test]
fn molto_rules_match_narrow_acceptance() {
    let mut mismatches = Vec::new();
    let mut check = |what: &str, narrow: Option<String>, wide: Option<String>| {
        if narrow != wide {
            mismatches.push(format!(
                "{what}: narrow writes {narrow:?}, plan writes {wide:?}"
            ));
        }
    };
    for e in [
        AEGIS_TOTP,
        AEGIS_HOTP,
        AEGIS_STEAM,
        AEGIS_DIGITS7,
        AEGIS_PERIOD45,
        AEGIS_SHA512,
        AEGIS_BAD_B32,
        AEGIS_SECRET64,
        AEGIS_EMPTY_ISSUER,
        AEGIS_DUP_COUNTER,
        // Titles cut at 12 bytes, on a character boundary.
        r#"{"type":"totp","name":"x","issuer":"Ünïcödé Company","info":{"secret":"JBSWY3DPEHPK3PXP"}}"#,
        r#"{"type":"totp","name":"alice@example.com","issuer":"","info":{"secret":"JBSWY3DPEHPK3PXP"}}"#,
    ] {
        let doc = aegis_doc(&[e]);
        check(
            e,
            molto_narrow_writes(aegis::parse(&doc)),
            molto_plan_writes(aegis::parse_wide(&doc)),
        );
    }
    // Each 2FAS service of the golden corpus, one per file.
    for svc in [
        r#"{"name":"Stripe","secret":"JBSWY3DPEHPK3PXP","otp":{"account":"ops@example.com","issuer":"Stripe","digits":8,"period":60,"algorithm":"SHA256","tokenType":"TOTP"}}"#,
        r#"{"name":"NoIssuer","secret":"JBSWY3DPEHPK3PXP","otp":{"account":"me"}}"#,
        r#"{"name":"Bank","secret":"JBSWY3DPEHPK3PXP","otp":{"account":"me","issuer":"Bank","digits":6,"counter":3,"algorithm":"SHA1","tokenType":"HOTP"}}"#,
        r#"{"name":"Dup","secret":"JBSWY3DPEHPK3PXP","otp":{"account":"me","counter":1,"counter":2,"tokenType":"TOTP"}}"#,
        r#"{"name":"Mail","secret":"JBSWY3DPEHPK3PXP","otp":{"account":"you","tokenType":"TOTP"}}"#,
    ] {
        let doc = format!(r#"{{"services":[{svc}]}}"#);
        check(
            svc,
            molto_narrow_writes(twofas::parse(&doc)),
            molto_plan_writes(twofas::parse_wide(&doc)),
        );
    }
    // Every URI line of the list corpus and every single-URI case.
    let lines = [LIST_OK, LIST_HOTP, LIST_PERIOD45]
        .iter()
        .flat_map(|t| t.lines())
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .chain(OTPAUTH_CASES.iter().map(|(uri, _)| *uri));
    for line in lines {
        check(
            line,
            molto_narrow_writes(parse_otpauth_list(line)),
            molto_plan_writes(keyroost_import::parse_list_wide(line)),
        );
    }
    assert_no_mismatches(&mismatches);
}
