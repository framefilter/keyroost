//! Import helpers for Molto2 programming: otpauth:// URI parsing and
//! (with the `bulk` feature) Aegis / 2FAS plaintext JSON parsers.
//! The `encrypted` feature additionally pulls in scrypt + AES-GCM for
//! decrypting password-protected Aegis vaults.
//!
//! Two layers of parsers sit side by side. The narrow ones (`parse`,
//! `aegis::parse`, ...) produce `BulkEntry` values limited to what a Molto2
//! slot stores. The wide ones (`parse_entry`, `aegis::parse_wide`, ...)
//! produce an [`ImportFile`] of every entry in the file — HOTP, any TOTP
//! period, SHA-512 — each marked usable or with the reason it isn't, for
//! keys whose limits are checked later.

pub mod classify;
pub mod entry;
pub mod otpauth;
pub mod plan;
pub mod run;
pub mod text;

pub use entry::{Format, HashAlg, ImportEntry, ImportFile, ImportItem, OtpKind, Unusable};
pub use otpauth::{parse as parse_otpauth, OtpAuth, OtpAuthError};

#[cfg(feature = "bulk")]
pub mod bulk;
#[cfg(feature = "bulk")]
pub use bulk::{
    aegis, parse_any as parse_bulk_any, parse_any_wide, parse_list_wide, parse_otpauth_list,
    twofas, BulkEntry, BulkError,
};

/// Google Authenticator `otpauth-migration://` export parsing. Lives under
/// the `bulk` feature because its output is `BulkEntry` batches; the
/// protobuf wire reader is vendored (~60 lines), no new dependencies.
#[cfg(feature = "bulk")]
pub mod migration;

#[cfg(feature = "encrypted")]
mod encrypted;
