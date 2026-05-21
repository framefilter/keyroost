//! Import helpers for Molto2 programming: otpauth:// URI parsing and
//! (with the `bulk` feature) Aegis / 2FAS plaintext JSON parsers.

pub mod otpauth;

pub use otpauth::{parse as parse_otpauth, OtpAuth, OtpAuthError};

#[cfg(feature = "bulk")]
pub mod bulk;
#[cfg(feature = "bulk")]
pub use bulk::{parse_any as parse_bulk_any, parse_otpauth_list, BulkEntry, BulkError};
