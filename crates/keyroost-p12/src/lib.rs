//! Host-side PKCS#12 (`.p12` / `.pfx`) reader for PIV key import.
//!
//! The file is untrusted input: every length is checked against the bytes that
//! remain, nesting is bounded, and nothing here panics on malformed data.
//!
//! [`open`] reads a file (legacy RC2/3DES or PBES2/AES, with or without a MAC)
//! into [`Contents`]: one [`Entry`] per private key, each with its
//! [`KeyParts`] (minimal big-endian integers, cleared on drop), the matching
//! certificate if the file has one, and a label; certificates that belong to no
//! key are returned as `authorities`. Choosing among several entries is left to
//! the caller. Key derivation is bounded per derivation and per file, so a
//! hostile file can't stall the caller; under `--cfg fuzzing` (set by
//! cargo-fuzz) both limits are lower.

#![forbid(unsafe_code)]

mod ber;
mod entries;
mod kdf;
mod pbe;
mod pfx;
mod pkcs8;

pub use entries::{open, Contents, Entry};
pub use pbe::TOO_MUCH_WORK;
pub use pkcs8::KeyParts;

use core::fmt;

/// Why a PKCS#12 file could not be read.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq)]
pub enum P12Error {
    /// The bytes are not a well-formed PKCS#12 structure.
    Malformed(&'static str),
    /// The password does not open the file (MAC or padding check failed).
    WrongPassword,
    /// A valid file that uses something this reader does not handle. A file
    /// that asks for more key-derivation work than [`open`] allows in total
    /// carries [`TOO_MUCH_WORK`].
    Unsupported(&'static str),
    /// The file holds no private key.
    NoKey,
    /// The file is over [`MAX_FILE_BYTES`]; [`open`] refuses it unread.
    TooLarge,
}

/// [`MAX_FILE_BYTES`] in MiB, the one place the limit is set.
const MAX_FILE_MIB: usize = 1;

/// The largest file [`open`] reads. A real .p12/.pfx holds a key and a few
/// certificates: kilobytes, not megabytes.
pub const MAX_FILE_BYTES: usize = MAX_FILE_MIB * 1024 * 1024;

/// [`MAX_FILE_BYTES`] for a message: "1 MiB".
#[must_use]
pub fn max_file_size() -> String {
    format!("{MAX_FILE_MIB} MiB")
}

impl fmt::Display for P12Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            P12Error::Malformed(what) => write!(f, "not a valid PKCS#12 file: {what}"),
            P12Error::WrongPassword => write!(f, "wrong password for this PKCS#12 file"),
            P12Error::Unsupported(what) => write!(f, "unsupported PKCS#12 feature: {what}"),
            P12Error::NoKey => write!(f, "the PKCS#12 file contains no private key"),
            P12Error::TooLarge => write!(f, "the file is over {}", max_file_size()),
        }
    }
}

impl std::error::Error for P12Error {}
