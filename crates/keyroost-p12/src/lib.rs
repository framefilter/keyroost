//! Host-side PKCS#12 (`.p12` / `.pfx`) reader for PIV key import.
//!
//! The file is untrusted input: every length is checked against the bytes that
//! remain, nesting is bounded, and nothing here panics on malformed data.

#![forbid(unsafe_code)]

// Consumed by the PFX walk in later tasks.
#[allow(dead_code)]
mod ber;

use core::fmt;

/// Why a PKCS#12 file could not be read.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq)]
pub enum P12Error {
    /// The bytes are not a well-formed PKCS#12 structure.
    Malformed(&'static str),
    /// The password does not open the file (MAC or padding check failed).
    WrongPassword,
    /// A valid file that uses something this reader does not handle.
    Unsupported(&'static str),
    /// The file holds no private key.
    NoKey,
    /// The file holds several entries and none was chosen (carries the count).
    SeveralEntries(usize),
    /// The chosen entry number is not in the file (carries the number).
    EntryOutOfRange(usize),
}

impl fmt::Display for P12Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            P12Error::Malformed(what) => write!(f, "not a valid PKCS#12 file: {what}"),
            P12Error::WrongPassword => write!(f, "wrong password for this PKCS#12 file"),
            P12Error::Unsupported(what) => write!(f, "unsupported PKCS#12 feature: {what}"),
            P12Error::NoKey => write!(f, "the PKCS#12 file contains no private key"),
            P12Error::SeveralEntries(n) => {
                write!(f, "the PKCS#12 file has {n} entries; choose one")
            }
            P12Error::EntryOutOfRange(n) => write!(f, "entry {n} is not in the PKCS#12 file"),
        }
    }
}

impl std::error::Error for P12Error {}
