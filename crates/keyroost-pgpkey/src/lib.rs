//! Host-side OpenPGP key sets for keyroost: key generation, GnuPG-compatible
//! secret-key backups, restore onto a card, and expiry changes.
//!
//! - [`cert`]: make a key set ([`cert::create`]), write its backup, public
//!   key and revocation certificate ([`cert::export`]), and change its
//!   expiry date.
//! - [`read`]: read backups and GnuPG secret exports back
//!   ([`read::open`]), and public keys ([`read::open_public`]).
//! - [`files`]: the file names and never-overwrite writes.
//! - `card` (feature `card`): load a key set onto an OpenPGP card, and
//!   sign with the card.
//!
//! The byte layer (packets, MPIs, S2K, signature encoding) stays inside
//! the crate.

use std::fmt;

pub mod armor;
#[cfg(feature = "card")]
pub mod card;
pub mod cert;
pub mod files;
pub mod keys;
pub(crate) mod packet;
pub mod read;
pub(crate) mod s2k;
pub mod sig;

/// Everything this crate can report. The `Display` text is written for end
/// users, one line each.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The input ended before a complete value was read.
    Truncated,
    /// The input is not valid OpenPGP data.
    Malformed(&'static str),
    /// Valid OpenPGP, but a form this tool does not handle.
    Unsupported(&'static str),
    /// A checksum (armor CRC or secret-key checksum) did not match.
    BadChecksum,
    /// The passphrase did not unlock the secret key.
    WrongPassphrase,
    /// The secret key is protected and no passphrase was given.
    NeedsPassphrase,
    /// The file holds GnuPG card stubs, not key material.
    CardStubs,
    /// The secret part of a key was left out of the file (GnuPG's
    /// `gnu-dummy`, as written by `gpg --export-secret-subkeys`).
    NoSecretPart,
    /// The file holds a public key only, not a backup.
    PublicOnly,
    /// The operation cannot be done with what was given; the text says
    /// why and what to do instead.
    Refused(&'static str),
    /// A cryptographic operation failed.
    Crypto(String),
    /// A file operation failed.
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Truncated => write!(f, "The key data ends too early; the file looks cut off."),
            Error::Malformed(what) => write!(f, "The key data is not valid OpenPGP ({what})."),
            Error::Unsupported(what) => {
                write!(f, "This key uses something not supported here ({what}).")
            }
            Error::BadChecksum => write!(f, "The key data is damaged (checksum mismatch)."),
            Error::WrongPassphrase => write!(f, "The passphrase is wrong."),
            Error::NeedsPassphrase => write!(f, "This backup needs its passphrase."),
            Error::CardStubs => write!(
                f,
                "This file holds placeholders for keys on a smart card, not the keys themselves."
            ),
            Error::NoSecretPart => write!(
                f,
                "This file has no secret part for this key (it was exported without it)."
            ),
            Error::PublicOnly => write!(
                f,
                "This file holds only a public key; restoring needs the backup with the secret keys."
            ),
            Error::Refused(why) => write!(f, "{why}"),
            Error::Crypto(msg) => write!(f, "Cryptographic error: {msg}"),
            Error::Io(e) => write!(f, "File error: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}
