//! The error type shared by every vault operation.

use std::fmt;

/// Why a vault operation failed. Messages are plain English for end users.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    /// The data does not start with the vault magic.
    NotAVault,
    /// A blob or backup version this build does not know.
    UnsupportedVersion(u8),
    /// The JSON format number is newer than this build understands.
    NewerFormat(u32),
    /// The data is damaged; the text says which part.
    Corrupt(&'static str),
    /// Authenticated decryption failed (wrong key/passphrase or damaged data).
    Decrypt,
    /// A backup file asks for key-derivation settings beyond the allowed bounds.
    KdfParams,
    /// The backup passphrase is shorter than 10 characters.
    ShortPassphrase,
    /// The data inflates past the size cap.
    TooLarge,
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::NotAVault => f.write_str("the data on this key is not a vault"),
            VaultError::UnsupportedVersion(v) => write!(f, "unsupported vault version {v}"),
            VaultError::NewerFormat(n) => {
                write!(f, "this vault was saved by a newer app (format {n})")
            }
            VaultError::Corrupt(what) => write!(f, "the vault data is damaged: {what}"),
            VaultError::Decrypt => {
                f.write_str("could not decrypt the vault (wrong key or damaged data)")
            }
            VaultError::KdfParams => {
                f.write_str("the backup file asks for unreasonable key-derivation settings")
            }
            VaultError::ShortPassphrase => {
                f.write_str("use a backup passphrase of at least 10 characters")
            }
            VaultError::TooLarge => f.write_str("the vault data is too large"),
        }
    }
}

impl std::error::Error for VaultError {}
