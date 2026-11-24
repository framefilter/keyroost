//! The error type shared by every vault operation.

use std::fmt;

/// Why a vault operation failed. Messages are plain English for end users.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VaultError {
    /// The data does not start with the vault magic.
    NotAVault,
    /// The file does not start with the backup magic.
    NotABackup,
    /// A key-blob or backup-file version this build does not know.
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
    /// The system's random number source failed.
    Random,
    /// A vault name is empty or longer than 32 bytes of UTF-8.
    NameLength,
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::NotAVault => f.write_str("the data on this key is not a vault"),
            VaultError::NotABackup => f.write_str("this is not a vault backup file"),
            VaultError::UnsupportedVersion(v) => write!(
                f,
                "this vault or backup uses version {v} of its file format, which this app cannot read"
            ),
            VaultError::NewerFormat(n) => {
                write!(f, "this vault was saved by a newer app (format {n})")
            }
            VaultError::Corrupt(what) => write!(f, "the vault data is damaged: {what}"),
            VaultError::Decrypt => f.write_str(
                "could not decrypt the vault (wrong key or passphrase, or damaged data)",
            ),
            VaultError::KdfParams => {
                f.write_str("the backup file asks for unreasonable key-derivation settings")
            }
            VaultError::ShortPassphrase => {
                f.write_str("use a backup passphrase of at least 10 characters")
            }
            VaultError::TooLarge => f.write_str("the vault data is too large"),
            VaultError::Random => f.write_str("the system's random number source failed"),
            VaultError::NameLength => f.write_str(
                "a vault name must be 1 to 32 bytes long (accented and non-Latin letters take 2 to 4 bytes each)",
            ),
        }
    }
}

impl std::error::Error for VaultError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_message_fits_blobs_and_backups() {
        // Both the key blob and the backup file report this variant.
        assert_eq!(
            VaultError::UnsupportedVersion(2).to_string(),
            "this vault or backup uses version 2 of its file format, which this app cannot read"
        );
    }
}
