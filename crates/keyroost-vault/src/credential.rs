//! The FIDO2 credential a vault lives under: its relying party, the
//! hmac-secret input, and the user handle that carries the vault's name.

use crate::error::VaultError;

/// The relying party ID every vault credential is created under.
pub const RP_ID: &str = "fido2-vault.token2";

/// The relying party name sent with makeCredential.
pub const RP_NAME: &str = "FidoParole";

/// The application input to the hmac-secret salt, mapped the way WebAuthn
/// PRF does: salt = SHA-256("WebAuthn PRF" || 0x00 || `PRF_INPUT`).
pub const PRF_INPUT: &[u8] = b"Token2 fido2-vault v1 / hmac-secret salt";

/// The longest vault name, in bytes of UTF-8.
pub const MAX_NAME_BYTES: usize = 32;

/// The user handle (`user.id`) of a new vault credential: a `0x01` tag,
/// 8 random bytes, then the vault's name in UTF-8. The random bytes keep two
/// vaults of the same name apart on the key.
///
/// The name must be 1 to [`MAX_NAME_BYTES`] bytes ([`VaultError::NameLength`]
/// otherwise); a failed system random source is [`VaultError::Random`].
pub fn user_handle(name: &str) -> Result<Vec<u8>, VaultError> {
    if name.is_empty() || name.len() > MAX_NAME_BYTES {
        return Err(VaultError::NameLength);
    }
    let mut random = [0u8; 8];
    getrandom::fill(&mut random).map_err(|_| VaultError::Random)?;
    let mut handle = Vec::with_capacity(1 + random.len() + name.len());
    handle.push(0x01);
    handle.extend_from_slice(&random);
    handle.extend_from_slice(name.as_bytes());
    Ok(handle)
}

/// The user handle of a vault credential with no name: the `0x01` tag and
/// 8 random bytes, as [`user_handle`] makes them, with no name after. A
/// vault that had none keeps none when its key is rotated. A failed system
/// random source is [`VaultError::Random`].
pub fn unnamed_user_handle() -> Result<Vec<u8>, VaultError> {
    let mut handle = vec![0x01; 1 + 8];
    getrandom::fill(&mut handle[1..]).map_err(|_| VaultError::Random)?;
    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_vectors::PRF_SALT_HEX;
    use sha2::{Digest, Sha256};

    #[test]
    fn prf_input_matches_the_salt_vector() {
        // WebAuthn PRF: SHA-256("WebAuthn PRF" || 0x00 || input).
        let mut h = Sha256::new();
        h.update(b"WebAuthn PRF\x00");
        h.update(PRF_INPUT);
        let hex: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, PRF_SALT_HEX);
    }

    #[test]
    fn user_handle_layout() {
        let h = user_handle("Mail").unwrap();
        assert_eq!(h.len(), 1 + 8 + 4);
        assert_eq!(h[0], 0x01);
        assert_eq!(&h[9..], b"Mail");
        // The 8 middle bytes are fresh each time.
        assert_ne!(user_handle("Mail").unwrap()[1..9], h[1..9]);
    }

    #[test]
    fn unnamed_user_handle_layout() {
        let h = unnamed_user_handle().unwrap();
        assert_eq!(h.len(), 1 + 8);
        assert_eq!(h[0], 0x01);
        assert_ne!(unnamed_user_handle().unwrap()[1..], h[1..]);
    }

    #[test]
    fn user_handle_counts_bytes_not_characters() {
        let max = "x".repeat(MAX_NAME_BYTES);
        assert_eq!(user_handle(&max).unwrap().len(), 9 + MAX_NAME_BYTES);
        // 16 two-byte characters fill the 32 bytes; one more does not fit.
        assert!(user_handle(&"é".repeat(16)).is_ok());
        for bad in ["", &"é".repeat(17), &"x".repeat(MAX_NAME_BYTES + 1)] {
            assert_eq!(user_handle(bad).unwrap_err(), VaultError::NameLength);
        }
    }
}
