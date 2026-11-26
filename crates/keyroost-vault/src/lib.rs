//! FIDO2 password vault (FidoParole-compatible formats) for keyroost.
//! Pure byte/format layer; no hardware.
//!
//! The vault design and its formats (the `T2VLT` key blob, the `T2VBK`
//! backup file, the entry JSON, and the credential's relying party,
//! hmac-secret input and user handle) come from Token2's
//! [FidoParole](https://github.com/token2/fidoparole). Token2 approved their
//! reuse in keyroost in
//! [discussion #74](https://github.com/framefilter/keyroost/discussions/74#discussioncomment-19674707);
//! thank you, Token2. This crate is an independent implementation that reads
//! and writes the same bytes, checked against vectors produced by
//! FidoParole's own code.

mod backup;
mod blob;
mod credential;
mod error;
mod generate;
mod kdf;
mod merge;
mod model;

#[cfg(test)]
pub(crate) mod test_vectors;

pub use backup::{
    backup_file_name, check_passphrase, export_backup, import_backup, KdfParams, BACKUP_KDF,
};
pub use blob::{open, seal};
pub use credential::{unnamed_user_handle, user_handle, MAX_NAME_BYTES, PRF_INPUT, RP_ID, RP_NAME};
pub use error::VaultError;
pub use generate::{generate_password, GenOptions};
pub use merge::{apply_import, classify, ImportStatus};
pub use model::{canon_id, from_json, new_id, to_json, Entry, Vault};
