//! FIDO2 password vault (fidoparole-compatible formats) for keyroost.
//! Pure byte/format layer; no hardware.

mod backup;
mod blob;
mod error;
mod kdf;
mod model;

#[cfg(test)]
pub(crate) mod test_vectors;

pub use backup::{export_backup, import_backup, KdfParams, BACKUP_KDF};
pub use blob::{open, seal};
pub use error::VaultError;
pub use model::{canon_id, from_json, new_id, to_json, Entry, Vault};
