//! FIDO2 password vault (fidoparole-compatible formats) for keyroost.
//! Pure byte/format layer; no hardware.

mod error;
// Not yet called from non-test code; the vault formats that use it land next.
#[allow(dead_code)]
mod kdf;
mod model;

#[cfg(test)]
pub(crate) mod test_vectors;

pub use error::VaultError;
pub use model::{canon_id, from_json, new_id, to_json, Entry, Vault};
