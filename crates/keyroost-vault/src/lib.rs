//! FIDO2 password vault (fidoparole-compatible formats) for keyroost.
//! Pure byte/format layer; no hardware.

// Not yet called from non-test code; the vault formats that use it land next.
#[allow(dead_code)]
mod kdf;

#[cfg(test)]
pub(crate) mod test_vectors;
