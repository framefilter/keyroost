//! Aegis encrypted-vault decryption.
//!
//! Aegis (https://getaegis.app/) uses a two-stage scheme:
//!   1. A *password slot* records scrypt parameters (n, r, p, salt) and an
//!      AES-256-GCM-encrypted master key (with its own nonce/tag).
//!   2. The vault `db` field is a base64-encoded AES-256-GCM ciphertext of the
//!      plaintext JSON, encrypted with the master key.
//!
//! To decrypt we:
//!   - derive KEK = scrypt(password, salt, n, r, p, len=32)
//!   - decrypt slot.key with AES-GCM(KEK, slot.key_params.nonce, tag)
//!     → master_key (32 bytes)
//!   - decrypt base64(db) with AES-GCM(master_key, header.params.nonce, tag)
//!     → plaintext JSON string
//!
//! Plaintext JSON can then be passed to `aegis::parse()`.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use scrypt::scrypt;
use serde::Deserialize;

use crate::bulk::BulkError;

#[derive(Deserialize)]
struct Root {
    header: Header,
    db: String,
}

#[derive(Deserialize)]
struct Header {
    slots: Vec<Slot>,
    params: AeadParams,
}

#[derive(Deserialize)]
struct Slot {
    #[serde(rename = "type")]
    typ: u32,
    /// hex-encoded ciphertext of the master key
    key: String,
    key_params: AeadParams,
    n: Option<u64>,
    r: Option<u32>,
    p: Option<u32>,
    salt: Option<String>,
}

#[derive(Deserialize)]
struct AeadParams {
    nonce: String,
    tag: String,
}

fn hex_decode(s: &str, label: &'static str) -> Result<Vec<u8>, BulkError> {
    molto2_proto::codec::hex_decode(s).map_err(|_| BulkError::UnsupportedFormat(label))
}

/// Decrypt the vault and return the plaintext db JSON.
pub fn decrypt_aegis(json: &str, password: &[u8]) -> Result<String, BulkError> {
    let root: Root = serde_json::from_str(json)?;

    // Find a password slot (type=1). Try each in order in case the user has
    // multiple — first one that decrypts wins.
    let password_slots: Vec<&Slot> = root.header.slots.iter().filter(|s| s.typ == 1).collect();
    if password_slots.is_empty() {
        return Err(BulkError::UnsupportedFormat(
            "Aegis vault has no password slot (biometric/keystore not supported)",
        ));
    }

    let mut last_err: Option<BulkError> = None;
    for slot in password_slots {
        match try_unlock_slot(slot, password, &root.header.params, &root.db) {
            Ok(plaintext) => return Ok(plaintext),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or(BulkError::UnsupportedFormat("Aegis decrypt failed")))
}

fn try_unlock_slot(
    slot: &Slot,
    password: &[u8],
    db_params: &AeadParams,
    db_b64: &str,
) -> Result<String, BulkError> {
    let salt = hex_decode(
        slot.salt
            .as_deref()
            .ok_or(BulkError::UnsupportedFormat("slot missing salt"))?,
        "slot salt",
    )?;
    let n = slot
        .n
        .ok_or(BulkError::UnsupportedFormat("slot missing n"))?;
    let r = slot
        .r
        .ok_or(BulkError::UnsupportedFormat("slot missing r"))?;
    let p = slot
        .p
        .ok_or(BulkError::UnsupportedFormat("slot missing p"))?;

    // scrypt's `log_n` parameter is log2 of N.
    let log_n = (n as f64).log2();
    if log_n.fract().abs() > 1e-9 || !(1.0..=63.0).contains(&log_n) {
        return Err(BulkError::UnsupportedFormat(
            "slot n is not a valid power of 2",
        ));
    }
    let params = scrypt::Params::new(log_n as u8, r, p, 32)
        .map_err(|_| BulkError::UnsupportedFormat("invalid scrypt params"))?;

    let mut kek = [0u8; 32];
    scrypt(password, &salt, &params, &mut kek)
        .map_err(|_| BulkError::UnsupportedFormat("scrypt failed"))?;

    let slot_nonce = hex_decode(&slot.key_params.nonce, "slot nonce")?;
    let slot_tag = hex_decode(&slot.key_params.tag, "slot tag")?;
    let slot_ct = hex_decode(&slot.key, "slot key ciphertext")?;
    let master_key = gcm_decrypt(&kek, &slot_nonce, &slot_ct, &slot_tag)
        .map_err(|()| BulkError::UnsupportedFormat("wrong password (slot did not decrypt)"))?;
    if master_key.len() != 32 {
        return Err(BulkError::UnsupportedFormat(
            "decrypted master key is not 32 bytes",
        ));
    }

    let db_nonce = hex_decode(&db_params.nonce, "db nonce")?;
    let db_tag = hex_decode(&db_params.tag, "db tag")?;
    let db_ct = B64
        .decode(db_b64.as_bytes())
        .map_err(|_| BulkError::UnsupportedFormat("db is not valid base64"))?;
    let plaintext = gcm_decrypt(&master_key, &db_nonce, &db_ct, &db_tag)
        .map_err(|()| BulkError::UnsupportedFormat("db did not decrypt with master key"))?;

    let inner = String::from_utf8(plaintext)
        .map_err(|_| BulkError::UnsupportedFormat("decrypted db is not UTF-8"))?;

    // Aegis encrypts only the inner database object (the value normally found
    // under "db"), not the outer wrapper. Wrap it back so `aegis::parse` can
    // consume the same shape it gets from plaintext exports.
    Ok(format!(r#"{{"db":{}}}"#, inner))
}

/// AES-256-GCM decrypt with separately-supplied tag (Aegis stores ct and tag
/// in separate fields; aes-gcm wants them concatenated).
fn gcm_decrypt(key: &[u8], nonce: &[u8], ct: &[u8], tag: &[u8]) -> Result<Vec<u8>, ()> {
    if key.len() != 32 {
        return Err(());
    }
    if nonce.len() != 12 {
        return Err(());
    }
    if tag.len() != 16 {
        return Err(());
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ())?;
    let mut buf = Vec::with_capacity(ct.len() + tag.len());
    buf.extend_from_slice(ct);
    buf.extend_from_slice(tag);
    cipher
        .decrypt(
            nonce.into(),
            Payload {
                msg: &buf,
                aad: b"",
            },
        )
        .map_err(|_| ())
}
