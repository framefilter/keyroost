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
use zeroize::{Zeroize, Zeroizing};

use crate::bulk::BulkError;

/// Caps on attacker-controlled scrypt parameters. The vault file dictates
/// n/r/p and the KDF must run before a wrong password can be detected, so
/// without these an adversarial "backup" can demand terabytes of memory or
/// hours of CPU per slot. Aegis itself uses n=2^15, r=8, p=1; the caps leave
/// generous headroom above that while bounding scrypt memory (128*n*r) at
/// 256 MiB.
const SCRYPT_MAX_N: u64 = 1 << 22;
const SCRYPT_MAX_R: u32 = 64;
const SCRYPT_MAX_P: u32 = 8;
const SCRYPT_MAX_MEM_BYTES: u64 = 256 * 1024 * 1024;
/// A vault only needs a handful of password slots; trying every slot in an
/// adversarial file multiplies the KDF cost arbitrarily.
const MAX_PASSWORD_SLOTS: usize = 8;

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
    keyroost_proto::codec::hex_decode(s).map_err(|_| BulkError::UnsupportedFormat(label))
}

/// Decrypt the vault and return the plaintext db JSON. The returned buffer
/// (every imported seed, in clear) wipes itself on drop; key material
/// derived along the way is wiped before this returns.
pub fn decrypt_aegis(json: &str, password: &[u8]) -> Result<Zeroizing<String>, BulkError> {
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
    for slot in password_slots.into_iter().take(MAX_PASSWORD_SLOTS) {
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
) -> Result<Zeroizing<String>, BulkError> {
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

    if !n.is_power_of_two() || n < 2 {
        return Err(BulkError::UnsupportedFormat(
            "slot n is not a valid power of 2",
        ));
    }
    if n > SCRYPT_MAX_N
        || r > SCRYPT_MAX_R
        || p > SCRYPT_MAX_P
        || 128 * n * u64::from(r) > SCRYPT_MAX_MEM_BYTES
    {
        return Err(BulkError::UnsupportedFormat(
            "slot scrypt parameters exceed sanity caps",
        ));
    }
    // scrypt's `log_n` parameter is log2 of N.
    let log_n = n.trailing_zeros() as u8;
    let params = scrypt::Params::new(log_n, r, p, 32)
        .map_err(|_| BulkError::UnsupportedFormat("invalid scrypt params"))?;

    // KEK and master key are wiped on every exit path, including the `?`s
    // between their derivation and last use.
    let mut kek = Zeroizing::new([0u8; 32]);
    scrypt(password, &salt, &params, kek.as_mut())
        .map_err(|_| BulkError::UnsupportedFormat("scrypt failed"))?;

    let slot_nonce = hex_decode(&slot.key_params.nonce, "slot nonce")?;
    let slot_tag = hex_decode(&slot.key_params.tag, "slot tag")?;
    let slot_ct = hex_decode(&slot.key, "slot key ciphertext")?;
    let master_key = Zeroizing::new(
        gcm_decrypt(kek.as_ref(), &slot_nonce, &slot_ct, &slot_tag)
            .map_err(|()| BulkError::UnsupportedFormat("wrong password (slot did not decrypt)"))?,
    );
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

    // from_utf8 moves the buffer on success (no copy); on failure the bytes
    // come back inside the error and are wiped before it propagates.
    let mut inner = Zeroizing::new(String::from_utf8(plaintext).map_err(|e| {
        let mut bytes = e.into_bytes();
        bytes.zeroize();
        BulkError::UnsupportedFormat("decrypted db is not UTF-8")
    })?);

    // Aegis encrypts only the inner database object (the value normally found
    // under "db"), not the outer wrapper. Wrap it back so `aegis::parse` can
    // consume the same shape it gets from plaintext exports. Built with an
    // exact-capacity buffer — `format!` would start small and reallocate
    // *after* the plaintext is in it, stranding an unwipeable copy in freed
    // memory. `inner` (also a full plaintext copy) is wiped by its Zeroizing
    // wrapper.
    let mut wrapped = Zeroizing::new(String::with_capacity(inner.len() + 8));
    wrapped.push_str(r#"{"db":"#);
    wrapped.push_str(&inner);
    wrapped.push('}');
    inner.zeroize();
    Ok(wrapped)
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
