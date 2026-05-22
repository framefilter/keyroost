//! End-to-end test for Aegis encrypted-vault decryption.
//!
//! We synthesize an encrypted vault byte-compatible with what Aegis produces:
//! scrypt-derive a KEK from a known password and salt, AES-GCM-encrypt a
//! 32-byte master key with the KEK, then AES-GCM-encrypt the plaintext db with
//! the master key. Then we ask our decryptor to recover the plaintext and
//! assert it matches.
//!
//! The point is to exercise the format-parsing and key-chaining logic — the
//! underlying scrypt and AES-GCM primitives are tested by their respective
//! upstream crates.

#![cfg(feature = "encrypted")]

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use base64::Engine;
use scrypt::Params;
use serde_json::json;

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for c in b {
        s.push_str(&format!("{:02x}", c));
    }
    s
}

/// Build a synthetic encrypted Aegis vault using fixed, test-only nonces and
/// master key. Intentionally weak scrypt params so the test runs in <1s.
fn make_vault(password: &str, plaintext_db: &str) -> String {
    let log_n: u8 = 12; // Aegis production uses 15; 12 keeps the test fast.
    let r: u32 = 8;
    let p: u32 = 1;
    let salt = b"0123456789abcdef0123456789abcdef";
    let slot_nonce: [u8; 12] = *b"slot-nonce__";
    let db_nonce: [u8; 12] = *b"db-nonce-aaa";
    let master_key: [u8; 32] = *b"master-key-32-bytes-for-aegis-12";

    let params = Params::new(log_n, r, p, 32).unwrap();
    let mut kek = [0u8; 32];
    scrypt::scrypt(password.as_bytes(), salt, &params, &mut kek).unwrap();

    let kek_cipher = Aes256Gcm::new_from_slice(&kek).unwrap();
    let mk_combined = kek_cipher
        .encrypt(
            &slot_nonce.into(),
            Payload {
                msg: &master_key,
                aad: b"",
            },
        )
        .unwrap();
    let (slot_ct, slot_tag) = mk_combined.split_at(mk_combined.len() - 16);

    let db_cipher = Aes256Gcm::new_from_slice(&master_key).unwrap();
    let db_combined = db_cipher
        .encrypt(
            &db_nonce.into(),
            Payload {
                msg: plaintext_db.as_bytes(),
                aad: b"",
            },
        )
        .unwrap();
    let (db_ct, db_tag) = db_combined.split_at(db_combined.len() - 16);

    let vault = json!({
        "version": 1,
        "header": {
            "slots": [{
                "type": 1,
                "uuid": "00000000-0000-0000-0000-000000000000",
                "key": hex(slot_ct),
                "key_params": {
                    "nonce": hex(&slot_nonce),
                    "tag": hex(slot_tag),
                },
                "n": 1u64 << log_n,
                "r": r,
                "p": p,
                "salt": hex(salt),
            }],
            "params": {
                "nonce": hex(&db_nonce),
                "tag": hex(db_tag),
            }
        },
        "db": base64::engine::general_purpose::STANDARD.encode(db_ct),
    });
    serde_json::to_string(&vault).unwrap()
}

#[test]
fn round_trip_decrypts_to_known_plaintext() {
    let plaintext_db = r#"{"entries":[{"type":"totp","name":"alice","issuer":"Acme","info":{"secret":"JBSWY3DPEHPK3PXP","algo":"SHA1","digits":6,"period":30}}]}"#;
    let vault = make_vault("correct horse battery staple", plaintext_db);

    let recovered =
        molto2_import::aegis::decrypt(&vault, b"correct horse battery staple").expect("decrypt");
    // `decrypt` returns the wrapped form so `parse` can consume it directly.
    assert_eq!(recovered, format!(r#"{{"db":{}}}"#, plaintext_db));

    let entries = molto2_import::aegis::parse(&recovered).expect("parse");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].issuer.as_deref(), Some("Acme"));
}

#[test]
fn wrong_password_fails_cleanly() {
    let vault = make_vault("the right one", r#"{"entries":[]}"#);
    let err = molto2_import::aegis::decrypt(&vault, b"the wrong one").unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("wrong password") || msg.contains("did not decrypt"),
        "got: {}",
        msg
    );
}

#[test]
fn is_encrypted_detects_correctly() {
    let plaintext =
        r#"{"version":1,"header":{"slots":[],"params":{"nonce":"","tag":""}},"db":{"entries":[]}}"#;
    let vault = make_vault("p", r#"{"entries":[]}"#);
    assert!(!molto2_import::aegis::is_encrypted(plaintext).unwrap());
    assert!(molto2_import::aegis::is_encrypted(&vault).unwrap());
}
