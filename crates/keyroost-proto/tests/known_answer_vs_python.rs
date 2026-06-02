//! Known-answer tests pinned to the Python `gmssl` reference, using the same
//! algorithm Token2's molto2.py performs. Cross-checks that this crate emits
//! byte-identical APDU payloads to what the official tool sends.
//!
//! Reference vectors generated with:
//!   key = SHA1(b"TOKEN2MOLTO1-KEY")[..16] = 099250fdb017f442da429ecbbee17f79
//! and a faithful Python reimplementation of the molto2.py algorithm using
//! gmssl.sm4.one_round (see commit history / dev journal for the script).

use keyroost_proto::apdu::{mac, pad_iso7816_minimal};
use keyroost_proto::codec::hex_encode;
use keyroost_proto::commands::{
    answer_challenge, derive_sm4_key, set_seed, set_title, sync_time, DEFAULT_CUSTOMER_KEY,
};
use keyroost_proto::sm4::Sm4;

fn key() -> [u8; 16] {
    derive_sm4_key(DEFAULT_CUSTOMER_KEY)
}

#[test]
fn set_seed_matches_python_reference() {
    // seed = 20 zero bytes -> pads to 32 (one 0x80 + 11x 0x00).
    let seed = [0u8; 20];
    let cmd = set_seed(&key(), 7, &seed);
    // The APDU body excluding the header is: 32 bytes ciphertext + 4 bytes MAC.
    let body = &cmd.apdu[5..];
    assert_eq!(body.len(), 36);
    let enc = hex_encode(&body[..32]);
    let mac_bytes = hex_encode(&body[32..]);
    assert_eq!(
        enc,
        "14cc24b0cc984da7612c0799d350e38c2c6ddd4f3d6531076ed6b99875607d58"
    );
    assert_eq!(mac_bytes, "cc52b85c");
    // Full header should be 84 C5 01 07 24
    assert_eq!(&cmd.apdu[..5], &[0x84, 0xC5, 0x01, 0x07, 0x24]);
}

#[test]
fn sync_time_matches_python_reference() {
    let cmd = sync_time(&key(), 0, 0x6612_3456);
    let body = &cmd.apdu[5..];
    // 8-byte TLV "81 06 0F 04 66 12 34 56" + 4-byte MAC
    let tlv_hex = hex_encode(&body[..8]);
    let mac_hex = hex_encode(&body[8..]);
    assert_eq!(tlv_hex, "81060f0466123456");
    assert_eq!(mac_hex, "42304790");
    assert_eq!(&cmd.apdu[..5], &[0x84, 0xD4, 0x01, 0x00, 0x0C]);
}

#[test]
fn set_title_matches_python_reference() {
    let cmd = set_title(&key(), 3, "hello");
    let body = &cmd.apdu[5..];
    // 16-byte ciphertext + 4-byte MAC.
    assert_eq!(body.len(), 20);
    let enc_hex = hex_encode(&body[..16]);
    let mac_hex = hex_encode(&body[16..]);
    assert_eq!(enc_hex, "aa6492e824df9e2be60917d1226ae896");
    assert_eq!(mac_hex, "5af94611");
    assert_eq!(&cmd.apdu[..5], &[0x84, 0xD5, 0x00, 0x03, 0x14]);
}

#[test]
fn answer_challenge_matches_python_reference() {
    // Challenge bytes 11..88 are zero-padded to 16 and SM4-encrypted in-place.
    let chal = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let cmd = answer_challenge(&key(), &chal);
    let ct_hex = hex_encode(&cmd.apdu[5..]);
    assert_eq!(ct_hex, "550ec1328f963eb02972bb141e1cf521");
}

/// Sanity-check the MAC primitive directly: confirm that the same Python
/// CBC-with-pad-minimal-then-truncate algorithm produces our values.
#[test]
fn mac_primitive_matches_python_reference() {
    // Recompute the set_seed case piece-by-piece without going through commands.
    let key = key();
    let padded = pad_iso7816_minimal(&[0u8; 20]);
    let mut enc = padded.clone();
    Sm4::new(&key).encrypt_ecb(&mut enc);
    let header = [0x80, 0xC5, 0x01, 0x07, enc.len() as u8];
    let m = mac(&key, &header, &enc);
    assert_eq!(hex_encode(&m), "cc52b85c");
}
