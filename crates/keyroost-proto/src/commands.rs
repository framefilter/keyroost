//! High-level Molto2 command builders.
//!
//! Each function returns a `Command` containing the APDU bytes to send and a
//! human description, leaving the actual PC/SC transmission to the transport
//! crate. The protocol layer is hardware-free and unit-testable.

use crate::apdu::{build_apdu, build_apdu_get, mac, pad_iso7816_minimal, CLA_PLAIN, CLA_SECURE};
use crate::sha1::sha1;
use crate::sm4::Sm4;

/// Default customer key shipped on a fresh device: ASCII "TOKEN2MOLTO1-KEY".
pub const DEFAULT_CUSTOMER_KEY: &[u8; 16] = b"TOKEN2MOLTO1-KEY";

/// Derive the 16-byte SM4 key the device uses from a customer key of any length.
pub fn derive_sm4_key(customer_key: &[u8]) -> [u8; 16] {
    let digest = sha1(customer_key);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HmacAlgo {
    Sha1 = 1,
    Sha256 = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeStep {
    Seconds30 = 0x1E,
    Seconds60 = 0x3C,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayTimeout {
    Sec15 = 0,
    Sec30 = 1,
    Sec60 = 2,
    Sec120 = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpDigits {
    Four = 4,
    Six = 6,
    Eight = 8,
    Ten = 10,
}

impl OtpDigits {
    fn as_byte(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ProfileConfig {
    pub display_timeout: DisplayTimeout,
    pub algorithm: HmacAlgo,
    pub digits: OtpDigits,
    pub time_step: TimeStep,
    /// Unix epoch seconds to seed the per-profile clock.
    pub utc_time: u32,
}

/// An APDU ready to send, plus a human label for logs/UI.
#[derive(Debug, Clone)]
pub struct Command {
    pub label: &'static str,
    pub apdu: Vec<u8>,
}

/// `80 41 00 00 00` — read serial and on-device UTC time. No auth needed.
pub fn get_info() -> Command {
    Command {
        label: "get info (serial + time)",
        apdu: build_apdu_get(CLA_PLAIN, 0x41, 0x00, 0x00, 0x00),
    }
}

/// `80 4B 08 00 00` — request the 8-byte auth challenge.
pub fn get_challenge() -> Command {
    Command {
        label: "get challenge",
        apdu: build_apdu_get(CLA_PLAIN, 0x4B, 0x08, 0x00, 0x00),
    }
}

/// `80 CE 00 00 10 <response>` — submit the SM4-encrypted 16-byte challenge.
/// `challenge` is the 8 bytes returned by `get_challenge`; we zero-pad to 16.
pub fn answer_challenge(sm4_key: &[u8; 16], challenge: &[u8; 8]) -> Command {
    let mut block = [0u8; 16];
    block[..8].copy_from_slice(challenge);
    let cipher = Sm4::new(sm4_key);
    cipher.encrypt_block(&mut block);
    Command {
        label: "answer challenge",
        apdu: build_apdu(CLA_PLAIN, 0xCE, 0x00, 0x00, &block),
    }
}

/// `84 C5 01 <profile> Lc <SM4(seed_padded) || mac>` — write a profile seed.
/// `seed` may be 1..=63 raw bytes (the device caps at 63).
pub fn set_seed(sm4_key: &[u8; 16], profile: u8, seed: &[u8]) -> Command {
    assert!(
        !seed.is_empty() && seed.len() <= 63,
        "seed must be 1..=63 bytes"
    );
    let padded = pad_iso7816_minimal(seed);
    let mut enc = padded;
    let cipher = Sm4::new(sm4_key);
    cipher.encrypt_ecb(&mut enc);
    let header = [CLA_SECURE, 0xC5, 0x01, profile, enc.len() as u8];
    let mac_bytes = mac(
        sm4_key,
        &[CLA_PLAIN, 0xC5, 0x01, profile, enc.len() as u8],
        &enc,
    );
    let mut body = enc;
    body.extend_from_slice(&mac_bytes);
    Command {
        label: "set seed",
        apdu: build_apdu(header[0], header[1], header[2], header[3], &body),
    }
}

/// `84 D5 00 <profile> 14 <SM4(title_padded_to_16) || mac>` — write a profile title.
/// `title` must be 1..=12 UTF-8 bytes.
pub fn set_title(sm4_key: &[u8; 16], profile: u8, title: &str) -> Command {
    let bytes = title.as_bytes();
    assert!(
        !bytes.is_empty() && bytes.len() <= 12,
        "title must be 1..=12 bytes"
    );
    let padded = pad_iso7816_minimal(bytes); // becomes 16 bytes
    let mut enc = padded;
    let cipher = Sm4::new(sm4_key);
    cipher.encrypt_ecb(&mut enc);
    debug_assert_eq!(enc.len(), 16);
    let mac_bytes = mac(sm4_key, &[CLA_PLAIN, 0xD5, 0x00, profile, 0x10], &enc);
    let mut body = enc;
    body.extend_from_slice(&mac_bytes);
    Command {
        label: "set title",
        apdu: build_apdu(CLA_SECURE, 0xD5, 0x00, profile, &body),
    }
}

/// TLV-encoded profile config. `84 D4 01 <profile> Lc <tlv || mac>`.
pub fn set_config(sm4_key: &[u8; 16], profile: u8, cfg: &ProfileConfig) -> Command {
    let mut tlv = Vec::with_capacity(20);
    // 81 14 — TLV_TAG_SYS_CONFG, length 20 (0x14) bytes of children
    tlv.push(0x81);
    tlv.push(0x14);
    // 1F 01 <display_timeout>
    tlv.push(0x1F);
    tlv.push(0x01);
    tlv.push(cfg.display_timeout as u8);
    // 0F 04 <utc_time BE>
    tlv.push(0x0F);
    tlv.push(0x04);
    tlv.extend_from_slice(&cfg.utc_time.to_be_bytes());
    // 86 09 — TLV_TAG_TOTP_PARAM, length 9 bytes of children
    tlv.push(0x86);
    tlv.push(0x09);
    // 0A 01 <hmac_method>
    tlv.push(0x0A);
    tlv.push(0x01);
    tlv.push(cfg.algorithm as u8);
    // 0B 01 <digits>
    tlv.push(0x0B);
    tlv.push(0x01);
    tlv.push(cfg.digits.as_byte());
    // 0D 01 <time_step>
    tlv.push(0x0D);
    tlv.push(0x01);
    tlv.push(cfg.time_step as u8);

    debug_assert_eq!(tlv.len(), 22);

    let mac_bytes = mac(
        sm4_key,
        &[CLA_PLAIN, 0xD4, 0x01, profile, tlv.len() as u8],
        &tlv,
    );
    let mut body = tlv;
    body.extend_from_slice(&mac_bytes);
    Command {
        label: "set config",
        apdu: build_apdu(CLA_SECURE, 0xD4, 0x01, profile, &body),
    }
}

/// Slim variant of set_config that only updates the UTC time TLV. Used by sync-time.
pub fn sync_time(sm4_key: &[u8; 16], profile: u8, utc_time: u32) -> Command {
    let mut tlv = Vec::with_capacity(8);
    tlv.push(0x81);
    tlv.push(0x06);
    tlv.push(0x0F);
    tlv.push(0x04);
    tlv.extend_from_slice(&utc_time.to_be_bytes());
    let mac_bytes = mac(
        sm4_key,
        &[CLA_PLAIN, 0xD4, 0x01, profile, tlv.len() as u8],
        &tlv,
    );
    let mut body = tlv;
    body.extend_from_slice(&mac_bytes);
    Command {
        label: "sync time",
        apdu: build_apdu(CLA_SECURE, 0xD4, 0x01, profile, &body),
    }
}

/// `84 D7 00 00 24 <SM4(00 || sha1(new)[..16] || 80 00..) || mac>` — set new customer key.
/// Device requires physical button confirmation after this.
pub fn set_customer_key(sm4_key: &[u8; 16], new_key: &[u8]) -> Command {
    let new_sm4 = derive_sm4_key(new_key);
    let mut plaintext = Vec::with_capacity(32);
    plaintext.push(0x00);
    plaintext.extend_from_slice(&new_sm4);
    plaintext.push(0x80);
    plaintext.extend_from_slice(&[0u8; 14]);
    debug_assert_eq!(plaintext.len(), 32);
    let mut enc = plaintext;
    let cipher = Sm4::new(sm4_key);
    cipher.encrypt_ecb(&mut enc);
    let mac_bytes = mac(sm4_key, &[CLA_PLAIN, 0xD7, 0x00, 0x00, 0x20], &enc);
    let mut body = enc;
    body.extend_from_slice(&mac_bytes);
    Command {
        label: "set customer key",
        apdu: build_apdu(CLA_SECURE, 0xD7, 0x00, 0x00, &body),
    }
}

/// `80 56 00 00 00` — factory reset (requires physical confirmation).
pub fn factory_reset() -> Command {
    Command {
        label: "factory reset",
        apdu: build_apdu_get(CLA_PLAIN, 0x56, 0x00, 0x00, 0x00),
    }
}

/// Status word helpers.
///
/// `9000` is plain success. `9060` is "command accepted, awaiting button
/// confirmation on the device" — observed on `factory_reset` and
/// `set_customer_key`. Both are non-failure outcomes from the host's
/// perspective; the device returns the same empty body for either.
pub fn sw_ok(sw1: u8, sw2: u8) -> bool {
    sw1 == 0x90 && (sw2 == 0x00 || sw2 == 0x60)
}

/// True only for the unambiguous "completed" status. Returns false for
/// `9060` (awaiting button confirmation).
pub fn sw_completed(sw1: u8, sw2: u8) -> bool {
    sw1 == 0x90 && sw2 == 0x00
}

/// True when the device returned a status indicating it's waiting for the
/// user to press the up-arrow button to commit the operation.
pub fn sw_awaiting_button(sw1: u8, sw2: u8) -> bool {
    sw1 == 0x90 && sw2 == 0x60
}

pub fn sw_auth_failed(sw1: u8) -> bool {
    // The Python tool checks `sw1 == 99` (decimal) which is 0x63 — the standard
    // "warning: authentication failed, N tries remaining" status word family.
    sw1 == 0x63
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_sm4_key() -> [u8; 16] {
        derive_sm4_key(DEFAULT_CUSTOMER_KEY)
    }

    #[test]
    fn get_info_apdu() {
        assert_eq!(get_info().apdu, [0x80, 0x41, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn get_challenge_apdu() {
        assert_eq!(get_challenge().apdu, [0x80, 0x4B, 0x08, 0x00, 0x00]);
    }

    #[test]
    fn answer_challenge_layout() {
        let key = default_sm4_key();
        let chal = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let cmd = answer_challenge(&key, &chal);
        // CLA INS P1 P2 Lc <16 bytes>
        assert_eq!(cmd.apdu[0], 0x80);
        assert_eq!(cmd.apdu[1], 0xCE);
        assert_eq!(cmd.apdu[2], 0x00);
        assert_eq!(cmd.apdu[3], 0x00);
        assert_eq!(cmd.apdu[4], 0x10);
        assert_eq!(cmd.apdu.len(), 5 + 16);
    }

    #[test]
    fn set_seed_apdu_shape() {
        let key = default_sm4_key();
        let seed = [0u8; 20]; // 20 bytes = pads to 32 = 2 blocks
        let cmd = set_seed(&key, 7, &seed);
        // header
        assert_eq!(cmd.apdu[0..4], [0x84, 0xC5, 0x01, 7]);
        // Lc = 32 (ciphertext) + 4 (mac)
        assert_eq!(cmd.apdu[4], 36);
        assert_eq!(cmd.apdu.len(), 5 + 36);
    }

    #[test]
    fn set_seed_short_seed_pads_to_one_block() {
        let key = default_sm4_key();
        let seed = [0xab; 10];
        let cmd = set_seed(&key, 0, &seed);
        // pads to 16 + 4-byte mac
        assert_eq!(cmd.apdu[4], 20);
    }

    #[test]
    fn set_title_is_always_one_block_plus_mac() {
        let key = default_sm4_key();
        for title in ["a", "abcdefghijkl", "hello"] {
            let cmd = set_title(&key, 3, title);
            assert_eq!(cmd.apdu[0..4], [0x84, 0xD5, 0x00, 3]);
            assert_eq!(cmd.apdu[4], 0x14); // 16 + 4
            assert_eq!(cmd.apdu.len(), 5 + 20);
        }
    }

    #[test]
    fn set_config_tlv_length_is_22_plus_mac() {
        let key = default_sm4_key();
        let cfg = ProfileConfig {
            display_timeout: DisplayTimeout::Sec30,
            algorithm: HmacAlgo::Sha1,
            digits: OtpDigits::Six,
            time_step: TimeStep::Seconds30,
            utc_time: 0x6500_0000,
        };
        let cmd = set_config(&key, 12, &cfg);
        assert_eq!(cmd.apdu[0..4], [0x84, 0xD4, 0x01, 12]);
        // TLV is 22 bytes, plus 4 MAC = 26
        assert_eq!(cmd.apdu[4], 26);
    }

    #[test]
    fn sync_time_tlv_shape() {
        let key = default_sm4_key();
        let cmd = sync_time(&key, 0, 0x6612_3456);
        assert_eq!(cmd.apdu[0..4], [0x84, 0xD4, 0x01, 0]);
        // 8-byte TLV + 4 MAC
        assert_eq!(cmd.apdu[4], 12);
        // 81 06 0F 04 66 12 34 56
        assert_eq!(
            &cmd.apdu[5..13],
            &[0x81, 0x06, 0x0F, 0x04, 0x66, 0x12, 0x34, 0x56]
        );
    }

    #[test]
    fn factory_reset_apdu() {
        assert_eq!(factory_reset().apdu, [0x80, 0x56, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn default_sm4_key_matches_python_reference() {
        // Captured from `hashlib.sha1(b"TOKEN2MOLTO1-KEY").hexdigest()[:32]`.
        assert_eq!(
            crate::codec::hex_encode(&default_sm4_key()),
            "099250fdb017f442da429ecbbee17f79"
        );
    }
}
