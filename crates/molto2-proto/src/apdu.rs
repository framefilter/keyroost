//! ISO 7816-4 APDU construction and the per-command MAC the Molto2 expects.
//!
//! Wire format reference (derived from observing molto2.py against a real device):
//!
//!   CLA  INS  P1   P2   Lc   data...
//!
//! For "secure" commands (CLA 0x84) the trailing 4 bytes of `data` are a MAC over
//! `[CLA, INS, P1, P2, Lc-as-1-byte-payload-len, payload]` computed as
//! SM4-CBC(key=SHA1(customer_key)[..16], iv=0) with 80/00 padding, taking the
//! last block then keeping its first 4 bytes.

use crate::sm4::Sm4;

pub const CLA_PLAIN: u8 = 0x80;
pub const CLA_SECURE: u8 = 0x84;

/// SM4 block-size padding (ISO/IEC 9797-1 padding method 2): append 0x80 then
/// zeros up to a 16-byte boundary. If the input is already block-aligned, an
/// entire extra padding block is appended.
pub fn pad_iso7816(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 16);
    out.extend_from_slice(data);
    out.push(0x80);
    while out.len() % 16 != 0 {
        out.push(0x00);
    }
    out
}

/// SM4 padding *only when necessary*: append 0x80 then zeros up to the next
/// 16-byte boundary; if already aligned, do nothing. This matches molto2.py's
/// behaviour for seed/title payloads.
pub fn pad_iso7816_minimal(data: &[u8]) -> Vec<u8> {
    if data.len() % 16 == 0 {
        return data.to_vec();
    }
    let mut out = Vec::with_capacity(((data.len() / 16) + 1) * 16);
    out.extend_from_slice(data);
    out.push(0x80);
    while out.len() % 16 != 0 {
        out.push(0x00);
    }
    out
}

/// Compute the 4-byte MAC the Molto2 expects on CLA 0x84 commands.
///
/// `header` is the 5-byte APDU prefix used as the MAC AAD: `[CLA, INS, P1, P2, Lc]`
/// where `Lc` here is the *payload* length (without the MAC), not the final
/// APDU Lc. `payload` is the encrypted body without the MAC suffix.
pub fn mac(sm4_key: &[u8; 16], header: &[u8; 5], payload: &[u8]) -> [u8; 4] {
    let mut msg = Vec::with_capacity(header.len() + payload.len() + 16);
    msg.extend_from_slice(header);
    msg.extend_from_slice(payload);
    let padded = pad_iso7816_minimal(&msg);
    let mut buf = padded;
    let cipher = Sm4::new(sm4_key);
    let iv = [0u8; 16];
    cipher.encrypt_cbc(&iv, &mut buf);
    // Take the last block, keep its first 4 bytes.
    let last = &buf[buf.len() - 16..];
    [last[0], last[1], last[2], last[3]]
}

/// Build a case-3 short APDU (header + Lc + data, no Le).
pub fn build_apdu(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    assert!(data.len() <= 255, "short APDU body too large");
    let mut out = Vec::with_capacity(5 + data.len());
    out.push(cla);
    out.push(ins);
    out.push(p1);
    out.push(p2);
    out.push(data.len() as u8);
    out.extend_from_slice(data);
    out
}

/// Build a case-2 short APDU (header + Le only). `le` of 0 means "up to 256 bytes".
pub fn build_apdu_get(cla: u8, ins: u8, p1: u8, p2: u8, le: u8) -> Vec<u8> {
    vec![cla, ins, p1, p2, le]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_block_aligned_minimal_is_noop() {
        let data = [0xaa; 16];
        assert_eq!(pad_iso7816_minimal(&data).as_slice(), &data);
    }

    #[test]
    fn padding_full_form_always_pads() {
        let data = [0xaa; 16];
        let padded = pad_iso7816(&data);
        assert_eq!(padded.len(), 32);
        assert_eq!(padded[16], 0x80);
        assert!(padded[17..].iter().all(|&b| b == 0));
    }

    #[test]
    fn padding_unaligned() {
        let data = b"hello"; // 5 bytes
        let padded = pad_iso7816_minimal(data);
        assert_eq!(padded.len(), 16);
        assert_eq!(&padded[..5], b"hello");
        assert_eq!(padded[5], 0x80);
        assert!(padded[6..].iter().all(|&b| b == 0));
    }

    #[test]
    fn build_apdu_layout() {
        let apdu = build_apdu(0x84, 0xC5, 0x01, 0x02, &[0xde, 0xad]);
        assert_eq!(apdu, [0x84, 0xC5, 0x01, 0x02, 0x02, 0xde, 0xad]);
    }
}
