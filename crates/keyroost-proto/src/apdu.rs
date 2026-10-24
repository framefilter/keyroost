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
    if data.len().is_multiple_of(16) {
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

/// Error from [`try_build_apdu`]: the body exceeds the 255-byte case-3
/// short-APDU limit, so no valid 1-byte `Lc` exists for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApduBodyTooLong {
    /// The offending body length in bytes.
    pub len: usize,
}

impl core::fmt::Display for ApduBodyTooLong {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "APDU body is {} bytes; a case-3 short APDU holds at most 255",
            self.len
        )
    }
}

impl std::error::Error for ApduBodyTooLong {}

/// Build a case-3 short APDU (header + Lc + data, no Le), rejecting a body
/// past the 255-byte limit instead of panicking. Use this for bodies whose
/// length a caller or a device can influence.
pub fn try_build_apdu(
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: &[u8],
) -> Result<Vec<u8>, ApduBodyTooLong> {
    if data.len() > 255 {
        return Err(ApduBodyTooLong { len: data.len() });
    }
    let mut out = Vec::with_capacity(5 + data.len());
    out.push(cla);
    out.push(ins);
    out.push(p1);
    out.push(p2);
    out.push(data.len() as u8);
    out.extend_from_slice(data);
    Ok(out)
}

/// Build a case-3 short APDU (header + Lc + data, no Le).
///
/// # Panics
/// Panics if `data` exceeds 255 bytes. Fine for the fixed-size Molto2
/// command bodies in `commands.rs`; anything caller- or device-sized goes
/// through [`try_build_apdu`].
pub fn build_apdu(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    match try_build_apdu(cla, ins, p1, p2, data) {
        Ok(apdu) => apdu,
        Err(e) => panic!("short APDU body too large: {} bytes", e.len),
    }
}

/// Build a case-2 short APDU (header + Le only). `le` of 0 means "up to 256 bytes".
pub fn build_apdu_get(cla: u8, ins: u8, p1: u8, p2: u8, le: u8) -> Vec<u8> {
    vec![cla, ins, p1, p2, le]
}

/// Build the APDU to resend after a `6C xx` ("wrong Le") status word.
///
/// ISO 7816-4: `6C xx` tells the host to reissue the *same* command with
/// `Le = xx`. Where that Le goes depends on the case of the original APDU:
///
/// * case 1 (bare 4-byte header): **append** Le → case 2;
/// * case 2 (header + Le): **replace** the trailing Le byte — appending
///   would produce the malformed `… Le_old Le_new`;
/// * case 3 (header + Lc + data, no Le): **append** Le → case 4. The last
///   byte here is *data* and must never be overwritten;
/// * case 4 (header + Lc + data + Le): **replace** the trailing Le byte.
///
/// Classification is by structure, not length: only an APDU that provably
/// ends in Le gets its last byte replaced. An extended-form APDU
/// (`Lc = 00 hi lo`) never matches the case-4 length check and safely falls
/// through to append.
pub fn resend_with_le(original: &[u8], le: u8) -> Vec<u8> {
    let mut out = original.to_vec();
    let ends_in_le = match out.len() {
        0..=4 => false, // case 1 (or truncated): nothing to replace
        5 => true,      // case 2: the 5th byte is Le
        n => {
            // Short-form body APDU: header + Lc + `Lc` data bytes (case 3),
            // or the same plus one trailing Le (case 4).
            let lc = out[4] as usize;
            n == 5 + lc + 1
        }
    };
    if ends_in_le {
        *out.last_mut().unwrap() = le;
    } else {
        out.push(le);
    }
    out
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

    #[test]
    fn resend_with_le_covers_all_four_short_cases() {
        // Case 1 (bare header): append Le → case 2.
        assert_eq!(
            resend_with_le(&[0x80, 0xC5, 0x05, 0x02], 0x00),
            vec![0x80, 0xC5, 0x05, 0x02, 0x00]
        );
        // Case 2 (header + Le): replace the trailing Le.
        assert_eq!(
            resend_with_le(&[0x00, 0xC0, 0x00, 0x00, 0x20], 0x08),
            vec![0x00, 0xC0, 0x00, 0x00, 0x08]
        );
        // Case 3 (header + Lc + data): append; the last data byte survives.
        let apdu = build_apdu(0x80, 0xC5, 0x05, 0x02, &[0xAA; 16]);
        let mut expected = apdu.clone();
        expected.push(0x2A);
        assert_eq!(resend_with_le(&apdu, 0x2A), expected);
        // Case 4 (header + Lc + data + Le): replace the trailing Le.
        assert_eq!(
            resend_with_le(&[0x80, 0xC5, 0x05, 0x00, 0x02, 0x03, 0x07, 0x10], 0x40),
            vec![0x80, 0xC5, 0x05, 0x00, 0x02, 0x03, 0x07, 0x40]
        );
    }

    #[test]
    fn try_build_apdu_boundary() {
        // At the exact 255-byte case-3 limit the APDU builds; one byte over
        // is a typed error, not a panic (device/caller-length safety).
        let body = [0u8; 255];
        let apdu = try_build_apdu(0x00, 0xA2, 0x00, 0x01, &body).unwrap();
        assert_eq!(apdu.len(), 5 + 255);
        assert_eq!(apdu[4], 255);
        let over = [0u8; 256];
        assert_eq!(
            try_build_apdu(0x00, 0xA2, 0x00, 0x01, &over),
            Err(ApduBodyTooLong { len: 256 })
        );
    }
}
