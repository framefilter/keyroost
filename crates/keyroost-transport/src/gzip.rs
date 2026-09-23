//! Minimal gzip (RFC 1952) reader and writer for compressed PIV certificate
//! objects, plus the CRC-32 both use.
//!
//! A PIV certificate object may hold the certificate gzip-compressed
//! (CertInfo `0x01`, SP 800-73-4 Part 1 Appendix A). The DEFLATE body is
//! inflated and deflated by `miniz_oxide`; the header, the CRC-32 and the
//! trailer are in-tree.

use crate::piv::CertUnreadable;

/// Host ceiling on an inflated PIV certificate. Real certs are a few KB; the
/// card's own object is small. This just bounds a hostile/broken gzip stream
/// so the decompressor cannot be made to allocate without limit.
pub(crate) const MAX_CERT_DECOMPRESSED: usize = 64 * 1024;

/// Lookup table for [`crc32`], one entry per byte value, built at compile time.
const CRC32_TABLE: [u32; 256] = crc32_table();

const fn crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut bit = 0;
        while bit < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            bit += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

/// CRC-32 as used by gzip (IEEE 802.3): reflected, polynomial `0xEDB88320`,
/// initial value and final XOR `0xFFFFFFFF`.
pub(crate) fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c = CRC32_TABLE[((c ^ u32::from(b)) & 0xFF) as usize] ^ (c >> 8);
    }
    c ^ 0xFFFF_FFFF
}

/// One gzip (RFC 1952) member holding `data`, as written into a compressed
/// PIV certificate object. The header is fixed for reproducible output: no
/// optional fields (FLG 0), MTIME 0, XFL 2 (maximum compression), OS 255
/// (unknown). The DEFLATE body is `miniz_oxide` at level 9; the trailer is
/// the CRC-32 and the input length, both little-endian.
pub(crate) fn gzip_member(data: &[u8]) -> Vec<u8> {
    const HEADER: [u8; 10] = [0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xFF];
    let body = miniz_oxide::deflate::compress_to_vec(data, 9);
    let mut out = Vec::with_capacity(HEADER.len() + body.len() + 8);
    out.extend_from_slice(&HEADER);
    out.extend_from_slice(&body);
    out.extend_from_slice(&crc32(data).to_le_bytes());
    // ISIZE is the input length modulo 2^32 (RFC 1952 section 2.3.1).
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out
}

/// Inflate a gzip (RFC 1952) stream, capped at [`MAX_CERT_DECOMPRESSED`].
/// [`CertUnreadable::TooLarge`] for output past the cap;
/// [`CertUnreadable::Damaged`] for a non-gzip or malformed header, an
/// unparseable or truncated DEFLATE body, or a trailer whose CRC-32 or
/// ISIZE does not match the inflated bytes.
pub(crate) fn gunzip_capped(data: &[u8]) -> Result<Vec<u8>, CertUnreadable> {
    gunzip_stream(data).ok_or(CertUnreadable::Damaged)?
}

/// [`gunzip_capped`]'s header walk: `None` for a malformed header, else the
/// inflate result.
fn gunzip_stream(data: &[u8]) -> Option<Result<Vec<u8>, CertUnreadable>> {
    // Fixed header: magic(2) CM(1) FLG(1) MTIME(4) XFL(1) OS(1) = 10 bytes,
    // plus the 8-byte trailer, so a valid stream is at least 18 bytes.
    if data.len() < 18 || data[0] != 0x1F || data[1] != 0x8B || data[2] != 0x08 {
        return None;
    }
    let flg = data[3];
    let mut pos = 10usize;
    if flg & 0x04 != 0 {
        // FEXTRA: 2-byte little-endian length, then that many bytes.
        let xlen = u16::from_le_bytes([*data.get(pos)?, *data.get(pos + 1)?]) as usize;
        pos = pos.checked_add(2)?.checked_add(xlen)?;
    }
    if flg & 0x08 != 0 {
        // FNAME: zero-terminated.
        let rel = data.get(pos..)?.iter().position(|&b| b == 0)?;
        pos = pos.checked_add(rel)?.checked_add(1)?;
    }
    if flg & 0x10 != 0 {
        // FCOMMENT: zero-terminated.
        let rel = data.get(pos..)?.iter().position(|&b| b == 0)?;
        pos = pos.checked_add(rel)?.checked_add(1)?;
    }
    if flg & 0x02 != 0 {
        // FHCRC: 2 bytes.
        pos = pos.checked_add(2)?;
    }
    let end = data.len().checked_sub(8)?; // the CRC32 + ISIZE trailer
    let deflate = data.get(pos..end)?;
    let trailer = &data[end..];
    let crc = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
    let isize = u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);
    Some(
        miniz_oxide::inflate::decompress_to_vec_with_limit(deflate, MAX_CERT_DECOMPRESSED)
            .map_err(|e| match e.status {
                miniz_oxide::inflate::TINFLStatus::HasMoreOutput => CertUnreadable::TooLarge,
                _ => CertUnreadable::Damaged,
            })
            .and_then(|out| {
                // ISIZE is the input length mod 2^32; the cap keeps it exact.
                if crc32(&out) == crc && out.len() as u32 == isize {
                    Ok(out)
                } else {
                    Err(CertUnreadable::Damaged)
                }
            }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Produced by CPython `gzip.compress(PAYLOAD, 9, mtime=0)`: an
    /// independent encoder, so the reader and its CRC are checked against
    /// bytes this crate did not write.
    const PAYLOAD: &[u8] = b"keyroost gzip interop fixture: a stand-in certificate body";
    const FIXTURE_HEX: &str = "1f8b08000000000002ff05c1810d80200c04c0557e0117701b84623e262d294f224eefdd633b23a6707f1ca0cb32063a5fadb4130553c5db4147b5143b6b91e18ab67f7f86b7b63a000000";

    fn fixture() -> Vec<u8> {
        (0..FIXTURE_HEX.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&FIXTURE_HEX[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn crc32_check_value() {
        // The standard CRC-32/ISO-HDLC check value, and the empty input.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn crc32_of_the_fixture_payload() {
        assert_eq!(PAYLOAD.len(), 58);
        assert_eq!(crc32(PAYLOAD), 0xb6b7_867f);
    }

    #[test]
    fn inflates_the_cpython_fixture() {
        assert_eq!(gunzip_capped(&fixture()).as_deref(), Ok(PAYLOAD));
    }

    #[test]
    fn a_flipped_crc_byte_is_damaged() {
        let mut gz = fixture();
        let crc_at = gz.len() - 8;
        gz[crc_at] ^= 0x01;
        assert_eq!(gunzip_capped(&gz), Err(CertUnreadable::Damaged));
    }

    #[test]
    fn gzip_member_header_is_pinned() {
        // magic, CM=8, FLG=0, MTIME=0, XFL=2 (max compression), OS=255.
        let gz = gzip_member(PAYLOAD);
        assert_eq!(
            &gz[..10],
            &[0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xFF]
        );
        // Trailer: CRC-32 then ISIZE, both little-endian.
        let n = gz.len();
        assert_eq!(&gz[n - 8..n - 4], &crc32(PAYLOAD).to_le_bytes());
        assert_eq!(&gz[n - 4..], &(PAYLOAD.len() as u32).to_le_bytes());
    }

    #[test]
    fn gzip_member_round_trips_through_the_reader() {
        for data in [&b""[..], PAYLOAD, &[0xA5u8; 3000][..]] {
            assert_eq!(gunzip_capped(&gzip_member(data)).as_deref(), Ok(data));
        }
    }

    #[test]
    fn gzip_member_is_deterministic() {
        assert_eq!(gzip_member(PAYLOAD), gzip_member(PAYLOAD));
    }

    #[test]
    fn gzip_member_compresses_repetitive_input() {
        // A certificate full of repeated structure shrinks a lot; 6 KB of
        // a repeating pattern must land well under 3 KB.
        let data: Vec<u8> = b"CN=keyroost test, O=example, "
            .iter()
            .copied()
            .cycle()
            .take(6 * 1024)
            .collect();
        let gz = gzip_member(&data);
        assert!(gz.len() < 3 * 1024, "compressed to {} bytes", gz.len());
        assert_eq!(gunzip_capped(&gz).as_deref(), Ok(&data[..]));
    }

    #[test]
    fn a_wrong_isize_is_damaged() {
        let mut gz = fixture();
        let isize_at = gz.len() - 4;
        gz[isize_at] = gz[isize_at].wrapping_add(1);
        assert_eq!(gunzip_capped(&gz), Err(CertUnreadable::Damaged));
    }
}
