//! The text an import file holds, as UTF-8.
//!
//! Exports are UTF-8, but Windows tools often write text with a byte-order
//! mark (BOM) in front: Windows PowerShell 5.1's `Out-File -Encoding utf8`
//! writes a UTF-8 BOM, and its `>` redirection writes UTF-16 with a BOM.
//! A UTF-8 BOM is skipped; UTF-16 is converted when a BOM says it is UTF-16.
//! Without a BOM nothing is converted: guessing UTF-16 from the pattern of
//! zero bytes can misread a binary file, and a wrong guess about a file
//! that holds secrets is worse than not reading it.

use core::ops::Deref;
use zeroize::Zeroizing;

const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];
const UTF16_LE_BOM: [u8; 2] = [0xFF, 0xFE];
const UTF16_BE_BOM: [u8; 2] = [0xFE, 0xFF];

/// Told to the person when a file starts with a UTF-16 byte-order mark but
/// doesn't decode as UTF-16.
pub const DAMAGED_UTF16: &str = "This file looks like UTF-16 text, but part of it is damaged. \
     Save it again as UTF-8, then import that file.";

/// An import file's bytes as UTF-8: the bytes as they were (a UTF-8 BOM
/// skipped), or a converted copy of UTF-16 text in a wipe-on-drop buffer
/// (an export is every seed in clear).
pub enum Utf8Bytes<'a> {
    Borrowed(&'a [u8]),
    Converted(Zeroizing<Vec<u8>>),
}

impl Deref for Utf8Bytes<'_> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Utf8Bytes::Borrowed(b) => b,
            Utf8Bytes::Converted(v) => v,
        }
    }
}

/// A file started with a UTF-16 byte-order mark but didn't decode: an odd
/// number of bytes, or a broken surrogate pair. Reported, never patched
/// with a replacement character: a replaced character in a seed would make
/// wrong codes without a word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DamagedUtf16;

/// `bytes` as UTF-8 text input: a leading UTF-8 BOM is skipped, UTF-16
/// with a BOM (either byte order) is converted, anything else is returned
/// unchanged, binary files included (a PNG or DER file never starts with a
/// BOM). Whether the result is valid UTF-8 is left to the caller.
pub fn to_utf8(bytes: &[u8]) -> Result<Utf8Bytes<'_>, DamagedUtf16> {
    if let Some(rest) = bytes.strip_prefix(&UTF8_BOM) {
        return Ok(Utf8Bytes::Borrowed(rest));
    }
    let (body, le) = if let Some(rest) = bytes.strip_prefix(&UTF16_LE_BOM) {
        (rest, true)
    } else if let Some(rest) = bytes.strip_prefix(&UTF16_BE_BOM) {
        (rest, false)
    } else {
        return Ok(Utf8Bytes::Borrowed(bytes));
    };
    if body.len() % 2 != 0 {
        return Err(DamagedUtf16);
    }
    let units = body.chunks_exact(2).map(|p| {
        if le {
            u16::from_le_bytes([p[0], p[1]])
        } else {
            u16::from_be_bytes([p[0], p[1]])
        }
    });
    // Sized for the worst case (3 UTF-8 bytes per UTF-16 unit) so the
    // buffer never reallocates and leaves an unwiped copy behind.
    let mut out = Zeroizing::new(Vec::with_capacity(body.len() / 2 * 3));
    let mut utf8 = [0u8; 4];
    for c in char::decode_utf16(units) {
        let c = c.map_err(|_| DamagedUtf16)?;
        out.extend_from_slice(c.encode_utf8(&mut utf8).as_bytes());
    }
    Ok(Utf8Bytes::Converted(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn le(s: &str) -> Vec<u8> {
        let mut v = UTF16_LE_BOM.to_vec();
        for u in s.encode_utf16() {
            v.extend_from_slice(&u.to_le_bytes());
        }
        v
    }

    fn be(s: &str) -> Vec<u8> {
        let mut v = UTF16_BE_BOM.to_vec();
        for u in s.encode_utf16() {
            v.extend_from_slice(&u.to_be_bytes());
        }
        v
    }

    const LIST: &str = "otpauth://totp/Ex:a%C3%A9?secret=JBSWY3DPEHPK3PXP\r\notpauth://totp/B:\u{1F511}?secret=GEZDGNBVGY3TQOJQ\r\n";

    #[test]
    fn plain_bytes_are_untouched() {
        let b = b"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP\n";
        match to_utf8(b).unwrap() {
            Utf8Bytes::Borrowed(got) => assert!(core::ptr::eq(got, &b[..])),
            Utf8Bytes::Converted(_) => panic!("plain UTF-8 was copied"),
        }
        // Binary files pass through as they are.
        let png = b"\x89PNG\r\n\x1a\n rest";
        assert_eq!(&*to_utf8(png).unwrap(), &png[..]);
    }

    #[test]
    fn a_utf8_bom_is_skipped() {
        let mut b = UTF8_BOM.to_vec();
        b.extend_from_slice(LIST.as_bytes());
        assert_eq!(&*to_utf8(&b).unwrap(), LIST.as_bytes());
    }

    #[test]
    fn utf16_with_a_bom_is_converted_in_either_byte_order() {
        // CRLF line ends, an accented letter and a character outside the
        // Basic Multilingual Plane (a surrogate pair) all come through.
        assert_eq!(&*to_utf8(&le(LIST)).unwrap(), LIST.as_bytes());
        assert_eq!(&*to_utf8(&be(LIST)).unwrap(), LIST.as_bytes());
    }

    #[test]
    fn a_bom_alone_is_empty_text() {
        assert!(to_utf8(&UTF8_BOM).unwrap().is_empty());
        assert!(to_utf8(&UTF16_LE_BOM).unwrap().is_empty());
    }

    #[test]
    fn damaged_utf16_is_reported_not_patched() {
        // An odd number of bytes after the BOM.
        let mut odd = le("ab");
        odd.push(0x41);
        assert_eq!(to_utf8(&odd).err(), Some(DamagedUtf16));
        // A high surrogate with nothing after it.
        let mut lone = UTF16_LE_BOM.to_vec();
        lone.extend_from_slice(&0xD83Du16.to_le_bytes());
        assert_eq!(to_utf8(&lone).err(), Some(DamagedUtf16));
        // A low surrogate on its own.
        let mut low = UTF16_BE_BOM.to_vec();
        low.extend_from_slice(&0xDC00u16.to_be_bytes());
        assert_eq!(to_utf8(&low).err(), Some(DamagedUtf16));
    }
}
