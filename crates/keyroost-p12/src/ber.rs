//! Minimal BER/DER reader: tag, length (definite or indefinite) and value.

use std::borrow::Cow;

use crate::P12Error;

/// Deepest nesting the reader follows.
const MAX_DEPTH: usize = 32;

/// One decoded element. `value` borrows the input, except a constructed OCTET
/// STRING (tag `0x24`), whose segments are joined into one owned value.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Tlv<'a> {
    pub tag: u8,
    pub constructed: bool,
    pub value: Cow<'a, [u8]>,
}

impl Drop for Tlv<'_> {
    /// A flattened (owned) value can hold decrypted material; clear it.
    fn drop(&mut self) {
        if let Cow::Owned(v) = &mut self.value {
            zeroize::Zeroize::zeroize(v);
        }
    }
}

/// Read one element from the front of `input`; returns it and the rest.
///
/// Nesting is bounded to 32 levels of indefinite-length and constructed
/// OCTET STRING content inside this one element. Definite-length structure
/// is not descended into here: a caller that walks it with [`children`] owns
/// that bound (the PFX walk has a fixed shape: PFX, AuthenticatedSafe,
/// SafeContents, bag).
pub(crate) fn read_tlv(input: &[u8]) -> Result<(Tlv<'_>, &[u8]), P12Error> {
    read_at(input, 0)
}

/// Split `value` (the content of a constructed element) into its elements.
/// Each element is bounded as in [`read_tlv`]; the caller bounds how deeply
/// it calls this again.
pub(crate) fn children(value: &[u8]) -> Result<Vec<Tlv<'_>>, P12Error> {
    let mut out = Vec::new();
    let mut rest = value;
    while !rest.is_empty() {
        let (tlv, next) = read_tlv(rest)?;
        out.push(tlv);
        rest = next;
    }
    Ok(out)
}

fn bad(what: &'static str) -> P12Error {
    P12Error::Malformed(what)
}

/// Parse a tag and length; `Ok((tag, len, header_len))`, `len == None` means
/// indefinite.
fn header(input: &[u8]) -> Result<(u8, Option<usize>, usize), P12Error> {
    let tag = *input.first().ok_or_else(|| bad("truncated element"))?;
    if tag & 0x1F == 0x1F {
        return Err(bad("multi-byte tags are not used"));
    }
    let first = *input.get(1).ok_or_else(|| bad("truncated length"))?;
    if first < 0x80 {
        return Ok((tag, Some(usize::from(first)), 2));
    }
    let n = usize::from(first & 0x7F);
    if n == 0 {
        // Indefinite length is only legal on constructed elements.
        if tag & 0x20 == 0 {
            return Err(bad("indefinite length on a primitive element"));
        }
        return Ok((tag, None, 2));
    }
    if n > core::mem::size_of::<usize>() {
        return Err(bad("length too large"));
    }
    let bytes = input.get(2..2 + n).ok_or_else(|| bad("truncated length"))?;
    let mut len = 0usize;
    for &b in bytes {
        len = (len << 8) | usize::from(b);
    }
    Ok((tag, Some(len), 2 + n))
}

/// Where one element sits in its input.
struct Extent {
    tag: u8,
    /// Header length in bytes.
    hlen: usize,
    /// Content length in bytes (excluding any end-of-contents marker).
    clen: usize,
    /// Bytes the whole element occupies, header and marker included.
    total: usize,
}

/// Measure one element without building anything. Indefinite elements are
/// walked once, so each byte is visited once per enclosing indefinite level;
/// `depth` counts those levels (the outermost element is depth 0).
fn extent(input: &[u8], depth: usize) -> Result<Extent, P12Error> {
    if depth >= MAX_DEPTH {
        return Err(bad("nesting too deep"));
    }
    let (tag, len, hlen) = header(input)?;
    let body = input.get(hlen..).ok_or_else(|| bad("truncated element"))?;
    match len {
        Some(clen) => {
            if clen > body.len() {
                return Err(bad("length exceeds input"));
            }
            Ok(Extent {
                tag,
                hlen,
                clen,
                total: hlen + clen,
            })
        }
        None => {
            let mut pos = 0usize;
            loop {
                let here = body
                    .get(pos..)
                    .ok_or_else(|| bad("missing end of contents"))?;
                if here.len() < 2 {
                    return Err(bad("missing end of contents"));
                }
                if here.first() == Some(&0) && here.get(1) == Some(&0) {
                    break;
                }
                pos += extent(here, depth + 1)?.total;
            }
            Ok(Extent {
                tag,
                hlen,
                clen: pos,
                total: hlen + pos + 2,
            })
        }
    }
}

fn read_at(input: &[u8], depth: usize) -> Result<(Tlv<'_>, &[u8]), P12Error> {
    let e = extent(input, depth)?;
    let content = input
        .get(e.hlen..e.hlen + e.clen)
        .ok_or_else(|| bad("truncated element"))?;
    let rest = input
        .get(e.total..)
        .ok_or_else(|| bad("truncated element"))?;
    let value = if e.tag == 0x24 {
        // The joined value is no longer than the content; sizing it up front
        // keeps reallocation from leaving copies of key material behind.
        let mut out = Vec::with_capacity(content.len());
        flatten_octets(content, depth, &mut out)?;
        Cow::Owned(out)
    } else {
        Cow::Borrowed(content)
    };
    Ok((
        Tlv {
            tag: e.tag,
            constructed: e.tag & 0x20 != 0,
            value,
        },
        rest,
    ))
}

/// Join the segments of a constructed OCTET STRING into `out`.
fn flatten_octets(content: &[u8], depth: usize, out: &mut Vec<u8>) -> Result<(), P12Error> {
    let mut rest = content;
    while !rest.is_empty() {
        let e = extent(rest, depth + 1)?;
        let seg = rest
            .get(e.hlen..e.hlen + e.clen)
            .ok_or_else(|| bad("truncated element"))?;
        match e.tag {
            0x04 => out.extend_from_slice(seg),
            0x24 => flatten_octets(seg, depth + 1, out)?,
            _ => return Err(bad("unexpected element inside an octet string")),
        }
        rest = rest
            .get(e.total..)
            .ok_or_else(|| bad("truncated element"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_definite_length_parses() {
        let (t, rest) = read_tlv(&[0x30, 0x03, 0x04, 0x01, 0xAA, 0xFF]).unwrap();
        assert_eq!(t.tag, 0x30);
        assert!(t.constructed);
        assert_eq!(&*t.value, &[0x04, 0x01, 0xAA]);
        assert_eq!(rest, &[0xFF]);
        let kids = children(&t.value).unwrap();
        assert_eq!(kids.len(), 1);
        assert_eq!(kids[0].tag, 0x04);
        assert_eq!(&*kids[0].value, &[0xAA]);
    }

    #[test]
    fn long_form_definite_length_parses() {
        let mut data = vec![0x04, 0x81, 0x80];
        data.extend(std::iter::repeat_n(7u8, 0x80));
        let (t, rest) = read_tlv(&data).unwrap();
        assert_eq!(t.value.len(), 0x80);
        assert!(rest.is_empty());
    }

    #[test]
    fn ber_indefinite_length_parses() {
        let (t, rest) = read_tlv(&[0x30, 0x80, 0x04, 0x01, 0xAA, 0x00, 0x00]).unwrap();
        assert_eq!(t.tag, 0x30);
        assert!(rest.is_empty());
        let kids = children(&t.value).unwrap();
        assert_eq!(kids.len(), 1);
        assert_eq!(&*kids[0].value, &[0xAA]);
    }

    #[test]
    fn constructed_octet_string_is_flattened() {
        let data = [
            0x24, 0x80, 0x04, 0x02, 0x01, 0x02, 0x04, 0x01, 0x03, 0x00, 0x00,
        ];
        let (t, rest) = read_tlv(&data).unwrap();
        assert_eq!(t.tag, 0x24);
        assert_eq!(&*t.value, &[1, 2, 3]);
        assert!(rest.is_empty());
    }

    #[test]
    fn truncated_input_is_malformed() {
        assert!(read_tlv(&[]).is_err());
        assert!(read_tlv(&[0x30]).is_err());
        assert!(read_tlv(&[0x30, 0x05, 0x01]).is_err());
        assert!(read_tlv(&[0x30, 0x80, 0x04, 0x01, 0xAA]).is_err());
    }

    #[test]
    fn nesting_beyond_32_is_malformed() {
        // 40 nested indefinite SEQUENCEs.
        let mut data = Vec::new();
        for _ in 0..40 {
            data.extend_from_slice(&[0x30, 0x80]);
        }
        for _ in 0..40 {
            data.extend_from_slice(&[0x00, 0x00]);
        }
        assert!(matches!(read_tlv(&data), Err(P12Error::Malformed(_))));
        // 10 levels are fine.
        let mut ok = Vec::new();
        for _ in 0..10 {
            ok.extend_from_slice(&[0x30, 0x80]);
        }
        for _ in 0..10 {
            ok.extend_from_slice(&[0x00, 0x00]);
        }
        assert!(read_tlv(&ok).is_ok());
    }

    #[test]
    fn long_form_length_beyond_input_is_malformed() {
        assert!(read_tlv(&[0x04, 0x84, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]).is_err());
        assert!(read_tlv(&[0x04, 0x88, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]).is_err());
        assert!(read_tlv(&[0x04, 0x89, 1, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
    }

    fn nested_octets(n: usize) -> Vec<u8> {
        let mut data = Vec::new();
        for _ in 0..n {
            data.extend_from_slice(&[0x24, 0x80]);
        }
        data.extend_from_slice(&[0x04, 0x01, 0x42]);
        for _ in 0..n {
            data.extend_from_slice(&[0x00, 0x00]);
        }
        data
    }

    #[test]
    fn nested_indefinite_octet_strings_are_fast_and_bounded() {
        // 31 wrappers around a primitive: the primitive sits at depth 31 (ok).
        let ok = nested_octets(31);
        let (t, rest) = read_tlv(&ok).unwrap();
        assert_eq!(&*t.value, &[0x42]);
        assert!(rest.is_empty());
        // 32 wrappers push the primitive to depth 32 (error).
        assert!(read_tlv(&nested_octets(32)).is_err());
        let mut only = Vec::new();
        for _ in 0..32 {
            only.extend_from_slice(&[0x24, 0x80]);
        }
        for _ in 0..32 {
            only.extend_from_slice(&[0x00, 0x00]);
        }
        // 32 nested elements (depths 0..31) are the limit; 33 are too many.
        assert!(read_tlv(&only).is_ok());
        let mut over = Vec::new();
        for _ in 0..33 {
            over.extend_from_slice(&[0x24, 0x80]);
        }
        for _ in 0..33 {
            over.extend_from_slice(&[0x00, 0x00]);
        }
        assert!(read_tlv(&over).is_err());
    }
}
