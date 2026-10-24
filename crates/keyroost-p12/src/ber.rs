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

/// Read one element from the front of `input`; returns it and the rest.
pub(crate) fn read_tlv(input: &[u8]) -> Result<(Tlv<'_>, &[u8]), P12Error> {
    read_at(input, 0)
}

/// Split `value` (the content of a constructed element) into its elements.
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

fn read_at(input: &[u8], depth: usize) -> Result<(Tlv<'_>, &[u8]), P12Error> {
    if depth > MAX_DEPTH {
        return Err(bad("nesting too deep"));
    }
    let (tag, len, hlen) = header(input)?;
    let constructed = tag & 0x20 != 0;
    let body = input.get(hlen..).ok_or_else(|| bad("truncated element"))?;
    match len {
        Some(len) => {
            let value = body.get(..len).ok_or_else(|| bad("length exceeds input"))?;
            let rest = body.get(len..).ok_or_else(|| bad("length exceeds input"))?;
            let value = if tag == 0x24 {
                Cow::Owned(flatten_octets(value, depth)?)
            } else {
                Cow::Borrowed(value)
            };
            Ok((
                Tlv {
                    tag,
                    constructed,
                    value,
                },
                rest,
            ))
        }
        None => {
            // Walk children until the end-of-contents marker (00 00).
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
                let (_, next) = read_at(here, depth + 1)?;
                pos += here.len() - next.len();
            }
            let content = body.get(..pos).ok_or_else(|| bad("truncated element"))?;
            let rest = body
                .get(pos + 2..)
                .ok_or_else(|| bad("truncated element"))?;
            let value = if tag == 0x24 {
                Cow::Owned(flatten_octets(content, depth)?)
            } else {
                Cow::Borrowed(content)
            };
            Ok((
                Tlv {
                    tag,
                    constructed,
                    value,
                },
                rest,
            ))
        }
    }
}

/// Join the segments of a constructed OCTET STRING into one value.
fn flatten_octets(content: &[u8], depth: usize) -> Result<Vec<u8>, P12Error> {
    let mut out = Vec::new();
    let mut rest = content;
    while !rest.is_empty() {
        let (seg, next) = read_at(rest, depth + 1)?;
        match seg.tag {
            0x04 | 0x24 => out.extend_from_slice(&seg.value),
            _ => return Err(bad("unexpected element inside an octet string")),
        }
        rest = next;
    }
    Ok(out)
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
}
