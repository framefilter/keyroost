//! Minimal CBOR codec scoped to CTAP2.
//!
//! Supports the major types CTAP authenticators actually use: unsigned and
//! negative integers, byte strings, text strings, arrays, maps, booleans,
//! and null. Indefinite-length items, tags, and floats are intentionally
//! unsupported — CTAP2 mandates canonical (definite-length) encoding, so
//! anything else from a real authenticator would be a protocol violation.
//! The one exception is [`item_len`], which only measures an item: it walks
//! tags and floats too, so large-blob elements written by other tools can be
//! skipped and kept byte-for-byte without being interpreted.
//! The decoder is deliberately lenient where strictness buys nothing:
//! non-shortest integer encodings are accepted, and a duplicate map key
//! resolves to the first match — robustness against quirky devices matters
//! more here than policing canonical form.

use std::fmt;

const MT_UINT: u8 = 0;
const MT_NINT: u8 = 1;
const MT_BYTES: u8 = 2;
const MT_TEXT: u8 = 3;
const MT_ARRAY: u8 = 4;
const MT_MAP: u8 = 5;
const MT_TAG: u8 = 6;
const MT_SIMPLE: u8 = 7;

const SIMPLE_FALSE: u8 = 20;
const SIMPLE_TRUE: u8 = 21;
const SIMPLE_NULL: u8 = 22;
const SIMPLE_UNDEFINED: u8 = 23;

const DECODE_DEPTH_LIMIT: usize = 16;

/// A decoded or to-be-encoded CBOR value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    UInt(u64),
    /// Encodes as -(n+1); CBOR negative integers cannot represent -0.
    NInt(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    /// Entries kept in insertion order; CTAP canonical encoding requires
    /// callers to sort by encoded key.
    Map(Vec<(Value, Value)>),
    Bool(bool),
    Null,
}

#[non_exhaustive]
#[derive(Debug)]
pub enum CborError {
    UnexpectedEnd,
    InvalidUtf8,
    UnsupportedType(u8),
    UnsupportedAdditional(u8),
    DepthLimit,
}

impl fmt::Display for CborError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CborError::UnexpectedEnd => write!(f, "CBOR input ended mid-item"),
            CborError::InvalidUtf8 => write!(f, "CBOR text string was not valid UTF-8"),
            CborError::UnsupportedType(t) => write!(f, "unsupported CBOR major type {}", t),
            CborError::UnsupportedAdditional(a) => {
                write!(f, "unsupported CBOR additional info {}", a)
            }
            CborError::DepthLimit => write!(f, "CBOR nesting exceeded depth limit"),
        }
    }
}

impl std::error::Error for CborError {}

impl Value {
    pub fn as_uint(&self) -> Option<u64> {
        if let Value::UInt(n) = self {
            Some(*n)
        } else {
            None
        }
    }
    pub fn as_text(&self) -> Option<&str> {
        if let Value::Text(s) = self {
            Some(s)
        } else {
            None
        }
    }
    pub fn as_bytes(&self) -> Option<&[u8]> {
        if let Value::Bytes(b) = self {
            Some(b)
        } else {
            None
        }
    }
    pub fn as_array(&self) -> Option<&[Value]> {
        if let Value::Array(a) = self {
            Some(a)
        } else {
            None
        }
    }
    pub fn as_map(&self) -> Option<&[(Value, Value)]> {
        if let Value::Map(m) = self {
            Some(m)
        } else {
            None
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        if let Value::Bool(b) = self {
            Some(*b)
        } else {
            None
        }
    }

    /// Convenience for the common case of looking up a uint-keyed entry in
    /// a map — CTAP request and response maps are keyed by small ints.
    pub fn get_uint_key(&self, key: u64) -> Option<&Value> {
        self.as_map()?.iter().find_map(|(k, v)| {
            if k.as_uint() == Some(key) {
                Some(v)
            } else {
                None
            }
        })
    }
}

/// Encode a single CBOR value, returning the serialized bytes.
pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(value, &mut out);
    out
}

fn encode_into(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::UInt(n) => encode_header(out, MT_UINT, *n),
        Value::NInt(n) => encode_header(out, MT_NINT, *n),
        Value::Bytes(b) => {
            encode_header(out, MT_BYTES, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Text(s) => {
            encode_header(out, MT_TEXT, s.len() as u64);
            out.extend_from_slice(s.as_bytes());
        }
        Value::Array(a) => {
            encode_header(out, MT_ARRAY, a.len() as u64);
            for v in a {
                encode_into(v, out);
            }
        }
        Value::Map(m) => {
            encode_header(out, MT_MAP, m.len() as u64);
            for (k, v) in m {
                encode_into(k, out);
                encode_into(v, out);
            }
        }
        Value::Bool(b) => out.push((MT_SIMPLE << 5) | if *b { SIMPLE_TRUE } else { SIMPLE_FALSE }),
        Value::Null => out.push((MT_SIMPLE << 5) | SIMPLE_NULL),
    }
}

fn encode_header(out: &mut Vec<u8>, major: u8, n: u64) {
    let mt = major << 5;
    if n < 24 {
        out.push(mt | (n as u8));
    } else if n <= 0xFF {
        out.push(mt | 24);
        out.push(n as u8);
    } else if n <= 0xFFFF {
        out.push(mt | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= 0xFFFF_FFFF {
        out.push(mt | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(mt | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

/// Decode a CBOR value. Returns the value and any trailing bytes.
pub fn decode(data: &[u8]) -> Result<(Value, &[u8]), CborError> {
    decode_at(data, 0)
}

fn decode_at(data: &[u8], depth: usize) -> Result<(Value, &[u8]), CborError> {
    if depth > DECODE_DEPTH_LIMIT {
        return Err(CborError::DepthLimit);
    }
    let (b, rest) = data.split_first().ok_or(CborError::UnexpectedEnd)?;
    let major = b >> 5;
    let additional = b & 0b1_1111;
    let (arg, mut rest) = read_arg(rest, additional)?;

    Ok(match major {
        MT_UINT => (Value::UInt(arg), rest),
        MT_NINT => (Value::NInt(arg), rest),
        MT_BYTES => {
            // try_from, not `as`: on 32-bit targets a 64-bit length would
            // silently truncate and "successfully" parse the wrong bytes.
            let len = usize::try_from(arg).map_err(|_| CborError::UnexpectedEnd)?;
            if rest.len() < len {
                return Err(CborError::UnexpectedEnd);
            }
            let (bytes, r) = rest.split_at(len);
            (Value::Bytes(bytes.to_vec()), r)
        }
        MT_TEXT => {
            let len = usize::try_from(arg).map_err(|_| CborError::UnexpectedEnd)?;
            if rest.len() < len {
                return Err(CborError::UnexpectedEnd);
            }
            let (bytes, r) = rest.split_at(len);
            let s = std::str::from_utf8(bytes).map_err(|_| CborError::InvalidUtf8)?;
            (Value::Text(s.to_owned()), r)
        }
        MT_ARRAY => {
            let mut items = Vec::with_capacity(arg.min(1024) as usize);
            for _ in 0..arg {
                let (v, r) = decode_at(rest, depth + 1)?;
                items.push(v);
                rest = r;
            }
            (Value::Array(items), rest)
        }
        MT_MAP => {
            let mut entries = Vec::with_capacity(arg.min(1024) as usize);
            for _ in 0..arg {
                let (k, r) = decode_at(rest, depth + 1)?;
                let (v, r) = decode_at(r, depth + 1)?;
                entries.push((k, v));
                rest = r;
            }
            (Value::Map(entries), rest)
        }
        MT_SIMPLE => match additional {
            SIMPLE_FALSE => (Value::Bool(false), rest),
            SIMPLE_TRUE => (Value::Bool(true), rest),
            SIMPLE_NULL | SIMPLE_UNDEFINED => (Value::Null, rest),
            _ => return Err(CborError::UnsupportedAdditional(additional)),
        },
        _ => return Err(CborError::UnsupportedType(major)),
    })
}

/// Byte length of the one CBOR item at the start of `data`, from its
/// structure alone. Unlike [`decode`] it accepts tags (major 6) and floats /
/// other simple values (major 7, additional 0..=27), so a large-blob element
/// keyroost can't interpret can still be measured, skipped and re-emitted
/// byte-for-byte. Indefinite lengths (additional 31) and reserved additional
/// values (28..=30) are refused; nesting obeys DECODE_DEPTH_LIMIT.
pub fn item_len(data: &[u8]) -> Result<usize, CborError> {
    item_len_at(data, 0)
}

fn item_len_at(data: &[u8], depth: usize) -> Result<usize, CborError> {
    if depth > DECODE_DEPTH_LIMIT {
        return Err(CborError::DepthLimit);
    }
    let (b, rest) = data.split_first().ok_or(CborError::UnexpectedEnd)?;
    let major = b >> 5;
    let additional = b & 0b1_1111;
    // read_arg consumes the 0/1/2/4/8 argument bytes after the initial byte.
    let (arg, after) = read_arg(rest, additional)?;
    let header = data.len() - after.len();
    let body_from = |len: usize| -> Result<usize, CborError> {
        let total = header.checked_add(len).ok_or(CborError::UnexpectedEnd)?;
        if total > data.len() {
            return Err(CborError::UnexpectedEnd);
        }
        Ok(total)
    };
    match major {
        MT_UINT | MT_NINT => Ok(header),
        MT_BYTES | MT_TEXT => {
            let len = usize::try_from(arg).map_err(|_| CborError::UnexpectedEnd)?;
            body_from(len)
        }
        MT_ARRAY | MT_MAP => {
            let count = if major == MT_MAP {
                arg.checked_mul(2).ok_or(CborError::UnexpectedEnd)?
            } else {
                arg
            };
            let mut at = header;
            for _ in 0..count {
                let len = item_len_at(&data[at..], depth + 1)?;
                at = at.checked_add(len).ok_or(CborError::UnexpectedEnd)?;
            }
            Ok(at)
        }
        MT_TAG => {
            let len = item_len_at(&data[header..], depth + 1)?;
            body_from(len)
        }
        // MT_SIMPLE: additional 0..=23 is the value itself, 24 one more byte,
        // 25/26/27 a half/single/double float — exactly read_arg's consumption.
        _ => Ok(header),
    }
}

/// The raw bytes of every element of the definite-length array at the
/// start of `data`, and the bytes after the array.
pub fn split_array(data: &[u8]) -> Result<(Vec<&[u8]>, &[u8]), CborError> {
    let (b, rest) = data.split_first().ok_or(CborError::UnexpectedEnd)?;
    let major = b >> 5;
    if major != MT_ARRAY {
        return Err(CborError::UnsupportedType(major));
    }
    let (count, mut rest) = read_arg(rest, b & 0b1_1111)?;
    let mut items = Vec::with_capacity(count.min(1024) as usize);
    for _ in 0..count {
        let len = item_len_at(rest, 1)?;
        let (item, r) = rest.split_at(len);
        items.push(item);
        rest = r;
    }
    Ok((items, rest))
}

/// Canonical (shortest) header for a definite-length array of `len` items.
pub fn array_header(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(9);
    encode_header(&mut out, MT_ARRAY, len as u64);
    out
}

fn read_arg(rest: &[u8], additional: u8) -> Result<(u64, &[u8]), CborError> {
    match additional {
        0..=23 => Ok((additional as u64, rest)),
        24 => {
            let (a, r) = rest.split_first().ok_or(CborError::UnexpectedEnd)?;
            Ok((*a as u64, r))
        }
        25 => {
            if rest.len() < 2 {
                return Err(CborError::UnexpectedEnd);
            }
            let (a, r) = rest.split_at(2);
            Ok((u16::from_be_bytes([a[0], a[1]]) as u64, r))
        }
        26 => {
            if rest.len() < 4 {
                return Err(CborError::UnexpectedEnd);
            }
            let (a, r) = rest.split_at(4);
            Ok((u32::from_be_bytes([a[0], a[1], a[2], a[3]]) as u64, r))
        }
        27 => {
            if rest.len() < 8 {
                return Err(CborError::UnexpectedEnd);
            }
            let (a, r) = rest.split_at(8);
            Ok((
                u64::from_be_bytes([a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]]),
                r,
            ))
        }
        _ => Err(CborError::UnsupportedAdditional(additional)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(v: Value, expected_bytes: &[u8]) {
        let bytes = encode(&v);
        assert_eq!(bytes, expected_bytes, "encode mismatch for {:?}", v);
        let (decoded, rest) = decode(&bytes).expect("decode");
        assert!(rest.is_empty(), "trailing bytes after decode");
        assert_eq!(decoded, v);
    }

    #[test]
    fn uint_inline() {
        roundtrip(Value::UInt(0), &[0x00]);
        roundtrip(Value::UInt(23), &[0x17]);
    }

    #[test]
    fn uint_one_byte() {
        roundtrip(Value::UInt(24), &[0x18, 0x18]);
        roundtrip(Value::UInt(255), &[0x18, 0xFF]);
    }

    #[test]
    fn uint_two_bytes() {
        roundtrip(Value::UInt(256), &[0x19, 0x01, 0x00]);
        roundtrip(Value::UInt(65535), &[0x19, 0xFF, 0xFF]);
    }

    #[test]
    fn uint_four_bytes() {
        roundtrip(Value::UInt(65536), &[0x1A, 0x00, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn nint_basic() {
        // -1 encodes as NInt(0)
        roundtrip(Value::NInt(0), &[0x20]);
        roundtrip(Value::NInt(23), &[0x37]);
    }

    #[test]
    fn byte_string() {
        roundtrip(Value::Bytes(vec![]), &[0x40]);
        roundtrip(Value::Bytes(vec![0xAA, 0xBB]), &[0x42, 0xAA, 0xBB]);
    }

    #[test]
    fn text_string() {
        roundtrip(Value::Text("hi".into()), &[0x62, b'h', b'i']);
    }

    #[test]
    fn array_of_uints() {
        roundtrip(
            Value::Array(vec![Value::UInt(1), Value::UInt(2), Value::UInt(3)]),
            &[0x83, 0x01, 0x02, 0x03],
        );
    }

    #[test]
    fn map_with_uint_keys() {
        roundtrip(
            Value::Map(vec![
                (Value::UInt(1), Value::Text("a".into())),
                (Value::UInt(2), Value::Text("b".into())),
            ]),
            &[0xA2, 0x01, 0x61, b'a', 0x02, 0x61, b'b'],
        );
    }

    #[test]
    fn bool_and_null() {
        roundtrip(Value::Bool(false), &[0xF4]);
        roundtrip(Value::Bool(true), &[0xF5]);
        roundtrip(Value::Null, &[0xF6]);
    }

    #[test]
    fn map_lookup_by_uint_key() {
        let m = Value::Map(vec![
            (Value::UInt(1), Value::Text("first".into())),
            (Value::UInt(3), Value::UInt(42)),
        ]);
        assert_eq!(m.get_uint_key(1).and_then(|v| v.as_text()), Some("first"));
        assert_eq!(m.get_uint_key(3).and_then(|v| v.as_uint()), Some(42));
        assert!(m.get_uint_key(99).is_none());
    }

    #[test]
    fn decode_real_getinfo_response_shape() {
        // Synthesized but realistic shape: map { 1: ["FIDO_2_0"], 3: <16-byte aaguid> }
        let aaguid = [0xABu8; 16];
        let value = Value::Map(vec![
            (
                Value::UInt(1),
                Value::Array(vec![Value::Text("FIDO_2_0".into())]),
            ),
            (Value::UInt(3), Value::Bytes(aaguid.to_vec())),
        ]);
        let bytes = encode(&value);
        let (decoded, _) = decode(&bytes).unwrap();
        let versions = decoded.get_uint_key(1).and_then(|v| v.as_array()).unwrap();
        assert_eq!(versions[0].as_text(), Some("FIDO_2_0"));
        let id = decoded.get_uint_key(3).and_then(|v| v.as_bytes()).unwrap();
        assert_eq!(id, &aaguid);
    }

    #[test]
    fn decode_truncated_input_errors() {
        // Says "byte string of length 5" but supplies only 3 bytes.
        let bytes = [0x45, 0x01, 0x02, 0x03];
        let result = decode(&bytes);
        assert!(matches!(result, Err(CborError::UnexpectedEnd)));
    }

    #[test]
    fn decode_depth_limit_enforced() {
        // 18 levels of nested array exceeds the limit of 16.
        let mut buf = vec![0x81; 18];
        buf.push(0x00);
        let result = decode(&buf);
        assert!(matches!(result, Err(CborError::DepthLimit)));
    }

    #[test]
    fn item_len_measures_every_major_type() {
        let cases: &[(&[u8], usize)] = &[
            (&[0x00], 1),
            (&[0x18, 0xff], 2),
            (&[0x39, 0x01, 0x00], 3),
            (&[0x43, 0x01, 0x02, 0x03], 4),
            (&[0x62, 0x6f, 0x6b], 3),
            (&[0x82, 0x01, 0x02], 3),
            (&[0xa1, 0x01, 0x02], 3),
        ];
        for (bytes, want) in cases {
            assert_eq!(item_len(bytes).unwrap(), *want, "{bytes:02x?}");
        }
        // Trailing bytes after the item are not counted.
        assert_eq!(item_len(&[0x01, 0xff, 0xff]).unwrap(), 1);
    }

    #[test]
    fn item_len_accepts_tags_and_floats() {
        let mut f64_item = vec![0xfb];
        f64_item.extend_from_slice(&[0x40, 0x09, 0x21, 0xfb, 0x54, 0x44, 0x2d, 0x18]);
        let cases: &[(&[u8], usize)] = &[
            (&[0xc1, 0x1a, 0x51, 0x4b, 0x67, 0xb0], 6),
            (&[0xf9, 0x3c, 0x00], 3),
            (&[0xfa, 0x47, 0xc3, 0x50, 0x00], 5),
            (&f64_item, 9),
            (&[0xf7], 1),
            (&[0xa1, 0x01, 0xf9, 0x3c, 0x00], 5),
        ];
        for (bytes, want) in cases {
            assert_eq!(item_len(bytes).unwrap(), *want, "{bytes:02x?}");
        }
    }

    #[test]
    fn item_len_refuses_indefinite_and_truncated() {
        assert!(item_len(&[0x9f, 0x01, 0xff]).is_err());
        assert!(item_len(&[0x5f, 0x41, 0x01, 0xff]).is_err());
        assert!(matches!(
            item_len(&[0x43, 0x01]),
            Err(CborError::UnexpectedEnd)
        ));
        assert!(item_len(&[0x1c]).is_err());
        assert!(matches!(item_len(&[]), Err(CborError::UnexpectedEnd)));
        // Truncated inside a container and inside a tag.
        assert!(matches!(
            item_len(&[0x82, 0x01]),
            Err(CborError::UnexpectedEnd)
        ));
        assert!(matches!(item_len(&[0xc1]), Err(CborError::UnexpectedEnd)));
        // A huge declared length fails cleanly instead of overflowing.
        let huge = [0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert!(item_len(&huge).is_err());
    }

    #[test]
    fn item_len_obeys_depth_limit() {
        let mut buf = vec![0x81; 17];
        buf.push(0x00);
        assert!(matches!(item_len(&buf), Err(CborError::DepthLimit)));
        // Tags nest too.
        let mut tags = vec![0xc1; 17];
        tags.push(0x00);
        assert!(matches!(item_len(&tags), Err(CborError::DepthLimit)));
        // 16 levels is still fine.
        let mut ok = vec![0x81; 16];
        ok.push(0x00);
        assert_eq!(item_len(&ok).unwrap(), 17);
    }

    #[test]
    fn split_array_returns_each_element_raw() {
        let bytes = [0x83, 0x01, 0xf9, 0x3c, 0x00, 0xa1, 0x01, 0x02, 0xff];
        let (items, rest) = split_array(&bytes).unwrap();
        assert_eq!(
            items,
            vec![
                &[0x01][..],
                &[0xf9, 0x3c, 0x00][..],
                &[0xa1, 0x01, 0x02][..]
            ]
        );
        assert_eq!(rest, &[0xff]);
    }

    #[test]
    fn split_array_rejects_non_array() {
        assert!(split_array(&[0xa0]).is_err());
        assert!(split_array(&[]).is_err());
        assert!(split_array(&[0x9f, 0xff]).is_err());
        assert!(matches!(
            split_array(&[0x82, 0x01]),
            Err(CborError::UnexpectedEnd)
        ));
    }

    #[test]
    fn array_header_is_shortest() {
        assert_eq!(array_header(0), vec![0x80]);
        assert_eq!(array_header(23), vec![0x97]);
        assert_eq!(array_header(24), vec![0x98, 0x18]);
        assert_eq!(array_header(300), vec![0x99, 0x01, 0x2c]);
    }
}
