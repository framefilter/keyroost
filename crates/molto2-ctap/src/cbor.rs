//! Minimal CBOR codec scoped to CTAP2.
//!
//! Supports the major types CTAP authenticators actually use: unsigned and
//! negative integers, byte strings, text strings, arrays, maps, booleans,
//! and null. Indefinite-length items, tags, and floats are intentionally
//! unsupported — CTAP2 mandates canonical (definite-length, shortest-int)
//! encoding, so anything else from a real authenticator would be a protocol
//! violation.

use std::fmt;

const MT_UINT: u8 = 0;
const MT_NINT: u8 = 1;
const MT_BYTES: u8 = 2;
const MT_TEXT: u8 = 3;
const MT_ARRAY: u8 = 4;
const MT_MAP: u8 = 5;
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
            let len = arg as usize;
            if rest.len() < len {
                return Err(CborError::UnexpectedEnd);
            }
            let (bytes, r) = rest.split_at(len);
            (Value::Bytes(bytes.to_vec()), r)
        }
        MT_TEXT => {
            let len = arg as usize;
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
}
