//! Small encoding helpers used by the protocol layer.
//! No external dependencies.

#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    InvalidLength,
    InvalidChar,
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DecodeError::InvalidLength => write!(f, "invalid input length"),
            DecodeError::InvalidChar => write!(f, "invalid character in input"),
        }
    }
}

impl std::error::Error for DecodeError {}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, DecodeError> {
    let bytes = s.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(DecodeError::InvalidLength);
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks(2) {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(NIBBLES[(b >> 4) as usize] as char);
        s.push(NIBBLES[(b & 0x0f) as usize] as char);
    }
    s
}

const NIBBLES: &[u8; 16] = b"0123456789abcdef";

fn hex_nibble(c: u8) -> Result<u8, DecodeError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(DecodeError::InvalidChar),
    }
}

/// RFC 4648 base32 decode. Tolerates lowercase, trailing padding, spaces, and
/// dashes. Required: otpauth:// secrets are base32.
///
/// Strict where it matters for key material: `=` is only accepted at the end
/// (data after padding errors), and leftover bits past the last full byte
/// must be zero — a truncated or mistyped secret should fail here, not decode
/// "successfully" into a different seed that yields wrong OTPs.
pub fn base32_decode(s: &str) -> Result<Vec<u8>, DecodeError> {
    let mut buf: u64 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(s.len() * 5 / 8 + 1);
    let mut padded = false;
    for c in s.chars() {
        let v = match c {
            ' ' | '-' | '\t' | '\n' | '\r' => continue,
            '=' => {
                padded = true;
                continue;
            }
            _ if padded => return Err(DecodeError::InvalidChar),
            'A'..='Z' => c as u8 - b'A',
            'a'..='z' => c as u8 - b'a',
            '2'..='7' => c as u8 - b'2' + 26,
            _ => return Err(DecodeError::InvalidChar),
        };
        buf = (buf << 5) | v as u64;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    if bits > 0 && (buf & ((1u64 << bits) - 1)) != 0 {
        return Err(DecodeError::InvalidLength);
    }
    Ok(out)
}

/// RFC 4648 base64 decode, accepting both the standard (`+/`) and URL-safe
/// (`-_`) alphabets — Google Authenticator migration payloads arrive in
/// either depending on what percent-decoded them. Same strictness rules as
/// [`base32_decode`]: whitespace tolerated, `=` only at the end, nonzero
/// residual bits rejected. Required: otpauth-migration:// payloads.
pub fn base64_decode(s: &str) -> Result<Vec<u8>, DecodeError> {
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(s.len() * 3 / 4 + 1);
    let mut padded = false;
    for c in s.chars() {
        let v = match c {
            ' ' | '\t' | '\n' | '\r' => continue,
            '=' => {
                padded = true;
                continue;
            }
            _ if padded => return Err(DecodeError::InvalidChar),
            'A'..='Z' => c as u8 - b'A',
            'a'..='z' => c as u8 - b'a' + 26,
            '0'..='9' => c as u8 - b'0' + 52,
            '+' | '-' => 62,
            '/' | '_' => 63,
            _ => return Err(DecodeError::InvalidChar),
        };
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    if bits > 0 && (buf & ((1u32 << bits) - 1)) != 0 {
        return Err(DecodeError::InvalidLength);
    }
    Ok(out)
}

/// Standard base64 encode (RFC 4648, with `=` padding). Used to PEM-wrap DER.
pub fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18) as usize & 0x3F] as char);
        out.push(ALPHABET[(n >> 12) as usize & 0x3F] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 0x3F] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 0x3F] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_encode_matches_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        // round-trips through the decoder
        let data = b"\x00\x01\x02\xfe\xff\x10\x20\x30";
        assert_eq!(base64_decode(&base64_encode(data)).unwrap(), data);
    }

    #[test]
    fn hex_roundtrip() {
        let original = b"\x00\x01\x10\xff\xab";
        let s = hex_encode(original);
        assert_eq!(s, "000110ffab");
        assert_eq!(hex_decode(&s).unwrap(), original);
    }

    #[test]
    fn hex_accepts_uppercase() {
        assert_eq!(
            hex_decode("DEADBEEF").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
    }

    #[test]
    fn hex_rejects_odd_length() {
        assert_eq!(hex_decode("abc"), Err(DecodeError::InvalidLength));
    }

    #[test]
    fn base32_rfc_vectors() {
        // RFC 4648 §10
        assert_eq!(base32_decode("").unwrap(), b"");
        assert_eq!(base32_decode("MY======").unwrap(), b"f");
        assert_eq!(base32_decode("MZXQ====").unwrap(), b"fo");
        assert_eq!(base32_decode("MZXW6===").unwrap(), b"foo");
        assert_eq!(base32_decode("MZXW6YQ=").unwrap(), b"foob");
        assert_eq!(base32_decode("MZXW6YTB").unwrap(), b"fooba");
        assert_eq!(base32_decode("MZXW6YTBOI======").unwrap(), b"foobar");
    }

    #[test]
    fn base32_handles_whitespace_and_dashes() {
        let with_separators = "JBSW Y3DP-EHPK-3PXP";
        let clean = "JBSWY3DPEHPK3PXP";
        assert_eq!(
            base32_decode(with_separators).unwrap(),
            base32_decode(clean).unwrap()
        );
    }

    #[test]
    fn base32_is_case_insensitive() {
        assert_eq!(
            base32_decode("jbswy3dp").unwrap(),
            base32_decode("JBSWY3DP").unwrap()
        );
    }

    #[test]
    fn base32_rejects_data_after_padding() {
        assert_eq!(base32_decode("MY==MZ"), Err(DecodeError::InvalidChar));
        // Trailing whitespace after padding is still fine.
        assert_eq!(base32_decode("MY====== \n").unwrap(), b"f");
    }

    #[test]
    fn base64_rfc_vectors_and_strictness() {
        // RFC 4648 §10
        assert_eq!(base64_decode("").unwrap(), b"");
        assert_eq!(base64_decode("Zg==").unwrap(), b"f");
        assert_eq!(base64_decode("Zm8=").unwrap(), b"fo");
        assert_eq!(base64_decode("Zm9v").unwrap(), b"foo");
        assert_eq!(base64_decode("Zm9vYg==").unwrap(), b"foob");
        assert_eq!(base64_decode("Zm9vYmE=").unwrap(), b"fooba");
        assert_eq!(base64_decode("Zm9vYmFy").unwrap(), b"foobar");
        // URL-safe alphabet maps to the same values.
        assert_eq!(
            base64_decode("-_-_").unwrap(),
            base64_decode("+/+/").unwrap()
        );
        // Data after padding and nonzero residual bits are rejected.
        assert_eq!(base64_decode("Zg==Zg"), Err(DecodeError::InvalidChar));
        assert_eq!(base64_decode("Zh"), Err(DecodeError::InvalidLength));
        assert_eq!(base64_decode("Z!"), Err(DecodeError::InvalidChar));
    }

    #[test]
    fn base32_rejects_nonzero_trailing_bits() {
        // "MZ" carries 10 bits: one full byte plus residual 01 — a truncated
        // encoding, not a canonical one ("MY" is 'f' with residual 00).
        assert_eq!(base32_decode("MZ"), Err(DecodeError::InvalidLength));
        assert_eq!(base32_decode("MY").unwrap(), b"f");
    }
}
