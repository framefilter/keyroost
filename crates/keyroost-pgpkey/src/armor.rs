//! ASCII armor (RFC 4880 section 6) with an in-crate base64 codec.

use crate::Error;

/// What an armored block contains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Kind {
    PrivateKey,
    PublicKey,
    Signature,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Kind::PrivateKey => "PRIVATE KEY BLOCK",
            Kind::PublicKey => "PUBLIC KEY BLOCK",
            Kind::Signature => "SIGNATURE",
        }
    }
}

/// CRC-24 as defined in RFC 4880 section 6.1.
pub(crate) fn crc24(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xB7_04CE;
    for &b in data {
        crc ^= (b as u32) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x100_0000 != 0 {
                crc ^= 0x186_4CFB;
            }
        }
    }
    crc & 0xFF_FFFF
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = (chunk[0] as u32) << 16
            | (*chunk.get(1).unwrap_or(&0) as u32) << 8
            | *chunk.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= chunk.len() {
                s.push(ALPHABET[(n >> (18 - 6 * i) & 0x3F) as usize] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}

fn b64_decode(text: &str) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut nbits = 0u32;
    let mut pad = 0usize;
    for c in text.bytes() {
        if c.is_ascii_whitespace() {
            continue;
        }
        if c == b'=' {
            pad += 1;
            continue;
        }
        if pad > 0 {
            return Err(Error::Malformed("bad base64"));
        }
        let v = ALPHABET
            .iter()
            .position(|&a| a == c)
            .ok_or(Error::Malformed("bad base64"))? as u32;
        acc = acc << 6 | v;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
            acc &= (1 << nbits) - 1;
        }
    }
    if pad > 2 || (pad > 0 && (text.bytes().filter(|c| !c.is_ascii_whitespace()).count()) % 4 != 0)
    {
        return Err(Error::Malformed("bad base64"));
    }
    Ok(out)
}

/// Armor binary data: header, blank line, 64-column base64, CRC line, footer.
pub fn encode(kind: Kind, data: &[u8]) -> String {
    encode_with_comment(kind, data, None)
}

/// Like [`encode`], with an optional `Comment:` armor header line.
pub(crate) fn encode_with_comment(kind: Kind, data: &[u8], comment: Option<&str>) -> String {
    let body = b64_encode(data);
    let mut s = format!("-----BEGIN PGP {}-----\n", kind.label());
    if let Some(c) = comment {
        s.push_str(&format!("Comment: {c}\n"));
    }
    s.push('\n');
    for line in body.as_bytes().chunks(64) {
        // Base64 output is ASCII, so every chunk is valid UTF-8.
        s.push_str(std::str::from_utf8(line).unwrap_or_default());
        s.push('\n');
    }
    let crc = crc24(data);
    s.push('=');
    s.push_str(&b64_encode(&crc.to_be_bytes()[1..]));
    s.push('\n');
    s.push_str(&format!("-----END PGP {}-----\n", kind.label()));
    s
}

/// Largest armored text `decode` looks at (comfortably above the 1 MiB
/// binary limit of `packet::parse_packets`).
const MAX_TEXT: usize = 2 << 20;

/// Decode one armored block. Verifies the CRC when present; ignores armor
/// header lines such as `Comment:`; accepts CRLF line endings.
pub fn decode(text: &str) -> Result<(Kind, Vec<u8>), Error> {
    if text.len() > MAX_TEXT {
        return Err(Error::Malformed("file too large"));
    }
    let mut lines = text.lines().map(str::trim_end);
    let kind = loop {
        let line = lines.next().ok_or(Error::Malformed("no armor header"))?;
        if let Some(rest) = line.strip_prefix("-----BEGIN PGP ") {
            break match rest.strip_suffix("-----") {
                Some("PRIVATE KEY BLOCK") => Kind::PrivateKey,
                Some("PUBLIC KEY BLOCK") => Kind::PublicKey,
                Some("SIGNATURE") => Kind::Signature,
                _ => return Err(Error::Unsupported("armor type")),
            };
        }
    };
    // Armor headers run until the first blank line.
    for line in lines.by_ref() {
        if line.is_empty() {
            break;
        }
        if !line.contains(':') {
            return Err(Error::Malformed("bad armor header"));
        }
    }
    let mut body = String::new();
    let mut crc_text: Option<&str> = None;
    let mut ended = false;
    for line in lines {
        if let Some(rest) = line.strip_prefix("-----END PGP ") {
            if rest.strip_suffix("-----") != Some(kind.label()) {
                return Err(Error::Malformed("armor footer does not match its header"));
            }
            ended = true;
            break;
        }
        if let Some(c) = line.strip_prefix('=') {
            crc_text = Some(c);
        } else {
            body.push_str(line);
        }
    }
    if !ended {
        return Err(Error::Malformed("no armor footer"));
    }
    let data = b64_decode(&body)?;
    if let Some(c) = crc_text {
        let want = b64_decode(c)?;
        if want.len() != 3 {
            return Err(Error::Malformed("bad armor checksum"));
        }
        let want = (want[0] as u32) << 16 | (want[1] as u32) << 8 | want[2] as u32;
        if want != crc24(&data) {
            return Err(Error::BadChecksum);
        }
    }
    Ok((kind, data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc24_known_answer() {
        assert_eq!(crc24(b"123456789"), 0x21CF02);
    }
    #[test]
    fn armor_round_trip_and_crc_check() {
        let data = b"hello pgp".to_vec();
        let text = encode(Kind::PublicKey, &data);
        assert!(text.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n"));
        assert_eq!(decode(&text).unwrap(), (Kind::PublicKey, data));
        let bad = text.replacen("aGVsbG8", "aGVsbG9", 1);
        assert!(matches!(
            decode(&bad),
            Err(Error::BadChecksum) | Err(Error::Malformed(_))
        ));
    }
    #[test]
    fn footer_must_be_complete_and_match() {
        let text = encode(Kind::PublicKey, b"hello pgp");
        let cut = text.trim_end().trim_end_matches('-');
        assert!(decode(cut).is_err());
        let other = text.replace("END PGP PUBLIC", "END PGP PRIVATE");
        assert!(decode(&other).is_err());
        assert!(decode(&"A".repeat(MAX_TEXT + 1)).is_err());
    }
}
