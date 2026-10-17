//! OpenPGP packet framing and multiprecision integers (RFC 4880 section 3, 4).

use crate::Error;

/// Packet tag numbers used by this crate.
pub struct Tag;

impl Tag {
    pub const SIGNATURE: u8 = 2;
    pub const SECRET_KEY: u8 = 5;
    pub const PUBLIC_KEY: u8 = 6;
    pub const SECRET_SUBKEY: u8 = 7;
    pub const USER_ID: u8 = 13;
    pub const PUBLIC_SUBKEY: u8 = 14;
}

/// Largest input `parse_packets` will look at.
const MAX_INPUT: usize = 1 << 20;

/// Append one packet with a new-format header.
pub fn write_packet(out: &mut Vec<u8>, tag: u8, body: &[u8]) {
    out.push(0xC0 | (tag & 0x3F));
    let n = body.len();
    if n < 192 {
        out.push(n as u8);
    } else if n < 8384 {
        let m = n - 192;
        out.push(((m >> 8) + 192) as u8);
        out.push((m & 0xFF) as u8);
    } else {
        out.push(0xFF);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    }
    out.extend_from_slice(body);
}

/// Encode big-endian bytes as an MPI: leading zeros stripped, 2-byte bit
/// count, then the value. All-zero input gives a zero-bit MPI.
#[cfg(test)]
pub fn mpi(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + bytes.len());
    push_mpi(&mut out, bytes);
    out
}

/// Append `bytes` as an MPI to `out` (same encoding as [`mpi`]) without an
/// intermediate buffer, so secret values can go straight into a
/// pre-sized `Zeroizing` vector.
pub fn push_mpi(out: &mut Vec<u8>, bytes: &[u8]) {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let v = &bytes[start..];
    let bits = match v.first() {
        Some(&first) => (v.len() - 1) * 8 + (8 - first.leading_zeros() as usize),
        None => 0,
    };
    out.extend_from_slice(&(bits as u16).to_be_bytes());
    out.extend_from_slice(v);
}

/// Bounds-checked cursor over a byte slice. No method panics.
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::Truncated)?;
        let s = self.data.get(self.pos..end).ok_or(Error::Truncated)?;
        self.pos = end;
        Ok(s)
    }

    pub fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, Error> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn u32(&mut self) -> Result<u32, Error> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Read an MPI and return its value bytes (without the bit count).
    pub fn mpi(&mut self) -> Result<&'a [u8], Error> {
        let bits = self.u16()? as usize;
        self.take(bits.div_ceil(8))
    }

    /// Everything not yet read.
    pub fn rest(&mut self) -> Result<&'a [u8], Error> {
        let s = self.data.get(self.pos..).ok_or(Error::Truncated)?;
        self.pos = self.data.len();
        Ok(s)
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }
}

/// One framed packet: its tag and raw body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet<'a> {
    pub tag: u8,
    pub body: &'a [u8],
}

/// Split a binary OpenPGP stream into packets (new and old header formats).
pub fn parse_packets(data: &[u8]) -> Result<Vec<Packet<'_>>, Error> {
    if data.len() > MAX_INPUT {
        return Err(Error::Malformed("file too large"));
    }
    let mut r = Reader::new(data);
    let mut out = Vec::new();
    while !r.is_empty() {
        let hdr = r.u8()?;
        if hdr & 0x80 == 0 {
            return Err(Error::Malformed("bad packet header"));
        }
        let (tag, len) = if hdr & 0x40 != 0 {
            let tag = hdr & 0x3F;
            let first = r.u8()? as usize;
            let len = match first {
                0..=191 => first,
                192..=223 => ((first - 192) << 8) + r.u8()? as usize + 192,
                255 => r.u32()? as usize,
                _ => return Err(Error::Unsupported("partial-length packet")),
            };
            (tag, len)
        } else {
            let tag = (hdr >> 2) & 0x0F;
            let len = match hdr & 0x03 {
                0 => r.u8()? as usize,
                1 => r.u16()? as usize,
                2 => r.u32()? as usize,
                _ => return Err(Error::Unsupported("indeterminate-length packet")),
            };
            (tag, len)
        };
        out.push(Packet {
            tag,
            body: r.take(len)?,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mpi_strips_leading_zeros_and_counts_bits() {
        assert_eq!(mpi(&[0x00, 0x01, 0xFF]), vec![0x00, 0x09, 0x01, 0xFF]);
        assert_eq!(mpi(&[0x80]), vec![0x00, 0x08, 0x80]);
        assert_eq!(mpi(&[0x00]), vec![0x00, 0x00]);
    }
    #[test]
    fn packet_lengths_round_trip() {
        for n in [0usize, 191, 192, 8383, 8384, 70_000] {
            let body = vec![0xAB; n];
            let mut out = Vec::new();
            write_packet(&mut out, 6, &body);
            let pk = parse_packets(&out).unwrap();
            assert_eq!((pk[0].tag, pk[0].body.len()), (6, n));
        }
    }
    #[test]
    fn old_format_header_parses() {
        let pk = parse_packets(&[0x99, 0x00, 0x02, 0xAA, 0xBB]).unwrap();
        assert_eq!((pk[0].tag, pk[0].body), (6, &[0xAA, 0xBB][..]));
    }
    #[test]
    fn truncated_packet_is_an_error_not_a_panic() {
        assert!(parse_packets(&[0xC6, 0x05, 0x01]).is_err());
    }
}
