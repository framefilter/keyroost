//! Google Authenticator export ("otpauth-migration://offline?data=…") parsing.
//!
//! The `data` parameter is base64 of a protobuf `MigrationPayload`:
//!
//! ```text
//! message MigrationPayload {
//!   repeated OtpParameters otp_parameters = 1;
//!   int32 version = 2;            // (ignored: payload is self-describing)
//!   int32 batch_size = 3;         // number of QR codes in the export
//!   int32 batch_index = 4;        // which one this is (0-based)
//! }
//! message OtpParameters {
//!   bytes  secret    = 1;         // raw key bytes (NOT base32)
//!   string name      = 2;         // "Issuer:account" or just account
//!   string issuer    = 3;
//!   enum?  algorithm = 4;         // 1=SHA1 2=SHA256 3=SHA512 4=MD5
//!   enum?  digits    = 5;         // 1=six 2=eight (an enum, not a count!)
//!   enum?  type      = 6;         // 1=HOTP 2=TOTP
//!   int64  counter   = 7;         // HOTP only
//! }
//! ```
//!
//! The wire format only needs varints and length-delimited fields, so the
//! reader below is ~60 lines of bounds-checked code rather than a protobuf
//! dependency — consistent with the workspace's vendoring policy. Unknown
//! fields are skipped (forward compatibility); entries the Molto2 can't
//! represent (HOTP, SHA-512/MD5, out-of-range secrets) are reported as
//! [`Skipped`] rather than failing the whole batch — a user migrating 20
//! accounts shouldn't lose 19 because one is HOTP.

use crate::bulk::{BulkEntry, BulkError};
use keyroost_proto::codec::base64_decode;
use keyroost_proto::commands::{HmacAlgo, OtpDigits, TimeStep};

/// An entry that couldn't be converted, and the human-readable reason.
#[derive(Debug)]
pub struct Skipped {
    /// `issuer:account` (or whatever subset the entry carried).
    pub label: String,
    pub reason: &'static str,
}

/// Outcome of parsing one migration QR payload.
#[derive(Debug)]
pub struct Migration {
    pub entries: Vec<BulkEntry>,
    pub skipped: Vec<Skipped>,
    /// `(batch_index, batch_size)` when the export spans several QR codes —
    /// front-ends should tell the user to scan the rest.
    pub batch: Option<(u32, u32)>,
}

/// True when `uri` looks like a Google Authenticator export.
pub fn is_migration_uri(uri: &str) -> bool {
    uri.trim_start().starts_with("otpauth-migration://")
}

/// Parse an `otpauth-migration://offline?data=…` URI.
pub fn parse(uri: &str) -> Result<Migration, BulkError> {
    let uri = uri.trim();
    let rest =
        uri.strip_prefix("otpauth-migration://offline")
            .ok_or(BulkError::UnsupportedFormat(
                "not an otpauth-migration://offline URI",
            ))?;
    let query = rest.strip_prefix('?').unwrap_or(rest);
    let mut data = None;
    for kv in query.split('&') {
        if let Some(v) = kv.strip_prefix("data=") {
            data = Some(v);
        }
    }
    let data = data.ok_or(BulkError::UnsupportedFormat(
        "migration URI has no data= parameter",
    ))?;
    // The value may arrive percent-encoded (%2B %2F %3D) — decode that, but
    // do NOT apply form-decoding's '+'→space rule: '+' here is base64.
    // Both intermediates carry every seed in the batch (base64-coded and
    // raw), so they wipe on drop; the caller owns the URI string itself.
    let data = zeroize::Zeroizing::new(
        percent_decode_keep_plus(data)
            .ok_or(BulkError::UnsupportedFormat("bad percent-encoding in data"))?,
    );
    let payload = zeroize::Zeroizing::new(
        base64_decode(&data)
            .map_err(|_| BulkError::UnsupportedFormat("migration data is not valid base64"))?,
    );
    parse_payload(&payload)
}

/// Parse the raw protobuf `MigrationPayload`.
pub fn parse_payload(buf: &[u8]) -> Result<Migration, BulkError> {
    let mut entries = Vec::new();
    let mut skipped = Vec::new();
    let (mut batch_size, mut batch_index) = (None, None);

    let mut r = Reader(buf);
    while let Some((field, wire)) = r.key()? {
        match (field, wire) {
            (1, 2) => {
                let bytes = r.bytes()?;
                match convert(bytes)? {
                    Ok(e) => entries.push(e),
                    Err(s) => skipped.push(s),
                }
            }
            (3, 0) => batch_size = Some(r.varint()? as u32),
            (4, 0) => batch_index = Some(r.varint()? as u32),
            _ => r.skip(wire)?,
        }
    }

    let batch = match (batch_index, batch_size) {
        (Some(i), Some(n)) if n > 1 => Some((i, n)),
        _ => None,
    };
    if entries.is_empty() && skipped.is_empty() {
        return Err(BulkError::UnsupportedFormat(
            "migration payload contains no accounts",
        ));
    }
    Ok(Migration {
        entries,
        skipped,
        batch,
    })
}

/// Convert one `OtpParameters` message; `Err` is the skip reason.
#[allow(clippy::type_complexity)]
fn convert(buf: &[u8]) -> Result<Result<BulkEntry, Skipped>, BulkError> {
    let mut secret: &[u8] = &[];
    let mut name = String::new();
    let mut issuer = String::new();
    let (mut algorithm, mut digits, mut typ) = (0u64, 0u64, 0u64);

    let mut r = Reader(buf);
    while let Some((field, wire)) = r.key()? {
        match (field, wire) {
            (1, 2) => secret = r.bytes()?,
            (2, 2) => name = String::from_utf8_lossy(r.bytes()?).into_owned(),
            (3, 2) => issuer = String::from_utf8_lossy(r.bytes()?).into_owned(),
            (4, 0) => algorithm = r.varint()?,
            (5, 0) => digits = r.varint()?,
            (6, 0) => typ = r.varint()?,
            _ => r.skip(wire)?,
        }
    }

    let label = if issuer.is_empty() {
        name.clone()
    } else if name.is_empty() {
        issuer.clone()
    } else {
        format!("{}:{}", issuer, name)
    };
    let skip = |reason| {
        Ok(Err(Skipped {
            label: label.clone(),
            reason,
        }))
    };

    // type: 0 (unspecified) is treated as TOTP, matching other importers.
    if typ != 0 && typ != 2 {
        return skip("HOTP is not supported by the Molto2");
    }
    let algorithm = match algorithm {
        0 | 1 => HmacAlgo::Sha1, // unspecified defaults to SHA-1
        2 => HmacAlgo::Sha256,
        _ => return skip("only SHA-1 / SHA-256 are supported"),
    };
    let digits = match digits {
        0 | 1 => OtpDigits::Six, // unspecified defaults to 6
        2 => OtpDigits::Eight,
        _ => return skip("unsupported digit count"),
    };
    if secret.is_empty() || secret.len() > 63 {
        return skip("secret must be 1..=63 bytes");
    }

    // "Issuer:account" labels: prefer the explicit issuer field.
    let (label_issuer, account) = match name.split_once(':') {
        Some((i, a)) => (Some(i.trim().to_owned()), Some(a.trim().to_owned())),
        None if name.is_empty() => (None, None),
        None => (None, Some(name.trim().to_owned())),
    };
    let issuer = if issuer.is_empty() {
        label_issuer
    } else {
        Some(issuer)
    }
    .filter(|s| !s.is_empty());

    Ok(Ok(BulkEntry {
        issuer,
        account: account.filter(|s| !s.is_empty()),
        secret: secret.to_vec(),
        algorithm,
        digits,
        time_step: TimeStep::Seconds30, // GA exports are always 30s
    }))
}

/// Minimal protobuf wire reader: varints (wire 0) and length-delimited
/// fields (wire 2), with skipping for fixed64/fixed32. Every read is
/// bounds-checked; malformed input yields an error, never a panic.
struct Reader<'a>(&'a [u8]);

const MALFORMED: BulkError = BulkError::UnsupportedFormat("malformed migration protobuf");

impl<'a> Reader<'a> {
    /// Next `(field_number, wire_type)`, or `None` at end of input.
    fn key(&mut self) -> Result<Option<(u64, u8)>, BulkError> {
        if self.0.is_empty() {
            return Ok(None);
        }
        let k = self.varint()?;
        Ok(Some((k >> 3, (k & 0x7) as u8)))
    }

    fn varint(&mut self) -> Result<u64, BulkError> {
        let mut v: u64 = 0;
        for i in 0..10 {
            let (b, rest) = self.0.split_first().ok_or(MALFORMED)?;
            self.0 = rest;
            v |= u64::from(b & 0x7f) << (7 * i);
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err(MALFORMED) // varint longer than 10 bytes
    }

    fn bytes(&mut self) -> Result<&'a [u8], BulkError> {
        let len = usize::try_from(self.varint()?).map_err(|_| MALFORMED)?;
        if self.0.len() < len {
            return Err(MALFORMED);
        }
        let (b, rest) = self.0.split_at(len);
        self.0 = rest;
        Ok(b)
    }

    fn skip(&mut self, wire: u8) -> Result<(), BulkError> {
        match wire {
            0 => {
                self.varint()?;
            }
            1 => self.0 = self.0.get(8..).ok_or(MALFORMED)?,
            2 => {
                self.bytes()?;
            }
            5 => self.0 = self.0.get(4..).ok_or(MALFORMED)?,
            _ => return Err(MALFORMED), // groups (3/4) and reserved types
        }
        Ok(())
    }
}

/// Percent-decode without the '+'→space rule (that rule is for
/// form-encoding; in a migration URI '+' is a base64 character).
fn percent_decode_keep_plus(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hi = hex_nibble(*bytes.get(i + 1)?)?;
            let lo = hex_nibble(*bytes.get(i + 2)?)?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-built protobuf: the test constructs the bytes field-by-field so
    /// the expected layout is visible (and independent of any encoder).
    fn otp_params(
        secret: &[u8],
        name: &str,
        issuer: &str,
        algo: u8,
        digits: u8,
        typ: u8,
    ) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend([0x0a, secret.len() as u8]); // field 1, wire 2
        m.extend(secret);
        m.extend([0x12, name.len() as u8]);
        m.extend(name.as_bytes());
        m.extend([0x1a, issuer.len() as u8]);
        m.extend(issuer.as_bytes());
        m.extend([0x20, algo]); // field 4, wire 0
        m.extend([0x28, digits]);
        m.extend([0x30, typ]);
        m
    }

    fn payload(params: &[Vec<u8>]) -> Vec<u8> {
        let mut p = Vec::new();
        for m in params {
            p.extend([0x0a, m.len() as u8]);
            p.extend(m);
        }
        p.extend([0x10, 1]); // version = 1
        p.extend([0x18, 1]); // batch_size = 1
        p.extend([0x20, 0]); // batch_index = 0
        p
    }

    #[test]
    fn migration_round_trip() {
        let p = payload(&[
            otp_params(b"0123456789", "Acme:alice", "Acme", 1, 1, 2),
            otp_params(b"counterkey", "Legacy", "", 1, 1, 1), // HOTP → skipped
        ]);
        let b64 = {
            // tiny local encoder for the test
            const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut s = String::new();
            for c in p.chunks(3) {
                let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
                let n = u32::from_be_bytes([0, b[0], b[1], b[2]]);
                for i in 0..=c.len() {
                    s.push(A[(n >> (18 - 6 * i) & 0x3f) as usize] as char);
                }
                for _ in c.len()..3 {
                    s.push('=');
                }
            }
            s
        };
        // percent-encode the padding the way a QR-embedded URI would.
        let uri = format!(
            "otpauth-migration://offline?data={}",
            b64.replace('+', "%2B")
                .replace('/', "%2F")
                .replace('=', "%3D")
        );

        let m = parse(&uri).expect("parse");
        assert_eq!(m.entries.len(), 1);
        assert_eq!(m.skipped.len(), 1);
        assert_eq!(m.batch, None); // batch_size 1 → not multi-part
        let e = &m.entries[0];
        assert_eq!(e.secret, b"0123456789");
        assert_eq!(e.issuer.as_deref(), Some("Acme"));
        assert_eq!(e.account.as_deref(), Some("alice"));
        assert!(m.skipped[0].reason.contains("HOTP"));
    }

    #[test]
    fn multi_batch_reported() {
        let mut p = vec![0x0a];
        let m1 = otp_params(b"k", "a", "", 1, 1, 2);
        p.push(m1.len() as u8);
        p.extend(&m1);
        p.extend([0x18, 3]); // batch_size = 3
        p.extend([0x20, 1]); // batch_index = 1
        let m = parse_payload(&p).expect("parse");
        assert_eq!(m.batch, Some((1, 3)));
    }

    #[test]
    fn malformed_never_panics() {
        // Truncated length prefix, runaway varint, huge declared length.
        for bad in [
            &[0x0a, 0xff][..],
            &[
                0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
            ][..],
            &[0x0a, 0x7f, 0x00][..],
        ] {
            assert!(parse_payload(bad).is_err());
        }
        assert!(parse("otpauth-migration://offline?data=!!!").is_err());
        assert!(parse("otpauth://totp/x?secret=A").is_err());
    }
}
