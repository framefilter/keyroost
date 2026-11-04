//! Read-only decoding of OpenSSH certificates (the `*-cert-v01@openssh.com`
//! wire format described in OpenSSH's PROTOCOL.certkeys). This exists so the
//! large-blob Storage views can *recognize and display* a certificate an SSH
//! CA workflow parked on the key — type, key id, principals, validity,
//! critical options. It deliberately does NOT verify the CA signature; that
//! is the relying server's job, not a display surface's.

use keyroost_proto::codec::{base64_decode, base64_encode};

/// Certificate type field values (PROTOCOL.certkeys).
pub const CERT_TYPE_USER: u32 = 1;
pub const CERT_TYPE_HOST: u32 = 2;

/// The human-relevant fields of an OpenSSH certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshCertInfo {
    /// e.g. `ssh-ed25519-cert-v01@openssh.com`.
    pub key_type: String,
    pub serial: u64,
    /// [`CERT_TYPE_USER`] or [`CERT_TYPE_HOST`].
    pub cert_type: u32,
    pub key_id: String,
    pub principals: Vec<String>,
    /// Unix seconds; 0 = no lower bound.
    pub valid_after: u64,
    /// Unix seconds; `u64::MAX` = no upper bound ("forever").
    pub valid_before: u64,
    /// `(name, value)` pairs; value is empty for flag-style options.
    pub critical_options: Vec<(String, String)>,
    /// Extension names (values are conventionally empty).
    pub extensions: Vec<String>,
}

/// Cursor over SSH wire data: big-endian integers and u32-length-prefixed
/// byte strings.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let out = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(out)
    }

    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_be_bytes(b.try_into().unwrap()))
    }

    fn u64(&mut self) -> Option<u64> {
        self.take(8)
            .map(|b| u64::from_be_bytes(b.try_into().unwrap()))
    }

    fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }

    fn string(&mut self) -> Option<String> {
        std::str::from_utf8(self.bytes()?).ok().map(str::to_owned)
    }

    fn done(&self) -> bool {
        self.pos == self.buf.len()
    }
}

/// How many wire fields the embedded public key occupies for each supported
/// certificate type (they sit between the nonce and the serial). `mpint`s and
/// `string`s share the same length-prefixed wire shape, so a count suffices.
fn pubkey_field_count(key_type: &str) -> Option<usize> {
    Some(match key_type {
        "ssh-ed25519-cert-v01@openssh.com" => 1, // pk
        "ssh-rsa-cert-v01@openssh.com" => 2,     // e, n
        "ecdsa-sha2-nistp256-cert-v01@openssh.com"
        | "ecdsa-sha2-nistp384-cert-v01@openssh.com"
        | "ecdsa-sha2-nistp521-cert-v01@openssh.com" => 2, // curve, point
        "sk-ssh-ed25519-cert-v01@openssh.com" => 2, // pk, application
        "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com" => 3, // curve, point, application
        _ => return None,
    })
}

/// Parse a wire-format OpenSSH certificate. Returns `None` on anything that
/// is not a complete, well-formed certificate of a supported type — including
/// trailing bytes — so this can double as a classifier over arbitrary
/// large-blob entry bytes without false positives.
pub fn parse_wire(blob: &[u8]) -> Option<SshCertInfo> {
    let mut r = Reader::new(blob);
    let key_type = r.string()?;
    let pubkey_fields = pubkey_field_count(&key_type)?;
    let _nonce = r.bytes()?;
    for _ in 0..pubkey_fields {
        r.bytes()?;
    }
    let serial = r.u64()?;
    let cert_type = r.u32()?;
    if cert_type != CERT_TYPE_USER && cert_type != CERT_TYPE_HOST {
        return None;
    }
    let key_id = r.string()?;
    let principals = packed_strings(r.bytes()?)?;
    let valid_after = r.u64()?;
    let valid_before = r.u64()?;
    let critical_options = packed_pairs(r.bytes()?)?;
    let extensions = packed_pairs(r.bytes()?)?
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    let _reserved = r.bytes()?;
    let _signature_key = r.bytes()?;
    let _signature = r.bytes()?;
    if !r.done() {
        return None;
    }
    Some(SshCertInfo {
        key_type,
        serial,
        cert_type,
        key_id,
        principals,
        valid_after,
        valid_before,
        critical_options,
        extensions,
    })
}

/// A buffer holding zero or more concatenated wire strings (the principals
/// section).
fn packed_strings(buf: &[u8]) -> Option<Vec<String>> {
    let mut r = Reader::new(buf);
    let mut out = Vec::new();
    while !r.done() {
        out.push(r.string()?);
    }
    Some(out)
}

/// A buffer holding zero or more `(string name, string data)` tuples, where
/// `data` is either empty or itself a single wire string (the critical
/// options and extensions sections).
fn packed_pairs(buf: &[u8]) -> Option<Vec<(String, String)>> {
    let mut r = Reader::new(buf);
    let mut out = Vec::new();
    while !r.done() {
        let name = r.string()?;
        let data = r.bytes()?;
        let value = if data.is_empty() {
            String::new()
        } else {
            let mut inner = Reader::new(data);
            let v = inner.string()?;
            if !inner.done() {
                return None;
            }
            v
        };
        out.push((name, value));
    }
    Some(out)
}

/// Render a Unix timestamp as `YYYY-MM-DD HH:MM:SS UTC` without pulling in a
/// date crate. Civil-from-days per Howard Hinnant's algorithm.
pub fn format_timestamp(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        y,
        m,
        d,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Human validity window. OpenSSH treats `(0, u64::MAX)` as unbounded.
pub fn format_validity(valid_after: u64, valid_before: u64) -> String {
    if valid_after == 0 && valid_before == u64::MAX {
        return "always valid".to_string();
    }
    let from = if valid_after == 0 {
        "beginning of time".to_string()
    } else {
        format_timestamp(valid_after)
    };
    let to = if valid_before == u64::MAX {
        "forever".to_string()
    } else {
        format_timestamp(valid_before)
    };
    format!("{from} to {to}")
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (y + i64::from(m <= 2), m, d)
}

/// Parse the text form of a certificate — the single `-cert.pub` line
/// (`<type> <base64> [comment]`). Returns the decoded fields plus the raw
/// wire blob so callers can export or re-store the canonical bytes. The
/// declared type must match the type embedded in the blob.
pub fn parse_text(s: &str) -> Option<(SshCertInfo, Vec<u8>)> {
    let mut parts = s.split_ascii_whitespace();
    let declared = parts.next()?;
    if !declared.ends_with("-cert-v01@openssh.com") {
        return None;
    }
    let wire = base64_decode(parts.next()?).ok()?;
    let info = parse_wire(&wire)?;
    if info.key_type != declared {
        return None;
    }
    Some((info, wire))
}

/// A certificate as a key stores it in large-blob storage: OpenSSH's binary
/// (wire) form, or the text of a `-cert.pub` file, as `fido2-token -S -b`
/// stores one. `cert_pub` is what to write back out: stored text that is
/// exactly one plain `-cert.pub` line as it was (comment and all, so the
/// file comes back byte for byte), otherwise the certificate re-encoded by
/// [`to_cert_pub`]. The stored bytes come from the key, so nothing beyond
/// that one checked line is ever written out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCert {
    pub info: SshCertInfo,
    pub wire: Vec<u8>,
    pub cert_pub: String,
}

/// Recognize a certificate stored in either form ([`StoredCert`]); `None`
/// when the bytes are neither.
pub fn from_stored(bytes: &[u8]) -> Option<StoredCert> {
    if let Some(info) = parse_wire(bytes) {
        return Some(StoredCert {
            info,
            wire: bytes.to_vec(),
            cert_pub: to_cert_pub(bytes)?,
        });
    }
    let text = std::str::from_utf8(bytes).ok()?;
    let (info, wire) = parse_text(text.trim())?;
    let cert_pub = match plain_cert_line(text) {
        Some(line) => format!("{line}\n"),
        None => to_cert_pub(&wire)?,
    };
    Some(StoredCert {
        info,
        wire,
        cert_pub,
    })
}

/// `text` as one `-cert.pub` line safe to write back as it is: a single
/// line (a final newline allowed) of printable ASCII, so a comment can carry
/// no control, direction or invisible characters and no second line.
fn plain_cert_line(text: &str) -> Option<&str> {
    let line = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text);
    line.bytes()
        .all(|b| (0x20..0x7f).contains(&b))
        .then_some(line)
}

/// Re-encode a wire-format certificate as the body of a `-cert.pub` file:
/// `<type> <base64>\n`. Returns `None` if the bytes are not a certificate.
pub fn to_cert_pub(wire: &[u8]) -> Option<String> {
    let info = parse_wire(wire)?;
    Some(format!("{} {}\n", info.key_type, base64_encode(wire)))
}

/// A safe `-cert.pub` filename derived from an SSH credential's RP id. Every
/// character outside `[A-Za-z0-9._-]` is replaced with `_`, so the result is
/// always a single path component — no `/`, `\`, or other separator can
/// survive, defeating path traversal from a hostile (device-derived) RP id.
pub fn default_cert_filename(rp_id: &str) -> String {
    let safe: String = rp_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("{safe}-cert.pub")
}

/// Test fixture shared with large_blobs' classification tests.
#[cfg(test)]
pub(crate) mod tests_fixture {
    /// Real ed25519 user certificate produced by ssh-keygen from throwaway
    /// keys (see the Tier A plan for the exact invocation). The base64 body
    /// is the wire-format certificate blob.
    pub const FIXTURE_CERT_PUB: &str = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIFnHByOSs9oyjoM3FSMYa4CyEkl9qj7cPldTCWBGw3soAAAAIB8WYDicxYHAvQ5QE8w24ZO0pod+x5Y7Zcjdk8D3kOpZAAAAAAAAACoAAAABAAAAC3Rlc3Qta2V5LWlkAAAAEAAAAAVhbGljZQAAAANib2IAAAAAaVW5AAAAAABrNuyAAAAAJgAAAA5zb3VyY2UtYWRkcmVzcwAAABAAAAAMMTkyLjAuMi4wLzI0AAAAEgAAAApwZXJtaXQtcHR5AAAAAAAAAAAAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIOkAWA6QeBu6LNDfyV4zAgonPK7XpSmq9aFdozDaQr76AAAAUwAAAAtzc2gtZWQyNTUxOQAAAEAEeDetmfpeDeQHbXOGfLlLg9XHjJQpaXg1foE9TuNXWP3Bx3oCk4Foa8S7VkuXtK0geecTqa4WZGF9dM6VSWgI user";
}

#[cfg(test)]
mod tests {
    use super::tests_fixture::FIXTURE_CERT_PUB;
    use super::*;

    fn fixture_wire() -> Vec<u8> {
        let b64 = FIXTURE_CERT_PUB.split_ascii_whitespace().nth(1).unwrap();
        base64_decode(b64).unwrap()
    }

    #[test]
    fn parses_real_ed25519_user_cert() {
        let info = parse_wire(&fixture_wire()).unwrap();
        assert_eq!(info.key_type, "ssh-ed25519-cert-v01@openssh.com");
        assert_eq!(info.serial, 42);
        assert_eq!(info.cert_type, CERT_TYPE_USER);
        assert_eq!(info.key_id, "test-key-id");
        assert_eq!(
            info.principals,
            vec!["alice".to_string(), "bob".to_string()]
        );
        assert_eq!(info.valid_after, 1767225600);
        assert_eq!(info.valid_before, 1798761600);
        assert_eq!(
            info.critical_options,
            vec![("source-address".to_string(), "192.0.2.0/24".to_string())]
        );
        assert_eq!(info.extensions, vec!["permit-pty".to_string()]);
    }

    #[test]
    fn rejects_non_certificates() {
        // Not even a length-prefixed string.
        assert!(parse_wire(&[0xde, 0xad, 0xbe, 0xef]).is_none());
        // Empty input.
        assert!(parse_wire(&[]).is_none());
        // A valid-looking type string but nothing after it.
        let mut b = Vec::new();
        b.extend_from_slice(&32u32.to_be_bytes());
        b.extend_from_slice(b"ssh-ed25519-cert-v01@openssh.com");
        assert!(parse_wire(&b).is_none());
        // Truncated real cert: cut the last 10 bytes off.
        let wire = fixture_wire();
        assert!(parse_wire(&wire[..wire.len() - 10]).is_none());
        // Trailing junk after a real cert must also be rejected (strictness
        // keeps classification from matching almost-certs).
        let mut padded = fixture_wire();
        padded.push(0x00);
        assert!(parse_wire(&padded).is_none());
    }

    #[test]
    fn formats_timestamps_and_validity() {
        assert_eq!(format_timestamp(1767225600), "2026-01-01 00:00:00 UTC");
        assert_eq!(format_timestamp(0), "1970-01-01 00:00:00 UTC");
        // OpenSSH convention: the all-1s valid_before means "forever".
        assert_eq!(format_validity(0, u64::MAX), "always valid");
        assert_eq!(
            format_validity(1767225600, 1798761600),
            "2026-01-01 00:00:00 UTC to 2027-01-01 00:00:00 UTC"
        );
    }

    /// A stored `-cert.pub` line comes back as it was only when it is one
    /// plain line; anything else on it is dropped by re-encoding the
    /// verified certificate.
    #[test]
    fn stored_text_comes_back_only_as_one_plain_line() {
        let cert = tests_fixture::FIXTURE_CERT_PUB.trim();
        let (_, wire) = parse_text(cert).unwrap();
        let rebuilt = to_cert_pub(&wire).unwrap();
        let plain = format!("{cert} kr-test@host\n");
        assert_eq!(from_stored(plain.as_bytes()).unwrap().cert_pub, plain);
        let crlf = format!("{cert} kr-test\r\n");
        assert_eq!(
            from_stored(crlf.as_bytes()).unwrap().cert_pub,
            format!("{cert} kr-test\n")
        );
        for hostile in [
            format!("{cert} two\nssh-ed25519 AAAA extra\n"),
            format!("{cert} bell\u{7}\n"),
            format!("{cert} rtl\u{202e}gnp.exe\n"),
        ] {
            assert_eq!(
                from_stored(hostile.as_bytes()).unwrap().cert_pub,
                rebuilt,
                "{hostile:?}"
            );
        }
    }

    #[test]
    fn parses_text_form_and_roundtrips_to_cert_pub() {
        let (info, wire) = parse_text(FIXTURE_CERT_PUB).unwrap();
        assert_eq!(info.key_id, "test-key-id");
        assert_eq!(wire, fixture_wire());

        // Re-encoding the wire form yields a line OpenSSH accepts: same type,
        // same base64 body (comment is not preserved — it isn't part of the
        // certificate).
        let line = to_cert_pub(&wire).unwrap();
        let mut parts = line.split_ascii_whitespace();
        assert_eq!(parts.next(), Some("ssh-ed25519-cert-v01@openssh.com"));
        assert_eq!(
            parts.next(),
            FIXTURE_CERT_PUB.split_ascii_whitespace().nth(1)
        );
        assert!(line.ends_with('\n'));
        // And the re-encoded line parses back.
        assert!(parse_text(&line).is_some());
    }

    #[test]
    fn default_cert_filename_is_path_safe() {
        assert_eq!(default_cert_filename("ssh:demo"), "ssh_demo-cert.pub");
        assert_eq!(default_cert_filename("ssh:"), "ssh_-cert.pub");
        // No path separator can survive a hostile RP id -> no traversal.
        let evil = default_cert_filename("ssh:../../etc/passwd");
        assert!(!evil.contains('/') && !evil.contains('\\'));
        assert!(evil.ends_with("-cert.pub"));
    }

    #[test]
    fn text_form_rejects_mismatch_and_garbage() {
        // Declared type must match the type inside the blob.
        let b64 = FIXTURE_CERT_PUB.split_ascii_whitespace().nth(1).unwrap();
        let lied = format!("ssh-rsa-cert-v01@openssh.com {b64}");
        assert!(parse_text(&lied).is_none());
        // Ordinary public keys (not certs) are not recognized.
        assert!(parse_text(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB8WYDicxYHAvQ5QE8w24ZO0pod+x5Y7Zcjdk8D3kOpZ user"
        )
        .is_none());
        // Not base64 / not a cert at all.
        assert!(parse_text("hello world").is_none());
        assert!(parse_text("").is_none());
    }
}
