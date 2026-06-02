//! Minimal `otpauth://` URI parser.
//!
//! Format (RFC-style spec at https://github.com/google/google-authenticator/wiki/Key-Uri-Format):
//!
//!   otpauth://TYPE/LABEL?secret=BASE32&issuer=ISSUER&algorithm=ALGO&digits=N&period=N
//!
//! TYPE is `totp` or `hotp` — this parser accepts only `totp` (Molto2 is TOTP).
//! LABEL is typically `Issuer:account@example.com`; we use it for the title.

use keyroost_proto::codec::base32_decode;
use keyroost_proto::commands::{DisplayTimeout, HmacAlgo, OtpDigits, ProfileConfig, TimeStep};

#[derive(Debug, PartialEq, Eq)]
pub enum OtpAuthError {
    NotOtpAuth,
    UnsupportedType(String),
    MissingSecret,
    InvalidSecret,
    UnsupportedAlgorithm(String),
    UnsupportedDigits(u32),
    UnsupportedPeriod(u32),
    Malformed(&'static str),
}

impl core::fmt::Display for OtpAuthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            OtpAuthError::NotOtpAuth => write!(f, "not an otpauth:// URI"),
            OtpAuthError::UnsupportedType(t) => {
                write!(f, "unsupported OTP type {:?} (only totp is supported)", t)
            }
            OtpAuthError::MissingSecret => write!(f, "URI is missing the `secret` parameter"),
            OtpAuthError::InvalidSecret => write!(f, "`secret` is not valid base32"),
            OtpAuthError::UnsupportedAlgorithm(a) => write!(
                f,
                "algorithm {:?} not supported by Molto2 (SHA1 or SHA256 only)",
                a
            ),
            OtpAuthError::UnsupportedDigits(d) => {
                write!(f, "digits={} not supported by Molto2 (4, 6, 8, or 10)", d)
            }
            OtpAuthError::UnsupportedPeriod(p) => {
                write!(f, "period={}s not supported by Molto2 (30 or 60)", p)
            }
            OtpAuthError::Malformed(s) => write!(f, "malformed URI: {}", s),
        }
    }
}

impl std::error::Error for OtpAuthError {}

/// A parsed otpauth:// URI, normalized to the subset Molto2 can store.
#[derive(Debug, Clone)]
pub struct OtpAuth {
    /// Issuer name from the `issuer=` query param, or extracted from the label prefix.
    pub issuer: Option<String>,
    /// Account name from the label (after the optional `Issuer:` prefix).
    pub account: Option<String>,
    /// Raw secret bytes (base32-decoded).
    pub secret: Vec<u8>,
    pub algorithm: HmacAlgo,
    pub digits: OtpDigits,
    pub time_step: TimeStep,
}

impl OtpAuth {
    /// Best-effort 12-byte title: prefer issuer, fall back to account, truncate hard.
    /// Caller can also override before sending to the device.
    pub fn suggested_title(&self) -> String {
        let candidate = self
            .issuer
            .as_deref()
            .or(self.account.as_deref())
            .unwrap_or("");
        truncate_bytes(candidate, 12).to_owned()
    }

    /// Build a Molto2 ProfileConfig from this URI, given a UTC timestamp and display timeout.
    /// Display timeout isn't carried in otpauth:// — caller picks (default 30s here).
    pub fn to_profile_config(
        &self,
        utc_time: u32,
        display_timeout: DisplayTimeout,
    ) -> ProfileConfig {
        ProfileConfig {
            display_timeout,
            algorithm: self.algorithm,
            digits: self.digits,
            time_step: self.time_step,
            utc_time,
        }
    }
}

/// Parse an otpauth:// URI into a normalized form. Returns specific errors for
/// each kind of mismatch with what Molto2 can program.
pub fn parse(uri: &str) -> Result<OtpAuth, OtpAuthError> {
    const PREFIX: &str = "otpauth://";
    let rest = uri.strip_prefix(PREFIX).ok_or(OtpAuthError::NotOtpAuth)?;

    // TYPE/LABEL?QUERY
    let (typ_label, query) = match rest.split_once('?') {
        Some((a, b)) => (a, b),
        None => (rest, ""),
    };
    let (typ, label_raw) = typ_label
        .split_once('/')
        .ok_or(OtpAuthError::Malformed("missing label"))?;
    if !typ.eq_ignore_ascii_case("totp") {
        return Err(OtpAuthError::UnsupportedType(typ.to_owned()));
    }
    let label =
        percent_decode(label_raw).map_err(|_| OtpAuthError::Malformed("label percent-encoding"))?;

    // Defaults per the spec.
    let mut secret_b32: Option<String> = None;
    let mut issuer_param: Option<String> = None;
    let mut algorithm = HmacAlgo::Sha1;
    let mut digits = OtpDigits::Six;
    let mut period: u32 = 30;

    for kv in query.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        let v = percent_decode(v)
            .map_err(|_| OtpAuthError::Malformed("query value percent-encoding"))?;
        match k {
            "secret" => secret_b32 = Some(v),
            "issuer" => issuer_param = Some(v),
            "algorithm" => match v.to_ascii_uppercase().as_str() {
                "SHA1" => algorithm = HmacAlgo::Sha1,
                "SHA256" => algorithm = HmacAlgo::Sha256,
                other => return Err(OtpAuthError::UnsupportedAlgorithm(other.to_owned())),
            },
            "digits" => {
                let n: u32 = v.parse().map_err(|_| OtpAuthError::Malformed("digits"))?;
                digits = match n {
                    4 => OtpDigits::Four,
                    6 => OtpDigits::Six,
                    8 => OtpDigits::Eight,
                    10 => OtpDigits::Ten,
                    other => return Err(OtpAuthError::UnsupportedDigits(other)),
                };
            }
            "period" => {
                period = v.parse().map_err(|_| OtpAuthError::Malformed("period"))?;
            }
            _ => {} // ignore unknown params (counter, image, ...)
        }
    }

    let time_step = match period {
        30 => TimeStep::Seconds30,
        60 => TimeStep::Seconds60,
        other => return Err(OtpAuthError::UnsupportedPeriod(other)),
    };

    let secret_b32 = secret_b32.ok_or(OtpAuthError::MissingSecret)?;
    let secret = base32_decode(&secret_b32).map_err(|_| OtpAuthError::InvalidSecret)?;
    if secret.is_empty() {
        return Err(OtpAuthError::InvalidSecret);
    }

    // Label may be "Issuer:account" — split on the first colon if present.
    let (label_issuer, account) = match label.split_once(':') {
        Some((i, a)) => (Some(i.trim().to_owned()), Some(a.trim().to_owned())),
        None if label.is_empty() => (None, None),
        None => (None, Some(label.trim().to_owned())),
    };

    // Prefer the explicit issuer= query param over the label prefix.
    let issuer = issuer_param.or(label_issuer).filter(|s| !s.is_empty());
    let account = account.filter(|s| !s.is_empty());

    Ok(OtpAuth {
        issuer,
        account,
        secret,
        algorithm,
        digits,
        time_step,
    })
}

fn percent_decode(s: &str) -> Result<String, ()> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' => {
                if i + 2 >= bytes.len() {
                    return Err(());
                }
                let hi = hex_nibble(bytes[i + 1])?;
                let lo = hex_nibble(bytes[i + 2])?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| ())
}

fn hex_nibble(c: u8) -> Result<u8, ()> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(()),
    }
}

/// Truncate a `&str` to at most `max` bytes, on a UTF-8 char boundary.
fn truncate_bytes(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_otpauth() {
        assert!(matches!(
            parse("https://example.com"),
            Err(OtpAuthError::NotOtpAuth)
        ));
    }

    #[test]
    fn rejects_hotp() {
        let r = parse("otpauth://hotp/x?secret=JBSWY3DP&counter=0");
        assert!(matches!(r, Err(OtpAuthError::UnsupportedType(_))));
    }

    #[test]
    fn minimal_uri() {
        let p = parse("otpauth://totp/Acme?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(p.issuer, None);
        assert_eq!(p.account.as_deref(), Some("Acme"));
        assert_eq!(p.secret, b"Hello!\xde\xad\xbe\xef");
        assert_eq!(p.algorithm, HmacAlgo::Sha1);
        assert_eq!(p.digits, OtpDigits::Six);
        assert_eq!(p.time_step, TimeStep::Seconds30);
    }

    #[test]
    fn full_uri_with_issuer_query_wins() {
        let p = parse(
            "otpauth://totp/OldName:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA256&digits=8&period=60"
        ).unwrap();
        assert_eq!(p.issuer.as_deref(), Some("GitHub"));
        assert_eq!(p.account.as_deref(), Some("alice@example.com"));
        assert_eq!(p.algorithm, HmacAlgo::Sha256);
        assert_eq!(p.digits, OtpDigits::Eight);
        assert_eq!(p.time_step, TimeStep::Seconds60);
    }

    #[test]
    fn issuer_from_label_when_query_missing() {
        let p = parse("otpauth://totp/Google:bob@example.com?secret=JBSWY3DP").unwrap();
        assert_eq!(p.issuer.as_deref(), Some("Google"));
        assert_eq!(p.account.as_deref(), Some("bob@example.com"));
    }

    #[test]
    fn rejects_unsupported_digits() {
        let r = parse("otpauth://totp/x?secret=JBSWY3DP&digits=7");
        assert!(matches!(r, Err(OtpAuthError::UnsupportedDigits(7))));
    }

    #[test]
    fn rejects_unsupported_algo() {
        let r = parse("otpauth://totp/x?secret=JBSWY3DP&algorithm=SHA512");
        assert!(matches!(r, Err(OtpAuthError::UnsupportedAlgorithm(_))));
    }

    #[test]
    fn rejects_unsupported_period() {
        let r = parse("otpauth://totp/x?secret=JBSWY3DP&period=45");
        assert!(matches!(r, Err(OtpAuthError::UnsupportedPeriod(45))));
    }

    #[test]
    fn missing_secret() {
        let r = parse("otpauth://totp/x");
        assert!(matches!(r, Err(OtpAuthError::MissingSecret)));
    }

    #[test]
    fn invalid_base32_secret() {
        let r = parse("otpauth://totp/x?secret=NOT_BASE32!!");
        assert!(matches!(r, Err(OtpAuthError::InvalidSecret)));
    }

    #[test]
    fn suggested_title_prefers_issuer_and_truncates() {
        let p = parse("otpauth://totp/x?secret=JBSWY3DP&issuer=ABCDEFGHIJKLMNOP").unwrap();
        assert_eq!(p.suggested_title(), "ABCDEFGHIJKL"); // 12 bytes
    }

    #[test]
    fn percent_decoded_label_with_plus() {
        let p =
            parse("otpauth://totp/Co%20Inc:alice%2Bwork%40example.com?secret=JBSWY3DP").unwrap();
        assert_eq!(p.issuer.as_deref(), Some("Co Inc"));
        assert_eq!(p.account.as_deref(), Some("alice+work@example.com"));
    }
}
