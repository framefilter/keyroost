//! Minimal `otpauth://` URI parser.
//!
//! Format (RFC-style spec at <https://github.com/google/google-authenticator/wiki/Key-Uri-Format>):
//!
//!   otpauth://TYPE/LABEL?secret=BASE32&issuer=ISSUER&algorithm=ALGO&digits=N&period=N
//!
//! TYPE is `totp` or `hotp` — this parser accepts only `totp` (Molto2 is TOTP).
//! LABEL is typically `Issuer:account@example.com`; we use it for the title.

use keyroost_proto::codec::base32_decode;
use keyroost_proto::commands::{DisplayTimeout, HmacAlgo, OtpDigits, ProfileConfig, TimeStep};

use crate::entry::{ImportEntry, Unusable};

#[non_exhaustive]
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
#[derive(Clone)]
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

/// Manual Debug so a stray `{:?}` in logs or error context can't print the
/// seed; only its length is shown.
impl std::fmt::Debug for OtpAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OtpAuth")
            .field("issuer", &self.issuer)
            .field("account", &self.account)
            .field("secret", &format_args!("[{} bytes]", self.secret.len()))
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("time_step", &self.time_step)
            .finish()
    }
}

/// The decoded seed is wiped when the parse result is dropped. (Buffer
/// reallocations and the URI string the caller holds are out of reach —
/// callers own those.)
impl Drop for OtpAuth {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret.zeroize();
    }
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
    let UriParts {
        typ,
        label_raw,
        query,
    } = split_uri(uri).map_err(|e| match e {
        SplitError::NotOtpAuth => OtpAuthError::NotOtpAuth,
        SplitError::NoLabel => OtpAuthError::Malformed("missing label"),
    })?;
    if !typ.eq_ignore_ascii_case("totp") {
        return Err(OtpAuthError::UnsupportedType(typ.to_owned()));
    }
    // The label is a URI path segment, not a form-encoded query value, so a
    // literal '+' must be preserved (only query values decode '+' to space).
    let label = percent_decode_keep_plus(label_raw)
        .map_err(|_| OtpAuthError::Malformed("label percent-encoding"))?;

    // Defaults per the spec. The decoded secret text is held in Zeroizing so it
    // is wiped on *every* exit — including an error in a later param (algorithm,
    // digits, period) after `secret=` was seen, or a duplicate `secret=` that
    // overwrites the first — not only on the success path.
    let mut secret_b32: Option<zeroize::Zeroizing<String>> = None;
    let mut issuer_param: Option<String> = None;
    let mut algorithm = HmacAlgo::Sha1;
    let mut digits = OtpDigits::Six;
    let mut period: u32 = 30;

    for (k, v) in query_params(query) {
        let v = v.map_err(|_| OtpAuthError::Malformed("query value percent-encoding"))?;
        match k {
            "secret" => secret_b32 = Some(v),
            "issuer" => issuer_param = Some(v.to_string()),
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

    // The percent-decoded base32 text is the seed in another spelling; it rides
    // in `secret_b32` (Zeroizing) and is wiped when it drops at function exit.
    // The binary copy rides in `OtpAuth`, which also wipes on drop.
    let secret_b32 = secret_b32.ok_or(OtpAuthError::MissingSecret)?;
    let decoded = base32_decode(&secret_b32);
    let mut secret = decoded.map_err(|_| OtpAuthError::InvalidSecret)?;
    // The Molto2 caps seeds at 63 bytes, and the protocol layer asserts the
    // same range; reject here so a malformed URI in an imported file fails
    // with an error instead of panicking mid-import (after some slots were
    // already written). Real TOTP secrets are 10–64 base32 chars (6–40 bytes).
    if secret.is_empty() || secret.len() > 63 {
        use zeroize::Zeroize;
        secret.zeroize();
        return Err(OtpAuthError::InvalidSecret);
    }

    // Label may be "Issuer:account" — split on the first colon if present.
    let (label_issuer, account) = split_label(&label);

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

/// Parse an otpauth:// URI into a format-neutral [`ImportEntry`]: HOTP with
/// its counter, any TOTP period, SHA-1/256/512, 1–10 digits and seeds up to
/// 255 bytes. Same percent-decoding and label rules as [`parse`]; problems
/// are reported secret first, then hash, digits and period.
pub fn parse_entry(uri: &str) -> Result<ImportEntry, Unusable> {
    parse_entry_labeled(uri).1
}

/// [`parse_entry`] plus the name the URI carries (`issuer:account`, or
/// whichever half it has), even when the entry itself is unusable — so a
/// list or a QR screenshot can say which account failed.
pub fn parse_entry_labeled(uri: &str) -> (Option<String>, Result<ImportEntry, Unusable>) {
    let UriParts {
        typ,
        label_raw,
        query,
    } = match split_uri(uri) {
        Ok(parts) => parts,
        Err(SplitError::NotOtpAuth) => {
            return (None, Err(Unusable::Malformed("not an otpauth:// URI")))
        }
        Err(SplitError::NoLabel) => {
            return (None, Err(Unusable::Malformed("the URI has no label")))
        }
    };
    // Same label rule as `parse`: a path segment keeps a literal '+'.
    let label = match percent_decode_keep_plus(label_raw) {
        Ok(l) => l,
        Err(()) => {
            return (
                None,
                Err(Unusable::Malformed(
                    "the label's percent-encoding is invalid",
                )),
            )
        }
    };
    let (label_issuer, account) = split_label(&label);

    // Collect the parameters first, then validate in a fixed order. The
    // decoded base32 text is the seed in another spelling: Zeroizing, so it
    // is wiped on every exit (including a duplicate `secret=`).
    let mut secret_b32: Option<zeroize::Zeroizing<String>> = None;
    let mut issuer_param: Option<String> = None;
    let mut algorithm: Option<String> = None;
    let mut digits: u32 = 6;
    let mut period: u32 = 30;
    let mut counter: u64 = 0;
    // Only a HOTP entry reads its counter; the Molto2 path ignores one on a
    // TOTP URI, and so does this.
    let mut counter_malformed = false;
    let mut malformed: Option<&'static str> = None;
    for (k, v) in query_params(query) {
        let v = match v {
            Ok(v) => v,
            Err(()) => {
                malformed.get_or_insert("a parameter's percent-encoding is invalid");
                continue;
            }
        };
        match k {
            "secret" => secret_b32 = Some(v),
            "issuer" => issuer_param = Some(v.to_string()),
            "algorithm" => algorithm = Some(v.to_string()),
            "digits" => match v.parse() {
                Ok(n) => digits = n,
                Err(_) => {
                    malformed.get_or_insert("the digits value isn't a number");
                }
            },
            "period" => match v.parse() {
                Ok(n) => period = n,
                Err(_) => {
                    malformed.get_or_insert("the period value isn't a number");
                }
            },
            "counter" => match v.parse() {
                Ok(n) => counter = n,
                Err(_) => counter_malformed = true,
            },
            _ => {} // image, color, ... carry nothing a key stores
        }
    }

    // Prefer the explicit issuer= query param over the label prefix.
    let issuer = issuer_param.or(label_issuer).filter(|s| !s.is_empty());
    let account = account.filter(|s| !s.is_empty());
    let name = crate::entry::name_label(issuer.as_deref(), account.as_deref());

    let entry = (|| {
        let kind = crate::entry::type_from_name(typ)?;
        if let Some(what) = malformed {
            return Err(Unusable::Malformed(what));
        }
        if counter_malformed && matches!(kind, crate::entry::TypeName::Hotp) {
            return Err(Unusable::Malformed("the counter value isn't a number"));
        }
        let secret = crate::entry::decode_secret(secret_b32.as_deref().map_or("", |s| s))?;
        let hash = crate::entry::hash_from_name(algorithm.as_deref().unwrap_or("SHA1"))?;
        let kind = match kind {
            crate::entry::TypeName::Totp => crate::entry::OtpKind::Totp { period },
            crate::entry::TypeName::Hotp => crate::entry::OtpKind::Hotp { counter },
        };
        crate::entry::finish(issuer, account, secret, hash, digits, kind)
    })();
    (name, entry)
}

/// The three parts of `otpauth://TYPE/LABEL?QUERY`, undecoded.
struct UriParts<'a> {
    typ: &'a str,
    label_raw: &'a str,
    query: &'a str,
}

enum SplitError {
    NotOtpAuth,
    NoLabel,
}

/// The one URI splitter both otpauth parsers ([`parse`], [`parse_entry`])
/// use, so they can't disagree on what the type, label and query are.
fn split_uri(uri: &str) -> Result<UriParts<'_>, SplitError> {
    let rest = uri
        .strip_prefix("otpauth://")
        .ok_or(SplitError::NotOtpAuth)?;
    let (typ_label, query) = rest.split_once('?').unwrap_or((rest, ""));
    let (typ, label_raw) = typ_label.split_once('/').ok_or(SplitError::NoLabel)?;
    Ok(UriParts {
        typ,
        label_raw,
        query,
    })
}

/// The query's `key=value` pairs in order, each value form-decoded ('+' is
/// a space) into a wipe-on-drop buffer, or `Err` for bad percent-encoding.
/// A pair without '=' has an empty value; empty pairs are skipped. Shared by
/// both otpauth parsers; each applies its own rules to the values.
fn query_params(
    query: &str,
) -> impl Iterator<Item = (&str, Result<zeroize::Zeroizing<String>, ()>)> {
    query.split('&').filter(|s| !s.is_empty()).map(|kv| {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        (k, percent_decode(v).map(zeroize::Zeroizing::new))
    })
}

/// Split an `Issuer:account` label on its first colon (both halves trimmed);
/// a label without a colon is the account.
pub(crate) fn split_label(label: &str) -> (Option<String>, Option<String>) {
    match label.split_once(':') {
        Some((i, a)) => (Some(i.trim().to_owned()), Some(a.trim().to_owned())),
        None if label.is_empty() => (None, None),
        None => (None, Some(label.trim().to_owned())),
    }
}

/// Percent-decode a query value: `+` decodes to a space (form-encoding).
fn percent_decode(s: &str) -> Result<String, ()> {
    percent_decode_impl(s, true)
}

/// Percent-decode a URI path segment (the label): `+` is a literal plus.
/// Shared with the Google Authenticator migration parser so malformed
/// `%XX` input decodes identically on both import paths.
pub(crate) fn percent_decode_keep_plus(s: &str) -> Result<String, ()> {
    percent_decode_impl(s, false)
}

fn percent_decode_impl(s: &str, plus_is_space: bool) -> Result<String, ()> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' if plus_is_space => {
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
    use crate::entry::{HashAlg, OtpKind};

    #[test]
    fn rejects_non_otpauth() {
        assert!(matches!(
            parse("https://example.com"),
            Err(OtpAuthError::NotOtpAuth)
        ));
    }

    #[test]
    fn plus_in_label_is_literal_but_space_in_query() {
        // In a path segment (the label) '+' is a literal plus, not a space —
        // only application/x-www-form-urlencoded *query* values decode '+' to
        // space. A '%20' in the label is still a space.
        let p =
            parse("otpauth://totp/alice+work%20a?secret=JBSWY3DPEHPK3PXP&issuer=Acme+Co").unwrap();
        assert_eq!(p.account.as_deref(), Some("alice+work a"));
        // The issuer query param keeps form-encoding: '+' becomes a space.
        assert_eq!(p.issuer.as_deref(), Some("Acme Co"));
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
    fn oversized_secret_rejected() {
        // 64 decoded bytes — one past the Molto2's 63-byte cap. Must error
        // here rather than trip the protocol layer's assert mid-import.
        let b32 = "A".repeat(103); // ceil(64*8/5) chars -> 64 bytes
        let r = parse(&format!("otpauth://totp/x?secret={}", b32));
        assert!(matches!(r, Err(OtpAuthError::InvalidSecret)));
        // 63 bytes stays accepted.
        let b32_ok = "A".repeat(101); // floor(63*8/5) chars -> 63 bytes
        let p = parse(&format!("otpauth://totp/x?secret={}", b32_ok)).unwrap();
        assert_eq!(p.secret.len(), 63);
    }

    #[test]
    fn suggested_title_prefers_issuer_and_truncates() {
        let p = parse("otpauth://totp/x?secret=JBSWY3DP&issuer=ABCDEFGHIJKLMNOP").unwrap();
        assert_eq!(p.suggested_title(), "ABCDEFGHIJKL"); // 12 bytes
    }

    #[test]
    fn parse_entry_accepts_hotp_with_counter() {
        let e = parse_entry("otpauth://hotp/X:a?secret=JBSWY3DPEHPK3PXP&counter=5").unwrap();
        assert_eq!(e.kind, OtpKind::Hotp { counter: 5 });
        assert_eq!(e.issuer.as_deref(), Some("X"));
        assert_eq!(e.account.as_deref(), Some("a"));
        assert_eq!(&e.secret[..], b"Hello!\xde\xad\xbe\xef");
        assert_eq!(e.hash, HashAlg::Sha1);
        assert_eq!(e.digits, 6);
        // No counter in the URI starts at 0.
        let e = parse_entry("otpauth://HOTP/X?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(e.kind, OtpKind::Hotp { counter: 0 });
    }

    #[test]
    fn parse_entry_accepts_any_period_and_sha512() {
        let e = parse_entry(
            "otpauth://totp/Co%20Inc:alice%2Bwork?secret=JBSWY3DPEHPK3PXP&period=45&algorithm=SHA512&digits=7",
        )
        .unwrap();
        assert_eq!(e.kind, OtpKind::Totp { period: 45 });
        assert_eq!(e.hash, HashAlg::Sha512);
        assert_eq!(e.digits, 7);
        // Same label rules as `parse`: '+' in the label is literal.
        assert_eq!(e.issuer.as_deref(), Some("Co Inc"));
        assert_eq!(e.account.as_deref(), Some("alice+work"));
        // The issuer= query param wins and form-decodes '+'.
        let e =
            parse_entry("otpauth://totp/Old:bob?secret=JBSWY3DPEHPK3PXP&issuer=Acme+Co").unwrap();
        assert_eq!(e.issuer.as_deref(), Some("Acme Co"));
        assert_eq!(e.kind, OtpKind::Totp { period: 30 });
        // A 64-byte secret (too long for a Molto2) is fine here.
        let e = parse_entry(&format!("otpauth://totp/x?secret={}", "A".repeat(103))).unwrap();
        assert_eq!(e.secret.len(), 64);
    }

    #[test]
    fn parse_entry_unusable_reasons() {
        let p = |q: &str| parse_entry(&format!("otpauth://totp/x?{}", q)).unwrap_err();
        assert_eq!(p("secret=JBSWY3DP&period=0"), Unusable::Period(0));
        assert_eq!(p("secret=JBSWY3DP&digits=11"), Unusable::Digits(11));
        assert_eq!(p("secret=JBSWY3DP&digits=0"), Unusable::Digits(0));
        assert_eq!(
            p("secret=JBSWY3DP&algorithm=MD5"),
            Unusable::Hash("MD5".into())
        );
        assert_eq!(p("secret=NOT_BASE32!!"), Unusable::BadSecret);
        assert_eq!(p("issuer=x"), Unusable::BadSecret);
        assert_eq!(p("secret="), Unusable::BadSecret);
        assert!(matches!(
            p("secret=JBSWY3DP&digits=x"),
            Unusable::Malformed(_)
        ));
        assert!(matches!(
            p("secret=JBSWY3DP&period=-1"),
            Unusable::Malformed(_)
        ));
        assert_eq!(
            parse_entry("otpauth://steam/x?secret=JBSWY3DP").unwrap_err(),
            Unusable::Type("steam".into())
        );
        assert!(matches!(
            parse_entry("https://example.com").unwrap_err(),
            Unusable::Malformed(_)
        ));
        assert!(matches!(
            parse_entry("otpauth://totp?secret=JBSWY3DP").unwrap_err(),
            Unusable::Malformed(_)
        ));
        // Secret problems are reported before hash and digit problems,
        // matching the Molto2 path's order.
        assert_eq!(p("secret=!!&algorithm=MD5&digits=11"), Unusable::BadSecret);
        assert_eq!(
            p("secret=JBSWY3DP&digits=11&algorithm=MD5"),
            Unusable::Hash("MD5".into())
        );
    }

    #[test]
    fn percent_decoded_label_with_plus() {
        let p =
            parse("otpauth://totp/Co%20Inc:alice%2Bwork%40example.com?secret=JBSWY3DP").unwrap();
        assert_eq!(p.issuer.as_deref(), Some("Co Inc"));
        assert_eq!(p.account.as_deref(), Some("alice+work@example.com"));
    }
}
