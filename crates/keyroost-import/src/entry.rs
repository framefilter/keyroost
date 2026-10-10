//! Format-neutral authenticator entries: everything an export can carry,
//! before any key's limits are applied. Destinations filter these against
//! their own rules; the Molto2 path keeps its own narrow `BulkEntry`.

use zeroize::Zeroizing;

/// Longest decoded seed an entry may carry. Generous on purpose: per-key
/// limits are applied later, against the destination, not here.
pub(crate) const MAX_SECRET_BYTES: usize = 255;

/// Most entries a wide reader takes from one file. Far above any real
/// authenticator export (a few hundred at most); a file past it is refused
/// as a whole before more items are built, which bounds the memory a
/// hostile file can make the readers allocate.
pub const MAX_ENTRIES: usize = 1000;

/// HMAC hash named by the entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlg {
    Sha1,
    Sha256,
    Sha512,
}

impl HashAlg {
    /// "SHA-1", "SHA-256", "SHA-512": how every message names it.
    pub fn name(self) -> &'static str {
        match self {
            HashAlg::Sha1 => "SHA-1",
            HashAlg::Sha256 => "SHA-256",
            HashAlg::Sha512 => "SHA-512",
        }
    }
}

/// Time- or counter-based, with the parameter that goes with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpKind {
    /// TOTP with its period in seconds (>= 1).
    Totp { period: u32 },
    /// HOTP with the next counter value from the export.
    Hotp { counter: u64 },
}

/// One usable entry. The seed is wiped on drop.
pub struct ImportEntry {
    /// Issuer; an empty string in the file becomes `None`.
    pub issuer: Option<String>,
    /// Account name; an empty string in the file becomes `None`.
    pub account: Option<String>,
    /// Decoded seed, 1..=255 bytes.
    pub secret: Zeroizing<Vec<u8>>,
    pub hash: HashAlg,
    /// Code length, 1..=10.
    pub digits: u8,
    pub kind: OtpKind,
}

/// Manual Debug so a stray `{:?}` can't print the seed; only its length is
/// shown.
impl core::fmt::Debug for ImportEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ImportEntry")
            .field("issuer", &self.issuer)
            .field("account", &self.account)
            .field("secret", &format_args!("[{} bytes]", self.secret.len()))
            .field("hash", &self.hash)
            .field("digits", &self.digits)
            .field("kind", &self.kind)
            .finish()
    }
}

/// Why an entry in a file can't go to any key.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Unusable {
    /// Missing, empty, over 255 bytes, or not valid base32.
    BadSecret,
    /// Steam, mOTP, Yandex, ... — the type as the file names it.
    Type(String),
    /// MD5 or a name keyroost doesn't know.
    Hash(String),
    /// Digits outside 1..=10.
    Digits(u32),
    /// Period of 0.
    Period(u32),
    /// A list line that isn't an otpauth:// URI, or a URI missing a required part.
    Malformed(&'static str),
}

impl core::fmt::Display for Unusable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Unusable::BadSecret => {
                write!(f, "the secret is missing, too long or isn't valid base32")
            }
            Unusable::Type(t) => match t.to_ascii_lowercase().as_str() {
                "steam" => write!(f, "Steam codes aren't supported"),
                "motp" => write!(f, "mOTP codes aren't supported"),
                "yandex" => write!(f, "Yandex codes aren't supported"),
                _ if is_plain_name(t) => write!(f, "{} codes aren't supported", t),
                _ => write!(f, "codes of this type aren't supported"),
            },
            Unusable::Hash(h) if is_plain_name(h) => write!(f, "{} isn't supported", h),
            Unusable::Hash(_) => write!(f, "this hash algorithm isn't supported"),
            Unusable::Digits(d) => write!(f, "{}-digit codes aren't supported", d),
            Unusable::Period(p) => write!(f, "a {}-second period isn't supported", p),
            Unusable::Malformed(what) => write!(f, "{}", what),
        }
    }
}

impl std::error::Error for Unusable {}

/// A type or hash name short and plain enough to repeat back in a message
/// (letters, digits, '-', '_', ' '; at most 16 bytes). Anything else in a
/// file isn't echoed.
fn is_plain_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 16
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b' '))
}

/// One entry of a file, in file order.
#[derive(Debug)]
pub struct ImportItem {
    /// Position in the file: the entry index for JSON formats, the line index
    /// for lists (the same index the narrow path reports in
    /// `BulkError::EntryRejected`).
    pub index: usize,
    /// "issuer:account" as the file names it, for display only (callers
    /// sanitize before printing). "line N" / "entry N" (counting from 1)
    /// when there is no name.
    pub label: String,
    pub entry: Result<ImportEntry, Unusable>,
}

/// Which kind of file the entries came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Format {
    Aegis,
    AegisEncrypted,
    TwoFas,
    OtpauthList,
    QrImage,
    GoogleExport,
}

impl Format {
    /// The export's layout as the CLI and the GUI name it.
    pub fn name(self) -> &'static str {
        match self {
            Format::Aegis => "Aegis",
            Format::AegisEncrypted => "Aegis, encrypted",
            Format::TwoFas => "2FAS",
            Format::OtpauthList => "otpauth:// list",
            Format::QrImage => "QR screenshot",
            Format::GoogleExport => "Google Authenticator export",
        }
    }
}

/// Everything read from one file.
#[derive(Debug)]
pub struct ImportFile {
    pub format: Format,
    pub items: Vec<ImportItem>,
    /// `(index, total)` when this is one QR of a multi-QR Google export.
    pub batch: Option<(u32, u32)>,
}

impl ImportFile {
    /// How many items carry an entry some key could take.
    pub fn usable(&self) -> usize {
        self.items.iter().filter(|i| i.entry.is_ok()).count()
    }
}

/// `"issuer:account"`, or whichever of the two is present, or `None`.
pub(crate) fn name_label(issuer: Option<&str>, account: Option<&str>) -> Option<String> {
    let issuer = issuer.filter(|s| !s.is_empty());
    let account = account.filter(|s| !s.is_empty());
    match (issuer, account) {
        (Some(i), Some(a)) => Some(format!("{}:{}", i, a)),
        (Some(one), None) | (None, Some(one)) => Some(one.to_owned()),
        (None, None) => None,
    }
}

/// The title a Molto2 slot gets: the issuer, else the account, cut to 12
/// bytes on a character boundary (empty when there is neither). One rule for
/// the Molto2 writer (`BulkEntry::suggested_title`) and the import plan.
pub(crate) fn molto_title(issuer: Option<&str>, account: Option<&str>) -> String {
    let candidate = issuer.or(account).unwrap_or("");
    let mut end = candidate.len().min(12);
    while end > 0 && !candidate.is_char_boundary(end) {
        end -= 1;
    }
    candidate[..end].to_owned()
}

/// Map a hash name as exports spell it (case-insensitive).
pub(crate) fn hash_from_name(name: &str) -> Result<HashAlg, Unusable> {
    match name.to_ascii_uppercase().as_str() {
        "SHA1" => Ok(HashAlg::Sha1),
        "SHA256" => Ok(HashAlg::Sha256),
        "SHA512" => Ok(HashAlg::Sha512),
        other => Err(Unusable::Hash(other.to_owned())),
    }
}

/// The kind a type name stands for, before its parameter is known.
pub(crate) enum TypeName {
    Totp,
    Hotp,
}

/// `totp` / `hotp` (case-insensitive); anything else is unusable, named as
/// the file names it.
pub(crate) fn type_from_name(name: &str) -> Result<TypeName, Unusable> {
    if name.eq_ignore_ascii_case("totp") {
        Ok(TypeName::Totp)
    } else if name.eq_ignore_ascii_case("hotp") {
        Ok(TypeName::Hotp)
    } else {
        Err(Unusable::Type(name.to_owned()))
    }
}

/// Decode a base32 seed into a wipe-on-drop buffer within the wide range.
pub(crate) fn decode_secret(secret_b32: &str) -> Result<Zeroizing<Vec<u8>>, Unusable> {
    let secret = Zeroizing::new(
        keyroost_proto::codec::base32_decode(secret_b32).map_err(|_| Unusable::BadSecret)?,
    );
    check_secret(secret)
}

/// Enforce the wide seed range on raw bytes.
pub(crate) fn check_secret(secret: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, Unusable> {
    if secret.is_empty() || secret.len() > MAX_SECRET_BYTES {
        return Err(Unusable::BadSecret);
    }
    Ok(secret)
}

/// Validate digits and the kind's parameter, in that order, and assemble the
/// entry. The secret and hash are already checked by the caller (secret
/// first, then hash — the same order the Molto2 path reports problems in).
pub(crate) fn finish(
    issuer: Option<String>,
    account: Option<String>,
    secret: Zeroizing<Vec<u8>>,
    hash: HashAlg,
    digits: u32,
    kind: OtpKind,
) -> Result<ImportEntry, Unusable> {
    if !(1..=10).contains(&digits) {
        return Err(Unusable::Digits(digits));
    }
    if let OtpKind::Totp { period: 0 } = kind {
        return Err(Unusable::Period(0));
    }
    Ok(ImportEntry {
        issuer: issuer.filter(|s| !s.is_empty()),
        account: account.filter(|s| !s.is_empty()),
        secret,
        hash,
        digits: digits as u8,
        kind,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ImportEntry {
        ImportEntry {
            issuer: Some("Acme".into()),
            account: Some("alice".into()),
            // "Hello!\xde\xad\xbe\xef" plus six more bytes: 16 in all.
            secret: Zeroizing::new(b"Hello!\xde\xad\xbe\xef012345".to_vec()),
            hash: HashAlg::Sha1,
            digits: 6,
            kind: OtpKind::Totp { period: 30 },
        }
    }

    #[test]
    fn debug_never_shows_secret() {
        let e = sample();
        let dbg = format!("{:?}", e);
        assert!(dbg.contains("[16 bytes]"), "{dbg}");
        // Neither the base32 nor the hex spelling of the seed, nor its bytes.
        assert!(!dbg.contains("JBSWY3DP"), "{dbg}");
        assert!(!dbg.to_ascii_lowercase().contains("48656c6c6f"), "{dbg}");
        assert!(!dbg.contains("Hello"), "{dbg}");
        assert!(!dbg.contains("72, 101"), "{dbg}");
        // The item wrapper's Debug goes through the same impl.
        let item = ImportItem {
            index: 0,
            label: "Acme:alice".into(),
            entry: Ok(sample()),
        };
        assert!(format!("{:?}", item).contains("[16 bytes]"));
    }

    #[test]
    fn secret_over_255_bytes_is_bad_secret() {
        assert!(check_secret(Zeroizing::new(vec![1u8; 255])).is_ok());
        assert_eq!(
            check_secret(Zeroizing::new(vec![1u8; 256])).unwrap_err(),
            Unusable::BadSecret
        );
        assert_eq!(
            check_secret(Zeroizing::new(Vec::new())).unwrap_err(),
            Unusable::BadSecret
        );
        // 408 base32 chars decode to 255 bytes; 410 to 256.
        assert_eq!(decode_secret(&"A".repeat(408)).unwrap().len(), 255);
        assert_eq!(
            decode_secret(&"A".repeat(410)).unwrap_err(),
            Unusable::BadSecret
        );
    }

    #[test]
    fn unusable_reasons_read_plainly() {
        assert_eq!(
            Unusable::Type("steam".into()).to_string(),
            "Steam codes aren't supported"
        );
        assert_eq!(
            Unusable::Type("MOTP".into()).to_string(),
            "mOTP codes aren't supported"
        );
        assert_eq!(
            Unusable::Type("yandex".into()).to_string(),
            "Yandex codes aren't supported"
        );
        assert_eq!(
            Unusable::BadSecret.to_string(),
            "the secret is missing, too long or isn't valid base32"
        );
        assert_eq!(
            Unusable::Hash("MD5".into()).to_string(),
            "MD5 isn't supported"
        );
        // File values that aren't plain short names are never echoed.
        let odd = "<b>x</b>\u{1b}[31mAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert_eq!(
            Unusable::Type(odd.into()).to_string(),
            "codes of this type aren't supported"
        );
        assert_eq!(
            Unusable::Hash(odd.into()).to_string(),
            "this hash algorithm isn't supported"
        );
        assert_eq!(
            Unusable::Type("type 3".into()).to_string(),
            "type 3 codes aren't supported"
        );
        assert_eq!(
            Unusable::Digits(7).to_string(),
            "7-digit codes aren't supported"
        );
        assert_eq!(
            Unusable::Period(0).to_string(),
            "a 0-second period isn't supported"
        );
    }

    #[test]
    fn finish_checks_digits_then_period() {
        let s = || Zeroizing::new(vec![1u8; 10]);
        let totp0 = OtpKind::Totp { period: 0 };
        assert_eq!(
            finish(None, None, s(), HashAlg::Sha1, 11, totp0).unwrap_err(),
            Unusable::Digits(11)
        );
        assert_eq!(
            finish(None, None, s(), HashAlg::Sha1, 6, totp0).unwrap_err(),
            Unusable::Period(0)
        );
        let e = finish(
            Some(String::new()),
            Some("a".into()),
            s(),
            HashAlg::Sha512,
            10,
            OtpKind::Hotp { counter: 0 },
        )
        .unwrap();
        assert_eq!(e.issuer, None);
        assert_eq!(e.digits, 10);
    }

    #[test]
    fn usable_counts_ok_items() {
        let file = ImportFile {
            format: Format::OtpauthList,
            items: vec![
                ImportItem {
                    index: 0,
                    label: "a".into(),
                    entry: Ok(sample()),
                },
                ImportItem {
                    index: 1,
                    label: "line 2".into(),
                    entry: Err(Unusable::BadSecret),
                },
            ],
            batch: None,
        };
        assert_eq!(file.usable(), 1);
    }
}
