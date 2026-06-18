//! Minimal X.509 Subject-DN *reader* (the inverse of the DER builder in
//! [`crate::x509`]).
//!
//! Scope is deliberately tiny: walk an X.509 `Certificate` (RFC 5280) far
//! enough to reach the `subject` `Name` and pull out its RDN attribute/value
//! pairs for human display. It does **not** validate signatures, parse
//! validity, extensions, or the public key — only the Subject DN.
//!
//! No external dependencies (this crate has none and must keep it). The DER
//! reader is a hand-rolled TLV walker that rejects truncated or over-long
//! length fields with an error rather than panicking, so feeding it a random
//! or truncated buffer is safe.
//!
//! # Example
//!
//! ```no_run
//! use keyroost_piv::x509_parse::parse_subject_dn;
//! # let cert_der: &[u8] = &[];
//! if let Ok(dn) = parse_subject_dn(cert_der) {
//!     println!("{dn}"); // e.g. "C=US, O=keyroost, CN=PIV Authentication"
//! }
//! ```

use std::fmt;

/// Errors from reading a Subject DN out of a DER certificate.
#[derive(Debug, PartialEq, Eq)]
pub enum X509ParseError {
    /// A TLV length field ran past the end of the buffer, or the buffer ended
    /// before an expected element.
    Truncated,
    /// A DER length used an unsupported long form (more than 4 length octets)
    /// — far larger than any real certificate.
    LengthTooLarge,
    /// The byte structure didn't match the expected `Certificate` /
    /// `tbsCertificate` / `Name` shape (wrong tag where one was required).
    Malformed,
}

impl fmt::Display for X509ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            X509ParseError::Truncated => write!(f, "certificate ended unexpectedly (truncated)"),
            X509ParseError::LengthTooLarge => write!(f, "DER length field is implausibly large"),
            X509ParseError::Malformed => write!(f, "certificate structure did not match X.509"),
        }
    }
}

impl std::error::Error for X509ParseError {}

// ---------------------------------------------------------------------------
// DER TLV reader
// ---------------------------------------------------------------------------

/// One parsed DER element: its tag byte and its content bytes.
struct Tlv<'a> {
    tag: u8,
    content: &'a [u8],
}

/// Read one DER TLV from the front of `input`, returning the element and the
/// remaining bytes after it. Supports definite short-form and long-form lengths
/// (`0x81`/`0x82`/… up to 4 length octets — certificates routinely exceed 127
/// content bytes). Indefinite length (`0x80`) and over-long lengths are
/// rejected, not panicked on.
fn read_tlv(input: &[u8]) -> Result<(Tlv<'_>, &[u8]), X509ParseError> {
    let tag = *input.first().ok_or(X509ParseError::Truncated)?;
    let len_byte = *input.get(1).ok_or(X509ParseError::Truncated)?;

    let (len, header) = if len_byte & 0x80 == 0 {
        // Short form: the byte is the length.
        (len_byte as usize, 2)
    } else {
        let num = (len_byte & 0x7f) as usize;
        // 0x80 is indefinite length (not valid in DER); >4 octets is absurd for
        // a certificate and would risk overflow on 32-bit usize.
        if num == 0 || num > 4 {
            return Err(X509ParseError::LengthTooLarge);
        }
        let mut len = 0usize;
        for i in 0..num {
            let b = *input.get(2 + i).ok_or(X509ParseError::Truncated)?;
            len = (len << 8) | b as usize;
        }
        (len, 2 + num)
    };

    let end = header
        .checked_add(len)
        .ok_or(X509ParseError::LengthTooLarge)?;
    if end > input.len() {
        return Err(X509ParseError::Truncated);
    }
    Ok((
        Tlv {
            tag,
            content: &input[header..end],
        },
        &input[end..],
    ))
}

/// Read one TLV and require its tag to equal `expected`.
fn expect_tag(input: &[u8], expected: u8) -> Result<(Tlv<'_>, &[u8]), X509ParseError> {
    let (tlv, rest) = read_tlv(input)?;
    if tlv.tag != expected {
        return Err(X509ParseError::Malformed);
    }
    Ok((tlv, rest))
}

// ---------------------------------------------------------------------------
// OID decoding
// ---------------------------------------------------------------------------

/// Decode a DER OBJECT IDENTIFIER content (without the tag/length) to its
/// dotted-decimal string. Returns `None` if the encoding is malformed.
fn decode_oid(content: &[u8]) -> Option<String> {
    let first = *content.first()?;
    // First byte encodes the first two arcs: arc1 * 40 + arc2.
    let arc1 = (first / 40) as u32;
    let arc2 = (first % 40) as u32;
    let mut out = format!("{arc1}.{arc2}");
    let mut value: u64 = 0;
    let mut started = false;
    for &b in &content[1..] {
        started = true;
        value = (value << 7) | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            out.push('.');
            out.push_str(&value.to_string());
            value = 0;
            started = false;
        }
    }
    // A high-bit-set byte with no terminator is malformed.
    if started {
        return None;
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// DN attribute labels
// ---------------------------------------------------------------------------

/// A directory-name attribute type, mapped to a short label for the common
/// OIDs and falling back to the dotted-decimal OID for anything else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnAttr {
    /// commonName — `2.5.4.3`
    CommonName,
    /// organizationName — `2.5.4.10`
    Organization,
    /// organizationalUnitName — `2.5.4.11`
    OrganizationalUnit,
    /// countryName — `2.5.4.6`
    Country,
    /// localityName — `2.5.4.7`
    Locality,
    /// stateOrProvinceName — `2.5.4.8`
    StateOrProvince,
    /// serialNumber — `2.5.4.5`
    SerialNumber,
    /// emailAddress (PKCS#9) — `1.2.840.113549.1.9.1`
    EmailAddress,
    /// Any other attribute: the dotted-decimal OID, preserved so it still
    /// renders rather than being dropped.
    Other(String),
}

impl DnAttr {
    /// Map a dotted-decimal OID string to the matching attribute.
    fn from_oid(oid: &str) -> DnAttr {
        match oid {
            "2.5.4.3" => DnAttr::CommonName,
            "2.5.4.10" => DnAttr::Organization,
            "2.5.4.11" => DnAttr::OrganizationalUnit,
            "2.5.4.6" => DnAttr::Country,
            "2.5.4.7" => DnAttr::Locality,
            "2.5.4.8" => DnAttr::StateOrProvince,
            "2.5.4.5" => DnAttr::SerialNumber,
            "1.2.840.113549.1.9.1" => DnAttr::EmailAddress,
            _ => DnAttr::Other(oid.to_string()),
        }
    }

    /// The short label used when rendering this attribute (`CN`, `O`, …), or the
    /// dotted-decimal OID for an unknown attribute.
    pub fn label(&self) -> &str {
        match self {
            DnAttr::CommonName => "CN",
            DnAttr::Organization => "O",
            DnAttr::OrganizationalUnit => "OU",
            DnAttr::Country => "C",
            DnAttr::Locality => "L",
            DnAttr::StateOrProvince => "ST",
            DnAttr::SerialNumber => "serialNumber",
            DnAttr::EmailAddress => "emailAddress",
            DnAttr::Other(oid) => oid,
        }
    }
}

// ---------------------------------------------------------------------------
// Subject DN
// ---------------------------------------------------------------------------

/// A parsed Subject Distinguished Name: its attribute/value pairs in encoding
/// (forward) order. [`fmt::Display`] renders them as `CN=Foo, O=Bar` joined
/// with `, ` — for human display, not RFC 4514 canonical form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectDn {
    /// The attribute/value pairs, in the order they appear in the certificate.
    pub rdns: Vec<(DnAttr, String)>,
}

impl fmt::Display for SubjectDn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for (attr, value) in &self.rdns {
            if !first {
                write!(f, ", ")?;
            }
            first = false;
            write!(f, "{}={}", attr.label(), value)?;
        }
        Ok(())
    }
}

/// Decode an `AttributeValue` string into a Rust `String`. PrintableString
/// (0x13), UTF8String (0x0C), and IA5String (0x16) are the common directory
/// string types; all are decoded as UTF-8 (lossy on invalid bytes), and any
/// other string-ish type is treated the same way as a best effort.
fn decode_dn_value(content: &[u8]) -> String {
    String::from_utf8_lossy(content).into_owned()
}

/// Parse the Subject DN out of a DER-encoded X.509 `Certificate`.
///
/// Navigates `Certificate -> tbsCertificate -> subject` per RFC 5280:
/// `tbsCertificate ::= SEQUENCE { [0] version OPTIONAL, serialNumber INTEGER,
/// signature SEQUENCE, issuer Name, validity SEQUENCE, subject Name, ... }`,
/// where `Name ::= SEQUENCE OF SET OF SEQUENCE { OID, value }`.
pub fn parse_subject_dn(cert_der: &[u8]) -> Result<SubjectDn, X509ParseError> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    let (cert, _) = expect_tag(cert_der, 0x30)?;
    // tbsCertificate ::= SEQUENCE { ... }
    let (tbs, _) = expect_tag(cert.content, 0x30)?;
    let mut rest = tbs.content;

    // Optional version [0] (context-specific constructed tag 0xA0): skip it.
    {
        let (peek, after) = read_tlv(rest)?;
        if peek.tag == 0xA0 {
            rest = after;
        }
    }
    // serialNumber INTEGER (0x02)
    let (_, rest) = expect_tag(rest, 0x02)?;
    // signature AlgorithmIdentifier SEQUENCE (0x30)
    let (_, rest) = expect_tag(rest, 0x30)?;
    // issuer Name SEQUENCE (0x30)
    let (_, rest) = expect_tag(rest, 0x30)?;
    // validity SEQUENCE (0x30)
    let (_, rest) = expect_tag(rest, 0x30)?;
    // subject Name SEQUENCE (0x30) — our target.
    let (subject, _) = expect_tag(rest, 0x30)?;

    parse_name(subject.content)
}

/// Parse a `Name` (RDNSequence): SEQUENCE content is a series of SETs, each SET
/// a series of `AttributeTypeAndValue` SEQUENCEs `{ OID, value }`. Attributes
/// are collected in encoding order (across SETs and within each SET).
fn parse_name(mut input: &[u8]) -> Result<SubjectDn, X509ParseError> {
    let mut rdns = Vec::new();
    while !input.is_empty() {
        // RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
        let (set, after_set) = expect_tag(input, 0x31)?;
        input = after_set;
        let mut atv = set.content;
        while !atv.is_empty() {
            // AttributeTypeAndValue ::= SEQUENCE { type OID, value }
            let (seq, after_seq) = expect_tag(atv, 0x30)?;
            atv = after_seq;
            // type OBJECT IDENTIFIER (0x06)
            let (oid_tlv, after_oid) = expect_tag(seq.content, 0x06)?;
            let oid = decode_oid(oid_tlv.content).ok_or(X509ParseError::Malformed)?;
            // value: a string type (PrintableString / UTF8String / IA5String / …)
            let (val_tlv, _) = read_tlv(after_oid)?;
            let attr = DnAttr::from_oid(&oid);
            rdns.push((attr, decode_dn_value(val_tlv.content)));
        }
    }
    Ok(SubjectDn { rdns })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oid_decoder_common_values() {
        // 2.5.4.3 = 55 04 03
        assert_eq!(decode_oid(&[0x55, 0x04, 0x03]).as_deref(), Some("2.5.4.3"));
        // 1.2.840.113549.1.9.1 = 2A 86 48 86 F7 0D 01 09 01
        assert_eq!(
            decode_oid(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01]).as_deref(),
            Some("1.2.840.113549.1.9.1")
        );
        // UID = 0.9.2342.19200300.100.1.1
        assert_eq!(
            decode_oid(&[0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x01]).as_deref(),
            Some("0.9.2342.19200300.100.1.1")
        );
    }

    #[test]
    fn oid_decoder_rejects_unterminated() {
        // Trailing byte with the high bit set and no terminator.
        assert_eq!(decode_oid(&[0x55, 0x81]), None);
    }

    #[test]
    fn tlv_long_form_length() {
        // Tag 0x04, long-form length 0x81 0x80 (128), 128 content bytes.
        let mut buf = vec![0x04, 0x81, 0x80];
        buf.extend(std::iter::repeat(0xAB).take(128));
        let (tlv, rest) = read_tlv(&buf).unwrap();
        assert_eq!(tlv.tag, 0x04);
        assert_eq!(tlv.content.len(), 128);
        assert!(rest.is_empty());
    }

    #[test]
    fn tlv_long_form_length_two_and_three_octets() {
        // 0x82 form: 2 length octets encoding 0x0140 = 320 content bytes.
        let mut buf = vec![0x04, 0x82, 0x01, 0x40];
        buf.extend(std::iter::repeat(0xCD).take(320));
        let (tlv, rest) = read_tlv(&buf).unwrap();
        assert_eq!(tlv.tag, 0x04);
        assert_eq!(tlv.content.len(), 320);
        assert!(rest.is_empty());

        // 0x83 form: 3 length octets encoding 0x010000 = 65536 content bytes.
        let mut buf = vec![0x04, 0x83, 0x01, 0x00, 0x00];
        buf.extend(std::iter::repeat(0xEF).take(65536));
        let (tlv, rest) = read_tlv(&buf).unwrap();
        assert_eq!(tlv.tag, 0x04);
        assert_eq!(tlv.content.len(), 65536);
        assert!(rest.is_empty());
    }

    #[test]
    fn tlv_rejects_five_octet_length() {
        // 0x85 announces 5 length octets — beyond the 4-octet cap. Must Err
        // (LengthTooLarge), not panic, even though no length octets follow.
        assert_eq!(
            read_tlv(&[0x04, 0x85, 0x00, 0x00, 0x00, 0x00, 0x01]).err(),
            Some(X509ParseError::LengthTooLarge)
        );
        // 0x8F (15 octets) likewise.
        assert_eq!(
            read_tlv(&[0x30, 0x8F]).err(),
            Some(X509ParseError::LengthTooLarge)
        );
    }

    #[test]
    fn parse_subject_dn_rejects_unterminated_oid() {
        // Hand-built minimal Certificate whose subject contains an attribute OID
        // whose final byte has the high bit set with no terminator — malformed.
        // Build inner -> outer so lengths stay short-form (all < 128).
        //
        // AttributeTypeAndValue ::= SEQUENCE { OID (bad), value }
        // OID content: 0x55 0x81  (0x81 continues but nothing follows -> malformed)
        let oid = [0x06u8, 0x02, 0x55, 0x81]; // OBJECT IDENTIFIER, len 2
        let value = [0x13u8, 0x01, b'X']; // PrintableString "X"
        let mut atv_content = Vec::new();
        atv_content.extend_from_slice(&oid);
        atv_content.extend_from_slice(&value);
        let mut atv = vec![0x30, atv_content.len() as u8]; // SEQUENCE
        atv.extend_from_slice(&atv_content);

        let mut set = vec![0x31, atv.len() as u8]; // SET
        set.extend_from_slice(&atv);

        // subject Name ::= SEQUENCE OF SET
        let mut subject = vec![0x30, set.len() as u8];
        subject.extend_from_slice(&set);

        // tbsCertificate fields that parse_subject_dn walks before `subject`:
        // serialNumber INTEGER, signature SEQUENCE, issuer SEQUENCE, validity SEQUENCE.
        let serial = [0x02u8, 0x01, 0x01]; // INTEGER 1
        let sig_alg = [0x30u8, 0x00]; // empty SEQUENCE
        let issuer = [0x30u8, 0x00]; // empty Name SEQUENCE
        let validity = [0x30u8, 0x00]; // empty SEQUENCE

        let mut tbs_content = Vec::new();
        tbs_content.extend_from_slice(&serial);
        tbs_content.extend_from_slice(&sig_alg);
        tbs_content.extend_from_slice(&issuer);
        tbs_content.extend_from_slice(&validity);
        tbs_content.extend_from_slice(&subject);
        let mut tbs = vec![0x30, tbs_content.len() as u8];
        tbs.extend_from_slice(&tbs_content);

        // Certificate ::= SEQUENCE { tbsCertificate, ... } — only tbs is read.
        let mut cert = vec![0x30, tbs.len() as u8];
        cert.extend_from_slice(&tbs);

        assert_eq!(
            parse_subject_dn(&cert),
            Err(X509ParseError::Malformed),
            "unterminated OID in subject must be rejected as Malformed"
        );
    }

    #[test]
    fn tlv_rejects_truncated_and_indefinite() {
        assert_eq!(read_tlv(&[]).err(), Some(X509ParseError::Truncated));
        assert_eq!(read_tlv(&[0x30]).err(), Some(X509ParseError::Truncated));
        // Declared length 5 but only 2 content bytes present.
        assert_eq!(
            read_tlv(&[0x04, 0x05, 0x00, 0x01]).err(),
            Some(X509ParseError::Truncated)
        );
        // Indefinite length 0x80.
        assert_eq!(
            read_tlv(&[0x30, 0x80]).err(),
            Some(X509ParseError::LengthTooLarge)
        );
    }
}
