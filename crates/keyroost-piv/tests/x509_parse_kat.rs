//! Known-answer tests for the Subject DN reader (`keyroost_piv::x509_parse`).
//!
//! Fixtures are real DER certificates minted offline with OpenSSL; the expected
//! Display strings are the subject components in **encoding (forward) order**,
//! which is the order they were passed to `openssl req -subj`. (OpenSSL's own
//! `-nameopt rfc2253` prints them reversed — this reader does not.)

use keyroost_piv::x509_parse::{parse_subject_dn, DnAttr, X509ParseError};

// C=US, O=keyroost, CN=PIV Authentication  (country is PrintableString; rest UTF8String)
const RSA_PIV: &[u8] = include_bytes!("fixtures/rsa_piv.der");
// CN=Test Key, OU=Engineering, O=Acme Corp  (EC P-256 key, all UTF8String)
const EC_TEST: &[u8] = include_bytes!("fixtures/ec_test.der");
// CN=Dom, UID=12345, L=Townsville  (UID OID 0.9.2342.19200300.100.1.1 is outside the known set)
const UNKNOWN_OID: &[u8] = include_bytes!("fixtures/unknown_oid.der");
// Subject C=US, O=keyroost, CN=Leaf Subject — signed by a DIFFERENT issuer
// (C=US, O=Example CA, CN=Example Root CA). Unlike the others this cert is NOT
// self-signed, so it catches a subject/issuer mix-up: the parser must return the
// *subject*, and the issuer's distinguishing names must never leak into it.
const LEAF_SIGNED: &[u8] = include_bytes!("fixtures/leaf_signed.der");

#[test]
fn rsa_subject_dn_forward_order() {
    let dn = parse_subject_dn(RSA_PIV).expect("RSA fixture parses");
    assert_eq!(dn.to_string(), "C=US, O=keyroost, CN=PIV Authentication");
    // Spot-check the structured pairs are in forward order with the right labels.
    assert_eq!(dn.rdns.len(), 3);
    assert_eq!(dn.rdns[0].0, DnAttr::Country);
    assert_eq!(dn.rdns[0].1, "US");
    assert_eq!(dn.rdns[2].0, DnAttr::CommonName);
    assert_eq!(dn.rdns[2].1, "PIV Authentication");
}

#[test]
fn ec_subject_dn_forward_order() {
    let dn = parse_subject_dn(EC_TEST).expect("EC fixture parses");
    assert_eq!(dn.to_string(), "CN=Test Key, OU=Engineering, O=Acme Corp");
}

#[test]
fn unknown_oid_renders_as_dotted_decimal() {
    let dn = parse_subject_dn(UNKNOWN_OID).expect("unknown-OID fixture parses");
    // The UID attribute has no short label, so it must fall back to its dotted OID
    // rather than being dropped.
    assert_eq!(
        dn.to_string(),
        "CN=Dom, 0.9.2342.19200300.100.1.1=12345, L=Townsville"
    );
    assert!(matches!(dn.rdns[1].0, DnAttr::Other(_)));
    assert_eq!(dn.rdns[1].0.label(), "0.9.2342.19200300.100.1.1");
}

#[test]
fn non_self_signed_returns_subject_not_issuer() {
    let dn = parse_subject_dn(LEAF_SIGNED).expect("leaf fixture parses");
    // Must be the SUBJECT in forward (encoding) order — verified against
    // `openssl x509 -inform DER -noout -subject` => "C=US, O=keyroost, CN=Leaf Subject".
    assert_eq!(dn.to_string(), "C=US, O=keyroost, CN=Leaf Subject");
    assert_eq!(dn.rdns.len(), 3);
    assert_eq!(dn.rdns[0].0, DnAttr::Country);
    assert_eq!(dn.rdns[0].1, "US");
    assert_eq!(dn.rdns[1].0, DnAttr::Organization);
    assert_eq!(dn.rdns[1].1, "keyroost");
    assert_eq!(dn.rdns[2].0, DnAttr::CommonName);
    assert_eq!(dn.rdns[2].1, "Leaf Subject");

    // The issuer (C=US, O=Example CA, CN=Example Root CA) must not bleed in:
    // a subject/issuer mix-up would surface these distinguishing strings.
    let rendered = dn.to_string();
    assert!(
        !rendered.contains("Example Root CA"),
        "issuer CN leaked into subject: {rendered}"
    );
    assert!(
        !rendered.contains("Example CA"),
        "issuer O leaked into subject: {rendered}"
    );
}

#[test]
fn empty_input_errors_without_panic() {
    assert!(parse_subject_dn(&[]).is_err());
}

#[test]
fn truncated_cert_errors_without_panic() {
    // First 20 bytes of a real cert: a valid outer SEQUENCE header whose declared
    // length runs far past the slice.
    let truncated = &RSA_PIV[..20];
    assert!(matches!(
        parse_subject_dn(truncated),
        Err(X509ParseError::Truncated) | Err(_)
    ));
}

#[test]
fn random_bytes_error_without_panic() {
    let junk: Vec<u8> = (0u16..512)
        .map(|i| (i.wrapping_mul(31) & 0xff) as u8)
        .collect();
    assert!(parse_subject_dn(&junk).is_err());
}

#[test]
fn dnattr_other_formats_oid() {
    // Directly exercise the OID formatter for the fallback path.
    let attr = DnAttr::Other("1.2.840.113549.1.9.1".to_string());
    assert_eq!(attr.label(), "1.2.840.113549.1.9.1");
}
