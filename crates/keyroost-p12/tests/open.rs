//! `open()` against the fixture files: key parts, pairing and labels.

use keyroost_p12::{open, Contents, KeyParts, P12Error};
use keyroost_piv::x509_parse::parse_certificate_public_key;
use keyroost_piv::{KeyAlg, PublicKey};

const PW: &str = "keyroost-test";

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("tests/fixtures/{name}")).expect("fixture")
}

fn open_fixture(name: &str) -> Contents {
    open(&fixture(&format!("{name}.p12")), Some(PW)).expect("open")
}

fn cert_public(der: &[u8]) -> (KeyAlg, PublicKey) {
    parse_certificate_public_key(der).expect("cert key")
}

#[test]
fn rsa_parts_match_openssl() {
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::traits::{PrivateKeyParts, PublicKeyParts};
    for name in ["rsa2048-modern", "rsa2048-legacy", "rsa4096-modern"] {
        let c = open_fixture(name);
        assert_eq!(c.entries.len(), 1, "{name}");
        let reference =
            rsa::RsaPrivateKey::from_pkcs8_der(&fixture(&format!("{name}.key.der"))).unwrap();
        let KeyParts::Rsa {
            n,
            e,
            p,
            q,
            dp,
            dq,
            qinv,
            ..
        } = &c.entries[0].key
        else {
            panic!("{name}: not RSA");
        };
        assert_eq!(*n, reference.n().to_bytes_be());
        assert_eq!(*e, reference.e().to_bytes_be());
        assert_eq!(*p, reference.primes()[0].to_bytes_be());
        assert_eq!(*q, reference.primes()[1].to_bytes_be());
        assert_eq!(*dp, reference.dp().unwrap().to_bytes_be());
        assert_eq!(*dq, reference.dq().unwrap().to_bytes_be());
        assert_eq!(*qinv, reference.crt_coefficient().unwrap().to_bytes_be());
        assert_ne!(n[0], 0);
        assert_ne!(p[0], 0);
    }
    assert_eq!(
        open_fixture("rsa2048-modern").entries[0].key.alg(),
        KeyAlg::Rsa2048
    );
    assert_eq!(
        open_fixture("rsa4096-modern").entries[0].key.alg(),
        KeyAlg::Rsa4096
    );
}

#[test]
fn rsa_public_key_matches_certificate() {
    let c = open_fixture("rsa2048-modern");
    let cert = c.entries[0].certificate.as_deref().unwrap();
    assert_eq!(c.entries[0].key.public_key(), cert_public(cert).1);
}

#[test]
fn ec_scalar_and_public_point() {
    use p256::pkcs8::DecodePrivateKey as _;
    let c = open_fixture("p256-modern");
    let KeyParts::Ec { alg, scalar, .. } = &c.entries[0].key else {
        panic!("not EC");
    };
    assert_eq!(*alg, KeyAlg::EccP256);
    let reference = p256::SecretKey::from_pkcs8_der(&fixture("p256-modern.key.der")).unwrap();
    assert_eq!(scalar[..], reference.to_bytes()[..]);
    let cert = c.entries[0].certificate.as_deref().unwrap();
    assert_eq!(c.entries[0].key.public_key(), cert_public(cert).1);

    let c = open_fixture("p384-legacy");
    let KeyParts::Ec { alg, scalar, .. } = &c.entries[0].key else {
        panic!("not EC");
    };
    assert_eq!(*alg, KeyAlg::EccP384);
    assert_eq!(scalar.len(), 48);
    let cert = c.entries[0].certificate.as_deref().unwrap();
    assert_eq!(c.entries[0].key.public_key(), cert_public(cert).1);
}

#[test]
fn ed25519_and_x25519_public_derived() {
    for (name, alg) in [
        ("ed25519-modern", KeyAlg::Ed25519),
        ("x25519-modern", KeyAlg::X25519),
    ] {
        let c = open_fixture(name);
        let key = &c.entries[0].key;
        assert_eq!(key.alg(), alg);
        let cert = c.entries[0].certificate.as_deref().unwrap();
        assert_eq!(key.public_key(), cert_public(cert).1, "{name}");
    }
}

#[test]
fn chain_fixture_has_one_entry_two_authorities() {
    let c = open_fixture("rsa2048-chain");
    assert_eq!(c.entries.len(), 1);
    assert_eq!(
        c.entries[0].certificate.as_deref().unwrap(),
        &fixture("rsa2048-chain.crt.der")[..]
    );
    assert_eq!(c.authorities.len(), 2);
}

#[test]
fn two_entries_listed_with_labels() {
    let c = open_fixture("two-entries");
    assert_eq!(c.entries.len(), 2);
    assert_eq!(
        c.entries[0].certificate.as_deref().unwrap(),
        &fixture("two-entries.crt.der")[..]
    );
    assert_eq!(
        c.entries[1].certificate.as_deref().unwrap(),
        &fixture("two-entries.crt2.der")[..]
    );
    assert!(c.authorities.is_empty());
    for e in &c.entries {
        let label = e.label.as_deref().expect("label");
        assert!(!label.is_empty());
    }
    assert_ne!(c.entries[0].label, c.entries[1].label);
}

#[test]
fn key_only_entry_has_no_certificate() {
    let c = open_fixture("key-only");
    assert_eq!(c.entries.len(), 1);
    assert!(c.entries[0].certificate.is_none());
    assert!(c.authorities.is_empty());
}

#[test]
fn rsa_e3_is_reported_with_its_exponent() {
    let c = open_fixture("rsa-e3");
    let KeyParts::Rsa { e, .. } = &c.entries[0].key else {
        panic!("not RSA");
    };
    assert_eq!(e, &[3]);
}

#[test]
fn empty_password_and_modern_files_open() {
    assert!(open(&fixture("empty-password.p12"), None).is_ok());
    assert!(open(&fixture("ber-full.p12"), Some(PW)).is_ok());
    assert!(open(&fixture("macless-shrouded.p12"), Some(PW)).is_ok());
    assert_eq!(
        open(&fixture("macless-plain-key.p12"), Some(PW)).err(),
        Some(P12Error::Unsupported("file has no integrity check"))
    );
    assert_eq!(
        open(&fixture("rsa2048-modern.p12"), Some("nope")).err(),
        Some(P12Error::WrongPassword)
    );
}

#[test]
fn garbage_file_is_malformed() {
    assert!(matches!(
        open(&[0x30, 0x00], None),
        Err(P12Error::Malformed(_))
    ));
}

#[test]
fn key_parts_debug_does_not_print_secrets() {
    let c = open_fixture("p256-modern");
    let KeyParts::Ec { scalar, .. } = &c.entries[0].key else {
        panic!("not EC");
    };
    let hex: String = scalar.iter().map(|b| format!("{b:02x}")).collect();
    let shown = format!("{:?} {:?}", c.entries[0].key, c.entries[0]);
    assert!(!shown.contains(&hex));
    assert!(!shown.contains(&format!("{scalar:?}")));
    let c = open_fixture("rsa2048-modern");
    let shown = format!("{:?}", c.entries[0].key);
    assert!(shown.contains("Rsa2048"), "{shown}");
}
