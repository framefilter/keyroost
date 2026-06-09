//! End-to-end: real QR images (generated with qrencode, JPEG via
//! ImageMagick) through the full decode → parse → entries pipeline.

#[test]
fn enrollment_png_round_trips() {
    let img = include_bytes!("fixtures/enroll.png");
    let import = keyroost_qr::entries_from_image(img).expect("decode png");
    assert_eq!(import.entries.len(), 1);
    let e = &import.entries[0];
    assert_eq!(e.issuer.as_deref(), Some("Acme"));
    assert_eq!(e.account.as_deref(), Some("alice"));
    // JBSWY3DPEHPK3PXP is the canonical test secret "Hello!\xde\xad\xbe\xef".
    assert_eq!(e.secret, b"Hello!\xde\xad\xbe\xef");
}

#[test]
fn enrollment_jpeg_round_trips() {
    let img = include_bytes!("fixtures/enroll.jpg");
    let import = keyroost_qr::entries_from_image(img).expect("decode jpeg");
    assert_eq!(import.entries.len(), 1);
    assert_eq!(import.entries[0].issuer.as_deref(), Some("Acme"));
}

#[test]
fn google_authenticator_migration_png_round_trips() {
    let img = include_bytes!("fixtures/migration.png");
    let import = keyroost_qr::entries_from_image(img).expect("decode migration");
    assert_eq!(import.entries.len(), 1);
    let e = &import.entries[0];
    assert_eq!(e.secret, b"0123456789");
    assert_eq!(e.issuer.as_deref(), Some("Acme"));
    assert_eq!(e.account.as_deref(), Some("alice"));
    assert!(import.skipped.is_empty());
    assert_eq!(import.batch, None);
}
