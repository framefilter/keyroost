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

#[test]
fn wide_enrollment_png_reads_one_item() {
    let img = include_bytes!("fixtures/enroll.png");
    let file = keyroost_qr::entries_from_image_wide(img).expect("decode png");
    assert_eq!(file.format, keyroost_import::Format::QrImage);
    assert_eq!(file.items.len(), 1);
    assert_eq!(file.items[0].label, "Acme:alice");
    let e = file.items[0].entry.as_ref().expect("usable");
    assert_eq!(&e.secret[..], b"Hello!\xde\xad\xbe\xef");
    assert_eq!(file.batch, None);
}

#[test]
fn wide_migration_png_is_a_google_export() {
    let img = include_bytes!("fixtures/migration.png");
    let file = keyroost_qr::entries_from_image_wide(img).expect("decode migration");
    assert_eq!(file.format, keyroost_import::Format::GoogleExport);
    assert_eq!(file.usable(), 1);
    assert_eq!(file.items[0].label, "Acme:alice");
}

#[test]
fn wide_keeps_the_narrow_errors() {
    assert!(matches!(
        keyroost_qr::entries_from_image_wide(b"not an image"),
        Err(keyroost_qr::QrError::UnsupportedImage)
    ));
}
