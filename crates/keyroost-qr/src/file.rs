//! The one "read this file" entry point the CLI and the GUI share: classify
//! the bytes, then read an authenticator export (decrypting an Aegis vault
//! when a password is given, decoding QR screenshots) into the wide
//! [`ImportFile`] model — or say what else the file is.

use keyroost_import::classify::{classify, AuthFormat, FileKind, KeyMaterial, UNKNOWN_FILE};
use keyroost_import::{aegis, twofas, BulkError, Format, ImportFile};

use crate::QrError;

/// Largest file `open_file` reads. Authenticator exports are kilobytes and
/// screenshots a few MiB; anything bigger isn't one.
pub const MAX_FILE_BYTES: usize = 16 * 1024 * 1024;

/// What a file turned out to hold.
#[derive(Debug)]
pub enum Opened {
    /// Entries read (decrypted if needed).
    Entries(ImportFile),
    /// An encrypted Aegis vault and no password was given.
    NeedsPassword,
    /// Recognized key material; nothing to import here.
    KeyMaterial(KeyMaterial),
}

/// Why a file couldn't be read as an import.
#[derive(Debug)]
pub enum OpenError {
    /// Too large (> 16 MiB), unreadable, or not a format keyroost reads.
    NotImportable(String),
    /// A recognized authenticator export that can't be read
    /// (wrong password, encrypted 2FAS, bad JSON, no entries).
    Unreadable(String),
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenError::NotImportable(msg) | OpenError::Unreadable(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for OpenError {}

/// Told to the person when a 2FAS export is password-protected: keyroost
/// doesn't decrypt those.
pub const TWOFAS_ENCRYPTED: &str =
    "This 2FAS export is encrypted. Re-export it from 2FAS without a password, then import that file.";

/// The one "read this file" entry point for CLI and GUI.
///
/// `file_name` (just the name, or a path) only helps tell binary key
/// material apart; the content decides everything else. `password` is used
/// only for an encrypted Aegis vault. The decrypted vault never leaves a
/// wipe-on-drop buffer; the entries come back in the same wipe-on-drop
/// model every parser uses.
pub fn open_file(
    bytes: &[u8],
    file_name: Option<&str>,
    password: Option<&[u8]>,
) -> Result<Opened, OpenError> {
    if bytes.len() > MAX_FILE_BYTES {
        return Err(too_large());
    }
    let format = match classify(bytes, file_name) {
        FileKind::Authenticator(format) => format,
        FileKind::KeyMaterial(kind) => return Ok(Opened::KeyMaterial(kind)),
        FileKind::Unknown => return Err(OpenError::NotImportable(UNKNOWN_FILE.to_owned())),
    };
    if format == AuthFormat::Image {
        return crate::entries_from_image_wide(bytes)
            .map(Opened::Entries)
            .map_err(image_error);
    }
    // Every other authenticator format was classified from valid UTF-8.
    let text = std::str::from_utf8(bytes)
        .map_err(|_| OpenError::NotImportable(UNKNOWN_FILE.to_owned()))?;
    let (file, layout) = match format {
        AuthFormat::Aegis => (aegis::parse_wide(text), "an Aegis export"),
        AuthFormat::AegisEncrypted => {
            let Some(password) = password else {
                return Ok(Opened::NeedsPassword);
            };
            // Wipe-on-drop: the plaintext is every seed in the vault.
            let plain = aegis::decrypt(text, password).map_err(decrypt_error)?;
            let file = aegis::parse_wide(&plain).map(|mut f| {
                f.format = Format::AegisEncrypted;
                f
            });
            (file, "an Aegis export")
        }
        AuthFormat::TwoFas => (twofas::parse_wide(text), "a 2FAS export"),
        AuthFormat::TwoFasEncrypted => {
            return Err(OpenError::Unreadable(TWOFAS_ENCRYPTED.to_owned()))
        }
        AuthFormat::OtpauthList => (keyroost_import::parse_list_wide(text), "an otpauth list"),
        AuthFormat::Image => unreachable!("handled above"),
    };
    file.map(Opened::Entries)
        .map_err(|e| read_error(&e, layout))
}

/// Read a file for [`open_file`], never holding more than
/// [`MAX_FILE_BYTES`] + 1 bytes: an oversized (or endless) source is refused
/// while reading, before it is all in memory.
///
/// A plaintext export is every seed in clear, so no copy of it is left
/// behind unwiped: the bytes go into a wipe-on-drop buffer that grows by
/// copying into a new wipe-on-drop buffer (the old one is wiped when it is
/// dropped), never by a plain reallocation.
pub fn read_bounded<R: std::io::Read>(
    mut reader: R,
) -> Result<zeroize::Zeroizing<Vec<u8>>, OpenError> {
    use zeroize::Zeroizing;
    const FIRST: usize = 64 * 1024;
    let limit = MAX_FILE_BYTES + 1;
    let mut buf = Zeroizing::new(Vec::with_capacity(FIRST));
    let mut chunk = Zeroizing::new([0u8; 8192]);
    loop {
        let want = chunk.len().min(limit - buf.len());
        if want == 0 {
            break;
        }
        let n = match reader.read(&mut chunk[..want]) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                return Err(OpenError::NotImportable(format!(
                    "The file couldn't be read ({}).",
                    e.kind()
                )))
            }
        };
        if buf.len() + n > buf.capacity() {
            let cap = (buf.capacity() * 2).max(buf.len() + n).min(limit);
            let mut grown = Zeroizing::new(Vec::with_capacity(cap));
            grown.extend_from_slice(&buf);
            buf = grown;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    if buf.len() > MAX_FILE_BYTES {
        return Err(too_large());
    }
    Ok(buf)
}

/// [`open_file`] on a path: a bounded read (see [`read_bounded`]), with the
/// file's name passed along for classification.
pub fn open_path(path: &std::path::Path, password: Option<&[u8]>) -> Result<Opened, OpenError> {
    let file = std::fs::File::open(path).map_err(|e| {
        OpenError::NotImportable(format!("The file couldn't be opened ({}).", e.kind()))
    })?;
    // Wipe-on-drop: a plaintext export is every seed in clear.
    let bytes = read_bounded(file)?;
    let name = path.file_name().and_then(|n| n.to_str());
    open_file(&bytes, name, password)
}

fn too_large() -> OpenError {
    OpenError::NotImportable(
        "This file is larger than 16 MiB, too large for an authenticator export or a \
         screenshot. Nothing was read."
            .to_owned(),
    )
}

/// A recognized export that didn't read, described without quoting any
/// value from the file.
fn read_error(e: &BulkError, layout: &str) -> OpenError {
    let msg = match e {
        BulkError::EmptyFile => "The file has no entries.".to_owned(),
        other => other.describe(layout),
    };
    OpenError::Unreadable(msg)
}

/// An export that didn't decrypt: told apart by the decryptor's typed error.
fn decrypt_error(e: BulkError) -> OpenError {
    match e {
        BulkError::WrongPassword => {
            OpenError::Unreadable("The password didn't open this Aegis export.".to_owned())
        }
        e @ BulkError::Json(_) => OpenError::Unreadable(e.describe("an encrypted Aegis export")),
        other => OpenError::Unreadable(format!("The Aegis export couldn't be opened: {}.", other)),
    }
}

/// An image with no readable 2FA code isn't an import; a 2FA code that is
/// damaged is a recognized export that didn't read.
fn image_error(e: QrError) -> OpenError {
    match e {
        QrError::Payload(_) => OpenError::Unreadable(e.to_string()),
        other => OpenError::NotImportable(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny all-white grayscale PNG: an image with no QR code in it.
    fn blank_png() -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut enc = png::Encoder::new(&mut out, 8, 8);
            enc.set_color(png::ColorType::Grayscale);
            enc.set_depth(png::BitDepth::Eight);
            let mut w = enc.write_header().unwrap();
            w.write_image_data(&[0xFF; 64]).unwrap();
        }
        out
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|c| format!("{:02x}", c)).collect()
    }

    /// An encrypted Aegis vault no password opens: a well-formed password
    /// slot (with cheap scrypt parameters) over random-looking ciphertext.
    /// The KDF runs and the slot's GCM tag check fails, exactly as for a
    /// wrong password on a real vault.
    fn locked_vault() -> String {
        format!(
            r#"{{"version":1,"header":{{"slots":[{{"type":1,"uuid":"0","key":"{}","key_params":{{"nonce":"{}","tag":"{}"}},"n":1024,"r":8,"p":1,"salt":"{}"}}],"params":{{"nonce":"{}","tag":"{}"}}}},"db":"ZW5jcnlwdGVkZGI="}}"#,
            hex(&[7u8; 32]),
            hex(&[1u8; 12]),
            hex(&[2u8; 16]),
            hex(&[3u8; 32]),
            hex(&[4u8; 12]),
            hex(&[5u8; 16]),
        )
    }

    #[test]
    fn open_file_image_without_qr_is_not_importable() {
        let png = blank_png();
        assert!(crate::looks_like_image(&png));
        match open_file(&png, Some("shot.png"), None) {
            Err(OpenError::NotImportable(msg)) => assert!(msg.contains("no QR code"), "{msg}"),
            other => panic!("expected NotImportable, got {other:?}"),
        }
    }

    #[test]
    fn open_file_encrypted_aegis_without_password_needs_password() {
        assert!(matches!(
            open_file(locked_vault().as_bytes(), Some("aegis.json"), None),
            Ok(Opened::NeedsPassword)
        ));
    }

    #[test]
    fn open_file_wrong_password_is_unreadable() {
        match open_file(locked_vault().as_bytes(), None, Some(b"not it")) {
            Err(OpenError::Unreadable(msg)) => {
                assert_eq!(msg, "The password didn't open this Aegis export.")
            }
            other => panic!("expected Unreadable, got {other:?}"),
        }
    }

    #[test]
    fn open_file_twofas_encrypted_says_re_export() {
        let json = br#"{"services":[],"servicesEncrypted":"c2VjcmV0","schemaVersion":4}"#;
        match open_file(json, Some("2fas.2fas"), None) {
            Err(OpenError::Unreadable(msg)) => {
                assert!(
                    msg.contains("Re-export it from 2FAS without a password"),
                    "{msg}"
                )
            }
            other => panic!("expected Unreadable, got {other:?}"),
        }
    }

    #[test]
    fn open_file_refuses_over_16_mib() {
        // A list that would otherwise read fine, padded past the cap.
        let mut big = b"otpauth://totp/A?secret=JBSWY3DP\n".to_vec();
        big.resize(MAX_FILE_BYTES + 1, b'\n');
        match open_file(&big, None, None) {
            Err(OpenError::NotImportable(msg)) => assert!(msg.contains("16 MiB"), "{msg}"),
            other => panic!("expected NotImportable, got {other:?}"),
        }
        // At the cap it is read.
        big.truncate(MAX_FILE_BYTES);
        assert!(matches!(
            open_file(&big, None, None),
            Ok(Opened::Entries(_))
        ));
    }

    #[test]
    fn open_file_reads_each_export_kind() {
        let aegis = br#"{"db":{"entries":[{"type":"hotp","name":"a","issuer":"X","info":{"secret":"JBSWY3DP","counter":2}}]}}"#;
        let twofas = br#"{"services":[{"name":"X","secret":"JBSWY3DP","otp":{}}]}"#;
        let list = b"otpauth://totp/A?secret=JBSWY3DP&period=45\n";
        for (bytes, want) in [
            (&aegis[..], Format::Aegis),
            (&twofas[..], Format::TwoFas),
            (&list[..], Format::OtpauthList),
        ] {
            match open_file(bytes, None, None) {
                Ok(Opened::Entries(f)) => {
                    assert_eq!(f.format, want);
                    assert_eq!(f.usable(), 1);
                }
                other => panic!("{want:?}: got {other:?}"),
            }
        }
        // A recognized export with nothing in it is unreadable, not unknown.
        assert!(matches!(
            open_file(br#"{"db":{"entries":[]}}"#, None, None),
            Err(OpenError::Unreadable(_))
        ));
    }

    /// Generated once by keyroost-import's `print_qr_fixture` test (its
    /// doc comment says how to regenerate it); password "keyroost-fixture".
    const ENCRYPTED_FIXTURE: &str = include_str!("../tests/fixtures/aegis-encrypted.json");

    #[test]
    fn open_file_decrypts_a_vault_with_the_right_password() {
        let bytes = ENCRYPTED_FIXTURE.trim_end().as_bytes();
        assert!(matches!(
            open_file(bytes, Some("aegis-export.json"), None),
            Ok(Opened::NeedsPassword)
        ));
        let file = match open_file(bytes, None, Some(b"keyroost-fixture")) {
            Ok(Opened::Entries(f)) => f,
            other => panic!("expected entries, got {other:?}"),
        };
        assert_eq!(file.format, Format::AegisEncrypted);
        let labels: Vec<_> = file.items.iter().map(|i| i.label.as_str()).collect();
        assert_eq!(labels, ["Acme:alice", "Bank:bob"]);
        let e = |i: usize| file.items[i].entry.as_ref().unwrap();
        assert_eq!(e(0).kind, keyroost_import::OtpKind::Totp { period: 45 });
        assert_eq!(e(0).hash, keyroost_import::HashAlg::Sha512);
        assert_eq!(&e(0).secret[..], b"Hello!\xde\xad\xbe\xef");
        assert_eq!(e(1).kind, keyroost_import::OtpKind::Hotp { counter: 7 });
        assert!(matches!(
            open_file(bytes, None, Some(b"keyroost-fixturE")),
            Err(OpenError::Unreadable(_))
        ));
    }

    #[test]
    fn read_bounded_stops_at_the_cap_while_reading() {
        // An endless source: only a bounded read can return at all.
        match read_bounded(std::io::repeat(b'x')) {
            Err(OpenError::NotImportable(msg)) => assert!(msg.contains("16 MiB"), "{msg}"),
            other => panic!("expected NotImportable, got {other:?}"),
        }
        assert_eq!(read_bounded(&b"abc"[..]).unwrap().as_slice(), b"abc");
        let at_cap = std::io::Read::take(std::io::repeat(b'\n'), MAX_FILE_BYTES as u64);
        assert_eq!(read_bounded(at_cap).unwrap().len(), MAX_FILE_BYTES);
    }

    #[test]
    fn read_bounded_keeps_every_byte_across_growth_in_a_wiped_buffer() {
        // Several times the first allocation, with a pattern so a lost or
        // reordered chunk shows; the buffer type wipes on drop.
        let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let got: zeroize::Zeroizing<Vec<u8>> = read_bounded(&data[..]).unwrap();
        assert_eq!(got.as_slice(), data.as_slice());
    }

    #[test]
    fn open_path_reads_a_file_by_name() {
        let dir =
            std::env::temp_dir().join(format!("keyroost-qr-open-path-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("export.txt");
        std::fs::write(&path, "otpauth://hotp/A?secret=JBSWY3DP&counter=3\n").unwrap();
        let opened = open_path(&path, None);
        std::fs::remove_dir_all(&dir).unwrap();
        match opened {
            Ok(Opened::Entries(f)) => assert_eq!(f.usable(), 1),
            other => panic!("expected entries, got {other:?}"),
        }
        assert!(matches!(
            open_path(&dir.join("missing.json"), None),
            Err(OpenError::NotImportable(_))
        ));
    }

    #[test]
    fn errors_never_quote_file_values() {
        let unread = |bytes: &[u8]| match open_file(bytes, None, None) {
            Err(OpenError::Unreadable(msg)) => msg,
            other => panic!("expected Unreadable, got {other:?}"),
        };
        // A wrong-typed value: serde would quote it ("invalid type: string").
        let msg = unread(
            br#"{"db":{"entries":[{"type":"totp","name":"a","info":{"secret":"JBSWY3DP","digits":"SENTINEL-VALUE"}}]}}"#,
        );
        assert!(!msg.contains("SENTINEL"), "{msg}");
        assert!(
            msg.starts_with("The file doesn't match the layout of an Aegis export"),
            "{msg}"
        );
        assert!(msg.contains("line 1, column"), "{msg}");
        // A missing field names the field (from the schema) and where.
        let msg = unread(br#"{"db":{"entries":[{"type":"totp","name":"SENTINEL","info":{}}]}}"#);
        assert!(!msg.contains("SENTINEL"), "{msg}");
        assert!(msg.contains("missing field `secret`"), "{msg}");
        // Broken JSON isn't recognized as an export at all.
        match open_file(b"{\"services\": [ {\"name\": \"SENTINEL\"", None, None) {
            Err(OpenError::NotImportable(msg)) => assert!(!msg.contains("SENTINEL"), "{msg}"),
            other => panic!("expected NotImportable, got {other:?}"),
        }
    }

    #[test]
    fn open_file_points_key_material_elsewhere_and_refuses_unknown() {
        let pem = b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
        assert!(matches!(
            open_file(pem, Some("c.pem"), None),
            Ok(Opened::KeyMaterial(KeyMaterial::Certificate))
        ));
        match open_file(b"hello", Some("notes.txt"), None) {
            Err(OpenError::NotImportable(msg)) => assert_eq!(msg, UNKNOWN_FILE),
            other => panic!("expected NotImportable, got {other:?}"),
        }
    }
}
