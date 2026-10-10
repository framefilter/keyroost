//! Sorting a dropped or opened file before anything reads it as an import:
//! an authenticator export, recognized key material (a certificate, a key,
//! ...) that belongs somewhere else, or something keyroost doesn't read.
//!
//! Classification looks only at the bytes it is given (plus, for binary
//! DER and OpenPGP files, the file name's extension). It never decrypts a
//! vault or decodes an image, and its JSON probes never materialize an entry
//! or a seed. The JSON probes need the `bulk` feature; without it every JSON
//! file is [`FileKind::Unknown`].

/// An authenticator export keyroost can read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFormat {
    Aegis,
    AegisEncrypted,
    TwoFas,
    TwoFasEncrypted,
    OtpauthList,
    /// A PNG or JPEG image (a QR screenshot, maybe).
    Image,
}

/// Key material keyroost recognizes but doesn't import as authenticator
/// codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyMaterial {
    Certificate,
    CertificateRequest,
    PrivateKey,
    OpenPgpKey,
    SshKey,
    Pkcs12,
}

/// What a file is, as far as importing goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    Authenticator(AuthFormat),
    KeyMaterial(KeyMaterial),
    Unknown,
}

/// Shown for a file that is neither an authenticator export nor recognized
/// key material.
pub const UNKNOWN_FILE: &str =
    "keyroost can't import this file. It reads Aegis, 2FAS and otpauth:// list exports and QR screenshots.";

impl KeyMaterial {
    /// "a certificate", "an OpenPGP key", ...
    pub fn what(self) -> &'static str {
        match self {
            KeyMaterial::Certificate => "a certificate",
            KeyMaterial::CertificateRequest => "a certificate request",
            KeyMaterial::PrivateKey => "a private key",
            KeyMaterial::OpenPgpKey => "an OpenPGP key",
            KeyMaterial::SshKey => "an SSH key",
            KeyMaterial::Pkcs12 => "a PKCS #12 bundle",
        }
    }

    /// Where keyroost imports it, or that it doesn't, in GUI words. Each ends
    /// "Nothing was changed."
    pub fn gui_pointer(self) -> &'static str {
        match self {
            KeyMaterial::Certificate => {
                "This looks like a certificate. To put it on a key, open the key's PIV tab \
                 and use Import certificate. Nothing was changed."
            }
            KeyMaterial::PrivateKey => {
                "This looks like a private key. keyroost imports RSA-2048 private keys in a \
                 key's OpenPGP tab (Import key from file). Nothing was changed."
            }
            KeyMaterial::CertificateRequest => {
                "This looks like a certificate request. keyroost can't import this kind of \
                 file. Nothing was changed."
            }
            KeyMaterial::OpenPgpKey => {
                "This looks like an OpenPGP key. keyroost can't import this kind of file. \
                 Nothing was changed."
            }
            KeyMaterial::SshKey => {
                "This looks like an SSH key. keyroost can't import this kind of file. \
                 Nothing was changed."
            }
            KeyMaterial::Pkcs12 => {
                "This looks like a PKCS #12 bundle. keyroost can't import this kind of file. \
                 Nothing was changed."
            }
        }
    }

    /// The same in CLI words.
    pub fn cli_pointer(self) -> &'static str {
        match self {
            KeyMaterial::Certificate => {
                "This looks like a certificate. To put it on a key, use: \
                 keyroostctl -d KEY piv cert import --slot SLOT --in FILE. Nothing was changed."
            }
            KeyMaterial::PrivateKey => {
                "This looks like a private key. keyroost imports RSA-2048 private keys with: \
                 keyroostctl -d KEY openpgp key import --in FILE. Nothing was changed."
            }
            // No command imports these, so the wording is the GUI's.
            other => other.gui_pointer(),
        }
    }
}

/// Sort a file by content (and, for binary DER, its extension). Never
/// decrypts or decodes images; reads at most the bytes given.
pub fn classify(bytes: &[u8], file_name: Option<&str>) -> FileKind {
    // 1. Images, by magic bytes.
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") || bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return FileKind::Authenticator(AuthFormat::Image);
    }

    let text = core::str::from_utf8(bytes).ok();
    if let Some(text) = text {
        // 2. JSON: an Aegis or 2FAS export, or nothing keyroost reads.
        if text.trim_start().starts_with('{') {
            return classify_json(text);
        }
        // 3. Any otpauth line makes it a list (bad lines are reported per
        //    line by the list parser).
        if text
            .lines()
            .map(str::trim_start)
            .any(|l| l.starts_with("otpauth://") || l.starts_with("otpauth-migration://"))
        {
            return FileKind::Authenticator(AuthFormat::OtpauthList);
        }
    }

    // 4. PEM armor, by label.
    if let Some(kind) = pem_kind(bytes) {
        return FileKind::KeyMaterial(kind);
    }

    // 5. An OpenSSH public key line.
    let first_line = bytes
        .split(|&b| b == b'\n')
        .next()
        .unwrap_or_default()
        .trim_ascii_start();
    const SSH_PREFIXES: [&[u8]; 5] = [
        b"ssh-ed25519 ",
        b"ssh-rsa ",
        b"ecdsa-sha2-",
        b"sk-ssh-",
        b"sk-ecdsa-",
    ];
    if SSH_PREFIXES.iter().any(|p| first_line.starts_with(p)) {
        return FileKind::KeyMaterial(KeyMaterial::SshKey);
    }

    let ext = extension(file_name);
    // Binary: not UTF-8, or carrying control bytes no text file has (DER
    // always does: its INTEGER/OCTET STRING/OID tags are 0x02/0x04/0x06).
    let binary = text.is_none() || bytes.iter().any(|&b| b < 0x09 || (0x0e..0x20).contains(&b));
    // 6. DER (an ASN.1 SEQUENCE), named by its extension.
    if binary && bytes.first() == Some(&0x30) {
        let kind = match ext.as_deref() {
            Some("cer" | "crt" | "der") => Some(KeyMaterial::Certificate),
            Some("p12" | "pfx") => Some(KeyMaterial::Pkcs12),
            Some("key") => Some(KeyMaterial::PrivateKey),
            Some("csr") => Some(KeyMaterial::CertificateRequest),
            _ => None,
        };
        if let Some(kind) = kind {
            return FileKind::KeyMaterial(kind);
        }
    }

    // 7. Binary OpenPGP.
    if binary && matches!(ext.as_deref(), Some("gpg" | "pgp")) {
        return FileKind::KeyMaterial(KeyMaterial::OpenPgpKey);
    }

    FileKind::Unknown
}

#[cfg(feature = "bulk")]
fn classify_json(text: &str) -> FileKind {
    match crate::bulk::aegis::is_encrypted(text) {
        // A string `db` is a vault only with Aegis's header around it.
        Ok(true) if crate::bulk::aegis::has_vault_shape(text) => {
            return FileKind::Authenticator(AuthFormat::AegisEncrypted)
        }
        Ok(true) => return FileKind::Unknown,
        Ok(false) => return FileKind::Authenticator(AuthFormat::Aegis),
        Err(_) => {}
    }
    match crate::bulk::twofas::probe(text) {
        Some(true) => FileKind::Authenticator(AuthFormat::TwoFasEncrypted),
        Some(false) => FileKind::Authenticator(AuthFormat::TwoFas),
        None => FileKind::Unknown,
    }
}

#[cfg(not(feature = "bulk"))]
fn classify_json(_text: &str) -> FileKind {
    FileKind::Unknown
}

/// The first recognized `-----BEGIN <LABEL>-----` in the file.
fn pem_kind(bytes: &[u8]) -> Option<KeyMaterial> {
    const BEGIN: &[u8] = b"-----BEGIN ";
    let mut rest = bytes;
    while let Some(at) = find(rest, BEGIN) {
        rest = &rest[at + BEGIN.len()..];
        let end = find(rest, b"-----")?;
        let kind = match &rest[..end] {
            b"CERTIFICATE" => Some(KeyMaterial::Certificate),
            b"CERTIFICATE REQUEST" | b"NEW CERTIFICATE REQUEST" => {
                Some(KeyMaterial::CertificateRequest)
            }
            b"PRIVATE KEY" | b"RSA PRIVATE KEY" | b"EC PRIVATE KEY" | b"ENCRYPTED PRIVATE KEY" => {
                Some(KeyMaterial::PrivateKey)
            }
            b"OPENSSH PRIVATE KEY" => Some(KeyMaterial::SshKey),
            b"PGP PRIVATE KEY BLOCK" | b"PGP PUBLIC KEY BLOCK" => Some(KeyMaterial::OpenPgpKey),
            _ => None,
        };
        if kind.is_some() {
            return kind;
        }
        rest = &rest[end..];
    }
    None
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// The file name's extension, lowercased.
fn extension(file_name: Option<&str>) -> Option<String> {
    let name = file_name?;
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let (stem, ext) = base.rsplit_once('.')?;
    if stem.is_empty() {
        return None;
    }
    Some(ext.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PNG: &[u8] = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR";
    const JPEG: &[u8] = &[0xFF, 0xD8, 0xFF, 0xE0, 0, 0x10];
    const DER: &[u8] = &[0x30, 0x82, 0x01, 0x0a, 0x02, 0x82];

    #[test]
    fn classify_table() {
        use AuthFormat as A;
        use FileKind::{Authenticator as Auth, KeyMaterial as Km, Unknown};
        use KeyMaterial as K;
        let pem = |label: &str| {
            format!("Bag Attributes\n-----BEGIN {label}-----\nMIIB\n-----END {label}-----\n")
        };
        let cases: Vec<(Vec<u8>, Option<&str>, FileKind)> = vec![
            // 1. images
            (PNG.to_vec(), Some("shot.png"), Auth(A::Image)),
            (JPEG.to_vec(), None, Auth(A::Image)),
            (PNG.to_vec(), Some("named.txt"), Auth(A::Image)),
            // 2. JSON
            (
                br#"{"version":1,"db":{"entries":[]}}"#.to_vec(),
                None,
                Auth(A::Aegis),
            ),
            (
                br#"  {"version":1,"header":{"slots":[{"type":1}],"params":{"nonce":"","tag":""}},"db":"ZW5jcnlwdGVk"}"#.to_vec(),
                None,
                Auth(A::AegisEncrypted),
            ),
            // A string `db` alone isn't a vault: it needs Aegis's header.
            (br#"{"db":"postgres://localhost/app"}"#.to_vec(), Some("config.json"), Unknown),
            (br#"{"header":{},"db":"ZW5jcnlwdGVk"}"#.to_vec(), None, Unknown),
            (
                br#"{"version":1,"header":{"slots":null,"params":null},"db":"ZW5j"}"#.to_vec(),
                None,
                Unknown,
            ),
            (
                br#"{"services":[{"name":"x","secret":"JBSWY3DP"}]}"#.to_vec(),
                None,
                Auth(A::TwoFas),
            ),
            (
                br#"{"services":[],"servicesEncrypted":"abc"}"#.to_vec(),
                None,
                Auth(A::TwoFasEncrypted),
            ),
            (
                br#"{"servicesEncrypted":"abc"}"#.to_vec(),
                None,
                Auth(A::TwoFasEncrypted),
            ),
            (
                br#"{"name":"package","version":"1"}"#.to_vec(),
                Some("x.json"),
                Unknown,
            ),
            (b"{ not json".to_vec(), None, Unknown),
            // 3. otpauth lists
            (
                b"# list\n  otpauth://totp/A?secret=JBSWY3DP\n".to_vec(),
                None,
                Auth(A::OtpauthList),
            ),
            (
                b"hello\notpauth-migration://offline?data=CgA%3D\n".to_vec(),
                None,
                Auth(A::OtpauthList),
            ),
            // 4. PEM
            (pem("CERTIFICATE").into_bytes(), None, Km(K::Certificate)),
            (
                pem("CERTIFICATE REQUEST").into_bytes(),
                None,
                Km(K::CertificateRequest),
            ),
            (
                pem("NEW CERTIFICATE REQUEST").into_bytes(),
                None,
                Km(K::CertificateRequest),
            ),
            (pem("PRIVATE KEY").into_bytes(), None, Km(K::PrivateKey)),
            (pem("RSA PRIVATE KEY").into_bytes(), None, Km(K::PrivateKey)),
            (pem("EC PRIVATE KEY").into_bytes(), None, Km(K::PrivateKey)),
            (
                pem("ENCRYPTED PRIVATE KEY").into_bytes(),
                None,
                Km(K::PrivateKey),
            ),
            (pem("OPENSSH PRIVATE KEY").into_bytes(), None, Km(K::SshKey)),
            (
                pem("PGP PRIVATE KEY BLOCK").into_bytes(),
                None,
                Km(K::OpenPgpKey),
            ),
            (
                pem("PGP PUBLIC KEY BLOCK").into_bytes(),
                None,
                Km(K::OpenPgpKey),
            ),
            (pem("PUBLIC KEY").into_bytes(), None, Unknown),
            (
                format!("{}{}", pem("X509 CRL"), pem("CERTIFICATE")).into_bytes(),
                None,
                Km(K::Certificate),
            ),
            // 5. OpenSSH public keys
            (
                b"ssh-ed25519 AAAAC3Nz me@host\n".to_vec(),
                None,
                Km(K::SshKey),
            ),
            (b"ssh-rsa AAAAB3Nz\n".to_vec(), None, Km(K::SshKey)),
            (
                b"ecdsa-sha2-nistp256 AAAAE2Vj".to_vec(),
                None,
                Km(K::SshKey),
            ),
            (
                b"sk-ssh-ed25519@openssh.com AAAA".to_vec(),
                None,
                Km(K::SshKey),
            ),
            (
                b"sk-ecdsa-sha2-nistp256@openssh.com AAAA".to_vec(),
                None,
                Km(K::SshKey),
            ),
            (b"comment\nssh-rsa AAAAB3Nz\n".to_vec(), None, Unknown),
            // 6. DER by extension
            (DER.to_vec(), Some("x.cer"), Km(K::Certificate)),
            (DER.to_vec(), Some("x.CRT"), Km(K::Certificate)),
            (DER.to_vec(), Some("dir.d/x.der"), Km(K::Certificate)),
            (DER.to_vec(), Some("x.p12"), Km(K::Pkcs12)),
            (DER.to_vec(), Some("x.pfx"), Km(K::Pkcs12)),
            (DER.to_vec(), Some("x.key"), Km(K::PrivateKey)),
            (DER.to_vec(), Some("x.csr"), Km(K::CertificateRequest)),
            (DER.to_vec(), Some("x.bin"), Unknown),
            (DER.to_vec(), None, Unknown),
            // A text file that happens to start with '0' (0x30) isn't DER.
            (b"0123 notes\n".to_vec(), Some("x.key"), Unknown),
            // 7. binary OpenPGP by extension
            (
                vec![0x99, 0x01, 0x0d, 0x04],
                Some("key.gpg"),
                Km(K::OpenPgpKey),
            ),
            (
                vec![0x99, 0x01, 0x0d, 0x04],
                Some("key.PGP"),
                Km(K::OpenPgpKey),
            ),
            // 8. everything else
            (vec![0x99, 0x01, 0x0d, 0x04], Some("key.bin"), Unknown),
            (b"just some notes\n".to_vec(), Some("notes.txt"), Unknown),
            (Vec::new(), None, Unknown),
        ];
        let mut wrong = Vec::new();
        for (bytes, name, want) in &cases {
            let got = classify(bytes, *name);
            if got != *want {
                wrong.push(format!(
                    "{:?} {:?}: got {:?}, want {:?}",
                    String::from_utf8_lossy(bytes),
                    name,
                    got,
                    want
                ));
            }
        }
        assert!(wrong.is_empty(), "\n{}", wrong.join("\n"));
    }

    #[test]
    fn pointer_texts_end_nothing_changed() {
        use KeyMaterial as K;
        for k in [
            K::Certificate,
            K::CertificateRequest,
            K::PrivateKey,
            K::OpenPgpKey,
            K::SshKey,
            K::Pkcs12,
        ] {
            for text in [k.gui_pointer(), k.cli_pointer()] {
                assert!(text.ends_with("Nothing was changed."), "{text}");
                assert!(text.starts_with("This looks like "), "{text}");
                assert!(text.contains(k.what()), "{text}");
                assert!(!text.contains("  "), "double space in {text:?}");
            }
        }
        assert!(K::Certificate
            .gui_pointer()
            .contains("PIV tab and use Import certificate"));
        assert!(K::Certificate
            .cli_pointer()
            .contains("keyroostctl -d KEY piv cert import --slot SLOT --in FILE"));
        assert!(K::PrivateKey
            .cli_pointer()
            .contains("openpgp key import --in FILE"));
        assert!(K::SshKey
            .gui_pointer()
            .contains("keyroost can't import this kind of file"));
        assert!(UNKNOWN_FILE.starts_with("keyroost can't import this file."));
    }
}
