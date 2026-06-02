//! Host-side RSA-2048 key material for OpenPGP card import.
//!
//! A small front-end helper shared by `keyroostctl` and `keyroost`. It owns the one
//! external-dependency exception in the workspace — the `rsa` crate — so the
//! protocol crates stay dependency-free and the security-critical keygen / parse
//! logic lives in exactly one place. It produces the full CRT component set
//! (`e, p, q, u, dp, dq, n`, minimal big-endian) that `keyroost_openpgp`'s import
//! path frames into the card's Extended Header List; the card selects which of
//! those parts it actually wants per its declared algorithm attributes.

use std::path::Path;

/// RSA-2048 private-key components for OpenPGP import, minimal big-endian.
///
/// Holds the full CRT set so the transport layer can satisfy whichever import
/// format the card declares (standard `e,p,q` or CRT `e,p,q,u,dp,dq`, with or
/// without the modulus). Borrow these as `keyroost_openpgp::RsaPrivateKeyParts`.
pub struct RsaKeyParts {
    pub e: Vec<u8>,
    pub p: Vec<u8>,
    pub q: Vec<u8>,
    /// `u = q⁻¹ mod p`.
    pub u: Vec<u8>,
    /// `dp = d mod (p−1)`.
    pub dp: Vec<u8>,
    /// `dq = d mod (q−1)`.
    pub dq: Vec<u8>,
    pub n: Vec<u8>,
}

/// Why obtaining RSA key parts failed. The `Display` strings are user-facing.
#[derive(Debug)]
pub enum RsaKeyError {
    /// Reading the key file failed.
    Io(std::io::Error),
    /// The key could not be parsed as PKCS#1 or PKCS#8 (PEM or DER).
    Parse(String),
    /// The key is not RSA-2048 (carries the actual modulus bit length).
    WrongSize(usize),
    /// Key generation or CRT precompute failed inside the `rsa` crate.
    Crypto(String),
    /// A required component was missing after CRT precompute.
    MissingComponent(&'static str),
}

impl std::fmt::Display for RsaKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RsaKeyError::Io(e) => write!(f, "cannot read key file: {e}"),
            RsaKeyError::Parse(e) => write!(f, "could not parse RSA private key: {e}"),
            RsaKeyError::WrongSize(bits) => write!(
                f,
                "key is RSA-{bits}, but the card slot is RSA-2048; \
                 import only supports 2048-bit keys"
            ),
            RsaKeyError::Crypto(e) => write!(f, "RSA operation failed: {e}"),
            RsaKeyError::MissingComponent(c) => write!(f, "RSA key missing precomputed {c}"),
        }
    }
}

impl std::error::Error for RsaKeyError {}

impl From<std::io::Error> for RsaKeyError {
    fn from(e: std::io::Error) -> Self {
        RsaKeyError::Io(e)
    }
}

/// Generate a fresh RSA-2048 key on the host and extract its import parts.
///
/// `RsaPrivateKey::new` validates the key and precomputes the CRT values
/// (dp, dq, qinv), so the full component set is available immediately.
pub fn generate_2048() -> Result<RsaKeyParts, RsaKeyError> {
    let mut rng = rand::thread_rng();
    let key = rsa::RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|e| RsaKeyError::Crypto(e.to_string()))?;
    parts_from_key(key)
}

/// Load an RSA private key from `path` and extract its import parts.
///
/// Accepts PKCS#8 or PKCS#1, PEM or DER, auto-detected: PEM by its
/// `-----BEGIN ... PRIVATE KEY-----` header, otherwise DER. The key must be
/// RSA-2048 (the only size the card slot is provisioned for here). The file
/// bytes are read locally; this crate never logs them.
pub fn load_from_file(path: &Path) -> Result<RsaKeyParts, RsaKeyError> {
    let bytes = std::fs::read(path)?;
    parts_from_encoded(&bytes)
}

/// Decode PKCS#1/PKCS#8 (PEM or DER) key bytes and extract the import parts.
/// Split out from [`load_from_file`] so the parsing path can be unit-tested
/// without touching the filesystem.
fn parts_from_encoded(bytes: &[u8]) -> Result<RsaKeyParts, RsaKeyError> {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs8::DecodePrivateKey;

    let key = if bytes.starts_with(b"-----BEGIN") {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| RsaKeyError::Parse("key file is not valid PEM/UTF-8".into()))?;
        // PKCS#8 ("BEGIN PRIVATE KEY") vs PKCS#1 ("BEGIN RSA PRIVATE KEY").
        rsa::RsaPrivateKey::from_pkcs8_pem(text)
            .or_else(|_| rsa::RsaPrivateKey::from_pkcs1_pem(text))
            .map_err(|e| RsaKeyError::Parse(e.to_string()))?
    } else {
        // Raw DER: try PKCS#8 then PKCS#1.
        rsa::RsaPrivateKey::from_pkcs8_der(bytes)
            .or_else(|_| rsa::RsaPrivateKey::from_pkcs1_der(bytes))
            .map_err(|e| RsaKeyError::Parse(e.to_string()))?
    };
    parts_from_key(key)
}

/// Validate the key is RSA-2048, ensure the CRT values are precomputed, and
/// extract the components (e, p, q, u, dp, dq, n) as minimal big-endian bytes.
fn parts_from_key(mut key: rsa::RsaPrivateKey) -> Result<RsaKeyParts, RsaKeyError> {
    use rsa::traits::{PrivateKeyParts, PublicKeyParts};

    let bits = key.n().bits();
    if bits != 2048 {
        return Err(RsaKeyError::WrongSize(bits));
    }
    // `from_*` decoders do not precompute the CRT values; `new` does. Calling
    // precompute unconditionally is cheap and makes dp/dq/qinv always present.
    key.precompute()
        .map_err(|e| RsaKeyError::Crypto(e.to_string()))?;

    let primes = key.primes();
    if primes.len() != 2 {
        return Err(RsaKeyError::Crypto("expected a 2-prime RSA key".into()));
    }
    let dp = key
        .dp()
        .ok_or(RsaKeyError::MissingComponent("dp"))?
        .to_bytes_be();
    let dq = key
        .dq()
        .ok_or(RsaKeyError::MissingComponent("dq"))?
        .to_bytes_be();
    // qinv = q⁻¹ mod p is positive; take its big-endian magnitude (drop sign).
    let u = key
        .qinv()
        .ok_or(RsaKeyError::MissingComponent("qinv"))?
        .to_bytes_be()
        .1;
    Ok(RsaKeyParts {
        e: key.e().to_bytes_be(),
        n: key.n().to_bytes_be(),
        p: primes[0].to_bytes_be(),
        q: primes[1].to_bytes_be(),
        u,
        dp,
        dq,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs8::EncodePrivateKey;

    #[test]
    fn generate_2048_has_expected_shapes() {
        let k = generate_2048().expect("keygen");
        // A 2048-bit modulus is exactly 256 bytes minimal big-endian (top bit
        // set); each prime is 1024 bits = 128 bytes.
        assert_eq!(k.n.len(), 256, "modulus should be 256 bytes");
        assert_eq!(k.p.len(), 128, "p should be 128 bytes");
        assert_eq!(k.q.len(), 128, "q should be 128 bytes");
        // Default public exponent is 65537 = 01 00 01.
        assert_eq!(k.e, vec![0x01, 0x00, 0x01]);
        // CRT components are present and sized like the primes.
        assert!(!k.u.is_empty() && !k.dp.is_empty() && !k.dq.is_empty());
        assert!(k.dp.len() <= 128 && k.dq.len() <= 128);
    }

    #[test]
    fn load_round_trips_through_der() {
        // Generate, serialize to PKCS#8 DER, parse back, and confirm the public
        // modulus survives the round trip (exercises the file-parse path
        // without keygen in the loader).
        let mut rng = rand::thread_rng();
        let key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("keygen");
        let der = key.to_pkcs8_der().expect("encode der");
        let parsed = parts_from_encoded(der.as_bytes()).expect("parse der");
        use rsa::traits::PublicKeyParts;
        assert_eq!(parsed.n, key.n().to_bytes_be());
        assert_eq!(parsed.e, key.e().to_bytes_be());
    }

    #[test]
    fn rejects_non_2048() {
        // A 1024-bit key (faster to generate) must be size-rejected.
        let mut rng = rand::thread_rng();
        let key = rsa::RsaPrivateKey::new(&mut rng, 1024).expect("keygen");
        let der = key.to_pkcs8_der().expect("encode der");
        // Avoid `{:?}` on the Ok value — RsaKeyParts deliberately isn't Debug
        // (it holds private-key bytes). Match on the error via Display.
        match parts_from_encoded(der.as_bytes()) {
            Err(RsaKeyError::WrongSize(1024)) => {}
            Err(e) => panic!("expected WrongSize(1024), got error: {e}"),
            Ok(_) => panic!("expected WrongSize(1024), but parsing succeeded"),
        }
    }

    #[test]
    fn rejects_garbage() {
        assert!(matches!(
            parts_from_encoded(&[0xDE, 0xAD, 0xBE, 0xEF]),
            Err(RsaKeyError::Parse(_))
        ));
    }
}
