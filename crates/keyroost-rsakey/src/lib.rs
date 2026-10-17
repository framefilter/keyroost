//! Host-side RSA key material (2048, 3072 or 4096 bits) for OpenPGP card import.
//!
//! A small front-end helper shared by `keyroostctl` and `keyroost`. It owns the one
//! external-dependency exception in the workspace — the `rsa` crate — so the
//! protocol crates stay dependency-free and the security-critical parse logic lives
//! in exactly one place. It produces the full CRT component set
//! (`e, p, q, u, dp, dq, n`, minimal big-endian) that `keyroost_openpgp`'s import
//! path frames into the card's Extended Header List; the card selects which of
//! those parts it actually wants per its declared algorithm attributes.

use std::path::Path;

/// RSA private-key components for OpenPGP import, minimal big-endian.
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

/// The `rsa` crate zeroizes its own `RsaPrivateKey` on drop; these extracted
/// copies deserve the same so a full private key doesn't linger in freed heap
/// pages (or swap / core dumps) after the card import finishes. `e` and `n`
/// are public but wiping them too costs nothing.
impl Drop for RsaKeyParts {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for buf in [
            &mut self.e,
            &mut self.p,
            &mut self.q,
            &mut self.u,
            &mut self.dp,
            &mut self.dq,
            &mut self.n,
        ] {
            buf.zeroize();
        }
    }
}

/// Why obtaining RSA key parts failed. The `Display` strings are user-facing.
#[non_exhaustive]
#[derive(Debug)]
pub enum RsaKeyError {
    /// Reading the key file failed.
    Io(std::io::Error),
    /// The key could not be parsed as PKCS#1 or PKCS#8 (PEM or DER).
    Parse(String),
    /// The key is not 2048, 3072 or 4096 bits (carries the actual modulus
    /// bit length).
    WrongSize(usize),
    /// The CRT precompute failed inside the `rsa` crate.
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
                "key is RSA-{bits}; import supports 2048-, 3072- and 4096-bit keys"
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

/// Load an RSA private key from `path` and extract its import parts.
///
/// Accepts PKCS#8 or PKCS#1, PEM or DER, auto-detected: PEM by its
/// `-----BEGIN ... PRIVATE KEY-----` header, otherwise DER. The key must be
/// 2048, 3072 or 4096 bits, the RSA sizes OpenPGP cards hold. The file
/// bytes are read locally; this crate never logs them.
pub fn load_from_file(path: &Path) -> Result<RsaKeyParts, RsaKeyError> {
    // The raw file *is* the private key — wipe the read buffer on drop, the
    // same hygiene `RsaKeyParts` applies to the parsed components.
    let bytes = zeroize::Zeroizing::new(std::fs::read(path)?);
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

/// Validate the key is 2048, 3072 or 4096 bits, ensure the CRT values are
/// precomputed, and extract the components (e, p, q, u, dp, dq, n) as minimal
/// big-endian bytes.
fn parts_from_key(mut key: rsa::RsaPrivateKey) -> Result<RsaKeyParts, RsaKeyError> {
    use rsa::traits::{PrivateKeyParts, PublicKeyParts};

    let bits = key.n().bits();
    if !matches!(bits, 2048 | 3072 | 4096) {
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
    fn load_round_trips_through_der() {
        // Make a key, serialize it to PKCS#8 DER, parse it back, and confirm
        // the public modulus survives the round trip.
        let mut rng = rand::thread_rng();
        let key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("keygen");
        let der = key.to_pkcs8_der().expect("encode der");
        let parsed = parts_from_encoded(der.as_bytes()).expect("parse der");
        use rsa::traits::PublicKeyParts;
        assert_eq!(parsed.n, key.n().to_bytes_be());
        assert_eq!(parsed.e, key.e().to_bytes_be());
    }

    #[test]
    fn accepts_3072() {
        let mut rng = rand::thread_rng();
        let key = rsa::RsaPrivateKey::new(&mut rng, 3072).expect("keygen");
        let der = key.to_pkcs8_der().expect("encode der");
        let parsed = parts_from_encoded(der.as_bytes()).expect("parse der");
        assert_eq!(parsed.n.len(), 384);
    }

    #[test]
    fn rejects_unsupported_sizes() {
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
