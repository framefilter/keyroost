//! Authenticator data (CTAP 2.1 §6.1, WebAuthn §6.1): the byte string an
//! authenticator returns from makeCredential and getAssertion.
//!
//! Layout:
//!
//! ```text
//! rpIdHash 32 | flags 1 | signCount u32 BE
//!   | attestedCredentialData   (only when flags & 0x40)
//!       AAGUID 16 | credentialIdLength u16 BE | credentialId | COSE public key
//!   | extensions CBOR map      (only when flags & 0x80)
//! ```
//!
//! [`parse_auth_data`] checks every length against the input and refuses
//! bytes after the parts the flags declare, so it is safe on device input.

use crate::cbor::{self, Value};
use crate::cmd::CtapError;

/// User present.
pub const FLAG_UP: u8 = 0x01;
/// User verified.
pub const FLAG_UV: u8 = 0x04;
/// Attested credential data included.
pub const FLAG_AT: u8 = 0x40;
/// Extension data included.
pub const FLAG_ED: u8 = 0x80;

const RP_ID_HASH_LEN: usize = 32;
const AAGUID_LEN: usize = 16;

/// The parts of authenticator data keyroost uses. The rpIdHash, AAGUID and
/// credential public key are checked for length and skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthData {
    pub flags: u8,
    pub sign_count: u32,
    /// The credential ID from the attested credential data; `None` when the
    /// `AT` flag (0x40) is clear.
    pub credential_id: Option<Vec<u8>>,
    /// The extension outputs map; `None` when the `ED` flag (0x80) is clear.
    pub extensions: Option<Value>,
}

const TRUNCATED: CtapError = CtapError::InvalidResponseShape("authenticator data is truncated");

/// Parse authenticator data. Every declared length is checked, and bytes left
/// over after the parts the flags announce are an error.
pub fn parse_auth_data(b: &[u8]) -> Result<AuthData, CtapError> {
    let rest = b.get(RP_ID_HASH_LEN..).ok_or(TRUNCATED)?;
    let (&flags, rest) = rest.split_first().ok_or(TRUNCATED)?;
    let (count, mut rest) = split(rest, 4)?;
    let sign_count = u32::from_be_bytes([count[0], count[1], count[2], count[3]]);

    let credential_id = if flags & FLAG_AT != 0 {
        let (_aaguid, r) = split(rest, AAGUID_LEN)?;
        let (len, r) = split(r, 2)?;
        let (id, r) = split(r, usize::from(u16::from_be_bytes([len[0], len[1]])))?;
        // The COSE public key is only measured: keyroost does not verify
        // attestation, so the key itself is not needed.
        let key_len = cbor::item_len(r)?;
        rest = &r[key_len..];
        Some(id.to_vec())
    } else {
        None
    };

    let extensions = if flags & FLAG_ED != 0 {
        let (value, r) = cbor::decode(rest)?;
        if value.as_map().is_none() {
            return Err(CtapError::InvalidResponseShape(
                "authenticator data extensions are not a map",
            ));
        }
        rest = r;
        Some(value)
    } else {
        None
    };

    if !rest.is_empty() {
        return Err(CtapError::InvalidResponseShape(
            "authenticator data has trailing bytes",
        ));
    }
    Ok(AuthData {
        flags,
        sign_count,
        credential_id,
        extensions,
    })
}

fn split(b: &[u8], n: usize) -> Result<(&[u8], &[u8]), CtapError> {
    if b.len() < n {
        return Err(TRUNCATED);
    }
    Ok(b.split_at(n))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Hand-built authenticator data with both optional parts.
    fn sample() -> Vec<u8> {
        unhex(concat!(
            // rpIdHash
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            // flags: UP | UV | AT | ED
            "c5",
            // signCount 7
            "00000007",
            // AAGUID
            "000102030405060708090a0b0c0d0e0f",
            // credentialIdLength 4, credentialId
            "0004 deadbeef",
            // COSE EC2 key {1: 2, 3: -7, -1: 1, -2: x, -3: y}
            "a5 0102 0326 2001",
            "21 5820 1111111111111111111111111111111111111111111111111111111111111111",
            "22 5820 2222222222222222222222222222222222222222222222222222222222222222",
            // extensions {"credProtect": 3}
            "a1 6b 6372656450726f74656374 03",
        ))
    }

    #[test]
    fn auth_data_with_attested_and_extensions() {
        let ad = parse_auth_data(&sample()).unwrap();
        assert_eq!(ad.flags, 0xc5);
        assert_eq!(ad.sign_count, 7);
        assert_eq!(
            ad.credential_id.as_deref(),
            Some(&[0xde, 0xad, 0xbe, 0xef][..])
        );
        assert_eq!(
            ad.extensions,
            Some(Value::Map(vec![(
                Value::Text("credProtect".into()),
                Value::UInt(3)
            )]))
        );
    }

    #[test]
    fn auth_data_truncated_errors() {
        let full = sample();
        for n in 0..full.len() {
            assert!(
                parse_auth_data(&full[..n]).is_err(),
                "a {n}-byte prefix must not parse"
            );
        }
    }

    #[test]
    fn auth_data_trailing_bytes_error() {
        let mut full = sample();
        full.push(0x00);
        assert!(matches!(
            parse_auth_data(&full),
            Err(CtapError::InvalidResponseShape(
                "authenticator data has trailing bytes"
            ))
        ));
        // Without AT or ED, anything after the sign count is trailing.
        let mut bare = vec![0u8; 37];
        bare[32] = FLAG_UP;
        assert_eq!(
            parse_auth_data(&bare).unwrap(),
            AuthData {
                flags: FLAG_UP,
                sign_count: 0,
                credential_id: None,
                extensions: None,
            }
        );
        bare.push(0xa0);
        assert!(parse_auth_data(&bare).is_err());
    }

    #[test]
    fn auth_data_extensions_must_be_a_map() {
        let mut b = vec![0u8; 37];
        b[32] = FLAG_ED;
        b.push(0x03);
        assert!(matches!(
            parse_auth_data(&b),
            Err(CtapError::InvalidResponseShape(
                "authenticator data extensions are not a map"
            ))
        ));
    }

    #[test]
    fn auth_data_credential_id_length_past_end_errors() {
        let mut b = vec![0u8; 37];
        b[32] = FLAG_AT;
        b.extend([0u8; 16]);
        b.extend([0xff, 0xff]);
        b.extend([0u8; 8]);
        assert!(matches!(
            parse_auth_data(&b),
            Err(CtapError::InvalidResponseShape(
                "authenticator data is truncated"
            ))
        ));
    }
}
