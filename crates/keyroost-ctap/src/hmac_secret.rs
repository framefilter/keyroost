//! The CTAP2 `hmac-secret` extension (CTAP 2.1 §12.5), getAssertion side.
//!
//! A credential created with `hmac-secret` lets the platform ask the
//! authenticator for `HMAC-SHA-256(CredRandom, salt)`: a 32-byte secret that is
//! stable per credential and salt and never leaves the key in the clear. The
//! salt travels encrypted under a PIN/UV-protocol shared secret, and the output
//! comes back encrypted under the same secret.
//!
//! This module builds those pieces and nothing more:
//!
//! - [`begin`] runs one `clientPin` getKeyAgreement and keeps the negotiated
//!   shared secret in a [`HmacSecretSession`].
//! - [`HmacSecretSession::extension_input`] builds the `hmac-secret` value for
//!   the getAssertion `extensions` map: `{1: keyAgreement, 2: saltEnc,
//!   3: saltAuth, 4: pinUvAuthProtocol}`, where key 4 is sent only for
//!   protocol 2 (CTAP 2.1 makes it mandatory for any protocol other than 1).
//! - [`HmacSecretSession::decrypt_output`] decrypts the authenticator's
//!   `hmac-secret` output back to its 32 bytes.
//! - [`prf_salt`] maps an application input to a salt the way WebAuthn PRF
//!   does, so a salt matches what a browser would send for the same input.
//!
//! Only one salt (`salt1`) is supported; a 64-byte `salt1 || salt2` request is
//! not built here.

use crate::cbor::Value;
use crate::client_pin::{key_agreement, select_pin_protocol};
use crate::cmd::{AuthenticatorInfo, CtapError};
use crate::pin::{PinProtocol, PIN_PROTOCOL_V2};
use crate::transport::CtapTransport;
use zeroize::Zeroizing;

/// `hmac-secret` getAssertion input map keys (CTAP 2.1 §12.5).
const KEY_KEY_AGREEMENT: u64 = 0x01;
const KEY_SALT_ENC: u64 = 0x02;
const KEY_SALT_AUTH: u64 = 0x03;
const KEY_PIN_UV_AUTH_PROTOCOL: u64 = 0x04;

/// One negotiated `hmac-secret` exchange: the PIN/UV-protocol shared secret
/// and the platform public key the authenticator needs to derive it too.
///
/// Not `Clone`, so the shared secret has a single owner. The secret lives in
/// the PIN protocol's own key types, which wipe themselves on drop.
pub struct HmacSecretSession {
    proto: Box<dyn PinProtocol>,
    our_cose: Value,
    protocol: u32,
}

/// Start an `hmac-secret` exchange: pick the PIN/UV protocol the key prefers
/// from `info`, then run one `clientPin` getKeyAgreement and derive the
/// shared secret.
pub fn begin(
    dev: &mut impl CtapTransport,
    info: &AuthenticatorInfo,
) -> Result<HmacSecretSession, CtapError> {
    let chosen = select_pin_protocol(&info.pin_uv_auth_protocols);
    let (proto, peer) = key_agreement(dev, chosen)?;
    Ok(HmacSecretSession {
        protocol: proto.version(),
        our_cose: peer.our_public_cose(),
        proto,
    })
}

impl HmacSecretSession {
    /// The PIN/UV auth protocol (1 or 2) this session negotiated.
    pub fn protocol(&self) -> u32 {
        self.protocol
    }

    /// The `hmac-secret` value for the getAssertion `extensions` map, asking
    /// for one 32-byte salt.
    pub fn extension_input(&self, salt1: &[u8; 32]) -> Value {
        // v1: 32 bytes under a zero IV, 16-byte tag. v2: random IV || 32
        // bytes, 32-byte tag. The protocol object carries both differences.
        let salt_enc = self.proto.encrypt(salt1);
        let salt_auth = self.proto.authenticate(&salt_enc);
        // Keys ascending, as CTAP canonical CBOR requires.
        let mut entries = vec![
            (Value::UInt(KEY_KEY_AGREEMENT), self.our_cose.clone()),
            (Value::UInt(KEY_SALT_ENC), Value::Bytes(salt_enc)),
            (Value::UInt(KEY_SALT_AUTH), Value::Bytes(salt_auth)),
        ];
        if self.protocol == PIN_PROTOCOL_V2 {
            entries.push((
                Value::UInt(KEY_PIN_UV_AUTH_PROTOCOL),
                Value::UInt(u64::from(self.protocol)),
            ));
        }
        Value::Map(entries)
    }

    /// Decrypt the authenticator's `hmac-secret` output (the bytes under the
    /// `hmac-secret` key of the authenticator-data extensions). Anything that
    /// does not decrypt to exactly 32 bytes is an error.
    pub fn decrypt_output(&self, enc: &[u8]) -> Result<Zeroizing<[u8; 32]>, CtapError> {
        const WRONG_SHAPE: CtapError =
            CtapError::InvalidResponseShape("hmac-secret output is not 32 bytes");
        // Every decrypt failure is a length problem (empty, short of the v2
        // IV, or not whole AES blocks), so it is the same error.
        let plain = Zeroizing::new(self.proto.decrypt(enc).map_err(|_| WRONG_SHAPE)?);
        let mut out = Zeroizing::new([0u8; 32]);
        if plain.len() != out.len() {
            return Err(WRONG_SHAPE);
        }
        out.copy_from_slice(&plain);
        Ok(out)
    }

    /// A session over a fixed PIN protocol, so tests do not need ECDH.
    #[cfg(test)]
    pub(crate) fn for_test(proto: Box<dyn PinProtocol>, our_cose: Value) -> Self {
        let protocol = proto.version();
        HmacSecretSession {
            proto,
            our_cose,
            protocol,
        }
    }
}

/// The salt WebAuthn PRF derives from an application input:
/// `SHA-256("WebAuthn PRF" || 0x00 || input)`.
pub fn prf_salt(input: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"WebAuthn PRF");
    hash.update([0x00]);
    hash.update(input);
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor;
    use crate::pin::{
        EphemeralKey, ProtocolV1, ProtocolV2, SharedSecretV1, SharedSecretV2, PIN_PROTOCOL_V1,
    };

    fn v1() -> ProtocolV1 {
        ProtocolV1 {
            secret: SharedSecretV1([0x42; 32]),
        }
    }

    fn v2() -> ProtocolV2 {
        ProtocolV2 {
            secret: SharedSecretV2 {
                hmac_key: [0x17; 32],
                aes_key: [0x29; 32],
            },
        }
    }

    fn dummy_cose() -> Value {
        Value::Map(vec![(Value::UInt(1), Value::UInt(2))])
    }

    fn keys(map: &Value) -> Vec<u64> {
        map.as_map()
            .unwrap()
            .iter()
            .map(|(k, _)| k.as_uint().unwrap())
            .collect()
    }

    fn bytes_at(map: &Value, key: u64) -> Vec<u8> {
        map.get_uint_key(key).unwrap().as_bytes().unwrap().to_vec()
    }

    #[test]
    fn extension_input_shape_v1() {
        let session = HmacSecretSession::for_test(Box::new(v1()), dummy_cose());
        assert_eq!(session.protocol(), PIN_PROTOCOL_V1);
        let salt1 = [0x5a; 32];
        let input = session.extension_input(&salt1);

        assert_eq!(keys(&input), vec![1, 2, 3]);
        assert_eq!(input.get_uint_key(1), Some(&dummy_cose()));
        let salt_enc = bytes_at(&input, 2);
        assert_eq!(salt_enc.len(), 32);
        // v1 uses a zero IV, so the ciphertext is deterministic.
        assert_eq!(salt_enc, v1().encrypt(&salt1));
        let salt_auth = bytes_at(&input, 3);
        assert_eq!(salt_auth.len(), 16);
        assert_eq!(salt_auth, v1().authenticate(&salt_enc));
    }

    #[test]
    fn extension_input_shape_v2() {
        let session = HmacSecretSession::for_test(Box::new(v2()), dummy_cose());
        assert_eq!(session.protocol(), PIN_PROTOCOL_V2);
        let salt1 = [0x5a; 32];
        let input = session.extension_input(&salt1);

        assert_eq!(keys(&input), vec![1, 2, 3, 4]);
        assert_eq!(input.get_uint_key(1), Some(&dummy_cose()));
        let salt_enc = bytes_at(&input, 2);
        assert_eq!(salt_enc.len(), 48, "16-byte IV + 32-byte salt");
        assert_eq!(v2().decrypt(&salt_enc).unwrap(), salt1);
        let salt_auth = bytes_at(&input, 3);
        assert_eq!(salt_auth.len(), 32);
        assert_eq!(salt_auth, v2().authenticate(&salt_enc));
        assert_eq!(input.get_uint_key(4).unwrap().as_uint(), Some(2));
    }

    #[test]
    fn decrypt_output_roundtrip() {
        let output = [0x33u8; 32];
        let protos: [(Box<dyn PinProtocol>, Box<dyn PinProtocol>); 2] = [
            (Box::new(v1()), Box::new(v1())),
            (Box::new(v2()), Box::new(v2())),
        ];
        for (device, platform) in protos {
            let session = HmacSecretSession::for_test(platform, dummy_cose());
            let enc = device.encrypt(&output);
            assert_eq!(*session.decrypt_output(&enc).unwrap(), output);

            // Two outputs (salt1 and salt2) decrypt to 64 bytes: refused.
            let enc64 = device.encrypt(&[0x33; 64]);
            let shape_error = |r: Result<Zeroizing<[u8; 32]>, CtapError>| {
                matches!(
                    r,
                    Err(CtapError::InvalidResponseShape(
                        "hmac-secret output is not 32 bytes"
                    ))
                )
            };
            assert!(shape_error(session.decrypt_output(&enc64)));
            // Ciphertext that cannot decrypt at all is the same error.
            assert!(shape_error(session.decrypt_output(&enc[..31])));
            assert!(shape_error(session.decrypt_output(&[])));
            assert!(shape_error(session.decrypt_output(&enc[..16])));
        }
    }

    /// Answers getKeyAgreement with a fixed authenticator key and records the
    /// request it was sent.
    struct KeyAgreementDevice {
        public: ([u8; 32], [u8; 32]),
        requests: Vec<(u8, Vec<u8>)>,
    }

    impl CtapTransport for KeyAgreementDevice {
        fn transact(&mut self, cmd: u8, payload: &[u8]) -> Result<Vec<u8>, CtapError> {
            self.requests.push((cmd, payload.to_vec()));
            let (x, y) = self.public;
            let cose = Value::Map(vec![
                (Value::UInt(1), Value::UInt(2)),
                (Value::UInt(3), Value::NInt(24)),
                (Value::NInt(0), Value::UInt(1)),
                (Value::NInt(1), Value::Bytes(x.to_vec())),
                (Value::NInt(2), Value::Bytes(y.to_vec())),
            ]);
            let mut resp = vec![0x00];
            resp.extend(cbor::encode(&Value::Map(vec![(Value::UInt(1), cose)])));
            Ok(resp)
        }
    }

    fn cose_xy(cose: &Value) -> ([u8; 32], [u8; 32]) {
        let coord = |n: u64| -> [u8; 32] {
            cose.as_map()
                .unwrap()
                .iter()
                .find(|(k, _)| *k == Value::NInt(n))
                .unwrap()
                .1
                .as_bytes()
                .unwrap()
                .try_into()
                .unwrap()
        };
        (coord(1), coord(2))
    }

    /// Both protocols end to end against a simulated authenticator: it derives
    /// the same secret from our keyAgreement, recovers the salt, checks
    /// saltAuth, and its encrypted output decrypts on our side.
    #[test]
    fn begin_negotiates_a_secret_the_authenticator_shares() {
        for (advertised, expected) in [(vec![2u64, 1], PIN_PROTOCOL_V2), (vec![1], 1)] {
            let authenticator = EphemeralKey::generate();
            let mut dev = KeyAgreementDevice {
                public: authenticator.public_xy(),
                requests: Vec::new(),
            };
            let info = AuthenticatorInfo {
                pin_uv_auth_protocols: advertised,
                ..Default::default()
            };
            let session = begin(&mut dev, &info).unwrap();
            assert_eq!(session.protocol(), expected);

            // Exactly one getKeyAgreement, declaring the chosen protocol.
            assert_eq!(dev.requests.len(), 1);
            let (_, payload) = &dev.requests[0];
            assert_eq!(payload[0], crate::client_pin::CTAP2_CLIENT_PIN);
            let (req, _) = cbor::decode(&payload[1..]).unwrap();
            assert_eq!(
                req.get_uint_key(1).unwrap().as_uint(),
                Some(expected as u64)
            );
            assert_eq!(req.get_uint_key(2).unwrap().as_uint(), Some(2));

            let salt1 = [0xa5; 32];
            let input = session.extension_input(&salt1);
            let (x, y) = cose_xy(input.get_uint_key(1).unwrap());
            let device: Box<dyn PinProtocol> = if expected == PIN_PROTOCOL_V2 {
                Box::new(ProtocolV2 {
                    secret: authenticator.shared_secret_v2(&x, &y).unwrap(),
                })
            } else {
                Box::new(ProtocolV1 {
                    secret: authenticator.shared_secret_v1(&x, &y).unwrap(),
                })
            };
            let salt_enc = bytes_at(&input, 2);
            assert_eq!(device.decrypt(&salt_enc).unwrap(), salt1);
            assert_eq!(bytes_at(&input, 3), device.authenticate(&salt_enc));

            let output = [0x5c; 32];
            let enc = device.encrypt(&output);
            assert_eq!(*session.decrypt_output(&enc).unwrap(), output);
        }
    }

    #[test]
    fn begin_rejects_an_invalid_authenticator_point() {
        let mut dev = KeyAgreementDevice {
            public: ([0u8; 32], [0u8; 32]),
            requests: Vec::new(),
        };
        let info = AuthenticatorInfo::default();
        assert!(matches!(
            begin(&mut dev, &info),
            Err(CtapError::InvalidResponseShape(_))
        ));
    }
}
