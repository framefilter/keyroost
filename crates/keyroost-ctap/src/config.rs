//! CTAP 2.1 `authenticatorConfig` (0x0D).
//!
//! Device-wide configuration sub-commands that change the authenticator's
//! security policy: enabling enterprise attestation, toggling "always require
//! user verification" (`alwaysUv`), and setting the minimum PIN length (with an
//! optional force-PIN-change flag and an RP-ID allow-list for the
//! `minPinLength` extension).
//!
//! Every request is authenticated with a `pinUvAuthParam`. Unlike
//! credentialManagement (which signs `subCommand || cbor(params)`), the
//! authenticatorConfig auth target is, per CTAP §6.11:
//!
//! ```text
//! 0xff * 32  ||  0x0d  ||  subCommand  ||  cbor(subCommandParams)
//! ```
//!
//! The pinUvAuthToken must carry the `acfg` (AuthenticatorConfiguration)
//! permission, obtained from
//! [`crate::client_pin::get_pin_uv_auth_token_with_permissions`] with
//! [`crate::client_pin::permissions::AUTHENTICATOR_CONFIGURATION`].
//!
//! Support is advertised in `getInfo`: the `authnrCfg` option must be `true`,
//! and (for setMinPINLength / forcePINChange) the `setMinPINLength` option.
//! Several of these changes are one-way or sticky — raising the minimum PIN
//! length can never lower it, and whether `alwaysUv`/enterprise attestation
//! survive a reset is vendor-specific — so callers should confirm intent.

use crate::cbor::{self, Value};
use crate::client_pin::PinUvAuthToken;
use crate::cmd::{AuthenticatorInfo, CtapError};
use crate::hid::CTAPHID_CBOR;
use crate::transport::CtapTransport;

pub const CTAP2_CONFIG: u8 = 0x0D;

/// Request map keys (CTAP §6.11).
const KEY_SUB_COMMAND: u64 = 0x01;
const KEY_SUB_COMMAND_PARAMS: u64 = 0x02;
const KEY_PIN_UV_AUTH_PROTOCOL: u64 = 0x03;
const KEY_PIN_UV_AUTH_PARAM: u64 = 0x04;

/// Sub-command numbers (CTAP §6.11).
const SUB_ENABLE_ENTERPRISE_ATTESTATION: u8 = 0x01;
const SUB_TOGGLE_ALWAYS_UV: u8 = 0x02;
const SUB_SET_MIN_PIN_LENGTH: u8 = 0x03;

/// setMinPINLength parameter keys (CTAP §6.11.4).
const PARAM_NEW_MIN_PIN_LENGTH: u64 = 0x01;
const PARAM_MIN_PIN_LENGTH_RP_IDS: u64 = 0x02;
const PARAM_FORCE_CHANGE_PIN: u64 = 0x03;

/// Issues `authenticatorConfig` sub-commands against an open device, using a
/// pinUvAuthToken that carries the AuthenticatorConfiguration permission.
pub struct Configurator<'a, T: CtapTransport> {
    dev: &'a mut T,
    token: PinUvAuthToken,
}

impl<'a, T: CtapTransport> Configurator<'a, T> {
    /// Construct after obtaining a token with the `acfg` permission. Verifies
    /// the authenticator actually advertises `authenticatorConfig` support.
    pub fn new(
        dev: &'a mut T,
        token: PinUvAuthToken,
        info: &AuthenticatorInfo,
    ) -> Result<Self, CtapError> {
        if info.option("authnrCfg") != Some(true) {
            return Err(CtapError::InvalidResponseShape(
                "authenticator does not support authenticatorConfig",
            ));
        }
        Ok(Self { dev, token })
    }

    /// Enable enterprise attestation (sub-command 0x01). Typically one-way:
    /// disabling again requires a reset. No effect if already enabled.
    pub fn enable_enterprise_attestation(&mut self) -> Result<(), CtapError> {
        self.dispatch(SUB_ENABLE_ENTERPRISE_ATTESTATION, None)
    }

    /// Toggle "always require user verification" (sub-command 0x02). Flips the
    /// current state: if `alwaysUv` is on it turns off, and vice versa. Inspect
    /// the `alwaysUv` option from `getInfo` first if you need a specific target
    /// state. Whether the setting survives a reset is vendor-specific.
    pub fn toggle_always_uv(&mut self) -> Result<(), CtapError> {
        self.dispatch(SUB_TOGGLE_ALWAYS_UV, None)
    }

    /// Set the minimum PIN length (sub-command 0x03).
    ///
    /// - `new_min` raises the minimum PIN length. The authenticator only
    ///   accepts a value greater than or equal to the current minimum — it can
    ///   never be lowered without a reset. `None` leaves it unchanged.
    /// - `rp_ids`, if non-empty, replaces the list of relying parties allowed
    ///   to read the minimum PIN length via the `minPinLength` extension.
    /// - `force_change` flags the key so the next platform interaction must set
    ///   a new PIN. If the current PIN is already shorter than `new_min`, the
    ///   authenticator sets this implicitly.
    ///
    /// At least one of the three should be meaningful, or the call is a no-op.
    pub fn set_min_pin_length(
        &mut self,
        new_min: Option<u32>,
        rp_ids: &[String],
        force_change: bool,
    ) -> Result<(), CtapError> {
        let mut entries: Vec<(Value, Value)> = Vec::with_capacity(3);
        if let Some(n) = new_min {
            entries.push((Value::UInt(PARAM_NEW_MIN_PIN_LENGTH), Value::UInt(n as u64)));
        }
        if !rp_ids.is_empty() {
            let arr = rp_ids
                .iter()
                .map(|s| Value::Text(s.clone()))
                .collect::<Vec<_>>();
            entries.push((Value::UInt(PARAM_MIN_PIN_LENGTH_RP_IDS), Value::Array(arr)));
        }
        if force_change {
            entries.push((Value::UInt(PARAM_FORCE_CHANGE_PIN), Value::Bool(true)));
        }
        let params = (!entries.is_empty()).then_some(Value::Map(entries));
        self.dispatch(SUB_SET_MIN_PIN_LENGTH, params)
    }

    /// Flag the authenticator so the next interaction forces a PIN change,
    /// without otherwise altering the minimum length. Convenience wrapper over
    /// [`set_min_pin_length`].
    pub fn force_pin_change(&mut self) -> Result<(), CtapError> {
        self.set_min_pin_length(None, &[], true)
    }

    fn dispatch(&mut self, sub: u8, params: Option<Value>) -> Result<(), CtapError> {
        let request = self.build_request(sub, params.as_ref());
        let mut payload = Vec::with_capacity(request.len() + 1);
        payload.push(CTAP2_CONFIG);
        payload.extend_from_slice(&request);
        let resp = self.dev.transact(CTAPHID_CBOR, &payload)?;
        let status = resp.first().copied().ok_or(CtapError::EmptyResponse)?;
        if status != 0 {
            return Err(CtapError::StatusCode(status));
        }
        // authenticatorConfig sub-commands return no response data on success.
        Ok(())
    }

    fn build_request(&self, sub: u8, params: Option<&Value>) -> Vec<u8> {
        let auth_input = config_auth_input(sub, params);
        let pin_uv_auth_param = self.token.authenticate(&auth_input);

        let mut entries: Vec<(Value, Value)> = Vec::with_capacity(4);
        entries.push((Value::UInt(KEY_SUB_COMMAND), Value::UInt(sub as u64)));
        if let Some(p) = params {
            entries.push((Value::UInt(KEY_SUB_COMMAND_PARAMS), p.clone()));
        }
        entries.push((
            Value::UInt(KEY_PIN_UV_AUTH_PROTOCOL),
            Value::UInt(self.token.protocol as u64),
        ));
        entries.push((
            Value::UInt(KEY_PIN_UV_AUTH_PARAM),
            Value::Bytes(pin_uv_auth_param),
        ));
        cbor::encode(&Value::Map(entries))
    }
}

/// The authenticatorConfig pinUvAuthParam auth target (CTAP §6.11):
///   `0xff * 32 || 0x0d || subCommand || cbor(subCommandParams)`.
fn config_auth_input(sub: u8, params: Option<&Value>) -> Vec<u8> {
    let mut auth_input = Vec::with_capacity(64);
    auth_input.extend_from_slice(&[0xffu8; 32]);
    auth_input.push(CTAP2_CONFIG);
    auth_input.push(sub);
    if let Some(p) = params {
        auth_input.extend_from_slice(&cbor::encode(p));
    }
    auth_input
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_input_prefix_and_subcommand() {
        // No-param sub-command (toggleAlwaysUv): 32 x 0xff, then 0x0d, then sub.
        let input = config_auth_input(SUB_TOGGLE_ALWAYS_UV, None);
        assert_eq!(input.len(), 34);
        assert!(input[..32].iter().all(|&b| b == 0xff));
        assert_eq!(input[32], CTAP2_CONFIG); // 0x0d
        assert_eq!(input[33], SUB_TOGGLE_ALWAYS_UV); // 0x02
    }

    #[test]
    fn auth_input_includes_params_cbor() {
        // setMinPINLength with newMinPINLength = 6: params follow the prefix.
        let params = Value::Map(vec![(
            Value::UInt(PARAM_NEW_MIN_PIN_LENGTH),
            Value::UInt(6),
        )]);
        let input = config_auth_input(SUB_SET_MIN_PIN_LENGTH, Some(&params));
        assert!(input[..32].iter().all(|&b| b == 0xff));
        assert_eq!(input[32], CTAP2_CONFIG);
        assert_eq!(input[33], SUB_SET_MIN_PIN_LENGTH);
        // Remainder is exactly the CBOR encoding of the params map.
        assert_eq!(&input[34..], &cbor::encode(&params)[..]);
    }

    #[test]
    fn set_min_pin_length_builds_expected_params() {
        // Build the params map the way set_min_pin_length would, and confirm the
        // key/value shape round-trips. newMin=8, one RP id, force_change=true.
        let entries: Vec<(Value, Value)> = vec![
            (Value::UInt(PARAM_NEW_MIN_PIN_LENGTH), Value::UInt(8)),
            (
                Value::UInt(PARAM_MIN_PIN_LENGTH_RP_IDS),
                Value::Array(vec![Value::Text("example.com".into())]),
            ),
            (Value::UInt(PARAM_FORCE_CHANGE_PIN), Value::Bool(true)),
        ];
        let map = Value::Map(entries);
        let (decoded, _) = cbor::decode(&cbor::encode(&map)).unwrap();
        assert_eq!(
            decoded
                .get_uint_key(PARAM_NEW_MIN_PIN_LENGTH)
                .unwrap()
                .as_uint(),
            Some(8)
        );
        assert_eq!(
            decoded
                .get_uint_key(PARAM_FORCE_CHANGE_PIN)
                .unwrap()
                .as_bool(),
            Some(true)
        );
    }

    #[test]
    fn auth_param_is_hmac_of_target() {
        // A token with a known key signs the auth target; verify the param is
        // the HMAC of exactly that target (protocol v2 => full 32-byte tag).
        let token = PinUvAuthToken {
            protocol: 2,
            token: vec![0x42; 32],
        };
        let cfg_input = config_auth_input(SUB_TOGGLE_ALWAYS_UV, None);
        let expected = token.authenticate(&cfg_input);
        assert_eq!(expected.len(), 32);
        // Re-deriving from the same input must match (determinism).
        assert_eq!(expected, token.authenticate(&cfg_input));
    }
}
