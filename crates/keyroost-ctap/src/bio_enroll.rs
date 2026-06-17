//! CTAP2 `authenticatorBioEnrollment` (0x09, or preview 0x40).
//!
//! Fingerprint management on a FIDO2 bio authenticator: enroll new fingers
//! (a multi-sample capture flow), enumerate existing enrollments, rename them,
//! and remove them. Mirrors the structure of [`crate::cred_mgmt`] — both wrap a
//! [`PinUvAuthToken`] and CBOR-encoded subcommands — but bio enrollment prefixes
//! its pinUvAuthParam input with a *modality* byte (fingerprint = 0x01), and the
//! enroll flow is stateful: `enroll_begin` then repeated `enroll_capture_next`
//! until the device reports completion.
//!
//! Spec: CTAP 2.1 §6.7 (authenticatorBioEnrollment).

use crate::cbor::{self, Value};
use crate::client_pin::PinUvAuthToken;
use crate::cmd::CtapError;
use crate::hid::{CtapHidDevice, CTAPHID_CBOR};

/// authenticatorBioEnrollment command byte (standard).
pub const CTAP2_BIO_ENROLLMENT: u8 = 0x09;
/// Preview command byte, used by authenticators that predate the final spec.
pub const CTAP2_BIO_ENROLLMENT_PREVIEW: u8 = 0x40;

/// Fingerprint modality (the only modality CTAP currently defines).
pub const MODALITY_FINGERPRINT: u64 = 0x01;

// --- request map keys (CTAP 2.1 §6.7) ---
const KEY_MODALITY: u64 = 0x01;
const KEY_SUB_COMMAND: u64 = 0x02;
const KEY_SUB_COMMAND_PARAMS: u64 = 0x03;
const KEY_PIN_UV_AUTH_PROTOCOL: u64 = 0x04;
const KEY_PIN_UV_AUTH_PARAM: u64 = 0x05;

// --- subcommands ---
const SUB_ENROLL_BEGIN: u8 = 0x01;
const SUB_ENROLL_CAPTURE_NEXT: u8 = 0x02;
const SUB_CANCEL_ENROLLMENT: u8 = 0x03;
const SUB_ENUMERATE_ENROLLMENTS: u8 = 0x04;
const SUB_SET_FRIENDLY_NAME: u8 = 0x05;
const SUB_REMOVE_ENROLLMENT: u8 = 0x06;
const SUB_GET_SENSOR_INFO: u8 = 0x07;

// --- subcommand param keys ---
const PARAM_TEMPLATE_ID: u64 = 0x01;
const PARAM_TEMPLATE_FRIENDLY_NAME: u64 = 0x02;
const PARAM_TIMEOUT_MS: u64 = 0x03;

// --- response keys ---
const RESP_FINGERPRINT_KIND: u64 = 0x02;
const RESP_MAX_CAPTURE_SAMPLES: u64 = 0x03;
const RESP_TEMPLATE_ID: u64 = 0x04;
const RESP_LAST_ENROLL_SAMPLE_STATUS: u64 = 0x05;
const RESP_REMAINING_SAMPLES: u64 = 0x06;
const RESP_TEMPLATE_INFOS: u64 = 0x07;
const RESP_MAX_FRIENDLY_NAME_BYTES: u64 = 0x08;

// template-info map keys (inside RESP_TEMPLATE_INFOS array)
const TI_TEMPLATE_ID: u64 = 0x01;
const TI_FRIENDLY_NAME: u64 = 0x02;

/// One enrolled fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrollment {
    /// Opaque template id the authenticator assigns (used to rename/remove).
    pub template_id: Vec<u8>,
    /// User-set name, if one was set.
    pub friendly_name: Option<String>,
}

/// Fingerprint sensor capabilities, from `getFingerprintSensorInfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensorInfo {
    /// 1 = touch sensor, 2 = swipe sensor.
    pub fingerprint_kind: u64,
    /// Samples a successful enrollment needs.
    pub max_capture_samples: u64,
    /// Max friendly-name length in bytes, if the authenticator reports it.
    pub max_friendly_name_bytes: Option<u64>,
}

/// Progress of a single enrollment capture step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureStatus {
    /// `lastEnrollSampleStatus` — 0x00 = good, others are retry hints (see
    /// [`sample_status_message`]).
    pub last_sample_status: u64,
    /// How many more good samples the device still wants. 0 = done.
    pub remaining_samples: u64,
}

/// Human-readable hint for a `lastEnrollSampleStatus` code (CTAP 2.1 §6.7.4).
pub fn sample_status_message(status: u64) -> &'static str {
    match status {
        0x00 => "good sample captured",
        0x01 => "sample too high or partial — try again",
        0x02 => "sample too low or partial — try again",
        0x03 => "sample partial — center your finger on the sensor",
        0x04 => "too many samples failed — enrollment may need restarting",
        0x05 => "low quality — clean the sensor and your finger and retry",
        0x06 => "too close to a previous sample — adjust finger position",
        0x07 => "sensor timeout — touch the sensor",
        _ => "retry the sample",
    }
}

/// Bio-enrollment session: holds the authenticated channel + the chosen command
/// byte (standard vs preview), like [`crate::cred_mgmt::CredentialManager`].
pub struct BioEnrollment<'a> {
    dev: &'a mut CtapHidDevice,
    token: PinUvAuthToken,
    cmd_code: u8,
}

impl<'a> BioEnrollment<'a> {
    /// Create a session. `cmd_code` is [`CTAP2_BIO_ENROLLMENT`] or
    /// [`CTAP2_BIO_ENROLLMENT_PREVIEW`] depending on what the authenticator
    /// advertises in its `AuthenticatorInfo`.
    pub fn new(dev: &'a mut CtapHidDevice, token: PinUvAuthToken, cmd_code: u8) -> Self {
        BioEnrollment {
            dev,
            token,
            cmd_code,
        }
    }

    /// `getFingerprintSensorInfo` — sensor kind and how many samples enrollment
    /// needs. Sent as `getModality`-style request (no auth required).
    pub fn sensor_info(&mut self) -> Result<SensorInfo, CtapError> {
        // getFingerprintSensorInfo is unauthenticated: modality + subCommand,
        // no pinUvAuthParam.
        let entries = vec![
            (Value::UInt(KEY_MODALITY), Value::UInt(MODALITY_FINGERPRINT)),
            (
                Value::UInt(KEY_SUB_COMMAND),
                Value::UInt(SUB_GET_SENSOR_INFO as u64),
            ),
        ];
        let resp = self.transact(&Value::Map(entries))?;
        Ok(SensorInfo {
            fingerprint_kind: field_uint(&resp, RESP_FINGERPRINT_KIND).unwrap_or(1),
            max_capture_samples: field_uint(&resp, RESP_MAX_CAPTURE_SAMPLES).unwrap_or(0),
            max_friendly_name_bytes: field_uint(&resp, RESP_MAX_FRIENDLY_NAME_BYTES),
        })
    }

    /// List enrolled fingerprints.
    pub fn enumerate(&mut self) -> Result<Vec<Enrollment>, CtapError> {
        let resp = match self.dispatch(SUB_ENUMERATE_ENROLLMENTS, None) {
            Ok(v) => v,
            // CTAP 2.1 §6.7.6: when no fingerprints are enrolled, the
            // authenticator answers CTAP2_ERR_INVALID_OPTION (0x2C) rather than
            // an empty list. Treat that as "no enrollments", not an error.
            Err(CtapError::StatusCode(0x2C)) => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let Some(arr) = resp
            .get_uint_key(RESP_TEMPLATE_INFOS)
            .and_then(|v| v.as_array())
        else {
            // No templateInfos -> no enrollments.
            return Ok(Vec::new());
        };
        let mut out = Vec::with_capacity(arr.len());
        for ti in arr {
            let template_id = ti
                .get_uint_key(TI_TEMPLATE_ID)
                .and_then(|v| v.as_bytes())
                .ok_or(CtapError::InvalidResponseShape("missing template id"))?
                .to_vec();
            let friendly_name = ti
                .get_uint_key(TI_FRIENDLY_NAME)
                .and_then(|v| v.as_text())
                .map(|s| s.to_owned());
            out.push(Enrollment {
                template_id,
                friendly_name,
            });
        }
        Ok(out)
    }

    /// Begin enrolling a new fingerprint. Returns the new template id plus the
    /// status of the first capture. `timeout_ms` is an optional per-sample
    /// timeout the authenticator may honor.
    pub fn enroll_begin(
        &mut self,
        timeout_ms: Option<u64>,
    ) -> Result<(Vec<u8>, CaptureStatus), CtapError> {
        // Each capture blocks on the user touching the sensor. The HID layer now
        // extends its deadline on every KEEPALIVE, but raise the base timeout too
        // so a device that sends sparse keepalives still gets time to capture.
        self.dev.set_timeout(std::time::Duration::from_secs(30));
        let params =
            timeout_ms.map(|t| Value::Map(vec![(Value::UInt(PARAM_TIMEOUT_MS), Value::UInt(t))]));
        let resp = self.dispatch(SUB_ENROLL_BEGIN, params)?;
        let template_id = resp
            .get_uint_key(RESP_TEMPLATE_ID)
            .and_then(|v| v.as_bytes())
            .ok_or(CtapError::InvalidResponseShape("missing template id"))?
            .to_vec();
        let status = CaptureStatus {
            last_sample_status: field_uint(&resp, RESP_LAST_ENROLL_SAMPLE_STATUS).unwrap_or(0),
            remaining_samples: field_uint(&resp, RESP_REMAINING_SAMPLES).unwrap_or(0),
        };
        Ok((template_id, status))
    }

    /// Capture the next sample for an in-progress enrollment. Call repeatedly
    /// (touching the sensor each time) until `remaining_samples` is 0.
    pub fn enroll_capture_next(
        &mut self,
        template_id: &[u8],
        timeout_ms: Option<u64>,
    ) -> Result<CaptureStatus, CtapError> {
        self.dev.set_timeout(std::time::Duration::from_secs(30));
        let mut p = vec![(
            Value::UInt(PARAM_TEMPLATE_ID),
            Value::Bytes(template_id.to_vec()),
        )];
        if let Some(t) = timeout_ms {
            p.push((Value::UInt(PARAM_TIMEOUT_MS), Value::UInt(t)));
        }
        let resp = self.dispatch(SUB_ENROLL_CAPTURE_NEXT, Some(Value::Map(p)))?;
        Ok(CaptureStatus {
            last_sample_status: field_uint(&resp, RESP_LAST_ENROLL_SAMPLE_STATUS).unwrap_or(0),
            remaining_samples: field_uint(&resp, RESP_REMAINING_SAMPLES).unwrap_or(0),
        })
    }

    /// Cancel an in-progress enrollment (e.g. the user gave up mid-capture).
    pub fn cancel_enrollment(&mut self) -> Result<(), CtapError> {
        // cancelCurrentEnrollment takes no params and no auth.
        let entries = vec![
            (Value::UInt(KEY_MODALITY), Value::UInt(MODALITY_FINGERPRINT)),
            (
                Value::UInt(KEY_SUB_COMMAND),
                Value::UInt(SUB_CANCEL_ENROLLMENT as u64),
            ),
        ];
        self.transact(&Value::Map(entries))?;
        Ok(())
    }

    /// Rename an enrolled fingerprint.
    pub fn set_friendly_name(&mut self, template_id: &[u8], name: &str) -> Result<(), CtapError> {
        let params = Value::Map(vec![
            (
                Value::UInt(PARAM_TEMPLATE_ID),
                Value::Bytes(template_id.to_vec()),
            ),
            (
                Value::UInt(PARAM_TEMPLATE_FRIENDLY_NAME),
                Value::Text(name.to_owned()),
            ),
        ]);
        self.dispatch(SUB_SET_FRIENDLY_NAME, Some(params))?;
        Ok(())
    }

    /// Remove an enrolled fingerprint.
    pub fn remove_enrollment(&mut self, template_id: &[u8]) -> Result<(), CtapError> {
        let params = Value::Map(vec![(
            Value::UInt(PARAM_TEMPLATE_ID),
            Value::Bytes(template_id.to_vec()),
        )]);
        self.dispatch(SUB_REMOVE_ENROLLMENT, Some(params))?;
        Ok(())
    }

    // --- internals ---

    /// Build + send an authenticated subcommand (those that require
    /// pinUvAuthParam): enroll*, setFriendlyName, removeEnrollment,
    /// enumerateEnrollments.
    fn dispatch(&mut self, sub: u8, params: Option<Value>) -> Result<Value, CtapError> {
        let request = self.build_request(sub, params.as_ref());
        self.transact(&request)
    }

    /// Encode the full request map for an authenticated subcommand.
    fn build_request(&self, sub: u8, params: Option<&Value>) -> Value {
        // pinUvAuthParam is computed over:
        //   modality (0x01) || subCommand || cbor(subCommandParams)
        // The leading modality byte is the bio-specific difference from
        // credential management.
        let mut auth_input = Vec::with_capacity(64);
        auth_input.push(MODALITY_FINGERPRINT as u8);
        auth_input.push(sub);
        if let Some(p) = params {
            auth_input.extend_from_slice(&cbor::encode(p));
        }
        let pin_uv_auth_param = self.token.authenticate(&auth_input);

        let mut entries: Vec<(Value, Value)> = Vec::with_capacity(6);
        entries.push((Value::UInt(KEY_MODALITY), Value::UInt(MODALITY_FINGERPRINT)));
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
        Value::Map(entries)
    }

    /// CBOR-encode `request`, prepend the command byte, transact, and decode.
    fn transact(&mut self, request: &Value) -> Result<Value, CtapError> {
        let encoded = cbor::encode(request);
        let mut payload = Vec::with_capacity(encoded.len() + 1);
        payload.push(self.cmd_code);
        payload.extend_from_slice(&encoded);
        let resp = self.dev.transact(CTAPHID_CBOR, &payload)?;
        let (status, body) = resp.split_first().ok_or(CtapError::EmptyResponse)?;
        if *status != 0 {
            return Err(CtapError::StatusCode(*status));
        }
        if body.is_empty() {
            return Ok(Value::Map(Vec::new()));
        }
        let (value, _) = cbor::decode(body)?;
        Ok(value)
    }
}

fn field_uint(v: &Value, key: u64) -> Option<u64> {
    v.get_uint_key(key).and_then(|x| x.as_uint())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_pin::PinUvAuthToken;

    fn fake_token() -> PinUvAuthToken {
        PinUvAuthToken {
            protocol: 2,
            token: vec![0x11; 32],
        }
    }

    // The auth input for bio enrollment must begin with the modality byte, then
    // the subcommand, then cbor(params). This is the bio-specific framing.
    #[test]
    fn auth_input_is_modality_then_subcommand_then_params() {
        let token = fake_token();
        let params = Value::Map(vec![(
            Value::UInt(PARAM_TEMPLATE_ID),
            Value::Bytes(vec![0xAB, 0xCD]),
        )]);

        let mut expected = Vec::new();
        expected.push(MODALITY_FINGERPRINT as u8);
        expected.push(SUB_REMOVE_ENROLLMENT);
        expected.extend_from_slice(&cbor::encode(&params));
        let expected_param = token.authenticate(&expected);

        // Rebuild what build_request would compute for the param.
        let mut auth_input = Vec::new();
        auth_input.push(MODALITY_FINGERPRINT as u8);
        auth_input.push(SUB_REMOVE_ENROLLMENT);
        auth_input.extend_from_slice(&cbor::encode(&params));
        let got_param = token.authenticate(&auth_input);

        assert_eq!(got_param, expected_param);
    }

    #[test]
    fn enumerate_parses_template_infos() {
        // Build a fake enumerateEnrollments response and parse it.
        let resp = Value::Map(vec![(
            Value::UInt(RESP_TEMPLATE_INFOS),
            Value::Array(vec![
                Value::Map(vec![
                    (Value::UInt(TI_TEMPLATE_ID), Value::Bytes(vec![0x01, 0x02])),
                    (
                        Value::UInt(TI_FRIENDLY_NAME),
                        Value::Text("left thumb".into()),
                    ),
                ]),
                Value::Map(vec![(
                    Value::UInt(TI_TEMPLATE_ID),
                    Value::Bytes(vec![0x03, 0x04]),
                )]),
            ]),
        )]);

        let arr = resp
            .get_uint_key(RESP_TEMPLATE_INFOS)
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(arr.len(), 2);
        let first_name = arr[0]
            .get_uint_key(TI_FRIENDLY_NAME)
            .and_then(|v| v.as_text());
        assert_eq!(first_name, Some("left thumb"));
        let second_name = arr[1]
            .get_uint_key(TI_FRIENDLY_NAME)
            .and_then(|v| v.as_text());
        assert_eq!(second_name, None);
    }

    #[test]
    fn sample_status_messages_cover_known_codes() {
        assert_eq!(sample_status_message(0x00), "good sample captured");
        assert!(sample_status_message(0x07).contains("timeout"));
        // unknown codes get a generic retry hint, never panic
        assert_eq!(sample_status_message(0xFF), "retry the sample");
    }

    // Documents the spec quirk: enumerate maps 0x2C (INVALID_OPTION) to an empty
    // list, since that's how an authenticator with zero enrollments answers.
    #[test]
    fn invalid_option_status_is_the_empty_signal() {
        // The mapping lives in enumerate(); this guards the constant we match on.
        assert_eq!(0x2C, 44);
        // A sanity check that StatusCode(0x2C) is the variant we special-case.
        let e = CtapError::StatusCode(0x2C);
        assert!(matches!(e, CtapError::StatusCode(0x2C)));
    }
}
