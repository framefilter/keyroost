//! Serializable shapes for the global `--json` output mode. Each struct mirrors
//! 1:1 the data the corresponding command's human handler already prints — no
//! new data, only structure.

use serde::Serialize;

/// A top-level `{"keys": [...]}` envelope: the bare-invocation overview
/// (`keyroostctl --json`) and `keyroostctl list --json`.
#[derive(Serialize)]
pub(crate) struct KeysJson<T: Serialize> {
    pub keys: Vec<T>,
}

/// A top-level `{"accounts": [...]}` envelope: `oath list` and `otp list`.
#[derive(Serialize)]
pub(crate) struct AccountsJson<T: Serialize> {
    pub accounts: Vec<T>,
}

/// One device in the bare-invocation overview (`keyroostctl --json`).
#[derive(Serialize)]
pub(crate) struct DeviceJson {
    pub vendor: String,
    pub model: String,
    pub name: Option<String>,
    pub serial: String,
    pub transport: String,
    /// "key" or "token".
    pub kind: &'static str,
    pub capabilities: Vec<&'static str>,
    /// The subset of `capabilities` keyroost could not verify against the
    /// device (no card channel was available to ask): still offered, but not
    /// proven present. Tri-state per capability: in `capabilities` only =
    /// verified present; in both lists = offered but unverified; in
    /// neither = absent.
    pub capabilities_unverified: Vec<&'static str>,
}

/// One `keyroostctl list --json` row. `device` is the exact value to pass
/// to `--device` (name if unique, else serial, else list number).
#[derive(Serialize)]
pub(crate) struct ListRowJson {
    pub number: usize,
    pub device: String,
    pub name: Option<String>,
    pub vendor: String,
    pub model: String,
    pub serial: String,
    pub kind: &'static str,
    pub capabilities: Vec<&'static str>,
    pub capabilities_unverified: Vec<&'static str>,
    pub readers: Vec<String>,
    pub hid_paths: Vec<String>,
}

/// `keyroostctl molto --json info`.
#[derive(Serialize)]
pub(crate) struct MoltoInfoJson {
    pub serial: String,
    pub utc_time: u32,
    pub drift_seconds: i64,
}

/// `keyroostctl molto --json slots`.
#[derive(Serialize)]
pub(crate) struct MoltoSlotsJson {
    pub serial: String,
    pub slots: Vec<MoltoSlotJson>,
}

/// One element of [`MoltoSlotsJson::slots`] (full parsed block).
/// `time_a`/`time_b` are raw big-endian u32s with unconfirmed semantics.
///
/// `algorithm` and `digits` are `null` for a code keyroost doesn't know;
/// `period` is the stored seconds byte, `null` when 0. An empty slot may
/// still report default values, so use `occupied`.
#[derive(Serialize)]
pub(crate) struct MoltoSlotJson {
    pub slot: u8,
    pub occupied: bool,
    pub title: Option<String>,
    pub flag: u8,
    /// `"sha1"` or `"sha256"`.
    pub algorithm: Option<&'static str>,
    /// TOTP time step in seconds.
    pub period: Option<u8>,
    /// 4, 6, 8 or 10.
    pub digits: Option<u8>,
    pub time_a: u32,
    pub time_b: u32,
}

impl MoltoSlotJson {
    pub(crate) fn from_block(slot: u8, b: &keyroost_proto::commands::ProfilePublicData) -> Self {
        Self {
            slot,
            occupied: b.seed_present,
            title: b.title.clone(),
            flag: b.flag,
            algorithm: match b.algorithm {
                1 => Some("sha1"),
                2 => Some("sha256"),
                _ => None,
            },
            period: (b.time_step != 0).then_some(b.time_step),
            digits: matches!(b.digits, 4 | 6 | 8 | 10).then_some(b.digits),
            time_a: b.time_a,
            time_b: b.time_b,
        }
    }
}

/// `keyroostctl fido --json info` — the CTAP2 authenticatorGetInfo fields the
/// human handler prints (plus the CTAPHID transport facts).
#[derive(Serialize)]
pub(crate) struct FidoInfoJson {
    pub device: String,
    pub channel_id: u32,
    pub ctaphid_protocol_version: u8,
    pub firmware: String,
    pub hid_caps: Vec<&'static str>,
    pub hid_caps_raw: u8,
    /// `null` when the device does not speak CTAP2 (U2F-only).
    pub ctap2: Option<Ctap2InfoJson>,
}

/// The authenticatorGetInfo payload (CTAP2 devices only).
#[derive(Serialize)]
pub(crate) struct Ctap2InfoJson {
    pub versions: Vec<String>,
    pub extensions: Vec<String>,
    pub aaguid: String,
    pub options: Vec<OptionJson>,
    pub max_msg_size: Option<u64>,
    pub pin_uv_auth_protocols: Vec<u64>,
    pub transports: Vec<String>,
    pub min_pin_length: Option<u64>,
    pub force_pin_change: Option<bool>,
    pub firmware_version: Option<u64>,
}

/// One authenticator option (e.g. `{ "name": "rk", "value": true }`).
#[derive(Serialize)]
pub(crate) struct OptionJson {
    pub name: String,
    pub value: bool,
}

/// `keyroostctl fido --json pin retries`.
#[derive(Serialize)]
pub(crate) struct FidoPinRetriesJson {
    pub pin_retries: u32,
}

/// `keyroostctl piv --json info`.
#[derive(Serialize)]
pub(crate) struct PivStatusJson {
    /// Yubico GET VERSION's raw reply, dotted (or hex past 4 bytes),
    /// tolerant of any non-empty byte count.
    pub version: Option<String>,
    /// Ordinarily the Yubico GET SERIAL extension; when a specific
    /// fingerprint's own probe supplies a serial instead (currently: a
    /// Nitrokey's admin application), that one is used and GET SERIAL is
    /// skipped — a Nitrokey answers that extension too, but with a number
    /// that isn't its real serial. `None` when neither source answers.
    ///
    /// A string, not a number: a serial can be up to 128 bits (a
    /// Nitrokey's admin serial), and a bare JSON number past 2^53 loses
    /// precision in most consumers. Decimal within `u64`, `0x`-hex
    /// beyond — the same rendering `piv info`'s text output uses.
    pub serial: Option<String>,
    pub pin_retries: Option<u8>,
    pub chuid: Option<PivChuidJson>,
    pub slots: Vec<PivSlotJson>,
    /// Best-effort applet fingerprint — from ATR/SELECT text as well as
    /// AID-selectability/instruction-support probes; see
    /// `keyroost_piv::fingerprint` for the full scheme. Its `Display`
    /// form — e.g. `"YubiKey"` or `"OpenFips201::SwissbitIShield2"`.
    pub applet_fingerprint: String,
    /// The token's own reported name, when one was actually discovered
    /// (currently: a Nitrokey's admin application, for `Trussed::NitroKey`).
    /// Empty when none was — not backfilled with a generic name for
    /// `applet_fingerprint`, so an empty string here means specifically
    /// "the token didn't tell us its name," not "fingerprinting failed."
    /// (The plain-text `piv info` output does apply that fallback —
    /// see `run_piv`.)
    pub applet_name: String,
    /// The applet's own firmware version, dotted (same formatting as
    /// `version`), when a specific fingerprint's probe discovered one —
    /// currently `Trussed::NitroKey` (Trussed's admin application) only.
    /// Not necessarily equal to `version`, which is the PIV applet's own
    /// version. `None` when no such probe applies or it found nothing
    /// parseable.
    pub version_firmware: Option<String>,
}

/// The card's CHUID — FASC-N, GUID, expiration, signature, and LRC. The
/// CLI is the one place that prints signature/LRC (empty hex in every
/// CHUID this crate itself writes); the GUI status line omits both, and
/// FASC-N besides.
#[derive(Serialize)]
pub(crate) struct PivChuidJson {
    pub fasc_n: String,
    pub guid: String,
    pub expiration: String,
    pub signature: String,
    pub lrc: String,
}

/// One PIV key slot in the status output.
#[derive(Serialize)]
pub(crate) struct PivSlotJson {
    /// The value `--slot` takes for this slot ([`piv_slot_token`]).
    pub slot: String,
    /// Human name, e.g. `"authentication (9A)"`.
    pub slot_name: String,
    pub cert_present: bool,
    pub cert_len: usize,
    /// `damaged` or `too_large` when the slot holds a certificate that
    /// cannot be read (then `cert_present` is true and `cert_len` is 0);
    /// `null` otherwise.
    pub cert_unreadable: Option<&'static str>,
    /// `true` when the certificate is stored gzip-compressed; `cert_len` is
    /// still the DER length.
    pub cert_compressed: bool,
}

/// The value `--slot` takes for this slot: "9a", "9c", "9d", "9e", "82".."95".
pub(crate) fn piv_slot_token(s: keyroost_piv::Slot) -> String {
    format!("{:02x}", s.key_ref())
}

/// `keyroostctl piv --json test`.
#[derive(Serialize)]
pub(crate) struct PivTestJson {
    /// The value `--slot` takes for this slot ([`piv_slot_token`]).
    pub slot: String,
    /// Human name, e.g. `"authentication (9A)"`.
    pub slot_name: String,
    pub algorithm: String,
    /// `true` when no operation failed (skipped ops don't count).
    pub ok: bool,
    pub operations: Vec<PivTestOpJson>,
}

/// One operation in [`PivTestJson::operations`].
#[derive(Serialize)]
pub(crate) struct PivTestOpJson {
    pub operation: String,
    /// `"passed"`, `"failed"`, or `"skipped"`.
    pub result: String,
    /// A short reason for `"failed"`; `null` otherwise.
    pub detail: Option<String>,
}

/// `keyroostctl openpgp --json info`.
#[derive(Serialize)]
pub(crate) struct OpenpgpStatusJson {
    pub aid: String,
    /// Decimal, as a string so a leading-zero or large serial survives any
    /// JSON consumer exactly.
    pub serial: Option<String>,
    pub sig_algo: String,
    pub dec_algo: String,
    pub aut_algo: String,
    pub fingerprint_sig: Option<String>,
    pub fingerprint_dec: Option<String>,
    pub fingerprint_aut: Option<String>,
    pub user_pin_retries: u8,
    pub reset_code_retries: u8,
    pub admin_pin_retries: u8,
    pub signature_count: Option<u32>,
}

/// `keyroostctl otp --json serial`.
#[derive(Serialize)]
pub(crate) struct OtpSerialJson {
    pub serial: String,
}

/// `keyroostctl oath --json list` — one stored OATH credential. Mirrors the
/// human line `<name>  [<type>/<algorithm>]`.
#[derive(Serialize)]
pub(crate) struct OathCredentialJson {
    pub name: String,
    /// "TOTP" or "HOTP".
    #[serde(rename = "type")]
    pub oath_type: &'static str,
    /// "sha1" / "sha256" / "sha512" (lowercase, like `molto slots`).
    pub algorithm: &'static str,
}

/// `keyroostctl oath --json code` — the calculated code. The human handler
/// prints only the code; we also carry the credential name that was queried.
#[derive(Serialize)]
pub(crate) struct OathCodeJson {
    pub name: String,
    pub code: String,
}

/// `keyroostctl otp --json list` — one Token2 OTP entry. Mirrors the human
/// line `<app:account>  [<type>/<algo>]  <code|—>  (touch)?`.
#[derive(Serialize)]
pub(crate) struct OtpEntryJson {
    pub app: String,
    pub account: String,
    /// "TOTP" or "HOTP".
    #[serde(rename = "type")]
    pub otp_type: &'static str,
    /// "sha1" / "sha256" (lowercase, like `molto slots`).
    pub algorithm: &'static str,
    /// `None` (JSON `null`) when the code is withheld pending a touch (the
    /// human shows an em-dash); present otherwise.
    pub code: Option<String>,
    pub touch_required: bool,
}

/// `keyroostctl otp --json pin-status` — the R3.4 OTP-PIN state.
///
/// `supported: false` means the key never answered the flag read, so the
/// three PIN fields are `null`: the feature is not there to report on.
#[derive(Serialize)]
pub(crate) struct OtpPinStatusJson {
    pub supported: bool,
    pub pin_set: Option<bool>,
    pub pin_retries: Option<u8>,
    pub pin_retries_max: Option<u8>,
}

/// `keyroostctl otp --json code` — a single read OTP code.
#[derive(Serialize)]
pub(crate) struct OtpCodeJson {
    pub app: String,
    pub account: String,
    pub code: String,
}

/// `keyroostctl fido --json credentials metadata` — resident-credential counts.
#[derive(Serialize)]
pub(crate) struct FidoCredsMetadataJson {
    pub existing_resident_credentials: u64,
    pub max_possible_remaining: u64,
}

/// `keyroostctl fido --json credentials list` — the resident credentials grouped
/// by relying party.
#[derive(Serialize)]
pub(crate) struct FidoCredsListJson {
    pub relying_parties: Vec<FidoRelyingPartyJson>,
}

/// One relying party in the `credentials list` output.
#[derive(Serialize)]
pub(crate) struct FidoRelyingPartyJson {
    pub rp_id: String,
    pub rp_name: Option<String>,
    pub credentials: Vec<FidoCredentialJson>,
}

/// One resident credential under a relying party.
#[derive(Serialize)]
pub(crate) struct FidoCredentialJson {
    /// Full hex credentialId (the value `credentials delete --cred-id` expects).
    pub credential_id: String,
    /// The user handle, rendered as UTF-8 (lossy), as the human prints it.
    pub user_id: String,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    pub algorithm: Option<i64>,
    pub algorithm_name: Option<&'static str>,
}

/// `keyroostctl fido large-blob --json list` — one entry per stored blob.
#[derive(Serialize)]
pub(crate) struct FidoLargeBlobListJson {
    pub entries: Vec<FidoLargeBlobEntryJson>,
    pub capacity: FidoLargeBlobCapacityJson,
}

/// Space accounting for the whole array (serialized form incl. checksum).
#[derive(Serialize)]
pub(crate) struct FidoLargeBlobCapacityJson {
    pub max_bytes: u64,
    pub used_bytes: u64,
    pub free_bytes: u64,
}

/// Decoded fields of a recognized OpenSSH certificate entry.
#[derive(Serialize)]
pub(crate) struct FidoLargeBlobSshCertJson {
    pub key_type: String,
    /// Decimal string: a u64 past 2^53 is not exact as a JSON number in
    /// most consumers.
    pub serial: String,
    /// "user" or "host".
    pub cert_type: &'static str,
    pub key_id: String,
    pub principals: Vec<String>,
    pub valid_after: u64,
    pub valid_before: u64,
    /// Human validity window, e.g. "2026-01-01 00:00:00 UTC to …".
    pub validity: String,
    /// "name=value" (or bare "name") per critical option.
    pub critical_options: Vec<String>,
    pub extensions: Vec<String>,
}

/// One large-blob array entry as the `list` view renders it.
#[derive(Serialize)]
pub(crate) struct FidoLargeBlobEntryJson {
    pub index: usize,
    /// Declared plaintext size of the entry (origSize), in bytes.
    pub size: u64,
    /// Whether this entry is a keyroost-authored plaintext note (true) or an
    /// opaque RP-encrypted record (false).
    pub is_note: bool,
    /// The note text when `is_note`; `null` for opaque entries.
    pub text: Option<String>,
    /// Entry classification: "note", "ssh-cert", or "opaque".
    pub kind: &'static str,
    pub ssh_cert: Option<FidoLargeBlobSshCertJson>,
}

/// `keyroostctl fido large-blob --json get <INDEX>` — a single entry in full.
#[derive(Serialize)]
pub(crate) struct FidoLargeBlobGetJson {
    pub index: usize,
    pub size: u64,
    pub is_note: bool,
    pub text: Option<String>,
    /// Entry classification: "note", "ssh-cert", or "opaque".
    pub kind: &'static str,
    pub ssh_cert: Option<FidoLargeBlobSshCertJson>,
    /// Hex of the raw ciphertext bytes (the note magic + UTF-8 for a note, or
    /// the RP's AEAD ciphertext for an opaque entry).
    pub hex: String,
}

/// `keyroostctl prog --json info`.
#[derive(Serialize)]
pub(crate) struct ProgInfoJson {
    pub serial: String,
    pub model: Option<String>,
    pub utc_time: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn kind(v: &Value) -> &'static str {
        match v {
            Value::Null => "null",
            Value::Bool(_) => "bool",
            Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
        }
    }

    /// `v` is an object with exactly these keys, each of one of the `|`-separated kinds.
    #[track_caller]
    fn assert_shape(v: &Value, want: &[(&str, &str)]) {
        let obj = v
            .as_object()
            .unwrap_or_else(|| panic!("not an object: {v}"));
        let mut got: Vec<&str> = obj.keys().map(String::as_str).collect();
        got.sort_unstable();
        let mut exp: Vec<&str> = want.iter().map(|(k, _)| *k).collect();
        exp.sort_unstable();
        assert_eq!(got, exp, "keys of {v}");
        for (k, kinds) in want {
            assert!(
                kinds.split('|').any(|t| t == kind(&obj[*k])),
                "{k}: {} is not {kinds}",
                kind(&obj[*k])
            );
        }
    }

    fn to_v<T: Serialize>(t: &T) -> Value {
        serde_json::to_value(t).unwrap()
    }

    fn block(
        algorithm: u8,
        time_step: u8,
        digits: u8,
        title: Option<&str>,
    ) -> keyroost_proto::commands::ProfilePublicData {
        keyroost_proto::commands::ProfilePublicData {
            flag: 0,
            title: title.map(str::to_string),
            time_a: 1,
            time_b: 2,
            algorithm,
            time_step,
            digits,
            seed_present: title.is_some(),
        }
    }

    #[test]
    fn no_field_is_ever_omitted() {
        assert!(!include_str!("json_out.rs").contains(concat!("skip_serializing", "_if")));
    }

    #[test]
    fn molto_slot_shape_with_and_without_data() {
        let shape = [
            ("slot", "number"),
            ("occupied", "bool"),
            ("title", "string|null"),
            ("flag", "number"),
            ("algorithm", "string|null"),
            ("period", "number|null"),
            ("digits", "number|null"),
            ("time_a", "number"),
            ("time_b", "number"),
        ];
        for (alg, step, digits, title) in [
            (1u8, 30u8, 6u8, Some("a")),
            (0, 0, 0, None),
            (3, 45, 7, None),
        ] {
            let v = to_v(&MoltoSlotJson::from_block(
                7,
                &block(alg, step, digits, title),
            ));
            assert_shape(&v, &shape);
        }
        let v = to_v(&MoltoSlotJson::from_block(7, &block(2, 60, 8, None)));
        assert_eq!(
            (
                v["algorithm"].as_str(),
                v["period"].as_u64(),
                v["digits"].as_u64()
            ),
            (Some("sha256"), Some(60), Some(8))
        );
        let v = to_v(&MoltoSlotJson::from_block(7, &block(3, 45, 7, None)));
        assert!(v["algorithm"].is_null() && v["digits"].is_null()); // unknown codes are null, period is the byte
        assert_eq!(v["period"].as_u64(), Some(45));
        let v = to_v(&MoltoSlotJson::from_block(7, &block(0, 0, 0, None)));
        assert!(v["algorithm"].is_null() && v["period"].is_null() && v["digits"].is_null());
        assert!(v["title"].is_null());
    }

    #[test]
    fn empty_lists_are_present_arrays() {
        let v = to_v(&KeysJson::<ListRowJson> { keys: vec![] });
        assert_eq!(v, serde_json::json!({"keys": []}));
        let v = to_v(&AccountsJson::<OathCredentialJson> { accounts: vec![] });
        assert_eq!(v, serde_json::json!({"accounts": []}));
    }

    #[test]
    fn device_json_shape() {
        let shape = [
            ("vendor", "string"),
            ("model", "string"),
            ("name", "string|null"),
            ("serial", "string"),
            ("transport", "string"),
            ("kind", "string"),
            ("capabilities", "array"),
            ("capabilities_unverified", "array"),
        ];
        for name in [Some("work".to_string()), None] {
            let d = DeviceJson {
                vendor: "V".into(),
                model: "M".into(),
                name,
                serial: "1".into(),
                transport: "USB".into(),
                kind: "key",
                capabilities: vec!["FIDO2"],
                capabilities_unverified: vec![],
            };
            let v = to_v(&KeysJson { keys: vec![d] });
            assert_shape(&v, &[("keys", "array")]);
            assert_shape(&v["keys"][0], &shape);
        }
    }

    #[test]
    fn list_row_shape() {
        let shape = [
            ("number", "number"),
            ("device", "string"),
            ("name", "string|null"),
            ("vendor", "string"),
            ("model", "string"),
            ("serial", "string"),
            ("kind", "string"),
            ("capabilities", "array"),
            ("capabilities_unverified", "array"),
            ("readers", "array"),
            ("hid_paths", "array"),
        ];
        for name in [Some("work".to_string()), None] {
            let r = ListRowJson {
                number: 1,
                device: "1".into(),
                name,
                vendor: "V".into(),
                model: "M".into(),
                serial: "1".into(),
                kind: "key",
                capabilities: vec![],
                capabilities_unverified: vec![],
                readers: vec![],
                hid_paths: vec![],
            };
            let v = to_v(&KeysJson { keys: vec![r] });
            assert_shape(&v, &[("keys", "array")]);
            assert_shape(&v["keys"][0], &shape);
        }
    }

    #[test]
    fn molto_info_shape() {
        let v = to_v(&MoltoInfoJson {
            serial: "S".into(),
            utc_time: 5,
            drift_seconds: -3,
        });
        assert_shape(
            &v,
            &[
                ("serial", "string"),
                ("utc_time", "number"),
                ("drift_seconds", "number"),
            ],
        );
    }

    #[test]
    fn prog_info_shape() {
        for model in [Some("C302".to_string()), None] {
            let v = to_v(&ProgInfoJson {
                serial: "S".into(),
                model,
                utc_time: 5,
            });
            assert_shape(
                &v,
                &[
                    ("serial", "string"),
                    ("model", "string|null"),
                    ("utc_time", "number"),
                ],
            );
        }
    }

    #[test]
    fn fido_info_shape_u2f_only_and_ctap2() {
        let top = [
            ("device", "string"),
            ("channel_id", "number"),
            ("ctaphid_protocol_version", "number"),
            ("firmware", "string"),
            ("hid_caps", "array"),
            ("hid_caps_raw", "number"),
            ("ctap2", "object|null"),
        ];
        let inner = [
            ("versions", "array"),
            ("extensions", "array"),
            ("aaguid", "string"),
            ("options", "array"),
            ("max_msg_size", "number|null"),
            ("pin_uv_auth_protocols", "array"),
            ("transports", "array"),
            ("min_pin_length", "number|null"),
            ("force_pin_change", "bool|null"),
            ("firmware_version", "number|null"),
        ];
        let info = |ctap2| FidoInfoJson {
            device: "/dev/hidraw0".into(),
            channel_id: 1,
            ctaphid_protocol_version: 2,
            firmware: "1.2.3".into(),
            hid_caps: vec!["WINK"],
            hid_caps_raw: 1,
            ctap2,
        };
        let v = to_v(&info(None));
        assert_shape(&v, &top);
        assert!(v["ctap2"].is_null());
        for some in [true, false] {
            let c = Ctap2InfoJson {
                versions: vec!["FIDO_2_0".into()],
                extensions: vec![],
                aaguid: "00".into(),
                options: vec![OptionJson {
                    name: "rk".into(),
                    value: true,
                }],
                max_msg_size: some.then_some(1200),
                pin_uv_auth_protocols: vec![2, 1],
                transports: vec![],
                min_pin_length: some.then_some(4),
                force_pin_change: some.then_some(false),
                firmware_version: some.then_some(7),
            };
            let v = to_v(&info(Some(c)));
            assert_shape(&v, &top);
            assert_shape(&v["ctap2"], &inner);
        }
    }

    #[test]
    fn piv_status_slot_shape() {
        let shape = [
            ("slot", "string"),
            ("slot_name", "string"),
            ("cert_present", "bool"),
            ("cert_len", "number"),
            ("cert_unreadable", "string|null"),
            ("cert_compressed", "bool"),
        ];
        let slot = keyroost_piv::Slot::Authentication;
        for (unreadable, compressed) in [(Some("damaged"), false), (None, true), (None, false)] {
            let v = to_v(&PivSlotJson {
                slot: piv_slot_token(slot),
                slot_name: slot.label(),
                cert_present: true,
                cert_len: 0,
                cert_unreadable: unreadable,
                cert_compressed: compressed,
            });
            assert_shape(&v, &shape);
            assert_eq!(v["slot"], "9a");
            assert_eq!(v["slot_name"], "authentication (9A)");
        }
    }

    #[test]
    fn piv_status_shape() {
        let shape = [
            ("version", "string|null"),
            ("serial", "string|null"),
            ("pin_retries", "number|null"),
            ("chuid", "object|null"),
            ("slots", "array"),
            ("applet_fingerprint", "string"),
            ("applet_name", "string"),
            ("version_firmware", "string|null"),
        ];
        for some in [true, false] {
            let v = to_v(&PivStatusJson {
                version: some.then(|| "5.7.1".to_string()),
                serial: some.then(|| "12345678".to_string()),
                pin_retries: some.then_some(3),
                chuid: some.then(|| PivChuidJson {
                    fasc_n: "d4".into(),
                    guid: "00".into(),
                    expiration: "2030-01-01".into(),
                    signature: String::new(),
                    lrc: String::new(),
                }),
                slots: vec![],
                applet_fingerprint: "YubiKey".into(),
                applet_name: String::new(),
                version_firmware: some.then(|| "1.0.0".to_string()),
            });
            assert_shape(&v, &shape);
            if some {
                assert_shape(
                    &v["chuid"],
                    &[
                        ("fasc_n", "string"),
                        ("guid", "string"),
                        ("expiration", "string"),
                        ("signature", "string"),
                        ("lrc", "string"),
                    ],
                );
            }
        }
    }

    #[test]
    fn piv_test_shape() {
        let slot = keyroost_piv::Slot::retired(1).unwrap();
        for detail in [Some("mismatch".to_string()), None] {
            let v = to_v(&PivTestJson {
                slot: piv_slot_token(slot),
                slot_name: slot.label(),
                algorithm: "ECCP256".into(),
                ok: detail.is_none(),
                operations: vec![PivTestOpJson {
                    operation: "sign".into(),
                    result: "passed".into(),
                    detail,
                }],
            });
            assert_shape(
                &v,
                &[
                    ("slot", "string"),
                    ("slot_name", "string"),
                    ("algorithm", "string"),
                    ("ok", "bool"),
                    ("operations", "array"),
                ],
            );
            assert_eq!(v["slot"], "82");
            assert_shape(
                &v["operations"][0],
                &[
                    ("operation", "string"),
                    ("result", "string"),
                    ("detail", "string|null"),
                ],
            );
        }
    }

    #[test]
    fn openpgp_status_shape() {
        let shape = [
            ("aid", "string"),
            ("serial", "string|null"),
            ("sig_algo", "string"),
            ("dec_algo", "string"),
            ("aut_algo", "string"),
            ("fingerprint_sig", "string|null"),
            ("fingerprint_dec", "string|null"),
            ("fingerprint_aut", "string|null"),
            ("user_pin_retries", "number"),
            ("reset_code_retries", "number"),
            ("admin_pin_retries", "number"),
            ("signature_count", "number|null"),
        ];
        let status = |serial: Option<u32>, fpr: Option<String>| OpenpgpStatusJson {
            aid: "D276".into(),
            serial: serial.map(|s| s.to_string()),
            sig_algo: "RSA-2048".into(),
            dec_algo: "RSA-2048".into(),
            aut_algo: "RSA-2048".into(),
            fingerprint_sig: fpr.clone(),
            fingerprint_dec: fpr.clone(),
            fingerprint_aut: fpr.clone(),
            user_pin_retries: 3,
            reset_code_retries: 0,
            admin_pin_retries: 3,
            signature_count: fpr.as_ref().map(|_| 9),
        };
        let v = to_v(&status(Some(0x0000_0001), Some("AB".into())));
        assert_shape(&v, &shape);
        assert_eq!(v["serial"], "1");
        let v = to_v(&status(Some(0x0123_4567), None));
        assert_shape(&v, &shape);
        assert_eq!(v["serial"], "19088743");
        let v = to_v(&status(None, None));
        assert_shape(&v, &shape);
        assert!(v["serial"].is_null());
    }

    #[test]
    fn oath_accounts_shape() {
        let v = to_v(&AccountsJson {
            accounts: vec![OathCredentialJson {
                name: "a".into(),
                oath_type: "TOTP",
                algorithm: "sha1",
            }],
        });
        assert_shape(&v, &[("accounts", "array")]);
        assert_shape(
            &v["accounts"][0],
            &[
                ("name", "string"),
                ("type", "string"),
                ("algorithm", "string"),
            ],
        );
        assert_eq!(v["accounts"][0]["algorithm"], "sha1");
    }

    #[test]
    fn otp_accounts_shape() {
        for code in [Some("123456".to_string()), None] {
            let v = to_v(&AccountsJson {
                accounts: vec![OtpEntryJson {
                    app: "a".into(),
                    account: "b".into(),
                    otp_type: "TOTP",
                    algorithm: "sha1",
                    touch_required: code.is_none(),
                    code,
                }],
            });
            assert_shape(&v, &[("accounts", "array")]);
            assert_shape(
                &v["accounts"][0],
                &[
                    ("app", "string"),
                    ("account", "string"),
                    ("type", "string"),
                    ("algorithm", "string"),
                    ("code", "string|null"),
                    ("touch_required", "bool"),
                ],
            );
            assert_eq!(v["accounts"][0]["algorithm"], "sha1");
        }
    }

    #[test]
    fn otp_pin_status_shape() {
        let shape = [
            ("supported", "bool"),
            ("pin_set", "bool|null"),
            ("pin_retries", "number|null"),
            ("pin_retries_max", "number|null"),
        ];
        let v = to_v(&OtpPinStatusJson {
            supported: true,
            pin_set: Some(true),
            pin_retries: Some(3),
            pin_retries_max: Some(8),
        });
        assert_shape(&v, &shape);
        let v = to_v(&OtpPinStatusJson {
            supported: false,
            pin_set: None,
            pin_retries: None,
            pin_retries_max: None,
        });
        assert_shape(&v, &shape);
    }

    #[test]
    fn creds_list_shape() {
        for some in [true, false] {
            let v = to_v(&FidoCredsListJson {
                relying_parties: vec![FidoRelyingPartyJson {
                    rp_id: "example.com".into(),
                    rp_name: some.then(|| "Example".to_string()),
                    credentials: vec![FidoCredentialJson {
                        credential_id: "00".into(),
                        user_id: "u".into(),
                        user_name: some.then(|| "n".to_string()),
                        user_display_name: some.then(|| "d".to_string()),
                        algorithm: some.then_some(-7),
                        algorithm_name: some.then_some("ES256"),
                    }],
                }],
            });
            assert_shape(&v, &[("relying_parties", "array")]);
            let rp = &v["relying_parties"][0];
            assert_shape(
                rp,
                &[
                    ("rp_id", "string"),
                    ("rp_name", "string|null"),
                    ("credentials", "array"),
                ],
            );
            assert_shape(
                &rp["credentials"][0],
                &[
                    ("credential_id", "string"),
                    ("user_id", "string"),
                    ("user_name", "string|null"),
                    ("user_display_name", "string|null"),
                    ("algorithm", "number|null"),
                    ("algorithm_name", "string|null"),
                ],
            );
        }
    }

    #[test]
    fn large_blob_entry_shape() {
        let cert = || FidoLargeBlobSshCertJson {
            key_type: "ssh-ed25519-cert-v01@openssh.com".into(),
            serial: u64::MAX.to_string(),
            cert_type: "user",
            key_id: "id".into(),
            principals: vec![],
            valid_after: 0,
            valid_before: u64::MAX,
            validity: "forever".into(),
            critical_options: vec![],
            extensions: vec![],
        };
        let entry_shape = [
            ("index", "number"),
            ("size", "number"),
            ("is_note", "bool"),
            ("text", "string|null"),
            ("kind", "string"),
            ("ssh_cert", "object|null"),
        ];
        let entries = vec![
            FidoLargeBlobEntryJson {
                index: 0,
                size: 2,
                is_note: true,
                text: Some("hi".into()),
                kind: "note",
                ssh_cert: None,
            },
            FidoLargeBlobEntryJson {
                index: 1,
                size: 9,
                is_note: false,
                text: None,
                kind: "ssh-cert",
                ssh_cert: Some(cert()),
            },
        ];
        let v = to_v(&FidoLargeBlobListJson {
            entries,
            capacity: FidoLargeBlobCapacityJson {
                max_bytes: 1024,
                used_bytes: 17,
                free_bytes: 1007,
            },
        });
        for e in v["entries"].as_array().unwrap() {
            assert_shape(e, &entry_shape);
        }
        assert_eq!(
            v["entries"][1]["ssh_cert"]["serial"],
            "18446744073709551615"
        );
        assert!(v["entries"][0]["ssh_cert"].is_null());
        assert!(v["entries"][1]["text"].is_null());

        let mut get_shape = entry_shape.to_vec();
        get_shape.push(("hex", "string"));
        for (text, ssh_cert) in [(Some("hi".to_string()), None), (None, Some(cert()))] {
            let v = to_v(&FidoLargeBlobGetJson {
                index: 0,
                size: 2,
                is_note: text.is_some(),
                text,
                kind: "note",
                ssh_cert,
                hex: "00".into(),
            });
            assert_shape(&v, &get_shape);
        }
    }
}
