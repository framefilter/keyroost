//! Serializable shapes for the global `--json` output mode. Each struct mirrors
//! 1:1 the data the corresponding command's human handler already prints — no
//! new data, only structure.

use serde::Serialize;

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
    pub caps: Vec<&'static str>,
    /// The subset of `caps` keyroost could not verify against the device
    /// (no card channel was available to ask): still offered, but not
    /// proven present. Tri-state per capability: in `caps` only =
    /// verified present; in both lists = offered but unverified; in
    /// neither = absent.
    pub caps_unverified: Vec<&'static str>,
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
    pub utc: u32,
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
#[derive(Serialize)]
pub(crate) struct MoltoSlotJson {
    pub slot: u8,
    pub occupied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub flag: u8,
    pub algorithm: u8,
    pub time_step: u8,
    pub digits: u8,
    pub time_a: u32,
    pub time_b: u32,
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
    /// Present only when the device speaks CTAP2 (CBOR-capable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ctap2: Option<Ctap2InfoJson>,
}

/// The authenticatorGetInfo payload (CTAP2 devices only).
#[derive(Serialize)]
pub(crate) struct Ctap2InfoJson {
    pub versions: Vec<String>,
    pub extensions: Vec<String>,
    pub aaguid: String,
    pub options: Vec<OptionJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_msg_size: Option<u64>,
    pub pin_uv_auth_protocols: Vec<u64>,
    pub transports: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_pin_length: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force_pin_change: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firmware_version: Option<u64>,
}

/// One authenticator option (e.g. `{ "name": "rk", "value": true }`).
#[derive(Serialize)]
pub(crate) struct OptionJson {
    pub name: String,
    pub value: bool,
}

/// `keyroostctl fido --json pin-retries`.
#[derive(Serialize)]
pub(crate) struct FidoPinRetriesJson {
    pub pin_retries: u32,
}

/// `keyroostctl piv --json status`.
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
    /// beyond — the same rendering `piv status`'s text output uses.
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
    /// (The plain-text `piv status` output does apply that fallback —
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
    pub slot: String,
    pub cert_present: bool,
    pub cert_len: usize,
    /// Present only when the slot holds a certificate that cannot be
    /// read: `damaged` or `too_large` (then `cert_present` is true and
    /// `cert_len` is 0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_unreadable: Option<&'static str>,
    /// Present (and `true`) only when the certificate is stored
    /// gzip-compressed; `cert_len` is still the DER length.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub cert_compressed: bool,
}

/// `keyroostctl piv --json test`.
#[derive(Serialize)]
pub(crate) struct PivTestJson {
    pub slot: String,
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
    /// Present only for `"failed"` — a short reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// `keyroostctl openpgp --json status`.
#[derive(Serialize)]
pub(crate) struct OpenpgpStatusJson {
    pub aid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial: Option<u32>,
    pub sig_algo: String,
    pub dec_algo: String,
    pub aut_algo: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint_sig: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint_dec: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint_aut: Option<String>,
    pub pin_retries_pw1: u8,
    pub pin_retries_rc: u8,
    pub pin_retries_pw3: u8,
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
    pub oath_type: &'static str,
    /// "SHA1" / "SHA256" / "SHA512".
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
    pub otp_type: &'static str,
    /// "SHA1" / "SHA256".
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_set: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retries_left: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_retries: Option<u8>,
}

/// `keyroostctl otp --json get` — a single read OTP code.
#[derive(Serialize)]
pub(crate) struct OtpGetJson {
    pub app: String,
    pub account: String,
    pub code: String,
}

/// `keyroostctl fido --json creds-metadata` — resident-credential counts.
#[derive(Serialize)]
pub(crate) struct FidoCredsMetadataJson {
    pub existing_resident_credentials: u64,
    pub max_possible_remaining: u64,
}

/// `keyroostctl fido --json creds-list` — the resident credentials grouped
/// by relying party.
#[derive(Serialize)]
pub(crate) struct FidoCredsListJson {
    pub relying_parties: Vec<FidoRelyingPartyJson>,
}

/// One relying party in the creds-list output.
#[derive(Serialize)]
pub(crate) struct FidoRelyingPartyJson {
    pub rp_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rp_name: Option<String>,
    pub credentials: Vec<FidoCredentialJson>,
}

/// One resident credential under a relying party.
#[derive(Serialize)]
pub(crate) struct FidoCredentialJson {
    /// Full hex credentialId (the value `creds-delete --cred-id` expects).
    pub credential_id: String,
    /// The user handle, rendered as UTF-8 (lossy), as the human prints it.
    pub user_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
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
    pub serial: u64,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Entry classification: "note", "ssh-cert", or "opaque".
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_cert: Option<FidoLargeBlobSshCertJson>,
}

/// `keyroostctl fido large-blob --json get <INDEX>` — a single entry in full.
#[derive(Serialize)]
pub(crate) struct FidoLargeBlobGetJson {
    pub index: usize,
    pub size: u64,
    pub is_note: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Entry classification: "note", "ssh-cert", or "opaque".
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_cert: Option<FidoLargeBlobSshCertJson>,
    /// Hex of the raw ciphertext bytes (the note magic + UTF-8 for a note, or
    /// the RP's AEAD ciphertext for an opaque entry).
    pub hex: String,
}

/// `keyroostctl prog --json info`.
#[derive(Serialize)]
pub(crate) struct ProgInfoJson {
    pub serial: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    pub utc_time: u32,
}
