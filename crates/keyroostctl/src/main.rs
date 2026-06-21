//! keyroostctl — CLI for programming Token2 Molto2 / Molto2v2 TOTP tokens.
//!
//! Drop-in replacement for `molto2.py` with a cleaner subcommand layout.

use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand, ValueEnum};
use keyroost_proto::codec::{base32_decode, hex_decode, hex_encode};
use keyroost_proto::commands::{
    DisplayTimeout, HmacAlgo, OtpDigits, ProfileConfig, TimeStep, DEFAULT_CUSTOMER_KEY,
};
use keyroost_transport::{Session, TransportError};

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use keyroost_keyring::Keyring;
use keyroost_resolve::{
    ccid_readers_if_needed, ccid_serial_for, connected_keys, effective_serials,
    read_effective_serial, VID_YUBICO,
};

mod overview;

/// The global `--name` selector, captured once in `run()` so the FIDO device
/// resolver can honor it without threading it through every subcommand handler.
static SELECTED_KEY_NAME: OnceLock<Option<String>> = OnceLock::new();

/// Whether the global `--json` flag was set, captured once in `run()` so the
/// status/query handlers can switch output without threading it through.
static JSON_OUTPUT: OnceLock<bool> = OnceLock::new();

fn json_output() -> bool {
    *JSON_OUTPUT.get().unwrap_or(&false)
}

/// Pretty-print a serializable value as JSON to stdout (the `--json` path for
/// the status/query commands).
fn emit_json<T: serde::Serialize>(value: &T) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

/// Serializable shapes for the global `--json` output mode. Each struct mirrors
/// 1:1 the data the corresponding command's human handler already prints — no
/// new data, only structure.
mod json_out {
    use serde::Serialize;

    /// One device in the bare-invocation overview (`keyroostctl --json`).
    #[derive(Serialize)]
    pub struct DeviceJson {
        pub vendor: String,
        pub model: String,
        pub name: Option<String>,
        pub serial: String,
        pub transport: String,
        /// "key" or "token".
        pub kind: &'static str,
        pub caps: Vec<&'static str>,
    }

    /// `keyroostctl molto --json info`.
    #[derive(Serialize)]
    pub struct MoltoInfoJson {
        pub serial: String,
        pub utc: u32,
        pub drift_seconds: i64,
    }

    /// `keyroostctl fido --json info` — the CTAP2 authenticatorGetInfo fields the
    /// human handler prints (plus the CTAPHID transport facts).
    #[derive(Serialize)]
    pub struct FidoInfoJson {
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
    pub struct Ctap2InfoJson {
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
    pub struct OptionJson {
        pub name: String,
        pub value: bool,
    }

    /// `keyroostctl fido --json pin-retries`.
    #[derive(Serialize)]
    pub struct FidoPinRetriesJson {
        pub pin_retries: u32,
    }

    /// `keyroostctl piv --json status`.
    #[derive(Serialize)]
    pub struct PivStatusJson {
        pub version: Option<String>,
        pub serial: Option<u32>,
        pub pin_retries: Option<u8>,
        pub slots: Vec<PivSlotJson>,
    }

    /// One PIV key slot in the status output.
    #[derive(Serialize)]
    pub struct PivSlotJson {
        pub slot: String,
        pub cert_present: bool,
        pub cert_len: usize,
    }

    /// `keyroostctl openpgp --json status`.
    #[derive(Serialize)]
    pub struct OpenpgpStatusJson {
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
    pub struct OtpSerialJson {
        pub serial: String,
    }

    /// `keyroostctl oath --json list` — one stored OATH credential. Mirrors the
    /// human line `<name>  [<type>/<algorithm>]`.
    #[derive(Serialize)]
    pub struct OathCredentialJson {
        pub name: String,
        /// "TOTP" or "HOTP".
        pub oath_type: &'static str,
        /// "SHA1" / "SHA256" / "SHA512".
        pub algorithm: &'static str,
    }

    /// `keyroostctl oath --json code` — the calculated code. The human handler
    /// prints only the code; we also carry the credential name that was queried.
    #[derive(Serialize)]
    pub struct OathCodeJson {
        pub name: String,
        pub code: String,
    }

    /// `keyroostctl otp --json list` — one Token2 OTP entry. Mirrors the human
    /// line `<app:account>  [<type>/<algo>]  <code|—>  (touch)?`.
    #[derive(Serialize)]
    pub struct OtpEntryJson {
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

    /// `keyroostctl otp --json get` — a single read OTP code.
    #[derive(Serialize)]
    pub struct OtpGetJson {
        pub app: String,
        pub account: String,
        pub code: String,
    }

    /// `keyroostctl fido --json creds-metadata` — resident-credential counts.
    #[derive(Serialize)]
    pub struct FidoCredsMetadataJson {
        pub existing_resident_credentials: u64,
        pub max_possible_remaining: u64,
    }

    /// `keyroostctl fido --json creds-list` — the resident credentials grouped
    /// by relying party.
    #[derive(Serialize)]
    pub struct FidoCredsListJson {
        pub relying_parties: Vec<FidoRelyingPartyJson>,
    }

    /// One relying party in the creds-list output.
    #[derive(Serialize)]
    pub struct FidoRelyingPartyJson {
        pub rp_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub rp_name: Option<String>,
        pub credentials: Vec<FidoCredentialJson>,
    }

    /// One resident credential under a relying party.
    #[derive(Serialize)]
    pub struct FidoCredentialJson {
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
    pub struct FidoLargeBlobListJson {
        pub entries: Vec<FidoLargeBlobEntryJson>,
    }

    /// One large-blob array entry as the `list` view renders it.
    #[derive(Serialize)]
    pub struct FidoLargeBlobEntryJson {
        pub index: usize,
        /// Declared plaintext size of the entry (origSize), in bytes.
        pub size: u64,
        /// Whether this entry is a keyroost-authored plaintext note (true) or an
        /// opaque RP-encrypted record (false).
        pub is_note: bool,
        /// The note text when `is_note`; `null` for opaque entries.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub text: Option<String>,
    }

    /// `keyroostctl fido large-blob --json get <INDEX>` — a single entry in full.
    #[derive(Serialize)]
    pub struct FidoLargeBlobGetJson {
        pub index: usize,
        pub size: u64,
        pub is_note: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub text: Option<String>,
        /// Hex of the raw ciphertext bytes (the note magic + UTF-8 for a note, or
        /// the RP's AEAD ciphertext for an opaque entry).
        pub hex: String,
    }
}

#[derive(Parser)]
#[command(
    name = "keyroostctl",
    version,
    about = "Program Token2 Molto2 / Molto2v2 TOTP tokens"
)]
struct Cli {
    /// List available PC/SC readers and exit.
    #[arg(long, global = true)]
    list_readers: bool,
    /// Print every outgoing APDU and incoming response to stderr.
    #[arg(long, global = true)]
    debug: bool,
    /// Target a security key by its friendly name (see the `key-name` command).
    /// Resolves to the device's current path. Mutually exclusive with --path.
    #[arg(long, global = true, value_name = "NAME")]
    name: Option<String>,
    /// Emit machine-readable JSON instead of human text (where supported: status
    /// and query commands). Side-effect commands ignore it.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print shell completions to stdout (e.g. `keyroostctl completions bash
    /// > /etc/bash_completion.d/keyroostctl`).
    Completions {
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// Write a set of man pages (keyroostctl.1 + keyroostctl-<group>.1) into a
    /// directory, e.g. `keyroostctl manpage ./man && man -l ./man/keyroostctl-piv.1`.
    Manpage {
        /// Directory to write the .1 files into (created if missing).
        #[arg(value_name = "DIR")]
        dir: std::path::PathBuf,
    },
    /// Diagnose the local environment: PC/SC service, readers, FIDO HID
    /// access, udev rules, registry permissions. Read-only, touches no key.
    Doctor,
    /// Token2 Molto2 / Molto2v2 programmable TOTP token.
    Molto {
        #[command(flatten)]
        key: KeyArgs,
        #[command(subcommand)]
        cmd: MoltoCmd,
    },
    /// Token2 2nd-generation single-profile programmable TOTP token. Uses the
    /// token's fixed device key; no customer key is needed.
    Prog {
        #[command(subcommand)]
        cmd: ProgCmd,
    },
    /// List connected devices: PC/SC readers and FIDO HID authenticators.
    List {
        /// Show every HID device, not just those advertising the FIDO usage page.
        #[arg(long)]
        all_hid: bool,
    },
    /// FIDO2 / CTAP2: device info, reset, PIN management, resident credentials.
    Fido {
        #[command(subcommand)]
        cmd: FidoCmd,
    },
    /// Manage friendly names for security keys (opt-in; stored in keys.json).
    KeyName {
        #[command(subcommand)]
        cmd: KeyNameCmd,
    },
    /// Read or manage OATH (TOTP/HOTP) credentials on a security key over PC/SC.
    Oath {
        #[command(subcommand)]
        cmd: OathCmd,
    },
    /// Manage the OpenPGP card applet on a security key over PC/SC: status,
    /// key generate/import, sign, decrypt, reset, and cardholder metadata.
    Openpgp {
        #[command(subcommand)]
        cmd: OpenpgpCmd,
    },
    /// Manage the PIV (smartcard) applet on a security key over PC/SC: status,
    /// PIN/PUK, management key, key generation, and certificate import/export.
    Piv {
        #[command(subcommand)]
        cmd: PivCmd,
    },
    /// Manage on-device OTP entries on a Token2 T2F2 / PIN+ FIDO key over USB-HID
    /// or CCID/NFC: list, get a code, add/delete entries, the button-press HOTP
    /// keystroke slot, and the serial number. This is the Token2 OTP applet,
    /// distinct from the Yubico/Trussed `oath` applet above.
    Otp {
        /// Which transport to reach the OTP applet on. `auto` (default) tries
        /// USB-HID and falls back to CCID/NFC when HID is disabled on the key.
        #[arg(long, value_enum, default_value_t = OtpTransportArg::Auto, global = true)]
        transport: OtpTransportArg,
        #[command(subcommand)]
        cmd: OtpCmd,
    },
}

/// A PIV key slot, selected on the CLI by its hex key reference.
#[derive(Clone, Copy, clap::ValueEnum)]
enum CliPivSlot {
    /// 9A — PIV Authentication.
    #[value(name = "9a")]
    Auth,
    /// 9C — Digital Signature.
    #[value(name = "9c")]
    Sign,
    /// 9D — Key Management (decryption).
    #[value(name = "9d")]
    KeyMgmt,
    /// 9E — Card Authentication.
    #[value(name = "9e")]
    CardAuth,
}

impl CliPivSlot {
    fn to_slot(self) -> keyroost_piv::Slot {
        match self {
            CliPivSlot::Auth => keyroost_piv::Slot::Authentication,
            CliPivSlot::Sign => keyroost_piv::Slot::Signature,
            CliPivSlot::KeyMgmt => keyroost_piv::Slot::KeyManagement,
            CliPivSlot::CardAuth => keyroost_piv::Slot::CardAuthentication,
        }
    }
}

/// Asymmetric key algorithm for `piv generate-key`.
#[derive(Clone, Copy, clap::ValueEnum)]
enum CliPivKeyAlg {
    Rsa1024,
    Rsa2048,
    Rsa3072,
    Rsa4096,
    #[value(name = "eccp256")]
    EccP256,
    #[value(name = "eccp384")]
    EccP384,
    Ed25519,
    X25519,
}

impl CliPivKeyAlg {
    fn to_alg(self) -> keyroost_piv::KeyAlg {
        use keyroost_piv::KeyAlg::*;
        match self {
            CliPivKeyAlg::Rsa1024 => Rsa1024,
            CliPivKeyAlg::Rsa2048 => Rsa2048,
            CliPivKeyAlg::Rsa3072 => Rsa3072,
            CliPivKeyAlg::Rsa4096 => Rsa4096,
            CliPivKeyAlg::EccP256 => EccP256,
            CliPivKeyAlg::EccP384 => EccP384,
            CliPivKeyAlg::Ed25519 => Ed25519,
            CliPivKeyAlg::X25519 => X25519,
        }
    }
}

/// Management-key cipher algorithm.
#[derive(Clone, Copy, clap::ValueEnum)]
enum CliPivMgmtAlg {
    #[value(name = "3des")]
    TripleDes,
    Aes128,
    Aes192,
    Aes256,
}

impl CliPivMgmtAlg {
    fn to_alg(self) -> keyroost_piv::MgmtAlg {
        use keyroost_piv::MgmtAlg::*;
        match self {
            CliPivMgmtAlg::TripleDes => TripleDes,
            CliPivMgmtAlg::Aes128 => Aes128,
            CliPivMgmtAlg::Aes192 => Aes192,
            CliPivMgmtAlg::Aes256 => Aes256,
        }
    }
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum CliPinPolicy {
    Default,
    Never,
    Once,
    Always,
}

impl CliPinPolicy {
    fn to_policy(self) -> keyroost_piv::PinPolicy {
        use keyroost_piv::PinPolicy::*;
        match self {
            CliPinPolicy::Default => Default,
            CliPinPolicy::Never => Never,
            CliPinPolicy::Once => Once,
            CliPinPolicy::Always => Always,
        }
    }
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum CliTouchPolicy {
    Default,
    Never,
    Always,
    Cached,
}

impl CliTouchPolicy {
    fn to_policy(self) -> keyroost_piv::TouchPolicy {
        use keyroost_piv::TouchPolicy::*;
        match self {
            CliTouchPolicy::Default => Default,
            CliTouchPolicy::Never => Never,
            CliTouchPolicy::Always => Always,
            CliTouchPolicy::Cached => Cached,
        }
    }
}

/// Subcommands for the PIV smart-card applet. Secret material (PINs, PUK,
/// management key) is read from env/stdin, never argv. The management key is a
/// hex string (48 hex chars for AES-192 / 3DES, 32 for AES-128, 64 for AES-256).
#[derive(Subcommand)]
enum PivCmd {
    /// Show PIV status: version, serial, PIN retries, and which key slots hold a
    /// certificate. No PIN or touch required.
    Status {
        #[arg(long, value_name = "SUBSTR")]
        reader: Option<String>,
    },
    /// Change the PIV PIN. PINs are sourced from env vars or stdin (stdin
    /// reads two consecutive lines: old then new).
    ChangePin {
        #[arg(long, value_name = "SUBSTR")]
        reader: Option<String>,
        #[arg(long, value_name = "VAR", conflicts_with = "old_pin_stdin")]
        old_pin_env: Option<String>,
        #[arg(long)]
        old_pin_stdin: bool,
        #[arg(long, value_name = "VAR", conflicts_with = "new_pin_stdin")]
        new_pin_env: Option<String>,
        #[arg(long)]
        new_pin_stdin: bool,
    },
    /// Change the PUK (PIN Unblocking Key). PUKs are sourced from env vars or
    /// stdin (stdin reads two consecutive lines: old then new).
    ChangePuk {
        #[arg(long, value_name = "SUBSTR")]
        reader: Option<String>,
        #[arg(long, value_name = "VAR", conflicts_with = "old_puk_stdin")]
        old_puk_env: Option<String>,
        #[arg(long)]
        old_puk_stdin: bool,
        #[arg(long, value_name = "VAR", conflicts_with = "new_puk_stdin")]
        new_puk_env: Option<String>,
        #[arg(long)]
        new_puk_stdin: bool,
    },
    /// Unblock a blocked PIN using the PUK, setting a new PIN.
    UnblockPin {
        #[arg(long, value_name = "SUBSTR")]
        reader: Option<String>,
        #[arg(long, value_name = "VAR", conflicts_with = "puk_stdin")]
        puk_env: Option<String>,
        #[arg(long)]
        puk_stdin: bool,
        #[arg(long, value_name = "VAR", conflicts_with = "new_pin_stdin")]
        new_pin_env: Option<String>,
        #[arg(long)]
        new_pin_stdin: bool,
    },
    /// Set the PIN and PUK retry counts (resets both to factory defaults).
    /// Needs the management key and the current PIN.
    SetRetries {
        #[arg(long, value_name = "SUBSTR")]
        reader: Option<String>,
        #[arg(long, value_name = "N")]
        pin_tries: u8,
        #[arg(long, value_name = "N")]
        puk_tries: u8,
        #[arg(long, value_name = "VAR", conflicts_with = "mgmt_key_stdin")]
        mgmt_key_env: Option<String>,
        #[arg(long)]
        mgmt_key_stdin: bool,
        #[arg(long, value_name = "VAR", conflicts_with = "pin_stdin")]
        pin_env: Option<String>,
        #[arg(long)]
        pin_stdin: bool,
    },
    /// Change the card-management (9B) key.
    ChangeManagementKey {
        #[arg(long, value_name = "SUBSTR")]
        reader: Option<String>,
        #[arg(long, value_name = "VAR", conflicts_with = "old_mgmt_key_stdin")]
        old_mgmt_key_env: Option<String>,
        #[arg(long)]
        old_mgmt_key_stdin: bool,
        #[arg(long, value_name = "VAR", conflicts_with = "new_mgmt_key_stdin")]
        new_mgmt_key_env: Option<String>,
        #[arg(long)]
        new_mgmt_key_stdin: bool,
        /// Algorithm of the NEW management key.
        #[arg(long, value_enum, default_value = "aes192")]
        new_algorithm: CliPivMgmtAlg,
        /// Require a physical touch for every future management-key auth.
        #[arg(long)]
        touch: bool,
    },
    /// Generate a new key pair in a slot and print its public key (PEM). Needs
    /// the management key. Overwrites any existing key in the slot.
    GenerateKey {
        #[arg(long, value_name = "SUBSTR")]
        reader: Option<String>,
        #[arg(long, value_enum)]
        slot: CliPivSlot,
        #[arg(long, value_enum, default_value = "eccp256")]
        algorithm: CliPivKeyAlg,
        #[arg(long, value_enum, default_value = "default")]
        pin_policy: CliPinPolicy,
        #[arg(long, value_enum, default_value = "default")]
        touch_policy: CliTouchPolicy,
        #[arg(long, value_name = "VAR", conflicts_with = "mgmt_key_stdin")]
        mgmt_key_env: Option<String>,
        #[arg(long)]
        mgmt_key_stdin: bool,
    },
    /// Import a DER or PEM X.509 certificate into a slot. Needs the management key.
    ImportCert {
        #[arg(long, value_name = "SUBSTR")]
        reader: Option<String>,
        #[arg(long, value_enum)]
        slot: CliPivSlot,
        /// Path to a `.der` or `.pem` certificate file.
        #[arg(long, value_name = "PATH")]
        file: std::path::PathBuf,
        #[arg(long, value_name = "VAR", conflicts_with = "mgmt_key_stdin")]
        mgmt_key_env: Option<String>,
        #[arg(long)]
        mgmt_key_stdin: bool,
    },
    /// Export a slot's certificate (DER) to a file or stdout. No PIN required.
    ExportCert {
        #[arg(long, value_name = "SUBSTR")]
        reader: Option<String>,
        #[arg(long, value_enum)]
        slot: CliPivSlot,
        /// Output path; omit to write DER to stdout.
        #[arg(long, value_name = "PATH")]
        file: Option<std::path::PathBuf>,
    },
    /// Create a PKCS#10 certificate signing request for the key in a slot,
    /// signed on the card (PEM to stdout or --file). Hand the result to a CA;
    /// import the certificate it issues with `import-cert`.
    RequestCert {
        #[arg(long, value_name = "SUBSTR")]
        reader: Option<String>,
        #[arg(long, value_enum)]
        slot: CliPivSlot,
        /// Subject distinguished name, e.g. "CN=Alice,O=Example,C=US"
        /// (supported attributes: CN, O, OU, C, L, ST).
        #[arg(long, value_name = "DN")]
        subject: String,
        #[arg(long, value_name = "VAR", conflicts_with = "pin_stdin")]
        pin_env: Option<String>,
        #[arg(long)]
        pin_stdin: bool,
        /// Output path; omit to print the PEM to stdout.
        #[arg(long, value_name = "PATH")]
        file: Option<std::path::PathBuf>,
    },
    /// Create a self-signed certificate for the key in a slot, signed on the
    /// card, and store it in that slot (the slot then works in PIV-aware
    /// software without an external CA).
    SelfSign {
        #[arg(long, value_name = "SUBSTR")]
        reader: Option<String>,
        #[arg(long, value_enum)]
        slot: CliPivSlot,
        /// Subject distinguished name, e.g. "CN=Alice,O=Example,C=US"
        /// (supported attributes: CN, O, OU, C, L, ST).
        #[arg(long, value_name = "DN")]
        subject: String,
        /// Validity period in days, starting now.
        #[arg(long, value_name = "N", default_value_t = 365)]
        days: u32,
        #[arg(long, value_name = "VAR", conflicts_with = "pin_stdin")]
        pin_env: Option<String>,
        #[arg(long)]
        pin_stdin: bool,
        #[arg(long, value_name = "VAR", conflicts_with = "mgmt_key_stdin")]
        mgmt_key_env: Option<String>,
        #[arg(long)]
        mgmt_key_stdin: bool,
        /// Also write the certificate as PEM to this path.
        #[arg(long, value_name = "PATH")]
        file: Option<std::path::PathBuf>,
    },
    /// Reset the PIV application to factory defaults. Only works when BOTH the
    /// PIN and PUK are already blocked. Wipes all keys, certs, and PINs.
    Reset {
        #[arg(long, value_name = "SUBSTR")]
        reader: Option<String>,
        #[arg(long)]
        yes: bool,
    },
    /// Clear a slot's certificate object (standard PIV; works on every card).
    /// Removes ONLY the X.509 certificate — the slot's private key is left in
    /// place. Needs the management key. DESTRUCTIVE: requires `--yes`.
    DeleteCert {
        #[arg(long, value_name = "SUBSTR")]
        reader: Option<String>,
        #[arg(long, value_enum)]
        slot: CliPivSlot,
        #[arg(long, value_name = "VAR", conflicts_with = "mgmt_key_stdin")]
        mgmt_key_env: Option<String>,
        #[arg(long)]
        mgmt_key_stdin: bool,
        #[arg(long)]
        yes: bool,
    },
    /// Delete a slot's private key (Yubico extension; needs YubiKey firmware
    /// 5.7 or newer). Permanently erases the key material — the certificate
    /// object is left in place. Needs the management key. DESTRUCTIVE: requires
    /// `--yes`. Older cards cannot delete a key; overwrite the slot instead.
    DeleteKey {
        #[arg(long, value_name = "SUBSTR")]
        reader: Option<String>,
        #[arg(long, value_enum)]
        slot: CliPivSlot,
        #[arg(long, value_name = "VAR", conflicts_with = "mgmt_key_stdin")]
        mgmt_key_env: Option<String>,
        #[arg(long)]
        mgmt_key_stdin: bool,
        #[arg(long)]
        yes: bool,
    },
}

/// Subcommands for the OpenPGP card applet.
#[derive(Subcommand)]
enum OpenpgpCmd {
    /// Show card status: AID/serial, key algorithms and fingerprints, PIN retry
    /// counters, and the signature counter. No PIN or touch required.
    Status {
        /// Select a reader whose name contains this substring (case-insensitive).
        /// Omit to use the only OpenPGP card, or to list choices when several exist.
        #[arg(long, value_name = "SUBSTR")]
        reader: Option<String>,
    },
    /// Verify a PIN against the card (checks it's correct; changes nothing). The
    /// PIN is read from an env var or stdin — never argv.
    Verify {
        /// Which PIN to check: `user` (PW1) or `admin` (PW3).
        #[arg(long, value_enum, default_value_t = OpenpgpPinKind::User)]
        pin: OpenpgpPinKind,
        /// Read the PIN from the named environment variable.
        #[arg(long, value_name = "VAR", conflicts_with = "pin_stdin")]
        pin_env: Option<String>,
        /// Read the PIN from stdin (one line).
        #[arg(long)]
        pin_stdin: bool,
        #[arg(long, value_name = "SUBSTR")]
        reader: Option<String>,
    },
    /// Read the public key from a slot (read-only; no PIN). RSA keys print their
    /// modulus and exponent in hex.
    PublicKey {
        /// Which key slot: `sign`, `decrypt`, or `auth`.
        #[arg(long, value_enum, default_value_t = OpenpgpSlot::Sign)]
        slot: OpenpgpSlot,
        #[arg(long, value_name = "SUBSTR")]
        reader: Option<String>,
    },
    /// Factory-reset the OpenPGP applet: wipe ALL key slots and restore default
    /// PINs (PW1 123456, PW3 12345678). DESTRUCTIVE. Requires `--yes`. Also works
    /// to recover a card whose PINs are blocked.
    Reset {
        /// Confirm you really want to wipe the OpenPGP applet.
        #[arg(long)]
        yes: bool,
        #[arg(long, value_name = "SUBSTR")]
        reader: Option<String>,
    },
    /// Set the cardholder name (PUT DATA 005B). Requires the admin PIN (PW3).
    SetName {
        /// Cardholder name to write (UTF-8). The OpenPGP convention is
        /// `Surname<<Given`, but it is stored verbatim.
        name: String,
        /// Read the admin PIN (PW3) from the named environment variable.
        #[arg(long, value_name = "VAR", conflicts_with = "admin_pin_stdin")]
        admin_pin_env: Option<String>,
        /// Read the admin PIN (PW3) from stdin (one line).
        #[arg(long)]
        admin_pin_stdin: bool,
        #[arg(long, value_name = "SUBSTR")]
        reader: Option<String>,
    },
    /// Set the public-key URL (PUT DATA 5F50). Requires the admin PIN (PW3).
    SetUrl {
        /// URL to write.
        url: String,
        /// Read the admin PIN (PW3) from the named environment variable.
        #[arg(long, value_name = "VAR", conflicts_with = "admin_pin_stdin")]
        admin_pin_env: Option<String>,
        /// Read the admin PIN (PW3) from stdin (one line).
        #[arg(long)]
        admin_pin_stdin: bool,
        #[arg(long, value_name = "SUBSTR")]
        reader: Option<String>,
    },
    /// Generate a fresh key pair in a slot. DESTRUCTIVE — overwrites any existing
    /// key in that slot. Requires the admin PIN (PW3) and `--yes`; on a YubiKey a
    /// touch is also required. Also writes the key's v4 fingerprint and a
    /// generation timestamp so an OpenPGP tool (e.g. gpg) recognizes the key.
    GenerateKey {
        /// Which key slot to (over)write: `sign`, `decrypt`, or `auth`.
        #[arg(long, value_enum, default_value_t = OpenpgpSlot::Sign)]
        slot: OpenpgpSlot,
        /// Confirm you really want to overwrite the slot.
        #[arg(long)]
        yes: bool,
        /// Read the admin PIN (PW3) from the named environment variable.
        #[arg(long, value_name = "VAR", conflicts_with = "admin_pin_stdin")]
        admin_pin_env: Option<String>,
        /// Read the admin PIN (PW3) from stdin (one line).
        #[arg(long)]
        admin_pin_stdin: bool,
        #[arg(long, value_name = "SUBSTR")]
        reader: Option<String>,
    },
    /// Import an RSA-2048 key into a slot. DESTRUCTIVE — overwrites any existing
    /// key. The key comes from either `--generate` (fresh host keygen) or `--in
    /// <FILE>` (an existing PKCS#1/PKCS#8 PEM or DER key); exactly one is
    /// required. Requires admin PIN (PW3) and `--yes`. The key is registered
    /// (fingerprint + timestamp) like generate-key.
    ImportKey {
        /// Generate a fresh RSA-2048 key on the host and import it.
        /// Mutually exclusive with `--in`.
        #[arg(long, conflicts_with = "in_file", required_unless_present = "in_file")]
        generate: bool,
        /// Import an existing RSA-2048 private key from a file (PKCS#1 or
        /// PKCS#8, PEM or DER; auto-detected). Mutually exclusive with
        /// `--generate`. The key is read locally and imported; it is never
        /// logged. Prefer an unencrypted key file you can delete afterward.
        #[arg(long = "in", value_name = "FILE", conflicts_with = "generate")]
        in_file: Option<std::path::PathBuf>,
        /// Which key slot to (over)write: `sign`, `decrypt`, or `auth`.
        #[arg(long, value_enum, default_value_t = OpenpgpSlot::Sign)]
        slot: OpenpgpSlot,
        /// Confirm you really want to overwrite the slot.
        #[arg(long)]
        yes: bool,
        /// Read the admin PIN (PW3) from the named environment variable.
        #[arg(long, value_name = "VAR", conflicts_with = "admin_pin_stdin")]
        admin_pin_env: Option<String>,
        /// Read the admin PIN (PW3) from stdin (one line).
        #[arg(long)]
        admin_pin_stdin: bool,
        #[arg(long, value_name = "SUBSTR")]
        reader: Option<String>,
    },
    /// Sign a file with the on-card signature key (PSO:CDS). Hashes the input
    /// (SHA-256 by default, or SHA-1 via `--hash`), wraps it in a PKCS#1
    /// DigestInfo, and has the card produce an RSA signature. Requires the
    /// signing PIN (PW1) and, on a YubiKey, a touch.
    Sign {
        /// File whose contents to sign.
        #[arg(long, value_name = "FILE")]
        r#in: std::path::PathBuf,
        /// Write the raw signature bytes here. Without it, the signature is
        /// printed as hex to stdout.
        #[arg(long, value_name = "FILE")]
        out: Option<std::path::PathBuf>,
        /// Read the signing PIN (PW1) from the named environment variable.
        #[arg(long, value_name = "VAR", conflicts_with = "pin_stdin")]
        pin_env: Option<String>,
        /// Read the signing PIN (PW1) from stdin (one line).
        #[arg(long)]
        pin_stdin: bool,
        /// Digest algorithm for the PKCS#1 v1.5 DigestInfo. SHA-256 is the
        /// modern default; SHA-1 is offered for interop with old verifiers.
        #[arg(long, value_enum, default_value_t = SignHash::Sha256)]
        hash: SignHash,
        #[arg(long, value_name = "SUBSTR")]
        reader: Option<String>,
    },
    /// Decrypt a file with the on-card decryption key (PSO:DECIPHER). The input
    /// is a raw RSA cryptogram — for RSA-2048, the 256-byte value produced by
    /// RSA-encrypting a PKCS#1 v1.5 block under the decryption slot's public
    /// key. The card applies the private key, strips the padding, and returns
    /// the plaintext. Requires the user PIN (PW1) and, on a YubiKey, a touch.
    Decrypt {
        /// File holding the raw RSA cryptogram to decrypt.
        #[arg(long, value_name = "FILE")]
        r#in: std::path::PathBuf,
        /// Write the recovered plaintext here. Without it, the plaintext is
        /// printed as hex to stdout.
        #[arg(long, value_name = "FILE")]
        out: Option<std::path::PathBuf>,
        /// Read the user PIN (PW1) from the named environment variable.
        #[arg(long, value_name = "VAR", conflicts_with = "pin_stdin")]
        pin_env: Option<String>,
        /// Read the user PIN (PW1) from stdin (one line).
        #[arg(long)]
        pin_stdin: bool,
        #[arg(long, value_name = "SUBSTR")]
        reader: Option<String>,
    },
    /// Produce a client/SSH authentication signature with the on-card
    /// Authentication key (INTERNAL AUTHENTICATE). Hashes the input, wraps it in
    /// a PKCS#1 DigestInfo, and has the card sign it. Requires the user PIN (PW1)
    /// and, on a YubiKey, a touch.
    Authenticate {
        /// File whose contents to authenticate-sign.
        #[arg(long, value_name = "FILE")]
        r#in: std::path::PathBuf,
        /// Write the raw signature bytes here. Without it, the signature is
        /// printed as hex to stdout.
        #[arg(long, value_name = "FILE")]
        out: Option<std::path::PathBuf>,
        /// Read the user PIN (PW1) from the named environment variable.
        #[arg(long, value_name = "VAR", conflicts_with = "pin_stdin")]
        pin_env: Option<String>,
        /// Read the user PIN (PW1) from stdin (one line).
        #[arg(long)]
        pin_stdin: bool,
        /// Digest algorithm for the PKCS#1 v1.5 DigestInfo. SHA-256 is the
        /// modern default; SHA-1 is offered for interop with old verifiers.
        #[arg(long, value_enum, default_value_t = SignHash::Sha256)]
        hash: SignHash,
        #[arg(long, value_name = "SUBSTR")]
        reader: Option<String>,
    },
    /// Change the user PIN (PW1). PINs are sourced from env vars or stdin
    /// (stdin reads two consecutive lines: old then new) — never argv.
    ChangePin {
        /// Read the old user PIN (PW1) from the named environment variable.
        #[arg(long, value_name = "VAR", conflicts_with = "old_pin_stdin")]
        old_pin_env: Option<String>,
        /// Read the old user PIN (PW1) from stdin (first line).
        #[arg(long)]
        old_pin_stdin: bool,
        /// Read the new user PIN (PW1) from the named environment variable.
        #[arg(long, value_name = "VAR", conflicts_with = "new_pin_stdin")]
        new_pin_env: Option<String>,
        /// Read the new user PIN (PW1) from stdin (second line).
        #[arg(long)]
        new_pin_stdin: bool,
        #[arg(long, value_name = "SUBSTR")]
        reader: Option<String>,
    },
    /// Change the admin PIN (PW3). PINs are sourced from env vars or stdin
    /// (stdin reads two consecutive lines: old then new) — never argv.
    ChangeAdminPin {
        /// Read the old admin PIN (PW3) from the named environment variable.
        #[arg(long, value_name = "VAR", conflicts_with = "old_pin_stdin")]
        old_pin_env: Option<String>,
        /// Read the old admin PIN (PW3) from stdin (first line).
        #[arg(long)]
        old_pin_stdin: bool,
        /// Read the new admin PIN (PW3) from the named environment variable.
        #[arg(long, value_name = "VAR", conflicts_with = "new_pin_stdin")]
        new_pin_env: Option<String>,
        /// Read the new admin PIN (PW3) from stdin (second line).
        #[arg(long)]
        new_pin_stdin: bool,
        #[arg(long, value_name = "SUBSTR")]
        reader: Option<String>,
    },
    /// Unblock the user PIN (PW1) using the admin PIN (PW3), setting a new user
    /// PIN. Recovers a card whose user PIN is blocked without a factory reset.
    /// PINs are sourced from env vars or stdin (admin then new) — never argv.
    UnblockPin {
        /// Read the admin PIN (PW3) from the named environment variable.
        #[arg(long, value_name = "VAR", conflicts_with = "admin_pin_stdin")]
        admin_pin_env: Option<String>,
        /// Read the admin PIN (PW3) from stdin (first line).
        #[arg(long)]
        admin_pin_stdin: bool,
        /// Read the new user PIN (PW1) from the named environment variable.
        #[arg(long, value_name = "VAR", conflicts_with = "new_pin_stdin")]
        new_pin_env: Option<String>,
        /// Read the new user PIN (PW1) from stdin (second line).
        #[arg(long)]
        new_pin_stdin: bool,
        #[arg(long, value_name = "SUBSTR")]
        reader: Option<String>,
    },
}

#[derive(Copy, Clone, ValueEnum)]
enum OpenpgpSlot {
    Sign,
    Decrypt,
    Auth,
}

/// Digest algorithm selectable for `openpgp sign`.
#[derive(Copy, Clone, ValueEnum)]
enum SignHash {
    Sha1,
    Sha256,
}
impl SignHash {
    /// Build the PKCS#1 v1.5 `DigestInfo` for `data` under this hash: the fixed
    /// ASN.1 prefix (RFC 8017 §9.2 / B.1) followed by the digest. The OpenPGP
    /// card wraps this in EMSA-PKCS1-v1_5 padding and applies the RSA key.
    fn digest_info(self, data: &[u8]) -> Vec<u8> {
        match self {
            SignHash::Sha1 => {
                const PREFIX: [u8; 15] = [
                    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00,
                    0x04, 0x14,
                ];
                let hash = keyroost_proto::sha1::sha1(data);
                [&PREFIX[..], &hash[..]].concat()
            }
            SignHash::Sha256 => {
                const PREFIX: [u8; 19] = [
                    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
                    0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
                ];
                let hash = keyroost_proto::sha256::sha256(data);
                [&PREFIX[..], &hash[..]].concat()
            }
        }
    }

    fn label(self) -> &'static str {
        match self {
            SignHash::Sha1 => "SHA-1",
            SignHash::Sha256 => "SHA-256",
        }
    }
}
impl OpenpgpSlot {
    fn to_crt(self) -> keyroost_openpgp::KeyCrt {
        match self {
            OpenpgpSlot::Sign => keyroost_openpgp::KeyCrt::Sign,
            OpenpgpSlot::Decrypt => keyroost_openpgp::KeyCrt::Decrypt,
            OpenpgpSlot::Auth => keyroost_openpgp::KeyCrt::Auth,
        }
    }
    fn label(self) -> &'static str {
        match self {
            OpenpgpSlot::Sign => "signature",
            OpenpgpSlot::Decrypt => "decryption",
            OpenpgpSlot::Auth => "authentication",
        }
    }
}

#[derive(Copy, Clone, ValueEnum)]
enum OpenpgpPinKind {
    /// PW1 — the user PIN (signing / decryption / authentication).
    User,
    /// PW3 — the admin PIN (card management).
    Admin,
}
impl OpenpgpPinKind {
    /// The VERIFY password-reference byte. For PW1 we use the "other" context
    /// (0x82), which authorizes decryption/auth; signing uses 0x81 but a plain
    /// "is this PIN right?" check is fine against 0x82.
    fn pw_ref(self) -> u8 {
        match self {
            OpenpgpPinKind::User => keyroost_openpgp::PW1_OTHER,
            OpenpgpPinKind::Admin => keyroost_openpgp::PW3_ADMIN,
        }
    }
    fn label(self) -> &'static str {
        match self {
            OpenpgpPinKind::User => "user (PW1)",
            OpenpgpPinKind::Admin => "admin (PW3)",
        }
    }
}

/// Subcommands for the `key-name` friendly-name registry.
#[derive(Subcommand)]
enum KeyNameCmd {
    /// Record a friendly name for a connected key. Writes the key's serial to
    /// keys.json on this computer (opt-in) so it's recognizable by name later.
    Add {
        /// Friendly label to assign, e.g. "signing-yubikey" ([a-z0-9_-]).
        name: String,
        /// Which connected key to name. Omit to auto-pick / choose interactively.
        #[arg(long, value_name = "PATH")]
        path: Option<std::path::PathBuf>,
    },
    /// List configured key names and whether each is currently connected.
    List,
    /// Remove a configured key name.
    Remove {
        /// The friendly label to remove.
        name: String,
    },
}

/// Reader selection plus the (optional) password for a protected OATH applet.
/// Flattened into each OATH subcommand so they share one access surface.
#[derive(clap::Args)]
struct OathAccess {
    /// Select a reader whose name contains this substring (case-insensitive).
    /// Omit to use the only OATH key, or to list choices when several exist.
    #[arg(long, value_name = "SUBSTR")]
    reader: Option<String>,
    /// Read the applet password from the named environment variable. Needed for
    /// password-protected applets (e.g. a YubiKey with an OATH password set).
    #[arg(long, value_name = "VAR", conflicts_with = "password_stdin")]
    password_env: Option<String>,
    /// Read the applet password from stdin (one line).
    #[arg(long)]
    password_stdin: bool,
}

impl OathAccess {
    /// Resolve the password from its env/stdin source, if one was given.
    fn password(&self) -> Result<Option<zeroize::Zeroizing<String>>, Box<dyn std::error::Error>> {
        if self.password_env.is_none() && !self.password_stdin {
            return Ok(None);
        }
        Ok(Some(read_secret(
            "OATH password",
            self.password_env.as_deref(),
            self.password_stdin,
        )?))
    }
}

/// Subcommands for OATH credentials on a security key (Yubico/Trussed applet).
#[derive(Subcommand)]
enum OathCmd {
    /// List the credentials stored on the key.
    List {
        #[command(flatten)]
        access: OathAccess,
    },
    /// Print the current TOTP code for a credential.
    Code {
        /// Credential name as stored on the key (e.g. "issuer:account").
        name: String,
        /// TOTP period in seconds.
        #[arg(long, default_value_t = 30)]
        period: u32,
        #[command(flatten)]
        access: OathAccess,
    },
    /// Add (provision) a TOTP or HOTP credential. The base32 secret is read from
    /// stdin or an env var — never argv.
    Add {
        /// Credential name to store (e.g. "issuer:account").
        name: String,
        /// Credential type: time-based (TOTP) or counter-based (HOTP).
        #[arg(long = "type", value_enum, default_value_t = OathTypeArg::Totp)]
        oath_type: OathTypeArg,
        /// Read the base32 secret from the named environment variable.
        #[arg(long, value_name = "VAR", conflicts_with = "secret_stdin")]
        secret_env: Option<String>,
        /// Read the base32 secret from stdin (one line).
        #[arg(long)]
        secret_stdin: bool,
        /// HMAC algorithm.
        #[arg(long, value_enum, default_value_t = OathAlgoArg::Sha1)]
        algorithm: OathAlgoArg,
        /// OTP digit count (6, 7, or 8).
        #[arg(long, default_value_t = 6)]
        digits: u8,
        /// Initial counter (moving factor) for HOTP credentials. Ignored for TOTP.
        #[arg(long, default_value_t = 0)]
        counter: u32,
        /// Require a touch on the key to compute this credential.
        #[arg(long)]
        touch: bool,
        #[command(flatten)]
        access: OathAccess,
    },
    /// Delete a credential by name.
    Delete {
        /// Credential name to remove.
        name: String,
        #[command(flatten)]
        access: OathAccess,
    },
    /// Set (or replace) the applet password. The new password is read from an
    /// env var or stdin — never argv. If a password is already set, supply the
    /// current one via `--password-env`/`--password-stdin` to unlock first.
    SetPassword {
        /// Read the new password from the named environment variable.
        #[arg(long, value_name = "VAR", conflicts_with = "new_password_stdin")]
        new_password_env: Option<String>,
        /// Read the new password from stdin (one line).
        #[arg(long)]
        new_password_stdin: bool,
        #[command(flatten)]
        access: OathAccess,
    },
    /// Remove the applet password. Supply the current password via
    /// `--password-env`/`--password-stdin` to unlock first.
    ClearPassword {
        #[command(flatten)]
        access: OathAccess,
    },
}

/// Molto2 customer-key selection (Molto2-scoped; was global pre-0.6.0).
#[derive(clap::Args)]
struct KeyArgs {
    /// Customer key as hex (alternative to --key-ascii). Default used if no
    /// key option is supplied. Argv is visible in `ps` and shell history;
    /// prefer --key-env for a non-default key.
    #[arg(long, global = true, value_name = "HEX")]
    key: Option<String>,
    /// Customer key as ASCII (alternative to --key). Argv is visible in `ps`
    /// and shell history; prefer --key-ascii-env for a non-default key.
    #[arg(long, global = true, value_name = "TEXT", conflicts_with = "key")]
    key_ascii: Option<String>,
    /// Read the hex customer key from the named environment variable
    /// (keeps it out of argv and shell history).
    #[arg(long, global = true, value_name = "VAR", conflicts_with_all = ["key", "key_ascii"])]
    key_env: Option<String>,
    /// Read the ASCII customer key from the named environment variable.
    #[arg(long, global = true, value_name = "VAR", conflicts_with_all = ["key", "key_ascii", "key_env"])]
    key_ascii_env: Option<String>,
}

/// Token2 single-profile programmable token subcommands. These talk to the
/// token over a PC/SC reader and authenticate with the token's fixed device key
/// (no customer key, no profile index).
#[derive(Subcommand)]
enum ProgCmd {
    /// Print device serial number and on-device UTC time. No auth needed.
    Info {
        /// Match the reader whose name contains this substring (when more than
        /// one reader is connected).
        #[arg(long, value_name = "SUBSTR")]
        reader: Option<String>,
    },
    /// Write the TOTP seed. Supply exactly one of --hex / --base32 / their
    /// -env / -stdin variants. Programs the configuration's clock too via
    /// --config-time if you also pass `config` separately.
    Seed {
        #[arg(long, value_name = "SUBSTR")]
        reader: Option<String>,
        /// Seed in hex. Argv is visible in `ps`; prefer --hex-stdin.
        #[arg(long, conflicts_with = "base32", value_name = "HEX")]
        hex: Option<String>,
        /// Seed in base32 (RFC 4648; whitespace and dashes tolerated).
        #[arg(long, value_name = "B32")]
        base32: Option<String>,
        /// Read the hex seed from the named environment variable.
        #[arg(long, value_name = "VAR")]
        hex_env: Option<String>,
        /// Read the base32 seed from the named environment variable.
        #[arg(long, value_name = "VAR")]
        base32_env: Option<String>,
        /// Read the hex seed from stdin (one line).
        #[arg(long)]
        hex_stdin: bool,
        /// Read the base32 seed from stdin (one line).
        #[arg(long)]
        base32_stdin: bool,
    },
    /// Set the device configuration and seed the clock with the host's UTC time.
    Config {
        #[arg(long, value_name = "SUBSTR")]
        reader: Option<String>,
        #[arg(long, value_enum, default_value_t = AlgoArg::Sha1)]
        algorithm: AlgoArg,
        #[arg(long, value_enum, default_value_t = StepArg::S30)]
        time_step: StepArg,
        #[arg(long, value_enum, default_value_t = TimeoutArg::S30)]
        display_timeout: TimeoutArg,
    },
}

/// Token2 Molto2 / Molto2v2 subcommands. These talk to the Molto2 PC/SC
/// reader, authenticated with the customer key (see the `--key*` flags).
#[derive(Subcommand)]
enum MoltoCmd {
    /// Print device serial number and on-device UTC time.
    Info,
    /// Write a TOTP seed to a profile slot. The seed can come from argv
    /// (--hex/--base32 — visible in `ps` and shell history), an environment
    /// variable, or stdin; supply exactly one source.
    Seed {
        /// Profile index 0..=99.
        #[arg(short, long)]
        profile: u8,
        /// Seed in hex. Argv is visible in `ps` and shell history; prefer
        /// --hex-env or --hex-stdin.
        #[arg(long, conflicts_with = "base32", value_name = "HEX")]
        hex: Option<String>,
        /// Seed in base32 (RFC 4648; whitespace and dashes tolerated). Argv
        /// is visible in `ps` and shell history; prefer --base32-env or
        /// --base32-stdin.
        #[arg(long, value_name = "B32")]
        base32: Option<String>,
        /// Read the hex seed from the named environment variable.
        #[arg(long, value_name = "VAR")]
        hex_env: Option<String>,
        /// Read the base32 seed from the named environment variable.
        #[arg(long, value_name = "VAR")]
        base32_env: Option<String>,
        /// Read the hex seed from stdin (one line).
        #[arg(long)]
        hex_stdin: bool,
        /// Read the base32 seed from stdin (one line).
        #[arg(long)]
        base32_stdin: bool,
    },
    /// Write a profile title (1..=12 ASCII chars).
    Title {
        #[arg(short, long)]
        profile: u8,
        title: String,
    },
    /// Set profile TOTP configuration (and seed the clock with the host's UTC time).
    Config {
        #[arg(short, long)]
        profile: u8,
        #[arg(long, value_enum, default_value_t = AlgoArg::Sha1)]
        algorithm: AlgoArg,
        #[arg(long, value_enum, default_value_t = DigitsArg::Six)]
        digits: DigitsArg,
        #[arg(long, value_enum, default_value_t = StepArg::S30)]
        time_step: StepArg,
        #[arg(long, value_enum, default_value_t = TimeoutArg::S30)]
        display_timeout: TimeoutArg,
    },
    /// Push the host's current UTC time to one profile (or all profiles).
    SyncTime {
        /// Sync only this profile (omit `--all`).
        #[arg(short, long, conflicts_with = "all")]
        profile: Option<u8>,
        /// Sync time on every profile 0..=99.
        #[arg(long)]
        all: bool,
    },
    /// Rotate the device's customer key (requires physical button
    /// confirmation). The new key can come from argv (--hex/--ascii —
    /// visible in `ps` and shell history), an environment variable, or
    /// stdin; supply exactly one source.
    CustomerKey {
        /// New key in hex. Argv is visible in `ps` and shell history;
        /// prefer --hex-env or --hex-stdin.
        #[arg(long, conflicts_with = "ascii", value_name = "HEX")]
        hex: Option<String>,
        /// New key as ASCII. Argv is visible in `ps` and shell history;
        /// prefer --ascii-env or --ascii-stdin.
        #[arg(long, value_name = "TEXT")]
        ascii: Option<String>,
        /// Read the new hex key from the named environment variable.
        #[arg(long, value_name = "VAR")]
        hex_env: Option<String>,
        /// Read the new ASCII key from the named environment variable.
        #[arg(long, value_name = "VAR")]
        ascii_env: Option<String>,
        /// Read the new hex key from stdin (one line).
        #[arg(long)]
        hex_stdin: bool,
        /// Read the new ASCII key from stdin (one line).
        #[arg(long)]
        ascii_stdin: bool,
    },
    /// Import an otpauth:// URI to a profile: writes seed, title, and config in one go.
    Import {
        #[arg(short, long)]
        profile: u8,
        /// Override the profile title (default: derived from URI issuer/account).
        #[arg(long)]
        title: Option<String>,
        /// Display timeout in seconds (otpauth:// has no equivalent field).
        #[arg(long, value_enum, default_value_t = TimeoutArg::S30)]
        display_timeout: TimeoutArg,
        /// Decode the otpauth:// URI from a QR code in a PNG/JPEG screenshot
        /// instead of passing it as text. For Google Authenticator export
        /// QRs (multiple accounts), use `import-file` with the image path.
        #[arg(long, value_name = "IMAGE", conflicts_with = "uri")]
        qr: Option<std::path::PathBuf>,
        /// The otpauth:// URI. Use single quotes to protect & from the shell.
        /// Argv is visible in `ps` and shell history (the URI embeds the
        /// secret); pass `-` to read the URI from stdin, or use --qr.
        uri: Option<String>,
    },
    /// Bulk-import a plaintext or encrypted export from Aegis, 2FAS, or a list
    /// of otpauth:// URIs. For encrypted Aegis vaults, pass the password via
    /// `--password-stdin` (suitable for piping from a file or password manager)
    /// or `--password-env VAR`.
    ImportFile {
        /// Path to the export file. Format is auto-detected.
        path: std::path::PathBuf,
        /// Starting profile index. Entries fill consecutive slots from here.
        #[arg(long, default_value_t = 0)]
        start: u8,
        /// Display timeout to use for every imported entry.
        #[arg(long, value_enum, default_value_t = TimeoutArg::S30)]
        display_timeout: TimeoutArg,
        /// Print what would be written, but don't touch the device.
        #[arg(long)]
        dry_run: bool,
        /// Read the vault password from stdin (single line, no trailing newline).
        #[arg(long, conflicts_with = "password_env")]
        password_stdin: bool,
        /// Read the vault password from the named environment variable.
        #[arg(long, value_name = "VAR")]
        password_env: Option<String>,
    },
    /// Sweep plausible read APDUs against the device and report what the firmware
    /// recognizes. Read-only by intent — sends short read-style requests with
    /// destructive INS bytes (set seed/title/config, factory reset, set customer
    /// key) excluded by default.
    #[command(hide = true)]
    Probe {
        /// Confirm you understand this sends ~256–512 experimental APDUs.
        #[arg(long)]
        yes: bool,
        /// Also probe the secure class (CLA 0x84) after authenticating. Without
        /// this, only CLA 0x80 is scanned (no auth needed).
        #[arg(long)]
        authed: bool,
        /// Override the safety filter and scan every INS byte 0x00..0xFF.
        /// Only useful if you've already exhausted the safe sweep.
        #[arg(long)]
        include_destructive: bool,
        /// Profile slot to use in P2 for `authed` scans (P2 is the profile index
        /// for the known secure commands). Defaults to a high, presumably-unused
        /// slot.
        #[arg(long, default_value_t = 99)]
        slot: u8,
    },
    /// Factory-reset the device. Wipes profiles and restores default customer key.
    /// Requires physical button confirmation on the device.
    Reset {
        /// Confirm you really want to wipe the device.
        #[arg(long)]
        yes: bool,
    },
}

/// FIDO2 / CTAP2 subcommands. These talk to a hidraw device, not the Molto2
/// PC/SC reader.
#[derive(Subcommand)]
enum FidoCmd {
    /// Run `authenticatorGetInfo` against a connected FIDO authenticator.
    Info {
        /// hidraw path to use. If omitted, auto-pick the only connected FIDO device.
        #[arg(long, value_name = "PATH")]
        path: Option<std::path::PathBuf>,
    },
    /// Run `authenticatorReset`, wiping all credentials on the key.
    ///
    /// Most authenticators only accept Reset within ~10s of plug-in and
    /// require a physical touch. If `--yes` is missing this is a no-op.
    Reset {
        /// Confirm you really want to wipe credentials.
        #[arg(long)]
        yes: bool,
        /// hidraw path to use. If omitted, auto-pick the only connected FIDO device.
        #[arg(long, value_name = "PATH")]
        path: Option<std::path::PathBuf>,
    },
    /// Print the current PIN retry counter.
    PinRetries {
        #[arg(long, value_name = "PATH")]
        path: Option<std::path::PathBuf>,
    },
    /// Set the initial PIN on an authenticator that doesn't have one yet.
    PinSet {
        /// Read the new PIN from the given environment variable.
        #[arg(long, value_name = "VAR", conflicts_with = "new_pin_stdin")]
        new_pin_env: Option<String>,
        /// Read the new PIN from stdin (one line, trailing newline stripped).
        #[arg(long)]
        new_pin_stdin: bool,
        #[arg(long, value_name = "PATH")]
        path: Option<std::path::PathBuf>,
    },
    /// Change the existing PIN. Old and new PINs are sourced from env vars
    /// or stdin (stdin reads two consecutive lines: old then new).
    PinChange {
        #[arg(long, value_name = "VAR", conflicts_with = "old_pin_stdin")]
        old_pin_env: Option<String>,
        #[arg(long)]
        old_pin_stdin: bool,
        #[arg(long, value_name = "VAR", conflicts_with = "new_pin_stdin")]
        new_pin_env: Option<String>,
        #[arg(long)]
        new_pin_stdin: bool,
        #[arg(long, value_name = "PATH")]
        path: Option<std::path::PathBuf>,
    },
    /// Show resident-credential storage stats (uses pinUvAuthToken).
    CredsMetadata {
        #[arg(long, value_name = "VAR", conflicts_with = "pin_stdin")]
        pin_env: Option<String>,
        #[arg(long)]
        pin_stdin: bool,
        #[arg(long, value_name = "PATH")]
        path: Option<std::path::PathBuf>,
    },
    /// List every resident credential on the authenticator, grouped by RP.
    CredsList {
        #[arg(long, value_name = "VAR", conflicts_with = "pin_stdin")]
        pin_env: Option<String>,
        #[arg(long)]
        pin_stdin: bool,
        #[arg(long, value_name = "PATH")]
        path: Option<std::path::PathBuf>,
    },
    /// Delete a single resident credential by its hex-encoded credentialId.
    CredsDelete {
        /// Hex-encoded credentialId as printed by `fido creds-list`.
        #[arg(long, value_name = "HEX")]
        cred_id: String,
        #[arg(long, value_name = "VAR", conflicts_with = "pin_stdin")]
        pin_env: Option<String>,
        #[arg(long)]
        pin_stdin: bool,
        #[arg(long, value_name = "PATH")]
        path: Option<std::path::PathBuf>,
    },
    /// List enrolled fingerprints (template id + name).
    FingerprintList {
        #[arg(long, value_name = "VAR", conflicts_with = "pin_stdin")]
        pin_env: Option<String>,
        #[arg(long)]
        pin_stdin: bool,
        #[arg(long, value_name = "PATH")]
        path: Option<std::path::PathBuf>,
    },
    /// Enroll a new fingerprint. Touch the sensor repeatedly when prompted until
    /// capture completes.
    FingerprintEnroll {
        /// Optional friendly name to set on the new fingerprint once enrolled.
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
        #[arg(long, value_name = "VAR", conflicts_with = "pin_stdin")]
        pin_env: Option<String>,
        #[arg(long)]
        pin_stdin: bool,
        #[arg(long, value_name = "PATH")]
        path: Option<std::path::PathBuf>,
    },
    /// Rename an enrolled fingerprint by its hex template id (from `list`).
    FingerprintRename {
        /// Hex-encoded template id as printed by `fido fingerprint-list`.
        #[arg(long, value_name = "HEX")]
        template_id: String,
        /// New friendly name.
        #[arg(long, value_name = "NAME")]
        name: String,
        #[arg(long, value_name = "VAR", conflicts_with = "pin_stdin")]
        pin_env: Option<String>,
        #[arg(long)]
        pin_stdin: bool,
        #[arg(long, value_name = "PATH")]
        path: Option<std::path::PathBuf>,
    },
    /// Delete an enrolled fingerprint by its hex template id (from `list`).
    FingerprintDelete {
        /// Hex-encoded template id as printed by `fido fingerprint-list`.
        #[arg(long, value_name = "HEX")]
        template_id: String,
        #[arg(long, value_name = "VAR", conflicts_with = "pin_stdin")]
        pin_env: Option<String>,
        #[arg(long)]
        pin_stdin: bool,
        #[arg(long, value_name = "PATH")]
        path: Option<std::path::PathBuf>,
    },
    /// Turn "always require user verification" (alwaysUv) on or off. This is a
    /// toggle relative to the key's current state; run `info` to check it.
    AlwaysUv {
        #[arg(long, value_name = "VAR", conflicts_with = "pin_stdin")]
        pin_env: Option<String>,
        #[arg(long)]
        pin_stdin: bool,
        #[arg(long, value_name = "PATH")]
        path: Option<std::path::PathBuf>,
    },
    /// Raise the minimum PIN length. The value can only be increased, never
    /// lowered (a reset is required to lower it), and may force a PIN change.
    SetMinPin {
        /// New minimum PIN length (in code points). Must be >= the current one.
        #[arg(long, value_name = "N")]
        length: u32,
        /// Also require the user to change the PIN on next use.
        #[arg(long)]
        force_change: bool,
        #[arg(long, value_name = "VAR", conflicts_with = "pin_stdin")]
        pin_env: Option<String>,
        #[arg(long)]
        pin_stdin: bool,
        #[arg(long, value_name = "PATH")]
        path: Option<std::path::PathBuf>,
    },
    /// Force a PIN change on next use, without changing the minimum length.
    ForcePinChange {
        #[arg(long, value_name = "VAR", conflicts_with = "pin_stdin")]
        pin_env: Option<String>,
        #[arg(long)]
        pin_stdin: bool,
        #[arg(long, value_name = "PATH")]
        path: Option<std::path::PathBuf>,
    },
    /// Enable enterprise attestation. This is typically one-way: disabling it
    /// again requires a device reset.
    EnterpriseAttestation {
        #[arg(long, value_name = "VAR", conflicts_with = "pin_stdin")]
        pin_env: Option<String>,
        #[arg(long)]
        pin_stdin: bool,
        #[arg(long, value_name = "PATH")]
        path: Option<std::path::PathBuf>,
    },
    /// Read and manage the FIDO2 large-blob array (the key's small shared store).
    ///
    /// IMPORTANT: the large-blob store is WORLD-READABLE without a PIN — any
    /// software with access to the key can read every entry. It is a convenience
    /// scratchpad, NOT a place for secrets. Relying parties (e.g. an SSH cert
    /// flow) may also keep their own encrypted entries here; keyroost never
    /// rewrites or deletes those without an explicit `--yes`.
    LargeBlob {
        #[command(subcommand)]
        cmd: LargeBlobCmd,
    },
}

/// Subcommands for the FIDO2 large-blob array.
///
/// keyroost stores its own entries as plaintext "notes" (a small magic prefix
/// marks them); relying parties store opaque AEAD-encrypted records keyroost
/// cannot read. Reads need no PIN (the store is world-readable); writes pull a
/// `largeBlobWrite` token from your PIN. Every write re-reads the live array
/// first so existing RP entries are never clobbered by stale state.
#[derive(Subcommand)]
enum LargeBlobCmd {
    /// List every entry: index, size, type (note vs opaque), and a short preview.
    List {
        #[arg(long, value_name = "PATH")]
        path: Option<std::path::PathBuf>,
    },
    /// Show one entry in full by its index (from `list`).
    Get {
        /// Zero-based entry index as printed by `large-blob list`.
        index: usize,
        #[arg(long, value_name = "PATH")]
        path: Option<std::path::PathBuf>,
    },
    /// Append a keyroost text note.
    ///
    /// IMPORTANT: the large-blob store is world-readable WITHOUT a PIN — do not
    /// put secrets here. TEXT is passed on the command line, so it is visible to
    /// other local processes (e.g. via the process list) while this runs.
    Add {
        /// The note text to store (plain UTF-8). Visible in argv to other
        /// local processes — never a secret.
        text: String,
        #[arg(long, value_name = "VAR", conflicts_with = "pin_stdin")]
        pin_env: Option<String>,
        #[arg(long)]
        pin_stdin: bool,
        #[arg(long, value_name = "PATH")]
        path: Option<std::path::PathBuf>,
    },
    /// Replace the text of an existing keyroost note by its index.
    ///
    /// Refuses to touch opaque RP-encrypted entries.
    Edit {
        /// Zero-based entry index as printed by `large-blob list`.
        index: usize,
        /// The new note text (plain UTF-8). Visible in argv to other processes.
        text: String,
        #[arg(long, value_name = "VAR", conflicts_with = "pin_stdin")]
        pin_env: Option<String>,
        #[arg(long)]
        pin_stdin: bool,
        #[arg(long, value_name = "PATH")]
        path: Option<std::path::PathBuf>,
    },
    /// Delete a single entry by its index.
    ///
    /// Deleting an opaque (RP-owned) entry may break a service that stored it,
    /// so that case requires `--yes`.
    Delete {
        /// Zero-based entry index as printed by `large-blob list`.
        index: usize,
        /// Confirm the deletion (required for opaque RP-owned entries).
        #[arg(long)]
        yes: bool,
        #[arg(long, value_name = "VAR", conflicts_with = "pin_stdin")]
        pin_env: Option<String>,
        #[arg(long)]
        pin_stdin: bool,
        #[arg(long, value_name = "PATH")]
        path: Option<std::path::PathBuf>,
    },
    /// Erase the ENTIRE large-blob array, including any RP-owned entries.
    Clear {
        /// Confirm wiping every entry (required).
        #[arg(long)]
        yes: bool,
        #[arg(long, value_name = "VAR", conflicts_with = "pin_stdin")]
        pin_env: Option<String>,
        #[arg(long)]
        pin_stdin: bool,
        #[arg(long, value_name = "PATH")]
        path: Option<std::path::PathBuf>,
    },
}

/// Subcommands for the Token2 on-device OTP applet (T2F2 / PIN+) over USB-HID
/// or NFC. Seeds are read from stdin or an env var — never argv.
#[derive(Subcommand)]
enum OtpCmd {
    /// List the OTP entries stored on the key, with their live codes where the
    /// device returns them (TOTP without button-press).
    List,
    /// Print the current code for one entry, identified by app and account.
    /// A button-required entry will prompt for a touch.
    Get {
        /// Application/issuer name as stored (may be empty).
        #[arg(long, default_value = "")]
        app: String,
        /// Account name as stored.
        #[arg(long)]
        account: String,
    },
    /// Add (or overwrite) an OTP entry. The base32 seed is read from stdin or an
    /// env var — never argv.
    Add {
        /// Application/issuer name (0..=64 ASCII chars; may be empty).
        #[arg(long, default_value = "")]
        app: String,
        /// Account name (1..=64 ASCII chars).
        #[arg(long)]
        account: String,
        /// Entry type: time-based (TOTP) or counter-based (HOTP).
        #[arg(long = "type", value_enum, default_value_t = OtpTypeArg::Totp)]
        otp_type: OtpTypeArg,
        /// HMAC algorithm.
        #[arg(long, value_enum, default_value_t = OtpAlgoArg::Sha1)]
        algorithm: OtpAlgoArg,
        /// Code length in digits (4..=10).
        #[arg(long, default_value_t = 6)]
        digits: u8,
        /// TOTP time step in seconds (ignored for HOTP).
        #[arg(long, default_value_t = 30)]
        period: u16,
        /// Require a button press on the key to emit this code.
        #[arg(long)]
        touch: bool,
        /// Read the base32 seed from the named environment variable.
        #[arg(long, value_name = "VAR", conflicts_with = "seed_stdin")]
        seed_env: Option<String>,
        /// Read the base32 seed from stdin (one line).
        #[arg(long)]
        seed_stdin: bool,
    },
    /// Delete one OTP entry by app and account.
    Delete {
        /// Application/issuer name as stored (may be empty).
        #[arg(long, default_value = "")]
        app: String,
        /// Account name as stored.
        #[arg(long)]
        account: String,
    },
    /// Erase every OTP entry on the key. Requires a confirming button press and
    /// the `--yes` acknowledgement.
    EraseAll {
        /// Acknowledge that this wipes all on-device OTP entries.
        #[arg(long)]
        yes: bool,
    },
    /// Read the device serial number (over USB, or NFC where the model allows).
    Serial,
    /// Configure the single HOTP-on-button keystroke slot: the key types this
    /// code when touched outside a session. The base32 seed is read from stdin
    /// or an env var — never argv.
    ButtonHotp {
        /// Code length — must be 6 or 8.
        #[arg(long, default_value_t = 6)]
        digits: u8,
        /// Suppress the trailing Enter keystroke after typing the code.
        #[arg(long)]
        no_enter: bool,
        /// Require a 2-second long touch (else a short tap triggers it).
        #[arg(long)]
        long_touch: bool,
        /// Type the digits using the numeric-keypad scancodes.
        #[arg(long)]
        numpad: bool,
        /// Read the base32 seed from the named environment variable.
        #[arg(long, value_name = "VAR", conflicts_with = "seed_stdin")]
        seed_env: Option<String>,
        /// Read the base32 seed from stdin (one line).
        #[arg(long)]
        seed_stdin: bool,
    },
    /// Delete the HOTP-on-button keystroke slot.
    DeleteButtonHotp,
    /// Enable or disable the key's USB interfaces (FIDO / keyboard-HID / CCID)
    /// via SET_DEVICE_TYPE.
    ///
    /// You name the interfaces to ENABLE; any not named are disabled. At least
    /// TWO must remain enabled: disabling all of them bricks the key, and leaving
    /// only one risks locking you out, so the tool refuses fewer than two. This
    /// reconfigures the hardware and requires typing a confirmation phrase.
    /// Read and print the device configuration (interface states, capabilities).
    /// Useful for diagnosing why the GUI's keyboard toggle or Touch HOTP gating
    /// behaves as it does.
    Config,
    Interface {
        /// Enable the FIDO2/U2F interface.
        #[arg(long)]
        fido: bool,
        /// Enable the keyboard-HID interface (needed for HOTP-on-touch keystroke).
        #[arg(long)]
        keyboard: bool,
        /// Enable the CCID/smart-card interface (PIV, OpenPGP, OTP over PC/SC).
        #[arg(long)]
        ccid: bool,
        /// Skip the interactive confirmation (still refuses to disable all).
        #[arg(long)]
        yes: bool,
    },
}

/// Transport selector for the `otp` command group.
#[derive(Copy, Clone, ValueEnum)]
enum OtpTransportArg {
    /// USB-HID first, fall back to CCID/NFC if HID is disabled on the key.
    Auto,
    /// Force USB-HID.
    Hid,
    /// Force CCID / NFC (PC/SC reader).
    Ccid,
}

#[derive(Copy, Clone, ValueEnum)]
enum OtpTypeArg {
    Totp,
    Hotp,
}
impl OtpTypeArg {
    fn to_t2(self) -> keyroost_token2otp::OtpType {
        match self {
            OtpTypeArg::Totp => keyroost_token2otp::OtpType::Totp,
            OtpTypeArg::Hotp => keyroost_token2otp::OtpType::Hotp,
        }
    }
}

#[derive(Copy, Clone, ValueEnum)]
enum OtpAlgoArg {
    Sha1,
    Sha256,
}
impl OtpAlgoArg {
    fn to_t2(self) -> keyroost_token2otp::Algorithm {
        match self {
            OtpAlgoArg::Sha1 => keyroost_token2otp::Algorithm::Sha1,
            OtpAlgoArg::Sha256 => keyroost_token2otp::Algorithm::Sha256,
        }
    }
}

#[derive(Copy, Clone, ValueEnum)]
enum OathTypeArg {
    Totp,
    Hotp,
}
impl OathTypeArg {
    fn to_oath(self) -> keyroost_oath::OathType {
        match self {
            OathTypeArg::Totp => keyroost_oath::OathType::Totp,
            OathTypeArg::Hotp => keyroost_oath::OathType::Hotp,
        }
    }
}

#[derive(Copy, Clone, ValueEnum)]
enum OathAlgoArg {
    Sha1,
    Sha256,
    Sha512,
}
impl OathAlgoArg {
    fn to_oath(self) -> keyroost_oath::Algorithm {
        match self {
            OathAlgoArg::Sha1 => keyroost_oath::Algorithm::Sha1,
            OathAlgoArg::Sha256 => keyroost_oath::Algorithm::Sha256,
            OathAlgoArg::Sha512 => keyroost_oath::Algorithm::Sha512,
        }
    }
}

#[derive(Copy, Clone, ValueEnum)]
enum AlgoArg {
    Sha1,
    Sha256,
}
impl AlgoArg {
    fn to_proto(self) -> HmacAlgo {
        match self {
            AlgoArg::Sha1 => HmacAlgo::Sha1,
            AlgoArg::Sha256 => HmacAlgo::Sha256,
        }
    }
}

#[derive(Copy, Clone, ValueEnum)]
enum DigitsArg {
    #[value(name = "4")]
    Four,
    #[value(name = "6")]
    Six,
    #[value(name = "8")]
    Eight,
    #[value(name = "10")]
    Ten,
}
impl DigitsArg {
    fn to_proto(self) -> OtpDigits {
        match self {
            DigitsArg::Four => OtpDigits::Four,
            DigitsArg::Six => OtpDigits::Six,
            DigitsArg::Eight => OtpDigits::Eight,
            DigitsArg::Ten => OtpDigits::Ten,
        }
    }
}

#[derive(Copy, Clone, ValueEnum)]
enum StepArg {
    #[value(name = "30")]
    S30,
    #[value(name = "60")]
    S60,
}
impl StepArg {
    fn to_proto(self) -> TimeStep {
        match self {
            StepArg::S30 => TimeStep::Seconds30,
            StepArg::S60 => TimeStep::Seconds60,
        }
    }
}

#[derive(Copy, Clone, ValueEnum)]
enum TimeoutArg {
    #[value(name = "15")]
    S15,
    #[value(name = "30")]
    S30,
    #[value(name = "60")]
    S60,
    #[value(name = "120")]
    S120,
}
impl TimeoutArg {
    fn to_proto(self) -> DisplayTimeout {
        match self {
            TimeoutArg::S15 => DisplayTimeout::Sec15,
            TimeoutArg::S30 => DisplayTimeout::Sec30,
            TimeoutArg::S60 => DisplayTimeout::Sec60,
            TimeoutArg::S120 => DisplayTimeout::Sec120,
        }
    }
}

fn customer_key_bytes(args: &KeyArgs) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    use zeroize::Zeroizing;
    if let Some(h) = &args.key {
        hex_decode(h)
            .map(Zeroizing::new)
            .map_err(|e| format!("invalid --key hex: {}", e))
    } else if let Some(s) = &args.key_ascii {
        Ok(Zeroizing::new(s.as_bytes().to_vec()))
    } else if let Some(var) = &args.key_env {
        let h = Zeroizing::new(
            std::env::var(var).map_err(|_| format!("env var {} (--key-env) is not set", var))?,
        );
        hex_decode(&h)
            .map(Zeroizing::new)
            .map_err(|e| format!("invalid hex in --key-env {}: {}", var, e))
    } else if let Some(var) = &args.key_ascii_env {
        std::env::var(var)
            .map(|s| Zeroizing::new(s.into_bytes()))
            .map_err(|_| format!("env var {} (--key-ascii-env) is not set", var))
    } else {
        Ok(Zeroizing::new(DEFAULT_CUSTOMER_KEY.to_vec()))
    }
}

fn unix_now() -> u32 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as u32,
        Err(_) => {
            // A pre-1970 clock would otherwise silently program time 0 into
            // the device (configure / sync-time / key registration).
            eprintln!("warning: system clock reads before 1970; using time 0");
            0
        }
    }
}

/// Load a bulk-import file, transparently decrypting an Aegis encrypted
/// vault if `--password-stdin` or `--password-env` was supplied.
fn load_bulk_entries(
    path: &std::path::Path,
    password_stdin: bool,
    password_env: Option<&str>,
) -> Result<Vec<keyroost_import::BulkEntry>, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {}: {}", path.display(), e))?;

    // Screenshot import: a PNG/JPEG (by magic bytes) goes through QR decode,
    // accepting both a single otpauth:// enrollment code and a Google
    // Authenticator export batch.
    if keyroost_qr::looks_like_image(&bytes) {
        let import = keyroost_qr::entries_from_image(&bytes)?;
        for s in &import.skipped {
            eprintln!("skipped {:?}: {}", s.label, s.reason);
        }
        if let Some((i, n)) = import.batch {
            eprintln!(
                "note: this is QR {} of {} in the export — import the other images too",
                i + 1,
                n
            );
        }
        eprintln!("remember to delete the screenshot after a successful import");
        return Ok(import.entries);
    }

    let text = String::from_utf8(bytes).map_err(|_| {
        format!(
            "{}: neither a text export nor a PNG/JPEG image",
            path.display()
        )
    })?;

    // Aegis vaults are the only format we know how to decrypt. Detect first
    // so we only consume the password when it would actually be used.
    let aegis_encrypted = keyroost_import::aegis::is_encrypted(&text).unwrap_or(false);

    if aegis_encrypted {
        let password = read_password(password_stdin, password_env)
            .ok_or("Aegis vault is encrypted; supply --password-stdin or --password-env VAR")?;
        let plaintext = keyroost_import::aegis::decrypt(&text, password.as_bytes())?;
        return Ok(keyroost_import::aegis::parse(&plaintext)?);
    }

    if password_stdin || password_env.is_some() {
        eprintln!("warning: password supplied but file is not an encrypted Aegis vault");
    }
    Ok(keyroost_import::parse_bulk_any(&text)?)
}

fn read_password(stdin: bool, env_var: Option<&str>) -> Option<zeroize::Zeroizing<String>> {
    if let Some(name) = env_var {
        return std::env::var(name).ok().map(zeroize::Zeroizing::new);
    }
    if stdin {
        let mut s = zeroize::Zeroizing::new(String::new());
        if std::io::Read::read_to_string(&mut std::io::stdin(), &mut s).is_err() {
            return None;
        }
        // Trim a single trailing newline (common when piping `echo`); preserve
        // intentional whitespace elsewhere.
        if s.ends_with('\n') {
            s.pop();
            if s.ends_with('\r') {
                s.pop();
            }
        }
        return Some(s);
    }
    None
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    // Capture --name once so resolve_fido_path() can honor it without threading
    // it through every FIDO subcommand handler.
    let _ = SELECTED_KEY_NAME.set(cli.name.clone());
    let _ = JSON_OUTPUT.set(cli.json);

    if cli.list_readers {
        for r in Session::list_readers()? {
            println!("{}", r);
        }
        return Ok(());
    }

    let Some(cmd) = cli.command.as_ref() else {
        // No subcommand → the friendly correlated overview of every connected
        // device. (The Molto2 serial/clock still lives under `molto info`.)
        let devices = keyroost_resolve::enumerate()?;
        if json_output() {
            use keyroost_resolve::DeviceKind;
            let out: Vec<json_out::DeviceJson> = devices
                .iter()
                .map(|d| json_out::DeviceJson {
                    vendor: d.vendor.clone(),
                    model: d.model.clone(),
                    name: d.name.clone(),
                    serial: d.serial.clone(),
                    transport: d.transport.clone(),
                    kind: match d.kind {
                        DeviceKind::Key => "key",
                        DeviceKind::Token => "token",
                        DeviceKind::ProgToken => "prog-token",
                    },
                    caps: d.cap_badges(),
                })
                .collect();
            emit_json(&out)?;
            return Ok(());
        }
        overview::print_overview(&devices);
        return Ok(());
    };

    // Pure-output subcommands: no device, no session.
    if let Cmd::Completions { shell } = cmd {
        use clap::CommandFactory;
        let mut c = Cli::command();
        clap_complete::generate(*shell, &mut c, "keyroostctl", &mut std::io::stdout());
        return Ok(());
    }
    if let Cmd::Manpage { dir } = cmd {
        use clap::CommandFactory;
        std::fs::create_dir_all(dir)?;
        let top = Cli::command();
        let render =
            |c: &clap::Command, file: &std::path::Path| -> Result<(), Box<dyn std::error::Error>> {
                let mut buf = Vec::new();
                clap_mangen::Man::new(c.clone()).render(&mut buf)?;
                std::fs::write(file, buf)?;
                Ok(())
            };
        render(&top, &dir.join("keyroostctl.1"))?;
        for sub in top.get_subcommands() {
            let name = format!("keyroostctl-{}.1", sub.get_name());
            render(sub, &dir.join(name))?;
        }
        eprintln!("wrote man pages to {}", dir.display());
        return Ok(());
    }
    if let Cmd::Doctor = cmd {
        run_doctor();
        return Ok(());
    }

    // List touches neither PC/SC card state nor any HID device — just enumerates.
    if let Cmd::List { all_hid } = cmd {
        run_list(*all_hid)?;
        return Ok(());
    }

    // Friendly-name registry management (reads HID enumeration; opt-in writes).
    if let Cmd::KeyName { cmd } = cmd {
        run_key_name(cmd)?;
        return Ok(());
    }

    // FIDO commands talk to a hidraw device, not the Molto2 PC/SC reader.
    if let Cmd::Fido { cmd } = cmd {
        return run_fido(cmd, cli.debug);
    }

    // OATH talks to a security key's CCID applet over PC/SC, not the Molto2.
    if let Cmd::Oath { cmd } = cmd {
        run_oath(cmd, cli.debug)?;
        return Ok(());
    }

    // OpenPGP likewise talks to a security key's CCID applet over PC/SC.
    if let Cmd::Openpgp { cmd } = cmd {
        run_openpgp(cmd, cli.debug)?;
        return Ok(());
    }

    // PIV is another CCID applet reached over PC/SC.
    if let Cmd::Piv { cmd } = cmd {
        run_piv(cmd, cli.debug)?;
        return Ok(());
    }

    // Token2 on-device OTP talks to the FIDO key's OTP applet over USB-HID
    // (with a PC/SC fallback), not the Molto2 — handle it before the Molto2
    // PC/SC auth flow below.
    if let Cmd::Otp { cmd, transport } = cmd {
        run_otp(cmd, *transport, cli.debug)?;
        return Ok(());
    }

    // Token2 Molto2 / Molto2v2 commands all talk to the Molto2 PC/SC reader,
    // authenticated with the customer key (scoped to this group via --key*).
    if let Cmd::Molto { key, cmd } = cmd {
        return run_molto(cmd, key, cli.debug);
    }

    if let Cmd::Prog { cmd } = cmd {
        return run_prog(cmd, cli.debug);
    }

    unreachable!("every subcommand is handled above");
}

/// Dispatch the Token2 Molto2 / Molto2v2 subcommands. The customer key comes
/// from the Molto2-scoped `--key*` flags (`KeyArgs`), not a global flag.
fn run_molto(cmd: &MoltoCmd, key: &KeyArgs, debug: bool) -> Result<(), Box<dyn std::error::Error>> {
    // --dry-run on bulk import doesn't need the device at all.
    if let MoltoCmd::ImportFile {
        path,
        start,
        display_timeout: _,
        dry_run: true,
        password_stdin,
        password_env,
    } = cmd
    {
        let entries = load_bulk_entries(path, *password_stdin, password_env.as_deref())?;
        let last = (*start as usize).saturating_add(entries.len());
        println!(
            "found {} entries; would fill slots #{}..#{} (dry-run)",
            entries.len(),
            start,
            last.saturating_sub(1)
        );
        for (i, entry) in entries.iter().enumerate() {
            let p = *start as usize + i;
            println!(
                "  #{:02}: {:?} ({} bytes, {:?}, {} digits, {:?})",
                p,
                entry.suggested_title(),
                entry.secret.len(),
                entry.algorithm,
                entry.digits as u8,
                entry.time_step
            );
        }
        return Ok(());
    }

    // Info is read-only and needs no auth — mirrors the bare-invocation path.
    if let MoltoCmd::Info = cmd {
        let mut session = Session::open()?;
        session.set_debug(debug);
        let info = session.read_info()?;
        if json_output() {
            emit_json(&json_out::MoltoInfoJson {
                serial: info.serial.clone(),
                utc: info.utc_time,
                drift_seconds: i64::from(info.utc_time) - i64::from(unix_now()),
            })?;
            return Ok(());
        }
        print_info(&info);
        return Ok(());
    }

    // Factory reset is a plain CLA 0x80 command and needs no auth. Read the
    // (read-only) device info before the --yes gate so even the refusal names
    // exactly which device would be wiped.
    if let MoltoCmd::Reset { yes } = cmd {
        let mut session = Session::open()?;
        session.set_debug(debug);
        let info = session.read_info()?;
        print_info(&info);
        if !yes {
            return Err(format!(
                "refusing to factory-reset device serial {} without --yes",
                info.serial
            )
            .into());
        }
        println!("requesting factory reset; confirm with the up-arrow button on the device");
        session.factory_reset()?;
        return Ok(());
    }

    // Probe walks unauth (and optionally auth) APDU space; it doesn't fit the
    // standard "open → auth → run command" flow because each transmission is
    // expected to fail with a non-9000 SW.
    if let MoltoCmd::Probe {
        yes,
        authed,
        include_destructive,
        slot,
    } = cmd
    {
        if !yes {
            return Err(
                "refusing to probe without --yes (see `keyroostctl molto probe --help`)".into(),
            );
        }
        let mut session = Session::open()?;
        session.set_debug(debug);
        let info = session.read_info()?;
        print_info(&info);
        if *authed {
            let key = customer_key_bytes(key)?;
            match session.authenticate(&key) {
                Ok(()) => println!("authenticated"),
                Err(TransportError::AuthFailed { tries_remaining }) => {
                    return Err(format!(
                        "authentication failed (wrong customer key); {} attempt(s) left",
                        tries_remaining
                    )
                    .into());
                }
                Err(e) => return Err(e.into()),
            }
        }
        run_probe(&mut session, *authed, *include_destructive, *slot);
        return Ok(());
    }

    let key = customer_key_bytes(key)?;
    // Wire confidentiality for seeds is SM4 keyed off the customer key, and
    // the factory default is public (it ships in every unit and in this
    // source). Programming real seeds under it means anyone holding a USB
    // capture can decrypt them — nudge, don't block.
    if key.as_slice() == DEFAULT_CUSTOMER_KEY
        && matches!(
            cmd,
            MoltoCmd::Seed { .. } | MoltoCmd::Import { .. } | MoltoCmd::ImportFile { .. }
        )
    {
        eprintln!(
            "warning: using the factory-default customer key — seeds sent to the \
             device are decryptable by anyone who captures the USB traffic. \
             Rotate it first: keyroostctl molto customer-key (see --help)."
        );
    }
    let mut session = Session::open()?;
    session.set_debug(debug);
    let info = session.read_info()?;
    print_info(&info);
    match session.authenticate(&key) {
        Ok(()) => println!("authenticated"),
        Err(TransportError::AuthFailed { tries_remaining }) => {
            return Err(format!(
                "authentication failed (wrong customer key); {} attempt(s) left",
                tries_remaining
            )
            .into());
        }
        Err(e) => return Err(e.into()),
    }

    match cmd {
        MoltoCmd::Info => unreachable!("handled above before auth"),
        MoltoCmd::Seed {
            profile,
            hex,
            base32,
            hex_env,
            base32_env,
            hex_stdin,
            base32_stdin,
        } => {
            let mut supplied = Vec::new();
            if let Some(h) = hex {
                supplied.push((SecretEncoding::Hex, SecretSource::Literal(h)));
            }
            if let Some(b) = base32 {
                supplied.push((SecretEncoding::Base32, SecretSource::Literal(b)));
            }
            if let Some(v) = hex_env {
                supplied.push((SecretEncoding::Hex, SecretSource::Env(v)));
            }
            if let Some(v) = base32_env {
                supplied.push((SecretEncoding::Base32, SecretSource::Env(v)));
            }
            if *hex_stdin {
                supplied.push((SecretEncoding::Hex, SecretSource::Stdin));
            }
            if *base32_stdin {
                supplied.push((SecretEncoding::Base32, SecretSource::Stdin));
            }
            let seed = gather_secret(
                "set-seed",
                "--hex, --base32, --hex-env, --base32-env, --hex-stdin, --base32-stdin",
                supplied,
            )?;
            if seed.is_empty() || seed.len() > 63 {
                return Err(format!("seed must be 1..=63 bytes, got {}", seed.len()).into());
            }
            session.set_seed(*profile, &seed)?;
            println!("seed written to profile #{}", profile);
        }
        MoltoCmd::Title { profile, title } => {
            if title.is_empty() || title.len() > 12 {
                return Err("title must be 1..=12 bytes".into());
            }
            session.set_title(*profile, title)?;
            println!("title set on profile #{}", profile);
        }
        MoltoCmd::Config {
            profile,
            algorithm,
            digits,
            time_step,
            display_timeout,
        } => {
            let cfg = ProfileConfig {
                display_timeout: display_timeout.to_proto(),
                algorithm: algorithm.to_proto(),
                digits: digits.to_proto(),
                time_step: time_step.to_proto(),
                utc_time: unix_now(),
            };
            session.set_config(*profile, &cfg)?;
            println!("profile #{} configured", profile);
        }
        MoltoCmd::SyncTime { profile, all } => {
            if *all {
                for p in 0..=99u8 {
                    match session.sync_time(p, unix_now()) {
                        Ok(()) => println!("synced profile #{}", p),
                        Err(e) => eprintln!("profile #{} failed: {}", p, e),
                    }
                }
            } else if let Some(p) = profile {
                session.sync_time(*p, unix_now())?;
                println!("time synced on profile #{}", p);
            } else {
                return Err("sync-time requires --profile <N> or --all".into());
            }
        }
        MoltoCmd::CustomerKey {
            hex,
            ascii,
            hex_env,
            ascii_env,
            hex_stdin,
            ascii_stdin,
        } => {
            let mut supplied = Vec::new();
            if let Some(h) = hex {
                supplied.push((SecretEncoding::Hex, SecretSource::Literal(h)));
            }
            if let Some(a) = ascii {
                supplied.push((SecretEncoding::Ascii, SecretSource::Literal(a)));
            }
            if let Some(v) = hex_env {
                supplied.push((SecretEncoding::Hex, SecretSource::Env(v)));
            }
            if let Some(v) = ascii_env {
                supplied.push((SecretEncoding::Ascii, SecretSource::Env(v)));
            }
            if *hex_stdin {
                supplied.push((SecretEncoding::Hex, SecretSource::Stdin));
            }
            if *ascii_stdin {
                supplied.push((SecretEncoding::Ascii, SecretSource::Stdin));
            }
            let new_key = gather_secret(
                "set-customer-key",
                "--hex, --ascii, --hex-env, --ascii-env, --hex-stdin, --ascii-stdin",
                supplied,
            )?;
            session.set_customer_key(&new_key)?;
            println!("customer-key rotation requested. Press the up-arrow button on the device to confirm.");
        }
        MoltoCmd::Import {
            profile,
            title,
            display_timeout,
            qr,
            uri,
        } => {
            let entry: keyroost_import::BulkEntry = if let Some(image_path) = qr {
                // Screenshot import: decode the QR, route through the same
                // hardened parsers as text input.
                let bytes = std::fs::read(image_path)
                    .map_err(|e| format!("read {}: {}", image_path.display(), e))?;
                let import = keyroost_qr::entries_from_image(&bytes)?;
                for s in &import.skipped {
                    eprintln!("skipped {:?}: {}", s.label, s.reason);
                }
                // A GA export can span several QR images; a clean single-slot
                // import of QR 1 must not read as "migration complete".
                if let Some((i, n)) = import.batch {
                    eprintln!(
                        "note: this is QR {} of {} in the export — import the other images too",
                        i + 1,
                        n
                    );
                }
                match import.entries.len() {
                    0 => {
                        return Err(
                            "QR decoded, but no account could be imported (see skips above)".into(),
                        )
                    }
                    1 => import.entries.into_iter().next().unwrap(),
                    n => {
                        return Err(format!(
                            "QR contains {} accounts — use `import-file {}` to program them \
                             into consecutive slots",
                            n,
                            image_path.display()
                        )
                        .into())
                    }
                }
            } else {
                let uri = match uri.as_deref() {
                    // `-` reads the URI (whose secret= parameter is the seed)
                    // from stdin so it stays out of /proc/*/cmdline and history.
                    Some("-") => {
                        use std::io::BufRead;
                        let mut line = String::new();
                        std::io::stdin().lock().read_line(&mut line)?;
                        line.trim_end_matches(['\r', '\n']).to_owned()
                    }
                    Some(u) => u.to_owned(),
                    None => return Err("import requires an otpauth:// URI or --qr <image>".into()),
                };
                keyroost_import::parse_otpauth(&uri)?.into()
            };
            let final_title = title.clone().unwrap_or_else(|| entry.suggested_title());
            if final_title.is_empty() || final_title.len() > 12 {
                return Err(format!(
                    "derived title {:?} must be 1..=12 bytes; pass --title to override",
                    final_title
                )
                .into());
            }
            session.set_seed(*profile, &entry.secret)?;
            session.set_title(*profile, &final_title)?;
            session.set_config(
                *profile,
                &entry.to_profile_config(unix_now(), display_timeout.to_proto()),
            )?;
            println!(
                "imported {:?} to profile #{} ({} bytes secret, {:?}, {} digits)",
                final_title,
                profile,
                entry.secret.len(),
                entry.algorithm,
                entry.digits as u8
            );
            if qr.is_some() {
                println!(
                    "remember to delete the screenshot (and any phone/cloud copies) — it \
                     contains the secret"
                );
            }
        }
        MoltoCmd::ImportFile {
            path,
            start,
            display_timeout,
            dry_run,
            password_stdin,
            password_env,
        } => {
            // dry-run prints the plan and returns *before* authentication
            // (see the pre-auth handling above) — it is always false here.
            debug_assert!(!*dry_run);
            let entries = load_bulk_entries(path, *password_stdin, password_env.as_deref())?;
            let n = entries.len();
            let last = (*start as usize).saturating_add(n);
            if last > 100 {
                return Err(format!(
                    "{} entries starting at #{} would exceed slot 99 (last slot needed: #{})",
                    n,
                    start,
                    last - 1
                )
                .into());
            }
            println!(
                "found {} entries; programming slots #{}..#{}",
                n,
                start,
                last - 1
            );
            for (i, entry) in entries.iter().enumerate() {
                let p = start + i as u8;
                let title = entry.suggested_title();
                if title.is_empty() {
                    eprintln!(
                        "  #{}: skipping — entry has no issuer or account to use as title",
                        p
                    );
                    continue;
                }
                println!(
                    "  #{}: {:?} ({} bytes secret, {:?}, {} digits)",
                    p,
                    title,
                    entry.secret.len(),
                    entry.algorithm,
                    entry.digits as u8
                );
                session.set_seed(p, &entry.secret)?;
                session.set_title(p, &title)?;
                session.set_config(
                    p,
                    &entry.to_profile_config(unix_now(), display_timeout.to_proto()),
                )?;
            }
            println!("done");
        }
        MoltoCmd::Reset { .. } => unreachable!("handled above before auth"),
        MoltoCmd::Probe { .. } => unreachable!("handled above before auth"),
    }
    Ok(())
}

/// Resolve a reader for the single-profile programmable token: auto-use a lone
/// connected reader, or match an explicit `--reader` substring.
fn prog_pick_reader(explicit: Option<&str>) -> Result<String, Box<dyn std::error::Error>> {
    let readers = keyroost_transport::Session::list_readers()?;
    resolve_reader(readers, explicit, "programmable-token")
}

fn run_prog(cmd: &ProgCmd, debug: bool) -> Result<(), Box<dyn std::error::Error>> {
    use keyroost_token2prog as prog;
    use keyroost_transport::Token2ProgSession;

    match cmd {
        ProgCmd::Info { reader } => {
            let name = prog_pick_reader(reader.as_deref())?;
            let mut session = Token2ProgSession::open_named(&name)?;
            session.set_debug(debug);
            let info = session.read_info()?;
            let model = info.model();
            if json_output() {
                println!(
                    "{{\"serial\":\"{}\",\"model\":{},\"utc_time\":{}}}",
                    info.serial,
                    match model {
                        Some(m) => format!("\"{m}\""),
                        None => "null".to_string(),
                    },
                    info.utc_time
                );
            } else {
                match model {
                    Some(m) => println!("model:    {m}"),
                    None => println!("model:    (unrecognized serial — not a known Token2 model)"),
                }
                println!("serial:   {}", info.serial);
                println!("utc_time: {}", info.utc_time);
            }
        }
        ProgCmd::Seed {
            reader,
            hex,
            base32,
            hex_env,
            base32_env,
            hex_stdin,
            base32_stdin,
        } => {
            let seed = resolve_prog_seed(
                hex.as_deref(),
                base32.as_deref(),
                hex_env.as_deref(),
                base32_env.as_deref(),
                *hex_stdin,
                *base32_stdin,
            )?;
            let name = prog_pick_reader(reader.as_deref())?;
            let mut session = Token2ProgSession::open_named(&name)?;
            session.set_debug(debug);
            // Refuse to program a device whose serial does not match a known
            // Token2 programmable-token model — guards against writing to the
            // wrong card on a shared reader.
            prog_guard_model(&mut session)?;
            session.authenticate()?;
            session.set_seed(&seed)?;
            println!("seed programmed ({} bytes).", seed.len());
        }
        ProgCmd::Config {
            reader,
            algorithm,
            time_step,
            display_timeout,
        } => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(0);
            let cfg = prog::Config {
                display_timeout: match display_timeout {
                    TimeoutArg::S15 => prog::DisplayTimeout::Sec15,
                    TimeoutArg::S30 => prog::DisplayTimeout::Sec30,
                    TimeoutArg::S60 => prog::DisplayTimeout::Sec60,
                    TimeoutArg::S120 => prog::DisplayTimeout::Sec120,
                },
                algorithm: match algorithm {
                    AlgoArg::Sha1 => prog::HmacAlgo::Sha1,
                    AlgoArg::Sha256 => prog::HmacAlgo::Sha256,
                },
                time_step: match time_step {
                    StepArg::S30 => prog::TimeStep::Seconds30,
                    StepArg::S60 => prog::TimeStep::Seconds60,
                },
                utc_time: now,
            };
            let name = prog_pick_reader(reader.as_deref())?;
            let mut session = Token2ProgSession::open_named(&name)?;
            session.set_debug(debug);
            // Refuse to program an unrecognized device (see Seed above).
            prog_guard_model(&mut session)?;
            session.authenticate()?;
            session.set_config(&cfg)?;
            println!("config programmed (clock set to {now}).");
        }
    }
    Ok(())
}

/// Read the device info and refuse to continue unless the serial matches a known
/// Token2 programmable-token model. Returns the resolved model name on success.
/// Used to gate the write commands so the tool never programs an unexpected card.
fn prog_guard_model(
    session: &mut keyroost_transport::Token2ProgSession,
) -> Result<&'static str, Box<dyn std::error::Error>> {
    let info = session.read_info()?;
    match info.model() {
        Some(model) => {
            eprintln!("[*] {model} (serial {})", info.serial);
            Ok(model)
        }
        None => Err(format!(
            "serial '{}' does not match any known Token2 programmable-token model; \
             refusing to program this device. Run `keyroostctl prog info` to inspect it.",
            info.serial
        )
        .into()),
    }
}

/// Decode a programmable-token seed from exactly one of the supplied sources.
fn resolve_prog_seed(
    hex: Option<&str>,
    base32: Option<&str>,
    hex_env: Option<&str>,
    base32_env: Option<&str>,
    hex_stdin: bool,
    base32_stdin: bool,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use std::io::Read;
    let sources = [
        hex.is_some(),
        base32.is_some(),
        hex_env.is_some(),
        base32_env.is_some(),
        hex_stdin,
        base32_stdin,
    ]
    .iter()
    .filter(|b| **b)
    .count();
    if sources != 1 {
        return Err("supply exactly one seed source (--hex / --base32 / -env / -stdin)".into());
    }
    let read_stdin = || -> Result<String, Box<dyn std::error::Error>> {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        Ok(s)
    };
    let (raw, is_hex): (String, bool) = if let Some(h) = hex {
        (h.to_string(), true)
    } else if let Some(b) = base32 {
        (b.to_string(), false)
    } else if let Some(v) = hex_env {
        (std::env::var(v)?, true)
    } else if let Some(v) = base32_env {
        (std::env::var(v)?, false)
    } else if hex_stdin {
        (read_stdin()?, true)
    } else {
        (read_stdin()?, false)
    };
    let seed = if is_hex {
        hex_decode(raw.trim())?
    } else {
        base32_decode(raw.trim())?
    };
    if seed.is_empty() || seed.len() > 63 {
        return Err(format!("seed must be 1..=63 bytes (got {})", seed.len()).into());
    }
    // Pad short secrets to the device's 20-byte stored length with trailing
    // zeros, matching the vendor tool — otherwise the device computes TOTP over
    // a shorter seed than an authenticator app set up from the same secret.
    Ok(keyroost_token2prog::pad_totp_seed(seed))
}

/// Environment diagnosis: each check prints one ✓/✗/– line with the fix
/// inline. Never touches card state and always exits 0 — it's a flashlight,
/// not a gate.
fn run_doctor() {
    println!("keyroost doctor — environment check\n");

    // PC/SC service + readers.
    match Session::list_readers() {
        Ok(readers) => {
            println!("✓ PC/SC service reachable");
            if readers.is_empty() {
                println!("– no smart-card readers present (plug in a key/token to test further)");
            } else {
                println!("✓ {} reader(s):", readers.len());
                let hint = keyroost_proto::READER_NAME_HINT.to_ascii_lowercase();
                for r in &readers {
                    let tag = if r.to_ascii_lowercase().contains(&hint) {
                        "  (Molto2)"
                    } else {
                        ""
                    };
                    println!("    {}{}", r, tag);
                }
            }
        }
        Err(e) => {
            println!("✗ PC/SC unavailable: {}", e);
        }
    }
    println!();

    // FIDO HID devices + node access.
    if !keyroost_hid::hid_supported() {
        println!("– FIDO HID enumeration not supported on this platform/backend");
    } else {
        match keyroost_hid::enumerate() {
            Ok(devices) => {
                let fido: Vec<_> = devices.iter().filter(|d| d.is_fido()).collect();
                if fido.is_empty() {
                    println!("– no FIDO HID devices present");
                    for d in &devices {
                        if let Some(label) = d.bootloader_label() {
                            println!("  note: {} at {} — re-plug it", label, d.path.display());
                        }
                    }
                } else {
                    for d in fido {
                        // RW open is exactly what CTAP needs; this is the
                        // udev-rules litmus test.
                        match std::fs::OpenOptions::new()
                            .read(true)
                            .write(true)
                            .open(&d.path)
                        {
                            Ok(_) => println!(
                                "✓ {} ({}) is accessible",
                                d.product_name,
                                d.path.display()
                            ),
                            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                                println!(
                                    "✗ {} ({}) permission denied — install the udev rules \
                                     (see README) and re-plug the key",
                                    d.product_name,
                                    d.path.display()
                                );
                            }
                            Err(e) => println!(
                                "✗ {} ({}) open failed: {}",
                                d.product_name,
                                d.path.display(),
                                e
                            ),
                        }
                    }
                }
            }
            Err(e) => println!("✗ HID enumeration failed: {}", e),
        }
    }
    println!();

    // udev rules (Linux only; elsewhere access is the OS's department).
    #[cfg(target_os = "linux")]
    {
        let rules = std::path::Path::new("/etc/udev/rules.d/70-keyroost-fido.rules");
        if rules.exists() {
            println!("✓ udev rules installed ({})", rules.display());
        } else {
            println!(
                "– udev rules not found at {} — FIDO commands will need them; \
                 PC/SC features work without (see README)",
                rules.display()
            );
        }
        println!();
    }

    // Registry file permissions.
    match keyroost_keyring::config_path() {
        Some(path) if path.exists() => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                match std::fs::metadata(&path) {
                    Ok(m) if m.permissions().mode() & 0o077 != 0 => println!(
                        "– {} is readable by other users (next save tightens it to 0600)",
                        path.display()
                    ),
                    Ok(_) => println!("✓ {} is owner-only", path.display()),
                    Err(e) => println!("✗ cannot stat {}: {}", path.display(), e),
                }
            }
            #[cfg(not(unix))]
            println!("✓ registry present at {}", path.display());
        }
        Some(path) => println!(
            "– no registry yet ({}) — created on first key-name",
            path.display()
        ),
        None => println!("– no config dir resolvable (HOME/XDG unset?)"),
    }
}

fn run_list(all_hid: bool) -> Result<(), Box<dyn std::error::Error>> {
    println!("PC/SC readers:");
    match Session::list_readers() {
        Ok(readers) if readers.is_empty() => println!("  (none)"),
        Ok(readers) => {
            for r in readers {
                println!("  {}", r);
            }
        }
        Err(e) => println!("  (unavailable: {})", e),
    }

    println!();
    println!("Applet probe (per reader):");
    let (probes, probe_ok) = match keyroost_transport::probe_readers() {
        Ok(p) => (p, true),
        Err(e) => {
            println!("  (unavailable: {})", e);
            (Vec::new(), false)
        }
    };
    if probe_ok && probes.is_empty() {
        println!("  (no readers)");
    } else if probe_ok {
        for p in &probes {
            if p.is_molto2 {
                println!("  {}  [Molto2 token]", p.reader_name);
                continue;
            }
            let mut applets = Vec::new();
            if p.has_oath {
                applets.push("OATH");
            }
            if p.has_openpgp {
                applets.push("OpenPGP");
            }
            if p.has_piv {
                applets.push("PIV");
            }
            let list = if applets.is_empty() {
                "(none detected)".to_string()
            } else {
                applets.join(", ")
            };
            println!("  {}  ->  {}", p.reader_name, list);
        }
    }

    println!();
    let header = if all_hid {
        "HID devices:"
    } else {
        "FIDO HID devices:"
    };
    println!("{}", header);
    let (hids, hids_ok) = match keyroost_hid::enumerate() {
        Ok(d) => (d, true),
        Err(e) => {
            println!("  (unavailable: {})", e);
            (Vec::new(), false)
        }
    };
    let keyring = Keyring::load_default().unwrap_or_default();
    if hids_ok {
        let filtered: Vec<_> = hids.iter().filter(|d| all_hid || d.is_fido()).collect();
        if filtered.is_empty() {
            println!("  (none)");
            if let Some(bl) = keyroost_hid::bootloader_device_present() {
                println!("  note: detected {bl} — re-plug it to return to application mode.");
            }
        } else {
            let ccid = ccid_readers_if_needed(&hids);
            for d in &filtered {
                let tag = if d.is_fido() {
                    " [FIDO]"
                } else if d.bootloader_label().is_some() {
                    " [bootloader]"
                } else {
                    ""
                };
                let eff = d
                    .serial_number
                    .clone()
                    .or_else(|| ccid_serial_for(d, &ccid));
                let serial = match (&d.serial_number, &eff) {
                    (Some(s), _) => format!(" serial={}", s),
                    (None, Some(s)) => format!(" serial={}(ccid)", s),
                    (None, None) => String::new(),
                };
                let name = keyring
                    .name_for(eff.as_deref())
                    .map(|n| format!(" name={}", n))
                    .unwrap_or_default();
                let model = if d.vendor_id == keyroost_proto::USB_VID {
                    keyroost_proto::token2_pid_label(d.product_id)
                        .map(|l| format!("{} [{}]", d.product_name, l))
                        .unwrap_or_else(|| d.product_name.clone())
                } else {
                    d.product_name.clone()
                };
                println!(
                    "  {} {:04x}:{:04x} usage={:04x}:{:04x} {}{}{}{}",
                    d.path.display(),
                    d.vendor_id,
                    d.product_id,
                    d.usage_page,
                    d.usage,
                    model,
                    serial,
                    name,
                    tag,
                );
            }
        }
    }

    // Correlated summary — built from the SAME hid+probe snapshot via the pure
    // correlate(), so the raw sections above and this decision can't disagree.
    println!();
    let devices = keyroost_resolve::correlate(&hids, &probes, &keyring);
    overview::print_correlated(&devices);

    Ok(())
}

/// Best-effort, non-interactive identification of the key a destructive FIDO
/// command would hit — so a `--yes` refusal tells the user *which* device
/// they're about to confirm against. Never prompts; empty when nothing
/// useful can be said.
fn fido_target_hint(path: Option<&Path>) -> String {
    if let Some(p) = path {
        return format!(" — target: {}", p.display());
    }
    let Ok(devices) = keyroost_hid::enumerate() else {
        return String::new();
    };
    let devices: Vec<_> = devices.into_iter().filter(|d| d.is_fido()).collect();
    let keyring = Keyring::load_default().unwrap_or_default();
    if let Some(name) = SELECTED_KEY_NAME.get().and_then(|o| o.as_deref()) {
        let connected = connected_keys(&devices);
        if let Ok(dev) = keyring.resolve(name, &connected) {
            return format!(" — target: {} at {}", dev.label, dev.path.display());
        }
        return String::new();
    }
    match devices.as_slice() {
        [d] => {
            let serials = effective_serials(&devices);
            let label = keyring
                .name_for(serials[0].as_deref())
                .unwrap_or(&d.product_name);
            format!(" — target: {} at {}", label, d.path.display())
        }
        [] => String::new(),
        many => format!(
            " — {} FIDO keys connected; pass --name or --path to choose",
            many.len()
        ),
    }
}

/// Resolve the global `--name` (if set) to a PC/SC reader name via the shared
/// device model, so `--name` targets smart-card / Molto2 groups the same way
/// `--reader` does. Returns the reader substring to match, or None when no
/// `--name` was given. Errors if a name is set but resolves to no PC/SC reader.
fn reader_from_name() -> Result<Option<String>, Box<dyn std::error::Error>> {
    let Some(name) = SELECTED_KEY_NAME.get().and_then(|o| o.clone()) else {
        return Ok(None);
    };
    let devices = keyroost_resolve::enumerate()?;
    let dev = devices
        .iter()
        .find(|d| d.name.as_deref() == Some(name.as_str()))
        .ok_or_else(|| {
            format!("no connected device is named '{name}' (see `keyroostctl key-name list`)")
        })?;
    match &dev.reader {
        Some(r) => Ok(Some(r.clone())),
        None => Err(format!(
            "device '{name}' has no smart-card (PC/SC) interface for this command"
        )
        .into()),
    }
}

fn resolve_fido_path(explicit: Option<&Path>) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let name = SELECTED_KEY_NAME.get().and_then(|o| o.as_deref());
    if explicit.is_some() && name.is_some() {
        return Err("pass either --path or --name, not both".into());
    }
    // An explicit --path is trusted as-is (preserves prior behavior).
    if let Some(p) = explicit {
        return Ok(p.to_path_buf());
    }

    let devices: Vec<keyroost_hid::HidDevice> = keyroost_hid::enumerate()?
        .into_iter()
        .filter(|d| d.is_fido())
        .collect();

    // Resolve by friendly name, if one was given.
    if let Some(name) = name {
        let keyring = Keyring::load_default()?;
        let connected = connected_keys(&devices);
        let dev = keyring.resolve(name, &connected)?;
        announce_target(&keyring, &dev.path, &dev.label, dev.serial.as_deref());
        return Ok(dev.path.clone());
    }

    // No name, no path: use a lone key, else pick interactively (never auto-pick
    // among several — that's the multi-device safety guard).
    let keyring = Keyring::load_default().unwrap_or_default();
    let serials = effective_serials(&devices);
    let i = pick_from_devices(&devices, &keyring, &serials)?;
    let dev = &devices[i];
    announce_target(
        &keyring,
        &dev.path,
        &dev.product_name,
        serials[i].as_deref(),
    );
    Ok(dev.path.clone())
}

/// The "no FIDO device" error, with a clear hint when a known security key is
/// present but stuck in bootloader / DFU mode (it enumerates as plain HID and
/// can't speak CTAP until re-plugged into application mode).
fn no_fido_device_error() -> Box<dyn std::error::Error> {
    let mut msg =
        String::from("no FIDO HID device found. Plug a security key in, or pass --path/--name.");
    if let Some(bl) = keyroost_hid::bootloader_device_present() {
        msg.push_str(&format!(
            " (Detected {bl} — re-plug it to return to application mode.)"
        ));
    }
    msg.into()
}

/// Print the resolved target to stderr so the user always sees which physical
/// key a command is about to act on (annotated with its friendly name if set).
fn announce_target(keyring: &Keyring, path: &Path, label: &str, serial: Option<&str>) {
    match keyring.name_for(serial) {
        Some(name) => eprintln!("\u{2192} {} ({}, {})", name, label, path.display()),
        None => eprintln!("\u{2192} {} ({})", label, path.display()),
    }
}

/// Pick one device when no `--path`/`--name` was given: a lone key is used
/// directly; with several, an interactive picker runs on the terminal, and in a
/// non-interactive context we refuse rather than guess. Returns the chosen index
/// into `devices`. `serials` is parallel to `devices` (used for name display).
fn pick_from_devices(
    devices: &[keyroost_hid::HidDevice],
    keyring: &Keyring,
    serials: &[Option<String>],
) -> Result<usize, Box<dyn std::error::Error>> {
    match devices.len() {
        0 => Err(no_fido_device_error()),
        1 => Ok(0),
        _ => match pick_device_interactively(devices, keyring, serials)? {
            Some(i) => Ok(i),
            None => {
                let paths: Vec<String> = devices
                    .iter()
                    .map(|d| d.path.display().to_string())
                    .collect();
                Err(format!(
                    "{} FIDO devices connected; pass --name or --path \
                     (or run in a terminal to choose): {}",
                    devices.len(),
                    paths.join(", ")
                )
                .into())
            }
        },
    }
}

/// Numbered device picker driven over `/dev/tty` (not stdin, which may carry a
/// piped PIN). Returns the chosen index, or `None` when there's no controlling
/// terminal to prompt on.
fn pick_device_interactively(
    devices: &[keyroost_hid::HidDevice],
    keyring: &Keyring,
    serials: &[Option<String>],
) -> Result<Option<usize>, Box<dyn std::error::Error>> {
    use std::io::{BufRead, IsTerminal, Write};
    let tty = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
    {
        Ok(f) => f,
        Err(_) => return Ok(None),
    };
    if !tty.is_terminal() {
        return Ok(None);
    }
    let mut out = &tty;
    writeln!(out, "Multiple security keys connected:")?;
    for (i, d) in devices.iter().enumerate() {
        let serial = serials.get(i).and_then(|s| s.as_deref());
        let label = match keyring.name_for(serial) {
            Some(name) => format!("{}  ({})", name, d.product_name),
            None => d.product_name.clone(),
        };
        writeln!(out, "  {}) {:<30} {}", i + 1, label, d.path.display())?;
    }
    write!(out, "Select [1-{}]: ", devices.len())?;
    out.flush()?;

    let mut line = String::new();
    std::io::BufReader::new(&tty).read_line(&mut line)?;
    let choice: usize = line
        .trim()
        .parse()
        .map_err(|_| format!("'{}' is not a valid selection", line.trim()))?;
    if (1..=devices.len()).contains(&choice) {
        Ok(Some(choice - 1))
    } else {
        Err(format!("selection {} out of range 1-{}", choice, devices.len()).into())
    }
}

/// Resolve which PC/SC reader to drive OATH on. Mirrors the FIDO picker posture:
/// auto-use a lone OATH key, match an explicit `--reader` substring, and refuse
/// to guess among several. Returns the full reader name.
fn resolve_oath_reader(explicit: Option<&str>) -> Result<String, Box<dyn std::error::Error>> {
    let readers = keyroost_transport::OathSession::list_oath_readers()?;
    resolve_reader(readers, explicit, "OATH")
}

/// Pick one reader from `readers` by the same posture across applets: auto-use a
/// lone reader, match an explicit `--reader` substring, and refuse to guess among
/// several. `kind` ("OATH" / "OpenPGP") only shapes the messages.
fn resolve_reader(
    readers: Vec<String>,
    explicit: Option<&str>,
    kind: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    if readers.is_empty() {
        return Err(format!(
            "no {kind}-capable security key found (no reader's {kind} applet \
             responded). Plug a key in, and check the smart-card (PC/SC) service is running."
        )
        .into());
    }
    match explicit {
        Some(substr) => {
            let needle = substr.to_ascii_lowercase();
            let matches: Vec<&String> = readers
                .iter()
                .filter(|r| r.to_ascii_lowercase().contains(&needle))
                .collect();
            match matches.as_slice() {
                [one] => Ok((*one).clone()),
                [] => Err(format!(
                    "no {kind} reader matches '{}'. Connected {kind} readers: {}",
                    substr,
                    readers.join("; ")
                )
                .into()),
                _ => Err(format!(
                    "'{}' matches several readers; be more specific: {}",
                    substr,
                    matches
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join("; ")
                )
                .into()),
            }
        }
        None => match readers.as_slice() {
            [one] => Ok(one.clone()),
            _ => Err(format!(
                "{} {kind} keys connected; pass --reader <substring>: {}",
                readers.len(),
                readers.join("; ")
            )
            .into()),
        },
    }
}

/// Open an announced OATH session on the resolved reader, unlocking it if the
/// applet is password-protected. A protected applet without a supplied password
/// is a clear error rather than a confusing downstream `6982`.
fn open_oath(
    access: &OathAccess,
    debug: bool,
) -> Result<keyroost_transport::OathSession, Box<dyn std::error::Error>> {
    let by_name = reader_from_name()?;
    let name = resolve_oath_reader(access.reader.as_deref().or(by_name.as_deref()))?;
    eprintln!("\u{2192} OATH on {}", name);
    let mut session = keyroost_transport::OathSession::open(&name)?;
    session.set_debug(debug);
    match access.password()? {
        Some(pw) => session.unlock(&pw)?,
        None if session.password_required() => {
            return Err("this OATH applet is password-protected; supply it with \
                        --password-env VAR or --password-stdin"
                .into());
        }
        None => {}
    }
    Ok(session)
}

fn run_oath(cmd: &OathCmd, debug: bool) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        OathCmd::List { access } => {
            let mut session = open_oath(access, debug)?;
            let creds = session.list()?;
            if json_output() {
                let out: Vec<json_out::OathCredentialJson> = creds
                    .iter()
                    .map(|c| json_out::OathCredentialJson {
                        name: c.name.clone(),
                        oath_type: oath_type_str(c.oath_type),
                        algorithm: oath_algo_str(c.algorithm),
                    })
                    .collect();
                emit_json(&out)?;
                return Ok(());
            }
            if creds.is_empty() {
                println!("(no OATH credentials)");
            } else {
                for c in creds {
                    println!(
                        "{}  [{}/{}]",
                        c.name,
                        oath_type_str(c.oath_type),
                        oath_algo_str(c.algorithm)
                    );
                }
            }
        }
        OathCmd::Code {
            name,
            period,
            access,
        } => {
            let mut session = open_oath(access, debug)?;
            // Dispatch on the stored credential type: HOTP uses the card's own
            // counter (empty challenge), TOTP a time counter.
            let is_hotp = session
                .list()?
                .iter()
                .find(|c| c.name == *name)
                .map(|c| matches!(c.oath_type, keyroost_oath::OathType::Hotp))
                .unwrap_or(false);
            let code = if is_hotp {
                session.calculate_hotp(name)?
            } else {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|e| e.to_string())?
                    .as_secs();
                session.calculate_totp(name, now, *period)?
            };
            if json_output() {
                emit_json(&json_out::OathCodeJson {
                    name: name.clone(),
                    code: code.code.clone(),
                })?;
                return Ok(());
            }
            println!("{}", code.code);
        }
        OathCmd::Add {
            name,
            oath_type,
            secret_env,
            secret_stdin,
            algorithm,
            digits,
            counter,
            touch,
            access,
        } => {
            if !(6..=8).contains(digits) {
                return Err("--digits must be 6, 7, or 8".into());
            }
            if *counter != 0 && !matches!(oath_type, OathTypeArg::Hotp) {
                return Err("--counter only applies to --type hotp".into());
            }
            let secret_b32 = read_secret("secret", secret_env.as_deref(), *secret_stdin)?;
            let secret = base32_decode(secret_b32.trim())
                .map_err(|e| format!("invalid base32 secret: {}", e))?;
            let mut session = open_oath(access, debug)?;
            let params = keyroost_oath::PutParams {
                name,
                secret: &secret,
                oath_type: oath_type.to_oath(),
                algorithm: algorithm.to_oath(),
                digits: *digits,
                require_touch: *touch,
                imf: *counter,
            };
            session.put(&params)?;
            println!(
                "Added OATH {} credential {:?}.",
                oath_type_str(oath_type.to_oath()),
                name
            );
        }
        OathCmd::Delete { name, access } => {
            let mut session = open_oath(access, debug)?;
            session.delete(name)?;
            println!("Deleted OATH credential {:?}.", name);
        }
        OathCmd::SetPassword {
            new_password_env,
            new_password_stdin,
            access,
        } => {
            let new_pw = read_secret(
                "new OATH password",
                new_password_env.as_deref(),
                *new_password_stdin,
            )?;
            if new_pw.is_empty() {
                return Err("new password is empty; use `clear-password` to remove it".into());
            }
            let mut session = open_oath(access, debug)?;
            session.set_password(&new_pw)?;
            println!("OATH password set.");
        }
        OathCmd::ClearPassword { access } => {
            let mut session = open_oath(access, debug)?;
            session.clear_password()?;
            println!("OATH password cleared.");
        }
    }
    Ok(())
}

fn oath_type_str(t: keyroost_oath::OathType) -> &'static str {
    match t {
        keyroost_oath::OathType::Totp => "TOTP",
        keyroost_oath::OathType::Hotp => "HOTP",
    }
}

/// Open a Token2 OTP session on the requested transport and register a touch
/// prompt for button-required commands.
fn open_otp(
    transport: OtpTransportArg,
    debug: bool,
) -> Result<keyroost_transport::Token2OtpSession, Box<dyn std::error::Error>> {
    let mut session = match transport {
        OtpTransportArg::Auto => keyroost_transport::Token2OtpSession::detect_debug(debug)?,
        OtpTransportArg::Hid => keyroost_transport::Token2OtpSession::detect_hid_only(debug)?,
        OtpTransportArg::Ccid => keyroost_transport::Token2OtpSession::detect_pcsc_only(debug)?,
    };
    session.set_debug(debug);
    eprintln!(
        "\u{2192} Token2 OTP on {}",
        if session.is_pcsc() {
            "CCID/NFC"
        } else {
            "USB-HID"
        }
    );
    session.set_button_prompt(Box::new(|| {
        eprintln!("touch your key to continue\u{2026}");
    }));
    Ok(session)
}

fn run_otp(
    cmd: &OtpCmd,
    transport: OtpTransportArg,
    debug: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        OtpCmd::List => {
            let mut session = open_otp(transport, debug)?;
            let now = unix_now() as u64;
            let entries = session.enumerate(now)?;
            if json_output() {
                let out: Vec<json_out::OtpEntryJson> = entries
                    .iter()
                    .map(|e| json_out::OtpEntryJson {
                        app: e.app_name.clone(),
                        account: e.account_name.clone(),
                        otp_type: keyroost_transport::otp_type_str(e.otp_type),
                        algorithm: otp_algo_str_t2(e.algorithm),
                        code: e.code.clone(),
                        touch_required: e.button_required,
                    })
                    .collect();
                emit_json(&out)?;
                return Ok(());
            }
            if entries.is_empty() {
                println!("(no OTP entries)");
            } else {
                for e in entries {
                    let label = if e.app_name.is_empty() {
                        e.account_name.clone()
                    } else {
                        format!("{}:{}", e.app_name, e.account_name)
                    };
                    let code = e.code.as_deref().unwrap_or("\u{2014}"); // em dash when withheld
                    println!(
                        "{label}  [{}/{}]  {}{}",
                        keyroost_transport::otp_type_str(e.otp_type),
                        otp_algo_str_t2(e.algorithm),
                        code,
                        if e.button_required { "  (touch)" } else { "" },
                    );
                }
            }
        }
        OtpCmd::Get { app, account } => {
            let mut session = open_otp(transport, debug)?;
            let now = unix_now() as u64;
            let entry = session.read_entry(now, app, account)?;
            match entry.code {
                Some(code) => {
                    if json_output() {
                        emit_json(&json_out::OtpGetJson {
                            app: app.clone(),
                            account: account.clone(),
                            code,
                        })?;
                        return Ok(());
                    }
                    println!("{code}");
                }
                None => return Err("device did not return a code for that entry".into()),
            }
        }
        OtpCmd::Add {
            app,
            account,
            otp_type,
            algorithm,
            digits,
            period,
            touch,
            seed_env,
            seed_stdin,
        } => {
            if !(4..=10).contains(digits) {
                return Err("--digits must be between 4 and 10".into());
            }
            let seed_b32 = read_secret("seed", seed_env.as_deref(), *seed_stdin)?;
            let seed = keyroost_token2otp::decode_base32_seed(seed_b32.trim())
                .map_err(|e| format!("invalid base32 seed: {e}"))?;
            let mut session = open_otp(transport, debug)?;
            let entry = keyroost_token2otp::WriteEntry {
                otp_type: otp_type.to_t2(),
                algorithm: algorithm.to_t2(),
                timestep: *period,
                code_length: *digits,
                button_required: *touch,
                app_name: app,
                account_name: account,
                seed: &seed,
            };
            session.write_entry(&entry)?;
            let label = if app.is_empty() {
                account.clone()
            } else {
                format!("{app}:{account}")
            };
            println!("Added OTP entry {label:?}.");
        }
        OtpCmd::Delete { app, account } => {
            let mut session = open_otp(transport, debug)?;
            session.delete_entry(app, account)?;
            let label = if app.is_empty() {
                account.clone()
            } else {
                format!("{app}:{account}")
            };
            println!("Deleted OTP entry {label:?}.");
        }
        OtpCmd::EraseAll { yes } => {
            if !yes {
                return Err("refusing to erase all OTP entries without --yes".into());
            }
            let mut session = open_otp(transport, debug)?;
            eprintln!("touch your key to confirm the erase\u{2026}");
            session.erase_all()?;
            println!("Erased all OTP entries.");
        }
        OtpCmd::Serial => {
            let mut session = open_otp(transport, debug)?;
            let sn = session.read_serial()?;
            let hex: String = sn.iter().map(|b| format!("{b:02x}")).collect();
            if json_output() {
                emit_json(&json_out::OtpSerialJson { serial: hex })?;
                return Ok(());
            }
            println!("{hex}");
        }
        OtpCmd::ButtonHotp {
            digits,
            no_enter,
            long_touch,
            numpad,
            seed_env,
            seed_stdin,
        } => {
            if *digits != 6 && *digits != 8 {
                return Err("button HOTP --digits must be 6 or 8".into());
            }
            let seed_b32 = read_secret("seed", seed_env.as_deref(), *seed_stdin)?;
            let seed = keyroost_token2otp::decode_base32_seed(seed_b32.trim())
                .map_err(|e| format!("invalid base32 seed: {e}"))?;
            let mut session = open_otp(transport, debug)?;
            session.set_button_hotp(*digits, &seed, !*no_enter, *long_touch, *numpad)?;
            println!("Configured the HOTP-on-button keystroke slot.");
        }
        OtpCmd::DeleteButtonHotp => {
            let mut session = open_otp(transport, debug)?;
            session.delete_button_hotp()?;
            println!("Deleted the HOTP-on-button keystroke slot.");
        }
        OtpCmd::Config => {
            let mut session = open_otp(transport, debug)?;
            // Show the raw READ_CONFIG bytes first (diagnostic), then the parse.
            match session.read_config() {
                Ok(raw) => {
                    let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
                    println!("READ_CONFIG returned {} bytes: {hex}", raw.len());
                }
                Err(e) => {
                    eprintln!("READ_CONFIG failed: {e}");
                    return Err(e.into());
                }
            }
            let info = session.read_device_info()?;
            println!("Device configuration:");
            println!(
                "  FIDO interface:         {}",
                if info.fido_disabled() {
                    "disabled"
                } else {
                    "enabled"
                }
            );
            println!(
                "  keyboard-HID interface: {}",
                if info.hotp_keystroke_disabled() {
                    "disabled"
                } else {
                    "enabled"
                }
            );
            println!(
                "  CCID interface:         {}",
                if info.ccid_disabled() {
                    "disabled"
                } else {
                    "enabled"
                }
            );
            println!(
                "  HOTP-on-touch support:  {}",
                if info.button_hotp_supported() {
                    "yes"
                } else {
                    "no"
                }
            );
            println!(
                "  HOTP-on-touch slot:     {}",
                if !info.has_config_byte() {
                    "unknown (device returned a short config block)"
                } else if info.button_hotp_configured() {
                    "configured"
                } else {
                    "empty"
                }
            );
        }
        OtpCmd::Interface {
            fido,
            keyboard,
            ccid,
            yes,
        } => {
            use keyroost_token2otp::{DEV_CCID, DEV_FIDO, DEV_KEYBOARD};
            // Require at least TWO interfaces to remain enabled. Disabling all
            // three bricks the key; leaving only one is fragile (if that single
            // interface can't be reached you'd be locked out), so the tool keeps
            // a two-interface minimum as a safety margin.
            let enabled_count = [*fido, *keyboard, *ccid].iter().filter(|x| **x).count();
            if enabled_count < 2 {
                return Err(
                    "at least two interfaces must stay enabled (--fido / --keyboard / --ccid); \
                     reducing to one or zero risks locking you out of the key"
                        .into(),
                );
            }
            // Build the *disable* mask: a set bit disables that interface.
            let mut disable: u8 = 0;
            if !*fido {
                disable |= DEV_FIDO;
            }
            if !*keyboard {
                disable |= DEV_KEYBOARD;
            }
            if !*ccid {
                disable |= DEV_CCID;
            }

            let enabled: Vec<&str> = [
                (*fido, "FIDO2/U2F"),
                (*keyboard, "keyboard-HID"),
                (*ccid, "CCID/smart-card"),
            ]
            .into_iter()
            .filter_map(|(on, name)| on.then_some(name))
            .collect();
            let disabled: Vec<&str> = [
                (!*fido, "FIDO2/U2F"),
                (!*keyboard, "keyboard-HID"),
                (!*ccid, "CCID/smart-card"),
            ]
            .into_iter()
            .filter_map(|(off, name)| off.then_some(name))
            .collect();

            eprintln!("This will reconfigure the key's USB interfaces:");
            eprintln!("  enable:  {}", enabled.join(", "));
            eprintln!(
                "  disable: {}",
                if disabled.is_empty() {
                    "(none)".to_string()
                } else {
                    disabled.join(", ")
                }
            );
            eprintln!(
                "Disabling an interface removes the matching features until you re-enable it.\n\
                 If you disable the interface you are currently connected over, you may not be\n\
                 able to reach the key to undo this. Proceed with caution."
            );

            if !*yes {
                // Require typing an exact phrase — not just "y" — for a hardware
                // reconfiguration this consequential.
                eprint!("Type EXACTLY 'reconfigure interfaces' to proceed: ");
                use std::io::Write as _;
                std::io::stderr().flush().ok();
                let mut line = String::new();
                std::io::stdin().read_line(&mut line)?;
                if line.trim() != "reconfigure interfaces" {
                    return Err("confirmation phrase did not match; aborted".into());
                }
            }

            let mut session = open_otp(transport, debug)?;
            session.set_device_type(disable)?;
            println!("Interface configuration updated. Re-plug the key for it to take effect.");
        }
    }
    Ok(())
}

fn otp_algo_str_t2(a: keyroost_token2otp::Algorithm) -> &'static str {
    match a {
        keyroost_token2otp::Algorithm::Sha1 => "SHA1",
        keyroost_token2otp::Algorithm::Sha256 => "SHA256",
    }
}

fn oath_algo_str(a: keyroost_oath::Algorithm) -> &'static str {
    match a {
        keyroost_oath::Algorithm::Sha1 => "SHA1",
        keyroost_oath::Algorithm::Sha256 => "SHA256",
        keyroost_oath::Algorithm::Sha512 => "SHA512",
    }
}

fn run_openpgp(cmd: &OpenpgpCmd, debug: bool) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        OpenpgpCmd::Status { reader } => {
            let mut session = open_openpgp(reader.as_deref(), debug)?;
            let status = session.status()?;

            if json_output() {
                // An all-zero fingerprint means "no key in that slot" — mirror the
                // human "(none)" by emitting null rather than 40 zeros.
                let fpr = |f: &[u8; 20]| -> Option<String> {
                    if f.iter().all(|&b| b == 0) {
                        None
                    } else {
                        Some(hex_encode(f))
                    }
                };
                emit_json(&json_out::OpenpgpStatusJson {
                    aid: hex_encode(&status.aid),
                    serial: status.serial(),
                    sig_algo: algo_id_str(status.sig_algo_id).to_string(),
                    dec_algo: algo_id_str(status.dec_algo_id).to_string(),
                    aut_algo: algo_id_str(status.aut_algo_id).to_string(),
                    fingerprint_sig: fpr(&status.fingerprint_sig),
                    fingerprint_dec: fpr(&status.fingerprint_dec),
                    fingerprint_aut: fpr(&status.fingerprint_aut),
                    pin_retries_pw1: status.tries_pw1,
                    pin_retries_rc: status.tries_rc,
                    pin_retries_pw3: status.tries_pw3,
                    signature_count: status.signature_count,
                })?;
                return Ok(());
            }

            println!("AID:            {}", hex_encode(&status.aid));
            if let Some(serial) = status.serial() {
                // Yubico prints this serial in hex; show both (it equals the
                // YubiKey's CCID/mgmt serial used for friendly names).
                println!("Serial:         {0} (0x{0:08X})", serial);
            }
            println!(
                "Key algorithms: sig={} dec={} aut={}",
                algo_id_str(status.sig_algo_id),
                algo_id_str(status.dec_algo_id),
                algo_id_str(status.aut_algo_id),
            );
            print_fingerprint("Signature  fpr", &status.fingerprint_sig);
            print_fingerprint("Decryption fpr", &status.fingerprint_dec);
            print_fingerprint("Auth       fpr", &status.fingerprint_aut);
            println!(
                "PIN retries:    PW1={} RC={} PW3={}",
                status.tries_pw1, status.tries_rc, status.tries_pw3
            );
            match status.signature_count {
                Some(n) => println!("Signatures:     {}", n),
                None => println!("Signatures:     (unavailable)"),
            }
        }
        OpenpgpCmd::Verify {
            pin,
            pin_env,
            pin_stdin,
            reader,
        } => {
            let pin_value = read_secret("OpenPGP PIN", pin_env.as_deref(), *pin_stdin)?;
            let mut session = open_openpgp(reader.as_deref(), debug)?;
            session.verify_pin(pin.pw_ref(), pin_value.as_bytes())?;
            println!("{} PIN verified.", pin.label());
        }
        OpenpgpCmd::PublicKey { slot, reader } => {
            let mut session = open_openpgp(reader.as_deref(), debug)?;
            let key = session.read_public_key(slot.to_crt())?;
            println!("{} key (RSA):", slot.label());
            println!("  modulus:  {}", hex_encode(&key.modulus));
            println!("  exponent: {}", hex_encode(&key.exponent));
        }
        OpenpgpCmd::Reset { yes, reader } => {
            // Resolve and identify the target *before* the --yes gate, so the
            // refusal (and the consent the flag implies) names the exact card —
            // the same posture as `factory-reset` and `piv reset`.
            let mut session = open_openpgp(reader.as_deref(), debug)?;
            let status = session.status()?;
            let ident = match status.serial() {
                Some(serial) => format!("serial {}", serial),
                None => format!("AID {}", hex_encode(&status.aid)),
            };
            if !yes {
                return Err(format!(
                    "refusing to reset the OpenPGP applet on {} without --yes \
                     (this wipes ALL OpenPGP keys and resets PINs to defaults)",
                    ident
                )
                .into());
            }
            session.factory_reset()?;
            println!(
                "OpenPGP applet on {} reset. All keys wiped; PINs restored to defaults.",
                ident
            );
        }
        OpenpgpCmd::GenerateKey {
            slot,
            yes,
            admin_pin_env,
            admin_pin_stdin,
            reader,
        } => {
            if !yes {
                return Err(format!(
                    "refusing to generate without --yes (this OVERWRITES the {} key slot)",
                    slot.label()
                )
                .into());
            }
            let admin_pin = read_secret(
                "admin PIN (PW3)",
                admin_pin_env.as_deref(),
                *admin_pin_stdin,
            )?;
            let mut session = open_openpgp(reader.as_deref(), debug)?;
            session.verify_pin(keyroost_openpgp::PW3_ADMIN, admin_pin.as_bytes())?;
            println!(
                "Generating {} key — touch the key if it blinks…",
                slot.label()
            );
            let key = session.generate_key(slot.to_crt())?;
            println!("Generated {} key (RSA):", slot.label());
            println!("  modulus:  {}", hex_encode(&key.modulus));
            println!("  exponent: {}", hex_encode(&key.exponent));
            // Register the key (fingerprint + creation timestamp) so gpg and
            // other OpenPGP tools recognize it. Use the host's current time as
            // the key's creation time; the card stores both, so read-back is
            // self-consistent.
            let creation_time = unix_now();
            let fpr = session.register_key(slot.to_crt(), creation_time)?;
            println!("  fingerprint: {}", hex_encode(&fpr));
            println!("  created:     {} (unix)", creation_time);
        }
        OpenpgpCmd::ImportKey {
            generate,
            in_file,
            slot,
            yes,
            admin_pin_env,
            admin_pin_stdin,
            reader,
        } => {
            if !yes {
                return Err(format!(
                    "refusing to import without --yes (this OVERWRITES the {} key slot)",
                    slot.label()
                )
                .into());
            }
            let admin_pin = read_secret(
                "admin PIN (PW3)",
                admin_pin_env.as_deref(),
                *admin_pin_stdin,
            )?;

            // Obtain the RSA-2048 key parts (full CRT set, big-endian) either by
            // host keygen or by loading a key file. Both go through the shared
            // `keyroost-rsakey` crate (which owns the scoped `rsa` dep); the card
            // decides which parts it wants.
            let k = if *generate {
                println!("Generating an RSA-2048 key on the host…");
                keyroost_rsakey::generate_2048()?
            } else {
                let path = in_file
                    .as_deref()
                    .ok_or("provide --generate or --in <FILE>")?;
                println!("Loading RSA key from {}…", path.display());
                keyroost_rsakey::load_from_file(path)?
            };

            let mut session = open_openpgp(reader.as_deref(), debug)?;
            session.verify_pin(keyroost_openpgp::PW3_ADMIN, admin_pin.as_bytes())?;
            println!("Importing {} key…", slot.label());
            let parts = keyroost_transport::RsaPrivateKeyParts {
                e: &k.e,
                p: &k.p,
                q: &k.q,
                u: &k.u,
                dp: &k.dp,
                dq: &k.dq,
                n: &k.n,
            };
            session.import_key(slot.to_crt(), &parts)?;
            // Register so gpg recognizes it; fingerprint is over (n, e) + time.
            let creation_time = unix_now();
            let fpr = session.register_key(slot.to_crt(), creation_time)?;
            println!("Imported {} key (RSA-2048):", slot.label());
            println!("  modulus:  {}", hex_encode(&k.n));
            println!("  exponent: {}", hex_encode(&k.e));
            println!("  fingerprint: {}", hex_encode(&fpr));
            println!("  created:     {} (unix)", creation_time);
        }
        OpenpgpCmd::SetName {
            name: cardholder,
            admin_pin_env,
            admin_pin_stdin,
            reader,
        } => {
            let admin_pin = read_secret(
                "admin PIN (PW3)",
                admin_pin_env.as_deref(),
                *admin_pin_stdin,
            )?;
            let mut session = open_openpgp(reader.as_deref(), debug)?;
            session.verify_pin(keyroost_openpgp::PW3_ADMIN, admin_pin.as_bytes())?;
            session.set_cardholder_name(cardholder.as_bytes())?;
            println!("Cardholder name set.");
        }
        OpenpgpCmd::SetUrl {
            url,
            admin_pin_env,
            admin_pin_stdin,
            reader,
        } => {
            let admin_pin = read_secret(
                "admin PIN (PW3)",
                admin_pin_env.as_deref(),
                *admin_pin_stdin,
            )?;
            let mut session = open_openpgp(reader.as_deref(), debug)?;
            session.verify_pin(keyroost_openpgp::PW3_ADMIN, admin_pin.as_bytes())?;
            session.set_url(url.as_bytes())?;
            println!("Public-key URL set.");
        }
        OpenpgpCmd::Sign {
            r#in,
            out,
            pin_env,
            pin_stdin,
            hash,
            reader,
        } => {
            let data = std::fs::read(r#in)
                .map_err(|e| format!("cannot read {}: {}", r#in.display(), e))?;
            // PKCS#1 v1.5 DigestInfo (SHA-256 by default, SHA-1 on request): the
            // card wraps it in EMSA padding and RSA-signs it. Both hashes are
            // in-tree (keyroost-proto); the card signs whatever DigestInfo it gets.
            let digest_info = hash.digest_info(&data);
            let pin = read_secret("signing PIN (PW1)", pin_env.as_deref(), *pin_stdin)?;
            let mut session = open_openpgp(reader.as_deref(), debug)?;
            session.verify_pin(keyroost_openpgp::PW1_SIGN, pin.as_bytes())?;
            eprintln!("Signing ({}) — touch the key if it blinks…", hash.label());
            let sig = session.sign(&digest_info)?;
            match out {
                Some(path) => {
                    write_private_file(path, &sig)
                        .map_err(|e| format!("cannot write {}: {}", path.display(), e))?;
                    eprintln!("Wrote {} signature bytes to {}", sig.len(), path.display());
                }
                None => println!("{}", hex_encode(&sig)),
            }
        }
        OpenpgpCmd::Decrypt {
            r#in,
            out,
            pin_env,
            pin_stdin,
            reader,
        } => {
            let cryptogram = std::fs::read(r#in)
                .map_err(|e| format!("cannot read {}: {}", r#in.display(), e))?;
            let pin = read_secret("user PIN (PW1)", pin_env.as_deref(), *pin_stdin)?;
            let mut session = open_openpgp(reader.as_deref(), debug)?;
            // Decryption authorizes under PW1 in the "other"/decipher context
            // (ref 0x82), not the signing context (0x81).
            session.verify_pin(keyroost_openpgp::PW1_OTHER, pin.as_bytes())?;
            eprintln!("Decrypting — touch the key if it blinks…");
            let plain = session.decrypt(&cryptogram)?;
            match out {
                Some(path) => {
                    write_private_file(path, &plain)
                        .map_err(|e| format!("cannot write {}: {}", path.display(), e))?;
                    eprintln!(
                        "Wrote {} plaintext bytes to {}",
                        plain.len(),
                        path.display()
                    );
                }
                None => println!("{}", hex_encode(&plain)),
            }
        }
        OpenpgpCmd::Authenticate {
            r#in,
            out,
            pin_env,
            pin_stdin,
            hash,
            reader,
        } => {
            let data = std::fs::read(r#in)
                .map_err(|e| format!("cannot read {}: {}", r#in.display(), e))?;
            // PKCS#1 v1.5 DigestInfo (SHA-256 by default, SHA-1 on request): the
            // card wraps it in EMSA padding and RSA-signs it with the Auth key.
            let digest_info = hash.digest_info(&data);
            let pin = read_secret("user PIN (PW1)", pin_env.as_deref(), *pin_stdin)?;
            let mut session = open_openpgp(reader.as_deref(), debug)?;
            // INTERNAL AUTHENTICATE authorizes under PW1 in the "other" context
            // (ref 0x82) — the same context as decipher, not the signing context.
            session.verify_pin(keyroost_openpgp::PW1_OTHER, pin.as_bytes())?;
            eprintln!(
                "Authenticating ({}) — touch the key if it blinks…",
                hash.label()
            );
            let sig = session.internal_authenticate(&digest_info)?;
            match out {
                Some(path) => {
                    write_private_file(path, &sig)
                        .map_err(|e| format!("cannot write {}: {}", path.display(), e))?;
                    eprintln!("Wrote {} signature bytes to {}", sig.len(), path.display());
                }
                None => println!("{}", hex_encode(&sig)),
            }
        }
        OpenpgpCmd::ChangePin {
            reader,
            old_pin_env,
            old_pin_stdin,
            new_pin_env,
            new_pin_stdin,
        } => {
            // CHANGE REFERENCE DATA carries the old PIN itself — no prior VERIFY.
            let old = read_secret("old user PIN (PW1)", old_pin_env.as_deref(), *old_pin_stdin)?;
            let new = read_secret("new user PIN (PW1)", new_pin_env.as_deref(), *new_pin_stdin)?;
            let mut session = open_openpgp(reader.as_deref(), debug)?;
            session.change_user_pin(old.as_bytes(), new.as_bytes())?;
            println!("User PIN (PW1) changed.");
        }
        OpenpgpCmd::ChangeAdminPin {
            reader,
            old_pin_env,
            old_pin_stdin,
            new_pin_env,
            new_pin_stdin,
        } => {
            let old = read_secret(
                "old admin PIN (PW3)",
                old_pin_env.as_deref(),
                *old_pin_stdin,
            )?;
            let new = read_secret(
                "new admin PIN (PW3)",
                new_pin_env.as_deref(),
                *new_pin_stdin,
            )?;
            let mut session = open_openpgp(reader.as_deref(), debug)?;
            session.change_admin_pin(old.as_bytes(), new.as_bytes())?;
            println!("Admin PIN (PW3) changed.");
        }
        OpenpgpCmd::UnblockPin {
            reader,
            admin_pin_env,
            admin_pin_stdin,
            new_pin_env,
            new_pin_stdin,
        } => {
            let admin = read_secret(
                "admin PIN (PW3)",
                admin_pin_env.as_deref(),
                *admin_pin_stdin,
            )?;
            let new = read_secret("new user PIN (PW1)", new_pin_env.as_deref(), *new_pin_stdin)?;
            let mut session = open_openpgp(reader.as_deref(), debug)?;
            // reset_retry_counter verifies PW3 internally, then RESET RETRY
            // COUNTER sets the new user PIN — don't double-verify here.
            session.reset_retry_counter(admin.as_bytes(), new.as_bytes())?;
            println!("User PIN (PW1) unblocked and reset.");
        }
    }
    Ok(())
}

fn run_piv(cmd: &PivCmd, debug: bool) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        PivCmd::Status { reader } => {
            let mut session = open_piv(reader.as_deref(), debug)?;
            let status = session.status()?;

            if json_output() {
                emit_json(&json_out::PivStatusJson {
                    version: status.version.map(|(a, b, c)| format!("{a}.{b}.{c}")),
                    serial: status.serial,
                    pin_retries: status.pin_retries,
                    slots: status
                        .slots
                        .iter()
                        .map(|s| json_out::PivSlotJson {
                            slot: s.slot.label().to_string(),
                            cert_present: s.cert_present,
                            cert_len: s.cert_len,
                        })
                        .collect(),
                })?;
                return Ok(());
            }

            match status.version {
                Some((a, b, c)) => println!("Version:     {}.{}.{}", a, b, c),
                None => println!("Version:     (unavailable)"),
            }
            match status.serial {
                Some(s) => println!("Serial:      {0} (0x{0:08X})", s),
                None => println!("Serial:      (unavailable)"),
            }
            match status.pin_retries {
                Some(0) => println!("PIN retries: 0 (blocked)"),
                Some(n) => println!("PIN retries: {}", n),
                None => println!("PIN retries: (unavailable)"),
            }
            println!("Slots:");
            for s in &status.slots {
                if s.cert_present {
                    println!(
                        "  {:<26} cert present ({} bytes)",
                        s.slot.label(),
                        s.cert_len
                    );
                } else {
                    println!("  {:<26} empty", s.slot.label());
                }
            }
        }

        PivCmd::ChangePin {
            reader,
            old_pin_env,
            old_pin_stdin,
            new_pin_env,
            new_pin_stdin,
        } => {
            let old = read_secret("old PIN", old_pin_env.as_deref(), *old_pin_stdin)?;
            let new = read_secret("new PIN", new_pin_env.as_deref(), *new_pin_stdin)?;
            let mut s = open_piv(reader.as_deref(), debug)?;
            s.change_pin(old.as_bytes(), new.as_bytes())?;
            println!("PIN changed.");
        }

        PivCmd::ChangePuk {
            reader,
            old_puk_env,
            old_puk_stdin,
            new_puk_env,
            new_puk_stdin,
        } => {
            let old = read_secret("old PUK", old_puk_env.as_deref(), *old_puk_stdin)?;
            let new = read_secret("new PUK", new_puk_env.as_deref(), *new_puk_stdin)?;
            let mut s = open_piv(reader.as_deref(), debug)?;
            s.change_puk(old.as_bytes(), new.as_bytes())?;
            println!("PUK changed.");
        }

        PivCmd::UnblockPin {
            reader,
            puk_env,
            puk_stdin,
            new_pin_env,
            new_pin_stdin,
        } => {
            let puk = read_secret("PUK", puk_env.as_deref(), *puk_stdin)?;
            let new = read_secret("new PIN", new_pin_env.as_deref(), *new_pin_stdin)?;
            let mut s = open_piv(reader.as_deref(), debug)?;
            s.unblock_pin(puk.as_bytes(), new.as_bytes())?;
            println!("PIN unblocked and reset.");
        }

        PivCmd::SetRetries {
            reader,
            pin_tries,
            puk_tries,
            mgmt_key_env,
            mgmt_key_stdin,
            pin_env,
            pin_stdin,
        } => {
            if *pin_tries == 0 || *puk_tries == 0 {
                return Err(
                    "retry counts must be at least 1 — a zero count would leave the \
                            PIN or PUK permanently blocked"
                        .into(),
                );
            }
            let mgmt = read_mgmt_key("management key", mgmt_key_env.as_deref(), *mgmt_key_stdin)?;
            let pin = read_secret("PIN", pin_env.as_deref(), *pin_stdin)?;
            let mut s = open_piv_authed(reader.as_deref(), debug, &mgmt)?;
            s.verify_pin(pin.as_bytes())?;
            s.set_pin_retries(*pin_tries, *puk_tries)?;
            println!(
                "PIN/PUK retry counts set to {}/{}. Both reset to factory defaults.",
                pin_tries, puk_tries
            );
        }

        PivCmd::ChangeManagementKey {
            reader,
            old_mgmt_key_env,
            old_mgmt_key_stdin,
            new_mgmt_key_env,
            new_mgmt_key_stdin,
            new_algorithm,
            touch,
        } => {
            let old = read_mgmt_key(
                "old management key",
                old_mgmt_key_env.as_deref(),
                *old_mgmt_key_stdin,
            )?;
            let new = read_mgmt_key(
                "new management key",
                new_mgmt_key_env.as_deref(),
                *new_mgmt_key_stdin,
            )?;
            let new_alg = new_algorithm.to_alg();
            if new.len() != new_alg.key_len() {
                return Err(format!(
                    "new management key is {} bytes; {} needs {}",
                    new.len(),
                    new_alg.label(),
                    new_alg.key_len()
                )
                .into());
            }
            let mut s = open_piv_authed(reader.as_deref(), debug, &old)?;
            s.set_management_key(new_alg, &new, *touch)?;
            println!(
                "Management key changed to {}{}.",
                new_alg.label(),
                if *touch { " (touch required)" } else { "" }
            );
        }

        PivCmd::GenerateKey {
            reader,
            slot,
            algorithm,
            pin_policy,
            touch_policy,
            mgmt_key_env,
            mgmt_key_stdin,
        } => {
            let mgmt = read_mgmt_key("management key", mgmt_key_env.as_deref(), *mgmt_key_stdin)?;
            let alg = algorithm.to_alg();
            let mut s = open_piv_authed(reader.as_deref(), debug, &mgmt)?;
            eprintln!(
                "Generating {} in {} (touch the key if it blinks)\u{2026}",
                alg.label(),
                slot.to_slot().label()
            );
            let pubkey = s.generate_key(
                slot.to_slot(),
                alg,
                pin_policy.to_policy(),
                touch_policy.to_policy(),
            )?;
            match keyroost_piv::spki::subject_public_key_info(&pubkey, alg) {
                Ok(der) => print!("{}", keyroost_piv::spki::to_pem(&der)),
                Err(e) => {
                    return Err(
                        format!("key generated, but encoding its public key failed: {}", e).into(),
                    )
                }
            }
        }

        PivCmd::ImportCert {
            reader,
            slot,
            file,
            mgmt_key_env,
            mgmt_key_stdin,
        } => {
            let mgmt = read_mgmt_key("management key", mgmt_key_env.as_deref(), *mgmt_key_stdin)?;
            let bytes =
                std::fs::read(file).map_err(|e| format!("read {}: {}", file.display(), e))?;
            let der = cert_to_der(&bytes)?;
            let mut s = open_piv_authed(reader.as_deref(), debug, &mgmt)?;
            s.import_certificate(slot.to_slot(), &der)?;
            println!(
                "Imported {}-byte certificate into {}.",
                der.len(),
                slot.to_slot().label()
            );
        }

        PivCmd::ExportCert { reader, slot, file } => {
            let mut s = open_piv(reader.as_deref(), debug)?;
            match s.read_certificate(slot.to_slot())? {
                None => {
                    return Err(format!("{} holds no certificate", slot.to_slot().label()).into())
                }
                Some(der) => match file {
                    Some(path) => {
                        std::fs::write(path, &der)
                            .map_err(|e| format!("write {}: {}", path.display(), e))?;
                        eprintln!(
                            "Wrote {}-byte DER certificate to {}.",
                            der.len(),
                            path.display()
                        );
                    }
                    None => {
                        use std::io::{IsTerminal, Write};
                        // DER is binary — don't garble an interactive terminal.
                        if std::io::stdout().is_terminal() {
                            return Err("stdout is a terminal; pass --file PATH or pipe \
                                        (e.g. | openssl x509 -inform der -text)"
                                .into());
                        }
                        std::io::stdout().write_all(&der)?;
                    }
                },
            }
        }

        PivCmd::RequestCert {
            reader,
            slot,
            subject,
            pin_env,
            pin_stdin,
            file,
        } => {
            let pin = read_secret("PIN", pin_env.as_deref(), *pin_stdin)?;
            let mut s = open_piv(reader.as_deref(), debug)?;
            s.verify_pin(pin.as_bytes())?;
            eprintln!("Signing the request on the card (touch if it blinks)\u{2026}");
            let pem = s.generate_csr(slot.to_slot(), subject)?;
            match file {
                Some(path) => {
                    std::fs::write(path, pem.as_bytes())
                        .map_err(|e| format!("write {}: {}", path.display(), e))?;
                    eprintln!(
                        "Wrote certificate request for {} to {}.",
                        slot.to_slot().label(),
                        path.display()
                    );
                }
                None => print!("{}", pem),
            }
        }

        PivCmd::SelfSign {
            reader,
            slot,
            subject,
            days,
            pin_env,
            pin_stdin,
            mgmt_key_env,
            mgmt_key_stdin,
            file,
        } => {
            if *days == 0 {
                return Err("validity must be at least 1 day".into());
            }
            let mgmt = read_mgmt_key("management key", mgmt_key_env.as_deref(), *mgmt_key_stdin)?;
            let pin = read_secret("PIN", pin_env.as_deref(), *pin_stdin)?;
            // Management-key auth covers the certificate import; the PIN
            // covers the signature itself.
            let mut s = open_piv_authed(reader.as_deref(), debug, &mgmt)?;
            s.verify_pin(pin.as_bytes())?;
            eprintln!("Signing the certificate on the card (touch if it blinks)\u{2026}");
            let now = unix_now() as i64;
            let der = s.self_signed_certificate(
                slot.to_slot(),
                subject,
                now,
                now + i64::from(*days) * 86_400,
            )?;
            println!(
                "Self-signed certificate ({} bytes, {} days) created and stored in {}.",
                der.len(),
                days,
                slot.to_slot().label()
            );
            if let Some(path) = file {
                std::fs::write(path, keyroost_piv::x509::pem_certificate(&der).as_bytes())
                    .map_err(|e| format!("write {}: {}", path.display(), e))?;
                eprintln!("PEM copy written to {}.", path.display());
            }
        }

        PivCmd::Reset { reader, yes } => {
            let mut s = open_piv(reader.as_deref(), debug)?;
            let st = s.status()?;
            let serial = st
                .serial
                .map(|v| format!("serial {}", v))
                .unwrap_or_else(|| "this device".into());
            if !yes {
                return Err(format!(
                    "refusing to reset the PIV application on {} without --yes \
                     (this wipes all PIV keys, certificates, and PINs)",
                    serial
                )
                .into());
            }
            s.reset()?;
            println!("PIV application reset to factory defaults on {}.", serial);
        }

        PivCmd::DeleteCert {
            reader,
            slot,
            mgmt_key_env,
            mgmt_key_stdin,
            yes,
        } => {
            if !yes {
                return Err(format!(
                    "refusing to clear the certificate in {} without --yes \
                     (this is irreversible; the slot's private key is left in place)",
                    slot.to_slot().label()
                )
                .into());
            }
            let mgmt = read_mgmt_key("management key", mgmt_key_env.as_deref(), *mgmt_key_stdin)?;
            let mut s = open_piv_authed(reader.as_deref(), debug, &mgmt)?;
            s.clear_certificate(slot.to_slot())?;
            println!(
                "Cleared the certificate in {} (the private key remains).",
                slot.to_slot().label()
            );
        }

        PivCmd::DeleteKey {
            reader,
            slot,
            mgmt_key_env,
            mgmt_key_stdin,
            yes,
        } => {
            if !yes {
                return Err(format!(
                    "refusing to delete the private key in {} without --yes \
                     (this is irreversible; the key material cannot be recovered)",
                    slot.to_slot().label()
                )
                .into());
            }
            let mgmt = read_mgmt_key("management key", mgmt_key_env.as_deref(), *mgmt_key_stdin)?;
            let mut s = open_piv_authed(reader.as_deref(), debug, &mgmt)?;
            s.delete_key(slot.to_slot())?;
            println!(
                "Deleted the private key in {} (the certificate object, if any, remains).",
                slot.to_slot().label()
            );
        }
    }
    Ok(())
}

/// Open the OpenPGP session on the reader matching `reader` (or the sole
/// OpenPGP reader), announcing the target on stderr.
fn open_openpgp(
    reader: Option<&str>,
    debug: bool,
) -> Result<keyroost_transport::OpenPgpSession, Box<dyn std::error::Error>> {
    let readers = keyroost_transport::OpenPgpSession::list_openpgp_readers()?;
    let by_name = reader_from_name()?;
    let name = resolve_reader(readers, reader.or(by_name.as_deref()), "OpenPGP")?;
    eprintln!("\u{2192} OpenPGP on {}", name);
    let mut session = keyroost_transport::OpenPgpSession::open(&name)?;
    session.set_debug(debug);
    Ok(session)
}

/// Open the PIV session on the reader matching `reader` (or the sole PIV reader).
fn open_piv(
    reader: Option<&str>,
    debug: bool,
) -> Result<keyroost_transport::PivSession, Box<dyn std::error::Error>> {
    let readers = keyroost_transport::PivSession::list_piv_readers()?;
    let by_name = reader_from_name()?;
    let name = resolve_reader(readers, reader.or(by_name.as_deref()), "PIV")?;
    eprintln!("\u{2192} PIV on {}", name);
    let mut session = keyroost_transport::PivSession::open(&name)?;
    session.set_debug(debug);
    Ok(session)
}

/// [`open_piv`], then authenticate the management key against the card's own
/// algorithm — with a friendly wrong-length message *before* the card sees
/// anything, instead of a bare transport error afterwards.
fn open_piv_authed(
    reader: Option<&str>,
    debug: bool,
    mgmt_key: &[u8],
) -> Result<keyroost_transport::PivSession, Box<dyn std::error::Error>> {
    let mut session = open_piv(reader, debug)?;
    let alg = session.management_key_algorithm();
    if mgmt_key.len() != alg.key_len() {
        return Err(format!(
            "management key is {} bytes; this card's {} key needs {}",
            mgmt_key.len(),
            alg.label(),
            alg.key_len()
        )
        .into());
    }
    session.authenticate_management(alg, mgmt_key)?;
    Ok(session)
}

/// Read a management key (a hex string) from env/stdin and decode it to bytes.
fn read_mgmt_key(
    label: &str,
    env: Option<&str>,
    from_stdin: bool,
) -> Result<zeroize::Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
    let hex = read_secret(label, env, from_stdin)?;
    Ok(zeroize::Zeroizing::new(hex_decode(hex.trim())?))
}

/// Write `data` to `path` with owner-only permissions (0600) on Unix, so
/// secret output (decrypted plaintext, signatures) isn't left group/world
/// readable. Sets the mode even if the file already existed (mode passed to
/// `OpenOptions` only applies at creation, so re-assert it after open).
fn write_private_file(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Re-assert 0600 in case the file pre-existed with looser perms.
        let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    f.write_all(data)?;
    Ok(())
}

/// Accept a certificate as DER or PEM, returning DER bytes.
fn cert_to_der(bytes: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let text = std::str::from_utf8(bytes).unwrap_or("");
    if let Some(start) = text.find("-----BEGIN CERTIFICATE-----") {
        let after = &text[start + "-----BEGIN CERTIFICATE-----".len()..];
        let end = after
            .find("-----END CERTIFICATE-----")
            .ok_or("PEM certificate has no END marker")?;
        // A chain/bundle holds several blocks; the card slot stores one cert.
        if after[end..].contains("-----BEGIN CERTIFICATE-----") {
            eprintln!("note: file contains multiple certificates; using the first");
        }
        let b64: String = after[..end].split_whitespace().collect();
        return Ok(keyroost_proto::codec::base64_decode(&b64)?);
    }
    // Not PEM — assume DER (must at least start with a SEQUENCE tag).
    if bytes.first() != Some(&0x30) {
        return Err("certificate is neither PEM nor DER (no 0x30 SEQUENCE)".into());
    }
    Ok(bytes.to_vec())
}

/// Map an OpenPGP algorithm id (first attribute byte) to a short label.
fn algo_id_str(id: Option<u8>) -> &'static str {
    match id {
        Some(0x01) => "RSA",
        Some(0x12) => "ECDH",
        Some(0x13) => "ECDSA",
        Some(0x16) => "EdDSA",
        Some(_) => "other",
        None => "none",
    }
}

/// Print a key fingerprint, rendering an all-zero (no key) slot as "(none)".
fn print_fingerprint(label: &str, fpr: &[u8; 20]) {
    if fpr.iter().all(|&b| b == 0) {
        println!("{}: (none)", label);
    } else {
        println!("{}: {}", label, hex_encode(fpr));
    }
}

fn run_key_name(cmd: &KeyNameCmd) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        KeyNameCmd::Add { name, path } => key_name_add(name, path.as_deref()),
        KeyNameCmd::List => key_name_list(),
        KeyNameCmd::Remove { name } => key_name_remove(name),
    }
}

fn key_name_add(name: &str, path: Option<&Path>) -> Result<(), Box<dyn std::error::Error>> {
    keyroost_keyring::validate_name(name)?;
    let devices: Vec<keyroost_hid::HidDevice> = keyroost_hid::enumerate()?
        .into_iter()
        .filter(|d| d.is_fido())
        .collect();
    let mut keyring = Keyring::load_default()?;
    let dev = match path {
        Some(p) => devices
            .iter()
            .find(|d| d.path == p)
            .ok_or_else(|| format!("{} is not a connected FIDO device", p.display()))?,
        None => {
            let serials = effective_serials(&devices);
            &devices[pick_from_devices(&devices, &keyring, &serials)?]
        }
    };
    let (serial, source) = read_effective_serial(dev)?;
    let vendor = (dev.vendor_id == VID_YUBICO).then(|| "yubico".to_string());

    keyring.add(keyroost_keyring::KeyEntry {
        name: name.to_string(),
        serial: serial.clone(),
        source,
        vendor,
        aaguid: None,
        note: None,
    })?;
    // Opt-in disclosure: state plainly what is stored, and how to undo it.
    eprintln!(
        "Recording \"{}\" \u{2192} serial {} ({}).",
        name, serial, dev.product_name
    );
    eprintln!(
        "This saves the key's serial number to keys.json on this computer so the \
         key can be recognized by name later — remove it any time with \
         `keyroostctl key-name remove {}`.",
        name
    );
    let written = keyring.save_default()?;
    println!("Saved to {}", written.display());
    Ok(())
}

fn key_name_list() -> Result<(), Box<dyn std::error::Error>> {
    let keyring = Keyring::load_default()?;
    if keyring.keys.is_empty() {
        println!("(no named keys; add one with `keyroostctl key-name add <name>`)");
        return Ok(());
    }
    let devices: Vec<keyroost_hid::HidDevice> = keyroost_hid::enumerate()
        .unwrap_or_default()
        .into_iter()
        .filter(|d| d.is_fido())
        .collect();
    let connected = connected_keys(&devices);
    for k in &keyring.keys {
        let here = connected
            .iter()
            .any(|c| c.serial.as_deref() == Some(k.serial.as_str()));
        let status = if here { "connected" } else { "not connected" };
        println!("  {:<20} serial={} [{}]", k.name, k.serial, status);
    }
    Ok(())
}

fn key_name_remove(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut keyring = Keyring::load_default()?;
    if keyring.remove(name) {
        keyring.save_default()?;
        println!("Removed \"{}\".", name);
    } else {
        println!("No key named \"{}\".", name);
    }
    Ok(())
}

fn format_aaguid(aaguid: &[u8; 16]) -> String {
    // Standard UUID grouping: 8-4-4-4-12.
    let mut s = String::with_capacity(36);
    for (i, b) in aaguid.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            s.push('-');
        }
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn run_fido(cmd: &FidoCmd, debug: bool) -> Result<(), Box<dyn std::error::Error>> {
    // FIDO handlers open their own hidraw transport and don't consult the
    // shared PC/SC debug flag; accept it for signature parity with the other
    // run_* group dispatchers.
    let _ = debug;
    match cmd {
        FidoCmd::Info { path } => {
            run_fido_info(path.as_deref())?;
            Ok(())
        }
        FidoCmd::Reset { yes, path } => {
            if !*yes {
                return Err(format!(
                    "refusing to reset FIDO key without --yes (this wipes credentials){}",
                    fido_target_hint(path.as_deref())
                )
                .into());
            }
            run_fido_reset(path.as_deref())?;
            Ok(())
        }
        FidoCmd::PinRetries { path } => {
            run_fido_pin_retries(path.as_deref())?;
            Ok(())
        }
        FidoCmd::PinSet {
            new_pin_env,
            new_pin_stdin,
            path,
        } => {
            let new_pin = read_secret("new PIN", new_pin_env.as_deref(), *new_pin_stdin)?;
            run_fido_pin_set(path.as_deref(), &new_pin)?;
            Ok(())
        }
        FidoCmd::PinChange {
            old_pin_env,
            old_pin_stdin,
            new_pin_env,
            new_pin_stdin,
            path,
        } => {
            let old_pin = read_secret("old PIN", old_pin_env.as_deref(), *old_pin_stdin)?;
            let new_pin = read_secret("new PIN", new_pin_env.as_deref(), *new_pin_stdin)?;
            run_fido_pin_change(path.as_deref(), &old_pin, &new_pin)?;
            Ok(())
        }
        FidoCmd::CredsMetadata {
            pin_env,
            pin_stdin,
            path,
        } => {
            let pin = read_secret("PIN", pin_env.as_deref(), *pin_stdin)?;
            run_fido_creds_metadata(path.as_deref(), &pin)?;
            Ok(())
        }
        FidoCmd::CredsList {
            pin_env,
            pin_stdin,
            path,
        } => {
            let pin = read_secret("PIN", pin_env.as_deref(), *pin_stdin)?;
            run_fido_creds_list(path.as_deref(), &pin)?;
            Ok(())
        }
        FidoCmd::CredsDelete {
            cred_id,
            pin_env,
            pin_stdin,
            path,
        } => {
            let pin = read_secret("PIN", pin_env.as_deref(), *pin_stdin)?;
            let cred_id_bytes =
                hex_decode(cred_id).map_err(|e| format!("--cred-id is not valid hex: {}", e))?;
            run_fido_creds_delete(path.as_deref(), &pin, &cred_id_bytes)?;
            Ok(())
        }
        FidoCmd::FingerprintList {
            pin_env,
            pin_stdin,
            path,
        } => {
            let pin = read_secret("PIN", pin_env.as_deref(), *pin_stdin)?;
            run_fido_fingerprint_list(path.as_deref(), &pin)?;
            Ok(())
        }
        FidoCmd::FingerprintEnroll {
            name,
            pin_env,
            pin_stdin,
            path,
        } => {
            let pin = read_secret("PIN", pin_env.as_deref(), *pin_stdin)?;
            run_fido_fingerprint_enroll(path.as_deref(), &pin, name.as_deref())?;
            Ok(())
        }
        FidoCmd::FingerprintRename {
            template_id,
            name,
            pin_env,
            pin_stdin,
            path,
        } => {
            let pin = read_secret("PIN", pin_env.as_deref(), *pin_stdin)?;
            let id = hex_decode(template_id)
                .map_err(|e| format!("--template-id is not valid hex: {}", e))?;
            run_fido_fingerprint_rename(path.as_deref(), &pin, &id, name)?;
            Ok(())
        }
        FidoCmd::FingerprintDelete {
            template_id,
            pin_env,
            pin_stdin,
            path,
        } => {
            let pin = read_secret("PIN", pin_env.as_deref(), *pin_stdin)?;
            let id = hex_decode(template_id)
                .map_err(|e| format!("--template-id is not valid hex: {}", e))?;
            run_fido_fingerprint_delete(path.as_deref(), &pin, &id)?;
            Ok(())
        }
        FidoCmd::AlwaysUv {
            pin_env,
            pin_stdin,
            path,
        } => {
            let pin = read_secret("PIN", pin_env.as_deref(), *pin_stdin)?;
            with_configurator(path.as_deref(), &pin, |cfg| {
                cfg.toggle_always_uv()?;
                println!(
                    "Toggled \"always require user verification\". Run `fido info` to \
                     confirm the new state."
                );
                Ok(())
            })?;
            Ok(())
        }
        FidoCmd::SetMinPin {
            length,
            force_change,
            pin_env,
            pin_stdin,
            path,
        } => {
            let pin = read_secret("PIN", pin_env.as_deref(), *pin_stdin)?;
            let length = *length;
            let force_change = *force_change;
            with_configurator(path.as_deref(), &pin, move |cfg| {
                cfg.set_min_pin_length(Some(length), &[], force_change)?;
                println!(
                    "Minimum PIN length set to {length}.{}",
                    if force_change {
                        " A PIN change is now required on next use."
                    } else {
                        ""
                    }
                );
                Ok(())
            })?;
            Ok(())
        }
        FidoCmd::ForcePinChange {
            pin_env,
            pin_stdin,
            path,
        } => {
            let pin = read_secret("PIN", pin_env.as_deref(), *pin_stdin)?;
            with_configurator(path.as_deref(), &pin, |cfg| {
                cfg.force_pin_change()?;
                println!("A PIN change is now required on next use of this key.");
                Ok(())
            })?;
            Ok(())
        }
        FidoCmd::EnterpriseAttestation {
            pin_env,
            pin_stdin,
            path,
        } => {
            let pin = read_secret("PIN", pin_env.as_deref(), *pin_stdin)?;
            with_configurator(path.as_deref(), &pin, |cfg| {
                cfg.enable_enterprise_attestation()?;
                println!("Enterprise attestation enabled. Disabling it again requires a reset.");
                Ok(())
            })?;
            Ok(())
        }
        FidoCmd::LargeBlob { cmd } => run_fido_large_blob(cmd),
    }
}

fn run_fido_large_blob(cmd: &LargeBlobCmd) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        LargeBlobCmd::List { path } => run_fido_large_blob_list(path.as_deref()),
        LargeBlobCmd::Get { index, path } => run_fido_large_blob_get(path.as_deref(), *index),
        LargeBlobCmd::Add {
            text,
            pin_env,
            pin_stdin,
            path,
        } => {
            let pin = read_secret("PIN", pin_env.as_deref(), *pin_stdin)?;
            run_fido_large_blob_add(path.as_deref(), &pin, text)
        }
        LargeBlobCmd::Edit {
            index,
            text,
            pin_env,
            pin_stdin,
            path,
        } => {
            let pin = read_secret("PIN", pin_env.as_deref(), *pin_stdin)?;
            run_fido_large_blob_edit(path.as_deref(), &pin, *index, text)
        }
        LargeBlobCmd::Delete {
            index,
            yes,
            pin_env,
            pin_stdin,
            path,
        } => {
            let pin = read_secret("PIN", pin_env.as_deref(), *pin_stdin)?;
            run_fido_large_blob_delete(path.as_deref(), &pin, *index, *yes)
        }
        LargeBlobCmd::Clear {
            yes,
            pin_env,
            pin_stdin,
            path,
        } => {
            let pin = read_secret("PIN", pin_env.as_deref(), *pin_stdin)?;
            run_fido_large_blob_clear(path.as_deref(), &pin, *yes)
        }
    }
}

/// Open a FIDO authenticator and read its large-blob array (no PIN required).
/// Returns the live device + info too, so a writer can reuse the same session
/// after re-reading.
fn open_and_read_large_blobs(
    path: Option<&std::path::Path>,
) -> Result<
    (
        keyroost_ctap::CtapHidDevice,
        keyroost_ctap::AuthenticatorInfo,
        keyroost_ctap::large_blobs::LargeBlobArray,
    ),
    Box<dyn std::error::Error>,
> {
    let path = resolve_fido_path(path)?;
    let (mut dev, init) = keyroost_ctap::CtapHidDevice::open(&path)?;
    if !init.supports_cbor() {
        return Err("device is U2F-only; CTAP2 large blobs not supported".into());
    }
    let info = keyroost_ctap::get_info(&mut dev)?;
    let array = keyroost_ctap::large_blobs::read(&mut dev, &info)?;
    Ok((dev, info, array))
}

/// Shape a parsed large-blob array into the JSON `list` view.
fn large_blob_list_json(
    array: &keyroost_ctap::large_blobs::LargeBlobArray,
) -> json_out::FidoLargeBlobListJson {
    let entries = array
        .entries
        .iter()
        .enumerate()
        .map(|(index, e)| json_out::FidoLargeBlobEntryJson {
            index,
            size: e.orig_size,
            is_note: e.is_kr_note(),
            text: e.as_text(),
        })
        .collect();
    json_out::FidoLargeBlobListJson { entries }
}

fn run_fido_large_blob_list(
    path: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (_dev, _info, array) = open_and_read_large_blobs(path)?;
    if json_output() {
        emit_json(&large_blob_list_json(&array))?;
        return Ok(());
    }
    if array.entries.is_empty() {
        println!("(large-blob array is empty)");
        return Ok(());
    }
    for (i, e) in array.entries.iter().enumerate() {
        if let Some(text) = e.as_text() {
            println!(
                "[{}] {} bytes  note      {}",
                i,
                e.orig_size,
                preview_note(&text)
            );
        } else {
            println!(
                "[{}] {} bytes  opaque    {}",
                i,
                e.orig_size,
                preview_opaque(&e.ciphertext)
            );
        }
    }
    Ok(())
}

fn run_fido_large_blob_get(
    path: Option<&std::path::Path>,
    index: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let (_dev, _info, array) = open_and_read_large_blobs(path)?;
    let entry = array
        .entries
        .get(index)
        .ok_or_else(|| large_blob_bad_index(index, array.entries.len()))?;
    if json_output() {
        emit_json(&json_out::FidoLargeBlobGetJson {
            index,
            size: entry.orig_size,
            is_note: entry.is_kr_note(),
            text: entry.as_text(),
            hex: hex_encode(&entry.ciphertext),
        })?;
        return Ok(());
    }
    if let Some(text) = entry.as_text() {
        println!("Entry {}: keyroost note, {} bytes", index, entry.orig_size);
        println!("{}", text);
    } else {
        println!(
            "Entry {}: opaque (RP-encrypted), {} bytes",
            index, entry.orig_size
        );
        println!();
        print!("{}", hex_ascii_dump(&entry.ciphertext));
    }
    Ok(())
}

fn run_fido_large_blob_add(
    path: Option<&std::path::Path>,
    pin: &str,
    text: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Re-read the live array immediately before writing so any concurrent or
    // pre-existing RP entries are preserved (mirror the GUI's add flow).
    let (mut dev, info, current) = open_and_read_large_blobs(path)?;
    let token = keyroost_ctap::client_pin::get_pin_uv_auth_token(
        &mut dev,
        pin,
        &info,
        keyroost_ctap::client_pin::permissions::LARGE_BLOB_WRITE,
    )?;
    let updated = current.with_text_note(text);
    let serialized = updated.serialize_with_checksum();
    keyroost_ctap::large_blobs::write(&mut dev, &info, &token, &serialized)?;
    println!("Note added; {} entries now.", updated.entries.len());
    Ok(())
}

fn run_fido_large_blob_edit(
    path: Option<&std::path::Path>,
    pin: &str,
    index: usize,
    text: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut dev, info, current) = open_and_read_large_blobs(path)?;
    let updated = current.with_replaced_note(index, text).ok_or_else(|| {
        format!(
            "entry {} is not a keyroost note (can't edit an RP-encrypted entry)",
            index
        )
    })?;
    let token = keyroost_ctap::client_pin::get_pin_uv_auth_token(
        &mut dev,
        pin,
        &info,
        keyroost_ctap::client_pin::permissions::LARGE_BLOB_WRITE,
    )?;
    let serialized = updated.serialize_with_checksum();
    keyroost_ctap::large_blobs::write(&mut dev, &info, &token, &serialized)?;
    println!("Note {} updated.", index);
    Ok(())
}

fn run_fido_large_blob_delete(
    path: Option<&std::path::Path>,
    pin: &str,
    index: usize,
    yes: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut dev, info, current) = open_and_read_large_blobs(path)?;
    let entry = current
        .entries
        .get(index)
        .ok_or_else(|| large_blob_bad_index(index, current.entries.len()))?;
    if !entry.is_kr_note() {
        // Opaque RP-owned entry: deleting it can break the owning service.
        if !yes {
            return Err(format!(
                "REFUSING to delete entry {idx}: it was NOT created by keyroost \
                 (it is an opaque, RP-encrypted record). Deleting it may break a \
                 service that stored it. Re-run with --yes to delete it anyway.",
                idx = index
            )
            .into());
        }
        eprintln!(
            "WARNING: entry {} was not created by keyroost; deleting it may break a \
             service that stored it.",
            index
        );
    } else if !yes {
        return Err(format!("refusing to delete entry {} without --yes", index).into());
    }

    let mut entries = current.entries.clone();
    entries.remove(index);
    let updated = keyroost_ctap::large_blobs::LargeBlobArray {
        entries,
        raw_array: Vec::new(),
    };
    let token = keyroost_ctap::client_pin::get_pin_uv_auth_token(
        &mut dev,
        pin,
        &info,
        keyroost_ctap::client_pin::permissions::LARGE_BLOB_WRITE,
    )?;
    let serialized = updated.serialize_with_checksum();
    keyroost_ctap::large_blobs::write(&mut dev, &info, &token, &serialized)?;
    println!("Entry deleted; {} entries now.", updated.entries.len());
    Ok(())
}

fn run_fido_large_blob_clear(
    path: Option<&std::path::Path>,
    pin: &str,
    yes: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Re-read first so we can report exactly what will be wiped.
    let (mut dev, info, current) = open_and_read_large_blobs(path)?;
    let total = current.entries.len();
    let opaque = current.entries.iter().filter(|e| !e.is_kr_note()).count();
    if !yes {
        eprintln!(
            "WARNING: `clear` erases the ENTIRE large-blob array — ALL {total} \
             entr{plural} ({opaque} opaque/RP-owned, e.g. stored SSH certs). This \
             can break any service that stored data here.",
            total = total,
            plural = if total == 1 { "y" } else { "ies" },
            opaque = opaque,
        );
        return Err("refusing to clear the large-blob array without --yes".into());
    }
    if opaque > 0 {
        eprintln!(
            "WARNING: wiping {} opaque/RP-owned entr{} along with everything else.",
            opaque,
            if opaque == 1 { "y" } else { "ies" }
        );
    }
    let token = keyroost_ctap::client_pin::get_pin_uv_auth_token(
        &mut dev,
        pin,
        &info,
        keyroost_ctap::client_pin::permissions::LARGE_BLOB_WRITE,
    )?;
    let serialized = keyroost_ctap::large_blobs::empty_array_serialized();
    keyroost_ctap::large_blobs::write(&mut dev, &info, &token, &serialized)?;
    println!("Large-blob array cleared ({} entries wiped).", total);
    Ok(())
}

/// A consistent "index out of range" error for the large-blob commands.
fn large_blob_bad_index(index: usize, len: usize) -> Box<dyn std::error::Error> {
    if len == 0 {
        format!("no entry {} — the large-blob array is empty", index).into()
    } else {
        format!("no entry {} — valid indices are 0..={}", index, len - 1).into()
    }
}

/// A short, single-line preview of a note's text for the `list` view.
fn preview_note(text: &str) -> String {
    const MAX: usize = 48;
    let one_line: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let trimmed = one_line.trim();
    let mut out: String = trimmed.chars().take(MAX).collect();
    if trimmed.chars().count() > MAX {
        out.push('…');
    }
    out
}

/// A short hex head of an opaque entry's ciphertext for the `list` view.
fn preview_opaque(bytes: &[u8]) -> String {
    const HEAD: usize = 12;
    let mut s = String::new();
    for b in bytes.iter().take(HEAD) {
        s.push_str(&format!("{:02x}", b));
    }
    if bytes.len() > HEAD {
        s.push('…');
    }
    if s.is_empty() {
        "(empty)".to_owned()
    } else {
        s
    }
}

/// A classic hex + ASCII dump (16 bytes per row) for the `get` view of an
/// opaque entry.
fn hex_ascii_dump(bytes: &[u8]) -> String {
    let mut out = String::new();
    for (row, chunk) in bytes.chunks(16).enumerate() {
        let mut hex = String::new();
        let mut ascii = String::new();
        for (i, b) in chunk.iter().enumerate() {
            hex.push_str(&format!("{:02x} ", b));
            if i == 7 {
                hex.push(' ');
            }
            ascii.push(if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '.'
            });
        }
        out.push_str(&format!("{:08x}  {:<49}|{}|\n", row * 16, hex, ascii));
    }
    out
}

fn run_fido_info(path: Option<&std::path::Path>) -> Result<(), Box<dyn std::error::Error>> {
    let path = resolve_fido_path(path)?;
    let (mut dev, init) = keyroost_ctap::CtapHidDevice::open(&path)?;
    let json = json_output();
    let mut caps = Vec::new();
    if init.supports_wink() {
        caps.push("WINK");
    }
    if init.supports_cbor() {
        caps.push("CBOR");
    }
    if init.supports_u2f() {
        caps.push("U2F");
    }
    if !json {
        println!("Device:    {}", path.display());
        println!(
            "Channel:   {:#010x} (CTAPHID protocol v{})",
            init.channel_id, init.protocol_version
        );
        println!(
            "Firmware:  {}.{}.{}",
            init.device_major, init.device_minor, init.device_build
        );
        println!(
            "Caps:      {} (raw 0x{:02X})",
            caps.join("+"),
            init.capabilities
        );
    }

    if !init.supports_cbor() {
        if json {
            emit_json(&json_out::FidoInfoJson {
                device: path.display().to_string(),
                channel_id: init.channel_id,
                ctaphid_protocol_version: init.protocol_version,
                firmware: format!(
                    "{}.{}.{}",
                    init.device_major, init.device_minor, init.device_build
                ),
                hid_caps: caps,
                hid_caps_raw: init.capabilities,
                ctap2: None,
            })?;
            return Ok(());
        }
        println!();
        println!("(device is U2F-only; CTAP2 GetInfo not available)");
        return Ok(());
    }

    let info = keyroost_ctap::get_info(&mut dev)?;

    if json {
        emit_json(&json_out::FidoInfoJson {
            device: path.display().to_string(),
            channel_id: init.channel_id,
            ctaphid_protocol_version: init.protocol_version,
            firmware: format!(
                "{}.{}.{}",
                init.device_major, init.device_minor, init.device_build
            ),
            hid_caps: caps,
            hid_caps_raw: init.capabilities,
            ctap2: Some(json_out::Ctap2InfoJson {
                versions: info.versions.clone(),
                extensions: info.extensions.clone(),
                aaguid: format_aaguid(&info.aaguid),
                options: info
                    .options
                    .iter()
                    .map(|(k, v)| json_out::OptionJson {
                        name: k.clone(),
                        value: *v,
                    })
                    .collect(),
                max_msg_size: info.max_msg_size,
                pin_uv_auth_protocols: info.pin_uv_auth_protocols.clone(),
                transports: info.transports.clone(),
                min_pin_length: info.min_pin_length,
                force_pin_change: info.force_pin_change,
                firmware_version: info.firmware_version,
            }),
        })?;
        return Ok(());
    }

    println!();
    println!("Versions:  {}", info.versions.join(", "));
    if !info.extensions.is_empty() {
        println!("Extensions: {}", info.extensions.join(", "));
    }
    println!("AAGUID:    {}", format_aaguid(&info.aaguid));
    if !info.options.is_empty() {
        let opts: Vec<String> = info
            .options
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect();
        println!("Options:   {}", opts.join(", "));
    }
    if let Some(n) = info.max_msg_size {
        println!("MaxMsgSize: {}", n);
    }
    if !info.pin_uv_auth_protocols.is_empty() {
        let v: Vec<String> = info
            .pin_uv_auth_protocols
            .iter()
            .map(|n| n.to_string())
            .collect();
        println!("PIN/UV protocols: {}", v.join(", "));
    }
    if !info.transports.is_empty() {
        println!("Transports: {}", info.transports.join(", "));
    }
    if let Some(n) = info.min_pin_length {
        println!("Min PIN length: {}", n);
    }
    if info.force_pin_change == Some(true) {
        println!("Force PIN change: yes");
    }
    if let Some(v) = info.firmware_version {
        println!("CTAP fwVer: {}", v);
    }
    Ok(())
}

fn run_fido_reset(path: Option<&std::path::Path>) -> Result<(), Box<dyn std::error::Error>> {
    let path = resolve_fido_path(path)?;
    let (mut dev, _init) = keyroost_ctap::CtapHidDevice::open(&path)?;
    println!("Resetting {} — touch the key now…", path.display());
    keyroost_ctap::reset(&mut dev)?;
    println!("Reset complete. All credentials wiped, PIN cleared.");
    Ok(())
}

fn run_fido_pin_retries(path: Option<&std::path::Path>) -> Result<(), Box<dyn std::error::Error>> {
    let path = resolve_fido_path(path)?;
    let (mut dev, _) = keyroost_ctap::CtapHidDevice::open(&path)?;
    let n = keyroost_ctap::client_pin::get_pin_retries(&mut dev)?;
    if json_output() {
        emit_json(&json_out::FidoPinRetriesJson { pin_retries: n })?;
        return Ok(());
    }
    println!("{} PIN attempt(s) remaining", n);
    Ok(())
}

fn run_fido_pin_set(
    path: Option<&std::path::Path>,
    new_pin: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = resolve_fido_path(path)?;
    let (mut dev, _) = keyroost_ctap::CtapHidDevice::open(&path)?;
    keyroost_ctap::client_pin::set_pin(&mut dev, new_pin)?;
    println!("PIN set.");
    Ok(())
}

fn run_fido_pin_change(
    path: Option<&std::path::Path>,
    old_pin: &str,
    new_pin: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = resolve_fido_path(path)?;
    let (mut dev, _) = keyroost_ctap::CtapHidDevice::open(&path)?;
    keyroost_ctap::client_pin::change_pin(&mut dev, old_pin, new_pin)?;
    println!("PIN changed.");
    Ok(())
}

fn run_fido_creds_metadata(
    path: Option<&std::path::Path>,
    pin: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    with_credential_manager(path, pin, |mgr| {
        let meta = mgr.metadata()?;
        if json_output() {
            emit_json(&json_out::FidoCredsMetadataJson {
                existing_resident_credentials: meta.existing_count,
                max_possible_remaining: meta.max_remaining,
            })?;
            return Ok(());
        }
        println!(
            "{} resident credential(s) stored, room for {} more",
            meta.existing_count, meta.max_remaining
        );
        Ok(())
    })
}

fn run_fido_creds_list(
    path: Option<&std::path::Path>,
    pin: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    with_credential_manager(path, pin, |mgr| {
        let rps = mgr.list_relying_parties()?;
        if json_output() {
            let mut relying_parties = Vec::with_capacity(rps.len());
            for rp in &rps {
                let creds = mgr.list_credentials(&rp.rp_id_hash)?;
                let credentials = creds
                    .iter()
                    .map(|c| json_out::FidoCredentialJson {
                        credential_id: hex_encode(&c.credential_id),
                        user_id: String::from_utf8_lossy(&c.user.id).into_owned(),
                        user_name: c.user.name.clone(),
                        user_display_name: c.user.display_name.clone(),
                        algorithm: c.algorithm,
                        algorithm_name: c.algorithm.map(cose_algorithm_name),
                    })
                    .collect();
                relying_parties.push(json_out::FidoRelyingPartyJson {
                    rp_id: rp.id.clone(),
                    rp_name: rp.name.clone().filter(|n| !n.is_empty()),
                    credentials,
                });
            }
            emit_json(&json_out::FidoCredsListJson { relying_parties })?;
            return Ok(());
        }
        if rps.is_empty() {
            println!("(no resident credentials)");
            return Ok(());
        }
        for rp in &rps {
            let creds = mgr.list_credentials(&rp.rp_id_hash)?;
            let name_suffix = match &rp.name {
                Some(n) if !n.is_empty() => format!("  ({})", n),
                _ => String::new(),
            };
            let count_suffix = if creds.is_empty() {
                "  (no credentials)".to_owned()
            } else {
                format!("  [{} credential(s)]", creds.len())
            };
            println!("{}{}{}", rp.id, name_suffix, count_suffix);
            for c in &creds {
                let name_field = match &c.user.name {
                    Some(n) => format!("  name={:?}", n),
                    None => String::new(),
                };
                let display_field = match &c.user.display_name {
                    Some(d) => format!("  display={:?}", d),
                    None => String::new(),
                };
                println!(
                    "  cred {}: user {:?}{}{}",
                    hex_short(&c.credential_id),
                    String::from_utf8_lossy(&c.user.id),
                    name_field,
                    display_field,
                );
                // Full credentialId on its own line: this is the exact value
                // `fido-creds-delete --cred-id` expects (the `cred …` summary
                // above is truncated for readability and can't be copied).
                println!("       id={}", hex_encode(&c.credential_id));
                if let Some(alg) = c.algorithm {
                    println!("       alg={} ({})", alg, cose_algorithm_name(alg));
                }
            }
        }
        Ok(())
    })
}

fn run_fido_creds_delete(
    path: Option<&std::path::Path>,
    pin: &str,
    cred_id: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    with_credential_manager(path, pin, |mgr| {
        mgr.delete(cred_id)?;
        println!("Credential {} deleted.", hex_short(cred_id));
        Ok(())
    })
}

fn run_fido_fingerprint_list(
    path: Option<&std::path::Path>,
    pin: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    with_bio_enrollment(path, pin, |bio| {
        let list = bio.enumerate()?;
        if list.is_empty() {
            println!("(no fingerprints enrolled)");
            return Ok(());
        }
        println!("Enrolled fingerprints:");
        for e in &list {
            let name = e.friendly_name.as_deref().unwrap_or("(unnamed)");
            // The hex template id is what --template-id takes for rename/delete.
            println!("  id {}   {}", hex_encode(&e.template_id), name);
        }
        println!("(use the id with --template-id to rename or delete)");
        Ok(())
    })
}

fn run_fido_fingerprint_enroll(
    path: Option<&std::path::Path>,
    pin: &str,
    name: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    use keyroost_ctap::bio_enroll::sample_status_message;
    with_bio_enrollment(path, pin, |bio| {
        if let Ok(info) = bio.sensor_info() {
            if info.max_capture_samples > 0 {
                println!(
                    "Enrolling a fingerprint ({} good samples needed).",
                    info.max_capture_samples
                );
            }
        }
        println!("Touch the sensor now\u{2026}");
        let (template_id, mut status) = bio.enroll_begin(None)?;
        println!("  {}", sample_status_message(status.last_sample_status));
        // Capture until the device says no samples remain.
        while status.remaining_samples > 0 {
            println!(
                "  {} more sample(s) needed \u{2014} touch the sensor again\u{2026}",
                status.remaining_samples
            );
            status = bio.enroll_capture_next(&template_id, None)?;
            println!("  {}", sample_status_message(status.last_sample_status));
        }
        // Optionally name it once enrolled.
        if let Some(n) = name {
            bio.set_friendly_name(&template_id, n)?;
        }
        println!(
            "Fingerprint enrolled: {}{}",
            hex_encode(&template_id),
            name.map(|n| format!("  ({})", n)).unwrap_or_default()
        );
        Ok(())
    })
}

fn run_fido_fingerprint_rename(
    path: Option<&std::path::Path>,
    pin: &str,
    template_id: &[u8],
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    with_bio_enrollment(path, pin, |bio| {
        bio.set_friendly_name(template_id, name)?;
        println!("Renamed {} to \"{}\".", hex_short(template_id), name);
        Ok(())
    })
}

fn run_fido_fingerprint_delete(
    path: Option<&std::path::Path>,
    pin: &str,
    template_id: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    with_bio_enrollment(path, pin, |bio| {
        bio.remove_enrollment(template_id)?;
        println!("Fingerprint {} deleted.", hex_short(template_id));
        Ok(())
    })
}

/// Open a hidraw device, fetch GetInfo, exchange PIN/UV auth, and hand a
/// fully-armed `CredentialManager` to the caller. Avoids a self-referential
/// return type by keeping the device on the stack and using a closure.
fn with_credential_manager<F>(
    path: Option<&std::path::Path>,
    pin: &str,
    f: F,
) -> Result<(), Box<dyn std::error::Error>>
where
    F: for<'a> FnOnce(
        &mut keyroost_ctap::cred_mgmt::CredentialManager<'a, keyroost_ctap::CtapHidDevice>,
    ) -> Result<(), Box<dyn std::error::Error>>,
{
    let path = resolve_fido_path(path)?;
    let (mut dev, init) = keyroost_ctap::CtapHidDevice::open(&path)?;
    if !init.supports_cbor() {
        return Err("device is U2F-only; CTAP2 credential management not supported".into());
    }
    let info = keyroost_ctap::get_info(&mut dev)?;
    let token = keyroost_ctap::client_pin::get_pin_uv_auth_token(
        &mut dev,
        pin,
        &info,
        keyroost_ctap::client_pin::permissions::CREDENTIAL_MANAGEMENT,
    )?;
    let mut mgr = keyroost_ctap::cred_mgmt::CredentialManager::new(&mut dev, token, &info)?;
    f(&mut mgr)
}

/// Open a FIDO device and hand the caller an armed `BioEnrollment` session,
/// mirroring `with_credential_manager`. Selects the standard (0x09) or preview
/// (0x40) command byte based on what the authenticator advertises.
fn with_bio_enrollment<F>(
    path: Option<&std::path::Path>,
    pin: &str,
    f: F,
) -> Result<(), Box<dyn std::error::Error>>
where
    F: for<'a> FnOnce(
        &mut keyroost_ctap::bio_enroll::BioEnrollment<'a, keyroost_ctap::CtapHidDevice>,
    ) -> Result<(), Box<dyn std::error::Error>>,
{
    let path = resolve_fido_path(path)?;
    let (mut dev, init) = keyroost_ctap::CtapHidDevice::open(&path)?;
    if !init.supports_cbor() {
        return Err("device is U2F-only; CTAP2 bio enrollment not supported".into());
    }
    let info = keyroost_ctap::get_info(&mut dev)?;
    // Pick the command byte from what the authenticator advertises. The option
    // value is Some(true) (enrolled), Some(false) (supported, none enrolled), or
    // None (not present). For *either* state the feature is supported, so test
    // `.is_some()` per option — but choose the command byte that matches which
    // option name the key actually lists, since a key supports exactly one.
    let has_standard = info.option("bioEnroll").is_some();
    let has_preview = info.option("userVerificationMgmtPreview").is_some();
    let cmd_code = if has_standard {
        keyroost_ctap::bio_enroll::CTAP2_BIO_ENROLLMENT
    } else if has_preview {
        keyroost_ctap::bio_enroll::CTAP2_BIO_ENROLLMENT_PREVIEW
    } else {
        return Err("this authenticator does not advertise fingerprint enrollment".into());
    };
    let token = keyroost_ctap::client_pin::get_pin_uv_auth_token(
        &mut dev,
        pin,
        &info,
        keyroost_ctap::client_pin::permissions::BIO_ENROLLMENT,
    )?;
    let mut bio = keyroost_ctap::bio_enroll::BioEnrollment::new(&mut dev, token, cmd_code);
    f(&mut bio)
}

/// Open the FIDO device, obtain a pinUvAuthToken with the AuthenticatorConfig
/// permission, and run `f` with a [`Configurator`]. Mirrors
/// [`with_bio_enrollment`] for the `authenticatorConfig` (0x0D) command family.
fn with_configurator<F>(
    path: Option<&std::path::Path>,
    pin: &str,
    f: F,
) -> Result<(), Box<dyn std::error::Error>>
where
    F: for<'a> FnOnce(
        &mut keyroost_ctap::config::Configurator<'a, keyroost_ctap::CtapHidDevice>,
    ) -> Result<(), Box<dyn std::error::Error>>,
{
    let path = resolve_fido_path(path)?;
    let (mut dev, init) = keyroost_ctap::CtapHidDevice::open(&path)?;
    if !init.supports_cbor() {
        return Err("device is U2F-only; CTAP2 authenticatorConfig not supported".into());
    }
    let info = keyroost_ctap::get_info(&mut dev)?;
    if info.option("authnrCfg") != Some(true) {
        return Err("this authenticator does not advertise authenticatorConfig support".into());
    }
    let token = keyroost_ctap::client_pin::get_pin_uv_auth_token(
        &mut dev,
        pin,
        &info,
        keyroost_ctap::client_pin::permissions::AUTHENTICATOR_CONFIGURATION,
    )?;
    let mut cfg = keyroost_ctap::config::Configurator::new(&mut dev, token, &info)?;
    f(&mut cfg)
}

/// How a seed/key option was supplied: literal argv value, env var name, or
/// stdin. Used by `gather_secret` to enforce exactly-one-source.
enum SecretSource<'a> {
    Literal(&'a str),
    Env(&'a str),
    Stdin,
}

enum SecretEncoding {
    Hex,
    Base32,
    Ascii,
}

/// Resolve a secret offered through several mutually-exclusive CLI options
/// (argv literal / env var / stdin, each with an encoding) into raw bytes.
/// `supplied` holds only the options the user actually passed.
fn gather_secret(
    cmd: &str,
    sources_hint: &str,
    supplied: Vec<(SecretEncoding, SecretSource)>,
) -> Result<zeroize::Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
    if supplied.len() != 1 {
        return Err(format!("{} requires exactly one of {}", cmd, sources_hint).into());
    }
    let (encoding, source) = supplied.into_iter().next().unwrap();
    let raw = zeroize::Zeroizing::new(match source {
        SecretSource::Literal(s) => s.to_owned(),
        SecretSource::Env(var) => {
            std::env::var(var).map_err(|_| format!("env var {} (for {}) is not set", var, cmd))?
        }
        SecretSource::Stdin => {
            use std::io::{BufRead, IsTerminal};
            let stdin = std::io::stdin();
            if stdin.is_terminal() {
                eprintln!(
                    "warning: reading the {} secret from a terminal — input will be \
                     visible; prefer piping (e.g. from a password manager)",
                    cmd
                );
            }
            // The raw line buffer holds the secret too — wipe it on drop.
            let mut line = zeroize::Zeroizing::new(String::new());
            stdin.lock().read_line(&mut line)?;
            line.trim_end_matches(['\r', '\n']).to_owned()
        }
    });
    Ok(zeroize::Zeroizing::new(match encoding {
        SecretEncoding::Hex => hex_decode(&raw)?,
        SecretEncoding::Base32 => base32_decode(&raw)?,
        SecretEncoding::Ascii => raw.as_bytes().to_vec(),
    }))
}

/// Returned wrapped in `Zeroizing` so the PIN/password is scrubbed from the
/// heap when the caller's binding drops; `Deref` keeps call sites unchanged.
fn read_secret(
    label: &str,
    env: Option<&str>,
    from_stdin: bool,
) -> Result<zeroize::Zeroizing<String>, Box<dyn std::error::Error>> {
    if let Some(var) = env {
        return std::env::var(var)
            .map(zeroize::Zeroizing::new)
            .map_err(|_| format!("env var {} (for {}) is not set", var, label).into());
    }
    if from_stdin {
        use std::io::{BufRead, IsTerminal};
        let stdin = std::io::stdin();
        // The --*-stdin flags are meant for piping. Typed at a terminal the
        // value echoes (and lands in scrollback); warn rather than refuse so
        // one-off interactive use still works.
        if stdin.is_terminal() {
            eprintln!(
                "warning: reading {} from a terminal — input will be visible; \
                 prefer piping (e.g. from a password manager)",
                label
            );
        }
        // The raw line buffer holds the secret too — wipe it on drop.
        let mut line = zeroize::Zeroizing::new(String::new());
        stdin.lock().read_line(&mut line)?;
        return Ok(zeroize::Zeroizing::new(
            line.trim_end_matches(['\r', '\n']).to_owned(),
        ));
    }
    Err(format!(
        "no source for {}: pass --{}env VAR or --{}stdin",
        label,
        env_prefix_for(label),
        env_prefix_for(label),
    )
    .into())
}

fn env_prefix_for(label: &str) -> &'static str {
    match label {
        "PIN" | "OpenPGP PIN" | "signing PIN (PW1)" | "user PIN (PW1)" => "pin-",
        "new PIN" => "new-pin-",
        "old PIN" => "old-pin-",
        "PUK" => "puk-",
        "new PUK" => "new-puk-",
        "old PUK" => "old-puk-",
        "management key" => "mgmt-key-",
        "old management key" => "old-mgmt-key-",
        "new management key" => "new-mgmt-key-",
        "admin PIN (PW3)" => "admin-pin-",
        "secret" => "secret-",
        "OATH password" => "password-",
        "new OATH password" => "new-password-",
        // A label without a mapping would render a broken hint ("--env VAR");
        // fall back to something generic rather than nothing.
        _ => "…-",
    }
}

fn hex_short(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes.iter().take(8) {
        s.push_str(&format!("{:02x}", b));
    }
    if bytes.len() > 8 {
        s.push('…');
    }
    s
}

fn cose_algorithm_name(alg: i64) -> &'static str {
    // Just the common FIDO2 algorithm IDs; unknown values get a generic label.
    match alg {
        -7 => "ES256",
        -8 => "EdDSA",
        -35 => "ES384",
        -36 => "ES512",
        -257 => "RS256",
        _ => "unknown",
    }
}

/// INS bytes whose effect is known to be destructive or mutating.
/// Skipped by `probe` unless `--include-destructive` is set.
const DESTRUCTIVE_INS: &[u8] = &[
    0xC5, // set seed
    0xD5, // set title
    0xD4, // set config / sync time
    0xD7, // set customer key
    0xCE, // answer challenge (consumes an auth attempt)
    0x56, // factory reset
    0xD8, // lock / unlock screen
];

fn run_probe(session: &mut Session, authed: bool, include_destructive: bool, slot: u8) {
    use keyroost_proto::apdu::{build_apdu_get, CLA_PLAIN, CLA_SECURE};
    use keyroost_proto::commands::{sw_awaiting_button, sw_completed, Command};

    // Known interesting status word categories. We treat anything that's not
    // "instruction not supported" or "class not supported" as worth surfacing.
    fn classify(sw1: u8, sw2: u8, data_len: usize) -> Option<&'static str> {
        if sw_completed(sw1, sw2) {
            return Some(if data_len > 0 {
                "✓ ok (data)"
            } else {
                "✓ ok (empty)"
            });
        }
        if sw_awaiting_button(sw1, sw2) {
            return Some("⏵ awaiting button (mutating!)");
        }
        match (sw1, sw2) {
            (0x6D, 0x00) | (0x6E, 0x00) => None, // INS/CLA not supported — boring
            (0x6C, _) => Some("Le wrong (retry with this length)"),
            (0x6B, _) => Some("P1/P2 wrong (command may exist)"),
            (0x67, _) => Some("Lc wrong"),
            (0x69, 0x82) => Some("security: needs auth"),
            (0x69, 0x83) => Some("security: auth blocked"),
            (0x69, 0x85) => Some("conditions of use not satisfied"),
            (0x6A, 0x80) => Some("wrong data"),
            (0x6A, 0x82) => Some("file not found"),
            (0x6A, 0x86) => Some("incorrect P1/P2"),
            (0x6A, 0x88) => Some("referenced data not found"),
            _ => Some("(other)"),
        }
    }

    let probe_one = |session: &mut Session, cla: u8, ins: u8, p1: u8, p2: u8| {
        let cmd = Command {
            label: "probe",
            apdu: build_apdu_get(cla, ins, p1, p2, 0x00),
        };
        match session.transmit_raw(&cmd) {
            Ok((data, sw1, sw2)) => {
                if let Some(note) = classify(sw1, sw2, data.len()) {
                    println!(
                        "  CLA={:02X} INS={:02X} P1={:02X} P2={:02X} Le=00  →  SW={:02X}{:02X}  ({} bytes)  {}",
                        cla, ins, p1, p2, sw1, sw2, data.len(), note
                    );
                }
            }
            Err(e) => eprintln!(
                "  CLA={:02X} INS={:02X} P1={:02X} P2={:02X} Le=00  →  transmit error: {}",
                cla, ins, p1, p2, e
            ),
        }
    };

    let safe = |ins: u8| include_destructive || !DESTRUCTIVE_INS.contains(&ins);

    println!();
    println!("── Phase 1: CLA 0x80 INS sweep, P1=00 P2=00 Le=00 ──");
    for ins in 0u8..=0xFF {
        if !safe(ins) {
            continue;
        }
        probe_one(session, CLA_PLAIN, ins, 0x00, 0x00);
    }

    if authed {
        println!();
        println!(
            "── Phase 2: CLA 0x84 INS sweep, P1=00 P2={:02X} Le=00 ──",
            slot
        );
        for ins in 0u8..=0xFF {
            if !safe(ins) {
                continue;
            }
            probe_one(session, CLA_SECURE, ins, 0x00, slot);
        }

        println!();
        println!(
            "── Phase 3: targeted read-back guesses on slot #{} ──",
            slot
        );
        // Pair each known write-INS with a plausible "read" counterpart and
        // also try the same INS with P1 toggled (the device sometimes uses
        // P1=00 for read, P1=01 for write or vice versa).
        let pairs: &[(u8, u8, u8, &str)] = &[
            (CLA_SECURE, 0xC5, 0x00, "read seed? (write is P1=01)"),
            (CLA_SECURE, 0xD5, 0x01, "read title? (write is P1=00)"),
            (CLA_SECURE, 0xD4, 0x00, "read config? (write is P1=01)"),
            (CLA_PLAIN, 0xB0, 0x00, "ISO READ BINARY"),
            (CLA_PLAIN, 0xCA, 0x00, "ISO GET DATA (even)"),
            (CLA_PLAIN, 0xCB, 0x00, "ISO GET DATA (odd)"),
            (CLA_PLAIN, 0xB2, 0x01, "ISO READ RECORD"),
            (CLA_PLAIN, 0xA4, 0x00, "ISO SELECT FILE"),
        ];
        for (cla, ins, p1, note) in pairs {
            print!("  [{}] ", note);
            probe_one(session, *cla, *ins, *p1, slot);
        }
    }

    println!();
    println!("Done. Boring instructions (SW 6D00/6E00) are filtered out.");
    println!("Any ✓ line is an instruction the firmware recognized and completed.");
}

fn print_info(info: &keyroost_transport::DeviceInfo) {
    println!("device serial: {}", info.serial);
    println!("device UTC:    {} (epoch)", info.utc_time);
    // TOTP tolerates small drift (one 30s step either way at most verifiers);
    // beyond that, codes get rejected in ways users misdiagnose as a bad
    // seed. Surface it here where it's cheap to see.
    let drift = i64::from(info.utc_time) - i64::from(unix_now());
    if drift.abs() > 30 {
        eprintln!(
            "warning: device clock is {} seconds {} the host clock — codes may be \
             rejected. Run `keyroostctl sync-time --all` to fix.",
            drift.abs(),
            if drift > 0 { "ahead of" } else { "behind" }
        );
    }
}

fn main() -> ExitCode {
    // HID enumeration (hidapi walking the system's device tree and parsing
    // report descriptors) is deep enough to exhaust the default main-thread
    // stack in unoptimized debug builds on Windows, where frames are large and
    // nothing is inlined — it manifests as STATUS_STACK_OVERFLOW before any
    // output. Release builds fit fine. Run the real work on a worker thread with
    // a generous 16 MiB stack so debug and release behave identically across
    // platforms. `run`'s error type is `Box<dyn Error>` (not `Send`), so flatten
    // it to a `String` inside the worker before it crosses the join boundary.
    let worker = std::thread::Builder::new()
        .name("keyroostctl-main".into())
        .stack_size(16 * 1024 * 1024)
        .spawn(|| run().map_err(|e| e.to_string()))
        .expect("spawn worker thread");

    match worker.join() {
        Ok(Ok(())) => ExitCode::SUCCESS,
        Ok(Err(e)) => {
            eprintln!("error: {}", e);
            ExitCode::FAILURE
        }
        Err(_) => {
            eprintln!("error: worker thread panicked");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod cli_tests {
    use super::*;
    use clap::Parser;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(args)
    }

    #[test]
    fn clap_command_is_valid() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    #[cfg(unix)]
    #[test]
    fn write_private_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let mut path = std::env::temp_dir();
        path.push(format!("keyroost_priv_{}", std::process::id()));

        // Fresh file is created 0600.
        write_private_file(&path, b"secret plaintext").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "fresh file should be 0600");

        // Loosen perms, then re-write: the helper must tighten back to 0600.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_private_file(&path, b"new secret").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "re-write should tighten to 0600");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn manpage_set_renders_for_every_subcommand() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let mut buf = Vec::new();
        clap_mangen::Man::new(cmd.clone()).render(&mut buf).unwrap();
        assert!(!buf.is_empty());
        let mut count = 0;
        for sub in cmd.get_subcommands() {
            let mut b = Vec::new();
            clap_mangen::Man::new(sub.clone()).render(&mut b).unwrap();
            assert!(!b.is_empty(), "empty man page for {}", sub.get_name());
            count += 1;
        }
        assert!(count >= 7, "expected >=7 subcommand groups, got {count}");
    }

    #[test]
    fn fido_is_nested() {
        assert!(parse(&["keyroostctl", "fido", "info"]).is_ok());
        assert!(parse(&["keyroostctl", "fido", "pin-set", "--new-pin-stdin"]).is_ok());
        assert!(parse(&["keyroostctl", "fido", "creds-list"]).is_ok());
        assert!(parse(&["keyroostctl", "fido-info"]).is_err());
        assert!(parse(&["keyroostctl", "fido-creds-list"]).is_err());
    }

    #[test]
    fn openpgp_pin_commands_parse() {
        assert!(Cli::try_parse_from([
            "keyroostctl",
            "openpgp",
            "change-pin",
            "--old-pin-stdin",
            "--new-pin-stdin"
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "keyroostctl",
            "openpgp",
            "change-admin-pin",
            "--old-pin-stdin",
            "--new-pin-stdin"
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "keyroostctl",
            "openpgp",
            "unblock-pin",
            "--admin-pin-stdin",
            "--new-pin-stdin"
        ])
        .is_ok());
    }

    #[test]
    fn molto_is_nested() {
        assert!(parse(&["keyroostctl", "molto", "info"]).is_ok());
        assert!(parse(&[
            "keyroostctl",
            "molto",
            "seed",
            "--profile",
            "0",
            "--hex-stdin"
        ])
        .is_ok());
        assert!(parse(&["keyroostctl", "molto", "reset", "--yes"]).is_ok());
        assert!(parse(&["keyroostctl", "molto", "probe", "--yes"]).is_ok());
        assert!(parse(&["keyroostctl", "set-seed", "--profile", "0", "--hex-stdin"]).is_err());
        assert!(parse(&["keyroostctl", "factory-reset", "--yes"]).is_err());
        assert!(parse(&["keyroostctl", "molto", "info", "--key-env", "K"]).is_ok());
    }

    #[test]
    fn name_is_accepted_on_every_group() {
        for g in [
            &["keyroostctl", "--name", "k", "piv", "status"][..],
            &["keyroostctl", "--name", "k", "oath", "list"][..],
            &["keyroostctl", "--name", "k", "openpgp", "status"][..],
            &["keyroostctl", "--name", "k", "otp", "list"][..],
            &["keyroostctl", "--name", "k", "molto", "info"][..],
            &["keyroostctl", "--name", "k", "fido", "info"][..],
        ] {
            assert!(parse(g).is_ok(), "should parse: {:?}", g);
        }
    }

    #[test]
    fn json_flag_parses_globally() {
        assert!(parse(&["keyroostctl", "--json", "piv", "status"]).is_ok());
        assert!(parse(&["keyroostctl", "--json", "fido", "info"]).is_ok());
        assert!(parse(&["keyroostctl", "--json", "molto", "info"]).is_ok());
        // Position-insensitive: --json after the subcommand also works (global).
        assert!(parse(&["keyroostctl", "piv", "status", "--json"]).is_ok());
    }

    /// Serialize `value`, assert it parses back to a JSON object, and assert
    /// every key in `keys` is present at the top level.
    fn assert_json_has_keys<T: serde::Serialize>(value: &T, keys: &[&str]) {
        let s = serde_json::to_string(value).expect("serialize");
        let v: serde_json::Value = serde_json::from_str(&s).expect("parse back");
        let obj = v.as_object().expect("top-level object");
        for k in keys {
            assert!(obj.contains_key(*k), "missing key {k:?} in {s}");
        }
    }

    #[test]
    fn device_json_serializes() {
        let d = json_out::DeviceJson {
            vendor: "Yubico".into(),
            model: "YubiKey 5".into(),
            name: Some("work".into()),
            serial: "12345678".into(),
            transport: "USB · PC/SC + FIDO HID".into(),
            kind: "key",
            caps: vec!["FIDO2", "OATH", "PIV"],
        };
        assert_json_has_keys(
            &d,
            &["vendor", "model", "serial", "transport", "kind", "caps"],
        );
        // The whole overview is a JSON array of these.
        let arr = serde_json::to_string(&vec![d]).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&arr).unwrap();
        assert!(parsed.is_array());
    }

    #[test]
    fn molto_info_json_serializes() {
        let m = json_out::MoltoInfoJson {
            serial: "ABC123".into(),
            utc: 1_700_000_000,
            drift_seconds: -3,
        };
        assert_json_has_keys(&m, &["serial", "utc", "drift_seconds"]);
    }

    #[test]
    fn fido_info_json_serializes() {
        // CTAP2 device: ctap2 present.
        let f = json_out::FidoInfoJson {
            device: "/dev/hidraw0".into(),
            channel_id: 0xdead_beef,
            ctaphid_protocol_version: 2,
            firmware: "5.4.3".into(),
            hid_caps: vec!["CBOR", "U2F"],
            hid_caps_raw: 0x0d,
            ctap2: Some(json_out::Ctap2InfoJson {
                versions: vec!["FIDO_2_0".into()],
                extensions: vec!["hmac-secret".into()],
                aaguid: "00000000-0000-0000-0000-000000000000".into(),
                options: vec![json_out::OptionJson {
                    name: "rk".into(),
                    value: true,
                }],
                max_msg_size: Some(1200),
                pin_uv_auth_protocols: vec![1, 2],
                transports: vec!["usb".into()],
                min_pin_length: Some(4),
                force_pin_change: Some(false),
                firmware_version: Some(328706),
            }),
        };
        assert_json_has_keys(
            &f,
            &["device", "channel_id", "firmware", "hid_caps", "ctap2"],
        );
        // U2F-only device: ctap2 omitted entirely (skip_serializing_if).
        let u = json_out::FidoInfoJson {
            device: "/dev/hidraw1".into(),
            channel_id: 1,
            ctaphid_protocol_version: 2,
            firmware: "1.0.0".into(),
            hid_caps: vec!["U2F"],
            hid_caps_raw: 0x08,
            ctap2: None,
        };
        let s = serde_json::to_string(&u).unwrap();
        assert!(!s.contains("ctap2"), "ctap2 should be omitted: {s}");
    }

    #[test]
    fn fido_pin_retries_json_serializes() {
        let p = json_out::FidoPinRetriesJson { pin_retries: 8 };
        assert_json_has_keys(&p, &["pin_retries"]);
    }

    #[test]
    fn piv_status_json_serializes() {
        let p = json_out::PivStatusJson {
            version: Some("5.4.3".into()),
            serial: Some(12345678),
            pin_retries: Some(3),
            slots: vec![json_out::PivSlotJson {
                slot: "9a (Authentication)".into(),
                cert_present: true,
                cert_len: 800,
            }],
        };
        assert_json_has_keys(&p, &["version", "serial", "pin_retries", "slots"]);
    }

    #[test]
    fn openpgp_status_json_serializes() {
        let o = json_out::OpenpgpStatusJson {
            aid: "d2760001240103040006...".into(),
            serial: Some(12345678),
            sig_algo: "RSA".into(),
            dec_algo: "RSA".into(),
            aut_algo: "RSA".into(),
            fingerprint_sig: Some("aabb...".into()),
            fingerprint_dec: None,
            fingerprint_aut: None,
            pin_retries_pw1: 3,
            pin_retries_rc: 0,
            pin_retries_pw3: 3,
            signature_count: Some(7),
        };
        assert_json_has_keys(
            &o,
            &[
                "aid",
                "sig_algo",
                "pin_retries_pw1",
                "pin_retries_pw3",
                "signature_count",
            ],
        );
    }

    #[test]
    fn otp_serial_json_serializes() {
        let s = json_out::OtpSerialJson {
            serial: "0123456789ab".into(),
        };
        assert_json_has_keys(&s, &["serial"]);
    }

    #[test]
    fn oath_credential_json_serializes() {
        // Synthetic credential — no real account data.
        let c = json_out::OathCredentialJson {
            name: "example".into(),
            oath_type: "TOTP",
            algorithm: "SHA1",
        };
        assert_json_has_keys(&c, &["name", "oath_type", "algorithm"]);
        // `oath list` emits a JSON array of these.
        let arr = serde_json::to_string(&vec![c]).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&arr).unwrap();
        assert!(parsed.is_array());
    }

    #[test]
    fn oath_code_json_serializes() {
        let c = json_out::OathCodeJson {
            name: "example".into(),
            code: "123456".into(),
        };
        assert_json_has_keys(&c, &["name", "code"]);
    }

    #[test]
    fn otp_entry_json_serializes() {
        // Synthetic entry with a code present.
        let e = json_out::OtpEntryJson {
            app: "Example".into(),
            account: "alice".into(),
            otp_type: "TOTP",
            algorithm: "SHA1",
            code: Some("123456".into()),
            touch_required: false,
        };
        assert_json_has_keys(
            &e,
            &[
                "app",
                "account",
                "otp_type",
                "algorithm",
                "code",
                "touch_required",
            ],
        );
        // Withheld (touch-required) entry: code serializes as JSON null.
        let withheld = json_out::OtpEntryJson {
            app: "Example".into(),
            account: "bob".into(),
            otp_type: "HOTP",
            algorithm: "SHA256",
            code: None,
            touch_required: true,
        };
        let s = serde_json::to_string(&withheld).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(v.get("code").unwrap().is_null());
        assert_eq!(
            v.get("touch_required").unwrap(),
            &serde_json::Value::Bool(true)
        );
        // `otp list` emits a JSON array.
        let arr = serde_json::to_string(&vec![e]).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&arr).unwrap();
        assert!(parsed.is_array());
    }

    #[test]
    fn otp_get_json_serializes() {
        let g = json_out::OtpGetJson {
            app: "Example".into(),
            account: "alice".into(),
            code: "123456".into(),
        };
        assert_json_has_keys(&g, &["app", "account", "code"]);
    }

    #[test]
    fn fido_creds_metadata_json_serializes() {
        let m = json_out::FidoCredsMetadataJson {
            existing_resident_credentials: 3,
            max_possible_remaining: 22,
        };
        assert_json_has_keys(
            &m,
            &["existing_resident_credentials", "max_possible_remaining"],
        );
    }

    #[test]
    fn fido_creds_list_json_serializes() {
        // Synthetic relying party + credential — no real RP/user data.
        let cred = json_out::FidoCredentialJson {
            credential_id: "aabbccdd".into(),
            user_id: "user-handle".into(),
            user_name: Some("alice".into()),
            user_display_name: Some("Alice Example".into()),
            algorithm: Some(-7),
            algorithm_name: Some("ES256"),
        };
        assert_json_has_keys(
            &cred,
            &["credential_id", "user_id", "user_name", "algorithm"],
        );
        let list = json_out::FidoCredsListJson {
            relying_parties: vec![json_out::FidoRelyingPartyJson {
                rp_id: "example.com".into(),
                rp_name: Some("Example".into()),
                credentials: vec![cred],
            }],
        };
        assert_json_has_keys(&list, &["relying_parties"]);
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&list).unwrap()).unwrap();
        assert!(v.get("relying_parties").unwrap().is_array());
        // Empty rp_name is omitted (skip_serializing_if).
        let no_name = json_out::FidoRelyingPartyJson {
            rp_id: "example.org".into(),
            rp_name: None,
            credentials: vec![],
        };
        let s = serde_json::to_string(&no_name).unwrap();
        assert!(!s.contains("rp_name"), "rp_name should be omitted: {s}");
    }

    // ---- large-blob shaping (pure logic; no hardware) ----

    use keyroost_ctap::large_blobs::{LargeBlobArray, LargeBlobEntry};

    /// An opaque RP-style entry (no keyroost note magic).
    fn opaque_entry() -> LargeBlobEntry {
        LargeBlobEntry {
            ciphertext: vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x99],
            nonce: vec![1u8; 12],
            orig_size: 4,
        }
    }

    #[test]
    fn large_blob_list_json_classifies_note_vs_opaque() {
        let array = LargeBlobArray {
            entries: vec![LargeBlobEntry::from_text("hello"), opaque_entry()],
            raw_array: Vec::new(),
        };
        let shaped = large_blob_list_json(&array);
        assert_eq!(shaped.entries.len(), 2);

        // [0] is a keyroost note: is_note true, text present, size == byte len.
        assert_eq!(shaped.entries[0].index, 0);
        assert!(shaped.entries[0].is_note);
        assert_eq!(shaped.entries[0].text.as_deref(), Some("hello"));
        assert_eq!(shaped.entries[0].size, "hello".len() as u64);

        // [1] is opaque: is_note false, text omitted.
        assert_eq!(shaped.entries[1].index, 1);
        assert!(!shaped.entries[1].is_note);
        assert!(shaped.entries[1].text.is_none());

        // The opaque entry's text is omitted from the JSON (skip_serializing_if).
        let s = serde_json::to_string(&shaped).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        let arr = v.get("entries").unwrap().as_array().unwrap();
        assert!(arr[0].get("text").is_some());
        assert!(arr[1].get("text").is_none());
    }

    #[test]
    fn large_blob_get_json_carries_hex_for_opaque() {
        let entry = opaque_entry();
        let g = json_out::FidoLargeBlobGetJson {
            index: 0,
            size: entry.orig_size,
            is_note: entry.is_kr_note(),
            text: entry.as_text(),
            hex: hex_encode(&entry.ciphertext),
        };
        assert!(!g.is_note);
        assert!(g.text.is_none());
        assert_eq!(g.hex, "deadbeef0099");
        assert_json_has_keys(&g, &["index", "size", "is_note", "hex"]);
        // text omitted for an opaque entry.
        let s = serde_json::to_string(&g).unwrap();
        assert!(!s.contains("\"text\""), "text should be omitted: {s}");
    }

    #[test]
    fn large_blob_get_json_includes_note_text() {
        let entry = LargeBlobEntry::from_text("a note");
        let g = json_out::FidoLargeBlobGetJson {
            index: 3,
            size: entry.orig_size,
            is_note: entry.is_kr_note(),
            text: entry.as_text(),
            hex: hex_encode(&entry.ciphertext),
        };
        assert!(g.is_note);
        assert_eq!(g.text.as_deref(), Some("a note"));
        let s = serde_json::to_string(&g).unwrap();
        assert!(s.contains("\"text\":\"a note\""), "{s}");
    }

    #[test]
    fn preview_note_truncates_and_flattens() {
        // Newlines/control chars flattened to spaces.
        assert_eq!(preview_note("line1\nline2"), "line1 line2");
        // Long text truncated with an ellipsis.
        let long = "x".repeat(100);
        let p = preview_note(&long);
        assert!(p.ends_with('…'));
        assert_eq!(p.chars().count(), 49); // 48 chars + ellipsis
    }

    #[test]
    fn preview_opaque_shows_hex_head() {
        let bytes: Vec<u8> = (0u8..20).collect();
        let p = preview_opaque(&bytes);
        assert!(p.starts_with("000102"));
        assert!(p.ends_with('…'));
        assert_eq!(preview_opaque(&[]), "(empty)");
    }

    #[test]
    fn hex_ascii_dump_renders_offset_and_ascii() {
        let dump = hex_ascii_dump(b"ABC");
        assert!(dump.starts_with("00000000"));
        assert!(dump.contains("41 42 43"));
        assert!(dump.contains("|ABC|"));
    }

    #[test]
    fn large_blob_bad_index_message_reflects_len() {
        let empty = large_blob_bad_index(2, 0).to_string();
        assert!(empty.contains("empty"), "{empty}");
        let oob = large_blob_bad_index(5, 3).to_string();
        assert!(oob.contains("0..=2"), "{oob}");
    }

    #[test]
    fn large_blob_subcommands_parse() {
        assert!(parse(&["keyroostctl", "fido", "large-blob", "list"]).is_ok());
        assert!(parse(&["keyroostctl", "fido", "large-blob", "get", "0"]).is_ok());
        assert!(parse(&["keyroostctl", "fido", "large-blob", "add", "hi"]).is_ok());
        assert!(parse(&["keyroostctl", "fido", "large-blob", "edit", "1", "new"]).is_ok());
        assert!(parse(&["keyroostctl", "fido", "large-blob", "delete", "2", "--yes"]).is_ok());
        assert!(parse(&["keyroostctl", "fido", "large-blob", "clear", "--yes"]).is_ok());
    }
}
