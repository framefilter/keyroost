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
use keyroost_transport::{SeedDeleteOutcome, Session, TransportError};

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use keyroost_keyring::Keyring;
use keyroost_resolve::{
    ccid_readers_if_needed, ccid_serial_for, connected_keys, effective_serials,
    read_effective_serial, VID_YUBICO,
};

mod overview;

/// The global `--device` selector, captured once in `run()` so the FIDO device
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
        /// The subset of `caps` keyroost could not verify against the device
        /// (no card channel was available to ask): still offered, but not
        /// proven present. Tri-state per capability: in `caps` only =
        /// verified present; in both lists = offered but unverified; in
        /// neither = absent.
        pub caps_unverified: Vec<&'static str>,
    }

    /// `keyroostctl molto --json info`.
    #[derive(Serialize)]
    pub struct MoltoInfoJson {
        pub serial: String,
        pub utc: u32,
        pub drift_seconds: i64,
    }

    /// `keyroostctl molto --json slots`.
    #[derive(Serialize)]
    pub struct MoltoSlotsJson {
        pub serial: String,
        pub slots: Vec<MoltoSlotJson>,
    }

    /// One element of [`MoltoSlotsJson::slots`] (full parsed block).
    /// `time_a`/`time_b` are raw big-endian u32s with unconfirmed semantics.
    #[derive(Serialize)]
    pub struct MoltoSlotJson {
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
        pub chuid: Option<PivChuidJson>,
        pub slots: Vec<PivSlotJson>,
    }

    /// The card's CHUID — FASC-N, GUID, expiration, signature, and LRC. The
    /// CLI is the one place that prints signature/LRC (empty hex in every
    /// CHUID this crate itself writes); the GUI status line omits both, and
    /// FASC-N besides.
    #[derive(Serialize)]
    pub struct PivChuidJson {
        pub fasc_n: String,
        pub guid: String,
        pub expiration: String,
        pub signature: String,
        pub lrc: String,
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
        pub capacity: FidoLargeBlobCapacityJson,
    }

    /// Space accounting for the whole array (serialized form incl. checksum).
    #[derive(Serialize)]
    pub struct FidoLargeBlobCapacityJson {
        pub max_bytes: u64,
        pub used_bytes: u64,
        pub free_bytes: u64,
    }

    /// Decoded fields of a recognized OpenSSH certificate entry.
    #[derive(Serialize)]
    pub struct FidoLargeBlobSshCertJson {
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
        /// Entry classification: "note", "ssh-cert", or "opaque".
        pub kind: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub ssh_cert: Option<FidoLargeBlobSshCertJson>,
    }

    /// `keyroostctl fido large-blob --json get <INDEX>` — a single entry in full.
    #[derive(Serialize)]
    pub struct FidoLargeBlobGetJson {
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
    pub struct ProgInfoJson {
        pub serial: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub model: Option<String>,
        pub utc_time: u32,
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
    //
    // Named `device` (flag `--device`), not `name`: a *global* arg whose clap id
    // is `name` merges with every subcommand arg of the same id (e.g. the
    // `oath add <NAME>` positional, `fido fingerprint --name`), so a credential
    // or fingerprint name was being consumed as this device selector. A distinct
    // id keeps the global selector separate from all of them.
    #[arg(long, global = true, value_name = "NAME")]
    device: Option<String>,
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
    /// Factory-reset EVERY resettable applet on the selected key: OATH,
    /// OpenPGP, PIV, Token2 OTP, then FIDO2. On a USB key the FIDO2 step ends
    /// with an unplug/replug + touch; a card in a smart-card reader is reset
    /// in place instead (no replug, no touch). Wipes all credentials, codes,
    /// keys, and PINs; each applet that completes comes back in factory
    /// condition, and every step reports its own outcome. Irreversible.
    FactoryReset {
        /// Substring of the PC/SC reader name (skips auto-detection for the
        /// smart-card applets).
        #[arg(long)]
        reader: Option<String>,
        /// Confirm the wipe. Required — without it the command refuses.
        #[arg(long)]
        yes: bool,
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
    /// 82 — Retired key 1.
    #[value(name = "82")]
    Retired1,
    /// 83 — Retired key 2.
    #[value(name = "83")]
    Retired2,
    /// 84 — Retired key 3.
    #[value(name = "84")]
    Retired3,
    /// 85 — Retired key 4.
    #[value(name = "85")]
    Retired4,
    /// 86 — Retired key 5.
    #[value(name = "86")]
    Retired5,
    /// 87 — Retired key 6.
    #[value(name = "87")]
    Retired6,
    /// 88 — Retired key 7.
    #[value(name = "88")]
    Retired7,
    /// 89 — Retired key 8.
    #[value(name = "89")]
    Retired8,
    /// 8A — Retired key 9.
    #[value(name = "8a")]
    Retired9,
    /// 8B — Retired key 10.
    #[value(name = "8b")]
    Retired10,
    /// 8C — Retired key 11.
    #[value(name = "8c")]
    Retired11,
    /// 8D — Retired key 12.
    #[value(name = "8d")]
    Retired12,
    /// 8E — Retired key 13.
    #[value(name = "8e")]
    Retired13,
    /// 8F — Retired key 14.
    #[value(name = "8f")]
    Retired14,
    /// 90 — Retired key 15.
    #[value(name = "90")]
    Retired15,
    /// 91 — Retired key 16.
    #[value(name = "91")]
    Retired16,
    /// 92 — Retired key 17.
    #[value(name = "92")]
    Retired17,
    /// 93 — Retired key 18.
    #[value(name = "93")]
    Retired18,
    /// 94 — Retired key 19.
    #[value(name = "94")]
    Retired19,
    /// 95 — Retired key 20.
    #[value(name = "95")]
    Retired20,
}

impl CliPivSlot {
    fn to_slot(self) -> keyroost_piv::Slot {
        match self {
            CliPivSlot::Auth => keyroost_piv::Slot::Authentication,
            CliPivSlot::Sign => keyroost_piv::Slot::Signature,
            CliPivSlot::KeyMgmt => keyroost_piv::Slot::KeyManagement,
            CliPivSlot::CardAuth => keyroost_piv::Slot::CardAuthentication,
            CliPivSlot::Retired1 => keyroost_piv::Slot::retired(1).unwrap(),
            CliPivSlot::Retired2 => keyroost_piv::Slot::retired(2).unwrap(),
            CliPivSlot::Retired3 => keyroost_piv::Slot::retired(3).unwrap(),
            CliPivSlot::Retired4 => keyroost_piv::Slot::retired(4).unwrap(),
            CliPivSlot::Retired5 => keyroost_piv::Slot::retired(5).unwrap(),
            CliPivSlot::Retired6 => keyroost_piv::Slot::retired(6).unwrap(),
            CliPivSlot::Retired7 => keyroost_piv::Slot::retired(7).unwrap(),
            CliPivSlot::Retired8 => keyroost_piv::Slot::retired(8).unwrap(),
            CliPivSlot::Retired9 => keyroost_piv::Slot::retired(9).unwrap(),
            CliPivSlot::Retired10 => keyroost_piv::Slot::retired(10).unwrap(),
            CliPivSlot::Retired11 => keyroost_piv::Slot::retired(11).unwrap(),
            CliPivSlot::Retired12 => keyroost_piv::Slot::retired(12).unwrap(),
            CliPivSlot::Retired13 => keyroost_piv::Slot::retired(13).unwrap(),
            CliPivSlot::Retired14 => keyroost_piv::Slot::retired(14).unwrap(),
            CliPivSlot::Retired15 => keyroost_piv::Slot::retired(15).unwrap(),
            CliPivSlot::Retired16 => keyroost_piv::Slot::retired(16).unwrap(),
            CliPivSlot::Retired17 => keyroost_piv::Slot::retired(17).unwrap(),
            CliPivSlot::Retired18 => keyroost_piv::Slot::retired(18).unwrap(),
            CliPivSlot::Retired19 => keyroost_piv::Slot::retired(19).unwrap(),
            CliPivSlot::Retired20 => keyroost_piv::Slot::retired(20).unwrap(),
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
        /// When the new key's private key may be used. `default` sends the
        /// standard PIV command every card accepts; the other values are a
        /// Yubico extension (firmware-dependent).
        #[arg(long, value_enum, default_value = "default")]
        pin_policy: CliPinPolicy,
        /// Whether using the new key requires a physical touch. Same caveat:
        /// only `default` is standard PIV, the rest are a Yubico extension
        /// (firmware-dependent).
        #[arg(long, value_enum, default_value = "default")]
        touch_policy: CliTouchPolicy,
        #[arg(long, value_name = "VAR", conflicts_with = "mgmt_key_stdin")]
        mgmt_key_env: Option<String>,
        #[arg(long)]
        mgmt_key_stdin: bool,
        /// Also write the generated public key (PEM) to this path. Needed to
        /// `request-cert`/`self-sign` this same key from a *later*, separate
        /// `keyroostctl` invocation on cards that don't support GET METADATA
        /// (firmware older than 5.3, or non-Yubico PIV): such a card has no
        /// way to name a key this fresh on its own — there's no certificate
        /// yet either — so nothing here is cached automatically; pass the
        /// same path to that later command's `--load-pubkey`.
        #[arg(long, value_name = "PATH")]
        save_pubkey: Option<std::path::PathBuf>,
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
        /// Path from a prior `generate-key --save-pubkey`. Needed on cards
        /// that don't support GET METADATA (firmware older than 5.3, or
        /// non-Yubico PIV) when the key was generated by a different
        /// `keyroostctl` invocation — such a card has no other way to name
        /// the slot's key material.
        #[arg(long, value_name = "PATH")]
        load_pubkey: Option<std::path::PathBuf>,
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
        /// Path from a prior `generate-key --save-pubkey`. Needed on cards
        /// that don't support GET METADATA (firmware older than 5.3, or
        /// non-Yubico PIV) when the key was generated by a different
        /// `keyroostctl` invocation — such a card has no other way to name
        /// the slot's key material.
        #[arg(long, value_name = "PATH")]
        load_pubkey: Option<std::path::PathBuf>,
    },
    /// Write a fresh, randomly-generated CHUID (Card Holder Unique
    /// Identifier). Needs the management key. Windows' PIV minidriver caches
    /// a card's contents by its CHUID's GUID, so after writing a new
    /// certificate or key it may keep showing stale data until the GUID
    /// changes — this forces that.
    NewChuid {
        #[arg(long, value_name = "SUBSTR")]
        reader: Option<String>,
        #[arg(long, value_name = "VAR", conflicts_with = "mgmt_key_stdin")]
        mgmt_key_env: Option<String>,
        #[arg(long)]
        mgmt_key_stdin: bool,
        /// CHUID expiration, in days from now. Informational only — it has no
        /// technical implications. Same default as self-sign's certificate
        /// validity.
        #[arg(long, value_name = "N", default_value_t = 365)]
        days: u32,
        /// GUID, hex (dashes optional). Omit to use random GUID.
        #[arg(long, value_name = "HEX")]
        guid: Option<String>,
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
    /// Move a slot's private key to another slot (Yubico MOVE KEY, fw 5.7+).
    /// Non-destructive; refuses an occupied destination. The certificate stays
    /// in the source slot.
    MoveKey {
        /// Source slot (9a/9c/9d/9e/82–95).
        #[arg(long)]
        from: CliPivSlot,
        /// Destination slot (must be empty).
        #[arg(long)]
        to: CliPivSlot,
        /// PC/SC reader substring (skips auto-detection).
        #[arg(long)]
        reader: Option<String>,
        #[arg(long, value_name = "VAR", conflicts_with = "mgmt_key_stdin")]
        mgmt_key_env: Option<String>,
        #[arg(long)]
        mgmt_key_stdin: bool,
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
    /// Read the public key from a slot (read-only; no PIN). RSA keys print
    /// modulus and exponent, ECC keys the public point, in hex.
    PublicKey {
        /// Which key slot: `sign`, `decrypt`, or `auth`.
        #[arg(long, value_enum, default_value_t = OpenpgpSlot::Sign)]
        slot: OpenpgpSlot,
        #[arg(long, value_name = "SUBSTR")]
        reader: Option<String>,
    },
    /// List the key algorithms this card reports accepting per slot (read-only;
    /// no PIN). Cards that don't publish the list accept any attempt and answer
    /// with an error if they can't.
    Algorithms {
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
    /// Generate a fresh key pair in a slot, optionally switching the slot's
    /// algorithm first. DESTRUCTIVE — overwrites any existing key in that slot.
    /// Requires the admin PIN (PW3) and `--yes`; on a YubiKey a touch is also
    /// required. Also writes the key's v4 fingerprint and a generation
    /// timestamp so an OpenPGP tool (e.g. gpg) recognizes the key.
    GenerateKey {
        /// Which key slot to (over)write: `sign`, `decrypt`, or `auth`.
        #[arg(long, value_enum, default_value_t = OpenpgpSlot::Sign)]
        slot: OpenpgpSlot,
        /// Key algorithm to generate. Omit to keep the slot's current algorithm
        /// (RSA-2048 on a factory card). Ed25519 fits the sign/auth slots,
        /// X25519 the decrypt slot; the NIST/brainpool/secp256k1 curves fit any.
        /// See `openpgp algorithms` for what this card accepts.
        #[arg(long, value_enum)]
        algorithm: Option<CliOpenpgpKeyAlg>,
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
    /// (SHA-256 by default, or SHA-1 via `--hash`). RSA slots sign a PKCS#1
    /// DigestInfo; ECC slots sign the bare digest. Requires the signing PIN
    /// (PW1) and, on a YubiKey, a touch. The output is the card's raw
    /// signature: PKCS#1 for RSA, `r||s` (not DER) for ECDSA, `R||S` for
    /// Ed25519.
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
    /// Decrypt a file with the on-card decryption key (PSO:DECIPHER). Requires
    /// the user PIN (PW1) and, on a YubiKey, a touch.
    Decrypt {
        /// For an RSA slot `--in` is the raw cryptogram; for an ECDH slot it is
        /// the sender's ephemeral public point (`04||X||Y`, or 32 raw bytes for
        /// X25519) and the output is the shared secret.
        #[arg(long, value_name = "FILE")]
        r#in: std::path::PathBuf,
        /// Write the recovered plaintext (or, for ECDH, the shared secret)
        /// here. Without it, the bytes are printed as hex to stdout.
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
    /// Authentication key (INTERNAL AUTHENTICATE). Hashes the input (SHA-256 by
    /// default, or SHA-1 via `--hash`). RSA slots sign a PKCS#1 DigestInfo; ECC
    /// slots sign the bare digest. Requires the user PIN (PW1) and, on a
    /// YubiKey, a touch. The output is the card's raw signature: PKCS#1 for
    /// RSA, `r||s` (not DER) for ECDSA, `R||S` for Ed25519.
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

    /// The bare digest of `data` — no DigestInfo wrapper. ECDSA and EdDSA
    /// slots sign this directly.
    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            SignHash::Sha1 => keyroost_proto::sha1::sha1(data).to_vec(),
            SignHash::Sha256 => keyroost_proto::sha256::sha256(data).to_vec(),
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

/// Key algorithm for `openpgp generate-key --algorithm`. Names follow GnuPG's
/// (`cv25519` is accepted as an alias of `x25519`).
#[derive(Copy, Clone, ValueEnum)]
enum CliOpenpgpKeyAlg {
    Rsa2048,
    Rsa3072,
    Rsa4096,
    Ed25519,
    #[value(alias = "cv25519")]
    X25519,
    #[value(name = "nistp256")]
    NistP256,
    #[value(name = "nistp384")]
    NistP384,
    #[value(name = "nistp521")]
    NistP521,
    Secp256k1,
    #[value(name = "brainpoolp256")]
    BrainpoolP256r1,
    #[value(name = "brainpoolp384")]
    BrainpoolP384r1,
    #[value(name = "brainpoolp512")]
    BrainpoolP512r1,
}

impl CliOpenpgpKeyAlg {
    fn to_alg(self) -> keyroost_openpgp::KeyAlg {
        use keyroost_openpgp::KeyAlg::*;
        match self {
            CliOpenpgpKeyAlg::Rsa2048 => Rsa2048,
            CliOpenpgpKeyAlg::Rsa3072 => Rsa3072,
            CliOpenpgpKeyAlg::Rsa4096 => Rsa4096,
            CliOpenpgpKeyAlg::Ed25519 => Ed25519,
            CliOpenpgpKeyAlg::X25519 => X25519,
            CliOpenpgpKeyAlg::NistP256 => NistP256,
            CliOpenpgpKeyAlg::NistP384 => NistP384,
            CliOpenpgpKeyAlg::NistP521 => NistP521,
            CliOpenpgpKeyAlg::Secp256k1 => Secp256k1,
            CliOpenpgpKeyAlg::BrainpoolP256r1 => BrainpoolP256r1,
            CliOpenpgpKeyAlg::BrainpoolP384r1 => BrainpoolP384r1,
            CliOpenpgpKeyAlg::BrainpoolP512r1 => BrainpoolP512r1,
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
        /// Friendly label to assign, e.g. "Signing YubiKey". Any text up to 64
        /// characters — letters of any script, digits, spaces, punctuation;
        /// only blank names and control / zero-width / bidi characters are
        /// rejected.
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
    /// Factory-reset the OATH applet: wipe ALL authenticator credentials and
    /// clear the access password. Needs no password — this is the recovery
    /// path for a forgotten one. Irreversible.
    Reset {
        /// Substring of the PC/SC reader name to use (skips auto-detection).
        #[arg(long)]
        reader: Option<String>,
        /// Confirm the wipe. Required: without it the command refuses to run.
        #[arg(long)]
        yes: bool,
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
        /// Seed in hex. Argv is visible in `ps` and shell history; prefer
        /// --hex-stdin or --hex-env.
        #[arg(long, conflicts_with = "base32", value_name = "HEX")]
        hex: Option<String>,
        /// Seed in base32 (RFC 4648; whitespace and dashes tolerated). Argv is
        /// visible in `ps` and shell history; prefer --base32-stdin or
        /// --base32-env.
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
    /// List the 100 profile slots: occupancy, title, TOTP config.
    /// Titles and occupancy are readable by anyone holding the token —
    /// no customer key is needed (or used).
    Slots {
        /// Show all 100 slots, including empty untitled ones.
        #[arg(long)]
        all: bool,
    },
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
    /// Write a profile title (1..=12 ASCII chars), or print the current
    /// one when TITLE is omitted (reading needs no customer key).
    Title {
        #[arg(short, long)]
        profile: u8,
        /// New title; omit to read the slot's stored title instead.
        title: Option<String>,
    },
    /// Delete one profile's seed. The title, if any, survives. Keyless:
    /// the device accepts this from any card holder (hardware-verified),
    /// so the only gate is --yes.
    Delete {
        #[arg(short, long)]
        profile: u8,
        /// Confirm you really want to delete this slot's seed.
        #[arg(long)]
        yes: bool,
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
    ///
    /// For a card in a smart-card reader (no USB interface), use `--reader`:
    /// the card is power-cycled in place — which starts the same
    /// just-after-power-up window a replug would — and the reset sent
    /// immediately. No touch is involved.
    Reset {
        /// Confirm you really want to wipe credentials.
        #[arg(long)]
        yes: bool,
        /// hidraw path to use. If omitted, auto-pick the only connected FIDO device.
        #[arg(long, value_name = "PATH", conflicts_with = "reader")]
        path: Option<std::path::PathBuf>,
        /// Substring of the PC/SC reader holding the card to reset. Routes the
        /// reset over the smart-card interface instead of USB-HID.
        #[arg(long, value_name = "SUBSTR")]
        reader: Option<String>,
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
    /// Enumerate resident SSH credentials and extract a stored OpenSSH
    /// certificate from a credential's largeBlob to a `-cert.pub` file.
    SshCert {
        #[command(subcommand)]
        cmd: SshCertCmd,
    },
}

/// Subcommands for resident SSH credentials (RP IDs of the form `ssh:*`).
///
/// A FIDO SSH key may stash its OpenSSH certificate in the FIDO2 large-blob
/// store, keyed by the credential's per-credential largeBlobKey. These commands
/// enumerate those credentials (needs a PIN for credential management) and pull
/// the certificate back out as an `id-cert.pub` file usable by `ssh`.
#[derive(Subcommand)]
enum SshCertCmd {
    /// List resident SSH credentials (ssh:* RP IDs) and whether each has a
    /// certificate stored in its largeBlob.
    List {
        #[arg(long, value_name = "VAR", conflicts_with = "pin_stdin")]
        pin_env: Option<String>,
        #[arg(long)]
        pin_stdin: bool,
        #[arg(long, value_name = "PATH")]
        path: Option<std::path::PathBuf>,
    },
    /// Extract an SSH certificate from its largeBlob to a -cert.pub file.
    Extract {
        /// RP ID of the SSH credential (e.g. ssh:demo). Required only to
        /// disambiguate when several SSH credentials are present.
        #[arg(long)]
        credential: Option<String>,
        /// Output file (default: <rp-id-sanitised>-cert.pub).
        #[arg(long, value_name = "FILE")]
        out: Option<std::path::PathBuf>,
        /// Overwrite the output file if it exists.
        #[arg(long)]
        force: bool,
        #[arg(long, value_name = "VAR", conflicts_with = "pin_stdin")]
        pin_env: Option<String>,
        #[arg(long)]
        pin_stdin: bool,
        #[arg(long, value_name = "PATH")]
        path: Option<std::path::PathBuf>,
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
    /// Save one entry's bytes to a file (read-only; no PIN needed).
    ///
    /// By default writes the entry's raw stored bytes. With --as-cert, a
    /// recognized OpenSSH certificate entry is written as a `-cert.pub` text
    /// line instead (the format `ssh` and `ssh-keygen` consume).
    Export {
        /// Zero-based entry index as printed by `large-blob list`.
        index: usize,
        /// Destination file (overwritten if it exists).
        output: std::path::PathBuf,
        /// Write a recognized SSH certificate in `-cert.pub` text form.
        #[arg(long)]
        as_cert: bool,
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
#[derive(Copy, Clone, Debug, ValueEnum)]
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

/// Reject a `piv self-sign`/`piv new-chuid` `--days` value beyond what a
/// certificate's validity period or a CHUID's expiration date can actually
/// represent ([`keyroost_piv::max_valid_days`]), instead of letting it
/// silently saturate deep in the encoder (`der_time`/`chuid_expiration_in_days`
/// both clamp to the same `9999-12-31` ceiling on their own, but a caller
/// asking for more than that deserves a clear error, not a silently
/// shorter validity period than what they typed).
fn check_valid_days(days: u32) -> Result<(), Box<dyn std::error::Error>> {
    let max = keyroost_piv::max_valid_days(u64::from(unix_now()));
    if days > max {
        return Err(format!(
            "--days {days} exceeds the largest representable value ({max} days \
             from now) — a CHUID/certificate date is a 4-digit year, capped at \
             9999-12-31"
        )
        .into());
    }
    Ok(())
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
    // Capture --device once so resolve_fido_path() can honor it without threading
    // it through every FIDO subcommand handler.
    let _ = SELECTED_KEY_NAME.set(cli.device.clone());
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
                    caps_unverified: d
                        .cap_badge_states()
                        .into_iter()
                        .filter(|(_, s)| *s == keyroost_resolve::CapState::Unverified)
                        .map(|(l, _)| l)
                        .collect(),
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

    // Whole-device factory reset: wipe every resettable applet in planner order.
    if let Cmd::FactoryReset { reader, yes } = cmd {
        return run_factory_reset(reader.as_deref(), *yes, cli.debug);
    }

    unreachable!("every subcommand is handled above");
}

/// Open a Molto2 session, honoring the global `--device` selector: when set, open
/// the named device's reader (failing closed if it resolves to none), otherwise
/// fall back to the first Molto2 reader found. Every `run_molto` path routes
/// through here so no Molto operation can silently hit an unselected token.
fn open_molto_session() -> Result<Session, Box<dyn std::error::Error>> {
    match reader_from_name()? {
        Some(reader) => Ok(Session::open_named(&reader)?),
        None => Ok(Session::open()?),
    }
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
        let mut session = open_molto_session()?;
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

    // Slots is read-only and needs no auth — the public block answers any
    // card holder (that's also why the output warns about title privacy).
    if let MoltoCmd::Slots { all } = cmd {
        let mut session = open_molto_session()?;
        session.set_debug(debug);
        let info = session.read_info()?;
        // A mid-sweep failure keeps the slots already read; the table below
        // prints them plus an error row instead of discarding everything a
        // flaky read had already produced.
        let (slots, sweep_err) =
            sweep_until_error((0..=99u8).map(|p| (p, session.read_public_data(p))));
        if json_output() {
            if let Some((slot, e)) = sweep_err {
                // JSON consumers get all-or-nothing: partial data with no
                // in-band error marker would read as "the other slots are
                // empty", which is worse than failing.
                return Err(format!("reading slot {slot}'s public block failed: {e}").into());
            }
            let out: Vec<json_out::MoltoSlotJson> = slots
                .iter()
                .enumerate()
                .map(|(i, b)| json_out::MoltoSlotJson {
                    slot: i as u8,
                    occupied: b.seed_present,
                    title: b.title.clone(),
                    flag: b.flag,
                    algorithm: b.algorithm,
                    time_step: b.time_step,
                    digits: b.digits,
                    time_a: b.time_a,
                    time_b: b.time_b,
                })
                .collect();
            let out = json_out::MoltoSlotsJson {
                serial: info.serial.clone(),
                slots: out,
            };
            emit_json(&out)?;
            return Ok(());
        }
        print_info(&info);
        let shown: Vec<_> = slots
            .iter()
            .enumerate()
            .filter(|(_, b)| *all || b.seed_present || b.title.is_some())
            .collect();
        if shown.is_empty() && sweep_err.is_none() {
            println!("no occupied or titled slots (use --all to list all 100)");
            return Ok(());
        }
        println!(
            "{:>4}  {:>8}  {:<16}  {:<6}  {:>4}  {:>6}",
            "slot", "occupied", "title", "algo", "step", "digits"
        );
        for (i, b) in shown {
            println!(
                "{:>4}  {:>8}  {:<16}  {:<6}  {:>4}  {:>6}",
                i,
                if b.seed_present { "yes" } else { "-" },
                b.title
                    .as_deref()
                    .map(sanitize_terminal)
                    .unwrap_or_default(),
                molto_algo_label(b.algorithm),
                b.time_step,
                b.digits,
            );
        }
        if let Some((slot, e)) = sweep_err {
            println!(
                "{:>4}  {}",
                slot,
                sanitize_terminal(&format!(
                    "read failed here — slots {slot}..=99 not shown: {e}"
                ))
            );
            return Err(format!("slot sweep incomplete: slot {slot} failed: {e}").into());
        }
        return Ok(());
    }

    // Title with TITLE omitted is a read — keyless, like Info/Slots.
    if let MoltoCmd::Title {
        profile,
        title: None,
    } = cmd
    {
        let mut session = open_molto_session()?;
        session.set_debug(debug);
        let block = session.read_public_data(*profile)?;
        match &block.title {
            Some(t) => println!("slot #{} title: {}", profile, sanitize_terminal(t)),
            None => println!("slot #{} has no title", profile),
        }
        println!(
            "occupied: {}",
            if block.seed_present { "yes" } else { "no" }
        );
        return Ok(());
    }

    // Delete needs no auth (hardware-verified) — gate on --yes, and show
    // what's in the slot before touching it.
    if let MoltoCmd::Delete { profile, yes } = cmd {
        let mut session = open_molto_session()?;
        session.set_debug(debug);
        let info = session.read_info()?;
        print_info(&info);
        let block = session.read_public_data(*profile)?;
        println!(
            "slot #{}: occupied: {}, title: {}",
            profile,
            if block.seed_present { "yes" } else { "no" },
            block
                .title
                .as_deref()
                .map(sanitize_terminal)
                .unwrap_or_else(|| "(none)".into()),
        );
        if !yes {
            return Err(format!(
                "refusing to delete slot #{}'s seed on device serial {} without --yes",
                profile,
                sanitize_terminal(&info.serial)
            )
            .into());
        }
        match session.delete_seed(*profile)? {
            SeedDeleteOutcome::Deleted => {
                println!(
                    "seed deleted from slot #{}; the title (if any) remains",
                    profile
                )
            }
            SeedDeleteOutcome::AlreadyEmpty => println!("slot #{} was already empty", profile),
        }
        return Ok(());
    }

    // Factory reset is a plain CLA 0x80 command and needs no auth. Read the
    // (read-only) device info before the --yes gate so even the refusal names
    // exactly which device would be wiped.
    if let MoltoCmd::Reset { yes } = cmd {
        let mut session = open_molto_session()?;
        session.set_debug(debug);
        let info = session.read_info()?;
        print_info(&info);
        if !yes {
            return Err(format!(
                "refusing to factory-reset device serial {} without --yes",
                sanitize_terminal(&info.serial)
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
        let mut session = open_molto_session()?;
        session.set_debug(debug);
        let info = session.read_info()?;
        print_info(&info);
        if *authed {
            let key = customer_key_bytes(key)?;
            match session.authenticate(&key) {
                Ok(()) => println!("authenticated"),
                // The Display impl renders the tries-remaining count (or
                // "unknown" when the card gave none).
                Err(e @ TransportError::AuthFailed { .. }) => {
                    return Err(e.to_string().into());
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
    let mut session = open_molto_session()?;
    session.set_debug(debug);
    let info = session.read_info()?;
    print_info(&info);
    match session.authenticate(&key) {
        Ok(()) => println!("authenticated"),
        // The Display impl renders the tries-remaining count (or "unknown").
        Err(e @ TransportError::AuthFailed { .. }) => return Err(e.to_string().into()),
        Err(e) => return Err(e.into()),
    }

    match cmd {
        MoltoCmd::Info => unreachable!("handled above before auth"),
        MoltoCmd::Slots { .. } => unreachable!("handled above before auth"),
        MoltoCmd::Delete { .. } => unreachable!("handled above before auth"),
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
            let title = title
                .as_deref()
                .expect("title read mode is handled before auth");
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
                // The URI embeds the seed in its secret= parameter; hold it in
                // Zeroizing so our copy is scrubbed after parse_otpauth (which
                // wipes its own copies).
                let uri: zeroize::Zeroizing<String> = match uri.as_deref() {
                    // `-` reads the URI from stdin so it stays out of
                    // /proc/*/cmdline and shell history.
                    Some("-") => {
                        use std::io::BufRead;
                        let mut line = zeroize::Zeroizing::new(String::new());
                        std::io::stdin().lock().read_line(&mut line)?;
                        zeroize::Zeroizing::new(line.trim_end_matches(['\r', '\n']).to_owned())
                    }
                    Some(u) => zeroize::Zeroizing::new(u.to_owned()),
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
                // serde escapes the device-supplied serial; the old hand-built
                // JSON did not, so a serial with `"`/`\`/control bytes produced
                // invalid or field-injected JSON for consuming scripts.
                emit_json(&json_out::ProgInfoJson {
                    serial: info.serial.clone(),
                    model: model.map(str::to_owned),
                    utc_time: info.utc_time,
                })?;
            } else {
                match model {
                    Some(m) => println!("model:    {m}"),
                    None => println!("model:    (unrecognized serial — not a known Token2 model)"),
                }
                println!("serial:   {}", sanitize_terminal(&info.serial));
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
            eprintln!("[*] {model} (serial {})", sanitize_terminal(&info.serial));
            Ok(model)
        }
        None => Err(format!(
            "serial '{}' does not match any known Token2 programmable-token model; \
             refusing to program this device. Run `keyroostctl prog info` to inspect it.",
            sanitize_terminal(&info.serial)
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
                    println!("    {}{}", sanitize_terminal(r), tag);
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
                                sanitize_terminal(&d.product_name),
                                d.path.display()
                            ),
                            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                                println!(
                                    "✗ {} ({}) permission denied — install the udev rules \
                                     (see README) and re-plug the key",
                                    sanitize_terminal(&d.product_name),
                                    d.path.display()
                                );
                            }
                            Err(e) => println!(
                                "✗ {} ({}) open failed: {}",
                                sanitize_terminal(&d.product_name),
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
                println!("  {}", sanitize_terminal(&r));
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
                println!("  {}  [Molto2 token]", sanitize_terminal(&p.reader_name));
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
            println!("  {}  ->  {}", sanitize_terminal(&p.reader_name), list);
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
                    (Some(s), _) => format!(" serial={}", sanitize_terminal(s)),
                    (None, Some(s)) => format!(" serial={}(ccid)", sanitize_terminal(s)),
                    (None, None) => String::new(),
                };
                let name = keyring
                    .name_for(eff.as_deref())
                    .map(|n| format!(" name={}", sanitize_terminal(n)))
                    .unwrap_or_default();
                let pname = sanitize_terminal(&d.product_name);
                let model = if d.vendor_id == keyroost_proto::USB_VID {
                    keyroost_proto::token2_pid_label(d.product_id)
                        .map(|l| format!("{} [{}]", pname, l))
                        .unwrap_or_else(|| pname.clone())
                } else {
                    pname
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
            return format!(
                " — target: {} at {}",
                sanitize_terminal(&dev.label),
                dev.path.display()
            );
        }
        return String::new();
    }
    match devices.as_slice() {
        [d] => {
            let serials = effective_serials(&devices);
            let label = keyring
                .name_for(serials[0].as_deref())
                .unwrap_or(&d.product_name);
            format!(
                " — target: {} at {}",
                sanitize_terminal(label),
                d.path.display()
            )
        }
        [] => String::new(),
        many => format!(
            " — {} FIDO keys connected; pass --device or --path to choose",
            many.len()
        ),
    }
}

/// Find the connected device named `name` and return its PC/SC reader substring.
/// Pure over an already-enumerated device list so it is unit-testable without
/// hardware. Fails closed when more than one device carries the name (KEY-015).
fn reader_for_name(
    devices: &[keyroost_resolve::Device],
    name: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let matches: Vec<&keyroost_resolve::Device> = devices
        .iter()
        .filter(|d| d.name.as_deref() == Some(name))
        .collect();
    let dev = match matches.as_slice() {
        [] => {
            return Err(format!(
                "no connected device is named '{name}' (see `keyroostctl key-name list`)"
            )
            .into());
        }
        [one] => *one,
        many => {
            return Err(format!(
                "{} connected devices are named '{name}'; refusing to guess which one",
                many.len()
            )
            .into());
        }
    };
    dev.reader.clone().ok_or_else(|| {
        format!("device '{name}' has no smart-card (PC/SC) interface for this command").into()
    })
}

/// Resolve the global `--device` (if set) to a PC/SC reader name via the shared
/// device model, so `--device` targets smart-card / Molto2 groups the same way
/// `--reader` does. Returns the reader substring to match, or None when no
/// `--device` was given. Errors if a name is set but resolves to no PC/SC reader.
fn reader_from_name() -> Result<Option<String>, Box<dyn std::error::Error>> {
    let Some(name) = SELECTED_KEY_NAME.get().and_then(|o| o.clone()) else {
        return Ok(None);
    };
    let devices = keyroost_resolve::enumerate()?;
    Ok(Some(reader_for_name(&devices, &name)?))
}

fn resolve_fido_path(explicit: Option<&Path>) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let name = SELECTED_KEY_NAME.get().and_then(|o| o.as_deref());
    if explicit.is_some() && name.is_some() {
        return Err("pass either --path or --device, not both".into());
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
        String::from("no FIDO HID device found. Plug a security key in, or pass --path/--device.");
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
    // `label` is a device USB product string and the keyring name is
    // user-editable; both reach the terminal, so flatten control chars.
    let label = sanitize_terminal(label);
    match keyring.name_for(serial) {
        Some(name) => eprintln!(
            "\u{2192} {} ({}, {})",
            sanitize_terminal(name),
            label,
            path.display()
        ),
        None => eprintln!("\u{2192} {} ({})", label, path.display()),
    }
}

/// Pick one device when no `--path`/`--device` was given: a lone key is used
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
                    "{} FIDO devices connected; pass --device or --path \
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
            Some(name) => format!(
                "{}  ({})",
                sanitize_terminal(name),
                sanitize_terminal(&d.product_name)
            ),
            None => sanitize_terminal(&d.product_name),
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
    eprintln!("\u{2192} OATH on {}", sanitize_terminal(&name));
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

/// Resolve exactly one device for a whole-device operation: the one matching
/// the global `--device` selector, or the lone connected key when no selector
/// is set. Fails closed on zero matches and refuses to guess among several
/// (mirrors `resolve_otp_target`'s name-match/ambiguity posture, without an
/// applet filter).
fn resolve_single_device<'a>(
    devices: &'a [keyroost_resolve::Device],
    name: Option<&str>,
) -> Result<&'a keyroost_resolve::Device, Box<dyn std::error::Error>> {
    match name {
        Some(name) => {
            let matches: Vec<&keyroost_resolve::Device> = devices
                .iter()
                .filter(|d| d.name.as_deref() == Some(name))
                .collect();
            match matches.as_slice() {
                [] => Err(format!(
                    "no connected device is named '{name}' \
                     (see `keyroostctl key-name list`)"
                )
                .into()),
                [one] => Ok(*one),
                many => Err(format!(
                    "{} connected devices are named '{name}'; refusing to guess \
                     which key to factory-reset",
                    many.len()
                )
                .into()),
            }
        }
        None => match devices {
            [] => Err("no security key detected".into()),
            [one] => Ok(one),
            many => Err(format!(
                "{} keys are connected; select one with `--device <name>` before \
                 factory-resetting",
                many.len()
            )
            .into()),
        },
    }
}

/// Whole-device factory reset: run every applet reset the key supports, in
/// planner order, continue on failure, print a per-step report, and exit
/// nonzero if anything failed. FIDO2 is last and needs a physical replug +
/// touch, prompted interactively.
/// A wipe command must not be handed a contradictory `--reader` and `--device`
/// at once: the banner would name the `--device`-resolved key while the card
/// steps opened the `--reader` one. Refuse the combination up front, mirroring
/// how `resolve_fido_path` rejects `--path` + `--device`.
fn reader_device_conflict(
    reader: Option<&str>,
    device_name: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    if reader.is_some() && device_name.is_some() {
        return Err("pass either --reader or --device, not both (they may name \
                    different keys, and this wipes the one you didn't mean to)"
            .into());
    }
    Ok(())
}

/// What the user reads before consenting to a whole-device wipe.
///
/// It does not promise the key "stays usable": PIV's wipe blocks the PIN and
/// PUK on purpose before erasing, so a run that stops in between leaves that
/// applet locked and un-wiped. What can be promised is per applet and per step
/// — the same line the GUI's `factory_reset_confirm_summary` settled on, so the
/// two front ends ask for consent to the same thing.
const FACTORY_RESET_CONSENT: &str =
    "refusing to factory-reset without --yes (wipes ALL applets: OATH, OpenPGP, \
     PIV, Token2 OTP, and FIDO2; every credential, code, key, and PIN is erased. \
     Each applet that completes comes back in factory condition, and every step \
     reports its own outcome)";

fn run_factory_reset(
    reader: Option<&str>,
    yes: bool,
    debug: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use keyroost_resolve::{factory_reset_plan, ResetStep, StepOutcome, StepReport};

    if !yes {
        return Err(FACTORY_RESET_CONSENT.into());
    }

    // Resolve the one selected device (or a lone key) via the shared model,
    // so a name/`--device` binds exactly like the other commands.
    let devices = keyroost_resolve::enumerate()?;
    let name = SELECTED_KEY_NAME.get().and_then(|o| o.as_deref());
    reader_device_conflict(reader, name)?;
    let dev = resolve_single_device(&devices, name)?;
    // Pin the target's identity now, while it is still the key the user
    // confirmed against: the FIDO step below has to re-find it after a replug,
    // and by then the resolver would happily hand back whichever key is in the
    // port instead.
    let expected_serial = dev.serial.clone();
    let expected_model = dev.model.clone();
    // …and its USB ids, which are what a key with no serial can still be told
    // apart by. The model name can't do that job on its own: before the replug
    // it may be read off the PC/SC reader name and afterwards off the HID
    // product string, and outside the vendors we normalize those two are not
    // the same string.
    let expected_ids = hid_ids_at(
        dev.hid_path.as_deref(),
        &keyroost_hid::enumerate().unwrap_or_default(),
    );
    let plan = factory_reset_plan(dev.caps);
    if plan.is_empty() {
        return Err(format!(
            "'{}' exposes no resettable applet (nothing to factory-reset)",
            sanitize_terminal(&dev.model)
        )
        .into());
    }

    eprintln!(
        "\u{2192} factory-resetting {} ({})",
        sanitize_terminal(&dev.serial),
        plan.iter()
            .map(|s| s.label())
            .collect::<Vec<_>>()
            .join(", ")
    );

    let mut reports: Vec<StepReport> = Vec::new();
    for step in &plan {
        let outcome = match step {
            ResetStep::Fido => {
                if dev.hid_path.is_none() {
                    // A card in a reader: no replug exists and no touch surface
                    // — the replug prompt below could never be satisfied
                    // (issue #84). Power-cycle the card in place instead,
                    // which starts the same post-power-up window. The target
                    // cannot have been swapped mid-flow: the card never left
                    // the reader we have been talking to all along.
                    match dev
                        .reader
                        .as_deref()
                        .ok_or_else(|| "no reader holds this card any more".to_string())
                        .and_then(|r| run_fido_reset_reader(r).map_err(|e| e.to_string()))
                    {
                        Ok(()) => StepOutcome::Wiped,
                        Err(e) => StepOutcome::Failed(sanitize_terminal(&e)),
                    }
                } else {
                    // Interactive replug + touch; on its own so a card-step
                    // failure above never skips the FIDO offer.
                    match fido_reset_after_replug(&expected_serial, &expected_model, expected_ids) {
                        Ok(()) => StepOutcome::Wiped,
                        Err(e) => StepOutcome::Failed(sanitize_terminal(&e.to_string())),
                    }
                }
            }
            other => reset_one_card_applet(*other, reader, debug),
        };
        let label = step.label();
        match &outcome {
            StepOutcome::Wiped => println!("{label:<8} wiped"),
            StepOutcome::Failed(e) => println!("{label:<8} failed: {e}"),
            StepOutcome::Skipped => println!("{label:<8} skipped"),
        }
        reports.push(StepReport {
            step: *step,
            outcome,
        });
    }

    let failed = reports
        .iter()
        .filter(|r| matches!(r.outcome, StepOutcome::Failed(_)))
        .count();
    let wiped = reports.len() - failed;
    println!("factory reset: {wiped} wiped, {failed} failed");
    if failed > 0 {
        return Err(format!("{failed} applet(s) failed to reset").into());
    }
    Ok(())
}

/// Which connected key — if any — is the one the factory reset was confirmed
/// for, after the FIDO step's replug prompt.
#[derive(Debug, PartialEq, Eq)]
enum ReinsertMatch {
    /// Index into the candidate list of the key the reset was confirmed for.
    Found(usize),
    /// Nothing connected carries the expected identity.
    NotPresent,
    /// Several connected keys claim it, so it identifies none of them.
    Ambiguous,
}

/// Decide which of the keys present after the replug prompt is the one the
/// factory reset was confirmed for. Identity is the resolver's effective serial
/// (USB `iSerialNumber`, else the CCID-read one); an unknown serial on either
/// side matches nothing, mirroring the GUI's `reset_reinsert_matches`
/// fail-closed rule — being the same model in the same port is not an identity
/// (KEY-005). A serial several keys report is not one either (KEY-015), so it
/// is reported as ambiguous rather than resolved to the first hit.
fn reinserted_target(expected_serial: &str, candidates: &[&str]) -> ReinsertMatch {
    if expected_serial.is_empty() {
        return ReinsertMatch::NotPresent;
    }
    let mut hits = candidates
        .iter()
        .enumerate()
        .filter(|(_, s)| **s == expected_serial)
        .map(|(i, _)| i);
    match (hits.next(), hits.next()) {
        (Some(i), None) => ReinsertMatch::Found(i),
        (Some(_), Some(_)) => ReinsertMatch::Ambiguous,
        _ => ReinsertMatch::NotPresent,
    }
}

/// Why the key the reset was confirmed for is not among the ones visible after
/// the replug. The two are not the same event and must not carry the same
/// message: one is a key swap, the other is a key that has not finished
/// re-enumerating.
#[derive(Debug, PartialEq, Eq)]
enum NotPresentReason {
    /// Everything visible names itself, and none of them is the pinned key.
    DifferentKey,
    /// Nothing is visible yet, or something visible has not published a serial
    /// yet — so it cannot be ruled in *or* out.
    Unidentified,
}

/// Distinguish "a different key is in the port" from "the key hasn't come back
/// with an identity yet".
///
/// Only the first is a swap, and only it may be said out loud: a key whose
/// serial is read over the card interface (every YubiKey — it exposes no USB
/// `iSerialNumber`) shows up HID-first with an empty serial and re-registers
/// with the smart-card service a beat later. Until then it is indistinguishable
/// from a stranger by serial alone, and accusing the user of a swap they did not
/// make — while pointing them at a re-run that races the same way — is the worse
/// error of the two. So a mismatch is claimed only when *every* visible key
/// names itself and none of the names is the pinned one; an empty serial
/// anywhere (including nothing connected at all) means unidentified.
///
/// `serials` must already be narrowed to devices that expose a FIDO interface.
/// Anything without one cannot be the key being waited for, so its (absent)
/// serial says nothing about whether that key came back — counting it would
/// turn every verdict into "unidentified" whenever an unrelated smart-card
/// token happened to be plugged in elsewhere.
fn not_present_reason(serials: &[&str]) -> NotPresentReason {
    if !serials.is_empty() && serials.iter().all(|s| !s.is_empty()) {
        NotPresentReason::DifferentKey
    } else {
        NotPresentReason::Unidentified
    }
}

/// What to tell the user when the pinned key wasn't among the keys visible
/// after the replug — a refusal either way, but only one of them is an
/// accusation, and only one of them names the right way out.
fn not_present_message(
    expected_model: &str,
    expected_serial: &str,
    waited_secs: u64,
    present: &str,
    reason: NotPresentReason,
) -> String {
    match reason {
        NotPresentReason::DifferentKey => format!(
            "the key now connected is not the one this factory reset was confirmed \
             for: expected {} serial {}, found {present}. Nothing was reset over \
             FIDO2 — plug the intended key in and re-run `keyroostctl \
             factory-reset --yes`.",
            sanitize_terminal(expected_model),
            sanitize_terminal(expected_serial),
        ),
        NotPresentReason::Unidentified => format!(
            "the key this factory reset was confirmed for ({} serial {}) did not \
             come back with an identity to match within {waited_secs} seconds of \
             the replug: found {present}. That is not a different key — its serial \
             is read over the card interface, which re-registers with the \
             smart-card service a beat after the FIDO one, so a key that is simply \
             slow to settle looks exactly like this. Nothing was reset over FIDO2 \
             — give it a moment, then run `keyroostctl fido reset --yes` to finish \
             the wipe (re-running `keyroostctl factory-reset --yes` would repeat \
             the applet resets and race the same way).",
            sanitize_terminal(expected_model),
            sanitize_terminal(expected_serial),
        ),
    }
}

/// One connected key reduced to what the post-replug match needs: its effective
/// serial, its model name, its USB ids, and whether it exposes a FIDO HID
/// interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Candidate<'a> {
    serial: &'a str,
    model: &'a str,
    ids: Option<(u16, u16)>,
    fido: bool,
}

/// The USB vendor/product ids of the hidraw node a resolved device is bound to.
/// `keyroost_resolve::Device` carries the path but not the ids, so the HID
/// enumeration is what supplies them; a device with no FIDO interface, or one
/// whose node came or went between the two scans, has none.
fn hid_ids_at(path: Option<&Path>, hids: &[keyroost_hid::HidDevice]) -> Option<(u16, u16)> {
    let path = path?;
    hids.iter()
        .find(|h| h.path == path)
        .map(|h| (h.vendor_id, h.product_id))
}

/// Whether a serial-less candidate is the same *product* as the pinned key.
///
/// USB ids decide it whenever both sides expose them, as `ResetArm.target_ids`
/// does in the GUI. The model name can't: it is derived from the PC/SC reader
/// name on one side of the replug and from the HID product string on the other,
/// and for any vendor whose reader name we don't normalize to the same string
/// those two differ — turning "the same key came back" into a refusal. A
/// differing name is no more a mismatch here than it is on the serial path,
/// which already accepts a relabelled key. The name stays only as the fallback
/// for a key whose ids are unknown on one side or the other.
fn same_product(
    expected_model: &str,
    expected_ids: Option<(u16, u16)>,
    cand: &Candidate<'_>,
) -> bool {
    match (expected_ids, cand.ids) {
        (Some(expected), Some(got)) => expected == got,
        _ => cand.model == expected_model,
    }
}

/// Decide which of the keys present after the replug prompt is the confirmed
/// one when that key has no serial to be matched by.
///
/// Some keys genuinely have no identity to pin: a FIDO-only key with no USB
/// `iSerialNumber` and no CCID reader resolves to an empty serial, and refusing
/// on that alone leaves the whole factory reset a dead end for them. So the
/// serial-less case matches on the one thing that *is* provable — that there is
/// nothing else the key could be: exactly one key is connected, it too has no
/// serial, it is the same product (see `same_product`), and it speaks FIDO. A
/// second visible key refuses immediately, which leaves only a deliberate
/// hot-swap of an identical serial-less model during the prompt — the risk
/// `fido reset --yes` already accepts.
fn reinserted_serial_less_target(
    expected_model: &str,
    expected_ids: Option<(u16, u16)>,
    candidates: &[Candidate<'_>],
) -> ReinsertMatch {
    match candidates {
        [only]
            if only.serial.is_empty()
                && same_product(expected_model, expected_ids, only)
                && only.fido =>
        {
            ReinsertMatch::Found(0)
        }
        [] | [_] => ReinsertMatch::NotPresent,
        // Anything else connected and the "nothing else it could be" argument
        // is gone; there is no serial left to tell them apart with.
        _ => ReinsertMatch::Ambiguous,
    }
}

/// Match the keys present after the replug against the identity pinned before
/// it: by serial when the key has one, by sole-candidate otherwise. Splitting on
/// the pinned serial is what keeps the looser serial-less rule out of reach of
/// any key that can be identified properly.
fn reinserted_match(
    expected_serial: &str,
    expected_model: &str,
    expected_ids: Option<(u16, u16)>,
    candidates: &[Candidate<'_>],
) -> ReinsertMatch {
    if expected_serial.is_empty() {
        return reinserted_serial_less_target(expected_model, expected_ids, candidates);
    }
    let serials: Vec<&str> = candidates.iter().map(|c| c.serial).collect();
    reinserted_target(expected_serial, &serials)
}

/// Whether a post-replug look has an answer worth acting on, or whether the
/// poll should keep going.
///
/// Anything but `NotPresent` normally settles it — except a `Found` on a row
/// with no FIDO HID interface, which is the *card* side of the key arriving
/// first: the hidraw node is not created yet, or its report descriptor still
/// reads empty so nothing classifies it as FIDO. Acting on that means failing
/// with "came back without a FIDO HID interface" while the whole budget that
/// exists for a half-enumerated key sits unspent. `Ambiguous` still stops at
/// once: a second key claiming the pinned identity does not become less true by
/// waiting.
fn reinsert_settled(found: &ReinsertMatch, candidates: &[Candidate<'_>]) -> bool {
    match *found {
        ReinsertMatch::NotPresent => false,
        ReinsertMatch::Found(i) => matches!(candidates.get(i), Some(c) if c.fido),
        ReinsertMatch::Ambiguous => true,
    }
}

/// One post-replug look: the resolved devices reduced to candidates, matched
/// against the pinned identity, plus whether that answer settles the poll.
fn match_reinsert(
    expected_serial: &str,
    expected_model: &str,
    expected_ids: Option<(u16, u16)>,
    present: &[keyroost_resolve::Device],
) -> (ReinsertMatch, bool) {
    let hids = keyroost_hid::enumerate().unwrap_or_default();
    let candidates = candidates_of(present, &hids);
    let found = reinserted_match(expected_serial, expected_model, expected_ids, &candidates);
    let settled = reinsert_settled(&found, &candidates);
    (found, settled)
}

/// The keys visible after the replug, named for the mismatch message so the
/// user can see what keyroost is looking at instead of the intended key.
fn describe_present(devices: &[keyroost_resolve::Device]) -> String {
    if devices.is_empty() {
        return "no connected key".into();
    }
    devices
        .iter()
        .map(|d| {
            let model = sanitize_terminal(&d.model);
            if d.serial.is_empty() {
                format!("{model} with no serial")
            } else {
                format!("{model} serial {}", sanitize_terminal(&d.serial))
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// The FIDO2 step of a whole-device factory reset: prompt for the replug the
/// CTAP reset window requires, then *prove* the key that came back is the one
/// the wipe was confirmed for before touching it.
///
/// Resolving a FIDO device from scratch after the prompt is what makes this
/// dangerous: with one key connected the resolver auto-selects whatever is now
/// plugged in, a same-model key is indistinguishable by product name and hidraw
/// path, and `authenticatorReset` erases every passkey and the PIN with no
/// further confirmation. So the identity captured before the prompt has to
/// match afterwards. A key that has no serial to match on can't prove that by
/// identity, so it falls back to proving it by exclusion — see
/// `reinserted_serial_less_target` — and any second key in sight refuses.
fn fido_reset_after_replug(
    expected_serial: &str,
    expected_model: &str,
    expected_ids: Option<(u16, u16)>,
) -> Result<(), Box<dyn std::error::Error>> {
    let serial_less = expected_serial.is_empty();

    println!("FIDO2  unplug the key, plug it back in, then press Enter\u{2026}");
    let mut _line = String::new();
    std::io::stdin().read_line(&mut _line).ok();

    // A just-replugged key needs a beat before its interfaces re-register, and
    // the card one — where a YubiKey's serial is read from, it publishes no USB
    // iSerialNumber — is the slower of the two. So a first look that finds
    // nothing is retried against a wall-clock deadline, not a scan count: with
    // no reader registered yet an `enumerate()` returns in milliseconds, and a
    // handful of those back to back is not a wait at all.
    //
    // Three seconds is the budget. It is long enough for a reader replugged a
    // moment ago to register with the smart-card service (the GUI spends four
    // scans at 1500 ms on this same event) and short enough to leave most of
    // the ~10 s post-power-up window a FIDO reset has to land in for the touch
    // that follows. It is only ever spent on a key that would otherwise have
    // been refused outright.
    const REINSERT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(3);
    const REINSERT_POLL: std::time::Duration = std::time::Duration::from_millis(300);
    let deadline = std::time::Instant::now() + REINSERT_DEADLINE;

    let mut present = keyroost_resolve::enumerate()?;
    let (mut found, mut settled) =
        match_reinsert(expected_serial, expected_model, expected_ids, &present);
    while !settled && std::time::Instant::now() + REINSERT_POLL < deadline {
        std::thread::sleep(REINSERT_POLL);
        present = keyroost_resolve::enumerate()?;
        (found, settled) = match_reinsert(expected_serial, expected_model, expected_ids, &present);
    }
    // Only keys that expose a FIDO interface can be the one we are waiting for,
    // so only their serials decide whether this is a swap or a key that has not
    // identified itself yet. A CCID-only device — a Molto2 sitting in another
    // port — reports no serial here and would otherwise drag every verdict to
    // "unidentified", telling the user "that is not a different key" while a
    // different key is plainly connected. Observed on hardware.
    let serials: Vec<&str> = present
        .iter()
        .filter(|d| d.hid_path.is_some())
        .map(|d| d.serial.as_str())
        .collect();

    let i = match found {
        ReinsertMatch::Found(i) => i,
        ReinsertMatch::NotPresent if serial_less => {
            return Err(format!(
                "'{}' exposes no serial to re-identify it by after a replug, so it can \
                 only be reset when it is the single connected key and answers over \
                 FIDO2 — and that is not what came back: found {}. Nothing was reset \
                 over FIDO2 — plug the intended key in on its own and re-run \
                 `keyroostctl factory-reset --yes`.",
                sanitize_terminal(expected_model),
                describe_present(&present)
            )
            .into());
        }
        ReinsertMatch::NotPresent => {
            return Err(not_present_message(
                expected_model,
                expected_serial,
                REINSERT_DEADLINE.as_secs(),
                &describe_present(&present),
                not_present_reason(&serials),
            )
            .into());
        }
        ReinsertMatch::Ambiguous if serial_less => {
            return Err(format!(
                "'{}' exposes no serial to re-identify it by after a replug, so it can \
                 only be told apart from other keys by being the only one connected — \
                 but more than one is: {}. Nothing was reset over FIDO2 — unplug the \
                 others and re-run `keyroostctl factory-reset --yes` with only the \
                 intended key connected.",
                sanitize_terminal(expected_model),
                describe_present(&present)
            )
            .into());
        }
        ReinsertMatch::Ambiguous => {
            return Err(format!(
                "more than one connected key reports serial {}, so the key that came \
                 back can't be told apart from the others. Nothing was reset over \
                 FIDO2 — re-run `keyroostctl factory-reset --yes` with only the \
                 intended key connected.",
                sanitize_terminal(expected_serial)
            )
            .into());
        }
    };

    let dev = &present[i];
    let Some(path) = dev.hid_path.clone() else {
        return Err(format!(
            "'{}' came back without a FIDO HID interface, so it can't be reset over \
             FIDO2 — re-plug it and re-run `keyroostctl factory-reset --yes`.",
            sanitize_terminal(&dev.model)
        )
        .into());
    };
    println!("FIDO2  touch the key now\u{2026}");
    fido_reset_at(&path)
}

/// The resolved devices reduced to what the post-replug match reads, parallel
/// to `devices` so a `Found(i)` indexes straight back into them.
fn candidates_of<'a>(
    devices: &'a [keyroost_resolve::Device],
    hids: &[keyroost_hid::HidDevice],
) -> Vec<Candidate<'a>> {
    devices
        .iter()
        .map(|d| Candidate {
            serial: d.serial.as_str(),
            model: d.model.as_str(),
            ids: hid_ids_at(d.hid_path.as_deref(), hids),
            fido: d.hid_path.is_some(),
        })
        .collect()
}

/// What a PIV factory-reset step reports when it fails with anything but the
/// three self-describing variants: the error, plus where the card actually
/// stands and what finishes the job.
///
/// `force_reset` blocks the PIN and PUK on its way to RESET — the card only
/// accepts a RESET once both are blocked — so a fault in the middle can leave
/// PIV locked but not wiped. That is not bricked, but it is also not something
/// `keyroostctl piv reset` can finish: a fault in the PUK loop leaves the PIN
/// blocked and the PUK *not* blocked, which is exactly the state
/// `PivSession::reset` answers `PivResetNotAllowed` to. Re-running the factory
/// reset is the path that works whether one credential ended up blocked or
/// both, so that is what this points at (and what the GUI says).
fn piv_factory_reset_failure(err: &str) -> String {
    format!(
        "{err} (the wipe blocks the PIN and PUK before erasing, so PIV may now be \
         locked but not wiped — that is not bricked: re-run `keyroostctl \
         factory-reset` to finish it)"
    )
}

/// Run one card-applet reset step, mapping its result to a StepOutcome so a
/// single failure is recorded, not propagated (continue-on-error).
fn reset_one_card_applet(
    step: keyroost_resolve::ResetStep,
    reader: Option<&str>,
    debug: bool,
) -> keyroost_resolve::StepOutcome {
    use keyroost_resolve::{ResetStep, StepOutcome};
    let run = || -> Result<(), Box<dyn std::error::Error>> {
        match step {
            ResetStep::Oath => {
                let by_name = reader_from_name()?;
                let name = resolve_oath_reader(reader.or(by_name.as_deref()))?;
                let mut s = keyroost_transport::OathSession::open(&name)?;
                s.set_debug(debug);
                s.factory_reset()?;
            }
            ResetStep::OpenPgp => {
                let mut s = open_openpgp(reader, debug)?;
                s.factory_reset()?;
            }
            ResetStep::Piv => {
                let mut s = open_piv(reader, debug)?;
                s.force_reset().map_err(|e| -> Box<dyn std::error::Error> {
                    match e {
                        // These three already state the card's real state and
                        // the way forward. Pointing at `keyroostctl piv reset`
                        // on top of them would be wrong: it sends the very
                        // RESET the card just refused (Unsupported), or it
                        // contradicts their own "re-run the factory reset"
                        // (Incomplete, PukGuessAccepted).
                        TransportError::PivForceResetUnsupported
                        | TransportError::PivForceResetIncomplete(_)
                        | TransportError::PivPukGuessAccepted => e.into(),
                        other => piv_factory_reset_failure(&other.to_string()).into(),
                    }
                })?;
            }
            ResetStep::Token2Otp => {
                let mut s = open_otp(OtpTransportArg::Auto, debug)?;
                s.erase_all()?;
            }
            ResetStep::Fido => unreachable!("FIDO handled by the interactive path"),
        }
        Ok(())
    };
    match run() {
        Ok(()) => StepOutcome::Wiped,
        Err(e) => StepOutcome::Failed(sanitize_terminal(&e.to_string())),
    }
}

fn run_oath(cmd: &OathCmd, debug: bool) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        OathCmd::List { access } => {
            let mut session = open_oath(access, debug)?;
            let listing = session.list()?;
            if listing.skipped > 0 {
                // The listing is PARTIAL — say so loudly, on stderr so it also
                // reaches --json users without breaking the output schema. An
                // invisible entry would otherwise be silently destroyed by a
                // reset the user believed they had fully audited.
                eprintln!(
                    "warning: {} credential entr{} on the key could not be decoded and {} not shown; \
                     the listing is incomplete",
                    listing.skipped,
                    if listing.skipped == 1 { "y" } else { "ies" },
                    if listing.skipped == 1 { "is" } else { "are" },
                );
            }
            let creds = listing.credentials;
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
                        sanitize_terminal(&c.name),
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
                .credentials
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
        OathCmd::Reset { reader, yes } => {
            if !*yes {
                return Err("refusing to reset the OATH applet without --yes \
                            (wipes ALL authenticator credentials and clears the \
                            access password; this cannot be undone)"
                    .into());
            }
            // Deliberately NOT open_oath(): reset must work on a
            // password-protected applet whose password is lost — that's its
            // entire purpose — so no unlock is attempted.
            let by_name = reader_from_name()?;
            let name = resolve_oath_reader(reader.as_deref().or(by_name.as_deref()))?;
            eprintln!("\u{2192} OATH on {}", sanitize_terminal(&name));
            let mut session = keyroost_transport::OathSession::open(&name)?;
            session.set_debug(debug);
            session.factory_reset()?;
            println!("OATH applet reset: all credentials wiped, access password cleared.");
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

/// Run a Molto2 slot sweep until the first read failure: everything read so
/// far is kept, and the failing (slot, error) pair — if any — is reported
/// alongside it. Sweeping past a failed read is pointless (a wedged CCID
/// session fails the remaining ~90 reads slowly, one timeout each), but the
/// slots already read are real data the user should still see. Pure over an
/// iterator of results so it is unit-testable without hardware.
fn sweep_until_error<I>(
    reads: I,
) -> (
    Vec<keyroost_proto::ProfilePublicData>,
    Option<(u8, keyroost_transport::TransportError)>,
)
where
    I: Iterator<
        Item = (
            u8,
            Result<keyroost_proto::ProfilePublicData, keyroost_transport::TransportError>,
        ),
    >,
{
    let mut slots = Vec::with_capacity(100);
    for (slot, read) in reads {
        match read {
            Ok(b) => slots.push(b),
            Err(e) => return (slots, Some((slot, e))),
        }
    }
    (slots, None)
}

/// Where an explicit `--device` selection resolves to for the Token2 OTP applet.
#[derive(Debug)]
enum OtpTarget {
    HidPath(std::path::PathBuf),
    Reader(String),
    /// An `auto` pick on a key exposing both interfaces: open USB-HID first,
    /// fall back to the SAME device's PC/SC reader when the HID open (or its
    /// applet probe) fails — some firmware answers the HID GET_INFO probe
    /// with a malformed status word while its CCID side works (#82). Both
    /// endpoints belong to the one resolved device, so the KEY-003
    /// never-first-match guarantee is preserved.
    HidThenReader(std::path::PathBuf, String),
}

/// Resolve the global `--device` selector to a concrete OTP transport target so
/// an OTP command binds to the key the user named rather than the first key that
/// enumerates. Returns `Ok(None)` when no `--device` is set (the caller then uses
/// the auto/HID/CCID detection path). Fails closed when the name matches zero or
/// more than one live OTP-capable device, or when the device cannot satisfy the
/// requested transport.
fn resolve_otp_target(
    devices: &[keyroost_resolve::Device],
    name: Option<&str>,
    transport: OtpTransportArg,
) -> Result<Option<OtpTarget>, Box<dyn std::error::Error>> {
    use keyroost_resolve::Caps;
    let Some(name) = name else { return Ok(None) };
    let matches: Vec<&keyroost_resolve::Device> = devices
        .iter()
        .filter(|d| d.name.as_deref() == Some(name) && d.caps.has(Caps::OTP))
        .collect();
    let dev = match matches.as_slice() {
        [] => {
            return Err(format!(
                "no connected OTP-capable device is named '{name}' \
                 (see `keyroostctl key-name list`)"
            )
            .into());
        }
        [one] => *one,
        many => {
            return Err(format!(
                "{} connected devices are named '{name}'; refusing to guess which \
                 OTP key to use",
                many.len()
            )
            .into());
        }
    };
    let target =
        match transport {
            OtpTransportArg::Hid => OtpTarget::HidPath(dev.hid_path.clone().ok_or_else(|| {
                format!("device '{name}' has no USB-HID interface for --transport hid")
            })?),
            OtpTransportArg::Ccid => OtpTarget::Reader(dev.reader.clone().ok_or_else(|| {
                format!("device '{name}' has no PC/SC reader for --transport ccid")
            })?),
            OtpTransportArg::Auto => {
                match (dev.hid_path.clone(), dev.reader.clone()) {
                    // Both interfaces: HID first, the same key's reader as an
                    // open-time fallback (#82).
                    (Some(p), Some(r)) => OtpTarget::HidThenReader(p, r),
                    (Some(p), None) => OtpTarget::HidPath(p),
                    (None, Some(r)) => OtpTarget::Reader(r),
                    (None, None) => {
                        return Err(format!(
                            "device '{name}' exposes no OTP transport (neither USB-HID nor PC/SC)"
                        )
                        .into());
                    }
                }
            }
        };
    Ok(Some(target))
}

/// Open a Token2 OTP session on the requested transport and register a touch
/// prompt for button-required commands. When a global `--device` selector is
/// set the session binds to that exact device (KEY-003) and fails closed on an
/// unknown or ambiguous name; without a selector it uses first-match detection.
fn open_otp(
    transport: OtpTransportArg,
    debug: bool,
) -> Result<keyroost_transport::Token2OtpSession, Box<dyn std::error::Error>> {
    let name = SELECTED_KEY_NAME.get().and_then(|o| o.as_deref());
    let mut session = if name.is_some() {
        let devices = keyroost_resolve::enumerate()?;
        match resolve_otp_target(&devices, name, transport)? {
            Some(OtpTarget::HidPath(p)) => {
                keyroost_transport::Token2OtpSession::open_hid_path(&p, debug)?
            }
            Some(OtpTarget::Reader(r)) => {
                keyroost_transport::Token2OtpSession::open_pcsc_reader(&r, debug)?
            }
            Some(OtpTarget::HidThenReader(p, r)) => {
                match keyroost_transport::Token2OtpSession::open_hid_path(&p, debug) {
                    Ok(s) => s,
                    Err(hid_err) => {
                        eprintln!(
                            "{}",
                            sanitize_terminal(&format!(
                                "USB-HID path failed ({hid_err}); trying the same \
                                 key's smart-card reader\u{2026}"
                            ))
                        );
                        keyroost_transport::Token2OtpSession::open_pcsc_reader(&r, debug)?
                    }
                }
            }
            None => unreachable!("a set --device always yields a target or an error"),
        }
    } else {
        match transport {
            OtpTransportArg::Auto => keyroost_transport::Token2OtpSession::detect_debug(debug)?,
            OtpTransportArg::Hid => keyroost_transport::Token2OtpSession::detect_hid_only(debug)?,
            OtpTransportArg::Ccid => keyroost_transport::Token2OtpSession::detect_pcsc_only(debug)?,
        }
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

/// A Token2 OTP function that ships as a separate product configuration. Which
/// functions a key has is fixed when it is made — a key supplied without one
/// can't gain it later — so a command that needs a missing function should say
/// that plainly rather than surface the protocol error its first APDU produces.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum OtpFeature {
    /// The on-device OTP store (`otp list` / `get` / `add` / `delete` / `erase-all`).
    OnDevice,
    /// The single HOTP-on-touch keystroke slot (`otp button-hotp`).
    ButtonHotp,
}

impl OtpFeature {
    fn missing_message(self) -> &'static str {
        match self {
            OtpFeature::OnDevice => {
                "this key does not have the on-device OTP function: it reports that it was \
                 supplied without it, so it cannot store TOTP or HOTP entries. Token2 keys \
                 aren't upgradable after purchase — OTP is a separate product configuration, \
                 not something that can be switched on later. Run `keyroostctl otp config` to \
                 see the capabilities the key reports."
            }
            OtpFeature::ButtonHotp => {
                "this key does not have the HOTP-on-touch function: it reports that it was \
                 supplied without it. Token2 keys aren't upgradable after purchase — the \
                 keystroke slot is a separate product configuration, not something that can \
                 be switched on later. Run `keyroostctl otp config` to see the capabilities \
                 the key reports."
            }
        }
    }
}

/// What the key's config block says about `feature`.
///
/// * `Some(true)`  — the key advertises it.
/// * `Some(false)` — the key answered with a full config block and says it does not
///   have it.
/// * `None` — we can't tell: no config was read, or the block was too short to
///   reach the capability byte. Callers must treat `None` as "go ahead": refusing
///   a command because a read failed would be worse than letting it run and
///   report its own error.
fn otp_feature_capability(
    info: Option<&keyroost_token2otp::DeviceInfo>,
    feature: OtpFeature,
) -> Option<bool> {
    let info = info?;
    // The capability bits live in byte 9. Some firmware answers READ_CONFIG with
    // only the leading interface-state byte(s); the parser zero-fills the rest,
    // which would read back as a confident "unsupported".
    if info.raw_len < 10 {
        return None;
    }
    Some(match feature {
        OtpFeature::OnDevice => info.totp_supported(),
        OtpFeature::ButtonHotp => info.button_hotp_supported(),
    })
}

/// Stop before the operation when the key's own config says it lacks `feature`.
///
/// Best-effort by design: this only helps when the config read SUCCEEDS. A key
/// whose exchange fails outright never yields a capability byte, and the command
/// proceeds exactly as before so that failure is reported unchanged.
fn ensure_otp_feature(
    session: &mut keyroost_transport::Token2OtpSession,
    feature: OtpFeature,
) -> Result<(), Box<dyn std::error::Error>> {
    let info = session.read_device_info().ok();
    if otp_feature_capability(info.as_ref(), feature) == Some(false) {
        return Err(feature.missing_message().into());
    }
    Ok(())
}

fn run_otp(
    cmd: &OtpCmd,
    transport: OtpTransportArg,
    debug: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        OtpCmd::List => {
            let mut session = open_otp(transport, debug)?;
            ensure_otp_feature(&mut session, OtpFeature::OnDevice)?;
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
                    // app/account names come from the device; strip escapes.
                    let label = sanitize_terminal(&label);
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
            ensure_otp_feature(&mut session, OtpFeature::OnDevice)?;
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
            ensure_otp_feature(&mut session, OtpFeature::OnDevice)?;
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
            ensure_otp_feature(&mut session, OtpFeature::OnDevice)?;
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
            // Checked before the touch prompt: no point asking for a physical
            // touch on a key that has nothing to erase.
            ensure_otp_feature(&mut session, OtpFeature::OnDevice)?;
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
            ensure_otp_feature(&mut session, OtpFeature::ButtonHotp)?;
            session.set_button_hotp(*digits, &seed, !*no_enter, *long_touch, *numpad)?;
            println!("Configured the HOTP-on-button keystroke slot.");
        }
        OtpCmd::DeleteButtonHotp => {
            let mut session = open_otp(transport, debug)?;
            ensure_otp_feature(&mut session, OtpFeature::ButtonHotp)?;
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
            // Capability bits live in byte 9, so a short block can't answer these;
            // say "unknown" rather than report a zero-fill as a hard "no".
            let cap = |feature| match otp_feature_capability(Some(&info), feature) {
                Some(true) => "yes",
                Some(false) => "no",
                None => "unknown (device returned a short config block)",
            };
            println!("  on-device OTP support:  {}", cap(OtpFeature::OnDevice));
            println!("  HOTP-on-touch support:  {}", cap(OtpFeature::ButtonHotp));
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

/// What to hand the card for a signature: RSA slots (algorithm id `0x01`)
/// take a PKCS#1 DigestInfo; ECDSA/EdDSA slots (`0x12`/`0x13`/`0x16`) take the
/// bare digest (the card signs those bytes directly — GnuPG does the same).
/// Framing is keyed off the algorithm-id byte alone; attributes this crate
/// can't identify (including an empty object) are an error, not a guess.
fn openpgp_sign_input(
    slot_label: &str,
    slot_attrs: &[u8],
    hash: SignHash,
    data: &[u8],
) -> Result<Vec<u8>, String> {
    match slot_attrs.first() {
        Some(0x01) => Ok(hash.digest_info(data)),
        Some(0x12 | 0x13 | 0x16) => {
            let is_ecc = matches!(
                keyroost_openpgp::parse_algorithm_attributes(slot_attrs),
                Ok(keyroost_openpgp::AlgorithmAttributes::Ecc { .. })
            );
            if is_ecc && matches!(hash, SignHash::Sha1) {
                return Err(
                    "SHA-1 cannot be used with an ECC signing key (OpenPGP requires a \
                     256-bit or wider hash for Ed25519/ECDSA); use --hash sha256"
                        .to_string(),
                );
            }
            Ok(hash.digest(data))
        }
        _ => Err(format!(
            "cannot tell the {slot_label} slot's algorithm from the card's attributes ({}); \
             refusing to guess how to frame the input",
            hex_encode(slot_attrs)
        )),
    }
}

/// Print a public key read from (or freshly generated into) an OpenPGP slot:
/// RSA prints modulus and exponent, ECC the public point, both in hex.
fn print_openpgp_public_key(slot_label: &str, attrs: &[u8], key: &keyroost_openpgp::PublicKey) {
    println!(
        "{} key ({}):",
        slot_label,
        keyroost_openpgp::describe_algorithm_attributes(attrs)
    );
    match key {
        keyroost_openpgp::PublicKey::Rsa { modulus, exponent } => {
            println!("  modulus:  {}", hex_encode(modulus));
            println!("  exponent: {}", hex_encode(exponent));
        }
        keyroost_openpgp::PublicKey::Ecc { point } => println!("  point:    {}", hex_encode(point)),
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
                    sig_algo: status.algorithm_label(keyroost_openpgp::KeyCrt::Sign),
                    dec_algo: status.algorithm_label(keyroost_openpgp::KeyCrt::Decrypt),
                    aut_algo: status.algorithm_label(keyroost_openpgp::KeyCrt::Auth),
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
                status.algorithm_label(keyroost_openpgp::KeyCrt::Sign),
                status.algorithm_label(keyroost_openpgp::KeyCrt::Decrypt),
                status.algorithm_label(keyroost_openpgp::KeyCrt::Auth),
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
            let attrs = session.algorithm_attributes(slot.to_crt())?;
            let key = session.read_public_key(slot.to_crt())?;
            print_openpgp_public_key(slot.label(), &attrs, &key);
        }
        OpenpgpCmd::Algorithms { reader } => {
            let mut session = open_openpgp(reader.as_deref(), debug)?;
            match session.supported_algorithms()? {
                None => println!(
                    "This card does not publish an algorithm list (pre-3.4 OpenPGP card). \
                     Any --algorithm may be tried; the card rejects what it cannot do."
                ),
                Some(info) => {
                    for (name, crt) in [
                        ("sign", keyroost_openpgp::KeyCrt::Sign),
                        ("decrypt", keyroost_openpgp::KeyCrt::Decrypt),
                        ("auth", keyroost_openpgp::KeyCrt::Auth),
                    ] {
                        let labels: Vec<String> = info
                            .raw(crt)
                            .iter()
                            .map(|a| keyroost_openpgp::describe_algorithm_attributes(a))
                            .collect();
                        println!("{:<8} {}", format!("{name}:"), labels.join(", "));
                    }
                }
            }
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
            algorithm,
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
            if let Some(a) = algorithm {
                a.to_alg().attributes(slot.to_crt())?;
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
            let key = session.generate_key(slot.to_crt(), algorithm.map(|a| a.to_alg()))?;
            let attrs = session.algorithm_attributes(slot.to_crt())?;
            print_openpgp_public_key(&format!("Generated {}", slot.label()), &attrs, &key);
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
            let pin = read_secret("signing PIN (PW1)", pin_env.as_deref(), *pin_stdin)?;
            let mut session = open_openpgp(reader.as_deref(), debug)?;
            session.verify_pin(keyroost_openpgp::PW1_SIGN, pin.as_bytes())?;
            // RSA slots want a PKCS#1 v1.5 DigestInfo (the card EMSA-pads and
            // RSA-signs it); ECDSA/EdDSA slots want the bare digest.
            let attrs = session.algorithm_attributes(keyroost_openpgp::KeyCrt::Sign)?;
            let input = openpgp_sign_input("signature", &attrs, *hash, &data)?;
            eprintln!("Signing ({}) — touch the key if it blinks…", hash.label());
            let sig = session.sign(&input)?;
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
            let attrs = session.algorithm_attributes(keyroost_openpgp::KeyCrt::Decrypt)?;
            // Framing is keyed off the algorithm-id byte alone: 0x12 (ECDH)
            // derives a shared secret, 0x01 (RSA) decrypts. Anything else
            // (including empty attributes) is refused rather than guessed.
            let (plain, noun) = match attrs.first() {
                Some(0x12) => {
                    eprintln!("Deriving shared secret — touch the key if it blinks…");
                    (session.decrypt_ecdh(&cryptogram)?, "shared-secret")
                }
                Some(0x01) => {
                    eprintln!("Decrypting — touch the key if it blinks…");
                    (session.decrypt(&cryptogram)?, "plaintext")
                }
                _ => {
                    return Err(format!(
                        "cannot tell the decryption slot's algorithm from the card's \
                         attributes ({}); refusing to guess how to frame the input",
                        hex_encode(&attrs)
                    )
                    .into());
                }
            };
            match out {
                Some(path) => {
                    write_private_file(path, &plain)
                        .map_err(|e| format!("cannot write {}: {}", path.display(), e))?;
                    eprintln!("Wrote {} {} bytes to {}", plain.len(), noun, path.display());
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
            let pin = read_secret("user PIN (PW1)", pin_env.as_deref(), *pin_stdin)?;
            let mut session = open_openpgp(reader.as_deref(), debug)?;
            // INTERNAL AUTHENTICATE authorizes under PW1 in the "other" context
            // (ref 0x82) — the same context as decipher, not the signing context.
            session.verify_pin(keyroost_openpgp::PW1_OTHER, pin.as_bytes())?;
            // RSA slots want a PKCS#1 v1.5 DigestInfo; ECDSA/EdDSA slots want
            // the bare digest.
            let attrs = session.algorithm_attributes(keyroost_openpgp::KeyCrt::Auth)?;
            let input = openpgp_sign_input("authentication", &attrs, *hash, &data)?;
            eprintln!(
                "Authenticating ({}) — touch the key if it blinks…",
                hash.label()
            );
            let sig = session.internal_authenticate(&input)?;
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
                    chuid: status.chuid.as_ref().map(|c| json_out::PivChuidJson {
                        fasc_n: c.fasc_n_display(),
                        guid: c.guid_display(),
                        expiration: c.expiration_display(),
                        signature: c.signature_display(),
                        lrc: c.lrc_display(),
                    }),
                    slots: status
                        .slots
                        .iter()
                        .map(|s| json_out::PivSlotJson {
                            slot: s.slot.label(),
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
            match &status.chuid {
                Some(c) => {
                    // Signature/LRC are empty in every CHUID this crate
                    // itself writes — "empty" reads clearer than a blank
                    // value after the label.
                    let or_empty = |s: String| if s.is_empty() { "empty".to_string() } else { s };
                    println!("CHUID:");
                    println!("  FASC-N:      {}", c.fasc_n_display());
                    println!("  GUID:        {}", c.guid_display());
                    println!("  Expiration:  {}", c.expiration_display());
                    println!("  Signature:   {}", or_empty(c.signature_display()));
                    println!("  LRC:         {}", or_empty(c.lrc_display()));
                }
                None => println!("CHUID:       (unavailable)"),
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
            save_pubkey,
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
            let der = match keyroost_piv::spki::subject_public_key_info(&pubkey, alg) {
                Ok(der) => der,
                Err(e) => {
                    return Err(
                        format!("key generated, but encoding its public key failed: {}", e).into(),
                    )
                }
            };
            let pem = keyroost_piv::spki::to_pem(&der);
            if let Some(path) = save_pubkey {
                std::fs::write(path, pem.as_bytes())
                    .map_err(|e| format!("write {}: {}", path.display(), e))?;
                eprintln!(
                    "Wrote key material for {} to {} — pass it to request-cert/self-sign's \
                     --load-pubkey if you sign this key from a separate command.",
                    slot.to_slot().label(),
                    path.display()
                );
            }
            print!("{}", pem);
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
            load_pubkey,
        } => {
            let pin = read_secret("PIN", pin_env.as_deref(), *pin_stdin)?;
            let mut s = open_piv(reader.as_deref(), debug)?;
            if let Some(path) = load_pubkey {
                let (alg, key) = load_pubkey_material(path)?;
                s.remember_pubkey(slot.to_slot(), alg, key);
            }
            eprintln!("Signing the request on the card (touch if it blinks)\u{2026}");
            let pem = s.generate_csr(slot.to_slot(), subject, pin.as_bytes())?;
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
            load_pubkey,
        } => {
            if *days == 0 {
                return Err("validity must be at least 1 day".into());
            }
            check_valid_days(*days)?;
            let mgmt = read_mgmt_key("management key", mgmt_key_env.as_deref(), *mgmt_key_stdin)?;
            let pin = read_secret("PIN", pin_env.as_deref(), *pin_stdin)?;
            // Management-key auth covers the certificate import; the PIN
            // covers the signature itself.
            let mut s = open_piv_authed(reader.as_deref(), debug, &mgmt)?;
            if let Some(path) = load_pubkey {
                let (alg, key) = load_pubkey_material(path)?;
                s.remember_pubkey(slot.to_slot(), alg, key);
            }
            eprintln!("Signing the certificate on the card (touch if it blinks)\u{2026}");
            let now = unix_now() as i64;
            let der = s.self_signed_certificate(
                slot.to_slot(),
                subject,
                now,
                now + i64::from(*days) * 86_400,
                pin.as_bytes(),
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

        PivCmd::NewChuid {
            reader,
            mgmt_key_env,
            mgmt_key_stdin,
            days,
            guid,
        } => {
            check_valid_days(*days)?;
            let guid = match guid {
                Some(hex) => keyroost_piv::parse_guid_hex(hex).ok_or(
                    "--guid must be 16 bytes of hex, dashes optional \
                     (e.g. aabbccdd-eeff-1122-3344-556677889900)",
                )?,
                None => keyroost_transport::random_chuid_guid()?,
            };
            let expiration = keyroost_piv::chuid_expiration_in_days(u64::from(unix_now()), *days);
            let mgmt = read_mgmt_key("management key", mgmt_key_env.as_deref(), *mgmt_key_stdin)?;
            let mut s = open_piv_authed(reader.as_deref(), debug, &mgmt)?;
            s.new_chuid(&guid, &expiration)?;
            println!("Wrote a new CHUID (GUID {}).", hex_encode(&guid));
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

        PivCmd::MoveKey {
            from,
            to,
            reader,
            mgmt_key_env,
            mgmt_key_stdin,
        } => {
            let mgmt = read_mgmt_key("management key", mgmt_key_env.as_deref(), *mgmt_key_stdin)?;
            let mut s = open_piv_authed(reader.as_deref(), debug, &mgmt)?;
            s.move_key(from.to_slot(), to.to_slot())?;
            println!(
                "moved the private key {} \u{2192} {}; the certificate remains in {}",
                from.to_slot().label(),
                to.to_slot().label(),
                from.to_slot().label()
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
    eprintln!("\u{2192} OpenPGP on {}", sanitize_terminal(&name));
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
    eprintln!("\u{2192} PIV on {}", sanitize_terminal(&name));
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

/// Write `data` to `path` with owner-only permissions (0600) on Unix, failing
/// closed against local path attacks (KEY-014). A local attacker who pre-plants
/// a symlink or a file they own at a predictable secret-output path must not be
/// able to capture the plaintext or have keyroost clobber an arbitrary file.
///
/// Strategy (Unix): reject a pre-existing symlink or non-regular / foreign-owned
/// destination outright, then write the secret only into a fresh `create_new`
/// temp file we exclusively own (0600 enforced as fatal) and atomically rename
/// it over the destination. Because bytes never touch the caller-supplied path
/// directly, no write can be redirected through an attacker's link.
#[cfg(unix)]
fn write_private_file(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind, Write};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let fname = path
        .file_name()
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "output path has no file name"))?;

    // 1) Create the temp file first. create_new = O_CREAT|O_EXCL, which refuses
    //    to follow a symlink at the final component and fails if the path already
    //    exists — so this file is unambiguously fresh and owned by our euid.
    let tmp = parent.join(format!(
        ".{}.keyroost-tmp-{}",
        fname.to_string_lossy(),
        std::process::id()
    ));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true).mode(0o600);
    let mut f = opts.open(&tmp)?;
    // Our euid, established from a file we just created (owned by us by definition).
    let our_uid = f.metadata()?.uid();

    // 2) Vet the real destination via lstat (no symlink follow). Fail closed on a
    //    symlink, a non-regular file, or a file owned by someone else.
    let vet = |e: Error| {
        let _ = std::fs::remove_file(&tmp);
        e
    };
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            let ft = meta.file_type();
            if ft.is_symlink() {
                return Err(vet(Error::new(
                    ErrorKind::AlreadyExists,
                    "refusing to write secret output through a symlink",
                )));
            }
            if !ft.is_file() {
                return Err(vet(Error::new(
                    ErrorKind::AlreadyExists,
                    "refusing to write secret output to a non-regular file",
                )));
            }
            if meta.uid() != our_uid {
                return Err(vet(Error::new(
                    ErrorKind::PermissionDenied,
                    "refusing to overwrite a secret-output file owned by another user",
                )));
            }
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {} // fresh output is fine
        Err(e) => return Err(vet(e)),
    }

    // 3) Write the secret into the temp, enforcing 0600 as FATAL before any
    //    bytes: never fall through to writing under looser permissions.
    if let Err(e) = f.set_permissions(std::fs::Permissions::from_mode(0o600)) {
        return Err(vet(e));
    }
    if let Err(e) = f.write_all(data).and_then(|_| f.sync_all()) {
        return Err(vet(e));
    }
    drop(f);

    // 4) Atomically replace the destination. rename() operates on the link/name
    //    itself, so even a symlink swapped in after step 2 is replaced rather
    //    than written through.
    if let Err(e) = std::fs::rename(&tmp, path) {
        return Err(vet(e));
    }
    Ok(())
}

/// Non-Unix fallback: create/overwrite with owner-intent semantics. Windows ACL
/// hardening is out of scope for this helper.
#[cfg(not(unix))]
fn write_private_file(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
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

/// Accept a `SubjectPublicKeyInfo` as PEM (`-----BEGIN PUBLIC KEY-----`, what
/// `generate-key --save-pubkey` writes) or raw DER, returning DER bytes.
/// Mirrors [`cert_to_der`] for the same reason: a file a user can inspect or
/// hand to other tools shouldn't be limited to one encoding.
fn spki_to_der(bytes: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let text = std::str::from_utf8(bytes).unwrap_or("");
    if let Some(start) = text.find("-----BEGIN PUBLIC KEY-----") {
        let after = &text[start + "-----BEGIN PUBLIC KEY-----".len()..];
        let end = after
            .find("-----END PUBLIC KEY-----")
            .ok_or("PEM public key has no END marker")?;
        let b64: String = after[..end].split_whitespace().collect();
        return Ok(keyroost_proto::codec::base64_decode(&b64)?);
    }
    if bytes.first() != Some(&0x30) {
        return Err("key material file is neither PEM nor DER (no 0x30 SEQUENCE)".into());
    }
    Ok(bytes.to_vec())
}

/// Load a `--load-pubkey` file (as written by `generate-key --save-pubkey`) and
/// decode it back to `(algorithm, public key)` for
/// [`keyroost_transport::PivSession::remember_pubkey`].
fn load_pubkey_material(
    path: &std::path::Path,
) -> Result<(keyroost_piv::KeyAlg, keyroost_piv::PublicKey), Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    let der = spki_to_der(&bytes)?;
    let (alg, key) =
        keyroost_piv::x509_parse::parse_subject_public_key_info(&der).map_err(|e| {
            format!(
                "{}: not a valid SubjectPublicKeyInfo: {}",
                path.display(),
                e
            )
        })?;
    Ok((alg, key))
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
        sanitize_terminal(name),
        sanitize_terminal(&serial),
        sanitize_terminal(&dev.product_name)
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
        println!(
            "  {:<20} serial={} [{}]",
            sanitize_terminal(&k.name),
            sanitize_terminal(&k.serial),
            status
        );
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
        FidoCmd::Reset { yes, path, reader } => {
            if !*yes {
                return Err(format!(
                    "refusing to reset FIDO key without --yes (this wipes credentials){}",
                    fido_target_hint(path.as_deref())
                )
                .into());
            }
            match reader {
                Some(substr) => run_fido_reset_reader(substr)?,
                None => run_fido_reset(path.as_deref())?,
            }
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
        FidoCmd::SshCert { cmd } => run_fido_ssh_cert(cmd),
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
        LargeBlobCmd::Export {
            index,
            output,
            as_cert,
            path,
        } => run_fido_large_blob_export(path.as_deref(), *index, output, *as_cert),
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

/// Dispatch for `fido ssh-cert` — list SSH credentials or extract a cert.
fn run_fido_ssh_cert(cmd: &SshCertCmd) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        SshCertCmd::List {
            pin_env,
            pin_stdin,
            path,
        } => {
            let pin = read_secret("PIN", pin_env.as_deref(), *pin_stdin)?;
            run_fido_ssh_cert_list(path.as_deref(), &pin)
        }
        SshCertCmd::Extract {
            credential,
            out,
            force,
            pin_env,
            pin_stdin,
            path,
        } => {
            let pin = read_secret("PIN", pin_env.as_deref(), *pin_stdin)?;
            run_fido_ssh_cert_extract(
                path.as_deref(),
                &pin,
                credential.as_deref(),
                out.as_deref(),
                *force,
            )
        }
    }
}

/// The (rp_id, credential) pairs for every resident `ssh:*` credential, paired
/// with the key's largeBlob array (the certificate bytes live in the array,
/// keyed by each credential's per-credential largeBlobKey).
type SshCredEnumeration = (
    Vec<(String, keyroost_ctap::cred_mgmt::Credential)>,
    keyroost_ctap::large_blobs::LargeBlobArray,
);

/// Open a FIDO key, read its largeBlob array, and enumerate every resident
/// credential under an `ssh:*` relying party. Both halves are needed to tell
/// whether a credential actually has a decodable certificate stored.
fn enumerate_ssh_credentials(
    path: Option<&std::path::Path>,
    pin: &str,
) -> Result<SshCredEnumeration, Box<dyn std::error::Error>> {
    let path = resolve_fido_path(path)?;
    let (mut dev, init) = keyroost_ctap::CtapHidDevice::open(&path)?;
    if !init.supports_cbor() {
        return Err("device is U2F-only; CTAP2 credential management not supported".into());
    }
    let info = keyroost_ctap::get_info(&mut dev)?;
    if info.option("largeBlobs") != Some(true) {
        return Err("this key does not support the FIDO2 large-blob store".into());
    }
    // Read the world-readable largeBlob array BEFORE we borrow the device for
    // the credential-management session (the manager holds `&mut dev` for its
    // whole lifetime, so both device users can't be live at once).
    let array = keyroost_ctap::large_blobs::read(&mut dev, &info)?;

    let token = keyroost_ctap::client_pin::get_pin_uv_auth_token(
        &mut dev,
        pin,
        &info,
        keyroost_ctap::client_pin::permissions::CREDENTIAL_MANAGEMENT,
    )?;
    let mut mgr = keyroost_ctap::cred_mgmt::CredentialManager::new(&mut dev, token, &info)?;

    let mut creds = Vec::new();
    for rp in mgr.list_relying_parties()? {
        if !rp.id.starts_with("ssh:") {
            continue;
        }
        // Every other CTAP API hands back the RP id-hash; a rare quirky entry
        // reports None, in which case we recompute it from the id ourselves.
        let hash = rp
            .rp_id_hash
            .unwrap_or_else(|| keyroost_proto::sha256::sha256(rp.id.as_bytes()));
        for c in mgr.list_credentials(&hash)? {
            creds.push((rp.id.clone(), c));
        }
    }
    Ok((creds, array))
}

fn run_fido_ssh_cert_list(
    path: Option<&std::path::Path>,
    pin: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (creds, array) = enumerate_ssh_credentials(path, pin)?;
    if creds.is_empty() {
        println!("No resident SSH credentials (ssh:* relying parties) on this key.");
        return Ok(());
    }
    for (rp_id, c) in &creds {
        let has_cert = c
            .large_blob_key
            .as_ref()
            .and_then(|k| keyroost_ctap::large_blobs::extract_cert_from_entries(k, &array.entries))
            .is_some();
        println!(
            "{}  {}",
            sanitize_terminal(rp_id),
            if has_cert {
                "certificate stored"
            } else {
                "no certificate"
            }
        );
    }
    Ok(())
}

fn run_fido_ssh_cert_extract(
    path: Option<&std::path::Path>,
    pin: &str,
    credential: Option<&str>,
    out: Option<&std::path::Path>,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (creds, array) = enumerate_ssh_credentials(path, pin)?;
    if creds.is_empty() {
        return Err("no resident SSH credentials (ssh:* relying parties) on this key".into());
    }

    // Select the SSH credential to extract — fail closed if ambiguous.
    let choices = || {
        creds
            .iter()
            .map(|(id, _)| sanitize_terminal(id))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let (rp_id, cred) = match credential {
        Some(want) => {
            let matches: Vec<&(String, keyroost_ctap::cred_mgmt::Credential)> =
                creds.iter().filter(|(id, _)| id == want).collect();
            match matches.len() {
                0 => {
                    return Err(format!(
                        "no SSH credential with RP ID {}; available: {}",
                        sanitize_terminal(want),
                        choices()
                    )
                    .into());
                }
                1 => matches[0],
                _ => {
                    return Err(format!(
                        "multiple credentials share RP id '{}'; cannot disambiguate",
                        sanitize_terminal(want)
                    )
                    .into());
                }
            }
        }
        None => {
            if creds.len() != 1 {
                return Err(format!(
                    "several SSH credentials present; pass --credential <rp-id> (one of: {})",
                    choices()
                )
                .into());
            }
            &creds[0]
        }
    };

    let key = cred.large_blob_key.as_ref().ok_or_else(|| {
        format!(
            "credential '{}' has no largeBlob key — no certificate is stored for it",
            sanitize_terminal(rp_id)
        )
    })?;
    let wire = keyroost_ctap::large_blobs::extract_cert_from_entries(key, &array.entries)
        .ok_or_else(|| {
            format!(
                "no SSH certificate found in credential '{}'s largeBlob (no matching entry, or the stored blob is not a certificate)",
                sanitize_terminal(rp_id)
            )
        })?;
    let cert_pub = keyroost_ctap::ssh_cert::to_cert_pub(&wire)
        .ok_or("stored blob is not a valid OpenSSH certificate")?;

    // Resolve the output path (default: <sanitised rp-id>-cert.pub). The RP id
    // is device-derived and must be treated as hostile: use the path-safe
    // filename sanitizer here, not sanitize_terminal (which only neutralizes
    // control/bidi/zero-width chars for display, not `/`, `\`, or `..`).
    let out_path = match out {
        Some(p) => p.to_path_buf(),
        None => std::path::PathBuf::from(keyroost_ctap::ssh_cert::default_cert_filename(rp_id)),
    };
    if out_path.exists() && !force {
        return Err(format!(
            "{} already exists; pass --force to overwrite",
            out_path.display()
        )
        .into());
    }
    std::fs::write(&out_path, cert_pub.as_bytes())?;
    println!("Wrote SSH certificate to {}", out_path.display());
    Ok(())
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
    if info.option("largeBlobs") != Some(true) {
        return Err("this key does not support the FIDO2 large-blob store".into());
    }
    let array = keyroost_ctap::large_blobs::read(&mut dev, &info)?;
    Ok((dev, info, array))
}

/// Classification results shaped for both the human and JSON views.
fn large_blob_kind(
    entry: &keyroost_ctap::large_blobs::LargeBlobEntry,
) -> (
    &'static str,
    Option<json_out::FidoLargeBlobSshCertJson>,
    keyroost_ctap::large_blobs::EntryKind,
) {
    use keyroost_ctap::large_blobs::EntryKind;
    let kind = entry.classify();
    match &kind {
        EntryKind::Note(_) => ("note", None, kind),
        EntryKind::Opaque => ("opaque", None, kind),
        EntryKind::SshCert { info, .. } => {
            let cert = json_out::FidoLargeBlobSshCertJson {
                key_type: info.key_type.clone(),
                serial: info.serial,
                cert_type: if info.cert_type == keyroost_ctap::ssh_cert::CERT_TYPE_USER {
                    "user"
                } else {
                    "host"
                },
                key_id: info.key_id.clone(),
                principals: info.principals.clone(),
                valid_after: info.valid_after,
                valid_before: info.valid_before,
                validity: keyroost_ctap::ssh_cert::format_validity(
                    info.valid_after,
                    info.valid_before,
                ),
                critical_options: info
                    .critical_options
                    .iter()
                    .map(|(n, v)| {
                        if v.is_empty() {
                            n.clone()
                        } else {
                            format!("{n}={v}")
                        }
                    })
                    .collect(),
                extensions: info.extensions.clone(),
            };
            ("ssh-cert", Some(cert), kind)
        }
    }
}

/// Shape a parsed large-blob array into the JSON `list` view.
fn large_blob_list_json(
    array: &keyroost_ctap::large_blobs::LargeBlobArray,
    info: &keyroost_ctap::AuthenticatorInfo,
) -> json_out::FidoLargeBlobListJson {
    let entries = array
        .entries
        .iter()
        .enumerate()
        .map(|(index, e)| {
            let (kind, ssh_cert, _) = large_blob_kind(e);
            json_out::FidoLargeBlobEntryJson {
                index,
                size: e.orig_size,
                is_note: e.is_kr_note(),
                text: e.as_text(),
                kind,
                ssh_cert,
            }
        })
        .collect();
    let cap = array.capacity(info);
    json_out::FidoLargeBlobListJson {
        entries,
        capacity: json_out::FidoLargeBlobCapacityJson {
            max_bytes: cap.max_bytes,
            used_bytes: cap.used_bytes,
            free_bytes: cap.free_bytes,
        },
    }
}

fn run_fido_large_blob_list(
    path: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (_dev, info, array) = open_and_read_large_blobs(path)?;
    if json_output() {
        emit_json(&large_blob_list_json(&array, &info))?;
        return Ok(());
    }
    if array.entries.is_empty() {
        println!("(large-blob array is empty)");
        let cap = array.capacity(&info);
        println!();
        println!(
            "Capacity: {} of {} bytes used, {} free",
            cap.used_bytes, cap.max_bytes, cap.free_bytes
        );
        return Ok(());
    }
    for (i, e) in array.entries.iter().enumerate() {
        use keyroost_ctap::large_blobs::EntryKind;
        match e.classify() {
            EntryKind::Note(text) => {
                println!(
                    "[{}] {} bytes  note      {}",
                    i,
                    e.orig_size,
                    preview_note(&text)
                )
            }
            EntryKind::SshCert { info, .. } => println!(
                "[{}] {} bytes  ssh-cert  {} ({})",
                i,
                e.orig_size,
                sanitize_terminal(&info.key_id),
                sanitize_terminal(&info.principals.join(","))
            ),
            EntryKind::Opaque => println!(
                "[{}] {} bytes  opaque    {}",
                i,
                e.orig_size,
                preview_opaque(&e.ciphertext)
            ),
        }
    }
    let cap = array.capacity(&info);
    println!();
    println!(
        "Capacity: {} of {} bytes used, {} free",
        cap.used_bytes, cap.max_bytes, cap.free_bytes
    );
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
    let (kind, ssh_cert, classified) = large_blob_kind(entry);
    if json_output() {
        emit_json(&json_out::FidoLargeBlobGetJson {
            index,
            size: entry.orig_size,
            is_note: entry.is_kr_note(),
            text: entry.as_text(),
            kind,
            ssh_cert,
            hex: hex_encode(&entry.ciphertext),
        })?;
        return Ok(());
    }
    use keyroost_ctap::large_blobs::EntryKind;
    match classified {
        EntryKind::Note(text) => {
            println!("Entry {}: keyroost note, {} bytes", index, entry.orig_size);
            // A note is arbitrary text written by any app with the PIN; keep its
            // line structure but strip escapes so it can't hijack the terminal.
            println!("{}", sanitize_multiline(&text));
        }
        EntryKind::SshCert { info, .. } => {
            println!(
                "Entry {}: OpenSSH certificate, {} bytes",
                index, entry.orig_size
            );
            println!(
                "  Type:        {} ({})",
                sanitize_terminal(&info.key_type),
                if info.cert_type == keyroost_ctap::ssh_cert::CERT_TYPE_USER {
                    "user"
                } else {
                    "host"
                }
            );
            println!("  Key ID:      {}", sanitize_terminal(&info.key_id));
            println!("  Serial:      {}", info.serial);
            println!(
                "  Principals:  {}",
                if info.principals.is_empty() {
                    "(any)".to_string()
                } else {
                    sanitize_terminal(&info.principals.join(", "))
                }
            );
            println!(
                "  Valid:       {}",
                keyroost_ctap::ssh_cert::format_validity(info.valid_after, info.valid_before)
            );
            for (n, v) in &info.critical_options {
                let n = sanitize_terminal(n);
                if v.is_empty() {
                    println!("  Critical:    {n}");
                } else {
                    let v = sanitize_terminal(v);
                    println!("  Critical:    {n}={v}");
                }
            }
            for ext in &info.extensions {
                println!("  Extension:   {}", sanitize_terminal(ext));
            }
            println!("\nExport with: keyroostctl fido large-blob export {index} <FILE> --as-cert");
        }
        EntryKind::Opaque => {
            println!(
                "Entry {}: opaque (RP-encrypted), {} bytes",
                index, entry.orig_size
            );
            println!();
            print!("{}", hex_ascii_dump(&entry.ciphertext));
        }
    }
    Ok(())
}

fn run_fido_large_blob_export(
    path: Option<&std::path::Path>,
    index: usize,
    output: &std::path::Path,
    as_cert: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use keyroost_ctap::large_blobs::EntryKind;
    let (_dev, _info, array) = open_and_read_large_blobs(path)?;
    let entry = array
        .entries
        .get(index)
        .ok_or_else(|| large_blob_bad_index(index, array.entries.len()))?;
    let bytes: Vec<u8> = if as_cert {
        match entry.classify() {
            EntryKind::SshCert { wire, .. } => keyroost_ctap::ssh_cert::to_cert_pub(&wire)
                .ok_or("could not re-encode certificate")?
                .into_bytes(),
            _ => {
                return Err(format!(
                "entry {index} is not a recognized SSH certificate; drop --as-cert to export raw bytes"
            )
                .into())
            }
        }
    } else {
        entry.ciphertext.clone()
    };
    std::fs::write(output, &bytes)?;
    println!("Wrote {} bytes to {}", bytes.len(), output.display());
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

/// Flatten control characters out of any attacker-supplied string before it
/// reaches the terminal, so a hostile value cannot inject ANSI/terminal escape
/// sequences. Applies to every device- or file-derived string printed by the
/// CLI: certificate fields, USB descriptor strings (vendor/model/serial),
/// PC/SC reader names, OATH/FIDO credential names, slot titles, and friendly
/// names. Control, zero-width, and bidi format chars (see
/// [`keyroost_keyring::is_spoofing_char`]) become spaces; character count is
/// preserved so column alignment is unaffected.
pub(crate) fn sanitize_terminal(s: &str) -> String {
    s.chars()
        .map(|c| {
            if keyroost_keyring::is_spoofing_char(c) {
                ' '
            } else {
                c
            }
        })
        .collect()
}

/// Like [`sanitize_terminal`] but preserves newlines and tabs — for multi-line
/// text (e.g. a large-blob note) where line structure is meaningful. Every
/// other control character (notably ESC `0x1b`) and bidi/zero-width format
/// char still becomes a space, so ANSI escapes and reordering can't survive.
pub(crate) fn sanitize_multiline(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c == '\n' || c == '\t' {
                c
            } else if keyroost_keyring::is_spoofing_char(c) {
                ' '
            } else {
                c
            }
        })
        .collect()
}

/// Human label for the public-block algorithm byte. Same coding as the
/// config TLV's hmac_algo (1=SHA1, 2=SHA256); anything else prints raw.
fn molto_algo_label(algo: u8) -> String {
    match algo {
        0x01 => "SHA1".into(),
        0x02 => "SHA256".into(),
        other => format!("0x{other:02X}"),
    }
}

/// A short, single-line preview of a note's text for the `list` view. Uses the
/// shared terminal sanitizer so a future policy change reaches this site too.
fn preview_note(text: &str) -> String {
    const MAX: usize = 48;
    let one_line = sanitize_terminal(text);
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
    // versions/extensions/option-keys come from the device's getInfo CBOR;
    // flatten any control bytes before they reach the terminal.
    println!(
        "Versions:  {}",
        sanitize_terminal(&info.versions.join(", "))
    );
    if !info.extensions.is_empty() {
        println!(
            "Extensions: {}",
            sanitize_terminal(&info.extensions.join(", "))
        );
    }
    println!("AAGUID:    {}", format_aaguid(&info.aaguid));
    if !info.options.is_empty() {
        let opts: Vec<String> = info
            .options
            .iter()
            .map(|(k, v)| format!("{}={}", sanitize_terminal(k), v))
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
        println!(
            "Transports: {}",
            sanitize_terminal(&info.transports.join(", "))
        );
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
    fido_reset_at(&resolve_fido_path(path)?)
}

/// Reset the FIDO2 applet of an already-resolved device. Split out so callers
/// that have *proved* which physical key they hold (the factory reset, after
/// its replug prompt) reset exactly that one, instead of re-resolving and
/// possibly landing on a different key.
fn fido_reset_at(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let (mut dev, _init) = keyroost_ctap::CtapHidDevice::open(path)?;
    println!("Resetting {} — touch the key now…", path.display());
    keyroost_ctap::reset(&mut dev)?;
    println!("Reset complete. All credentials wiped, PIN cleared.");
    Ok(())
}

/// Reset the FIDO2 applet of a card in the PC/SC reader matching `substr`.
///
/// A card has no replug and no touch surface, so the "reset within ~10 s of
/// power-up" window is opened another way: PC/SC power-cycles the card in the
/// reader and the reset is sent the moment the applet answers (issue #84 —
/// the replug ceremony can never complete for a card).
fn run_fido_reset_reader(substr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let readers = keyroost_transport::CtapPcscDevice::list_fido_readers()?;
    let name = resolve_reader(readers, Some(substr), "FIDO")?;
    eprintln!("\u{2192} FIDO on {}", sanitize_terminal(&name));
    println!("Power-cycling the card and sending the reset\u{2026}");
    let mut dev = keyroost_transport::CtapPcscDevice::open_after_power_cycle(&name)?;
    keyroost_ctap::reset(&mut dev).map_err(|e| -> Box<dyn std::error::Error> {
        let s = e.to_string();
        if s.contains("NOT_ALLOWED") || s.contains("0x30") {
            "the card refused the reset even straight after a power cycle. Some cards \
             only accept a FIDO reset over NFC (contactless) rather than a contact \
             reader — try a contactless reader or the vendor's mobile app."
                .into()
        } else {
            Box::new(e)
        }
    })?;
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
                let creds = match rp.rp_id_hash {
                    Some(hash) => mgr.list_credentials(&hash)?,
                    None => Vec::new(),
                };
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
            let creds = match rp.rp_id_hash {
                Some(hash) => mgr.list_credentials(&hash)?,
                None => Vec::new(),
            };
            // rp.id and rp.name are attacker-controlled (any app with the PIN
            // can register a credential); flatten control chars. The user.name /
            // display_name / user.id below print via {:?}, which already
            // escape-debugs control bytes.
            let name_suffix = match &rp.name {
                Some(n) if !n.is_empty() => format!("  ({})", sanitize_terminal(n)),
                _ => String::new(),
            };
            let count_suffix = if rp.rp_id_hash.is_none() {
                "  (credentials unavailable: device returned a malformed rpIdHash)".to_owned()
            } else if creds.is_empty() {
                "  (no credentials)".to_owned()
            } else {
                format!("  [{} credential(s)]", creds.len())
            };
            println!(
                "{}{}{}",
                sanitize_terminal(&rp.id),
                name_suffix,
                count_suffix
            );
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
            // The friendly name is stored on the device; strip escapes.
            let name = e
                .friendly_name
                .as_deref()
                .map(sanitize_terminal)
                .unwrap_or_else(|| "(unnamed)".to_string());
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
    // The serial is `from_utf8_lossy` over device bytes; flatten any control
    // characters before they reach the terminal (a hostile token could embed
    // escape sequences). Shared by every command that prints device info.
    println!("device serial: {}", sanitize_terminal(&info.serial));
    println!("device UTC:    {} (epoch)", info.utc_time);
    // TOTP tolerates small drift (one 30s step either way at most verifiers);
    // beyond that, codes get rejected in ways users misdiagnose as a bad
    // seed. Surface it here where it's cheap to see.
    let drift = i64::from(info.utc_time) - i64::from(unix_now());
    if drift.abs() > 30 {
        eprintln!(
            "warning: device clock is {} seconds {} the host clock — codes may be \
             rejected. Run `keyroostctl molto sync-time --all` to fix.",
            drift.abs(),
            if drift > 0 { "ahead of" } else { "behind" }
        );
    }
}

/// Exit quietly on a broken output pipe instead of dumping a panic + backtrace.
///
/// Rust ignores `SIGPIPE`, so writing to a closed pipe (`keyroostctl … | head`)
/// turns the next `println!` into a panic ("failed printing to stdout: Broken
/// pipe") rather than a clean exit. Resetting `SIGPIPE` to `SIG_DFL` is the
/// idiomatic fix, but it needs an `unsafe` call (forbidden workspace-wide) or
/// the nightly-only `-Zon-broken-pipe` flag — so instead we intercept that one
/// panic and exit with 141 (128 + `SIGPIPE`'s signal 13): the status a normal
/// Unix filter yields on a closed pipe, and exactly what `-Zon-broken-pipe=kill`
/// will produce once stable. So a `set -o pipefail` pipeline sees the truncation,
/// and adopting the built-in later won't silently change the exit code.
///
/// Detection is by the panic *message* (see [`is_broken_pipe_panic`]). When
/// `-Zon-broken-pipe` (or the `unix_sigpipe` attribute) reaches stable, delete
/// this whole dance and adopt the built-in — see `TODO.md`.
fn install_broken_pipe_guard() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let payload = info.payload();
        let msg = payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| payload.downcast_ref::<&str>().copied())
            .unwrap_or("");
        if is_broken_pipe_panic(msg) {
            // 141 = 128 + SIGPIPE(13): the conventional "killed by broken pipe"
            // status, matching what `-Zon-broken-pipe=kill` will emit once stable.
            std::process::exit(141);
        }
        default_hook(info);
    }));
}

/// Whether a panic message signals a broken output pipe.
///
/// Broken-pipe panics arrive in two structurally different shapes that share
/// no common prefix: std's `println!` formats the `io::Error` via `Display`
/// (`"failed printing to stdout: Broken pipe (os error 32)"`), while
/// clap_complete's generator formats it via `Debug`
/// (`"failed to write completion file: Os { code: 32, kind: BrokenPipe, … }"`).
///
/// So the match is deliberately **unanchored** — do NOT add a message-prefix
/// check, it silently misses the clap_complete source (a regression caught by
/// `tests/broken_pipe.rs`). The tokens are locale-independent where it counts:
/// `BrokenPipe` (the `Debug` kind name) covers the Debug shape and
/// `(os error 32)` (the Rust-appended EPIPE errno on Linux/macOS) covers the
/// Display shape, each surviving a translated non-C `LC_MESSAGES`; the
/// translatable `strerror` text `"Broken pipe"` is only a last-resort fallback.
/// Errno 32 is EPIPE on all Unix targets, so a code-32 `io::Error` is always a
/// broken pipe — a genuine failure like disk-full (`os error 28`) is left to
/// panic normally.
fn is_broken_pipe_panic(msg: &str) -> bool {
    msg.contains("BrokenPipe") || msg.contains("(os error 32)") || msg.contains("Broken pipe")
}

fn main() -> ExitCode {
    // A closed output pipe (`… | head`) should exit quietly, not panic.
    install_broken_pipe_guard();
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
mod otp_capability_tests {
    use super::*;

    /// A config block of `len` bytes whose capability byte (9) is `ext`.
    fn config_block(len: usize, ext: u8) -> keyroost_token2otp::DeviceInfo {
        let mut raw = vec![0u8; len];
        if len > 9 {
            raw[9] = ext;
        }
        keyroost_token2otp::DeviceInfo::parse(&raw).expect("non-empty block parses")
    }

    #[test]
    fn a_full_config_block_decides_both_features() {
        // Byte 9: bit 1 sets TOTP support; bit 6 is inverted (set = NO button HOTP).
        let both = config_block(10, 0x01);
        assert_eq!(
            otp_feature_capability(Some(&both), OtpFeature::OnDevice),
            Some(true)
        );
        assert_eq!(
            otp_feature_capability(Some(&both), OtpFeature::ButtonHotp),
            Some(true)
        );

        let neither = config_block(10, 0x20);
        assert_eq!(
            otp_feature_capability(Some(&neither), OtpFeature::OnDevice),
            Some(false)
        );
        assert_eq!(
            otp_feature_capability(Some(&neither), OtpFeature::ButtonHotp),
            Some(false)
        );

        // The two are independent: a key can have the keystroke slot and no store.
        let hotp_only = config_block(64, 0x10);
        assert_eq!(
            otp_feature_capability(Some(&hotp_only), OtpFeature::OnDevice),
            Some(false)
        );
        assert_eq!(
            otp_feature_capability(Some(&hotp_only), OtpFeature::ButtonHotp),
            Some(true)
        );
    }

    #[test]
    fn a_short_config_block_is_unknown_not_unsupported() {
        // Byte 9 is absent; the parser zero-fills it. Reading that as "no" would
        // refuse commands on keys whose firmware answers with a stub block.
        for len in 1..=9 {
            assert_eq!(
                otp_feature_capability(Some(&config_block(len, 0)), OtpFeature::OnDevice),
                None,
                "{len}"
            );
            assert_eq!(
                otp_feature_capability(Some(&config_block(len, 0)), OtpFeature::ButtonHotp),
                None,
                "{len}"
            );
        }
    }

    #[test]
    fn a_failed_config_read_never_blocks_a_command() {
        // `ensure_otp_feature` passes `None` when the read fails; that must leave
        // the command running exactly as it did before this gate existed.
        assert_eq!(otp_feature_capability(None, OtpFeature::OnDevice), None);
        assert_eq!(otp_feature_capability(None, OtpFeature::ButtonHotp), None);
    }

    #[test]
    fn the_missing_feature_messages_name_the_feature() {
        // The wording is what a user with a non-OTP key actually sees, so keep it
        // specific to the function that is absent.
        assert!(OtpFeature::OnDevice
            .missing_message()
            .contains("on-device OTP function"));
        assert!(OtpFeature::ButtonHotp
            .missing_message()
            .contains("HOTP-on-touch function"));
        for f in [OtpFeature::OnDevice, OtpFeature::ButtonHotp] {
            assert!(f
                .missing_message()
                .contains("aren't upgradable after purchase"));
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
    fn fido_ssh_cert_extract_grammar() {
        match parse(&[
            "keyroostctl",
            "fido",
            "ssh-cert",
            "extract",
            "--credential",
            "ssh:demo",
            "--out",
            "id-cert.pub",
            "--force",
            "--pin-stdin",
        ])
        .unwrap()
        .command
        {
            Some(Cmd::Fido {
                cmd:
                    FidoCmd::SshCert {
                        cmd:
                            SshCertCmd::Extract {
                                credential,
                                out,
                                force,
                                pin_stdin,
                                ..
                            },
                    },
            }) => {
                assert_eq!(credential.as_deref(), Some("ssh:demo"));
                assert_eq!(out.as_deref(), Some(std::path::Path::new("id-cert.pub")));
                assert!(force && pin_stdin);
            }
            _ => panic!("expected fido ssh-cert extract"),
        }
    }

    #[test]
    fn security_sensitive_flags_decode_to_expected_fields() {
        // Grammar-only `is_ok()` tests can't catch a field-mapping regression
        // (exactly what the --device collision was). Assert the *decoded values*
        // for the flags where a silent mis-wire is dangerous.

        // A destructive op's --yes must actually land in its confirm field —
        // and be false when omitted (so the op can't run unconfirmed).
        match parse(&["keyroostctl", "molto", "reset", "--yes"])
            .unwrap()
            .command
        {
            Some(Cmd::Molto {
                cmd: MoltoCmd::Reset { yes, .. },
                ..
            }) => assert!(yes),
            _ => panic!("expected molto reset"),
        }
        match parse(&["keyroostctl", "molto", "reset"]).unwrap().command {
            Some(Cmd::Molto {
                cmd: MoltoCmd::Reset { yes, .. },
                ..
            }) => assert!(!yes),
            _ => panic!("expected molto reset"),
        }

        // A stdin secret source must route to its own field, not somewhere else.
        match parse(&["keyroostctl", "fido", "pin-set", "--new-pin-stdin"])
            .unwrap()
            .command
        {
            Some(Cmd::Fido {
                cmd: FidoCmd::PinSet { new_pin_stdin, .. },
            }) => assert!(new_pin_stdin),
            _ => panic!("expected fido pin-set"),
        }

        // Global flags decode as themselves.
        let g = parse(&["keyroostctl", "--json", "--debug", "piv", "status"]).unwrap();
        assert!(g.json && g.debug && g.device.is_none());
    }

    #[test]
    fn oath_reset_requires_explicit_yes() {
        // Same decode guarantee as molto/fido reset: --yes must land in the
        // confirm field, and omitting it must decode to false so the handler
        // refuses to wipe.
        match parse(&["keyroostctl", "oath", "reset", "--yes"])
            .unwrap()
            .command
        {
            Some(Cmd::Oath {
                cmd: OathCmd::Reset { yes, .. },
            }) => assert!(yes),
            _ => panic!("expected oath reset"),
        }
        match parse(&["keyroostctl", "oath", "reset"]).unwrap().command {
            Some(Cmd::Oath {
                cmd: OathCmd::Reset { yes, .. },
            }) => assert!(!yes),
            _ => panic!("expected oath reset"),
        }
    }

    #[test]
    fn factory_reset_refuses_contradictory_reader_and_device() {
        // Both --reader and --device set is a contradiction on a WIPE command
        // (the banner would name one key while the card steps opened another);
        // refuse rather than silently pick one.
        assert!(reader_device_conflict(Some("Alcor 00"), Some("work-key")).is_err());
        // Either alone, or neither, is fine.
        assert!(reader_device_conflict(Some("Alcor 00"), None).is_ok());
        assert!(reader_device_conflict(None, Some("work-key")).is_ok());
        assert!(reader_device_conflict(None, None).is_ok());
    }

    #[test]
    fn factory_reset_fido_step_only_accepts_the_confirmed_key() {
        // The same key replugged: its serial is still there, so the reset goes
        // ahead on that one device.
        assert_eq!(
            reinserted_target("12345678", &["12345678"]),
            ReinsertMatch::Found(0)
        );
        // …and is found among other connected keys, not just alone.
        assert_eq!(
            reinserted_target("12345678", &["87654321", "12345678"]),
            ReinsertMatch::Found(1)
        );
        // A different key in the port at the prompt is refused — this is the
        // whole point: a FIDO reset wipes every passkey and the PIN, and the
        // product name / hidraw path of a same-model key looks identical.
        assert_eq!(
            reinserted_target("12345678", &["87654321"]),
            ReinsertMatch::NotPresent
        );
        // Nothing plugged back in yet.
        assert_eq!(
            reinserted_target("12345678", &[]),
            ReinsertMatch::NotPresent
        );
    }

    #[test]
    fn factory_reset_fido_step_fails_closed_without_an_identity() {
        // Neither side has a serial: same-model-in-the-same-port is not an
        // identity, so the serial rule must NOT match (KEY-005, as in the GUI).
        // The serial-less fallback in `reinserted_serial_less_target` is what
        // decides this case, and only when the key is the sole candidate.
        assert_eq!(reinserted_target("", &[""]), ReinsertMatch::NotPresent);
        // The expected key has no serial: nothing can ever match it.
        assert_eq!(
            reinserted_target("", &["12345678"]),
            ReinsertMatch::NotPresent
        );
        // The key that came back has none: not the confirmed key either.
        assert_eq!(
            reinserted_target("12345678", &["", ""]),
            ReinsertMatch::NotPresent
        );
        // A serial several connected keys report identifies none of them
        // (KEY-015) — refuse rather than wipe the first hit.
        assert_eq!(
            reinserted_target("12345678", &["12345678", "12345678"]),
            ReinsertMatch::Ambiguous
        );
    }

    /// Terse `Candidate` builder so the match tests read as tables. No USB ids:
    /// the cases below are about serials and the sole-candidate rule, and with
    /// the ids unknown `same_product` falls back to the model name.
    fn cand<'a>(serial: &'a str, model: &'a str, fido: bool) -> Candidate<'a> {
        Candidate {
            serial,
            model,
            ids: None,
            fido,
        }
    }

    /// `cand` with USB ids, for the cases where the ids are what decides.
    fn cand_ids<'a>(serial: &'a str, model: &'a str, ids: (u16, u16), fido: bool) -> Candidate<'a> {
        Candidate {
            serial,
            model,
            ids: Some(ids),
            fido,
        }
    }

    #[test]
    fn factory_reset_fido_step_accepts_a_lone_serial_less_key() {
        // A FIDO-only key with no USB iSerialNumber and no CCID reader resolves
        // to an empty serial. It is the only thing connected, it is the model
        // the reset was confirmed for, and it answers over FIDO: there is
        // nothing else it could be, so the reset goes ahead.
        assert_eq!(
            reinserted_match("", "Security Key", None, &[cand("", "Security Key", true)]),
            ReinsertMatch::Found(0)
        );
    }

    #[test]
    fn factory_reset_fido_step_refuses_a_serial_less_key_it_cannot_isolate() {
        // A second key in sight and the "nothing else it could be" argument is
        // gone — there is no serial left to tell them apart with.
        assert_eq!(
            reinserted_match(
                "",
                "Security Key",
                None,
                &[
                    cand("", "Security Key", true),
                    cand("12345678", "YubiKey", true)
                ]
            ),
            ReinsertMatch::Ambiguous
        );
        // Two identical serial-less keys are the case this rule exists for.
        assert_eq!(
            reinserted_match(
                "",
                "Security Key",
                None,
                &[
                    cand("", "Security Key", true),
                    cand("", "Security Key", true)
                ]
            ),
            ReinsertMatch::Ambiguous
        );
        // A different model came back: not the confirmed key.
        assert_eq!(
            reinserted_match("", "Security Key", None, &[cand("", "Solo 2", true)]),
            ReinsertMatch::NotPresent
        );
        // The lone key now reports a serial, so it is not the serial-less key
        // the reset was confirmed for.
        assert_eq!(
            reinserted_match(
                "",
                "Security Key",
                None,
                &[cand("12345678", "Security Key", true)]
            ),
            ReinsertMatch::NotPresent
        );
        // Right model, no serial, but no FIDO HID interface to reset over.
        assert_eq!(
            reinserted_match("", "Security Key", None, &[cand("", "Security Key", false)]),
            ReinsertMatch::NotPresent
        );
        // Nothing plugged back in yet.
        assert_eq!(
            reinserted_match("", "Security Key", None, &[]),
            ReinsertMatch::NotPresent
        );
    }

    #[test]
    fn factory_reset_serial_less_rule_is_out_of_reach_when_a_serial_is_known() {
        // The looser sole-candidate rule must never be what accepts a key whose
        // identity is knowable: with a serial pinned, a lone serial-less key of
        // the same model is refused, however unambiguous it looks.
        assert_eq!(
            reinserted_match(
                "12345678",
                "Security Key",
                None,
                &[cand("", "Security Key", true)]
            ),
            ReinsertMatch::NotPresent
        );
        // …and the serial path still decides the cases it always did.
        assert_eq!(
            reinserted_match(
                "12345678",
                "Security Key",
                None,
                &[cand("12345678", "Security Key", true)]
            ),
            ReinsertMatch::Found(0)
        );
        // A match on serial stands even when the model name differs (a relabel
        // or a firmware-changed product string is not a mismatch of identity).
        assert_eq!(
            reinserted_match(
                "12345678",
                "Security Key",
                None,
                &[
                    cand("87654321", "Solo 2", true),
                    cand("12345678", "YubiKey 5", true)
                ]
            ),
            ReinsertMatch::Found(1)
        );
        // A different key in the port at the prompt is refused.
        assert_eq!(
            reinserted_match(
                "12345678",
                "Security Key",
                None,
                &[cand("87654321", "Security Key", true)]
            ),
            ReinsertMatch::NotPresent
        );
        // A serial several connected keys report identifies none of them.
        assert_eq!(
            reinserted_match(
                "12345678",
                "Security Key",
                None,
                &[
                    cand("12345678", "Security Key", true),
                    cand("12345678", "Security Key", true)
                ]
            ),
            ReinsertMatch::Ambiguous
        );
    }

    #[test]
    fn factory_reset_only_calls_it_a_different_key_when_every_key_names_itself() {
        // A YubiKey publishes no USB iSerialNumber, so right after a replug it
        // is visible over HID with an empty serial and its real one only lands
        // once the reader re-registers. That is the key coming back, not a
        // swap — it must not be reported as one.
        assert_eq!(
            not_present_reason(&[""]),
            NotPresentReason::Unidentified,
            "a key that hasn't published its serial yet is not a different key"
        );
        // Same when it is one of several: anything unidentified leaves the
        // question open.
        assert_eq!(
            not_present_reason(&["87654321", ""]),
            NotPresentReason::Unidentified
        );
        // Nothing back in the port yet — also not an accusation.
        assert_eq!(not_present_reason(&[]), NotPresentReason::Unidentified);

        // Regression, found on hardware 2026-07-28: a CCID-only token (a Molto2
        // in another port) reports no serial and has no FIDO interface, so it
        // can never be the key being waited for. Its serial must not reach this
        // function — the caller filters on `hid_path` — or a genuine swap gets
        // reported as "that is not a different key" while the different key is
        // sitting right there. The list below is what the caller now passes for
        // {Solo 2 present, Molto2 present, YubiKey pinned and absent}.
        assert_eq!(
            not_present_reason(&["07A9568FBE31AD5DAD1F2298476CF0D4"]),
            NotPresentReason::DifferentKey,
            "a serial-less non-FIDO device must not mask a real mismatch"
        );
        // Every visible key names itself and none of them is the pinned one:
        // now, and only now, is a mismatch a fact.
        assert_eq!(
            not_present_reason(&["87654321"]),
            NotPresentReason::DifferentKey
        );
        assert_eq!(
            not_present_reason(&["87654321", "11112222"]),
            NotPresentReason::DifferentKey
        );
    }

    #[test]
    fn factory_reset_unidentified_key_is_not_accused_of_being_a_swap() {
        // The message the empty-serial case produces must not claim a swap, and
        // must name the command that finishes the wipe without re-running the
        // race — `factory-reset --yes` would just replay it.
        let msg = not_present_message(
            "YubiKey 5",
            "12345678",
            3,
            "YubiKey 5 with no serial",
            not_present_reason(&[""]),
        );
        assert!(
            !msg.contains("is not the one this factory reset was confirmed for"),
            "must not accuse a swap: {msg}"
        );
        assert!(msg.contains("did not come back with an identity"), "{msg}");
        assert!(msg.contains("card interface"), "must say why: {msg}");
        assert!(
            msg.contains("`keyroostctl fido reset --yes`"),
            "must name the way to finish the wipe: {msg}"
        );

        // …and the genuine mismatch still refuses in as many words.
        let msg = not_present_message(
            "YubiKey 5",
            "12345678",
            3,
            "YubiKey 5 serial 87654321",
            not_present_reason(&["87654321"]),
        );
        assert!(
            msg.contains("is not the one this factory reset was confirmed for"),
            "{msg}"
        );
        assert!(msg.contains("87654321"), "{msg}");
        assert!(
            !msg.contains("fido reset"),
            "a different key must not be offered a shortcut to wiping it: {msg}"
        );
    }

    #[test]
    fn factory_reset_serial_less_key_is_matched_by_usb_ids_not_model_name() {
        // The model name is read from the PC/SC reader name before the replug
        // and from the HID product string after it. For a vendor whose reader
        // name we don't normalize the two differ, and comparing them refuses
        // the very key that just came back. The USB ids don't drift.
        const NITROKEY: (u16, u16) = (0x20a0, 0x42b2);
        assert_eq!(
            reinserted_serial_less_target(
                "Nitrokey 3",
                Some(NITROKEY),
                &[cand_ids("", "Nitrokey 3 NFC", NITROKEY, true)]
            ),
            ReinsertMatch::Found(0),
            "same product, differently spelled model name: still the same key"
        );
        // A different product in the port is still refused — the ids are what
        // does the disqualifying now.
        assert_eq!(
            reinserted_serial_less_target(
                "Nitrokey 3",
                Some(NITROKEY),
                &[cand_ids("", "Nitrokey 3", (0x1050, 0x0407), true)]
            ),
            ReinsertMatch::NotPresent
        );
        // With the ids unknown on one side there is nothing better than the
        // model name, so that rule stays in place as the fallback.
        assert_eq!(
            reinserted_serial_less_target("Nitrokey 3", None, &[cand("", "Nitrokey 3", true)]),
            ReinsertMatch::Found(0)
        );
        assert_eq!(
            reinserted_serial_less_target("Nitrokey 3", None, &[cand("", "Solo 2", true)]),
            ReinsertMatch::NotPresent
        );
        // Matching ids do not loosen anything else: a second key still refuses,
        // and a key with a serial is not the serial-less one that was pinned.
        assert_eq!(
            reinserted_serial_less_target(
                "Nitrokey 3",
                Some(NITROKEY),
                &[
                    cand_ids("", "Nitrokey 3", NITROKEY, true),
                    cand_ids("", "Nitrokey 3", NITROKEY, true)
                ]
            ),
            ReinsertMatch::Ambiguous
        );
        assert_eq!(
            reinserted_serial_less_target(
                "Nitrokey 3",
                Some(NITROKEY),
                &[cand_ids("12345678", "Nitrokey 3", NITROKEY, true)]
            ),
            ReinsertMatch::NotPresent
        );
    }

    #[test]
    fn factory_reset_keeps_polling_for_a_key_that_came_back_card_first() {
        // The card side re-registered before the hidraw node existed: the key
        // is the right one, but there is nothing to send CTAP over yet. Acting
        // on it fails with "came back without a FIDO HID interface" while the
        // budget that exists for exactly this moment is unspent — so keep
        // polling instead.
        let half = [cand("12345678", "YubiKey 5", false)];
        assert!(!reinsert_settled(&ReinsertMatch::Found(0), &half));
        // Once the FIDO interface shows up there is nothing left to wait for.
        let whole = [cand("12345678", "YubiKey 5", true)];
        assert!(reinsert_settled(&ReinsertMatch::Found(0), &whole));
        // Nothing matched yet: keep looking until the deadline.
        assert!(!reinsert_settled(&ReinsertMatch::NotPresent, &whole));
        // Ambiguous stops at once, in both directions: a second key claiming
        // the pinned identity is not something waiting can resolve, and the
        // wait would only be spent to refuse anyway.
        assert!(reinsert_settled(&ReinsertMatch::Ambiguous, &half));
        assert!(reinsert_settled(&ReinsertMatch::Ambiguous, &whole));
    }

    #[test]
    fn piv_factory_reset_failure_points_at_the_reset_that_can_finish() {
        // A fault in the PUK loop leaves the PIN blocked and the PUK not, and
        // the card refuses RESET until both are — so `piv reset` cannot finish
        // the job in the state this message accompanies. Only re-running the
        // factory reset works whether one credential ended up blocked or both.
        let msg = piv_factory_reset_failure("PIV: unexpected status 6A80");
        assert!(msg.contains("PIV: unexpected status 6A80"), "{msg}");
        assert!(
            !msg.contains("piv reset"),
            "must not point at a command the card would refuse: {msg}"
        );
        assert!(msg.contains("`keyroostctl factory-reset`"), "{msg}");
        assert!(
            msg.contains("not bricked"),
            "the user needs to know the card is recoverable: {msg}"
        );
    }

    #[test]
    fn factory_reset_consent_does_not_promise_the_key_stays_usable() {
        // PIV's wipe blocks the PIN and PUK before erasing, so a run that stops
        // in between leaves that applet locked and un-wiped. Consent must not
        // be asked for on a promise the tool can't keep — same rule the GUI's
        // confirmation follows.
        assert!(!FACTORY_RESET_CONSENT.contains("stays usable"));
        assert!(!FACTORY_RESET_CONSENT.contains("stays fully usable"));
        assert!(
            FACTORY_RESET_CONSENT
                .contains("Each applet that completes comes back in factory condition"),
            "{FACTORY_RESET_CONSENT}"
        );
        // The command's own help text is the other place the user reads this
        // before consenting.
        use clap::CommandFactory;
        let cmd = Cli::command();
        let sub = cmd
            .find_subcommand("factory-reset")
            .expect("factory-reset subcommand");
        let help = sub.clone().render_long_help().to_string();
        assert!(!help.contains("stays fully usable"), "{help}");
        assert!(help.contains("comes back in factory condition"), "{help}");
    }

    #[test]
    fn factory_reset_requires_explicit_yes() {
        match parse(&["keyroostctl", "factory-reset", "--yes"])
            .unwrap()
            .command
        {
            Some(Cmd::FactoryReset { yes, .. }) => assert!(yes),
            _ => panic!("expected factory-reset"),
        }
        match parse(&["keyroostctl", "factory-reset"]).unwrap().command {
            Some(Cmd::FactoryReset { yes, .. }) => assert!(!yes),
            _ => panic!("expected factory-reset"),
        }
    }

    #[test]
    fn oath_add_positional_name_does_not_hijack_device_selector() {
        // Regression: a subcommand's `name` arg must not be consumed as the
        // global device selector. That happened when the global selector shared
        // the clap id `name` (a global arg merges with same-id subcommand args),
        // so `oath add <NAME>` routed the credential name into device resolution
        // and could never run. The global selector's id/flag is now `--device`.
        let cli = parse(&[
            "keyroostctl",
            "oath",
            "add",
            "issuer:acct",
            "--secret-stdin",
        ])
        .unwrap();
        assert!(
            cli.device.is_none(),
            "the global --device selector must stay unset when only a positional is given"
        );
        match cli.command {
            Some(Cmd::Oath {
                cmd: OathCmd::Add { name, .. },
            }) => assert_eq!(name, "issuer:acct"),
            _ => panic!("expected `oath add` with the credential name bound to the positional"),
        }

        // And --device still selects a device, independent of any positional.
        let cli2 = parse(&["keyroostctl", "--device", "mykey", "oath", "list"]).unwrap();
        assert_eq!(cli2.device.as_deref(), Some("mykey"));
    }

    #[test]
    fn sanitize_terminal_flattens_all_control_chars() {
        // ESC-based CSI, OSC with BEL, DEL, and a C1 byte all become spaces.
        let dirty = "a\x1b[31mb\x1b]0;t\x07c\x7fd\u{9b}e";
        let clean = sanitize_terminal(dirty);
        assert!(!clean.chars().any(|c| c.is_control()));
        assert_eq!(clean.chars().count(), dirty.chars().count()); // 1:1, alignment safe
        assert!(clean.starts_with("a "));
    }

    #[test]
    fn sanitize_multiline_keeps_newline_tab_but_strips_escapes() {
        let dirty = "line1\n\tcol\x1b[2Jx\r";
        let clean = sanitize_multiline(dirty);
        assert!(clean.contains('\n'), "newline preserved");
        assert!(clean.contains('\t'), "tab preserved");
        assert!(!clean.contains('\x1b'), "ESC flattened");
        assert!(!clean.contains('\r'), "other control (CR) flattened");
    }

    #[test]
    fn sanitize_terminal_neutralizes_all_hostile_chars() {
        for c in [
            '\u{001B}',
            '\u{061C}',
            '\u{200B}',
            '\u{202E}',
            '\u{2069}',
            '\u{FEFF}',
            '\u{2028}',
            '\u{2029}',
            '\u{2060}',
            '\u{00AD}',
            '\u{180E}',
            '\u{E007F}',
        ] {
            let s = sanitize_terminal(&format!("x{c}y"));
            assert!(
                !s.chars().any(|ch| ch == c),
                "U+{:04X} survived sanitize_terminal",
                c as u32
            );
            assert_eq!(s.chars().count(), 3, "length must be preserved");
        }
        // A line separator must not survive into a single listing line.
        let line = sanitize_terminal("app:acct\u{2028}injected");
        assert!(!line.contains('\u{2028}'));
        assert!(!line.contains('\n'));
    }

    #[test]
    fn sanitize_flattens_bidi_and_zero_width_format_chars() {
        // Cf-category chars pass char::is_control(); a hostile device string
        // using RLO/isolates could visually reverse or spoof `list` output
        // (Trojan-Source class), and zero-widths can hide a lookalike name.
        let dirty = "ser\u{202E}321\u{2066}x\u{200B}y\u{061C}z\u{FEFF}";
        for clean in [sanitize_terminal(dirty), sanitize_multiline(dirty)] {
            for hostile in ['\u{202E}', '\u{2066}', '\u{200B}', '\u{061C}', '\u{FEFF}'] {
                assert!(!clean.contains(hostile), "bidi/ZW flattened");
            }
            assert!(!clean.chars().any(|c| c.is_control()));
            assert_eq!(clean.chars().count(), dirty.chars().count());
        }
        // Plain text — including non-ASCII letters — is untouched.
        assert_eq!(sanitize_terminal("Ĺéttèrs 123"), "Ĺéttèrs 123");
    }

    #[test]
    fn broken_pipe_panic_detection() {
        // std println! Display shape (what `molto slots … | head` panics with).
        assert!(is_broken_pipe_panic(
            "failed printing to stdout: Broken pipe (os error 32)"
        ));
        // clap_complete Debug shape (what `completions … | head` panics with).
        assert!(is_broken_pipe_panic(
            "failed to write completion file: Os { code: 32, kind: BrokenPipe, message: \"Broken pipe\" }"
        ));
        // Non-C locale: strerror text is translated, but the errno / Debug kind
        // token still fires, so the guard is not locale-fragile.
        assert!(is_broken_pipe_panic(
            "failed printing to stdout: Rohrbruch (os error 32)"
        ));
        assert!(is_broken_pipe_panic(
            "failed to write completion file: Os { code: 32, kind: BrokenPipe, message: \"Rohrbruch\" }"
        ));
        // A different print failure (disk full) must NOT be swallowed as success.
        assert!(!is_broken_pipe_panic(
            "failed printing to stdout: No space left on device (os error 28)"
        ));
        // Unrelated panics fall through to the default hook.
        assert!(!is_broken_pipe_panic(
            "index out of bounds: the len is 3 but the index is 5"
        ));
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

    #[cfg(unix)]
    #[test]
    fn write_private_file_rejects_symlink_destination() {
        use std::os::unix::fs::symlink;

        let mut base = std::env::temp_dir();
        base.push(format!("keyroost_symtest_{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let victim = base.join("victim");
        let link = base.join("link");
        // Attacker pre-plants a symlink where keyroost will write secret output.
        symlink(&victim, &link).unwrap();

        let err = write_private_file(&link, b"top secret plaintext").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);

        // No bytes may have been written through the link to the victim target.
        assert!(!victim.exists(), "secret bytes leaked through the symlink");
        // The link itself is left untouched (still a symlink).
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());

        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn resolve_otp_target_binds_selected_device_or_fails_closed() {
        use keyroost_resolve::{Caps, Device, DeviceKind};

        fn otp_dev(name: &str, hid: Option<&str>, reader: Option<&str>) -> Device {
            let mut caps = Caps::default();
            caps.insert(Caps::OTP);
            Device {
                id: format!("serial:{name}"),
                name: Some(name.to_string()),
                vendor: "Token2".into(),
                model: "PIN+".into(),
                serial: name.to_string(),
                transport: "USB".into(),
                firmware: String::new(),
                caps,
                unverified: Caps::default(),
                kind: DeviceKind::Key,
                hid_path: hid.map(std::path::PathBuf::from),
                reader: reader.map(str::to_owned),
            }
        }

        let a = otp_dev("keyA", Some("/dev/hidraw0"), Some("Token2 A 00 00"));
        let b = otp_dev("keyB", Some("/dev/hidraw1"), Some("Token2 B 00 00"));
        let devices = vec![a, b];

        // No selector -> None, so the caller falls back to detect_*.
        assert!(matches!(
            resolve_otp_target(&devices, None, OtpTransportArg::Auto),
            Ok(None)
        ));

        // Named + Auto on a dual-interface key -> the *selected* device's HID
        // path with ITS OWN reader kept as an open-time fallback (#82: some
        // firmware botches the HID probe while CCID works), never the first
        // device on the bus.
        match resolve_otp_target(&devices, Some("keyB"), OtpTransportArg::Auto) {
            Ok(Some(OtpTarget::HidThenReader(p, r))) => {
                assert_eq!(p, std::path::PathBuf::from("/dev/hidraw1"));
                assert_eq!(r, "Token2 B 00 00");
            }
            other => panic!("expected keyB HID path + reader fallback, got {other:?}"),
        }

        // Named + Auto on a HID-only key -> a plain HID target.
        let hid_only = vec![otp_dev("solo", Some("/dev/hidraw7"), None)];
        match resolve_otp_target(&hid_only, Some("solo"), OtpTransportArg::Auto) {
            Ok(Some(OtpTarget::HidPath(p))) => {
                assert_eq!(p, std::path::PathBuf::from("/dev/hidraw7"))
            }
            other => panic!("expected plain HID target, got {other:?}"),
        }

        // Named + Ccid -> that device's reader.
        match resolve_otp_target(&devices, Some("keyA"), OtpTransportArg::Ccid) {
            Ok(Some(OtpTarget::Reader(r))) => assert_eq!(r, "Token2 A 00 00"),
            other => panic!("expected keyA reader, got {other:?}"),
        }

        // Unknown name -> error, never opens anything.
        assert!(resolve_otp_target(&devices, Some("ghost"), OtpTransportArg::Auto).is_err());

        // Ambiguous (two live devices share the selected name) -> fail closed.
        let mut dup = devices.clone();
        dup[0].name = Some("keyB".to_string());
        assert!(resolve_otp_target(&dup, Some("keyB"), OtpTransportArg::Auto).is_err());

        // Transport a device can't satisfy -> error (no HID interface for --transport hid).
        let ccid_only = vec![otp_dev("nfc", None, Some("ACS reader 00"))];
        assert!(resolve_otp_target(&ccid_only, Some("nfc"), OtpTransportArg::Hid).is_err());
    }

    #[test]
    fn reader_for_name_targets_the_named_molto() {
        use keyroost_resolve::{Caps, Device, DeviceKind};

        fn molto(name: &str, reader: &str) -> Device {
            let mut caps = Caps::default();
            caps.insert(Caps::TOTP);
            Device {
                id: format!("molto:{reader}"),
                name: Some(name.to_string()),
                vendor: "Token2".into(),
                model: "Molto2".into(),
                serial: name.to_string(),
                transport: "USB · PC/SC".into(),
                firmware: String::new(),
                caps,
                unverified: Caps::default(),
                kind: DeviceKind::Token,
                hid_path: None,
                reader: Some(reader.to_string()),
            }
        }

        let devices = vec![
            molto("deskA", "TOKEN2 Molto2 (AAAA) 00 00"),
            molto("deskB", "TOKEN2 Molto2 (BBBB) 00 00"),
        ];

        assert_eq!(
            reader_for_name(&devices, "deskB").unwrap(),
            "TOKEN2 Molto2 (BBBB) 00 00"
        );
        assert!(reader_for_name(&devices, "nope").is_err());
    }

    #[test]
    fn reader_for_name_is_ambiguous_when_two_devices_share_a_name() {
        use keyroost_resolve::{Caps, Device, DeviceKind};
        fn dev(name: &str, reader: &str) -> Device {
            Device {
                id: format!("reader:{reader}"),
                name: Some(name.to_string()),
                vendor: "X".into(),
                model: "Y".into(),
                serial: String::new(),
                transport: String::new(),
                firmware: String::new(),
                caps: Caps::default(),
                unverified: Caps::default(),
                kind: DeviceKind::Key,
                hid_path: None,
                reader: Some(reader.to_string()),
            }
        }
        let devices = vec![dev("twin", "reader-1"), dev("twin", "reader-2")];
        assert!(reader_for_name(&devices, "twin").is_err());
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
    fn openpgp_generate_key_algorithm_is_optional_and_named_like_gpg() {
        // No --algorithm: None — generate whatever the slot's attributes say
        // (the pre-#106 behaviour, unchanged for scripts).
        match parse(&["keyroostctl", "openpgp", "generate-key", "--yes"])
            .unwrap()
            .command
        {
            Some(Cmd::Openpgp {
                cmd: OpenpgpCmd::GenerateKey { algorithm, .. },
            }) => assert!(algorithm.is_none()),
            _ => panic!("expected openpgp generate-key"),
        }
        for (name, want) in [
            ("ed25519", keyroost_openpgp::KeyAlg::Ed25519),
            ("x25519", keyroost_openpgp::KeyAlg::X25519),
            ("cv25519", keyroost_openpgp::KeyAlg::X25519),
            ("nistp256", keyroost_openpgp::KeyAlg::NistP256),
            ("brainpoolp512", keyroost_openpgp::KeyAlg::BrainpoolP512r1),
            ("rsa4096", keyroost_openpgp::KeyAlg::Rsa4096),
        ] {
            match parse(&[
                "keyroostctl",
                "openpgp",
                "generate-key",
                "--yes",
                "--algorithm",
                name,
            ])
            .unwrap()
            .command
            {
                Some(Cmd::Openpgp {
                    cmd:
                        OpenpgpCmd::GenerateKey {
                            algorithm: Some(a), ..
                        },
                }) => assert_eq!(a.to_alg(), want, "{name}"),
                _ => panic!("expected openpgp generate-key --algorithm {name}"),
            }
        }
        assert!(parse(&["keyroostctl", "openpgp", "algorithms"]).is_ok());
    }

    #[test]
    fn openpgp_sign_input_framing_follows_the_slot_algorithm() {
        let data = b"hello";
        // RSA: PKCS#1 DigestInfo. ECC (ECDSA/EdDSA): the bare digest.
        let rsa = [0x01, 0x08, 0x00, 0x00, 0x20, 0x02];
        let ecdsa = [0x13, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
        let ed = [0x16, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];
        assert_eq!(
            openpgp_sign_input("signature", &rsa, SignHash::Sha256, data).unwrap(),
            SignHash::Sha256.digest_info(data)
        );
        assert_eq!(
            openpgp_sign_input("signature", &ecdsa, SignHash::Sha256, data).unwrap(),
            keyroost_proto::sha256::sha256(data).to_vec()
        );
        assert_eq!(
            openpgp_sign_input("signature", &ed, SignHash::Sha256, data).unwrap(),
            keyroost_proto::sha256::sha256(data).to_vec()
        );
        // Unknown / empty attributes: refuse to guess rather than assume RSA.
        let err = openpgp_sign_input("signature", &[], SignHash::Sha1, data).unwrap_err();
        assert!(
            err.contains("cannot tell the signature slot's algorithm"),
            "{err}"
        );
        // SHA-1 is refused on an ECC signing key.
        let err = openpgp_sign_input("signature", &ed, SignHash::Sha1, data).unwrap_err();
        assert!(
            err.contains("SHA-1 cannot be used with an ECC signing key"),
            "{err}"
        );
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
        assert!(parse(&["keyroostctl", "molto", "info", "--key-env", "K"]).is_ok());
    }

    #[test]
    fn name_is_accepted_on_every_group() {
        for g in [
            &["keyroostctl", "--device", "k", "piv", "status"][..],
            &["keyroostctl", "--device", "k", "oath", "list"][..],
            &["keyroostctl", "--device", "k", "openpgp", "status"][..],
            &["keyroostctl", "--device", "k", "otp", "list"][..],
            &["keyroostctl", "--device", "k", "molto", "info"][..],
            &["keyroostctl", "--device", "k", "fido", "info"][..],
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

    #[test]
    fn piv_move_key_parses_standard_and_retired_slots() {
        match parse(&[
            "keyroostctl",
            "piv",
            "move-key",
            "--from",
            "9d",
            "--to",
            "82",
        ])
        .unwrap()
        .command
        {
            Some(Cmd::Piv {
                cmd: PivCmd::MoveKey { from, to, .. },
            }) => {
                assert_eq!(from.to_slot().key_ref(), 0x9D);
                assert_eq!(to.to_slot().key_ref(), 0x82);
            }
            _ => panic!("expected piv move-key"),
        }
    }

    #[test]
    fn piv_generate_key_policies_default_to_the_plain_piv_wire_format() {
        // Omitting both flags must decode to Default/Default — the byte layer
        // then leaves the 0xAA/0xAB policy tags out of the APDU entirely, the
        // standard PIV command every card accepts. A drifted default would
        // silently switch every scripted generate-key to the Yubico extended
        // APDU, which non-Yubico cards reject.
        match parse(&["keyroostctl", "piv", "generate-key", "--slot", "9a"])
            .unwrap()
            .command
        {
            Some(Cmd::Piv {
                cmd:
                    PivCmd::GenerateKey {
                        pin_policy,
                        touch_policy,
                        ..
                    },
            }) => {
                assert_eq!(pin_policy.to_policy(), keyroost_piv::PinPolicy::Default);
                assert_eq!(touch_policy.to_policy(), keyroost_piv::TouchPolicy::Default);
            }
            _ => panic!("expected piv generate-key"),
        }

        // Explicit values must land in their own fields, not each other's.
        match parse(&[
            "keyroostctl",
            "piv",
            "generate-key",
            "--slot",
            "9a",
            "--pin-policy",
            "once",
            "--touch-policy",
            "cached",
        ])
        .unwrap()
        .command
        {
            Some(Cmd::Piv {
                cmd:
                    PivCmd::GenerateKey {
                        pin_policy,
                        touch_policy,
                        ..
                    },
            }) => {
                assert_eq!(pin_policy.to_policy(), keyroost_piv::PinPolicy::Once);
                assert_eq!(touch_policy.to_policy(), keyroost_piv::TouchPolicy::Cached);
            }
            _ => panic!("expected piv generate-key"),
        }
    }

    #[test]
    fn piv_new_chuid_default_days_matches_self_sign() {
        // `new-chuid --days` and `self-sign --days` are two separate clap
        // literal defaults (365 each) — pin them equal so a future change to
        // one doesn't silently drift from the other.
        let chuid_days = match parse(&["keyroostctl", "piv", "new-chuid"]).unwrap().command {
            Some(Cmd::Piv {
                cmd: PivCmd::NewChuid { days, .. },
            }) => days,
            _ => panic!("expected piv new-chuid"),
        };
        let cert_days = match parse(&[
            "keyroostctl",
            "piv",
            "self-sign",
            "--slot",
            "9a",
            "--subject",
            "CN=x",
        ])
        .unwrap()
        .command
        {
            Some(Cmd::Piv {
                cmd: PivCmd::SelfSign { days, .. },
            }) => days,
            _ => panic!("expected piv self-sign"),
        };
        assert_eq!(chuid_days, cert_days);
    }

    #[test]
    fn check_valid_days_accepts_the_default_and_the_actual_ceiling() {
        assert!(check_valid_days(365).is_ok());
        assert!(check_valid_days(keyroost_piv::max_valid_days(u64::from(unix_now()))).is_ok());
    }

    #[test]
    fn check_valid_days_rejects_one_past_the_ceiling() {
        let max = keyroost_piv::max_valid_days(u64::from(unix_now()));
        let err = check_valid_days(max + 1).unwrap_err();
        assert!(err.to_string().contains("exceeds"));
    }

    #[test]
    fn piv_policy_values_map_one_to_one_onto_the_byte_layer() {
        use keyroost_piv::{PinPolicy, TouchPolicy};
        for (cli, lib) in [
            (CliPinPolicy::Default, PinPolicy::Default),
            (CliPinPolicy::Never, PinPolicy::Never),
            (CliPinPolicy::Once, PinPolicy::Once),
            (CliPinPolicy::Always, PinPolicy::Always),
        ] {
            assert_eq!(cli.to_policy(), lib);
        }
        for (cli, lib) in [
            (CliTouchPolicy::Default, TouchPolicy::Default),
            (CliTouchPolicy::Never, TouchPolicy::Never),
            (CliTouchPolicy::Always, TouchPolicy::Always),
            (CliTouchPolicy::Cached, TouchPolicy::Cached),
        ] {
            assert_eq!(cli.to_policy(), lib);
        }
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
            caps_unverified: vec![],
        };
        assert_json_has_keys(
            &d,
            &[
                "vendor",
                "model",
                "serial",
                "transport",
                "kind",
                "caps",
                "caps_unverified",
            ],
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
            chuid: Some(json_out::PivChuidJson {
                fasc_n: "d4e739da...".into(),
                guid: "aabbccdd-eeff-1122-3344-556677889900".into(),
                expiration: "2030-01-01".into(),
                signature: "".into(),
                lrc: "".into(),
            }),
            slots: vec![json_out::PivSlotJson {
                slot: "9a (Authentication)".into(),
                cert_present: true,
                cert_len: 800,
            }],
        };
        assert_json_has_keys(&p, &["version", "serial", "pin_retries", "chuid", "slots"]);
    }

    #[test]
    fn openpgp_status_json_serializes() {
        let o = json_out::OpenpgpStatusJson {
            aid: "d2760001240103040006...".into(),
            serial: Some(12345678),
            sig_algo: "RSA-2048".into(),
            dec_algo: "RSA-2048".into(),
            aut_algo: "RSA-2048".into(),
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
        let info = keyroost_ctap::AuthenticatorInfo::default();
        let shaped = large_blob_list_json(&array, &info);
        assert_eq!(shaped.entries.len(), 2);

        // [0] is a keyroost note: is_note true, text present, size == byte len.
        assert_eq!(shaped.entries[0].index, 0);
        assert!(shaped.entries[0].is_note);
        assert_eq!(shaped.entries[0].text.as_deref(), Some("hello"));
        assert_eq!(shaped.entries[0].size, "hello".len() as u64);
        assert_eq!(shaped.entries[0].kind, "note");
        assert!(shaped.entries[0].ssh_cert.is_none());

        // [1] is opaque: is_note false, text omitted.
        assert_eq!(shaped.entries[1].index, 1);
        assert!(!shaped.entries[1].is_note);
        assert!(shaped.entries[1].text.is_none());
        assert_eq!(shaped.entries[1].kind, "opaque");
        assert!(shaped.entries[1].ssh_cert.is_none());

        // The array's capacity is computed against the given AuthenticatorInfo
        // (spec-minimum 1024 bytes here, since max_serialized_large_blob_array
        // is unset).
        assert_eq!(shaped.capacity.max_bytes, 1024);
        assert!(shaped.capacity.used_bytes > 0);
        assert_eq!(
            shaped.capacity.free_bytes,
            shaped.capacity.max_bytes - shaped.capacity.used_bytes
        );

        // The opaque entry's text is omitted from the JSON (skip_serializing_if).
        let s = serde_json::to_string(&shaped).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        let arr = v.get("entries").unwrap().as_array().unwrap();
        assert!(arr[0].get("text").is_some());
        assert!(arr[1].get("text").is_none());
        assert!(arr[0].get("ssh_cert").is_none());
    }

    #[test]
    fn large_blob_get_json_carries_hex_for_opaque() {
        let entry = opaque_entry();
        let (kind, ssh_cert, _) = large_blob_kind(&entry);
        let g = json_out::FidoLargeBlobGetJson {
            index: 0,
            size: entry.orig_size,
            is_note: entry.is_kr_note(),
            text: entry.as_text(),
            kind,
            ssh_cert,
            hex: hex_encode(&entry.ciphertext),
        };
        assert!(!g.is_note);
        assert!(g.text.is_none());
        assert_eq!(g.kind, "opaque");
        assert_eq!(g.hex, "deadbeef0099");
        assert_json_has_keys(&g, &["index", "size", "is_note", "kind", "hex"]);
        // text omitted for an opaque entry.
        let s = serde_json::to_string(&g).unwrap();
        assert!(!s.contains("\"text\""), "text should be omitted: {s}");
    }

    #[test]
    fn large_blob_get_json_includes_note_text() {
        let entry = LargeBlobEntry::from_text("a note");
        let (kind, ssh_cert, _) = large_blob_kind(&entry);
        let g = json_out::FidoLargeBlobGetJson {
            index: 3,
            size: entry.orig_size,
            is_note: entry.is_kr_note(),
            text: entry.as_text(),
            kind,
            ssh_cert,
            hex: hex_encode(&entry.ciphertext),
        };
        assert!(g.is_note);
        assert_eq!(g.kind, "note");
        assert_eq!(g.text.as_deref(), Some("a note"));
        let s = serde_json::to_string(&g).unwrap();
        assert!(s.contains("\"text\":\"a note\""), "{s}");
    }

    #[test]
    fn large_blob_kind_classifies_note_and_opaque() {
        // Note entries classify as "note" with no ssh_cert payload.
        let note = LargeBlobEntry::from_text("hello");
        let (kind, ssh_cert, classified) = large_blob_kind(&note);
        assert_eq!(kind, "note");
        assert!(ssh_cert.is_none());
        assert!(matches!(
            classified,
            keyroost_ctap::large_blobs::EntryKind::Note(t) if t == "hello"
        ));

        // Unrecognized bytes classify as "opaque" with no ssh_cert payload.
        let opaque = opaque_entry();
        let (kind, ssh_cert, classified) = large_blob_kind(&opaque);
        assert_eq!(kind, "opaque");
        assert!(ssh_cert.is_none());
        assert!(matches!(
            classified,
            keyroost_ctap::large_blobs::EntryKind::Opaque
        ));
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
    fn preview_note_renders_hostile_content_inert() {
        // ESC + an OSC-style sequence and a soft hyphen must all be neutralized
        // through the shared sanitize path.
        let note = "hello\u{1b}]0;pwn\u{07}\u{00AD}world";
        let p = preview_note(note);
        assert!(!p.contains('\u{1b}'));
        assert!(!p.contains('\u{07}'));
        assert!(!p.contains('\u{00AD}'));
        assert!(p.contains("hello"));
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
        assert!(parse(&[
            "keyroostctl",
            "fido",
            "large-blob",
            "export",
            "0",
            "/tmp/out.bin"
        ])
        .is_ok());
        assert!(parse(&[
            "keyroostctl",
            "fido",
            "large-blob",
            "export",
            "0",
            "/tmp/out-cert.pub",
            "--as-cert"
        ])
        .is_ok());
    }
}

/// Randomized coverage (proptest, dev-only) for the pure device-selection and
/// terminal-sanitizing helpers — the CLI's fail-closed / output-hygiene
/// decisions, unreachable by the libfuzzer workspace because they live in a
/// binary crate.
#[cfg(test)]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;
    use std::path::PathBuf;

    /// Minimal Device fixture; only the fields the resolvers consult vary.
    fn dev(
        name: Option<&str>,
        otp: bool,
        hid: Option<&str>,
        reader: Option<&str>,
    ) -> keyroost_resolve::Device {
        let mut caps = keyroost_resolve::Caps::default();
        if otp {
            caps.insert(keyroost_resolve::Caps::OTP);
        }
        keyroost_resolve::Device {
            id: String::new(),
            name: name.map(String::from),
            vendor: String::new(),
            model: String::new(),
            serial: String::new(),
            transport: String::new(),
            firmware: String::new(),
            caps,
            unverified: keyroost_resolve::Caps::default(),
            kind: keyroost_resolve::DeviceKind::Key,
            hid_path: hid.map(PathBuf::from),
            reader: reader.map(String::from),
        }
    }

    /// (name, otp-capable, hid path, reader) — the raw shape a strategy
    /// turns into one test device.
    type DevSpec = (
        Option<&'static str>,
        bool,
        Option<&'static str>,
        Option<&'static str>,
    );

    /// Device-spec lists; names come from a two-value pool so collisions
    /// with the looked-up name actually happen.
    fn any_devices() -> impl Strategy<Value = Vec<DevSpec>> {
        proptest::collection::vec(
            (
                proptest::option::of(prop_oneof![Just("alpha"), Just("beta")]),
                any::<bool>(),
                proptest::option::of(Just("/dev/hidraw9")),
                proptest::option::of(Just("Acme CCID 00")),
            ),
            0..6,
        )
    }

    fn any_transport() -> impl Strategy<Value = OtpTransportArg> {
        prop_oneof![
            Just(OtpTransportArg::Auto),
            Just(OtpTransportArg::Hid),
            Just(OtpTransportArg::Ccid),
        ]
    }

    /// Strings biased toward the hostile end: arbitrary chars salted with
    /// ANSI escape, bidi override, zero-width space, BOM, newline, and tab —
    /// `\PC*`-style strategies would almost never produce these.
    fn any_hostile_string() -> impl Strategy<Value = String> {
        proptest::collection::vec(
            prop_oneof![
                4 => any::<char>(),
                1 => Just('\x1b'),
                1 => Just('\u{202E}'),
                1 => Just('\u{200B}'),
                1 => Just('\u{FEFF}'),
                1 => Just('\n'),
                1 => Just('\t'),
            ],
            0..64,
        )
        .prop_map(|chars| chars.into_iter().collect())
    }

    proptest! {
        /// `reader_for_name` hands back a reader only when exactly one
        /// connected device carries the name and that device has one —
        /// zero, two-plus, or a reader-less match all fail closed (KEY-015).
        #[test]
        fn reader_for_name_fails_closed_on_ambiguity(specs in any_devices()) {
            let devices: Vec<_> =
                specs.iter().map(|(n, o, h, r)| dev(*n, *o, *h, *r)).collect();
            let named: Vec<_> = devices
                .iter()
                .filter(|d| d.name.as_deref() == Some("alpha"))
                .collect();
            let got = reader_for_name(&devices, "alpha");
            match named.as_slice() {
                [only] => match &only.reader {
                    Some(r) => prop_assert_eq!(got.unwrap(), r.clone()),
                    None => prop_assert!(got.is_err()),
                },
                _ => prop_assert!(got.is_err(), "0 or >1 named devices must error"),
            }
        }

        /// `resolve_otp_target` binds to the one OTP-capable device carrying
        /// the name, honors the transport pick, and fails closed on zero /
        /// ambiguous matches or an unsatisfiable transport (KEY-003).
        #[test]
        fn resolve_otp_target_binds_exactly_or_errors(
            specs in any_devices(),
            transport in any_transport(),
        ) {
            let devices: Vec<_> =
                specs.iter().map(|(n, o, h, r)| dev(*n, *o, *h, *r)).collect();

            // No selector: never an error, never a target.
            prop_assert!(matches!(
                resolve_otp_target(&devices, None, transport),
                Ok(None)
            ));

            let named: Vec<_> = devices
                .iter()
                .filter(|d| {
                    d.name.as_deref() == Some("alpha")
                        && d.caps.has(keyroost_resolve::Caps::OTP)
                })
                .collect();
            let got = resolve_otp_target(&devices, Some("alpha"), transport);
            let [only] = named.as_slice() else {
                prop_assert!(got.is_err(), "0 or >1 OTP matches must error");
                return Ok(());
            };
            let expected_endpoint = match transport {
                OtpTransportArg::Hid => only.hid_path.clone().map(|p| (Some(p), None)),
                OtpTransportArg::Ccid => only.reader.clone().map(|r| (None, Some(r))),
                // Auto binds every interface the selected device offers:
                // both → HID first, its own reader as fallback (#82).
                OtpTransportArg::Auto => match (&only.hid_path, &only.reader) {
                    (Some(p), Some(r)) => Some((Some(p.clone()), Some(r.clone()))),
                    (Some(p), None) => Some((Some(p.clone()), None)),
                    (None, Some(r)) => Some((None, Some(r.clone()))),
                    (None, None) => None,
                },
            };
            match (got, expected_endpoint) {
                (Ok(Some(OtpTarget::HidPath(p))), Some((Some(exp), None))) => {
                    prop_assert_eq!(p, exp)
                }
                (Ok(Some(OtpTarget::Reader(r))), Some((None, Some(exp)))) => {
                    prop_assert_eq!(r, exp)
                }
                (Ok(Some(OtpTarget::HidThenReader(p, r))), Some((Some(ep), Some(er)))) => {
                    prop_assert_eq!(p, ep);
                    prop_assert_eq!(r, er);
                }
                (Err(_), None) => {}
                (got, exp) => prop_assert!(
                    false,
                    "target must be exactly the contracted endpoint: got={got:?} exp={exp:?}"
                ),
            }
        }

        /// Whatever bytes arrive from a device or file, the sanitized line is
        /// inert: no control, bidi, or zero-width char survives, and the
        /// character count is preserved so column alignment can't shift.
        #[test]
        fn sanitize_terminal_output_is_always_inert(s in any_hostile_string()) {
            let out = sanitize_terminal(&s);
            prop_assert!(!out.chars().any(keyroost_keyring::is_spoofing_char));
            prop_assert_eq!(out.chars().count(), s.chars().count());
            // Innocent characters pass through untouched, in place.
            for (o, i) in out.chars().zip(s.chars()) {
                if keyroost_keyring::is_spoofing_char(i) {
                    prop_assert_eq!(o, ' ');
                } else {
                    prop_assert_eq!(o, i);
                }
            }
        }

        /// The multiline variant keeps only `\n` and `\t` of the control
        /// space; everything else follows the terminal rule.
        #[test]
        fn sanitize_multiline_keeps_only_newline_and_tab(s in any_hostile_string()) {
            let out = sanitize_multiline(&s);
            prop_assert!(!out
                .chars()
                .any(|c| keyroost_keyring::is_spoofing_char(c) && c != '\n' && c != '\t'));
            prop_assert_eq!(out.chars().count(), s.chars().count());
            for (o, i) in out.chars().zip(s.chars()) {
                if i == '\n' || i == '\t' {
                    prop_assert_eq!(o, i);
                } else if keyroost_keyring::is_spoofing_char(i) {
                    prop_assert_eq!(o, ' ');
                } else {
                    prop_assert_eq!(o, i);
                }
            }
        }
    }
}

#[cfg(test)]
mod slot_sweep_tests {
    use super::*;
    use keyroost_proto::{ProfilePublicData, PublicDataError};
    use keyroost_transport::TransportError;

    fn block(title: Option<&str>) -> ProfilePublicData {
        ProfilePublicData {
            title: title.map(String::from),
            flag: 0,
            algorithm: 1,
            time_step: 30,
            time_a: 0,
            time_b: 0,
            digits: 6,
            seed_present: title.is_some(),
        }
    }

    /// A mid-sweep read failure must yield everything read so far plus the
    /// failing slot, not throw the partial results away.
    #[test]
    fn sweep_keeps_partial_results_up_to_the_failure() {
        let reads = vec![
            (0u8, Ok(block(Some("github")))),
            (1u8, Ok(block(None))),
            (
                2u8,
                Err(TransportError::PublicData(PublicDataError::Truncated)),
            ),
            // Never reached — the sweep stops at the first failure.
            (3u8, Ok(block(Some("unreachable")))),
        ];
        let (slots, err) = sweep_until_error(reads.into_iter());
        assert_eq!(slots.len(), 2);
        assert_eq!(slots[0].title.as_deref(), Some("github"));
        let (slot, e) = err.expect("failure must be reported");
        assert_eq!(slot, 2);
        assert!(matches!(
            e,
            TransportError::PublicData(PublicDataError::Truncated)
        ));
    }

    #[test]
    fn clean_sweep_reports_no_error() {
        let reads = (0u8..=3).map(|p| (p, Ok(block(None))));
        let (slots, err) = sweep_until_error(reads);
        assert_eq!(slots.len(), 4);
        assert!(err.is_none());
    }
}
