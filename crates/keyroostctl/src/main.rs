//! keyroostctl — CLI for managing hardware security keys: FIDO2, OATH,
//! OpenPGP, PIV, and Token2 programmable TOTP tokens.
//!
//! Started as a replacement for the Molto2 vendor script with a cleaner
//! subcommand layout; each applet now has its own command group.

// clap turns the arg doc comments into --help text and man pages, where
// placeholders like `<group>` are meant literally, not as HTML tags.
#![allow(rustdoc::invalid_html_tags)]

use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand, ValueEnum};
use keyroost_proto::codec::{base32_decode, hex_decode, hex_encode};
use keyroost_proto::commands::{
    DisplayTimeout, HmacAlgo, OtpDigits, ProfileConfig, TimeStep, DEFAULT_CUSTOMER_KEY,
};
use keyroost_transport::{SeedDeleteOutcome, Session, TransportError};

use std::path::Path;
use std::sync::OnceLock;

use keyroost_keyring::Keyring;
use keyroost_resolve::{ccid_readers_if_needed, ccid_serials_for, Need};

mod json_out;
mod output;
mod overview;
mod prompt;
mod secrets;
mod target;

use crate::output::{emit_json, json_output};
use crate::secrets::{SecretSource, Secrets, Source, Spec};

/// The global `--device` selector, captured once in `run()` so the FIDO device
/// resolver can honor it without threading it through every subcommand handler.
static SELECTED_KEY_NAME: OnceLock<Option<String>> = OnceLock::new();

/// `--reader` help shared by every command that takes it.
const READER_HELP: &str =
    "Smart-card reader whose name contains this text (case-insensitive), instead of --device";
/// `--path` help shared by every FIDO and OTP command that takes it.
const PATH_HELP: &str = "USB HID device path of the key, instead of --device";

#[derive(Parser)]
#[command(
    name = "keyroostctl",
    version,
    about = "Manage hardware security keys: FIDO2, OATH, OpenPGP, PIV and Token2 OTP, plus Token2 programmable TOTP tokens (Molto2 and the 2nd-generation single-profile token)"
)]
struct Cli {
    /// Print every message sent to and received from the key to stderr (APDUs,
    /// and FIDO CTAP over USB; not FIDO through a smart-card reader). The
    /// format is for people and may change between releases.
    #[arg(long, global = true, help_heading = "Global options")]
    debug: bool,
    /// Target a key by friendly name, serial, or `list` number (prefix name:,
    /// serial: or list: to force which). Can't be combined with --reader/--path.
    //
    // Named `device` (flag `--device`), not `name`: a *global* arg whose clap id
    // is `name` merges with every subcommand arg of the same id (e.g. the
    // `oath add <NAME>` positional, `fido fingerprint --name`), so a credential
    // or fingerprint name was being consumed as this device selector. A distinct
    // id keeps the global selector separate from all of them.
    #[arg(
        long,
        short = 'd',
        global = true,
        help_heading = "Global options",
        value_name = "KEY",
        add = clap_complete::ArgValueCandidates::new(device_candidates)
    )]
    device: Option<String>,
    /// Emit machine-readable JSON instead of human text (where supported: status
    /// and query commands). Side-effect commands ignore it.
    #[arg(long, global = true, help_heading = "Global options")]
    json: bool,

    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// List connected keys: smart-card (PC/SC) readers and FIDO USB (HID)
    /// devices.
    List {
        /// Show every HID device, not just those advertising the FIDO usage page.
        #[arg(long)]
        all_hid: bool,
    },
    /// Diagnose the local environment: PC/SC service, readers, FIDO HID
    /// access, udev rules, registry permissions. Read-only, touches no key.
    Doctor,
    /// Manage friendly names for security keys (opt-in; stored in keys.json).
    Name {
        #[command(subcommand)]
        cmd: NameCmd,
    },
    /// Manage FIDO2: passkeys, PIN, fingerprints, settings, the large-blob
    /// store, SSH certificates, and reset.
    Fido {
        #[command(subcommand)]
        cmd: FidoCmd,
    },
    /// Show codes and manage OATH (TOTP/HOTP) accounts on a security key.
    ///
    /// Talks to the key over the smart-card interface (PC/SC).
    Oath {
        #[command(subcommand)]
        cmd: OathCmd,
    },
    /// Manage the OTP entries stored on a Token2 T2F2 / PIN+ FIDO key.
    ///
    /// Talks to the key over USB (HID) or the smart-card interface (CCID/NFC).
    /// List entries, print a code, add or delete entries, set the button-press
    /// HOTP keystroke slot, and read the serial number. This is the Token2 OTP
    /// applet, distinct from the Yubico/Trussed applet the `oath` group
    /// manages.
    Otp {
        /// Which transport to reach the OTP applet on. `auto` (default) tries
        /// USB-HID and falls back to CCID/NFC when HID is disabled on the key.
        #[arg(long, value_enum, default_value_t = OtpTransportArg::Auto, global = true)]
        transport: OtpTransportArg,
        #[arg(
            id = "otp_reader",
            long = "reader",
            value_name = "SUBSTR",
            global = true,
            help = READER_HELP
        )]
        reader: Option<String>,
        #[arg(
            id = "otp_path",
            long = "path",
            value_name = "PATH",
            global = true,
            help = PATH_HELP
        )]
        path: Option<std::path::PathBuf>,
        #[command(subcommand)]
        cmd: OtpCmd,
    },
    /// Manage the OpenPGP card applet: info, keys, sign, decrypt, PINs,
    /// cardholder details, and reset.
    ///
    /// Talks to the key over the smart-card interface (PC/SC).
    Openpgp {
        #[command(subcommand)]
        cmd: OpenpgpCmd,
    },
    /// Manage the PIV (smart card) applet: info, PIN/PUK, management key,
    /// keys, and certificates.
    ///
    /// Talks to the key over the smart-card interface (PC/SC).
    Piv {
        #[command(subcommand)]
        cmd: PivCmd,
    },
    /// Token2 Molto2 / Molto2v2 programmable TOTP token.
    Molto {
        #[command(flatten)]
        key: KeyArgs,
        #[arg(
            id = "molto_reader",
            long = "reader",
            value_name = "SUBSTR",
            global = true,
            help = READER_HELP
        )]
        reader: Option<String>,
        #[command(subcommand)]
        cmd: MoltoCmd,
    },
    /// Token2 2nd-generation single-profile programmable TOTP token. Uses the
    /// token's fixed device key; no customer key is needed.
    Prog {
        #[command(subcommand)]
        cmd: ProgCmd,
    },
    /// Factory-reset EVERY resettable applet on the selected key: OATH,
    /// OpenPGP, Token2 OTP, PIV, then FIDO2. Irreversible: asks for a typed
    /// confirmation (`--yes` to skip).
    ///
    /// Wipes all credentials, codes, keys, and PINs; each applet that
    /// completes comes back in factory condition, and every step reports its
    /// own outcome. On a USB key the FIDO2 step ends with an unplug/replug +
    /// touch; a card in a smart-card reader is reset in place instead (no
    /// replug, no touch).
    FactoryReset {
        #[arg(long, value_name = "SUBSTR", help = READER_HELP)]
        reader: Option<String>,
        /// Skip the typed confirmation (required when not run from a terminal).
        #[arg(long, short = 'y')]
        yes: bool,
        /// Some cards protect reset behind management auth, checked just
        /// before the PIV step. Whether that applies to the selected device
        /// is only known once it's fingerprinted: running this command
        /// without a management key (or, depending on the card, a PIN)
        /// either succeeds outright, or refuses and asks you to re-run it
        /// with --mgmt-key or --pin. This flag is the management key (hex):
        /// env:NAME reads that environment variable, stdin reads one line
        /// (hidden when typed at a terminal), default uses the
        /// factory-default management key keyroost knows for this device.
        /// Give this or --pin, whichever credential you have.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source_or_default, allow_hyphen_values = true, conflicts_with = "pin")]
        mgmt_key: Option<SecretSource>,
        /// The PIN, for a card that accepts one instead of the management
        /// key: env:NAME reads that environment variable, stdin reads one
        /// line (hidden when typed at a terminal).
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
    },
    /// Print shell completions to stdout.
    ///
    /// They call back into keyroostctl so `--device` completes saved key names
    /// (e.g. `keyroostctl completions bash >
    /// ~/.local/share/bash-completion/completions/keyroostctl`).
    Completions {
        /// Shell to print completions for.
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// Write man pages (keyroostctl.1 + keyroostctl-<group>.1) into a
    /// directory.
    ///
    /// For example: `keyroostctl manpage ./man && man -l
    /// ./man/keyroostctl-piv.1`.
    Manpage {
        /// Directory to write the .1 files into (created if missing).
        #[arg(value_name = "DIR")]
        dir: std::path::PathBuf,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum CertFormat {
    Pem,
    Der,
}

/// Encode a certificate for `piv cert export`.
fn encode_cert(der: &[u8], format: CertFormat) -> Vec<u8> {
    match format {
        CertFormat::Pem => keyroost_piv::x509::pem_certificate(der).into_bytes(),
        CertFormat::Der => der.to_vec(),
    }
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

/// Asymmetric key algorithm for `piv key generate`.
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
    #[value(name = "eccp521")]
    EccP521,
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
            CliPivKeyAlg::EccP521 => EccP521,
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

/// X.509 key usages selectable with `--key-usage`.
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum CliKeyUsage {
    /// The PIV standard's key usage extension for the slot: its usages,
    /// marked critical. Valid on its own or next to exactly those usages plus
    /// `critical`; needs a slot the standard defines a usage for.
    Default,
    /// Write no keyUsage extension. Can't be combined with other values,
    /// except `default` for a slot whose PIV default is itself undefined.
    Undefined,
    /// Mark the keyUsage extension critical. Needs at least one usage (or
    /// `default`).
    Critical,
    DigitalSignature,
    NonRepudiation,
    KeyEncipherment,
    DataEncipherment,
    KeyAgreement,
    KeyCertSign,
    CrlSign,
    EncipherOnly,
    DecipherOnly,
}

impl CliKeyUsage {
    fn bit(self) -> Option<keyroost_piv::x509::KeyUsage> {
        use keyroost_piv::x509::KeyUsage as K;
        Some(match self {
            CliKeyUsage::Default | CliKeyUsage::Undefined | CliKeyUsage::Critical => return None,
            CliKeyUsage::DigitalSignature => K::DIGITAL_SIGNATURE,
            CliKeyUsage::NonRepudiation => K::NON_REPUDIATION,
            CliKeyUsage::KeyEncipherment => K::KEY_ENCIPHERMENT,
            CliKeyUsage::DataEncipherment => K::DATA_ENCIPHERMENT,
            CliKeyUsage::KeyAgreement => K::KEY_AGREEMENT,
            CliKeyUsage::KeyCertSign => K::KEY_CERT_SIGN,
            CliKeyUsage::CrlSign => K::CRL_SIGN,
            CliKeyUsage::EncipherOnly => K::ENCIPHER_ONLY,
            CliKeyUsage::DecipherOnly => K::DECIPHER_ONLY,
        })
    }
}

#[derive(clap::Args)]
struct KeyUsageArgs {
    /// Write an X.509 keyUsage extension with these usages (comma-separated
    /// or repeated). `critical` marks the extension critical (otherwise it
    /// is not). `default` selects the PIV standard's extension for the slot
    /// (its usages, critical) and may only be combined with exactly those
    /// usages plus `critical`. `undefined` writes no extension. Without this
    /// option the slot's default is used, as with `default`.
    #[arg(
        long = "key-usage",
        value_enum,
        value_delimiter = ',',
        value_name = "USAGE"
    )]
    key_usage: Vec<CliKeyUsage>,
}

/// The explicit usages named in `args` and whether `critical` is among them.
fn explicit_key_usage(args: &[CliKeyUsage]) -> (keyroost_piv::x509::KeyUsage, bool) {
    let usages = args
        .iter()
        .filter_map(|u| u.bit())
        .fold(keyroost_piv::x509::KeyUsage::EMPTY, |a, b| a.union(b));
    (usages, args.contains(&CliKeyUsage::Critical))
}

/// Check the `--key-usage` values that need no card access: `undefined`
/// stands alone, `critical` needs a usage, `default` only accompanies exactly
/// the usages (plus `critical`) that form the default for `slot`, and the
/// explicit usages form a valid RFC 5280 combination. `alg` is the slot key's
/// algorithm if already known; a default that can't be determined yet is left
/// for [`resolve_key_usage`] to judge.
fn check_key_usage_args(
    args: &[CliKeyUsage],
    slot: keyroost_piv::Slot,
    alg: Option<keyroost_piv::KeyAlg>,
) -> Result<(), String> {
    let has = |u| args.contains(&u);
    if has(CliKeyUsage::Undefined)
        && args
            .iter()
            .any(|u| !matches!(u, CliKeyUsage::Default | CliKeyUsage::Undefined))
    {
        return Err("--key-usage undefined can't be combined with other key usages".into());
    }
    let (usages, critical) = explicit_key_usage(args);
    if critical && usages.is_empty() && !has(CliKeyUsage::Default) {
        return Err("--key-usage critical needs at least one key usage".into());
    }
    if !usages.is_empty() && !usages.is_valid() {
        return Err(
            "invalid --key-usage combination: encipher-only and decipher-only need \
             key-agreement and exclude each other"
                .into(),
        );
    }
    if has(CliKeyUsage::Default) && (!usages.is_empty() || critical) {
        if let Some(default) = keyroost_piv::x509::piv_default_key_usage(slot, alg) {
            if usages != default.usages || !critical {
                return Err(format!(
                    "--key-usage default can only be combined with exactly the usages that \
                     form the PIV default for {} (including critical)",
                    slot.label()
                ));
            }
        }
    }
    Ok(())
}

/// The slot key's algorithm if `--generate-key`/`--pubkey-in` already name
/// it, so `--key-usage` can be checked before touching the card.
fn early_key_alg(
    keygen: &InlineKeyGen,
    pubkey_in: Option<&std::path::Path>,
) -> Result<Option<keyroost_piv::KeyAlg>, Box<dyn std::error::Error>> {
    if keygen.generate_key {
        Ok(Some(keygen.algorithm.to_alg()))
    } else if let Some(path) = pubkey_in {
        Ok(Some(load_pubkey_material(path)?.0))
    } else {
        Ok(None)
    }
}

/// Resolve `--key-usage` for `slot` holding a key of algorithm `alg`.
/// `None` means no extension. Usages the key type can't back are accepted
/// with a warning on stderr.
fn resolve_key_usage(
    args: &[CliKeyUsage],
    slot: keyroost_piv::Slot,
    alg: Option<keyroost_piv::KeyAlg>,
) -> Result<Option<keyroost_piv::x509::KeyUsageExt>, String> {
    // No `--key-usage` at all means the slot's PIV default, exactly as if
    // `default` had been given (the GUI preselects the same).
    let args = if args.is_empty() {
        &[CliKeyUsage::Default][..]
    } else {
        args
    };
    check_key_usage_args(args, slot, alg)?;
    if args.contains(&CliKeyUsage::Undefined) {
        // Alone it simply means "no extension". Next to `default` it is only
        // consistent if the slot's PIV default is itself "undefined" — which
        // we can only say when the standard has no answer for reasons other
        // than a key type we don't know.
        let default_is_undefined = args.contains(&CliKeyUsage::Default)
            && keyroost_piv::x509::piv_default_key_usage(slot, alg).is_none()
            && !(matches!(
                slot,
                keyroost_piv::Slot::KeyManagement | keyroost_piv::Slot::Retired(_)
            ) && alg.is_none());
        if args.contains(&CliKeyUsage::Default) && !default_is_undefined {
            return Err(format!(
                "--key-usage undefined can't be combined with default: the PIV default for {} \
                 is not \"undefined\"",
                slot.label()
            ));
        }
        return Ok(None);
    }
    if args.contains(&CliKeyUsage::Default) {
        return match keyroost_piv::x509::piv_default_key_usage(slot, alg) {
            Some(default) => Ok(Some(default)),
            // The key type is known and can back none of the slot's default
            // usages (Ed25519 in 9D / retired): the default is "no extension".
            None if keyroost_piv::x509::piv_default_degrades_to_undefined(slot, alg) => {
                output::warn(&format!(
                    "the slot default key usage for {} is undefined: {} keys \
                     can't back the usages the PIV standard defines there; no keyUsage \
                     extension will be added.",
                    slot.label(),
                    alg.map_or("these", |a| a.label())
                ));
                Ok(None)
            }
            None => Err(format!(
                "no PIV-defined key usage for {} (with this key type); name the usages \
                 explicitly instead of `default`",
                slot.label()
            )),
        };
    }
    let (usages, critical) = explicit_key_usage(args);
    if let Some(alg) = alg {
        if !keyroost_piv::x509::supported_key_usages(alg).contains(usages) {
            output::warn(&format!(
                "some requested key usages are incompatible with {} keys; \
                 a CA or verifier may reject the certificate.",
                alg.label()
            ));
        }
    }
    Ok(Some(keyroost_piv::x509::KeyUsageExt { usages, critical }))
}

/// Whether `piv cert import` / `piv cert generate` store the certificate
/// compressed. Neither flag: compress only if the card refuses the
/// certificate as too large.
#[derive(clap::Args)]
struct CertCompressArgs {
    /// Store the certificate compressed (the PIV standard's gzip form), even
    /// if it would fit uncompressed. Some software may not read compressed
    /// certificates. Without --compress or --no-compress, the certificate is
    /// compressed only if the card refuses it as too large.
    #[arg(long, conflicts_with = "no_compress")]
    compress: bool,
    /// Never store the certificate compressed (the PIV standard's gzip
    /// form), which some software may not read; a certificate the card
    /// refuses as too large then fails instead.
    #[arg(long)]
    no_compress: bool,
}

impl CertCompressArgs {
    fn choice(&self) -> keyroost_transport::CertCompression {
        use keyroost_transport::CertCompression;
        if self.compress {
            CertCompression::Always
        } else if self.no_compress {
            CertCompression::Never
        } else {
            CertCompression::Auto
        }
    }
}

/// Help for every `--overwrite` flag (one per command that writes a file).
const OVERWRITE_HELP: &str =
    "Replace an output file that already exists (otherwise asked at a terminal, refused in a script)";

/// Printed after a certificate the default (automatic) choice had to store
/// compressed. The GUI shows the same note.
const AUTO_COMPRESSED_NOTE: &str = "the certificate did not fit on the card \
    uncompressed, so it was stored compressed (the PIV standard's gzip form). Most PIV \
    software reads compressed certificates, including Windows' built-in smart-card \
    driver in a community test; macOS's built-in PIV support has not been verified.";

/// The success line's addition for a compressed certificate: how many bytes
/// the card holds. Empty for an uncompressed one.
fn stored_compressed_suffix(compressed: bool, stored_len: usize) -> String {
    if compressed {
        format!(" (stored compressed: {stored_len} bytes on the card)")
    } else {
        String::new()
    }
}

/// A certificate import's error for the user: with `--no-compress`, a card
/// that refused the certificate as too large also gets the flags that would
/// let it be stored compressed. Every other error passes through.
fn cert_import_error(
    e: keyroost_transport::TransportError,
    choice: keyroost_transport::CertCompression,
) -> Box<dyn std::error::Error> {
    use keyroost_transport::{CertCompression, TransportError};
    match e {
        TransportError::PivCertTooLarge {
            compressed_len: None,
            ..
        } if choice == CertCompression::Never => {
            format!("{e} (leave out --no-compress, or pass --compress)").into()
        }
        e => e.into(),
    }
}

/// Print the success line of a certificate import plus, when the automatic
/// choice compressed it, why.
fn print_cert_stored(line: &str, stored: &keyroost_transport::CertImport) {
    println!(
        "{line}{}.",
        stored_compressed_suffix(stored.compressed, stored.stored_len)
    );
    if stored.auto_compressed {
        output::note(AUTO_COMPRESSED_NOTE);
    }
}

/// The optional `--generate-key` convenience shared by `piv cert request` and
/// `piv cert generate`. Flattened into both: it folds a fresh `piv key generate`
/// into the signing command so that on a card without GET METADATA (firmware
/// older than 5.3, or non-Yubico PIV) you don't have to shuttle the public key
/// through a temporary file (`piv key generate --out` then this command's
/// `--pubkey-in`). Every option mirrors `piv key generate` and is inert
/// unless `--generate-key` is passed.
#[derive(clap::Args)]
struct InlineKeyGen {
    /// Generate a fresh key pair in the slot on the card first, then sign
    /// against it. This replaces any key already in the slot (asks first when
    /// there is one). Convenience only: it does exactly what running `piv
    /// key generate` beforehand would, but keeps the freshly generated public
    /// key in this same session so no temporary key-material file is needed.
    /// Omit it to keep the normal behavior — sign the key already in the slot,
    /// named via GET METADATA or `--pubkey-in`. With it, `--pubkey-in`
    /// (and any prior `piv key generate --out`) is unnecessary, which is
    /// the whole point on cards that don't support GET METADATA. Needs the
    /// management key.
    #[arg(long, conflicts_with = "pubkey_in")]
    generate_key: bool,
    /// With `--generate-key`: algorithm of the new key pair.
    #[arg(long, value_enum, default_value = "eccp256", requires = "generate_key")]
    algorithm: CliPivKeyAlg,
    /// With `--generate-key`: when the new key's private key may be used.
    /// `default` sends the standard PIV command every card accepts; the other
    /// values are a Yubico extension (firmware-dependent).
    #[arg(long, value_enum, default_value = "default", requires = "generate_key")]
    pin_policy: CliPinPolicy,
    /// With `--generate-key`: whether using the new key requires a physical
    /// touch. Same caveat: only `default` is standard PIV, the rest are a
    /// Yubico extension (firmware-dependent).
    #[arg(long, value_enum, default_value = "default", requires = "generate_key")]
    touch_policy: CliTouchPolicy,
    /// With `--generate-key`: also write the generated public key (PEM) to
    /// FILE. Not needed for the signature itself — the key is used from this
    /// session — just a spare copy to keep or hand to other tools.
    #[arg(long, value_name = "FILE", requires = "generate_key")]
    pubkey_out: Option<std::path::PathBuf>,
}

/// Subcommands for the PIV smart-card applet. Secret material (PINs, PUK,
/// management key) is read from env/stdin, never argv. The management key is a
/// hex string (48 hex chars for AES-192 / 3DES, 32 for AES-128, 64 for AES-256).
#[derive(Subcommand)]
enum PivCmd {
    /// Show PIV status: version, serial, PIN retries, and which key slots hold a
    /// certificate. No PIN or touch required.
    Info {
        #[arg(long, value_name = "SUBSTR", help = READER_HELP)]
        reader: Option<String>,
    },
    /// Change the PIV PIN, or unblock it with the PUK.
    Pin {
        #[command(subcommand)]
        cmd: PivPinCmd,
    },
    /// Change the PUK (the code that unblocks the PIN).
    Puk {
        #[command(subcommand)]
        cmd: PivPukCmd,
    },
    /// Set how many wrong PIN and PUK entries are allowed.
    Retries {
        #[command(subcommand)]
        cmd: PivRetriesCmd,
    },
    /// Change the management key (mgmt-key: the key that authorizes changes to keys and certificates).
    MgmtKey {
        #[command(subcommand)]
        cmd: PivMgmtKeyCmd,
    },
    /// Generate, delete or move the private keys in PIV slots.
    Key {
        #[command(subcommand)]
        cmd: PivKeyCmd,
    },
    /// Import, export, delete, request or generate the certificates in PIV slots.
    Cert {
        #[command(subcommand)]
        cmd: PivCertCmd,
    },
    /// Write a new CHUID (Card Holder Unique Identifier, the card's identity record).
    Chuid {
        #[command(subcommand)]
        cmd: PivChuidCmd,
    },
    /// Test a slot's private key end to end against the slot certificate's
    /// public key. Read-only — nothing on the card changes.
    ///
    /// For every operation the key's algorithm supports (decrypt for RSA,
    /// key-agree for ECDH curves, sign for RSA / ECDSA / Ed25519), run a fixed
    /// challenge on the card and verify the result against the slot
    /// certificate's public key. Reports each operation's pass / fail /
    /// skipped. `--pin` is always optional: it's your
    /// call whether to test with or without a PIN. Depending on device state
    /// and PIN policy, omitting it may fail.
    Test {
        #[arg(long, value_name = "SUBSTR", help = READER_HELP)]
        reader: Option<String>,
        /// PIV key slot: 9a authentication, 9c signature, 9d key management, 9e
        /// card authentication, 82-95 retired key management.
        #[arg(long, short = 's', value_enum)]
        slot: CliPivSlot,
        /// The PIN: env:NAME reads that environment variable, stdin reads one
        /// line (hidden when typed at a terminal). Optional and never asked
        /// for; omit it to test without a PIN.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
    },
    /// Reset the PIV application to factory defaults: wipe all keys,
    /// certificates and PINs. Irreversible: asks first (`--yes` to skip).
    ///
    /// This typically requires both the PIN and PUK to already be
    /// blocked; keyroost arranges that itself where its list says the key
    /// supports RESET. A key with no entry gets a warning and a single bare
    /// RESET with nothing blocked; if it needs the PIN and PUK blocked first,
    /// block them yourself and run it again.
    ///
    /// Resetting the PIV applet is an extension to standard PIV (YubiKey and
    /// other keys that implement it). If keyroost's list marks this key as
    /// not supporting it, the command stops unless `--force`, which sends a
    /// single bare RESET.
    ///
    /// Some cards protect reset behind management auth instead of the
    /// PIN/PUK convention above. Whether that applies to the selected device
    /// is only known once it's fingerprinted: running this command without a
    /// management key (or, depending on the card, a PIN) either succeeds
    /// outright, or refuses and asks you to re-run it with --mgmt-key
    /// env:NAME, stdin or default, or --pin env:NAME or stdin.
    Reset {
        #[arg(long, value_name = "SUBSTR", help = READER_HELP)]
        reader: Option<String>,
        /// Confirm without asking (required when not run from a terminal).
        #[arg(long, short = 'y')]
        yes: bool,
        /// Run even on a device listed as incompatible. There it sends one bare
        /// RESET without blocking the PIN or PUK; if the card can't reset, it
        /// refuses.
        #[arg(long)]
        force: bool,
        /// The management key (hex), only used when the selected device
        /// turns out to need one: env:NAME reads that environment variable,
        /// stdin reads one line (hidden when typed at a terminal), default
        /// uses the factory-default management key keyroost knows for this
        /// device. Give this or --pin, whichever credential you have.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source_or_default, allow_hyphen_values = true, conflicts_with = "pin")]
        mgmt_key: Option<SecretSource>,
        /// The PIN, for a card that accepts one instead of the management
        /// key: env:NAME reads that environment variable, stdin reads one
        /// line (hidden when typed at a terminal).
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
    },
}

/// `piv pin` subcommands.
#[derive(Subcommand)]
enum PivPinCmd {
    /// Change the PIV PIN. Each PIN comes from an environment variable,
    /// stdin (the current PIN on the first line, the new one on the second)
    /// or, with neither, a hidden prompt.
    Change {
        #[arg(long, value_name = "SUBSTR", help = READER_HELP)]
        reader: Option<String>,
        /// The current PIN: env:NAME reads that environment variable, stdin
        /// reads one line (first line; hidden when typed at a terminal). With
        /// neither, a terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        /// The new PIN: env:NAME reads that environment variable, stdin reads
        /// one line (second line when --pin stdin is also given; hidden when
        /// typed at a terminal). With neither, a terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        new_pin: Option<SecretSource>,
    },
    /// Unblock a blocked PIN using the PUK, setting a new PIN.
    Unblock {
        #[arg(long, value_name = "SUBSTR", help = READER_HELP)]
        reader: Option<String>,
        /// The PUK: env:NAME reads that environment variable, stdin reads one
        /// line (first line; hidden when typed at a terminal). With neither, a
        /// terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        puk: Option<SecretSource>,
        /// The new PIN: env:NAME reads that environment variable, stdin reads
        /// one line (second line when --puk stdin is also given; hidden when
        /// typed at a terminal). With neither, a terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        new_pin: Option<SecretSource>,
    },
}

/// `piv puk` subcommands.
#[derive(Subcommand)]
enum PivPukCmd {
    /// Change the PUK (PIN Unblocking Key). Each PUK comes from an
    /// environment variable, stdin (the current PUK on the first line, the
    /// new one on the second) or, with neither, a hidden prompt.
    Change {
        #[arg(long, value_name = "SUBSTR", help = READER_HELP)]
        reader: Option<String>,
        /// The current PUK: env:NAME reads that environment variable, stdin
        /// reads one line (first line; hidden when typed at a terminal). With
        /// neither, a terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        puk: Option<SecretSource>,
        /// The new PUK: env:NAME reads that environment variable, stdin reads
        /// one line (second line when --puk stdin is also given; hidden when
        /// typed at a terminal). With neither, a terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        new_puk: Option<SecretSource>,
    },
}

/// `piv retries` subcommands.
#[derive(Subcommand)]
enum PivRetriesCmd {
    /// Set how many wrong PIN and PUK entries are allowed. Irreversible: asks first (`--yes` to skip).
    ///
    /// Also resets the PIN and PUK to their factory defaults (a Yubico
    /// extension to PIV). Needs the PIN and the management key.
    Set {
        #[arg(long, value_name = "SUBSTR", help = READER_HELP)]
        reader: Option<String>,
        /// PIN retry count, at least 1: a zero count would leave the PIN
        /// permanently blocked.
        #[arg(long, value_name = "N", value_parser = clap::value_parser!(u8).range(1..))]
        pin_tries: u8,
        /// PUK retry count, at least 1: a zero count would leave the PUK
        /// permanently blocked.
        #[arg(long, value_name = "N", value_parser = clap::value_parser!(u8).range(1..))]
        puk_tries: u8,
        /// The management key (hex): env:NAME reads that environment variable,
        /// stdin reads one line (second line when --pin stdin is also given;
        /// hidden when typed at a terminal), default uses the factory-default
        /// management key keyroost knows for this device. With none of these, a
        /// terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source_or_default, allow_hyphen_values = true)]
        mgmt_key: Option<SecretSource>,
        /// The PIN: env:NAME reads that environment variable, stdin reads one
        /// line (first line; hidden when typed at a terminal). With neither, a
        /// terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        /// Confirm without asking (required when not run from a terminal).
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

/// `piv mgmt-key` subcommands.
#[derive(Subcommand)]
enum PivMgmtKeyCmd {
    /// Change the card-management (9B) key. Both keys are hex; from stdin,
    /// the current key comes on the first line and the new one on the
    /// second.
    ///
    /// Changing the management key is an extension to standard PIV (YubiKey
    /// and other keys that implement it).
    /// If keyroost's list marks this key as not supporting it, the command
    /// stops unless `--force`; a key with no entry gets a warning.
    ///
    /// On every device except HID Crescendo (which unlocks management
    /// directly off the PIN, with no key material to store), this also
    /// maintains Yubico's PIN-protected management-key storage, enabling it
    /// with `--allow-pin-unlock` or disabling it without. The same list
    /// applies: a key with no entry gets a warning. If the list marks
    /// this key as not supporting it, `--allow-pin-unlock` stops unless
    /// `--force`, and without it the step is skipped, so a plain key rotation
    /// isn't blocked.
    Change {
        // Explicit `display_order` on every field here (10.. up, one per
        // field, matching declaration order): clap-derive's implicit order
        // is an auto-incrementing counter that starts fresh at 0 in *each*
        // derive invocation, including the top-level `Cli` struct's own
        // `global = true` args (`--debug`/`--device`/`--json`, implicitly
        // 0..2). Left implicit, this variant's own
        // fields also start at 0, so `--help` interleaved the two structs'
        // args by tied order number instead of keeping this command's own
        // args — the `--old-mgmt-key-*` trio in particular — together.
        #[arg(long, value_name = "SUBSTR", display_order = 10, help = READER_HELP)]
        reader: Option<String>,
        /// The current management key (hex): env:NAME reads that environment
        /// variable, stdin reads one line (first line; hidden when typed at a
        /// terminal), default uses the factory-default management key keyroost
        /// knows for this device. With none of these, a terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source_or_default, allow_hyphen_values = true, display_order = 11)]
        mgmt_key: Option<SecretSource>,
        /// The new management key (hex): env:NAME reads that environment
        /// variable, stdin reads one line (second line when --mgmt-key stdin is
        /// also given; hidden when typed at a terminal). With neither, a
        /// terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true, display_order = 14)]
        new_mgmt_key: Option<SecretSource>,
        /// Algorithm of the new management key.
        #[arg(long, value_enum, default_value = "aes192", display_order = 16)]
        algorithm: CliPivMgmtAlg,
        /// Require a physical touch for every future management-key auth.
        #[arg(long, display_order = 17)]
        touch: bool,
        /// Store the new management key PIN-protected, so it can later be
        /// unlocked with the PIN alone instead of the raw key. Omit to
        /// instead clear any existing PIN-protected storage of the old key —
        /// except on a device confirmed unable to support this at all, where
        /// omitting it is a no-op rather than an attempted clear. Ignored on
        /// HID Crescendo, which already unlocks management off the PIN with
        /// no key material of its own to store.
        #[arg(long, display_order = 18)]
        allow_pin_unlock: bool,
        /// Run even if keyroost's list marks this key as not supporting it.
        #[arg(long, display_order = 19)]
        force: bool,
    },
}

/// `piv key` subcommands.
#[derive(Subcommand)]
enum PivKeyCmd {
    /// Generate a new key pair in a slot, replacing any key already there, and
    /// print its public key (PEM). Irreversible: asks first (`--yes` to skip).
    ///
    /// Needs the management key. Asks only when the slot isn't known to be
    /// empty.
    Generate {
        #[arg(long, value_name = "SUBSTR", help = READER_HELP)]
        reader: Option<String>,
        /// PIV key slot: 9a authentication, 9c signature, 9d key management, 9e
        /// card authentication, 82-95 retired key management.
        #[arg(long, short = 's', value_enum)]
        slot: CliPivSlot,
        /// Key type to generate (OpenPGP's `nistp256` is `eccp256` here).
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
        /// The management key (hex): env:NAME reads that environment variable,
        /// stdin reads one line (hidden when typed at a terminal), default uses
        /// the factory-default management key keyroost knows for this device.
        /// With none of these, a terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source_or_default, allow_hyphen_values = true)]
        mgmt_key: Option<SecretSource>,
        /// Write the new public key (PEM) to FILE.
        ///
        /// Needed to `piv cert request`/`piv cert generate` this same key from
        /// a *later*, separate `keyroostctl` invocation on cards that don't
        /// support GET METADATA (firmware older than 5.3, or non-Yubico PIV):
        /// such a card has no way to name a key this fresh on its own — there's
        /// no certificate yet either — so nothing here is cached automatically;
        /// pass the same path to that later command's `--pubkey-in`. To skip
        /// the temporary file altogether, use `--generate-key` on `piv cert
        /// request`/`piv cert generate`, which folds this key generation into
        /// the signing command.
        #[arg(long, short = 'o', value_name = "FILE")]
        out: Option<std::path::PathBuf>,
        #[arg(long, help = OVERWRITE_HELP)]
        overwrite: bool,
        /// Run even if keyroost's list marks this key as not supporting the
        /// chosen key type, PIN policy or touch policy.
        #[arg(long)]
        force: bool,
        /// Confirm without asking (required when not run from a terminal).
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Delete a slot's private key; the slot's certificate is left in place.
    /// Needs the management key. Irreversible: asks first (`--yes` to skip).
    ///
    /// Permanently erases the key material. Deleting a key is an extension to
    /// standard PIV (YubiKey 5.7+ and other keys that implement it). If
    /// keyroost's list marks this key as not supporting it, the command
    /// stops unless `--force`; a key with no entry gets a warning.
    Delete {
        #[arg(long, value_name = "SUBSTR", help = READER_HELP)]
        reader: Option<String>,
        /// PIV key slot: 9a authentication, 9c signature, 9d key management, 9e
        /// card authentication, 82-95 retired key management.
        #[arg(long, short = 's', value_enum)]
        slot: CliPivSlot,
        /// The management key (hex): env:NAME reads that environment variable,
        /// stdin reads one line (hidden when typed at a terminal), default uses
        /// the factory-default management key keyroost knows for this device.
        /// With none of these, a terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source_or_default, allow_hyphen_values = true)]
        mgmt_key: Option<SecretSource>,
        /// Confirm without asking (required when not run from a terminal).
        #[arg(long, short = 'y')]
        yes: bool,
        /// Run even if keyroost's list marks this key as not supporting it.
        #[arg(long)]
        force: bool,
    },
    /// Move a slot's private key to another slot, without it leaving the card.
    ///
    /// Refuses when the card reports that the destination slot already
    /// holds a key (delete it first or pick an empty slot). When keyroost
    /// can't tell, it says so and sends the move; the card decides. Only the
    /// key moves; the certificate stays in the source slot. Needs the
    /// management key.
    ///
    /// Moving keys between slots is an extension to standard PIV (YubiKey
    /// 5.7+ and other keys that implement it). If keyroost's list marks this
    /// key as not supporting it, the command stops unless `--force`; a key
    /// with no entry gets a warning.
    Move {
        /// Source slot (9a/9c/9d/9e/82–95).
        #[arg(long)]
        from: CliPivSlot,
        /// Destination slot.
        #[arg(long)]
        to: CliPivSlot,
        #[arg(long, value_name = "SUBSTR", help = READER_HELP)]
        reader: Option<String>,
        /// The management key (hex): env:NAME reads that environment variable,
        /// stdin reads one line (hidden when typed at a terminal), default uses
        /// the factory-default management key keyroost knows for this device.
        /// With none of these, a terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source_or_default, allow_hyphen_values = true)]
        mgmt_key: Option<SecretSource>,
        /// Run even if keyroost's list marks this key as not supporting it.
        #[arg(long)]
        force: bool,
    },
}

/// `piv cert` subcommands.
#[derive(Subcommand)]
enum PivCertCmd {
    /// Import a DER or PEM X.509 certificate into a slot, replacing any
    /// certificate already there. Irreversible: asks first (`--yes` to skip).
    ///
    /// Needs the management key. Asks only when the slot isn't known to be
    /// empty.
    ///
    /// No `--pubkey-in` here, unlike `cert request`/`cert generate`: those
    /// commands need the key material to build their actual output (a CSR, a
    /// self-signed certificate), so it's load-bearing there. This command's
    /// key-match check is only an extra, best-effort safety net — without an
    /// independently confirmed key to compare against, there's no way to
    /// judge whether the certificate is "correct" anyway, so it simply
    /// trusts the certificate's own declared public key and imports it, same
    /// as it did before that check existed. A `--pubkey-in` flag here would
    /// only feed that same unverifiable trust back into the comparison.
    Import {
        #[arg(long, value_name = "SUBSTR", help = READER_HELP)]
        reader: Option<String>,
        /// PIV key slot: 9a authentication, 9c signature, 9d key management, 9e
        /// card authentication, 82-95 retired key management.
        #[arg(long, short = 's', value_enum)]
        slot: CliPivSlot,
        /// Certificate file to import (`.der` or `.pem`).
        #[arg(long = "in", short = 'i', value_name = "FILE")]
        in_file: std::path::PathBuf,
        /// The management key (hex): env:NAME reads that environment variable,
        /// stdin reads one line (hidden when typed at a terminal), default uses
        /// the factory-default management key keyroost knows for this device.
        /// With none of these, a terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source_or_default, allow_hyphen_values = true)]
        mgmt_key: Option<SecretSource>,
        #[command(flatten)]
        compression: CertCompressArgs,
        /// Confirm without asking (required when not run from a terminal).
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Export a slot's certificate as PEM (default) or DER, to a file or stdout. No PIN required.
    Export {
        #[arg(long, value_name = "SUBSTR", help = READER_HELP)]
        reader: Option<String>,
        /// PIV key slot: 9a authentication, 9c signature, 9d key management, 9e
        /// card authentication, 82-95 retired key management.
        #[arg(long, short = 's', value_enum)]
        slot: CliPivSlot,
        /// Write the certificate to this file instead of stdout.
        #[arg(long, short = 'o', value_name = "FILE")]
        out: Option<std::path::PathBuf>,
        #[arg(long, help = OVERWRITE_HELP)]
        overwrite: bool,
        /// Output encoding: PEM text (default) or raw DER.
        #[arg(long, value_enum, default_value_t = CertFormat::Pem)]
        format: CertFormat,
    },
    /// Create a PKCS#10 certificate signing request for the key in a slot,
    /// signed on the card (PEM to stdout or --out). Hand the result to a CA;
    /// import the certificate it issues with `piv cert import`.
    Request {
        #[arg(long, value_name = "SUBSTR", help = READER_HELP)]
        reader: Option<String>,
        /// PIV key slot: 9a authentication, 9c signature, 9d key management, 9e
        /// card authentication, 82-95 retired key management.
        #[arg(long, short = 's', value_enum)]
        slot: CliPivSlot,
        /// Subject distinguished name, e.g. "CN=Alice,O=Example,C=US"
        /// (supported attributes: CN, O, OU, C, L, ST).
        #[arg(long, value_name = "DN")]
        subject: String,
        /// The PIN: env:NAME reads that environment variable, stdin reads one
        /// line (first line, the only one without --generate-key; hidden when
        /// typed at a terminal). With neither, a terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        /// Write the request (PEM) to this file instead of stdout.
        #[arg(long, short = 'o', value_name = "FILE")]
        out: Option<std::path::PathBuf>,
        #[arg(long, help = OVERWRITE_HELP)]
        overwrite: bool,
        /// The slot's public key (PEM or DER), as written by a prior `piv key
        /// generate --out FILE`. Needed on cards that don't support GET
        /// METADATA (firmware older than 5.3, or non-Yubico PIV) when the key
        /// was generated by a different `keyroostctl` invocation — such a card
        /// has no other way to name the slot's key material. `--generate-key`
        /// sidesteps this entirely.
        #[arg(long, value_name = "FILE")]
        pubkey_in: Option<std::path::PathBuf>,
        /// The management key (hex): env:NAME reads that environment variable,
        /// stdin reads one line (second line when --pin stdin is also given;
        /// hidden when typed at a terminal), default uses the factory-default
        /// management key keyroost knows for this device. Needed only with
        /// --generate-key, for the key-generation step (the request itself
        /// needs just the PIN); then, with none of these, a terminal asks for
        /// it.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source_or_default, allow_hyphen_values = true, requires = "generate_key")]
        mgmt_key: Option<SecretSource>,
        #[command(flatten)]
        keygen: InlineKeyGen,
        #[command(flatten)]
        key_usage: KeyUsageArgs,
        /// Confirm without asking (required when not run from a terminal).
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Create a self-signed certificate for the key in a slot and store it
    /// there, replacing any certificate already there. Irreversible: asks first
    /// (`--yes` to skip).
    ///
    /// The certificate is signed on the card, so the slot then works in
    /// PIV-aware software without an external CA. With `--generate-key` the
    /// slot's key is replaced too. Asks only when the slot isn't known to be
    /// empty.
    Generate {
        #[arg(long, value_name = "SUBSTR", help = READER_HELP)]
        reader: Option<String>,
        /// PIV key slot: 9a authentication, 9c signature, 9d key management, 9e
        /// card authentication, 82-95 retired key management.
        #[arg(long, short = 's', value_enum)]
        slot: CliPivSlot,
        /// Subject distinguished name, e.g. "CN=Alice,O=Example,C=US"
        /// (supported attributes: CN, O, OU, C, L, ST).
        #[arg(long, value_name = "DN")]
        subject: String,
        /// Validity period in whole calendar years from now, applied before
        /// `--months`/`--days` — the same month and day as today, that many
        /// years later (a Feb 29 clamps to Feb 28 in a target year that
        /// isn't a leap year).
        #[arg(long, value_name = "N", value_parser = parse_valid_years)]
        years: Option<u32>,
        /// Validity period in whole calendar months, added on top of
        /// `--years` (if given) before `--days` — the same day of month as
        /// that point, that many months later (e.g. Jan 31 + 1 month clamps
        /// to Feb 28/29, the month's last day).
        #[arg(long, value_name = "N", value_parser = parse_valid_months)]
        months: Option<u32>,
        /// Validity period in days, starting now. Combines with `--years`/
        /// `--months` (e.g. `--years 1 --days 5` is 1 year and 5 additional
        /// days from now); defaults to 1 year if none of the three is given.
        #[arg(long, value_name = "N", value_parser = parse_valid_days)]
        days: Option<u32>,
        /// The PIN: env:NAME reads that environment variable, stdin reads one
        /// line (first line; hidden when typed at a terminal). With neither, a
        /// terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        /// The management key (hex): env:NAME reads that environment variable,
        /// stdin reads one line (second line when --pin stdin is also given;
        /// hidden when typed at a terminal), default uses the factory-default
        /// management key keyroost knows for this device. With none of these, a
        /// terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source_or_default, allow_hyphen_values = true)]
        mgmt_key: Option<SecretSource>,
        /// Also write the certificate (PEM) to this file.
        #[arg(long, short = 'o', value_name = "FILE")]
        out: Option<std::path::PathBuf>,
        #[arg(long, help = OVERWRITE_HELP)]
        overwrite: bool,
        /// The slot's public key (PEM or DER), as written by a prior `piv key
        /// generate --out FILE`. Needed on cards that don't support GET
        /// METADATA (firmware older than 5.3, or non-Yubico PIV) when the key
        /// was generated by a different `keyroostctl` invocation — such a card
        /// has no other way to name the slot's key material. `--generate-key`
        /// sidesteps this entirely.
        #[arg(long, value_name = "FILE")]
        pubkey_in: Option<std::path::PathBuf>,
        #[command(flatten)]
        keygen: InlineKeyGen,
        #[command(flatten)]
        compression: CertCompressArgs,
        #[command(flatten)]
        key_usage: KeyUsageArgs,
        /// Confirm without asking (required when not run from a terminal).
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Delete a slot's certificate; the slot's private key is left in place.
    /// Needs the management key. Irreversible: asks first (`--yes` to skip).
    ///
    /// Clears ONLY the X.509 certificate object (standard PIV; works on every
    /// card).
    Delete {
        #[arg(long, value_name = "SUBSTR", help = READER_HELP)]
        reader: Option<String>,
        /// PIV key slot: 9a authentication, 9c signature, 9d key management, 9e
        /// card authentication, 82-95 retired key management.
        #[arg(long, short = 's', value_enum)]
        slot: CliPivSlot,
        /// The management key (hex): env:NAME reads that environment variable,
        /// stdin reads one line (hidden when typed at a terminal), default uses
        /// the factory-default management key keyroost knows for this device.
        /// With none of these, a terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source_or_default, allow_hyphen_values = true)]
        mgmt_key: Option<SecretSource>,
        /// Confirm without asking (required when not run from a terminal).
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

/// `piv chuid` subcommands.
#[derive(Subcommand)]
enum PivChuidCmd {
    /// Write a fresh, randomly-generated CHUID (Card Holder Unique
    /// Identifier). Needs the management key.
    ///
    /// Windows' PIV minidriver caches
    /// a card's contents by its CHUID's GUID, so after writing a new
    /// certificate or key it may keep showing stale data until the GUID
    /// changes — this forces that.
    Generate {
        #[arg(long, value_name = "SUBSTR", help = READER_HELP)]
        reader: Option<String>,
        /// The management key (hex): env:NAME reads that environment variable,
        /// stdin reads one line (hidden when typed at a terminal), default uses
        /// the factory-default management key keyroost knows for this device.
        /// With none of these, a terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source_or_default, allow_hyphen_values = true)]
        mgmt_key: Option<SecretSource>,
        /// CHUID expiration, in whole calendar years from now, applied
        /// before `--months`/`--days` — the same month and day as today,
        /// that many years later (a Feb 29 clamps to Feb 28 in a target
        /// year that isn't a leap year). Informational only.
        #[arg(long, value_name = "N", value_parser = parse_valid_years)]
        years: Option<u32>,
        /// CHUID expiration, in whole calendar months, added on top of
        /// `--years` (if given) before `--days` — the same day of month as
        /// that point, that many months later (e.g. Jan 31 + 1 month clamps
        /// to Feb 28/29, the month's last day). Informational only.
        #[arg(long, value_name = "N", value_parser = parse_valid_months)]
        months: Option<u32>,
        /// CHUID expiration, in days from now. Informational only — it has no
        /// technical implications. Combines with `--years`/`--months` (e.g.
        /// `--years 1 --days 5` is 1 year and 5 additional days from now);
        /// same default as `piv cert generate`'s certificate validity.
        #[arg(long, value_name = "N", value_parser = parse_valid_days)]
        days: Option<u32>,
        /// GUID, hex (dashes optional). Omit to use random GUID.
        #[arg(long, value_name = "HEX", value_parser = parse_guid_arg)]
        guid: Option<String>,
    },
}

/// Subcommands for the OpenPGP card applet.
#[derive(Subcommand)]
enum OpenpgpCmd {
    /// Show card status: AID/serial, key algorithms and fingerprints, PIN retry
    /// counters, and the signature counter. No PIN or touch required.
    Info {
        #[arg(long, value_name = "SUBSTR", help = READER_HELP)]
        reader: Option<String>,
    },
    /// Check, change or unblock the user PIN (PW1) or the admin PIN (PW3).
    Pin {
        #[command(subcommand)]
        cmd: OpenpgpPinCmd,
    },
    /// Generate, import or show the card's keys, and list the algorithms it supports.
    Key {
        #[command(subcommand)]
        cmd: OpenpgpKeyCmd,
    },
    /// Set the cardholder name stored on the card.
    Name {
        #[command(subcommand)]
        cmd: OpenpgpNameCmd,
    },
    /// Set the public-key URL stored on the card.
    Url {
        #[command(subcommand)]
        cmd: OpenpgpUrlCmd,
    },
    /// Sign a file with the key in the signature slot.
    ///
    /// Runs PSO:CDS. Hashes the input (SHA-256 by default, or SHA-1 via
    /// `--hash`). RSA slots sign a PKCS#1 DigestInfo; ECC slots sign the bare
    /// digest. Needs the signing PIN (PW1) and, on a YubiKey, a touch. The
    /// output is the card's raw signature: PKCS#1 for RSA, `r||s` (not DER)
    /// for ECDSA, `R||S` for Ed25519.
    Sign {
        /// File whose contents to sign.
        #[arg(long, short = 'i', value_name = "FILE")]
        r#in: std::path::PathBuf,
        /// Write the raw signature bytes here. Without it, the signature is
        /// printed as hex to stdout.
        #[arg(long, short = 'o', value_name = "FILE")]
        out: Option<std::path::PathBuf>,
        #[arg(long, help = OVERWRITE_HELP)]
        overwrite: bool,
        /// The signing PIN (PW1): env:NAME reads that environment variable,
        /// stdin reads one line (hidden when typed at a terminal). With
        /// neither, a terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        /// Digest algorithm for the PKCS#1 v1.5 DigestInfo. SHA-256 is the
        /// modern default; SHA-1 is offered for interop with old verifiers.
        #[arg(long, value_enum, default_value_t = SignHash::Sha256)]
        hash: SignHash,
        #[arg(long, value_name = "SUBSTR", help = READER_HELP)]
        reader: Option<String>,
    },
    /// Decrypt a file with the key in the decryption slot.
    ///
    /// Runs PSO:DECIPHER. Needs the user PIN (PW1) and, on a YubiKey, a
    /// touch.
    Decrypt {
        /// For an RSA slot `--in` is the raw cryptogram; for an ECDH slot it is
        /// the sender's ephemeral public point (`04||X||Y`, or 32 raw bytes for
        /// X25519) and the output is the shared secret.
        #[arg(long, short = 'i', value_name = "FILE")]
        r#in: std::path::PathBuf,
        /// Write the recovered plaintext (or, for ECDH, the shared secret)
        /// here. Without it, the bytes are printed as hex to stdout.
        #[arg(long, short = 'o', value_name = "FILE")]
        out: Option<std::path::PathBuf>,
        #[arg(long, help = OVERWRITE_HELP)]
        overwrite: bool,
        /// The user PIN (PW1): env:NAME reads that environment variable, stdin
        /// reads one line (hidden when typed at a terminal). With neither, a
        /// terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        #[arg(long, value_name = "SUBSTR", help = READER_HELP)]
        reader: Option<String>,
    },
    /// Sign a challenge with the key in the authentication slot (client or SSH
    /// login).
    ///
    /// Runs INTERNAL AUTHENTICATE. Hashes the input (SHA-256 by default, or
    /// SHA-1 via `--hash`). RSA slots sign a PKCS#1 DigestInfo; ECC slots sign
    /// the bare digest. Needs the user PIN (PW1) and, on a YubiKey, a touch.
    /// The output is the card's raw signature: PKCS#1 for RSA, `r||s` (not
    /// DER) for ECDSA, `R||S` for Ed25519.
    Authenticate {
        /// File whose contents to authenticate-sign.
        #[arg(long, short = 'i', value_name = "FILE")]
        r#in: std::path::PathBuf,
        /// Write the raw signature bytes here. Without it, the signature is
        /// printed as hex to stdout.
        #[arg(long, short = 'o', value_name = "FILE")]
        out: Option<std::path::PathBuf>,
        #[arg(long, help = OVERWRITE_HELP)]
        overwrite: bool,
        /// The user PIN (PW1): env:NAME reads that environment variable, stdin
        /// reads one line (hidden when typed at a terminal). With neither, a
        /// terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        /// Digest algorithm for the PKCS#1 v1.5 DigestInfo. SHA-256 is the
        /// modern default; SHA-1 is offered for interop with old verifiers.
        #[arg(long, value_enum, default_value_t = SignHash::Sha256)]
        hash: SignHash,
        #[arg(long, value_name = "SUBSTR", help = READER_HELP)]
        reader: Option<String>,
    },
    /// Factory-reset the OpenPGP applet: wipe ALL key slots and restore default
    /// PINs (PW1 123456, PW3 12345678). Irreversible: asks first (`--yes` to
    /// skip).
    ///
    /// Also works to recover a card whose PINs are blocked.
    Reset {
        /// Confirm without asking (required when not run from a terminal).
        #[arg(long, short = 'y')]
        yes: bool,
        #[arg(long, value_name = "SUBSTR", help = READER_HELP)]
        reader: Option<String>,
    },
}

/// `openpgp pin`: the user PIN (PW1) and the admin PIN (PW3).
#[derive(Subcommand)]
enum OpenpgpPinCmd {
    /// Check a PIN without changing anything (the user PIN, or the admin PIN with --admin).
    ///
    /// The PIN comes from an environment variable, stdin or, with neither, a
    /// hidden prompt — never argv.
    Verify {
        /// Check the admin PIN (PW3) instead of the user PIN (PW1).
        #[arg(long)]
        admin: bool,
        /// The PIN: env:NAME reads that environment variable, stdin reads one
        /// line (hidden when typed at a terminal). With neither, a terminal
        /// asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        #[arg(long, value_name = "SUBSTR", help = READER_HELP)]
        reader: Option<String>,
    },
    /// Change the user PIN, or the admin PIN with --admin.
    ///
    /// Each PIN comes from an environment variable, stdin (the current PIN on
    /// the first line, the new one on the second) or, with neither, a hidden
    /// prompt — never argv.
    Change {
        /// Change the admin PIN (PW3) instead of the user PIN (PW1).
        #[arg(long)]
        admin: bool,
        /// The current user PIN (PW1), or the current admin PIN (PW3) with
        /// --admin: env:NAME reads that environment variable, stdin reads one
        /// line (first line; hidden when typed at a terminal). With neither,
        /// a terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        /// The new user PIN (PW1), or the new admin PIN (PW3) with --admin:
        /// env:NAME reads that environment variable, stdin reads one line
        /// (second line when --pin stdin is also given; hidden when typed at
        /// a terminal). With neither, a terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        new_pin: Option<SecretSource>,
        #[arg(long, value_name = "SUBSTR", help = READER_HELP)]
        reader: Option<String>,
    },
    /// Set a new user PIN using the admin PIN (after too many wrong user PINs).
    ///
    /// Recovers a card whose user PIN is blocked without a factory reset.
    /// Each PIN comes from an environment variable, stdin (the admin PIN on
    /// the first line, the new user PIN on the second) or, with neither, a
    /// hidden prompt — never argv.
    Unblock {
        /// The admin PIN (PW3): env:NAME reads that environment variable, stdin
        /// reads one line (first line; hidden when typed at a terminal). With
        /// neither, a terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        admin_pin: Option<SecretSource>,
        /// The new user PIN (PW1): env:NAME reads that environment variable,
        /// stdin reads one line (second line when --admin-pin stdin is also
        /// given; hidden when typed at a terminal). With neither, a terminal
        /// asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        new_pin: Option<SecretSource>,
        #[arg(long, value_name = "SUBSTR", help = READER_HELP)]
        reader: Option<String>,
    },
}

/// `openpgp key`: the card's key slots.
#[derive(Subcommand)]
enum OpenpgpKeyCmd {
    /// Generate a fresh key pair in a slot, replacing any key already there.
    /// Irreversible: asks first (`--yes` to skip).
    ///
    /// Can switch the slot's algorithm first. Needs the admin PIN (PW3); on a
    /// YubiKey a touch is also required. Also writes the key's v4 fingerprint
    /// and a generation timestamp so an OpenPGP tool (e.g. gpg) recognizes the
    /// key.
    Generate {
        /// Which key slot to (over)write: `sign`, `decrypt`, or `auth`.
        #[arg(long, short = 's', value_enum, default_value_t = OpenpgpSlot::Sign)]
        slot: OpenpgpSlot,
        /// Key algorithm to generate. Omit to keep the slot's current algorithm
        /// (RSA-2048 on a factory card). Ed25519 fits the sign/auth slots,
        /// X25519 the decrypt slot; the NIST/brainpool/secp256k1 curves fit any.
        /// See `openpgp key algorithms` for what this card accepts. (PIV's `eccp256`
        /// is `nistp256` here.)
        #[arg(long, value_enum)]
        algorithm: Option<CliOpenpgpKeyAlg>,
        /// Confirm without asking (required when not run from a terminal).
        #[arg(long, short = 'y')]
        yes: bool,
        /// The admin PIN (PW3): env:NAME reads that environment variable, stdin
        /// reads one line (hidden when typed at a terminal). With neither, a
        /// terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        admin_pin: Option<SecretSource>,
        #[arg(long, value_name = "SUBSTR", help = READER_HELP)]
        reader: Option<String>,
    },
    /// Import an RSA-2048 key into a slot, replacing any key already there.
    /// Irreversible: asks first (`--yes` to skip).
    ///
    /// The key comes from either `--generate` (fresh host keygen) or `--in
    /// <FILE>` (an existing PKCS#1/PKCS#8 PEM or DER key); exactly one is
    /// required. Needs the admin PIN (PW3). The key is registered (fingerprint
    /// + timestamp) like `openpgp key generate`.
    Import {
        /// Generate a fresh RSA-2048 key on the host and import it.
        /// Mutually exclusive with `--in`.
        #[arg(long, conflicts_with = "in_file", required_unless_present = "in_file")]
        generate: bool,
        /// Import an existing RSA-2048 private key from a file (PKCS#1 or
        /// PKCS#8, PEM or DER; auto-detected). Mutually exclusive with
        /// `--generate`. The key is read locally and imported; it is never
        /// logged. Prefer an unencrypted key file you can delete afterward.
        #[arg(
            long = "in",
            short = 'i',
            value_name = "FILE",
            conflicts_with = "generate"
        )]
        in_file: Option<std::path::PathBuf>,
        /// Which key slot to (over)write: `sign`, `decrypt`, or `auth`.
        #[arg(long, short = 's', value_enum, default_value_t = OpenpgpSlot::Sign)]
        slot: OpenpgpSlot,
        /// Confirm without asking (required when not run from a terminal).
        #[arg(long, short = 'y')]
        yes: bool,
        /// The admin PIN (PW3): env:NAME reads that environment variable, stdin
        /// reads one line (hidden when typed at a terminal). With neither, a
        /// terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        admin_pin: Option<SecretSource>,
        #[arg(long, value_name = "SUBSTR", help = READER_HELP)]
        reader: Option<String>,
    },
    /// Read the public key from a slot (read-only; no PIN). RSA keys print
    /// modulus and exponent, ECC keys the public point, in hex.
    Show {
        /// Which key slot: `sign`, `decrypt`, or `auth`.
        #[arg(long, short = 's', value_enum, default_value_t = OpenpgpSlot::Sign)]
        slot: OpenpgpSlot,
        #[arg(long, value_name = "SUBSTR", help = READER_HELP)]
        reader: Option<String>,
    },
    /// List the key algorithms this card reports accepting per slot (read-only;
    /// no PIN). Cards that don't publish the list accept any attempt and answer
    /// with an error if they can't.
    Algorithms {
        #[arg(long, value_name = "SUBSTR", help = READER_HELP)]
        reader: Option<String>,
    },
}

/// `openpgp name`: the cardholder name.
#[derive(Subcommand)]
enum OpenpgpNameCmd {
    /// Set the cardholder name. Needs the admin PIN (PW3).
    ///
    /// Writes PUT DATA 005B.
    Set {
        /// Cardholder name to write (UTF-8). The OpenPGP convention is
        /// `Surname<<Given`, but it is stored verbatim.
        name: String,
        /// The admin PIN (PW3): env:NAME reads that environment variable, stdin
        /// reads one line (hidden when typed at a terminal). With neither, a
        /// terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        admin_pin: Option<SecretSource>,
        #[arg(long, value_name = "SUBSTR", help = READER_HELP)]
        reader: Option<String>,
    },
}

/// `openpgp url`: the public-key URL.
#[derive(Subcommand)]
enum OpenpgpUrlCmd {
    /// Set the public-key URL. Needs the admin PIN (PW3).
    ///
    /// Writes PUT DATA 5F50.
    Set {
        /// URL to write.
        url: String,
        /// The admin PIN (PW3): env:NAME reads that environment variable, stdin
        /// reads one line (hidden when typed at a terminal). With neither, a
        /// terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        admin_pin: Option<SecretSource>,
        #[arg(long, value_name = "SUBSTR", help = READER_HELP)]
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

/// Key algorithm for `openpgp key generate --algorithm`. Names follow GnuPG's
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

/// Which OpenPGP PIN a command checks: `--admin` picks PW3 ([`pin_kind`]).
#[derive(Copy, Clone)]
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

/// The PIN `--admin` selects: the admin PIN (PW3) with it, the user PIN
/// (PW1) without.
fn pin_kind(admin: bool) -> OpenpgpPinKind {
    if admin {
        OpenpgpPinKind::Admin
    } else {
        OpenpgpPinKind::User
    }
}

/// Subcommands for the `name` friendly-name registry.
#[derive(Subcommand)]
enum NameCmd {
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
        /// Name the key on this smart-card reader (substring).
        #[arg(long, value_name = "SUBSTR")]
        reader: Option<String>,
    },
    /// List configured key names and whether each is currently connected.
    List,
    /// Delete a friendly name from keys.json (the key itself is not touched).
    Delete {
        /// The friendly label to delete.
        name: String,
    },
}

/// Reader selection plus the (optional) password for a protected OATH applet.
/// Flattened into each OATH subcommand so they share one access surface.
#[derive(clap::Args)]
struct OathAccess {
    #[arg(long, value_name = "SUBSTR", help = READER_HELP)]
    reader: Option<String>,
    /// The applet password: env:NAME reads that environment variable, stdin
    /// reads one line (hidden when typed at a terminal). With neither, a
    /// terminal asks when the applet has a password. Needed for
    /// password-protected applets (e.g. a YubiKey
    /// with an OATH password set). `oath password set` reads it on the first line,
    /// before the new password; `add` reads it after the seed (second line when
    /// --seed stdin is also given).
    #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
    password: Option<SecretSource>,
}

impl OathAccess {
    /// Where the applet password comes from, if a flag names a source.
    fn source(&self) -> Source<'_> {
        Source::from_flag(self.password.as_ref())
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
    /// Add (provision) a TOTP or HOTP credential.
    ///
    /// The seed comes from an environment variable, stdin or, with neither,
    /// a hidden prompt — never argv; --encoding says how it is written
    /// (base32 unless --encoding hex). Piped together with the applet
    /// password, the seed is the first line and the password the second.
    Add {
        /// Credential name to store (e.g. "issuer:account").
        name: String,
        /// Credential type: time-based (TOTP) or counter-based (HOTP).
        #[arg(long = "type", value_enum, default_value_t = OathTypeArg::Totp)]
        oath_type: OathTypeArg,
        /// The seed: env:NAME reads that environment variable, stdin reads
        /// one line (first line; hidden when typed at a terminal). With
        /// neither, a terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        seed: Option<SecretSource>,
        /// How --seed is written.
        #[arg(long, value_enum, default_value_t = SeedEncoding::Base32)]
        encoding: SeedEncoding,
        /// HMAC algorithm.
        #[arg(long, value_enum, default_value_t = OathAlgoArg::Sha1)]
        algorithm: OathAlgoArg,
        /// OTP digit count (6, 7, or 8).
        #[arg(long, default_value_t = 6, value_parser = clap::value_parser!(u8).range(6..=8))]
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
    /// Delete a credential by name. Irreversible: asks first (`--yes` to
    /// skip).
    Delete {
        /// Credential name to remove.
        name: String,
        #[command(flatten)]
        access: OathAccess,
        /// Confirm without asking (required when not run from a terminal).
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Set or clear the OATH applet's access password.
    Password {
        #[command(subcommand)]
        cmd: OathPasswordCmd,
    },
    /// Factory-reset the OATH applet: wipe ALL authenticator credentials and
    /// clear the access password. Irreversible: asks first (`--yes` to skip).
    ///
    /// Needs no password — this is the recovery path for a forgotten one.
    Reset {
        #[arg(long, value_name = "SUBSTR", help = READER_HELP)]
        reader: Option<String>,
        /// Confirm without asking (required when not run from a terminal).
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

/// `oath password`: the applet's access password.
#[derive(Subcommand)]
enum OathPasswordCmd {
    /// Set (or replace) the applet password — never from argv.
    ///
    /// The current password, if one is set, is read first (env, stdin line 1,
    /// or the prompt), then the new one. To remove the password, use `oath
    /// password clear`.
    Set {
        /// The new password: env:NAME reads that environment variable, stdin
        /// reads one line (second line when --password stdin is also given;
        /// hidden when typed at a terminal). With neither, a terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        new_password: Option<SecretSource>,
        #[command(flatten)]
        access: OathAccess,
    },
    /// Remove the applet password. The current password comes from
    /// `--password env:NAME` / `--password stdin` or, with neither, a hidden
    /// prompt.
    Clear {
        #[command(flatten)]
        access: OathAccess,
    },
}

/// How a seed is written: base32 (what services show) or hex.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
enum SeedEncoding {
    #[default]
    Base32,
    Hex,
}

/// How a Molto2 customer key is written: hex or ASCII text.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
enum KeyEncoding {
    #[default]
    Hex,
    Ascii,
}

/// The Molto2 customer key, usable before or after the subcommand.
#[derive(clap::Args)]
struct KeyArgs {
    /// The current customer key: env:NAME reads that environment variable,
    /// stdin reads one line (the first line, before any other secret;
    /// hidden when typed at a terminal). Without it, the factory-default
    /// key is used.
    #[arg(long, global = true, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
    customer_key: Option<SecretSource>,
    /// How --customer-key is written.
    #[arg(long, global = true, value_enum, default_value_t = KeyEncoding::Hex)]
    customer_key_encoding: KeyEncoding,
}

/// Token2 single-profile programmable token subcommands. These talk to the
/// token over a PC/SC reader and authenticate with the token's fixed device key
/// (no customer key, no profile index).
#[derive(Subcommand)]
enum ProgCmd {
    /// Print device serial number and on-device UTC time. No auth needed.
    Info {
        #[arg(long, value_name = "SUBSTR", help = READER_HELP)]
        reader: Option<String>,
    },
    /// Write the TOTP seed, replacing the one on the token. Irreversible: asks
    /// first (`--yes` to skip).
    ///
    /// The seed comes from --seed env:NAME or --seed stdin, or a terminal
    /// asks for it (hidden); --encoding says how it is written (base32
    /// unless --encoding hex).
    Seed {
        #[arg(long, value_name = "SUBSTR", help = READER_HELP)]
        reader: Option<String>,
        /// The seed: env:NAME reads that environment variable, stdin reads
        /// one line (hidden when typed at a terminal). With neither, a
        /// terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        seed: Option<SecretSource>,
        /// How --seed is written.
        #[arg(long, value_enum, default_value_t = SeedEncoding::Base32)]
        encoding: SeedEncoding,
        /// Confirm without asking (required when not run from a terminal).
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Set the device configuration and seed the clock with the host's UTC time.
    Config {
        #[arg(long, value_name = "SUBSTR", help = READER_HELP)]
        reader: Option<String>,
        /// HMAC algorithm for the codes.
        #[arg(long, value_enum, default_value_t = AlgoArg::Sha1)]
        algorithm: AlgoArg,
        /// TOTP period in seconds.
        #[arg(long, value_enum, default_value_t = StepArg::S30)]
        period: StepArg,
        /// How long the code stays on the display, in seconds.
        #[arg(long, value_enum, default_value_t = TimeoutArg::S30)]
        display_timeout: TimeoutArg,
        /// Confirm without asking (required when not run from a terminal).
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

/// Token2 Molto2 / Molto2v2 subcommands. These talk to the Molto2 PC/SC
/// reader, authenticated with the customer key (see --customer-key).
#[derive(Subcommand)]
enum MoltoCmd {
    /// Print device serial number and on-device UTC time.
    Info,
    /// List the 100 slots: occupancy, title, TOTP config.
    /// Titles and occupancy are readable by anyone holding the token —
    /// no customer key is needed (or used).
    Slots {
        /// Show all 100 slots, including empty untitled ones.
        #[arg(long)]
        all: bool,
    },
    /// Write a TOTP seed to a slot, replacing any seed already there.
    /// Irreversible: asks first (`--yes` to skip).
    ///
    /// Asks only when the slot is occupied. The seed comes from --seed
    /// env:NAME or --seed stdin, or a terminal asks for it (hidden);
    /// --encoding says how it is written (base32 unless --encoding hex).
    Seed {
        /// Slot number, 0-99 (Token2 calls these profiles).
        #[arg(long, short = 's', value_name = "SLOT", value_parser = parse_molto_slot)]
        slot: u8,
        /// The seed: env:NAME reads that environment variable, stdin reads
        /// one line (second line when --customer-key stdin is also given;
        /// hidden when typed at a terminal). With neither, a terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        seed: Option<SecretSource>,
        /// How --seed is written.
        #[arg(long, value_enum, default_value_t = SeedEncoding::Base32)]
        encoding: SeedEncoding,
        /// Confirm without asking (required when not run from a terminal).
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Write a slot title (1..=12 ASCII chars), or print the current
    /// one when TITLE is omitted (reading needs no customer key).
    Title {
        /// Slot number, 0-99 (Token2 calls these profiles).
        #[arg(long, short = 's', value_name = "SLOT", value_parser = parse_molto_slot)]
        slot: u8,
        /// New title; omit to read the slot's stored title instead.
        #[arg(value_parser = parse_molto_title)]
        title: Option<String>,
    },
    /// Delete one slot's seed. Irreversible: asks first (`--yes` to skip).
    ///
    /// The title, if any, survives. Keyless: the device accepts this from any
    /// card holder (hardware-verified), so the only gate is the confirmation.
    Delete {
        /// Slot number, 0-99 (Token2 calls these profiles).
        #[arg(long, short = 's', value_name = "SLOT", value_parser = parse_molto_slot)]
        slot: u8,
        /// Confirm without asking (required when not run from a terminal).
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Set a slot's TOTP configuration (and seed the clock with the host's UTC time).
    Config {
        /// Slot number, 0-99 (Token2 calls these profiles).
        #[arg(long, short = 's', value_name = "SLOT", value_parser = parse_molto_slot)]
        slot: u8,
        /// HMAC algorithm for the codes.
        #[arg(long, value_enum, default_value_t = AlgoArg::Sha1)]
        algorithm: AlgoArg,
        /// Code length in digits.
        #[arg(long, value_enum, default_value_t = DigitsArg::Six)]
        digits: DigitsArg,
        /// TOTP period in seconds.
        #[arg(long, value_enum, default_value_t = StepArg::S30)]
        period: StepArg,
        /// How long the code stays on the display, in seconds.
        #[arg(long, value_enum, default_value_t = TimeoutArg::S30)]
        display_timeout: TimeoutArg,
    },
    /// Push the host's current UTC time to one slot (or all slots).
    Sync {
        /// Slot number, 0-99 (Token2 calls these profiles). Omit with `--all`.
        #[arg(long, short = 's', value_name = "SLOT", conflicts_with = "all", value_parser = parse_molto_slot)]
        slot: Option<u8>,
        /// Sync time on every slot 0..=99.
        #[arg(long)]
        all: bool,
    },
    /// Replace the Molto2's customer key. Irreversible: asks first (`--yes` to skip).
    ///
    /// The current key stops working. If the new one is lost, only `molto
    /// reset` (which wipes every slot) recovers the token. The token also
    /// asks for its up-arrow button before it changes the key. The new key
    /// comes from --new-customer-key env:NAME or stdin, or a terminal asks
    /// for it twice (hidden); --encoding says how it is written (hex unless
    /// --encoding ascii). The current key comes from --customer-key (the
    /// factory default without it).
    CustomerKey {
        /// The new customer key: env:NAME reads that environment variable,
        /// stdin reads one line (second line when --customer-key stdin is
        /// also given; hidden when typed at a terminal). With neither, a
        /// terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        new_customer_key: Option<SecretSource>,
        /// How --new-customer-key is written.
        #[arg(long, value_enum, default_value_t = KeyEncoding::Hex)]
        encoding: KeyEncoding,
        /// Confirm without asking (required when not run from a terminal).
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Import an otpauth:// URI to a slot, or every entry of an export file
    /// to consecutive slots: writes seed, title, and config, replacing what
    /// the slots held. Irreversible: asks first (`--yes` to skip).
    ///
    /// Asks only when a target slot is occupied. The URI comes from --uri
    /// env:NAME, --uri stdin or a QR screenshot (--qr IMAGE), never the
    /// command line; with none of them and no --file, a terminal asks for it
    /// (hidden). For an encrypted Aegis vault given with --file, the password
    /// comes from --password env:NAME or --password stdin; with neither, a
    /// terminal asks for it (hidden).
    #[command(group(clap::ArgGroup::new("import_source").args(["uri", "qr", "file"]).multiple(false)))]
    Import {
        /// Slot number, 0-99 (Token2 calls these profiles). With --file, the
        /// first slot to fill (default 0); entries fill consecutive slots.
        #[arg(long, short = 's', value_name = "SLOT", value_parser = parse_molto_slot, required_unless_present = "file")]
        slot: Option<u8>,
        /// Override the slot title (default: derived from the URI issuer/account).
        #[arg(long, value_parser = parse_molto_title, conflicts_with = "file")]
        title: Option<String>,
        /// Display timeout in seconds (otpauth:// has no equivalent field).
        #[arg(long, value_enum, default_value_t = TimeoutArg::S30)]
        display_timeout: TimeoutArg,
        /// The otpauth:// URI: env:NAME reads that environment variable, stdin
        /// reads one line (second line when --customer-key stdin is also given;
        /// hidden when typed at a terminal). With none of --uri, --qr and
        /// --file, a terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        uri: Option<SecretSource>,
        /// Decode the otpauth:// URI from a QR code in a PNG/JPEG screenshot.
        /// For a Google Authenticator export QR (several accounts), use --file.
        #[arg(long, value_name = "IMAGE")]
        qr: Option<std::path::PathBuf>,
        /// Import every entry of an export file instead: Aegis (plain or
        /// encrypted), 2FAS, a list of otpauth:// URIs, or a Google
        /// Authenticator export QR image. The format is detected.
        #[arg(long, value_name = "PATH")]
        file: Option<std::path::PathBuf>,
        /// Print what would be written, but don't touch the device.
        #[arg(long, requires = "file")]
        dry_run: bool,
        /// The password of an encrypted Aegis vault: env:NAME or stdin (second
        /// line when --customer-key stdin is also given; hidden when typed at a
        /// terminal). With neither, a terminal asks when the vault needs one.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true, requires = "file")]
        password: Option<SecretSource>,
        /// Confirm without asking (required when not run from a terminal).
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Sweep plausible read APDUs against the device and report what the firmware
    /// recognizes.
    ///
    /// Read-only by intent — sends short read-style requests with
    /// destructive INS bytes (set seed/title/config, factory reset, set customer
    /// key) excluded by default.
    #[command(hide = true)]
    Probe {
        /// Confirm you understand this sends ~256–512 experimental APDUs.
        #[arg(long, short = 'y')]
        yes: bool,
        /// Also probe the secure class (CLA 0x84) after authenticating. Without
        /// this, only CLA 0x80 is scanned (no auth needed).
        #[arg(long)]
        authed: bool,
        /// Override the safety filter and scan every INS byte 0x00..0xFF.
        /// Only useful if you've already exhausted the safe sweep.
        #[arg(long)]
        include_destructive: bool,
        /// Slot to use in P2 for `authed` scans (P2 is the slot number
        /// for the known secure commands). Defaults to a high, presumably-unused
        /// slot.
        #[arg(long, short = 's', default_value_t = 99)]
        slot: u8,
    },
    /// Factory-reset the device: wipe all slots and restore the default
    /// customer key. Irreversible: asks first (`--yes` to skip).
    ///
    /// Requires physical button confirmation on the device.
    Reset {
        /// Confirm without asking (required when not run from a terminal).
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

/// FIDO2 / CTAP2 subcommands. These talk to the key over USB HID (`fido reset
/// --reader` can use a smart-card reader instead).
#[derive(Subcommand)]
enum FidoCmd {
    /// Show the key's FIDO2 capabilities and settings.
    ///
    /// Runs authenticatorGetInfo.
    Info {
        #[arg(long, value_name = "PATH", help = PATH_HELP)]
        path: Option<std::path::PathBuf>,
    },
    /// Factory-reset FIDO2: wipe every credential (passkeys and security-key
    /// sign-ins) and the PIN. Irreversible: asks first (`--yes` to skip).
    ///
    /// Runs authenticatorReset. Most authenticators only accept it within
    /// ~10s of plug-in and require a physical touch, so over USB keyroost
    /// waits up to 60 seconds for the key to be unplugged and plugged back in
    /// before sending the reset.
    ///
    /// For a card in a smart-card reader (no USB interface), use `--reader`:
    /// the card is power-cycled in place — which starts the same
    /// just-after-power-up window a replug would — and the reset sent
    /// immediately. No touch is involved.
    Reset {
        /// Confirm without asking (required when not run from a terminal).
        #[arg(long, short = 'y')]
        yes: bool,
        #[arg(long, value_name = "PATH", conflicts_with = "reader", help = PATH_HELP)]
        path: Option<std::path::PathBuf>,
        /// Smart-card reader holding the card to reset (name contains this
        /// text); sends the reset over the smart-card interface instead of USB.
        #[arg(long, value_name = "SUBSTR")]
        reader: Option<String>,
    },
    /// Set, change or check the FIDO2 PIN, and the PIN rules (minimum length, forced change).
    Pin {
        #[command(subcommand)]
        cmd: FidoPinCmd,
    },
    /// List, inspect or delete the credentials (passkeys and security-key sign-ins) on the key.
    Credential {
        #[command(subcommand)]
        cmd: FidoCredentialCmd,
    },
    /// List, add, rename or delete enrolled fingerprints.
    Fingerprint {
        #[command(subcommand)]
        cmd: FidoFingerprintCmd,
    },
    /// Key-wide FIDO2 switches: always-uv and enterprise attestation.
    Config {
        #[command(subcommand)]
        cmd: FidoConfigCmd,
    },
    /// Read and write the key's large-blob store (notes, SSH certificates).
    ///
    /// IMPORTANT: the large-blob store is WORLD-READABLE without a PIN — any
    /// software with access to the key can read every entry. It is a convenience
    /// scratchpad, NOT a place for secrets. Relying parties (e.g. an SSH cert
    /// flow) may also keep their own encrypted entries here; keyroost never
    /// rewrites or deletes those without an explicit `--yes`.
    Blob {
        #[command(subcommand)]
        cmd: LargeBlobCmd,
    },
    /// List SSH credentials and extract their certificates.
    ///
    /// A stored OpenSSH certificate is read from the credential's largeBlob
    /// and written to a `-cert.pub` file.
    Ssh {
        #[command(subcommand)]
        cmd: SshCertCmd,
    },
}

/// `fido pin` subcommands: the FIDO2 PIN itself.
#[derive(Subcommand)]
enum FidoPinCmd {
    /// Print the current PIN retry counter.
    Retries {
        #[arg(long, value_name = "PATH", help = PATH_HELP)]
        path: Option<std::path::PathBuf>,
    },
    /// Set the initial PIN on an authenticator that doesn't have one yet. The
    /// PIN comes from an environment variable, stdin or, with neither, a
    /// hidden prompt (asked twice) — never argv.
    Set {
        /// The new PIN: env:NAME reads that environment variable, stdin reads
        /// one line (hidden when typed at a terminal). With neither, a terminal
        /// asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        new_pin: Option<SecretSource>,
        #[arg(long, value_name = "PATH", help = PATH_HELP)]
        path: Option<std::path::PathBuf>,
    },
    /// Change the existing PIN. Each PIN comes from an environment variable,
    /// stdin (the current PIN on the first line, the new one on the second)
    /// or, with neither, a hidden prompt — never argv.
    Change {
        /// The current PIN: env:NAME reads that environment variable, stdin
        /// reads one line (first line; hidden when typed at a terminal). With
        /// neither, a terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        /// The new PIN: env:NAME reads that environment variable, stdin reads
        /// one line (second line when --pin stdin is also given; hidden when
        /// typed at a terminal). With neither, a terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        new_pin: Option<SecretSource>,
        #[arg(long, value_name = "PATH", help = PATH_HELP)]
        path: Option<std::path::PathBuf>,
    },
    /// Raise the minimum PIN length. One-way: asks first (`--yes` to skip).
    ///
    /// The value can only be increased, never lowered (a FIDO2 reset is
    /// required to lower it), and may force a PIN change. To only force a PIN
    /// change, use `fido pin force-change` instead.
    MinLength {
        /// New minimum PIN length (in code points). Must be >= the current one.
        #[arg(long, value_name = "N")]
        length: u32,
        /// Also require the user to change the PIN on next use.
        #[arg(long)]
        force_change: bool,
        /// Confirm without asking (required when not run from a terminal).
        #[arg(long, short = 'y')]
        yes: bool,
        /// The PIN: env:NAME reads that environment variable, stdin reads one
        /// line (hidden when typed at a terminal). With neither, a terminal
        /// asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        #[arg(long, value_name = "PATH", help = PATH_HELP)]
        path: Option<std::path::PathBuf>,
    },
    /// Force a PIN change on next use, without changing the minimum length.
    ForceChange {
        /// The PIN: env:NAME reads that environment variable, stdin reads one
        /// line (hidden when typed at a terminal). With neither, a terminal
        /// asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        #[arg(long, value_name = "PATH", help = PATH_HELP)]
        path: Option<std::path::PathBuf>,
    },
}

/// `fido credential` subcommands: the credentials (passkeys and security-key
/// sign-ins) stored on the key.
#[derive(Subcommand)]
enum FidoCredentialCmd {
    /// List every resident credential on the authenticator, grouped by RP.
    List {
        /// The PIN: env:NAME reads that environment variable, stdin reads one
        /// line (hidden when typed at a terminal). With neither, a terminal
        /// asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        #[arg(long, value_name = "PATH", help = PATH_HELP)]
        path: Option<std::path::PathBuf>,
    },
    /// Delete one credential (passkey or security-key sign-in) by its hex
    /// credential ID.
    /// Irreversible: asks first (`--yes` to skip).
    Delete {
        /// Credential ID to delete, in hex (see `fido credential list`).
        #[arg(long, value_name = "HEX", value_parser = parse_hex_arg)]
        id: String,
        /// The PIN: env:NAME reads that environment variable, stdin reads one
        /// line (hidden when typed at a terminal). With neither, a terminal
        /// asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        #[arg(long, value_name = "PATH", help = PATH_HELP)]
        path: Option<std::path::PathBuf>,
        /// Confirm without asking (required when not run from a terminal).
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Show how many passkeys the key holds and how many more fit. Needs the
    /// PIN.
    Metadata {
        /// The PIN: env:NAME reads that environment variable, stdin reads one
        /// line (hidden when typed at a terminal). With neither, a terminal
        /// asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        #[arg(long, value_name = "PATH", help = PATH_HELP)]
        path: Option<std::path::PathBuf>,
    },
}

/// `fido fingerprint` subcommands: bio enrollment on keys with a sensor.
#[derive(Subcommand)]
enum FidoFingerprintCmd {
    /// List enrolled fingerprints (template id + name).
    List {
        /// The PIN: env:NAME reads that environment variable, stdin reads one
        /// line (hidden when typed at a terminal). With neither, a terminal
        /// asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        #[arg(long, value_name = "PATH", help = PATH_HELP)]
        path: Option<std::path::PathBuf>,
    },
    /// Enroll a new fingerprint. Touch the sensor repeatedly when prompted until
    /// capture completes.
    Add {
        /// Optional friendly name to set on the new fingerprint once enrolled.
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
        /// The PIN: env:NAME reads that environment variable, stdin reads one
        /// line (hidden when typed at a terminal). With neither, a terminal
        /// asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        #[arg(long, value_name = "PATH", help = PATH_HELP)]
        path: Option<std::path::PathBuf>,
    },
    /// Rename an enrolled fingerprint by its hex template ID (from `fido
    /// fingerprint list`).
    Rename {
        /// Fingerprint template ID, in hex (see `fido fingerprint list`).
        #[arg(long, value_name = "HEX", value_parser = parse_hex_arg)]
        id: String,
        /// New friendly name.
        #[arg(long, value_name = "NAME")]
        name: String,
        /// The PIN: env:NAME reads that environment variable, stdin reads one
        /// line (hidden when typed at a terminal). With neither, a terminal
        /// asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        #[arg(long, value_name = "PATH", help = PATH_HELP)]
        path: Option<std::path::PathBuf>,
    },
    /// Delete an enrolled fingerprint by its hex template ID (from `fido
    /// fingerprint list`). Irreversible: asks first (`--yes` to skip).
    Delete {
        /// Fingerprint template ID, in hex (see `fido fingerprint list`).
        #[arg(long, value_name = "HEX", value_parser = parse_hex_arg)]
        id: String,
        /// The PIN: env:NAME reads that environment variable, stdin reads one
        /// line (hidden when typed at a terminal). With neither, a terminal
        /// asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        #[arg(long, value_name = "PATH", help = PATH_HELP)]
        path: Option<std::path::PathBuf>,
        /// Confirm without asking (required when not run from a terminal).
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

/// `fido config` subcommands: key-wide authenticatorConfig switches.
#[derive(Subcommand)]
enum FidoConfigCmd {
    /// Always-uv (always user verification): when on, every sign-in needs the PIN or a fingerprint, not only a touch.
    AlwaysUv {
        #[command(subcommand)]
        cmd: FidoToggleCmd,
    },
    /// Enterprise attestation: lets a managed deployment's sign-in prove which exact key is used.
    Attestation {
        #[command(subcommand)]
        cmd: FidoAttestationCmd,
    },
}

/// `fido config always-uv` subcommands.
#[derive(Subcommand)]
enum FidoToggleCmd {
    /// Turn on "always require user verification" (alwaysUv). Does nothing if it is already on.
    Enable {
        /// The PIN: env:NAME reads that environment variable, stdin reads one
        /// line (hidden when typed at a terminal). With neither, a terminal
        /// asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        #[arg(long, value_name = "PATH", help = PATH_HELP)]
        path: Option<std::path::PathBuf>,
    },
    /// Turn off "always require user verification" (alwaysUv). Does nothing if it is already off.
    Disable {
        /// The PIN: env:NAME reads that environment variable, stdin reads one
        /// line (hidden when typed at a terminal). With neither, a terminal
        /// asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        #[arg(long, value_name = "PATH", help = PATH_HELP)]
        path: Option<std::path::PathBuf>,
    },
}

/// `fido config attestation` subcommands.
#[derive(Subcommand)]
enum FidoAttestationCmd {
    /// Enable enterprise attestation. One-way: asks first (`--yes` to skip).
    ///
    /// Turning it off again typically requires a FIDO2 reset.
    Enable {
        /// Confirm without asking (required when not run from a terminal).
        #[arg(long, short = 'y')]
        yes: bool,
        /// The PIN: env:NAME reads that environment variable, stdin reads one
        /// line (hidden when typed at a terminal). With neither, a terminal
        /// asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        #[arg(long, value_name = "PATH", help = PATH_HELP)]
        path: Option<std::path::PathBuf>,
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
        /// The PIN: env:NAME reads that environment variable, stdin reads one
        /// line (hidden when typed at a terminal). With neither, a terminal
        /// asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        #[arg(long, value_name = "PATH", help = PATH_HELP)]
        path: Option<std::path::PathBuf>,
    },
    /// Extract an SSH certificate from its largeBlob to a -cert.pub file.
    Extract {
        /// RP ID of the SSH credential (e.g. ssh:demo). Needed only when several SSH credentials are present.
        #[arg(long, value_name = "RP_ID")]
        id: Option<String>,
        /// Output file (default: <rp-id-sanitized>-cert.pub).
        #[arg(long, short = 'o', value_name = "FILE")]
        out: Option<std::path::PathBuf>,
        #[arg(long, help = OVERWRITE_HELP)]
        overwrite: bool,
        /// The PIN: env:NAME reads that environment variable, stdin reads one
        /// line (hidden when typed at a terminal). With neither, a terminal
        /// asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        #[arg(long, value_name = "PATH", help = PATH_HELP)]
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
        #[arg(long, value_name = "PATH", help = PATH_HELP)]
        path: Option<std::path::PathBuf>,
    },
    /// Show one entry in full by its index (from `fido blob list`).
    Get {
        /// Zero-based entry index as printed by `fido blob list`.
        index: usize,
        #[arg(long, value_name = "PATH", help = PATH_HELP)]
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
        /// The PIN: env:NAME reads that environment variable, stdin reads one
        /// line (hidden when typed at a terminal). With neither, a terminal
        /// asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        #[arg(long, value_name = "PATH", help = PATH_HELP)]
        path: Option<std::path::PathBuf>,
    },
    /// Replace the text of an existing keyroost note by its index.
    ///
    /// Refuses to touch opaque RP-encrypted entries.
    Edit {
        /// Zero-based entry index as printed by `fido blob list`.
        index: usize,
        /// The new note text (plain UTF-8). Visible in argv to other processes.
        text: String,
        /// The PIN: env:NAME reads that environment variable, stdin reads one
        /// line (hidden when typed at a terminal). With neither, a terminal
        /// asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        #[arg(long, value_name = "PATH", help = PATH_HELP)]
        path: Option<std::path::PathBuf>,
    },
    /// Delete a single entry by its index. Irreversible: asks first (`--yes`
    /// to skip).
    ///
    /// Deleting an opaque (RP-owned) entry may break a service that stored it;
    /// the command warns before asking.
    Delete {
        /// Zero-based entry index as printed by `fido blob list`.
        index: usize,
        /// Confirm without asking (required when not run from a terminal).
        #[arg(long, short = 'y')]
        yes: bool,
        /// The PIN: env:NAME reads that environment variable, stdin reads one
        /// line (hidden when typed at a terminal). With neither, a terminal
        /// asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        #[arg(long, value_name = "PATH", help = PATH_HELP)]
        path: Option<std::path::PathBuf>,
    },
    /// Save one entry's bytes to a file (read-only; no PIN needed).
    ///
    /// By default writes the entry's raw stored bytes. With --as-cert, a
    /// recognized OpenSSH certificate entry is written as a `-cert.pub` text
    /// line instead (the format `ssh` and `ssh-keygen` consume).
    Export {
        /// Zero-based entry index as printed by `fido blob list`.
        index: usize,
        /// File to write the entry's bytes to.
        #[arg(long, short = 'o', value_name = "FILE")]
        out: std::path::PathBuf,
        #[arg(long, help = OVERWRITE_HELP)]
        overwrite: bool,
        /// Write a recognized SSH certificate in `-cert.pub` text form.
        #[arg(long)]
        as_cert: bool,
        #[arg(long, value_name = "PATH", help = PATH_HELP)]
        path: Option<std::path::PathBuf>,
    },
    /// Erase the ENTIRE large-blob array, including any RP-owned entries.
    /// Irreversible: asks first (`--yes` to skip).
    Clear {
        /// Confirm without asking (required when not run from a terminal).
        #[arg(long, short = 'y')]
        yes: bool,
        /// The PIN: env:NAME reads that environment variable, stdin reads one
        /// line (hidden when typed at a terminal). With neither, a terminal
        /// asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        #[arg(long, value_name = "PATH", help = PATH_HELP)]
        path: Option<std::path::PathBuf>,
    },
}

/// Subcommands for the Token2 on-device OTP applet (T2F2 / PIN+) over USB-HID
/// or NFC. Seeds are read from stdin or an env var — never argv.
#[derive(Subcommand)]
enum OtpCmd {
    /// List the OTP entries stored on the key, with their live codes where the
    /// device returns them (TOTP without button-press).
    ///
    /// On a PIN-protected
    /// (R3.4+) key, `--unlock pin` (the default) takes the PIN from
    /// `--pin env:NAME` / `--pin stdin` or, with neither, a hidden prompt; a key
    /// without a PIN is never asked. `--unlock fingerprint` unlocks by a
    /// fingerprint touch instead, and `--unlock auto` tries the fingerprint
    /// and falls back to a PIN given by flag (never asked for).
    List {
        /// How to unlock the codes on a PIN-protected key; `pin` asks for the
        /// PIN when the key needs one and no flag gives it.
        #[arg(long, value_enum, default_value_t = OtpUnlock::Pin)]
        unlock: OtpUnlock,
        /// The OTP PIN to unlock a protected key: env:NAME reads that
        /// environment variable, stdin reads one line (hidden when typed at a
        /// terminal). With neither, a terminal asks when the key has a PIN
        /// (`--unlock pin` only).
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
    },
    /// Print the current code for one entry, identified by app and account.
    /// A button-required entry will prompt for a touch.
    Code {
        /// Application/issuer name as stored (may be empty).
        #[arg(long, default_value = "")]
        app: String,
        /// Account name as stored.
        #[arg(long)]
        account: String,
    },
    /// Add (or overwrite) an OTP entry.
    ///
    /// The seed comes from an environment variable, stdin or, with neither,
    /// a hidden prompt — never argv; --encoding says how it is written
    /// (base32 unless --encoding hex). A PIN-protected (R3.4+) key also
    /// needs its PIN: piped together with the seed, the seed is the first line
    /// and the PIN the second.
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
        #[arg(long, default_value_t = 6, value_parser = clap::value_parser!(u8).range(4..=10))]
        digits: u8,
        /// TOTP time step in seconds (ignored for HOTP).
        #[arg(long, default_value_t = 30)]
        period: u16,
        /// Require a button press on the key to emit this code.
        #[arg(long)]
        touch: bool,
        /// The seed: env:NAME reads that environment variable, stdin reads
        /// one line (first line; hidden when typed at a terminal). With
        /// neither, a terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        seed: Option<SecretSource>,
        /// How --seed is written.
        #[arg(long, value_enum, default_value_t = SeedEncoding::Base32)]
        encoding: SeedEncoding,
        /// The OTP PIN to unlock a protected key: env:NAME reads that
        /// environment variable, stdin reads one line (second line when --seed
        /// stdin is also given; hidden when typed at a terminal). With neither,
        /// a terminal asks when the key has a PIN.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
    },
    /// Delete one OTP entry by app and account. Irreversible: asks first
    /// (`--yes` to skip).
    ///
    /// A PIN-protected (R3.4+) key's PIN comes from `--pin env:NAME` / `--pin stdin`
    /// or, with neither, a hidden prompt after the question.
    Delete {
        /// Application/issuer name as stored (may be empty).
        #[arg(long, default_value = "")]
        app: String,
        /// Account name as stored.
        #[arg(long)]
        account: String,
        /// The OTP PIN to unlock a protected key: env:NAME reads that
        /// environment variable, stdin reads one line (hidden when typed at a
        /// terminal). With neither, a terminal asks when the key has a PIN.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        /// Confirm without asking (required when not run from a terminal).
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Erase every OTP entry on the key. Irreversible: asks first (`--yes` to
    /// skip).
    ///
    /// The key then needs a confirming button press.
    Reset {
        /// Confirm without asking (required when not run from a terminal).
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Read the device serial number (over USB, or NFC where the model allows).
    Serial,
    /// Set or delete the HOTP code the key types when its button is pressed.
    Button {
        #[command(subcommand)]
        cmd: OtpButtonCmd,
    },
    /// Read and print the device configuration (interface states, capabilities).
    ///
    /// Useful for diagnosing why the GUI's keyboard toggle or Touch HOTP gating
    /// behaves as it does.
    Info,
    /// Choose which USB interfaces the key offers (FIDO, keyboard, CCID). Irreversible: asks for a typed confirmation (`--yes` to skip).
    ///
    /// Sends SET_DEVICE_TYPE. You name the interfaces to ENABLE; any not named
    /// are disabled. At least TWO must remain enabled: with all of them off,
    /// the key offers no USB interface to turn one back on through, and
    /// leaving only one risks locking you out, so the tool refuses fewer
    /// than two. Turning an interface back on needs a host that
    /// reaches the key through one that stays on.
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
        /// Skip the typed confirmation (required when not run from a terminal).
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Set, change, clear, check or verify the OTP PIN.
    Pin {
        #[command(subcommand)]
        cmd: OtpPinCmd,
    },
    /// Check, enable or disable fingerprint unlock for the OTP entries.
    Fingerprint {
        #[command(subcommand)]
        cmd: OtpFingerprintCmd,
    },
}

/// `otp pin`: the OTP PIN (R3.4+ keys).
#[derive(Subcommand)]
enum OtpPinCmd {
    /// Set an OTP PIN on a currently-unprotected key.
    ///
    /// After this, reading codes needs the PIN (`otp list` asks for it, or
    /// takes `--pin`). The new PIN comes from an
    /// environment variable, stdin or, with neither, a hidden prompt (asked
    /// twice) — never argv.
    ///
    /// There is no PIN reset: wrong attempts count down a retry counter, and a
    /// blocked PIN is recoverable only by erasing every OTP entry on the key
    /// (`otp reset`). Keep a record of the PIN somewhere you trust.
    Set {
        /// The new OTP PIN: env:NAME reads that environment variable, stdin
        /// reads one line (hidden when typed at a terminal). With neither, a
        /// terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        new_pin: Option<SecretSource>,
    },
    /// Change the OTP PIN: current first, then new (stdin lines 1 and 2, env
    /// vars, or the prompt).
    Change {
        /// The current OTP PIN: env:NAME reads that environment variable, stdin
        /// reads one line (first line; hidden when typed at a terminal). With
        /// neither, a terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        /// The new OTP PIN: env:NAME reads that environment variable, stdin
        /// reads one line (second line when --pin stdin is also given; hidden
        /// when typed at a terminal). With neither, a terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        new_pin: Option<SecretSource>,
    },
    /// Remove the OTP PIN. Needs the current OTP PIN: via env, stdin or, with
    /// neither, a hidden prompt.
    Clear {
        /// The OTP PIN: env:NAME reads that environment variable, stdin reads
        /// one line (hidden when typed at a terminal). With neither, a terminal
        /// asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
    },
    /// Report OTP-PIN status (R3.4+ keys): whether a PIN is set and retries left.
    Status,
    /// Verify the OTP PIN, opening the read window for this connection (mostly
    /// for testing; `otp list` takes `--pin` directly). The PIN comes from
    /// --pin env:NAME or stdin or, with neither, a hidden prompt.
    Verify {
        /// The OTP PIN: env:NAME reads that environment variable, stdin reads
        /// one line (hidden when typed at a terminal). With neither, a terminal
        /// asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
    },
}

/// `otp fingerprint`: fingerprint unlock for the OTP entries.
#[derive(Subcommand)]
enum OtpFingerprintCmd {
    /// Report whether the key supports fingerprint-protected OTP and whether
    /// it is on.
    Status,
    /// Enable fingerprint protection for OTP. Needs the current OTP PIN. After
    /// this, codes can be unlocked by a fingerprint touch as well as the PIN.
    Enable {
        /// The OTP PIN: env:NAME reads that environment variable, stdin reads
        /// one line (hidden when typed at a terminal). With neither, a terminal
        /// asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
    },
    /// Disable fingerprint protection for OTP. Needs the current OTP PIN.
    Disable {
        /// The OTP PIN: env:NAME reads that environment variable, stdin reads
        /// one line (hidden when typed at a terminal). With neither, a terminal
        /// asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
    },
}

/// `otp button`: the HOTP code typed on a button press.
#[derive(Subcommand)]
enum OtpButtonCmd {
    /// Configure the single HOTP-on-button keystroke slot, replacing any seed
    /// already there. Irreversible: asks first (`--yes` to skip).
    ///
    /// The key types this code when touched outside a session. Asks only when
    /// the slot may already be configured. The seed comes from an
    /// environment variable, stdin or, with neither, a hidden prompt — never
    /// argv; --encoding says how it is written (base32 unless --encoding
    /// hex).
    Set {
        /// Code length — must be 6 or 8.
        #[arg(long, default_value_t = 6, value_parser = parse_button_digits)]
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
        /// The seed: env:NAME reads that environment variable, stdin reads
        /// one line (hidden when typed at a terminal). With neither, a
        /// terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        seed: Option<SecretSource>,
        /// How --seed is written.
        #[arg(long, value_enum, default_value_t = SeedEncoding::Base32)]
        encoding: SeedEncoding,
        /// Confirm without asking (required when not run from a terminal).
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Delete the HOTP-on-button keystroke slot. Irreversible: asks first
    /// (`--yes` to skip).
    Delete {
        /// Confirm without asking (required when not run from a terminal).
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

/// How `otp list` unlocks the codes on a PIN-protected key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum OtpUnlock {
    /// The OTP PIN: from --pin, or asked for when the key needs one.
    Pin,
    /// A fingerprint touch, no PIN (fingerprint protection must be on).
    Fingerprint,
    /// A fingerprint touch when fingerprint protection is on, falling back to
    /// the PIN given by --pin (never asked for).
    Auto,
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

/// The selectors an `otp` invocation was given: the transport plus the
/// group's own `--reader` / `--path` (an alternative to the global `--device`).
#[derive(Clone, Copy)]
struct OtpSelect<'a> {
    transport: OtpTransportArg,
    reader: Option<&'a str>,
    path: Option<&'a Path>,
}

/// What the shared key finder needs to admit a device for this transport pick.
fn otp_need(t: OtpTransportArg) -> Need {
    match t {
        OtpTransportArg::Auto => Need::Otp,
        OtpTransportArg::Hid => Need::OtpHid,
        OtpTransportArg::Ccid => Need::OtpCcid,
    }
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

const SEED_HEX: Spec = Spec::value("seed", "seed").hex();
const SEED_B32: Spec = Spec::value("seed", "seed").base32();
/// The seed's [`Spec`] for an encoding (the prompt names the encoding).
const fn seed_spec(e: SeedEncoding) -> &'static Spec {
    match e {
        SeedEncoding::Hex => &SEED_HEX,
        SeedEncoding::Base32 => &SEED_B32,
    }
}

const CUSTOMER_KEY_HEX: Spec = Spec::current("customer key", "customer-key").hex();
const CUSTOMER_KEY_ASCII: Spec = Spec::current("customer key", "customer-key");
const NEW_CUSTOMER_KEY_HEX: Spec = Spec::new_secret("new customer key", "new-customer-key").hex();
const NEW_CUSTOMER_KEY_ASCII: Spec = Spec::new_secret("new customer key", "new-customer-key");
/// The current (`new == false`) or new customer key's [`Spec`].
const fn customer_key_spec(e: KeyEncoding, new: bool) -> &'static Spec {
    match (e, new) {
        (KeyEncoding::Hex, false) => &CUSTOMER_KEY_HEX,
        (KeyEncoding::Ascii, false) => &CUSTOMER_KEY_ASCII,
        (KeyEncoding::Hex, true) => &NEW_CUSTOMER_KEY_HEX,
        (KeyEncoding::Ascii, true) => &NEW_CUSTOMER_KEY_ASCII,
    }
}

const IMPORT_URI: Spec = Spec::value("otpauth:// URI", "uri")
    .prompt_as("otpauth:// URI")
    .hint("--uri env:NAME, --uri stdin, --qr IMAGE or --file PATH");
const VAULT_PASSWORD: Spec = Spec::current("vault password", "password");

/// Decode a seed; the error names the flag and the encoding, never the input.
fn decode_seed(text: &str, e: SeedEncoding) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    let r = match e {
        SeedEncoding::Hex => hex_decode(text).map_err(|err| {
            format!("the seed is not valid hex ({err}); pass --encoding base32 if it is base32")
        }),
        SeedEncoding::Base32 => base32_decode(text).map_err(|err| {
            format!("the seed is not valid base32 ({err}); pass --encoding hex if it is hex")
        }),
    };
    r.map(zeroize::Zeroizing::new)
}

/// Decode a customer key: hex, or ASCII taken as its bytes. `flag` is the
/// flag named in the error ("--customer-key" or "--new-customer-key").
fn decode_customer_key(text: &str, e: KeyEncoding, flag: &str) -> Result<CustomerKey, String> {
    match e {
        KeyEncoding::Hex => hex_decode(text)
            .map(zeroize::Zeroizing::new)
            .map_err(|err| format!("the customer key given by {flag} is not valid hex ({err})")),
        KeyEncoding::Ascii => Ok(zeroize::Zeroizing::new(text.as_bytes().to_vec())),
    }
}

/// The Molto2 customer key from --customer-key, or the factory default
/// without it. Never prompted for: an absent flag means the default key,
/// not a question.
fn customer_key<I: crate::secrets::SecretIo>(
    sec: &mut Secrets<I>,
    args: &KeyArgs,
) -> Result<CustomerKey, String> {
    let Some(flag) = args.customer_key.as_ref() else {
        return Ok(zeroize::Zeroizing::new(DEFAULT_CUSTOMER_KEY.to_vec()));
    };
    let enc = args.customer_key_encoding;
    let text = sec.read(customer_key_spec(enc, false), Source::from_flag(Some(flag)))?;
    decode_customer_key(&text, enc, "--customer-key")
}

/// What a Molto2 write command was given, read before the token is
/// authenticated (and before any session is held while the user types).
enum MoltoInput {
    Nothing,
    Seed(zeroize::Zeroizing<Vec<u8>>),
    NewKey(CustomerKey),
    Entry {
        entry: keyroost_import::BulkEntry,
        title: String,
    },
}

/// Clap value parser for a Molto2 slot: 0..=99.
fn parse_molto_slot(s: &str) -> Result<u8, String> {
    let n: u8 = s
        .parse()
        .map_err(|_| "slot must be a number 0..=99".to_string())?;
    if n > 99 {
        return Err("slot must be 0..=99".into());
    }
    Ok(n)
}

/// Clap value parser for a Molto2 slot title: 1..=12 bytes.
fn parse_molto_title(s: &str) -> Result<String, String> {
    if s.is_empty() || s.len() > 12 {
        return Err("title must be 1..=12 bytes".into());
    }
    Ok(s.to_string())
}

/// Clap value parser for `otp button set --digits`: 6 or 8.
fn parse_button_digits(s: &str) -> Result<u8, String> {
    match s.parse::<u8>() {
        Ok(n @ (6 | 8)) => Ok(n),
        _ => Err("button HOTP --digits must be 6 or 8".into()),
    }
}

/// Clap value parser for a hex argument: valid, non-empty hex. Returns the
/// input unchanged; the handler decodes it.
fn parse_hex_arg(s: &str) -> Result<String, String> {
    match hex_decode(s) {
        Ok(b) if !b.is_empty() => Ok(s.to_string()),
        Ok(_) => Err("must not be empty".into()),
        Err(e) => Err(format!("not valid hex: {e}")),
    }
}

/// Clap value parser for `piv chuid generate --guid`: 16 bytes of hex, dashes
/// optional. Returns the input unchanged.
fn parse_guid_arg(s: &str) -> Result<String, String> {
    keyroost_piv::parse_guid_hex(s)
        .map(|_| s.to_string())
        .ok_or_else(|| "must be 16 bytes of hex, dashes optional".to_string())
}

/// Everything that can fail without the token: a secret with no source
/// and no terminal, an unusable `env:NAME`. Reads nothing and does no device
/// I/O.
fn molto_validate<I: crate::secrets::SecretIo>(
    cmd: &MoltoCmd,
    key: &KeyArgs,
    sec: &Secrets<I>,
) -> Result<(), Box<dyn std::error::Error>> {
    if key.customer_key.is_some() {
        sec.check(
            customer_key_spec(key.customer_key_encoding, false),
            Source::from_flag(key.customer_key.as_ref()),
        )?;
    }
    match cmd {
        MoltoCmd::Seed { seed, encoding, .. } => {
            sec.check(seed_spec(*encoding), Source::from_flag(seed.as_ref()))?
        }
        MoltoCmd::CustomerKey {
            new_customer_key,
            encoding,
            ..
        } => sec.check(
            customer_key_spec(*encoding, true),
            Source::from_flag(new_customer_key.as_ref()),
        )?,
        MoltoCmd::Import {
            uri,
            qr: None,
            file: None,
            ..
        } => sec.check(&IMPORT_URI, Source::from_flag(uri.as_ref()))?,
        _ => {}
    }
    Ok(())
}

/// Read the secret (or QR image) a write command needs and finish checking
/// it: the seed's length, the import's title. No session may be held.
fn read_molto_input<I: crate::secrets::SecretIo>(
    sec: &mut Secrets<I>,
    cmd: &MoltoCmd,
) -> Result<MoltoInput, Box<dyn std::error::Error>> {
    Ok(match cmd {
        MoltoCmd::Seed { seed, encoding, .. } => {
            let text = sec.read(seed_spec(*encoding), Source::from_flag(seed.as_ref()))?;
            let seed = decode_seed(&text, *encoding)?;
            if seed.is_empty() || seed.len() > 63 {
                return Err(format!("seed must be 1..=63 bytes, got {}", seed.len()).into());
            }
            MoltoInput::Seed(seed)
        }
        MoltoCmd::CustomerKey {
            new_customer_key,
            encoding,
            ..
        } => {
            let text = sec.read(
                customer_key_spec(*encoding, true),
                Source::from_flag(new_customer_key.as_ref()),
            )?;
            MoltoInput::NewKey(decode_customer_key(&text, *encoding, "--new-customer-key")?)
        }
        MoltoCmd::Import {
            title,
            qr,
            uri,
            file: None,
            ..
        } => {
            let entry = match qr {
                Some(image_path) => molto_entry_from_qr(image_path)?,
                None => {
                    // The URI embeds the seed in its secret= parameter; it is
                    // held in Zeroizing so our copy is scrubbed after
                    // parse_otpauth (which wipes its own copies).
                    let uri = sec.read(&IMPORT_URI, Source::from_flag(uri.as_ref()))?;
                    keyroost_import::parse_otpauth(&uri)?.into()
                }
            };
            let title = title.clone().unwrap_or_else(|| entry.suggested_title());
            if title.is_empty() || title.len() > 12 {
                return Err(format!(
                    "derived title {title:?} must be 1..=12 bytes; pass --title to override"
                )
                .into());
            }
            MoltoInput::Entry { entry, title }
        }
        _ => MoltoInput::Nothing,
    })
}

/// A Molto2 customer key as read and decoded.
type CustomerKey = zeroize::Zeroizing<Vec<u8>>;

/// The customer key is stdin line 1 on every Molto2 command. Bulk import
/// reads its vault password before the occupancy question, so its key is
/// read before that, here; every other command gets `None` and reads the
/// key after the question, in [`molto_key_and_input`].
fn molto_early_key<I: crate::secrets::SecretIo>(
    sec: &mut Secrets<I>,
    key: &KeyArgs,
    cmd: &MoltoCmd,
) -> Result<Option<CustomerKey>, String> {
    match cmd {
        MoltoCmd::Import { file: Some(_), .. } => customer_key(sec, key).map(Some),
        _ => Ok(None),
    }
}

/// `molto import --file --dry-run` never uses the customer key. It reads and
/// drops it only when both it and the password are piped on stdin, so the
/// password stays on line 2 as in a real import; at a terminal each is its
/// own prompt, so the key is not asked for.
fn molto_dry_run_key<I: crate::secrets::SecretIo>(
    sec: &mut Secrets<I>,
    key: &KeyArgs,
    password: Option<&SecretSource>,
) -> Result<(), String> {
    let both_piped = matches!(key.customer_key, Some(SecretSource::Stdin))
        && matches!(password, Some(SecretSource::Stdin))
        && !sec.io.stdin_is_terminal();
    if both_piped {
        customer_key(sec, key)?;
    }
    Ok(())
}

/// After any question, with nothing held: the customer key (unless
/// [`molto_early_key`] already read it), then the seed, new key or URI (or
/// the QR image).
fn molto_key_and_input<I: crate::secrets::SecretIo>(
    sec: &mut Secrets<I>,
    key: &KeyArgs,
    cmd: &MoltoCmd,
    early_key: Option<CustomerKey>,
) -> Result<(CustomerKey, MoltoInput), Box<dyn std::error::Error>> {
    let key = match early_key {
        Some(k) => k,
        None => customer_key(sec, key)?,
    };
    // Wire confidentiality for seeds is SM4 keyed off the customer key, and
    // the factory default is public (it ships in every unit and in this
    // source). Programming real seeds under it means anyone holding a USB
    // capture can decrypt them — nudge, don't block.
    if key.as_slice() == DEFAULT_CUSTOMER_KEY
        && matches!(cmd, MoltoCmd::Seed { .. } | MoltoCmd::Import { .. })
    {
        output::warn(
            "using the factory-default customer key — seeds sent to the \
             device are decryptable by anyone who captures the USB traffic. \
             Rotate it first: keyroostctl molto customer-key (see --help).",
        );
    }
    Ok((key, read_molto_input(sec, cmd)?))
}

/// Decode the one account in a QR screenshot, through the same hardened
/// parsers as text input.
fn molto_entry_from_qr(
    image_path: &std::path::Path,
) -> Result<keyroost_import::BulkEntry, Box<dyn std::error::Error>> {
    let bytes =
        std::fs::read(image_path).map_err(|e| format!("read {}: {}", image_path.display(), e))?;
    let import = keyroost_qr::entries_from_image(&bytes)?;
    for s in &import.skipped {
        output::note(&format!("skipped {:?}: {}", s.label, s.reason));
    }
    // A GA export can span several QR images; a clean single-slot import of
    // QR 1 must not read as "migration complete".
    if let Some((i, n)) = import.batch {
        output::note(&format!(
            "this is QR {} of {} in the export — import the other images too",
            i + 1,
            n
        ));
    }
    match import.entries.len() {
        0 => Err("QR decoded, but no account could be imported (see skips above)".into()),
        1 => Ok(import.entries.into_iter().next().unwrap()),
        n => Err(format!(
            "QR contains {} accounts — use `molto import --file {}` to program them \
             into consecutive slots",
            n,
            image_path.display()
        )
        .into()),
    }
}

/// The token reopened after a question must be the one the question was
/// about. `None`: no session was open before (nothing to compare).
fn same_molto(before: Option<&str>, now: &str) -> Result<(), String> {
    match before {
        Some(b) if b != now => {
            Err("the Molto2 changed while waiting for a confirmation or a typed secret; nothing was changed".into())
        }
        _ => Ok(()),
    }
}

/// [`same_molto`] for the programmable token.
fn same_prog_token(before: &str, now: &str) -> Result<(), String> {
    if before != now {
        return Err(
            "the programmable token changed while waiting for a confirmation or a typed secret; nothing was changed"
                .into(),
        );
    }
    Ok(())
}

fn unix_now() -> u32 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as u32,
        Err(_) => {
            // A pre-1970 clock would otherwise silently program time 0 into
            // the device (configure / sync / key registration).
            output::warn("system clock reads before 1970; using time 0");
            0
        }
    }
}

/// Clap value parser: reject a `piv cert generate`/`piv chuid generate` `--days` value beyond what a
/// certificate's validity period or a CHUID's expiration date can actually
/// represent ([`keyroost_piv::max_valid_days`]), instead of letting it
/// silently saturate deep in the encoder (`der_time`/`chuid_expiration_in_days`
/// both clamp to the same `9999-12-31` ceiling on their own, but a caller
/// asking for more than that deserves a clear error, not a silently
/// shorter validity period than what they typed).
fn parse_valid_days(s: &str) -> Result<u32, String> {
    let days: u32 = s
        .parse()
        .map_err(|_| "--days must be a whole number".to_string())?;
    let max = keyroost_piv::max_valid_days(u64::from(unix_now()));
    if days > max {
        return Err(format!(
            "--days exceeds the largest representable validity ({max} days \
             from now) — a CHUID/certificate date is a 4-digit year, capped at \
             9999-12-31"
        ));
    }
    Ok(days)
}

/// The years counterpart of [`parse_valid_days`] — same rationale, same
/// 9999-12-31 ceiling, just checked against [`keyroost_piv::max_valid_years`]
/// instead.
fn parse_valid_years(s: &str) -> Result<u32, String> {
    let years: u32 = s
        .parse()
        .map_err(|_| "--years must be a whole number".to_string())?;
    let max = keyroost_piv::max_valid_years(u64::from(unix_now()));
    if years > max {
        return Err(format!(
            "--years exceeds the largest representable validity ({max} years \
             from now) — a CHUID/certificate date is a 4-digit year, capped at \
             9999-12-31"
        ));
    }
    Ok(years)
}

/// The months counterpart of [`parse_valid_days`]/[`parse_valid_years`] —
/// same rationale, same 9999-12-31 ceiling, checked against
/// [`keyroost_piv::max_valid_months`].
fn parse_valid_months(s: &str) -> Result<u32, String> {
    let months: u32 = s
        .parse()
        .map_err(|_| "--months must be a whole number".to_string())?;
    let max = keyroost_piv::max_valid_months(u64::from(unix_now()));
    if months > max {
        return Err(format!(
            "--months exceeds the largest representable validity ({max} months \
             from now) — a CHUID/certificate date is a 4-digit year, capped at \
             9999-12-31"
        ));
    }
    Ok(months)
}

/// `piv cert generate` and `piv chuid generate` both take a `--days`/`--months`/
/// `--years` triple that freely combines and sums (e.g. `--years 1 --days 5`
/// is 1 year and 5 additional days from now, applied in that order — see
/// [`keyroost_piv::add_calendar_period`]); `None`/`None`/`None` — no flag
/// given — resolves to a 1-year default rather than each call site
/// re-deriving it.
#[derive(Debug, PartialEq, Eq)]
struct ValidFor {
    years: u32,
    months: u32,
    days: u32,
}

impl ValidFor {
    fn resolve(days: Option<u32>, months: Option<u32>, years: Option<u32>) -> ValidFor {
        if days.is_none() && months.is_none() && years.is_none() {
            return ValidFor {
                years: 1,
                months: 0,
                days: 0,
            };
        }
        ValidFor {
            years: years.unwrap_or(0),
            months: months.unwrap_or(0),
            days: days.unwrap_or(0),
        }
    }

    /// Reject an all-zero period. Each unit's own ceiling is already enforced
    /// by its clap value parser (`parse_valid_days`/`_months`/`_years`, each
    /// independently computed from "now") — a conservative check when units
    /// combine (adding years first only ever shrinks the days/months budget
    /// left before 9999-12-31, so a component that already fits its own
    /// from-now ceiling always fits the summed one too); the actual encoder
    /// clamps the summed result as a backstop regardless (see
    /// `parse_valid_days`'s doc comment for why a clear error is still
    /// preferred over that silent saturation for the common single-unit
    /// case).
    fn check(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.years == 0 && self.months == 0 && self.days == 0 {
            return Err("validity must be at least 1 day".into());
        }
        Ok(())
    }

    /// Unix seconds this period ends at, starting from `now_unix_secs`.
    fn end_unix_secs(&self, now_unix_secs: u64) -> i64 {
        keyroost_piv::add_calendar_period(now_unix_secs, self.years, self.months, self.days)
    }

    /// CHUID expiration (`YYYYMMDD`) this period produces from `now_unix_secs`.
    fn chuid_expiration(&self, now_unix_secs: u64) -> [u8; 8] {
        keyroost_piv::yyyymmdd_from_unix_secs(self.end_unix_secs(now_unix_secs))
    }

    fn describe(&self) -> String {
        let mut parts = Vec::new();
        if self.years > 0 {
            parts.push(format!(
                "{} year{}",
                self.years,
                if self.years == 1 { "" } else { "s" }
            ));
        }
        if self.months > 0 {
            parts.push(format!(
                "{} month{}",
                self.months,
                if self.months == 1 { "" } else { "s" }
            ));
        }
        if self.days > 0 {
            parts.push(format!(
                "{} day{}",
                self.days,
                if self.days == 1 { "" } else { "s" }
            ));
        }
        parts.join(", ")
    }
}

/// The slots a bulk import writes: consecutive from `start`, leaving out the
/// entries it skips (no issuer or account to title them with).
fn bulk_import_slots(start: u8, entries: &[keyroost_import::BulkEntry]) -> Vec<u8> {
    entries
        .iter()
        .enumerate()
        .filter(|(_, e)| !e.suggested_title().is_empty())
        .filter_map(|(i, _)| u8::try_from(start as usize + i).ok())
        .collect()
}

/// Which of `slots` already hold a seed (read-only; no customer key).
fn molto_occupied(
    session: &mut Session,
    slots: impl IntoIterator<Item = u8>,
) -> Result<Vec<u8>, TransportError> {
    let mut out = Vec::new();
    for p in slots {
        if session.read_public_data(p)?.seed_present {
            out.push(p);
        }
    }
    Ok(out)
}

/// Load a bulk-import file, transparently decrypting an Aegis encrypted
/// vault if `--password` was supplied.
fn load_bulk_entries<I: crate::secrets::SecretIo>(
    sec: &mut Secrets<I>,
    path: &std::path::Path,
    password: Option<&SecretSource>,
) -> Result<Vec<keyroost_import::BulkEntry>, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {}: {}", path.display(), e))?;

    // Screenshot import: a PNG/JPEG (by magic bytes) goes through QR decode,
    // accepting both a single otpauth:// enrollment code and a Google
    // Authenticator export batch.
    if keyroost_qr::looks_like_image(&bytes) {
        let import = keyroost_qr::entries_from_image(&bytes)?;
        for s in &import.skipped {
            output::note(&format!("skipped {:?}: {}", s.label, s.reason));
        }
        if let Some((i, n)) = import.batch {
            output::note(&format!(
                "this is QR {} of {} in the export — import the other images too",
                i + 1,
                n
            ));
        }
        output::note("remember to delete the screenshot after a successful import");
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
        let password = sec.read(&VAULT_PASSWORD, Source::from_flag(password))?;
        let plaintext = keyroost_import::aegis::decrypt(&text, password.as_bytes())?;
        return Ok(keyroost_import::aegis::parse(&plaintext)?);
    }

    if password.is_some() {
        output::warn("password supplied but file is not an encrypted Aegis vault");
    }
    Ok(keyroost_import::parse_bulk_any(&text)?)
}

/// `--device` on a command that never touches a key is a mistake (it used
/// to be silently ignored). `list` and the bare overview filter by it.
/// The usage mistake in `otp list --unlock fingerprint --pin SOURCE`:
/// a fingerprint unlock takes no PIN. clap can't tie a conflict to one value
/// of `--unlock`, so `run` checks this straight after parsing and exits 2,
/// like any other usage error, before a key is looked at.
fn otp_unlock_conflict(cmd: Option<&Cmd>) -> Option<&'static str> {
    match cmd {
        Some(Cmd::Otp {
            cmd:
                OtpCmd::List {
                    unlock: OtpUnlock::Fingerprint,
                    pin,
                },
            ..
        }) if pin.is_some() => Some(
            "`--unlock fingerprint` takes no PIN; drop --pin, or use --unlock auto for a PIN fallback",
        ),
        _ => None,
    }
}

fn inert_device_flag(cmd: Option<&Cmd>) -> Option<&'static str> {
    match cmd? {
        Cmd::Doctor => Some("doctor"),
        Cmd::Completions { .. } => Some("completions"),
        Cmd::Manpage { .. } => Some("manpage"),
        Cmd::Name { cmd: NameCmd::List } => Some("name list"),
        Cmd::Name {
            cmd: NameCmd::Delete { .. },
        } => Some("name delete"),
        Cmd::Molto {
            cmd: MoltoCmd::Import { dry_run: true, .. },
            ..
        } => Some("molto import --dry-run"),
        _ => None,
    }
}

/// Rows to show for `list` / the bare overview: every row numbered in `list`
/// order with no `--device`, or the one row it names (an unknown value is an
/// error naming the fix, via [`keyroost_resolve::resolve_target`]).
fn filter_rows<'d>(
    devices: &'d [keyroost_resolve::Device],
    device: Option<&str>,
) -> Result<Vec<(usize, &'d keyroost_resolve::Device)>, Box<dyn std::error::Error>> {
    match device {
        None => Ok(overview::numbered(devices)),
        Some(v) => {
            let s = keyroost_resolve::Selector {
                device: Some(v),
                ..Default::default()
            };
            let t = keyroost_resolve::resolve_target(
                devices,
                &s,
                Need::Any,
                &mut keyroost_resolve::NoPicker,
            )?;
            Ok(vec![(t.number, t.device)])
        }
    }
}

/// `list --json` rows for `rows` (already numbered/filtered by [`filter_rows`]).
fn list_json_rows(
    devices: &[keyroost_resolve::Device],
    rows: &[(usize, &keyroost_resolve::Device)],
) -> Vec<json_out::ListRowJson> {
    use keyroost_resolve::{CapState, DeviceKind};
    rows.iter()
        .map(|(n, d)| {
            let idx = devices
                .iter()
                .position(|x| std::ptr::eq(x, *d))
                .expect("row device must come from the same device list");
            json_out::ListRowJson {
                number: *n,
                device: keyroost_resolve::device_value(devices, idx),
                name: d.name.clone(),
                vendor: d.vendor.clone(),
                model: d.model.clone(),
                serial: d.serial.clone(),
                kind: match d.kind {
                    DeviceKind::Key => "key",
                    DeviceKind::Token => "token",
                    DeviceKind::ProgToken => "prog-token",
                },
                capabilities: d.cap_badges(),
                capabilities_unverified: d
                    .cap_badge_states()
                    .into_iter()
                    .filter(|(_, s)| *s == CapState::Unverified)
                    .map(|(l, _)| l)
                    .collect(),
                readers: d.reader.iter().cloned().collect(),
                hid_paths: d.hid_path.iter().map(|p| p.display().to_string()).collect(),
            }
        })
        .collect()
}

/// A removed or renamed flag. `words` must all appear in argv for the row
/// to apply (empty = any command); `msg` is static text that never repeats
/// a value; `now` lists the flags `msg` recommends, each of which exists
/// on that command (checked by `retired_flag_rows_name_real_flags`).
/// Specific rows come before generic (`words: &[]`) ones.
struct RetiredFlag {
    flag: &'static str,
    words: &'static [&'static str],
    msg: &'static str,
    #[cfg_attr(
        not(test),
        allow(dead_code, reason = "checked by retired_flag_rows_name_real_flags")
    )]
    now: &'static [&'static str],
}

/// clap only hands us the flag name, never its value or the next token, so
/// nothing a user typed can leak through these messages.
const RETIRED_FLAGS: &[RetiredFlag] = &[
    RetiredFlag {
        flag: "--admin-pin-env",
        words: &["openpgp", "pin", "change", "--admin"],
        msg: "--admin-pin-env was removed: with --admin, --pin is the admin PIN \
              (--pin env:NAME or --pin stdin)",
        now: &["--pin"],
    },
    RetiredFlag {
        flag: "--admin-pin-stdin",
        words: &["openpgp", "pin", "change", "--admin"],
        msg: "--admin-pin-stdin was removed: with --admin, --pin is the admin PIN \
              (--pin env:NAME or --pin stdin)",
        now: &["--pin"],
    },
    RetiredFlag {
        flag: "-p",
        words: &["molto"],
        msg: "-p/--profile was renamed -s/--slot (Token2 calls slots profiles)",
        now: &["--slot"],
    },
    RetiredFlag {
        flag: "--profile",
        words: &["molto"],
        msg: "-p/--profile was renamed -s/--slot (Token2 calls slots profiles)",
        now: &["--slot"],
    },
    RetiredFlag {
        flag: "--time-step",
        words: &["molto"],
        msg: "--time-step was renamed --period (same values: 30 or 60)",
        now: &["--period"],
    },
    RetiredFlag {
        flag: "--time-step",
        words: &["prog"],
        msg: "--time-step was renamed --period (same values: 30 or 60)",
        now: &["--period"],
    },
    RetiredFlag {
        flag: "--key",
        words: &["molto"],
        msg: "--key was removed (a secret on the command line ends up in shell history and `ps`): use --customer-key env:NAME",
        now: &["--customer-key"],
    },
    RetiredFlag {
        flag: "--key-ascii",
        words: &["molto"],
        msg: "--key-ascii was removed (a secret on the command line ends up in shell history and `ps`): use --customer-key env:NAME --customer-key-encoding ascii",
        now: &["--customer-key", "--customer-key-encoding"],
    },
    RetiredFlag {
        flag: "--key-env",
        words: &["molto"],
        msg: "--key-env VAR is now --customer-key env:VAR",
        now: &["--customer-key"],
    },
    RetiredFlag {
        flag: "--key-ascii-env",
        words: &["molto"],
        msg: "--key-ascii-env VAR is now --customer-key env:VAR --customer-key-encoding ascii",
        now: &["--customer-key", "--customer-key-encoding"],
    },
    RetiredFlag {
        flag: "--hex",
        words: &["customer-key"],
        msg: "--hex was removed (a secret on the command line ends up in shell history and `ps`): use --new-customer-key env:NAME (hex is the default encoding)",
        now: &["--new-customer-key"],
    },
    RetiredFlag {
        flag: "--ascii",
        words: &["customer-key"],
        msg: "--ascii was removed (a secret on the command line ends up in shell history and `ps`): use --new-customer-key env:NAME --encoding ascii",
        now: &["--new-customer-key", "--encoding"],
    },
    RetiredFlag {
        flag: "--hex-env",
        words: &["customer-key"],
        msg: "--hex-env VAR is now --new-customer-key env:VAR (hex is the default encoding)",
        now: &["--new-customer-key"],
    },
    RetiredFlag {
        flag: "--hex-stdin",
        words: &["customer-key"],
        msg: "--hex-stdin is now --new-customer-key stdin (hex is the default encoding)",
        now: &["--new-customer-key"],
    },
    RetiredFlag {
        flag: "--ascii-env",
        words: &["customer-key"],
        msg: "--ascii-env VAR is now --new-customer-key env:VAR --encoding ascii",
        now: &["--new-customer-key", "--encoding"],
    },
    RetiredFlag {
        flag: "--ascii-stdin",
        words: &["customer-key"],
        msg: "--ascii-stdin is now --new-customer-key stdin --encoding ascii",
        now: &["--new-customer-key", "--encoding"],
    },
    RetiredFlag {
        flag: "--hex",
        words: &["seed"],
        msg: "--hex was removed (a secret on the command line ends up in shell history and `ps`): use --seed env:NAME --encoding hex",
        now: &["--seed", "--encoding"],
    },
    RetiredFlag {
        flag: "--base32",
        words: &["seed"],
        msg: "--base32 was removed (a secret on the command line ends up in shell history and `ps`): use --seed env:NAME (base32 is the default encoding)",
        now: &["--seed"],
    },
    RetiredFlag {
        flag: "--hex-env",
        words: &["seed"],
        msg: "--hex-env VAR is now --seed env:VAR --encoding hex",
        now: &["--seed", "--encoding"],
    },
    RetiredFlag {
        flag: "--hex-stdin",
        words: &["seed"],
        msg: "--hex-stdin is now --seed stdin --encoding hex",
        now: &["--seed", "--encoding"],
    },
    RetiredFlag {
        flag: "--base32-env",
        words: &["seed"],
        msg: "--base32-env VAR is now --seed env:VAR (base32 is the default encoding)",
        now: &["--seed"],
    },
    RetiredFlag {
        flag: "--base32-stdin",
        words: &["seed"],
        msg: "--base32-stdin is now --seed stdin (base32 is the default encoding)",
        now: &["--seed"],
    },
    RetiredFlag {
        flag: "--secret-env",
        words: &["oath"],
        msg: "--secret-env VAR is now --seed env:VAR",
        now: &["--seed"],
    },
    RetiredFlag {
        flag: "--secret-stdin",
        words: &["oath"],
        msg: "--secret-stdin is now --seed stdin",
        now: &["--seed"],
    },
    RetiredFlag {
        flag: "--current-env",
        words: &["otp"],
        msg: "--current-env VAR is now --pin env:VAR (the current PIN)",
        now: &["--pin"],
    },
    RetiredFlag {
        flag: "--new-env",
        words: &["otp"],
        msg: "--new-env VAR is now --new-pin env:VAR",
        now: &["--new-pin"],
    },
    RetiredFlag {
        flag: "--pin-stdin",
        words: &["otp", "pin", "change"],
        msg: "--pin-stdin is now --pin stdin --new-pin stdin: the current PIN on the first line, the new one on the second",
        now: &["--pin", "--new-pin"],
    },
    RetiredFlag {
        flag: "--pin-env",
        words: &["otp", "pin", "set"],
        msg: "--pin-env VAR is now --new-pin env:VAR (the PIN being set)",
        now: &["--new-pin"],
    },
    RetiredFlag {
        flag: "--pin-stdin",
        words: &["otp", "pin", "set"],
        msg: "--pin-stdin is now --new-pin stdin (the PIN being set)",
        now: &["--new-pin"],
    },
    RetiredFlag {
        flag: "--pin-only",
        words: &["otp", "list"],
        msg: "--pin-only was replaced by --unlock pin, the default",
        now: &["--unlock"],
    },
    RetiredFlag {
        flag: "--start",
        words: &["molto", "import"],
        msg: "--start is now -s/--slot (with --file, the first slot to fill)",
        now: &["--slot"],
    },
    RetiredFlag {
        flag: "--which",
        words: &["openpgp", "pin", "verify"],
        msg: "--which admin is now --admin (without it, the user PIN is checked)",
        now: &["--admin"],
    },
    RetiredFlag {
        flag: "--file",
        words: &["piv", "cert", "import"],
        msg: "--file was renamed -i/--in (the certificate file to read)",
        now: &["--in"],
    },
    RetiredFlag {
        flag: "--file",
        words: &["piv", "cert", "export"],
        msg: "--file was renamed -o/--out (the file to write)",
        now: &["--out"],
    },
    RetiredFlag {
        flag: "--file",
        words: &["piv", "cert", "request"],
        msg: "--file was renamed -o/--out (the file to write)",
        now: &["--out"],
    },
    RetiredFlag {
        flag: "--file",
        words: &["piv", "cert", "generate"],
        msg: "--file was renamed -o/--out (the file to write)",
        now: &["--out"],
    },
    RetiredFlag {
        flag: "--save-pubkey",
        words: &["piv", "key", "generate"],
        msg: "--save-pubkey is now -o/--out (the public key file)",
        now: &["--out"],
    },
    RetiredFlag {
        flag: "--save-pubkey",
        words: &["piv", "cert"],
        msg: "--save-pubkey is now --pubkey-out (with --generate-key)",
        now: &["--pubkey-out"],
    },
    RetiredFlag {
        flag: "--load-pubkey",
        words: &["piv", "cert"],
        msg: "--load-pubkey is now --pubkey-in",
        now: &["--pubkey-in"],
    },
    RetiredFlag {
        flag: "--new-algorithm",
        words: &["piv", "mgmt-key"],
        msg: "--new-algorithm is now --algorithm (of the new management key)",
        now: &["--algorithm"],
    },
    RetiredFlag {
        flag: "--force",
        words: &["fido", "ssh", "extract"],
        msg: "--force was renamed --overwrite (replace an existing file)",
        now: &["--overwrite"],
    },
    RetiredFlag {
        flag: "--cred-id",
        words: &["fido", "credential"],
        msg: "--cred-id is now --id",
        now: &["--id"],
    },
    RetiredFlag {
        flag: "--template-id",
        words: &["fido", "fingerprint"],
        msg: "--template-id is now --id",
        now: &["--id"],
    },
    RetiredFlag {
        flag: "--credential",
        words: &["fido", "ssh"],
        msg: "--credential is now --id (the SSH credential's RP ID)",
        now: &["--id"],
    },
    RetiredFlag {
        flag: "--list-readers",
        words: &[],
        msg: "--list-readers was removed; `keyroostctl list` shows the smart-card readers",
        now: &[],
    },
    // Generic: a retired flag family, on any command. Keep these last.
    RetiredFlag {
        flag: "--pin-env",
        words: &[],
        msg: "--pin-env VAR is now --pin env:VAR",
        now: &["--pin"],
    },
    RetiredFlag {
        flag: "--pin-stdin",
        words: &[],
        msg: "--pin-stdin is now --pin stdin",
        now: &["--pin"],
    },
    RetiredFlag {
        flag: "--old-pin-env",
        words: &[],
        msg: "--old-pin-env VAR is now --pin env:VAR (the current PIN)",
        now: &["--pin"],
    },
    RetiredFlag {
        flag: "--old-pin-stdin",
        words: &[],
        msg: "--old-pin-stdin is now --pin stdin (the current PIN)",
        now: &["--pin"],
    },
    RetiredFlag {
        flag: "--new-pin-env",
        words: &[],
        msg: "--new-pin-env VAR is now --new-pin env:VAR",
        now: &["--new-pin"],
    },
    RetiredFlag {
        flag: "--new-pin-stdin",
        words: &[],
        msg: "--new-pin-stdin is now --new-pin stdin",
        now: &["--new-pin"],
    },
    RetiredFlag {
        flag: "--puk-env",
        words: &[],
        msg: "--puk-env VAR is now --puk env:VAR",
        now: &["--puk"],
    },
    RetiredFlag {
        flag: "--puk-stdin",
        words: &[],
        msg: "--puk-stdin is now --puk stdin",
        now: &["--puk"],
    },
    RetiredFlag {
        flag: "--old-puk-env",
        words: &[],
        msg: "--old-puk-env VAR is now --puk env:VAR (the current PUK)",
        now: &["--puk"],
    },
    RetiredFlag {
        flag: "--old-puk-stdin",
        words: &[],
        msg: "--old-puk-stdin is now --puk stdin (the current PUK)",
        now: &["--puk"],
    },
    RetiredFlag {
        flag: "--new-puk-env",
        words: &[],
        msg: "--new-puk-env VAR is now --new-puk env:VAR",
        now: &["--new-puk"],
    },
    RetiredFlag {
        flag: "--new-puk-stdin",
        words: &[],
        msg: "--new-puk-stdin is now --new-puk stdin",
        now: &["--new-puk"],
    },
    RetiredFlag {
        flag: "--admin-pin-env",
        words: &[],
        msg: "--admin-pin-env VAR is now --admin-pin env:VAR",
        now: &["--admin-pin"],
    },
    RetiredFlag {
        flag: "--admin-pin-stdin",
        words: &[],
        msg: "--admin-pin-stdin is now --admin-pin stdin",
        now: &["--admin-pin"],
    },
    RetiredFlag {
        flag: "--mgmt-key-env",
        words: &[],
        msg: "--mgmt-key-env VAR is now --mgmt-key env:VAR",
        now: &["--mgmt-key"],
    },
    RetiredFlag {
        flag: "--mgmt-key-stdin",
        words: &[],
        msg: "--mgmt-key-stdin is now --mgmt-key stdin",
        now: &["--mgmt-key"],
    },
    RetiredFlag {
        flag: "--mgmt-key-default",
        words: &[],
        msg: "--mgmt-key-default is now --mgmt-key default",
        now: &["--mgmt-key"],
    },
    RetiredFlag {
        flag: "--old-mgmt-key-env",
        words: &[],
        msg: "--old-mgmt-key-env VAR is now --mgmt-key env:VAR (the current management key)",
        now: &["--mgmt-key"],
    },
    RetiredFlag {
        flag: "--old-mgmt-key-stdin",
        words: &[],
        msg: "--old-mgmt-key-stdin is now --mgmt-key stdin (the current management key)",
        now: &["--mgmt-key"],
    },
    RetiredFlag {
        flag: "--old-mgmt-key-default",
        words: &[],
        msg: "--old-mgmt-key-default is now --mgmt-key default (the current management key)",
        now: &["--mgmt-key"],
    },
    RetiredFlag {
        flag: "--new-mgmt-key-env",
        words: &[],
        msg: "--new-mgmt-key-env VAR is now --new-mgmt-key env:VAR",
        now: &["--new-mgmt-key"],
    },
    RetiredFlag {
        flag: "--new-mgmt-key-stdin",
        words: &[],
        msg: "--new-mgmt-key-stdin is now --new-mgmt-key stdin",
        now: &["--new-mgmt-key"],
    },
    RetiredFlag {
        flag: "--password-env",
        words: &[],
        msg: "--password-env VAR is now --password env:VAR",
        now: &["--password"],
    },
    RetiredFlag {
        flag: "--password-stdin",
        words: &[],
        msg: "--password-stdin is now --password stdin",
        now: &["--password"],
    },
    RetiredFlag {
        flag: "--new-password-env",
        words: &[],
        msg: "--new-password-env VAR is now --new-password env:VAR",
        now: &["--new-password"],
    },
    RetiredFlag {
        flag: "--new-password-stdin",
        words: &[],
        msg: "--new-password-stdin is now --new-password stdin",
        now: &["--new-password"],
    },
    RetiredFlag {
        flag: "--seed-env",
        words: &[],
        msg: "--seed-env VAR is now --seed env:VAR",
        now: &["--seed"],
    },
    RetiredFlag {
        flag: "--seed-stdin",
        words: &[],
        msg: "--seed-stdin is now --seed stdin",
        now: &["--seed"],
    },
    RetiredFlag {
        flag: "--uri-env",
        words: &[],
        msg: "--uri-env VAR is now --uri env:VAR",
        now: &["--uri"],
    },
];

/// A renamed or removed subcommand. `parent` is the command path above it
/// ("" for top level, "fido", "fido config"), `old` the retired word,
/// `new` the full command to use now (it may end in flags), `note` an
/// optional extra clause.
struct RetiredCommand {
    parent: &'static str,
    old: &'static str,
    new: &'static str,
    note: &'static str,
}

const RETIRED_COMMANDS: &[RetiredCommand] = &[
    RetiredCommand {
        parent: "fido",
        old: "pin-set",
        new: "fido pin set",
        note: "",
    },
    RetiredCommand {
        parent: "fido",
        old: "pin-change",
        new: "fido pin change",
        note: "",
    },
    RetiredCommand {
        parent: "fido",
        old: "pin-retries",
        new: "fido pin retries",
        note: "",
    },
    RetiredCommand {
        parent: "fido",
        old: "creds-list",
        new: "fido credential list",
        note: "",
    },
    RetiredCommand {
        parent: "fido",
        old: "creds-delete",
        new: "fido credential delete",
        note: "",
    },
    RetiredCommand {
        parent: "fido",
        old: "creds-metadata",
        new: "fido credential metadata",
        note: "",
    },
    RetiredCommand {
        parent: "fido",
        old: "fingerprint-list",
        new: "fido fingerprint list",
        note: "",
    },
    RetiredCommand {
        parent: "fido",
        old: "fingerprint-enroll",
        new: "fido fingerprint add",
        note: "",
    },
    RetiredCommand {
        parent: "fido",
        old: "fingerprint-rename",
        new: "fido fingerprint rename",
        note: "",
    },
    RetiredCommand {
        parent: "fido",
        old: "fingerprint-delete",
        new: "fido fingerprint delete",
        note: "",
    },
    RetiredCommand {
        parent: "fido",
        old: "always-uv",
        new: "fido config always-uv enable",
        note: "or `fido config always-uv disable`; no longer a toggle",
    },
    RetiredCommand {
        parent: "fido",
        old: "set-min-pin",
        new: "fido pin min-length",
        note: "",
    },
    RetiredCommand {
        parent: "fido",
        old: "force-pin-change",
        new: "fido pin force-change",
        note: "",
    },
    RetiredCommand {
        parent: "fido",
        old: "enterprise-attestation",
        new: "fido config attestation enable",
        note: "",
    },
    RetiredCommand {
        parent: "fido",
        old: "large-blob",
        new: "fido blob",
        note: "same subcommands",
    },
    RetiredCommand {
        parent: "fido",
        old: "ssh-cert",
        new: "fido ssh",
        note: "same subcommands",
    },
    RetiredCommand {
        parent: "fido",
        old: "credentials",
        new: "fido credential",
        note: "same subcommands",
    },
    RetiredCommand {
        parent: "fido",
        old: "fingerprints",
        new: "fido fingerprint",
        note: "same subcommands",
    },
    RetiredCommand {
        parent: "fido config",
        old: "enable-always-uv",
        new: "fido config always-uv enable",
        note: "",
    },
    RetiredCommand {
        parent: "fido config",
        old: "disable-always-uv",
        new: "fido config always-uv disable",
        note: "",
    },
    RetiredCommand {
        parent: "fido config",
        old: "set-min-pin-length",
        new: "fido pin min-length",
        note: "",
    },
    RetiredCommand {
        parent: "fido config",
        old: "force-pin-change",
        new: "fido pin force-change",
        note: "",
    },
    RetiredCommand {
        parent: "fido config",
        old: "enable-enterprise-attestation",
        new: "fido config attestation enable",
        note: "",
    },
    RetiredCommand {
        parent: "",
        old: "key-name",
        new: "name",
        note: "`key-name remove` is now `name delete`",
    },
    RetiredCommand {
        parent: "piv",
        old: "status",
        new: "piv info",
        note: "",
    },
    RetiredCommand {
        parent: "piv",
        old: "change-pin",
        new: "piv pin change",
        note: "",
    },
    RetiredCommand {
        parent: "piv",
        old: "unblock-pin",
        new: "piv pin unblock",
        note: "",
    },
    RetiredCommand {
        parent: "piv",
        old: "change-puk",
        new: "piv puk change",
        note: "",
    },
    RetiredCommand {
        parent: "piv",
        old: "set-retries",
        new: "piv retries set",
        note: "",
    },
    RetiredCommand {
        parent: "piv",
        old: "change-management-key",
        new: "piv mgmt-key change",
        note: "",
    },
    RetiredCommand {
        parent: "piv",
        old: "generate-key",
        new: "piv key generate",
        note: "",
    },
    RetiredCommand {
        parent: "piv",
        old: "delete-key",
        new: "piv key delete",
        note: "",
    },
    RetiredCommand {
        parent: "piv",
        old: "move-key",
        new: "piv key move",
        note: "",
    },
    RetiredCommand {
        parent: "piv",
        old: "import-cert",
        new: "piv cert import",
        note: "",
    },
    RetiredCommand {
        parent: "piv",
        old: "export-cert",
        new: "piv cert export",
        note: "",
    },
    RetiredCommand {
        parent: "piv",
        old: "delete-cert",
        new: "piv cert delete",
        note: "",
    },
    RetiredCommand {
        parent: "piv",
        old: "request-cert",
        new: "piv cert request",
        note: "",
    },
    RetiredCommand {
        parent: "piv",
        old: "self-sign",
        new: "piv cert generate",
        note: "",
    },
    RetiredCommand {
        parent: "piv",
        old: "new-chuid",
        new: "piv chuid generate",
        note: "",
    },
    RetiredCommand {
        parent: "openpgp",
        old: "status",
        new: "openpgp info",
        note: "",
    },
    RetiredCommand {
        parent: "openpgp",
        old: "verify",
        new: "openpgp pin verify",
        note: "the admin PIN is `--admin`",
    },
    RetiredCommand {
        parent: "openpgp",
        old: "change-pin",
        new: "openpgp pin change",
        note: "",
    },
    RetiredCommand {
        parent: "openpgp",
        old: "change-admin-pin",
        new: "openpgp pin change --admin",
        note: "",
    },
    RetiredCommand {
        parent: "openpgp",
        old: "unblock-pin",
        new: "openpgp pin unblock",
        note: "",
    },
    RetiredCommand {
        parent: "openpgp",
        old: "generate-key",
        new: "openpgp key generate",
        note: "",
    },
    RetiredCommand {
        parent: "openpgp",
        old: "import-key",
        new: "openpgp key import",
        note: "",
    },
    RetiredCommand {
        parent: "openpgp",
        old: "public-key",
        new: "openpgp key show",
        note: "",
    },
    RetiredCommand {
        parent: "openpgp",
        old: "algorithms",
        new: "openpgp key algorithms",
        note: "",
    },
    RetiredCommand {
        parent: "openpgp",
        old: "set-name",
        new: "openpgp name set",
        note: "",
    },
    RetiredCommand {
        parent: "openpgp",
        old: "set-url",
        new: "openpgp url set",
        note: "",
    },
    RetiredCommand {
        parent: "oath",
        old: "set-password",
        new: "oath password set",
        note: "",
    },
    RetiredCommand {
        parent: "oath",
        old: "clear-password",
        new: "oath password clear",
        note: "",
    },
    RetiredCommand {
        parent: "otp",
        old: "get",
        new: "otp code",
        note: "",
    },
    RetiredCommand {
        parent: "otp",
        old: "config",
        new: "otp info",
        note: "",
    },
    RetiredCommand {
        parent: "otp",
        old: "erase-all",
        new: "otp reset",
        note: "",
    },
    RetiredCommand {
        parent: "otp",
        old: "button-hotp",
        new: "otp button set",
        note: "",
    },
    RetiredCommand {
        parent: "otp",
        old: "set-button-hotp",
        new: "otp button set",
        note: "",
    },
    RetiredCommand {
        parent: "otp",
        old: "delete-button-hotp",
        new: "otp button delete",
        note: "",
    },
    RetiredCommand {
        parent: "otp",
        old: "pin-status",
        new: "otp pin status",
        note: "",
    },
    RetiredCommand {
        parent: "otp",
        old: "set-pin",
        new: "otp pin set",
        note: "",
    },
    RetiredCommand {
        parent: "otp",
        old: "verify",
        new: "otp pin verify",
        note: "",
    },
    RetiredCommand {
        parent: "otp",
        old: "change-pin",
        new: "otp pin change",
        note: "",
    },
    RetiredCommand {
        parent: "otp",
        old: "remove-pin",
        new: "otp pin clear",
        note: "",
    },
    RetiredCommand {
        parent: "otp",
        old: "clear-pin",
        new: "otp pin clear",
        note: "",
    },
    RetiredCommand {
        parent: "otp",
        old: "fp-status",
        new: "otp fingerprint status",
        note: "",
    },
    RetiredCommand {
        parent: "otp",
        old: "fp-enable",
        new: "otp fingerprint enable",
        note: "",
    },
    RetiredCommand {
        parent: "otp",
        old: "fp-disable",
        new: "otp fingerprint disable",
        note: "",
    },
    RetiredCommand {
        parent: "otp",
        old: "fingerprint-status",
        new: "otp fingerprint status",
        note: "",
    },
    RetiredCommand {
        parent: "otp",
        old: "fingerprint-enable",
        new: "otp fingerprint enable",
        note: "",
    },
    RetiredCommand {
        parent: "otp",
        old: "fingerprint-disable",
        new: "otp fingerprint disable",
        note: "",
    },
    RetiredCommand {
        parent: "otp",
        old: "fp-list",
        new: "otp list --unlock fingerprint",
        note: "",
    },
    RetiredCommand {
        parent: "otp",
        old: "unlock-list",
        new: "otp list --unlock auto",
        note: "`--pin-only` is `--unlock pin`, the default",
    },
    RetiredCommand {
        parent: "molto",
        old: "sync-time",
        new: "molto sync",
        note: "",
    },
    RetiredCommand {
        parent: "molto",
        old: "import-file",
        new: "molto import --file",
        note: "the path is the value of `--file`; `--start` is `--slot`",
    },
];

/// The message for a retired subcommand, if clap's unknown subcommand
/// `invalid` is one. Walks `argv` down the real command tree to find the
/// path it was typed under, skipping the value of every flag that takes
/// one (`--device pin-set fido pin-set` resolves to `fido`). The
/// message is static table text: nothing from argv is repeated.
fn retired_command_hint(invalid: &str, argv: &[String]) -> Option<String> {
    use clap::CommandFactory;
    let mut root = Cli::command();
    root.build();
    let (path, _) = walk_argv(&root, argv);
    let parent = path.join(" ");
    RETIRED_COMMANDS
        .iter()
        .find(|r| r.parent == parent && r.old == invalid)
        .map(|r| {
            let old = if r.parent.is_empty() {
                r.old.to_string()
            } else {
                format!("{} {}", r.parent, r.old)
            };
            let note = if r.note.is_empty() {
                String::new()
            } else {
                format!(" ({})", r.note)
            };
            format!("`keyroostctl {old}` is now `keyroostctl {}`{note}", r.new)
        })
}

/// The deepest command `argv` names, built.
fn command_in_argv(argv: &[String]) -> clap::Command {
    use clap::CommandFactory;
    let mut root = Cli::command();
    root.build();
    let (_, cmd) = walk_argv(&root, argv);
    cmd.clone()
}

/// Walk `argv` down `root`'s tree: the subcommand path and the deepest
/// command, skipping the value of every flag that takes one.
fn walk_argv<'c>(root: &'c clap::Command, argv: &[String]) -> (Vec<&'c str>, &'c clap::Command) {
    let mut cmd = root;
    let mut path: Vec<&str> = Vec::new();
    let mut words = argv.iter().skip(1);
    while let Some(word) = words.next() {
        if word == "--" {
            break;
        }
        if let Some(long) = word.strip_prefix("--") {
            let takes_value = cmd
                .get_arguments()
                .any(|a| a.get_long() == Some(long) && a.get_action().takes_values());
            if takes_value {
                words.next();
            }
            continue;
        }
        if word.starts_with('-') {
            continue;
        }
        match cmd.find_subcommand(word) {
            Some(sub) => {
                path.push(sub.get_name());
                cmd = sub;
            }
            None => break,
        }
    }
    (path, cmd)
}

/// A friendly hint for a removed or renamed secret-bearing flag, or `None` if
/// `invalid` isn't one of ours (or the surrounding argv doesn't match, so an
/// unrelated flag of the same name elsewhere isn't misdiagnosed). The rows
/// stay inert until each flag is actually removed from its `clap` struct:
/// clap only raises `UnknownArgument` for flags it no longer knows about.
///
/// A generic row (any command) names its replacement only when the command
/// typed has it; otherwise the message lists the secret flags it does have
/// (`--pin-env` on `openpgp name set` points at `--admin-pin`).
fn retired_flag_hint(invalid: &str, argv: &[String]) -> Option<String> {
    let r = RETIRED_FLAGS
        .iter()
        .find(|r| r.flag == invalid && r.words.iter().all(|w| argv.iter().any(|a| a == w)))?;
    if !r.words.is_empty() || r.now.is_empty() {
        return Some(r.msg.to_string());
    }
    let cmd = command_in_argv(argv);
    let has = |f: &str| {
        cmd.get_arguments()
            .any(|a| a.get_long() == Some(f.trim_start_matches('-')))
    };
    if r.now.iter().all(|f| has(f)) {
        return Some(r.msg.to_string());
    }
    let own: Vec<String> = cmd
        .get_arguments()
        .filter(|a| is_secret_arg(a))
        .filter_map(|a| a.get_long())
        .map(|l| format!("--{l}"))
        .collect();
    Some(match own.as_slice() {
        [] => format!("{invalid} was removed, and this command takes no secret"),
        [one] => format!(
            "{invalid} was removed, and this command has no {}: its secret flag is {one} \
             (env:NAME or stdin)",
            r.now.join("/")
        ),
        _ => format!(
            "{invalid} was removed, and this command has no {}: its secret flags are {} \
             (env:NAME or stdin)",
            r.now.join("/"),
            own.join(", ")
        ),
    })
}

/// A double-dash word made only of letters and dashes — a typo'd flag name
/// (`--hexx-stdin`), never a secret. clap's own "similar argument" tip is
/// more useful here than hiding it, so this shape is always let through.
fn looks_like_flag_typo(word: &str) -> bool {
    word.strip_prefix("--").is_some_and(|rest| {
        !rest.is_empty() && rest.chars().all(|c| c.is_ascii_alphabetic() || c == '-')
    })
}

/// Whether `argv` has a word starting with `prefix` right after a secret
/// source (`--pin stdin`, `--pin env:NAME`, `--mgmt-key default`, or the
/// same with `=`). clap's `UnknownArgument` context
/// sometimes names only a prefix of the real word (`-1` for `-123456`), so
/// this matches by prefix.
fn secret_flag_precedes(argv: &[String], prefix: &str) -> bool {
    let is_source = |w: &str| w == "stdin" || w == "default" || w.starts_with("env:");
    argv.windows(2).any(|w| {
        let value = match w[0].split_once('=') {
            Some((flag, value)) if flag.starts_with("--") => value,
            _ => w[0].as_str(),
        };
        w[1].starts_with(prefix) && is_source(value)
    })
}

/// Whether `value` is the word after a flag that directly follows a secret
/// source (`--seed stdin -s VALUE`, `--seed=env:X --slot VALUE`).
fn value_follows_source(argv: &[String], value: &str) -> bool {
    let is_source = |w: &str| w == "stdin" || w == "default" || w.starts_with("env:");
    argv.windows(3).any(|w| {
        let source = match w[0].split_once('=') {
            Some((flag, v)) if flag.starts_with("--") => v,
            _ => w[0].as_str(),
        };
        is_source(source) && w[1].starts_with('-') && w[2] == value
    })
}

/// `keyroostctl` and the subcommands `argv` names.
fn command_path(argv: &[String]) -> Vec<String> {
    use clap::CommandFactory;
    let mut root = Cli::command();
    root.build();
    let (path, _) = walk_argv(&root, argv);
    std::iter::once("keyroostctl")
        .chain(path)
        .map(str::to_string)
        .collect()
}

/// The fixed refusal for a secret flag with its value glued on
/// (`--pin123456`, `--pin:123456`, the retired `--pin-env123456`), or
/// `None`. A word made only of letters and dashes is a typo'd flag name.
fn glued_secret_flag(word: &str) -> Option<String> {
    if looks_like_flag_typo(word) {
        return None;
    }
    let rest = word.strip_prefix("--")?;
    crate::secrets::SECRET_FLAGS
        .iter()
        .filter(|f| rest.starts_with(f.long))
        .max_by_key(|f| f.long.len())
        .and_then(|f| crate::secrets::literal_refusal(f.long))
}

/// Whether a word right after a secret source starts like one of the short
/// flags with a value glued on (`--pin stdin -s3cret`). clap would take
/// the rest as a slot, device or file name and could repeat it in an
/// error, and the word may be a secret that starts with a dash. A short
/// flag on its own (`-s 9a`, `-y`) is not matched.
fn short_glued_after_source(argv: &[String]) -> bool {
    let is_source = |w: &str| w == "stdin" || w == "default" || w.starts_with("env:");
    argv.windows(2).any(|w| {
        let value = match w[0].split_once('=') {
            Some((flag, value)) if flag.starts_with("--") => value,
            _ => w[0].as_str(),
        };
        let b = w[1].as_bytes();
        is_source(value) && b.len() > 2 && b[0] == b'-' && b"dyois".contains(&b[1])
    })
}

/// "--pin needs a value: env:NAME or stdin" when a secret flag in `argv` is
/// followed by a flag-shaped word (`--pin --yes`): clap takes that word as
/// the value (a secret flag accepts a dash-led one), so the value is most
/// likely missing. Neither word is repeated.
fn missing_secret_value(argv: &[String]) -> Option<String> {
    argv.windows(2).find_map(|w| {
        let long = w[0].strip_prefix("--")?;
        let f = crate::secrets::SECRET_FLAGS
            .iter()
            .find(|f| f.long == long)?;
        if !looks_like_flag_typo(&w[1]) {
            return None;
        }
        let sources = if f.default_ok {
            "env:NAME, stdin or default"
        } else {
            "env:NAME or stdin"
        };
        Some(format!("--{long} needs a value: {sources}"))
    })
}

/// Whether `a` is a secret flag (its value names a source, never the secret).
fn is_secret_arg(a: &clap::Arg) -> bool {
    a.get_value_names()
        .is_some_and(|v| v.iter().any(|n| n.as_str() == crate::secrets::SOURCE))
}

/// The message to print instead of clap's for a parse error that could
/// repeat a secret, or `None` to let clap print its own.
///
/// A retired subcommand gets its replacement hint, and so does a retired
/// flag. An unexpected non-flag argument on a command that takes a secret
/// is not repeated:
/// clap's "unexpected argument 'X' found" would echo X, which may be the
/// secret itself (`molto seed --seed stdin DEADBEEF`, or an otpauth:// URI
/// on `molto import`), and neither is a dash-led word right after a secret
/// source (`--pin stdin -123456`, `--pin env:KR_PIN -123456`) unless it's
/// shaped like a typo'd flag name. A secret flag (any `<SOURCE>` flag)
/// given something other than a source (`--pin 123456`) is refused with a
/// fixed message naming the sources it takes, never the value, and so is
/// a secret flag with the value glued on (`--pin123456`). An invalid value
/// right after a secret source and a flag (`--seed stdin -s S3CRET`) names
/// only the flag. Any other error about a flag keeps clap's message: clap
/// names only the flag, never a value.
fn redacted_parse_error(e: &clap::Error, argv: &[String]) -> Option<String> {
    use clap::error::{ContextKind, ContextValue, ErrorKind};
    use clap::CommandFactory;

    if e.kind() == ErrorKind::InvalidSubcommand {
        let Some(ContextValue::String(word)) = e.get(ContextKind::InvalidSubcommand) else {
            return None;
        };
        return retired_command_hint(word, argv);
    }

    if let Some(msg) = missing_secret_value(argv) {
        return Some(msg);
    }

    // A secret flag given something other than a source. clap's own
    // message would repeat the value, which may be the secret itself.
    if matches!(
        e.kind(),
        ErrorKind::ValueValidation | ErrorKind::InvalidValue
    ) {
        let Some(ContextValue::String(arg)) = e.get(ContextKind::InvalidArg) else {
            return None;
        };
        let long = arg
            .split([' ', '='])
            .next()
            .unwrap_or("")
            .trim_start_matches('-');
        if let Some(msg) = crate::secrets::literal_refusal(long) {
            return Some(msg);
        }
        // A source flag the table doesn't list is refused all the same.
        let source = format!("<{}>", crate::secrets::SOURCE);
        if arg.contains(&source) {
            return Some(format!(
                "--{long} takes env:NAME or stdin — never the secret itself"
            ));
        }
        // A value right after a secret source and this flag (`--seed stdin
        // -s S3CRET`) may be the secret typed in the wrong place.
        let Some(ContextValue::String(value)) = e.get(ContextKind::InvalidValue) else {
            return None;
        };
        return value_follows_source(argv, value).then(|| {
            format!(
                "invalid value for --{long} (not shown, in case it is a secret); \
                 see `{} --help`",
                command_path(argv).join(" ")
            )
        });
    }

    if e.kind() != ErrorKind::UnknownArgument {
        return None;
    }
    let Some(ContextValue::String(arg)) = e.get(ContextKind::InvalidArg) else {
        return None;
    };
    if let Some(msg) = retired_flag_hint(arg, argv) {
        return Some(msg);
    }
    if let Some(msg) = glued_secret_flag(arg) {
        return Some(msg);
    }

    // The deepest subcommand named in argv, and whether it takes a secret.
    let mut cmd = Cli::command();
    cmd.build();
    let mut cmd = &cmd;
    let mut path = vec!["keyroostctl".to_string()];
    for word in argv.iter().skip(1) {
        if word == "--" {
            break;
        }
        if let Some(sub) = cmd.find_subcommand(word) {
            path.push(sub.get_name().to_string());
            cmd = sub;
        }
    }
    if !arg.starts_with('-')
        && path
            .iter()
            .map(String::as_str)
            .eq(["keyroostctl", "fido", "blob", "export"])
    {
        return Some(
            "`fido blob export` takes the output file as -o/--out FILE: \
             `keyroostctl fido blob export INDEX --out FILE`"
                .to_string(),
        );
    }
    if path
        .iter()
        .map(String::as_str)
        .eq(["keyroostctl", "molto", "import"])
        && !arg.starts_with("--")
    {
        return Some(if arg == "-" {
            "`molto import -` is now `molto import --uri stdin`".to_string()
        } else {
            "`molto import` takes the otpauth:// URI as --uri env:NAME or --uri stdin \
             (the extra argument is not shown, in case it is a secret)"
                .to_string()
        });
    }
    let takes_secret = cmd.get_arguments().any(is_secret_arg);

    let hidden = if arg.starts_with('-') {
        !looks_like_flag_typo(arg) && secret_flag_precedes(argv, arg)
    } else {
        takes_secret
    };
    hidden.then(|| {
        format!(
            "unexpected extra argument (not shown, in case it is a secret); see `{} --help`",
            path.join(" ")
        )
    })
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let argv: Vec<String> = std::env::args_os()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    if short_glued_after_source(&argv) {
        eprintln!(
            "error: unexpected argument after a secret source (not shown, in case it is a \
             secret); give a short flag its value as a separate word (`-s 9a`)"
        );
        std::process::exit(2);
    }
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            if let Some(msg) = redacted_parse_error(&e, &argv) {
                eprintln!("error: {msg}");
                std::process::exit(2);
            }
            e.exit()
        }
    };
    if let Some(msg) = otp_unlock_conflict(cli.command.as_ref()) {
        eprintln!("error: {msg}");
        std::process::exit(2);
    }
    // Capture --device once so target::select() can honor it without threading
    // it through every command handler.
    let _ = SELECTED_KEY_NAME.set(cli.device.clone());
    output::set_json(cli.json);
    let _ = target::DEBUG.set(cli.debug);
    if cli.debug {
        keyroost_ctap::set_trace(true);
    }

    if cli.device.is_some() {
        if let Some(what) = inert_device_flag(cli.command.as_ref()) {
            return Err(format!("--device has no effect on `{what}`; remove it").into());
        }
    }

    let Some(cmd) = cli.command.as_ref() else {
        // No subcommand → the friendly correlated overview of every connected
        // device, or (with --device) just the one key it names. (The Molto2
        // serial/clock still lives under `molto info`.)
        let devices = target::enumerate()?;
        let rows = filter_rows(&devices, cli.device.as_deref())?;
        if json_output() {
            use keyroost_resolve::DeviceKind;
            let keys: Vec<json_out::DeviceJson> = rows
                .iter()
                .map(|(_, d)| json_out::DeviceJson {
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
                    capabilities: d.cap_badges(),
                    capabilities_unverified: d
                        .cap_badge_states()
                        .into_iter()
                        .filter(|(_, s)| *s == keyroost_resolve::CapState::Unverified)
                        .map(|(l, _)| l)
                        .collect(),
                })
                .collect();
            emit_json(&json_out::KeysJson { keys })?;
            return Ok(());
        }
        overview::print_overview(&rows);
        return Ok(());
    };

    // Pure-output subcommands: no device, no session.
    if let Cmd::Completions { shell } = cmd {
        write_completion_registration(*shell, &mut std::io::stdout())?;
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
        eprintln!("Wrote man pages to {}.", dir.display());
        return Ok(());
    }
    if let Cmd::Doctor = cmd {
        run_doctor();
        return Ok(());
    }

    // List touches neither PC/SC card state nor any HID device — just enumerates.
    if let Cmd::List { all_hid } = cmd {
        run_list(*all_hid, cli.device.as_deref())?;
        return Ok(());
    }

    // Friendly-name registry management (reads HID enumeration; opt-in writes).
    if let Cmd::Name { cmd } = cmd {
        run_name(cmd)?;
        return Ok(());
    }

    // FIDO commands talk to a hidraw device, not the Molto2 PC/SC reader.
    if let Cmd::Fido { cmd } = cmd {
        return run_fido(cmd);
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
    if let Cmd::Otp {
        cmd,
        transport,
        reader,
        path,
    } = cmd
    {
        run_otp(
            cmd,
            OtpSelect {
                transport: *transport,
                reader: reader.as_deref(),
                path: path.as_deref(),
            },
            cli.debug,
        )?;
        return Ok(());
    }

    // Token2 Molto2 / Molto2v2 commands all talk to the Molto2 PC/SC reader,
    // authenticated with the customer key (--customer-key).
    if let Cmd::Molto { key, cmd, reader } = cmd {
        return run_molto(cmd, key, reader.as_deref(), cli.debug);
    }

    if let Cmd::Prog { cmd } = cmd {
        return run_prog(cmd, cli.debug);
    }

    // Whole-device factory reset: wipe every resettable applet in planner order.
    if let Cmd::FactoryReset {
        reader,
        yes,
        mgmt_key,
        pin,
    } = cmd
    {
        return run_factory_reset(
            reader.as_deref(),
            *yes,
            cli.debug,
            mgmt_key.as_ref(),
            pin.as_ref(),
        );
    }

    unreachable!("every subcommand is handled above");
}

/// Open the selected Molto2 (one token is used directly; several ask or
/// refuse — never the first one found).
fn open_molto_session(reader: Option<&str>) -> Result<Session, Box<dyn std::error::Error>> {
    Ok(Session::open_named(&crate::target::reader_for(
        Need::Molto2,
        reader,
    )?)?)
}

/// Dispatch the Token2 Molto2 / Molto2v2 subcommands. The customer key comes
/// from `--customer-key` (`KeyArgs`), accepted before or after the
/// subcommand.
fn run_molto(
    cmd: &MoltoCmd,
    key: &KeyArgs,
    exact: Option<&str>,
    debug: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut sec = Secrets::real();
    // Arguments and secret sources are checked before any file is read or
    // the token is touched (no seed source, an unset variable).
    molto_validate(cmd, key, &sec)?;

    // --dry-run on bulk import doesn't need the device at all.
    if let MoltoCmd::Import {
        file: Some(path),
        slot,
        dry_run: true,
        password,
        ..
    } = cmd
    {
        let start = slot.unwrap_or(0);
        molto_dry_run_key(&mut sec, key, password.as_ref())?;
        let entries = load_bulk_entries(&mut sec, path, password.as_ref())?;
        let last = (start as usize).saturating_add(entries.len());
        println!(
            "Found {} entries; would fill slots #{}..#{} (dry run).",
            entries.len(),
            start,
            last.saturating_sub(1)
        );
        for (i, entry) in entries.iter().enumerate() {
            let p = start as usize + i;
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
        let mut session = open_molto_session(exact)?;
        session.set_debug(debug);
        let info = session.read_info()?;
        if json_output() {
            emit_json(&json_out::MoltoInfoJson {
                serial: info.serial.clone(),
                utc_time: info.utc_time,
                drift_seconds: i64::from(info.utc_time) - i64::from(unix_now()),
            })?;
            return Ok(());
        }
        write_info(&mut std::io::stdout(), &info)?;
        return Ok(());
    }

    // Slots is read-only and needs no auth — the public block answers any
    // card holder (that's also why the output warns about title privacy).
    if let MoltoCmd::Slots { all } = cmd {
        let mut session = open_molto_session(exact)?;
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
                .map(|(i, b)| json_out::MoltoSlotJson::from_block(i as u8, b))
                .collect();
            let out = json_out::MoltoSlotsJson {
                serial: info.serial.clone(),
                slots: out,
            };
            emit_json(&out)?;
            return Ok(());
        }
        write_info(&mut std::io::stderr(), &info)?;
        let shown: Vec<_> = slots
            .iter()
            .enumerate()
            .filter(|(_, b)| *all || b.seed_present || b.title.is_some())
            .collect();
        if shown.is_empty() && sweep_err.is_none() {
            println!("No occupied or titled slots (use --all to list all 100).");
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
    if let MoltoCmd::Title { slot, title: None } = cmd {
        let mut session = open_molto_session(exact)?;
        session.set_debug(debug);
        let block = session.read_public_data(*slot)?;
        let title = block
            .title
            .as_deref()
            .map(sanitize_terminal)
            .unwrap_or_else(|| "(none)".into());
        let occupied = if block.seed_present { "yes" } else { "no" };
        println!(
            "{}",
            output::kv_block(&[("Title", title), ("Occupied", occupied.into())])
        );
        return Ok(());
    }

    // Delete needs no auth (hardware-verified) — show what's in the slot,
    // then confirm before touching it.
    if let MoltoCmd::Delete { slot, yes } = cmd {
        let dev = crate::target::select(Need::Molto2, exact, None)?;
        let mut session = open_molto_session(exact)?;
        session.set_debug(debug);
        let info = session.read_info()?;
        write_info(&mut std::io::stderr(), &info)?;
        let block = session.read_public_data(*slot)?;
        output::status(&format!(
            "slot #{}: occupied: {}, title: {}",
            slot,
            if block.seed_present { "yes" } else { "no" },
            block
                .title
                .as_deref()
                .map(sanitize_terminal)
                .unwrap_or_else(|| "(none)".into()),
        ));
        crate::prompt::confirm_on_held(&dev, *yes, &format!("delete slot #{slot}'s seed"))?;
        match session.delete_seed(*slot)? {
            SeedDeleteOutcome::Deleted => {
                println!(
                    "Seed deleted from slot #{}; the title (if any) remains.",
                    slot
                )
            }
            SeedDeleteOutcome::AlreadyEmpty => println!("Slot #{} was already empty.", slot),
        }
        return Ok(());
    }

    // Factory reset is a plain CLA 0x80 command and needs no auth. Show the
    // (read-only) device info before asking, so the question comes after
    // everything that identifies the token being wiped.
    if let MoltoCmd::Reset { yes } = cmd {
        // Unlike the other Molto commands, a wipe never falls back to the
        // first Molto2 reader found: with several tokens and no --device it
        // refuses instead of guessing.
        let dev = crate::target::select(Need::Molto2, exact, None)?;
        let reader = crate::target::reader_of(&dev)?;
        let mut session = Session::open_named(&reader)?;
        session.set_debug(debug);
        let info = session.read_info()?;
        write_info(&mut std::io::stderr(), &info)?;
        crate::prompt::confirm_on_held(&dev, *yes, "factory-reset the Molto2 (all 100 slots)")?;
        output::status(
            "Requesting a factory reset: confirm with the up-arrow button on the device.",
        );
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
        // Read before the session opens: nothing is held while a key is
        // typed.
        let key = if *authed {
            Some(customer_key(&mut sec, key)?)
        } else {
            None
        };
        let mut session = open_molto_session(exact)?;
        session.set_debug(debug);
        let info = session.read_info()?;
        write_info(&mut std::io::stderr(), &info)?;
        if let Some(key) = key {
            match session.authenticate(&key) {
                Ok(()) => output::status("Authenticated."),
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

    let early_key = molto_early_key(&mut sec, key, cmd)?;
    // Bulk import reads its file — and so any vault password, from the
    // environment, stdin or the hidden prompt — before the question, unlike
    // every other secret: which slots it writes, and so whether to ask at
    // all, depends on the entries inside. No token session is open yet. A
    // password piped on stdin means stdin is not a terminal, so it can never
    // be mistaken for the answer (there is no question then; an occupied
    // slot needs --yes).
    let bulk = match cmd {
        MoltoCmd::Import {
            file: Some(path),
            slot,
            password,
            ..
        } => {
            let start = slot.unwrap_or(0);
            let entries = load_bulk_entries(&mut sec, path, password.as_ref())?;
            let n = entries.len();
            let last = (start as usize).saturating_add(n);
            if last > 100 {
                return Err(format!(
                    "{} entries starting at #{} would exceed slot 99 (last slot needed: #{})",
                    n,
                    start,
                    last - 1
                )
                .into());
            }
            Some(entries)
        }
        _ => None,
    };
    // The seed slots this command writes, and whether it may skip asking.
    let writes: Option<(Vec<u8>, bool)> = match cmd {
        MoltoCmd::Seed { slot, yes, .. } => Some((vec![*slot], *yes)),
        MoltoCmd::Import {
            file: None,
            slot,
            yes,
            ..
        } => {
            let Some(slot) = slot else {
                unreachable!("clap requires --slot without --file")
            };
            Some((vec![*slot], *yes))
        }
        MoltoCmd::Import {
            file: Some(_),
            slot,
            yes,
            ..
        } => {
            let entries = bulk.as_deref().unwrap_or_default();
            Some((bulk_import_slots(slot.unwrap_or(0), entries), *yes))
        }
        _ => None,
    };
    let dev = crate::target::select(Need::Molto2, exact, None)?;
    // Occupancy is read in a short unauthenticated session, closed before
    // the question and before any secret is typed. The write session reopens
    // afterwards and must find the same token.
    let mut asked = false;
    let mut seen_serial: Option<String> = None;
    if let Some((slots, false)) = &writes {
        let mut probe = open_molto_session(exact)?;
        probe.set_debug(debug);
        let info = probe.read_info()?;
        write_info(&mut std::io::stderr(), &info)?;
        let busy = molto_occupied(&mut probe, slots.iter().copied())?;
        seen_serial = Some(info.serial.clone());
        drop(probe);
        if !busy.is_empty() {
            let list: Vec<String> = busy.iter().map(|p| format!("#{p}")).collect();
            asked = crate::prompt::confirm_then_read(
                &dev,
                false,
                &format!("overwrite occupied Molto2 slot(s) {}", list.join(", ")),
            )?;
        }
    }
    // Replacing the customer key asks before either key is read, so a typed
    // key comes after the answer.
    if let MoltoCmd::CustomerKey { yes, .. } = cmd {
        asked = crate::prompt::confirm_then_read(&dev, *yes, "replace the Molto2 customer key")?;
    }
    let (key, input) = molto_key_and_input(&mut sec, key, cmd, early_key)?;
    crate::prompt::reverify_if_asked(&dev, asked || sec.prompted())?;
    let mut session = open_molto_session(exact)?;
    session.set_debug(debug);
    let info = session.read_info()?;
    same_molto(seen_serial.as_deref(), &info.serial)?;
    if seen_serial.is_none() {
        write_info(&mut std::io::stderr(), &info)?;
    }
    match session.authenticate(&key) {
        Ok(()) => output::status("Authenticated."),
        // The Display impl renders the tries-remaining count (or "unknown").
        Err(e @ TransportError::AuthFailed { .. }) => return Err(e.to_string().into()),
        Err(e) => return Err(e.into()),
    }

    match cmd {
        MoltoCmd::Info => unreachable!("handled above before auth"),
        MoltoCmd::Slots { .. } => unreachable!("handled above before auth"),
        MoltoCmd::Delete { .. } => unreachable!("handled above before auth"),
        MoltoCmd::Seed { slot, .. } => {
            let MoltoInput::Seed(seed) = &input else {
                unreachable!("read before authentication")
            };
            session.set_seed(*slot, seed)?;
            println!("Seed written to slot #{}.", slot);
        }
        MoltoCmd::Title { slot, title } => {
            // Checked by molto_validate before the token was touched.
            let title = title
                .as_deref()
                .expect("title read mode is handled before auth");
            session.set_title(*slot, title)?;
            println!("Title set on slot #{}.", slot);
        }
        MoltoCmd::Config {
            slot,
            algorithm,
            digits,
            period,
            display_timeout,
        } => {
            let cfg = ProfileConfig {
                display_timeout: display_timeout.to_proto(),
                algorithm: algorithm.to_proto(),
                digits: digits.to_proto(),
                time_step: period.to_proto(),
                utc_time: unix_now(),
            };
            session.set_config(*slot, &cfg)?;
            println!("Slot #{} configured.", slot);
        }
        MoltoCmd::Sync { slot, all } => {
            if *all {
                for p in 0..=99u8 {
                    match session.sync_time(p, unix_now()) {
                        Ok(()) => println!("Time synced on slot #{}.", p),
                        Err(e) => output::warn(&format!("time sync failed on slot #{p}: {e}")),
                    }
                }
            } else if let Some(p) = slot {
                session.sync_time(*p, unix_now())?;
                println!("Time synced on slot #{}.", p);
            } else {
                return Err("sync requires --slot <N> or --all".into());
            }
        }
        MoltoCmd::CustomerKey { .. } => {
            let MoltoInput::NewKey(new_key) = &input else {
                unreachable!("read before authentication")
            };
            session.set_customer_key(new_key)?;
            output::status(
                "Customer-key rotation requested: press the up-arrow button on the device to confirm.",
            );
        }
        MoltoCmd::Import {
            file: None,
            slot,
            display_timeout,
            qr,
            ..
        } => {
            let Some(slot) = slot else {
                unreachable!("clap requires --slot without --file")
            };
            let MoltoInput::Entry {
                entry,
                title: final_title,
            } = &input
            else {
                unreachable!("read before authentication")
            };
            session.set_seed(*slot, &entry.secret)?;
            session.set_title(*slot, final_title)?;
            session.set_config(
                *slot,
                &entry.to_profile_config(unix_now(), display_timeout.to_proto()),
            )?;
            println!(
                "Imported {:?} to slot #{} ({} bytes secret, {:?}, {} digits).",
                final_title,
                slot,
                entry.secret.len(),
                entry.algorithm,
                entry.digits as u8
            );
            if qr.is_some() {
                output::note(
                    "remember to delete the screenshot (and any phone/cloud copies) — it \
                     contains the secret",
                );
            }
        }
        MoltoCmd::Import {
            file: Some(_),
            slot,
            display_timeout,
            dry_run,
            ..
        } => {
            let start = slot.unwrap_or(0);
            // dry-run prints the plan and returns *before* authentication
            // (see the pre-auth handling above) — it is always false here.
            debug_assert!(!*dry_run);
            // Loaded and range-checked before authentication (see above).
            let entries = bulk
                .as_deref()
                .ok_or("internal error: bulk entries not loaded")?;
            let n = entries.len();
            let last = start as usize + n;
            output::status(&format!(
                "Found {} entries; programming slots #{}..#{}.",
                n,
                start,
                last - 1
            ));
            let mut written = 0usize;
            for (i, entry) in entries.iter().enumerate() {
                let p = start + i as u8;
                let title = entry.suggested_title();
                if title.is_empty() {
                    output::warn(&format!(
                        "  #{}: skipping — entry has no issuer or account to use as title",
                        p
                    ));
                    continue;
                }
                output::status(&format!(
                    "  #{}: {:?} ({} bytes secret, {:?}, {} digits)",
                    p,
                    title,
                    entry.secret.len(),
                    entry.algorithm,
                    entry.digits as u8
                ));
                session.set_seed(p, &entry.secret)?;
                session.set_title(p, &title)?;
                session.set_config(
                    p,
                    &entry.to_profile_config(unix_now(), display_timeout.to_proto()),
                )?;
                written += 1;
            }
            println!("{}", import_file_ack(written, start, last - 1));
        }
        MoltoCmd::Reset { .. } => unreachable!("handled above before auth"),
        MoltoCmd::Probe { .. } => unreachable!("handled above before auth"),
    }
    Ok(())
}

fn run_prog(cmd: &ProgCmd, debug: bool) -> Result<(), Box<dyn std::error::Error>> {
    use keyroost_token2prog as prog;
    use keyroost_transport::Token2ProgSession;

    match cmd {
        ProgCmd::Info { reader } => {
            let name = crate::target::reader_for(Need::Prog, reader.as_deref())?;
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
                let model = model.map_or_else(
                    || "(unrecognized serial — not a known Token2 model)".to_owned(),
                    str::to_owned,
                );
                println!(
                    "{}",
                    output::kv_block(&[
                        ("Model", model),
                        ("Serial", sanitize_terminal(&info.serial)),
                        ("Device UTC", format!("{} (epoch)", info.utc_time)),
                    ])
                );
            }
        }
        ProgCmd::Seed {
            reader,
            seed,
            encoding,
            yes,
        } => {
            let mut sec = Secrets::real();
            let spec = seed_spec(*encoding);
            let src = Source::from_flag(seed.as_ref());
            sec.check(spec, src)?;
            let dev = crate::target::select(Need::Prog, reader.as_deref(), None)?;
            let name = crate::target::reader_of(&dev)?;
            // Refuse to program a device whose serial does not match a known
            // Token2 programmable-token model — guards against writing to the
            // wrong card on a shared reader. This first session is closed
            // before the question and before the seed is typed.
            let seen_serial = {
                let mut probe = Token2ProgSession::open_named(&name)?;
                probe.set_debug(debug);
                prog_guard_model(&mut probe)?;
                probe.read_info()?.serial
            };
            let asked = crate::prompt::confirm_then_read(
                &dev,
                *yes,
                "overwrite the programmable token's seed",
            )?;
            let seed = prog_seed(decode_seed(&sec.read(spec, src)?, *encoding)?)?;
            crate::prompt::reverify_if_asked(&dev, asked || sec.prompted())?;
            let mut session = Token2ProgSession::open_named(&name)?;
            session.set_debug(debug);
            prog_guard_model(&mut session)?;
            same_prog_token(&seen_serial, &session.read_info()?.serial)?;
            session.authenticate()?;
            session.set_seed(&seed)?;
            println!("Seed programmed ({} bytes).", seed.len());
        }
        ProgCmd::Config {
            reader,
            algorithm,
            period,
            display_timeout,
            yes,
        } => {
            let dev = crate::target::select(Need::Prog, reader.as_deref(), None)?;
            let name = crate::target::reader_of(&dev)?;
            let mut session = Token2ProgSession::open_named(&name)?;
            session.set_debug(debug);
            // Refuse to program an unrecognized device (see Seed above).
            prog_guard_model(&mut session)?;
            crate::prompt::confirm_on_held(
                &dev,
                *yes,
                "overwrite the programmable token's configuration",
            )?;
            // The clock is read after the answer, so a slow reply can't
            // leave the token's time behind.
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
                time_step: match period {
                    StepArg::S30 => prog::TimeStep::Seconds30,
                    StepArg::S60 => prog::TimeStep::Seconds60,
                },
                utc_time: now,
            };
            session.authenticate()?;
            session.set_config(&cfg)?;
            println!("Config programmed (clock set to {now}).");
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
            output::status(&format!(
                "\u{2192} {model} \u{b7} serial {}",
                sanitize_terminal(&info.serial)
            ));
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

/// Check a programmable-token seed's length and pad it to the stored length.
fn prog_seed(
    mut seed: zeroize::Zeroizing<Vec<u8>>,
) -> Result<zeroize::Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
    if seed.is_empty() || seed.len() > 63 {
        return Err(format!("seed must be 1..=63 bytes (got {})", seed.len()).into());
    }
    // Pad short secrets to the device's 20-byte stored length with trailing
    // zeros, matching the vendor tool — otherwise the device computes TOTP over
    // a shorter seed than an authenticator app set up from the same secret.
    Ok(zeroize::Zeroizing::new(keyroost_token2prog::pad_totp_seed(
        std::mem::take(&mut *seed),
    )))
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
            "– no registry yet ({}) — created on first `name add`",
            path.display()
        ),
        None => println!("– no config dir resolvable (HOME/XDG unset?)"),
    }
}

fn run_list(all_hid: bool, device: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    // `--json`: one row per key, nothing else on stdout (announce lines, if
    // any, stay on stderr — but filter_rows below never announces).
    if json_output() {
        let devices = target::enumerate()?;
        let rows = filter_rows(&devices, device)?;
        emit_json(&json_out::KeysJson {
            keys: list_json_rows(&devices, &rows),
        })?;
        return Ok(());
    }

    // `--device` narrows the human output to that one key's correlated row;
    // the raw reader/HID sections (which aren't per-key) are skipped.
    if device.is_none() {
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
    }
    let (probes, probe_ok) = match keyroost_transport::probe_readers() {
        Ok(p) => (p, true),
        Err(e) => {
            if device.is_none() {
                println!("  (unavailable: {})", e);
            }
            (Vec::new(), false)
        }
    };
    if device.is_none() {
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
    }
    let (hids, hids_ok) = match keyroost_hid::enumerate() {
        Ok(d) => (d, true),
        Err(e) => {
            if device.is_none() {
                println!("  (unavailable: {})", e);
            }
            (Vec::new(), false)
        }
    };
    let keyring = Keyring::load_default().unwrap_or_default();
    if device.is_none() && hids_ok {
        let filtered: Vec<_> = hids.iter().filter(|d| all_hid || d.is_fido()).collect();
        if filtered.is_empty() {
            println!("  (none)");
            if let Some(bl) = keyroost_hid::bootloader_device_present() {
                println!("  note: detected {bl} — re-plug it to return to application mode.");
            }
        } else {
            // CCID attribution only ever applies to FIDO HID nodes (a YubiKey's
            // other interfaces aren't candidates), and matching `correlate`'s
            // own FIDO-only view here keeps `--all-hid` from having a non-FIDO
            // interface count as a claimant and starve a real contended case.
            let fido_hids: Vec<keyroost_hid::HidDevice> =
                hids.iter().filter(|d| d.is_fido()).cloned().collect();
            let ccid = ccid_readers_if_needed(&fido_hids);
            let fido_refs: Vec<&keyroost_hid::HidDevice> = fido_hids.iter().collect();
            let attributed = ccid_serials_for(&fido_refs, &ccid);
            for d in &filtered {
                let tag = if d.is_fido() {
                    " [FIDO]"
                } else if d.bootloader_label().is_some() {
                    " [bootloader]"
                } else {
                    ""
                };
                let eff = d.serial_number.clone().or_else(|| {
                    if !d.is_fido() {
                        return None;
                    }
                    let i = fido_hids.iter().position(|h| h.path == d.path)?;
                    attributed.get(i).cloned().flatten()
                });
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

    // Correlated summary — built from the SAME hid+probe snapshot (plus any
    // on-demand identity reads correlate_live() needs to settle a case
    // topology alone can't decide), so the raw sections above and this
    // decision can't disagree.
    if device.is_none() {
        println!();
    }
    let devices =
        keyroost_resolve::correlate_live(&hids, &probes, &keyring, crate::target::debug_on());
    let rows = filter_rows(&devices, device)?;
    overview::print_correlated(&rows);

    Ok(())
}

const OATH_PASSWORD: Spec = Spec::current("OATH password", "password");
const OATH_NEW_PASSWORD: Spec = Spec::new_secret("new OATH password", "new-password");

/// Open the OATH applet on the announced key, unlocking it when it is
/// password-protected. Nothing is held while a password is typed: see
/// [`oath_current_password`].
fn open_oath(
    sec: &mut Secrets,
    access: &OathAccess,
    debug: bool,
) -> Result<keyroost_transport::OathSession, Box<dyn std::error::Error>> {
    open_oath_from(sec, access, access.source(), debug)
}

/// [`open_oath`] with the password's source given (the second secret of a
/// [`SecretPair`]).
fn open_oath_from(
    sec: &mut Secrets,
    access: &OathAccess,
    password: Source<'_>,
    debug: bool,
) -> Result<keyroost_transport::OathSession, Box<dyn std::error::Error>> {
    let (name, password) = oath_password_from(sec, access, password, debug)?;
    reverify_if_prompted(sec, Need::Oath, access.reader.as_deref())?;
    open_oath_unlocked(&name, password.as_deref().map(String::as_str), debug)
}

/// The announced OATH key's reader, its current password if it has one, and
/// the new password still to read.
type OathCurrentThen<'a> = (String, Option<zeroize::Zeroizing<String>>, SecondSecret<'a>);

/// `oath password set`'s current password (the first secret of its pair),
/// then the new one's [`SecondSecret`] to read next.
fn oath_current_then<'a>(
    sec: &mut Secrets,
    access: &OathAccess,
    pair: SecretPair<'a>,
    debug: bool,
) -> Result<OathCurrentThen<'a>, Box<dyn std::error::Error>> {
    let (name, current) = oath_password_from(sec, access, Source::from_flag(pair.first.1), debug)?;
    Ok((name, current, pair.second))
}

/// The announced OATH key's exact reader and, when it needs one, its
/// current password.
type OathReaderPassword = (String, Option<zeroize::Zeroizing<String>>);

/// Announce the OATH key and get its current password, if it needs one. A
/// password named by flag is read without touching the card. Otherwise a
/// short read-only session asks the applet whether it is protected and is
/// closed again before the hidden prompt, so nothing is held while the
/// password is typed.
fn oath_current_password(
    sec: &mut Secrets,
    access: &OathAccess,
    debug: bool,
) -> Result<OathReaderPassword, Box<dyn std::error::Error>> {
    oath_password_from(sec, access, access.source(), debug)
}

/// [`oath_current_password`] with the password's source given.
fn oath_password_from(
    sec: &mut Secrets,
    access: &OathAccess,
    password: Source<'_>,
    debug: bool,
) -> Result<OathReaderPassword, Box<dyn std::error::Error>> {
    let name = crate::target::reader_for(Need::Oath, access.reader.as_deref())?;
    if let Some(pw) = sec.read_given(&OATH_PASSWORD, password)? {
        return Ok((name, Some(pw)));
    }
    let required = {
        let mut probe = keyroost_transport::OathSession::open(&name)?;
        probe.set_debug(debug);
        probe.password_required()
    }; // the probe session is closed here, before any prompt
    if !required {
        return Ok((name, None));
    }
    let pw = sec
        .read(&OATH_PASSWORD, Source::NONE)
        .map_err(|e| format!("this OATH applet is password-protected; {e}"))?;
    Ok((name, Some(pw)))
}

/// Open the OATH applet on `name` and unlock it with `password`. A protected
/// applet without one is a clear error rather than a confusing downstream
/// `6982` (the key may have been swapped since the password was asked for).
fn open_oath_unlocked(
    name: &str,
    password: Option<&str>,
    debug: bool,
) -> Result<keyroost_transport::OathSession, Box<dyn std::error::Error>> {
    let mut session = keyroost_transport::OathSession::open(name)?;
    session.set_debug(debug);
    match password {
        Some(pw) => session.unlock(pw)?,
        None if session.password_required() => {
            return Err(format!(
                "this OATH applet is password-protected; pass {}",
                OATH_PASSWORD.sources_hint()
            )
            .into());
        }
        None => {}
    }
    Ok(session)
}

/// What the user confirms before a whole-device wipe, given the plan's
/// applet labels ("OATH, OpenPGP, PIV, FIDO2").
///
/// It does not promise the key "stays usable": PIV's wipe blocks the PIN and
/// PUK on purpose before erasing, so a run that stops in between leaves that
/// applet locked and un-wiped. What can be promised is per applet and per step
/// — the same line the GUI's `factory_reset_confirm_summary` settled on, so the
/// two front ends ask for consent to the same thing.
fn factory_reset_action(labels: &str) -> String {
    format!(
        "factory-reset {labels} (every credential, code, key and PIN is erased; \
         each applet that completes comes back in factory condition, and every \
         step reports its own outcome)"
    )
}

// One more `--mgmt-key-*` source (`mgmt_key_default`) pushed this past
// clippy's default 7-argument threshold; every argument here is a distinct
// CLI flag, so a struct would just move the sprawl rather than reduce it.
/// Whole-device factory reset: run every applet reset the key supports, in
/// planner order, continue on failure, print a per-step report, and exit
/// nonzero if anything failed. FIDO2 is last and needs a physical replug +
/// touch; the replug is detected, not confirmed with a keypress.
#[allow(clippy::too_many_arguments)]
fn run_factory_reset(
    reader: Option<&str>,
    yes: bool,
    debug: bool,
    mgmt_key: Option<&SecretSource>,
    pin: Option<&SecretSource>,
) -> Result<(), Box<dyn std::error::Error>> {
    use keyroost_resolve::{factory_reset_plan, ResetStep, StepOutcome, StepReport};

    // Only rows with something to reset count; --reader resolves to a row too.
    let dev = crate::target::select(Need::FactoryReset, reader, None)?;
    // A `--reader` that matched no detected key passes through as a stand-in
    // row with no capabilities — nothing to plan the steps from.
    if dev.id.starts_with("override:") {
        return Err("factory-reset needs a detected key; check `keyroostctl list`".into());
    }
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
    let mut plan = factory_reset_plan(dev.caps);
    if plan.is_empty() {
        return Err(format!(
            "'{}' exposes no resettable applet (nothing to factory-reset)",
            sanitize_terminal(&dev.model)
        )
        .into());
    }
    let labels = plan
        .iter()
        .map(|s| s.label())
        .collect::<Vec<_>>()
        .join(", ");
    let asked =
        crate::prompt::confirm_typed_then_read(&dev, yes, "reset", &factory_reset_action(&labels))?;
    // The PIV credential, if one was given, is read now — after the question
    // and before any card session; only the probe below can say whether it
    // is needed.
    let mut sec = Secrets::real();
    let reset_input = read_reset_auth_input(&mut sec, mgmt_key, pin)?;
    crate::prompt::reverify_if_asked(&dev, asked || sec.prompted())?;

    // Fingerprint PIV before running anything destructive — mirrors the GUI's
    // `App::start_factory_reset_confirm`, just synchronous (the CLI has no
    // worker thread to keep this off of). Two separate questions, not one:
    // whether PIV can be reset at all (`PivSession::preview_factory_reset`,
    // which checks `PivExtension::ResetGlobal` first and falls back to
    // `PivExtension::Reset`'s own shape — `Unsupported` means neither is
    // available, so `ResetStep::Piv` is dropped from the plan entirely
    // rather than offered for a step `factory_reset` would only refuse), and
    // whether a credential is needed for whichever mechanism does run
    // (`PivSession::global_reset_available` — `PivQuirk::
    // ResetNeedsManagementAuth` applying, ORed across either extension not
    // being a confirmed dead end). `factory_reset` itself decides which
    // mechanism actually consumes the resolved credential; a device that
    // can't be probed (no reader, transport fault) is treated as needing
    // neither — the PIV step below still runs and reports its own, real
    // error if the device is genuinely unreachable.
    let mut piv_resettable = true;
    let reset_auth = if plan.contains(&ResetStep::Piv) {
        match dev.reader.as_deref() {
            Some(r) => {
                // `with_transaction`'s own connect/SELECT failure is
                // swallowed below, same as the old `PivSession::open(r).ok()`
                // — the PIV step itself surfaces a real error later if the
                // device is genuinely unreachable. A failure *inside* the
                // closure (from `resolve_reset_cli_auth`) is a different
                // matter — a real credential-resolution problem that must
                // abort the whole command — so it travels out as the
                // closure's own `Result` value rather than through
                // `with_transaction`'s error channel, and is propagated
                // (`return Err`) below instead of swallowed.
                type Probed = Result<
                    (
                        bool,
                        Option<Result<ResetCliAuth, Box<dyn std::error::Error>>>,
                    ),
                    TransportError,
                >;
                let probed: Probed = keyroost_transport::PivSession::with_transaction(r, |s| {
                    let resettable = !matches!(
                        s.preview_factory_reset(),
                        keyroost_transport::PivResetPreview::Unsupported
                    );
                    let auth = if s.global_reset_available() {
                        // Ask before the PIN gate is consulted below:
                        // whichever mechanism actually runs, both need
                        // `current`, so this is the one place
                        // `PivQuirk::ResetNeedsManagementAuth` applying
                        // is handled — abort here, before anything
                        // destructive, rather than let the PIV step
                        // discover it partway through the plan.
                        let pin_gate = s.pin_management_auth_gate();
                        Some(resolve_reset_cli_auth(
                            reset_input.as_ref(),
                            pin_gate,
                            Some(s),
                        ))
                    } else {
                        None
                    };
                    Ok::<_, TransportError>((resettable, auth))
                });
                match probed {
                    Ok((resettable, auth)) => {
                        piv_resettable = resettable;
                        match auth {
                            Some(Ok(a)) => Some(a),
                            Some(Err(e)) => return Err(e),
                            None => None,
                        }
                    }
                    Err(_) => None,
                }
            }
            None => None,
        }
    } else {
        None
    };
    if !piv_resettable {
        keyroost_resolve::exclude_unresettable_piv(&mut plan);
    }
    // Re-check: a device offering only `Caps::PIV` (the check above only
    // catches an empty plan built from caps, before this exclusion) can
    // still end up with nothing left to reset once a live fingerprint rules
    // PIV out too.
    if plan.is_empty() {
        return Err(format!(
            "'{}' has no reset mechanism available for any of its applets \
             (nothing to factory-reset)",
            sanitize_terminal(&dev.model)
        )
        .into());
    }

    eprintln!(
        "factory reset steps: {}",
        plan.iter()
            .map(|s| s.label())
            .collect::<Vec<_>>()
            .join(", ")
    );

    let mut reports: Vec<StepReport> = Vec::new();
    for step in &plan {
        let outcome = match step {
            ResetStep::Fido => match dev.hid_path.as_deref() {
                None => {
                    // A card in a reader: no replug exists and no touch surface
                    // — the replug wait below could never be satisfied
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
                }
                Some(armed) => {
                    // Replug + touch; on its own so a card-step failure above
                    // never skips the FIDO offer.
                    match fido_reset_after_replug(
                        armed,
                        dev.name.as_deref().unwrap_or(&dev.model),
                        &expected_serial,
                        &expected_model,
                        expected_ids,
                        FACTORY_RESET_NOUN,
                        FACTORY_RESET_RERUN,
                        Some(step.label()),
                    ) {
                        Ok(()) => StepOutcome::Wiped,
                        // Nobody replugged: nothing was sent, so this step was
                        // skipped rather than failed.
                        Err(e) if e.downcast_ref::<NoReplugSeen>().is_some() => {
                            StepOutcome::Skipped(format!(
                                "no replug seen within {} seconds",
                                REPLUG_BUDGET.as_secs()
                            ))
                        }
                        Err(e) => StepOutcome::Failed(sanitize_terminal(&e.to_string())),
                    }
                }
            },
            other => reset_one_card_applet(*other, &dev, debug, reset_auth.as_ref()),
        };
        let label = step.label();
        match &outcome {
            StepOutcome::Wiped => println!("{label:<8} wiped"),
            // Device-wide mechanism, not confined to PIV alone — name the
            // whole device instead of just the applet that triggered it.
            StepOutcome::WipedGlobal => {
                println!("{:<8} wiped", keyroost_resolve::PIV_GLOBAL_RESET_LABEL)
            }
            StepOutcome::WipedWithWarning(e) => println!("{label:<8} wiped (warning: {e})"),
            StepOutcome::Failed(e) => println!("{label:<8} failed: {e}"),
            StepOutcome::Skipped(reason) => println!("{label:<8} skipped: {reason}"),
        }
        reports.push(StepReport {
            step: *step,
            outcome,
        });
    }

    let (summary, verdict) = factory_reset_summary(&reports);
    println!("{summary}");
    verdict.map_err(Into::into)
}

/// The closing line of a factory reset and whether the command succeeded.
///
/// Only a step that actually wiped counts as wiped. A skipped step (say, a
/// FIDO2 step nobody replugged for) left that applet as it was, so the key was
/// not fully reset and the command must not report success.
fn factory_reset_summary(reports: &[keyroost_resolve::StepReport]) -> (String, Result<(), String>) {
    use keyroost_resolve::StepOutcome;
    let count = |f: fn(&StepOutcome) -> bool| reports.iter().filter(|r| f(&r.outcome)).count();
    let wiped = count(|o| {
        matches!(
            o,
            StepOutcome::Wiped | StepOutcome::WipedGlobal | StepOutcome::WipedWithWarning(_)
        )
    });
    let skipped = count(|o| matches!(o, StepOutcome::Skipped(_)));
    let failed = count(|o| matches!(o, StepOutcome::Failed(_)));
    let summary = format!("factory reset: {wiped} wiped, {skipped} skipped, {failed} failed");
    let verdict = match (failed, skipped) {
        (0, 0) => Ok(()),
        (f, 0) => Err(format!("{f} applet(s) failed to reset")),
        (0, s) => Err(format!(
            "{s} applet(s) skipped; the key was not fully reset"
        )),
        (f, s) => Err(format!(
            "{f} applet(s) failed to reset and {s} skipped; the key was not fully reset"
        )),
    };
    (summary, verdict)
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

/// The command that finishes a FIDO2 wipe on its own (named in replug
/// messages so the user re-runs the right thing).
const FIDO_RESET_RERUN: &str = "keyroostctl fido reset --yes";
/// The command that re-runs the whole-device wipe.
const FACTORY_RESET_RERUN: &str = "keyroostctl factory-reset --yes";
/// What the refusal messages call the operation, matching the rerun command.
const FIDO_RESET_NOUN: &str = "FIDO2 reset";
const FACTORY_RESET_NOUN: &str = "factory reset";

/// What to tell the user when the pinned key wasn't among the keys visible
/// after the replug — a refusal either way, but only one of them is an
/// accusation, and only one of them names the right way out.
fn not_present_message(
    expected_model: &str,
    expected_serial: &str,
    waited_secs: u64,
    present: &str,
    reason: NotPresentReason,
    noun: &str,
    rerun: &str,
) -> String {
    match reason {
        NotPresentReason::DifferentKey => format!(
            "the key now connected is not the one this {noun} was confirmed for: \
             expected {} serial {}, found {present}. Nothing was reset over \
             FIDO2 — plug the intended key in and re-run `{rerun}`.",
            sanitize_terminal(expected_model),
            sanitize_terminal(expected_serial),
        ),
        NotPresentReason::Unidentified => format!(
            "the key this {noun} was confirmed for ({} serial {}) did not \
             come back with an identity to match within {waited_secs} seconds of \
             the replug: found {present}. That is not a different key — its serial \
             is read over the card interface, which re-registers with the \
             smart-card service a beat after the FIDO one, so a key that is simply \
             slow to settle looks exactly like this. Nothing was reset over FIDO2 \
             — give it a moment, then run `{FIDO_RESET_RERUN}` to finish the \
             wipe{}",
            sanitize_terminal(expected_model),
            sanitize_terminal(expected_serial),
            if rerun == FIDO_RESET_RERUN {
                ".".to_string()
            } else {
                // Re-running a whole-device wipe would repeat the applet
                // resets and race the same way.
                format!(
                    " (re-running `{rerun}` would repeat the applet resets and race \
                     the same way)."
                )
            },
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
/// which already accepts a relabeled key. The name stays only as the fallback
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

/// How long a FIDO2 reset waits for the armed key to be unplugged and plugged
/// back in before giving up with nothing sent.
const REPLUG_BUDGET: std::time::Duration = std::time::Duration::from_secs(60);
/// How often the replug wait re-scans HID.
const REPLUG_POLL: std::time::Duration = std::time::Duration::from_millis(300);

/// The replug wait ran out: the armed key was never seen leaving and coming
/// back, so no reset was sent.
#[derive(Debug)]
struct NoReplugSeen;

impl std::fmt::Display for NoReplugSeen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "no replug seen within {} seconds; nothing was wiped",
            REPLUG_BUDGET.as_secs()
        )
    }
}

impl std::error::Error for NoReplugSeen {}

/// Watches successive HID scans for the armed key's node to disappear and a
/// FIDO node to (re)appear afterwards.
///
/// "Reappeared" means the armed path itself coming back, or a node that was
/// not there when the wait started (a replugged key may come back under a new
/// path). A key that was already connected elsewhere is never mistaken for the
/// replug, and nothing counts while the armed node is still present.
struct ReplugWatch<'a> {
    armed: &'a Path,
    baseline: Option<Vec<std::path::PathBuf>>,
    removed: bool,
}

impl<'a> ReplugWatch<'a> {
    fn new(armed: &'a Path) -> Self {
        ReplugWatch {
            armed,
            baseline: None,
            removed: false,
        }
    }

    /// Feed one scan of FIDO HID node paths; true once the replug is complete.
    fn observe(&mut self, nodes: &[std::path::PathBuf]) -> bool {
        let baseline = self.baseline.get_or_insert_with(|| nodes.to_vec());
        if !self.removed {
            if nodes.iter().any(|n| n == self.armed) {
                return false;
            }
            self.removed = true;
        }
        nodes
            .iter()
            .any(|n| n == self.armed || !baseline.contains(n))
    }
}

/// Poll `fido_nodes` every `poll` until a [`ReplugWatch`] sees the armed key
/// go and come back, or `elapsed` passes `budget`. Clock, sleep and scan are
/// injected so the wait is testable without hardware or real time.
fn wait_for_replug(
    armed: &Path,
    budget: std::time::Duration,
    poll: std::time::Duration,
    mut elapsed: impl FnMut() -> std::time::Duration,
    mut sleep: impl FnMut(std::time::Duration),
    mut fido_nodes: impl FnMut() -> Option<Vec<std::path::PathBuf>>,
) -> Result<(), NoReplugSeen> {
    let mut watch = ReplugWatch::new(armed);
    loop {
        // A failed scan says nothing about the key: skip it rather than read
        // it as "the armed node is gone" (or as an empty baseline).
        if let Some(nodes) = fido_nodes() {
            if watch.observe(&nodes) {
                return Ok(());
            }
        }
        if elapsed() + poll > budget {
            return Err(NoReplugSeen);
        }
        sleep(poll);
    }
}

/// The FIDO HID nodes connected right now: the cheap scan the replug wait
/// polls (no identity reads). `None` when the scan itself failed.
fn fido_hid_nodes() -> Option<Vec<std::path::PathBuf>> {
    keyroost_hid::enumerate().ok().map(|hids| {
        hids.into_iter()
            .filter(|h| h.is_fido())
            .map(|h| h.path)
            .collect()
    })
}

/// A FIDO2 reset over USB (`fido reset`, and the FIDO2 step of a whole-device
/// factory reset): wait for the replug the CTAP reset window requires (see
/// [`wait_for_replug`]), then *prove* the key that came back is the one the
/// wipe was confirmed for before touching it. `rerun` is the command the
/// refusal messages tell the user to run again.
///
/// Resolving a FIDO device from scratch after the replug is what makes this
/// dangerous: with one key connected the resolver auto-selects whatever is now
/// plugged in, a same-model key is indistinguishable by product name and hidraw
/// path, and `authenticatorReset` erases every passkey and the PIN with no
/// further confirmation. So the identity captured before the replug has to
/// match afterwards. A key that has no serial to match on can't prove that by
/// identity, so it falls back to proving it by exclusion — see
/// `reinserted_serial_less_target` — and any second key in sight refuses.
///
/// `step_name` is this step's name in a multi-step factory reset (`"FIDO2"`),
/// printed with the touch prompt instead of [`fido_reset_at`]'s own generic
/// one, so the two callers (the factory reset and the standalone `fido
/// reset`) each print exactly one touch prompt, not both. `None` for the
/// standalone reset, which has no step name to show and keeps the generic one.
#[allow(clippy::too_many_arguments)]
fn fido_reset_after_replug(
    armed_path: &Path,
    label: &str,
    expected_serial: &str,
    expected_model: &str,
    expected_ids: Option<(u16, u16)>,
    noun: &str,
    rerun: &str,
    step_name: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let serial_less = expected_serial.is_empty();

    // No Enter to press: the replug itself is the go-ahead. Watching the cheap
    // HID-only scan (no identity reads) keeps the poll light; a run nobody
    // replugs for simply times out with nothing sent to the key.
    eprintln!(
        "Unplug {} and plug it back in now (waiting up to {} seconds)\u{2026}",
        sanitize_terminal(label),
        REPLUG_BUDGET.as_secs()
    );
    let start = std::time::Instant::now();
    wait_for_replug(
        armed_path,
        REPLUG_BUDGET,
        REPLUG_POLL,
        || start.elapsed(),
        std::thread::sleep,
        fido_hid_nodes,
    )?;

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

    // No identity reads here: the just-replugged key is exactly the kind of
    // unmatched node they would target, and an unanswered one would spend
    // the post-power-up window the reset has to land in.
    let mut present = crate::target::enumerate_without_identity_reads()?;
    let (mut found, mut settled) =
        match_reinsert(expected_serial, expected_model, expected_ids, &present);
    while !settled && std::time::Instant::now() + REINSERT_POLL < deadline {
        std::thread::sleep(REINSERT_POLL);
        present = crate::target::enumerate_without_identity_reads()?;
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
                 `{rerun}`.",
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
                noun,
                rerun,
            )
            .into());
        }
        ReinsertMatch::Ambiguous if serial_less => {
            return Err(format!(
                "'{}' exposes no serial to re-identify it by after a replug, so it can \
                 only be told apart from other keys by being the only one connected — \
                 but more than one is: {}. Nothing was reset over FIDO2 — unplug the \
                 others and re-run `{rerun}` with only the \
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
                 FIDO2 — re-run `{rerun}` with only the \
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
             FIDO2 — re-plug it and re-run `{rerun}`.",
            sanitize_terminal(&dev.model)
        )
        .into());
    };
    // Exactly one touch prompt: this step's name when there is one (factory
    // reset), else `fido_reset_at`'s own generic one (standalone `fido reset`).
    if let Some(name) = step_name {
        eprintln!("{name}  touch the key now\u{2026}");
    }
    fido_reset_at(&path, needs_generic_touch_prompt(step_name))
}

/// Whether [`fido_reset_at`] must print its own generic touch prompt: only
/// when the caller had no step name of its own to print instead, so a reset
/// shows exactly one touch prompt regardless of which caller it came from.
fn needs_generic_touch_prompt(step_name: Option<&str>) -> bool {
    step_name.is_none()
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
/// `factory_reset` blocks the PIN and PUK on its way to RESET — the card only
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

/// The credential a RESET resolved to: the management key or a PIN for
/// whichever RESET mechanism actually consumes it — `PivSession::
/// factory_reset` (today, always HID Crescendo's ACA instance when it runs
/// the device-wide step) for `factory-reset`'s PIV step, or a plain
/// `PivSession::authenticate_management_current` + `PivSession::reset` for
/// `piv reset` — see `resolve_reset_cli_auth`'s doc. Mirrors the GUI's
/// `GlobalResetAuth` — same two-way shape, same eventual conversion into
/// `keyroost_transport::CurrentMgmtAuth`.
enum ResetCliAuth {
    Key(zeroize::Zeroizing<Vec<u8>>),
    Pin(zeroize::Zeroizing<String>),
}

/// A RESET credential as given on the command line, read before any card
/// session: a management key (hex), `--mgmt-key default` (resolved inside the
/// session, from the applet's fingerprint), or a PIN.
enum ResetAuthInput {
    Key(zeroize::Zeroizing<Vec<u8>>),
    Default,
    Pin(zeroize::Zeroizing<String>),
}

const RESET_MGMT_KEY: Spec = Spec::current("PIV management key", "mgmt-key")
    .hex()
    .with_default();
const RESET_PIN: Spec = Spec::current("PIV PIN", "pin");

/// Read a RESET command's optional credential from its `--mgmt-key` /
/// `--pin` flags, mutually exclusive by construction — shared by
/// `factory-reset` and `piv reset`, the two commands that can hit
/// `PivQuirk::ResetNeedsManagementAuth`'s precondition. Only the flag given
/// is read; with none, nothing is — never a prompt: whether a credential is
/// needed at all, and of which kind, is only known once the card is open,
/// and nothing may be read while it is. `--mgmt-key stdin` / `--pin stdin`
/// typed at a terminal read hidden ([`Secrets::prompted`]).
///
/// `--mgmt-key default` is the CLI equivalent of the GUI's "Use default XAUTH
/// key" convenience: it reads nothing and instead reaches for keyroost's own
/// per-fingerprint quirks-table default (`PivSession::default_management_key`)
/// — a deliberate opt-in, so a scripted `--yes` run only reaches for a
/// well-known key when the caller explicitly asked for it.
fn read_reset_auth_input<I: crate::secrets::SecretIo>(
    sec: &mut Secrets<I>,
    mgmt_key: Option<&SecretSource>,
    pin: Option<&SecretSource>,
) -> Result<Option<ResetAuthInput>, Box<dyn std::error::Error>> {
    if crate::secrets::wants_default(mgmt_key) {
        return Ok(Some(ResetAuthInput::Default));
    }
    let key_src = Source::from_flag(mgmt_key);
    if key_src.given() {
        return Ok(Some(ResetAuthInput::Key(read_mgmt_key_hex(
            sec,
            &RESET_MGMT_KEY,
            key_src,
        )?)));
    }
    Ok(sec
        .read_given(&RESET_PIN, Source::from_flag(pin))?
        .map(ResetAuthInput::Pin))
}

/// Resolve [`ResetCliAuth`] from what [`read_reset_auth_input`] read, once
/// the open session has said a credential is needed.
///
/// `pin_gate` is `PivSession::pin_management_auth_gate`'s live verdict for
/// the device being reset, consulted only for the error below: the abort
/// message names the PIN option — and whether it's confirmed or merely
/// unverified on this device — precisely when that gate says a PIN is a
/// candidate at all, rather than always offering it (`PivQuirk::
/// ResetNeedsManagementAuth` says a credential is needed; it says nothing
/// about which kinds this fingerprint actually accepts).
///
/// `session` is only consulted for `--mgmt-key default` — every other branch
/// ignores it. Both real call sites already have one open (fingerprinting
/// the device is how `PivQuirk::ResetNeedsManagementAuth` gets checked in
/// the first place) and pass `Some`; it's `Option` rather than a required
/// reference purely so the unit tests below, which have no reader to open a
/// real session against, can pass `None`.
fn resolve_reset_cli_auth(
    input: Option<&ResetAuthInput>,
    pin_gate: keyroost_piv::compat::FeatureGate,
    session: Option<&mut keyroost_transport::PivSession<'_>>,
) -> Result<ResetCliAuth, Box<dyn std::error::Error>> {
    match input {
        Some(ResetAuthInput::Default) => {
            let session = session.expect(
                "--mgmt-key default always runs with an already-open PivSession at both call sites",
            );
            return session
                .default_management_key()
                .map(|key| ResetCliAuth::Key(zeroize::Zeroizing::new(key.to_vec())))
                .ok_or_else(|| {
                    "--mgmt-key default: keyroost has no known factory-default management key \
                     on record for this device; pass --mgmt-key env:NAME or --mgmt-key stdin instead"
                        .into()
                });
        }
        Some(ResetAuthInput::Key(key)) => return Ok(ResetCliAuth::Key(key.clone())),
        Some(ResetAuthInput::Pin(pin)) => return Ok(ResetCliAuth::Pin(pin.clone())),
        None => {}
    }
    use keyroost_piv::compat::FeatureGate;
    let pin_hint = match pin_gate {
        FeatureGate::Supported => {
            " or --pin env:NAME or stdin (a PIN works too, instead of the management key)"
        }
        FeatureGate::Unverified => {
            " or --pin env:NAME or stdin (a PIN may also work instead of the management key, \
             but that's unverified on this device)"
        }
        FeatureGate::Unsupported => "",
    };
    Err(format!(
        "this device needs a management-key credential to reset PIV \u{2014} pass \
         --mgmt-key env:NAME, stdin or default{pin_hint}"
    )
    .into())
}

/// Run one card-applet reset step, mapping its result to a StepOutcome so a
/// single failure is recorded, not propagated (continue-on-error).
/// `reset_auth` is only ever consulted for `ResetStep::Piv` — the credential
/// `run_factory_reset` resolved when `PivSession::global_reset_available`
/// said one was needed, handed straight through to
/// `PivSession::factory_reset`, which decides on its own whether the
/// device-wide mechanism or a plain PIV reset actually consumes it.
fn reset_one_card_applet(
    step: keyroost_resolve::ResetStep,
    dev: &keyroost_resolve::Device,
    debug: bool,
    reset_auth: Option<&ResetCliAuth>,
) -> keyroost_resolve::StepOutcome {
    use keyroost_resolve::{ResetStep, StepOutcome};

    // Every card step opens the resolved key's own reader — never a fresh
    // lookup that could land on another key.
    let reader = || {
        dev.reader
            .clone()
            .ok_or("this key has no smart-card reader any more")
    };

    // PIV gets its own path, ahead of the shared closure below:
    // `PivSession::factory_reset` decides on its own, from a live fingerprint,
    // whether to run the device-wide mechanism, a PIV-only reset, or skip the
    // applet outright (RESET known-unsupported on both axes, or a
    // precondition — an authenticated management-key session — with no
    // credential supplied) rather than fail it, a distinction `run()`'s
    // uniform Ok/Err mapping below can't express.
    if step == ResetStep::Piv {
        let outcome = (|| -> Result<StepOutcome, Box<dyn std::error::Error>> {
            let name = reader()?;
            keyroost_transport::PivSession::with_transaction_traced(&name, debug, |s| {
                let current = reset_auth.map(|auth| match auth {
                    ResetCliAuth::Key(key) => keyroost_transport::CurrentMgmtAuth::Key(key),
                    ResetCliAuth::Pin(pin) => {
                        keyroost_transport::CurrentMgmtAuth::Pin(pin.as_bytes())
                    }
                });
                Ok(match s.factory_reset(current) {
                    Ok(keyroost_transport::FactoryResetOutcome::Wiped) => StepOutcome::Wiped,
                    // The device-wide mechanism ran cleanly -- more than just PIV
                    // was wiped, so the report should say so rather than naming
                    // only the applet that happened to trigger it.
                    Ok(keyroost_transport::FactoryResetOutcome::WipedGlobal) => {
                        StepOutcome::WipedGlobal
                    }
                    // The device IS wiped -- only the courtesy XAUTH-key restore
                    // (the device-wide mechanism's own follow-up) failed.
                    // `WipedWithWarning`, not `Failed`: the wipe itself is done,
                    // so this counts as wiped, but the restore failure is real
                    // and still needs its own line.
                    Ok(keyroost_transport::FactoryResetOutcome::WipedKeyRestoreFailed) => {
                        StepOutcome::WipedWithWarning(
                            "restoring XAUTH key 1 to the factory-delivery value afterward failed \
                         \u{2014} it's left cleared instead. Set it manually \
                         (`keyroostctl piv mgmt-key change`) if you need it back."
                                .into(),
                        )
                    }
                    // Never touched the PIN or PUK -- refused before the burn
                    // sequence even started. Not a failure, an exclusion.
                    Err(
                        e @ (TransportError::PivResetUnsupported
                        | TransportError::PivResetNeedsManagementAuth),
                    ) => StepOutcome::Skipped(sanitize_terminal(&e.to_string())),
                    // These already state the card's real state and the way
                    // forward. Pointing at `keyroostctl piv reset` on top of them
                    // would be wrong: it sends the very RESET the card just
                    // refused, or it contradicts their own "re-run the factory
                    // reset" (Incomplete, PukGuessAccepted); the unverified-attempt,
                    // device-wide-mechanism, and authenticated-management-key
                    // failures already explain themselves in full, with no
                    // PIN/PUK blocked to caveat about.
                    Err(
                        e @ (TransportError::PivResetIncomplete(_)
                        | TransportError::PivPukGuessAccepted
                        | TransportError::PivResetUnverifiedFailed(_)
                        | TransportError::PivResetForcedFailed(_)
                        | TransportError::PivResetGlobalFailed(_)
                        | TransportError::PivResetManagementAuthFailed(_)),
                    ) => StepOutcome::Failed(sanitize_terminal(&e.to_string())),
                    Err(other) => StepOutcome::Failed(sanitize_terminal(
                        &piv_factory_reset_failure(&other.to_string()),
                    )),
                })
            })
        })();
        return outcome.unwrap_or_else(|e| StepOutcome::Failed(sanitize_terminal(&e.to_string())));
    }

    let run = || -> Result<(), Box<dyn std::error::Error>> {
        match step {
            ResetStep::Oath => {
                let mut s = keyroost_transport::OathSession::open(&reader()?)?;
                s.set_debug(debug);
                s.factory_reset()?;
            }
            ResetStep::OpenPgp => {
                let mut s = open_openpgp_at(&reader()?, debug)?;
                s.factory_reset()?;
            }
            ResetStep::Piv => unreachable!("handled above, before this closure"),
            ResetStep::Token2Otp => {
                let mut s = open_otp_on(dev, OtpTransportArg::Auto, debug)?;
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
            let mut session = open_oath(&mut Secrets::real(), access, debug)?;
            let listing = session.list()?;
            if listing.skipped > 0 {
                // The listing is PARTIAL — say so loudly, on stderr so it also
                // reaches --json users without breaking the output schema. An
                // invisible entry would otherwise be silently destroyed by a
                // reset the user believed they had fully audited.
                output::warn(&format!(
                    "{} credential entr{} on the key could not be decoded and {} not shown; \
                     the listing is incomplete",
                    listing.skipped,
                    if listing.skipped == 1 { "y" } else { "ies" },
                    if listing.skipped == 1 { "is" } else { "are" },
                ));
            }
            let creds = listing.credentials;
            if json_output() {
                let accounts: Vec<json_out::OathCredentialJson> = creds
                    .iter()
                    .map(|c| json_out::OathCredentialJson {
                        name: c.name.clone(),
                        oath_type: oath_type_str(c.oath_type),
                        algorithm: oath_algo_json(c.algorithm),
                    })
                    .collect();
                emit_json(&json_out::AccountsJson { accounts })?;
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
            let mut session = open_oath(&mut Secrets::real(), access, debug)?;
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
            algorithm,
            digits,
            counter,
            touch,
            access,
            encoding,
            ..
        } => {
            if *counter != 0 && !matches!(oath_type, OathTypeArg::Hotp) {
                return Err("--counter only applies to --type hotp".into());
            }
            let mut sec = Secrets::real();
            let pair = pair_of(oath_secret_pair(cmd))?;
            pair.check_first(&sec)?;
            crate::target::select(Need::Oath, access.reader.as_deref(), None)?;
            // The seed first (stdin line 1); the applet password, if it needs
            // one, second.
            let (seed_text, password) = pair.read_first(&mut sec)?;
            let secret = decode_seed(&seed_text.text()?, *encoding)?;
            let mut session = open_oath_from(&mut sec, access, password.source(), debug)?;
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
        OathCmd::Delete { name, access, yes } => {
            let dev = crate::target::select(Need::Oath, access.reader.as_deref(), None)?;
            let asked = crate::prompt::confirm_then_read(
                &dev,
                *yes,
                &format!("delete OATH credential {name:?}"),
            )?;
            let mut sec = Secrets::real();
            let (reader, password) = oath_current_password(&mut sec, access, debug)?;
            crate::prompt::reverify_if_asked(&dev, asked || sec.prompted())?;
            let mut session =
                open_oath_unlocked(&reader, password.as_deref().map(String::as_str), debug)?;
            session.delete(name)?;
            println!("Deleted OATH credential {:?}.", name);
        }
        OathCmd::Password {
            cmd: OathPasswordCmd::Set { access, .. },
        } => {
            let mut sec = Secrets::real();
            let pair = pair_of(oath_secret_pair(cmd))?;
            pair.second.check(&sec)?;
            // The current password first (stdin line 1, when the applet has
            // one), then the new one. The helper refuses an empty new
            // password; `oath password clear` removes it.
            let (name, current, new_pw) = oath_current_then(&mut sec, access, pair, debug)?;
            let new_pw = new_pw.read(&mut sec)?.text()?;
            reverify_if_prompted(&sec, Need::Oath, access.reader.as_deref())?;
            let mut session =
                open_oath_unlocked(&name, current.as_deref().map(String::as_str), debug)?;
            session.set_password(&new_pw)?;
            println!("OATH password set.");
        }
        OathCmd::Password {
            cmd: OathPasswordCmd::Clear { access },
        } => {
            let mut session = open_oath(&mut Secrets::real(), access, debug)?;
            session.clear_password()?;
            println!("OATH password cleared.");
        }
        OathCmd::Reset { reader, yes } => {
            let dev = crate::target::select(Need::Oath, reader.as_deref(), None)?;
            crate::prompt::confirm_on(&dev, *yes, "wipe the OATH applet")?;
            // Deliberately NOT open_oath(): reset must work on a
            // password-protected applet whose password is lost — that's its
            // entire purpose — so no unlock is attempted.
            let name = crate::target::reader_of(&dev)?;
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

/// The OTP endpoint(s) on an already-selected key. Both interfaces under
/// `auto`: HID first, the SAME key's reader as an open-time fallback (#82).
fn otp_target_for(
    dev: &keyroost_resolve::Device,
    transport: OtpTransportArg,
) -> Result<OtpTarget, String> {
    let label = sanitize_terminal(dev.name.as_deref().unwrap_or(&dev.model));
    match transport {
        OtpTransportArg::Hid => dev
            .hid_path
            .clone()
            .map(OtpTarget::HidPath)
            .ok_or_else(|| format!("'{label}' has no USB-HID interface for --transport hid")),
        OtpTransportArg::Ccid => dev
            .reader
            .clone()
            .map(OtpTarget::Reader)
            .ok_or_else(|| format!("'{label}' has no smart-card reader for --transport ccid")),
        OtpTransportArg::Auto => match (dev.hid_path.clone(), dev.reader.clone()) {
            (Some(p), Some(r)) => Ok(OtpTarget::HidThenReader(p, r)),
            (Some(p), None) => Ok(OtpTarget::HidPath(p)),
            (None, Some(r)) => Ok(OtpTarget::Reader(r)),
            (None, None) => Err(format!(
                "'{label}' exposes no OTP transport (neither USB-HID nor PC/SC)"
            )),
        },
    }
}

/// Resolve the key this `otp` invocation acts on through the shared finder
/// (KEY-003: never the first OTP-capable key that happens to enumerate).
fn select_otp(sel: &OtpSelect<'_>) -> Result<keyroost_resolve::Device, Box<dyn std::error::Error>> {
    crate::target::select(otp_need(sel.transport), sel.reader, sel.path)
}

/// Open a Token2 OTP session on an already-selected device and register a
/// touch prompt for button-required commands.
fn open_otp_on(
    dev: &keyroost_resolve::Device,
    transport: OtpTransportArg,
    debug: bool,
) -> Result<keyroost_transport::Token2OtpSession, Box<dyn std::error::Error>> {
    use keyroost_transport::Token2OtpSession as S;
    let mut session = match otp_target_for(dev, transport)? {
        OtpTarget::HidPath(p) => S::open_hid_path(&p, debug)?,
        OtpTarget::Reader(r) => S::open_pcsc_reader(&r, debug)?,
        OtpTarget::HidThenReader(p, r) => match S::open_hid_path(&p, debug) {
            Ok(s) => s,
            Err(hid_err) => {
                eprintln!(
                    "{}",
                    sanitize_terminal(&format!(
                        "USB-HID path failed ({hid_err}); trying the same key's \
                         smart-card reader\u{2026}"
                    ))
                );
                S::open_pcsc_reader(&r, debug)?
            }
        },
    };
    session.set_debug(debug);
    session.set_button_prompt(Box::new(|| {
        eprintln!("touch your key to continue\u{2026}");
    }));
    Ok(session)
}

/// Select the key for this `otp` invocation and open its OTP session.
fn open_otp(
    sel: &OtpSelect<'_>,
    debug: bool,
) -> Result<keyroost_transport::Token2OtpSession, Box<dyn std::error::Error>> {
    let dev = select_otp(sel)?;
    open_otp_on(&dev, sel.transport, debug)
}

/// A Token2 OTP function that ships as a separate product configuration. Which
/// functions a key has is fixed when it is made — a key supplied without one
/// can't gain it later — so a command that needs a missing function should say
/// that plainly rather than surface the protocol error its first APDU produces.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum OtpFeature {
    /// The on-device OTP store (`otp list` / `code` / `add` / `delete` / `reset`).
    OnDevice,
    /// The single HOTP-on-touch keystroke slot (`otp button set`).
    ButtonHotp,
}

impl OtpFeature {
    fn missing_message(self) -> &'static str {
        match self {
            OtpFeature::OnDevice => {
                "this key does not have the on-device OTP function: it reports that it was \
                 supplied without it, so it cannot store TOTP or HOTP entries. Token2 keys \
                 aren't upgradable after purchase — OTP is a separate product configuration, \
                 not something that can be switched on later. Run `keyroostctl otp info` to \
                 see the capabilities the key reports."
            }
            OtpFeature::ButtonHotp => {
                "this key does not have the HOTP-on-touch function: it reports that it was \
                 supplied without it. Token2 keys aren't upgradable after purchase — the \
                 keystroke slot is a separate product configuration, not something that can \
                 be switched on later. Run `keyroostctl otp info` to see the capabilities \
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

/// Read-only look before asking: open a session, refuse a key without
/// `feature` (as [`ensure_otp_feature`] does), and close the session again
/// so nothing is held open while the user answers. Returns the device
/// configuration, `None` when it couldn't be read.
fn otp_precheck(
    dev: &keyroost_resolve::Device,
    transport: OtpTransportArg,
    debug: bool,
    feature: OtpFeature,
) -> Result<Option<keyroost_token2otp::DeviceInfo>, Box<dyn std::error::Error>> {
    let mut session = open_otp_on(dev, transport, debug)?;
    let info = session.read_device_info().ok();
    if otp_feature_capability(info.as_ref(), feature) == Some(false) {
        return Err(feature.missing_message().into());
    }
    Ok(info)
}

/// Whether the HOTP-on-button slot may hold a seed. Fail-closed: an
/// unreadable configuration, or a short reply without the config byte
/// (some CCID/NFC paths), counts as configured.
fn button_hotp_maybe_configured(info: Option<&keyroost_token2otp::DeviceInfo>) -> bool {
    info.is_none_or(|i| !i.has_config_byte() || i.button_hotp_configured())
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

const OTP_PIN: Spec = Spec::current("OTP PIN", "pin");
const OTP_OLD_PIN: Spec = Spec::current("current OTP PIN", "pin");
const OTP_NEW_PIN: Spec = Spec::new_secret("new OTP PIN", "new-pin");

/// An OTP entry's seed: base32 through the token's own decoder (which also
/// checks the length), or hex with the same length check.
fn otp_seed(text: &str, e: SeedEncoding) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    match e {
        SeedEncoding::Base32 => keyroost_token2otp::decode_base32_seed(text).map_err(|err| {
            format!("the seed is not valid base32 ({err}); pass --encoding hex if it is hex")
        }),
        SeedEncoding::Hex => {
            let seed = decode_seed(text, e)?;
            keyroost_token2otp::validate_seed_len(seed.len())
                .map_err(|_| format!("seed must be 1..=64 bytes, got {}", seed.len()))?;
            Ok(seed)
        }
    }
}

/// The OTP PIN for a command that needs it only when the key has one set
/// (list, add, delete). A PIN given by flag is read as is; otherwise a
/// short session asks the key, is closed, and only then does a terminal
/// get the hidden prompt.
///
/// `waited` is whether the person has already been kept waiting (a question
/// shown, or an earlier secret typed at the prompt). On return the key has
/// been re-found whenever anything kept them waiting — before the probe
/// opens it, and again after a PIN typed at the prompt — so the caller can
/// open it straight away.
fn otp_pin_if_needed(
    sec: &mut Secrets,
    dev: &keyroost_resolve::Device,
    transport: OtpTransportArg,
    debug: bool,
    src: Source<'_>,
    waited: bool,
) -> Result<Option<zeroize::Zeroizing<String>>, Box<dyn std::error::Error>> {
    if let Some(pin) = sec.read_given(&OTP_PIN, src)? {
        crate::prompt::reverify_if_asked(dev, waited || sec.prompted())?;
        return Ok(Some(pin));
    }
    crate::prompt::reverify_if_asked(dev, waited)?;
    let pinned = {
        let mut probe = open_otp_on(dev, transport, debug)?;
        probe.pin_is_set()
    }; // the probe session is closed here, before any prompt
    if let Err(e) = &pinned {
        if sec.terminal_present() {
            eprintln!(
                "{}",
                sanitize_terminal(&format!(
                    "could not tell whether this key has an OTP PIN ({e}); asking for it in case"
                ))
            );
        }
    }
    let pin = otp_pin_after_probe(sec, pinned)?;
    // With no PIN flag, a PIN can only have come from the hidden prompt.
    crate::prompt::reverify_if_asked(dev, pin.is_some())?;
    Ok(pin)
}

/// A secret every run of the command needs: refused before any device I/O
/// when it has no source, read after the key is announced and before its
/// session opens.
fn otp_required_secret(
    sel: &OtpSelect<'_>,
    spec: &Spec,
    flag: Option<&SecretSource>,
) -> Result<zeroize::Zeroizing<String>, Box<dyn std::error::Error>> {
    let mut sec = Secrets::real();
    let src = Source::from_flag(flag);
    sec.check(spec, src)?;
    let dev = select_otp(sel)?;
    let secret = sec.read(spec, src)?;
    crate::prompt::reverify_if_asked(&dev, sec.prompted())?;
    Ok(secret)
}

/// What the key's answer means for the PIN: none needed when it has no PIN;
/// the hidden prompt (or a refusal naming the flags) when it has one. A
/// probe that failed is never taken as "no PIN" — that would carry on
/// without one and fail later with a less helpful error — so it is treated
/// like a PIN-protected key.
fn otp_pin_after_probe<I: crate::secrets::SecretIo, E: std::fmt::Display>(
    sec: &mut Secrets<I>,
    pinned: Result<bool, E>,
) -> Result<Option<zeroize::Zeroizing<String>>, String> {
    let why = match pinned {
        Ok(false) => return Ok(None),
        Ok(true) => "this key's OTP codes are PIN-protected".to_string(),
        Err(e) => sanitize_terminal(&format!(
            "could not tell whether this key's OTP codes are PIN-protected ({e})"
        )),
    };
    sec.read(&OTP_PIN, Source::NONE)
        .map(Some)
        .map_err(|e| format!("{why}; {e}"))
}

fn run_otp(
    cmd: &OtpCmd,
    sel: OtpSelect<'_>,
    debug: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        OtpCmd::List {
            unlock: OtpUnlock::Pin,
            pin,
        } => {
            let dev = select_otp(&sel)?;
            let pin = otp_pin_if_needed(
                &mut Secrets::real(),
                &dev,
                sel.transport,
                debug,
                Source::from_flag(pin.as_ref()),
                false,
            )?;
            let mut session = open_otp_on(&dev, sel.transport, debug)?;
            ensure_otp_feature(&mut session, OtpFeature::OnDevice)?;
            let now = unix_now() as u64;
            // A key whose PIN was set since the probe still surfaces a clear
            // "PIN required" error from enumerate_pinned.
            let entries = session.enumerate_pinned(now, pin.as_deref().map(|p| p.as_str()))?;
            print_otp_entries(&entries)?;
        }
        OtpCmd::List {
            unlock: OtpUnlock::Fingerprint,
            pin,
        } => {
            // A PIN flag here was refused at parse time (otp_unlock_conflict).
            debug_assert!(pin.is_none());
            let mut session = open_otp(&sel, debug)?;
            ensure_otp_feature(&mut session, OtpFeature::OnDevice)?;
            let now = unix_now() as u64;
            eprintln!("Touch the fingerprint sensor to unlock OTP codes\u{2026}");
            session.verify_fingerprint()?;
            let entries = session.enumerate(now)?;
            print_otp_entries(&entries)?;
        }
        OtpCmd::List {
            unlock: OtpUnlock::Auto,
            pin,
        } => {
            // The PIN is only the fingerprint's fallback: read when a flag
            // names it, never prompted for.
            let mut sec = Secrets::real();
            let dev = select_otp(&sel)?;
            let pin = sec.read_given(&OTP_PIN, Source::from_flag(pin.as_ref()))?;
            crate::prompt::reverify_if_asked(&dev, sec.prompted())?;
            let mut session = open_otp_on(&dev, sel.transport, debug)?;
            ensure_otp_feature(&mut session, OtpFeature::OnDevice)?;
            let now = unix_now() as u64;
            if session.fp_is_enabled().unwrap_or(false) {
                eprintln!("Touch the fingerprint sensor (or wait to fall back to PIN)\u{2026}");
            }
            let method = session.unlock_fp_or_pin(pin.as_deref().map(|p| p.as_str()), true)?;
            eprintln!(
                "Unlocked with {}.",
                match method {
                    keyroost_transport::UnlockMethod::Fingerprint => "fingerprint",
                    keyroost_transport::UnlockMethod::Pin => "PIN",
                }
            );
            let entries = session.enumerate(now)?;
            print_otp_entries(&entries)?;
        }
        OtpCmd::Code { app, account } => {
            let mut session = open_otp(&sel, debug)?;
            ensure_otp_feature(&mut session, OtpFeature::OnDevice)?;
            let now = unix_now() as u64;
            let entry = session.read_entry(now, app, account)?;
            match entry.code {
                Some(code) => {
                    if json_output() {
                        emit_json(&json_out::OtpCodeJson {
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
            encoding,
            ..
        } => {
            let mut sec = Secrets::real();
            let pair = pair_of(otp_secret_pair(cmd))?;
            pair.check_first(&sec)?;
            let dev = select_otp(&sel)?;
            // The seed first (stdin line 1); the OTP PIN, if the key has one,
            // second.
            let (seed_text, pin) = pair.read_first(&mut sec)?;
            let seed = otp_seed(&seed_text.text()?, *encoding)?;
            let waited = sec.prompted();
            let pin =
                otp_pin_if_needed(&mut sec, &dev, sel.transport, debug, pin.source(), waited)?;
            let mut session = open_otp_on(&dev, sel.transport, debug)?;
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
            session.write_entry_pinned(&entry, pin.as_deref().map(|p| p.as_str()))?;
            let label = if app.is_empty() {
                account.clone()
            } else {
                format!("{app}:{account}")
            };
            println!("Added OTP entry {label:?}.");
        }
        OtpCmd::Delete {
            app,
            account,
            pin,
            yes,
        } => {
            let label = if app.is_empty() {
                account.clone()
            } else {
                format!("{app}:{account}")
            };
            let dev = select_otp(&sel)?;
            otp_precheck(&dev, sel.transport, debug, OtpFeature::OnDevice)?;
            let asked = crate::prompt::confirm_then_read(
                &dev,
                *yes,
                &format!("delete OTP entry {label:?}"),
            )?;
            // Re-checks the key before its probe session and again after a
            // typed PIN, so nothing is left to re-check here.
            let pin = otp_pin_if_needed(
                &mut Secrets::real(),
                &dev,
                sel.transport,
                debug,
                Source::from_flag(pin.as_ref()),
                asked,
            )?;
            let mut session = open_otp_on(&dev, sel.transport, debug)?;
            session.delete_entry_pinned(app, account, pin.as_deref().map(|p| p.as_str()))?;
            println!("Deleted OTP entry {label:?}.");
        }
        OtpCmd::Reset { yes } => {
            let dev = select_otp(&sel)?;
            // Checked before the question and the touch prompt: no point
            // asking on a key that has nothing to erase.
            otp_precheck(&dev, sel.transport, debug, OtpFeature::OnDevice)?;
            crate::prompt::confirm_on(&dev, *yes, "erase every OTP entry")?;
            let mut session = open_otp_on(&dev, sel.transport, debug)?;
            eprintln!("touch your key to confirm the erase\u{2026}");
            session.erase_all()?;
            println!("Erased all OTP entries.");
        }
        OtpCmd::Serial => {
            let mut session = open_otp(&sel, debug)?;
            let sn = session.read_serial()?;
            let hex: String = sn.iter().map(|b| format!("{b:02x}")).collect();
            if json_output() {
                emit_json(&json_out::OtpSerialJson { serial: hex })?;
                return Ok(());
            }
            println!("{hex}");
        }
        OtpCmd::Button {
            cmd:
                OtpButtonCmd::Set {
                    digits,
                    no_enter,
                    long_touch,
                    numpad,
                    seed,
                    encoding,
                    yes,
                },
        } => {
            let mut sec = Secrets::real();
            let seed_src = Source::from_flag(seed.as_ref());
            sec.check(seed_spec(*encoding), seed_src)?;
            let dev = select_otp(&sel)?;
            // An unsupported key fails here, and an empty button slot needs
            // no question.
            let info = otp_precheck(&dev, sel.transport, debug, OtpFeature::ButtonHotp)?;
            let asked = if button_hotp_maybe_configured(info.as_ref()) {
                crate::prompt::confirm_then_read(&dev, *yes, "replace the HOTP-on-button seed")?
            } else {
                false
            };
            let seed = otp_seed(&sec.read(seed_spec(*encoding), seed_src)?, *encoding)?;
            crate::prompt::reverify_if_asked(&dev, asked || sec.prompted())?;
            let mut session = open_otp_on(&dev, sel.transport, debug)?;
            session.set_button_hotp(*digits, &seed, !*no_enter, *long_touch, *numpad)?;
            println!("Configured the HOTP-on-button keystroke slot.");
        }
        OtpCmd::Button {
            cmd: OtpButtonCmd::Delete { yes },
        } => {
            let dev = select_otp(&sel)?;
            otp_precheck(&dev, sel.transport, debug, OtpFeature::ButtonHotp)?;
            crate::prompt::confirm_on(&dev, *yes, "delete the HOTP-on-button seed")?;
            let mut session = open_otp_on(&dev, sel.transport, debug)?;
            session.delete_button_hotp()?;
            println!("Deleted the HOTP-on-button keystroke slot.");
        }
        OtpCmd::Info => {
            let mut session = open_otp(&sel, debug)?;
            // Show the raw READ_CONFIG bytes first (diagnostic), then the parse.
            // A failure is returned for `main` to print once.
            let raw = session.read_config()?;
            let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
            output::status(&format!("READ_CONFIG returned {} bytes: {hex}", raw.len()));
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
            // three leaves no USB interface to turn one back on through;
            // leaving only one is fragile (if that single interface can't be
            // reached you'd be locked out), so the tool keeps a two-interface
            // minimum as a safety margin.
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

            let dev = select_otp(&sel)?;
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

            // A typed phrase — not just "y" — for a hardware reconfiguration
            // this consequential; read from the terminal only.
            crate::prompt::confirm_typed_on(
                &dev,
                *yes,
                "reconfigure interfaces",
                "reconfigure this key's USB interfaces",
            )?;

            let mut session = open_otp_on(&dev, sel.transport, debug)?;
            session.set_device_type(disable)?;
            println!("Interface configuration updated. Re-plug the key for it to take effect.");
        }
        OtpCmd::Pin {
            cmd: OtpPinCmd::Status,
        } => {
            let mut session = open_otp(&sel, debug)?;
            ensure_otp_feature(&mut session, OtpFeature::OnDevice)?;
            // `None` = the key never answered the flag read, i.e. it has no
            // OTP-PIN feature. That is a fact about the key, not a failure.
            let flag = session.pin_status()?;
            if json_output() {
                emit_json(&json_out::OtpPinStatusJson {
                    supported: flag.is_some(),
                    pin_set: flag.as_ref().map(|f| f.is_set()),
                    pin_retries: flag.as_ref().map(|f| f.retries_left),
                    pin_retries_max: flag.as_ref().map(|f| f.max_retries),
                })?;
                return Ok(());
            }
            match flag {
                Some(f) if f.is_set() => println!(
                    "OTP PIN: set  (retries left: {}, max: {})",
                    f.retries_left, f.max_retries
                ),
                Some(_) => println!("OTP PIN: not set"),
                None => println!(
                    "OTP PIN: not offered by this key (the OTP-PIN feature arrived with R3.4)"
                ),
            }
        }
        OtpCmd::Pin {
            cmd: OtpPinCmd::Set { new_pin },
        } => {
            let pin = otp_required_secret(&sel, &OTP_NEW_PIN, new_pin.as_ref())?;
            let mut session = open_otp(&sel, debug)?;
            ensure_otp_feature(&mut session, OtpFeature::OnDevice)?;
            session.set_pin(pin.as_str())?;
            println!("OTP PIN set. Codes now require the PIN to read.");
        }
        OtpCmd::Pin {
            cmd: OtpPinCmd::Verify { pin },
        } => {
            let pin = otp_required_secret(&sel, &OTP_PIN, pin.as_ref())?;
            let mut session = open_otp(&sel, debug)?;
            ensure_otp_feature(&mut session, OtpFeature::OnDevice)?;
            session.verify_pin(pin.as_str())?;
            println!("OTP PIN verified; read window open for this connection.");
        }
        OtpCmd::Pin {
            cmd: OtpPinCmd::Change { .. },
        } => {
            let mut sec = Secrets::real();
            let pair = pair_of(otp_secret_pair(cmd))?;
            pair.check(&sec)?;
            let dev = select_otp(&sel)?;
            let (current, new) = pair.read_text(&mut sec)?;
            crate::prompt::reverify_if_asked(&dev, sec.prompted())?;
            let mut session = open_otp_on(&dev, sel.transport, debug)?;
            ensure_otp_feature(&mut session, OtpFeature::OnDevice)?;
            session.change_pin(current.as_str(), new.as_str())?;
            println!("OTP PIN changed.");
        }
        OtpCmd::Pin {
            cmd: OtpPinCmd::Clear { pin },
        } => {
            let current = otp_required_secret(&sel, &OTP_PIN, pin.as_ref())?;
            let mut session = open_otp(&sel, debug)?;
            ensure_otp_feature(&mut session, OtpFeature::OnDevice)?;
            session.remove_pin(current.as_str())?;
            println!("OTP PIN removed. Codes are readable without a PIN again.");
        }
        OtpCmd::Fingerprint {
            cmd: OtpFingerprintCmd::Status,
        } => {
            let mut session = open_otp(&sel, debug)?;
            ensure_otp_feature(&mut session, OtpFeature::OnDevice)?;
            match session.fp_supported()? {
                Some(true) => println!("Fingerprint-protected OTP: enabled"),
                Some(false) => println!("Fingerprint-protected OTP: disabled (supported)"),
                None => println!("Fingerprint-protected OTP: not available on this firmware"),
            }
        }
        OtpCmd::Fingerprint {
            cmd: OtpFingerprintCmd::Enable { pin },
        } => {
            let pin = otp_required_secret(&sel, &OTP_PIN, pin.as_ref())?;
            let mut session = open_otp(&sel, debug)?;
            ensure_otp_feature(&mut session, OtpFeature::OnDevice)?;
            session.set_fp_protection(pin.as_str(), true)?;
            println!("Fingerprint protection enabled. Touch the sensor to unlock codes.");
        }
        OtpCmd::Fingerprint {
            cmd: OtpFingerprintCmd::Disable { pin },
        } => {
            let pin = otp_required_secret(&sel, &OTP_PIN, pin.as_ref())?;
            let mut session = open_otp(&sel, debug)?;
            ensure_otp_feature(&mut session, OtpFeature::OnDevice)?;
            session.set_fp_protection(pin.as_str(), false)?;
            println!("Fingerprint protection disabled.");
        }
    }
    Ok(())
}

/// `otp list` output for every --unlock mode: JSON `{"accounts": [...]}`
/// or one line per entry ("(no OTP entries)" when there are none).
fn print_otp_entries(
    entries: &[keyroost_token2otp::Entry],
) -> Result<(), Box<dyn std::error::Error>> {
    if json_output() {
        let accounts: Vec<json_out::OtpEntryJson> = entries
            .iter()
            .map(|e| json_out::OtpEntryJson {
                app: e.app_name.clone(),
                account: e.account_name.clone(),
                otp_type: keyroost_transport::otp_type_str(e.otp_type),
                algorithm: otp_algo_json_t2(e.algorithm),
                code: e.code.clone(),
                touch_required: e.button_required,
            })
            .collect();
        return emit_json(&json_out::AccountsJson { accounts });
    }
    if entries.is_empty() {
        println!("(no OTP entries)");
    }
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
    Ok(())
}

fn otp_algo_str_t2(a: keyroost_token2otp::Algorithm) -> &'static str {
    match a {
        keyroost_token2otp::Algorithm::Sha1 => "SHA1",
        keyroost_token2otp::Algorithm::Sha256 => "SHA256",
    }
}

/// JSON spelling: lowercase, the same as `molto slots`.
fn otp_algo_json_t2(a: keyroost_token2otp::Algorithm) -> &'static str {
    match a {
        keyroost_token2otp::Algorithm::Sha1 => "sha1",
        keyroost_token2otp::Algorithm::Sha256 => "sha256",
    }
}

/// JSON spelling: lowercase, the same as `molto slots`.
fn oath_algo_json(a: keyroost_oath::Algorithm) -> &'static str {
    match a {
        keyroost_oath::Algorithm::Sha1 => "sha1",
        keyroost_oath::Algorithm::Sha256 => "sha256",
        keyroost_oath::Algorithm::Sha512 => "sha512",
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

const PGP_USER_PIN: Spec = Spec::current("user PIN (PW1)", "pin");
const PGP_SIGN_PIN: Spec = Spec::current("signing PIN (PW1)", "pin");
const PGP_ADMIN_PIN_VERIFY: Spec = Spec::current("admin PIN (PW3)", "pin");
const PGP_ADMIN_PIN: Spec = Spec::current("admin PIN (PW3)", "admin-pin");
const PGP_OLD_USER_PIN: Spec = Spec::current("current user PIN (PW1)", "pin");
const PGP_NEW_USER_PIN: Spec = Spec::new_secret("new user PIN (PW1)", "new-pin");
const PGP_OLD_ADMIN_PIN: Spec = Spec::current("current admin PIN (PW3)", "pin");
const PGP_NEW_ADMIN_PIN: Spec = Spec::new_secret("new admin PIN (PW3)", "new-pin");

fn run_openpgp(cmd: &OpenpgpCmd, debug: bool) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        OpenpgpCmd::Info { reader } => {
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
                    serial: status.full_serial().map(|s| s.to_string()),
                    sig_algo: status.algorithm_label(keyroost_openpgp::KeyCrt::Sign),
                    dec_algo: status.algorithm_label(keyroost_openpgp::KeyCrt::Decrypt),
                    aut_algo: status.algorithm_label(keyroost_openpgp::KeyCrt::Auth),
                    fingerprint_sig: fpr(&status.fingerprint_sig),
                    fingerprint_dec: fpr(&status.fingerprint_dec),
                    fingerprint_aut: fpr(&status.fingerprint_aut),
                    user_pin_retries: status.tries_pw1,
                    reset_code_retries: status.tries_rc,
                    admin_pin_retries: status.tries_pw3,
                    signature_count: status.signature_count,
                })?;
                return Ok(());
            }

            println!("AID:            {}", hex_encode(&status.aid));
            // AID serial: shown in decimal and hex (Yubico prints it in hex;
            // it equals the YubiKey's CCID/mgmt serial used for friendly
            // names). A Token2 key's full serial from its OTP applet is shown
            // as printed on the key.
            if let Some(serial) = status.serial_text() {
                println!("Serial:         {serial}");
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
        OpenpgpCmd::Pin {
            cmd: OpenpgpPinCmd::Verify { admin, pin, reader },
        } => {
            let which = pin_kind(*admin);
            let spec = match which {
                OpenpgpPinKind::User => &PGP_USER_PIN,
                OpenpgpPinKind::Admin => &PGP_ADMIN_PIN_VERIFY,
            };
            let mut sec = Secrets::real();
            let src = Source::from_flag(pin.as_ref());
            sec.check(spec, src)?;
            let name = crate::target::reader_for(Need::OpenPgp, reader.as_deref())?;
            let pin = sec.read(spec, src)?;
            reverify_if_prompted(&sec, Need::OpenPgp, reader.as_deref())?;
            let mut session = open_openpgp_at(&name, debug)?;
            session.verify_pin(which.pw_ref(), pin.as_bytes())?;
            println!("{} PIN verified.", which.label());
        }
        OpenpgpCmd::Key {
            cmd: OpenpgpKeyCmd::Show { slot, reader },
        } => {
            let mut session = open_openpgp(reader.as_deref(), debug)?;
            let attrs = session.algorithm_attributes(slot.to_crt())?;
            let key = session.read_public_key(slot.to_crt())?;
            print_openpgp_public_key(slot.label(), &attrs, &key);
        }
        OpenpgpCmd::Key {
            cmd: OpenpgpKeyCmd::Algorithms { reader },
        } => {
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
            let dev = crate::target::select(Need::OpenPgp, reader.as_deref(), None)?;
            crate::prompt::confirm_on(&dev, *yes, "wipe the OpenPGP applet")?;
            let name = crate::target::reader_of(&dev)?;
            let mut session = open_openpgp_at(&name, debug)?;
            let status = session.status()?;
            let ident = match status.full_serial() {
                Some(serial) => format!("serial {}", serial),
                None => format!("AID {}", hex_encode(&status.aid)),
            };
            session.factory_reset()?;
            println!(
                "OpenPGP applet on {} reset. All keys wiped; PINs restored to defaults.",
                ident
            );
        }
        OpenpgpCmd::Key {
            cmd:
                OpenpgpKeyCmd::Generate {
                    slot,
                    algorithm,
                    yes,
                    admin_pin,
                    reader,
                },
        } => {
            if let Some(a) = algorithm {
                a.to_alg().attributes(slot.to_crt())?;
            }
            let mut sec = Secrets::real();
            let src = Source::from_flag(admin_pin.as_ref());
            sec.check(&PGP_ADMIN_PIN, src)?;
            let dev = crate::target::select(Need::OpenPgp, reader.as_deref(), None)?;
            let asked = crate::prompt::confirm_then_read(
                &dev,
                *yes,
                &format!("overwrite the OpenPGP {} key", slot.label()),
            )?;
            let admin_pin = sec.read(&PGP_ADMIN_PIN, src)?;
            crate::prompt::reverify_if_asked(&dev, asked || sec.prompted())?;
            let mut session = open_openpgp_at(&crate::target::reader_of(&dev)?, debug)?;
            session.verify_pin(keyroost_openpgp::PW3_ADMIN, admin_pin.as_bytes())?;
            output::status(&format!(
                "Generating {} key — touch the key if it blinks…",
                slot.label()
            ));
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
        OpenpgpCmd::Key {
            cmd:
                OpenpgpKeyCmd::Import {
                    generate,
                    in_file,
                    slot,
                    yes,
                    admin_pin,
                    reader,
                },
        } => {
            let mut sec = Secrets::real();
            let src = Source::from_flag(admin_pin.as_ref());
            sec.check(&PGP_ADMIN_PIN, src)?;

            // Obtain the RSA-2048 key parts (full CRT set, big-endian) either by
            // host keygen or by loading a key file. Both go through the shared
            // `keyroost-rsakey` crate (which owns the scoped `rsa` dep); the card
            // decides which parts it wants. A key file is loaded and checked
            // first, so a wrong path or key type fails before the question and
            // the admin PIN; keygen waits until the question is answered.
            let loaded = if *generate {
                None
            } else {
                let path = in_file
                    .as_deref()
                    .ok_or("provide --generate or --in <FILE>")?;
                output::status(&format!("Loading RSA key from {}…", path.display()));
                Some(keyroost_rsakey::load_from_file(path)?)
            };
            let dev = crate::target::select(Need::OpenPgp, reader.as_deref(), None)?;
            let asked = crate::prompt::confirm_then_read(
                &dev,
                *yes,
                &format!("overwrite the OpenPGP {} key", slot.label()),
            )?;
            let admin_pin = sec.read(&PGP_ADMIN_PIN, src)?;
            let k = match loaded {
                Some(k) => k,
                None => {
                    output::status("Generating an RSA-2048 key on the host…");
                    keyroost_rsakey::generate_2048()?
                }
            };

            crate::prompt::reverify_if_asked(&dev, asked || sec.prompted())?;
            let mut session = open_openpgp_at(&crate::target::reader_of(&dev)?, debug)?;
            session.verify_pin(keyroost_openpgp::PW3_ADMIN, admin_pin.as_bytes())?;
            output::status(&format!("Importing {} key…", slot.label()));
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
        OpenpgpCmd::Name {
            cmd:
                OpenpgpNameCmd::Set {
                    name: cardholder,
                    admin_pin,
                    reader,
                },
        } => {
            let mut sec = Secrets::real();
            let src = Source::from_flag(admin_pin.as_ref());
            sec.check(&PGP_ADMIN_PIN, src)?;
            let name = crate::target::reader_for(Need::OpenPgp, reader.as_deref())?;
            let admin_pin = sec.read(&PGP_ADMIN_PIN, src)?;
            reverify_if_prompted(&sec, Need::OpenPgp, reader.as_deref())?;
            let mut session = open_openpgp_at(&name, debug)?;
            session.verify_pin(keyroost_openpgp::PW3_ADMIN, admin_pin.as_bytes())?;
            session.set_cardholder_name(cardholder.as_bytes())?;
            println!("Cardholder name set.");
        }
        OpenpgpCmd::Url {
            cmd:
                OpenpgpUrlCmd::Set {
                    url,
                    admin_pin,
                    reader,
                },
        } => {
            let mut sec = Secrets::real();
            let src = Source::from_flag(admin_pin.as_ref());
            sec.check(&PGP_ADMIN_PIN, src)?;
            let name = crate::target::reader_for(Need::OpenPgp, reader.as_deref())?;
            let admin_pin = sec.read(&PGP_ADMIN_PIN, src)?;
            reverify_if_prompted(&sec, Need::OpenPgp, reader.as_deref())?;
            let mut session = open_openpgp_at(&name, debug)?;
            session.verify_pin(keyroost_openpgp::PW3_ADMIN, admin_pin.as_bytes())?;
            session.set_url(url.as_bytes())?;
            println!("Public-key URL set.");
        }
        OpenpgpCmd::Sign {
            r#in,
            out,
            overwrite,
            pin,
            hash,
            reader,
        } => {
            let out_mode = crate::prompt::check_secret_overwrite(out.as_deref(), *overwrite)?;
            let mut sec = Secrets::real();
            let src = Source::from_flag(pin.as_ref());
            sec.check(&PGP_SIGN_PIN, src)?;
            let data = std::fs::read(r#in)
                .map_err(|e| format!("cannot read {}: {}", r#in.display(), e))?;
            let name = crate::target::reader_for(Need::OpenPgp, reader.as_deref())?;
            let pin = sec.read(&PGP_SIGN_PIN, src)?;
            reverify_if_prompted(&sec, Need::OpenPgp, reader.as_deref())?;
            let mut session = open_openpgp_at(&name, debug)?;
            session.verify_pin(keyroost_openpgp::PW1_SIGN, pin.as_bytes())?;
            // RSA slots want a PKCS#1 v1.5 DigestInfo (the card EMSA-pads and
            // RSA-signs it); ECDSA/EdDSA slots want the bare digest.
            let attrs = session.algorithm_attributes(keyroost_openpgp::KeyCrt::Sign)?;
            let input = openpgp_sign_input("signature", &attrs, *hash, &data)?;
            eprintln!("Signing ({}) — touch the key if it blinks…", hash.label());
            let sig = session.sign(&input)?;
            match out {
                Some(path) => {
                    write_private_file(path, &sig, out_mode)
                        .map_err(|e| format!("cannot write {}: {}", path.display(), e))?;
                    eprintln!("Wrote {} signature bytes to {}.", sig.len(), path.display());
                }
                None => println!("{}", hex_encode(&sig)),
            }
        }
        OpenpgpCmd::Decrypt {
            r#in,
            out,
            overwrite,
            pin,
            reader,
        } => {
            let out_mode = crate::prompt::check_secret_overwrite(out.as_deref(), *overwrite)?;
            let mut sec = Secrets::real();
            let src = Source::from_flag(pin.as_ref());
            sec.check(&PGP_USER_PIN, src)?;
            let cryptogram = std::fs::read(r#in)
                .map_err(|e| format!("cannot read {}: {}", r#in.display(), e))?;
            let name = crate::target::reader_for(Need::OpenPgp, reader.as_deref())?;
            let pin = sec.read(&PGP_USER_PIN, src)?;
            reverify_if_prompted(&sec, Need::OpenPgp, reader.as_deref())?;
            let mut session = open_openpgp_at(&name, debug)?;
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
                    write_private_file(path, &plain, out_mode)
                        .map_err(|e| format!("cannot write {}: {}", path.display(), e))?;
                    eprintln!(
                        "Wrote {} {} bytes to {}.",
                        plain.len(),
                        noun,
                        path.display()
                    );
                }
                None => println!("{}", hex_encode(&plain)),
            }
        }
        OpenpgpCmd::Authenticate {
            r#in,
            out,
            overwrite,
            pin,
            hash,
            reader,
        } => {
            let out_mode = crate::prompt::check_secret_overwrite(out.as_deref(), *overwrite)?;
            let mut sec = Secrets::real();
            let src = Source::from_flag(pin.as_ref());
            sec.check(&PGP_USER_PIN, src)?;
            let data = std::fs::read(r#in)
                .map_err(|e| format!("cannot read {}: {}", r#in.display(), e))?;
            let name = crate::target::reader_for(Need::OpenPgp, reader.as_deref())?;
            let pin = sec.read(&PGP_USER_PIN, src)?;
            reverify_if_prompted(&sec, Need::OpenPgp, reader.as_deref())?;
            let mut session = open_openpgp_at(&name, debug)?;
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
                    write_private_file(path, &sig, out_mode)
                        .map_err(|e| format!("cannot write {}: {}", path.display(), e))?;
                    eprintln!("Wrote {} signature bytes to {}.", sig.len(), path.display());
                }
                None => println!("{}", hex_encode(&sig)),
            }
        }
        OpenpgpCmd::Pin {
            cmd: OpenpgpPinCmd::Change { admin, reader, .. },
        } => {
            let mut sec = Secrets::real();
            let pair = pair_of(pgp_secret_pair(cmd))?;
            pair.check(&sec)?;
            let name = crate::target::reader_for(Need::OpenPgp, reader.as_deref())?;
            let (old, new) = pair.read_text(&mut sec)?;
            reverify_if_prompted(&sec, Need::OpenPgp, reader.as_deref())?;
            // CHANGE REFERENCE DATA carries the old PIN itself — no prior VERIFY.
            let mut session = open_openpgp_at(&name, debug)?;
            match pin_kind(*admin) {
                OpenpgpPinKind::User => {
                    session.change_user_pin(old.as_bytes(), new.as_bytes())?;
                    println!("User PIN (PW1) changed.");
                }
                OpenpgpPinKind::Admin => {
                    session.change_admin_pin(old.as_bytes(), new.as_bytes())?;
                    println!("Admin PIN (PW3) changed.");
                }
            }
        }
        OpenpgpCmd::Pin {
            cmd: OpenpgpPinCmd::Unblock { reader, .. },
        } => {
            let mut sec = Secrets::real();
            let pair = pair_of(pgp_secret_pair(cmd))?;
            pair.check(&sec)?;
            let name = crate::target::reader_for(Need::OpenPgp, reader.as_deref())?;
            let (admin, new) = pair.read_text(&mut sec)?;
            reverify_if_prompted(&sec, Need::OpenPgp, reader.as_deref())?;
            let mut session = open_openpgp_at(&name, debug)?;
            // reset_retry_counter verifies PW3 internally, then RESET RETRY
            // COUNTER sets the new user PIN — don't double-verify here.
            session.reset_retry_counter(admin.as_bytes(), new.as_bytes())?;
            println!("User PIN (PW1) unblocked and reset.");
        }
    }
    Ok(())
}

const PIV_PIN: Spec = Spec::current("PIN", "pin");
const PIV_OLD_PIN: Spec = Spec::current("current PIN", "pin");
const PIV_NEW_PIN: Spec = Spec::new_secret("new PIN", "new-pin");
const PIV_PUK: Spec = Spec::current("PUK", "puk");
const PIV_OLD_PUK: Spec = Spec::current("current PUK", "puk");
const PIV_NEW_PUK: Spec = Spec::new_secret("new PUK", "new-puk");
const PIV_MGMT_KEY: Spec = Spec::current("management key", "mgmt-key")
    .hex()
    .with_default();
const PIV_OLD_MGMT_KEY: Spec = Spec::current("current management key", "mgmt-key")
    .hex()
    .with_default();
const PIV_NEW_MGMT_KEY: Spec = Spec::new_secret("new management key", "new-mgmt-key").hex();

fn run_piv(cmd: &PivCmd, debug: bool) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        PivCmd::Info { reader } => {
            let name = crate::target::reader_for(Need::Piv, reader.as_deref())?;
            keyroost_transport::PivSession::with_transaction_traced(
                &name,
                debug,
                |session| -> Result<(), Box<dyn std::error::Error>> {
                    let status = session.status()?;

                    if json_output() {
                        emit_json(&json_out::PivStatusJson {
                            version: status
                                .version
                                .as_deref()
                                .map(keyroost_piv::format_version_bytes),
                            serial: status.serial.map(keyroost_piv::format_serial_short),
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
                                    slot: json_out::piv_slot_token(s.slot),
                                    slot_name: s.slot.label(),
                                    cert_present: s.cert_present,
                                    cert_len: if s.cert_present { s.cert_len } else { 0 },
                                    cert_unreadable: s.cert_unreadable.map(|r| r.code()),
                                    cert_compressed: s.cert_compressed,
                                })
                                .collect(),
                            applet_fingerprint: status.applet_fingerprint.to_string(),
                            applet_name: status.applet_name.clone(),
                            version_firmware: status
                                .version_firmware
                                .as_deref()
                                .map(keyroost_piv::format_version_bytes),
                        })?;
                        return Ok(());
                    }

                    // `applet_name` is only ever the token's own reported name (e.g.
                    // a Nitrokey's admin application) — empty means none was
                    // discovered, not that fingerprinting failed, so
                    // the plain-text line falls back to the fingerprint's generic
                    // display name instead of showing nothing.
                    let applet_name = if status.applet_name.is_empty() {
                        status.applet_fingerprint.applet_name().to_string()
                    } else {
                        status.applet_name.clone()
                    };

                    println!(
                        "Applet:      {} ({})",
                        applet_name, status.applet_fingerprint
                    );
                    // Tolerant of any non-empty GET VERSION reply, not just real
                    // Yubico firmware's 3 bytes — some third-party PIV applets that
                    // answer this vendor extension at all use a different byte count
                    // (observed: a Swissbit iShield Key 2 Pro replies with 4).
                    let version_str = status
                        .version
                        .as_deref()
                        .map(keyroost_piv::format_version_bytes)
                        .unwrap_or_else(|| "(unavailable)".to_string());
                    // `version_firmware` is the token's own firmware (read through a
                    // fingerprint-specific probe only some tokens answer — currently
                    // a Nitrokey only), not necessarily the same as the PIV applet's
                    // own version above; a
                    // dedicated line would repeat the applet version for every token
                    // that doesn't distinguish the two, so it's appended here instead
                    // — and only when it actually differs from the applet version.
                    let fw_suffix = status
                        .version_firmware
                        .as_deref()
                        .filter(|fw| Some(*fw) != status.version.as_deref())
                        .map(|fw| format!(" (FW v{})", keyroost_piv::format_version_bytes(fw)))
                        .unwrap_or_default();
                    println!("Version:     {version_str}{fw_suffix}");
                    match status.serial {
                        Some(s) => println!("Serial:      {}", keyroost_piv::format_serial_long(s)),
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
                            let or_empty =
                                |s: String| if s.is_empty() { "empty".to_string() } else { s };
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
                        println!(
                            "  {:<26} {}",
                            s.slot.label(),
                            piv_slot_state(
                                s.cert_unreadable,
                                s.cert_present,
                                s.cert_len,
                                s.cert_compressed,
                                s.key,
                            )
                        );
                    }
                    Ok(())
                },
            )?;
        }

        PivCmd::Pin {
            cmd: PivPinCmd::Change { reader, .. },
        } => {
            let mut sec = Secrets::real();
            let pair = pair_of(piv_secret_pair(cmd))?;
            pair.check(&sec)?;
            let name = crate::target::reader_for(Need::Piv, reader.as_deref())?;
            let (old, new) = pair.read_text(&mut sec)?;
            reverify_if_prompted(&sec, Need::Piv, reader.as_deref())?;
            keyroost_transport::PivSession::with_transaction_traced(
                &name,
                debug,
                |s| -> Result<(), Box<dyn std::error::Error>> {
                    s.change_pin(old.as_bytes(), new.as_bytes())?;
                    println!("PIN changed.");
                    Ok(())
                },
            )?;
        }

        PivCmd::Puk {
            cmd: PivPukCmd::Change { reader, .. },
        } => {
            let mut sec = Secrets::real();
            let pair = pair_of(piv_secret_pair(cmd))?;
            pair.check(&sec)?;
            let name = crate::target::reader_for(Need::Piv, reader.as_deref())?;
            let (old, new) = pair.read_text(&mut sec)?;
            reverify_if_prompted(&sec, Need::Piv, reader.as_deref())?;
            keyroost_transport::PivSession::with_transaction_traced(
                &name,
                debug,
                |s| -> Result<(), Box<dyn std::error::Error>> {
                    s.change_puk(old.as_bytes(), new.as_bytes())?;
                    println!("PUK changed.");
                    Ok(())
                },
            )?;
        }

        PivCmd::Pin {
            cmd: PivPinCmd::Unblock { reader, .. },
        } => {
            let mut sec = Secrets::real();
            let pair = pair_of(piv_secret_pair(cmd))?;
            pair.check(&sec)?;
            let name = crate::target::reader_for(Need::Piv, reader.as_deref())?;
            let (puk, new) = pair.read_text(&mut sec)?;
            reverify_if_prompted(&sec, Need::Piv, reader.as_deref())?;
            keyroost_transport::PivSession::with_transaction_traced(
                &name,
                debug,
                |s| -> Result<(), Box<dyn std::error::Error>> {
                    s.unblock_pin(puk.as_bytes(), new.as_bytes())?;
                    println!("PIN unblocked and reset.");
                    Ok(())
                },
            )?;
        }

        PivCmd::Retries {
            cmd:
                PivRetriesCmd::Set {
                    reader,
                    pin_tries,
                    puk_tries,
                    yes,
                    ..
                },
        } => {
            let mut sec = Secrets::real();
            let pair = pair_of(piv_secret_pair(cmd))?;
            pair.check(&sec)?;
            let dev = crate::target::select(Need::Piv, reader.as_deref(), None)?;
            let asked = crate::prompt::confirm_then_read(
                &dev,
                *yes,
                "set PIV retry counts (resets the PIN and PUK to factory defaults)",
            )?;
            let (pin, mgmt) = pair.read(&mut sec)?;
            let pin = pin.text()?;
            let mgmt = mgmt.mgmt(&PIV_MGMT_KEY)?;
            crate::prompt::reverify_if_asked(&dev, asked || sec.prompted())?;
            let name = crate::target::reader_of(&dev)?;
            keyroost_transport::PivSession::with_transaction_traced(
                &name,
                debug,
                |s| -> Result<(), Box<dyn std::error::Error>> {
                    let mgmt = mgmt_key_bytes(&mgmt, &PIV_MGMT_KEY, s)?;
                    authenticate_piv(s, &mgmt)?;
                    s.verify_pin(pin.as_bytes())?;
                    s.set_pin_retries(*pin_tries, *puk_tries)?;
                    println!(
                        "PIN/PUK retry counts set to {}/{}. Both reset to factory defaults.",
                        pin_tries, puk_tries
                    );
                    Ok(())
                },
            )?;
        }

        PivCmd::MgmtKey {
            cmd:
                PivMgmtKeyCmd::Change {
                    reader,
                    algorithm,
                    touch,
                    allow_pin_unlock,
                    force,
                    ..
                },
        } => {
            let mut sec = Secrets::real();
            let pair = pair_of(piv_secret_pair(cmd))?;
            pair.check(&sec)?;
            let name = crate::target::reader_for(Need::Piv, reader.as_deref())?;
            // The current key first (stdin line 1), then the new one (line 2).
            let (old, new) = pair.read(&mut sec)?;
            let old = old.mgmt(&PIV_OLD_MGMT_KEY)?;
            let new = new.mgmt_hex(&PIV_NEW_MGMT_KEY)?;
            let new_alg = algorithm.to_alg();
            if new.len() != new_alg.key_len() {
                return Err(format!(
                    "new management key is {} bytes; {} needs {}",
                    new.len(),
                    new_alg.label(),
                    new_alg.key_len()
                )
                .into());
            }
            // Gate on the applet's fingerprint before authenticating — the
            // fingerprint probe re-SELECTs PIV and would clear the auth.
            reverify_if_prompted(&sec, Need::Piv, reader.as_deref())?;
            keyroost_transport::PivSession::with_transaction_traced(
                &name,
                debug,
                |s| -> Result<(), Box<dyn std::error::Error>> {
                    let old = mgmt_key_bytes(&old, &PIV_OLD_MGMT_KEY, s)?;
                    guard_piv_feature(
                        s,
                        keyroost_piv::compat::PivExtension::SetManagementKey,
                        *force,
                    )?;
                    let pin_unlock_gate =
                        s.feature_gate(keyroost_piv::compat::PivExtension::PinManagementAuth);
                    // Whether to run the PIN-protected-storage maintenance step
                    // below (2a/2b) at all, alongside the key change:
                    // - `Supported`: always.
                    // - `Unverified`: always, with a warning — support was never
                    //   confirmed either way, so a caller who didn't even ask
                    //   still gets best-effort maintenance rather than being
                    //   blocked, but is told it isn't confirmed here.
                    // - `Unsupported`: only if `--allow-pin-unlock` was actually
                    //   given — that's a deliberate request for a feature
                    //   confirmed absent, gated like any other extension (error
                    //   unless `--force`). Left unset (the common case — most
                    //   invocations of this command are a plain key rotation
                    //   that never touches pin-unlock at all), a confirmed-absent
                    //   device is silently skipped: no error, no warning, just
                    //   the ordinary management-key change. Irrelevant on HID
                    //   Crescendo in practice (it resolves this extension
                    //   `Supported` unconditionally), which is also the
                    //   fingerprint `set_management_key_pin_protected` skips the
                    //   maintenance step for entirely regardless of this flag.
                    let maintain_pin_unlock = match pin_unlock_gate {
                        keyroost_piv::compat::FeatureGate::Supported => true,
                        keyroost_piv::compat::FeatureGate::Unverified => {
                            output::warn(&format!(
                                "{} {}",
                                keyroost_piv::compat::PivExtension::PinManagementAuth.requirement(),
                                keyroost_piv::compat::FeatureGate::UNVERIFIED_SUFFIX
                            ));
                            true
                        }
                        keyroost_piv::compat::FeatureGate::Unsupported if *allow_pin_unlock => {
                            guard_piv_feature(
                                s,
                                keyroost_piv::compat::PivExtension::PinManagementAuth,
                                *force,
                            )?;
                            true
                        }
                        keyroost_piv::compat::FeatureGate::Unsupported => false,
                    };
                    authenticate_piv(s, &old)?;
                    // A HID Crescendo unit whose management key isn't a real PIV
                    // object runs its own self-contained unlock right before PUT
                    // XAUTH KEY (see `set_management_key`'s doc) rather than relying
                    // on `authenticate_piv`'s auth above still being in force —
                    // `current` carries the same key again for that path; every
                    // other device ignores it.
                    let current = keyroost_transport::CurrentMgmtAuth::Key(&old);
                    let maintenance = if maintain_pin_unlock {
                        s.set_management_key_pin_protected(
                            current,
                            new_alg,
                            &new,
                            *touch,
                            *allow_pin_unlock,
                        )?
                    } else {
                        s.set_management_key(current, new_alg, &new, *touch)?;
                        keyroost_transport::PinProtectMaintenance::NotApplicable
                    };
                    println!(
                        "Management key changed to {}{}.",
                        new_alg.label(),
                        if *touch { " (touch required)" } else { "" }
                    );
                    match maintenance {
                        keyroost_transport::PinProtectMaintenance::NotApplicable => {}
                        keyroost_transport::PinProtectMaintenance::Ran {
                            printed_data: Ok(()),
                        } => {
                            println!(
                                "{}",
                                if *allow_pin_unlock {
                                    "PIN-protected management-key storage enabled: the PIN \
                                     alone now unlocks management on this device."
                                } else {
                                    "PIN-protected management-key storage disabled (if it \
                                     was set)."
                                }
                            );
                        }
                        keyroost_transport::PinProtectMaintenance::Ran {
                            printed_data: Err(e),
                        } => {
                            let action = if *allow_pin_unlock {
                                "enable"
                            } else {
                                "disable"
                            };
                            // `Supported` means this device is confirmed to support
                            // the write, so a failure here is a real problem — every
                            // other gate value (`Unverified`, or `Unsupported`
                            // overridden by `--force`) means it was never confirmed
                            // to work here at all, so the same failure is expected
                            // background noise (see `PinProtectMaintenance`'s doc).
                            if matches!(
                                pin_unlock_gate,
                                keyroost_piv::compat::FeatureGate::Supported
                            ) {
                                return Err(format!(
                                    "management key changed, but failed to {action} \
                                     PIN-protected management-key storage: {e}"
                                )
                                .into());
                            }
                            output::warn(&format!(
                                "management key changed, but could not {action} \
                                 PIN-protected management-key storage ({e}). keyroost's list \
                                 has no entry for this on this key."
                            ));
                        }
                    }
                    Ok(())
                },
            )?;
        }

        PivCmd::Key {
            cmd:
                PivKeyCmd::Generate {
                    reader,
                    slot,
                    algorithm,
                    pin_policy,
                    touch_policy,
                    mgmt_key,
                    out,
                    overwrite,
                    force,
                    yes,
                },
        } => {
            let [pub_mode] = crate::prompt::check_overwrites([out.as_deref()], *overwrite)?;
            let alg = algorithm.to_alg();
            // Gate the PIN/touch policy — Yubico extensions to GENERATE
            // ASYMMETRIC KEYPAIR, not SP 800-73-4 — on the applet's
            // fingerprint before authenticating, same reasoning as
            // `guard_piv_feature`'s own doc: its fingerprint probe re-SELECTs
            // PIV and would clear the auth. `default` is standard PIV and
            // needs neither extension, so both checks are skipped outright
            // when the caller didn't ask for anything non-default.
            let mut sec = Secrets::real();
            check_mgmt_key(&sec, &PIV_MGMT_KEY, mgmt_key.as_ref())?;
            let dev = crate::target::select(Need::Piv, reader.as_deref(), None)?;
            let gate = piv_confirm_replace(
                dev,
                debug,
                *yes,
                &format!("replace the key in PIV slot {}", slot_name(*slot)),
                |s| piv_slot_known_empty(s, slot.to_slot()),
            )?;
            let mgmt = read_mgmt_key_input(&mut sec, &PIV_MGMT_KEY, mgmt_key.as_ref())?;
            crate::prompt::reverify_if_asked(&gate.dev, gate.asked || sec.prompted())?;
            keyroost_transport::PivSession::with_transaction_traced(
                &gate.name,
                debug,
                |s| -> Result<(), Box<dyn std::error::Error>> {
                    let mgmt = mgmt_key_bytes(&mgmt, &PIV_MGMT_KEY, s)?;
                    // Unlike PIN/touch policy, every algorithm choice is gated —
                    // there's no "default" that's exempt: even the SP 800-73-4
                    // standardized algorithms (RSA-1024/2048, ECC P-256/P-384) aren't
                    // universally implemented, and RSA-3072/4096/Ed25519/X25519 are
                    // vendor extensions with no standard obligation at all. See
                    // `keyroost_piv::compat::PivExtension::SlotKeyAlgorithm`.
                    guard_piv_feature(
                        s,
                        keyroost_piv::compat::PivExtension::SlotKeyAlgorithm(alg),
                        *force,
                    )?;
                    if !matches!(pin_policy, CliPinPolicy::Default) {
                        guard_piv_feature(
                            s,
                            keyroost_piv::compat::PivExtension::SlotPinPolicy,
                            *force,
                        )?;
                    }
                    if !matches!(touch_policy, CliTouchPolicy::Default) {
                        guard_piv_feature(
                            s,
                            keyroost_piv::compat::PivExtension::SlotTouchPolicy,
                            *force,
                        )?;
                    }
                    // Narrower than the two gates above: a device can support the
                    // extension in general yet reject one specific value.
                    guard_piv_policy_value(
                        s,
                        keyroost_piv::compat::PivQuirk::SlotPinPolicyOnceNotSupported,
                        matches!(pin_policy, CliPinPolicy::Once),
                        "PIN policy \"once\"",
                        *force,
                    )?;
                    guard_piv_policy_value(
                        s,
                        keyroost_piv::compat::PivQuirk::SlotTouchPolicyCachedNotSupported,
                        matches!(touch_policy, CliTouchPolicy::Cached),
                        "Touch policy \"cached\"",
                        *force,
                    )?;
                    authenticate_piv(s, &mgmt)?;
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
                            return Err(format!(
                                "key generated, but encoding its public key failed: {}",
                                e
                            )
                            .into())
                        }
                    };
                    let pem = keyroost_piv::spki::to_pem(&der);
                    if let Some(path) = out {
                        pub_mode
                            .write(path, pem.as_bytes())
                            .map_err(|e| format!("write {}: {}", path.display(), e))?;
                        eprintln!(
                    "Wrote key material for {} to {} — pass it to `piv cert request`/`piv cert \
                     generate`'s --pubkey-in if you sign this key from a separate command.",
                    slot.to_slot().label(),
                    path.display()
                );
                    }
                    print!("{}", pem);
                    Ok(())
                },
            )?;
        }

        PivCmd::Cert {
            cmd:
                PivCertCmd::Import {
                    reader,
                    slot,
                    in_file,
                    mgmt_key,
                    compression,
                    yes,
                },
        } => {
            let mut sec = Secrets::real();
            check_mgmt_key(&sec, &PIV_MGMT_KEY, mgmt_key.as_ref())?;
            let bytes =
                std::fs::read(in_file).map_err(|e| format!("read {}: {}", in_file.display(), e))?;
            let der = cert_to_der(&bytes)?;
            let dev = crate::target::select(Need::Piv, reader.as_deref(), None)?;
            let gate = piv_confirm_replace(
                dev,
                debug,
                *yes,
                &format!("replace the certificate in PIV slot {}", slot_name(*slot)),
                |s| piv_cert_known_absent(s, slot.to_slot()),
            )?;
            let mgmt = read_mgmt_key_input(&mut sec, &PIV_MGMT_KEY, mgmt_key.as_ref())?;
            crate::prompt::reverify_if_asked(&gate.dev, gate.asked || sec.prompted())?;
            keyroost_transport::PivSession::with_transaction_traced(
                &gate.name,
                debug,
                |s| -> Result<(), Box<dyn std::error::Error>> {
                    let mgmt = mgmt_key_bytes(&mgmt, &PIV_MGMT_KEY, s)?;
                    authenticate_piv(s, &mgmt)?;
                    let choice = compression.choice();
                    let stored = s
                        .import_certificate(slot.to_slot(), &der, choice)
                        .map_err(|e| cert_import_error(e, choice))?;
                    print_cert_stored(
                        &format!(
                            "Imported {}-byte certificate into {}",
                            der.len(),
                            slot.to_slot().label()
                        ),
                        &stored,
                    );
                    Ok(())
                },
            )?;
        }

        PivCmd::Cert {
            cmd:
                PivCertCmd::Export {
                    reader,
                    slot,
                    out,
                    overwrite,
                    format,
                },
        } => {
            let [out_mode] = crate::prompt::check_overwrites([out.as_deref()], *overwrite)?;
            let name = crate::target::reader_for(Need::Piv, reader.as_deref())?;
            keyroost_transport::PivSession::with_transaction_traced(
                &name,
                debug,
                |s| -> Result<(), Box<dyn std::error::Error>> {
                    match s.read_certificate(slot.to_slot())? {
                        None => {
                            return Err(
                                format!("{} holds no certificate", slot.to_slot().label()).into()
                            )
                        }
                        Some(der) => {
                            let bytes = encode_cert(&der, *format);
                            match out {
                                Some(path) => {
                                    out_mode
                                        .write(path, &bytes)
                                        .map_err(|e| format!("write {}: {}", path.display(), e))?;
                                    let kind = match format {
                                        CertFormat::Pem => "PEM",
                                        CertFormat::Der => "DER",
                                    };
                                    output::status(&format!(
                                        "Wrote {}-byte {kind} certificate to {}.",
                                        bytes.len(),
                                        path.display()
                                    ));
                                }
                                None => {
                                    use std::io::Write;
                                    std::io::stdout().write_all(&bytes)?;
                                }
                            }
                        }
                    }
                    Ok(())
                },
            )?;
        }

        PivCmd::Cert {
            cmd:
                PivCertCmd::Request {
                    reader,
                    slot,
                    subject,
                    out,
                    overwrite,
                    pubkey_in,
                    keygen,
                    key_usage,
                    yes,
                    ..
                },
        } => {
            let [out_mode, pub_mode] = crate::prompt::check_overwrites(
                [out.as_deref(), keygen.pubkey_out.as_deref()],
                *overwrite,
            )?;
            let mut sec = Secrets::real();
            let pair = pair_of(piv_secret_pair(cmd))?;
            pair.check_first(&sec)?;
            if keygen.generate_key {
                pair.second.check(&sec)?;
            }
            // Judge `--key-usage` and whether the target key can sign before
            // the PIN or the management key is asked for: the algorithm is
            // knowable from `--algorithm`/`--pubkey-in` with no card I/O,
            // or else from a read-only look at the slot once it's selected.
            let known_alg = early_key_alg(keygen, pubkey_in.as_deref())?;
            check_signing_key(&key_usage.key_usage, slot.to_slot(), known_alg)?;
            let dev = crate::target::select(Need::Piv, reader.as_deref(), None)?;
            if known_alg.is_none() {
                let probed =
                    piv_probe_slot_alg(&crate::target::reader_of(&dev)?, debug, slot.to_slot())?;
                check_signing_key(&key_usage.key_usage, slot.to_slot(), probed)?;
            }
            // Only `--generate-key` replaces anything; a plain request
            // just reads the slot's key.
            let gate = if keygen.generate_key {
                piv_confirm_replace(
                    dev,
                    debug,
                    *yes,
                    &format!("replace the key in PIV slot {}", slot_name(*slot)),
                    |s| piv_slot_known_empty(s, slot.to_slot()),
                )?
            } else {
                ReplaceGate {
                    name: crate::target::reader_of(&dev)?,
                    dev,
                    asked: false,
                }
            };
            let (pin, mgmt_key) = pair.read_first(&mut sec)?;
            let pin = pin.text()?;
            // The key-generation step needs management-key auth; the CSR
            // signature that follows still only needs the PIN.
            let mgmt = if keygen.generate_key {
                Some(mgmt_key.read(&mut sec)?.mgmt(&PIV_MGMT_KEY)?)
            } else {
                None
            };
            crate::prompt::reverify_if_asked(&gate.dev, gate.asked || sec.prompted())?;
            keyroost_transport::PivSession::with_transaction_traced(
                &gate.name,
                debug,
                |s| -> Result<(), Box<dyn std::error::Error>> {
                    if let Some(mgmt) = &mgmt {
                        let mgmt = mgmt_key_bytes(mgmt, &PIV_MGMT_KEY, s)?;
                        authenticate_piv(s, &mgmt)?;
                        inline_generate_key(s, slot.to_slot(), keygen, pub_mode)?;
                    } else if let Some(path) = pubkey_in {
                        let (alg, key) = load_pubkey_material(path)?;
                        s.remember_pubkey(slot.to_slot(), alg, key);
                    }
                    eprintln!("Signing the request on the card (touch if it blinks)\u{2026}");
                    let ku = resolve_key_usage(
                        &key_usage.key_usage,
                        slot.to_slot(),
                        s.slot_key(slot.to_slot()).ok().map(|(a, _)| a),
                    )?;
                    let pem = s.generate_csr(slot.to_slot(), subject, pin.as_bytes(), ku)?;
                    match out {
                        Some(path) => {
                            // Only `--generate-key` changed the card; the
                            // request itself is stored nowhere.
                            let note = keygen.generate_key.then(|| {
                                format!(
                                    "the new key is in slot {}; rerun without \
                                     --generate-key to sign a request for it",
                                    slot_name(*slot)
                                )
                            });
                            out_mode.write(path, pem.as_bytes()).map_err(|e| {
                                crate::prompt::write_error(path, &e, note.as_deref())
                            })?;
                            eprintln!(
                                "Wrote certificate request for {} to {}.",
                                slot.to_slot().label(),
                                path.display()
                            );
                        }
                        None => print!("{}", pem),
                    }
                    Ok(())
                },
            )?;
        }

        PivCmd::Cert {
            cmd:
                PivCertCmd::Generate {
                    reader,
                    slot,
                    subject,
                    days,
                    months,
                    years,
                    out,
                    overwrite,
                    pubkey_in,
                    keygen,
                    compression,
                    key_usage,
                    yes,
                    ..
                },
        } => {
            let [out_mode, pub_mode] = crate::prompt::check_overwrites(
                [out.as_deref(), keygen.pubkey_out.as_deref()],
                *overwrite,
            )?;
            let valid_for = ValidFor::resolve(*days, *months, *years);
            valid_for.check()?;
            let mut sec = Secrets::real();
            let pair = pair_of(piv_secret_pair(cmd))?;
            pair.check(&sec)?;
            // Judge `--key-usage` and whether the target key can sign before
            // the PIN or the management key is asked for (see cert request).
            let known_alg = early_key_alg(keygen, pubkey_in.as_deref())?;
            check_signing_key(&key_usage.key_usage, slot.to_slot(), known_alg)?;
            let dev = crate::target::select(Need::Piv, reader.as_deref(), None)?;
            if known_alg.is_none() {
                let probed =
                    piv_probe_slot_alg(&crate::target::reader_of(&dev)?, debug, slot.to_slot())?;
                check_signing_key(&key_usage.key_usage, slot.to_slot(), probed)?;
            }
            // The new certificate always replaces the slot's; `--generate-key`
            // replaces its key as well.
            let gate = if keygen.generate_key {
                piv_confirm_replace(
                    dev,
                    debug,
                    *yes,
                    &format!(
                        "replace the key and certificate in PIV slot {}",
                        slot_name(*slot)
                    ),
                    |s| piv_slot_known_empty(s, slot.to_slot()),
                )?
            } else {
                piv_confirm_replace(
                    dev,
                    debug,
                    *yes,
                    &format!("replace the certificate in PIV slot {}", slot_name(*slot)),
                    |s| piv_cert_known_absent(s, slot.to_slot()),
                )?
            };
            // The PIN covers the signature (stdin line 1); management-key
            // auth covers the certificate import (line 2).
            let (pin, mgmt) = pair.read(&mut sec)?;
            let pin = pin.text()?;
            let mgmt = mgmt.mgmt(&PIV_MGMT_KEY)?;
            crate::prompt::reverify_if_asked(&gate.dev, gate.asked || sec.prompted())?;
            keyroost_transport::PivSession::with_transaction_traced(
                &gate.name,
                debug,
                |s| -> Result<(), Box<dyn std::error::Error>> {
                    let mgmt = mgmt_key_bytes(&mgmt, &PIV_MGMT_KEY, s)?;
                    authenticate_piv(s, &mgmt)?;
                    if keygen.generate_key {
                        inline_generate_key(s, slot.to_slot(), keygen, pub_mode)?;
                    } else if let Some(path) = pubkey_in {
                        let (alg, key) = load_pubkey_material(path)?;
                        s.remember_pubkey(slot.to_slot(), alg, key);
                    }
                    eprintln!("Signing the certificate on the card (touch if it blinks)\u{2026}");
                    let now = unix_now();
                    let choice = compression.choice();
                    let ku = resolve_key_usage(
                        &key_usage.key_usage,
                        slot.to_slot(),
                        s.slot_key(slot.to_slot()).ok().map(|(a, _)| a),
                    )?;
                    let (der, stored) = s
                        .self_signed_certificate(
                            slot.to_slot(),
                            subject,
                            i64::from(now),
                            valid_for.end_unix_secs(u64::from(now)),
                            pin.as_bytes(),
                            choice,
                            ku,
                        )
                        .map_err(|e| cert_import_error(e, choice))?;
                    print_cert_stored(
                        &format!(
                            "Self-signed certificate ({} bytes, {}) created and stored in {}",
                            der.len(),
                            valid_for.describe(),
                            slot.to_slot().label()
                        ),
                        &stored,
                    );
                    if let Some(path) = out {
                        let note = format!(
                            "the certificate is stored on the card; `piv cert export \
                             --slot {} --out FILE` writes it",
                            slot_name(*slot)
                        );
                        out_mode
                            .write(path, keyroost_piv::x509::pem_certificate(&der).as_bytes())
                            .map_err(|e| crate::prompt::write_error(path, &e, Some(&note)))?;
                        eprintln!("PEM copy written to {}.", path.display());
                    }
                    Ok(())
                },
            )?;
        }

        PivCmd::Test { reader, slot, pin } => {
            let piv_slot = slot.to_slot();
            // The PIN is always optional, independent of the slot's PIN
            // policy — it's the caller's call whether to test with or
            // without one. When given, verify it once up front so a wrong
            // PIN fails before any op and costs just one retry.
            let name = crate::target::reader_for(Need::Piv, reader.as_deref())?;
            let mut sec = Secrets::real();
            let pin = sec.read_given(&PIV_PIN, Source::from_flag(pin.as_ref()))?;
            reverify_if_prompted(&sec, Need::Piv, reader.as_deref())?;
            keyroost_transport::PivSession::with_transaction_traced(
                &name,
                debug,
                |s| -> Result<(), Box<dyn std::error::Error>> {
                    // The self-test verifies against the slot CERTIFICATE's public
                    // key on purpose: the cert is what other PIV software consumes,
                    // so a pass proves the cert matches the slot's key material. The
                    // cert object may hold it gzip-compressed (the writing tool's
                    // choice); read_certificate inflates it (#147/#148), so reading
                    // it back here works.
                    let cert = s.read_certificate(piv_slot)?.ok_or_else(|| {
                        format!("{} has no certificate to test against", piv_slot.label())
                    })?;
                    let (alg, pubkey) = keyroost_piv::x509_parse::parse_certificate_public_key(
                        &cert,
                    )
                    .map_err(|e| format!("could not read the slot certificate's key: {e}"))?;

                    if !keyroost_pivtest::SelfTest::all()
                        .into_iter()
                        .any(|op| keyroost_pivtest::supports(op, alg))
                    {
                        return Err(format!("no self-test applies to a {} key", alg.label()).into());
                    }

                    if let Some(pin) = &pin {
                        s.verify_pin(pin.as_bytes())?;
                    }
                    eprintln!(
                        "\u{2192} Testing {} ({}) on the card (touch if it blinks)\u{2026}",
                        piv_slot.label(),
                        alg.label()
                    );

                    let mut ran = 0usize;
                    let results = keyroost_pivtest::run(alg, &pubkey, |op, input| {
                        // PIN-per-use slots (9c) drop the verified state after each
                        // GENERAL AUTHENTICATE — re-verify before every op past the
                        // first that actually runs.
                        if let (Some(pin), true) = (&pin, ran > 0) {
                            s.verify_pin(pin.as_bytes())?;
                        }
                        ran += 1;
                        if op.is_key_agreement() {
                            s.key_agree(piv_slot, alg, input)
                        } else if op == keyroost_pivtest::SelfTest::Decrypt {
                            s.decrypt(piv_slot, alg, input)
                        } else {
                            s.sign(piv_slot, alg, input)
                        }
                    });

                    let all_ok = !results.iter().any(|(_, r)| r.is_failure());
                    if json_output() {
                        emit_json(&json_out::PivTestJson {
                            slot: json_out::piv_slot_token(piv_slot),
                            slot_name: piv_slot.label(),
                            algorithm: alg.label().to_string(),
                            ok: all_ok,
                            operations: results
                                .iter()
                                .map(|(op, r)| json_out::PivTestOpJson {
                                    operation: op.label().to_string(),
                                    result: match r {
                                        keyroost_pivtest::Outcome::Passed => "passed",
                                        keyroost_pivtest::Outcome::Skipped(_) => "skipped",
                                        keyroost_pivtest::Outcome::Failed(_) => "failed",
                                    }
                                    .to_string(),
                                    detail: match r {
                                        keyroost_pivtest::Outcome::Failed(e) => Some(e.clone()),
                                        _ => None,
                                    },
                                })
                                .collect(),
                        })?;
                    } else {
                        println!("{}", keyroost_pivtest::format_report(&results));
                    }
                    if !all_ok {
                        return Err("one or more self-tests failed".into());
                    }
                    Ok(())
                },
            )?;
        }

        PivCmd::Chuid {
            cmd:
                PivChuidCmd::Generate {
                    reader,
                    mgmt_key,
                    days,
                    months,
                    years,
                    guid,
                },
        } => {
            let mut sec = Secrets::real();
            check_mgmt_key(&sec, &PIV_MGMT_KEY, mgmt_key.as_ref())?;
            let valid_for = ValidFor::resolve(*days, *months, *years);
            valid_for.check()?;
            let guid = match guid {
                Some(hex) => keyroost_piv::parse_guid_hex(hex).ok_or(
                    "--guid must be 16 bytes of hex, dashes optional \
                     (e.g. aabbccdd-eeff-1122-3344-556677889900)",
                )?,
                None => keyroost_transport::random_chuid_guid()?,
            };
            let expiration = valid_for.chuid_expiration(u64::from(unix_now()));
            let name = crate::target::reader_for(Need::Piv, reader.as_deref())?;
            let mgmt = read_mgmt_key_input(&mut sec, &PIV_MGMT_KEY, mgmt_key.as_ref())?;
            reverify_if_prompted(&sec, Need::Piv, reader.as_deref())?;
            keyroost_transport::PivSession::with_transaction_traced(
                &name,
                debug,
                |s| -> Result<(), Box<dyn std::error::Error>> {
                    let mgmt = mgmt_key_bytes(&mgmt, &PIV_MGMT_KEY, s)?;
                    authenticate_piv(s, &mgmt)?;
                    s.new_chuid(&guid, &expiration)?;
                    println!("Wrote a new CHUID (GUID {}).", hex_encode(&guid));
                    Ok(())
                },
            )?;
        }

        PivCmd::Reset {
            reader,
            yes,
            force,
            mgmt_key,
            pin,
        } => {
            let dev = crate::target::select(Need::Piv, reader.as_deref(), None)?;
            let name = crate::target::reader_of(&dev)?;
            // First, read-only transaction: the compatibility gate and the
            // serial. The question is asked outside any transaction (a card
            // held idle while the user answers can drop it), then a fresh
            // transaction re-checks the gate quietly and does the wipe.
            let confirmed_serial = keyroost_transport::PivSession::with_transaction_traced(
                &name,
                debug,
                |s| -> Result<Option<u128>, Box<dyn std::error::Error>> {
                    // Gate on the applet's fingerprint before reading status — the
                    // fingerprint probe re-SELECTs PIV, same ordering concern
                    // `key delete`/`key move` document at their own call sites.
                    guard_piv_feature(s, keyroost_piv::compat::PivExtension::Reset, *force)?;
                    Ok(s.status()?.serial)
                },
            )?;
            let asked = crate::prompt::confirm_then_read(&dev, *yes, "wipe the PIV applet")?;
            // The credential, if one was given, is read before the session
            // opens; only the session can say whether it is needed.
            let mut sec = Secrets::real();
            let reset_input = read_reset_auth_input(&mut sec, mgmt_key.as_ref(), pin.as_ref())?;
            crate::prompt::reverify_if_asked(&dev, asked || sec.prompted())?;
            keyroost_transport::PivSession::with_transaction_traced(
                &name,
                debug,
                |s| -> Result<(), Box<dyn std::error::Error>> {
                    // Same verdict as above (already shown); re-run so this
                    // session carries --force's read override too.
                    check_piv_feature(s, keyroost_piv::compat::PivExtension::Reset, *force)?;
                    // The question above ran outside any transaction, and a
                    // same-model key plugged in meanwhile gets the same reader
                    // name: re-read the serial before any auth or RESET, and
                    // report the card this transaction actually wipes.
                    let serial = s.status()?.serial;
                    if !same_piv_card(confirmed_serial, serial) {
                        return Err(format!(
                            "the card in {} changed while waiting for a confirmation or a typed secret; \
                             nothing was reset",
                            sanitize_terminal(&name)
                        )
                        .into());
                    }
                    let serial = serial
                        .map(|v| format!("serial {v}"))
                        .unwrap_or_else(|| "this device".into());
                    // Some fingerprints need an authenticated management-key session
                    // before RESET is even accepted (`PivQuirk::
                    // ResetNeedsManagementAuth`) — the same precondition
                    // `factory-reset`'s PIV step fingerprints for, scoped here to
                    // the plain PIV-only mechanism this command sends
                    // (`PivSession::plan_factory_reset`'s own shape, never the
                    // device-wide one `factory-reset` may additionally reach for).
                    // Resolve a credential for it up front, before the wipe, rather
                    // than let the bare RESET below fail with a raw status word.
                    let auth = match s.plan_factory_reset() {
                        keyroost_transport::FactoryResetPlan::NeedsManagementAuth => {
                            let pin_gate = s.pin_management_auth_gate();
                            Some(resolve_reset_cli_auth(
                                reset_input.as_ref(),
                                pin_gate,
                                Some(s),
                            )?)
                        }
                        _ => None,
                    };
                    let current = auth.as_ref().map(|auth| match auth {
                        ResetCliAuth::Key(key) => keyroost_transport::CurrentMgmtAuth::Key(key),
                        ResetCliAuth::Pin(pin) => {
                            keyroost_transport::CurrentMgmtAuth::Pin(pin.as_bytes())
                        }
                    });
                    if let Some(current) = current {
                        s.authenticate_management_current(current)?;
                    }
                    // Some fingerprints are known to take unusually long to finish
                    // RESET (`PivQuirk::ResetLongRunning`, e.g. observed over a
                    // minute on ArekinathPivApplet::SwissbitIShield1) — warn right
                    // before the wipe actually starts, using the same wording the
                    // GUI's PIV pane shows on its "Reset applet" card, so a slow but
                    // working reset isn't mistaken for a hang and interrupted.
                    if s.quirks()
                        .contains(&keyroost_piv::compat::PivQuirk::ResetLongRunning)
                    {
                        output::warn(keyroost_piv::compat::PivQuirk::RESET_LONG_RUNNING_HINT);
                    }
                    // `current` is also handed to `force_reset_if_known_supported`
                    // below — dead today (`PivSession::reset`'s doc explains why),
                    // since the authenticated session above is what actually
                    // satisfies `NeedsManagementAuth` here; threaded through anyway
                    // so nothing here needs to change if the plain PIV-only RESET
                    // ever grows its own use for it. `--force` on a card listed
                    // without RESET sends one bare RESET and blocks nothing.
                    s.force_reset_if_known_supported(current, *force)?;
                    println!("PIV application reset to factory defaults on {}.", serial);
                    Ok(())
                },
            )?;
        }

        PivCmd::Cert {
            cmd:
                PivCertCmd::Delete {
                    reader,
                    slot,
                    mgmt_key,
                    yes,
                },
        } => {
            let mut sec = Secrets::real();
            check_mgmt_key(&sec, &PIV_MGMT_KEY, mgmt_key.as_ref())?;
            let dev = crate::target::select(Need::Piv, reader.as_deref(), None)?;
            let asked = crate::prompt::confirm_then_read(
                &dev,
                *yes,
                &format!("delete the certificate in PIV slot {}", slot_name(*slot)),
            )?;
            let mgmt = read_mgmt_key_input(&mut sec, &PIV_MGMT_KEY, mgmt_key.as_ref())?;
            crate::prompt::reverify_if_asked(&dev, asked || sec.prompted())?;
            let name = crate::target::reader_of(&dev)?;
            keyroost_transport::PivSession::with_transaction_traced(
                &name,
                debug,
                |s| -> Result<(), Box<dyn std::error::Error>> {
                    let mgmt = mgmt_key_bytes(&mgmt, &PIV_MGMT_KEY, s)?;
                    authenticate_piv(s, &mgmt)?;
                    s.clear_certificate(slot.to_slot())?;
                    println!(
                        "Cleared the certificate in {} (the private key remains).",
                        slot.to_slot().label()
                    );
                    Ok(())
                },
            )?;
        }

        PivCmd::Key {
            cmd:
                PivKeyCmd::Delete {
                    reader,
                    slot,
                    mgmt_key,
                    yes,
                    force,
                },
        } => {
            let mut sec = Secrets::real();
            check_mgmt_key(&sec, &PIV_MGMT_KEY, mgmt_key.as_ref())?;
            let dev = crate::target::select(Need::Piv, reader.as_deref(), None)?;
            let asked = crate::prompt::confirm_then_read(
                &dev,
                *yes,
                &format!("delete the key in PIV slot {}", slot_name(*slot)),
            )?;
            let mgmt = read_mgmt_key_input(&mut sec, &PIV_MGMT_KEY, mgmt_key.as_ref())?;
            crate::prompt::reverify_if_asked(&dev, asked || sec.prompted())?;
            // Gate on the applet's fingerprint before authenticating — the
            // fingerprint probe re-SELECTs PIV and would clear the auth.
            let name = crate::target::reader_of(&dev)?;
            keyroost_transport::PivSession::with_transaction_traced(
                &name,
                debug,
                |s| -> Result<(), Box<dyn std::error::Error>> {
                    let mgmt = mgmt_key_bytes(&mgmt, &PIV_MGMT_KEY, s)?;
                    guard_piv_feature(s, keyroost_piv::compat::PivExtension::DeleteKey, *force)?;
                    authenticate_piv(s, &mgmt)?;
                    s.delete_key(slot.to_slot())?;
                    println!(
                        "Deleted the private key in {} (the certificate object, if any, remains).",
                        slot.to_slot().label()
                    );
                    Ok(())
                },
            )?;
        }

        PivCmd::Key {
            cmd:
                PivKeyCmd::Move {
                    from,
                    to,
                    reader,
                    mgmt_key,
                    force,
                },
        } => {
            let mut sec = Secrets::real();
            check_mgmt_key(&sec, &PIV_MGMT_KEY, mgmt_key.as_ref())?;
            let dev = crate::target::select(Need::Piv, reader.as_deref(), None)?;
            let mgmt = read_mgmt_key_input(&mut sec, &PIV_MGMT_KEY, mgmt_key.as_ref())?;
            crate::prompt::reverify_if_asked(&dev, sec.prompted())?;
            let name = crate::target::reader_of(&dev)?;
            keyroost_transport::PivSession::with_transaction_traced(
                &name,
                debug,
                |s| -> Result<(), Box<dyn std::error::Error>> {
                    let mgmt = mgmt_key_bytes(&mgmt, &PIV_MGMT_KEY, s)?;
                    guard_piv_feature(s, keyroost_piv::compat::PivExtension::MoveKey, *force)?;
                    authenticate_piv(s, &mgmt)?;
                    let dest = to.to_slot();
                    if let Some(note) = piv_move_dest_note(s.slot_key_presence(dest), &dest.label())
                    {
                        eprintln!("note: {note}");
                    }
                    s.move_key(from.to_slot(), dest)?;
                    println!(
                        "Moved the private key {} \u{2192} {}; the certificate remains in {}.",
                        from.to_slot().label(),
                        to.to_slot().label(),
                        from.to_slot().label()
                    );
                    Ok(())
                },
            )?;
        }
    }
    Ok(())
}

/// The note `piv key move` prints when keyroost can't read whether the
/// destination holds a key: the move is then sent, and the card decides.
fn piv_move_dest_note(presence: keyroost_transport::SlotKeyPresence, slot: &str) -> Option<String> {
    matches!(presence, keyroost_transport::SlotKeyPresence::Unknown)
        .then(|| format!("keyroost can't tell whether {slot} holds a key; the card decides"))
}

/// Re-find the selected key before reopening it when a secret was typed at
/// the hidden prompt: the person may have swapped keys while typing. The
/// selection is memoised, so this never announces a second time; env and
/// piped sources skip it.
fn reverify_if_prompted<I: crate::secrets::SecretIo>(
    sec: &Secrets<I>,
    need: Need,
    reader: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    if sec.prompted() {
        let dev = crate::target::select(need, reader, None)?;
        crate::target::reverify(&dev)?;
    }
    Ok(())
}

/// Open the OpenPGP session on the reader matching `reader` (or the sole
/// OpenPGP reader), announcing the target on stderr.
fn open_openpgp(
    reader: Option<&str>,
    debug: bool,
) -> Result<keyroost_transport::OpenPgpSession, Box<dyn std::error::Error>> {
    let name = crate::target::reader_for(Need::OpenPgp, reader)?;
    open_openpgp_at(&name, debug)
}

/// Open the OpenPGP session on an exact, already-selected reader.
fn open_openpgp_at(
    name: &str,
    debug: bool,
) -> Result<keyroost_transport::OpenPgpSession, Box<dyn std::error::Error>> {
    let mut session = keyroost_transport::OpenPgpSession::open(name)?;
    session.set_debug(debug);
    Ok(session)
}

/// Authenticate the management key on an already-open [`keyroost_transport::PivSession`] against
/// the card's own algorithm — with a friendly wrong-length message *before*
/// the card sees anything, instead of a bare transport error afterwards.
///
/// Every call site opens the plain session via
/// [`keyroost_transport::PivSession::with_transaction_traced`] first, since
/// resolving `--mgmt-key default` (via [`mgmt_key_bytes`]) and feature
/// gates like [`guard_piv_feature`] both need one already open — the latter's
/// fingerprint probe re-SELECTs PIV and clears the auth state, so it must run
/// before this, not after.
fn authenticate_piv(
    session: &mut keyroost_transport::PivSession<'_>,
    mgmt_key: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    // Prefer GET METADATA; when the card stubs it out, probe every GENERAL
    // AUTHENTICATE P1 with a witness request and narrow by key length, rather
    // than blindly assuming 3DES.
    let alg = match session.reported_management_key_algorithm() {
        Some(reported) if mgmt_key.len() != reported.key_len() => {
            return Err(format!(
                "management key is {} bytes; this card's {} key needs {}",
                mgmt_key.len(),
                reported.label(),
                reported.key_len()
            )
            .into());
        }
        Some(reported) => reported,
        None => session
            .resolve_management_key_algorithm(mgmt_key.len())
            .map_err(|e| -> Box<dyn std::error::Error> {
                match e {
                    // Only the length verdict gets the friendly wording; a
                    // transport failure mid-probe (card pulled, reader gone)
                    // must surface as itself, not as a key-length complaint.
                    TransportError::PivBadKeyLength => format!(
                        "management key is {} bytes, which does not match any \
                         PIV management-key algorithm this card accepts",
                        mgmt_key.len()
                    )
                    .into(),
                    other => other.into(),
                }
            })?,
    };
    session.authenticate_management(alg, mgmt_key)?;
    Ok(())
}

/// Apply the per-fingerprint known-support table ([`keyroost_piv::compat`]) to
/// one of the Yubico vendor-extension operations before it runs, mirroring the
/// GUI's three-way gate and reusing its exact wording
/// ([`keyroost_piv::compat::PivExtension::requirement`] plus a state suffix):
///
/// * known-supported → run, no output;
/// * unverified → warn `<requirement> <UNVERIFIED_SUFFIX>`, then run;
/// * known-unsupported → fail with `<requirement> <INCOMPATIBLE_SUFFIX> Pass
///   --force to run anyway.`; with `force`, downgrade that to the same kind of
///   warning and run.
///
/// For [`keyroost_piv::compat::PivExtension::Reset`] specifically, the known-unsupported refusal
/// also checks [`keyroost_piv::compat::PivExtension::ResetGlobal`] — the device-wide reset
/// directive that takes PIV down with it alongside at least one other applet
/// — and, if that resolves `Supported` or `Unverified`, appends a sentence
/// pointing at `keyroostctl factory-reset` as the working alternative. This
/// is the CLI counterpart of the PIV pane's "Factory reset supported →" link
/// (`piv_reset_global_alternative_available` in the GUI), except the CLI also
/// mentions the unverified case — a sentence can carry that nuance where a
/// link either shows or doesn't.
///
/// Must be called on the session **before** management-key auth — it runs a
/// fingerprint probe that re-SELECTs PIV.
fn guard_piv_feature(
    session: &mut keyroost_transport::PivSession<'_>,
    extension: keyroost_piv::compat::PivExtension,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(warning) = check_piv_feature(session, extension, force)? {
        output::warn(&warning);
    }
    Ok(())
}

/// [`guard_piv_feature`] without printing: the refusal as the error, and the
/// warning (if any) returned for the caller to show. Lets a command that
/// re-checks in a second transaction avoid printing the same warning twice.
fn check_piv_feature(
    session: &mut keyroost_transport::PivSession<'_>,
    extension: keyroost_piv::compat::PivExtension,
    force: bool,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    use keyroost_piv::compat::{FeatureGate, PivExtension};
    // --force also covers the internal reads the table would skip (GET
    // METADATA, ATTEST) for the rest of this command, like the GUI's "Enable
    // Anyway"; each one still leaves a --debug trace line.
    if force {
        session.set_send_unsupported_reads(true);
    }
    let needs = extension.requirement();
    match session.feature_gate(extension) {
        FeatureGate::Supported => Ok(None),
        FeatureGate::Unverified => Ok(Some(format!("{needs} {}", FeatureGate::UNVERIFIED_SUFFIX))),
        FeatureGate::Unsupported if force => Ok(Some(format!(
            "{needs} {} Running anyway because --force was given.",
            FeatureGate::INCOMPATIBLE_SUFFIX
        ))),
        FeatureGate::Unsupported => {
            let mut msg = format!(
                "{needs} {} Pass --force to run anyway.",
                FeatureGate::INCOMPATIBLE_SUFFIX
            );
            if extension == PivExtension::Reset {
                if let Some(hint) = reset_global_alternative_hint(session) {
                    msg.push(' ');
                    msg.push_str(&hint);
                }
            }
            Err(msg.into())
        }
    }
}

/// When [`guard_piv_feature`] is about to refuse `PivExtension::Reset` as
/// known-unsupported, checks whether `PivExtension::ResetGlobal` resolves
/// `Supported` or `Unverified` on this same device and, if so, returns a
/// sentence pointing at the whole-device `keyroostctl factory-reset` as a
/// working alternative — `None` when `ResetGlobal` is itself known-unsupported,
/// leaving nothing to redirect to.
///
/// Runs its own fingerprint probe (same cost as [`keyroost_transport::PivSession::feature_gate`]
/// itself), so this is one more SELECT round trip — acceptable here since it
/// only runs on the road to an error, never on a path that would otherwise
/// succeed.
fn reset_global_alternative_hint(
    session: &mut keyroost_transport::PivSession<'_>,
) -> Option<String> {
    use keyroost_piv::compat::{FeatureGate, PivExtension};
    match session.feature_gate(PivExtension::ResetGlobal) {
        FeatureGate::Supported => Some(
            "Its whole-device factory reset is supported, though — run \
             `keyroostctl factory-reset` instead."
                .to_string(),
        ),
        FeatureGate::Unverified => Some(
            "It may reset as a whole device instead — try \
             `keyroostctl factory-reset`."
                .to_string(),
        ),
        FeatureGate::Unsupported => None,
    }
}

/// Refuse one specific PIN/touch policy *value* the fingerprint/version
/// quirk table ([`keyroost_piv::compat::PivQuirk`]) has flagged as
/// unsupported even though the surrounding extension
/// ([`keyroost_piv::compat::PivExtension::SlotPinPolicy`]/
/// [`SlotTouchPolicy`](keyroost_piv::compat::PivExtension::SlotTouchPolicy))
/// otherwise resolves fine — e.g. YubiKey firmware 4.0\u{2013}4.2 supports slot
/// touch policy in general but rejects the specific `cached` value
/// ([`keyroost_piv::compat::PivQuirk::SlotTouchPolicyCachedNotSupported`]).
/// Mirrors [`guard_piv_feature`]'s tone and `--force` override, but keys off a
/// quirk rather than a [`keyroost_piv::compat::FeatureGate`], since this is about one option within
/// an otherwise-supported extension, not the extension as a whole:
///
/// * `value_selected` is `false` (some other value was picked) → no-op,
///   regardless of the quirk;
/// * the quirk isn't present → no-op;
/// * quirk present and selected → refuse with `--force` guidance, unless
///   `force` is set, in which case warn and continue.
///
/// Must run before management-key auth for the same reason
/// [`guard_piv_feature`] must: [`PivSession::quirks`] shares the cached
/// fingerprint probe [`PivSession::feature_gate`] performs, and that probe
/// re-SELECTs PIV.
///
/// [`PivSession::quirks`]: keyroost_transport::PivSession::quirks
/// [`PivSession::feature_gate`]: keyroost_transport::PivSession::feature_gate
fn guard_piv_policy_value(
    session: &mut keyroost_transport::PivSession<'_>,
    quirk: keyroost_piv::compat::PivQuirk,
    value_selected: bool,
    value_label: &str,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if !value_selected || !session.quirks().contains(&quirk) {
        return Ok(());
    }
    if force {
        output::warn(&format!(
            "{value_label} is known to be unsupported on this device. Running anyway \
             because --force was given."
        ));
        return Ok(());
    }
    Err(format!(
        "{value_label} is known to be unsupported on this device. Pass --force to run anyway."
    )
    .into())
}

/// The slot as typed on the command line (`9a`, `82`, …).
fn slot_name(s: CliPivSlot) -> String {
    s.to_possible_value()
        .map(|v| v.get_name().to_string())
        .unwrap_or_default()
}

/// Whether `quirks` include one that makes this card's GET METADATA answer
/// untrustworthy, so its "no key here" can't be taken at its word either.
///
/// Stricter than the display rule `piv info` uses (keyroost-transport's
/// `metadata_says_no_key`, which distrusts only the key-type quirk): a
/// replace prompt decides whether anything can be lost, so it also distrusts
/// a card with the PIN/touch-policy quirk. Change the two together.
fn piv_metadata_quirky(
    quirks: &std::collections::BTreeSet<keyroost_piv::compat::PivQuirk>,
) -> bool {
    use keyroost_piv::compat::PivQuirk;
    quirks.contains(&PivQuirk::InsF7MetadataAlgorithmInvalid)
        || quirks.contains(&PivQuirk::InsF7MetadataPinTouchPolicyInvalid)
}

/// The `piv info` words for one slot. A slot without a certificate reads
/// "empty" only when the card said it holds no key (`key` from
/// `PivSession::slot_key_presence`); when keyroost can't tell, it says so.
fn piv_slot_state(
    cert_unreadable: Option<keyroost_transport::CertUnreadable>,
    cert_present: bool,
    cert_len: usize,
    cert_compressed: bool,
    key: keyroost_transport::SlotKeyPresence,
) -> String {
    use keyroost_transport::SlotKeyPresence;
    match (cert_unreadable, cert_present) {
        (Some(reason), _) => format!("cert present but unreadable ({reason})"),
        (None, true) => format!(
            "cert present ({cert_len} bytes{})",
            if cert_compressed {
                ", stored compressed"
            } else {
                ""
            }
        ),
        (None, false) => match key {
            SlotKeyPresence::Present => "key present, no certificate".to_string(),
            SlotKeyPresence::NoKey => "empty".to_string(),
            _ => "no certificate (a key may be present)".to_string(),
        },
    }
}

/// The fail-closed "nothing to lose in this slot" decision. Only a card
/// without a metadata quirk that answers the slot's GET METADATA with
/// "reference data not found" says there is no key; anything else — no
/// answer, a transmit error, a reply with a body (some cards answer that
/// way for slots that were never used, which can't be told apart from a
/// key) — counts as a key. The certificate must also be known absent.
fn piv_slot_empty_from(metadata_sw: Option<u16>, metadata_quirky: bool, cert_absent: bool) -> bool {
    !metadata_quirky && metadata_sw == Some(keyroost_piv::SW_REFERENCE_NOT_FOUND) && cert_absent
}

/// A certificate is known absent only when the read succeeded and found
/// none; an unreadable one, or a failed read, counts as present.
fn piv_cert_absent_from<E>(cert: &Result<Option<Vec<u8>>, E>) -> bool {
    matches!(cert, Ok(None))
}

/// Known empty: see [`piv_slot_empty_from`]. A card that can't tell is
/// treated as occupied, so the user is asked.
fn piv_slot_known_empty(
    s: &mut keyroost_transport::PivSession<'_>,
    slot: keyroost_piv::Slot,
) -> Result<bool, TransportError> {
    let quirky = piv_metadata_quirky(&s.quirks());
    let sw = s.metadata_status(slot.key_ref());
    // Only worth reading the certificate when the key answer allows "empty".
    let cert_absent =
        piv_slot_empty_from(sw, quirky, true) && piv_cert_absent_from(&s.read_certificate(slot));
    Ok(piv_slot_empty_from(sw, quirky, cert_absent))
}

/// Known to hold no certificate (see [`piv_cert_absent_from`]).
fn piv_cert_known_absent(
    s: &mut keyroost_transport::PivSession<'_>,
    slot: keyroost_piv::Slot,
) -> Result<bool, TransportError> {
    Ok(piv_cert_absent_from(&s.read_certificate(slot)))
}

/// The outcome of [`piv_confirm_replace`]: the reader to act on, the key
/// the user confirmed, and whether a question was actually shown (pass it
/// to [`crate::prompt::reverify_if_asked`] after reading the secrets).
struct ReplaceGate {
    name: String,
    dev: keyroost_resolve::Device,
    asked: bool,
}

/// Unless `known_empty` shows there is nothing in the slot to lose, ask
/// before `action` on the already-selected PIV key `dev`. The check runs in
/// its own short, read-only transaction (skipped under `--yes`), so no PC/SC
/// transaction is held while waiting for an answer. Callers read their
/// secrets next, then call
/// `reverify_if_asked(&gate.dev, gate.asked || sec.prompted())` right
/// before opening the session.
fn piv_confirm_replace(
    dev: keyroost_resolve::Device,
    debug: bool,
    yes: bool,
    action: &str,
    known_empty: impl FnOnce(&mut keyroost_transport::PivSession<'_>) -> Result<bool, TransportError>,
) -> Result<ReplaceGate, Box<dyn std::error::Error>> {
    let name = crate::target::reader_of(&dev)?;
    let mut asked = false;
    if !yes {
        let empty = keyroost_transport::PivSession::with_transaction_traced(
            &name,
            debug,
            |s| -> Result<bool, Box<dyn std::error::Error>> { Ok(known_empty(s)?) },
        )?;
        if !empty {
            asked = crate::prompt::confirm_then_read(&dev, yes, action)?;
        }
    }
    Ok(ReplaceGate { name, dev, asked })
}

/// The algorithm of the key already in `slot`, if the card says (GET
/// METADATA, or the slot certificate), read in its own short read-only
/// transaction — so `--key-usage` and an unsignable key are judged before
/// any PIN or management key is asked for.
fn piv_probe_slot_alg(
    name: &str,
    debug: bool,
    slot: keyroost_piv::Slot,
) -> Result<Option<keyroost_piv::KeyAlg>, Box<dyn std::error::Error>> {
    keyroost_transport::PivSession::with_transaction_traced(
        name,
        debug,
        |s| -> Result<Option<keyroost_piv::KeyAlg>, Box<dyn std::error::Error>> {
            Ok(s.slot_key_algorithm(slot))
        },
    )
}

/// The `--key-usage` and signable-key checks of `cert request` /
/// `cert generate`, once the slot key's algorithm is known (`None`: the card
/// can't say, and the in-session resolution judges it).
fn check_signing_key(
    key_usage: &[CliKeyUsage],
    slot: keyroost_piv::Slot,
    alg: Option<keyroost_piv::KeyAlg>,
) -> Result<(), Box<dyn std::error::Error>> {
    check_key_usage_args(key_usage, slot, alg)?;
    if let Some(alg) = alg {
        guard_signable_alg(alg)?;
    }
    Ok(())
}

/// Refuse early when `alg` can't produce a signature — currently just
/// X25519, whose only card operation is ECDH key agreement (see
/// [`keyroost_piv::x509::signature_hash`]). Issuing a certificate for such a
/// key needs a different enrollment mechanism (CRMF/CMP-style, proving
/// possession via key agreement rather than a signature), which keyroost
/// doesn't implement. `piv cert generate` / `piv cert request` call this as soon
/// as the target algorithm is known — before any PIN/management-key prompt
/// or card write — so a doomed request fails fast instead of after a touch
/// prompt.
fn guard_signable_alg(alg: keyroost_piv::KeyAlg) -> Result<(), Box<dyn std::error::Error>> {
    keyroost_piv::x509::signature_hash(alg)
        .map(|_| ())
        .map_err(|_| {
            format!(
                "{} keys can't sign a certificate or certificate request \u{2014} that key type \
                 only supports key agreement. keyroost doesn't implement the CRMF/CMP-style \
                 enrollment such a key would need.",
                alg.label()
            )
            .into()
        })
}

/// The `--generate-key` convenience shared by `piv cert request` / `piv
/// cert generate`: generate a fresh key pair in `slot` on `s` (which must already
/// be management-key authenticated), and, if asked, drop a PEM copy of its
/// public key. [`PivSession::generate_key`](keyroost_transport::PivSession::generate_key) seeds this session's in-memory
/// pubkey cache, so the CSR / self-signed certificate that follows finds the
/// key without any `--pubkey-in`.
fn inline_generate_key(
    s: &mut keyroost_transport::PivSession<'_>,
    slot: keyroost_piv::Slot,
    keygen: &InlineKeyGen,
    pub_mode: crate::prompt::OutMode,
) -> Result<(), Box<dyn std::error::Error>> {
    let alg = keygen.algorithm.to_alg();
    eprintln!(
        "Generating {} in {} (touch the key if it blinks)\u{2026}",
        alg.label(),
        slot.label()
    );
    let pubkey = s.generate_key(
        slot,
        alg,
        keygen.pin_policy.to_policy(),
        keygen.touch_policy.to_policy(),
    )?;
    if let Some(path) = &keygen.pubkey_out {
        let der = keyroost_piv::spki::subject_public_key_info(&pubkey, alg)
            .map_err(|e| format!("key generated, but encoding its public key failed: {}", e))?;
        let pem = keyroost_piv::spki::to_pem(&der);
        // The key is already replaced; a rerun with --generate-key would
        // replace it again.
        let note = format!(
            "the new key is in slot {:02x}; rerun without --generate-key to use it",
            slot.key_ref()
        );
        pub_mode
            .write(path, pem.as_bytes())
            .map_err(|e| crate::prompt::write_error(path, &e, Some(&note)))?;
        eprintln!(
            "Wrote a copy of {}'s generated public key to {}.",
            slot.label(),
            path.display()
        );
    }
    Ok(())
}

/// A PIV management key as given: read before any card session (env /
/// stdin / prompt), or `--mgmt-key default`, resolved inside the session because
/// it depends on the applet's fingerprint.
enum MgmtKeyInput {
    Key(zeroize::Zeroizing<Vec<u8>>),
    Default,
}

/// [`Secrets::check`] for a management key, which `--mgmt-key default` also
/// satisfies.
fn check_mgmt_key<I: crate::secrets::SecretIo>(
    sec: &Secrets<I>,
    spec: &Spec,
    flag: Option<&SecretSource>,
) -> Result<(), String> {
    if crate::secrets::wants_default(flag) {
        Ok(())
    } else {
        sec.check(spec, Source::from_flag(flag))
    }
}

/// Read a management key (hex) before any card session, or defer
/// `--mgmt-key default` to [`mgmt_key_bytes`].
fn read_mgmt_key_input<I: crate::secrets::SecretIo>(
    sec: &mut Secrets<I>,
    spec: &Spec,
    flag: Option<&SecretSource>,
) -> Result<MgmtKeyInput, Box<dyn std::error::Error>> {
    if crate::secrets::wants_default(flag) {
        return Ok(MgmtKeyInput::Default);
    }
    Ok(MgmtKeyInput::Key(read_mgmt_key_hex(
        sec,
        spec,
        Source::from_flag(flag),
    )?))
}

/// Read a management key given as hex and decode it.
fn read_mgmt_key_hex<I: crate::secrets::SecretIo>(
    sec: &mut Secrets<I>,
    spec: &Spec,
    src: Source<'_>,
) -> Result<zeroize::Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
    let hex = sec.read(spec, src)?;
    Ok(decode_mgmt_key_hex(spec, &hex)?)
}

/// Decode a management key given as hex. The error names the key, never
/// the input (hex_decode's errors describe the problem only).
fn decode_mgmt_key_hex(spec: &Spec, hex: &str) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    let key = hex_decode(hex).map_err(|e| format!("the {} is not valid hex: {e}", spec.label))?;
    Ok(zeroize::Zeroizing::new(key))
}

/// The key bytes for `input`; `--mgmt-key default` looks up this device's known
/// factory default on the open session's fingerprint
/// ([`keyroost_transport::PivSession::default_management_key`]).
fn mgmt_key_bytes(
    input: &MgmtKeyInput,
    spec: &Spec,
    session: &mut keyroost_transport::PivSession<'_>,
) -> Result<zeroize::Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
    match input {
        MgmtKeyInput::Key(k) => Ok(k.clone()),
        MgmtKeyInput::Default => session
            .default_management_key()
            .map(|k| zeroize::Zeroizing::new(k.to_vec()))
            .ok_or_else(|| {
                format!(
                    "{}: keyroost has no known factory-default {} on record for this \
                     device; pass {} instead",
                    spec.default_flag(),
                    spec.label,
                    spec.env_or_stdin_hint(),
                )
                .into()
            }),
    }
}

/// The two secrets a command can read from stdin, in line order: with both
/// on stdin, the first line is `first` and the second line `second`. Each
/// such command builds its pair in one place from its own flags
/// ([`piv_secret_pair`], [`pgp_secret_pair`], [`otp_secret_pair`],
/// [`oath_secret_pair`], [`fido_pin_secret_pair`]) and reads through it; the
/// second secret is only reachable after the first is read
/// ([`SecretPair::read_first`]), so no handler can read them the other way
/// round.
#[derive(Clone, Copy)]
struct SecretPair<'a> {
    first: (&'static Spec, Option<&'a SecretSource>),
    second: SecondSecret<'a>,
}

/// The second secret of a [`SecretPair`], handed out once the first is read.
#[derive(Clone, Copy)]
struct SecondSecret<'a> {
    spec: &'static Spec,
    flag: Option<&'a SecretSource>,
}

/// One secret of a [`SecretPair`] as read: a value, or `default` (a
/// management key, resolved inside the card session).
enum PairValue {
    Value(zeroize::Zeroizing<String>),
    Default,
}

fn secret_pair<'a>(
    first: (&'static Spec, &'a Option<SecretSource>),
    second: (&'static Spec, &'a Option<SecretSource>),
) -> SecretPair<'a> {
    SecretPair {
        first: (first.0, first.1.as_ref()),
        second: SecondSecret {
            spec: second.0,
            flag: second.1.as_ref(),
        },
    }
}

/// [`Secrets::check`] for one flag; `default` satisfies a flag that takes it.
fn check_flag_secret<I: crate::secrets::SecretIo>(
    sec: &Secrets<I>,
    spec: &Spec,
    flag: Option<&SecretSource>,
) -> Result<(), String> {
    if spec.default_ok && crate::secrets::wants_default(flag) {
        Ok(())
    } else {
        sec.check(spec, Source::from_flag(flag))
    }
}

fn read_flag_secret<I: crate::secrets::SecretIo>(
    sec: &mut Secrets<I>,
    spec: &Spec,
    flag: Option<&SecretSource>,
) -> Result<PairValue, String> {
    if spec.default_ok && crate::secrets::wants_default(flag) {
        Ok(PairValue::Default)
    } else {
        Ok(PairValue::Value(sec.read(spec, Source::from_flag(flag))?))
    }
}

impl<'a> SecretPair<'a> {
    /// Check both secrets have a source (before any device I/O).
    fn check<I: crate::secrets::SecretIo>(&self, sec: &Secrets<I>) -> Result<(), String> {
        self.check_first(sec)?;
        self.second.check(sec)
    }
    fn check_first<I: crate::secrets::SecretIo>(&self, sec: &Secrets<I>) -> Result<(), String> {
        check_flag_secret(sec, self.first.0, self.first.1)
    }
    /// Read the first secret (stdin line 1); the second comes with it.
    fn read_first<I: crate::secrets::SecretIo>(
        self,
        sec: &mut Secrets<I>,
    ) -> Result<(PairValue, SecondSecret<'a>), String> {
        Ok((
            read_flag_secret(sec, self.first.0, self.first.1)?,
            self.second,
        ))
    }
    /// Read both, first then second.
    fn read<I: crate::secrets::SecretIo>(
        self,
        sec: &mut Secrets<I>,
    ) -> Result<(PairValue, PairValue), String> {
        let (a, second) = self.read_first(sec)?;
        Ok((a, second.read(sec)?))
    }
    /// Read both as text (no `default` on either flag).
    fn read_text<I: crate::secrets::SecretIo>(
        self,
        sec: &mut Secrets<I>,
    ) -> Result<(zeroize::Zeroizing<String>, zeroize::Zeroizing<String>), String> {
        let (a, b) = self.read(sec)?;
        Ok((a.text()?, b.text()?))
    }
}

impl<'a> SecondSecret<'a> {
    fn check<I: crate::secrets::SecretIo>(&self, sec: &Secrets<I>) -> Result<(), String> {
        check_flag_secret(sec, self.spec, self.flag)
    }
    fn read<I: crate::secrets::SecretIo>(self, sec: &mut Secrets<I>) -> Result<PairValue, String> {
        read_flag_secret(sec, self.spec, self.flag)
    }
    fn source(&self) -> Source<'a> {
        Source::from_flag(self.flag)
    }
}

impl PairValue {
    fn text(self) -> Result<zeroize::Zeroizing<String>, String> {
        match self {
            PairValue::Value(v) => Ok(v),
            PairValue::Default => Err("this secret has no default".into()),
        }
    }
    /// A management key: hex, or `default`.
    fn mgmt(self, spec: &Spec) -> Result<MgmtKeyInput, Box<dyn std::error::Error>> {
        match self {
            PairValue::Default => Ok(MgmtKeyInput::Default),
            PairValue::Value(hex) => Ok(MgmtKeyInput::Key(decode_mgmt_key_hex(spec, &hex)?)),
        }
    }
    /// A management key that must be given as hex.
    fn mgmt_hex(
        self,
        spec: &Spec,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
        Ok(decode_mgmt_key_hex(spec, &self.text()?)?)
    }
}

fn piv_secret_pair(cmd: &PivCmd) -> Option<SecretPair<'_>> {
    Some(match cmd {
        PivCmd::Pin {
            cmd: PivPinCmd::Change { pin, new_pin, .. },
        } => secret_pair((&PIV_OLD_PIN, pin), (&PIV_NEW_PIN, new_pin)),
        PivCmd::Puk {
            cmd: PivPukCmd::Change { puk, new_puk, .. },
        } => secret_pair((&PIV_OLD_PUK, puk), (&PIV_NEW_PUK, new_puk)),
        PivCmd::Pin {
            cmd: PivPinCmd::Unblock { puk, new_pin, .. },
        } => secret_pair((&PIV_PUK, puk), (&PIV_NEW_PIN, new_pin)),
        PivCmd::Retries {
            cmd: PivRetriesCmd::Set { pin, mgmt_key, .. },
        }
        | PivCmd::Cert {
            cmd: PivCertCmd::Request { pin, mgmt_key, .. },
        }
        | PivCmd::Cert {
            cmd: PivCertCmd::Generate { pin, mgmt_key, .. },
        } => secret_pair((&PIV_PIN, pin), (&PIV_MGMT_KEY, mgmt_key)),
        PivCmd::MgmtKey {
            cmd:
                PivMgmtKeyCmd::Change {
                    mgmt_key,
                    new_mgmt_key,
                    ..
                },
        } => secret_pair(
            (&PIV_OLD_MGMT_KEY, mgmt_key),
            (&PIV_NEW_MGMT_KEY, new_mgmt_key),
        ),
        _ => return None,
    })
}

fn pgp_secret_pair(cmd: &OpenpgpCmd) -> Option<SecretPair<'_>> {
    Some(match cmd {
        OpenpgpCmd::Pin {
            cmd:
                OpenpgpPinCmd::Change {
                    admin,
                    pin,
                    new_pin,
                    ..
                },
        } => match pin_kind(*admin) {
            OpenpgpPinKind::User => {
                secret_pair((&PGP_OLD_USER_PIN, pin), (&PGP_NEW_USER_PIN, new_pin))
            }
            OpenpgpPinKind::Admin => {
                secret_pair((&PGP_OLD_ADMIN_PIN, pin), (&PGP_NEW_ADMIN_PIN, new_pin))
            }
        },
        OpenpgpCmd::Pin {
            cmd: OpenpgpPinCmd::Unblock {
                admin_pin, new_pin, ..
            },
        } => secret_pair((&PGP_ADMIN_PIN, admin_pin), (&PGP_NEW_USER_PIN, new_pin)),
        _ => return None,
    })
}

fn otp_secret_pair(cmd: &OtpCmd) -> Option<SecretPair<'_>> {
    Some(match cmd {
        OtpCmd::Pin {
            cmd: OtpPinCmd::Change { pin, new_pin },
        } => secret_pair((&OTP_OLD_PIN, pin), (&OTP_NEW_PIN, new_pin)),
        OtpCmd::Add {
            seed,
            pin,
            encoding,
            ..
        } => secret_pair((seed_spec(*encoding), seed), (&OTP_PIN, pin)),
        _ => return None,
    })
}

fn oath_secret_pair(cmd: &OathCmd) -> Option<SecretPair<'_>> {
    Some(match cmd {
        OathCmd::Add {
            seed,
            access,
            encoding,
            ..
        } => secret_pair(
            (seed_spec(*encoding), seed),
            (&OATH_PASSWORD, &access.password),
        ),
        OathCmd::Password {
            cmd:
                OathPasswordCmd::Set {
                    new_password,
                    access,
                },
        } => secret_pair(
            (&OATH_PASSWORD, &access.password),
            (&OATH_NEW_PASSWORD, new_password),
        ),
        _ => return None,
    })
}

fn fido_pin_secret_pair(cmd: &FidoPinCmd) -> Option<SecretPair<'_>> {
    Some(match cmd {
        FidoPinCmd::Change { pin, new_pin, .. } => {
            secret_pair((&FIDO_OLD_PIN, pin), (&FIDO_NEW_PIN, new_pin))
        }
        _ => return None,
    })
}

/// The pair of a command its handler knows has one.
fn pair_of(pair: Option<SecretPair<'_>>) -> Result<SecretPair<'_>, String> {
    pair.ok_or_else(|| "internal error: this command has no secret pair".to_string())
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
fn write_private_file(
    path: &std::path::Path,
    data: &[u8],
    mode: crate::prompt::OutMode,
) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind, Write};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    // Nothing was there at check time: create it exclusively (O_CREAT|O_EXCL
    // never follows a link and fails if anything appeared since), owner-only
    // from the start.
    if mode == crate::prompt::OutMode::New {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true).mode(0o600);
        let mut f = opts.open(path).map_err(|e| {
            if e.kind() == ErrorKind::AlreadyExists {
                Error::new(ErrorKind::AlreadyExists, crate::prompt::APPEARED)
            } else {
                e
            }
        })?;
        return f.write_all(data).and_then(|_| f.sync_all());
    }

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
fn write_private_file(
    path: &std::path::Path,
    data: &[u8],
    mode: crate::prompt::OutMode,
) -> std::io::Result<()> {
    mode.write(path, data)
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
            output::note("file contains multiple certificates; using the first");
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
/// `piv key generate --out` writes) or raw DER, returning DER bytes.
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

/// Load a `--pubkey-in` file (as written by `piv key generate --out`) and
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

fn run_name(cmd: &NameCmd) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        NameCmd::Add { name, path, reader } => {
            key_name_add(name, path.as_deref(), reader.as_deref())
        }
        NameCmd::List => key_name_list(),
        NameCmd::Delete { name } => key_name_delete(name),
    }
}

/// Whether `dev` can be recorded in the name registry: it must be a row
/// keyroost actually detected (not a synthetic `--reader`/`--path` override —
/// `target::select` skips the capability check for those, so an override row
/// can reach here) and it must carry a serial, which is the match key
/// `name add` stores. A Molto2 is never connected during detection, so it
/// always has an empty serial and can't be named yet.
fn nameable(dev: &keyroost_resolve::Device) -> Result<(), String> {
    if dev.id.starts_with("override:") {
        return Err("can't name a key keyroost didn't detect; check `keyroostctl list`".into());
    }
    if dev.serial.is_empty() {
        return Err(
            "this key reports no serial without connecting, so it can't be named yet".into(),
        );
    }
    Ok(())
}

/// Build the registry entry for naming `dev`: the serial it was resolved
/// with, and whether that serial came off the USB-HID node itself (vs. a
/// smart-card applet read) — the same union the shared device model already
/// correlated, so this never re-derives identity on its own.
fn key_entry_for(
    name: &str,
    dev: &keyroost_resolve::Device,
    hids: &[keyroost_hid::HidDevice],
) -> keyroost_keyring::KeyEntry {
    let usb = dev
        .hid_path
        .as_ref()
        .and_then(|p| hids.iter().find(|h| &h.path == p))
        .and_then(|h| h.serial_number.as_deref())
        == Some(dev.serial.as_str());
    keyroost_keyring::KeyEntry {
        name: name.to_string(),
        serial: dev.serial.clone(),
        source: if usb {
            keyroost_keyring::IdSource::Usb
        } else {
            keyroost_keyring::IdSource::Ccid
        },
        vendor: (dev.vendor == "Yubico").then(|| "yubico".to_string()),
        aaguid: None,
        note: None,
    }
}

fn key_name_add(
    name: &str,
    path: Option<&Path>,
    reader: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    keyroost_keyring::validate_name(name)?;
    let mut keyring = Keyring::load_default()?;
    // Any row with a serial (FIDO, card-only, prog token) — the same rows the
    // GUI can name. The serial is the correlated one (whole-set attribution).
    let dev = crate::target::select(Need::Nameable, reader, path)?;
    nameable(&dev)?;
    let hids = keyroost_hid::enumerate().unwrap_or_default();
    keyring.add(key_entry_for(name, &dev, &hids))?;
    // Opt-in disclosure: state plainly what is stored, and how to undo it.
    eprintln!(
        "Recording \"{}\" \u{2192} serial {} ({}).",
        sanitize_terminal(name),
        sanitize_terminal(&dev.serial),
        sanitize_terminal(&dev.model)
    );
    eprintln!(
        "This saves the key's serial number to keys.json on this computer so the \
         key can be recognized by name later — delete it any time with \
         `keyroostctl name delete {}`.",
        name
    );
    let written = keyring.save_default()?;
    output::status(&format!("Saved to {}.", written.display()));
    Ok(())
}

fn key_name_list() -> Result<(), Box<dyn std::error::Error>> {
    let keyring = Keyring::load_default()?;
    if keyring.keys.is_empty() {
        println!("(no named keys; add one with `keyroostctl name add <name>`)");
        return Ok(());
    }
    let devices = crate::target::enumerate().unwrap_or_default();
    for k in &keyring.keys {
        let here = devices
            .iter()
            .any(|d| !d.serial.is_empty() && d.serial.eq_ignore_ascii_case(&k.serial));
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

fn key_name_delete(name: &str) -> Result<(), Box<dyn std::error::Error>> {
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

const FIDO_PIN: Spec = Spec::current("PIN", "pin");
const FIDO_OLD_PIN: Spec = Spec::current("current PIN", "pin");
const FIDO_NEW_PIN: Spec = Spec::new_secret("new PIN", "new-pin");

/// The PIN for a FIDO command that always needs it: refused before any
/// device I/O when it has no source, read after the key is announced and
/// before the command opens it.
fn fido_pin(
    path: Option<&std::path::Path>,
    flag: Option<&SecretSource>,
) -> Result<zeroize::Zeroizing<String>, Box<dyn std::error::Error>> {
    let mut sec = Secrets::real();
    let src = Source::from_flag(flag);
    sec.check(&FIDO_PIN, src)?;
    let dev = crate::target::select_fido(path)?;
    let pin = sec.read(&FIDO_PIN, src)?;
    fido_reverify_if_prompted(&sec, &dev)?;
    Ok(pin)
}

/// [`reverify_if_prompted`] for the FIDO-over-USB key.
/// `dev` is the key selected (and shown) before the PIN was read; it is
/// re-checked as is, never selected afresh, so a key swapped in while the
/// PIN was typed is caught.
fn fido_reverify_if_prompted<I: crate::secrets::SecretIo>(
    sec: &Secrets<I>,
    dev: &keyroost_resolve::Device,
) -> Result<(), Box<dyn std::error::Error>> {
    fido_reverify_with(sec, dev, crate::target::reverify)
}

/// [`fido_reverify_if_prompted`] with the re-check passed in (tests).
fn fido_reverify_with<I: crate::secrets::SecretIo>(
    sec: &Secrets<I>,
    dev: &keyroost_resolve::Device,
    reverify: impl FnOnce(&keyroost_resolve::Device) -> Result<(), Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    if sec.prompted() {
        reverify(dev)?;
    }
    Ok(())
}

fn run_fido(cmd: &FidoCmd) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        FidoCmd::Info { path } => {
            run_fido_info(path.as_deref())?;
            Ok(())
        }
        FidoCmd::Reset { yes, path, reader } => {
            let dev = crate::target::select(Need::FidoAny, reader.as_deref(), path.as_deref())?;
            // The USB ids are what a key with no serial is re-found by after
            // the replug; read them now, while the key is surely connected,
            // not after a question the user may answer with it unplugged.
            let ids = hid_ids_at(
                dev.hid_path.as_deref(),
                &keyroost_hid::enumerate().unwrap_or_default(),
            );
            crate::prompt::confirm_on(&dev, *yes, "wipe every FIDO2 credential and the PIN")?;
            match fido_reset_route(&dev, reader.is_some())? {
                FidoResetRoute::Card { reader } => run_fido_reset_reader(&reader)?,
                FidoResetRoute::Replug { path } => fido_reset_after_replug(
                    &path,
                    dev.name.as_deref().unwrap_or(&dev.model),
                    &dev.serial,
                    &dev.model,
                    ids,
                    FIDO_RESET_NOUN,
                    FIDO_RESET_RERUN,
                    None,
                )?,
            }
            Ok(())
        }
        FidoCmd::Pin { cmd } => run_fido_pin(cmd),
        FidoCmd::Credential { cmd } => run_fido_credentials(cmd),
        FidoCmd::Fingerprint { cmd } => run_fido_fingerprints(cmd),
        FidoCmd::Config { cmd } => run_fido_config(cmd),
        FidoCmd::Blob { cmd } => run_fido_large_blob(cmd),
        FidoCmd::Ssh { cmd } => run_fido_ssh_cert(cmd),
    }
}

fn run_fido_pin(cmd: &FidoPinCmd) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        FidoPinCmd::Retries { path } => {
            run_fido_pin_retries(path.as_deref())?;
            Ok(())
        }
        FidoPinCmd::Set { new_pin, path } => {
            let mut sec = Secrets::real();
            let src = Source::from_flag(new_pin.as_ref());
            sec.check(&FIDO_NEW_PIN, src)?;
            let dev = crate::target::select_fido(path.as_deref())?;
            let new_pin = sec.read(&FIDO_NEW_PIN, src)?;
            fido_reverify_if_prompted(&sec, &dev)?;
            run_fido_pin_set(path.as_deref(), &new_pin)?;
            Ok(())
        }
        FidoPinCmd::Change { path, .. } => {
            let mut sec = Secrets::real();
            let pair = pair_of(fido_pin_secret_pair(cmd))?;
            pair.check(&sec)?;
            let dev = crate::target::select_fido(path.as_deref())?;
            let (old_pin, new_pin) = pair.read_text(&mut sec)?;
            fido_reverify_if_prompted(&sec, &dev)?;
            run_fido_pin_change(path.as_deref(), &old_pin, &new_pin)?;
            Ok(())
        }
        FidoPinCmd::MinLength {
            length,
            force_change,
            yes,
            pin,
            path,
        } => {
            let mut sec = Secrets::real();
            let src = Source::from_flag(pin.as_ref());
            sec.check(&FIDO_PIN, src)?;
            let dev = crate::target::select_fido(path.as_deref())?;
            let pin = confirm_then_read_pin(
                &mut crate::prompt::RealTerm,
                &mut sec,
                *yes,
                &format!("raise the minimum PIN length to {length} (only a reset lowers it again)"),
                &crate::prompt::key_label(&dev),
                Some(&dev),
                src,
            )?;
            let length = *length;
            let force_change = *force_change;
            with_configurator(path.as_deref(), &pin, move |cfg, _info| {
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
        FidoPinCmd::ForceChange { pin, path } => {
            let pin = fido_pin(path.as_deref(), pin.as_ref())?;
            with_configurator(path.as_deref(), &pin, |cfg, _info| {
                cfg.force_pin_change()?;
                println!("A PIN change is now required on next use of this key.");
                Ok(())
            })?;
            Ok(())
        }
    }
}

fn run_fido_credentials(cmd: &FidoCredentialCmd) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        FidoCredentialCmd::List { pin, path } => {
            let pin = fido_pin(path.as_deref(), pin.as_ref())?;
            run_fido_creds_list(path.as_deref(), &pin)?;
            Ok(())
        }
        FidoCredentialCmd::Delete { id, pin, path, yes } => {
            let cred_id_bytes =
                hex_decode(id).map_err(|e| format!("--id is not valid hex: {}", e))?;
            let mut sec = Secrets::real();
            let src = Source::from_flag(pin.as_ref());
            sec.check(&FIDO_PIN, src)?;
            let dev = crate::target::select_fido(path.as_deref())?;
            let asked = crate::prompt::confirm_then_read(
                &dev,
                *yes,
                &format!("delete FIDO credential {}", hex_short(&cred_id_bytes)),
            )?;
            let pin = sec.read(&FIDO_PIN, src)?;
            crate::prompt::reverify_if_asked(&dev, asked || sec.prompted())?;
            run_fido_creds_delete(path.as_deref(), &pin, &cred_id_bytes)?;
            Ok(())
        }
        FidoCredentialCmd::Metadata { pin, path } => {
            let pin = fido_pin(path.as_deref(), pin.as_ref())?;
            run_fido_creds_metadata(path.as_deref(), &pin)?;
            Ok(())
        }
    }
}

fn run_fido_fingerprints(cmd: &FidoFingerprintCmd) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        FidoFingerprintCmd::List { pin, path } => {
            let pin = fido_pin(path.as_deref(), pin.as_ref())?;
            run_fido_fingerprint_list(path.as_deref(), &pin)?;
            Ok(())
        }
        FidoFingerprintCmd::Add { name, pin, path } => {
            let pin = fido_pin(path.as_deref(), pin.as_ref())?;
            run_fido_fingerprint_enroll(path.as_deref(), &pin, name.as_deref())?;
            Ok(())
        }
        FidoFingerprintCmd::Rename {
            id,
            name,
            pin,
            path,
        } => {
            let id = hex_decode(id).map_err(|e| format!("--id is not valid hex: {}", e))?;
            let pin = fido_pin(path.as_deref(), pin.as_ref())?;
            run_fido_fingerprint_rename(path.as_deref(), &pin, &id, name)?;
            Ok(())
        }
        FidoFingerprintCmd::Delete { id, pin, path, yes } => {
            let id = hex_decode(id).map_err(|e| format!("--id is not valid hex: {}", e))?;
            let mut sec = Secrets::real();
            let src = Source::from_flag(pin.as_ref());
            sec.check(&FIDO_PIN, src)?;
            let dev = crate::target::select_fido(path.as_deref())?;
            let asked = crate::prompt::confirm_then_read(
                &dev,
                *yes,
                &format!("delete fingerprint template {}", hex_short(&id)),
            )?;
            let pin = sec.read(&FIDO_PIN, src)?;
            crate::prompt::reverify_if_asked(&dev, asked || sec.prompted())?;
            run_fido_fingerprint_delete(path.as_deref(), &pin, &id)?;
            Ok(())
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum AlwaysUvStep {
    AlreadySet,
    Change,
}

/// What `fido config always-uv enable|disable` must do, from the `alwaysUv` option the
/// key reports. A key that doesn't report it can't be brought to a known
/// state, so nothing is sent.
fn always_uv_step(current: Option<bool>, want_on: bool) -> Result<AlwaysUvStep, String> {
    match current {
        None => Err(
            "this key doesn't report its \"always require user verification\" \
                     setting (alwaysUv), so keyroost can't set it to a known state; \
                     nothing was changed"
                .into(),
        ),
        Some(on) if on == want_on => Ok(AlwaysUvStep::AlreadySet),
        Some(_) => Ok(AlwaysUvStep::Change),
    }
}

/// [`always_uv_step`] from the info read before the PIN. A change also
/// needs authenticatorConfig, so a key without it is refused before the
/// PIN is asked for; an already-set key is a no-op either way.
fn always_uv_pre_pin_step(
    info: &keyroost_ctap::AuthenticatorInfo,
    want_on: bool,
) -> Result<AlwaysUvStep, Box<dyn std::error::Error>> {
    let step = always_uv_step(info.option("alwaysUv"), want_on)?;
    if step == AlwaysUvStep::Change && info.option("authnrCfg") != Some(true) {
        return Err("this authenticator does not advertise authenticatorConfig support".into());
    }
    Ok(step)
}

fn run_fido_always_uv(
    want_on: bool,
    path: Option<&std::path::Path>,
    pin: Option<&SecretSource>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut sec = Secrets::real();
    let src = Source::from_flag(pin);
    sec.check(&FIDO_PIN, src)?;
    let dev = crate::target::select_fido(path)?;
    let word = if want_on { "on" } else { "off" };
    // Read the state first (no PIN needed), so a key already in the
    // wanted state is never asked for its PIN.
    let current = {
        let (mut hid, init) =
            keyroost_ctap::CtapHidDevice::open(&crate::target::hid_path_of(&dev)?)?;
        if !init.supports_cbor() {
            return Err("device is U2F-only; CTAP2 authenticatorConfig not supported".into());
        }
        keyroost_ctap::get_info(&mut hid)?
    };
    let already = || {
        println!("\"Always require user verification\" is already {word}; nothing was changed.");
    };
    if always_uv_pre_pin_step(&current, want_on)? == AlwaysUvStep::AlreadySet {
        already();
        return Ok(());
    }
    let pin = sec.read(&FIDO_PIN, src)?;
    fido_reverify_if_prompted(&sec, &dev)?;
    with_configurator(path, &pin, |cfg, info| {
        // Checked again on this handle: the key may have changed since the first read.
        match always_uv_step(info.option("alwaysUv"), want_on)? {
            AlwaysUvStep::AlreadySet => already(),
            AlwaysUvStep::Change => {
                cfg.toggle_always_uv()?;
                println!("\"Always require user verification\" is now {word}.");
            }
        }
        Ok(())
    })
}

fn run_fido_config(cmd: &FidoConfigCmd) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        FidoConfigCmd::AlwaysUv {
            cmd: FidoToggleCmd::Enable { pin, path },
        } => run_fido_always_uv(true, path.as_deref(), pin.as_ref()),
        FidoConfigCmd::AlwaysUv {
            cmd: FidoToggleCmd::Disable { pin, path },
        } => run_fido_always_uv(false, path.as_deref(), pin.as_ref()),
        FidoConfigCmd::Attestation {
            cmd: FidoAttestationCmd::Enable { yes, pin, path },
        } => {
            let mut sec = Secrets::real();
            let src = Source::from_flag(pin.as_ref());
            sec.check(&FIDO_PIN, src)?;
            let dev = crate::target::select_fido(path.as_deref())?;
            let pin = confirm_then_read_pin(
                &mut crate::prompt::RealTerm,
                &mut sec,
                *yes,
                "enable enterprise attestation (only a reset turns it off)",
                &crate::prompt::key_label(&dev),
                Some(&dev),
                src,
            )?;
            with_configurator(path.as_deref(), &pin, |cfg, _info| {
                cfg.enable_enterprise_attestation()?;
                println!("Enterprise attestation enabled. Disabling it again requires a reset.");
                Ok(())
            })?;
            Ok(())
        }
    }
}

fn run_fido_large_blob(cmd: &LargeBlobCmd) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        LargeBlobCmd::List { path } => run_fido_large_blob_list(path.as_deref()),
        LargeBlobCmd::Get { index, path } => run_fido_large_blob_get(path.as_deref(), *index),
        LargeBlobCmd::Add { text, pin, path } => {
            let pin = fido_pin(path.as_deref(), pin.as_ref())?;
            run_fido_large_blob_add(path.as_deref(), &pin, text)
        }
        LargeBlobCmd::Edit {
            index,
            text,
            pin,
            path,
        } => {
            let pin = fido_pin(path.as_deref(), pin.as_ref())?;
            run_fido_large_blob_edit(path.as_deref(), &pin, *index, text)
        }
        LargeBlobCmd::Delete {
            index,
            yes,
            pin,
            path,
        } => run_fido_large_blob_delete(
            path.as_deref(),
            Source::from_flag(pin.as_ref()),
            *index,
            *yes,
        ),
        LargeBlobCmd::Export {
            index,
            out,
            overwrite,
            as_cert,
            path,
        } => {
            let [out_mode] = crate::prompt::check_overwrites([Some(out.as_path())], *overwrite)?;
            run_fido_large_blob_export(path.as_deref(), *index, out, out_mode, *as_cert)
        }
        LargeBlobCmd::Clear { yes, pin, path } => {
            run_fido_large_blob_clear(path.as_deref(), Source::from_flag(pin.as_ref()), *yes)
        }
    }
}

/// Dispatch for `fido ssh` — list SSH credentials or extract a cert.
fn run_fido_ssh_cert(cmd: &SshCertCmd) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        SshCertCmd::List { pin, path } => {
            let pin = fido_pin(path.as_deref(), pin.as_ref())?;
            run_fido_ssh_cert_list(path.as_deref(), &pin)
        }
        SshCertCmd::Extract {
            id,
            out,
            overwrite,
            pin,
            path,
        } => {
            let [out_mode] = crate::prompt::check_overwrites([out.as_deref()], *overwrite)?;
            let pin = fido_pin(path.as_deref(), pin.as_ref())?;
            run_fido_ssh_cert_extract(
                path.as_deref(),
                &pin,
                id.as_deref(),
                out.as_deref(),
                out_mode,
                *overwrite,
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
    let path = crate::target::fido_path(path)?;
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
            .and_then(|k| keyroost_ctap::large_blobs::extract_cert_from_entries(k, &array))
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
    out_mode: crate::prompt::OutMode,
    overwrite: bool,
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
                    "several SSH credentials present; pass --id <rp-id> (one of: {})",
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
    let wire = keyroost_ctap::large_blobs::extract_cert_from_entries(key, &array)
        .ok_or_else(|| {
            format!(
                "no SSH certificate found in credential '{}'s largeBlob (no matching entry, or the stored blob is not a certificate)",
                sanitize_terminal(rp_id)
            )
        })?;
    let cert_pub = keyroost_ctap::ssh_cert::to_cert_pub(&wire)
        .ok_or("stored blob is not a valid OpenSSH certificate")?;

    // Resolve the output path (default: <sanitized rp-id>-cert.pub). The RP id
    // is device-derived and must be treated as hostile: use the path-safe
    // filename sanitizer here, not sanitize_terminal (which only neutralizes
    // control/bidi/zero-width chars for display, not `/`, `\`, or `..`).
    let out_path = match out {
        Some(p) => p.to_path_buf(),
        None => std::path::PathBuf::from(keyroost_ctap::ssh_cert::default_cert_filename(rp_id)),
    };
    // A given --out was checked before the key was touched; the default name
    // is only known now.
    let out_mode = match out {
        Some(_) => out_mode,
        None => crate::prompt::check_overwrite(&mut crate::prompt::RealTerm, &out_path, overwrite)?,
    };
    out_mode
        .write(&out_path, cert_pub.as_bytes())
        .map_err(|e| format!("write {}: {}", out_path.display(), e))?;
    output::status(&format!("Wrote SSH certificate to {}.", out_path.display()));
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
    let path = crate::target::fido_path(path)?;
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
        EntryKind::KeyName(_) => ("key-name", None, kind),
        EntryKind::Opaque => ("opaque", None, kind),
        EntryKind::SshCert { info, .. } => {
            let cert = json_out::FidoLargeBlobSshCertJson {
                key_type: info.key_type.clone(),
                serial: info.serial.to_string(),
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
        .entries()
        .into_iter()
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
        skipped: array.skipped_count(),
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
    let skipped = array.skipped_count();
    if array.is_empty() && skipped == 0 {
        println!("(large-blob array is empty)");
    }
    for (i, e) in array.entries().into_iter().enumerate() {
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
            EntryKind::KeyName(l) => println!(
                "[{}] {} bytes  key name  \"{}\"",
                i,
                e.orig_size,
                sanitize_terminal(&l.label)
            ),
            EntryKind::Opaque => println!(
                "[{}] {} bytes  opaque    {}",
                i,
                e.orig_size,
                preview_opaque(&e.ciphertext)
            ),
        }
    }
    if skipped > 0 {
        println!("{skipped} element(s) not in the standard format were skipped (kept unchanged)");
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
        .entry(index)
        .ok_or_else(|| large_blob_bad_index(index, array.len()))?;
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
        EntryKind::KeyName(l) => {
            println!("Entry {}: key name, {} bytes", index, entry.orig_size);
            println!("{}", sanitize_terminal(&l.label));
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
            output::note(&format!(
                "export with: keyroostctl fido blob export {index} --out FILE --as-cert"
            ));
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
    out_mode: crate::prompt::OutMode,
    as_cert: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use keyroost_ctap::large_blobs::EntryKind;
    let (_dev, _info, array) = open_and_read_large_blobs(path)?;
    let entry = array
        .entry(index)
        .ok_or_else(|| large_blob_bad_index(index, array.len()))?;
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
    out_mode
        .write(output, &bytes)
        .map_err(|e| format!("write {}: {}", output.display(), e))?;
    output::status(&format!(
        "Wrote {} bytes to {}.",
        bytes.len(),
        output.display()
    ));
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
    let updated = current.with_text_note(text);
    let serialized = updated.serialize_with_checksum()?;
    let token = keyroost_ctap::client_pin::get_pin_uv_auth_token(
        &mut dev,
        pin,
        &info,
        keyroost_ctap::client_pin::permissions::LARGE_BLOB_WRITE,
    )?;
    keyroost_ctap::large_blobs::write(&mut dev, &info, &token, &serialized)?;
    println!("Note added; {} entries now.", updated.len());
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
    let serialized = updated.serialize_with_checksum()?;
    let token = keyroost_ctap::client_pin::get_pin_uv_auth_token(
        &mut dev,
        pin,
        &info,
        keyroost_ctap::client_pin::permissions::LARGE_BLOB_WRITE,
    )?;
    keyroost_ctap::large_blobs::write(&mut dev, &info, &token, &serialized)?;
    println!("Note {} updated.", index);
    Ok(())
}

fn run_fido_large_blob_delete(
    path: Option<&std::path::Path>,
    src: Source<'_>,
    index: usize,
    yes: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut sec = Secrets::real();
    sec.check(&FIDO_PIN, src)?;
    let (dev, _info, current) = open_and_read_large_blobs(path)?;
    let entry = current
        .entry(index)
        .ok_or_else(|| large_blob_bad_index(index, current.len()))?;
    if !entry.is_kr_note() {
        // Opaque RP-owned entry: deleting it can break the owning service.
        output::warn(&format!(
            "entry {} was not created by keyroost (it is an opaque, \
             RP-encrypted record); deleting it may break a service that stored it.",
            index
        ));
    }
    drop(dev); // not held across the question or while the PIN is typed
    let key = crate::target::select_fido(path)?;
    let pin = confirm_then_read_pin(
        &mut crate::prompt::RealTerm,
        &mut sec,
        yes,
        &format!("delete large-blob entry {index}"),
        &crate::prompt::key_label(&key),
        Some(&key),
        src,
    )?;
    let (mut dev, info, again) = open_and_read_large_blobs(path)?;
    if !large_blob_unchanged(&current, &again) {
        return Err(LARGE_BLOB_CHANGED.into());
    }

    let updated = again
        .without_entry(index)
        .ok_or_else(|| large_blob_bad_index(index, again.len()))?;
    let serialized = updated.serialize_with_checksum()?;
    let token = keyroost_ctap::client_pin::get_pin_uv_auth_token(
        &mut dev,
        &pin,
        &info,
        keyroost_ctap::client_pin::permissions::LARGE_BLOB_WRITE,
    )?;
    keyroost_ctap::large_blobs::write(&mut dev, &info, &token, &serialized)?;
    println!("Entry deleted; {} entries now.", updated.len());
    Ok(())
}

fn run_fido_large_blob_clear(
    path: Option<&std::path::Path>,
    src: Source<'_>,
    yes: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut sec = Secrets::real();
    sec.check(&FIDO_PIN, src)?;
    // Read first so we can report exactly what will be wiped.
    let (dev, _info, current) = open_and_read_large_blobs(path)?;
    // Skipped (non-standard) elements are wiped too, so they count as opaque.
    let skipped = current.skipped_count();
    let total = current.len() + skipped;
    let opaque = current
        .entries()
        .into_iter()
        .filter(|e| !e.is_kr_note())
        .count()
        + skipped;
    if !yes {
        output::warn(&format!(
            "`clear` erases the ENTIRE large-blob array — ALL {total} \
             entr{plural} ({opaque} opaque/RP-owned, e.g. stored SSH certs). This \
             can break any service that stored data here.",
            total = total,
            plural = if total == 1 { "y" } else { "ies" },
            opaque = opaque,
        ));
    } else if opaque > 0 {
        output::warn(&format!(
            "wiping {} opaque/RP-owned entr{} along with everything else.",
            opaque,
            if opaque == 1 { "y" } else { "ies" }
        ));
    }
    drop(dev); // not held across the question or while the PIN is typed
    let key = crate::target::select_fido(path)?;
    let pin = confirm_then_read_pin(
        &mut crate::prompt::RealTerm,
        &mut sec,
        yes,
        "clear the whole large-blob array",
        &crate::prompt::key_label(&key),
        Some(&key),
        src,
    )?;
    let (mut dev, info, again) = open_and_read_large_blobs(path)?;
    if !large_blob_unchanged(&current, &again) {
        return Err(LARGE_BLOB_CHANGED.into());
    }
    let token = keyroost_ctap::client_pin::get_pin_uv_auth_token(
        &mut dev,
        &pin,
        &info,
        keyroost_ctap::client_pin::permissions::LARGE_BLOB_WRITE,
    )?;
    let serialized = keyroost_ctap::large_blobs::empty_array_serialized();
    keyroost_ctap::large_blobs::write(&mut dev, &info, &token, &serialized)?;
    println!("Large-blob array cleared ({} entries wiped).", total);
    Ok(())
}

/// The large-blob array is re-read after the question and the PIN; a
/// delete or clear refuses when it no longer matches what was shown.
const LARGE_BLOB_CHANGED: &str =
    "the large-blob array changed while waiting for a confirmation or a typed secret; nothing was changed";

/// Whether the array read after the question and the PIN is the one the
/// person was shown. An extra guard on top of re-finding the key: two keys
/// with identical arrays (e.g. both empty) pass it.
fn large_blob_unchanged(
    before: &keyroost_ctap::large_blobs::LargeBlobArray,
    after: &keyroost_ctap::large_blobs::LargeBlobArray,
) -> bool {
    before.raw_array() == after.raw_array()
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
    let path = crate::target::fido_path(path)?;
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
        println!(
            "{}",
            output::kv_block(&[
                ("Device", path.display().to_string()),
                (
                    "Channel",
                    format!(
                        "{:#010x} (CTAPHID protocol v{})",
                        init.channel_id, init.protocol_version
                    ),
                ),
                (
                    "Firmware",
                    format!(
                        "{}.{}.{}",
                        init.device_major, init.device_minor, init.device_build
                    ),
                ),
                (
                    "Caps",
                    format!("{} (raw 0x{:02X})", caps.join("+"), init.capabilities),
                ),
            ])
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
    println!("{}", output::kv_block(&fido_info_rows(&info)));
    Ok(())
}

/// `fido info`'s CTAP2 block, one `(label, value)` row per field the
/// authenticator reported; a field it left out has no row.
fn fido_info_rows(info: &keyroost_ctap::AuthenticatorInfo) -> Vec<(&'static str, String)> {
    // versions/extensions/option-keys come from the device's getInfo CBOR;
    // flatten any control bytes before they reach the terminal.
    let mut rows = vec![("Versions", sanitize_terminal(&info.versions.join(", ")))];
    if !info.extensions.is_empty() {
        rows.push(("Extensions", sanitize_terminal(&info.extensions.join(", "))));
    }
    rows.push(("AAGUID", format_aaguid(&info.aaguid)));
    if !info.options.is_empty() {
        let opts: Vec<String> = info
            .options
            .iter()
            .map(|(k, v)| format!("{}={}", sanitize_terminal(k), v))
            .collect();
        rows.push(("Options", opts.join(", ")));
    }
    if let Some(n) = info.max_msg_size {
        rows.push(("Max message size", n.to_string()));
    }
    if !info.pin_uv_auth_protocols.is_empty() {
        let v: Vec<String> = info
            .pin_uv_auth_protocols
            .iter()
            .map(|n| n.to_string())
            .collect();
        rows.push(("PIN/UV protocols", v.join(", ")));
    }
    if !info.transports.is_empty() {
        rows.push(("Transports", sanitize_terminal(&info.transports.join(", "))));
    }
    if let Some(n) = info.min_pin_length {
        rows.push(("Min PIN length", n.to_string()));
    }
    if info.force_pin_change == Some(true) {
        rows.push(("Force PIN change", "yes".to_owned()));
    }
    if let Some(v) = info.firmware_version {
        rows.push(("CTAP firmware version", v.to_string()));
    }
    rows
}

/// How `fido reset` reaches the selected key's FIDO2 applet.
#[derive(Debug, PartialEq, Eq)]
enum FidoResetRoute {
    /// Over USB HID: the key is replugged to open the reset window.
    Replug { path: std::path::PathBuf },
    /// A card in a PC/SC reader: power-cycled in place instead.
    Card { reader: String },
}

/// Pick the route for a FIDO2 reset of `dev`: HID with a replug when the key
/// has a FIDO HID node, unless `--reader` asked for the card interface (or
/// there is no HID node, as for a card in a reader).
fn fido_reset_route(
    dev: &keyroost_resolve::Device,
    reader_given: bool,
) -> Result<FidoResetRoute, String> {
    match (&dev.hid_path, &dev.reader) {
        (Some(path), _) if !reader_given => Ok(FidoResetRoute::Replug { path: path.clone() }),
        (_, Some(reader)) => Ok(FidoResetRoute::Card {
            reader: reader.clone(),
        }),
        (Some(path), None) => Ok(FidoResetRoute::Replug { path: path.clone() }),
        (None, None) => Err(format!(
            "'{}' has neither a FIDO HID interface nor a smart-card reader to reset it over",
            sanitize_terminal(dev.name.as_deref().unwrap_or(&dev.model))
        )),
    }
}

/// Whether the PIV card a transaction reads now is the one the user
/// confirmed against: the serials must agree, and a serial known on one side
/// only is a different card (two unknowns can't be told apart, so they pass).
fn same_piv_card(confirmed: Option<u128>, now: Option<u128>) -> bool {
    confirmed == now
}

/// Reset the FIDO2 applet of an already-resolved device. Split out so callers
/// that have *proved* which physical key they hold (the factory reset, after
/// its replug prompt) reset exactly that one, instead of re-resolving and
/// possibly landing on a different key.
///
/// `announce_touch` prints this function's own generic touch prompt; the
/// caller sets it `false` when it already printed its own (naming its step)
/// right before calling in, so the two never stack into two prompts for one
/// reset ([`fido_reset_after_replug`]).
fn fido_reset_at(
    path: &std::path::Path,
    announce_touch: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut dev, _init) = keyroost_ctap::CtapHidDevice::open(path)?;
    if announce_touch {
        eprintln!("Resetting {} — touch the key now…", path.display());
    }
    keyroost_ctap::reset(&mut dev)?;
    println!("Reset complete. All credentials wiped, PIN cleared.");
    Ok(())
}

/// Reset the FIDO2 applet of a card in the exact PC/SC reader `exact_reader`.
///
/// A card has no replug and no touch surface, so the "reset within ~10 s of
/// power-up" window is opened another way: PC/SC power-cycles the card in the
/// reader and the reset is sent the moment the applet answers (issue #84 —
/// the replug ceremony can never complete for a card).
fn run_fido_reset_reader(exact_reader: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !keyroost_transport::CtapPcscDevice::list_fido_readers()?
        .iter()
        .any(|r| r == exact_reader)
    {
        return Err(format!(
            "'{}' has no FIDO applet answering over this reader",
            sanitize_terminal(exact_reader)
        )
        .into());
    }
    output::status("Power-cycling the card and sending the reset\u{2026}");
    let mut dev = keyroost_transport::CtapPcscDevice::open_after_power_cycle(exact_reader)?;
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
    let path = crate::target::fido_path(path)?;
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
    let path = crate::target::fido_path(path)?;
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
    let path = crate::target::fido_path(path)?;
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
                // `fido credential delete --id` expects (the `cred …` summary
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
            // The hex template ID is what --id takes for rename/delete.
            println!("  id {}   {}", hex_encode(&e.template_id), name);
        }
        output::note("use the ID with --id to rename or delete");
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
                output::status(&format!(
                    "Enrolling a fingerprint ({} good samples needed).",
                    info.max_capture_samples
                ));
            }
        }
        output::status("Touch the sensor now\u{2026}");
        let (template_id, mut status) = bio.enroll_begin(None)?;
        output::status(&format!(
            "  {}",
            sample_status_message(status.last_sample_status)
        ));
        // Capture until the device says no samples remain.
        while status.remaining_samples > 0 {
            output::status(&format!(
                "  {} more sample(s) needed \u{2014} touch the sensor again\u{2026}",
                status.remaining_samples
            ));
            status = bio.enroll_capture_next(&template_id, None)?;
            output::status(&format!(
                "  {}",
                sample_status_message(status.last_sample_status)
            ));
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
    let path = crate::target::fido_path(path)?;
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
    let path = crate::target::fido_path(path)?;
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
/// permission, and run `f` with a [`Configurator`](keyroost_ctap::config::Configurator). Mirrors
/// [`with_bio_enrollment`] for the `authenticatorConfig` (0x0D) command family.
fn with_configurator<F>(
    path: Option<&std::path::Path>,
    pin: &str,
    f: F,
) -> Result<(), Box<dyn std::error::Error>>
where
    F: for<'a> FnOnce(
        &mut keyroost_ctap::config::Configurator<'a, keyroost_ctap::CtapHidDevice>,
        &keyroost_ctap::AuthenticatorInfo,
    ) -> Result<(), Box<dyn std::error::Error>>,
{
    let path = crate::target::fido_path(path)?;
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
    f(&mut cfg, &info)
}

/// Ask first, then read the PIN: a refusal or a "no" never consumes a PIN
/// source (the FIDO one-way settings and the large-blob wipes). `reopened`
/// is the key a command reopens after this returns; when the question was
/// shown or the PIN was typed at the hidden prompt, it is re-found
/// ([`crate::target::reverify`]) only after the PIN has been read —
/// immediately before the reopen, not while the person is still typing the
/// PIN. Nothing may hold the key's handle open across the
/// question or the PIN entry.
fn confirm_then_read_pin<I: crate::secrets::SecretIo>(
    term: &mut dyn crate::prompt::Term,
    sec: &mut Secrets<I>,
    yes: bool,
    action: &str,
    key: &str,
    reopened: Option<&keyroost_resolve::Device>,
    src: Source<'_>,
) -> Result<zeroize::Zeroizing<String>, Box<dyn std::error::Error>> {
    confirm_then_read_pin_ordered(term, sec, yes, action, key, src, |waited| {
        if waited {
            if let Some(dev) = reopened {
                crate::target::reverify(dev)?;
            }
        }
        Ok(())
    })
}

/// The pure ask → read → re-verify ordering behind [`confirm_then_read_pin`],
/// with the re-verify step injectable so the ordering can be asserted
/// without talking to hardware: `reverify` must run after the PIN is read,
/// never before.
fn confirm_then_read_pin_ordered<I: crate::secrets::SecretIo>(
    term: &mut dyn crate::prompt::Term,
    sec: &mut Secrets<I>,
    yes: bool,
    action: &str,
    key: &str,
    src: Source<'_>,
    reverify: impl FnOnce(bool) -> Result<(), Box<dyn std::error::Error>>,
) -> Result<zeroize::Zeroizing<String>, Box<dyn std::error::Error>> {
    let asked = crate::prompt::confirm(term, yes, action, key)?;
    let pin = sec.read(&FIDO_PIN, src)?;
    // A question shown or a PIN typed at the prompt both leave a gap in
    // which the key could have been swapped.
    reverify(asked || sec.prompted())?;
    Ok(pin)
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
    0xE6, // delete seed (keyless: P2=00 would wipe slot #0)
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

/// `molto import --file`'s result line: how many entries were written (entries
/// skipped for having no title are not counted) and the slot range covered.
fn import_file_ack(written: usize, first: u8, last: usize) -> String {
    format!(
        "Imported {written} entr{} into slots #{first}..#{last}.",
        if written == 1 { "y" } else { "ies" }
    )
}

/// Write the Molto2's serial and clock to `w`: stdout for `molto info` (the
/// result), stderr for every other command (context before the result).
fn write_info(
    w: &mut impl std::io::Write,
    info: &keyroost_transport::DeviceInfo,
) -> std::io::Result<()> {
    // The serial is `from_utf8_lossy` over device bytes; flatten any control
    // characters before they reach the terminal (a hostile token could embed
    // escape sequences). Shared by every command that prints device info.
    writeln!(
        w,
        "{}",
        output::kv_block(&[
            ("Serial", sanitize_terminal(&info.serial)),
            ("Device UTC", format!("{} (epoch)", info.utc_time)),
        ])
    )?;
    // TOTP tolerates small drift (one 30s step either way at most verifiers);
    // beyond that, codes get rejected in ways users misdiagnose as a bad
    // seed. Surface it here where it's cheap to see.
    let drift = i64::from(info.utc_time) - i64::from(unix_now());
    if drift.abs() > 30 {
        output::warn(&format!(
            "device clock is {} seconds {} the host clock — codes may be \
             rejected. Run `keyroostctl molto sync --all` to fix.",
            drift.abs(),
            if drift > 0 { "ahead of" } else { "behind" }
        ));
    }
    Ok(())
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
/// clap_complete's static generator formats it via `Debug`
/// (`"failed to write completion file: Os { code: 32, kind: BrokenPipe, … }"`).
///
/// So the match is deliberately **unanchored** — do NOT add a message-prefix
/// check, it silently misses the `Debug` shape (both shapes are pinned by the
/// `broken_pipe_panic_detection` unit test). The tokens are locale-independent where it counts:
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

/// Whether a completion-engine error is a closed stdout pipe.
///
/// clap flattens the engine's `io::Error` into an `Io`-kind error carrying
/// only its `Display` text, so the io error kind is gone by the time we see
/// it. EPIPE reads as `"Broken pipe (os error 32)"` on Unix, which
/// [`is_broken_pipe_panic`] already matches; Windows reports a closed pipe as
/// `ERROR_BROKEN_PIPE` (109) or `ERROR_NO_DATA` (232) with a localized
/// message, so match those codes.
fn is_closed_pipe_error(e: &clap::Error) -> bool {
    if e.kind() != clap::error::ErrorKind::Io {
        return false;
    }
    let msg = e.to_string();
    is_broken_pipe_panic(&msg)
        || (cfg!(windows) && (msg.contains("(os error 109)") || msg.contains("(os error 232)")))
}

/// The environment variable a shell sets to ask keyroostctl for completions.
/// Namespaced (rather than clap_complete's default `COMPLETE`) so a stray
/// `COMPLETE` in a user's environment can't hijack every run.
const COMPLETE_VAR: &str = "KEYROOSTCTL_COMPLETE";

/// Answer a shell's completion request (`KEYROOSTCTL_COMPLETE=<shell>
/// keyroostctl …`) if this run is one: `None` means a normal run, `Some` is
/// the status to exit with. Candidates come from keys.json only, never
/// hardware. Completion writes straight to stdout and reports a closed pipe
/// as an error rather than panicking, so the panic guard never sees it —
/// exit 141 quietly here instead, the same status the guard uses.
fn answer_completion_request() -> Option<ExitCode> {
    match clap_complete::CompleteEnv::with_factory(<Cli as clap::CommandFactory>::command)
        .var(COMPLETE_VAR)
        .try_complete(std::env::args_os(), std::env::current_dir().ok().as_deref())
    {
        Ok(true) => Some(ExitCode::SUCCESS),
        Ok(false) => None,
        Err(e) if is_closed_pipe_error(&e) => Some(ExitCode::from(141)),
        Err(e) => {
            let _ = e.print();
            Some(ExitCode::from(u8::try_from(e.exit_code()).unwrap_or(2)))
        }
    }
}

/// `--device` candidates for `keyring`: every saved friendly name, in file order.
fn device_candidates_from(keyring: &Keyring) -> Vec<clap_complete::CompletionCandidate> {
    keyring
        .keys
        .iter()
        .map(|e| clap_complete::CompletionCandidate::new(&e.name))
        .collect()
}

/// `--device` completion: saved names from keys.json only — never hardware.
/// An unreadable keys.json completes nothing rather than failing the shell.
fn device_candidates() -> Vec<clap_complete::CompletionCandidate> {
    device_candidates_from(&Keyring::load_default().unwrap_or_default())
}

/// Write the shell snippet that registers keyroostctl's completions. The
/// snippet calls back into `COMPLETE=<shell> keyroostctl …`, which [`main`]
/// answers, so completions always match the installed binary.
fn write_completion_registration(
    shell: clap_complete::Shell,
    out: &mut dyn std::io::Write,
) -> Result<(), Box<dyn std::error::Error>> {
    use clap_complete::env::{Bash, Elvish, EnvCompleter, Fish, Powershell, Zsh};
    let completer: &dyn EnvCompleter = match shell {
        clap_complete::Shell::Bash => &Bash,
        clap_complete::Shell::Zsh => &Zsh,
        clap_complete::Shell::Fish => &Fish,
        clap_complete::Shell::Elvish => &Elvish,
        clap_complete::Shell::PowerShell => &Powershell,
        other => return Err(format!("no completion support for {other}").into()),
    };
    completer.write_registration(
        COMPLETE_VAR,
        "keyroostctl",
        "keyroostctl",
        "keyroostctl",
        out,
    )?;
    Ok(())
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
    //
    // A shell's completion request is answered first, on the worker too:
    // building the full command tree also needs more than a small main-thread
    // stack in debug builds.
    let worker = std::thread::Builder::new()
        .name("keyroostctl-main".into())
        .stack_size(16 * 1024 * 1024)
        .spawn(|| match answer_completion_request() {
            Some(code) => Ok(Some(code)),
            None => run().map(|()| None).map_err(|e| e.to_string()),
        })
        .expect("spawn worker thread");

    match worker.join() {
        Ok(Ok(Some(code))) => code,
        Ok(Ok(None)) => ExitCode::SUCCESS,
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
mod human_style_tests {
    use super::*;

    /// The column each `Key: value` line's value starts at.
    fn value_columns(block: &str) -> Vec<usize> {
        block
            .lines()
            .map(|l| {
                let colon = l.find(':').expect("every row has a label") + 1;
                colon + l[colon..].len() - l[colon..].trim_start().len()
            })
            .collect()
    }

    #[test]
    fn fido_info_block_is_one_column() {
        let info = keyroost_ctap::AuthenticatorInfo {
            versions: vec!["FIDO_2_0".into(), "FIDO_2_1".into()],
            extensions: vec!["credProtect".into()],
            options: vec![("rk".into(), true), ("clientPin".into(), false)],
            max_msg_size: Some(1200),
            pin_uv_auth_protocols: vec![2, 1],
            transports: vec!["usb".into()],
            min_pin_length: Some(4),
            force_pin_change: Some(true),
            firmware_version: Some(7),
            ..Default::default()
        };
        let rows = fido_info_rows(&info);
        let labels: Vec<&str> = rows.iter().map(|(k, _)| *k).collect();
        assert_eq!(
            labels,
            [
                "Versions",
                "Extensions",
                "AAGUID",
                "Options",
                "Max message size",
                "PIN/UV protocols",
                "Transports",
                "Min PIN length",
                "Force PIN change",
                "CTAP firmware version",
            ]
        );
        let block = output::kv_block(&rows);
        let cols = value_columns(&block);
        assert!(cols.iter().all(|c| *c == cols[0]), "{block}");
        // An absent field has no row, as before.
        let bare = fido_info_rows(&keyroost_ctap::AuthenticatorInfo::default());
        let labels: Vec<&str> = bare.iter().map(|(k, _)| *k).collect();
        assert_eq!(labels, ["Versions", "AAGUID"]);
    }

    #[test]
    fn molto_info_is_an_aligned_block() {
        let info = keyroost_transport::DeviceInfo {
            serial: "T2M-0001".into(),
            utc_time: unix_now(),
        };
        let mut out = Vec::new();
        write_info(&mut out, &info).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(
            text,
            format!(
                "Serial:     T2M-0001\nDevice UTC: {} (epoch)\n",
                info.utc_time
            )
        );
    }

    #[test]
    fn import_file_ack_counts_written_entries() {
        assert_eq!(
            import_file_ack(3, 95, 97),
            "Imported 3 entries into slots #95..#97."
        );
        assert_eq!(
            import_file_ack(1, 99, 99),
            "Imported 1 entry into slots #99..#99."
        );
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

    const IRREVERSIBLE: &str = "Irreversible: asks first (`--yes` to skip)";
    const IRREVERSIBLE_TYPED: &str =
        "Irreversible: asks for a typed confirmation (`--yes` to skip)";
    const ONE_WAY: &str = "One-way: asks first (`--yes` to skip)";

    #[test]
    fn literal_refusal_names_the_flag_never_the_value() {
        use clap::{Arg, Command};
        let cmd = || {
            Command::new("t")
                .arg(
                    Arg::new("pin")
                        .long("pin")
                        .value_name("SOURCE")
                        .allow_hyphen_values(true)
                        .value_parser(crate::secrets::parse_source),
                )
                .arg(
                    Arg::new("mgmt_key")
                        .long("mgmt-key")
                        .value_name("SOURCE")
                        .allow_hyphen_values(true)
                        .value_parser(crate::secrets::parse_source_or_default),
                )
        };
        for (args, want) in [
            (
                &["t", "--pin", "S3CRETVALUE"][..],
                "--pin takes env:NAME or stdin",
            ),
            (&["t", "--pin=S3CRETVALUE"], "--pin takes env:NAME or stdin"),
            (
                &["t", "--pin", "-S3CRETVALUE"],
                "--pin takes env:NAME or stdin",
            ),
            (&["t", "--pin", "env:"], "--pin takes env:NAME or stdin"),
            (&["t", "--pin", "default"], "--pin takes env:NAME or stdin"),
            (
                &["t", "--mgmt-key", "S3CRETVALUE"],
                "--mgmt-key takes env:NAME, stdin or default",
            ),
        ] {
            let e = cmd().try_get_matches_from(args).unwrap_err();
            let argv: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            let msg = redacted_parse_error(&e, &argv).expect("redacted");
            assert!(msg.starts_with(want), "{args:?}: {msg}");
            assert!(!msg.contains("S3CRET"), "{args:?}: {msg}");
        }
        assert!(cmd()
            .try_get_matches_from(["t", "--mgmt-key", "default"])
            .is_ok());
    }

    /// A `<SOURCE>` flag the refusal table doesn't know is still refused
    /// without the value; a value error on any other flag keeps clap's text.
    #[test]
    fn a_source_flag_missing_from_the_table_is_still_refused() {
        use clap::{Arg, Command};
        let cmd = || {
            Command::new("t")
                .arg(
                    Arg::new("other")
                        .long("other-secret")
                        .value_name("SOURCE")
                        .allow_hyphen_values(true)
                        .value_parser(crate::secrets::parse_source),
                )
                .arg(
                    Arg::new("count")
                        .long("count")
                        .value_parser(clap::value_parser!(u8)),
                )
        };
        for args in [
            &["t", "--other-secret", "S3CRETVALUE"][..],
            &["t", "--other-secret=S3CRETVALUE"],
            &["t", "--other-secret", "-S3CRETVALUE"],
        ] {
            let e = cmd().try_get_matches_from(args).unwrap_err();
            let argv: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            assert_eq!(
                redacted_parse_error(&e, &argv).as_deref(),
                Some("--other-secret takes env:NAME or stdin — never the secret itself"),
                "{args:?}"
            );
        }
        let e = cmd()
            .try_get_matches_from(["t", "--count", "x"])
            .unwrap_err();
        assert_eq!(redacted_parse_error(&e, &["t".into()]), None);
    }

    /// Problems with the `<SOURCE>` flags in `root`'s tree: a flag missing
    /// from `SECRET_FLAGS`, a parser that isn't a source parser, a `default`
    /// that the parser and the table disagree on, a flag that doesn't take
    /// a dash-led value (clap would then report it as an unknown flag, not
    /// a value error), or a table entry no command uses.
    fn secret_flag_problems(root: &clap::Command) -> Vec<String> {
        use crate::secrets::SECRET_FLAGS;
        fn walk(c: &clap::Command, path: String, out: &mut Vec<(String, clap::Command)>) {
            out.push((path.clone(), c.clone()));
            for s in c.get_subcommands().filter(|s| s.get_name() != "help") {
                walk(s, format!("{path} {}", s.get_name()), out);
            }
        }
        let mut root = root.clone();
        root.build();
        let mut cmds = Vec::new();
        walk(&root, root.get_name().to_string(), &mut cmds);
        // Whether `c` accepts `value` for `--long` (anything but a value
        // error on that flag counts as accepted).
        let accepts = |c: &clap::Command, long: &str, value: &str| {
            use clap::error::{ContextKind, ContextValue, ErrorKind};
            match c
                .clone()
                .try_get_matches_from([c.get_name(), &format!("--{long}"), value])
            {
                Ok(_) => true,
                Err(e) => {
                    !(matches!(
                        e.kind(),
                        ErrorKind::ValueValidation | ErrorKind::InvalidValue
                    ) && matches!(
                        e.get(ContextKind::InvalidArg),
                        Some(ContextValue::String(a)) if a.starts_with(&format!("--{long} "))
                    ))
                }
            }
        };
        let mut problems = Vec::new();
        let mut used = std::collections::HashSet::new();
        for (path, c) in &cmds {
            for a in c.get_arguments() {
                if !is_secret_arg(a) {
                    continue;
                }
                let Some(long) = a.get_long() else {
                    problems.push(format!(
                        "{path}: <SOURCE> argument {} has no long name",
                        a.get_id()
                    ));
                    continue;
                };
                let Some(f) = SECRET_FLAGS.iter().find(|f| f.long == long) else {
                    problems.push(format!("{path} --{long}: not in SECRET_FLAGS"));
                    continue;
                };
                used.insert(long.to_string());
                if !a.is_allow_hyphen_values_set() {
                    problems.push(format!("{path} --{long}: does not allow a dash-led value"));
                }
                if !accepts(c, long, "stdin")
                    || !accepts(c, long, "env:KR_X")
                    || accepts(c, long, "S3CRET")
                {
                    problems.push(format!("{path} --{long}: not a secret-source parser"));
                }
                if accepts(c, long, "default") != f.default_ok {
                    problems.push(format!(
                        "{path} --{long}: the parser and SECRET_FLAGS disagree on `default`"
                    ));
                }
            }
        }
        for f in SECRET_FLAGS {
            if !used.contains(f.long) {
                problems.push(format!("SECRET_FLAGS --{}: no command uses it", f.long));
            }
        }
        problems
    }

    #[test]
    fn every_source_flag_agrees_with_the_refusal_table() {
        use clap::CommandFactory;
        assert_eq!(secret_flag_problems(&Cli::command()), Vec::<String>::new());
    }

    #[test]
    fn secret_flag_problems_catches_each_mismatch() {
        use clap::{Arg, Command};
        let src = |id: &'static str, long: &'static str| {
            Arg::new(id)
                .long(long)
                .value_name("SOURCE")
                .allow_hyphen_values(true)
                .value_parser(crate::secrets::parse_source)
        };
        let bad = Command::new("t").subcommand(
            Command::new("s")
                .arg(src("unknown", "not-in-table"))
                .arg(src("mgmt", "mgmt-key"))
                .arg(
                    Arg::new("pin")
                        .long("pin")
                        .value_name("SOURCE")
                        .value_parser(crate::secrets::parse_source_or_default),
                )
                .arg(
                    Arg::new("puk")
                        .long("puk")
                        .value_name("SOURCE")
                        .allow_hyphen_values(true),
                ),
        );
        let mut want: Vec<String> = [
            "t s --not-in-table: not in SECRET_FLAGS",
            "t s --mgmt-key: the parser and SECRET_FLAGS disagree on `default`",
            "t s --pin: does not allow a dash-led value",
            "t s --pin: the parser and SECRET_FLAGS disagree on `default`",
            "t s --puk: not a secret-source parser",
            "t s --puk: the parser and SECRET_FLAGS disagree on `default`",
        ]
        .map(String::from)
        .to_vec();
        want.extend(
            crate::secrets::SECRET_FLAGS
                .iter()
                .filter(|f| !["mgmt-key", "pin", "puk"].contains(&f.long))
                .map(|f| format!("SECRET_FLAGS --{}: no command uses it", f.long)),
        );
        assert_eq!(secret_flag_problems(&bad), want);
    }

    /// A dash-led secret right after a source can start like a short flag
    /// with its value attached (`-s3cret` is `-s 3cret`); clap would then
    /// take it as a slot, device or file and could repeat it. Refused
    /// before parsing; a short flag on its own is fine.
    #[test]
    fn an_attached_short_after_a_source_is_refused() {
        let argv = |s: &str| s.split(' ').map(String::from).collect::<Vec<_>>();
        for line in [
            "k molto seed --seed stdin -s3cret",
            "k piv pin change --pin stdin --new-pin stdin -d3cret",
            "k piv key move --mgmt-key=default -s3cret",
            "k piv key generate --mgmt-key env:K -o3cret",
            "k openpgp key import --admin-pin stdin -i3cret",
        ] {
            assert!(short_glued_after_source(&argv(line)), "{line}");
        }
        for line in [
            "k molto seed --seed stdin -s 1 -y",
            "k molto seed -s1 --seed stdin -y",
            "k piv pin change --pin stdin -d k",
            "k piv x --pin stdin --slot 9a",
            "k piv x --pin stdin -123456",
        ] {
            assert!(!short_glued_after_source(&argv(line)), "{line}");
        }
    }

    #[test]
    fn a_dash_led_word_after_any_source_is_hidden() {
        let argv = |s: &str| s.split(' ').map(String::from).collect::<Vec<_>>();
        for line in [
            "k piv x --pin env:KR_PIN -123456",
            "k piv x --pin=env:KR_PIN -123456",
            "k piv x --mgmt-key default -0102",
            "k piv x --mgmt-key=default -0102",
        ] {
            assert!(secret_flag_precedes(&argv(line), "-"), "{line}");
        }
    }

    #[test]
    fn a_dash_led_word_after_a_stdin_source_is_hidden() {
        let argv = |s: &str| s.split(' ').map(String::from).collect::<Vec<_>>();
        assert!(secret_flag_precedes(
            &argv("k piv x --pin stdin -123456"),
            "-1"
        ));
        assert!(secret_flag_precedes(
            &argv("k piv x --pin=stdin -123456"),
            "-1"
        ));
        assert!(!secret_flag_precedes(
            &argv("k piv x --slot 9a -123456"),
            "-1"
        ));
    }

    /// Every command in the tree with its path ("fido pin set"; "" for the root).
    fn all_commands() -> Vec<(String, clap::Command)> {
        use clap::CommandFactory;
        fn walk(c: &clap::Command, path: String, out: &mut Vec<(String, clap::Command)>) {
            out.push((path.clone(), c.clone()));
            for s in c.get_subcommands().filter(|s| s.get_name() != "help") {
                let p = if path.is_empty() {
                    s.get_name().to_string()
                } else {
                    format!("{path} {}", s.get_name())
                };
                walk(s, p, out);
            }
        }
        let mut root = Cli::command();
        root.build();
        let mut out = Vec::new();
        walk(&root, String::new(), &mut out);
        out
    }

    /// The built command at `path` (`&["openpgp", "pin", "unblock"]`).
    fn find(path: &[&str]) -> clap::Command {
        use clap::CommandFactory;
        let mut root = Cli::command();
        root.build();
        let mut c = &root;
        for name in path {
            c = c
                .find_subcommand(name)
                .unwrap_or_else(|| panic!("no command {path:?}"));
        }
        c.clone()
    }

    #[test]
    fn every_flag_and_argument_has_help() {
        let mut bad = Vec::new();
        for (path, cmd) in all_commands() {
            for a in cmd.get_arguments() {
                if matches!(a.get_id().as_str(), "help" | "version") || a.is_hide_set() {
                    continue;
                }
                if a.get_help().is_none_or(|h| h.to_string().trim().is_empty()) {
                    let name = a
                        .get_long()
                        .map_or_else(|| a.get_id().to_string(), |l| format!("--{l}"));
                    bad.push(format!("{path}: {name}"));
                }
            }
        }
        assert!(bad.is_empty(), "no help:\n{}", bad.join("\n"));
    }

    /// Two markers, on purpose. "Irreversible" ends the first line of every
    /// command whose change loses something stored (a key, seed, certificate,
    /// credential or blob). "One-way" is a deliberate second marker for a
    /// setting that loses nothing but can't be turned back except by a FIDO
    /// reset; only `ONE_WAY_SETTINGS` carry it.
    #[test]
    fn destructive_marker_styles() {
        const ONE_WAY_SETTINGS: [&str; 2] =
            ["fido pin min-length", "fido config attestation enable"];
        let irreversible: &[(&str, &str)] = &[
            ("fido reset", IRREVERSIBLE),
            ("fido credential delete", IRREVERSIBLE),
            ("fido fingerprint delete", IRREVERSIBLE),
            ("fido blob delete", IRREVERSIBLE),
            ("fido blob clear", IRREVERSIBLE),
            ("molto delete", IRREVERSIBLE),
            ("molto reset", IRREVERSIBLE),
            ("oath delete", IRREVERSIBLE),
            ("oath reset", IRREVERSIBLE),
            ("otp delete", IRREVERSIBLE),
            ("otp reset", IRREVERSIBLE),
            ("otp button delete", IRREVERSIBLE),
            ("openpgp reset", IRREVERSIBLE),
            ("openpgp key generate", IRREVERSIBLE),
            ("openpgp key import", IRREVERSIBLE),
            ("piv reset", IRREVERSIBLE),
            ("piv cert delete", IRREVERSIBLE),
            ("piv key delete", IRREVERSIBLE),
            // These replace a key, seed or certificate already on the device.
            ("piv key generate", IRREVERSIBLE),
            ("piv cert import", IRREVERSIBLE),
            ("piv cert generate", IRREVERSIBLE),
            ("molto seed", IRREVERSIBLE),
            ("molto import", IRREVERSIBLE),
            ("prog seed", IRREVERSIBLE),
            ("otp button set", IRREVERSIBLE),
            ("piv retries set", IRREVERSIBLE),
            ("molto customer-key", IRREVERSIBLE),
            ("factory-reset", IRREVERSIBLE_TYPED),
            ("otp interface", IRREVERSIBLE_TYPED),
        ];
        let marked: Vec<(&str, &str)> = irreversible
            .iter()
            .copied()
            .chain(ONE_WAY_SETTINGS.iter().map(|p| (*p, ONE_WAY)))
            .collect();
        // Commands that ask before a change that destroys no key, seed or
        // certificate: a token setting, plus `piv cert request`, which
        // replaces a key only with the optional `--generate-key`.
        let confirms_only = ["prog config", "piv cert request"];
        let tree = all_commands();
        for p in marked.iter().map(|(p, _)| *p).chain(confirms_only) {
            assert!(tree.iter().any(|(t, _)| t == p), "{p:?} is not a command");
        }
        for (path, cmd) in tree {
            // Hidden commands (`molto probe`) take `--yes` as a gate, not an answer.
            if cmd.is_hide_set() {
                continue;
            }
            let about = cmd.get_about().map(|s| s.to_string()).unwrap_or_default();
            let long = cmd
                .get_long_about()
                .map(|s| s.to_string())
                .unwrap_or_default();
            for old in [
                "DESTRUCTIVE",
                "ONE-WAY",
                "Irreversible.",
                "Irreversible\n",
                "Asks first.",
            ] {
                assert!(
                    !about.contains(old) && !long.contains(old),
                    "{path}: old marker {old:?}"
                );
            }
            match marked.iter().find(|(p, _)| *p == path) {
                Some((_, m)) => assert!(
                    about.ends_with(m),
                    "{path}: first line must end with {m:?}: {about:?}"
                ),
                None => {
                    assert!(
                        !about.contains("Irreversible") && !about.contains("One-way"),
                        "{path}: {about:?}"
                    );
                    let asks = cmd.get_arguments().any(|a| a.get_long() == Some("yes"));
                    assert!(
                        !asks || confirms_only.contains(&path.as_str()),
                        "{path} has --yes: mark it or list it in confirms_only"
                    );
                }
            }
        }
    }

    #[test]
    fn first_lines_are_plain_and_short() {
        let jargon = [
            "authenticatorGetInfo",
            "authenticatorReset",
            "PUT DATA",
            "PSO:",
            "INTERNAL AUTHENTICATE",
            "SET_DEVICE_TYPE",
            "FpEnable",
            "pinUvAuthToken",
            "hidraw",
        ];
        let old_credential = [
            "Requires the admin PIN",
            "Requires admin PIN",
            "(needs the current PIN)",
            "(uses pinUvAuthToken)",
        ];
        for (path, cmd) in all_commands() {
            let about = cmd.get_about().map(|s| s.to_string()).unwrap_or_default();
            for j in jargon {
                assert!(!about.contains(j), "{path}: {j:?} in the first line");
            }
            let plain = [IRREVERSIBLE, IRREVERSIBLE_TYPED, ONE_WAY]
                .iter()
                .fold(about.clone(), |s, m| s.replace(m, ""));
            assert!(
                plain.chars().count() <= 200,
                "{path}: first line is {} chars",
                plain.chars().count()
            );
            let long = cmd
                .get_long_about()
                .map(|s| s.to_string())
                .unwrap_or_default();
            for c in old_credential {
                assert!(!about.contains(c) && !long.contains(c), "{path}: {c:?}");
            }
        }
        for (path, cmd) in all_commands() {
            for a in cmd.get_arguments() {
                let h = a.get_help().map(|s| s.to_string()).unwrap_or_default();
                assert!(!h.contains("hidraw"), "{path}: --{:?}", a.get_long());
            }
        }
    }

    #[test]
    fn top_level_help_covers_every_group_and_globals_come_last() {
        use clap::CommandFactory;
        let about = Cli::command().get_about().unwrap().to_string();
        for g in ["FIDO2", "OATH", "OpenPGP", "PIV", "OTP", "Molto2"] {
            assert!(about.contains(g), "{g}: {about}");
        }
        let names: Vec<String> = Cli::command()
            .get_subcommands()
            .map(|s| s.get_name().to_string())
            .collect();
        assert_eq!(
            names,
            [
                "list",
                "doctor",
                "name",
                "fido",
                "oath",
                "otp",
                "openpgp",
                "piv",
                "molto",
                "prog",
                "factory-reset",
                "completions",
                "manpage"
            ]
        );
        // `Cli` isn't Debug, so `.err().unwrap()` rather than `unwrap_err()`.
        let help = Cli::try_parse_from(["keyroostctl", "molto", "config", "--help"])
            .err()
            .unwrap()
            .to_string();
        let own = help.find("--algorithm").unwrap();
        let global = help
            .find("Global options:")
            .expect("no Global options heading");
        assert!(
            own < global && global < help.find("--debug").unwrap(),
            "{help}"
        );
    }

    #[test]
    fn always_uv_step_table() {
        assert_eq!(always_uv_step(Some(false), true), Ok(AlwaysUvStep::Change));
        assert_eq!(always_uv_step(Some(true), false), Ok(AlwaysUvStep::Change));
        assert_eq!(
            always_uv_step(Some(true), true),
            Ok(AlwaysUvStep::AlreadySet)
        );
        assert_eq!(
            always_uv_step(Some(false), false),
            Ok(AlwaysUvStep::AlreadySet)
        );
        for want in [true, false] {
            let e = always_uv_step(None, want).unwrap_err();
            assert!(e.contains("nothing was changed"), "{e}");
        }
    }

    #[test]
    fn piv_slot_token_matches_clap_for_every_slot() {
        use clap::ValueEnum;
        for v in CliPivSlot::value_variants() {
            let clap_name = v.to_possible_value().unwrap().get_name().to_string();
            assert_eq!(json_out::piv_slot_token(v.to_slot()), clap_name);
        }
        assert_eq!(
            json_out::piv_slot_token(keyroost_piv::Slot::retired(20).unwrap()),
            "95"
        );
    }

    #[test]
    fn piv_reset_refuses_a_card_swapped_during_the_question() {
        assert!(same_piv_card(Some(12345678), Some(12345678)));
        assert!(same_piv_card(None, None));
        assert!(!same_piv_card(Some(12345678), Some(87654321)));
        assert!(!same_piv_card(Some(12345678), None));
        assert!(!same_piv_card(None, Some(12345678)));
    }

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(args)
    }

    #[test]
    fn export_cert_encodings() {
        // Minimal DER SEQUENCE; the encoders don't interpret the contents.
        let der: Vec<u8> = vec![0x30, 0x05, 0x02, 0x01, 0x01, 0x05, 0x00];
        assert_eq!(encode_cert(&der, CertFormat::Der), der);
        let pem = String::from_utf8(encode_cert(&der, CertFormat::Pem)).unwrap();
        assert!(
            pem.starts_with("-----BEGIN CERTIFICATE-----\n")
                && pem.ends_with("-----END CERTIFICATE-----\n")
        );
        assert_eq!(cert_to_der(pem.as_bytes()).unwrap(), der);
    }

    #[test]
    fn export_cert_format_parses_and_defaults_to_pem() {
        let format_of = |argv: &[&str]| match parse(argv).unwrap().command {
            Some(Cmd::Piv {
                cmd:
                    PivCmd::Cert {
                        cmd: PivCertCmd::Export { format, .. },
                    },
            }) => format,
            _ => panic!("not cert export"),
        };
        let base = ["keyroostctl", "piv", "cert", "export", "--slot", "9a"];
        assert_eq!(format_of(&base), CertFormat::Pem);
        let der: Vec<&str> = base.iter().copied().chain(["--format", "der"]).collect();
        assert_eq!(format_of(&der), CertFormat::Der);
        let txt: Vec<&str> = base.iter().copied().chain(["--format", "txt"]).collect();
        assert!(parse(&txt).is_err());
    }

    #[test]
    fn token2_secrets_are_not_accepted_on_the_command_line() {
        for args in [
            &[
                "keyroostctl",
                "molto",
                "seed",
                "--slot",
                "99",
                "--hex",
                "00",
            ][..],
            &[
                "keyroostctl",
                "molto",
                "seed",
                "--slot",
                "99",
                "--base32",
                "X",
            ],
            &["keyroostctl", "prog", "seed", "--hex", "00"],
            &["keyroostctl", "prog", "seed", "--base32", "X"],
            &["keyroostctl", "molto", "customer-key", "--ascii", "x"],
            &["keyroostctl", "molto", "customer-key", "--hex", "00"],
            &["keyroostctl", "molto", "--key", "00", "info"],
            &["keyroostctl", "molto", "--key-ascii", "x", "info"],
            &["keyroostctl", "molto", "--key-env", "V", "info"],
            &["keyroostctl", "molto", "seed", "--slot", "1", "--hex-stdin"],
            &[
                "keyroostctl",
                "molto",
                "import",
                "--slot",
                "1",
                "--uri-env",
                "V",
            ],
        ] {
            match parse(args) {
                Err(e) => assert_eq!(
                    e.kind(),
                    clap::error::ErrorKind::UnknownArgument,
                    "{args:?}"
                ),
                Ok(_) => panic!("{args:?} must not parse"),
            }
        }
    }

    #[test]
    fn molto_import_takes_one_uri_source() {
        let e = parse(&[
            "keyroostctl",
            "molto",
            "import",
            "--slot",
            "1",
            "--uri",
            "env:V",
            "--qr",
            "f.png",
        ])
        .err()
        .expect("must not parse");
        assert_eq!(e.kind(), clap::error::ErrorKind::ArgumentConflict);
        match parse(&[
            "keyroostctl",
            "molto",
            "import",
            "--slot",
            "1",
            "--uri",
            "env:V",
        ])
        .unwrap()
        .command
        {
            Some(Cmd::Molto {
                cmd: MoltoCmd::Import { uri, qr, .. },
                ..
            }) => {
                assert_eq!(uri, Some(SecretSource::Env("V".into())));
                assert!(qr.is_none());
            }
            _ => panic!("expected molto import"),
        }
    }

    #[test]
    fn import_uri_comes_from_stdin_env_or_the_prompt() {
        use crate::secrets::fake::FakeIo;
        let read = |sec: &mut Secrets<FakeIo>, flag: Option<SecretSource>| {
            sec.read(&IMPORT_URI, Source::from_flag(flag.as_ref()))
        };
        let mut sec = Secrets::new(FakeIo::piped(&["otpauth://totp/y?secret=AB\n"]));
        let uri = read(&mut sec, Some(SecretSource::Stdin)).unwrap();
        assert_eq!(uri.as_str(), "otpauth://totp/y?secret=AB");
        let mut sec = Secrets::new(FakeIo::default().var("U", "otpauth://totp/z?secret=CD"));
        let uri = read(&mut sec, Some(SecretSource::Env("U".into()))).unwrap();
        assert_eq!(uri.as_str(), "otpauth://totp/z?secret=CD");
        let mut sec = Secrets::new(FakeIo::terminal().typing(&["otpauth://totp/t?secret=EF"]));
        let uri = read(&mut sec, None).unwrap();
        assert_eq!(uri.as_str(), "otpauth://totp/t?secret=EF");
        assert_eq!(sec.io.prompts, ["otpauth:// URI: "]);
        let mut sec = Secrets::new(FakeIo::default());
        let e = read(&mut sec, None).unwrap_err();
        assert_eq!(
            e,
            "no otpauth:// URI given: pass --uri env:NAME, --uri stdin, --qr IMAGE or --file PATH"
        );
    }

    #[test]
    fn customer_key_comes_from_its_source_or_is_the_factory_default() {
        use crate::secrets::fake::FakeIo;
        let args = |src: Option<SecretSource>, enc: KeyEncoding| KeyArgs {
            customer_key: src,
            customer_key_encoding: enc,
        };
        let env = |v: &str| Some(SecretSource::Env(v.into()));
        let mut sec =
            Secrets::new(FakeIo::default().var("V", " 00112233445566778899aabbccddeeff \n"));
        let k = customer_key(&mut sec, &args(env("V"), KeyEncoding::Hex)).unwrap();
        assert_eq!(k.len(), 16);
        assert_eq!(k[15], 0xff);
        let mut sec = Secrets::new(FakeIo::terminal());
        let k = customer_key(&mut sec, &args(None, KeyEncoding::Hex)).unwrap();
        assert_eq!(&k[..], &DEFAULT_CUSTOMER_KEY[..]);
        assert!(
            sec.io.prompts.is_empty(),
            "the customer key is never prompted for"
        );
        let mut sec = Secrets::new(FakeIo::default());
        let e = customer_key(&mut sec, &args(env("V"), KeyEncoding::Hex)).unwrap_err();
        assert_eq!(
            e,
            "the environment variable given to --customer-key is not set"
        );
        let mut sec = Secrets::new(FakeIo::default().var("A", "my key "));
        let k = customer_key(&mut sec, &args(env("A"), KeyEncoding::Ascii)).unwrap();
        assert_eq!(&k[..], b"my key ");
        let mut sec = Secrets::new(FakeIo::default().var("V", "zz"));
        let e = customer_key(&mut sec, &args(env("V"), KeyEncoding::Hex)).unwrap_err();
        assert!(
            e.contains("given by --customer-key is not valid hex"),
            "{e}"
        );
        assert!(!e.contains("zz") && !e.contains('V'), "{e}");
    }

    #[test]
    fn seeds_are_read_from_their_source_in_their_encoding() {
        use crate::secrets::fake::FakeIo;
        let seed = |args: &[&str], sec: &mut Secrets<FakeIo>| match read_molto_input(
            sec,
            &molto_cmd(args),
        )
        .map_err(|e| e.to_string())?
        {
            MoltoInput::Seed(s) => Ok::<Vec<u8>, String>(s.to_vec()),
            _ => panic!("expected a seed"),
        };
        let base = ["keyroostctl", "molto", "seed", "--slot", "1"];
        let with = |extra: &[&'static str]| -> Vec<&'static str> {
            base.iter().copied().chain(extra.iter().copied()).collect()
        };
        let mut sec = Secrets::new(FakeIo::default());
        assert_eq!(
            seed(&base, &mut sec).unwrap_err(),
            "no seed given: pass --seed env:NAME or --seed stdin"
        );
        let mut sec = Secrets::new(FakeIo::piped(&[" 0102 \n", "never read\n"]));
        let args = with(&["--seed", "stdin", "--encoding", "hex"]);
        assert_eq!(seed(&args, &mut sec).unwrap(), [1, 2]);
        assert_eq!(sec.io.lines_read, 1, "one line, not all of stdin");
        let mut sec = Secrets::new(FakeIo::default().var("B", "JBSWY3DP"));
        assert_eq!(
            seed(&with(&["--seed", "env:B"]), &mut sec).unwrap(),
            b"Hello"
        );
        // Typed at a terminal: asked once (a seed is checked by the service).
        let mut sec = Secrets::new(FakeIo::terminal().typing(&["0a"]));
        let args = with(&["--encoding", "hex"]);
        assert_eq!(seed(&args, &mut sec).unwrap(), [0x0a]);
        assert_eq!(sec.io.prompts, ["Seed (hex): "]);
    }

    #[test]
    fn new_customer_key_is_asked_twice_at_a_prompt() {
        use crate::secrets::fake::FakeIo;
        let new_key = |args: &[&str], sec: &mut Secrets<FakeIo>| match read_molto_input(
            sec,
            &molto_cmd(args),
        )
        .unwrap()
        {
            MoltoInput::NewKey(k) => k.to_vec(),
            _ => panic!("expected a new key"),
        };
        let mut sec = Secrets::new(FakeIo::terminal().typing(&["0011", "0011"]));
        let k = new_key(&["keyroostctl", "molto", "customer-key"], &mut sec);
        assert_eq!(k, [0x00, 0x11]);
        assert_eq!(
            sec.io.prompts,
            [
                "New customer key (hex): ",
                "Repeat new customer key (hex): "
            ]
        );
        let mut sec = Secrets::new(FakeIo::piped(&["abc\n"]));
        let args = [
            "keyroostctl",
            "molto",
            "customer-key",
            "--new-customer-key",
            "stdin",
            "--encoding",
            "ascii",
        ];
        assert_eq!(new_key(&args, &mut sec), b"abc");
    }

    #[test]
    fn seed_and_new_key_decode_errors_name_the_value_but_never_echo_it() {
        use crate::secrets::fake::FakeIo;
        let err = |args: &[&str], line: &str| {
            let mut sec = Secrets::new(FakeIo::piped(&[line]));
            read_molto_input(&mut sec, &molto_cmd(args))
                .err()
                .expect("must refuse")
                .to_string()
        };
        let e = err(
            &[
                "keyroostctl",
                "molto",
                "seed",
                "--slot",
                "1",
                "--seed",
                "stdin",
                "--encoding",
                "hex",
            ],
            "zzS3CRET\n",
        );
        assert_eq!(
            e,
            "the seed is not valid hex (invalid character in input); pass --encoding base32 if it is base32"
        );
        let e = err(
            &[
                "keyroostctl",
                "molto",
                "seed",
                "--slot",
                "1",
                "--seed",
                "stdin",
            ],
            "S3CRET!1\n",
        );
        assert_eq!(
            e,
            "the seed is not valid base32 (invalid character in input); pass --encoding hex if it is hex"
        );
        let e = err(
            &[
                "keyroostctl",
                "molto",
                "customer-key",
                "--new-customer-key",
                "stdin",
            ],
            "zzS3CRET\n",
        );
        assert_eq!(
            e,
            "the customer key given by --new-customer-key is not valid hex (invalid character in input)"
        );
    }

    #[test]
    fn molto_encodings_stay_with_their_secret() {
        use crate::secrets::fake::FakeIo;
        let cli = parse(&[
            "keyroostctl",
            "molto",
            "--customer-key",
            "env:K",
            "--customer-key-encoding",
            "ascii",
            "seed",
            "--slot",
            "1",
            "--seed",
            "env:S",
            "--encoding",
            "hex",
            "--yes",
        ])
        .unwrap();
        let Some(Cmd::Molto { key, cmd, .. }) = cli.command else {
            panic!()
        };
        assert_eq!(key.customer_key_encoding, KeyEncoding::Ascii);
        let MoltoCmd::Seed { encoding, .. } = &cmd else {
            panic!()
        };
        assert_eq!(*encoding, SeedEncoding::Hex);
        let mut sec = Secrets::new(
            FakeIo::default()
                .var("K", "TOKEN2MOLTO1-KEY")
                .var("S", "0102"),
        );
        assert_eq!(
            &customer_key(&mut sec, &key).unwrap()[..],
            b"TOKEN2MOLTO1-KEY"
        );
        match read_molto_input(&mut sec, &cmd).unwrap() {
            MoltoInput::Seed(s) => assert_eq!(&s[..], &[1, 2]),
            _ => panic!(),
        }
        // Defaults: hex key, base32 seed.
        let cli = parse(&[
            "keyroostctl",
            "molto",
            "seed",
            "--slot",
            "1",
            "--seed",
            "env:S",
        ])
        .unwrap();
        let Some(Cmd::Molto {
            key,
            cmd: MoltoCmd::Seed { encoding, .. },
            ..
        }) = cli.command
        else {
            panic!()
        };
        assert_eq!(
            (key.customer_key_encoding, encoding),
            (KeyEncoding::Hex, SeedEncoding::Base32)
        );
    }

    #[test]
    fn molto_customer_key_is_the_first_stdin_line() {
        use crate::secrets::fake::FakeIo;
        let cli = parse(&[
            "keyroostctl",
            "molto",
            "--customer-key",
            "stdin",
            "seed",
            "--slot",
            "1",
            "--seed",
            "stdin",
            "--encoding",
            "hex",
            "--yes",
        ])
        .unwrap();
        let Some(Cmd::Molto { key, cmd, .. }) = cli.command else {
            panic!()
        };
        let mut sec = Secrets::new(FakeIo::piped(&[
            "00112233445566778899aabbccddeeff\n",
            "0a0b\n",
        ]));
        assert_eq!(customer_key(&mut sec, &key).unwrap()[15], 0xff);
        match read_molto_input(&mut sec, &cmd).unwrap() {
            MoltoInput::Seed(s) => assert_eq!(&s[..], &[0x0a, 0x0b]),
            _ => panic!(),
        }
    }

    #[test]
    fn seed_and_key_decode_errors_name_the_flag_never_the_value() {
        let e = decode_seed("zz", SeedEncoding::Hex).unwrap_err();
        assert!(
            e.contains("not valid hex") && e.contains("--encoding base32") && !e.contains("zz"),
            "{e}"
        );
        let e = decode_seed("0189", SeedEncoding::Base32).unwrap_err();
        assert!(
            e.contains("not valid base32") && e.contains("--encoding hex") && !e.contains("0189"),
            "{e}"
        );
        let e = decode_customer_key("zz", KeyEncoding::Hex, "--customer-key").unwrap_err();
        assert!(
            e.contains("given by --customer-key is not valid hex") && !e.contains("zz"),
            "{e}"
        );
        assert_eq!(
            &decode_customer_key("my key ", KeyEncoding::Ascii, "--customer-key").unwrap()[..],
            b"my key "
        );
    }

    #[test]
    fn molto_seed_prompts_at_a_terminal_now() {
        use crate::secrets::fake::FakeIo;
        let cli = parse(&["keyroostctl", "molto", "seed", "--slot", "1", "--yes"]).unwrap();
        let Some(Cmd::Molto { cmd, .. }) = cli.command else {
            panic!()
        };
        let mut sec = Secrets::new(FakeIo::terminal().typing(&["AEBA"]));
        match read_molto_input(&mut sec, &cmd).unwrap() {
            MoltoInput::Seed(s) => assert_eq!(&s[..], &[1, 2]),
            _ => panic!(),
        }
        assert_eq!(sec.io.prompts, vec!["Seed (base32): ".to_string()]);
    }

    #[test]
    fn oath_and_otp_seeds_take_an_encoding() {
        use crate::secrets::fake::FakeIo;
        assert_eq!(
            &decode_seed("0a0b", SeedEncoding::Hex).unwrap()[..],
            [10, 11]
        );
        assert_eq!(&otp_seed("0a0b", SeedEncoding::Hex).unwrap()[..], [10, 11]);
        assert_eq!(
            &otp_seed("jbswy3dp", SeedEncoding::Base32).unwrap()[..],
            b"Hello"
        );
        let e = otp_seed(&"00".repeat(65), SeedEncoding::Hex).unwrap_err();
        assert_eq!(e, "seed must be 1..=64 bytes, got 65");
        let e = otp_seed("S3CRET!1", SeedEncoding::Base32).unwrap_err();
        assert!(e.contains("--encoding hex") && !e.contains("S3CRET"), "{e}");
        for argv in [
            &["keyroostctl", "oath", "add", "n", "--encoding", "hex"][..],
            &[
                "keyroostctl",
                "otp",
                "add",
                "--account",
                "a",
                "--encoding",
                "hex",
            ],
            &["keyroostctl", "otp", "button", "set", "--encoding", "hex"],
            &["keyroostctl", "prog", "seed", "--encoding", "hex"],
        ] {
            parse(argv).unwrap_or_else(|e| panic!("{argv:?}: {e}"));
        }
        // The pair the oath/otp handlers read prompts in the chosen encoding.
        let cli = parse(&["keyroostctl", "oath", "add", "n", "--encoding", "hex"]).unwrap();
        let pair = cli.command.as_ref().and_then(stdin_pair).unwrap();
        assert_eq!(pair.first.0.form, crate::secrets::Form::Hex);
        let mut sec = Secrets::new(FakeIo::terminal().typing(&["0a"]));
        sec.read(pair.first.0, Source::NONE).unwrap();
        assert_eq!(sec.io.prompts, ["Seed (hex): "]);
    }

    fn molto_cmd(args: &[&str]) -> MoltoCmd {
        match parse(args)
            .unwrap_or_else(|e| panic!("{args:?}: {e}"))
            .command
        {
            Some(Cmd::Molto { cmd, .. }) => cmd,
            _ => panic!("expected a molto command"),
        }
    }

    fn molto_key_args(args: &[&str]) -> KeyArgs {
        match parse(args)
            .unwrap_or_else(|e| panic!("{args:?}: {e}"))
            .command
        {
            Some(Cmd::Molto { key, .. }) => key,
            _ => panic!("expected a molto command"),
        }
    }

    #[test]
    fn molto_arguments_are_checked_without_the_token() {
        use crate::secrets::fake::FakeIo;
        let sec = Secrets::new(FakeIo::default());
        let err = |args: &[&str]| {
            molto_validate(&molto_cmd(args), &molto_key_args(args), &sec)
                .expect_err("must refuse")
                .to_string()
        };
        assert_eq!(
            err(&["keyroostctl", "molto", "seed", "--slot", "99"]),
            "no seed given: pass --seed env:NAME or --seed stdin"
        );
        // Range checks are clap value parsers now: they fail at parse time.
        let parse_err = |args: &[&str]| parse(args).err().expect("must refuse").to_string();
        let e = parse_err(&[
            "keyroostctl",
            "molto",
            "seed",
            "--slot",
            "100",
            "--seed",
            "stdin",
        ]);
        assert!(e.contains("slot must be 0..=99"), "{e}");
        let e = parse_err(&[
            "keyroostctl",
            "molto",
            "title",
            "--slot",
            "1",
            "thirteen-chars",
        ]);
        assert!(e.contains("title must be 1..=12 bytes"), "{e}");
        assert_eq!(
            err(&["keyroostctl", "molto", "import", "--slot", "1"]),
            "no otpauth:// URI given: pass --uri env:NAME, --uri stdin, --qr IMAGE or --file PATH"
        );
        let e = parse_err(&[
            "keyroostctl",
            "molto",
            "import",
            "--slot",
            "1",
            "--title",
            "thirteen-chars",
            "--qr",
            "f.png",
        ]);
        assert!(e.contains("title must be 1..=12 bytes"), "{e}");
        assert_eq!(
            err(&["keyroostctl", "molto", "customer-key"]),
            "no new customer key given: pass --new-customer-key env:NAME or --new-customer-key stdin"
        );
        // An unusable --customer-key is caught here too, on any command.
        assert_eq!(
            err(&[
                "keyroostctl",
                "molto",
                "--customer-key",
                "env:KR_UNSET",
                "config",
                "--slot",
                "1"
            ]),
            "the environment variable given to --customer-key is not set"
        );
        // Nothing was read to find any of that out.
        assert!(sec.io.prompts.is_empty() && sec.io.lines_read == 0);

        // Accepted: a source given, or a terminal that can ask for the URI.
        for args in [
            &[
                "keyroostctl",
                "molto",
                "seed",
                "--slot",
                "99",
                "--seed",
                "stdin",
            ][..],
            &[
                "keyroostctl",
                "molto",
                "import",
                "--slot",
                "1",
                "--uri",
                "stdin",
            ],
            &[
                "keyroostctl",
                "molto",
                "import",
                "--slot",
                "1",
                "--qr",
                "f.png",
            ],
            &[
                "keyroostctl",
                "molto",
                "title",
                "--slot",
                "1",
                "twelve-chars",
            ],
            &["keyroostctl", "molto", "config", "--slot", "99"],
            &["keyroostctl", "molto", "--customer-key", "stdin", "info"],
        ] {
            molto_validate(&molto_cmd(args), &molto_key_args(args), &sec)
                .unwrap_or_else(|e| panic!("{args:?}: {e}"));
        }
        // A terminal can ask for the seed, the new key and the URI.
        let term = Secrets::new(FakeIo::terminal());
        for args in [
            &["keyroostctl", "molto", "import", "--slot", "1"][..],
            &["keyroostctl", "molto", "seed", "--slot", "1"],
            &["keyroostctl", "molto", "customer-key"],
        ] {
            molto_validate(&molto_cmd(args), &molto_key_args(args), &term)
                .unwrap_or_else(|e| panic!("{args:?}: {e}"));
        }
    }

    #[test]
    fn molto_input_is_read_and_checked_before_the_token() {
        use crate::secrets::fake::FakeIo;
        // A seed over 63 bytes is refused once read.
        let long = format!("{}\n", "00".repeat(64));
        let mut sec = Secrets::new(FakeIo::piped(&[&long]));
        let cmd = molto_cmd(&[
            "keyroostctl",
            "molto",
            "seed",
            "--slot",
            "1",
            "--seed",
            "stdin",
            "--encoding",
            "hex",
        ]);
        let e = read_molto_input(&mut sec, &cmd).err().expect("too long");
        assert_eq!(e.to_string(), "seed must be 1..=63 bytes, got 64");
        let mut sec = Secrets::new(FakeIo::piped(&["0102\n"]));
        match read_molto_input(&mut sec, &cmd).unwrap() {
            MoltoInput::Seed(s) => assert_eq!(&s[..], &[1, 2]),
            _ => panic!("expected a seed"),
        }
        // An import's title is settled before authentication.
        let cmd = molto_cmd(&[
            "keyroostctl",
            "molto",
            "import",
            "--slot",
            "1",
            "--uri",
            "stdin",
        ]);
        let mut sec = Secrets::new(FakeIo::piped(&["otpauth://totp/?secret=JBSWY3DP\n"]));
        let e = read_molto_input(&mut sec, &cmd).err().expect("no title");
        assert!(e.to_string().contains("must be 1..=12 bytes"), "{e}");
        let mut sec = Secrets::new(FakeIo::piped(&["otpauth://totp/acct?secret=JBSWY3DP\n"]));
        match read_molto_input(&mut sec, &cmd).unwrap() {
            MoltoInput::Entry { entry, title } => {
                assert_eq!(title, "acct");
                assert_eq!(&entry.secret[..], b"Hello");
            }
            _ => panic!("expected an entry"),
        }
        // Commands with no secret read nothing.
        let mut sec = Secrets::new(FakeIo::terminal());
        let cmd = molto_cmd(&["keyroostctl", "molto", "config", "--slot", "1"]);
        assert!(matches!(
            read_molto_input(&mut sec, &cmd).unwrap(),
            MoltoInput::Nothing
        ));
        assert!(sec.io.prompts.is_empty());
    }

    #[test]
    fn the_same_molto_must_be_present_after_the_question() {
        assert_eq!(
            same_molto(Some("A1"), "A2").unwrap_err(),
            "the Molto2 changed while waiting for a confirmation or a typed secret; nothing was changed"
        );
        assert!(same_molto(None, "x").is_ok());
        assert!(same_molto(Some("A"), "A").is_ok());
        assert_eq!(
            same_prog_token("A1", "A2").unwrap_err(),
            "the programmable token changed while waiting for a confirmation or a typed secret; nothing was changed"
        );
        assert!(same_prog_token("A", "A").is_ok());
    }

    #[test]
    fn retired_flags_name_their_replacement_and_never_the_value() {
        let argv = |s: &str| s.split(' ').map(String::from).collect::<Vec<_>>();
        for (flag, line, want) in [
            (
                "--key",
                "keyroostctl molto --key 00aa seed -p 1",
                "use --customer-key env:NAME",
            ),
            (
                "--key-ascii",
                "keyroostctl molto --key-ascii x info",
                "use --customer-key env:NAME --customer-key-encoding ascii",
            ),
            (
                "--key-env",
                "keyroostctl molto --key-env V info",
                "--customer-key env:VAR",
            ),
            (
                "--key-ascii-env",
                "keyroostctl molto info --key-ascii-env V",
                "--customer-key env:VAR --customer-key-encoding ascii",
            ),
            (
                "--hex",
                "keyroostctl molto seed -p 1 --hex 00",
                "use --seed env:NAME --encoding hex",
            ),
            (
                "--base32",
                "keyroostctl prog seed --base32 AA",
                "use --seed env:NAME (base32 is the default encoding)",
            ),
            (
                "--hex-env",
                "keyroostctl molto seed --slot 1 --hex-env V",
                "--seed env:VAR --encoding hex",
            ),
            (
                "--base32-stdin",
                "keyroostctl prog seed --base32-stdin",
                "--seed stdin (base32",
            ),
            (
                "--hex",
                "keyroostctl molto customer-key --hex 00",
                "use --new-customer-key env:NAME (hex is the default encoding)",
            ),
            (
                "--ascii",
                "keyroostctl molto customer-key --ascii x",
                "use --new-customer-key env:NAME --encoding ascii",
            ),
            (
                "--hex-stdin",
                "keyroostctl molto customer-key --hex-stdin",
                "--new-customer-key stdin",
            ),
            (
                "--ascii-env",
                "keyroostctl molto customer-key --ascii-env V",
                "--new-customer-key env:VAR --encoding ascii",
            ),
            (
                "--uri-env",
                "keyroostctl molto import --slot 1 --uri-env V",
                "--uri env:VAR",
            ),
            (
                "--secret-env",
                "keyroostctl oath add n --secret-env V",
                "--seed env:VAR",
            ),
            (
                "--secret-stdin",
                "keyroostctl oath add n --secret-stdin",
                "--seed stdin",
            ),
            (
                "--current-env",
                "keyroostctl otp pin change --current-env V",
                "--pin env:VAR",
            ),
            (
                "--new-env",
                "keyroostctl otp pin change --new-env V",
                "--new-pin env:VAR",
            ),
            (
                "--pin-stdin",
                "keyroostctl otp pin change --pin-stdin",
                "--pin stdin --new-pin stdin",
            ),
            // Generic rows apply on any command.
            (
                "--pin-stdin",
                "keyroostctl fido credential list --pin-stdin",
                "--pin stdin",
            ),
            (
                "--old-mgmt-key-default",
                "keyroostctl piv mgmt-key change --old-mgmt-key-default",
                "--mgmt-key default",
            ),
        ] {
            let msg = retired_flag_hint(flag, &argv(line)).unwrap_or_else(|| panic!("{line}"));
            assert!(msg.contains(want), "{line}: {msg}");
            for value in ["00aa", "AA"] {
                assert!(!msg.contains(value), "{msg}");
            }
        }
        // Scoped: a row only applies under the words it names.
        assert!(retired_flag_hint("--pin", &argv("keyroostctl fido info --pin")).is_none());
        assert!(retired_flag_hint("--hex", &argv("keyroostctl oath add n --hex")).is_none());
    }

    #[test]
    fn an_unexpected_value_on_a_secret_command_is_never_repeated() {
        let argv: fn(&[&str]) -> Vec<String> =
            |a| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let redacted = |args: &[&str]| {
            let e = parse(args)
                .err()
                .unwrap_or_else(|| panic!("{args:?} parsed"));
            redacted_parse_error(&e, &argv(args))
        };
        for (args, path) in [
            (
                &[
                    "keyroostctl",
                    "molto",
                    "seed",
                    "--slot",
                    "99",
                    "--seed",
                    "stdin",
                    "S3CRET",
                ][..],
                "keyroostctl molto seed",
            ),
            (
                &[
                    "keyroostctl",
                    "piv",
                    "pin",
                    "change",
                    "--pin",
                    "stdin",
                    "S3CRET",
                ],
                "keyroostctl piv pin change",
            ),
            (
                &[
                    "keyroostctl",
                    "oath",
                    "add",
                    "n",
                    "--seed",
                    "stdin",
                    "--",
                    "S3CRET",
                ],
                "keyroostctl oath add",
            ),
        ] {
            let msg = redacted(args).unwrap_or_else(|| panic!("{args:?}: not redacted"));
            assert_eq!(
                msg,
                format!(
                    "unexpected extra argument (not shown, in case it is a secret); \
                     see `{path} --help`"
                )
            );
            assert!(!msg.contains("S3CRET"), "{msg}");
        }
        // A misspelled flag keeps clap's message (it names only the flag),
        // and a command without a secret flag keeps clap's message too.
        assert!(redacted(&[
            "keyroostctl",
            "molto",
            "seed",
            "--slot",
            "99",
            "--hexx-stdin"
        ])
        .is_none());
        assert!(redacted(&["keyroostctl", "list", "extra"]).is_none());
        // A stray word on `molto import` (an otpauth:// URI, most likely)
        // names --uri, and the retired `-` says what replaced it.
        let msg = redacted(&[
            "keyroostctl",
            "molto",
            "import",
            "--slot",
            "99",
            "otpauth://totp/x?secret=S3CRET",
        ])
        .expect("redacted");
        assert!(
            msg.contains("--uri env:NAME or --uri stdin") && !msg.contains("S3CRET"),
            "{msg}"
        );
        assert_eq!(
            redacted(&["keyroostctl", "molto", "import", "--slot", "99", "-"]).as_deref(),
            Some("`molto import -` is now `molto import --uri stdin`")
        );
        // A retired flag still gets its replacement hint.
        assert!(redacted(&[
            "keyroostctl",
            "molto",
            "seed",
            "--slot",
            "99",
            "--hex",
            "S3CRET"
        ])
        .is_some_and(|m| m.contains("--seed env:NAME --encoding hex") && !m.contains("S3CRET")));
    }

    /// A retired `--X-stdin=VALUE` is an unknown flag: the hint names its
    /// replacement and never the value, which may be the secret itself.
    #[test]
    fn a_stdin_flag_given_a_value_is_never_repeated() {
        let argv: fn(&[&str]) -> Vec<String> =
            |a| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let redacted = |args: &[&str]| {
            let e = parse(args)
                .err()
                .unwrap_or_else(|| panic!("{args:?} parsed"));
            redacted_parse_error(&e, &argv(args))
        };
        let args = [
            "keyroostctl",
            "molto",
            "seed",
            "--slot",
            "99",
            "--hex-stdin=S3CRET",
        ];
        let msg = redacted(&args).unwrap_or_else(|| panic!("{args:?}: not redacted"));
        assert!(msg.contains("--seed stdin --encoding hex"), "{msg}");
        assert!(!msg.contains("S3CRET"), "{msg}");
        // A retired `--X-stdin` flag gets its replacement, never the value.
        let args = [
            "keyroostctl",
            "piv",
            "pin",
            "change",
            "--old-pin-stdin",
            "--new-pin-stdin=S3CRET",
        ];
        let msg = redacted(&args).unwrap_or_else(|| panic!("{args:?}: not redacted"));
        assert!(
            msg.contains("--pin stdin") && !msg.contains("S3CRET"),
            "{msg}"
        );
    }

    /// A secret flag with the value glued on (`--pin123456`, `--pin:123456`,
    /// the retired `--pin-env123456`) is refused with the fixed text and
    /// never repeated. A glued word made only of letters and dashes is a
    /// typo'd flag name and keeps clap's own message.
    #[test]
    fn a_secret_flag_with_the_value_glued_on_is_never_repeated() {
        let argv: fn(&[&str]) -> Vec<String> =
            |a| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let redacted = |args: &[&str]| {
            let e = parse(args)
                .err()
                .unwrap_or_else(|| panic!("{args:?} parsed"));
            redacted_parse_error(&e, &argv(args))
        };
        for (args, want) in [
            (
                &["keyroostctl", "piv", "test", "--slot", "9a", "--pin123456"][..],
                "--pin takes env:NAME or stdin — never the PIN itself",
            ),
            (
                &["keyroostctl", "piv", "test", "--slot", "9a", "--pin:123456"][..],
                "--pin takes env:NAME or stdin — never the PIN itself",
            ),
            (
                &[
                    "keyroostctl",
                    "piv",
                    "test",
                    "--slot",
                    "9a",
                    "--pin-env123456",
                ][..],
                "--pin takes env:NAME or stdin — never the PIN itself",
            ),
            (
                &[
                    "keyroostctl",
                    "piv",
                    "test",
                    "--slot",
                    "9a",
                    "--pinenv:123456",
                ][..],
                "--pin takes env:NAME or stdin — never the PIN itself",
            ),
            (
                &[
                    "keyroostctl",
                    "molto",
                    "seed",
                    "--slot",
                    "99",
                    "--seed123456",
                ][..],
                "--seed takes env:NAME or stdin",
            ),
            (
                &["keyroostctl", "piv", "pin", "change", "--new-pin123456"][..],
                "--new-pin takes env:NAME or stdin",
            ),
        ] {
            let msg = redacted(args).unwrap_or_else(|| panic!("{args:?}: not redacted"));
            assert!(msg.contains(want), "{args:?}: {msg}");
            assert!(!msg.contains("123456"), "{msg}");
        }
        // A typo'd flag name keeps clap's message and its tip.
        assert!(redacted(&["keyroostctl", "piv", "test", "--slot", "9a", "--pinn"]).is_none());
    }

    /// A word right after a secret source and a non-secret flag (`--seed
    /// stdin -s S3CRET`) may be the secret typed in the wrong place: an
    /// invalid value there names the flag, never the value.
    #[test]
    fn an_invalid_value_right_after_a_secret_source_is_never_repeated() {
        let argv: fn(&[&str]) -> Vec<String> =
            |a| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let redacted = |args: &[&str]| {
            let e = parse(args)
                .err()
                .unwrap_or_else(|| panic!("{args:?} parsed"));
            redacted_parse_error(&e, &argv(args))
        };
        for args in [
            &[
                "keyroostctl",
                "molto",
                "seed",
                "--seed",
                "stdin",
                "-s",
                "S3CRET",
            ][..],
            &[
                "keyroostctl",
                "molto",
                "seed",
                "--seed=env:X",
                "--slot",
                "S3CRET",
            ][..],
        ] {
            let msg = redacted(args).unwrap_or_else(|| panic!("{args:?}: not redacted"));
            assert!(msg.contains("--slot"), "{msg}");
            assert!(!msg.contains("S3CRET"), "{msg}");
        }
        // Anywhere else, clap's own message (which shows the value) stays.
        assert!(redacted(&["keyroostctl", "molto", "seed", "-s", "S3CRET"]).is_none());
    }

    /// `openpgp pin change --admin` takes the admin PIN through --pin.
    #[test]
    fn the_admin_pin_hint_on_pin_change_names_pin_under_admin() {
        let argv: Vec<String> = [
            "keyroostctl",
            "openpgp",
            "pin",
            "change",
            "--admin",
            "--admin-pin-env",
            "X",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let msg = retired_flag_hint("--admin-pin-env", &argv).expect("hint");
        assert!(
            msg.contains("with --admin, --pin is the admin PIN"),
            "{msg}"
        );
    }

    /// A dash-led word right after a stdin source (`--pin stdin
    /// -123456`) is hidden the same way as a bare stray value — clap only
    /// reports the short-flag prefix it choked on (`-1`), but the rest of
    /// the word never reached argv's own InvalidArg context, so it must be
    /// kept out some other way. A word shaped like a typo'd flag name is
    /// still shown: that's useful, and never a secret.
    #[test]
    fn a_dash_led_value_after_a_stdin_flag_is_never_repeated() {
        let argv: fn(&[&str]) -> Vec<String> =
            |a| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let redacted = |args: &[&str]| {
            let e = parse(args)
                .err()
                .unwrap_or_else(|| panic!("{args:?} parsed"));
            redacted_parse_error(&e, &argv(args))
        };
        let args = [
            "keyroostctl",
            "piv",
            "pin",
            "change",
            "--pin",
            "stdin",
            "-123456",
        ];
        let msg = redacted(&args).unwrap_or_else(|| panic!("{args:?}: not redacted"));
        assert!(
            msg.contains("unexpected extra argument (not shown, in case it is a secret)"),
            "{msg}"
        );
        assert!(!msg.contains("123456"), "{msg}");
        // A typo'd flag name after the same source is still clap's own
        // message, with its "similar argument" tip.
        assert!(redacted(&[
            "keyroostctl",
            "piv",
            "pin",
            "change",
            "--pin",
            "stdin",
            "--new-pn"
        ])
        .is_none());
    }

    #[test]
    fn device_completion_offers_saved_names_only() {
        let entry = |name: &str, serial: &str| keyroost_keyring::KeyEntry {
            name: name.into(),
            serial: serial.into(),
            source: keyroost_keyring::IdSource::Usb,
            vendor: None,
            aaguid: None,
            note: None,
        };
        let mut k = Keyring::default();
        k.add(entry("yubi-test", "1")).unwrap();
        k.add(entry("solo test", "2")).unwrap();
        let got: Vec<String> = device_candidates_from(&k)
            .iter()
            .map(|c| c.get_value().to_string_lossy().into_owned())
            .collect();
        assert_eq!(got, vec!["yubi-test".to_string(), "solo test".to_string()]);
        let cmd = <Cli as clap::CommandFactory>::command();
        let arg = cmd
            .get_arguments()
            .find(|a| a.get_id() == "device")
            .unwrap();
        assert!(arg.get::<clap_complete::ArgValueCandidates>().is_some());
    }

    #[test]
    fn completions_print_a_callback_registration() {
        let mut out = Vec::new();
        write_completion_registration(clap_complete::Shell::Zsh, &mut out).unwrap();
        assert!(String::from_utf8(out)
            .unwrap()
            .starts_with("#compdef keyroostctl"));
        let mut out = Vec::new();
        write_completion_registration(clap_complete::Shell::Bash, &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("KEYROOSTCTL_COMPLETE=") && s.contains("keyroostctl"));
        // One completion mode only: there is no static-script variant.
        assert!(parse(&["keyroostctl", "completions", "bash"]).is_ok());
        assert!(parse(&["keyroostctl", "completions", "bash", "--static"]).is_err());
    }

    #[test]
    fn fido_ssh_cert_extract_grammar() {
        match parse(&[
            "keyroostctl",
            "fido",
            "ssh",
            "extract",
            "--id",
            "ssh:demo",
            "--out",
            "id-cert.pub",
            "--overwrite",
            "--pin",
            "stdin",
        ])
        .unwrap()
        .command
        {
            Some(Cmd::Fido {
                cmd:
                    FidoCmd::Ssh {
                        cmd:
                            SshCertCmd::Extract {
                                id,
                                out,
                                overwrite,
                                pin,
                                ..
                            },
                    },
            }) => {
                assert_eq!(id.as_deref(), Some("ssh:demo"));
                assert_eq!(out.as_deref(), Some(std::path::Path::new("id-cert.pub")));
                assert!(overwrite && pin == Some(SecretSource::Stdin));
            }
            _ => panic!("expected fido ssh extract"),
        }
    }

    // `--force` was renamed to `--overwrite` with no alias, so that "force" has
    // one meaning across the CLI: it exists only on piv commands, where it
    // means "ignore keyroost's compatibility list" — a different question from
    // "overwrite this file" (and from `--yes`, which skips the confirmation).
    // The old spelling must be rejected, not silently accepted.
    #[test]
    fn ssh_cert_extract_overwrite_flag() {
        match parse(&["keyroostctl", "fido", "ssh", "extract", "--overwrite"])
            .unwrap()
            .command
        {
            Some(Cmd::Fido {
                cmd:
                    FidoCmd::Ssh {
                        cmd: SshCertCmd::Extract { overwrite, .. },
                    },
            }) => assert!(overwrite),
            _ => panic!("expected fido ssh extract"),
        }
        assert!(parse(&["keyroostctl", "fido", "ssh", "extract", "--force"]).is_err());
        let help = <Cli as clap::CommandFactory>::command()
            .find_subcommand_mut("fido")
            .unwrap()
            .find_subcommand_mut("ssh")
            .unwrap()
            .find_subcommand_mut("extract")
            .unwrap()
            .render_help()
            .to_string();
        assert!(help.contains("--overwrite") && !help.contains("--force"));
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
        match parse(&["keyroostctl", "fido", "pin", "set", "--new-pin", "stdin"])
            .unwrap()
            .command
        {
            Some(Cmd::Fido {
                cmd:
                    FidoCmd::Pin {
                        cmd: FidoPinCmd::Set { new_pin, .. },
                    },
            }) => assert_eq!(new_pin, Some(SecretSource::Stdin)),
            _ => panic!("expected fido pin set"),
        }

        // Global flags decode as themselves.
        let g = parse(&["keyroostctl", "--json", "--debug", "piv", "info"]).unwrap();
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
    fn fido_one_way_settings_require_explicit_yes() {
        // Raising the minimum PIN length and enabling enterprise attestation
        // cannot be undone without a reset, so both take the same --yes as the
        // other irreversible commands. --yes must land in the confirm field and
        // omitting it must decode to false.
        match parse(&[
            "keyroostctl",
            "fido",
            "pin",
            "min-length",
            "--length",
            "8",
            "--yes",
        ])
        .unwrap()
        .command
        {
            Some(Cmd::Fido {
                cmd:
                    FidoCmd::Pin {
                        cmd: FidoPinCmd::MinLength { yes, length, .. },
                    },
            }) => assert!(yes && length == 8),
            _ => panic!("expected fido pin min-length"),
        }
        match parse(&["keyroostctl", "fido", "pin", "min-length", "--length", "8"])
            .unwrap()
            .command
        {
            Some(Cmd::Fido {
                cmd:
                    FidoCmd::Pin {
                        cmd: FidoPinCmd::MinLength { yes, .. },
                    },
            }) => assert!(!yes),
            _ => panic!("expected fido pin min-length"),
        }
        match parse(&[
            "keyroostctl",
            "fido",
            "config",
            "attestation",
            "enable",
            "--yes",
        ])
        .unwrap()
        .command
        {
            Some(Cmd::Fido {
                cmd:
                    FidoCmd::Config {
                        cmd:
                            FidoConfigCmd::Attestation {
                                cmd: FidoAttestationCmd::Enable { yes, .. },
                            },
                    },
            }) => assert!(yes),
            _ => panic!("expected fido config attestation enable"),
        }
        match parse(&["keyroostctl", "fido", "config", "attestation", "enable"])
            .unwrap()
            .command
        {
            Some(Cmd::Fido {
                cmd:
                    FidoCmd::Config {
                        cmd:
                            FidoConfigCmd::Attestation {
                                cmd: FidoAttestationCmd::Enable { yes, .. },
                            },
                    },
            }) => assert!(!yes),
            _ => panic!("expected fido config attestation enable"),
        }
    }

    #[test]
    fn refusals_name_the_key_and_the_fix() {
        // The mechanism every --yes command now shares (prompt::confirm*);
        // scripts see one line naming the key and "add --yes".
        use crate::prompt::{confirm, confirm_typed, Term};
        struct NoTty;
        impl Term for NoTty {
            fn present(&self) -> bool {
                false
            }
            fn say(&mut self, _: &str) {}
            fn ask(&mut self, _: &str) -> std::io::Result<String> {
                unreachable!("never asks without a terminal")
            }
        }
        let e = confirm(
            &mut NoTty,
            false,
            "raise the minimum PIN length to 8",
            "solo-test",
        )
        .unwrap_err();
        assert_eq!(
            e,
            "refusing to raise the minimum PIN length to 8 on solo-test without confirmation; add --yes"
        );
        assert!(
            confirm_typed(&mut NoTty, false, "reset", "factory-reset", "k")
                .unwrap_err()
                .ends_with("add --yes")
        );
    }

    #[test]
    fn fido_one_way_settings_ask_before_reading_the_pin() {
        // Without a terminal and without --yes the refusal comes first: an
        // unset PIN variable would otherwise be the error. With --yes the PIN
        // is read next, so the same unset variable is what fails.
        use crate::secrets::fake::FakeIo;
        use crate::secrets::{Secrets, Source};
        struct NoTty;
        impl crate::prompt::Term for NoTty {
            fn present(&self) -> bool {
                false
            }
            fn say(&mut self, _: &str) {}
            fn ask(&mut self, _: &str) -> std::io::Result<String> {
                unreachable!("never asks without a terminal")
            }
        }
        let unset = Source::env("KR_UNSET");
        let action = "enable enterprise attestation (only a reset turns it off)";
        let mut sec = Secrets::new(FakeIo::default());
        let e = confirm_then_read_pin(
            &mut NoTty,
            &mut sec,
            false,
            action,
            "solo-test",
            None,
            unset,
        )
        .unwrap_err()
        .to_string();
        assert!(e.ends_with("add --yes"), "{e}");
        assert!(!e.contains("KR_UNSET"), "{e}");
        let e = confirm_then_read_pin(&mut NoTty, &mut sec, true, action, "solo-test", None, unset)
            .unwrap_err()
            .to_string();
        assert!(!e.contains("KR_UNSET"), "{e}");
        assert!(e.contains("--pin"), "{e}");
    }

    /// A terminal that answers "y" to every question.
    struct YesTerm;
    impl crate::prompt::Term for YesTerm {
        fn present(&self) -> bool {
            true
        }
        fn say(&mut self, _: &str) {}
        fn ask(&mut self, _: &str) -> std::io::Result<String> {
            Ok("y\n".into())
        }
    }

    #[test]
    fn confirm_then_read_pin_reverifies_only_after_the_pin_is_read() {
        // The re-check must never run ahead of the PIN read: if reading the
        // PIN fails, nothing has been reopened yet and there is nothing to
        // re-check. This is what would regress if the re-check moved back
        // to right after the question, ahead of the (possibly slow, typed)
        // PIN entry.
        use crate::secrets::fake::FakeIo;
        use crate::secrets::{Secrets, Source};
        let reverify_ran = std::cell::Cell::new(false);
        let mut sec = Secrets::new(FakeIo::default());
        let e = confirm_then_read_pin_ordered(
            &mut YesTerm,
            &mut sec,
            false,
            "action",
            "k",
            Source::env("KR_T"),
            |_asked| {
                reverify_ran.set(true);
                Ok(())
            },
        )
        .unwrap_err()
        .to_string();
        assert!(!e.contains("KR_T") && e.contains("--pin"), "{e}");
        assert!(!reverify_ran.get(), "re-check ran before the PIN was read");
    }

    #[test]
    fn confirm_then_read_pin_reverifies_after_a_successful_read() {
        use crate::secrets::fake::FakeIo;
        use crate::secrets::{Secrets, Source};
        let mut sec = Secrets::new(FakeIo::default().var("KR_T", "1234"));
        let seen = std::cell::RefCell::new(Vec::new());
        let pin = confirm_then_read_pin_ordered(
            &mut YesTerm,
            &mut sec,
            false,
            "action",
            "k",
            Source::env("KR_T"),
            |asked| {
                seen.borrow_mut().push(asked);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(&*pin, "1234");
        // The read already happened (the PIN above came from it); the
        // re-check runs once more, right after, with `asked` carried through.
        assert_eq!(*seen.borrow(), vec![true]);
    }

    #[test]
    fn fido_secret_flags_all_have_help_and_name_their_stdin_line() {
        use clap::CommandFactory;
        fn walk(cmd: &clap::Command, path: &str, out: &mut Vec<String>) {
            for a in cmd.get_arguments() {
                let long = a.get_long().unwrap_or_default();
                if is_secret_arg(a) && long.contains("pin") {
                    let help = a.get_help().map(|h| h.to_string()).unwrap_or_default();
                    if help.is_empty() {
                        out.push(format!("{path} --{long}"));
                    }
                }
            }
            for sub in cmd.get_subcommands() {
                walk(sub, &format!("{path} {}", sub.get_name()), out);
            }
        }
        let cli = Cli::command();
        let fido = cli.find_subcommand("fido").unwrap();
        let mut missing = Vec::new();
        walk(fido, "fido", &mut missing);
        assert!(missing.is_empty(), "no help: {missing:?}");
        let change = fido
            .find_subcommand("pin")
            .unwrap()
            .find_subcommand("change")
            .unwrap();
        for (flag, line) in [
            ("pin", "first line"),
            ("new-pin", "second line when --pin stdin is also given"),
        ] {
            let help = change
                .get_arguments()
                .find(|a| a.get_long() == Some(flag))
                .and_then(|a| a.get_help().map(|h| h.to_string()))
                .unwrap_or_default();
            assert!(help.contains(line), "pin change --{flag}: {help:?}");
        }
    }

    #[test]
    fn confirm_then_read_pin_prompts_then_reverifies() {
        // --yes and no PIN flag at a terminal: the PIN comes from the hidden
        // prompt, and the re-check runs only once it has been typed.
        use crate::secrets::fake::FakeIo;
        use crate::secrets::{Secrets, Source};
        let mut sec = Secrets::new(FakeIo::terminal().typing(&["1234"]));
        let order = std::cell::RefCell::new(Vec::new());
        let pin = confirm_then_read_pin_ordered(
            &mut YesTerm,
            &mut sec,
            true,
            "action",
            "k",
            Source::NONE,
            |waited| {
                order.borrow_mut().push(format!("reverify waited={waited}"));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(&*pin, "1234");
        assert_eq!(sec.io.prompts, vec!["PIN: ".to_string()]);
        // No question under --yes, but the PIN was typed: the key is
        // re-found anyway.
        assert_eq!(*order.borrow(), vec!["reverify waited=true".to_string()]);
    }

    #[test]
    fn confirm_then_read_pin_skips_the_recheck_for_a_piped_pin_under_yes() {
        use crate::secrets::fake::FakeIo;
        use crate::secrets::{Secrets, Source};
        let mut sec = Secrets::new(FakeIo::piped(&["1234\n"]));
        let seen = std::cell::RefCell::new(Vec::new());
        let pin = confirm_then_read_pin_ordered(
            &mut YesTerm,
            &mut sec,
            true,
            "action",
            "k",
            Source::new(None, true),
            |waited| {
                seen.borrow_mut().push(waited);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(&*pin, "1234");
        assert_eq!(*seen.borrow(), vec![false]);
    }

    #[test]
    fn reverify_if_prompted_is_free_for_scripts() {
        // Env and piped sources never re-enumerate (no device I/O at all).
        use crate::secrets::fake::FakeIo;
        use crate::secrets::{Secrets, Source};
        let mut sec = Secrets::new(FakeIo::piped(&["1234\n"]).var("V", "1"));
        sec.read(&PIV_PIN, Source::env("V")).unwrap();
        sec.read(&PIV_PIN, Source::new(None, true)).unwrap();
        assert!(reverify_if_prompted(&sec, Need::Piv, None).is_ok());
        assert!(fido_reverify_if_prompted(&sec, &test_fido_row()).is_ok());
    }

    fn test_fido_row() -> keyroost_resolve::Device {
        let mut caps = keyroost_resolve::Caps::default();
        caps.insert(keyroost_resolve::Caps::FIDO2);
        keyroost_resolve::Device {
            id: "x".into(),
            name: None,
            vendor: "V".into(),
            model: "M".into(),
            serial: "1".into(),
            transport: String::new(),
            firmware: String::new(),
            caps,
            unverified: keyroost_resolve::Caps::default(),
            kind: keyroost_resolve::DeviceKind::Key,
            hid_path: Some("/dev/hidraw3".into()),
            reader: None,
        }
    }

    #[test]
    fn fido_reverify_checks_the_key_shown_before_the_pin() {
        // After a hidden prompt the re-check gets the very row the caller
        // selected before the PIN, never a fresh selection; with no prompt
        // it does nothing.
        use crate::secrets::fake::FakeIo;
        use crate::secrets::{Secrets, Source};
        let dev = test_fido_row();
        let mut seen = Vec::new();
        let mut sec = Secrets::new(FakeIo::piped(&["1234\n"]));
        sec.read(&FIDO_PIN, Source::new(None, true)).unwrap();
        fido_reverify_with(&sec, &dev, |d| {
            seen.push(std::ptr::eq(d, &dev));
            Ok(())
        })
        .unwrap();
        assert!(seen.is_empty(), "piped stdin is not a prompt");

        let mut sec = Secrets::new(FakeIo::terminal().typing(&["1234"]));
        sec.read(&FIDO_PIN, Source::NONE).unwrap();
        fido_reverify_with(&sec, &dev, |d| {
            seen.push(std::ptr::eq(d, &dev));
            Ok(())
        })
        .unwrap();
        assert_eq!(seen, vec![true]);
        let e = fido_reverify_with(&sec, &dev, |_| Err("swapped".into())).unwrap_err();
        assert_eq!(e.to_string(), "swapped");
    }

    #[test]
    fn always_uv_pre_pin_needs_authnr_cfg_only_to_change() {
        let info = |opts: &[(&str, bool)]| keyroost_ctap::AuthenticatorInfo {
            options: opts.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
            ..Default::default()
        };
        // Already in the wanted state: a no-op whatever authnrCfg says.
        let set = info(&[("alwaysUv", true)]);
        assert_eq!(
            always_uv_pre_pin_step(&set, true).unwrap(),
            AlwaysUvStep::AlreadySet
        );
        // A change needs authenticatorConfig, refused before any PIN.
        let e = always_uv_pre_pin_step(&set, false).unwrap_err().to_string();
        assert!(e.contains("authenticatorConfig"), "{e}");
        let off = info(&[("alwaysUv", true), ("authnrCfg", false)]);
        assert!(always_uv_pre_pin_step(&off, false).is_err());
        let ok = info(&[("alwaysUv", true), ("authnrCfg", true)]);
        assert_eq!(
            always_uv_pre_pin_step(&ok, false).unwrap(),
            AlwaysUvStep::Change
        );
        // Unreported state: refused even when authenticatorConfig is there.
        let e = always_uv_pre_pin_step(&info(&[("authnrCfg", true)]), true)
            .unwrap_err()
            .to_string();
        assert!(e.contains("nothing was changed"), "{e}");
    }

    #[test]
    fn large_blob_unchanged_compares_the_raw_array() {
        use keyroost_ctap::large_blobs::LargeBlobArray;
        let arr = |raw: &[u8]| LargeBlobArray::parse(raw).unwrap();
        assert!(large_blob_unchanged(&arr(&[0x80]), &arr(&[0x80])));
        assert!(!large_blob_unchanged(&arr(&[0x80]), &arr(&[0x81, 0x40])));
        assert!(!large_blob_unchanged(&arr(&[0x81, 0x40]), &arr(&[0x80])));
    }

    #[test]
    fn fido_reset_shows_exactly_one_touch_prompt_per_caller() {
        // A factory-reset step names itself and `fido_reset_at` stays quiet;
        // the standalone reset has no step name and keeps the generic prompt.
        assert!(!needs_generic_touch_prompt(Some("FIDO2")));
        assert!(needs_generic_touch_prompt(None));
    }

    #[test]
    fn fido_reset_route_prefers_replug_unless_a_reader_was_asked_for() {
        use keyroost_resolve::{Caps, Device, DeviceKind};
        let mut caps = Caps::default();
        caps.insert(Caps::FIDO2);
        let both = Device {
            id: "x".into(),
            name: None,
            vendor: "V".into(),
            model: "M".into(),
            serial: "1".into(),
            transport: String::new(),
            firmware: String::new(),
            caps,
            unverified: Caps::default(),
            kind: DeviceKind::Key,
            hid_path: Some("/dev/hidraw3".into()),
            reader: Some("R 00".into()),
        };
        assert_eq!(
            fido_reset_route(&both, false),
            Ok(FidoResetRoute::Replug {
                path: "/dev/hidraw3".into()
            })
        );
        assert_eq!(
            fido_reset_route(&both, true),
            Ok(FidoResetRoute::Card {
                reader: "R 00".into()
            })
        );
        let mut card = both.clone();
        card.hid_path = None;
        assert_eq!(
            fido_reset_route(&card, false),
            Ok(FidoResetRoute::Card {
                reader: "R 00".into()
            })
        );
        let mut none = card;
        none.reader = None;
        assert!(fido_reset_route(&none, false).is_err());
    }

    /// Run `wait_for_replug` against scripted HID scans (the last one repeats)
    /// on a fake clock that only advances when the wait sleeps. Returns the
    /// result and how much fake time passed.
    fn scripted_replug_wait(
        armed: &str,
        scans: &[&[&str]],
    ) -> (Result<(), NoReplugSeen>, std::time::Duration) {
        let scans: Vec<Option<&[&str]>> = scans.iter().map(|s| Some(*s)).collect();
        scripted_replug_wait_with_failures(armed, &scans)
    }

    /// As `scripted_replug_wait`, where `None` is a scan that failed.
    fn scripted_replug_wait_with_failures(
        armed: &str,
        scans: &[Option<&[&str]>],
    ) -> (Result<(), NoReplugSeen>, std::time::Duration) {
        use std::cell::Cell;
        use std::path::PathBuf;
        let clock = Cell::new(std::time::Duration::ZERO);
        let next = Cell::new(0usize);
        let result = wait_for_replug(
            Path::new(armed),
            REPLUG_BUDGET,
            REPLUG_POLL,
            || clock.get(),
            |d| clock.set(clock.get() + d),
            || {
                let i = next.get().min(scans.len() - 1);
                next.set(next.get() + 1);
                scans[i].map(|nodes| nodes.iter().map(PathBuf::from).collect())
            },
        );
        (result, clock.get())
    }

    #[test]
    fn replug_wait_succeeds_once_the_armed_node_goes_and_comes_back() {
        // Same node path back.
        let (r, t) = scripted_replug_wait(
            "/dev/hidraw3",
            &[&["/dev/hidraw3"], &["/dev/hidraw3"], &[], &["/dev/hidraw3"]],
        );
        assert!(r.is_ok());
        assert_eq!(t, REPLUG_POLL * 3);
        // Renumbered on the way back, with another key present throughout.
        let (r, _) = scripted_replug_wait(
            "/dev/hidraw3",
            &[
                &["/dev/hidraw1", "/dev/hidraw3"],
                &["/dev/hidraw1"],
                &["/dev/hidraw1", "/dev/hidraw7"],
            ],
        );
        assert!(r.is_ok());
    }

    #[test]
    fn replug_wait_times_out_when_the_key_is_never_removed() {
        let (r, t) = scripted_replug_wait("/dev/hidraw3", &[&["/dev/hidraw3"]]);
        assert!(r.is_err());
        assert!(
            t <= REPLUG_BUDGET && t + REPLUG_POLL > REPLUG_BUDGET,
            "{t:?}"
        );
        assert_eq!(
            NoReplugSeen.to_string(),
            "no replug seen within 60 seconds; nothing was wiped"
        );
    }

    #[test]
    fn replug_wait_times_out_when_the_key_never_comes_back() {
        let (r, _) = scripted_replug_wait("/dev/hidraw3", &[&["/dev/hidraw3"], &[]]);
        assert!(r.is_err());
        // Another key that was already connected is not the key coming back.
        let (r, _) = scripted_replug_wait(
            "/dev/hidraw3",
            &[&["/dev/hidraw1", "/dev/hidraw3"], &["/dev/hidraw1"]],
        );
        assert!(r.is_err());
    }

    #[test]
    fn replug_wait_does_not_read_a_failed_scan_as_the_key_leaving() {
        // A transient scan failure between two scans that both show the armed
        // node is not a removal, so the wait runs out instead of completing.
        let (r, _) = scripted_replug_wait_with_failures(
            "/dev/hidraw3",
            &[Some(&["/dev/hidraw3"]), None, Some(&["/dev/hidraw3"])],
        );
        assert!(r.is_err());
        // A failed first scan is no baseline either: an already-connected key
        // still does not count as the replug.
        let (r, _) = scripted_replug_wait_with_failures(
            "/dev/hidraw3",
            &[
                None,
                Some(&["/dev/hidraw1", "/dev/hidraw3"]),
                Some(&["/dev/hidraw1"]),
            ],
        );
        assert!(r.is_err());
    }

    #[test]
    fn factory_reset_summary_counts_only_real_wipes_and_fails_on_a_skip() {
        use keyroost_resolve::{ResetStep, StepOutcome, StepReport};
        let r = |step, outcome| StepReport { step, outcome };
        let all_wiped = [
            r(ResetStep::Oath, StepOutcome::Wiped),
            r(ResetStep::Piv, StepOutcome::WipedGlobal),
            r(
                ResetStep::OpenPgp,
                StepOutcome::WipedWithWarning("w".into()),
            ),
        ];
        let (line, verdict) = factory_reset_summary(&all_wiped);
        assert_eq!(line, "factory reset: 3 wiped, 0 skipped, 0 failed");
        assert!(verdict.is_ok());

        // Nobody replugged: the FIDO2 step was skipped, so the key was not
        // fully reset and the command must not succeed.
        let fido_skipped = [
            r(ResetStep::Oath, StepOutcome::Wiped),
            r(
                ResetStep::Fido,
                StepOutcome::Skipped("no replug seen within 60 seconds".into()),
            ),
        ];
        let (line, verdict) = factory_reset_summary(&fido_skipped);
        assert_eq!(line, "factory reset: 1 wiped, 1 skipped, 0 failed");
        assert!(verdict.unwrap_err().contains("not fully reset"));

        let failed = [
            r(ResetStep::Oath, StepOutcome::Failed("x".into())),
            r(ResetStep::Fido, StepOutcome::Skipped("y".into())),
        ];
        let (line, verdict) = factory_reset_summary(&failed);
        assert_eq!(line, "factory reset: 0 wiped, 1 skipped, 1 failed");
        let err = verdict.unwrap_err();
        assert!(
            err.contains("1 applet(s) failed") && err.contains("1 skipped"),
            "{err}"
        );
    }

    #[test]
    fn fido_reset_unidentified_message_names_itself_without_the_factory_reset_aside() {
        let msg = not_present_message(
            "YubiKey 5",
            "12345678",
            3,
            "YubiKey 5 with no serial",
            not_present_reason(&[""]),
            FIDO_RESET_NOUN,
            FIDO_RESET_RERUN,
        );
        assert!(
            msg.contains("the key this FIDO2 reset was confirmed for"),
            "{msg}"
        );
        assert!(
            msg.ends_with("then run `keyroostctl fido reset --yes` to finish the wipe."),
            "{msg}"
        );
        assert!(!msg.contains("factory"), "no factory-reset aside: {msg}");

        let msg = not_present_message(
            "YubiKey 5",
            "12345678",
            3,
            "YubiKey 5 serial 87654321",
            not_present_reason(&["87654321"]),
            FIDO_RESET_NOUN,
            FIDO_RESET_RERUN,
        );
        assert!(
            msg.contains("is not the one this FIDO2 reset was confirmed for"),
            "{msg}"
        );
        assert!(
            msg.ends_with("re-run `keyroostctl fido reset --yes`."),
            "{msg}"
        );
    }

    #[test]
    fn replug_wait_ignores_a_new_node_while_the_armed_one_is_still_there() {
        let (r, _) = scripted_replug_wait(
            "/dev/hidraw3",
            &[&["/dev/hidraw3"], &["/dev/hidraw3", "/dev/hidraw9"]],
        );
        assert!(r.is_err());
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
            FACTORY_RESET_NOUN,
            FACTORY_RESET_RERUN,
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
            FACTORY_RESET_NOUN,
            FACTORY_RESET_RERUN,
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
        let action = factory_reset_action("OATH, OpenPGP, PIV, FIDO2");
        assert!(!action.contains("stays usable"), "{action}");
        assert!(!action.contains("stays fully usable"), "{action}");
        assert!(
            action.contains("each applet that completes comes back in factory condition"),
            "{action}"
        );
        assert!(
            action.contains("every step reports its own outcome"),
            "{action}"
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
    fn factory_reset_global_reset_credential_flags_parse_and_are_optional() {
        // Absent by default -- most devices never need a management-key
        // credential for PIV's reset at all.
        match parse(&["keyroostctl", "factory-reset", "--yes"])
            .unwrap()
            .command
        {
            Some(Cmd::FactoryReset { mgmt_key, pin, .. }) => {
                assert_eq!(mgmt_key, None);
                assert_eq!(pin, None);
            }
            _ => panic!("expected factory-reset"),
        }
        match parse(&[
            "keyroostctl",
            "factory-reset",
            "--yes",
            "--mgmt-key",
            "env:XAUTH",
        ])
        .unwrap()
        .command
        {
            Some(Cmd::FactoryReset { mgmt_key, .. }) => {
                assert_eq!(mgmt_key, Some(SecretSource::Env("XAUTH".into())))
            }
            _ => panic!("expected factory-reset"),
        }
        match parse(&["keyroostctl", "factory-reset", "--yes", "--pin", "env:GPIN"])
            .unwrap()
            .command
        {
            Some(Cmd::FactoryReset { pin, .. }) => {
                assert_eq!(pin, Some(SecretSource::Env("GPIN".into())))
            }
            _ => panic!("expected factory-reset"),
        }
        // The two credentials are one choice.
        assert!(parse(&[
            "keyroostctl",
            "factory-reset",
            "--yes",
            "--mgmt-key",
            "default",
            "--pin",
            "stdin",
        ])
        .is_err());
    }

    #[test]
    fn resolve_reset_cli_auth_errors_when_nothing_was_passed() {
        // No `Debug` on `ResetCliAuth` (it carries secret material — same
        // reason the GUI's analogous `PivMgmtAuth` skips it too), so match
        // rather than `.expect_err()`.
        use crate::secrets::fake::FakeIo;
        use keyroost_piv::compat::FeatureGate;
        let mut sec = Secrets::new(FakeIo::default());
        let input = read_reset_auth_input(&mut sec, None, None).unwrap();
        assert!(input.is_none());
        match resolve_reset_cli_auth(input.as_ref(), FeatureGate::Unsupported, None) {
            Ok(_) => panic!("no credential source was given"),
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("--mgmt-key env:NAME, stdin or default"),
                    "{msg}"
                );
                assert!(!msg.contains("--pin"), "{msg}");
            }
        }
        match resolve_reset_cli_auth(input.as_ref(), FeatureGate::Supported, None) {
            Ok(_) => panic!("no credential source was given"),
            Err(e) => {
                let msg = e.to_string();
                assert!(msg.contains("--mgmt-key env:NAME"), "{msg}");
                assert!(msg.contains("--pin env:NAME or stdin"), "{msg}");
                assert!(!msg.contains("unverified"), "{msg}");
            }
        }
        match resolve_reset_cli_auth(input.as_ref(), FeatureGate::Unverified, None) {
            Ok(_) => panic!("no credential source was given"),
            Err(e) => {
                let msg = e.to_string();
                assert!(msg.contains("--mgmt-key env:NAME"), "{msg}");
                assert!(msg.contains("--pin env:NAME or stdin"), "{msg}");
                assert!(msg.contains("unverified"), "{msg}");
            }
        }
    }

    #[test]
    fn reset_credentials_are_never_prompted_for() {
        // Optional, and of two possible kinds: with no flag, a terminal is
        // not asked for either.
        use crate::secrets::fake::FakeIo;
        let mut sec = Secrets::new(FakeIo::terminal());
        let input = read_reset_auth_input(&mut sec, None, None).unwrap();
        assert!(input.is_none());
        assert!(sec.io.prompts.is_empty());
        assert!(!sec.prompted());
    }

    #[test]
    fn reset_credentials_come_from_the_flag_given() {
        use crate::secrets::fake::FakeIo;
        use keyroost_piv::compat::FeatureGate;
        // Management key from env: hex, surrounding whitespace trimmed.
        let mut sec = Secrets::new(FakeIo::terminal().var("K", " 0102ff \n"));
        let input =
            read_reset_auth_input(&mut sec, Some(&SecretSource::Env("K".into())), None).unwrap();
        match resolve_reset_cli_auth(input.as_ref(), FeatureGate::Unsupported, None) {
            Ok(ResetCliAuth::Key(k)) => assert_eq!(&k[..], &[0x01, 0x02, 0xff]),
            _ => panic!("expected the management key"),
        }
        assert!(!sec.prompted());
        // PIN from piped stdin: kept exactly, line ending stripped.
        let mut sec = Secrets::new(FakeIo::piped(&["12 34\n"]));
        let input = read_reset_auth_input(&mut sec, None, Some(&SecretSource::Stdin)).unwrap();
        match resolve_reset_cli_auth(input.as_ref(), FeatureGate::Supported, None) {
            Ok(ResetCliAuth::Pin(p)) => assert_eq!(p.as_str(), "12 34"),
            _ => panic!("expected the PIN"),
        }
        assert!(!sec.prompted());
        // --mgmt-key default reads nothing; it resolves inside the session.
        let mut sec = Secrets::new(FakeIo::terminal());
        let input = read_reset_auth_input(&mut sec, Some(&SecretSource::Default), None).unwrap();
        assert!(matches!(input, Some(ResetAuthInput::Default)));
        assert!(sec.io.prompts.is_empty());
        // Unset env var names the flag, never the variable.
        let mut sec = Secrets::new(FakeIo::default());
        match read_reset_auth_input(&mut sec, None, Some(&SecretSource::Env("NOPE".into()))) {
            Ok(_) => panic!("the variable is unset"),
            Err(e) => {
                let msg = e.to_string();
                assert!(!msg.contains("NOPE") && msg.contains("--pin"), "{msg}");
            }
        }
        // Bad hex says so without echoing the input.
        let mut sec = Secrets::new(FakeIo::default().var("K", "zz"));
        match read_reset_auth_input(&mut sec, Some(&SecretSource::Env("K".into())), None) {
            Ok(_) => panic!("not hex"),
            Err(e) => assert!(e.to_string().contains("not valid hex"), "{e}"),
        }
    }

    #[test]
    fn reset_stdin_flag_at_a_terminal_reads_hidden_and_counts_as_prompted() {
        use crate::secrets::fake::FakeIo;
        let mut sec = Secrets::new(FakeIo::terminal().typing(&["0102"]));
        let input = read_reset_auth_input(&mut sec, Some(&SecretSource::Stdin), None).unwrap();
        match input {
            Some(ResetAuthInput::Key(k)) => assert_eq!(&k[..], &[0x01, 0x02]),
            _ => panic!("expected the management key"),
        }
        assert_eq!(sec.io.prompts.len(), 1);
        // The caller re-finds the key before opening it.
        assert!(sec.prompted());
    }

    #[test]
    fn factory_reset_global_reset_credential_flags_are_mutually_exclusive() {
        // --mgmt-key and --pin together must refuse -- only one credential
        // at a time.
        assert!(parse(&[
            "keyroostctl",
            "factory-reset",
            "--yes",
            "--mgmt-key",
            "env:XAUTH",
            "--pin",
            "env:GPIN",
        ])
        .is_err());
        assert!(parse(&[
            "keyroostctl",
            "factory-reset",
            "--yes",
            "--mgmt-key",
            "stdin",
            "--pin",
            "stdin",
        ])
        .is_err());
        assert!(parse(&[
            "keyroostctl",
            "factory-reset",
            "--yes",
            "--mgmt-key",
            "default",
            "--mgmt-key",
            "env:XAUTH",
        ])
        .is_err());
        assert!(parse(&[
            "keyroostctl",
            "factory-reset",
            "--yes",
            "--mgmt-key",
            "default",
            "--pin",
            "stdin",
        ])
        .is_err());
        match parse(&[
            "keyroostctl",
            "factory-reset",
            "--yes",
            "--mgmt-key",
            "default",
        ])
        .unwrap()
        .command
        {
            Some(Cmd::FactoryReset { mgmt_key, .. }) => {
                assert_eq!(mgmt_key, Some(SecretSource::Default))
            }
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
            "--seed",
            "stdin",
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
    fn oath_add_takes_seed_flags_not_secret() {
        match parse(&["keyroostctl", "oath", "add", "n", "--seed", "stdin"])
            .unwrap()
            .command
        {
            Some(Cmd::Oath {
                cmd: OathCmd::Add { seed, .. },
            }) => assert_eq!(seed, Some(SecretSource::Stdin)),
            _ => panic!("expected oath add"),
        }
        match parse(&["keyroostctl", "oath", "add", "n", "--seed", "env:V"])
            .unwrap()
            .command
        {
            Some(Cmd::Oath {
                cmd: OathCmd::Add { seed, .. },
            }) => assert_eq!(seed, Some(SecretSource::Env("V".into()))),
            _ => panic!("expected oath add"),
        }
        for old in ["--secret-stdin", "--secret-env"] {
            let e = parse(&["keyroostctl", "oath", "add", "n", old, "V"])
                .err()
                .unwrap();
            assert_eq!(e.kind(), clap::error::ErrorKind::UnknownArgument, "{old}");
        }
    }

    #[test]
    fn oath_two_secret_flags_name_their_stdin_line() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let oath = cmd.find_subcommand("oath").unwrap();
        for (sub, flag, line) in [
            ("password set", "password", "first line"),
            (
                "password set",
                "new-password",
                "second line when --password stdin is also given",
            ),
            ("add", "seed", "first line"),
            (
                "add",
                "password",
                "second line when --seed stdin is also given",
            ),
        ] {
            let arg = sub
                .split(' ')
                .fold(oath, |c, name| c.find_subcommand(name).unwrap())
                .get_arguments()
                .find(|a| a.get_long() == Some(flag))
                .unwrap_or_else(|| panic!("{sub} --{flag}"));
            let help = arg.get_help().map(|h| h.to_string()).unwrap_or_default();
            assert!(help.contains(line), "oath {sub} --{flag}: {help:?}");
        }
    }

    #[test]
    fn otp_change_pin_takes_old_and_new_pin_flags() {
        match parse(&[
            "keyroostctl",
            "otp",
            "pin",
            "change",
            "--pin",
            "env:A",
            "--new-pin",
            "stdin",
        ])
        .unwrap()
        .command
        {
            Some(Cmd::Otp {
                cmd:
                    OtpCmd::Pin {
                        cmd: OtpPinCmd::Change { pin, new_pin },
                    },
                ..
            }) => {
                assert_eq!(pin, Some(SecretSource::Env("A".into())));
                assert_eq!(new_pin, Some(SecretSource::Stdin));
            }
            _ => panic!("expected otp pin change"),
        }
        for old in [
            &["--current-env", "V"][..],
            &["--new-env", "V"][..],
            &["--pin-stdin"][..],
            &["--old-pin-env", "V"][..],
        ] {
            let mut argv = vec!["keyroostctl", "otp", "pin", "change"];
            argv.extend_from_slice(old);
            let e = parse(&argv).err().unwrap();
            assert_eq!(e.kind(), clap::error::ErrorKind::UnknownArgument, "{old:?}");
        }
        // One PIN, one source.
        assert!(parse(&[
            "keyroostctl",
            "otp",
            "pin",
            "change",
            "--pin",
            "env:A",
            "--pin",
            "stdin",
        ])
        .is_err());
    }

    #[test]
    fn openpgp_two_secret_flags_name_their_stdin_line() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let openpgp = cmd
            .find_subcommand("openpgp")
            .and_then(|c| c.find_subcommand("pin"))
            .unwrap();
        for (sub, flag, line) in [
            ("change", "pin", "first line"),
            (
                "change",
                "new-pin",
                "second line when --pin stdin is also given",
            ),
            ("unblock", "admin-pin", "first line"),
            (
                "unblock",
                "new-pin",
                "second line when --admin-pin stdin is also given",
            ),
        ] {
            let arg = openpgp
                .find_subcommand(sub)
                .unwrap()
                .get_arguments()
                .find(|a| a.get_long() == Some(flag))
                .unwrap_or_else(|| panic!("{sub} --{flag}"));
            let help = arg.get_help().map(|h| h.to_string()).unwrap_or_default();
            assert!(help.contains(line), "openpgp {sub} --{flag}: {help:?}");
        }
    }

    #[test]
    fn otp_two_secret_flags_name_their_stdin_line() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let otp = cmd.find_subcommand("otp").unwrap();
        for (sub, flag, line) in [
            ("pin change", "pin", "first line"),
            (
                "pin change",
                "new-pin",
                "second line when --pin stdin is also given",
            ),
            ("add", "seed", "first line"),
            ("add", "pin", "second line when --seed stdin is also given"),
        ] {
            let arg = sub
                .split(' ')
                .fold(otp, |c, name| c.find_subcommand(name).unwrap())
                .get_arguments()
                .find(|a| a.get_long() == Some(flag))
                .unwrap_or_else(|| panic!("{sub} --{flag}"));
            let help = arg.get_help().map(|h| h.to_string()).unwrap_or_default();
            assert!(help.contains(line), "otp {sub} --{flag}: {help:?}");
        }
    }

    #[test]
    fn otp_pin_is_asked_only_when_the_key_has_one() {
        use crate::secrets::fake::FakeIo;
        use crate::secrets::Secrets;
        // No PIN on the key: nothing is asked, even at a terminal.
        let mut sec = Secrets::new(FakeIo::terminal().typing(&["1234"]));
        assert!(otp_pin_after_probe(&mut sec, Ok::<_, String>(false))
            .unwrap()
            .is_none());
        assert!(sec.io.prompts.is_empty());
        // A PIN on the key: the hidden prompt, once.
        let mut sec = Secrets::new(FakeIo::terminal().typing(&["1234"]));
        let pin = otp_pin_after_probe(&mut sec, Ok::<_, String>(true)).unwrap();
        assert_eq!(pin.as_deref().map(String::as_str), Some("1234"));
        assert_eq!(sec.io.prompts, vec!["OTP PIN: ".to_string()]);
        // A PIN on the key and no terminal: refuse naming the flags.
        let mut sec = Secrets::new(FakeIo::default());
        let e = otp_pin_after_probe(&mut sec, Ok::<_, String>(true)).unwrap_err();
        assert!(e.contains("PIN-protected"), "{e}");
        assert!(e.contains("--pin env:NAME or --pin stdin"), "{e}");
    }

    #[test]
    fn otp_pin_probe_failure_is_never_taken_as_no_pin() {
        use crate::secrets::fake::FakeIo;
        use crate::secrets::Secrets;
        // At a terminal: ask rather than carry on without a PIN.
        let mut sec = Secrets::new(FakeIo::terminal().typing(&["1234"]));
        let pin = otp_pin_after_probe(&mut sec, Err("read failed")).unwrap();
        assert_eq!(pin.as_deref().map(String::as_str), Some("1234"));
        // Without one: refuse, naming the probe failure and the flags.
        let mut sec = Secrets::new(FakeIo::default());
        let e = otp_pin_after_probe(&mut sec, Err("read failed")).unwrap_err();
        assert!(e.contains("read failed"), "{e}");
        assert!(e.contains("--pin env:NAME or --pin stdin"), "{e}");
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
        // clap_complete's static generator Debug shape.
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
    fn closed_pipe_error_detection() {
        use clap::error::ErrorKind;
        let io = |msg: &str| clap::Error::raw(ErrorKind::Io, msg);
        // What the completion engine's error reads as on a closed stdout pipe.
        assert!(is_closed_pipe_error(&io("Broken pipe (os error 32)")));
        assert!(is_closed_pipe_error(&io("Rohrbruch (os error 32)")));
        // Windows' closed-pipe codes count only on Windows.
        assert_eq!(
            is_closed_pipe_error(&io("The pipe is being closed. (os error 232)")),
            cfg!(windows)
        );
        assert_eq!(
            is_closed_pipe_error(&io("The pipe has been ended. (os error 109)")),
            cfg!(windows)
        );
        // Other completion failures still surface.
        assert!(!is_closed_pipe_error(&io(
            "unknown shell `tcsh`, expected one of bash, elvish, fish, powershell, zsh"
        )));
        // Only I/O errors count, whatever their text says.
        assert!(!is_closed_pipe_error(&clap::Error::raw(
            ErrorKind::InvalidValue,
            "Broken pipe (os error 32)"
        )));
    }

    #[test]
    fn clap_command_is_valid() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    /// Exactly five short flags, each with one meaning, and every one of
    /// the five long flags has its short wherever it appears.
    #[test]
    fn short_flags_are_the_five_and_mean_one_thing() {
        const SHORTS: [(char, &str); 5] = [
            ('d', "device"),
            ('y', "yes"),
            ('o', "out"),
            ('i', "in"),
            ('s', "slot"),
        ];
        for (path, cmd) in all_commands() {
            let mut seen = std::collections::BTreeSet::new();
            for a in cmd.get_arguments() {
                if matches!(a.get_id().as_str(), "help" | "version") {
                    continue;
                }
                if let Some(s) = a.get_short() {
                    let (_, long) = SHORTS
                        .iter()
                        .find(|(c, _)| *c == s)
                        .unwrap_or_else(|| panic!("{path}: -{s} is not one of the five"));
                    assert_eq!(a.get_long(), Some(*long), "{path}: -{s} means --{long}");
                    assert!(seen.insert(s), "{path}: -{s} twice");
                }
                if let Some((c, _)) = SHORTS.iter().find(|(_, l)| a.get_long() == Some(l)) {
                    assert_eq!(
                        a.get_short(),
                        Some(*c),
                        "{path}: --{} has no -{c}",
                        a.get_long().unwrap()
                    );
                }
            }
        }
    }

    #[test]
    fn short_flags_parse() {
        for a in [
            &["keyroostctl", "-d", "yubi-test", "piv", "info"][..],
            &[
                "keyroostctl",
                "piv",
                "cert",
                "export",
                "-s",
                "9a",
                "-o",
                "c.pem",
            ],
            &[
                "keyroostctl",
                "piv",
                "cert",
                "import",
                "-s",
                "9a",
                "-i",
                "c.der",
                "-y",
            ],
            &[
                "keyroostctl",
                "molto",
                "seed",
                "-s",
                "1",
                "--seed",
                "stdin",
                "-y",
            ],
            &[
                "keyroostctl",
                "piv",
                "key",
                "generate",
                "-s",
                "9a",
                "-o",
                "p.pem",
            ],
        ] {
            assert!(parse(a).is_ok(), "{a:?}");
        }
    }

    /// A retired-name message that spells a flag as `-x/--long` names a
    /// short that exists: every `--long` in the tree has `-x`. Only the
    /// retired flag a row is about may be missing from the tree.
    #[test]
    fn retired_messages_name_real_short_flags() {
        let all = all_commands();
        let check = |msg: &str, retired: Option<&str>| {
            let b = msg.as_bytes();
            for i in 0..b.len().saturating_sub(4) {
                let starts = i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'-');
                if !(starts
                    && b[i] == b'-'
                    && b[i + 1].is_ascii_alphabetic()
                    && msg[i + 2..].starts_with("/--"))
                {
                    continue;
                }
                let c = b[i + 1] as char;
                let long: String = msg[i + 5..]
                    .chars()
                    .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '-')
                    .collect();
                let args: Vec<clap::Arg> = all
                    .iter()
                    .flat_map(|(_, cmd)| cmd.get_arguments().cloned().collect::<Vec<_>>())
                    .filter(|a| a.get_long() == Some(long.as_str()))
                    .collect();
                if args.is_empty() {
                    assert!(
                        retired.is_some_and(|f| f == format!("-{c}") || f == format!("--{long}")),
                        "{msg:?}: --{long} is in no command"
                    );
                    continue;
                }
                for a in args {
                    assert_eq!(a.get_short(), Some(c), "{msg:?}: --{long} has no -{c}");
                }
            }
        };
        for r in RETIRED_FLAGS {
            check(r.msg, Some(r.flag));
        }
        for r in RETIRED_COMMANDS {
            check(r.new, None);
            check(r.note, None);
        }
        // The positional messages built in `redacted_parse_error`.
        for a in [
            &["keyroostctl", "fido", "blob", "export", "0", "out.bin"][..],
            &["keyroostctl", "molto", "import", "--slot", "1", "-"],
        ] {
            let argv: Vec<String> = a.iter().map(|s| s.to_string()).collect();
            let e = parse(a).err().expect("refused");
            let msg = redacted_parse_error(&e, &argv).expect("a message");
            check(&msg, None);
        }
    }

    #[cfg(unix)]
    #[test]
    fn write_private_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let mut path = std::env::temp_dir();
        path.push(format!("keyroost_priv_{}", std::process::id()));

        use crate::prompt::OutMode;
        // Fresh file is created 0600.
        write_private_file(&path, b"secret plaintext", OutMode::New).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "fresh file should be 0600");

        // A file that appeared after the check is not replaced in New mode.
        let err = write_private_file(&path, b"other", OutMode::New).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(err.to_string().contains("--overwrite"), "{err}");
        assert_eq!(std::fs::read(&path).unwrap(), b"secret plaintext");

        // Loosen perms, then re-write: the helper must tighten back to 0600.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_private_file(&path, b"new secret", OutMode::Replace).unwrap();
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

        for mode in [crate::prompt::OutMode::New, crate::prompt::OutMode::Replace] {
            let err = write_private_file(&link, b"top secret plaintext", mode).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        }

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
    fn otp_target_for_binds_selected_device_or_fails_closed() {
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
        let devices = [a, b];

        // Auto on a dual-interface key -> the SELECTED device's own HID path
        // with ITS OWN reader kept as an open-time fallback (#82: some
        // firmware botches the HID probe while CCID works), never another
        // device's.
        match otp_target_for(&devices[1], OtpTransportArg::Auto) {
            Ok(OtpTarget::HidThenReader(p, r)) => {
                assert_eq!(p, std::path::PathBuf::from("/dev/hidraw1"));
                assert_eq!(r, "Token2 B 00 00");
            }
            other => panic!("expected keyB HID path + reader fallback, got {other:?}"),
        }

        // Auto on a HID-only key -> a plain HID target.
        let hid_only = otp_dev("solo", Some("/dev/hidraw7"), None);
        match otp_target_for(&hid_only, OtpTransportArg::Auto) {
            Ok(OtpTarget::HidPath(p)) => assert_eq!(p, std::path::PathBuf::from("/dev/hidraw7")),
            other => panic!("expected plain HID target, got {other:?}"),
        }

        // Ccid -> that device's reader.
        match otp_target_for(&devices[0], OtpTransportArg::Ccid) {
            Ok(OtpTarget::Reader(r)) => assert_eq!(r, "Token2 A 00 00"),
            other => panic!("expected keyA reader, got {other:?}"),
        }

        // Transport a device can't satisfy -> error (no HID interface for --transport hid).
        let ccid_only = otp_dev("nfc", None, Some("ACS reader 00"));
        assert!(otp_target_for(&ccid_only, OtpTransportArg::Hid).is_err());
    }

    #[test]
    fn otp_target_for_maps_a_synthetic_reader_only_row_under_auto() {
        // `target::select` turns an unmatched --reader/--path into a synthetic
        // row carrying only that endpoint (see target.rs's `typed_device`);
        // `otp_target_for` must map it like any other reader-only device.
        use keyroost_resolve::{Caps, Device, DeviceKind};

        let row = Device {
            id: "override:Some Reader".into(),
            name: None,
            vendor: String::new(),
            model: "key not detected".into(),
            serial: String::new(),
            transport: String::new(),
            firmware: String::new(),
            caps: Caps::default(),
            unverified: Caps::default(),
            kind: DeviceKind::Key,
            hid_path: None,
            reader: Some("Some Reader".to_string()),
        };
        match otp_target_for(&row, OtpTransportArg::Auto) {
            Ok(OtpTarget::Reader(r)) => assert_eq!(r, "Some Reader"),
            other => {
                panic!("expected a Reader target for a synthetic reader-only row, got {other:?}")
            }
        }
    }

    #[test]
    fn otp_takes_reader_and_path_and_needs_follow_transport() {
        assert!(parse(&["keyroostctl", "otp", "--reader", "Token2", "list"]).is_ok());
        assert!(parse(&["keyroostctl", "otp", "list", "--path", "/dev/hidraw3"]).is_ok());
        assert_eq!(otp_need(OtpTransportArg::Hid), Need::OtpHid);
        assert_eq!(otp_need(OtpTransportArg::Ccid), Need::OtpCcid);
        assert_eq!(otp_need(OtpTransportArg::Auto), Need::Otp);
    }

    #[test]
    fn molto_takes_a_reader_selector() {
        match parse(&["keyroostctl", "molto", "--reader", "Molto2 (B", "info"])
            .unwrap()
            .command
        {
            Some(Cmd::Molto { reader, .. }) => assert_eq!(reader.as_deref(), Some("Molto2 (B")),
            _ => panic!("expected molto"),
        }
        assert!(
            parse(&["keyroostctl", "molto", "info", "--reader", "x"]).is_ok(),
            "global within the group"
        );
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
    fn fido_nests_by_topic() {
        for a in [
            &["keyroostctl", "fido", "pin", "retries"][..],
            &["keyroostctl", "fido", "pin", "set"],
            &["keyroostctl", "fido", "pin", "change"],
            &["keyroostctl", "fido", "pin", "min-length", "--length", "8"],
            &["keyroostctl", "fido", "pin", "force-change"],
            &["keyroostctl", "fido", "credential", "list"],
            &["keyroostctl", "fido", "credential", "metadata"],
            &["keyroostctl", "fido", "credential", "delete", "--id", "00"],
            &["keyroostctl", "fido", "fingerprint", "list"],
            &["keyroostctl", "fido", "fingerprint", "add"],
            &[
                "keyroostctl",
                "fido",
                "fingerprint",
                "rename",
                "--id",
                "00",
                "--name",
                "x",
            ],
            &["keyroostctl", "fido", "fingerprint", "delete", "--id", "00"],
            &["keyroostctl", "fido", "config", "always-uv", "enable"],
            &["keyroostctl", "fido", "config", "always-uv", "disable"],
            &["keyroostctl", "fido", "config", "attestation", "enable"],
            &["keyroostctl", "fido", "blob", "list"],
            &["keyroostctl", "fido", "blob", "export", "0", "--out", "f"],
            &["keyroostctl", "fido", "ssh", "list"],
            &["keyroostctl", "fido", "ssh", "extract", "--id", "ssh:demo"],
            &["keyroostctl", "name", "list"],
            &["keyroostctl", "name", "delete", "x"],
        ] {
            assert!(parse(a).is_ok(), "{a:?}");
        }
    }

    #[test]
    fn openpgp_nests_by_topic_and_admin_selects_pw3() {
        for a in [
            &["keyroostctl", "openpgp", "pin", "verify"][..],
            &["keyroostctl", "openpgp", "pin", "verify", "--admin"],
            &["keyroostctl", "openpgp", "pin", "change", "--admin"],
            &["keyroostctl", "openpgp", "pin", "unblock"],
            &[
                "keyroostctl",
                "openpgp",
                "key",
                "generate",
                "--slot",
                "sign",
            ],
            &[
                "keyroostctl",
                "openpgp",
                "key",
                "import",
                "--generate",
                "--slot",
                "sign",
            ],
            &["keyroostctl", "openpgp", "key", "show", "--slot", "sign"],
            &["keyroostctl", "openpgp", "key", "algorithms"],
            &["keyroostctl", "openpgp", "name", "set", "x"],
            &[
                "keyroostctl",
                "openpgp",
                "url",
                "set",
                "https://example.invalid/k.asc",
            ],
        ] {
            assert!(parse(a).is_ok(), "{a:?}");
        }
        assert!(matches!(pin_kind(true), OpenpgpPinKind::Admin));
        assert!(matches!(pin_kind(false), OpenpgpPinKind::User));
        // Commands that only ever check PW3 take --admin-pin, never --pin.
        for p in [
            &["openpgp", "pin", "unblock"][..],
            &["openpgp", "name", "set"],
            &["openpgp", "url", "set"],
            &["openpgp", "key", "generate"],
            &["openpgp", "key", "import"],
        ] {
            let c = find(p);
            assert!(
                c.get_arguments().any(|a| a.get_long() == Some("admin-pin")),
                "{p:?}"
            );
            assert!(
                !c.get_arguments().any(|a| a.get_long() == Some("pin")),
                "{p:?}"
            );
        }
    }

    #[test]
    fn oath_otp_molto_nest_by_topic() {
        for a in [
            &["keyroostctl", "oath", "password", "set"][..],
            &["keyroostctl", "oath", "password", "clear"],
            &["keyroostctl", "otp", "pin", "set"],
            &["keyroostctl", "otp", "pin", "change"],
            &["keyroostctl", "otp", "pin", "clear"],
            &["keyroostctl", "otp", "pin", "status"],
            &["keyroostctl", "otp", "pin", "verify"],
            &["keyroostctl", "otp", "fingerprint", "status"],
            &["keyroostctl", "otp", "fingerprint", "enable"],
            &["keyroostctl", "otp", "fingerprint", "disable"],
            &["keyroostctl", "otp", "button", "set"],
            &["keyroostctl", "otp", "button", "delete"],
            &["keyroostctl", "molto", "sync", "--slot", "1"],
            &[
                "keyroostctl",
                "molto",
                "import",
                "--slot",
                "1",
                "--uri",
                "stdin",
            ],
            &["keyroostctl", "molto", "import", "--file", "v.json"],
            &[
                "keyroostctl",
                "molto",
                "import",
                "--file",
                "v.json",
                "--slot",
                "5",
                "--dry-run",
                "--password",
                "stdin",
            ],
        ] {
            assert!(parse(a).is_ok(), "{a:?}");
        }
        for bad in [
            // --slot is required without --file
            &["keyroostctl", "molto", "import", "--uri", "stdin"][..],
            &[
                "keyroostctl",
                "molto",
                "import",
                "--slot",
                "1",
                "--uri",
                "stdin",
                "--file",
                "v.json",
            ],
            // --dry-run needs --file
            &["keyroostctl", "molto", "import", "--slot", "1", "--dry-run"],
            // --password is for an encrypted --file; --qr is one URI
            &[
                "keyroostctl",
                "molto",
                "import",
                "--slot",
                "1",
                "--password",
                "stdin",
            ],
            &[
                "keyroostctl",
                "molto",
                "import",
                "--file",
                "v.json",
                "--qr",
                "x.png",
            ],
            &[
                "keyroostctl",
                "molto",
                "import",
                "--file",
                "v.json",
                "--title",
                "x",
            ],
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn piv_nests_by_topic() {
        for a in [
            &["keyroostctl", "piv", "pin", "change"][..],
            &["keyroostctl", "piv", "pin", "unblock"],
            &["keyroostctl", "piv", "puk", "change"],
            &[
                "keyroostctl",
                "piv",
                "retries",
                "set",
                "--pin-tries",
                "3",
                "--puk-tries",
                "3",
            ],
            &[
                "keyroostctl",
                "piv",
                "mgmt-key",
                "change",
                "--algorithm",
                "aes192",
            ],
            &[
                "keyroostctl",
                "piv",
                "key",
                "generate",
                "--slot",
                "9a",
                "--out",
                "p.pem",
            ],
            &["keyroostctl", "piv", "key", "delete", "--slot", "9a"],
            &[
                "keyroostctl",
                "piv",
                "key",
                "move",
                "--from",
                "9a",
                "--to",
                "9c",
            ],
            &[
                "keyroostctl",
                "piv",
                "cert",
                "import",
                "--slot",
                "9a",
                "--in",
                "c.der",
            ],
            &[
                "keyroostctl",
                "piv",
                "cert",
                "export",
                "--slot",
                "9a",
                "--out",
                "c.pem",
            ],
            &[
                "keyroostctl",
                "piv",
                "cert",
                "request",
                "--slot",
                "9a",
                "--subject",
                "CN=x",
                "--generate-key",
                "--pubkey-out",
                "p.pem",
            ],
            &[
                "keyroostctl",
                "piv",
                "cert",
                "request",
                "--slot",
                "9a",
                "--subject",
                "CN=x",
                "--pubkey-in",
                "p.pem",
            ],
            &[
                "keyroostctl",
                "piv",
                "cert",
                "generate",
                "--slot",
                "9a",
                "--subject",
                "CN=x",
            ],
            &["keyroostctl", "piv", "cert", "delete", "--slot", "9a"],
            &["keyroostctl", "piv", "chuid", "generate"],
        ] {
            assert!(parse(a).is_ok(), "{a:?}");
        }
        assert!(
            parse(&[
                "keyroostctl",
                "piv",
                "cert",
                "request",
                "--slot",
                "9a",
                "--subject",
                "CN=x",
                "--pubkey-out",
                "p.pem"
            ])
            .is_err(),
            "--pubkey-out needs --generate-key"
        );
    }

    #[test]
    fn fido_is_nested() {
        assert!(parse(&["keyroostctl", "fido", "info"]).is_ok());
        assert!(parse(&["keyroostctl", "fido", "pin", "set", "--new-pin", "stdin"]).is_ok());
        assert!(parse(&["keyroostctl", "fido", "credential", "list"]).is_ok());
        assert!(parse(&["keyroostctl", "fido-info"]).is_err());
        assert!(parse(&["keyroostctl", "fido-creds-list"]).is_err());
    }

    #[test]
    fn openpgp_pin_commands_parse() {
        assert!(Cli::try_parse_from([
            "keyroostctl",
            "openpgp",
            "pin",
            "change",
            "--pin",
            "stdin",
            "--new-pin",
            "stdin"
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "keyroostctl",
            "openpgp",
            "pin",
            "change",
            "--admin",
            "--pin",
            "stdin",
            "--new-pin",
            "stdin"
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "keyroostctl",
            "openpgp",
            "pin",
            "unblock",
            "--admin-pin",
            "stdin",
            "--new-pin",
            "stdin"
        ])
        .is_ok());
    }

    #[test]
    fn openpgp_pin_verify_takes_admin_not_a_pin_kind() {
        match parse(&[
            "keyroostctl",
            "openpgp",
            "pin",
            "verify",
            "--admin",
            "--pin",
            "stdin",
        ])
        .unwrap()
        .command
        {
            Some(Cmd::Openpgp {
                cmd:
                    OpenpgpCmd::Pin {
                        cmd: OpenpgpPinCmd::Verify { admin, pin, .. },
                    },
            }) => assert!(admin && pin == Some(SecretSource::Stdin)),
            _ => panic!("expected openpgp pin verify"),
        }
        // `--pin admin` (which PIN, in older releases) is now a literal
        // given to the PIN's source flag, refused like any other.
        let e = parse(&["keyroostctl", "openpgp", "pin", "verify", "--pin", "admin"])
            .err()
            .unwrap();
        assert_eq!(e.kind(), clap::error::ErrorKind::ValueValidation);
    }

    #[test]
    fn openpgp_generate_key_algorithm_is_optional_and_named_like_gpg() {
        // No --algorithm: None — generate whatever the slot's attributes say
        // (the pre-#106 behavior, unchanged for scripts).
        match parse(&["keyroostctl", "openpgp", "key", "generate", "--yes"])
            .unwrap()
            .command
        {
            Some(Cmd::Openpgp {
                cmd:
                    OpenpgpCmd::Key {
                        cmd: OpenpgpKeyCmd::Generate { algorithm, .. },
                    },
            }) => assert!(algorithm.is_none()),
            _ => panic!("expected openpgp key generate"),
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
                "key",
                "generate",
                "--yes",
                "--algorithm",
                name,
            ])
            .unwrap()
            .command
            {
                Some(Cmd::Openpgp {
                    cmd:
                        OpenpgpCmd::Key {
                            cmd:
                                OpenpgpKeyCmd::Generate {
                                    algorithm: Some(a), ..
                                },
                        },
                }) => assert_eq!(a.to_alg(), want, "{name}"),
                _ => panic!("expected openpgp key generate --algorithm {name}"),
            }
        }
        assert!(parse(&["keyroostctl", "openpgp", "key", "algorithms"]).is_ok());
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
    fn molto_help_says_slot() {
        use clap::CommandFactory;
        fn texts(c: &clap::Command, out: &mut Vec<String>) {
            out.extend(c.get_about().map(|s| s.to_string()));
            out.extend(c.get_long_about().map(|s| s.to_string()));
            for a in c.get_arguments() {
                out.extend(a.get_help().map(|s| s.to_string()));
                out.extend(a.get_long_help().map(|s| s.to_string()));
            }
            for s in c.get_subcommands() {
                texts(s, out);
            }
        }
        let root = Cli::command();
        let mut all = Vec::new();
        texts(root.find_subcommand("molto").unwrap(), &mut all);
        for t in all {
            let t = t
                .replace("Token2 calls these profiles", "")
                .replace("Token2 calls slots profiles", "");
            assert!(!t.to_lowercase().contains("profile"), "{t}");
        }
    }

    #[test]
    fn molto_is_nested() {
        assert!(parse(&["keyroostctl", "molto", "info"]).is_ok());
        assert!(parse(&[
            "keyroostctl",
            "molto",
            "seed",
            "--slot",
            "0",
            "--seed",
            "stdin"
        ])
        .is_ok());
        assert!(parse(&["keyroostctl", "molto", "reset", "--yes"]).is_ok());
        assert!(parse(&["keyroostctl", "molto", "probe", "--yes"]).is_ok());
        assert!(parse(&["keyroostctl", "set-seed", "--profile", "0", "--hex-stdin"]).is_err());
        assert!(parse(&["keyroostctl", "molto", "info", "--customer-key", "env:K"]).is_ok());
    }

    #[test]
    fn otp_unlock_conflict_only_flags_a_pin_with_fingerprint() {
        for (args, conflict) in [
            (&["keyroostctl", "otp", "list"][..], false),
            (&["keyroostctl", "otp", "list", "--pin", "env:V"], false),
            (
                &[
                    "keyroostctl",
                    "otp",
                    "list",
                    "--unlock",
                    "auto",
                    "--pin",
                    "stdin",
                ],
                false,
            ),
            (
                &["keyroostctl", "otp", "list", "--unlock", "fingerprint"],
                false,
            ),
            (
                &[
                    "keyroostctl",
                    "otp",
                    "list",
                    "--unlock",
                    "fingerprint",
                    "--pin",
                    "env:V",
                ],
                true,
            ),
            (
                &[
                    "keyroostctl",
                    "otp",
                    "list",
                    "--unlock",
                    "fingerprint",
                    "--pin",
                    "stdin",
                ],
                true,
            ),
            (&["keyroostctl", "piv", "info"], false),
        ] {
            let cli = parse(args).unwrap();
            assert_eq!(
                otp_unlock_conflict(cli.command.as_ref()).is_some(),
                conflict,
                "{args:?}"
            );
        }
    }

    #[test]
    fn info_and_otp_names_parse() {
        for a in [
            &["keyroostctl", "piv", "info"][..],
            &["keyroostctl", "openpgp", "info"],
            &["keyroostctl", "otp", "info"],
            &["keyroostctl", "otp", "code", "--account", "a"],
            &["keyroostctl", "otp", "button", "set"],
            &["keyroostctl", "otp", "reset"],
            &["keyroostctl", "otp", "pin", "clear"],
            &["keyroostctl", "otp", "fingerprint", "status"],
            &["keyroostctl", "otp", "fingerprint", "enable"],
            &["keyroostctl", "otp", "fingerprint", "disable"],
            &["keyroostctl", "otp", "pin", "set", "--new-pin", "env:V"],
        ] {
            assert!(parse(a).is_ok(), "{a:?}");
        }
        let unlock_of = |a: &[&str]| match parse(a).unwrap().command {
            Some(Cmd::Otp {
                cmd: OtpCmd::List { unlock, .. },
                ..
            }) => unlock,
            _ => panic!("not otp list"),
        };
        assert_eq!(unlock_of(&["keyroostctl", "otp", "list"]), OtpUnlock::Pin);
        assert_eq!(
            unlock_of(&["keyroostctl", "otp", "list", "--unlock", "fingerprint"]),
            OtpUnlock::Fingerprint
        );
        assert_eq!(
            unlock_of(&["keyroostctl", "otp", "list", "--unlock", "auto"]),
            OtpUnlock::Auto
        );
    }

    #[test]
    fn name_is_accepted_on_every_group() {
        for g in [
            &["keyroostctl", "--device", "k", "piv", "info"][..],
            &["keyroostctl", "--device", "k", "oath", "list"][..],
            &["keyroostctl", "--device", "k", "openpgp", "info"][..],
            &["keyroostctl", "--device", "k", "otp", "list"][..],
            &["keyroostctl", "--device", "k", "molto", "info"][..],
            &["keyroostctl", "--device", "k", "fido", "info"][..],
        ] {
            assert!(parse(g).is_ok(), "should parse: {:?}", g);
        }
    }

    #[test]
    fn range_checks_are_usage_errors_from_clap() {
        use clap::error::ErrorKind;
        for argv in [
            &["keyroostctl", "oath", "add", "x", "--digits", "9"][..],
            &[
                "keyroostctl",
                "otp",
                "add",
                "--app",
                "a",
                "--account",
                "b",
                "--digits",
                "11",
            ],
            &["keyroostctl", "otp", "button", "set", "--digits", "7"],
            &[
                "keyroostctl",
                "piv",
                "retries",
                "set",
                "--pin-tries",
                "0",
                "--puk-tries",
                "3",
            ],
            &["keyroostctl", "molto", "title", "--slot", "100"],
            &[
                "keyroostctl",
                "molto",
                "title",
                "--slot",
                "1",
                "THIRTEEN-LONG",
            ],
            &["keyroostctl", "piv", "chuid", "generate", "--guid", "zz"],
            &["keyroostctl", "fido", "credential", "delete", "--id", "xyz"],
        ] {
            let e = Cli::try_parse_from(argv)
                .err()
                .unwrap_or_else(|| panic!("{argv:?} parsed"));
            assert_eq!(e.kind(), ErrorKind::ValueValidation, "{argv:?}: {e}");
            assert_eq!(e.exit_code(), 2);
        }
    }

    #[test]
    fn json_flag_parses_globally() {
        assert!(parse(&["keyroostctl", "--json", "piv", "info"]).is_ok());
        assert!(parse(&["keyroostctl", "--json", "fido", "info"]).is_ok());
        assert!(parse(&["keyroostctl", "--json", "molto", "info"]).is_ok());
        // Position-insensitive: --json after the subcommand also works (global).
        assert!(parse(&["keyroostctl", "piv", "info", "--json"]).is_ok());
    }

    fn argv(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    /// `--file` is only hinted on the piv commands that had it; other piv
    /// commands never took it and have no --out to point at.
    #[test]
    fn piv_file_hint_only_where_file_was() {
        let hint = |cmd: &str| {
            retired_flag_hint(
                "--file",
                &argv(
                    &["keyroostctl", "piv"]
                        .into_iter()
                        .chain(cmd.split(' '))
                        .chain(["--slot", "9a", "--file", "x"])
                        .collect::<Vec<_>>(),
                ),
            )
        };
        assert!(hint("cert import").unwrap().contains("--in"));
        for cmd in ["cert export", "cert request", "cert generate"] {
            assert!(hint(cmd).unwrap().contains("--out"), "{cmd}");
        }
        for cmd in ["key generate", "test", "info"] {
            assert_eq!(hint(cmd), None, "{cmd}");
        }
    }

    #[test]
    fn retired_command_hint_skips_flag_values() {
        let want = "`keyroostctl fido pin-set` is now `keyroostctl fido pin set`";
        for a in [
            &["keyroostctl", "fido", "pin-set", "x"][..],
            &["keyroostctl", "--json", "fido", "pin-set", "x"],
            // The value of --device is a word that is no command here, and
            // must be skipped.
            &["keyroostctl", "--device", "pin", "fido", "pin-set", "x"],
            &["keyroostctl", "--device=pin", "fido", "pin-set"],
        ] {
            assert_eq!(
                retired_command_hint("pin-set", &argv(a)).as_deref(),
                Some(want),
                "{a:?}"
            );
        }
        // Same word under another parent is not this row.
        assert_eq!(
            retired_command_hint("pin-set", &argv(&["keyroostctl", "pin-set"])),
            None
        );
        assert_eq!(
            retired_command_hint("pin-set", &argv(&["keyroostctl", "oath", "pin-set"])),
            None
        );
    }

    #[test]
    fn retired_rows_point_at_real_commands() {
        use clap::CommandFactory;
        let mut root = Cli::command();
        root.build();
        let descend = |path: &str| -> Option<&clap::Command> {
            let mut c = &root;
            for w in path.split(' ').filter(|w| !w.is_empty()) {
                c = c.find_subcommand(w)?;
            }
            Some(c)
        };
        for r in RETIRED_COMMANDS {
            let parent =
                descend(r.parent).unwrap_or_else(|| panic!("parent `{}` is gone", r.parent));
            assert!(
                parent.find_subcommand(r.old).is_none(),
                "`{} {}` still parses",
                r.parent,
                r.old
            );
            let mut c = &root;
            let mut in_flags = false;
            for w in r.new.split(' ') {
                if let Some(flag) = w.strip_prefix("--") {
                    in_flags = true;
                    assert!(
                        c.get_arguments().any(|a| a.get_long() == Some(flag)),
                        "`{}`: no --{flag}",
                        r.new
                    );
                } else if !in_flags {
                    c = c
                        .find_subcommand(w)
                        .unwrap_or_else(|| panic!("`{}`: no `{w}`", r.new));
                }
            }
        }
    }

    #[test]
    fn piv_move_notes_a_destination_it_cannot_read() {
        use keyroost_transport::SlotKeyPresence as K;
        assert_eq!(
            piv_move_dest_note(K::Unknown, "9a").as_deref(),
            Some("keyroost can't tell whether 9a holds a key; the card decides")
        );
        assert_eq!(piv_move_dest_note(K::Present, "9a"), None);
        assert_eq!(piv_move_dest_note(K::NoKey, "9a"), None);
    }

    #[test]
    fn piv_move_key_parses_standard_and_retired_slots() {
        match parse(&[
            "keyroostctl",
            "piv",
            "key",
            "move",
            "--from",
            "9d",
            "--to",
            "82",
        ])
        .unwrap()
        .command
        {
            Some(Cmd::Piv {
                cmd:
                    PivCmd::Key {
                        cmd:
                            PivKeyCmd::Move {
                                from, to, force, ..
                            },
                    },
            }) => {
                assert_eq!(from.to_slot().key_ref(), 0x9D);
                assert_eq!(to.to_slot().key_ref(), 0x82);
                // --force is opt-in; absent here.
                assert!(!force);
            }
            _ => panic!("expected piv key move"),
        }
    }

    #[test]
    fn piv_test_parses_slot_and_optional_pin() {
        // No PIN source — valid (PIN-never slots).
        match parse(&["keyroostctl", "piv", "test", "--slot", "9e"])
            .unwrap()
            .command
        {
            Some(Cmd::Piv {
                cmd: PivCmd::Test { slot, pin, .. },
            }) => {
                assert_eq!(slot.to_slot().key_ref(), 0x9E);
                assert!(pin.is_none());
            }
            _ => panic!("expected piv test"),
        }
        match parse(&[
            "keyroostctl",
            "piv",
            "test",
            "--slot",
            "9a",
            "--pin",
            "env:KR_PIN",
        ])
        .unwrap()
        .command
        {
            Some(Cmd::Piv {
                cmd: PivCmd::Test { pin, .. },
            }) => assert_eq!(pin, Some(SecretSource::Env("KR_PIN".into()))),
            _ => panic!("expected piv test"),
        }
    }

    #[test]
    fn piv_key_ops_take_force_flag() {
        match parse(&[
            "keyroostctl",
            "piv",
            "key",
            "move",
            "--from",
            "9d",
            "--to",
            "82",
            "--force",
        ])
        .unwrap()
        .command
        {
            Some(Cmd::Piv {
                cmd:
                    PivCmd::Key {
                        cmd: PivKeyCmd::Move { force, .. },
                    },
            }) => assert!(force),
            _ => panic!("expected piv key move"),
        }
        match parse(&[
            "keyroostctl",
            "piv",
            "key",
            "delete",
            "--slot",
            "9a",
            "--yes",
            "--force",
        ])
        .unwrap()
        .command
        {
            Some(Cmd::Piv {
                cmd:
                    PivCmd::Key {
                        cmd: PivKeyCmd::Delete { force, yes, .. },
                    },
            }) => {
                assert!(force);
                assert!(yes);
            }
            _ => panic!("expected piv key delete"),
        }
        match parse(&["keyroostctl", "piv", "reset", "--yes", "--force"])
            .unwrap()
            .command
        {
            Some(Cmd::Piv {
                cmd: PivCmd::Reset { force, yes, .. },
            }) => {
                assert!(force);
                assert!(yes);
            }
            _ => panic!("expected piv reset"),
        }
    }

    #[test]
    fn piv_reset_credential_flags_parse_and_are_optional() {
        // Absent by default -- most devices' RESET never needs a
        // management-key credential at all.
        match parse(&["keyroostctl", "piv", "reset", "--yes"])
            .unwrap()
            .command
        {
            Some(Cmd::Piv {
                cmd: PivCmd::Reset { mgmt_key, pin, .. },
            }) => {
                assert_eq!(mgmt_key, None);
                assert_eq!(pin, None);
            }
            _ => panic!("expected piv reset"),
        }
        match parse(&[
            "keyroostctl",
            "piv",
            "reset",
            "--yes",
            "--mgmt-key",
            "env:XAUTH",
        ])
        .unwrap()
        .command
        {
            Some(Cmd::Piv {
                cmd: PivCmd::Reset { mgmt_key, .. },
            }) => assert_eq!(mgmt_key, Some(SecretSource::Env("XAUTH".into()))),
            _ => panic!("expected piv reset"),
        }
        match parse(&["keyroostctl", "piv", "reset", "--yes", "--pin", "env:GPIN"])
            .unwrap()
            .command
        {
            Some(Cmd::Piv {
                cmd: PivCmd::Reset { pin, .. },
            }) => assert_eq!(pin, Some(SecretSource::Env("GPIN".into()))),
            _ => panic!("expected piv reset"),
        }
    }

    #[test]
    fn piv_reset_credential_flags_are_mutually_exclusive() {
        // --mgmt-key and --pin together must refuse -- only one credential
        // at a time.
        assert!(parse(&[
            "keyroostctl",
            "piv",
            "reset",
            "--yes",
            "--mgmt-key",
            "env:XAUTH",
            "--pin",
            "env:GPIN",
        ])
        .is_err());
        assert!(parse(&[
            "keyroostctl",
            "piv",
            "reset",
            "--yes",
            "--mgmt-key",
            "stdin",
            "--pin",
            "stdin",
        ])
        .is_err());
        assert!(parse(&[
            "keyroostctl",
            "piv",
            "reset",
            "--yes",
            "--mgmt-key",
            "default",
            "--mgmt-key",
            "stdin",
        ])
        .is_err());
        assert!(parse(&[
            "keyroostctl",
            "piv",
            "reset",
            "--yes",
            "--mgmt-key",
            "default",
            "--pin",
            "env:GPIN",
        ])
        .is_err());
        match parse(&[
            "keyroostctl",
            "piv",
            "reset",
            "--yes",
            "--mgmt-key",
            "default",
        ])
        .unwrap()
        .command
        {
            Some(Cmd::Piv {
                cmd: PivCmd::Reset { mgmt_key, .. },
            }) => assert_eq!(mgmt_key, Some(SecretSource::Default)),
            _ => panic!("expected piv reset"),
        }
    }

    #[test]
    fn piv_generate_key_policies_default_to_the_plain_piv_wire_format() {
        // Omitting both flags must decode to Default/Default — the byte layer
        // then leaves the 0xAA/0xAB policy tags out of the APDU entirely, the
        // standard PIV command every card accepts. A drifted default would
        // silently switch every scripted `piv key generate` to the Yubico extended
        // APDU, which non-Yubico cards reject.
        match parse(&["keyroostctl", "piv", "key", "generate", "--slot", "9a"])
            .unwrap()
            .command
        {
            Some(Cmd::Piv {
                cmd:
                    PivCmd::Key {
                        cmd:
                            PivKeyCmd::Generate {
                                pin_policy,
                                touch_policy,
                                force,
                                ..
                            },
                    },
            }) => {
                assert_eq!(pin_policy.to_policy(), keyroost_piv::PinPolicy::Default);
                assert_eq!(touch_policy.to_policy(), keyroost_piv::TouchPolicy::Default);
                assert!(!force);
            }
            _ => panic!("expected piv key generate"),
        }

        // Explicit values must land in their own fields, not each other's.
        match parse(&[
            "keyroostctl",
            "piv",
            "key",
            "generate",
            "--slot",
            "9a",
            "--pin-policy",
            "once",
            "--touch-policy",
            "cached",
            "--force",
        ])
        .unwrap()
        .command
        {
            Some(Cmd::Piv {
                cmd:
                    PivCmd::Key {
                        cmd:
                            PivKeyCmd::Generate {
                                pin_policy,
                                touch_policy,
                                force,
                                ..
                            },
                    },
            }) => {
                assert_eq!(pin_policy.to_policy(), keyroost_piv::PinPolicy::Once);
                assert_eq!(touch_policy.to_policy(), keyroost_piv::TouchPolicy::Cached);
                assert!(force);
            }
            _ => panic!("expected piv key generate"),
        }
    }

    #[test]
    fn piv_self_sign_inline_generate_key_mirrors_generate_key_defaults() {
        // Omitted: the convenience is off and its options carry the same
        // defaults `piv key generate` uses, so a later `--generate-key` run
        // behaves identically to the two-step flow.
        match parse(&[
            "keyroostctl",
            "piv",
            "cert",
            "generate",
            "--slot",
            "9a",
            "--subject",
            "CN=x",
        ])
        .unwrap()
        .command
        {
            Some(Cmd::Piv {
                cmd:
                    PivCmd::Cert {
                        cmd: PivCertCmd::Generate { keygen, .. },
                    },
            }) => {
                assert!(!keygen.generate_key);
                assert_eq!(keygen.algorithm.to_alg(), keyroost_piv::KeyAlg::EccP256);
                assert_eq!(
                    keygen.pin_policy.to_policy(),
                    keyroost_piv::PinPolicy::Default
                );
                assert_eq!(
                    keygen.touch_policy.to_policy(),
                    keyroost_piv::TouchPolicy::Default
                );
                assert!(keygen.pubkey_out.is_none());
            }
            _ => panic!("expected piv cert generate"),
        }

        // Passed: the flag flips on and its options are honored.
        match parse(&[
            "keyroostctl",
            "piv",
            "cert",
            "generate",
            "--slot",
            "9a",
            "--subject",
            "CN=x",
            "--generate-key",
            "--algorithm",
            "rsa2048",
            "--touch-policy",
            "always",
        ])
        .unwrap()
        .command
        {
            Some(Cmd::Piv {
                cmd:
                    PivCmd::Cert {
                        cmd: PivCertCmd::Generate { keygen, .. },
                    },
            }) => {
                assert!(keygen.generate_key);
                assert_eq!(keygen.algorithm.to_alg(), keyroost_piv::KeyAlg::Rsa2048);
                assert_eq!(
                    keygen.touch_policy.to_policy(),
                    keyroost_piv::TouchPolicy::Always
                );
            }
            _ => panic!("expected piv cert generate"),
        }
    }

    #[test]
    fn piv_inline_generate_key_options_require_the_flag_and_conflict_with_pubkey_in() {
        // A key-generation option without `--generate-key` is a mistake, not
        // a silent no-op.
        for cmd in ["generate", "request"] {
            assert!(parse(&[
                "keyroostctl",
                "piv",
                "cert",
                cmd,
                "--slot",
                "9a",
                "--subject",
                "CN=x",
                "--algorithm",
                "eccp384",
            ])
            .is_err());
        }
        // `--generate-key` and `--pubkey-in` are two ways to name the key;
        // asking for both is contradictory.
        assert!(parse(&[
            "keyroostctl",
            "piv",
            "cert",
            "request",
            "--slot",
            "9a",
            "--subject",
            "CN=x",
            "--generate-key",
            "--pubkey-in",
            "some/path",
        ])
        .is_err());
        // `cert request --generate-key` also needs the management key wired up
        // for the (new) key-generation step.
        assert!(parse(&[
            "keyroostctl",
            "piv",
            "cert",
            "request",
            "--slot",
            "9a",
            "--subject",
            "CN=x",
            "--mgmt-key",
            "env:MK",
        ])
        .is_err());
    }

    #[test]
    fn piv_new_chuid_default_days_matches_self_sign() {
        // Neither command's `--days`/`--months`/`--years` defaults via clap
        // anymore (all three are `Option<u32>`, left `None` when omitted so
        // `ValidFor::resolve` can tell "explicitly given" from "defaulted");
        // pin the parsed triples equal across both commands so a future
        // change to one doesn't silently drift from the other, and pin
        // `ValidFor::resolve`'s shared default to 1 year.
        let chuid = match parse(&["keyroostctl", "piv", "chuid", "generate"])
            .unwrap()
            .command
        {
            Some(Cmd::Piv {
                cmd:
                    PivCmd::Chuid {
                        cmd:
                            PivChuidCmd::Generate {
                                days,
                                months,
                                years,
                                ..
                            },
                    },
            }) => (days, months, years),
            _ => panic!("expected piv chuid generate"),
        };
        let cert = match parse(&[
            "keyroostctl",
            "piv",
            "cert",
            "generate",
            "--slot",
            "9a",
            "--subject",
            "CN=x",
        ])
        .unwrap()
        .command
        {
            Some(Cmd::Piv {
                cmd:
                    PivCmd::Cert {
                        cmd:
                            PivCertCmd::Generate {
                                days,
                                months,
                                years,
                                ..
                            },
                    },
            }) => (days, months, years),
            _ => panic!("expected piv cert generate"),
        };
        assert_eq!(chuid, cert);
        assert_eq!(chuid, (None, None, None));
        assert_eq!(
            ValidFor::resolve(chuid.0, chuid.1, chuid.2),
            ValidFor {
                years: 1,
                months: 0,
                days: 0
            }
        );
    }

    #[test]
    fn piv_self_sign_days_months_years_combine_and_sum() {
        // `--years 1 --days 5` is not rejected as a conflict; it resolves to
        // both counts at once.
        let (days, months, years) = match parse(&[
            "keyroostctl",
            "piv",
            "cert",
            "generate",
            "--slot",
            "9a",
            "--subject",
            "CN=x",
            "--years",
            "1",
            "--days",
            "5",
        ])
        .unwrap()
        .command
        {
            Some(Cmd::Piv {
                cmd:
                    PivCmd::Cert {
                        cmd:
                            PivCertCmd::Generate {
                                days,
                                months,
                                years,
                                ..
                            },
                    },
            }) => (days, months, years),
            _ => panic!("expected piv cert generate"),
        };
        assert_eq!(
            ValidFor::resolve(days, months, years),
            ValidFor {
                years: 1,
                months: 0,
                days: 5
            }
        );
    }

    #[test]
    fn check_valid_days_accepts_the_default_and_the_actual_ceiling() {
        assert!(parse_valid_days("365").is_ok());
        assert!(
            parse_valid_days(&keyroost_piv::max_valid_days(u64::from(unix_now())).to_string())
                .is_ok()
        );
    }

    #[test]
    fn check_valid_days_rejects_one_past_the_ceiling() {
        let max = keyroost_piv::max_valid_days(u64::from(unix_now()));
        let err = parse_valid_days(&(max + 1).to_string()).unwrap_err();
        assert!(err.contains("exceeds"));
    }

    #[test]
    fn check_valid_months_accepts_the_default_and_the_actual_ceiling() {
        assert!(parse_valid_months("12").is_ok());
        assert!(parse_valid_months(
            &keyroost_piv::max_valid_months(u64::from(unix_now())).to_string()
        )
        .is_ok());
    }

    #[test]
    fn check_valid_months_rejects_one_past_the_ceiling() {
        let max = keyroost_piv::max_valid_months(u64::from(unix_now()));
        let err = parse_valid_months(&(max + 1).to_string()).unwrap_err();
        assert!(err.contains("exceeds"));
    }

    #[test]
    fn check_valid_years_accepts_the_default_and_the_actual_ceiling() {
        assert!(parse_valid_years("1").is_ok());
        assert!(parse_valid_years(
            &keyroost_piv::max_valid_years(u64::from(unix_now())).to_string()
        )
        .is_ok());
    }

    #[test]
    fn check_valid_years_rejects_one_past_the_ceiling() {
        let max = keyroost_piv::max_valid_years(u64::from(unix_now()));
        let err = parse_valid_years(&(max + 1).to_string()).unwrap_err();
        assert!(err.contains("exceeds"));
    }

    #[test]
    fn valid_for_check_rejects_an_all_zero_period() {
        assert!(ValidFor {
            years: 0,
            months: 0,
            days: 0
        }
        .check()
        .is_err());
        // Explicitly passing `--days 0` (nothing else) also resolves to an
        // all-zero period, and must be rejected the same way.
        assert!(ValidFor::resolve(Some(0), None, None).check().is_err());
    }

    /// `guard_signable_alg` is the early-exit `piv cert generate` / `piv
    /// cert request` call before any PIN/management-key prompt or card
    /// write: every signing-capable algorithm passes, and X25519 — the one
    /// key-agreement-only algorithm keyroost supports — is rejected with a
    /// message naming the key type, mirroring
    /// `keyroost_piv::x509::signature_hash`'s own verdict exactly.
    #[test]
    fn key_usage_default_only_with_its_exact_set() {
        use keyroost_piv::{
            x509::{KeyUsage as K, KeyUsageExt},
            KeyAlg, Slot,
        };
        use CliKeyUsage as U;
        let ext = |usages, critical| Some(KeyUsageExt { usages, critical });
        let sign_default = ext(K::DIGITAL_SIGNATURE.union(K::NON_REPUDIATION), true);
        // `default` is the PIV extension: usages plus critical.
        assert_eq!(
            resolve_key_usage(&[U::Default], Slot::Signature, None),
            Ok(sign_default)
        );
        assert_eq!(
            resolve_key_usage(&[U::Default], Slot::KeyManagement, Some(KeyAlg::EccP256)),
            Ok(ext(K::KEY_AGREEMENT, true))
        );
        // No PIV definition for this slot/key: `default` is an error, not "none".
        assert!(resolve_key_usage(&[U::Default], Slot::KeyManagement, None).is_err());
        // Ed25519 can't back keyAgreement: the 9D / retired default is "no extension".
        assert_eq!(
            resolve_key_usage(&[U::Default], Slot::KeyManagement, Some(KeyAlg::Ed25519)),
            Ok(None)
        );
        assert_eq!(
            resolve_key_usage(
                &[U::Default, U::Critical],
                Slot::Retired(2),
                Some(KeyAlg::Ed25519)
            ),
            Ok(None)
        );
        // `default` may accompany exactly the default set incl. critical, in any order.
        assert_eq!(
            resolve_key_usage(
                &[
                    U::Critical,
                    U::NonRepudiation,
                    U::Default,
                    U::DigitalSignature
                ],
                Slot::Signature,
                None
            ),
            Ok(sign_default)
        );
        // A subset, a superset, a different set, or the usages without critical.
        for bad in [
            &[U::Default, U::DigitalSignature, U::Critical][..],
            &[U::Default, U::DigitalSignature, U::NonRepudiation][..],
            &[U::Default, U::Critical][..],
            &[
                U::Default,
                U::DigitalSignature,
                U::NonRepudiation,
                U::CrlSign,
                U::Critical,
            ][..],
            &[U::Default, U::KeyAgreement, U::Critical][..],
        ] {
            assert!(resolve_key_usage(bad, Slot::Signature, None).is_err());
        }
        // Explicit values combine; critical is only set when asked for.
        assert_eq!(
            resolve_key_usage(
                &[U::DigitalSignature, U::NonRepudiation],
                Slot::Authentication,
                None
            ),
            Ok(ext(K::DIGITAL_SIGNATURE.union(K::NON_REPUDIATION), false))
        );
        assert_eq!(
            resolve_key_usage(
                &[U::DigitalSignature, U::Critical],
                Slot::Authentication,
                None
            ),
            Ok(ext(K::DIGITAL_SIGNATURE, true))
        );
        // critical needs a usage; invalid combinations are rejected.
        assert!(resolve_key_usage(&[U::Critical], Slot::Authentication, None).is_err());
        assert!(check_key_usage_args(&[U::EncipherOnly], Slot::Signature, None).is_err());
    }

    /// No `--key-usage` behaves exactly like `--key-usage default`: the
    /// slot's PIV extension, the same "no extension" for a key type that
    /// can't back it, and the same error where the default can't be known.
    #[test]
    fn key_usage_absent_is_the_slot_default() {
        use keyroost_piv::{KeyAlg, Slot};
        let slots = [
            Slot::Authentication,
            Slot::Signature,
            Slot::KeyManagement,
            Slot::CardAuthentication,
            Slot::Retired(1),
            Slot::Retired(20),
        ];
        let algs = [
            None,
            Some(KeyAlg::Rsa2048),
            Some(KeyAlg::EccP256),
            Some(KeyAlg::EccP384),
            Some(KeyAlg::Ed25519),
            Some(KeyAlg::X25519),
        ];
        for slot in slots {
            for alg in algs {
                assert_eq!(
                    resolve_key_usage(&[], slot, alg),
                    resolve_key_usage(&[CliKeyUsage::Default], slot, alg),
                );
            }
        }
        // Spot checks of what that default is.
        assert_eq!(
            resolve_key_usage(&[], Slot::Signature, None).map(|e| e.map(|e| e.critical)),
            Ok(Some(true))
        );
        assert_eq!(
            resolve_key_usage(&[], Slot::KeyManagement, Some(KeyAlg::Ed25519)),
            Ok(None)
        );
    }

    #[test]
    fn key_usage_undefined_means_no_extension() {
        use keyroost_piv::Slot;
        let r = |a: &[CliKeyUsage]| resolve_key_usage(a, Slot::Authentication, None);
        assert_eq!(r(&[CliKeyUsage::Undefined]), Ok(None));
        assert!(r(&[CliKeyUsage::Undefined, CliKeyUsage::CrlSign]).is_err());
        assert!(r(&[CliKeyUsage::CrlSign, CliKeyUsage::Undefined]).is_err());
        assert!(r(&[CliKeyUsage::Undefined, CliKeyUsage::Critical]).is_err());
        // 9A's PIV default is digitalSignature, so undefined != default there.
        assert!(r(&[CliKeyUsage::Default, CliKeyUsage::Undefined]).is_err());
    }

    #[test]
    fn key_usage_flag_parses_lists_and_repeats() {
        let parse = |extra: &[&str]| {
            let mut args = vec![
                "keyroostctl",
                "piv",
                "cert",
                "generate",
                "--slot",
                "9a",
                "--subject",
                "CN=x",
            ];
            args.extend_from_slice(extra);
            match parse(&args).map(|c| c.command) {
                Ok(Some(Cmd::Piv {
                    cmd:
                        PivCmd::Cert {
                            cmd: PivCertCmd::Generate { key_usage, .. },
                        },
                })) => Some(key_usage.key_usage.len()),
                _ => None,
            }
        };
        assert_eq!(parse(&[]), Some(0));
        assert_eq!(
            parse(&["--key-usage", "digital-signature,key-agreement"]),
            Some(2)
        );
        assert_eq!(
            parse(&["--key-usage", "default", "--key-usage", "crl-sign"]),
            Some(2)
        );
        assert_eq!(parse(&["--key-usage", "bogus"]), None);
    }

    #[test]
    fn guard_signable_alg_rejects_only_x25519() {
        use keyroost_piv::KeyAlg;
        for alg in KeyAlg::ALL {
            let guard_ok = guard_signable_alg(alg).is_ok();
            let x509_ok = keyroost_piv::x509::signature_hash(alg).is_ok();
            assert_eq!(guard_ok, x509_ok, "mismatch for {alg:?}");
        }
        let err = guard_signable_alg(KeyAlg::X25519).unwrap_err();
        assert!(err.to_string().contains("X25519"));
    }

    #[test]
    fn piv_change_pin_reads_both_before_opening() {
        use crate::secrets::fake::FakeIo;
        let mut sec = crate::secrets::Secrets::new(FakeIo::piped(&["123456\n"]));
        let cli = parse(&[
            "keyroostctl",
            "piv",
            "pin",
            "change",
            "--pin",
            "stdin",
            "--new-pin",
            "stdin",
        ])
        .unwrap();
        let Some(Cmd::Piv { cmd }) = &cli.command else {
            panic!("expected piv pin change")
        };
        let Err(e) = piv_secret_pair(cmd).unwrap().read_text(&mut sec) else {
            panic!("stdin ended after one line")
        };
        assert_eq!(e, "expected the new PIN on stdin line 2, but stdin ended");
    }

    #[test]
    fn piv_current_secrets_are_called_current_like_every_other_group() {
        use crate::secrets::fake::FakeIo;
        let sec = crate::secrets::Secrets::new(FakeIo::default());
        for (spec, label, flag) in [
            (&PIV_OLD_PIN, "current PIN", "pin"),
            (&PIV_OLD_PUK, "current PUK", "puk"),
            (&PIV_OLD_MGMT_KEY, "current management key", "mgmt-key"),
        ] {
            let e = sec.check(spec, Source::NONE).unwrap_err();
            assert!(
                e.starts_with(&format!("no {label} given: pass --{flag} env:NAME")),
                "{e}"
            );
        }
        let mut sec = crate::secrets::Secrets::new(FakeIo::terminal().typing(&["123456"]));
        sec.read(&PIV_OLD_PIN, Source::NONE).unwrap();
        assert_eq!(sec.io.prompts, vec!["Current PIN: ".to_string()]);
    }

    #[test]
    fn mgmt_key_default_is_deferred_and_hex_is_decoded() {
        use crate::secrets::fake::FakeIo;
        let mut sec = crate::secrets::Secrets::new(FakeIo::piped(&[
            " 010203040506070801020304050607080102030405060708 \n",
        ]));
        assert!(matches!(
            read_mgmt_key_input(&mut sec, &PIV_MGMT_KEY, Some(&SecretSource::Default)).unwrap(),
            MgmtKeyInput::Default
        ));
        assert_eq!(sec.io.lines_read, 0, "--mgmt-key default reads nothing");
        match read_mgmt_key_input(&mut sec, &PIV_MGMT_KEY, Some(&SecretSource::Stdin)).unwrap() {
            MgmtKeyInput::Key(k) => assert_eq!(k.len(), 24),
            MgmtKeyInput::Default => panic!(),
        }
        let sec = crate::secrets::Secrets::new(FakeIo::default());
        assert_eq!(
            check_mgmt_key(&sec, &PIV_MGMT_KEY, None).unwrap_err(),
            "no management key given: pass --mgmt-key env:NAME, --mgmt-key stdin or --mgmt-key default"
        );
        assert!(check_mgmt_key(&sec, &PIV_MGMT_KEY, Some(&SecretSource::Default)).is_ok());
    }

    #[test]
    fn mgmt_key_bad_hex_names_the_key_but_never_the_value() {
        use crate::secrets::fake::FakeIo;
        let mut sec =
            crate::secrets::Secrets::new(FakeIo::default().var("KR_MK", "zz0102secretish"));
        let e = read_mgmt_key_input(
            &mut sec,
            &PIV_OLD_MGMT_KEY,
            Some(&SecretSource::Env("KR_MK".into())),
        )
        .err()
        .unwrap()
        .to_string();
        assert!(
            e.starts_with("the current management key is not valid hex"),
            "{e}"
        );
        assert!(!e.contains("secretish") && !e.contains("zz01"), "{e}");
    }

    #[test]
    fn piv_two_line_flags_state_their_line() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let piv = cmd.find_subcommand("piv").unwrap();
        for (sub, flag, line) in [
            ("pin change", "pin", "first line"),
            (
                "pin change",
                "new-pin",
                "second line when --pin stdin is also given",
            ),
            ("puk change", "puk", "first line"),
            (
                "puk change",
                "new-puk",
                "second line when --puk stdin is also given",
            ),
            ("pin unblock", "puk", "first line"),
            (
                "pin unblock",
                "new-pin",
                "second line when --puk stdin is also given",
            ),
            ("retries set", "pin", "first line"),
            (
                "retries set",
                "mgmt-key",
                "second line when --pin stdin is also given",
            ),
            ("mgmt-key change", "mgmt-key", "first line"),
            (
                "mgmt-key change",
                "new-mgmt-key",
                "second line when --mgmt-key stdin is also given",
            ),
            ("cert generate", "pin", "first line"),
            (
                "cert generate",
                "mgmt-key",
                "second line when --pin stdin is also given",
            ),
            ("cert request", "pin", "first line"),
            (
                "cert request",
                "mgmt-key",
                "second line when --pin stdin is also given",
            ),
        ] {
            let leaf = sub
                .split(' ')
                .fold(piv, |c, w| c.find_subcommand(w).unwrap());
            let arg = leaf
                .get_arguments()
                .find(|a| a.get_long() == Some(flag))
                .unwrap_or_else(|| panic!("{sub} --{flag}"));
            let help = arg.get_help().map(|h| h.to_string()).unwrap_or_default();
            assert!(help.contains(line), "piv {sub} --{flag}: {help:?}");
        }
    }

    #[test]
    fn piv_secret_flags_all_have_help() {
        for (path, cmd) in all_commands() {
            if !path.starts_with("piv ") {
                continue;
            }
            for arg in cmd.get_arguments().filter(|a| is_secret_arg(a)) {
                let help = arg.get_help().map(|h| h.to_string()).unwrap_or_default();
                assert!(
                    help.contains("env:NAME") && help.contains("stdin"),
                    "{path} --{} has no help naming its sources",
                    arg.get_long().unwrap_or_default()
                );
            }
        }
    }

    const SECRET_TABLE: &str = include_str!("../tests/secret_flags.txt");

    /// (path, every secret flag) for each visible command that runs (a
    /// leaf), from the clap tree: the long of each `<SOURCE>` flag, its own
    /// or a global one declared above it (`molto --customer-key`).
    fn secret_pairs() -> std::collections::BTreeMap<String, Vec<String>> {
        use clap::CommandFactory;
        fn walk(
            cmd: &clap::Command,
            path: String,
            inherited: &[String],
            out: &mut std::collections::BTreeMap<String, Vec<String>>,
        ) {
            let mut secrets: Vec<String> = inherited.to_vec();
            for a in cmd.get_arguments().filter(|a| is_secret_arg(a)) {
                let long = a.get_long().unwrap().to_owned();
                if !secrets.contains(&long) {
                    secrets.push(long);
                }
            }
            let subs: Vec<&clap::Command> = cmd
                .get_subcommands()
                .filter(|s| !s.is_hide_set() && s.get_name() != "help")
                .collect();
            if subs.is_empty() || !cmd.is_subcommand_required_set() {
                let mut pairs = secrets.clone();
                pairs.sort();
                if !pairs.is_empty() && !path.is_empty() {
                    out.insert(path.clone(), pairs);
                }
            }
            let globals: Vec<String> = secrets
                .iter()
                .filter(|l| {
                    inherited.contains(l)
                        || cmd
                            .get_arguments()
                            .any(|a| a.get_long() == Some(l.as_str()) && a.is_global_set())
                })
                .cloned()
                .collect();
            for sub in subs {
                let p = if path.is_empty() {
                    sub.get_name().to_owned()
                } else {
                    format!("{path} {}", sub.get_name())
                };
                walk(sub, p, &globals, out);
            }
        }
        let mut root = Cli::command();
        root.build();
        let mut out = std::collections::BTreeMap::new();
        walk(&root, String::new(), &[], &mut out);
        out
    }

    /// Whether clap refuses `a` and `b` together: a direct conflict, or both
    /// in an exclusive (`multiple(false)`) group.
    fn args_conflict(cmd: &clap::Command, a: &clap::Arg, b: &clap::Arg) -> bool {
        let one_way = |x: &clap::Arg, y: &clap::Arg| {
            cmd.get_arg_conflicts_with(x)
                .iter()
                .any(|c| c.get_id() == y.get_id())
        };
        one_way(a, b)
            || one_way(b, a)
            || cmd.get_groups().any(|g| {
                let ids: Vec<&clap::Id> = g.get_args().collect();
                !g.clone().is_multiple() && ids.contains(&a.get_id()) && ids.contains(&b.get_id())
            })
    }

    #[test]
    fn every_secret_flag_is_in_the_table_with_help_and_line_order() {
        use crate::secrets::SECRET_FLAGS;
        use clap::CommandFactory;
        let tree = secret_pairs();
        let mut table = std::collections::BTreeMap::new();
        // Column 3 as written: the stdin line order.
        let mut order: std::collections::BTreeMap<String, Vec<String>> =
            std::collections::BTreeMap::new();
        // A path may have several rows (one per mode, e.g. `otp list
        // --unlock auto`) as long as their extra args differ and they all
        // list the same secrets.
        let mut seen = std::collections::BTreeSet::new();
        for line in SECRET_TABLE
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        {
            let cols: Vec<&str> = line.split('\t').filter(|c| !c.is_empty()).collect();
            assert!(cols.len() == 3 || cols.len() == 4, "bad row: {line:?}");
            let extra = if cols.len() == 4 { cols[1] } else { "" };
            assert!(seen.insert((cols[0], extra)), "duplicate row: {line:?}");
            let written: Vec<String> = cols[cols.len() - 2].split(' ').map(str::to_owned).collect();
            let mut all = written.clone();
            all.sort();
            if let Some(prev) = table.insert(cols[0].to_owned(), all.clone()) {
                assert_eq!(prev, all, "rows for one path disagree: {line:?}");
            }
            order.insert(cols[0].to_owned(), written);
        }
        assert_eq!(tree, table, "tests/secret_flags.txt is out of date");
        // Column 4 per path: the secrets every run needs (all rows).
        let mut needed: std::collections::BTreeMap<String, Vec<String>> =
            std::collections::BTreeMap::new();
        for line in SECRET_TABLE
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        {
            let cols: Vec<&str> = line.split('\t').filter(|c| !c.is_empty()).collect();
            needed.entry(cols[0].to_owned()).or_default().extend(
                cols[cols.len() - 1]
                    .split([' ', '|'])
                    .filter(|w| *w != "-")
                    .map(str::to_owned),
            );
        }
        let mut root = Cli::command();
        root.build();
        for path in tree.keys() {
            let mut cmd = &root;
            for name in path.split(' ') {
                cmd = cmd.find_subcommand(name).unwrap();
            }
            let help_of = |a: &clap::Arg| a.get_help().map(|h| h.to_string()).unwrap_or_default();
            // Every `<SOURCE>` flag names its sources and is in the
            // refusal table with the same `default`.
            for a in cmd.get_arguments().filter(|a| is_secret_arg(a)) {
                let long = a.get_long().unwrap();
                let help = help_of(a);
                for want in ["env:NAME", "stdin", "hidden when typed at a terminal"] {
                    assert!(help.contains(want), "{path} --{long}: {want:?} in {help}");
                }
                let f = SECRET_FLAGS
                    .iter()
                    .find(|f| f.long == long)
                    .unwrap_or_else(|| panic!("{path} --{long}: not in SECRET_FLAGS"));
                assert!(
                    !f.default_ok || help.contains("default"),
                    "{path} --{long}: the help doesn't name `default`: {help}"
                );
                // "a terminal asks." unqualified only where every run needs
                // the secret; elsewhere the help says when it asks, or that
                // it never does.
                let required = needed[path.as_str()].iter().any(|n| n == long);
                // (clap drops the help's final period.)
                let asks_always =
                    help.ends_with("a terminal asks") || help.contains("a terminal asks.");
                assert_eq!(asks_always, required, "{path} --{long}: {help}");
            }
            // Two stdin sources that can be combined: each states its line,
            // and column 3 lists the first-line one first.
            let stdin_args: Vec<&clap::Arg> =
                cmd.get_arguments().filter(|a| is_secret_arg(a)).collect();
            let short = |a: &clap::Arg| -> String { a.get_long().unwrap().to_owned() };
            for a in &stdin_args {
                let combinable: Vec<&&clap::Arg> = stdin_args
                    .iter()
                    .filter(|b| b.get_id() != a.get_id() && !args_conflict(cmd, a, b))
                    .collect();
                if combinable.is_empty() {
                    continue;
                }
                let help = help_of(a);
                let first = help.contains("first line");
                let second = help.contains("second line");
                assert!(
                    first || second,
                    "{path} --{}: {help}",
                    a.get_long().unwrap()
                );
                if first && !second {
                    let col = &order[path];
                    let pos = |n: &str| col.iter().position(|c| c == n);
                    for b in &combinable {
                        let hb = help_of(b);
                        if hb.contains("second line") && !hb.contains("first line") {
                            assert!(
                                pos(&short(a)) < pos(&short(b)),
                                "{path}: column 3 lists --{} after --{}",
                                short(a),
                                short(b)
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn retired_flag_rows_name_real_flags() {
        use clap::CommandFactory;
        let mut root = Cli::command();
        root.build();
        let all = all_commands();
        for r in RETIRED_FLAGS {
            for f in r.now {
                assert!(r.msg.contains(f), "{}: message doesn't name {f}", r.flag);
                let long = f.trim_start_matches('-');
                // On the command the words name, when they name one;
                // otherwise somewhere in the tree.
                let mut c = &root;
                let mut on_path = true;
                for w in r.words {
                    match c.find_subcommand(w) {
                        Some(s) => c = s,
                        None => on_path = false,
                    }
                }
                let here =
                    |c: &clap::Command| c.get_arguments().any(|a| a.get_long() == Some(long));
                if on_path && !r.words.is_empty() && c.get_subcommands().next().is_none() {
                    assert!(here(c), "{}: {f} is not on `{}`", r.flag, r.words.join(" "));
                } else {
                    assert!(
                        all.iter().any(|(_, c)| here(c)),
                        "{}: {f} is in no command",
                        r.flag
                    );
                }
            }
        }
    }

    #[test]
    fn specific_retired_flag_rows_come_first() {
        let first_generic = RETIRED_FLAGS
            .iter()
            .position(|r| r.words.is_empty() && r.flag != "--list-readers");
        if let Some(i) = first_generic {
            assert!(
                RETIRED_FLAGS[i..].iter().all(|r| r.words.is_empty()),
                "a specific row after the first generic one"
            );
        }
    }

    /// On `openpgp pin change`, `--admin` turns `--pin` and `--new-pin`
    /// into the admin PIN; their help says so plainly.
    #[test]
    fn openpgp_pin_change_help_names_the_admin_pin() {
        let c = find(&["openpgp", "pin", "change"]);
        for (long, want) in [
            ("pin", "the current admin PIN (PW3) with --admin"),
            ("new-pin", "the new admin PIN (PW3) with --admin"),
        ] {
            let help = c
                .get_arguments()
                .find(|a| a.get_long() == Some(long))
                .and_then(|a| a.get_help().map(|h| h.to_string()))
                .unwrap_or_default();
            assert!(help.contains(want), "--{long}: {help}");
        }
    }

    /// No help text names an old `--X-env` / `--X-stdin` / `--X-default`
    /// spelling (or `--pin-*`) of a flag that now takes a source. The
    /// Molto2 key, seed and URI flags keep theirs until they move.
    #[test]
    fn help_names_no_retired_secret_flag() {
        let retired = RETIRED_FLAGS
            .iter()
            .filter(|r| r.words.is_empty() && r.flag != "--list-readers")
            .map(|r| r.flag)
            .chain(["--pin-*", "--old-"]);
        let retired: Vec<&str> = retired.collect();
        let mut bad = Vec::new();
        for (path, cmd) in all_commands() {
            let mut texts: Vec<String> = [cmd.get_about(), cmd.get_long_about()]
                .into_iter()
                .flatten()
                .map(|t| t.to_string())
                .collect();
            for a in cmd.get_arguments() {
                texts.extend(a.get_help().map(|h| h.to_string()));
                texts.extend(a.get_long_help().map(|h| h.to_string()));
            }
            for t in texts {
                for r in &retired {
                    // Whole flags only: `--pin-env` but not `--pin-envelope`.
                    let hit = if r.ends_with('*') || r.ends_with('-') {
                        t.contains(r)
                    } else {
                        t.match_indices(r).any(|(i, _)| {
                            !t[i + r.len()..]
                                .chars()
                                .next()
                                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '-')
                        })
                    };
                    if hit {
                        bad.push(format!("{path}: {r} in {t:?}"));
                    }
                }
            }
        }
        assert!(bad.is_empty(), "{}", bad.join("\n"));
    }

    /// A retired `--X-env` / `--X-stdin` flag names the replacement this
    /// command really has: `--pin-env` on a command whose PIN flag is
    /// `--admin-pin` or `--new-pin` names that flag, never `--pin`.
    #[test]
    fn a_retired_secret_flag_names_this_commands_own_flag() {
        let argv = |s: &str| s.split(' ').map(String::from).collect::<Vec<_>>();
        for (flag, line, want, never) in [
            (
                "--pin-env",
                "keyroostctl openpgp name set x --pin-env V",
                "--admin-pin",
                "now --pin ",
            ),
            (
                "--pin-stdin",
                "keyroostctl fido pin set --pin-stdin",
                "--new-pin",
                "now --pin ",
            ),
            (
                "--mgmt-key-env",
                "keyroostctl piv pin change --mgmt-key-env V",
                "--pin",
                "now --mgmt-key",
            ),
            // The command has the flag: the plain row.
            (
                "--pin-env",
                "keyroostctl piv pin change --pin-env V",
                "--pin-env VAR is now --pin env:VAR",
                "\u{0}",
            ),
        ] {
            let msg = retired_flag_hint(flag, &argv(line)).unwrap_or_else(|| panic!("{line}"));
            assert!(msg.contains(want), "{line}: {msg}");
            assert!(!msg.contains(never), "{line}: {msg}");
            assert!(
                !msg.contains(" V ") && !msg.ends_with(" V"),
                "{line}: {msg}"
            );
        }
    }

    /// The pair a two-secret command's handler reads through.
    fn stdin_pair(cmd: &Cmd) -> Option<SecretPair<'_>> {
        match cmd {
            Cmd::Piv { cmd } => piv_secret_pair(cmd),
            Cmd::Openpgp { cmd } => pgp_secret_pair(cmd),
            Cmd::Otp { cmd, .. } => otp_secret_pair(cmd),
            Cmd::Oath { cmd } => oath_secret_pair(cmd),
            Cmd::Fido {
                cmd: FidoCmd::Pin { cmd },
            } => fido_pin_secret_pair(cmd),
            _ => None,
        }
    }

    /// Every command whose two secrets can both come from stdin (every
    /// table row with two combinable secret flags): parsed with both on
    /// stdin and read through the pair its handler uses, line 1 lands in
    /// the first secret and line 2 in the second; the pair's flags are the
    /// table's column 3 in order, and the help calls them first and second
    /// line.
    #[test]
    fn stdin_line_order_per_command() {
        use crate::secrets::fake::FakeIo;
        use clap::CommandFactory;
        let mut root = Cli::command();
        root.build();
        let mut covered = Vec::new();
        for line in SECRET_TABLE
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        {
            let cols: Vec<&str> = line.split('\t').filter(|c| !c.is_empty()).collect();
            let mut flags: Vec<&str> = cols[cols.len() - 2].split(' ').collect();
            let path: Vec<&str> = cols[0].split(' ').collect();
            if flags.len() > 2 {
                // One command, several modes (`molto import --file` takes
                // --password, `--slot` takes --uri): a row's pair is the
                // flags its own extra args leave usable.
                let mut base = vec!["keyroostctl"];
                base.extend(&path);
                if cols.len() == 4 {
                    base.extend(cols[1].split(' '));
                }
                flags.retain(|f| {
                    let flag = format!("--{f}");
                    let mut argv = base.clone();
                    argv.extend([flag.as_str(), "stdin"]);
                    parse(&argv).is_ok()
                });
            }
            if flags.len() != 2 {
                continue;
            }
            let mut cmd = &root;
            for name in &path {
                cmd = cmd.find_subcommand(name).unwrap();
            }
            let arg = |long: &str| {
                cmd.get_arguments()
                    .find(|a| a.get_long() == Some(long))
                    .unwrap_or_else(|| panic!("{line}: no --{long}"))
            };
            let source = |long: &str| {
                cmd.get_arguments()
                    .any(|a| a.get_long() == Some(long) && is_secret_arg(a))
            };
            assert!(source(flags[0]) && source(flags[1]), "{line}");
            if args_conflict(cmd, arg(flags[0]), arg(flags[1])) {
                continue; // one choice of two
            }
            let help = |long: &str| arg(long).get_help().unwrap().to_string();
            assert!(help(flags[0]).contains("first line"), "{line}");
            assert!(help(flags[1]).contains("second line"), "{line}");
            let mut argv = vec!["keyroostctl"];
            argv.extend(&path);
            if cols.len() == 4 {
                argv.extend(cols[1].split(' '));
            }
            let a = format!("--{}", flags[0]);
            let b = format!("--{}", flags[1]);
            argv.extend([a.as_str(), "stdin", b.as_str(), "stdin"]);
            if cols[0] == "piv cert request" {
                argv.push("--generate-key"); // --mgmt-key needs it there
            }
            if path[0] == "molto" {
                molto_stdin_order(line, &argv, flags[1]);
                covered.push(cols[0]);
                continue;
            }
            let cli = parse(&argv).unwrap_or_else(|e| panic!("{argv:?}: {e}"));
            let pair = cli
                .command
                .as_ref()
                .and_then(stdin_pair)
                .unwrap_or_else(|| panic!("{line}: the handler reads no pair"));
            assert_eq!(
                [pair.first.0.flag, pair.second.spec.flag],
                [flags[0], flags[1]],
                "{line}"
            );
            let mut sec = Secrets::new(FakeIo::piped(&["11\n", "22\n"]));
            let (first, second) = pair.read_text(&mut sec).unwrap();
            assert_eq!([first.as_str(), second.as_str()], ["11", "22"], "{line}");
            covered.push(cols[0]);
        }
        covered.dedup();
        assert_eq!(
            covered,
            [
                "molto seed",
                "molto customer-key",
                "molto import",
                "fido pin change",
                "oath add",
                "oath password set",
                "openpgp pin change",
                "openpgp pin unblock",
                "piv pin change",
                "piv pin unblock",
                "piv puk change",
                "piv retries set",
                "piv mgmt-key change",
                "piv cert request",
                "piv cert generate",
                "otp add",
                "otp pin change",
            ]
        );
    }

    /// One Molto2 row of [`stdin_line_order_per_command`]: the customer key
    /// (`--customer-key stdin`) and `second`, both piped, read through the
    /// functions `run_molto` uses: line 1 is the key, line 2 the other.
    fn molto_stdin_order(line: &str, argv: &[&str], second: &str) {
        use crate::secrets::fake::FakeIo;
        let vault = std::env::temp_dir().join(format!(
            "keyroostctl-order-{}-vault.json",
            std::process::id()
        ));
        // An encrypted Aegis vault as far as the importer can tell; its
        // password is read, then decryption fails.
        std::fs::write(&vault, r#"{"version":1,"db":"AAAA"}"#).unwrap();
        // Removed on every path, a failing assert included.
        struct Cleanup<'a>(&'a std::path::Path);
        impl Drop for Cleanup<'_> {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(self.0);
            }
        }
        let _cleanup = Cleanup(&vault);
        let vault_arg = vault.to_str().unwrap();
        let argv: Vec<&str> = argv
            .iter()
            .map(|a| if *a == "vault.json" { vault_arg } else { a })
            .collect();
        let cli = parse(&argv).unwrap_or_else(|e| panic!("{argv:?}: {e}"));
        let Some(Cmd::Molto { key, cmd, .. }) = cli.command else {
            panic!("{line}: not a molto command")
        };
        let line2 = match second {
            "uri" => "otpauth://totp/acct?secret=JBSWY3DP\n",
            "seed" => "AEBA\n",
            _ => "22\n",
        };
        let mut sec = Secrets::new(FakeIo::piped(&["11\n", line2]));
        let early = molto_early_key(&mut sec, &key, &cmd).unwrap();
        match (second, &cmd) {
            (
                "password",
                MoltoCmd::Import {
                    file: Some(path),
                    password,
                    ..
                },
            ) => {
                assert_eq!(&early.unwrap()[..], [0x11], "{line}");
                assert!(load_bulk_entries(&mut sec, path, password.as_ref()).is_err());
                assert_eq!(sec.io.lines_read, 2, "{line}");
            }
            _ => match (second, {
                let (k, input) = molto_key_and_input(&mut sec, &key, &cmd, early).unwrap();
                assert_eq!(&k[..], [0x11], "{line}");
                input
            }) {
                ("seed", MoltoInput::Seed(s)) => {
                    assert_eq!(&s[..], [1, 2], "{line}")
                }
                ("new-customer-key", MoltoInput::NewKey(k)) => assert_eq!(&k[..], [0x22], "{line}"),
                ("uri", MoltoInput::Entry { entry, .. }) => {
                    assert_eq!(&entry.secret[..], b"Hello", "{line}")
                }
                _ => panic!("{line}: read the wrong input"),
            },
        }
    }

    /// `molto import --file --dry-run` never uses the customer key: it reads
    /// (and drops) it only to keep a piped password on stdin line 2, and
    /// never asks for it at a terminal.
    #[test]
    fn dry_run_reads_the_customer_key_only_for_stdin_order() {
        use crate::secrets::fake::FakeIo;
        let parts = |argv: &[&str]| {
            let mut full = vec![
                "keyroostctl",
                "molto",
                "import",
                "--file",
                "v.json",
                "--dry-run",
            ];
            full.extend(argv);
            match parse(&full).unwrap().command {
                Some(Cmd::Molto {
                    key,
                    cmd: MoltoCmd::Import { password, .. },
                    ..
                }) => (key, password),
                _ => unreachable!(),
            }
        };
        let both = ["--customer-key", "stdin", "--password", "stdin"];

        // Piped, both on stdin: line 1 (the key) is consumed.
        let (key, pw) = parts(&both);
        let mut sec = Secrets::new(FakeIo::piped(&["11\n", "pw\n"]));
        molto_dry_run_key(&mut sec, &key, pw.as_ref()).unwrap();
        assert_eq!(sec.io.lines_read, 1);

        // At a terminal: each is its own prompt, so the key is not asked for.
        let mut sec = Secrets::new(FakeIo::terminal());
        molto_dry_run_key(&mut sec, &key, pw.as_ref()).unwrap();
        assert!(sec.io.prompts.is_empty(), "{:?}", sec.io.prompts);

        // Piped, but the password comes from elsewhere: nothing is read.
        let (key, pw) = parts(&["--customer-key", "stdin", "--password", "env:P"]);
        let mut sec = Secrets::new(FakeIo::piped(&["11\n"]));
        molto_dry_run_key(&mut sec, &key, pw.as_ref()).unwrap();
        assert_eq!(sec.io.lines_read, 0);
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
            capabilities: vec!["FIDO2", "OATH", "PIV"],
            capabilities_unverified: vec![],
        };
        assert_json_has_keys(
            &d,
            &[
                "vendor",
                "model",
                "serial",
                "transport",
                "kind",
                "capabilities",
                "capabilities_unverified",
            ],
        );
        // The whole overview is one object whose `keys` array holds these.
        let doc = serde_json::to_string(&json_out::KeysJson { keys: vec![d] }).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&doc).unwrap();
        assert!(parsed["keys"].is_array());
    }

    #[test]
    fn molto_info_json_serializes() {
        let m = json_out::MoltoInfoJson {
            serial: "ABC123".into(),
            utc_time: 1_700_000_000,
            drift_seconds: -3,
        };
        assert_json_has_keys(&m, &["serial", "utc_time", "drift_seconds"]);
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
        // U2F-only device: ctap2 present as null.
        let u = json_out::FidoInfoJson {
            device: "/dev/hidraw1".into(),
            channel_id: 1,
            ctaphid_protocol_version: 2,
            firmware: "1.0.0".into(),
            hid_caps: vec!["U2F"],
            hid_caps_raw: 0x08,
            ctap2: None,
        };
        let v = serde_json::to_value(&u).unwrap();
        assert!(v["ctap2"].is_null(), "ctap2 should be null: {v}");
        assert!(v.as_object().unwrap().contains_key("ctap2"));
    }

    #[test]
    fn fido_pin_retries_json_serializes() {
        let p = json_out::FidoPinRetriesJson { pin_retries: 8 };
        assert_json_has_keys(&p, &["pin_retries"]);
    }

    #[test]
    fn probe_skips_every_molto_write_instruction() {
        // The probe's plain sweep sends each INS with P2=00, so any write the
        // device accepts without a key would hit profile #0. Every builder in
        // keyroost-proto that changes the token must be on the skip list.
        let writes = [keyroost_proto::commands::delete_seed(0)];
        for cmd in writes {
            let ins = cmd.apdu[1];
            assert!(
                DESTRUCTIVE_INS.contains(&ins),
                "probe would send {} (INS {ins:02X}) in its sweep",
                cmd.label
            );
        }
        for ins in [0xC5u8, 0xD5, 0xD4, 0xD7, 0xCE, 0x56, 0xD8, 0xE6] {
            assert!(DESTRUCTIVE_INS.contains(&ins), "INS {ins:02X} not skipped");
        }
    }

    #[test]
    fn piv_status_json_serializes() {
        let p = json_out::PivStatusJson {
            version: Some("5.4.3".into()),
            serial: Some("12345678".into()),
            pin_retries: Some(3),
            chuid: Some(json_out::PivChuidJson {
                fasc_n: "d4e739da...".into(),
                guid: "aabbccdd-eeff-1122-3344-556677889900".into(),
                expiration: "2030-01-01".into(),
                signature: "".into(),
                lrc: "".into(),
            }),
            slots: vec![json_out::PivSlotJson {
                slot: "9a".into(),
                slot_name: "authentication (9A)".into(),
                cert_present: true,
                cert_len: 800,
                cert_unreadable: None,
                cert_compressed: false,
            }],
            applet_fingerprint: "YubiKey".into(),
            applet_name: "YubiKey".into(),
            version_firmware: Some("3.35.0".into()),
        };
        assert_json_has_keys(
            &p,
            &[
                "version",
                "serial",
                "pin_retries",
                "chuid",
                "slots",
                "applet_fingerprint",
                "applet_name",
                "version_firmware",
            ],
        );
    }

    #[test]
    fn piv_cert_compression_flags_parse() {
        use keyroost_transport::CertCompression;
        let import = |extra: &[&str]| {
            let mut args = vec![
                "keyroostctl",
                "piv",
                "cert",
                "import",
                "--slot",
                "9d",
                "--in",
                "c.pem",
            ];
            args.extend_from_slice(extra);
            parse(&args).map(|cli| match cli.command {
                Some(Cmd::Piv {
                    cmd:
                        PivCmd::Cert {
                            cmd: PivCertCmd::Import { compression, .. },
                        },
                }) => compression.choice(),
                _ => panic!("expected piv cert import"),
            })
        };
        assert_eq!(import(&[]).unwrap(), CertCompression::Auto);
        assert_eq!(import(&["--compress"]).unwrap(), CertCompression::Always);
        assert_eq!(import(&["--no-compress"]).unwrap(), CertCompression::Never);
        assert!(import(&["--compress", "--no-compress"]).is_err());

        let self_sign = |extra: &[&str]| {
            let mut args = vec![
                "keyroostctl",
                "piv",
                "cert",
                "generate",
                "--slot",
                "9a",
                "--subject",
                "CN=x",
            ];
            args.extend_from_slice(extra);
            parse(&args).map(|cli| match cli.command {
                Some(Cmd::Piv {
                    cmd:
                        PivCmd::Cert {
                            cmd: PivCertCmd::Generate { compression, .. },
                        },
                }) => compression.choice(),
                _ => panic!("expected piv cert generate"),
            })
        };
        assert_eq!(self_sign(&[]).unwrap(), CertCompression::Auto);
        assert_eq!(self_sign(&["--compress"]).unwrap(), CertCompression::Always);
        assert_eq!(
            self_sign(&["--no-compress"]).unwrap(),
            CertCompression::Never
        );
        assert!(self_sign(&["--no-compress", "--compress"]).is_err());
    }

    #[test]
    fn piv_cert_stored_output() {
        // Uncompressed: the existing line stays as it was, no note.
        assert_eq!(stored_compressed_suffix(false, 3087), "");
        // Compressed: the stored size is named.
        assert_eq!(
            stored_compressed_suffix(true, 2900),
            " (stored compressed: 2900 bytes on the card)"
        );
        // The Auto note says why, and words unverified support neutrally.
        let note = AUTO_COMPRESSED_NOTE;
        assert!(note.contains("did not fit"), "{note}");
        assert!(note.contains("stored compressed"), "{note}");
        assert!(note.contains("Windows"), "{note}");
        assert!(note.contains("macOS"), "{note}");
        assert!(note.contains("not been verified"), "{note}");
        assert!(!note.to_lowercase().contains("unsupported"), "{note}");
    }

    #[test]
    fn piv_too_large_with_no_compress_points_at_the_flags() {
        use keyroost_transport::{CertCompression, TransportError};
        let slot = keyroost_piv::Slot::KeyManagement;
        let e = || TransportError::PivCertTooLarge {
            slot,
            len: 6164,
            compressed_len: None,
        };
        let msg = cert_import_error(e(), CertCompression::Never).to_string();
        assert!(msg.contains("may make it fit"), "{msg}");
        assert!(msg.contains("--no-compress"), "{msg}");
        // Auto/Always never reach "not tried"; other errors pass through.
        let msg = cert_import_error(e(), CertCompression::Auto).to_string();
        assert!(!msg.contains("--no-compress"), "{msg}");
        let msg = cert_import_error(TransportError::PivCardFull { slot }, CertCompression::Never)
            .to_string();
        assert!(!msg.contains("--no-compress"), "{msg}");
    }

    #[test]
    fn piv_slot_json_reports_compression_as_a_bool() {
        let slot = |cert_compressed| json_out::PivSlotJson {
            slot: "9d".into(),
            slot_name: "key management (9D)".into(),
            cert_present: true,
            cert_len: 6164,
            cert_unreadable: None,
            cert_compressed,
        };
        let v = serde_json::to_value(slot(true)).expect("serialize");
        assert_eq!(v["cert_compressed"], true);
        let v = serde_json::to_value(slot(false)).expect("serialize");
        assert_eq!(v["cert_compressed"], false, "{v}");
    }

    #[test]
    fn piv_slot_json_reports_an_unreadable_cert_or_null() {
        let slot = |cert_unreadable| json_out::PivSlotJson {
            slot: "9d".into(),
            slot_name: "key management (9D)".into(),
            cert_present: true,
            cert_len: 0,
            cert_unreadable,
            cert_compressed: false,
        };
        let v = serde_json::to_value(slot(Some("damaged"))).expect("serialize");
        assert_eq!(v["cert_unreadable"], "damaged");
        let v = serde_json::to_value(slot(None)).expect("serialize");
        assert!(v["cert_unreadable"].is_null(), "{v}");
        assert!(v.as_object().unwrap().contains_key("cert_unreadable"));
    }

    #[test]
    fn piv_slot_state_words() {
        use keyroost_transport::{CertUnreadable, SlotKeyPresence as K};
        assert_eq!(piv_slot_state(None, false, 0, false, K::NoKey), "empty");
        assert_eq!(
            piv_slot_state(None, false, 0, false, K::Unknown),
            "no certificate (a key may be present)"
        );
        assert_eq!(
            piv_slot_state(None, false, 0, false, K::Present),
            "key present, no certificate"
        );
        assert_eq!(
            piv_slot_state(None, true, 812, true, K::Unknown),
            "cert present (812 bytes, stored compressed)"
        );
        assert_eq!(
            piv_slot_state(None, true, 812, false, K::NoKey),
            "cert present (812 bytes)"
        );
        assert!(
            piv_slot_state(Some(CertUnreadable::Damaged), true, 0, false, K::Unknown)
                .starts_with("cert present but unreadable")
        );
    }

    #[test]
    fn openpgp_status_json_serializes() {
        let o = json_out::OpenpgpStatusJson {
            aid: "d2760001240103040006...".into(),
            serial: Some("12345678".into()),
            sig_algo: "RSA-2048".into(),
            dec_algo: "RSA-2048".into(),
            aut_algo: "RSA-2048".into(),
            fingerprint_sig: Some("aabb...".into()),
            fingerprint_dec: None,
            fingerprint_aut: None,
            user_pin_retries: 3,
            reset_code_retries: 0,
            admin_pin_retries: 3,
            signature_count: Some(7),
        };
        assert_json_has_keys(
            &o,
            &[
                "aid",
                "serial",
                "sig_algo",
                "fingerprint_dec",
                "user_pin_retries",
                "reset_code_retries",
                "admin_pin_retries",
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
        assert_json_has_keys(&c, &["name", "type", "algorithm"]);
        // `oath list` emits one object whose `accounts` array holds these.
        let doc = serde_json::to_string(&json_out::AccountsJson { accounts: vec![c] }).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&doc).unwrap();
        assert!(parsed["accounts"].is_array());
    }

    #[test]
    fn json_algorithm_names_are_lowercase() {
        assert_eq!(oath_algo_json(keyroost_oath::Algorithm::Sha512), "sha512");
        assert_eq!(oath_algo_json(keyroost_oath::Algorithm::Sha256), "sha256");
        assert_eq!(
            otp_algo_json_t2(keyroost_token2otp::Algorithm::Sha1),
            "sha1"
        );
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
                "type",
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
        // `otp list` emits one object whose `accounts` array holds these.
        let doc = serde_json::to_string(&json_out::AccountsJson { accounts: vec![e] }).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&doc).unwrap();
        assert!(parsed["accounts"].is_array());
    }

    #[test]
    fn otp_code_json_serializes() {
        let g = json_out::OtpCodeJson {
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
        // An unknown rp_name is present as null.
        let no_name = json_out::FidoRelyingPartyJson {
            rp_id: "example.org".into(),
            rp_name: None,
            credentials: vec![],
        };
        let v = serde_json::to_value(&no_name).unwrap();
        assert!(v["rp_name"].is_null(), "rp_name should be null: {v}");
        assert!(v.as_object().unwrap().contains_key("rp_name"));
    }

    // ---- large-blob shaping (pure logic; no hardware) ----

    use keyroost_ctap::large_blobs::{LargeBlobArray, LargeBlobEntry};

    /// The CBOR of an opaque RP-style entry map (no keyroost note magic).
    fn opaque_entry_map() -> Vec<u8> {
        use keyroost_ctap::cbor::{encode, Value};
        encode(&Value::Map(vec![
            (
                Value::UInt(1),
                Value::Bytes(vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x99]),
            ),
            (Value::UInt(2), Value::Bytes(vec![1u8; 12])),
            (Value::UInt(3), Value::UInt(4)),
        ]))
    }

    /// An array of the given raw CBOR elements, as read from a key.
    fn large_blob_array_of(elements: &[&[u8]]) -> LargeBlobArray {
        let mut bytes = keyroost_ctap::cbor::array_header(elements.len());
        for e in elements {
            bytes.extend_from_slice(e);
        }
        LargeBlobArray::parse(&bytes).unwrap()
    }

    /// An opaque RP-style entry (no keyroost note magic).
    fn opaque_entry() -> LargeBlobEntry {
        large_blob_array_of(&[&opaque_entry_map()])
            .entry(0)
            .unwrap()
            .clone()
    }

    #[test]
    fn large_blob_list_json_classifies_note_vs_opaque() {
        // A note, an opaque entry, and one element not in the standard
        // format (a bare text string), which is skipped and only counted.
        let note = {
            use keyroost_ctap::cbor::{encode, Value};
            let mut body = keyroost_ctap::large_blobs::KR_NOTE_MAGIC.to_vec();
            body.extend_from_slice(b"hello");
            encode(&Value::Map(vec![
                (Value::UInt(1), Value::Bytes(body)),
                (Value::UInt(2), Value::Bytes(vec![0u8; 12])),
                (Value::UInt(3), Value::UInt(5)),
            ]))
        };
        let array = large_blob_array_of(&[&note, &opaque_entry_map(), &[0x61, 0x78]]);
        let info = keyroost_ctap::AuthenticatorInfo::default();
        let shaped = large_blob_list_json(&array, &info);
        assert_eq!(shaped.entries.len(), 2);
        assert_eq!(shaped.skipped, 1);

        // [0] is a keyroost note: is_note true, text present, size == byte len.
        assert_eq!(shaped.entries[0].index, 0);
        assert!(shaped.entries[0].is_note);
        assert_eq!(shaped.entries[0].text.as_deref(), Some("hello"));
        assert_eq!(shaped.entries[0].size, "hello".len() as u64);
        assert_eq!(shaped.entries[0].kind, "note");
        assert!(shaped.entries[0].ssh_cert.is_none());

        // [1] is opaque: is_note false, no text.
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

        // The opaque entry's text is null in the JSON, and so is a note's
        // ssh_cert; both keys are present.
        let s = serde_json::to_string(&shaped).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        let arr = v.get("entries").unwrap().as_array().unwrap();
        assert_eq!(arr[0]["text"], "hello");
        assert!(arr[1].get("text").is_some_and(|t| t.is_null()));
        assert!(arr[0].get("ssh_cert").is_some_and(|c| c.is_null()));
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
        // text is null for an opaque entry.
        let s = serde_json::to_string(&g).unwrap();
        assert!(s.contains("\"text\":null"), "text should be null: {s}");
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
        assert!(parse(&["keyroostctl", "fido", "blob", "list"]).is_ok());
        assert!(parse(&["keyroostctl", "fido", "blob", "get", "0"]).is_ok());
        assert!(parse(&["keyroostctl", "fido", "blob", "add", "hi"]).is_ok());
        assert!(parse(&["keyroostctl", "fido", "blob", "edit", "1", "new"]).is_ok());
        assert!(parse(&["keyroostctl", "fido", "blob", "delete", "2", "--yes"]).is_ok());
        assert!(parse(&["keyroostctl", "fido", "blob", "clear", "--yes"]).is_ok());
        assert!(parse(&[
            "keyroostctl",
            "fido",
            "blob",
            "export",
            "0",
            "--out",
            "/tmp/out.bin"
        ])
        .is_ok());
        assert!(parse(&[
            "keyroostctl",
            "fido",
            "blob",
            "export",
            "0",
            "--out",
            "/tmp/out-cert.pub",
            "--as-cert"
        ])
        .is_ok());
    }

    #[test]
    fn key_entry_records_serial_and_where_it_came_from() {
        use keyroost_resolve::{Caps, Device, DeviceKind};
        let yk = Device {
            id: "serial:12345678".into(),
            name: None,
            vendor: "Yubico".into(),
            model: "YubiKey 5 NFC".into(),
            serial: "12345678".into(),
            transport: String::new(),
            firmware: String::new(),
            caps: Caps::default(),
            unverified: Caps::default(),
            kind: DeviceKind::Key,
            hid_path: Some("/dev/hidraw16".into()),
            reader: Some("Yubico 00".into()),
        };
        let hid = keyroost_hid::HidDevice {
            path: "/dev/hidraw16".into(),
            vendor_id: 0x1050,
            product_id: 0x0407,
            product_name: "YubiKey".into(),
            usage_page: keyroost_hid::HID_USAGE_PAGE_FIDO,
            usage: keyroost_hid::HID_USAGE_FIDO_AUTHENTICATOR,
            serial_number: None,
            usb_bus: None,
            usb_address: None,
        };
        let e = key_entry_for("work", &yk, std::slice::from_ref(&hid));
        assert_eq!(
            (e.serial.as_str(), e.source, e.vendor.as_deref()),
            ("12345678", keyroost_keyring::IdSource::Ccid, Some("yubico"))
        );
        let mut solo = yk.clone();
        solo.vendor = "SoloKeys".into();
        solo.serial = "07A9".into();
        let mut solo_hid = hid;
        solo_hid.serial_number = Some("07A9".into());
        let e = key_entry_for("s", &solo, &[solo_hid]);
        assert_eq!(
            (e.source, e.vendor),
            (keyroost_keyring::IdSource::Usb, None)
        );
    }

    #[test]
    fn key_name_add_takes_reader_or_path() {
        assert!(parse(&["keyroostctl", "name", "add", "desk", "--reader", "Molto"]).is_ok());
        assert!(parse(&[
            "keyroostctl",
            "name",
            "add",
            "desk",
            "--path",
            "/dev/hidraw3"
        ])
        .is_ok());
    }

    #[test]
    fn nameable_refuses_an_override_row_and_a_blank_serial() {
        use keyroost_resolve::{Caps, Device, DeviceKind};
        let base = Device {
            id: "serial:1".into(),
            name: None,
            vendor: "Yubico".into(),
            model: "YubiKey".into(),
            serial: "1".into(),
            transport: String::new(),
            firmware: String::new(),
            caps: Caps::default(),
            unverified: Caps::default(),
            kind: DeviceKind::Key,
            hid_path: None,
            reader: None,
        };
        // A normal detected row with a serial is nameable.
        assert!(nameable(&base).is_ok());

        // A synthetic --reader/--path override (never detected) is refused,
        // even though target::select skips the capability check for it.
        let mut over = base.clone();
        over.id = "override:Molto".into();
        let err = nameable(&over).unwrap_err();
        assert!(err.contains("didn't detect"), "{err}");

        // A detected row with no serial (e.g. a Molto2, never connected
        // during detection) is refused too, whatever picked it.
        let mut no_serial = base.clone();
        no_serial.serial = String::new();
        no_serial.kind = DeviceKind::Token;
        let err = nameable(&no_serial).unwrap_err();
        assert!(err.contains("can't be named yet"), "{err}");
    }

    #[test]
    fn prog_selection_ignores_other_readers_and_honours_device() {
        use keyroost_resolve::{resolve_target, Caps, Device, DeviceKind, NoPicker, Selector};
        fn d(name: &str, caps: Caps, kind: DeviceKind, reader: &str) -> Device {
            Device {
                id: format!("r:{reader}"),
                name: Some(name.into()),
                vendor: "V".into(),
                model: "M".into(),
                serial: name.into(),
                transport: String::new(),
                firmware: String::new(),
                caps,
                unverified: Caps::default(),
                kind,
                hid_path: None,
                reader: Some(reader.into()),
            }
        }
        let devs = [
            d("yubi-test", Caps::OATH, DeviceKind::Key, "Yubico 00"),
            d("card", Caps::PROG, DeviceKind::ProgToken, "NFC 01"),
        ];
        let t = resolve_target(&devs, &Selector::default(), Need::Prog, &mut NoPicker).unwrap();
        assert_eq!(
            t.device.reader.as_deref(),
            Some("NFC 01"),
            "a YubiKey reader is not a prog candidate"
        );
        let s = Selector {
            device: Some("yubi-test"),
            ..Default::default()
        };
        assert!(
            resolve_target(&devs, &s, Need::Prog, &mut NoPicker).is_err(),
            "--device naming another key must refuse, not write"
        );
    }

    /// The `--yes` of each command that asks before erasing or replacing
    /// something the host can't restore; `None` for any other command.
    fn confirm_yes(cli: &Cli) -> Option<bool> {
        let yes = match cli.command.as_ref()? {
            Cmd::Piv {
                cmd:
                    PivCmd::Key {
                        cmd: PivKeyCmd::Generate { yes, .. },
                    }
                    | PivCmd::Cert {
                        cmd: PivCertCmd::Import { yes, .. },
                    }
                    | PivCmd::Retries {
                        cmd: PivRetriesCmd::Set { yes, .. },
                    }
                    | PivCmd::Cert {
                        cmd: PivCertCmd::Generate { yes, .. },
                    }
                    | PivCmd::Cert {
                        cmd: PivCertCmd::Request { yes, .. },
                    },
            } => yes,
            Cmd::Oath {
                cmd: OathCmd::Delete { yes, .. },
                ..
            } => yes,
            Cmd::Otp {
                cmd:
                    OtpCmd::Delete { yes, .. }
                    | OtpCmd::Button {
                        cmd: OtpButtonCmd::Set { yes, .. } | OtpButtonCmd::Delete { yes },
                    },
                ..
            } => yes,
            Cmd::Fido {
                cmd:
                    FidoCmd::Credential {
                        cmd: FidoCredentialCmd::Delete { yes, .. },
                    }
                    | FidoCmd::Fingerprint {
                        cmd: FidoFingerprintCmd::Delete { yes, .. },
                    },
            } => yes,
            Cmd::Molto {
                cmd:
                    MoltoCmd::Seed { yes, .. }
                    | MoltoCmd::Import { yes, .. }
                    | MoltoCmd::CustomerKey { yes, .. },
                ..
            } => yes,
            Cmd::Prog {
                cmd: ProgCmd::Seed { yes, .. } | ProgCmd::Config { yes, .. },
            } => yes,
            _ => return None,
        };
        Some(*yes)
    }

    #[test]
    fn customer_key_has_yes() {
        for (a, want) in [
            (&["keyroostctl", "molto", "customer-key"][..], false),
            (&["keyroostctl", "molto", "customer-key", "--yes"], true),
        ] {
            let cli = parse(a).unwrap();
            assert_eq!(confirm_yes(&cli), Some(want), "{a:?}");
        }
    }

    #[test]
    fn piv_key_move_takes_no_yes_and_never_replaces() {
        // Moving refuses a destination the card reports holds a key, so there
        // is nothing to confirm.
        assert!(parse(&[
            "keyroostctl",
            "piv",
            "key",
            "move",
            "--from",
            "9a",
            "--to",
            "9c",
            "--yes"
        ])
        .is_err());
        let cli = parse(&[
            "keyroostctl",
            "piv",
            "key",
            "move",
            "--from",
            "9a",
            "--to",
            "9c",
        ])
        .unwrap();
        assert_eq!(confirm_yes(&cli), None);
        let move_cmd = all_commands()
            .into_iter()
            .find(|(p, _)| p == "piv key move")
            .unwrap()
            .1;
        let help = format!(
            "{} {}",
            move_cmd
                .get_about()
                .map(|s| s.to_string())
                .unwrap_or_default(),
            move_cmd
                .get_long_about()
                .map(|s| s.to_string())
                .unwrap_or_default()
        );
        assert!(help.contains(
            "Refuses when the card reports that the destination slot already holds a key"
        ));
        assert!(help.contains("When keyroost can't tell, it says so and sends the move"));
        assert!(!help.contains("Irreversible") && !help.contains("replace"));
    }

    #[test]
    fn piv_slot_counts_as_empty_only_on_reference_not_found() {
        let not_found = Some(keyroost_piv::SW_REFERENCE_NOT_FOUND);
        // The one empty case: no quirk, 6A88, no certificate.
        assert!(piv_slot_empty_from(not_found, false, true));
        // Transmit error, or the read not sent at all: ask.
        assert!(!piv_slot_empty_from(None, false, true));
        // A metadata quirk makes the card's answer untrustworthy: ask.
        assert!(!piv_slot_empty_from(not_found, true, true));
        // Any other reply — a key, or a body that may or may not be one: ask.
        assert!(!piv_slot_empty_from(Some(keyroost_piv::SW_OK), false, true));
        assert!(!piv_slot_empty_from(Some(0x6A82), false, true));
        assert!(!piv_slot_empty_from(Some(0x6D00), false, true));
        // No key but a certificate (or one that can't be read): ask.
        assert!(!piv_slot_empty_from(not_found, false, false));
    }

    #[test]
    fn piv_metadata_quirks_are_recognised() {
        use keyroost_piv::compat::PivQuirk;
        use std::collections::BTreeSet;
        assert!(!piv_metadata_quirky(&BTreeSet::new()));
        assert!(piv_metadata_quirky(&BTreeSet::from([
            PivQuirk::InsF7MetadataAlgorithmInvalid
        ])));
        assert!(piv_metadata_quirky(&BTreeSet::from([
            PivQuirk::InsF7MetadataPinTouchPolicyInvalid
        ])));
    }

    #[test]
    fn piv_certificate_is_absent_only_when_read_and_missing() {
        assert!(piv_cert_absent_from::<()>(&Ok(None)));
        assert!(!piv_cert_absent_from::<()>(&Ok(Some(vec![0x30]))));
        assert!(!piv_cert_absent_from(&Err(())));
    }

    #[test]
    fn button_hotp_is_assumed_configured_unless_the_config_says_not() {
        use keyroost_token2otp::DeviceInfo;
        // Unreadable configuration: ask.
        assert!(button_hotp_maybe_configured(None));
        // A short CCID/NFC stub without the config byte: ask.
        let stub = DeviceInfo::parse(&[0x07]).unwrap();
        assert!(!stub.has_config_byte());
        assert!(button_hotp_maybe_configured(Some(&stub)));
        // Config byte present, button seed bit set: ask.
        let set = DeviceInfo::parse(&[0x07, 0x80, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        assert!(button_hotp_maybe_configured(Some(&set)));
        // Config byte present, bit clear: genuinely empty, no question.
        let clear = DeviceInfo::parse(&[0x07, 0x00, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        assert!(!button_hotp_maybe_configured(Some(&clear)));
    }

    #[test]
    fn slot_name_is_the_value_typed_on_the_command_line() {
        assert_eq!(slot_name(CliPivSlot::Auth), "9a");
        assert_eq!(slot_name(CliPivSlot::CardAuth), "9e");
        assert_eq!(slot_name(CliPivSlot::Retired9), "8a");
    }

    #[test]
    fn bulk_import_asks_only_about_slots_it_writes() {
        let titled = |uri: &str| -> keyroost_import::BulkEntry {
            keyroost_import::parse_otpauth(uri).unwrap().into()
        };
        let entries = vec![
            titled("otpauth://totp/a?secret=JBSWY3DP"),
            // No issuer and no account: the import skips this slot.
            titled("otpauth://totp/?secret=JBSWY3DP"),
            titled("otpauth://totp/c?secret=JBSWY3DP"),
        ];
        assert!(entries[1].suggested_title().is_empty());
        assert_eq!(bulk_import_slots(97, &entries), vec![97, 99]);
        assert!(bulk_import_slots(0, &[]).is_empty());
    }

    #[test]
    fn newly_confirmed_commands_take_yes() {
        for args in [
            &["keyroostctl", "piv", "key", "generate", "--slot", "9a"][..],
            &[
                "keyroostctl",
                "piv",
                "cert",
                "import",
                "--slot",
                "9c",
                "--in",
                "c.pem",
            ],
            &[
                "keyroostctl",
                "piv",
                "retries",
                "set",
                "--pin-tries",
                "3",
                "--puk-tries",
                "3",
            ],
            &[
                "keyroostctl",
                "piv",
                "cert",
                "generate",
                "--slot",
                "9d",
                "--subject",
                "CN=x",
            ],
            &[
                "keyroostctl",
                "piv",
                "cert",
                "request",
                "--slot",
                "9e",
                "--subject",
                "CN=x",
                "--generate-key",
            ],
            &["keyroostctl", "oath", "delete", "x"],
            &["keyroostctl", "otp", "delete", "--account", "a"],
            &["keyroostctl", "otp", "button", "set", "--seed", "stdin"],
            &["keyroostctl", "otp", "button", "delete"],
            &["keyroostctl", "fido", "credential", "delete", "--id", "00"],
            &["keyroostctl", "fido", "fingerprint", "delete", "--id", "00"],
            &[
                "keyroostctl",
                "molto",
                "seed",
                "--slot",
                "99",
                "--seed",
                "stdin",
            ],
            &[
                "keyroostctl",
                "molto",
                "import",
                "--slot",
                "99",
                "--uri",
                "stdin",
            ],
            &["keyroostctl", "molto", "import", "--file", "f.json"],
            &["keyroostctl", "prog", "seed", "--seed", "stdin"],
            &["keyroostctl", "prog", "config"],
        ] {
            let without = parse(args).unwrap_or_else(|e| panic!("{args:?}: {e}"));
            assert_eq!(confirm_yes(&without), Some(false), "{args:?}");
            let with: Vec<&str> = args.iter().copied().chain(["--yes"]).collect();
            let with = parse(&with).unwrap_or_else(|e| panic!("{args:?} --yes: {e}"));
            assert_eq!(confirm_yes(&with), Some(true), "{args:?} --yes");
        }
    }

    #[test]
    fn device_flag_is_refused_where_it_has_no_effect() {
        for (args, what) in [
            (&["keyroostctl", "doctor"][..], Some("doctor")),
            (&["keyroostctl", "completions", "bash"], Some("completions")),
            (&["keyroostctl", "manpage", "d"], Some("manpage")),
            (&["keyroostctl", "name", "list"], Some("name list")),
            (&["keyroostctl", "name", "delete", "x"], Some("name delete")),
            (
                &[
                    "keyroostctl",
                    "molto",
                    "import",
                    "--dry-run",
                    "--file",
                    "x.json",
                ],
                Some("molto import --dry-run"),
            ),
            (
                &["keyroostctl", "molto", "import", "--file", "x.json"],
                None,
            ),
            (&["keyroostctl", "list"], None),
            (&["keyroostctl", "name", "add", "x"], None),
            (&["keyroostctl", "piv", "info"], None),
        ] {
            let cli = parse(args).unwrap();
            assert_eq!(inert_device_flag(cli.command.as_ref()), what, "{args:?}");
        }
    }

    #[test]
    fn filter_rows_matches_exactly_or_errors() {
        use keyroost_resolve::{Caps, Device, DeviceKind};
        let mk = |name: Option<&str>, serial: &str, reader: Option<&str>| Device {
            id: format!("s:{serial}"),
            name: name.map(str::to_owned),
            vendor: "Yubico".into(),
            model: "YubiKey 5".into(),
            serial: serial.into(),
            transport: String::new(),
            firmware: String::new(),
            caps: Caps::FIDO2,
            unverified: Caps::default(),
            kind: DeviceKind::Key,
            hid_path: Some("/dev/hidraw1".into()),
            reader: reader.map(str::to_owned),
        };
        let devs = [
            mk(Some("yubi-test"), "2", Some("Y 00")),
            mk(None, "1", None),
        ];

        // No --device: every row, numbered in list order.
        let rows = filter_rows(&devs, None).unwrap();
        assert_eq!(rows.iter().map(|(n, _)| *n).collect::<Vec<_>>(), vec![1, 2]);

        // --device given: exactly the matching row and its list number come back.
        let rows = filter_rows(&devs, Some("yubi-test")).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, 2);
        assert_eq!(rows[0].1.name.as_deref(), Some("yubi-test"));

        // An unknown value is an error naming the fix (not a silent empty list).
        match filter_rows(&devs, Some("nope")) {
            Err(e) => assert!(e.to_string().contains("--device"), "{e}"),
            Ok(_) => panic!("expected an error for an unknown --device value"),
        }
    }

    #[test]
    fn list_json_rows_carry_the_exact_device_value() {
        use keyroost_resolve::{Caps, Device, DeviceKind};
        let mk = |name: Option<&str>, serial: &str, reader: Option<&str>| Device {
            id: format!("s:{serial}"),
            name: name.map(str::to_owned),
            vendor: "Yubico".into(),
            model: "YubiKey 5".into(),
            serial: serial.into(),
            transport: String::new(),
            firmware: String::new(),
            caps: Caps::FIDO2,
            unverified: Caps::default(),
            kind: DeviceKind::Key,
            hid_path: Some("/dev/hidraw1".into()),
            reader: reader.map(str::to_owned),
        };
        let devs = [
            mk(Some("yubi-test"), "2", Some("Y 00")),
            mk(None, "1", None),
        ];
        let rows = list_json_rows(&devs, &overview::numbered(&devs));
        let v = serde_json::to_value(&rows).unwrap();
        assert_eq!(v[0]["number"], 1);
        assert_eq!(v[0]["device"], "1");
        assert_eq!(v[1]["device"], "yubi-test");
        assert_eq!(v[1]["readers"], serde_json::json!(["Y 00"]));
        assert_eq!(v[1]["hid_paths"], serde_json::json!(["/dev/hidraw1"]));
        assert_eq!(v[1]["capabilities"], serde_json::json!(["FIDO2"]));
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
        /// The shared resolver hands back a device only when exactly one
        /// connected device carries the `--device` name — zero or two-plus
        /// named devices both fail closed (KEY-015).
        #[test]
        fn device_name_selection_fails_closed_on_ambiguity(specs in any_devices()) {
            let devices: Vec<_> =
                specs.iter().map(|(n, o, h, r)| dev(*n, *o, *h, *r)).collect();
            let named = devices.iter().filter(|d| d.name.as_deref() == Some("alpha")).count();
            let got = keyroost_resolve::resolve_target(
                &devices,
                &keyroost_resolve::Selector { device: Some("alpha"), ..Default::default() },
                Need::Any,
                &mut keyroost_resolve::NoPicker,
            );
            match got {
                Ok(t) => { prop_assert_eq!(named, 1); prop_assert_eq!(t.device.name.as_deref(), Some("alpha")); }
                Err(_) => prop_assert_ne!(named, 1),
            }
        }

        /// `otp_target_for` maps an already-selected device's HID path
        /// and/or reader to the requested transport's endpoint — HID first,
        /// the device's own reader as the `auto` open-time fallback (#82) —
        /// and fails closed when the device lacks the endpoint a specific
        /// transport needs. Device name-match / ambiguity is the shared
        /// resolver's job now (`resolve_target`, tested on its own), so this
        /// only varies the one selected device's endpoints.
        #[test]
        fn otp_target_for_maps_every_endpoint(
            hid in proptest::option::of(Just("/dev/hidraw9")),
            reader in proptest::option::of(Just("Acme CCID 00")),
            transport in any_transport(),
        ) {
            let device = dev(None, false, hid, reader);
            let got = otp_target_for(&device, transport);
            match transport {
                OtpTransportArg::Hid => match (got, hid) {
                    (Ok(OtpTarget::HidPath(p)), Some(h)) => prop_assert_eq!(p, PathBuf::from(h)),
                    (Err(_), None) => {}
                    (got, hid) => prop_assert!(false, "got={got:?} hid={hid:?}"),
                },
                OtpTransportArg::Ccid => match (got, reader) {
                    (Ok(OtpTarget::Reader(r)), Some(rd)) => prop_assert_eq!(r, rd),
                    (Err(_), None) => {}
                    (got, reader) => prop_assert!(false, "got={got:?} reader={reader:?}"),
                },
                OtpTransportArg::Auto => match (got, hid, reader) {
                    (Ok(OtpTarget::HidThenReader(p, r)), Some(h), Some(rd)) => {
                        prop_assert_eq!(p, PathBuf::from(h));
                        prop_assert_eq!(r, rd);
                    }
                    (Ok(OtpTarget::HidPath(p)), Some(h), None) => {
                        prop_assert_eq!(p, PathBuf::from(h))
                    }
                    (Ok(OtpTarget::Reader(r)), None, Some(rd)) => prop_assert_eq!(r, rd),
                    (Err(_), None, None) => {}
                    (got, hid, reader) => {
                        prop_assert!(false, "got={got:?} hid={hid:?} reader={reader:?}")
                    }
                },
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
