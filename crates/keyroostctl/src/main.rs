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

/// The global `--name` selector, captured once in `run()` so the FIDO device
/// resolver can honor it without threading it through every subcommand handler.
static SELECTED_KEY_NAME: OnceLock<Option<String>> = OnceLock::new();

#[derive(Parser)]
#[command(
    name = "keyroostctl",
    version,
    about = "Program Token2 Molto2 / Molto2v2 TOTP tokens"
)]
struct Cli {
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

    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print device serial number and on-device UTC time.
    Info,
    /// Write a TOTP seed to a profile slot. The seed can come from argv
    /// (--hex/--base32 — visible in `ps` and shell history), an environment
    /// variable, or stdin; supply exactly one source.
    SetSeed {
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
    SetTitle {
        #[arg(short, long)]
        profile: u8,
        title: String,
    },
    /// Set profile TOTP configuration (and seed the clock with the host's UTC time).
    Configure {
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
    SetCustomerKey {
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
        /// The otpauth:// URI. Use single quotes to protect & from the shell.
        /// Argv is visible in `ps` and shell history (the URI embeds the
        /// secret); pass `-` to read the URI from stdin instead.
        uri: String,
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
    FactoryReset {
        /// Confirm you really want to wipe the device.
        #[arg(long)]
        yes: bool,
    },
    /// List connected devices: PC/SC readers and FIDO HID authenticators.
    List {
        /// Show every HID device, not just those advertising the FIDO usage page.
        #[arg(long)]
        all_hid: bool,
    },
    /// Run `authenticatorGetInfo` against a connected FIDO authenticator.
    FidoInfo {
        /// hidraw path to use. If omitted, auto-pick the only connected FIDO device.
        #[arg(long, value_name = "PATH")]
        path: Option<std::path::PathBuf>,
    },
    /// Run `authenticatorReset`, wiping all credentials on the key.
    ///
    /// Most authenticators only accept Reset within ~10s of plug-in and
    /// require a physical touch. If `--yes` is missing this is a no-op.
    FidoReset {
        /// Confirm you really want to wipe credentials.
        #[arg(long)]
        yes: bool,
        /// hidraw path to use. If omitted, auto-pick the only connected FIDO device.
        #[arg(long, value_name = "PATH")]
        path: Option<std::path::PathBuf>,
    },
    /// Print the current PIN retry counter.
    FidoPinRetries {
        #[arg(long, value_name = "PATH")]
        path: Option<std::path::PathBuf>,
    },
    /// Set the initial PIN on an authenticator that doesn't have one yet.
    FidoPinSet {
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
    FidoPinChange {
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
    FidoCredsMetadata {
        #[arg(long, value_name = "VAR", conflicts_with = "pin_stdin")]
        pin_env: Option<String>,
        #[arg(long)]
        pin_stdin: bool,
        #[arg(long, value_name = "PATH")]
        path: Option<std::path::PathBuf>,
    },
    /// List every resident credential on the authenticator, grouped by RP.
    FidoCredsList {
        #[arg(long, value_name = "VAR", conflicts_with = "pin_stdin")]
        pin_env: Option<String>,
        #[arg(long)]
        pin_stdin: bool,
        #[arg(long, value_name = "PATH")]
        path: Option<std::path::PathBuf>,
    },
    /// Delete a single resident credential by its hex-encoded credentialId.
    FidoCredsDelete {
        /// Hex-encoded credentialId as printed by `fido-creds-list`.
        #[arg(long, value_name = "HEX")]
        cred_id: String,
        #[arg(long, value_name = "VAR", conflicts_with = "pin_stdin")]
        pin_env: Option<String>,
        #[arg(long)]
        pin_stdin: bool,
        #[arg(long, value_name = "PATH")]
        path: Option<std::path::PathBuf>,
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
    /// Read PIV (smartcard) status on a security key over PC/SC (read-only).
    Piv {
        #[command(subcommand)]
        cmd: PivCmd,
    },
}

/// PIV subcommands. Read-only for now (see PLAN.md for the write/auth roadmap).
#[derive(Subcommand)]
enum PivCmd {
    /// Show PIV status: version, serial, PIN retries, and which key slots hold a
    /// certificate. No PIN or touch required.
    Status {
        #[arg(long, value_name = "SUBSTR")]
        reader: Option<String>,
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
    fn password(&self) -> Result<Option<String>, Box<dyn std::error::Error>> {
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

fn customer_key_bytes(cli: &Cli) -> Result<Vec<u8>, String> {
    if let Some(h) = &cli.key {
        hex_decode(h).map_err(|e| format!("invalid --key hex: {}", e))
    } else if let Some(s) = &cli.key_ascii {
        Ok(s.as_bytes().to_vec())
    } else if let Some(var) = &cli.key_env {
        let h = std::env::var(var).map_err(|_| format!("env var {} (--key-env) is not set", var))?;
        hex_decode(&h).map_err(|e| format!("invalid hex in --key-env {}: {}", var, e))
    } else if let Some(var) = &cli.key_ascii_env {
        std::env::var(var)
            .map(|s| s.into_bytes())
            .map_err(|_| format!("env var {} (--key-ascii-env) is not set", var))
    } else {
        Ok(DEFAULT_CUSTOMER_KEY.to_vec())
    }
}

fn unix_now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

/// Load a bulk-import file, transparently decrypting an Aegis encrypted
/// vault if `--password-stdin` or `--password-env` was supplied.
fn load_bulk_entries(
    path: &std::path::Path,
    password_stdin: bool,
    password_env: Option<&str>,
) -> Result<Vec<keyroost_import::BulkEntry>, Box<dyn std::error::Error>> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {}", path.display(), e))?;

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

fn read_password(stdin: bool, env_var: Option<&str>) -> Option<String> {
    if let Some(name) = env_var {
        return std::env::var(name).ok();
    }
    if stdin {
        let mut s = String::new();
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

    if cli.list_readers {
        for r in Session::list_readers()? {
            println!("{}", r);
        }
        return Ok(());
    }

    let Some(cmd) = cli.command.as_ref() else {
        // No subcommand → show info, mirroring molto2.py's bare-invocation behavior.
        let mut session = Session::open()?;
        session.set_debug(cli.debug);
        let info = session.read_info()?;
        print_info(&info);
        return Ok(());
    };

    // --dry-run on bulk import doesn't need the device at all.
    if let Cmd::ImportFile {
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
    if let Cmd::Info = cmd {
        let mut session = Session::open()?;
        session.set_debug(cli.debug);
        let info = session.read_info()?;
        print_info(&info);
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
    if let Cmd::FidoInfo { path } = cmd {
        run_fido_info(path.as_deref())?;
        return Ok(());
    }
    if let Cmd::FidoReset { yes, path } = cmd {
        if !*yes {
            return Err("refusing to reset FIDO key without --yes (this wipes credentials)".into());
        }
        run_fido_reset(path.as_deref())?;
        return Ok(());
    }
    if let Cmd::FidoPinRetries { path } = cmd {
        run_fido_pin_retries(path.as_deref())?;
        return Ok(());
    }
    if let Cmd::FidoPinSet {
        new_pin_env,
        new_pin_stdin,
        path,
    } = cmd
    {
        let new_pin = read_secret("new PIN", new_pin_env.as_deref(), *new_pin_stdin)?;
        run_fido_pin_set(path.as_deref(), &new_pin)?;
        return Ok(());
    }
    if let Cmd::FidoPinChange {
        old_pin_env,
        old_pin_stdin,
        new_pin_env,
        new_pin_stdin,
        path,
    } = cmd
    {
        let old_pin = read_secret("old PIN", old_pin_env.as_deref(), *old_pin_stdin)?;
        let new_pin = read_secret("new PIN", new_pin_env.as_deref(), *new_pin_stdin)?;
        run_fido_pin_change(path.as_deref(), &old_pin, &new_pin)?;
        return Ok(());
    }
    if let Cmd::FidoCredsMetadata {
        pin_env,
        pin_stdin,
        path,
    } = cmd
    {
        let pin = read_secret("PIN", pin_env.as_deref(), *pin_stdin)?;
        run_fido_creds_metadata(path.as_deref(), &pin)?;
        return Ok(());
    }
    if let Cmd::FidoCredsList {
        pin_env,
        pin_stdin,
        path,
    } = cmd
    {
        let pin = read_secret("PIN", pin_env.as_deref(), *pin_stdin)?;
        run_fido_creds_list(path.as_deref(), &pin)?;
        return Ok(());
    }
    if let Cmd::FidoCredsDelete {
        cred_id,
        pin_env,
        pin_stdin,
        path,
    } = cmd
    {
        let pin = read_secret("PIN", pin_env.as_deref(), *pin_stdin)?;
        let cred_id_bytes =
            hex_decode(cred_id).map_err(|e| format!("--cred-id is not valid hex: {}", e))?;
        run_fido_creds_delete(path.as_deref(), &pin, &cred_id_bytes)?;
        return Ok(());
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

    // Factory reset is a plain CLA 0x80 command and needs no auth.
    if let Cmd::FactoryReset { yes } = cmd {
        if !yes {
            return Err("refusing to factory-reset without --yes".into());
        }
        let mut session = Session::open()?;
        session.set_debug(cli.debug);
        let info = session.read_info()?;
        print_info(&info);
        println!("requesting factory reset; confirm with the up-arrow button on the device");
        session.factory_reset()?;
        return Ok(());
    }

    // Probe walks unauth (and optionally auth) APDU space; it doesn't fit the
    // standard "open → auth → run command" flow because each transmission is
    // expected to fail with a non-9000 SW.
    if let Cmd::Probe {
        yes,
        authed,
        include_destructive,
        slot,
    } = cmd
    {
        if !yes {
            return Err("refusing to probe without --yes (see `keyroostctl probe --help`)".into());
        }
        let mut session = Session::open()?;
        session.set_debug(cli.debug);
        let info = session.read_info()?;
        print_info(&info);
        if *authed {
            let key = customer_key_bytes(&cli)?;
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

    let key = customer_key_bytes(&cli)?;
    let mut session = Session::open()?;
    session.set_debug(cli.debug);
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
        Cmd::Info => unreachable!("handled above before auth"),
        Cmd::SetSeed {
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
        Cmd::SetTitle { profile, title } => {
            if title.is_empty() || title.len() > 12 {
                return Err("title must be 1..=12 bytes".into());
            }
            session.set_title(*profile, title)?;
            println!("title set on profile #{}", profile);
        }
        Cmd::Configure {
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
        Cmd::SyncTime { profile, all } => {
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
        Cmd::SetCustomerKey {
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
        Cmd::Import {
            profile,
            title,
            display_timeout,
            uri,
        } => {
            // `-` reads the URI (whose secret= parameter is the seed) from
            // stdin so it stays out of /proc/*/cmdline and shell history.
            let uri = if uri == "-" {
                use std::io::BufRead;
                let mut line = String::new();
                std::io::stdin().lock().read_line(&mut line)?;
                line.trim_end_matches(['\r', '\n']).to_owned()
            } else {
                uri.clone()
            };
            let parsed = keyroost_import::parse_otpauth(&uri)?;
            let final_title = title.clone().unwrap_or_else(|| parsed.suggested_title());
            if final_title.is_empty() || final_title.len() > 12 {
                return Err(format!(
                    "derived title {:?} must be 1..=12 bytes; pass --title to override",
                    final_title
                )
                .into());
            }
            session.set_seed(*profile, &parsed.secret)?;
            session.set_title(*profile, &final_title)?;
            session.set_config(
                *profile,
                &parsed.to_profile_config(unix_now(), display_timeout.to_proto()),
            )?;
            println!(
                "imported {:?} to profile #{} ({} bytes secret, {:?}, {} digits)",
                final_title,
                profile,
                parsed.secret.len(),
                parsed.algorithm,
                parsed.digits as u8
            );
        }
        Cmd::ImportFile {
            path,
            start,
            display_timeout,
            dry_run,
            password_stdin,
            password_env,
        } => {
            let _ = dry_run; // dry-run is handled before auth
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
                if *dry_run {
                    continue;
                }
                session.set_seed(p, &entry.secret)?;
                session.set_title(p, &title)?;
                session.set_config(
                    p,
                    &entry.to_profile_config(unix_now(), display_timeout.to_proto()),
                )?;
            }
            if *dry_run {
                println!("dry-run: nothing written");
            } else {
                println!("done");
            }
        }
        Cmd::FactoryReset { .. } => unreachable!("handled above before auth"),
        Cmd::Probe { .. } => unreachable!("handled above before auth"),
        Cmd::List { .. } => unreachable!("handled above before auth"),
        Cmd::KeyName { .. } => unreachable!("handled above before auth"),
        Cmd::Oath { .. } => unreachable!("handled above before auth"),
        Cmd::Openpgp { .. } => unreachable!("handled above before auth"),
        Cmd::Piv { .. } => unreachable!("handled above before auth"),
        Cmd::FidoInfo { .. }
        | Cmd::FidoReset { .. }
        | Cmd::FidoPinRetries { .. }
        | Cmd::FidoPinSet { .. }
        | Cmd::FidoPinChange { .. }
        | Cmd::FidoCredsMetadata { .. }
        | Cmd::FidoCredsList { .. }
        | Cmd::FidoCredsDelete { .. } => {
            unreachable!("FIDO commands handled above before PC/SC auth")
        }
    }
    Ok(())
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
    let header = if all_hid {
        "HID devices:"
    } else {
        "FIDO HID devices:"
    };
    println!("{}", header);
    match keyroost_hid::enumerate() {
        Ok(devices) => {
            let filtered: Vec<_> = devices
                .into_iter()
                .filter(|d| all_hid || d.is_fido())
                .collect();
            if filtered.is_empty() {
                println!("  (none)");
                if let Some(bl) = keyroost_hid::bootloader_device_present() {
                    println!("  note: detected {bl} — re-plug it to return to application mode.");
                }
            } else {
                let keyring = Keyring::load_default().unwrap_or_default();
                let ccid = ccid_readers_if_needed(&filtered);
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
                    println!(
                        "  {} {:04x}:{:04x} usage={:04x}:{:04x} {}{}{}{}",
                        d.path.display(),
                        d.vendor_id,
                        d.product_id,
                        d.usage_page,
                        d.usage,
                        d.product_name,
                        serial,
                        name,
                        tag,
                    );
                }
            }
        }
        Err(e) => println!("  (unavailable: {})", e),
    }
    Ok(())
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
    let name = resolve_oath_reader(access.reader.as_deref())?;
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
            let readers = keyroost_transport::OpenPgpSession::list_openpgp_readers()?;
            let name = resolve_reader(readers, reader.as_deref(), "OpenPGP")?;
            eprintln!("\u{2192} OpenPGP on {}", name);
            let mut session = keyroost_transport::OpenPgpSession::open(&name)?;
            session.set_debug(debug);
            let status = session.status()?;

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
            let readers = keyroost_transport::OpenPgpSession::list_openpgp_readers()?;
            let name = resolve_reader(readers, reader.as_deref(), "OpenPGP")?;
            eprintln!("\u{2192} OpenPGP on {}", name);
            let mut session = keyroost_transport::OpenPgpSession::open(&name)?;
            session.set_debug(debug);
            session.verify_pin(pin.pw_ref(), pin_value.as_bytes())?;
            println!("{} PIN verified.", pin.label());
        }
        OpenpgpCmd::PublicKey { slot, reader } => {
            let readers = keyroost_transport::OpenPgpSession::list_openpgp_readers()?;
            let name = resolve_reader(readers, reader.as_deref(), "OpenPGP")?;
            eprintln!("\u{2192} OpenPGP on {}", name);
            let mut session = keyroost_transport::OpenPgpSession::open(&name)?;
            session.set_debug(debug);
            let key = session.read_public_key(slot.to_crt())?;
            println!("{} key (RSA):", slot.label());
            println!("  modulus:  {}", hex_encode(&key.modulus));
            println!("  exponent: {}", hex_encode(&key.exponent));
        }
        OpenpgpCmd::Reset { yes, reader } => {
            if !yes {
                return Err("refusing to reset without --yes (this wipes ALL OpenPGP \
                            keys and resets PINs to defaults)"
                    .into());
            }
            let readers = keyroost_transport::OpenPgpSession::list_openpgp_readers()?;
            let name = resolve_reader(readers, reader.as_deref(), "OpenPGP")?;
            eprintln!("\u{2192} OpenPGP on {}", name);
            let mut session = keyroost_transport::OpenPgpSession::open(&name)?;
            session.set_debug(debug);
            session.factory_reset()?;
            println!("OpenPGP applet reset. All keys wiped; PINs restored to defaults.");
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
            let readers = keyroost_transport::OpenPgpSession::list_openpgp_readers()?;
            let name = resolve_reader(readers, reader.as_deref(), "OpenPGP")?;
            eprintln!("\u{2192} OpenPGP on {}", name);
            let mut session = keyroost_transport::OpenPgpSession::open(&name)?;
            session.set_debug(debug);
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

            let readers = keyroost_transport::OpenPgpSession::list_openpgp_readers()?;
            let name = resolve_reader(readers, reader.as_deref(), "OpenPGP")?;
            eprintln!("\u{2192} OpenPGP on {}", name);
            let mut session = keyroost_transport::OpenPgpSession::open(&name)?;
            session.set_debug(debug);
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
            let readers = keyroost_transport::OpenPgpSession::list_openpgp_readers()?;
            let name = resolve_reader(readers, reader.as_deref(), "OpenPGP")?;
            eprintln!("\u{2192} OpenPGP on {}", name);
            let mut session = keyroost_transport::OpenPgpSession::open(&name)?;
            session.set_debug(debug);
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
            let readers = keyroost_transport::OpenPgpSession::list_openpgp_readers()?;
            let name = resolve_reader(readers, reader.as_deref(), "OpenPGP")?;
            eprintln!("\u{2192} OpenPGP on {}", name);
            let mut session = keyroost_transport::OpenPgpSession::open(&name)?;
            session.set_debug(debug);
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
            let readers = keyroost_transport::OpenPgpSession::list_openpgp_readers()?;
            let name = resolve_reader(readers, reader.as_deref(), "OpenPGP")?;
            eprintln!("\u{2192} OpenPGP on {}", name);
            let mut session = keyroost_transport::OpenPgpSession::open(&name)?;
            session.set_debug(debug);
            session.verify_pin(keyroost_openpgp::PW1_SIGN, pin.as_bytes())?;
            eprintln!("Signing ({}) — touch the key if it blinks…", hash.label());
            let sig = session.sign(&digest_info)?;
            match out {
                Some(path) => {
                    std::fs::write(path, &sig)
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
            let readers = keyroost_transport::OpenPgpSession::list_openpgp_readers()?;
            let name = resolve_reader(readers, reader.as_deref(), "OpenPGP")?;
            eprintln!("\u{2192} OpenPGP on {}", name);
            let mut session = keyroost_transport::OpenPgpSession::open(&name)?;
            session.set_debug(debug);
            // Decryption authorizes under PW1 in the "other"/decipher context
            // (ref 0x82), not the signing context (0x81).
            session.verify_pin(keyroost_openpgp::PW1_OTHER, pin.as_bytes())?;
            eprintln!("Decrypting — touch the key if it blinks…");
            let plain = session.decrypt(&cryptogram)?;
            match out {
                Some(path) => {
                    std::fs::write(path, &plain)
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
    }
    Ok(())
}

fn run_piv(cmd: &PivCmd, debug: bool) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        PivCmd::Status { reader } => {
            let readers = keyroost_transport::PivSession::list_piv_readers()?;
            let name = resolve_reader(readers, reader.as_deref(), "PIV")?;
            eprintln!("\u{2192} PIV on {}", name);
            let mut session = keyroost_transport::PivSession::open(&name)?;
            session.set_debug(debug);
            let status = session.status()?;

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
    }
    Ok(())
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

fn run_fido_info(path: Option<&std::path::Path>) -> Result<(), Box<dyn std::error::Error>> {
    let path = resolve_fido_path(path)?;
    let (mut dev, init) = keyroost_ctap::CtapHidDevice::open(&path)?;
    println!("Device:    {}", path.display());
    println!(
        "Channel:   {:#010x} (CTAPHID protocol v{})",
        init.channel_id, init.protocol_version
    );
    println!(
        "Firmware:  {}.{}.{}",
        init.device_major, init.device_minor, init.device_build
    );
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
    println!(
        "Caps:      {} (raw 0x{:02X})",
        caps.join("+"),
        init.capabilities
    );

    if !init.supports_cbor() {
        println!();
        println!("(device is U2F-only; CTAP2 GetInfo not available)");
        return Ok(());
    }

    let info = keyroost_ctap::get_info(&mut dev)?;
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
        &mut keyroost_ctap::cred_mgmt::CredentialManager<'a>,
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
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if supplied.len() != 1 {
        return Err(format!("{} requires exactly one of {}", cmd, sources_hint).into());
    }
    let (encoding, source) = supplied.into_iter().next().unwrap();
    let raw = match source {
        SecretSource::Literal(s) => s.to_owned(),
        SecretSource::Env(var) => std::env::var(var)
            .map_err(|_| format!("env var {} (for {}) is not set", var, cmd))?,
        SecretSource::Stdin => {
            use std::io::BufRead;
            let stdin = std::io::stdin();
            let mut line = String::new();
            stdin.lock().read_line(&mut line)?;
            line.trim_end_matches(['\r', '\n']).to_owned()
        }
    };
    Ok(match encoding {
        SecretEncoding::Hex => hex_decode(&raw)?,
        SecretEncoding::Base32 => base32_decode(&raw)?,
        SecretEncoding::Ascii => raw.into_bytes(),
    })
}

fn read_secret(
    label: &str,
    env: Option<&str>,
    from_stdin: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(var) = env {
        return std::env::var(var)
            .map_err(|_| format!("env var {} (for {}) is not set", var, label).into());
    }
    if from_stdin {
        use std::io::BufRead;
        let stdin = std::io::stdin();
        let mut line = String::new();
        stdin.lock().read_line(&mut line)?;
        return Ok(line.trim_end_matches(['\r', '\n']).to_owned());
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
        "PIN" => "pin-",
        "new PIN" => "new-pin-",
        "old PIN" => "old-pin-",
        _ => "",
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
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {}", e);
            ExitCode::FAILURE
        }
    }
}
