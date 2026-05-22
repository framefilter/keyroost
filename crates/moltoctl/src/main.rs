//! moltoctl — CLI for programming Token2 Molto2 / Molto2v2 TOTP tokens.
//!
//! Drop-in replacement for `molto2.py` with a cleaner subcommand layout.

use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand, ValueEnum};
use molto2_proto::codec::{base32_decode, hex_decode};
use molto2_proto::commands::{
    DisplayTimeout, HmacAlgo, OtpDigits, ProfileConfig, TimeStep, DEFAULT_CUSTOMER_KEY,
};
use molto2_transport::{Session, TransportError};

#[derive(Parser)]
#[command(
    name = "moltoctl",
    version,
    about = "Program Token2 Molto2 / Molto2v2 TOTP tokens"
)]
struct Cli {
    /// Customer key as hex (alternative to --key-ascii). Default used if neither is supplied.
    #[arg(long, global = true, value_name = "HEX")]
    key: Option<String>,
    /// Customer key as ASCII (alternative to --key).
    #[arg(long, global = true, value_name = "TEXT", conflicts_with = "key")]
    key_ascii: Option<String>,
    /// List available PC/SC readers and exit.
    #[arg(long, global = true)]
    list_readers: bool,
    /// Print every outgoing APDU and incoming response to stderr.
    #[arg(long, global = true)]
    debug: bool,

    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print device serial number and on-device UTC time.
    Info,
    /// Write a TOTP seed to a profile slot.
    SetSeed {
        /// Profile index 0..=99.
        #[arg(short, long)]
        profile: u8,
        /// Seed in hex.
        #[arg(long, conflicts_with = "base32", value_name = "HEX")]
        hex: Option<String>,
        /// Seed in base32 (RFC 4648; whitespace and dashes tolerated).
        #[arg(long, value_name = "B32")]
        base32: Option<String>,
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
    /// Rotate the device's customer key (requires physical button confirmation).
    SetCustomerKey {
        #[arg(long, conflicts_with = "ascii", value_name = "HEX")]
        hex: Option<String>,
        #[arg(long, value_name = "TEXT")]
        ascii: Option<String>,
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
        uri: String,
    },
    /// Bulk-import a plaintext export from Aegis, 2FAS, or a list of otpauth:// URIs.
    ImportFile {
        /// Path to the plaintext export file. Format is auto-detected.
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

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

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
    } = cmd
    {
        let text =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {}", path.display(), e))?;
        let entries = molto2_import::parse_bulk_any(&text)?;
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
            return Err("refusing to probe without --yes (see `moltoctl probe --help`)".into());
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
        } => {
            let seed = match (hex.as_ref(), base32.as_ref()) {
                (Some(h), None) => hex_decode(h)?,
                (None, Some(b)) => base32_decode(b)?,
                (None, None) => return Err("set-seed requires --hex or --base32".into()),
                (Some(_), Some(_)) => {
                    return Err("set-seed: --hex and --base32 are mutually exclusive".into())
                }
            };
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
        Cmd::SetCustomerKey { hex, ascii } => {
            let new_key = match (hex.as_ref(), ascii.as_ref()) {
                (Some(h), None) => hex_decode(h)?,
                (None, Some(a)) => a.as_bytes().to_vec(),
                (None, None) => return Err("set-customer-key requires --hex or --ascii".into()),
                (Some(_), Some(_)) => return Err("--hex and --ascii are mutually exclusive".into()),
            };
            session.set_customer_key(&new_key)?;
            println!("customer-key rotation requested. Press the up-arrow button on the device to confirm.");
        }
        Cmd::Import {
            profile,
            title,
            display_timeout,
            uri,
        } => {
            let parsed = molto2_import::parse_otpauth(uri)?;
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
        } => {
            let text = std::fs::read_to_string(path)
                .map_err(|e| format!("read {}: {}", path.display(), e))?;
            let entries = molto2_import::parse_bulk_any(&text)?;
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
    }
    Ok(())
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
    use molto2_proto::apdu::{build_apdu_get, CLA_PLAIN, CLA_SECURE};
    use molto2_proto::commands::{sw_awaiting_button, sw_completed, Command};

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

fn print_info(info: &molto2_transport::DeviceInfo) {
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
