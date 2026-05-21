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

    let key = customer_key_bytes(&cli)?;
    let mut session = Session::open()?;
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
        Cmd::Info => {} // already printed
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
    }
    Ok(())
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
