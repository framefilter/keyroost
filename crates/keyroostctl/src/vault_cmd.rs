//! `keyroostctl fido vault`: password vaults on a FIDO2 key, in
//! FidoParole's vault format. `keyroost-transport::vault` talks to the key;
//! this module reads the secrets, asks the questions and prints.
//!
//! Vaults are told apart by name, and copies sharing a name by what they
//! hold (entry count, or stored size where nothing was unlocked): a
//! credential ID is never shown in text and never taken as a selector, only
//! carried in `--json`.

use std::error::Error;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};

use clap::Subcommand;
use keyroost_ctap::large_blobs::BlobCapacity;
use keyroost_ctap::CtapHidDevice;
use keyroost_proto::codec::hex_encode;
use keyroost_resolve::{Choice, Device, Picker};
use keyroost_transport::vault::{
    self, Change, CtapVaultKey, LeftOver, OldVault, StoredData, Unlocked, VaultAuth,
    VaultCredential, VaultKeyError, VaultPick, VaultProblem, VaultRef, VaultStep,
};
use keyroost_vault::{Entry, Vault};
use zeroize::{Zeroize, Zeroizing};

use crate::code_import::entries;
use crate::json_out;
use crate::output::{emit_json, json_output};
use crate::prompt::{
    confirm, confirm_statement, key_label, refuse_unaskable, RealTerm, TermPicker,
};
use crate::secrets::{SecretIo, SecretSource, Secrets, Source, Spec};
use crate::{sanitize_terminal, PATH_HELP};

/// `fido vault` subcommands.
#[derive(Subcommand)]
pub(crate) enum FidoVaultCmd {
    /// List the key's vaults with how many entries each holds (PIN and a touch).
    List {
        /// The PIN: env:NAME reads that environment variable, stdin reads one
        /// line (hidden when typed at a terminal). With neither, a terminal
        /// asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        #[arg(long, value_name = "PATH", help = PATH_HELP)]
        path: Option<PathBuf>,
    },
    /// Create an empty vault on the key (PIN and two touches).
    ///
    /// Vault names are unique on a key. If the key is lost or reset, its
    /// vaults go with it: keep a backup with `fido vault export`.
    Add {
        /// The new vault's name: 1 to 32 bytes (accented and non-Latin
        /// letters take 2 to 4 bytes each).
        name: String,
        /// The PIN: env:NAME reads that environment variable, stdin reads one
        /// line (hidden when typed at a terminal). With neither, a terminal
        /// asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        #[arg(long, value_name = "PATH", help = PATH_HELP)]
        path: Option<PathBuf>,
    },
    /// Delete a vault and its entries (PIN, no touch). Irreversible: asks first (`--yes` to skip).
    ///
    /// To keep the entries, export the vault first with `fido vault export`.
    /// Copies that share a name are told apart by how much each stores.
    Delete {
        /// The vault's name, as `fido vault list` shows it.
        name: String,
        /// Confirm without asking (required when not run from a terminal).
        #[arg(long, short = 'y')]
        yes: bool,
        /// The PIN: env:NAME reads that environment variable, stdin reads one
        /// line (hidden when typed at a terminal). With neither, a terminal
        /// asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        #[arg(long, value_name = "PATH", help = PATH_HELP)]
        path: Option<PathBuf>,
    },
    /// Give a vault a new key: a new vault takes its entries and the old one is deleted after every entry is checked.
    ///
    /// Use it after unlocking the vault on a computer you no longer trust, then change the passwords that matter.
    Rotate {
        /// The vault's name, as `fido vault list` shows it.
        name: String,
        /// Confirm without asking (required when not run from a terminal).
        #[arg(long, short = 'y')]
        yes: bool,
        /// The PIN: env:NAME reads that environment variable, stdin reads one
        /// line (hidden when typed at a terminal). With neither, a terminal
        /// asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        #[arg(long, value_name = "PATH", help = PATH_HELP)]
        path: Option<PathBuf>,
    },
    /// Write a vault's entries to a backup file protected by a passphrase (PIN and a touch).
    ///
    /// The file opens with its passphrase alone, without the key: keep the
    /// two apart. The passphrase needs at least 10 characters. Restore the
    /// entries with `fido vault import`, on this key or another.
    Export {
        /// The vault's name, as `fido vault list` shows it.
        name: String,
        /// The backup file to write.
        #[arg(long, short = 'o', value_name = "FILE")]
        out: PathBuf,
        #[arg(long, help = crate::OVERWRITE_HELP)]
        overwrite: bool,
        /// The backup's passphrase: env:NAME reads that environment
        /// variable, stdin reads one line (first line when --pin stdin is
        /// also given; hidden when typed at a terminal, twice). With
        /// neither, a terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        passphrase: Option<SecretSource>,
        /// The PIN: env:NAME reads that environment variable, stdin reads one
        /// line (second line when --passphrase stdin is also given; hidden
        /// when typed at a terminal). With neither, a terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        #[arg(long, value_name = "PATH", help = PATH_HELP)]
        path: Option<PathBuf>,
    },
    /// Bring entries back from a vault backup file: shows what each becomes, then asks once (PIN and a touch; two to make a new vault).
    ///
    /// An entry the vault lacks is added; one whose backup copy is newer
    /// replaces the vault's; one that is the same is left as is; one whose
    /// copy on the key is newer is skipped unless --replace. --entry imports
    /// only the entries with the titles it names. With --vault NAME and no
    /// vault of that name on the key, asks to create it and imports into
    /// it. Asks once before writing (`--yes` to skip); with --dry-run
    /// nothing is written.
    Import {
        /// The backup file to read.
        #[arg(long = "in", short = 'i', value_name = "FILE")]
        input: PathBuf,
        /// The vault to import into; created (after asking) when the key has
        /// none of that name.
        #[arg(long, value_name = "NAME")]
        vault: Option<String>,
        /// The backup's passphrase: env:NAME reads that environment
        /// variable, stdin reads one line (first line when --pin stdin is
        /// also given; hidden when typed at a terminal). With neither, a
        /// terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        passphrase: Option<SecretSource>,
        /// Import only the entries with this title, as the preview shows it.
        /// Repeat for more.
        #[arg(long, value_name = "TITLE")]
        entry: Vec<String>,
        /// Also import entries whose copy on the key is newer than the
        /// backup's.
        #[arg(long)]
        replace: bool,
        /// Show what would be added, replaced or skipped; nothing is written.
        #[arg(long)]
        dry_run: bool,
        /// Confirm without asking (required when not run from a terminal).
        #[arg(long, short = 'y')]
        yes: bool,
        /// The PIN: env:NAME reads that environment variable, stdin reads one
        /// line (second line when --passphrase stdin is also given; hidden
        /// when typed at a terminal). With neither, a terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        #[arg(long, value_name = "PATH", help = PATH_HELP)]
        path: Option<PathBuf>,
    },
    /// Read and change the entries in a vault.
    Entry {
        #[command(subcommand)]
        cmd: FidoVaultEntryCmd,
    },
}

/// The help every vault entry command gives `--vault` (no final period,
/// like the doc-comment help clap shows next to it).
const VAULT_HELP: &str = "The vault to use when the key has several";

/// `fido vault entry` subcommands.
#[derive(Subcommand)]
pub(crate) enum FidoVaultEntryCmd {
    /// List a vault's entries with their usernames and web addresses (PIN and a touch).
    List {
        #[arg(long, value_name = "NAME", help = VAULT_HELP)]
        vault: Option<String>,
        /// The PIN: env:NAME reads that environment variable, stdin reads one
        /// line (hidden when typed at a terminal). With neither, a terminal
        /// asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        #[arg(long, value_name = "PATH", help = PATH_HELP)]
        path: Option<PathBuf>,
    },
    /// Show one entry; its password only with --reveal (PIN and a touch).
    ///
    /// Entries that share a title are told apart by username: name one with
    /// --username, or pick it from a list at a terminal.
    Show {
        /// The entry's title, as `fido vault entry list` shows it.
        title: String,
        /// Pick the entry with this username when several share the title.
        #[arg(long, value_name = "USERNAME")]
        username: Option<String>,
        #[arg(long, value_name = "NAME", help = VAULT_HELP)]
        vault: Option<String>,
        /// Also show the password until you press Enter. Anyone watching, or
        /// anything recording, your terminal will capture it.
        #[arg(long)]
        reveal: bool,
        /// The PIN: env:NAME reads that environment variable, stdin reads one
        /// line (hidden when typed at a terminal). With neither, a terminal
        /// asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        #[arg(long, value_name = "PATH", help = PATH_HELP)]
        path: Option<PathBuf>,
    },
    /// Add an entry to a vault (PIN and a touch).
    ///
    /// Titles need not be unique: entries that share one are told apart by
    /// username.
    Add {
        /// The new entry's title.
        title: String,
        #[arg(long, value_name = "NAME", help = VAULT_HELP)]
        vault: Option<String>,
        /// The entry's username.
        #[arg(long, value_name = "USERNAME")]
        username: Option<String>,
        /// The entry's web address.
        #[arg(long, value_name = "URL")]
        url: Option<String>,
        /// The notes: env:NAME reads that environment variable, stdin reads
        /// one line (second line when --password stdin is also given; hidden
        /// when typed at a terminal).
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        notes: Option<SecretSource>,
        /// The password: env:NAME reads that environment variable, stdin
        /// reads one line (first line; hidden when typed at a terminal,
        /// twice). With neither (and no --generate-password), a terminal
        /// asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        password: Option<SecretSource>,
        /// Make up a random password instead of reading one.
        #[arg(long, conflicts_with = "password")]
        generate_password: bool,
        /// Length of the generated password (default 20).
        #[arg(long, value_name = "N", requires = "generate_password", value_parser = length_parser())]
        length: Option<usize>,
        /// The PIN: env:NAME reads that environment variable, stdin reads one
        /// line (the line after the password and notes when they come from
        /// stdin too: second line after one of them, third after both; hidden
        /// when typed at a terminal). With neither, a terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        #[arg(long, value_name = "PATH", help = PATH_HELP)]
        path: Option<PathBuf>,
    },
    /// Change an entry's title, username, web address, notes or password (PIN and a touch).
    ///
    /// Only what the flags name changes; an empty value clears a field
    /// (`--url ""`). Entries that share a title are picked from a list at a
    /// terminal.
    #[command(group(
        clap::ArgGroup::new("change")
            .args(["new_title", "username", "url", "notes", "password", "generate_password"])
            .required(true)
            .multiple(true)
    ))]
    Edit {
        /// The entry's title, as `fido vault entry list` shows it.
        title: String,
        #[arg(long, value_name = "NAME", help = VAULT_HELP)]
        vault: Option<String>,
        /// The new title.
        #[arg(long = "title", value_name = "TITLE")]
        new_title: Option<String>,
        /// The new username.
        #[arg(long, value_name = "USERNAME")]
        username: Option<String>,
        /// The new web address.
        #[arg(long, value_name = "URL")]
        url: Option<String>,
        /// The notes: env:NAME reads that environment variable, stdin reads
        /// one line (second line when --password stdin is also given; hidden
        /// when typed at a terminal).
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        notes: Option<SecretSource>,
        /// The password: env:NAME reads that environment variable, stdin
        /// reads one line (first line; hidden when typed at a terminal,
        /// twice).
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        password: Option<SecretSource>,
        /// Replace the password with a random one.
        #[arg(long, conflicts_with = "password")]
        generate_password: bool,
        /// Length of the generated password (default 20).
        #[arg(long, value_name = "N", requires = "generate_password", value_parser = length_parser())]
        length: Option<usize>,
        /// The PIN: env:NAME reads that environment variable, stdin reads one
        /// line (the line after the password and notes when they come from
        /// stdin too: second line after one of them, third after both; hidden
        /// when typed at a terminal). With neither, a terminal asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        #[arg(long, value_name = "PATH", help = PATH_HELP)]
        path: Option<PathBuf>,
    },
    /// Delete an entry from a vault (PIN and a touch). Irreversible: asks first (`--yes` to skip).
    Delete {
        /// The entry's title, as `fido vault entry list` shows it.
        title: String,
        /// Pick the entry with this username when several share the title.
        #[arg(long, value_name = "USERNAME")]
        username: Option<String>,
        #[arg(long, value_name = "NAME", help = VAULT_HELP)]
        vault: Option<String>,
        /// Confirm without asking (required when not run from a terminal).
        #[arg(long, short = 'y')]
        yes: bool,
        /// The PIN: env:NAME reads that environment variable, stdin reads one
        /// line (hidden when typed at a terminal). With neither, a terminal
        /// asks.
        #[arg(long, value_name = "SOURCE", value_parser = crate::secrets::parse_source, allow_hyphen_values = true)]
        pin: Option<SecretSource>,
        #[arg(long, value_name = "PATH", help = PATH_HELP)]
        path: Option<PathBuf>,
    },
}

/// `--length`: what the generator makes, 4 to 128 characters.
fn length_parser() -> clap::builder::RangedU64ValueParser<usize> {
    clap::builder::RangedU64ValueParser::new().range(4..=128)
}

pub(crate) fn run_fido_vault(cmd: &FidoVaultCmd) -> Result<(), Box<dyn Error>> {
    match cmd {
        FidoVaultCmd::List { pin, path } => {
            let pin = crate::fido_pin(path.as_deref(), pin.as_ref())?;
            let mut key = open_vault_key(path.as_deref())?;
            let mut auth = VaultAuth::pin(pin);
            let mut touches = Touches::new(1);
            let unlocked = vault::unlock(&mut key, &mut auth, &mut |s| touches.step(s))
                .map_err(vault_error)?;
            let rows = rows(&unlocked);
            if json_output() {
                return emit_json(&list_json(&rows, &unlocked.capacity));
            }
            for line in list_lines(&rows, &unlocked.capacity) {
                outln!("{line}");
            }
            Ok(())
        }
        FidoVaultCmd::Add { name, pin, path } => {
            // The format's name rule, before a key is looked for.
            keyroost_vault::user_handle(name)?;
            let pin = crate::fido_pin(path.as_deref(), pin.as_ref())?;
            let mut key = open_vault_key(path.as_deref())?;
            let mut auth = VaultAuth::pin(pin);
            let mut touches = Touches::new(2);
            vault::create(
                &mut key,
                &mut auth,
                name,
                &keyroost_vault::Vault::default(),
                &mut |s| touches.step(s),
            )
            .map_err(vault_error)?;
            outln!("{}", backup_hint(name));
            Ok(())
        }
        FidoVaultCmd::Delete {
            name,
            yes,
            pin,
            path,
        } => {
            let (dev, pin) =
                key_and_pin(path.as_deref(), pin.as_ref(), *yes, &delete_action(name))?;
            let mut key = open_vault_key(path.as_deref())?;
            let mut auth = VaultAuth::pin(pin);
            // Credential management: no touch.
            let creds = vault::list_credentials(&mut key, &mut auth).map_err(vault_error)?;
            let matches = vault::matching(&creds, &VaultPick::Name(name)).map_err(vault_error)?;
            let i = choose_vault(
                &delete_choices(&creds),
                &matches,
                Some(name),
                &mut TermPicker::new(&mut RealTerm),
            )?;
            errln!("{}", delete_note(name));
            // The open handle ties the question to the key (`confirm_on_held`).
            delete_question(&mut RealTerm, *yes, name, &key_label(&dev))?;
            // A touch only on a key that listed no largeBlobKey for the vault.
            let mut touches = Touches::new(1);
            vault::delete(&mut key, &mut auth, &creds[i], &mut |s| touches.step(s))
                .map_err(vault_error)?;
            outln!("{}", deleted_line(name));
            Ok(())
        }
        FidoVaultCmd::Rotate {
            name,
            yes,
            pin,
            path,
        } => {
            let (dev, pin) =
                key_and_pin(path.as_deref(), pin.as_ref(), *yes, &rotate_action(name))?;
            let mut key = open_vault_key(path.as_deref())?;
            let mut auth = VaultAuth::pin(pin);
            // One touch to unlock, then the two of the new vault's create.
            let mut touches = Touches::new(3);
            let mut unlocked = vault::unlock(&mut key, &mut auth, &mut |s| touches.step(s))
                .map_err(vault_error)?;
            let matches =
                vault::matching(&unlocked.vaults, &VaultPick::Name(name)).map_err(vault_error)?;
            let i = choose_vault(
                &unlocked_choices(&unlocked),
                &matches,
                Some(name),
                &mut TermPicker::new(&mut RealTerm),
            )?;
            let old = unlocked.vaults[i].open_mut().map_err(vault_error)?;
            rotate_question(&mut RealTerm, *yes, name, &key_label(&dev))?;
            let new = vault::rotate(&mut key, &mut auth, old, &mut |s| touches.step(s))
                .map_err(vault_error)?;
            outln!("{}", rotated_line(name, new.contents.entries.len()));
            Ok(())
        }
        FidoVaultCmd::Export {
            name,
            out,
            overwrite,
            path,
            ..
        } => run_export(
            name,
            out,
            *overwrite,
            crate::pair_of(vault_secret_pair(cmd))?,
            path.as_deref(),
        ),
        FidoVaultCmd::Import {
            input,
            vault,
            entry,
            replace,
            dry_run,
            yes,
            path,
            ..
        } => run_import(&ImportArgs {
            input,
            vault: vault.as_deref(),
            pair: crate::pair_of(vault_secret_pair(cmd))?,
            entries: entry,
            replace: *replace,
            dry_run: *dry_run,
            yes: *yes,
            path: path.as_deref(),
        }),
        FidoVaultCmd::Entry { cmd } => run_vault_entry(cmd),
    }
}

/// The two secrets of `vault export` and `vault import`, in stdin order:
/// the backup's passphrase (asked twice at a terminal for a new backup),
/// then the PIN.
pub(crate) fn vault_secret_pair(cmd: &FidoVaultCmd) -> Option<crate::SecretPair<'_>> {
    Some(match cmd {
        FidoVaultCmd::Export {
            passphrase, pin, ..
        } => crate::secret_pair(
            (&crate::PGP_NEW_PASSPHRASE, passphrase),
            (&crate::FIDO_PIN, pin),
        ),
        FidoVaultCmd::Import {
            passphrase, pin, ..
        } => crate::secret_pair(
            (&crate::PGP_PASSPHRASE, passphrase),
            (&crate::FIDO_PIN, pin),
        ),
        _ => return None,
    })
}

/// `vault export`. Order: check the passphrase and PIN sources, check the
/// output file, read the passphrase and check its length (it belongs to the
/// file, so a short one is refused before the key is used), select the
/// key, read the PIN, unlock (a touch), choose the vault, encrypt, write.
fn run_export(
    name: &str,
    out: &Path,
    overwrite: bool,
    pair: crate::SecretPair<'_>,
    path: Option<&Path>,
) -> Result<(), Box<dyn Error>> {
    let mut sec = Secrets::real();
    pair.check(&sec)?;
    let mode = crate::prompt::check_secret_overwrite(Some(out), overwrite)?;
    let (pass, pin) = pair.read_first(&mut sec)?;
    let pass = pass.text()?;
    keyroost_vault::check_passphrase(&pass)?;
    let dev = crate::target::select_fido(path)?;
    let pin = crate::fido_pin_with(&mut sec, &dev, pin.flag)?;
    let mut key = open_vault_key(path)?;
    let mut auth = VaultAuth::pin(pin);
    let mut touches = Touches::new(1);
    let mut unlocked =
        vault::unlock(&mut key, &mut auth, &mut |s| touches.step(s)).map_err(vault_error)?;
    let matches = vault::matching(&unlocked.vaults, &VaultPick::Name(name)).map_err(vault_error)?;
    let i = choose_vault(
        &unlocked_choices(&unlocked),
        &matches,
        Some(name),
        &mut TermPicker::new(&mut RealTerm),
    )?;
    let open = unlocked.vaults[i].open_mut().map_err(vault_error)?;
    let bytes = keyroost_vault::export_backup(&open.contents, &pass)?;
    crate::write_private_file(out, &bytes, mode)
        .map_err(|e| format!("cannot write {}: {}", out.display(), e))?;
    outln!("{}", exported_line(name, open.contents.entries.len(), out));
    Ok(())
}

/// What `vault export` prints when the file is written.
fn exported_line(name: &str, n: usize, out: &Path) -> String {
    format!(
        "Backup of vault \"{}\" ({}) written to {}.",
        sanitize_terminal(name),
        entries(n),
        sanitize_terminal(&out.display().to_string())
    )
}

/// `vault import`'s flags.
struct ImportArgs<'a> {
    input: &'a Path,
    vault: Option<&'a str>,
    /// The passphrase, then the PIN.
    pair: crate::SecretPair<'a>,
    entries: &'a [String],
    replace: bool,
    dry_run: bool,
    yes: bool,
    path: Option<&'a Path>,
}

/// The largest backup file read: as large as an authenticator export may
/// be for the code imports. A vault fits a key's largeBlob store, so a real
/// backup is a few kilobytes.
const MAX_BACKUP_BYTES: usize = keyroost_qr::file::MAX_FILE_BYTES;

/// A backup file's bytes, refused past [`MAX_BACKUP_BYTES`].
fn read_backup_file(path: &Path) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let read_err = |e: io::Error| format!("cannot read {}: {}", path.display(), e);
    let f = std::fs::File::open(path).map_err(read_err)?;
    let mut bytes = Vec::new();
    f.take(MAX_BACKUP_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(read_err)?;
    if bytes.len() > MAX_BACKUP_BYTES {
        return Err(format!(
            "{}: larger than 16 MiB, too large for a vault backup. Nothing was read.",
            path.display()
        ));
    }
    Ok(bytes)
}

/// `vault import`. Order: check the passphrase and PIN sources, read and
/// decrypt the file (a wrong passphrase fails before any key is looked
/// for), check the `--entry` titles, select the key, read the PIN, list the
/// vaults (no touch), then either unlock (a touch) and compare with the
/// vault, or plan a new vault; preview, ask once, write.
fn run_import(a: &ImportArgs<'_>) -> Result<(), Box<dyn Error>> {
    if let Some(name) = a.vault {
        // The format's name rule, before anything is read.
        keyroost_vault::user_handle(name)?;
    }
    let mut sec = Secrets::real();
    a.pair.check(&sec)?;
    let bytes = read_backup_file(a.input)?;
    let (pass, pin) = a.pair.read_first(&mut sec)?;
    let incoming = keyroost_vault::import_backup(&bytes, &pass.text()?)
        .map_err(|e| format!("{}: {e}", a.input.display()))?;
    check_entry_titles(&incoming, a.entries)?;
    let dev = crate::target::select_fido(a.path)?;
    let key_name = key_label(&dev);
    let file = a
        .input
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| a.input.display().to_string());
    if !a.dry_run {
        // The question comes after the unlock; a run that could never
        // answer it is refused before the PIN is read.
        refuse_unaskable(&RealTerm, a.yes, &import_action(&file, a.vault), &key_name)?;
    }
    let pin = crate::fido_pin_with(&mut sec, &dev, pin.flag)?;
    let mut key = open_vault_key(a.path)?;
    let mut auth = VaultAuth::pin(pin);
    // Credential management: no touch.
    let creds = vault::list_credentials(&mut key, &mut auth).map_err(vault_error)?;
    let pick = vault_pick(a.vault);
    match vault::matching(&creds, &pick) {
        Ok(_) => {}
        Err(VaultKeyError::NotFound(_)) => {
            let Some(name) = a.vault else {
                return Err(vault_error(VaultKeyError::NoVaults));
            };
            return import_into_new(a, &mut key, &mut auth, name, &incoming, &file, &key_name);
        }
        Err(VaultKeyError::NoVaults) => {
            return Err(format!(
                "{}; pass --vault NAME to make a vault from this backup",
                VaultKeyError::NoVaults
            )
            .into())
        }
        Err(e) => return Err(vault_error(e)),
    }
    let mut touches = Touches::new(1);
    let mut unlocked =
        vault::unlock(&mut key, &mut auth, &mut |s| touches.step(s)).map_err(vault_error)?;
    let matches = vault::matching(&unlocked.vaults, &pick).map_err(vault_error)?;
    let i = choose_vault(
        &unlocked_choices(&unlocked),
        &matches,
        a.vault,
        &mut TermPicker::new(&mut RealTerm),
    )?;
    let open = unlocked.vaults[i].open_mut().map_err(vault_error)?;
    let statuses = keyroost_vault::classify(&open.contents, &incoming);
    let rows = import_rows(&statuses, &incoming, a.entries, a.replace)?;
    let name = open.vault_ref.name.clone();
    let lines = import_lines(
        &rows,
        &file,
        &shown_name(name.as_deref()),
        &key_name,
        open.contents.entries.len(),
    );
    if preview_stops(&lines, &rows, name.as_deref(), false, a.dry_run)? {
        return Ok(());
    }
    let chosen = chosen(&rows);
    // The open handle ties the question to the key (`confirm_on_held`).
    import_question(
        &mut RealTerm,
        a.yes,
        chosen.len(),
        name.as_deref(),
        &key_name,
    )?;
    let mut progress = SaveProgress::default();
    let saved = vault::save(
        &mut key,
        &mut auth,
        open,
        &Change::Import { incoming, chosen },
        &mut |s| progress.step(s),
    )
    .map_err(import_save_error)?;
    import_done(&rows, name.as_deref(), false, saved.added, saved.replaced)
}

/// `vault import` into a vault the key doesn't have: every entry (or every
/// one `--entry` names) is added, after the `create vault` question; the
/// create takes two touches.
fn import_into_new(
    a: &ImportArgs<'_>,
    key: &mut CtapVaultKey<CtapHidDevice>,
    auth: &mut VaultAuth,
    name: &str,
    incoming: &Vault,
    file: &str,
    key_name: &str,
) -> Result<(), Box<dyn Error>> {
    let statuses: Vec<_> = (0..incoming.entries.len())
        .map(|i| (i, keyroost_vault::ImportStatus::New))
        .collect();
    let rows = import_rows(&statuses, incoming, a.entries, a.replace)?;
    let lines = import_lines(&rows, file, name, key_name, 0);
    if preview_stops(&lines, &rows, Some(name), true, a.dry_run)? {
        return Ok(());
    }
    create_question(&mut RealTerm, a.yes, name, key_name)?;
    let initial = Vault {
        entries: chosen(&rows)
            .into_iter()
            .map(|i| incoming.entries[i].clone())
            .collect(),
    };
    let mut touches = Touches::new(2);
    let made =
        vault::create(key, auth, name, &initial, &mut |s| touches.step(s)).map_err(vault_error)?;
    import_done(&rows, Some(name), true, made.contents.entries.len(), 0)
}

/// Show the preview. A dry run prints it on stdout (or its JSON) and
/// stops; otherwise it goes to stderr, and a plan with nothing to add or
/// replace stops with `Nothing to add.` `Ok(true)`: stop here.
fn preview_stops(
    lines: &[String],
    rows: &[ImportRow],
    vault: Option<&str>,
    creates: bool,
    dry_run: bool,
) -> Result<bool, Box<dyn Error>> {
    if dry_run {
        if json_output() {
            emit_json(&import_json(rows, vault, creates, true))?;
        } else {
            for l in lines {
                outln!("{l}");
            }
        }
        return Ok(true);
    }
    for l in lines {
        errln!("{l}");
    }
    if chosen(rows).is_empty() {
        if json_output() {
            emit_json(&import_json(rows, vault, creates, false))?;
        } else {
            outln!("Nothing to add.");
        }
        return Ok(true);
    }
    Ok(false)
}

/// The result of an import that wrote: its JSON, or the summary line.
fn import_done(
    rows: &[ImportRow],
    vault: Option<&str>,
    creates: bool,
    added: usize,
    replaced: usize,
) -> Result<(), Box<dyn Error>> {
    if json_output() {
        return emit_json(&import_json(rows, vault, creates, false));
    }
    outln!("{}", imported_line(vault, added, replaced));
    Ok(())
}

/// A failed import save as `main` prints it: a conflict says to run the
/// command again; everything else as [`vault_error`].
fn import_save_error(e: VaultKeyError) -> Box<dyn Error> {
    match e {
        VaultKeyError::Conflict => "an entry in this vault changed on the key while the command \
                                    ran; nothing was written. Run it again."
            .into(),
        e => vault_error(e),
    }
}

/// What `vault import` prints when done.
fn imported_line(vault: Option<&str>, added: usize, replaced: usize) -> String {
    format!(
        "Imported into vault \"{}\": {added} added, {replaced} replaced.",
        shown_name(vault)
    )
}

/// One backup entry in the import preview: what the import does with it.
/// Its text is entry data, wiped when it is dropped.
#[derive(Debug, Clone)]
pub(crate) struct ImportRow {
    /// Its place in the backup, from 0.
    pub(crate) index: usize,
    /// Carried for `--json` only, never printed in text.
    pub(crate) id: String,
    pub(crate) title: String,
    pub(crate) username: String,
    /// `add`, `replace`, `exists` or `skip`.
    pub(crate) plan: &'static str,
    pub(crate) reason: Option<&'static str>,
}

impl Drop for ImportRow {
    fn drop(&mut self) {
        self.id.zeroize();
        self.title.zeroize();
        self.username.zeroize();
    }
}

const NEWER: &str = "the backup's copy is newer";
const OLDER: &str = "the key's copy is newer (--replace takes it)";
const OLDER_TAKEN: &str = "replaces the key's newer copy";
const SAME: &str = "already in the vault; left as is";
const NOT_NAMED: &str = "not named with --entry";

/// Every `--entry` title is some backup entry's title; the first that
/// isn't is refused.
fn check_entry_titles(incoming: &Vault, titles: &[String]) -> Result<(), String> {
    match titles
        .iter()
        .find(|t| !incoming.entries.iter().any(|e| e.title == **t))
    {
        Some(t) => Err(format!(
            "no entry in the backup is titled \"{}\"",
            sanitize_terminal(t)
        )),
        None => Ok(()),
    }
}

/// What the import does with each backup entry, from how it compares with
/// the vault (`statuses`, from [`keyroost_vault::classify`]). By default it
/// takes the new ones and those whose backup copy is newer; `replace` also
/// takes those whose key copy is newer. With `--entry` titles (`entries`),
/// it takes every entry with one of them (an older one too) and skips the
/// rest; a title no backup entry has is refused.
pub(crate) fn import_rows(
    statuses: &[(usize, keyroost_vault::ImportStatus)],
    incoming: &Vault,
    entries: &[String],
    replace: bool,
) -> Result<Vec<ImportRow>, String> {
    use keyroost_vault::ImportStatus;
    check_entry_titles(incoming, entries)?;
    statuses
        .iter()
        .map(|&(index, status)| {
            let e = incoming
                .entries
                .get(index)
                .ok_or_else(|| format!("internal error: the backup has no entry {index}"))?;
            let named = entries.is_empty() || entries.contains(&e.title);
            let (plan, reason) = match status {
                _ if !named => ("skip", Some(NOT_NAMED)),
                ImportStatus::New => ("add", None),
                ImportStatus::Newer => ("replace", Some(NEWER)),
                ImportStatus::Same => ("exists", Some(SAME)),
                ImportStatus::Older if replace || !entries.is_empty() => {
                    ("replace", Some(OLDER_TAKEN))
                }
                ImportStatus::Older => ("skip", Some(OLDER)),
                _ => ("skip", Some("this build can't tell how it compares")),
            };
            Ok(ImportRow {
                index,
                id: e.id.clone(),
                title: e.title.clone(),
                username: e.username.clone(),
                plan,
                reason,
            })
        })
        .collect()
}

/// The backup indices the import writes: its `add` and `replace` rows.
fn chosen(rows: &[ImportRow]) -> Vec<usize> {
    rows.iter()
        .filter(|r| matches!(r.plan, "add" | "replace"))
        .map(|r| r.index)
        .collect()
}

/// The import preview: a header, one row per backup entry (as the code
/// imports lay them out, named `title (username)`), then the counts. Never
/// a password or an ID.
pub(crate) fn import_lines(
    rows: &[ImportRow],
    file: &str,
    vault: &str,
    key: &str,
    on_key: usize,
) -> Vec<String> {
    let mut out = vec![format!(
        "{} in {} for vault \"{}\" on {}:",
        entries(rows.len()),
        sanitize_terminal(file),
        sanitize_terminal(vault),
        key
    )];
    let table: Vec<(&str, String, Option<String>)> = rows
        .iter()
        .map(|r| {
            let name = if r.username.is_empty() {
                sanitize_terminal(&r.title)
            } else {
                format!(
                    "{} ({})",
                    sanitize_terminal(&r.title),
                    sanitize_terminal(&r.username)
                )
            };
            (r.plan, name, r.reason.map(str::to_owned))
        })
        .collect();
    out.extend(crate::code_import::plan_row_lines(&table));
    let count = |w: &str| rows.iter().filter(|r| r.plan == w).count();
    out.push(format!(
        "{} in the vault; {} will be added, {} replaced, {} left as is, {} skipped.",
        entries(on_key),
        count("add"),
        count("replace"),
        count("exists"),
        count("skip")
    ));
    out
}

/// `vault import`'s question, in the code imports' `confirm` form.
fn import_question(
    term: &mut dyn crate::prompt::Term,
    yes: bool,
    n: usize,
    vault: Option<&str>,
    key: &str,
) -> Result<bool, String> {
    confirm(
        term,
        yes,
        &format!("import {} into vault \"{}\"", entries(n), shown_name(vault)),
        key,
    )
}

/// The question before an import makes the vault it writes to.
fn create_question(
    term: &mut dyn crate::prompt::Term,
    yes: bool,
    name: &str,
    key: &str,
) -> Result<bool, String> {
    confirm(
        term,
        yes,
        &format!("create vault \"{}\"", sanitize_terminal(name)),
        key,
    )
}

/// `vault import --json`: the plan, as the preview shows it, with ids.
pub(crate) fn import_json(
    rows: &[ImportRow],
    vault: Option<&str>,
    creates: bool,
    dry_run: bool,
) -> json_out::FidoVaultImportJson {
    json_out::FidoVaultImportJson {
        vault: vault.map(str::to_owned),
        creates,
        dry_run,
        entries: rows
            .iter()
            .map(|r| json_out::FidoVaultImportRowJson {
                index: r.index,
                id: r.id.clone(),
                title: r.title.clone(),
                username: unless_empty(&r.username),
                plan: r.plan,
                reason: r.reason,
            })
            .collect(),
    }
}

/// How the vault named `name` is written in a command line hint: bare when
/// safe, else in POSIX single quotes, as the `-d` hints quote a key.
pub(crate) fn export_hint_arg(name: &str) -> String {
    keyroost_resolve::shell_quote(&sanitize_terminal(name))
}

/// The file name a hint suggests for a backup of the vault `name`: lower
/// case, letters and digits (any script) kept, every run of anything else
/// one `-`, trimmed, `vault` when nothing is left, then `.t2vault`. Never a
/// path: no separator survives, and the only dot is the extension's.
pub(crate) fn backup_file_name(name: &str) -> String {
    let mut stem = String::new();
    for c in name.to_lowercase().chars() {
        if c.is_alphanumeric() {
            stem.push(c);
        } else if !stem.is_empty() && !stem.ends_with('-') {
            stem.push('-');
        }
    }
    let stem = stem.trim_end_matches('-');
    let stem = if stem.is_empty() { "vault" } else { stem };
    format!("{stem}.t2vault")
}

/// The export command the hints name for the vault `name`.
fn export_command(name: &str) -> String {
    format!(
        "keyroostctl fido vault export {} -o {}",
        export_hint_arg(name),
        backup_file_name(name)
    )
}

/// What `vault add` prints once the vault is made: a backup reminder.
pub(crate) fn backup_hint(name: &str) -> String {
    format!(
        "Vault \"{}\" created on this key.\nIf the key is lost or reset, the vault goes with it. \
         Keep a backup:\n  {}",
        sanitize_terminal(name),
        export_command(name)
    )
}

/// The line `vault delete` prints before its question.
pub(crate) fn delete_note(name: &str) -> String {
    format!(
        "Its entries go with it. To keep them, export it first: {}",
        export_command(name)
    )
}

/// `vault delete`'s question, in `confirm`'s form.
fn delete_question(
    term: &mut dyn crate::prompt::Term,
    yes: bool,
    name: &str,
    key: &str,
) -> Result<bool, String> {
    confirm(term, yes, &delete_action(name), key)
}

/// `vault delete`'s action.
fn delete_action(name: &str) -> String {
    format!("delete vault \"{}\"", sanitize_terminal(name))
}

/// `vault rotate`'s question, as a statement.
fn rotate_question(
    term: &mut dyn crate::prompt::Term,
    yes: bool,
    name: &str,
    key: &str,
) -> Result<bool, String> {
    let action = rotate_action(name);
    let name = sanitize_terminal(name);
    confirm_statement(
        term,
        yes,
        &format!(
            "Rotate the key of vault \"{name}\" on {key}? A new vault replaces it; the old one \
             is deleted after every entry is checked."
        ),
        &action,
        key,
    )
}

/// `vault rotate`'s action.
fn rotate_action(name: &str) -> String {
    format!("rotate the key of vault \"{}\"", sanitize_terminal(name))
}

/// `vault import`'s action as it is known before the unlock: the backup
/// file, and the vault when `--vault` names it.
fn import_action(file: &str, vault: Option<&str>) -> String {
    let file = sanitize_terminal(file);
    match vault {
        Some(v) => format!("import {file} into vault \"{}\"", sanitize_terminal(v)),
        None => format!("import {file}"),
    }
}

/// The key and its PIN for a command that asks only after the unlock: the
/// PIN source is checked, the key selected, a run that could never answer
/// the question refused ([`refuse_unaskable`]), then the PIN read.
fn key_and_pin(
    path: Option<&Path>,
    pin: Option<&SecretSource>,
    yes: bool,
    action: &str,
) -> Result<(Device, Zeroizing<String>), Box<dyn Error>> {
    let mut sec = Secrets::real();
    sec.check(&crate::FIDO_PIN, Source::from_flag(pin))?;
    let dev = crate::target::select_fido(path)?;
    refuse_unaskable(&RealTerm, yes, action, &key_label(&dev))?;
    let pin = crate::fido_pin_with(&mut sec, &dev, pin)?;
    Ok((dev, pin))
}

/// What `vault delete` prints when done.
fn deleted_line(name: &str) -> String {
    format!("Vault \"{}\" deleted.", sanitize_terminal(name))
}

/// What `vault rotate` prints when done; `n` is the new vault's entry count.
fn rotated_line(name: &str, n: usize) -> String {
    format!(
        "Vault \"{}\" rotated: a new vault holds its {} and the old one is deleted.",
        sanitize_terminal(name),
        entries(n)
    )
}

/// The vaults as `vault delete` tells them apart: by what each stores,
/// without unlocking any.
pub(crate) fn delete_choices(creds: &[VaultCredential]) -> Vec<VaultChoice> {
    creds
        .iter()
        .map(|c| VaultChoice {
            name: c.vault.name.clone(),
            detail: stored_detail(c.stored),
        })
        .collect()
}

/// An unlocked vault's detail: its entry count, or `(unavailable)` when it
/// did not open.
pub(crate) fn count_detail(count: Option<usize>) -> String {
    count.map_or_else(|| "(unavailable)".to_owned(), entries)
}

/// The vaults one unlock opened, told apart by their entry counts.
pub(crate) fn unlocked_choices(u: &Unlocked) -> Vec<VaultChoice> {
    u.vaults
        .iter()
        .map(|v| VaultChoice {
            name: v.vault_ref.name.clone(),
            detail: count_detail(v.entry_count()),
        })
        .collect()
}

/// Open the selected FIDO key for the vault flows. A U2F-only key is
/// refused as `fido blob` refuses it; a key that cannot hold a vault is
/// refused by the transport's support check before anything else is sent.
pub(crate) fn open_vault_key(
    path: Option<&Path>,
) -> Result<CtapVaultKey<CtapHidDevice>, Box<dyn Error>> {
    let path = crate::target::fido_path(path)?;
    let (dev, init) = crate::open_ctap_hid(&path)?;
    if !init.supports_cbor() {
        return Err("device is U2F-only; CTAP2 password vaults not supported".into());
    }
    CtapVaultKey::open(dev).map_err(vault_error)
}

/// How `--vault` names the vault: by name, or (not given) the only one.
pub(crate) fn vault_pick(arg: Option<&str>) -> VaultPick<'_> {
    match arg {
        None => VaultPick::Only,
        Some(name) => VaultPick::Name(name),
    }
}

/// A vault's name as text shows it: sanitized, `(unnamed)` when it has
/// none (or an empty one).
fn shown_name(name: Option<&str>) -> String {
    match name {
        Some(n) if !n.is_empty() => sanitize_terminal(n),
        _ => "(unnamed)".to_owned(),
    }
}

/// One vault a command may mean, as a question or a refusal lists it.
pub(crate) struct VaultChoice {
    pub(crate) name: Option<String>,
    /// What tells copies apart: where the vaults were unlocked,
    /// [`count_detail`] (`entries(n)` or `(unavailable)`); where nothing was
    /// unlocked, [`stored_detail`] (the size, `(none)` or `(unavailable)`).
    pub(crate) detail: String,
}

/// What a vault holds, told without unlocking it, as listings print it:
/// the size, `(none)`, `(unavailable)`, or nothing when the key could not
/// say.
pub(crate) fn stored_detail(stored: StoredData) -> String {
    match stored {
        StoredData::Bytes(n) => format!("{n} bytes stored"),
        StoredData::Empty => "(none)".to_owned(),
        StoredData::Unreadable => "(unavailable)".to_owned(),
        StoredData::Unknown => String::new(),
    }
}

/// `  NAME  detail` lines with the names in one column.
fn name_detail_lines<'a>(
    rows: impl Iterator<Item = (Option<&'a str>, String)>,
    indent: &str,
) -> Vec<String> {
    let rows: Vec<(String, String)> = rows.map(|(n, d)| (shown_name(n), d)).collect();
    let width = rows
        .iter()
        .map(|(n, _)| n.chars().count())
        .max()
        .unwrap_or(0);
    rows.into_iter()
        .map(|(name, detail)| {
            let line = format!("{indent}{name:<width$}  {detail}");
            line.trim_end().to_owned()
        })
        .collect()
}

/// Which of `choices` the command means, among the `matches` (indices into
/// `choices`) for the name `asked_for` (`None`: no `--vault` given). One
/// match is it; several are asked about at a terminal and refused,
/// listing them, without one.
pub(crate) fn choose_vault(
    choices: &[VaultChoice],
    matches: &[usize],
    asked_for: Option<&str>,
    picker: &mut dyn Picker,
) -> Result<usize, String> {
    match matches {
        [] => Err(match asked_for {
            Some(name) => VaultKeyError::NotFound(name.to_owned()).to_string(),
            None => VaultKeyError::NoVaults.to_string(),
        }),
        [one] => Ok(*one),
        many => {
            let heading = match asked_for {
                Some(name) => format!("{} vaults are named \"{name}\":", many.len()),
                None => format!("This key has {} vaults:", many.len()),
            };
            if picker.interactive() {
                let list: Vec<Choice> = many
                    .iter()
                    .enumerate()
                    .map(|(i, &c)| Choice {
                        number: i + 1,
                        label: shown_name(choices[c].name.as_deref()),
                        endpoint: choices[c].detail.clone(),
                    })
                    .collect();
                let k = picker.pick(&heading, &list)?;
                return many
                    .get(k)
                    .copied()
                    .ok_or_else(|| format!("choice {k} is out of range"));
            }
            let (heading, next) = match asked_for {
                Some(_) => (heading, "run this in a terminal to pick one"),
                None => (
                    format!("this key has {} vaults:", many.len()),
                    "pick one with --vault NAME",
                ),
            };
            let mut lines = vec![sanitize_terminal(&heading)];
            lines.extend(name_detail_lines(
                many.iter().map(|&c| {
                    (
                        choices[c].name.as_deref(),
                        sanitize_terminal(&choices[c].detail),
                    )
                }),
                "  ",
            ));
            lines.push(next.to_owned());
            Err(lines.join("\n"))
        }
    }
}

/// The touch line for touch `n` of `total`.
pub(crate) fn touch_line(n: u8, total: u8) -> String {
    if total == 1 {
        "touch the key now\u{2026}".to_owned()
    } else {
        format!("touch the key ({n} of {total})\u{2026}")
    }
}

/// The touches one command asks for, counted as the transport reports them.
pub(crate) struct Touches {
    done: u8,
    total: u8,
}

impl Touches {
    pub(crate) fn new(total: u8) -> Self {
        Touches { done: 0, total }
    }

    /// The line for `step`: the next touch's, or `None` for a step that
    /// waits on no touch.
    pub(crate) fn line(&mut self, step: VaultStep) -> Option<String> {
        match step {
            VaultStep::CreateTouch | VaultStep::UnlockTouch => {
                self.done = self.done.saturating_add(1);
                Some(touch_line(self.done, self.total))
            }
            _ => None,
        }
    }

    /// An `on_step` callback: print the touch line, if the step has one.
    pub(crate) fn step(&mut self, step: VaultStep) {
        if let Some(line) = self.line(step) {
            crate::prompt::touch(&line);
        }
    }
}

/// The command to delete a vault, as the hints name it.
const VAULT_DELETE: &str = "keyroostctl fido vault delete NAME";
/// The command to rotate a vault's key, as the hints name it.
const VAULT_ROTATE: &str = "keyroostctl fido vault rotate NAME";

/// A vault error as `main` prints it: a CTAP or vault-format error is passed
/// on as itself (so `error_text`'s hints still apply), and the errors whose
/// fix is another command name it.
pub(crate) fn vault_error(e: VaultKeyError) -> Box<dyn Error> {
    match e {
        VaultKeyError::Ctap(e) => Box::new(e),
        VaultKeyError::Vault(e) => Box::new(e),
        VaultKeyError::NoVaults => {
            format!("{e}; create one with: keyroostctl fido vault add NAME").into()
        }
        VaultKeyError::PinNotSet => format!("{e}; set one with: keyroostctl fido pin set").into(),
        VaultKeyError::CreateUndone { left_over, .. } => {
            let hint = match left_over {
                LeftOver {
                    credential: true,
                    data: true,
                } => format!("; remove both with: {VAULT_DELETE}"),
                LeftOver {
                    credential: true,
                    data: false,
                } => format!("; remove it with: {VAULT_DELETE} (the copy listed as (none))"),
                LeftOver {
                    credential: false,
                    data: true,
                } => "; remove it with: keyroostctl fido blob list, then keyroostctl fido blob \
                      delete INDEX"
                    .to_owned(),
                LeftOver {
                    credential: false,
                    data: false,
                } => String::new(),
            };
            format!("{e}{hint}").into()
        }
        VaultKeyError::OldNotDeleted { name, cause, old } => {
            old_not_deleted_text(name.as_deref(), &cause, old).into()
        }
        VaultKeyError::VaultGone { name } => format!(
            "vault \"{}\" is no longer on the key; it was deleted or rotated elsewhere, and \
             nothing was written",
            shown_name(name.as_deref())
        )
        .into(),
        e => Box::new(e),
    }
}

/// A rotate made and checked the new vault but the old one is still on the
/// key: say which copy to delete, and when the survivor needs another
/// rotate to end up on a fresh key.
fn old_not_deleted_text(name: Option<&str>, cause: &VaultKeyError, old: OldVault) -> String {
    let which = match name {
        Some(n) if !n.is_empty() => format!("vault \"{}\"", sanitize_terminal(n)),
        _ => "vault".to_owned(),
    };
    let both_copies = format!(
        "both copies hold the same checked entries, but one still uses the old key: delete \
         either with: {VAULT_DELETE}, then run {VAULT_ROTATE} again so the one left gets a \
         fresh key"
    );
    let next = match old {
        OldVault::Emptied => format!(
            "the old copy is left with no data: delete the copy listed as (none) with: \
             {VAULT_DELETE}"
        ),
        OldVault::Kept => both_copies,
        OldVault::Unknown => format!(
            "whether the old copy still holds its data is not known: if {VAULT_DELETE} shows a \
             copy listed as (none), delete that one; otherwise {both_copies}"
        ),
    };
    format!(
        "the new {which} is in place with every entry checked, but deleting the old one \
         failed: {}; {next}",
        error_words(cause)
    )
}

/// A nested vault error's own text, with `error_text`'s hints.
fn error_words(e: &VaultKeyError) -> String {
    match e {
        VaultKeyError::Ctap(c) => crate::error_text(c),
        other => other.to_string(),
    }
}

/// One vault in `vault list`.
pub(crate) struct VaultRow {
    pub(crate) name: Option<String>,
    /// Full hex; carried for `--json` only, never printed in text.
    pub(crate) credential_id: String,
    pub(crate) entry_count: Option<usize>,
    /// `ok`, `no-data` (opens empty: nothing stored yet) or `unavailable`.
    pub(crate) state: &'static str,
    /// Why an `unavailable` vault does not open.
    pub(crate) detail: Option<String>,
}

/// The `vault list` rows for every vault one unlock opened, in the key's
/// order.
pub(crate) fn rows(u: &Unlocked) -> Vec<VaultRow> {
    u.vaults
        .iter()
        .map(|v| {
            let state = v
                .state
                .as_ref()
                .map(|o| (o.contents.entries.len(), o.stored));
            row_of(&v.vault_ref, state)
        })
        .collect()
}

/// One row from a vault's name and what it opened to: its entry count and
/// whether anything was stored, or why it did not open.
fn row_of(vault_ref: &VaultRef, state: Result<(usize, bool), &VaultProblem>) -> VaultRow {
    let (entry_count, state, detail) = match state {
        Ok((n, true)) => (Some(n), "ok", None),
        Ok((n, false)) => (Some(n), "no-data", None),
        Err(p) => (None, "unavailable", Some(p.to_string())),
    };
    VaultRow {
        name: vault_ref.name.clone(),
        credential_id: hex_encode(&vault_ref.credential_id),
        entry_count,
        state,
        detail,
    }
}

/// `vault list` as text: one line per vault (`(none)` without any), then
/// the store's capacity as `fido blob list` prints it. Never an ID.
pub(crate) fn list_lines(rows: &[VaultRow], cap: &BlobCapacity) -> Vec<String> {
    let mut lines = if rows.is_empty() {
        vec!["(none)".to_owned()]
    } else {
        name_detail_lines(
            rows.iter().map(|r| {
                let what = match (r.entry_count, r.state) {
                    (Some(n), "no-data") => format!("{} (no data stored yet)", entries(n)),
                    (Some(n), _) => entries(n),
                    (None, _) => match &r.detail {
                        Some(d) => format!("(unavailable): {}", sanitize_terminal(d)),
                        None => "(unavailable)".to_owned(),
                    },
                };
                (r.name.as_deref(), what)
            }),
            "",
        )
    };
    lines.push(String::new());
    lines.push(format!(
        "Capacity: {} of {} bytes used, {} free",
        cap.used_bytes, cap.max_bytes, cap.free_bytes
    ));
    lines
}

/// `vault list --json`.
pub(crate) fn list_json(rows: &[VaultRow], cap: &BlobCapacity) -> json_out::FidoVaultListJson {
    json_out::FidoVaultListJson {
        vaults: rows
            .iter()
            .map(|r| json_out::FidoVaultJson {
                name: r.name.clone(),
                credential_id: r.credential_id.clone(),
                state: r.state,
                entry_count: r.entry_count,
                detail: r.detail.clone(),
            })
            .collect(),
        capacity: json_out::FidoLargeBlobCapacityJson {
            max_bytes: cap.max_bytes,
            used_bytes: cap.used_bytes,
            free_bytes: cap.free_bytes,
        },
    }
}

/// An entry's password, read like any secret: asked twice at a terminal,
/// and an empty one is a real answer (an entry with no password).
const ENTRY_PASSWORD: Spec = Spec::new_secret("password", "password")
    .allow_empty()
    .hint("--password env:NAME, --password stdin or --generate-password");

/// An entry's notes (where people keep recovery codes), read like a secret;
/// read only when `--notes` is given. Empty clears them.
const ENTRY_NOTES: Spec = Spec::value("notes", "notes").allow_empty();

/// Refuse early, before any key is looked for, a password or notes source
/// that can't be read. `password_needed`: no `--password` doesn't excuse it
/// (`entry add` without `--generate-password`).
fn check_content<I: SecretIo>(
    sec: &Secrets<I>,
    password: Option<&SecretSource>,
    password_needed: bool,
    notes: Option<&SecretSource>,
) -> Result<(), String> {
    if password.is_some() || password_needed {
        sec.check(&ENTRY_PASSWORD, Source::from_flag(password))?;
    }
    if notes.is_some() {
        sec.check(&ENTRY_NOTES, Source::from_flag(notes))?;
    }
    Ok(())
}

/// The password and notes, in stdin order (password first); the PIN comes
/// after them ([`crate::fido_pin_with`]).
type Content = (Option<Zeroizing<String>>, Option<Zeroizing<String>>);

fn read_content<I: SecretIo>(
    sec: &mut Secrets<I>,
    password: Option<&SecretSource>,
    password_needed: bool,
    notes: Option<&SecretSource>,
) -> Result<Content, String> {
    let password = if password.is_some() || password_needed {
        Some(sec.read(&ENTRY_PASSWORD, Source::from_flag(password))?)
    } else {
        None
    };
    let notes = sec.read_given(&ENTRY_NOTES, Source::from_flag(notes))?;
    Ok((password, notes))
}

/// What an entry command reads in, in order, before it opens the key, and
/// the question it asks after the unlock.
#[derive(Default)]
struct ContentFlags<'a> {
    password: Option<&'a SecretSource>,
    password_needed: bool,
    notes: Option<&'a SecretSource>,
    /// `--yes` and the action of the question asked after the unlock: a run
    /// that could never answer it is refused before the PIN is read.
    asks: Option<(bool, &'a str)>,
}

/// An entry command's key, opened after every secret was read.
struct EntryKey {
    dev: Device,
    key: CtapVaultKey<CtapHidDevice>,
    auth: VaultAuth,
    password: Option<Zeroizing<String>>,
    notes: Option<Zeroizing<String>>,
}

/// One `Secrets` for the command: check every source, select the key,
/// refuse a run that could never answer the question asked after the unlock
/// (`asks`), read the password and notes, then the PIN, then open the key.
fn open_entry_key(
    path: Option<&Path>,
    pin: Option<&SecretSource>,
    c: ContentFlags<'_>,
) -> Result<EntryKey, Box<dyn Error>> {
    let mut sec = Secrets::real();
    check_content(&sec, c.password, c.password_needed, c.notes)?;
    sec.check(&crate::FIDO_PIN, Source::from_flag(pin))?;
    let dev = crate::target::select_fido(path)?;
    if let Some((yes, action)) = c.asks {
        refuse_unaskable(&RealTerm, yes, action, &key_label(&dev))?;
    }
    let (password, notes) = read_content(&mut sec, c.password, c.password_needed, c.notes)?;
    let pin = crate::fido_pin_with(&mut sec, &dev, pin)?;
    let key = open_vault_key(path)?;
    Ok(EntryKey {
        dev,
        key,
        auth: VaultAuth::pin(pin),
        password,
        notes,
    })
}

/// Unlock (one touch) and choose the vault `--vault` names, or the only one.
fn unlock_one(k: &mut EntryKey, name: Option<&str>) -> Result<(Unlocked, usize), Box<dyn Error>> {
    let mut touches = Touches::new(1);
    let unlocked =
        vault::unlock(&mut k.key, &mut k.auth, &mut |s| touches.step(s)).map_err(vault_error)?;
    let matches = vault::matching(&unlocked.vaults, &vault_pick(name)).map_err(vault_error)?;
    let i = choose_vault(
        &unlocked_choices(&unlocked),
        &matches,
        name,
        &mut TermPicker::new(&mut RealTerm),
    )?;
    Ok((unlocked, i))
}

/// The indices of the entries titled exactly `title` (and, when given,
/// with exactly this username), in vault order.
pub(crate) fn entry_matches(v: &Vault, title: &str, username: Option<&str>) -> Vec<usize> {
    v.entries
        .iter()
        .enumerate()
        .filter(|(_, e)| e.title == title && username.is_none_or(|u| e.username == u))
        .map(|(i, _)| i)
        .collect()
}

/// `  TITLE  USERNAME  URL` lines with the columns aligned (no username
/// column when no entry has one). Titles, usernames and URLs are entry
/// data, so every cell and line is built in its own wiped buffer, sized up
/// front so it never grows and leaves no unwiped copy behind.
fn entry_rows<'a>(rows: impl Iterator<Item = &'a Entry>, indent: &str) -> Vec<Zeroizing<String>> {
    let rows: Vec<[Zeroizing<String>; 3]> = rows
        .map(|e| [&e.title, &e.username, &e.url].map(|s| wiped_cell(s)))
        .collect();
    let width = |k: usize| rows.iter().map(|r| r[k].chars().count()).max().unwrap_or(0);
    let (wt, wu) = (width(0), width(1));
    rows.iter()
        .map(|[t, u, url]| {
            // Padding is one byte per missing character, as `{:<w$}` pads.
            let pad = |s: &str, w: usize| w - s.chars().count();
            let mut size = indent.len() + t.len() + pad(t, wt) + 2 + url.len();
            if wu != 0 {
                size += u.len() + pad(u, wu) + 2;
            }
            let mut line = Zeroizing::new(String::with_capacity(size));
            line.push_str(indent);
            line.push_str(t);
            line.extend(std::iter::repeat_n(' ', pad(t, wt) + 2));
            if wu != 0 {
                line.push_str(u);
                line.extend(std::iter::repeat_n(' ', pad(u, wu) + 2));
            }
            line.push_str(url);
            let kept = line.trim_end().len();
            line.truncate(kept);
            line
        })
        .collect()
}

/// [`sanitize_terminal`] into a wiped buffer sized up front (each control,
/// zero-width or bidi character a space, so the text never lengthens).
fn wiped_cell(s: &str) -> Zeroizing<String> {
    let mut cell = Zeroizing::new(String::with_capacity(s.len()));
    cell.extend(s.chars().map(|c| {
        if keyroost_keyring::is_spoofing_char(c) {
            ' '
        } else {
            c
        }
    }));
    cell
}

/// Which of `matches` (indices into `v`, all titled `title`) the command
/// means. One is it; several are asked about at a terminal and refused,
/// listed by username and URL, without one. `username_selects`: the
/// command's `--username` picks among them (`show`, `delete`; on `edit` it
/// is the new value), so the refusal suggests it when the usernames differ.
pub(crate) fn choose_entry(
    v: &Vault,
    title: &str,
    matches: &[usize],
    username_selects: bool,
    picker: &mut dyn Picker,
) -> Result<usize, String> {
    let shown = sanitize_terminal(title);
    match matches {
        [] => Err(format!("no entry titled \"{shown}\" in this vault")),
        [one] => Ok(*one),
        many => {
            let heading = format!("{} entries are titled \"{shown}\":", many.len());
            if picker.interactive() {
                let list: Vec<Choice> = many
                    .iter()
                    .enumerate()
                    .map(|(n, &i)| {
                        let e = &v.entries[i];
                        Choice {
                            number: n + 1,
                            label: if e.username.is_empty() {
                                e.title.clone()
                            } else {
                                format!("{}  {}", e.title, e.username)
                            },
                            endpoint: e.url.clone(),
                        }
                    })
                    .collect();
                let k = picker.pick(&heading, &list)?;
                return many
                    .get(k)
                    .copied()
                    .ok_or_else(|| format!("choice {k} is out of range"));
            }
            let names: Vec<&str> = many
                .iter()
                .map(|&i| v.entries[i].username.as_str())
                .collect();
            let distinct = names
                .iter()
                .enumerate()
                .all(|(a, n)| !names[..a].contains(n));
            let next = if username_selects && distinct {
                "add --username to pick one"
            } else {
                "run this in a terminal to pick one"
            };
            let mut lines = vec![heading];
            lines.extend(
                entry_rows(many.iter().map(|&i| &v.entries[i]), "  ")
                    .iter()
                    .map(|l| l.to_string()),
            );
            lines.push(next.to_owned());
            Err(lines.join("\n"))
        }
    }
}

/// [`entry_matches`] + [`choose_entry`] at the real terminal, saying so
/// when `--username` is what left nothing.
fn pick_entry(
    v: &Vault,
    title: &str,
    username: Option<&str>,
    username_selects: bool,
) -> Result<usize, String> {
    let matches = entry_matches(v, title, username);
    if let (true, Some(u)) = (matches.is_empty(), username) {
        if !entry_matches(v, title, None).is_empty() {
            return Err(format!(
                "no entry titled \"{}\" with username \"{}\" in this vault",
                sanitize_terminal(title),
                sanitize_terminal(u)
            ));
        }
    }
    choose_entry(
        v,
        title,
        &matches,
        username_selects,
        &mut TermPicker::new(&mut RealTerm),
    )
}

/// An entry's `modified_minutes` as a date, `YYYY-MM-DD` (UTC).
pub(crate) fn changed_date(minutes: i64) -> String {
    let (y, m, d) = keyroost_pgpkey::cert::civil_from_days(minutes.div_euclid(24 * 60));
    format!("{y:04}-{m:02}-{d:02}")
}

/// What starts the password line, revealed or not; as wide as the widest
/// label, so the value lines up with the others.
const REVEAL_LABEL: &str = "Password: ";

/// One wiped line: `head`, then `value` with every control, zero-width and
/// bidi character a space (tabs kept), then trailing spaces dropped. Built
/// in a buffer sized up front: sanitizing never lengthens text, so it never
/// grows and leaves no unwiped copy behind ([`sanitize_terminal`] would
/// collect into a growing `String`).
fn wiped_line(head: &str, value: &str) -> Zeroizing<String> {
    let mut line = Zeroizing::new(String::with_capacity(head.len() + value.len()));
    line.push_str(head);
    for c in value.chars() {
        line.push(if c != '\t' && keyroost_keyring::is_spoofing_char(c) {
            ' '
        } else {
            c
        });
    }
    let kept = line.trim_end().len();
    line.truncate(kept);
    line
}

/// `entry show` as text: Title, Username, URL, Notes, Changed, then
/// `Password: (hidden)` or `(none)`. Never the password, never the ID.
///
/// Laid out like [`crate::output::kv_block`] (each value one space after the
/// longest `Key:`), but not built with it: notes are secret and may span
/// lines, and `kv_block` joins plain `String`s, so every line here is its
/// own wiped buffer and a note's later lines stay under its column.
pub(crate) fn entry_lines(e: &Entry) -> Vec<Zeroizing<String>> {
    let head = |name: &str| format!("{:<w$}", format!("{name}:"), w = REVEAL_LABEL.len());
    let field =
        |name: &str, v: &str| wiped_line(&head(name), if v.is_empty() { "(none)" } else { v });
    let mut lines = vec![
        field("Title", &e.title),
        field("Username", &e.username),
        field("URL", &e.url),
    ];
    if e.notes.is_empty() {
        lines.push(field("Notes", ""));
    } else {
        let indent = " ".repeat(REVEAL_LABEL.len());
        for (n, l) in e.notes.split('\n').enumerate() {
            let h = if n == 0 {
                head("Notes")
            } else {
                indent.clone()
            };
            lines.push(wiped_line(&h, l));
        }
    }
    lines.push(field("Changed", &changed_date(e.modified_minutes)));
    let password = if e.password.is_empty() {
        "(none)"
    } else {
        "(hidden)"
    };
    lines.push(wiped_line(REVEAL_LABEL, password));
    lines
}

/// Print `lines` to stdout as they are, with no formatted copy on the way
/// (`outln!` would format each into a new `String`).
fn print_lines(out: &mut impl Write, lines: &[Zeroizing<String>]) -> io::Result<()> {
    for l in lines {
        out.write_all(l.as_bytes())?;
        out.write_all(b"\n")?;
    }
    out.flush()
}

/// How `entry show --reveal` gives the password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RevealPlan {
    /// A terminal: the entry, the password on its own line until Enter,
    /// then that line erased.
    ShowUntilEnter,
    /// A pipe or a file: the password bytes alone, no newline.
    PasswordOnly,
    /// `--json`: the entry with its password.
    Json,
}

pub(crate) fn reveal_plan(stdout_is_tty: bool, json: bool) -> RevealPlan {
    match (json, stdout_is_tty) {
        (true, _) => RevealPlan::Json,
        (false, true) => RevealPlan::ShowUntilEnter,
        (false, false) => RevealPlan::PasswordOnly,
    }
}

/// Exactly the password's bytes: no newline, so `| xclip` or `> file` gets
/// the password and nothing else.
pub(crate) fn write_password_only(out: &mut impl Write, p: &str) -> io::Result<()> {
    out.write_all(p.as_bytes())
}

/// Erases the shown password once the Enter wait is over. The reader
/// (rpassword) writes a newline to the terminal when it returns, which
/// leaves the cursor at the start of the line below the password: up one
/// line, then clear that whole line.
pub(crate) fn erase_shown_line() -> &'static str {
    "\x1b[1A\x1b[2K"
}

/// Erases the password when the Enter wait failed: no newline was written,
/// so the password is still on the cursor's own line.
pub(crate) fn erase_current_line() -> &'static str {
    "\r\x1b[2K"
}

/// Whether the terminal the Enter wait reads (and the reader writes its
/// newline to) can be opened: checked before the password is shown, so a
/// failure never leaves it on screen.
fn terminal_opens() -> io::Result<()> {
    let open = |p: &str, read: bool| {
        std::fs::OpenOptions::new()
            .read(read)
            .write(true)
            .open(p)
            .map(drop)
    };
    if cfg!(windows) {
        open("CONIN$", true)?;
        open("CONOUT$", false)
    } else {
        open("/dev/tty", true)
    }
}

/// [`RevealPlan::ShowUntilEnter`]: the entry, `Password: p` with no
/// newline, a wait for Enter at the terminal (never stdin, which may carry
/// the PIN), then the password line erased.
fn show_until_enter(e: &Entry) -> Result<(), Box<dyn Error>> {
    let lines = entry_lines(e);
    let mut out = io::stdout();
    if e.password.is_empty() {
        print_lines(&mut out, &lines)?;
        return Ok(());
    }
    terminal_opens().map_err(|err| {
        format!("could not open the terminal to wait for Enter ({err}); the password was not shown")
    })?;
    print_lines(&mut out, &lines[..lines.len() - 1])?;
    // Shown on a terminal: no control characters reach it. (Trailing
    // spaces trimmed: invisible there anyway.)
    let shown = wiped_line(REVEAL_LABEL, &e.password);
    out.write_all(shown.as_bytes())?;
    out.flush()?;
    let waited = rpassword::prompt_password("").map(Zeroizing::new);
    let erase = if waited.is_ok() {
        erase_shown_line()
    } else {
        erase_current_line()
    };
    out.write_all(erase.as_bytes())?;
    out.flush()?;
    waited.map(drop).map_err(|err| match err.kind() {
        io::ErrorKind::Interrupted | io::ErrorKind::UnexpectedEof => {
            "canceled while the password was shown; it is erased".into()
        }
        _ => format!("could not wait for Enter ({err}); the password is erased").into(),
    })
}

/// `value` as pretty JSON and a newline, built in a wiped buffer sized up
/// front (so no growth leaves an unwiped copy): for a document that holds
/// a password or notes.
fn write_json_wiped<T: serde::Serialize>(
    out: &mut impl Write,
    value: &T,
) -> Result<(), Box<dyn Error>> {
    struct Count(usize);
    impl Write for Count {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0 += b.len();
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut size = Count(0);
    serde_json::to_writer_pretty(&mut size, value)?;
    let mut buf = Zeroizing::new(Vec::with_capacity(size.0 + 1));
    serde_json::to_writer_pretty(&mut *buf, value)?;
    buf.push(b'\n');
    out.write_all(&buf)?;
    out.flush()?;
    Ok(())
}

/// `entry list --json`: ids and every field but the password and notes.
/// An optional entry field for JSON: `null` when it is empty (nothing
/// there), as text output shows `(none)`.
fn unless_empty(s: &str) -> Option<String> {
    (!s.is_empty()).then(|| s.to_owned())
}

pub(crate) fn entry_list_json(vault: Option<&str>, v: &Vault) -> json_out::FidoVaultEntryListJson {
    json_out::FidoVaultEntryListJson {
        vault: vault.map(str::to_owned),
        entries: v
            .entries
            .iter()
            .map(|e| json_out::FidoVaultEntryJson {
                id: e.id.clone(),
                title: e.title.clone(),
                username: unless_empty(&e.username),
                url: unless_empty(&e.url),
                changed: changed_date(e.modified_minutes),
            })
            .collect(),
    }
}

/// `entry show --json`; the password only when `reveal`.
pub(crate) fn entry_show_json(
    vault: Option<&str>,
    e: &Entry,
    reveal: bool,
) -> json_out::FidoVaultEntryShowJson {
    json_out::FidoVaultEntryShowJson {
        vault: vault.map(str::to_owned),
        id: e.id.clone(),
        title: e.title.clone(),
        username: unless_empty(&e.username),
        url: unless_empty(&e.url),
        notes: unless_empty(&e.notes),
        changed: changed_date(e.modified_minutes),
        password: reveal.then(|| e.password.to_string()),
    }
}

/// `entry list` as text: one aligned line per entry, `(none)` without any.
fn entry_list_lines(v: &Vault) -> Vec<Zeroizing<String>> {
    if v.entries.is_empty() {
        return vec![Zeroizing::new("(none)".to_owned())];
    }
    entry_rows(v.entries.iter(), "")
}

/// `entry delete`'s question, in `confirm`'s form.
fn entry_delete_question(
    term: &mut dyn crate::prompt::Term,
    yes: bool,
    title: &str,
    vault: Option<&str>,
    key: &str,
) -> Result<bool, String> {
    confirm(
        term,
        yes,
        &entry_delete_action(title, Some(&shown_name(vault))),
        key,
    )
}

/// `entry delete`'s action: the entry, and the vault when it is known
/// (`--vault` before the unlock; the chosen one's shown name after).
fn entry_delete_action(title: &str, vault: Option<&str>) -> String {
    let title = sanitize_terminal(title);
    match vault {
        Some(v) => format!(
            "delete entry \"{title}\" from vault \"{}\"",
            sanitize_terminal(v)
        ),
        None => format!("delete entry \"{title}\""),
    }
}

/// The progress line a save prints when it writes.
pub(crate) const SAVE_LINE: &str = "Saving to the key\u{2026}";

/// A save's progress: [`SAVE_LINE`] once, even when a fresh-token retry
/// repeats the write step.
#[derive(Default)]
pub(crate) struct SaveProgress {
    shown: bool,
}

impl SaveProgress {
    pub(crate) fn line(&mut self, step: VaultStep) -> Option<&'static str> {
        if step == VaultStep::Write && !self.shown {
            self.shown = true;
            return Some(SAVE_LINE);
        }
        None
    }

    /// An `on_step` callback.
    pub(crate) fn step(&mut self, step: VaultStep) {
        if let Some(line) = self.line(step) {
            crate::output::status(line);
        }
    }
}

/// A failed entry save as `main` prints it: a conflict says to run the
/// command again; everything else as [`vault_error`].
fn entry_save_error(e: VaultKeyError) -> Box<dyn Error> {
    match e {
        VaultKeyError::Conflict => "this entry changed on the key while the command ran; \
                                    nothing was written. Run it again."
            .into(),
        e => vault_error(e),
    }
}

/// Save one change to the chosen vault, with its progress line.
fn save_change(
    k: &mut EntryKey,
    open: &mut vault::OpenVault,
    change: &Change,
) -> Result<(), Box<dyn Error>> {
    let mut progress = SaveProgress::default();
    vault::save(&mut k.key, &mut k.auth, open, change, &mut |s| {
        progress.step(s)
    })
    .map_err(entry_save_error)?;
    Ok(())
}

/// What `entry add` prints when done.
fn added_line(title: &str, vault: Option<&str>) -> String {
    format!(
        "Entry \"{}\" added to vault \"{}\".",
        sanitize_terminal(title),
        shown_name(vault)
    )
}

/// The command that shows a generated password: `--vault` when the key has
/// several vaults, `--username` when the title is shared.
fn reveal_hint(title: &str, vault: Option<&str>, username: Option<&str>) -> String {
    let mut cmd = format!(
        "See the new password with keyroostctl fido vault entry show {}",
        export_hint_arg(title)
    );
    if let Some(v) = vault {
        cmd.push_str(&format!(" --vault {}", export_hint_arg(v)));
    }
    if let Some(u) = username {
        cmd.push_str(&format!(" --username {}", export_hint_arg(u)));
    }
    cmd.push_str(" --reveal");
    cmd
}

/// [`reveal_hint`] for the entry just saved as `title` / `username` in the
/// vault `name` (one of `vaults` on the key). `contents` must be the vault
/// as saved: `save` updates the open vault in place (transport test
/// `add_edit_delete_apply_to_current_contents`), so a title the new entry
/// shares is seen there.
fn reveal_hint_for(
    name: Option<&str>,
    contents: &Vault,
    vaults: usize,
    title: &str,
    username: &str,
) -> String {
    let shared = entry_matches(contents, title, None).len() > 1;
    reveal_hint(
        title,
        name.filter(|_| vaults > 1),
        Some(username).filter(|u| shared && !u.is_empty()),
    )
}

/// A generated password, `--length` long (20 by default).
fn generated(length: Option<usize>) -> Result<Zeroizing<String>, Box<dyn Error>> {
    Ok(keyroost_vault::generate_password(
        &keyroost_vault::GenOptions {
            length: length.unwrap_or(20),
            ..Default::default()
        },
    )?)
}

/// A title an entry may have: not empty, since entries are found by it.
fn check_title(title: &str) -> Result<(), String> {
    if title.is_empty() {
        return Err("an entry needs a title".to_owned());
    }
    Ok(())
}

/// The text of a secret read as an entry field, moved out of its wiped
/// buffer into the entry (which wipes it in turn).
fn moved_text(mut s: Zeroizing<String>) -> String {
    std::mem::take(&mut *s)
}

/// Set an entry's text field to `value`, wiping what it held first (a
/// plain assignment or `clone_from` can free the old bytes unwiped).
fn replace_text(field: &mut String, value: &str) {
    field.zeroize();
    field.push_str(value);
}

fn run_vault_entry(cmd: &FidoVaultEntryCmd) -> Result<(), Box<dyn Error>> {
    match cmd {
        FidoVaultEntryCmd::List { vault, pin, path } => {
            let mut k = open_entry_key(path.as_deref(), pin.as_ref(), ContentFlags::default())?;
            let (mut unlocked, i) = unlock_one(&mut k, vault.as_deref())?;
            let open = unlocked.vaults[i].open_mut().map_err(vault_error)?;
            if json_output() {
                return emit_json(&entry_list_json(
                    open.vault_ref.name.as_deref(),
                    &open.contents,
                ));
            }
            // Entry data: printed from its wiped lines, never formatted
            // into a new `String` (as `entry show` prints).
            Ok(print_lines(
                &mut io::stdout(),
                &entry_list_lines(&open.contents),
            )?)
        }
        FidoVaultEntryCmd::Show {
            title,
            username,
            vault,
            reveal,
            pin,
            path,
        } => {
            let mut k = open_entry_key(path.as_deref(), pin.as_ref(), ContentFlags::default())?;
            let (mut unlocked, i) = unlock_one(&mut k, vault.as_deref())?;
            let open = unlocked.vaults[i].open_mut().map_err(vault_error)?;
            let n = pick_entry(&open.contents, title, username.as_deref(), true)?;
            let e = &open.contents.entries[n];
            let name = open.vault_ref.name.as_deref();
            let plan = reveal_plan(io::stdout().is_terminal(), json_output());
            match (*reveal, plan) {
                (_, RevealPlan::Json) => {
                    write_json_wiped(&mut io::stdout().lock(), &entry_show_json(name, e, *reveal))
                }
                (false, _) => Ok(print_lines(&mut io::stdout(), &entry_lines(e))?),
                (true, RevealPlan::ShowUntilEnter) => show_until_enter(e),
                (true, RevealPlan::PasswordOnly) => {
                    let mut out = io::stdout().lock();
                    write_password_only(&mut out, &e.password)?;
                    out.flush()?;
                    Ok(())
                }
            }
        }
        FidoVaultEntryCmd::Add {
            title,
            vault,
            username,
            url,
            notes,
            password,
            generate_password,
            length,
            pin,
            path,
        } => {
            check_title(title)?;
            let mut k = open_entry_key(
                path.as_deref(),
                pin.as_ref(),
                ContentFlags {
                    password: password.as_ref(),
                    password_needed: !generate_password,
                    notes: notes.as_ref(),
                    asks: None,
                },
            )?;
            let password = match k.password.take() {
                Some(p) => p,
                None => generated(*length)?,
            };
            let notes = k.notes.take().map(moved_text).unwrap_or_default();
            let (mut unlocked, i) = unlock_one(&mut k, vault.as_deref())?;
            let vaults = unlocked.vaults.len();
            let open = unlocked.vaults[i].open_mut().map_err(vault_error)?;
            let entry = Entry {
                id: keyroost_vault::new_id(),
                title: title.clone(),
                username: username.clone().unwrap_or_default(),
                password,
                url: url.clone().unwrap_or_default(),
                notes,
                modified_minutes: vault::now_minutes(),
            };
            let username = entry.username.clone();
            save_change(&mut k, open, &Change::Add(entry))?;
            outln!("{}", added_line(title, open.vault_ref.name.as_deref()));
            if *generate_password {
                outln!(
                    "{}",
                    reveal_hint_for(
                        open.vault_ref.name.as_deref(),
                        &open.contents,
                        vaults,
                        title,
                        &username
                    )
                );
            }
            Ok(())
        }
        FidoVaultEntryCmd::Edit {
            title,
            vault,
            new_title,
            username,
            url,
            notes,
            password,
            generate_password,
            length,
            pin,
            path,
        } => {
            if let Some(t) = new_title {
                check_title(t)?;
            }
            let mut k = open_entry_key(
                path.as_deref(),
                pin.as_ref(),
                ContentFlags {
                    password: password.as_ref(),
                    password_needed: false,
                    notes: notes.as_ref(),
                    asks: None,
                },
            )?;
            let new_password = match k.password.take() {
                Some(p) => Some(p),
                None if *generate_password => Some(generated(*length)?),
                None => None,
            };
            let new_notes = k.notes.take().map(moved_text);
            let (mut unlocked, i) = unlock_one(&mut k, vault.as_deref())?;
            let vaults = unlocked.vaults.len();
            let open = unlocked.vaults[i].open_mut().map_err(vault_error)?;
            // `--username` is the new value here, never a selector.
            let n = pick_entry(&open.contents, title, None, false)?;
            let before = open.contents.entries[n].clone();
            let mut after = before.clone();
            // The old values are entry data too: wiped as they are replaced.
            if let Some(t) = new_title {
                replace_text(&mut after.title, t);
            }
            if let Some(u) = username {
                replace_text(&mut after.username, u);
            }
            if let Some(u) = url {
                replace_text(&mut after.url, u);
            }
            if let Some(n) = new_notes {
                after.notes.zeroize();
                after.notes = n;
            }
            if let Some(p) = new_password {
                after.password = p;
            }
            after.modified_minutes = vault::now_minutes();
            let (now_title, now_username) = (
                Zeroizing::new(after.title.clone()),
                Zeroizing::new(after.username.clone()),
            );
            save_change(&mut k, open, &Change::Edit { before, after })?;
            outln!("Entry \"{}\" updated.", sanitize_terminal(title));
            if *generate_password {
                outln!(
                    "{}",
                    reveal_hint_for(
                        open.vault_ref.name.as_deref(),
                        &open.contents,
                        vaults,
                        &now_title,
                        &now_username,
                    )
                );
            }
            Ok(())
        }
        FidoVaultEntryCmd::Delete {
            title,
            username,
            vault,
            yes,
            pin,
            path,
        } => {
            let action = entry_delete_action(title, vault.as_deref());
            let mut k = open_entry_key(
                path.as_deref(),
                pin.as_ref(),
                ContentFlags {
                    asks: Some((*yes, &action)),
                    ..ContentFlags::default()
                },
            )?;
            let (mut unlocked, i) = unlock_one(&mut k, vault.as_deref())?;
            let open = unlocked.vaults[i].open_mut().map_err(vault_error)?;
            let n = pick_entry(&open.contents, title, username.as_deref(), true)?;
            let before = open.contents.entries[n].clone();
            // The open handle ties the question to the key (`confirm_on_held`).
            entry_delete_question(
                &mut RealTerm,
                *yes,
                title,
                open.vault_ref.name.as_deref(),
                &key_label(&k.dev),
            )?;
            save_change(&mut k, open, &Change::Delete { before })?;
            outln!("Entry \"{}\" deleted.", sanitize_terminal(title));
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyroost_resolve::Picker;

    /// A scripted terminal: whether one is present, the answers it types,
    /// and what it was told and asked.
    struct ScriptTerm {
        present: bool,
        answers: Vec<String>,
        said: Vec<String>,
        asked: Vec<String>,
    }

    impl ScriptTerm {
        fn new(present: bool, answers: &[&str]) -> Self {
            ScriptTerm {
                present,
                answers: answers.iter().rev().map(|s| s.to_string()).collect(),
                said: Vec::new(),
                asked: Vec::new(),
            }
        }
    }

    impl crate::prompt::Term for ScriptTerm {
        fn present(&self) -> bool {
            self.present
        }
        fn say(&mut self, line: &str) {
            self.said.push(line.to_owned());
        }
        fn ask(&mut self, prompt: &str) -> std::io::Result<String> {
            self.asked.push(prompt.to_owned());
            Ok(self.answers.pop().unwrap_or_default())
        }
    }

    fn row(name: Option<&str>, id: &str, count: Option<usize>, state: &'static str) -> VaultRow {
        VaultRow {
            name: name.map(str::to_owned),
            credential_id: id.to_owned(),
            entry_count: count,
            state,
            detail: (state == "unavailable").then(|| "the stored data is damaged".to_owned()),
        }
    }

    fn cap() -> BlobCapacity {
        BlobCapacity {
            max_bytes: 1024,
            used_bytes: 300,
            free_bytes: 724,
            entry_count: 2,
        }
    }

    fn choice(name: Option<&str>, detail: &str) -> VaultChoice {
        VaultChoice {
            name: name.map(str::to_owned),
            detail: detail.to_owned(),
        }
    }

    #[test]
    fn touch_line_counts() {
        assert_eq!(touch_line(1, 1), "touch the key now\u{2026}");
        assert_eq!(touch_line(1, 2), "touch the key (1 of 2)\u{2026}");
        assert_eq!(touch_line(3, 3), "touch the key (3 of 3)\u{2026}");

        // Only the steps that wait on a touch count, in order.
        let mut t = Touches::new(2);
        assert_eq!(
            t.line(VaultStep::CreateTouch).as_deref(),
            Some("touch the key (1 of 2)\u{2026}")
        );
        assert_eq!(t.line(VaultStep::Write), None);
        assert_eq!(
            t.line(VaultStep::UnlockTouch).as_deref(),
            Some("touch the key (2 of 2)\u{2026}")
        );
        let mut t = Touches::new(1);
        assert_eq!(
            t.line(VaultStep::UnlockTouch).as_deref(),
            Some("touch the key now\u{2026}")
        );
    }

    #[test]
    fn list_lines_show_counts_and_states() {
        let rows = [
            row(Some("Personal"), "a1b2c3d4", Some(12), "ok"),
            row(Some("Work"), "e5f6a7b8", Some(1), "ok"),
            row(None, "c9d0e1f2", Some(0), "no-data"),
            row(Some(""), "0badc0de", None, "unavailable"),
        ];
        let lines = list_lines(&rows, &cap());
        assert_eq!(
            lines,
            [
                "Personal   12 entries",
                "Work       1 entry",
                "(unnamed)  0 entries (no data stored yet)",
                "(unnamed)  (unavailable): the stored data is damaged",
                "",
                "Capacity: 300 of 1024 bytes used, 724 free",
            ]
        );
        for id in ["a1b2c3d4", "e5f6a7b8", "c9d0e1f2", "0badc0de"] {
            assert!(lines.iter().all(|l| !l.contains(id)), "{id} in {lines:?}");
        }

        assert_eq!(
            list_lines(&[], &cap()),
            ["(none)", "", "Capacity: 300 of 1024 bytes used, 724 free"]
        );
    }

    #[test]
    fn list_lines_neutralize_control_chars() {
        let mut bad = row(Some("a\u{1b}[2Jb"), "00", None, "unavailable");
        bad.detail = Some("x\u{1b}]0;title\u{7}y".to_owned());
        let lines = list_lines(&[bad], &cap());
        for l in &lines {
            assert!(!l.contains('\u{1b}') && !l.contains('\u{7}'), "{l:?}");
        }
    }

    #[test]
    fn rows_say_what_each_vault_holds() {
        let vref = |name: &str| keyroost_transport::vault::VaultRef {
            credential_id: vec![0xAB, 0x01],
            name: Some(name.to_owned()),
        };
        let ok = row_of(&vref("A"), Ok((3, true)));
        assert_eq!(
            (ok.state, ok.entry_count, ok.detail.as_deref()),
            ("ok", Some(3), None)
        );
        assert_eq!(ok.credential_id, "ab01");
        let empty = row_of(&vref("B"), Ok((0, false)));
        assert_eq!((empty.state, empty.entry_count), ("no-data", Some(0)));
        let problem = VaultProblem::NoSecret;
        let bad = row_of(&vref("C"), Err(&problem));
        assert_eq!((bad.state, bad.entry_count), ("unavailable", None));
        assert_eq!(bad.detail, Some(problem.to_string()));
    }

    #[test]
    fn list_json_fields() {
        let rows = [
            row(Some("Personal"), "a1b2", Some(12), "ok"),
            row(None, "c3d4", None, "unavailable"),
        ];
        let v = serde_json::to_value(list_json(&rows, &cap())).unwrap();
        let mut top: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        top.sort_unstable();
        assert_eq!(top, ["capacity", "vaults"]);
        for vault in v["vaults"].as_array().unwrap() {
            let mut keys: Vec<&str> = vault
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            keys.sort_unstable();
            assert_eq!(
                keys,
                ["credential_id", "detail", "entry_count", "name", "state"]
            );
        }
        assert_eq!(v["vaults"][0]["credential_id"], "a1b2");
        assert_eq!(v["vaults"][0]["entry_count"], 12);
        assert!(v["vaults"][1]["name"].is_null());
        assert!(v["vaults"][1]["entry_count"].is_null());
        assert_eq!(v["capacity"]["free_bytes"], 724);
    }

    #[test]
    fn one_match_needs_no_question() {
        let choices = [
            choice(Some("Personal"), "12 entries"),
            choice(Some("Work"), "3 entries"),
        ];
        let mut t = ScriptTerm::new(false, &[]);
        let mut p = crate::prompt::TermPicker::new(&mut t);
        assert_eq!(choose_vault(&choices, &[1], Some("Work"), &mut p), Ok(1));
        assert!(t.asked.is_empty());
    }

    #[test]
    fn ambiguous_vault_in_a_terminal_uses_the_picker() {
        let choices = [
            choice(Some("Work"), "1 entry"),
            choice(Some("Personal"), "12 entries"),
            choice(Some("Personal"), "3 entries"),
        ];
        let mut t = ScriptTerm::new(true, &["2\n"]);
        let picked = {
            let mut p = crate::prompt::TermPicker::new(&mut t);
            assert!(p.interactive());
            choose_vault(&choices, &[1, 2], Some("Personal"), &mut p)
        };
        assert_eq!(picked, Ok(2), "the second Personal");
        assert_eq!(t.said[0], "2 vaults are named \"Personal\":");
        assert!(t.said[1].contains("1) Personal") && t.said[1].contains("12 entries"));
        assert!(t.said[2].contains("2) Personal") && t.said[2].contains("3 entries"));
        assert_eq!(t.asked, ["Select [1/2]: "]);

        // No name given: every vault is a match.
        let mut t = ScriptTerm::new(true, &["1\n"]);
        let picked = {
            let mut p = crate::prompt::TermPicker::new(&mut t);
            choose_vault(&choices, &[0, 1, 2], None, &mut p)
        };
        assert_eq!(picked, Ok(0));
        assert_eq!(t.said[0], "This key has 3 vaults:");
    }

    #[test]
    fn ambiguous_vault_without_terminal_is_refused_with_details() {
        let choices = [
            choice(Some("Personal"), "12 entries"),
            choice(Some("Personal"), "3 entries"),
        ];
        let mut t = ScriptTerm::new(false, &["1\n"]);
        let e = {
            let mut p = crate::prompt::TermPicker::new(&mut t);
            choose_vault(&choices, &[0, 1], Some("Personal"), &mut p).unwrap_err()
        };
        assert!(t.asked.is_empty(), "never reads stdin without a terminal");
        assert_eq!(
            e,
            "2 vaults are named \"Personal\":\n  Personal  12 entries\n  Personal  3 entries\n\
             run this in a terminal to pick one"
        );
    }

    #[test]
    fn several_vaults_without_a_name_and_no_terminal_say_use_vault() {
        let choices = [
            choice(Some("Personal"), "12 entries"),
            choice(None, "(no data stored yet)"),
            choice(Some("a\u{1b}[2Jb"), "(unavailable)"),
        ];
        let mut t = ScriptTerm::new(false, &[]);
        let e = {
            let mut p = crate::prompt::TermPicker::new(&mut t);
            choose_vault(&choices, &[0, 1, 2], None, &mut p).unwrap_err()
        };
        assert!(e.starts_with("this key has 3 vaults:\n"), "{e}");
        assert!(e.contains("\n  Personal   12 entries\n"), "{e}");
        assert!(e.contains("\n  (unnamed)  (no data stored yet)\n"), "{e}");
        assert!(!e.contains('\u{1b}'), "{e:?}");
        assert!(e.ends_with("\npick one with --vault NAME"), "{e}");
    }

    #[test]
    fn stored_data_words() {
        assert_eq!(stored_detail(StoredData::Bytes(812)), "812 bytes stored");
        assert_eq!(stored_detail(StoredData::Empty), "(none)");
        assert_eq!(stored_detail(StoredData::Unreadable), "(unavailable)");
        assert_eq!(stored_detail(StoredData::Unknown), "");
    }

    #[test]
    fn vault_pick_by_name_or_only() {
        assert_eq!(vault_pick(None), VaultPick::Only);
        assert_eq!(vault_pick(Some("Work")), VaultPick::Name("Work"));
    }

    #[test]
    fn vault_error_keeps_ctap_hints() {
        let e = vault_error(VaultKeyError::Ctap(
            keyroost_ctap::CtapError::PinChangeRequired,
        ));
        let text = crate::error_text(e.as_ref());
        assert!(text.contains("keyroostctl fido pin change"), "{text}");
    }

    #[test]
    fn vault_error_names_the_next_step() {
        let text = |e| crate::error_text(vault_error(e).as_ref());
        assert!(
            text(VaultKeyError::NoVaults)
                .ends_with("; create one with: keyroostctl fido vault add NAME"),
            "{}",
            text(VaultKeyError::NoVaults)
        );
        assert!(
            text(VaultKeyError::PinNotSet).ends_with("; set one with: keyroostctl fido pin set")
        );
        // Anything else is the transport's own text.
        assert_eq!(
            text(VaultKeyError::Conflict),
            VaultKeyError::Conflict.to_string()
        );
    }

    #[test]
    fn a_failed_create_says_how_to_remove_what_is_left() {
        let undone = |credential, data| VaultKeyError::CreateUndone {
            cause: Box::new(VaultKeyError::NoLargeBlobKey),
            left_over: LeftOver { credential, data },
        };
        let text = |e| crate::error_text(vault_error(e).as_ref());
        const VAULT_DELETE: &str =
            "remove it with: keyroostctl fido vault delete NAME (the copy listed as (none))";
        const BLOB_DELETE: &str =
            "remove it with: keyroostctl fido blob list, then keyroostctl fido blob delete INDEX";

        let none = text(undone(false, false));
        assert!(!none.contains("keyroostctl"), "{none}");
        let cred = text(undone(true, false));
        assert!(cred.ends_with(&format!("; {VAULT_DELETE}")), "{cred}");
        assert!(!cred.contains("fido blob"), "{cred}");
        let data = text(undone(false, true));
        assert!(data.ends_with(&format!("; {BLOB_DELETE}")), "{data}");
        assert!(!data.contains("vault delete"), "{data}");
        // A vault delete removes the credential and its data together.
        let both = text(undone(true, true));
        assert!(
            both.ends_with("; remove both with: keyroostctl fido vault delete NAME"),
            "{both}"
        );
    }

    #[test]
    fn a_rotate_whose_old_vault_stayed_says_which_copy_to_delete() {
        let left = |old| VaultKeyError::OldNotDeleted {
            name: Some("Personal".to_owned()),
            cause: Box::new(VaultKeyError::Ctap(keyroost_ctap::CtapError::StatusCode(
                0x2F,
            ))),
            old,
        };
        let text = |e| crate::error_text(vault_error(e).as_ref());
        for old in [OldVault::Kept, OldVault::Emptied, OldVault::Unknown] {
            let t = text(left(old));
            assert!(
                t.starts_with(
                    "the new vault \"Personal\" is in place with every entry checked, \
                     but deleting the old one failed: "
                ),
                "{t}"
            );
            assert!(!t.contains("deleting either is safe"), "{t}");
            assert!(t.contains("keyroostctl fido vault delete NAME"), "{t}");
        }
        let emptied = text(left(OldVault::Emptied));
        assert!(emptied.contains("listed as (none)"), "{emptied}");
        assert!(!emptied.contains("rotate"), "{emptied}");
        let kept = text(left(OldVault::Kept));
        assert!(kept.contains("one still uses the old key"), "{kept}");
        assert!(
            kept.contains("then run keyroostctl fido vault rotate NAME again"),
            "{kept}"
        );
        let unknown = text(left(OldVault::Unknown));
        assert!(unknown.contains("listed as (none)"), "{unknown}");
        assert!(
            unknown.contains("then run keyroostctl fido vault rotate NAME again"),
            "{unknown}"
        );
    }

    #[test]
    fn backup_hint_text() {
        assert_eq!(
            backup_hint("Personal"),
            "Vault \"Personal\" created on this key.\n\
             If the key is lost or reset, the vault goes with it. Keep a backup:\n  \
             keyroostctl fido vault export Personal -o personal.t2vault"
        );
        assert!(
            backup_hint("Work Mail").ends_with(
                "Keep a backup:\n  keyroostctl fido vault export 'Work Mail' -o work-mail.t2vault"
            ),
            "{}",
            backup_hint("Work Mail")
        );
    }

    #[test]
    fn export_hint_arg_quotes_only_what_needs_it() {
        assert_eq!(export_hint_arg("Mail.backup_2-x"), "Mail.backup_2-x");
        assert_eq!(export_hint_arg("Work Mail"), "'Work Mail'");
        assert_eq!(export_hint_arg("Café"), "'Café'");
        // Single quotes keep everything literal; a quote in the name is closed,
        // escaped and reopened.
        assert_eq!(export_hint_arg("a'b$c"), r"'a'\''b$c'");
        assert!(!export_hint_arg("a\u{1b}[2Jb").contains('\u{1b}'));
    }

    #[test]
    fn backup_file_name_is_plain() {
        assert_eq!(backup_file_name("Personal"), "personal.t2vault");
        assert_eq!(backup_file_name("Work  Mail!"), "work-mail.t2vault");
        assert_eq!(backup_file_name("--Home/Bank--"), "home-bank.t2vault");
        assert_eq!(backup_file_name("Café"), "café.t2vault");
        assert_eq!(backup_file_name("Почта 2"), "почта-2.t2vault");
        assert_eq!(backup_file_name("ééé"), "ééé.t2vault");
        assert_eq!(backup_file_name("!!!"), "vault.t2vault");
        // Never a path: no separator, and the only dot is the extension's.
        for name in ["../..", "a/../b", "C:\\x", "..", ".hidden", "a.b.c"] {
            let f = backup_file_name(name);
            assert!(
                !f.contains('/') && !f.contains('\\') && !f.contains(':'),
                "{f}"
            );
            assert_eq!(f.matches('.').count(), 1, "{f}");
            assert!(!f.starts_with('.') && !f.starts_with('-'), "{f}");
        }
        assert_eq!(backup_file_name("../.."), "vault.t2vault");
    }

    #[test]
    fn delete_note_text() {
        assert_eq!(
            delete_note("Personal"),
            "Its entries go with it. To keep them, export it first: \
             keyroostctl fido vault export Personal -o personal.t2vault"
        );
        assert!(delete_note("Work Mail").ends_with("export 'Work Mail' -o work-mail.t2vault"));
    }

    #[test]
    fn delete_question_uses_the_confirm_form() {
        let mut t = ScriptTerm::new(true, &["y\n"]);
        assert_eq!(
            delete_question(&mut t, false, "Personal", "yubi-test"),
            Ok(true)
        );
        assert_eq!(t.asked, ["delete vault \"Personal\" on yubi-test? [y/N] "]);

        let mut t = ScriptTerm::new(true, &["\n"]);
        assert_eq!(
            delete_question(&mut t, false, "Personal", "yubi-test"),
            Err("canceled; nothing was changed".to_owned())
        );

        // -y asks nothing.
        let mut t = ScriptTerm::new(true, &[]);
        assert_eq!(
            delete_question(&mut t, true, "Personal", "yubi-test"),
            Ok(false)
        );
        assert!(t.asked.is_empty());
    }

    #[test]
    fn delete_without_terminal_is_refused() {
        let mut t = ScriptTerm::new(false, &["y\n"]);
        assert_eq!(
            delete_question(&mut t, false, "x", "yubi-test"),
            Err(
                "refusing to delete vault \"x\" on yubi-test without confirmation; add --yes"
                    .to_owned()
            )
        );
        assert!(t.asked.is_empty(), "never reads stdin without a terminal");
    }

    #[test]
    fn rotate_question_text() {
        let mut t = ScriptTerm::new(true, &["y\n"]);
        assert_eq!(
            rotate_question(&mut t, false, "Personal", "yubi-test"),
            Ok(true)
        );
        assert_eq!(
            t.asked,
            [
                "Rotate the key of vault \"Personal\" on yubi-test? A new vault replaces it; the \
              old one is deleted after every entry is checked. Continue? [y/N] "
            ]
        );

        let mut t = ScriptTerm::new(false, &[]);
        assert_eq!(
            rotate_question(&mut t, false, "Personal", "yubi-test"),
            Err(
                "refusing to rotate the key of vault \"Personal\" on yubi-test without \
                 confirmation; add --yes"
                    .to_owned()
            )
        );
    }

    #[test]
    fn rotated_and_deleted_lines() {
        assert_eq!(
            rotated_line("Personal", 12),
            "Vault \"Personal\" rotated: a new vault holds its 12 entries and the old one is \
             deleted."
        );
        assert!(rotated_line("Personal", 1).contains("holds its 1 entry and"));
        assert_eq!(deleted_line("Personal"), "Vault \"Personal\" deleted.");
        assert!(!deleted_line("a\u{1b}[2Jb").contains('\u{1b}'));
    }

    fn cred(name: &str, stored: StoredData) -> keyroost_transport::vault::VaultCredential {
        keyroost_transport::vault::VaultCredential {
            vault: VaultRef {
                credential_id: vec![0xAB, 0xCD],
                name: Some(name.to_owned()),
            },
            large_blob_key: None,
            stored,
        }
    }

    #[test]
    fn duplicate_delete_lists_stored_sizes() {
        let creds = [
            cred("Work", StoredData::Bytes(40)),
            cred("Personal", StoredData::Bytes(812)),
            cred("Personal", StoredData::Empty),
            cred("Personal", StoredData::Unreadable),
        ];
        let choices = delete_choices(&creds);
        let details: Vec<&str> = choices.iter().map(|c| c.detail.as_str()).collect();
        assert_eq!(
            details,
            [
                "40 bytes stored",
                "812 bytes stored",
                "(none)",
                "(unavailable)"
            ]
        );
        let matches = vault::matching(&creds, &VaultPick::Name("Personal")).unwrap();

        let mut t = ScriptTerm::new(false, &[]);
        let e = {
            let mut p = crate::prompt::TermPicker::new(&mut t);
            choose_vault(&choices, &matches, Some("Personal"), &mut p).unwrap_err()
        };
        assert_eq!(
            e,
            "3 vaults are named \"Personal\":\n  Personal  812 bytes stored\n  Personal  (none)\n  \
             Personal  (unavailable)\nrun this in a terminal to pick one"
        );
        assert!(!e.contains("abcd"), "never an ID: {e}");

        let mut t = ScriptTerm::new(true, &["2\n"]);
        let picked = {
            let mut p = crate::prompt::TermPicker::new(&mut t);
            choose_vault(&choices, &matches, Some("Personal"), &mut p)
        };
        assert_eq!(picked, Ok(2), "the copy listed as (none)");
        assert!(t.said[2].contains("2) Personal") && t.said[2].contains("(none)"));
    }

    #[test]
    fn unlocked_copies_are_told_apart_by_entry_count() {
        assert_eq!(count_detail(Some(12)), "12 entries");
        assert_eq!(count_detail(Some(1)), "1 entry");
        assert_eq!(count_detail(Some(0)), "0 entries");
        assert_eq!(count_detail(None), "(unavailable)");

        let u = Unlocked {
            vaults: vec![keyroost_transport::vault::VaultOnKey {
                vault_ref: VaultRef {
                    credential_id: vec![1],
                    name: Some("Personal".to_owned()),
                },
                state: Err(VaultProblem::NoSecret),
            }],
            capacity: cap(),
        };
        let choices = unlocked_choices(&u);
        assert_eq!(choices.len(), 1);
        assert_eq!(choices[0].name.as_deref(), Some("Personal"));
        assert_eq!(choices[0].detail, "(unavailable)");
    }

    fn ent(id: &str, title: &str, username: &str, url: &str) -> Entry {
        Entry {
            id: id.to_owned(),
            title: title.to_owned(),
            username: username.to_owned(),
            password: Zeroizing::new("hunter2-secret".to_owned()),
            url: url.to_owned(),
            notes: String::new(),
            modified_minutes: 28_333_343,
        }
    }

    fn gmail_vault() -> Vault {
        Vault {
            entries: vec![
                ent(
                    "id-aaaa",
                    "Gmail",
                    "alice@example.com",
                    "https://mail.google.com",
                ),
                ent("id-bbbb", "GitHub", "alice", "https://github.com"),
                ent(
                    "id-cccc",
                    "Gmail",
                    "bob@example.com",
                    "https://accounts.google.com",
                ),
            ],
        }
    }

    fn texts(lines: &[Zeroizing<String>]) -> Vec<&str> {
        lines.iter().map(|l| l.as_str()).collect()
    }

    #[test]
    fn wiped_line_sanitizes_in_a_buffer_that_never_grows() {
        let l = wiped_line("Notes:    ", "a\u{1b}[2J\tb\u{202e}c  ");
        assert_eq!(l.as_str(), "Notes:    a [2J\tb c");
        // Sized up front for head + value: sanitizing only shortens.
        let value = "\u{202e}\u{202e}x";
        let l = wiped_line("H: ", value);
        assert!(l.capacity() >= "H: ".len() + value.len());
        assert_eq!(l.as_str(), "H:   x");
    }

    #[test]
    fn entry_list_lines_align_in_wiped_buffers() {
        let v = Vault {
            entries: vec![
                ent("a", "Gmail", "alice", "https://mail.example"),
                ent("b", "GitHub\u{1b}[2J", "", ""),
                ent("c", "Bank", "bob", "https://bank.example"),
            ],
        };
        let lines = entry_list_lines(&v);
        let text: Vec<&str> = lines.iter().map(|l| l.as_str()).collect();
        assert_eq!(
            text,
            [
                "Gmail       alice  https://mail.example",
                "GitHub [2J",
                "Bank        bob    https://bank.example",
            ]
        );
        // No username anywhere: no username column.
        let v = Vault {
            entries: vec![ent("a", "Gmail", "", "https://mail.example")],
        };
        assert_eq!(
            entry_list_lines(&v)[0].as_str(),
            "Gmail  https://mail.example"
        );
        let mut out = Vec::new();
        print_lines(&mut out, &entry_list_lines(&Vault::default())).unwrap();
        assert_eq!(out, b"(none)\n");
    }

    #[test]
    fn entry_lines_print_as_they_are() {
        let mut e = ent("id", "Gmail", "alice", "");
        e.notes = "one\ntwo".to_owned();
        let mut out = Vec::new();
        print_lines(&mut out, &entry_lines(&e)).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("Title:    Gmail\n"), "{text}");
        assert!(text.contains("\nNotes:    one\n          two\n"), "{text}");
        assert!(text.ends_with("Password: (hidden)\n"), "{text}");
    }

    /// The hint reads the vault as saved: a title the new entry now shares
    /// adds `--username`, which the vault as read before the save would miss.
    #[test]
    fn reveal_hint_for_sees_the_saved_contents() {
        let before = Vault {
            entries: vec![ent("1", "Gmail", "alice", "")],
        };
        let mut saved = before.clone();
        saved.entries.push(ent("2", "Gmail", "bob", ""));
        assert_eq!(
            reveal_hint_for(Some("Personal"), &saved, 1, "Gmail", "bob"),
            "See the new password with keyroostctl fido vault entry show Gmail --username bob \
             --reveal"
        );
        assert_eq!(
            reveal_hint_for(Some("Personal"), &before, 1, "Gmail", "bob"),
            "See the new password with keyroostctl fido vault entry show Gmail --reveal"
        );
        // Several vaults: the vault is named too; a shared title with no
        // username can't be narrowed by one.
        let mut no_user = saved.clone();
        no_user.entries[1].username.clear();
        assert_eq!(
            reveal_hint_for(Some("Personal"), &no_user, 2, "Gmail", ""),
            "See the new password with keyroostctl fido vault entry show Gmail --vault Personal \
             --reveal"
        );
    }

    #[test]
    fn entry_matches_by_title_and_username() {
        let v = gmail_vault();
        assert_eq!(entry_matches(&v, "Gmail", None), [0, 2]);
        assert_eq!(entry_matches(&v, "Gmail", Some("bob@example.com")), [2]);
        assert_eq!(entry_matches(&v, "GitHub", None), [1]);
        // Exact: no case folding, no prefix match.
        assert!(entry_matches(&v, "gmail", None).is_empty());
        assert!(entry_matches(&v, "Gm", None).is_empty());
        assert!(entry_matches(&v, "Gmail", Some("bob")).is_empty());
    }

    #[test]
    fn duplicate_titles_in_a_terminal_use_the_picker() {
        let v = gmail_vault();
        let mut t = ScriptTerm::new(true, &["1\n"]);
        let picked = {
            let mut p = crate::prompt::TermPicker::new(&mut t);
            choose_entry(&v, "Gmail", &[0, 2], true, &mut p)
        };
        assert_eq!(picked, Ok(0));
        assert_eq!(t.said[0], "2 entries are titled \"Gmail\":");
        assert!(
            t.said[1].contains("1) Gmail  alice@example.com")
                && t.said[1].contains("https://mail.google.com"),
            "{}",
            t.said[1]
        );
        assert!(t.said[2].contains("2) Gmail  bob@example.com"));
        assert_eq!(t.asked, ["Select [1/2]: "]);
    }

    #[test]
    fn duplicate_titles_without_terminal_are_refused_with_usernames() {
        let v = gmail_vault();
        let mut t = ScriptTerm::new(false, &["1\n"]);
        let e = {
            let mut p = crate::prompt::TermPicker::new(&mut t);
            choose_entry(&v, "Gmail", &[0, 2], true, &mut p).unwrap_err()
        };
        assert!(t.asked.is_empty(), "never reads stdin without a terminal");
        assert_eq!(
            e,
            "2 entries are titled \"Gmail\":\n  \
             Gmail  alice@example.com  https://mail.google.com\n  \
             Gmail  bob@example.com    https://accounts.google.com\n\
             add --username to pick one"
        );
        assert!(!e.contains("id-"), "never an ID: {e}");
    }

    #[test]
    fn edit_duplicates_without_terminal_say_use_a_terminal() {
        let v = gmail_vault();
        let mut t = ScriptTerm::new(false, &[]);
        let e = {
            let mut p = crate::prompt::TermPicker::new(&mut t);
            choose_entry(&v, "Gmail", &[0, 2], false, &mut p).unwrap_err()
        };
        assert!(e.ends_with("\nrun this in a terminal to pick one"), "{e}");
        assert!(!e.contains("--username"), "{e}");
    }

    #[test]
    fn same_title_and_username_without_terminal_says_use_a_terminal() {
        let v = Vault {
            entries: vec![
                ent("id-1", "Bank", "alice", "https://a.example"),
                ent("id-2", "Bank", "alice", "https://b.example"),
            ],
        };
        let mut t = ScriptTerm::new(false, &[]);
        let e = {
            let mut p = crate::prompt::TermPicker::new(&mut t);
            choose_entry(&v, "Bank", &[0, 1], true, &mut p).unwrap_err()
        };
        assert!(e.ends_with("\nrun this in a terminal to pick one"), "{e}");
    }

    #[test]
    fn no_matching_entry_is_said_plainly() {
        let v = gmail_vault();
        let mut t = ScriptTerm::new(true, &[]);
        let mut p = crate::prompt::TermPicker::new(&mut t);
        assert_eq!(
            choose_entry(&v, "Bank", &[], true, &mut p),
            Err("no entry titled \"Bank\" in this vault".to_owned())
        );
        assert_eq!(choose_entry(&v, "GitHub", &[1], true, &mut p), Ok(1));
    }

    #[test]
    fn key_supplied_entry_text_is_neutralized() {
        let v = Vault {
            entries: vec![
                ent("1", "a\u{1b}[2Jb", "u\u{7}", "x\u{1b}]0;t\u{7}"),
                ent("2", "a\u{1b}[2Jb", "v", ""),
            ],
        };
        let mut t = ScriptTerm::new(false, &[]);
        let e = {
            let mut p = crate::prompt::TermPicker::new(&mut t);
            choose_entry(&v, "a\u{1b}[2Jb", &[0, 1], true, &mut p).unwrap_err()
        };
        assert!(!e.contains('\u{1b}') && !e.contains('\u{7}'), "{e:?}");
        let mut e = ent("1", "t\u{1b}", "u\u{1b}", "x\u{1b}");
        e.notes = "line1\u{1b}[2J\nline2".to_owned();
        for l in entry_lines(&e) {
            assert!(!l.contains('\u{1b}'), "{l:?}");
        }
    }

    #[test]
    fn entry_lines_hide_the_password() {
        let mut e = ent(
            "id-aaaa",
            "Gmail",
            "alice@example.com",
            "https://mail.google.com",
        );
        e.notes = "recovery codes in the safe".to_owned();
        let lines = entry_lines(&e);
        assert_eq!(
            texts(&lines),
            [
                "Title:    Gmail",
                "Username: alice@example.com",
                "URL:      https://mail.google.com",
                "Notes:    recovery codes in the safe",
                "Changed:  2023-11-14",
                "Password: (hidden)",
            ]
        );
        for l in &lines {
            assert!(!l.contains("hunter2"), "{}", l.as_str());
            assert!(!l.contains("id-aaaa"), "no ID in text: {}", l.as_str());
        }

        // Nothing there: (none), the password too.
        let mut empty = ent("id", "Bare", "", "");
        empty.password = Zeroizing::new(String::new());
        assert_eq!(
            texts(&entry_lines(&empty)),
            [
                "Title:    Bare",
                "Username: (none)",
                "URL:      (none)",
                "Notes:    (none)",
                "Changed:  2023-11-14",
                "Password: (none)",
            ]
        );

        // Notes over several lines stay under their column.
        let mut multi = ent("id", "X", "u", "");
        multi.notes = "one\ntwo".to_owned();
        let lines = entry_lines(&multi);
        assert_eq!(lines[3].as_str(), "Notes:    one");
        assert_eq!(lines[4].as_str(), "          two");
    }

    #[test]
    fn changed_date() {
        assert_eq!(super::changed_date(28_333_343), "2023-11-14");
        assert_eq!(super::changed_date(0), "1970-01-01");
        // The last minute of a day is still that day (UTC).
        assert_eq!(super::changed_date(1439), "1970-01-01");
        assert_eq!(super::changed_date(1440), "1970-01-02");
        assert_eq!(super::changed_date(-1), "1969-12-31");
    }

    #[test]
    fn reveal_plan_by_output() {
        assert_eq!(reveal_plan(true, false), RevealPlan::ShowUntilEnter);
        assert_eq!(reveal_plan(false, false), RevealPlan::PasswordOnly);
        assert_eq!(reveal_plan(true, true), RevealPlan::Json);
        assert_eq!(reveal_plan(false, true), RevealPlan::Json);
    }

    #[test]
    fn write_password_only_writes_no_newline() {
        let mut out = Vec::new();
        write_password_only(&mut out, "pw").unwrap();
        assert_eq!(out, b"pw");
        let mut out = Vec::new();
        write_password_only(&mut out, "").unwrap();
        assert!(out.is_empty());
    }

    /// The reader for Enter (rpassword) writes a newline when it returns, so
    /// the cursor is one line below the shown password: up one line, then
    /// clear that whole line.
    #[test]
    fn erase_sequence_after_the_readers_newline() {
        assert_eq!(erase_shown_line(), "\x1b[1A\x1b[2K");
        // A reader that failed wrote no newline: the password is on the
        // cursor's own line.
        assert_eq!(erase_current_line(), "\r\x1b[2K");
    }

    #[test]
    fn reveal_line_is_the_hidden_lines_label() {
        let e = ent("id", "Gmail", "alice", "");
        let lines = entry_lines(&e);
        assert_eq!(
            lines.last().unwrap().as_str(),
            format!("{REVEAL_LABEL}(hidden)")
        );
    }

    #[test]
    fn entry_json_has_ids_and_no_password_without_reveal() {
        let mut v = gmail_vault();
        v.entries[0].notes = "n".to_owned();
        let list = serde_json::to_value(entry_list_json(Some("Personal"), &v)).unwrap();
        assert_eq!(list["vault"], "Personal");
        let entries = list["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 3);
        let mut keys: Vec<&str> = entries[0]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["changed", "id", "title", "url", "username"]);
        assert_eq!(entries[0]["id"], "id-aaaa");
        assert_eq!(entries[0]["changed"], "2023-11-14");
        assert!(!list.to_string().contains("hunter2"));

        let shown =
            serde_json::to_value(entry_show_json(Some("Personal"), &v.entries[0], false)).unwrap();
        let mut keys: Vec<&str> = shown
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["changed", "id", "notes", "password", "title", "url", "username", "vault"]
        );
        // Never omitted (the JSON rule): `null` until --reveal.
        assert!(shown["password"].is_null());
        assert!(!shown.to_string().contains("hunter2"));

        let revealed =
            serde_json::to_value(entry_show_json(Some("Personal"), &v.entries[0], true)).unwrap();
        assert_eq!(revealed["password"], "hunter2-secret");
        assert_eq!(revealed["id"], "id-aaaa");

        // The bytes written for --json: the same document, one newline.
        let mut out = Vec::new();
        write_json_wiped(&mut out, &entry_show_json(None, &v.entries[0], true)).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.ends_with("}\n"), "{text}");
        let back: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(back["password"], "hunter2-secret");
        assert!(back["vault"].is_null());
    }

    #[test]
    fn entry_json_empty_strings_are_null() {
        let mut v = Vault {
            entries: vec![ent("id-aaaa", "Gmail", "", "")],
        };
        let list = serde_json::to_value(entry_list_json(None, &v)).unwrap();
        let e = &list["entries"][0];
        assert!(e["username"].is_null(), "{e}");
        assert!(e["url"].is_null(), "{e}");
        assert_eq!(e["title"], "Gmail");

        for reveal in [false, true] {
            let shown = serde_json::to_value(entry_show_json(None, &v.entries[0], reveal)).unwrap();
            for field in ["username", "url", "notes"] {
                assert!(shown[field].is_null(), "{field}: {shown}");
            }
        }

        // Filled-in fields stay strings.
        v.entries[0].username = "alice".into();
        v.entries[0].url = "https://mail.google.com".into();
        v.entries[0].notes = "n".into();
        let list = serde_json::to_value(entry_list_json(None, &v)).unwrap();
        assert_eq!(list["entries"][0]["username"], "alice");
        assert_eq!(list["entries"][0]["url"], "https://mail.google.com");
        let shown = serde_json::to_value(entry_show_json(None, &v.entries[0], false)).unwrap();
        assert_eq!(shown["username"], "alice");
        assert_eq!(shown["url"], "https://mail.google.com");
        assert_eq!(shown["notes"], "n");
    }

    #[test]
    fn entry_delete_question_uses_the_confirm_form() {
        let mut t = ScriptTerm::new(true, &["y\n"]);
        assert_eq!(
            entry_delete_question(&mut t, false, "Gmail", Some("Personal"), "yubi-test"),
            Ok(true)
        );
        assert_eq!(
            t.asked,
            ["delete entry \"Gmail\" from vault \"Personal\" on yubi-test? [y/N] "]
        );
        let mut t = ScriptTerm::new(false, &[]);
        assert_eq!(
            entry_delete_question(&mut t, false, "Gmail", Some("Personal"), "yubi-test"),
            Err(
                "refusing to delete entry \"Gmail\" from vault \"Personal\" on yubi-test \
                 without confirmation; add --yes"
                    .to_owned()
            )
        );
        let mut t = ScriptTerm::new(true, &[]);
        assert_eq!(
            entry_delete_question(&mut t, true, "Gmail", None, "yubi-test"),
            Ok(false)
        );
        assert!(t.asked.is_empty());
    }

    fn parse(args: &[&str]) -> Result<crate::Cli, clap::Error> {
        use clap::Parser;
        crate::Cli::try_parse_from(
            ["keyroostctl", "fido", "vault", "entry"]
                .iter()
                .chain(args)
                .copied(),
        )
    }

    #[test]
    fn edit_needs_a_change() {
        let e = parse(&["edit", "Gmail"]).err().expect("refused");
        assert_eq!(e.kind(), clap::error::ErrorKind::MissingRequiredArgument);
        for change in [
            &["--title", "Mail"][..],
            &["--username", ""],
            &["--url", "u"],
            &["--notes", "stdin"],
            &["--password", "stdin"],
            &["--generate-password"],
        ] {
            let mut args = vec!["edit", "Gmail"];
            args.extend_from_slice(change);
            assert!(parse(&args).is_ok(), "{change:?}");
        }
    }

    #[test]
    fn password_and_generate_conflict() {
        for cmd in ["add", "edit"] {
            let e = parse(&[cmd, "x", "--password", "stdin", "--generate-password"])
                .err()
                .expect("refused");
            assert_eq!(e.kind(), clap::error::ErrorKind::ArgumentConflict, "{cmd}");
        }
    }

    #[test]
    fn length_requires_generate() {
        for cmd in ["add", "edit"] {
            let e = parse(&[cmd, "x", "--length", "30", "--url", "u"])
                .err()
                .expect("refused");
            assert_eq!(
                e.kind(),
                clap::error::ErrorKind::MissingRequiredArgument,
                "{cmd}"
            );
            assert!(parse(&[cmd, "x", "--generate-password", "--length", "30"]).is_ok());
        }
    }

    #[test]
    fn length_out_of_range_is_refused() {
        for n in ["3", "129", "0"] {
            let e = parse(&["add", "x", "--generate-password", "--length", n])
                .err()
                .expect("refused");
            assert_eq!(e.kind(), clap::error::ErrorKind::ValueValidation, "{n}");
        }
        for n in ["4", "128"] {
            assert!(parse(&["add", "x", "--generate-password", "--length", n]).is_ok());
        }
    }

    #[test]
    fn content_secrets_come_before_the_pin_on_stdin() {
        use crate::secrets::fake::FakeIo;
        use crate::secrets::{Secrets, Source};
        let mut sec = Secrets::new(FakeIo::piped(&["pw\n", "my notes\n", "1234\n"]));
        let stdin = SecretSource::Stdin;
        check_content(&sec, Some(&stdin), true, Some(&stdin)).unwrap();
        let (password, notes) = read_content(&mut sec, Some(&stdin), true, Some(&stdin)).unwrap();
        let pin = sec.read(&crate::FIDO_PIN, Source::new(None, true)).unwrap();
        assert_eq!(password.as_deref().map(|s| s.as_str()), Some("pw"));
        assert_eq!(notes.as_deref().map(|s| s.as_str()), Some("my notes"));
        assert_eq!(pin.as_str(), "1234");

        // Notes alone take the first line; an empty one clears.
        let mut sec = Secrets::new(FakeIo::piped(&["\n", "1234\n"]));
        let (password, notes) = read_content(&mut sec, None, false, Some(&stdin)).unwrap();
        assert!(password.is_none());
        assert_eq!(notes.as_deref().map(|s| s.as_str()), Some(""));
    }

    #[test]
    fn a_password_with_no_source_and_no_terminal_names_generate() {
        use crate::secrets::fake::FakeIo;
        use crate::secrets::Secrets;
        let sec = Secrets::new(FakeIo::piped(&[]));
        let e = check_content(&sec, None, true, None).unwrap_err();
        assert_eq!(
            e,
            "no password given: pass --password env:NAME, --password stdin or \
             --generate-password"
        );
        // Not needed (edit, or --generate-password): nothing to refuse.
        assert!(check_content(&sec, None, false, None).is_ok());
    }

    #[test]
    fn a_typed_password_is_asked_twice() {
        use crate::secrets::fake::FakeIo;
        use crate::secrets::Secrets;
        let mut sec = Secrets::new(FakeIo::terminal().typing(&["pw", "pw"]));
        let (password, _) = read_content(&mut sec, None, true, None).unwrap();
        assert_eq!(password.as_deref().map(|s| s.as_str()), Some("pw"));
        assert_eq!(sec.io.prompts, ["Password: ", "Repeat password: "]);
    }

    #[test]
    fn the_save_line_shows_once() {
        let mut s = SaveProgress::default();
        assert_eq!(s.line(VaultStep::UnlockTouch), None);
        assert_eq!(s.line(VaultStep::Write), Some(SAVE_LINE));
        // A fresh-token retry repeats the write step: no second line.
        assert_eq!(s.line(VaultStep::Write), None);
    }

    #[test]
    fn conflict_says_run_it_again() {
        let t = crate::error_text(entry_save_error(VaultKeyError::Conflict).as_ref());
        assert_eq!(
            t,
            "this entry changed on the key while the command ran; nothing was written. Run it \
             again."
        );
        // Anything else goes through vault_error.
        let t = crate::error_text(entry_save_error(VaultKeyError::NoVaults).as_ref());
        assert!(t.contains("keyroostctl fido vault add NAME"), "{t}");
    }

    #[test]
    fn early_refusal_actions() {
        assert_eq!(delete_action("Personal"), "delete vault \"Personal\"");
        assert_eq!(
            rotate_action("Personal"),
            "rotate the key of vault \"Personal\""
        );
        assert_eq!(entry_delete_action("Gmail", None), "delete entry \"Gmail\"");
        assert_eq!(
            entry_delete_action("Gmail", Some("Work")),
            "delete entry \"Gmail\" from vault \"Work\""
        );
        assert_eq!(import_action("b.t2vault", None), "import b.t2vault");
        assert_eq!(
            import_action("b.t2vault", Some("Work")),
            "import b.t2vault into vault \"Work\""
        );
        for a in [
            delete_action("a\u{1b}[2J"),
            rotate_action("a\u{1b}[2J"),
            entry_delete_action("a\u{1b}[2J", Some("b\u{1b}[2J")),
            import_action("a\u{1b}[2J", Some("b\u{1b}[2J")),
        ] {
            assert!(!a.contains('\u{1b}'), "{a}");
        }
    }

    #[test]
    fn replace_text_sets_the_new_value() {
        let mut f = String::from("an old note");
        replace_text(&mut f, "new");
        assert_eq!(f, "new");
        // An empty value clears the field.
        replace_text(&mut f, "");
        assert_eq!(f, "");
    }

    #[test]
    fn a_vanished_vault_has_its_own_words() {
        let gone = |name: Option<&str>| VaultKeyError::VaultGone {
            name: name.map(str::to_owned),
        };
        let expected = "vault \"Personal\" is no longer on the key; it was deleted or rotated \
                        elsewhere, and nothing was written";
        for t in [
            crate::error_text(entry_save_error(gone(Some("Personal"))).as_ref()),
            crate::error_text(import_save_error(gone(Some("Personal"))).as_ref()),
        ] {
            assert_eq!(t, expected);
        }
        let t = crate::error_text(entry_save_error(gone(None)).as_ref());
        assert!(t.starts_with("vault \"(unnamed)\" is no longer"), "{t}");
        // Key-supplied names are neutralized.
        let t = crate::error_text(entry_save_error(gone(Some("a\u{1b}[2Jb"))).as_ref());
        assert!(!t.contains('\u{1b}'), "{t}");
    }

    #[test]
    fn result_lines() {
        assert_eq!(
            added_line("Gmail", Some("Personal")),
            "Entry \"Gmail\" added to vault \"Personal\"."
        );
        assert_eq!(
            added_line("Gmail", None),
            "Entry \"Gmail\" added to vault \"(unnamed)\"."
        );
        assert_eq!(
            reveal_hint("Gmail", None, None),
            "See the new password with keyroostctl fido vault entry show Gmail --reveal"
        );
        assert_eq!(
            reveal_hint("Work Mail", Some("My Vault"), Some("bob")),
            "See the new password with keyroostctl fido vault entry show 'Work Mail' --vault \
             'My Vault' --username bob --reveal"
        );
    }

    #[test]
    fn key_supplied_names_in_errors_are_neutralized() {
        let e = VaultKeyError::OldNotDeleted {
            name: Some("a\u{1b}[2Jb".to_owned()),
            cause: Box::new(VaultKeyError::Conflict),
            old: OldVault::Kept,
        };
        let t = crate::error_text(vault_error(e).as_ref());
        assert!(!t.contains('\u{1b}'), "{t:?}");
    }

    /// A backup of four entries, one per status, and the statuses
    /// `classify` gives them against a vault of five.
    fn backup() -> (Vault, Vec<(usize, keyroost_vault::ImportStatus)>) {
        use keyroost_vault::ImportStatus::*;
        let v = Vault {
            entries: vec![
                ent("id-new", "Mail", "alice", ""),
                ent("id-newer", "GitHub", "alice", ""),
                ent("id-older", "Bank", "", ""),
                ent("id-same", "Forum", "bob", ""),
            ],
        };
        (v, vec![(0, New), (1, Newer), (2, Older), (3, Same)])
    }

    fn plans(rows: &[ImportRow]) -> Vec<(&str, Option<&str>)> {
        rows.iter().map(|r| (r.plan, r.reason)).collect()
    }

    #[test]
    fn import_rows_default_takes_add_and_replace() {
        let (v, st) = backup();
        let rows = import_rows(&st, &v, &[], false).unwrap();
        assert_eq!(
            plans(&rows),
            [
                ("add", None),
                ("replace", Some("the backup's copy is newer")),
                ("skip", Some("the key's copy is newer (--replace takes it)")),
                ("exists", Some("already in the vault; left as is")),
            ]
        );
        let r = &rows[1];
        assert_eq!(
            (
                r.index,
                r.id.as_str(),
                r.title.as_str(),
                r.username.as_str()
            ),
            (1, "id-newer", "GitHub", "alice")
        );
        assert_eq!(chosen(&rows), [0, 1]);
    }

    #[test]
    fn import_rows_replace_takes_the_older() {
        let (v, st) = backup();
        let rows = import_rows(&st, &v, &[], true).unwrap();
        assert_eq!(
            plans(&rows),
            [
                ("add", None),
                ("replace", Some("the backup's copy is newer")),
                ("replace", Some("replaces the key's newer copy")),
                ("exists", Some("already in the vault; left as is")),
            ]
        );
        assert_eq!(chosen(&rows), [0, 1, 2]);
    }

    #[test]
    fn import_rows_entry_names_exactly_those() {
        let (v, st) = backup();
        let named = ["Bank".to_owned(), "Forum".to_owned()];
        let rows = import_rows(&st, &v, &named, false).unwrap();
        assert_eq!(
            plans(&rows),
            [
                ("skip", Some("not named with --entry")),
                ("skip", Some("not named with --entry")),
                ("replace", Some("replaces the key's newer copy")),
                ("exists", Some("already in the vault; left as is")),
            ]
        );
        assert_eq!(chosen(&rows), [2]);
    }

    #[test]
    fn import_rows_entry_takes_every_entry_with_that_title() {
        use keyroost_vault::ImportStatus::*;
        let v = Vault {
            entries: vec![
                ent("id-1", "GitHub", "alice", ""),
                ent("id-2", "Mail", "alice", ""),
                ent("id-3", "GitHub", "work", ""),
            ],
        };
        let st = [(0, New), (1, New), (2, Newer)];
        let rows = import_rows(&st, &v, &["GitHub".to_owned()], false).unwrap();
        assert_eq!(
            plans(&rows),
            [
                ("add", None),
                ("skip", Some("not named with --entry")),
                ("replace", Some("the backup's copy is newer")),
            ]
        );
        assert_eq!(chosen(&rows), [0, 2]);
    }

    #[test]
    fn import_rows_unknown_entry_is_refused() {
        let (v, st) = backup();
        let err =
            import_rows(&st, &v, &["Mail".to_owned(), "Gmial".to_owned()], false).unwrap_err();
        assert_eq!(err, "no entry in the backup is titled \"Gmial\"");
        assert_eq!(
            check_entry_titles(&v, &["Gmial".to_owned()]).unwrap_err(),
            err
        );
        assert!(check_entry_titles(&v, &["Mail".to_owned()]).is_ok());
        // Key-supplied text never reaches the terminal raw.
        let err = check_entry_titles(&v, &["a\u{1b}[2Jb".to_owned()]).unwrap_err();
        assert!(!err.contains('\u{1b}'), "{err:?}");
    }

    #[test]
    fn import_lines_layout() {
        let (v, st) = backup();
        let rows = import_rows(&st, &v, &[], false).unwrap();
        let lines = import_lines(&rows, "vault.t2vault", "Personal", "yubi-test", 5);
        let mut want =
            vec!["4 entries in vault.t2vault for vault \"Personal\" on yubi-test:".to_owned()];
        want.extend(crate::code_import::plan_row_lines(&[
            ("add", "Mail (alice)".to_owned(), None),
            (
                "replace",
                "GitHub (alice)".to_owned(),
                Some("the backup's copy is newer".to_owned()),
            ),
            (
                "skip",
                "Bank".to_owned(),
                Some("the key's copy is newer (--replace takes it)".to_owned()),
            ),
            (
                "exists",
                "Forum (bob)".to_owned(),
                Some("already in the vault; left as is".to_owned()),
            ),
        ]));
        want.push(
            "5 entries in the vault; 1 will be added, 1 replaced, 1 left as is, 1 skipped."
                .to_owned(),
        );
        assert_eq!(lines, want);
        assert_eq!(lines[1], "  add       Mail (alice)");
        assert_eq!(
            lines[2],
            "  replace   GitHub (alice)  the backup's copy is newer"
        );

        let one = import_lines(&rows[..1], "f", "V", "k", 1);
        assert_eq!(one[0], "1 entry in f for vault \"V\" on k:");
        assert_eq!(
            one[2],
            "1 entry in the vault; 1 will be added, 0 replaced, 0 left as is, 0 skipped."
        );

        // Key- and file-supplied text is neutralized.
        let mut bad = rows[..1].to_vec();
        bad[0].title = "x\u{1b}[2Jy".to_owned();
        for l in import_lines(&bad, "a\u{7}b", "c\u{1b}d", "k", 0) {
            assert!(!l.contains('\u{1b}') && !l.contains('\u{7}'), "{l:?}");
        }
    }

    #[test]
    fn import_question_uses_code_imports_form() {
        let mut t = ScriptTerm::new(true, &["y"]);
        assert_eq!(
            import_question(&mut t, false, 2, Some("Personal"), "yubi-test"),
            Ok(true)
        );
        assert_eq!(
            t.asked,
            ["import 2 entries into vault \"Personal\" on yubi-test? [y/N] "]
        );
        let mut t = ScriptTerm::new(false, &[]);
        assert_eq!(
            import_question(&mut t, false, 2, Some("Personal"), "yubi-test").unwrap_err(),
            "refusing to import 2 entries into vault \"Personal\" on yubi-test without \
             confirmation; add --yes"
        );
        let mut t = ScriptTerm::new(false, &[]);
        assert_eq!(import_question(&mut t, true, 1, None, "k"), Ok(false));
        assert!(t.asked.is_empty());
    }

    #[test]
    fn import_into_a_new_vault_asks_to_create() {
        let mut t = ScriptTerm::new(true, &["y"]);
        assert_eq!(
            create_question(&mut t, false, "Personal", "yubi-test"),
            Ok(true)
        );
        assert_eq!(t.asked, ["create vault \"Personal\" on yubi-test? [y/N] "]);
        let mut t = ScriptTerm::new(true, &["n"]);
        assert!(create_question(&mut t, false, "Personal", "yubi-test").is_err());
    }

    #[test]
    fn import_json_fields() {
        let (v, st) = backup();
        let rows = import_rows(&st, &v, &[], false).unwrap();
        let json = serde_json::to_value(import_json(&rows, Some("Personal"), false, true)).unwrap();
        assert_eq!(json["vault"], "Personal");
        assert_eq!(json["creates"], false);
        assert_eq!(json["dry_run"], true);
        let e = &json["entries"][2];
        let keys: Vec<&str> = e.as_object().unwrap().keys().map(String::as_str).collect();
        let mut want = ["index", "id", "title", "username", "plan", "reason"];
        want.sort_unstable();
        let mut keys = keys;
        keys.sort_unstable();
        assert_eq!(keys, want);
        assert_eq!(e["index"], 2);
        assert_eq!(e["id"], "id-older");
        assert_eq!(e["title"], "Bank");
        // An empty username is nothing there: `null`, never `""`.
        assert!(e["username"].is_null(), "{e}");
        assert_eq!(json["entries"][0]["username"], "alice");
        assert_eq!(e["plan"], "skip");
        assert_eq!(e["reason"], "the key's copy is newer (--replace takes it)");
        assert_eq!(json["entries"][0]["reason"], serde_json::Value::Null);
        // Never a password.
        assert!(!json.to_string().contains("hunter2"), "{json}");
    }

    #[test]
    fn export_and_import_result_lines() {
        assert_eq!(
            exported_line("Personal", 3, Path::new("personal.t2vault")),
            "Backup of vault \"Personal\" (3 entries) written to personal.t2vault."
        );
        assert_eq!(
            exported_line("Personal", 1, Path::new("p.t2vault")),
            "Backup of vault \"Personal\" (1 entry) written to p.t2vault."
        );
        assert_eq!(
            imported_line(Some("Personal"), 2, 1),
            "Imported into vault \"Personal\": 2 added, 1 replaced."
        );
    }

    #[test]
    fn import_and_export_flags() {
        use clap::Parser;
        let p = |args: &[&str]| {
            crate::Cli::try_parse_from(["keyroostctl", "fido", "vault"].iter().chain(args).copied())
        };
        assert!(p(&["export", "Personal", "-o", "p.t2vault", "--overwrite"]).is_ok());
        assert!(p(&["export", "Personal"]).is_err(), "--out is required");
        assert!(p(&[
            "import",
            "-i",
            "p.t2vault",
            "--vault",
            "V",
            "--entry",
            "A",
            "--entry",
            "B",
            "--replace",
            "--dry-run",
            "-y"
        ])
        .is_ok());
        assert!(p(&["import"]).is_err(), "--in is required");
    }
}
