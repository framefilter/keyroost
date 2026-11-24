//! `keyroostctl fido vault`: password vaults on a FIDO2 key, in
//! FidoParole's vault format. `keyroost-transport::vault` talks to the key;
//! this module reads the secrets, asks the questions and prints.
//!
//! Vaults are told apart by name, and copies sharing a name by what they
//! hold (entry count, or stored size where nothing was unlocked): a
//! credential ID is never shown in text and never taken as a selector, only
//! carried in `--json`.

use std::error::Error;
use std::path::{Path, PathBuf};

use clap::Subcommand;
use keyroost_ctap::large_blobs::BlobCapacity;
use keyroost_ctap::CtapHidDevice;
use keyroost_proto::codec::hex_encode;
use keyroost_resolve::{Choice, Picker};
use keyroost_transport::vault::{
    self, CtapVaultKey, LeftOver, OldVault, StoredData, Unlocked, VaultAuth, VaultCredential,
    VaultKeyError, VaultPick, VaultProblem, VaultRef, VaultStep,
};

use crate::code_import::entries;
use crate::json_out;
use crate::output::{emit_json, json_output};
use crate::prompt::{confirm, confirm_statement, key_label, RealTerm, TermPicker};
use crate::secrets::SecretSource;
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
            let pin = crate::fido_pin(path.as_deref(), pin.as_ref())?;
            let dev = crate::target::select_fido(path.as_deref())?;
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
            let pin = crate::fido_pin(path.as_deref(), pin.as_ref())?;
            let dev = crate::target::select_fido(path.as_deref())?;
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
    confirm(
        term,
        yes,
        &format!("delete vault \"{}\"", sanitize_terminal(name)),
        key,
    )
}

/// `vault rotate`'s question, as a statement.
fn rotate_question(
    term: &mut dyn crate::prompt::Term,
    yes: bool,
    name: &str,
    key: &str,
) -> Result<bool, String> {
    let name = sanitize_terminal(name);
    confirm_statement(
        term,
        yes,
        &format!(
            "Rotate the key of vault \"{name}\" on {key}? A new vault replaces it; the old one \
             is deleted after every entry is checked."
        ),
        &format!("rotate the key of vault \"{name}\""),
        key,
    )
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
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the vault entry, export and import commands use it"
    )
)]
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
}
