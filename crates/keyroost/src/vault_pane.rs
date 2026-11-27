//! The Vault tab: the FIDO2 password vault on the selected key, beside
//! Authenticator, and the "Password vault" card on the key's Overview.
//!
//! The tab is offered only on keys that can hold a vault, the way
//! Authenticator and OpenPGP are offered only on keys that have them; the
//! Overview card says why a key can't. The vault is experimental, so both
//! carry [`experimental_note`].
//!
//! The words are the CLI's (`keyroostctl fido vault`), fitted to the layout.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use keyroost_ctap::client_pin::Verified;
use keyroost_ctap::large_blobs::{BlobCapacity, CredentialData};
use keyroost_ctap::transport::CtapTransport;
use keyroost_ctap::{AuthenticatorInfo, CtapError};
use keyroost_resolve::private_file::{write_private_file, OutMode};
use keyroost_transport::vault::{
    self, Change, Created, CtapVaultKey, LeftOver, OldVault, OpenVault, Saved, Unlocked, VaultAuth,
    VaultKey, VaultKeyError, VaultOnKey, VaultRef, VaultStep,
};
use keyroost_vault::{
    backup_file_name, canon_id, check_passphrase, classify, export_backup, generate_password,
    import_backup, new_id, Entry, GenOptions, ImportStatus, Vault, VaultError, MAX_NAME_BYTES,
};
use zeroize::{Zeroize, Zeroizing};

use crate::ui::device::{CapTab, DeviceId};
use crate::ui::theme::{self, BtnKind, Palette};
use crate::{
    completion_still_valid, fido_unread_line, guard_secret_field, now_secs_f64, open_fido,
    sanitize_title, wipe, App, FidoTarget, FileTarget, Severity, TypedSecrets,
};

/// Where problems are reported: the CLI help's URL.
pub(crate) const ISSUES_URL: &str = "https://github.com/framefilter/keyroost/issues";

/// Whether the selected key is offered a vault, from what is known of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VaultOffer {
    /// No getInfo answer yet (still reading, or the read failed).
    Unknown,
    /// Windows without administrator rights: FIDO access is gated, so
    /// getInfo never arrives.
    NeedsAdmin,
    /// The key can hold a vault.
    Ready,
    /// The key could hold a vault but has no PIN set.
    NeedsPin,
    /// The key cannot hold a vault: it lacks what is named.
    No(&'static str),
}

/// What `info` (the key's getInfo, `None` until read) says about a vault.
/// A key with no CTAP2 interface (`u2f_only`) can't hold one; without
/// getInfo, a Windows session without administrator rights (`non_admin`)
/// is told so, others wait for the read.
pub(crate) fn vault_offer(
    info: Option<&AuthenticatorInfo>,
    u2f_only: bool,
    non_admin: bool,
) -> VaultOffer {
    if u2f_only {
        return VaultOffer::No("CTAP2");
    }
    let Some(info) = info else {
        return if non_admin {
            VaultOffer::NeedsAdmin
        } else {
            VaultOffer::Unknown
        };
    };
    match vault::check_support(info) {
        Ok(()) => VaultOffer::Ready,
        Err(VaultKeyError::PinNotSet) => VaultOffer::NeedsPin,
        Err(VaultKeyError::Unsupported(what)) => VaultOffer::No(what),
        // `check_support` answers with the two above today. A refusal it
        // adds later is still a refusal: never a key left on "Reading key…".
        Err(_) => VaultOffer::No("everything a vault needs"),
    }
}

/// The key's tabs with Vault added when it is offered: on a key with a
/// FIDO2 tab, right after Authenticator, else right after FIDO2. A key
/// still being read (`Unknown`, `NeedsAdmin`) keeps it, so a remembered
/// Vault pick isn't snapped away before getInfo lands.
pub(crate) fn with_vault_tab(mut tabs: Vec<CapTab>, offer: VaultOffer) -> Vec<CapTab> {
    if matches!(offer, VaultOffer::No(_)) {
        return tabs;
    }
    let anchor = tabs
        .iter()
        .position(|t| *t == CapTab::Oath)
        .or_else(|| tabs.iter().position(|t| *t == CapTab::Fido2));
    if tabs.contains(&CapTab::Fido2) {
        if let Some(i) = anchor {
            tabs.insert(i + 1, CapTab::Vault);
        }
    }
    tabs
}

/// `1 entry` / `N entries`: the app's copy of the CLI's helper.
pub(crate) fn entries(n: usize) -> String {
    if n == 1 {
        "1 entry".to_owned()
    } else {
        format!("{n} entries")
    }
}

/// A vault's name as the app shows it: control characters flattened,
/// `(unnamed)` when it has none.
fn shown_name(name: Option<&str>) -> String {
    match name {
        Some(n) if !n.is_empty() => sanitize_title(n),
        _ => "(unnamed)".to_owned(),
    }
}

/// A vault as its chip names it: `Personal · 12`; `Personal · (none)` when
/// the key holds no data for it (the copy a failed create or rotate leaves,
/// as the CLI lists it); `Personal · (unavailable)` when it did not open.
/// Two vaults that share a name are told apart this way.
pub(crate) fn chip_label(v: &VaultOnKey) -> String {
    let name = shown_name(v.vault_ref.name.as_deref());
    match &v.state {
        Ok(open) if !open.stored => format!("{name} \u{00B7} (none)"),
        Ok(open) => format!("{name} \u{00B7} {}", open.contents.entries.len()),
        Err(_) => format!("{name} \u{00B7} (unavailable)"),
    }
}

/// For each conforming entry of `array.entries()`: `Some(name)` (or
/// `(unnamed)`) when an open vault holds it, else `None`. The vault's name
/// is the only thing taken from it; the entry itself is never decrypted.
pub(crate) fn vault_entry_labels(
    array: &keyroost_ctap::large_blobs::LargeBlobArray,
    vaults: &[VaultOnKey],
) -> Vec<Option<String>> {
    array
        .entries()
        .into_iter()
        .map(|e| {
            vaults.iter().find_map(|v| match &v.state {
                Ok(open) if open.holds_entry(e) => Some(shown_name(v.vault_ref.name.as_deref())),
                _ => None,
            })
        })
        .collect()
}

/// The Storage row's text for an entry an unlocked vault holds.
pub(crate) fn vault_entry_row_text(name: &str) -> String {
    format!("password vault \"{name}\" (encrypted)")
}

/// Upper-case the first letter of a CLI message, as a sentence starts.
fn sentence(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(first) => first.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

/// The Overview card's line: why there is no vault, or what is in it.
/// `read_failed` is whether the key's getInfo read failed (the FIDO2 tab's
/// "Couldn't read this key."); `vaults` is the unlocked list, `None` while
/// locked; `finger` whether the key's sensor can unlock it.
pub(crate) fn overview_line(
    offer: VaultOffer,
    read_failed: bool,
    vaults: Option<&[VaultOnKey]>,
    finger: bool,
) -> String {
    match offer {
        VaultOffer::Unknown => fido_unread_line(false, read_failed).to_owned(),
        VaultOffer::NeedsAdmin => "Open the FIDO2 tab to manage this key via Windows settings \
                                   or restart as administrator."
            .to_owned(),
        VaultOffer::No(what) => format!(
            "{}.",
            sentence(&VaultKeyError::Unsupported(what).to_string())
        ),
        VaultOffer::NeedsPin => {
            "A password vault needs a FIDO2 PIN; set one on the FIDO2 tab.".to_owned()
        }
        VaultOffer::Ready => match vaults {
            None if finger => {
                "Passwords in an encrypted vault on this key, opened with the PIN or \
                               a fingerprint, and a touch."
                    .to_owned()
            }
            None => "Passwords in an encrypted vault on this key, opened with the PIN and a touch."
                .to_owned(),
            Some([]) => "No vaults on this key yet.".to_owned(),
            Some(vs) => vs.iter().map(chip_label).collect::<Vec<_>>().join(", "),
        },
    }
}

/// Why a new vault can't be named `name` (already trimmed): the format's
/// length limit, or one of the vaults named `taken` has it. `None` when it
/// can. No key and no randomness: cheap enough to ask every frame.
pub(crate) fn new_name_refusal(name: &str, taken: &[Option<String>]) -> Option<VaultKeyError> {
    if name.is_empty() || name.len() > MAX_NAME_BYTES {
        return Some(VaultKeyError::Vault(VaultError::NameLength));
    }
    taken
        .iter()
        .any(|t| t.as_deref() == Some(name))
        .then(|| VaultKeyError::DuplicateName(name.to_owned()))
}

/// What one more entry takes on the key, for the space line's "room for
/// about N more entries": one fixed size, so the number only falls as the
/// store fills and only rises as it empties. Measured by sealing 40
/// typical logins with `keyroost_vault::seal` (site, user name and URL, a
/// generated password, no notes): after the first entry, each adds about
/// 45 bytes with 20-character passwords and up to about 57 with
/// 32-character ones and distinct user names (the ID and password don't
/// compress). 60 bytes sits just above that, so the line promises a
/// little less room than there is rather than more.
pub(crate) const TYPICAL_ENTRY_BYTES: u64 = 60;

/// `bytes` in KB with one decimal, a trailing `.0` dropped: `1.3`, `4`.
pub(crate) fn kb(bytes: u64) -> String {
    let s = format!("{:.1}", bytes as f64 / 1024.0);
    s.strip_suffix(".0").map(str::to_owned).unwrap_or(s)
}

/// How full the key's store is, in plain numbers: `1.3 of 4 KB used · room
/// for about 45 more entries` (free bytes ÷ [`TYPICAL_ENTRY_BYTES`]), or
/// `· full` when not one more fits.
pub(crate) fn space_line(cap: &BlobCapacity) -> String {
    let used = format!("{} of {} KB used", kb(cap.used_bytes), kb(cap.max_bytes));
    let n = cap.free_bytes / TYPICAL_ENTRY_BYTES;
    match n {
        0 => format!("{used} \u{00B7} full"),
        1 => format!("{used} \u{00B7} room for about 1 more entry"),
        n => format!("{used} \u{00B7} room for about {n} more entries"),
    }
}

/// When an entry last changed, as an opened entry says it: `modified` and
/// `now` in minutes since the Unix epoch. Recent changes in days, older (or
/// clock-skewed) ones as a date; `None` for an entry with no time.
pub(crate) fn changed_ago(modified: i64, now: i64) -> Option<String> {
    if modified <= 0 {
        return None;
    }
    let days = now.saturating_sub(modified) / (24 * 60);
    Some(match days {
        0 if now >= modified => "changed today".to_owned(),
        1 => "changed yesterday".to_owned(),
        2..=59 => format!("changed {days} days ago"),
        _ => {
            let (y, m, d) = keyroost_pgpkey::cert::civil_from_days(modified.div_euclid(24 * 60));
            format!("changed on {y:04}-{m:02}-{d:02}")
        }
    })
}

/// Whether `hay` holds `needle` (already lower-cased), ignoring case,
/// without a lower-cased copy of `hay`: a username is private.
fn contains_folded(hay: &str, needle: &[char]) -> bool {
    needle.is_empty()
        || hay.char_indices().any(|(i, _)| {
            let mut h = fold(&hay[i..]);
            needle.iter().all(|n| h.next() == Some(*n))
        })
}

/// Whether entry `e` matches the filter: its title, username or URL holds
/// `filter`, ignoring case. Never its notes or password, which the list
/// doesn't show. An empty filter matches every entry.
///
/// The list lower-cases the filter once ([`shown_rows`]); this one-entry
/// form is for tests.
#[cfg(test)]
pub(crate) fn matches_filter(e: &Entry, filter: &str) -> bool {
    matches_needle(e, &needle(filter))
}

/// The filter lower-cased once, for [`matches_needle`].
fn needle(filter: &str) -> Vec<char> {
    fold(filter.trim()).collect()
}

/// Whether entry `e` matches the filter, already lower-cased ([`needle`]):
/// its title, username or URL holds it. Never its notes or password.
fn matches_needle(e: &Entry, needle: &[char]) -> bool {
    [&e.title, &e.username, &e.url]
        .iter()
        .any(|f| contains_folded(f, needle))
}

/// The entries of `v` the list shows for `filter`, as indices into
/// `v.entries`: sorted by title, then username, ignoring case.
pub(crate) fn shown_rows(v: &Vault, filter: &str) -> Vec<usize> {
    let needle = needle(filter);
    let mut rows: Vec<usize> = (0..v.entries.len())
        .filter(|&i| matches_needle(&v.entries[i], &needle))
        .collect();
    rows.sort_by(|&a, &b| {
        let (a, b) = (&v.entries[a], &v.entries[b]);
        // Compared a character at a time: no lower-cased copies to wipe.
        fold(&a.title)
            .cmp(fold(&b.title))
            .then_with(|| fold(&a.username).cmp(fold(&b.username)))
    });
    rows
}

/// `s` lower-cased, a character at a time.
fn fold(s: &str) -> impl Iterator<Item = char> + '_ {
    s.chars().flat_map(char::to_lowercase)
}

/// A URL's host: no scheme, no `user:password@`, no path, query or
/// fragment. `https://alice@github.com/login` → `github.com`.
fn url_host(url: &str) -> &str {
    let rest = url.trim().split_once("://").map_or(url.trim(), |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    authority.rsplit_once('@').map_or(authority, |(_, h)| h)
}

/// Push `text` to `out` with control characters (from another program's
/// entry) flattened to spaces.
fn push_flat(out: &mut String, text: &str) {
    out.extend(text.chars().map(|c| if c.is_control() { ' ' } else { c }));
}

/// An entry's row: `title · username · host`, empty parts left out. Built
/// in a wiped buffer: the username is private.
fn row_line(e: &Entry) -> Zeroizing<String> {
    let mut line = Zeroizing::new(String::with_capacity(
        e.title.len() + e.username.len() + e.url.len() + 8,
    ));
    for part in [e.title.as_str(), e.username.as_str(), url_host(&e.url)] {
        if part.trim().is_empty() {
            continue;
        }
        if !line.is_empty() {
            line.push_str(" \u{00B7} ");
        }
        push_flat(&mut line, part);
    }
    line
}

/// What a row's copy button copies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CopyWhat {
    Username,
    Password,
}

impl CopyWhat {
    /// The copied flash's key for entry `id`: `"{id}:u"` / `"{id}:p"`.
    fn flash_key(self, id: &str) -> String {
        match self {
            CopyWhat::Username => format!("{id}:u"),
            CopyWhat::Password => format!("{id}:p"),
        }
    }
}

/// The index in `vaults` of the vault with credential ID `selected`; the
/// first vault when none is selected or that one is no longer listed.
pub(crate) fn selected_index(vaults: &[VaultOnKey], selected: Option<&[u8]>) -> Option<usize> {
    selected
        .and_then(|id| vaults.iter().position(|v| v.vault_ref.credential_id == id))
        .or_else(|| (!vaults.is_empty()).then_some(0))
}

/// The Backup card's reason for a backup, in one sentence.
const BACKUP_TEXT: &str = "A vault lives only on this key: if the key is lost or reset, the \
                           vault goes with it. Keep a backup file, protected by a passphrase.";

/// The "Experimental" pill and the line asking for reports and a backup.
pub(crate) fn experimental_note(ui: &mut egui::Ui, p: &Palette) {
    experimental_line(ui, p, " and keep a backup.");
}

/// The "Experimental" pill and the line asking for reports, beside every
/// offer of a fingerprint unlock.
pub(crate) fn fingerprint_experimental_note(ui: &mut egui::Ui, p: &Palette) {
    experimental_line(ui, p, ".");
}

/// The "Experimental" pill, then "Please report problems" (a link) and
/// `tail`, which ends the sentence.
pub(crate) fn experimental_line(ui: &mut egui::Ui, p: &Palette, tail: &str) {
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        theme::pill(ui, "Experimental", p.warn, p.warn_soft());
        ui.add_space(8.0);
        let text = |s: &str| {
            egui::Label::new(
                egui::RichText::new(s)
                    .font(theme::f_reg(11.5))
                    .color(p.txt3),
            )
        };
        // The pill says "Experimental": the sentence starts after it.
        ui.add(text("Please "));
        ui.hyperlink_to(
            egui::RichText::new("report problems").font(theme::f_reg(11.5)),
            ISSUES_URL,
        );
        ui.add(text(tail));
    });
}

/// Why a vault job failed: the key couldn't be opened for it, or a vault
/// flow refused or failed. Every vault apply takes this one type.
#[derive(Debug)]
pub(crate) enum VaultJobError {
    /// Opening the key failed (or it speaks no CTAP2): the text to show.
    Open(String),
    Vault(VaultKeyError),
    /// A vault delete removed the vault's data but not its credential: the
    /// vault is left with no data (`cause` says what stopped it), and
    /// `capacity` is the store after the data went. Deleting it again
    /// finishes the job.
    DataRemoved {
        cause: VaultKeyError,
        capacity: BlobCapacity,
    },
}

impl From<VaultKeyError> for VaultJobError {
    fn from(e: VaultKeyError) -> Self {
        VaultJobError::Vault(e)
    }
}

/// Open `target` for the vault flows. A U2F-only key is refused in the
/// CLI's words; a key that can't hold a vault is refused by the
/// transport's support check before anything else is sent.
pub(crate) fn open_vault_key(
    target: &FidoTarget,
) -> Result<CtapVaultKey<Box<dyn CtapTransport>>, VaultJobError> {
    let (dev, cbor, _init) = open_fido(target).map_err(VaultJobError::Open)?;
    if !cbor {
        return Err(VaultJobError::Open(
            "device is U2F-only; CTAP2 password vaults not supported".into(),
        ));
    }
    Ok(CtapVaultKey::open(dev)?)
}

/// `text` as a sentence: the first letter upper-cased, a full stop at the
/// end unless it has one, control characters (from a vault name the key
/// gave) flattened.
fn as_sentence(text: &str) -> String {
    let mut s = sentence(&sanitize_title(text));
    if !s.ends_with(['.', '!', '?']) {
        s.push('.');
    }
    s
}

/// A delete whose entry is no longer in the vault.
const ENTRY_NOT_IN_VAULT: &str = "This entry is no longer in the vault; nothing was deleted.";

/// A delete refused because the entry changed on the key.
const DELETE_CHANGED_ON_KEY: &str = "This entry changed on the key since the vault was opened; \
                                     nothing was deleted. Check it and delete again.";

/// The CLI's `entry delete` question, for the confirmation card.
fn delete_entry_question(title: &str, vault: &str, key: &str) -> String {
    format!(
        "Delete entry \"{}\" from vault \"{}\" on {}?",
        sanitize_title(title),
        sanitize_title(vault),
        sanitize_title(key)
    )
}

/// A vault error as the pane shows it: the error's own words, with the
/// app's place to fix it where the CLI names a command.
pub(crate) fn vault_error_text(e: &VaultKeyError) -> String {
    let hint = match e {
        VaultKeyError::PinNotSet => "; set one on the FIDO2 tab",
        VaultKeyError::Ctap(CtapError::PinChangeRequired) => "; change it on the FIDO2 tab",
        VaultKeyError::NoVaults => "; create one with New vault",
        VaultKeyError::CreateUndone { left_over, .. } => match left_over {
            LeftOver {
                credential: true,
                data: false,
            } => "; delete the copy listed as (none) with Delete vault\u{2026}",
            LeftOver {
                credential: true,
                data: true,
            } => "; remove both with Delete vault\u{2026}",
            LeftOver {
                credential: false,
                data: true,
            } => {
                "; it shows on the FIDO2 tab's Storage as relying-party data, and nothing \
                 tells it apart from a website's data"
            }
            LeftOver {
                credential: false,
                data: false,
            } => "",
        },
        VaultKeyError::OldNotDeleted { name, cause, old } => {
            return old_not_deleted_text(name.as_deref(), cause, *old);
        }
        VaultKeyError::VaultGone { .. } => {
            return format!("{} {UNLOCK_AGAIN}", as_sentence(&e.to_string()));
        }
        _ => "",
    };
    as_sentence(&format!("{e}{hint}"))
}

/// A rotate made and checked the new vault but the old one is still on the
/// key: which copy to delete, and when the one left needs another rotate
/// to end up on a fresh key (the CLI's words, with the app's buttons).
/// Never "delete either" without that second rotate.
fn old_not_deleted_text(name: Option<&str>, cause: &VaultKeyError, old: OldVault) -> String {
    let which = match name {
        Some(n) if !n.is_empty() => format!("vault \"{n}\""),
        _ => "vault".to_owned(),
    };
    let both_copies = "both copies hold the same checked entries, but one still uses the old \
                       key: delete either with Delete vault\u{2026}, then rotate the one left \
                       again with Rotate vault key\u{2026} so it gets a fresh key";
    let next = match old {
        OldVault::Emptied => "the old copy is left with no data: delete the copy listed as \
                              (none) with Delete vault\u{2026}"
            .to_owned(),
        OldVault::Kept => both_copies.to_owned(),
        OldVault::Unknown => format!(
            "whether the old copy still holds its data is not known: if a copy is listed as \
             (none), delete that one with Delete vault\u{2026}; otherwise {both_copies}"
        ),
    };
    format!(
        "{} {UNLOCK_AGAIN}",
        as_sentence(&format!(
            "the new {which} is in place with every entry checked, but deleting the old one \
             failed: {cause}; {next}"
        ))
    )
}

/// A vault job's error as the pane shows it, as a sentence like the rest.
pub(crate) fn job_error_text(e: &VaultJobError) -> String {
    match e {
        VaultJobError::Open(s) => as_sentence(s),
        VaultJobError::Vault(e) => vault_error_text(e),
        VaultJobError::DataRemoved { cause, .. } => as_sentence(&format!(
            "the vault's entries were removed from the key, but deleting the vault itself \
             failed: {cause}; Delete vault\u{2026} again finishes it"
        )),
    }
}

/// What the touch banner says before touch `n` of `total`.
pub(crate) fn touch_text(n: u8, total: u8) -> String {
    if total <= 1 || n > total {
        "Touch your key\u{2026}".to_owned()
    } else {
        format!("Touch your key ({n} of {total})\u{2026}")
    }
}

/// A vault job's touches, counted into the cell the touch banner reads
/// ([`VaultState::progress`]). The prompt goes up just before each call
/// that waits for a touch and comes down at the next step, and when the
/// job ends, whatever its outcome.
pub(crate) struct TouchProgress {
    shown: Arc<Mutex<Option<String>>>,
    total: u8,
    done: u8,
}

impl TouchProgress {
    pub(crate) fn new(shown: Arc<Mutex<Option<String>>>, total: u8) -> Self {
        TouchProgress {
            shown,
            total,
            done: 0,
        }
    }

    fn show(&self, text: Option<String>) {
        if let Ok(mut cell) = self.shown.lock() {
            *cell = text;
        }
    }

    /// The flow's next step: a touch puts the prompt up, anything else
    /// (the write) takes it down.
    pub(crate) fn step(&mut self, s: VaultStep) {
        match s {
            VaultStep::CreateTouch | VaultStep::UnlockTouch => {
                self.done = self.done.saturating_add(1);
                self.show(Some(touch_text(self.done, self.total)));
            }
            _ => self.show(None),
        }
    }
}

impl Drop for TouchProgress {
    fn drop(&mut self) {
        self.show(None);
    }
}

/// Unlock every vault on `key`, the touch counted into `touches`.
pub(crate) fn run_unlock<K: VaultKey>(
    key: &mut K,
    auth: &mut VaultAuth,
    touches: &mut TouchProgress,
) -> Result<Unlocked, VaultKeyError> {
    vault::unlock(key, auth, &mut |s| touches.step(s))
}

/// Read the open vaults on `key` again with the secrets held: no PIN, no
/// touch.
pub(crate) fn run_reload<K: VaultKey>(
    key: &mut K,
    unlocked: &mut Unlocked,
) -> Result<(), VaultKeyError> {
    vault::reload(key, unlocked)
}

/// Save `change` to `open` on `key` with the secrets held: no PIN unless the
/// key dropped the token, no touch.
pub(crate) fn run_save<K: VaultKey>(
    key: &mut K,
    auth: &mut VaultAuth,
    open: &mut OpenVault,
    change: &Change,
    touches: &mut TouchProgress,
) -> Result<Saved, VaultKeyError> {
    vault::save(key, auth, open, change, &mut |s| touches.step(s))
}

/// Create a vault named `name` holding `initial` on `key`: two touches,
/// counted into `touches`. Refused before any touch when the name is taken
/// or the store has no room.
pub(crate) fn run_create<K: VaultKey>(
    key: &mut K,
    auth: &mut VaultAuth,
    name: &str,
    initial: &Vault,
    touches: &mut TouchProgress,
) -> Result<Created, VaultKeyError> {
    vault::create(key, auth, name, initial, &mut |s| touches.step(s))
}

/// Delete the vault `target` (found by its credential ID, so a vault of the
/// same name is never touched): no touch unless the key lists no
/// largeBlobKey for it. Returns how full the store is afterwards. A delete
/// that failed after the vault's data went is
/// [`VaultJobError::DataRemoved`], so the pane stops showing entries the key
/// no longer holds.
pub(crate) fn run_delete_vault<K: VaultKey>(
    key: &mut K,
    auth: &mut VaultAuth,
    target: &VaultRef,
    touches: &mut TouchProgress,
) -> Result<BlobCapacity, VaultJobError> {
    let cred = vault::list_credentials(key, auth)?
        .into_iter()
        .find(|c| c.vault.credential_id == target.credential_id)
        .ok_or_else(|| VaultKeyError::VaultGone {
            name: target.name.clone(),
        })?;
    if let Err(cause) = vault::delete(key, auth, &cred, &mut |s| touches.step(s)) {
        // Whether the data went before the failure: then only the
        // credential is left, as a vault with no data.
        let after = cred.large_blob_key.as_ref().and_then(|lbk| {
            key.read_blobs()
                .ok()
                .filter(|a| matches!(a.credential_data(lbk), CredentialData::Absent))
        });
        return Err(match after {
            Some(array) => VaultJobError::DataRemoved {
                cause,
                capacity: array.capacity(key.info()),
            },
            None => VaultJobError::Vault(cause),
        });
    }
    Ok(key
        .read_blobs()
        .map_err(VaultKeyError::from)?
        .capacity(key.info()))
}

/// Give the open vault `old` a new key: a new vault of the same name with
/// the same entries, then the old one deleted. Two touches.
pub(crate) fn run_rotate<K: VaultKey>(
    key: &mut K,
    auth: &mut VaultAuth,
    old: &OpenVault,
    touches: &mut TouchProgress,
) -> Result<Created, VaultKeyError> {
    vault::rotate(key, auth, old, &mut |s| touches.step(s))
}

/// Whether `e` is a rotate that was refused and undone because the vault
/// changed (or went) on the key since it was unlocked.
fn changed_during_rotate(e: &VaultKeyError) -> bool {
    matches!(
        e,
        VaultKeyError::CreateUndone { cause, .. }
            if matches!(**cause, VaultKeyError::ChangedDuringRotate)
    )
}

/// What a rotate job read again after the vault changed on the key: the
/// open vaults as the key holds them now, or why they couldn't be read.
pub(crate) type Reloaded = (Unlocked, Result<(), VaultJobError>);

/// After a rotate refused because the vault changed on the key: read the
/// open vaults again (no PIN, no touch), so the list shows what the key
/// holds now. `None` for any other outcome.
pub(crate) fn reload_after_rotate<K: VaultKey>(
    key: &mut K,
    result: &Result<Created, VaultKeyError>,
    mut unlocked: Unlocked,
) -> Option<Reloaded> {
    let changed = result.as_ref().err().is_some_and(changed_during_rotate);
    changed.then(|| {
        let r = run_reload(key, &mut unlocked).map_err(VaultJobError::from);
        (unlocked, r)
    })
}

/// A rotate refused because vault `name` changed on the key meanwhile.
fn changed_during_rotate_text(name: &str) -> String {
    format!(
        "Vault \"{}\" changed on the key while its key was being rotated, so nothing was \
         rotated.",
        sanitize_title(name)
    )
}

/// After [`changed_during_rotate_text`], when the list was read again.
const ROTATE_AGAIN: &str = "The list now shows it as the key holds it; check it and rotate again.";

/// What the pane says once a vault is made: the CLI's backup reminder,
/// with the app's Export backup… for its command.
pub(crate) fn backup_reminder(name: &str) -> String {
    format!(
        "Vault \"{}\" created on this key. If the key is lost or reset, the vault goes with \
         it. Keep a backup with Export backup\u{2026} below.",
        sanitize_title(name)
    )
}

/// The CLI's `vault delete` question.
fn delete_vault_question(name: &str, key: &str) -> String {
    format!(
        "Delete vault \"{}\" on {}?",
        sanitize_title(name),
        sanitize_title(key)
    )
}

/// The CLI's `vault delete` note, with the app's export for its command.
const DELETE_VAULT_NOTE: &str = "Its entries go with it. To keep them, export a backup first.";

/// The CLI's `vault rotate` question, word for word.
fn rotate_question(name: &str, key: &str) -> String {
    format!(
        "Rotate the key of vault \"{}\" on {}? A new vault replaces it; the old one is \
         deleted after every entry is checked.",
        sanitize_title(name),
        sanitize_title(key)
    )
}

/// What Rotate vault key… is for, under its button.
const ROTATE_EXPLAINED: &str = "Gives this vault a new key. Use it after unlocking the vault on \
                                a computer you no longer trust, then change the passwords that \
                                matter.";

/// How every line that locks the vault ends: one wording across the tab
/// (the idle lock keeps the app-wide "unlock again to continue").
const UNLOCK_AGAIN: &str = "Unlock the vault again to see what the key holds now.";

/// Why the vault locked when the FIDO2 tab changed the PIN it was opened
/// with.
pub(crate) fn pin_changed_text() -> String {
    format!("The FIDO2 PIN was changed, so the vault locked. {UNLOCK_AGAIN}")
}

/// Why the vault locked at a FIDO2 reset: nothing is left to unlock.
pub(crate) const FIDO_RESET_LOCKED: &str =
    "The FIDO2 reset wiped the key's passkeys and every vault on it.";

/// `why` the vault locked, then [`UNLOCK_AGAIN`] (once).
fn with_unlock_again(why: &str) -> String {
    if why.ends_with(UNLOCK_AGAIN) {
        why.to_owned()
    } else {
        format!("{why} {UNLOCK_AGAIN}")
    }
}

/// Why the vault locked when a create, delete or rotate couldn't start
/// (then [`UNLOCK_AGAIN`]).
const JOB_NOT_STARTED: &str = "That couldn't start, and nothing was changed.";

/// Why an unlock by fingerprint ended when the key refused the token it
/// gave, and the one it gave after asking again: the key's own words name
/// the PIN, which a person who touched the sensor never typed. The FIDO2
/// tab says the same.
pub(crate) const FINGER_UNLOCK_REFUSED: &str =
    "The key refused the fingerprint unlock; unlock again and retry.";

/// The unlock job couldn't be queued: the PIN typed for it is wiped.
const UNLOCK_NOT_STARTED: &str = "Unlocking couldn't start; press Unlock again.";

/// [`UNLOCK_NOT_STARTED`] for Touch fingerprint.
const UNLOCK_NOT_STARTED_FINGER: &str = "Unlocking couldn't start; press Touch fingerprint again.";

/// [`UNLOCK_NOT_STARTED`] when the PIN came from the Vault tab's box.
const UNLOCK_NOT_STARTED_TYPED: &str =
    "Unlocking couldn't start; type the PIN and press Unlock again.";

/// A Refresh of the unlocked vault couldn't be queued.
const REFRESH_NOT_STARTED: &str = "Reading the vault couldn't start; press Refresh again.";

/// Whether the key refused the vault's PIN (or locked it): every retry
/// would spend another of the key's PIN tries, so the vault locks.
fn pin_refused(e: &VaultJobError) -> bool {
    matches!(
        e,
        VaultJobError::Vault(VaultKeyError::Ctap(c))
            if c.is_pin_auth_error() || matches!(c, CtapError::StatusCode(0x32))
    )
}

/// What the job label and the CLI say while a vault is written.
const SAVE_LABEL: &str = "Saving to the key\u{2026}";

/// Why the vault locked when a save job couldn't be started (then
/// [`UNLOCK_AGAIN`]).
const SAVE_NOT_STARTED: &str = "The save couldn't start, and nothing was written.";

/// The CLI's `an entry needs a title`, as a sentence.
const NEEDS_TITLE: &str = "An entry needs a title.";

/// The form's notice when the entry it edits changed on the key.
const CHANGED_ON_KEY: &str = "This entry changed on the key since the vault was opened; nothing \
                              was written. Check it and save again.";

/// The form's notice after a conflict: [`CHANGED_ON_KEY`], naming the
/// fields changed both on the key and in the form, whose typed values will
/// replace the key's at the next Save.
fn changed_on_key(both: &[&str]) -> String {
    let fields = match both {
        [] => return CHANGED_ON_KEY.to_owned(),
        [one] => (*one).to_owned(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    };
    let (verb, them) = if both.len() == 1 {
        ("was", "it")
    } else {
        ("were", "them")
    };
    format!(
        "This entry changed on the key since the vault was opened; nothing was written. The \
         {fields} {verb} also changed elsewhere; yours will replace {them}. Check it and save \
         again."
    )
}

/// The form's notice when the entry it edits was deleted on the key.
const DELETED_ON_KEY: &str = "This entry was deleted on the key; Save adds it again.";

/// The generator's settings in one line: `Generate: 20 characters · A–Z
/// a–z 0–9 symbols`, the classes that are off left out. The length and the
/// classes are the ones [`generate_password`] uses (with every class off,
/// lower case).
pub(crate) fn gen_summary(o: &GenOptions) -> String {
    let mut classes: Vec<&str> = [
        (o.upper, "A\u{2013}Z"),
        (o.lower, "a\u{2013}z"),
        (o.digits, "0\u{2013}9"),
        (o.symbols, "symbols"),
    ]
    .into_iter()
    .filter_map(|(on, name)| on.then_some(name))
    .collect();
    if classes.is_empty() {
        classes.push("a\u{2013}z");
    }
    let length = o.length.clamp(classes.len().max(4), 128);
    format!(
        "Generate: {length} characters \u{00B7} {}",
        classes.join(" ")
    )
}

/// Set an entry's text field to `value`, wiping what it held first (a
/// plain assignment would free the old bytes unwiped).
fn replace_text(field: &mut String, value: &str) {
    field.zeroize();
    field.push_str(value);
}

/// The add / edit form of one vault entry. Every text box is listed as a
/// secret (usernames and notes are as private as the password), so Save,
/// Cancel, Lock and the idle lock all wipe them.
pub(crate) struct EntryForm {
    /// The entry as read, for an edit: `Change::Edit`'s `before`. `None`
    /// adds a new entry.
    pub(crate) editing: Option<Entry>,
    /// The vault it saves to, found by credential ID.
    pub(crate) vault: VaultRef,
    pub(crate) title: String,
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) url: String,
    pub(crate) notes: String,
    /// The password box shows its text.
    pub(crate) show_password: bool,
    /// Why the last Save didn't go through, shown in the form.
    pub(crate) notice: Option<String>,
}

impl TypedSecrets for EntryForm {
    fn secrets_mut(&mut self) -> Vec<&mut String> {
        let Self {
            editing: _,
            vault: _,
            title,
            username,
            password,
            url,
            notes,
            show_password: _,
            notice: _,
        } = self;
        vec![title, username, password, url, notes]
    }
}

impl Drop for EntryForm {
    fn drop(&mut self) {
        self.wipe_typed();
    }
}

impl EntryForm {
    /// An empty form that adds an entry to `vault`.
    pub(crate) fn for_add(vault: VaultRef) -> Self {
        EntryForm {
            editing: None,
            vault,
            title: String::new(),
            username: String::new(),
            password: String::new(),
            url: String::new(),
            notes: String::new(),
            show_password: false,
            notice: None,
        }
    }

    /// A form holding `e` as read, to edit it.
    pub(crate) fn for_edit(vault: VaultRef, e: &Entry) -> Self {
        EntryForm {
            editing: Some(e.clone()),
            vault,
            title: e.title.clone(),
            username: e.username.clone(),
            password: e.password.as_str().to_owned(),
            url: e.url.clone(),
            notes: e.notes.clone(),
            show_password: false,
            notice: None,
        }
    }

    /// After a conflict: edit `current` (the entry as the key holds it now)
    /// instead of the entry as first read. A field left as it was read takes
    /// the key's value, so the next Save doesn't undo the other change; a
    /// field typed over keeps the typed value. Returns the fields changed
    /// both here and on the key, in the form's order.
    pub(crate) fn rebase(&mut self, current: Entry) -> Vec<&'static str> {
        let Some(before) = self.editing.take() else {
            self.editing = Some(current);
            return Vec::new();
        };
        let mut both = Vec::new();
        for (name, typed, was, now) in [
            (
                "title",
                &mut self.title,
                before.title.as_str(),
                current.title.as_str(),
            ),
            (
                "username",
                &mut self.username,
                before.username.as_str(),
                current.username.as_str(),
            ),
            (
                "password",
                &mut self.password,
                before.password.as_str(),
                current.password.as_str(),
            ),
            (
                "URL",
                &mut self.url,
                before.url.as_str(),
                current.url.as_str(),
            ),
            (
                "notes",
                &mut self.notes,
                before.notes.as_str(),
                current.notes.as_str(),
            ),
        ] {
            if typed.as_str() == was {
                replace_text(typed, now);
            } else if was != now && typed.as_str() != now {
                both.push(name);
            }
        }
        self.editing = Some(current);
        both
    }

    /// Whether any field differs from where the form started: empty for an
    /// add, the entry as read for an edit.
    pub(crate) fn is_dirty(&self) -> bool {
        let start: [&str; 5] = match &self.editing {
            Some(e) => [&e.title, &e.username, &e.password, &e.url, &e.notes],
            None => [""; 5],
        };
        [
            &self.title,
            &self.username,
            &self.password,
            &self.url,
            &self.notes,
        ]
        .into_iter()
        .zip(start)
        .any(|(now, was)| now != was)
    }

    /// The change Save writes, stamped `now` (minutes since the epoch): a new
    /// entry with a new ID, or the entry as read becoming the typed values
    /// under its own ID. A title that is empty or only spaces is refused.
    pub(crate) fn change(&self, now: i64) -> Result<Change, &'static str> {
        if self.title.trim().is_empty() {
            return Err(NEEDS_TITLE);
        }
        match &self.editing {
            None => Ok(Change::Add(Entry {
                id: new_id(),
                title: self.title.clone(),
                username: self.username.clone(),
                password: Zeroizing::new(self.password.clone()),
                url: self.url.clone(),
                notes: self.notes.clone(),
                modified_minutes: now,
            })),
            Some(before) => {
                let mut after = before.clone();
                replace_text(&mut after.title, &self.title);
                replace_text(&mut after.username, &self.username);
                replace_text(&mut after.password, &self.password);
                replace_text(&mut after.url, &self.url);
                replace_text(&mut after.notes, &self.notes);
                after.modified_minutes = now;
                Ok(Change::Edit {
                    before: before.clone(),
                    after,
                })
            }
        }
    }
}

/// What a vault save was for, so its end reports in that change's words.
/// The titles are entry data: held wiped, shown in the pane, never logged.
pub(crate) enum SaveKind {
    Add {
        title: Zeroizing<String>,
    },
    Edit {
        title: Zeroizing<String>,
    },
    Delete {
        title: Zeroizing<String>,
    },
    /// The ticked rows of the import dialog; [`Saved`] counts what was
    /// added and replaced.
    Import,
}

/// A destructive vault action waiting for its Yes. Keyed by credential ID /
/// entry ID, never by name: two vaults or entries may share one.
pub(crate) enum VaultConfirm {
    DeleteEntry { vault: VaultRef, entry_id: String },
    DeleteVault { vault: VaultRef },
    Rotate { vault: VaultRef },
}

/// The unlocked vaults of one key. Reached only through
/// [`App::vault_session`], which refuses it once another key is selected.
pub(crate) struct VaultSession {
    /// The key it was unlocked on.
    pub(crate) device: DeviceId,
    /// The PIN (or the fingerprint unlock) and the token the writes reuse;
    /// `None` while a job holds it.
    pub(crate) auth: Option<VaultAuth>,
    pub(crate) unlocked: Unlocked,
    /// The PIN came from the FIDO2 tab's session, so a refusal of it
    /// locks that tab too.
    pub(crate) pin_from_fido: bool,
    /// How the unlock was verified, kept here so the tab can say so while
    /// a job holds [`Self::auth`].
    pub(crate) verified: Option<Verified>,
}

impl VaultSession {
    /// The session's vault `credential_id`: found by credential ID, never
    /// by name, since two vaults may share one.
    pub(crate) fn vault(&self, credential_id: &[u8]) -> Option<&VaultOnKey> {
        self.unlocked
            .vaults
            .iter()
            .find(|v| v.vault_ref.credential_id == credential_id)
    }

    /// [`Self::vault`], to change it.
    pub(crate) fn vault_mut(&mut self, credential_id: &[u8]) -> Option<&mut VaultOnKey> {
        self.unlocked
            .vaults
            .iter_mut()
            .find(|v| v.vault_ref.credential_id == credential_id)
    }
}

/// The Vault tab's state for the selected key. Replaced whole when another
/// key is selected, and on lock ([`App::vault_lock`]), so every field
/// drops and wipes through its own `Drop` / `Zeroizing`.
#[derive(Default)]
pub(crate) struct VaultState {
    /// The last failure, shown under the header.
    pub(crate) error: Option<String>,
    /// The last success, shown under the header.
    pub(crate) info: Option<String>,
    /// The unlocked vaults; `None` while locked.
    pub(crate) session: Option<VaultSession>,
    /// The PIN box, used when the FIDO2 tab isn't unlocked.
    pub(crate) pin_input: Zeroizing<String>,
    /// The touch prompt a running vault job shows on the touch banner.
    /// Kept across a lock, so a job still running keeps its prompt.
    pub(crate) progress: Arc<Mutex<Option<String>>>,
    /// The chosen vault's credential ID; `None`, or an ID no longer listed,
    /// shows the first vault.
    pub(crate) selected: Option<Vec<u8>>,
    /// The list's filter: titles, usernames and URLs.
    pub(crate) filter: String,
    /// The opened entry's ID.
    pub(crate) open_entry: Option<String>,
    /// The entry whose password Show reveals; only ever the opened one.
    pub(crate) revealed: Option<String>,
    /// The "Copied" flash: `"{id}:u"` / `"{id}:p"` and when it ends (unix
    /// seconds).
    pub(crate) copied: Option<(String, f64)>,
    /// The add / edit entry form; it takes the list's place while open.
    pub(crate) form: Option<EntryForm>,
    /// The generator's length and character sets. Kept across a lock.
    pub(crate) gen: GenOptions,
    /// The generator's settings are shown under the password box.
    pub(crate) gen_open: bool,
    /// The action waiting for its confirmation card.
    pub(crate) confirm: Option<VaultConfirm>,
    /// That card was just asked for: it scrolls into view once (the
    /// vault's questions sit far from the buttons that ask them).
    pub(crate) scroll_to_confirm: bool,
    /// The New vault box's name, while it is open. Not a secret: vault
    /// names are listed without unlocking.
    pub(crate) new_vault: Option<String>,
    /// The vault Export backup… was pressed for, while its save dialog is
    /// open; the chosen file opens [`Self::export`] for it.
    pub(crate) export_for: Option<VaultRef>,
    /// The backup's passphrase dialog; it takes the list's place while open.
    pub(crate) export: Option<ExportDialog>,
    /// Import backup…'s open dialog is up; the chosen file opens
    /// [`Self::import`].
    pub(crate) import_asked: bool,
    /// The import dialog: the backup's passphrase, then its preview. It
    /// takes the list's place while open.
    pub(crate) import: Option<ImportDialog>,
}

impl TypedSecrets for VaultState {
    fn secrets_mut(&mut self) -> Vec<&mut String> {
        // Every field named, so a new one has to be classified here.
        let Self {
            error: _,
            info: _,
            session: _,
            pin_input,
            progress: _,
            selected: _,
            // What the list is filtered by: titles, usernames and URLs the
            // unlocked list shows anyway.
            filter: _,
            open_entry: _,
            revealed: _,
            copied: _,
            form,
            gen: _,
            gen_open: _,
            confirm: _,
            scroll_to_confirm: _,
            new_vault: _,
            export_for: _,
            export,
            import_asked: _,
            import,
        } = self;
        let mut out = vec![&mut **pin_input];
        if let Some(f) = form.as_mut() {
            out.extend(f.secrets_mut());
        }
        if let Some(d) = export.as_mut() {
            out.extend(d.secrets_mut());
        }
        if let Some(d) = import.as_mut() {
            out.extend(d.secrets_mut());
        }
        out
    }
}

impl VaultState {
    /// The import preview holds a backup's entries, opened with its
    /// passphrase.
    pub(crate) fn holds_opened(&self) -> bool {
        self.import.as_ref().is_some_and(|d| d.incoming.is_some())
    }
}

impl App {
    /// Name the Storage entries an unlocked vault holds. Run after a Storage
    /// load and whenever the vault session is set, changed or dropped; never
    /// per frame.
    pub(crate) fn refresh_storage_vault_labels(&mut self) {
        let labels = match (&self.security_keys.large_blobs, self.vault_session()) {
            (Some(array), Some(s)) => vault_entry_labels(array, &s.unlocked.vaults),
            _ => Vec::new(),
        };
        self.security_keys.lb_vault_labels = labels;
    }

    /// The vault session, only while it is bound to the selected key.
    pub(crate) fn vault_session(&self) -> Option<&VaultSession> {
        self.vault
            .session
            .as_ref()
            .filter(|s| completion_still_valid(Some(&s.device), self.selected_device.as_ref()))
    }

    pub(crate) fn vault_session_mut(&mut self) -> Option<&mut VaultSession> {
        let selected = self.selected_device.clone();
        self.vault
            .session
            .as_mut()
            .filter(|s| completion_still_valid(Some(&s.device), selected.as_ref()))
    }

    /// Vault `credential_id` of the session ([`VaultSession::vault`]).
    pub(crate) fn session_vault(&self, credential_id: &[u8]) -> Option<&VaultOnKey> {
        self.vault_session()?.vault(credential_id)
    }

    /// The PIN an unlock uses: the FIDO2 tab's, when that tab is unlocked on
    /// this key (`true`), else the one typed in the Vault tab's box, which
    /// empties.
    pub(crate) fn unlock_pin(&mut self) -> Result<(Zeroizing<String>, bool), &'static str> {
        // A fingerprint session holds no PIN: the vault takes its own.
        if let Some(pin) = self.fido_session().and_then(|s| s.unlock.pin()) {
            if !pin.is_empty() {
                return Ok((pin.clone(), true));
            }
        }
        let pin = std::mem::take(&mut self.vault.pin_input);
        if pin.is_empty() {
            return Err("PIN is empty");
        }
        Ok((pin, false))
    }

    /// Unlock every vault on the selected key: the PIN, then one touch (none
    /// when the key holds no vault).
    pub(crate) fn vault_unlock(&mut self) {
        // Before the PIN is taken: a refused job would drop it.
        if self.refuse_if_busy() {
            return;
        }
        let Some(target) = self.selected_fido_target() else {
            return;
        };
        let (pin, pin_from_fido) = match self.unlock_pin() {
            Ok(p) => p,
            Err(e) => {
                self.vault.error = Some(e.to_owned());
                return;
            }
        };
        // A PIN typed here also unlocks the FIDO2 tab once it's accepted.
        let typed_pin = (!pin_from_fido).then(|| pin.clone());
        let auth = VaultAuth::pin(pin);
        let queued = self.vault_spawn_unlock(target, auth, pin_from_fido, typed_pin);
        if !queued {
            // The job dropped (and wiped) the PIN it took; the box is wiped
            // too, so nothing typed waits for a retry.
            wipe(&mut self.vault.pin_input);
            self.vault.error = Some(
                if pin_from_fido {
                    UNLOCK_NOT_STARTED
                } else {
                    UNLOCK_NOT_STARTED_TYPED
                }
                .to_owned(),
            );
        }
    }

    /// Unlock every vault on the selected key with a fingerprint: the key's
    /// own sensor gives the tokens, then one touch. Only the vault unlocks
    /// (the FIDO2 tab takes its own touch), and no PIN is kept; one typed
    /// into the box is wiped.
    pub(crate) fn vault_unlock_fingerprint(&mut self) {
        if self.refuse_if_busy() {
            return;
        }
        let Some(target) = self.selected_fido_target() else {
            return;
        };
        wipe(&mut self.vault.pin_input);
        let auth = self.vault_fingerprint_auth();
        if !self.vault_spawn_unlock(target, auth, false, None) {
            self.vault.error = Some(UNLOCK_NOT_STARTED_FINGER.to_owned());
        }
    }

    /// A fingerprint [`VaultAuth`] whose asks for the finger show in the
    /// touch banner ([`VaultState::progress`]), with the reason when the
    /// key dropped the token it gave.
    pub(crate) fn vault_fingerprint_auth(&self) -> VaultAuth {
        let progress = self.vault.progress.clone();
        VaultAuth::fingerprint(Box::new(move |ask| {
            if let Ok(mut cell) = progress.lock() {
                *cell = Some(ask.prompt().to_owned());
            }
        }))
    }

    /// Queue the unlock job with `auth`; whether it was queued.
    fn vault_spawn_unlock(
        &mut self,
        target: FidoTarget,
        auth: VaultAuth,
        pin_from_fido: bool,
        typed_pin: Option<Zeroizing<String>>,
    ) -> bool {
        let shown = self.vault.progress.clone();
        let for_device = self.selected_device.clone();
        self.vault.error = None;
        self.vault.info = None;
        self.spawn_job("Unlocking the vault\u{2026}", move || {
            let mut auth = auth;
            let result = {
                let mut touches = TouchProgress::new(shown, 1);
                open_vault_key(&target).and_then(|mut key| {
                    run_unlock(&mut key, &mut auth, &mut touches).map_err(VaultJobError::from)
                })
            };
            Box::new(move |app: &mut App| {
                app.vault_apply_unlock(for_device, auth, pin_from_fido, typed_pin, result);
            })
        })
    }

    /// The end of an unlock. A result for a key no longer selected is
    /// dropped with its secrets. A refused PIN says so, and when the PIN was
    /// the FIDO2 tab's, locks that tab too.
    pub(crate) fn vault_apply_unlock(
        &mut self,
        for_device: Option<DeviceId>,
        auth: VaultAuth,
        pin_from_fido: bool,
        typed_pin: Option<Zeroizing<String>>,
        result: Result<Unlocked, VaultJobError>,
    ) {
        if !completion_still_valid(for_device.as_ref(), self.selected_device.as_ref()) {
            return;
        }
        let Some(device) = for_device else {
            return;
        };
        match result {
            Ok(unlocked) => {
                self.vault.error = None;
                self.vault.session = Some(VaultSession {
                    device,
                    verified: auth.verified(),
                    auth: Some(auth),
                    unlocked,
                    pin_from_fido,
                });
                self.refresh_storage_vault_labels();
                // One PIN entry serves both tabs: the FIDO2 tab unlocks with
                // the PIN the key just accepted (no touch).
                if let Some(pin) = typed_pin {
                    if self.fido_session().is_none() {
                        self.unlock_fido_with(pin);
                    }
                }
            }
            Err(e) => {
                let refused = pin_refused(&e);
                if refused && auth.verified() == Some(Verified::Fingerprint) {
                    self.vault_fail_finger_refused();
                    return;
                }
                self.vault_fail(&e);
                if refused && pin_from_fido {
                    // The shared PIN is wrong on the FIDO2 tab too.
                    self.relock_fido_session();
                }
            }
        }
    }

    /// Read the unlocked vaults again: another program's changes show, with
    /// no PIN and no touch. The list stays on screen while it runs.
    pub(crate) fn vault_refresh(&mut self) {
        if self.refuse_if_busy() {
            return;
        }
        let Some(target) = self.selected_fido_target() else {
            return;
        };
        let Some(session) = self.vault_session() else {
            return;
        };
        let unlocked = session.unlocked.clone();
        let for_device = self.selected_device.clone();
        let queued = self.spawn_job("Reading the vault\u{2026}", move || {
            let mut unlocked = unlocked;
            let result = open_vault_key(&target).and_then(|mut key| {
                run_reload(&mut key, &mut unlocked).map_err(VaultJobError::from)
            });
            Box::new(move |app: &mut App| app.vault_apply_reload(for_device, unlocked, result))
        });
        if !queued {
            self.vault.info = None;
            self.vault.error = Some(REFRESH_NOT_STARTED.to_owned());
        }
    }

    /// The end of a Refresh. Lands only on the session it was read for, so a
    /// Lock pressed meanwhile stays locked. A vault gone from the key locks
    /// the vault: only a new unlock shows what the key holds now.
    pub(crate) fn vault_apply_reload(
        &mut self,
        for_device: Option<DeviceId>,
        unlocked: Unlocked,
        result: Result<(), VaultJobError>,
    ) {
        if !completion_still_valid(for_device.as_ref(), self.selected_device.as_ref()) {
            return;
        }
        if self.vault_session().is_none() {
            return;
        }
        match result {
            Ok(()) => {
                if let Some(s) = self.vault_session_mut() {
                    s.unlocked = unlocked;
                }
                self.refresh_storage_vault_labels();
                self.vault_fix_selection();
                self.vault.error = None;
                // An import preview open meanwhile compares with the vault
                // as it is now, so no tick replaces a copy saved elsewhere.
                self.vault_import_refreshed();
            }
            Err(e @ VaultJobError::Vault(VaultKeyError::VaultGone { .. })) => {
                let text = job_error_text(&e);
                self.log(Severity::Err, format!("Vault: {text}"));
                self.vault_lock(Some(text));
            }
            Err(e) => self.vault_fail(&e),
        }
    }

    /// Lock the vault: the state is rebuilt, so every field (the session's
    /// secrets, the PIN box, and whatever later forms hold) drops and wipes,
    /// and a username or password copied from it that the clipboard still
    /// holds is cleared. The touch prompt cell stays for a job still
    /// running, and the generator's settings stay. `why` is shown.
    pub(crate) fn vault_lock(&mut self, why: Option<String>) {
        self.clear_vault_clipboard_now();
        let progress = std::mem::take(&mut self.vault.progress);
        let gen = std::mem::take(&mut self.vault.gen);
        self.vault = VaultState {
            error: why,
            progress,
            gen,
            ..Default::default()
        };
        self.refresh_storage_vault_labels();
    }

    /// The add / edit entry form holds unsaved changes: the one thing that
    /// keeps the vault open past [`crate::IDLE_LOCK_AFTER`].
    pub(crate) fn vault_form_dirty(&self) -> bool {
        self.vault.form.as_ref().is_some_and(EntryForm::is_dirty)
    }

    /// How long the vault waits without input before the idle lock takes
    /// it: [`crate::VAULT_EDIT_IDLE_LOCK_AFTER`] while its form holds
    /// unsaved changes, else the app's [`crate::IDLE_LOCK_AFTER`].
    pub(crate) fn vault_idle_limit(&self) -> std::time::Duration {
        if self.vault_form_dirty() {
            crate::VAULT_EDIT_IDLE_LOCK_AFTER
        } else {
            crate::IDLE_LOCK_AFTER
        }
    }

    /// The Vault tab holds something the idle lock clears: the unlocked
    /// vaults, a typed secret, or a backup opened for import.
    pub(crate) fn vault_holds_secrets(&mut self) -> bool {
        self.vault.session.is_some()
            || self.vault.holds_opened()
            || self.vault.secrets_mut().iter().any(|s| !s.is_empty())
    }

    /// The idle lock's part in the vault, after [`Self::vault_idle_limit`]
    /// without input: an unlocked vault locks ([`Self::vault_lock`], which
    /// also wipes its forms and clears a vault copy still on the clipboard)
    /// and says why; a PIN typed into a locked tab is only wiped, as the
    /// FIDO2 tab's is.
    pub(crate) fn vault_idle_lock(&mut self) {
        let v = &self.vault;
        if v.session.is_some() || v.form.is_some() || v.export.is_some() || v.import.is_some() {
            let limit = self.vault_idle_limit();
            self.vault_lock(Some(crate::idle_locked_msg_for(limit)));
        } else {
            self.vault.wipe_typed();
        }
    }

    /// The vault alone reaches [`crate::VAULT_EDIT_IDLE_LOCK_AFTER`]: the
    /// rest of the app locked at [`crate::IDLE_LOCK_AFTER`], while the form
    /// held unsaved changes. Now the vault locks too, and the log says so.
    pub(crate) fn vault_idle_lock_alone(&mut self) {
        let limit = self.vault_idle_limit();
        self.vault_idle_lock();
        // A focused box keeps egui's undo history of what was typed.
        self.drop_text_focus = true;
        self.vault_idle_log(limit);
    }

    /// The log line of a vault idle lock after `limit`, its own deadline.
    pub(crate) fn vault_idle_log(&mut self, limit: std::time::Duration) {
        self.log(
            Severity::Info,
            format!(
                "Vault: Locked after {} of inactivity.",
                crate::span_words(limit)
            ),
        );
    }

    /// The vault the list shows: the selected one, else the first.
    pub(crate) fn selected_vault(&self) -> Option<&VaultOnKey> {
        let vaults = &self.vault_session()?.unlocked.vaults;
        selected_index(vaults, self.vault.selected.as_deref()).map(|i| &vaults[i])
    }

    /// A selected vault no longer listed (deleted or replaced): back to the
    /// first vault, with nothing of the old one left open or shown.
    pub(crate) fn vault_fix_selection(&mut self) {
        let Some(id) = self.vault.selected.as_deref() else {
            return;
        };
        if self.session_vault(id).is_none() {
            self.vault.selected = None;
            self.vault.open_entry = None;
            self.vault.revealed = None;
        }
    }

    /// Copy entry `id`'s username or password from the shown vault: the
    /// concealed copy, marked as the vault's so Lock clears it, and the
    /// button's "Copied" flash. Nothing for an empty value.
    pub(crate) fn vault_copy(&mut self, ctx: &egui::Context, id: &str, what: CopyWhat, now: f64) {
        if let Some(mut text) = self.vault_copy_text(id, what) {
            let text = std::mem::take(&mut *text);
            self.copy_secret_from(ctx, text, true);
            self.vault.copied = Some((what.flash_key(id), now + COPIED_FLASH_SECS));
        }
    }

    /// Show vault `id` (its credential ID): the opened entry closes and a
    /// shown password hides.
    pub(crate) fn vault_select(&mut self, id: Vec<u8>) {
        self.vault.selected = Some(id);
        self.vault.confirm = None;
        self.vault.open_entry = None;
        self.vault.revealed = None;
    }

    /// Open entry `id`, or close it when it is the open one. A shown
    /// password hides either way.
    pub(crate) fn vault_toggle_entry(&mut self, id: &str) {
        self.vault.revealed = None;
        if self.vault.open_entry.as_deref() == Some(id) {
            self.vault.open_entry = None;
        } else {
            self.vault.open_entry = Some(id.to_owned());
        }
    }

    /// Whether the shown vault can be changed: it opened. A vault that
    /// can't be opened is left as it is (only Delete vault… reaches it).
    pub(crate) fn vault_writable(&self) -> bool {
        self.selected_vault().is_some_and(|v| v.state.is_ok())
    }

    /// The text a row's copy button puts on the clipboard: entry `id` of the
    /// shown vault (by ID, so two entries titled alike never swap), `None`
    /// when it has no such value.
    pub(crate) fn vault_copy_text(&self, id: &str, what: CopyWhat) -> Option<Zeroizing<String>> {
        let open = self.selected_vault()?.state.as_ref().ok()?;
        let e = open.contents.entries.iter().find(|e| e.id == id)?;
        let value: &str = match what {
            CopyWhat::Username => &e.username,
            CopyWhat::Password => &e.password,
        };
        (!value.is_empty()).then(|| Zeroizing::new(value.to_owned()))
    }

    /// Open the form that adds an entry to the shown vault, when it opened.
    /// Refused while a job runs: a save still running reports on the form
    /// it was started from.
    pub(crate) fn vault_add_entry(&mut self) {
        if !self.vault_writable() || self.refuse_if_busy() {
            return;
        }
        let Some(v) = self.selected_vault() else {
            return;
        };
        let form = EntryForm::for_add(v.vault_ref.clone());
        self.vault.form = Some(form);
        self.vault.error = None;
        self.vault.info = None;
    }

    /// Open the form that edits entry `id` of the shown vault. Refused
    /// while a job runs, as Add entry is.
    pub(crate) fn vault_edit_entry(&mut self, id: &str) {
        if self.refuse_if_busy() {
            return;
        }
        let Some(v) = self.selected_vault() else {
            return;
        };
        let Some(e) = v
            .state
            .as_ref()
            .ok()
            .and_then(|o| o.contents.entries.iter().find(|e| e.id == id))
        else {
            return;
        };
        let form = EntryForm::for_edit(v.vault_ref.clone(), e);
        self.vault.form = Some(form);
        self.vault.error = None;
        self.vault.info = None;
    }

    /// Close the form; what was typed is wiped. Not while a job runs (the
    /// button is disabled then): a save still running reports on this form.
    pub(crate) fn vault_cancel_form(&mut self) {
        if self.busy() {
            return;
        }
        self.vault.form = None;
    }

    /// Generate: a new password from the generator's settings replaces the
    /// form's, which is wiped first.
    pub(crate) fn vault_generate(&mut self) {
        let Some(f) = self.vault.form.as_mut() else {
            return;
        };
        match generate_password(&self.vault.gen) {
            Ok(pw) => {
                wipe(&mut f.password);
                f.password.push_str(&pw);
            }
            Err(e) => f.notice = Some(as_sentence(&e.to_string())),
        }
    }

    /// The open form's change and what it is, or `None` with the reason in
    /// the form when it can't be saved.
    pub(crate) fn vault_form_change(&mut self) -> Option<(VaultRef, SaveKind, Change)> {
        let f = self.vault.form.as_mut()?;
        match f.change(vault::now_minutes()) {
            Err(why) => {
                f.notice = Some(why.to_owned());
                None
            }
            Ok(change) => {
                let title = Zeroizing::new(f.title.clone());
                let kind = match change {
                    Change::Add(_) => SaveKind::Add { title },
                    _ => SaveKind::Edit { title },
                };
                Some((f.vault.clone(), kind, change))
            }
        }
    }

    /// Save: the form's change goes to the key.
    pub(crate) fn vault_save_form(&mut self) {
        let Some((vault, kind, change)) = self.vault_form_change() else {
            return;
        };
        self.vault_start_save(vault, kind, change);
    }

    /// Ask before deleting entry `id` of the shown vault.
    pub(crate) fn vault_ask_delete_entry(&mut self, id: &str) {
        if !self.vault_writable() {
            return;
        }
        let Some(v) = self.selected_vault() else {
            return;
        };
        let vault = v.vault_ref.clone();
        self.vault.confirm = Some(VaultConfirm::DeleteEntry {
            vault,
            entry_id: id.to_owned(),
        });
        self.vault.scroll_to_confirm = true;
    }

    /// The confirmed delete: the entry as the session holds it goes through
    /// the one save path as `Change::Delete`, so a change made elsewhere is
    /// refused. Refused while a job runs; the question stays for the next
    /// try.
    pub(crate) fn vault_confirm_delete_entry(&mut self) {
        if let Some((vault, kind, change)) = self.vault_take_delete() {
            self.vault_start_save(vault, kind, change);
        }
    }

    /// The confirmed delete's change, with the confirmation taken. `None`
    /// while a job runs (the question stays) or when the entry is no longer
    /// in the vault (said plainly; nothing is written).
    pub(crate) fn vault_take_delete(&mut self) -> Option<(VaultRef, SaveKind, Change)> {
        let Some(VaultConfirm::DeleteEntry { vault, entry_id }) = self.vault.confirm.as_ref()
        else {
            return None;
        };
        let (vault, entry_id) = (vault.clone(), entry_id.clone());
        if self.refuse_if_busy() {
            return None;
        }
        self.vault.confirm = None;
        let Some(before) = self.vault_entry(&vault, &entry_id) else {
            self.vault.info = None;
            self.vault.error = Some(ENTRY_NOT_IN_VAULT.to_owned());
            return None;
        };
        let title = self.vault_entry_name(&vault, &before);
        Some((vault, SaveKind::Delete { title }, Change::Delete { before }))
    }

    /// Entry `e` of `vault` as a question or a result line names it
    /// ([`entry_shown_name`]): with its username (and host) when another
    /// entry shares its title.
    fn vault_entry_name(&self, vault: &VaultRef, e: &Entry) -> Zeroizing<String> {
        match self
            .session_vault(&vault.credential_id)
            .and_then(|v| v.state.as_ref().ok())
        {
            Some(open) => entry_shown_name(&open.contents, e),
            None => Zeroizing::new(e.title.clone()),
        }
    }

    /// Entry `id` of `vault` as the session holds it.
    fn vault_entry(&self, vault: &VaultRef, id: &str) -> Option<Entry> {
        self.session_vault(&vault.credential_id)?
            .state
            .as_ref()
            .ok()?
            .contents
            .entries
            .iter()
            .find(|e| e.id == id)
            .cloned()
    }

    /// What a save job takes from the session: the vault's auth (the session
    /// holds none until the job puts it back) and a copy of the open vault.
    /// `None`, and nothing taken, when the vault isn't open in the session or
    /// a job holds the auth.
    pub(crate) fn vault_take_for_save(
        &mut self,
        vault: &VaultRef,
    ) -> Option<(VaultAuth, OpenVault)> {
        let open = self
            .session_vault(&vault.credential_id)?
            .state
            .as_ref()
            .ok()?
            .clone();
        let auth = self.vault_session_mut()?.auth.take()?;
        Some((auth, open))
    }

    /// Write `change` to `vault` on the selected key: the session's PIN and
    /// token, no touch.
    fn vault_start_save(&mut self, vault: VaultRef, kind: SaveKind, change: Change) {
        if self.refuse_if_busy() {
            return;
        }
        let Some(target) = self.selected_fido_target() else {
            return;
        };
        let Some((auth, open)) = self.vault_take_for_save(&vault) else {
            // Gone from the session (a Refresh no longer lists it).
            self.vault.info = None;
            self.vault.error = Some(vault_error_text(&VaultKeyError::VaultGone {
                name: vault.name.clone(),
            }));
            return;
        };
        if let Some(f) = self.vault.form.as_mut() {
            f.notice = None;
        }
        self.vault.error = None;
        self.vault.info = None;
        let shown = self.vault.progress.clone();
        let for_device = self.selected_device.clone();
        let queued = self.spawn_job(SAVE_LABEL, move || {
            let mut auth = auth;
            let mut open = open;
            let result = {
                let mut touches = TouchProgress::new(shown, 0);
                open_vault_key(&target).and_then(|mut key| {
                    run_save(&mut key, &mut auth, &mut open, &change, &mut touches)
                        .map_err(VaultJobError::from)
                })
            };
            Box::new(move |app: &mut App| {
                app.vault_apply_save(for_device, vault, kind, auth, open, result);
            })
        });
        if !queued {
            // The job and the auth it took are gone: lock rather than keep
            // a session that can't save.
            let why = with_unlock_again(SAVE_NOT_STARTED);
            self.log(Severity::Err, format!("Vault: {why}"));
            self.vault_lock(Some(why));
        }
    }

    /// Back into the session after a save job: the auth, and the vault as
    /// the job left it (what was written, or on a conflict what the key
    /// holds now).
    fn vault_put_back(&mut self, auth: VaultAuth, open: OpenVault) {
        let Some(s) = self.vault_session_mut() else {
            return;
        };
        s.auth = Some(auth);
        let id = open.vault_ref.credential_id.clone();
        if let Some(v) = s.vault_mut(&id) {
            v.state = Ok(open);
        }
        self.refresh_storage_vault_labels();
    }

    /// The end of a save. A result for another key is dropped with its
    /// secrets. A change made elsewhere is never overwritten: a conflict
    /// reloads the vault and leaves the form open with what was typed; a
    /// vault gone from the key locks the session; a refused PIN locks it
    /// too, so no retry spends another of the key's PIN tries.
    pub(crate) fn vault_apply_save(
        &mut self,
        for_device: Option<DeviceId>,
        vault: VaultRef,
        kind: SaveKind,
        auth: VaultAuth,
        open: OpenVault,
        result: Result<Saved, VaultJobError>,
    ) {
        if !completion_still_valid(for_device.as_ref(), self.selected_device.as_ref()) {
            return;
        }
        let Some(pin_from_fido) = self.vault_session().map(|s| s.pin_from_fido) else {
            return;
        };
        self.vault_put_back(auth, open);
        let name = shown_name(vault.name.as_deref());
        match result {
            Err(e @ VaultJobError::Vault(VaultKeyError::VaultGone { .. })) => {
                self.vault_job_failed(&e, pin_from_fido);
            }
            Err(e) if pin_refused(&e) => self.vault_job_failed(&e, pin_from_fido),
            Ok(saved) => {
                if let Some(s) = self.vault_session_mut() {
                    s.unlocked.capacity = saved.capacity;
                }
                match &kind {
                    SaveKind::Add { title } => {
                        self.vault.form = None;
                        self.vault_done(
                            format!(
                                "Entry \"{}\" added to vault \"{name}\".",
                                sanitize_title(title)
                            ),
                            format!("entry added to vault \"{name}\""),
                        );
                    }
                    SaveKind::Edit { title } => {
                        self.vault.form = None;
                        self.vault_done(
                            format!("Entry \"{}\" updated.", sanitize_title(title)),
                            format!("entry updated in vault \"{name}\""),
                        );
                    }
                    SaveKind::Delete { title } => {
                        self.vault.open_entry = None;
                        self.vault.revealed = None;
                        self.vault_done(
                            format!("Entry \"{}\" deleted.", sanitize_title(title)),
                            format!("entry deleted from vault \"{name}\""),
                        );
                    }
                    SaveKind::Import => {
                        // Closing the dialog drops (and wipes) the backup.
                        self.vault.import = None;
                        let (added, replaced) = (saved.added, saved.replaced);
                        self.vault_done(
                            imported_line(&name, added, replaced),
                            format!(
                                "imported into vault \"{name}\": {added} added, \
                                 {replaced} replaced"
                            ),
                        );
                    }
                }
                // Every write that leaves the store nearly full says so,
                // whatever it was.
                self.space_note("Vault", &saved.capacity);
            }
            Err(e @ VaultJobError::Vault(VaultKeyError::Conflict))
                if matches!(kind, SaveKind::Add { .. } | SaveKind::Edit { .. }) =>
            {
                self.log(Severity::Warn, format!("Vault: {}", job_error_text(&e)));
                self.vault_rebase_form();
            }
            Err(e @ VaultJobError::Vault(VaultKeyError::Conflict))
                if matches!(kind, SaveKind::Import) =>
            {
                // The session holds the vault as the key does now (put back
                // above): the preview is worked out again against it.
                self.log(Severity::Warn, format!("Vault: {}", job_error_text(&e)));
                self.vault.info = None;
                self.vault_import_classify();
                if let Some(d) = self.vault.import.as_mut() {
                    d.notice = Some(IMPORT_CHANGED_ON_KEY.to_owned());
                }
            }
            Err(e @ VaultJobError::Vault(VaultKeyError::Conflict))
                if matches!(kind, SaveKind::Delete { .. }) =>
            {
                // The list already shows the key's entry (put back above).
                self.log(Severity::Warn, format!("Vault: {}", job_error_text(&e)));
                self.vault.info = None;
                self.vault.error = Some(DELETE_CHANGED_ON_KEY.to_owned());
            }
            Err(e) => self.vault_fail(&e),
        }
    }

    /// After a conflict: the form keeps what was typed and now edits the
    /// entry as the key holds it (reloaded into the session), or adds it
    /// again when it was deleted there.
    fn vault_rebase_form(&mut self) {
        self.vault.info = None;
        let Some(f) = self.vault.form.as_ref() else {
            self.vault.error = Some(CHANGED_ON_KEY.to_owned());
            return;
        };
        let id = f.editing.as_ref().map(|e| canon_id(&e.id));
        let cred = f.vault.credential_id.clone();
        let current = id.as_ref().and_then(|id| {
            self.session_vault(&cred)?
                .state
                .as_ref()
                .ok()?
                .contents
                .entries
                .iter()
                .find(|e| canon_id(&e.id) == *id)
                .cloned()
        });
        let Some(f) = self.vault.form.as_mut() else {
            return;
        };
        let notice = match (id, current) {
            (Some(_), None) => {
                f.editing = None;
                DELETED_ON_KEY.to_owned()
            }
            (Some(_), Some(e)) => changed_on_key(&f.rebase(e)),
            (None, _) => CHANGED_ON_KEY.to_owned(),
        };
        f.notice = Some(notice);
    }

    /// A vault change that worked: `shown` in the pane, `logged` in the
    /// activity log (never an entry's title, username, URL or notes).
    pub(crate) fn vault_done(&mut self, shown: String, logged: String) {
        self.log(Severity::Ok, format!("Vault: {logged}"));
        self.vault.error = None;
        self.vault.info = Some(shown);
    }

    /// [`FINGER_UNLOCK_REFUSED`] in the pane and the activity log.
    fn vault_fail_finger_refused(&mut self) {
        self.log(Severity::Err, format!("Vault: {FINGER_UNLOCK_REFUSED}"));
        self.vault.info = None;
        self.vault.error = Some(FINGER_UNLOCK_REFUSED.to_owned());
    }

    /// A vault job that failed: the pane and the activity log say why.
    pub(crate) fn vault_fail(&mut self, e: &VaultJobError) {
        let text = job_error_text(e);
        self.log(Severity::Err, format!("Vault: {text}"));
        self.vault.info = None;
        self.vault.error = Some(text);
    }

    /// The card that unlocks the vault: the FIDO2 tab's PIN when that tab is
    /// unlocked with one, else a PIN box (a fingerprint unlock of the FIDO2
    /// tab holds no PIN to share), with Touch fingerprint beside it on a key
    /// whose sensor can unlock it.
    fn vault_unlock_card(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let waiting = self.waiting_for().map(str::to_owned);
        let shared = self
            .fido_session()
            .and_then(|s| s.unlock.pin())
            .is_some_and(|pin| !pin.is_empty());
        // Experimental: no key with a sensor was on hand to try it.
        let finger = !shared && self.finger_ready();
        let mut unlock = false;
        let mut unlock_finger = false;
        theme::card_frame(p).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.label(
                egui::RichText::new("Unlock the vault")
                    .font(theme::f_sb(14.5))
                    .color(p.txt),
            );
            ui.add_space(8.0);
            if shared {
                ui.label(
                    egui::RichText::new(
                        "Uses the key's FIDO2 PIN \u{2014} already unlocked on the FIDO2 tab.",
                    )
                    .font(theme::f_reg(13.0))
                    .color(p.txt2),
                );
                ui.add_space(8.0);
                unlock = theme::key_button(ui, p, BtnKind::Primary, "Unlock", waiting.as_deref())
                    .clicked();
            } else {
                ui.horizontal(|ui| {
                    let resp = ui.add_sized(
                        [220.0, 32.0],
                        egui::TextEdit::singleline(&mut *self.vault.pin_input)
                            .margin(theme::TEXT_EDIT_MARGIN)
                            .align(egui::Align2::LEFT_CENTER)
                            .password(true)
                            .hint_text("FIDO2 PIN"),
                    );
                    guard_secret_field(ui.ctx(), &resp);
                    let submit =
                        theme::key_button(ui, p, BtnKind::Primary, "Unlock", waiting.as_deref())
                            .clicked();
                    if submit
                        || (resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)))
                    {
                        unlock = true;
                    }
                    if finger
                        && theme::key_button(
                            ui,
                            p,
                            BtnKind::Default,
                            "Touch fingerprint",
                            waiting.as_deref(),
                        )
                        .clicked()
                    {
                        unlock_finger = true;
                    }
                });
            }
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(if finger {
                    "Touch the fingerprint sensor, or enter the FIDO2 PIN, to unlock the vault."
                } else {
                    "Unlocking asks for a touch."
                })
                .font(theme::f_reg(11.5))
                .color(p.txt3),
            );
            if finger {
                ui.add_space(6.0);
                fingerprint_experimental_note(ui, p);
            }
        });
        if unlock {
            self.vault_unlock();
        } else if unlock_finger {
            self.vault_unlock_fingerprint();
        }
    }

    /// The Vault tab.
    pub(crate) fn cap_vault(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let offer = self.vault_offer();
        let unlocked = offer == VaultOffer::Ready && self.vault_session().is_some();
        let by_finger = self
            .vault_session()
            .is_some_and(|s| s.verified == Some(Verified::Fingerprint));
        let busy = self.busy();
        let mut open_fido2 = false;
        let mut lock = false;
        theme::card_frame(p).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("Vault")
                        .font(theme::f_sb(14.5))
                        .color(p.txt),
                );
                ui.add_space(6.0);
                self.help_dot(ui, p, "vault");
            });
            ui.add_space(6.0);
            experimental_note(ui, p);
            if unlocked {
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new(if by_finger {
                            "Unlocked with a fingerprint"
                        } else {
                            "Unlocked with the FIDO2 PIN"
                        })
                        .font(theme::f_reg(13.0))
                        .color(p.txt2),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        // Not while a job runs: a vault job may be
                        // working on this session.
                        if busy {
                            theme::button_disabled(ui, p, "Lock");
                        } else {
                            lock = theme::button(ui, p, BtnKind::Ghost, "Lock").clicked();
                        }
                    });
                });
            }
            if offer == VaultOffer::Ready {
                return;
            }
            ui.add_space(8.0);
            if offer == VaultOffer::NeedsAdmin {
                theme::pill(ui, "Administrator rights needed", p.warn, p.warn_soft());
                ui.add_space(6.0);
            }
            ui.label(
                egui::RichText::new(overview_line(
                    offer,
                    self.security_keys.error.is_some(),
                    None,
                    false,
                ))
                .font(theme::f_reg(13.0))
                .color(if offer == VaultOffer::Unknown {
                    p.txt3
                } else {
                    p.txt2
                }),
            );
            if matches!(offer, VaultOffer::NeedsAdmin | VaultOffer::NeedsPin) {
                ui.add_space(8.0);
                open_fido2 = theme::button(ui, p, BtnKind::Default, "Open FIDO2").clicked();
            }
        });
        if open_fido2 {
            self.cap_tab = CapTab::Fido2;
        }
        if lock {
            self.vault_lock(None);
        }
        ui.add_space(12.0);
        if let Some(info) = &self.vault.info {
            ui.colored_label(p.ok, info);
            ui.add_space(6.0);
        }
        if let Some(err) = &self.vault.error {
            ui.colored_label(p.err, err);
            ui.add_space(6.0);
        }
        if offer == VaultOffer::Ready && self.vault_session().is_none() {
            self.vault_unlock_card(ui, p);
        }
        if unlocked && self.vault_session().is_some() {
            self.render_vault_list(ui, p);
        }
    }

    /// The unlocked vaults: a chip per vault, how full the key is, the
    /// filter and Add entry, a row per entry with its copy buttons (the
    /// opened one with its password behind Show, its URL and notes, and
    /// Edit), then the Backup card. An open add / edit form takes the
    /// list's place.
    fn render_vault_list(&mut self, ui: &mut egui::Ui, p: &Palette) {
        self.vault_fix_selection();
        if self.vault_session().is_none() {
            return;
        }
        if self.vault.form.is_some() {
            self.render_entry_form(ui, p);
            return;
        }
        if self.vault.export.is_some() {
            self.render_export_dialog(ui, p);
            return;
        }
        if self.vault.import.is_some() {
            self.render_vault_import_dialog(ui, p);
            return;
        }
        self.render_vault_confirm(ui, p);
        let Some(session) = self.vault_session() else {
            return;
        };
        let vaults = &session.unlocked.vaults;
        let waiting = self.waiting_for().map(str::to_owned);
        if vaults.is_empty() {
            ui.label(
                egui::RichText::new("No vaults on this key yet.")
                    .font(theme::f_reg(13.0))
                    .color(p.txt2),
            );
            ui.add_space(8.0);
            let name = self.vault.new_vault.get_or_insert_with(String::new);
            if new_vault_row(ui, p, name, waiting.as_deref(), false).create {
                self.vault_create();
            }
            // A backup makes a vault too.
            ui.add_space(12.0);
            if theme::button(ui, p, BtnKind::Default, IMPORT_BUTTON).clicked() {
                self.vault_import_start();
            }
            return;
        }
        let now = now_secs_f64();
        if self.vault.copied.as_ref().is_some_and(|(_, t)| now >= *t) {
            self.vault.copied = None;
        }
        // What this frame's clicks ask for, acted on once the list is drawn.
        let mut select: Option<Vec<u8>> = None;
        let mut toggle: Option<String> = None;
        let mut copy: Option<(String, CopyWhat)> = None;
        let mut reveal: Option<Option<String>> = None;
        let mut add = false;
        let mut edit: Option<String> = None;
        let mut delete: Option<String> = None;
        let mut new_chip = false;
        let mut new_row = NewVaultClicks::default();
        let (mut rotate, mut delete_vault) = (false, false);
        let (mut export, mut import) = (false, false);
        // The filter and name boxes edit copies while the session is
        // borrowed.
        let mut filter = std::mem::take(&mut self.vault.filter);
        let mut new_name = self.vault.new_vault.take();

        let session = self.vault_session().expect("checked above");
        let vaults = &session.unlocked.vaults;
        let shown = selected_index(vaults, self.vault.selected.as_deref()).unwrap_or(0);

        // One chip per vault, keyed by credential ID: two vaults may share
        // a name.
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            for (i, v) in vaults.iter().enumerate() {
                if chip(ui, p, &chip_label(v), i == shown).clicked() && i != shown {
                    select = Some(v.vault_ref.credential_id.clone());
                }
            }
            new_chip = chip(ui, p, "+ New vault", new_name.is_some()).clicked();
        });
        if let Some(name) = new_name.as_mut() {
            ui.add_space(6.0);
            new_row = new_vault_row(ui, p, name, waiting.as_deref(), true);
        }
        ui.add_space(6.0);
        let cap = &session.unlocked.capacity;
        ui.horizontal(|ui| {
            space_bar(ui, p, cap);
            ui.add_space(6.0);
            ui.label(
                egui::RichText::new(space_line(cap))
                    .font(theme::f_reg(11.5))
                    .color(p.txt3),
            );
        });
        ui.add_space(8.0);

        match &vaults[shown].state {
            Err(problem) => {
                ui.label(
                    egui::RichText::new(format!(
                        "This vault can't be opened: {}. It is left as it is.",
                        sanitize_title(problem.to_string().trim_end_matches('.'))
                    ))
                    .font(theme::f_reg(13.0))
                    .color(p.warn),
                );
            }
            Ok(open) => {
                ui.horizontal(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        add = theme::button(ui, p, BtnKind::Primary, "Add entry").clicked();
                        ui.add(
                            egui::TextEdit::singleline(&mut filter)
                                .margin(theme::TEXT_EDIT_MARGIN)
                                .hint_text("Filter entries\u{2026}")
                                .desired_width(f32::INFINITY),
                        );
                    });
                });
                ui.add_space(6.0);
                let rows = shown_rows(&open.contents, &filter);
                theme::card_frame(p).show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    if rows.is_empty() {
                        let text = if open.contents.entries.is_empty() {
                            "(none)"
                        } else {
                            "No entries match the filter."
                        };
                        ui.label(
                            egui::RichText::new(text)
                                .font(theme::f_reg(13.0))
                                .color(p.txt3),
                        );
                    }
                    for (n, &i) in rows.iter().enumerate() {
                        let e = &open.contents.entries[i];
                        if n > 0 {
                            ui.separator();
                        }
                        let is_open = self.vault.open_entry.as_deref() == Some(e.id.as_str());
                        let flash = |what: CopyWhat| {
                            self.vault
                                .copied
                                .as_ref()
                                .is_some_and(|(k, _)| *k == what.flash_key(&e.id))
                        };
                        let row = entry_row(
                            ui,
                            p,
                            e,
                            [flash(CopyWhat::Username), flash(CopyWhat::Password)],
                        );
                        if row.toggle {
                            toggle = Some(e.id.clone());
                        }
                        if let Some(what) = row.copy {
                            copy = Some((e.id.clone(), what));
                        }
                        if is_open {
                            let showing = self.vault.revealed.as_deref() == Some(e.id.as_str());
                            let clicks = opened_entry(ui, p, e, showing);
                            if let Some(show) = clicks.reveal {
                                reveal = Some(show.then(|| e.id.clone()));
                            }
                            if clicks.edit {
                                edit = Some(e.id.clone());
                            }
                            if clicks.delete {
                                delete = Some(e.id.clone());
                            }
                        }
                    }
                });
            }
        }

        // Export backup… and Rotate vault key… need a vault that opened.
        let writable = vaults[shown].state.is_ok();
        ui.add_space(12.0);
        theme::card_frame(p).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.label(
                egui::RichText::new("Backup")
                    .font(theme::f_sb(13.5))
                    .color(p.txt),
            );
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(BACKUP_TEXT)
                    .font(theme::f_reg(12.0))
                    .color(p.txt3),
            );
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if writable {
                    export = theme::button(ui, p, BtnKind::Default, EXPORT_BUTTON).clicked();
                    import = theme::button(ui, p, BtnKind::Default, IMPORT_BUTTON).clicked();
                } else {
                    theme::button_disabled(ui, p, EXPORT_BUTTON);
                    theme::button_disabled(ui, p, IMPORT_BUTTON);
                }
            });
        });

        // The shown vault as a whole. Delete vault… reaches a vault that
        // can't be opened too; Rotate needs one that opened.
        ui.add_space(12.0);
        theme::card_frame(p).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.label(
                egui::RichText::new("This vault")
                    .font(theme::f_sb(13.5))
                    .color(p.txt),
            );
            ui.add_space(6.0);
            if writable {
                rotate =
                    theme::button(ui, p, BtnKind::Default, "Rotate vault key\u{2026}").clicked();
            } else {
                theme::button_disabled(ui, p, "Rotate vault key\u{2026}");
            }
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(ROTATE_EXPLAINED)
                    .font(theme::f_reg(12.0))
                    .color(p.txt3),
            );
            ui.add_space(10.0);
            delete_vault = theme::button(ui, p, BtnKind::Danger, "Delete vault\u{2026}").clicked();
        });

        self.vault.filter = filter;
        self.vault.new_vault = new_name;
        if new_chip {
            self.vault_new_vault();
        } else if new_row.cancel {
            self.vault.new_vault = None;
        } else if new_row.create {
            self.vault_create();
        }
        if rotate {
            self.vault_ask_rotate();
        }
        if delete_vault {
            self.vault_ask_delete_vault();
        }
        if export {
            self.vault_export_start();
        }
        if import {
            self.vault_import_start();
        }
        if let Some(id) = select {
            self.vault_select(id);
        }
        if let Some(id) = toggle {
            self.vault_toggle_entry(&id);
        }
        if let Some(r) = reveal {
            self.vault.revealed = r;
        }
        if let Some((id, what)) = copy {
            self.vault_copy(ui.ctx(), &id, what, now);
        }
        if add {
            self.vault_add_entry();
        }
        if let Some(id) = edit {
            self.vault_edit_entry(&id);
        }
        if let Some(id) = delete {
            self.vault_ask_delete_entry(&id);
        }
        if let Some((_, t)) = &self.vault.copied {
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_secs_f64((t - now).max(0.05)));
        }
        self.render_vault_action_confirm(ui, p);
    }
}

/// New vault, Delete vault and Rotate vault key: the jobs and their ends.
impl App {
    /// The selected key as a question names it.
    fn vault_key_title(&self) -> String {
        self.selected_device().map_or_else(
            || "this key".to_owned(),
            |d| crate::ui::device::DeviceView::title(d).into_owned(),
        )
    }

    /// The session's PIN and token, for a job that holds them until its end
    /// puts them back. `None` while another job holds them.
    pub(crate) fn vault_take_auth(&mut self) -> Option<VaultAuth> {
        self.vault_session_mut()?.auth.take()
    }

    /// Back into the session at a job's end.
    fn vault_give_back_auth(&mut self, auth: VaultAuth) {
        if let Some(s) = self.vault_session_mut() {
            s.auth = Some(auth);
        }
    }

    /// A job that took the session's auth couldn't be queued: the auth went
    /// with it, so lock rather than keep a session that can't write.
    fn vault_not_started(&mut self) {
        let why = with_unlock_again(JOB_NOT_STARTED);
        self.log(Severity::Err, format!("Vault: {why}"));
        self.vault_lock(Some(why));
    }

    /// The `+ New vault` chip: open the name box, or close it again.
    pub(crate) fn vault_new_vault(&mut self) {
        self.vault.new_vault = match self.vault.new_vault {
            Some(_) => None,
            None => Some(String::new()),
        };
    }

    /// What Create vault takes: the typed name (spaces around it dropped)
    /// and the session's auth. A name the format refuses, or one a vault on
    /// the key already has, is refused here, before any job, with nothing
    /// taken; the box keeps the name.
    pub(crate) fn vault_take_for_create(&mut self) -> Option<(String, VaultAuth)> {
        let typed = self.vault.new_vault.clone()?;
        let name = self.vault_check_new_name(&typed)?;
        let auth = self.vault_take_auth()?;
        Some((name, auth))
    }

    /// A new vault's name as typed, spaces around it dropped, when the
    /// format takes it and no vault on the key has it; otherwise `None`
    /// with the reason in the pane.
    fn vault_check_new_name(&mut self, typed: &str) -> Option<String> {
        self.vault_session()?;
        let name = typed.trim().to_owned();
        if let Some(e) = self.vault_new_name_refusal(&name) {
            self.vault.info = None;
            self.vault.error = Some(vault_error_text(&e));
            return None;
        }
        Some(name)
    }

    /// The names of the session's vaults, for [`new_name_refusal`].
    fn vault_names(&self) -> Vec<Option<String>> {
        self.vault_session().map_or_else(Vec::new, |s| {
            s.unlocked
                .vaults
                .iter()
                .map(|v| v.vault_ref.name.clone())
                .collect()
        })
    }

    /// Why a new vault can't be named `name` (already trimmed), against the
    /// session's vaults ([`new_name_refusal`]).
    pub(crate) fn vault_new_name_refusal(&self, name: &str) -> Option<VaultKeyError> {
        new_name_refusal(name, &self.vault_names())
    }

    /// Create vault: an empty vault of the typed name on the selected key,
    /// two touches.
    pub(crate) fn vault_create(&mut self) {
        if self.refuse_if_busy() {
            return;
        }
        let Some((name, auth)) = self.vault_take_for_create() else {
            return;
        };
        self.vault_spawn_create(name, auth, Vault::default(), None);
    }

    /// The create job: vault `name` holding `initial` (`imported` entries
    /// of a backup, or none) on the selected key, two touches.
    fn vault_spawn_create(
        &mut self,
        name: String,
        auth: VaultAuth,
        initial: Vault,
        imported: Option<usize>,
    ) {
        let Some(target) = self.selected_fido_target() else {
            self.vault_give_back_auth(auth);
            return;
        };
        self.vault.error = None;
        self.vault.info = None;
        let shown = self.vault.progress.clone();
        let for_device = self.selected_device.clone();
        let queued = self.spawn_job("Creating the vault\u{2026}", move || {
            let mut auth = auth;
            let result = {
                let mut touches = TouchProgress::new(shown, 2);
                open_vault_key(&target).and_then(|mut key| {
                    run_create(&mut key, &mut auth, &name, &initial, &mut touches)
                        .map_err(VaultJobError::from)
                })
            };
            drop(initial);
            Box::new(move |app: &mut App| {
                app.vault_apply_create(for_device, auth, imported, result);
            })
        });
        if !queued {
            self.vault_not_started();
        }
    }

    /// The end of a create. The new vault joins the list, selected, with
    /// the backup reminder (after an import into a new vault, `imported`
    /// entries, the import's line first). A create that failed keeps the
    /// typed name; one that left something on the key locks, since only a
    /// new unlock lists it.
    pub(crate) fn vault_apply_create(
        &mut self,
        for_device: Option<DeviceId>,
        auth: VaultAuth,
        imported: Option<usize>,
        result: Result<Created, VaultJobError>,
    ) {
        if !completion_still_valid(for_device.as_ref(), self.selected_device.as_ref()) {
            return;
        }
        let Some(pin_from_fido) = self.vault_session().map(|s| s.pin_from_fido) else {
            return;
        };
        self.vault_give_back_auth(auth);
        let Created { open, capacity } = match result {
            Ok(created) => created,
            Err(e) => return self.vault_job_failed(&e, pin_from_fido),
        };
        let name = shown_name(open.vault_ref.name.as_deref());
        let id = open.vault_ref.credential_id.clone();
        if let Some(s) = self.vault_session_mut() {
            s.unlocked.vaults.push(VaultOnKey {
                vault_ref: open.vault_ref.clone(),
                state: Ok(open),
            });
            s.unlocked.capacity = capacity;
        }
        self.refresh_storage_vault_labels();
        self.vault_select(id);
        self.vault.new_vault = None;
        if imported.is_some() {
            // Closing the dialog drops (and wipes) the backup.
            self.vault.import = None;
        }
        let reminder = backup_reminder(&name);
        let shown = match imported {
            None => reminder,
            Some(n) => format!("{} {reminder}", imported_line(&name, n, 0)),
        };
        self.vault_done(shown, format!("vault \"{name}\" created"));
        self.space_note("Vault", &capacity);
    }

    /// Ask before deleting the shown vault. A vault that can't be opened can
    /// be deleted too: it is the one way to clear it.
    pub(crate) fn vault_ask_delete_vault(&mut self) {
        let Some(v) = self.selected_vault() else {
            return;
        };
        let vault = v.vault_ref.clone();
        self.vault.confirm = Some(VaultConfirm::DeleteVault { vault });
        self.vault.scroll_to_confirm = true;
    }

    /// Ask before rotating the shown vault's key; only a vault that opened.
    pub(crate) fn vault_ask_rotate(&mut self) {
        if !self.vault_writable() {
            return;
        }
        let Some(v) = self.selected_vault() else {
            return;
        };
        let vault = v.vault_ref.clone();
        self.vault.confirm = Some(VaultConfirm::Rotate { vault });
        self.vault.scroll_to_confirm = true;
    }

    /// The waiting Delete vault or Rotate, taken once its Yes can run.
    /// `None` while a job runs: the question stays for the next try.
    pub(crate) fn vault_take_confirmed(&mut self) -> Option<VaultConfirm> {
        if !matches!(
            self.vault.confirm,
            Some(VaultConfirm::DeleteVault { .. } | VaultConfirm::Rotate { .. })
        ) {
            return None;
        }
        if self.refuse_if_busy() {
            return None;
        }
        self.vault.confirm.take()
    }

    /// Delete `vault` from the selected key: the session's PIN, no touch.
    pub(crate) fn vault_delete_vault(&mut self, vault: VaultRef) {
        if self.refuse_if_busy() {
            return;
        }
        let Some(target) = self.selected_fido_target() else {
            return;
        };
        let Some(auth) = self.vault_take_auth() else {
            return;
        };
        self.vault.error = None;
        self.vault.info = None;
        let shown = self.vault.progress.clone();
        let for_device = self.selected_device.clone();
        let queued = self.spawn_job("Deleting the vault\u{2026}", move || {
            let mut auth = auth;
            let result = {
                // A touch only on a key that lists no largeBlobKey for it.
                let mut touches = TouchProgress::new(shown, 1);
                open_vault_key(&target)
                    .and_then(|mut key| run_delete_vault(&mut key, &mut auth, &vault, &mut touches))
            };
            Box::new(move |app: &mut App| {
                app.vault_apply_delete_vault(for_device, auth, vault, result);
            })
        });
        if !queued {
            self.vault_not_started();
        }
    }

    /// The end of a vault delete: it leaves the list, the selection falls
    /// back to the first vault, and the space line takes the new numbers.
    pub(crate) fn vault_apply_delete_vault(
        &mut self,
        for_device: Option<DeviceId>,
        auth: VaultAuth,
        vault: VaultRef,
        result: Result<BlobCapacity, VaultJobError>,
    ) {
        if !completion_still_valid(for_device.as_ref(), self.selected_device.as_ref()) {
            return;
        }
        let Some(pin_from_fido) = self.vault_session().map(|s| s.pin_from_fido) else {
            return;
        };
        self.vault_give_back_auth(auth);
        let capacity = match result {
            Ok(capacity) => capacity,
            Err(e @ VaultJobError::DataRemoved { capacity, .. }) => {
                // The entries are gone from the key: the vault shows with no
                // data, as a new unlock would list it, until it is deleted.
                if let Some(s) = self.vault_session_mut() {
                    if let Some(open) = s
                        .vault_mut(&vault.credential_id)
                        .and_then(|v| v.state.as_mut().ok())
                    {
                        open.contents = Vault::default();
                        open.stored = false;
                    }
                    s.unlocked.capacity = capacity;
                }
                self.refresh_storage_vault_labels();
                self.vault.open_entry = None;
                self.vault.revealed = None;
                return self.vault_fail(&e);
            }
            Err(e) => return self.vault_job_failed(&e, pin_from_fido),
        };
        if let Some(s) = self.vault_session_mut() {
            s.unlocked
                .vaults
                .retain(|v| v.vault_ref.credential_id != vault.credential_id);
            s.unlocked.capacity = capacity;
        }
        self.refresh_storage_vault_labels();
        self.vault_fix_selection();
        let name = shown_name(vault.name.as_deref());
        self.vault_done(
            format!("Vault \"{name}\" deleted."),
            format!("vault \"{name}\" deleted"),
        );
    }

    /// Rotate `vault`'s key on the selected key: the session's PIN, two
    /// touches.
    pub(crate) fn vault_rotate(&mut self, vault: VaultRef) {
        if self.refuse_if_busy() {
            return;
        }
        let Some(target) = self.selected_fido_target() else {
            return;
        };
        let Some((auth, old)) = self.vault_take_for_save(&vault) else {
            // Gone from the session (a Refresh no longer lists it).
            self.vault.info = None;
            self.vault.error = Some(vault_error_text(&VaultKeyError::VaultGone {
                name: vault.name.clone(),
            }));
            return;
        };
        // Read again with the held secrets if the vault changed meanwhile.
        let Some(unlocked) = self.vault_session().map(|s| s.unlocked.clone()) else {
            return;
        };
        self.vault.error = None;
        self.vault.info = None;
        let shown = self.vault.progress.clone();
        let for_device = self.selected_device.clone();
        let queued = self.spawn_job("Rotating the vault key\u{2026}", move || {
            let mut auth = auth;
            let (result, reloaded) = {
                let mut touches = TouchProgress::new(shown, 2);
                match open_vault_key(&target) {
                    Err(e) => (Err(e), None),
                    Ok(mut key) => {
                        let r = run_rotate(&mut key, &mut auth, &old, &mut touches);
                        let reloaded = reload_after_rotate(&mut key, &r, unlocked);
                        (r.map_err(VaultJobError::from), reloaded)
                    }
                }
            };
            Box::new(move |app: &mut App| {
                app.vault_apply_rotate(for_device, auth, vault, result, reloaded);
            })
        });
        if !queued {
            self.vault_not_started();
        }
    }

    /// The end of a rotate: the new vault takes the old one's place in the
    /// list, and the selection follows it when the old one was shown. A
    /// rotate that left two copies on the key locks with which to delete. A
    /// rotate refused because the vault changed on the key meanwhile shows
    /// the vaults as `reloaded` read them (locks when that one is gone).
    pub(crate) fn vault_apply_rotate(
        &mut self,
        for_device: Option<DeviceId>,
        auth: VaultAuth,
        old: VaultRef,
        result: Result<Created, VaultJobError>,
        reloaded: Option<Reloaded>,
    ) {
        if !completion_still_valid(for_device.as_ref(), self.selected_device.as_ref()) {
            return;
        }
        let Some(pin_from_fido) = self.vault_session().map(|s| s.pin_from_fido) else {
            return;
        };
        self.vault_give_back_auth(auth);
        let Created { open, capacity } = match result {
            Ok(created) => created,
            Err(VaultJobError::Vault(e @ VaultKeyError::CreateUndone { left_over, .. }))
                if changed_during_rotate(&e) && !left_over.any() =>
            {
                return self.vault_rotate_changed(&old, reloaded);
            }
            Err(e) => return self.vault_job_failed(&e, pin_from_fido),
        };
        let n = open.contents.entries.len();
        let new_id = open.vault_ref.credential_id.clone();
        let was_shown = self
            .selected_vault()
            .is_some_and(|v| v.vault_ref.credential_id == old.credential_id);
        if let Some(s) = self.vault_session_mut() {
            let new = VaultOnKey {
                vault_ref: open.vault_ref.clone(),
                state: Ok(open),
            };
            match s.vault_mut(&old.credential_id) {
                Some(v) => *v = new,
                None => s.unlocked.vaults.push(new),
            }
            s.unlocked.capacity = capacity;
        }
        self.refresh_storage_vault_labels();
        if was_shown {
            // Same entries, same IDs: an opened entry stays open.
            self.vault.selected = Some(new_id);
        }
        let name = shown_name(old.name.as_deref());
        self.vault_done(
            format!(
                "Vault \"{name}\" rotated: a new vault holds its {} and the old one is deleted.",
                entries(n)
            ),
            format!("vault \"{name}\" rotated"),
        );
        self.space_note("Vault", &capacity);
    }

    /// A rotate of `old` refused (and cleanly undone) because the vault
    /// changed on the key since unlock: nothing was rotated, and the list
    /// takes what the key holds now (`reloaded`, read with no touch). A
    /// vault gone from the key, or a read that failed, locks.
    fn vault_rotate_changed(&mut self, old: &VaultRef, reloaded: Option<Reloaded>) {
        let text = changed_during_rotate_text(&shown_name(old.name.as_deref()));
        match reloaded {
            Some((unlocked, Ok(()))) => {
                let text = format!("{text} {ROTATE_AGAIN}");
                self.log(Severity::Warn, format!("Vault: {text}"));
                if let Some(s) = self.vault_session_mut() {
                    s.unlocked = unlocked;
                }
                self.refresh_storage_vault_labels();
                self.vault_fix_selection();
                self.vault.info = None;
                self.vault.error = Some(text);
            }
            // Locked: only a new unlock shows the vault now.
            Some((_, Err(e))) => {
                let why = with_unlock_again(&format!("{text} {}", job_error_text(&e)));
                self.log(Severity::Err, format!("Vault: {why}"));
                self.vault_lock(Some(why));
            }
            None => {
                let why = with_unlock_again(&text);
                self.log(Severity::Err, format!("Vault: {why}"));
                self.vault_lock(Some(why));
            }
        }
    }

    /// A create, delete, rotate or save that failed. What left the list stale
    /// locks the vault (only a new unlock lists what the key holds now): a
    /// vault gone elsewhere, a failed create that left something behind, a
    /// rotate that left two copies. A refused PIN locks it too, so no retry
    /// spends another of the key's PIN tries; on a fingerprint session the
    /// refused token is [`FINGER_UNLOCK_REFUSED`]. Anything else is said,
    /// and the session stays.
    fn vault_job_failed(&mut self, e: &VaultJobError, pin_from_fido: bool) {
        let stale = matches!(
            e,
            VaultJobError::Vault(
                VaultKeyError::VaultGone { .. } | VaultKeyError::OldNotDeleted { .. }
            )
        ) || matches!(
            e,
            VaultJobError::Vault(VaultKeyError::CreateUndone { left_over, .. }) if left_over.any()
        );
        if stale {
            let text = job_error_text(e);
            self.log(Severity::Err, format!("Vault: {text}"));
            self.vault_lock(Some(text));
        } else if pin_refused(e)
            && self
                .vault_session()
                .is_some_and(|s| s.verified == Some(Verified::Fingerprint))
        {
            // No PIN was ever typed: say the finger's unlock ended. The
            // FIDO2 tab took no part in it, so it stays.
            self.vault_fail_finger_refused();
            let why = self.vault.error.take();
            self.vault_lock(why);
        } else if pin_refused(e) {
            self.vault_fail(e);
            let why = self.vault.error.take();
            self.vault_lock(why);
            if pin_from_fido {
                self.relock_fido_session();
            }
        } else {
            self.vault_fail(e);
        }
    }
}

impl App {
    /// The confirmation card of a waiting Delete vault or Rotate, under the
    /// card its button is on: the CLI's question. A vault no longer listed
    /// (a Refresh) drops it.
    fn render_vault_action_confirm(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let (vault, rotate) = match &self.vault.confirm {
            Some(VaultConfirm::DeleteVault { vault }) => (vault.clone(), false),
            Some(VaultConfirm::Rotate { vault }) => (vault.clone(), true),
            _ => return,
        };
        if self.session_vault(&vault.credential_id).is_none() {
            self.vault.confirm = None;
            return;
        }
        let key = self.vault_key_title();
        let name = shown_name(vault.name.as_deref());
        let (question, note, yes, kind, color) = if rotate {
            (
                rotate_question(&name, &key),
                "This asks for two touches.",
                "Rotate vault key",
                BtnKind::Primary,
                p.txt,
            )
        } else {
            (
                delete_vault_question(&name, &key),
                DELETE_VAULT_NOTE,
                "Delete vault",
                BtnKind::Danger,
                p.err,
            )
        };
        let waiting = self.waiting_for().map(str::to_owned);
        let writable = self.vault_writable();
        let (mut confirm, mut cancel, mut export) = (false, false, false);
        ui.add_space(10.0);
        let card = theme::card_frame(p).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.colored_label(color, question);
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(note)
                    .font(theme::f_reg(11.5))
                    .color(p.txt3),
            );
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                // A delete offers the backup first.
                if !rotate {
                    if writable {
                        export = theme::button(ui, p, BtnKind::Default, EXPORT_BUTTON).clicked();
                    } else {
                        theme::button_disabled(ui, p, EXPORT_BUTTON);
                    }
                    ui.add_space(6.0);
                }
                confirm = theme::key_button(ui, p, kind, yes, waiting.as_deref()).clicked();
                ui.add_space(6.0);
                cancel = theme::button(ui, p, BtnKind::Default, "Cancel").clicked();
            });
        });
        // Asked just now: bring it into view (it may sit below the fold).
        if std::mem::take(&mut self.vault.scroll_to_confirm) {
            card.response.scroll_to_me(Some(egui::Align::Center));
        }
        if export {
            self.vault_export_start();
        } else if confirm {
            match self.vault_take_confirmed() {
                Some(VaultConfirm::DeleteVault { vault }) => self.vault_delete_vault(vault),
                Some(VaultConfirm::Rotate { vault }) => self.vault_rotate(vault),
                Some(VaultConfirm::DeleteEntry { .. }) | None => {}
            }
        } else if cancel {
            self.vault.confirm = None;
        }
    }

    /// The confirmation card of a waiting delete (ftotp's shape): the CLI's
    /// question, no touch (the session's PIN does it).
    fn render_vault_confirm(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let Some(VaultConfirm::DeleteEntry { vault, entry_id }) = self.vault.confirm.as_ref()
        else {
            return;
        };
        let (vault, entry_id) = (vault.clone(), entry_id.clone());
        let Some(entry) = self.vault_entry(&vault, &entry_id) else {
            // Gone from the list (a Refresh): nothing left to ask about.
            self.vault.confirm = None;
            return;
        };
        let key = self.vault_key_title();
        let name = self.vault_entry_name(&vault, &entry);
        let question = delete_entry_question(&name, &shown_name(vault.name.as_deref()), &key);
        let waiting = self.waiting_for().map(str::to_owned);
        let mut confirm = false;
        let mut cancel = false;
        let card = theme::card_frame(p).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.colored_label(p.err, question);
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new("This cannot be undone.")
                    .font(theme::f_reg(11.5))
                    .color(p.txt3),
            );
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if theme::key_button(ui, p, BtnKind::Danger, "Delete", waiting.as_deref()).clicked()
                {
                    confirm = true;
                }
                ui.add_space(6.0);
                if theme::button(ui, p, BtnKind::Default, "Cancel").clicked() {
                    cancel = true;
                }
            });
        });
        // Asked just now: bring it into view (it may sit below the fold).
        if std::mem::take(&mut self.vault.scroll_to_confirm) {
            card.response.scroll_to_me(Some(egui::Align::Center));
        }
        ui.add_space(10.0);
        if confirm {
            self.vault_confirm_delete_entry();
        } else if cancel {
            self.vault.confirm = None;
        }
    }

    /// The add / edit form (the mockup's): Title, Username, Password with
    /// Show and Generate, the generator's settings behind `change`, URL and
    /// Notes, then Cancel / Save. Cancel waits for a running save, so its
    /// end finds the form it reports on.
    fn render_entry_form(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let busy = self.busy();
        let waiting = self.waiting_for().map(str::to_owned);
        let Some(mut form) = self.vault.form.take() else {
            return;
        };
        let mut gen = std::mem::take(&mut self.vault.gen);
        let mut gen_open = self.vault.gen_open;
        let (mut generate, mut cancel, mut save) = (false, false, false);
        let name = shown_name(form.vault.name.as_deref());
        let heading = match form.editing {
            Some(_) => format!("Edit entry in \"{name}\""),
            None => format!("Add entry to \"{name}\""),
        };
        const LABEL_W: f32 = 90.0;
        theme::card_frame(p).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.label(
                egui::RichText::new(heading)
                    .font(theme::f_sb(14.5))
                    .color(p.txt),
            );
            ui.add_space(8.0);
            let label = |ui: &mut egui::Ui, text: &str| {
                ui.add_sized(
                    [LABEL_W, 24.0],
                    egui::Label::new(
                        egui::RichText::new(text)
                            .font(theme::f_reg(12.5))
                            .color(p.txt2),
                    ),
                );
            };
            fn line<'a>(text: &'a mut String, hint: &'static str) -> egui::TextEdit<'a> {
                egui::TextEdit::singleline(text)
                    .margin(theme::TEXT_EDIT_MARGIN)
                    .desired_width(f32::INFINITY)
                    .hint_text(hint)
            }
            ui.horizontal(|ui| {
                label(ui, "Title");
                ui.add(line(&mut form.title, ""));
            });
            ui.horizontal(|ui| {
                label(ui, "Username");
                ui.add(line(&mut form.username, ""));
            });
            ui.horizontal(|ui| {
                label(ui, "Password");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    generate = theme::button(ui, p, BtnKind::Ghost, "Generate").clicked();
                    let show = if form.show_password { "Hide" } else { "Show" };
                    if theme::button(ui, p, BtnKind::Ghost, show).clicked() {
                        form.show_password = !form.show_password;
                    }
                    let masked = !form.show_password;
                    let resp = ui.add(line(&mut form.password, "").password(masked));
                    guard_secret_field(ui.ctx(), &resp);
                });
            });
            ui.horizontal(|ui| {
                ui.add_space(LABEL_W + ui.spacing().item_spacing.x);
                ui.label(
                    egui::RichText::new(gen_summary(&gen))
                        .font(theme::f_reg(11.5))
                        .color(p.txt3),
                );
                if ui
                    .link(egui::RichText::new("change").font(theme::f_reg(11.5)))
                    .clicked()
                {
                    gen_open = !gen_open;
                }
            });
            if gen_open {
                ui.horizontal_wrapped(|ui| {
                    ui.add_space(LABEL_W + ui.spacing().item_spacing.x);
                    ui.add(
                        egui::DragValue::new(&mut gen.length)
                            .range(4..=128)
                            .suffix(" characters"),
                    );
                    ui.checkbox(&mut gen.upper, "A\u{2013}Z");
                    ui.checkbox(&mut gen.lower, "a\u{2013}z");
                    ui.checkbox(&mut gen.digits, "0\u{2013}9");
                    ui.checkbox(&mut gen.symbols, "symbols");
                });
            }
            ui.horizontal(|ui| {
                label(ui, "URL");
                ui.add(line(&mut form.url, "optional"));
            });
            ui.horizontal_top(|ui| {
                label(ui, "Notes");
                let resp = ui.add(
                    egui::TextEdit::multiline(&mut form.notes)
                        .margin(theme::TEXT_EDIT_MARGIN)
                        .desired_rows(3)
                        .desired_width(f32::INFINITY)
                        .hint_text("optional"),
                );
                guard_secret_field(ui.ctx(), &resp);
            });
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.add_space(LABEL_W + ui.spacing().item_spacing.x);
                ui.label(
                    egui::RichText::new(
                        "Saving writes the vault back to the key (already unlocked; no touch \
                         needed).",
                    )
                    .font(theme::f_reg(11.5))
                    .color(p.txt3),
                );
            });
            if let Some(notice) = &form.notice {
                ui.add_space(6.0);
                ui.colored_label(p.warn, notice);
            }
            ui.add_space(8.0);
            right_row(ui, 32.0, |ui| {
                save = theme::key_button(ui, p, BtnKind::Primary, "Save", waiting.as_deref())
                    .clicked();
                if busy {
                    theme::button_disabled(ui, p, "Cancel");
                } else {
                    cancel = theme::button(ui, p, BtnKind::Default, "Cancel").clicked();
                }
            });
        });
        self.vault.gen = gen;
        self.vault.gen_open = gen_open;
        self.vault.form = Some(form);
        if generate {
            self.vault_generate();
        }
        if cancel {
            self.vault_cancel_form();
        } else if save {
            self.vault_save_form();
        }
    }
}

/// A Repeat box that differs from the Passphrase box.
const PASSPHRASES_DIFFER: &str = "the two passphrases don't match";

/// Under the backup's passphrase boxes.
const PASSPHRASE_NOTE: &str = "At least 10 characters. Without it, the backup can't be opened.";

/// The button that backs the shown vault up to a file.
pub(crate) const EXPORT_BUTTON: &str = "Export backup\u{2026}";

/// Export backup… pressed while the save dialog of an earlier one is
/// still open.
fn backup_pending_text(vault: &VaultRef) -> String {
    format!(
        "A backup of vault \"{}\" is already being saved: finish or cancel its save dialog first.",
        shown_name(vault.name.as_deref())
    )
}

/// The busy label while a backup is encrypted and written.
const EXPORT_LABEL: &str = "Writing backup\u{2026}";

/// A save dialog opened before a lock chose a file while a backup of
/// another vault waits for its own dialog: that file isn't used.
const EXPORT_OTHER_VAULT: &str =
    "The file chosen was for a backup of another vault, so nothing was written to it.";

/// Write backup's job couldn't be queued; the dialog stays as it was.
const EXPORT_NOT_STARTED: &str = "Writing the backup couldn't start; press Write backup again.";

/// The passphrase dialog of Export backup…, for the file the save dialog
/// chose. Both boxes are secrets: Write backup, Cancel, Lock and the idle
/// lock wipe them.
pub(crate) struct ExportDialog {
    /// The vault backed up, found by credential ID.
    pub(crate) vault: VaultRef,
    /// The file the save dialog chose (it already asked about replacing one).
    pub(crate) path: PathBuf,
    pub(crate) passphrase: String,
    pub(crate) repeat: String,
}

impl TypedSecrets for ExportDialog {
    fn secrets_mut(&mut self) -> Vec<&mut String> {
        let Self {
            vault: _,
            path: _,
            passphrase,
            repeat,
        } = self;
        vec![passphrase, repeat]
    }
}

impl Drop for ExportDialog {
    fn drop(&mut self) {
        self.wipe_typed();
    }
}

/// The two passphrase boxes agree and the passphrase is one a backup takes;
/// otherwise what to say, before anything is encrypted or written.
pub(crate) fn check_export_passphrase(passphrase: &str, repeat: &str) -> Result<(), String> {
    if passphrase != repeat {
        return Err(PASSPHRASES_DIFFER.to_owned());
    }
    check_passphrase(passphrase).map_err(|e| e.to_string())
}

/// Encrypt `contents` under `passphrase` into a backup file at `path`; the
/// number of entries it holds. Runs on the worker: Argon2id takes a moment.
pub(crate) fn write_backup(
    contents: &Vault,
    passphrase: &str,
    path: &Path,
) -> Result<usize, String> {
    let bytes = export_backup(contents, passphrase).map_err(|e| e.to_string())?;
    write_backup_file(path, &bytes)?;
    Ok(contents.entries.len())
}

/// Write an encrypted backup with the CLI's owner-only writer, replacing a
/// file already there (the save dialog asked) but never writing through a
/// link; the CLI's `cannot write FILE: ERROR` when it can't.
fn write_backup_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    write_private_file(path, bytes, OutMode::Replace).map_err(|e| {
        format!(
            "cannot write {}: {e}",
            sanitize_title(&path.display().to_string())
        )
    })
}

/// Export backup…: a passphrase-protected backup file of the shown vault,
/// as `fido vault export` writes it. No key is used: the vault is the one
/// the session holds.
impl App {
    /// Export backup…: ask where to save the shown vault's backup. Only a
    /// vault that opened; the chosen file opens [`ExportDialog`].
    pub(crate) fn vault_export_start(&mut self) {
        if !self.vault_writable() {
            return;
        }
        // One backup at a time: a second save dialog's file would find
        // nothing waiting for it.
        if let Some(pending) = self.vault.export_for.as_ref() {
            self.vault.info = None;
            self.vault.error = Some(backup_pending_text(pending));
            return;
        }
        let Some(v) = self.selected_vault() else {
            return;
        };
        let vault = v.vault_ref.clone();
        let file = backup_file_name(vault.name.as_deref().unwrap_or_default());
        let target = FileTarget::VaultExport {
            credential_id: vault.credential_id.clone(),
            device: self.selected_device.clone(),
        };
        self.vault.export_for = Some(vault);
        self.spawn_file_dialog(target, true, &[("Vault backup", &["t2vault"])], Some(&file));
    }

    /// Whether the backup waiting for a file is the one a save dialog was
    /// opened for: vault `credential_id` on key `device`.
    fn vault_export_waits_for(&self, credential_id: &[u8], device: Option<&DeviceId>) -> bool {
        self.selected_device.as_ref() == device
            && self
                .vault
                .export_for
                .as_ref()
                .is_some_and(|v| v.credential_id == credential_id)
    }

    /// The save dialog for vault `credential_id` on key `device` chose
    /// `path`: the passphrase dialog for that vault. Nothing when no backup
    /// waits (a lock or another key in the meantime rebuilt the tab's
    /// state); a backup of another vault waiting (Export backup… pressed
    /// again after a lock) keeps waiting, and the file isn't used for it.
    pub(crate) fn vault_export_chosen(
        &mut self,
        path: PathBuf,
        credential_id: &[u8],
        device: Option<&DeviceId>,
    ) {
        if !self.vault_export_waits_for(credential_id, device) {
            if self.vault.export_for.is_some() {
                self.vault.info = None;
                self.vault.error = Some(EXPORT_OTHER_VAULT.to_owned());
            }
            return;
        }
        let Some(vault) = self.vault.export_for.take() else {
            return;
        };
        if self.vault_session().is_none() {
            return;
        }
        self.vault.error = None;
        self.vault.info = None;
        self.vault.export = Some(ExportDialog {
            vault,
            path,
            passphrase: String::new(),
            repeat: String::new(),
        });
    }

    /// The save dialog for vault `credential_id` on key `device` was
    /// cancelled: that backup no longer waits. One waiting for another
    /// vault's dialog still does.
    pub(crate) fn vault_export_dismissed(
        &mut self,
        credential_id: &[u8],
        device: Option<&DeviceId>,
    ) {
        if self.vault_export_waits_for(credential_id, device) {
            self.vault.export_for = None;
        }
    }

    /// Cancel: the dialog closes and its boxes are wiped.
    pub(crate) fn vault_export_cancel(&mut self) {
        self.vault.export = None;
    }

    /// The vault's contents as the session last read them, for a backup;
    /// what to say when it is no longer there to back up.
    fn vault_export_contents(&self, vault: &VaultRef) -> Result<Vault, String> {
        let name = shown_name(vault.name.as_deref());
        let v = self.session_vault(&vault.credential_id).ok_or_else(|| {
            format!("Vault \"{name}\" is no longer on this key; nothing was written.")
        })?;
        match &v.state {
            Ok(open) => Ok(open.contents.clone()),
            Err(_) => Err(format!(
                "Vault \"{name}\" can't be opened, so it can't be backed up; nothing was written."
            )),
        }
    }

    /// Write backup: the passphrase is checked first (a mismatch or a short
    /// one writes nothing), then a job encrypts the vault as the session
    /// holds it and writes the file. No key, no touch.
    pub(crate) fn vault_export(&mut self) {
        let Some(d) = self.vault.export.as_ref() else {
            return;
        };
        if let Err(e) = check_export_passphrase(&d.passphrase, &d.repeat) {
            self.vault.info = None;
            self.vault.error = Some(as_sentence(&e));
            return;
        }
        let (vault, path) = (d.vault.clone(), d.path.clone());
        let name = shown_name(vault.name.as_deref());
        let file = sanitize_title(&path.display().to_string());
        let passphrase = Zeroizing::new(d.passphrase.clone());
        let contents = match self.vault_export_contents(&vault) {
            Ok(c) => c,
            Err(e) => {
                self.vault.export = None;
                self.vault.info = None;
                self.vault.error = Some(e);
                return;
            }
        };
        if self.refuse_if_busy() {
            return;
        }
        self.vault.error = None;
        self.vault.info = None;
        let for_device = self.selected_device.clone();
        let queued = self.spawn_job(EXPORT_LABEL, move || {
            let result = write_backup(&contents, &passphrase, &path);
            drop((contents, passphrase));
            Box::new(move |app: &mut App| app.vault_apply_export(for_device, name, file, result))
        });
        if !queued {
            self.vault.error = Some(EXPORT_NOT_STARTED.to_owned());
        }
    }

    /// The end of Write backup for vault `name` (as shown) and `file`:
    /// written closes the dialog (wiping it) with the CLI's line; a failure
    /// keeps it open with the reason. Either way the activity log says so,
    /// even when the dialog is gone (the vault locked, or another key was
    /// selected, while the file was written): the file is there or not
    /// whatever the pane shows now.
    pub(crate) fn vault_apply_export(
        &mut self,
        for_device: Option<DeviceId>,
        name: String,
        file: String,
        result: Result<usize, String>,
    ) {
        let (severity, logged) = match &result {
            Ok(_) => (
                Severity::Ok,
                format!("Vault: backup of vault \"{name}\" written to {file}"),
            ),
            Err(e) => (
                Severity::Err,
                format!("Vault: backup of vault \"{name}\" not written: {e}"),
            ),
        };
        if !completion_still_valid(for_device.as_ref(), self.selected_device.as_ref())
            || self.vault.export.is_none()
        {
            // Not under the key now selected: the backup isn't of it.
            self.log_global(severity, crate::LogKind::User, logged);
            return;
        }
        self.log(severity, logged);
        match result {
            Ok(n) => {
                self.vault.export = None;
                self.vault.error = None;
                self.vault.info = Some(format!(
                    "Backup of vault \"{name}\" ({}) written to {file}.",
                    entries(n)
                ));
            }
            Err(e) => {
                self.vault.info = None;
                self.vault.error = Some(as_sentence(&e));
            }
        }
    }

    /// The backup's passphrase dialog: which vault, the chosen file, the
    /// passphrase twice (masked), then Write backup / Cancel. Cancel waits
    /// for a running write, so its end finds the dialog it reports on.
    fn render_export_dialog(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let busy = self.busy();
        let Some(d) = self.vault.export.as_mut() else {
            return;
        };
        let (mut write, mut cancel) = (false, false);
        const LABEL_W: f32 = 90.0;
        theme::card_frame(p).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.label(
                egui::RichText::new(format!(
                    "Back up vault \"{}\"",
                    shown_name(d.vault.name.as_deref())
                ))
                .font(theme::f_sb(14.5))
                .color(p.txt),
            );
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(sanitize_title(&d.path.display().to_string()))
                    .font(theme::f_reg(12.5))
                    .color(p.txt2),
            );
            ui.add_space(8.0);
            let secret_row = |ui: &mut egui::Ui, label: &str, text: &mut String| {
                ui.horizontal(|ui| {
                    ui.add_sized(
                        [LABEL_W, 24.0],
                        egui::Label::new(
                            egui::RichText::new(label)
                                .font(theme::f_reg(12.5))
                                .color(p.txt2),
                        ),
                    );
                    let resp = ui.add(
                        egui::TextEdit::singleline(text)
                            .margin(theme::TEXT_EDIT_MARGIN)
                            .desired_width(f32::INFINITY)
                            .password(true),
                    );
                    guard_secret_field(ui.ctx(), &resp);
                });
            };
            secret_row(ui, "Passphrase", &mut d.passphrase);
            secret_row(ui, "Repeat", &mut d.repeat);
            ui.horizontal(|ui| {
                ui.add_space(LABEL_W + ui.spacing().item_spacing.x);
                ui.label(
                    egui::RichText::new(PASSPHRASE_NOTE)
                        .font(theme::f_reg(11.5))
                        .color(p.txt3),
                );
            });
            ui.add_space(8.0);
            right_row(ui, 32.0, |ui| {
                write = theme::button(ui, p, BtnKind::Primary, "Write backup").clicked();
                if busy {
                    theme::button_disabled(ui, p, "Cancel");
                } else {
                    cancel = theme::button(ui, p, BtnKind::Default, "Cancel").clicked();
                }
            });
        });
        if cancel {
            self.vault_export_cancel();
        } else if write {
            self.vault_export();
        }
    }
}

/// The CLI's line after an import wrote.
fn imported_line(vault: &str, added: usize, replaced: usize) -> String {
    format!("Imported into vault \"{vault}\": {added} added, {replaced} replaced.")
}

/// Under the button of an import into a new vault before it has a name.
const IMPORT_NAME_NEEDED: &str = "Type a name for the new vault.";

/// The button that imports a backup file.
const IMPORT_BUTTON: &str = "Import backup\u{2026}";

/// The busy label while a backup is read and decrypted.
const IMPORT_OPEN_LABEL: &str = "Opening backup\u{2026}";

/// The largest backup file read: the CLI's limit.
const MAX_BACKUP_BYTES: usize = keyroost_qr::file::MAX_FILE_BYTES;

/// An import refused because an entry it touches changed on the key.
const IMPORT_CHANGED_ON_KEY: &str = "An entry in this vault changed on the key since it was \
                                     opened; nothing was written. The list below shows the vault \
                                     as it is now.";

/// A Refresh found the import's target vault changed on the key.
const IMPORT_REFRESHED: &str = "An entry in this vault changed on the key since the backup was \
                                opened. The list below now compares with the vault as it is; \
                                check the ticks before importing.";

/// Open backup couldn't be queued.
const IMPORT_OPEN_NOT_STARTED: &str = "Opening the backup couldn't start; press Open backup again.";

/// Import backup… pressed while the open dialog of an earlier one is up.
const IMPORT_PENDING: &str =
    "A backup file is already being chosen: finish or cancel that dialog first.";

/// A row left unticked.
const NOT_TICKED: &str = "not ticked";
/// The backup's copy was changed later than the key's.
const NEWER: &str = "the backup's copy is newer";
/// The key's copy was changed later: left alone unless ticked.
const OLDER: &str = "the key's copy is newer (tick it to replace it)";
/// The key's newer copy, ticked to be replaced.
const OLDER_TAKEN: &str = "replaces the key's newer copy";
/// An entry the vault already holds as it is.
const SAME: &str = "already in the vault; left as is";
/// A comparison this build doesn't know (the CLI's words).
const UNKNOWN_STATUS: &str = "this build can't tell how it compares";

/// Where an import writes: a vault on the key (by credential ID), or a new
/// vault it creates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ImportTarget {
    Existing(VaultRef),
    New,
}

/// One backup entry in the import preview: how it compares with the
/// target vault and whether it is ticked. Holds no entry text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ImportRow {
    /// Its place in the backup, from 0.
    pub index: usize,
    pub status: ImportStatus,
    pub ticked: bool,
}

/// Whether a row has a box: a new entry, or one whose copies differ. An
/// entry already in the vault, or a comparison this build doesn't know,
/// has none.
pub(crate) fn has_box(s: ImportStatus) -> bool {
    matches!(
        s,
        ImportStatus::New | ImportStatus::Newer | ImportStatus::Older
    )
}

/// Pre-ticked: the rows the CLI takes by default (add and replace).
pub(crate) fn default_tick(s: ImportStatus) -> bool {
    matches!(s, ImportStatus::New | ImportStatus::Newer)
}

/// What the import does with a row, and why: the CLI's plan words
/// (`add`, `replace`, `exists`, `skip`) and reasons, with the app's ticks
/// in place of `--replace` and `--entry`.
pub(crate) fn plan_of(s: ImportStatus, ticked: bool) -> (&'static str, Option<&'static str>) {
    match (s, ticked) {
        (ImportStatus::New, true) => ("add", None),
        (ImportStatus::Newer, true) => ("replace", Some(NEWER)),
        (ImportStatus::Older, true) => ("replace", Some(OLDER_TAKEN)),
        (ImportStatus::New | ImportStatus::Newer, false) => ("skip", Some(NOT_TICKED)),
        (ImportStatus::Older, false) => ("skip", Some(OLDER)),
        (ImportStatus::Same, _) => ("exists", Some(SAME)),
        _ => ("skip", Some(UNKNOWN_STATUS)),
    }
}

/// The plan of `r`; a row with no box counts as unticked.
fn row_plan(r: &ImportRow) -> (&'static str, Option<&'static str>) {
    plan_of(r.status, r.ticked && has_box(r.status))
}

/// The backup indices the import writes: its ticked `add` and `replace`
/// rows.
pub(crate) fn chosen(rows: &[ImportRow]) -> Vec<usize> {
    rows.iter()
        .filter(|r| matches!(row_plan(r).0, "add" | "replace"))
        .map(|r| r.index)
        .collect()
}

/// The CLI's summary line under the preview; `on_key` entries are in the
/// target vault now.
pub(crate) fn import_summary(rows: &[ImportRow], on_key: usize) -> String {
    let count = |w: &str| rows.iter().filter(|r| row_plan(r).0 == w).count();
    format!(
        "{} in the vault; {} will be added, {} replaced, {} left as is, {} skipped.",
        entries(on_key),
        count("add"),
        count("replace"),
        count("exists"),
        count("skip")
    )
}

/// The preview's rows for `incoming` against `current` (`None`: a new
/// vault, where every entry is new), with the default ticks.
fn preview_rows(current: Option<&Vault>, incoming: &Vault) -> Vec<ImportRow> {
    let statuses = match current {
        Some(current) => classify(current, incoming),
        None => (0..incoming.entries.len())
            .map(|i| (i, ImportStatus::New))
            .collect(),
    };
    statuses
        .into_iter()
        .map(|(index, status)| ImportRow {
            index,
            status,
            ticked: default_tick(status),
        })
        .collect()
}

/// A backup entry as its preview row names it: `title (username) · host`,
/// empty parts left out (the code imports' `title (username)`, with the
/// URL's host so two entries titled alike can be told apart). Never an ID.
fn import_row_name(e: &Entry) -> Zeroizing<String> {
    let mut s = Zeroizing::new(String::with_capacity(
        e.title.len() + e.username.len() + e.url.len() + 8,
    ));
    push_flat(&mut s, &e.title);
    if !e.username.trim().is_empty() {
        s.push_str(" (");
        push_flat(&mut s, &e.username);
        s.push(')');
    }
    let host = url_host(&e.url);
    if !host.trim().is_empty() {
        s.push_str(" \u{00B7} ");
        push_flat(&mut s, host);
    }
    s
}

/// Entry `e` of `v` named so it can't be taken for another: its title when
/// no other entry has it, else with its username, and its host too when
/// that still leaves two alike (the row's words). Wiped: the username is
/// private.
fn entry_shown_name(v: &Vault, e: &Entry) -> Zeroizing<String> {
    let alike = |same: &dyn Fn(&Entry) -> bool| v.entries.iter().filter(|o| same(o)).count() > 1;
    if !alike(&|o| o.title == e.title) {
        let mut s = Zeroizing::new(String::with_capacity(e.title.len()));
        push_flat(&mut s, &e.title);
        return s;
    }
    if !e.username.trim().is_empty() && !alike(&|o| o.title == e.title && o.username == e.username)
    {
        let mut s = Zeroizing::new(String::with_capacity(e.title.len() + e.username.len() + 3));
        push_flat(&mut s, &e.title);
        s.push_str(" (");
        push_flat(&mut s, &e.username);
        s.push(')');
        return s;
    }
    import_row_name(e)
}

/// A file's name as the preview names it.
fn file_label(path: &Path) -> String {
    sanitize_title(&path.file_name().map_or_else(
        || path.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    ))
}

/// A backup file's bytes, in a wiped buffer, refused past
/// [`MAX_BACKUP_BYTES`] (the CLI's words).
fn read_backup_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
    use std::io::Read;
    let read_err = |e: std::io::Error| format!("cannot read {}: {e}", path.display());
    let f = std::fs::File::open(path).map_err(read_err)?;
    // Sized up front, so the buffer isn't grown (and copied) while it fills.
    let len = f.metadata().map_or(0, |m| m.len());
    let cap = usize::try_from(len)
        .unwrap_or(MAX_BACKUP_BYTES)
        .min(MAX_BACKUP_BYTES)
        + 1;
    let mut bytes = Zeroizing::new(Vec::with_capacity(cap));
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

/// Read and decrypt the backup at `path`: its entries, or what to say.
/// Runs on the worker (Argon2id takes a moment); the file's bytes are wiped
/// once read. A backup listing one ID twice is refused (the crate's check).
pub(crate) fn open_backup(path: &Path, passphrase: &str) -> Result<Vault, String> {
    let bytes = read_backup_file(path)?;
    import_backup(&bytes, passphrase).map_err(|e| e.to_string())
}

/// The import dialog of Import backup…: the passphrase, then a preview of
/// every backup entry, each ticked or not. The passphrase box is a secret;
/// the opened backup's entries wipe themselves when dropped (Import, Cancel,
/// Lock, the idle lock).
pub(crate) struct ImportDialog {
    /// The file the open dialog chose.
    pub path: PathBuf,
    pub passphrase: String,
    pub target: ImportTarget,
    /// The new vault's name when `target` is [`ImportTarget::New`]. Not a
    /// secret: vault names are listed without unlocking.
    pub new_name: String,
    /// The backup's entries, once opened.
    pub incoming: Option<Vault>,
    /// One per backup entry, in the backup's order.
    pub rows: Vec<ImportRow>,
    /// What the dialog says: a backup that didn't open, an import refused.
    pub notice: Option<String>,
}

impl ImportDialog {
    pub(crate) fn new(path: PathBuf, target: ImportTarget, new_name: String) -> Self {
        Self {
            path,
            passphrase: String::new(),
            target,
            new_name,
            incoming: None,
            rows: Vec::new(),
            notice: None,
        }
    }
}

impl TypedSecrets for ImportDialog {
    fn secrets_mut(&mut self) -> Vec<&mut String> {
        let Self {
            path: _,
            passphrase,
            target: _,
            new_name: _,
            // The opened entries wipe themselves when the dialog drops.
            incoming: _,
            rows: _,
            notice: _,
        } = self;
        vec![passphrase]
    }
}

impl Drop for ImportDialog {
    fn drop(&mut self) {
        self.wipe_typed();
    }
}

/// What the preview's button starts.
pub(crate) enum ImportJob {
    /// Into a vault on the key: the one save path, no touch. The change
    /// (the whole backup) is boxed: it is far larger than a create.
    Save {
        vault: VaultRef,
        kind: SaveKind,
        change: Box<Change>,
    },
    /// Into a new vault: created holding the ticked entries, two touches.
    Create {
        name: String,
        auth: VaultAuth,
        initial: Vault,
    },
}

/// Import backup…: a backup file's entries into a vault, each one ticked
/// or not, as `fido vault import` plans them.
impl App {
    /// Import backup…: ask which file to open. Not for a vault that can't
    /// be opened; a key with no vault imports into a new one.
    pub(crate) fn vault_import_start(&mut self) {
        if self.vault_session().is_none() {
            return;
        }
        if self.selected_vault().is_some() && !self.vault_writable() {
            return;
        }
        if self.vault.import_asked {
            self.vault.info = None;
            self.vault.error = Some(IMPORT_PENDING.to_owned());
            return;
        }
        self.vault.import_asked = true;
        self.spawn_file_dialog(
            FileTarget::VaultImport,
            false,
            &[("Vault backup", &["t2vault"])],
            None,
        );
    }

    /// The open dialog chose `path`: the import dialog, into the shown
    /// vault, or into a new vault named after the file when the key has
    /// none. Nothing when the tab was locked or rebuilt meanwhile.
    pub(crate) fn vault_import_chosen(&mut self, path: PathBuf) {
        if !std::mem::take(&mut self.vault.import_asked) || self.vault_session().is_none() {
            return;
        }
        let shown = self
            .selected_vault()
            .filter(|v| v.state.is_ok())
            .map(|v| v.vault_ref.clone());
        let (target, new_name) = match shown {
            Some(v) => (ImportTarget::Existing(v), String::new()),
            None => (
                ImportTarget::New,
                path.file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default(),
            ),
        };
        self.vault.error = None;
        self.vault.info = None;
        self.vault.import = Some(ImportDialog::new(path, target, new_name));
    }

    /// Cancel: the dialog closes; its passphrase and the backup's entries
    /// are wiped.
    pub(crate) fn vault_import_cancel(&mut self) {
        self.vault.import = None;
    }

    /// Open backup: read and decrypt the file with the typed passphrase.
    /// No key: a wrong passphrase fails before the key is used.
    pub(crate) fn vault_import_open(&mut self) {
        let Some(d) = self.vault.import.as_mut() else {
            return;
        };
        if d.passphrase.is_empty() || d.incoming.is_some() {
            return;
        }
        d.notice = None;
        let path = d.path.clone();
        let passphrase = Zeroizing::new(d.passphrase.clone());
        let for_device = self.selected_device.clone();
        let queued = self.spawn_job(IMPORT_OPEN_LABEL, move || {
            let result = open_backup(&path, &passphrase);
            drop(passphrase);
            Box::new(move |app: &mut App| app.vault_apply_import_open(for_device, result))
        });
        if !queued {
            if let Some(d) = self.vault.import.as_mut() {
                d.notice = Some(IMPORT_OPEN_NOT_STARTED.to_owned());
            }
        }
    }

    /// The end of Open backup. A result for another key, or one whose
    /// dialog is gone, is dropped (and wiped). Opened: the passphrase box is
    /// wiped and the preview shows; otherwise the dialog says why.
    pub(crate) fn vault_apply_import_open(
        &mut self,
        for_device: Option<DeviceId>,
        result: Result<Vault, String>,
    ) {
        if !completion_still_valid(for_device.as_ref(), self.selected_device.as_ref())
            || self.vault_session().is_none()
        {
            return;
        }
        let Some(d) = self.vault.import.as_mut() else {
            return;
        };
        match result {
            Ok(incoming) => {
                wipe(&mut d.passphrase);
                d.incoming = Some(incoming);
                d.notice = None;
                self.vault_import_classify();
            }
            Err(e) => d.notice = Some(as_sentence(&e)),
        }
    }

    /// The target vault's contents as the session holds them; `None` for a
    /// new vault. `Err`, what to say, when that vault is no longer open in
    /// the session.
    fn vault_import_current(&self, target: &ImportTarget) -> Result<Option<&Vault>, String> {
        let ImportTarget::Existing(vault) = target else {
            return Ok(None);
        };
        self.session_vault(&vault.credential_id)
            .and_then(|v| v.state.as_ref().ok())
            .map(|open| Some(&open.contents))
            .ok_or_else(|| {
                vault_error_text(&VaultKeyError::VaultGone {
                    name: vault.name.clone(),
                })
            })
    }

    /// The preview's rows against the target as the session holds it now,
    /// with the default ticks; `None` before the backup is opened, `Err`
    /// when the target is no longer open.
    fn vault_import_rows_now(&self) -> Option<Result<Vec<ImportRow>, String>> {
        let d = self.vault.import.as_ref()?;
        let incoming = d.incoming.as_ref()?;
        Some(
            self.vault_import_current(&d.target)
                .map(|current| preview_rows(current, incoming)),
        )
    }

    /// Work the preview out again against the target as the session holds
    /// it, with the default ticks.
    fn vault_import_classify(&mut self) {
        let Some(now) = self.vault_import_rows_now() else {
            return;
        };
        if let Some(d) = self.vault.import.as_mut() {
            match now {
                Ok(rows) => d.rows = rows,
                Err(e) => {
                    d.rows = Vec::new();
                    d.notice = Some(e);
                }
            }
        }
    }

    /// After a Refresh: rows whose comparison changed take their new plan
    /// and default tick, and the dialog says so; the others keep the
    /// user's ticks.
    fn vault_import_refreshed(&mut self) {
        let Some(now) = self.vault_import_rows_now() else {
            return;
        };
        let Some(d) = self.vault.import.as_mut() else {
            return;
        };
        match now {
            Ok(rows) => {
                let mut changed = rows.len() != d.rows.len();
                let merged = rows
                    .into_iter()
                    .map(|new| match d.rows.iter().find(|r| r.index == new.index) {
                        Some(old) if old.status == new.status => *old,
                        _ => {
                            changed = true;
                            new
                        }
                    })
                    .collect();
                d.rows = merged;
                if changed {
                    d.notice = Some(IMPORT_REFRESHED.to_owned());
                }
            }
            Err(e) => {
                d.rows = Vec::new();
                d.notice = Some(e);
            }
        }
    }

    /// Into vault: another target, and the preview against it.
    pub(crate) fn vault_import_set_target(&mut self, target: ImportTarget) {
        let Some(d) = self.vault.import.as_mut() else {
            return;
        };
        if d.target == target {
            return;
        }
        d.target = target;
        d.notice = None;
        self.vault_import_classify();
    }

    /// Tick or untick row `i`; a row with no box stays as it is.
    pub(crate) fn vault_import_tick(&mut self, i: usize, on: bool) {
        if let Some(r) = self
            .vault
            .import
            .as_mut()
            .and_then(|d| d.rows.get_mut(i))
            .filter(|r| has_box(r.status))
        {
            r.ticked = on;
        }
    }

    /// Tick all / Untick all: every row with a box.
    pub(crate) fn vault_import_tick_all(&mut self, on: bool) {
        if let Some(d) = self.vault.import.as_mut() {
            for r in d.rows.iter_mut().filter(|r| has_box(r.status)) {
                r.ticked = on;
            }
        }
    }

    /// What the preview's button starts, with what it takes from the
    /// session. `None`, with nothing taken, when nothing is ticked, the
    /// new vault's name is refused (said in the pane), or a job holds the
    /// session's auth.
    pub(crate) fn vault_take_import(&mut self) -> Option<ImportJob> {
        let d = self.vault.import.as_ref()?;
        let incoming = d.incoming.as_ref()?;
        let picked = chosen(&d.rows);
        if picked.is_empty() {
            return None;
        }
        match d.target.clone() {
            ImportTarget::Existing(vault) => Some(ImportJob::Save {
                vault,
                kind: SaveKind::Import,
                change: Box::new(Change::Import {
                    incoming: incoming.clone(),
                    chosen: picked,
                }),
            }),
            ImportTarget::New => {
                let initial = Vault {
                    entries: picked
                        .iter()
                        .filter_map(|&i| incoming.entries.get(i).cloned())
                        .collect(),
                };
                let typed = d.new_name.clone();
                let name = self.vault_check_new_name(&typed)?;
                let auth = self.vault_take_auth()?;
                Some(ImportJob::Create {
                    name,
                    auth,
                    initial,
                })
            }
        }
    }

    /// The preview's button: the ticked entries into the vault on the key
    /// (no touch), or into a new vault it creates (two touches). The button
    /// is the confirmation, as the CLI's `import … into vault` and
    /// `create vault` questions are.
    pub(crate) fn vault_import(&mut self) {
        // Before anything is taken: a refused job would drop it.
        if self.refuse_if_busy() {
            return;
        }
        if let Some(d) = self.vault.import.as_mut() {
            d.notice = None;
        }
        match self.vault_take_import() {
            None => {}
            Some(ImportJob::Save {
                vault,
                kind,
                change,
            }) => self.vault_start_save(vault, kind, *change),
            Some(ImportJob::Create {
                name,
                auth,
                initial,
            }) => {
                let n = initial.entries.len();
                self.vault_spawn_create(name, auth, initial, Some(n));
            }
        }
    }

    /// The import dialog: which file, the passphrase and Open backup; once
    /// opened, the target vault and the preview, a row per backup entry with
    /// its box, plan and reason, then the summary and the button. Cancel
    /// waits for a running job, so its end finds the dialog.
    fn render_vault_import_dialog(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let busy = self.busy();
        let waiting = self.waiting_for().map(str::to_owned);
        // The target choices: every vault that opened, by chip label.
        let choices: Vec<(VaultRef, String)> = self
            .vault_session()
            .map(|s| {
                s.unlocked
                    .vaults
                    .iter()
                    .filter(|v| v.state.is_ok())
                    .map(|v| (v.vault_ref.clone(), chip_label(v)))
                    .collect()
            })
            .unwrap_or_default();
        let on_key = self
            .vault
            .import
            .as_ref()
            .and_then(|d| self.vault_import_current(&d.target).ok().flatten())
            .map_or(0, |v| v.entries.len());
        let taken_names = self.vault_names();
        let Some(d) = self.vault.import.as_mut() else {
            return;
        };
        let (mut open, mut cancel, mut import) = (false, false, false);
        let mut tick: Option<(usize, bool)> = None;
        let mut tick_all: Option<bool> = None;
        let mut target: Option<ImportTarget> = None;
        const LABEL_W: f32 = 90.0;
        let label = |text: &str| {
            egui::Label::new(
                egui::RichText::new(text)
                    .font(theme::f_reg(12.5))
                    .color(p.txt2),
            )
        };
        theme::card_frame(p).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.label(
                egui::RichText::new("Import backup")
                    .font(theme::f_sb(14.5))
                    .color(p.txt),
            );
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(sanitize_title(&d.path.display().to_string()))
                    .font(theme::f_reg(12.5))
                    .color(p.txt2),
            );
            ui.add_space(8.0);
            let Some(incoming) = d.incoming.as_ref() else {
                // Not opened yet: the passphrase and Open backup.
                ui.horizontal(|ui| {
                    ui.add_sized([LABEL_W, 24.0], label("Passphrase"));
                    let resp = ui.add(
                        egui::TextEdit::singleline(&mut d.passphrase)
                            .margin(theme::TEXT_EDIT_MARGIN)
                            .desired_width(f32::INFINITY)
                            .password(true),
                    );
                    guard_secret_field(ui.ctx(), &resp);
                    open = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                });
                if let Some(n) = &d.notice {
                    ui.add_space(6.0);
                    ui.colored_label(p.warn, n);
                }
                ui.add_space(8.0);
                let can_open = !busy && !d.passphrase.is_empty();
                right_row(ui, 32.0, |ui| {
                    if can_open {
                        open |= theme::button(ui, p, BtnKind::Primary, "Open backup").clicked();
                    } else {
                        theme::button_disabled(ui, p, "Open backup");
                    }
                    if busy {
                        theme::button_disabled(ui, p, "Cancel");
                    } else {
                        cancel = theme::button(ui, p, BtnKind::Default, "Cancel").clicked();
                    }
                });
                open &= can_open;
                return;
            };

            // Into vault: one on the key (by chip label), or a new one.
            let new_label = "A new vault named\u{2026}";
            let selected_text = match &d.target {
                ImportTarget::Existing(v) => choices
                    .iter()
                    .find(|(c, _)| c.credential_id == v.credential_id)
                    .map_or_else(|| shown_name(v.name.as_deref()), |(_, l)| l.clone()),
                ImportTarget::New => new_label.to_owned(),
            };
            ui.horizontal(|ui| {
                ui.add_sized([LABEL_W, 24.0], label("Into vault"));
                egui::ComboBox::from_id_salt("vault-import-target")
                    .selected_text(selected_text)
                    .show_ui(ui, |ui| {
                        for (v, chip) in &choices {
                            let on = matches!(
                                &d.target,
                                ImportTarget::Existing(t) if t.credential_id == v.credential_id
                            );
                            if ui.selectable_label(on, chip).clicked() && !on {
                                target = Some(ImportTarget::Existing(v.clone()));
                            }
                        }
                        let on = d.target == ImportTarget::New;
                        if ui.selectable_label(on, new_label).clicked() && !on {
                            target = Some(ImportTarget::New);
                        }
                    });
                if d.target == ImportTarget::New {
                    ui.add_sized(
                        [220.0, 28.0],
                        egui::TextEdit::singleline(&mut d.new_name)
                            .margin(theme::TEXT_EDIT_MARGIN)
                            .hint_text("Vault name"),
                    );
                }
            });
            ui.add_space(8.0);

            // A new vault's name, once it is one New vault would take.
            let new_name = d.new_name.trim();
            let refusal = match &d.target {
                ImportTarget::Existing(_) => None,
                ImportTarget::New => new_name_refusal(new_name, &taken_names),
            };
            let for_vault = match &d.target {
                ImportTarget::Existing(v) => format!("vault \"{}\"", shown_name(v.name.as_deref())),
                ImportTarget::New if refusal.is_none() => {
                    format!("new vault \"{}\"", sanitize_title(new_name))
                }
                ImportTarget::New => "a new vault".to_owned(),
            };
            ui.label(
                egui::RichText::new(format!(
                    "{} in {} for {for_vault}:",
                    entries(incoming.entries.len()),
                    file_label(&d.path)
                ))
                .font(theme::f_sb(13.0))
                .color(p.txt),
            );
            ui.add_space(6.0);
            // A row per entry: the box and the plan in narrow columns, the
            // entry's name in all the width left, its reason under it.
            const BOX_W: f32 = 24.0;
            const PLAN_W: f32 = 64.0;
            for (i, r) in d.rows.iter().enumerate() {
                let Some(e) = incoming.entries.get(r.index) else {
                    continue;
                };
                let (plan, reason) = row_plan(r);
                let taken = matches!(plan, "add" | "replace");
                ui.horizontal_top(|ui| {
                    if has_box(r.status) {
                        let mut on = r.ticked;
                        if ui
                            .add_sized([BOX_W, 20.0], egui::Checkbox::without_text(&mut on))
                            .changed()
                        {
                            tick = Some((i, on));
                        }
                    } else {
                        // `exists` (and a comparison this build doesn't
                        // know) has no box.
                        ui.add_space(BOX_W);
                    }
                    ui.add_sized(
                        [PLAN_W, 20.0],
                        egui::Label::new(
                            egui::RichText::new(plan)
                                .font(theme::f_sb(12.5))
                                .color(if taken { p.txt } else { p.txt3 }),
                        ),
                    );
                    ui.vertical(|ui| {
                        let name = import_row_name(e);
                        ui.label(
                            egui::RichText::new(name.as_str())
                                .font(theme::f_reg(12.5))
                                .color(p.txt),
                        );
                        if let Some(reason) = reason {
                            ui.label(
                                egui::RichText::new(reason)
                                    .font(theme::f_reg(11.5))
                                    .color(p.txt3),
                            );
                        }
                    });
                });
                ui.add_space(4.0);
            }
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if theme::button(ui, p, BtnKind::Ghost, "Tick all").clicked() {
                    tick_all = Some(true);
                }
                if theme::button(ui, p, BtnKind::Ghost, "Untick all").clicked() {
                    tick_all = Some(false);
                }
            });
            ui.add_space(6.0);
            ui.label(
                egui::RichText::new(import_summary(&d.rows, on_key))
                    .font(theme::f_reg(12.5))
                    .color(p.txt2),
            );
            if let Some(n) = &d.notice {
                ui.add_space(6.0);
                ui.colored_label(p.warn, n);
            }
            ui.add_space(8.0);
            let k = chosen(&d.rows).len();
            let button = match &d.target {
                ImportTarget::Existing(_) => format!("Import {}", entries(k)),
                ImportTarget::New if refusal.is_none() => format!(
                    "Create vault \"{}\" and import {}",
                    sanitize_title(new_name),
                    entries(k)
                ),
                ImportTarget::New => format!("Create vault and import {}", entries(k)),
            };
            right_row(ui, 32.0, |ui| {
                if k == 0 || refusal.is_some() {
                    theme::button_disabled(ui, p, &button);
                } else {
                    import =
                        theme::key_button(ui, p, BtnKind::Primary, &button, waiting.as_deref())
                            .clicked();
                }
                if busy {
                    theme::button_disabled(ui, p, "Cancel");
                } else {
                    cancel = theme::button(ui, p, BtnKind::Default, "Cancel").clicked();
                }
            });
            let under = if k == 0 {
                Some("Nothing to add.".to_owned())
            } else if let Some(e) = &refusal {
                // Nothing typed yet says what to do; anything else, what
                // New vault would say.
                Some(if new_name.is_empty() {
                    IMPORT_NAME_NEEDED.to_owned()
                } else {
                    vault_error_text(e)
                })
            } else if d.target == ImportTarget::New {
                Some("This asks for two touches.".to_owned())
            } else {
                None
            };
            if let Some(text) = under {
                ui.add_space(4.0);
                right_row(ui, 16.0, |ui| {
                    ui.label(
                        egui::RichText::new(text)
                            .font(theme::f_reg(11.5))
                            .color(p.txt3),
                    );
                });
            }
        });
        if let Some(t) = target {
            self.vault_import_set_target(t);
        }
        if let Some((i, on)) = tick {
            self.vault_import_tick(i, on);
        }
        if let Some(on) = tick_all {
            self.vault_import_tick_all(on);
        }
        if cancel {
            self.vault_import_cancel();
        } else if open {
            self.vault_import_open();
        } else if import {
            self.vault_import();
        }
    }
}

/// Whether a passkey listed on the FIDO2 tab is a password vault's: its
/// relying party is the vault's.
pub(crate) fn is_vault_passkey(rp_id: &str) -> bool {
    rp_id == keyroost_vault::RP_ID
}

/// What the FIDO2 tab's delete question adds for a vault's passkey: the
/// vault it unlocks (`name` when the vault session or the passkey list
/// knows it) and what deleting it loses, in the Storage tab's words.
pub(crate) fn vault_passkey_warning(name: Option<&str>) -> String {
    let which = match name {
        Some(n) => format!("password vault \"{}\"", sanitize_title(n)),
        None => "a password vault".to_owned(),
    };
    format!(
        "This passkey unlocks {which}: deleting it loses every entry in it. To keep them, \
         export a backup first."
    )
}

/// Export backup… on a vault passkey's question while the vault isn't
/// unlocked here any more.
const PASSKEY_EXPORT_LOCKED: &str = "Unlock the vault on the Vault tab to export a backup of it.";

/// Why the vault locked after its passkey was deleted on the FIDO2 tab.
fn passkey_deleted_text(name: Option<&str>) -> String {
    format!(
        "{} {UNLOCK_AGAIN}",
        as_sentence(&format!(
            "vault \"{}\" is no longer on the key: its passkey was deleted on the FIDO2 tab",
            shown_name(name)
        ))
    )
}

/// A password vault's passkey on the FIDO2 tab.
impl App {
    /// The name of the vault passkey `credential_id` unlocks: the unlocked
    /// vault's, else the one its user handle carries in the passkey list.
    pub(crate) fn vault_passkey_name(&self, credential_id: &[u8]) -> Option<String> {
        let name = match self.session_vault(credential_id) {
            Some(v) => v.vault_ref.name.clone(),
            None => self
                .fido_session()?
                .rps
                .iter()
                .flat_map(|(_, creds)| creds.iter())
                .find(|c| c.credential_id == credential_id)
                .and_then(|c| {
                    keyroost_ctap::get_assertion::vault_name_from_user_id(&c.user.id)
                        .or_else(|| c.user.name.clone())
                }),
        };
        name.filter(|n| !n.is_empty())
    }

    /// Whether the delete question of vault passkey `credential_id` offers
    /// Export backup…: that vault is unlocked here and opened.
    pub(crate) fn vault_passkey_can_export(&self, credential_id: &[u8]) -> bool {
        self.session_vault(credential_id)
            .is_some_and(|v| v.state.is_ok())
    }

    /// Export backup… on a vault passkey's delete question: that vault
    /// shown on the Vault tab, with its backup's save dialog; the question
    /// closes (nothing is deleted), so Remove asks again once the backup is
    /// saved. When the backup can't start (the vault
    /// locked or can't be opened, or another backup's save dialog is still
    /// open), nothing changes and `Err` says why, for the question to show.
    pub(crate) fn vault_passkey_export(&mut self, credential_id: &[u8]) -> Result<(), String> {
        let v = self
            .session_vault(credential_id)
            .ok_or_else(|| PASSKEY_EXPORT_LOCKED.to_owned())?;
        let vault = v.vault_ref.clone();
        if v.state.is_err() {
            return Err(format!(
                "Vault \"{}\" can't be opened, so it can't be backed up.",
                shown_name(vault.name.as_deref())
            ));
        }
        if let Some(pending) = self.vault.export_for.as_ref() {
            return Err(backup_pending_text(pending));
        }
        self.vault_select(vault.credential_id.clone());
        self.vault_export_start();
        if !self.vault_export_waits_for(&vault.credential_id, self.selected_device.as_ref()) {
            return Err(self
                .vault
                .error
                .clone()
                .unwrap_or_else(|| PASSKEY_EXPORT_LOCKED.to_owned()));
        }
        self.cap_tab = CapTab::Vault;
        Ok(())
    }

    /// Passkey `credential_id` was deleted on the FIDO2 tab. When an
    /// unlocked vault's, that vault went with it: the session locks, as for
    /// a vault gone elsewhere, so no later save reports success into data
    /// no unlock can open.
    pub(crate) fn vault_passkey_deleted(&mut self, credential_id: &[u8]) {
        let Some(v) = self.session_vault(credential_id) else {
            return;
        };
        let text = passkey_deleted_text(v.vault_ref.name.as_deref());
        self.log(Severity::Warn, format!("Vault: {text}"));
        self.vault_lock(Some(text));
    }
}

/// How long a copy button says "Copied" (the Authenticator codes' flash).
const COPIED_FLASH_SECS: f64 = 1.2;

/// What the New vault row's buttons asked for this frame.
#[derive(Default)]
struct NewVaultClicks {
    create: bool,
    cancel: bool,
}

/// The New vault row: the name box, Create vault (Enter too) and, when
/// there is a list to go back to, Cancel; under it, the touches it takes.
fn new_vault_row(
    ui: &mut egui::Ui,
    p: &Palette,
    name: &mut String,
    waiting: Option<&str>,
    can_cancel: bool,
) -> NewVaultClicks {
    let mut clicks = NewVaultClicks::default();
    ui.horizontal(|ui| {
        let resp = ui.add_sized(
            [220.0, 32.0],
            egui::TextEdit::singleline(name)
                .margin(theme::TEXT_EDIT_MARGIN)
                .align(egui::Align2::LEFT_CENTER)
                .hint_text("Vault name"),
        );
        let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        clicks.create = theme::key_button(ui, p, BtnKind::Primary, "Create vault", waiting)
            .clicked()
            || (enter && waiting.is_none());
        if can_cancel {
            ui.add_space(6.0);
            clicks.cancel = theme::button(ui, p, BtnKind::Default, "Cancel").clicked();
        }
    });
    ui.add_space(4.0);
    ui.label(
        egui::RichText::new("Creating asks for two touches.")
            .font(theme::f_reg(11.5))
            .color(p.txt3),
    );
    clicks
}

/// A right-aligned row `height` tall. A right-to-left layout added straight
/// to a card takes all the height left in it, which leaves an empty gap
/// above its buttons.
fn right_row<R>(ui: &mut egui::Ui, height: f32, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    ui.allocate_ui_with_layout(
        egui::vec2(ui.available_width(), height),
        egui::Layout::right_to_left(egui::Align::Center),
        add,
    )
    .inner
}

/// A vault chip: a rounded, selectable label.
fn chip(ui: &mut egui::Ui, p: &Palette, label: &str, on: bool) -> egui::Response {
    let (fill, fg, stroke) = if on {
        (p.accent_soft(), p.txt, egui::Stroke::new(1.0, p.accent))
    } else {
        (p.raised2, p.txt2, egui::Stroke::new(1.0, p.line))
    };
    let r = ui.add(
        egui::Button::new(egui::RichText::new(label).font(theme::f_sb(12.0)).color(fg))
            .fill(fill)
            .stroke(stroke)
            .corner_radius(egui::CornerRadius::same(14)),
    );
    if r.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    r
}

/// The small bar before the space line: how much of the store is used.
fn space_bar(ui: &mut egui::Ui, p: &Palette, cap: &BlobCapacity) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(150.0, 6.0), egui::Sense::hover());
    let frac = if cap.max_bytes == 0 {
        1.0
    } else {
        (cap.used_bytes as f32 / cap.max_bytes as f32).clamp(0.0, 1.0)
    };
    let r = egui::CornerRadius::same(4);
    ui.painter().rect_filled(rect, r, p.line);
    let mut used = rect;
    used.set_width(rect.width() * frac);
    ui.painter().rect_filled(used, r, p.accent);
}

/// What a click on an entry's row asks for.
struct RowClicks {
    /// The row itself: open or close the entry.
    toggle: bool,
    copy: Option<CopyWhat>,
}

/// One entry's row: `title · username · host`, and its two copy buttons
/// (disabled for an empty value; "Copied" while `flash` says so).
fn entry_row(ui: &mut egui::Ui, p: &Palette, e: &Entry, flash: [bool; 2]) -> RowClicks {
    let mut clicks = RowClicks {
        toggle: false,
        copy: None,
    };
    ui.horizontal(|ui| {
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            for (what, label, has, flashing) in [
                (
                    CopyWhat::Password,
                    "Copy password",
                    !e.password.is_empty(),
                    flash[1],
                ),
                (
                    CopyWhat::Username,
                    "Copy username",
                    !e.username.is_empty(),
                    flash[0],
                ),
            ] {
                if !has {
                    theme::button_disabled(ui, p, label);
                } else if flashing {
                    theme::button(ui, p, BtnKind::Ghost, "Copied");
                } else if theme::button(ui, p, BtnKind::Ghost, label).clicked() {
                    clicks.copy = Some(what);
                }
            }
            ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                let line = row_line(e);
                let title_len = line_title_len(e, &line);
                let mut job = egui::text::LayoutJob::default();
                job.append(
                    &line[..title_len],
                    0.0,
                    egui::TextFormat::simple(theme::f_sb(13.0), p.txt),
                );
                job.append(
                    &line[title_len..],
                    0.0,
                    egui::TextFormat::simple(theme::f_reg(12.5), p.txt3),
                );
                job.wrap.max_rows = 1;
                job.wrap.break_anywhere = true;
                job.wrap.max_width = ui.available_width();
                let resp = ui.add(egui::Label::new(job).sense(egui::Sense::click()));
                if resp.hovered() {
                    ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                }
                clicks.toggle = resp.clicked();
            });
        });
    });
    clicks
}

/// How many bytes of `line` (`row_line(e)`) are the title, drawn in bold:
/// its length once flattened as [`push_flat`] does.
fn line_title_len(e: &Entry, line: &str) -> usize {
    if e.title.trim().is_empty() {
        return 0;
    }
    let n = e
        .title
        .chars()
        .map(|c| if c.is_control() { 1 } else { c.len_utf8() })
        .sum::<usize>();
    if line.is_char_boundary(n.min(line.len())) {
        n.min(line.len())
    } else {
        0
    }
}

/// What a click in an opened entry asks for.
#[derive(Default)]
struct OpenedClicks {
    /// `Some(show)`: Show or Hide was clicked.
    reveal: Option<bool>,
    edit: bool,
    delete: bool,
}

/// The opened entry under its row: the password behind Show, the URL, the
/// notes (shown, as `entry show` does), Edit, and when it last changed.
fn opened_entry(ui: &mut egui::Ui, p: &Palette, e: &Entry, showing: bool) -> OpenedClicks {
    let mut clicks = OpenedClicks::default();
    egui::Frame::new()
        .fill(p.raised2)
        .corner_radius(egui::CornerRadius::same(8))
        .inner_margin(egui::Margin::symmetric(10, 8))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            let field = |ui: &mut egui::Ui, label: &str| {
                ui.add_sized(
                    [80.0, 20.0],
                    egui::Label::new(
                        egui::RichText::new(label)
                            .font(theme::f_reg(12.0))
                            .color(p.txt3),
                    ),
                );
            };
            let value = |ui: &mut egui::Ui, text: &str| {
                if text.is_empty() {
                    ui.label(
                        egui::RichText::new("(none)")
                            .font(theme::f_reg(13.0))
                            .color(p.txt3),
                    );
                } else {
                    let mut flat = Zeroizing::new(String::with_capacity(text.len()));
                    flat.extend(text.chars().map(|c| {
                        if c.is_control() && c != '\n' {
                            ' '
                        } else {
                            c
                        }
                    }));
                    ui.label(
                        egui::RichText::new(flat.as_str())
                            .font(theme::f_reg(13.0))
                            .color(p.txt),
                    );
                }
            };
            ui.horizontal(|ui| {
                field(ui, "Password");
                if e.password.is_empty() {
                    value(ui, "");
                } else {
                    if showing {
                        // Not selectable: Ctrl+C would skip the concealed
                        // copy and its 45 s clear.
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(e.password.as_str())
                                    .font(theme::f_mono(13.0))
                                    .color(p.txt),
                            )
                            .selectable(false),
                        );
                    } else {
                        ui.label(
                            egui::RichText::new("\u{2022}".repeat(8))
                                .font(theme::f_reg(13.0))
                                .color(p.txt2),
                        );
                    }
                    let label = if showing { "Hide" } else { "Show" };
                    if theme::button(ui, p, BtnKind::Ghost, label).clicked() {
                        clicks.reveal = Some(!showing);
                    }
                }
            });
            ui.horizontal(|ui| {
                field(ui, "URL");
                value(ui, &e.url);
            });
            ui.horizontal_top(|ui| {
                field(ui, "Notes");
                value(ui, &e.notes);
            });
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                clicks.edit = theme::button(ui, p, BtnKind::Default, "Edit").clicked();
                clicks.delete = theme::button(ui, p, BtnKind::Danger, "Delete").clicked();
                if let Some(when) = changed_ago(e.modified_minutes, vault::now_minutes()) {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            egui::RichText::new(when)
                                .font(theme::f_reg(11.5))
                                .color(p.txt3),
                        );
                    });
                }
            });
        });
    clicks
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyroost_transport::vault::fake::FakeKey;
    use keyroost_transport::vault::{unlock, VaultAuth, VaultProblem, VaultRef};
    use keyroost_vault::{seal, Entry, Vault};
    use zeroize::Zeroizing;

    fn entry(title: &str) -> Entry {
        Entry {
            id: keyroost_vault::new_id(),
            title: title.into(),
            username: "alice".into(),
            password: Zeroizing::new("hunter22".into()),
            url: String::new(),
            notes: String::new(),
            modified_minutes: 29_000_000,
        }
    }

    /// The vaults one unlock of `key` opens.
    fn unlocked(key: &mut FakeKey) -> Vec<VaultOnKey> {
        let mut auth = VaultAuth::pin(Zeroizing::new(FakeKey::PIN.to_owned()));
        unlock(key, &mut auth, &mut |_| {}).unwrap().vaults
    }

    fn unavailable(name: Option<&str>) -> VaultOnKey {
        VaultOnKey {
            vault_ref: VaultRef {
                credential_id: vec![1, 2, 3],
                name: name.map(str::to_owned),
            },
            state: Err(VaultProblem::NoSecret),
        }
    }

    fn info_with(f: impl FnOnce(&mut AuthenticatorInfo)) -> AuthenticatorInfo {
        let mut info = FakeKey::new().info;
        f(&mut info);
        info
    }

    #[test]
    fn vault_offer_reads_get_info() {
        let full = FakeKey::new().info;
        assert_eq!(vault_offer(Some(&full), false, false), VaultOffer::Ready);
        let no_pin = info_with(|i| {
            for (k, v) in &mut i.options {
                if k == "clientPin" {
                    *v = false;
                }
            }
        });
        assert_eq!(
            vault_offer(Some(&no_pin), false, false),
            VaultOffer::NeedsPin
        );
        let no_lbk = info_with(|i| i.extensions.retain(|e| e != "largeBlobKey"));
        assert_eq!(
            vault_offer(Some(&no_lbk), false, false),
            VaultOffer::No("largeBlobKey")
        );
        assert_eq!(vault_offer(None, false, false), VaultOffer::Unknown);
        assert_eq!(vault_offer(None, false, true), VaultOffer::NeedsAdmin);
        assert_eq!(vault_offer(None, true, false), VaultOffer::No("CTAP2"));
        assert_eq!(
            vault_offer(Some(&full), true, false),
            VaultOffer::No("CTAP2")
        );
    }

    #[test]
    fn vault_tab_sits_beside_authenticator() {
        use CapTab::*;
        assert_eq!(
            with_vault_tab(vec![Overview, Fido2, Oath, Pgp], VaultOffer::Ready),
            vec![Overview, Fido2, Oath, Vault, Pgp]
        );
        assert_eq!(
            with_vault_tab(vec![Overview, Fido2, Pgp, Piv], VaultOffer::Ready),
            vec![Overview, Fido2, Vault, Pgp, Piv]
        );
        assert_eq!(
            with_vault_tab(vec![Overview, Fido2, Oath], VaultOffer::No("CTAP2")),
            vec![Overview, Fido2, Oath]
        );
        // No FIDO2 tab (a U2F-only key, a card-only key): no vault.
        assert_eq!(
            with_vault_tab(vec![Overview, Oath, Piv], VaultOffer::Ready),
            vec![Overview, Oath, Piv]
        );
        for offer in [
            VaultOffer::Unknown,
            VaultOffer::NeedsAdmin,
            VaultOffer::NeedsPin,
        ] {
            assert_eq!(
                with_vault_tab(vec![Overview, Fido2], offer),
                vec![Overview, Fido2, Vault],
                "{offer:?}"
            );
        }
    }

    #[test]
    fn a_remembered_vault_tab_survives_until_info_loads() {
        use CapTab::*;
        let tabs = || vec![Overview, Fido2, Oath];
        assert_eq!(
            crate::snap_cap_tab(Vault, &with_vault_tab(tabs(), VaultOffer::Unknown)),
            Vault
        );
        assert_eq!(
            crate::snap_cap_tab(Vault, &with_vault_tab(tabs(), VaultOffer::No("a PIN"))),
            Overview
        );
    }

    #[test]
    fn overview_line_says_why() {
        assert_eq!(
            overview_line(VaultOffer::Unknown, false, None, false),
            "Reading key\u{2026}"
        );
        // A failed read isn't left on "Reading key…".
        assert_eq!(
            overview_line(VaultOffer::Unknown, true, None, false),
            "Couldn't read this key."
        );
        assert_eq!(
            overview_line(VaultOffer::NeedsAdmin, false, None, false),
            "Open the FIDO2 tab to manage this key via Windows settings or restart as \
             administrator."
        );
        assert_eq!(
            overview_line(VaultOffer::No("largeBlobKey"), false, None, false),
            "This key cannot hold a password vault: it does not support largeBlobKey."
        );
        assert_eq!(
            overview_line(VaultOffer::NeedsPin, false, None, false),
            "A password vault needs a FIDO2 PIN; set one on the FIDO2 tab."
        );
        assert_eq!(
            overview_line(VaultOffer::Ready, false, None, false),
            "Passwords in an encrypted vault on this key, opened with the PIN and a touch."
        );
        assert_eq!(
            overview_line(VaultOffer::Ready, false, None, true),
            "Passwords in an encrypted vault on this key, opened with the PIN or a fingerprint, \
             and a touch."
        );
        assert_eq!(
            overview_line(VaultOffer::Ready, false, Some(&[]), true),
            "No vaults on this key yet.",
            "unlocked, what the vaults hold"
        );
        assert_eq!(
            overview_line(VaultOffer::Ready, false, Some(&[]), false),
            "No vaults on this key yet."
        );
        let mut key = FakeKey::new();
        key.add_vault(
            "Personal",
            &Vault {
                entries: vec![entry("GitHub"), entry("Bank")],
            },
        );
        key.add_vault("Work", &Vault::default());
        let vaults = unlocked(&mut key);
        assert_eq!(
            overview_line(VaultOffer::Ready, false, Some(&vaults), false),
            "Personal \u{00B7} 2, Work \u{00B7} 0"
        );
    }

    #[test]
    fn chip_labels_and_entries() {
        let mut key = FakeKey::new();
        key.add_vault(
            "Personal",
            &Vault {
                entries: (0..12).map(|i| entry(&format!("Site {i}"))).collect(),
            },
        );
        let unnamed = key.add_credential(keyroost_vault::unnamed_user_handle().unwrap(), None);
        key.put_vault(&unnamed, &Vault::default());
        let vaults = unlocked(&mut key);
        assert_eq!(chip_label(&vaults[0]), "Personal \u{00B7} 12");
        assert_eq!(chip_label(&vaults[1]), "(unnamed) \u{00B7} 0");
        assert_eq!(
            chip_label(&unavailable(None)),
            "(unnamed) \u{00B7} (unavailable)"
        );
        assert_eq!(
            chip_label(&unavailable(Some(""))),
            "(unnamed) \u{00B7} (unavailable)"
        );
        assert_eq!(
            chip_label(&unavailable(Some("Work"))),
            "Work \u{00B7} (unavailable)"
        );
        // A name from the key can't break the line.
        assert_eq!(
            chip_label(&unavailable(Some("a\u{1b}[2Jb"))),
            "a [2Jb \u{00B7} (unavailable)"
        );
        assert_eq!(entries(0), "0 entries");
        assert_eq!(entries(1), "1 entry");
        assert_eq!(entries(12), "12 entries");
    }

    #[test]
    fn the_vault_help_topic_exists() {
        let h = crate::ui::help::help("vault").expect("a vault help topic");
        assert_eq!(h.title, "Password vault");
        assert!(h.body.contains("keep a backup file"), "{}", h.body);
        assert_eq!(h.slug, "/vault");
    }

    // ----- unlock, lock, Refresh -----

    use crate::{App, SessionUnlock, UnlockedSession};
    use keyroost_ctap::client_pin::PinUvAuthToken;
    use keyroost_ctap::CtapError;
    use keyroost_transport::vault::fake::Call;
    use keyroost_transport::vault::{LeftOver, OldVault};
    use std::sync::{Arc, Mutex};

    const KEY: &str = "serial:AAA";

    fn app() -> App {
        App {
            selected_device: Some(KEY.into()),
            ..Default::default()
        }
    }

    fn pin_auth() -> VaultAuth {
        VaultAuth::pin(Zeroizing::new(FakeKey::PIN.to_owned()))
    }

    /// A key with Personal (2 entries) and Work (empty); Personal's ID.
    fn two_vaults(key: &mut FakeKey) -> Vec<u8> {
        let p = key.add_vault(
            "Personal",
            &Vault {
                entries: vec![entry("GitHub"), entry("Bank")],
            },
        );
        key.add_vault("Work", &Vault::default());
        p
    }

    /// Unlock `key` as the job does, and land it as the apply does.
    fn unlock_into(app: &mut App, key: &mut FakeKey) {
        let mut auth = pin_auth();
        let shown = Arc::new(Mutex::new(None));
        let mut touches = TouchProgress::new(shown, 1);
        let result = run_unlock(key, &mut auth, &mut touches).map_err(VaultJobError::from);
        app.vault_apply_unlock(Some(KEY.into()), auth, false, None, result);
    }

    fn fido_session(pin: &str) -> UnlockedSession {
        UnlockedSession {
            token: PinUvAuthToken {
                protocol: 2,
                token: vec![7; 32],
            },
            metadata: keyroost_ctap::cred_mgmt::CredsMetadata::default(),
            rps: Arc::new(Vec::new()),
            fingerprints: None,
            unlock: SessionUnlock::Pin(Zeroizing::new(pin.to_owned())),
        }
    }

    fn wrong_pin() -> Result<Unlocked, VaultJobError> {
        Err(VaultJobError::Vault(VaultKeyError::Ctap(
            CtapError::StatusCode(0x31),
        )))
    }

    fn shown(cell: &Arc<Mutex<Option<String>>>) -> Option<String> {
        cell.lock().unwrap().clone()
    }

    #[test]
    fn touch_text_counts() {
        assert_eq!(touch_text(1, 1), "Touch your key\u{2026}");
        assert_eq!(touch_text(1, 2), "Touch your key (1 of 2)\u{2026}");
        assert_eq!(touch_text(2, 2), "Touch your key (2 of 2)\u{2026}");
        assert_eq!(touch_text(3, 2), "Touch your key\u{2026}");
        assert_eq!(touch_text(1, 0), "Touch your key\u{2026}");
    }

    #[test]
    fn touch_progress_shows_and_clears() {
        let cell = Arc::new(Mutex::new(None));
        let mut touches = TouchProgress::new(cell.clone(), 2);
        touches.step(VaultStep::CreateTouch);
        assert_eq!(
            shown(&cell).as_deref(),
            Some("Touch your key (1 of 2)\u{2026}")
        );
        touches.step(VaultStep::Write);
        assert_eq!(shown(&cell), None);
        touches.step(VaultStep::UnlockTouch);
        assert_eq!(
            shown(&cell).as_deref(),
            Some("Touch your key (2 of 2)\u{2026}")
        );
        drop(touches);
        assert_eq!(shown(&cell), None, "a job that ends never leaves it up");
    }

    #[test]
    fn unlock_opens_every_vault_on_the_fake() {
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        let s = app.vault_session().expect("a session");
        assert_eq!(s.device, KEY);
        assert!(s.auth.is_some(), "the session keeps its PIN for writes");
        assert!(!s.pin_from_fido);
        let names: Vec<_> = s
            .unlocked
            .vaults
            .iter()
            .map(|v| (v.vault_ref.name.clone(), v.entry_count()))
            .collect();
        assert_eq!(
            names,
            vec![
                (Some("Personal".to_owned()), Some(2)),
                (Some("Work".to_owned()), Some(0)),
            ]
        );
        assert!(app.vault.error.is_none());
        // Bound to its key: another selection doesn't reach it.
        app.selected_device = Some("serial:BBB".into());
        assert!(app.vault_session().is_none());
        assert!(app.vault_session_mut().is_none());
    }

    /// A key with three foreign entries, then two vaults, and an app showing
    /// that key's Storage list.
    fn storage_app() -> (App, FakeKey) {
        let mut key = FakeKey::new();
        key.add_foreign_entries();
        two_vaults(&mut key);
        let mut app = app();
        app.security_keys.large_blobs = Some(key.array());
        (app, key)
    }

    #[test]
    fn storage_names_an_unlocked_vaults_entry() {
        let (mut app, mut key) = storage_app();
        app.refresh_storage_vault_labels();
        assert!(app.security_keys.lb_vault_labels.is_empty(), "locked");
        unlock_into(&mut app, &mut key);
        let labels = &app.security_keys.lb_vault_labels;
        let array = key.array();
        assert_eq!(labels.len(), array.entries().len());
        let named: Vec<&str> = labels.iter().flatten().map(String::as_str).collect();
        assert_eq!(named, ["Personal", "Work"]);
        assert_eq!(
            labels.iter().filter(|l| l.is_none()).count(),
            labels.len() - 2
        );
        // Only the vault entries: the foreign ones (first) stay unnamed.
        assert!(labels[..3].iter().all(Option::is_none));
        // A vault that did not open names nothing.
        let unnamed = unavailable(None);
        assert!(vault_entry_labels(&array, &[unnamed])
            .iter()
            .all(Option::is_none));
        assert_eq!(
            vault_entry_row_text("Personal"),
            "password vault \"Personal\" (encrypted)"
        );
    }

    #[test]
    fn labels_go_when_the_vault_locks() {
        let (mut app, mut key) = storage_app();
        unlock_into(&mut app, &mut key);
        assert!(app
            .security_keys
            .lb_vault_labels
            .iter()
            .any(Option::is_some));
        app.vault_lock(None);
        assert!(app.security_keys.lb_vault_labels.is_empty());
    }

    #[test]
    fn labels_reset_on_selection_change() {
        let (mut app, mut key) = storage_app();
        unlock_into(&mut app, &mut key);
        assert!(!app.security_keys.lb_vault_labels.is_empty());
        let previous = app.selected_device.take();
        app.selected_device = Some("serial:BBB".into());
        app.on_device_selected(previous);
        assert!(app.security_keys.lb_vault_labels.is_empty());
    }

    #[test]
    fn a_result_for_another_key_is_discarded() {
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut auth = pin_auth();
        let mut touches = TouchProgress::new(Arc::default(), 1);
        let result = run_unlock(&mut key, &mut auth, &mut touches).map_err(VaultJobError::from);
        let mut app = app();
        app.vault_apply_unlock(
            Some("serial:BBB".into()),
            auth,
            false,
            Some(Zeroizing::new("123456".into())),
            result,
        );
        assert!(app.vault.session.is_none());
        assert!(app.log.is_empty(), "{:?}", app.log.len());
        // An error for another key is dropped the same way.
        app.vault_apply_unlock(
            Some("serial:BBB".into()),
            pin_auth(),
            true,
            None,
            wrong_pin(),
        );
        assert!(app.vault.error.is_none());
        assert!(app.log.is_empty());
    }

    #[test]
    fn a_wrong_pin_locks_and_says_why() {
        let mut app = app();
        app.security_keys.session = Some(fido_session("654321"));
        app.security_keys.session_device = Some(KEY.into());
        app.vault_apply_unlock(
            Some(KEY.into()),
            pin_auth(),
            false,
            Some(Zeroizing::new("111111".into())),
            wrong_pin(),
        );
        assert!(app.vault.session.is_none());
        let expected = vault_error_text(&VaultKeyError::Ctap(CtapError::StatusCode(0x31)));
        assert_eq!(app.vault.error.as_deref(), Some(expected.as_str()));
        assert!(expected.contains("PIN was incorrect"), "{expected}");
        assert!(
            app.security_keys.session.is_some(),
            "a PIN typed on the Vault tab says nothing about the FIDO2 tab's"
        );
    }

    #[test]
    fn a_wrong_shared_pin_locks_both_tabs() {
        for code in [0x31, 0x32, 0x34] {
            let mut app = app();
            app.security_keys.session = Some(fido_session("654321"));
            app.security_keys.session_device = Some(KEY.into());
            let err = Err(VaultJobError::Vault(VaultKeyError::Ctap(
                CtapError::StatusCode(code),
            )));
            app.vault_apply_unlock(Some(KEY.into()), pin_auth(), true, None, err);
            assert!(app.vault.session.is_none());
            assert!(app.vault.error.is_some());
            assert!(
                app.security_keys.session.is_none(),
                "{code:#04x}: the FIDO2 tab's PIN is the refused one"
            );
            assert_eq!(
                app.security_keys.error.as_deref(),
                Some(crate::FIDO_RELOCKED),
                "and it says why, as any re-lock does"
            );
        }
    }

    #[test]
    fn an_open_failure_reaches_the_pane() {
        let mut app = app();
        app.vault_apply_unlock(
            Some(KEY.into()),
            pin_auth(),
            false,
            None,
            Err(VaultJobError::Open("no such device".into())),
        );
        assert!(app.vault.session.is_none());
        assert_eq!(app.vault.error.as_deref(), Some("No such device."));
        assert!(app.log.iter().any(|l| l.text == "Vault: No such device."));
    }

    #[test]
    fn the_fido2_tabs_pin_is_reused() {
        let mut app = app();
        app.security_keys.session = Some(fido_session("123456"));
        app.security_keys.session_device = Some(KEY.into());
        let (pin, from_fido) = app.unlock_pin().unwrap();
        assert_eq!(pin.as_str(), "123456");
        assert!(from_fido);

        // Without a FIDO2 session the typed PIN is taken (and the box empties).
        let mut app = super::tests::app();
        *app.vault.pin_input = "246810".into();
        let (pin, from_fido) = app.unlock_pin().unwrap();
        assert_eq!(pin.as_str(), "246810");
        assert!(!from_fido);
        assert!(app.vault.pin_input.is_empty());
        assert_eq!(app.unlock_pin().err(), Some("PIN is empty"));

        // A session for another key is not this key's PIN.
        let mut app = super::tests::app();
        app.security_keys.session = Some(fido_session("123456"));
        app.security_keys.session_device = Some("serial:BBB".into());
        assert_eq!(app.unlock_pin().err(), Some("PIN is empty"));
    }

    // Linux only: the follow-on unlock reaches a HID open (of a path that
    // doesn't exist), which on Linux is a plain file open; elsewhere hidapi
    // misbehaves in a test process.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_typed_vault_pin_unlocks_the_fido2_tab_too() {
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut auth = pin_auth();
        let mut touches = TouchProgress::new(Arc::default(), 1);
        let result = run_unlock(&mut key, &mut auth, &mut touches).map_err(VaultJobError::from);
        // A key whose FIDO2 side can't be opened here: the follow-on unlock
        // runs inline (no worker in tests) and says it failed, which shows
        // that it was dispatched with the PIN.
        let mut app = App {
            devices: vec![crate::ui::device::Device {
                hid_path: Some("/nonexistent/keyroost-test/hidraw0".into()),
                ..crate::tests::test_key(KEY, "AAA", None)
            }],
            selected_device: Some(KEY.into()),
            ..Default::default()
        };
        app.vault_apply_unlock(
            Some(KEY.into()),
            auth,
            false,
            Some(Zeroizing::new(FakeKey::PIN.into())),
            result,
        );
        assert!(app.vault.session.is_some(), "the vault stays unlocked");
        let err = app.security_keys.error.clone().unwrap_or_default();
        assert!(err.starts_with("unlock failed"), "{err}");

        // With the FIDO2 tab already unlocked, nothing more is sent.
        let mut app = App {
            devices: app.devices.clone(),
            selected_device: Some(KEY.into()),
            ..Default::default()
        };
        app.security_keys.session = Some(fido_session("123456"));
        app.security_keys.session_device = Some(KEY.into());
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut auth = pin_auth();
        let result = run_unlock(
            &mut key,
            &mut auth,
            &mut TouchProgress::new(Arc::default(), 1),
        )
        .map_err(VaultJobError::from);
        app.vault_apply_unlock(
            Some(KEY.into()),
            auth,
            false,
            Some(Zeroizing::new(FakeKey::PIN.into())),
            result,
        );
        assert!(app.security_keys.error.is_none());
    }

    #[test]
    fn refresh_shows_another_writers_change_without_a_touch() {
        let mut key = FakeKey::new();
        let p = two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        key.log.clear();
        // Another program edits Personal's first entry.
        let mut v = key.vault_on_key(&p).unwrap();
        v.entries[0].username = "bob".into();
        key.put_vault(&p, &v);

        let mut unlocked = app.vault_session().unwrap().unlocked.clone();
        let result = run_reload(&mut key, &mut unlocked).map_err(VaultJobError::from);
        assert_eq!(key.log, vec![Call::Read], "no token, no touch");
        app.vault_apply_reload(Some(KEY.into()), unlocked, result);
        let s = app.vault_session().expect("still unlocked");
        let personal = s.unlocked.vaults[0].state.as_ref().unwrap();
        assert_eq!(personal.contents.entries[0].username, "bob");
        assert!(app.vault.error.is_none());
    }

    #[test]
    fn refresh_of_a_vanished_vault_locks() {
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        // Work is deleted elsewhere: its data goes.
        let lbk = key.creds[1].lbk.unwrap();
        let rest = key.array().without_credential_blob(&lbk);
        key.set_array(&rest);

        let mut unlocked = app.vault_session().unwrap().unlocked.clone();
        let result = run_reload(&mut key, &mut unlocked).map_err(VaultJobError::from);
        app.vault_apply_reload(Some(KEY.into()), unlocked, result);
        assert!(
            app.vault.session.is_none(),
            "locked: unlock again to see it"
        );
        let err = app.vault.error.clone().unwrap_or_default();
        assert!(
            err.starts_with("Vault \"Work\" is no longer on the key"),
            "{err}"
        );
        assert!(err.ends_with(UNLOCK_AGAIN), "{err}");
    }

    #[test]
    fn a_reload_after_lock_is_dropped() {
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        let mut unlocked = app.vault_session().unwrap().unlocked.clone();
        let result = run_reload(&mut key, &mut unlocked).map_err(VaultJobError::from);
        app.vault_lock(None);
        app.vault_apply_reload(Some(KEY.into()), unlocked, result);
        assert!(
            app.vault.session.is_none(),
            "Lock pressed mid-read stays locked"
        );
    }

    #[test]
    fn lock_rebuilds_the_state_and_keeps_the_touch_cell() {
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        *app.vault.pin_input = "123".into();
        app.vault.info = Some("Entry \"x\" added.".into());
        let cell = app.vault.progress.clone();
        app.vault_lock(Some("Locked.".into()));
        assert!(app.vault.session.is_none());
        assert!(app.vault.pin_input.is_empty());
        assert!(app.vault.info.is_none());
        assert_eq!(app.vault.error.as_deref(), Some("Locked."));
        assert!(
            Arc::ptr_eq(&cell, &app.vault.progress),
            "a running job's touch prompt still shows"
        );
    }

    #[test]
    fn done_and_fail_log_under_vault() {
        let mut app = app();
        app.vault_done("Shown.".into(), "logged".into());
        assert_eq!(app.vault.info.as_deref(), Some("Shown."));
        assert!(app.log.iter().any(|l| l.text == "Vault: logged"));
        app.vault_fail(&VaultJobError::Vault(VaultKeyError::NoVaults));
        assert_eq!(
            app.vault.error.as_deref(),
            Some("This key holds no vaults; create one with New vault.")
        );
        assert!(app
            .log
            .iter()
            .any(|l| l.text == "Vault: This key holds no vaults; create one with New vault."));
    }

    #[test]
    fn vault_error_text_uses_app_hints() {
        let undone = |credential, data| VaultKeyError::CreateUndone {
            cause: Box::new(VaultKeyError::Ctap(CtapError::StatusCode(0x2F))),
            left_over: LeftOver { credential, data },
        };
        let old_not_deleted = |old| VaultKeyError::OldNotDeleted {
            name: Some("Personal".into()),
            cause: Box::new(VaultKeyError::Ctap(CtapError::StatusCode(0x30))),
            old,
        };
        let cases = vec![
            (VaultKeyError::PinNotSet, "; set one on the FIDO2 tab."),
            (
                VaultKeyError::Ctap(CtapError::PinChangeRequired),
                "; change it on the FIDO2 tab.",
            ),
            (VaultKeyError::NoVaults, "; create one with New vault."),
            (
                undone(true, false),
                "; delete the copy listed as (none) with Delete vault\u{2026}.",
            ),
            (
                undone(true, true),
                "; remove both with Delete vault\u{2026}.",
            ),
            (
                undone(false, true),
                "; it shows on the FIDO2 tab's Storage as relying-party data, and nothing \
                 tells it apart from a website's data.",
            ),
            (
                undone(false, false),
                "its new credential was removed again.",
            ),
            (old_not_deleted(OldVault::Kept), UNLOCK_AGAIN),
            (old_not_deleted(OldVault::Emptied), UNLOCK_AGAIN),
            (
                VaultKeyError::VaultGone {
                    name: Some("Work".into()),
                },
                UNLOCK_AGAIN,
            ),
            (VaultKeyError::Conflict, "nothing was written."),
        ];
        for (e, end) in cases {
            let text = vault_error_text(&e);
            assert!(text.ends_with(end), "{text:?} should end {end:?}");
            assert!(!text.contains("keyroostctl"), "{text}");
            assert!(text.chars().next().unwrap().is_uppercase(), "{text}");
            assert!(!text.contains(".."), "{text}");
        }
        let kept = vault_error_text(&old_not_deleted(OldVault::Kept));
        assert!(
            kept.contains("is in place with every entry checked"),
            "{kept}"
        );
        assert!(kept.starts_with("The new vault \"Personal\""), "{kept}");
        // A name from the key can't break the line.
        let gone = vault_error_text(&VaultKeyError::VaultGone {
            name: Some("a\u{1b}[2Jb".into()),
        });
        assert!(gone.starts_with("Vault \"a [2Jb\""), "{gone}");
        // Everything else is the error's own words.
        assert_eq!(
            vault_error_text(&VaultKeyError::DuplicateName("Work".into())),
            "This key already holds a vault named \"Work\"."
        );
        assert_eq!(
            job_error_text(&VaultJobError::Open(
                "device is U2F-only; CTAP2 password vaults not supported".into()
            )),
            "Device is U2F-only; CTAP2 password vaults not supported."
        );
        assert_eq!(
            job_error_text(&VaultJobError::Vault(VaultKeyError::NoVaults)),
            vault_error_text(&VaultKeyError::NoVaults)
        );
    }

    #[test]
    fn holding_a_session_counts_for_the_idle_lock() {
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut app = app();
        assert!(!app.holds_unlocked_secrets());
        unlock_into(&mut app, &mut key);
        assert!(app.holds_unlocked_secrets());
        let t0 = std::time::Instant::now();
        assert_eq!(
            app.idle_lock_tick(t0, false),
            Some(crate::IDLE_LOCK_AFTER),
            "the clock runs while the vault is open"
        );
        // A typed vault PIN is a typed secret, wiped by the idle lock.
        let mut app = super::tests::app();
        *app.vault.pin_input = "1234".into();
        assert!(app.holds_unlocked_secrets());
    }

    #[test]
    fn refresh_on_the_vault_tab_rereads_the_vault() {
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut app = App {
            cap_tab: CapTab::Vault,
            ..app()
        };
        assert!(matches!(app.reread_choice(), crate::Reread::FidoInfo));
        unlock_into(&mut app, &mut key);
        assert!(matches!(app.reread_choice(), crate::Reread::Vault));
        app.cap_tab = CapTab::Overview;
        assert!(matches!(app.reread_choice(), crate::Reread::FidoInfo));
    }

    #[test]
    fn banner_shows_vault_progress_while_busy() {
        let mut app = app();
        *app.vault.progress.lock().unwrap() = Some(touch_text(1, 2));
        assert_eq!(app.touch_banner_text(), None, "no job, no banner");
        app.busy_jobs = 1;
        app.busy_label = Some("Creating the vault\u{2026}".into());
        assert_eq!(
            app.touch_banner_text().as_deref(),
            Some("Touch your key (1 of 2)\u{2026}")
        );
        *app.vault.progress.lock().unwrap() = None;
        assert_eq!(app.touch_banner_text(), None, "between touches: no banner");
    }

    #[test]
    fn pin_change_and_fido_reset_lock_the_vault() {
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        app.apply_pin_changed(Ok(()));
        assert!(app.vault.session.is_none(), "a changed PIN locks the vault");

        // A failed change leaves it open.
        let mut app = super::tests::app();
        unlock_into(&mut app, &mut key);
        app.apply_pin_changed(Err("the PIN was incorrect".into()));
        assert!(app.vault.session.is_some());

        let mut app = super::tests::app();
        unlock_into(&mut app, &mut key);
        App::apply_reset_path_outcome(&mut app, Some(&KEY.to_owned()), Ok(()));
        assert!(app.vault.session.is_none(), "a FIDO2 reset wipes the vault");
    }

    #[test]
    fn idle_lock_drops_the_vault_session_once() {
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        assert!(app.holds_unlocked_secrets());
        let t0 = std::time::Instant::now();
        app.idle_lock_tick(t0, false);
        app.idle_lock_tick(t0 + crate::IDLE_LOCK_AFTER, false);
        assert!(app.vault.session.is_none());
        assert_eq!(
            app.vault.error.as_deref(),
            Some(crate::idle_locked_msg().as_str())
        );
        let lines = app.log.len();
        assert!(!app.holds_unlocked_secrets());
        app.idle_lock_tick(t0 + crate::IDLE_LOCK_AFTER * 2, false);
        assert_eq!(app.log.len(), lines, "nothing left to lock, nothing logged");
    }

    // ----- the idle lock: the vault's scoped extension and its secrets -----

    const MIN: std::time::Duration = std::time::Duration::from_secs(60);

    /// How many activity-log lines say the idle lock fired.
    fn idle_lines(app: &App) -> usize {
        app.log
            .iter()
            .filter(|l| l.text.contains("of inactivity"))
            .count()
    }

    fn export_dialog(vault: VaultRef) -> ExportDialog {
        ExportDialog {
            vault,
            path: "personal.t2vault".into(),
            passphrase: "correct horse".into(),
            repeat: "correct horse".into(),
        }
    }

    #[test]
    fn idle_lock_locks_the_vault_and_wipes_its_forms() {
        let mut key = FakeKey::new();
        let mut app = super::tests::app();
        opened_into(&mut app, &mut key);
        import_dialog(&mut app).passphrase.push_str(IMPORT_PASS);
        let vault = shown_ref(&app);
        app.vault.form = Some(EntryForm::for_add(vault.clone()));
        app.vault.export = Some(export_dialog(vault));
        *app.security_keys.pin_input = "fido-pin".into();
        app.clipboard_clear_at = Some(clipboard_clear_for("hunter22".into(), 0.0, true));
        assert!(!app.vault_form_dirty(), "an untouched form");

        let t0 = std::time::Instant::now();
        assert_eq!(app.idle_lock_tick(t0, false), Some(crate::IDLE_LOCK_AFTER));
        assert_eq!(
            app.idle_lock_tick(t0 + crate::IDLE_LOCK_AFTER - MIN, false),
            Some(MIN)
        );
        assert!(app.vault.session.is_some(), "not yet");
        assert_eq!(app.idle_lock_tick(t0 + crate::IDLE_LOCK_AFTER, false), None);

        assert!(app.vault.session.is_none());
        assert!(app.vault.form.is_none());
        assert!(app.vault.export.is_none());
        assert!(
            app.vault.import.is_none(),
            "the preview goes with its entries"
        );
        assert!(app.typed_secrets().iter().all(|s| s.is_empty()));
        assert!(app.security_keys.pin_input.is_empty());
        assert!(app.clipboard_clear_at.is_none(), "a vault copy is cleared");
        assert_eq!(
            app.vault.error.as_deref(),
            Some(crate::idle_locked_msg().as_str())
        );
        assert_eq!(idle_lines(&app), 1);
        assert!(app
            .log
            .iter()
            .any(|l| l.text == "Locked after 5 minutes of inactivity."));
        assert!(app.drop_text_focus);
        assert!(!app.holds_unlocked_secrets());
    }

    #[test]
    fn a_dirty_vault_form_keeps_only_the_vault_open() {
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        app.security_keys.session = Some(fido_session("123456"));
        app.security_keys.session_device = Some(KEY.into());
        app.oath.loaded = true;
        app.oath.creds = vec![crate::OathRow::new(
            "Example:alice".into(),
            Some("123456".into()),
            false,
        )];
        let mut form = EntryForm::for_add(shown_ref(&app));
        form.title.push_str("Mail");
        form.password.push_str("half-typed");
        form.notes.push_str("a note");
        app.vault.form = Some(form);
        assert!(app.vault_form_dirty());

        let t0 = std::time::Instant::now();
        assert_eq!(
            app.idle_lock_tick(t0, false),
            Some(crate::IDLE_LOCK_AFTER),
            "the nearest deadline is the rest of the app's"
        );
        assert_eq!(
            app.idle_lock_tick(t0 + crate::IDLE_LOCK_AFTER, false),
            Some(crate::VAULT_EDIT_IDLE_LOCK_AFTER - crate::IDLE_LOCK_AFTER)
        );
        // Everything outside the vault locked as today.
        assert!(app.security_keys.session.is_none());
        assert_eq!(app.security_keys.error, Some(crate::idle_locked_msg()));
        assert!(app.oath.creds.is_empty());
        assert_eq!(app.oath.notice, Some(crate::idle_hidden_msg()));
        assert!(!app.holds_secrets_outside_vault());
        // The vault and its form stay.
        assert!(app.vault.session.is_some());
        let form = app.vault.form.as_ref().expect("the form stays");
        assert_eq!(form.password, "half-typed");
        assert_eq!(form.notes, "a note");
        assert!(app.vault.error.is_none());
        assert_eq!(idle_lines(&app), 1);

        // No second lock, no log line, in between.
        assert_eq!(app.idle_lock_tick(t0 + 10 * MIN, false), Some(5 * MIN));
        let almost = t0 + crate::VAULT_EDIT_IDLE_LOCK_AFTER - std::time::Duration::from_secs(1);
        assert_eq!(
            app.idle_lock_tick(almost, false),
            Some(std::time::Duration::from_secs(1))
        );
        assert!(app.vault.session.is_some());
        assert_eq!(idle_lines(&app), 1);

        assert_eq!(
            app.idle_lock_tick(t0 + crate::VAULT_EDIT_IDLE_LOCK_AFTER, false),
            None
        );
        assert!(app.vault.session.is_none());
        assert!(app.vault.form.is_none(), "the form is wiped");
        let msg = app.vault.error.clone().expect("the tab says why");
        assert_eq!(
            msg,
            crate::idle_locked_msg_for(crate::VAULT_EDIT_IDLE_LOCK_AFTER)
        );
        assert!(msg.contains("15 minutes"), "{msg}");
        assert!(app
            .log
            .iter()
            .any(|l| l.text == "Vault: Locked after 15 minutes of inactivity."));
        assert_eq!(idle_lines(&app), 2);
        assert!(app.typed_secrets().iter().all(|s| s.is_empty()));
        assert!(!app.holds_unlocked_secrets());

        assert_eq!(
            app.idle_lock_tick(t0 + crate::VAULT_EDIT_IDLE_LOCK_AFTER * 2, false),
            None
        );
        assert_eq!(idle_lines(&app), 2, "nothing left to lock");
    }

    #[test]
    fn an_untouched_form_does_not_extend_the_lock() {
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        let e = session_entry(&app, "GitHub");
        let mut form = EntryForm::for_edit(shown_ref(&app), &e);
        // Typed over and typed back: as read, so nothing unsaved.
        form.title.push('x');
        form.title.pop();
        app.vault.form = Some(form);
        assert!(!app.vault_form_dirty());

        let t0 = std::time::Instant::now();
        assert_eq!(app.idle_lock_tick(t0, false), Some(crate::IDLE_LOCK_AFTER));
        assert_eq!(app.idle_lock_tick(t0 + crate::IDLE_LOCK_AFTER, false), None);
        assert!(app.vault.session.is_none());
        assert!(app.vault.form.is_none());
        assert_eq!(
            app.vault.error.as_deref(),
            Some(crate::idle_locked_msg().as_str())
        );
    }

    #[test]
    fn typing_restarts_both_clocks() {
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        app.security_keys.session = Some(fido_session("123456"));
        app.security_keys.session_device = Some(KEY.into());
        let mut form = EntryForm::for_add(shown_ref(&app));
        form.title.push_str("Mail");
        app.vault.form = Some(form);

        let t0 = std::time::Instant::now();
        app.idle_lock_tick(t0, false);
        assert_eq!(
            app.idle_lock_tick(t0 + 4 * MIN, true),
            Some(crate::IDLE_LOCK_AFTER)
        );
        assert_eq!(app.idle_lock_tick(t0 + 8 * MIN, false), Some(MIN));
        assert!(app.security_keys.session.is_some(), "input restarted it");
        // 5 minutes after the input: the FIDO2 tab locks; the vault has 10
        // more.
        assert_eq!(app.idle_lock_tick(t0 + 9 * MIN, false), Some(10 * MIN));
        assert!(app.security_keys.session.is_none());
        assert!(app.vault.session.is_some());
        // Typing in the form restarts the vault's 15 minutes.
        assert_eq!(
            app.idle_lock_tick(t0 + 18 * MIN, true),
            Some(crate::VAULT_EDIT_IDLE_LOCK_AFTER)
        );
        assert_eq!(app.idle_lock_tick(t0 + 32 * MIN, false), Some(MIN));
        assert!(app.vault.session.is_some());
        // A running operation postpones the lock, as for every other pane.
        app.busy_jobs = 1;
        assert_eq!(
            app.idle_lock_tick(t0 + 40 * MIN, false),
            Some(std::time::Duration::from_secs(1))
        );
        assert!(app.vault.session.is_some(), "never mid-operation");
        app.busy_jobs = 0;
        assert_eq!(app.idle_lock_tick(t0 + 40 * MIN, false), None);
        assert!(app.vault.session.is_none());
    }

    #[test]
    fn a_job_past_both_deadlines_logs_the_vaults_lock_too() {
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        app.security_keys.session = Some(fido_session("123456"));
        app.security_keys.session_device = Some(KEY.into());
        let mut form = EntryForm::for_add(shown_ref(&app));
        form.title.push_str("Mail");
        app.vault.form = Some(form);

        let t0 = std::time::Instant::now();
        app.idle_lock_tick(t0, false);
        app.busy_jobs = 1;
        let late = t0 + crate::VAULT_EDIT_IDLE_LOCK_AFTER + MIN;
        app.idle_lock_tick(late, false);
        assert!(app.vault.session.is_some() && app.security_keys.session.is_some());
        app.busy_jobs = 0;
        assert_eq!(app.idle_lock_tick(late, false), None);

        assert!(app.security_keys.session.is_none());
        assert_eq!(app.security_keys.error, Some(crate::idle_locked_msg()));
        assert!(app.vault.session.is_none() && app.vault.form.is_none());
        assert_eq!(
            app.vault.error,
            Some(crate::idle_locked_msg_for(
                crate::VAULT_EDIT_IDLE_LOCK_AFTER
            ))
        );
        let texts: Vec<&str> = app.log.iter().map(|l| l.text.as_str()).collect();
        assert!(texts.contains(&"Locked after 5 minutes of inactivity."));
        assert!(
            texts.contains(&"Vault: Locked after 15 minutes of inactivity."),
            "the log matches the Vault tab"
        );
        assert_eq!(idle_lines(&app), 2);
    }

    #[test]
    fn the_existing_idle_messages_are_unchanged() {
        assert_eq!(crate::VAULT_EDIT_IDLE_LOCK_AFTER.as_secs(), 15 * 60);
        assert_eq!(crate::idle_lock_span(), "5 minutes");
        assert_eq!(crate::span_words(crate::IDLE_LOCK_AFTER), "5 minutes");
        assert_eq!(crate::span_words(MIN), "1 minute");
        assert_eq!(
            crate::span_words(std::time::Duration::from_secs(75)),
            "75 seconds"
        );
        assert_eq!(
            crate::span_words(crate::VAULT_EDIT_IDLE_LOCK_AFTER),
            "15 minutes"
        );
        assert_eq!(
            crate::idle_locked_msg(),
            "Locked after 5 minutes of inactivity \u{2014} unlock again to continue."
        );
        assert_eq!(
            crate::idle_locked_msg(),
            crate::idle_locked_msg_for(crate::IDLE_LOCK_AFTER)
        );
        assert_eq!(
            crate::idle_locked_msg_for(crate::VAULT_EDIT_IDLE_LOCK_AFTER),
            "Locked after 15 minutes of inactivity \u{2014} unlock again to continue."
        );
        assert_eq!(
            crate::idle_hidden_msg(),
            "Codes hidden after 5 minutes of inactivity."
        );
        assert_eq!(
            crate::idle_closed_msg(),
            "Closed after 5 minutes of inactivity."
        );
    }

    #[test]
    fn vault_state_lists_every_secret_field() {
        let mut key = FakeKey::new();
        let mut app = super::tests::app();
        opened_into(&mut app, &mut key);
        let vault = shown_ref(&app);
        *app.vault.pin_input = "1234".into();
        let mut form = EntryForm::for_add(vault.clone());
        for s in [
            &mut form.title,
            &mut form.username,
            &mut form.password,
            &mut form.url,
            &mut form.notes,
        ] {
            s.push_str("typed");
        }
        app.vault.form = Some(form);
        app.vault.export = Some(export_dialog(vault));
        import_dialog(&mut app).passphrase.push_str(IMPORT_PASS);
        // Not secrets: the filter and a new vault's name.
        app.vault.filter = "git".into();
        app.vault.new_vault = Some("Work".into());

        assert_eq!(app.vault.secrets_mut().len(), 1 + 5 + 2 + 1);
        assert_eq!(
            app.typed_secrets().len(),
            app.typed_secrets_outside_vault().len() + 9,
            "the app's list is the outside list plus the vault's"
        );
        assert!(!app.typed_secrets_outside_vault().is_empty());
        app.vault.wipe_typed();
        assert!(app.vault.pin_input.is_empty());
        let f = app.vault.form.as_ref().unwrap();
        for s in [&f.title, &f.username, &f.password, &f.url, &f.notes] {
            assert!(s.is_empty());
        }
        let d = app.vault.export.as_ref().unwrap();
        assert!(d.passphrase.is_empty() && d.repeat.is_empty());
        assert!(app.vault.import.as_ref().unwrap().passphrase.is_empty());
        assert_eq!(app.vault.filter, "git");
        assert_eq!(app.vault.new_vault.as_deref(), Some("Work"));
        assert!(app.typed_secrets().iter().all(|s| s.is_empty()));
    }

    #[test]
    fn vault_lock_rebuilds_the_state() {
        let mut key = FakeKey::new();
        let mut app = super::tests::app();
        let id = opened_into(&mut app, &mut key);
        let vault = shown_ref(&app);
        app.vault.info = Some("Entry \"x\" added.".into());
        *app.vault.pin_input = "1234".into();
        app.vault.selected = Some(id);
        app.vault.filter = "git".into();
        app.vault.open_entry = Some("ghghghgh".into());
        app.vault.revealed = Some("ghghghgh".into());
        app.vault.copied = Some(("ghghghgh:p".into(), 1.0));
        app.vault.form = Some(EntryForm::for_add(vault.clone()));
        app.vault.gen.length = 32;
        app.vault.gen_open = true;
        app.vault.confirm = Some(VaultConfirm::Rotate {
            vault: vault.clone(),
        });
        app.vault.new_vault = Some("Work".into());
        app.vault.export_for = Some(vault.clone());
        app.vault.export = Some(export_dialog(vault));
        app.vault.import_asked = true;
        let cell = app.vault.progress.clone();

        app.vault_lock(Some("Locked.".into()));

        // Destructured, so a new field has to say what a lock does to it.
        let VaultState {
            error,
            info,
            session,
            pin_input,
            progress,
            selected,
            filter,
            open_entry,
            revealed,
            copied,
            form,
            gen,
            gen_open,
            confirm,
            scroll_to_confirm,
            new_vault,
            export_for,
            export,
            import_asked,
            import,
        } = &app.vault;
        assert_eq!(error.as_deref(), Some("Locked."));
        assert!(info.is_none());
        assert!(session.is_none());
        assert!(pin_input.is_empty());
        assert!(Arc::ptr_eq(progress, &cell), "kept: a running job's prompt");
        assert!(selected.is_none());
        assert!(filter.is_empty());
        assert!(open_entry.is_none());
        assert!(revealed.is_none());
        assert!(copied.is_none());
        assert!(form.is_none());
        assert_eq!(gen.length, 32, "kept: the generator's settings");
        assert!(!gen_open);
        assert!(confirm.is_none());
        assert!(!scroll_to_confirm);
        assert!(new_vault.is_none());
        assert!(export_for.is_none());
        assert!(export.is_none());
        assert!(!import_asked);
        assert!(import.is_none());
    }

    // ----- the list: space, rows, copy, Show -----

    use crate::{clear_if_still_held, clipboard_clear_for};

    fn cap(used: u64, max: u64) -> BlobCapacity {
        BlobCapacity {
            max_bytes: max,
            used_bytes: used,
            free_bytes: max - used,
            entry_count: 1,
        }
    }

    fn login(title: &str, username: &str, password: &str) -> Entry {
        let mut e = entry(title);
        e.username = username.into();
        e.password = Zeroizing::new(password.into());
        e
    }

    #[test]
    fn kb_and_space_line() {
        assert_eq!(kb(1331), "1.3");
        assert_eq!(kb(4096), "4");
        assert_eq!(kb(0), "0");
        // 2725 free at 60 bytes an entry: room for 45.
        assert_eq!(TYPICAL_ENTRY_BYTES, 60);
        assert_eq!(
            space_line(&cap(1371, 4096)),
            "1.3 of 4 KB used \u{00B7} room for about 45 more entries"
        );
        assert_eq!(
            space_line(&cap(4000, 4096)),
            "3.9 of 4 KB used \u{00B7} room for about 1 more entry"
        );
        assert_eq!(space_line(&cap(4050, 4096)), "4 of 4 KB used \u{00B7} full");
    }

    /// The "room for about N" number of the session's store.
    fn room(app: &App) -> u64 {
        app.vault_session().unwrap().unlocked.capacity.free_bytes / TYPICAL_ENTRY_BYTES
    }

    /// The room line follows only the free space: it never rises after an
    /// add or falls after a delete, whatever the entries hold.
    #[test]
    fn room_falls_with_adds_and_rises_with_deletes() {
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        let mut last = room(&app);
        let start = last;
        for i in 0..6 {
            app.vault_add_entry();
            let f = form(&mut app);
            replace_text(
                &mut f.title,
                &format!("Site {i} {}", keyroost_vault::new_id()),
            );
            replace_text(&mut f.username, &format!("user{i}@example.com"));
            replace_text(&mut f.password, &keyroost_vault::new_id());
            if i % 2 == 0 {
                replace_text(&mut f.notes, &keyroost_vault::new_id().repeat(i + 1));
            }
            save_form(&mut app, &mut key);
            let now = room(&app);
            assert!(now <= last, "add {i}: {now} after {last}");
            last = now;
        }
        assert!(last < start, "six adds use room");
        let ids: Vec<String> = app
            .selected_vault()
            .unwrap()
            .state
            .as_ref()
            .unwrap()
            .contents
            .entries
            .iter()
            .map(|e| e.id.clone())
            .collect();
        for id in ids.iter().take(5) {
            delete_by_id(&mut app, &mut key, id);
            let now = room(&app);
            assert!(now >= last, "delete: {now} after {last}");
            last = now;
        }
        let shown = space_line(&app.vault_session().unwrap().unlocked.capacity);
        assert!(
            shown.ends_with(&format!("room for about {last} more entries")),
            "{shown}"
        );
    }

    #[test]
    fn changed_ago_words() {
        const DAY: i64 = 24 * 60;
        // 2026-11-26, noon UTC.
        let now = 20_783 * DAY + 12 * 60;
        assert_eq!(changed_ago(now, now).as_deref(), Some("changed today"));
        assert_eq!(
            changed_ago(now - DAY + 5, now).as_deref(),
            Some("changed today")
        );
        assert_eq!(
            changed_ago(now - DAY, now).as_deref(),
            Some("changed yesterday")
        );
        assert_eq!(
            changed_ago(now - 3 * DAY, now).as_deref(),
            Some("changed 3 days ago")
        );
        assert_eq!(
            changed_ago(now - 59 * DAY, now).as_deref(),
            Some("changed 59 days ago")
        );
        assert_eq!(
            changed_ago(now - 60 * DAY, now).as_deref(),
            Some("changed on 2026-09-27")
        );
        // A time from a clock ahead of this one: the date.
        assert_eq!(
            changed_ago(now + 2 * DAY, now).as_deref(),
            Some("changed on 2026-11-28")
        );
        assert_eq!(
            changed_ago(now + 5, now).as_deref(),
            Some("changed on 2026-11-26")
        );
        assert_eq!(changed_ago(0, now), None, "no time recorded");
        assert_eq!(changed_ago(-5, now), None);
    }

    #[test]
    fn filter_never_searches_notes_or_passwords() {
        let mut e = login("GitHub", "Alice", "hunter22");
        e.url = "https://github.com/login".into();
        e.notes = "recovery: tulip-garden".into();
        for hit in ["", "  ", "git", "HUB", "alice", "LIC", "github.com/log"] {
            assert!(matches_filter(&e, hit), "{hit:?}");
        }
        for miss in ["hunter", "tulip", "recovery", "bank"] {
            assert!(!matches_filter(&e, miss), "{miss:?}");
        }
        // Case folds beyond ASCII.
        let e = login("Ärzte", "", "x");
        assert!(matches_filter(&e, "ärz"));
    }

    #[test]
    fn rows_sort_by_title_then_username() {
        let v = Vault {
            entries: vec![
                login("bank", "zed", "1"),
                login("GitHub", "bob", "2"),
                login("Bank", "amy", "3"),
                login("apple", "x", "4"),
                login("github", "Alice", "5"),
            ],
        };
        let order = |filter: &str| -> Vec<String> {
            shown_rows(&v, filter)
                .into_iter()
                .map(|i| format!("{}/{}", v.entries[i].title, v.entries[i].username))
                .collect()
        };
        assert_eq!(
            order(""),
            [
                "apple/x",
                "Bank/amy",
                "bank/zed",
                "github/Alice",
                "GitHub/bob"
            ]
        );
        assert_eq!(order("git"), ["github/Alice", "GitHub/bob"]);
        assert!(order("nothing").is_empty());

        // The row: title, username and the URL's host, empty parts left out.
        let mut e = login("GitHub", "alice", "x");
        e.url = "https://alice:pw@github.com:443/login?next=1".into();
        assert_eq!(
            row_line(&e).as_str(),
            "GitHub \u{00B7} alice \u{00B7} github.com:443"
        );
        let mut e = login("Router", "admin", "x");
        e.url = "192.168.1.1/admin".into();
        assert_eq!(
            row_line(&e).as_str(),
            "Router \u{00B7} admin \u{00B7} 192.168.1.1"
        );
        let e = login("Router", "", "x");
        assert_eq!(row_line(&e).as_str(), "Router");
        // Another program's control characters can't break the row.
        let e = login("a\u{1b}[2Jb\u{85}c", "", "x");
        let line = row_line(&e);
        assert_eq!(line.as_str(), "a [2Jb c");
        assert_eq!(line_title_len(&e, &line), line.len());
    }

    /// A key whose Personal vault holds two "GitHub" logins; its ID and
    /// the two entries' IDs.
    fn two_githubs(key: &mut FakeKey) -> (Vec<u8>, String, String) {
        let a = login("GitHub", "alice", "pw-a");
        let b = login("GitHub", "bob", "pw-b");
        let (ia, ib) = (a.id.clone(), b.id.clone());
        let c = login("Router", "", "pw-c");
        let p = key.add_vault(
            "Personal",
            &Vault {
                entries: vec![a, b, c],
            },
        );
        key.add_vault("Work", &Vault::default());
        (p, ia, ib)
    }

    #[test]
    fn duplicate_titles_copy_their_own_password() {
        let mut key = FakeKey::new();
        let (_, a, b) = two_githubs(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        let text = |what| app.vault_copy_text(&b, what).map(|t| t.as_str().to_owned());
        assert_eq!(text(CopyWhat::Password).as_deref(), Some("pw-b"));
        assert_eq!(text(CopyWhat::Username).as_deref(), Some("bob"));
        assert_eq!(
            app.vault_copy_text(&a, CopyWhat::Password)
                .as_deref()
                .map(String::as_str),
            Some("pw-a")
        );
        // The empty username copies nothing (its button is disabled).
        let open = app.selected_vault().unwrap().state.as_ref().unwrap();
        let router = open.contents.entries[2].id.clone();
        assert_eq!(app.vault_copy_text(&router, CopyWhat::Username), None);
        assert!(app
            .vault_copy_text("no-such-id", CopyWhat::Password)
            .is_none());
        assert_eq!(CopyWhat::Username.flash_key(&a), format!("{a}:u"));
        assert_eq!(CopyWhat::Password.flash_key(&a), format!("{a}:p"));
    }

    #[test]
    fn selection_follows_the_credential_id() {
        assert_eq!(selected_index(&[], None), None);
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        key.add_vault("Home", &Vault::default());
        let mut app = app();
        unlock_into(&mut app, &mut key);
        let name = |app: &App| app.selected_vault().unwrap().vault_ref.name.clone();
        assert_eq!(
            name(&app).as_deref(),
            Some("Personal"),
            "the first by default"
        );
        let work = app.vault_session().unwrap().unlocked.vaults[1]
            .vault_ref
            .credential_id
            .clone();
        app.vault_select(work);
        assert_eq!(name(&app).as_deref(), Some("Work"));
        // A vault before it leaves the list: still Work.
        app.vault
            .session
            .as_mut()
            .unwrap()
            .unlocked
            .vaults
            .remove(0);
        assert_eq!(name(&app).as_deref(), Some("Work"));
        // Work itself gone: the first vault, with nothing of Work left
        // open or shown.
        app.vault.open_entry = Some("w1".into());
        app.vault.revealed = Some("w1".into());
        app.vault
            .session
            .as_mut()
            .unwrap()
            .unlocked
            .vaults
            .remove(0);
        assert_eq!(name(&app).as_deref(), Some("Home"));
        app.vault_fix_selection();
        assert_eq!(app.vault.selected, None);
        assert_eq!(app.vault.open_entry, None);
        assert_eq!(app.vault.revealed, None);
        // A listed selection is kept as it is.
        let home = app.vault_session().unwrap().unlocked.vaults[0]
            .vault_ref
            .credential_id
            .clone();
        app.vault_select(home.clone());
        app.vault.open_entry = Some("h1".into());
        app.vault_fix_selection();
        assert_eq!(app.vault.selected, Some(home));
        assert_eq!(app.vault.open_entry.as_deref(), Some("h1"));
    }

    #[test]
    fn unavailable_vault_disables_every_write() {
        let mut app = app();
        assert!(!app.vault_writable(), "locked");
        let mut key = FakeKey::new();
        let (_, a, _) = two_githubs(&mut key);
        let damaged = key.add_vault("Old", &Vault::default());
        key.put_blob(&damaged, b"not a vault at all, just bytes");
        unlock_into(&mut app, &mut key);
        assert!(app.vault_writable(), "Personal opened");
        app.vault_select(damaged);
        let shown = app.selected_vault().unwrap();
        assert!(shown.state.is_err(), "{:?}", shown.state);
        assert_eq!(chip_label(shown), "Old \u{00B7} (unavailable)");
        assert!(!app.vault_writable());
        assert!(app.vault_copy_text(&a, CopyWhat::Password).is_none());
    }

    #[test]
    fn reveal_clears_on_collapse_and_chip_change() {
        let mut key = FakeKey::new();
        let (_, a, b) = two_githubs(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);

        app.vault_toggle_entry(&a);
        assert_eq!(app.vault.open_entry.as_deref(), Some(a.as_str()));
        app.vault.revealed = Some(a.clone());
        app.vault_toggle_entry(&a);
        assert_eq!(app.vault.open_entry, None, "closed");
        assert_eq!(app.vault.revealed, None);

        app.vault_toggle_entry(&a);
        app.vault.revealed = Some(a.clone());
        app.vault_toggle_entry(&b);
        assert_eq!(app.vault.open_entry.as_deref(), Some(b.as_str()));
        assert_eq!(app.vault.revealed, None, "another opened");

        app.vault.revealed = Some(b.clone());
        let work = app.vault_session().unwrap().unlocked.vaults[1]
            .vault_ref
            .credential_id
            .clone();
        app.vault_select(work);
        assert_eq!(app.vault.revealed, None, "the chip changed");
        assert_eq!(app.vault.open_entry, None);

        app.vault.open_entry = Some(b.clone());
        app.vault.revealed = Some(b.clone());
        app.vault.filter = "git".into();
        app.vault_lock(None);
        assert_eq!(app.vault.revealed, None, "locked");
        assert_eq!(app.vault.open_entry, None);
        assert!(app.vault.filter.is_empty());
        assert!(app.vault.selected.is_none());
    }

    #[test]
    fn clear_only_when_the_clipboard_still_holds_it() {
        let mut cleared = false;
        assert!(clear_if_still_held(
            "pw-a",
            || Some("pw-a".to_owned()),
            || cleared = true
        ));
        assert!(cleared);

        let mut cleared = false;
        assert!(!clear_if_still_held(
            "pw-a",
            || Some("copied elsewhere".to_owned()),
            || cleared = true
        ));
        assert!(!cleared, "someone else's text stays");

        let mut cleared = false;
        assert!(!clear_if_still_held("pw-a", || None, || cleared = true));
        assert!(!cleared, "an unreadable clipboard is left alone");
    }

    #[test]
    fn copying_schedules_the_clear_45_seconds_out() {
        let c = clipboard_clear_for("x".to_owned(), 100.0, true);
        assert_eq!(c.at, 145.0);
        assert_eq!(c.text.as_str(), "x");
        assert!(c.from_vault);
        assert!(!clipboard_clear_for("x".to_owned(), 0.0, false).from_vault);
    }

    #[test]
    fn a_vault_copy_is_marked_as_the_vaults() {
        // No clipboard handle in a test: the copy takes egui's path.
        let mut key = FakeKey::new();
        let (_, a, _) = two_githubs(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        let ctx = egui::Context::default();
        app.vault_copy(&ctx, &a, CopyWhat::Password, 100.0);
        let c = app.clipboard_clear_at.as_ref().expect("a clear scheduled");
        assert!(c.from_vault, "Lock clears it");
        assert_eq!(c.text.as_str(), "pw-a");
        assert_eq!(
            app.vault.copied,
            Some((format!("{a}:p"), 100.0 + COPIED_FLASH_SECS))
        );
        assert!(app.secret_clipboard.is_none(), "no real clipboard opened");
        app.vault_lock(None);
        assert!(app.clipboard_clear_at.is_none());
    }

    #[test]
    fn lock_clears_a_vault_copy_now() {
        // No clipboard handle in a test: the clear reads nothing and touches
        // no real clipboard.
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        app.clipboard_clear_at = Some(clipboard_clear_for("pw".into(), 1e12, true));
        app.vault_lock(None);
        assert!(
            app.clipboard_clear_at.is_none(),
            "a vault copy goes at Lock"
        );
        assert!(app.secret_clipboard.is_none(), "no real clipboard opened");

        // Someone else's copy (an Authenticator code) keeps its 45 s.
        unlock_into(&mut app, &mut key);
        app.clipboard_clear_at = Some(clipboard_clear_for("123456".into(), 1e12, false));
        app.vault_lock(None);
        assert!(app.clipboard_clear_at.is_some());
        app.clear_vault_clipboard_now();
        assert!(app.clipboard_clear_at.is_some());

        app.clipboard_clear_at = Some(clipboard_clear_for("pw".into(), 1e12, true));
        app.clear_vault_clipboard_now();
        assert!(app.clipboard_clear_at.is_none());
    }

    /// The text one headless frame of the list draws.
    fn list_text(app: &mut App) -> String {
        use crate::tests::TestFrame;
        use crate::ui::theme::Mode;
        fn collect(shape: &egui::Shape, text: &mut String) {
            match shape {
                egui::Shape::Text(t) => {
                    text.push_str(t.galley.text());
                    text.push('\n');
                }
                egui::Shape::Vec(shapes) => shapes.iter().for_each(|s| collect(s, text)),
                _ => {}
            }
        }
        let ctx = egui::Context::default();
        theme::install_fonts(&ctx);
        let palette = Palette::new(Mode::Dark, Palette::ACCENTS[0], false);
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(900.0, 700.0),
            )),
            ..Default::default()
        };
        let output = ctx.test_frame(input, |ui| {
            egui::CentralPanel::default().show(ui, |ui| {
                app.render_vault_list(ui, &palette);
            });
        });
        let mut text = String::new();
        for clipped in output.shapes {
            collect(&clipped.shape, &mut text);
        }
        text
    }

    #[test]
    fn the_list_draws_rows_and_hides_the_password_until_show() {
        let mut key = FakeKey::new();
        let (_, a, _) = two_githubs(&mut key);
        let damaged = key.add_vault("Old", &Vault::default());
        key.put_blob(&damaged, b"not a vault at all, just bytes");
        let mut app = app();
        unlock_into(&mut app, &mut key);
        if let Some(e) = app.vault.session.as_mut().and_then(|s| {
            s.unlocked.vaults[0]
                .state
                .as_mut()
                .ok()?
                .contents
                .entries
                .first_mut()
        }) {
            e.url = "https://github.com/login".into();
            e.notes = "recovery: tulip-garden".into();
        }

        let text = list_text(&mut app);
        for shown in [
            "Personal \u{00B7} 3",
            "Work \u{00B7} 0",
            "Old \u{00B7} (unavailable)",
            "KB used",
            "GitHub \u{00B7} alice \u{00B7} github.com",
            "Copy username",
            "Copy password",
            "A vault lives only on this key",
        ] {
            assert!(text.contains(shown), "{shown:?} in {text}");
        }
        assert!(!text.contains("tulip"), "notes show only when opened");

        app.vault_toggle_entry(&a);
        let text = list_text(&mut app);
        assert!(text.contains("tulip-garden"), "notes shown when opened");
        assert!(
            text.contains("Show") && text.contains("changed on"),
            "{text}"
        );
        assert!(!text.contains("pw-a"), "the password stays hidden");
        app.vault.revealed = Some(a.clone());
        let text = list_text(&mut app);
        assert!(text.contains("pw-a") && text.contains("Hide"), "{text}");

        app.vault.filter = "nothing like it".into();
        assert!(list_text(&mut app).contains("No entries match the filter."));

        app.vault_select(damaged);
        let text = list_text(&mut app);
        assert!(
            text.contains("This vault can't be opened: ") && text.contains("It is left as it is."),
            "{text}"
        );
        assert!(!text.contains("Copy password"));
    }

    // ----- add and edit, the generator, saving -----

    use crate::blob_space_line;
    use keyroost_transport::vault::{Change, OpenVault};

    /// The shown vault's reference (Personal after `two_vaults`).
    fn shown_ref(app: &App) -> VaultRef {
        app.selected_vault().unwrap().vault_ref.clone()
    }

    /// The shown vault's entry titled `title`, as the session holds it.
    fn session_entry(app: &App, title: &str) -> Entry {
        let open = app.selected_vault().unwrap().state.as_ref().unwrap();
        open.contents
            .entries
            .iter()
            .find(|e| e.title == title)
            .unwrap()
            .clone()
    }

    /// Save `change` as the job does (against `key`), and land it as the
    /// apply does.
    fn save_into(
        app: &mut App,
        key: &mut FakeKey,
        vault: VaultRef,
        kind: SaveKind,
        change: Change,
    ) {
        let (mut auth, mut open): (VaultAuth, OpenVault) = app
            .vault_take_for_save(&vault)
            .expect("an open vault and its auth");
        assert!(
            app.vault_session().unwrap().auth.is_none(),
            "the job holds it"
        );
        let result = {
            let mut touches = TouchProgress::new(Arc::new(Mutex::new(None)), 0);
            run_save(key, &mut auth, &mut open, &change, &mut touches).map_err(VaultJobError::from)
        };
        app.vault_apply_save(Some(KEY.into()), vault, kind, auth, open, result);
    }

    /// Press Save on the open form, the job running against `key`.
    fn save_form(app: &mut App, key: &mut FakeKey) {
        let (vault, kind, change) = app.vault_form_change().expect("a form that validates");
        save_into(app, key, vault, kind, change);
    }

    fn form(app: &mut App) -> &mut EntryForm {
        app.vault.form.as_mut().expect("the form is open")
    }

    /// A hook that stores `vault` as credential `id`'s data: another writer.
    fn writes_elsewhere(
        id: Vec<u8>,
        vault: Vault,
    ) -> Option<(usize, keyroost_transport::vault::fake::Hook)> {
        Some((1, Box::new(move |k: &mut FakeKey| k.put_vault(&id, &vault))))
    }

    const CONFLICT_NOTICE: &str = "This entry changed on the key since the vault was opened; \
                                   nothing was written. Check it and save again.";

    #[test]
    fn add_saves_and_closes_the_form() {
        let mut key = FakeKey::new();
        let p = two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        app.vault_add_entry();
        {
            let f = form(&mut app);
            assert!(f.editing.is_none());
            f.title.push_str("GitHub");
            f.username.push_str("carol");
            f.password.push_str("s3cret-pw");
            f.notes.push_str("recovery: tulip");
        }
        save_form(&mut app, &mut key);

        let on_key = key.vault_on_key(&p).unwrap();
        assert_eq!(on_key.entries.len(), 3);
        let added = on_key
            .entries
            .iter()
            .find(|e| e.username == "carol")
            .unwrap();
        assert_eq!(added.title, "GitHub");
        assert_eq!(*added.password, "s3cret-pw");
        assert_eq!(added.notes, "recovery: tulip");
        assert!(app.vault.form.is_none(), "the form closes");
        assert_eq!(
            app.vault.info.as_deref(),
            Some("Entry \"GitHub\" added to vault \"Personal\".")
        );
        assert!(app
            .log
            .iter()
            .any(|l| l.text == "Vault: entry added to vault \"Personal\""));
        for l in &app.log {
            assert!(
                !l.text.contains("GitHub")
                    && !l.text.contains("carol")
                    && !l.text.contains("tulip"),
                "{}",
                l.text
            );
        }
        // The list shows it, and the session can save again.
        assert_eq!(app.selected_vault().unwrap().entry_count(), Some(3));
        assert!(app.vault_session().unwrap().auth.is_some());
        // A save asks for no touch.
        assert!(!key
            .log
            .iter()
            .skip_while(|c| **c != Call::Read)
            .any(|c| matches!(c, Call::Assertions(_) | Call::MakeCredential)));
    }

    #[test]
    fn edit_keeps_the_id() {
        let mut key = FakeKey::new();
        let p = two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        let github = session_entry(&app, "GitHub");
        app.vault_edit_entry(&github.id);
        {
            let f = form(&mut app);
            assert_eq!(f.title, "GitHub");
            assert_eq!(f.password, "hunter22");
            f.password.clear();
            f.password.push_str("new-pw");
        }
        save_form(&mut app, &mut key);

        let on_key = key.vault_on_key(&p).unwrap();
        assert_eq!(on_key.entries.len(), 2);
        let e = on_key.entries.iter().find(|e| e.id == github.id).unwrap();
        assert_eq!(*e.password, "new-pw");
        assert_eq!(e.title, "GitHub");
        assert!(app.vault.form.is_none());
        assert_eq!(app.vault.info.as_deref(), Some("Entry \"GitHub\" updated."));
        assert!(app
            .log
            .iter()
            .any(|l| l.text == "Vault: entry updated in vault \"Personal\""));
    }

    #[test]
    fn another_writers_change_to_a_different_entry_is_kept() {
        let mut key = FakeKey::new();
        let (a, b) = (
            login("GitHub", "alice", "pw-a"),
            login("Bank", "alice", "pw-b"),
        );
        let p = key.add_vault(
            "Personal",
            &Vault {
                entries: vec![a.clone(), b.clone()],
            },
        );
        let mut b2 = b.clone();
        b2.password = Zeroizing::new("theirs".into());
        key.hook = writes_elsewhere(
            p.clone(),
            Vault {
                entries: vec![a.clone(), b2.clone()],
            },
        );
        let mut app = app();
        unlock_into(&mut app, &mut key);
        app.vault_edit_entry(&a.id);
        form(&mut app).username.push_str("-mine");
        save_form(&mut app, &mut key);

        let on_key = key.vault_on_key(&p).unwrap();
        let find = |id: &str| on_key.entries.iter().find(|e| e.id == id).unwrap();
        assert_eq!(find(&a.id).username, "alice-mine");
        assert_eq!(
            *find(&b.id).password,
            "theirs",
            "the other writer's change is kept"
        );
        assert!(app.vault.form.is_none());
        // The list shows both changes.
        assert_eq!(*session_entry(&app, "Bank").password, "theirs");
    }

    #[test]
    fn edit_conflict_reloads_and_keeps_the_form() {
        let mut key = FakeKey::new();
        let (a, b) = (
            login("GitHub", "alice", "pw-a"),
            login("Bank", "alice", "pw-b"),
        );
        let p = key.add_vault(
            "Personal",
            &Vault {
                entries: vec![a.clone(), b.clone()],
            },
        );
        let mut a2 = a.clone();
        a2.password = Zeroizing::new("theirs".into());
        key.hook = writes_elsewhere(
            p.clone(),
            Vault {
                entries: vec![a2.clone(), b.clone()],
            },
        );
        let mut app = app();
        unlock_into(&mut app, &mut key);
        app.vault_edit_entry(&a.id);
        form(&mut app).username.push_str("-mine");
        let stored = key.stored().to_vec();
        save_form(&mut app, &mut key);

        assert_eq!(key.stored(), &stored[..], "nothing was written");
        // The list shows the key's copy.
        assert_eq!(*session_entry(&app, "GitHub").password, "theirs");
        let f = form(&mut app);
        assert_eq!(f.username, "alice-mine", "the typed values stay");
        assert_eq!(
            f.password, "theirs",
            "an untouched field takes the key's value"
        );
        assert_eq!(f.notice.as_deref(), Some(CONFLICT_NOTICE));
        assert_eq!(
            f.editing.as_ref().map(|e| e.password.as_str()),
            Some("theirs"),
            "re-based on the key's entry"
        );
        assert!(app.vault_session().unwrap().auth.is_some());

        // Saved again, it goes through, and the other program's password
        // survives.
        save_form(&mut app, &mut key);
        let on_key = key.vault_on_key(&p).unwrap();
        let e = on_key.entries.iter().find(|e| e.id == a.id).unwrap();
        assert_eq!(e.username, "alice-mine");
        assert_eq!(*e.password, "theirs");
        assert!(app.vault.form.is_none());
        assert_eq!(app.vault.info.as_deref(), Some("Entry \"GitHub\" updated."));
    }

    #[test]
    fn edit_of_an_entry_deleted_elsewhere_offers_to_add_it() {
        let mut key = FakeKey::new();
        let (a, b) = (
            login("GitHub", "alice", "pw-a"),
            login("Bank", "alice", "pw-b"),
        );
        let p = key.add_vault(
            "Personal",
            &Vault {
                entries: vec![a.clone(), b.clone()],
            },
        );
        key.hook = writes_elsewhere(
            p.clone(),
            Vault {
                entries: vec![b.clone()],
            },
        );
        let mut app = app();
        unlock_into(&mut app, &mut key);
        app.vault_edit_entry(&a.id);
        form(&mut app).password.push('!');
        save_form(&mut app, &mut key);

        let f = form(&mut app);
        assert!(f.editing.is_none());
        assert_eq!(
            f.notice.as_deref(),
            Some("This entry was deleted on the key; Save adds it again.")
        );
        assert_eq!(f.password, "pw-a!");
        assert_eq!(app.selected_vault().unwrap().entry_count(), Some(1));

        save_form(&mut app, &mut key);
        let on_key = key.vault_on_key(&p).unwrap();
        assert_eq!(on_key.entries.len(), 2);
        assert!(on_key
            .entries
            .iter()
            .any(|e| e.title == "GitHub" && *e.password == "pw-a!"));
        assert_eq!(
            app.vault.info.as_deref(),
            Some("Entry \"GitHub\" added to vault \"Personal\".")
        );
    }

    #[test]
    fn a_vault_gone_elsewhere_locks_the_session() {
        let mut key = FakeKey::new();
        let p = two_vaults(&mut key);
        let lbk = key.creds.iter().find(|c| c.id == p).unwrap().lbk.unwrap();
        key.hook = Some((
            1,
            Box::new(move |k: &mut FakeKey| {
                let rest = k.array().without_credential_blob(&lbk);
                k.set_array(&rest);
            }),
        ));
        let mut app = app();
        unlock_into(&mut app, &mut key);
        app.vault_add_entry();
        form(&mut app).title.push_str("Mail");
        save_form(&mut app, &mut key);

        assert!(app.vault.session.is_none(), "locked");
        assert!(app.vault.form.is_none(), "the form went with it");
        let err = app.vault.error.as_deref().unwrap();
        assert!(
            err.starts_with("Vault \"Personal\" is no longer on the key")
                && err.ends_with(UNLOCK_AGAIN),
            "{err}"
        );
    }

    #[test]
    fn full_store_refuses_and_keeps_the_form() {
        let mut key = FakeKey::new();
        key.set_max_bytes(1024);
        let p = two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        let stored = key.stored().to_vec();
        app.vault_add_entry();
        // Random text, so it does not compress below the limit.
        let notes: String = (0..250).map(|_| keyroost_vault::new_id()).collect();
        {
            let f = form(&mut app);
            f.title.push_str("Recovery codes");
            f.notes.push_str(&notes);
        }
        save_form(&mut app, &mut key);

        assert_eq!(key.stored(), &stored[..], "nothing was written");
        assert_eq!(key.vault_on_key(&p).unwrap().entries.len(), 2);
        let f = form(&mut app);
        assert_eq!(f.title, "Recovery codes");
        assert_eq!(f.notes, notes);
        let err = app.vault.error.as_deref().unwrap();
        assert!(err.contains("too small") && err.contains("1024"), "{err}");
        assert!(app.vault_session().unwrap().auth.is_some());
    }

    #[test]
    fn a_save_leaving_under_a_quarter_free_logs_the_store_note() {
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        let notes_of = |app: &App| {
            app.log
                .iter()
                .filter(|l| l.severity == Severity::Warn && l.text.starts_with("Vault: "))
                .count()
        };
        let github = session_entry(&app, "GitHub");
        app.vault_edit_entry(&github.id);
        form(&mut app).password.push('1');
        save_form(&mut app, &mut key);
        assert_eq!(notes_of(&app), 0, "room left: no note");

        // The store shrinks to just over what the vault uses.
        let used = app.vault_session().unwrap().unlocked.capacity.used_bytes;
        key.set_max_bytes(used + 40);
        app.vault_edit_entry(&github.id);
        form(&mut app).password.push('2');
        save_form(&mut app, &mut key);
        assert!(app.vault.form.is_none(), "the save is never refused for it");
        let cap = app.vault_session().unwrap().unlocked.capacity;
        assert_eq!(
            cap.max_bytes,
            used + 40,
            "the session's capacity is the save's"
        );
        let line = blob_space_line("Vault", &cap).expect("under a quarter free");
        assert!(app
            .log
            .iter()
            .any(|l| l.severity == Severity::Warn && l.text == line));
        assert_eq!(notes_of(&app), 1);
    }

    #[test]
    fn storage_notes_still_say_storage() {
        let mut app = app();
        app.space_note("Storage", &cap(3500, 4096));
        let line = app.log.last().unwrap();
        assert_eq!(line.severity, Severity::Warn);
        assert_eq!(
            line.text,
            "Storage: the key's large-blob store is 85% full (3500 of 4096 bytes). \
             Websites that store data with their passkeys may have no room left."
        );
        let n = app.log.len();
        app.space_note("Vault", &cap(1000, 4096));
        assert_eq!(app.log.len(), n, "room left: no line");
    }

    #[test]
    fn empty_title_is_refused_before_the_key() {
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        app.vault_add_entry();
        {
            let f = form(&mut app);
            f.title.push_str("   ");
            f.password.push_str("pw");
            assert_eq!(f.change(0).unwrap_err(), "An entry needs a title.");
        }
        let calls = key.log.len();
        app.vault_save_form();
        assert_eq!(key.log.len(), calls);
        let f = form(&mut app);
        assert_eq!(f.notice.as_deref(), Some("An entry needs a title."));
        assert_eq!(f.password, "pw");
        assert!(
            app.vault_session().unwrap().auth.is_some(),
            "auth not taken"
        );
        assert!(!app.busy());
    }

    #[test]
    fn form_dirty_tracks_changes() {
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        let v = shown_ref(&app);
        let mut add = EntryForm::for_add(v.clone());
        assert!(!add.is_dirty());
        add.show_password = true;
        assert!(!add.is_dirty(), "Show isn't a change");
        add.notes.push('x');
        assert!(add.is_dirty());

        let github = session_entry(&app, "GitHub");
        let mut edit = EntryForm::for_edit(v, &github);
        assert!(!edit.is_dirty());
        edit.url.push_str("https://github.com");
        assert!(edit.is_dirty());
        edit.url.clear();
        assert!(!edit.is_dirty(), "back to the entry as read");
        edit.title.push(' ');
        assert!(edit.is_dirty());

        // Add and Edit build the matching change, stamped with `now`.
        add.title.push_str("Mail");
        match add.change(42).unwrap() {
            Change::Add(e) => {
                assert_eq!(e.title, "Mail");
                assert_eq!(e.notes, "x");
                assert_eq!(e.modified_minutes, 42);
                assert!(!e.id.is_empty() && e.id != github.id);
            }
            other => panic!("{other:?}"),
        }
        match edit.change(43).unwrap() {
            Change::Edit { before, after } => {
                assert_eq!(before, github);
                assert_eq!(after.id, github.id);
                assert_eq!(after.title, "GitHub ");
                assert_eq!(after.modified_minutes, 43);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn generator_summary_and_length() {
        let mut o = keyroost_vault::GenOptions::default();
        assert_eq!(
            gen_summary(&o),
            "Generate: 20 characters \u{00B7} A\u{2013}Z a\u{2013}z 0\u{2013}9 symbols"
        );
        o.digits = false;
        o.length = 32;
        assert_eq!(
            gen_summary(&o),
            "Generate: 32 characters \u{00B7} A\u{2013}Z a\u{2013}z symbols"
        );
        // With every class off the generator uses lower case; so does the line.
        o.upper = false;
        o.lower = false;
        o.symbols = false;
        assert_eq!(
            gen_summary(&o),
            "Generate: 32 characters \u{00B7} a\u{2013}z"
        );

        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        assert_eq!(app.vault.gen, keyroost_vault::GenOptions::default());
        app.vault.gen.length = 32;
        app.vault.gen.symbols = false;
        app.vault_add_entry();
        form(&mut app).password.push_str("typed");
        app.vault_generate();
        let pw = form(&mut app).password.clone();
        assert_eq!(pw.chars().count(), 32);
        assert!(pw.chars().all(|c| c.is_ascii_alphanumeric()), "{pw}");
        app.vault_generate();
        assert_ne!(form(&mut app).password, pw);
        // The options outlive a lock; the form doesn't.
        app.vault_lock(None);
        assert_eq!(app.vault.gen.length, 32);
        assert!(!app.vault.gen.symbols);
        assert!(app.vault.form.is_none());
    }

    #[test]
    fn entry_form_lists_every_text_field_as_secret() {
        let mut f = EntryForm::for_add(VaultRef {
            credential_id: vec![1],
            name: Some("Personal".into()),
        });
        for (i, s) in [
            &mut f.title,
            &mut f.username,
            &mut f.password,
            &mut f.url,
            &mut f.notes,
        ]
        .into_iter()
        .enumerate()
        {
            s.push_str(&format!("value {i}"));
        }
        assert_eq!(f.secrets_mut().len(), 5);
        f.wipe_typed();
        for s in [&f.title, &f.username, &f.password, &f.url, &f.notes] {
            assert!(s.is_empty());
        }

        // The tab's own list carries the open form's fields too.
        let mut state = VaultState {
            form: Some(EntryForm::for_add(VaultRef {
                credential_id: vec![1],
                name: None,
            })),
            ..Default::default()
        };
        assert_eq!(state.secrets_mut().len(), 6);
    }

    #[test]
    fn cancel_closes_the_form_and_edit_needs_an_open_vault() {
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let damaged = key.add_vault("Old", &Vault::default());
        key.put_blob(&damaged, b"not a vault at all, just bytes");
        let mut app = app();
        unlock_into(&mut app, &mut key);
        app.vault_add_entry();
        form(&mut app).password.push_str("pw");
        app.vault_cancel_form();
        assert!(app.vault.form.is_none());

        app.vault_select(damaged);
        app.vault_add_entry();
        assert!(
            app.vault.form.is_none(),
            "a vault that can't be opened takes no entry"
        );
        app.vault_edit_entry("no-such-id");
        assert!(app.vault.form.is_none());
    }

    #[test]
    fn a_refused_pin_on_save_locks_the_vault() {
        for pin_from_fido in [false, true] {
            let mut key = FakeKey::new();
            two_vaults(&mut key);
            let mut app = app();
            unlock_into(&mut app, &mut key);
            app.vault.session.as_mut().unwrap().pin_from_fido = pin_from_fido;
            app.security_keys.session = Some(fido_session("123456"));
            app.vault_add_entry();
            form(&mut app).title.push_str("Mail");
            let (vault, kind, _) = app.vault_form_change().unwrap();
            let (auth, open) = app.vault_take_for_save(&vault).unwrap();
            app.vault_apply_save(
                Some(KEY.into()),
                vault,
                kind,
                auth,
                open,
                Err(VaultJobError::Vault(VaultKeyError::Ctap(
                    CtapError::StatusCode(0x31),
                ))),
            );
            assert!(
                app.vault.session.is_none(),
                "no retry spends another PIN try"
            );
            assert!(app.vault.error.is_some());
            assert_eq!(
                app.security_keys.session.is_none(),
                pin_from_fido,
                "the FIDO2 tab locks only when the PIN was its"
            );
        }
    }

    #[test]
    fn a_save_for_another_key_is_discarded() {
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        app.vault_add_entry();
        form(&mut app).title.push_str("Mail");
        let (vault, kind, change) = app.vault_form_change().unwrap();
        let (mut auth, mut open) = app.vault_take_for_save(&vault).unwrap();
        let mut touches = TouchProgress::new(Arc::new(Mutex::new(None)), 0);
        let result = run_save(&mut key, &mut auth, &mut open, &change, &mut touches)
            .map_err(VaultJobError::from);
        app.selected_device = Some("serial:BBB".into());
        let n = app.log.len();
        app.vault_apply_save(Some(KEY.into()), vault, kind, auth, open, result);
        assert_eq!(app.log.len(), n);
        assert!(app.vault.info.is_none());
    }

    #[test]
    fn the_form_draws_and_masks_the_password() {
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        app.vault_add_entry();
        form(&mut app).password.push_str("pw-typed");
        let text = list_text(&mut app);
        for shown in [
            "Add entry to \"Personal\"",
            "Title",
            "Username",
            "Password",
            "Generate: 20 characters",
            "change",
            "optional",
            "Saving writes the vault back to the key (already unlocked; no touch needed).",
            "Cancel",
            "Save",
        ] {
            assert!(text.contains(shown), "{shown:?} in {text}");
        }
        assert!(!text.contains("pw-typed"), "masked until Show");
        assert!(
            !text.contains("Copy password"),
            "the form replaces the list"
        );
        form(&mut app).show_password = true;
        assert!(list_text(&mut app).contains("pw-typed"));
        app.vault.gen_open = true;
        let text = list_text(&mut app);
        assert!(
            text.contains("symbols") && text.contains("0\u{2013}9"),
            "{text}"
        );

        app.vault_cancel_form();
        let github = session_entry(&app, "GitHub");
        app.vault_edit_entry(&github.id);
        assert!(list_text(&mut app).contains("Edit entry in \"Personal\""));
        app.vault_cancel_form();
        app.vault_toggle_entry(&github.id);
        let text = list_text(&mut app);
        assert!(
            text.contains("Add entry") && text.contains("Edit"),
            "{text}"
        );
    }

    #[test]
    fn a_field_changed_on_both_sides_is_named() {
        let mut key = FakeKey::new();
        let a = login("GitHub", "alice", "pw-a");
        let p = key.add_vault(
            "Personal",
            &Vault {
                entries: vec![a.clone()],
            },
        );
        let mut a2 = a.clone();
        a2.password = Zeroizing::new("theirs".into());
        a2.notes = "their notes".into();
        key.hook = writes_elsewhere(p.clone(), Vault { entries: vec![a2] });
        let mut app = app();
        unlock_into(&mut app, &mut key);
        app.vault_edit_entry(&a.id);
        {
            let f = form(&mut app);
            f.password.clear();
            f.password.push_str("mine");
        }
        save_form(&mut app, &mut key);
        let f = form(&mut app);
        assert_eq!(f.password, "mine", "the typed value stays");
        assert_eq!(f.notes, "their notes");
        assert_eq!(
            f.notice.as_deref(),
            Some(
                "This entry changed on the key since the vault was opened; nothing was \
                 written. The password was also changed elsewhere; yours will replace it. \
                 Check it and save again."
            )
        );
        save_form(&mut app, &mut key);
        let on_key = key.vault_on_key(&p).unwrap();
        assert_eq!(*on_key.entries[0].password, "mine");
        assert_eq!(on_key.entries[0].notes, "their notes");

        assert_eq!(changed_on_key(&[]), CONFLICT_NOTICE);
        assert!(changed_on_key(&["username", "password"]).contains(
            "The username and password were also changed elsewhere; yours will \
                       replace them."
        ));
        assert!(changed_on_key(&["title", "URL", "notes"])
            .contains("The title, URL and notes were also"));
    }

    #[test]
    fn every_save_kind_logs_the_store_note() {
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        let used = app.vault_session().unwrap().unlocked.capacity.used_bytes;
        key.set_max_bytes(used + 10);
        let bank = session_entry(&app, "Bank");
        let vault = shown_ref(&app);
        save_into(
            &mut app,
            &mut key,
            vault,
            SaveKind::Delete {
                title: Zeroizing::new("Bank".into()),
            },
            Change::Delete { before: bank },
        );
        assert_eq!(app.selected_vault().unwrap().entry_count(), Some(1));
        let cap = app.vault_session().unwrap().unlocked.capacity;
        assert!(cap.used_bytes < used, "the delete freed room");
        let line = blob_space_line("Vault", &cap).expect("still under a quarter free");
        assert!(app
            .log
            .iter()
            .any(|l| l.severity == Severity::Warn && l.text == line));
    }

    // ----- delete an entry -----

    /// Ask, confirm (the real confirm logic), then run the job against
    /// `key` and land it as the apply does.
    fn delete_by_id(app: &mut App, key: &mut FakeKey, id: &str) {
        app.vault_ask_delete_entry(id);
        let (vault, kind, change) = app.vault_take_delete().expect("a confirmed delete");
        assert!(app.vault.confirm.is_none());
        save_into(app, key, vault, kind, change);
    }

    #[test]
    fn the_question_stays_while_another_job_runs() {
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        let id = session_entry(&app, "Bank").id.clone();
        app.vault_ask_delete_entry(&id);
        app.busy_jobs = 1;
        app.busy_label = Some("Reading\u{2026}".into());
        assert!(app.vault_take_delete().is_none());
        assert!(matches!(
            app.vault.confirm,
            Some(VaultConfirm::DeleteEntry { .. })
        ));
        app.busy_jobs = 0;
        assert!(app.vault_take_delete().is_some());
    }

    #[test]
    fn an_entry_gone_before_confirm_writes_nothing() {
        let mut key = FakeKey::new();
        let p = two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        let id = session_entry(&app, "Bank").id.clone();
        app.vault_ask_delete_entry(&id);
        // A Refresh (or another writer) took it out of the session.
        {
            let s = app.vault_session_mut().unwrap();
            let v = s
                .unlocked
                .vaults
                .iter_mut()
                .find(|v| v.vault_ref.credential_id == p)
                .unwrap();
            v.state
                .as_mut()
                .unwrap()
                .contents
                .entries
                .retain(|e| e.id != id);
        }
        let stored = key.stored().to_vec();
        assert!(app.vault_take_delete().is_none());
        assert!(app.vault.confirm.is_none());
        assert_eq!(
            app.vault.error.as_deref(),
            Some("This entry is no longer in the vault; nothing was deleted.")
        );
        assert_eq!(key.stored(), &stored[..]);
        assert!(
            app.vault_session().unwrap().auth.is_some(),
            "auth untouched"
        );
    }

    #[test]
    fn delete_removes_only_that_entry() {
        let mut key = FakeKey::new();
        let (p, ia, ib) = two_githubs(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        app.vault.open_entry = Some(ia.clone());
        delete_by_id(&mut app, &mut key, &ia);
        // Named as its row: another entry is titled GitHub too.
        assert_eq!(
            app.vault.info.as_deref(),
            Some("Entry \"GitHub (alice)\" deleted.")
        );
        assert!(app.vault.open_entry.is_none());
        let on_key = key.vault_on_key(&p).unwrap();
        assert_eq!(on_key.entries.len(), 2);
        assert!(on_key.entries.iter().any(|e| e.id == ib));
        assert!(on_key.entries.iter().all(|e| e.id != ia));
        assert_eq!(app.selected_vault().unwrap().entry_count(), Some(2));
        assert!(app.log.iter().any(|l| l.severity == Severity::Ok
            && l.text == "Vault: entry deleted from vault \"Personal\""));
        assert!(app.log.iter().all(|l| !l.text.contains("GitHub")));
    }

    #[test]
    fn delete_of_a_changed_entry_is_refused_and_reloaded() {
        let mut key = FakeKey::new();
        let (a, b) = (
            login("GitHub", "alice", "pw-a"),
            login("Bank", "alice", "pw-b"),
        );
        let p = key.add_vault(
            "Personal",
            &Vault {
                entries: vec![a.clone(), b.clone()],
            },
        );
        let mut a2 = a.clone();
        a2.password = Zeroizing::new("changed-elsewhere".into());
        key.hook = writes_elsewhere(
            p.clone(),
            Vault {
                entries: vec![a2, b],
            },
        );
        let mut app = app();
        unlock_into(&mut app, &mut key);
        delete_by_id(&mut app, &mut key, &a.id);
        assert_eq!(
            app.vault.error.as_deref(),
            Some(
                "This entry changed on the key since the vault was opened; nothing was \
                 deleted. Check it and delete again."
            )
        );
        assert!(app.vault.info.is_none());
        assert_eq!(key.vault_on_key(&p).unwrap().entries.len(), 2);
        assert_eq!(*session_entry(&app, "GitHub").password, "changed-elsewhere");
        assert!(app.vault_session().unwrap().auth.is_some());
    }

    #[test]
    fn delete_asks_no_touch() {
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        let before = key.log.len();
        let id = session_entry(&app, "Bank").id.clone();
        delete_by_id(&mut app, &mut key, &id);
        assert!(key.log[before..]
            .iter()
            .all(|c| !matches!(c, Call::Assertions(_) | Call::MakeCredential)));
    }

    #[test]
    fn the_confirmation_is_the_cli_question() {
        assert_eq!(
            delete_entry_question("GitHub", "Personal", "yubi-test"),
            "Delete entry \"GitHub\" from vault \"Personal\" on yubi-test?"
        );
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut app = app();
        app.devices = vec![crate::tests::test_key(KEY, "AAA", Some("yubi-test"))];
        unlock_into(&mut app, &mut key);
        let id = session_entry(&app, "GitHub").id.clone();
        assert!(!list_text(&mut app).contains("This cannot be undone."));
        app.vault_ask_delete_entry(&id);
        let text = list_text(&mut app);
        assert!(
            text.contains("Delete entry \"GitHub\" from vault \"Personal\" on yubi-test?"),
            "{text}"
        );
        assert!(text.contains("This cannot be undone.") && text.contains("Cancel"));
        // Another vault's chip closes the question.
        let w = app.vault_session().unwrap().unlocked.vaults[1]
            .vault_ref
            .credential_id
            .clone();
        app.vault_select(w);
        assert!(app.vault.confirm.is_none());
    }

    // ----- new vault, delete vault, rotate the vault key -----

    use keyroost_ctap::client_pin::PinUvAuthToken as Token;
    use keyroost_transport::vault::{Created, VaultCredential};

    /// The fake key, noting what the touch banner says each time a touch
    /// is asked for (makeCredential, getAssertion).
    struct Watched<'a> {
        key: &'a mut FakeKey,
        banner: Arc<Mutex<Option<String>>>,
        at_touch: Vec<Option<String>>,
    }

    impl VaultKey for Watched<'_> {
        fn info(&self) -> &AuthenticatorInfo {
            self.key.info()
        }
        fn pin_token(
            &mut self,
            pin: &str,
            permissions: u32,
            rp_id: Option<&str>,
        ) -> Result<Token, CtapError> {
            self.key.pin_token(pin, permissions, rp_id)
        }
        fn uv_token(
            &mut self,
            permissions: u32,
            rp_id: Option<&str>,
            on_finger: &mut dyn FnMut(),
        ) -> Result<Token, CtapError> {
            // The key waits for the finger once `on_finger` has run, so the
            // banner shown then is the one this finger touch sees.
            let (at_touch, banner) = (&mut self.at_touch, &self.banner);
            self.key.uv_token(permissions, rp_id, &mut || {
                on_finger();
                at_touch.push(shown(banner));
            })
        }
        fn make_credential(
            &mut self,
            token: &Token,
            user_id: &[u8],
            name: &str,
        ) -> Result<keyroost_ctap::make_credential::MadeCredential, CtapError> {
            self.at_touch.push(shown(&self.banner));
            self.key.make_credential(token, user_id, name)
        }
        fn assertions(
            &mut self,
            token: &Token,
            allow: Option<&[u8]>,
        ) -> Result<Vec<keyroost_ctap::get_assertion::Assertion>, CtapError> {
            self.at_touch.push(shown(&self.banner));
            self.key.assertions(token, allow)
        }
        fn credentials(&mut self, token: &Token) -> Result<Vec<VaultCredential>, CtapError> {
            self.key.credentials(token)
        }
        fn delete_credential(&mut self, token: &Token, id: &[u8]) -> Result<(), CtapError> {
            self.key.delete_credential(token, id)
        }
        fn read_blobs(&mut self) -> Result<keyroost_ctap::large_blobs::LargeBlobArray, CtapError> {
            self.key.read_blobs()
        }
        fn write_blobs(&mut self, token: &Token, serialized: &[u8]) -> Result<(), CtapError> {
            self.key.write_blobs(token, serialized)
        }
    }

    /// Type `name` in the New vault box and press Create vault, the job
    /// running against `key`; what the banner said at each touch.
    fn create_into(app: &mut App, key: &mut FakeKey, name: &str) -> Vec<Option<String>> {
        app.vault.new_vault = Some(name.to_owned());
        let (name, mut auth) = app.vault_take_for_create().expect("a name that passes");
        assert!(
            app.vault_session().unwrap().auth.is_none(),
            "the job holds it"
        );
        let banner = Arc::new(Mutex::new(None));
        let mut watched = Watched {
            key,
            banner: banner.clone(),
            at_touch: Vec::new(),
        };
        let result = {
            let mut touches = TouchProgress::new(banner.clone(), 2);
            run_create(
                &mut watched,
                &mut auth,
                &name,
                &Vault::default(),
                &mut touches,
            )
            .map_err(VaultJobError::from)
        };
        assert_eq!(shown(&banner), None, "the prompt is down after the job");
        let seen = watched.at_touch;
        app.vault_apply_create(Some(KEY.into()), auth, None, result);
        seen
    }

    /// Confirm the waiting Delete vault (the real confirm logic) and run it
    /// against `key`.
    fn delete_vault_into(app: &mut App, key: &mut FakeKey) {
        let Some(VaultConfirm::DeleteVault { vault }) = app.vault_take_confirmed() else {
            panic!("a confirmed vault delete");
        };
        let mut auth = app.vault_take_auth().expect("the session's auth");
        let result = {
            let mut touches = TouchProgress::new(Arc::new(Mutex::new(None)), 1);
            run_delete_vault(key, &mut auth, &vault, &mut touches)
        };
        app.vault_apply_delete_vault(Some(KEY.into()), auth, vault, result);
    }

    /// Confirm the waiting rotate and run it against `key`; what the
    /// banner said at each touch.
    fn rotate_into(app: &mut App, key: &mut FakeKey) -> Vec<Option<String>> {
        let Some(VaultConfirm::Rotate { vault }) = app.vault_take_confirmed() else {
            panic!("a confirmed rotate");
        };
        let (mut auth, old) = app.vault_take_for_save(&vault).expect("an open vault");
        let unlocked = app.vault_session().unwrap().unlocked.clone();
        let banner = Arc::new(Mutex::new(None));
        let mut watched = Watched {
            key,
            banner: banner.clone(),
            at_touch: Vec::new(),
        };
        let (result, reloaded) = {
            let mut touches = TouchProgress::new(banner.clone(), 2);
            let r = run_rotate(&mut watched, &mut auth, &old, &mut touches);
            let reloaded = reload_after_rotate(&mut watched, &r, unlocked);
            (r.map_err(VaultJobError::from), reloaded)
        };
        let seen = watched.at_touch;
        app.vault_apply_rotate(Some(KEY.into()), auth, vault, result, reloaded);
        seen
    }

    fn touched_since(key: &FakeKey, from: usize) -> bool {
        key.log[from..]
            .iter()
            .any(|c| matches!(c, Call::Assertions(_) | Call::MakeCredential))
    }

    fn chip_labels(app: &App) -> Vec<String> {
        app.vault_session()
            .unwrap()
            .unlocked
            .vaults
            .iter()
            .map(chip_label)
            .collect()
    }

    /// The shown vault's entry IDs, in the vault's order.
    fn session_entry_ids(app: &App) -> Vec<String> {
        let open = app.selected_vault().unwrap().state.as_ref().unwrap();
        open.contents.entries.iter().map(|e| e.id.clone()).collect()
    }

    /// The store's size for `array` with one more vault holding `v`.
    fn room_for(key: &FakeKey, v: &Vault) -> u64 {
        let stand_in = [0u8; 32];
        key.array()
            .with_credential_blob(&stand_in, &seal(v, &stand_in).unwrap())
            .unwrap()
            .serialize_with_checksum()
            .unwrap()
            .len() as u64
    }

    #[test]
    fn create_adds_a_selected_vault_with_two_touches() {
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        app.vault_new_vault();
        assert_eq!(app.vault.new_vault.as_deref(), Some(""));
        let seen = create_into(&mut app, &mut key, "Travel");
        assert_eq!(
            seen,
            vec![
                Some("Touch your key (1 of 2)\u{2026}".to_owned()),
                Some("Touch your key (2 of 2)\u{2026}".to_owned()),
            ]
        );
        assert_eq!(
            app.vault.info.as_deref(),
            Some(
                "Vault \"Travel\" created on this key. If the key is lost or reset, the vault \
                 goes with it. Keep a backup with Export backup\u{2026} below."
            )
        );
        assert_eq!(app.vault.info, Some(backup_reminder("Travel")));
        assert!(app.vault.new_vault.is_none(), "the form closes");
        let s = app.vault_session().unwrap();
        assert!(s.auth.is_some(), "the auth is back");
        assert_eq!(s.unlocked.vaults.len(), 3);
        let new = s.unlocked.vaults[2].vault_ref.clone();
        assert_eq!(new.name.as_deref(), Some("Travel"));
        assert_eq!(app.vault.selected.as_deref(), Some(&new.credential_id[..]));
        assert_eq!(
            chip_label(app.selected_vault().unwrap()),
            "Travel \u{00B7} 0"
        );
        assert_eq!(key.vault_on_key(&new.credential_id), Some(Vault::default()));
        assert!(app
            .log
            .iter()
            .any(|l| l.severity == Severity::Ok && l.text == "Vault: vault \"Travel\" created"));
    }

    #[test]
    fn create_refused_for_room_asks_no_touch() {
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        let used = app.vault_session().unwrap().unlocked.capacity.used_bytes;
        key.set_max_bytes(used + 8);
        let stored = key.stored().to_vec();
        let before = key.log.len();
        let seen = create_into(&mut app, &mut key, "Travel");
        assert!(seen.is_empty(), "no touch asked for");
        assert!(!touched_since(&key, before));
        assert_eq!(key.stored(), &stored[..], "nothing written");
        let err = app.vault.error.clone().unwrap();
        assert!(err.contains("large-blob store is too small"), "{err}");
        assert_eq!(
            app.vault.new_vault.as_deref(),
            Some("Travel"),
            "the name stays"
        );
        let s = app.vault_session().unwrap();
        assert!(s.auth.is_some());
        assert_eq!(s.unlocked.vaults.len(), 2);
    }

    #[test]
    fn duplicate_name_is_refused_before_the_job() {
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        let before = key.log.len();
        app.vault.new_vault = Some("Work".into());
        assert!(app.vault_take_for_create().is_none());
        assert_eq!(
            app.vault.error.as_deref(),
            Some("This key already holds a vault named \"Work\".")
        );
        assert_eq!(app.vault.new_vault.as_deref(), Some("Work"));
        assert!(app.vault_session().unwrap().auth.is_some(), "nothing taken");
        assert_eq!(key.log.len(), before, "nothing sent");
        // The real entry point stops at the same place, with no job.
        app.vault.error = None;
        app.vault_create();
        assert!(app.vault.error.is_some() && !app.busy());
        // Spaces around a name are not part of it.
        app.vault.new_vault = Some("  Work ".into());
        assert!(app.vault_take_for_create().is_none());
    }

    #[test]
    fn too_long_name_is_refused_before_the_job() {
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        for bad in ["\u{e9}".repeat(17), String::new(), "   ".into()] {
            app.vault.new_vault = Some(bad);
            assert!(app.vault_take_for_create().is_none());
            assert_eq!(
                app.vault.error.as_deref(),
                Some(
                    "A vault name must be 1 to 32 bytes long (accented and non-Latin letters \
                     take 2 to 4 bytes each)."
                )
            );
            assert!(app.vault_session().unwrap().auth.is_some());
        }
        // 16 accented letters are 32 bytes: allowed.
        app.vault.new_vault = Some("\u{e9}".repeat(16));
        assert!(app.vault_take_for_create().is_some());
    }

    #[test]
    fn a_key_with_no_vault_shows_the_form() {
        let mut key = FakeKey::new();
        let mut app = app();
        unlock_into(&mut app, &mut key);
        let text = list_text(&mut app);
        for shown in [
            "No vaults on this key yet.",
            "Create vault",
            "Creating asks for two touches.",
        ] {
            assert!(text.contains(shown), "{shown:?} in {text}");
        }
        assert!(!text.contains("Cancel"), "nothing to go back to");
        create_into(&mut app, &mut key, "Personal");
        let text = list_text(&mut app);
        assert!(text.contains("Personal \u{00B7} 0"), "{text}");
        assert!(text.contains("+ New vault") && !text.contains("Create vault"));
        app.vault_new_vault();
        let text = list_text(&mut app);
        assert!(
            text.contains("Create vault") && text.contains("Cancel"),
            "{text}"
        );
        app.vault_new_vault();
        assert!(app.vault.new_vault.is_none(), "the chip closes it again");
    }

    #[test]
    fn create_undone_locks_and_says_what_to_delete() {
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        // The write fails, and so does removing the new credential.
        key.write_refusals.push_back(0x30);
        key.delete_fails = true;
        create_into(&mut app, &mut key, "Travel");
        assert!(app.vault.session.is_none(), "the list was stale: locked");
        let err = app.vault.error.clone().unwrap();
        assert!(err.starts_with("The vault was not created"), "{err}");
        assert!(
            err.ends_with("; delete the copy listed as (none) with Delete vault\u{2026}."),
            "{err}"
        );
        assert!(app
            .log
            .iter()
            .any(|l| l.severity == Severity::Err && l.text == format!("Vault: {err}")));
        // Unlocking again lists that copy as (none).
        unlock_into(&mut app, &mut key);
        assert!(
            chip_labels(&app).contains(&"Travel \u{00B7} (none)".to_owned()),
            "{:?}",
            chip_labels(&app)
        );
    }

    #[test]
    fn delete_vault_asks_no_touch_and_keeps_other_entries() {
        let mut key = FakeKey::new();
        let p = two_vaults(&mut key);
        key.add_foreign_entries();
        let work = key.creds[1].id.clone();
        let lbk = key.creds[0].lbk.unwrap();
        let mut app = app();
        unlock_into(&mut app, &mut key);
        let expected = key
            .array()
            .without_credential_blob(&lbk)
            .serialize_with_checksum()
            .unwrap();
        let before = key.log.len();
        app.vault_ask_delete_vault();
        assert!(matches!(
            app.vault.confirm,
            Some(VaultConfirm::DeleteVault { .. })
        ));
        delete_vault_into(&mut app, &mut key);
        assert!(!touched_since(&key, before), "no touch");
        assert_eq!(key.stored(), &expected[..], "every other entry as it was");
        assert!(key.creds.iter().all(|c| c.id != p));
        assert_eq!(key.vault_on_key(&work), Some(Vault::default()));
        assert_eq!(
            app.vault.info.as_deref(),
            Some("Vault \"Personal\" deleted.")
        );
        let s = app.vault_session().unwrap();
        assert!(s.auth.is_some());
        assert_eq!(s.unlocked.vaults.len(), 1);
        assert_eq!(
            s.unlocked.capacity.used_bytes,
            key.array().capacity(&key.info).used_bytes
        );
        assert_eq!(app.selected_vault().unwrap().vault_ref.credential_id, work);
        assert!(app
            .log
            .iter()
            .any(|l| l.severity == Severity::Ok && l.text == "Vault: vault \"Personal\" deleted"));
    }

    /// An interrupted rotate's two "Personal": one with an entry, one with
    /// no data. Their credential IDs, in that order.
    fn two_copies(key: &mut FakeKey) -> (Vec<u8>, Vec<u8>) {
        let full = key.add_vault(
            "Personal",
            &Vault {
                entries: vec![entry("GitHub")],
            },
        );
        let empty = key.add_credential(
            keyroost_vault::user_handle("Personal").unwrap(),
            Some("Personal"),
        );
        (full, empty)
    }

    #[test]
    fn delete_of_a_duplicate_named_vault_takes_the_chosen_copy() {
        let mut key = FakeKey::new();
        let (full, empty) = two_copies(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        // Told apart by what each stores.
        assert_eq!(
            chip_labels(&app),
            ["Personal \u{00B7} 1", "Personal \u{00B7} (none)"]
        );
        app.vault_select(empty.clone());
        app.vault_ask_delete_vault();
        delete_vault_into(&mut app, &mut key);
        assert!(key.creds.iter().all(|c| c.id != empty));
        assert_eq!(key.vault_on_key(&full).unwrap().entries.len(), 1);
        assert_eq!(chip_labels(&app), ["Personal \u{00B7} 1"]);
        assert_eq!(app.selected_vault().unwrap().vault_ref.credential_id, full);

        // And the copy with the entry, when that is the one chosen.
        let mut key = FakeKey::new();
        let (full, empty) = two_copies(&mut key);
        let mut app = self::app();
        unlock_into(&mut app, &mut key);
        app.vault_select(full.clone());
        app.vault_ask_delete_vault();
        delete_vault_into(&mut app, &mut key);
        assert_eq!(
            key.creds.iter().map(|c| c.id.clone()).collect::<Vec<_>>(),
            [empty]
        );
        assert_eq!(chip_labels(&app), ["Personal \u{00B7} (none)"]);
    }

    #[test]
    fn an_unavailable_vault_can_still_be_deleted() {
        let mut key = FakeKey::new();
        let p = two_vaults(&mut key);
        let damaged = key.add_vault("Old", &Vault::default());
        key.put_unreadable(&damaged);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        app.vault_select(damaged.clone());
        assert!(!app.vault_writable());
        app.vault_ask_rotate();
        assert!(app.vault.confirm.is_none(), "no rotate for it");
        let text = list_text(&mut app);
        assert!(text.contains("Delete vault\u{2026}"), "{text}");
        app.vault_ask_delete_vault();
        delete_vault_into(&mut app, &mut key);
        assert_eq!(app.vault.info.as_deref(), Some("Vault \"Old\" deleted."));
        assert!(key.creds.iter().all(|c| c.id != damaged));
        assert_eq!(key.vault_on_key(&p).unwrap().entries.len(), 2);
        assert_eq!(app.vault_session().unwrap().unlocked.vaults.len(), 2);
    }

    #[test]
    fn a_vault_gone_before_its_delete_locks() {
        let mut key = FakeKey::new();
        let p = two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        app.vault_ask_delete_vault();
        // Another program deletes it first.
        key.creds.retain(|c| c.id != p);
        delete_vault_into(&mut app, &mut key);
        assert!(app.vault.session.is_none());
        let err = app.vault.error.clone().unwrap();
        assert!(
            err.starts_with("Vault \"Personal\" is no longer on the key"),
            "{err}"
        );
    }

    #[test]
    fn rotate_replaces_the_vault_with_the_same_entries() {
        let mut key = FakeKey::new();
        let p = two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        let ids = session_entry_ids(&app);
        app.vault.open_entry = Some(ids[0].clone());
        app.vault_ask_rotate();
        assert!(matches!(
            app.vault.confirm,
            Some(VaultConfirm::Rotate { .. })
        ));
        let seen = rotate_into(&mut app, &mut key);
        assert_eq!(
            seen,
            vec![
                Some("Touch your key (1 of 2)\u{2026}".to_owned()),
                Some("Touch your key (2 of 2)\u{2026}".to_owned()),
            ]
        );
        assert_eq!(
            app.vault.info.as_deref(),
            Some(
                "Vault \"Personal\" rotated: a new vault holds its 2 entries and the old one is \
                 deleted."
            )
        );
        let s = app.vault_session().unwrap();
        assert!(s.auth.is_some());
        assert_eq!(s.unlocked.vaults.len(), 2);
        let new = s.unlocked.vaults[0].vault_ref.clone();
        assert_ne!(new.credential_id, p);
        assert_eq!(new.name.as_deref(), Some("Personal"));
        assert_eq!(app.vault.selected.as_deref(), Some(&new.credential_id[..]));
        assert_eq!(session_entry_ids(&app), ids, "the same entries");
        assert_eq!(
            app.vault.open_entry.as_deref(),
            Some(&*ids[0]),
            "still open"
        );
        assert!(
            key.creds.iter().all(|c| c.id != p),
            "the old one is deleted"
        );
        assert_eq!(
            key.vault_on_key(&new.credential_id).unwrap().entries.len(),
            2
        );
        assert!(app
            .log
            .iter()
            .any(|l| l.severity == Severity::Ok && l.text == "Vault: vault \"Personal\" rotated"));
    }

    #[test]
    fn rotate_logs_the_store_note() {
        let mut key = FakeKey::new();
        let p = key.add_vault(
            "Personal",
            &Vault {
                entries: vec![entry("GitHub")],
            },
        );
        // Another vault fills most of the store.
        key.add_vault(
            "Work",
            &Vault {
                entries: (0..30).map(|i| entry(&format!("Site {i}"))).collect(),
            },
        );
        let personal = key.vault_on_key(&p).unwrap();
        key.set_max_bytes(room_for(&key, &personal));
        let mut app = app();
        unlock_into(&mut app, &mut key);
        app.vault_ask_rotate();
        rotate_into(&mut app, &mut key);
        assert!(app.vault.info.as_deref().unwrap().contains("rotated"));
        let cap = app.vault_session().unwrap().unlocked.capacity;
        assert!(cap.free_bytes * 4 < cap.max_bytes, "{cap:?}");
        let note = blob_space_line("Vault", &cap).expect("under a quarter free");
        assert_eq!(
            app.log
                .iter()
                .filter(|l| l.severity == Severity::Warn && l.text == note)
                .count(),
            1
        );
    }

    #[test]
    fn create_logs_the_store_note() {
        let mut key = FakeKey::new();
        key.add_vault(
            "Work",
            &Vault {
                entries: (0..30).map(|i| entry(&format!("Site {i}"))).collect(),
            },
        );
        key.set_max_bytes(room_for(&key, &Vault::default()) + 4);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        create_into(&mut app, &mut key, "Travel");
        let cap = app.vault_session().unwrap().unlocked.capacity;
        assert_eq!(app.vault_session().unwrap().unlocked.vaults.len(), 2);
        let note = blob_space_line("Vault", &cap).expect("under a quarter free");
        assert!(app
            .log
            .iter()
            .any(|l| l.severity == Severity::Warn && l.text == note));
    }

    #[test]
    fn old_not_deleted_locks_with_the_whole_message() {
        // Emptied: the old data went, its credential didn't.
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        key.delete_fails = true;
        let mut app = app();
        unlock_into(&mut app, &mut key);
        app.vault_ask_rotate();
        rotate_into(&mut app, &mut key);
        assert!(app.vault.session.is_none(), "locked");
        let err = app.vault.error.clone().unwrap();
        assert!(err.starts_with("The new vault \"Personal\""), "{err}");
        assert!(
            err.contains("is in place with every entry checked"),
            "{err}"
        );
        assert!(
            err.contains(
                "the old copy is left with no data: delete the copy listed as (none) with \
                 Delete vault\u{2026}"
            ),
            "{err}"
        );
        assert!(!err.contains("delete either"), "{err}");
        assert!(err.ends_with(UNLOCK_AGAIN), "{err}");
        assert!(app
            .log
            .iter()
            .any(|l| l.severity == Severity::Err && l.text == format!("Vault: {err}")));
        // Unlocking again shows both copies, the old one as (none).
        unlock_into(&mut app, &mut key);
        let labels = chip_labels(&app);
        assert!(
            labels.contains(&"Personal \u{00B7} (none)".to_owned()),
            "{labels:?}"
        );
        assert!(
            labels.contains(&"Personal \u{00B7} 2".to_owned()),
            "{labels:?}"
        );
    }

    #[test]
    fn old_kept_says_delete_either_then_rotate_again() {
        // Removing the old data is refused: the old copy keeps its data.
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        key.after_write = Some((
            1,
            Box::new(|k: &mut FakeKey| k.write_refusals.push_back(0x30)),
        ));
        let mut app = app();
        unlock_into(&mut app, &mut key);
        app.vault_ask_rotate();
        rotate_into(&mut app, &mut key);
        assert!(app.vault.session.is_none());
        let err = app.vault.error.clone().unwrap();
        assert!(
            err.contains("is in place with every entry checked"),
            "{err}"
        );
        assert!(
            err.contains(
                "both copies hold the same checked entries, but one still uses the old key: \
                 delete either with Delete vault\u{2026}, then rotate the one left again with \
                 Rotate vault key\u{2026} so it gets a fresh key"
            ),
            "{err}"
        );
        assert!(!err.contains("(none)"), "{err}");
        assert!(err.ends_with(UNLOCK_AGAIN), "{err}");
    }

    #[test]
    fn old_unknown_says_which_copy_or_rotate_again() {
        // The reply to the old data's removal is lost: whether it went is
        // not known.
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        key.after_write = Some((
            1,
            Box::new(|k: &mut FakeKey| {
                k.after_write = Some((2, Box::new(|k: &mut FakeKey| k.lost_write_replies = 1)));
            }),
        ));
        let mut app = app();
        unlock_into(&mut app, &mut key);
        app.vault_ask_rotate();
        rotate_into(&mut app, &mut key);
        assert!(app.vault.session.is_none());
        let err = app.vault.error.clone().unwrap();
        assert!(
            err.contains("is in place with every entry checked"),
            "{err}"
        );
        assert!(
            err.contains(
                "whether the old copy still holds its data is not known: if a copy is listed \
                 as (none), delete that one with Delete vault\u{2026}; otherwise both copies"
            ),
            "{err}"
        );
        assert!(
            err.contains("then rotate the one left again with Rotate vault key\u{2026}"),
            "{err}"
        );
        assert!(err.ends_with(UNLOCK_AGAIN), "{err}");
    }

    #[test]
    fn a_rotate_undone_cleanly_keeps_the_session() {
        let mut key = FakeKey::new();
        let p = two_vaults(&mut key);
        // The new vault's write is refused: it is removed again, and
        // nothing is left that the list doesn't show.
        key.write_refusals.push_back(0x30);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        app.vault_ask_rotate();
        rotate_into(&mut app, &mut key);
        let s = app.vault_session().expect("still unlocked");
        assert!(s.auth.is_some());
        assert_eq!(s.unlocked.vaults[0].vault_ref.credential_id, p);
        assert_eq!(key.creds.len(), 2, "the new credential was removed");
        let err = app.vault.error.clone().unwrap();
        assert!(err.starts_with("The vault was not created"), "{err}");
        assert!(
            err.ends_with("its new credential was removed again."),
            "{err}"
        );
        assert_eq!(
            key.vault_on_key(&p).unwrap().entries.len(),
            2,
            "old untouched"
        );
    }

    #[test]
    fn rotate_and_delete_questions_are_the_cli_words() {
        assert_eq!(
            rotate_question("Personal", "yubi-test"),
            "Rotate the key of vault \"Personal\" on yubi-test? A new vault replaces it; the \
             old one is deleted after every entry is checked."
        );
        assert_eq!(
            delete_vault_question("Personal", "yubi-test"),
            "Delete vault \"Personal\" on yubi-test?"
        );
        assert_eq!(
            ROTATE_EXPLAINED,
            "Gives this vault a new key. Use it after unlocking the vault on a computer you no \
             longer trust, then change the passwords that matter."
        );
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut app = app();
        app.devices = vec![crate::tests::test_key(KEY, "AAA", Some("yubi-test"))];
        unlock_into(&mut app, &mut key);
        let text = list_text(&mut app);
        for shown in [
            "This vault",
            "Rotate vault key\u{2026}",
            "Gives this vault a new key.",
            "unlocking the vault",
            "Delete vault\u{2026}",
            "+ New vault",
        ] {
            assert!(text.contains(shown), "{shown:?} in {text}");
        }
        app.vault_ask_rotate();
        let text = list_text(&mut app);
        for shown in [
            "Rotate the key of vault \"Personal\" on yubi-test?",
            "This asks for two touches.",
            "Cancel",
        ] {
            assert!(text.contains(shown), "{shown:?} in {text}");
        }
        app.vault.confirm = None;
        app.vault_ask_delete_vault();
        let text = list_text(&mut app);
        for shown in [
            "Delete vault \"Personal\" on yubi-test?",
            "Its entries go with it. To keep them, export a backup first.",
            "Cancel",
        ] {
            assert!(text.contains(shown), "{shown:?} in {text}");
        }
        // Another vault's chip closes the question.
        let w = app.vault_session().unwrap().unlocked.vaults[1]
            .vault_ref
            .credential_id
            .clone();
        app.vault_select(w);
        assert!(app.vault.confirm.is_none());
    }

    #[test]
    fn a_vault_question_stays_while_another_job_runs() {
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        app.vault_ask_delete_vault();
        app.busy_jobs = 1;
        app.busy_label = Some("Reading\u{2026}".into());
        assert!(app.vault_take_confirmed().is_none());
        assert!(matches!(
            app.vault.confirm,
            Some(VaultConfirm::DeleteVault { .. })
        ));
        app.busy_jobs = 0;
        assert!(app.vault_take_confirmed().is_some());
        assert!(app.vault.confirm.is_none());
    }

    #[test]
    fn vault_results_for_another_key_are_discarded() {
        let mut key = FakeKey::new();
        let p = two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        let vault = app.selected_vault().unwrap().vault_ref.clone();
        let other: Option<DeviceId> = Some("serial:BBB".into());
        let failed = || VaultJobError::Vault(VaultKeyError::NoVaults);
        app.vault_apply_delete_vault(other.clone(), pin_auth(), vault.clone(), Err(failed()));
        app.vault_apply_rotate(other.clone(), pin_auth(), vault, Err(failed()), None);
        app.vault_apply_create(other, pin_auth(), None, Err(failed()));
        assert!(app.vault.error.is_none() && app.log.is_empty());
        assert_eq!(
            app.vault_session().unwrap().unlocked.vaults[0]
                .vault_ref
                .credential_id,
            p
        );
    }

    #[test]
    fn an_import_into_a_new_vault_says_both() {
        let mut key = FakeKey::new();
        let mut app = app();
        unlock_into(&mut app, &mut key);
        app.vault.new_vault = Some("Travel".into());
        let (name, mut auth) = app.vault_take_for_create().unwrap();
        let initial = Vault {
            entries: vec![entry("GitHub"), entry("Bank")],
        };
        let result: Result<Created, VaultJobError> = {
            let mut touches = TouchProgress::new(Arc::new(Mutex::new(None)), 2);
            run_create(&mut key, &mut auth, &name, &initial, &mut touches)
                .map_err(VaultJobError::from)
        };
        app.vault_apply_create(Some(KEY.into()), auth, Some(2), result);
        assert_eq!(
            app.vault.info,
            Some(format!(
                "Imported into vault \"Travel\": 2 added, 0 replaced. {}",
                backup_reminder("Travel")
            ))
        );
    }

    #[test]
    fn a_vault_changed_during_rotate_reloads_and_rotates_nothing() {
        let mut key = FakeKey::new();
        let p = two_vaults(&mut key);
        let mut changed = key.vault_on_key(&p).unwrap();
        changed.entries[0].username = "changed-elsewhere".into();
        let on_key = changed.clone();
        // Another program saves to it right after the new vault is written.
        key.after_write = Some((
            1,
            Box::new(move |k: &mut FakeKey| k.put_vault(&p.clone(), &on_key)),
        ));
        let mut app = app();
        unlock_into(&mut app, &mut key);
        let p = app
            .selected_vault()
            .unwrap()
            .vault_ref
            .credential_id
            .clone();
        let before = key.log.len();
        app.vault_ask_rotate();
        rotate_into(&mut app, &mut key);
        let s = app.vault_session().expect("still unlocked");
        assert!(s.auth.is_some());
        assert_eq!(s.unlocked.vaults.len(), 2);
        assert_eq!(s.unlocked.vaults[0].vault_ref.credential_id, p);
        assert_eq!(
            session_entry(&app, &changed.entries[0].title).username,
            "changed-elsewhere",
            "the list shows what the key holds now"
        );
        let err = app.vault.error.clone().unwrap();
        assert_eq!(
            err,
            "Vault \"Personal\" changed on the key while its key was being rotated, so \
             nothing was rotated. The list now shows it as the key holds it; check it and \
             rotate again."
        );
        assert!(app.vault.info.is_none());
        // Nothing left behind: the two vaults and their data, no more.
        assert_eq!(key.creds.len(), 2, "the new credential was removed");
        assert_eq!(key.vault_on_key(&p), Some(changed));
        let mut expected = key.array();
        for c in &key.creds {
            expected = expected.without_credential_blob(&c.lbk.unwrap());
        }
        assert_eq!(
            expected.capacity(&key.info).used_bytes,
            FakeKey::new().array().capacity(&key.info).used_bytes,
            "no orphan blob"
        );
        // The reload asked for no touch beyond the rotate's two.
        let touches = key.log[before..]
            .iter()
            .filter(|c| matches!(c, Call::Assertions(_) | Call::MakeCredential))
            .count();
        assert_eq!(touches, 2);
        assert!(app
            .log
            .iter()
            .any(|l| l.severity == Severity::Warn && l.text == format!("Vault: {err}")));
    }

    #[test]
    fn a_vault_deleted_during_rotate_locks() {
        let mut key = FakeKey::new();
        let p = two_vaults(&mut key);
        let lbk = key.creds[0].lbk.unwrap();
        let gone = p.clone();
        key.after_write = Some((
            1,
            Box::new(move |k: &mut FakeKey| {
                let array = k.array().without_credential_blob(&lbk);
                k.set_array(&array);
                k.creds.retain(|c| c.id != gone);
            }),
        ));
        let mut app = app();
        unlock_into(&mut app, &mut key);
        app.vault_ask_rotate();
        rotate_into(&mut app, &mut key);
        assert!(app.vault.session.is_none(), "locked");
        let err = app.vault.error.clone().unwrap();
        assert!(
            err.starts_with(
                "Vault \"Personal\" changed on the key while its key was being rotated, so \
                 nothing was rotated."
            ),
            "{err}"
        );
        assert!(err.ends_with(UNLOCK_AGAIN), "{err}");
        // Locked, nothing is listed: no line points at the list.
        assert!(!err.contains(ROTATE_AGAIN), "{err}");
        assert_eq!(err.matches(UNLOCK_AGAIN).count(), 1, "{err}");
        // Only Work is left, with its data and nothing else.
        assert_eq!(key.creds.len(), 1);
        let work_lbk = key.creds[0].lbk.unwrap();
        assert_eq!(
            key.array()
                .without_credential_blob(&work_lbk)
                .capacity(&key.info)
                .used_bytes,
            FakeKey::new().array().capacity(&key.info).used_bytes,
            "no orphan blob"
        );
    }

    #[test]
    fn a_half_done_vault_delete_shows_no_data_and_finishes_on_retry() {
        let mut key = FakeKey::new();
        let p = two_vaults(&mut key);
        key.delete_fails = true;
        let mut app = app();
        unlock_into(&mut app, &mut key);
        app.vault.open_entry = Some(session_entry_ids(&app)[0].clone());
        app.vault_ask_delete_vault();
        delete_vault_into(&mut app, &mut key);
        let s = app.vault_session().expect("still unlocked");
        assert!(s.auth.is_some());
        assert_eq!(
            s.unlocked.capacity.used_bytes,
            key.array().capacity(&key.info).used_bytes
        );
        assert_eq!(chip_labels(&app)[0], "Personal \u{00B7} (none)");
        assert!(app.vault.open_entry.is_none());
        assert!(
            !list_text(&mut app).contains("GitHub"),
            "no entry the key lost"
        );
        let err = app.vault.error.clone().unwrap();
        assert!(
            err.starts_with(
                "The vault's entries were removed from the key, but deleting the \
                             vault itself failed"
            ),
            "{err}"
        );
        assert!(
            err.ends_with("Delete vault\u{2026} again finishes it."),
            "{err}"
        );
        assert!(
            key.creds.iter().any(|c| c.id == p),
            "the credential is left"
        );
        assert_eq!(key.vault_on_key(&p), None, "its data is gone");
        // Again, once the key lets it: done.
        key.delete_fails = false;
        app.vault_select(p.clone());
        app.vault_ask_delete_vault();
        delete_vault_into(&mut app, &mut key);
        assert_eq!(
            app.vault.info.as_deref(),
            Some("Vault \"Personal\" deleted.")
        );
        assert!(key.creds.iter().all(|c| c.id != p));
    }

    #[test]
    fn a_vault_delete_that_failed_early_keeps_the_entries() {
        let mut key = FakeKey::new();
        let p = two_vaults(&mut key);
        key.write_refusals.push_back(0x30);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        app.vault_ask_delete_vault();
        delete_vault_into(&mut app, &mut key);
        assert!(app.vault_session().is_some());
        assert_eq!(chip_labels(&app)[0], "Personal \u{00B7} 2");
        assert_eq!(key.vault_on_key(&p).unwrap().entries.len(), 2);
        assert!(!app.vault.error.clone().unwrap().contains("finishes it"));
    }

    // Export backup…

    const BACKUP_PASS: &str = "correct horse battery";

    /// A fresh temp folder of this test run's own.
    fn export_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "keyroost-vault-export-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The save dialog Export backup… asked for (the one still queued,
    /// else the one for the backup waiting) resolves to `path` (`None`:
    /// cancelled), the way `drain_file_dialogs` receives it.
    fn choose_file(app: &mut App, path: Option<std::path::PathBuf>) {
        let target = match app.file_dialog_queue.pop() {
            Some(request) => request.target,
            None => FileTarget::VaultExport {
                credential_id: app
                    .vault
                    .export_for
                    .as_ref()
                    .map(|v| v.credential_id.clone())
                    .unwrap_or_default(),
                device: app.selected_device.clone(),
            },
        };
        resolve_dialog(app, target, path);
    }

    /// A save dialog for `target` resolves to `path`.
    fn resolve_dialog(app: &mut App, target: FileTarget, path: Option<std::path::PathBuf>) {
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(path).unwrap();
        app.pending_files.push((target, rx));
        app.drain_file_dialogs();
    }

    /// An unlocked key with Personal (2 entries) shown, the save dialog of
    /// Export backup… resolved to `path`.
    fn export_dialog_for(app: &mut App, key: &mut FakeKey, path: &Path) {
        two_vaults(key);
        unlock_into(app, key);
        app.vault_export_start();
        let request = app.file_dialog_queue.pop().expect("a save dialog");
        assert!(matches!(request.target, FileTarget::VaultExport { .. }) && request.save);
        assert_eq!(
            request.filters,
            vec![("Vault backup".to_owned(), vec!["t2vault".to_owned()])]
        );
        assert_eq!(request.default_name.as_deref(), Some("personal.t2vault"));
        choose_file(app, Some(path.to_owned()));
        assert!(app.vault.export_for.is_none());
    }

    fn type_passphrases(app: &mut App, passphrase: &str, repeat: &str) {
        let d = app.vault.export.as_mut().expect("the passphrase dialog");
        replace_text(&mut d.passphrase, passphrase);
        replace_text(&mut d.repeat, repeat);
    }

    /// One Export backup… run the tests share (Argon2id is slow in a test
    /// build): Personal written over an older file with looser permissions,
    /// which the save dialog chose.
    struct ExportRun {
        path: std::path::PathBuf,
        contents: Vault,
        info: Option<String>,
        dialog_open: bool,
        auth_kept: bool,
        bytes: Vec<u8>,
        #[cfg(unix)]
        mode: u32,
    }

    fn exported() -> &'static ExportRun {
        static RUN: std::sync::OnceLock<ExportRun> = std::sync::OnceLock::new();
        RUN.get_or_init(|| {
            let dir = export_dir("run");
            let path = dir.join("personal.t2vault");
            std::fs::write(&path, b"an older file").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            }
            let mut key = FakeKey::new();
            let mut app = app();
            export_dialog_for(&mut app, &mut key, &path);
            type_passphrases(&mut app, BACKUP_PASS, BACKUP_PASS);
            app.vault_export();
            let contents = app.selected_vault().unwrap().state.as_ref().unwrap();
            let run = ExportRun {
                contents: contents.contents.clone(),
                info: app.vault.info.clone(),
                dialog_open: app.vault.export.is_some(),
                auth_kept: app.vault_session().is_some_and(|s| s.auth.is_some()),
                bytes: std::fs::read(&path).unwrap(),
                #[cfg(unix)]
                mode: {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::metadata(&path).unwrap().permissions().mode() & 0o777
                },
                path,
            };
            let _ = std::fs::remove_dir_all(&dir);
            run
        })
    }

    #[test]
    fn export_writes_a_backup_that_opens_with_the_passphrase() {
        let run = exported();
        assert_eq!(run.contents.entries.len(), 2);
        let back = keyroost_vault::import_backup(&run.bytes, BACKUP_PASS).unwrap();
        assert_eq!(back, run.contents);
        assert!(keyroost_vault::import_backup(&run.bytes, "another passphrase").is_err());
        assert_eq!(
            run.info.as_deref(),
            Some(
                format!(
                    "Backup of vault \"Personal\" (2 entries) written to {}.",
                    run.path.display()
                )
                .as_str()
            )
        );
        assert!(!run.dialog_open, "written closes the dialog");
        assert!(run.auth_kept, "no key was used: the session keeps its auth");
    }

    #[test]
    fn export_refuses_short_and_mismatched_passphrases() {
        assert_eq!(
            check_export_passphrase("long enough one", "long enough two"),
            Err(PASSPHRASES_DIFFER.to_owned())
        );
        assert_eq!(
            check_export_passphrase("too short", "too short"),
            Err("use a backup passphrase of at least 10 characters".to_owned())
        );
        assert_eq!(check_export_passphrase("ten chars!", "ten chars!"), Ok(()));

        let dir = export_dir("refuse");
        let path = dir.join("personal.t2vault");
        let mut key = FakeKey::new();
        let mut app = app();
        export_dialog_for(&mut app, &mut key, &path);
        let text = list_text(&mut app);
        for line in [
            "Back up vault \"Personal\"",
            "Passphrase",
            "Repeat",
            PASSPHRASE_NOTE,
            "Write backup",
            "Cancel",
        ] {
            assert!(text.contains(line), "{line}: {text}");
        }
        // Shown as sentences, like the rest of the tab.
        for (pass, repeat, said) in [
            (
                BACKUP_PASS,
                "correct horse battery!",
                "The two passphrases don't match.",
            ),
            (
                "short",
                "short",
                "Use a backup passphrase of at least 10 characters.",
            ),
        ] {
            type_passphrases(&mut app, pass, repeat);
            app.vault_export();
            assert_eq!(app.vault.error.as_deref(), Some(said));
            assert!(app.vault.export.is_some(), "the dialog stays");
            assert!(!path.exists(), "nothing was written");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn export_dialog_wipes_on_close() {
        let mut d = ExportDialog {
            vault: VaultRef {
                credential_id: vec![1],
                name: Some("Personal".into()),
            },
            path: "personal.t2vault".into(),
            passphrase: BACKUP_PASS.into(),
            repeat: BACKUP_PASS.into(),
        };
        assert_eq!(d.secrets_mut().len(), 2);
        d.wipe_typed();
        assert!(d.passphrase.is_empty() && d.repeat.is_empty());
        // The tab's own list carries the dialog's boxes too.
        let mut state = VaultState {
            export: Some(d),
            ..Default::default()
        };
        assert_eq!(state.secrets_mut().len(), 3);

        // Cancel closes it; so does Lock, and a cancelled save dialog
        // forgets which vault it was for.
        let dir = export_dir("close");
        let path = dir.join("personal.t2vault");
        let mut key = FakeKey::new();
        let mut app = app();
        export_dialog_for(&mut app, &mut key, &path);
        type_passphrases(&mut app, BACKUP_PASS, BACKUP_PASS);
        app.vault_export_cancel();
        assert!(app.vault.export.is_none());
        app.vault_export_start();
        assert!(app.vault.export_for.is_some());
        choose_file(&mut app, None);
        assert!(app.vault.export_for.is_none() && app.vault.export.is_none());
        app.vault_export_start();
        choose_file(&mut app, Some(path.clone()));
        type_passphrases(&mut app, BACKUP_PASS, BACKUP_PASS);
        app.vault_lock(None);
        assert!(app.vault.export.is_none());
        // A save dialog still open at a lock opens nothing when it resolves.
        unlock_into(&mut app, &mut key);
        app.vault_export_start();
        app.vault_lock(None);
        assert!(app.vault.export_for.is_none());
        choose_file(&mut app, Some(path.clone()));
        assert!(app.vault.export.is_none());
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn export_replaces_a_chosen_file_but_not_through_a_symlink() {
        let run = exported();
        assert_eq!(run.mode, 0o600, "the replaced file is owner-only");
        assert_ne!(run.bytes, b"an older file");

        let dir = export_dir("link");
        let victim = dir.join("victim");
        let link = dir.join("personal.t2vault");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        let e = write_backup_file(&link, &run.bytes).unwrap_err();
        assert_eq!(
            e,
            format!(
                "cannot write {}: refusing to write secret output through a symlink",
                link.display()
            )
        );
        assert!(!victim.exists(), "nothing was written through the link");
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());

        // The app's end of a failed write: the dialog stays with the reason.
        let mut key = FakeKey::new();
        let mut app = app();
        export_dialog_for(&mut app, &mut key, &link);
        let file = link.display().to_string();
        app.vault_apply_export(
            Some(KEY.into()),
            "Personal".into(),
            file.clone(),
            Err(e.clone()),
        );
        assert_eq!(
            app.vault.error.as_deref(),
            Some(
                format!(
                    "Cannot write {}: refusing to write secret output through a symlink.",
                    link.display()
                )
                .as_str()
            ),
            "shown as a sentence"
        );
        assert!(app.vault.export.is_some());
        assert_eq!(
            app.log.last().unwrap().text,
            format!("Vault: backup of vault \"Personal\" not written: {e}")
        );
        // A result for another key leaves the pane alone but is logged.
        app.vault_apply_export(
            Some("serial:BBB".into()),
            "Personal".into(),
            file.clone(),
            Ok(2),
        );
        assert!(app.vault.export.is_some() && app.vault.info.is_none());
        assert_eq!(
            app.log.last().unwrap().text,
            format!("Vault: backup of vault \"Personal\" written to {file}")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The vault locked while its backup was written: the dialog is gone,
    /// but the activity log still says whether the file was written.
    #[test]
    fn a_backup_finished_after_a_lock_is_still_logged() {
        let dir = export_dir("locked");
        let path = dir.join("personal.t2vault");
        let mut key = FakeKey::new();
        let mut app = app();
        export_dialog_for(&mut app, &mut key, &path);
        app.vault_lock(None);
        let file = path.display().to_string();
        app.vault_apply_export(Some(KEY.into()), "Personal".into(), file.clone(), Ok(2));
        assert_eq!(
            app.log.last().unwrap().text,
            format!("Vault: backup of vault \"Personal\" written to {file}")
        );
        assert!(app.vault.info.is_none() && app.vault.export.is_none());
        app.vault_apply_export(
            Some(KEY.into()),
            "Personal".into(),
            file.clone(),
            Err("cannot write it: disk full".into()),
        );
        assert_eq!(
            app.log.last().unwrap().text,
            "Vault: backup of vault \"Personal\" not written: cannot write it: disk full"
        );
        assert!(app.vault.export.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Export backup… again while the first one's save dialog is still
    /// open says so instead of opening a second dialog whose file would go
    /// unused.
    #[test]
    fn a_second_export_while_one_is_pending_says_so() {
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        app.vault_export_start();
        assert_eq!(app.file_dialog_queue.len(), 1);
        app.vault_export_start();
        assert_eq!(app.file_dialog_queue.len(), 1, "no second save dialog");
        assert_eq!(
            app.vault.error.as_deref(),
            Some(
                "A backup of vault \"Personal\" is already being saved: finish or cancel its \
                 save dialog first."
            )
        );
        // Once the first dialog is cancelled, Export backup… works again.
        app.file_dialog_queue.clear();
        choose_file(&mut app, None);
        app.vault_export_start();
        assert_eq!(app.file_dialog_queue.len(), 1);
    }

    #[test]
    fn export_backup_is_offered_on_the_backup_card_and_before_a_delete() {
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        let text = list_text(&mut app);
        assert_eq!(text.matches("Export backup\u{2026}").count(), 1, "{text}");
        app.vault_ask_delete_vault();
        let text = list_text(&mut app);
        assert_eq!(text.matches("Export backup\u{2026}").count(), 2, "{text}");
        // Pressing it keeps the question for after the backup.
        app.vault_export_start();
        assert!(app.vault.export_for.is_some());
        assert!(matches!(
            app.vault.confirm,
            Some(VaultConfirm::DeleteVault { .. })
        ));
    }

    #[test]
    fn an_unavailable_vault_has_no_export() {
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let damaged = key.add_vault("Old", &Vault::default());
        key.put_blob(&damaged, b"not a vault at all, just bytes");
        let mut app = app();
        unlock_into(&mut app, &mut key);
        app.vault_select(damaged);
        assert_eq!(
            list_text(&mut app).matches("Export backup\u{2026}").count(),
            1
        );
        assert!(!app.vault_writable());
        app.vault_export_start();
        assert!(app.vault.export_for.is_none() && app.file_dialog_queue.is_empty());
    }

    // ----- Import backup… -----

    use keyroost_vault::ImportStatus;

    const IMPORT_PASS: &str = "a backup passphrase";

    fn kv(id: &str, title: &str, username: &str, password: &str, url: &str, m: i64) -> Entry {
        Entry {
            id: id.into(),
            title: title.into(),
            username: username.into(),
            password: Zeroizing::new(password.into()),
            url: url.into(),
            notes: String::new(),
            modified_minutes: m,
        }
    }

    /// Personal as the key holds it.
    fn key_vault() -> Vault {
        Vault {
            entries: vec![
                kv("ghghghgh", "GitHub", "alice", "gh-key", "", 100),
                kv("bkbkbkbk", "Bank", "", "bank-key", "", 200),
                kv("fofofofo", "Forum", "bob", "forum", "", 100),
            ],
        }
    }

    /// The backup: two new entries that share a title, GitHub newer than
    /// the key's, Bank older, Forum the same.
    fn backup_vault() -> Vault {
        Vault {
            entries: vec![
                kv("mama0001", "Mail", "alice", "mail-a", "", 120),
                kv(
                    "mama0002",
                    "Mail",
                    "bob",
                    "mail-b",
                    "https://mail.example/x",
                    120,
                ),
                kv("ghghghgh", "GitHub", "alice", "gh-backup", "", 150),
                kv("bkbkbkbk", "Bank", "", "bank-backup", "", 150),
                kv("fofofofo", "Forum", "bob", "forum", "", 100),
            ],
        }
    }

    /// A fresh temp folder of this test run's own.
    fn import_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "keyroost-vault-import-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The open dialog Import backup… asked for resolves to `path` (`None`:
    /// cancelled), the way `drain_file_dialogs` receives it.
    fn choose_backup(app: &mut App, path: Option<std::path::PathBuf>) {
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(path).unwrap();
        app.pending_files.push((FileTarget::VaultImport, rx));
        app.drain_file_dialogs();
    }

    /// Press Import backup… and pick `path`.
    fn import_dialog_for(app: &mut App, path: &Path) {
        app.vault_import_start();
        let request = app.file_dialog_queue.pop().expect("an open dialog");
        assert!(request.target == FileTarget::VaultImport && !request.save);
        assert_eq!(
            request.filters,
            vec![("Vault backup".to_owned(), vec!["t2vault".to_owned()])]
        );
        assert_eq!(request.default_name, None);
        choose_backup(app, Some(path.to_owned()));
        assert!(app.vault.import.is_some(), "the dialog opens");
    }

    fn import_dialog(app: &mut App) -> &mut ImportDialog {
        app.vault.import.as_mut().expect("the import dialog")
    }

    /// One Open backup run the tests share (Argon2id is slow in a test
    /// build): the backup written with the real writer, then opened through
    /// the dialog against Personal.
    struct OpenRun {
        bytes: Vec<u8>,
        opened: Vault,
        rows: Vec<ImportRow>,
        target: ImportTarget,
        passphrase_left: String,
        notice: Option<String>,
    }

    fn opened_backup() -> &'static OpenRun {
        static RUN: std::sync::OnceLock<OpenRun> = std::sync::OnceLock::new();
        RUN.get_or_init(|| {
            let dir = import_dir("run");
            let path = dir.join("personal.t2vault");
            let bytes = keyroost_vault::export_backup(&backup_vault(), IMPORT_PASS).unwrap();
            std::fs::write(&path, &bytes).unwrap();
            let mut key = FakeKey::new();
            key.add_vault("Personal", &key_vault());
            let mut app = app();
            unlock_into(&mut app, &mut key);
            import_dialog_for(&mut app, &path);
            replace_text(&mut import_dialog(&mut app).passphrase, IMPORT_PASS);
            app.vault_import_open();
            let d = import_dialog(&mut app);
            let run = OpenRun {
                bytes,
                opened: d.incoming.clone().expect("the backup opened"),
                rows: d.rows.clone(),
                target: d.target.clone(),
                passphrase_left: d.passphrase.clone(),
                notice: d.notice.clone(),
            };
            let _ = std::fs::remove_dir_all(&dir);
            run
        })
    }

    /// An unlocked key holding Personal (`key_vault`), its backup opened in
    /// the import dialog; Personal's credential ID.
    fn opened_into(app: &mut App, key: &mut FakeKey) -> Vec<u8> {
        let id = key.add_vault("Personal", &key_vault());
        unlock_into(app, key);
        open_shared_backup(app);
        id
    }

    /// Import backup… on the unlocked `app`, the shared backup opened.
    fn open_shared_backup(app: &mut App) {
        import_dialog_for(app, Path::new("personal.t2vault"));
        app.vault_apply_import_open(Some(KEY.into()), Ok(opened_backup().opened.clone()));
    }

    /// Press the preview's button, the job running against `key`.
    fn import_into(app: &mut App, key: &mut FakeKey) {
        match app.vault_take_import().expect("something to import") {
            ImportJob::Save {
                vault,
                kind,
                change,
            } => save_into(app, key, vault, kind, *change),
            ImportJob::Create { .. } => panic!("an import into a vault on the key"),
        }
    }

    fn ticks(app: &mut App) -> Vec<bool> {
        import_dialog(app).rows.iter().map(|r| r.ticked).collect()
    }

    fn statuses(app: &mut App) -> Vec<ImportStatus> {
        import_dialog(app).rows.iter().map(|r| r.status).collect()
    }

    #[test]
    fn plan_words_and_reasons() {
        use ImportStatus::*;
        let not_ticked = Some("not ticked");
        for (status, ticked, want) in [
            (New, true, ("add", None)),
            (New, false, ("skip", not_ticked)),
            (Newer, true, ("replace", Some("the backup's copy is newer"))),
            (Newer, false, ("skip", not_ticked)),
            (
                Older,
                false,
                (
                    "skip",
                    Some("the key's copy is newer (tick it to replace it)"),
                ),
            ),
            (
                Older,
                true,
                ("replace", Some("replaces the key's newer copy")),
            ),
            (
                Same,
                false,
                ("exists", Some("already in the vault; left as is")),
            ),
            (
                Same,
                true,
                ("exists", Some("already in the vault; left as is")),
            ),
        ] {
            assert_eq!(plan_of(status, ticked), want, "{status:?} {ticked}");
        }
        assert!(has_box(New) && has_box(Newer) && has_box(Older));
        assert!(!has_box(Same), "exists has no box");
        assert_eq!(
            UNKNOWN_STATUS, "this build can't tell how it compares",
            "the CLI's words"
        );
    }

    #[test]
    fn default_ticks_take_add_and_replace() {
        use ImportStatus::*;
        assert!(default_tick(New) && default_tick(Newer));
        assert!(!default_tick(Older) && !default_tick(Same));

        let run = opened_backup();
        assert_eq!(run.notice, None);
        assert!(
            run.passphrase_left.is_empty(),
            "the passphrase box is wiped"
        );
        assert!(
            matches!(&run.target, ImportTarget::Existing(v) if v.name.as_deref() == Some("Personal"))
        );
        assert_eq!(run.opened, backup_vault());
        assert_eq!(
            run.rows,
            vec![
                ImportRow {
                    index: 0,
                    status: New,
                    ticked: true
                },
                ImportRow {
                    index: 1,
                    status: New,
                    ticked: true
                },
                ImportRow {
                    index: 2,
                    status: Newer,
                    ticked: true
                },
                ImportRow {
                    index: 3,
                    status: Older,
                    ticked: false
                },
                ImportRow {
                    index: 4,
                    status: Same,
                    ticked: false
                },
            ]
        );
        assert_eq!(chosen(&run.rows), vec![0, 1, 2]);
    }

    #[test]
    fn import_summary_counts() {
        use ImportStatus::*;
        let rows = [
            ImportRow {
                index: 0,
                status: New,
                ticked: true,
            },
            ImportRow {
                index: 1,
                status: Newer,
                ticked: true,
            },
            ImportRow {
                index: 2,
                status: Older,
                ticked: false,
            },
            ImportRow {
                index: 3,
                status: Same,
                ticked: false,
            },
        ];
        assert_eq!(
            import_summary(&rows, 5),
            "5 entries in the vault; 1 will be added, 1 replaced, 1 left as is, 1 skipped."
        );
        assert_eq!(chosen(&rows), vec![0, 1]);
        let one = [ImportRow {
            index: 0,
            status: New,
            ticked: false,
        }];
        assert_eq!(
            import_summary(&one, 1),
            "1 entry in the vault; 0 will be added, 0 replaced, 0 left as is, 1 skipped."
        );
        assert!(chosen(&one).is_empty());
    }

    #[test]
    fn wrong_passphrase_fails_before_the_key() {
        let dir = import_dir("wrong");
        let path = dir.join("personal.t2vault");
        std::fs::write(&path, &opened_backup().bytes).unwrap();
        let mut key = FakeKey::new();
        key.add_vault("Personal", &key_vault());
        let mut app = app();
        unlock_into(&mut app, &mut key);
        let calls = key.log.len();
        let stored = key.stored().to_vec();
        import_dialog_for(&mut app, &path);
        // Open backup needs a passphrase first.
        app.vault_import_open();
        assert!(import_dialog(&mut app).incoming.is_none());
        replace_text(
            &mut import_dialog(&mut app).passphrase,
            "not the passphrase",
        );
        app.vault_import_open();
        let d = import_dialog(&mut app);
        assert_eq!(
            d.notice.as_deref(),
            Some("Could not decrypt the vault (wrong key or passphrase, or damaged data).")
        );
        assert!(d.incoming.is_none() && d.rows.is_empty());
        assert_eq!(key.log.len(), calls, "the key was not used");
        assert_eq!(key.stored(), &stored[..]);
        assert!(app.vault_session().unwrap().auth.is_some());

        // A file that isn't there says so in the CLI's words.
        // The OS words for a missing file differ by platform, so take them
        // from the OS itself.
        let gone = dir.join("gone.t2vault");
        let os_text = std::fs::read(&gone).unwrap_err().to_string();
        assert_eq!(
            open_backup(&gone, IMPORT_PASS).unwrap_err(),
            format!("cannot read {}: {os_text}", gone.display())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_backup_listing_one_id_twice_is_refused() {
        let dir = import_dir("dup");
        let path = dir.join("dup.t2vault");
        let mut twice = backup_vault();
        twice.entries[1].id = twice.entries[0].id.clone();
        std::fs::write(
            &path,
            keyroost_vault::export_backup(&twice, IMPORT_PASS).unwrap(),
        )
        .unwrap();
        let mut key = FakeKey::new();
        key.add_vault("Personal", &key_vault());
        let mut app = app();
        unlock_into(&mut app, &mut key);
        import_dialog_for(&mut app, &path);
        replace_text(&mut import_dialog(&mut app).passphrase, IMPORT_PASS);
        app.vault_import_open();
        let d = import_dialog(&mut app);
        assert_eq!(
            d.notice.as_deref(),
            Some("This backup lists two entries with the same id; it may be damaged.")
        );
        assert!(d.incoming.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn import_applies_only_ticked_rows() {
        let mut key = FakeKey::new();
        let mut app = app();
        let id = opened_into(&mut app, &mut key);
        // The second "Mail" unticked, the older Bank ticked.
        app.vault_import_tick(1, false);
        app.vault_import_tick(3, true);
        // A row with no box can't be ticked.
        app.vault_import_tick(4, true);
        assert_eq!(ticks(&mut app), vec![true, false, true, true, false]);
        let calls = key.log.len();
        import_into(&mut app, &mut key);
        assert!(!touched_since(&key, calls), "an import asks no touch");
        let on_key = key.vault_on_key(&id).unwrap();
        let backup = backup_vault();
        let find = |id: &str| on_key.entries.iter().find(|e| e.id == id).cloned();
        assert_eq!(find("mama0001"), Some(backup.entries[0].clone()));
        assert_eq!(find("mama0002"), None, "the unticked Mail is not added");
        assert_eq!(find("ghghghgh"), Some(backup.entries[2].clone()));
        assert_eq!(
            find("bkbkbkbk"),
            Some(backup.entries[3].clone()),
            "ticked: replaced"
        );
        assert_eq!(on_key.entries.len(), 4);
        assert_eq!(
            app.vault.info.as_deref(),
            Some("Imported into vault \"Personal\": 1 added, 2 replaced.")
        );
        assert!(app.vault.import.is_none(), "the dialog closes");
        let s = app.vault_session().unwrap();
        assert!(s.auth.is_some());
        assert_eq!(
            chip_label(app.selected_vault().unwrap()),
            "Personal \u{00B7} 4"
        );
        let last = app.log.last().unwrap();
        assert_eq!(last.severity, Severity::Ok);
        assert_eq!(
            last.text,
            "Vault: imported into vault \"Personal\": 1 added, 2 replaced"
        );
        for l in &app.log {
            for secret in ["Mail", "GitHub", "Bank", "alice", "gh-backup"] {
                assert!(!l.text.contains(secret), "{}", l.text);
            }
        }
    }

    #[test]
    fn tick_all_and_untick_all() {
        let mut key = FakeKey::new();
        let mut app = app();
        opened_into(&mut app, &mut key);
        app.vault_import_tick_all(true);
        assert_eq!(ticks(&mut app), vec![true, true, true, true, false]);
        assert_eq!(chosen(&import_dialog(&mut app).rows), vec![0, 1, 2, 3]);
        app.vault_import_tick_all(false);
        assert_eq!(ticks(&mut app), vec![false; 5]);
    }

    #[test]
    fn nothing_ticked_disables_import() {
        let mut key = FakeKey::new();
        let mut app = app();
        opened_into(&mut app, &mut key);
        let text = list_text(&mut app);
        assert!(text.contains("Import 3 entries"), "{text}");
        assert!(!text.contains("Nothing to add."), "{text}");
        app.vault_import_tick_all(false);
        let text = list_text(&mut app);
        assert!(text.contains("Nothing to add."), "{text}");
        let calls = key.log.len();
        assert!(app.vault_take_import().is_none());
        app.vault_import();
        assert_eq!(key.log.len(), calls, "the key was not used");
        assert!(app.vault_session().unwrap().auth.is_some(), "nothing taken");
        assert!(app.vault.import.is_some(), "the dialog stays");
    }

    #[test]
    fn the_preview_draws_each_row_with_its_plan_and_reason() {
        let mut key = FakeKey::new();
        let mut app = app();
        opened_into(&mut app, &mut key);
        let text = list_text(&mut app);
        for line in [
            "Import backup",
            "personal.t2vault",
            "Into vault",
            "Personal \u{00B7} 3",
            "5 entries in personal.t2vault for vault \"Personal\":",
            "Mail (alice)",
            "Mail (bob) \u{00B7} mail.example",
            "GitHub (alice)",
            "the backup's copy is newer",
            "the key's copy is newer (tick it to replace it)",
            "already in the vault; left as is",
            "Tick all",
            "Untick all",
            "3 entries in the vault; 2 will be added, 1 replaced, 1 left as is, 1 skipped.",
            "Import 3 entries",
            "Cancel",
        ] {
            assert!(text.contains(line), "{line}: {text}");
        }
        for word in ["add", "replace", "skip", "exists"] {
            assert!(text.lines().any(|l| l == word), "{word}: {text}");
        }
        for secret in ["mail-a", "gh-backup", "bank-backup", "mama0001", "ghghghgh"] {
            assert!(!text.contains(secret), "{secret}: {text}");
        }
        // Before the backup is opened: the passphrase box and Open backup.
        app.vault.import.as_mut().unwrap().incoming = None;
        let text = list_text(&mut app);
        for line in ["Passphrase", "Open backup", "Cancel"] {
            assert!(text.contains(line), "{line}: {text}");
        }
        assert!(!text.contains("Tick all"), "{text}");
    }

    #[test]
    fn changing_the_target_reclassifies() {
        let mut key = FakeKey::new();
        key.add_vault("Personal", &key_vault());
        key.add_vault("Work", &Vault::default());
        let mut app = app();
        unlock_into(&mut app, &mut key);
        open_shared_backup(&mut app);
        use ImportStatus::*;
        assert_eq!(statuses(&mut app), vec![New, New, Newer, Older, Same]);
        app.vault_import_tick(0, false);
        app.vault_import_set_target(ImportTarget::New);
        assert_eq!(statuses(&mut app), vec![New; 5]);
        assert_eq!(ticks(&mut app), vec![true; 5], "the default ticks again");
        let work = app.vault_session().unwrap().unlocked.vaults[1]
            .vault_ref
            .clone();
        assert_eq!(work.name.as_deref(), Some("Work"));
        app.vault_import_set_target(ImportTarget::Existing(work));
        assert_eq!(statuses(&mut app), vec![New; 5]);
        let text = list_text(&mut app);
        assert!(text.contains("for vault \"Work\":"), "{text}");
        assert!(
            text.contains("0 entries in the vault; 5 will be added"),
            "{text}"
        );
    }

    #[test]
    fn import_into_a_new_vault_creates_it_with_two_touches() {
        let mut key = FakeKey::new();
        let mut app = app();
        unlock_into(&mut app, &mut key);
        assert!(app.vault_session().unwrap().unlocked.vaults.is_empty());
        // A key with no vault still offers Import backup….
        assert!(list_text(&mut app).contains("Import backup\u{2026}"));
        import_dialog_for(&mut app, Path::new("/backups/travel.t2vault"));
        {
            let d = import_dialog(&mut app);
            assert!(d.target == ImportTarget::New);
            assert_eq!(d.new_name, "travel", "the file's name");
        }
        app.vault_apply_import_open(Some(KEY.into()), Ok(opened_backup().opened.clone()));
        assert_eq!(statuses(&mut app), vec![ImportStatus::New; 5]);
        app.vault_import_tick(4, false);
        replace_text(&mut import_dialog(&mut app).new_name, "Travel");
        let text = list_text(&mut app);
        for line in [
            "A new vault named\u{2026}",
            "5 entries in travel.t2vault for new vault \"Travel\":",
            "0 entries in the vault; 4 will be added, 0 replaced, 0 left as is, 1 skipped.",
            "Create vault \"Travel\" and import 4 entries",
            "This asks for two touches.",
        ] {
            assert!(text.contains(line), "{line}: {text}");
        }
        let Some(ImportJob::Create {
            name,
            mut auth,
            initial,
        }) = app.vault_take_import()
        else {
            panic!("a create");
        };
        assert_eq!(name, "Travel");
        let backup = backup_vault();
        assert_eq!(initial.entries, backup.entries[..4].to_vec());
        let banner = Arc::new(Mutex::new(None));
        let mut watched = Watched {
            key: &mut key,
            banner: banner.clone(),
            at_touch: Vec::new(),
        };
        let result = {
            let mut touches = TouchProgress::new(banner.clone(), 2);
            run_create(&mut watched, &mut auth, &name, &initial, &mut touches)
                .map_err(VaultJobError::from)
        };
        assert_eq!(
            watched.at_touch,
            vec![
                Some("Touch your key (1 of 2)\u{2026}".to_owned()),
                Some("Touch your key (2 of 2)\u{2026}".to_owned()),
            ]
        );
        app.vault_apply_create(Some(KEY.into()), auth, Some(initial.entries.len()), result);
        assert_eq!(
            app.vault.info,
            Some(format!(
                "Imported into vault \"Travel\": 4 added, 0 replaced. {}",
                backup_reminder("Travel")
            ))
        );
        assert!(app.vault.import.is_none(), "the dialog closes");
        let new = app.selected_vault().unwrap().vault_ref.clone();
        assert_eq!(new.name.as_deref(), Some("Travel"));
        assert_eq!(key.vault_on_key(&new.credential_id), Some(initial));
    }

    #[test]
    fn a_new_vault_name_is_checked_before_the_job() {
        let mut key = FakeKey::new();
        let mut app = app();
        opened_into(&mut app, &mut key);
        app.vault_import_set_target(ImportTarget::New);
        for (name, said) in [
            (
                "Personal",
                "this key already holds a vault named \"Personal\"",
            ),
            ("", "a vault name must be 1 to 32 bytes long"),
        ] {
            replace_text(&mut import_dialog(&mut app).new_name, name);
            let calls = key.log.len();
            assert!(app.vault_take_import().is_none(), "{name}");
            assert_eq!(key.log.len(), calls);
            let err = app.vault.error.clone().unwrap_or_default().to_lowercase();
            assert!(err.contains(&said.to_lowercase()), "{name}: {err}");
            assert!(app.vault_session().unwrap().auth.is_some(), "nothing taken");
            assert!(app.vault.import.is_some(), "the dialog stays");
        }
    }

    #[test]
    fn import_conflict_reclassifies_the_preview() {
        let mut key = FakeKey::new();
        let id = key.add_vault("Personal", &key_vault());
        // Another program changes GitHub (a ticked replace) after unlock.
        let mut theirs = key_vault();
        theirs.entries[0].password = Zeroizing::new("gh-theirs".into());
        theirs.entries[0].modified_minutes = 300;
        key.hook = writes_elsewhere(id.clone(), theirs.clone());
        let mut app = app();
        unlock_into(&mut app, &mut key);
        open_shared_backup(&mut app);
        assert_eq!(statuses(&mut app)[2], ImportStatus::Newer, "as unlocked");
        import_into(&mut app, &mut key);
        assert_eq!(
            key.vault_on_key(&id),
            Some(theirs.clone()),
            "nothing was written"
        );
        let d = import_dialog(&mut app);
        assert_eq!(
            d.notice.as_deref(),
            Some(
                "An entry in this vault changed on the key since it was opened; nothing was \
                 written. The list below shows the vault as it is now."
            )
        );
        use ImportStatus::*;
        assert_eq!(statuses(&mut app), vec![New, New, Older, Older, Same]);
        assert_eq!(ticks(&mut app), vec![true, true, false, false, false]);
        assert_eq!(session_entry(&app, "GitHub").password.as_str(), "gh-theirs");
        assert!(app.vault_session().unwrap().auth.is_some());
        assert!(app.log.iter().any(|l| l.severity == Severity::Warn));
        // Importing again now adds the two Mails and leaves GitHub alone.
        import_into(&mut app, &mut key);
        assert_eq!(
            app.vault.info.as_deref(),
            Some("Imported into vault \"Personal\": 2 added, 0 replaced.")
        );
        let on_key = key.vault_on_key(&id).unwrap();
        assert_eq!(on_key.entries.len(), 5);
        assert_eq!(on_key.entries[0], theirs.entries[0]);
    }

    #[test]
    fn a_refresh_under_the_preview_reclassifies_changed_rows() {
        let mut key = FakeKey::new();
        let mut app = app();
        let id = opened_into(&mut app, &mut key);
        // The user's own tick on an unchanged row survives the refresh.
        app.vault_import_tick(1, false);
        // Another program saves a GitHub newer than the backup's.
        let mut theirs = key_vault();
        theirs.entries[0].password = Zeroizing::new("gh-theirs".into());
        theirs.entries[0].modified_minutes = 300;
        key.put_vault(&id, &theirs);
        // Refresh, as the job does.
        let mut unlocked = app.vault_session().unwrap().unlocked.clone();
        let result = run_reload(&mut key, &mut unlocked).map_err(VaultJobError::from);
        app.vault_apply_reload(Some(KEY.into()), unlocked, result);
        use ImportStatus::*;
        assert_eq!(statuses(&mut app), vec![New, New, Older, Older, Same]);
        assert_eq!(ticks(&mut app), vec![true, false, false, false, false]);
        assert_eq!(plan_of(Older, false).0, "skip");
        assert_eq!(
            import_dialog(&mut app).notice.as_deref(),
            Some(IMPORT_REFRESHED)
        );
        import_into(&mut app, &mut key);
        let on_key = key.vault_on_key(&id).unwrap();
        assert_eq!(on_key.entries[0], theirs.entries[0], "not overwritten");
        assert_eq!(
            app.vault.info.as_deref(),
            Some("Imported into vault \"Personal\": 1 added, 0 replaced.")
        );
        // A refresh that changes nothing says nothing.
        let mut key = FakeKey::new();
        let mut app = super::tests::app();
        opened_into(&mut app, &mut key);
        let mut unlocked = app.vault_session().unwrap().unlocked.clone();
        let result = run_reload(&mut key, &mut unlocked).map_err(VaultJobError::from);
        app.vault_apply_reload(Some(KEY.into()), unlocked, result);
        assert_eq!(import_dialog(&mut app).notice, None);
        assert_eq!(ticks(&mut app), vec![true, true, true, false, false]);
    }

    #[test]
    fn import_logs_the_store_note() {
        // What the store holds after this import, from a first run.
        let mut key = FakeKey::new();
        let mut app = app();
        opened_into(&mut app, &mut key);
        import_into(&mut app, &mut key);
        let after = app.vault_session().unwrap().unlocked.capacity.used_bytes;
        assert!(
            app.log.iter().all(|l| l.severity != Severity::Warn),
            "room left: no note"
        );
        // The same import into a store just big enough for it.
        let mut key = FakeKey::new();
        let mut app = super::tests::app();
        opened_into(&mut app, &mut key);
        key.set_max_bytes(after + 40);
        import_into(&mut app, &mut key);
        assert!(app.vault.import.is_none(), "never refused for it");
        let cap = app.vault_session().unwrap().unlocked.capacity;
        let line = blob_space_line("Vault", &cap).expect("under a quarter free");
        assert_eq!(
            app.log
                .iter()
                .filter(|l| l.severity == Severity::Warn && l.text == line)
                .count(),
            1
        );
    }

    #[test]
    fn the_decrypted_backup_counts_for_the_idle_lock() {
        let mut app = app();
        assert!(!app.holds_opened_secrets());
        app.vault.import = Some(ImportDialog::new(
            "personal.t2vault".into(),
            ImportTarget::New,
            String::new(),
        ));
        assert!(!app.holds_opened_secrets(), "nothing opened yet");
        assert!(!app.holds_unlocked_secrets());
        import_dialog(&mut app).passphrase.push_str(IMPORT_PASS);
        assert!(
            app.holds_unlocked_secrets(),
            "a typed passphrase is a typed secret"
        );
        assert_eq!(app.vault.secrets_mut().len(), 2);
        import_dialog(&mut app).incoming = Some(backup_vault());
        assert!(app.holds_opened_secrets());

        // The idle lock drops the dialog and what it opened.
        let mut key = FakeKey::new();
        let mut app = super::tests::app();
        opened_into(&mut app, &mut key);
        let t0 = std::time::Instant::now();
        app.idle_lock_tick(t0, false);
        app.idle_lock_tick(t0 + crate::IDLE_LOCK_AFTER, false);
        assert!(app.vault.import.is_none());
        assert!(!app.holds_unlocked_secrets());
    }

    #[test]
    fn import_dialog_wipes_and_cancel_forgets_the_file() {
        let mut d = ImportDialog::new("p.t2vault".into(), ImportTarget::New, String::new());
        d.passphrase.push_str(IMPORT_PASS);
        assert_eq!(d.secrets_mut().len(), 1);
        d.wipe_typed();
        assert!(d.passphrase.is_empty());

        let mut key = FakeKey::new();
        key.add_vault("Personal", &key_vault());
        let mut app = app();
        unlock_into(&mut app, &mut key);
        // A cancelled open dialog opens nothing; a second press while one is
        // open asks for no second dialog.
        app.vault_import_start();
        app.vault_import_start();
        assert_eq!(app.file_dialog_queue.len(), 1);
        app.file_dialog_queue.clear();
        choose_backup(&mut app, None);
        assert!(app.vault.import.is_none());
        // A dialog resolved after a lock opens nothing.
        app.vault_import_start();
        app.vault_lock(None);
        unlock_into(&mut app, &mut key);
        choose_backup(&mut app, Some("p.t2vault".into()));
        assert!(app.vault.import.is_none());
        // Cancel closes the dialog.
        import_dialog_for(&mut app, Path::new("p.t2vault"));
        app.vault_import_cancel();
        assert!(app.vault.import.is_none());
    }

    #[test]
    fn an_opened_backup_for_another_key_is_dropped() {
        let mut key = FakeKey::new();
        key.add_vault("Personal", &key_vault());
        let mut app = app();
        unlock_into(&mut app, &mut key);
        import_dialog_for(&mut app, Path::new("p.t2vault"));
        app.vault_apply_import_open(Some("serial:BBB".into()), Ok(backup_vault()));
        assert!(import_dialog(&mut app).incoming.is_none());
        // An unavailable shown vault offers no import into it.
        let damaged = key.add_vault("Old", &Vault::default());
        key.put_blob(&damaged, b"not a vault at all, just bytes");
        let mut app = super::tests::app();
        unlock_into(&mut app, &mut key);
        app.vault_select(damaged);
        app.vault_import_start();
        assert!(app.file_dialog_queue.is_empty());
    }

    // ----- Final review fixes -----

    /// Every text shape of one headless 900 x 700 frame drawn by `render`,
    /// with where it was drawn.
    fn frame_texts(
        ctx: &egui::Context,
        events: Vec<egui::Event>,
        render: impl FnMut(&mut egui::Ui, &Palette),
    ) -> Vec<(String, egui::Rect)> {
        frame_texts_at(ctx, events, egui::vec2(900.0, 700.0), render)
    }

    /// [`frame_texts`] in a window of `size`.
    fn frame_texts_at(
        ctx: &egui::Context,
        events: Vec<egui::Event>,
        size: egui::Vec2,
        mut render: impl FnMut(&mut egui::Ui, &Palette),
    ) -> Vec<(String, egui::Rect)> {
        use crate::tests::TestFrame;
        use crate::ui::theme::Mode;
        fn collect(shape: &egui::Shape, out: &mut Vec<(String, egui::Rect)>) {
            match shape {
                egui::Shape::Text(t) => {
                    out.push((t.galley.text().to_owned(), shape.visual_bounding_rect()))
                }
                egui::Shape::Vec(shapes) => shapes.iter().for_each(|s| collect(s, out)),
                _ => {}
            }
        }
        let palette = Palette::new(Mode::Dark, Palette::ACCENTS[0], false);
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
            events,
            ..Default::default()
        };
        let output = ctx.test_frame(input, |ui| {
            egui::CentralPanel::default().show(ui, |ui| render(ui, &palette));
        });
        let mut out = Vec::new();
        for clipped in output.shapes {
            collect(&clipped.shape, &mut out);
        }
        out
    }

    /// Click the text `label` that `render` draws, as a person would: a
    /// frame to lay it out, then the pointer moves there, presses and lets
    /// go.
    fn click_text(label: &str, mut render: impl FnMut(&mut egui::Ui, &Palette)) {
        let ctx = egui::Context::default();
        theme::install_fonts(&ctx);
        // Two frames: a window's first one only sizes it.
        frame_texts(&ctx, Vec::new(), &mut render);
        let texts = frame_texts(&ctx, Vec::new(), &mut render);
        let pos = texts
            .iter()
            .find(|(t, _)| t == label)
            .map(|(_, r)| r.center())
            .unwrap_or_else(|| panic!("{label} is drawn: {texts:?}"));
        let press = |pressed| egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        };
        for events in [
            vec![egui::Event::PointerMoved(pos)],
            vec![press(true)],
            vec![press(false)],
        ] {
            frame_texts(&ctx, events, &mut render);
        }
    }

    fn click_in_list(app: &mut App, label: &str) {
        click_text(label, |ui, p| app.render_vault_list(ui, p));
    }

    /// Save → Cancel → Add entry can't happen: while a save runs, its form's
    /// Cancel is disabled and Add entry / Edit don't open another form, so
    /// the save's end reports on the form it was started from.
    #[test]
    fn a_running_save_keeps_its_form() {
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        let github = session_entry(&app, "GitHub");
        app.vault_add_entry();
        replace_text(&mut form(&mut app).title, "Saving");
        // The save's job is in flight.
        app.busy_jobs = 1;
        click_in_list(&mut app, "Cancel");
        assert_eq!(form(&mut app).title, "Saving", "Cancel is disabled");
        app.vault_cancel_form();
        assert_eq!(form(&mut app).title, "Saving");
        app.vault_add_entry();
        assert_eq!(form(&mut app).title, "Saving", "no new form");
        app.vault_edit_entry(&github.id);
        assert!(form(&mut app).editing.is_none(), "no edit form either");
        assert_eq!(form(&mut app).title, "Saving");
        // Once the save ended, Cancel works (the click reaches it).
        app.busy_jobs = 0;
        click_in_list(&mut app, "Cancel");
        assert!(app.vault.form.is_none());
    }

    /// The FIDO2 tab's passkey list: a github.com passkey, and every
    /// credential on `key` under the vault's relying party.
    fn passkeys_of(app: &mut App, key: &FakeKey) {
        use keyroost_ctap::cred_mgmt::{Credential, CredentialUser, RelyingParty};
        let creds = key
            .creds
            .iter()
            .map(|c| Credential {
                credential_id: c.id.clone(),
                user: CredentialUser {
                    id: c.user_id.clone(),
                    name: c.user_name.clone(),
                    display_name: None,
                },
                algorithm: None,
                large_blob_key: None,
            })
            .collect();
        let github = Credential {
            credential_id: GITHUB_CRED.to_vec(),
            user: CredentialUser {
                id: vec![7; 16],
                name: Some("alice".into()),
                display_name: None,
            },
            algorithm: None,
            large_blob_key: None,
        };
        let rp = |id: &str| RelyingParty {
            id: id.to_owned(),
            name: None,
            rp_id_hash: None,
        };
        let mut session = fido_session(FakeKey::PIN);
        session.rps = Arc::new(vec![
            (rp("github.com"), vec![github]),
            (rp(keyroost_vault::RP_ID), creds),
        ]);
        app.security_keys.session = Some(session);
        app.security_keys.session_device = Some(KEY.into());
        // The list is showing: the FIDO2 tab's Passkeys.
        app.cap_tab = CapTab::Fido2;
        app.security_keys.subview = crate::FidoSubview::Passkeys;
    }

    /// The passkey delete question's text in one frame (after the window's
    /// sizing frame).
    fn passkey_question(app: &mut App) -> String {
        let ctx = egui::Context::default();
        theme::install_fonts(&ctx);
        let mut texts = Vec::new();
        for _ in 0..2 {
            texts = frame_texts(&ctx, Vec::new(), |ui, p| {
                app.render_passkey_delete_confirm(ui.ctx(), p);
            });
        }
        texts.into_iter().map(|(t, _)| t + "\n").collect()
    }

    /// Click `label` in the passkey delete question; what it handed over
    /// to delete.
    fn answer_passkey_question(app: &mut App, label: &str) -> Option<Vec<u8>> {
        let mut confirmed = None;
        click_text(label, |ui, p| {
            if let Some(id) = app.render_passkey_delete_confirm(ui.ctx(), p) {
                confirmed = Some(id);
            }
        });
        confirmed
    }

    const GITHUB_CRED: &[u8] = b"github credential";

    #[test]
    fn every_passkey_remove_asks_first() {
        use keyroost_ctap::cred_mgmt::CredentialUser;
        let user = |name: Option<&str>, display: Option<&str>| CredentialUser {
            id: vec![1],
            name: name.map(str::to_owned),
            display_name: display.map(str::to_owned),
        };
        assert_eq!(
            crate::passkey_label("github.com", &user(Some("alice"), Some("Alice"))),
            "github.com (alice)"
        );
        assert_eq!(
            crate::passkey_label("github.com", &user(None, Some("Alice"))),
            "github.com (Alice)"
        );
        assert_eq!(
            crate::passkey_label("github.com", &user(Some(""), None)),
            "github.com"
        );
        // Text-direction and zero-width marks don't reach the screen.
        assert_eq!(
            crate::passkey_label("github.com", &user(Some("ali\u{202E}ce\u{200B}"), None)),
            "github.com (ali ce )"
        );

        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut app = app();
        passkeys_of(&mut app, &key);
        let ask = |app: &mut App| {
            app.ask_delete_passkey(GITHUB_CRED.to_vec(), "github.com (alice)".into(), false);
        };
        ask(&mut app);
        let text = passkey_question(&mut app);
        for line in [
            "Delete passkey?",
            "Permanently delete \u{201c}github.com (alice)\u{201d} from this key? This cannot \
             be undone.",
            "Delete",
            "Cancel",
        ] {
            assert!(text.contains(line), "{line}: {text}");
        }
        assert!(!text.contains("password vault"), "{text}");
        assert!(!text.contains(EXPORT_BUTTON), "{text}");
        // Cancel deletes nothing.
        assert_eq!(answer_passkey_question(&mut app, "Cancel"), None);
        assert!(app.security_keys.passkey_confirm_delete.is_none());
        // Delete is refused while a job runs; the question stays.
        ask(&mut app);
        app.busy_jobs = 1;
        assert_eq!(answer_passkey_question(&mut app, "Delete"), None);
        assert!(app.security_keys.passkey_confirm_delete.is_some());
        app.busy_jobs = 0;
        assert_eq!(
            answer_passkey_question(&mut app, "Delete"),
            Some(GITHUB_CRED.to_vec())
        );
        assert!(app.security_keys.passkey_confirm_delete.is_none());
        // Another key selected: the question is dropped, never shown over it.
        ask(&mut app);
        app.selected_device = Some("serial:BBB".into());
        assert!(!passkey_question(&mut app).contains("Permanently delete"));
        assert!(app.security_keys.passkey_confirm_delete.is_none());
        // So is one on another tab: it never floats over that tab.
        app.selected_device = Some(KEY.into());
        ask(&mut app);
        app.cap_tab = CapTab::Vault;
        assert!(!passkey_question(&mut app).contains("Permanently delete"));
        assert!(app.security_keys.passkey_confirm_delete.is_none());
        app.cap_tab = CapTab::Fido2;
        ask(&mut app);
        app.security_keys.subview = crate::FidoSubview::Settings;
        passkey_question(&mut app);
        assert!(app.security_keys.passkey_confirm_delete.is_none());
        app.security_keys.subview = crate::FidoSubview::Passkeys;
        // So is one whose passkey left the list.
        app.selected_device = Some(KEY.into());
        app.ask_delete_passkey(b"gone".to_vec(), "gone.example".into(), false);
        passkey_question(&mut app);
        assert!(app.security_keys.passkey_confirm_delete.is_none());
    }

    #[test]
    fn a_vault_passkeys_question_adds_its_warning() {
        assert!(is_vault_passkey("fido2-vault.token2"));
        assert!(!is_vault_passkey("github.com"));
        let mut key = FakeKey::new();
        let personal = two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        passkeys_of(&mut app, &key);
        app.ask_delete_passkey(
            personal.clone(),
            "fido2-vault.token2 (Personal)".into(),
            true,
        );
        let text = passkey_question(&mut app);
        for line in [
            "Permanently delete \u{201c}fido2-vault.token2 (Personal)\u{201d} from this key? \
             This cannot be undone.",
            &vault_passkey_warning(Some("Personal")),
            EXPORT_BUTTON,
            "Delete",
            "Cancel",
        ] {
            assert!(text.contains(line), "{line}: {text}");
        }
        assert_eq!(
            vault_passkey_warning(None),
            "This passkey unlocks a password vault: deleting it loses every entry in it. To \
             keep them, export a backup first."
        );
        // Locked, the passkey list still names the vault; there is nothing
        // to export from here.
        app.vault_lock(None);
        let text = passkey_question(&mut app);
        assert!(
            text.contains(&vault_passkey_warning(Some("Personal"))),
            "{text}"
        );
        assert!(!text.contains(EXPORT_BUTTON), "{text}");
    }

    #[test]
    fn export_from_the_passkey_question_says_when_it_cant_start() {
        let mut key = FakeKey::new();
        let personal = two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        passkeys_of(&mut app, &key);
        let work = app.vault_session().unwrap().unlocked.vaults[1]
            .vault_ref
            .credential_id
            .clone();
        // Work's backup is still waiting for its save dialog.
        app.vault_select(work.clone());
        app.vault_export_start();
        app.file_dialog_queue.clear();
        app.ask_delete_passkey(
            personal.clone(),
            "fido2-vault.token2 (Personal)".into(),
            true,
        );
        assert_eq!(answer_passkey_question(&mut app, EXPORT_BUTTON), None);
        assert_eq!(app.cap_tab, CapTab::Fido2, "no tab switch");
        assert_eq!(app.vault.selected.as_deref(), Some(work.as_slice()));
        let notice = backup_pending_text(app.vault.export_for.as_ref().unwrap());
        let q = app.security_keys.passkey_confirm_delete.as_ref().unwrap();
        assert_eq!(q.notice.as_deref(), Some(notice.as_str()));
        assert!(passkey_question(&mut app).contains(&notice));
        // With nothing waiting, it goes to the Vault tab with Personal's
        // save dialog, and the question closes: nothing can be deleted
        // over the backup form without a new Remove.
        app.vault.export_for = None;
        assert_eq!(answer_passkey_question(&mut app, EXPORT_BUTTON), None);
        assert_eq!(app.cap_tab, CapTab::Vault);
        assert_eq!(app.vault.selected.as_deref(), Some(personal.as_slice()));
        assert_eq!(
            app.vault
                .export_for
                .as_ref()
                .map(|v| v.credential_id.clone()),
            Some(personal.clone())
        );
        assert_eq!(app.file_dialog_queue.len(), 1);
        assert!(app.security_keys.passkey_confirm_delete.is_none());
        assert!(!passkey_question(&mut app).contains("Permanently delete"));
        app.cap_tab = CapTab::Fido2;
        assert!(
            !passkey_question(&mut app).contains("Permanently delete"),
            "back on the FIDO2 tab, Remove has to ask again"
        );
        // Locked meanwhile: said, and nothing else changes.
        app.cap_tab = CapTab::Fido2;
        app.vault_lock(None);
        assert_eq!(
            app.vault_passkey_export(&personal),
            Err(PASSKEY_EXPORT_LOCKED.to_owned())
        );
        assert_eq!(app.cap_tab, CapTab::Fido2);
    }

    #[test]
    fn deleting_a_vaults_passkey_drops_the_vault() {
        let mut key = FakeKey::new();
        let personal = two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        passkeys_of(&mut app, &key);
        let fresh = || Ok(fido_session(FakeKey::PIN));
        // Another passkey: the vault stays.
        app.apply_passkey_deleted(Some(KEY.into()), b"some website", true, fresh());
        assert!(app.vault_session().is_some());
        // A delete that failed changes nothing.
        app.apply_passkey_deleted(
            Some(KEY.into()),
            &personal,
            false,
            Err(crate::SessionOpError::msg("not deleted")),
        );
        assert!(app.vault_session().is_some());
        // The vault's own passkey: the vault leaves the session, as one
        // gone elsewhere does, so no later save can report success.
        app.apply_passkey_deleted(Some(KEY.into()), &personal, true, fresh());
        assert!(app.vault.session.is_none());
        let err = app.vault.error.clone().unwrap();
        assert_eq!(
            err,
            format!(
                "Vault \"Personal\" is no longer on the key: its passkey was deleted on the \
                 FIDO2 tab. {UNLOCK_AGAIN}"
            )
        );
        assert!(app
            .log
            .iter()
            .any(|l| l.severity == Severity::Warn && l.text == format!("Vault: {err}")));
        assert!(app.security_keys.session.is_some(), "the FIDO2 tab stays");
    }

    #[test]
    fn pin_change_and_fido_reset_say_why_the_vault_locked() {
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        app.apply_pin_changed(Ok(()));
        assert_eq!(
            app.vault.error.as_deref(),
            Some(
                "The FIDO2 PIN was changed, so the vault locked. Unlock the vault again to see \
                 what the key holds now."
            )
        );
        let mut app = super::tests::app();
        unlock_into(&mut app, &mut key);
        App::apply_reset_path_outcome(&mut app, Some(&KEY.to_owned()), Ok(()));
        assert_eq!(app.vault.error.as_deref(), Some(FIDO_RESET_LOCKED));
    }

    /// The tab's lines that send the person back to Unlock all end alike.
    #[test]
    fn every_unlock_again_line_is_worded_alike() {
        let gone = vault_error_text(&VaultKeyError::VaultGone {
            name: Some("Work".into()),
        });
        let old = vault_error_text(&VaultKeyError::OldNotDeleted {
            name: Some("Personal".into()),
            cause: Box::new(VaultKeyError::Ctap(CtapError::StatusCode(0x30))),
            old: OldVault::Kept,
        });
        for text in [
            gone,
            old,
            pin_changed_text(),
            with_unlock_again(JOB_NOT_STARTED),
            with_unlock_again(SAVE_NOT_STARTED),
            passkey_deleted_text(None),
        ] {
            assert!(text.ends_with(UNLOCK_AGAIN), "{text}");
            assert_eq!(text.matches("nlock").count(), 1, "{text}");
        }
    }

    /// A dead worker: every job is refused as not queued.
    fn dead_worker(app: &mut App) {
        let (job_tx, job_rx) = std::sync::mpsc::channel();
        drop(job_rx);
        let (_result_tx, result_rx) = std::sync::mpsc::channel();
        app.worker = Some(crate::Worker { job_tx, result_rx });
    }

    #[test]
    fn an_unlock_that_cant_start_says_so_and_wipes_the_pin() {
        // The job is never run: nothing opens this path.
        let mut app = App {
            devices: vec![crate::ui::device::Device {
                hid_path: Some("/nonexistent/keyroost-test/hidraw0".into()),
                ..crate::tests::test_key(KEY, "AAA", None)
            }],
            selected_device: Some(KEY.into()),
            ..Default::default()
        };
        dead_worker(&mut app);
        replace_text(&mut app.vault.pin_input, FakeKey::PIN);
        app.vault_unlock();
        assert!(app.vault.pin_input.is_empty(), "the typed PIN is wiped");
        assert_eq!(app.vault.error.as_deref(), Some(UNLOCK_NOT_STARTED_TYPED));
        assert!(app.vault.session.is_none());
        // With the FIDO2 tab's PIN, there is nothing to type again.
        app.security_keys.session = Some(fido_session(FakeKey::PIN));
        app.security_keys.session_device = Some(KEY.into());
        app.vault_unlock();
        assert_eq!(app.vault.error.as_deref(), Some(UNLOCK_NOT_STARTED));
    }

    /// A save dialog opened for one vault before a lock resolves after
    /// Export backup… was pressed for another: its file isn't used for that
    /// backup, which keeps waiting for its own dialog.
    #[test]
    fn a_save_dialog_for_another_vault_is_not_used() {
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        app.vault_export_start();
        let first = app.file_dialog_queue.pop().unwrap().target;
        app.vault_lock(None);
        unlock_into(&mut app, &mut key);
        let work = app.vault_session().unwrap().unlocked.vaults[1]
            .vault_ref
            .clone();
        app.vault_select(work.credential_id.clone());
        app.vault_export_start();
        let second = app.file_dialog_queue.pop().unwrap().target;
        resolve_dialog(&mut app, first.clone(), Some("personal.t2vault".into()));
        assert!(app.vault.export.is_none(), "no passphrase dialog for Work");
        assert_eq!(app.vault.error.as_deref(), Some(EXPORT_OTHER_VAULT));
        assert_eq!(
            app.vault
                .export_for
                .as_ref()
                .map(|v| v.credential_id.clone()),
            Some(work.credential_id.clone()),
            "Work's backup still waits"
        );
        // A cancelled dialog of the other vault doesn't drop it either.
        resolve_dialog(&mut app, first, None);
        assert!(app.vault.export_for.is_some());
        // A dialog for the same vault on another key isn't used either.
        let FileTarget::VaultExport { credential_id, .. } = second.clone() else {
            panic!("a backup's save dialog");
        };
        let elsewhere = FileTarget::VaultExport {
            credential_id,
            device: Some("serial:BBB".into()),
        };
        resolve_dialog(&mut app, elsewhere, Some("work.t2vault".into()));
        assert!(app.vault.export.is_none());
        // Its own dialog opens the passphrase dialog for Work.
        resolve_dialog(&mut app, second, Some("work.t2vault".into()));
        let d = app.vault.export.as_ref().expect("the passphrase dialog");
        assert_eq!(d.vault.credential_id, work.credential_id);
        assert_eq!(d.path, Path::new("work.t2vault"));
    }

    /// The Storage tab's question names what a delete loses (ruling R4).
    #[test]
    fn storage_delete_says_what_it_loses() {
        assert_eq!(
            crate::lb_delete_question(0, false, false),
            "Delete entry 1 and rewrite the array? Requires the key to be unlocked."
        );
        assert_eq!(
            crate::lb_delete_question(3, false, true),
            "Delete entry 4 and rewrite the array? Requires the key to be unlocked. This is a \
             password vault: deleting it loses every entry in it."
        );
        assert_eq!(
            crate::lb_delete_question(1, true, false),
            "Delete entry 2 and rewrite the array? Requires the key to be unlocked. This removes \
             the key's name."
        );
    }

    // ----- Hardware-run UI fixes -----

    /// Every text galley one headless frame of the list draws: its text,
    /// where, and how many lines it wrapped to.
    fn list_galleys(app: &mut App) -> Vec<(String, egui::Rect, usize)> {
        use crate::tests::TestFrame;
        use crate::ui::theme::Mode;
        fn collect(shape: &egui::Shape, out: &mut Vec<(String, egui::Rect, usize)>) {
            match shape {
                egui::Shape::Text(t) => out.push((
                    t.galley.text().to_owned(),
                    shape.visual_bounding_rect(),
                    t.galley.rows.len(),
                )),
                egui::Shape::Vec(shapes) => shapes.iter().for_each(|s| collect(s, out)),
                _ => {}
            }
        }
        let ctx = egui::Context::default();
        theme::install_fonts(&ctx);
        let palette = Palette::new(Mode::Dark, Palette::ACCENTS[0], false);
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(900.0, 700.0),
            )),
            ..Default::default()
        };
        let output = ctx.test_frame(input, |ui| {
            egui::CentralPanel::default().show(ui, |ui| app.render_vault_list(ui, &palette));
        });
        let mut out = Vec::new();
        for clipped in output.shapes {
            collect(&clipped.shape, &mut out);
        }
        out
    }

    /// An import preview of `backup` into Personal, opened.
    fn preview_of(backup: Vault) -> (App, FakeKey) {
        let mut key = FakeKey::new();
        key.add_vault("Personal", &key_vault());
        let mut app = app();
        unlock_into(&mut app, &mut key);
        import_dialog_for(&mut app, Path::new("demo.t2vault"));
        app.vault_apply_import_open(Some(KEY.into()), Ok(backup));
        (app, key)
    }

    #[test]
    fn an_import_rows_name_has_the_width() {
        let mut backup = backup_vault();
        backup.entries.push(kv(
            "exexexex",
            "Example Mail",
            "demo@example.com",
            "pw",
            "https://mail.example.com/inbox",
            120,
        ));
        let (mut app, _key) = preview_of(backup);
        let galleys = list_galleys(&mut app);
        let name = "Example Mail (demo@example.com) \u{00B7} mail.example.com";
        let row = galleys
            .iter()
            .find(|(t, _, _)| t == name)
            .unwrap_or_else(|| panic!("{name} is drawn: {galleys:?}"));
        assert_eq!(row.2, 1, "one line");
        // A reason sits under its entry's name, not squeezed beside it.
        let github = galleys
            .iter()
            .find(|(t, _, _)| t == "GitHub (alice)")
            .unwrap();
        let reason = galleys.iter().find(|(t, _, _)| t == NEWER).unwrap();
        assert!(
            reason.1.top() >= github.1.bottom() - 1.0 && reason.1.left() >= github.1.left() - 1.0,
            "{reason:?} under {github:?}"
        );
    }

    #[test]
    fn an_import_into_a_new_vault_waits_for_a_name() {
        assert!(matches!(
            new_name_refusal("", &[]),
            Some(VaultKeyError::Vault(_))
        ));
        assert!(matches!(
            new_name_refusal(&"x".repeat(33), &[]),
            Some(VaultKeyError::Vault(_))
        ));
        assert!(matches!(
            new_name_refusal("Personal", &[Some("Personal".into())]),
            Some(VaultKeyError::DuplicateName(_))
        ));
        assert!(new_name_refusal("Travel", &[Some("Personal".into()), None]).is_none());

        let (mut app, key) = preview_of(backup_vault());
        app.vault_import_set_target(ImportTarget::New);
        import_dialog(&mut app).new_name.clear();
        let k = entries(chosen(&import_dialog(&mut app).rows).len());
        let unnamed_button = format!("Create vault and import {k}");
        let text: String = list_galleys(&mut app)
            .into_iter()
            .map(|(t, _, _)| t + "\n")
            .collect();
        assert!(text.contains("for a new vault:"), "{text}");
        assert!(text.contains(&unnamed_button), "{text}");
        assert!(text.contains(IMPORT_NAME_NEEDED), "{text}");
        assert!(!text.contains("\"\""), "no empty quotes: {text}");
        assert!(!text.contains("(unnamed)"), "{text}");
        // The button is disabled: a click starts nothing.
        let before = key.creds.len();
        click_in_list(&mut app, &unnamed_button);
        assert_eq!(key.creds.len(), before);
        assert!(app.vault.import.is_some());
        // A name a vault already has: New vault's words.
        replace_text(&mut import_dialog(&mut app).new_name, " Personal ");
        let text: String = list_galleys(&mut app)
            .into_iter()
            .map(|(t, _, _)| t + "\n")
            .collect();
        let dup = vault_error_text(&VaultKeyError::DuplicateName("Personal".into()));
        assert!(text.contains(&dup), "{dup}: {text}");
        assert!(text.contains(&unnamed_button), "{text}");
        // A name it takes.
        replace_text(&mut import_dialog(&mut app).new_name, "Travel");
        let text: String = list_galleys(&mut app)
            .into_iter()
            .map(|(t, _, _)| t + "\n")
            .collect();
        assert!(text.contains("for new vault \"Travel\":"), "{text}");
        assert!(
            text.contains(&format!("Create vault \"Travel\" and import {k}")),
            "{text}"
        );
        assert!(text.contains("This asks for two touches."), "{text}");
    }

    #[test]
    fn a_delete_question_names_the_entry_as_its_row() {
        let v = Vault {
            entries: vec![
                kv("a1", "GitHub", "alice", "p", "https://github.com", 1),
                kv("a2", "GitHub", "alice", "p", "https://x.example", 1),
                kv("b1", "GitHub", "bob", "p", "", 1),
                kv("c1", "Bank", "", "p", "", 1),
                kv("d1", "Mail", "", "p", "https://mail.example", 1),
                kv("d2", "Mail", "", "p", "", 1),
            ],
        };
        let name = |i: usize| entry_shown_name(&v, &v.entries[i]).to_string();
        assert_eq!(name(3), "Bank", "a unique title is enough");
        assert_eq!(name(2), "GitHub (bob)");
        assert_eq!(name(0), "GitHub (alice) \u{00B7} github.com");
        assert_eq!(name(1), "GitHub (alice) \u{00B7} x.example");
        assert_eq!(name(4), "Mail \u{00B7} mail.example");

        let mut key = FakeKey::new();
        let (_, _, bob) = two_githubs(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        app.vault_ask_delete_entry(&bob);
        let text = list_text(&mut app);
        assert!(
            text.contains("Delete entry \"GitHub (bob)\" from vault \"Personal\""),
            "{text}"
        );
        delete_by_id(&mut app, &mut key, &bob);
        assert_eq!(
            app.vault.info.as_deref(),
            Some("Entry \"GitHub (bob)\" deleted.")
        );
    }

    #[test]
    fn the_experimental_line_doesnt_repeat_the_pill() {
        let ctx = egui::Context::default();
        theme::install_fonts(&ctx);
        let text: String = frame_texts(&ctx, Vec::new(), experimental_note)
            .into_iter()
            .map(|(t, _)| t)
            .collect();
        assert_eq!(text.matches("Experimental").count(), 1, "{text}");
        assert!(
            text.contains("Please report problems and keep a backup."),
            "{text}"
        );
    }

    /// The vault's questions come into view once when asked: the flag is
    /// set by the asking button and spent by the card's first frame.
    #[test]
    fn a_new_question_scrolls_into_view_once() {
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        let bank = session_entry(&app, "Bank").id.clone();
        for ask in [
            &mut |app: &mut App| app.vault_ask_rotate() as (),
            &mut |app: &mut App| app.vault_ask_delete_vault(),
            &mut |app: &mut App| app.vault_ask_delete_entry(&bank),
        ] as [&mut dyn FnMut(&mut App); 3]
        {
            ask(&mut app);
            assert!(app.vault.scroll_to_confirm);
            list_text(&mut app);
            assert!(app.vault.confirm.is_some(), "still asked");
            assert!(!app.vault.scroll_to_confirm, "scrolled once");
            app.vault.confirm = None;
        }
    }

    /// The entry form's card ends with its buttons: no empty gap above
    /// Cancel / Save.
    #[test]
    fn the_entry_form_is_as_tall_as_its_content() {
        let mut key = FakeKey::new();
        two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        app.vault_add_entry();
        let galleys = list_galleys(&mut app);
        let at = |label: &str| {
            galleys
                .iter()
                .find(|(t, _, _)| t.starts_with(label))
                .unwrap_or_else(|| panic!("{label}: {galleys:?}"))
                .1
        };
        let gap = at("Save").top() - at("Saving writes the vault").bottom();
        assert!(gap < 40.0, "{gap} px between the last line and Save");
    }

    // ----- the fingerprint unlock -----

    use keyroost_ctap::client_pin::{FingerAsk, Verified};

    const FINGER_LINE: &str =
        "Touch the fingerprint sensor, or enter the FIDO2 PIN, to unlock the vault.";

    fn unlock_prompt() -> Option<String> {
        Some(FingerAsk::Unlock.prompt().to_owned())
    }

    fn again_prompt() -> Option<String> {
        Some(FingerAsk::Again.prompt().to_owned())
    }

    /// An app showing a key whose sensor can unlock it.
    fn finger_app() -> App {
        let mut app = app();
        app.security_keys.info = Some(FakeKey::with_fingerprint().info);
        app
    }

    /// A FIDO2 tab session on [`KEY`] unlocked with a fingerprint.
    fn finger_fido_session() -> UnlockedSession {
        UnlockedSession {
            unlock: SessionUnlock::Fingerprint,
            ..fido_session("")
        }
    }

    /// Unlock `key` with a fingerprint as Touch fingerprint's job does (the
    /// finger asks going to the touch banner's cell), and land it as its
    /// apply does; what the banner said at each finger and touch.
    fn finger_unlock_into(app: &mut App, key: &mut FakeKey) -> Vec<Option<String>> {
        let mut auth = app.vault_fingerprint_auth();
        let banner = app.vault.progress.clone();
        let mut watched = Watched {
            key,
            banner: banner.clone(),
            at_touch: Vec::new(),
        };
        let result = {
            let mut touches = TouchProgress::new(banner.clone(), 1);
            run_unlock(&mut watched, &mut auth, &mut touches).map_err(VaultJobError::from)
        };
        assert_eq!(shown(&banner), None, "the prompt is down after the job");
        let seen = watched.at_touch;
        app.vault_apply_unlock(Some(KEY.into()), auth, false, None, result);
        seen
    }

    /// Add an entry titled `title` through the form and save it as the job
    /// does, the banner being the app's; what it said at each finger.
    fn add_into(app: &mut App, key: &mut FakeKey, title: &str) -> Vec<Option<String>> {
        app.vault_add_entry();
        replace_text(&mut form(app).title, title);
        let (vault, kind, change) = app.vault_form_change().expect("a form that validates");
        let (mut auth, mut open) = app.vault_take_for_save(&vault).expect("an open vault");
        let banner = app.vault.progress.clone();
        let mut watched = Watched {
            key,
            banner: banner.clone(),
            at_touch: Vec::new(),
        };
        let result = {
            let mut touches = TouchProgress::new(banner.clone(), 0);
            run_save(&mut watched, &mut auth, &mut open, &change, &mut touches)
                .map_err(VaultJobError::from)
        };
        let seen = watched.at_touch;
        app.vault_apply_save(Some(KEY.into()), vault, kind, auth, open, result);
        seen
    }

    /// Every text the Vault tab draws at the smallest window, beside a
    /// full-width sidebar.
    fn vault_tab_texts(app: &mut App) -> Vec<(String, egui::Rect)> {
        let ctx = egui::Context::default();
        theme::install_fonts(&ctx);
        let pane = egui::vec2(
            crate::WINDOW_MIN_SIZE[0] - crate::SIDEBAR_FULL_W,
            crate::WINDOW_MIN_SIZE[1],
        );
        // Two frames: the first lays out the rows.
        frame_texts_at(&ctx, Vec::new(), pane, |ui, p| app.cap_vault(ui, p));
        frame_texts_at(&ctx, Vec::new(), pane, |ui, p| app.cap_vault(ui, p))
    }

    fn has(texts: &[(String, egui::Rect)], s: &str) -> bool {
        texts.iter().any(|(t, _)| t == s)
    }

    /// A finger opens the vault and nothing else: the FIDO2 tab stays
    /// locked, no PIN goes to the key, and the banner asks for the finger
    /// in plain words.
    #[test]
    fn a_fingerprint_vault_unlock_leaves_the_fido2_tab_locked() {
        let mut key = FakeKey::with_fingerprint();
        two_vaults(&mut key);
        let mut app = finger_app();
        let seen = finger_unlock_into(&mut app, &mut key);
        let s = app.vault_session().expect("a vault session");
        assert!(!s.pin_from_fido);
        assert_eq!(
            s.auth.as_ref().and_then(VaultAuth::verified),
            Some(Verified::Fingerprint)
        );
        assert_eq!(s.unlocked.vaults.len(), 2);
        assert!(
            app.security_keys.session.is_none(),
            "the FIDO2 tab stays locked"
        );
        assert!(app.security_keys.error.is_none());
        assert!(!key.log.iter().any(|c| matches!(c, Call::Token { .. })));
        assert!(!seen.contains(&again_prompt()), "{seen:?}");
        assert_eq!(seen.first(), Some(&unlock_prompt()), "{seen:?}");
        assert_eq!(
            seen.last(),
            Some(&Some("Touch your key\u{2026}".to_owned())),
            "{seen:?}"
        );
        assert!(app.vault.error.is_none());
    }

    /// A FIDO2 tab unlocked by a finger holds no PIN to share: the vault
    /// card asks for its own PIN or finger. A PIN session still shares its
    /// PIN, and a key with no sensor offers no finger.
    #[test]
    fn a_fingerprint_fido2_session_does_not_unlock_the_vault() {
        let shared = "Uses the key's FIDO2 PIN \u{2014} already unlocked on the FIDO2 tab.";
        let mut app = finger_app();
        app.security_keys.session = Some(finger_fido_session());
        app.security_keys.session_device = Some(KEY.into());
        let texts = vault_tab_texts(&mut app);
        for s in ["Unlock", "Touch fingerprint", "FIDO2 PIN", FINGER_LINE] {
            assert!(has(&texts, s), "{s}: {texts:?}");
        }
        assert!(!has(&texts, shared), "{texts:?}");
        assert!(!has(&texts, "Unlocking asks for a touch."), "{texts:?}");
        let pills = texts.iter().filter(|(t, _)| t == "Experimental").count();
        assert_eq!(pills, 2, "the tab's note and the finger's: {texts:?}");
        assert_eq!(app.unlock_pin().err(), Some("PIN is empty"));

        // A PIN session shares its PIN: Unlock alone.
        app.security_keys.session = Some(fido_session("123456"));
        let texts = vault_tab_texts(&mut app);
        assert!(has(&texts, shared), "{texts:?}");
        assert!(has(&texts, "Unlock"), "{texts:?}");
        assert!(!has(&texts, "Touch fingerprint"), "{texts:?}");
        assert!(!has(&texts, FINGER_LINE), "{texts:?}");

        // No sensor: the card as before.
        let mut app = super::tests::app();
        app.security_keys.info = Some(FakeKey::new().info);
        let texts = vault_tab_texts(&mut app);
        assert!(has(&texts, "Unlock"), "{texts:?}");
        assert!(has(&texts, "Unlocking asks for a touch."), "{texts:?}");
        assert!(!has(&texts, "Touch fingerprint"), "{texts:?}");
        assert!(!has(&texts, FINGER_LINE), "{texts:?}");
        let pills = texts.iter().filter(|(t, _)| t == "Experimental").count();
        assert_eq!(pills, 1, "{texts:?}");
    }

    /// The unlocked vault says how it was unlocked, also while a job holds
    /// its auth.
    #[test]
    fn a_vault_unlocked_by_finger_says_so() {
        let mut key = FakeKey::with_fingerprint();
        two_vaults(&mut key);
        let mut app = finger_app();
        finger_unlock_into(&mut app, &mut key);
        let texts = vault_tab_texts(&mut app);
        assert!(has(&texts, "Unlocked with a fingerprint"), "{texts:?}");
        assert!(!has(&texts, "Unlocked with the FIDO2 PIN"), "{texts:?}");
        let held = app.vault_take_auth().expect("the session's auth");
        let texts = vault_tab_texts(&mut app);
        assert!(has(&texts, "Unlocked with a fingerprint"), "{texts:?}");
        app.vault_give_back_auth(held);

        let mut key = FakeKey::with_fingerprint();
        two_vaults(&mut key);
        let mut app = finger_app();
        unlock_into(&mut app, &mut key);
        let texts = vault_tab_texts(&mut app);
        assert!(has(&texts, "Unlocked with the FIDO2 PIN"), "{texts:?}");
        assert!(!has(&texts, "Unlocked with a fingerprint"), "{texts:?}");
    }

    /// A refused finger says why on the Vault tab and leaves the FIDO2
    /// tab's PIN session alone, at unlock and on a later save.
    #[test]
    fn a_refused_vault_fingerprint_does_not_lock_the_fido2_tab() {
        let not_recognized = "not recognized";
        let blocked = "blocked after too many tries";
        for (refusals, retries, said) in [
            (vec![0x3F], 5, not_recognized),
            (vec![0x3C], 5, blocked),
            (vec![], 0, blocked),
        ] {
            let mut key = FakeKey::with_fingerprint();
            two_vaults(&mut key);
            key.uv_refusals.extend(refusals);
            key.uv_retries = retries;
            let mut app = finger_app();
            app.security_keys.session = Some(fido_session("123456"));
            app.security_keys.session_device = Some(KEY.into());
            finger_unlock_into(&mut app, &mut key);
            assert!(app.vault.session.is_none());
            let err = app.vault.error.clone().unwrap_or_default();
            assert!(err.contains(said), "{said}: {err}");
            assert!(err.contains("use the PIN instead"), "{err}");
            assert!(
                app.security_keys.session.is_some(),
                "{said}: the FIDO2 tab's PIN was never refused"
            );
            assert!(app.security_keys.error.is_none());
        }

        // Mid-session: the key dropped the token and the finger asked
        // again is refused. The save fails; both sessions stay.
        let mut key = FakeKey::with_fingerprint();
        two_vaults(&mut key);
        key.drops_token_after_presence = true;
        let mut app = finger_app();
        app.security_keys.session = Some(fido_session("123456"));
        app.security_keys.session_device = Some(KEY.into());
        finger_unlock_into(&mut app, &mut key);
        assert!(app.vault_session().is_some());
        key.uv_refusals.push_back(0x3F);
        add_into(&mut app, &mut key, "Refused");
        let err = app.vault.error.clone().unwrap_or_default();
        assert!(err.contains(not_recognized), "{err}");
        assert!(
            app.vault_session().is_some(),
            "a finger refusal is no PIN refusal"
        );
        assert!(app.vault_session().unwrap().auth.is_some());
        assert!(app.security_keys.session.is_some());
    }

    /// Unlock and Touch fingerprint sit side by side, apart, inside the
    /// pane at the smallest window, and nothing on the card runs past it.
    #[test]
    fn the_vault_card_buttons_do_not_overlap() {
        let mut app = finger_app();
        let texts = vault_tab_texts(&mut app);
        let rect = |s: &str| {
            texts
                .iter()
                .find(|(t, _)| t == s)
                .map(|(_, r)| *r)
                .unwrap_or_else(|| panic!("{s} drawn: {texts:?}"))
        };
        let unlock = rect("Unlock");
        let finger = rect("Touch fingerprint");
        assert!(!unlock.intersects(finger), "{unlock:?} {finger:?}");
        assert!(finger.left() > unlock.right(), "right of Unlock");
        assert!(
            (unlock.center().y - finger.center().y).abs() < 2.0,
            "one row"
        );
        let width = crate::WINDOW_MIN_SIZE[0] - crate::SIDEBAR_FULL_W;
        for (t, r) in &texts {
            if !t.is_empty() {
                assert!(r.left() >= 0.0 && r.right() <= width, "{t}: {r:?}");
            }
        }
    }

    /// A key that drops the token after a touch: the save asks the finger
    /// again and says why; a PIN session re-derives silently, as before.
    #[test]
    fn a_dropped_token_puts_the_again_prompt_up() {
        let mut key = FakeKey::with_fingerprint();
        let p = two_vaults(&mut key);
        key.drops_token_after_presence = true;
        let mut app = finger_app();
        finger_unlock_into(&mut app, &mut key);
        let fingers = key.fingers;
        let seen = add_into(&mut app, &mut key, "Dropped");
        assert_eq!(seen, vec![again_prompt()]);
        assert_eq!(key.fingers, fingers + 1);
        assert_eq!(
            app.vault.info.as_deref(),
            Some("Entry \"Dropped\" added to vault \"Personal\".")
        );
        assert_eq!(key.vault_on_key(&p).unwrap().entries.len(), 3);
        assert!(!key.log.iter().any(|c| matches!(c, Call::Token { .. })));
        // The renewed token is the session's: the next save needs none.
        key.drops_token_after_presence = false;
        let seen = add_into(&mut app, &mut key, "Held");
        assert!(seen.is_empty(), "{seen:?}");
        assert_eq!(key.fingers, fingers + 1);

        // The PIN path: the same key, no prompt.
        let mut key = FakeKey::with_fingerprint();
        two_vaults(&mut key);
        key.drops_token_after_presence = true;
        let mut app = finger_app();
        unlock_into(&mut app, &mut key);
        let seen = add_into(&mut app, &mut key, "Silent");
        assert!(seen.is_empty(), "{seen:?}");
        assert_eq!(shown(&app.vault.progress), None);
        assert_eq!(key.fingers, 0);
        assert!(app.vault.info.is_some(), "{:?}", app.vault.error);
    }

    /// Ruling R2: a create, delete or rotate takes its fresh token by
    /// design, so a fingerprint session asks for it plainly, never with
    /// the "asked for a new unlock" reason.
    #[test]
    fn a_fingerprint_session_asks_plainly_for_new_tokens() {
        let mut key = FakeKey::with_fingerprint();
        two_vaults(&mut key);
        let mut app = finger_app();
        finger_unlock_into(&mut app, &mut key);
        let seen = create_into(&mut app, &mut key, "Travel");
        assert!(app.vault.error.is_none(), "{:?}", app.vault.error);
        assert!(!seen.contains(&again_prompt()), "{seen:?}");
        assert!(app
            .vault_session()
            .unwrap()
            .unlocked
            .vaults
            .iter()
            .any(|v| v.vault_ref.name.as_deref() == Some("Travel")));
        assert!(!key.log.iter().any(|c| matches!(c, Call::Token { .. })));
        assert_eq!(
            app.vault_session()
                .and_then(|s| s.auth.as_ref())
                .and_then(VaultAuth::verified),
            Some(Verified::Fingerprint)
        );
    }

    /// A fingerprint session asks for the finger once per job, and again
    /// only where a touch of the key ended what that token allows: the
    /// unlock 1 (its listing and its touch share the token), a save none, a
    /// create 2, a rotate 3, a vault delete 1 (none when the token it would
    /// take is still held untouched).
    #[test]
    fn a_fingerprint_session_asks_for_the_finger_once_per_job() {
        let mut key = FakeKey::with_fingerprint();
        two_vaults(&mut key);
        let mut app = finger_app();
        let seen = finger_unlock_into(&mut app, &mut key);
        assert_eq!(key.fingers, 1);
        assert_eq!(
            seen,
            vec![unlock_prompt(), Some("Touch your key\u{2026}".to_owned())]
        );
        let check = |app: &App, key: &FakeKey, fingers: usize, job: &str| {
            assert!(app.vault.error.is_none(), "{job}: {:?}", app.vault.error);
            assert!(app.vault.info.is_some(), "{job}: done");
            assert_eq!(key.fingers, fingers, "{job}");
        };
        add_into(&mut app, &mut key, "Saved");
        check(&app, &key, 1, "save");
        create_into(&mut app, &mut key, "Travel");
        check(&app, &key, 3, "create");
        app.vault_ask_rotate();
        rotate_into(&mut app, &mut key);
        check(&app, &key, 6, "rotate");
        // The rotate's last token (for the old credential's delete) saw no
        // touch, so it still serves a vault delete.
        app.vault_ask_delete_vault();
        delete_vault_into(&mut app, &mut key);
        check(&app, &key, 6, "delete after a rotate");
        assert!(!key.log.iter().any(|c| matches!(c, Call::Token { .. })));

        // Right after an unlock (whose touch left the token only the
        // write), a delete takes one finger.
        let mut key = FakeKey::with_fingerprint();
        two_vaults(&mut key);
        let mut app = finger_app();
        finger_unlock_into(&mut app, &mut key);
        app.vault_ask_delete_vault();
        delete_vault_into(&mut app, &mut key);
        check(&app, &key, 2, "delete");
    }

    /// A pre-2.2 key that lists its vaults only under a token bound to no
    /// relying party: the unlock asks for a second finger to list, saying
    /// why, and opens the vaults; the session remembers, so a later delete
    /// lists with one finger and no reason line. A key reporting CTAP 2.2
    /// lists unbound from the start: the unlock takes 2 fingers, both plain.
    #[test]
    fn a_strict_listing_key_opens_with_a_second_finger_and_says_why() {
        let mut key = FakeKey::with_fingerprint();
        key.strict_listing = true;
        two_vaults(&mut key);
        let mut app = finger_app();
        let seen = finger_unlock_into(&mut app, &mut key);
        assert!(app.vault.error.is_none(), "{:?}", app.vault.error);
        assert_eq!(app.vault_session().unwrap().unlocked.vaults.len(), 2);
        assert_eq!(
            seen,
            vec![
                unlock_prompt(),
                Some(FingerAsk::ListVaults.prompt().to_owned()),
                unlock_prompt(),
                Some("Touch your key\u{2026}".to_owned()),
            ]
        );
        assert_eq!(key.fingers, 3);
        app.vault_ask_delete_vault();
        delete_vault_into(&mut app, &mut key);
        assert!(app.vault.error.is_none(), "{:?}", app.vault.error);
        assert_eq!(key.fingers, 4, "one finger, unbound straight away");
        assert!(!key.log.iter().any(|c| matches!(c, Call::Token { .. })));

        let mut key = FakeKey::with_fingerprint();
        key.as_ctap22();
        two_vaults(&mut key);
        let mut app = finger_app();
        let seen = finger_unlock_into(&mut app, &mut key);
        assert!(app.vault.error.is_none(), "{:?}", app.vault.error);
        assert_eq!(app.vault_session().unwrap().unlocked.vaults.len(), 2);
        assert_eq!(
            seen,
            vec![
                unlock_prompt(),
                unlock_prompt(),
                Some("Touch your key\u{2026}".to_owned()),
            ]
        );
        assert_eq!(key.fingers, 2);
    }

    /// The key refuses the session's token and the one it gave after the
    /// finger was asked again: the vault locks in the finger's words, never
    /// the PIN's, and the FIDO2 tab's PIN session stays. A PIN session
    /// keeps its existing text.
    #[test]
    fn a_twice_refused_fingerprint_token_locks_in_plain_words() {
        let mut key = FakeKey::with_fingerprint();
        two_vaults(&mut key);
        let mut app = finger_app();
        app.security_keys.session = Some(fido_session("123456"));
        app.security_keys.session_device = Some(KEY.into());
        finger_unlock_into(&mut app, &mut key);
        key.write_refusals.extend([0x33, 0x33]);
        let seen = add_into(&mut app, &mut key, "Refused twice");
        assert_eq!(seen, vec![again_prompt()], "one ask after the refusal");
        assert!(app.vault.session.is_none(), "the vault locks");
        assert_eq!(app.vault.error.as_deref(), Some(FINGER_UNLOCK_REFUSED));
        assert!(!FINGER_UNLOCK_REFUSED.contains("PIN"));
        assert!(app
            .log
            .iter()
            .any(|l| l.text == format!("Vault: {FINGER_UNLOCK_REFUSED}")));
        assert!(app.security_keys.session.is_some());
        assert!(app.security_keys.error.is_none());

        let mut key = FakeKey::with_fingerprint();
        two_vaults(&mut key);
        let mut app = finger_app();
        unlock_into(&mut app, &mut key);
        key.write_refusals.extend([0x33, 0x33]);
        add_into(&mut app, &mut key, "PIN refused twice");
        assert!(app.vault.session.is_none());
        let expected = vault_error_text(&VaultKeyError::Ctap(CtapError::StatusCode(0x33)));
        assert_eq!(app.vault.error.as_deref(), Some(expected.as_str()));
    }

    /// Lock, the idle lock and a key switch drop a fingerprint vault
    /// session like a PIN one, its token with it.
    #[test]
    fn a_fingerprint_vault_session_locks_like_a_pin_one() {
        let opened = || {
            let mut key = FakeKey::with_fingerprint();
            two_vaults(&mut key);
            let mut app = finger_app();
            finger_unlock_into(&mut app, &mut key);
            assert!(app.vault_session().is_some());
            assert!(app.holds_unlocked_secrets());
            app
        };
        let mut app = opened();
        app.vault_lock(None);
        assert!(app.vault.session.is_none());
        assert!(!app.holds_unlocked_secrets());

        let mut app = opened();
        let t0 = std::time::Instant::now();
        app.idle_lock_tick(t0, false);
        app.idle_lock_tick(t0 + crate::IDLE_LOCK_AFTER, false);
        assert!(app.vault.session.is_none());
        assert_eq!(
            app.vault.error.as_deref(),
            Some(crate::idle_locked_msg().as_str())
        );

        let mut app = opened();
        let previous = app.selected_device.take();
        app.selected_device = Some("serial:BBB".into());
        app.on_device_selected(previous);
        assert!(app.vault.session.is_none());
    }

    /// Touch fingerprint on the card runs a vault-only unlock: the job
    /// opens the key (a path that doesn't exist here, so it says that
    /// failed), and the FIDO2 tab is never unlocked. A PIN typed into the
    /// box first is wiped rather than kept.
    // Linux only: the job reaches a HID open, a plain file open on Linux.
    #[cfg(target_os = "linux")]
    #[test]
    fn touch_fingerprint_unlocks_only_the_vault() {
        let mut app = App {
            devices: vec![crate::ui::device::Device {
                hid_path: Some("/nonexistent/keyroost-test/hidraw0".into()),
                ..crate::tests::test_key(KEY, "AAA", None)
            }],
            selected_device: Some(KEY.into()),
            ..Default::default()
        };
        app.security_keys.info = Some(FakeKey::with_fingerprint().info);
        *app.vault.pin_input = "246810".into();
        click_text("Touch fingerprint", |ui, p| app.cap_vault(ui, p));
        assert!(app.vault.session.is_none());
        assert!(app.vault.error.is_some(), "the open failure is said");
        assert!(app.vault.pin_input.is_empty(), "the typed PIN is wiped");
        assert!(app.security_keys.session.is_none());
        assert!(
            app.security_keys.error.is_none(),
            "no FIDO2 unlock was tried"
        );
    }
}
