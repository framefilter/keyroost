//! The Vault tab: the FIDO2 password vault on the selected key, beside
//! Authenticator, and the "Password vault" card on the key's Overview.
//!
//! The tab is offered only on keys that can hold a vault, the way
//! Authenticator and OpenPGP are offered only on keys that have them; the
//! Overview card says why a key can't. The vault is experimental, so both
//! carry [`experimental_note`].
//!
//! The words are the CLI's (`keyroostctl fido vault`), fitted to the layout.

use std::sync::{Arc, Mutex};

use keyroost_ctap::large_blobs::BlobCapacity;
use keyroost_ctap::transport::CtapTransport;
use keyroost_ctap::{AuthenticatorInfo, CtapError};
use keyroost_transport::vault::{
    self, CtapVaultKey, LeftOver, Unlocked, VaultAuth, VaultKey, VaultKeyError, VaultOnKey,
    VaultStep,
};
use keyroost_vault::{seal, Entry, Vault};
use zeroize::Zeroizing;

use crate::ui::device::{CapTab, DeviceId};
use crate::ui::theme::{self, BtnKind, Palette};
use crate::{
    completion_still_valid, fido_unread_line, guard_secret_field, now_secs_f64, open_fido,
    sanitize_title, App, FidoTarget, Severity, TypedSecrets,
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
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the vault's messages count entries with it (later tasks)"
    )
)]
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

/// A vault as its chip names it: `Personal · 12`, or
/// `Personal · (unavailable)` when it did not open.
pub(crate) fn chip_label(v: &VaultOnKey) -> String {
    let name = shown_name(v.vault_ref.name.as_deref());
    match v.entry_count() {
        Some(n) => format!("{name} \u{00B7} {n}"),
        None => format!("{name} \u{00B7} (unavailable)"),
    }
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
/// locked.
pub(crate) fn overview_line(
    offer: VaultOffer,
    read_failed: bool,
    vaults: Option<&[VaultOnKey]>,
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
            None => "Passwords in an encrypted vault on this key, opened with the PIN and a touch."
                .to_owned(),
            Some([]) => "No vaults on this key yet.".to_owned(),
            Some(vs) => vs.iter().map(chip_label).collect::<Vec<_>>().join(", "),
        },
    }
}

/// What one entry adds to a sealed vault when nothing is known yet: a short
/// login with no notes, rounded up.
pub(crate) const DEFAULT_ENTRY_BYTES: usize = 80;

/// About how many bytes one entry takes on the key, from the open vaults:
/// what their entries add to a sealed empty vault, per entry, sealed under a
/// stand-in secret (the size doesn't depend on it). At least 1;
/// [`DEFAULT_ENTRY_BYTES`] with no entries to go by. Seals every open vault,
/// so it runs when the contents change, never while drawing.
pub(crate) fn entry_bytes_estimate(vaults: &[VaultOnKey]) -> usize {
    let secret = [0x5a_u8; 32];
    let Ok(empty) = seal(&Vault::default(), &secret).map(|b| b.len()) else {
        return DEFAULT_ENTRY_BYTES;
    };
    let mut grown = 0usize;
    let mut count = 0usize;
    for open in vaults.iter().filter_map(|v| v.state.as_ref().ok()) {
        let n = open.contents.entries.len();
        if n == 0 {
            continue;
        }
        let Ok(sealed) = seal(&open.contents, &secret) else {
            return DEFAULT_ENTRY_BYTES;
        };
        grown += sealed.len().saturating_sub(empty);
        count += n;
    }
    grown
        .checked_div(count)
        .map_or(DEFAULT_ENTRY_BYTES, |n| n.max(1))
}

/// `bytes` in KB with one decimal, a trailing `.0` dropped: `1.3`, `4`.
pub(crate) fn kb(bytes: u64) -> String {
    let s = format!("{:.1}", bytes as f64 / 1024.0);
    s.strip_suffix(".0").map(str::to_owned).unwrap_or(s)
}

/// How full the key's store is, in plain numbers: `1.3 of 4 KB used · room
/// for about 75 more entries`, or `· full` when not one more fits.
pub(crate) fn space_line(cap: &BlobCapacity, entry_bytes: usize) -> String {
    let used = format!("{} of {} KB used", kb(cap.used_bytes), kb(cap.max_bytes));
    let n = cap.free_bytes / entry_bytes.max(1) as u64;
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
pub(crate) fn matches_filter(e: &Entry, filter: &str) -> bool {
    let needle: Vec<char> = fold(filter.trim()).collect();
    [&e.title, &e.username, &e.url]
        .iter()
        .any(|f| contains_folded(f, &needle))
}

/// The entries of `v` the list shows for `filter`, as indices into
/// `v.entries`: sorted by title, then username, ignoring case.
pub(crate) fn shown_rows(v: &Vault, filter: &str) -> Vec<usize> {
    let mut rows: Vec<usize> = (0..v.entries.len())
        .filter(|&i| matches_filter(&v.entries[i], filter))
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
        ui.add(text("Experimental: please "));
        ui.hyperlink_to(
            egui::RichText::new("report problems").font(theme::f_reg(11.5)),
            ISSUES_URL,
        );
        ui.add(text(" and keep a backup."));
    });
}

/// Why a vault job failed: the key couldn't be opened for it, or a vault
/// flow refused or failed. Every vault apply takes this one type.
#[derive(Debug)]
pub(crate) enum VaultJobError {
    /// Opening the key failed (or it speaks no CTAP2): the text to show.
    Open(String),
    Vault(VaultKeyError),
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
            } => "; delete the copy with no data with Delete vault\u{2026}",
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
        VaultKeyError::OldNotDeleted { .. } => {
            return format!(
                "{} Unlock the vault again to see both copies.",
                as_sentence(&e.to_string())
            );
        }
        VaultKeyError::VaultGone { .. } => {
            return format!(
                "{} Unlock again to see what the key holds now.",
                as_sentence(&e.to_string())
            );
        }
        _ => "",
    };
    as_sentence(&format!("{e}{hint}"))
}

/// A vault job's error as the pane shows it, as a sentence like the rest.
pub(crate) fn job_error_text(e: &VaultJobError) -> String {
    match e {
        VaultJobError::Open(s) => as_sentence(s),
        VaultJobError::Vault(e) => vault_error_text(e),
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

/// The unlocked vaults of one key. Reached only through
/// [`App::vault_session`], which refuses it once another key is selected.
pub(crate) struct VaultSession {
    /// The key it was unlocked on.
    pub(crate) device: DeviceId,
    /// The PIN and the token the writes reuse; `None` while a job holds it.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the vault's writes take it (later tasks)")
    )]
    pub(crate) auth: Option<VaultAuth>,
    pub(crate) unlocked: Unlocked,
    /// The PIN came from the FIDO2 tab's session, so a refusal of it
    /// locks that tab too.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the vault's writes read it (later tasks)")
    )]
    pub(crate) pin_from_fido: bool,
    /// About how many bytes one more entry takes ([`entry_bytes_estimate`]),
    /// for the space line. Set whenever the contents change, never while
    /// drawing.
    pub(crate) entry_bytes: usize,
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
}

impl TypedSecrets for VaultState {
    fn secrets_mut(&mut self) -> Vec<&mut String> {
        vec![&mut *self.pin_input]
    }
}

impl App {
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

    /// The PIN an unlock uses: the FIDO2 tab's, when that tab is unlocked on
    /// this key (`true`), else the one typed in the Vault tab's box, which
    /// empties.
    pub(crate) fn unlock_pin(&mut self) -> Result<(Zeroizing<String>, bool), &'static str> {
        if let Some(s) = self.fido_session() {
            if !s.pin.is_empty() {
                return Ok((s.pin.clone(), true));
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
        });
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
                let entry_bytes = entry_bytes_estimate(&unlocked.vaults);
                self.vault.session = Some(VaultSession {
                    device,
                    auth: Some(auth),
                    unlocked,
                    pin_from_fido,
                    entry_bytes,
                });
                // One PIN entry serves both tabs: the FIDO2 tab unlocks with
                // the PIN the key just accepted (no touch).
                if let Some(pin) = typed_pin {
                    if self.fido_session().is_none() {
                        self.unlock_fido_with(pin);
                    }
                }
            }
            Err(e) => {
                let pin_refused = matches!(
                    &e,
                    VaultJobError::Vault(VaultKeyError::Ctap(c))
                        if c.is_pin_auth_error() || matches!(c, CtapError::StatusCode(0x32))
                );
                self.vault_fail(&e);
                if pin_refused && pin_from_fido {
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
        self.spawn_job("Reading the vault\u{2026}", move || {
            let mut unlocked = unlocked;
            let result = open_vault_key(&target).and_then(|mut key| {
                run_reload(&mut key, &mut unlocked).map_err(VaultJobError::from)
            });
            Box::new(move |app: &mut App| app.vault_apply_reload(for_device, unlocked, result))
        });
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
                    s.entry_bytes = entry_bytes_estimate(&unlocked.vaults);
                    s.unlocked = unlocked;
                }
                self.vault.error = None;
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
    /// running. `why` is shown.
    pub(crate) fn vault_lock(&mut self, why: Option<String>) {
        self.clear_vault_clipboard_now();
        let progress = std::mem::take(&mut self.vault.progress);
        self.vault = VaultState {
            error: why,
            progress,
            ..Default::default()
        };
    }

    /// The vault the list shows: the selected one, else the first.
    pub(crate) fn selected_vault(&self) -> Option<&VaultOnKey> {
        let vaults = &self.vault_session()?.unlocked.vaults;
        selected_index(vaults, self.vault.selected.as_deref()).map(|i| &vaults[i])
    }

    /// Show vault `id` (its credential ID): the opened entry closes and a
    /// shown password hides.
    pub(crate) fn vault_select(&mut self, id: Vec<u8>) {
        self.vault.selected = Some(id);
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
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "gates add, edit, delete, export, import and rotate (later tasks)"
        )
    )]
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

    /// A vault change that worked: `shown` in the pane, `logged` in the
    /// activity log (never an entry's title, username, URL or notes).
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the vault's writes report with it (later tasks)")
    )]
    pub(crate) fn vault_done(&mut self, shown: String, logged: String) {
        self.log(Severity::Ok, format!("Vault: {logged}"));
        self.vault.error = None;
        self.vault.info = Some(shown);
    }

    /// A vault job that failed: the pane and the activity log say why.
    pub(crate) fn vault_fail(&mut self, e: &VaultJobError) {
        let text = job_error_text(e);
        self.log(Severity::Err, format!("Vault: {text}"));
        self.vault.info = None;
        self.vault.error = Some(text);
    }

    /// The card that unlocks the vault: the FIDO2 tab's PIN when that tab is
    /// unlocked, else a PIN box.
    fn vault_unlock_card(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let waiting = self.waiting_for().map(str::to_owned);
        let shared = self.fido_session().is_some_and(|s| !s.pin.is_empty());
        let mut unlock = false;
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
                });
            }
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new("Unlocking asks for a touch.")
                    .font(theme::f_reg(11.5))
                    .color(p.txt3),
            );
        });
        if unlock {
            self.vault_unlock();
        }
    }

    /// The Vault tab.
    pub(crate) fn cap_vault(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let offer = self.vault_offer();
        let unlocked = offer == VaultOffer::Ready && self.vault_session().is_some();
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
                        egui::RichText::new("Unlocked with the FIDO2 PIN")
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
    /// filter, a row per entry with its copy buttons (the opened one with its
    /// password behind Show, its URL and notes), then the Backup card.
    fn render_vault_list(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let Some(session) = self.vault_session() else {
            return;
        };
        let vaults = &session.unlocked.vaults;
        if vaults.is_empty() {
            ui.label(
                egui::RichText::new("No vaults on this key yet.")
                    .font(theme::f_reg(13.0))
                    .color(p.txt2),
            );
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
        // The filter box edits a copy while the session is borrowed.
        let mut filter = std::mem::take(&mut self.vault.filter);

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
        });
        ui.add_space(6.0);
        let cap = &session.unlocked.capacity;
        ui.horizontal(|ui| {
            space_bar(ui, p, cap);
            ui.add_space(6.0);
            ui.label(
                egui::RichText::new(space_line(cap, session.entry_bytes))
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
                ui.add(
                    egui::TextEdit::singleline(&mut filter)
                        .margin(theme::TEXT_EDIT_MARGIN)
                        .hint_text("Filter entries\u{2026}")
                        .desired_width(f32::INFINITY),
                );
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
                            if let Some(show) = opened_entry(ui, p, e, showing) {
                                reveal = Some(show.then(|| e.id.clone()));
                            }
                        }
                    }
                });
            }
        }

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
        });

        self.vault.filter = filter;
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
            if let Some(mut text) = self.vault_copy_text(&id, what) {
                let text = std::mem::take(&mut *text);
                self.copy_secret_from(ui.ctx(), text, true);
                self.vault.copied = Some((what.flash_key(&id), now + COPIED_FLASH_SECS));
            }
        }
        if let Some((_, t)) = &self.vault.copied {
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_secs_f64((t - now).max(0.05)));
        }
    }
}

/// How long a copy button says "Copied" (the Authenticator codes' flash).
const COPIED_FLASH_SECS: f64 = 1.2;

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

/// The opened entry under its row: the password behind Show, the URL, the
/// notes (shown, as `entry show` does), and when it last changed. Returns
/// `Some(show)` when Show or Hide was clicked.
fn opened_entry(ui: &mut egui::Ui, p: &Palette, e: &Entry, showing: bool) -> Option<bool> {
    let mut clicked = None;
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
                        ui.label(
                            egui::RichText::new(e.password.as_str())
                                .font(theme::f_mono(13.0))
                                .color(p.txt),
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
                        clicked = Some(!showing);
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
            if let Some(when) = changed_ago(e.modified_minutes, vault::now_minutes()) {
                ui.horizontal(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            egui::RichText::new(when)
                                .font(theme::f_reg(11.5))
                                .color(p.txt3),
                        );
                    });
                });
            }
        });
    clicked
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyroost_transport::vault::fake::FakeKey;
    use keyroost_transport::vault::{unlock, VaultAuth, VaultProblem, VaultRef};
    use keyroost_vault::{Entry, Vault};
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
            overview_line(VaultOffer::Unknown, false, None),
            "Reading key\u{2026}"
        );
        // A failed read isn't left on "Reading key…".
        assert_eq!(
            overview_line(VaultOffer::Unknown, true, None),
            "Couldn't read this key."
        );
        assert_eq!(
            overview_line(VaultOffer::NeedsAdmin, false, None),
            "Open the FIDO2 tab to manage this key via Windows settings or restart as \
             administrator."
        );
        assert_eq!(
            overview_line(VaultOffer::No("largeBlobKey"), false, None),
            "This key cannot hold a password vault: it does not support largeBlobKey."
        );
        assert_eq!(
            overview_line(VaultOffer::NeedsPin, false, None),
            "A password vault needs a FIDO2 PIN; set one on the FIDO2 tab."
        );
        assert_eq!(
            overview_line(VaultOffer::Ready, false, None),
            "Passwords in an encrypted vault on this key, opened with the PIN and a touch."
        );
        assert_eq!(
            overview_line(VaultOffer::Ready, false, Some(&[])),
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
            overview_line(VaultOffer::Ready, false, Some(&vaults)),
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
    }

    // ----- unlock, lock, Refresh -----

    use crate::{App, UnlockedSession};
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
            pin: Zeroizing::new(pin.to_owned()),
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
        assert!(
            err.ends_with("Unlock again to see what the key holds now."),
            "{err}"
        );
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
                "; delete the copy with no data with Delete vault\u{2026}.",
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
            (
                old_not_deleted(OldVault::Kept),
                " Unlock the vault again to see both copies.",
            ),
            (
                old_not_deleted(OldVault::Emptied),
                " Unlock the vault again to see both copies.",
            ),
            (
                VaultKeyError::VaultGone {
                    name: Some("Work".into()),
                },
                " Unlock again to see what the key holds now.",
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
        // 2725 free at 36 bytes an entry: room for 75.
        assert_eq!(
            space_line(&cap(1371, 4096), 36),
            "1.3 of 4 KB used \u{00B7} room for about 75 more entries"
        );
        assert_eq!(
            space_line(&cap(4000, 4096), 80),
            "3.9 of 4 KB used \u{00B7} room for about 1 more entry"
        );
        assert_eq!(
            space_line(&cap(4050, 4096), 80),
            "4 of 4 KB used \u{00B7} full"
        );
        assert_eq!(
            space_line(&cap(4096, 4096), 0),
            "4 of 4 KB used \u{00B7} full",
            "never a division by zero"
        );
    }

    #[test]
    fn entry_bytes_estimate_defaults_and_grows() {
        assert_eq!(entry_bytes_estimate(&[]), DEFAULT_ENTRY_BYTES);
        assert_eq!(DEFAULT_ENTRY_BYTES, 80);
        let mut key = FakeKey::new();
        key.add_vault("Empty", &Vault::default());
        let vaults = unlocked(&mut key);
        assert_eq!(entry_bytes_estimate(&vaults), 80, "no entries to go by");
        assert_eq!(entry_bytes_estimate(&[unavailable(Some("Work"))]), 80);

        let ten = Vault {
            entries: (0..10).map(|i| entry(&format!("Site {i}"))).collect(),
        };
        let mut key = FakeKey::new();
        key.add_vault("Ten", &ten);
        let vaults = unlocked(&mut key);
        let secret = [1u8; 32];
        let growth =
            seal(&ten, &secret).unwrap().len() - seal(&Vault::default(), &secret).unwrap().len();
        let est = entry_bytes_estimate(&vaults);
        assert!((1..=growth).contains(&est), "{est} of {growth}");
    }

    #[test]
    fn entry_bytes_are_set_at_unlock_not_per_frame() {
        let mut key = FakeKey::new();
        let p = two_vaults(&mut key);
        let mut app = app();
        unlock_into(&mut app, &mut key);
        let s = app.vault_session().unwrap();
        assert_eq!(s.entry_bytes, entry_bytes_estimate(&s.unlocked.vaults));
        let before = s.entry_bytes;

        // A Refresh that finds more entries sets it again.
        let mut v = key.vault_on_key(&p).unwrap();
        // Random notes, which compress poorly: each entry adds more.
        v.entries.extend((0..20).map(|_| {
            let mut e = entry(&keyroost_vault::new_id());
            e.notes = (0..8).map(|_| keyroost_vault::new_id()).collect();
            e
        }));
        key.put_vault(&p, &v);
        let mut unlocked = app.vault_session().unwrap().unlocked.clone();
        let result = run_reload(&mut key, &mut unlocked).map_err(VaultJobError::from);
        app.vault_apply_reload(Some(KEY.into()), unlocked, result);
        let s = app.vault_session().unwrap();
        assert_eq!(s.entry_bytes, entry_bytes_estimate(&s.unlocked.vaults));
        assert!(s.entry_bytes > before, "{} > {before}", s.entry_bytes);
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
        // Work itself gone: the first vault.
        app.vault
            .session
            .as_mut()
            .unwrap()
            .unlocked
            .vaults
            .remove(0);
        assert_eq!(name(&app).as_deref(), Some("Home"));
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
}
