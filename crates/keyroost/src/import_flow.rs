//! Importing authenticator codes from a file: every dropped or picked file
//! waits its turn in a queue, is read and identified on the import thread,
//! and then opens either the "Import authenticator codes" dialog (an
//! authenticator export) or a short notice (key material, or a file keyroost
//! can't read). Nothing is written to a key from here without the person
//! clicking the dialog's Add button, which names the destination.
//!
//! The state logic (queue, destinations, preselection, the reason the Add
//! button is disabled, every close route) is pure and tested below; the
//! `impl App` block wires it to the frame loop, the import thread and the
//! device worker, the same way `otp_pane` extends `App`.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use eframe::egui;
use keyroost_import::plan::{
    molto_plan, plan_for, Existing, OathFamily, Plan, PlanRow, Store, Verdict,
};
use keyroost_import::run::{Outcome, Report};
use keyroost_import::{Format, ImportFile, OtpKind};
use keyroost_transport::import::molto_existing;

use crate::otp_pane::{otp_target_for, OtpTransportSel};
use crate::ui::device::{CapTab, Caps, Device, DeviceId, DeviceKind, DeviceView};
use crate::ui::theme::{self, BtnKind, Palette};
use crate::{
    clear_edit_undo, completion_still_valid, guard_secret_field, wipe, App, LogKind, Severity,
    TimeoutChoice, PROFILES,
};

/// Which storage on a key the codes go to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreKind {
    Molto2,
    Oath,
    Token2Otp,
}

/// One destination in the dialog: a connected key plus one of its stores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestKey {
    pub device: DeviceId,
    pub store: StoreKind,
}

/// Where the flow was started, for preselection.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Origin {
    /// Dropped on the window: no view asked for it.
    #[default]
    Dropped,
    /// "Import file…" in a key's view: that key's store.
    View(DestKey),
}

/// Files waiting their turn, oldest first, plus the one being shown.
#[derive(Default)]
pub struct ImportFlow {
    pub queue: VecDeque<(PathBuf, Origin)>,
    pub dialog: Option<ImportDialog>,
    pub notice: Option<FileNotice>,
    /// Hands each dialog its own id, so a late result from the import
    /// thread or the worker can never land in a dialog opened after it.
    next_id: u64,
}

/// Where a result from the import thread goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadRoute {
    /// A password retry for the dialog still showing.
    ToDialog,
    /// A queued file, nothing showing: open its dialog or notice.
    NewWindow,
    /// The dialog it was for is gone (closed while decrypting) or another is
    /// showing: drop it, entries and all.
    Drop,
}

/// Route a read for dialog `id`: a retry only ever lands in the dialog that
/// asked for it, and never reopens one the person closed meanwhile.
pub fn route_read(showing: Option<u64>, id: u64, retry: bool) -> ReadRoute {
    match (showing, retry) {
        (Some(d), true) if d == id => ReadRoute::ToDialog,
        (None, false) => ReadRoute::NewWindow,
        _ => ReadRoute::Drop,
    }
}

/// A file that isn't an authenticator export: what it looks like, and
/// that nothing happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileNotice {
    pub file_name: String,
    pub text: String,
}

/// Every capable store of every connected key, in device-list order; per key
/// Molto2, then OATH, then Token2 OTP. From `Caps::TOTP`, `Caps::OATH`,
/// `Caps::OTP`. (`Caps::PROG`, the single-profile token, isn't a
/// destination: it holds one code, programmed by hand.)
pub fn destinations(devices: &[Device]) -> Vec<DestKey> {
    let mut out = Vec::new();
    for d in devices {
        for (cap, store) in [
            (Caps::TOTP, StoreKind::Molto2),
            (Caps::OATH, StoreKind::Oath),
            (Caps::OTP, StoreKind::Token2Otp),
        ] {
            if d.caps.has(cap) {
                out.push(DestKey {
                    device: d.id.clone(),
                    store,
                });
            }
        }
    }
    out
}

/// True when the next queued file may start: no dialog or notice showing,
/// no import-thread stage and no device job running.
pub fn may_start_next(flow: &ImportFlow, import_busy: bool, device_busy: bool) -> bool {
    flow.dialog.is_none() && flow.notice.is_none() && !import_busy && !device_busy
}

impl ImportFlow {
    /// Queue `paths` in order, each once: a path already waiting isn't
    /// added again.
    pub fn enqueue(&mut self, paths: impl IntoIterator<Item = PathBuf>, origin: &Origin) {
        for p in paths {
            if !self.queue.iter().any(|(q, _)| *q == p) {
                self.queue.push_back((p, origin.clone()));
            }
        }
    }

    /// A fresh dialog id.
    fn take_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }
}

/// The notice for recognized key material: what it looks like and where
/// keyroost imports it, if anywhere.
pub fn key_material_notice(
    file_name: &str,
    k: keyroost_import::classify::KeyMaterial,
) -> FileNotice {
    FileNotice {
        file_name: file_name.to_owned(),
        text: k.gui_pointer().to_owned(),
    }
}

/// The name shown for a path: its last component, else the whole path.
pub fn file_name_of(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

/// "N more file(s) waiting." for the footer, or `None` with an empty queue.
pub fn waiting_line(n: usize) -> Option<String> {
    match n {
        0 => None,
        1 => Some("1 more file waiting.".to_owned()),
        n => Some(format!("{n} more files waiting.")),
    }
}

/// Preselection: the store named by the view the flow started from; else
/// the viewed key's only store, or the store matching the open tab when
/// it has two (C14); else the only capable key's only store; else none.
pub fn preselect(
    dests: &[DestKey],
    origin: &Origin,
    viewed: Option<(&DeviceId, Option<StoreKind>)>,
) -> Option<DestKey> {
    if let Origin::View(d) = origin {
        if dests.contains(d) {
            return Some(d.clone());
        }
    }
    if let Some((id, tab)) = viewed {
        let mine: Vec<&DestKey> = dests.iter().filter(|d| d.device == *id).collect();
        match mine.as_slice() {
            [] => {}
            [only] => return Some((*only).clone()),
            several => {
                return tab
                    .and_then(|t| several.iter().find(|d| d.store == t).map(|d| (*d).clone()))
            }
        }
    }
    match dests {
        [only] => Some(only.clone()),
        _ => None,
    }
}

/// The plan's store for a destination: an OATH key's family comes from its
/// vendor and, once read, the applet's version.
pub fn store_of(kind: StoreKind, vendor: &str, version: Option<(u8, u8, u8)>) -> Store {
    match kind {
        StoreKind::Molto2 => Store::Molto2,
        StoreKind::Oath => Store::Oath(OathFamily::from_vendor(vendor, version)),
        StoreKind::Token2Otp => Store::Token2Otp,
    }
}

/// How many entries the store's rules accept (nothing read from the key):
/// the "N of M can be stored" count next to each destination.
pub fn fit_count(file: &ImportFile, store: Store, first_slot: u8) -> usize {
    plan_for(file, store, first_slot, Existing::default(), false)
        .writes()
        .count()
}

/// One entry row: `label · TOTP 30 s · SHA-1 · 6 digits` (or `· HOTP ·`),
/// or `label — reason` for an entry no key can take. The flag is false for
/// the latter (drawn dimmed).
pub fn entry_line(item: &keyroost_import::ImportItem) -> (String, bool) {
    match &item.entry {
        Ok(e) => {
            let kind = match e.kind {
                OtpKind::Totp { period } => format!("TOTP {period} s"),
                OtpKind::Hotp { .. } => "HOTP".to_owned(),
            };
            (
                format!(
                    "{} \u{b7} {} \u{b7} {} \u{b7} {} digits",
                    item.label,
                    kind,
                    e.hash.name(),
                    e.digits
                ),
                true,
            )
        }
        Err(u) => (format!("{} \u{2014} {}", item.label, u), false),
    }
}

/// `<display name> — Authenticator (OATH)` / `— OTP storage` / `— Molto2 slots`.
pub fn dest_label(device_name: &str, store: StoreKind) -> String {
    let what = match store {
        StoreKind::Oath => "Authenticator (OATH)",
        StoreKind::Token2Otp => "OTP storage",
        StoreKind::Molto2 => "Molto2 slots",
    };
    format!("{device_name} \u{2014} {what}")
}

/// `Add 9 codes to <display name>`.
pub fn add_button_text(n: usize, device_name: &str) -> String {
    if n == 1 {
        format!("Add 1 code to {device_name}")
    } else {
        format!("Add {n} codes to {device_name}")
    }
}

/// The preview's first line: what the key holds and has room for.
pub fn holds_line(plan: &Plan, first_slot: u8) -> String {
    match (plan.store, plan.capacity) {
        (Store::Molto2, Some(cap)) => format!(
            "{cap} slots from #{first_slot:02} to #99; {} slots in use on the Molto2.",
            plan.on_key
        ),
        (_, Some(cap)) => format!("Holds {cap} codes; {} on the key.", plan.on_key),
        (_, None) => format!("{} on the key.", plan.on_key),
    }
}

/// One preview row, in the words the CLI preview uses:
/// `GitHub:alice — add`, `#05 GitHub — replace: replaces the code in this
/// slot`, `Bank — skip: Solo 2 doesn't take SHA-512 codes`.
pub fn plan_row_line(row: &PlanRow, store: Store) -> String {
    let mut s = format!("{} \u{2014} {}", row.shown_label(), row.verdict.word());
    if let Some(reason) = row.verdict.reason(store) {
        s.push_str(": ");
        s.push_str(&reason);
    }
    s
}

/// One report row (its label carries a Molto2 slot number):
/// `#05 GitHub — added`, `Bank — failed: <the key's error>`.
pub fn outcome_line(label: &str, o: &Outcome) -> String {
    let mut s = format!("{label} \u{2014} {}", o.word().replace('-', " "));
    if let Some(reason) = o.reason() {
        s.push_str(": ");
        s.push_str(&reason);
    }
    s
}

/// Shown when no connected key can store authenticator codes.
pub const NO_CAPABLE_KEY: &str = "Connect a key that can store authenticator codes \
     (for example a YubiKey, Solo 2, Nitrokey 3, Token2 key or Molto2).";

/// Shown for a Molto2 destination whose slot use hasn't been read.
pub const MOLTO_SLOTS_UNREAD: &str = "Slot use is read when the Molto2 is unlocked";

/// Shown for an unlocked Molto2 whose slot sweep failed.
pub const MOLTO_SLOTS_FAILED: &str =
    "Slot use couldn't be read; select the Molto2 and click Refresh.";

/// Shown for an OATH destination with no smart-card reader.
pub const NO_SMART_CARD: &str = "This key has no smart-card interface to reach its OATH codes.";

/// Shown for a Token2 key supplied without the on-device OTP function.
pub const NO_OTP_FUNCTION: &str = "This key was supplied without the on-device OTP \
     function, so it can't store codes.";

/// Why "Add" is disabled, first reason in fix order (generalizes #171's
/// bulk-dialog reasons; the Molto2 ones keep #171's words).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportBlock {
    /// The file is still being read or decrypted.
    Loading,
    /// An encrypted file, no password given yet.
    NeedsFilePassword,
    /// The file holds nothing any key could take.
    NoEntries,
    /// No connected key stores codes.
    NoCapableKey,
    /// Nothing picked under "Add to".
    NoDestination,
    /// The preview is reading the key.
    Reading,
    /// The preview couldn't read the key.
    KeyNotRead,
    /// The OATH password / OTP PIN is needed.
    Locked(StoreKind),
    /// The chosen Molto2's session isn't open yet (choosing it selects it,
    /// which opens the session).
    NoMoltoSession,
    /// #171: the Molto2 isn't unlocked (Authenticate button).
    MoltoNotUnlocked,
    /// Every entry is already on the key or skipped.
    NothingToAdd,
    /// The import is writing.
    Running,
    /// Another device operation runs.
    Busy,
}

/// What [`ImportBlock::find`] looks at.
#[derive(Debug, Clone, Default)]
pub struct BlockInput {
    pub loading: bool,
    pub needs_password: bool,
    /// Entries some key could take.
    pub usable: usize,
    pub capable_key: bool,
    pub dest: Option<StoreKind>,
    pub reading: bool,
    pub key_not_read: bool,
    pub locked: bool,
    pub molto_session: bool,
    pub molto_unlocked: bool,
    /// Planned writes (add + replace).
    pub writes: usize,
    pub running: bool,
    pub device_busy: bool,
}

impl ImportBlock {
    /// The first reason "Add" can't run, in the order the person fixes
    /// them, or `None` when it can.
    pub fn find(i: &BlockInput) -> Option<Self> {
        if i.loading {
            return Some(Self::Loading);
        }
        if i.needs_password {
            return Some(Self::NeedsFilePassword);
        }
        if i.usable == 0 {
            return Some(Self::NoEntries);
        }
        if !i.capable_key {
            return Some(Self::NoCapableKey);
        }
        let Some(kind) = i.dest else {
            return Some(Self::NoDestination);
        };
        if i.reading {
            return Some(Self::Reading);
        }
        if i.locked {
            return Some(Self::Locked(kind));
        }
        if i.key_not_read {
            return Some(Self::KeyNotRead);
        }
        if kind == StoreKind::Molto2 {
            if !i.molto_session {
                return Some(Self::NoMoltoSession);
            }
            if !i.molto_unlocked {
                return Some(Self::MoltoNotUnlocked);
            }
        }
        if i.writes == 0 {
            return Some(Self::NothingToAdd);
        }
        if i.running {
            return Some(Self::Running);
        }
        if i.device_busy {
            return Some(Self::Busy);
        }
        None
    }

    /// The one plain line under the buttons, also the disabled button's
    /// hover text.
    pub fn message(&self) -> String {
        match self {
            Self::Loading => "Still reading the file.".to_owned(),
            Self::NeedsFilePassword => "Enter the file password, then click Open.".to_owned(),
            Self::NoEntries => "None of the entries in this file can be imported.".to_owned(),
            Self::NoCapableKey => NO_CAPABLE_KEY.to_owned(),
            Self::NoDestination => {
                "Choose where to add the codes under \u{201C}Add to\u{201D}.".to_owned()
            }
            Self::Reading => "Reading what the key holds\u{2026}".to_owned(),
            Self::KeyNotRead => "keyroost couldn't read this key. Check that it's connected, \
                 then click Try again."
                .to_owned(),
            Self::Locked(StoreKind::Token2Otp) => {
                "This key's codes are protected by a PIN. Enter its OTP PIN and click Unlock."
                    .to_owned()
            }
            Self::Locked(_) => "This key's codes are protected by a password. Enter its OATH \
                 password and click Unlock."
                .to_owned(),
            Self::NoMoltoSession => "Opening the Molto2\u{2026} If this doesn't finish, \
                 unplug it and plug it back in."
                .to_owned(),
            Self::MoltoNotUnlocked => "The Molto2 is not unlocked yet. Click Authenticate \
                 (uses the factory-default customer key unless another one is entered \
                 in the Molto2 view)."
                .to_owned(),
            Self::NothingToAdd => "Nothing to add: each entry is already on the key or can't \
                 be stored there."
                .to_owned(),
            Self::Running => "Adding codes\u{2026}".to_owned(),
            Self::Busy => "Waiting for another key operation to finish.".to_owned(),
        }
    }
}

/// What the chosen key holds, read by the preview job.
pub type KeyContents = (DestKey, Existing, Option<(u8, u8, u8)>);

/// The dialog for one file.
#[derive(Default)]
pub struct ImportDialog {
    pub open: bool,
    /// From [`ImportFlow::take_id`]; results for another id are dropped.
    pub id: u64,
    /// Where the file was read from (for the retry with a password).
    pub path: PathBuf,
    pub file_name: String,
    pub format: Option<Format>,
    /// Parsed entries; dropping the last reference wipes the seeds. Shared
    /// with a running Add job, which holds its own reference until it ends.
    pub file: Option<Arc<ImportFile>>,
    pub needs_password: bool,
    /// Wiped on every close route.
    pub file_password: String,
    /// About the file (wrong password, unreadable).
    pub error: Option<String>,
    pub origin: Origin,
    pub dest: Option<DestKey>,
    /// Whether the person has picked (preselection never overrides a pick).
    pub dest_picked: bool,
    /// "Replace codes already on the key that have the same name" (OATH /
    /// Token2 OTP).
    pub replace: bool,
    /// What the chosen key holds, read by the preview job; reused when only
    /// `replace` changes.
    pub existing: Option<KeyContents>,
    /// The preview job is reading the key.
    pub reading: bool,
    /// A preview should be read as soon as no device job runs.
    pub preview_wanted: bool,
    /// About the chosen key (couldn't read it, wrong password, changed).
    pub dest_error: Option<String>,
    /// OATH password / OTP PIN for a destination that needs one (wiped on
    /// close and whenever the destination changes).
    pub dest_secret: String,
    pub dest_locked: bool,
    pub molto_start: u8,
    pub molto_timeout: TimeoutChoice,
    /// `(done, total)` while the Add job writes.
    pub running: Option<Arc<Mutex<(usize, usize)>>>,
    pub report: Option<Report>,
    /// The report's counts line ([`Report::summary`] over the plan it ran).
    pub report_line: String,
    /// The last Molto2 Authenticate failed (#171).
    pub auth_failed: bool,
    /// The destination just became a Molto2: select that Molto2 in the app
    /// (as clicking it in the list would), which opens its session.
    pub select_molto: bool,
    /// The selection when that wish was armed; a different selection later
    /// (the person clicked another key while a job ran) drops the wish.
    pub molto_armed_on: Option<Option<DeviceId>>,
}

impl Drop for ImportDialog {
    fn drop(&mut self) {
        self.close();
    }
}

impl ImportDialog {
    /// A dialog, open, for the file at `path`.
    pub fn new(id: u64, path: PathBuf, file_name: String, origin: Origin) -> Self {
        let mut d = Self::default();
        d.open = true;
        d.id = id;
        d.path = path;
        d.file_name = file_name;
        d.origin = origin;
        d
    }

    /// Same rule as #171's bulk dialog: a button never writes `open` inside
    /// the window closure (the write-back of egui's stale `[X]` copy would
    /// undo it); `window_open` is that copy, `close_clicked` the Close button.
    pub fn settle_open(&mut self, window_open: bool, close_clicked: bool) {
        if self.open && !(window_open && !close_clicked) {
            self.close();
        }
    }

    /// Close by any route: wipe both typed secrets, drop the entries, what
    /// the key holds and the report.
    pub fn close(&mut self) {
        self.open = false;
        wipe(&mut self.file_password);
        wipe(&mut self.dest_secret);
        self.file = None;
        self.existing = None;
        self.report = None;
        self.report_line.clear();
        self.auth_failed = false;
        self.select_molto = false;
        self.molto_armed_on = None;
    }

    /// Choose `dest` (`picked` when the person clicked it). A different
    /// destination drops what was read from the old one, and its secret.
    pub fn set_dest(&mut self, dest: Option<DestKey>, picked: bool) {
        self.dest_picked = picked && dest.is_some();
        if self.dest == dest {
            return;
        }
        wipe(&mut self.dest_secret);
        self.existing = None;
        self.dest_locked = false;
        self.reading = false;
        self.dest_error = None;
        self.report = None;
        self.preview_wanted = dest.as_ref().is_some_and(|d| d.store != StoreKind::Molto2);
        self.select_molto = dest.as_ref().is_some_and(|d| d.store == StoreKind::Molto2);
        self.molto_armed_on = None;
        self.dest = dest;
    }

    /// Called every frame with the app's selection: remembers the selection
    /// a pending Molto2 selection was armed under, and drops the pending
    /// selection when the person has selected something else since.
    pub fn arm_molto_select(&mut self, selected: Option<&DeviceId>) {
        if !self.select_molto {
            return;
        }
        match &self.molto_armed_on {
            None => self.molto_armed_on = Some(selected.cloned()),
            Some(armed) if armed.as_ref() != selected => {
                self.select_molto = false;
                self.molto_armed_on = None;
            }
            Some(_) => {}
        }
    }

    /// The Molto2 to select now, once per choice: the chosen Molto2 when
    /// another device (or none) is selected. The dialog's destination is
    /// the choice; the list on the left follows it.
    pub fn take_molto_select(&mut self, selected: Option<&DeviceId>) -> Option<DeviceId> {
        let armed = self.molto_armed_on.take();
        if !std::mem::take(&mut self.select_molto) {
            return None;
        }
        if armed.is_some_and(|a| a.as_ref() != selected) {
            return None;
        }
        self.dest
            .as_ref()
            .filter(|k| k.store == StoreKind::Molto2 && Some(&k.device) != selected)
            .map(|k| k.device.clone())
    }

    /// Follow the connected keys: a destination that went away is cleared
    /// (with its preview), and until the person picks, the preselection
    /// follows the selection and hotplug. Nothing changes while writing or
    /// while a report is showing.
    pub fn follow_devices(&mut self, dests: &[DestKey], pre: Option<DestKey>) {
        if self.running.is_some() || self.report.is_some() {
            return;
        }
        if self.dest.as_ref().is_some_and(|d| !dests.contains(d)) {
            self.set_dest(None, false);
        }
        if !self.dest_picked && self.dest != pre {
            self.set_dest(pre, false);
        }
    }

    /// The `existing` read for the current destination, if any.
    fn contents(&self) -> Option<&KeyContents> {
        self.existing
            .as_ref()
            .filter(|(d, _, _)| Some(d) == self.dest.as_ref())
    }
}

/// Ids of the dialog's masked fields, for scrubbing egui's undo history.
pub const FILE_PASSWORD_ID: &str = "import-file-password";
pub const DEST_SECRET_ID: &str = "import-dest-secret";

/// What the import thread read from a file.
enum Read {
    Opened(keyroost_qr::file::Opened),
    Failed(String),
}

/// What the preview job read.
enum Preview {
    Read(Existing, Option<(u8, u8, u8)>),
    /// The key needs its password / PIN.
    Locked,
    /// A password / PIN was sent and refused (or the read failed after it).
    Refused(String),
    Failed(String),
}

/// What the Add job did.
enum Added {
    /// The run's report and its counts line.
    Done(Report, String),
    /// The key's codes changed since the preview; nothing was written.
    Changed(Existing, Option<(u8, u8, u8)>),
    Locked,
    /// The password was sent and refused; nothing was written.
    Refused(String),
    Failed(String),
}

/// How the Add job's report asks for the applet password if the key wants
/// one nobody gave.
const OATH_PASSWORD_HINT: &str = "enter its OATH password in the import dialog";

/// Everything one frame of the dialog shows, gathered before drawing.
struct View {
    dests: Vec<(DestKey, String, usize)>,
    total: usize,
    plan: Option<Plan>,
    molto_note: Option<&'static str>,
    block: Option<ImportBlock>,
    dest_name: String,
}

impl App {
    /// Queue every file dropped on the window this frame, in order.
    pub(crate) fn import_take_drops(&mut self, ctx: &egui::Context) {
        let dropped: Vec<PathBuf> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .filter_map(|f| f.path.clone())
                .collect()
        });
        if !dropped.is_empty() {
            self.import_flow.enqueue(dropped, &Origin::Dropped);
        }
    }

    /// Start reading the next queued file when nothing else is showing or
    /// running. Called once per frame, after the worker and the import
    /// thread were drained.
    pub(crate) fn import_start_next(&mut self) {
        if !may_start_next(&self.import_flow, self.import_busy(), self.busy()) {
            return;
        }
        let Some((path, origin)) = self.import_flow.queue.pop_front() else {
            return;
        };
        let name = file_name_of(&path);
        let id = self.import_flow.take_id();
        self.import_read(id, path, name, origin, None);
    }

    /// Read `path` on the import thread (with the vault password when one
    /// was typed) and open the dialog or the notice with what it holds.
    fn import_read(
        &mut self,
        id: u64,
        path: PathBuf,
        name: String,
        origin: Origin,
        password: Option<zeroize::Zeroizing<String>>,
    ) {
        let label = format!("Reading {name}\u{2026}");
        let retry = password.is_some();
        self.run_import(label, move || {
            let read = match keyroost_qr::file::open_path(
                &path,
                password.as_deref().map(|p| p.as_bytes()),
            ) {
                Ok(o) => Read::Opened(o),
                Err(e) => Read::Failed(e.to_string()),
            };
            drop(password);
            Box::new(move |app: &mut App| {
                app.import_apply_read(id, retry, path, name, origin, read)
            })
        });
    }

    /// Apply what the import thread read.
    fn import_apply_read(
        &mut self,
        id: u64,
        retry: bool,
        path: PathBuf,
        name: String,
        origin: Origin,
        read: Read,
    ) {
        use keyroost_qr::file::Opened;
        let showing = self.import_flow.dialog.as_ref().map(|d| d.id);
        match route_read(showing, id, retry) {
            // Dropping `read` wipes any entries it decrypted.
            ReadRoute::Drop => return,
            ReadRoute::NewWindow => {}
            ReadRoute::ToDialog => {
                if matches!(read, Read::Opened(Opened::Entries(_))) {
                    self.import_scrub(FILE_PASSWORD_ID);
                }
            }
        }
        // A retry with a password lands in the dialog that asked for it.
        if let Some(d) = self.import_flow.dialog.as_mut() {
            match read {
                Read::Opened(Opened::Entries(file)) => {
                    wipe(&mut d.file_password);
                    d.needs_password = false;
                    d.error = None;
                    d.format = Some(file.format);
                    d.file = Some(Arc::new(file));
                }
                Read::Opened(Opened::NeedsPassword) => {
                    d.error = Some("Enter the file password.".to_owned());
                }
                Read::Opened(Opened::KeyMaterial(k)) => {
                    d.error = Some(k.gui_pointer().to_owned());
                }
                Read::Failed(e) => d.error = Some(e),
            }
            return;
        }
        let mut dialog = ImportDialog::new(id, path, name.clone(), origin);
        dialog.molto_start = self.slot;
        match read {
            Read::Opened(Opened::Entries(file)) => {
                dialog.format = Some(file.format);
                dialog.file = Some(Arc::new(file));
            }
            Read::Opened(Opened::NeedsPassword) => {
                dialog.format = Some(Format::AegisEncrypted);
                dialog.needs_password = true;
            }
            Read::Opened(Opened::KeyMaterial(k)) => {
                self.import_flow.notice = Some(key_material_notice(&name, k));
                return;
            }
            Read::Failed(text) => {
                self.import_flow.notice = Some(FileNotice {
                    file_name: name,
                    text,
                });
                return;
            }
        }
        self.import_flow.dialog = Some(dialog);
    }

    /// Scrub the undo history of one of the dialog's masked fields.
    fn import_scrub(&self, id: &str) {
        if let Some(ctx) = self.egui_ctx.as_ref() {
            clear_edit_undo(ctx, egui::Id::new(id));
        }
    }

    /// The import thread stopped without a result.
    pub(crate) fn import_thread_failed(&mut self, text: String) {
        match self.import_flow.dialog.as_mut() {
            Some(d) => d.error = Some(text),
            None => {
                self.import_flow.notice = Some(FileNotice {
                    file_name: String::new(),
                    text,
                })
            }
        }
    }

    /// The Molto2 Authenticate result, for the dialog's reason line (#171).
    pub(crate) fn import_auth_result(&mut self, ok: bool) {
        if let Some(d) = self.import_flow.dialog.as_mut() {
            d.auth_failed = !ok;
            if ok {
                // A "not unlocked" line from an earlier Add is no longer true.
                d.dest_error = None;
            }
        }
    }

    /// "Import file…": pick a file; it joins the queue.
    pub(crate) fn import_pick_file(&mut self, origin: Origin) {
        self.spawn_file_dialog(
            crate::FileTarget::ImportCodes(origin),
            false,
            &[
                (
                    "Authenticator export",
                    &["json", "txt", "png", "jpg", "jpeg"],
                ),
                ("All files", &["*"]),
            ],
            None,
        );
    }

    /// "Add" couldn't start: say why on the dialog's line, never nothing.
    fn import_add_refused(&mut self, why: &str) {
        if let Some(d) = self.import_flow.dialog.as_mut() {
            d.dest_error = Some(why.to_owned());
        }
    }

    /// The selected key and the store its open view shows, for preselection.
    fn import_viewed(&self) -> Option<(DeviceId, Option<StoreKind>)> {
        let dev = self.selected_device()?;
        let tab = if dev.kind == DeviceKind::Token {
            Some(StoreKind::Molto2)
        } else {
            match self.cap_tab {
                CapTab::Oath => Some(StoreKind::Oath),
                CapTab::Otp => Some(StoreKind::Token2Otp),
                _ => None,
            }
        };
        Some((dev.id.clone(), tab))
    }

    fn import_device(&self, id: &DeviceId) -> Option<&Device> {
        self.devices.iter().find(|d| d.id == *id)
    }

    /// The Molto2 session belongs to this destination's key and to the
    /// current selection.
    fn import_molto_ready(&self, dest: &DestKey) -> bool {
        self.molto_session_usable() && self.molto_session_device.as_ref() == Some(&dest.device)
    }

    /// The OATH password to send to `dest`: the one typed in the dialog,
    /// else the one the OATH pane already unlocked this key with.
    fn import_oath_password(
        &self,
        d: &ImportDialog,
        dest: &DestKey,
    ) -> Option<zeroize::Zeroizing<String>> {
        if !d.dest_secret.is_empty() {
            return Some(zeroize::Zeroizing::new(d.dest_secret.clone()));
        }
        if self.selected_device.as_ref() == Some(&dest.device) {
            return self.oath.unlocked_password.clone();
        }
        None
    }

    /// The OTP PIN to send to `dest`: typed in the dialog, else the one the
    /// OTP pane verified for this key.
    fn import_otp_pin(
        &self,
        d: &ImportDialog,
        dest: &DestKey,
    ) -> Option<zeroize::Zeroizing<String>> {
        if !d.dest_secret.is_empty() {
            return Some(zeroize::Zeroizing::new(d.dest_secret.clone()));
        }
        if self.selected_device.as_ref() == Some(&dest.device) {
            return self.otp.pin.clone();
        }
        None
    }

    /// The OTP endpoint of `dev`: the pane's transport choice when it is the
    /// selected key, else Auto.
    fn import_otp_target(&self, dev: &Device) -> Result<crate::otp_pane::OtpTarget, String> {
        let sel = if self.selected_device.as_ref() == Some(&dev.id) {
            self.otp.transport
        } else {
            OtpTransportSel::Auto
        };
        otp_target_for(sel, dev.hid_path.as_deref(), dev.reader.as_deref())
    }

    /// Read what the chosen key holds (OATH / Token2 OTP), off the frame
    /// loop. The session closes when the job returns: nothing is held while
    /// the person types.
    fn import_preview(&mut self) {
        let Some(d) = self.import_flow.dialog.as_ref() else {
            return;
        };
        let Some(dest) = d.dest.clone() else {
            return;
        };
        let id = d.id;
        let Some(dev) = self.import_device(&dest.device).cloned() else {
            return;
        };
        let oath_pw = self.import_oath_password(d, &dest);
        let otp_pin = self.import_otp_pin(d, &dest);
        let job: Box<dyn FnOnce() -> Preview + Send> = match dest.store {
            StoreKind::Molto2 => return,
            StoreKind::Oath => {
                let Some(reader) = dev.reader.clone() else {
                    self.import_set_preview(id, &dest, Preview::Failed(NO_SMART_CARD.into()));
                    return;
                };
                let pw = oath_pw;
                Box::new(move || {
                    let mut s = match keyroost_transport::OathSession::open(&reader) {
                        Ok(s) => s,
                        Err(e) => return Preview::Failed(e.to_string()),
                    };
                    if s.password_required() {
                        let Some(pw) = pw else {
                            return Preview::Locked;
                        };
                        if let Err(e) = s.unlock(&pw) {
                            return Preview::Refused(e.to_string());
                        }
                    }
                    match keyroost_transport::import::read_oath_existing(&mut s) {
                        Ok(ex) => Preview::Read(ex, s.version()),
                        Err(e) => Preview::Failed(e.to_string()),
                    }
                })
            }
            StoreKind::Token2Otp => {
                let target = match self.import_otp_target(&dev) {
                    Ok(t) => t,
                    Err(e) => {
                        self.import_set_preview(id, &dest, Preview::Failed(e));
                        return;
                    }
                };
                let pin = otp_pin;
                Box::new(move || {
                    let mut s = match target.open() {
                        Ok(s) => s,
                        Err(e) => return Preview::Failed(e.to_string()),
                    };
                    let had_pin = pin.is_some();
                    match keyroost_transport::import::read_token2_existing(
                        &mut s,
                        pin.as_deref().map(String::as_str),
                    ) {
                        Ok(ex) => Preview::Read(ex, None),
                        Err(keyroost_transport::OtpTransportError::PinRequired) => Preview::Locked,
                        // Like the OTP pane and the CLI: a key supplied
                        // without the OTP function says so plainly.
                        Err(_)
                            if crate::otp_pane::totp_capability(
                                s.read_device_info().ok().as_ref(),
                            ) == Some(false) =>
                        {
                            Preview::Failed(NO_OTP_FUNCTION.to_owned())
                        }
                        Err(e) if had_pin => Preview::Refused(e.to_string()),
                        Err(e) => Preview::Failed(e.to_string()),
                    }
                })
            }
        };
        let queued = self.spawn_job("Reading the key\u{2026}", move || {
            let preview = job();
            Box::new(move |app: &mut App| app.import_set_preview(id, &dest, preview))
        });
        if let Some(d) = self.import_flow.dialog.as_mut() {
            if queued {
                d.preview_wanted = false;
                d.reading = true;
            }
        }
    }

    /// Apply a preview to the dialog it was read for.
    fn import_set_preview(&mut self, id: u64, dest: &DestKey, preview: Preview) {
        let Some(d) = self.import_flow.dialog.as_mut() else {
            return;
        };
        if d.id != id || d.dest.as_ref() != Some(dest) {
            return;
        }
        d.reading = false;
        d.preview_wanted = false;
        match preview {
            Preview::Read(ex, version) => {
                d.existing = Some((dest.clone(), ex, version));
                d.dest_locked = false;
                d.dest_error = None;
            }
            Preview::Locked => {
                d.existing = None;
                d.dest_locked = true;
                d.dest_error = None;
            }
            Preview::Refused(e) => {
                d.existing = None;
                d.dest_locked = true;
                wipe(&mut d.dest_secret);
                d.dest_error = Some(format!("The key didn't accept that: {e}"));
                self.import_scrub(DEST_SECRET_ID);
            }
            Preview::Failed(e) => {
                d.existing = None;
                d.dest_error = Some(e);
            }
        }
    }

    /// The plan the dialog shows for its destination, when it can be made.
    fn import_plan(&self, d: &ImportDialog) -> (Option<Plan>, bool) {
        let (Some(file), Some(dest)) = (d.file.as_ref(), d.dest.as_ref()) else {
            return (None, false);
        };
        let Some(dev) = self.import_device(&dest.device) else {
            return (None, false);
        };
        match dest.store {
            StoreKind::Molto2 => {
                let meta = self
                    .slot_meta
                    .as_deref()
                    .filter(|_| self.molto_session_device.as_ref() == Some(&dest.device));
                let existing = meta.map(molto_existing).unwrap_or_default();
                let plan = molto_plan(file, d.molto_start, existing);
                (Some(plan), meta.is_none())
            }
            _ => match d.contents() {
                Some((_, ex, version)) => {
                    let store = store_of(dest.store, &dev.vendor, *version);
                    (Some(plan_for(file, store, 0, ex.clone(), d.replace)), false)
                }
                None => (None, false),
            },
        }
    }

    /// Gather what this frame of the dialog shows.
    fn import_view(&self, d: &ImportDialog, dests: &[DestKey]) -> View {
        let (plan, molto_unread) = self.import_plan(d);
        let unlocked_here =
            self.authenticated && d.dest.as_ref().is_some_and(|k| self.import_molto_ready(k));
        let molto_note = molto_unread.then_some(if unlocked_here {
            MOLTO_SLOTS_FAILED
        } else {
            MOLTO_SLOTS_UNREAD
        });
        let dest_rows = dests
            .iter()
            .filter_map(|k| {
                let dev = self.import_device(&k.device)?;
                let fit = d.file.as_ref().map_or(0, |f| {
                    let version = d
                        .existing
                        .as_ref()
                        .filter(|(dk, _, _)| dk == k)
                        .and_then(|(_, _, v)| *v);
                    fit_count(f, store_of(k.store, &dev.vendor, version), d.molto_start)
                });
                Some((k.clone(), dest_label(dev.title(), k.store), fit))
            })
            .collect();
        let dest_name = d
            .dest
            .as_ref()
            .and_then(|k| self.import_device(&k.device))
            .map(|dev| dev.title().to_owned())
            .unwrap_or_default();
        let molto = d.dest.as_ref().filter(|k| k.store == StoreKind::Molto2);
        let input = BlockInput {
            loading: self.import_busy(),
            needs_password: d.needs_password && d.file.is_none(),
            usable: d.file.as_ref().map_or(0, |f| f.usable()),
            capable_key: !dests.is_empty(),
            dest: d.dest.as_ref().map(|k| k.store),
            reading: d.reading || d.preview_wanted,
            key_not_read: plan.is_none() && d.dest.is_some(),
            locked: d.dest_locked,
            molto_session: molto.is_some_and(|k| self.import_molto_ready(k)),
            molto_unlocked: self.authenticated,
            writes: plan.as_ref().map_or(0, |p| p.writes().count()),
            running: d.running.is_some(),
            device_busy: self.busy(),
        };
        View {
            dests: dest_rows,
            total: d.file.as_ref().map_or(0, |f| f.items.len()),
            plan,
            molto_note,
            block: ImportBlock::find(&input),
            dest_name,
        }
    }

    /// "Add": write the planned codes to the chosen destination.
    fn import_add(&mut self, shown: Plan) {
        let Some(d) = self.import_flow.dialog.as_ref() else {
            return;
        };
        let (Some(file), Some(dest)) = (d.file.clone(), d.dest.clone()) else {
            return;
        };
        let Some(dev) = self.import_device(&dest.device).cloned() else {
            self.import_add_refused("The key is no longer connected.");
            return;
        };
        let id = d.id;
        let replace = d.replace;
        let timeout = d.molto_timeout.to_proto();
        let oath_pw = self.import_oath_password(d, &dest);
        let otp_pin = self.import_otp_pin(d, &dest);
        let progress = Arc::new(Mutex::new((0usize, shown.writes().count())));
        let counter = progress.clone();
        let on_progress = move |done: usize, total: usize, _row: &PlanRow| {
            if let Ok(mut g) = counter.lock() {
                *g = (done, total);
            }
        };
        let label = format!("Adding codes to {}\u{2026}", dev.title());
        let queued = match dest.store {
            StoreKind::Molto2 => {
                if !self.authenticated {
                    self.import_add_refused(
                        "The Molto2 is not unlocked yet. Click Authenticate, then Add.",
                    );
                    return;
                }
                let for_device = self.selected_device.clone();
                let Some(mut s) = self.take_molto_session() else {
                    self.import_add_refused("The Molto2 isn't ready yet; try again in a moment.");
                    return;
                };
                self.spawn_job(label, move || {
                    let mut on_progress = on_progress;
                    let report = {
                        let mut store =
                            keyroost_transport::import::MoltoImportStore::new(&mut s, timeout);
                        keyroost_import::run::run(&file, &shown, &mut store, &mut on_progress)
                    };
                    let line = report.summary(&shown);
                    drop(file);
                    // Public-block sweep, as after every Molto2 write: a
                    // failed sweep keeps the old slot list.
                    let meta = (0..PROFILES)
                        .map(|p| s.read_public_data(p))
                        .collect::<Result<Vec<_>, _>>()
                        .ok();
                    Box::new(move |app: &mut App| {
                        app.session = Some(s);
                        if completion_still_valid(for_device.as_ref(), app.selected_device.as_ref())
                        {
                            match meta {
                                Some(m) => app.slot_meta = Some(m),
                                // The sweep failed: read the slots again so
                                // the list shows what was written.
                                None => app.resweep_slot_meta(LogKind::Background),
                            }
                        }
                        app.import_finish(id, &dest, Added::Done(report, line));
                    })
                })
            }
            StoreKind::Oath => {
                let Some(reader) = dev.reader.clone() else {
                    self.import_add_refused(NO_SMART_CARD);
                    return;
                };
                let pw = oath_pw;
                let vendor = dev.vendor.clone();
                self.spawn_job(label, move || {
                    let mut on_progress = on_progress;
                    let added = (|| {
                        let mut s = match keyroost_transport::OathSession::open(&reader) {
                            Ok(s) => s,
                            Err(e) => return Added::Failed(e.to_string()),
                        };
                        if s.password_required() {
                            let Some(pw) = pw.as_ref() else {
                                return Added::Locked;
                            };
                            if let Err(e) = s.unlock(pw) {
                                return Added::Refused(e.to_string());
                            }
                        }
                        let version = s.version();
                        let store = store_of(StoreKind::Oath, &vendor, version);
                        let ex = match keyroost_transport::import::read_oath_existing(&mut s) {
                            Ok(ex) => ex,
                            Err(e) => return Added::Failed(e.to_string()),
                        };
                        let again = plan_for(&file, store, 0, ex.clone(), replace);
                        if !again.same_rows(&shown) {
                            return Added::Changed(ex, version);
                        }
                        let mut w = keyroost_transport::import::OathImportStore::new(
                            &mut s,
                            OathFamily::from_vendor(&vendor, version),
                        )
                        .password_hint(OATH_PASSWORD_HINT);
                        let report =
                            keyroost_import::run::run(&file, &again, &mut w, &mut on_progress);
                        let line = report.summary(&again);
                        Added::Done(report, line)
                    })();
                    drop(file);
                    drop(pw);
                    Box::new(move |app: &mut App| app.import_finish(id, &dest, added))
                })
            }
            StoreKind::Token2Otp => {
                let target = match self.import_otp_target(&dev) {
                    Ok(t) => t,
                    Err(e) => {
                        if let Some(d) = self.import_flow.dialog.as_mut() {
                            d.dest_error = Some(e);
                        }
                        return;
                    }
                };
                let pin = otp_pin;
                self.spawn_job(label, move || {
                    let mut on_progress = on_progress;
                    let added = (|| {
                        let mut s = match target.open() {
                            Ok(s) => s,
                            Err(e) => return Added::Failed(e.to_string()),
                        };
                        let ex = match keyroost_transport::import::read_token2_existing(
                            &mut s,
                            pin.as_deref().map(String::as_str),
                        ) {
                            Ok(ex) => ex,
                            Err(keyroost_transport::OtpTransportError::PinRequired) => {
                                return Added::Locked
                            }
                            Err(e) => return Added::Failed(e.to_string()),
                        };
                        let again = plan_for(&file, Store::Token2Otp, 0, ex.clone(), replace);
                        if !again.same_rows(&shown) {
                            return Added::Changed(ex, None);
                        }
                        let mut w =
                            keyroost_transport::import::Token2ImportStore::new(&mut s, pin.clone());
                        let report =
                            keyroost_import::run::run(&file, &again, &mut w, &mut on_progress);
                        let line = report.summary(&again);
                        Added::Done(report, line)
                    })();
                    drop(file);
                    drop(pin);
                    Box::new(move |app: &mut App| app.import_finish(id, &dest, added))
                })
            }
        };
        if let Some(d) = self.import_flow.dialog.as_mut() {
            if queued {
                d.running = Some(progress);
                d.dest_error = None;
            } else {
                d.dest_error =
                    Some("Another key operation is running; try again in a moment.".into());
            }
        }
    }

    /// Apply the Add job's result to the dialog it ran for.
    fn import_finish(&mut self, id: u64, dest: &DestKey, added: Added) {
        let name = self
            .import_device(&dest.device)
            .map(|d| d.title().to_owned())
            .unwrap_or_default();
        let selected = self.selected_device.as_ref() == Some(&dest.device);
        if let Added::Done(report, line) = &added {
            let sev = if report.ok() && report.stopped.is_none() {
                Severity::Ok
            } else {
                Severity::Warn
            };
            self.log_global(sev, LogKind::User, format!("{name}: import: {line}"));
            // The matching pane shows the new codes.
            if selected {
                match dest.store {
                    StoreKind::Oath => self.load_oath_creds(),
                    StoreKind::Token2Otp => self.load_otp_entries(),
                    StoreKind::Molto2 => {}
                }
            }
        }
        let Some(d) = self.import_flow.dialog.as_mut() else {
            return;
        };
        if d.id != id {
            return;
        }
        d.running = None;
        match added {
            // Every destination, Molto2 included, shows its report.
            Added::Done(report, line) => {
                d.report = Some(report);
                d.report_line = line;
            }
            Added::Changed(ex, version) => {
                d.existing = Some((dest.clone(), ex, version));
                d.dest_error = Some(
                    "The codes on the key changed; check the preview and try again.".to_owned(),
                );
            }
            Added::Locked => {
                d.existing = None;
                d.dest_locked = true;
            }
            Added::Refused(e) => {
                d.existing = None;
                d.dest_locked = true;
                wipe(&mut d.dest_secret);
                d.dest_error = Some(format!("The key didn't accept that: {e}"));
                self.import_scrub(DEST_SECRET_ID);
            }
            Added::Failed(e) => d.dest_error = Some(format!("Nothing was written: {e}")),
        }
    }

    /// Draw the notice and the dialog, when one is showing.
    pub(crate) fn render_import(&mut self, ctx: &egui::Context, p: &Palette) {
        let waiting = waiting_line(self.import_flow.queue.len());
        if let Some(n) = &self.import_flow.notice {
            let (file_name, text) = (n.file_name.clone(), n.text.clone());
            let mut ok = false;
            let closed = Self::modal_window(ctx, p, "import-notice", "Import file", 420.0, |ui| {
                if !file_name.is_empty() {
                    ui.label(
                        egui::RichText::new(&file_name)
                            .font(theme::f_sb(12.5))
                            .color(p.txt),
                    );
                    ui.add_space(6.0);
                }
                ui.label(egui::RichText::new(&text).color(p.txt2));
                if let Some(w) = &waiting {
                    ui.add_space(8.0);
                    ui.label(
                        egui::RichText::new(w)
                            .font(theme::f_reg(11.5))
                            .color(p.txt3),
                    );
                }
                ui.add_space(12.0);
                if theme::button(ui, p, BtnKind::Primary, "OK").clicked() {
                    ok = true;
                }
            });
            if ok || closed {
                self.import_flow.notice = None;
            }
        }
        self.render_import_dialog(ctx, p, waiting);
    }

    fn render_import_dialog(&mut self, ctx: &egui::Context, p: &Palette, waiting: Option<String>) {
        if self.import_flow.dialog.is_none() {
            return;
        }
        // Follow the connected keys and the selection before drawing.
        let dests = destinations(&self.devices);
        let viewed = self.import_viewed();
        if let Some(d) = self.import_flow.dialog.as_mut() {
            let pre = preselect(
                &dests,
                &d.origin,
                viewed.as_ref().map(|(id, tab)| (id, *tab)),
            );
            let before = d.dest.clone();
            d.follow_devices(&dests, pre);
            if d.dest != before {
                clear_edit_undo(ctx, egui::Id::new(DEST_SECRET_ID));
            }
        }
        // A Molto2 destination works on its own: select it (once per choice)
        // as soon as no device job runs, which opens its session.
        let selected = self.selected_device.clone();
        if let Some(d) = self.import_flow.dialog.as_mut() {
            d.arm_molto_select(selected.as_ref());
        }
        if !self.busy() {
            let to_select = self
                .import_flow
                .dialog
                .as_mut()
                .and_then(|d| d.take_molto_select(selected.as_ref()));
            if let Some(id) = to_select {
                self.select_device(id);
            }
        }
        let want_preview = self
            .import_flow
            .dialog
            .as_ref()
            .is_some_and(|d| d.preview_wanted && d.running.is_none());
        if want_preview && !self.busy() && !self.import_busy() {
            self.import_preview();
        }
        let importing = self.import_busy();
        let import_label = self.import_label.clone();
        let busy = self.busy();
        let Some(d) = self.import_flow.dialog.as_ref() else {
            return;
        };
        let view = self.import_view(d, &dests);
        let Some(d) = self.import_flow.dialog.as_mut() else {
            return;
        };

        let mut open = d.open;
        let mut close_clicked = false;
        let mut do_open = false;
        let mut do_add = false;
        let mut do_auth = false;
        let mut do_unlock = false;
        let mut picked: Option<DestKey> = None;
        egui::Window::new("Import authenticator codes")
            .open(&mut open)
            .collapsible(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .default_width(580.0)
            .show(ctx, |ui| {
                // The file.
                ui.label(egui::RichText::new(file_line(d)).color(p.txt));
                if let Some(file) = d.file.as_ref() {
                    if let Some((i, n)) = file.batch {
                        ui.label(
                            egui::RichText::new(format!(
                                "QR {} of {n} \u{2014} import the others too.",
                                i + 1
                            ))
                            .color(p.txt2),
                        );
                    }
                    if matches!(file.format, Format::QrImage | Format::GoogleExport) {
                        ui.label(
                            egui::RichText::new("Delete the screenshot after a successful import.")
                                .color(p.txt2),
                        );
                    }
                }
                if d.needs_password && d.file.is_none() {
                    ui.add_space(6.0);
                    ui.label("File password:");
                    ui.horizontal(|ui| {
                        let resp = ui.add(
                            egui::TextEdit::singleline(&mut d.file_password)
                                .id(egui::Id::new(FILE_PASSWORD_ID))
                                .password(true)
                                .desired_width(300.0),
                        );
                        guard_secret_field(ui.ctx(), &resp);
                        let enter =
                            resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                        let can = !importing && !d.file_password.is_empty();
                        if ui.add_enabled(can, egui::Button::new("Open")).clicked()
                            || (enter && can)
                        {
                            do_open = true;
                        }
                    });
                }
                if importing {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        if let Some(l) = &import_label {
                            ui.label(l.as_str());
                        }
                    });
                }
                if let Some(err) = &d.error {
                    ui.colored_label(p.err, err);
                }

                // The entries.
                if let Some(file) = d.file.as_ref() {
                    ui.add_space(6.0);
                    egui::ScrollArea::vertical()
                        .id_salt("import-entries")
                        .max_height(8.0 * 20.0)
                        .show(ui, |ui| {
                            for item in &file.items {
                                let (line, usable) = entry_line(item);
                                let color = if usable { p.txt2 } else { p.txt3 };
                                ui.label(egui::RichText::new(line).color(color));
                            }
                        });
                }

                // Where they go.
                if d.file.is_some() && d.report.is_none() {
                    ui.add_space(8.0);
                    ui.label(
                        egui::RichText::new("Add to")
                            .font(theme::f_sb(13.0))
                            .color(p.txt),
                    );
                    if view.dests.is_empty() {
                        // The reason line under the buttons says what to do.
                        ui.colored_label(p.txt3, "No connected key can store codes yet.");
                    }
                    let locked_choice = d.running.is_some();
                    for (k, label, fit) in &view.dests {
                        ui.horizontal(|ui| {
                            let chosen = d.dest.as_ref() == Some(k);
                            if ui
                                .add_enabled(!locked_choice, egui::RadioButton::new(chosen, label))
                                .clicked()
                                && !chosen
                            {
                                picked = Some(k.clone());
                            }
                            ui.label(
                                egui::RichText::new(format!(
                                    "{fit} of {} can be stored",
                                    view.total
                                ))
                                .font(theme::f_reg(11.5))
                                .color(p.txt3),
                            );
                        });
                    }
                    match d.dest.as_ref().map(|k| k.store) {
                        Some(StoreKind::Oath | StoreKind::Token2Otp) => {
                            ui.checkbox(
                                &mut d.replace,
                                "Replace codes already on the key that have the same name",
                            );
                        }
                        Some(StoreKind::Molto2) => {
                            ui.horizontal(|ui| {
                                ui.label("Start at slot:");
                                ui.add(
                                    egui::DragValue::new(&mut d.molto_start)
                                        .clamp_existing_to_range(true)
                                        .range(0..=99u8),
                                );
                                ui.label("Display timeout:");
                                timeout_combo(ui, &mut d.molto_timeout);
                            });
                        }
                        None => {}
                    }
                    if d.dest_locked {
                        let what = match d.dest.as_ref().map(|k| k.store) {
                            Some(StoreKind::Token2Otp) => "OTP PIN:",
                            _ => "OATH password:",
                        };
                        ui.add_space(6.0);
                        ui.label(what);
                        ui.horizontal(|ui| {
                            let resp = ui.add(
                                egui::TextEdit::singleline(&mut d.dest_secret)
                                    .id(egui::Id::new(DEST_SECRET_ID))
                                    .password(true)
                                    .desired_width(260.0),
                            );
                            guard_secret_field(ui.ctx(), &resp);
                            let enter =
                                resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                            let can = !busy && !d.dest_secret.is_empty();
                            if ui.add_enabled(can, egui::Button::new("Unlock")).clicked()
                                || (enter && can)
                            {
                                do_unlock = true;
                            }
                        });
                    }
                    if let Some(err) = &d.dest_error {
                        ui.colored_label(p.err, err);
                    }

                    // The preview.
                    if let Some(plan) = &view.plan {
                        ui.add_space(6.0);
                        ui.label(
                            egui::RichText::new(holds_line(plan, d.molto_start)).color(p.txt2),
                        );
                        egui::ScrollArea::vertical()
                            .id_salt("import-preview")
                            .max_height(8.0 * 20.0)
                            .show(ui, |ui| {
                                for row in &plan.rows {
                                    let color = match row.verdict {
                                        Verdict::Add | Verdict::Replace => p.txt2,
                                        _ => p.txt3,
                                    };
                                    ui.label(
                                        egui::RichText::new(plan_row_line(row, plan.store))
                                            .color(color),
                                    );
                                }
                            });
                        for note in &plan.notes {
                            ui.label(
                                egui::RichText::new(note.to_string())
                                    .font(theme::f_reg(11.5))
                                    .color(p.txt3),
                            );
                        }
                        if let Some(note) = view.molto_note {
                            ui.label(
                                egui::RichText::new(note)
                                    .font(theme::f_reg(11.5))
                                    .color(p.txt3),
                            );
                        }
                    }
                }

                // The report.
                if let Some(report) = &d.report {
                    ui.add_space(8.0);
                    ui.label(egui::RichText::new(&d.report_line).color(p.txt));
                    egui::ScrollArea::vertical()
                        .id_salt("import-report")
                        .max_height(8.0 * 20.0)
                        .show(ui, |ui| {
                            for (_, label, outcome) in &report.rows {
                                let color = match outcome {
                                    Outcome::Added | Outcome::Replaced | Outcome::AlreadyThere => {
                                        p.txt2
                                    }
                                    _ => p.err,
                                };
                                ui.label(
                                    egui::RichText::new(outcome_line(label, outcome)).color(color),
                                );
                            }
                        });
                    if let Some(why) = &report.stopped {
                        ui.colored_label(p.err, format!("Stopped: {why}"));
                    }
                }

                // The buttons.
                ui.add_space(10.0);
                if let Some(progress) = &d.running {
                    let (done, total) = progress.lock().map(|g| *g).unwrap_or((0, 0));
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(format!(
                            "Adding {} of {total}\u{2026}",
                            (done + 1).min(total.max(1))
                        ));
                    });
                } else {
                    ui.horizontal(|ui| {
                        if d.report.is_none() && d.file.is_some() {
                            let writes = view.plan.as_ref().map_or(0, |p| p.writes().count());
                            let text = if d.dest.is_some() {
                                add_button_text(writes, &view.dest_name)
                            } else {
                                "Add codes".to_owned()
                            };
                            let resp =
                                ui.add_enabled(view.block.is_none(), egui::Button::new(text));
                            let resp = match &view.block {
                                Some(b) => resp.on_disabled_hover_text(b.message()),
                                None => resp,
                            };
                            if resp.clicked() {
                                do_add = true;
                            }
                        }
                        if ui.button("Close").clicked() {
                            close_clicked = true;
                        }
                        if d.report.is_none()
                            && view.block == Some(ImportBlock::MoltoNotUnlocked)
                            && ui
                                .add_enabled(!busy, egui::Button::new("Authenticate"))
                                .clicked()
                        {
                            do_auth = true;
                        }
                        if d.report.is_none()
                            && view.block == Some(ImportBlock::KeyNotRead)
                            && ui
                                .add_enabled(!busy, egui::Button::new("Try again"))
                                .clicked()
                        {
                            do_unlock = true;
                        }
                    });
                }
                if d.report.is_none() && d.running.is_none() {
                    if let Some(b) = &view.block {
                        let msg = if *b == ImportBlock::MoltoNotUnlocked && d.auth_failed {
                            "Couldn't unlock the Molto2 \u{2014} check the customer key".to_owned()
                        } else {
                            b.message()
                        };
                        ui.colored_label(p.warn, msg);
                    }
                }
                if let Some(w) = &waiting {
                    ui.add_space(6.0);
                    ui.label(
                        egui::RichText::new(w)
                            .font(theme::f_reg(11.5))
                            .color(p.txt3),
                    );
                }
            });

        // Apply Close and [X] only now, after the window is drawn; every
        // route wipes both secrets and drops the entries. A running import
        // can't be closed from under its report.
        if d.running.is_some() {
            close_clicked = false;
            open = true;
        }
        d.settle_open(open, close_clicked);
        if !d.open {
            self.import_flow.dialog = None;
            clear_edit_undo(ctx, egui::Id::new(FILE_PASSWORD_ID));
            clear_edit_undo(ctx, egui::Id::new(DEST_SECRET_ID));
            return;
        }
        if let Some(k) = picked {
            d.set_dest(Some(k), true);
            clear_edit_undo(ctx, egui::Id::new(DEST_SECRET_ID));
        }
        if do_unlock {
            d.preview_wanted = true;
            d.dest_error = None;
        }
        if do_open {
            let (id, path, name) = (d.id, d.path.clone(), d.file_name.clone());
            let origin = d.origin.clone();
            let pw = zeroize::Zeroizing::new(d.file_password.clone());
            d.error = None;
            self.import_read(id, path, name, origin, Some(pw));
        }
        if do_auth {
            self.authenticate();
        }
        if do_add {
            if let Some(plan) = view.plan {
                self.import_add(plan);
            }
        }
    }
}

/// The Molto2 display-timeout picker.
fn timeout_combo(ui: &mut egui::Ui, value: &mut TimeoutChoice) {
    let label = |t: TimeoutChoice| match t {
        TimeoutChoice::S15 => "15s",
        TimeoutChoice::S30 => "30s",
        TimeoutChoice::S60 => "60s",
        TimeoutChoice::S120 => "120s",
    };
    egui::ComboBox::from_id_salt("import-molto-timeout")
        .selected_text(label(*value))
        .show_ui(ui, |ui| {
            for t in [
                TimeoutChoice::S15,
                TimeoutChoice::S30,
                TimeoutChoice::S60,
                TimeoutChoice::S120,
            ] {
                ui.selectable_value(value, t, label(t));
            }
        });
}

/// `vault.json — Aegis (encrypted) · 12 entries`.
pub fn file_line(d: &ImportDialog) -> String {
    let mut s = d.file_name.clone();
    if let Some(f) = d.format {
        s.push_str(" \u{2014} ");
        s.push_str(f.name());
    }
    if let Some(file) = &d.file {
        let n = file.items.len();
        s.push_str(&format!(
            " \u{b7} {n} {}",
            if n == 1 { "entry" } else { "entries" }
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyroost_import::plan::StoredName;
    use keyroost_import::HashAlg;
    use keyroost_import::{ImportEntry, ImportItem};

    fn dev(id: &str, caps: &[Caps]) -> Device {
        let mut c = Caps::default();
        for x in caps {
            c.insert(*x);
        }
        Device {
            id: id.into(),
            name: None,
            vendor: "Yubico".into(),
            model: "YubiKey".into(),
            serial: id.into(),
            transport: "USB".into(),
            firmware: String::new(),
            caps: c,
            unverified: Caps::default(),
            kind: DeviceKind::Key,
            hid_path: None,
            reader: None,
            hid_serial: None,
            naming: Default::default(),
            smart_card_unlisted: false,
        }
    }

    fn dk(id: &str, store: StoreKind) -> DestKey {
        DestKey {
            device: id.into(),
            store,
        }
    }

    fn entry(issuer: &str, hash: HashAlg, period: u32) -> ImportEntry {
        ImportEntry {
            issuer: Some(issuer.into()),
            account: Some("alice".into()),
            secret: zeroize::Zeroizing::new(vec![7u8; 20]),
            hash,
            digits: 6,
            kind: OtpKind::Totp { period },
        }
    }

    fn file_of(entries: Vec<ImportEntry>) -> ImportFile {
        ImportFile {
            format: Format::Aegis,
            items: entries
                .into_iter()
                .enumerate()
                .map(|(index, e)| ImportItem {
                    index,
                    label: format!("{}:alice", e.issuer.as_deref().unwrap_or("")),
                    entry: Ok(e),
                })
                .collect(),
            batch: None,
        }
    }

    fn open_dialog() -> ImportDialog {
        let mut d = ImportDialog::new(
            1,
            PathBuf::from("/x/v.json"),
            "v.json".into(),
            Origin::Dropped,
        );
        d.file = Some(Arc::new(file_of(vec![entry("GitHub", HashAlg::Sha1, 30)])));
        d.file_password = "hunter2".into();
        d.dest = Some(dk("a", StoreKind::Oath));
        d.dest_secret = "oathpw".into();
        d.existing = Some((dk("a", StoreKind::Oath), Existing::default(), None));
        d.report = Some(Report {
            rows: Vec::new(),
            stopped: None,
        });
        d
    }

    fn assert_wiped(d: &ImportDialog) {
        assert!(!d.open);
        assert!(d.file_password.is_empty());
        assert!(d.dest_secret.is_empty());
        assert!(d.file.is_none());
        assert!(d.existing.is_none());
        assert!(d.report.is_none());
    }

    #[test]
    fn destinations_order_and_labels() {
        let devices = vec![
            dev("both", &[Caps::FIDO2, Caps::OTP, Caps::OATH]),
            dev("molto", &[Caps::TOTP]),
            dev("fido-only", &[Caps::FIDO2, Caps::PIV]),
            dev("prog", &[Caps::PROG]),
        ];
        assert_eq!(
            destinations(&devices),
            vec![
                dk("both", StoreKind::Oath),
                dk("both", StoreKind::Token2Otp),
                dk("molto", StoreKind::Molto2),
            ]
        );
        assert_eq!(
            dest_label("YubiKey", StoreKind::Oath),
            "YubiKey \u{2014} Authenticator (OATH)"
        );
        assert_eq!(
            dest_label("Token2", StoreKind::Token2Otp),
            "Token2 \u{2014} OTP storage"
        );
        assert_eq!(
            dest_label("Molto2", StoreKind::Molto2),
            "Molto2 \u{2014} Molto2 slots"
        );
    }

    #[test]
    fn drop_queues_every_file_once() {
        let mut flow = ImportFlow::default();
        let a = PathBuf::from("/x/a.json");
        let b = PathBuf::from("/x/b.png");
        let c = PathBuf::from("/x/c.txt");
        flow.enqueue([a.clone(), b.clone(), a.clone()], &Origin::Dropped);
        flow.enqueue([b.clone(), c.clone()], &Origin::Dropped);
        let got: Vec<_> = flow.queue.iter().map(|(p, _)| p.clone()).collect();
        assert_eq!(got, vec![a, b, c]);
        assert!(flow.queue.iter().all(|(_, o)| *o == Origin::Dropped));
    }

    #[test]
    fn queue_waits_while_busy_or_showing() {
        let mut flow = ImportFlow::default();
        assert!(may_start_next(&flow, false, false));
        assert!(!may_start_next(&flow, true, false));
        assert!(!may_start_next(&flow, false, true));
        flow.notice = Some(FileNotice {
            file_name: "a".into(),
            text: "t".into(),
        });
        assert!(!may_start_next(&flow, false, false));
        flow.notice = None;
        flow.dialog = Some(ImportDialog::new(
            1,
            PathBuf::from("a"),
            "a".into(),
            Origin::Dropped,
        ));
        assert!(!may_start_next(&flow, false, false));
        flow.dialog = None;
        assert!(may_start_next(&flow, false, false));
    }

    #[test]
    fn notice_text_per_key_material() {
        use keyroost_import::classify::KeyMaterial;
        for k in [
            KeyMaterial::Certificate,
            KeyMaterial::CertificateRequest,
            KeyMaterial::PrivateKey,
            KeyMaterial::OpenPgpKey,
            KeyMaterial::SshKey,
            KeyMaterial::Pkcs12,
        ] {
            let n = key_material_notice("f.pem", k);
            assert_eq!(n.file_name, "f.pem");
            assert_eq!(n.text, k.gui_pointer());
            assert!(n.text.ends_with("Nothing was changed."));
        }
        assert!(key_material_notice("c.pem", KeyMaterial::Certificate)
            .text
            .starts_with("This looks like a certificate."));
    }

    #[test]
    fn waiting_line_counts() {
        assert_eq!(waiting_line(0), None);
        assert_eq!(waiting_line(1).as_deref(), Some("1 more file waiting."));
        assert_eq!(waiting_line(3).as_deref(), Some("3 more files waiting."));
    }

    #[test]
    fn import_dialog_close_button_wins_over_stale_open_copy() {
        let mut d = open_dialog();
        d.settle_open(true, true);
        assert_wiped(&d);
    }

    #[test]
    fn import_dialog_x_closes() {
        let mut d = open_dialog();
        d.settle_open(false, false);
        assert_wiped(&d);
    }

    #[test]
    fn import_dialog_stays_open_without_a_close() {
        let mut d = open_dialog();
        d.settle_open(true, false);
        assert!(d.open);
        assert_eq!(d.file_password, "hunter2");
        assert_eq!(d.dest_secret, "oathpw");
        assert!(d.file.is_some());
    }

    #[test]
    fn import_dialog_every_close_route_wipes() {
        // Close, [X], and close() as a finished Molto2 import uses it.
        for route in 0..3 {
            let mut d = open_dialog();
            match route {
                0 => d.settle_open(true, true),
                1 => d.settle_open(false, false),
                _ => d.close(),
            }
            assert_wiped(&d);
        }
        // The destination going away wipes what belongs to it.
        let mut d = open_dialog();
        d.report = None;
        d.follow_devices(&[], None);
        assert!(d.dest_secret.is_empty());
        assert!(d.existing.is_none());
        // The next file only starts once the dialog is gone; dropping the
        // flow (app exit) closes what is showing.
        let flow = ImportFlow {
            dialog: Some(open_dialog()),
            ..ImportFlow::default()
        };
        let file = flow.dialog.as_ref().unwrap().file.clone().unwrap();
        drop(flow);
        // Only the test's own reference is left: the dialog let go of the
        // entries.
        assert_eq!(Arc::strong_count(&file), 1);
    }

    #[test]
    fn read_results_route_by_dialog_and_retry() {
        // A queued file with nothing showing opens its window.
        assert_eq!(route_read(None, 3, false), ReadRoute::NewWindow);
        // A retry lands in the dialog that asked for it.
        assert_eq!(route_read(Some(3), 3, true), ReadRoute::ToDialog);
        // The dialog was closed while decrypting: dropped, never reopened.
        assert_eq!(route_read(None, 3, true), ReadRoute::Drop);
        // A result for another dialog is dropped.
        assert_eq!(route_read(Some(4), 3, true), ReadRoute::Drop);
        assert_eq!(route_read(Some(4), 3, false), ReadRoute::Drop);
    }

    /// The app with one dialog waiting for its file password.
    fn app_with_password_dialog() -> App {
        let mut app = App::default();
        let mut d = ImportDialog::new(
            7,
            PathBuf::from("/x/v.json"),
            "v.json".into(),
            Origin::Dropped,
        );
        d.needs_password = true;
        d.format = Some(Format::AegisEncrypted);
        d.file_password = "hunter2".into();
        app.import_flow.dialog = Some(d);
        app
    }

    fn apply(app: &mut App, id: u64, retry: bool, read: Read) {
        app.import_apply_read(
            id,
            retry,
            PathBuf::from("/x/v.json"),
            "v.json".into(),
            Origin::Dropped,
            read,
        );
    }

    #[test]
    fn closed_while_decrypting_stays_closed() {
        use keyroost_qr::file::Opened;
        // The decrypted entries arrive after Close: nothing reopens, and
        // the entries are dropped (their seeds wiped) with the result.
        let mut app = app_with_password_dialog();
        app.import_flow
            .dialog
            .as_mut()
            .unwrap()
            .settle_open(true, true);
        app.import_flow.dialog = None;
        let file = file_of(vec![entry("GitHub", HashAlg::Sha1, 30)]);
        apply(&mut app, 7, true, Read::Opened(Opened::Entries(file)));
        assert!(app.import_flow.dialog.is_none());
        assert!(app.import_flow.notice.is_none());
        // A wrong password after Close shows nothing either.
        let mut app = app_with_password_dialog();
        app.import_flow.dialog = None;
        apply(
            &mut app,
            7,
            true,
            Read::Failed("The password didn't open this Aegis export.".into()),
        );
        assert!(app.import_flow.dialog.is_none());
        assert!(app.import_flow.notice.is_none());
    }

    #[test]
    fn password_retry_lands_in_its_dialog() {
        use keyroost_qr::file::Opened;
        let mut app = app_with_password_dialog();
        apply(&mut app, 7, true, Read::Failed("wrong".into()));
        let d = app.import_flow.dialog.as_ref().unwrap();
        assert_eq!(d.error.as_deref(), Some("wrong"));
        assert_eq!(
            d.file_password, "hunter2",
            "a wrong password keeps the field"
        );
        let file = file_of(vec![entry("GitHub", HashAlg::Sha1, 30)]);
        apply(&mut app, 7, true, Read::Opened(Opened::Entries(file)));
        let d = app.import_flow.dialog.as_ref().unwrap();
        assert!(d.file.is_some());
        assert!(!d.needs_password);
        assert!(d.file_password.is_empty());
        assert!(app.import_flow.notice.is_none());
    }

    #[test]
    fn first_read_routes_to_dialog_or_notice() {
        use keyroost_import::classify::KeyMaterial;
        use keyroost_qr::file::Opened;
        // Entries → the dialog.
        let mut app = App::default();
        let file = file_of(vec![entry("GitHub", HashAlg::Sha1, 30)]);
        apply(&mut app, 1, false, Read::Opened(Opened::Entries(file)));
        assert!(app.import_flow.dialog.as_ref().unwrap().file.is_some());
        assert!(app.import_flow.notice.is_none());
        // An encrypted vault → the dialog, asking for its password.
        let mut app = App::default();
        apply(&mut app, 1, false, Read::Opened(Opened::NeedsPassword));
        let d = app.import_flow.dialog.as_ref().unwrap();
        assert!(d.needs_password && d.file.is_none());
        assert_eq!(d.format, Some(Format::AegisEncrypted));
        // Key material → the notice with its pointer; no dialog.
        let mut app = App::default();
        apply(
            &mut app,
            1,
            false,
            Read::Opened(Opened::KeyMaterial(KeyMaterial::Certificate)),
        );
        assert!(app.import_flow.dialog.is_none());
        assert_eq!(
            app.import_flow.notice,
            Some(key_material_notice("v.json", KeyMaterial::Certificate))
        );
        // Unreadable → the notice with the reason; no dialog.
        let mut app = App::default();
        apply(
            &mut app,
            1,
            false,
            Read::Failed("keyroost can't import this file.".into()),
        );
        assert!(app.import_flow.dialog.is_none());
        assert_eq!(
            app.import_flow.notice.as_ref().map(|n| n.text.as_str()),
            Some("keyroost can't import this file.")
        );
    }

    #[test]
    fn import_block_reports_reasons_in_fix_order() {
        let ready = BlockInput {
            usable: 3,
            capable_key: true,
            dest: Some(StoreKind::Oath),
            writes: 3,
            ..BlockInput::default()
        };
        assert_eq!(ImportBlock::find(&ready), None);
        let with = |f: &dyn Fn(&mut BlockInput)| {
            let mut i = ready.clone();
            f(&mut i);
            ImportBlock::find(&i)
        };
        assert_eq!(
            with(&|i| {
                i.loading = true;
                i.needs_password = true;
            }),
            Some(ImportBlock::Loading)
        );
        assert_eq!(
            with(&|i| {
                i.needs_password = true;
                i.usable = 0;
            }),
            Some(ImportBlock::NeedsFilePassword)
        );
        assert_eq!(
            with(&|i| {
                i.usable = 0;
                i.capable_key = false;
            }),
            Some(ImportBlock::NoEntries)
        );
        assert_eq!(
            with(&|i| {
                i.capable_key = false;
                i.dest = None;
            }),
            Some(ImportBlock::NoCapableKey)
        );
        assert_eq!(
            with(&|i| {
                i.dest = None;
                i.reading = true;
            }),
            Some(ImportBlock::NoDestination)
        );
        assert_eq!(
            with(&|i| {
                i.reading = true;
                i.locked = true;
            }),
            Some(ImportBlock::Reading)
        );
        assert_eq!(
            with(&|i| {
                i.locked = true;
                i.key_not_read = true;
            }),
            Some(ImportBlock::Locked(StoreKind::Oath))
        );
        assert_eq!(
            with(&|i| {
                i.key_not_read = true;
                i.writes = 0;
            }),
            Some(ImportBlock::KeyNotRead)
        );
        assert_eq!(
            with(&|i| {
                i.writes = 0;
                i.running = true;
            }),
            Some(ImportBlock::NothingToAdd)
        );
        assert_eq!(
            with(&|i| {
                i.running = true;
                i.device_busy = true;
            }),
            Some(ImportBlock::Running)
        );
        assert_eq!(with(&|i| i.device_busy = true), Some(ImportBlock::Busy));
        // Molto2: session, then unlock, before anything else.
        let molto = |f: &dyn Fn(&mut BlockInput)| {
            let mut i = ready.clone();
            i.dest = Some(StoreKind::Molto2);
            i.molto_session = true;
            i.molto_unlocked = true;
            f(&mut i);
            ImportBlock::find(&i)
        };
        assert_eq!(molto(&|_| {}), None);
        assert_eq!(
            molto(&|i| {
                i.molto_session = false;
                i.molto_unlocked = false;
            }),
            Some(ImportBlock::NoMoltoSession)
        );
        assert_eq!(
            molto(&|i| i.molto_unlocked = false),
            Some(ImportBlock::MoltoNotUnlocked)
        );
        // A file that runs past #99: the plan skips what doesn't fit (as
        // `molto import` does) and Add writes the rest; overflow never
        // blocks it.
        let three = file_of(vec![
            entry("A", HashAlg::Sha1, 30),
            entry("B", HashAlg::Sha1, 30),
            entry("C", HashAlg::Sha1, 30),
        ]);
        let plan = molto_plan(&three, 98, Existing::default());
        let words: Vec<&str> = plan.rows.iter().map(|r| r.verdict.word()).collect();
        assert_eq!(words, ["add", "add", "skip"]);
        assert_eq!(
            plan.rows[2].verdict.reason(Store::Molto2).as_deref(),
            Some("no slot left after #99")
        );
        let writes = plan.writes().count();
        assert_eq!(molto(&|i| i.writes = writes), None);
        assert_eq!(molto(&|i| i.writes = 0), Some(ImportBlock::NothingToAdd));
    }

    #[test]
    fn import_block_molto_messages() {
        assert_eq!(ImportBlock::Loading.message(), "Still reading the file.");
        assert_eq!(
            ImportBlock::NoMoltoSession.message(),
            "Opening the Molto2\u{2026} If this doesn't finish, unplug it and plug it back in."
        );
        // The dialog works on its own: no pointer to another view for the
        // default key.
        assert_eq!(
            ImportBlock::MoltoNotUnlocked.message(),
            "The Molto2 is not unlocked yet. Click Authenticate \
             (uses the factory-default customer key unless another one is entered \
             in the Molto2 view)."
        );
    }

    #[test]
    fn preselect_table() {
        let a_oath = dk("a", StoreKind::Oath);
        let a_otp = dk("a", StoreKind::Token2Otp);
        let b_oath = dk("b", StoreKind::Oath);
        let m = dk("m", StoreKind::Molto2);
        let a: DeviceId = "a".into();
        let b: DeviceId = "b".into();
        let all = vec![a_oath.clone(), a_otp.clone(), b_oath.clone(), m.clone()];

        // Started from a view: that store, whatever else is connected.
        assert_eq!(
            preselect(&all, &Origin::View(a_otp.clone()), None),
            Some(a_otp.clone())
        );
        // …unless it went away.
        assert_eq!(
            preselect(
                &[b_oath.clone(), m.clone()],
                &Origin::View(a_otp.clone()),
                None
            ),
            None
        );
        // Viewed key with one store.
        assert_eq!(
            preselect(&all, &Origin::Dropped, Some((&b, None))),
            Some(b_oath.clone())
        );
        // Viewed key with two stores: the open tab decides, else none (C14).
        assert_eq!(
            preselect(&all, &Origin::Dropped, Some((&a, Some(StoreKind::Oath)))),
            Some(a_oath.clone())
        );
        assert_eq!(
            preselect(
                &all,
                &Origin::Dropped,
                Some((&a, Some(StoreKind::Token2Otp)))
            ),
            Some(a_otp.clone())
        );
        assert_eq!(preselect(&all, &Origin::Dropped, Some((&a, None))), None);
        // One capable key with one store; with two stores: none.
        assert_eq!(
            preselect(std::slice::from_ref(&m), &Origin::Dropped, None),
            Some(m.clone())
        );
        assert_eq!(
            preselect(&[a_oath.clone(), a_otp.clone()], &Origin::Dropped, None),
            None
        );
        // Two keys, nothing viewed: none. No key: none.
        assert_eq!(
            preselect(&[b_oath.clone(), m.clone()], &Origin::Dropped, None),
            None
        );
        assert_eq!(preselect(&[], &Origin::Dropped, None), None);
        // A viewed key that stores nothing falls through to the rest.
        let x: DeviceId = "x".into();
        assert_eq!(
            preselect(std::slice::from_ref(&m), &Origin::Dropped, Some((&x, None))),
            Some(m)
        );
    }

    #[test]
    fn destination_disappearing_clears_preview() {
        let mut d = open_dialog();
        d.report = None;
        d.dest_picked = true;
        let a = dk("a", StoreKind::Oath);
        // Still connected: nothing changes.
        d.follow_devices(std::slice::from_ref(&a), None);
        assert_eq!(d.dest, Some(a.clone()));
        assert!(d.existing.is_some());
        assert_eq!(d.dest_secret, "oathpw");
        // Gone: the destination, what was read from it and its password go.
        d.follow_devices(&[], None);
        assert_eq!(d.dest, None);
        assert!(d.existing.is_none());
        assert!(d.dest_secret.is_empty());
        assert!(!d.dest_picked);
        // The entries stay; plugging a key in preselects it again.
        assert!(d.file.is_some());
        d.follow_devices(std::slice::from_ref(&a), Some(a.clone()));
        assert_eq!(d.dest, Some(a));
        assert!(d.preview_wanted);
    }

    #[test]
    fn choosing_a_molto2_asks_to_select_it_once() {
        let mut d = open_dialog();
        let a = dk("a", StoreKind::Oath);
        let m = dk("m", StoreKind::Molto2);
        d.set_dest(Some(m.clone()), true);
        let sel: DeviceId = "a".into();
        // Another key is selected: select the Molto2, once.
        d.arm_molto_select(Some(&sel));
        assert_eq!(d.take_molto_select(Some(&sel)), Some(m.device.clone()));
        assert_eq!(d.take_molto_select(Some(&sel)), None);
        // Already selected: nothing to do.
        d.set_dest(Some(a), true);
        d.set_dest(Some(m.clone()), true);
        d.arm_molto_select(Some(&m.device));
        assert_eq!(d.take_molto_select(Some(&m.device)), None);
        // An OATH destination never selects anything.
        let mut d = open_dialog();
        d.set_dest(Some(dk("b", StoreKind::Oath)), true);
        d.arm_molto_select(None);
        assert_eq!(d.take_molto_select(None), None);
    }

    #[test]
    fn a_pending_molto2_selection_yields_to_a_later_choice() {
        let m = dk("m", StoreKind::Molto2);
        let a: DeviceId = "a".into();
        let b: DeviceId = "b".into();
        // Armed while "a" was selected (a device job running); the person
        // then clicks "b" in the list: the pending selection is dropped.
        let mut d = open_dialog();
        d.set_dest(Some(m.clone()), true);
        d.arm_molto_select(Some(&a));
        d.arm_molto_select(Some(&b));
        assert_eq!(d.take_molto_select(Some(&b)), None);
        assert_eq!(d.take_molto_select(Some(&a)), None);
        // The destination changed meanwhile: dropped.
        let mut d = open_dialog();
        d.set_dest(Some(m.clone()), true);
        d.arm_molto_select(Some(&a));
        d.set_dest(Some(dk("x", StoreKind::Oath)), true);
        assert_eq!(d.take_molto_select(Some(&a)), None);
        // Closed meanwhile: dropped.
        let mut d = open_dialog();
        d.set_dest(Some(m), true);
        d.arm_molto_select(Some(&a));
        d.close();
        assert_eq!(d.take_molto_select(Some(&a)), None);
    }

    #[test]
    fn preselection_never_overrides_a_pick() {
        let mut d = open_dialog();
        let a = dk("a", StoreKind::Oath);
        let m = dk("m", StoreKind::Molto2);
        d.set_dest(Some(m.clone()), true);
        d.follow_devices(&[a.clone(), m.clone()], Some(a));
        assert_eq!(d.dest, Some(m));
    }

    #[test]
    fn fit_count_uses_rules_only() {
        let file = file_of(vec![
            entry("A", HashAlg::Sha1, 30),
            entry("B", HashAlg::Sha512, 30),
            entry("C", HashAlg::Sha1, 60),
        ]);
        let yubi = store_of(StoreKind::Oath, "Yubico", Some((5, 7, 0)));
        let solo = store_of(StoreKind::Oath, "SoloKeys", None);
        let nk3 = store_of(StoreKind::Oath, "Nitrokey", None);
        assert_eq!(fit_count(&file, yubi, 0), 3);
        // Solo 2 doesn't take SHA-512.
        assert_eq!(fit_count(&file, solo, 0), 2);
        // Nitrokey 3: no SHA-512, only 30 s.
        assert_eq!(fit_count(&file, nk3, 0), 1);
        // Molto2: room from the start slot.
        assert_eq!(fit_count(&file, Store::Molto2, 99), 1);
    }

    #[test]
    fn report_and_button_wording() {
        assert_eq!(add_button_text(9, "yubi"), "Add 9 codes to yubi");
        assert_eq!(add_button_text(1, "yubi"), "Add 1 code to yubi");
        assert_eq!(
            outcome_line("c", &Outcome::Failed("x".into())),
            "c \u{2014} failed: x"
        );
        assert_eq!(
            outcome_line("#05 GitHub", &Outcome::Added),
            "#05 GitHub \u{2014} added"
        );
        assert_eq!(
            outcome_line("d", &Outcome::NotTried),
            "d \u{2014} not tried: stopped before this one"
        );
        assert_eq!(
            outcome_line("e", &Outcome::AlreadyThere),
            "e \u{2014} exists: already on the key; left as is"
        );
    }

    #[test]
    fn preview_rows_use_the_shared_words_and_keep_slots() {
        let row = |name, verdict| PlanRow {
            index: 0,
            label: "GitHub".into(),
            name,
            verdict,
        };
        let m = Some(StoredName::Molto2 {
            slot: 5,
            title: "GitHub".into(),
        });
        assert_eq!(
            plan_row_line(&row(m.clone(), Verdict::Add), Store::Molto2),
            "#05 GitHub \u{2014} add"
        );
        assert_eq!(
            plan_row_line(&row(m, Verdict::Replace), Store::Molto2),
            "#05 GitHub \u{2014} replace: replaces the code in this slot"
        );
        let solo = Store::Oath(OathFamily::Solo2);
        assert_eq!(
            plan_row_line(
                &row(
                    None,
                    Verdict::Skip(keyroost_import::plan::Skip::Hash(HashAlg::Sha512))
                ),
                solo
            ),
            "GitHub \u{2014} skip: Solo 2 doesn't take SHA-512 codes"
        );
        assert_eq!(
            plan_row_line(&row(None, Verdict::Exists), solo),
            "GitHub \u{2014} exists: already on the key; left as is"
        );
    }
}
