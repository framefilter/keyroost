//! keyroost — desktop GUI for programming Token2 Molto2 / Molto2v2 tokens.
//!
//! Dark-themed by default, modeled loosely on Token2's PyQt5 layout: device
//! status across the top, 100-slot grid on the left, edit form on the right.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::time::{SystemTime, UNIX_EPOCH};

mod ui;
use ui::device::{self, CapTab, Caps, DeviceId, DeviceKind, UiDevice};
use ui::theme::{self, BtnKind, Mode, Palette};

use eframe::egui;
use keyroost_import::parse_otpauth;
use keyroost_proto::commands::{
    DisplayTimeout, HmacAlgo, OtpDigits, ProfileConfig, TimeStep, DEFAULT_CUSTOMER_KEY,
};
use keyroost_transport::{DeviceInfo, Session, TransportError};

use keyroost_ctap::client_pin::PinUvAuthToken;
use keyroost_ctap::cred_mgmt::{Credential, CredsMetadata, RelyingParty};
use keyroost_ctap::{AuthenticatorInfo, CtapHidDevice, InitResponse};
use keyroost_hid::HidDevice;

const PROFILES: u8 = 100;

#[derive(Default)]
struct SecurityKeysState {
    devices: Vec<HidDevice>,
    selected: Option<usize>,
    /// CTAP info for `selected`, fetched lazily after selection.
    info: Option<AuthenticatorInfo>,
    init: Option<InitResponse>,
    /// User-facing error from the last enumeration / open / GetInfo call.
    error: Option<String>,
    /// Live PIN entry field (cleared after submit).
    pin_input: String,
    /// Active unlocked session: token + cached resident credentials.
    session: Option<UnlockedSession>,
    /// Change-PIN modal state.
    change_pin: ChangePinDialog,
    /// Reset-confirmation modal state.
    reset: ResetDialog,
}

/// State for the "reset key" confirmation. Reset wipes all credentials and the
/// PIN, so the user must type a confirmation word and then touch the key.
#[derive(Default)]
struct ResetDialog {
    open: bool,
    /// Typed confirmation (`reset` required to enable the button).
    confirm_input: String,
}

struct UnlockedSession {
    token: PinUvAuthToken,
    metadata: CredsMetadata,
    rps: Vec<(RelyingParty, Vec<Credential>)>,
}

#[derive(Default)]
struct ChangePinDialog {
    /// Whether the inline PIN form is expanded.
    open: bool,
    old: String,
    new: String,
    /// Confirmation field, used only when *setting* a first-time PIN.
    confirm: String,
}

/// State for the OATH (TOTP) pane. The applet is driven over PC/SC, so a
/// "reader name" identifies the key rather than a hidraw path.
#[derive(Default)]
struct OathState {
    /// Credentials listed from the selected key, with their freshly-computed code.
    creds: Vec<OathRow>,
    /// True when the selected applet is password-protected and not yet unlocked.
    locked: bool,
    /// Password entry field (cleared after an unlock attempt).
    password_input: String,
    /// User-facing error/status from the last OATH operation.
    error: Option<String>,
    /// True once a list has been fetched for the current selection.
    loaded: bool,
    /// "Add credential" dialog state.
    add: OathAddDialog,
    /// Credential name awaiting a delete confirmation, if any.
    confirm_delete: Option<String>,
}

/// One credential row in the OATH pane: its stored name and the last code we
/// computed for it (empty until "Show code" / refresh).
struct OathRow {
    name: String,
    code: Option<String>,
}

/// "Add credential" form state for the OATH pane.
#[derive(Default)]
struct OathAddDialog {
    open: bool,
    name: String,
    /// Base32 secret (entered masked).
    secret: String,
    /// True = TOTP, false = HOTP.
    totp: bool,
    require_touch: bool,
}

/// State for the OpenPGP pane. Like OATH, the applet is driven over PC/SC, so a
/// reader name identifies the card.
#[derive(Default)]
struct OpenPgpState {
    /// Last status read from the selected card.
    status: Option<keyroost_transport::OpenPgpStatus>,
    /// User-facing error from the last operation.
    error: Option<String>,
    /// Success/info line from the last write operation.
    notice: Option<String>,
    /// True once a status has been fetched for the current selection.
    loaded: bool,
    /// Admin PIN (PW3) entry, used for every write op. Cleared after use.
    admin_pin: String,
    /// Cardholder-name entry.
    name_input: String,
    /// Public-key-URL entry.
    url_input: String,
    /// Slot selected in the generate-key control.
    gen_slot: OpenPgpSlotSel,
    /// Generate-key confirmation modal state.
    confirm_generate: bool,
    /// Slot selected in the import-key control.
    import_slot: OpenPgpSlotSel,
    /// Path to an RSA key file for import-from-file (text-entered).
    import_path: String,
    /// Import confirmation modal: the chosen key source (modal open iff `Some`).
    confirm_import: Option<ImportSource>,
    /// Reset confirmation modal: typed-`reset` text (modal open iff `Some`).
    confirm_reset: Option<String>,
}

/// Where an OpenPGP key import gets its key material. Mirrors the CLI's
/// `--generate` / `--in <FILE>` choice.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ImportSource {
    /// Generate a fresh RSA-2048 key on the host.
    Generate,
    /// Load an RSA-2048 key from a file (PKCS#1/PKCS#8, PEM or DER).
    FromFile,
}

/// Which key slot a GUI generate targets. Mirrors the CLI's slot choice.
#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum OpenPgpSlotSel {
    #[default]
    Sign,
    Decrypt,
    Auth,
}

impl OpenPgpSlotSel {
    fn to_crt(self) -> keyroost_transport::KeyCrt {
        match self {
            OpenPgpSlotSel::Sign => keyroost_transport::KeyCrt::Sign,
            OpenPgpSlotSel::Decrypt => keyroost_transport::KeyCrt::Decrypt,
            OpenPgpSlotSel::Auth => keyroost_transport::KeyCrt::Auth,
        }
    }
    fn label(self) -> &'static str {
        match self {
            OpenPgpSlotSel::Sign => "signature",
            OpenPgpSlotSel::Decrypt => "decryption",
            OpenPgpSlotSel::Auth => "authentication",
        }
    }
}

/// State for the PIV pane. Read-only today: a status snapshot driven over PC/SC,
/// keyed (like OATH/OpenPGP) by the selected device's reader name.
#[derive(Default)]
struct PivState {
    /// Last status read from the selected card.
    status: Option<keyroost_transport::PivStatus>,
    /// User-facing error from the last read.
    error: Option<String>,
    /// True once a status has been fetched for the current selection.
    loaded: bool,
}

/// A unit of work applied back to the [`App`] on the UI thread once a background
/// job finishes. Returned by the job closure and run inside `update()`.
type ApplyFn = Box<dyn FnOnce(&mut App) + Send>;
/// A background job: blocking device I/O that yields an [`ApplyFn`].
type Job = Box<dyn FnOnce() -> ApplyFn + Send>;

/// A single background worker thread. Device calls (CTAP / OATH over PC/SC) can
/// block for seconds — a touch-required credential or a 30s Reset window — so we
/// run them off the egui frame thread and apply their results back on the UI
/// thread. One thread keeps device access serialized (no concurrent card I/O).
struct Worker {
    job_tx: std::sync::mpsc::Sender<Job>,
    result_rx: std::sync::mpsc::Receiver<ApplyFn>,
}

impl Worker {
    fn spawn(ctx: egui::Context) -> Self {
        let (job_tx, job_rx) = std::sync::mpsc::channel::<Job>();
        let (result_tx, result_rx) = std::sync::mpsc::channel::<ApplyFn>();
        std::thread::Builder::new()
            .name("keyroost-worker".into())
            .spawn(move || {
                while let Ok(job) = job_rx.recv() {
                    let apply = job();
                    if result_tx.send(apply).is_err() {
                        break; // UI gone
                    }
                    ctx.request_repaint(); // wake the frame loop to apply it
                }
            })
            .expect("spawn worker thread");
        Worker { job_tx, result_rx }
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1180.0, 760.0])
            .with_min_inner_size([900.0, 560.0])
            .with_title("keyroost"),
        ..Default::default()
    };
    eframe::run_native(
        "keyroost",
        options,
        Box::new(|cc| {
            // Register IBM Plex Sans + JetBrains Mono so the redesign's type
            // weights resolve. (Vendored under assets/.)
            theme::install_fonts(&cc.egui_ctx);
            // Restore the persisted theme (mode + accent), defaulting to the
            // refined dark + blue accent the prototype ships with.
            let (mode, accent_idx) = cc
                .storage
                .map(|s| {
                    let mode = if s.get_string("mode").as_deref() == Some("light") {
                        Mode::Light
                    } else {
                        Mode::Dark
                    };
                    let accent_idx = s
                        .get_string("accent")
                        .and_then(|v| v.parse::<usize>().ok())
                        .unwrap_or(0)
                        .min(Palette::ACCENTS.len() - 1);
                    (mode, accent_idx)
                })
                .unwrap_or((Mode::Dark, 0));
            Palette::new(mode, Palette::ACCENTS[accent_idx]).apply(&cc.egui_ctx, mode);
            let app = App {
                mode,
                accent_idx,
                worker: Some(Worker::spawn(cc.egui_ctx.clone())),
                ..Default::default()
            };
            Ok(Box::new(app))
        }),
    )
}

#[derive(Default)]
struct App {
    /// Active PC/SC session, if any.
    session: Option<Session>,
    /// Last device info read.
    info: Option<DeviceInfo>,
    /// Whether the session has been authenticated.
    authenticated: bool,
    /// Customer key text the user typed.
    customer_key_input: String,
    /// Treat customer_key_input as hex vs ASCII.
    customer_key_hex: bool,
    /// Currently selected Molto2 profile slot (0..PROFILES-1).
    slot: u8,
    /// Draft of the form fields for `selected` (per-slot; cleared on slot switch).
    draft: Draft,
    /// Rolling log of operations (newest last).
    log: Vec<LogLine>,
    /// otpauth:// import dialog state.
    import_dialog: ImportDialog,
    /// Bulk-import dialog state.
    bulk_dialog: BulkDialog,
    /// Unified device list (physical keys + Molto2 tokens), most recent scan.
    devices: Vec<UiDevice>,
    /// Selected device id — stable across refreshes so the pane doesn't jump
    /// when an *unrelated* key is plugged or unplugged.
    selected_device: Option<DeviceId>,
    /// Which capability pane is showing for the selected key.
    cap_tab: CapTab,
    /// Error from the last device enumeration, surfaced in the sidebar.
    devices_error: Option<String>,
    /// True once the first automatic device scan has been kicked off.
    scanned: bool,
    /// Sidebar filter text (filters the visible device list by vendor/model).
    filter: String,
    /// FIDO security-key view state (CTAP info, PIN session, errors).
    security_keys: SecurityKeysState,
    /// OATH (TOTP) view state.
    oath: OathState,
    /// OpenPGP view state.
    openpgp: OpenPgpState,
    /// PIV read-only status view state.
    piv: PivState,
    /// Dark / light theme (persisted via eframe storage).
    mode: Mode,
    /// Accent index into `Palette::ACCENTS` (persisted).
    accent_idx: usize,
    /// Whether the activity-log drawer is open.
    log_open: bool,
    /// Open help topic id, or `None` when the popover is closed.
    help_open: Option<&'static str>,
    /// Anchor point (the clicked "?" button's left-bottom) for the popover.
    help_anchor: egui::Pos2,
    /// OATH "copied" flash: (credential name, expiry unix-secs). Cleared after.
    copied: Option<(String, f64)>,
    /// Whether the OATH pane has auto-attempted a read for the current selection
    /// (so a hard error doesn't retry every frame). Reset on selection change.
    oath_tried: bool,
    /// Same guard for the PIV pane's auto-read.
    piv_tried: bool,
    /// True while the Molto2 factory-reset confirmation is showing.
    molto_reset_confirm: bool,
    /// Background worker for blocking device I/O. `None` only in tests.
    worker: Option<Worker>,
    /// Number of in-flight background jobs. While >0 the UI shows a spinner and
    /// disables actions that would issue overlapping device I/O.
    busy_jobs: u32,
    /// Human-readable description of what the worker is currently doing.
    busy_label: Option<String>,
}

#[derive(Default)]
struct Draft {
    /// 1..=12 byte title.
    title: String,
    /// Base32-encoded TOTP secret.
    secret_base32: String,
    algorithm: AlgoChoice,
    digits: DigitsChoice,
    time_step: StepChoice,
    display_timeout: TimeoutChoice,
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum AlgoChoice {
    #[default]
    Sha1,
    Sha256,
}
impl AlgoChoice {
    fn to_proto(self) -> HmacAlgo {
        match self {
            AlgoChoice::Sha1 => HmacAlgo::Sha1,
            AlgoChoice::Sha256 => HmacAlgo::Sha256,
        }
    }
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum DigitsChoice {
    Four,
    #[default]
    Six,
    Eight,
    Ten,
}
impl DigitsChoice {
    fn to_proto(self) -> OtpDigits {
        match self {
            DigitsChoice::Four => OtpDigits::Four,
            DigitsChoice::Six => OtpDigits::Six,
            DigitsChoice::Eight => OtpDigits::Eight,
            DigitsChoice::Ten => OtpDigits::Ten,
        }
    }
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum StepChoice {
    #[default]
    S30,
    S60,
}
impl StepChoice {
    fn to_proto(self) -> TimeStep {
        match self {
            StepChoice::S30 => TimeStep::Seconds30,
            StepChoice::S60 => TimeStep::Seconds60,
        }
    }
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum TimeoutChoice {
    S15,
    #[default]
    S30,
    S60,
    S120,
}
impl TimeoutChoice {
    fn to_proto(self) -> DisplayTimeout {
        match self {
            TimeoutChoice::S15 => DisplayTimeout::Sec15,
            TimeoutChoice::S30 => DisplayTimeout::Sec30,
            TimeoutChoice::S60 => DisplayTimeout::Sec60,
            TimeoutChoice::S120 => DisplayTimeout::Sec120,
        }
    }
}

#[derive(Default)]
struct ImportDialog {
    open: bool,
    uri: String,
}

#[derive(Default)]
struct BulkDialog {
    open: bool,
    path: String,
    /// Successfully parsed entries (cleared on each load).
    entries: Vec<keyroost_import::BulkEntry>,
    /// Last load error message, if any.
    error: Option<String>,
    /// Starting slot for programming.
    start: u8,
    /// Display timeout applied to every entry.
    display_timeout: TimeoutChoice,
    /// Password for encrypted Aegis vaults (revealed when the loader detects one).
    password: String,
    /// True once the loader has seen an encrypted vault at the current path.
    needs_password: bool,
}

struct LogLine {
    severity: Severity,
    text: String,
}

#[derive(Clone, Copy)]
enum Severity {
    Info,
    Ok,
    Warn,
    Err,
}

impl App {
    /// Queue a blocking device job on the worker thread. `label` describes it for
    /// the busy indicator; `job` runs off-thread and returns a closure applied
    /// back to `self` on the UI thread. Falls back to running inline if there's
    /// no worker (tests).
    fn spawn_job<F>(&mut self, label: impl Into<String>, job: F)
    where
        F: FnOnce() -> ApplyFn + Send + 'static,
    {
        // Serialize device access: ignore a new job while one is in flight rather
        // than queueing overlapping card I/O behind a click the user can't see
        // landed. (A single worker thread would serialize anyway, but this also
        // stops a growing backlog of duplicate refreshes from rapid clicks.)
        if self.busy() {
            return;
        }
        match &self.worker {
            Some(worker) => {
                self.busy_jobs += 1;
                self.busy_label = Some(label.into());
                if worker.job_tx.send(Box::new(job)).is_err() {
                    // Worker died; undo the bookkeeping so the UI doesn't hang.
                    self.busy_jobs -= 1;
                    self.busy_label = None;
                }
            }
            None => {
                let apply = job();
                apply(self);
            }
        }
    }

    /// Apply any finished background jobs. Called once per frame from `update()`.
    fn drain_worker(&mut self) {
        let applies: Vec<ApplyFn> = match &self.worker {
            Some(w) => w.result_rx.try_iter().collect(),
            None => Vec::new(),
        };
        for apply in applies {
            // Decrement *before* applying so an apply closure that chains another
            // job (e.g. refresh-readers → probe-lock) isn't blocked by the busy
            // guard in `spawn_job`.
            self.busy_jobs = self.busy_jobs.saturating_sub(1);
            if self.busy_jobs == 0 {
                self.busy_label = None;
            }
            apply(self);
        }
    }

    /// True while any background device job is in flight.
    fn busy(&self) -> bool {
        self.busy_jobs > 0
    }

    fn log(&mut self, severity: Severity, text: impl Into<String>) {
        self.log.push(LogLine {
            severity,
            text: text.into(),
        });
        // Keep the log bounded; oldest entries are least interesting.
        if self.log.len() > 200 {
            let overflow = self.log.len() - 200;
            self.log.drain(0..overflow);
        }
    }

    fn customer_key_bytes(&self) -> Result<Vec<u8>, String> {
        if self.customer_key_input.is_empty() {
            return Ok(DEFAULT_CUSTOMER_KEY.to_vec());
        }
        if self.customer_key_hex {
            keyroost_proto::codec::hex_decode(&self.customer_key_input)
                .map_err(|e| format!("invalid customer key hex: {}", e))
        } else {
            Ok(self.customer_key_input.as_bytes().to_vec())
        }
    }

    fn authenticate(&mut self) {
        let key = match self.customer_key_bytes() {
            Ok(k) => k,
            Err(e) => {
                self.log(Severity::Err, e);
                return;
            }
        };
        let Some(s) = self.session.as_mut() else {
            self.log(Severity::Warn, "not connected");
            return;
        };
        match s.authenticate(&key) {
            Ok(()) => {
                self.authenticated = true;
                self.log(Severity::Ok, "authenticated");
            }
            Err(TransportError::AuthFailed { tries_remaining }) => {
                self.log(
                    Severity::Err,
                    format!(
                        "authentication failed (wrong customer key); {} attempt(s) left",
                        tries_remaining
                    ),
                );
            }
            Err(e) => self.log(Severity::Err, format!("auth failed: {}", e)),
        }
    }

    fn apply_draft(&mut self) {
        if !self.ensure_auth() {
            return;
        }
        let secret = match keyroost_proto::codec::base32_decode(&self.draft.secret_base32) {
            Ok(s) if !s.is_empty() && s.len() <= 63 => s,
            Ok(s) => {
                self.log(
                    Severity::Err,
                    format!("seed must decode to 1..=63 bytes (got {})", s.len()),
                );
                return;
            }
            Err(e) => {
                self.log(Severity::Err, format!("seed base32 invalid: {}", e));
                return;
            }
        };
        let title = self.draft.title.trim().to_owned();
        if title.is_empty() || title.len() > 12 {
            self.log(Severity::Err, "title must be 1..=12 bytes");
            return;
        }
        let cfg = ProfileConfig {
            display_timeout: self.draft.display_timeout.to_proto(),
            algorithm: self.draft.algorithm.to_proto(),
            digits: self.draft.digits.to_proto(),
            time_step: self.draft.time_step.to_proto(),
            utc_time: unix_now(),
        };
        let p = self.slot;
        let s = self.session.as_mut().expect("auth implies session");
        if let Err(e) = s.set_seed(p, &secret) {
            self.log(Severity::Err, format!("set_seed #{}: {}", p, e));
            return;
        }
        if let Err(e) = s.set_title(p, &title) {
            self.log(Severity::Err, format!("set_title #{}: {}", p, e));
            return;
        }
        if let Err(e) = s.set_config(p, &cfg) {
            self.log(Severity::Err, format!("set_config #{}: {}", p, e));
            return;
        }
        self.log(Severity::Ok, format!("profile #{} written", p));
    }

    fn sync_time_selected(&mut self) {
        if !self.ensure_auth() {
            return;
        }
        let p = self.slot;
        let s = self.session.as_mut().expect("auth implies session");
        match s.sync_time(p, unix_now()) {
            Ok(()) => self.log(Severity::Ok, format!("time synced on #{}", p)),
            Err(e) => self.log(Severity::Err, format!("sync_time #{}: {}", p, e)),
        }
    }

    fn sync_time_all(&mut self) {
        if !self.ensure_auth() {
            return;
        }
        let s = self.session.as_mut().expect("auth implies session");
        let mut ok = 0;
        let mut fail = 0;
        for p in 0..PROFILES {
            match s.sync_time(p, unix_now()) {
                Ok(()) => ok += 1,
                Err(_) => fail += 1,
            }
        }
        let sev = if fail == 0 {
            Severity::Ok
        } else {
            Severity::Warn
        };
        self.log(sev, format!("time-sync-all: {} ok, {} failed", ok, fail));
    }

    fn import_otpauth(&mut self) {
        let uri = self.import_dialog.uri.trim().to_owned();
        let parsed = match parse_otpauth(&uri) {
            Ok(p) => p,
            Err(e) => {
                self.log(Severity::Err, format!("import: {}", e));
                return;
            }
        };
        // Push parsed fields into the draft so the user can review before pushing.
        self.draft.title = parsed.suggested_title();
        // Show the original base32 from the URI rather than re-encoding the bytes.
        self.draft.secret_base32 = uri
            .find("secret=")
            .map(|i| {
                let rest = &uri[i + 7..];
                let end = rest.find('&').unwrap_or(rest.len());
                rest[..end].to_owned()
            })
            .unwrap_or_default();
        self.draft.algorithm = match parsed.algorithm {
            HmacAlgo::Sha1 => AlgoChoice::Sha1,
            HmacAlgo::Sha256 => AlgoChoice::Sha256,
        };
        self.draft.digits = match parsed.digits {
            OtpDigits::Four => DigitsChoice::Four,
            OtpDigits::Six => DigitsChoice::Six,
            OtpDigits::Eight => DigitsChoice::Eight,
            OtpDigits::Ten => DigitsChoice::Ten,
        };
        self.draft.time_step = match parsed.time_step {
            TimeStep::Seconds30 => StepChoice::S30,
            TimeStep::Seconds60 => StepChoice::S60,
        };
        self.log(
            Severity::Info,
            format!(
                "imported draft for #{} from URI; review and click Write profile",
                self.slot
            ),
        );
        self.import_dialog.open = false;
        self.import_dialog.uri.clear();
    }

    fn factory_reset(&mut self) {
        let Some(s) = self.session.as_mut() else {
            self.log(Severity::Warn, "not connected");
            return;
        };
        match s.factory_reset() {
            Ok(()) => self.log(
                Severity::Warn,
                "factory-reset requested. Confirm with the ▲ button on the device.",
            ),
            Err(e) => self.log(Severity::Err, format!("factory_reset: {}", e)),
        }
    }

    fn bulk_load(&mut self) {
        let path = self.bulk_dialog.path.trim().to_owned();
        if path.is_empty() {
            self.bulk_dialog.error = Some("enter a file path first".into());
            return;
        }
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => {
                self.bulk_dialog.error = Some(format!("read failed: {}", e));
                return;
            }
        };

        // If this looks like an encrypted Aegis vault, ask for a password first
        // (unless the user has already typed one).
        let is_encrypted_aegis = keyroost_import::aegis::is_encrypted(&text).unwrap_or(false);
        let final_text = if is_encrypted_aegis {
            self.bulk_dialog.needs_password = true;
            if self.bulk_dialog.password.is_empty() {
                self.bulk_dialog.entries.clear();
                self.bulk_dialog.error =
                    Some("encrypted Aegis vault — enter password and click Load again".into());
                return;
            }
            match keyroost_import::aegis::decrypt(&text, self.bulk_dialog.password.as_bytes()) {
                Ok(plaintext) => plaintext,
                Err(e) => {
                    self.bulk_dialog.entries.clear();
                    self.bulk_dialog.error = Some(format!("decrypt: {}", e));
                    return;
                }
            }
        } else {
            self.bulk_dialog.needs_password = false;
            text
        };

        match keyroost_import::parse_bulk_any(&final_text) {
            Ok(entries) => {
                self.bulk_dialog.entries = entries;
                self.bulk_dialog.error = None;
                self.bulk_dialog.password.clear();
                self.log(
                    Severity::Info,
                    format!(
                        "loaded {} entries from {}",
                        self.bulk_dialog.entries.len(),
                        path
                    ),
                );
            }
            Err(e) => {
                self.bulk_dialog.entries.clear();
                self.bulk_dialog.error = Some(e.to_string());
            }
        }
    }

    fn bulk_apply(&mut self) {
        if !self.ensure_auth() {
            return;
        }
        if self.bulk_dialog.entries.is_empty() {
            self.log(Severity::Warn, "no entries loaded");
            return;
        }
        let start = self.bulk_dialog.start;
        let n = self.bulk_dialog.entries.len();
        let last = (start as usize).saturating_add(n);
        if last > PROFILES as usize {
            self.log(
                Severity::Err,
                format!(
                    "{} entries starting at #{} would overflow slot 99 (would need #{})",
                    n,
                    start,
                    last - 1
                ),
            );
            return;
        }
        let timeout = self.bulk_dialog.display_timeout.to_proto();
        let mut ok = 0;
        let mut fail = 0;
        for (i, entry) in self.bulk_dialog.entries.clone().into_iter().enumerate() {
            let p = start + i as u8;
            let title = entry.suggested_title();
            if title.is_empty() {
                self.log(Severity::Warn, format!("#{}: no title; skipping", p));
                fail += 1;
                continue;
            }
            let s = self.session.as_mut().expect("auth implies session");
            if let Err(e) = s.set_seed(p, &entry.secret) {
                self.log(Severity::Err, format!("#{} set_seed: {}", p, e));
                fail += 1;
                continue;
            }
            if let Err(e) = s.set_title(p, &title) {
                self.log(Severity::Err, format!("#{} set_title: {}", p, e));
                fail += 1;
                continue;
            }
            if let Err(e) = s.set_config(p, &entry.to_profile_config(unix_now(), timeout)) {
                self.log(Severity::Err, format!("#{} set_config: {}", p, e));
                fail += 1;
                continue;
            }
            ok += 1;
        }
        let sev = if fail == 0 {
            Severity::Ok
        } else {
            Severity::Warn
        };
        self.log(sev, format!("bulk import: {} ok, {} failed", ok, fail));
        if fail == 0 {
            self.bulk_dialog.open = false;
        }
    }

    fn ensure_auth(&mut self) -> bool {
        if self.authenticated {
            return true;
        }
        self.log(
            Severity::Warn,
            "not authenticated; click Authenticate first",
        );
        false
    }

    /// Open the currently-selected hidraw device, run CTAPHID_INIT and
    /// authenticatorGetInfo, and cache the result. Blocks the UI briefly —
    /// CTAP GetInfo typically completes in a few milliseconds.
    fn fetch_selected_info(&mut self) {
        self.security_keys.info = None;
        self.security_keys.init = None;
        self.security_keys.error = None;
        let Some(path) = self.selected_fido_path() else {
            return;
        };
        self.spawn_job("Reading key info\u{2026}", move || {
            // Off-thread: open the hidraw, run INIT + GetInfo.
            let outcome = match CtapHidDevice::open(&path) {
                Ok((mut hid, init)) => {
                    let info = if init.supports_cbor() {
                        Some(keyroost_ctap::get_info(&mut hid).map_err(|e| e.to_string()))
                    } else {
                        None
                    };
                    Ok((init, info))
                }
                Err(e) => Err(format!(
                    "could not open {}: {} (have you installed udev/70-keyroost-fido.rules?)",
                    path.display(),
                    e
                )),
            };
            // Back on the UI thread: store the results.
            Box::new(move |app: &mut App| match outcome {
                Ok((init, info)) => {
                    app.security_keys.init = Some(init);
                    match info {
                        Some(Ok(info)) => app.security_keys.info = Some(info),
                        Some(Err(e)) => {
                            app.security_keys.error = Some(format!("GetInfo failed: {}", e))
                        }
                        None => {}
                    }
                }
                Err(e) => app.security_keys.error = Some(e),
            })
        });
    }

    /// Open the selected hidraw, run the PIN exchange, and populate the
    /// session with metadata + credential listing. Errors land in
    /// `security_keys.error`.
    fn try_unlock(&mut self) {
        let Some(path) = self.selected_fido_path() else {
            return;
        };
        let pin = std::mem::take(&mut self.security_keys.pin_input);
        if pin.is_empty() {
            self.security_keys.error = Some("PIN is empty".into());
            return;
        }
        self.spawn_job("Unlocking\u{2026} (enter PIN / touch)", move || {
            let result = Self::open_and_unlock(&path, &pin).map_err(|e| e.to_string());
            Box::new(move |app: &mut App| match result {
                Ok(sess) => {
                    app.security_keys.session = Some(sess);
                    app.security_keys.error = None;
                }
                Err(e) => app.security_keys.error = Some(format!("unlock failed: {}", e)),
            })
        });
    }

    fn open_and_unlock(
        path: &std::path::Path,
        pin: &str,
    ) -> Result<UnlockedSession, Box<dyn std::error::Error>> {
        let (mut dev, init) = CtapHidDevice::open(path)?;
        if !init.supports_cbor() {
            return Err("device is U2F-only".into());
        }
        let info = keyroost_ctap::get_info(&mut dev)?;
        let token = keyroost_ctap::client_pin::get_pin_uv_auth_token(
            &mut dev,
            pin,
            &info,
            keyroost_ctap::client_pin::permissions::CREDENTIAL_MANAGEMENT,
        )?;
        // Hand the manager a clone and keep `token` for the cached session; the
        // token stays valid for the device session, so this avoids a redundant
        // second PIN/ECDH exchange just to rebuild it.
        let mut mgr =
            keyroost_ctap::cred_mgmt::CredentialManager::new(&mut dev, token.clone(), &info)?;
        let metadata = mgr.metadata()?;
        let parties = mgr.list_relying_parties()?;
        let mut rps = Vec::with_capacity(parties.len());
        for rp in parties {
            let creds = mgr.list_credentials(&rp.rp_id_hash).unwrap_or_default();
            rps.push((rp, creds));
        }
        Ok(UnlockedSession {
            token,
            metadata,
            rps,
        })
    }

    fn lock_session(&mut self) {
        self.security_keys.session = None;
        self.security_keys.pin_input.clear();
    }

    fn refresh_credentials(&mut self) {
        let Some(path) = self.selected_fido_path() else {
            return;
        };
        let Some(session) = self.security_keys.session.take() else {
            return;
        };
        let token = session.token;
        self.spawn_job("Refreshing credentials\u{2026}", move || {
            let result = Self::refresh_with_token(&path, token).map_err(|e| e.to_string());
            Box::new(move |app: &mut App| match result {
                Ok(fresh) => app.security_keys.session = Some(fresh),
                Err(e) => app.security_keys.error = Some(format!("refresh failed: {}", e)),
            })
        });
    }

    fn refresh_with_token(
        path: &std::path::Path,
        token: PinUvAuthToken,
    ) -> Result<UnlockedSession, Box<dyn std::error::Error>> {
        let (mut dev, _) = CtapHidDevice::open(path)?;
        let info = keyroost_ctap::get_info(&mut dev)?;
        let mut mgr =
            keyroost_ctap::cred_mgmt::CredentialManager::new(&mut dev, token.clone(), &info)?;
        let metadata = mgr.metadata()?;
        let parties = mgr.list_relying_parties()?;
        let mut rps = Vec::with_capacity(parties.len());
        for rp in parties {
            let creds = mgr.list_credentials(&rp.rp_id_hash).unwrap_or_default();
            rps.push((rp, creds));
        }
        Ok(UnlockedSession {
            token,
            metadata,
            rps,
        })
    }

    fn delete_credential(&mut self, cred_id: Vec<u8>) {
        let Some(path) = self.selected_fido_path() else {
            return;
        };
        let Some(session) = self.security_keys.session.as_ref() else {
            return;
        };
        let token = session.token.clone();
        // The refresh after delete needs its own token; clone for the chained op.
        let token_refresh = token.clone();
        self.spawn_job("Deleting credential\u{2026}", move || {
            // Delete, then re-list in the same job so the UI updates atomically.
            let result = Self::try_delete(&path, token, &cred_id)
                .and_then(|()| Self::refresh_with_token(&path, token_refresh))
                .map_err(|e| e.to_string());
            Box::new(move |app: &mut App| match result {
                Ok(fresh) => {
                    app.security_keys.session = Some(fresh);
                    app.security_keys.error = None;
                }
                Err(e) => app.security_keys.error = Some(format!("delete failed: {}", e)),
            })
        });
    }

    fn try_delete(
        path: &std::path::Path,
        token: PinUvAuthToken,
        cred_id: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut dev, _) = CtapHidDevice::open(path)?;
        let info = keyroost_ctap::get_info(&mut dev)?;
        let mut mgr = keyroost_ctap::cred_mgmt::CredentialManager::new(&mut dev, token, &info)?;
        mgr.delete(cred_id)?;
        Ok(())
    }

    fn submit_change_pin(&mut self) {
        let Some(path) = self.selected_fido_path() else {
            return;
        };
        let old = std::mem::take(&mut self.security_keys.change_pin.old);
        let new = std::mem::take(&mut self.security_keys.change_pin.new);
        if old.is_empty() || new.is_empty() {
            self.security_keys.error = Some("both PIN fields are required".into());
            return;
        }
        self.spawn_job("Changing PIN\u{2026} (touch)", move || {
            let result = Self::try_change_pin(&path, &old, &new).map_err(|e| e.to_string());
            Box::new(move |app: &mut App| match result {
                Ok(()) => {
                    app.security_keys.change_pin.open = false;
                    app.security_keys.error = None;
                    // Force re-unlock with the new PIN.
                    app.lock_session();
                }
                Err(e) => app.security_keys.error = Some(format!("change PIN failed: {}", e)),
            })
        });
    }

    fn try_change_pin(
        path: &std::path::Path,
        old: &str,
        new: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut dev, _) = CtapHidDevice::open(path)?;
        keyroost_ctap::client_pin::change_pin(&mut dev, old, new)?;
        Ok(())
    }

    /// Set a first-time PIN on a key that has none (CTAP setPIN). Validates that
    /// the two entries match and meet the 4-char minimum, then re-reads info so
    /// the status flips to "PIN set".
    fn submit_set_pin(&mut self) {
        let Some(path) = self.selected_fido_path() else {
            return;
        };
        let new = std::mem::take(&mut self.security_keys.change_pin.new);
        let confirm = std::mem::take(&mut self.security_keys.change_pin.confirm);
        if new.chars().count() < 4 {
            self.security_keys.error = Some("PIN must be at least 4 characters".into());
            return;
        }
        if new != confirm {
            self.security_keys.error = Some("the two PINs don't match".into());
            return;
        }
        self.spawn_job("Setting PIN\u{2026} (touch the key)", move || {
            let result = (|| -> Result<(), String> {
                let (mut dev, _) = CtapHidDevice::open(&path).map_err(|e| e.to_string())?;
                keyroost_ctap::client_pin::set_pin(&mut dev, &new).map_err(|e| e.to_string())
            })();
            Box::new(move |app: &mut App| match result {
                Ok(()) => {
                    app.security_keys.change_pin = ChangePinDialog::default();
                    app.security_keys.error = None;
                    app.fetch_selected_info();
                }
                Err(e) => app.security_keys.error = Some(format!("set PIN failed: {e}")),
            })
        });
    }

    fn selected_fido_path(&self) -> Option<std::path::PathBuf> {
        self.selected_device().and_then(|d| d.hid_path.clone())
    }

    /// Wipe the selected key (authenticatorReset). Runs on the worker thread —
    /// the card needs a touch within ~30s, which the worker keeps off the UI
    /// frame. On success the cached session and CTAP info are cleared.
    fn submit_reset(&mut self) {
        let Some(path) = self.selected_fido_path() else {
            return;
        };
        self.spawn_job("Resetting key\u{2026} (touch now)", move || {
            let result = (|| -> Result<(), String> {
                let (mut dev, _) = CtapHidDevice::open(&path).map_err(|e| e.to_string())?;
                keyroost_ctap::reset(&mut dev).map_err(|e| e.to_string())
            })();
            Box::new(move |app: &mut App| match result {
                Ok(()) => {
                    app.security_keys.session = None;
                    app.security_keys.info = None;
                    app.security_keys.error = None;
                    // Re-read info so the PIN status reflects the wipe.
                    app.fetch_selected_info();
                }
                Err(e) => {
                    let msg = if e.contains("NOT_ALLOWED") || e.contains("0x30") {
                        "This key refused the reset. Most security keys (YubiKey \
                         included) only allow a FIDO reset within about 10 seconds \
                         of being plugged in. Unplug the key, plug it back in, then \
                         click \u{201C}Reset key\u{201D} again right away."
                            .to_string()
                    } else {
                        format!("reset failed: {e}")
                    };
                    app.security_keys.error = Some(msg);
                }
            })
        });
    }

    fn selected_oath_reader(&self) -> Option<String> {
        self.selected_device().and_then(|d| d.reader.clone())
    }

    /// Off-thread helper: open `name` and unlock with `password` if protected.
    fn oath_open_unlock(
        name: &str,
        password: &str,
    ) -> Result<keyroost_transport::OathSession, TransportError> {
        let mut session = keyroost_transport::OathSession::open(name)?;
        if session.password_required() {
            session.unlock(password)?;
        }
        Ok(session)
    }

    /// Off-thread helper: list credentials and compute each current TOTP.
    fn oath_list_rows(
        session: &mut keyroost_transport::OathSession,
    ) -> Result<Vec<OathRow>, TransportError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut rows = Vec::new();
        for c in session.list()? {
            // A touch-required credential blocks until touched; fine off-thread.
            let code = session
                .calculate_totp(&c.name, now, 30)
                .ok()
                .map(|otp| otp.code);
            rows.push(OathRow {
                name: c.name,
                code,
            });
        }
        Ok(rows)
    }

    /// Store the outcome of an op that ends by (re)listing credentials.
    fn apply_oath_rows(app: &mut App, result: Result<Vec<OathRow>, TransportError>) {
        match result {
            Ok(rows) => {
                app.oath.creds = rows;
                app.oath.loaded = true;
                app.oath.locked = false;
                app.oath.password_input.clear();
            }
            Err(TransportError::OathPasswordRejected) => {
                app.oath.locked = true;
                app.oath.error = Some("wrong OATH password".into());
                app.oath.password_input.clear();
            }
            Err(e) => app.oath.error = Some(e.to_string()),
        }
    }

    /// List credentials on the selected key, computing each current TOTP. Unlocks
    /// first with the entered password when the applet is protected.
    fn load_oath_creds(&mut self) {
        self.oath.error = None;
        let Some(name) = self.selected_oath_reader() else {
            self.oath.error = Some("no OATH key selected".into());
            return;
        };
        let password = self.oath.password_input.clone();
        self.spawn_job("Reading OATH codes\u{2026}", move || {
            let result = Self::oath_open_unlock(&name, &password)
                .and_then(|mut session| Self::oath_list_rows(&mut session));
            Box::new(move |app: &mut App| Self::apply_oath_rows(app, result))
        });
    }

    /// Provision the credential described by the add-dialog fields.
    fn provision_oath(&mut self) {
        self.oath.error = None;
        let Some(name) = self.selected_oath_reader() else {
            self.oath.error = Some("no OATH key selected".into());
            return;
        };
        let cred_name = self.oath.add.name.trim().to_owned();
        if cred_name.is_empty() {
            self.oath.error = Some("credential name is required".into());
            return;
        }
        let secret = match keyroost_proto::codec::base32_decode(self.oath.add.secret.trim()) {
            Ok(s) if !s.is_empty() => s,
            Ok(_) => {
                self.oath.error = Some("secret is empty".into());
                return;
            }
            Err(e) => {
                self.oath.error = Some(format!("invalid base32 secret: {e}"));
                return;
            }
        };
        let oath_type = if self.oath.add.totp {
            keyroost_oath::OathType::Totp
        } else {
            keyroost_oath::OathType::Hotp
        };
        let require_touch = self.oath.add.require_touch;
        let password = self.oath.password_input.clone();
        // Clear the form now; on error the message is surfaced separately.
        self.oath.add = OathAddDialog::default();
        self.spawn_job("Adding credential\u{2026}", move || {
            let result = (|| -> Result<Vec<OathRow>, TransportError> {
                let mut session = Self::oath_open_unlock(&name, &password)?;
                session.put(&keyroost_oath::PutParams {
                    name: &cred_name,
                    secret: &secret,
                    oath_type,
                    algorithm: keyroost_oath::Algorithm::Sha1,
                    digits: 6,
                    require_touch,
                    imf: 0,
                })?;
                Self::oath_list_rows(&mut session)
            })();
            Box::new(move |app: &mut App| Self::apply_oath_rows(app, result))
        });
    }

    /// Delete the named credential (already confirmed).
    fn delete_oath(&mut self, name: &str) {
        self.oath.error = None;
        let Some(reader) = self.selected_oath_reader() else {
            self.oath.error = Some("no OATH key selected".into());
            return;
        };
        let cred_name = name.to_owned();
        let password = self.oath.password_input.clone();
        self.spawn_job("Deleting credential\u{2026}", move || {
            let result = (|| -> Result<Vec<OathRow>, TransportError> {
                let mut session = Self::oath_open_unlock(&reader, &password)?;
                session.delete(&cred_name)?;
                Self::oath_list_rows(&mut session)
            })();
            Box::new(move |app: &mut App| Self::apply_oath_rows(app, result))
        });
    }

    /// The inline "Add credential" form, shown when the add dialog is open.
    fn render_oath_add_form(&mut self, ui: &mut egui::Ui) {
        if !self.oath.add.open {
            return;
        }
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Add credential").strong());
                helper_bubble(
                    ui,
                    "The secret is sent to the key to store the credential; it is \
                     not written to disk by keyroost. Use the base32 secret from the \
                     service's enrollment (the text behind the QR code).",
                );
            });
            ui.horizontal(|ui| {
                ui.label("Name:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.oath.add.name)
                        .hint_text("issuer:account")
                        .desired_width(220.0),
                );
            });
            ui.horizontal(|ui| {
                ui.label("Secret (base32):");
                ui.add(
                    egui::TextEdit::singleline(&mut self.oath.add.secret)
                        .password(true)
                        .desired_width(220.0),
                );
            });
            ui.horizontal(|ui| {
                ui.label("Type:");
                ui.selectable_value(&mut self.oath.add.totp, true, "TOTP");
                ui.selectable_value(&mut self.oath.add.totp, false, "HOTP");
                ui.checkbox(&mut self.oath.add.require_touch, "Require touch");
            });
            ui.horizontal(|ui| {
                if ui.button("Save").clicked() {
                    self.provision_oath();
                }
                if ui.button("Cancel").clicked() {
                    self.oath.add = OathAddDialog::default();
                }
            });
        });
    }

    /// Modal confirmation before deleting a credential (irreversible).
    fn render_oath_delete_confirm(&mut self, ctx: &egui::Context) {
        let Some(name) = self.oath.confirm_delete.clone() else {
            return;
        };
        let mut decision: Option<bool> = None;
        egui::Window::new("Delete credential?")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label(format!(
                    "Permanently delete \u{201c}{name}\u{201d} from this key? \
                     This cannot be undone."
                ));
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button("Delete").clicked() {
                        decision = Some(true);
                    }
                    if ui.button("Cancel").clicked() {
                        decision = Some(false);
                    }
                });
            });
        match decision {
            Some(true) => {
                self.oath.confirm_delete = None;
                self.delete_oath(&name);
            }
            Some(false) => self.oath.confirm_delete = None,
            None => {}
        }
    }

    /// Reset confirmation: wiping a key is irreversible, so require the user to
    /// type `reset` before the button activates, then a physical touch.
    fn render_reset_dialog(&mut self, ctx: &egui::Context) {
        if !self.security_keys.reset.open {
            return;
        }
        let label = self
            .security_keys
            .selected
            .and_then(|i| self.security_keys.devices.get(i))
            .map(|d| d.product_name.clone())
            .unwrap_or_else(|| "this key".into());

        let mut window_open = true;
        let mut do_reset = false;
        let mut cancel = false;
        egui::Window::new("Reset security key?")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .open(&mut window_open)
            .show(ctx, |ui| {
                ui.colored_label(
                    egui::Color32::from_rgb(220, 110, 110),
                    format!("This wipes ALL credentials and the PIN on {label}."),
                );
                ui.label("This cannot be undone. The key must be freshly plugged in,");
                ui.label("and you'll need to touch it within ~30 seconds.");
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.label("Type \u{201c}reset\u{201d} to confirm:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.security_keys.reset.confirm_input)
                            .desired_width(120.0),
                    );
                });
                ui.add_space(6.0);
                let armed = self.security_keys.reset.confirm_input.trim() == "reset";
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(armed, egui::Button::new("Reset key"))
                        .clicked()
                    {
                        do_reset = true;
                    }
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                });
            });
        if do_reset {
            self.security_keys.reset = ResetDialog::default();
            self.submit_reset();
        } else if cancel || !window_open {
            // Cancel button, or the window's [x] close.
            self.security_keys.reset = ResetDialog::default();
        }
    }

    fn selected_openpgp_reader(&self) -> Option<String> {
        self.selected_device().and_then(|d| d.reader.clone())
    }

    /// Read the selected card's status on the worker thread.
    fn load_openpgp_status(&mut self) {
        self.openpgp.error = None;
        let Some(name) = self.selected_openpgp_reader() else {
            self.openpgp.error = Some("no OpenPGP card selected".into());
            return;
        };
        self.spawn_job("Reading OpenPGP status\u{2026}", move || {
            let result = (|| -> Result<keyroost_transport::OpenPgpStatus, TransportError> {
                let mut session = keyroost_transport::OpenPgpSession::open(&name)?;
                session.status()
            })();
            Box::new(move |app: &mut App| match result {
                Ok(status) => {
                    app.openpgp.status = Some(status);
                    app.openpgp.loaded = true;
                }
                Err(e) => app.openpgp.error = Some(e.to_string()),
            })
        });
    }

    /// Off-thread helper: open the card and verify the admin PIN (PW3). Shared by
    /// every write op so they all gate on PW3.
    fn openpgp_open_admin(
        name: &str,
        admin_pin: &str,
    ) -> Result<keyroost_transport::OpenPgpSession, TransportError> {
        let mut session = keyroost_transport::OpenPgpSession::open(name)?;
        session.verify_admin_pin(admin_pin.as_bytes())?;
        Ok(session)
    }

    /// Re-read status after a write and store it, surfacing `notice` on success.
    fn apply_openpgp_write(
        app: &mut App,
        result: Result<keyroost_transport::OpenPgpStatus, TransportError>,
        notice: String,
    ) {
        match result {
            Ok(status) => {
                app.openpgp.status = Some(status);
                app.openpgp.loaded = true;
                app.openpgp.error = None;
                app.openpgp.notice = Some(notice);
                app.openpgp.admin_pin.clear();
            }
            Err(e) => {
                app.openpgp.error = Some(e.to_string());
                app.openpgp.admin_pin.clear();
            }
        }
    }

    /// Set the cardholder name (PW3-gated), then refresh status.
    fn set_openpgp_name(&mut self) {
        let Some(name) = self.selected_openpgp_reader() else {
            return;
        };
        let pin = self.openpgp.admin_pin.clone();
        let value = self.openpgp.name_input.clone();
        self.openpgp.notice = None;
        self.spawn_job("Setting cardholder name…", move || {
            let result = (|| -> Result<keyroost_transport::OpenPgpStatus, TransportError> {
                let mut s = Self::openpgp_open_admin(&name, &pin)?;
                s.set_cardholder_name(value.as_bytes())?;
                s.status()
            })();
            Box::new(move |app: &mut App| {
                Self::apply_openpgp_write(app, result, "Cardholder name set.".into())
            })
        });
    }

    /// Set the public-key URL (PW3-gated), then refresh status.
    fn set_openpgp_url(&mut self) {
        let Some(name) = self.selected_openpgp_reader() else {
            return;
        };
        let pin = self.openpgp.admin_pin.clone();
        let value = self.openpgp.url_input.clone();
        self.openpgp.notice = None;
        self.spawn_job("Setting public-key URL…", move || {
            let result = (|| -> Result<keyroost_transport::OpenPgpStatus, TransportError> {
                let mut s = Self::openpgp_open_admin(&name, &pin)?;
                s.set_url(value.as_bytes())?;
                s.status()
            })();
            Box::new(move |app: &mut App| {
                Self::apply_openpgp_write(app, result, "Public-key URL set.".into())
            })
        });
    }

    /// Generate + register a key in the selected slot (PW3-gated, destructive),
    /// then refresh status. May require a touch on the key.
    fn generate_openpgp_key(&mut self) {
        let Some(name) = self.selected_openpgp_reader() else {
            return;
        };
        let pin = self.openpgp.admin_pin.clone();
        let slot = self.openpgp.gen_slot;
        let creation_time = unix_now();
        self.openpgp.notice = None;
        self.spawn_job("Generating key… (touch the key if it blinks)", move || {
            let result = (|| -> Result<(keyroost_transport::OpenPgpStatus, [u8; 20]), TransportError> {
                let mut s = Self::openpgp_open_admin(&name, &pin)?;
                let _ = s.generate_key(slot.to_crt())?;
                let fpr = s.register_key(slot.to_crt(), creation_time)?;
                Ok((s.status()?, fpr))
            })();
            Box::new(move |app: &mut App| match result {
                Ok((status, fpr)) => {
                    app.openpgp.status = Some(status);
                    app.openpgp.loaded = true;
                    app.openpgp.error = None;
                    app.openpgp.notice = Some(format!("Generated {} key: {}", slot.label(), hex_lower(&fpr)));
                    app.openpgp.admin_pin.clear();
                }
                Err(e) => {
                    app.openpgp.error = Some(e.to_string());
                    app.openpgp.admin_pin.clear();
                }
            })
        });
    }

    /// Import a key into the selected slot (PW3-gated, destructive), then refresh
    /// status. The key material comes from host keygen or a file, obtained on the
    /// worker thread (keygen is slow). May require a touch on the key.
    fn import_openpgp_key(&mut self, source: ImportSource) {
        let Some(name) = self.selected_openpgp_reader() else {
            return;
        };
        let pin = self.openpgp.admin_pin.clone();
        let slot = self.openpgp.import_slot;
        let path = self.openpgp.import_path.clone();
        let creation_time = unix_now();
        self.openpgp.notice = None;
        let label = match source {
            ImportSource::Generate => "Generating & importing RSA-2048 key… (touch if it blinks)",
            ImportSource::FromFile => "Importing RSA key from file… (touch if it blinks)",
        };
        self.spawn_job(label, move || {
            // Obtain the key parts first (keygen / file parse on this worker
            // thread). Map every error to a String so success and the various
            // failure kinds (key, PIN, card) flow through one result channel.
            let result = (|| -> Result<(keyroost_transport::OpenPgpStatus, [u8; 20]), String> {
                let k = match source {
                    ImportSource::Generate => keyroost_rsakey::generate_2048(),
                    ImportSource::FromFile => {
                        keyroost_rsakey::load_from_file(std::path::Path::new(&path))
                    }
                }
                .map_err(|e| e.to_string())?;

                let mut s = Self::openpgp_open_admin(&name, &pin).map_err(|e| e.to_string())?;
                let parts = keyroost_transport::RsaPrivateKeyParts {
                    e: &k.e,
                    p: &k.p,
                    q: &k.q,
                    u: &k.u,
                    dp: &k.dp,
                    dq: &k.dq,
                    n: &k.n,
                };
                s.import_key(slot.to_crt(), &parts)
                    .map_err(|e| e.to_string())?;
                let fpr = s
                    .register_key(slot.to_crt(), creation_time)
                    .map_err(|e| e.to_string())?;
                let status = s.status().map_err(|e| e.to_string())?;
                Ok((status, fpr))
            })();
            Box::new(move |app: &mut App| match result {
                Ok((status, fpr)) => {
                    app.openpgp.status = Some(status);
                    app.openpgp.loaded = true;
                    app.openpgp.error = None;
                    app.openpgp.notice = Some(format!(
                        "Imported {} key: {}",
                        slot.label(),
                        hex_lower(&fpr)
                    ));
                    app.openpgp.admin_pin.clear();
                    app.openpgp.import_path.clear();
                }
                Err(e) => {
                    app.openpgp.error = Some(e);
                    app.openpgp.admin_pin.clear();
                }
            })
        });
    }

    /// Factory-reset the OpenPGP applet (destructive), then refresh status. No
    /// PIN needed — reset blocks the PINs itself.
    fn reset_openpgp(&mut self) {
        let Some(name) = self.selected_openpgp_reader() else {
            return;
        };
        self.openpgp.notice = None;
        self.spawn_job("Resetting OpenPGP applet…", move || {
            let result = (|| -> Result<keyroost_transport::OpenPgpStatus, TransportError> {
                let mut s = keyroost_transport::OpenPgpSession::open(&name)?;
                s.factory_reset()?;
                s.status()
            })();
            Box::new(move |app: &mut App| {
                Self::apply_openpgp_write(
                    app,
                    result,
                    "OpenPGP applet reset; keys wiped, PINs back to defaults.".into(),
                )
            })
        });
    }

    /// Write-operations section: cardholder name / URL, generate key, reset.
    /// All write ops use the admin PIN (PW3) entered here; reset is the exception
    /// (it blocks the PINs itself). Destructive ops route through confirm modals.
    fn render_openpgp_manage(&mut self, ui: &mut egui::Ui) {
        ui.collapsing("Manage (write operations)", |ui| {
            ui.horizontal(|ui| {
                ui.label("Admin PIN (PW3):");
                ui.add(
                    egui::TextEdit::singleline(&mut self.openpgp.admin_pin)
                        .password(true)
                        .desired_width(160.0),
                );
                helper_bubble(
                    ui,
                    "The admin PIN authorizes write operations. It is sent to the \
                     card for this operation only and never written to disk.",
                );
            });
            ui.add_space(4.0);

            ui.horizontal(|ui| {
                ui.label("Name:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.openpgp.name_input)
                        .hint_text("Surname<<Given")
                        .desired_width(200.0),
                );
                if ui.button("Set name").clicked() {
                    self.set_openpgp_name();
                }
            });
            ui.horizontal(|ui| {
                ui.label("URL:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.openpgp.url_input)
                        .hint_text("https://…")
                        .desired_width(200.0),
                );
                if ui.button("Set URL").clicked() {
                    self.set_openpgp_url();
                }
            });
            ui.add_space(6.0);

            ui.horizontal(|ui| {
                ui.label("Generate RSA key in slot:");
                egui::ComboBox::from_id_salt("openpgp-gen-slot")
                    .selected_text(self.openpgp.gen_slot.label())
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.openpgp.gen_slot, OpenPgpSlotSel::Sign, "signature");
                        ui.selectable_value(&mut self.openpgp.gen_slot, OpenPgpSlotSel::Decrypt, "decryption");
                        ui.selectable_value(&mut self.openpgp.gen_slot, OpenPgpSlotSel::Auth, "authentication");
                    });
                if ui.button("Generate\u{2026}").clicked() {
                    self.openpgp.confirm_generate = true;
                }
            });
            ui.add_space(6.0);

            ui.horizontal(|ui| {
                ui.label("Import RSA key into slot:");
                egui::ComboBox::from_id_salt("openpgp-import-slot")
                    .selected_text(self.openpgp.import_slot.label())
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.openpgp.import_slot, OpenPgpSlotSel::Sign, "signature");
                        ui.selectable_value(&mut self.openpgp.import_slot, OpenPgpSlotSel::Decrypt, "decryption");
                        ui.selectable_value(&mut self.openpgp.import_slot, OpenPgpSlotSel::Auth, "authentication");
                    });
                if ui.button("Generate & import\u{2026}").clicked() {
                    self.openpgp.confirm_import = Some(ImportSource::Generate);
                }
            });
            ui.horizontal(|ui| {
                ui.label("From file:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.openpgp.import_path)
                        .hint_text("/path/to/key.pem (PKCS#1/8, PEM or DER)")
                        .desired_width(260.0),
                );
                let armed = !self.openpgp.import_path.trim().is_empty();
                if ui
                    .add_enabled(armed, egui::Button::new("Import file\u{2026}"))
                    .clicked()
                {
                    self.openpgp.confirm_import = Some(ImportSource::FromFile);
                }
            });
            helper_bubble(
                ui,
                "Imports an RSA-2048 private key into the slot. \u{201c}Generate & import\u{201d} \
                 makes a fresh key on this host; \u{201c}From file\u{201d} loads a PKCS#1/PKCS#8 \
                 key (PEM or DER). Like generate, this OVERWRITES the slot and needs the admin PIN.",
            );
            ui.add_space(6.0);

            ui.horizontal(|ui| {
                let reset = egui::Button::new(
                    egui::RichText::new("Reset applet\u{2026}").color(egui::Color32::from_rgb(220, 110, 110)),
                );
                if ui.add(reset).clicked() {
                    self.openpgp.confirm_reset = Some(String::new());
                }
                helper_bubble(
                    ui,
                    "Wipes ALL OpenPGP keys and restores default PINs. Works even \
                     if the PINs are forgotten (it blocks them first).",
                );
            });
        });
    }

    /// The generate-key and reset confirmation modals for the OpenPGP pane.
    fn render_openpgp_confirms(&mut self, ctx: &egui::Context) {
        if self.openpgp.confirm_generate {
            let slot = self.openpgp.gen_slot.label();
            let mut do_it = false;
            let mut cancel = false;
            let mut window_open = true;
            egui::Window::new("Generate key?")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .open(&mut window_open)
                .show(ctx, |ui| {
                    ui.colored_label(
                        egui::Color32::from_rgb(220, 180, 80),
                        format!("Generate a fresh RSA key in the {slot} slot?"),
                    );
                    ui.label("This OVERWRITES any existing key in that slot (a slot");
                    ui.label("can only be cleared by a full applet reset). May need a touch.");
                    if self.openpgp.admin_pin.is_empty() {
                        ui.colored_label(
                            egui::Color32::from_rgb(220, 110, 110),
                            "Enter the admin PIN (PW3) above first.",
                        );
                    }
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        let armed = !self.openpgp.admin_pin.is_empty();
                        if ui
                            .add_enabled(armed, egui::Button::new("Generate"))
                            .clicked()
                        {
                            do_it = true;
                        }
                        if ui.button("Cancel").clicked() {
                            cancel = true;
                        }
                    });
                });
            if do_it {
                self.openpgp.confirm_generate = false;
                self.generate_openpgp_key();
            } else if cancel || !window_open {
                self.openpgp.confirm_generate = false;
            }
        }

        if let Some(source) = self.openpgp.confirm_import {
            let slot = self.openpgp.import_slot.label();
            let mut do_it = false;
            let mut cancel = false;
            let mut window_open = true;
            egui::Window::new("Import key?")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .open(&mut window_open)
                .show(ctx, |ui| {
                    let what = match source {
                        ImportSource::Generate => "a fresh host-generated RSA-2048 key".to_string(),
                        ImportSource::FromFile => {
                            format!("the RSA key from {}", self.openpgp.import_path.trim())
                        }
                    };
                    ui.colored_label(
                        egui::Color32::from_rgb(220, 180, 80),
                        format!("Import {what} into the {slot} slot?"),
                    );
                    ui.label("This OVERWRITES any existing key in that slot (a slot");
                    ui.label("can only be cleared by a full applet reset). May need a touch.");
                    if self.openpgp.admin_pin.is_empty() {
                        ui.colored_label(
                            egui::Color32::from_rgb(220, 110, 110),
                            "Enter the admin PIN (PW3) above first.",
                        );
                    }
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        let armed = !self.openpgp.admin_pin.is_empty();
                        if ui.add_enabled(armed, egui::Button::new("Import")).clicked() {
                            do_it = true;
                        }
                        if ui.button("Cancel").clicked() {
                            cancel = true;
                        }
                    });
                });
            if do_it {
                self.openpgp.confirm_import = None;
                self.import_openpgp_key(source);
            } else if cancel || !window_open {
                self.openpgp.confirm_import = None;
            }
        }

        if let Some(typed) = self.openpgp.confirm_reset.clone() {
            let mut do_it = false;
            let mut cancel = false;
            let mut window_open = true;
            let mut buf = typed;
            egui::Window::new("Reset OpenPGP applet?")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .open(&mut window_open)
                .show(ctx, |ui| {
                    ui.colored_label(
                        egui::Color32::from_rgb(220, 110, 110),
                        "This wipes ALL OpenPGP keys and resets the PINs to defaults.",
                    );
                    ui.label("This cannot be undone.");
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        ui.label("Type \u{201c}reset\u{201d} to confirm:");
                        ui.add(egui::TextEdit::singleline(&mut buf).desired_width(120.0));
                    });
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        let armed = buf.trim() == "reset";
                        if ui.add_enabled(armed, egui::Button::new("Reset")).clicked() {
                            do_it = true;
                        }
                        if ui.button("Cancel").clicked() {
                            cancel = true;
                        }
                    });
                });
            if do_it {
                self.openpgp.confirm_reset = None;
                self.reset_openpgp();
            } else if cancel || !window_open {
                self.openpgp.confirm_reset = None;
            } else {
                self.openpgp.confirm_reset = Some(buf);
            }
        }
    }
}

/// Map an OpenPGP algorithm id (first attribute byte) to a short label.
fn algo_id_label(id: Option<u8>) -> &'static str {
    match id {
        Some(0x01) => "RSA",
        Some(0x12) => "ECDH",
        Some(0x13) => "ECDSA",
        Some(0x16) => "EdDSA",
        Some(_) => "other",
        None => "none",
    }
}

/// Render a 20-byte fingerprint, or "(no key)" when the slot is all-zero.
fn fpr_label(fpr: &[u8; 20]) -> String {
    if fpr.iter().all(|&b| b == 0) {
        "(no key)".to_string()
    } else {
        hex_lower(fpr)
    }
}

/// Lowercase hex of a byte slice.
fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn kv(ui: &mut egui::Ui, key: &str, value: &str) {
    ui.horizontal_wrapped(|ui| {
        ui.label(egui::RichText::new(format!("{key}:")).color(ui.visuals().weak_text_color()));
        ui.label(value);
    });
}

/// The reusable "helper-bubble": a small information glyph that reveals a
/// plain-English note on hover. Used to disclose, concisely, any choice that
/// persists data or affects security (here, that naming a key writes its serial
/// to disk) without cluttering the layout with a wall of text.
fn helper_bubble(ui: &mut egui::Ui, text: &str) {
    ui.label(egui::RichText::new("\u{24d8}").weak()) // ⓘ
        .on_hover_text(text);
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

fn unix_now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

// --- Device-centric coordination (selection, theme, per-device loads) --------
impl App {
    /// The palette for the current theme + accent.
    fn palette(&self) -> Palette {
        Palette::new(self.mode, Palette::ACCENTS[self.accent_idx])
    }

    /// The currently selected device, if the id still resolves to a present one.
    fn selected_device(&self) -> Option<&UiDevice> {
        let id = self.selected_device.as_ref()?;
        self.devices.iter().find(|d| &d.id == id)
    }

    /// (Re)build the unified device list off-thread, then re-resolve selection.
    fn refresh_devices(&mut self) {
        self.scanned = true;
        self.spawn_job("Scanning for devices\u{2026}", move || {
            let result = device::enumerate();
            Box::new(move |app: &mut App| match result {
                Ok(devices) => {
                    app.devices_error = None;
                    // Keep the current selection if that device is still present;
                    // otherwise fall back to the first device.
                    let keep = app
                        .selected_device
                        .as_ref()
                        .filter(|id| devices.iter().any(|d| &d.id == *id))
                        .cloned();
                    let next = keep.or_else(|| devices.first().map(|d| d.id.clone()));
                    let changed = next != app.selected_device;
                    app.selected_device = next;
                    app.devices = devices;
                    if changed {
                        app.on_device_selected();
                    }
                }
                Err(e) => {
                    app.devices_error = Some(e);
                    app.devices.clear();
                    app.selected_device = None;
                }
            })
        });
    }

    /// Select a device by id (no-op if already selected).
    fn select_device(&mut self, id: DeviceId) {
        if self.selected_device.as_deref() == Some(id.as_str()) {
            return;
        }
        self.selected_device = Some(id);
        self.on_device_selected();
    }

    /// Reset per-applet state for a new selection and kick off the cheap,
    /// no-touch reads (FIDO GetInfo; Molto2 session open). OATH/PGP/PIV reads
    /// stay deferred to their tab so selecting a key never triggers a surprise
    /// touch prompt.
    fn on_device_selected(&mut self) {
        self.cap_tab = CapTab::Overview;
        self.security_keys.info = None;
        self.security_keys.init = None;
        self.security_keys.session = None;
        self.security_keys.error = None;
        self.oath.creds.clear();
        self.oath.loaded = false;
        self.oath.locked = false;
        self.oath.error = None;
        self.openpgp.status = None;
        self.openpgp.loaded = false;
        self.openpgp.error = None;
        self.piv = PivState::default();
        self.oath_tried = false;
        self.piv_tried = false;
        self.authenticated = false;
        self.session = None;
        self.info = None;

        let Some(dev) = self.selected_device().cloned() else {
            return;
        };
        match dev.kind {
            DeviceKind::Token => self.open_molto(),
            DeviceKind::Key if dev.caps.has(Caps::FIDO2) => self.fetch_selected_info(),
            DeviceKind::Key => {}
        }
    }

    /// Open the selected Molto2 token's PC/SC session and read its info, so the
    /// dedicated token pane has a live handle.
    fn open_molto(&mut self) {
        let Some(reader) = self.selected_device().and_then(|d| d.reader.clone()) else {
            return;
        };
        self.spawn_job("Opening Molto2\u{2026}", move || {
            let result = (|| -> Result<(Session, DeviceInfo), TransportError> {
                let mut s = Session::open_named(&reader)?;
                let info = s.read_info()?;
                Ok((s, info))
            })();
            Box::new(move |app: &mut App| match result {
                Ok((s, info)) => {
                    app.log(Severity::Ok, format!("opened Molto2 {}", info.serial));
                    app.session = Some(s);
                    app.info = Some(info);
                    app.authenticated = false;
                }
                Err(e) => app.log(Severity::Err, format!("open Molto2: {e}")),
            })
        });
    }

    /// Read the selected card's read-only PIV status snapshot.
    fn load_piv_status(&mut self) {
        self.piv.error = None;
        let Some(reader) = self.selected_oath_reader() else {
            return;
        };
        self.spawn_job("Reading PIV status\u{2026}", move || {
            let result = keyroost_transport::PivSession::open(&reader).and_then(|mut s| s.status());
            Box::new(move |app: &mut App| match result {
                Ok(status) => {
                    app.piv.status = Some(status);
                    app.piv.loaded = true;
                }
                Err(e) => app.piv.error = Some(e.to_string()),
            })
        });
    }

    /// Toggle the help popover for `topic`, anchored under the clicked "?".
    fn toggle_help(&mut self, topic: &'static str, anchor: egui::Pos2) {
        self.help_anchor = anchor;
        self.help_open = if self.help_open == Some(topic) {
            None
        } else {
            Some(topic)
        };
    }
}

/// Current unix time as a float (for the OATH "copied" flash window).
fn now_secs_f64() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// A flat panel frame with a fill and symmetric inner padding.
fn panel_frame(fill: egui::Color32, mx: f32, my: f32) -> egui::Frame {
    egui::Frame::none()
        .fill(fill)
        .inner_margin(egui::Margin::symmetric(mx, my))
}

/// A rounded square "glyph tile". `ch = Some(c)` paints a letter; `None` paints a
/// small clock (the Molto2 token mark).
fn glyph_tile(ui: &mut egui::Ui, size: f32, fill: egui::Color32, fg: egui::Color32, ch: Option<char>) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    ui.painter()
        .rect_filled(rect, egui::Rounding::same(size * 0.28), fill);
    match ch {
        Some(c) => {
            ui.painter().text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                c,
                theme::f_bold(size * 0.5),
                fg,
            );
        }
        None => {
            let c = rect.center();
            let r = size * 0.26;
            ui.painter().circle_stroke(c, r, egui::Stroke::new(1.6, fg));
            ui.painter()
                .line_segment([c, c + egui::vec2(0.0, -r * 0.72)], egui::Stroke::new(1.6, fg));
            ui.painter()
                .line_segment([c, c + egui::vec2(r * 0.55, 0.0)], egui::Stroke::new(1.6, fg));
        }
    }
}

/// Does the device match the sidebar filter text?
fn matches_filter(d: &UiDevice, q: &str) -> bool {
    let q = q.trim().to_ascii_lowercase();
    if q.is_empty() {
        return true;
    }
    d.vendor.to_ascii_lowercase().contains(&q)
        || d.model.to_ascii_lowercase().contains(&q)
        || d.title().to_ascii_lowercase().contains(&q)
}

/// Short label for a capability tab.
fn cap_tab_label(t: CapTab) -> &'static str {
    match t {
        CapTab::Overview => "Overview",
        CapTab::Fido2 => "Passkeys",
        CapTab::Oath => "Authenticator",
        CapTab::Pgp => "OpenPGP",
        CapTab::Piv => "PIV",
    }
}

/// A labelled password field row for the inline PIN form.
fn pin_field(ui: &mut egui::Ui, p: &Palette, label: &str, buf: &mut String) {
    ui.horizontal(|ui| {
        ui.add_sized(
            [96.0, 22.0],
            egui::Label::new(egui::RichText::new(label).font(theme::f_reg(13.0)).color(p.txt2)),
        );
        ui.add(egui::TextEdit::singleline(buf).password(true).desired_width(200.0));
    });
    ui.add_space(4.0);
}

/// Paint a rounded glyph tile at `rect` with the painter (no widget allocation,
/// so it never steals clicks from a surrounding row). `ch = None` draws a clock.
fn paint_glyph_tile(ui: &egui::Ui, rect: egui::Rect, fill: egui::Color32, fg: egui::Color32, ch: Option<char>) {
    ui.painter().rect_filled(rect, egui::Rounding::same(rect.width() * 0.28), fill);
    match ch {
        Some(c) => {
            ui.painter().text(rect.center(), egui::Align2::CENTER_CENTER, c, theme::f_bold(rect.width() * 0.5), fg);
        }
        None => {
            let c = rect.center();
            let r = rect.width() * 0.26;
            ui.painter().circle_stroke(c, r, egui::Stroke::new(1.6, fg));
            ui.painter().line_segment([c, c + egui::vec2(0.0, -r * 0.72)], egui::Stroke::new(1.6, fg));
            ui.painter().line_segment([c, c + egui::vec2(r * 0.55, 0.0)], egui::Stroke::new(1.6, fg));
        }
    }
}

/// Paint a small rounded pill at `left_top` with the painter; returns its width
/// so the caller can advance a cursor.
fn paint_pill(ui: &egui::Ui, left_top: egui::Pos2, text: &str, fg: egui::Color32, bg: egui::Color32) -> f32 {
    let galley = ui.fonts(|f| f.layout_no_wrap(text.to_string(), theme::f_sb(11.0), fg));
    let pad_x = 8.0;
    let h = 18.0;
    let w = galley.size().x + pad_x * 2.0;
    let rect = egui::Rect::from_min_size(left_top, egui::vec2(w, h));
    ui.painter().rect_filled(rect, egui::Rounding::same(999.0), bg);
    let pos = egui::pos2(left_top.x + pad_x, rect.center().y - galley.size().y / 2.0);
    ui.painter().galley(pos, galley, fg);
    w
}

/// Paint one selectable device row. The whole row is a single painter-drawn
/// click target (no nested widgets), so clicking anywhere in it selects the
/// device — fixing the "only the gaps are clickable" inconsistency.
fn device_row(ui: &mut egui::Ui, p: &Palette, dev: &UiDevice, selected: bool) -> bool {
    let w = ui.available_width();
    let h = 68.0;
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(w, h), egui::Sense::click());
    let bg = if selected {
        p.raised
    } else if resp.hovered() {
        p.line_soft
    } else {
        egui::Color32::TRANSPARENT
    };
    ui.painter().rect(
        rect,
        egui::Rounding::same(11.0),
        bg,
        egui::Stroke::new(1.0, if selected { p.line } else { egui::Color32::TRANSPARENT }),
    );
    if selected {
        ui.painter().rect_filled(
            egui::Rect::from_min_size(rect.left_top() + egui::vec2(0.0, 13.0), egui::vec2(3.0, h - 26.0)),
            egui::Rounding::same(3.0),
            p.accent,
        );
    }

    let token = dev.kind == DeviceKind::Token;
    let tile = egui::Rect::from_min_size(rect.left_top() + egui::vec2(14.0, (h - 38.0) / 2.0), egui::vec2(38.0, 38.0));
    if token {
        paint_glyph_tile(ui, tile, p.brand_soft(), p.brand, None);
    } else {
        paint_glyph_tile(ui, tile, p.raised2, p.txt2, Some(dev.vendor.chars().next().unwrap_or('?').to_ascii_uppercase()));
    }

    let tx = tile.right() + 11.0;
    let right_pad = 16.0;
    // status dot, top-right
    ui.painter().circle_filled(egui::pos2(rect.right() - right_pad, rect.top() + 18.0), 3.5, p.ok);
    // vendor eyebrow
    ui.painter().text(egui::pos2(tx, rect.top() + 13.0), egui::Align2::LEFT_TOP, &dev.vendor, theme::f_sb(11.0), p.txt3);
    // model, truncated to the available width
    let avail = (rect.right() - right_pad - 8.0) - tx;
    let galley = ui.fonts(|f| {
        let mut job = egui::text::LayoutJob::single_section(
            dev.title().to_string(),
            egui::TextFormat { font_id: theme::f_sb(13.5), color: p.txt, ..Default::default() },
        );
        job.wrap = egui::text::TextWrapping {
            max_width: avail.max(0.0),
            max_rows: 1,
            break_anywhere: true,
            overflow_character: Some('\u{2026}'),
        };
        f.layout_job(job)
    });
    ui.painter().galley(egui::pos2(tx, rect.top() + 26.0), galley, p.txt);
    // capability pills
    let py = rect.top() + 46.0;
    if token {
        paint_pill(ui, egui::pos2(tx, py), "TOTP token", p.brand, p.brand_soft());
    } else {
        let mut px = tx;
        for (cap, label) in [
            (Caps::FIDO2, "FIDO2"),
            (Caps::OATH, "OATH"),
            (Caps::PGP, "PGP"),
            (Caps::PIV, "PIV"),
        ] {
            if dev.caps.has(cap) {
                px += paint_pill(ui, egui::pos2(px, py), label, p.txt2, p.raised2) + 5.0;
            }
        }
    }
    resp.clicked()
}

impl eframe::App for App {
    /// Persist the theme so it survives a restart.
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        storage.set_string(
            "mode",
            match self.mode {
                Mode::Dark => "dark",
                Mode::Light => "light",
            }
            .to_string(),
        );
        storage.set_string("accent", self.accent_idx.to_string());
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Apply any results from background device jobs before drawing.
        self.drain_worker();
        let p = self.palette();
        p.apply(ctx, self.mode);

        // First frame: scan for devices automatically so the user isn't staring
        // at an empty pane wondering whether the app is broken.
        if !self.scanned {
            self.refresh_devices();
        }

        self.top_bar(ctx, &p);
        self.device_sidebar(ctx, &p);
        if self.log_open {
            self.activity_log(ctx, &p);
        }
        self.central(ctx, &p);

        // Modal dialogs (reused from the per-applet logic) + Molto2 import dialogs.
        self.render_reset_dialog(ctx);
        self.render_oath_delete_confirm(ctx);
        self.render_openpgp_confirms(ctx);
        self.molto_dialogs(ctx, &p);

        // Help popover, painted last so it sits above everything.
        if let Some(topic) = self.help_open {
            if ui::help_popover(ctx, &p, topic, self.help_anchor) {
                self.help_open = None;
            }
        }

        // Keep OATH rings / Molto2 time ticking while a device is selected.
        // Only keep ticking when something actually animates (OATH countdown
        // rings, the Molto2 view, or the "copied" flash) — not on every static
        // pane, which would burn frames and feel sluggish.
        let animating = self.copied.is_some()
            || matches!(self.cap_tab, CapTab::Oath)
            || (matches!(self.cap_tab, CapTab::Overview) && self.oath.loaded && !self.oath.creds.is_empty())
            || self.selected_device().map_or(false, |d| d.kind == DeviceKind::Token);
        if animating {
            ctx.request_repaint_after(std::time::Duration::from_millis(500));
        }
    }
}

// --- Device-centric rendering ------------------------------------------------
impl App {
    /// Toggle the help popover for `topic`, anchored under the clicked "?" button.
    fn help_dot(&mut self, ui: &mut egui::Ui, p: &Palette, topic: &'static str) {
        let r = ui::help_button(ui, p, self.help_open == Some(topic));
        if r.clicked() {
            self.toggle_help(topic, r.rect.left_bottom());
        }
    }

    /// Top bar: brand · "keyroost" · connected count | accents · theme · Learn ·
    /// Activity log · Refresh.
    fn top_bar(&mut self, ctx: &egui::Context, p: &Palette) {
        egui::TopBottomPanel::top("bar")
            .exact_height(52.0)
            .frame(panel_frame(p.bar, 16.0, 0.0))
            .show(ctx, |ui| {
                ui.horizontal_centered(|ui| {
                    glyph_tile(ui, 26.0, p.brand, p.accent_ink, Some('k'));
                    ui.add_space(8.0);
                    ui.label(egui::RichText::new("keyroost").font(theme::f_bold(14.0)).color(p.txt));
                    ui.add_space(12.0);
                    theme::status_dot(ui, p.ok, 7.0);
                    ui.add_space(5.0);
                    ui.label(
                        egui::RichText::new(format!("{} connected", self.devices.len()))
                            .font(theme::f_reg(12.0))
                            .color(p.txt2),
                    );
                    if self.busy() {
                        ui.add_space(12.0);
                        ui.spinner();
                        if let Some(label) = &self.busy_label {
                            ui.label(egui::RichText::new(label.as_str()).font(theme::f_reg(12.0)).color(p.txt3));
                        }
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if theme::button(ui, p, BtnKind::Ghost, "Refresh").clicked() {
                            self.refresh_devices();
                        }
                        ui.add_space(4.0);
                        let log_color = if self.log_open { p.accent } else { p.txt2 };
                        if ui
                            .add(
                                egui::Label::new(
                                    egui::RichText::new("Activity log").font(theme::f_sb(12.5)).color(log_color),
                                )
                                .sense(egui::Sense::click()),
                            )
                            .clicked()
                        {
                            self.log_open = !self.log_open;
                        }
                        ui.add_space(10.0);
                        ui.hyperlink_to(
                            egui::RichText::new("Learn \u{2197}").font(theme::f_sb(12.5)).color(p.txt2),
                            ui::help::LEARN_BASE,
                        );
                        ui.add_space(10.0);
                        if ui
                            .add(
                                egui::Label::new(egui::RichText::new("\u{25D0}").font(theme::f_reg(15.0)).color(p.txt2))
                                    .sense(egui::Sense::click()),
                            )
                            .on_hover_text("Toggle light / dark")
                            .clicked()
                        {
                            self.mode = match self.mode {
                                Mode::Dark => Mode::Light,
                                Mode::Light => Mode::Dark,
                            };
                        }
                        ui.add_space(10.0);
                        for (i, c) in Palette::ACCENTS.iter().enumerate().rev() {
                            let (rect, resp) =
                                ui.allocate_exact_size(egui::vec2(16.0, 16.0), egui::Sense::click());
                            let on = i == self.accent_idx;
                            ui.painter()
                                .circle_filled(rect.center(), if on { 6.0 } else { 5.0 }, *c);
                            if on {
                                ui.painter()
                                    .circle_stroke(rect.center(), 7.5, egui::Stroke::new(1.5, p.txt));
                            }
                            if resp.clicked() {
                                self.accent_idx = i;
                            }
                        }
                    });
                });
            });
    }

    /// Left device bar: header · filter · rows · footer tip.
    fn device_sidebar(&mut self, ctx: &egui::Context, p: &Palette) {
        egui::SidePanel::left("devices")
            .exact_width(286.0)
            .resizable(false)
            .frame(panel_frame(p.side, 14.0, 12.0))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("DEVICES").font(theme::f_bold(11.0)).color(p.txt3));
                    ui.add_space(6.0);
                    theme::pill(ui, &self.devices.len().to_string(), p.txt2, p.raised2);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .add(
                                egui::Label::new(egui::RichText::new("\u{21BB}").font(theme::f_reg(15.0)).color(p.txt2))
                                    .sense(egui::Sense::click()),
                            )
                            .on_hover_text("Rescan")
                            .clicked()
                        {
                            self.refresh_devices();
                        }
                    });
                });
                ui.add_space(8.0);
                ui.add(
                    egui::TextEdit::singleline(&mut self.filter)
                        .hint_text("Filter keys\u{2026}")
                        .desired_width(f32::INFINITY),
                );
                ui.add_space(8.0);

                if let Some(err) = &self.devices_error {
                    ui.colored_label(p.err, err);
                    ui.add_space(6.0);
                }

                let mut clicked: Option<DeviceId> = None;
                egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                    if self.devices.is_empty() {
                        ui.add_space(12.0);
                        ui.vertical_centered(|ui| {
                            ui.label(egui::RichText::new("No keys detected yet.").font(theme::f_reg(13.0)).color(p.txt3));
                        });
                    }
                    for dev in self.devices.iter().filter(|d| matches_filter(d, &self.filter)) {
                        let selected = self.selected_device.as_deref() == Some(dev.id.as_str());
                        if device_row(ui, p, dev, selected) {
                            clicked = Some(dev.id.clone());
                        }
                        ui.add_space(2.0);
                    }
                });
                if let Some(id) = clicked {
                    self.select_device(id);
                }

                // Footer tip (only worth showing once a key is present).
                if !self.devices.is_empty() {
                    ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
                        ui.add_space(4.0);
                        ui.horizontal_wrapped(|ui| {
                            ui.spacing_mut().item_spacing.x = 4.0;
                            ui.label(egui::RichText::new("Several keys plugged in?").font(theme::f_reg(12.0)).color(p.txt3));
                            ui.hyperlink_to(
                                egui::RichText::new("Give them names").font(theme::f_sb(12.0)).color(p.accent),
                                ui::help::learn_url("/naming"),
                            );
                        });
                    });
                }
            });
    }

    /// Global activity-log drawer (bottom), replacing the Molto2-only log.
    fn activity_log(&mut self, ctx: &egui::Context, p: &Palette) {
        egui::TopBottomPanel::bottom("log")
            .exact_height(180.0)
            .frame(panel_frame(p.bar, 16.0, 10.0))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("ACTIVITY LOG").font(theme::f_bold(11.0)).color(p.txt3));
                    ui.add_space(6.0);
                    theme::pill(ui, "live", p.ok, p.ok_soft());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if theme::button(ui, p, BtnKind::Ghost, "Collapse").clicked() {
                            self.log_open = false;
                        }
                        ui.add_space(4.0);
                        if theme::button(ui, p, BtnKind::Ghost, "Copy").clicked() {
                            let all = self.log.iter().map(|l| l.text.clone()).collect::<Vec<_>>().join("\n");
                            ui.output_mut(|o| o.copied_text = all);
                        }
                    });
                });
                ui.add_space(6.0);
                egui::ScrollArea::vertical()
                    .stick_to_bottom(true)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for line in &self.log {
                            let color = match line.severity {
                                Severity::Ok => p.ok,
                                Severity::Warn => p.warn,
                                Severity::Err => p.err,
                                Severity::Info => p.txt2,
                            };
                            ui.label(egui::RichText::new(&line.text).font(theme::f_mono(12.0)).color(color));
                        }
                    });
            });
    }

    /// The central pane: empty state, the Molto2 token view, or the selected
    /// key's hero + capability tabs + active capability panel.
    fn central(&mut self, ctx: &egui::Context, p: &Palette) {
        egui::CentralPanel::default()
            .frame(panel_frame(p.surface, 0.0, 0.0))
            .show(ctx, |ui| match self.selected_device().cloned() {
                None => self.empty_state(ui, p),
                Some(dev) if dev.kind == DeviceKind::Token => self.molto_view(ui, p, &dev),
                Some(dev) => {
                    egui::Frame::none()
                        .inner_margin(egui::Margin::symmetric(26.0, 16.0))
                        .show(ui, |ui| {
                            self.device_hero(ui, p, &dev);
                            self.cap_tabs(ui, p, &dev);
                            ui.add_space(16.0);
                            match self.cap_tab {
                                CapTab::Overview => self.overview(ui, p, &dev),
                                CapTab::Fido2 => self.cap_fido2(ui, p),
                                CapTab::Oath => self.cap_oath(ui, p),
                                CapTab::Pgp => self.cap_pgp(ui, p),
                                CapTab::Piv => self.cap_piv(ui, p),
                            }
                        });
                }
            });
    }

    /// Welcoming first-run state shown when nothing is plugged in.
    fn empty_state(&mut self, ui: &mut egui::Ui, p: &Palette) {
        // Manually center a fixed-width column. `vertical_centered` doesn't
        // reliably center nested rows (a `horizontal` fills full width and
        // left-aligns), which is what jammed the buttons against the divider.
        let col_w = 440.0_f32;
        let pad = ((ui.available_width() - col_w) * 0.5).max(12.0);
        ui.add_space(90.0);
        ui.horizontal(|ui| {
            ui.add_space(pad);
            ui.allocate_ui_with_layout(
                egui::vec2(col_w, ui.available_height()),
                egui::Layout::top_down(egui::Align::Center),
                |ui| {
                    let (rect, _) = ui.allocate_exact_size(egui::vec2(64.0, 64.0), egui::Sense::hover());
                    ui.painter()
                        .rect_stroke(rect, egui::Rounding::same(16.0), egui::Stroke::new(1.5, p.line));
                    ui.painter().text(
                        rect.center(),
                        egui::Align2::CENTER_CENTER,
                        "\u{1F511}",
                        theme::f_reg(26.0),
                        p.txt3,
                    );
                    ui.add_space(18.0);
                    ui.label(egui::RichText::new("Plug in a security key to begin").font(theme::f_bold(19.0)).color(p.txt));
                    ui.add_space(8.0);
                    ui.label(
                        egui::RichText::new(
                            "keyroost manages YubiKeys, Nitrokeys, SoloKeys and Token2 tokens. Connect one over USB and it shows up in the list on the left.",
                        )
                        .font(theme::f_reg(13.0))
                        .color(p.txt2),
                    );
                    ui.add_space(22.0);
                    // Numbered steps: left-aligned within the centered column.
                    ui.allocate_ui_with_layout(egui::vec2(360.0, 0.0), egui::Layout::top_down(egui::Align::Min), |ui| {
                        for (n, step) in [
                            "Insert your key into a USB port",
                            "It appears in the Devices list automatically",
                            "Select it to view and manage everything it can do",
                        ]
                        .iter()
                        .enumerate()
                        {
                            ui.horizontal(|ui| {
                                let (badge, _) = ui.allocate_exact_size(egui::vec2(22.0, 22.0), egui::Sense::hover());
                                ui.painter().circle_filled(badge.center(), 11.0, p.accent_soft());
                                ui.painter().text(
                                    badge.center(),
                                    egui::Align2::CENTER_CENTER,
                                    format!("{}", n + 1),
                                    theme::f_sb(12.0),
                                    p.accent,
                                );
                                ui.add_space(10.0);
                                ui.label(egui::RichText::new(*step).font(theme::f_reg(13.0)).color(p.txt));
                            });
                            ui.add_space(10.0);
                        }
                    });
                    ui.add_space(14.0);
                    ui.horizontal(|ui| {
                        if theme::button(ui, p, BtnKind::Primary, "Scan for devices").clicked() {
                            self.refresh_devices();
                        }
                        ui.add_space(8.0);
                        ui.hyperlink_to(
                            egui::RichText::new("Supported devices \u{2197}").font(theme::f_sb(12.5)).color(p.accent),
                            ui::help::learn_url("/devices"),
                        );
                    });
                },
            );
        });
    }

    /// Device hero strip at the top of a key's pane.
    fn device_hero(&mut self, ui: &mut egui::Ui, p: &Palette, dev: &UiDevice) {
        ui.horizontal(|ui| {
            glyph_tile(ui, 46.0, p.raised2, p.txt2, Some(dev.vendor.chars().next().unwrap_or('?').to_ascii_uppercase()));
            ui.add_space(12.0);
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(dev.title()).font(theme::f_bold(21.0)).color(p.txt));
                    ui.add_space(5.0);
                    self.help_dot(ui, p, "device");
                });
                ui.add_space(2.0);
                let serial = if dev.serial.is_empty() { "\u{2014}".to_string() } else { dev.serial.clone() };
                let mut meta = format!("{} \u{00B7} #{} \u{00B7} {}", dev.vendor, serial, dev.transport);
                if !dev.firmware.is_empty() {
                    meta.push_str(&format!(" \u{00B7} fw {}", dev.firmware));
                }
                ui.label(egui::RichText::new(meta).font(theme::f_reg(12.5)).color(p.txt2));
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(egui::RichText::new("Connected").font(theme::f_sb(12.5)).color(p.txt2));
                ui.add_space(5.0);
                theme::status_dot(ui, p.ok, 8.0);
            });
        });
        ui.add_space(14.0);
        let y = ui.cursor().top();
        ui.painter().hline(ui.max_rect().x_range(), y, egui::Stroke::new(1.0, p.line));
    }

    /// Capability tab bar under the hero. The active tab gets `txt` + an accent
    /// underline; the rest are muted.
    fn cap_tabs(&mut self, ui: &mut egui::Ui, p: &Palette, dev: &UiDevice) {
        ui.add_space(12.0);
        let mut next = None;
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 20.0;
            for t in dev.tabs() {
                let active = self.cap_tab == t;
                let color = if active { p.txt } else { p.txt3 };
                let resp = ui.add(
                    egui::Label::new(egui::RichText::new(cap_tab_label(t)).font(theme::f_sb(13.5)).color(color))
                        .sense(egui::Sense::click()),
                );
                if active {
                    let y = resp.rect.bottom() + 6.0;
                    ui.painter().line_segment(
                        [egui::pos2(resp.rect.left(), y), egui::pos2(resp.rect.right(), y)],
                        egui::Stroke::new(2.0, p.accent),
                    );
                }
                if resp.clicked() {
                    next = Some(t);
                }
            }
        });
        if let Some(t) = next {
            self.cap_tab = t;
        }
    }

    /// A card header row: title · "?" help · right-aligned "Manage →". Returns
    /// true when Manage is clicked (caller switches `cap_tab`).
    fn card_head(&mut self, ui: &mut egui::Ui, p: &Palette, title: &str, topic: &'static str) -> bool {
        let mut go = false;
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(title).font(theme::f_sb(14.5)).color(p.txt));
            ui.add_space(6.0);
            self.help_dot(ui, p, topic);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add(
                        egui::Label::new(egui::RichText::new("Manage \u{2192}").font(theme::f_sb(12.5)).color(p.accent))
                            .sense(egui::Sense::click()),
                    )
                    .clicked()
                {
                    go = true;
                }
            });
        });
        go
    }

    /// Overview tab: one summary card per capability, each with a `Manage →` jump.
    fn overview(&mut self, ui: &mut egui::Ui, p: &Palette, dev: &UiDevice) {
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            if dev.caps.has(Caps::FIDO2) {
                theme::card_frame(p).show(ui, |ui| {
                    if self.card_head(ui, p, "Passkeys & sign-in (FIDO2)", "fido2") {
                        self.cap_tab = CapTab::Fido2;
                    }
                    ui.add_space(8.0);
                    match self.security_keys.info.as_ref().and_then(|i| i.option("clientPin")) {
                        Some(true) => {
                            ui.horizontal(|ui| {
                                theme::pill(ui, "PIN set", p.ok, p.ok_soft());
                                ui.add_space(8.0);
                                ui.label(
                                    egui::RichText::new("PIN configured \u{00B7} ready for passkeys")
                                        .font(theme::f_reg(13.0))
                                        .color(p.txt2),
                                );
                            });
                        }
                        Some(false) => {
                            theme::pill(ui, "No PIN configured", p.warn, p.warn_soft());
                        }
                        None => {
                            ui.label(egui::RichText::new("Reading key\u{2026}").font(theme::f_reg(13.0)).color(p.txt3));
                        }
                    }
                });
                ui.add_space(14.0);
            }
            if dev.caps.has(Caps::OATH) {
                theme::card_frame(p).show(ui, |ui| {
                    if self.card_head(ui, p, "Authenticator codes (OATH)", "oath") {
                        self.cap_tab = CapTab::Oath;
                    }
                    ui.add_space(8.0);
                    if self.oath.loaded && !self.oath.creds.is_empty() {
                        let total = self.oath.creds.len();
                        let mut copy = None;
                        for row in self.oath.creds.iter().take(2) {
                            let is_copied = self.copied.as_ref().map_or(false, |(n, _)| n == &row.name);
                            if let (Some(code), _) = oath_row(ui, p, &row.name, row.code.as_deref(), is_copied, false) {
                                copy = Some((row.name.clone(), code));
                            }
                            ui.add_space(6.0);
                        }
                        if total > 2 {
                            ui.label(egui::RichText::new(format!("+{} more codes", total - 2)).font(theme::f_reg(12.5)).color(p.txt3));
                        }
                        if let Some((name, code)) = copy {
                            ui.output_mut(|o| o.copied_text = code);
                            self.copied = Some((name, now_secs_f64() + 1.2));
                        }
                    } else {
                        ui.label(
                            egui::RichText::new("Open Authenticator to view live codes.")
                                .font(theme::f_reg(13.0))
                                .color(p.txt3),
                        );
                    }
                });
                ui.add_space(14.0);
            }
            if dev.caps.has(Caps::PGP) {
                theme::card_frame(p).show(ui, |ui| {
                    if self.card_head(ui, p, "OpenPGP", "pgp") {
                        self.cap_tab = CapTab::Pgp;
                    }
                    ui.add_space(8.0);
                    if let Some(st) = &self.openpgp.status {
                        ui.horizontal_wrapped(|ui| {
                            ui.spacing_mut().item_spacing.x = 5.0;
                            theme::pill(ui, &format!("Signature \u{00B7} {}", slot_summary(st.sig_algo_id, &st.fingerprint_sig)), p.txt2, p.raised2);
                            theme::pill(ui, &format!("Encryption \u{00B7} {}", slot_summary(st.dec_algo_id, &st.fingerprint_dec)), p.txt2, p.raised2);
                            theme::pill(ui, &format!("Auth \u{00B7} {}", slot_summary(st.aut_algo_id, &st.fingerprint_aut)), p.txt2, p.raised2);
                        });
                    } else {
                        ui.label(
                            egui::RichText::new("Open OpenPGP and Read status to view key slots.")
                                .font(theme::f_reg(13.0))
                                .color(p.txt3),
                        );
                    }
                });
                ui.add_space(14.0);
            }
            if dev.caps.has(Caps::PIV) {
                theme::card_frame(p).show(ui, |ui| {
                    if self.card_head(ui, p, "PIV smart card", "piv") {
                        self.cap_tab = CapTab::Piv;
                    }
                    ui.add_space(8.0);
                    if let Some(st) = &self.piv.status {
                        ui.horizontal_wrapped(|ui| {
                            ui.spacing_mut().item_spacing.x = 5.0;
                            for slot in &st.slots {
                                let lab = format!("{:02X} \u{00B7} {}", slot.slot.key_ref(), if slot.cert_present { "cert" } else { "empty" });
                                theme::pill(ui, &lab, p.txt2, p.raised2);
                            }
                        });
                    } else {
                        ui.label(
                            egui::RichText::new("Open PIV to read certificate slots.")
                                .font(theme::f_reg(13.0))
                                .color(p.txt3),
                        );
                    }
                });
            }
        });
    }

    /// FIDO2 / Passkeys tab — reuses the existing PIN + credentials section.
    fn cap_fido2(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let pin_set = self.security_keys.info.as_ref().and_then(|i| i.option("clientPin"));

        // --- PIN & sign-in card (inline Set / Change PIN; no floating modal) ---
        let mut go_set = false;
        let mut go_change = false;
        let mut cancel = false;
        theme::card_frame(p).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("PIN & sign-in").font(theme::f_sb(14.5)).color(p.txt));
                ui.add_space(6.0);
                self.help_dot(ui, p, "pin");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| match pin_set {
                    Some(true) => {
                        if theme::button(ui, p, BtnKind::Default, "Change PIN").clicked() {
                            let open = !self.security_keys.change_pin.open;
                            self.security_keys.change_pin = ChangePinDialog { open, ..Default::default() };
                            self.security_keys.error = None;
                        }
                    }
                    Some(false) => {
                        if theme::button(ui, p, BtnKind::Primary, "Set a PIN").clicked() {
                            let open = !self.security_keys.change_pin.open;
                            self.security_keys.change_pin = ChangePinDialog { open, ..Default::default() };
                            self.security_keys.error = None;
                        }
                    }
                    None => {}
                });
            });
            ui.add_space(8.0);
            match pin_set {
                Some(true) => {
                    ui.horizontal(|ui| {
                        theme::pill(ui, "PIN set", p.ok, p.ok_soft());
                        ui.add_space(8.0);
                        ui.label(egui::RichText::new("This key has a PIN. Unlock below to manage passkeys.").font(theme::f_reg(13.0)).color(p.txt2));
                    });
                }
                Some(false) => {
                    ui.horizontal(|ui| {
                        theme::pill(ui, "No PIN yet", p.warn, p.warn_soft());
                        ui.add_space(8.0);
                        ui.label(egui::RichText::new("Set a PIN to protect this key and turn on passkeys.").font(theme::f_reg(13.0)).color(p.txt2));
                    });
                }
                None => {
                    let msg = if self.security_keys.error.is_some() { "Couldn't read this key." } else { "Reading key\u{2026}" };
                    ui.label(egui::RichText::new(msg).font(theme::f_reg(13.0)).color(p.txt3));
                }
            }

            if self.security_keys.change_pin.open {
                let setting = pin_set == Some(false);
                ui.add_space(10.0);
                egui::Frame::none()
                    .fill(p.raised)
                    .inner_margin(egui::Margin::same(12.0))
                    .rounding(egui::Rounding::same(8.0))
                    .show(ui, |ui| {
                        ui.label(egui::RichText::new(if setting { "Create a PIN" } else { "Change PIN" }).font(theme::f_sb(13.0)).color(p.txt));
                        ui.add_space(8.0);
                        if setting {
                            pin_field(ui, p, "New PIN", &mut self.security_keys.change_pin.new);
                            pin_field(ui, p, "Confirm", &mut self.security_keys.change_pin.confirm);
                        } else {
                            pin_field(ui, p, "Current PIN", &mut self.security_keys.change_pin.old);
                            pin_field(ui, p, "New PIN", &mut self.security_keys.change_pin.new);
                        }
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            if theme::button(ui, p, BtnKind::Primary, if setting { "Set PIN" } else { "Change PIN" }).clicked() {
                                if setting {
                                    go_set = true;
                                } else {
                                    go_change = true;
                                }
                            }
                            ui.add_space(6.0);
                            if theme::button(ui, p, BtnKind::Ghost, "Cancel").clicked() {
                                cancel = true;
                            }
                        });
                        ui.add_space(4.0);
                        ui.label(egui::RichText::new("4\u{2013}63 characters. You'll touch the key to confirm.").font(theme::f_reg(11.5)).color(p.txt3));
                    });
            }

            if let Some(err) = &self.security_keys.error {
                ui.add_space(6.0);
                ui.colored_label(p.err, err);
            }
        });
        if cancel {
            self.security_keys.change_pin = ChangePinDialog::default();
        }
        if go_set {
            self.submit_set_pin();
        }
        if go_change {
            self.submit_change_pin();
        }

        // --- Resident passkeys (only meaningful once a PIN exists) ---
        if pin_set == Some(true) {
            ui.add_space(14.0);
            let mut lock = false;
            let mut reload = false;
            let mut unlock = false;
            let mut delete: Option<Vec<u8>> = None;
            theme::card_frame(p).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Resident passkeys").font(theme::f_sb(14.5)).color(p.txt));
                    ui.add_space(6.0);
                    self.help_dot(ui, p, "passkeys");
                    if self.security_keys.session.is_some() {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if theme::button(ui, p, BtnKind::Ghost, "Lock").clicked() {
                                lock = true;
                            }
                            ui.add_space(6.0);
                            if theme::button(ui, p, BtnKind::Default, "Reload").clicked() {
                                reload = true;
                            }
                        });
                    }
                });
                ui.add_space(8.0);
                if self.security_keys.session.is_none() {
                    ui.horizontal(|ui| {
                        let resp = ui.add(
                            egui::TextEdit::singleline(&mut self.security_keys.pin_input)
                                .password(true)
                                .hint_text("Enter PIN to view passkeys")
                                .desired_width(220.0),
                        );
                        let submit = theme::button(ui, p, BtnKind::Primary, "Unlock").clicked();
                        if submit || (resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))) {
                            unlock = true;
                        }
                    });
                } else {
                    let (existing, max_remaining, rps) = {
                        let s = self.security_keys.session.as_ref().expect("checked");
                        (s.metadata.existing_count, s.metadata.max_remaining, s.rps.clone())
                    };
                    ui.label(
                        egui::RichText::new(format!("{existing} stored \u{00B7} room for {max_remaining} more"))
                            .font(theme::f_reg(12.5))
                            .color(p.txt2),
                    );
                    ui.add_space(6.0);
                    egui::ScrollArea::vertical().max_height(320.0).show(ui, |ui| {
                        for (rp, creds) in &rps {
                            let header = if let Some(name) = rp.name.as_ref().filter(|s| !s.is_empty()) {
                                format!("{}  ({})", rp.id, name)
                            } else {
                                rp.id.clone()
                            };
                            ui.collapsing(header, |ui| {
                                if creds.is_empty() {
                                    ui.label("(no credentials)");
                                }
                                for c in creds {
                                    ui.horizontal(|ui| {
                                        ui.monospace(hex_short(&c.credential_id));
                                        let user_field = c
                                            .user
                                            .display_name
                                            .clone()
                                            .or_else(|| c.user.name.clone())
                                            .unwrap_or_else(|| String::from_utf8_lossy(&c.user.id).into_owned());
                                        ui.label(user_field);
                                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                            if theme::button(ui, p, BtnKind::Ghost, "Remove").clicked() {
                                                delete = Some(c.credential_id.clone());
                                            }
                                        });
                                    });
                                }
                            });
                        }
                    });
                }
            });
            if lock {
                self.lock_session();
            }
            if reload {
                self.refresh_credentials();
            }
            if unlock {
                self.try_unlock();
            }
            if let Some(id) = delete {
                self.delete_credential(id);
            }
        }

        // --- Danger: reset key (typed-confirm modal stays) ---
        ui.add_space(14.0);
        let mut arm_reset = false;
        theme::card_frame(p)
            .stroke(egui::Stroke::new(1.0, theme::tint(p.err, 90)))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Reset this key").font(theme::f_sb(14.5)).color(p.err));
                    ui.add_space(6.0);
                    self.help_dot(ui, p, "reset");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if theme::button(ui, p, BtnKind::Danger, "Reset key\u{2026}").clicked() {
                            arm_reset = true;
                        }
                    });
                });
                ui.label(
                    egui::RichText::new("Wipes every passkey and the PIN on this key. Cannot be undone.")
                        .font(theme::f_reg(12.5))
                        .color(p.txt2),
                );
            });
        if arm_reset {
            self.security_keys.reset = ResetDialog { open: true, ..Default::default() };
        }
    }

    /// Authenticator / OATH tab — live codes with countdown rings + copy.
    fn cap_oath(&mut self, ui: &mut egui::Ui, p: &Palette) {
        // Auto-attempt a read once per selection (a hard error won't retry).
        if !self.oath_tried && !self.busy() && self.oath.error.is_none() && !self.oath.locked {
            self.oath_tried = true;
            self.load_oath_creds();
        }
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Authenticator codes").font(theme::f_sb(14.5)).color(p.txt));
            ui.add_space(6.0);
            self.help_dot(ui, p, "oath");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if theme::button(ui, p, BtnKind::Primary, "+ Add credential").clicked() {
                    self.oath.add = OathAddDialog { open: true, totp: true, ..Default::default() };
                }
                ui.add_space(6.0);
                if theme::button(ui, p, BtnKind::Default, "Refresh").clicked() {
                    self.load_oath_creds();
                }
            });
        });
        ui.add_space(12.0);
        if let Some(err) = &self.oath.error {
            ui.colored_label(p.err, err);
            ui.add_space(6.0);
        }
        self.render_oath_add_form(ui);

        if self.oath.locked {
            theme::card_frame(p).show(ui, |ui| {
                ui.label(
                    egui::RichText::new("This key's OATH applet is password-protected.")
                        .font(theme::f_reg(13.0))
                        .color(p.txt),
                );
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.add(egui::TextEdit::singleline(&mut self.oath.password_input).password(true).desired_width(220.0));
                    if theme::button(ui, p, BtnKind::Primary, "Unlock").clicked() {
                        self.load_oath_creds();
                    }
                });
            });
            return;
        }
        if !self.oath.loaded {
            ui.label(egui::RichText::new("Reading codes\u{2026}").font(theme::f_reg(13.0)).color(p.txt3));
            return;
        }
        if self.oath.creds.is_empty() {
            ui.label(egui::RichText::new("No authenticator codes on this key.").font(theme::f_reg(13.0)).color(p.txt3));
            return;
        }

        let mut copy: Option<(String, String)> = None;
        let mut delete: Option<String> = None;
        theme::card_frame(p).show(ui, |ui| {
            let n = self.oath.creds.len();
            for (i, row) in self.oath.creds.iter().enumerate() {
                let is_copied = self.copied.as_ref().map_or(false, |(nm, _)| nm == &row.name);
                let (c, d) = oath_row(ui, p, &row.name, row.code.as_deref(), is_copied, true);
                if let Some(code) = c {
                    copy = Some((row.name.clone(), code));
                }
                if d {
                    delete = Some(row.name.clone());
                }
                if i + 1 < n {
                    ui.add_space(5.0);
                    let y = ui.cursor().top();
                    ui.painter().hline(ui.max_rect().x_range(), y, egui::Stroke::new(1.0, p.line_soft));
                    ui.add_space(5.0);
                }
            }
        });
        if let Some((name, code)) = copy {
            ui.output_mut(|o| o.copied_text = code);
            self.copied = Some((name, now_secs_f64() + 1.2));
        }
        if let Some(name) = delete {
            self.oath.confirm_delete = Some(name);
        }
    }

    /// OpenPGP tab — read-only status + the existing management section.
    fn cap_pgp(&mut self, ui: &mut egui::Ui, p: &Palette) {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("OpenPGP").font(theme::f_sb(14.5)).color(p.txt));
            ui.add_space(6.0);
            self.help_dot(ui, p, "pgp");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if theme::button(ui, p, BtnKind::Default, "Read status").clicked() {
                    self.load_openpgp_status();
                }
            });
        });
        ui.add_space(12.0);
        if let Some(err) = &self.openpgp.error {
            ui.colored_label(p.err, err);
            ui.add_space(6.0);
        }
        if let Some(notice) = &self.openpgp.notice {
            ui.colored_label(p.ok, notice);
            ui.add_space(6.0);
        }
        if let Some(status) = &self.openpgp.status {
            theme::card_frame(p).show(ui, |ui| {
                kv(ui, "AID", &hex_lower(&status.aid));
                if let Some(serial) = status.serial() {
                    kv(ui, "Serial", &format!("{serial} (0x{serial:08X})"));
                }
                kv(ui, "Signature key", &format!("{}  {}", algo_id_label(status.sig_algo_id), fpr_label(&status.fingerprint_sig)));
                kv(ui, "Decryption key", &format!("{}  {}", algo_id_label(status.dec_algo_id), fpr_label(&status.fingerprint_dec)));
                kv(ui, "Authentication key", &format!("{}  {}", algo_id_label(status.aut_algo_id), fpr_label(&status.fingerprint_aut)));
                kv(ui, "PIN retries", &format!("PW1={} RC={} PW3={}", status.tries_pw1, status.tries_rc, status.tries_pw3));
                kv(ui, "Signatures made", &status.signature_count.map_or("(unavailable)".to_string(), |n| n.to_string()));
            });
        } else {
            ui.label(
                egui::RichText::new("Click Read status to read this card (no PIN or touch).")
                    .font(theme::f_reg(13.0))
                    .color(p.txt3),
            );
        }
        ui.add_space(10.0);
        self.render_openpgp_manage(ui);
    }

    /// PIV tab — read-only status snapshot (auto-read on first view).
    fn cap_piv(&mut self, ui: &mut egui::Ui, p: &Palette) {
        if !self.piv_tried && !self.busy() {
            self.piv_tried = true;
            self.load_piv_status();
        }
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("PIV smart card").font(theme::f_sb(14.5)).color(p.txt));
            ui.add_space(6.0);
            self.help_dot(ui, p, "piv");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                theme::pill(ui, "read-only", p.txt3, p.raised2);
                ui.add_space(6.0);
                if theme::button(ui, p, BtnKind::Default, "Refresh").clicked() {
                    self.load_piv_status();
                }
            });
        });
        ui.add_space(12.0);
        if let Some(err) = &self.piv.error {
            ui.colored_label(p.err, err);
            ui.add_space(6.0);
        }
        if let Some(st) = &self.piv.status {
            theme::card_frame(p).show(ui, |ui| {
                kv(ui, "Applet version", &st.version.map_or("\u{2014}".to_string(), |(a, b, c)| format!("{a}.{b}.{c}")));
                kv(ui, "Serial", &st.serial.map_or("\u{2014}".to_string(), |s| s.to_string()));
                kv(ui, "PIN retries", &st.pin_retries.map_or("\u{2014}".to_string(), |n| n.to_string()));
                ui.add_space(6.0);
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing.x = 5.0;
                    for slot in &st.slots {
                        let lab = format!("{:02X} \u{00B7} {}", slot.slot.key_ref(), if slot.cert_present { "cert" } else { "empty" });
                        theme::pill(ui, &lab, p.txt2, p.raised2);
                    }
                });
            });
        } else if self.piv.error.is_none() {
            ui.label(egui::RichText::new("Reading PIV status\u{2026}").font(theme::f_reg(13.0)).color(p.txt3));
        }
    }

    /// The Molto2 token's dedicated amber view: hero band · customer-key strip ·
    /// 100-slot rail + editor.
    fn molto_view(&mut self, ui: &mut egui::Ui, p: &Palette, dev: &UiDevice) {
        // Amber hero band.
        egui::Frame::none()
            .fill(p.brand_soft())
            .inner_margin(egui::Margin::symmetric(26.0, 16.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    glyph_tile(ui, 46.0, p.brand, p.accent_ink, None);
                    ui.add_space(12.0);
                    ui.vertical(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new(dev.title()).font(theme::f_bold(21.0)).color(p.txt));
                            ui.add_space(6.0);
                            theme::pill(ui, "Programmable TOTP token", p.brand, p.panel);
                            ui.add_space(4.0);
                            self.help_dot(ui, p, "molto");
                        });
                        ui.add_space(2.0);
                        let serial = if dev.serial.is_empty() { "\u{2014}".to_string() } else { dev.serial.clone() };
                        ui.label(
                            egui::RichText::new(format!("{} \u{00B7} #{} \u{00B7} {} slots", dev.vendor, serial, PROFILES))
                                .font(theme::f_reg(12.5))
                                .color(p.txt2),
                        );
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if theme::button(ui, p, BtnKind::Default, "Sync time on all").clicked() {
                            self.sync_time_all();
                        }
                    });
                });
            });

        // Customer-key strip.
        egui::Frame::none()
            .inner_margin(egui::Margin::symmetric(26.0, 10.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Customer key").font(theme::f_sb(12.5)).color(p.txt2));
                    ui.add_space(2.0);
                    self.help_dot(ui, p, "custkey");
                    ui.add_space(8.0);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.customer_key_input)
                            .password(true)
                            .hint_text("default if empty")
                            .desired_width(180.0),
                    );
                    ui.checkbox(&mut self.customer_key_hex, "hex");
                    if theme::button(ui, p, BtnKind::Default, "Authenticate").clicked() {
                        self.authenticate();
                    }
                    if self.authenticated {
                        theme::pill(ui, "authed", p.ok, p.ok_soft());
                    }
                });
            });

        // Body: slot rail + editor.
        egui::Frame::none()
            .inner_margin(egui::Margin::symmetric(26.0, 8.0))
            .show(ui, |ui| {
                ui.horizontal_top(|ui| {
                    ui.vertical(|ui| {
                        ui.set_width(200.0);
                        ui.label(egui::RichText::new(format!("SLOTS \u{00B7} {}", PROFILES)).font(theme::f_bold(11.0)).color(p.txt3));
                        ui.add_space(6.0);
                        let mut pick = None;
                        egui::ScrollArea::vertical().auto_shrink([false, false]).max_height(440.0).show(ui, |ui| {
                            for s in 0..PROFILES {
                                let selected = s == self.slot;
                                let (rect, resp) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 32.0), egui::Sense::click());
                                let bg = if selected {
                                    p.brand_soft()
                                } else if resp.hovered() {
                                    p.line_soft
                                } else {
                                    egui::Color32::TRANSPARENT
                                };
                                ui.painter().rect(rect, egui::Rounding::same(8.0), bg, egui::Stroke::NONE);
                                ui.allocate_new_ui(egui::UiBuilder::new().max_rect(rect.shrink2(egui::vec2(10.0, 4.0))), |ui| {
                                    ui.horizontal(|ui| {
                                        ui.label(
                                            egui::RichText::new(format!("{:02}", s))
                                                .font(theme::f_mono(12.0))
                                                .color(if selected { p.brand } else { p.txt3 }),
                                        );
                                        ui.add_space(8.0);
                                        let (text, color) = if selected && !self.draft.title.trim().is_empty() {
                                            (self.draft.title.clone(), p.txt)
                                        } else {
                                            ("empty".to_string(), p.txt3)
                                        };
                                        ui.label(egui::RichText::new(text).font(theme::f_reg(12.5)).color(color));
                                    });
                                });
                                if resp.clicked() {
                                    pick = Some(s);
                                }
                            }
                        });
                        if let Some(s) = pick {
                            self.slot = s;
                        }
                    });

                    ui.add_space(22.0);

                    ui.vertical(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new(format!("SLOT {:02}", self.slot)).font(theme::f_bold(11.0)).color(p.txt3));
                        });
                        ui.add_space(10.0);
                        editor_row(ui, p, "Title", |ui| {
                            ui.add(egui::TextEdit::singleline(&mut self.draft.title).hint_text("\u{2264} 12 chars").desired_width(300.0));
                        });
                        editor_row(ui, p, "Secret", |ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut self.draft.secret_base32)
                                    .password(true)
                                    .hint_text("base32 secret")
                                    .desired_width(300.0),
                            );
                        });
                        editor_row(ui, p, "Algorithm", |ui| {
                            let cur = match self.draft.algorithm {
                                AlgoChoice::Sha1 => "SHA1",
                                AlgoChoice::Sha256 => "SHA256",
                            };
                            if let Some(v) = theme::segmented(ui, p, &["SHA1", "SHA256"], cur, p.brand) {
                                self.draft.algorithm = if v == "SHA256" { AlgoChoice::Sha256 } else { AlgoChoice::Sha1 };
                            }
                        });
                        editor_row(ui, p, "Digits", |ui| {
                            let cur = match self.draft.digits {
                                DigitsChoice::Four => "4",
                                DigitsChoice::Six => "6",
                                DigitsChoice::Eight => "8",
                                DigitsChoice::Ten => "10",
                            };
                            if let Some(v) = theme::segmented(ui, p, &["4", "6", "8", "10"], cur, p.brand) {
                                self.draft.digits = match v.as_str() {
                                    "4" => DigitsChoice::Four,
                                    "8" => DigitsChoice::Eight,
                                    "10" => DigitsChoice::Ten,
                                    _ => DigitsChoice::Six,
                                };
                            }
                        });
                        editor_row(ui, p, "Time step", |ui| {
                            let cur = match self.draft.time_step {
                                StepChoice::S30 => "30s",
                                StepChoice::S60 => "60s",
                            };
                            if let Some(v) = theme::segmented(ui, p, &["30s", "60s"], cur, p.brand) {
                                self.draft.time_step = if v == "60s" { StepChoice::S60 } else { StepChoice::S30 };
                            }
                        });
                        editor_row(ui, p, "Display", |ui| {
                            let cur = match self.draft.display_timeout {
                                TimeoutChoice::S15 => "15s",
                                TimeoutChoice::S30 => "30s",
                                TimeoutChoice::S60 => "60s",
                                TimeoutChoice::S120 => "120s",
                            };
                            if let Some(v) = theme::segmented(ui, p, &["15s", "30s", "60s", "120s"], cur, p.brand) {
                                self.draft.display_timeout = match v.as_str() {
                                    "15s" => TimeoutChoice::S15,
                                    "60s" => TimeoutChoice::S60,
                                    "120s" => TimeoutChoice::S120,
                                    _ => TimeoutChoice::S30,
                                };
                            }
                        });
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            if theme::button(ui, p, BtnKind::Primary, "Write to slot").clicked() {
                                self.apply_draft();
                            }
                            ui.add_space(6.0);
                            if theme::button(ui, p, BtnKind::Default, "Import otpauth\u{2026}").clicked() {
                                self.import_dialog.open = true;
                            }
                            ui.add_space(6.0);
                            if theme::button(ui, p, BtnKind::Default, "Bulk import\u{2026}").clicked() {
                                self.bulk_dialog.open = true;
                                self.bulk_dialog.start = self.slot;
                            }
                            ui.add_space(6.0);
                            if theme::button(ui, p, BtnKind::Default, "Sync time").clicked() {
                                self.sync_time_selected();
                            }
                            ui.add_space(6.0);
                            if theme::button(ui, p, BtnKind::Danger, "Factory reset\u{2026}").clicked() {
                                self.molto_reset_confirm = true;
                            }
                        });
                        if self.molto_reset_confirm {
                            ui.add_space(10.0);
                            egui::Frame::none()
                                .fill(p.err_soft())
                                .inner_margin(egui::Margin::same(12.0))
                                .rounding(egui::Rounding::same(8.0))
                                .show(ui, |ui| {
                                    ui.label(
                                        egui::RichText::new(
                                            "Factory-reset the token? This wipes all slots, then asks you to confirm with the \u{25B2} button on the device itself.",
                                        )
                                        .font(theme::f_reg(12.5))
                                        .color(p.txt),
                                    );
                                    ui.add_space(8.0);
                                    ui.horizontal(|ui| {
                                        if theme::button(ui, p, BtnKind::Danger, "Yes, factory reset").clicked() {
                                            self.molto_reset_confirm = false;
                                            self.factory_reset();
                                        }
                                        ui.add_space(6.0);
                                        if theme::button(ui, p, BtnKind::Ghost, "Cancel").clicked() {
                                            self.molto_reset_confirm = false;
                                        }
                                    });
                                });
                        }
                    });
                });
            });
    }

    /// The Molto2 import dialogs (otpauth:// + bulk). Reused verbatim from the
    /// original Molto2 view; only the entry point changed.
    fn molto_dialogs(&mut self, ctx: &egui::Context, _p: &Palette) {
        if self.bulk_dialog.open {
            let mut open = self.bulk_dialog.open;
            let mut do_load = false;
            let mut do_apply = false;
            egui::Window::new("Bulk import")
                .open(&mut open)
                .collapsible(false)
                .default_width(560.0)
                .show(ctx, |ui| {
                    ui.label("Export file path (Aegis JSON [plain or encrypted], 2FAS JSON, or otpauth:// list):");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.bulk_dialog.path)
                            .desired_width(540.0)
                            .hint_text("/path/to/export.json"),
                    );
                    if self.bulk_dialog.needs_password {
                        ui.label("Aegis vault password:");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.bulk_dialog.password)
                                .password(true)
                                .desired_width(360.0),
                        );
                    }
                    ui.horizontal(|ui| {
                        if ui.button("Load").clicked() {
                            do_load = true;
                        }
                        ui.label("Start at profile:");
                        ui.add(
                            egui::DragValue::new(&mut self.bulk_dialog.start)
                                .clamp_existing_to_range(true)
                                .range(0..=99u8),
                        );
                        ui.label("Display timeout:");
                        egui::ComboBox::from_id_salt("bulk-timeout")
                            .selected_text(match self.bulk_dialog.display_timeout {
                                TimeoutChoice::S15 => "15s",
                                TimeoutChoice::S30 => "30s",
                                TimeoutChoice::S60 => "60s",
                                TimeoutChoice::S120 => "120s",
                            })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut self.bulk_dialog.display_timeout,
                                    TimeoutChoice::S15,
                                    "15s",
                                );
                                ui.selectable_value(
                                    &mut self.bulk_dialog.display_timeout,
                                    TimeoutChoice::S30,
                                    "30s",
                                );
                                ui.selectable_value(
                                    &mut self.bulk_dialog.display_timeout,
                                    TimeoutChoice::S60,
                                    "60s",
                                );
                                ui.selectable_value(
                                    &mut self.bulk_dialog.display_timeout,
                                    TimeoutChoice::S120,
                                    "120s",
                                );
                            });
                    });

                    if let Some(err) = &self.bulk_dialog.error {
                        ui.colored_label(egui::Color32::from_rgb(220, 100, 100), err);
                    }

                    if !self.bulk_dialog.entries.is_empty() {
                        ui.separator();
                        ui.label(format!(
                            "{} entries — will fill slots #{:02}..#{:02}",
                            self.bulk_dialog.entries.len(),
                            self.bulk_dialog.start,
                            self.bulk_dialog.start as usize + self.bulk_dialog.entries.len() - 1,
                        ));
                        egui::ScrollArea::vertical()
                            .max_height(220.0)
                            .show(ui, |ui| {
                                for (i, e) in self.bulk_dialog.entries.iter().enumerate() {
                                    let slot = self.bulk_dialog.start as usize + i;
                                    ui.label(format!(
                                        "#{:02}  {}  ({}/{:?}/{}d)",
                                        slot,
                                        e.suggested_title(),
                                        match e.algorithm {
                                            HmacAlgo::Sha1 => "SHA1",
                                            HmacAlgo::Sha256 => "SHA256",
                                        },
                                        e.time_step,
                                        e.digits as u8
                                    ));
                                }
                            });
                        ui.horizontal(|ui| {
                            let can_apply = self.authenticated;
                            if ui
                                .add_enabled(can_apply, egui::Button::new("Program all"))
                                .on_hover_text("Write seed, title, and config for every entry")
                                .clicked()
                            {
                                do_apply = true;
                            }
                            if ui.button("Close").clicked() {
                                self.bulk_dialog.open = false;
                            }
                        });
                    }
                });
            self.bulk_dialog.open = open;
            if do_load {
                self.bulk_load();
            }
            if do_apply {
                self.bulk_apply();
            }
        }

        if self.import_dialog.open {
            let mut open = self.import_dialog.open;
            let mut should_apply = false;
            egui::Window::new(format!("Import to profile #{:02}", self.slot))
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label("Paste an otpauth:// URI:");
                    ui.add(
                        egui::TextEdit::multiline(&mut self.import_dialog.uri)
                            .desired_rows(3)
                            .desired_width(420.0)
                            .font(egui::TextStyle::Monospace),
                    );
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        if ui.button("Parse & populate fields").clicked() {
                            should_apply = true;
                        }
                        if ui.button("Cancel").clicked() {
                            self.import_dialog.open = false;
                            self.import_dialog.uri.clear();
                        }
                    });
                });
            self.import_dialog.open = open;
            if should_apply {
                self.import_otpauth();
            }
        }
    }
}

/// Paint one OATH credential row: issuer/account · code · countdown ring ·
/// seconds · copy (· delete). Returns `(Some(code) if copy clicked, delete?)`.
fn oath_row(
    ui: &mut egui::Ui,
    p: &Palette,
    name: &str,
    code: Option<&str>,
    is_copied: bool,
    with_delete: bool,
) -> (Option<String>, bool) {
    let (issuer, account) = match name.split_once(':') {
        Some((a, b)) => (a.to_string(), b.to_string()),
        None => (name.to_string(), String::new()),
    };
    let (secs, pct) = theme::totp_window(30);
    let code_color = if secs <= 5 { p.warn } else { p.accent };
    let mut copy = None;
    let mut delete = false;
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.label(egui::RichText::new(issuer).font(theme::f_sb(13.5)).color(p.txt));
            if !account.is_empty() {
                ui.label(egui::RichText::new(account).font(theme::f_reg(12.0)).color(p.txt3));
            }
        });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if with_delete {
                if ui
                    .add(
                        egui::Label::new(egui::RichText::new("\u{2715}").font(theme::f_reg(13.0)).color(p.txt3))
                            .sense(egui::Sense::click()),
                    )
                    .on_hover_text("Delete")
                    .clicked()
                {
                    delete = true;
                }
                ui.add_space(8.0);
            }
            let glyph = if is_copied { "\u{2713}" } else { "\u{29C9}" };
            let gcolor = if is_copied { p.ok } else { p.txt3 };
            if ui
                .add(egui::Label::new(egui::RichText::new(glyph).font(theme::f_reg(15.0)).color(gcolor)).sense(egui::Sense::click()))
                .on_hover_text("Copy code")
                .clicked()
            {
                if let Some(c) = code {
                    copy = Some(c.to_string());
                }
            }
            ui.add_space(10.0);
            ui.label(egui::RichText::new(format!("{secs}s")).font(theme::f_reg(11.0)).color(p.txt3));
            ui.add_space(5.0);
            theme::ring(ui, pct, 20.0, code_color, p.line);
            ui.add_space(14.0);
            match code {
                Some(c) => {
                    ui.label(egui::RichText::new(c).font(theme::f_mono(19.0)).color(code_color));
                }
                None => {
                    ui.label(egui::RichText::new("touch").font(theme::f_reg(13.0)).color(p.txt3));
                }
            }
        });
    });
    (copy, delete)
}

/// One labelled editor row in the Molto2 form: fixed-width label + a field.
fn editor_row(ui: &mut egui::Ui, p: &Palette, label: &str, add: impl FnOnce(&mut egui::Ui)) {
    ui.horizontal(|ui| {
        ui.add_sized(
            [92.0, 22.0],
            egui::Label::new(egui::RichText::new(label).font(theme::f_reg(13.0)).color(p.txt2)),
        );
        add(ui);
    });
    ui.add_space(8.0);
}

/// Summarize an OpenPGP key slot: its algorithm label, or "empty" when no key.
fn slot_summary(algo: Option<u8>, fpr: &[u8; 20]) -> &'static str {
    if fpr.iter().all(|&b| b == 0) {
        "empty"
    } else {
        algo_id_label(algo)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A job dispatched to a real worker thread runs off-thread, and its result
    /// applies back to the App with the busy bookkeeping cleared.
    #[test]
    fn worker_round_trip_applies_result_and_clears_busy() {
        let mut app = App {
            worker: Some(Worker::spawn(egui::Context::default())),
            ..Default::default()
        };
        app.spawn_job("test", || Box::new(|app: &mut App| app.slot = 42));
        assert!(app.busy(), "busy should be set right after dispatch");

        // Wait for the worker to produce a result, then drain it.
        let worker = app.worker.as_ref().unwrap();
        let apply = worker
            .result_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("worker produced a result");
        // Mimic drain_worker: decrement before applying.
        app.busy_jobs -= 1;
        apply(&mut app);

        assert_eq!(app.slot, 42);
        assert!(!app.busy(), "busy should clear once the result is applied");
    }

    /// While a job is in flight, a second dispatch is dropped (device access is
    /// serialized; rapid clicks don't queue overlapping card I/O).
    #[test]
    fn spawn_job_ignored_while_busy() {
        let mut app = App {
            worker: Some(Worker::spawn(egui::Context::default())),
            ..Default::default()
        };
        // Occupy the worker with a job whose result we don't drain.
        app.spawn_job("first", || Box::new(|_: &mut App| {}));
        assert_eq!(app.busy_jobs, 1);
        app.spawn_job("second", || Box::new(|app: &mut App| app.slot = 99));
        assert_eq!(
            app.busy_jobs, 1,
            "second dispatch must be ignored while busy"
        );
    }

    /// With no worker (the default), a job runs inline so headless tests and any
    /// non-GUI use still apply results.
    #[test]
    fn inline_when_no_worker() {
        let mut app = App::default();
        assert!(app.worker.is_none());
        app.spawn_job("inline", || Box::new(|app: &mut App| app.slot = 7));
        assert_eq!(app.slot, 7);
        assert!(!app.busy());
    }
}
