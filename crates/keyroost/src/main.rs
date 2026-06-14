//! keyroost — desktop GUI for programming Token2 Molto2 / Molto2v2 tokens.
//!
//! Dark-themed by default, modeled loosely on Token2's PyQt5 layout: device
//! status across the top, 100-slot grid on the left, edit form on the right.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::time::{SystemTime, UNIX_EPOCH};

mod otp_pane;
mod ui;
use otp_pane::OtpState;
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
    /// CTAP info for the selected device, fetched lazily after selection.
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

/// "Armed" reset: a FIDO authenticator only accepts a reset within ~10 s of
/// being powered on, which the plug-then-navigate-then-confirm flow can never
/// hit. So we confirm intent first, then watch for the user to unplug and
/// replug the key and fire the reset the instant it reconnects. Polled in
/// `update()` against the live FIDO HID list (no PC/SC, so it can't disturb
/// other cards).
struct ResetArm {
    /// The armed key's USB/HID serial, if it exposes one (SoloKeys / Nitrokey
    /// do; most YubiKeys don't). When present we track the key by serial, so it
    /// is recognised on re-insertion into *any* USB port, not just the same one.
    target_serial: Option<String>,
    /// The armed key's HID path at arm time. Used as the identity when there is
    /// no serial (`target_serial` is `None`): its disappearance is the "unplug"
    /// half of the dance, and a fresh path is treated as the re-insert.
    target_path: Option<std::path::PathBuf>,
    /// The armed key's USB vendor/product ids, captured at arm time. In path
    /// mode a fresh path must match these — so plugging in a *different*
    /// model while a reset is armed doesn't get it reset by mistake.
    target_ids: Option<(u16, u16)>,
    /// FIDO HID paths present at the previous poll, to diff against (path mode).
    prev_paths: Vec<std::path::PathBuf>,
    /// True once the armed key has been unplugged; the next fresh insertion then
    /// fires the reset.
    saw_removal: bool,
}

struct UnlockedSession {
    token: PinUvAuthToken,
    metadata: CredsMetadata,
    /// Behind an `Arc`: the pane clones this every frame to escape the borrow
    /// of `self`, and credential lists (ids, user blobs) are not per-frame
    /// clone material.
    rps: std::sync::Arc<Vec<(RelyingParty, Vec<Credential>)>>,
}

/// One FIDO HID device as the armed-reset poll sees it.
struct FidoHid {
    path: std::path::PathBuf,
    serial: Option<String>,
    ids: (u16, u16),
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

// The form is replaced wholesale after submit; wipe the typed seed on drop.
impl Drop for OathAddDialog {
    fn drop(&mut self) {
        wipe(&mut self.secret);
    }
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
    /// Change-user-PIN (PW1) old/new entries. Cleared after use.
    user_pin_old: String,
    user_pin_new: String,
    /// Change-admin-PIN (PW3) old/new entries. Cleared after use.
    admin_pin_old: String,
    admin_pin_new: String,
    /// New user PIN for the unblock flow (reset retry counter); authorised by
    /// `admin_pin`. Cleared after use.
    unblock_new: String,
}

impl OpenPgpState {
    /// Zeroize every PIN entry field. Called when the selection changes (a PIN
    /// typed for one card must not ride along to another) and on drop.
    fn wipe_secrets(&mut self) {
        wipe(&mut self.admin_pin);
        wipe(&mut self.user_pin_old);
        wipe(&mut self.user_pin_new);
        wipe(&mut self.admin_pin_old);
        wipe(&mut self.admin_pin_new);
        wipe(&mut self.unblock_new);
    }
}

/// Zeroize a secret-bearing text field (wipes the bytes, then leaves the
/// string empty — strictly better than `.clear()`, which only resets the
/// length and leaves the secret in the buffer).
fn wipe(s: &mut String) {
    use zeroize::Zeroize;
    s.zeroize();
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
    fn from_label(s: &str) -> Self {
        match s {
            "decryption" => OpenPgpSlotSel::Decrypt,
            "authentication" => OpenPgpSlotSel::Auth,
            _ => OpenPgpSlotSel::Sign,
        }
    }
}

/// State for the PIV pane: a status snapshot plus the entry fields for the full
/// management surface (PIN/PUK, management key, key generation, certificate
/// import/export, reset), keyed by the selected device's reader name.
struct PivState {
    /// Last status read from the selected card.
    status: Option<keyroost_transport::PivStatus>,
    /// User-facing error from the last read/write.
    error: Option<String>,
    /// Success/info line from the last write operation.
    notice: Option<String>,
    /// True once a status has been fetched for the current selection.
    loaded: bool,
    /// Management key (hex) entered to authorize key-gen / cert-import /
    /// set-retries / management-key change. Cleared after use.
    mgmt_key_input: String,
    /// Change-PIN old/new entries. Cleared after use.
    pin_old: String,
    pin_new: String,
    /// Change-PUK old/new entries. Cleared after use.
    puk_old: String,
    puk_new: String,
    /// Unblock-PIN: PUK + new PIN entries. Cleared after use.
    unblock_puk: String,
    unblock_new_pin: String,
    /// PIN/PUK retry counts for set-retries, and the PIN that authorizes it.
    retries_pin: u8,
    retries_puk: u8,
    retries_pin_auth: String,
    /// Key-generation slot + algorithm selectors.
    gen_slot: PivSlotSel,
    gen_alg: PivKeyAlgSel,
    /// PEM of the most recently generated public key, shown for copying.
    gen_pubkey_pem: Option<String>,
    /// Certificate import slot + file path.
    cert_slot: PivSlotSel,
    cert_path: String,
    /// Certificate export slot + destination path.
    export_slot: PivSlotSel,
    export_path: String,
    /// New management key (hex) + algorithm for a management-key rotation.
    new_mgmt_key_input: String,
    new_mgmt_alg: PivMgmtAlgSel,
    /// Certificate creation: slot, subject (bare name or full DN), validity,
    /// the PIN that authorizes the on-card signature, and the CSR destination.
    certify_slot: PivSlotSel,
    cert_subject: String,
    cert_days: u32,
    sign_pin: String,
    csr_path: String,
    /// Reset confirmation modal: typed-`reset` text (modal open iff `Some`).
    confirm_reset: Option<String>,
}

// The pane is replaced wholesale on device switch (`self.piv =
// PivState::default()`); wiping on drop means the discarded fields don't
// leave PINs/keys in freed memory.
impl Drop for PivState {
    fn drop(&mut self) {
        wipe(&mut self.mgmt_key_input);
        wipe(&mut self.pin_old);
        wipe(&mut self.pin_new);
        wipe(&mut self.puk_old);
        wipe(&mut self.puk_new);
        wipe(&mut self.unblock_puk);
        wipe(&mut self.unblock_new_pin);
        wipe(&mut self.retries_pin_auth);
        wipe(&mut self.new_mgmt_key_input);
        wipe(&mut self.sign_pin);
    }
}

impl Default for PivState {
    fn default() -> Self {
        PivState {
            status: None,
            error: None,
            notice: None,
            loaded: false,
            mgmt_key_input: String::new(),
            pin_old: String::new(),
            pin_new: String::new(),
            puk_old: String::new(),
            puk_new: String::new(),
            unblock_puk: String::new(),
            unblock_new_pin: String::new(),
            retries_pin: 3,
            retries_puk: 3,
            retries_pin_auth: String::new(),
            gen_slot: PivSlotSel::default(),
            gen_alg: PivKeyAlgSel::default(),
            gen_pubkey_pem: None,
            cert_slot: PivSlotSel::default(),
            cert_path: String::new(),
            export_slot: PivSlotSel::default(),
            export_path: String::new(),
            new_mgmt_key_input: String::new(),
            new_mgmt_alg: PivMgmtAlgSel::default(),
            certify_slot: PivSlotSel::default(),
            cert_subject: String::new(),
            cert_days: 365,
            sign_pin: String::new(),
            csr_path: String::new(),
            confirm_reset: None,
        }
    }
}

/// PIV key-slot selector for the GUI controls.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum PivSlotSel {
    #[default]
    Auth,
    Sign,
    KeyMgmt,
    CardAuth,
}

impl PivSlotSel {
    fn to_slot(self) -> keyroost_piv::Slot {
        match self {
            PivSlotSel::Auth => keyroost_piv::Slot::Authentication,
            PivSlotSel::Sign => keyroost_piv::Slot::Signature,
            PivSlotSel::KeyMgmt => keyroost_piv::Slot::KeyManagement,
            PivSlotSel::CardAuth => keyroost_piv::Slot::CardAuthentication,
        }
    }
    fn label(self) -> &'static str {
        self.to_slot().label()
    }
    const ALL: [PivSlotSel; 4] = [
        PivSlotSel::Auth,
        PivSlotSel::Sign,
        PivSlotSel::KeyMgmt,
        PivSlotSel::CardAuth,
    ];
}

/// PIV key-generation algorithm selector.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum PivKeyAlgSel {
    #[default]
    EccP256,
    EccP384,
    Rsa2048,
    Rsa3072,
    Rsa4096,
    Ed25519,
}

impl PivKeyAlgSel {
    fn to_alg(self) -> keyroost_piv::KeyAlg {
        use keyroost_piv::KeyAlg::*;
        match self {
            PivKeyAlgSel::EccP256 => EccP256,
            PivKeyAlgSel::EccP384 => EccP384,
            PivKeyAlgSel::Rsa2048 => Rsa2048,
            PivKeyAlgSel::Rsa3072 => Rsa3072,
            PivKeyAlgSel::Rsa4096 => Rsa4096,
            PivKeyAlgSel::Ed25519 => Ed25519,
        }
    }
    fn label(self) -> &'static str {
        self.to_alg().label()
    }
    const ALL: [PivKeyAlgSel; 6] = [
        PivKeyAlgSel::EccP256,
        PivKeyAlgSel::EccP384,
        PivKeyAlgSel::Rsa2048,
        PivKeyAlgSel::Rsa3072,
        PivKeyAlgSel::Rsa4096,
        PivKeyAlgSel::Ed25519,
    ];
}

/// PIV management-key algorithm selector (for rotation).
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum PivMgmtAlgSel {
    #[default]
    Aes192,
    Aes128,
    Aes256,
    TripleDes,
}

impl PivMgmtAlgSel {
    fn to_alg(self) -> keyroost_piv::MgmtAlg {
        use keyroost_piv::MgmtAlg::*;
        match self {
            PivMgmtAlgSel::Aes192 => Aes192,
            PivMgmtAlgSel::Aes128 => Aes128,
            PivMgmtAlgSel::Aes256 => Aes256,
            PivMgmtAlgSel::TripleDes => TripleDes,
        }
    }
    fn label(self) -> &'static str {
        self.to_alg().label()
    }
    const ALL: [PivMgmtAlgSel; 4] = [
        PivMgmtAlgSel::Aes192,
        PivMgmtAlgSel::Aes128,
        PivMgmtAlgSel::Aes256,
        PivMgmtAlgSel::TripleDes,
    ];
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
            let (mode, accent_idx, colorblind) = cc
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
                    let colorblind = s.get_string("colorblind").as_deref() == Some("1");
                    (mode, accent_idx, colorblind)
                })
                .unwrap_or((Mode::Dark, 0, false));
            Palette::new(mode, Palette::ACCENTS[accent_idx], colorblind).apply(&cc.egui_ctx, mode);
            // Watch for reader hotplug so already-plugged-in or newly-inserted
            // devices appear without a manual Refresh. The watcher only flags a
            // shared bit and wakes the frame loop; `update()` does the rescan.
            let devices_dirty = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let reader_watch = {
                let dirty = devices_dirty.clone();
                let egui_ctx = cc.egui_ctx.clone();
                keyroost_transport::ReaderWatcher::spawn(move || {
                    dirty.store(true, std::sync::atomic::Ordering::Relaxed);
                    egui_ctx.request_repaint();
                })
            };
            let app = App {
                mode,
                accent_idx,
                colorblind,
                worker: Some(Worker::spawn(cc.egui_ctx.clone())),
                egui_ctx: Some(cc.egui_ctx.clone()),
                devices_dirty,
                reader_watch: Some(reader_watch),
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
    /// When set: the OTP code we placed on the clipboard and the time
    /// (now_secs_f64 epoch) to clear it — codes shouldn't sit in
    /// clipboard-manager history forever. Cleared conditionally: only if the
    /// clipboard still holds that exact code.
    clipboard_clear_at: Option<(String, f64)>,
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
    /// Token2 on-device OTP (TOTP/HOTP) view state.
    otp: OtpState,
    /// Dark / light theme (persisted via eframe storage).
    mode: Mode,
    /// Accent index into `Palette::ACCENTS` (persisted).
    accent_idx: usize,
    /// Colorblind-safe palette (blue/vermillion status colors) — persisted.
    colorblind: bool,
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
    /// Same guard for the OTP pane's auto-read.
    otp_tried: bool,
    /// True while the Molto2 factory-reset confirmation is showing.
    molto_reset_confirm: bool,
    /// True while the selected device's inline rename field is open.
    rename_open: bool,
    /// Friendly-name draft for the selected device.
    rename_input: String,
    /// Background worker for blocking device I/O. `None` only in tests.
    worker: Option<Worker>,
    /// Number of in-flight background jobs. While >0 the UI shows a spinner and
    /// disables actions that would issue overlapping device I/O.
    busy_jobs: u32,
    /// Human-readable description of what the worker is currently doing.
    busy_label: Option<String>,
    /// Set by the reader watcher on a PC/SC hotplug; consumed in `update()` to
    /// trigger a re-enumeration. Shared with the watcher thread.
    devices_dirty: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// While `Some`, a FIDO reset is armed and waiting for the key to be
    /// unplugged and plugged back in (see [`ResetArm`]).
    reset_arm: Option<ResetArm>,
    /// Remaining scans in the current burst. A single scan races slow-to-
    /// register readers (the Molto2's CCID interface appears in pcscd a beat
    /// after the USB device), so startup and every hotplug schedule several
    /// staggered rescans instead of one.
    pending_scans: u8,
    /// When the next burst scan is due.
    next_scan_at: Option<std::time::Instant>,
    /// Background PC/SC hotplug watcher. `None` in tests / if it can't start.
    /// Held only to keep the thread alive; dropped on app exit.
    #[allow(dead_code)]
    reader_watch: Option<keyroost_transport::ReaderWatcher>,
    /// Result channel of the in-flight bulk-import stage (QR decode, vault
    /// decrypt, export parse). `Some` while one is running — these can take
    /// seconds (scrypt: minutes at the caps) and run on their own thread so
    /// they block neither the frame loop nor the device worker. One at a time.
    import_rx: Option<std::sync::mpsc::Receiver<ApplyFn>>,
    /// What the import thread is doing, for the dialog's progress row.
    import_label: Option<String>,
    /// Frame-loop handle for waking egui from helper threads. `None` in tests.
    egui_ctx: Option<egui::Context>,
    /// The `(mode, accent, colorblind)` triple whose Visuals are currently
    /// applied to the egui context — re-applied on change, not per frame.
    applied_theme: Option<(Mode, usize, bool)>,
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
    /// Returns `false` when the job was *not* queued (a job is already in
    /// flight, or the worker died). Callers that consumed user state to build
    /// the job — a typed PIN, a confirmed modal, a one-shot arm — must check
    /// the return and keep (or restore) that state on `false`, otherwise a
    /// click during a background read silently swallows the action.
    fn spawn_job<F>(&mut self, label: impl Into<String>, job: F) -> bool
    where
        F: FnOnce() -> ApplyFn + Send + 'static,
    {
        // Serialize device access: ignore a new job while one is in flight rather
        // than queueing overlapping card I/O behind a click the user can't see
        // landed. (A single worker thread would serialize anyway, but this also
        // stops a growing backlog of duplicate refreshes from rapid clicks.)
        if self.busy() {
            return false;
        }
        match &self.worker {
            Some(worker) => {
                self.busy_jobs += 1;
                self.busy_label = Some(label.into());
                if worker.job_tx.send(Box::new(job)).is_err() {
                    // Worker died; undo the bookkeeping so the UI doesn't hang.
                    self.busy_jobs -= 1;
                    self.busy_label = None;
                    return false;
                }
                true
            }
            None => {
                let apply = job();
                apply(self);
                true
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

    /// True while a bulk-import stage runs on its own thread.
    fn import_busy(&self) -> bool {
        self.import_rx.is_some()
    }

    /// Run a bulk-import stage (QR decode / vault decrypt / export parse) on a
    /// dedicated thread. Not `spawn_job`: that queue serializes device I/O,
    /// and a multi-second scrypt must not park card operations behind it.
    fn run_import<F>(&mut self, label: impl Into<String>, job: F)
    where
        F: FnOnce() -> ApplyFn + Send + 'static,
    {
        if self.import_busy() {
            return;
        }
        let Some(ctx) = self.egui_ctx.clone() else {
            // Tests: no frame loop to wake; run inline.
            let apply = job();
            apply(self);
            return;
        };
        let (tx, rx) = std::sync::mpsc::channel::<ApplyFn>();
        let spawned = std::thread::Builder::new()
            .name("keyroost-import".into())
            .spawn(move || {
                let apply = job();
                if tx.send(apply).is_ok() {
                    ctx.request_repaint(); // wake the frame loop to apply it
                }
            });
        match spawned {
            Ok(_) => {
                self.import_rx = Some(rx);
                self.import_label = Some(label.into());
            }
            Err(e) => {
                self.bulk_dialog.error = Some(format!("could not start import thread: {}", e));
            }
        }
    }

    /// Apply a finished bulk-import stage. Called once per frame from
    /// `update()`, alongside `drain_worker`.
    fn drain_import(&mut self) {
        let received = match &self.import_rx {
            Some(rx) => rx.try_recv(),
            None => return,
        };
        match received {
            Ok(apply) => {
                self.import_rx = None;
                self.import_label = None;
                apply(self);
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                // Import thread died (panicked) without sending a result.
                self.import_rx = None;
                self.import_label = None;
                self.bulk_dialog.error = Some("import failed unexpectedly".into());
            }
        }
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

    /// Take the Molto2 session so a worker job can use it (the apply step
    /// hands it back). `None` — with the reason logged — when not connected;
    /// silently `None` while another job runs, so a click during a background
    /// read is dropped *before* any state is consumed.
    fn take_molto_session(&mut self) -> Option<Session> {
        if self.busy() {
            return None;
        }
        match self.session.take() {
            Some(s) => Some(s),
            None => {
                self.log(Severity::Warn, "not connected");
                None
            }
        }
    }

    fn authenticate(&mut self) {
        let key = match self.customer_key_bytes() {
            Ok(k) => zeroize::Zeroizing::new(k),
            Err(e) => {
                self.log(Severity::Err, e);
                return;
            }
        };
        let Some(mut s) = self.take_molto_session() else {
            return;
        };
        self.spawn_job("Authenticating\u{2026}", move || {
            let result = s.authenticate(&key);
            Box::new(move |app: &mut App| {
                app.session = Some(s);
                match result {
                    Ok(()) => {
                        app.authenticated = true;
                        app.log(Severity::Ok, "authenticated");
                    }
                    Err(TransportError::AuthFailed { tries_remaining }) => {
                        app.log(
                            Severity::Err,
                            format!(
                                "authentication failed (wrong customer key); {} attempt(s) left",
                                tries_remaining
                            ),
                        );
                    }
                    Err(e) => app.log(Severity::Err, format!("auth failed: {}", e)),
                }
            })
        });
    }

    fn apply_draft(&mut self) {
        if !self.ensure_auth() {
            return;
        }
        let secret = match keyroost_proto::codec::base32_decode(&self.draft.secret_base32) {
            Ok(s) if !s.is_empty() && s.len() <= 63 => zeroize::Zeroizing::new(s),
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
        let Some(mut s) = self.take_molto_session() else {
            return;
        };
        self.spawn_job(format!("Writing profile #{p}\u{2026}"), move || {
            let result = s
                .set_seed(p, &secret)
                .map_err(|e| format!("set_seed #{}: {}", p, e))
                .and_then(|()| {
                    s.set_title(p, &title)
                        .map_err(|e| format!("set_title #{}: {}", p, e))
                })
                .and_then(|()| {
                    s.set_config(p, &cfg)
                        .map_err(|e| format!("set_config #{}: {}", p, e))
                });
            Box::new(move |app: &mut App| {
                app.session = Some(s);
                match result {
                    Ok(()) => {
                        // The seed now lives on the device; keeping it in the
                        // (masked) field for the app's lifetime is pure
                        // liability. Title/config drafts stay — convenient for
                        // programming a run of similar slots.
                        wipe(&mut app.draft.secret_base32);
                        app.log(Severity::Ok, format!("profile #{} written", p));
                    }
                    Err(e) => app.log(Severity::Err, e),
                }
            })
        });
    }

    fn sync_time_selected(&mut self) {
        if !self.ensure_auth() {
            return;
        }
        let p = self.slot;
        let Some(mut s) = self.take_molto_session() else {
            return;
        };
        self.spawn_job("Syncing time\u{2026}", move || {
            let result = s.sync_time(p, unix_now());
            Box::new(move |app: &mut App| {
                app.session = Some(s);
                match result {
                    Ok(()) => app.log(Severity::Ok, format!("time synced on #{}", p)),
                    Err(e) => app.log(Severity::Err, format!("sync_time #{}: {}", p, e)),
                }
            })
        });
    }

    fn sync_time_all(&mut self) {
        if !self.ensure_auth() {
            return;
        }
        let Some(mut s) = self.take_molto_session() else {
            return;
        };
        // 100 slots × one APDU each — emphatically not frame-loop work.
        self.spawn_job("Syncing time on all profiles\u{2026}", move || {
            let mut ok = 0;
            let mut fail = 0;
            for p in 0..PROFILES {
                match s.sync_time(p, unix_now()) {
                    Ok(()) => ok += 1,
                    Err(_) => fail += 1,
                }
            }
            Box::new(move |app: &mut App| {
                app.session = Some(s);
                let sev = if fail == 0 {
                    Severity::Ok
                } else {
                    Severity::Warn
                };
                app.log(sev, format!("time-sync-all: {} ok, {} failed", ok, fail));
            })
        });
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
        let Some(mut s) = self.take_molto_session() else {
            return;
        };
        self.spawn_job("Requesting factory reset\u{2026}", move || {
            let result = s.factory_reset();
            Box::new(move |app: &mut App| {
                app.session = Some(s);
                match result {
                    Ok(()) => app.log(
                        Severity::Warn,
                        "factory-reset requested. Confirm with the ▲ button on the device.",
                    ),
                    Err(e) => app.log(Severity::Err, format!("factory_reset: {}", e)),
                }
            })
        });
    }

    fn bulk_load(&mut self) {
        if self.import_busy() {
            return;
        }
        let path = self.bulk_dialog.path.trim().to_owned();
        if path.is_empty() {
            self.bulk_dialog.error = Some("enter a file path first".into());
            return;
        }
        let password = zeroize::Zeroizing::new(self.bulk_dialog.password.clone());
        // Everything below — including the file read (slow media, network
        // mounts) and the format branching — runs on the import thread; the
        // frame loop only ever sees the finished apply step.
        self.run_import("Loading import file\u{2026}", move || {
            let bytes = match std::fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    let msg = format!("read failed: {}", e);
                    return Box::new(move |app: &mut App| app.bulk_dialog.error = Some(msg));
                }
            };

            // Screenshot import: a PNG/JPEG (by magic bytes) goes through QR
            // decode — handles both standard otpauth:// enrollment codes and
            // Google Authenticator export batches.
            if keyroost_qr::looks_like_image(&bytes) {
                let result = keyroost_qr::entries_from_image(&bytes);
                return Box::new(move |app: &mut App| app.bulk_qr_loaded(result));
            }

            // Plaintext exports carry the seeds in clear — wipe-on-drop, same
            // as the decrypted variant.
            let text = match String::from_utf8(bytes) {
                Ok(t) => zeroize::Zeroizing::new(t),
                Err(_) => {
                    return Box::new(move |app: &mut App| {
                        app.bulk_dialog.error =
                            Some("file is neither a text export nor a PNG/JPEG image".into());
                    })
                }
            };

            // An encrypted Aegis vault needs the password; the scrypt KDF is
            // seconds of CPU at stock parameters — exactly why this thread
            // exists.
            let is_encrypted_aegis = keyroost_import::aegis::is_encrypted(&text).unwrap_or(false);
            if is_encrypted_aegis {
                if password.is_empty() {
                    return Box::new(move |app: &mut App| {
                        app.bulk_dialog.needs_password = true;
                        app.bulk_dialog.entries.clear();
                        app.bulk_dialog.error = Some(
                            "encrypted Aegis vault — enter password and click Load again".into(),
                        );
                    });
                }
                let result = match keyroost_import::aegis::decrypt(&text, password.as_bytes()) {
                    Ok(plaintext) => {
                        keyroost_import::parse_bulk_any(&plaintext).map_err(|e| e.to_string())
                    }
                    Err(e) => Err(format!("decrypt: {}", e)),
                };
                return Box::new(move |app: &mut App| {
                    app.bulk_dialog.needs_password = true;
                    app.bulk_text_loaded(result, path);
                });
            }

            let result = keyroost_import::parse_bulk_any(&text).map_err(|e| e.to_string());
            Box::new(move |app: &mut App| {
                app.bulk_dialog.needs_password = false;
                app.bulk_text_loaded(result, path);
            })
        });
    }

    /// Apply a finished QR-image decode to the bulk dialog.
    fn bulk_qr_loaded(&mut self, result: Result<keyroost_qr::QrImport, keyroost_qr::QrError>) {
        match result {
            Ok(import) => {
                self.bulk_dialog.error = None;
                self.bulk_dialog.needs_password = false;
                for s in &import.skipped {
                    self.log(
                        Severity::Err,
                        format!("skipped {:?}: {}", s.label, s.reason),
                    );
                }
                if let Some((i, n)) = import.batch {
                    self.log(
                        Severity::Info,
                        format!(
                            "this is QR {} of {} in the export — load the others too",
                            i + 1,
                            n
                        ),
                    );
                }
                self.log(
                    Severity::Info,
                    format!(
                        "loaded {} entries from QR image — delete the screenshot after a \
                         successful import",
                        import.entries.len()
                    ),
                );
                self.bulk_dialog.entries = import.entries;
            }
            Err(e) => {
                self.bulk_dialog.entries.clear();
                self.bulk_dialog.error = Some(e.to_string());
            }
        }
    }

    /// Apply a finished text-export parse (with or without vault decryption)
    /// to the bulk dialog.
    fn bulk_text_loaded(
        &mut self,
        result: Result<Vec<keyroost_import::BulkEntry>, String>,
        path: String,
    ) {
        match result {
            Ok(entries) => {
                self.bulk_dialog.entries = entries;
                self.bulk_dialog.error = None;
                wipe(&mut self.bulk_dialog.password);
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
                self.bulk_dialog.error = Some(e);
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
        let entries = self.bulk_dialog.entries.clone();
        let Some(mut s) = self.take_molto_session() else {
            return;
        };
        // Up to 100 × 3 card writes — runs on the worker, log lines are
        // collected and replayed in the apply step.
        self.spawn_job(format!("Programming {n} profiles\u{2026}"), move || {
            let mut ok = 0;
            let mut fail = 0;
            let mut lines: Vec<(Severity, String)> = Vec::new();
            for (i, entry) in entries.into_iter().enumerate() {
                let p = start + i as u8;
                let title = entry.suggested_title();
                if title.is_empty() {
                    lines.push((Severity::Warn, format!("#{}: no title; skipping", p)));
                    fail += 1;
                    continue;
                }
                if let Err(e) = s.set_seed(p, &entry.secret) {
                    lines.push((Severity::Err, format!("#{} set_seed: {}", p, e)));
                    fail += 1;
                    continue;
                }
                if let Err(e) = s.set_title(p, &title) {
                    lines.push((Severity::Err, format!("#{} set_title: {}", p, e)));
                    fail += 1;
                    continue;
                }
                if let Err(e) = s.set_config(p, &entry.to_profile_config(unix_now(), timeout)) {
                    lines.push((Severity::Err, format!("#{} set_config: {}", p, e)));
                    fail += 1;
                    continue;
                }
                ok += 1;
            }
            Box::new(move |app: &mut App| {
                app.session = Some(s);
                for (sev, line) in lines {
                    app.log(sev, line);
                }
                let sev = if fail == 0 {
                    Severity::Ok
                } else {
                    Severity::Warn
                };
                app.log(sev, format!("bulk import: {} ok, {} failed", ok, fail));
                if fail == 0 {
                    app.bulk_dialog.open = false;
                }
            })
        });
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
        // Tag the job with the device it reads — if the user switches devices
        // while it's in flight, the result must not be painted into the new
        // device's pane (or its row in the sidebar).
        let for_device = self.selected_device.clone();
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
            Box::new(move |app: &mut App| {
                if app.selected_device != for_device {
                    return; // selection changed mid-read; discard
                }
                match outcome {
                    Ok((init, info)) => {
                        // Surface the key's firmware on the hero (e.g. "fw 5.7.4").
                        let fw = format!(
                            "{}.{}.{}",
                            init.device_major, init.device_minor, init.device_build
                        );
                        app.security_keys.init = Some(init);
                        if let Some(id) = for_device.clone() {
                            if let Some(dev) = app.devices.iter_mut().find(|d| d.id == id) {
                                dev.firmware = fw;
                            }
                        }
                        match info {
                            Some(Ok(info)) => {
                                // Refine the model from the AAGUID (e.g. "YubiKey" ->
                                // "YubiKey 5 Series with NFC") on the read device.
                                if let Some(model) = ui::aaguid::model_for_aaguid(&info.aaguid) {
                                    if let Some(id) = for_device {
                                        if let Some(dev) =
                                            app.devices.iter_mut().find(|d| d.id == id)
                                        {
                                            dev.model = model.to_string();
                                        }
                                    }
                                }
                                app.security_keys.info = Some(info);
                            }
                            Some(Err(e)) => {
                                app.security_keys.error = Some(format!("GetInfo failed: {}", e))
                            }
                            None => {}
                        }
                    }
                    Err(e) => app.security_keys.error = Some(e),
                }
            })
        });
    }

    /// Open the selected hidraw, run the PIN exchange, and populate the
    /// session with metadata + credential listing. Errors land in
    /// `security_keys.error`.
    fn try_unlock(&mut self) {
        // Check busy *before* consuming the typed PIN — spawn_job would drop
        // the job (and the PIN with it) if a background read is in flight.
        if self.busy() {
            return;
        }
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
            rps: std::sync::Arc::new(rps),
        })
    }

    fn lock_session(&mut self) {
        self.security_keys.session = None;
        wipe(&mut self.security_keys.pin_input);
    }

    fn refresh_credentials(&mut self) {
        // Check busy *before* taking the session — spawn_job would silently
        // drop the job, destroying the unlocked session (and its PIN token)
        // and logging the user out for clicking Reload at the wrong moment.
        if self.busy() {
            return;
        }
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
            rps: std::sync::Arc::new(rps),
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
        // Check busy *before* consuming the typed PINs (see try_unlock).
        if self.busy() {
            return;
        }
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
        // Check busy *before* consuming the typed PINs (see try_unlock).
        if self.busy() {
            return;
        }
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

    /// Wipe the FIDO key at `path` (authenticatorReset). Runs on the worker
    /// thread — the card needs a touch within ~30s, which the worker keeps off
    /// the UI frame. Used by the armed-reset flow, which targets the
    /// just-reconnected key rather than the (now stale) selection. On success
    /// the cached session and CTAP info are cleared.
    fn submit_reset_path(&mut self, path: std::path::PathBuf) -> bool {
        self.spawn_job("Resetting key\u{2026} (touch now)", move || {
            let result = (|| -> Result<(), String> {
                // A just-replugged node (especially on a fresh port) can take a
                // moment to accept opens; retry briefly before giving up.
                let mut dev = None;
                for attempt in 0..10 {
                    match CtapHidDevice::open(&path) {
                        Ok((d, _)) => {
                            dev = Some(d);
                            break;
                        }
                        Err(e) if attempt == 9 => return Err(e.to_string()),
                        Err(_) => std::thread::sleep(std::time::Duration::from_millis(100)),
                    }
                }
                let mut dev = dev.ok_or_else(|| "could not open key".to_string())?;
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
        })
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
            rows.push(OathRow { name: c.name, code });
        }
        Ok(rows)
    }

    /// Store the outcome of an op that ends by (re)listing credentials.
    fn apply_oath_rows(app: &mut App, result: Result<Vec<OathRow>, TransportError>) {
        // The typed password is consumed whatever the outcome — success,
        // wrong-password, or a transport error must not leave it buffered for
        // an automatic retry against (potentially) a different key.
        wipe(&mut app.oath.password_input);
        match result {
            Ok(rows) => {
                app.oath.creds = rows;
                app.oath.loaded = true;
                app.oath.locked = false;
            }
            Err(TransportError::OathPasswordRejected) => {
                app.oath.locked = true;
                app.oath.error = Some("wrong OATH password".into());
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
        let password = zeroize::Zeroizing::new(self.oath.password_input.clone());
        let for_device = self.selected_device.clone();
        self.spawn_job("Reading OATH codes\u{2026}", move || {
            let result = Self::oath_open_unlock(&name, &password)
                .and_then(|mut session| Self::oath_list_rows(&mut session));
            Box::new(move |app: &mut App| {
                // Discard if the user switched devices while the read (which
                // can block on a touch) was in flight — device B's pane must
                // not show device A's codes.
                if app.selected_device == for_device {
                    Self::apply_oath_rows(app, result);
                }
            })
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
            Ok(s) if !s.is_empty() => zeroize::Zeroizing::new(s),
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
        let password = zeroize::Zeroizing::new(self.oath.password_input.clone());
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
        let password = zeroize::Zeroizing::new(self.oath.password_input.clone());
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
            .selected_device()
            .map(|d| match &d.name {
                Some(name) => name.clone(),
                None => format!("{} {}", d.vendor, d.model).trim().to_string(),
            })
            .unwrap_or_else(|| "this key".into());

        let mut window_open = true;
        let mut arm = false;
        let mut cancel = false;
        let waiting = self.reset_arm.is_some();
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
                ui.label("This cannot be undone.");
                ui.add_space(6.0);
                if waiting {
                    // Armed: the clock starts when the key is re-inserted, so we
                    // wait for the unplug/replug and fire the moment it returns.
                    ui.add_space(2.0);
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(
                            egui::RichText::new("Now unplug the key, then plug it back in.")
                                .strong(),
                        );
                    });
                    ui.label("The reset is sent the instant it reconnects \u{2014} then the");
                    ui.label("key will blink. Touch it to finish the wipe.");
                    ui.add_space(6.0);
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                } else {
                    ui.label("A key only accepts a reset within ~10 seconds of being");
                    ui.label("plugged in, so after you confirm you'll re-insert it.");
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        ui.label("Type \u{201c}reset\u{201d} to confirm:");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.security_keys.reset.confirm_input)
                                .desired_width(120.0),
                        );
                    });
                    ui.add_space(6.0);
                    let ready = self.security_keys.reset.confirm_input.trim() == "reset";
                    ui.horizontal(|ui| {
                        if ui
                            .add_enabled(ready, egui::Button::new("Arm reset"))
                            .clicked()
                        {
                            arm = true;
                        }
                        if ui.button("Cancel").clicked() {
                            cancel = true;
                        }
                    });
                }
            });
        if arm {
            // Snapshot the current FIDO keys so the poll can tell when ours
            // leaves and a fresh one arrives. Prefer the armed key's HID serial
            // (port-independent) and fall back to its path + USB ids.
            let target_path = self.selected_fido_path();
            let devices = Self::fido_devices();
            let target = target_path
                .as_ref()
                .and_then(|p| devices.iter().find(|d| &d.path == p));
            let target_serial = target.and_then(|d| d.serial.clone());
            let target_ids = target.map(|d| d.ids);
            self.reset_arm = Some(ResetArm {
                target_serial,
                target_path,
                target_ids,
                prev_paths: devices.into_iter().map(|d| d.path).collect(),
                saw_removal: false,
            });
        } else if cancel || !window_open {
            // Cancel button, or the window's [x] close.
            self.security_keys.reset = ResetDialog::default();
            self.reset_arm = None;
        }
    }

    /// Current FIDO HID devices (cheap sysfs read, no PC/SC).
    fn fido_devices() -> Vec<FidoHid> {
        keyroost_hid::enumerate()
            .unwrap_or_default()
            .into_iter()
            .filter(HidDevice::is_fido)
            .map(|h| FidoHid {
                path: h.path,
                serial: h.serial_number,
                ids: (h.vendor_id, h.product_id),
            })
            .collect()
    }

    /// Poll the live FIDO list while a reset is armed: once the armed key has
    /// been unplugged, fire the reset on its re-insertion (which the user does),
    /// inside the ~10 s window. Matches by HID serial when the key exposes one
    /// (so it works across USB ports) and falls back to the HID path otherwise.
    fn poll_reset_arm(&mut self) {
        let current = Self::fido_devices();
        let mut fire: Option<std::path::PathBuf> = None;
        if let Some(arm) = self.reset_arm.as_mut() {
            if let Some(target_serial) = arm.target_serial.clone() {
                // Serial mode: identity is port-independent.
                let here = current
                    .iter()
                    .find(|d| d.serial.as_deref() == Some(target_serial.as_str()));
                match here {
                    None => arm.saw_removal = true, // unplugged
                    Some(d) if arm.saw_removal => fire = Some(d.path.clone()),
                    Some(_) => {}
                }
            } else {
                // Path mode (no serial, e.g. most YubiKeys): the armed path
                // leaving is the unplug; a fresh path with the armed key's
                // vendor/product ids is the re-insert. (Without the id match,
                // any newly plugged key would receive the reset.)
                let present = |p: &std::path::PathBuf| current.iter().any(|d| &d.path == p);
                match &arm.target_path {
                    Some(t) if !present(t) => arm.saw_removal = true,
                    _ => {}
                }
                if arm.saw_removal {
                    fire = current
                        .iter()
                        .filter(|d| arm.target_ids.is_none() || arm.target_ids == Some(d.ids))
                        .map(|d| &d.path)
                        .find(|p| !arm.prev_paths.contains(p))
                        .cloned();
                }
            }
        }
        match fire {
            Some(path) => {
                // The replug window is one-shot. If the worker is mid-job the
                // submission is refused — keep the arm (and the stale
                // prev_paths, so the fresh path still counts as new) and let
                // the next poll retry instead of silently losing the reset.
                if self.submit_reset_path(path) {
                    self.reset_arm = None;
                    self.security_keys.reset = ResetDialog::default();
                }
            }
            None => {
                if let Some(arm) = self.reset_arm.as_mut() {
                    arm.prev_paths = current.into_iter().map(|d| d.path).collect();
                }
            }
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
        let for_device = self.selected_device.clone();
        self.spawn_job("Reading OpenPGP status\u{2026}", move || {
            let result = (|| -> Result<keyroost_transport::OpenPgpStatus, TransportError> {
                let mut session = keyroost_transport::OpenPgpSession::open(&name)?;
                session.status()
            })();
            Box::new(move |app: &mut App| {
                if app.selected_device != for_device {
                    return; // selection changed mid-read; discard
                }
                match result {
                    Ok(status) => {
                        app.openpgp.status = Some(status);
                        app.openpgp.loaded = true;
                    }
                    Err(e) => app.openpgp.error = Some(e.to_string()),
                }
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
                wipe(&mut app.openpgp.admin_pin);
            }
            Err(e) => {
                app.openpgp.error = Some(e.to_string());
                wipe(&mut app.openpgp.admin_pin);
            }
        }
    }

    /// Set the cardholder name (PW3-gated), then refresh status.
    fn set_openpgp_name(&mut self) {
        let Some(name) = self.selected_openpgp_reader() else {
            return;
        };
        let pin = zeroize::Zeroizing::new(self.openpgp.admin_pin.clone());
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
        let pin = zeroize::Zeroizing::new(self.openpgp.admin_pin.clone());
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
    /// Returns `false` when the job couldn't be queued (worker busy) — the
    /// caller's confirm modal stays open so the confirmed click isn't lost.
    fn generate_openpgp_key(&mut self) -> bool {
        let Some(name) = self.selected_openpgp_reader() else {
            return true; // nothing to do; let the modal close
        };
        let pin = zeroize::Zeroizing::new(self.openpgp.admin_pin.clone());
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
                    wipe(&mut app.openpgp.admin_pin);
                }
                Err(e) => {
                    app.openpgp.error = Some(e.to_string());
                    wipe(&mut app.openpgp.admin_pin);
                }
            })
        })
    }

    /// Import a key into the selected slot (PW3-gated, destructive), then refresh
    /// status. The key material comes from host keygen or a file, obtained on the
    /// worker thread (keygen is slow). May require a touch on the key. Returns
    /// `false` when the job couldn't be queued (worker busy).
    fn import_openpgp_key(&mut self, source: ImportSource) -> bool {
        let Some(name) = self.selected_openpgp_reader() else {
            return true; // nothing to do; let the modal close
        };
        let pin = zeroize::Zeroizing::new(self.openpgp.admin_pin.clone());
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
                    wipe(&mut app.openpgp.admin_pin);
                    app.openpgp.import_path.clear();
                }
                Err(e) => {
                    app.openpgp.error = Some(e);
                    wipe(&mut app.openpgp.admin_pin);
                }
            })
        })
    }

    /// Factory-reset the OpenPGP applet (destructive), then refresh status. No
    /// PIN needed — reset blocks the PINs itself. Returns `false` when the job
    /// couldn't be queued (worker busy).
    fn reset_openpgp(&mut self) -> bool {
        let Some(name) = self.selected_openpgp_reader() else {
            return true; // nothing to do; let the modal close
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
        })
    }

    /// Change the user PIN (PW1) from old to new, then refresh status. No admin
    /// PIN needed — CHANGE REFERENCE DATA carries the old PIN itself.
    fn change_openpgp_user_pin(&mut self) {
        let Some(name) = self.selected_openpgp_reader() else {
            return;
        };
        let old = zeroize::Zeroizing::new(self.openpgp.user_pin_old.clone());
        let new = zeroize::Zeroizing::new(self.openpgp.user_pin_new.clone());
        self.openpgp.notice = None;
        self.spawn_job("Changing user PIN\u{2026}", move || {
            let result = (|| -> Result<keyroost_transport::OpenPgpStatus, TransportError> {
                let mut s = keyroost_transport::OpenPgpSession::open(&name)?;
                s.change_user_pin(old.as_bytes(), new.as_bytes())?;
                s.status()
            })();
            Box::new(move |app: &mut App| {
                wipe(&mut app.openpgp.user_pin_old);
                wipe(&mut app.openpgp.user_pin_new);
                Self::apply_openpgp_write(app, result, "User PIN (PW1) changed.".into());
            })
        });
    }

    /// Change the admin PIN (PW3) from old to new, then refresh status.
    fn change_openpgp_admin_pin(&mut self) {
        let Some(name) = self.selected_openpgp_reader() else {
            return;
        };
        let old = zeroize::Zeroizing::new(self.openpgp.admin_pin_old.clone());
        let new = zeroize::Zeroizing::new(self.openpgp.admin_pin_new.clone());
        self.openpgp.notice = None;
        self.spawn_job("Changing admin PIN\u{2026}", move || {
            let result = (|| -> Result<keyroost_transport::OpenPgpStatus, TransportError> {
                let mut s = keyroost_transport::OpenPgpSession::open(&name)?;
                s.change_admin_pin(old.as_bytes(), new.as_bytes())?;
                s.status()
            })();
            Box::new(move |app: &mut App| {
                wipe(&mut app.openpgp.admin_pin_old);
                wipe(&mut app.openpgp.admin_pin_new);
                Self::apply_openpgp_write(app, result, "Admin PIN (PW3) changed.".into());
            })
        });
    }

    /// Unblock the user PIN (PW1): set it to a new value, authorised by the admin
    /// PIN (PW3). Recovers a card whose user PIN is blocked without a reset.
    fn unblock_openpgp_user_pin(&mut self) {
        let Some(name) = self.selected_openpgp_reader() else {
            return;
        };
        let admin = zeroize::Zeroizing::new(self.openpgp.admin_pin.clone());
        let new = zeroize::Zeroizing::new(self.openpgp.unblock_new.clone());
        self.openpgp.notice = None;
        self.spawn_job("Unblocking user PIN\u{2026}", move || {
            let result = (|| -> Result<keyroost_transport::OpenPgpStatus, TransportError> {
                let mut s = keyroost_transport::OpenPgpSession::open(&name)?;
                s.reset_retry_counter(admin.as_bytes(), new.as_bytes())?;
                s.status()
            })();
            Box::new(move |app: &mut App| {
                wipe(&mut app.openpgp.unblock_new);
                Self::apply_openpgp_write(app, result, "User PIN (PW1) unblocked.".into());
            })
        });
    }

    /// Write-operations section: cardholder name / URL, generate key, reset.
    /// All write ops use the admin PIN (PW3) entered here; reset is the exception
    /// (it blocks the PINs itself). Destructive ops route through confirm modals.
    fn render_openpgp_manage(&mut self, ui: &mut egui::Ui, p: &Palette) {
        // Intents collected inside the UI closures and applied afterwards, so a
        // submit method's `&mut self` never overlaps the card's borrow.
        let mut go_name = false;
        let mut go_url = false;
        let mut arm_generate = false;
        let mut arm_import: Option<ImportSource> = None;
        let mut go_change_user = false;
        let mut go_change_admin = false;
        let mut go_unblock = false;
        let mut arm_reset = false;

        let head = |ui: &mut egui::Ui, t: &str| card_head(ui, p, t);
        let sub = |ui: &mut egui::Ui, t: &str| card_sub(ui, p, t);
        let note = |ui: &mut egui::Ui, t: &str| card_note(ui, p, t);

        // --- Admin PIN: shared by the card-detail and key writes (PW3) ---
        theme::card_frame(p).show(ui, |ui| {
            head(ui, "Admin PIN (PW3)");
            note(
                ui,
                "Authorizes the card-detail and key writes below. Sent for the \
                 operation only; never stored.",
            );
            ui.add_space(6.0);
            pin_field(ui, p, "Admin PIN", &mut self.openpgp.admin_pin);
        });
        ui.add_space(10.0);

        // --- Card details: cardholder name + public-key URL ---
        theme::card_frame(p).show(ui, |ui| {
            head(ui, "Card details");
            ui.add_space(6.0);
            text_field(
                ui,
                p,
                "Name",
                &mut self.openpgp.name_input,
                "Surname<<Given",
                200.0,
            );
            ui.horizontal(|ui| {
                if theme::button(ui, p, BtnKind::Default, "Set name").clicked() {
                    go_name = true;
                }
            });
            ui.add_space(6.0);
            text_field(
                ui,
                p,
                "URL",
                &mut self.openpgp.url_input,
                "https://\u{2026}",
                240.0,
            );
            ui.horizontal(|ui| {
                if theme::button(ui, p, BtnKind::Default, "Set URL").clicked() {
                    go_url = true;
                }
            });
        });
        ui.add_space(10.0);

        // --- Keys: generate on-card / import per slot (both overwrite) ---
        theme::card_frame(p).show(ui, |ui| {
            head(ui, "Keys");
            note(
                ui,
                "Generating or importing OVERWRITES that slot (clearable only by a \
                 full reset). Needs the admin PIN; may need a touch.",
            );
            ui.add_space(8.0);
            sub(ui, "Generate on-card");
            if let Some(s) = theme::segmented(
                ui,
                p,
                &["signature", "decryption", "authentication"],
                self.openpgp.gen_slot.label(),
                p.accent,
            ) {
                self.openpgp.gen_slot = OpenPgpSlotSel::from_label(&s);
            }
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                if theme::button(ui, p, BtnKind::Default, "Generate\u{2026}").clicked() {
                    arm_generate = true;
                }
            });
            ui.add_space(10.0);
            sub(ui, "Import RSA-2048");
            if let Some(s) = theme::segmented(
                ui,
                p,
                &["signature", "decryption", "authentication"],
                self.openpgp.import_slot.label(),
                p.accent,
            ) {
                self.openpgp.import_slot = OpenPgpSlotSel::from_label(&s);
            }
            text_field(
                ui,
                p,
                "From file",
                &mut self.openpgp.import_path,
                "/path/to/key.pem (PKCS#1/8, PEM or DER)",
                260.0,
            );
            let have_path = !self.openpgp.import_path.trim().is_empty();
            ui.horizontal(|ui| {
                if theme::button(ui, p, BtnKind::Default, "Generate & import\u{2026}").clicked() {
                    arm_import = Some(ImportSource::Generate);
                }
                if theme::button(ui, p, BtnKind::Default, "Import file\u{2026}").clicked()
                    && have_path
                {
                    arm_import = Some(ImportSource::FromFile);
                }
            });
        });
        ui.add_space(10.0);

        // --- PINs: change user / admin, unblock user ---
        theme::card_frame(p).show(ui, |ui| {
            head(ui, "PINs");
            ui.add_space(6.0);
            sub(ui, "Change user PIN (PW1)");
            pin_field(ui, p, "Current", &mut self.openpgp.user_pin_old);
            pin_field(ui, p, "New", &mut self.openpgp.user_pin_new);
            ui.horizontal(|ui| {
                if theme::button(ui, p, BtnKind::Default, "Change user PIN").clicked() {
                    go_change_user = true;
                }
            });
            ui.add_space(10.0);
            sub(ui, "Change admin PIN (PW3)");
            pin_field(ui, p, "Current", &mut self.openpgp.admin_pin_old);
            pin_field(ui, p, "New", &mut self.openpgp.admin_pin_new);
            ui.horizontal(|ui| {
                if theme::button(ui, p, BtnKind::Default, "Change admin PIN").clicked() {
                    go_change_admin = true;
                }
            });
            ui.add_space(10.0);
            sub(ui, "Unblock user PIN");
            note(ui, "Sets a new user PIN using the admin PIN entered above.");
            pin_field(ui, p, "New user PIN", &mut self.openpgp.unblock_new);
            ui.horizontal(|ui| {
                if theme::button(ui, p, BtnKind::Default, "Unblock user PIN").clicked() {
                    go_unblock = true;
                }
            });
        });
        ui.add_space(10.0);

        // --- Danger: factory reset ---
        theme::card_frame(p)
            .stroke(egui::Stroke::new(1.0, theme::tint(p.err, 90)))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new("Reset applet")
                            .font(theme::f_sb(14.0))
                            .color(p.err),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if theme::button(ui, p, BtnKind::Danger, "Reset applet\u{2026}").clicked() {
                            arm_reset = true;
                        }
                    });
                });
                ui.label(
                    egui::RichText::new(
                        "Wipes ALL OpenPGP keys and restores default PINs. Works even if the PINs are forgotten.",
                    )
                    .font(theme::f_reg(12.0))
                    .color(p.txt2),
                );
            });

        // Apply collected intents now that the card borrows have ended.
        if go_name {
            self.set_openpgp_name();
        }
        if go_url {
            self.set_openpgp_url();
        }
        if arm_generate {
            self.openpgp.confirm_generate = true;
        }
        if let Some(src) = arm_import {
            self.openpgp.confirm_import = Some(src);
        }
        if go_change_user {
            self.change_openpgp_user_pin();
        }
        if go_change_admin {
            self.change_openpgp_admin_pin();
        }
        if go_unblock {
            self.unblock_openpgp_user_pin();
        }
        if arm_reset {
            self.openpgp.confirm_reset = Some(String::new());
        }
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
                // Close the modal only once the job was actually queued — a
                // busy worker would otherwise silently swallow the confirmed
                // click.
                if self.generate_openpgp_key() {
                    self.openpgp.confirm_generate = false;
                }
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
                // Close the modal only once the job was actually queued (see
                // the generate modal above).
                if self.import_openpgp_key(source) {
                    self.openpgp.confirm_import = None;
                }
            } else if cancel || !window_open {
                self.openpgp.confirm_import = None;
            }
        }

        if typed_reset_modal(
            ctx,
            "Reset OpenPGP applet?",
            "This wipes ALL OpenPGP keys and resets the PINs to defaults.",
            &[],
            &mut self.openpgp.confirm_reset,
        ) && self.reset_openpgp()
        {
            self.openpgp.confirm_reset = None;
        }
    }

    /// The reset confirmation modal for the PIV pane.
    fn render_piv_confirms(&mut self, ctx: &egui::Context) {
        if typed_reset_modal(
            ctx,
            "Reset PIV applet?",
            "This wipes ALL PIV keys, certificates, and PINs.",
            &["Only works when the PIN and PUK are already blocked."],
            &mut self.piv.confirm_reset,
        ) && self.piv_reset()
        {
            self.piv.confirm_reset = None;
        }
    }
}

/// A typed-"reset" confirmation modal, shared by the OpenPGP and PIV panes.
/// `confirm` is the modal state (`Some(typed text)` = open). Returns `true`
/// when the user confirmed; the *caller* fires the action and closes the
/// modal only if the action was actually queued — a busy worker must not
/// swallow a confirmed destructive click.
fn typed_reset_modal(
    ctx: &egui::Context,
    title: &str,
    warning: &str,
    extra_lines: &[&str],
    confirm: &mut Option<String>,
) -> bool {
    let Some(typed) = confirm.clone() else {
        return false;
    };
    let mut do_it = false;
    let mut cancel = false;
    let mut window_open = true;
    let mut buf = typed;
    egui::Window::new(title)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .open(&mut window_open)
        .show(ctx, |ui| {
            ui.colored_label(egui::Color32::from_rgb(220, 110, 110), warning);
            for line in extra_lines {
                ui.label(*line);
            }
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
        true
    } else {
        if cancel || !window_open {
            *confirm = None;
        } else {
            *confirm = Some(buf);
        }
        false
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
    keyroost_proto::codec::hex_encode(bytes)
}

/// Decode a management-key hex field into wipe-on-drop bytes.
fn piv_mgmt_key_bytes(hex: &str) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    keyroost_proto::codec::hex_decode(hex.trim())
        .map(zeroize::Zeroizing::new)
        .map_err(|e| format!("management key is not valid hex: {}", e))
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
    let d = 15.0;
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(d, d), egui::Sense::hover());
    let c = ui.visuals().weak_text_color();
    ui.painter()
        .circle_stroke(rect.center(), d / 2.0 - 1.0, egui::Stroke::new(1.0, c));
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        "?",
        egui::FontId::proportional(10.0),
        c,
    );
    resp.on_hover_text(text);
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
        Palette::new(
            self.mode,
            Palette::ACCENTS[self.accent_idx],
            self.colorblind,
        )
    }

    /// The currently selected device, if the id still resolves to a present one.
    fn selected_device(&self) -> Option<&UiDevice> {
        let id = self.selected_device.as_ref()?;
        self.devices.iter().find(|d| &d.id == id)
    }

    /// (Re)build the unified device list off-thread, then re-resolve selection.
    /// Queue a burst of staggered rescans (see `pending_scans`). The first runs
    /// as soon as the worker is free; the rest follow over the next few seconds
    /// so a slow-registering reader is caught without the user touching Refresh.
    fn schedule_scan_burst(&mut self) {
        self.pending_scans = 4;
        self.next_scan_at = None; // first scan is due immediately
    }

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
        self.openpgp.notice = None;
        self.openpgp.name_input.clear();
        self.openpgp.url_input.clear();
        self.piv = PivState::default();
        // Typed secrets must never survive a selection change — a PIN entered
        // for one key would otherwise be sent to another (the OATH pane even
        // auto-submits its password on tab open), silently burning retry
        // counters on the wrong device.
        wipe(&mut self.security_keys.pin_input);
        wipe(&mut self.security_keys.change_pin.old);
        wipe(&mut self.security_keys.change_pin.new);
        wipe(&mut self.security_keys.change_pin.confirm);
        self.security_keys.change_pin.open = false;
        wipe(&mut self.oath.password_input);
        wipe(&mut self.oath.add.secret);
        wipe(&mut self.otp.add.secret);
        self.openpgp.wipe_secrets();
        self.oath_tried = false;
        self.piv_tried = false;
        self.otp_tried = false;
        self.otp = OtpState::default();
        self.molto_reset_confirm = false;
        self.rename_open = false;
        self.rename_input.clear();
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
                    // Enumeration's gentle probe usually fills these already;
                    // refresh them here as a fallback in case that read failed.
                    if let Some(id) = app.selected_device.clone() {
                        let named = keyroost_keyring::Keyring::load_default()
                            .ok()
                            .and_then(|k| k.name_for(Some(&info.serial)).map(str::to_owned));
                        if let Some(dev) = app.devices.iter_mut().find(|d| d.id == id) {
                            dev.serial = info.serial.clone();
                            if dev.name.is_none() {
                                dev.name = named;
                            }
                        }
                    }
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
        let for_device = self.selected_device.clone();
        self.spawn_job("Reading PIV status\u{2026}", move || {
            let result = keyroost_transport::PivSession::open(&reader).and_then(|mut s| s.status());
            Box::new(move |app: &mut App| {
                if app.selected_device != for_device {
                    return; // selection changed mid-read; discard
                }
                match result {
                    Ok(status) => {
                        app.piv.status = Some(status);
                        app.piv.loaded = true;
                    }
                    Err(e) => app.piv.error = Some(e.to_string()),
                }
            })
        });
    }

    /// Apply a PIV write result: on success store the notice and refreshed
    /// status; on error store the message. Shared by every PIV write action.
    fn apply_piv_write(
        app: &mut App,
        result: Result<keyroost_transport::PivStatus, TransportError>,
        notice: String,
    ) {
        match result {
            Ok(status) => {
                app.piv.status = Some(status);
                app.piv.error = None;
                app.piv.notice = Some(notice);
            }
            Err(e) => {
                app.piv.notice = None;
                app.piv.error = Some(e.to_string());
            }
        }
    }

    /// Decode the management-key hex field, surfacing a parse error in the pane.
    fn piv_change_pin(&mut self) {
        let Some(name) = self.selected_oath_reader() else {
            return;
        };
        let (old, new) = (self.piv.pin_old.clone(), self.piv.pin_new.clone());
        self.piv.notice = None;
        self.spawn_job("Changing PIV PIN\u{2026}", move || {
            let result = (|| -> Result<keyroost_transport::PivStatus, TransportError> {
                let mut s = keyroost_transport::PivSession::open(&name)?;
                s.change_pin(old.as_bytes(), new.as_bytes())?;
                s.status()
            })();
            Box::new(move |app: &mut App| {
                wipe(&mut app.piv.pin_old);
                wipe(&mut app.piv.pin_new);
                Self::apply_piv_write(app, result, "PIN changed.".into());
            })
        });
    }

    fn piv_change_puk(&mut self) {
        let Some(name) = self.selected_oath_reader() else {
            return;
        };
        let (old, new) = (self.piv.puk_old.clone(), self.piv.puk_new.clone());
        self.piv.notice = None;
        self.spawn_job("Changing PUK\u{2026}", move || {
            let result = (|| -> Result<keyroost_transport::PivStatus, TransportError> {
                let mut s = keyroost_transport::PivSession::open(&name)?;
                s.change_puk(old.as_bytes(), new.as_bytes())?;
                s.status()
            })();
            Box::new(move |app: &mut App| {
                wipe(&mut app.piv.puk_old);
                wipe(&mut app.piv.puk_new);
                Self::apply_piv_write(app, result, "PUK changed.".into());
            })
        });
    }

    fn piv_unblock_pin(&mut self) {
        let Some(name) = self.selected_oath_reader() else {
            return;
        };
        let (puk, new) = (
            self.piv.unblock_puk.clone(),
            self.piv.unblock_new_pin.clone(),
        );
        self.piv.notice = None;
        self.spawn_job("Unblocking PIN\u{2026}", move || {
            let result = (|| -> Result<keyroost_transport::PivStatus, TransportError> {
                let mut s = keyroost_transport::PivSession::open(&name)?;
                s.unblock_pin(puk.as_bytes(), new.as_bytes())?;
                s.status()
            })();
            Box::new(move |app: &mut App| {
                wipe(&mut app.piv.unblock_puk);
                wipe(&mut app.piv.unblock_new_pin);
                Self::apply_piv_write(app, result, "PIN unblocked and reset.".into());
            })
        });
    }

    fn piv_set_retries(&mut self) {
        let Some(name) = self.selected_oath_reader() else {
            return;
        };
        let mgmt = match piv_mgmt_key_bytes(&self.piv.mgmt_key_input) {
            Ok(b) => b,
            Err(e) => {
                self.piv.error = Some(e);
                return;
            }
        };
        let pin = zeroize::Zeroizing::new(self.piv.retries_pin_auth.clone());
        let (pin_tries, puk_tries) = (self.piv.retries_pin, self.piv.retries_puk);
        self.piv.notice = None;
        self.spawn_job("Setting PIV retry counts\u{2026}", move || {
            let result = (|| -> Result<keyroost_transport::PivStatus, TransportError> {
                let mut s = keyroost_transport::PivSession::open(&name)?;
                let alg = s.management_key_algorithm();
                s.authenticate_management(alg, &mgmt)?;
                s.verify_pin(pin.as_bytes())?;
                s.set_pin_retries(pin_tries, puk_tries)?;
                s.status()
            })();
            Box::new(move |app: &mut App| {
                wipe(&mut app.piv.mgmt_key_input);
                wipe(&mut app.piv.retries_pin_auth);
                Self::apply_piv_write(
                    app,
                    result,
                    "Retry counts set; PIN/PUK reset to defaults.".into(),
                );
            })
        });
    }

    fn piv_generate_key(&mut self) {
        let Some(name) = self.selected_oath_reader() else {
            return;
        };
        let mgmt = match piv_mgmt_key_bytes(&self.piv.mgmt_key_input) {
            Ok(b) => b,
            Err(e) => {
                self.piv.error = Some(e);
                return;
            }
        };
        let slot = self.piv.gen_slot.to_slot();
        let alg = self.piv.gen_alg.to_alg();
        self.piv.notice = None;
        self.piv.gen_pubkey_pem = None;
        self.spawn_job("Generating key\u{2026} (touch if it blinks)", move || {
            let result = (|| -> Result<
                (keyroost_piv::PublicKey, keyroost_transport::PivStatus),
                TransportError,
            > {
                let mut s = keyroost_transport::PivSession::open(&name)?;
                let mgmt_alg = s.management_key_algorithm();
                s.authenticate_management(mgmt_alg, &mgmt)?;
                let pubkey = s.generate_key(
                    slot,
                    alg,
                    keyroost_piv::PinPolicy::Default,
                    keyroost_piv::TouchPolicy::Default,
                )?;
                Ok((pubkey, s.status()?))
            })();
            Box::new(move |app: &mut App| {
                wipe(&mut app.piv.mgmt_key_input);
                match result {
                    Ok((pubkey, status)) => {
                        app.piv.status = Some(status);
                        app.piv.error = None;
                        match keyroost_piv::spki::subject_public_key_info(&pubkey, alg) {
                            Ok(der) => {
                                app.piv.gen_pubkey_pem = Some(keyroost_piv::spki::to_pem(&der));
                                app.piv.notice = Some(format!("Generated {} key.", alg.label()));
                            }
                            Err(e) => {
                                app.piv.notice = Some(format!(
                                    "Generated {} key (public-key encoding failed: {})",
                                    alg.label(),
                                    e
                                ));
                            }
                        }
                    }
                    Err(e) => {
                        app.piv.notice = None;
                        app.piv.error = Some(e.to_string());
                    }
                }
            })
        });
    }

    fn piv_import_cert(&mut self) {
        let Some(name) = self.selected_oath_reader() else {
            return;
        };
        let mgmt = match piv_mgmt_key_bytes(&self.piv.mgmt_key_input) {
            Ok(b) => b,
            Err(e) => {
                self.piv.error = Some(e);
                return;
            }
        };
        let slot = self.piv.cert_slot.to_slot();
        let path = self.piv.cert_path.trim().to_owned();
        self.piv.notice = None;
        self.spawn_job("Importing certificate\u{2026}", move || {
            let result = (|| -> Result<keyroost_transport::PivStatus, TransportError> {
                let bytes = std::fs::read(&path).map_err(|_| {
                    TransportError::MalformedResponse("cannot read certificate file")
                })?;
                let der = cert_bytes_to_der(&bytes)
                    .ok_or(TransportError::MalformedResponse("file is not PEM or DER"))?;
                let mut s = keyroost_transport::PivSession::open(&name)?;
                let mgmt_alg = s.management_key_algorithm();
                s.authenticate_management(mgmt_alg, &mgmt)?;
                s.import_certificate(slot, &der)?;
                s.status()
            })();
            Box::new(move |app: &mut App| {
                wipe(&mut app.piv.mgmt_key_input);
                Self::apply_piv_write(app, result, "Certificate imported.".into());
            })
        });
    }

    /// Normalize the certificate-subject field: a bare name becomes `CN=name`;
    /// anything containing `=` is taken as a full distinguished name.
    fn piv_subject(&self) -> Option<String> {
        let s = self.piv.cert_subject.trim();
        if s.is_empty() {
            return None;
        }
        Some(if s.contains('=') {
            s.to_owned()
        } else {
            format!("CN={s}")
        })
    }

    /// Create a self-signed certificate for the selected slot's key and store
    /// it in the slot (management key authorizes the import, PIN the signing).
    fn piv_self_sign(&mut self) {
        let Some(name) = self.selected_oath_reader() else {
            return;
        };
        let mgmt = match piv_mgmt_key_bytes(&self.piv.mgmt_key_input) {
            Ok(b) => b,
            Err(e) => {
                self.piv.error = Some(e);
                return;
            }
        };
        let Some(subject) = self.piv_subject() else {
            self.piv.error = Some("enter a name for the certificate".into());
            return;
        };
        let pin = zeroize::Zeroizing::new(self.piv.sign_pin.clone());
        let slot = self.piv.certify_slot.to_slot();
        let days = i64::from(self.piv.cert_days.max(1));
        self.piv.notice = None;
        self.spawn_job(
            "Creating self-signed certificate\u{2026} (touch if it blinks)",
            move || {
                let result = (|| -> Result<keyroost_transport::PivStatus, TransportError> {
                    let mut s = keyroost_transport::PivSession::open(&name)?;
                    let mgmt_alg = s.management_key_algorithm();
                    s.authenticate_management(mgmt_alg, &mgmt)?;
                    s.verify_pin(pin.as_bytes())?;
                    let now = i64::from(unix_now());
                    s.self_signed_certificate(slot, &subject, now, now + days * 86_400)?;
                    s.status()
                })();
                Box::new(move |app: &mut App| {
                    wipe(&mut app.piv.sign_pin);
                    wipe(&mut app.piv.mgmt_key_input);
                    Self::apply_piv_write(
                        app,
                        result,
                        format!("Self-signed certificate stored in {}.", slot.label()),
                    );
                })
            },
        );
    }

    /// Sign a PKCS#10 certificate request on the card and save it as PEM.
    fn piv_request_csr(&mut self) {
        let Some(name) = self.selected_oath_reader() else {
            return;
        };
        let Some(subject) = self.piv_subject() else {
            self.piv.error = Some("enter a name for the certificate request".into());
            return;
        };
        let path = self.piv.csr_path.trim().to_owned();
        if path.is_empty() {
            self.piv.error = Some("enter a destination path for the request".into());
            return;
        }
        if std::path::Path::new(&path).exists() {
            self.piv.error = Some(format!(
                "{path} already exists — delete it first or choose another name"
            ));
            return;
        }
        let pin = zeroize::Zeroizing::new(self.piv.sign_pin.clone());
        let slot = self.piv.certify_slot.to_slot();
        self.piv.notice = None;
        self.spawn_job(
            "Signing certificate request\u{2026} (touch if it blinks)",
            move || {
                let result = (|| -> Result<(), TransportError> {
                    let mut s = keyroost_transport::PivSession::open(&name)?;
                    s.verify_pin(pin.as_bytes())?;
                    let pem = s.generate_csr(slot, &subject)?;
                    std::fs::write(&path, pem.as_bytes()).map_err(|_| {
                        TransportError::MalformedResponse("cannot write destination file")
                    })?;
                    Ok(())
                })();
                Box::new(move |app: &mut App| {
                    wipe(&mut app.piv.sign_pin);
                    match result {
                        Ok(()) => {
                            app.piv.error = None;
                            app.piv.notice = Some("Certificate request signed and saved.".into());
                        }
                        Err(e) => {
                            app.piv.notice = None;
                            app.piv.error = Some(e.to_string());
                        }
                    }
                })
            },
        );
    }

    fn piv_export_cert(&mut self) {
        let Some(name) = self.selected_oath_reader() else {
            return;
        };
        let slot = self.piv.export_slot.to_slot();
        let path = self.piv.export_path.trim().to_owned();
        if path.is_empty() {
            self.piv.error = Some("enter a destination path for the certificate".into());
            return;
        }
        // Refuse to clobber an existing file — the user can delete it or pick
        // another name; there is no undo for an overwritten file.
        if std::path::Path::new(&path).exists() {
            self.piv.error = Some(format!(
                "{path} already exists — delete it first or choose another name"
            ));
            return;
        }
        self.piv.notice = None;
        self.spawn_job("Exporting certificate\u{2026}", move || {
            let result = (|| -> Result<usize, TransportError> {
                let mut s = keyroost_transport::PivSession::open(&name)?;
                let der = s
                    .read_certificate(slot)?
                    .ok_or(TransportError::MalformedResponse(
                        "slot holds no certificate",
                    ))?;
                std::fs::write(&path, &der).map_err(|_| {
                    TransportError::MalformedResponse("cannot write destination file")
                })?;
                Ok(der.len())
            })();
            Box::new(move |app: &mut App| match result {
                Ok(n) => {
                    app.piv.error = None;
                    app.piv.notice = Some(format!("Exported {}-byte DER certificate.", n));
                }
                Err(e) => {
                    app.piv.notice = None;
                    app.piv.error = Some(e.to_string());
                }
            })
        });
    }

    fn piv_change_management_key(&mut self) {
        let Some(name) = self.selected_oath_reader() else {
            return;
        };
        let old = match piv_mgmt_key_bytes(&self.piv.mgmt_key_input) {
            Ok(b) => b,
            Err(e) => {
                self.piv.error = Some(e);
                return;
            }
        };
        let new = match piv_mgmt_key_bytes(&self.piv.new_mgmt_key_input) {
            Ok(b) => b,
            Err(e) => {
                self.piv.error = Some(e);
                return;
            }
        };
        let new_alg = self.piv.new_mgmt_alg.to_alg();
        if new.len() != new_alg.key_len() {
            self.piv.error = Some(format!(
                "new management key is {} bytes; {} needs {}",
                new.len(),
                new_alg.label(),
                new_alg.key_len()
            ));
            return;
        }
        self.piv.notice = None;
        self.spawn_job("Changing management key\u{2026}", move || {
            let result = (|| -> Result<keyroost_transport::PivStatus, TransportError> {
                let mut s = keyroost_transport::PivSession::open(&name)?;
                let cur_alg = s.management_key_algorithm();
                s.authenticate_management(cur_alg, &old)?;
                s.set_management_key(new_alg, &new, false)?;
                s.status()
            })();
            Box::new(move |app: &mut App| {
                wipe(&mut app.piv.mgmt_key_input);
                wipe(&mut app.piv.new_mgmt_key_input);
                Self::apply_piv_write(
                    app,
                    result,
                    format!("Management key changed to {}.", new_alg.label()),
                );
            })
        });
    }

    /// Returns `false` when the job couldn't be queued (worker busy) — the
    /// caller's confirm modal stays open so the confirmed click isn't lost.
    fn piv_reset(&mut self) -> bool {
        let Some(name) = self.selected_oath_reader() else {
            return true; // nothing to do; let the modal close
        };
        self.piv.notice = None;
        self.spawn_job("Resetting PIV applet\u{2026}", move || {
            let result = (|| -> Result<keyroost_transport::PivStatus, TransportError> {
                let mut s = keyroost_transport::PivSession::open(&name)?;
                s.reset()?;
                s.status()
            })();
            Box::new(move |app: &mut App| {
                Self::apply_piv_write(
                    app,
                    result,
                    "PIV application reset to factory defaults.".into(),
                );
            })
        })
    }

    /// Apply the three rename-dialog actions shared by the security-key hero and
    /// the Molto2 hero: open the inline field, cancel it, or commit the name.
    /// The flags are collected during the `ui` closures (where `self` is already
    /// borrowed) and applied here afterwards.
    fn apply_rename_actions(&mut self, dev: &UiDevice, open: bool, cancel: bool, save: bool) {
        if open {
            self.rename_open = true;
            self.rename_input = dev.name.clone().unwrap_or_default();
        }
        if cancel {
            self.rename_open = false;
            self.rename_input.clear();
        }
        if save {
            self.save_device_name();
        }
    }

    /// Persist (or clear) the selected device's friendly name in `keys.json`,
    /// keyed by its serial. Empty input removes the existing name.
    fn save_device_name(&mut self) {
        let Some(dev) = self.selected_device().cloned() else {
            return;
        };
        if dev.serial.is_empty() {
            self.log(
                Severity::Warn,
                "this device exposes no serial, so it can't be named yet",
            );
            self.rename_open = false;
            return;
        }
        let name = self.rename_input.trim().to_owned();
        if !name.is_empty() {
            if let Err(e) = keyroost_keyring::validate_name(&name) {
                self.log(Severity::Err, format!("invalid name: {e}"));
                return;
            }
        }
        let mut keyring = keyroost_keyring::Keyring::load_default().unwrap_or_default();
        // Drop any existing name for this device first (covers rename + clear).
        if let Some(current) = dev.name.clone() {
            keyring.remove(&current);
        }
        if !name.is_empty() {
            let entry = keyroost_keyring::KeyEntry {
                name,
                serial: dev.serial.clone(),
                source: keyroost_keyring::IdSource::default(),
                vendor: Some(dev.vendor.to_ascii_lowercase()),
                aaguid: None,
                note: None,
            };
            if let Err(e) = keyring.add(entry) {
                self.log(Severity::Err, format!("name: {e}"));
                return;
            }
        }
        match keyring.save_default() {
            Ok(_) => self.log(Severity::Ok, "name saved"),
            Err(e) => self.log(Severity::Err, format!("save names: {e}")),
        }
        self.rename_open = false;
        self.rename_input.clear();
        self.refresh_devices();
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
fn glyph_tile(
    ui: &mut egui::Ui,
    size: f32,
    fill: egui::Color32,
    fg: egui::Color32,
    ch: Option<char>,
) {
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
            ui.painter().line_segment(
                [c, c + egui::vec2(0.0, -r * 0.72)],
                egui::Stroke::new(1.6, fg),
            );
            ui.painter().line_segment(
                [c, c + egui::vec2(r * 0.55, 0.0)],
                egui::Stroke::new(1.6, fg),
            );
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
        CapTab::Otp => "On-device OTP",
    }
}

/// A labelled password field row for the inline PIN form.
fn pin_field(ui: &mut egui::Ui, p: &Palette, label: &str, buf: &mut String) {
    ui.horizontal(|ui| {
        ui.add_sized(
            [96.0, 22.0],
            egui::Label::new(
                egui::RichText::new(label)
                    .font(theme::f_reg(13.0))
                    .color(p.txt2),
            ),
        );
        ui.add(
            egui::TextEdit::singleline(buf)
                .password(true)
                .desired_width(200.0),
        );
    });
    ui.add_space(4.0);
}

/// Like [`pin_field`] but with a hint and custom width — for secrets that are
/// longer than a PIN (the PIV management key). Masked: a management key is a
/// card-write credential and shouldn't sit readable on screen.
fn secret_field(ui: &mut egui::Ui, p: &Palette, label: &str, buf: &mut String, hint: &str, w: f32) {
    ui.horizontal(|ui| {
        ui.add_sized(
            [96.0, 22.0],
            egui::Label::new(
                egui::RichText::new(label)
                    .font(theme::f_reg(13.0))
                    .color(p.txt2),
            ),
        );
        ui.add(
            egui::TextEdit::singleline(buf)
                .password(true)
                .hint_text(hint)
                .desired_width(w),
        );
    });
    ui.add_space(4.0);
}

/// Section heading inside a management card (shared by the OpenPGP and PIV
/// panes).
fn card_head(ui: &mut egui::Ui, p: &Palette, t: &str) {
    ui.label(egui::RichText::new(t).font(theme::f_sb(14.0)).color(p.txt));
}

/// Sub-heading inside a management card.
fn card_sub(ui: &mut egui::Ui, p: &Palette, t: &str) {
    ui.label(egui::RichText::new(t).font(theme::f_sb(12.5)).color(p.txt2));
}

/// Fine-print note inside a management card.
fn card_note(ui: &mut egui::Ui, p: &Palette, t: &str) {
    ui.label(
        egui::RichText::new(t)
            .font(theme::f_reg(12.0))
            .color(p.txt3),
    );
}

/// A themed single-line text input with a fixed-width label — the non-password
/// sibling of [`pin_field`], for cardholder name / URL / file path.
fn text_field(ui: &mut egui::Ui, p: &Palette, label: &str, buf: &mut String, hint: &str, w: f32) {
    ui.horizontal(|ui| {
        ui.add_sized(
            [96.0, 22.0],
            egui::Label::new(
                egui::RichText::new(label)
                    .font(theme::f_reg(13.0))
                    .color(p.txt2),
            ),
        );
        ui.add(
            egui::TextEdit::singleline(buf)
                .hint_text(hint)
                .desired_width(w),
        );
    });
    ui.add_space(4.0);
}

/// A PIV slot picker combo.
fn piv_slot_combo(ui: &mut egui::Ui, id: &str, sel: &mut PivSlotSel) {
    egui::ComboBox::from_id_salt(id)
        .selected_text(sel.label())
        .show_ui(ui, |ui| {
            for opt in PivSlotSel::ALL {
                ui.selectable_value(sel, opt, opt.label());
            }
        });
}

/// A PIV key-algorithm picker combo.
fn piv_keyalg_combo(ui: &mut egui::Ui, id: &str, sel: &mut PivKeyAlgSel) {
    egui::ComboBox::from_id_salt(id)
        .selected_text(sel.label())
        .show_ui(ui, |ui| {
            for opt in PivKeyAlgSel::ALL {
                ui.selectable_value(sel, opt, opt.label());
            }
        });
}

/// A PIV management-key-algorithm picker combo.
fn piv_mgmtalg_combo(ui: &mut egui::Ui, id: &str, sel: &mut PivMgmtAlgSel) {
    egui::ComboBox::from_id_salt(id)
        .selected_text(sel.label())
        .show_ui(ui, |ui| {
            for opt in PivMgmtAlgSel::ALL {
                ui.selectable_value(sel, opt, opt.label());
            }
        });
}

/// Accept a certificate file's bytes as PEM or DER, returning DER. `None` when
/// the bytes are neither.
fn cert_bytes_to_der(bytes: &[u8]) -> Option<Vec<u8>> {
    if let Ok(text) = std::str::from_utf8(bytes) {
        if let Some(start) = text.find("-----BEGIN CERTIFICATE-----") {
            let after = &text[start + "-----BEGIN CERTIFICATE-----".len()..];
            let end = after.find("-----END CERTIFICATE-----")?;
            let b64: String = after[..end].split_whitespace().collect();
            return keyroost_proto::codec::base64_decode(&b64).ok();
        }
    }
    // Not PEM — accept DER (must begin with a SEQUENCE tag).
    if bytes.first() == Some(&0x30) {
        Some(bytes.to_vec())
    } else {
        None
    }
}

/// Paint a rounded glyph tile at `rect` with the painter (no widget allocation,
/// so it never steals clicks from a surrounding row). `ch = None` draws a clock.
fn paint_glyph_tile(
    ui: &egui::Ui,
    rect: egui::Rect,
    fill: egui::Color32,
    fg: egui::Color32,
    ch: Option<char>,
) {
    ui.painter()
        .rect_filled(rect, egui::Rounding::same(rect.width() * 0.28), fill);
    match ch {
        Some(c) => {
            ui.painter().text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                c,
                theme::f_bold(rect.width() * 0.5),
                fg,
            );
        }
        None => {
            let c = rect.center();
            let r = rect.width() * 0.26;
            ui.painter().circle_stroke(c, r, egui::Stroke::new(1.6, fg));
            ui.painter().line_segment(
                [c, c + egui::vec2(0.0, -r * 0.72)],
                egui::Stroke::new(1.6, fg),
            );
            ui.painter().line_segment(
                [c, c + egui::vec2(r * 0.55, 0.0)],
                egui::Stroke::new(1.6, fg),
            );
        }
    }
}

/// Paint a small rounded pill at `left_top` with the painter; returns its width
/// so the caller can advance a cursor.
fn paint_pill(
    ui: &egui::Ui,
    left_top: egui::Pos2,
    text: &str,
    fg: egui::Color32,
    bg: egui::Color32,
) -> f32 {
    let galley = ui.fonts(|f| f.layout_no_wrap(text.to_string(), theme::f_sb(11.0), fg));
    let pad_x = 8.0;
    let h = 18.0;
    let w = galley.size().x + pad_x * 2.0;
    let rect = egui::Rect::from_min_size(left_top, egui::vec2(w, h));
    ui.painter()
        .rect_filled(rect, egui::Rounding::same(999.0), bg);
    let pos = egui::pos2(left_top.x + pad_x, rect.center().y - galley.size().y / 2.0);
    ui.painter().galley(pos, galley, fg);
    w
}

// ---- small vector icons, painted so they render regardless of font coverage
// (IBM Plex Sans lacks ⓘ / ◐ / ↻ / ⧉ / ✓ / ✕, which otherwise show as tofu) ----

/// Half-filled circle — the light/dark theme toggle.
fn paint_theme_icon(ui: &egui::Ui, center: egui::Pos2, r: f32, color: egui::Color32) {
    use std::f32::consts::{FRAC_PI_2, PI};
    ui.painter()
        .circle_stroke(center, r, egui::Stroke::new(1.3, color));
    let n = 20;
    let pts: Vec<egui::Pos2> = (0..=n)
        .map(|i| {
            let a = FRAC_PI_2 + PI * (i as f32 / n as f32);
            center + r * egui::vec2(a.cos(), a.sin())
        })
        .collect();
    ui.painter()
        .add(egui::Shape::convex_polygon(pts, color, egui::Stroke::NONE));
}

/// An eye (two lids + a pupil) — the colorblind-mode toggle.
fn paint_eye_icon(ui: &egui::Ui, center: egui::Pos2, color: egui::Color32) {
    let stroke = egui::Stroke::new(1.3, color);
    let (w, h) = (8.0_f32, 4.6_f32);
    let n = 14;
    let lid = |sign: f32| -> Vec<egui::Pos2> {
        (0..=n)
            .map(|i| {
                let t = -1.0 + 2.0 * (i as f32 / n as f32);
                egui::pos2(center.x + t * w, center.y + sign * h * (1.0 - t * t))
            })
            .collect()
    };
    ui.painter().add(egui::Shape::line(lid(-1.0), stroke));
    ui.painter().add(egui::Shape::line(lid(1.0), stroke));
    ui.painter().circle_filled(center, 2.2, color);
}

/// Circular arrow — refresh / rescan. Clockwise, with a filled arrowhead at the
/// leading end (egui's y-down space makes increasing angle clockwise).
fn paint_refresh_icon(ui: &egui::Ui, center: egui::Pos2, r: f32, color: egui::Color32) {
    let stroke = egui::Stroke::new(1.4, color);
    let (a0, a1) = (0.5_f32, 5.6_f32);
    let n = 24;
    let pts: Vec<egui::Pos2> = (0..=n)
        .map(|i| {
            let a = a0 + (a1 - a0) * (i as f32 / n as f32);
            center + r * egui::vec2(a.cos(), a.sin())
        })
        .collect();
    ui.painter().add(egui::Shape::line(pts, stroke));
    // Filled arrowhead at the leading (clockwise) end, pointing along the motion.
    let end = center + r * egui::vec2(a1.cos(), a1.sin());
    let tangent = egui::vec2(-a1.sin(), a1.cos());
    let radial = egui::vec2(a1.cos(), a1.sin());
    let tip = end + tangent * 3.5;
    let b1 = end + radial * 2.6 - tangent * 0.8;
    let b2 = end - radial * 2.6 - tangent * 0.8;
    ui.painter().add(egui::Shape::convex_polygon(
        vec![tip, b1, b2],
        color,
        egui::Stroke::NONE,
    ));
}

/// Two stacked sheets — copy.
fn paint_copy_icon(ui: &egui::Ui, center: egui::Pos2, color: egui::Color32) {
    let s = egui::Stroke::new(1.3, color);
    let back = egui::Rect::from_min_size(center + egui::vec2(-1.0, -5.0), egui::vec2(7.0, 8.0));
    let front = egui::Rect::from_min_size(center + egui::vec2(-5.0, -1.0), egui::vec2(7.0, 8.0));
    ui.painter().rect_stroke(back, egui::Rounding::same(1.5), s);
    ui.painter()
        .rect_stroke(front, egui::Rounding::same(1.5), s);
}

/// Checkmark — copied / confirmed.
fn paint_check_icon(ui: &egui::Ui, center: egui::Pos2, color: egui::Color32) {
    let s = egui::Stroke::new(1.7, color);
    ui.painter().line_segment(
        [
            center + egui::vec2(-4.0, 0.0),
            center + egui::vec2(-1.0, 3.0),
        ],
        s,
    );
    ui.painter().line_segment(
        [
            center + egui::vec2(-1.0, 3.0),
            center + egui::vec2(4.0, -3.5),
        ],
        s,
    );
}

/// Cross — delete / dismiss.
fn paint_x_icon(ui: &egui::Ui, center: egui::Pos2, color: egui::Color32) {
    let s = egui::Stroke::new(1.4, color);
    ui.painter().line_segment(
        [
            center + egui::vec2(-3.5, -3.5),
            center + egui::vec2(3.5, 3.5),
        ],
        s,
    );
    ui.painter().line_segment(
        [
            center + egui::vec2(-3.5, 3.5),
            center + egui::vec2(3.5, -3.5),
        ],
        s,
    );
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
        egui::Stroke::new(
            1.0,
            if selected {
                p.line
            } else {
                egui::Color32::TRANSPARENT
            },
        ),
    );
    if selected {
        ui.painter().rect_filled(
            egui::Rect::from_min_size(
                rect.left_top() + egui::vec2(0.0, 13.0),
                egui::vec2(3.0, h - 26.0),
            ),
            egui::Rounding::same(3.0),
            p.accent,
        );
    }

    let token = dev.kind == DeviceKind::Token;
    let tile = egui::Rect::from_min_size(
        rect.left_top() + egui::vec2(14.0, (h - 38.0) / 2.0),
        egui::vec2(38.0, 38.0),
    );
    if token {
        paint_glyph_tile(ui, tile, p.brand_soft(), p.brand, None);
    } else {
        paint_glyph_tile(
            ui,
            tile,
            p.raised2,
            p.txt2,
            Some(
                dev.vendor
                    .chars()
                    .next()
                    .unwrap_or('?')
                    .to_ascii_uppercase(),
            ),
        );
    }

    let tx = tile.right() + 11.0;
    let right_pad = 16.0;
    // status dot, top-right
    ui.painter().circle_filled(
        egui::pos2(rect.right() - right_pad, rect.top() + 18.0),
        3.5,
        p.ok,
    );
    // vendor eyebrow
    ui.painter().text(
        egui::pos2(tx, rect.top() + 13.0),
        egui::Align2::LEFT_TOP,
        &dev.vendor,
        theme::f_sb(11.0),
        p.txt3,
    );
    // model, truncated to the available width
    let avail = (rect.right() - right_pad - 8.0) - tx;
    let galley = ui.fonts(|f| {
        let mut job = egui::text::LayoutJob::single_section(
            dev.title().to_string(),
            egui::TextFormat {
                font_id: theme::f_sb(13.5),
                color: p.txt,
                ..Default::default()
            },
        );
        job.wrap = egui::text::TextWrapping {
            max_width: avail.max(0.0),
            max_rows: 1,
            break_anywhere: true,
            overflow_character: Some('\u{2026}'),
        };
        f.layout_job(job)
    });
    ui.painter()
        .galley(egui::pos2(tx, rect.top() + 26.0), galley, p.txt);
    // capability pills
    let py = rect.top() + 46.0;
    if token {
        paint_pill(
            ui,
            egui::pos2(tx, py),
            "TOTP token",
            p.brand,
            p.brand_soft(),
        );
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
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
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
        storage.set_string(
            "colorblind",
            if self.colorblind { "1" } else { "0" }.to_string(),
        );
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Clipboard hygiene: ~45s after an OTP code was copied, clear the
        // clipboard so the code doesn't live on in clipboard-manager history —
        // but only if the clipboard still holds that exact code. Content the
        // user copied elsewhere in the meantime is never clobbered. arboard is
        // already in the tree via eframe's clipboard integration; if the
        // clipboard can't be read (e.g. some Wayland setups), fail open and
        // clear nothing rather than risk destroying foreign content.
        if let Some((ref code, t)) = self.clipboard_clear_at {
            let now = now_secs_f64();
            if now >= t {
                if let Ok(mut cb) = arboard::Clipboard::new() {
                    if cb.get_text().is_ok_and(|current| current == *code) {
                        let _ = cb.clear();
                    }
                }
                self.clipboard_clear_at = None;
            } else {
                ctx.request_repaint_after(std::time::Duration::from_secs_f64((t - now).max(0.1)));
            }
        }
        // Dropping a file on the window routes it to the bulk-import dialog —
        // the natural gesture for "import this screenshot/export".
        let dropped = ctx.input(|i| {
            i.raw
                .dropped_files
                .first()
                .and_then(|f| f.path.as_ref())
                .map(|p| p.display().to_string())
        });
        if let Some(path) = dropped {
            self.bulk_dialog.open = true;
            self.bulk_dialog.path = path;
            self.bulk_load();
        }

        // Apply any results from background device jobs and the import
        // thread before drawing.
        self.drain_worker();
        self.drain_import();
        let p = self.palette();
        // Rebuilding + re-applying egui Visuals every frame is wasted work;
        // only do it when a theme knob actually changed.
        let theme_key = (self.mode, self.accent_idx, self.colorblind);
        if self.applied_theme != Some(theme_key) {
            p.apply(ctx, self.mode);
            self.applied_theme = Some(theme_key);
        }

        // First frame: scan for devices automatically so the user isn't staring
        // at an empty pane wondering whether the app is broken.
        if !self.scanned {
            self.scanned = true;
            self.schedule_scan_burst();
        }

        // Armed FIDO reset: poll the live key list so we can fire the reset the
        // instant the user re-inserts the key. Runs before the hotplug refresh
        // and holds the worker slot, so a replug-triggered rescan can't beat the
        // reset to it.
        if self.reset_arm.is_some() {
            self.poll_reset_arm();
            ctx.request_repaint_after(std::time::Duration::from_millis(200));
        }

        // Reader hotplug: the watcher set this flag (and woke us). Start a
        // rescan burst (suppressed while a reset is armed, so its job can't
        // steal the worker slot).
        if self.reset_arm.is_none()
            && self
                .devices_dirty
                .swap(false, std::sync::atomic::Ordering::Relaxed)
        {
            self.schedule_scan_burst();
        }

        // Drive the rescan burst: run a scan when one is due and the worker is
        // free, then schedule the next. Spacing gives a slow reader (Molto2)
        // time to register with pcscd between attempts.
        if self.reset_arm.is_none() && self.pending_scans > 0 {
            let now = std::time::Instant::now();
            let due = self.next_scan_at.map_or(true, |t| now >= t);
            if due && !self.busy() {
                self.refresh_devices();
                self.pending_scans -= 1;
                self.next_scan_at = Some(now + std::time::Duration::from_millis(1500));
            }
            if self.pending_scans > 0 {
                ctx.request_repaint_after(std::time::Duration::from_millis(500));
            }
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
        self.render_piv_confirms(ctx);
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
            || (matches!(self.cap_tab, CapTab::Overview)
                && self.oath.loaded
                && !self.oath.creds.is_empty())
            || self
                .selected_device()
                .is_some_and(|d| d.kind == DeviceKind::Token);
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
        if r.hovered() {
            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
        }
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
                    ui.label(
                        egui::RichText::new("keyroost")
                            .font(theme::f_bold(14.0))
                            .color(p.txt),
                    );
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
                            ui.label(
                                egui::RichText::new(label.as_str())
                                    .font(theme::f_reg(12.0))
                                    .color(p.txt3),
                            );
                        }
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if theme::button(ui, p, BtnKind::Ghost, "Refresh").clicked() {
                            self.schedule_scan_burst();
                        }
                        ui.add_space(4.0);
                        let log_color = if self.log_open { p.accent } else { p.txt2 };
                        if ui
                            .add(
                                egui::Label::new(
                                    egui::RichText::new("Activity log")
                                        .font(theme::f_sb(12.5))
                                        .color(log_color),
                                )
                                .sense(egui::Sense::click()),
                            )
                            .on_hover_cursor(egui::CursorIcon::PointingHand)
                            .clicked()
                        {
                            self.log_open = !self.log_open;
                        }
                        ui.add_space(10.0);
                        ui.hyperlink_to(
                            egui::RichText::new("Learn \u{2197}")
                                .font(theme::f_sb(12.5))
                                .color(p.txt2),
                            ui::help::LEARN_BASE,
                        );
                        ui.add_space(10.0);
                        let (trect, tresp) =
                            ui.allocate_exact_size(egui::vec2(18.0, 18.0), egui::Sense::click());
                        paint_theme_icon(ui, trect.center(), 7.0, p.txt2);
                        if tresp
                            .on_hover_text("Toggle light / dark")
                            .on_hover_cursor(egui::CursorIcon::PointingHand)
                            .clicked()
                        {
                            self.mode = match self.mode {
                                Mode::Dark => Mode::Light,
                                Mode::Light => Mode::Dark,
                            };
                        }
                        ui.add_space(10.0);
                        let (erect, eresp) =
                            ui.allocate_exact_size(egui::vec2(18.0, 18.0), egui::Sense::click());
                        paint_eye_icon(
                            ui,
                            erect.center(),
                            if self.colorblind { p.accent } else { p.txt2 },
                        );
                        if eresp
                            .on_hover_text("Colorblind-safe colors")
                            .on_hover_cursor(egui::CursorIcon::PointingHand)
                            .clicked()
                        {
                            self.colorblind = !self.colorblind;
                        }
                        ui.add_space(10.0);
                        for (i, c) in Palette::ACCENTS.iter().enumerate().rev() {
                            let (rect, resp) = ui
                                .allocate_exact_size(egui::vec2(16.0, 16.0), egui::Sense::click());
                            let on = i == self.accent_idx;
                            ui.painter().circle_filled(
                                rect.center(),
                                if on { 6.0 } else { 5.0 },
                                *c,
                            );
                            if on {
                                ui.painter().circle_stroke(
                                    rect.center(),
                                    7.5,
                                    egui::Stroke::new(1.5, p.txt),
                                );
                            }
                            if resp.hovered() {
                                ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
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
                    ui.label(
                        egui::RichText::new("DEVICES")
                            .font(theme::f_bold(11.0))
                            .color(p.txt3),
                    );
                    ui.add_space(6.0);
                    theme::pill(ui, &self.devices.len().to_string(), p.txt2, p.raised2);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let (rrect, rresp) =
                            ui.allocate_exact_size(egui::vec2(18.0, 18.0), egui::Sense::click());
                        paint_refresh_icon(ui, rrect.center(), 6.5, p.txt2);
                        if rresp
                            .on_hover_text("Rescan")
                            .on_hover_cursor(egui::CursorIcon::PointingHand)
                            .clicked()
                        {
                            self.schedule_scan_burst();
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
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        if self.devices.is_empty() {
                            ui.add_space(12.0);
                            ui.vertical_centered(|ui| {
                                ui.label(
                                    egui::RichText::new("No keys detected yet.")
                                        .font(theme::f_reg(13.0))
                                        .color(p.txt3),
                                );
                            });
                        }
                        for dev in self
                            .devices
                            .iter()
                            .filter(|d| matches_filter(d, &self.filter))
                        {
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
                            ui.label(
                                egui::RichText::new("Several keys plugged in?")
                                    .font(theme::f_reg(12.0))
                                    .color(p.txt3),
                            );
                            ui.hyperlink_to(
                                egui::RichText::new("Give them names")
                                    .font(theme::f_sb(12.0))
                                    .color(p.accent),
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
                    ui.label(
                        egui::RichText::new("ACTIVITY LOG")
                            .font(theme::f_bold(11.0))
                            .color(p.txt3),
                    );
                    ui.add_space(6.0);
                    theme::pill(ui, "live", p.ok, p.ok_soft());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if theme::button(ui, p, BtnKind::Ghost, "Collapse").clicked() {
                            self.log_open = false;
                        }
                        ui.add_space(4.0);
                        if theme::button(ui, p, BtnKind::Ghost, "Copy").clicked() {
                            let all = self
                                .log
                                .iter()
                                .map(|l| l.text.clone())
                                .collect::<Vec<_>>()
                                .join("\n");
                            ui.output_mut(|o| o.copied_text = all);
                            // The user copied non-secret log text over the
                            // code; a pending auto-clear would clobber it.
                            self.clipboard_clear_at = None;
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
                            ui.label(
                                egui::RichText::new(&line.text)
                                    .font(theme::f_mono(12.0))
                                    .color(color),
                            );
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
                            // Hero + tabs stay pinned; the active pane scrolls.
                            // This is the one place every capability pane gets
                            // its overflow handling — a card-heavy OpenPGP pane
                            // or a key holding dozens of passkeys/TOTP codes
                            // scrolls instead of clipping at the window edge.
                            // Salted per tab so each pane keeps its own
                            // scroll position.
                            //
                            // Solid bar style: reserve a real gutter for the
                            // scrollbar instead of floating it over the cards'
                            // right edge (the floating bar sat on top of card
                            // borders and the panes' top-right action buttons).
                            ui.spacing_mut().scroll = egui::style::ScrollStyle::solid();
                            egui::ScrollArea::vertical()
                                .id_salt(("cap-pane", self.cap_tab as u8))
                                .auto_shrink([false, false])
                                .show(ui, |ui| {
                                    match self.cap_tab {
                                        CapTab::Overview => self.overview(ui, p, &dev),
                                        CapTab::Fido2 => self.cap_fido2(ui, p),
                                        CapTab::Oath => self.cap_oath(ui, p),
                                        CapTab::Pgp => self.cap_pgp(ui, p),
                                        CapTab::Piv => self.cap_piv(ui, p),
                                        CapTab::Otp => self.cap_otp(ui, p),
                                    }
                                    // Breathing room below the last card.
                                    ui.add_space(18.0);
                                });
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
                            self.schedule_scan_burst();
                        }
                        ui.add_space(8.0);
                        ui.hyperlink_to(
                            egui::RichText::new("Supported devices \u{2197}").font(theme::f_sb(12.5)).color(p.accent),
                            ui::help::learn_url("/devices"),
                        );
                    });
                    // Be honest on platforms without a HID backend yet: a plugged-in
                    // FIDO key simply won't appear, so say why rather than letting
                    // the user think it's broken.
                    if !keyroost_hid::hid_supported() {
                        ui.add_space(16.0);
                        ui.label(
                            egui::RichText::new(
                                "Note: FIDO / passkey security keys aren't supported on this platform yet. Smart-card features (OATH, OpenPGP, PIV, Token2 Molto2) work over PC/SC.",
                            )
                            .font(theme::f_reg(12.5))
                            .color(p.txt3),
                        );
                    }
                },
            );
        });
    }

    /// Device hero strip at the top of a key's pane.
    fn device_hero(&mut self, ui: &mut egui::Ui, p: &Palette, dev: &UiDevice) {
        let mut open_rename = false;
        let mut do_save = false;
        let mut do_cancel = false;
        ui.horizontal(|ui| {
            glyph_tile(ui, 46.0, p.raised2, p.txt2, Some(dev.vendor.chars().next().unwrap_or('?').to_ascii_uppercase()));
            ui.add_space(12.0);
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    if self.rename_open {
                        let resp = ui.add(
                            egui::TextEdit::singleline(&mut self.rename_input)
                                .hint_text("friendly-name")
                                .desired_width(200.0),
                        );
                        let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                        if theme::button(ui, p, BtnKind::Primary, "Save").clicked() || enter {
                            do_save = true;
                        }
                        ui.add_space(4.0);
                        if theme::button(ui, p, BtnKind::Ghost, "Cancel").clicked() {
                            do_cancel = true;
                        }
                    } else {
                        ui.label(egui::RichText::new(dev.title()).font(theme::f_bold(21.0)).color(p.txt));
                        ui.add_space(5.0);
                        self.help_dot(ui, p, "device");
                        ui.add_space(8.0);
                        let label = if dev.name.is_some() { "Rename" } else { "Name this key" };
                        if ui
                            .add(
                                egui::Label::new(egui::RichText::new(label).font(theme::f_sb(12.0)).color(p.accent))
                                    .sense(egui::Sense::click()),
                            )
                            .clicked()
                        {
                            open_rename = true;
                        }
                    }
                });
                if self.rename_open {
                    ui.add_space(3.0);
                    ui.label(
                        egui::RichText::new(
                            "Saves this key's serial with the name to keys.json on this computer \u{2014} nothing leaves your machine. Lowercase letters, digits, - and _.",
                        )
                        .font(theme::f_reg(11.5))
                        .color(p.txt3),
                    );
                }
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
        self.apply_rename_actions(dev, open_rename, do_cancel, do_save);
        ui.add_space(14.0);
        let y = ui.cursor().top();
        ui.painter()
            .hline(ui.max_rect().x_range(), y, egui::Stroke::new(1.0, p.line));
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
                    egui::Label::new(
                        egui::RichText::new(cap_tab_label(t))
                            .font(theme::f_sb(13.5))
                            .color(color),
                    )
                    .sense(egui::Sense::click()),
                );
                if active {
                    let y = resp.rect.bottom() + 6.0;
                    ui.painter().line_segment(
                        [
                            egui::pos2(resp.rect.left(), y),
                            egui::pos2(resp.rect.right(), y),
                        ],
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
    fn card_head(
        &mut self,
        ui: &mut egui::Ui,
        p: &Palette,
        title: &str,
        topic: &'static str,
    ) -> bool {
        let mut go = false;
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new(title)
                    .font(theme::f_sb(14.5))
                    .color(p.txt),
            );
            ui.add_space(6.0);
            self.help_dot(ui, p, topic);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add(
                        egui::Label::new(
                            egui::RichText::new("Manage \u{2192}")
                                .font(theme::f_sb(12.5))
                                .color(p.accent),
                        )
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
    /// Scrolling comes from the shared capability-pane scroller in `central`.
    fn overview(&mut self, ui: &mut egui::Ui, p: &Palette, dev: &UiDevice) {
        ui.vertical(|ui| {
            if dev.caps.has(Caps::FIDO2) {
                theme::card_frame(p).show(ui, |ui| {
                    if self.card_head(ui, p, "Passkeys & sign-in (FIDO2)", "fido2") {
                        self.cap_tab = CapTab::Fido2;
                    }
                    ui.add_space(8.0);
                    match self
                        .security_keys
                        .info
                        .as_ref()
                        .and_then(|i| i.option("clientPin"))
                    {
                        Some(true) => {
                            ui.horizontal(|ui| {
                                theme::pill(ui, "PIN set", p.ok, p.ok_soft());
                                ui.add_space(8.0);
                                ui.label(
                                    egui::RichText::new(
                                        "PIN configured \u{00B7} ready for passkeys",
                                    )
                                    .font(theme::f_reg(13.0))
                                    .color(p.txt2),
                                );
                            });
                        }
                        Some(false) => {
                            theme::pill(ui, "No PIN configured", p.warn, p.warn_soft());
                        }
                        None => {
                            ui.label(
                                egui::RichText::new("Reading key\u{2026}")
                                    .font(theme::f_reg(13.0))
                                    .color(p.txt3),
                            );
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
                            let is_copied =
                                self.copied.as_ref().is_some_and(|(n, _)| n == &row.name);
                            if let (Some(code), _) =
                                oath_row(ui, p, &row.name, row.code.as_deref(), is_copied, false)
                            {
                                copy = Some((row.name.clone(), code));
                            }
                            ui.add_space(6.0);
                        }
                        if total > 2 {
                            ui.label(
                                egui::RichText::new(format!("+{} more codes", total - 2))
                                    .font(theme::f_reg(12.5))
                                    .color(p.txt3),
                            );
                        }
                        if let Some((name, code)) = copy {
                            ui.output_mut(|o| o.copied_text = code.clone());
                            self.copied = Some((name, now_secs_f64() + 1.2));
                            self.clipboard_clear_at = Some((code, now_secs_f64() + 45.0));
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
                            theme::pill(
                                ui,
                                &format!(
                                    "Signature \u{00B7} {}",
                                    slot_summary(st.sig_algo_id, &st.fingerprint_sig)
                                ),
                                p.txt2,
                                p.raised2,
                            );
                            theme::pill(
                                ui,
                                &format!(
                                    "Encryption \u{00B7} {}",
                                    slot_summary(st.dec_algo_id, &st.fingerprint_dec)
                                ),
                                p.txt2,
                                p.raised2,
                            );
                            theme::pill(
                                ui,
                                &format!(
                                    "Auth \u{00B7} {}",
                                    slot_summary(st.aut_algo_id, &st.fingerprint_aut)
                                ),
                                p.txt2,
                                p.raised2,
                            );
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
                                let lab = format!(
                                    "{:02X} \u{00B7} {}",
                                    slot.slot.key_ref(),
                                    if slot.cert_present { "cert" } else { "empty" }
                                );
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
        let pin_set = self
            .security_keys
            .info
            .as_ref()
            .and_then(|i| i.option("clientPin"));

        // --- PIN & sign-in card (inline Set / Change PIN; no floating modal) ---
        let mut go_set = false;
        let mut go_change = false;
        let mut cancel = false;
        theme::card_frame(p).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("PIN & sign-in")
                        .font(theme::f_sb(14.5))
                        .color(p.txt),
                );
                ui.add_space(6.0);
                self.help_dot(ui, p, "pin");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let (kind, label) = match pin_set {
                        Some(true) => (BtnKind::Default, "Change PIN"),
                        Some(false) => (BtnKind::Primary, "Set a PIN"),
                        None => return,
                    };
                    if theme::button(ui, p, kind, label).clicked() {
                        let open = !self.security_keys.change_pin.open;
                        self.security_keys.change_pin = ChangePinDialog {
                            open,
                            ..Default::default()
                        };
                        self.security_keys.error = None;
                    }
                });
            });
            ui.add_space(8.0);
            match pin_set {
                Some(true) => {
                    ui.horizontal(|ui| {
                        theme::pill(ui, "PIN set", p.ok, p.ok_soft());
                        ui.add_space(8.0);
                        ui.label(
                            egui::RichText::new(
                                "This key has a PIN. Unlock below to manage passkeys.",
                            )
                            .font(theme::f_reg(13.0))
                            .color(p.txt2),
                        );
                    });
                }
                Some(false) => {
                    ui.horizontal(|ui| {
                        theme::pill(ui, "No PIN yet", p.warn, p.warn_soft());
                        ui.add_space(8.0);
                        ui.label(
                            egui::RichText::new(
                                "Set a PIN to protect this key and turn on passkeys.",
                            )
                            .font(theme::f_reg(13.0))
                            .color(p.txt2),
                        );
                    });
                }
                None => {
                    let msg = if self.security_keys.error.is_some() {
                        "Couldn't read this key."
                    } else {
                        // The initial read can be dropped if the worker was
                        // busy at selection time; retry rather than showing
                        // "Reading key…" forever.
                        if self.security_keys.init.is_none() && !self.busy() {
                            self.fetch_selected_info();
                        }
                        "Reading key\u{2026}"
                    };
                    ui.label(
                        egui::RichText::new(msg)
                            .font(theme::f_reg(13.0))
                            .color(p.txt3),
                    );
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
                        ui.label(
                            egui::RichText::new(if setting {
                                "Create a PIN"
                            } else {
                                "Change PIN"
                            })
                            .font(theme::f_sb(13.0))
                            .color(p.txt),
                        );
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
                            if theme::button(
                                ui,
                                p,
                                BtnKind::Primary,
                                if setting { "Set PIN" } else { "Change PIN" },
                            )
                            .clicked()
                            {
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
                        ui.label(
                            egui::RichText::new(
                                "4\u{2013}63 characters. You'll touch the key to confirm.",
                            )
                            .font(theme::f_reg(11.5))
                            .color(p.txt3),
                        );
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
                    ui.label(
                        egui::RichText::new("Resident passkeys")
                            .font(theme::f_sb(14.5))
                            .color(p.txt),
                    );
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
                let session_info = self.security_keys.session.as_ref().map(|s| {
                    (
                        s.metadata.existing_count,
                        s.metadata.max_remaining,
                        s.rps.clone(),
                    )
                });
                if let Some((existing, max_remaining, rps)) = session_info {
                    ui.label(
                        egui::RichText::new(format!(
                            "{existing} stored \u{00B7} room for {max_remaining} more"
                        ))
                        .font(theme::f_reg(12.5))
                        .color(p.txt2),
                    );
                    ui.add_space(6.0);
                    if rps.is_empty() {
                        ui.label(
                            egui::RichText::new("No passkeys stored on this key yet.")
                                .font(theme::f_reg(13.0))
                                .color(p.txt3),
                        );
                    }
                    // No inner scroller: the shared capability-pane scroller in
                    // `central` handles overflow, so a long passkey list flows
                    // down the page instead of trapping the wheel in a box.
                    ui.vertical(|ui| {
                        for (rp, creds) in rps.iter() {
                            let header =
                                if let Some(name) = rp.name.as_ref().filter(|s| !s.is_empty()) {
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
                                            .unwrap_or_else(|| {
                                                String::from_utf8_lossy(&c.user.id).into_owned()
                                            });
                                        ui.label(user_field);
                                        ui.with_layout(
                                            egui::Layout::right_to_left(egui::Align::Center),
                                            |ui| {
                                                if theme::button(ui, p, BtnKind::Ghost, "Remove")
                                                    .clicked()
                                                {
                                                    delete = Some(c.credential_id.clone());
                                                }
                                            },
                                        );
                                    });
                                }
                            });
                        }
                    });
                } else {
                    ui.horizontal(|ui| {
                        let resp = ui.add(
                            egui::TextEdit::singleline(&mut self.security_keys.pin_input)
                                .password(true)
                                .hint_text("Enter PIN to view passkeys")
                                .desired_width(220.0),
                        );
                        let submit = theme::button(ui, p, BtnKind::Primary, "Unlock").clicked();
                        if submit
                            || (resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)))
                        {
                            unlock = true;
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
                    ui.label(
                        egui::RichText::new("Reset this key")
                            .font(theme::f_sb(14.5))
                            .color(p.err),
                    );
                    ui.add_space(6.0);
                    self.help_dot(ui, p, "reset");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if theme::button(ui, p, BtnKind::Danger, "Reset key\u{2026}").clicked() {
                            arm_reset = true;
                        }
                    });
                });
                ui.label(
                    egui::RichText::new(
                        "Wipes every passkey and the PIN on this key. Cannot be undone.",
                    )
                    .font(theme::f_reg(12.5))
                    .color(p.txt2),
                );
            });
        if arm_reset {
            self.security_keys.reset = ResetDialog {
                open: true,
                ..Default::default()
            };
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
            ui.label(
                egui::RichText::new("Authenticator codes")
                    .font(theme::f_sb(14.5))
                    .color(p.txt),
            );
            ui.add_space(6.0);
            self.help_dot(ui, p, "oath");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if theme::button(ui, p, BtnKind::Primary, "+ Add credential").clicked() {
                    // No struct-update syntax: OathAddDialog has a Drop impl
                    // (it wipes the typed seed), which forbids `..Default`.
                    self.oath.add = OathAddDialog {
                        open: true,
                        name: String::new(),
                        secret: String::new(),
                        totp: true,
                        require_touch: false,
                    };
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
                    ui.add(
                        egui::TextEdit::singleline(&mut self.oath.password_input)
                            .password(true)
                            .desired_width(220.0),
                    );
                    if theme::button(ui, p, BtnKind::Primary, "Unlock").clicked() {
                        self.load_oath_creds();
                    }
                });
            });
            return;
        }
        if !self.oath.loaded {
            ui.label(
                egui::RichText::new("Reading codes\u{2026}")
                    .font(theme::f_reg(13.0))
                    .color(p.txt3),
            );
            return;
        }
        if self.oath.creds.is_empty() {
            ui.label(
                egui::RichText::new("No authenticator codes on this key.")
                    .font(theme::f_reg(13.0))
                    .color(p.txt3),
            );
            return;
        }

        let mut copy: Option<(String, String)> = None;
        let mut delete: Option<String> = None;
        theme::card_frame(p).show(ui, |ui| {
            let n = self.oath.creds.len();
            for (i, row) in self.oath.creds.iter().enumerate() {
                let is_copied = self.copied.as_ref().is_some_and(|(nm, _)| nm == &row.name);
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
                    ui.painter().hline(
                        ui.max_rect().x_range(),
                        y,
                        egui::Stroke::new(1.0, p.line_soft),
                    );
                    ui.add_space(5.0);
                }
            }
        });
        if let Some((name, code)) = copy {
            ui.output_mut(|o| o.copied_text = code.clone());
            self.copied = Some((name, now_secs_f64() + 1.2));
            self.clipboard_clear_at = Some((code, now_secs_f64() + 45.0));
        }
        if let Some(name) = delete {
            self.oath.confirm_delete = Some(name);
        }
    }

    /// OpenPGP tab — read-only status + the existing management section.
    fn cap_pgp(&mut self, ui: &mut egui::Ui, p: &Palette) {
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new("OpenPGP")
                    .font(theme::f_sb(14.5))
                    .color(p.txt),
            );
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
                kv(
                    ui,
                    "Signature key",
                    &format!(
                        "{}  {}",
                        algo_id_label(status.sig_algo_id),
                        fpr_label(&status.fingerprint_sig)
                    ),
                );
                kv(
                    ui,
                    "Decryption key",
                    &format!(
                        "{}  {}",
                        algo_id_label(status.dec_algo_id),
                        fpr_label(&status.fingerprint_dec)
                    ),
                );
                kv(
                    ui,
                    "Authentication key",
                    &format!(
                        "{}  {}",
                        algo_id_label(status.aut_algo_id),
                        fpr_label(&status.fingerprint_aut)
                    ),
                );
                kv(
                    ui,
                    "PIN retries",
                    &format!(
                        "PW1={} RC={} PW3={}",
                        status.tries_pw1, status.tries_rc, status.tries_pw3
                    ),
                );
                kv(
                    ui,
                    "Signatures made",
                    &status
                        .signature_count
                        .map_or("(unavailable)".to_string(), |n| n.to_string()),
                );
            });
        } else {
            ui.label(
                egui::RichText::new("Click Read status to read this card (no PIN or touch).")
                    .font(theme::f_reg(13.0))
                    .color(p.txt3),
            );
        }
        ui.add_space(10.0);
        self.render_openpgp_manage(ui, p);
    }

    /// PIV tab — read-only status snapshot (auto-read on first view).
    fn cap_piv(&mut self, ui: &mut egui::Ui, p: &Palette) {
        if !self.piv_tried && !self.busy() {
            self.piv_tried = true;
            self.load_piv_status();
        }
        // Intents collected inside the UI closures and applied afterwards, so a
        // submit method's `&mut self` never overlaps a card's borrow.
        let mut do_refresh = false;
        let mut go_change_pin = false;
        let mut go_change_puk = false;
        let mut go_unblock = false;
        let mut go_generate = false;
        let mut go_import = false;
        let mut go_export = false;
        let mut go_self_sign = false;
        let mut go_csr = false;
        let mut go_set_retries = false;
        let mut go_change_mgmt = false;
        let mut arm_reset = false;
        let mut copy_pem: Option<String> = None;

        let head = |ui: &mut egui::Ui, t: &str| card_head(ui, p, t);
        let sub = |ui: &mut egui::Ui, t: &str| card_sub(ui, p, t);
        let note = |ui: &mut egui::Ui, t: &str| card_note(ui, p, t);

        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new("PIV smart card")
                    .font(theme::f_sb(14.5))
                    .color(p.txt),
            );
            ui.add_space(6.0);
            self.help_dot(ui, p, "piv");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if theme::button(ui, p, BtnKind::Default, "Refresh").clicked() {
                    do_refresh = true;
                }
            });
        });
        ui.add_space(10.0);
        if let Some(err) = &self.piv.error {
            ui.colored_label(p.err, err);
            ui.add_space(6.0);
        }
        if let Some(n) = &self.piv.notice {
            ui.colored_label(p.ok, n);
            ui.add_space(6.0);
        }

        // --- Status ---
        if let Some(st) = &self.piv.status {
            theme::card_frame(p).show(ui, |ui| {
                kv(
                    ui,
                    "Applet version",
                    &st.version
                        .map_or("\u{2014}".to_string(), |(a, b, c)| format!("{a}.{b}.{c}")),
                );
                kv(
                    ui,
                    "Serial",
                    &st.serial.map_or("\u{2014}".to_string(), |s| s.to_string()),
                );
                kv(
                    ui,
                    "PIN retries",
                    &st.pin_retries
                        .map_or("\u{2014}".to_string(), |n| n.to_string()),
                );
                ui.add_space(6.0);
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing.x = 5.0;
                    for slot in &st.slots {
                        let lab = format!(
                            "{:02X} \u{00B7} {}",
                            slot.slot.key_ref(),
                            if slot.cert_present { "cert" } else { "empty" }
                        );
                        theme::pill(ui, &lab, p.txt2, p.raised2);
                    }
                });
            });
        } else if self.piv.error.is_none() {
            ui.label(
                egui::RichText::new("Reading PIV status\u{2026}")
                    .font(theme::f_reg(13.0))
                    .color(p.txt3),
            );
        }
        ui.add_space(10.0);

        // --- Management key: authorizes key-gen / cert-import / retries / rotation ---
        // Compute the vendor-specific default hint before the closure borrows self.
        let is_token2 = self
            .selected_device()
            .map(|d| d.vendor.eq_ignore_ascii_case("token2"))
            .unwrap_or(false);
        let mgmt_default_note = if is_token2 {
            "Hex key authorizing key generation, certificate import, retry \
             changes, and rotation below. Token2 PIN+ factory default is \
             865362865362865362865362865362865362865362865362. Sent for the \
             operation only; never stored."
        } else {
            "Hex key authorizing key generation, certificate import, retry \
             changes, and rotation below. Factory default (most keys) is \
             010203040506070801020304050607080102030405060708. Sent for the \
             operation only; never stored."
        };
        theme::card_frame(p).show(ui, |ui| {
            head(ui, "Management key");
            note(ui, mgmt_default_note);
            ui.add_space(6.0);
            secret_field(
                ui,
                p,
                "Management key",
                &mut self.piv.mgmt_key_input,
                "hex (48/32/64 chars)",
                300.0,
            );
        });
        ui.add_space(10.0);

        // --- PIN & PUK ---
        egui::CollapsingHeader::new(
            egui::RichText::new("PIN & PUK")
                .font(theme::f_sb(13.5))
                .color(p.txt),
        )
        .id_salt("piv-pin-puk")
        .show(ui, |ui| {
            theme::card_frame(p).show(ui, |ui| {
                sub(ui, "Change PIN");
                pin_field(ui, p, "Current PIN", &mut self.piv.pin_old);
                pin_field(ui, p, "New PIN", &mut self.piv.pin_new);
                if theme::button(ui, p, BtnKind::Default, "Change PIN").clicked() {
                    go_change_pin = true;
                }
                ui.add_space(10.0);
                sub(ui, "Change PUK");
                pin_field(ui, p, "Current PUK", &mut self.piv.puk_old);
                pin_field(ui, p, "New PUK", &mut self.piv.puk_new);
                if theme::button(ui, p, BtnKind::Default, "Change PUK").clicked() {
                    go_change_puk = true;
                }
                ui.add_space(10.0);
                sub(ui, "Unblock PIN with PUK");
                note(ui, "Recovers a blocked PIN without wiping any keys.");
                pin_field(ui, p, "PUK", &mut self.piv.unblock_puk);
                pin_field(ui, p, "New PIN", &mut self.piv.unblock_new_pin);
                if theme::button(ui, p, BtnKind::Default, "Unblock PIN").clicked() {
                    go_unblock = true;
                }
            });
        });
        ui.add_space(6.0);

        // --- Keys & certificates ---
        egui::CollapsingHeader::new(
            egui::RichText::new("Keys & certificates")
                .font(theme::f_sb(13.5))
                .color(p.txt),
        )
        .id_salt("piv-keys")
        .default_open(true)
        .show(ui, |ui| {
            theme::card_frame(p).show(ui, |ui| {
                sub(ui, "Generate key pair");
                note(
                    ui,
                    "Creates a fresh key in the slot (OVERWRITES it) and shows its \
                     public key. Needs the management key above.",
                );
                ui.horizontal(|ui| {
                    piv_slot_combo(ui, "piv-gen-slot", &mut self.piv.gen_slot);
                    piv_keyalg_combo(ui, "piv-gen-alg", &mut self.piv.gen_alg);
                    if theme::button(ui, p, BtnKind::Default, "Generate\u{2026}").clicked() {
                        go_generate = true;
                    }
                });
                if let Some(pem) = &self.piv.gen_pubkey_pem {
                    ui.add_space(4.0);
                    ui.add(
                        egui::TextEdit::multiline(&mut pem.as_str())
                            .desired_rows(4)
                            .desired_width(360.0)
                            .font(egui::TextStyle::Monospace),
                    );
                    if theme::button(ui, p, BtnKind::Ghost, "Copy public key").clicked() {
                        copy_pem = Some(pem.clone());
                    }
                }
                ui.add_space(10.0);
                sub(ui, "Create certificate");
                note(
                    ui,
                    "Signed on the card with the slot's key (generate one above \
                     first). \u{201c}Self-signed\u{201d} stores the certificate in \
                     the slot — needs the PIN and the management key. \u{201c}Save \
                     CSR\u{201d} writes a request file to hand to a certificate \
                     authority — needs only the PIN.",
                );
                ui.horizontal(|ui| {
                    piv_slot_combo(ui, "piv-certify-slot", &mut self.piv.certify_slot);
                });
                text_field(
                    ui,
                    p,
                    "Name",
                    &mut self.piv.cert_subject,
                    "e.g. Alice — or full CN=Alice,O=Example,C=US",
                    300.0,
                );
                pin_field(ui, p, "PIN", &mut self.piv.sign_pin);
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new("Valid for")
                            .font(theme::f_reg(13.0))
                            .color(p.txt2),
                    );
                    ui.add(
                        egui::DragValue::new(&mut self.piv.cert_days)
                            .range(1..=3650u32)
                            .suffix(" days"),
                    );
                    ui.add_space(8.0);
                    if theme::button(ui, p, BtnKind::Default, "Self-signed \u{2192} slot").clicked()
                    {
                        go_self_sign = true;
                    }
                });
                text_field(
                    ui,
                    p,
                    "CSR file",
                    &mut self.piv.csr_path,
                    "/path/to/request.csr",
                    240.0,
                );
                if theme::button(ui, p, BtnKind::Default, "Sign & save CSR").clicked() {
                    go_csr = true;
                }
                ui.add_space(10.0);
                sub(ui, "Import certificate");
                note(ui, "PEM or DER X.509 file. Needs the management key.");
                ui.horizontal(|ui| {
                    piv_slot_combo(ui, "piv-cert-slot", &mut self.piv.cert_slot);
                });
                text_field(
                    ui,
                    p,
                    "File",
                    &mut self.piv.cert_path,
                    "/path/to/cert.pem",
                    240.0,
                );
                if theme::button(ui, p, BtnKind::Default, "Import certificate").clicked() {
                    go_import = true;
                }
                ui.add_space(10.0);
                sub(ui, "Export certificate");
                note(ui, "Writes the slot's certificate as DER. No PIN needed.");
                ui.horizontal(|ui| {
                    piv_slot_combo(ui, "piv-export-slot", &mut self.piv.export_slot);
                });
                text_field(
                    ui,
                    p,
                    "Destination",
                    &mut self.piv.export_path,
                    "/path/to/out.der",
                    240.0,
                );
                if theme::button(ui, p, BtnKind::Default, "Export certificate").clicked() {
                    go_export = true;
                }
            });
        });
        ui.add_space(6.0);

        // --- Retry counts & management-key rotation ---
        egui::CollapsingHeader::new(
            egui::RichText::new("Retry counts & key rotation")
                .font(theme::f_sb(13.5))
                .color(p.txt),
        )
        .id_salt("piv-admin")
        .show(ui, |ui| {
            theme::card_frame(p).show(ui, |ui| {
                sub(ui, "Set PIN/PUK retry counts");
                note(
                    ui,
                    "Resets PIN and PUK to factory defaults. Needs the management \
                     key above and the current PIN.",
                );
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new("PIN tries")
                            .font(theme::f_reg(13.0))
                            .color(p.txt2),
                    );
                    ui.add(egui::DragValue::new(&mut self.piv.retries_pin).range(1..=15u8));
                    ui.add_space(8.0);
                    ui.label(
                        egui::RichText::new("PUK tries")
                            .font(theme::f_reg(13.0))
                            .color(p.txt2),
                    );
                    ui.add(egui::DragValue::new(&mut self.piv.retries_puk).range(1..=15u8));
                });
                pin_field(ui, p, "Current PIN", &mut self.piv.retries_pin_auth);
                if theme::button(ui, p, BtnKind::Default, "Set retry counts").clicked() {
                    go_set_retries = true;
                }
                ui.add_space(10.0);
                sub(ui, "Change management key");
                note(ui, "Enter the current key above; the new key here.");
                secret_field(
                    ui,
                    p,
                    "New key",
                    &mut self.piv.new_mgmt_key_input,
                    "hex (48/32/64 chars)",
                    300.0,
                );
                ui.horizontal(|ui| {
                    piv_mgmtalg_combo(ui, "piv-new-mgmt-alg", &mut self.piv.new_mgmt_alg);
                    if theme::button(ui, p, BtnKind::Default, "Change management key").clicked() {
                        go_change_mgmt = true;
                    }
                });
            });
        });
        ui.add_space(10.0);

        // --- Danger: reset applet ---
        theme::card_frame(p)
            .stroke(egui::Stroke::new(1.0, theme::tint(p.err, 90)))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new("Reset applet")
                            .font(theme::f_sb(14.0))
                            .color(p.err),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if theme::button(ui, p, BtnKind::Danger, "Reset applet\u{2026}").clicked() {
                            arm_reset = true;
                        }
                    });
                });
                ui.label(
                    egui::RichText::new(
                        "Wipes ALL PIV keys, certificates, and PINs. Only works when both \
                         the PIN and PUK are already blocked.",
                    )
                    .font(theme::f_reg(12.0))
                    .color(p.txt2),
                );
            });

        // Apply collected intents now that the card borrows have ended.
        if do_refresh {
            self.load_piv_status();
        }
        if go_change_pin {
            self.piv_change_pin();
        }
        if go_change_puk {
            self.piv_change_puk();
        }
        if go_unblock {
            self.piv_unblock_pin();
        }
        if go_generate {
            self.piv_generate_key();
        }
        if go_import {
            self.piv_import_cert();
        }
        if go_export {
            self.piv_export_cert();
        }
        if go_self_sign {
            self.piv_self_sign();
        }
        if go_csr {
            self.piv_request_csr();
        }
        if go_set_retries {
            self.piv_set_retries();
        }
        if go_change_mgmt {
            self.piv_change_management_key();
        }
        if arm_reset {
            self.piv.confirm_reset = Some(String::new());
        }
        if let Some(pem) = copy_pem {
            ui.output_mut(|o| o.copied_text = pem);
            self.clipboard_clear_at = None; // public key, not a secret to auto-clear
        }
    }

    /// The Molto2 token's dedicated amber view: hero band · customer-key strip ·
    /// 100-slot rail + editor.
    fn molto_view(&mut self, ui: &mut egui::Ui, p: &Palette, dev: &UiDevice) {
        // Make brand-orange the accent throughout the Molto2 view, so its help
        // dots, links, selection highlights and primary action are all one
        // orange rather than mixing the app's blue accent into the token's
        // identity. Green stays for status, red for danger.
        let mp = Palette {
            accent: p.brand,
            ..*p
        };
        let p = &mp;
        let mut open_rename = false;
        let mut do_save = false;
        let mut do_cancel = false;
        // Hero (no amber band — the orange comes from the clock glyph + accents,
        // matching the security-key hero layout and avoiding a muddy brown tint).
        egui::Frame::none()
            .inner_margin(egui::Margin::symmetric(26.0, 16.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    glyph_tile(ui, 46.0, p.brand, p.accent_ink, None);
                    ui.add_space(12.0);
                    ui.vertical(|ui| {
                        ui.horizontal(|ui| {
                            if self.rename_open {
                                let resp = ui.add(
                                    egui::TextEdit::singleline(&mut self.rename_input)
                                        .hint_text("friendly-name")
                                        .desired_width(200.0),
                                );
                                let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                                if theme::button(ui, p, BtnKind::Primary, "Save").clicked() || enter {
                                    do_save = true;
                                }
                                ui.add_space(4.0);
                                if theme::button(ui, p, BtnKind::Ghost, "Cancel").clicked() {
                                    do_cancel = true;
                                }
                            } else {
                                ui.label(egui::RichText::new(dev.title()).font(theme::f_bold(21.0)).color(p.txt));
                                ui.add_space(6.0);
                                theme::pill(ui, "Programmable TOTP token", p.brand, p.brand_soft());
                                ui.add_space(4.0);
                                self.help_dot(ui, p, "molto");
                                ui.add_space(6.0);
                                let label = if dev.name.is_some() { "Rename" } else { "Name this token" };
                                if ui
                                    .add(
                                        egui::Label::new(egui::RichText::new(label).font(theme::f_sb(12.0)).color(p.accent))
                                            .sense(egui::Sense::click()),
                                    )
                                    .clicked()
                                {
                                    open_rename = true;
                                }
                            }
                        });
                        if self.rename_open {
                            ui.add_space(3.0);
                            ui.label(
                                egui::RichText::new(
                                    "Saves this token's serial with the name to keys.json on this computer \u{2014} nothing leaves your machine.",
                                )
                                .font(theme::f_reg(11.5))
                                .color(p.txt3),
                            );
                        }
                        ui.add_space(2.0);
                        let serial = if dev.serial.is_empty() { "\u{2014}".to_string() } else { dev.serial.clone() };
                        ui.label(
                            egui::RichText::new(format!("{} \u{00B7} #{} \u{00B7} {} slots", dev.vendor, serial, PROFILES))
                                .font(theme::f_reg(12.5))
                                .color(p.txt2),
                        );
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(egui::RichText::new("Connected").font(theme::f_sb(12.5)).color(p.txt2));
                        ui.add_space(5.0);
                        theme::status_dot(ui, p.ok, 8.0);
                    });
                });
            });
        self.apply_rename_actions(dev, open_rename, do_cancel, do_save);

        // --- Device-wide settings (apply to the whole token) ---
        egui::Frame::none()
            .inner_margin(egui::Margin::symmetric(26.0, 14.0))
            .show(ui, |ui| {
                theme::card_frame(p).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Device").font(theme::f_sb(14.5)).color(p.txt));
                        ui.add_space(6.0);
                        self.help_dot(ui, p, "molto");
                    });
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        ui.add_sized(
                            [104.0, 22.0],
                            egui::Label::new(egui::RichText::new("Customer key").font(theme::f_reg(13.0)).color(p.txt2)),
                        );
                        self.help_dot(ui, p, "custkey");
                        ui.add_space(6.0);
                        ui.add(
                            egui::TextEdit::singleline(&mut self.customer_key_input)
                                .password(true)
                                .hint_text("default if empty")
                                .desired_width(200.0),
                        );
                        ui.checkbox(&mut self.customer_key_hex, "hex");
                        if theme::button(ui, p, BtnKind::Default, "Authenticate").clicked() {
                            self.authenticate();
                        }
                        if self.authenticated {
                            theme::pill(ui, "authed", p.ok, p.ok_soft());
                        }
                    });
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new("Programming any slot first needs the token's customer key (blank = factory default).")
                            .font(theme::f_reg(11.5))
                            .color(p.txt3),
                    );
                    ui.add_space(12.0);
                    ui.horizontal(|ui| {
                        if theme::button(ui, p, BtnKind::Default, "Sync time on all").clicked() {
                            self.sync_time_all();
                        }
                        ui.add_space(6.0);
                        if theme::button(ui, p, BtnKind::Default, "Bulk import\u{2026}").clicked() {
                            self.bulk_dialog.open = true;
                            self.bulk_dialog.start = self.slot;
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
                                    egui::RichText::new("Factory-reset the token? This wipes all slots, then asks you to confirm with the \u{25B2} button on the device itself.")
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
                                    if theme::button(ui, p, BtnKind::Default, "Cancel").clicked() {
                                        self.molto_reset_confirm = false;
                                    }
                                });
                            });
                    }
                });
            });

        // --- Per-slot programming (applies only to the selected slot) ---
        egui::Frame::none()
            .inner_margin(egui::Margin::symmetric(26.0, 4.0))
            .show(ui, |ui| {
                theme::card_frame(p).show(ui, |ui| {
                    ui.label(egui::RichText::new("Program a slot").font(theme::f_sb(14.5)).color(p.txt));
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new("The token is write-only: pick a slot and program it. The Molto2 shows codes on its own screen \u{2014} they can't be read back here.")
                            .font(theme::f_reg(11.5))
                            .color(p.txt3),
                    );
                    ui.add_space(10.0);
                    ui.horizontal_top(|ui| {
                        ui.vertical(|ui| {
                            ui.set_width(140.0);
                            // Fill the remaining height so the rail isn't a fixed
                            // block jammed at the window bottom; leave a margin.
                            let rail_h = (ui.available_height() - 48.0).max(160.0);
                            let mut pick = None;
                            egui::ScrollArea::vertical().auto_shrink([false, false]).max_height(rail_h).show(ui, |ui| {
                                for s in 0..PROFILES {
                                    let selected = s == self.slot;
                                    let (rect, resp) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 30.0), egui::Sense::click());
                                    let bg = if selected {
                                        p.brand_soft()
                                    } else if resp.hovered() {
                                        p.line_soft
                                    } else {
                                        egui::Color32::TRANSPARENT
                                    };
                                    ui.painter().rect(rect, egui::Rounding::same(8.0), bg, egui::Stroke::NONE);
                                    ui.painter().text(
                                        rect.left_center() + egui::vec2(12.0, 0.0),
                                        egui::Align2::LEFT_CENTER,
                                        format!("Slot {s:02}"),
                                        theme::f_mono(12.5),
                                        if selected { p.brand } else { p.txt2 },
                                    );
                                    if resp.clicked() {
                                        pick = Some(s);
                                    }
                                }
                            });
                            if let Some(s) = pick {
                                self.slot = s;
                            }
                        });
                        ui.add_space(24.0);
                        ui.vertical(|ui| {
                            ui.label(egui::RichText::new(format!("SLOT {:02}", self.slot)).font(theme::f_bold(11.0)).color(p.brand));
                            ui.add_space(10.0);
                            editor_row(ui, p, "Title", |ui| {
                                ui.add(egui::TextEdit::singleline(&mut self.draft.title).hint_text("\u{2264} 12 chars").desired_width(360.0));
                            });
                            editor_row(ui, p, "Secret", |ui| {
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.draft.secret_base32)
                                        .password(true)
                                        .hint_text("base32 secret")
                                        .desired_width(360.0),
                                );
                            });
                            // Two columns for the short choices, to use the width.
                            let field_label = |ui: &mut egui::Ui, w: f32, text: &str| {
                                ui.add_sized([w, 22.0], egui::Label::new(egui::RichText::new(text).font(theme::f_reg(13.0)).color(p.txt2)));
                            };
                            ui.horizontal(|ui| {
                                field_label(ui, 92.0, "Algorithm");
                                let cur = match self.draft.algorithm {
                                    AlgoChoice::Sha1 => "SHA1",
                                    AlgoChoice::Sha256 => "SHA256",
                                };
                                if let Some(v) = theme::segmented(ui, p, &["SHA1", "SHA256"], cur, p.brand) {
                                    self.draft.algorithm = if v == "SHA256" { AlgoChoice::Sha256 } else { AlgoChoice::Sha1 };
                                }
                                ui.add_space(30.0);
                                field_label(ui, 50.0, "Digits");
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
                            ui.add_space(8.0);
                            ui.horizontal(|ui| {
                                field_label(ui, 92.0, "Time step");
                                let cur = match self.draft.time_step {
                                    StepChoice::S30 => "30s",
                                    StepChoice::S60 => "60s",
                                };
                                if let Some(v) = theme::segmented(ui, p, &["30s", "60s"], cur, p.brand) {
                                    self.draft.time_step = if v == "60s" { StepChoice::S60 } else { StepChoice::S30 };
                                }
                                ui.add_space(30.0);
                                field_label(ui, 50.0, "Display");
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
                                if theme::button(ui, p, BtnKind::Default, "Sync time").clicked() {
                                    self.sync_time_selected();
                                }
                            });
                        });
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
                        let importing = self.import_busy();
                        if ui
                            .add_enabled(!importing, egui::Button::new("Load"))
                            .clicked()
                        {
                            do_load = true;
                        }
                        if importing {
                            ui.spinner();
                            if let Some(label) = &self.import_label {
                                ui.label(label.as_str());
                            }
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
                            // Block programming while a load is in flight so a
                            // stale entry list can't be written mid-replace.
                            let can_apply = self.authenticated && !self.import_busy();
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
            ui.label(
                egui::RichText::new(issuer)
                    .font(theme::f_sb(13.5))
                    .color(p.txt),
            );
            if !account.is_empty() {
                ui.label(
                    egui::RichText::new(account)
                        .font(theme::f_reg(12.0))
                        .color(p.txt3),
                );
            }
        });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if with_delete {
                let (xr, xresp) =
                    ui.allocate_exact_size(egui::vec2(18.0, 18.0), egui::Sense::click());
                paint_x_icon(ui, xr.center(), p.txt3);
                if xresp.on_hover_text("Delete").clicked() {
                    delete = true;
                }
                ui.add_space(8.0);
            }
            let (cr, cresp) = ui.allocate_exact_size(egui::vec2(20.0, 18.0), egui::Sense::click());
            if is_copied {
                paint_check_icon(ui, cr.center(), p.ok);
            } else {
                paint_copy_icon(ui, cr.center(), p.txt3);
            }
            if cresp.on_hover_text("Copy code").clicked() {
                if let Some(c) = code {
                    copy = Some(c.to_string());
                }
            }
            ui.add_space(10.0);
            ui.label(
                egui::RichText::new(format!("{secs}s"))
                    .font(theme::f_reg(11.0))
                    .color(p.txt3),
            );
            ui.add_space(5.0);
            theme::ring(ui, pct, 20.0, code_color, p.line);
            ui.add_space(14.0);
            match code {
                Some(c) => {
                    ui.label(
                        egui::RichText::new(c)
                            .font(theme::f_mono(19.0))
                            .color(code_color),
                    );
                }
                None => {
                    ui.label(
                        egui::RichText::new("touch")
                            .font(theme::f_reg(13.0))
                            .color(p.txt3),
                    );
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
            egui::Label::new(
                egui::RichText::new(label)
                    .font(theme::f_reg(13.0))
                    .color(p.txt2),
            ),
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
