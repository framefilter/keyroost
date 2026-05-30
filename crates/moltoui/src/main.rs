//! moltoui — desktop GUI for programming Token2 Molto2 / Molto2v2 tokens.
//!
//! Dark-themed by default, modeled loosely on Token2's PyQt5 layout: device
//! status across the top, 100-slot grid on the left, edit form on the right.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::time::{SystemTime, UNIX_EPOCH};

use eframe::egui;
use molto2_import::parse_otpauth;
use molto2_proto::commands::{
    DisplayTimeout, HmacAlgo, OtpDigits, ProfileConfig, TimeStep, DEFAULT_CUSTOMER_KEY,
};
use molto2_transport::{DeviceInfo, Session, TransportError};

use molto2_ctap::client_pin::PinUvAuthToken;
use molto2_ctap::cred_mgmt::{Credential, CredsMetadata, RelyingParty};
use molto2_ctap::{AuthenticatorInfo, CtapHidDevice, InitResponse};
use molto2_hid::HidDevice;
use molto2_keyring::Keyring;

const PROFILES: u8 = 100;

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum ViewTab {
    #[default]
    Molto2,
    SecurityKeys,
    Oath,
}

#[derive(Default)]
struct SecurityKeysState {
    devices: Vec<HidDevice>,
    /// Effective serial per device (USB, else CCID for YubiKeys), parallel to
    /// `devices`. Computed once per refresh via the shared resolver.
    serials: Vec<Option<String>>,
    /// Friendly-name registry, reloaded each refresh so names show in the list.
    keyring: Keyring,
    selected: Option<usize>,
    /// CTAP info for `selected`, fetched lazily after selection.
    info: Option<AuthenticatorInfo>,
    init: Option<InitResponse>,
    /// User-facing error from the last enumeration / open / GetInfo call.
    error: Option<String>,
    /// Live PIN entry field (cleared after submit).
    pin_input: String,
    /// "Name this key" text field (friendly name to assign to the selected key).
    name_input: String,
    /// Feedback line from the last name save / removal.
    name_status: Option<String>,
    /// Active unlocked session: token + cached resident credentials.
    session: Option<UnlockedSession>,
    /// Change-PIN modal state.
    change_pin: ChangePinDialog,
}

struct UnlockedSession {
    token: PinUvAuthToken,
    metadata: CredsMetadata,
    rps: Vec<(RelyingParty, Vec<Credential>)>,
}

#[derive(Default)]
struct ChangePinDialog {
    open: bool,
    old: String,
    new: String,
}

/// State for the OATH (TOTP) pane. The applet is driven over PC/SC, so a
/// "reader name" identifies the key rather than a hidraw path.
#[derive(Default)]
struct OathState {
    /// Names of connected readers whose OATH applet responds.
    readers: Vec<String>,
    /// Index into `readers` of the selected key.
    selected: Option<usize>,
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
}

/// One credential row in the OATH pane: its stored name and the last code we
/// computed for it (empty until "Show code" / refresh).
struct OathRow {
    name: String,
    detail: String,
    code: Option<String>,
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([960.0, 640.0])
            .with_min_inner_size([720.0, 480.0])
            .with_title("MoltoUI"),
        ..Default::default()
    };
    eframe::run_native(
        "MoltoUI",
        options,
        Box::new(|cc| {
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
            Ok(Box::new(App::default()))
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
    /// Currently selected profile (0..PROFILES-1).
    selected: u8,
    /// Draft of the form fields for `selected` (per-slot; cleared on slot switch).
    draft: Draft,
    /// Rolling log of operations (newest last).
    log: Vec<LogLine>,
    /// otpauth:// import dialog state.
    import_dialog: ImportDialog,
    /// Bulk-import dialog state.
    bulk_dialog: BulkDialog,
    /// Active top-level view tab.
    view: ViewTab,
    /// FIDO security-key view state (devices, selected CTAP info, errors).
    security_keys: SecurityKeysState,
    /// OATH (TOTP) view state.
    oath: OathState,
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
    entries: Vec<molto2_import::BulkEntry>,
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

impl Severity {
    fn color(self, visuals: &egui::Visuals) -> egui::Color32 {
        match self {
            Severity::Info => visuals.weak_text_color(),
            Severity::Ok => egui::Color32::from_rgb(120, 200, 130),
            Severity::Warn => egui::Color32::from_rgb(220, 180, 80),
            Severity::Err => egui::Color32::from_rgb(220, 100, 100),
        }
    }
}

impl App {
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
            molto2_proto::codec::hex_decode(&self.customer_key_input)
                .map_err(|e| format!("invalid customer key hex: {}", e))
        } else {
            Ok(self.customer_key_input.as_bytes().to_vec())
        }
    }

    fn connect(&mut self) {
        match Session::open() {
            Ok(mut s) => match s.read_info() {
                Ok(info) => {
                    self.log(
                        Severity::Ok,
                        format!("connected to {} (utc={})", info.serial, info.utc_time),
                    );
                    self.info = Some(info);
                    self.session = Some(s);
                    self.authenticated = false;
                }
                Err(e) => self.log(Severity::Err, format!("read_info failed: {}", e)),
            },
            Err(e) => self.log(Severity::Err, format!("connect failed: {}", e)),
        }
    }

    fn disconnect(&mut self) {
        self.session = None;
        self.info = None;
        self.authenticated = false;
        self.log(Severity::Info, "disconnected");
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
        let secret = match molto2_proto::codec::base32_decode(&self.draft.secret_base32) {
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
        let p = self.selected;
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
        let p = self.selected;
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
                self.selected
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
        let is_encrypted_aegis = molto2_import::aegis::is_encrypted(&text).unwrap_or(false);
        let final_text = if is_encrypted_aegis {
            self.bulk_dialog.needs_password = true;
            if self.bulk_dialog.password.is_empty() {
                self.bulk_dialog.entries.clear();
                self.bulk_dialog.error =
                    Some("encrypted Aegis vault — enter password and click Load again".into());
                return;
            }
            match molto2_import::aegis::decrypt(&text, self.bulk_dialog.password.as_bytes()) {
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

        match molto2_import::parse_bulk_any(&final_text) {
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

    fn refresh_security_keys(&mut self) {
        self.security_keys.error = None;
        self.security_keys.info = None;
        self.security_keys.init = None;
        match molto2_hid::enumerate() {
            Ok(devices) => {
                let fido_only: Vec<_> = devices.into_iter().filter(|d| d.is_fido()).collect();
                let prev_path = self
                    .security_keys
                    .selected
                    .and_then(|i| self.security_keys.devices.get(i).map(|d| d.path.clone()));
                // Effective serials (USB, else CCID for YubiKeys) via the shared
                // resolver, plus the friendly-name registry, so the list and
                // header can show names. Reading is non-persisting / opt-out free.
                self.security_keys.serials = molto2_resolve::effective_serials(&fido_only);
                self.security_keys.keyring = Keyring::load_default().unwrap_or_default();
                self.security_keys.devices = fido_only;
                self.security_keys.selected = prev_path.and_then(|p| {
                    self.security_keys
                        .devices
                        .iter()
                        .position(|d| d.path == p)
                });
            }
            Err(e) => {
                self.security_keys.error = Some(format!("enumeration failed: {}", e));
                self.security_keys.devices.clear();
                self.security_keys.serials.clear();
                self.security_keys.selected = None;
            }
        }
    }

    /// The friendly name registered for the device at `idx`, if any.
    fn name_for_index(&self, idx: usize) -> Option<&str> {
        let serial = self.security_keys.serials.get(idx)?.as_deref();
        self.security_keys.keyring.name_for(serial)
    }

    /// Friendly-name controls for the selected key: show the current name (or
    /// that it's unnamed) and let the user assign or remove one. Assigning
    /// persists the key's serial to `keys.json` — an opt-in step, disclosed
    /// inline via the helper-bubble.
    fn render_key_naming(&mut self, ui: &mut egui::Ui, idx: usize, dev: &HidDevice) {
        let current = self.name_for_index(idx).map(str::to_owned);
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Friendly name").strong());
            helper_bubble(
                ui,
                "Assigning a name saves this key's serial number to keys.json on \
                 this computer, so the key can be recognized by name later. \
                 Nothing is stored until you click Save; you can remove it any time.",
            );
        });

        match &current {
            Some(name) => {
                ui.horizontal(|ui| {
                    ui.label(format!("This key is named \u{201c}{name}\u{201d}."));
                    if ui.button("Remove name").clicked() {
                        self.remove_key_name(name);
                    }
                });
            }
            None => {
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.security_keys.name_input)
                            .hint_text("e.g. test-yubikey")
                            .desired_width(180.0),
                    );
                    if ui.button("Save name").clicked() {
                        self.save_key_name(dev);
                    }
                });
                ui.label(
                    egui::RichText::new("Lowercase letters, digits, '-' and '_'.")
                        .weak()
                        .small(),
                );
            }
        }

        if let Some(status) = &self.security_keys.name_status {
            ui.colored_label(ui.visuals().weak_text_color(), status);
        }
    }

    /// Persist a friendly name for `dev` (opt-in). Reads the effective serial
    /// (USB, or CCID for YubiKeys), validates the name, and writes `keys.json`.
    fn save_key_name(&mut self, dev: &HidDevice) {
        let name = self.security_keys.name_input.trim().to_owned();
        if name.is_empty() {
            self.security_keys.name_status = Some("Enter a name first.".into());
            return;
        }
        if let Err(e) = molto2_keyring::validate_name(&name) {
            self.security_keys.name_status = Some(e.to_string());
            return;
        }
        let (serial, source) = match molto2_resolve::read_effective_serial(dev) {
            Ok(v) => v,
            Err(e) => {
                self.security_keys.name_status = Some(e);
                return;
            }
        };
        let vendor =
            (dev.vendor_id == molto2_resolve::VID_YUBICO).then(|| "yubico".to_string());
        let entry = molto2_keyring::KeyEntry {
            name,
            serial,
            source,
            vendor,
            aaguid: None,
            note: None,
        };
        if let Err(e) = self.security_keys.keyring.add(entry) {
            self.security_keys.name_status = Some(e.to_string());
            return;
        }
        match self.security_keys.keyring.save_default() {
            Ok(path) => {
                self.security_keys.name_input.clear();
                self.security_keys.name_status = Some(format!("Saved to {}", path.display()));
            }
            Err(e) => self.security_keys.name_status = Some(e.to_string()),
        }
        // Recompute serials/keyring so the list and header pick up the new name.
        self.refresh_security_keys();
    }

    /// Remove a friendly name and persist the change.
    fn remove_key_name(&mut self, name: &str) {
        if self.security_keys.keyring.remove(name) {
            let _ = self.security_keys.keyring.save_default();
            self.security_keys.name_status = Some(format!("Removed \u{201c}{name}\u{201d}."));
        }
        self.refresh_security_keys();
    }

    /// Open the currently-selected hidraw device, run CTAPHID_INIT and
    /// authenticatorGetInfo, and cache the result. Blocks the UI briefly —
    /// CTAP GetInfo typically completes in a few milliseconds.
    fn fetch_selected_info(&mut self) {
        self.security_keys.info = None;
        self.security_keys.init = None;
        self.security_keys.error = None;
        let Some(idx) = self.security_keys.selected else {
            return;
        };
        let Some(dev) = self.security_keys.devices.get(idx) else {
            return;
        };
        let path = dev.path.clone();
        match CtapHidDevice::open(&path) {
            Ok((mut hid, init)) => {
                self.security_keys.init = Some(init.clone());
                if init.supports_cbor() {
                    match molto2_ctap::get_info(&mut hid) {
                        Ok(info) => self.security_keys.info = Some(info),
                        Err(e) => {
                            self.security_keys.error = Some(format!("GetInfo failed: {}", e))
                        }
                    }
                }
            }
            Err(e) => {
                self.security_keys.error = Some(format!(
                    "could not open {}: {} (have you installed udev/70-moltoui-fido.rules?)",
                    path.display(),
                    e
                ));
            }
        }
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
        match self.open_and_unlock(&path, &pin) {
            Ok(sess) => {
                self.security_keys.session = Some(sess);
                self.security_keys.error = None;
            }
            Err(e) => self.security_keys.error = Some(format!("unlock failed: {}", e)),
        }
    }

    fn open_and_unlock(
        &self,
        path: &std::path::Path,
        pin: &str,
    ) -> Result<UnlockedSession, Box<dyn std::error::Error>> {
        let (mut dev, init) = CtapHidDevice::open(path)?;
        if !init.supports_cbor() {
            return Err("device is U2F-only".into());
        }
        let info = molto2_ctap::get_info(&mut dev)?;
        let token = molto2_ctap::client_pin::get_pin_uv_auth_token(
            &mut dev,
            pin,
            &info,
            molto2_ctap::client_pin::permissions::CREDENTIAL_MANAGEMENT,
        )?;
        let mut mgr = molto2_ctap::cred_mgmt::CredentialManager::new(&mut dev, token, &info)?;
        let metadata = mgr.metadata()?;
        let parties = mgr.list_relying_parties()?;
        let mut rps = Vec::with_capacity(parties.len());
        for rp in parties {
            let creds = mgr.list_credentials(&rp.rp_id_hash).unwrap_or_default();
            rps.push((rp, creds));
        }
        // Reconstruct the token we used (CredentialManager consumed it).
        // The PIN exchange is cheap, so we re-run it for the cached session.
        let token = molto2_ctap::client_pin::get_pin_uv_auth_token(
            &mut dev,
            pin,
            &info,
            molto2_ctap::client_pin::permissions::CREDENTIAL_MANAGEMENT,
        )?;
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
        match self.refresh_with_token(&path, session.token) {
            Ok(fresh) => self.security_keys.session = Some(fresh),
            Err(e) => self.security_keys.error = Some(format!("refresh failed: {}", e)),
        }
    }

    fn refresh_with_token(
        &self,
        path: &std::path::Path,
        token: PinUvAuthToken,
    ) -> Result<UnlockedSession, Box<dyn std::error::Error>> {
        let (mut dev, _) = CtapHidDevice::open(path)?;
        let info = molto2_ctap::get_info(&mut dev)?;
        let token2 = PinUvAuthToken {
            protocol: token.protocol,
            token: token.token.clone(),
        };
        let mut mgr = molto2_ctap::cred_mgmt::CredentialManager::new(&mut dev, token2, &info)?;
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
        let token_copy = PinUvAuthToken {
            protocol: session.token.protocol,
            token: session.token.token.clone(),
        };
        match self.try_delete(&path, token_copy, &cred_id) {
            Ok(()) => {
                self.refresh_credentials();
            }
            Err(e) => self.security_keys.error = Some(format!("delete failed: {}", e)),
        }
    }

    fn try_delete(
        &self,
        path: &std::path::Path,
        token: PinUvAuthToken,
        cred_id: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut dev, _) = CtapHidDevice::open(path)?;
        let info = molto2_ctap::get_info(&mut dev)?;
        let mut mgr = molto2_ctap::cred_mgmt::CredentialManager::new(&mut dev, token, &info)?;
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
        match self.try_change_pin(&path, &old, &new) {
            Ok(()) => {
                self.security_keys.change_pin.open = false;
                self.security_keys.error = None;
                // Force re-unlock with the new PIN.
                self.lock_session();
            }
            Err(e) => self.security_keys.error = Some(format!("change PIN failed: {}", e)),
        }
    }

    fn try_change_pin(
        &self,
        path: &std::path::Path,
        old: &str,
        new: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut dev, _) = CtapHidDevice::open(path)?;
        molto2_ctap::client_pin::change_pin(&mut dev, old, new)?;
        Ok(())
    }

    fn selected_fido_path(&self) -> Option<std::path::PathBuf> {
        let idx = self.security_keys.selected?;
        Some(self.security_keys.devices.get(idx)?.path.clone())
    }

    fn render_security_keys(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("fido-devices")
            .resizable(true)
            .default_width(280.0)
            .width_range(180.0..=520.0)
            .show(ctx, |ui| {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.heading("Security keys");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Refresh").clicked() {
                            self.refresh_security_keys();
                        }
                    });
                });
                ui.label("FIDO HID devices currently visible.");
                ui.add_space(4.0);

                if self.security_keys.devices.is_empty() {
                    ui.colored_label(
                        ui.visuals().weak_text_color(),
                        "No FIDO keys detected. Plug one in and click Refresh.",
                    );
                }

                let mut click: Option<usize> = None;
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for (i, dev) in self.security_keys.devices.iter().enumerate() {
                        let selected = self.security_keys.selected == Some(i);
                        // Lead with the friendly name when the key is registered.
                        let name = self
                            .security_keys
                            .serials
                            .get(i)
                            .and_then(|s| s.as_deref())
                            .and_then(|s| self.security_keys.keyring.name_for(Some(s)));
                        let header = match name {
                            Some(n) => format!("{}  ({})", n, dev.product_name),
                            None => dev.product_name.clone(),
                        };
                        let label = format!(
                            "{}\n{:04x}:{:04x}  {}",
                            short_path(&dev.path),
                            dev.vendor_id,
                            dev.product_id,
                            header
                        );
                        if ui
                            .selectable_label(selected, label)
                            .clicked()
                        {
                            click = Some(i);
                        }
                    }
                });
                if let Some(i) = click {
                    self.security_keys.selected = Some(i);
                    self.fetch_selected_info();
                }
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(4.0);
            let Some(idx) = self.security_keys.selected else {
                ui.heading("No key selected");
                ui.label("Pick a device from the left panel, or click Refresh.");
                return;
            };
            let Some(dev) = self.security_keys.devices.get(idx).cloned() else {
                return;
            };

            ui.heading(if dev.product_name.is_empty() {
                format!("{}", dev.path.display())
            } else {
                dev.product_name.clone()
            });
            ui.label(format!(
                "{}    vendor 0x{:04x}    product 0x{:04x}",
                dev.path.display(),
                dev.vendor_id,
                dev.product_id
            ));
            ui.separator();

            self.render_key_naming(ui, idx, &dev);
            ui.separator();

            if let Some(err) = &self.security_keys.error {
                ui.colored_label(egui::Color32::from_rgb(220, 110, 110), err);
                ui.add_space(8.0);
            }

            if let Some(init) = &self.security_keys.init {
                kv(ui, "CTAPHID channel", &format!("{:#010x}", init.channel_id));
                kv(
                    ui,
                    "Protocol",
                    &format!("v{} (capabilities 0x{:02X})", init.protocol_version, init.capabilities),
                );
                kv(
                    ui,
                    "HID firmware",
                    &format!("{}.{}.{}", init.device_major, init.device_minor, init.device_build),
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
                kv(ui, "Supports", &caps.join(" + "));
            }

            if let Some(info) = &self.security_keys.info {
                ui.add_space(8.0);
                ui.label(egui::RichText::new("authenticatorGetInfo").strong());
                kv(ui, "Versions", &info.versions.join(", "));
                if !info.extensions.is_empty() {
                    kv(ui, "Extensions", &info.extensions.join(", "));
                }
                kv(ui, "AAGUID", &format_aaguid(&info.aaguid));
                if !info.options.is_empty() {
                    let s: Vec<String> = info
                        .options
                        .iter()
                        .map(|(k, v)| format!("{}={}", k, v))
                        .collect();
                    kv(ui, "Options", &s.join(", "));
                }
                if let Some(n) = info.max_msg_size {
                    kv(ui, "MaxMsgSize", &n.to_string());
                }
                if !info.pin_uv_auth_protocols.is_empty() {
                    let s: Vec<String> = info
                        .pin_uv_auth_protocols
                        .iter()
                        .map(|n| n.to_string())
                        .collect();
                    kv(ui, "PIN/UV protocols", &s.join(", "));
                }
                if !info.transports.is_empty() {
                    kv(ui, "Transports", &info.transports.join(", "));
                }
                if let Some(v) = info.firmware_version {
                    kv(ui, "CTAP firmware", &v.to_string());
                }
            } else if self
                .security_keys
                .init
                .as_ref()
                .is_some_and(|i| !i.supports_cbor())
            {
                ui.add_space(8.0);
                ui.colored_label(
                    ui.visuals().weak_text_color(),
                    "Device is U2F-only — CTAP2 GetInfo not available.",
                );
            }

            ui.add_space(12.0);
            ui.separator();
            self.render_credentials_section(ui);
            ui.add_space(12.0);
            ui.colored_label(
                ui.visuals().weak_text_color(),
                "Reset is CLI-only for now: `moltoctl fido-reset --yes`.",
            );
        });

        self.render_change_pin_dialog(ctx);
    }

    fn render_credentials_section(&mut self, ui: &mut egui::Ui) {
        let pin_set = self
            .security_keys
            .info
            .as_ref()
            .and_then(|i| i.option("clientPin"));

        ui.label(egui::RichText::new("Credentials").strong());

        ui.horizontal(|ui| {
            match pin_set {
                Some(true) => ui.colored_label(egui::Color32::from_rgb(120, 200, 130), "PIN set"),
                Some(false) => {
                    ui.colored_label(egui::Color32::from_rgb(220, 180, 80), "No PIN configured")
                }
                None => ui.colored_label(ui.visuals().weak_text_color(), "PIN status unknown"),
            };
            if ui.button("Change PIN…").clicked() {
                self.security_keys.change_pin.open = true;
            }
            if self.security_keys.session.is_some() && ui.button("Lock").clicked() {
                self.lock_session();
            }
        });

        ui.add_space(4.0);

        if self.security_keys.session.is_none() {
            if pin_set != Some(true) {
                ui.colored_label(
                    ui.visuals().weak_text_color(),
                    "Set a PIN with `moltoctl fido-pin-set` before listing credentials.",
                );
                return;
            }
            ui.horizontal(|ui| {
                ui.label("PIN:");
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut self.security_keys.pin_input)
                        .password(true)
                        .desired_width(180.0),
                );
                let submit = ui.button("Unlock").clicked();
                if submit || (resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))) {
                    self.try_unlock();
                }
            });
            return;
        }

        // Session is active — pull the data out for rendering, then drop the
        // borrow before we issue any further state-mutating clicks.
        let (existing, max_remaining, rps) = {
            let s = self.security_keys.session.as_ref().expect("just checked");
            (
                s.metadata.existing_count,
                s.metadata.max_remaining,
                s.rps.clone(),
            )
        };

        ui.label(format!(
            "{} resident credential(s), room for {} more",
            existing, max_remaining
        ));
        ui.add_space(6.0);

        let mut delete: Option<Vec<u8>> = None;
        egui::ScrollArea::vertical()
            .max_height(360.0)
            .show(ui, |ui| {
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
                                let user_field = if let Some(d) = &c.user.display_name {
                                    d.clone()
                                } else if let Some(n) = &c.user.name {
                                    n.clone()
                                } else {
                                    String::from_utf8_lossy(&c.user.id).into_owned()
                                };
                                ui.label(user_field);
                                if let Some(alg) = c.algorithm {
                                    ui.colored_label(
                                        ui.visuals().weak_text_color(),
                                        cose_algorithm_name(alg),
                                    );
                                }
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if ui.button("Delete").clicked() {
                                            delete = Some(c.credential_id.clone());
                                        }
                                    },
                                );
                            });
                        }
                    });
                }
            });

        if let Some(cred_id) = delete {
            self.delete_credential(cred_id);
        }
    }

    fn render_change_pin_dialog(&mut self, ctx: &egui::Context) {
        if !self.security_keys.change_pin.open {
            return;
        }
        let mut still_open = self.security_keys.change_pin.open;
        let mut submit = false;
        egui::Window::new("Change PIN")
            .collapsible(false)
            .resizable(false)
            .open(&mut still_open)
            .show(ctx, |ui| {
                ui.label("Old PIN:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.security_keys.change_pin.old)
                        .password(true)
                        .desired_width(220.0),
                );
                ui.label("New PIN (4–63 UTF-8 bytes):");
                ui.add(
                    egui::TextEdit::singleline(&mut self.security_keys.change_pin.new)
                        .password(true)
                        .desired_width(220.0),
                );
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button("Change PIN").clicked() {
                        submit = true;
                    }
                });
            });
        if !still_open {
            self.security_keys.change_pin.open = false;
            self.security_keys.change_pin.old.clear();
            self.security_keys.change_pin.new.clear();
        }
        if submit {
            self.submit_change_pin();
        }
    }

    // --- OATH (TOTP) pane ------------------------------------------------

    /// (Re)enumerate readers whose OATH applet responds. Resets per-key state.
    fn refresh_oath_readers(&mut self) {
        self.oath.error = None;
        self.oath.creds.clear();
        self.oath.loaded = false;
        match molto2_transport::OathSession::list_oath_readers() {
            Ok(readers) => {
                // Preserve the selection by name across refreshes.
                let prev = self
                    .oath
                    .selected
                    .and_then(|i| self.oath.readers.get(i).cloned());
                self.oath.readers = readers;
                self.oath.selected = prev
                    .and_then(|p| self.oath.readers.iter().position(|r| *r == p))
                    .or(if self.oath.readers.is_empty() { None } else { Some(0) });
            }
            Err(e) => {
                self.oath.error = Some(format!("enumeration failed: {e}"));
                self.oath.readers.clear();
                self.oath.selected = None;
            }
        }
        self.probe_oath_lock();
    }

    /// Open the selected reader to learn whether its applet is password-locked,
    /// without listing anything yet.
    fn probe_oath_lock(&mut self) {
        self.oath.locked = false;
        self.oath.loaded = false;
        self.oath.creds.clear();
        let Some(name) = self.selected_oath_reader() else {
            return;
        };
        match molto2_transport::OathSession::open(&name) {
            Ok(session) => self.oath.locked = session.password_required(),
            Err(e) => self.oath.error = Some(format!("open failed: {e}")),
        }
    }

    fn selected_oath_reader(&self) -> Option<String> {
        self.oath.readers.get(self.oath.selected?).cloned()
    }

    /// List credentials on the selected key, computing each current TOTP. Unlocks
    /// first with the entered password when the applet is protected.
    fn load_oath_creds(&mut self) {
        self.oath.error = None;
        let Some(name) = self.selected_oath_reader() else {
            self.oath.error = Some("no OATH key selected".into());
            return;
        };
        let result = (|| -> Result<Vec<OathRow>, TransportError> {
            let mut session = molto2_transport::OathSession::open(&name)?;
            if session.password_required() {
                session.unlock(&self.oath.password_input)?;
            }
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let mut rows = Vec::new();
            for c in session.list()? {
                // Compute TOTP per credential. A touch-required credential would
                // block here; that's acceptable for a button-driven refresh.
                let code = session
                    .calculate_totp(&c.name, now, 30)
                    .ok()
                    .map(|otp| otp.code);
                rows.push(OathRow {
                    name: c.name,
                    detail: format!("{:?}/{:?}", c.oath_type, c.algorithm),
                    code,
                });
            }
            Ok(rows)
        })();
        match result {
            Ok(rows) => {
                self.oath.creds = rows;
                self.oath.loaded = true;
                self.oath.locked = false;
                self.oath.password_input.clear();
            }
            Err(TransportError::OathPasswordRejected) => {
                self.oath.locked = true;
                self.oath.error = Some("wrong OATH password".into());
                self.oath.password_input.clear();
            }
            Err(e) => self.oath.error = Some(e.to_string()),
        }
    }

    fn render_oath(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("oath-readers")
            .resizable(true)
            .default_width(280.0)
            .width_range(180.0..=520.0)
            .show(ctx, |ui| {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.heading("OATH keys");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Refresh").clicked() {
                            self.refresh_oath_readers();
                        }
                    });
                });
                ui.label("Security keys with an OATH applet.");
                ui.add_space(4.0);

                if self.oath.readers.is_empty() {
                    ui.colored_label(
                        ui.visuals().weak_text_color(),
                        "No OATH-capable key detected. Plug one in and click Refresh.",
                    );
                }

                let mut clicked: Option<usize> = None;
                for (i, name) in self.oath.readers.iter().enumerate() {
                    let selected = self.oath.selected == Some(i);
                    if ui.selectable_label(selected, name).clicked() {
                        clicked = Some(i);
                    }
                }
                if let Some(i) = clicked {
                    self.oath.selected = Some(i);
                    self.oath.password_input.clear();
                    self.probe_oath_lock();
                }
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(4.0);
            if self.selected_oath_reader().is_none() {
                ui.heading("No OATH key selected");
                ui.label("Pick a key from the left panel, or click Refresh.");
                return;
            };

            if let Some(err) = &self.oath.error {
                ui.colored_label(egui::Color32::from_rgb(220, 110, 110), err);
                ui.add_space(6.0);
            }

            if self.oath.locked {
                ui.horizontal(|ui| {
                    ui.label("This key's OATH applet is password-protected.");
                    helper_bubble(
                        ui,
                        "The password is sent to the key to unlock it for this \
                         operation only; it is never written to disk.",
                    );
                });
                ui.horizontal(|ui| {
                    ui.label("Password:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.oath.password_input)
                            .password(true)
                            .desired_width(200.0),
                    );
                    if ui.button("Unlock & list").clicked() {
                        self.load_oath_creds();
                    }
                });
                return;
            }

            ui.horizontal(|ui| {
                if ui.button("List / refresh codes").clicked() {
                    self.load_oath_creds();
                }
                helper_bubble(
                    ui,
                    "Reads the credentials on the key and computes each current \
                     TOTP. Codes are shown for ~30s; click again to refresh.",
                );
            });
            ui.separator();

            if !self.oath.loaded {
                ui.label("Click \u{201c}List / refresh codes\u{201d} to read this key.");
                return;
            }
            if self.oath.creds.is_empty() {
                ui.label("(no OATH credentials on this key)");
                return;
            }

            egui::Grid::new("oath-creds")
                .num_columns(3)
                .striped(true)
                .spacing([16.0, 6.0])
                .show(ui, |ui| {
                    for row in &self.oath.creds {
                        ui.label(&row.name);
                        match &row.code {
                            Some(code) => {
                                ui.label(egui::RichText::new(code).monospace().strong());
                            }
                            None => {
                                ui.colored_label(ui.visuals().weak_text_color(), "(touch / n/a)");
                            }
                        }
                        ui.colored_label(ui.visuals().weak_text_color(), &row.detail);
                        ui.end_row();
                    }
                });
        });
    }
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

fn short_path(p: &std::path::Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.display().to_string())
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
    match alg {
        -7 => "ES256",
        -8 => "EdDSA",
        -35 => "ES384",
        -36 => "ES512",
        -257 => "RS256",
        _ => "unknown",
    }
}

fn format_aaguid(aaguid: &[u8; 16]) -> String {
    let mut s = String::with_capacity(36);
    for (i, b) in aaguid.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            s.push('-');
        }
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn unix_now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.view, ViewTab::Molto2, "Molto2");
                ui.selectable_value(&mut self.view, ViewTab::SecurityKeys, "Security keys");
                ui.selectable_value(&mut self.view, ViewTab::Oath, "OATH");
            });
            ui.add_space(2.0);
        });

        if self.view == ViewTab::SecurityKeys {
            // First visit: populate the list automatically so the user isn't
            // staring at an empty pane wondering whether the app is broken.
            if self.security_keys.devices.is_empty() && self.security_keys.error.is_none() {
                self.refresh_security_keys();
            }
            self.render_security_keys(ctx);
            return;
        }

        if self.view == ViewTab::Oath {
            if self.oath.readers.is_empty() && self.oath.error.is_none() {
                self.refresh_oath_readers();
            }
            self.render_oath(ctx);
            return;
        }

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let connected = self.session.is_some();
                if !connected {
                    if ui.button("Connect").clicked() {
                        self.connect();
                    }
                } else if ui.button("Disconnect").clicked() {
                    self.disconnect();
                }

                ui.separator();

                if let Some(info) = self.info.as_ref() {
                    ui.label(format!("device: {}", info.serial));
                    ui.label(format!("utc: {}", info.utc_time));
                } else {
                    ui.colored_label(ui.visuals().weak_text_color(), "no device");
                }

                ui.separator();

                ui.label("Customer key:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.customer_key_input)
                        .password(true)
                        .hint_text("(default if empty)")
                        .desired_width(160.0),
                );
                ui.checkbox(&mut self.customer_key_hex, "hex");
                let can_auth = self.session.is_some() && !self.authenticated;
                if ui
                    .add_enabled(can_auth, egui::Button::new("Authenticate"))
                    .clicked()
                {
                    self.authenticate();
                }
                if self.authenticated {
                    ui.colored_label(egui::Color32::from_rgb(120, 200, 130), "authed");
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Sync time on all").clicked() {
                        self.sync_time_all();
                    }
                });
            });
            ui.add_space(4.0);
        });

        egui::SidePanel::left("slots")
            .resizable(true)
            .default_width(150.0)
            .width_range(110.0..=320.0)
            .show(ctx, |ui| {
                ui.add_space(4.0);
                ui.heading("Profiles");
                ui.label("Click a slot to edit it.");
                ui.add_space(4.0);
                // One full-width row per profile, mirroring the Security Keys
                // device list. A compact list (rather than a 100-cell grid)
                // keeps the picker out of the way and leaves room for a
                // per-device friendly name later (task: device naming).
                egui::ScrollArea::vertical().show(ui, |ui| {
                    let width = ui.available_width();
                    for p in 0..PROFILES {
                        let selected = p == self.selected;
                        let label = format!("Profile {:02}", p);
                        let btn = egui::SelectableLabel::new(selected, label);
                        if ui.add_sized([width, 22.0], btn).clicked() {
                            self.selected = p;
                        }
                    }
                });
            });

        egui::TopBottomPanel::bottom("log")
            .resizable(true)
            .min_height(80.0)
            .show(ctx, |ui| {
                ui.add_space(2.0);
                ui.label("Log");
                egui::ScrollArea::vertical()
                    .stick_to_bottom(true)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let visuals = ui.visuals().clone();
                        for line in &self.log {
                            ui.colored_label(line.severity.color(&visuals), &line.text);
                        }
                    });
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(4.0);
            ui.heading(format!("Profile #{:02}", self.selected));
            ui.separator();
            egui::Grid::new("edit-grid")
                .num_columns(2)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    ui.label("Title (≤12):");
                    ui.add(egui::TextEdit::singleline(&mut self.draft.title).desired_width(220.0));
                    ui.end_row();

                    ui.label("Secret (base32):");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.draft.secret_base32)
                            .desired_width(340.0)
                            .hint_text("e.g. JBSW Y3DP EHPK 3PXP"),
                    );
                    ui.end_row();

                    ui.label("Algorithm:");
                    ui.horizontal(|ui| {
                        ui.selectable_value(&mut self.draft.algorithm, AlgoChoice::Sha1, "SHA1");
                        ui.selectable_value(
                            &mut self.draft.algorithm,
                            AlgoChoice::Sha256,
                            "SHA256",
                        );
                    });
                    ui.end_row();

                    ui.label("Digits:");
                    ui.horizontal(|ui| {
                        ui.selectable_value(&mut self.draft.digits, DigitsChoice::Four, "4");
                        ui.selectable_value(&mut self.draft.digits, DigitsChoice::Six, "6");
                        ui.selectable_value(&mut self.draft.digits, DigitsChoice::Eight, "8");
                        ui.selectable_value(&mut self.draft.digits, DigitsChoice::Ten, "10");
                    });
                    ui.end_row();

                    ui.label("Time step:");
                    ui.horizontal(|ui| {
                        ui.selectable_value(&mut self.draft.time_step, StepChoice::S30, "30s");
                        ui.selectable_value(&mut self.draft.time_step, StepChoice::S60, "60s");
                    });
                    ui.end_row();

                    ui.label("Display timeout:");
                    ui.horizontal(|ui| {
                        ui.selectable_value(
                            &mut self.draft.display_timeout,
                            TimeoutChoice::S15,
                            "15s",
                        );
                        ui.selectable_value(
                            &mut self.draft.display_timeout,
                            TimeoutChoice::S30,
                            "30s",
                        );
                        ui.selectable_value(
                            &mut self.draft.display_timeout,
                            TimeoutChoice::S60,
                            "60s",
                        );
                        ui.selectable_value(
                            &mut self.draft.display_timeout,
                            TimeoutChoice::S120,
                            "120s",
                        );
                    });
                    ui.end_row();
                });

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                let can_write = self.authenticated;
                if ui
                    .add_enabled(can_write, egui::Button::new("Write profile"))
                    .on_hover_text("Send title, seed, and config to the device")
                    .clicked()
                {
                    self.apply_draft();
                }
                if ui
                    .add_enabled(can_write, egui::Button::new("Sync time"))
                    .clicked()
                {
                    self.sync_time_selected();
                }
                if ui.button("Import otpauth://...").clicked() {
                    self.import_dialog.open = true;
                }
                if ui.button("Bulk import...").clicked() {
                    self.bulk_dialog.open = true;
                    self.bulk_dialog.start = self.selected;
                }
            });

            ui.add_space(16.0);
            ui.separator();
            ui.collapsing("Danger zone", |ui| {
                if ui
                    .add_enabled(self.session.is_some(), egui::Button::new("Factory reset"))
                    .on_hover_text("Wipes all profiles. Requires physical button confirmation.")
                    .clicked()
                {
                    self.factory_reset();
                }
            });
        });

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
            egui::Window::new(format!("Import to profile #{:02}", self.selected))
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
