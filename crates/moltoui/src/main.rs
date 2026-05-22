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

const PROFILES: u8 = 100;

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
}

fn unix_now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
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
            .default_width(220.0)
            .width_range(120.0..=560.0)
            .show(ctx, |ui| {
                ui.add_space(4.0);
                ui.heading("Profiles");
                ui.label("Click to select. Drag the divider to resize.");
                ui.add_space(4.0);
                egui::ScrollArea::vertical().show(ui, |ui| {
                    // Compute columns from the actual content width so every slot is reachable
                    // regardless of how the user has dragged the side-panel divider.
                    const CELL: f32 = 26.0;
                    const GAP: f32 = 4.0;
                    let avail = ui.available_width().max(CELL);
                    let cols = (((avail + GAP) / (CELL + GAP)).floor() as usize).max(1);
                    egui::Grid::new("slot-grid")
                        .num_columns(cols)
                        .spacing([GAP, GAP])
                        .show(ui, |ui| {
                            for p in 0..PROFILES {
                                let selected = p == self.selected;
                                let label = format!("{:02}", p);
                                let btn = egui::SelectableLabel::new(selected, label);
                                if ui.add_sized([CELL, CELL], btn).clicked() {
                                    self.selected = p;
                                }
                                if (p as usize + 1) % cols == 0 {
                                    ui.end_row();
                                }
                            }
                        });
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
