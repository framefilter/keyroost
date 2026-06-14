//! Token2 on-device OTP (TOTP/HOTP) pane for the desktop GUI.
//!
//! This mirrors the OATH pane's structure: a per-selection state struct, a set
//! of `spawn_job`-driven operations that do blocking device I/O off the UI
//! thread, and a `cap_otp` render function. It drives [`keyroost_transport::
//! Token2OtpSession`], which auto-selects USB-HID or CCID/NFC (and can be forced
//! to either).
//!
//! Kept in its own file to avoid growing `main.rs`; the `impl App` blocks here
//! extend the same `App` type via Rust's multi-file inherent-impl support.

use std::time::{SystemTime, UNIX_EPOCH};

use keyroost_transport::{OtpTransportError, Token2OtpSession};

use crate::ui::theme::{self, BtnKind, Palette};
use crate::{now_secs_f64, wipe, App};

/// Which transport the OTP pane should use. Mirrors the CLI `--transport` flag.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum OtpTransportSel {
    #[default]
    Auto,
    Hid,
    Ccid,
}

impl OtpTransportSel {
    fn label(self) -> &'static str {
        match self {
            OtpTransportSel::Auto => "Auto",
            OtpTransportSel::Hid => "USB-HID",
            OtpTransportSel::Ccid => "CCID/NFC",
        }
    }

    fn open(self) -> Result<Token2OtpSession, OtpTransportError> {
        match self {
            OtpTransportSel::Auto => Token2OtpSession::detect_debug(false),
            OtpTransportSel::Hid => Token2OtpSession::detect_hid_only(false),
            OtpTransportSel::Ccid => Token2OtpSession::detect_pcsc_only(false),
        }
    }
}

/// One row in the OTP list: the stored entry plus the live code (when the
/// device returned one — TOTP without a button requirement).
pub struct OtpRow {
    pub app_name: String,
    pub account_name: String,
    pub type_str: &'static str,
    pub algo_str: &'static str,
    pub button_required: bool,
    pub code: Option<String>,
}

impl OtpRow {
    /// Display label `app:account`, or just `account` when the app name is empty.
    fn label(&self) -> String {
        if self.app_name.is_empty() {
            self.account_name.clone()
        } else {
            format!("{}:{}", self.app_name, self.account_name)
        }
    }
}

/// "Add OTP entry" dialog state.
pub struct OtpAddDialog {
    pub open: bool,
    pub app_name: String,
    pub account_name: String,
    /// Base32 secret, entered masked.
    pub secret: String,
    /// True = TOTP, false = HOTP.
    pub totp: bool,
    /// True = SHA256, false = SHA1.
    pub sha256: bool,
    pub digits: u8,
    pub period: u16,
    pub require_touch: bool,
}

impl Default for OtpAddDialog {
    fn default() -> Self {
        OtpAddDialog {
            open: false,
            app_name: String::new(),
            account_name: String::new(),
            secret: String::new(),
            totp: true,
            sha256: false,
            digits: 6,
            period: 30,
            require_touch: false,
        }
    }
}

// Wipe the typed seed on drop (the form is replaced wholesale after submit).
impl Drop for OtpAddDialog {
    fn drop(&mut self) {
        wipe(&mut self.secret);
    }
}

/// Per-selection state for the OTP pane.
#[derive(Default)]
pub struct OtpState {
    pub transport: OtpTransportSel,
    pub rows: Vec<OtpRow>,
    pub error: Option<String>,
    pub info: Option<String>,
    pub loaded: bool,
    pub add: OtpAddDialog,
    pub confirm_delete: Option<(String, String)>,
    /// Active transport label after a successful open (for the status line).
    pub active: Option<&'static str>,
    /// Device serial number (hex), read alongside the entry list when available.
    pub serial: Option<String>,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl App {
    /// List entries on the selected key over the chosen transport.
    pub(crate) fn load_otp_entries(&mut self) {
        self.otp.error = None;
        let sel = self.otp.transport;
        let for_device = self.selected_device.clone();
        self.spawn_job("Reading OTP entries\u{2026}", move || {
            let result =
                (|| -> Result<(Vec<OtpRow>, &'static str, Option<String>), OtpTransportError> {
                    let mut session = sel.open()?;
                    let active = if session.is_pcsc() {
                        "CCID/NFC"
                    } else {
                        "USB-HID"
                    };
                    // Read the serial first, while we hold the session. It's a
                    // nice-to-have: some models/readers don't expose it over CCID,
                    // so a failure here must not block the entry list.
                    let serial = session
                        .read_serial()
                        .ok()
                        .map(|sn| sn.iter().map(|b| format!("{b:02x}")).collect::<String>());
                    let now = unix_now();
                    let entries = session.enumerate(now)?;
                    let rows = entries
                        .into_iter()
                        .map(|e| OtpRow {
                            app_name: e.app_name,
                            account_name: e.account_name,
                            type_str: keyroost_transport::otp_type_str(e.otp_type),
                            algo_str: otp_algo_str(e.algorithm),
                            button_required: e.button_required,
                            code: e.code,
                        })
                        .collect();
                    Ok((rows, active, serial))
                })();
            Box::new(move |app: &mut App| {
                if app.selected_device != for_device {
                    return; // user switched keys mid-read
                }
                match result {
                    Ok((rows, active, serial)) => {
                        app.otp.rows = rows;
                        app.otp.loaded = true;
                        app.otp.active = Some(active);
                        app.otp.serial = serial;
                        app.otp.error = None;
                    }
                    Err(e) => {
                        app.otp.error = Some(e.to_string());
                        app.otp.loaded = true;
                    }
                }
            })
        });
    }

    /// Provision the entry described by the add-dialog fields.
    pub(crate) fn provision_otp(&mut self) {
        self.otp.error = None;
        let app_name = self.otp.add.app_name.trim().to_owned();
        let account_name = self.otp.add.account_name.trim().to_owned();
        if account_name.is_empty() {
            self.otp.error = Some("account name is required".into());
            return;
        }
        let secret = zeroize::Zeroizing::new(self.otp.add.secret.clone());
        let totp = self.otp.add.totp;
        let sha256 = self.otp.add.sha256;
        let digits = self.otp.add.digits;
        let period = self.otp.add.period;
        let touch = self.otp.add.require_touch;
        let sel = self.otp.transport;
        let for_device = self.selected_device.clone();

        self.spawn_job("Adding OTP entry\u{2026}", move || {
            let result = (|| -> Result<(), String> {
                let seed = keyroost_token2otp::decode_base32_seed(secret.trim())
                    .map_err(|m| format!("invalid Base32 secret: {m}"))?;
                let mut session = sel.open().map_err(|e| e.to_string())?;
                let entry = keyroost_token2otp::WriteEntry {
                    otp_type: if totp {
                        keyroost_token2otp::OtpType::Totp
                    } else {
                        keyroost_token2otp::OtpType::Hotp
                    },
                    algorithm: if sha256 {
                        keyroost_token2otp::Algorithm::Sha256
                    } else {
                        keyroost_token2otp::Algorithm::Sha1
                    },
                    timestep: period,
                    code_length: digits,
                    button_required: touch,
                    app_name: &app_name,
                    account_name: &account_name,
                    seed: &seed,
                };
                session.write_entry(&entry).map_err(|e| e.to_string())
            })();
            Box::new(move |app: &mut App| {
                if app.selected_device != for_device {
                    return;
                }
                match result {
                    Ok(()) => {
                        app.otp.add = OtpAddDialog::default();
                        app.otp.info = Some("OTP entry added.".into());
                        app.load_otp_entries();
                    }
                    Err(e) => app.otp.error = Some(e.to_string()),
                }
            })
        });
    }

    /// Delete the entry identified by `(app, account)`.
    pub(crate) fn delete_otp_entry(&mut self, app_name: String, account_name: String) {
        self.otp.error = None;
        let sel = self.otp.transport;
        let for_device = self.selected_device.clone();
        self.spawn_job("Deleting OTP entry\u{2026}", move || {
            let result = (|| -> Result<(), OtpTransportError> {
                let mut session = sel.open()?;
                session.delete_entry(&app_name, &account_name)
            })();
            Box::new(move |app: &mut App| {
                if app.selected_device != for_device {
                    return;
                }
                match result {
                    Ok(()) => {
                        app.otp.info = Some("OTP entry deleted.".into());
                        app.load_otp_entries();
                    }
                    Err(e) => app.otp.error = Some(e.to_string()),
                }
            })
        });
    }

    /// Erase every entry on the key.
    pub(crate) fn erase_all_otp(&mut self) {
        self.otp.error = None;
        let sel = self.otp.transport;
        let for_device = self.selected_device.clone();
        self.spawn_job("Erasing all OTP entries\u{2026}", move || {
            let result = (|| -> Result<(), OtpTransportError> {
                let mut session = sel.open()?;
                session.erase_all()
            })();
            Box::new(move |app: &mut App| {
                if app.selected_device != for_device {
                    return;
                }
                match result {
                    Ok(()) => {
                        app.otp.info = Some("All OTP entries erased.".into());
                        app.load_otp_entries();
                    }
                    Err(e) => app.otp.error = Some(e.to_string()),
                }
            })
        });
    }

    /// Render the OTP tab.
    pub(crate) fn cap_otp(&mut self, ui: &mut egui::Ui, p: &Palette) {
        // Auto-read once per selection (a hard error won't auto-retry).
        if !self.otp_tried && !self.busy() && self.otp.error.is_none() {
            self.otp_tried = true;
            self.load_otp_entries();
        }

        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new("On-device OTP")
                    .font(theme::f_sb(14.5))
                    .color(p.txt),
            );
            if let Some(active) = self.otp.active {
                ui.add_space(8.0);
                let mut meta = format!("via {active}");
                if let Some(serial) = &self.otp.serial {
                    meta.push_str(&format!("  ·  S/N {serial}"));
                }
                ui.label(
                    egui::RichText::new(meta)
                        .font(theme::f_reg(11.5))
                        .color(p.txt3),
                );
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if theme::button(ui, p, BtnKind::Primary, "+ Add entry").clicked() {
                    // OtpAddDialog has a Drop impl (wipes the typed seed), so
                    // `..Default` struct-update isn't allowed; build via default()
                    // then flip `open`.
                    let mut dlg = OtpAddDialog::default();
                    dlg.open = true;
                    self.otp.add = dlg;
                }
                ui.add_space(6.0);
                if theme::button(ui, p, BtnKind::Default, "Refresh").clicked() {
                    self.otp.active = None;
                    self.otp.serial = None;
                    self.load_otp_entries();
                }
                ui.add_space(6.0);
                // Transport selector.
                egui::ComboBox::from_id_salt("otp_transport")
                    .selected_text(self.otp.transport.label())
                    .show_ui(ui, |ui| {
                        for sel in [
                            OtpTransportSel::Auto,
                            OtpTransportSel::Hid,
                            OtpTransportSel::Ccid,
                        ] {
                            if ui
                                .selectable_label(self.otp.transport == sel, sel.label())
                                .clicked()
                            {
                                self.otp.transport = sel;
                                self.otp.active = None;
                                self.otp.serial = None;
                                self.load_otp_entries();
                            }
                        }
                    });
            });
        });
        ui.add_space(12.0);

        if let Some(info) = &self.otp.info {
            ui.colored_label(p.ok, info);
            ui.add_space(6.0);
        }
        if let Some(err) = &self.otp.error {
            ui.colored_label(p.err, err);
            ui.add_space(6.0);
        }

        self.render_otp_add_form(ui, p);
        self.render_otp_delete_confirm(ui, p);

        if !self.otp.loaded {
            ui.label(
                egui::RichText::new("Reading entries\u{2026}")
                    .font(theme::f_reg(13.0))
                    .color(p.txt3),
            );
            return;
        }
        if self.otp.rows.is_empty() && self.otp.error.is_none() {
            ui.label(
                egui::RichText::new("No OTP entries on this key.")
                    .font(theme::f_reg(13.0))
                    .color(p.txt3),
            );
            return;
        }

        let mut copy: Option<String> = None;
        let mut delete: Option<(String, String)> = None;
        theme::card_frame(p).show(ui, |ui| {
            let n = self.otp.rows.len();
            for (i, row) in self.otp.rows.iter().enumerate() {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(
                            egui::RichText::new(row.label())
                                .font(theme::f_sb(13.5))
                                .color(p.txt),
                        );
                        let mut meta = format!("{}/{}", row.type_str, row.algo_str);
                        if row.button_required {
                            meta.push_str("  · touch");
                        }
                        ui.label(
                            egui::RichText::new(meta)
                                .font(theme::f_reg(11.0))
                                .color(p.txt3),
                        );
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if theme::button(ui, p, BtnKind::Default, "Delete").clicked() {
                            delete = Some((row.app_name.clone(), row.account_name.clone()));
                        }
                        ui.add_space(8.0);
                        match &row.code {
                            Some(code) => {
                                if theme::button(ui, p, BtnKind::Default, "Copy").clicked() {
                                    copy = Some(code.clone());
                                }
                                ui.add_space(8.0);
                                ui.label(
                                    egui::RichText::new(code)
                                        .font(theme::f_mono(16.0))
                                        .color(p.txt),
                                );
                            }
                            None => {
                                ui.label(
                                    egui::RichText::new(if row.button_required {
                                        "touch to view"
                                    } else {
                                        "\u{2014}"
                                    })
                                    .font(theme::f_reg(11.5))
                                    .color(p.txt3),
                                );
                            }
                        }
                    });
                });
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

        ui.add_space(10.0);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if theme::button(ui, p, BtnKind::Danger, "Erase all\u{2026}").clicked() {
                self.otp.confirm_delete = Some((String::new(), String::new())); // sentinel = erase-all
            }
        });

        if let Some(code) = copy {
            ui.output_mut(|o| o.copied_text = code.clone());
            self.clipboard_clear_at = Some((code, now_secs_f64() + 45.0));
        }
        if let Some((a, acct)) = delete {
            self.otp.confirm_delete = Some((a, acct));
        }
    }

    /// The add-entry form, shown inline when `add.open`.
    fn render_otp_add_form(&mut self, ui: &mut egui::Ui, p: &Palette) {
        if !self.otp.add.open {
            return;
        }
        let mut submit = false;
        let mut cancel = false;
        theme::card_frame(p).show(ui, |ui| {
            ui.label(
                egui::RichText::new("Add OTP entry")
                    .font(theme::f_sb(13.5))
                    .color(p.txt),
            );
            ui.add_space(8.0);
            egui::Grid::new("otp_add_grid")
                .num_columns(2)
                .spacing([10.0, 8.0])
                .show(ui, |ui| {
                    ui.label("Issuer / app");
                    ui.text_edit_singleline(&mut self.otp.add.app_name);
                    ui.end_row();

                    ui.label("Account");
                    ui.text_edit_singleline(&mut self.otp.add.account_name);
                    ui.end_row();

                    ui.label("Secret (Base32)");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.otp.add.secret)
                            .password(true)
                            .desired_width(260.0),
                    );
                    ui.end_row();

                    ui.label("Type");
                    ui.horizontal(|ui| {
                        ui.selectable_value(&mut self.otp.add.totp, true, "TOTP");
                        ui.selectable_value(&mut self.otp.add.totp, false, "HOTP");
                    });
                    ui.end_row();

                    ui.label("Algorithm");
                    ui.horizontal(|ui| {
                        ui.selectable_value(&mut self.otp.add.sha256, false, "SHA1");
                        ui.selectable_value(&mut self.otp.add.sha256, true, "SHA256");
                    });
                    ui.end_row();

                    ui.label("Digits");
                    ui.add(egui::DragValue::new(&mut self.otp.add.digits).range(4..=10));
                    ui.end_row();

                    if self.otp.add.totp {
                        ui.label("Period (s)");
                        ui.add(egui::DragValue::new(&mut self.otp.add.period).range(1..=120));
                        ui.end_row();
                    }

                    ui.label("Require touch");
                    ui.checkbox(&mut self.otp.add.require_touch, "");
                    ui.end_row();
                });
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if theme::button(ui, p, BtnKind::Primary, "Add").clicked() {
                    submit = true;
                }
                ui.add_space(6.0);
                if theme::button(ui, p, BtnKind::Default, "Cancel").clicked() {
                    cancel = true;
                }
            });
        });
        ui.add_space(10.0);
        if submit {
            self.otp.add.open = false;
            self.provision_otp();
        } else if cancel {
            self.otp.add = OtpAddDialog::default();
        }
    }

    /// Confirmation dialog for delete / erase-all.
    fn render_otp_delete_confirm(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let Some((app_name, account_name)) = self.otp.confirm_delete.clone() else {
            return;
        };
        let erase_all = app_name.is_empty() && account_name.is_empty();
        let mut confirm = false;
        let mut cancel = false;
        theme::card_frame(p).show(ui, |ui| {
            let msg = if erase_all {
                "Erase ALL OTP entries on this key? This cannot be undone.".to_string()
            } else if app_name.is_empty() {
                format!("Delete OTP entry \"{account_name}\"?")
            } else {
                format!("Delete OTP entry \"{app_name}:{account_name}\"?")
            };
            ui.colored_label(p.err, msg);
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                let label = if erase_all { "Erase all" } else { "Delete" };
                if theme::button(ui, p, BtnKind::Danger, label).clicked() {
                    confirm = true;
                }
                ui.add_space(6.0);
                if theme::button(ui, p, BtnKind::Default, "Cancel").clicked() {
                    cancel = true;
                }
            });
        });
        ui.add_space(10.0);
        if confirm {
            self.otp.confirm_delete = None;
            if erase_all {
                self.erase_all_otp();
            } else {
                self.delete_otp_entry(app_name, account_name);
            }
        } else if cancel {
            self.otp.confirm_delete = None;
        }
    }
}

/// SHA label for an OTP algorithm (the byte layer has only SHA1/SHA256).
fn otp_algo_str(a: keyroost_token2otp::Algorithm) -> &'static str {
    match a {
        keyroost_token2otp::Algorithm::Sha1 => "SHA1",
        keyroost_token2otp::Algorithm::Sha256 => "SHA256",
    }
}
