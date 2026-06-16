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

/// Dialog state for configuring the HOTP-on-touch keystroke slot: the key types
/// a fresh HOTP code as keyboard input when touched outside any session.
pub struct ButtonHotpDialog {
    pub open: bool,
    /// Base32 secret, entered masked.
    pub secret: String,
    /// 6 or 8.
    pub digits: u8,
    /// Append an Enter keystroke after the code.
    pub send_enter: bool,
    /// Require a 2-second long touch (else a short tap triggers it).
    pub long_touch: bool,
    /// Type digits using the numeric-keypad scancodes.
    pub numpad: bool,
}

impl Default for ButtonHotpDialog {
    fn default() -> Self {
        ButtonHotpDialog {
            open: false,
            secret: String::new(),
            digits: 6,
            send_enter: true,
            long_touch: false,
            numpad: false,
        }
    }
}

impl Drop for ButtonHotpDialog {
    fn drop(&mut self) {
        wipe(&mut self.secret);
    }
}

/// Current enabled-state of the key's three USB interfaces, read from the device
/// config. Used to show the keyboard-HID toggle and to keep at least two
/// interfaces enabled when changing one.
#[derive(Clone, Copy)]
pub struct IfaceState {
    pub fido: bool,
    pub keyboard: bool,
    pub ccid: bool,
}

impl IfaceState {
    fn enabled_count(&self) -> usize {
        [self.fido, self.keyboard, self.ccid]
            .iter()
            .filter(|x| **x)
            .count()
    }
}

/// Pending keyboard-HID toggle awaiting a typed-phrase confirmation.
pub struct KbdToggle {
    /// The state keyboard-HID will be set to.
    pub enable: bool,
    /// What the user has typed; must match the required phrase to proceed.
    pub typed: String,
}

/// Result of a successful OTP-pane load: the entry rows plus the device facts the
/// pane shows (transport label, serial, touch-HOTP availability, interface state).
struct OtpLoad {
    rows: Vec<OtpRow>,
    active: &'static str,
    serial: Option<String>,
    touch_ok: Option<bool>,
    touch_why: Option<&'static str>,
    iface: Option<IfaceState>,
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
    /// Dialog for the HOTP-on-touch keystroke slot.
    pub button_hotp: ButtonHotpDialog,
    pub confirm_delete: Option<(String, String)>,
    /// Active transport label after a successful open (for the status line).
    pub active: Option<&'static str>,
    /// Device serial number (hex), read alongside the entry list when available.
    pub serial: Option<String>,
    /// Whether the key currently supports HOTP-on-touch (keyboard-HID enabled and
    /// the feature present). `None` until determined. Drives the Touch HOTP button.
    pub touch_hotp_ok: Option<bool>,
    /// Why touch-HOTP is unavailable, for the disabled-button tooltip.
    pub touch_hotp_why: Option<&'static str>,
    /// Current interface enabled-states (fido, keyboard-HID, ccid), read from the
    /// device config on load. `None` until known.
    pub iface: Option<IfaceState>,
    /// Pending keyboard-HID toggle confirmation: the target state and the typed
    /// confirmation phrase. `Some` while the confirm dialog is open.
    pub kbd_confirm: Option<KbdToggle>,
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
                (|| -> Result<OtpLoad, OtpTransportError> {
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
                    // Determine whether HOTP-on-touch is usable: it types over the
                    // keyboard-HID interface, so a key with that interface disabled
                    // (or that doesn't support the feature) returns 6A81. Detect it
                    // up front so the UI can disable the action with a reason rather
                    // than letting the user fill the form and fail at submit.
                    // Read the device config once; derive both the touch-HOTP
                    // availability and the interface states from it.
                    let dev_info = session.read_device_info().ok();
                    let (touch_ok, touch_why): (Option<bool>, Option<&'static str>) =
                        match &dev_info {
                            Some(info) => {
                                if !info.button_hotp_supported() {
                                    (Some(false), Some("this key model does not support HOTP-on-touch"))
                                } else if info.hotp_keystroke_disabled() {
                                    (Some(false), Some("the keyboard-HID interface is disabled on this key; enable it to use HOTP-on-touch"))
                                } else {
                                    (Some(true), None)
                                }
                            }
                            // Couldn't read config (older model / reader quirk):
                            // leave it permitted rather than wrongly blocking.
                            None => (None, None),
                        };
                    let iface = dev_info.as_ref().map(|info| IfaceState {
                        fido: !info.fido_disabled(),
                        keyboard: !info.hotp_keystroke_disabled(),
                        ccid: !info.ccid_disabled(),
                    });
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
                    Ok(OtpLoad {
                        rows,
                        active,
                        serial,
                        touch_ok,
                        touch_why,
                        iface,
                    })
                })();
            Box::new(move |app: &mut App| {
                if app.selected_device != for_device {
                    return; // user switched keys mid-read
                }
                match result {
                    Ok(load) => {
                        app.otp.rows = load.rows;
                        app.otp.loaded = true;
                        app.otp.active = Some(load.active);
                        app.otp.serial = load.serial;
                        app.otp.touch_hotp_ok = load.touch_ok;
                        app.otp.touch_hotp_why = load.touch_why;
                        app.otp.iface = load.iface;
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

    /// Configure the HOTP-on-touch keystroke slot from the dialog fields.
    pub(crate) fn provision_button_hotp(&mut self) {
        self.otp.error = None;
        let digits = self.otp.button_hotp.digits;
        if digits != 6 && digits != 8 {
            self.otp.error = Some("button HOTP digits must be 6 or 8".into());
            return;
        }
        let secret = zeroize::Zeroizing::new(self.otp.button_hotp.secret.clone());
        let send_enter = self.otp.button_hotp.send_enter;
        let long_touch = self.otp.button_hotp.long_touch;
        let numpad = self.otp.button_hotp.numpad;
        let sel = self.otp.transport;
        let for_device = self.selected_device.clone();

        self.spawn_job("Setting touch HOTP\u{2026}", move || {
            let result = (|| -> Result<(), String> {
                let seed = keyroost_token2otp::decode_base32_seed(secret.trim())
                    .map_err(|m| format!("invalid Base32 secret: {m}"))?;
                let mut session = sel.open().map_err(|e| e.to_string())?;
                session
                    .set_button_hotp(digits, &seed, send_enter, long_touch, numpad)
                    .map_err(|e| e.to_string())
            })();
            Box::new(move |app: &mut App| {
                if app.selected_device != for_device {
                    return;
                }
                match result {
                    Ok(()) => {
                        app.otp.button_hotp = ButtonHotpDialog::default();
                        app.otp.info = Some("Touch HOTP configured.".into());
                    }
                    Err(e) => app.otp.error = Some(e.to_string()),
                }
            })
        });
    }

    /// Apply a keyboard-HID enable/disable, preserving the other two interfaces
    /// and never dropping below two enabled. Built from the cached `iface` state.
    pub(crate) fn apply_keyboard_toggle(&mut self, enable: bool) {
        self.otp.error = None;
        let Some(cur) = self.otp.iface else {
            self.otp.error = Some("interface state unknown; refresh first".into());
            return;
        };
        // Compute the resulting state and enforce the two-interface minimum.
        let next = IfaceState {
            fido: cur.fido,
            keyboard: enable,
            ccid: cur.ccid,
        };
        if next.enabled_count() < 2 {
            self.otp.error = Some(
                "at least two interfaces must stay enabled; enable another interface first".into(),
            );
            return;
        }
        // Build the SET_DEVICE_TYPE *disable* mask (set bit = disable).
        use keyroost_token2otp::{DEV_CCID, DEV_FIDO, DEV_KEYBOARD};
        let mut disable: u8 = 0;
        if !next.fido {
            disable |= DEV_FIDO;
        }
        if !next.keyboard {
            disable |= DEV_KEYBOARD;
        }
        if !next.ccid {
            disable |= DEV_CCID;
        }
        let sel = self.otp.transport;
        let for_device = self.selected_device.clone();
        self.spawn_job("Updating interfaces\u{2026}", move || {
            let result = (|| -> Result<(), String> {
                let mut session = sel.open().map_err(|e| e.to_string())?;
                session.set_device_type(disable).map_err(|e| e.to_string())
            })();
            Box::new(move |app: &mut App| {
                if app.selected_device != for_device {
                    return;
                }
                match result {
                    Ok(()) => {
                        app.otp.info = Some(
                            "Interface updated. Re-plug the key for the change to take effect."
                                .into(),
                        );
                        // Reflect the change locally; a refresh re-reads from hardware.
                        app.otp.iface = Some(next);
                    }
                    Err(e) => app.otp.error = Some(e),
                }
            })
        });
    }

    /// Clear the HOTP-on-touch keystroke slot.
    pub(crate) fn delete_button_hotp_slot(&mut self) {
        self.otp.error = None;
        let sel = self.otp.transport;
        let for_device = self.selected_device.clone();
        self.spawn_job("Clearing touch HOTP\u{2026}", move || {
            let result = (|| -> Result<(), String> {
                let mut session = sel.open().map_err(|e| e.to_string())?;
                session.delete_button_hotp().map_err(|e| e.to_string())
            })();
            Box::new(move |app: &mut App| {
                if app.selected_device != for_device {
                    return;
                }
                match result {
                    Ok(()) => app.otp.info = Some("Touch HOTP cleared.".into()),
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
        self.spawn_job(
            "Erasing all OTP entries \u{2014} touch your key\u{2026}",
            move || {
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
            },
        );
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
                ui.label(
                    egui::RichText::new(format!("via {active}"))
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
                // Touch-HOTP types over the keyboard-HID interface; disable the
                // action when that interface is off or the model lacks the feature.
                let touch_blocked = self.otp.touch_hotp_ok == Some(false);
                let mut open_touch = false;
                ui.add_enabled_ui(!touch_blocked, |ui| {
                    let r = theme::button(ui, p, BtnKind::Default, "Touch HOTP");
                    let r = match self.otp.touch_hotp_why {
                        Some(why) if touch_blocked => r.on_disabled_hover_text(why),
                        _ => r,
                    };
                    if r.clicked() {
                        open_touch = true;
                    }
                });
                if open_touch {
                    let mut dlg = ButtonHotpDialog::default();
                    dlg.open = true;
                    self.otp.button_hotp = dlg;
                }
                // Keyboard-HID enable/disable toggle (governs whether Touch HOTP
                // can work at all). Only shown once we know the interface state.
                if let Some(iface) = self.otp.iface {
                    ui.add_space(6.0);
                    let (label, target) = if iface.keyboard {
                        ("Disable keyboard", false)
                    } else {
                        ("Enable keyboard", true)
                    };
                    // Don't offer a disable that would drop below two interfaces.
                    let would_underflow = !target && {
                        let after = IfaceState {
                            keyboard: false,
                            ..iface
                        };
                        after.enabled_count() < 2
                    };
                    let mut open_kbd = false;
                    ui.add_enabled_ui(!would_underflow, |ui| {
                        let r = theme::button(ui, p, BtnKind::Ghost, label);
                        let r = if would_underflow {
                            r.on_disabled_hover_text("at least two interfaces must stay enabled")
                        } else {
                            r
                        };
                        if r.clicked() {
                            open_kbd = true;
                        }
                    });
                    if open_kbd {
                        self.otp.kbd_confirm = Some(KbdToggle {
                            enable: target,
                            typed: String::new(),
                        });
                    }
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
        // Serial on its own line, so a long serial never collides with the
        // controls on the header row.
        if let Some(serial) = &self.otp.serial {
            ui.label(
                egui::RichText::new(format!("S/N {serial}"))
                    .font(theme::f_reg(11.5))
                    .color(p.txt3),
            );
        }
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
        self.render_button_hotp_form(ui, p);
        self.render_keyboard_confirm(ui, p);
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

    /// The touch-HOTP form, shown inline when `button_hotp.open`. Configures the
    /// single HOTP-on-touch keystroke slot.
    fn render_button_hotp_form(&mut self, ui: &mut egui::Ui, p: &Palette) {
        if !self.otp.button_hotp.open {
            return;
        }
        let mut submit = false;
        let mut clear = false;
        let mut cancel = false;
        theme::card_frame(p).show(ui, |ui| {
            ui.label(
                egui::RichText::new("Touch HOTP (keystroke)")
                    .font(theme::f_sb(13.5))
                    .color(p.txt),
            );
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(
                    "The key types a fresh HOTP code as keyboard input when you touch it \
                     outside any session. One slot per key.",
                )
                .font(theme::f_reg(11.5))
                .color(p.txt3),
            );
            ui.add_space(8.0);
            egui::Grid::new("button_hotp_grid")
                .num_columns(2)
                .spacing([10.0, 8.0])
                .show(ui, |ui| {
                    ui.label("Secret (Base32)");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.otp.button_hotp.secret)
                            .password(true)
                            .desired_width(260.0),
                    );
                    ui.end_row();

                    ui.label("Digits");
                    ui.horizontal(|ui| {
                        ui.selectable_value(&mut self.otp.button_hotp.digits, 6u8, "6");
                        ui.selectable_value(&mut self.otp.button_hotp.digits, 8u8, "8");
                    });
                    ui.end_row();

                    ui.label("Send Enter");
                    ui.checkbox(&mut self.otp.button_hotp.send_enter, "");
                    ui.end_row();

                    ui.label("Long touch (2s)");
                    ui.checkbox(&mut self.otp.button_hotp.long_touch, "");
                    ui.end_row();

                    ui.label("Numeric keypad");
                    ui.checkbox(&mut self.otp.button_hotp.numpad, "");
                    ui.end_row();
                });
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if theme::button(ui, p, BtnKind::Primary, "Save").clicked() {
                    submit = true;
                }
                ui.add_space(6.0);
                if theme::button(ui, p, BtnKind::Default, "Cancel").clicked() {
                    cancel = true;
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if theme::button(ui, p, BtnKind::Danger, "Clear slot").clicked() {
                        clear = true;
                    }
                });
            });
        });
        ui.add_space(10.0);
        if submit {
            self.otp.button_hotp.open = false;
            self.provision_button_hotp();
        } else if clear {
            self.otp.button_hotp.open = false;
            self.delete_button_hotp_slot();
        } else if cancel {
            self.otp.button_hotp = ButtonHotpDialog::default();
        }
    }

    /// Typed-phrase confirmation for the keyboard-HID enable/disable toggle.
    /// Mirrors the CLI's `interface` confirmation: this reconfigures the hardware,
    /// so the user must type an exact phrase before it applies.
    fn render_keyboard_confirm(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let Some(tog) = self.otp.kbd_confirm.as_ref() else {
            return;
        };
        let enable = tog.enable;
        const PHRASE: &str = "change interface";
        let mut apply = false;
        let mut cancel = false;
        theme::card_frame(p).show(ui, |ui| {
            let title = if enable {
                "Enable the keyboard-HID interface?"
            } else {
                "Disable the keyboard-HID interface?"
            };
            ui.colored_label(p.err, title);
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(
                    "This reconfigures the key's USB interfaces. The change takes effect \
                     after you re-plug the key. Disabling an interface removes the matching \
                     features until you re-enable it; if you disable the interface you are \
                     connected over, you may lose access to the key.",
                )
                .font(theme::f_reg(11.5))
                .color(p.txt3),
            );
            ui.add_space(8.0);
            ui.label(
                egui::RichText::new(format!("Type \u{201c}{PHRASE}\u{201d} to confirm:"))
                    .font(theme::f_reg(12.0))
                    .color(p.txt2),
            );
            if let Some(t) = self.otp.kbd_confirm.as_mut() {
                ui.add(egui::TextEdit::singleline(&mut t.typed).desired_width(220.0));
            }
            ui.add_space(8.0);
            let matched = self
                .otp
                .kbd_confirm
                .as_ref()
                .is_some_and(|t| t.typed.trim() == PHRASE);
            ui.horizontal(|ui| {
                ui.add_enabled_ui(matched, |ui| {
                    if theme::button(ui, p, BtnKind::Danger, "Apply").clicked() {
                        apply = true;
                    }
                });
                ui.add_space(6.0);
                if theme::button(ui, p, BtnKind::Default, "Cancel").clicked() {
                    cancel = true;
                }
            });
        });
        ui.add_space(10.0);
        if apply {
            self.otp.kbd_confirm = None;
            self.apply_keyboard_toggle(enable);
        } else if cancel {
            self.otp.kbd_confirm = None;
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
            if erase_all {
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(
                        "After you confirm, touch the key's sensor to complete the erase \
                         — the device waits for a physical touch.",
                    )
                    .font(theme::f_reg(11.5))
                    .color(p.txt3),
                );
            }
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
