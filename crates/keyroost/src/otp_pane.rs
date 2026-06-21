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
        // Honor KEYROOST_OTP_DEBUG so a stuck/empty list over NFC can be traced
        // from the GUI (the CLI has --debug; the GUI had no switch). Matches the
        // KEYROOST_CTAP_DEBUG convention.
        let debug = std::env::var_os("KEYROOST_OTP_DEBUG").is_some();
        match self {
            OtpTransportSel::Auto => Token2OtpSession::detect_debug(debug),
            OtpTransportSel::Hid => Token2OtpSession::detect_hid_only(debug),
            OtpTransportSel::Ccid => Token2OtpSession::detect_pcsc_only(debug),
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
    /// TOTP time-step in seconds (e.g. 30 or 60), straight from the entry
    /// record's `timestep` field. Meaningful only for TOTP entries.
    pub period: u16,
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

/// Current state of the HOTP-on-button keystroke slot, read from the device
/// config. Lets the UI show whether a seed is provisioned and edit the typing
/// options without re-entering the seed.
#[derive(Clone, Copy)]
pub struct ButtonHotpStatus {
    /// A seed is provisioned in the button-HOTP slot (config bit 8).
    pub configured: bool,
    /// The slot types Enter after the code.
    pub send_enter: bool,
    /// Long-press is required to emit the code.
    pub long_touch: bool,
    /// Codes are typed using the numeric keypad layout.
    pub numpad: bool,
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
    /// Whether the key MODEL supports HOTP-on-touch at all (distinct from the
    /// keyboard interface merely being disabled). `None` if config unreadable.
    hotp_supported: Option<bool>,
    iface: Option<IfaceState>,
    button_hotp_status: Option<ButtonHotpStatus>,
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
    /// Whether the key MODEL supports HOTP-on-touch at all (distinct from the
    /// keyboard interface being toggled off). Gates the "Enable HID-HOTP" item.
    /// `None` until known.
    pub hotp_supported: Option<bool>,
    /// Current interface enabled-states (fido, keyboard-HID, ccid), read from the
    /// device config on load. `None` until known.
    pub iface: Option<IfaceState>,
    /// Pending keyboard-HID toggle confirmation: the target state and the typed
    /// confirmation phrase. `Some` while the confirm dialog is open.
    pub kbd_confirm: Option<KbdToggle>,
    /// Codes read on-demand for touch-required TOTP entries, keyed by
    /// `(app_name, account_name)`. Populated when the user presses "Read" and
    /// touches the key; shown in place of "touch to view" until the list reloads.
    pub touch_codes: std::collections::HashMap<(String, String), String>,
    /// Cached button-HOTP slot status from the device config: whether a seed is
    /// configured, and the current send-Enter / long-touch / numpad settings.
    /// `None` until read. Drives the "seed configured" indicator and the
    /// settings-only editor.
    pub button_hotp_status: Option<ButtonHotpStatus>,
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
        // On a reader-attached key (no USB-HID interface), force the CCID/NFC
        // transport. The "Auto" path probes USB-HID first, which is pointless
        // here and — on Windows, where the FIDO HID interface is access-
        // restricted — can disrupt the read and yield an empty list, even though
        // the OTP applet is reachable over the reader. If the user explicitly
        // picked a transport, honour it.
        let reader_only = self
            .selected_device()
            .map(|d| d.hid_path.is_none() && d.reader.is_some())
            .unwrap_or(false);
        let sel = if reader_only && self.otp.transport == OtpTransportSel::Auto {
            OtpTransportSel::Ccid
        } else {
            self.otp.transport
        };
        if std::env::var_os("KEYROOST_OTP_DEBUG").is_some() {
            eprintln!(
                "[otp gui] reader_only={reader_only} chosen_transport={} (user_sel={})",
                sel.label(),
                self.otp.transport.label()
            );
        }
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
                    // Over a PC/SC reader (NFC/contact) we skip the best-effort
                    // serial and device-config reads and go straight to the entry
                    // enumeration — exactly what the CLI `otp list` does. Two
                    // reasons: (1) `read_serial` selects the FIDO applet for the
                    // serial, a detour only needed for display; (2) some contact
                    // (T=0) readers stall on the Case-2 `READ_CONFIG` APDU, which
                    // would hang the whole list. Both are cosmetic (serial string,
                    // HOTP-on-touch hints), so their absence degrades gracefully.
                    let pcsc = session.is_pcsc();
                    let serial = if pcsc {
                        None
                    } else {
                        session
                            .read_serial()
                            .ok()
                            .map(|sn| sn.iter().map(|b| format!("{b:02x}")).collect::<String>())
                    };
                    // Read the device config once; derive both the touch-HOTP
                    // availability and the interface states from it. Skipped over
                    // PC/SC (see above) — `dev_info` stays None, which the match
                    // arms below already treat as "unknown" rather than blocking.
                    let dev_info = if pcsc {
                        None
                    } else {
                        session.read_device_info().ok()
                    };
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
                    // Model-level support, separate from the interface toggle so
                    // the UI can disable "Enable HID-HOTP" on keys that lack the
                    // feature entirely (vs merely having the interface off).
                    let hotp_supported = dev_info.as_ref().map(|i| i.button_hotp_supported());
                    let button_hotp_status = dev_info.as_ref().and_then(|info| {
                        // The seed bit lives in byte 1; over a short CCID stub
                        // (byte 0 only) we can't tell, so report unknown rather
                        // than a misleading "no seed configured".
                        if !info.has_config_byte() {
                            return None;
                        }
                        Some(ButtonHotpStatus {
                            configured: info.button_hotp_configured(),
                            send_enter: !info.hotp_suppresses_enter(),
                            long_touch: info.hotp_long_press(),
                            numpad: info.hotp_uses_numpad(),
                        })
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
                            period: e.timestep,
                        })
                        .collect();
                    Ok(OtpLoad {
                        rows,
                        active,
                        serial,
                        touch_ok,
                        touch_why,
                        hotp_supported,
                        iface,
                        button_hotp_status,
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
                        app.otp.hotp_supported = load.hotp_supported;
                        app.otp.iface = load.iface;
                        app.otp.button_hotp_status = load.button_hotp_status;
                        // Codes read on touch are tied to the old time-window;
                        // drop them so the freshly-loaded list governs display.
                        app.otp.touch_codes.clear();
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
        if self.otp.add.secret.trim().is_empty() {
            self.otp.error = Some("Enter a Base32 secret for this entry.".into());
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
        // An empty secret field means "don't change the seed" — just apply the
        // typing options (Send Enter / long touch / numeric keypad). This works
        // whether or not a seed is already configured: with a seed it edits the
        // options in place; without one it sets the options the device will use
        // once a seed is written. Either way the seed slot is left untouched.
        if self.otp.button_hotp.secret.trim().is_empty() {
            let send_enter = self.otp.button_hotp.send_enter;
            let long_touch = self.otp.button_hotp.long_touch;
            let numpad = self.otp.button_hotp.numpad;
            self.otp.button_hotp.open = false;
            self.apply_button_hotp_options(send_enter, long_touch, numpad);
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
                        // Re-read the config so the "seed configured" status and
                        // the settings-only editor reflect the new slot.
                        app.load_otp_entries();
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
                    Ok(()) => {
                        app.otp.info = Some("Touch HOTP cleared.".into());
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

    /// Read a touch-required TOTP entry's current code: the device requires a
    /// button press, so `read_entry` waits for the touch (the transport fires
    /// the button-prompt). The returned code is stashed in `touch_codes` and
    /// shown in place of "touch to view" until the next list reload.
    pub(crate) fn read_touch_otp_entry(&mut self, app_name: String, account_name: String) {
        self.otp.error = None;
        let sel = self.otp.transport;
        let for_device = self.selected_device.clone();
        let key = (app_name.clone(), account_name.clone());
        self.spawn_job("Reading code \u{2014} touch your key\u{2026}", move || {
            let result = (|| -> Result<Option<String>, String> {
                let mut session = sel.open().map_err(|e| e.to_string())?;
                let now = unix_now();
                let entry = session
                    .read_entry(now, &app_name, &account_name)
                    .map_err(|e| e.to_string())?;
                Ok(entry.code)
            })();
            Box::new(move |app: &mut App| {
                if app.selected_device != for_device {
                    return;
                }
                match result {
                    Ok(Some(code)) => {
                        app.otp.touch_codes.insert(key, code);
                    }
                    Ok(None) => {
                        app.otp.error = Some("the key did not return a code".into());
                    }
                    Err(e) => app.otp.error = Some(e),
                }
            })
        });
    }

    /// Apply the HOTP-on-button typing options (send-Enter, long-touch, numpad)
    /// to the already-provisioned slot, without re-sending the seed.
    pub(crate) fn apply_button_hotp_options(
        &mut self,
        send_enter: bool,
        long_touch: bool,
        numpad: bool,
    ) {
        self.otp.error = None;
        let sel = self.otp.transport;
        let for_device = self.selected_device.clone();
        self.spawn_job("Updating touch HOTP options\u{2026}", move || {
            let result = (|| -> Result<(), String> {
                let mut session = sel.open().map_err(|e| e.to_string())?;
                session
                    .set_button_hotp_options(send_enter, long_touch, numpad)
                    .map_err(|e| e.to_string())
            })();
            Box::new(move |app: &mut App| {
                if app.selected_device != for_device {
                    return;
                }
                match result {
                    Ok(()) => {
                        app.otp.info = Some("Touch HOTP options updated.".into());
                        if let Some(st) = app.otp.button_hotp_status.as_mut() {
                            st.send_enter = send_enter;
                            st.long_touch = long_touch;
                            st.numpad = numpad;
                        }
                    }
                    Err(e) => app.otp.error = Some(e),
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
            ui.add_space(6.0);
            self.help_dot(ui, p, "otp");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                // Secondary actions live in an overflow menu so the header row
                // doesn't crowd: HID-HOTP configure, the interface toggle, and the
                // transport selector. Rendered first so that, in this
                // right-to-left layout, it sits at the far right edge. Actions are
                // accumulated as locals and applied after the menu closure to keep
                // `self` borrows simple.
                let mut open_touch = false;
                let mut kbd_target: Option<bool> = None;
                let mut new_transport: Option<OtpTransportSel> = None;

                let menu_btn =
                    theme::button(ui, p, BtnKind::Default, "...").on_hover_text("More actions");
                let menu_id = ui.make_persistent_id("otp_more_menu");
                if menu_btn.clicked() {
                    ui.memory_mut(|m| m.toggle_popup(menu_id));
                }
                egui::popup::popup_below_widget(
                    ui,
                    menu_id,
                    &menu_btn,
                    egui::popup::PopupCloseBehavior::CloseOnClick,
                    |ui| {
                        ui.set_min_width(180.0);

                        // Transport selector.
                        ui.label(
                            egui::RichText::new("Transport")
                                .font(theme::f_reg(11.0))
                                .color(p.txt3),
                        );
                        for sel in [
                            OtpTransportSel::Auto,
                            OtpTransportSel::Hid,
                            OtpTransportSel::Ccid,
                        ] {
                            if ui
                                .selectable_label(self.otp.transport == sel, sel.label())
                                .clicked()
                            {
                                new_transport = Some(sel);
                            }
                        }
                        ui.separator();

                        // Configure HID-HOTP — disabled (with reason) when the
                        // keyboard interface is off or unsupported.
                        let touch_blocked = self.otp.touch_hotp_ok == Some(false);
                        ui.add_enabled_ui(!touch_blocked, |ui| {
                            let r = ui.selectable_label(false, "Configure HID-HOTP\u{2026}");
                            let r = match self.otp.touch_hotp_why {
                                Some(why) if touch_blocked => r.on_disabled_hover_text(why),
                                _ => r,
                            };
                            if r.clicked() {
                                open_touch = true;
                            }
                        });

                        // Enable/Disable the keyboard-HID interface.
                        if let Some(iface) = self.otp.iface {
                            let (label, target) = if iface.keyboard {
                                ("Disable HID-HOTP", false)
                            } else {
                                ("Enable HID-HOTP", true)
                            };
                            let would_underflow = !target && {
                                let after = IfaceState {
                                    keyboard: false,
                                    ..iface
                                };
                                after.enabled_count() < 2
                            };
                            // Enabling the keyboard interface is pointless on a
                            // model that doesn't have the HOTP-on-touch feature,
                            // so block it (the interface toggle only makes sense
                            // for keys that actually support it).
                            let unsupported = target && self.otp.hotp_supported == Some(false);
                            let blocked = would_underflow || unsupported;
                            ui.add_enabled_ui(!blocked, |ui| {
                                let r = ui.selectable_label(false, label);
                                let r = if unsupported {
                                    r.on_disabled_hover_text(
                                        "this key model does not support HOTP-on-touch",
                                    )
                                } else if would_underflow {
                                    r.on_disabled_hover_text(
                                        "at least two interfaces must stay enabled",
                                    )
                                } else {
                                    r
                                };
                                if r.clicked() {
                                    kbd_target = Some(target);
                                }
                            });
                        }
                    },
                );

                // Apply menu selections after the closure.
                if let Some(sel) = new_transport {
                    self.otp.transport = sel;
                    self.otp.active = None;
                    self.otp.serial = None;
                    self.load_otp_entries();
                }
                if open_touch {
                    let mut dlg = ButtonHotpDialog::default();
                    dlg.open = true;
                    if let Some(st) = self.otp.button_hotp_status {
                        dlg.send_enter = st.send_enter;
                        dlg.long_touch = st.long_touch;
                        dlg.numpad = st.numpad;
                    }
                    self.otp.button_hotp = dlg;
                }
                if let Some(target) = kbd_target {
                    self.otp.kbd_confirm = Some(KbdToggle {
                        enable: target,
                        typed: String::new(),
                    });
                }

                // Primary actions, to the left of the overflow menu (added after
                // it so they sit left of it in this right-to-left layout).
                ui.add_space(6.0);
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
            });
        });
        // Transport + serial on their own line, so neither collides with the
        // controls on the header row.
        if self.otp.active.is_some() || self.otp.serial.is_some() {
            let mut bits: Vec<String> = Vec::new();
            if let Some(active) = self.otp.active {
                bits.push(format!("via {active}"));
            }
            if let Some(serial) = &self.otp.serial {
                bits.push(format!("S/N {serial}"));
            }
            ui.label(
                egui::RichText::new(bits.join("  \u{00b7}  "))
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
        let mut read_touch: Option<(String, String)> = None;
        // Snapshot on-demand-read codes so the row loop (which borrows
        // `self.otp.rows`) can look them up without also borrowing `self.otp`.
        let touch_codes = self.otp.touch_codes.clone();
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
                                let is_totp = row.type_str.eq_ignore_ascii_case("TOTP");
                                // TOTP codes are time-based: show the same live
                                // countdown ring + seconds the OATH pane uses, so
                                // the user can see how long the code stays valid.
                                // HOTP codes are counter-based and have no window.
                                // Use the entry's own time-step (30 or 60s, etc.);
                                // fall back to 30 if the record reported 0.
                                let period = if row.period == 0 {
                                    30
                                } else {
                                    row.period as u64
                                };
                                let totp = is_totp.then(|| theme::totp_window(period));
                                let code_color = match totp {
                                    Some((secs, _)) if secs <= 5 => p.warn,
                                    _ => p.txt,
                                };
                                ui.label(
                                    egui::RichText::new(code)
                                        .font(theme::f_mono(16.0))
                                        .color(code_color),
                                );
                                if let Some((secs, pct)) = totp {
                                    let ring_color = if secs <= 5 { p.warn } else { p.accent };
                                    ui.add_space(8.0);
                                    theme::ring(ui, pct, 18.0, ring_color, p.line);
                                    ui.add_space(6.0);
                                    ui.label(
                                        egui::RichText::new(format!("{secs}s"))
                                            .font(theme::f_reg(11.0))
                                            .color(p.txt3),
                                    );
                                }
                            }
                            None => {
                                let rkey = (row.app_name.clone(), row.account_name.clone());
                                if let Some(code) = touch_codes.get(&rkey) {
                                    // Already read on touch this session — show it
                                    // (TOTP touch entries still have a window, but
                                    // the device gives no countdown for them here).
                                    if theme::button(ui, p, BtnKind::Default, "Copy").clicked() {
                                        copy = Some(code.clone());
                                    }
                                    ui.add_space(8.0);
                                    ui.label(
                                        egui::RichText::new(code)
                                            .font(theme::f_mono(16.0))
                                            .color(p.txt),
                                    );
                                } else if row.button_required {
                                    if theme::button(ui, p, BtnKind::Default, "Read")
                                        .on_hover_text("Touch the key to read this code")
                                        .clicked()
                                    {
                                        read_touch = Some(rkey);
                                    }
                                } else {
                                    ui.label(
                                        egui::RichText::new("\u{2014}")
                                            .font(theme::f_reg(11.5))
                                            .color(p.txt3),
                                    );
                                }
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
        if let Some((a, acct)) = read_touch {
            self.read_touch_otp_entry(a, acct);
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
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("HID-HOTP (keystroke)")
                        .font(theme::f_sb(13.5))
                        .color(p.txt),
                );
                ui.add_space(6.0);
                self.help_dot(ui, p, "touch-hotp");
            });
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
            // Show whether a seed is already provisioned in the slot, read from
            // the device config on load.
            match self.otp.button_hotp_status {
                Some(st) if st.configured => {
                    theme::pill(ui, "Seed configured", p.ok, p.ok_soft());
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new(
                            "A seed is already set. Leave the secret blank and Save \
                             to change only the typing options; enter a new secret to \
                             replace the seed or change the digit length.",
                        )
                        .font(theme::f_reg(11.0))
                        .color(p.txt3),
                    );
                }
                Some(_) => {
                    theme::pill(ui, "No seed configured", p.txt3, p.line);
                }
                None => {
                    // Couldn't read the device config — most often because the
                    // full config block is only served over USB-HID, which
                    // Windows restricts for FIDO-class devices unless elevated.
                    // Don't claim "no seed"; say we can't tell.
                    theme::pill(ui, "Slot status unknown", p.txt3, p.line);
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new(
                            "Couldn't read the slot status from this key's config \
                             block. Provisioning still works; reload to retry.",
                        )
                        .font(theme::f_reg(11.0))
                        .color(p.txt3),
                    );
                }
            }
            ui.add_space(8.0);
            egui::Grid::new("button_hotp_grid")
                .num_columns(2)
                .spacing([10.0, 8.0])
                .show(ui, |ui| {
                    let configured = matches!(
                        self.otp.button_hotp_status,
                        Some(st) if st.configured
                    );
                    ui.label(if configured {
                        "New secret (Base32)"
                    } else {
                        "Secret (Base32)"
                    });
                    ui.add(
                        egui::TextEdit::singleline(&mut self.otp.button_hotp.secret)
                            .password(true)
                            .hint_text(if configured {
                                "leave blank to keep current seed"
                            } else {
                                ""
                            })
                            .desired_width(260.0),
                    );
                    ui.end_row();

                    // Digit length is only settable as part of a seed write
                    // (spec §1.7); there's no standalone command for it. So it's
                    // only editable when a secret is being entered — with a blank
                    // secret (options-only Save) the existing length is kept.
                    let seed_present = !self.otp.button_hotp.secret.trim().is_empty();
                    ui.label("Digits");
                    ui.add_enabled_ui(seed_present, |ui| {
                        ui.horizontal(|ui| {
                            ui.selectable_value(&mut self.otp.button_hotp.digits, 6u8, "6");
                            ui.selectable_value(&mut self.otp.button_hotp.digits, 8u8, "8");
                        });
                    })
                    .response
                    .on_disabled_hover_text(
                        "Digit length can only change when you set a new secret \u{2014} \
                         the key has no command to change it on its own.",
                    );
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
                "Enable HID-HOTP (keyboard interface)?"
            } else {
                "Disable HID-HOTP (keyboard interface)?"
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
