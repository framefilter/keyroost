//! Feitian OTP (TOTP/HOTP) pane for the desktop GUI.
//!
//! Same shape as the on-device OTP pane: a per-selection state struct,
//! `spawn_job`-driven operations that do the card I/O off the UI thread, and
//! a `cap_ftotp` render function. It drives
//! [`keyroost_transport::FeitianOtpSession`] on the selected key's own
//! smart-card reader.
//!
//! The key lists its accounts without a touch, and computes a code, stores
//! an account or deletes one only once it is touched
//! (`docs/PROTOCOL-feitianotp.md`). So the list shows no codes: each is read
//! with its own button, and a TOTP code stays until its time window ends.

use std::time::{SystemTime, UNIX_EPOCH};

use keyroost_feitianotp as fotp;
use keyroost_transport::{FeitianOtpListing, FeitianOtpSession, TransportError};

use crate::ui::theme::{self, BtnKind, Palette};
use crate::{completion_still_valid, wipe, App, Severity, TypedSecrets};

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One account in the list.
pub struct FtotpRow {
    pub slot: fotp::Slot,
    /// The name as the key stores it, period prefix included: what a code
    /// read and a delete send back.
    pub stored: String,
    pub issuer: Option<String>,
    pub account: String,
    pub hotp: bool,
    pub sha256: bool,
    /// TOTP period in seconds (30 or 60); 0 for HOTP.
    pub period: u32,
    /// The code read on the last touch.
    pub code: Option<String>,
    /// The TOTP window (unix time / period) `code` is for; `None` for HOTP.
    pub code_window: Option<u64>,
}

impl FtotpRow {
    fn from_credential(c: &fotp::Credential) -> Self {
        let parts = fotp::parse_name(&c.name, c.oath_type);
        let hotp = c.oath_type == fotp::OathType::Hotp;
        FtotpRow {
            slot: c.slot,
            stored: c.name.clone(),
            issuer: parts.issuer.map(str::to_owned),
            account: parts.account.to_owned(),
            hotp,
            sha256: c.algorithm == fotp::Algorithm::Sha256,
            period: if hotp { 0 } else { fotp::totp_period(&c.name) },
            code: None,
            code_window: None,
        }
    }

    /// Display label `issuer:account`, or the account alone.
    pub(crate) fn label(&self) -> String {
        match &self.issuer {
            Some(issuer) => format!("{issuer}:{}", self.account),
            None => self.account.clone(),
        }
    }

    pub(crate) fn type_str(&self) -> &'static str {
        if self.hotp {
            "HOTP"
        } else {
            "TOTP"
        }
    }

    /// The line under the label: kind, algorithm, period, and the slot when
    /// it is one of the keyboard slots.
    fn meta(&self) -> String {
        let mut meta = format!(
            "{}/{}",
            self.type_str(),
            if self.sha256 { "SHA256" } else { "SHA1" }
        );
        if !self.hotp {
            meta.push_str(&format!("  \u{00b7} {}s", self.period));
        }
        if self.slot != fotp::Slot::Default {
            meta.push_str(&format!("  \u{00b7} slot {}", self.slot.label()));
        }
        meta
    }

    /// Drop the shown code, wiping it.
    pub(crate) fn forget_code(&mut self) {
        if let Some(mut code) = self.code.take() {
            wipe(&mut code);
        }
        self.code_window = None;
    }

    /// Whether the shown code is a TOTP code whose time window has ended at
    /// `now`. An HOTP code has no window.
    fn code_expired(&self, now: u64) -> bool {
        self.code.is_some()
            && self
                .code_window
                .is_some_and(|w| w != now / u64::from(self.period.max(1)))
    }
}

// A row replaced by a new listing, or dropped with the pane, takes its code
// with it.
impl Drop for FtotpRow {
    fn drop(&mut self) {
        self.forget_code();
    }
}

/// "Add account" form state.
pub struct FtotpAddDialog {
    pub open: bool,
    pub issuer: String,
    pub account: String,
    /// Base32 secret, entered masked.
    pub secret: String,
    /// True = TOTP, false = HOTP.
    pub totp: bool,
    /// True = SHA256, false = SHA1.
    pub sha256: bool,
    /// 6 or 8.
    pub digits: u8,
    /// 30 or 60 (TOTP only).
    pub period: u32,
}

impl Default for FtotpAddDialog {
    fn default() -> Self {
        FtotpAddDialog {
            open: false,
            issuer: String::new(),
            account: String::new(),
            secret: String::new(),
            totp: true,
            sha256: false,
            digits: 6,
            period: 30,
        }
    }
}

impl TypedSecrets for FtotpAddDialog {
    fn secrets_mut(&mut self) -> Vec<&mut String> {
        let Self {
            open: _,
            issuer: _,
            account: _,
            secret,
            totp: _,
            sha256: _,
            digits: _,
            period: _,
        } = self;
        vec![secret]
    }
}

// Wipe the typed seed on drop (the form is replaced wholesale after an add).
impl Drop for FtotpAddDialog {
    fn drop(&mut self) {
        self.wipe_typed();
    }
}

/// What the add form asks the key to store: checked, with the secret decoded.
struct FtotpNew {
    /// The name as it will be stored (period prefix and separator included).
    stored: String,
    secret: zeroize::Zeroizing<Vec<u8>>,
    oath_type: fotp::OathType,
    algorithm: fotp::Algorithm,
    digits: u8,
}

impl FtotpAddDialog {
    /// Check the form the way `keyroostctl ftotp add` checks its flags,
    /// before anything is sent to the key.
    fn validate(&self) -> Result<FtotpNew, String> {
        let account = self.account.trim();
        if account.is_empty() {
            return Err("account name is required".into());
        }
        let issuer = Some(self.issuer.trim()).filter(|i| !i.is_empty());
        let oath_type = if self.totp {
            fotp::OathType::Totp
        } else {
            fotp::OathType::Hotp
        };
        let stored = fotp::stored_name(issuer, account, oath_type, self.period)
            .map_err(|e| e.to_string())?;
        // The key splits a name at `_#_`: one that would come back as
        // another issuer and account is refused, as the import does.
        let parts = fotp::parse_name(&stored, oath_type);
        if parts.issuer != issuer || parts.account != account {
            // The same words as `keyroostctl ftotp add`, here and below.
            return Err(format!(
                "the name would read back differently on the key: it keeps issuer and \
                 account apart with {}, and this name has that in it",
                fotp::ISSUER_SEPARATOR
            ));
        }
        let limits = keyroost_import::plan::limits(keyroost_import::plan::Store::FeitianOtp);
        if let Some(max) = limits.name_max.filter(|max| stored.len() > *max) {
            return Err(format!(
                "the name is {} bytes as stored ({:?}); keyroost stores names of up to \
                 {max} bytes on this key",
                stored.len(),
                stored
            ));
        }
        let secret = match keyroost_proto::codec::base32_decode(self.secret.trim()) {
            Ok(s) if !s.is_empty() => zeroize::Zeroizing::new(s),
            Ok(_) => return Err("Enter a Base32 secret for this account.".into()),
            Err(e) => return Err(format!("invalid Base32 secret: {e}")),
        };
        if let Some(max) = limits.secret_max.filter(|max| secret.len() > *max) {
            return Err(format!(
                "the secret is {} bytes; keyroost stores secrets of up to {max} bytes on \
                 this key",
                secret.len()
            ));
        }
        if !matches!(self.digits, 6 | 8) {
            return Err("codes on this key have 6 or 8 digits".into());
        }
        Ok(FtotpNew {
            stored,
            secret,
            oath_type,
            algorithm: if self.sha256 {
                fotp::Algorithm::Sha256
            } else {
                fotp::Algorithm::Sha1
            },
            digits: self.digits,
        })
    }
}

/// Per-selection state for the Feitian OTP pane.
#[derive(Default)]
pub struct FtotpState {
    pub rows: Vec<FtotpRow>,
    pub error: Option<String>,
    pub info: Option<String>,
    pub loaded: bool,
    /// The applet's version, from the last read.
    pub version: Option<(u8, u8, u8)>,
    /// What the last listing could not show (see [`partial_note`]).
    pub partial: Option<String>,
    pub add: FtotpAddDialog,
    /// The account a delete is being confirmed for: slot and stored name.
    pub confirm_delete: Option<(fotp::Slot, String)>,
}

impl FtotpState {
    /// Whether any row shows a code.
    pub(crate) fn has_codes(&self) -> bool {
        self.rows.iter().any(|r| r.code.is_some())
    }

    /// Drop every shown code, wiping it.
    pub(crate) fn forget_codes(&mut self) {
        for row in &mut self.rows {
            row.forget_code();
        }
    }

    /// Whether a TOTP code is showing: its countdown needs a repaint.
    pub(crate) fn shows_totp_code(&self) -> bool {
        self.rows.iter().any(|r| !r.hotp && r.code.is_some())
    }
}

impl TypedSecrets for FtotpState {
    fn secrets_mut(&mut self) -> Vec<&mut String> {
        self.add.secrets_mut()
    }
}

/// What a listing leaves out, in one line: entries that are not shown, and
/// keyboard slots that did not answer. `None` when the listing is complete.
fn partial_note(listing: &FeitianOtpListing) -> Option<String> {
    let mut parts = Vec::new();
    if listing.skipped > 0 {
        parts.push(format!(
            "{} entr{} on the key {} not shown (not a TOTP or HOTP account, or not readable).",
            listing.skipped,
            if listing.skipped == 1 { "y" } else { "ies" },
            if listing.skipped == 1 { "is" } else { "are" },
        ));
    }
    for (slot, sw) in &listing.unread {
        parts.push(format!(
            "Slot {} did not answer (status {sw:04X}); any accounts in it are not listed.",
            slot.label()
        ));
    }
    (!parts.is_empty()).then(|| parts.join(" "))
}

/// Result of a successful pane load.
struct FtotpLoad {
    rows: Vec<FtotpRow>,
    version: Option<(u8, u8, u8)>,
    partial: Option<String>,
}

impl App {
    /// A Feitian OTP job's success: shown in the pane and written to the
    /// activity log.
    fn ftotp_done(&mut self, msg: String) {
        self.log(Severity::Ok, msg.trim_end_matches('.').to_string());
        self.ftotp.info = Some(msg);
    }

    /// The list read's failure: shown in the pane, and logged once in the
    /// background, since the read also runs unasked when the tab opens.
    fn ftotp_read_failed(&mut self, err: String) {
        self.log_bg_once(Severity::Err, format!("Feitian OTP: {err}"));
        self.ftotp.error = Some(err);
    }

    /// A Feitian OTP job's failure: shown in the pane and written to the
    /// activity log.
    fn ftotp_failed(&mut self, err: String) {
        self.log(Severity::Err, format!("Feitian OTP: {err}"));
        self.ftotp.error = Some(err);
    }

    /// The selected key's own smart-card reader. `Err` when nothing is
    /// selected or the key has none, so no other key's reader is opened.
    fn ftotp_reader(&self) -> Result<String, String> {
        self.selected_device()
            .ok_or_else(|| "no key selected".to_string())?
            .reader
            .clone()
            .ok_or_else(|| "the selected key has no smart-card reader".to_string())
    }

    /// Read the pane again from scratch. The pane's part of a Refresh.
    pub(crate) fn refresh_ftotp(&mut self) {
        self.load_ftotp_accounts();
    }

    /// List the accounts on the selected key. Needs no touch.
    pub(crate) fn load_ftotp_accounts(&mut self) {
        self.ftotp.error = None;
        let reader = match self.ftotp_reader() {
            Ok(r) => r,
            Err(e) => {
                self.ftotp.error = Some(e);
                self.ftotp.loaded = true; // show the error, not a stuck "Reading…"
                return;
            }
        };
        let for_device = self.selected_device.clone();
        self.spawn_job("Reading Feitian OTP accounts\u{2026}", move || {
            let result = (|| -> Result<FtotpLoad, TransportError> {
                let mut session = FeitianOtpSession::open(&reader)?;
                let version = session.version();
                let listing = session.list()?;
                Ok(FtotpLoad {
                    rows: listing
                        .credentials
                        .iter()
                        .map(FtotpRow::from_credential)
                        .collect(),
                    version,
                    partial: partial_note(&listing),
                })
            })();
            Box::new(move |app: &mut App| {
                if !completion_still_valid(for_device.as_ref(), app.selected_device.as_ref()) {
                    return; // another key was selected mid-read
                }
                match result {
                    Ok(mut load) => {
                        // A code already showing stays with its account; the
                        // rows it leaves behind wipe what they still hold.
                        for row in &mut load.rows {
                            if let Some(old) = app
                                .ftotp
                                .rows
                                .iter_mut()
                                .find(|o| o.slot == row.slot && o.stored == row.stored)
                            {
                                row.code = old.code.take();
                                row.code_window = old.code_window.take();
                            }
                        }
                        app.ftotp.rows = load.rows;
                        app.ftotp.version = load.version;
                        app.ftotp.partial = load.partial;
                        app.ftotp.loaded = true;
                        app.ftotp.error = None;
                    }
                    Err(e) => {
                        app.ftotp_read_failed(e.to_string());
                        app.ftotp.loaded = true;
                    }
                }
            })
        });
    }

    /// Read one account's code. The key computes it once it is touched; an
    /// HOTP read moves the key's counter on.
    pub(crate) fn read_ftotp_code(&mut self, slot: fotp::Slot, stored: String) {
        self.ftotp.error = None;
        self.ftotp.info = None;
        let reader = match self.ftotp_reader() {
            Ok(r) => r,
            Err(e) => {
                self.ftotp.error = Some(e);
                return;
            }
        };
        let Some(row) = self
            .ftotp
            .rows
            .iter()
            .find(|r| r.slot == slot && r.stored == stored)
        else {
            return;
        };
        let hotp = row.hotp;
        let period = row.period.max(1);
        let for_device = self.selected_device.clone();
        self.spawn_job("Reading code \u{2014} touch your key\u{2026}", move || {
            let now = unix_now();
            let result = (|| -> Result<String, TransportError> {
                let mut session = FeitianOtpSession::open(&reader)?;
                let answer = if hotp {
                    session.calculate_hotp(slot, &stored)?
                } else {
                    session.calculate_totp(slot, &stored, now, period)?
                };
                Ok(answer.code)
            })();
            let window = (!hotp).then(|| now / u64::from(period));
            Box::new(move |app: &mut App| {
                if !completion_still_valid(for_device.as_ref(), app.selected_device.as_ref()) {
                    app.log_moved_on(for_device.as_ref(), "reading a Feitian OTP code", &result);
                    return;
                }
                match result {
                    Ok(mut code) => {
                        // The code is for the window the read started in; the
                        // touch may have come after it ended.
                        if window.is_some_and(|w| w != unix_now() / u64::from(period)) {
                            wipe(&mut code);
                            app.ftotp_failed(
                                "that code's time window ended while the key waited for the \
                                 touch; read it again"
                                    .into(),
                            );
                            return;
                        }
                        match app
                            .ftotp
                            .rows
                            .iter_mut()
                            .find(|r| r.slot == slot && r.stored == stored)
                        {
                            Some(row) => {
                                row.forget_code();
                                row.code = Some(code);
                                row.code_window = window;
                            }
                            None => wipe(&mut code),
                        }
                    }
                    Err(e) => app.ftotp_failed(e.to_string()),
                }
            })
        });
    }

    /// Store the account the add form describes, in the default slot. The
    /// form stays open until the key has stored it.
    pub(crate) fn provision_ftotp(&mut self) {
        self.ftotp.error = None;
        self.ftotp.info = None;
        let new = match self.ftotp.add.validate() {
            Ok(n) => n,
            Err(e) => {
                self.ftotp.error = Some(e);
                return;
            }
        };
        let reader = match self.ftotp_reader() {
            Ok(r) => r,
            Err(e) => {
                self.ftotp.error = Some(e);
                return;
            }
        };
        let for_device = self.selected_device.clone();
        self.spawn_job(
            "Adding account \u{2014} touch your key\u{2026}",
            move || {
                let result = (|| -> Result<(), String> {
                    let mut session =
                        FeitianOtpSession::open(&reader).map_err(|e| e.to_string())?;
                    // What the key does with a second account of the same name
                    // is not known, so one is never sent.
                    let listing = session.list().map_err(|e| e.to_string())?;
                    if listing
                        .credentials
                        .iter()
                        .any(|c| c.slot == fotp::Slot::Default && c.name == new.stored)
                    {
                        return Err(format!(
                            "an account named {:?} is already on the key; nothing was added \
                             (delete it first to replace it)",
                            new.stored
                        ));
                    }
                    session
                        .put(&fotp::PutParams {
                            slot: fotp::Slot::Default,
                            name: &new.stored,
                            secret: &new.secret,
                            oath_type: new.oath_type,
                            algorithm: new.algorithm,
                            digits: new.digits,
                        })
                        .map_err(|e| e.to_string())
                })();
                Box::new(move |app: &mut App| {
                    if !completion_still_valid(for_device.as_ref(), app.selected_device.as_ref()) {
                        app.log_moved_on(
                            for_device.as_ref(),
                            "adding a Feitian OTP account",
                            &result,
                        );
                        return;
                    }
                    match result {
                        Ok(()) => {
                            app.ftotp.add = FtotpAddDialog::default();
                            app.ftotp_done("Account added.".into());
                            app.load_ftotp_accounts();
                        }
                        Err(e) => app.ftotp_failed(e),
                    }
                })
            },
        );
    }

    /// Delete one account. The key deletes it once it is touched.
    pub(crate) fn delete_ftotp_account(&mut self, slot: fotp::Slot, stored: String) {
        self.ftotp.error = None;
        self.ftotp.info = None;
        let reader = match self.ftotp_reader() {
            Ok(r) => r,
            Err(e) => {
                self.ftotp.error = Some(e);
                return;
            }
        };
        let for_device = self.selected_device.clone();
        self.spawn_job(
            "Deleting account \u{2014} touch your key\u{2026}",
            move || {
                let result = (|| -> Result<(), String> {
                    let mut session =
                        FeitianOtpSession::open(&reader).map_err(|e| e.to_string())?;
                    // A name the key no longer holds is refused before anything
                    // is sent, as `keyroostctl ftotp delete` does.
                    let listing = session.list().map_err(|e| e.to_string())?;
                    if !listing
                        .credentials
                        .iter()
                        .any(|c| c.slot == slot && c.name == stored)
                    {
                        return Err(format!(
                            "no Feitian OTP account named {stored:?} on this key; nothing was \
                             deleted"
                        ));
                    }
                    session.delete(slot, &stored).map_err(|e| e.to_string())
                })();
                Box::new(move |app: &mut App| {
                    if !completion_still_valid(for_device.as_ref(), app.selected_device.as_ref()) {
                        app.log_moved_on(
                            for_device.as_ref(),
                            "deleting a Feitian OTP account",
                            &result,
                        );
                        return;
                    }
                    match result {
                        Ok(()) => app.ftotp_done("Account deleted.".into()),
                        Err(e) => app.ftotp_failed(e),
                    }
                    // Either way the list is read again: it shows what the key
                    // holds now.
                    app.load_ftotp_accounts();
                })
            },
        );
    }

    /// Drop TOTP codes whose time window has ended.
    fn ftotp_expire_codes(&mut self) {
        let now = unix_now();
        for row in &mut self.ftotp.rows {
            if row.code_expired(now) {
                row.forget_code();
            }
        }
    }

    pub(crate) fn cap_ftotp(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let waiting = self.waiting_for().map(str::to_owned);
        // Auto-read once per selection (a hard error won't auto-retry).
        if !self.ftotp_tried && !self.busy() && self.ftotp.error.is_none() {
            self.ftotp_tried = true;
            self.load_ftotp_accounts();
        }
        self.ftotp_expire_codes();

        // The button moves to a line of its own under the title when the
        // window is too narrow for both.
        self.adaptive_row(
            ui,
            |app, ui| {
                ui.label(
                    egui::RichText::new("Feitian OTP")
                        .font(theme::f_sb(14.5))
                        .color(p.txt),
                );
                ui.add_space(6.0);
                app.help_dot(ui, p, "ftotp");
            },
            |app, ui| {
                if theme::button(ui, p, BtnKind::Primary, "+ Add account").clicked() {
                    // FtotpAddDialog has a Drop impl (wipes the typed seed),
                    // so `..Default` struct-update isn't allowed.
                    let mut dlg = FtotpAddDialog::default();
                    dlg.open = true;
                    app.ftotp.add = dlg;
                    // A reopened form starts masked, whatever a reveal
                    // toggle was left at.
                    app.secret_reveal.insert("ftotp-add-secret", false);
                }
            },
        );
        if let Some((a, b, c)) = self.ftotp.version {
            ui.label(
                egui::RichText::new(format!("applet {a}.{b}.{c}"))
                    .font(theme::f_reg(11.5))
                    .color(p.txt3),
            );
        }
        ui.add_space(12.0);

        if let Some(info) = &self.ftotp.info {
            ui.colored_label(p.ok, info);
            ui.add_space(6.0);
        }
        if let Some(err) = &self.ftotp.error {
            ui.colored_label(p.err, err);
            ui.add_space(6.0);
        }

        self.render_ftotp_add_form(ui, p);
        self.render_ftotp_delete_confirm(ui, p);

        if !self.ftotp.loaded {
            ui.label(
                egui::RichText::new("Reading accounts\u{2026}")
                    .font(theme::f_reg(13.0))
                    .color(p.txt3),
            );
            return;
        }
        if let Some(note) = &self.ftotp.partial {
            ui.colored_label(p.warn, note);
            ui.add_space(6.0);
        }
        if self.ftotp.rows.is_empty() {
            if self.ftotp.error.is_none() {
                ui.label(
                    egui::RichText::new("No OTP accounts on this key.")
                        .font(theme::f_reg(13.0))
                        .color(p.txt3),
                );
            }
            return;
        }

        let mut copy: Option<String> = None;
        let mut delete: Option<(fotp::Slot, String)> = None;
        let mut read: Option<(fotp::Slot, String)> = None;
        theme::card_frame(p).show(ui, |ui| {
            let n = self.ftotp.rows.len();
            for (i, row) in self.ftotp.rows.iter().enumerate() {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(
                            egui::RichText::new(row.label())
                                .font(theme::f_sb(13.5))
                                .color(p.txt),
                        );
                        ui.label(
                            egui::RichText::new(row.meta())
                                .font(theme::f_reg(11.0))
                                .color(p.txt3),
                        );
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if theme::button(ui, p, BtnKind::Default, "Delete").clicked() {
                            delete = Some((row.slot, row.stored.clone()));
                        }
                        ui.add_space(8.0);
                        match &row.code {
                            Some(code) => {
                                // An HOTP code is used once: offer the next.
                                if row.hotp
                                    && theme::key_button(
                                        ui,
                                        p,
                                        BtnKind::Default,
                                        "Next code",
                                        waiting.as_deref(),
                                    )
                                    .on_hover_text("Touch the key to read the next code")
                                    .clicked()
                                {
                                    read = Some((row.slot, row.stored.clone()));
                                }
                                if theme::button(ui, p, BtnKind::Default, "Copy").clicked() {
                                    copy = Some(code.clone());
                                }
                                ui.add_space(8.0);
                                // A TOTP code shows the same countdown ring
                                // and seconds as the other code panes.
                                let totp = (!row.hotp)
                                    .then(|| theme::totp_window(u64::from(row.period.max(1))));
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
                                if theme::key_button(
                                    ui,
                                    p,
                                    BtnKind::Default,
                                    "Read code",
                                    waiting.as_deref(),
                                )
                                .on_hover_text("Touch the key to read this code")
                                .clicked()
                                {
                                    read = Some((row.slot, row.stored.clone()));
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

        if let Some(code) = copy {
            self.copy_secret(ui.ctx(), code);
        }
        if let Some(target) = delete {
            self.ftotp.confirm_delete = Some(target);
        }
        if let Some((slot, stored)) = read {
            self.read_ftotp_code(slot, stored);
        }
    }

    /// The add-account form, shown inline when `add.open`.
    fn render_ftotp_add_form(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let waiting = self.waiting_for().map(str::to_owned);
        if !self.ftotp.add.open {
            return;
        }
        let mut submit = false;
        let mut cancel = false;
        theme::card_frame(p).show(ui, |ui| {
            ui.label(
                egui::RichText::new("Add OTP account")
                    .font(theme::f_sb(13.5))
                    .color(p.txt),
            );
            ui.add_space(8.0);
            egui::Grid::new("ftotp_add_grid")
                .num_columns(2)
                .spacing([10.0, 8.0])
                .show(ui, |ui| {
                    // A narrow window must not break a label mid-word; the
                    // fields take the squeeze instead.
                    ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Extend);
                    ui.label("Issuer");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.ftotp.add.issuer)
                            .margin(theme::TEXT_EDIT_MARGIN),
                    );
                    ui.end_row();

                    ui.label("Account");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.ftotp.add.account)
                            .margin(theme::TEXT_EDIT_MARGIN),
                    );
                    ui.end_row();

                    ui.label("Secret (Base32)");
                    {
                        let mut rev = self
                            .secret_reveal
                            .get("ftotp-add-secret")
                            .copied()
                            .unwrap_or(false);
                        // Narrower in a narrow window (the eye button takes
                        // ~34 px), so the field stays inside the card.
                        let w = (ui.available_width() - 34.0).clamp(80.0, 260.0);
                        crate::secret_edit(ui, p, &mut self.ftotp.add.secret, &mut rev, "", w);
                        self.secret_reveal.insert("ftotp-add-secret", rev);
                    }
                    ui.end_row();

                    ui.label("Type");
                    ui.horizontal(|ui| {
                        ui.selectable_value(&mut self.ftotp.add.totp, true, "TOTP");
                        ui.selectable_value(&mut self.ftotp.add.totp, false, "HOTP");
                    });
                    ui.end_row();

                    ui.label("Algorithm");
                    ui.horizontal(|ui| {
                        ui.selectable_value(&mut self.ftotp.add.sha256, false, "SHA1");
                        ui.selectable_value(&mut self.ftotp.add.sha256, true, "SHA256");
                    });
                    ui.end_row();

                    ui.label("Digits");
                    ui.horizontal(|ui| {
                        ui.selectable_value(&mut self.ftotp.add.digits, 6, "6");
                        ui.selectable_value(&mut self.ftotp.add.digits, 8, "8");
                    });
                    ui.end_row();

                    if self.ftotp.add.totp {
                        ui.label("Period");
                        ui.horizontal(|ui| {
                            ui.selectable_value(&mut self.ftotp.add.period, 30, "30 s");
                            ui.selectable_value(&mut self.ftotp.add.period, 60, "60 s");
                        });
                        ui.end_row();
                    }
                });
            ui.add_space(6.0);
            ui.label(
                egui::RichText::new("The key saves the account once you touch it.")
                    .font(theme::f_reg(11.5))
                    .color(p.txt3),
            );
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if theme::key_button(ui, p, BtnKind::Primary, "Add", waiting.as_deref()).clicked() {
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
            self.provision_ftotp();
        } else if cancel {
            self.ftotp.add = FtotpAddDialog::default();
        }
    }

    /// The delete confirmation, shown inline while one is pending.
    fn render_ftotp_delete_confirm(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let waiting = self.waiting_for().map(str::to_owned);
        let Some((slot, stored)) = self.ftotp.confirm_delete.clone() else {
            return;
        };
        // Named as its row shows it; the stored name if the row is gone.
        let label = self
            .ftotp
            .rows
            .iter()
            .find(|r| r.slot == slot && r.stored == stored)
            .map_or_else(|| stored.clone(), FtotpRow::label);
        let mut confirm = false;
        let mut cancel = false;
        theme::card_frame(p).show(ui, |ui| {
            ui.colored_label(p.err, format!("Delete OTP account \"{label}\"?"));
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(
                    "This cannot be undone. After you confirm, touch the key: it deletes \
                     the account once it is touched.",
                )
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
        ui.add_space(10.0);
        if confirm {
            // Refused while a job runs, before the confirmation is taken: it
            // stays for the next try.
            if self.refuse_if_busy() {
                return;
            }
            self.ftotp.confirm_delete = None;
            self.delete_ftotp_account(slot, stored);
        } else if cancel {
            self.ftotp.confirm_delete = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cred(name: &str, oath_type: fotp::OathType, algorithm: fotp::Algorithm) -> fotp::Credential {
        fotp::Credential {
            slot: fotp::Slot::Default,
            name: name.into(),
            oath_type,
            algorithm,
        }
    }

    fn form(issuer: &str, account: &str, secret: &str) -> FtotpAddDialog {
        let mut d = FtotpAddDialog::default();
        d.issuer = issuer.into();
        d.account = account.into();
        d.secret = secret.into();
        d
    }

    #[test]
    fn a_row_reads_period_issuer_and_account_from_the_stored_name() {
        let row = FtotpRow::from_credential(&cred(
            "60:Example_#_alice",
            fotp::OathType::Totp,
            fotp::Algorithm::Sha256,
        ));
        assert_eq!(row.label(), "Example:alice");
        assert_eq!(row.stored, "60:Example_#_alice");
        assert_eq!((row.hotp, row.sha256, row.period), (false, true, 60));
        assert_eq!(row.meta(), "TOTP/SHA256  \u{00b7} 60s");

        // HOTP names carry no period prefix; no issuer shows the account alone.
        let row =
            FtotpRow::from_credential(&cred("alice", fotp::OathType::Hotp, fotp::Algorithm::Sha1));
        assert_eq!(row.label(), "alice");
        assert_eq!((row.hotp, row.period), (true, 0));
        assert_eq!(row.meta(), "HOTP/SHA1");
    }

    #[test]
    fn a_keyboard_slot_row_says_its_slot() {
        let mut c = cred("30:a", fotp::OathType::Totp, fotp::Algorithm::Sha1);
        c.slot = fotp::Slot::Keyboard2;
        assert_eq!(
            FtotpRow::from_credential(&c).meta(),
            "TOTP/SHA1  \u{00b7} 30s  \u{00b7} slot 2"
        );
    }

    #[test]
    fn a_totp_code_expires_with_its_window_and_an_hotp_code_does_not() {
        let mut totp =
            FtotpRow::from_credential(&cred("30:a", fotp::OathType::Totp, fotp::Algorithm::Sha1));
        assert!(!totp.code_expired(1_000), "no code, nothing to expire");
        totp.code = Some("123456".into());
        totp.code_window = Some(1_000 / 30);
        assert!(!totp.code_expired(1_000));
        assert!(!totp.code_expired(1_019), "last second of the window");
        assert!(totp.code_expired(1_020), "the next window");

        let mut hotp =
            FtotpRow::from_credential(&cred("a", fotp::OathType::Hotp, fotp::Algorithm::Sha1));
        hotp.code = Some("123456".into());
        assert!(!hotp.code_expired(u64::MAX));
    }

    #[test]
    fn forgetting_codes_clears_every_row() {
        let mut state = FtotpState::default();
        for name in ["30:a", "30:b"] {
            let mut row =
                FtotpRow::from_credential(&cred(name, fotp::OathType::Totp, fotp::Algorithm::Sha1));
            row.code = Some("123456".into());
            row.code_window = Some(1);
            state.rows.push(row);
        }
        assert!(state.has_codes() && state.shows_totp_code());
        state.forget_codes();
        assert!(!state.has_codes() && !state.shows_totp_code());
        assert!(state.rows.iter().all(|r| r.code_window.is_none()));
    }

    #[test]
    fn the_add_form_builds_the_stored_name_and_decodes_the_secret() {
        let mut d = form(" Example ", " alice ", "JBSWY3DPEHPK3PXP");
        d.period = 60;
        d.sha256 = true;
        d.digits = 8;
        let new = d.validate().unwrap();
        assert_eq!(new.stored, "60:Example_#_alice");
        assert_eq!(new.secret.as_slice(), b"Hello!\xDE\xAD\xBE\xEF");
        assert_eq!(new.oath_type, fotp::OathType::Totp);
        assert_eq!(new.algorithm, fotp::Algorithm::Sha256);
        assert_eq!(new.digits, 8);

        // HOTP: no period prefix; no issuer: the account alone.
        let mut d = form("", "alice", "JBSWY3DPEHPK3PXP");
        d.totp = false;
        assert_eq!(d.validate().unwrap().stored, "alice");
    }

    #[test]
    fn the_add_form_refuses_what_the_key_would_not_read_back() {
        let err = |d: &FtotpAddDialog| d.validate().err().unwrap();
        assert_eq!(
            err(&form("x", "  ", "JBSWY3DPEHPK3PXP")),
            "account name is required"
        );
        // The separator inside a name would split it differently.
        assert!(err(&form("a_#_b", "c", "JBSWY3DPEHPK3PXP")).contains("_#_"));
        assert!(err(&form("", "a_#_b", "JBSWY3DPEHPK3PXP")).contains("_#_"));
        assert_eq!(
            err(&form("x", "alice", "  ")),
            "Enter a Base32 secret for this account."
        );
        assert!(err(&form("x", "alice", "not base32!")).starts_with("invalid Base32 secret"));
        // Past the stored-name limit (64 bytes, prefix and separator included).
        assert!(err(&form("x", &"a".repeat(64), "JBSWY3DPEHPK3PXP")).contains("64 bytes"));
        let mut d = form("x", "alice", "JBSWY3DPEHPK3PXP");
        d.digits = 7;
        assert_eq!(err(&d), "codes on this key have 6 or 8 digits");
    }

    #[test]
    fn a_partial_listing_says_what_is_missing() {
        let mut listing = FeitianOtpListing {
            credentials: Vec::new(),
            skipped: 0,
            unread: Vec::new(),
            legacy: false,
        };
        assert_eq!(partial_note(&listing), None);
        listing.skipped = 1;
        listing.unread.push((fotp::Slot::Keyboard1, 0x6982));
        assert_eq!(
            partial_note(&listing).as_deref(),
            Some(
                "1 entry on the key is not shown (not a TOTP or HOTP account, or not \
                 readable). Slot 1 did not answer (status 6982); any accounts in it are not \
                 listed."
            )
        );
    }

    /// A job's outcome shows in the pane and in the activity log; a failure
    /// is logged as one.
    #[test]
    fn ftotp_results_are_logged() {
        let mut app = App::default();
        app.ftotp_done("Account deleted.".into());
        assert_eq!(app.ftotp.info.as_deref(), Some("Account deleted."));
        app.ftotp_failed("the key was not touched".into());
        assert_eq!(app.ftotp.error.as_deref(), Some("the key was not touched"));
        let texts: Vec<(&str, bool)> = app
            .log
            .iter()
            .map(|l| (l.text.as_str(), matches!(l.severity, Severity::Err)))
            .collect();
        assert_eq!(
            texts,
            vec![
                ("Account deleted", false),
                ("Feitian OTP: the key was not touched", true)
            ]
        );
    }

    /// With no key selected nothing is opened: the pane shows why.
    #[test]
    fn nothing_is_read_without_a_selected_key() {
        let mut app = App::default();
        app.load_ftotp_accounts();
        assert_eq!(app.ftotp.error.as_deref(), Some("no key selected"));
        assert!(app.ftotp.loaded, "the error shows, not a stuck read");
    }
}
