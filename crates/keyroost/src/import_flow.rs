//! Importing authenticator codes from a file: every dropped or picked file
//! waits its turn in a queue, is read and identified on the import thread,
//! and then opens either the "Import authenticator codes" dialog (an
//! authenticator export) or a short notice (key material, or a file keyroost
//! can't read). Nothing is written to a key from here without the person
//! clicking the dialog's Add button, which names the destination.
//!
//! The state logic (queue, destinations, preselection, the reason the Add
//! button is disabled, every close route) is pure and tested below; the
//! `impl App` block at the end wires it to the frame loop, the import thread
//! and the device worker, the same way `otp_pane` extends `App`.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use eframe::egui;
use keyroost_import::{Format, HashAlg, ImportFile, OtpKind};

use crate::ui::device::{Caps, Device, DeviceId};
use crate::ui::theme::{self, BtnKind, Palette};
use crate::{guard_secret_field, wipe, App};

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// Dropped on the window: no view asked for it.
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
    /// thread can never land in a dialog opened after it was started.
    next_id: u64,
}

impl Drop for ImportFlow {
    fn drop(&mut self) {
        if let Some(d) = self.dialog.as_mut() {
            d.close();
        }
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

/// The export's layout, as the dialog's file line names it.
pub fn format_name(f: Format) -> &'static str {
    match f {
        Format::Aegis => "Aegis",
        Format::AegisEncrypted => "Aegis (encrypted)",
        Format::TwoFas => "2FAS",
        Format::OtpauthList => "otpauth:// list",
        Format::QrImage => "QR screenshot",
        Format::GoogleExport => "Google Authenticator export",
    }
}

/// "SHA-1", "SHA-256", "SHA-512".
fn hash_name(h: HashAlg) -> &'static str {
    match h {
        HashAlg::Sha1 => "SHA-1",
        HashAlg::Sha256 => "SHA-256",
        HashAlg::Sha512 => "SHA-512",
    }
}

/// One entry row: `label · TOTP 30 s · SHA-1 · 6 digits` (or `· HOTP ·`),
/// or `label — reason` for an entry no key can take.
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
                    hash_name(e.hash),
                    e.digits
                ),
                true,
            )
        }
        Err(u) => (format!("{} \u{2014} {}", item.label, u), false),
    }
}

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
    /// Parsed entries; dropping them wipes the seeds.
    pub file: Option<ImportFile>,
    pub needs_password: bool,
    /// Wiped on every close route.
    pub file_password: String,
    pub error: Option<String>,
    pub origin: Option<Origin>,
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
        d.origin = Some(origin);
        d
    }

    /// Settle the open state after the window was drawn this frame:
    /// `window_open` is the copy egui's `[X]` wrote to, `close_clicked` the
    /// in-window Close. A button never writes `open` inside the window
    /// closure; the write-back of the stale copy would undo it (#171).
    pub fn settle_open(&mut self, window_open: bool, close_clicked: bool) {
        if self.open && !(window_open && !close_clicked) {
            self.close();
        }
    }

    /// Close by any route: wipe the typed password and drop the entries.
    pub fn close(&mut self) {
        self.open = false;
        wipe(&mut self.file_password);
        self.file = None;
    }
}

/// Shown when no connected key can store authenticator codes.
pub const NO_CAPABLE_KEY: &str = "Connect a key that can store authenticator codes \
     (for example a YubiKey, Solo 2, Nitrokey 3, Token2 key or Molto2).";

/// Ids of the dialog's masked fields, for scrubbing egui's undo history.
pub const FILE_PASSWORD_ID: &str = "import-file-password";

/// What the import thread read from a file.
enum Read {
    Opened(keyroost_qr::file::Opened),
    Failed(String),
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
        self.run_import(label, move || {
            let read = match keyroost_qr::file::open_path(
                &path,
                password.as_deref().map(|p| p.as_bytes()),
            ) {
                Ok(o) => Read::Opened(o),
                Err(e) => Read::Failed(e.to_string()),
            };
            drop(password);
            Box::new(move |app: &mut App| app.import_apply_read(id, path, name, origin, read))
        });
    }

    /// Apply what the import thread read.
    fn import_apply_read(
        &mut self,
        id: u64,
        path: PathBuf,
        name: String,
        origin: Origin,
        read: Read,
    ) {
        use keyroost_qr::file::Opened;
        // A retry with a password lands in the dialog that asked for it.
        if let Some(d) = self.import_flow.dialog.as_mut() {
            if d.id != id {
                return;
            }
            match read {
                Read::Opened(Opened::Entries(file)) => {
                    wipe(&mut d.file_password);
                    d.needs_password = false;
                    d.error = None;
                    d.format = Some(file.format);
                    d.file = Some(file);
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
        match read {
            Read::Opened(Opened::Entries(file)) => {
                dialog.format = Some(file.format);
                dialog.file = Some(file);
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
        let importing = self.import_busy();
        let import_label = self.import_label.clone();
        let no_capable_key = destinations(&self.devices).is_empty();
        let Some(d) = self.import_flow.dialog.as_mut() else {
            return;
        };
        let mut open = d.open;
        let mut close_clicked = false;
        let mut do_open = false;
        egui::Window::new("Import authenticator codes")
            .open(&mut open)
            .collapsible(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .default_width(560.0)
            .show(ctx, |ui| {
                ui.label(egui::RichText::new(file_line(d)).color(p.txt));
                if d.needs_password {
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
                        if ui
                            .add_enabled(
                                !importing && !d.file_password.is_empty(),
                                egui::Button::new("Open"),
                            )
                            .clicked()
                            || (enter && !importing && !d.file_password.is_empty())
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
                if let Some(file) = &d.file {
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
                if no_capable_key {
                    ui.add_space(6.0);
                    ui.colored_label(p.warn, NO_CAPABLE_KEY);
                }
                ui.add_space(10.0);
                if ui.button("Close").clicked() {
                    close_clicked = true;
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
        d.settle_open(open, close_clicked);
        if !d.open {
            self.import_flow.dialog = None;
            crate::clear_edit_undo(ctx, egui::Id::new(FILE_PASSWORD_ID));
            return;
        }
        if do_open {
            let (id, path, name) = (d.id, d.path.clone(), d.file_name.clone());
            let origin = d.origin.clone().unwrap_or(Origin::Dropped);
            let pw = zeroize::Zeroizing::new(d.file_password.clone());
            d.error = None;
            self.import_read(id, path, name, origin, Some(pw));
        }
    }
}

/// `vault.json — Aegis (encrypted) · 12 entries`.
pub fn file_line(d: &ImportDialog) -> String {
    let mut s = d.file_name.clone();
    if let Some(f) = d.format {
        s.push_str(" \u{2014} ");
        s.push_str(format_name(f));
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
    use crate::ui::device::DeviceKind;

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
        }
    }

    fn dk(id: &str, store: StoreKind) -> DestKey {
        DestKey {
            device: id.into(),
            store,
        }
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
}
