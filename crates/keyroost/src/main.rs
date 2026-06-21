//! keyroost — desktop GUI for programming Token2 Molto2 / Molto2v2 tokens.
//!
//! Dark-themed by default, modeled loosely on Token2's PyQt5 layout: device
//! status across the top, 100-slot grid on the left, edit form on the right.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::time::{SystemTime, UNIX_EPOCH};

mod otp_pane;
#[cfg(feature = "qr")]
mod qrscan;
mod settings;
mod ui;
use otp_pane::OtpState;
use settings::Settings;
use ui::device::{self, CapTab, Caps, Device, DeviceId, DeviceKind, DeviceView};
use ui::theme::{self, BtnKind, Mode, Palette};

use eframe::egui;
use keyroost_import::parse_otpauth;
use keyroost_proto::commands::{
    DisplayTimeout, HmacAlgo, OtpDigits, ProfileConfig, TimeStep, DEFAULT_CUSTOMER_KEY,
};
use keyroost_transport::{DeviceInfo, Session, TransportError};
use keyroost_transport::Token2ProgSession;

use keyroost_ctap::client_pin::PinUvAuthToken;
use keyroost_ctap::cred_mgmt::{Credential, CredsMetadata, RelyingParty};
use keyroost_ctap::{AuthenticatorInfo, CtapHidDevice, InitResponse};

/// How the selected FIDO key is reached: over USB-HID (a `hidraw` path) or over
/// a PC/SC reader (NFC or contact, by reader name).
#[derive(Debug, Clone)]
enum FidoTarget {
    Hid(std::path::PathBuf),
    Pcsc(String),
}

/// The successful result of [`open_fido`]: the boxed CTAP transport, whether it
/// speaks CTAP2 (CBOR), and the HID `InitResponse` (HID only; `None` over PC/SC).
/// Aliased so the `open_fido` signature isn't `clippy::type_complexity`-complex.
type OpenFido = (
    Box<dyn keyroost_ctap::transport::CtapTransport>,
    bool,
    Option<InitResponse>,
);

/// Open a CTAP transport for `target`, returning the boxed transport, whether
/// it speaks CTAP2 (CBOR), and the HID `InitResponse` when available (HID only;
/// `None` over PC/SC, which has no INIT phase). The InitResponse carries the
/// firmware version shown on the hero for USB keys.
fn open_fido(target: &FidoTarget) -> Result<OpenFido, String> {
    match target {
        FidoTarget::Hid(path) => {
            let (dev, init) = CtapHidDevice::open(path).map_err(|e| e.to_string())?;
            let cbor = init.supports_cbor();
            Ok((Box::new(dev), cbor, Some(init)))
        }
        FidoTarget::Pcsc(reader) => {
            let dev =
                keyroost_transport::CtapPcscDevice::open(reader).map_err(|e| e.to_string())?;
            // After a successful FIDO applet SELECT we attempt CTAP2 regardless of
            // the exact version string (keys answer U2F_V2, FIDO_2_0, FIDO_2_1,
            // sometimes with trailing bytes). A genuinely U2F-only card will make
            // get_info return a clean CTAP error, which the caller surfaces —
            // rather than silently reporting "no CBOR" and leaving the UI idle.
            Ok((Box::new(dev), true, None))
        }
    }
}
use keyroost_hid::HidDevice;

const PROFILES: u8 = 100;

/// Error from an unlocked-session FIDO operation, carrying both a
/// human-readable message and whether it was a PIN / PIN-auth failure that
/// invalidated the session. Worker closures produce this so their completion
/// closures can decide (via [`App::fail_session_op`]) whether to auto-lock.
struct SessionOpError {
    message: String,
    relock: bool,
}

impl SessionOpError {
    /// A non-PIN failure (HID open, U2F-only device, etc.): never re-locks.
    fn msg(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            relock: false,
        }
    }

    /// Classify a CTAP error: PIN / PIN-auth codes (`0x31` / `0x33` / `0x34`)
    /// mark the session as invalidated so the caller re-locks.
    fn from_ctap(err: keyroost_ctap::CtapError) -> Self {
        Self {
            relock: err.is_pin_auth_error(),
            message: err.to_string(),
        }
    }

    /// Classify a boxed error from an op path that returns `Box<dyn Error>`
    /// (e.g. passkey delete/refresh). Downcasts to [`CtapError`] to recover the
    /// status byte; non-CTAP errors never re-lock.
    fn from_boxed(err: Box<dyn std::error::Error>) -> Self {
        match err.downcast::<keyroost_ctap::CtapError>() {
            Ok(ctap) => Self::from_ctap(*ctap),
            Err(other) => Self::msg(other.to_string()),
        }
    }
}

impl std::fmt::Display for SessionOpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

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
    /// Enrolled fingerprints, cached after a list. `None` until first read.
    fingerprints: Option<Vec<keyroost_ctap::Enrollment>>,
    /// Friendly-name buffer for the "enroll new fingerprint" field.
    fp_new_name: String,
    /// Shared live enroll progress, written by the worker after each captured
    /// sample and polled by the UI each frame to drive the wizard view.
    fp_progress: Option<std::sync::Arc<std::sync::Mutex<EnrollProgress>>>,
    /// Pending delete confirmation: the template id awaiting "Are you sure?".
    fp_confirm_delete: Option<Vec<u8>>,
    /// Inline rename editor: (template_id, new-name buffer).
    fp_rename: Option<(Vec<u8>, String)>,
    /// Pending advanced-config action awaiting typed confirmation + PIN.
    advanced: Option<AdvancedDialog>,
    /// Which sub-view of the FIDO2 tab is active (passkeys / fingerprints /
    /// settings), so the sections no longer stack in one long panel.
    subview: FidoSubview,
    /// Cached large-blob array, read on demand. `None` until first load.
    large_blobs: Option<keyroost_ctap::large_blobs::LargeBlobArray>,
    /// Index of the entry currently expanded in the hex/ASCII viewer.
    lb_selected: Option<usize>,
    /// Pending "delete entry N" confirmation in the structured editor.
    lb_confirm_delete: Option<usize>,
    /// Pending "clear all storage" confirmation. Set by the first click on the
    /// destructive clear control; the confirmed click wipes every entry.
    lb_confirm_clear: bool,
    /// Status / result line for the last large-blob load or write.
    lb_status: Option<String>,
    /// Text buffer for the "add a note" field.
    lb_new_text: String,
    /// Whether the add-note composer is expanded (toggled by the Add button).
    lb_show_add: bool,
    /// Index of the note currently being edited inline, with its edit buffer.
    lb_editing: Option<usize>,
    lb_edit_text: String,
    /// Set once we've auto-loaded (or tried to) on first showing the Storage
    /// tab, so a failed read doesn't retry every frame. Reset when the selected
    /// device changes so a different key loads fresh.
    lb_autoloaded: bool,
}

#[derive(Default, Clone, Copy, PartialEq)]
enum FidoSubview {
    #[default]
    Passkeys,
    Fingerprints,
    Settings,
    LargeBlobs,
}

/// A pending `authenticatorConfig` action in the Advanced view. The action is
/// only dispatched once the user supplies the PIN (these commands need a token
/// with the AuthenticatorConfiguration permission) and, for irreversible ones,
/// confirms explicitly.
#[derive(Default)]
struct AdvancedDialog {
    action: AdvancedAction,
    /// PIN entry for this action (config needs its own permissioned token).
    pin_input: String,
    /// New minimum PIN length buffer (only for SetMinPin).
    min_pin_input: String,
    /// Whether to also force a PIN change (SetMinPin option).
    force_change: bool,
}

#[derive(Default, Clone, Copy, PartialEq)]
enum AdvancedAction {
    #[default]
    None,
    ToggleAlwaysUv,
    SetMinPin,
    ForcePinChange,
    EnterpriseAttestation,
}

/// Live state of an in-progress fingerprint enrollment, shared between the
/// capture worker and the UI so the wizard can show per-sample progress.
#[derive(Clone)]
struct EnrollProgress {
    /// Total samples the sensor wants (from getFingerprintSensorInfo / begin).
    total: u64,
    /// Samples captured successfully so far.
    captured: u64,
    /// Human-readable status of the most recent sample (quality hint).
    last_message: String,
    /// Set when the flow finishes (Ok) or fails (Err message).
    done: Option<Result<(), String>>,
    /// Set by the UI's Cancel button; the worker checks it between samples,
    /// asks the device to cancel the current enrollment, and stops.
    cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Default for EnrollProgress {
    fn default() -> Self {
        EnrollProgress {
            total: 0,
            captured: 0,
            last_message: "Touch the sensor to begin\u{2026}".into(),
            done: None,
            cancel: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }
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
    /// Enrolled fingerprints read at unlock (when the key supports bio), so the
    /// list shows immediately. `None` when bio is unsupported or the read failed.
    fingerprints: Option<Vec<keyroost_ctap::Enrollment>>,
    /// PIN retained for the unlocked session (wiped on lock). Bio writes
    /// (enroll/rename/delete) re-derive a fresh pinUvAuthToken per operation —
    /// the authenticator can invalidate a token after a UV-gated bio write, so
    /// reusing one across operations fails with PIN_AUTH_INVALID (0x33).
    pin: zeroize::Zeroizing<String>,
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

/// "Add credential" modal state for the OATH pane. Open iff `open` is true; the
/// name + base32 **secret** + type/touch fields render *inside* the centered
/// `modal_window` (not inline in the pane) so the secret entry and its result
/// stay on-screen, mirroring the PIV/OpenPGP credential modals (issue #31).
/// `busy` shows the spinner while `provision_oath`'s job is in flight; `result`
/// is `None` until it completes, then `Ok(())` on success or `Err(message)` on
/// failure — both shown in the modal.
#[derive(Default)]
struct OathAddDialog {
    open: bool,
    name: String,
    /// Base32 secret (entered masked).
    secret: String,
    /// True = TOTP, false = HOTP.
    totp: bool,
    require_touch: bool,
    /// True while the provision op is in flight (spinner + Submit disabled).
    busy: bool,
    /// Outcome of the last provision op, shown in the modal.
    result: Option<Result<(), String>>,
}

impl OathAddDialog {
    /// A freshly-opened dialog: empty fields, TOTP default, no in-flight op.
    /// (No `..Default::default()` — the `Drop` impl forbids struct-update.)
    fn opened() -> Self {
        OathAddDialog {
            open: true,
            name: String::new(),
            secret: String::new(),
            totp: true,
            require_touch: false,
            busy: false,
            result: None,
        }
    }

    /// Client-side validation of the entered fields, mirroring the guards in
    /// `provision_oath` so the modal can reject bad input before dispatching.
    /// Returns the trimmed name + decoded secret on success, or an error message.
    fn validate(&self) -> Result<(String, Vec<u8>), String> {
        let name = self.name.trim().to_owned();
        if name.is_empty() {
            return Err("credential name is required".into());
        }
        match keyroost_proto::codec::base32_decode(self.secret.trim()) {
            Ok(s) if !s.is_empty() => Ok((name, s)),
            Ok(_) => Err("secret is empty".into()),
            Err(e) => Err(format!("invalid base32 secret: {e}")),
        }
    }
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
    /// The key (Signature / Decryption / Authentication) whose sub-tab is open.
    /// Every per-key action — generate on-card, import — targets this key, the
    /// same way the PIV pane's `selected_slot` drives its per-slot cards.
    selected_key: OpenPgpSlotSel,
    /// Path to an RSA key file for import-from-file (text-entered).
    import_path: String,
    /// Change-user-PIN (PW1) old/new entries. Cleared after use.
    user_pin_old: String,
    user_pin_new: String,
    /// Change-admin-PIN (PW3) old/new entries. Cleared after use.
    admin_pin_old: String,
    admin_pin_new: String,
    /// New user PIN for the unblock flow (reset retry counter); authorised by
    /// `admin_pin`. Cleared after use.
    unblock_new: String,
    /// "Use default admin PIN (PW3)" toggle in the credential modal: when set,
    /// the well-known factory default (`12345678`) fills `admin_pin` on Submit
    /// instead of whatever was typed. Reset per modal. (Most cards still on the
    /// factory PIN, so this saves typing during bring-up.)
    use_default_admin: bool,
    /// Credential-entry modal for the PIN changes + the admin-PIN-gated writes
    /// (open iff `Some`). The PW1/PW3 secret fields render *inside* this modal,
    /// not inline in the pane, so the entry and its result stay on-screen
    /// (issue #31). The non-secret parameters (name, URL, slot, file path) stay
    /// inline in the pane.
    cred_modal: Option<OpenPgpCredModal>,
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
        self.use_default_admin = false;
    }
}

/// Which OpenPGP credential flow the modal is driving. The first three map 1:1
/// to the PIN operations (`change_openpgp_user_pin` / `change_openpgp_admin_pin`
/// / `unblock_openpgp_user_pin`); the rest are the admin-PIN (PW3)-gated writes
/// whose *secret* (the admin PIN) now lives in the modal while their non-secret
/// parameters (cardholder name, URL, slot, file path) stay inline in the pane.
/// The variant selects which secret fields the modal renders and which op
/// Submit dispatches to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OpenPgpCredKind {
    ChangeUserPin,
    ChangeAdminPin,
    UnblockUserPin,
    SetName,
    SetUrl,
    GenerateKey,
    GenerateImportKey,
    ImportKeyFile,
    Reset,
}

impl OpenPgpCredKind {
    /// Modal title, matching the FIDO/PIV dialogs' title style.
    fn title(self) -> &'static str {
        match self {
            OpenPgpCredKind::ChangeUserPin => "Change user PIN",
            OpenPgpCredKind::ChangeAdminPin => "Change admin PIN",
            OpenPgpCredKind::UnblockUserPin => "Unblock user PIN",
            OpenPgpCredKind::SetName => "Set cardholder name",
            OpenPgpCredKind::SetUrl => "Set public-key URL",
            OpenPgpCredKind::GenerateKey => "Generate key on-card",
            OpenPgpCredKind::GenerateImportKey => "Generate & import key",
            OpenPgpCredKind::ImportKeyFile => "Import key from file",
            OpenPgpCredKind::Reset => "Reset applet",
        }
    }
    /// Label for the modal's primary Submit button. Shorter than the title for
    /// the verbose flows so the button doesn't overflow.
    fn submit_label(self) -> &'static str {
        match self {
            OpenPgpCredKind::ChangeUserPin => "Change user PIN",
            OpenPgpCredKind::ChangeAdminPin => "Change admin PIN",
            OpenPgpCredKind::UnblockUserPin => "Unblock",
            OpenPgpCredKind::SetName => "Set name",
            OpenPgpCredKind::SetUrl => "Set URL",
            OpenPgpCredKind::GenerateKey => "Generate",
            OpenPgpCredKind::GenerateImportKey => "Generate & import",
            OpenPgpCredKind::ImportKeyFile => "Import",
            OpenPgpCredKind::Reset => "Reset applet",
        }
    }
    /// Spinner caption shown while this flow's op runs.
    fn busy_label(self) -> &'static str {
        match self {
            OpenPgpCredKind::ChangeUserPin => "Changing user PIN\u{2026}",
            OpenPgpCredKind::ChangeAdminPin => "Changing admin PIN\u{2026}",
            OpenPgpCredKind::UnblockUserPin => "Unblocking user PIN\u{2026}",
            OpenPgpCredKind::SetName => "Setting cardholder name\u{2026}",
            OpenPgpCredKind::SetUrl => "Setting public-key URL\u{2026}",
            OpenPgpCredKind::GenerateKey => "Generating key\u{2026}",
            OpenPgpCredKind::GenerateImportKey => "Generating & importing key\u{2026}",
            OpenPgpCredKind::ImportKeyFile => "Importing key from file\u{2026}",
            OpenPgpCredKind::Reset => "Resetting OpenPGP applet\u{2026}",
        }
    }
    /// In-modal success confirmation text. The key flows whose *detailed* result
    /// (the new fingerprint) still surfaces in the pane only need a generic
    /// confirmation here.
    fn success(self) -> &'static str {
        match self {
            OpenPgpCredKind::ChangeUserPin => "User PIN changed",
            OpenPgpCredKind::ChangeAdminPin => "Admin PIN changed",
            OpenPgpCredKind::UnblockUserPin => "User PIN unblocked",
            OpenPgpCredKind::SetName => "Cardholder name set",
            OpenPgpCredKind::SetUrl => "Public-key URL set",
            OpenPgpCredKind::GenerateKey => "Key generated",
            OpenPgpCredKind::GenerateImportKey => "Key generated and imported",
            OpenPgpCredKind::ImportKeyFile => "Key imported",
            OpenPgpCredKind::Reset => "Applet reset",
        }
    }
    /// True when this flow collects the *admin* PIN (PW3) — i.e. it shows the
    /// admin-PIN field and the "Use default admin PIN (PW3)" convenience toggle.
    /// The user-PIN change (PW1, self-authorising) and the reset (PIN-less) do
    /// not.
    fn needs_admin_pin(self) -> bool {
        matches!(
            self,
            OpenPgpCredKind::ChangeAdminPin
                | OpenPgpCredKind::UnblockUserPin
                | OpenPgpCredKind::SetName
                | OpenPgpCredKind::SetUrl
                | OpenPgpCredKind::GenerateKey
                | OpenPgpCredKind::GenerateImportKey
                | OpenPgpCredKind::ImportKeyFile
        )
    }
}

/// Live state of the OpenPGP credential-entry modal. Open iff
/// `OpenPgpState::cred_modal` is `Some`. Tracks the flow, whether its op is in
/// flight, and the op's result so the outcome is shown *in the modal* (issue
/// #31). `result` is `None` until the op completes, then `Ok(())` on success or
/// `Err(message)` on failure.
struct OpenPgpCredModal {
    kind: OpenPgpCredKind,
    busy: bool,
    result: Option<Result<(), String>>,
}

impl OpenPgpCredModal {
    fn new(kind: OpenPgpCredKind) -> Self {
        OpenPgpCredModal {
            kind,
            busy: false,
            result: None,
        }
    }
}

/// The well-known OpenPGP Card factory-default admin PIN (PW3).
const OPENPGP_DEFAULT_ADMIN_PIN: &str = "12345678";

/// Inline new==confirm guard for the PIN-change flows, mirroring the op-level
/// backstop. Returns the error message when the two new entries diverge (and
/// the confirm field is non-empty). The admin-PIN-gated *writes* have no
/// new==confirm pair — they're validated by the ops' own client-side guards.
fn openpgp_cred_mismatch(pgp: &OpenPgpState, kind: OpenPgpCredKind) -> Option<&'static str> {
    // The OpenPGP PIN flows ask for old + new with no separate "confirm" field
    // (the original inline forms had none), so there is no mismatch to report.
    // The function exists to mirror the PIV modal's shape and to give a single
    // place to add a confirm guard later without touching the render path.
    let _ = (pgp, kind);
    None
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
    /// Capitalized tab label for the sub-tab strip (mirrors PIV slot tabs).
    fn tab_label(self) -> &'static str {
        match self {
            OpenPgpSlotSel::Sign => "Signature",
            OpenPgpSlotSel::Decrypt => "Decryption",
            OpenPgpSlotSel::Auth => "Authentication",
        }
    }
    /// This key's algorithm id and fingerprint out of an `OpenPgpStatus`,
    /// so the per-key state line can read directly from the selected key.
    fn status_fields(self, st: &keyroost_transport::OpenPgpStatus) -> (Option<u8>, &[u8; 20]) {
        match self {
            OpenPgpSlotSel::Sign => (st.sig_algo_id, &st.fingerprint_sig),
            OpenPgpSlotSel::Decrypt => (st.dec_algo_id, &st.fingerprint_dec),
            OpenPgpSlotSel::Auth => (st.aut_algo_id, &st.fingerprint_aut),
        }
    }
}

/// Which credential-entry flow the PIV modal is currently driving. The first
/// three map 1:1 to the PIN/PUK operations (`piv_change_pin` / `piv_change_puk`
/// / `piv_unblock_pin`); the rest are the management-key-gated operations whose
/// *secrets* (management key and/or PIN) now live in the modal while their
/// non-secret parameters (slot, algorithm, file path, subject, …) stay inline
/// in the pane. The variant selects which secret fields the modal renders and
/// which op Submit dispatches to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PivCredKind {
    ChangePin,
    ChangePuk,
    UnblockPin,
    GenerateKey,
    ImportCert,
    SelfSign,
    RequestCsr,
    SetRetries,
    ChangeMgmtKey,
    DeleteCert,
    DeleteKey,
}

impl PivCredKind {
    /// Modal title, matching the FIDO dialogs' title style.
    fn title(self) -> &'static str {
        match self {
            PivCredKind::ChangePin => "Change PIN",
            PivCredKind::ChangePuk => "Change PUK",
            PivCredKind::UnblockPin => "Unblock PIN",
            PivCredKind::GenerateKey => "Generate key",
            PivCredKind::ImportCert => "Import certificate",
            PivCredKind::SelfSign => "Self-signed certificate",
            PivCredKind::RequestCsr => "Sign certificate request",
            PivCredKind::SetRetries => "Set retry counts",
            PivCredKind::ChangeMgmtKey => "Change management key",
            PivCredKind::DeleteCert => "Delete certificate",
            PivCredKind::DeleteKey => "Delete key",
        }
    }
    /// Label for the modal's primary Submit button. Shorter than the title for
    /// the verbose flows so the button doesn't overflow.
    fn submit_label(self) -> &'static str {
        match self {
            PivCredKind::GenerateKey => "Generate",
            PivCredKind::ImportCert => "Import",
            PivCredKind::SelfSign => "Create",
            PivCredKind::RequestCsr => "Sign & save",
            PivCredKind::SetRetries => "Set retry counts",
            PivCredKind::ChangeMgmtKey => "Change key",
            PivCredKind::DeleteCert => "Delete",
            PivCredKind::DeleteKey => "Delete",
            _ => self.title(),
        }
    }
    /// Spinner caption shown while this flow's op runs (matches the busy label
    /// the underlying `spawn_job` op uses).
    fn busy_label(self) -> &'static str {
        match self {
            PivCredKind::ChangePin => "Changing PIV PIN\u{2026}",
            PivCredKind::ChangePuk => "Changing PUK\u{2026}",
            PivCredKind::UnblockPin => "Unblocking PIN\u{2026}",
            PivCredKind::GenerateKey => "Generating key\u{2026}",
            PivCredKind::ImportCert => "Importing certificate\u{2026}",
            PivCredKind::SelfSign => "Creating certificate\u{2026}",
            PivCredKind::RequestCsr => "Signing request\u{2026}",
            PivCredKind::SetRetries => "Setting retry counts\u{2026}",
            PivCredKind::ChangeMgmtKey => "Changing management key\u{2026}",
            PivCredKind::DeleteCert => "Deleting certificate\u{2026}",
            PivCredKind::DeleteKey => "Deleting key\u{2026}",
        }
    }
    /// True when this flow collects the *current* management key (and therefore
    /// shows the "Use default management key" convenience toggle).
    fn needs_mgmt_key(self) -> bool {
        matches!(
            self,
            PivCredKind::GenerateKey
                | PivCredKind::ImportCert
                | PivCredKind::SelfSign
                | PivCredKind::SetRetries
                | PivCredKind::ChangeMgmtKey
                | PivCredKind::DeleteCert
                | PivCredKind::DeleteKey
        )
    }
}

/// Live state of the PIV credential-entry modal. Open iff `PivState::cred_modal`
/// is `Some`. Tracks the flow, whether its op is in flight, and the op's result
/// so the outcome is shown *in the modal* (issue #31 — feedback must not scroll
/// off-screen). `result` is `None` until the op completes, then `Ok(())` on
/// success or `Err(message)` on failure.
struct PivCredModal {
    kind: PivCredKind,
    busy: bool,
    result: Option<Result<(), String>>,
}

impl PivCredModal {
    fn new(kind: PivCredKind) -> Self {
        PivCredModal {
            kind,
            busy: false,
            result: None,
        }
    }
}

/// State for the PIV pane: a status snapshot plus the entry fields for the full
/// management surface (PIN/PUK, management key, key generation, certificate
/// import/export, reset), keyed by the selected device's reader name.
struct PivState {
    /// Last status read from the selected card.
    status: Option<keyroost_transport::PivStatus>,
    /// Per-slot detail, in canonical slot order, gathered on each refresh:
    /// the key algorithm from GET METADATA (`None` if the slot holds no key or
    /// the firmware lacks the metadata extension), and the certificate's
    /// Subject DN (`None` if the slot has no certificate or its DN failed to
    /// parse — degraded silently).
    slot_keys: Vec<(
        keyroost_piv::Slot,
        Option<keyroost_piv::KeyAlg>,
        Option<String>,
    )>,
    /// User-facing error from the last read/write.
    error: Option<String>,
    /// Success/info line from the last write operation.
    notice: Option<String>,
    /// True once a status has been fetched for the current selection.
    loaded: bool,
    /// Management key (hex) entered to authorize key-gen / cert-import /
    /// set-retries / management-key change. Cleared after use.
    mgmt_key_input: String,
    /// "Use default management key" toggle in the modal: when set, the standard
    /// factory-default key is used instead of `mgmt_key_input` (the common case,
    /// since most users never rotate the PIV management key). Reset per modal.
    use_default_mgmt: bool,
    /// Change-PIN old/new/confirm entries. Cleared after use.
    pin_old: String,
    pin_new: String,
    pin_confirm: String,
    /// Change-PUK old/new/confirm entries. Cleared after use.
    puk_old: String,
    puk_new: String,
    puk_confirm: String,
    /// Unblock-PIN: PUK + new PIN entries. Cleared after use.
    unblock_puk: String,
    unblock_new_pin: String,
    /// PIN/PUK retry counts for set-retries, and the PIN that authorizes it.
    retries_pin: u8,
    retries_puk: u8,
    retries_pin_auth: String,
    /// The slot every key/certificate action targets. Chosen once by clicking a
    /// row in the status card (issue #31): the "Keys & certificates" section is
    /// slot-first now, so Generate / Create cert / Import / Export / Delete all
    /// act on this single selection instead of each carrying its own dropdown.
    selected_slot: PivSlotSel,
    /// Key-generation algorithm selector.
    gen_alg: PivKeyAlgSel,
    /// PEM of the most recently generated public key, shown for copying.
    gen_pubkey_pem: Option<String>,
    /// Certificate import file path.
    cert_path: String,
    /// Certificate export destination path.
    export_path: String,
    /// New management key (hex) + algorithm for a management-key rotation.
    new_mgmt_key_input: String,
    new_mgmt_alg: PivMgmtAlgSel,
    /// Certificate creation: subject (bare name or full DN), validity, the PIN
    /// that authorizes the on-card signature, and the CSR destination.
    cert_subject: String,
    cert_days: u32,
    sign_pin: String,
    csr_path: String,
    /// Reset confirmation modal: typed-`reset` text (modal open iff `Some`).
    confirm_reset: Option<String>,
    /// Credential-entry modal for PIN/PUK changes + unblock (open iff `Some`).
    /// The PIN/PUK secret fields above render *inside* this modal, not inline in
    /// the pane, so the entry and its result stay on-screen (issue #31).
    cred_modal: Option<PivCredModal>,
}

// The pane is replaced wholesale on device switch (`self.piv =
// PivState::default()`); wiping on drop means the discarded fields don't
// leave PINs/keys in freed memory.
impl Drop for PivState {
    fn drop(&mut self) {
        wipe(&mut self.mgmt_key_input);
        self.use_default_mgmt = false;
        wipe(&mut self.pin_old);
        wipe(&mut self.pin_new);
        wipe(&mut self.pin_confirm);
        wipe(&mut self.puk_old);
        wipe(&mut self.puk_new);
        wipe(&mut self.puk_confirm);
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
            slot_keys: Vec::new(),
            error: None,
            notice: None,
            loaded: false,
            mgmt_key_input: String::new(),
            use_default_mgmt: false,
            pin_old: String::new(),
            pin_new: String::new(),
            pin_confirm: String::new(),
            puk_old: String::new(),
            puk_new: String::new(),
            puk_confirm: String::new(),
            unblock_puk: String::new(),
            unblock_new_pin: String::new(),
            retries_pin: 3,
            retries_puk: 3,
            retries_pin_auth: String::new(),
            selected_slot: PivSlotSel::default(),
            gen_alg: PivKeyAlgSel::default(),
            gen_pubkey_pem: None,
            cert_path: String::new(),
            export_path: String::new(),
            new_mgmt_key_input: String::new(),
            new_mgmt_alg: PivMgmtAlgSel::default(),
            cert_subject: String::new(),
            cert_days: 365,
            sign_pin: String::new(),
            csr_path: String::new(),
            confirm_reset: None,
            cred_modal: None,
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
            // Restore the persisted UI preferences (theme mode + accent +
            // colorblind + zoom) from our own settings.json, defaulting to the
            // refined dark + blue accent the prototype ships with. eframe's own
            // storage is off in this crate (no `persistence` feature), so
            // `App::save()` never fires — `settings::Settings` carries the
            // persistence instead. A missing/corrupt file yields defaults.
            let saved = Settings::load();
            let mode: Mode = saved.mode.into();
            // Clamp the accent index against the live accent count in case the
            // file predates an accent being removed.
            let accent_idx = saved.accent.min(Palette::ACCENTS.len() - 1);
            let colorblind = saved.colorblind;
            // `Settings::load` already clamps zoom; clamp again defensively.
            let zoom = theme::clamp_zoom(saved.zoom);
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
                zoom,
                // Seed the persistence baseline with exactly what we loaded so
                // the first `persist_settings()` doesn't re-write an unchanged
                // file. The sanitized values (clamped zoom / accent) are what we
                // actually hold, so record those.
                last_saved_settings: Some(Settings {
                    zoom,
                    mode: mode.into(),
                    accent: accent_idx,
                    colorblind,
                }),
                worker: Some(Worker::spawn(cc.egui_ctx.clone())),
                egui_ctx: Some(cc.egui_ctx.clone()),
                devices_dirty,
                reader_watch: Some(reader_watch),
                mds: ui::mds::MdsDb::load_bundled(),
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
    /// Active single-profile programmable-token session, if any.
    prog_session: Option<keyroost_transport::Token2ProgSession>,
    /// Last programmable-token info read (serial + on-device UTC time).
    prog_info: Option<keyroost_token2prog::Info>,
    /// Whether the programmable-token session has been authenticated.
    prog_authenticated: bool,
    /// Form state for programming the prog token (seed + config inputs).
    prog_seed_input: String,
    prog_seed_hex: bool,
    prog_algo_sha256: bool,
    prog_step_60: bool,
    prog_timeout_idx: usize,
    /// Last burn result for the prog pane: (success, message). Shown inline.
    prog_status: Option<(bool, String)>,
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
    devices: Vec<Device>,
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
    /// FIDO Metadata Service database (bundled, plus any refreshed download).
    mds: ui::mds::MdsDb,
    /// Cached icon texture for the selected device's AAGUID, with the AAGUID it
    /// was decoded for so we re-upload only when the device changes.
    mds_icon: Option<(String, egui::TextureHandle)>,
    /// Last TOTP window index seen while the On-device OTP tab was showing live
    /// codes. When the window rolls over, the codes have expired, so the pane
    /// auto-reloads. `None` until first observed.
    otp_last_window: Option<u64>,
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
    /// UI scale ("Text size", issue #42): egui's global zoom factor, which
    /// scales fonts AND painted symbols uniformly. Persisted via `settings.json`.
    /// `#[derive(Default)]` starts this at `0.0`; `theme::clamp_zoom` maps that
    /// (and any out-of-range value) back to 100%, so the default look is
    /// unchanged for existing users until they touch the control.
    zoom: f32,
    /// The zoom factor currently applied to the egui context — re-applied on
    /// change, not per frame (parallel to `applied_theme`).
    applied_zoom: Option<f32>,
    /// Slider preview while the "Text size" slider is actively dragged. The
    /// slider lives *inside* the UI it scales, so applying the zoom live during
    /// a drag would grow/shift the slider under the cursor and run the value
    /// away to the maximum (issue: slider runaway). Instead we stash the
    /// in-progress value here and keep the real `set_zoom_factor` untouched
    /// until the drag is released — see `text_size_control`. `None` means no
    /// drag in flight, so the readout/handle track the committed factor.
    zoom_pending: Option<f32>,
    /// The last `Settings` snapshot written to `settings.json` (or loaded at
    /// startup). `persist_settings()` compares the current UI state against
    /// this and only writes when something actually changed, so the disk isn't
    /// touched every frame. `None` until the first comparison.
    last_saved_settings: Option<Settings>,
    /// In-flight native file-chooser dialogs. rfd's xdg-portal backend is
    /// async, so each Browse…/Save… click spawns a helper thread that drives
    /// the dialog to completion and sends the chosen path back over a channel.
    /// `update()` drains this every frame and writes the path into the target
    /// field, so the picker never blocks the egui frame loop. One entry per
    /// open dialog; an entry is dropped once its result is consumed.
    pending_files: Vec<(
        FileTarget,
        std::sync::mpsc::Receiver<Option<std::path::PathBuf>>,
    )>,
}

/// Which path text field a resolved file-chooser result should populate. Keeps
/// the dialog plumbing generic — one helper, one drain loop, no per-field
/// duplication.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FileTarget {
    /// OpenPGP "Import RSA-2048" key file (`openpgp.import_path`).
    OpenpgpImport,
    /// PIV "Sign & save CSR" destination (`piv.csr_path`).
    PivCsr,
    /// PIV "Import certificate" source file (`piv.cert_path`).
    PivCert,
    /// PIV "Export certificate" destination (`piv.export_path`).
    PivExport,
}

impl App {
    /// Spawn a native file-chooser for `target`. `save` picks the dialog kind
    /// (Save… vs open); `filters` is `(name, &[extensions])` rows for the
    /// type dropdown; `default_name` seeds the filename on save dialogs.
    ///
    /// rfd's portal backend is async, so the dialog runs on a throwaway thread
    /// (driven by `pollster::block_on`) and the result returns over a channel
    /// drained in `update()` — the egui frame thread is never blocked. The
    /// frame loop is woken via `request_repaint` once the user dismisses the
    /// dialog so the picked path lands without waiting for the next input event.
    fn spawn_file_dialog(
        &mut self,
        target: FileTarget,
        save: bool,
        filters: &[(&'static str, &'static [&'static str])],
        default_name: Option<&str>,
    ) {
        let (tx, rx) = std::sync::mpsc::channel();
        let owned_filters: Vec<(String, Vec<String>)> = filters
            .iter()
            .map(|(name, exts)| {
                (
                    (*name).to_owned(),
                    exts.iter().map(|e| (*e).to_owned()).collect(),
                )
            })
            .collect();
        let default_name = default_name.map(str::to_owned);
        let egui_ctx = self.egui_ctx.clone();
        std::thread::spawn(move || {
            let result = pollster::block_on(async move {
                let mut dialog = rfd::AsyncFileDialog::new();
                for (name, exts) in &owned_filters {
                    let ext_refs: Vec<&str> = exts.iter().map(String::as_str).collect();
                    dialog = dialog.add_filter(name, &ext_refs);
                }
                if let Some(name) = &default_name {
                    dialog = dialog.set_file_name(name);
                }
                let handle = if save {
                    dialog.save_file().await
                } else {
                    dialog.pick_file().await
                };
                handle.map(|h| h.path().to_path_buf())
            });
            let _ = tx.send(result);
            if let Some(ctx) = egui_ctx {
                ctx.request_repaint();
            }
        });
        self.pending_files.push((target, rx));
    }

    /// Drain any resolved file-chooser dialogs and write the picked path into
    /// the matching text field. A `None` result (the user cancelled) leaves the
    /// field untouched. Entries are removed once they resolve. Called once per
    /// frame from `update()`.
    fn drain_file_dialogs(&mut self) {
        let mut i = 0;
        while i < self.pending_files.len() {
            match self.pending_files[i].1.try_recv() {
                Ok(result) => {
                    let (target, _) = self.pending_files.remove(i);
                    if let Some(path) = result {
                        let text = path.display().to_string();
                        match target {
                            FileTarget::OpenpgpImport => self.openpgp.import_path = text,
                            FileTarget::PivCsr => self.piv.csr_path = text,
                            FileTarget::PivCert => self.piv.cert_path = text,
                            FileTarget::PivExport => self.piv.export_path = text,
                        }
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => i += 1,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.pending_files.remove(i);
                }
            }
        }
    }
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

    /// Scan a TOTP QR from the screen, then run the normal otpauth import to
    /// fill the Molto2 draft — reusing the same parse+fill path as paste-a-URI.
    #[cfg(feature = "qr")]
    fn molto_scan_qr(&mut self) {
        match qrscan::scan_screens_for_otpauth() {
            Ok(uri) => {
                self.import_dialog.uri = uri;
                self.import_otpauth();
            }
            Err(e) => self.log(Severity::Err, format!("scan QR: {e}")),
        }
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
        let Some(target) = self.selected_fido_target() else {
            return;
        };
        // Tag the job with the device it reads — if the user switches devices
        // while it's in flight, the result must not be painted into the new
        // device's pane (or its row in the sidebar).
        let for_device = self.selected_device.clone();
        self.spawn_job("Reading key info\u{2026}", move || {
            // Off-thread: open the transport, run GetInfo. HID also yields an
            // InitResponse (firmware + CBOR capability); PC/SC (NFC/contact) has
            // no INIT phase, so we synthesize a minimal one and rely on GetInfo.
            let outcome = match open_fido(&target) {
                Ok((mut dev, cbor, init)) => {
                    let info = if cbor {
                        Some(keyroost_ctap::get_info(&mut dev).map_err(|e| e.to_string()))
                    } else {
                        None
                    };
                    Ok((init, info))
                }
                Err(e) => Err(format!("could not open key: {e}")),
            };
            // Back on the UI thread: store the results.
            Box::new(move |app: &mut App| {
                if app.selected_device != for_device {
                    return; // selection changed mid-read; discard
                }
                match outcome {
                    Ok((init, info)) => {
                        // Surface the key's firmware on the hero (e.g. "fw 5.7.4")
                        // when we have an InitResponse (USB-HID); PC/SC has none.
                        if let Some(init) = init {
                            let fw = format!(
                                "{}.{}.{}",
                                init.device_major, init.device_minor, init.device_build
                            );
                            if let Some(id) = for_device.clone() {
                                if let Some(dev) = app.devices.iter_mut().find(|d| d.id == id) {
                                    dev.firmware = fw;
                                }
                            }
                            app.security_keys.init = Some(init);
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
                            None => {
                                // CBOR was reported unavailable and we never even
                                // attempted GetInfo. Record it as an error rather
                                // than leaving the pane spinning on "Reading key…"
                                // forever (the spinner re-fires while info is None).
                                app.security_keys.error = Some(
                                    "this key did not present a CTAP2 (FIDO2) interface over \
                                     the reader; only U2F was detected"
                                        .to_string(),
                                );
                            }
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
        let Some(target) = self.selected_fido_target() else {
            return;
        };
        let pin = std::mem::take(&mut self.security_keys.pin_input);
        if pin.is_empty() {
            self.security_keys.error = Some("PIN is empty".into());
            return;
        }
        self.spawn_job("Unlocking\u{2026} (enter PIN / touch)", move || {
            let result = Self::open_and_unlock(&target, &pin).map_err(|e| e.to_string());
            Box::new(move |app: &mut App| match result {
                Ok(sess) => {
                    // Surface fingerprints read during unlock so the list shows
                    // without a separate Reload.
                    app.security_keys.fingerprints = sess.fingerprints.clone();
                    app.security_keys.session = Some(sess);
                    app.security_keys.error = None;
                }
                Err(e) => app.security_keys.error = Some(format!("unlock failed: {}", e)),
            })
        });
    }

    fn open_and_unlock(
        target: &FidoTarget,
        pin: &str,
    ) -> Result<UnlockedSession, Box<dyn std::error::Error>> {
        let (mut dev, cbor, _init) = open_fido(target)?;
        if !cbor {
            return Err("device is U2F-only".into());
        }
        let info = keyroost_ctap::get_info(&mut dev)?;
        // Request credential-management permission, plus bio-enrollment when the
        // key supports it, so the one cached session token authorizes both
        // passkey management and fingerprint operations. Permissions are a
        // bitmask; only OR in BIO_ENROLLMENT when advertised, since asking for an
        // unsupported permission would make the whole unlock fail.
        let mut perms = keyroost_ctap::client_pin::permissions::CREDENTIAL_MANAGEMENT;
        if info.option("bioEnroll").is_some()
            || info.option("userVerificationMgmtPreview").is_some()
        {
            perms |= keyroost_ctap::client_pin::permissions::BIO_ENROLLMENT;
        }
        let token = keyroost_ctap::client_pin::get_pin_uv_auth_token(&mut dev, pin, &info, perms)?;
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
        // While the session is fresh, also read enrolled fingerprints (when the
        // key supports bio) so the Fingerprints list appears immediately without
        // a separate Reload. Best-effort: a failure here doesn't block unlock.
        let fingerprints = if info.option("bioEnroll").is_some()
            || info.option("userVerificationMgmtPreview").is_some()
        {
            let cmd_code = if info.option("bioEnroll").is_some() {
                keyroost_ctap::bio_enroll::CTAP2_BIO_ENROLLMENT
            } else {
                keyroost_ctap::bio_enroll::CTAP2_BIO_ENROLLMENT_PREVIEW
            };
            let mut bio =
                keyroost_ctap::bio_enroll::BioEnrollment::new(&mut dev, token.clone(), cmd_code);
            bio.enumerate().ok()
        } else {
            None
        };
        Ok(UnlockedSession {
            token,
            metadata,
            rps: std::sync::Arc::new(rps),
            fingerprints,
            pin: zeroize::Zeroizing::new(pin.to_owned()),
        })
    }

    fn lock_session(&mut self) {
        self.security_keys.session = None;
        wipe(&mut self.security_keys.pin_input);
    }

    /// Resolve a failed unlocked-session operation. When the underlying CTAP
    /// error is a PIN / PIN-auth failure (`0x31` / `0x33` / `0x34`) the key has
    /// invalidated the in-flight session, so we drop it and ask the user to
    /// unlock again. Any other failure keeps the existing behavior: surface the
    /// caller's contextual message. Auto-lock applies ONLY to operations that
    /// already hold a session — `try_unlock`'s own wrong-PIN handling is left
    /// untouched.
    fn fail_session_op(&mut self, err: &SessionOpError, context: &str) {
        if err.relock {
            self.lock_session();
            self.security_keys.error = Some(
                "the key re-locked (PIN or session changed) \u{2014} \
                 unlock again to continue."
                    .into(),
            );
        } else {
            self.security_keys.error = Some(format!("{context}: {err}"));
        }
    }

    fn refresh_credentials(&mut self) {
        // Check busy *before* taking the session — spawn_job would silently
        // drop the job, destroying the unlocked session (and its PIN token)
        // and logging the user out for clicking Reload at the wrong moment.
        if self.busy() {
            return;
        }
        let Some(target) = self.selected_fido_target() else {
            return;
        };
        let Some(session) = self.security_keys.session.take() else {
            return;
        };
        let token = session.token;
        let pin = session.pin;
        self.spawn_job("Refreshing credentials\u{2026}", move || {
            let result =
                Self::refresh_with_token(&target, token, pin).map_err(SessionOpError::from_boxed);
            Box::new(move |app: &mut App| match result {
                Ok(fresh) => app.security_keys.session = Some(fresh),
                Err(e) => app.fail_session_op(&e, "refresh failed"),
            })
        });
    }

    fn refresh_with_token(
        target: &FidoTarget,
        token: PinUvAuthToken,
        pin: zeroize::Zeroizing<String>,
    ) -> Result<UnlockedSession, Box<dyn std::error::Error>> {
        let (mut dev, _cbor, _init) = open_fido(target)?;
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
            fingerprints: None,
            pin,
        })
    }

    /// Pick the bio-enrollment command byte from the cached AuthenticatorInfo.
    /// Mirrors the CLI helper: standard 0x09 when `bioEnroll` is advertised,
    /// else the preview 0x40.
    fn bio_cmd_code(&self) -> Option<u8> {
        let info = self.security_keys.info.as_ref()?;
        if info.option("bioEnroll").is_some() {
            Some(keyroost_ctap::bio_enroll::CTAP2_BIO_ENROLLMENT)
        } else if info.option("userVerificationMgmtPreview").is_some() {
            Some(keyroost_ctap::bio_enroll::CTAP2_BIO_ENROLLMENT_PREVIEW)
        } else {
            None
        }
    }

    /// Open the device, derive a FRESH bio pinUvAuthToken from the PIN, and run
    /// `f` with an armed BioEnrollment. A fresh token per operation is required:
    /// the authenticator can invalidate a token after a UV-gated bio write, so
    /// reusing the unlock token across operations fails with 0x33.
    fn with_fresh_bio<T>(
        target: &FidoTarget,
        pin: &str,
        f: impl FnOnce(
            &mut keyroost_ctap::bio_enroll::BioEnrollment<
                Box<dyn keyroost_ctap::transport::CtapTransport>,
            >,
        ) -> Result<T, SessionOpError>,
    ) -> Result<T, SessionOpError> {
        let (mut dev, cbor, _init) = open_fido(target).map_err(SessionOpError::msg)?;
        if !cbor {
            return Err(SessionOpError::msg("device is U2F-only"));
        }
        let info = keyroost_ctap::get_info(&mut dev).map_err(SessionOpError::from_ctap)?;
        let cmd_code = if info.option("bioEnroll").is_some() {
            keyroost_ctap::bio_enroll::CTAP2_BIO_ENROLLMENT
        } else if info.option("userVerificationMgmtPreview").is_some() {
            keyroost_ctap::bio_enroll::CTAP2_BIO_ENROLLMENT_PREVIEW
        } else {
            return Err(SessionOpError::msg(
                "key does not support fingerprint enrollment",
            ));
        };
        let token = keyroost_ctap::client_pin::get_pin_uv_auth_token(
            &mut dev,
            pin,
            &info,
            keyroost_ctap::client_pin::permissions::BIO_ENROLLMENT,
        )
        .map_err(SessionOpError::from_ctap)?;
        let mut bio = keyroost_ctap::bio_enroll::BioEnrollment::new(&mut dev, token, cmd_code);
        f(&mut bio)
    }

    /// Refresh the cached fingerprint list.
    fn refresh_fingerprints(&mut self) {
        if self.busy() {
            return;
        }
        let Some(target) = self.selected_fido_target() else {
            return;
        };
        let Some(session) = self.security_keys.session.as_ref() else {
            self.security_keys.error = Some("unlock the key first".into());
            return;
        };
        let pin = session.pin.clone();
        self.spawn_job("Reading fingerprints\u{2026}", move || {
            let result = Self::with_fresh_bio(&target, &pin, |bio| {
                bio.enumerate().map_err(SessionOpError::from_ctap)
            });
            Box::new(move |app: &mut App| match result {
                Ok(list) => {
                    app.security_keys.fingerprints = Some(list);
                    app.security_keys.error = None;
                }
                Err(e) => app.fail_session_op(&e, "fingerprint list failed"),
            })
        });
    }

    /// Enroll a new fingerprint end-to-end (begin + capture loop) on a worker.
    /// Writes live progress to a shared cell so the UI can show a wizard with
    /// per-sample quality feedback.
    fn enroll_fingerprint(&mut self) {
        if self.busy() {
            return;
        }
        let Some(target) = self.selected_fido_target() else {
            return;
        };
        let Some(session) = self.security_keys.session.as_ref() else {
            self.security_keys.error = Some("unlock the key first".into());
            return;
        };
        let pin = session.pin.clone();
        let name = self.security_keys.fp_new_name.trim().to_owned();
        let name = if name.is_empty() { None } else { Some(name) };

        // Shared progress cell the worker updates and the UI polls each frame.
        let progress = std::sync::Arc::new(std::sync::Mutex::new(EnrollProgress::default()));
        // Pull out the cancel flag so the worker can poll it without locking the
        // whole progress mutex on every check.
        let cancel_flag = progress
            .lock()
            .map(|g| g.cancel.clone())
            .unwrap_or_default();
        self.security_keys.fp_progress = Some(progress.clone());

        self.spawn_job("Enrolling fingerprint\u{2026}", move || {
            use keyroost_ctap::bio_enroll::sample_status_message;
            let result = (|| -> Result<Vec<keyroost_ctap::Enrollment>, SessionOpError> {
                let (mut dev, cbor, _init) = open_fido(&target).map_err(SessionOpError::msg)?;
                if !cbor {
                    return Err(SessionOpError::msg("device is U2F-only"));
                }
                // Wire the cooperative-cancel flag into the transport so a
                // capture blocked waiting for a touch aborts promptly (at the
                // next KEEPALIVE) when the user clicks Cancel.
                dev.set_cancel_flag(cancel_flag.clone());
                let info = keyroost_ctap::get_info(&mut dev).map_err(SessionOpError::from_ctap)?;
                let cmd_code = if info.option("bioEnroll").is_some() {
                    keyroost_ctap::bio_enroll::CTAP2_BIO_ENROLLMENT
                } else {
                    keyroost_ctap::bio_enroll::CTAP2_BIO_ENROLLMENT_PREVIEW
                };
                // Fresh bio token per enroll, derived from the session PIN.
                let token = keyroost_ctap::client_pin::get_pin_uv_auth_token(
                    &mut dev,
                    &pin,
                    &info,
                    keyroost_ctap::client_pin::permissions::BIO_ENROLLMENT,
                )
                .map_err(SessionOpError::from_ctap)?;
                let mut bio =
                    keyroost_ctap::bio_enroll::BioEnrollment::new(&mut dev, token, cmd_code);

                // Learn how many samples the sensor wants, for the progress bar.
                let total = bio
                    .sensor_info()
                    .map(|i| i.max_capture_samples)
                    .unwrap_or(0);

                let (template_id, mut status) =
                    bio.enroll_begin(None).map_err(SessionOpError::from_ctap)?;
                // captured = total - remaining (clamped), so the bar advances
                // even though the protocol reports "remaining".
                let update = |p: &std::sync::Mutex<EnrollProgress>,
                              total: u64,
                              remaining: u64,
                              msg: &str| {
                    if let Ok(mut g) = p.lock() {
                        g.total = total;
                        g.captured = total.saturating_sub(remaining);
                        g.last_message = msg.to_string();
                    }
                };
                update(
                    &progress,
                    total.max(status.remaining_samples + 1),
                    status.remaining_samples,
                    sample_status_message(status.last_sample_status),
                );

                while status.remaining_samples > 0 {
                    // The capture below blocks waiting for a touch, but the
                    // transport checks the cancel flag on every KEEPALIVE, so a
                    // cancel returns the "cancelled" error promptly. Map that to
                    // a device-side cancel + a clean exit.
                    match bio.enroll_capture_next(&template_id, None) {
                        Ok(s) => status = s,
                        Err(e) if e.to_string().contains("cancelled") => {
                            // Clear the flag first, otherwise the cancel command
                            // itself would be cancelled at its first KEEPALIVE.
                            cancel_flag.store(false, std::sync::atomic::Ordering::Relaxed);
                            let _ = bio.cancel_enrollment();
                            return Err(SessionOpError::msg("cancelled"));
                        }
                        Err(e) => return Err(SessionOpError::from_ctap(e)),
                    }
                    let total = total.max(status.remaining_samples + 1);
                    update(
                        &progress,
                        total,
                        status.remaining_samples,
                        sample_status_message(status.last_sample_status),
                    );
                }

                if let Some(n) = &name {
                    bio.set_friendly_name(&template_id, n)
                        .map_err(SessionOpError::from_ctap)?;
                }
                bio.enumerate().map_err(SessionOpError::from_ctap)
            })();

            // Mark the shared cell done (success or failure) for the UI.
            if let Ok(mut g) = progress.lock() {
                g.done = Some(result.as_ref().map(|_| ()).map_err(|e| e.message.clone()));
                if result.is_ok() {
                    g.last_message = "Fingerprint enrolled.".into();
                    g.captured = g.total;
                }
            }

            Box::new(move |app: &mut App| {
                match result {
                    Ok(list) => {
                        app.security_keys.fingerprints = Some(list);
                        app.security_keys.fp_new_name.clear();
                        app.security_keys.error = None;
                    }
                    Err(e) if e.message == "cancelled" => {
                        // User cancelled — dismiss the wizard without an error
                        // banner, and refresh the list so it reflects reality.
                        app.security_keys.fp_progress = None;
                        app.security_keys.error = None;
                        app.refresh_fingerprints();
                    }
                    Err(e) => app.fail_session_op(&e, "enroll failed"),
                }
                // Leave fp_progress in place briefly so the UI shows the final
                // "enrolled" state; it's cleared on the next user action.
            })
        });
    }

    /// Delete one fingerprint by template id, then refresh the list.
    fn delete_fingerprint(&mut self, template_id: Vec<u8>) {
        if self.busy() {
            return;
        }
        let Some(target) = self.selected_fido_target() else {
            return;
        };
        let Some(session) = self.security_keys.session.as_ref() else {
            return;
        };
        let pin = session.pin.clone();
        self.spawn_job("Deleting fingerprint\u{2026}", move || {
            let result = Self::with_fresh_bio(&target, &pin, |bio| {
                bio.remove_enrollment(&template_id)
                    .map_err(SessionOpError::from_ctap)?;
                bio.enumerate().map_err(SessionOpError::from_ctap)
            });
            Box::new(move |app: &mut App| match result {
                Ok(list) => app.security_keys.fingerprints = Some(list),
                Err(e) => app.fail_session_op(&e, "delete failed"),
            })
        });
    }

    /// Rename one fingerprint, then refresh the list.
    fn rename_fingerprint(&mut self, template_id: Vec<u8>, new_name: String) {
        if self.busy() {
            return;
        }
        let Some(target) = self.selected_fido_target() else {
            return;
        };
        let Some(session) = self.security_keys.session.as_ref() else {
            return;
        };
        let pin = session.pin.clone();
        self.spawn_job("Renaming fingerprint\u{2026}", move || {
            let result = Self::with_fresh_bio(&target, &pin, |bio| {
                bio.set_friendly_name(&template_id, &new_name)
                    .map_err(SessionOpError::from_ctap)?;
                bio.enumerate().map_err(SessionOpError::from_ctap)
            });
            Box::new(move |app: &mut App| match result {
                Ok(list) => app.security_keys.fingerprints = Some(list),
                Err(e) => app.fail_session_op(&e, "rename failed"),
            })
        });
    }

    /// Open the device and run `f` with a [`Configurator`] holding a fresh
    /// pinUvAuthToken that carries the AuthenticatorConfiguration permission.
    /// Mirrors `with_fresh_bio`; config commands need their own permissioned
    /// token, so they always take a PIN at action time.
    fn with_config<T>(
        target: &FidoTarget,
        pin: &str,
        f: impl FnOnce(
            &mut keyroost_ctap::config::Configurator<
                Box<dyn keyroost_ctap::transport::CtapTransport>,
            >,
        ) -> Result<T, SessionOpError>,
    ) -> Result<T, SessionOpError> {
        let (mut dev, cbor, _init) = open_fido(target).map_err(SessionOpError::msg)?;
        if !cbor {
            return Err(SessionOpError::msg("device is U2F-only"));
        }
        let info = keyroost_ctap::get_info(&mut dev).map_err(SessionOpError::from_ctap)?;
        if info.option("authnrCfg") != Some(true) {
            return Err(SessionOpError::msg(
                "this key does not support authenticatorConfig",
            ));
        }
        let token = keyroost_ctap::client_pin::get_pin_uv_auth_token(
            &mut dev,
            pin,
            &info,
            keyroost_ctap::client_pin::permissions::AUTHENTICATOR_CONFIGURATION,
        )
        .map_err(SessionOpError::from_ctap)?;
        let mut cfg = keyroost_ctap::config::Configurator::new(&mut dev, token, &info)
            .map_err(SessionOpError::from_ctap)?;
        f(&mut cfg)
    }

    /// Dispatch the pending Advanced action on a worker thread, then refresh the
    /// key's info so the view reflects the new state.
    fn run_advanced_action(&mut self) {
        if self.busy() {
            return;
        }
        let Some(dlg) = self.security_keys.advanced.as_ref() else {
            return;
        };
        let Some(target) = self.selected_fido_target() else {
            return;
        };
        let action = dlg.action;
        let pin = dlg.pin_input.clone();
        let force_change = dlg.force_change;
        let min_pin = dlg.min_pin_input.trim().parse::<u32>().ok();

        // Validate inputs before spawning.
        if action == AdvancedAction::SetMinPin && min_pin.is_none() {
            self.security_keys.error = Some("Enter a whole number for the new minimum.".into());
            return;
        }
        if pin.is_empty() {
            self.security_keys.error = Some("Enter the device PIN to apply this change.".into());
            return;
        }

        let label = match action {
            AdvancedAction::ToggleAlwaysUv => "Updating always-UV\u{2026}",
            AdvancedAction::SetMinPin => "Setting minimum PIN length\u{2026}",
            AdvancedAction::ForcePinChange => "Requesting PIN change\u{2026}",
            AdvancedAction::EnterpriseAttestation => "Enabling enterprise attestation\u{2026}",
            AdvancedAction::None => return,
        };
        self.spawn_job(label, move || {
            let result = Self::with_config(&target, &pin, |cfg| match action {
                AdvancedAction::ToggleAlwaysUv => {
                    cfg.toggle_always_uv().map_err(SessionOpError::from_ctap)
                }
                AdvancedAction::SetMinPin => cfg
                    .set_min_pin_length(min_pin, &[], force_change)
                    .map_err(SessionOpError::from_ctap),
                AdvancedAction::ForcePinChange => {
                    cfg.force_pin_change().map_err(SessionOpError::from_ctap)
                }
                AdvancedAction::EnterpriseAttestation => cfg
                    .enable_enterprise_attestation()
                    .map_err(SessionOpError::from_ctap),
                AdvancedAction::None => Ok(()),
            });
            Box::new(move |app: &mut App| match result {
                Ok(()) => {
                    app.security_keys.advanced = None;
                    app.security_keys.error = None;
                    // Re-read info so alwaysUv / minPinLength reflect the change.
                    app.fetch_selected_info();
                }
                Err(e) => app.fail_session_op(&e, "config change failed"),
            })
        });
    }

    fn delete_credential(&mut self, cred_id: Vec<u8>) {
        let Some(target) = self.selected_fido_target() else {
            return;
        };
        let Some(session) = self.security_keys.session.as_ref() else {
            return;
        };
        let token = session.token.clone();
        // The refresh after delete needs its own token; clone for the chained op.
        let token_refresh = token.clone();
        let pin_refresh = session.pin.clone();
        self.spawn_job("Deleting credential\u{2026}", move || {
            // Delete, then re-list in the same job so the UI updates atomically.
            let result = Self::try_delete(&target, token, &cred_id)
                .and_then(|()| Self::refresh_with_token(&target, token_refresh, pin_refresh))
                .map_err(SessionOpError::from_boxed);
            Box::new(move |app: &mut App| match result {
                Ok(fresh) => {
                    app.security_keys.session = Some(fresh);
                    app.security_keys.error = None;
                }
                Err(e) => app.fail_session_op(&e, "delete failed"),
            })
        });
    }

    fn try_delete(
        target: &FidoTarget,
        token: PinUvAuthToken,
        cred_id: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut dev, _cbor, _init) = open_fido(target)?;
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
        let Some(target) = self.selected_fido_target() else {
            return;
        };
        let old = std::mem::take(&mut self.security_keys.change_pin.old);
        let new = std::mem::take(&mut self.security_keys.change_pin.new);
        if old.is_empty() || new.is_empty() {
            self.security_keys.error = Some("both PIN fields are required".into());
            return;
        }
        self.spawn_job("Changing PIN\u{2026}", move || {
            let result = Self::try_change_pin(&target, &old, &new).map_err(|e| e.to_string());
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
        target: &FidoTarget,
        old: &str,
        new: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut dev, _cbor, _init) = open_fido(target)?;
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
        let Some(target) = self.selected_fido_target() else {
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
        self.spawn_job("Setting PIN\u{2026}", move || {
            let result = (|| -> Result<(), String> {
                let (mut dev, _cbor, _init) = open_fido(&target)?;
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

    /// The transport descriptor for the selected FIDO key: a USB-HID path, or a
    /// PC/SC reader name (NFC or contact). Prefers HID when both are present (a
    /// USB key that also exposes a CCID interface).
    fn selected_fido_target(&self) -> Option<FidoTarget> {
        let d = self.selected_device()?;
        if let Some(p) = d.hid_path.clone() {
            return Some(FidoTarget::Hid(p));
        }
        if d.caps.has(Caps::FIDO2) {
            if let Some(r) = d.reader.clone() {
                return Some(FidoTarget::Pcsc(r));
            }
        }
        None
    }

    /// The selected key's USB-HID path, if any. Used only by the armed-reset
    /// hotplug tracker, which watches for a USB key being unplugged and
    /// replugged within the reset window — a USB-only concept (an NFC tap has no
    /// replug), so this intentionally returns `None` for reader-attached keys.
    fn selected_fido_hid_path(&self) -> Option<std::path::PathBuf> {
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
        // Mirror the outcome into the add modal when one is in flight (the
        // provision op routes through here), so success/error shows *in* the
        // dialog (issue #31) rather than only as a pane-level error line.
        let modal_busy = app.oath.add.open && app.oath.add.busy;
        match &result {
            Ok(_) if modal_busy => app.oath.add.result = Some(Ok(())),
            Err(TransportError::OathPasswordRejected) if modal_busy => {
                app.oath.add.result = Some(Err("wrong OATH password".into()));
            }
            Err(e) if modal_busy => app.oath.add.result = Some(Err(e.to_string())),
            _ => {}
        }
        if app.oath.add.open {
            app.oath.add.busy = false;
        }
        match result {
            Ok(rows) => {
                app.oath.creds = rows;
                app.oath.loaded = true;
                app.oath.locked = false;
            }
            Err(TransportError::OathPasswordRejected) => {
                app.oath.locked = true;
                // The add modal already shows this; don't double-report when it
                // is the one that failed.
                if !modal_busy {
                    app.oath.error = Some("wrong OATH password".into());
                }
            }
            Err(e) => {
                if !modal_busy {
                    app.oath.error = Some(e.to_string());
                }
            }
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
        // Validate before dispatch; the modal surfaces the reason on failure.
        let (cred_name, secret) = match self.oath.add.validate() {
            Ok((n, s)) => (n, zeroize::Zeroizing::new(s)),
            Err(e) => {
                self.oath.error = Some(e);
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
        // The form stays open showing the spinner; it is wiped/closed on the
        // modal's Done (success) or Cancel/✕/Esc. Do not reset it here.
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

    /// Close the "Add credential" modal, wiping the typed secret. (`OathAddDialog`
    /// also wipes on drop; the explicit reset here makes the close-path intent
    /// clear and mirrors the PIV/OpenPGP `*_cred_modal_close` helpers.)
    fn oath_add_modal_close(&mut self) {
        wipe(&mut self.oath.add.secret);
        self.oath.add = OathAddDialog::default();
    }

    /// Centered "New credential" modal: the name + base32 **secret** + type/touch
    /// fields live *inside* the shared `modal_window` chrome (not inline in the
    /// pane), so the secret entry and its result stay on-screen — matching the
    /// PIV/OpenPGP credential modals (issue #31). Submit dispatches the unchanged
    /// `provision_oath`; the outcome is mirrored back via `apply_oath_rows`. The
    /// secret is wiped on Done/Cancel/✕/Esc.
    fn render_oath_add_modal(&mut self, ctx: &egui::Context, p: &Palette) {
        if !self.oath.add.open {
            return;
        }
        let busy = self.oath.add.busy;
        let result = self.oath.add.result.clone();

        let mut want_submit = false;
        let mut want_close = false;

        let closed = Self::modal_window(ctx, p, "oath_add", "New credential", |ui| {
            match &result {
                Some(Ok(())) => {
                    // Success: confirmation + a single Done that dismisses.
                    ui.label(
                        egui::RichText::new("\u{2713} Credential added")
                            .font(theme::f_sb(13.0))
                            .color(p.ok),
                    );
                    ui.add_space(16.0);
                    if theme::button(ui, p, BtnKind::Primary, "Done").clicked() {
                        want_close = true;
                    }
                }
                _ => {
                    // Entry form (also the path while busy / after an error so the
                    // user can retry without losing the dialog).
                    ui.horizontal(|ui| {
                        ui.add_sized(
                            [96.0, 22.0],
                            egui::Label::new(
                                egui::RichText::new("Name")
                                    .font(theme::f_reg(13.0))
                                    .color(p.txt2),
                            ),
                        );
                        ui.add(
                            egui::TextEdit::singleline(&mut self.oath.add.name)
                                .hint_text("issuer:account")
                                .desired_width(300.0),
                        );
                    });
                    ui.add_space(4.0);
                    secret_field(
                        ui,
                        p,
                        "Secret",
                        &mut self.oath.add.secret,
                        "base32 (behind the QR code)",
                        300.0,
                    );
                    ui.horizontal(|ui| {
                        ui.add_sized(
                            [96.0, 22.0],
                            egui::Label::new(
                                egui::RichText::new("Type")
                                    .font(theme::f_reg(13.0))
                                    .color(p.txt2),
                            ),
                        );
                        ui.selectable_value(&mut self.oath.add.totp, true, "TOTP");
                        ui.selectable_value(&mut self.oath.add.totp, false, "HOTP");
                    });
                    ui.add_space(4.0);
                    ui.checkbox(&mut self.oath.add.require_touch, "Require touch");
                    card_note(
                        ui,
                        p,
                        "The secret is sent to the key, not written to disk by keyroost.",
                    );

                    if let Some(Err(e)) = &result {
                        ui.add_space(6.0);
                        ui.colored_label(p.err, e);
                    }

                    ui.add_space(16.0);
                    ui.horizontal(|ui| {
                        if busy {
                            ui.add(egui::Spinner::new());
                            ui.label(
                                egui::RichText::new("Adding credential\u{2026}")
                                    .font(theme::f_reg(12.5))
                                    .color(p.txt2),
                            );
                        } else {
                            if theme::button(ui, p, BtnKind::Primary, "Add").clicked() {
                                want_submit = true;
                            }
                            ui.add_space(8.0);
                            if theme::button(ui, p, BtnKind::Default, "Cancel").clicked() {
                                want_close = true;
                            }
                        }
                    });
                }
            }
        });

        // ✕ / Esc / Cancel dismiss too, but never yank the dialog out from under
        // a running op (mirrors the PIV/OpenPGP modals' busy handling).
        if (closed || want_close) && !busy {
            self.oath_add_modal_close();
            return;
        }
        if want_submit && !busy {
            // Mark busy first so the modal shows the spinner this frame; the op
            // writes the outcome back via `apply_oath_rows`.
            self.oath.add.busy = true;
            self.oath.add.result = None;
            self.oath.error = None;
            self.provision_oath();
            // If the op didn't actually queue — the worker was busy (no error
            // set; retry on the next click) or a client-side guard rejected the
            // input and stored the reason in `oath.error` — unstick the modal and
            // surface the guard reason in the dialog rather than the pane.
            if !self.busy() {
                let guard_err = self.oath.error.take();
                self.oath.add.busy = false;
                if let Some(e) = guard_err {
                    self.oath.add.result = Some(Err(e));
                }
            }
        }
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

        // A reset wipes credentials + the PIN but leaves the large-blob array
        // intact, so warn when this key supports it. Computed up front to avoid
        // borrowing `self` inside the window closure.
        let has_large_blobs = self
            .security_keys
            .info
            .as_ref()
            .and_then(|i| i.option("largeBlobs"))
            == Some(true);

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
                if has_large_blobs {
                    ui.add_space(6.0);
                    let muted = egui::Color32::from_rgb(150, 150, 150);
                    ui.colored_label(
                        muted,
                        "Note: a reset does not erase large-blob storage. Open the Storage tab",
                    );
                    ui.colored_label(
                        muted,
                        "and use \u{201c}Clear all storage\u{201d} to wipe every entry there.",
                    );
                }
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
            let target_path = self.selected_fido_hid_path();
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
        Self::apply_openpgp_cred_result(app);
    }

    /// Mirror an OpenPGP write result into the credential modal so the outcome
    /// is shown in-modal (issue #31). Reads the pane status the apply closure
    /// just set: no error → `Ok(())`; an error → the message, with the modal
    /// kept open for a retry. `busy` always clears. No-op when the modal is
    /// closed (e.g. the flow was triggered some other way).
    fn apply_openpgp_cred_result(app: &mut App) {
        if let Some(m) = app.openpgp.cred_modal.as_mut() {
            m.busy = false;
            m.result = match &app.openpgp.error {
                Some(e) => Some(Err(e.clone())),
                None => Some(Ok(())),
            };
        }
    }

    /// The admin PIN (PW3) the modal's flows send: the typed `admin_pin`, or the
    /// well-known factory default when "Use default admin PIN (PW3)" is ticked.
    /// Mirrors the PIV `use_default_mgmt` convenience. Does not mutate state.
    fn openpgp_admin_pin_value(&self) -> String {
        if self.openpgp.use_default_admin {
            OPENPGP_DEFAULT_ADMIN_PIN.to_string()
        } else {
            self.openpgp.admin_pin.clone()
        }
    }

    /// Set the cardholder name (PW3-gated), then refresh status.
    fn set_openpgp_name(&mut self) {
        let Some(name) = self.selected_openpgp_reader() else {
            return;
        };
        let pin = zeroize::Zeroizing::new(self.openpgp_admin_pin_value());
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
        let pin = zeroize::Zeroizing::new(self.openpgp_admin_pin_value());
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
        let pin = zeroize::Zeroizing::new(self.openpgp_admin_pin_value());
        let slot = self.openpgp.selected_key;
        let creation_time = unix_now();
        self.openpgp.notice = None;
        self.spawn_job("Generating key… (touch the key if it blinks)", move || {
            let result = (|| -> Result<(keyroost_transport::OpenPgpStatus, [u8; 20]), TransportError> {
                let mut s = Self::openpgp_open_admin(&name, &pin)?;
                let _ = s.generate_key(slot.to_crt())?;
                let fpr = s.register_key(slot.to_crt(), creation_time)?;
                Ok((s.status()?, fpr))
            })();
            Box::new(move |app: &mut App| {
                match result {
                    Ok((status, fpr)) => {
                        app.openpgp.status = Some(status);
                        app.openpgp.loaded = true;
                        app.openpgp.error = None;
                        app.openpgp.notice =
                            Some(format!("Generated {} key: {}", slot.label(), hex_lower(&fpr)));
                        wipe(&mut app.openpgp.admin_pin);
                    }
                    Err(e) => {
                        app.openpgp.error = Some(e.to_string());
                        wipe(&mut app.openpgp.admin_pin);
                    }
                }
                Self::apply_openpgp_cred_result(app);
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
        let pin = zeroize::Zeroizing::new(self.openpgp_admin_pin_value());
        let slot = self.openpgp.selected_key;
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
            Box::new(move |app: &mut App| {
                match result {
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
                }
                Self::apply_openpgp_cred_result(app);
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
        let admin = zeroize::Zeroizing::new(self.openpgp_admin_pin_value());
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

/// The well-known factory-default PIV management key, as a hex string. The
/// standard PIV default is 24 bytes of `01 02 03 04 05 06 07 08` repeated three
/// times (a 3-DES / AES-192 key); Token2 PIN+ ships a vendor-specific default
/// instead. Used by the modal's "Use default management key" convenience toggle
/// so the common case (key never rotated) is one click.
fn piv_default_mgmt_key_hex(is_token2: bool) -> &'static str {
    if is_token2 {
        "865362865362865362865362865362865362865362865362"
    } else {
        "010203040506070801020304050607080102030405060708"
    }
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

    /// Persist the current UI preferences to `settings.json` — but only when
    /// something actually changed since the last write, so a per-change call
    /// site can fire freely without spamming the disk. Best-effort: a write
    /// failure is swallowed inside `Settings::save`, since a UI preference that
    /// won't persist must never crash the app. Called at the change points
    /// (theme toggle, accent pick, colorblind toggle, zoom commit) because
    /// eframe's own `save()` is disabled in this crate.
    fn persist_settings(&mut self) {
        let current = Settings {
            zoom: theme::clamp_zoom(self.zoom),
            mode: self.mode.into(),
            accent: self.accent_idx,
            colorblind: self.colorblind,
        };
        if self.last_saved_settings.as_ref() == Some(&current) {
            return;
        }
        current.save();
        self.last_saved_settings = Some(current);
    }

    /// The currently selected device, if the id still resolves to a present one.
    fn selected_device(&self) -> Option<&Device> {
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
        // Large-blob state is per-key; drop it so the next key auto-loads fresh.
        self.security_keys.large_blobs = None;
        self.security_keys.lb_autoloaded = false;
        self.security_keys.lb_selected = None;
        self.security_keys.lb_editing = None;
        self.security_keys.lb_show_add = false;
        self.security_keys.lb_status = None;
        self.security_keys.lb_confirm_delete = None;
        self.security_keys.lb_confirm_clear = false;
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
            DeviceKind::ProgToken => self.open_prog(),
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

    /// Open the selected programmable token's PC/SC session and read its info,
    /// so the pane can show the model, serial and on-device clock.
    fn open_prog(&mut self) {
        let Some(reader) = self.selected_device().and_then(|d| d.reader.clone()) else {
            return;
        };
        self.spawn_job("Opening token\u{2026}", move || {
            let result =
                (|| -> Result<(Token2ProgSession, keyroost_token2prog::Info), TransportError> {
                    let mut s = Token2ProgSession::open_named(&reader)?;
                    let info = s.read_info()?;
                    Ok((s, info))
                })();
            Box::new(move |app: &mut App| match result {
                Ok((s, info)) => {
                    app.log(
                        Severity::Ok,
                        format!("opened programmable token {}", info.serial),
                    );
                    app.prog_session = Some(s);
                    app.prog_info = Some(info);
                    app.prog_authenticated = false;
                }
                Err(e) => app.log(Severity::Err, format!("open token: {e}")),
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
            // Alongside the status, probe each slot's key algorithm via GET
            // METADATA. This surfaces an algorithm (and confirms a key exists)
            // even for a slot with no certificate; `None` covers an empty slot
            // or firmware without the metadata extension.
            let result = keyroost_transport::PivSession::open(&reader).map(|mut s| {
                let status = s.status();
                let slot_keys: Vec<_> = keyroost_piv::Slot::all()
                    .into_iter()
                    .map(|slot| {
                        let alg = s
                            .metadata(slot.key_ref())
                            .and_then(|m| m.algorithm)
                            .and_then(keyroost_piv::KeyAlg::from_id);
                        // Pull the slot's certificate (if any) and extract its
                        // Subject DN for display. Any failure — no cert, read
                        // error, or unparseable DER — degrades to `None` so the
                        // pane never breaks on a malformed certificate.
                        let subject = s
                            .read_certificate(slot)
                            .ok()
                            .flatten()
                            .and_then(|der| keyroost_piv::x509_parse::parse_subject_dn(&der).ok())
                            .map(|dn| dn.to_string());
                        (slot, alg, subject)
                    })
                    .collect();
                (status, slot_keys)
            });
            Box::new(move |app: &mut App| {
                if app.selected_device != for_device {
                    return; // selection changed mid-read; discard
                }
                match result {
                    Ok((Ok(status), slot_keys)) => {
                        app.piv.status = Some(status);
                        app.piv.slot_keys = slot_keys;
                        app.piv.loaded = true;
                    }
                    Ok((Err(e), _)) | Err(e) => app.piv.error = Some(e.to_string()),
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
                // Re-read so per-slot key algorithms (and anything the write
                // touched) reflect the new state without a manual Refresh.
                app.load_piv_status();
            }
            Err(e) => {
                app.piv.notice = None;
                app.piv.error = Some(e.to_string());
            }
        }
    }

    /// Mirror a PIV PIN/PUK write result into the credential modal so the outcome
    /// is shown in-modal (issue #31). Reads the pane status `apply_piv_write` just
    /// set: success clears `busy` and records `Ok(())`; an error records the
    /// message and keeps the modal open for a retry. Cleared secrets on success
    /// are wiped by the op's apply closure regardless.
    fn apply_piv_cred_result(app: &mut App) {
        if let Some(m) = app.piv.cred_modal.as_mut() {
            m.busy = false;
            m.result = match &app.piv.error {
                Some(e) => Some(Err(e.clone())),
                None => Some(Ok(())),
            };
        }
    }

    /// Change the PIV PIN. Validates new==confirm, runs off-thread, and surfaces
    /// the outcome both in the pane banner and in the credential modal.
    fn piv_change_pin(&mut self) {
        let Some(name) = self.selected_oath_reader() else {
            return;
        };
        if self.piv.pin_new != self.piv.pin_confirm {
            self.piv.notice = None;
            self.piv.error = Some("the two new PINs don't match".into());
            return;
        }
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
                wipe(&mut app.piv.pin_confirm);
                Self::apply_piv_write(app, result, "PIN changed.".into());
                Self::apply_piv_cred_result(app);
            })
        });
    }

    fn piv_change_puk(&mut self) {
        let Some(name) = self.selected_oath_reader() else {
            return;
        };
        if self.piv.puk_new != self.piv.puk_confirm {
            self.piv.notice = None;
            self.piv.error = Some("the two new PUKs don't match".into());
            return;
        }
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
                wipe(&mut app.piv.puk_confirm);
                Self::apply_piv_write(app, result, "PUK changed.".into());
                Self::apply_piv_cred_result(app);
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
                Self::apply_piv_cred_result(app);
            })
        });
    }

    /// Resolve the *current* management key the user authorized this op with:
    /// the well-known factory default when "Use default management key" is
    /// ticked, otherwise the hex they typed. Decoding errors are surfaced the
    /// same way the inline field's were.
    fn piv_current_mgmt_key(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
        if self.piv.use_default_mgmt {
            let is_token2 = self
                .selected_device()
                .map(|d| d.vendor.eq_ignore_ascii_case("token2"))
                .unwrap_or(false);
            piv_mgmt_key_bytes(piv_default_mgmt_key_hex(is_token2))
        } else {
            piv_mgmt_key_bytes(&self.piv.mgmt_key_input)
        }
    }

    fn piv_set_retries(&mut self) {
        let Some(name) = self.selected_oath_reader() else {
            return;
        };
        let mgmt = match self.piv_current_mgmt_key() {
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
                Self::apply_piv_cred_result(app);
            })
        });
    }

    fn piv_generate_key(&mut self) {
        let Some(name) = self.selected_oath_reader() else {
            return;
        };
        let mgmt = match self.piv_current_mgmt_key() {
            Ok(b) => b,
            Err(e) => {
                self.piv.error = Some(e);
                return;
            }
        };
        let slot = self.piv.selected_slot.to_slot();
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
                Self::apply_piv_cred_result(app);
            })
        });
    }

    fn piv_import_cert(&mut self) {
        let Some(name) = self.selected_oath_reader() else {
            return;
        };
        let mgmt = match self.piv_current_mgmt_key() {
            Ok(b) => b,
            Err(e) => {
                self.piv.error = Some(e);
                return;
            }
        };
        let slot = self.piv.selected_slot.to_slot();
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
                Self::apply_piv_cred_result(app);
            })
        });
    }

    /// Delete (clear) the certificate in the selected slot. The private
    /// key, if any, is left intact. Management-key authorized; works on every
    /// PIV card. Mirrors `piv_import_cert`'s shape: open → authenticate → call
    /// the transport method → re-read status (so the slot's cert state updates).
    fn piv_delete_cert(&mut self) {
        let Some(name) = self.selected_oath_reader() else {
            return;
        };
        let mgmt = match self.piv_current_mgmt_key() {
            Ok(b) => b,
            Err(e) => {
                self.piv.error = Some(e);
                return;
            }
        };
        let slot = self.piv.selected_slot.to_slot();
        self.piv.notice = None;
        self.spawn_job("Deleting certificate\u{2026}", move || {
            let result = (|| -> Result<keyroost_transport::PivStatus, TransportError> {
                let mut s = keyroost_transport::PivSession::open(&name)?;
                let mgmt_alg = s.management_key_algorithm();
                s.authenticate_management(mgmt_alg, &mgmt)?;
                s.clear_certificate(slot)?;
                s.status()
            })();
            Box::new(move |app: &mut App| {
                wipe(&mut app.piv.mgmt_key_input);
                Self::apply_piv_write(
                    app,
                    result,
                    format!("Certificate removed from {}.", slot.label()),
                );
                Self::apply_piv_cred_result(app);
            })
        });
    }

    /// Permanently delete (erase) the private key in the selected slot.
    /// Management-key authorized. Needs YubiKey firmware 5.7+; the transport
    /// version-gates and surfaces `PivFirmwareTooOld` as the error on older
    /// cards (the pane also hides the button below 5.7 — this is the backstop).
    fn piv_delete_key(&mut self) {
        let Some(name) = self.selected_oath_reader() else {
            return;
        };
        let mgmt = match self.piv_current_mgmt_key() {
            Ok(b) => b,
            Err(e) => {
                self.piv.error = Some(e);
                return;
            }
        };
        let slot = self.piv.selected_slot.to_slot();
        self.piv.notice = None;
        self.spawn_job("Deleting key\u{2026}", move || {
            let result = (|| -> Result<keyroost_transport::PivStatus, TransportError> {
                let mut s = keyroost_transport::PivSession::open(&name)?;
                let mgmt_alg = s.management_key_algorithm();
                s.authenticate_management(mgmt_alg, &mgmt)?;
                s.delete_key(slot)?;
                s.status()
            })();
            Box::new(move |app: &mut App| {
                wipe(&mut app.piv.mgmt_key_input);
                Self::apply_piv_write(app, result, format!("Key erased from {}.", slot.label()));
                Self::apply_piv_cred_result(app);
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
        let mgmt = match self.piv_current_mgmt_key() {
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
        let slot = self.piv.selected_slot.to_slot();
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
                    Self::apply_piv_cred_result(app);
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
        let slot = self.piv.selected_slot.to_slot();
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
                    Self::apply_piv_cred_result(app);
                })
            },
        );
    }

    fn piv_export_cert(&mut self) {
        let Some(name) = self.selected_oath_reader() else {
            return;
        };
        let slot = self.piv.selected_slot.to_slot();
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
        let old = match self.piv_current_mgmt_key() {
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
                Self::apply_piv_cred_result(app);
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
    fn apply_rename_actions(&mut self, dev: &Device, open: bool, cancel: bool, save: bool) {
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
fn matches_filter(d: &Device, q: &str) -> bool {
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
        CapTab::Fido2 => "FIDO2",
        CapTab::Oath => "Authenticator",
        CapTab::Pgp => "OpenPGP",
        CapTab::Piv => "PIV",
        CapTab::Otp => "On-device OTP",
    }
}

/// A labelled password field row for the inline PIN form.
/// New==confirm guard for the PIV credential modal. Returns the inline error
/// message when the new secret and its confirmation differ, or `None` when they
/// match (or the flow has no confirm field, i.e. `UnblockPin`). Empty fields are
/// treated as "not yet a mismatch" so the error doesn't flash before the user
/// finishes typing.
fn piv_cred_mismatch(piv: &PivState, kind: PivCredKind) -> Option<&'static str> {
    let (new, confirm, msg) = match kind {
        PivCredKind::ChangePin => (
            &piv.pin_new,
            &piv.pin_confirm,
            "the two new PINs don't match",
        ),
        PivCredKind::ChangePuk => (
            &piv.puk_new,
            &piv.puk_confirm,
            "the two new PUKs don't match",
        ),
        // Unblock and the management-key-gated flows have no new==confirm pair;
        // their inputs are validated by the op's own client-side guards.
        PivCredKind::UnblockPin
        | PivCredKind::GenerateKey
        | PivCredKind::ImportCert
        | PivCredKind::SelfSign
        | PivCredKind::RequestCsr
        | PivCredKind::SetRetries
        | PivCredKind::ChangeMgmtKey
        | PivCredKind::DeleteCert
        | PivCredKind::DeleteKey => return None,
    };
    if confirm.is_empty() || new == confirm {
        None
    } else {
        Some(msg)
    }
}

/// In-modal success confirmation text for each PIV credential flow. The
/// management-key-gated flows whose *detailed* result (e.g. the generated
/// public-key PEM) still surfaces in the pane only need a generic confirmation
/// here — the pane keeps showing the rich outcome.
fn piv_cred_success(kind: PivCredKind) -> &'static str {
    match kind {
        PivCredKind::ChangePin => "PIN changed",
        PivCredKind::ChangePuk => "PUK changed",
        PivCredKind::UnblockPin => "PIN unblocked and reset",
        PivCredKind::GenerateKey => "Key generated",
        PivCredKind::ImportCert => "Certificate imported",
        PivCredKind::SelfSign => "Certificate created",
        PivCredKind::RequestCsr => "Request signed and saved",
        PivCredKind::SetRetries => "Retry counts set",
        PivCredKind::ChangeMgmtKey => "Management key changed",
        PivCredKind::DeleteCert => "Certificate deleted",
        PivCredKind::DeleteKey => "Key deleted",
    }
}

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

/// Fine-print note inside a management card.
fn card_note(ui: &mut egui::Ui, p: &Palette, t: &str) {
    ui.label(
        egui::RichText::new(t)
            .font(theme::f_reg(12.0))
            .color(p.txt3),
    );
}

/// A key/value detail row for the device-metadata card: a muted fixed-width
/// label on the left, the value on the right. Wraps long values.
fn mds_kv(ui: &mut egui::Ui, p: &Palette, key: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.add_sized(
            [150.0, 16.0],
            egui::Label::new(
                egui::RichText::new(key)
                    .font(theme::f_reg(12.0))
                    .color(p.txt3),
            )
            .wrap_mode(egui::TextWrapMode::Extend),
        );
        ui.label(
            egui::RichText::new(value)
                .font(theme::f_reg(12.5))
                .color(p.txt2),
        );
    });
    ui.add_space(3.0);
}

/// One "label  value" cell in the metadata grid, occupying width `w`. The label
/// is muted and fixed-width; the value sits immediately to its right so the pair
/// reads as a unit rather than drifting apart.
fn mds_cell(ui: &mut egui::Ui, p: &Palette, key: &str, value: &str, w: f32) {
    let label_w = 138.0_f32.min(w * 0.5);
    ui.allocate_ui(egui::vec2(w, 18.0), |ui| {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 10.0;
            ui.add_sized(
                [label_w, 16.0],
                egui::Label::new(
                    egui::RichText::new(key)
                        .font(theme::f_reg(12.0))
                        .color(p.txt3),
                )
                .wrap_mode(egui::TextWrapMode::Extend)
                .halign(egui::Align::LEFT),
            );
            ui.add(
                egui::Label::new(
                    egui::RichText::new(value)
                        .font(theme::f_reg(12.5))
                        .color(p.txt2),
                )
                .wrap_mode(egui::TextWrapMode::Truncate),
            );
        });
    });
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
/// Format a Unix timestamp (seconds) as a human-readable UTC string
/// `YYYY-MM-DD HH:MM:SS UTC`. Self-contained civil-date conversion (Howard
/// Hinnant's algorithm) so no date crate is pulled in.
fn fmt_unix_utc(secs: u32) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // days since 1970-01-01 -> civil date
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}:{ss:02} UTC")
}

fn paint_copy_icon(ui: &egui::Ui, center: egui::Pos2, color: egui::Color32) {
    let s = egui::Stroke::new(1.3, color);
    let back = egui::Rect::from_min_size(center + egui::vec2(-1.0, -5.0), egui::vec2(7.0, 8.0));
    let front = egui::Rect::from_min_size(center + egui::vec2(-5.0, -1.0), egui::vec2(7.0, 8.0));
    ui.painter().rect_stroke(back, egui::Rounding::same(1.5), s);
    ui.painter()
        .rect_stroke(front, egui::Rounding::same(1.5), s);
}

/// A small QR-glyph: three finder squares plus a couple of module dots.
fn paint_qr_icon(ui: &egui::Ui, center: egui::Pos2, color: egui::Color32) {
    let s = egui::Stroke::new(1.2, color);
    // Three finder squares (top-left, top-right, bottom-left).
    let finder = |min: egui::Vec2| {
        let r = egui::Rect::from_min_size(center + min, egui::vec2(3.4, 3.4));
        ui.painter().rect_stroke(r, egui::Rounding::same(0.6), s);
    };
    finder(egui::vec2(-5.0, -5.0));
    finder(egui::vec2(1.6, -5.0));
    finder(egui::vec2(-5.0, 1.6));
    // A few modules in the data quadrant so it reads as a QR, not four boxes.
    let dot = |off: egui::Vec2| {
        ui.painter().rect_filled(
            egui::Rect::from_min_size(center + off, egui::vec2(1.2, 1.2)),
            egui::Rounding::ZERO,
            color,
        );
    };
    dot(egui::vec2(2.0, 2.0));
    dot(egui::vec2(4.0, 4.0));
    dot(egui::vec2(2.0, 4.4));
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
fn device_row(ui: &mut egui::Ui, p: &Palette, dev: &Device, selected: bool) -> bool {
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

    let token = dev.kind == DeviceKind::Token || dev.kind == DeviceKind::ProgToken;
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
    // capability pills — labels come from the shared cap_badges() vocabulary so
    // the GUI and the CLI overview never disagree. Tokens keep the amber accent.
    let py = rect.top() + 46.0;
    let (fg, bg) = if token {
        (p.brand, p.brand_soft())
    } else {
        (p.txt2, p.raised2)
    };
    let mut px = tx;
    for label in dev.cap_badges() {
        px += paint_pill(ui, egui::pos2(px, py), label, fg, bg) + 5.0;
    }
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp.clicked()
}

impl eframe::App for App {
    // Note: `eframe::App::save` is intentionally not implemented. This crate
    // builds eframe without its `persistence` feature (to avoid pulling in
    // three extra crates), so `save()` would never be called. UI preferences
    // are persisted by `App::persist_settings` into `settings.json` instead —
    // see the `settings` module.

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
        // While a device job is in flight (e.g. fingerprint enrollment writing
        // live progress to a shared cell), keep the frame loop ticking so the UI
        // reflects per-sample updates instead of freezing until the job ends.
        if self.busy() {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
        self.drain_import();
        // Land any path picked by a native file-chooser into its target field.
        self.drain_file_dialogs();
        let p = self.palette();
        // Rebuilding + re-applying egui Visuals every frame is wasted work;
        // only do it when a theme knob actually changed.
        let theme_key = (self.mode, self.accent_idx, self.colorblind);
        if self.applied_theme != Some(theme_key) {
            p.apply(ctx, self.mode);
            self.applied_theme = Some(theme_key);
        }

        // UI scale ("Text size", issue #42). Let Ctrl +/-/scroll zoom the whole
        // UI immediately (egui then scales fonts AND painted symbols uniformly).
        ctx.options_mut(|o| o.zoom_with_keyboard = true);
        match self.applied_zoom {
            // First frame: push *our* persisted factor into the context. This
            // is also the persistence-conflict fix: eframe restores egui's own
            // memory (which includes egui's separately-persisted zoom factor)
            // before this runs, so two sources of truth exist. We resolve it by
            // making our "zoom" storage key authoritative — re-applying it here
            // every launch deterministically overrides whatever egui restored,
            // so the two can never drift (last writer is always us). We do NOT
            // read `ctx.zoom_factor()` back on this frame: doing so previously
            // clobbered the loaded value with a stale 1.0, which `save()` then
            // persisted, so the chosen size reset on every reopen.
            None => {
                self.zoom = theme::clamp_zoom(self.zoom);
                ctx.set_zoom_factor(self.zoom);
                self.applied_zoom = Some(self.zoom);
            }
            // Steady state: the context owns the live factor (Ctrl +/-/scroll
            // and the slider's on-release commit both write it via
            // `set_zoom_factor`). Mirror it back into `self.zoom` so the readout
            // and the persisted value stay in sync — but never while the slider
            // is mid-drag, since the drag stashes its preview in `zoom_pending`
            // and has not committed to the context yet.
            Some(_) => {
                if self.zoom_pending.is_none() {
                    // Ctrl +/- and Ctrl-scroll use egui's built-in keyboard zoom,
                    // which ignores our 80–200% slider bounds. If it ran past the
                    // limit, pull the context back to the clamp so the keyboard
                    // path obeys the same range as the slider (issue #42).
                    let live = ctx.zoom_factor();
                    let clamped = theme::clamp_zoom(live);
                    if (live - clamped).abs() > f32::EPSILON {
                        ctx.set_zoom_factor(clamped);
                    }
                    self.zoom = clamped;
                    self.applied_zoom = Some(self.zoom);
                    // The zoom only lands here once it's committed to the
                    // context (slider release, Ctrl +/-/scroll, or Reset), never
                    // mid-drag (guarded by `zoom_pending`). Persist on the
                    // committed value; `persist_settings` no-ops when the factor
                    // is unchanged, so this is cheap on every quiescent frame.
                    self.persist_settings();
                }
            }
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
        self.render_advanced_confirm(ctx, &p);
        self.render_enroll_dialog(ctx, &p);
        if let Some(id) = self.render_fp_delete_confirm(ctx, &p) {
            self.delete_fingerprint(id);
        }
        self.render_oath_delete_confirm(ctx);
        self.render_oath_add_modal(ctx, &p);
        self.render_openpgp_cred_modal(ctx, &p);
        self.render_piv_confirms(ctx);
        self.render_piv_cred_modal(ctx, &p);
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
        // Auto-refresh on-device TOTP codes when their time window rolls over.
        // The device returns codes only at read time, so once the window flips
        // the shown codes are stale; reload them (like clicking Refresh). Keyed
        // on the shortest period among the visible TOTP rows so a 30s entry
        // refreshes on its boundary even if a 60s entry is also present.
        if matches!(self.cap_tab, CapTab::Otp) && self.otp.loaded {
            let min_period = self
                .otp
                .rows
                .iter()
                .filter(|r| r.type_str.eq_ignore_ascii_case("TOTP") && r.code.is_some())
                .map(|r| if r.period == 0 { 30 } else { r.period as u64 })
                .min();
            if let Some(period) = min_period {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let window = now / period;
                match self.otp_last_window {
                    Some(prev) if prev != window => {
                        self.otp_last_window = Some(window);
                        self.load_otp_entries();
                    }
                    None => self.otp_last_window = Some(window),
                    _ => {}
                }
            }
        } else {
            // Reset when leaving the tab so re-entry doesn't trigger a spurious
            // reload on a window that "changed" while we weren't watching.
            self.otp_last_window = None;
        }

        let animating = self.copied.is_some()
            || matches!(self.cap_tab, CapTab::Oath)
            || (matches!(self.cap_tab, CapTab::Overview)
                && self.oath.loaded
                && !self.oath.creds.is_empty())
            || (matches!(self.cap_tab, CapTab::Otp)
                && self
                    .otp
                    .rows
                    .iter()
                    .any(|r| r.type_str.eq_ignore_ascii_case("TOTP") && r.code.is_some()))
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
        // The bar height must track the zoom factor: at a larger text size the
        // glyph tile, labels and icons are all scaled up, and a fixed 52px panel
        // would clip them and let the left content overrun the right-hand
        // controls. Scale the base height by the live zoom so the bar grows with
        // its contents (clamped so it never collapses below the base).
        let zoom = theme::clamp_zoom(ctx.zoom_factor());
        let bar_h = (52.0 * zoom).max(52.0);
        egui::TopBottomPanel::top("bar")
            .exact_height(bar_h)
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
                            // Truncate so a long status never pushes the left
                            // content into the right-hand controls (overlap on
                            // small / zoomed layouts).
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(label.as_str())
                                        .font(theme::f_reg(12.0))
                                        .color(p.txt3),
                                )
                                .truncate(),
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
                            self.persist_settings();
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
                            self.persist_settings();
                        }
                        ui.add_space(10.0);
                        // "Text size" (issue #42): a compact UI-scale control.
                        // The slider drives egui's global zoom factor, which
                        // scales fonts AND painted symbols uniformly. A live "%"
                        // readout sits to the right (rightmost in this RTL row),
                        // with a "Reset" that appears only when off 100%.
                        self.text_size_control(ui, p);
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
                                self.persist_settings();
                            }
                        }
                    });
                });
            });
    }

    /// "Text size" control for the top bar (issue #42): a compact slider over
    /// egui's global zoom factor (80%–200%), with a live "%" readout and a
    /// "Reset" that surfaces only when the scale is off 100%. Writing the slider
    /// calls `set_zoom_factor`, so the whole UI — fonts and painted symbols —
    /// rescales uniformly. Lives inside the top bar's right-to-left layout, so
    /// widgets are added right-to-left: readout, slider, label, then Reset.
    fn text_size_control(&mut self, ui: &mut egui::Ui, p: &Palette) {
        // The slider lives inside the very UI it scales, so applying the zoom
        // *live* during a drag grows/shifts the slider track under the cursor
        // and runs the value away to the maximum. Fix: apply-on-release. While
        // dragging we edit a preview (`zoom_pending`) and leave the context
        // factor alone, so the UI stays stable; we commit `set_zoom_factor`
        // only when the drag ends. Keyboard/scroll zoom is unaffected (it has
        // no feedback loop) and keeps writing the context directly.
        //
        // The slider edits `factor`: the pending preview if a drag is in
        // flight, otherwise the committed live factor. The readout tracks the
        // same value so it follows the handle during the drag.
        let mut factor = self
            .zoom_pending
            .unwrap_or_else(|| theme::clamp_zoom(ui.ctx().zoom_factor()));

        // Live percentage readout (rightmost). FIXED width: as the value crosses
        // 99%→100% the glyph count goes 3→4; in the bar's right-to-left layout a
        // wider readout would shove the slider track left under the cursor and
        // make the value lurch (issue #42). `allocate_exact_size` reserves the
        // widest readout's box unconditionally (unlike `allocate_ui_with_layout`,
        // which advances by content width and so would still let the track move);
        // we then paint the value right-aligned inside it, so the slider geometry
        // is identical for "99%" and "100%".
        let pct = (factor * 100.0).round() as i32;
        let cell = ui.fonts(|f| {
            f.layout_no_wrap("888%".to_owned(), theme::f_sb(12.0), p.txt2)
                .size()
        });
        let (rrect, _) = ui.allocate_exact_size(
            egui::vec2(cell.x.ceil(), cell.y.ceil()),
            egui::Sense::hover(),
        );
        ui.painter().text(
            rrect.right_center(),
            egui::Align2::RIGHT_CENTER,
            format!("{pct}%"),
            theme::f_sb(12.0),
            p.txt2,
        );
        ui.add_space(6.0);

        // The slider itself. Style its track/handle to the palette so it reads
        // as part of the bar rather than egui's default blue.
        let style = ui.style_mut();
        style.visuals.widgets.inactive.bg_fill = p.raised2;
        style.visuals.widgets.hovered.bg_fill = theme::lighten(p.raised2, 0.08);
        style.visuals.widgets.active.bg_fill = p.accent;
        style.visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, p.txt2);
        style.visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, p.txt);
        style.spacing.slider_width = 92.0;

        // [+] / [−] steppers flanking the slider, each nudging the size by 1%
        // (0.01). The bar is laid out right-to-left, so to read "[−] slider [+]"
        // left-to-right we emit the [+] first, then the slider, then the [−].
        // A small closure paints one square stepper button and reports clicks.
        let step = |ui: &mut egui::Ui, glyph: &str| -> bool {
            let (rect, resp) =
                ui.allocate_exact_size(egui::vec2(16.0, 16.0), egui::Sense::click());
            let hot = resp.hovered();
            ui.painter().rect_filled(
                rect,
                3.0,
                if hot {
                    theme::lighten(p.raised2, 0.08)
                } else {
                    p.raised2
                },
            );
            ui.painter().text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                glyph,
                theme::f_sb(13.0),
                if hot { p.txt } else { p.txt2 },
            );
            resp.on_hover_cursor(egui::CursorIcon::PointingHand).clicked()
        };

        // [+] (rightmost of the trio in this RTL row).
        if step(ui, "+") {
            factor = theme::clamp_zoom(factor + 0.01);
            ui.ctx().set_zoom_factor(factor);
            self.zoom_pending = None;
        }
        ui.add_space(4.0);

        let resp = ui.add(
            egui::Slider::new(&mut factor, theme::ZOOM_MIN..=theme::ZOOM_MAX).show_value(false),
        );
        if resp.dragged() {
            // Mid-drag: preview only, don't touch the context (avoids runaway).
            self.zoom_pending = Some(theme::clamp_zoom(factor));
        } else if resp.drag_stopped() {
            // Drag released: commit the chosen size to the context once.
            ui.ctx().set_zoom_factor(theme::clamp_zoom(factor));
            self.zoom_pending = None;
        } else if resp.changed() {
            // Click/keyboard committed a value without a drag (e.g. arrow keys
            // or clicking the track): apply immediately, nothing to preview.
            ui.ctx().set_zoom_factor(theme::clamp_zoom(factor));
            self.zoom_pending = None;
        }
        resp.on_hover_text("Text size — scales the whole interface (Ctrl + / Ctrl − also work)");

        ui.add_space(4.0);
        // [−] (leftmost of the trio).
        if step(ui, "\u{2212}") {
            factor = theme::clamp_zoom(factor - 0.01);
            ui.ctx().set_zoom_factor(factor);
            self.zoom_pending = None;
        }

        ui.add_space(7.0);

        // Label.
        ui.label(
            egui::RichText::new("Text size")
                .font(theme::f_reg(12.0))
                .color(p.txt3),
        );

        // "Reset" appears only when we're off the default, so the chrome stays
        // quiet for users who never change it.
        if (factor - theme::ZOOM_DEFAULT).abs() > f32::EPSILON {
            ui.add_space(8.0);
            if ui
                .add(
                    egui::Label::new(
                        egui::RichText::new("Reset")
                            .font(theme::f_sb(12.0))
                            .color(p.accent),
                    )
                    .sense(egui::Sense::click()),
                )
                .on_hover_cursor(egui::CursorIcon::PointingHand)
                .clicked()
            {
                ui.ctx().set_zoom_factor(theme::ZOOM_DEFAULT);
                self.zoom_pending = None;
            }
        }
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
            .show(ctx, |ui| {
                match self.selected_device().cloned() {
                    None => self.empty_state(ui, p),
                    Some(dev) if dev.kind == DeviceKind::Token => self.molto_view(ui, p, &dev),
                    Some(dev) if dev.kind == DeviceKind::ProgToken => {
                        self.prog_view(ui, p, &dev)
                    }
                    Some(dev) => {
                        // Cap the content column to a readable width and center it.
                        // At wide window sizes a full-width card flings its label to
                        // the far left and its action to the far right, opening a dead
                        // gap in the middle that makes a row hard to read as one unit.
                        // A symmetric margin that grows past the base 26px once the
                        // pane exceeds ~920px keeps every pane (hero, tabs, cards) in
                        // one centered, legible column instead of stretching edge to
                        // edge — and removes the lopsided empty space on one side.
                        let hmargin = (((ui.available_width() - 920.0) * 0.5).max(26.0)).round();
                        egui::Frame::none()
                            .inner_margin(egui::Margin::symmetric(hmargin, 16.0))
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
    fn device_hero(&mut self, ui: &mut egui::Ui, p: &Palette, dev: &Device) {
        let mut open_rename = false;
        let mut do_save = false;
        let mut do_cancel = false;
        ui.horizontal(|ui| {
            glyph_tile(ui, 46.0, p.raised2, p.txt2, Some(dev.vendor.chars().next().unwrap_or('?').to_ascii_uppercase()));
            ui.add_space(12.0);
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    if self.rename_open {
                        let resp = ui.add_sized(
                            [200.0, 32.0],
                            egui::TextEdit::singleline(&mut self.rename_input)
                                .vertical_align(egui::Align::Center)
                                .hint_text("friendly-name"),
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
    fn cap_tabs(&mut self, ui: &mut egui::Ui, p: &Palette, dev: &Device) {
        ui.add_space(12.0);
        let mut next = None;
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 20.0;
            for t in dev.tabs() {
                let active = self.cap_tab == t;
                let color = if active { p.txt } else { p.txt3 };
                let resp = ui
                    .add(
                        egui::Label::new(
                            egui::RichText::new(cap_tab_label(t))
                                .font(theme::f_sb(13.5))
                                .color(color),
                        )
                        .sense(egui::Sense::click()),
                    )
                    .on_hover_cursor(egui::CursorIcon::PointingHand);
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

    /// Device-metadata card (FIDO Metadata Service): vendor icon, description,
    /// and certification status for the selected key's AAGUID. Shown only when
    /// the AAGUID is known to the MDS dataset. Renders nothing otherwise so it
    /// doesn't clutter the overview for unknown keys.
    fn mds_card(&mut self, ui: &mut egui::Ui, p: &Palette, _dev: &Device) {
        let Some(aaguid) = self.security_keys.info.as_ref().map(|i| i.aaguid) else {
            return;
        };
        // Look up first; clone the few fields we render so we don't hold an
        // immutable borrow of `self.mds` across the icon-texture mutation.
        let Some(entry) = self.mds.get(&aaguid).cloned() else {
            return;
        };
        let key = ui::aaguid::format_aaguid_pub(&aaguid);
        // Live versions reported by the device's authenticatorGetInfo, preferred
        // over the MDS statement's copy since they describe the actual unit.
        let device_versions: Vec<String> = self
            .security_keys
            .info
            .as_ref()
            .map(|i| i.versions.clone())
            .unwrap_or_default();

        // Decode + upload the icon once per AAGUID, cached in `self.mds_icon`.
        if let Some(icon_uri) = entry.icon.as_deref() {
            let need = self
                .mds_icon
                .as_ref()
                .map(|(k, _)| k != &key)
                .unwrap_or(true);
            if need {
                if let Some(img) = ui::mds::decode_icon(icon_uri) {
                    let tex = ui.ctx().load_texture(
                        format!("mds-icon-{key}"),
                        img,
                        egui::TextureOptions::LINEAR,
                    );
                    self.mds_icon = Some((key.clone(), tex));
                } else {
                    self.mds_icon = None;
                }
            }
        } else {
            self.mds_icon = None;
        }

        theme::card_frame(p).show(ui, |ui| {
            // Claim the full row width so this card matches the capability cards
            // below it (which stretch via their right-aligned "Manage" header).
            ui.set_min_width(ui.available_width());
            self.card_head_plain(ui, p, "Device metadata (FIDO MDS)", "mds");
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if let Some((k, tex)) = &self.mds_icon {
                    if k == &key {
                        let side = 44.0;
                        ui.add(
                            egui::Image::from_texture(tex)
                                .fit_to_exact_size(egui::vec2(side, side)),
                        );
                        ui.add_space(12.0);
                    }
                }
                ui.vertical(|ui| {
                    if !entry.description.is_empty() {
                        ui.label(
                            egui::RichText::new(&entry.description)
                                .font(theme::f_sb(14.0))
                                .color(p.txt),
                        );
                        ui.add_space(3.0);
                    }
                    // Certification badge (level highlighted) + advisory flag.
                    if let Some(label) = entry.certification_label() {
                        let (fg, bg) = if entry.is_advisory() {
                            (p.err, p.warn_soft())
                        } else {
                            (p.ok, p.ok_soft())
                        };
                        theme::pill(ui, &label, fg, bg);
                    }
                });
            });

            ui.add_space(12.0);

            // Short fields go into a two-column grid (label/value pairs, two
            // pairs per row) so the card fills its width and columns align.
            // Long fields (Versions, AAGUID) get their own full-width rows below.
            let mut pairs: Vec<(&str, String)> = Vec::new();
            if let Some(lvl) = entry.certification_level() {
                pairs.push(("Certification level", lvl.to_string()));
            }
            if let Some(date) = &entry.effective_date {
                let d = date.split(['T', ' ']).next().unwrap_or(date);
                pairs.push(("Certified since", d.to_string()));
            }
            if let Some(fam) = &entry.protocol_family {
                pairs.push(("Protocol family", fam.clone()));
            }

            // Lay the short fields out as tight "label  value" cells distributed
            // across the card width. Pick 1-3 columns based on available width so
            // each value sits right next to its label and the row stays filled.
            let avail = ui.available_width();
            let cols = if avail >= 760.0 {
                3
            } else if avail >= 470.0 {
                2
            } else {
                1
            };
            let cell_w = (avail - 18.0 * (cols as f32 - 1.0)) / cols as f32;
            egui::Grid::new("mds-meta-grid")
                .num_columns(cols)
                .spacing(egui::vec2(18.0, 10.0))
                .min_col_width(0.0)
                .show(ui, |ui| {
                    for (i, (k, v)) in pairs.iter().enumerate() {
                        mds_cell(ui, p, k, v, cell_w);
                        if (i + 1) % cols == 0 {
                            ui.end_row();
                        }
                    }
                    if pairs.len() % cols != 0 {
                        ui.end_row();
                    }
                });

            // Long, full-width fields.
            let versions = if !device_versions.is_empty() {
                device_versions
            } else {
                entry.mds_versions.clone()
            };
            ui.add_space(8.0);
            if !versions.is_empty() {
                mds_kv(ui, p, "Versions", &versions.join(", "));
            }
            mds_kv(ui, p, "AAGUID", &key);
        });
        ui.add_space(14.0);
    }

    /// Card header with no "Manage →" affordance (for read-only info cards).
    fn card_head_plain(
        &mut self,
        ui: &mut egui::Ui,
        p: &Palette,
        title: &str,
        topic: &'static str,
    ) {
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new(title)
                    .font(theme::f_sb(14.5))
                    .color(p.txt),
            );
            ui.add_space(6.0);
            self.help_dot(ui, p, topic);
        });
    }

    /// Overview tab: one summary card per capability, each with a `Manage →` jump.
    /// Scrolling comes from the shared capability-pane scroller in `central`.
    fn overview(&mut self, ui: &mut egui::Ui, p: &Palette, dev: &Device) {
        ui.vertical(|ui| {
            self.mds_card(ui, p, dev);
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
            if dev.caps.has(Caps::OTP) {
                ui.add_space(14.0);
                theme::card_frame(p).show(ui, |ui| {
                    if self.card_head(ui, p, "On-device OTP", "otp") {
                        self.cap_tab = CapTab::Otp;
                    }
                    ui.add_space(8.0);
                    if self.otp.loaded && !self.otp.rows.is_empty() {
                        let total = self.otp.rows.len();
                        for row in self.otp.rows.iter().take(2) {
                            let label = if row.account_name.is_empty() {
                                row.app_name.clone()
                            } else {
                                format!("{} \u{00B7} {}", row.app_name, row.account_name)
                            };
                            ui.horizontal(|ui| {
                                theme::pill(ui, row.type_str, p.txt2, p.raised2);
                                ui.label(
                                    egui::RichText::new(label)
                                        .font(theme::f_reg(13.0))
                                        .color(p.txt2),
                                );
                            });
                            ui.add_space(4.0);
                        }
                        if total > 2 {
                            ui.label(
                                egui::RichText::new(format!("+{} more entries", total - 2))
                                    .font(theme::f_reg(12.5))
                                    .color(p.txt3),
                            );
                        }
                    } else {
                        ui.label(
                            egui::RichText::new("Open On-device OTP to view stored entries.")
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
                    // Lock the whole session here, where the lock/unlock state
                    // lives — locking ends access to passkeys, fingerprints and
                    // settings alike, so it doesn't belong inside one panel.
                    if self.security_keys.session.is_some() {
                        ui.add_space(6.0);
                        if theme::button(ui, p, BtnKind::Ghost, "Lock").clicked() {
                            self.lock_session();
                        }
                    }
                });
            });
            ui.add_space(8.0);
            match pin_set {
                Some(true) => {
                    ui.horizontal(|ui| {
                        theme::pill(ui, "PIN set", p.ok, p.ok_soft());
                        ui.add_space(8.0);
                        // Reflect whether the key is already unlocked: once a
                        // session is open, the "unlock below" prompt is stale.
                        let hint = if self.security_keys.session.is_some() {
                            "This key has a PIN."
                        } else {
                            "This key has a PIN. Unlock below to manage it."
                        };
                        ui.label(
                            egui::RichText::new(hint)
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
                        if self.security_keys.info.is_none() && !self.busy() {
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
                            egui::RichText::new("4\u{2013}63 characters.")
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

        let unlocked = self.security_keys.session.is_some();
        let has_bio = self.bio_cmd_code().is_some();
        let supports_cfg = self
            .security_keys
            .info
            .as_ref()
            .and_then(|i| i.option("authnrCfg"))
            == Some(true);
        let has_large_blobs = self
            .security_keys
            .info
            .as_ref()
            .and_then(|i| i.option("largeBlobs"))
            == Some(true);

        // When the key has a PIN but isn't unlocked yet, show a standalone
        // unlock card. Unlocking gates passkeys, fingerprints, and settings
        // alike, so it lives above the tabs rather than inside the Passkeys tab.
        if pin_set == Some(true) && !unlocked {
            ui.add_space(14.0);
            let mut unlock = false;
            theme::card_frame(p).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new("Unlock this key")
                            .font(theme::f_sb(14.5))
                            .color(p.txt),
                    );
                    ui.add_space(6.0);
                    self.help_dot(ui, p, "unlock");
                });
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    let resp = ui.add_sized(
                        [220.0, 32.0],
                        egui::TextEdit::singleline(&mut self.security_keys.pin_input)
                            .vertical_align(egui::Align::Center)
                            .password(true)
                            .hint_text("Enter PIN to unlock this key"),
                    );
                    let submit = theme::button(ui, p, BtnKind::Primary, "Unlock").clicked();
                    if submit
                        || (resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)))
                    {
                        unlock = true;
                    }
                });
                let extras = match (has_bio, supports_cfg) {
                    (true, true) => "passkeys, fingerprints, and settings",
                    (true, false) => "passkeys and fingerprints",
                    (false, true) => "passkeys and settings",
                    (false, false) => "passkeys",
                };
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(format!("Unlock to manage {extras}."))
                        .font(theme::f_reg(11.5))
                        .color(p.txt3),
                );
            });
            if unlock {
                self.try_unlock();
            }

            // Read-only "Security policy" summary. getInfo is unauthenticated,
            // so the policy STATE is known without a PIN. Shown only on keys
            // that support authenticatorConfig (the same gate as the Settings
            // tab); the controls themselves still live in that tab post-unlock.
            if supports_cfg {
                let info = self.security_keys.info.as_ref();
                let always_uv = info.and_then(|i| i.option("alwaysUv"));
                let min_pin = info.and_then(|i| i.min_pin_length);
                let force_change = info.and_then(|i| i.force_pin_change);
                let ep = info.and_then(|i| i.option("ep"));

                ui.add_space(14.0);
                theme::card_frame(p).show(ui, |ui| {
                    ui.label(
                        egui::RichText::new("Security policy")
                            .font(theme::f_sb(14.5))
                            .color(p.txt),
                    );
                    ui.add_space(8.0);

                    let row = |ui: &mut egui::Ui, label: &str, value: String| {
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new(label)
                                    .font(theme::f_reg(12.0))
                                    .color(p.txt3),
                            );
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    ui.label(
                                        egui::RichText::new(value)
                                            .font(theme::f_sb(12.0))
                                            .color(p.txt),
                                    );
                                },
                            );
                        });
                    };

                    row(
                        ui,
                        "Always require user verification",
                        match always_uv {
                            Some(true) => "On".to_string(),
                            Some(false) => "Off".to_string(),
                            None => "\u{2014}".to_string(),
                        },
                    );
                    ui.add_space(4.0);
                    row(
                        ui,
                        "Minimum PIN length",
                        match min_pin {
                            Some(n) => n.to_string(),
                            None => "\u{2014}".to_string(),
                        },
                    );
                    if force_change == Some(true) {
                        ui.add_space(4.0);
                        row(ui, "Force PIN change", "Required on next use".to_string());
                    }
                    if let Some(ep) = ep {
                        ui.add_space(4.0);
                        row(
                            ui,
                            "Enterprise attestation",
                            if ep { "Enabled" } else { "Supported" }.to_string(),
                        );
                    }

                    ui.add_space(8.0);
                    ui.label(
                        egui::RichText::new("Unlock to change these.")
                            .font(theme::f_reg(11.5))
                            .color(p.txt3),
                    );
                });
            }
        }

        // Once unlocked, the sub-view tabs sit at the top of the content, each
        // owning its own panel below. Styled like the main capability tabs:
        // bold label with an accent underline on the active one.
        if unlocked {
            let mut tabs: Vec<(FidoSubview, &str)> = vec![(FidoSubview::Passkeys, "Passkeys")];
            if has_bio {
                tabs.push((FidoSubview::Fingerprints, "Fingerprints"));
            }
            if supports_cfg {
                tabs.push((FidoSubview::Settings, "Settings"));
            }
            if has_large_blobs {
                tabs.push((FidoSubview::LargeBlobs, "Storage"));
            }
            ui.add_space(14.0);
            let mut next: Option<FidoSubview> = None;
            // Paint an opaque surface strip here first (full content width,
            // fixed height covering the label row + its underline) so the row has
            // a clean backing - drawn before the labels, so it sits under them.
            {
                let top = ui.cursor().top();
                let strip = egui::Rect::from_min_max(
                    egui::pos2(ui.max_rect().left(), top - 4.0),
                    egui::pos2(ui.max_rect().right(), top + 30.0),
                );
                ui.painter().rect_filled(strip, 0.0, p.surface);
            }
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 20.0;
                for (view, label) in &tabs {
                    let active = self.security_keys.subview == *view;
                    let color = if active { p.txt } else { p.txt3 };
                    let resp = ui
                        .add(
                            egui::Label::new(
                                egui::RichText::new(*label)
                                    .font(theme::f_sb(13.5))
                                    .color(color),
                            )
                            .sense(egui::Sense::click()),
                        )
                        .on_hover_cursor(egui::CursorIcon::PointingHand);
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
                        next = Some(*view);
                    }
                }
            });
            if let Some(v) = next {
                self.security_keys.subview = v;
            }
        } else {
            self.security_keys.subview = FidoSubview::Passkeys;
        }
        let subview = self.security_keys.subview;

        // --- Passkeys panel: only when unlocked and the Passkeys tab is active. ---
        if unlocked && subview == FidoSubview::Passkeys {
            ui.add_space(14.0);
            let mut reload = false;
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
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if theme::button(ui, p, BtnKind::Default, "Reload").clicked() {
                            reload = true;
                        }
                    });
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
                }
            });
            if reload {
                self.refresh_credentials();
            }
            if let Some(id) = delete {
                self.delete_credential(id);
            }
        }

        // --- Fingerprint management (only when unlocked and the key supports it) ---
        if subview == FidoSubview::Fingerprints
            && self.security_keys.session.is_some()
            && self.bio_cmd_code().is_some()
        {
            ui.add_space(14.0);
            let mut do_enroll = false;
            let mut do_refresh_fp = false;
            let mut fp_rename_commit: Option<(Vec<u8>, String)> = None;
            theme::card_frame(p).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new("Fingerprints")
                            .font(theme::f_sb(14.5))
                            .color(p.txt),
                    );
                    ui.add_space(6.0);
                    self.help_dot(ui, p, "fingerprint");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if theme::button(ui, p, BtnKind::Default, "Reload").clicked() {
                            do_refresh_fp = true;
                        }
                    });
                });
                ui.add_space(8.0);

                // Enroll wizard now renders as a centered modal overlay
                // (render_enroll_dialog, called from the top-level render). Keep
                // the flag so the list below is hidden while a capture runs.
                let enrolling = self.security_keys.fp_progress.is_some();

                // The list (None until first read). Hidden while the wizard runs.
                if !enrolling {
                    match &self.security_keys.fingerprints {
                        None => {
                            ui.label(
                                egui::RichText::new("Click Reload to read enrolled fingerprints.")
                                    .font(theme::f_reg(13.0))
                                    .color(p.txt3),
                            );
                        }
                        Some(list) if list.is_empty() => {
                            ui.label(
                                egui::RichText::new("No fingerprints enrolled yet.")
                                    .font(theme::f_reg(13.0))
                                    .color(p.txt3),
                            );
                        }
                        Some(list) => {
                            for e in list.iter() {
                                let id = e.template_id.clone();
                                ui.horizontal(|ui| {
                                    ui.monospace(hex_short(&id));
                                    // Inline rename editor for this row, or the name + buttons.
                                    let renaming = self
                                        .security_keys
                                        .fp_rename
                                        .as_ref()
                                        .is_some_and(|(rid, _)| rid == &id);
                                    if renaming {
                                        if let Some((_, buf)) =
                                            self.security_keys.fp_rename.as_mut()
                                        {
                                            ui.add_sized(
                                                [160.0, 32.0],
                                                egui::TextEdit::singleline(buf)
                                                    .vertical_align(egui::Align::Center),
                                            );
                                        }
                                        if theme::button(ui, p, BtnKind::Primary, "Save").clicked()
                                        {
                                            if let Some((rid, buf)) =
                                                self.security_keys.fp_rename.take()
                                            {
                                                fp_rename_commit = Some((rid, buf));
                                            }
                                        }
                                        if theme::button(ui, p, BtnKind::Ghost, "Cancel").clicked()
                                        {
                                            self.security_keys.fp_rename = None;
                                        }
                                    } else {
                                        let name =
                                            e.friendly_name.as_deref().unwrap_or("(unnamed)");
                                        ui.label(name);
                                        ui.with_layout(
                                            egui::Layout::right_to_left(egui::Align::Center),
                                            |ui| {
                                                if theme::button(ui, p, BtnKind::Ghost, "Delete")
                                                    .clicked()
                                                {
                                                    self.security_keys.fp_confirm_delete =
                                                        Some(id.clone());
                                                }
                                                if theme::button(ui, p, BtnKind::Ghost, "Rename")
                                                    .clicked()
                                                {
                                                    self.security_keys.fp_rename = Some((
                                                        id.clone(),
                                                        e.friendly_name.clone().unwrap_or_default(),
                                                    ));
                                                }
                                            },
                                        );
                                    }
                                });
                            }
                        }
                    }
                }

                ui.add_space(10.0);
                // Enroll a new fingerprint (hidden while a wizard is running).
                if !enrolling {
                    ui.horizontal(|ui| {
                        ui.add_sized(
                            [160.0, 32.0],
                            egui::TextEdit::singleline(&mut self.security_keys.fp_new_name)
                                .vertical_align(egui::Align::Center)
                                .hint_text("name (optional)"),
                        );
                        if theme::button(ui, p, BtnKind::Primary, "Enroll new\u{2026}").clicked() {
                            do_enroll = true;
                        }
                    });
                    ui.label(
                        egui::RichText::new(
                            "Enrolling asks you to touch the sensor several times. \
                             Keyboard-HID is not needed; this uses the FIDO interface.",
                        )
                        .font(theme::f_reg(11.0))
                        .color(p.txt3),
                    );
                }

                // --- Delete confirmation ("Are you sure?") ---
            });
            if do_refresh_fp {
                self.refresh_fingerprints();
            }
            if do_enroll {
                self.enroll_fingerprint();
            }
            if let Some((id, name)) = fp_rename_commit {
                self.rename_fingerprint(id, name);
            }
        }

        // --- Settings sub-view: advanced config + the danger reset card. ---
        if subview == FidoSubview::Settings {
            // Advanced (authenticatorConfig) security-policy controls.
            self.render_fido_advanced(ui, p);

            // Danger: reset key (typed-confirm modal stays).
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
                            if theme::button(ui, p, BtnKind::Danger, "Reset key\u{2026}").clicked()
                            {
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

        if subview == FidoSubview::LargeBlobs {
            self.render_large_blobs(ui, p);
        }
    }

    /// Append a keyroost text note to the array and write it back. Needs the
    /// unlocked session's PIN (the write path requires a Large-Blob-Write token).
    fn add_large_blob_note(&mut self, text: String) {
        let Some(target) = self.selected_fido_target() else {
            self.security_keys.lb_status = Some("No FIDO key selected.".into());
            return;
        };
        let Some(session) = self.security_keys.session.as_ref() else {
            self.security_keys.lb_status =
                Some("Unlock the key with your PIN first to add data.".into());
            return;
        };
        let pin = session.pin.clone();
        // Start from the currently-loaded array if we have one, else an empty
        // array (read fresh inside the worker to avoid clobbering RP entries we
        // never loaded).
        let loaded = self.security_keys.large_blobs.clone();

        self.spawn_job("Saving to large blobs\u{2026}", move || {
            let result = (|| -> Result<keyroost_ctap::large_blobs::LargeBlobArray, String> {
                let (mut dev, cbor, _init) = open_fido(&target)?;
                if !cbor {
                    return Err("device is U2F-only".into());
                }
                let info = keyroost_ctap::get_info(&mut dev).map_err(|e| e.to_string())?;

                // Always re-read immediately before writing so we append onto the
                // authenticator's current array (not a stale cached copy), which
                // protects any RP entries written since our last load.
                let current =
                    keyroost_ctap::large_blobs::read(&mut dev, &info).map_err(|e| e.to_string())?;
                let _ = loaded; // cached copy only informs the UI, not the write

                let token = keyroost_ctap::client_pin::get_pin_uv_auth_token(
                    &mut dev,
                    &pin,
                    &info,
                    keyroost_ctap::client_pin::permissions::LARGE_BLOB_WRITE,
                )
                .map_err(|e| e.to_string())?;

                let updated = current.with_text_note(&text);
                let serialized = updated.serialize_with_checksum();
                keyroost_ctap::large_blobs::write(&mut dev, &info, &token, &serialized)
                    .map_err(|e| e.to_string())?;

                keyroost_ctap::large_blobs::read(&mut dev, &info).map_err(|e| e.to_string())
            })();

            Box::new(move |app: &mut App| match result {
                Ok(array) => {
                    let n = array.entries.len();
                    app.security_keys.large_blobs = Some(array);
                    app.security_keys.lb_new_text.clear();
                    app.security_keys.lb_show_add = false;
                    app.security_keys.lb_status = Some(format!(
                        "Saved. {n} entr{} total.",
                        if n == 1 { "y" } else { "ies" }
                    ));
                    app.security_keys.error = None;
                }
                Err(e) => {
                    app.security_keys.lb_status = Some(format!("Save failed: {e}"));
                }
            })
        });
    }

    /// Replace the keyroost note at `idx` with `text` and write the array back.
    /// Refuses if the entry is not a keyroost note. Needs the session PIN.
    fn edit_large_blob_note(&mut self, idx: usize, text: String) {
        let Some(target) = self.selected_fido_target() else {
            self.security_keys.lb_status = Some("No FIDO key selected.".into());
            return;
        };
        let Some(session) = self.security_keys.session.as_ref() else {
            self.security_keys.lb_status =
                Some("Unlock the key with your PIN first to edit notes.".into());
            return;
        };
        let pin = session.pin.clone();

        self.spawn_job("Saving edit to large blobs\u{2026}", move || {
            let result = (|| -> Result<keyroost_ctap::large_blobs::LargeBlobArray, String> {
                let (mut dev, cbor, _init) = open_fido(&target)?;
                if !cbor {
                    return Err("device is U2F-only".into());
                }
                let info = keyroost_ctap::get_info(&mut dev).map_err(|e| e.to_string())?;

                // Re-read live so we edit the authenticator's current array and
                // never clobber RP entries written since our last load.
                let current =
                    keyroost_ctap::large_blobs::read(&mut dev, &info).map_err(|e| e.to_string())?;
                let updated = current.with_replaced_note(idx, &text).ok_or(
                    "that entry is not an editable keyroost note (it may have \
                            changed on the key — reload and try again)",
                )?;

                let token = keyroost_ctap::client_pin::get_pin_uv_auth_token(
                    &mut dev,
                    &pin,
                    &info,
                    keyroost_ctap::client_pin::permissions::LARGE_BLOB_WRITE,
                )
                .map_err(|e| e.to_string())?;

                let serialized = updated.serialize_with_checksum();
                keyroost_ctap::large_blobs::write(&mut dev, &info, &token, &serialized)
                    .map_err(|e| e.to_string())?;

                keyroost_ctap::large_blobs::read(&mut dev, &info).map_err(|e| e.to_string())
            })();

            Box::new(move |app: &mut App| match result {
                Ok(array) => {
                    app.security_keys.large_blobs = Some(array);
                    app.security_keys.lb_editing = None;
                    app.security_keys.lb_edit_text.clear();
                    app.security_keys.lb_status = Some("Note updated.".into());
                    app.security_keys.error = None;
                }
                Err(e) => {
                    app.security_keys.lb_status = Some(format!("Edit failed: {e}"));
                }
            })
        });
    }

    /// Read the large-blob array from the selected key (no PIN required) and
    /// cache it. Runs synchronously — a read is one or two small fragments.
    fn load_large_blobs(&mut self) {
        let Some(target) = self.selected_fido_target() else {
            self.security_keys.lb_status = Some("No FIDO key selected.".into());
            return;
        };
        let result = (|| -> Result<keyroost_ctap::large_blobs::LargeBlobArray, String> {
            let (mut dev, cbor, _init) = open_fido(&target)?;
            if !cbor {
                return Err("device is U2F-only".into());
            }
            let info = keyroost_ctap::get_info(&mut dev).map_err(|e| e.to_string())?;
            keyroost_ctap::large_blobs::read(&mut dev, &info).map_err(|e| e.to_string())
        })();
        match result {
            Ok(array) => {
                let n = array.entries.len();
                self.security_keys.large_blobs = Some(array);
                self.security_keys.lb_selected = None;
                self.security_keys.lb_status = Some(format!(
                    "Loaded {n} entr{}.",
                    if n == 1 { "y" } else { "ies" }
                ));
            }
            Err(e) => {
                self.security_keys.lb_status = Some(format!("Load failed: {e}"));
            }
        }
    }

    /// Delete entry `idx`, re-serialize the remaining entries with a fresh
    /// checksum, and write the array back. Needs a Large-Blob-Write token, which
    /// we derive from the unlocked session's PIN. Runs on the worker thread.
    fn delete_large_blob_entry(&mut self, idx: usize) {
        let Some(target) = self.selected_fido_target() else {
            self.security_keys.lb_status = Some("No FIDO key selected.".into());
            return;
        };
        let Some(array) = self.security_keys.large_blobs.clone() else {
            return;
        };
        let Some(session) = self.security_keys.session.as_ref() else {
            self.security_keys.lb_status =
                Some("Unlock the key with your PIN first to modify large blobs.".into());
            return;
        };
        if idx >= array.entries.len() {
            return;
        }
        let pin = session.pin.clone();

        // Capture the *target entry* (not its cached index). The actual removal
        // happens against a fresh read of the live array inside the worker, so an
        // RP entry written to the key since our last load is preserved and a
        // position shift can't delete the wrong entry. Matches the re-read shape
        // of `add_large_blob_note` / `edit_large_blob_note` / the CLI delete.
        let target_entry = array.entries[idx].clone();

        self.spawn_job("Updating large blobs\u{2026}", move || {
            let result = (|| -> Result<keyroost_ctap::large_blobs::LargeBlobArray, String> {
                let (mut dev, cbor, _init) = open_fido(&target)?;
                if !cbor {
                    return Err("device is U2F-only".into());
                }
                let info = keyroost_ctap::get_info(&mut dev).map_err(|e| e.to_string())?;
                let token = keyroost_ctap::client_pin::get_pin_uv_auth_token(
                    &mut dev,
                    &pin,
                    &info,
                    keyroost_ctap::client_pin::permissions::LARGE_BLOB_WRITE,
                )
                .map_err(|e| e.to_string())?;

                // Re-read the live array and remove the matching entry from it
                // (by content, since `LargeBlobEntry` is `PartialEq`).
                let live =
                    keyroost_ctap::large_blobs::read(&mut dev, &info).map_err(|e| e.to_string())?;
                let Some(pos) = live.entries.iter().position(|e| *e == target_entry) else {
                    return Err(
                        "that entry is no longer on the key (its storage changed since it was \
                         loaded) \u{2014} nothing was deleted; reload and try again."
                            .into(),
                    );
                };
                let mut entries = live.entries;
                entries.remove(pos);
                let updated = keyroost_ctap::large_blobs::LargeBlobArray {
                    entries,
                    raw_array: Vec::new(),
                };
                let serialized = updated.serialize_with_checksum();
                keyroost_ctap::large_blobs::write(&mut dev, &info, &token, &serialized)
                    .map_err(|e| e.to_string())?;

                // Read back so the view reflects the authenticator's actual state.
                keyroost_ctap::large_blobs::read(&mut dev, &info).map_err(|e| e.to_string())
            })();

            Box::new(move |app: &mut App| match result {
                Ok(array) => {
                    let n = array.entries.len();
                    app.security_keys.large_blobs = Some(array);
                    app.security_keys.lb_selected = None;
                    app.security_keys.lb_status = Some(format!("Entry deleted. {n} remaining."));
                    app.security_keys.error = None;
                }
                Err(e) => {
                    app.security_keys.lb_status = Some(format!("Update failed: {e}"));
                }
            })
        });
    }

    /// Wipe the entire large-blob array: serialize an empty array with a fresh
    /// checksum and write it back. This is what a FIDO reset does NOT do, so it
    /// is the only way to erase plaintext notes that survive a reset. Mirrors
    /// `delete_large_blob_entry` but clears every entry. Needs a Large-Blob-Write
    /// token derived from the unlocked session's PIN. Runs on the worker thread.
    fn clear_large_blob_storage(&mut self) {
        let Some(target) = self.selected_fido_target() else {
            self.security_keys.lb_status = Some("No FIDO key selected.".into());
            return;
        };
        if self.security_keys.large_blobs.is_none() {
            return;
        }
        let Some(session) = self.security_keys.session.as_ref() else {
            self.security_keys.lb_status =
                Some("Unlock the key with your PIN first to modify large blobs.".into());
            return;
        };
        let pin = session.pin.clone();

        // Wipe all entries: an empty array, re-serialized with checksum inside
        // the worker.
        let new_entries = Vec::new();

        self.spawn_job("Clearing large blobs\u{2026}", move || {
            let result = (|| -> Result<keyroost_ctap::large_blobs::LargeBlobArray, String> {
                let (mut dev, cbor, _init) = open_fido(&target)?;
                if !cbor {
                    return Err("device is U2F-only".into());
                }
                let info = keyroost_ctap::get_info(&mut dev).map_err(|e| e.to_string())?;
                let token = keyroost_ctap::client_pin::get_pin_uv_auth_token(
                    &mut dev,
                    &pin,
                    &info,
                    keyroost_ctap::client_pin::permissions::LARGE_BLOB_WRITE,
                )
                .map_err(|e| e.to_string())?;

                let updated = keyroost_ctap::large_blobs::LargeBlobArray {
                    entries: new_entries,
                    raw_array: Vec::new(),
                };
                let serialized = updated.serialize_with_checksum();
                keyroost_ctap::large_blobs::write(&mut dev, &info, &token, &serialized)
                    .map_err(|e| e.to_string())?;

                // Read back so the view reflects the authenticator's actual state.
                keyroost_ctap::large_blobs::read(&mut dev, &info).map_err(|e| e.to_string())
            })();

            Box::new(move |app: &mut App| match result {
                Ok(array) => {
                    let n = array.entries.len();
                    app.security_keys.large_blobs = Some(array);
                    app.security_keys.lb_selected = None;
                    app.security_keys.lb_status =
                        Some(format!("Storage cleared. {n} entries remaining."));
                    app.security_keys.error = None;
                }
                Err(e) => {
                    app.security_keys.lb_status = Some(format!("Clear failed: {e}"));
                }
            })
        });
    }

    /// Large-blob array viewer/editor (CTAP authenticatorLargeBlobs 0x0C).
    ///
    /// Reads the key-global serialized array (no PIN needed) and shows it both
    /// as a structured entry list and as a hex/ASCII dump. Deleting an entry
    /// re-serializes the remaining entries, recomputes the 16-byte checksum
    /// trailer, and writes the whole array back (which needs a PIN, because the
    /// write path requires a token with the Large Blob Write permission).
    fn render_large_blobs(&mut self, ui: &mut egui::Ui, p: &Palette) {
        ui.add_space(14.0);

        // Auto-load the array the first time this tab is shown, so entries
        // appear without a manual Load click. The flag stops a failed read from
        // retrying every frame; Reload remains available to refresh on demand.
        if !self.security_keys.lb_autoloaded && self.security_keys.large_blobs.is_none() {
            self.security_keys.lb_autoloaded = true;
            self.load_large_blobs();
        }

        // Header + Load/Reload control.
        let mut do_load = false;
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new("Large blob storage")
                    .font(theme::f_sb(14.5))
                    .color(p.txt),
            );
            ui.add_space(6.0);
            self.help_dot(ui, p, "large_blobs");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let label = if self.security_keys.large_blobs.is_some() {
                    "Reload"
                } else {
                    "Load"
                };
                if theme::button(ui, p, BtnKind::Ghost, label).clicked() {
                    do_load = true;
                }
                ui.add_space(8.0);
                let add_label = if self.security_keys.lb_show_add {
                    "Close"
                } else {
                    "Add"
                };
                if theme::button(ui, p, BtnKind::Ghost, add_label).clicked() {
                    self.security_keys.lb_show_add = !self.security_keys.lb_show_add;
                }
                // "Clear all storage" wipes every entry — the only way to erase
                // plaintext notes a FIDO reset leaves behind. Show it only when
                // there is something to clear and the session is unlocked (the
                // write needs a PIN-derived token, like Delete). The first click
                // arms a confirm; the confirmed click fires below.
                let entry_count = self
                    .security_keys
                    .large_blobs
                    .as_ref()
                    .map(|a| a.entries.len())
                    .unwrap_or(0);
                let unlocked = self.security_keys.session.is_some();
                if entry_count > 0 && unlocked {
                    ui.add_space(8.0);
                    if theme::button(ui, p, BtnKind::Danger, "Clear all storage").clicked() {
                        self.security_keys.lb_confirm_clear = true;
                    }
                }
            });
        });
        ui.add_space(4.0);
        ui.label(
            egui::RichText::new(
                "This store is readable by anyone holding the key and is meant for \
                 RP-encrypted data \u{2014} not a place for plaintext secrets.",
            )
            .font(theme::f_reg(11.5))
            .color(p.txt3),
        );

        if let Some(status) = &self.security_keys.lb_status {
            ui.add_space(6.0);
            ui.label(
                egui::RichText::new(status)
                    .font(theme::f_reg(12.0))
                    .color(p.txt2),
            );
        }

        if do_load {
            self.load_large_blobs();
        }

        // Add-a-note composer — only when the user clicked Add. Requires an
        // unlocked session (the write needs a PIN-derived token); show a hint
        // instead when locked.
        if self.security_keys.lb_show_add {
            ui.add_space(12.0);
            theme::card_frame(p).show(ui, |ui| {
                ui.label(
                    egui::RichText::new("Add a text note")
                        .font(theme::f_sb(13.0))
                        .color(p.txt),
                );
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(
                        "Stored as a keyroost entry you can read back here. It is NOT \
                         encrypted and is visible to anyone holding the key.",
                    )
                    .font(theme::f_reg(11.0))
                    .color(p.txt3),
                );
                ui.add_space(6.0);
                ui.add(
                    egui::TextEdit::multiline(&mut self.security_keys.lb_new_text)
                        .desired_rows(2)
                        .desired_width(f32::INFINITY)
                        .hint_text("Type a note to store on the key\u{2026}"),
                );
                ui.add_space(6.0);
                let unlocked = self.security_keys.session.is_some();
                let has_text = !self.security_keys.lb_new_text.trim().is_empty();
                ui.horizontal(|ui| {
                    let add = theme::button(ui, p, BtnKind::Primary, "Add note");
                    if add.clicked() && unlocked && has_text {
                        let text = self.security_keys.lb_new_text.clone();
                        self.add_large_blob_note(text);
                    }
                    if !unlocked {
                        ui.label(
                            egui::RichText::new("Unlock with your PIN to save.")
                                .font(theme::f_reg(11.0))
                                .color(p.txt3),
                        );
                    }
                });
            });
        }

        // Render the loaded array, if any.
        let Some(array) = self.security_keys.large_blobs.clone() else {
            return;
        };

        ui.add_space(10.0);
        if array.entries.is_empty() {
            ui.label(
                egui::RichText::new("The large-blob array is empty.")
                    .font(theme::f_reg(12.5))
                    .color(p.txt2),
            );
            return;
        }

        let mut delete_request: Option<usize> = None;
        let mut start_edit: Option<(usize, String)> = None;
        let mut save_edit: Option<(usize, String)> = None;
        let mut cancel_edit = false;
        let selected = self.security_keys.lb_selected;
        let editing = self.security_keys.lb_editing;
        for (idx, entry) in array.entries.iter().enumerate() {
            theme::card_frame(p).show(ui, |ui| {
                let note_text = entry.as_text();
                ui.horizontal(|ui| {
                    let title = if note_text.is_some() {
                        format!("Note {}", idx + 1)
                    } else {
                        format!("Entry {}", idx + 1)
                    };
                    ui.label(
                        egui::RichText::new(title)
                            .font(theme::f_sb(13.0))
                            .color(p.txt),
                    );
                    ui.add_space(8.0);
                    let meta = if note_text.is_some() {
                        "keyroost text note".to_string()
                    } else {
                        format!(
                            "{} bytes ciphertext \u{00b7} {}-byte nonce \u{00b7} origSize {} \u{00b7} relying-party data",
                            entry.ciphertext.len(),
                            entry.nonce.len(),
                            entry.orig_size,
                        )
                    };
                    ui.label(
                        egui::RichText::new(meta)
                            .font(theme::f_reg(11.5))
                            .color(p.txt3),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if theme::button(ui, p, BtnKind::Danger, "Delete").clicked() {
                            delete_request = Some(idx);
                        }
                        let is_open = selected == Some(idx);
                        let toggle = if is_open { "Hide bytes" } else { "View bytes" };
                        if theme::button(ui, p, BtnKind::Ghost, toggle).clicked() {
                            self.security_keys.lb_selected =
                                if is_open { None } else { Some(idx) };
                        }
                        // Edit only applies to keyroost's own notes.
                        if note_text.is_some()
                            && editing != Some(idx)
                            && theme::button(ui, p, BtnKind::Ghost, "Edit").clicked()
                        {
                            start_edit = Some((idx, note_text.clone().unwrap_or_default()));
                        }
                    });
                });
                // keyroost notes: inline editor when editing this entry, else
                // the decoded text read-only.
                if editing == Some(idx) {
                    ui.add_space(6.0);
                    ui.add(
                        egui::TextEdit::multiline(&mut self.security_keys.lb_edit_text)
                            .desired_rows(2)
                            .desired_width(f32::INFINITY),
                    );
                    ui.add_space(6.0);
                    let unlocked = self.security_keys.session.is_some();
                    let has_text =
                        !self.security_keys.lb_edit_text.trim().is_empty();
                    ui.horizontal(|ui| {
                        if theme::button(ui, p, BtnKind::Primary, "Save").clicked()
                            && unlocked
                            && has_text
                        {
                            save_edit = Some((idx, self.security_keys.lb_edit_text.clone()));
                        }
                        if theme::button(ui, p, BtnKind::Ghost, "Cancel").clicked() {
                            cancel_edit = true;
                        }
                        if !unlocked {
                            ui.label(
                                egui::RichText::new("Unlock with your PIN to save.")
                                    .font(theme::f_reg(11.0))
                                    .color(p.txt3),
                            );
                        }
                    });
                } else if let Some(text) = &note_text {
                    ui.add_space(6.0);
                    ui.label(
                        egui::RichText::new(text)
                            .font(theme::f_reg(12.5))
                            .color(p.txt),
                    );
                }
                if selected == Some(idx) {
                    ui.add_space(8.0);
                    Self::hex_ascii_view(ui, p, &entry.ciphertext);
                }
            });
            ui.add_space(8.0);
        }

        // Apply edit-related actions collected during the loop (kept outside it
        // to avoid borrowing `self` while iterating the cloned array).
        if let Some((idx, text)) = start_edit {
            self.security_keys.lb_editing = Some(idx);
            self.security_keys.lb_edit_text = text;
        }
        if cancel_edit {
            self.security_keys.lb_editing = None;
            self.security_keys.lb_edit_text.clear();
        }
        if let Some((idx, text)) = save_edit {
            self.edit_large_blob_note(idx, text);
        }

        // A delete is a write; confirm before touching the key.
        if let Some(idx) = delete_request {
            self.security_keys.lb_confirm_delete = Some(idx);
        }
        if let Some(idx) = self.security_keys.lb_confirm_delete {
            ui.add_space(6.0);
            theme::card_frame(p)
                .stroke(egui::Stroke::new(1.0, theme::tint(p.err, 90)))
                .show(ui, |ui| {
                    ui.label(
                        egui::RichText::new(format!(
                            "Delete entry {} and rewrite the array? Requires your PIN.",
                            idx + 1
                        ))
                        .font(theme::f_reg(12.5))
                        .color(p.txt),
                    );
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if theme::button(ui, p, BtnKind::Danger, "Delete entry").clicked() {
                            self.security_keys.lb_confirm_delete = None;
                            self.delete_large_blob_entry(idx);
                        }
                        if theme::button(ui, p, BtnKind::Ghost, "Cancel").clicked() {
                            self.security_keys.lb_confirm_delete = None;
                        }
                    });
                });
        }

        // Clearing all storage is irreversible and wipes every note, so the
        // first click only arms this confirm; the user must confirm explicitly.
        if self.security_keys.lb_confirm_clear {
            let n = array.entries.len();
            ui.add_space(6.0);
            theme::card_frame(p)
                .stroke(egui::Stroke::new(1.0, theme::tint(p.err, 90)))
                .show(ui, |ui| {
                    ui.label(
                        egui::RichText::new(format!(
                            "Wipe all {n} entr{} from this key? This erases every entry \u{2014} \
                             including any relying-party data (e.g. SSH certificates, sign-in \
                             records), not just keyroost notes. Cannot be undone; requires your PIN.",
                            if n == 1 { "y" } else { "ies" },
                        ))
                        .font(theme::f_reg(12.5))
                        .color(p.txt),
                    );
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if theme::button(
                            ui,
                            p,
                            BtnKind::Danger,
                            &format!(
                                "Confirm \u{2014} wipe all {n} entr{}",
                                if n == 1 { "y" } else { "ies" }
                            ),
                        )
                        .clicked()
                        {
                            self.security_keys.lb_confirm_clear = false;
                            self.clear_large_blob_storage();
                        }
                        if theme::button(ui, p, BtnKind::Ghost, "Cancel").clicked() {
                            self.security_keys.lb_confirm_clear = false;
                        }
                    });
                });
        }
    }

    /// Render a byte slice as a side-by-side hex + ASCII dump, 16 bytes/row.
    fn hex_ascii_view(ui: &mut egui::Ui, p: &Palette, bytes: &[u8]) {
        let mut text = String::new();
        for (i, row) in bytes.chunks(16).enumerate() {
            let mut hex = String::new();
            let mut ascii = String::new();
            for (j, b) in row.iter().enumerate() {
                hex.push_str(&format!("{:02x} ", b));
                if j == 7 {
                    hex.push(' ');
                }
                ascii.push(if b.is_ascii_graphic() || *b == b' ' {
                    *b as char
                } else {
                    '.'
                });
            }
            // Pad short final rows so the ASCII column lines up.
            let width = 16 * 3 + 1;
            while hex.len() < width {
                hex.push(' ');
            }
            text.push_str(&format!("{:08x}  {} |{}|\n", i * 16, hex, ascii));
        }
        ui.add(
            egui::Label::new(
                egui::RichText::new(text.trim_end())
                    .font(theme::f_mono(11.5))
                    .color(p.txt2),
            )
            .wrap(),
        );
    }

    /// Advanced security-policy view (CTAP authenticatorConfig). Grouped here,
    /// behind the overflow menu, because several of these are irreversible and
    /// shouldn't sit alongside everyday controls. Each action takes the device
    /// PIN at apply time (config needs its own permissioned token) and the
    /// irreversible ones require an explicit typed confirmation.
    fn render_fido_advanced(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let always_uv = self
            .security_keys
            .info
            .as_ref()
            .and_then(|i| i.option("alwaysUv"));
        // Enterprise attestation support: the `ep` option is present (true =
        // already enabled, false = supported but off) on keys that can do it,
        // and absent entirely on keys that can't. Hide the row when unsupported.
        let ep = self
            .security_keys
            .info
            .as_ref()
            .and_then(|i| i.option("ep"));
        let supports_ep = ep.is_some();
        let ep_enabled = ep == Some(true);
        let min_pin_length = self
            .security_keys
            .info
            .as_ref()
            .and_then(|i| i.min_pin_length);

        ui.add_space(14.0);
        theme::card_frame(p).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("Security policy")
                        .font(theme::f_sb(14.5))
                        .color(p.txt),
                );
                ui.add_space(6.0);
                self.help_dot(ui, p, "settings");
            });
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(
                    "These change the key's security policy. Some are irreversible \
                     without a full reset \u{2014} read each note before applying.",
                )
                .font(theme::f_reg(12.0))
                .color(p.txt3),
            );
            ui.add_space(10.0);

            // Each row: a description + a button that arms the confirm dialog.
            let mut arm: Option<AdvancedAction> = None;

            // Always-UV (reversible toggle).
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label(
                        egui::RichText::new("Always require user verification")
                            .font(theme::f_sb(13.0))
                            .color(p.txt),
                    );
                    let state = match always_uv {
                        Some(true) => "Currently on \u{2014} every sign-in needs PIN or biometric.",
                        Some(false) => "Currently off.",
                        None => "State unknown.",
                    };
                    ui.label(
                        egui::RichText::new(state)
                            .font(theme::f_reg(11.5))
                            .color(p.txt3),
                    );
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if theme::button(ui, p, BtnKind::Default, "Toggle").clicked() {
                        arm = Some(AdvancedAction::ToggleAlwaysUv);
                    }
                });
            });
            ui.add_space(8.0);

            // Set minimum PIN length (one-way).
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label(
                        egui::RichText::new("Set minimum PIN length")
                            .font(theme::f_sb(13.0))
                            .color(p.txt),
                    );
                    ui.label(
                        egui::RichText::new("Can only be raised, never lowered without a reset.")
                            .font(theme::f_reg(11.5))
                            .color(p.txt3),
                    );
                    let current = match min_pin_length {
                        Some(n) => format!("Current minimum: {} characters", n),
                        None => "Current minimum: \u{2014}".to_string(),
                    };
                    ui.label(
                        egui::RichText::new(current)
                            .font(theme::f_reg(11.5))
                            .color(p.txt3),
                    );
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if theme::button(ui, p, BtnKind::Default, "Set\u{2026}").clicked() {
                        arm = Some(AdvancedAction::SetMinPin);
                    }
                });
            });
            ui.add_space(8.0);

            // Force PIN change.
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label(
                        egui::RichText::new("Force PIN change on next use")
                            .font(theme::f_sb(13.0))
                            .color(p.txt),
                    );
                    ui.label(
                        egui::RichText::new("Useful before handing the key to someone else.")
                            .font(theme::f_reg(11.5))
                            .color(p.txt3),
                    );
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if theme::button(ui, p, BtnKind::Default, "Force\u{2026}").clicked() {
                        arm = Some(AdvancedAction::ForcePinChange);
                    }
                });
            });
            // Enterprise attestation (one-way) — only shown on keys that
            // support it (the `ep` getInfo option is present).
            if supports_ep {
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(
                            egui::RichText::new("Enable enterprise attestation")
                                .font(theme::f_sb(13.0))
                                .color(p.txt),
                        );
                        let note = if ep_enabled {
                            "Currently on. Disabling it again requires a device reset."
                        } else {
                            "One-way: disabling it again requires a device reset."
                        };
                        ui.label(
                            egui::RichText::new(note)
                                .font(theme::f_reg(11.5))
                                .color(p.txt3),
                        );
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ep_enabled {
                            // Already enabled: nothing actionable, show a pill.
                            theme::pill(ui, "Enabled", p.ok, p.ok_soft());
                        } else if theme::button(ui, p, BtnKind::Danger, "Enable\u{2026}").clicked()
                        {
                            arm = Some(AdvancedAction::EnterpriseAttestation);
                        }
                    });
                });
            }

            if let Some(action) = arm {
                self.security_keys.advanced = Some(AdvancedDialog {
                    action,
                    ..Default::default()
                });
                self.security_keys.error = None;
            }
        });
    }

    /// Inline confirm + PIN entry for an armed Advanced action.
    /// Confirm/apply overlay for an armed Advanced action. Rendered as a
    /// centered modal window (like the reset dialog) so it floats over the
    /// Settings panel instead of pushing the list down.
    /// Shared centered-modal chrome used by the Settings, fingerprint-delete,
    /// and enrollment dialogs so they all look identical: no native title bar,
    /// a custom frame (pop fill, line stroke, drop shadow, 20px padding), a
    /// title at button-font size with a painted X close, and Esc-to-dismiss.
    /// `body` draws the dialog contents. Returns true if the X or Esc was used
    /// (the caller dismisses its own state).
    fn modal_window(
        ctx: &egui::Context,
        p: &Palette,
        id: &str,
        title: &str,
        body: impl FnOnce(&mut egui::Ui),
    ) -> bool {
        let mut closed = ctx.input(|i| i.key_pressed(egui::Key::Escape));
        egui::Window::new(id)
            .collapsible(false)
            .resizable(false)
            .title_bar(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .frame(egui::Frame {
                inner_margin: egui::Margin::same(20.0),
                rounding: egui::Rounding::same(13.0),
                fill: p.pop,
                stroke: egui::Stroke::new(1.0, p.line),
                shadow: egui::epaint::Shadow {
                    offset: egui::vec2(0.0, 12.0),
                    blur: 40.0,
                    spread: 0.0,
                    color: egui::Color32::from_black_alpha(115),
                },
                ..Default::default()
            })
            .show(ctx, |ui| {
                ui.set_max_width(300.0);
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new(title)
                            .font(theme::f_sb(13.0))
                            .color(p.txt),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let (xr, xresp) =
                            ui.allocate_exact_size(egui::vec2(18.0, 18.0), egui::Sense::click());
                        let xcolor = if xresp.hovered() { p.txt } else { p.txt3 };
                        paint_x_icon(ui, xr.center(), xcolor);
                        if xresp.clicked() {
                            closed = true;
                        }
                    });
                });
                ui.add_space(12.0);
                body(ui);
            });
        closed
    }

    /// Centered-modal enrollment dialog (same chrome as the Settings dialogs):
    /// live per-sample progress, a Cancel during capture, and a Done once the
    /// flow finishes.
    fn render_enroll_dialog(&mut self, ctx: &egui::Context, p: &Palette) {
        let Some(prog) = self.security_keys.fp_progress.clone() else {
            return;
        };

        // Snapshot the shared state under one short lock so the body closure
        // (which only borrows `ui`) doesn't need the mutex.
        let (captured, total, last_message, done) = {
            let Ok(g) = prog.lock() else { return };
            (
                g.captured,
                g.total.max(1),
                g.last_message.clone(),
                g.done.clone(),
            )
        };
        let frac = (captured as f32 / total as f32).clamp(0.0, 1.0);
        let finished = done.is_some();

        let mut want_cancel = false;
        let mut want_done = false;
        let closed = Self::modal_window(
            ctx,
            p,
            "fp_enroll",
            "Enroll fingerprint",
            |ui| match &done {
                None => {
                    ui.label(
                        egui::RichText::new(format!(
                            "Enrolling \u{2014} sample {} of {}",
                            captured.min(total),
                            total
                        ))
                        .font(theme::f_sb(13.0))
                        .color(p.accent),
                    );
                    ui.add_space(8.0);
                    ui.add(egui::ProgressBar::new(frac).desired_width(280.0));
                    ui.add_space(6.0);
                    ui.label(
                        egui::RichText::new(format!("\u{1F446} {last_message}"))
                            .font(theme::f_reg(12.0))
                            .color(p.txt2),
                    );
                    ui.add_space(16.0);
                    if theme::button(ui, p, BtnKind::Default, "Cancel").clicked() {
                        want_cancel = true;
                    }
                }
                Some(Ok(())) => {
                    ui.label(
                        egui::RichText::new("\u{2713} Fingerprint enrolled")
                            .font(theme::f_sb(13.0))
                            .color(p.ok),
                    );
                    ui.add_space(8.0);
                    ui.add(egui::ProgressBar::new(1.0).desired_width(280.0));
                    ui.add_space(16.0);
                    if theme::button(ui, p, BtnKind::Primary, "Done").clicked() {
                        want_done = true;
                    }
                }
                Some(Err(e)) => {
                    ui.colored_label(p.err, format!("Enrollment failed: {e}"));
                    ui.add_space(16.0);
                    if theme::button(ui, p, BtnKind::Default, "Close").clicked() {
                        want_done = true;
                    }
                }
            },
        );

        if want_cancel {
            // Signal the worker to abort the capture between samples.
            if let Ok(mut g) = prog.lock() {
                g.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                g.last_message = "Cancelling\u{2026}".into();
            }
        }
        // Done / Close / the X / Esc dismiss the dialog once the flow is
        // finished. While a capture is still running, the X/Esc act as Cancel
        // rather than leaving an orphaned worker.
        if want_done || (closed && finished) {
            self.security_keys.fp_progress = None;
        } else if closed && !finished {
            if let Ok(mut g) = prog.lock() {
                g.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                g.last_message = "Cancelling\u{2026}".into();
            }
        }
    }

    /// Centered-modal confirmation for deleting a fingerprint (same chrome as
    /// the Settings dialogs). Returns the template id to delete, if confirmed.
    fn render_fp_delete_confirm(&mut self, ctx: &egui::Context, p: &Palette) -> Option<Vec<u8>> {
        let id = self.security_keys.fp_confirm_delete.clone()?;
        let label = self
            .security_keys
            .fingerprints
            .as_ref()
            .and_then(|l| l.iter().find(|e| e.template_id == id))
            .and_then(|e| e.friendly_name.clone())
            .unwrap_or_else(|| hex_short(&id));

        let mut confirm = false;
        let mut cancel = false;
        let closed = Self::modal_window(ctx, p, "fp_delete", "Delete fingerprint?", |ui| {
            ui.label(
                egui::RichText::new(format!(
                    "Delete fingerprint \u{201c}{label}\u{201d}? This cannot be undone."
                ))
                .font(theme::f_reg(12.5))
                .color(p.txt),
            );
            ui.add_space(16.0);
            ui.horizontal(|ui| {
                if theme::button(ui, p, BtnKind::Danger, "Delete").clicked() {
                    confirm = true;
                }
                ui.add_space(8.0);
                if theme::button(ui, p, BtnKind::Default, "Cancel").clicked() {
                    cancel = true;
                }
            });
        });

        if cancel || closed {
            self.security_keys.fp_confirm_delete = None;
            return None;
        }
        if confirm {
            self.security_keys.fp_confirm_delete = None;
            return Some(id);
        }
        None
    }

    fn render_advanced_confirm(&mut self, ctx: &egui::Context, p: &Palette) {
        let Some(dlg) = self.security_keys.advanced.as_ref() else {
            return;
        };
        let action = dlg.action;
        if action == AdvancedAction::None {
            return;
        }

        let (title, irreversible) = match action {
            AdvancedAction::ToggleAlwaysUv => ("Toggle always-UV", false),
            AdvancedAction::SetMinPin => ("Set minimum PIN length", true),
            AdvancedAction::ForcePinChange => ("Force a PIN change", false),
            AdvancedAction::EnterpriseAttestation => ("Enable enterprise attestation", true),
            AdvancedAction::None => return,
        };

        let mut apply = false;
        let mut cancel = false;
        // No built-in title bar, so handle Esc-to-dismiss ourselves.
        if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            cancel = true;
        }
        egui::Window::new(title)
            .collapsible(false)
            .resizable(false)
            .title_bar(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .frame(egui::Frame {
                inner_margin: egui::Margin::same(20.0),
                rounding: egui::Rounding::same(13.0),
                fill: p.pop,
                stroke: egui::Stroke::new(1.0, p.line),
                shadow: egui::epaint::Shadow {
                    offset: egui::vec2(0.0, 12.0),
                    blur: 40.0,
                    spread: 0.0,
                    color: egui::Color32::from_black_alpha(115),
                },
                ..Default::default()
            })
            .show(ctx, |ui| {
                ui.set_max_width(300.0);
                // Custom title at the button font size (the default window title
                // bar is dropped via title_bar(false), so render our own).
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new(title)
                            .font(theme::f_sb(13.0))
                            .color(p.txt),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let (xr, xresp) =
                            ui.allocate_exact_size(egui::vec2(18.0, 18.0), egui::Sense::click());
                        let xcolor = if xresp.hovered() { p.txt } else { p.txt3 };
                        paint_x_icon(ui, xr.center(), xcolor);
                        if xresp.clicked() {
                            cancel = true;
                        }
                    });
                });
                ui.add_space(12.0);
                if irreversible {
                    ui.label(
                        egui::RichText::new(
                            "This cannot be undone without a full reset of the key.",
                        )
                        .font(theme::f_reg(12.0))
                        .color(p.warn),
                    );
                    ui.add_space(12.0);
                }

                if action == AdvancedAction::SetMinPin {
                    ui.horizontal(|ui| {
                        ui.label("New minimum length");
                        if let Some(d) = self.security_keys.advanced.as_mut() {
                            ui.add(
                                egui::TextEdit::singleline(&mut d.min_pin_input)
                                    .desired_width(64.0)
                                    .hint_text("e.g. 6"),
                            );
                        }
                    });
                    ui.add_space(8.0);
                    if let Some(d) = self.security_keys.advanced.as_mut() {
                        ui.checkbox(&mut d.force_change, "Also force a PIN change now");
                    }
                    ui.add_space(12.0);
                }

                ui.horizontal(|ui| {
                    ui.label("Device PIN");
                    if let Some(d) = self.security_keys.advanced.as_mut() {
                        ui.add(
                            egui::TextEdit::singleline(&mut d.pin_input)
                                .password(true)
                                .desired_width(160.0),
                        );
                    }
                });
                ui.add_space(16.0);

                ui.horizontal(|ui| {
                    let kind = if irreversible {
                        BtnKind::Danger
                    } else {
                        BtnKind::Primary
                    };
                    if theme::button(ui, p, kind, "Apply").clicked() {
                        apply = true;
                    }
                    ui.add_space(8.0);
                    if theme::button(ui, p, BtnKind::Default, "Cancel").clicked() {
                        cancel = true;
                    }
                });

                if let Some(err) = &self.security_keys.error {
                    ui.add_space(10.0);
                    ui.label(
                        egui::RichText::new(err)
                            .font(theme::f_reg(12.0))
                            .color(p.err),
                    );
                }
            });

        if apply {
            self.run_advanced_action();
        } else if cancel {
            // The Cancel button, the ✕, or pressing Esc all dismiss.
            self.security_keys.advanced = None;
            self.security_keys.error = None;
        }
    }

    /// Render the *current* management-key collector inside the modal, but only
    /// for the flows that need it (`PivCredKind::needs_mgmt_key`). Shows a "Use
    /// default management key" toggle (the common case — most users never rotate
    /// the well-known factory default) and, when it's off, the hex entry field.
    /// When the toggle is on the field is hidden and the op reads the default via
    /// `piv_current_mgmt_key`.
    fn piv_modal_mgmt_field(&mut self, ui: &mut egui::Ui, p: &Palette, kind: PivCredKind) {
        if !kind.needs_mgmt_key() {
            return;
        }
        ui.checkbox(&mut self.piv.use_default_mgmt, "Use default management key");
        if !self.piv.use_default_mgmt {
            secret_field(
                ui,
                p,
                "Management key",
                &mut self.piv.mgmt_key_input,
                "hex (48/32/64 chars)",
                300.0,
            );
        }
    }

    /// PIV credential-entry modal: drives the PIN/PUK flows (Change PIN / Change
    /// PUK / Unblock PIN) *and* the management-key-gated operations (generate
    /// key, import / self-sign / CSR, set retries, change management key) inside
    /// the shared `modal_window` chrome, so the secret fields *and* the op's
    /// result stay centered on-screen rather than scrolling off (issue #31).
    ///
    /// The secret fields live in `PivState` (rendered here, not inline in the
    /// pane); the inline pane keeps the *non-secret* parameters (slot, algorithm,
    /// file path, subject, validity, retry counts). The modal state
    /// (`PivState::cred_modal`) tracks the flow, an in-flight flag, and the op
    /// result. On Submit it validates (new==confirm for PIN/PUK; the ops' own
    /// client-side guards for the rest), then runs the existing op, which writes
    /// the outcome back into the modal via `apply_piv_cred_result`. Rich,
    /// non-secret results (e.g. the generated public-key PEM) still surface in
    /// the pane — the modal only shows a generic success line. Cancel / ✕ / Esc —
    /// and a successful Done — wipe the secret fields.
    fn render_piv_cred_modal(&mut self, ctx: &egui::Context, p: &Palette) {
        let Some(kind) = self.piv.cred_modal.as_ref().map(|m| m.kind) else {
            return;
        };
        let busy = self.piv.cred_modal.as_ref().is_some_and(|m| m.busy);
        let result = self.piv.cred_modal.as_ref().and_then(|m| m.result.clone());

        let mut want_submit = false;
        let mut want_close = false;
        // Inline new==confirm guard, mirroring the op-level backstop. Shown as
        // the modal's error line; blocks Submit when set.
        let mismatch = piv_cred_mismatch(&self.piv, kind);

        let closed = Self::modal_window(ctx, p, "piv_cred", kind.title(), |ui| {
            match &result {
                Some(Ok(())) => {
                    // Success: confirmation + a single Done that dismisses.
                    ui.label(
                        egui::RichText::new(format!("\u{2713} {}", piv_cred_success(kind)))
                            .font(theme::f_sb(13.0))
                            .color(p.ok),
                    );
                    ui.add_space(16.0);
                    if theme::button(ui, p, BtnKind::Primary, "Done").clicked() {
                        want_close = true;
                    }
                }
                _ => {
                    // Entry form (also the path while busy / after an error so the
                    // user can retry without losing the dialog).
                    match kind {
                        PivCredKind::ChangePin => {
                            pin_field(ui, p, "Current PIN", &mut self.piv.pin_old);
                            pin_field(ui, p, "New PIN", &mut self.piv.pin_new);
                            pin_field(ui, p, "Confirm new PIN", &mut self.piv.pin_confirm);
                            card_note(ui, p, "6\u{2013}8 characters.");
                        }
                        PivCredKind::ChangePuk => {
                            pin_field(ui, p, "Current PUK", &mut self.piv.puk_old);
                            pin_field(ui, p, "New PUK", &mut self.piv.puk_new);
                            pin_field(ui, p, "Confirm new PUK", &mut self.piv.puk_confirm);
                            card_note(ui, p, "8 characters.");
                        }
                        PivCredKind::UnblockPin => {
                            pin_field(ui, p, "PUK", &mut self.piv.unblock_puk);
                            pin_field(ui, p, "New PIN", &mut self.piv.unblock_new_pin);
                            card_note(ui, p, "Recovers a blocked PIN without wiping any keys.");
                        }
                        // Management-key-gated flows: only the *secrets* live here;
                        // their non-secret parameters stay inline in the pane.
                        PivCredKind::GenerateKey => {
                            self.piv_modal_mgmt_field(ui, p, kind);
                            card_note(ui, p, "Authorizes overwriting the slot with a fresh key.");
                        }
                        PivCredKind::ImportCert => {
                            self.piv_modal_mgmt_field(ui, p, kind);
                            card_note(ui, p, "Authorizes writing the certificate to the slot.");
                        }
                        PivCredKind::SelfSign => {
                            self.piv_modal_mgmt_field(ui, p, kind);
                            pin_field(ui, p, "PIN", &mut self.piv.sign_pin);
                            card_note(
                                ui,
                                p,
                                "Management key authorizes the import; the PIN authorizes \
                                 the on-card signature.",
                            );
                        }
                        PivCredKind::RequestCsr => {
                            pin_field(ui, p, "PIN", &mut self.piv.sign_pin);
                            card_note(ui, p, "The PIN authorizes the on-card signature.");
                        }
                        PivCredKind::SetRetries => {
                            self.piv_modal_mgmt_field(ui, p, kind);
                            pin_field(ui, p, "Current PIN", &mut self.piv.retries_pin_auth);
                            card_note(
                                ui,
                                p,
                                "Resets PIN and PUK to factory defaults; needs the \
                                 management key and the current PIN.",
                            );
                        }
                        PivCredKind::ChangeMgmtKey => {
                            self.piv_modal_mgmt_field(ui, p, kind);
                            secret_field(
                                ui,
                                p,
                                "New key",
                                &mut self.piv.new_mgmt_key_input,
                                "hex (48/32/64 chars)",
                                300.0,
                            );
                            card_note(ui, p, "Enter the current key, then the new key.");
                        }
                        PivCredKind::DeleteCert => {
                            let slot = self.piv.selected_slot.label();
                            ui.colored_label(
                                p.err,
                                egui::RichText::new(format!(
                                    "Removes the certificate in {slot}. The private key in \
                                     the slot remains. This cannot be undone."
                                ))
                                .font(theme::f_sb(12.5)),
                            );
                            ui.add_space(6.0);
                            self.piv_modal_mgmt_field(ui, p, kind);
                            card_note(ui, p, "The management key authorizes the deletion.");
                        }
                        PivCredKind::DeleteKey => {
                            let slot = self.piv.selected_slot.label();
                            ui.colored_label(
                                p.err,
                                egui::RichText::new(format!(
                                    "Permanently erases the private key in {slot}. This \
                                     cannot be undone."
                                ))
                                .font(theme::f_sb(12.5)),
                            );
                            ui.add_space(6.0);
                            self.piv_modal_mgmt_field(ui, p, kind);
                            card_note(
                                ui,
                                p,
                                "The management key authorizes the deletion. Needs \
                                 YubiKey 5.7 or newer.",
                            );
                        }
                    }

                    // Inline error/result line: the new==confirm mismatch, then
                    // the op's error (kept open for a retry).
                    if let Some(msg) = mismatch {
                        ui.add_space(6.0);
                        ui.colored_label(p.err, msg);
                    } else if let Some(Err(e)) = &result {
                        ui.add_space(6.0);
                        ui.colored_label(p.err, e);
                    }

                    ui.add_space(16.0);
                    ui.horizontal(|ui| {
                        if busy {
                            ui.add(egui::Spinner::new());
                            ui.label(
                                egui::RichText::new(kind.busy_label())
                                    .font(theme::f_reg(12.5))
                                    .color(p.txt2),
                            );
                        } else {
                            if theme::button(ui, p, BtnKind::Primary, kind.submit_label()).clicked()
                                && mismatch.is_none()
                            {
                                want_submit = true;
                            }
                            ui.add_space(8.0);
                            if theme::button(ui, p, BtnKind::Default, "Cancel").clicked() {
                                want_close = true;
                            }
                        }
                    });
                }
            }
        });

        // ✕ / Esc dismiss too, but never yank the dialog out from under a
        // running op (mirrors the enroll dialog's busy handling).
        if (closed || want_close) && !busy {
            self.piv_cred_modal_close();
            return;
        }
        if want_submit && !busy {
            // Mark busy first so the modal shows the spinner this frame; the op
            // writes the result back via `apply_piv_cred_result`. If the worker
            // is busy (spawn_job returns false implicitly), the op simply no-ops
            // and the next click retries.
            if let Some(m) = self.piv.cred_modal.as_mut() {
                m.busy = true;
                m.result = None;
            }
            // Clear any stale pane error so a client-side guard tripping during
            // this dispatch is distinguishable from a previous failure.
            self.piv.error = None;
            match kind {
                PivCredKind::ChangePin => self.piv_change_pin(),
                PivCredKind::ChangePuk => self.piv_change_puk(),
                PivCredKind::UnblockPin => self.piv_unblock_pin(),
                PivCredKind::GenerateKey => self.piv_generate_key(),
                PivCredKind::ImportCert => self.piv_import_cert(),
                PivCredKind::SelfSign => self.piv_self_sign(),
                PivCredKind::RequestCsr => self.piv_request_csr(),
                PivCredKind::SetRetries => self.piv_set_retries(),
                PivCredKind::ChangeMgmtKey => self.piv_change_management_key(),
                PivCredKind::DeleteCert => self.piv_delete_cert(),
                PivCredKind::DeleteKey => self.piv_delete_key(),
            }
            // If the op didn't actually queue, unstick the modal. This happens
            // either because the worker was busy (no error set — just retry on
            // the next click) or because a client-side guard rejected the input
            // (bad hex, wrong new-key length, empty subject/path) and stored the
            // reason in `piv.error` — surface that reason in the modal result so
            // it shows in the dialog rather than scrolling off in the pane.
            if !self.busy() {
                let guard_err = self.piv.error.clone();
                if let Some(m) = self.piv.cred_modal.as_mut() {
                    m.busy = false;
                    if let Some(e) = guard_err {
                        m.result = Some(Err(e));
                    }
                }
            }
        }
    }

    /// Close the PIV credential modal, wiping every PIN/PUK field it could have
    /// touched (cheap to over-wipe; all are secrets).
    fn piv_cred_modal_close(&mut self) {
        wipe(&mut self.piv.pin_old);
        wipe(&mut self.piv.pin_new);
        wipe(&mut self.piv.pin_confirm);
        wipe(&mut self.piv.puk_old);
        wipe(&mut self.piv.puk_new);
        wipe(&mut self.piv.puk_confirm);
        wipe(&mut self.piv.unblock_puk);
        wipe(&mut self.piv.unblock_new_pin);
        // Management-key-gated flows also route their secrets through this modal.
        wipe(&mut self.piv.mgmt_key_input);
        wipe(&mut self.piv.new_mgmt_key_input);
        wipe(&mut self.piv.sign_pin);
        wipe(&mut self.piv.retries_pin_auth);
        self.piv.use_default_mgmt = false;
        self.piv.cred_modal = None;
    }

    /// Render the admin-PIN (PW3) collector inside the OpenPGP modal, but only
    /// for the flows that need it (`OpenPgpCredKind::needs_admin_pin`). Shows a
    /// "Use default admin PIN (PW3)" toggle (the factory default `12345678`,
    /// common during bring-up) and, when it's off, the masked PIN field. When the
    /// toggle is on the field is hidden and the op reads the default via
    /// `openpgp_admin_pin_value`.
    fn openpgp_modal_admin_field(&mut self, ui: &mut egui::Ui, p: &Palette, kind: OpenPgpCredKind) {
        if !kind.needs_admin_pin() {
            return;
        }
        ui.checkbox(
            &mut self.openpgp.use_default_admin,
            "Use default admin PIN (PW3)",
        );
        if !self.openpgp.use_default_admin {
            pin_field(ui, p, "Admin PIN", &mut self.openpgp.admin_pin);
        }
    }

    /// OpenPGP credential-entry modal: drives the PIN flows (Change user PIN /
    /// Change admin PIN / Unblock user PIN) *and* the admin-PIN (PW3)-gated writes
    /// (set cardholder name / URL, generate / import key) plus the factory reset,
    /// inside the shared `modal_window` chrome, so the secret fields *and* the
    /// op's result stay centered on-screen rather than scrolling off (issue #31).
    ///
    /// The secret fields live in `OpenPgpState` (rendered here, not inline in the
    /// pane); the inline pane keeps the *non-secret* parameters (name, URL, slot,
    /// file path). The modal state (`OpenPgpState::cred_modal`) tracks the flow,
    /// an in-flight flag, and the op result. On Submit it runs the existing op,
    /// which writes the outcome back into the modal via `apply_openpgp_cred_result`.
    /// Rich, non-secret results (e.g. the new key fingerprint) still surface in
    /// the pane — the modal only shows a generic success line. Cancel / ✕ / Esc —
    /// and a successful Done — wipe the secret fields.
    fn render_openpgp_cred_modal(&mut self, ctx: &egui::Context, p: &Palette) {
        let Some(kind) = self.openpgp.cred_modal.as_ref().map(|m| m.kind) else {
            return;
        };
        let busy = self.openpgp.cred_modal.as_ref().is_some_and(|m| m.busy);
        let result = self
            .openpgp
            .cred_modal
            .as_ref()
            .and_then(|m| m.result.clone());

        let mut want_submit = false;
        let mut want_close = false;
        // Inline new==confirm guard, mirroring the op-level backstop (currently
        // never fires — the OpenPGP PIN forms have no confirm field — but kept
        // for shape parity with the PIV modal).
        let mismatch = openpgp_cred_mismatch(&self.openpgp, kind);

        let closed = Self::modal_window(ctx, p, "openpgp_cred", kind.title(), |ui| {
            match &result {
                Some(Ok(())) => {
                    // Success: confirmation + a single Done that dismisses.
                    ui.label(
                        egui::RichText::new(format!("\u{2713} {}", kind.success()))
                            .font(theme::f_sb(13.0))
                            .color(p.ok),
                    );
                    ui.add_space(16.0);
                    if theme::button(ui, p, BtnKind::Primary, "Done").clicked() {
                        want_close = true;
                    }
                }
                _ => {
                    // Entry form (also the path while busy / after an error so the
                    // user can retry without losing the dialog).
                    match kind {
                        OpenPgpCredKind::ChangeUserPin => {
                            pin_field(ui, p, "Current PIN", &mut self.openpgp.user_pin_old);
                            pin_field(ui, p, "New PIN", &mut self.openpgp.user_pin_new);
                            card_note(ui, p, "User PIN (PW1): 6\u{2013}127 characters.");
                        }
                        OpenPgpCredKind::ChangeAdminPin => {
                            pin_field(ui, p, "Current PIN", &mut self.openpgp.admin_pin_old);
                            pin_field(ui, p, "New PIN", &mut self.openpgp.admin_pin_new);
                            card_note(ui, p, "Admin PIN (PW3): 8\u{2013}127 characters.");
                        }
                        OpenPgpCredKind::UnblockUserPin => {
                            self.openpgp_modal_admin_field(ui, p, kind);
                            pin_field(ui, p, "New user PIN", &mut self.openpgp.unblock_new);
                            card_note(
                                ui,
                                p,
                                "Resets a blocked user PIN using the admin PIN (PW3).",
                            );
                        }
                        OpenPgpCredKind::SetName => {
                            self.openpgp_modal_admin_field(ui, p, kind);
                            card_note(ui, p, "Authorizes writing the cardholder name.");
                        }
                        OpenPgpCredKind::SetUrl => {
                            self.openpgp_modal_admin_field(ui, p, kind);
                            card_note(ui, p, "Authorizes writing the public-key URL.");
                        }
                        OpenPgpCredKind::GenerateKey => {
                            self.openpgp_modal_admin_field(ui, p, kind);
                            card_note(
                                ui,
                                p,
                                "OVERWRITES the slot with a fresh on-card key (clearable \
                                 only by a full reset). May need a touch.",
                            );
                        }
                        OpenPgpCredKind::GenerateImportKey | OpenPgpCredKind::ImportKeyFile => {
                            self.openpgp_modal_admin_field(ui, p, kind);
                            card_note(
                                ui,
                                p,
                                "OVERWRITES the slot with the imported key (clearable only \
                                 by a full reset). May need a touch.",
                            );
                        }
                        OpenPgpCredKind::Reset => {
                            card_note(
                                ui,
                                p,
                                "Wipes ALL OpenPGP keys and restores default PINs. Works \
                                 even if the PINs are forgotten. No PIN needed.",
                            );
                        }
                    }

                    // Inline error/result line: the (currently inert) mismatch,
                    // then the op's error (kept open for a retry).
                    if let Some(msg) = mismatch {
                        ui.add_space(6.0);
                        ui.colored_label(p.err, msg);
                    } else if let Some(Err(e)) = &result {
                        ui.add_space(6.0);
                        ui.colored_label(p.err, e);
                    }

                    ui.add_space(16.0);
                    ui.horizontal(|ui| {
                        if busy {
                            ui.add(egui::Spinner::new());
                            ui.label(
                                egui::RichText::new(kind.busy_label())
                                    .font(theme::f_reg(12.5))
                                    .color(p.txt2),
                            );
                        } else {
                            let btn = if kind == OpenPgpCredKind::Reset {
                                BtnKind::Danger
                            } else {
                                BtnKind::Primary
                            };
                            if theme::button(ui, p, btn, kind.submit_label()).clicked()
                                && mismatch.is_none()
                            {
                                want_submit = true;
                            }
                            ui.add_space(8.0);
                            if theme::button(ui, p, BtnKind::Default, "Cancel").clicked() {
                                want_close = true;
                            }
                        }
                    });
                }
            }
        });

        // ✕ / Esc dismiss too, but never yank the dialog out from under a
        // running op (mirrors the PIV modal's busy handling).
        if (closed || want_close) && !busy {
            self.openpgp_cred_modal_close();
            return;
        }
        if want_submit && !busy {
            // Mark busy first so the modal shows the spinner this frame; the op
            // writes the result back via `apply_openpgp_cred_result`.
            if let Some(m) = self.openpgp.cred_modal.as_mut() {
                m.busy = true;
                m.result = None;
            }
            self.openpgp.error = None;
            match kind {
                OpenPgpCredKind::ChangeUserPin => self.change_openpgp_user_pin(),
                OpenPgpCredKind::ChangeAdminPin => self.change_openpgp_admin_pin(),
                OpenPgpCredKind::UnblockUserPin => self.unblock_openpgp_user_pin(),
                OpenPgpCredKind::SetName => self.set_openpgp_name(),
                OpenPgpCredKind::SetUrl => self.set_openpgp_url(),
                OpenPgpCredKind::GenerateKey => {
                    self.generate_openpgp_key();
                }
                OpenPgpCredKind::GenerateImportKey => {
                    self.import_openpgp_key(ImportSource::Generate);
                }
                OpenPgpCredKind::ImportKeyFile => {
                    self.import_openpgp_key(ImportSource::FromFile);
                }
                OpenPgpCredKind::Reset => {
                    self.reset_openpgp();
                }
            }
            // If the op didn't actually queue, unstick the modal. Either the
            // worker was busy (no error set — retry on the next click) or a
            // client-side guard rejected the input and stored the reason in
            // `openpgp.error`; surface that in the modal so it shows in the
            // dialog rather than scrolling off in the pane.
            if !self.busy() {
                let guard_err = self.openpgp.error.clone();
                if let Some(m) = self.openpgp.cred_modal.as_mut() {
                    m.busy = false;
                    if let Some(e) = guard_err {
                        m.result = Some(Err(e));
                    }
                }
            }
        }
    }

    /// Close the OpenPGP credential modal, wiping every PIN field it could have
    /// touched (cheap to over-wipe; all are secrets) and clearing the
    /// use-default toggle.
    fn openpgp_cred_modal_close(&mut self) {
        self.openpgp.wipe_secrets();
        self.openpgp.cred_modal = None;
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
                    // Opens the centered "New credential" modal (rendered in the
                    // update loop alongside the other credential modals).
                    self.oath.add = OathAddDialog::opened();
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
        if self.oath.locked {
            theme::card_frame(p).show(ui, |ui| {
                ui.label(
                    egui::RichText::new("This key's OATH applet is password-protected.")
                        .font(theme::f_reg(13.0))
                        .color(p.txt),
                );
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    let resp = ui.add_sized(
                        [220.0, 32.0],
                        egui::TextEdit::singleline(&mut self.oath.password_input)
                            .vertical_align(egui::Align::Center)
                            .password(true),
                    );
                    let submit = theme::button(ui, p, BtnKind::Primary, "Unlock").clicked();
                    // Enter in the field submits too, matching the FIDO2 unlock card
                    // and the other inline credential fields in this redesign.
                    if submit
                        || (resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)))
                    {
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
        // Intents collected inside the UI closures and applied afterwards, so a
        // submit method's `&mut self` never overlaps a card's borrow. (Mirrors
        // the PIV pane.) `open_modal` carries the chosen credential flow.
        let mut do_refresh = false;
        let mut open_modal: Option<OpenPgpCredKind> = None;
        let mut browse_import_key = false;
        // The key the user clicked in the sub-tab strip this frame (applied
        // after the card borrows end). `selected` is a copy of the active key so
        // the immutable card closures can compare without borrowing self.
        let mut clicked_key: Option<OpenPgpSlotSel> = None;
        let selected = self.openpgp.selected_key;

        let note = |ui: &mut egui::Ui, t: &str| card_note(ui, p, t);

        // --- OpenPGP card status card (full-width, FIDO2 shape): title + help
        // left, Read status right, applet-wide status body, then the applet-wide
        // admin (Card details, PINs) folded in as setting-rows.
        theme::card_frame(p).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("OpenPGP card")
                        .font(theme::f_sb(14.5))
                        .color(p.txt),
                );
                ui.add_space(6.0);
                self.help_dot(ui, p, "pgp");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if theme::button(ui, p, BtnKind::Default, "Read status").clicked() {
                        do_refresh = true;
                    }
                });
            });
            ui.add_space(8.0);
            if let Some(err) = &self.openpgp.error {
                ui.colored_label(p.err, err);
                ui.add_space(6.0);
            }
            if let Some(notice) = &self.openpgp.notice {
                ui.colored_label(p.ok, notice);
                ui.add_space(6.0);
            }
            // Applet-wide status: AID / serial / PIN retries / signatures made.
            // The three per-key algorithm+fingerprint rows live under the sub-tab
            // strip now, not here.
            if let Some(status) = &self.openpgp.status {
                let serial = status
                    .serial()
                    .map_or("\u{2014}".to_string(), |s| format!("{s} (0x{s:08X})"));
                let sigs = status
                    .signature_count
                    .map_or("\u{2014}".to_string(), |n| n.to_string());
                ui.label(
                    egui::RichText::new(format!(
                        "AID {} \u{00B7} Serial {serial}",
                        hex_lower(&status.aid)
                    ))
                    .font(theme::f_reg(12.5))
                    .color(p.txt2),
                );
                ui.add_space(2.0);
                ui.label(
                    egui::RichText::new(format!(
                        "PIN retries PW1={} RC={} PW3={} \u{00B7} Signatures made {sigs}",
                        status.tries_pw1, status.tries_rc, status.tries_pw3
                    ))
                    .font(theme::f_reg(12.5))
                    .color(p.txt2),
                );
            } else if self.openpgp.error.is_none() {
                ui.label(
                    egui::RichText::new("Click Read status to read this card (no PIN or touch).")
                        .font(theme::f_reg(13.0))
                        .color(p.txt3),
                );
            }

            // Applet-wide administration folded in as FIDO2 setting-rows: the
            // cardholder details and the PIN operations apply to the whole card,
            // not to one key, so they sit with the applet status here.
            ui.add_space(12.0);

            // Card details: cardholder name + public-key URL. The values are
            // typed in the per-row text fields; both writes prompt for the admin
            // PIN (PW3) in a dialog.
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("Card details")
                        .font(theme::f_sb(13.5))
                        .color(p.txt),
                );
                ui.add_space(6.0);
                self.help_dot(ui, p, "pgp-card-details");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if theme::button(ui, p, BtnKind::Default, "Set URL\u{2026}").clicked() {
                        open_modal = Some(OpenPgpCredKind::SetUrl);
                    }
                    ui.add_space(6.0);
                    if theme::button(ui, p, BtnKind::Default, "Set name\u{2026}").clicked() {
                        open_modal = Some(OpenPgpCredKind::SetName);
                    }
                });
            });
            ui.add_space(6.0);
            text_field(
                ui,
                p,
                "Name",
                &mut self.openpgp.name_input,
                "Surname<<Given",
                200.0,
            );
            ui.add_space(4.0);
            text_field(
                ui,
                p,
                "URL",
                &mut self.openpgp.url_input,
                "https://\u{2026}",
                240.0,
            );

            // PINs: change user / admin, unblock user. Each opens a dialog where
            // the PIN entry happens; nothing secret is typed inline.
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("PINs")
                        .font(theme::f_sb(13.5))
                        .color(p.txt),
                );
                ui.add_space(6.0);
                self.help_dot(ui, p, "pin");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if theme::button(ui, p, BtnKind::Default, "Unblock user PIN\u{2026}").clicked()
                    {
                        open_modal = Some(OpenPgpCredKind::UnblockUserPin);
                    }
                    ui.add_space(6.0);
                    if theme::button(ui, p, BtnKind::Default, "Change admin PIN\u{2026}").clicked()
                    {
                        open_modal = Some(OpenPgpCredKind::ChangeAdminPin);
                    }
                    ui.add_space(6.0);
                    if theme::button(ui, p, BtnKind::Default, "Change user PIN\u{2026}").clicked() {
                        open_modal = Some(OpenPgpCredKind::ChangeUserPin);
                    }
                });
            });
        });

        // --- Selected-key display data (shown under the key tab strip) -------
        // The active key's algorithm + fingerprint, read straight off the loaded
        // status. Precomputed here so the immutable card closures don't borrow
        // self.
        let sel_state: String = match &self.openpgp.status {
            Some(st) => {
                let (algo, fpr) = selected.status_fields(st);
                if fpr.iter().all(|&b| b == 0) {
                    "no key".to_string()
                } else {
                    format!("{} \u{00B7} fpr {}", algo_id_label(algo), hex_lower(fpr))
                }
            }
            None => "read status to view this key".to_string(),
        };

        // --- Key sub-tab strip ----------------------------------------------
        // Signature / Decryption / Authentication, each a tab exactly like the
        // FIDO2 sub-tab strip: an opaque surface strip behind a row of bold
        // labels, the active one underlined with a 2px accent. Clicking a tab
        // selects that key; the Generate / Import cards below target it.
        ui.add_space(14.0);
        {
            let top = ui.cursor().top();
            let strip = egui::Rect::from_min_max(
                egui::pos2(ui.max_rect().left(), top - 4.0),
                egui::pos2(ui.max_rect().right(), top + 30.0),
            );
            ui.painter().rect_filled(strip, 0.0, p.surface);
        }
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 20.0;
            for key in [
                OpenPgpSlotSel::Sign,
                OpenPgpSlotSel::Decrypt,
                OpenPgpSlotSel::Auth,
            ] {
                let active = selected == key;
                let color = if active { p.txt } else { p.txt3 };
                let resp = ui
                    .add(
                        egui::Label::new(
                            egui::RichText::new(key.tab_label())
                                .font(theme::f_sb(13.5))
                                .color(color),
                        )
                        .sense(egui::Sense::click()),
                    )
                    .on_hover_cursor(egui::CursorIcon::PointingHand);
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
                    clicked_key = Some(key);
                }
            }
        });

        // --- Selected key content (single column under the strip) -----------
        ui.add_space(14.0);
        ui.label(
            egui::RichText::new(format!("State: {}", &sel_state))
                .font(theme::f_reg(12.5))
                .color(p.txt2),
        );
        ui.add_space(10.0);
        theme::card_frame(p).show(ui, |ui| {
            ui.set_min_width(ui.available_width());

            // Generate on-card: label + help left, Generate pinned right.
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("Generate on-card")
                        .font(theme::f_sb(13.5))
                        .color(p.txt),
                );
                ui.add_space(6.0);
                self.help_dot(ui, p, "pgp-keys");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if theme::button(ui, p, BtnKind::Default, "Generate\u{2026}").clicked() {
                        open_modal = Some(OpenPgpCredKind::GenerateKey);
                    }
                });
            });
            note(
                ui,
                "Generating OVERWRITES this key (clearable only by a full reset). \
                 Prompts for the admin PIN; touch the key if it blinks.",
            );

            ui.add_space(12.0);
            // Import RSA-2048: file path + Browse left, the two import actions
            // pinned right.
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("Import RSA-2048")
                        .font(theme::f_sb(13.5))
                        .color(p.txt),
                );
                ui.add_space(6.0);
                self.help_dot(ui, p, "pgp-keys");
            });
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                text_field(
                    ui,
                    p,
                    "From file",
                    &mut self.openpgp.import_path,
                    "/path/to/key.pem (PKCS#1/8, PEM or DER)",
                    240.0,
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    browse_import_key =
                        theme::button(ui, p, BtnKind::Default, "Browse\u{2026}").clicked();
                });
            });
            let have_path = !self.openpgp.import_path.trim().is_empty();
            ui.add_space(6.0);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if theme::button(ui, p, BtnKind::Default, "Import file\u{2026}").clicked()
                    && have_path
                {
                    open_modal = Some(OpenPgpCredKind::ImportKeyFile);
                }
                ui.add_space(6.0);
                if theme::button(ui, p, BtnKind::Default, "Generate & import\u{2026}").clicked() {
                    open_modal = Some(OpenPgpCredKind::GenerateImportKey);
                }
            });
        });
        ui.add_space(12.0);

        // Reset applet — its own destructive card with a red stroke at the
        // bottom of the pane (mirrors the FIDO2 / PIV "Reset" card), full width,
        // description left + red button right.
        theme::card_frame(p)
            .stroke(egui::Stroke::new(1.0, theme::tint(p.err, 90)))
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new("Reset applet")
                            .font(theme::f_sb(14.5))
                            .color(p.err),
                    );
                    ui.add_space(6.0);
                    self.help_dot(ui, p, "reset");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if theme::button(ui, p, BtnKind::Danger, "Reset applet\u{2026}").clicked() {
                            open_modal = Some(OpenPgpCredKind::Reset);
                        }
                    });
                });
                ui.label(
                    egui::RichText::new(
                        "Wipes ALL OpenPGP keys and restores default PINs. Works even if \
                         the PINs are forgotten.",
                    )
                    .font(theme::f_reg(12.5))
                    .color(p.txt2),
                );
            });

        // Apply collected intents now that the card borrows have ended.
        if let Some(key) = clicked_key {
            self.openpgp.selected_key = key;
        }
        if do_refresh {
            self.load_openpgp_status();
        }
        if browse_import_key {
            self.spawn_file_dialog(
                FileTarget::OpenpgpImport,
                false,
                &[("Keys", &["pem", "der", "key"]), ("All files", &["*"])],
                None,
            );
        }
        // Open the chosen flow's credential modal, wiping any stale secret first
        // so a PIN typed for a previous flow can't ride along.
        if let Some(kind) = open_modal {
            self.openpgp.wipe_secrets();
            self.openpgp.error = None;
            self.openpgp.cred_modal = Some(OpenPgpCredModal::new(kind));
        }
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
        let mut open_change_pin = false;
        let mut open_change_puk = false;
        let mut open_unblock = false;
        let mut open_generate = false;
        let mut open_import = false;
        let mut go_export = false;
        let mut open_self_sign = false;
        let mut open_csr = false;
        let mut open_set_retries = false;
        let mut open_change_mgmt = false;
        let mut open_delete_cert = false;
        let mut open_delete_key = false;
        let mut arm_reset = false;
        let mut copy_pem: Option<String> = None;
        // Slot the user clicked in the status card this frame (applied after the
        // card borrows end). `selected` is a copy of the active selection so the
        // immutable card closures can compare against it without borrowing self.
        let mut clicked_slot: Option<PivSlotSel> = None;
        let selected = self.piv.selected_slot;

        let note = |ui: &mut egui::Ui, t: &str| card_note(ui, p, t);

        // --- PIV smart card status card (full-width, FIDO2 "PIN & sign-in"
        // shape): title + help left, Refresh right, applet/serial/retries body.
        theme::card_frame(p).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
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
            ui.add_space(8.0);
            if let Some(err) = &self.piv.error {
                ui.colored_label(p.err, err);
                ui.add_space(6.0);
            }
            if let Some(n) = &self.piv.notice {
                ui.colored_label(p.ok, n);
                ui.add_space(6.0);
            }
            // Status body: version / serial / PIN retries collapsed onto one
            // dotted line.
            if let Some(st) = &self.piv.status {
                let ver = st
                    .version
                    .map_or("\u{2014}".to_string(), |(a, b, c)| format!("{a}.{b}.{c}"));
                let serial = st.serial.map_or("\u{2014}".to_string(), |s| s.to_string());
                let retries = st
                    .pin_retries
                    .map_or("\u{2014}".to_string(), |n| n.to_string());
                ui.label(
                    egui::RichText::new(format!(
                        "Applet {ver} \u{00B7} Serial {serial} \u{00B7} PIN retries {retries}"
                    ))
                    .font(theme::f_reg(12.5))
                    .color(p.txt2),
                );
            } else if self.piv.error.is_none() {
                ui.label(
                    egui::RichText::new("Reading PIV status\u{2026}")
                        .font(theme::f_reg(13.0))
                        .color(p.txt3),
                );
            }

            // Applet-wide administration: PIN & PUK, retry counts, and the
            // management key all apply to the whole applet rather than to one
            // slot, so they sit with the applet status here.
            ui.add_space(12.0);

            // PIN & PUK: bold label + help left, the three actions right.
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("PIN & PUK")
                        .font(theme::f_sb(13.5))
                        .color(p.txt),
                );
                ui.add_space(6.0);
                self.help_dot(ui, p, "pin");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if theme::button(ui, p, BtnKind::Default, "Unblock PIN\u{2026}").clicked() {
                        open_unblock = true;
                    }
                    ui.add_space(6.0);
                    if theme::button(ui, p, BtnKind::Default, "Change PUK\u{2026}").clicked() {
                        open_change_puk = true;
                    }
                    ui.add_space(6.0);
                    if theme::button(ui, p, BtnKind::Default, "Change PIN\u{2026}").clicked() {
                        open_change_pin = true;
                    }
                });
            });

            // Retry counts: label + help left, the tries DragValues and the
            // apply button right-aligned.
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("Retry counts")
                        .font(theme::f_sb(13.5))
                        .color(p.txt),
                );
                ui.add_space(6.0);
                self.help_dot(ui, p, "piv-admin");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if theme::button(ui, p, BtnKind::Default, "Set retry counts\u{2026}").clicked()
                    {
                        open_set_retries = true;
                    }
                    ui.add_space(8.0);
                    ui.add(egui::DragValue::new(&mut self.piv.retries_puk).range(1..=15u8));
                    ui.label(
                        egui::RichText::new("PUK tries")
                            .font(theme::f_reg(13.0))
                            .color(p.txt2),
                    );
                    ui.add_space(8.0);
                    ui.add(egui::DragValue::new(&mut self.piv.retries_pin).range(1..=15u8));
                    ui.label(
                        egui::RichText::new("PIN tries")
                            .font(theme::f_reg(13.0))
                            .color(p.txt2),
                    );
                });
            });

            // Management key: label + help left, algorithm combo and change
            // button right-aligned.
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("Management key")
                        .font(theme::f_sb(13.5))
                        .color(p.txt),
                );
                ui.add_space(6.0);
                self.help_dot(ui, p, "piv-admin");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if theme::button(ui, p, BtnKind::Default, "Change management key\u{2026}")
                        .clicked()
                    {
                        open_change_mgmt = true;
                    }
                    ui.add_space(8.0);
                    piv_mgmtalg_combo(ui, "piv-new-mgmt-alg", &mut self.piv.new_mgmt_alg);
                });
            });
        });

        // --- Selected-slot display data (shown under the slot tab strip) ---
        let sel_state: String = {
            let sel_slot = selected.to_slot();
            let cert_present = self
                .piv
                .status
                .as_ref()
                .and_then(|s| s.slots.iter().find(|sl| sl.slot == sel_slot))
                .map(|sl| sl.cert_present)
                .unwrap_or(false);
            let entry = self.piv.slot_keys.iter().find(|(s, _, _)| *s == sel_slot);
            let alg = entry.and_then(|(_, a, _)| *a);
            let dn = entry.and_then(|(_, _, d)| d.as_deref());
            let base = if cert_present {
                "certificate present"
            } else if alg.is_some() {
                "key present, no certificate"
            } else {
                "empty"
            };
            let mut s = base.to_string();
            if let Some(a) = alg {
                s.push_str(" \u{00B7} ");
                s.push_str(a.label());
            }
            if let Some(dn) = dn {
                s.push_str(" \u{00B7} ");
                if dn.chars().count() > 64 {
                    s.extend(dn.chars().take(63));
                    s.push('\u{2026}');
                } else {
                    s.push_str(dn);
                }
            }
            s
        };
        // Key deletion (Yubico MOVE/DELETE KEY) needs firmware 5.7+. The
        // transport version-gates as a backstop; here we hide the button (and
        // explain) when the loaded status reports an older — or unknown —
        // version. Clearing a certificate works everywhere.
        let can_delete_key = matches!(
            self.piv.status.as_ref().and_then(|s| s.version),
            Some(v) if v >= (5, 7, 0)
        );
        // --- Slot sub-tab strip ---------------------------------------------
        // Each PIV slot is a tab, exactly like the FIDO2 sub-tab strip
        // (Passkeys / Settings / Storage): an opaque surface strip behind a row
        // of bold labels, the active one underlined with a 2px accent. Clicking
        // a tab selects that slot; every action card below targets it.
        ui.add_space(14.0);
        {
            let top = ui.cursor().top();
            let strip = egui::Rect::from_min_max(
                egui::pos2(ui.max_rect().left(), top - 4.0),
                egui::pos2(ui.max_rect().right(), top + 30.0),
            );
            ui.painter().rect_filled(strip, 0.0, p.surface);
        }
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 20.0;
            for slot in [
                PivSlotSel::Auth,
                PivSlotSel::Sign,
                PivSlotSel::KeyMgmt,
                PivSlotSel::CardAuth,
            ] {
                let active = selected == slot;
                let color = if active { p.txt } else { p.txt3 };
                let resp = ui
                    .add(
                        egui::Label::new(
                            egui::RichText::new(slot.label())
                                .font(theme::f_sb(13.5))
                                .color(color),
                        )
                        .sense(egui::Sense::click()),
                    )
                    .on_hover_cursor(egui::CursorIcon::PointingHand);
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
                    clicked_slot = Some(slot);
                }
            }
        });
        // --- Selected slot content (single column under the strip) ----------
        // State line for the active slot, then the styled full-width action
        // cards (unchanged from the old detail column) in single-column flow.
        ui.add_space(14.0);
        ui.label(
            egui::RichText::new(format!("State: {}", &sel_state))
                .font(theme::f_reg(12.5))
                .color(p.txt2),
        );
        ui.add_space(10.0);
        theme::card_frame(p).show(ui, |ui| {
            ui.set_min_width(ui.available_width());

            // --- Generate key: bold label + help left, algorithm combo
            // and primary button pinned right (FIDO2 setting-row shape).
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("Generate key")
                        .font(theme::f_sb(13.5))
                        .color(p.txt),
                );
                ui.add_space(6.0);
                self.help_dot(ui, p, "piv-generate");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if theme::button(ui, p, BtnKind::Default, "Generate\u{2026}").clicked() {
                        open_generate = true;
                    }
                    ui.add_space(8.0);
                    piv_keyalg_combo(ui, "piv-gen-alg", &mut self.piv.gen_alg);
                });
            });
            if let Some(pem) = &self.piv.gen_pubkey_pem {
                ui.add_space(6.0);
                ui.add(
                    egui::TextEdit::multiline(&mut pem.as_str())
                        .desired_rows(4)
                        .desired_width(f32::INFINITY)
                        .font(egui::TextStyle::Monospace),
                );
                ui.add_space(4.0);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if theme::button(ui, p, BtnKind::Ghost, "Copy public key").clicked() {
                        copy_pem = Some(pem.clone());
                    }
                });
            }

            ui.add_space(12.0);
            // --- Certificate: subject/validity inputs, then the two
            // issue actions each right-aligned on their own row.
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("Certificate")
                        .font(theme::f_sb(13.5))
                        .color(p.txt),
                );
                ui.add_space(6.0);
                self.help_dot(ui, p, "piv-certificate");
            });
            ui.add_space(6.0);
            text_field(
                ui,
                p,
                "Name",
                &mut self.piv.cert_subject,
                "e.g. Alice — or full CN=Alice,O=Example,C=US",
                300.0,
            );
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
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if theme::button(ui, p, BtnKind::Default, "Self-signed \u{2192} slot").clicked()
                    {
                        open_self_sign = true;
                    }
                });
            });
            ui.add_space(6.0);
            let mut save_csr = false;
            ui.horizontal(|ui| {
                text_field(
                    ui,
                    p,
                    "CSR file",
                    &mut self.piv.csr_path,
                    "/path/to/request.csr",
                    240.0,
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if theme::button(ui, p, BtnKind::Default, "Sign & save CSR").clicked() {
                        open_csr = true;
                    }
                    ui.add_space(8.0);
                    save_csr = theme::button(ui, p, BtnKind::Default, "Save\u{2026}").clicked();
                });
            });
            if save_csr {
                self.spawn_file_dialog(
                    FileTarget::PivCsr,
                    true,
                    &[("CSR", &["csr", "pem"]), ("All files", &["*"])],
                    Some("request.csr"),
                );
            }

            ui.add_space(12.0);
            // --- Import cert: file path + Browse/Import right-aligned.
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("Import cert")
                        .font(theme::f_sb(13.5))
                        .color(p.txt),
                );
                ui.add_space(6.0);
                self.help_dot(ui, p, "piv-import");
            });
            ui.add_space(6.0);
            let mut browse_cert = false;
            ui.horizontal(|ui| {
                text_field(
                    ui,
                    p,
                    "File",
                    &mut self.piv.cert_path,
                    "/path/to/cert.pem",
                    240.0,
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if theme::button(ui, p, BtnKind::Default, "Import certificate").clicked() {
                        open_import = true;
                    }
                    ui.add_space(8.0);
                    browse_cert =
                        theme::button(ui, p, BtnKind::Default, "Browse\u{2026}").clicked();
                });
            });
            if browse_cert {
                self.spawn_file_dialog(
                    FileTarget::PivCert,
                    false,
                    &[
                        ("Certificates", &["pem", "der", "crt", "cer"]),
                        ("All files", &["*"]),
                    ],
                    None,
                );
            }

            ui.add_space(12.0);
            // --- Export cert: destination path + Save/Export right.
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("Export cert")
                        .font(theme::f_sb(13.5))
                        .color(p.txt),
                );
                ui.add_space(6.0);
                self.help_dot(ui, p, "piv-export");
            });
            ui.add_space(6.0);
            let mut save_export = false;
            ui.horizontal(|ui| {
                text_field(
                    ui,
                    p,
                    "Destination",
                    &mut self.piv.export_path,
                    "/path/to/out.der",
                    240.0,
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if theme::button(ui, p, BtnKind::Default, "Export certificate").clicked() {
                        go_export = true;
                    }
                    ui.add_space(8.0);
                    save_export = theme::button(ui, p, BtnKind::Default, "Save\u{2026}").clicked();
                });
            });
            if save_export {
                self.spawn_file_dialog(
                    FileTarget::PivExport,
                    true,
                    &[
                        ("Certificate (DER)", &["der", "cer"]),
                        ("Certificate (PEM)", &["pem", "crt"]),
                        ("All files", &["*"]),
                    ],
                    Some("cert.der"),
                );
            }

            ui.add_space(12.0);
            // --- Delete: bold label + help left, the two delete
            // actions right-aligned (Delete key is Danger, gated 5.7+).
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("Delete")
                        .font(theme::f_sb(13.5))
                        .color(p.txt),
                );
                ui.add_space(6.0);
                self.help_dot(ui, p, "piv-delete");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if can_delete_key {
                        if theme::button(ui, p, BtnKind::Danger, "Delete key\u{2026}").clicked() {
                            open_delete_key = true;
                        }
                        ui.add_space(6.0);
                    }
                    if theme::button(ui, p, BtnKind::Default, "Delete certificate\u{2026}")
                        .clicked()
                    {
                        open_delete_cert = true;
                    }
                });
            });
            if !can_delete_key {
                ui.add_space(4.0);
                note(ui, "Key deletion needs YubiKey 5.7+.");
            }
        });
        ui.add_space(12.0);

        // Reset applet — its own destructive card with a red stroke at the
        // bottom of the pane (mirrors the FIDO2 "Reset this key" card exactly),
        // full width, description left + red button right.
        theme::card_frame(p)
            .stroke(egui::Stroke::new(1.0, theme::tint(p.err, 90)))
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new("Reset applet")
                            .font(theme::f_sb(14.5))
                            .color(p.err),
                    );
                    ui.add_space(6.0);
                    self.help_dot(ui, p, "reset");
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
                    .font(theme::f_reg(12.5))
                    .color(p.txt2),
                );
            });

        // Apply collected intents now that the card borrows have ended.
        if let Some(slot) = clicked_slot {
            self.piv.selected_slot = slot;
        }
        if do_refresh {
            self.load_piv_status();
        }
        // The three buttons open the centered credential modal; the modal itself
        // (rendered once per frame) runs the actual op. Opening wipes any stale
        // fields first so a fresh dialog starts blank.
        if open_change_pin {
            self.piv_cred_modal_close();
            self.piv.cred_modal = Some(PivCredModal::new(PivCredKind::ChangePin));
        }
        if open_change_puk {
            self.piv_cred_modal_close();
            self.piv.cred_modal = Some(PivCredModal::new(PivCredKind::ChangePuk));
        }
        if open_unblock {
            self.piv_cred_modal_close();
            self.piv.cred_modal = Some(PivCredModal::new(PivCredKind::UnblockPin));
        }
        // The management-key-gated operations open the centered credential modal
        // (which collects their secrets and runs the op on Submit) rather than
        // running directly. Opening wipes any stale secret fields first so a
        // fresh dialog starts blank. Export needs no secret, so it still runs
        // inline.
        if open_generate {
            self.piv_cred_modal_close();
            self.piv.cred_modal = Some(PivCredModal::new(PivCredKind::GenerateKey));
        }
        if open_import {
            self.piv_cred_modal_close();
            self.piv.cred_modal = Some(PivCredModal::new(PivCredKind::ImportCert));
        }
        if go_export {
            self.piv_export_cert();
        }
        if open_self_sign {
            self.piv_cred_modal_close();
            self.piv.cred_modal = Some(PivCredModal::new(PivCredKind::SelfSign));
        }
        if open_csr {
            self.piv_cred_modal_close();
            self.piv.cred_modal = Some(PivCredModal::new(PivCredKind::RequestCsr));
        }
        if open_set_retries {
            self.piv_cred_modal_close();
            self.piv.cred_modal = Some(PivCredModal::new(PivCredKind::SetRetries));
        }
        if open_change_mgmt {
            self.piv_cred_modal_close();
            self.piv.cred_modal = Some(PivCredModal::new(PivCredKind::ChangeMgmtKey));
        }
        if open_delete_cert {
            self.piv_cred_modal_close();
            self.piv.cred_modal = Some(PivCredModal::new(PivCredKind::DeleteCert));
        }
        if open_delete_key {
            self.piv_cred_modal_close();
            self.piv.cred_modal = Some(PivCredModal::new(PivCredKind::DeleteKey));
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
    fn molto_view(&mut self, ui: &mut egui::Ui, p: &Palette, dev: &Device) {
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
                                let resp = ui.add_sized(
                                    [200.0, 32.0],
                                    egui::TextEdit::singleline(&mut self.rename_input)
                                        .vertical_align(egui::Align::Center)
                                        .hint_text("friendly-name"),
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
                        ui.add_sized(
                            [200.0, 32.0],
                            egui::TextEdit::singleline(&mut self.customer_key_input)
                                .vertical_align(egui::Align::Center)
                                .password(true)
                                .hint_text("default if empty"),
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
                                #[cfg(feature = "qr")]
                                {
                                    let (resp, icon_center, fg) = theme::button_with_icon(
                                        ui,
                                        p,
                                        BtnKind::Default,
                                        "Scan QR",
                                        14.0,
                                    );
                                    paint_qr_icon(ui, icon_center, fg);
                                    if resp.clicked() {
                                        self.molto_scan_qr();
                                    }
                                }
                                #[cfg(feature = "qr")]
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

    /// Pane for the single-profile programmable token: shows model/serial/clock
    /// and a form to program a seed + configuration. Uses the brand accent like
    /// the Molto2 view.
    fn prog_view(&mut self, ui: &mut egui::Ui, p: &Palette, dev: &Device) {
        let mp = Palette {
            accent: p.brand,
            ..*p
        };
        let p = &mp;

        // Hero: brand tile + model + serial + on-device clock.
        egui::Frame::none()
            .inner_margin(egui::Margin::symmetric(26.0, 16.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    glyph_tile(ui, 46.0, p.brand, p.accent_ink, None);
                    ui.add_space(12.0);
                    ui.vertical(|ui| {
                        ui.label(
                            egui::RichText::new(dev.title())
                                .font(theme::f_bold(18.0))
                                .color(p.txt),
                        );
                        let serial = self
                            .prog_info
                            .as_ref()
                            .map(|i| i.serial.clone())
                            .unwrap_or_else(|| dev.serial.clone());
                        ui.label(
                            egui::RichText::new(format!("Token2 · serial {serial}"))
                                .font(theme::f_reg(12.5))
                                .color(p.txt2),
                        );
                        if let Some(info) = &self.prog_info {
                            ui.label(
                                egui::RichText::new(format!(
                                    "device clock (UTC): {}",
                                    fmt_unix_utc(info.utc_time)
                                ))
                                    .font(theme::f_reg(12.0))
                                    .color(p.txt3),
                            );
                        }
                    });
                });
            });

        ui.separator();

        // Program form.
        egui::Frame::none()
            .inner_margin(egui::Margin::symmetric(26.0, 12.0))
            .show(ui, |ui| {
                ui.label(
                    egui::RichText::new("Program seed & configuration")
                        .font(theme::f_sb(14.0))
                        .color(p.txt),
                );
                ui.add_space(8.0);

                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Seed:").font(theme::f_reg(12.5)).color(p.txt2));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.prog_seed_input)
                            .desired_width(320.0)
                            .hint_text(if self.prog_seed_hex { "hex" } else { "base32" }),
                    );
                    ui.checkbox(&mut self.prog_seed_hex, "hex");
                });
                ui.add_space(6.0);

                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Algorithm:").font(theme::f_reg(12.5)).color(p.txt2));
                    egui::ComboBox::from_id_salt("prog-algo")
                        .selected_text(if self.prog_algo_sha256 { "SHA256" } else { "SHA1" })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.prog_algo_sha256, false, "SHA1");
                            ui.selectable_value(&mut self.prog_algo_sha256, true, "SHA256");
                        });
                    ui.add_space(12.0);
                    ui.label(egui::RichText::new("Time step:").font(theme::f_reg(12.5)).color(p.txt2));
                    egui::ComboBox::from_id_salt("prog-step")
                        .selected_text(if self.prog_step_60 { "60s" } else { "30s" })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.prog_step_60, false, "30s");
                            ui.selectable_value(&mut self.prog_step_60, true, "60s");
                        });
                    ui.add_space(12.0);
                    ui.label(egui::RichText::new("Sleep:").font(theme::f_reg(12.5)).color(p.txt2));
                    let timeouts = ["15s", "30s", "60s", "120s"];
                    egui::ComboBox::from_id_salt("prog-timeout")
                        .selected_text(timeouts[self.prog_timeout_idx.min(3)])
                        .show_ui(ui, |ui| {
                            for (i, t) in timeouts.iter().enumerate() {
                                ui.selectable_value(&mut self.prog_timeout_idx, i, *t);
                            }
                        });
                });
                ui.add_space(12.0);

                let busy = self.busy();
                let can_burn = !busy && !self.prog_seed_input.trim().is_empty();
                ui.horizontal(|ui| {
                    ui.add_enabled_ui(can_burn, |ui| {
                        if theme::button(ui, p, BtnKind::Primary, "Burn seed").clicked() {
                            self.prog_burn();
                        }
                    });
                    #[cfg(feature = "qr")]
                    {
                        ui.add_space(6.0);
                        let (resp, icon_center, fg) =
                            theme::button_with_icon(ui, p, BtnKind::Default, "Scan QR", 14.0);
                        paint_qr_icon(ui, icon_center, fg);
                        if resp.clicked() {
                            self.prog_scan_qr();
                        }
                    }
                });
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(
                        "Sets the configuration (clock + parameters) and writes the seed.",
                    )
                    .font(theme::f_reg(11.5))
                    .color(p.txt3),
                );

                if let Some((ok, msg)) = &self.prog_status {
                    ui.add_space(8.0);
                    ui.label(
                        egui::RichText::new(msg)
                            .font(theme::f_sb(12.5))
                            .color(if *ok { p.ok } else { p.err }),
                    );
                }
            });
    }

    /// Authenticate (fixed device key) and program config + seed in one job.
    fn prog_burn(&mut self) {
        self.prog_status = None;
        let Some(reader) = self.selected_device().and_then(|d| d.reader.clone()) else {
            return;
        };
        // Decode the seed up front so input errors surface before any I/O.
        let raw = self.prog_seed_input.trim().to_string();
        let seed = if self.prog_seed_hex {
            keyroost_proto::codec::hex_decode(&raw)
        } else {
            keyroost_proto::codec::base32_decode(&raw)
        };
        let seed = match seed {
            Ok(s) if !s.is_empty() && s.len() <= 63 => s,
            Ok(s) => {
                self.log(Severity::Err, format!("seed length {} out of range (1..=63)", s.len()));
                return;
            }
            Err(e) => {
                self.log(Severity::Err, format!("invalid seed: {e}"));
                return;
            }
        };
        // Pad short seeds to the standard 20-byte TOTP length with trailing
        // zero bytes, matching the vendor tool. Without this a 10-byte base32
        // secret is stored as 10 bytes and the device's codes won't match an
        // authenticator app that uses the same secret padded to 20 bytes.
        let seed = keyroost_token2prog::pad_totp_seed(seed);
        let algo = if self.prog_algo_sha256 {
            keyroost_token2prog::HmacAlgo::Sha256
        } else {
            keyroost_token2prog::HmacAlgo::Sha1
        };
        let step = if self.prog_step_60 {
            keyroost_token2prog::TimeStep::Seconds60
        } else {
            keyroost_token2prog::TimeStep::Seconds30
        };
        let timeout = match self.prog_timeout_idx {
            0 => keyroost_token2prog::DisplayTimeout::Sec15,
            2 => keyroost_token2prog::DisplayTimeout::Sec60,
            3 => keyroost_token2prog::DisplayTimeout::Sec120,
            _ => keyroost_token2prog::DisplayTimeout::Sec30,
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);

        self.spawn_job("Programming token\u{2026}", move || {
            let result = (|| -> Result<(), TransportError> {
                let mut s = Token2ProgSession::open_named(&reader)?;
                s.authenticate()?;
                let cfg = keyroost_token2prog::Config {
                    display_timeout: timeout,
                    algorithm: algo,
                    time_step: step,
                    utc_time: now,
                };
                s.set_config(&cfg)?;
                s.set_seed(&seed)?;
                Ok(())
            })();
            Box::new(move |app: &mut App| match result {
                Ok(()) => {
                    app.log(Severity::Ok, "programmed token (config + seed)".to_string());
                    app.prog_status =
                        Some((true, "Seed and configuration programmed successfully.".to_string()));
                    app.prog_seed_input.clear();
                }
                Err(e) => {
                    app.log(Severity::Err, format!("program token: {e}"));
                    app.prog_status = Some((false, format!("Programming failed: {e}")));
                }
            })
        });
    }

    /// Scan a TOTP QR from the screen and fill the prog seed form from it.
    #[cfg(feature = "qr")]
    fn prog_scan_qr(&mut self) {
        self.prog_status = None;
        let uri = match qrscan::scan_screens_for_otpauth() {
            Ok(u) => u,
            Err(e) => {
                self.prog_status = Some((false, e));
                return;
            }
        };
        let parsed = match parse_otpauth(&uri) {
            Ok(p) => p,
            Err(e) => {
                self.prog_status = Some((false, format!("QR parse failed: {e}")));
                return;
            }
        };
        // Fill the seed with the original base32 secret from the URI.
        let secret = uri
            .find("secret=")
            .map(|i| {
                let rest = &uri[i + 7..];
                let end = rest.find('&').unwrap_or(rest.len());
                rest[..end].to_owned()
            })
            .unwrap_or_default();
        if secret.is_empty() {
            self.prog_status = Some((false, "scanned QR has no secret".into()));
            return;
        }
        self.prog_seed_input = secret;
        self.prog_seed_hex = false;
        self.prog_algo_sha256 = matches!(parsed.algorithm, HmacAlgo::Sha256);
        self.prog_step_60 = matches!(parsed.time_step, TimeStep::Seconds60);
        self.prog_status = Some((true, "Filled seed and parameters from the scanned QR.".into()));
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

    /// The PIV credential modal's new==confirm guard: matching (or still-empty)
    /// confirm fields pass; a divergent confirm reports the right message.
    #[test]
    fn piv_cred_mismatch_change_pin() {
        let mut piv = PivState::default();
        // Empty confirm is treated as "not yet a mismatch".
        piv.pin_new = "1234".into();
        assert_eq!(piv_cred_mismatch(&piv, PivCredKind::ChangePin), None);
        // Matching new/confirm: no error.
        piv.pin_confirm = "1234".into();
        assert_eq!(piv_cred_mismatch(&piv, PivCredKind::ChangePin), None);
        // Divergent confirm: the PIN-specific message.
        piv.pin_confirm = "9999".into();
        assert_eq!(
            piv_cred_mismatch(&piv, PivCredKind::ChangePin),
            Some("the two new PINs don't match")
        );
    }

    #[test]
    fn piv_cred_mismatch_change_puk() {
        let mut piv = PivState::default();
        piv.puk_new = "12345678".into();
        piv.puk_confirm = "00000000".into();
        assert_eq!(
            piv_cred_mismatch(&piv, PivCredKind::ChangePuk),
            Some("the two new PUKs don't match")
        );
        piv.puk_confirm = "12345678".into();
        assert_eq!(piv_cred_mismatch(&piv, PivCredKind::ChangePuk), None);
    }

    /// Unblock has no confirm field, so the guard never reports a mismatch even
    /// with arbitrary field contents.
    #[test]
    fn piv_cred_mismatch_unblock_never_fires() {
        let mut piv = PivState::default();
        piv.unblock_puk = "12345678".into();
        piv.unblock_new_pin = "1234".into();
        assert_eq!(piv_cred_mismatch(&piv, PivCredKind::UnblockPin), None);
    }

    /// Each flow maps to its own title, busy caption, and success text.
    #[test]
    fn piv_cred_kind_strings_are_distinct() {
        let kinds = [
            PivCredKind::ChangePin,
            PivCredKind::ChangePuk,
            PivCredKind::UnblockPin,
        ];
        let titles: Vec<_> = kinds.iter().map(|k| k.title()).collect();
        assert_eq!(titles, ["Change PIN", "Change PUK", "Unblock PIN"]);
        assert_eq!(piv_cred_success(PivCredKind::ChangePin), "PIN changed");
        assert_eq!(piv_cred_success(PivCredKind::ChangePuk), "PUK changed");
        assert_eq!(
            piv_cred_success(PivCredKind::UnblockPin),
            "PIN unblocked and reset"
        );
        // Busy captions are non-empty and unique.
        let busy: Vec<_> = kinds.iter().map(|k| k.busy_label()).collect();
        assert!(busy.iter().all(|s| !s.is_empty()));
        assert_eq!(busy[0], "Changing PIV PIN\u{2026}");
    }

    /// The management-key-gated flows declare they collect the current
    /// management key (and therefore show the "Use default" toggle); the PIN/PUK
    /// and CSR flows do not.
    #[test]
    fn piv_cred_kind_mgmt_key_mapping() {
        assert!(PivCredKind::GenerateKey.needs_mgmt_key());
        assert!(PivCredKind::ImportCert.needs_mgmt_key());
        assert!(PivCredKind::SelfSign.needs_mgmt_key());
        assert!(PivCredKind::SetRetries.needs_mgmt_key());
        assert!(PivCredKind::ChangeMgmtKey.needs_mgmt_key());
        // Slot deletion is authorized by the management key (like generate).
        assert!(PivCredKind::DeleteCert.needs_mgmt_key());
        assert!(PivCredKind::DeleteKey.needs_mgmt_key());
        // CSR signs with the PIN only — no management key.
        assert!(!PivCredKind::RequestCsr.needs_mgmt_key());
        // PIN/PUK flows never collect a management key.
        assert!(!PivCredKind::ChangePin.needs_mgmt_key());
        assert!(!PivCredKind::ChangePuk.needs_mgmt_key());
        assert!(!PivCredKind::UnblockPin.needs_mgmt_key());
    }

    /// Every new gated variant has a distinct, non-empty title / submit label /
    /// busy caption / success line.
    #[test]
    fn piv_cred_kind_gated_strings_are_present() {
        let kinds = [
            PivCredKind::GenerateKey,
            PivCredKind::ImportCert,
            PivCredKind::SelfSign,
            PivCredKind::RequestCsr,
            PivCredKind::SetRetries,
            PivCredKind::ChangeMgmtKey,
            PivCredKind::DeleteCert,
            PivCredKind::DeleteKey,
        ];
        for k in kinds {
            assert!(!k.title().is_empty());
            assert!(!k.submit_label().is_empty());
            assert!(k.busy_label().ends_with('\u{2026}'));
            assert!(!piv_cred_success(k).is_empty());
        }
        // Mismatch guard only fires for the PIN/PUK change flows; gated flows
        // never report a new==confirm mismatch.
        let piv = PivState::default();
        for k in kinds {
            assert_eq!(piv_cred_mismatch(&piv, k), None);
        }
    }

    /// The standard PIV factory default is 24 bytes of `01..08` ×3; Token2 PIN+
    /// ships its own vendor default. Both decode to 24-byte keys.
    #[test]
    fn piv_default_mgmt_key_is_well_known() {
        let std = piv_default_mgmt_key_hex(false);
        assert_eq!(std, "010203040506070801020304050607080102030405060708");
        let bytes = piv_mgmt_key_bytes(std).unwrap();
        assert_eq!(bytes.len(), 24);
        assert_eq!(&bytes[..8], &[1, 2, 3, 4, 5, 6, 7, 8]);
        // Repeated three times.
        assert_eq!(&bytes[8..16], &bytes[..8]);
        assert_eq!(&bytes[16..24], &bytes[..8]);

        let t2 = piv_default_mgmt_key_hex(true);
        assert_eq!(piv_mgmt_key_bytes(t2).unwrap().len(), 24);
        assert_ne!(std, t2);
    }

    /// `OathAddDialog::validate` trims the name, requires it, base32-decodes the
    /// secret, and rejects an empty/invalid secret — the same guards the modal's
    /// Submit relies on before dispatching `provision_oath`.
    #[test]
    fn oath_add_dialog_validate() {
        // Empty name → error, regardless of the secret.
        let mut d = OathAddDialog::opened();
        d.name = "  ".into();
        d.secret = "JBSWY3DPEHPK3PXP".into();
        assert_eq!(d.validate().unwrap_err(), "credential name is required");

        // Empty secret → error.
        d.name = "acme:alice".into();
        d.secret = String::new();
        assert_eq!(d.validate().unwrap_err(), "secret is empty");

        // Non-base32 secret → "invalid base32 secret: …".
        d.secret = "not base32!!".into();
        assert!(d
            .validate()
            .unwrap_err()
            .starts_with("invalid base32 secret"));

        // Valid input → trimmed name + decoded secret bytes.
        d.name = "  acme:alice  ".into();
        d.secret = "JBSWY3DPEHPK3PXP".into();
        let (name, secret) = d.validate().expect("valid");
        assert_eq!(name, "acme:alice");
        assert_eq!(
            secret,
            keyroost_proto::codec::base32_decode("JBSWY3DPEHPK3PXP").unwrap()
        );
        assert!(!secret.is_empty());
    }

    /// `apply_oath_rows` mirrors the provision outcome into the open add modal
    /// (busy clears; success → `Ok`, error → `Err(message)`) and does *not*
    /// double-report into the pane-level `oath.error` while the modal owns the op.
    #[test]
    fn apply_oath_rows_mirrors_into_add_modal() {
        // Success path: modal busy → result Ok, busy cleared, rows applied.
        let mut app = App::default();
        app.oath.add = OathAddDialog::opened();
        app.oath.add.busy = true;
        App::apply_oath_rows(
            &mut app,
            Ok(vec![OathRow {
                name: "x".into(),
                code: None,
            }]),
        );
        assert!(!app.oath.add.busy);
        assert_eq!(app.oath.add.result, Some(Ok(())));
        assert_eq!(app.oath.creds.len(), 1);
        assert!(app.oath.error.is_none());

        // Error path: wrong password surfaces in the modal, not the pane.
        let mut app = App::default();
        app.oath.add = OathAddDialog::opened();
        app.oath.add.busy = true;
        App::apply_oath_rows(&mut app, Err(TransportError::OathPasswordRejected));
        assert!(!app.oath.add.busy);
        assert_eq!(app.oath.add.result, Some(Err("wrong OATH password".into())));
        assert!(app.oath.error.is_none());

        // No modal open: the pane-level error path still works (unlock/refresh).
        let mut app = App::default();
        App::apply_oath_rows(&mut app, Err(TransportError::OathPasswordRejected));
        assert!(!app.oath.add.open);
        assert!(app.oath.locked);
        assert_eq!(app.oath.error.as_deref(), Some("wrong OATH password"));
    }

    /// With "Use default management key" ticked, `piv_current_mgmt_key` ignores
    /// the (possibly empty) hex field and yields the well-known default; with it
    /// off, it decodes the typed hex.
    #[test]
    fn piv_current_mgmt_key_honours_use_default() {
        let mut app = App::default();
        // Default toggle on, hex field empty → resolves to the non-Token2 default
        // (no device selected ⇒ not Token2).
        app.piv.use_default_mgmt = true;
        app.piv.mgmt_key_input.clear();
        let key = app.piv_current_mgmt_key().expect("default fills");
        assert_eq!(
            &key[..],
            &piv_mgmt_key_bytes(piv_default_mgmt_key_hex(false)).unwrap()[..]
        );

        // Toggle off → uses the typed hex.
        app.piv.use_default_mgmt = false;
        app.piv.mgmt_key_input = "aabbccddeeff00112233445566778899aabbccddeeff0011".into();
        let typed = app.piv_current_mgmt_key().expect("valid hex");
        assert_eq!(typed.len(), 24);
        assert_eq!(typed[0], 0xaa);

        // Toggle off with bad hex → error surfaces.
        app.piv.mgmt_key_input = "nothex".into();
        assert!(app.piv_current_mgmt_key().is_err());
    }

    /// `apply_piv_cred_result` mirrors the pane outcome into the open modal:
    /// no error → `Ok`, error present → `Err(message)`, and `busy` clears.
    #[test]
    fn apply_piv_cred_result_mirrors_outcome() {
        let mut app = App::default();
        // Success path.
        app.piv.cred_modal = Some(PivCredModal {
            kind: PivCredKind::ChangePin,
            busy: true,
            result: None,
        });
        app.piv.error = None;
        App::apply_piv_cred_result(&mut app);
        let m = app.piv.cred_modal.as_ref().unwrap();
        assert!(!m.busy);
        assert_eq!(m.result, Some(Ok(())));

        // Error path.
        app.piv.cred_modal = Some(PivCredModal::new(PivCredKind::ChangePuk));
        app.piv.cred_modal.as_mut().unwrap().busy = true;
        app.piv.error = Some("wrong PUK".into());
        App::apply_piv_cred_result(&mut app);
        let m = app.piv.cred_modal.as_ref().unwrap();
        assert!(!m.busy);
        assert_eq!(m.result, Some(Err("wrong PUK".into())));
    }

    /// `PivSlotSel::label` maps each selector to the canonical PIV slot name; the
    /// delete flows name this slot in their destructive warning and success line.
    #[test]
    fn piv_slot_sel_labels() {
        assert_eq!(PivSlotSel::Auth.label(), "authentication (9A)");
        assert_eq!(PivSlotSel::Sign.label(), "signature (9C)");
        assert_eq!(PivSlotSel::KeyMgmt.label(), "key management (9D)");
        assert_eq!(PivSlotSel::CardAuth.label(), "card authentication (9E)");
    }

    /// `OpenPgpCredKind::needs_admin_pin` is true for every admin-PIN (PW3)-gated
    /// flow and false for the self-authorising user-PIN change and the PIN-less
    /// reset — this is what decides whether the admin-PIN field + use-default
    /// toggle render in the modal.
    #[test]
    fn openpgp_cred_kind_needs_admin_pin_mapping() {
        use OpenPgpCredKind::*;
        for k in [
            ChangeAdminPin,
            UnblockUserPin,
            SetName,
            SetUrl,
            GenerateKey,
            GenerateImportKey,
            ImportKeyFile,
        ] {
            assert!(k.needs_admin_pin(), "{} should need PW3", k.title());
        }
        for k in [ChangeUserPin, Reset] {
            assert!(!k.needs_admin_pin(), "{} should not need PW3", k.title());
        }
    }

    /// With "Use default admin PIN (PW3)" ticked, `openpgp_admin_pin_value`
    /// ignores the (possibly empty) typed field and yields the well-known factory
    /// default; with it off, it returns the typed PIN verbatim.
    #[test]
    fn openpgp_admin_pin_value_honours_use_default() {
        let mut app = App::default();

        // Default toggle on, field empty → resolves to the factory default.
        app.openpgp.use_default_admin = true;
        app.openpgp.admin_pin.clear();
        assert_eq!(app.openpgp_admin_pin_value(), OPENPGP_DEFAULT_ADMIN_PIN);
        assert_eq!(app.openpgp_admin_pin_value(), "12345678");

        // Toggle off → uses the typed PIN.
        app.openpgp.use_default_admin = false;
        app.openpgp.admin_pin = "7654321".into();
        assert_eq!(app.openpgp_admin_pin_value(), "7654321");
    }

    /// `apply_openpgp_cred_result` mirrors the pane outcome into the open modal:
    /// no error → `Ok`, error present → `Err(message)`, and `busy` clears.
    #[test]
    fn apply_openpgp_cred_result_mirrors_outcome() {
        let mut app = App::default();

        // Success path.
        app.openpgp.cred_modal = Some(OpenPgpCredModal {
            kind: OpenPgpCredKind::SetName,
            busy: true,
            result: None,
        });
        app.openpgp.error = None;
        App::apply_openpgp_cred_result(&mut app);
        let m = app.openpgp.cred_modal.as_ref().unwrap();
        assert!(!m.busy);
        assert_eq!(m.result, Some(Ok(())));

        // Error path.
        app.openpgp.cred_modal = Some(OpenPgpCredModal::new(OpenPgpCredKind::ChangeAdminPin));
        app.openpgp.cred_modal.as_mut().unwrap().busy = true;
        app.openpgp.error = Some("wrong admin PIN".into());
        App::apply_openpgp_cred_result(&mut app);
        let m = app.openpgp.cred_modal.as_ref().unwrap();
        assert!(!m.busy);
        assert_eq!(m.result, Some(Err("wrong admin PIN".into())));
    }

    /// The OpenPGP mismatch guard is inert (the PIN forms have no confirm field),
    /// so it returns `None` for every flow — locks in the documented behaviour.
    #[test]
    fn openpgp_cred_mismatch_never_fires() {
        use OpenPgpCredKind::*;
        let pgp = OpenPgpState {
            user_pin_new: "111111".into(),
            admin_pin_new: "22222222".into(),
            ..Default::default()
        };
        for k in [
            ChangeUserPin,
            ChangeAdminPin,
            UnblockUserPin,
            SetName,
            SetUrl,
            GenerateKey,
            GenerateImportKey,
            ImportKeyFile,
            Reset,
        ] {
            assert!(openpgp_cred_mismatch(&pgp, k).is_none());
        }
    }
}
