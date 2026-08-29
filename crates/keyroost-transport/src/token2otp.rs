//! Token2 T2F2 / PIN+ on-device OTP management over USB-HID or PC/SC.
//!
//! Drives the OTP applet using the pure-byte builders/parsers and the ECDH+AES
//! seal in [`keyroost_token2otp`]. Two transports implement the same
//! `transmit` contract:
//!
//! * **USB-HID** ([`HidOtpTransport`]) — the primary path for a key plugged into
//!   USB. Uses the applet's own 64-byte feature-report framing (spec §4), not
//!   CTAP-HID. Honors the `0xC0` "device busy" polling flag and fires a
//!   button-press prompt callback while a touch-required command waits.
//! * **PC/SC** ([`PcScOtpTransport`]) — for NFC / contact readers, where framing
//!   is native and there is no button-press polling (spec §5).
//!
//! [`Token2OtpSession`] wraps either transport with the high-level operations:
//! enumerate, read-one, write, delete, erase-all, the button-HOTP keystroke
//! slot, TOTP enable, the device-config read, the guarded `SET_DEVICE_TYPE`, and
//! the serial-number read.
//!
//! Seeds never touch argv or logs; cleartext seed payloads are scrubbed by the
//! byte layer, and this module redacts secret-bearing traffic from the debug
//! trace in *both* directions: seed-bearing request bodies on the way out, and
//! `ENUM_CODES` responses (which carry account names and live OTP codes) on the
//! way back — on the HID and PC/SC transports alike.

use keyroost_token2otp as t2;
use keyroost_token2otp::entry::{serialize_enum_all, ParseError};
use keyroost_token2otp::hidframe::{self, ResponseAssembler, Step};
use keyroost_token2otp::{cmd, EncryptError, Entry, OtpError, OtpType, WriteEntry};

#[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
use std::fs::{File, OpenOptions};
#[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
use std::io::Write;
use std::path::Path;
#[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
use std::sync::mpsc;
#[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
use std::thread;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// Errors specific to the Token2 OTP applet. Kept separate from the crate-wide
/// `TransportError` so the OTP feature can evolve without churning every other
/// applet's error surface; the CLI maps these to exit messages.
#[derive(Debug)]
pub enum OtpTransportError {
    /// No Token2 OTP-capable device was found on any transport (spec §8.4
    /// `TokenNotDetected`).
    TokenNotDetected,
    /// A transport opened but I/O failed partway (spec §8.4 `TransportUnavailable`).
    TransportUnavailable(String),
    /// HID frame-level error (bad magic, sequence, oversized chunk).
    Frame(hidframe::FrameError),
    /// The applet returned a non-success status word.
    Applet(OtpError),
    /// A response could not be parsed.
    Parse(ParseError),
    /// The ECDH+AES seal failed (bad device pubkey or RNG failure).
    Encrypt(EncryptError),
    /// PC/SC service / reader error.
    Pcsc(pcsc::Error),
    /// The device sent a response with no status word at all.
    EmptyResponse,
    /// Reading the serial over PC/SC needs a FIDO-applet SELECT that this
    /// reader/model refused (spec §6.10).
    SerialUnavailable,
    /// A Token2 key was found, but the OTP applet was not reachable over either
    /// HID or CCID — typically because HID is disabled on the device and no
    /// contact/NFC reader is available. Enable one of the interfaces (or place
    /// the key on a reader) and retry.
    NoUsableInterface,
    /// The device kept reporting "more enumeration pages" (or streaming
    /// entries) past the host-owned caps — a device-controlled continuation
    /// flag must never drive unbounded host work (audit KEY-009), so this is
    /// treated as a buggy or hostile token rather than looped on forever.
    EnumerationCapExceeded,
    /// The key declined the OTP applet over HID with a status word, *and* the
    /// CCID fallback was unavailable — carrying why, because on these models
    /// the CCID failure is the one the user can act on.
    ///
    /// Distinct from [`NoUsableInterface`](Self::NoUsableInterface) on purpose.
    /// A status word proves HID carried a full request and response, so the
    /// interface plainly works and "HID may be disabled; enable it" is wrong
    /// advice. Token2 explained the real shape in issue #95: models with no
    /// HOTP-over-HID ship with the HID channel disabled *by design* and carry
    /// OTP over CCID, so a declined HID probe is expected and the actionable
    /// fault is whatever stopped CCID — for the reporter, a smart-card service
    /// that was not running.
    HidDeclinedAndNoCcid { sw: u16, ccid: String },
    /// The key has an OTP PIN set, but no PIN was supplied for an operation that
    /// needs one (the caller — CLI or GUI — should prompt for it and retry).
    PinRequired,
    /// A PIN operation needed the ECDH session keys and none were cached. An
    /// internal ordering fault, distinct from a short or malformed device
    /// response — which is what reusing `Parse(Truncated)` for it used to say.
    PinSessionMissing,
}

impl std::fmt::Display for OtpTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OtpTransportError::TokenNotDetected => {
                write!(f, "no Token2 OTP-capable security key was detected")
            }
            OtpTransportError::TransportUnavailable(s) => write!(f, "transport unavailable: {}", s),
            OtpTransportError::Frame(e) => write!(f, "HID framing error: {}", e),
            OtpTransportError::Applet(e) => write!(f, "{}", e),
            OtpTransportError::Parse(e) => write!(f, "{}", e),
            OtpTransportError::Encrypt(e) => write!(f, "{}", e),
            OtpTransportError::Pcsc(e) => write!(f, "PC/SC error: {}", e),
            OtpTransportError::EmptyResponse => write!(f, "device returned an empty response"),
            OtpTransportError::SerialUnavailable => {
                write!(f, "this model/reader does not expose the serial number")
            }
            OtpTransportError::NoUsableInterface => write!(
                f,
                "the OTP applet is not reachable over HID or CCID — HID may be \
                 disabled on the key; enable it, or use a contact/NFC reader"
            ),
            OtpTransportError::EnumerationCapExceeded => write!(
                f,
                "the device kept reporting more OTP entries than any supported \
                 token stores; aborting enumeration"
            ),
            OtpTransportError::HidDeclinedAndNoCcid { sw, ccid } => write!(
                f,
                "{} over USB-HID (status word {:#06X}). Token2 models without \
                 HOTP-over-HID ship with the HID channel disabled, so there is nothing \
                 to enable on the key — OTP is carried over CCID instead, and that is \
                 the path that failed: {}. Start the smart-card service (pcscd on \
                 Linux; the Smart Card service on Windows; built in on macOS) or place \
                 the key on a contact/NFC reader, then retry — `--transport ccid` \
                 forces it",
                if keyroost_token2otp::sw::is_applet_status(*sw) {
                    "the OTP applet declined the request"
                } else {
                    // Outside 0x6xxx/0x9000 the applet was never reached: the
                    // answer came from a layer in front of it. Saying "the
                    // applet declined" would misattribute it (issue #95).
                    "the key answered, but not from the OTP applet"
                },
                sw,
                ccid
            ),
            OtpTransportError::PinRequired => write!(
                f,
                "this key's OTP codes are PIN-protected; supply the OTP PIN to unlock them"
            ),
            OtpTransportError::PinSessionMissing => {
                write!(f, "no OTP-PIN session was established before a PIN command")
            }
        }
    }
}

impl std::error::Error for OtpTransportError {}

impl From<hidframe::FrameError> for OtpTransportError {
    fn from(e: hidframe::FrameError) -> Self {
        OtpTransportError::Frame(e)
    }
}
impl From<OtpError> for OtpTransportError {
    fn from(e: OtpError) -> Self {
        OtpTransportError::Applet(e)
    }
}
impl From<ParseError> for OtpTransportError {
    fn from(e: ParseError) -> Self {
        OtpTransportError::Parse(e)
    }
}
impl From<EncryptError> for OtpTransportError {
    fn from(e: EncryptError) -> Self {
        OtpTransportError::Encrypt(e)
    }
}
impl From<pcsc::Error> for OtpTransportError {
    fn from(e: pcsc::Error) -> Self {
        OtpTransportError::Pcsc(e)
    }
}

/// Callback invoked once when a touch-required command has been waiting on the
/// key for a few poll cycles, so a front-end can prompt "touch your key".
/// Callback fired while a touch-required command waits. Must be `Send`: the
/// transport may be moved onto a worker thread (e.g. the time-bounded HID probe
/// in [`Token2OtpSession::detect`]).
pub type ButtonPrompt = Box<dyn FnMut() + Send>;

/// The contract both transports implement: send one APDU and return
/// `(response_data, status_word)`, having handled all framing/reassembly and,
/// for HID, the `0xC0` busy-poll loop.
trait OtpTransport {
    fn transmit(
        &mut self,
        apdu: &[u8],
        detect_button_wait: bool,
    ) -> Result<(Vec<u8>, u16), OtpTransportError>;
    fn set_button_prompt(&mut self, _cb: ButtonPrompt) {}
    fn set_debug(&mut self, _on: bool) {}
}

// ---------------------------------------------------------------------------
// USB-HID transport
// ---------------------------------------------------------------------------

/// Platform HID I/O — hidraw `File` on Linux, hidapi elsewhere. Mirrors the
/// split in `keyroost-ctap`'s HID transport so the workspace keeps one backend
/// story.
enum HidIo {
    #[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
    Hidraw(File),
    #[cfg(any(not(target_os = "linux"), feature = "hidapi-backend"))]
    Hidapi(hidapi::HidDevice),
}

/// True when the *response* to `apdu` carries user secrets — account names and
/// live OTP codes — and so must be redacted from the debug trace.
///
/// Only the `ENUM_CODES` / `ENUM_CODES_CONTINUE` reads (INS `0xC5`, P1 `0x05`,
/// P2 `0x00`/`0x01`) return entry data. `WRITE_SEED` shares P1 `0x05` but its
/// request (not response) is the secret-bearing side and answers with a status
/// word only; every other command returns public config, the public ECDH key,
/// the serial, or a bare status word. Keyed off the *original* command so a
/// `61xx` GET-RESPONSE continuation (which resends a different header) still
/// inherits the correct verdict.
fn response_is_sensitive(apdu: &[u8]) -> bool {
    matches!(
        (apdu.get(1), apdu.get(2), apdu.get(3)),
        (Some(&0xC5), Some(&0x05), Some(&0x00) | Some(&0x01))
    )
}

/// True when `apdu`'s *request* body carries the encrypted seed blob and should
/// be redacted from the send trace (`WRITE_SEED` / `WRITE_HOTP_SEED`, spec
/// §1.3). Shared by both transports so a seed never reaches the trace on either
/// path.
fn request_is_sensitive(apdu: &[u8]) -> bool {
    matches!(apdu.get(1), Some(0xC5))
        && matches!(apdu.get(2), Some(0x05) | Some(0x00))
        && matches!(apdu.get(3), Some(0x02) | Some(0x00))
}

/// Render one debug-trace line. Sensitive payloads (seed blobs on the way
/// out, ENUM_CODES entry data on the way back) are length-redacted;
/// everything else is dumped as lowercase hex. This is the single place the
/// redaction policy is *rendered* — the four former inline copies of this
/// block had drifted apart in wording. Pure, so the "secrets never reach the
/// trace" guarantee is unit-testable.
fn trace_line(label: &str, bytes: &[u8], sensitive: bool) -> String {
    if sensitive {
        format!("[token2otp {label}] <{} bytes redacted>", bytes.len())
    } else {
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        format!("[token2otp {label}] {hex}")
    }
}

/// Print one debug-trace line to stderr when `debug` is on. Every byte dump
/// in this module — both transports, both directions — must go through here
/// so the redaction policy in [`trace_line`] cannot drift per call site.
fn trace_bytes(debug: bool, label: &str, bytes: &[u8], sensitive: bool) {
    if debug {
        eprintln!("{}", trace_line(label, bytes, sensitive));
    }
}

// The `6C xx` ("wrong Le") retry classifier lives in `keyroost_proto::apdu`
// (pure ISO 7816-4 logic, fuzzed there via the `otp_apdu_retry` target);
// re-exported so this transport's callers and tests keep their name for it.
pub(crate) use keyroost_proto::apdu::resend_with_le;

/// USB-HID transport for the Token2 OTP applet (spec §4).
pub struct HidOtpTransport {
    io: HidIo,
    timeout: Duration,
    button_prompt: Option<ButtonPrompt>,
    debug: bool,
    /// Set per-command before the response read loop: when the in-flight
    /// command's response carries secrets ([`response_is_sensitive`]), the raw
    /// per-frame dump and the parsed-response dump are redacted.
    resp_sensitive: bool,
}

impl HidOtpTransport {
    /// Open the first connected Token2 OTP key (spec §2.1). Matches on the
    /// Token2 vendor ID plus either the FIDO usage page or the product string,
    /// rather than a single hard-coded PID — these keys ship under several PIDs
    /// (e.g. 0x0014, 0x0022) that all expose the same OTP applet.
    pub fn open_first() -> Result<Self, OtpTransportError> {
        let devices = keyroost_hid::enumerate()
            .map_err(|e| OtpTransportError::TransportUnavailable(e.to_string()))?;
        let found = devices.into_iter().find(|d| {
            d.vendor_id == t2::USB_VID
                && (d.usage_page == t2::FIDO_USAGE_PAGE
                    || d.product_name.contains(t2::USB_PRODUCT)
                    || d.product_id == t2::USB_PID)
        });
        let dev = found.ok_or(OtpTransportError::TokenNotDetected)?;
        // Deliberately NOT gated on the PID's function set. A PID names an
        // enabled function set, not proof that an applet is absent, and OTP
        // may live on a channel this opener does not speak: Token2 confirmed
        // in issue #95 that Bio3 (0x0204) carries OTP over CCID while shipping
        // with HID disabled, because it has no HOTP-over-HID. Refusing here on
        // the table would deny OTP to a key that has it.
        Self::open_path(&dev.path)
    }

    /// Open a specific hidraw / platform device path.
    pub fn open_path(path: &Path) -> Result<Self, OtpTransportError> {
        let io = Self::open_io(path)?;
        Ok(Self {
            io,
            timeout: Duration::from_secs(20),
            button_prompt: None,
            debug: false,
            resp_sensitive: false,
        })
    }

    #[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
    fn open_io(path: &Path) -> Result<HidIo, OtpTransportError> {
        // O_NONBLOCK so read_report can poll with a budget instead of
        // blocking forever on a silent device (audit KEY-011); hidraw writes
        // do not consult it.
        use std::os::unix::fs::OpenOptionsExt;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(keyroost_hid::O_NONBLOCK)
            .open(path)
            .map_err(|e| OtpTransportError::TransportUnavailable(e.to_string()))?;
        Ok(HidIo::Hidraw(file))
    }

    #[cfg(any(not(target_os = "linux"), feature = "hidapi-backend"))]
    fn open_io(path: &Path) -> Result<HidIo, OtpTransportError> {
        let api = hidapi::HidApi::new()
            .map_err(|e| OtpTransportError::TransportUnavailable(e.to_string()))?;
        let cpath = std::ffi::CString::new(path.to_string_lossy().as_bytes())
            .map_err(|_| OtpTransportError::TransportUnavailable("device path had a NUL".into()))?;
        let dev = api
            .open_path(&cpath)
            .map_err(|e| OtpTransportError::TransportUnavailable(e.to_string()))?;
        Ok(HidIo::Hidapi(dev))
    }

    /// Write one 65-byte report (leading `0x00` report ID). This device uses
    /// interrupt OUT reports on its HID interface (the same path keyroost-ctap
    /// uses for FIDO on this key) — not feature reports, which Windows rejects
    /// with "Incorrect function" for this interface.
    fn write_report(&mut self, frame: &[u8]) -> Result<(), OtpTransportError> {
        match &mut self.io {
            #[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
            HidIo::Hidraw(f) => f
                .write_all(frame)
                .map_err(|e| OtpTransportError::TransportUnavailable(e.to_string()))?,
            #[cfg(any(not(target_os = "linux"), feature = "hidapi-backend"))]
            HidIo::Hidapi(d) => {
                d.write(frame)
                    .map_err(|e| OtpTransportError::TransportUnavailable(e.to_string()))?;
            }
        }
        Ok(())
    }

    /// Read one input report via interrupt IN. Linux hidraw delivers the 64
    /// payload bytes directly; hidapi on Windows/macOS returns the 64-byte
    /// report (report ID 0 is not prepended for non-numbered reports). The
    /// assembler auto-detects whether a report-ID byte is present.
    fn read_report(
        &mut self,
        buf: &mut [u8; hidframe::REPORT_PAYLOAD + 1],
    ) -> Result<usize, OtpTransportError> {
        let n = match &mut self.io {
            #[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
            HidIo::Hidraw(f) => {
                // Bounded read (KEY-011): the fd is O_NONBLOCK and the helper
                // polls with a budget; `0` means the budget elapsed with no
                // report, and the transmit loop re-checks its deadline.
                keyroost_hid::read_nonblocking_bounded(f, &mut buf[..hidframe::REPORT_PAYLOAD])
                    .map_err(|e| OtpTransportError::TransportUnavailable(e.to_string()))?
            }
            #[cfg(any(not(target_os = "linux"), feature = "hidapi-backend"))]
            HidIo::Hidapi(d) => {
                // Bounded read via the shared helper (see
                // `keyroost_hid::read_report_bounded` for the poll contract):
                // `0` means the poll interval elapsed with no report; the
                // transmit loop treats that as "retry" and re-checks its
                // deadline.
                keyroost_hid::read_report_bounded(d, &mut buf[..hidframe::REPORT_PAYLOAD])
                    .map_err(|e| OtpTransportError::TransportUnavailable(e.to_string()))?
            }
        };
        if n > 0 {
            trace_bytes(self.debug, "HID raw-frame", &buf[..n], self.resp_sensitive);
        }
        Ok(n)
    }
}

impl OtpTransport for HidOtpTransport {
    fn transmit(
        &mut self,
        apdu: &[u8],
        detect_button_wait: bool,
    ) -> Result<(Vec<u8>, u16), OtpTransportError> {
        // Seed-bearing commands (WRITE_SEED / WRITE_HOTP_SEED) carry the ECDH
        // blob; redact those from the trace (matches the OATH PUT redaction).
        trace_bytes(self.debug, "HID send", apdu, request_is_sensitive(apdu));

        // Decide once whether the response frames carry secrets (ENUM_CODES
        // entries: account names + live OTP codes) so the per-frame and parsed
        // dumps below redact them. Kept for the whole transaction.
        self.resp_sensitive = response_is_sensitive(apdu);

        for frame in hidframe::build_send_frames(apdu) {
            self.write_report(&frame)?;
        }

        let mut asm = ResponseAssembler::new();
        let deadline = Instant::now() + self.timeout;
        let mut prompted = false;
        // Distinguishes "device is telling us to wait for a button press"
        // (BUSY frames seen) from total silence (unplugged / dead device) at
        // the deadline — a device that never sent a single frame is not
        // waiting for a button.
        let mut got_frame = false;
        let mut buf = [0u8; hidframe::REPORT_PAYLOAD + 1];
        loop {
            if Instant::now() >= deadline {
                return Err(if got_frame {
                    OtpTransportError::Applet(OtpError::ButtonPressRequired)
                } else {
                    OtpTransportError::TransportUnavailable(
                        "device sent no response before the timeout".into(),
                    )
                });
            }
            let n = self.read_report(&mut buf)?;
            if n == 0 {
                // Bounded hidapi read polled with no frame; re-check the deadline.
                continue;
            }
            got_frame = true;
            match asm.push(&buf[..n])? {
                Step::Busy { retries } => {
                    // Fire the prompt once at the 3rd busy frame (spec §4.4).
                    if detect_button_wait && !prompted && retries >= 3 {
                        if let Some(cb) = self.button_prompt.as_mut() {
                            cb();
                        }
                        prompted = true;
                    }
                }
                Step::NeedMore => {}
                Step::Done => break,
            }
        }
        let (data, sw) = asm
            .into_response()
            .ok_or(OtpTransportError::EmptyResponse)?;
        if self.debug {
            trace_bytes(
                true,
                &format!("HID parsed sw={sw:#06x}"),
                &data,
                self.resp_sensitive,
            );
        }
        trace_bytes(self.debug, "HID recv", &data, self.resp_sensitive);
        Ok((data, sw))
    }

    fn set_button_prompt(&mut self, cb: ButtonPrompt) {
        self.button_prompt = Some(cb);
    }
    fn set_debug(&mut self, on: bool) {
        self.debug = on;
    }
}

// ---------------------------------------------------------------------------
// PC/SC transport
// ---------------------------------------------------------------------------

/// PC/SC transport for the Token2 OTP applet over NFC / contact readers
/// (spec §5). No button-press polling; the device answers when it answers.
pub struct PcScOtpTransport {
    card: pcsc::Card,
    debug: bool,
    /// AID of the applet currently selected on the card. Tracked so that a
    /// transient card reset (handled in [`raw_transmit`](Self::raw_transmit))
    /// can re-SELECT the same applet before resending — a `ResetCard`
    /// reconnect drops the selection done at open, and the resent command would
    /// otherwise hit the default applet.
    current_aid: Vec<u8>,
}

impl PcScOtpTransport {
    /// Connect to each reader in turn and SELECT the OTP applet; the first that
    /// accepts the SELECT is the device (spec §2.2).
    pub fn open_first() -> Result<Self, OtpTransportError> {
        Self::open_first_debug(false)
    }

    /// As [`open_first`](Self::open_first), but with optional tracing of each
    /// reader connect + SELECT so failures are diagnosable.
    pub fn open_first_debug(debug: bool) -> Result<Self, OtpTransportError> {
        let ctx = pcsc::Context::establish(pcsc::Scope::User)?;
        let mut buf = [0u8; 4096];
        let names: Vec<std::ffi::CString> =
            ctx.list_readers(&mut buf)?.map(|r| r.to_owned()).collect();
        if debug && names.is_empty() {
            eprintln!("[token2otp PCSC] no readers present");
        }
        for name in names {
            if debug {
                eprintln!("[token2otp PCSC] trying reader: {}", name.to_string_lossy());
            }
            // Try shared first, then exclusive; some CCID interfaces only grant
            // one or the other.
            let card = match ctx.connect(
                name.as_c_str(),
                pcsc::ShareMode::Shared,
                pcsc::Protocols::ANY,
            ) {
                Ok(c) => Some(c),
                Err(e) => {
                    if debug {
                        eprintln!("[token2otp PCSC]   shared connect failed: {e}");
                    }
                    match ctx.connect(
                        name.as_c_str(),
                        pcsc::ShareMode::Exclusive,
                        pcsc::Protocols::ANY,
                    ) {
                        Ok(c) => Some(c),
                        Err(e2) => {
                            if debug {
                                eprintln!("[token2otp PCSC]   exclusive connect failed: {e2}");
                            }
                            None
                        }
                    }
                }
            };
            let Some(card) = card else { continue };
            let mut t = PcScOtpTransport {
                card,
                debug,
                current_aid: Vec::new(),
            };
            match t.select(&t2::OTP_APPLET_AID) {
                Ok(()) => {
                    if debug {
                        eprintln!("[token2otp PCSC]   OTP applet selected OK");
                    }
                    return Ok(t);
                }
                Err(e) => {
                    if debug {
                        eprintln!("[token2otp PCSC]   SELECT OTP applet failed: {e}");
                    }
                    let _ = t.card.disconnect(pcsc::Disposition::LeaveCard);
                }
            }
        }
        Err(OtpTransportError::TokenNotDetected)
    }

    /// Connect to one explicitly named reader and SELECT the OTP applet. Unlike
    /// [`open_first`](Self::open_first) this never scans other readers, so a
    /// caller that resolved a `--device` selection binds to exactly that reader.
    pub fn open_reader_debug(reader_name: &str, debug: bool) -> Result<Self, OtpTransportError> {
        let ctx = pcsc::Context::establish(pcsc::Scope::User)?;
        let cname = std::ffi::CString::new(reader_name).map_err(|_| {
            OtpTransportError::TransportUnavailable("reader name contained a NUL".into())
        })?;
        let card = ctx
            .connect(&cname, pcsc::ShareMode::Shared, pcsc::Protocols::ANY)
            .or_else(|_| ctx.connect(&cname, pcsc::ShareMode::Exclusive, pcsc::Protocols::ANY))?;
        let mut t = PcScOtpTransport {
            card,
            debug,
            current_aid: Vec::new(),
        };
        t.select(&t2::OTP_APPLET_AID)?;
        Ok(t)
    }

    fn select(&mut self, aid: &[u8]) -> Result<(), OtpTransportError> {
        let (_, sw) = self.raw_transmit(&t2::build_select(aid))?;
        OtpError::check(sw)?;
        Ok(())
    }

    fn raw_transmit(&mut self, apdu: &[u8]) -> Result<(Vec<u8>, u16), OtpTransportError> {
        // Keyed off the original command: a `61xx` GET-RESPONSE continuation
        // resends a different header into `to_send`, but the secret verdict must
        // follow the command the user actually issued.
        let resp_sensitive = response_is_sensitive(apdu);
        trace_bytes(self.debug, "PCSC send", apdu, request_is_sensitive(apdu));
        // Remember which applet a SELECT switches us to (SELECT = `00 A4 04 00
        // Lc aid...`), so the reset-recovery path below can re-SELECT it. This
        // covers both the open-time SELECT and the FIDO/OTP applet switches the
        // serial read performs.
        if apdu.len() >= 5 && apdu[..4] == [0x00, 0xA4, 0x04, 0x00] {
            let lc = apdu[4] as usize;
            if 5 + lc <= apdu.len() {
                self.current_aid = apdu[5..5 + lc].to_vec();
            }
        }
        let mut acc = Vec::new();
        let mut to_send = apdu.to_vec();
        let mut chunks = 0usize;
        let mut le_retries = 0u8;
        // Contact (T=0) readers occasionally drop a transmit with a transient
        // SCARD_W_RESET_CARD / SCARD_F_COMM_ERROR ("communications error, retry").
        // Reconnect to the card and retry the *current* APDU a few times before
        // giving up, so a momentary glitch doesn't fail the whole read.
        let mut retries_left = 3u8;
        loop {
            let mut rbuf = [0u8; 4096];
            let resp = match self.card.transmit(&to_send, &mut rbuf) {
                Ok(r) => r,
                Err(pcsc::Error::ResetCard)
                | Err(pcsc::Error::RemovedCard)
                | Err(pcsc::Error::CommError)
                    if retries_left > 0 =>
                {
                    retries_left -= 1;
                    if self.debug {
                        eprintln!(
                            "[token2otp PCSC] transient card error; reconnecting and retrying"
                        );
                    }
                    // Re-establish the link to the same card.
                    self.card.reconnect(
                        pcsc::ShareMode::Shared,
                        pcsc::Protocols::ANY,
                        pcsc::Disposition::ResetCard,
                    )?;
                    // A `ResetCard` reconnect resets the card: it clears the
                    // applet selection made at open AND discards any in-flight
                    // `61xx` GET-RESPONSE chain. So we must (a) re-SELECT the
                    // applet we were on — otherwise the resend targets the
                    // default applet and fails — and (b) throw away everything
                    // accumulated so far and restart from the *original* APDU.
                    // Resending a bare GET RESPONSE (or appending fresh bytes to
                    // a half-filled `acc`) against a freshly reset card would
                    // corrupt the reassembly.
                    if !self.current_aid.is_empty() {
                        let sel = t2::build_select(&self.current_aid);
                        let mut sbuf = [0u8; 256];
                        let sresp = self.card.transmit(&sel, &mut sbuf)?;
                        if sresp.len() < 2 {
                            return Err(OtpTransportError::EmptyResponse);
                        }
                        let ssw =
                            ((sresp[sresp.len() - 2] as u16) << 8) | sresp[sresp.len() - 1] as u16;
                        // A failed re-SELECT means the resend would hit the
                        // wrong applet; surface that rather than send blind.
                        OtpError::check(ssw)?;
                    }
                    acc.clear();
                    chunks = 0;
                    to_send = apdu.to_vec();
                    continue;
                }
                Err(e) => return Err(OtpTransportError::Pcsc(e)),
            };
            trace_bytes(self.debug, "PCSC recv", resp, resp_sensitive);
            if resp.len() < 2 {
                return Err(OtpTransportError::EmptyResponse);
            }
            let split = resp.len() - 2;
            let (data, sw_bytes) = resp.split_at(split);
            acc.extend_from_slice(data);
            chunks += 1;
            if acc.len() > 65536 || chunks > 64 {
                return Err(OtpTransportError::Parse(ParseError::Malformed(
                    "61xx continuation exceeded reassembly limits",
                )));
            }
            // T=0 continuation status words:
            //   61 XX -> XX more bytes available; issue GET RESPONSE with Le=XX.
            //   6C XX -> wrong Le; re-issue the *same* command with Le=XX.
            match sw_bytes[0] {
                0x61 => {
                    let le = sw_bytes[1];
                    to_send = vec![0x00, 0xC0, 0x00, 0x00, le];
                    continue;
                }
                0x6C => {
                    // A conformant card answers 6C at most once per command
                    // (with the Le it wants); a card that keeps rejecting the
                    // corrected APDU must not spin this loop forever — the
                    // `chunks` reset below defeats the reassembly bound.
                    le_retries += 1;
                    if le_retries > 4 {
                        return Err(OtpTransportError::Parse(ParseError::Malformed(
                            "card kept answering 6C to the corrected Le",
                        )));
                    }
                    // Re-send the *original* command with the card-suggested
                    // Le, attached according to the APDU's ISO 7816 case —
                    // see `resend_with_le`. Replacing the last byte of a
                    // body-carrying (case 3) command would corrupt its final
                    // data byte.
                    to_send = resend_with_le(apdu, sw_bytes[1]);
                    acc.clear(); // the 6C response carried no data
                    chunks = 0;
                    continue;
                }
                _ => {}
            }
            let sw = ((sw_bytes[0] as u16) << 8) | sw_bytes[1] as u16;
            return Ok((acc, sw));
        }
    }
}

impl OtpTransport for PcScOtpTransport {
    fn transmit(
        &mut self,
        apdu: &[u8],
        _detect_button_wait: bool,
    ) -> Result<(Vec<u8>, u16), OtpTransportError> {
        self.raw_transmit(apdu)
    }
    fn set_debug(&mut self, on: bool) {
        self.debug = on;
    }
}

// ---------------------------------------------------------------------------
// High-level session
// ---------------------------------------------------------------------------

/// An open Token2 OTP management session over whichever transport was found.
pub struct Token2OtpSession {
    transport: Box<dyn OtpTransport>,
    is_pcsc: bool,
    /// ECDH session keys, established lazily on the first PIN operation. `None`
    /// until then.
    pin_session: Option<t2::crypto::SessionKeys>,
    /// Whether a successful `VERIFY_OTP_PIN` has opened the device read window on
    /// this connection.
    pin_verified: bool,
    /// What the most recent flag read on this connection said: `Some(true)` a
    /// PIN is set, `Some(false)` the feature is there and no PIN is set, `None`
    /// nothing has asked yet or the key does not offer the feature.
    pin_present: Option<bool>,
}

/// Host-owned caps on the `ENUM_CODES` pagination loop (audit KEY-009). Both
/// the more-pages bit and the page contents are device-controlled, so a
/// hostile key could otherwise keep a GUI worker or CLI command paging (and
/// allocating) forever. The largest shipping Token2 OTP stores are on the
/// order of 100 entries (the Molto2 line tops out at 100 slots; the PIN+ /
/// T2F2 FIDO keys store fewer), and a well-formed page carries at least one
/// entry, so 256 pages / 1024 entries is more than an order of magnitude of
/// headroom over real hardware while still terminating promptly.
const MAX_ENUM_PAGES: usize = 256;
const MAX_ENUM_ENTRIES: usize = 1024;

/// How long the HID probe waits for the OTP applet to answer before giving up
/// and falling back to PC/SC (which carries the same applet). Reads are now
/// bounded on every backend (`keyroost_hid::read_nonblocking_bounded` /
/// `read_report_bounded`), but the transport's default per-command timeout is
/// 20 s — far too long for a detect-time probe — so the probe still runs on a
/// worker thread bounded by this shorter deadline. Only used on the Linux
/// hidraw path; the hidapi backend probes directly.
#[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
const HID_PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Probe whether the OTP applet answers over HID, taking the transport by value
/// so a probe that hangs on a blocking read cannot stall the caller.
///
/// On success returns the transport back (it's reused as the live channel). On
/// failure — including the probe exceeding [`HID_PROBE_TIMEOUT`] — returns an
/// error; the transport is dropped (on Linux it may briefly be owned by an
/// abandoned worker thread, which now ends on its own when the transport's
/// bounded read loop hits its deadline).
fn probe_hid_owned(
    mut t: HidOtpTransport,
) -> Result<HidOtpTransport, (OtpTransportError, Option<HidOtpTransport>)> {
    #[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
    {
        // The probe must answer within HID_PROBE_TIMEOUT (3 s) but the
        // transport's own command timeout is 20 s, so run it on a worker
        // thread and bound the wait with a channel recv deadline. An
        // abandoned worker no longer blocks forever: the bounded read loop
        // exits at the transport timeout and the thread ends (KEY-011).
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let res = probe_hid(&mut t);
            // Send the outcome and the transport back; if the receiver already
            // gave up (timed out), this send fails and the transport is dropped
            // here instead — either way nothing leaks.
            let _ = tx.send((res, t));
        });
        match rx.recv_timeout(HID_PROBE_TIMEOUT) {
            Ok((Ok(()), t)) => Ok(t),
            Ok((Err(e), t)) => Err((e, Some(t))),
            Err(_) => Err((OtpTransportError::TokenNotDetected, None)),
        }
    }
    #[cfg(not(all(target_os = "linux", not(feature = "hidapi-backend"))))]
    {
        // hidapi reads are now bounded via read_timeout, so a direct probe
        // can't hang; no worker-thread wrapper is needed on this backend.
        match probe_hid(&mut t) {
            Ok(()) => Ok(t),
            Err(e) => Err((e, Some(t))),
        }
    }
}

/// Which error to report when the HID probe failed *and* the CCID fallback was
/// unavailable, so the probe outcome is the only evidence there is.
///
/// The distinction this makes is the whole point. If the applet returned a
/// status word, the HID interface carried a complete request and response —
/// it demonstrably works, and the key simply declined. Reporting that as
/// [`NoUsableInterface`](OtpTransportError::NoUsableInterface) tells the user
/// to enable an interface that is already enabled, which is what issue #95
/// reported: a key answering `0105` was diagnosed as "HID may be disabled".
/// Only a probe that never got an answer (framing error, timeout, I/O failure)
/// is evidence about the interface itself.
///
/// Pure and total so the classification is unit-testable without hardware —
/// the original defect was a `_ =>` arm in an inline match that no test could
/// reach.
fn detect_failure_from(
    probe_err: OtpTransportError,
    ccid_err: OtpTransportError,
) -> OtpTransportError {
    match probe_err {
        // The applet spoke, so HID demonstrably works and the key declined —
        // expected on a model that carries OTP over CCID only. Report the
        // status word AND why CCID failed, because CCID is the channel the
        // user can actually do something about.
        OtpTransportError::Applet(e) => OtpTransportError::HidDeclinedAndNoCcid {
            sw: e.status_word(),
            ccid: ccid_err.to_string(),
        },
        // Silence, framing damage, or the interface never opening: these are
        // genuinely about the transport.
        _ => OtpTransportError::NoUsableInterface,
    }
}

/// Confirm the OTP applet answers over HID using the read-only
/// `GET_ECDH_PUBKEY` command (supported by every model, changes nothing). A
/// non-`9000` status word or any transport error means HID isn't usable for the
/// applet. Called only via [`probe_hid_owned`], which bounds it in time.
fn probe_hid(t: &mut HidOtpTransport) -> Result<(), OtpTransportError> {
    let (_data, sw) = t.transmit(&t2::get_ecdh_pubkey(), false)?;
    OtpError::check(sw)?;
    Ok(())
}

/// Status words that mean "this applet has no PIN command at all" — the ISO
/// unknown-instruction family, plus `6AF8`, which R3.4 firmware itself answers a
/// bodyless flag read with. Every other non-`9000` answer to the flag read is a
/// real PIN state (Token2 confirmed `6982`/`6983`/`6985`/`6A81`/`63xx` are) and
/// is surfaced, never mistaken for "no feature".
const NO_PIN_FEATURE_ANSWERS: [u16; 5] = [
    0x6D00, // instruction not supported
    0x6E00, // class not supported
    0x6A86, // incorrect P1/P2
    0x6AF8, // what R3.4 itself answers a bodyless flag read
    0x6700, // wrong length
];

impl Token2OtpSession {
    /// Open the OTP applet, trying USB-HID first and falling back to PC/SC.
    ///
    /// HID enumerating successfully is not the same as the OTP applet being
    /// reachable over HID: a key can expose its FIDO HID interface while having
    /// the on-device OTP-over-HID channel disabled, in which case the first real
    /// command fails at the OS layer ("Incorrect function") rather than during
    /// enumeration. So when a HID transport opens, we probe it with a harmless
    /// read-only command (`GET_ECDH_PUBKEY`); if that probe fails for any reason,
    /// we fall back to PC/SC (CCID), which carries the same applet over a contact
    /// / NFC reader. This mirrors the vendor app, which reaches the applet over
    /// whichever interface is actually live.
    pub fn detect() -> Result<Self, OtpTransportError> {
        Self::detect_debug(false)
    }

    /// As [`detect`](Self::detect), with tracing of the CCID probe.
    pub fn detect_debug(debug: bool) -> Result<Self, OtpTransportError> {
        match HidOtpTransport::open_first() {
            Ok(mut t) => {
                t.set_debug(debug);
                // Probe (time-bounded): does the OTP applet actually answer over
                // HID? A hung probe falls through to the CCID fallback below
                // rather than blocking forever.
                match probe_hid_owned(t) {
                    Ok(t) => Ok(Self {
                        transport: Box::new(t),
                        is_pcsc: false,
                        pin_session: None,
                        pin_verified: false,
                        pin_present: None,
                    }),
                    Err((probe_err, _)) => {
                        // HID present but the applet didn't accept the probe
                        // (HID disabled on the device, the probe timed out, or
                        // the key declined) — try CCID instead.
                        match PcScOtpTransport::open_first_debug(debug) {
                            Ok(p) => Ok(Self {
                                transport: Box::new(p),
                                is_pcsc: true,
                                pin_session: None,
                                pin_verified: false,
                                pin_present: None,
                            }),
                            // No CCID either. Both outcomes matter now: which
                            // kind of HID failure it was, and why CCID could
                            // not stand in for it.
                            Err(ccid_err) => Err(detect_failure_from(probe_err, ccid_err)),
                        }
                    }
                }
            }
            Err(OtpTransportError::TokenNotDetected) => {
                let t = PcScOtpTransport::open_first_debug(debug)?;
                Ok(Self {
                    transport: Box::new(t),
                    is_pcsc: true,
                    pin_session: None,
                    pin_verified: false,
                    pin_present: None,
                })
            }
            Err(e) => Err(e),
        }
    }

    /// Force the USB-HID transport (no PC/SC fallback). Errors if HID isn't
    /// usable.
    pub fn detect_hid_only(debug: bool) -> Result<Self, OtpTransportError> {
        let mut t = HidOtpTransport::open_first()?;
        t.set_debug(debug);
        let t = probe_hid_owned(t).map_err(|(e, _)| e)?;
        Ok(Self {
            transport: Box::new(t),
            is_pcsc: false,
            pin_session: None,
            pin_verified: false,
            pin_present: None,
        })
    }

    /// Force the PC/SC (CCID / NFC) transport (no HID).
    pub fn detect_pcsc_only(debug: bool) -> Result<Self, OtpTransportError> {
        let t = PcScOtpTransport::open_first_debug(debug)?;
        Ok(Self {
            transport: Box::new(t),
            is_pcsc: true,
            pin_session: None,
            pin_verified: false,
            pin_present: None,
        })
    }

    /// Open the OTP applet on one explicitly resolved USB-HID device path (no
    /// first-match scan). Probes the applet the same way [`detect_hid_only`] does.
    pub fn open_hid_path(path: &Path, debug: bool) -> Result<Self, OtpTransportError> {
        let mut t = HidOtpTransport::open_path(path)?;
        t.set_debug(debug);
        let t = probe_hid_owned(t).map_err(|(e, _)| e)?;
        Ok(Self {
            transport: Box::new(t),
            is_pcsc: false,
            pin_session: None,
            pin_verified: false,
            pin_present: None,
        })
    }

    /// Open the OTP applet on one explicitly resolved PC/SC reader (no
    /// first-match scan).
    pub fn open_pcsc_reader(reader_name: &str, debug: bool) -> Result<Self, OtpTransportError> {
        let t = PcScOtpTransport::open_reader_debug(reader_name, debug)?;
        Ok(Self {
            transport: Box::new(t),
            is_pcsc: true,
            pin_session: None,
            pin_verified: false,
            pin_present: None,
        })
    }

    /// Wrap an explicit HID transport (e.g. when the caller resolved a path).
    pub fn with_hid(t: HidOtpTransport) -> Self {
        Self {
            transport: Box::new(t),
            is_pcsc: false,
            pin_session: None,
            pin_verified: false,
            pin_present: None,
        }
    }

    /// Wrap an explicit PC/SC transport.
    pub fn with_pcsc(t: PcScOtpTransport) -> Self {
        Self {
            transport: Box::new(t),
            is_pcsc: true,
            pin_session: None,
            pin_verified: false,
            pin_present: None,
        }
    }

    /// Enable per-APDU stderr tracing (seed bodies stay redacted).
    pub fn set_debug(&mut self, on: bool) {
        self.transport.set_debug(on);
    }

    /// Register a "touch your key" prompt fired while a button-required command
    /// waits (HID only; PC/SC has no such wait, spec §5).
    pub fn set_button_prompt(&mut self, cb: ButtonPrompt) {
        self.transport.set_button_prompt(cb);
    }

    /// Enumerate every stored entry, paging through `ENUM_CODES_CONTINUE` as
    /// needed (spec §6.1). `timestamp` is UNIX seconds, used to compute the live
    /// TOTP codes the device returns. An empty token yields an empty list rather
    /// than an error (spec §3.1).
    pub fn enumerate(&mut self, timestamp: u64) -> Result<Vec<Entry>, OtpTransportError> {
        let first = t2::build_apdu(cmd::ENUM_CODES, &serialize_enum_all(timestamp));
        let (data, sw) = self.transport.transmit(&first, false)?;
        // A clean "not found" here means zero entries (spec §3.1, §11).
        if let Err(e) = OtpError::check(sw) {
            if e.is_empty_token() {
                return Ok(Vec::new());
            }
            return Err(e.into());
        }
        let data = self.maybe_decrypt_page(&data)?;
        let mut page = t2::parse_enum_page(&data)?;
        let mut entries = page.entries;
        let mut pages = 1usize;
        while page.more_pages {
            // Device-controlled continuation flag: enforce the host caps
            // *before* issuing another transmit (KEY-009).
            pages += 1;
            if pages > MAX_ENUM_PAGES || entries.len() > MAX_ENUM_ENTRIES {
                return Err(OtpTransportError::EnumerationCapExceeded);
            }
            let cont = t2::build_apdu(cmd::ENUM_CODES_CONTINUE, &timestamp.to_be_bytes());
            let (data, sw) = self.transport.transmit(&cont, false)?;
            OtpError::check(sw)?;
            let data = self.maybe_decrypt_page(&data)?;
            page = t2::parse_enum_page(&data)?;
            entries.extend(page.entries);
        }
        // A single final page could still be entry-stuffed; apply the total
        // cap to the result as well.
        if entries.len() > MAX_ENUM_ENTRIES {
            return Err(OtpTransportError::EnumerationCapExceeded);
        }
        Ok(entries)
    }

    /// On a PIN-protected key with the read window open (after `verify_pin`), the
    /// applet returns enumeration/read pages ENCRYPTED under the session key:
    /// `IV(16) || AES-CBC(SessionEncKey, IV, page) || HMAC(SessionMacKey, enc)[:16]`.
    /// Decrypt and authenticate before parsing. When the window isn't open (no
    /// PIN, or not verified) the page is already cleartext and returned as-is.
    fn maybe_decrypt_page(&self, data: &[u8]) -> Result<Vec<u8>, OtpTransportError> {
        if !self.pin_verified {
            return Ok(data.to_vec());
        }
        let keys = self
            .pin_session
            .as_ref()
            .ok_or(OtpTransportError::PinSessionMissing)?;
        if data.len() < 16 + 16 + 16 {
            return Err(OtpTransportError::Parse(ParseError::Truncated));
        }
        let iv: [u8; 16] = data[..16].try_into().expect("checked length");
        let enc = &data[16..data.len() - 16];
        let auth = &data[data.len() - 16..];
        t2::crypto::verify_auth_tag(&keys.mac, enc, auth)?;
        let plain = t2::crypto::session_decrypt(&keys.enc, &iv, enc)?;
        Ok(plain.to_vec())
    }

    // --- OTP PIN (R3.4 privacy protection) -----------------------------------

    /// Read the PIN flag (base form): reports whether a PIN is set, retry counts.
    /// Needs no session.
    ///
    /// `Ok(None)` means **the key does not offer the OTP-PIN feature** — not an
    /// error. keyroost keeps no firmware-version table; it offers the surface
    /// and lets the attempt report the truth. A key whose applet predates R3.4
    /// has never heard of `80 C5 05 04` and says so with a status word (`6A81`,
    /// `6D00`, `6A86`, `6AF8` — the exact one varies by model and channel), and
    /// a key that answers with a body too short to parse has told us just as
    /// little. Both mean "no PIN here", and every caller must carry on exactly
    /// as it did before this feature existed: an unprotected key's list, add and
    /// delete are not allowed to start failing because a capability probe came
    /// back negative.
    ///
    /// A genuine I/O failure still propagates — that is the transport breaking,
    /// not the applet declining.
    pub fn pin_status(&mut self) -> Result<Option<t2::PinFlag>, OtpTransportError> {
        let apdu = t2::read_otp_pin_flag(t2::cmd::PIN_FLAG_LC_BASE);
        let (data, sw) = self.transport.transmit(&apdu, false)?;
        let flag = if sw == t2::sw::OK {
            t2::PinFlag::parse(&data).ok()
        } else if NO_PIN_FEATURE_ANSWERS.contains(&sw) {
            None
        } else {
            // Anything else is the applet reporting a real PIN state — a
            // locked PIN answers 6983 here — and must reach the caller.
            t2::OtpError::check(sw)?;
            None
        };
        self.pin_present = flag.as_ref().map(|f| f.is_set());
        Ok(flag)
    }

    /// True if the key currently has an OTP PIN set. A key without the PIN
    /// feature reports `false` — see [`pin_status`](Self::pin_status).
    pub fn pin_is_set(&mut self) -> Result<bool, OtpTransportError> {
        Ok(self.pin_status()?.is_some_and(|f| f.is_set()))
    }

    /// Whether the last flag read on this connection found a PIN set, without
    /// spending another round trip. `None` until one has run, and after one that
    /// found no PIN feature at all.
    ///
    /// Only ever filled by [`pin_status`](Self::pin_status), which every
    /// `*_pinned` call runs first, so a caller that has just enumerated is
    /// reading what the key said moments ago on this same connection — not a
    /// value carried across devices or sessions.
    #[must_use]
    pub fn pin_set_cached(&self) -> Option<bool> {
        self.pin_present
    }

    /// Establish an authenticated ECDH session and cache the derived keys.
    /// Required before any PIN command and before reading PIN-protected entries.
    ///
    /// NOTE: the protocol also returns an ECC-P521 signature over
    /// `hostPub || devPub` that the host *should* verify against the device's
    /// P-521 key. This is NOT verified here: the P-256 crate can't check a P-521
    /// signature. The ECDH still provides session confidentiality, but device
    /// *authenticity* is not cryptographically checked — see the reference
    /// client's identical caveat.
    pub fn open_session(&mut self) -> Result<(), OtpTransportError> {
        // The reference sequence reads the PIN flag FIRST (Lc=09) before the
        // handshake — this primes the device PIN state. Skipping it makes a
        // subsequent SET fail with 6985.
        let prime = t2::read_otp_pin_flag(t2::cmd::PIN_FLAG_LC_PRIME);
        let (_pdata, psw) = self.transport.transmit(&prime, false)?;
        OtpError::check(psw)?;

        // The ephemeral keypair and every curve operation live in the byte
        // layer, which is where this crate's split puts the crypto; the
        // transport only carries the two halves of the exchange.
        let agreement = t2::crypto::HostAgreement::new();
        let apdu = t2::read_agreement_pubkey(agreement.public_xy());
        let (data, sw) = self.transport.transmit(&apdu, false)?;
        OtpError::check(sw)?;
        // Response: devPub(64) || sig(132). We consume devPub; sig is unverified.
        if data.len() < 64 {
            return Err(OtpTransportError::Parse(ParseError::Truncated));
        }
        let dev_xy = &data[..64];

        let keys = agreement.establish_session(dev_xy)?;
        self.pin_session = Some(keys);
        self.pin_verified = false;
        Ok(())
    }

    /// Open a session if one isn't already cached.
    fn ensure_session(&mut self) -> Result<(), OtpTransportError> {
        if self.pin_session.is_none() {
            self.open_session()?;
        }
        Ok(())
    }

    /// Set an OTP PIN on a currently-unprotected key.
    ///
    /// The PIN is not screened here: the applet owns that policy and reports
    /// what it will not take.
    pub fn set_pin(&mut self, pin: &str) -> Result<(), OtpTransportError> {
        self.ensure_session()?;
        let keys = self
            .pin_session
            .as_ref()
            .ok_or(OtpTransportError::PinSessionMissing)?;
        let data =
            t2::crypto::build_set_pin_data(keys, pin.as_bytes(), t2::cmd::PIN_DEFAULT_MAX_RETRY)?;
        let apdu = t2::build_apdu(t2::cmd::SET_OTP_PIN, &data);
        let (_, sw) = self.transport.transmit(&apdu, false)?;
        OtpError::check_pin(sw)?;
        Ok(())
    }

    /// Verify the OTP PIN, opening the device read window for this connection so
    /// subsequent `enumerate`/`read_entry` calls return usable codes.
    pub fn verify_pin(&mut self, pin: &str) -> Result<(), OtpTransportError> {
        self.ensure_session()?;
        // Fetch the verify challenge: IV || EncRand (Lc = 0x29).
        let flag_apdu = t2::read_otp_pin_flag(t2::cmd::PIN_FLAG_LC_CHALLENGE);
        let (data, sw) = self.transport.transmit(&flag_apdu, false)?;
        OtpError::check_pin(sw)?;
        let flag = t2::PinFlag::parse(&data)?;
        if !flag.is_set() {
            return Err(OtpTransportError::PinRequired);
        }
        let (iv, enc_rand) = flag
            .challenge
            .ok_or(OtpTransportError::Parse(ParseError::Truncated))?;

        let keys = self
            .pin_session
            .as_ref()
            .ok_or(OtpTransportError::PinSessionMissing)?;
        // Rand is a raw 16-byte block with NO PKCS#7 padding.
        let rand = t2::crypto::session_decrypt_raw(&keys.enc, &iv, &enc_rand);
        if rand.len() != 16 {
            return Err(OtpTransportError::Encrypt(EncryptError::BadCiphertext));
        }

        let data_field = t2::crypto::build_verify_pin_data(keys, pin.as_bytes(), &rand)?;
        let apdu = t2::build_apdu(t2::cmd::VERIFY_OTP_PIN, &data_field);
        let (_, sw) = self.transport.transmit(&apdu, false)?;
        OtpError::check_pin(sw)?;
        self.pin_verified = true;
        Ok(())
    }

    /// Change the OTP PIN (requires the current PIN). The new PIN is not
    /// screened here — see [`set_pin`](Self::set_pin).
    pub fn change_pin(&mut self, current: &str, new: &str) -> Result<(), OtpTransportError> {
        self.change_pin_inner(current, Some(new))
    }

    /// Remove the OTP PIN (a change to length 0; requires the current PIN).
    pub fn remove_pin(&mut self, current: &str) -> Result<(), OtpTransportError> {
        self.change_pin_inner(current, None)
    }

    fn change_pin_inner(
        &mut self,
        current: &str,
        new: Option<&str>,
    ) -> Result<(), OtpTransportError> {
        self.ensure_session()?;
        // The reference sequence reads the challenge before a change, and the
        // Rand it yields is passed on to the builder — but nothing in the change
        // block binds it (see the TODO on `build_change_pin_data`). The read is
        // kept because it is what the applet has been observed to expect; it is
        // deliberately NOT described here as a binding the bytes don't perform.
        let flag_apdu = t2::read_otp_pin_flag(t2::cmd::PIN_FLAG_LC_CHALLENGE);
        let (data, sw) = self.transport.transmit(&flag_apdu, false)?;
        OtpError::check_pin(sw)?;
        let flag = t2::PinFlag::parse(&data)?;
        let (iv, enc_rand) = flag
            .challenge
            .ok_or(OtpTransportError::Parse(ParseError::Truncated))?;
        let keys = self
            .pin_session
            .as_ref()
            .ok_or(OtpTransportError::PinSessionMissing)?;
        let rand = t2::crypto::session_decrypt_raw(&keys.enc, &iv, &enc_rand);
        if rand.len() != 16 {
            return Err(OtpTransportError::Encrypt(EncryptError::BadCiphertext));
        }
        let new_bytes = new.map(|s| s.as_bytes()).unwrap_or(&[]);
        let data_field =
            t2::crypto::build_change_pin_data(keys, new_bytes, current.as_bytes(), &rand)?;
        let apdu = t2::build_apdu(t2::cmd::CHANGE_OTP_PIN, &data_field);
        let (_, sw) = self.transport.transmit(&apdu, false)?;
        OtpError::check_pin(sw)?;
        self.pin_verified = false;
        Ok(())
    }

    /// Close the PIN read/write window immediately (the window a verify opens for
    /// ~5 minutes). After this, protected reads/writes need a fresh verify.
    pub fn lock_pin(&mut self) -> Result<(), OtpTransportError> {
        let apdu = t2::lock_otp_pin();
        let (_, sw) = self.transport.transmit(&apdu, false)?;
        OtpError::check(sw)?;
        self.pin_verified = false;
        Ok(())
    }

    /// If the key has an OTP PIN set, verify `pin` to open the read/write window;
    /// if no PIN is set, this is a no-op. Returns [`OtpTransportError::PinRequired`]
    /// when a PIN is set but `pin` is `None`.
    pub fn unlock_if_pinned(&mut self, pin: Option<&str>) -> Result<(), OtpTransportError> {
        if self.pin_is_set()? {
            match pin {
                Some(p) => self.verify_pin(p)?,
                None => return Err(OtpTransportError::PinRequired),
            }
        }
        Ok(())
    }

    /// List entries, transparently handling a PIN-protected key: if a PIN is set,
    /// `pin` must be supplied (it is verified to open the read window). When a PIN
    /// is set but `pin` is `None`, returns [`OtpTransportError::PinRequired`] so a
    /// caller (CLI/GUI) can prompt for it.
    pub fn enumerate_pinned(
        &mut self,
        timestamp: u64,
        pin: Option<&str>,
    ) -> Result<Vec<Entry>, OtpTransportError> {
        self.unlock_if_pinned(pin)?;
        self.enumerate(timestamp)
    }

    /// Add/overwrite an entry, transparently handling a PIN-protected key: if a
    /// PIN is set it must be supplied (verified to open the write window) unless
    /// the window is already open on this session. Returns
    /// [`OtpTransportError::PinRequired`] when a PIN is set but none was given.
    pub fn write_entry_pinned(
        &mut self,
        entry: &WriteEntry<'_>,
        pin: Option<&str>,
    ) -> Result<(), OtpTransportError> {
        if !self.pin_verified && self.pin_is_set()? {
            match pin {
                Some(p) => self.verify_pin(p)?,
                None => return Err(OtpTransportError::PinRequired),
            }
        }
        self.write_entry(entry)
    }

    /// Delete an entry, transparently handling a PIN-protected key (see
    /// [`write_entry_pinned`](Self::write_entry_pinned)). Delete is a seed-write
    /// with an empty seed, so it takes the same protected path.
    pub fn delete_entry_pinned(
        &mut self,
        app_name: &str,
        account_name: &str,
        pin: Option<&str>,
    ) -> Result<(), OtpTransportError> {
        if !self.pin_verified && self.pin_is_set()? {
            match pin {
                Some(p) => self.verify_pin(p)?,
                None => return Err(OtpTransportError::PinRequired),
            }
        }
        self.delete_entry(app_name, account_name)
    }

    /// Read a single entry by `(app, account)`, returning its live code (spec
    /// §6.2). A button-required entry blocks until the user touches the key;
    /// over HID the registered prompt fires while waiting.
    pub fn read_entry(
        &mut self,
        timestamp: u64,
        app_name: &str,
        account_name: &str,
    ) -> Result<Entry, OtpTransportError> {
        let body = t2::serialize_read_entry(timestamp, app_name, account_name)?;
        let apdu = t2::build_apdu(cmd::ENUM_CODES, &body);
        let (data, sw) = self.transport.transmit(&apdu, true)?;
        OtpError::check(sw)?;
        Ok(t2::entry::parse_read_one(&data)?)
    }

    /// Provision (or overwrite) an entry (spec §6.3). Fetches the device ECDH
    /// pubkey, seals the cleartext with IV-1, and sends `WRITE_SEED`.
    pub fn write_entry(&mut self, entry: &WriteEntry<'_>) -> Result<(), OtpTransportError> {
        let cleartext = t2::serialize_write_entry(entry)?;
        let blob = self.seal(cleartext.as_bytes(), &t2::IV_OTP)?;
        let apdu = t2::build_apdu(cmd::WRITE_SEED, &blob);
        let (_, sw) = self.transport.transmit(&apdu, false)?;
        OtpError::check(sw)?;
        Ok(())
    }

    /// Delete an entry by `(app, account)` (spec §6.4): an encrypted write with
    /// an empty seed.
    pub fn delete_entry(
        &mut self,
        app_name: &str,
        account_name: &str,
    ) -> Result<(), OtpTransportError> {
        let cleartext = t2::serialize_delete_entry(app_name, account_name)?;
        let blob = self.seal(cleartext.as_bytes(), &t2::IV_OTP)?;
        let apdu = t2::build_apdu(cmd::WRITE_SEED, &blob);
        let (_, sw) = self.transport.transmit(&apdu, false)?;
        OtpError::check(sw)?;
        Ok(())
    }

    /// Erase every entry (spec §6.5): a bodyless `WRITE_SEED`. Requires a
    /// confirming button press over HID.
    pub fn erase_all(&mut self) -> Result<(), OtpTransportError> {
        let (_, sw) = self.transport.transmit(&t2::erase_all(), true)?;
        OtpError::check(sw)?;
        Ok(())
    }

    /// Configure the HOTP-on-button keystroke slot (spec §6.6). `code_length`
    /// must be 6 or 8. `send_enter`, `long_touch`, and `numpad` set the three
    /// follow-up config bytes.
    #[allow(clippy::too_many_arguments)]
    pub fn set_button_hotp(
        &mut self,
        code_length: u8,
        seed: &[u8],
        send_enter: bool,
        long_touch: bool,
        numpad: bool,
    ) -> Result<(), OtpTransportError> {
        if code_length != 6 && code_length != 8 {
            return Err(OtpTransportError::Parse(ParseError::Invalid(
                "button HOTP code_length must be 6 or 8",
            )));
        }
        t2::validate_seed_len(seed.len())
            .map_err(|m| OtpTransportError::Parse(ParseError::Invalid(m)))?;

        // 1. Seed (IV-2).
        let mut cleartext = Zeroizing::new(Vec::with_capacity(2 + seed.len()));
        cleartext.push(code_length);
        cleartext.push(seed.len() as u8);
        cleartext.extend_from_slice(seed);
        let blob = self.seal(&cleartext, &t2::IV_HOTP)?;
        let apdu = t2::build_apdu(cmd::WRITE_HOTP_SEED, &blob);
        let (_, sw) = self.transport.transmit(&apdu, false)?;
        OtpError::check(sw)?;

        // 2..4. Send-Enter / long-touch / numpad config bytes.
        self.config_byte(cmd::CFG_HOTP_ENTER, (!send_enter) as u8)?; // 0x01 suppresses Enter
        self.config_byte(cmd::CFG_HOTP_TOUCH, long_touch as u8)?;
        self.config_byte(cmd::CFG_HOTP_KBD_TYPE, numpad as u8)?;
        Ok(())
    }

    /// Update the HOTP-on-button keystroke options (send-Enter, long-touch,
    /// numpad) *without* touching the configured seed (spec §1.8–1.10). Sends
    /// only the three `CFG_HOTP_*` config bytes, so the existing seed slot is
    /// left intact — unlike [`Self::set_button_hotp`], which rewrites the seed.
    ///
    /// Use this to change typing behaviour for an already-provisioned slot. It
    /// has no effect if no seed is configured (the device keeps the config bytes
    /// but they only matter once a seed is present).
    pub fn set_button_hotp_options(
        &mut self,
        send_enter: bool,
        long_touch: bool,
        numpad: bool,
    ) -> Result<(), OtpTransportError> {
        self.config_byte(cmd::CFG_HOTP_ENTER, (!send_enter) as u8)?; // 0x01 suppresses Enter
        self.config_byte(cmd::CFG_HOTP_TOUCH, long_touch as u8)?;
        self.config_byte(cmd::CFG_HOTP_KBD_TYPE, numpad as u8)?;
        Ok(())
    }

    /// Delete the HOTP-on-button slot (spec §6.6): seal the two zero bytes with
    /// IV-2 and send `WRITE_HOTP_SEED`.
    /// Set which USB interfaces the key exposes, via `SET_DEVICE_TYPE`
    /// (spec §6.8). The argument is a *disable* mask over [`t2::DEV_FIDO`],
    /// [`t2::DEV_KEYBOARD`], and [`t2::DEV_CCID`]: a set bit disables that
    /// interface, a clear bit enables it.
    ///
    /// **Brick risk.** The firmware does not refuse a mask that disables every
    /// interface, which would leave the key permanently unreachable. The byte
    /// layer's [`t2::set_device_type`] refuses such a mask client-side
    /// ([`t2::SetDeviceTypeError::WouldBrick`]); this method surfaces that as an
    /// error and never transmits a bricking APDU. Callers should additionally
    /// confirm the change with the user before calling.
    pub fn set_device_type(&mut self, disable_mask: u8) -> Result<(), OtpTransportError> {
        let apdu = t2::set_device_type(disable_mask).map_err(|_| {
            OtpTransportError::Parse(ParseError::Invalid(
                "refusing to disable every interface (would brick the key)",
            ))
        })?;
        let (_, sw) = self.transport.transmit(&apdu, false)?;
        OtpError::check(sw)?;
        Ok(())
    }

    /// Read the key's interface-configuration byte via `READ_CONFIG`
    /// (spec §6.9), so callers can show which interfaces are currently enabled
    /// before changing them. Returns the raw config bytes the device reports.
    pub fn read_config(&mut self) -> Result<Vec<u8>, OtpTransportError> {
        // READ_CONFIG (0x80 0xC5 0x02) is in the same command family as
        // ENUM_CODES (0x80 0xC5 0x05) and is answered by the OTP applet — NOT the
        // FIDO applet. The OTP applet is already current (selected at session
        // open), so issue the command directly, exactly as `enumerate` does.
        //
        // Note: over CCID/NFC some firmware returns only a short block (e.g. the
        // 1-byte transfer-type byte) where USB-HID returns the full device-info.
        // We return whatever we get; `DeviceInfo::parse` records the length so
        // callers can tell which fields are actually backed by real bytes rather
        // than zero-padding (see `DeviceInfo::has_config_byte`).
        let apdu = t2::read_config(64);
        let (data, sw) = self.transport.transmit(&apdu, false)?;
        OtpError::check(sw)?;
        Ok(data)
    }

    /// Read and parse the device-info / configuration block (spec §6.9). Callers
    /// can use the returned [`t2::DeviceInfo`] to tell, for example, whether the
    /// keyboard-HID interface is enabled before offering HOTP-on-touch (which
    /// types over that interface and fails with `6A81` when it's disabled).
    pub fn read_device_info(&mut self) -> Result<t2::DeviceInfo, OtpTransportError> {
        let data = self.read_config()?;
        Ok(t2::DeviceInfo::parse(&data)?)
    }

    pub fn delete_button_hotp(&mut self) -> Result<(), OtpTransportError> {
        let blob = self.seal(&[0x00, 0x00], &t2::IV_HOTP)?;
        let apdu = t2::build_apdu(cmd::WRITE_HOTP_SEED, &blob);
        let (_, sw) = self.transport.transmit(&apdu, false)?;
        OtpError::check(sw)?;
        Ok(())
    }

    /// Read the serial number (spec §6.10). The FIDO applet answers it, so over
    /// PC/SC a FIDO-applet SELECT is sent first.
    ///
    /// The reference client fires that SELECT and ignores its status word,
    /// judging success only by the subsequent `GET_INFO` — some PIN+ firmware
    /// answers `6A81` ("function not supported") to the SELECT yet still switches
    /// applets and serves the serial. So we do the same: SELECT, ignore its SW,
    /// then GET_INFO and decide from that. Only a non-`9000` *GET_INFO* (or an
    /// unparseable body) means the serial really isn't available here.
    pub fn read_serial(&mut self) -> Result<Vec<u8>, OtpTransportError> {
        if self.is_pcsc {
            // Fire the FIDO-applet SELECT; intentionally ignore its status word.
            let _ = self
                .transport
                .transmit(&t2::build_select(&t2::FIDO_APPLET_AID), false);
        }
        let serial = self.transport.transmit(&t2::read_serial_request(), false);
        // Over PC/SC the FIDO SELECT above left the card on the FIDO applet.
        // Restore the OTP applet so a following command (enumerate, config) does
        // not fail with 6A86 ("no current applet / wrong parameters"). Without
        // this, listing entries after a serial read returns empty.
        if self.is_pcsc {
            let _ = self
                .transport
                .transmit(&t2::build_select(&t2::OTP_APPLET_AID), false);
        }
        let (data, sw) = serial?;
        if OtpError::check(sw).is_err() {
            return Err(OtpTransportError::SerialUnavailable);
        }
        Ok(t2::parse_serial(&data)?)
    }

    /// Send a one-byte plaintext config command (spec §6.6 steps 2–4).
    fn config_byte(&mut self, header: [u8; 4], byte: u8) -> Result<(), OtpTransportError> {
        let (_, sw) = self
            .transport
            .transmit(&t2::build_apdu(header, &[byte]), false)?;
        // HOTP-over-HID may be unsupported on older models (spec §6.6 compat).
        match OtpError::check(sw) {
            Ok(()) => Ok(()),
            Err(OtpError::HidNotSupported) => {
                Err(OtpTransportError::Applet(OtpError::HidNotSupported))
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Seal `cleartext` for a `WRITE_SEED`, choosing the encryption by PIN state:
    ///
    ///  * PIN window open (`pin_verified`): the device rejects `GET_ECDH_PUBKEY`
    ///    with `6A81`, so there is no ECDH blob. The write instead reuses the
    ///    verified PIN session keys, in the authenticated format that mirrors a
    ///    PIN-mode read: `IV || AES-CBC(SessionEncKey, IV, pt) ||
    ///    HMAC(SessionMacKey, EncData)[:16]` (confirmed against a device capture
    ///    in the reference client).
    ///  * Otherwise (unprotected key): fetch a fresh ephemeral device pubkey via
    ///    `GET_ECDH_PUBKEY` and build the standard ECDH seed blob with `iv`.
    fn seal(&mut self, cleartext: &[u8], iv: &[u8; 16]) -> Result<Vec<u8>, OtpTransportError> {
        if self.pin_verified {
            let keys = self
                .pin_session
                .as_ref()
                .ok_or(OtpTransportError::Parse(ParseError::Truncated))?;
            return Ok(t2::crypto::build_protected_write_data(keys, cleartext));
        }
        let (device_pub, sw) = self.transport.transmit(&t2::get_ecdh_pubkey(), false)?;
        OtpError::check(sw)?;
        Ok(t2::encrypt_seed_payload(&device_pub, cleartext, iv)?)
    }

    /// True when this session is over PC/SC (NFC / contact reader).
    pub fn is_pcsc(&self) -> bool {
        self.is_pcsc
    }
}

/// Map an [`OtpType`] to a short display string for the CLI.
pub fn otp_type_str(t: OtpType) -> &'static str {
    match t {
        OtpType::Hotp => "HOTP",
        OtpType::Totp => "TOTP",
    }
}

#[cfg(test)]
mod trace_redaction_tests {
    use super::response_is_sensitive;
    use keyroost_token2otp::cmd;

    #[test]
    fn enum_reads_have_sensitive_responses() {
        // ENUM_CODES and its continuation return account names + live OTP codes.
        assert!(response_is_sensitive(&cmd::ENUM_CODES));
        assert!(response_is_sensitive(&cmd::ENUM_CODES_CONTINUE));
        // Trailing body bytes (subcommand, timestamp) don't change the verdict.
        let mut enum_with_body = cmd::ENUM_CODES.to_vec();
        enum_with_body.extend_from_slice(&[cmd::SUB_READ_ONE, b'a', b'c', b'c', b't']);
        assert!(response_is_sensitive(&enum_with_body));
    }

    #[test]
    fn write_seed_response_is_not_sensitive() {
        // WRITE_SEED shares P1=0x05 but answers with a status word only, so its
        // response carries no secret even though its *request* does.
        assert!(!response_is_sensitive(&cmd::WRITE_SEED));
    }

    #[test]
    fn public_and_status_only_responses_are_not_sensitive() {
        // ECDH pubkey and device config are public; the serial read and a bare
        // GET RESPONSE / SELECT return non-secret bytes or a status word.
        assert!(!response_is_sensitive(&cmd::GET_ECDH_PUBKEY));
        assert!(!response_is_sensitive(&cmd::READ_CONFIG));
        assert!(!response_is_sensitive(&cmd::READ_SERIAL_INS));
        assert!(!response_is_sensitive(&[0x00, 0xC0, 0x00, 0x00, 0x20])); // GET RESPONSE
        assert!(!response_is_sensitive(&[0x00, 0xA4, 0x04, 0x00])); // SELECT
    }

    #[test]
    fn short_apdu_is_not_sensitive() {
        assert!(!response_is_sensitive(&[]));
        assert!(!response_is_sensitive(&[0x80, 0xC5]));
        assert!(!response_is_sensitive(&[0x80, 0xC5, 0x05]));
    }

    #[test]
    fn seed_write_requests_are_redacted() {
        use super::request_is_sensitive;
        // The request body carries the ECDH-sealed seed on both write paths.
        assert!(request_is_sensitive(&cmd::WRITE_SEED));
        assert!(request_is_sensitive(&cmd::WRITE_HOTP_SEED));
        // A read command's request has no secret and stays in the clear.
        assert!(!request_is_sensitive(&cmd::GET_ECDH_PUBKEY));
        assert!(!request_is_sensitive(&cmd::READ_CONFIG));
        assert!(!request_is_sensitive(&[0x00, 0xA4, 0x04, 0x00]));
    }

    #[test]
    fn trace_line_redacts_sensitive_payloads() {
        use super::trace_line;
        let secret = [0xDE, 0xAD, 0xBE, 0xEF];
        // A sensitive payload must never reach the trace as hex — only its
        // length may appear.
        let line = trace_line("PCSC send", &secret, true);
        assert!(!line.contains("deadbeef"), "secret bytes leaked: {line}");
        assert_eq!(line, "[token2otp PCSC send] <4 bytes redacted>");
        // A non-sensitive payload prints as lowercase hex.
        let clear = trace_line("HID recv", &secret, false);
        assert_eq!(clear, "[token2otp HID recv] deadbeef");
    }
}

#[cfg(test)]
mod le_retry_tests {
    use super::*;

    #[test]
    fn case_2_replaces_the_trailing_le() {
        // READ_CONFIG is header + Le (case 2): 80 C5 02 00 40.
        let apdu = t2::read_config(64);
        assert_eq!(
            resend_with_le(&apdu, 0x0A),
            vec![0x80, 0xC5, 0x02, 0x00, 0x0A]
        );
        // GET RESPONSE (00 C0 00 00 Le) is also case 2.
        assert_eq!(
            resend_with_le(&[0x00, 0xC0, 0x00, 0x00, 0x20], 0x08),
            vec![0x00, 0xC0, 0x00, 0x00, 0x08]
        );
    }

    #[test]
    fn case_3_appends_le_and_keeps_the_body_intact() {
        // WRITE_SEED with a body is case 3 — header + Lc + data, no trailing
        // Le (keyroost_token2otp::build_apdu appends none). Its last byte is
        // *data*; the branch regression overwrote it (seed ciphertext /
        // account-name byte) on a 6C retry.
        let body = [0xAA; 16];
        let apdu = t2::build_apdu(cmd::WRITE_SEED, &body);
        let resent = resend_with_le(&apdu, 0x2A);
        let mut expected = apdu.clone();
        expected.push(0x2A);
        assert_eq!(resent, expected);
        assert_eq!(resent[resent.len() - 2], 0xAA); // last body byte survived

        // ENUM_CODES (subcommand + timestamp body) likewise appends.
        let apdu = t2::build_apdu(cmd::ENUM_CODES, &serialize_enum_all(0x1122_3344));
        let mut expected = apdu.clone();
        expected.push(0x10);
        assert_eq!(resend_with_le(&apdu, 0x10), expected);

        // SELECT (header + Lc + AID) is case 3 too.
        let apdu = t2::build_select(&t2::OTP_APPLET_AID);
        let mut expected = apdu.clone();
        expected.push(0x00);
        assert_eq!(resend_with_le(&apdu, 0x00), expected);
    }

    #[test]
    fn case_1_appends_le_forming_case_2() {
        // ERASE_ALL is a bare 4-byte header (case 1).
        assert_eq!(
            resend_with_le(&t2::erase_all(), 0x00),
            vec![0x80, 0xC5, 0x05, 0x02, 0x00]
        );
    }

    #[test]
    fn case_4_replaces_the_trailing_le() {
        // header + Lc(2) + 2 data bytes + Le: len == 5 + Lc + 1 ends in Le.
        let apdu = [0x80, 0xC5, 0x05, 0x00, 0x02, 0x03, 0x07, 0x10];
        assert_eq!(
            resend_with_le(&apdu, 0x40),
            vec![0x80, 0xC5, 0x05, 0x00, 0x02, 0x03, 0x07, 0x40]
        );
    }
}

#[cfg(test)]
mod enumerate_bounds_tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    /// One valid single-entry ENUM page (the spec §10.1 worked example, same
    /// bytes as the known-answer tests in `keyroost_token2otp::entry`), with
    /// the more-pages bit optionally OR'd into the leading type byte.
    fn one_entry_page(more_pages: bool) -> Vec<u8> {
        let first = if more_pages { 0x81 } else { 0x01 };
        let mut payload = vec![first, 0xC1, 0x00, 0x1E, 0x06, 0x00, 0x04];
        payload.extend_from_slice(b"Test");
        payload.push(0x05);
        payload.extend_from_slice(b"alice");
        payload.push(0x06);
        payload.extend_from_slice(b"123456");
        payload
    }

    /// A key that never stops paging: every response is a valid one-entry
    /// page with the more-pages bit set.
    struct EndlessPages {
        transmits: Rc<Cell<usize>>,
    }

    impl OtpTransport for EndlessPages {
        fn transmit(
            &mut self,
            _apdu: &[u8],
            _detect_button_wait: bool,
        ) -> Result<(Vec<u8>, u16), OtpTransportError> {
            self.transmits.set(self.transmits.get() + 1);
            Ok((one_entry_page(true), 0x9000))
        }
    }

    #[test]
    fn endless_more_pages_is_bounded_by_host_caps() {
        let transmits = Rc::new(Cell::new(0));
        let mut session = Token2OtpSession {
            transport: Box::new(EndlessPages {
                transmits: transmits.clone(),
            }),
            is_pcsc: false,
            pin_session: None,
            pin_verified: false,
            pin_present: None,
        };
        let res = session.enumerate(0);
        assert!(
            matches!(res, Err(OtpTransportError::EnumerationCapExceeded)),
            "endless more_pages must fail with the cap error, got {res:?}"
        );
        // Boundedness, not just eventual failure: the host stops issuing
        // continuations at its own cap.
        assert!(
            transmits.get() <= MAX_ENUM_PAGES,
            "issued {} transmits, cap is {}",
            transmits.get(),
            MAX_ENUM_PAGES
        );
    }

    /// A well-behaved two-page enumeration still works (regression guard).
    struct TwoPages {
        sent: usize,
    }

    impl OtpTransport for TwoPages {
        fn transmit(
            &mut self,
            _apdu: &[u8],
            _detect_button_wait: bool,
        ) -> Result<(Vec<u8>, u16), OtpTransportError> {
            let more = self.sent == 0; // first page continues, second is last
            self.sent += 1;
            Ok((one_entry_page(more), 0x9000))
        }
    }

    #[test]
    fn normal_two_page_enumeration_is_unaffected() {
        let mut session = Token2OtpSession {
            transport: Box::new(TwoPages { sent: 0 }),
            is_pcsc: false,
            pin_session: None,
            pin_verified: false,
            pin_present: None,
        };
        let entries = session.enumerate(0).expect("two pages must enumerate");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].account_name, "alice");
    }
}

#[cfg(all(test, target_os = "linux", not(feature = "hidapi-backend")))]
mod hidraw_bounded_read_tests {
    use super::*;

    /// KEY-011 for the Token2 OTP HID path: a silent device must produce a
    /// timeout error within the transport deadline, not a blocked read.
    #[test]
    fn silent_device_times_out_instead_of_blocking() {
        use std::os::unix::net::UnixStream;
        let (a, _b) = UnixStream::pair().unwrap();
        a.set_nonblocking(true).unwrap(); // same fd state open_io now sets
        let file = std::fs::File::from(std::os::fd::OwnedFd::from(a));
        let mut t = HidOtpTransport {
            io: HidIo::Hidraw(file),
            timeout: Duration::from_millis(300),
            button_prompt: None,
            debug: false,
            resp_sensitive: false,
        };
        let start = Instant::now();
        let res = t.transmit(&t2::get_ecdh_pubkey(), false);
        assert!(
            matches!(res, Err(OtpTransportError::TransportUnavailable(_))),
            "expected the no-response timeout, got {res:?}"
        );
        assert!(start.elapsed() < Duration::from_secs(5));
    }
}

/// Issue #95: a key that answers must not be reported as a key that cannot be
/// reached. The reporter's Bio3 completed a full HID exchange and returned
/// `0105`, and keyroost told them "HID may be disabled on the key" — advice
/// that could not have helped, because HID was working.
///
/// Token2 then explained the shape (same thread): Bio3 **has** OTP, carried
/// over CCID, and ships with HID disabled precisely because it has no
/// HOTP-over-HID. So a declined HID probe is the expected state, not a fault,
/// and the actionable failure is whatever stopped CCID — for the reporter, a
/// smart-card service that was not running.
#[cfg(test)]
mod declined_probe_is_not_an_unusable_interface {
    use super::*;
    use keyroost_token2otp::sw;

    /// Stand-in for the reporter's CCID failure: pcscd was not running.
    fn no_pcsc() -> OtpTransportError {
        OtpTransportError::TransportUnavailable(
            "PC/SC service is unavailable (The Smart card resource manager is not running)".into(),
        )
    }

    #[test]
    fn an_applet_status_word_reports_the_key_declining() {
        // Exactly the reporter's case.
        let err = detect_failure_from(
            OtpTransportError::Applet(OtpError::BadStatusCode(0x0105)),
            no_pcsc(),
        );
        assert!(
            matches!(
                err,
                OtpTransportError::HidDeclinedAndNoCcid { sw: 0x0105, .. }
            ),
            "an answering applet must not be classified as an unusable interface, got {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("0x0105"),
            "the status word belongs in the message: {msg}"
        );
        // The specific wrong advice that was reported.
        assert!(
            !msg.contains("HID may be disabled"),
            "must not tell the user to enable an interface that just carried a \
             full request and response: {msg}"
        );
        assert!(
            !msg.contains("does not have"),
            "must not claim the key lacks OTP — Token2 confirmed Bio3 has it \
             over CCID: {msg}"
        );
    }

    #[test]
    fn the_actionable_ccid_reason_reaches_the_user() {
        // The reporter's real blocker was pcscd, and it must not be swallowed:
        // CCID is the channel these models actually carry OTP on.
        let err = detect_failure_from(
            OtpTransportError::Applet(OtpError::BadStatusCode(0x0105)),
            no_pcsc(),
        );
        let msg = err.to_string();
        assert!(
            msg.contains("Smart card resource manager is not running"),
            "the CCID failure is the one the user can act on: {msg}"
        );
        assert!(
            msg.contains("pcscd") || msg.contains("smart-card service"),
            "say what to start: {msg}"
        );
    }

    #[test]
    fn every_applet_error_keeps_its_status_word() {
        // status_word() is the inverse of check(), so the transport can always
        // recover what the key said regardless of which variant it mapped to.
        for sw in [
            sw::ENTRY_NOT_FOUND,
            sw::NOT_ENOUGH_SPACE,
            sw::BUTTON_TIMEOUT,
            sw::HID_NOT_SUPPORTED,
            0x0105,
            0x6A80,
        ] {
            let e = OtpError::check(sw).expect_err("non-9000 must map to an error");
            match detect_failure_from(OtpTransportError::Applet(e), no_pcsc()) {
                OtpTransportError::HidDeclinedAndNoCcid { sw: got, .. } => {
                    assert_eq!(got, sw, "status word must survive the round trip");
                }
                other => panic!("expected HidDeclinedAndNoCcid for {sw:#06X}, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_silent_or_broken_interface_still_blames_the_interface() {
        // The other half of the distinction: no answer really is a transport
        // problem, and must keep the original message.
        for probe_err in [
            OtpTransportError::TokenNotDetected,
            OtpTransportError::EmptyResponse,
            OtpTransportError::TransportUnavailable("no such device".into()),
        ] {
            assert!(
                matches!(
                    detect_failure_from(probe_err, no_pcsc()),
                    OtpTransportError::NoUsableInterface
                ),
                "a probe that got no answer is evidence about the interface"
            );
        }
    }
}

/// A key that has never heard of the OTP-PIN command must behave exactly as it
/// did before the feature existed.
///
/// The PIN-flag read now runs ahead of every list, add and delete, so the way
/// an older applet answers it decides whether those still work. Firmware before
/// R3.4 answers `80 C5 05 04` with whatever its dispatcher says for an unknown
/// instruction — the exact status word varies by model and channel — and none
/// of those may become a failure the user sees.
#[cfg(test)]
mod pre_r34_keys_are_unaffected {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// The `ENUM_CODES` READ_ALL APDU as `main` builds it, byte for byte: the
    /// short-Lc 9-byte body carrying the subcommand and a big-endian timestamp.
    /// Pinned here rather than rebuilt, so a change to the builder shows up as a
    /// diff in *this* test too.
    const ENUM_READ_ALL_AT_T0: [u8; 14] = [
        0x80, 0xC5, 0x05, 0x00, // ENUM_CODES
        0x09, // short Lc
        0x03, // SUB_READ_ALL
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // timestamp 0
    ];

    /// One valid single-entry page (spec §10.1), never encrypted.
    fn cleartext_page() -> Vec<u8> {
        let mut payload = vec![0x01, 0xC1, 0x00, 0x1E, 0x06, 0x00, 0x04];
        payload.extend_from_slice(b"Test");
        payload.push(0x05);
        payload.extend_from_slice(b"alice");
        payload.push(0x06);
        payload.extend_from_slice(b"123456");
        payload
    }

    /// The P-256 generator, as the raw `X || Y` a `GET_ECDH_PUBKEY` answers
    /// with. Any valid point does; this one needs no key generation in a test.
    const DEVICE_PUB_XY: [u8; 64] = [
        0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40,
        0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98,
        0xC2, 0x96, 0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C,
        0x0F, 0x9E, 0x16, 0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68,
        0x37, 0xBF, 0x51, 0xF5,
    ];

    /// Stands in for pre-R3.4 firmware: the PIN-flag instruction gets `sw`, and
    /// everything else answers the way it always has. Records every APDU.
    struct OldFirmware {
        flag_sw: u16,
        sent: Rc<RefCell<Vec<Vec<u8>>>>,
    }

    impl OtpTransport for OldFirmware {
        fn transmit(
            &mut self,
            apdu: &[u8],
            _detect_button_wait: bool,
        ) -> Result<(Vec<u8>, u16), OtpTransportError> {
            self.sent.borrow_mut().push(apdu.to_vec());
            match apdu.get(..4) {
                Some(h) if h == t2::cmd::READ_OTP_PIN_FLAG => Ok((Vec::new(), self.flag_sw)),
                Some(h) if h == t2::cmd::GET_ECDH_PUBKEY => Ok((DEVICE_PUB_XY.to_vec(), 0x9000)),
                Some(h) if h == t2::cmd::ENUM_CODES => Ok((cleartext_page(), 0x9000)),
                _ => Ok((Vec::new(), 0x9000)),
            }
        }
    }

    fn old_key(flag_sw: u16) -> (Token2OtpSession, Rc<RefCell<Vec<Vec<u8>>>>) {
        let sent = Rc::new(RefCell::new(Vec::new()));
        let session = Token2OtpSession {
            transport: Box::new(OldFirmware {
                flag_sw,
                sent: sent.clone(),
            }),
            is_pcsc: false,
            pin_session: None,
            pin_verified: false,
            pin_present: None,
        };
        (session, sent)
    }

    /// The answers that mean "no PIN command here" — shared with the probe so a
    /// word added there is exercised here.
    const UNKNOWN_INSTRUCTION_ANSWERS: [u16; 5] = super::NO_PIN_FEATURE_ANSWERS;

    #[test]
    fn a_locked_pin_is_reported_not_hidden() {
        // 6983 on the flag read is the applet saying "PIN locked", not "no PIN
        // feature" — listing must stop with that state, never proceed as if
        // the key were unprotected. 6A81 is likewise a real state per Token2.
        for sw in [0x6983u16, 0x6982, 0x6985, 0x6A81] {
            let (mut session, _) = old_key(sw);
            let err = session
                .pin_status()
                .expect_err("a real PIN state must not be swallowed");
            assert!(
                matches!(err, OtpTransportError::Applet(_)),
                "{sw:#06X} surfaced as {err:?}"
            );
            let (mut session, _) = old_key(sw);
            assert!(session.enumerate_pinned(0, None).is_err(), "{sw:#06X}");
        }
    }

    #[test]
    fn listing_still_works_and_sends_the_same_bytes_as_before() {
        for sw in UNKNOWN_INSTRUCTION_ANSWERS {
            let (mut session, sent) = old_key(sw);
            let entries = session
                .enumerate_pinned(0, None)
                .unwrap_or_else(|e| panic!("a key answering {sw:#06X} must still list: {e}"));
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].account_name, "alice");
            assert_eq!(entries[0].code.as_deref(), Some("123456"));

            // The only new traffic is the capability probe itself; the
            // enumeration is byte-identical to what shipped before the PIN work.
            let sent = sent.borrow();
            assert_eq!(sent.len(), 2, "one flag read, then the enumeration");
            assert_eq!(&sent[0][..4], &t2::cmd::READ_OTP_PIN_FLAG);
            assert_eq!(sent[1], ENUM_READ_ALL_AT_T0);
        }
    }

    #[test]
    fn writing_and_deleting_still_work() {
        for sw in UNKNOWN_INSTRUCTION_ANSWERS {
            let (mut session, sent) = old_key(sw);
            let entry = WriteEntry {
                otp_type: t2::OtpType::Totp,
                algorithm: t2::Algorithm::Sha1,
                timestep: 30,
                code_length: 6,
                button_required: false,
                app_name: "Test",
                account_name: "alice",
                seed: &[0u8; 20],
            };
            session
                .write_entry_pinned(&entry, None)
                .unwrap_or_else(|e| panic!("a key answering {sw:#06X} must still write: {e}"));
            // The unprotected write still goes out as an ECDH-sealed blob —
            // the session-key path is only for a verified PIN window.
            let seen = sent.borrow().clone();
            assert!(seen.iter().any(|a| a[..4] == t2::cmd::GET_ECDH_PUBKEY));
            assert!(seen.iter().any(|a| a[..4] == t2::cmd::WRITE_SEED));

            let (mut session, _) = old_key(sw);
            session
                .delete_entry_pinned("Test", "alice", None)
                .unwrap_or_else(|e| panic!("a key answering {sw:#06X} must still delete: {e}"));
        }
    }

    #[test]
    fn the_pin_state_reads_as_absent_rather_than_as_an_error() {
        for sw in UNKNOWN_INSTRUCTION_ANSWERS {
            let (mut session, _) = old_key(sw);
            assert!(
                session.pin_status().expect("not an error").is_none(),
                "{sw:#06X} means the feature is not there"
            );
            assert!(!session.pin_is_set().unwrap());
            assert_eq!(session.pin_set_cached(), None);
        }
    }

    #[test]
    fn a_body_too_short_to_parse_is_also_just_absent() {
        // A key that answers 9000 with nothing useful has told us as little as
        // one that declined outright.
        struct EmptyOk;
        impl OtpTransport for EmptyOk {
            fn transmit(
                &mut self,
                apdu: &[u8],
                _b: bool,
            ) -> Result<(Vec<u8>, u16), OtpTransportError> {
                if apdu[..4] == t2::cmd::READ_OTP_PIN_FLAG {
                    Ok((vec![0x07, 0x64], 0x9000)) // under the 4-byte head
                } else {
                    Ok((cleartext_page(), 0x9000))
                }
            }
        }
        let mut session = Token2OtpSession {
            transport: Box::new(EmptyOk),
            is_pcsc: false,
            pin_session: None,
            pin_verified: false,
            pin_present: None,
        };
        assert!(session.pin_status().unwrap().is_none());
        assert_eq!(session.enumerate_pinned(0, None).unwrap().len(), 1);
    }

    #[test]
    fn a_transport_failure_is_still_a_failure() {
        // Degrading on a status word must not swallow a broken cable: the
        // applet declining and the interface not working are different facts.
        struct Dead;
        impl OtpTransport for Dead {
            fn transmit(
                &mut self,
                _a: &[u8],
                _b: bool,
            ) -> Result<(Vec<u8>, u16), OtpTransportError> {
                Err(OtpTransportError::EmptyResponse)
            }
        }
        let mut session = Token2OtpSession {
            transport: Box::new(Dead),
            is_pcsc: false,
            pin_session: None,
            pin_verified: false,
            pin_present: None,
        };
        assert!(matches!(
            session.pin_status(),
            Err(OtpTransportError::EmptyResponse)
        ));
    }

    #[test]
    fn a_protected_key_with_no_pin_supplied_asks_for_one() {
        // The other side of the same branch: a key that DOES answer the flag
        // read, and reports a PIN, must not silently list nothing.
        struct Protected;
        impl OtpTransport for Protected {
            fn transmit(
                &mut self,
                apdu: &[u8],
                _b: bool,
            ) -> Result<(Vec<u8>, u16), OtpTransportError> {
                if apdu[..4] == t2::cmd::READ_OTP_PIN_FLAG {
                    // AlgId, retries left, PIN length 6, max retries.
                    Ok((vec![0x07, 0x64, 0x06, 0x64], 0x9000))
                } else {
                    Ok((cleartext_page(), 0x9000))
                }
            }
        }
        let mut session = Token2OtpSession {
            transport: Box::new(Protected),
            is_pcsc: false,
            pin_session: None,
            pin_verified: false,
            pin_present: None,
        };
        assert!(matches!(
            session.enumerate_pinned(0, None),
            Err(OtpTransportError::PinRequired)
        ));
        assert_eq!(session.pin_set_cached(), Some(true));
    }
}
