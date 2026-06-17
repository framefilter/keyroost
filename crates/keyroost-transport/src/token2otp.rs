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
//! byte layer, and this module redacts seed-bearing APDU bodies from the debug
//! trace.

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

/// USB-HID transport for the Token2 OTP applet (spec §4).
pub struct HidOtpTransport {
    io: HidIo,
    timeout: Duration,
    button_prompt: Option<ButtonPrompt>,
    debug: bool,
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
        })
    }

    #[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
    fn open_io(path: &Path) -> Result<HidIo, OtpTransportError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
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
                use std::io::Read;
                f.read(&mut buf[..hidframe::REPORT_PAYLOAD])
                    .map_err(|e| OtpTransportError::TransportUnavailable(e.to_string()))?
            }
            #[cfg(any(not(target_os = "linux"), feature = "hidapi-backend"))]
            HidIo::Hidapi(d) => {
                buf.fill(0);
                d.read(&mut buf[..hidframe::REPORT_PAYLOAD])
                    .map_err(|e| OtpTransportError::TransportUnavailable(e.to_string()))?
            }
        };
        if self.debug {
            let hex: String = buf[..n].iter().map(|b| format!("{b:02x}")).collect();
            eprintln!("[token2otp HID raw-frame] ({n} bytes) {hex}");
        }
        Ok(n)
    }

    fn trace(&self, dir: &str, bytes: &[u8], sensitive: bool) {
        if !self.debug {
            return;
        }
        if sensitive {
            eprintln!("[token2otp HID {dir}] <{} bytes redacted>", bytes.len());
        } else {
            let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            eprintln!("[token2otp HID {dir}] {hex}");
        }
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
        let sensitive = matches!(apdu.get(1), Some(0xC5))
            && matches!(apdu.get(2), Some(0x05) | Some(0x00))
            && matches!(apdu.get(3), Some(0x02) | Some(0x00));
        self.trace("send", apdu, sensitive);

        for frame in hidframe::build_send_frames(apdu) {
            self.write_report(&frame)?;
        }

        let mut asm = ResponseAssembler::new();
        let deadline = Instant::now() + self.timeout;
        let mut prompted = false;
        let mut buf = [0u8; hidframe::REPORT_PAYLOAD + 1];
        loop {
            if Instant::now() >= deadline {
                return Err(OtpTransportError::Applet(OtpError::ButtonPressRequired));
            }
            let n = self.read_report(&mut buf)?;
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
            let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
            eprintln!("[token2otp HID parsed] data={hex} sw={sw:#06x}");
        }
        self.trace("recv", &data, false);
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
            let mut t = PcScOtpTransport { card, debug };
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

    fn select(&mut self, aid: &[u8]) -> Result<(), OtpTransportError> {
        let (_, sw) = self.raw_transmit(&t2::build_select(aid))?;
        OtpError::check(sw)?;
        Ok(())
    }

    fn raw_transmit(&self, apdu: &[u8]) -> Result<(Vec<u8>, u16), OtpTransportError> {
        if self.debug {
            let hex: String = apdu.iter().map(|b| format!("{b:02x}")).collect();
            eprintln!("[token2otp PCSC send] {hex}");
        }
        let mut acc = Vec::new();
        let mut to_send = apdu.to_vec();
        let mut chunks = 0usize;
        loop {
            let mut rbuf = [0u8; 4096];
            let resp = self.card.transmit(&to_send, &mut rbuf)?;
            if self.debug {
                let hex: String = resp.iter().map(|b| format!("{b:02x}")).collect();
                eprintln!("[token2otp PCSC recv] {hex}");
            }
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
                    let le = sw_bytes[1];
                    // Re-send the original command with the corrected Le appended.
                    to_send = apdu.to_vec();
                    to_send.push(le);
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
}

/// How long the HID probe waits for the OTP applet to answer before giving up.
/// On Linux the hidraw `read()` is blocking and the kernel surfaces no timeout,
/// so a key whose FIDO HID interface enumerates but whose OTP-over-HID channel
/// is disabled (e.g. when the keyboard interface is enabled, changing the USB
/// composite) would otherwise block forever here instead of falling back to
/// PC/SC. Bounding the probe lets `detect` fail over to CCID, which carries the
/// same applet. Only used on the Linux hidraw path; the hidapi backend bounds
/// its own reads.
#[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
const HID_PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Probe whether the OTP applet answers over HID, taking the transport by value
/// so a probe that hangs on a blocking read cannot stall the caller.
///
/// On success returns the transport back (it's reused as the live channel). On
/// failure — including the probe exceeding [`HID_PROBE_TIMEOUT`] — returns an
/// error; the transport is dropped (on Linux it may still be owned by a detached
/// worker thread blocked in `read()`, which is harmless and ends when the read
/// returns or the process exits).
fn probe_hid_owned(
    mut t: HidOtpTransport,
) -> Result<HidOtpTransport, (OtpTransportError, Option<HidOtpTransport>)> {
    #[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
    {
        // hidraw read() is blocking with no kernel timeout, so run the probe on
        // a worker thread and bound it with a channel recv deadline. If it times
        // out we abandon the thread (and the transport it owns) and report a
        // timeout so the caller can fall back to PC/SC.
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
        // hidapi's read honors its own timeout, so a direct probe can't hang.
        match probe_hid(&mut t) {
            Ok(()) => Ok(t),
            Err(e) => Err((e, Some(t))),
        }
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
                    }),
                    Err(_) => {
                        // HID present but applet unreachable (HID disabled on the
                        // device, or the probe timed out) — try CCID instead.
                        match PcScOtpTransport::open_first_debug(debug) {
                            Ok(p) => Ok(Self {
                                transport: Box::new(p),
                                is_pcsc: true,
                            }),
                            Err(_) => Err(OtpTransportError::NoUsableInterface),
                        }
                    }
                }
            }
            Err(OtpTransportError::TokenNotDetected) => {
                let t = PcScOtpTransport::open_first_debug(debug)?;
                Ok(Self {
                    transport: Box::new(t),
                    is_pcsc: true,
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
        })
    }

    /// Force the PC/SC (CCID / NFC) transport (no HID).
    pub fn detect_pcsc_only(debug: bool) -> Result<Self, OtpTransportError> {
        let t = PcScOtpTransport::open_first_debug(debug)?;
        Ok(Self {
            transport: Box::new(t),
            is_pcsc: true,
        })
    }

    /// Wrap an explicit HID transport (e.g. when the caller resolved a path).
    pub fn with_hid(t: HidOtpTransport) -> Self {
        Self {
            transport: Box::new(t),
            is_pcsc: false,
        }
    }

    /// Wrap an explicit PC/SC transport.
    pub fn with_pcsc(t: PcScOtpTransport) -> Self {
        Self {
            transport: Box::new(t),
            is_pcsc: true,
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
        let mut page = t2::parse_enum_page(&data)?;
        let mut entries = page.entries;
        while page.more_pages {
            let cont = t2::build_apdu(cmd::ENUM_CODES_CONTINUE, &timestamp.to_be_bytes());
            let (data, sw) = self.transport.transmit(&cont, false)?;
            OtpError::check(sw)?;
            page = t2::parse_enum_page(&data)?;
            entries.extend(page.entries);
        }
        Ok(entries)
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
    /// left intact — unlike [`set_button_hotp`], which rewrites the seed.
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
    /// ([`SetDeviceTypeError::WouldBrick`]); this method surfaces that as an
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
        let (data, sw) = self.transport.transmit(&t2::read_serial_request(), false)?;
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

    /// Run the ECDH handshake: fetch the device pubkey, then seal `cleartext`
    /// with `iv` (spec §6.3 step 1, §7).
    fn seal(&mut self, cleartext: &[u8], iv: &[u8; 16]) -> Result<Vec<u8>, OtpTransportError> {
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
