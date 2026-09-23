//! CTAP HID transport. Linux uses a dependency-free `/dev/hidraw*` `File`
//! backend; macOS and Windows use hidapi (IOKit / hid.dll) behind the same
//! `write_report` / `read_report` interface. The `hidapi-backend` feature forces
//! the hidapi path on for building/testing it on Linux too.
//!
//! Implements the wire framing from the FIDO CTAP HID spec: 64-byte reports,
//! init frame with a 7-byte header (CID + CMD + BCNT), continuation frames
//! with a 5-byte header (CID + SEQ), and channel allocation via
//! `CTAPHID_INIT`. KEEPALIVE frames during long-running operations are
//! consumed transparently.
//!
//! Read bounding is uniform across backends (audit KEY-011). The hidapi
//! backend (macOS/Windows) polls with a timeout via
//! `keyroost_hid::read_report_bounded`; the Linux hidraw `File` backend opens
//! the node `O_NONBLOCK` and polls via
//! `keyroost_hid::read_nonblocking_bounded`. On every backend the overall
//! deadline and the cooperative-cancel flag are honored even if a device goes
//! completely silent mid-response — it cannot block a caller forever.

#[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
use std::fs::{File, OpenOptions};
use std::io;
#[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

/// Broadcast channel ID used for the initial `CTAPHID_INIT` request.
pub const CTAPHID_BROADCAST_CID: u32 = 0xFFFF_FFFF;

/// Default per-report read deadline for ordinary commands. Long user-present
/// operations (reset, fingerprint capture) widen it temporarily and must
/// restore it to this afterwards so later commands don't inherit the long
/// window.
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(2);
/// Output / input HID report size on USB authenticators. Both reports are
/// exactly 64 bytes; the leading report-ID byte (0x00) is added by the
/// transport layer, making the host-side write 65 bytes.
pub const CTAPHID_REPORT_SIZE: usize = 64;
/// Maximum CTAP HID payload length, set by the 16-bit BCNT field minus the
/// space the first frame consumes for cont-frame headers.
pub const CTAPHID_MAX_PAYLOAD: usize = 7609;

const INIT_FRAME_HEADER: usize = 7;
const CONT_FRAME_HEADER: usize = 5;
const INIT_FRAME_DATA: usize = CTAPHID_REPORT_SIZE - INIT_FRAME_HEADER;
const CONT_FRAME_DATA: usize = CTAPHID_REPORT_SIZE - CONT_FRAME_HEADER;

/// CTAPHID command bytes. The high bit (`0x80`) marks an initialization
/// frame; continuation frames put the sequence number in that field instead.
pub const CTAPHID_PING: u8 = 0x81;
pub const CTAPHID_MSG: u8 = 0x83;
pub const CTAPHID_INIT: u8 = 0x86;
pub const CTAPHID_WINK: u8 = 0x88;
pub const CTAPHID_CBOR: u8 = 0x90;
pub const CTAPHID_CANCEL: u8 = 0x91;
pub const CTAPHID_KEEPALIVE: u8 = 0xBB;
pub const CTAPHID_ERROR: u8 = 0xBF;

/// CTAPHID transport error codes carried in the one-byte `CTAPHID_ERROR`
/// payload. These are transport-level faults and are a different namespace
/// from the CTAP2 status bytes decoded in `cmd.rs`.
pub const CTAPHID_ERR_INVALID_CMD: u8 = 0x01;
pub const CTAPHID_ERR_INVALID_PAR: u8 = 0x02;
pub const CTAPHID_ERR_INVALID_LEN: u8 = 0x03;
pub const CTAPHID_ERR_INVALID_SEQ: u8 = 0x04;
pub const CTAPHID_ERR_MSG_TIMEOUT: u8 = 0x05;
pub const CTAPHID_ERR_CHANNEL_BUSY: u8 = 0x06;
pub const CTAPHID_ERR_LOCK_REQUIRED: u8 = 0x0A;
pub const CTAPHID_ERR_INVALID_CHANNEL: u8 = 0x0B;
pub const CTAPHID_ERR_OTHER: u8 = 0x7F;

/// Retry budget for `ERR_CHANNEL_BUSY`, the one CTAPHID error the spec tells
/// clients to retry ("the client SHOULD retry the request after a short
/// delay"). Everything else in the table is a protocol fault where retrying
/// only delays the error, so the policy below is deliberately narrow.
///
/// Four attempts (the first plus three retries) 200 ms apart: 200 ms is long
/// enough for another client's in-flight transaction to finish and release the
/// device, short enough that a retry that is not going to help costs almost
/// nothing. The wall-clock cap is the backstop for a device that answers busy
/// slowly or forever — it bounds the whole loop below the ordinary
/// [`DEFAULT_READ_TIMEOUT`], so a busy key never makes a command sit longer
/// than a silent one already does.
const CHANNEL_BUSY_MAX_ATTEMPTS: u32 = 4;
const CHANNEL_BUSY_RETRY_DELAY: Duration = Duration::from_millis(200);
const CHANNEL_BUSY_TOTAL_BUDGET: Duration = Duration::from_millis(1500);

/// Capability flags reported in byte 16 of the INIT response.
pub const CAPABILITY_WINK: u8 = 0x01;
pub const CAPABILITY_CBOR: u8 = 0x04;
pub const CAPABILITY_NMSG: u8 = 0x08;

#[non_exhaustive]
#[derive(Debug)]
pub enum HidTransportError {
    Io(io::Error),
    Timeout,
    UnexpectedCommand {
        expected: u8,
        got: u8,
    },
    InitResponseTooShort,
    PayloadTooLarge(usize),
    OutOfSequence {
        expected: u8,
        got: u8,
    },
    DeviceError(u8),
    NonceMismatch,
    /// A cooperative cancel was requested (see [`CtapHidDevice::set_cancel_flag`])
    /// while waiting on the device.
    Cancelled,
    /// The hidapi I/O backend (macOS / Windows, or Linux under the
    /// `hidapi-backend` feature) reported an error opening or talking to the
    /// device.
    Backend(String),
}

impl std::fmt::Display for HidTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HidTransportError::Io(e) => write!(f, "HID I/O error: {}", e),
            HidTransportError::Timeout => write!(f, "CTAP transaction timed out"),
            HidTransportError::UnexpectedCommand { expected, got } => write!(
                f,
                "expected CTAPHID command 0x{:02X}, got 0x{:02X}",
                expected, got
            ),
            HidTransportError::InitResponseTooShort => {
                write!(f, "CTAPHID_INIT response was shorter than 17 bytes")
            }
            HidTransportError::PayloadTooLarge(n) => write!(f, "payload too large: {} bytes", n),
            HidTransportError::OutOfSequence { expected, got } => write!(
                f,
                "continuation frame out of sequence: expected SEQ={}, got SEQ={}",
                expected, got
            ),
            HidTransportError::DeviceError(c) => match ctaphid_error_meaning(*c) {
                // Lead with a plain-English explanation, keeping the spec name
                // + hex so a bug report stays diagnosable — the same shape the
                // CTAP2 status codes are rendered in (see `cmd.rs`).
                Some((name, hint)) => write!(f, "{} (CTAPHID error 0x{:02X} {})", hint, c, name),
                None => write!(f, "device reported CTAPHID_ERROR code 0x{:02X}", c),
            },
            HidTransportError::NonceMismatch => {
                write!(f, "CTAPHID_INIT response carried the wrong nonce")
            }
            HidTransportError::Cancelled => write!(f, "operation cancelled"),
            HidTransportError::Backend(s) => write!(f, "HID backend error: {}", s),
        }
    }
}

/// Spec name and plain-language explanation for a `CTAPHID_ERROR` code, as
/// defined by the FIDO CTAP HID spec's error-code table. Returns `None` for
/// codes outside that table — reserved or vendor behaviour — so the caller can
/// still print the raw hex rather than inventing a meaning for it.
fn ctaphid_error_meaning(code: u8) -> Option<(&'static str, &'static str)> {
    Some(match code {
        CTAPHID_ERR_INVALID_CMD => (
            "ERR_INVALID_CMD",
            "the key did not recognise the command \u{2014} its firmware may not support this feature",
        ),
        CTAPHID_ERR_INVALID_PAR => (
            "ERR_INVALID_PAR",
            "the key rejected a parameter in the request as invalid",
        ),
        CTAPHID_ERR_INVALID_LEN => (
            "ERR_INVALID_LEN",
            "the key rejected the request's declared message length",
        ),
        CTAPHID_ERR_INVALID_SEQ => (
            "ERR_INVALID_SEQ",
            "the key saw the message's frames arrive out of order",
        ),
        CTAPHID_ERR_MSG_TIMEOUT => (
            "ERR_MSG_TIMEOUT",
            "the key gave up waiting for the rest of the message",
        ),
        CTAPHID_ERR_CHANNEL_BUSY => (
            "ERR_CHANNEL_BUSY",
            "the key's HID channel was busy and stayed busy after retrying \u{2014} \
             close anything else using the key (a browser sign-in prompt, an \
             agent) and try again",
        ),
        CTAPHID_ERR_LOCK_REQUIRED => (
            "ERR_LOCK_REQUIRED",
            "the command needs an exclusive channel lock this client does not hold",
        ),
        CTAPHID_ERR_INVALID_CHANNEL => (
            "ERR_INVALID_CHANNEL",
            "the key no longer recognises this channel \u{2014} remove and re-insert the key",
        ),
        CTAPHID_ERR_OTHER => (
            "ERR_OTHER",
            "the key reported an unspecified internal error",
        ),
        _ => return None,
    })
}

/// Whether a `CTAPHID_ERROR` warrants another attempt, and how long to wait
/// first. `attempt` counts from 1 for the attempt that just failed; `elapsed`
/// is the time since the *first* attempt started, so it covers the earlier
/// round trips and delays, not just the sleeps.
///
/// Only `ERR_CHANNEL_BUSY` is retryable (see [`CHANNEL_BUSY_MAX_ATTEMPTS`]);
/// every other code reports a protocol fault that a retry cannot clear. Two
/// independent bounds apply, so a device that answers busy forever terminates
/// either way: the attempt count caps how many re-sends happen, and the
/// wall-clock budget caps how long the loop may take even if each attempt is
/// slow. Kept pure so the policy is testable without a device.
fn busy_retry_delay(code: u8, attempt: u32, elapsed: Duration) -> Option<Duration> {
    if code != CTAPHID_ERR_CHANNEL_BUSY || attempt >= CHANNEL_BUSY_MAX_ATTEMPTS {
        return None;
    }
    if elapsed.saturating_add(CHANNEL_BUSY_RETRY_DELAY) >= CHANNEL_BUSY_TOTAL_BUDGET {
        return None;
    }
    Some(CHANNEL_BUSY_RETRY_DELAY)
}

impl std::error::Error for HidTransportError {}

impl From<io::Error> for HidTransportError {
    fn from(e: io::Error) -> Self {
        HidTransportError::Io(e)
    }
}

/// Parsed `CTAPHID_INIT` response.
#[derive(Debug, Clone)]
pub struct InitResponse {
    pub channel_id: u32,
    pub protocol_version: u8,
    pub device_major: u8,
    pub device_minor: u8,
    pub device_build: u8,
    pub capabilities: u8,
}

impl InitResponse {
    pub fn supports_cbor(&self) -> bool {
        self.capabilities & CAPABILITY_CBOR != 0
    }
    pub fn supports_u2f(&self) -> bool {
        self.capabilities & CAPABILITY_NMSG == 0
    }
    pub fn supports_wink(&self) -> bool {
        self.capabilities & CAPABILITY_WINK != 0
    }
}

/// Platform HID I/O backend. Linux uses the dependency-free hidraw `File`;
/// macOS/Windows (and Linux under `hidapi-backend`) use hidapi. Exactly one
/// variant exists per build.
enum HidIo {
    #[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
    Hidraw(File),
    #[cfg(any(not(target_os = "linux"), feature = "hidapi-backend"))]
    Hidapi(hidapi::HidDevice),
}

/// An open CTAP HID channel ready to dispatch commands.
pub struct CtapHidDevice {
    io: HidIo,
    channel_id: u32,
    timeout: Duration,
    /// Optional cooperative-cancel flag. Checked in the KEEPALIVE wait loop so a
    /// long user-presence wait (e.g. fingerprint capture) can be aborted from
    /// another thread without unplugging the key.
    cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

impl CtapHidDevice {
    /// Open a HID device by path and allocate a CTAPHID channel.
    pub fn open(path: &Path) -> Result<(Self, InitResponse), HidTransportError> {
        let io = Self::open_io(path)?;
        let mut dev = Self {
            io,
            channel_id: CTAPHID_BROADCAST_CID,
            timeout: DEFAULT_READ_TIMEOUT,
            cancel: None,
        };
        let init = dev.do_init()?;
        dev.channel_id = init.channel_id;
        Ok((dev, init))
    }

    /// Install a cooperative-cancel flag. When set to `true` from another
    /// thread, an in-progress transaction waiting on KEEPALIVE frames returns
    /// [`HidTransportError::Cancelled`] at the next keep-alive (≈ every 100 ms),
    /// instead of blocking until the user acts or the device times out.
    pub fn set_cancel_flag(&mut self, flag: std::sync::Arc<std::sync::atomic::AtomicBool>) {
        self.cancel = Some(flag);
    }

    /// Linux backend: open the `/dev/hidraw*` node read/write, `O_NONBLOCK`
    /// so [`Self::read_report`] can poll with a budget instead of blocking
    /// forever on a silent device (audit KEY-011). hidraw writes do not
    /// consult `O_NONBLOCK` (the kernel issues output reports synchronously),
    /// so `write_all` is unaffected.
    #[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
    fn open_io(path: &Path) -> Result<HidIo, HidTransportError> {
        use std::os::unix::fs::OpenOptionsExt;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(keyroost_hid::O_NONBLOCK)
            .open(path)?;
        Ok(HidIo::Hidraw(file))
    }

    /// hidapi backend (macOS / Windows): open by the platform device path.
    #[cfg(any(not(target_os = "linux"), feature = "hidapi-backend"))]
    fn open_io(path: &Path) -> Result<HidIo, HidTransportError> {
        let api = hidapi::HidApi::new().map_err(|e| HidTransportError::Backend(e.to_string()))?;
        let cpath = std::ffi::CString::new(path.to_string_lossy().as_bytes())
            .map_err(|_| HidTransportError::Backend("device path contained a NUL byte".into()))?;
        let dev = api
            .open_path(&cpath)
            .map_err(|e| HidTransportError::Backend(e.to_string()))?;
        Ok(HidIo::Hidapi(dev))
    }

    /// Write one 65-byte output report (leading 0x00 report ID) to the device.
    fn write_report(&mut self, frame: &[u8]) -> Result<(), HidTransportError> {
        match &mut self.io {
            #[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
            HidIo::Hidraw(f) => f.write_all(frame)?,
            #[cfg(any(not(target_os = "linux"), feature = "hidapi-backend"))]
            HidIo::Hidapi(d) => {
                d.write(frame)
                    .map_err(|e| HidTransportError::Backend(e.to_string()))?;
            }
        }
        Ok(())
    }

    /// Read one 64-byte input report into `buf`.
    ///
    /// Returns `Ok(true)` when a full report was read, `Ok(false)` when the
    /// bounded backend polled with no report available (the caller re-checks
    /// its overall deadline and cancel flag, then retries). The hidapi
    /// backend (macOS/Windows) reads through
    /// [`keyroost_hid::read_report_bounded`]; the Linux hidraw backend reads
    /// through [`keyroost_hid::read_nonblocking_bounded`] against the
    /// `O_NONBLOCK` fd set in `open_io`. Either way a device that goes silent
    /// mid-response cannot block a caller past its deadline (audit KEY-011).
    fn read_report(&mut self, buf: &mut [u8]) -> Result<bool, HidTransportError> {
        match &mut self.io {
            #[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
            HidIo::Hidraw(f) => {
                let n = keyroost_hid::read_nonblocking_bounded(f, buf)?;
                if n == 0 {
                    // Read budget elapsed with no report; let the caller loop.
                    return Ok(false);
                }
                // CTAPHID input reports are a fixed 64 bytes; a short read
                // must not let the zero-filled tail parse as frame content.
                if n != buf.len() {
                    return Err(HidTransportError::Io(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!("short HID read: {} of {} bytes", n, buf.len()),
                    )));
                }
                Ok(true)
            }
            #[cfg(any(not(target_os = "linux"), feature = "hidapi-backend"))]
            HidIo::Hidapi(d) => {
                let n = keyroost_hid::read_report_bounded(d, buf)
                    .map_err(|e| HidTransportError::Backend(e.to_string()))?;
                if n == 0 {
                    // Poll interval elapsed with no report; let the caller loop.
                    return Ok(false);
                }
                // CTAPHID input reports are a fixed 64 bytes; a short read
                // would otherwise let the zero-filled tail be parsed as frame
                // content. (The hidraw path uses read_exact and can't hit this.)
                if n != buf.len() {
                    return Err(HidTransportError::Backend(format!(
                        "short HID read: {} of {} bytes",
                        n,
                        buf.len()
                    )));
                }
                Ok(true)
            }
        }
    }

    pub fn channel_id(&self) -> u32 {
        self.channel_id
    }

    /// Time KEEPALIVE polling considers a transaction abandoned. Plain reads
    /// remain blocking; the timeout only bounds how long we'll loop on
    /// KEEPALIVE frames before bailing.
    pub fn set_timeout(&mut self, t: Duration) {
        self.timeout = t;
    }

    /// The read timeout currently in effect (see [`Self::set_timeout`]).
    pub fn read_timeout(&self) -> Duration {
        self.timeout
    }

    /// Send a CTAPHID command and read the response.
    ///
    /// A device that answers `ERR_CHANNEL_BUSY` is retried transparently under
    /// the budget in `busy_retry_delay`; every other CTAPHID error code is
    /// returned to the caller on the spot. A retry re-enters `send`/`recv`
    /// unchanged — the sensitivity of the exchange is classified once, up
    /// front, so every attempt's trace line is redacted identically, and the
    /// request frame is rebuilt from the caller's borrowed `payload` rather
    /// than held across attempts. `recv` derives its own deadline per call, so
    /// retrying adds bounded attempts rather than extending any one deadline.
    ///
    /// The retry covers command traffic only; channel allocation in `do_init`
    /// is left to fail fast so opening a device can't stall.
    pub fn transact(&mut self, cmd: u8, payload: &[u8]) -> Result<Vec<u8>, HidTransportError> {
        let sensitive = exchange_is_sensitive(cmd, payload);
        let started = Instant::now();
        let mut attempt: u32 = 1;
        loop {
            if ctap_trace_enabled() {
                eprintln!(
                    "CTAP > cmd=0x{cmd:02x} len={} {}",
                    payload.len(),
                    trace_payload(payload, sensitive)
                );
            }
            let outcome = self
                .send(self.channel_id, cmd, payload)
                .and_then(|()| self.recv(self.channel_id, cmd));
            match outcome {
                Ok(resp) => {
                    if ctap_trace_enabled() {
                        eprintln!(
                            "CTAP < len={} {}",
                            resp.len(),
                            trace_payload(&resp, sensitive)
                        );
                    }
                    return Ok(resp);
                }
                Err(HidTransportError::DeviceError(code)) => {
                    let Some(delay) = busy_retry_delay(code, attempt, started.elapsed()) else {
                        return Err(HidTransportError::DeviceError(code));
                    };
                    if ctap_trace_enabled() {
                        // Framing metadata only — no payload, so this line
                        // can't leak what the redacted trace withheld.
                        eprintln!(
                            "CTAP ! cmd=0x{cmd:02x} error=0x{code:02x} busy, retry {attempt} in {}ms",
                            delay.as_millis()
                        );
                    }
                    self.sleep_between_attempts(delay)?;
                    attempt += 1;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Pause between retry attempts without swallowing a cooperative cancel:
    /// the flag is honored on entry and again on wake, so a caller aborting
    /// mid-retry waits at most one delay slice.
    fn sleep_between_attempts(&self, delay: Duration) -> Result<(), HidTransportError> {
        if self.cancel_requested() {
            return Err(HidTransportError::Cancelled);
        }
        std::thread::sleep(delay);
        if self.cancel_requested() {
            return Err(HidTransportError::Cancelled);
        }
        Ok(())
    }

    /// True when a cooperative cancel has been requested (see
    /// [`Self::set_cancel_flag`]); false when no flag was installed.
    fn cancel_requested(&self) -> bool {
        self.cancel
            .as_ref()
            .is_some_and(|f| f.load(std::sync::atomic::Ordering::Relaxed))
    }

    fn do_init(&mut self) -> Result<InitResponse, HidTransportError> {
        let nonce = generate_nonce();
        self.send(CTAPHID_BROADCAST_CID, CTAPHID_INIT, &nonce)?;
        let resp = self.recv(CTAPHID_BROADCAST_CID, CTAPHID_INIT)?;
        if resp.len() < 17 {
            return Err(HidTransportError::InitResponseTooShort);
        }
        if resp[..8] != nonce {
            return Err(HidTransportError::NonceMismatch);
        }
        Ok(InitResponse {
            channel_id: u32::from_be_bytes([resp[8], resp[9], resp[10], resp[11]]),
            protocol_version: resp[12],
            device_major: resp[13],
            device_minor: resp[14],
            device_build: resp[15],
            capabilities: resp[16],
        })
    }

    fn send(&mut self, cid: u32, cmd: u8, payload: &[u8]) -> Result<(), HidTransportError> {
        if payload.len() > CTAPHID_MAX_PAYLOAD {
            return Err(HidTransportError::PayloadTooLarge(payload.len()));
        }
        let cid_be = cid.to_be_bytes();
        let mut frame = [0u8; CTAPHID_REPORT_SIZE + 1];

        // Initialization frame.
        frame[0] = 0x00; // hidraw output report ID
        frame[1..5].copy_from_slice(&cid_be);
        frame[5] = cmd;
        frame[6] = (payload.len() >> 8) as u8;
        frame[7] = (payload.len() & 0xFF) as u8;
        let first_chunk = payload.len().min(INIT_FRAME_DATA);
        frame[8..8 + first_chunk].copy_from_slice(&payload[..first_chunk]);
        self.write_report(&frame)?;

        // Continuation frames.
        let mut offset = first_chunk;
        let mut seq: u8 = 0;
        while offset < payload.len() {
            let chunk = (payload.len() - offset).min(CONT_FRAME_DATA);
            frame.fill(0);
            frame[0] = 0x00;
            frame[1..5].copy_from_slice(&cid_be);
            frame[5] = seq & 0x7F;
            frame[6..6 + chunk].copy_from_slice(&payload[offset..offset + chunk]);
            self.write_report(&frame)?;
            offset += chunk;
            seq = seq.wrapping_add(1);
        }
        Ok(())
    }

    /// One bounded wait step, shared by the initiation- and continuation-frame
    /// loops in `recv` so their retry policy can't drift apart:
    /// - errors when `deadline` has passed — checked on every frame, not just
    ///   KEEPALIVEs, so a misbehaving device spamming foreign-CID frames can't
    ///   spin forever;
    /// - honors a cooperative cancel between reads (not only at KEEPALIVEs),
    ///   so a device that goes silent on the bounded backend — even mid-way
    ///   through a multi-frame response — can still be abandoned promptly;
    /// - otherwise polls one report; `Ok(false)` means no frame yet.
    fn wait_report(
        &mut self,
        deadline: Instant,
        buf: &mut [u8; CTAPHID_REPORT_SIZE],
    ) -> Result<bool, HidTransportError> {
        if Instant::now() >= deadline {
            return Err(HidTransportError::Timeout);
        }
        if self.cancel_requested() {
            return Err(HidTransportError::Cancelled);
        }
        self.read_report(buf)
    }

    fn recv(&mut self, expected_cid: u32, expected_cmd: u8) -> Result<Vec<u8>, HidTransportError> {
        let mut deadline = Instant::now() + self.timeout;
        let mut buf = [0u8; CTAPHID_REPORT_SIZE];

        loop {
            if !self.wait_report(deadline, &mut buf)? {
                continue; // bounded read polled with no frame; re-check deadline
            }
            let cid = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
            let cmd = buf[4];
            if cid != expected_cid {
                continue;
            }
            if cmd == CTAPHID_KEEPALIVE {
                // The device is alive and working — commonly waiting for the user
                // to touch the sensor (e.g. fingerprint enrollment or a user-
                // presence check). This is the point to honour a cooperative
                // cancel: a caller waiting on a touch can abort here without
                // unplugging the key, since KEEPALIVEs arrive ≈ every 100 ms.
                if self.cancel_requested() {
                    return Err(HidTransportError::Cancelled);
                }
                // Push the deadline out so the timeout bounds device *silence*,
                // not how long the user takes to respond.
                deadline = Instant::now() + self.timeout;
                continue;
            }
            if cmd == CTAPHID_ERROR {
                let code = buf.get(7).copied().unwrap_or(0);
                return Err(HidTransportError::DeviceError(code));
            }
            if cmd != expected_cmd {
                return Err(HidTransportError::UnexpectedCommand {
                    expected: expected_cmd,
                    got: cmd,
                });
            }

            let bcnt = u16::from_be_bytes([buf[5], buf[6]]) as usize;
            // The send side enforces this cap; reject device responses that
            // claim more than the spec's maximum message size.
            if bcnt > CTAPHID_MAX_PAYLOAD {
                return Err(HidTransportError::PayloadTooLarge(bcnt));
            }
            let mut payload = Vec::with_capacity(bcnt);
            let take = bcnt.min(INIT_FRAME_DATA);
            payload.extend_from_slice(&buf[INIT_FRAME_HEADER..INIT_FRAME_HEADER + take]);

            let mut seq: u8 = 0;
            while payload.len() < bcnt {
                if !self.wait_report(deadline, &mut buf)? {
                    continue; // bounded read polled with no frame; re-check deadline
                }
                let cid2 = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                if cid2 != expected_cid {
                    continue;
                }
                let s = buf[4];
                if s & 0x80 != 0 {
                    return Err(HidTransportError::UnexpectedCommand {
                        expected: 0x00,
                        got: s,
                    });
                }
                if s != seq {
                    return Err(HidTransportError::OutOfSequence {
                        expected: seq,
                        got: s,
                    });
                }
                let rem = bcnt - payload.len();
                let chunk = rem.min(CONT_FRAME_DATA);
                payload.extend_from_slice(&buf[CONT_FRAME_HEADER..CONT_FRAME_HEADER + chunk]);
                seq = seq.wrapping_add(1);
            }
            return Ok(payload);
        }
    }
}

/// True when `KEYROOST_CTAP_DEBUG` is set, enabling a stderr hex trace of every
/// CTAP-HID transaction. Diagnostics only — never on by default.
fn ctap_trace_enabled() -> bool {
    std::env::var_os("KEYROOST_CTAP_DEBUG").is_some()
}

/// True when a CTAPHID CBOR exchange carries personal data that must be
/// redacted from the opt-in trace — in **both** directions, because requests
/// carry the same material the responses enumerate:
/// - authenticatorCredentialManagement (`0x0A`, preview `0x41`): responses
///   enumerate RP IDs and user names; `updateUserInformation` requests carry
///   the replacement user entity;
/// - authenticatorBioEnrollment (`0x09`, preview `0x40`): responses enumerate
///   fingerprint template friendly names; `setFriendlyName` requests carry
///   the new name — often a person's name;
/// - authenticatorLargeBlobs (`0x0C`): reads return the serialized array,
///   which includes keyroost's own plaintext notes (see
///   `large_blobs::LargeBlobEntry::from_text` — explicitly NOT encryption),
///   and writes carry the same bytes out.
///
/// (PIN material in other commands is ciphertext under the ECDH session key,
/// not recoverable from the trace.) Add every future personal-data-bearing
/// CTAP2 command here, not at the trace call sites.
fn exchange_is_sensitive(cmd: u8, payload: &[u8]) -> bool {
    cmd == CTAPHID_CBOR
        && matches!(
            payload.first(),
            Some(0x0A) | Some(0x41) | Some(0x09) | Some(0x40) | Some(0x0C)
        )
}

/// The payload portion of one trace line: full hex normally, a redaction
/// marker for sensitive exchanges. Framing metadata (direction, command byte,
/// length) stays visible on the caller's side of the line.
fn trace_payload(payload: &[u8], sensitive: bool) -> String {
    if sensitive {
        "<redacted: personal-data payload>".to_owned()
    } else {
        hexline(payload)
    }
}

/// Lowercase hex of a byte slice, for the debug trace.
fn hexline(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Cheap host-only nonce for `CTAPHID_INIT`. Doesn't need to be
/// cryptographic — its only job is to disambiguate concurrent INIT requests
/// from different clients sharing the broadcast channel.
fn generate_nonce() -> [u8; 8] {
    let mut nonce = [0u8; 8];
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0xDEAD_BEEF_CAFE_F00D);
    let pid = std::process::id() as u64;
    nonce.copy_from_slice(&now.rotate_left(13).wrapping_mul(pid | 1).to_be_bytes());
    nonce
}

impl crate::transport::CtapTransport for CtapHidDevice {
    /// Delegate to the inherent HID `transact`, mapping its transport error into
    /// the shared [`crate::cmd::CtapError`]. This is what lets HID and PC/SC backends be used
    /// interchangeably by the command layer.
    fn transact(&mut self, cmd: u8, payload: &[u8]) -> Result<Vec<u8>, crate::cmd::CtapError> {
        CtapHidDevice::transact(self, cmd, payload).map_err(crate::cmd::CtapError::from)
    }

    fn set_timeout(&mut self, timeout: std::time::Duration) {
        CtapHidDevice::set_timeout(self, timeout);
    }

    fn read_timeout(&self) -> std::time::Duration {
        CtapHidDevice::read_timeout(self)
    }

    fn set_cancel_flag(&mut self, flag: std::sync::Arc<std::sync::atomic::AtomicBool>) {
        CtapHidDevice::set_cancel_flag(self, flag);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// KEY-011: a device that accepts a request and then goes silent must be
    /// bounded by the configured deadline, not block in read() forever. A
    /// socketpair end with a mute peer is exactly that fd.
    #[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
    #[test]
    fn recv_times_out_on_a_silent_device_instead_of_blocking() {
        use std::os::unix::net::UnixStream;
        let (a, _b) = UnixStream::pair().unwrap();
        a.set_nonblocking(true).unwrap(); // same fd state open_io now sets
        let file = std::fs::File::from(std::os::fd::OwnedFd::from(a));
        let mut dev = CtapHidDevice {
            io: HidIo::Hidraw(file),
            channel_id: 1,
            timeout: Duration::from_millis(300),
            cancel: None,
        };
        let start = Instant::now();
        let res = dev.recv(1, CTAPHID_CBOR);
        assert!(
            matches!(res, Err(HidTransportError::Timeout)),
            "expected Timeout, got {res:?}"
        );
        // One 500 ms read budget + the 300 ms deadline, with generous slack.
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    /// Every code in the CTAP HID spec's `CTAPHID_ERROR` table must render as
    /// its spec name plus an explanation a non-specialist can act on — a bare
    /// `0x06` told the user nothing.
    #[test]
    fn ctaphid_error_codes_map_to_spec_names_and_explanations() {
        let expected = [
            (0x01u8, "ERR_INVALID_CMD"),
            (0x02, "ERR_INVALID_PAR"),
            (0x03, "ERR_INVALID_LEN"),
            (0x04, "ERR_INVALID_SEQ"),
            (0x05, "ERR_MSG_TIMEOUT"),
            (0x06, "ERR_CHANNEL_BUSY"),
            (0x0A, "ERR_LOCK_REQUIRED"),
            (0x0B, "ERR_INVALID_CHANNEL"),
            (0x7F, "ERR_OTHER"),
        ];
        for (code, name) in expected {
            let (got_name, hint) =
                ctaphid_error_meaning(code).unwrap_or_else(|| panic!("0x{code:02X} unmapped"));
            assert_eq!(got_name, name, "0x{code:02X} spec name");
            assert!(!hint.is_empty(), "0x{code:02X} needs an explanation");
            // The rendered error leads with the explanation and keeps the
            // numeric code + spec name so a bug report stays diagnosable.
            let shown = HidTransportError::DeviceError(code).to_string();
            assert!(shown.starts_with(hint), "0x{code:02X} shows: {shown}");
            assert!(shown.contains(&format!("CTAPHID error 0x{code:02X} {name}")));
        }
    }

    /// Codes outside the spec table keep the old raw-hex rendering rather than
    /// having a meaning invented for them.
    #[test]
    fn unknown_ctaphid_error_codes_fall_back_to_raw_hex() {
        for code in [0x00u8, 0x07, 0x09, 0x0C, 0x42, 0xFF] {
            assert!(ctaphid_error_meaning(code).is_none(), "0x{code:02X}");
            assert_eq!(
                HidTransportError::DeviceError(code).to_string(),
                format!("device reported CTAPHID_ERROR code 0x{code:02X}")
            );
        }
    }

    /// The regression this file exists to fix: a user who hit `0x06` had no way
    /// to know it meant "busy, try again".
    #[test]
    fn channel_busy_explains_itself_to_the_user() {
        let shown = HidTransportError::DeviceError(CTAPHID_ERR_CHANNEL_BUSY).to_string();
        assert_eq!(
            shown,
            "the key's HID channel was busy and stayed busy after retrying \u{2014} \
             close anything else using the key (a browser sign-in prompt, an \
             agent) and try again (CTAPHID error 0x06 ERR_CHANNEL_BUSY)"
        );
    }

    /// Only `ERR_CHANNEL_BUSY` is retryable; the rest of the table reports a
    /// protocol fault where a retry would only delay the error.
    #[test]
    fn only_channel_busy_is_retried() {
        for code in 0u8..=0xFF {
            let decision = busy_retry_delay(code, 1, Duration::ZERO);
            if code == CTAPHID_ERR_CHANNEL_BUSY {
                assert_eq!(decision, Some(CHANNEL_BUSY_RETRY_DELAY));
            } else {
                assert_eq!(decision, None, "0x{code:02X} must not be retried");
            }
        }
    }

    /// The attempt counter bounds the number of re-sends even when every
    /// attempt returns instantly.
    #[test]
    fn busy_retry_is_bounded_by_attempt_count() {
        for attempt in 1..CHANNEL_BUSY_MAX_ATTEMPTS {
            assert_eq!(
                busy_retry_delay(CTAPHID_ERR_CHANNEL_BUSY, attempt, Duration::ZERO),
                Some(CHANNEL_BUSY_RETRY_DELAY),
                "attempt {attempt} should still retry"
            );
        }
        for attempt in [
            CHANNEL_BUSY_MAX_ATTEMPTS,
            CHANNEL_BUSY_MAX_ATTEMPTS + 1,
            1000,
        ] {
            assert_eq!(
                busy_retry_delay(CTAPHID_ERR_CHANNEL_BUSY, attempt, Duration::ZERO),
                None,
                "attempt {attempt} is past the cap"
            );
        }
    }

    /// The wall-clock budget is the backstop for a device that answers busy
    /// slowly: even on the first attempt, no retry is scheduled that would run
    /// past the budget.
    #[test]
    fn busy_retry_is_bounded_by_wall_clock() {
        assert_eq!(
            busy_retry_delay(CTAPHID_ERR_CHANNEL_BUSY, 1, CHANNEL_BUSY_TOTAL_BUDGET),
            None
        );
        assert_eq!(
            busy_retry_delay(
                CTAPHID_ERR_CHANNEL_BUSY,
                1,
                CHANNEL_BUSY_TOTAL_BUDGET - CHANNEL_BUSY_RETRY_DELAY
            ),
            None,
            "a retry that would land exactly on the budget is not scheduled"
        );
        assert!(busy_retry_delay(
            CTAPHID_ERR_CHANNEL_BUSY,
            1,
            CHANNEL_BUSY_TOTAL_BUDGET - CHANNEL_BUSY_RETRY_DELAY - Duration::from_millis(1)
        )
        .is_some());
        // Absurd elapsed values must not overflow the budget comparison.
        assert_eq!(
            busy_retry_delay(CTAPHID_ERR_CHANNEL_BUSY, 1, Duration::MAX),
            None
        );
    }

    /// A device answering busy forever must terminate the loop, by whichever
    /// bound trips first, with the total delay inside the budget.
    #[test]
    fn busy_retry_loop_terminates_against_a_permanently_busy_device() {
        for per_attempt in [
            Duration::ZERO,
            Duration::from_millis(50),
            Duration::from_millis(700),
            Duration::from_secs(5),
        ] {
            let mut elapsed = Duration::ZERO;
            let mut attempt = 1u32;
            let mut slept = Duration::ZERO;
            while let Some(delay) = busy_retry_delay(CTAPHID_ERR_CHANNEL_BUSY, attempt, elapsed) {
                slept += delay;
                elapsed += delay + per_attempt;
                attempt += 1;
                assert!(
                    attempt <= CHANNEL_BUSY_MAX_ATTEMPTS,
                    "loop did not terminate"
                );
            }
            assert!(slept < CHANNEL_BUSY_TOTAL_BUDGET, "slept {slept:?}");
        }
    }

    /// End-to-end over a socketpair standing in for the hidraw node: a device
    /// that answers busy is re-sent to through the ordinary `send`/`recv` path,
    /// and a busy state that clears is invisible to the caller.
    #[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
    #[test]
    fn channel_busy_is_retried_and_a_clearing_device_succeeds() {
        // Two busy answers then a real response: the caller sees only the
        // success, and the device saw three identical requests.
        let (mut dev, mut peer) = paired_device(Duration::from_millis(300));
        queue_frames(
            &mut peer,
            &[
                error_frame(CTAPHID_ERR_CHANNEL_BUSY),
                error_frame(CTAPHID_ERR_CHANNEL_BUSY),
                ok_frame(),
            ],
        );
        let resp = dev.transact(CTAPHID_CBOR, &[0x04]).expect("busy cleared");
        assert_eq!(resp, vec![0x00]);
        assert_eq!(
            sent_requests(&mut peer),
            3,
            "each retry re-sends the request"
        );
    }

    /// A device that answers busy forever surfaces the busy error instead of
    /// looping, and does so within the retry budget.
    #[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
    #[test]
    fn a_permanently_busy_device_surfaces_the_error_within_the_budget() {
        let (mut dev, mut peer) = paired_device(Duration::from_millis(300));
        let busy: Vec<[u8; CTAPHID_REPORT_SIZE]> = (0..CHANNEL_BUSY_MAX_ATTEMPTS + 2)
            .map(|_| error_frame(CTAPHID_ERR_CHANNEL_BUSY))
            .collect();
        queue_frames(&mut peer, &busy);
        let start = Instant::now();
        let res = dev.transact(CTAPHID_CBOR, &[0x04]);
        assert!(
            matches!(
                res,
                Err(HidTransportError::DeviceError(CTAPHID_ERR_CHANNEL_BUSY))
            ),
            "expected the busy error to surface, got {res:?}"
        );
        assert_eq!(
            sent_requests(&mut peer) as u32,
            CHANNEL_BUSY_MAX_ATTEMPTS,
            "retries must stop at the attempt cap"
        );
        assert!(
            start.elapsed() < CHANNEL_BUSY_TOTAL_BUDGET + Duration::from_secs(2),
            "loop overran its budget: {:?}",
            start.elapsed()
        );
    }

    /// Errors other than busy are surfaced on the first attempt — retrying a
    /// protocol fault would only delay the error.
    #[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
    #[test]
    fn other_ctaphid_errors_are_not_retried() {
        for code in [
            CTAPHID_ERR_INVALID_CMD,
            CTAPHID_ERR_INVALID_LEN,
            CTAPHID_ERR_INVALID_CHANNEL,
            CTAPHID_ERR_OTHER,
        ] {
            let (mut dev, mut peer) = paired_device(Duration::from_millis(300));
            queue_frames(&mut peer, &[error_frame(code), ok_frame()]);
            let res = dev.transact(CTAPHID_CBOR, &[0x04]);
            assert!(
                matches!(res, Err(HidTransportError::DeviceError(c)) if c == code),
                "0x{code:02X} should surface immediately, got {res:?}"
            );
            assert_eq!(sent_requests(&mut peer), 1, "0x{code:02X} must not retry");
        }
    }

    /// A `CtapHidDevice` on one end of a socketpair (channel 1) and the raw
    /// peer end the test drives as a make-believe authenticator.
    #[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
    fn paired_device(timeout: Duration) -> (CtapHidDevice, std::os::unix::net::UnixStream) {
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        a.set_nonblocking(true).unwrap(); // same fd state open_io sets
        let file = std::fs::File::from(std::os::fd::OwnedFd::from(a));
        let dev = CtapHidDevice {
            io: HidIo::Hidraw(file),
            channel_id: 1,
            timeout,
            cancel: None,
        };
        (dev, b)
    }

    /// One `CTAPHID_ERROR` initiation frame on channel 1 carrying `code`.
    #[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
    fn error_frame(code: u8) -> [u8; CTAPHID_REPORT_SIZE] {
        let mut f = [0u8; CTAPHID_REPORT_SIZE];
        f[3] = 0x01; // CID = 1
        f[4] = CTAPHID_ERROR;
        f[6] = 0x01; // BCNT = 1
        f[7] = code;
        f
    }

    /// A one-byte `CTAPHID_CBOR` response carrying CTAP2_OK.
    #[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
    fn ok_frame() -> [u8; CTAPHID_REPORT_SIZE] {
        let mut f = [0u8; CTAPHID_REPORT_SIZE];
        f[3] = 0x01;
        f[4] = CTAPHID_CBOR;
        f[6] = 0x01;
        f[7] = 0x00; // CTAP2_OK, empty body
        f
    }

    #[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
    fn queue_frames(
        peer: &mut std::os::unix::net::UnixStream,
        frames: &[[u8; CTAPHID_REPORT_SIZE]],
    ) {
        for frame in frames {
            peer.write_all(frame).unwrap();
        }
    }

    /// How many 65-byte output reports the device wrote to the peer. Every
    /// attempt sends exactly one here (the test payload fits one frame).
    #[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
    fn sent_requests(peer: &mut std::os::unix::net::UnixStream) -> usize {
        use std::io::Read;
        peer.set_nonblocking(true).unwrap();
        let mut seen = 0;
        let mut buf = [0u8; CTAPHID_REPORT_SIZE + 1];
        while let Ok(n) = peer.read(&mut buf) {
            if n == 0 {
                break;
            }
            seen += n;
        }
        seen / (CTAPHID_REPORT_SIZE + 1)
    }

    #[test]
    fn init_response_capability_flags() {
        let cbor_only = InitResponse {
            channel_id: 0x12345678,
            protocol_version: 2,
            device_major: 5,
            device_minor: 4,
            device_build: 0,
            capabilities: CAPABILITY_CBOR | CAPABILITY_WINK,
        };
        assert!(cbor_only.supports_cbor());
        assert!(cbor_only.supports_wink());
        assert!(cbor_only.supports_u2f()); // NMSG bit not set -> U2F supported
    }

    #[test]
    fn init_response_u2f_only_when_nmsg_unset() {
        let u2f_only = InitResponse {
            channel_id: 0x42,
            protocol_version: 2,
            device_major: 1,
            device_minor: 0,
            device_build: 0,
            capabilities: 0, // neither CBOR nor NMSG
        };
        assert!(!u2f_only.supports_cbor());
        assert!(u2f_only.supports_u2f());
    }

    #[test]
    fn init_response_pure_cbor_device_no_u2f() {
        let cbor_only = InitResponse {
            channel_id: 0x42,
            protocol_version: 2,
            device_major: 1,
            device_minor: 0,
            device_build: 0,
            capabilities: CAPABILITY_CBOR | CAPABILITY_NMSG,
        };
        assert!(cbor_only.supports_cbor());
        assert!(!cbor_only.supports_u2f());
    }

    #[test]
    fn nonce_is_nonzero_and_varies() {
        let n1 = generate_nonce();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let n2 = generate_nonce();
        assert_ne!(n1, [0u8; 8]);
        assert_ne!(n1, n2);
    }

    #[test]
    fn trace_redaction_covers_personal_data_commands() {
        // credentialManagement enumerates RP IDs / user names; bioEnrollment
        // enumerates fingerprint template friendly names; largeBlobs carries
        // keyroost's plaintext notes. All (and the vendor-preview forms) must
        // be redacted from the debug trace, in both directions.
        for cbor_cmd in [0x0A, 0x41, 0x09, 0x40, 0x0C] {
            assert!(
                exchange_is_sensitive(CTAPHID_CBOR, &[cbor_cmd]),
                "CBOR cmd 0x{cbor_cmd:02x} must be redacted"
            );
        }
        // getInfo / clientPIN traces stay visible (PIN material is ciphertext).
        assert!(!exchange_is_sensitive(CTAPHID_CBOR, &[0x04]));
        assert!(!exchange_is_sensitive(CTAPHID_CBOR, &[0x06]));
        // Non-CBOR frames (INIT, PING) are never redacted.
        assert!(!exchange_is_sensitive(CTAPHID_INIT, &[0x0A]));
        assert!(!exchange_is_sensitive(CTAPHID_CBOR, &[]));
    }

    #[test]
    fn trace_redacts_sensitive_request_payloads() {
        // KEY-002 residual: the request side of the trace used to hex-dump
        // every payload. A bioEnrollment setFriendlyName request carries a
        // person's name in plaintext CBOR; the trace must show framing only.
        let mut payload = vec![0x09]; // authenticatorBioEnrollment
        payload.extend_from_slice(b"\xa1\x02mAlice Example"); // CBOR text: the name
        let sensitive = exchange_is_sensitive(CTAPHID_CBOR, &payload);
        assert!(sensitive, "bioEnroll requests must be classed sensitive");
        let body = trace_payload(&payload, sensitive);
        assert!(body.contains("redacted"));
        // No hex of the payload (in particular the name bytes) may appear.
        assert!(!body.contains(&hexline(b"Alice")));
    }

    #[test]
    fn trace_redacts_large_blob_exchanges() {
        // authenticatorLargeBlobs (0x0C) reads return the serialized array,
        // which can include keyroost's own PLAINTEXT notes (large_blobs.rs
        // documents from_text as "NOT encryption"); writes carry the same
        // bytes out. Both directions key off the request's command byte.
        let read_req = [0x0C, 0xA1, 0x03, 0x01];
        assert!(exchange_is_sensitive(CTAPHID_CBOR, &read_req));
        // Response bytes are formatted with the request's sensitivity flag.
        let resp = b"\x00KR1\0my recovery note";
        let body = trace_payload(resp, true);
        assert!(body.contains("redacted"));
        assert!(!body.contains(&hexline(b"note")));
    }

    #[test]
    fn trace_shows_hex_for_non_sensitive_commands() {
        // getInfo stays fully visible — the trace must remain useful.
        let payload = [0x04];
        let sensitive = exchange_is_sensitive(CTAPHID_CBOR, &payload);
        assert!(!sensitive);
        assert_eq!(trace_payload(&payload, sensitive), "04");
    }
}
