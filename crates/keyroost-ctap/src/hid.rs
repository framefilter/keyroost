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
//! Reads are blocking — the kernel hidraw driver does not surface a timeout
//! on read(), and we deliberately avoid `unsafe` (workspace lints forbid it)
//! so we cannot set O_NONBLOCK + poll() without taking an extra dep. In
//! practice CTAP authenticators respond within milliseconds or send periodic
//! KEEPALIVE frames, so a true hang only happens for an unplugged or broken
//! device.

#[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
use std::fs::{File, OpenOptions};
use std::io;
#[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
use std::io::{Read, Write};
use std::path::Path;
use std::time::{Duration, Instant};

/// Broadcast channel ID used for the initial `CTAPHID_INIT` request.
pub const CTAPHID_BROADCAST_CID: u32 = 0xFFFF_FFFF;
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

/// Capability flags reported in byte 16 of the INIT response.
pub const CAPABILITY_WINK: u8 = 0x01;
pub const CAPABILITY_CBOR: u8 = 0x04;
pub const CAPABILITY_NMSG: u8 = 0x08;

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
            HidTransportError::DeviceError(c) => {
                write!(f, "device reported CTAPHID_ERROR code 0x{:02X}", c)
            }
            HidTransportError::NonceMismatch => {
                write!(f, "CTAPHID_INIT response carried the wrong nonce")
            }
            HidTransportError::Backend(s) => write!(f, "HID backend error: {}", s),
        }
    }
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
}

impl CtapHidDevice {
    /// Open a HID device by path and allocate a CTAPHID channel.
    pub fn open(path: &Path) -> Result<(Self, InitResponse), HidTransportError> {
        let io = Self::open_io(path)?;
        let mut dev = Self {
            io,
            channel_id: CTAPHID_BROADCAST_CID,
            timeout: Duration::from_secs(2),
        };
        let init = dev.do_init()?;
        dev.channel_id = init.channel_id;
        Ok((dev, init))
    }

    /// Linux backend: open the `/dev/hidraw*` node read/write.
    #[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
    fn open_io(path: &Path) -> Result<HidIo, HidTransportError> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
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
    fn read_report(&mut self, buf: &mut [u8]) -> Result<(), HidTransportError> {
        match &mut self.io {
            #[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
            HidIo::Hidraw(f) => f.read_exact(buf)?,
            #[cfg(any(not(target_os = "linux"), feature = "hidapi-backend"))]
            HidIo::Hidapi(d) => {
                buf.fill(0);
                let n = d
                    .read(buf)
                    .map_err(|e| HidTransportError::Backend(e.to_string()))?;
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
            }
        }
        Ok(())
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

    /// Send a CTAPHID command and read the response.
    pub fn transact(&mut self, cmd: u8, payload: &[u8]) -> Result<Vec<u8>, HidTransportError> {
        if ctap_trace_enabled() {
            eprintln!(
                "CTAP > cmd=0x{cmd:02x} len={} {}",
                payload.len(),
                hexline(payload)
            );
        }
        self.send(self.channel_id, cmd, payload)?;
        let resp = self.recv(self.channel_id, cmd)?;
        if ctap_trace_enabled() {
            eprintln!("CTAP < len={} {}", resp.len(), hexline(&resp));
        }
        Ok(resp)
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

    fn recv(&mut self, expected_cid: u32, expected_cmd: u8) -> Result<Vec<u8>, HidTransportError> {
        let mut deadline = Instant::now() + self.timeout;
        let mut buf = [0u8; CTAPHID_REPORT_SIZE];

        loop {
            // Check the deadline on every frame, not just KEEPALIVEs: a
            // misbehaving device spamming foreign-CID frames would otherwise
            // spin here forever.
            if Instant::now() >= deadline {
                return Err(HidTransportError::Timeout);
            }
            self.read_report(&mut buf)?;
            let cid = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
            let cmd = buf[4];
            if cid != expected_cid {
                continue;
            }
            if cmd == CTAPHID_KEEPALIVE {
                // The device is alive and working — commonly waiting for the user
                // to touch the sensor (e.g. fingerprint enrollment or a user-
                // presence check). Push the deadline out so the timeout bounds
                // device *silence*, not how long the user takes to respond.
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
                if Instant::now() >= deadline {
                    return Err(HidTransportError::Timeout);
                }
                self.read_report(&mut buf)?;
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
