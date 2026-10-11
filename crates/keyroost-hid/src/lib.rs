//! USB HID enumeration for FIDO / security-key devices.
//!
//! On **Linux** this enumerates `/dev/hidraw*` device nodes by reading sysfs
//! metadata — no external dependencies, no ioctls, no device-open required.
//! That keeps enumeration root-free and means it works even when the user has
//! not yet installed the udev rules in `udev/70-keyroost-fido.rules`.
//!
//! On **macOS and Windows** it uses the `hidapi` crate (IOKit / hid.dll),
//! selected automatically off Linux. The `hidapi-backend` feature forces that
//! path on for building/testing the cross-platform backend on Linux too.
//!
//! Each node carries [`UsbDeviceKey`] evidence of which physical USB device it
//! belongs to, when the platform offers it: bus + address from sysfs on Linux,
//! the USB device devnode from the device tree on Windows (see [`devtree`]).
//! macOS reports none.

pub mod devtree;
pub use devtree::{same_usb_device, usb_device_node, UsbDeviceKey};

use std::fmt;
#[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
use std::fs;
use std::io;
#[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
use std::path::Path;
use std::path::PathBuf;

/// HID usage page assigned to FIDO U2F / CTAP HID by usb.org.
pub const HID_USAGE_PAGE_FIDO: u16 = 0xF1D0;
/// HID usage within the FIDO page used by U2F / CTAP HID authenticators.
pub const HID_USAGE_FIDO_AUTHENTICATOR: u16 = 0x01;

/// Things that can go wrong enumerating HID devices.
#[non_exhaustive]
#[derive(Debug)]
pub enum HidError {
    /// Underlying filesystem error reading sysfs or `/dev`.
    Io(io::Error),
    /// A sysfs file existed but was structured unexpectedly.
    Parse(&'static str),
    /// The platform HID backend (hidapi, on macOS/Windows) reported an error.
    Backend(String),
}

impl fmt::Display for HidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HidError::Io(e) => write!(f, "HID I/O error: {}", e),
            HidError::Parse(s) => write!(f, "HID parse error: {}", s),
            HidError::Backend(s) => write!(f, "HID backend error: {}", s),
        }
    }
}

impl std::error::Error for HidError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            HidError::Io(e) => Some(e),
            HidError::Parse(_) | HidError::Backend(_) => None,
        }
    }
}

impl From<io::Error> for HidError {
    fn from(e: io::Error) -> Self {
        HidError::Io(e)
    }
}

/// Metadata for a single connected HID device.
#[derive(Debug, Clone)]
pub struct HidDevice {
    /// `/dev/hidraw*` path the device is exposed under.
    pub path: PathBuf,
    /// USB / Bluetooth vendor ID.
    pub vendor_id: u16,
    /// USB / Bluetooth product ID.
    pub product_id: u16,
    /// Human-readable product string from the kernel's HID name.
    pub product_name: String,
    /// Top-level HID usage page from the report descriptor.
    pub usage_page: u16,
    /// Top-level HID usage from the report descriptor.
    pub usage: u16,
    /// USB device serial number (`iSerialNumber`), if the device exposes one.
    /// SoloKeys / Nitrokey publish a unique serial here; many YubiKeys omit it
    /// (their serial is only reachable via the management applet over CCID).
    pub serial_number: Option<String>,
    /// Which physical USB device this node belongs to, if known: sysfs
    /// `busnum`/`devnum` on Linux (matching the same key's CCID reader, whose
    /// PC/SC `CHANNEL_ID` encodes the same bus/address), or the USB device
    /// devnode on Windows (matching the reader's devnode). `None` on macOS and
    /// whenever the evidence could not be read. Compare with
    /// [`same_usb_device`].
    pub usb_device: Option<UsbDeviceKey>,
}

/// Known USB `(vendor, product, description)` IDs of security keys sitting in
/// bootloader / DFU mode. Such a device enumerates as plain HID with no FIDO
/// usage page and cannot speak CTAP, so it would otherwise silently vanish from
/// FIDO lists. Solo 2 / Nitrokey 3 share the Trussed bootloader (`1209:b000`).
const KNOWN_BOOTLOADERS: &[(u16, u16, &str)] =
    &[(0x1209, 0xb000, "Solo 2 / Nitrokey 3 in bootloader/DFU mode")];

impl HidDevice {
    /// True when the device advertises the FIDO usage page (`0xF1D0`).
    pub fn is_fido(&self) -> bool {
        self.usage_page == HID_USAGE_PAGE_FIDO
    }

    /// If this device is a recognized security key in bootloader / DFU mode,
    /// returns a human-readable description. Such a device can't speak FIDO/CTAP
    /// until it's returned to application mode (typically by re-plugging), so
    /// callers can message this clearly instead of hanging on a CTAPHID INIT or
    /// reporting "no FIDO devices" with no explanation.
    pub fn bootloader_label(&self) -> Option<&'static str> {
        KNOWN_BOOTLOADERS
            .iter()
            .find(|(vid, pid, _)| *vid == self.vendor_id && *pid == self.product_id)
            .map(|(_, _, label)| *label)
    }
}

/// Scan all connected HID devices for any recognized security key in
/// bootloader / DFU mode, returning the first match's description. A front-end
/// that finds no FIDO devices can call this to explain why (e.g. a Solo 2 stuck
/// in DFU) rather than just reporting an empty list.
pub fn bootloader_device_present() -> Option<&'static str> {
    enumerate()
        .ok()?
        .iter()
        .find_map(HidDevice::bootloader_label)
}

/// Whether this platform has a HID backend: Linux (sysfs), macOS (IOKit via
/// hidapi), and Windows (hid.dll via hidapi). When `false`, [`enumerate`]
/// returns an empty list and FIDO/CTAP is unavailable — front-ends should say
/// so explicitly rather than reporting "no FIDO devices", which would imply none
/// are plugged in.
#[must_use]
pub fn hid_supported() -> bool {
    cfg!(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows"
    ))
}

/// List all `/dev/hidraw*` devices visible to the current user via sysfs.
///
/// Devices the caller lacks permission to *open* are still returned —
/// enumeration reads sysfs only. Returns an empty list on platforms without a
/// HID backend (see [`hid_supported`]).
pub fn enumerate() -> Result<Vec<HidDevice>, HidError> {
    // Linux uses the dependency-free sysfs backend; macOS/Windows use hidapi.
    // The `hidapi-backend` feature forces hidapi on (for building/testing the
    // cross-platform path on Linux too).
    #[cfg(any(not(target_os = "linux"), feature = "hidapi-backend"))]
    {
        enumerate_hidapi()
    }
    #[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
    {
        enumerate_sysfs()
    }
}

/// hidapi-backed enumeration for macOS / Windows (and Linux under the
/// `hidapi-backend` feature). hidapi exposes no USB topology, so on Windows the
/// USB device devnode is read from the device tree (never opening the device;
/// see [`devtree`]); elsewhere it is left `None` and the HID↔CCID correlation
/// degrades gracefully to serial/identity matching.
#[cfg(any(not(target_os = "linux"), feature = "hidapi-backend"))]
fn enumerate_hidapi() -> Result<Vec<HidDevice>, HidError> {
    let api = hidapi::HidApi::new().map_err(|e| HidError::Backend(e.to_string()))?;
    let mut devices: Vec<HidDevice> = api
        .device_list()
        .map(|info| HidDevice {
            path: PathBuf::from(info.path().to_string_lossy().into_owned()),
            vendor_id: info.vendor_id(),
            product_id: info.product_id(),
            product_name: info.product_string().unwrap_or_default().to_string(),
            usage_page: info.usage_page(),
            usage: info.usage(),
            serial_number: info.serial_number().map(str::to_owned),
            usb_device: None,
        })
        .collect();
    #[cfg(windows)]
    for d in &mut devices {
        let path = d.path.to_string_lossy().into_owned();
        let chain = keyroost_windevtree::hid_path_chain(&path);
        let trace = devtree::devtree_trace_enabled() && d.is_fido();
        d.usb_device =
            devtree::win_node_from_chain(&format!("hid {path}"), chain.as_deref(), trace);
    }
    devices.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(devices)
}

/// Poll interval, in milliseconds, for bounded reads on the hidapi backend —
/// see [`read_report_bounded`], the one place that uses it.
#[cfg(any(not(target_os = "linux"), feature = "hidapi-backend"))]
pub const READ_POLL_MS: i32 = 500;

/// One bounded input-report read against a hidapi device.
///
/// hidapi reads are blocking by default, so a device that goes silent
/// mid-response would hang its caller forever. Every keyroost transport that
/// reads HID reports through hidapi (the CTAP-HID transport in `keyroost-ctap`
/// and the Token2 OTP transport in `keyroost-transport`) reads through this
/// helper instead: it blocks at most [`READ_POLL_MS`], returning `Ok(0)` when
/// the interval elapsed with no report — callers loop on that, re-checking
/// their overall deadline and cancel flag — and `Ok(n)` when a report of `n`
/// bytes arrived (`buf` is zeroed first so no stale tail survives a short
/// read). A report that has already arrived returns immediately, so the poll
/// adds no meaningful latency to a normal transaction; 500 ms keeps a
/// cooperative cancel responsive.
///
/// This helper exists so the poll interval, the `0 = poll expired` contract,
/// and this caveat live in exactly one place. Two policies deliberately stay
/// with the callers:
/// - **Short reads**: CTAP-HID input reports are a fixed 64 bytes, so
///   `keyroost-ctap` rejects `n != buf.len()`; the Token2 OTP framing
///   tolerates a short frame and hands `buf[..n]` to its reassembler.
/// - **Linux hidraw**: the dependency-free production backend on Linux reads
///   `/dev/hidrawN` through [`read_nonblocking_bounded`], the `O_NONBLOCK`
///   counterpart of this helper with the same `0 = no report yet` contract;
///   this helper governs macOS/Windows (and Linux under the testing-oriented
///   `hidapi-backend` feature).
#[cfg(any(not(target_os = "linux"), feature = "hidapi-backend"))]
pub fn read_report_bounded(
    dev: &hidapi::HidDevice,
    buf: &mut [u8],
) -> Result<usize, hidapi::HidError> {
    buf.fill(0);
    dev.read_timeout(buf, READ_POLL_MS)
}

/// `O_NONBLOCK`, hand-defined because std exposes no fcntl constants and this
/// crate's Linux backend is deliberately dependency-free (`libc` would be a
/// new direct dependency, and `poll(2)` would need `unsafe`, which the
/// workspace forbids). `0o4000` is the value on every Linux target keyroost
/// ships (x86_64, aarch64, armv7, riscv64, ppc64le, s390x); it differs only
/// on mips/sparc/alpha/hppa, which are not supported targets.
#[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
pub const O_NONBLOCK: i32 = 0o4000;

/// How long one bounded hidraw read waits before reporting "no report yet"
/// (`Ok(0)`). Mirrors the hidapi backend's `READ_POLL_MS` (500 ms) so
/// deadline/cancel responsiveness is the same on every platform.
#[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
pub const HIDRAW_READ_BUDGET: std::time::Duration = std::time::Duration::from_millis(500);

/// Sleep between attempts inside [`read_nonblocking_bounded`]'s poll loop —
/// short enough to add no perceptible latency to a real response, long enough
/// not to spin the CPU while waiting.
#[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
const NONBLOCK_POLL_SLEEP: std::time::Duration = std::time::Duration::from_millis(5);

/// One bounded input-report read against an `O_NONBLOCK` hidraw `File` — the
/// Linux counterpart of the hidapi-backend `read_report_bounded` (audit
/// KEY-011: the deadline
/// must bound device *silence*, not just the frame count).
///
/// Same contract as the hidapi helper: `Ok(n)` when a report of `n` bytes
/// arrived, `Ok(0)` when [`HIDRAW_READ_BUDGET`] elapsed with no report —
/// callers loop on `Ok(0)`, re-checking their overall deadline and cancel
/// flag. `buf` is zeroed first so no stale tail survives a short read.
///
/// The fd **must** have been opened with [`O_NONBLOCK`] (via
/// `OpenOptions::custom_flags`); on a blocking fd this degenerates to the old
/// unbounded read. A `read` of 0 bytes (EOF — the device node vanished
/// mid-wait) is also reported as `Ok(0)` after the budget, so callers resolve
/// it at their overall deadline instead of spinning. Generic over `Read` so
/// tests can drive it with a nonblocking socket instead of real hardware.
#[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
pub fn read_nonblocking_bounded<F: std::io::Read>(f: &mut F, buf: &mut [u8]) -> io::Result<usize> {
    buf.fill(0);
    let deadline = std::time::Instant::now() + HIDRAW_READ_BUDGET;
    loop {
        match f.read(buf) {
            Ok(0) => {} // EOF/unplug: treat as silence; bounded below
            Ok(n) => return Ok(n),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e),
        }
        if std::time::Instant::now() >= deadline {
            return Ok(0);
        }
        std::thread::sleep(NONBLOCK_POLL_SLEEP);
    }
}

/// Dependency-free Linux backend: enumerate `/dev/hidraw*` via sysfs metadata.
#[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
fn enumerate_sysfs() -> Result<Vec<HidDevice>, HidError> {
    let entries = match fs::read_dir("/sys/class/hidraw") {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(HidError::Io(e)),
    };

    let mut devices = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if !name_str.starts_with("hidraw") {
            continue;
        }
        if let Ok(dev) = read_one(name_str, &entry.path()) {
            devices.push(dev);
        }
    }
    devices.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(devices)
}

#[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
fn read_one(name: &str, sysfs: &Path) -> Result<HidDevice, HidError> {
    let uevent = fs::read_to_string(sysfs.join("device/uevent"))?;
    let mut vendor_id: u16 = 0;
    let mut product_id: u16 = 0;
    let mut product_name = String::new();
    for line in uevent.lines() {
        if let Some(rest) = line.strip_prefix("HID_ID=") {
            let parts: Vec<&str> = rest.split(':').collect();
            if parts.len() != 3 {
                return Err(HidError::Parse("HID_ID format"));
            }
            vendor_id = parse_hex_u16(parts[1]).ok_or(HidError::Parse("HID_ID vendor"))?;
            product_id = parse_hex_u16(parts[2]).ok_or(HidError::Parse("HID_ID product"))?;
        } else if let Some(rest) = line.strip_prefix("HID_NAME=") {
            product_name = rest.to_string();
        }
    }

    let report_desc = fs::read(sysfs.join("device/report_descriptor")).unwrap_or_default();
    let (usage_page, usage) = parse_top_usage(&report_desc).unwrap_or((0, 0));

    // Locate the backing USB device node once and read its serial + topology.
    let (serial_number, usb_device) = match usb_device_dir(&sysfs.join("device")) {
        Some(dir) => (
            read_usb_serial(&dir),
            UsbDeviceKey::from_bus_addr(
                read_sysfs_u8(&dir.join("busnum")),
                read_sysfs_u8(&dir.join("devnum")),
            ),
        ),
        None => (None, None),
    };

    Ok(HidDevice {
        path: PathBuf::from(format!("/dev/{}", name)),
        vendor_id,
        product_id,
        product_name,
        usage_page,
        usage,
        serial_number,
        usb_device,
    })
}

/// Walk up the sysfs tree from a HID device link to the first ancestor carrying
/// an `idVendor` file — that's the backing USB device node. Returns `None` on a
/// non-USB transport (e.g. Bluetooth) or any read error.
#[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
fn usb_device_dir(device_link: &Path) -> Option<PathBuf> {
    let mut dir = fs::canonicalize(device_link).ok()?;
    loop {
        if dir.join("idVendor").exists() {
            return Some(dir);
        }
        dir = dir.parent()?.to_path_buf();
    }
}

/// Read the USB device serial (`iSerialNumber`) from a USB device node.
/// Returns `None` when the descriptor carries no serial (many YubiKeys) or the
/// attribute can't be read.
#[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
fn read_usb_serial(usb_dir: &Path) -> Option<String> {
    let serial = fs::read_to_string(usb_dir.join("serial")).ok()?;
    let serial = serial.trim();
    (!serial.is_empty()).then(|| serial.to_string())
}

/// Read a small decimal sysfs attribute (e.g. `busnum`, `devnum`) as a `u8`.
#[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
fn read_sysfs_u8(path: &Path) -> Option<u8> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

// Used by the sysfs backend and the tests; dead on the hidapi-only build.
#[cfg_attr(
    any(not(target_os = "linux"), feature = "hidapi-backend"),
    allow(dead_code)
)]
fn parse_hex_u16(s: &str) -> Option<u16> {
    // Sysfs HID_ID fields are 8 hex chars wide; only the low 16 bits are the VID/PID.
    let v = u32::from_str_radix(s.trim(), 16).ok()?;
    Some((v & 0xFFFF) as u16)
}

/// Walk a HID report descriptor and return the first
/// `(usage_page, usage)` pair, which describes the device's top-level
/// application collection.
// Used by the sysfs backend and the tests; dead on the hidapi-only build.
#[cfg_attr(
    any(not(target_os = "linux"), feature = "hidapi-backend"),
    allow(dead_code)
)]
fn parse_top_usage(desc: &[u8]) -> Option<(u16, u16)> {
    let mut i = 0;
    let mut usage_page: Option<u16> = None;

    while i < desc.len() {
        let prefix = desc[i];
        // Long items (rare): prefix 0xFE, then bSize, bTag, data.
        if prefix == 0xFE {
            if i + 1 >= desc.len() {
                break;
            }
            let size = desc[i + 1] as usize;
            i = i.saturating_add(3).saturating_add(size);
            continue;
        }
        let size = match prefix & 0b11 {
            0 => 0,
            1 => 1,
            2 => 2,
            3 => 4,
            _ => 0,
        };
        let typ = (prefix >> 2) & 0b11;
        let tag = (prefix >> 4) & 0xF;

        if i + 1 + size > desc.len() {
            break;
        }
        let data = &desc[i + 1..i + 1 + size];
        let value: u32 = match size {
            0 => 0,
            1 => data[0] as u32,
            2 => u16::from_le_bytes([data[0], data[1]]) as u32,
            4 => u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            _ => 0,
        };

        // typ=1 (Global), tag=0 → Usage Page
        if typ == 1 && tag == 0 {
            usage_page = Some((value & 0xFFFF) as u16);
        }
        // typ=2 (Local), tag=0 → Usage
        if typ == 2 && tag == 0 {
            if let Some(page) = usage_page {
                return Some((page, (value & 0xFFFF) as u16));
            }
        }

        i += 1 + size;
    }

    usage_page.map(|p| (p, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hid_id_field_parses_8_char_hex() {
        assert_eq!(parse_hex_u16("00001050"), Some(0x1050));
        assert_eq!(parse_hex_u16("00000407"), Some(0x0407));
        assert_eq!(parse_hex_u16("1050"), Some(0x1050));
        assert!(parse_hex_u16("xyz").is_none());
    }

    #[test]
    fn fido_descriptor_yields_f1d0_01() {
        // Usage Page (FIDO 0xF1D0); Usage (Authenticator 0x01); Collection (App)
        let desc = [0x06, 0xD0, 0xF1, 0x09, 0x01, 0xA1, 0x01];
        let (page, usage) = parse_top_usage(&desc).expect("usage pair present");
        assert_eq!(page, 0xF1D0);
        assert_eq!(usage, 0x01);
    }

    #[test]
    fn keyboard_descriptor_yields_generic_desktop_keyboard() {
        // Usage Page (Generic Desktop 0x01); Usage (Keyboard 0x06)
        let desc = [0x05, 0x01, 0x09, 0x06];
        let (page, usage) = parse_top_usage(&desc).expect("usage pair present");
        assert_eq!(page, 0x01);
        assert_eq!(usage, 0x06);
    }

    #[test]
    fn empty_descriptor_yields_none() {
        assert!(parse_top_usage(&[]).is_none());
    }

    #[test]
    fn fido_helper_only_matches_fido_page() {
        let fido = HidDevice {
            path: PathBuf::from("/dev/hidraw0"),
            vendor_id: 0x1050,
            product_id: 0x0407,
            product_name: "YubiKey".into(),
            usage_page: HID_USAGE_PAGE_FIDO,
            usage: HID_USAGE_FIDO_AUTHENTICATOR,
            serial_number: None,
            usb_device: None,
        };
        let kbd = HidDevice {
            usage_page: 0x01,
            ..fido.clone()
        };
        assert!(fido.is_fido());
        assert!(!kbd.is_fido());
    }

    #[test]
    fn bootloader_label_matches_known_dfu_id() {
        let fido = HidDevice {
            path: PathBuf::from("/dev/hidraw0"),
            vendor_id: 0x1050,
            product_id: 0x0407,
            product_name: "YubiKey".into(),
            usage_page: HID_USAGE_PAGE_FIDO,
            usage: HID_USAGE_FIDO_AUTHENTICATOR,
            serial_number: None,
            usb_device: None,
        };
        // A normal FIDO key is not a bootloader.
        assert!(fido.bootloader_label().is_none());
        // Solo 2 / Nitrokey 3 in DFU mode (1209:b000) is recognized.
        let dfu = HidDevice {
            vendor_id: 0x1209,
            product_id: 0xb000,
            usage_page: 0x01,
            ..fido
        };
        assert!(dfu.bootloader_label().is_some());
    }
}

#[cfg(all(test, target_os = "linux", not(feature = "hidapi-backend")))]
mod nonblocking_read_tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::time::Instant;

    #[test]
    fn silent_fd_returns_zero_within_the_budget() {
        // A connected socket with a peer that never writes is a genuinely
        // silent fd — the exact shape of a device that accepts a request and
        // then says nothing (KEY-011).
        let (mut a, _b) = UnixStream::pair().unwrap();
        a.set_nonblocking(true).unwrap();
        let mut buf = [0u8; 64];
        let start = Instant::now();
        let n = read_nonblocking_bounded(&mut a, &mut buf).unwrap();
        assert_eq!(n, 0, "a silent fd must poll out, not block");
        let elapsed = start.elapsed();
        assert!(elapsed >= HIDRAW_READ_BUDGET, "returned early: {elapsed:?}");
        assert!(
            elapsed < HIDRAW_READ_BUDGET * 4,
            "took far longer than the budget: {elapsed:?}"
        );
    }

    #[test]
    fn available_data_is_returned_immediately() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        a.set_nonblocking(true).unwrap();
        b.write_all(&[0x42; 8]).unwrap();
        let mut buf = [0u8; 64];
        let start = Instant::now();
        let n = read_nonblocking_bounded(&mut a, &mut buf).unwrap();
        assert_eq!(n, 8);
        assert_eq!(&buf[..8], &[0x42; 8]);
        assert!(start.elapsed() < HIDRAW_READ_BUDGET);
    }
}
