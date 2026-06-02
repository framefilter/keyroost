//! USB HID enumeration for FIDO / security-key devices.
//!
//! Phase 0 of extending keyroost toward FIDO2/U2F support. This crate
//! enumerates `/dev/hidraw*` device nodes by reading sysfs metadata — no
//! external dependencies, no ioctls, no device-open required. That keeps
//! enumeration root-free and means it works even when the user has not yet
//! installed the udev rules in `udev/70-keyroost-fido.rules`.
//!
//! On non-Linux targets [`enumerate`] returns an empty list. macOS and
//! Windows backends are deferred to a later phase.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// HID usage page assigned to FIDO U2F / CTAP HID by usb.org.
pub const HID_USAGE_PAGE_FIDO: u16 = 0xF1D0;
/// HID usage within the FIDO page used by U2F / CTAP HID authenticators.
pub const HID_USAGE_FIDO_AUTHENTICATOR: u16 = 0x01;

/// Things that can go wrong enumerating HID devices.
#[derive(Debug)]
pub enum HidError {
    /// Underlying filesystem error reading sysfs or `/dev`.
    Io(io::Error),
    /// A sysfs file existed but was structured unexpectedly.
    Parse(&'static str),
}

impl fmt::Display for HidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HidError::Io(e) => write!(f, "HID I/O error: {}", e),
            HidError::Parse(s) => write!(f, "HID parse error: {}", s),
        }
    }
}

impl std::error::Error for HidError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            HidError::Io(e) => Some(e),
            HidError::Parse(_) => None,
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
    /// USB bus number (`busnum`) of the underlying device, if known. Together
    /// with [`Self::usb_address`] this identifies the physical USB device, which
    /// lets a caller match this hidraw node to the same key's CCID reader (whose
    /// PC/SC `CHANNEL_ID` encodes the same bus/address).
    pub usb_bus: Option<u8>,
    /// USB device address (`devnum`) of the underlying device, if known.
    pub usb_address: Option<u8>,
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

/// List all `/dev/hidraw*` devices visible to the current user via sysfs.
///
/// Devices the caller lacks permission to *open* are still returned —
/// enumeration reads sysfs only. Returns an empty list on non-Linux
/// platforms.
pub fn enumerate() -> Result<Vec<HidDevice>, HidError> {
    if !cfg!(target_os = "linux") {
        return Ok(Vec::new());
    }
    let entries = match fs::read_dir("/sys/class/hidraw") {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(HidError::Io(e)),
    };

    let mut devices = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else { continue };
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
    let (serial_number, usb_bus, usb_address) = match usb_device_dir(&sysfs.join("device")) {
        Some(dir) => (
            read_usb_serial(&dir),
            read_sysfs_u8(&dir.join("busnum")),
            read_sysfs_u8(&dir.join("devnum")),
        ),
        None => (None, None, None),
    };

    Ok(HidDevice {
        path: PathBuf::from(format!("/dev/{}", name)),
        vendor_id,
        product_id,
        product_name,
        usage_page,
        usage,
        serial_number,
        usb_bus,
        usb_address,
    })
}

/// Walk up the sysfs tree from a HID device link to the first ancestor carrying
/// an `idVendor` file — that's the backing USB device node. Returns `None` on a
/// non-USB transport (e.g. Bluetooth) or any read error.
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
fn read_usb_serial(usb_dir: &Path) -> Option<String> {
    let serial = fs::read_to_string(usb_dir.join("serial")).ok()?;
    let serial = serial.trim();
    (!serial.is_empty()).then(|| serial.to_string())
}

/// Read a small decimal sysfs attribute (e.g. `busnum`, `devnum`) as a `u8`.
fn read_sysfs_u8(path: &Path) -> Option<u8> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn parse_hex_u16(s: &str) -> Option<u16> {
    // Sysfs HID_ID fields are 8 hex chars wide; only the low 16 bits are the VID/PID.
    let v = u32::from_str_radix(s.trim(), 16).ok()?;
    Some((v & 0xFFFF) as u16)
}

/// Walk a HID report descriptor and return the first
/// `(usage_page, usage)` pair, which describes the device's top-level
/// application collection.
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
            usb_bus: None,
            usb_address: None,
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
            usb_bus: None,
            usb_address: None,
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
