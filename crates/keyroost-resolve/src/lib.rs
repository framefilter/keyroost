//! Shared security-key identity resolution.
//!
//! Bridges raw device enumeration ([`keyroost_hid`]) and the friendly-name
//! registry ([`keyroost_keyring`]) into one place, so the CLI (`keyroostctl`) and the
//! GUI (`keyroost`) are thin front-ends over a single resolver rather than each
//! re-implementing serial computation.
//!
//! The key job is computing a device's *effective serial*: the USB
//! `iSerialNumber` when present, else a serial read over CCID for YubiKeys
//! (which expose none). YubiKeys are matched to their CCID reader by USB
//! topology so two connected YubiKeys are never confused — see
//! [`ccid_serial_for`].

use keyroost_hid::HidDevice;
use keyroost_keyring::{ConnectedKey, IdSource};
use keyroost_transport::YubiKeyCcid;

pub mod device;
pub use device::{
    correlate, enumerate, exclude_unresettable_piv, factory_reset_plan, CapState, Caps, Device,
    DeviceId, DeviceKind, ResetStep, StepOutcome, StepReport, PIV_GLOBAL_RESET_LABEL,
};

/// USB vendor ID for Yubico keys, which expose no USB `iSerialNumber`.
pub const VID_YUBICO: u16 = 0x1050;

/// True when a device has no USB serial but is a YubiKey, so its serial must be
/// read over CCID instead.
pub fn needs_ccid_serial(d: &HidDevice) -> bool {
    d.serial_number.is_none() && d.vendor_id == VID_YUBICO
}

/// Effective serial for each device (USB serial, else a CCID-read YubiKey
/// serial), parallel to `devices`. The CCID readers are enumerated once, and
/// only if at least one device needs them — so a setup without YubiKeys never
/// touches PC/SC.
pub fn effective_serials(devices: &[HidDevice]) -> Vec<Option<String>> {
    let ccid = ccid_readers_if_needed(devices);
    let refs: Vec<&HidDevice> = devices.iter().collect();
    devices
        .iter()
        .zip(ccid_serials_for(&refs, &ccid))
        .map(|(d, s)| d.serial_number.clone().or(s))
        .collect()
}

/// CCID-read serials for a whole HID set at once, parallel to `devices` (`None`
/// where the node needs no CCID serial, or where none can be attributed safely).
///
/// Beyond what [`ccid_serial_for`] decides per node, this refuses the
/// single-reader fallback whenever *several* topology-free nodes could each be
/// that reader's owner. One reader belongs to exactly one physical key, so
/// handing its serial to more than one row makes two keys report the same
/// identity — and a caller that re-checks the serial to confirm it is talking to
/// the key the user chose would then accept the wrong one.
pub fn ccid_serials_for(devices: &[&HidDevice], readers: &[YubiKeyCcid]) -> Vec<Option<String>> {
    // Serials proven to belong to a node by exact USB topology. Those readers
    // are spoken for, so they are not available to a topology-free guess.
    let taken: Vec<String> = devices
        .iter()
        .filter(|d| d.usb_bus.is_some())
        .filter_map(|d| ccid_serial_for(d, readers))
        .collect();
    // With no topology on either side, every such node is an equally good owner
    // of the one reader, so more than one claimant means nobody may take it.
    let claimants = devices
        .iter()
        .filter(|d| needs_ccid_serial(d) && d.usb_bus.is_none())
        .count();
    devices
        .iter()
        .map(|d| {
            let serial = ccid_serial_for(d, readers);
            let contended = claimants > 1 || serial.as_ref().is_some_and(|s| taken.contains(s));
            if d.usb_bus.is_none() && contended {
                return None;
            }
            serial
        })
        .collect()
}

/// Map enumerated HID devices into the keyring resolver's view, filling in a
/// CCID-read serial for YubiKeys that expose no USB serial.
pub fn connected_keys(devices: &[HidDevice]) -> Vec<ConnectedKey> {
    devices
        .iter()
        .zip(effective_serials(devices))
        .map(|(d, serial)| ConnectedKey {
            path: d.path.clone(),
            serial,
            label: d.product_name.clone(),
        })
        .collect()
}

/// Read YubiKey CCID serials once, but only if some device actually needs one.
/// PC/SC failures (e.g. pcscd down) degrade to an empty list rather than erroring
/// — a missing CCID serial just means that key can't be matched, which is safe.
pub fn ccid_readers_if_needed(devices: &[HidDevice]) -> Vec<YubiKeyCcid> {
    if devices.iter().any(needs_ccid_serial) {
        keyroost_transport::yubikey_ccid_serials().unwrap_or_default()
    } else {
        Vec::new()
    }
}

/// Match a YubiKey HID device to one of the CCID-read serials. Prefers an exact
/// USB-topology match (bus + address), so two connected YubiKeys are never
/// confused; falls back to the unambiguous single-reader case only when the HID
/// node reports no topology at all. Never guesses among several readers —
/// returns `None` instead, which is the safe outcome.
///
/// This single-node view cannot see that *another* topology-free node is an
/// equally good owner of the one reader; callers holding the whole HID set
/// should use [`ccid_serials_for`], which additionally refuses that fallback
/// when it is contended.
pub fn ccid_serial_for(d: &HidDevice, readers: &[YubiKeyCcid]) -> Option<String> {
    if !needs_ccid_serial(d) {
        return None;
    }
    let with_serial: Vec<&YubiKeyCcid> = readers.iter().filter(|r| r.serial.is_some()).collect();
    if let (Some(bus), Some(addr)) = (d.usb_bus, d.usb_address) {
        if let Some(r) = with_serial
            .iter()
            .find(|r| r.usb_bus == Some(bus) && r.usb_address == Some(addr))
        {
            return r.serial.clone();
        }
    }
    // A node that reported its own bus/address and still matched nothing has
    // positive evidence it is a *different* physical device, so the
    // single-reader fallback would hand it another key's serial. Only backends
    // that report no topology whatsoever (usb_bus is None — hidapi on Windows
    // and macOS) may take that fallback, or correlation breaks there entirely.
    if d.usb_bus.is_some() {
        return None;
    }
    match with_serial.as_slice() {
        [only] => only.serial.clone(),
        _ => None,
    }
}

/// The effective serial + its source for a single device, reading the YubiKey
/// CCID serial on demand. Used when naming one chosen device, where a clear
/// error is wanted if a YubiKey serial can't be read. The `Err` is a
/// ready-to-display message (front-ends convert it into their own error type).
pub fn read_effective_serial(d: &HidDevice) -> Result<(String, IdSource), String> {
    if let Some(s) = &d.serial_number {
        return Ok((s.clone(), IdSource::Usb));
    }
    if d.vendor_id == VID_YUBICO {
        let readers = keyroost_transport::yubikey_ccid_serials().map_err(|e| e.to_string())?;
        if let Some(s) = ccid_serial_for(d, &readers) {
            return Ok((s, IdSource::Ccid));
        }
        return Err(format!(
            "{} ({}) is a YubiKey, but its serial couldn't be read over CCID. \
             Check that the smart-card (PC/SC) service is running and that this key's CCID reader is \
             present (`keyroostctl list` shows connected readers).",
            d.path.display(),
            d.product_name
        ));
    }
    Err(format!(
        "{} ({}) exposes no USB serial, so it can't be named yet.",
        d.path.display(),
        d.product_name
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyroost_hid::{HID_USAGE_FIDO_AUTHENTICATOR, HID_USAGE_PAGE_FIDO};

    fn yubikey(path: &str, bus: Option<u8>, addr: Option<u8>) -> HidDevice {
        HidDevice {
            path: path.into(),
            vendor_id: VID_YUBICO,
            product_id: 0x0407,
            product_name: "YubiKey".into(),
            usage_page: HID_USAGE_PAGE_FIDO,
            usage: HID_USAGE_FIDO_AUTHENTICATOR,
            serial_number: None,
            usb_bus: bus,
            usb_address: addr,
        }
    }

    fn reader(bus: Option<u8>, addr: Option<u8>, serial: &str) -> YubiKeyCcid {
        YubiKeyCcid {
            reader_name: "Yubico YubiKey OTP+FIDO+CCID".into(),
            usb_bus: bus,
            usb_address: addr,
            serial: Some(serial.into()),
        }
    }

    #[test]
    fn topology_match_disambiguates_two_yubikeys() {
        let readers = [
            reader(Some(9), Some(53), "37806840"),
            reader(Some(9), Some(54), "27717893"),
        ];
        let a = yubikey("/dev/hidraw16", Some(9), Some(53));
        let b = yubikey("/dev/hidraw18", Some(9), Some(54));
        assert_eq!(ccid_serial_for(&a, &readers).as_deref(), Some("37806840"));
        assert_eq!(ccid_serial_for(&b, &readers).as_deref(), Some("27717893"));
    }

    #[test]
    fn single_reader_is_used_without_topology() {
        let readers = [reader(None, None, "37806840")];
        let d = yubikey("/dev/hidraw16", None, None);
        assert_eq!(ccid_serial_for(&d, &readers).as_deref(), Some("37806840"));
    }

    #[test]
    fn never_guesses_among_several_when_topology_unknown() {
        // Two readers, no usable topology on either side: refuse rather than
        // risk targeting the wrong physical key.
        let readers = [
            reader(None, None, "37806840"),
            reader(None, None, "27717893"),
        ];
        let d = yubikey("/dev/hidraw16", None, None);
        assert_eq!(ccid_serial_for(&d, &readers), None);
    }

    #[test]
    fn reported_topology_that_matches_nothing_never_falls_back() {
        // A FIDO-only YubiKey sitting next to a *different* key's reader: the HID
        // node reports its own bus/address and matches none of them, which is
        // positive evidence they are different devices. Taking the single-reader
        // fallback here would stamp the other key's serial onto this one.
        let readers = [reader(Some(9), Some(53), "37806840")];
        let d = yubikey("/dev/hidraw20", Some(9), Some(60));
        assert_eq!(ccid_serial_for(&d, &readers), None);
    }

    #[test]
    fn set_view_refuses_a_contended_single_reader() {
        // Two topology-free YubiKeys and one reader: per node the fallback looks
        // unambiguous, but only one of them owns that reader. Stamping its
        // serial on both would make the two keys report the same identity.
        let readers = [reader(None, None, "37806840")];
        let a = yubikey("/dev/hidraw16", None, None);
        let b = yubikey("/dev/hidraw18", None, None);
        assert_eq!(ccid_serials_for(&[&a, &b], &readers), vec![None, None]);
        // One node alone still takes it — the common no-topology case.
        assert_eq!(
            ccid_serials_for(&[&a], &readers),
            vec![Some("37806840".to_string())]
        );
        // A node with topology is decided by topology, whatever else is present.
        let c = yubikey("/dev/hidraw20", Some(9), Some(53));
        let topo = [reader(Some(9), Some(53), "27717893")];
        assert_eq!(
            ccid_serials_for(&[&a, &c], &topo),
            vec![None, Some("27717893".to_string())]
        );
    }

    #[test]
    fn no_serial_for_non_yubikey_or_keys_with_usb_serial() {
        let readers = [reader(Some(9), Some(53), "37806840")];
        // A non-Yubico device never consults CCID.
        let mut solo = yubikey("/dev/hidraw5", Some(9), Some(53));
        solo.vendor_id = 0x1209;
        assert_eq!(ccid_serial_for(&solo, &readers), None);
        // A YubiKey that already has a USB serial isn't a CCID candidate.
        let mut yk = yubikey("/dev/hidraw16", Some(9), Some(53));
        yk.serial_number = Some("ABC".into());
        assert_eq!(ccid_serial_for(&yk, &readers), None);
    }
}
