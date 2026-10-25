//! Shared security-key identity resolution.
//!
//! Bridges raw device enumeration ([`keyroost_hid`]) and the friendly-name
//! registry ([`keyroost_keyring`]) into one place, so the CLI (`keyroostctl`) and the
//! GUI (`keyroost`) are thin front-ends over a single resolver rather than each
//! re-implementing identity matching.
//!
//! The device-model path ([`device::correlate`] / [`device::correlate_live`])
//! is how every front end identifies a key: it merges HID enumeration with a
//! PC/SC applet probe and, where topology alone can't decide, an on-demand
//! identity read ([`identity::read_identities`]), then hands the result to
//! [`select::resolve_target`] for `--device`/`--reader`/`--path`/picker
//! matching. A USB
//! `iSerialNumber` or a CCID-read YubiKey serial ([`ccid_serial_for`]) is one
//! input into that merge, not a resolver of its own — this module no longer
//! exposes a HID-only name lookup; use the device model instead.

use keyroost_hid::{same_usb_device, HidDevice, UsbDeviceKey};
use keyroost_transport::YubiKeyCcid;

pub mod device;
pub mod identity;
pub mod names;
pub mod select;
pub use device::{
    add_key_names, correlate, correlate_live, correlate_with, enumerate, enumerate_with,
    exclude_unresettable_piv, factory_reset_plan, forget_key_names, load_keyring_for_scan,
    name_from_keys, smart_cards_without_reader, take_scan_warnings, vendor_name,
    with_key_names_forgotten, CapState, Caps, Device, DeviceId, DeviceKind, EnumerateOptions,
    MatchOptions, MatchStep, ResetStep, StepOutcome, StepReport, PIV_GLOBAL_RESET_LABEL,
};
pub use identity::{
    plan_identity_reads, read_identities, CanonicalId, IdScheme, Identities, IdentityPlan,
    IdentityReader, KeyAnswer, IDENTITY_READERS,
};
pub use names::{
    apply_names, apply_updates, clear_key_names, name_held_elsewhere, row_serials, serial_tail,
    set_key_name, KeyLabel, NameSource, NameUpdate, Naming,
};
pub use select::{
    device_value, endpoint, list_number, list_order, molto_reader_serial, parse_device_spec,
    resolve_target, resolve_target_reading, row_label, rows_matching, selection_needs_key_names,
    shell_quote, Candidate, Choice, DeviceSpec, Need, NoPicker, Picker, SelectError, SelectedBy,
    Selector, Target,
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
    ccid_serials_attributed(devices, readers, true)
}

/// [`ccid_serials_for`] with the single-reader fallback switchable: with
/// `allow_guess` off, a serial is attributed only on exact USB topology, so a
/// topology-free node gets none. Matching uses this when its vendor fallback
/// is disabled, so no guessed serial can join rows behind the matcher's back.
pub(crate) fn ccid_serials_attributed(
    devices: &[&HidDevice],
    readers: &[YubiKeyCcid],
    allow_guess: bool,
) -> Vec<Option<String>> {
    // Serials proven to belong to a node by exact USB topology. Those readers
    // are spoken for, so they are not available to a topology-free guess.
    let taken: Vec<String> = devices
        .iter()
        .filter_map(|d| ccid_serial_by_topology(d, readers))
        .collect();
    // With no topology evidence either way, every such node is an equally good
    // owner of the one reader, so more than one claimant means nobody may take
    // it.
    let claimants = devices
        .iter()
        .filter(|d| ccid_serial_by_topology(d, readers).is_none())
        .filter(|d| ccid_serial_guess(d, readers).is_some())
        .count();
    devices
        .iter()
        .map(|d| {
            if let Some(serial) = ccid_serial_by_topology(d, readers) {
                return Some(serial);
            }
            let guess = ccid_serial_guess(d, readers)?;
            let contended = claimants > 1 || taken.contains(&guess);
            (allow_guess && !contended).then_some(guess)
        })
        .collect()
}

/// Whether a node's own USB evidence rules out *guessing* that a reader
/// carrying `reader` evidence is its sibling (the guess is only ever taken
/// after an exact match failed).
///
/// Linux bus/address is read on both sides from the kernel, so a node that
/// has one and matched nothing is positive evidence of a *different* physical
/// device, whatever the reader reports (the rule since before #51). A Windows
/// devnode rules a guess out only when the reader has evidence too: the reader
/// side of the device tree can fail to resolve (or have a shape not yet seen
/// on hardware), and a one-sided devnode then falls through to the steps that
/// applied before Windows had any topology at all.
pub(crate) fn topology_rules_out_guess(
    node: Option<&UsbDeviceKey>,
    reader: Option<&UsbDeviceKey>,
) -> bool {
    match node {
        None => false,
        Some(UsbDeviceKey::WinNode(_)) => reader.is_some(),
        Some(_) => true,
    }
}

/// The serial of the YubiKey reader at this node's exact USB device, if any.
fn ccid_serial_by_topology(d: &HidDevice, readers: &[YubiKeyCcid]) -> Option<String> {
    if !needs_ccid_serial(d) {
        return None;
    }
    readers
        .iter()
        .filter(|r| r.serial.is_some())
        .find(|r| same_usb_device(r.usb_device.as_ref(), d.usb_device.as_ref()))
        .and_then(|r| r.serial.clone())
}

/// The single-reader fallback for a node with no exact match: the serial of
/// the one reader that answered, unless the node's own evidence rules it out
/// ([`topology_rules_out_guess`]).
fn ccid_serial_guess(d: &HidDevice, readers: &[YubiKeyCcid]) -> Option<String> {
    if !needs_ccid_serial(d) {
        return None;
    }
    let with_serial: Vec<&YubiKeyCcid> = readers.iter().filter(|r| r.serial.is_some()).collect();
    match with_serial.as_slice() {
        [only] if !topology_rules_out_guess(d.usb_device.as_ref(), only.usb_device.as_ref()) => {
            only.serial.clone()
        }
        _ => None,
    }
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
/// USB-device match (Linux bus + address, or the Windows devnode), so two
/// connected YubiKeys are never confused; falls back to the unambiguous
/// single-reader case only when the HID node's own topology does not rule it
/// out. Never guesses among several readers —
/// returns `None` instead, which is the safe outcome.
///
/// This single-node view cannot see that *another* topology-free node is an
/// equally good owner of the one reader; callers holding the whole HID set
/// should use [`ccid_serials_for`], which additionally refuses that fallback
/// when it is contended.
pub fn ccid_serial_for(d: &HidDevice, readers: &[YubiKeyCcid]) -> Option<String> {
    // A node that reported its own bus/address and still matched nothing has
    // positive evidence it is a *different* physical device, so the
    // single-reader fallback would hand it another key's serial. Only a node
    // with no topology evidence against that reader may take the fallback
    // (see `topology_rules_out_guess`), or correlation breaks there entirely.
    ccid_serial_by_topology(d, readers).or_else(|| ccid_serial_guess(d, readers))
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyroost_hid::{HID_USAGE_FIDO_AUTHENTICATOR, HID_USAGE_PAGE_FIDO};

    /// The `test-isolation` dev-dependency feature is on: a test here can
    /// never resolve, read or write the person's config directory.
    #[test]
    fn tests_never_resolve_the_real_config_dir() {
        let tmp = std::env::temp_dir();
        let dir = keyroost_keyring::config_dir().expect("always set in tests");
        assert!(dir.starts_with(&tmp), "{dir:?} is outside {tmp:?}");
        assert!(keyroost_keyring::config_path().unwrap().starts_with(&tmp));
    }

    fn yubikey(path: &str, bus: Option<u8>, addr: Option<u8>) -> HidDevice {
        HidDevice {
            path: path.into(),
            vendor_id: VID_YUBICO,
            product_id: 0x0407,
            product_name: "YubiKey".into(),
            usage_page: HID_USAGE_PAGE_FIDO,
            usage: HID_USAGE_FIDO_AUTHENTICATOR,
            serial_number: None,
            usb_device: UsbDeviceKey::from_bus_addr(bus, addr),
        }
    }

    fn reader(bus: Option<u8>, addr: Option<u8>, serial: &str) -> YubiKeyCcid {
        YubiKeyCcid {
            reader_name: "Yubico YubiKey OTP+FIDO+CCID".into(),
            usb_device: UsbDeviceKey::from_bus_addr(bus, addr),
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

    fn with_node(mut d: HidDevice, id: &str) -> HidDevice {
        d.usb_device = Some(UsbDeviceKey::win_node(id));
        d
    }

    fn reader_at(id: Option<&str>, serial: &str) -> YubiKeyCcid {
        let mut r = reader(None, None, serial);
        r.usb_device = id.map(UsbDeviceKey::win_node);
        r
    }

    const YK_A: &str = r"USB\VID_1050&PID_0407\5&2C1A&0&3";
    const YK_B: &str = r"USB\VID_1050&PID_0407\5&2C1A&0&4";

    #[test]
    fn windows_devnodes_disambiguate_two_yubikeys() {
        let readers = [
            reader_at(Some(YK_B), "27717893"),
            reader_at(Some(YK_A), "37806840"),
        ];
        let a = with_node(yubikey(r"\\?\HID#A", None, None), YK_A);
        let b = with_node(yubikey(r"\\?\HID#B", None, None), YK_B);
        assert_eq!(
            ccid_serials_for(&[&a, &b], &readers),
            vec![Some("37806840".to_string()), Some("27717893".to_string())]
        );
    }

    #[test]
    fn windows_one_sided_devnode_keeps_the_single_reader_fallback() {
        // The reader's devnode didn't resolve: no evidence against the guess.
        let d = with_node(yubikey(r"\\?\HID#A", None, None), YK_A);
        let readers = [reader_at(None, "37806840")];
        assert_eq!(ccid_serial_for(&d, &readers).as_deref(), Some("37806840"));
        // Nor the other way round.
        let d = yubikey(r"\\?\HID#A", None, None);
        let readers = [reader_at(Some(YK_A), "37806840")];
        assert_eq!(ccid_serial_for(&d, &readers).as_deref(), Some("37806840"));
    }

    #[test]
    fn windows_differing_devnodes_never_fall_back() {
        let d = with_node(yubikey(r"\\?\HID#A", None, None), YK_A);
        let readers = [reader_at(Some(YK_B), "27717893")];
        assert_eq!(ccid_serial_for(&d, &readers), None);
        assert_eq!(ccid_serials_for(&[&d], &readers), vec![None]);
    }

    #[test]
    fn windows_devnode_never_matches_a_bus_address() {
        let d = with_node(yubikey(r"\\?\HID#A", None, None), YK_A);
        let readers = [reader(Some(9), Some(53), "37806840")];
        assert_eq!(ccid_serial_for(&d, &readers), None);
    }
}
