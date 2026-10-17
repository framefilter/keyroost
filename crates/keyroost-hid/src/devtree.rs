//! "Same physical USB device" evidence, shared by the HID and smart-card
//! sides of key pairing (#51).
//!
//! [`UsbDeviceKey`] is the one comparable value both sides carry. On Linux it
//! is the USB bus + device address (sysfs `busnum`/`devnum` on the HID side,
//! the reader's PC/SC `CHANNEL_ID` on the card side). On Windows it is the
//! device instance ID of the nearest USB *device* devnode above the node,
//! picked out of the raw ancestor chain (read by `keyroost-windevtree`) by the
//! pure, fail-closed [`usb_device_node`].
//!
//! Two keys are the same physical device only when both sides carry a key and
//! the keys are equal ([`same_usb_device`]); a missing key is never evidence.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

/// Evidence of which physical USB device a HID node or reader belongs to.
/// Equal keys mean the same physical device; keys of different kinds are never
/// equal.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum UsbDeviceKey {
    /// USB bus number and device address (Linux). Per attach: a replug gets a
    /// new address.
    BusAddr(u8, u8),
    /// Uppercased device instance ID of the USB device devnode (Windows), as
    /// chosen by [`usb_device_node`]. Persistent across replugs.
    WinNode(String),
}

impl UsbDeviceKey {
    /// The Linux key, present only when both bus and address are known.
    #[must_use]
    pub fn from_bus_addr(bus: Option<u8>, addr: Option<u8>) -> Option<Self> {
        match (bus, addr) {
            (Some(b), Some(a)) => Some(Self::BusAddr(b, a)),
            _ => None,
        }
    }

    /// A Windows key from a USB device instance ID (uppercased here).
    #[must_use]
    pub fn win_node(instance_id: &str) -> Self {
        Self::WinNode(instance_id.to_ascii_uppercase())
    }
}

/// True only when both sides carry a key and the keys are equal: the two are
/// interfaces of the same physical USB device. `None` on either side is "no
/// evidence", never a match.
#[must_use]
pub fn same_usb_device(a: Option<&UsbDeviceKey>, b: Option<&UsbDeviceKey>) -> bool {
    matches!((a, b), (Some(x), Some(y)) if x == y)
}

/// Enumerators of virtual or wireless nodes that must never be paired by
/// device tree: Bluetooth, root-enumerated (e.g. Windows Hello virtual smart
/// cards) and software devices.
const REJECTED_ENUMERATORS: &[&str] = &["BTHENUM", "BTHLEDEVICE", "ROOT", "SWD"];

/// How far into a chain a USB device node may sit: one leading non-USB level
/// (the HID devnode, or a reader devnode below its USB interface), one USB
/// interface level, then the USB device itself.
const MAX_DEPTH: usize = 3;

/// What one device instance ID is, for the shape check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Level {
    /// `USB\VID_…&PID_…\…` with no `&MI_` in the device-ID part.
    UsbDevice,
    /// `USB\VID_…&PID_…&MI_nn\…`: one interface of a composite device.
    UsbInterface,
    /// `USB\ROOT_HUB…\…`.
    RootHub,
    /// Any other `USB\` node (not a `VID_` device ID).
    UsbOther,
    /// A Bluetooth, root-enumerated or software node.
    Rejected,
    /// Not of the form `enumerator\device-id\instance`.
    Malformed,
    /// Any other enumerator (`HID\`, a reader's own node, …).
    Other,
}

/// Classify one (already uppercased) device instance ID. Only the
/// device-ID part (between the first and second `\`) is searched for `&MI_`,
/// so an instance part that happens to contain it does not count.
fn classify(id: &str) -> Level {
    let parts: Vec<&str> = id.split('\\').collect();
    let [enumerator, device, instance] = parts.as_slice() else {
        return Level::Malformed;
    };
    if enumerator.is_empty() || device.is_empty() || instance.is_empty() {
        return Level::Malformed;
    }
    if REJECTED_ENUMERATORS.contains(enumerator) {
        return Level::Rejected;
    }
    if *enumerator != "USB" {
        return Level::Other;
    }
    if device.starts_with("ROOT_HUB") {
        Level::RootHub
    } else if !device.starts_with("VID_") {
        Level::UsbOther
    } else if device.contains("&MI_") {
        Level::UsbInterface
    } else {
        Level::UsbDevice
    }
}

/// Why a chain yielded no USB device node (shown in `--debug` traces).
fn refusal(level: Level) -> &'static str {
    match level {
        Level::RootHub => "reached a USB root hub",
        Level::UsbOther => "unrecognized USB node",
        Level::Rejected => "Bluetooth, virtual or software node",
        Level::Malformed => "malformed instance ID",
        Level::Other => "more than one non-USB level",
        Level::UsbDevice | Level::UsbInterface => "unexpected chain shape",
    }
}

/// [`usb_device_node`], with the reason when there is none.
///
/// # Errors
/// A short human-readable reason the chain does not have an accepted shape.
pub fn usb_device_node_checked(chain: &[String]) -> Result<String, &'static str> {
    if chain.is_empty() {
        return Err("empty chain");
    }
    let up: Vec<String> = chain
        .iter()
        .take(MAX_DEPTH)
        .map(|s| s.to_ascii_uppercase())
        .collect();
    let at = |i: usize| up.get(i).map(|s| classify(s));
    // At most one leading non-USB level.
    let mut i = usize::from(at(0) == Some(Level::Other));
    match at(i) {
        None => Err("chain ends before a USB node"),
        Some(Level::UsbDevice) => Ok(up[i].clone()),
        Some(Level::UsbInterface) => {
            i += 1;
            match at(i) {
                Some(Level::UsbDevice) => Ok(up[i].clone()),
                None => Err("USB interface with no USB device parent"),
                Some(Level::UsbInterface) => Err("USB interface with no USB device parent"),
                Some(other) => Err(refusal(other)),
            }
        }
        Some(other) => Err(refusal(other)),
    }
}

/// The nearest USB *device* devnode in a Windows ancestor chain (node first),
/// uppercased, or `None` when the chain does not have one of the accepted
/// shapes. Fail-closed: `None` means "no topology evidence".
///
/// Accepted (each entry `enumerator\device-id\instance`):
/// - `[X?, USB\VID_…&MI_nn\…, USB\VID_…\…]` → the last entry (a composite
///   device's parent node);
/// - `[X?, USB\VID_…\…]` → that entry (a single-interface device).
///
/// `X` is at most one leading non-USB level: the HID devnode, or a reader
/// devnode that sits below its USB interface. Everything else yields `None`:
/// an empty chain, a USB root hub, a Bluetooth / root-enumerated / software
/// node (`BTHENUM`, `BTHLEDEVICE`, `ROOT`, `SWD`), two non-USB levels, an
/// interface with no USB device parent, or a malformed ID. Only the first
/// three entries are examined, so the walk never reaches a hub.
#[must_use]
pub fn usb_device_node(chain: &[String]) -> Option<String> {
    usb_device_node_checked(chain).ok()
}

static DEVTREE_TRACE: AtomicBool = AtomicBool::new(false);

/// Turn the `--debug` device-tree trace on or off for this process. When on,
/// each Windows device-tree lookup prints its raw chain and the chosen node
/// (or why none) to stderr. Off by default; nothing is traced off Windows.
pub fn set_devtree_trace(on: bool) {
    DEVTREE_TRACE.store(on, Ordering::Relaxed);
}

/// Whether [`set_devtree_trace`] turned the trace on.
#[must_use]
pub fn devtree_trace_enabled() -> bool {
    DEVTREE_TRACE.load(Ordering::Relaxed)
}

/// Control characters replaced, so OS- or device-supplied text can't drive
/// the terminal.
fn clean(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// A device instance ID as shown in a trace: `ENUMERATOR\device-id` in full,
/// the instance part (after the last `\`) shortened with
/// [`keyroost_proto::trace::abbreviate`], since it can carry the device's USB
/// serial and `--debug` output gets pasted publicly. Matching always uses
/// the full ID; only the trace is shortened.
fn shown_id(id: &str) -> String {
    use keyroost_proto::trace::abbreviate;
    let id = clean(id);
    match id.rsplit_once('\\') {
        Some((head, instance)) => format!("{head}\\{}", abbreviate(instance)),
        None => abbreviate(&id),
    }
}

/// The two `--debug` trace lines for one lookup: the chain, then the chosen
/// node or why there is none. Each ID keeps `ENUMERATOR\device-id` in full but
/// its instance part is shortened (first two … last two, plus the length),
/// since it can carry a USB serial. `subject` names what was looked up.
#[must_use]
pub fn devtree_trace_lines(subject: &str, chain: Option<&[String]>) -> [String; 2] {
    use keyroost_proto::trace::{format_line, Dir};
    let subject = clean(subject);
    let (shown, decision) = match chain {
        None => ("none".to_string(), "no node: lookup failed".to_string()),
        Some(c) => (
            c.iter()
                .map(|s| shown_id(s))
                .collect::<Vec<_>>()
                .join(" < "),
            match usb_device_node_checked(c) {
                Ok(node) => format!("node {}", shown_id(&node)),
                Err(why) => format!("no node: {why}"),
            },
        ),
    };
    [
        format_line(Dir::Note, "devtree", &format!("{subject}: chain {shown}")),
        format_line(Dir::Note, "devtree", &format!("{subject}: {decision}")),
    ]
}

/// Trace lines already printed by this process. One `list` run can scan the
/// readers twice (the applet probe and the YubiKey serial read), and the same
/// lookup with the same result says nothing new the second time.
static TRACED: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

/// True the first time this exact pair of lines is offered in this process.
fn first_time(lines: &[String; 2]) -> bool {
    match TRACED.lock() {
        Ok(mut seen) => seen.insert(lines.join("\n")),
        // A poisoned set only costs a repeated line.
        Err(_) => true,
    }
}

/// The key for a node whose raw chain is `chain` (`None` when the lookup
/// failed), printing the trace lines to stderr when `trace` is set (once per
/// process for an identical lookup and result).
#[must_use]
pub fn win_node_from_chain(
    subject: &str,
    chain: Option<&[String]>,
    trace: bool,
) -> Option<UsbDeviceKey> {
    if trace {
        let lines = devtree_trace_lines(subject, chain);
        if first_time(&lines) {
            for line in lines {
                eprintln!("{line}");
            }
        }
    }
    chain
        .and_then(usb_device_node)
        .map(|n| UsbDeviceKey::win_node(&n))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(ids: &[&str]) -> Vec<String> {
        ids.iter().map(|s| (*s).to_string()).collect()
    }

    // Wallby-like Token2 FIDO keys (VID 349E, PIDs 0014 / 0024), composite.
    const T14_HID: &str = r"HID\VID_349E&PID_0014&MI_00\8&1A2B3C4D&0&0000";
    const T14_MI00: &str = r"USB\VID_349E&PID_0014&MI_00\7&2F1E0D9C&0&0000";
    const T14_MI01: &str = r"USB\VID_349E&PID_0014&MI_01\7&2F1E0D9C&0&0001";
    const T14_DEV: &str = r"USB\VID_349E&PID_0014\6&11223344&0&2";
    const T24_DEV: &str = r"USB\VID_349E&PID_0024\6&11223344&0&3";
    const HUB: &str = r"USB\VID_05E3&PID_0610\5&ABCDEF&0&1";
    const ROOT_HUB: &str = r"USB\ROOT_HUB30\4&12345678&0&0";
    const PCI: &str = r"PCI\VEN_8086&DEV_A36D&SUBSYS_00000000&REV_10\3&11583659&0&A0";
    const MOLTO2: &str = r"USB\VID_349E&PID_0300\5&3A4B5C6D&0&4";

    #[test]
    fn composite_hid_chain_gives_the_composite_parent() {
        let chain = c(&[T14_HID, T14_MI00, T14_DEV, HUB, ROOT_HUB, PCI]);
        assert_eq!(usb_device_node(&chain).as_deref(), Some(T14_DEV));
    }

    #[test]
    fn single_interface_hid_chain_gives_the_device_itself() {
        let chain = c(&[r"HID\VID_349E&PID_0024\7&9&0&0000", T24_DEV, ROOT_HUB]);
        assert_eq!(usb_device_node(&chain).as_deref(), Some(T24_DEV));
    }

    #[test]
    fn hid_collection_node_with_interface_parent() {
        let hid = r"HID\VID_1050&PID_0407&MI_01&COL01\8&3A&0&0000";
        let mi = r"USB\VID_1050&PID_0407&MI_01\7&1B&0&0001";
        let dev = r"USB\VID_1050&PID_0407\5&2C&0&3";
        assert_eq!(usb_device_node(&c(&[hid, mi, dev])).as_deref(), Some(dev));
    }

    #[test]
    fn composite_reader_chain_gives_the_composite_parent() {
        let chain = c(&[T14_MI01, T14_DEV, HUB]);
        assert_eq!(usb_device_node(&chain).as_deref(), Some(T14_DEV));
    }

    #[test]
    fn reader_as_child_of_its_interface_gives_the_composite_parent() {
        let chain = c(&[r"WUDF\SMARTCARDREADER\9&1&0", T14_MI01, T14_DEV, HUB]);
        assert_eq!(usb_device_node(&chain).as_deref(), Some(T14_DEV));
    }

    #[test]
    fn single_interface_reader_molto2_gives_itself() {
        assert_eq!(
            usb_device_node(&c(&[MOLTO2, ROOT_HUB, PCI])).as_deref(),
            Some(MOLTO2)
        );
    }

    #[test]
    fn hid_and_reader_of_one_key_agree() {
        let hid = c(&[T14_HID, T14_MI00, T14_DEV, HUB]);
        let reader = c(&[T14_MI01, T14_DEV, HUB]);
        assert_eq!(usb_device_node(&hid), usb_device_node(&reader));
        assert!(usb_device_node(&hid).is_some());
    }

    #[test]
    fn two_keys_on_one_hub_stay_distinct() {
        let a = c(&[T14_MI01, T14_DEV, HUB]);
        let b = c(&[r"USB\VID_349E&PID_0024&MI_01\7&5&0&0001", T24_DEV, HUB]);
        assert_ne!(usb_device_node(&a), usb_device_node(&b));
    }

    #[test]
    fn bluetooth_virtual_and_software_chains_yield_none() {
        for chain in [
            c(&[
                r"HID\{00001124-0000-1000-8000-00805F9B34FB}_VID&0002046D\9&1&0",
                r"BTHENUM\{00001124-0000-1000-8000-00805F9B34FB}_VID&0002046D\8&2&0",
                r"BTH\MS_BTHBRB\7&3&0",
            ]),
            c(&[
                r"HID\{00001812-0000-1000-8000-00805F9B34FB}\9&1&0",
                r"BTHLEDEVICE\{00001812-0000-1000-8000-00805F9B34FB}_DEV_VID&01\8&2&0",
            ]),
            c(&[r"ROOT\SMARTCARDREADER\0000", r"HTREE\ROOT\0"]),
            c(&[r"SWD\SCDEVICEENUM\1_VIRTUAL_SMART_CARD", r"HTREE\ROOT\0"]),
            c(&[r"HID\VID_349E&PID_0014\1&2&0", r"SWD\FOO\1"]),
        ] {
            assert_eq!(usb_device_node(&chain), None, "{chain:?}");
        }
    }

    #[test]
    fn a_chain_reaching_a_root_hub_yields_none() {
        assert_eq!(usb_device_node(&c(&[ROOT_HUB, PCI])), None);
        assert_eq!(usb_device_node(&c(&[r"HID\X\1", ROOT_HUB])), None);
        assert_eq!(
            usb_device_node_checked(&c(&[r"HID\X\1", ROOT_HUB])),
            Err("reached a USB root hub")
        );
    }

    #[test]
    fn over_deep_chains_yield_none() {
        // Two non-USB levels before the USB interface.
        let chain = c(&[r"HID\X\1", r"WUDF\Y\2", T14_MI00, T14_DEV]);
        assert_eq!(usb_device_node(&chain), None);
        // Two interface levels.
        let chain = c(&[r"HID\X\1", T14_MI00, T14_MI01, T14_DEV]);
        assert_eq!(usb_device_node(&chain), None);
    }

    #[test]
    fn empty_and_truncated_chains_yield_none() {
        assert_eq!(usb_device_node(&[]), None);
        assert_eq!(usb_device_node(&c(&[r"HID\X\1"])), None);
        assert_eq!(usb_device_node(&c(&[T14_HID])), None);
    }

    #[test]
    fn an_interface_with_no_usb_parent_yields_none() {
        assert_eq!(usb_device_node(&c(&[T14_MI00])), None);
        assert_eq!(usb_device_node(&c(&[T14_HID, T14_MI00])), None);
        assert_eq!(usb_device_node(&c(&[T14_MI00, PCI])), None);
        assert_eq!(usb_device_node(&c(&[T14_HID, T14_MI00, ROOT_HUB])), None);
    }

    #[test]
    fn malformed_ids_yield_none() {
        for bad in [
            "",
            r"USB",
            r"USB\VID_349E&PID_0014",
            r"USB\\X",
            r"USB\A\B\C",
        ] {
            assert_eq!(usb_device_node(&c(&[bad])), None, "{bad:?}");
        }
        // A non-VID USB node is not a device.
        assert_eq!(usb_device_node(&c(&[r"USB\CLASS_0B\1"])), None);
    }

    #[test]
    fn comparison_is_case_insensitive_and_output_uppercase() {
        let lower = c(&[
            &T14_HID.to_ascii_lowercase(),
            &T14_MI00.to_ascii_lowercase(),
            &T14_DEV.to_ascii_lowercase(),
        ]);
        assert_eq!(usb_device_node(&lower).as_deref(), Some(T14_DEV));
        assert_eq!(
            UsbDeviceKey::win_node(&T14_DEV.to_ascii_lowercase()),
            UsbDeviceKey::win_node(T14_DEV)
        );
    }

    #[test]
    fn mi_in_the_instance_part_does_not_count() {
        // A single-interface device whose instance part contains "&MI_".
        let dev = r"USB\VID_349E&PID_0024\ABC&MI_00";
        assert_eq!(usb_device_node(&c(&[dev])).as_deref(), Some(dev));
        assert_eq!(
            usb_device_node(&c(&[r"HID\VID_349E&PID_0024\X&MI_01", dev])).as_deref(),
            Some(dev)
        );
    }

    #[test]
    fn only_the_first_three_entries_are_examined() {
        // A hub at index 3 never becomes the comparison point.
        let chain = c(&[r"HID\X\1", r"WUDF\Y\2", r"WUDF\Z\3", HUB]);
        assert_eq!(usb_device_node(&chain), None);
    }

    #[test]
    fn same_usb_device_needs_evidence_on_both_sides() {
        let a = UsbDeviceKey::win_node(T14_DEV);
        let b = UsbDeviceKey::win_node(T24_DEV);
        assert!(same_usb_device(Some(&a), Some(&a.clone())));
        assert!(!same_usb_device(Some(&a), Some(&b)));
        assert!(!same_usb_device(Some(&a), None));
        assert!(!same_usb_device(None, None));
        // Kinds never compare equal.
        let ba = UsbDeviceKey::BusAddr(1, 4);
        assert!(!same_usb_device(Some(&a), Some(&ba)));
        assert!(same_usb_device(
            Some(&ba),
            Some(&UsbDeviceKey::BusAddr(1, 4))
        ));
    }

    #[test]
    fn from_bus_addr_needs_both_halves() {
        assert_eq!(
            UsbDeviceKey::from_bus_addr(Some(9), Some(53)),
            Some(UsbDeviceKey::BusAddr(9, 53))
        );
        assert_eq!(UsbDeviceKey::from_bus_addr(Some(9), None), None);
        assert_eq!(UsbDeviceKey::from_bus_addr(None, Some(53)), None);
        assert_eq!(UsbDeviceKey::from_bus_addr(None, None), None);
    }

    #[test]
    fn trace_lines_show_chain_and_decision() {
        let chain = c(&[T14_MI01, T14_DEV]);
        let [a, b] =
            devtree_trace_lines("reader 'TOKEN2 FIDO2 Security Key(0014) 0'", Some(&chain));
        assert!(a.starts_with("! devtree"), "{a}");
        assert!(
            a.ends_with(
                r"chain USB\VID_349E&PID_0014&MI_01\7&…01 (len 17) < USB\VID_349E&PID_0014\6&…&2 (len 14)"
            ),
            "{a}"
        );
        assert!(
            b.ends_with(r"node USB\VID_349E&PID_0014\6&…&2 (len 14)"),
            "{b}"
        );
        // Full instance parts never reach the trace.
        assert!(!a.contains("2F1E0D9C") && !a.contains("11223344"), "{a}");
        assert!(!b.contains("11223344"), "{b}");

        let [a, b] = devtree_trace_lines("hid x", None);
        assert!(a.ends_with("hid x: chain none"), "{a}");
        assert!(b.ends_with("hid x: no node: lookup failed"), "{b}");

        let [_, b] = devtree_trace_lines("hid y\x1b[2J", Some(&c(&[ROOT_HUB])));
        assert!(
            b.ends_with("hid y?[2J: no node: reached a USB root hub"),
            "{b}"
        );
    }

    #[test]
    fn shown_id_shortens_only_the_instance_part() {
        // A serial-bearing instance part (a devnode carrying the key's USB
        // iSerialNumber).
        assert_eq!(
            shown_id(r"USB\VID_1050&PID_0407\0123456789AB"),
            r"USB\VID_1050&PID_0407\01…AB (len 12)"
        );
        // Short instance parts print as is.
        assert_eq!(shown_id(r"HTREE\ROOT\0"), r"HTREE\ROOT\0");
        assert_eq!(shown_id(r"USB\X\ABCD"), r"USB\X\ABCD");
        // No separator at all: the whole value is shortened.
        assert_eq!(shown_id("SERIAL123"), "SE…23 (len 9)");
        // Control characters are cleaned first.
        assert_eq!(shown_id("A\\B\\\u{1b}x"), r"A\B\?x");
    }

    #[test]
    fn matching_still_uses_the_full_id() {
        let chain = c(&[T14_HID, T14_MI00, T14_DEV]);
        assert_eq!(
            usb_device_node(&chain).as_deref(),
            Some(T14_DEV),
            "the decision keeps the full instance part"
        );
        assert_eq!(
            win_node_from_chain("hid", Some(&chain), false),
            Some(UsbDeviceKey::WinNode(T14_DEV.into()))
        );
    }

    #[test]
    fn identical_trace_lines_print_once_per_process() {
        let chain = c(&[T14_MI01, r"USB\VID_349E&PID_0014\DEDUPE&TEST&1"]);
        let lines = devtree_trace_lines("reader 'dedupe test'", Some(&chain));
        assert!(first_time(&lines));
        assert!(!first_time(&lines));
        // A different result for the same subject is new information.
        let other = devtree_trace_lines("reader 'dedupe test'", None);
        assert!(first_time(&other));
    }

    #[test]
    fn win_node_from_chain_maps_and_fails_closed() {
        let chain = c(&[T14_HID, T14_MI00, T14_DEV]);
        assert_eq!(
            win_node_from_chain("hid", Some(&chain), false),
            Some(UsbDeviceKey::WinNode(T14_DEV.into()))
        );
        assert_eq!(win_node_from_chain("hid", None, false), None);
        assert_eq!(
            win_node_from_chain("hid", Some(&c(&[ROOT_HUB])), false),
            None
        );
    }
}
