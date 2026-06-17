//! Shared device model: one physical key correlated from its FIDO-HID node(s)
//! and PC/SC reader(s), with a capability union and a Molto2-vs-key
//! classification. Consumed by both the GUI and the CLI so they never drift.

use std::path::PathBuf;

use keyroost_hid::HidDevice;
use keyroost_keyring::Keyring;
use keyroost_transport::{ReaderProbe, YubiKeyCcid};

/// Capability bit-set. Hand-rolled (no `bitflags` dep). Each physical key
/// advertises the union of the applets it answers.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct Caps(u8);

impl Caps {
    pub const FIDO2: Caps = Caps(1 << 0);
    pub const OATH: Caps = Caps(1 << 1);
    pub const PGP: Caps = Caps(1 << 2);
    pub const PIV: Caps = Caps(1 << 3);
    pub const TOTP: Caps = Caps(1 << 4); // Molto2 programmable token
    pub const OTP: Caps = Caps(1 << 5); // Token2 FIDO key on-device OTP applet

    pub fn has(self, c: Caps) -> bool {
        self.0 & c.0 != 0
    }
    pub fn insert(&mut self, c: Caps) {
        self.0 |= c.0;
    }
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// What kind of physical device this is. `Token` is the Molto2 family; everything
/// else is a `Key`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceKind {
    Key,
    Token,
}

/// A stable identity for a device across refreshes (effective serial, else reader
/// name, else hidraw path).
pub type DeviceId = String;

/// One physical device: the union of its FIDO-HID node and PC/SC applets.
#[derive(Clone)]
pub struct Device {
    pub id: DeviceId,
    pub name: Option<String>,
    pub vendor: String,
    pub model: String,
    pub serial: String,
    pub transport: String,
    pub firmware: String,
    pub caps: Caps,
    pub kind: DeviceKind,
    pub hid_path: Option<PathBuf>,
    pub reader: Option<String>,
}

impl Device {
    /// Ordered capability badge labels — the shared vocabulary used by the CLI
    /// overview/list and the GUI pills, so they cannot drift. A Token shows a
    /// single "TOTP token" badge; a Key shows one per applet it answers.
    pub fn cap_badges(&self) -> Vec<&'static str> {
        if self.kind == DeviceKind::Token {
            return vec!["TOTP token"];
        }
        let mut v = Vec::new();
        for (c, label) in [
            (Caps::FIDO2, "FIDO2"),
            (Caps::OATH, "OATH"),
            (Caps::PGP, "PGP"),
            (Caps::PIV, "PIV"),
            (Caps::OTP, "OTP"),
        ] {
            if self.caps.has(c) {
                v.push(label);
            }
        }
        v
    }
}

/// Map a USB vendor id to a display name; unknown ids fall back to a generic label.
fn vendor_name(vid: u16) -> &'static str {
    match vid {
        0x1050 => "Yubico",
        0x20a0 => "Nitrokey",
        0x1209 => "SoloKeys",
        0x096e | 0x311f => "Feitian",
        0x2581 => "Kanokey",
        0x349e => "Token2",
        0x1e0d => "OpenSK",
        _ => "Security key",
    }
}

/// Turn a raw PC/SC reader name or USB product name into a clean model label,
/// stripping bracketed groups, interface-noise tokens, a leading vendor word, and
/// trailing two-digit pcsc index groups.
fn clean_model(raw: &str, vendor: &str) -> String {
    let mut s = String::with_capacity(raw.len());
    let mut depth = 0i32;
    for ch in raw.chars() {
        match ch {
            '[' | '(' => depth += 1,
            ']' | ')' => depth = (depth - 1).max(0),
            _ if depth == 0 => s.push(ch),
            _ => {}
        }
    }
    for junk in [
        "CCID/ICCD Interface",
        "OTP+FIDO+CCID",
        "FIDO+CCID",
        "OTP+FIDO",
        "U2F+CCID",
        "+CCID",
        "ICCD",
        "CCID",
        "Interface",
        "Smartcard",
        "Smart Card",
    ] {
        s = s.replace(junk, " ");
    }
    let lead = s.trim_start();
    if !vendor.is_empty()
        && lead
            .to_ascii_lowercase()
            .starts_with(&vendor.to_ascii_lowercase())
    {
        s = lead[vendor.len()..].to_string();
    }
    let mut parts: Vec<&str> = s.split_whitespace().collect();
    while parts.len() > 1 {
        let last = parts[parts.len() - 1];
        if last.len() == 2 && last.chars().all(|c| c.is_ascii_digit()) {
            parts.pop();
        } else {
            break;
        }
    }
    let out = parts.join(" ");
    if out.is_empty() {
        vendor.to_string()
    } else {
        out
    }
}

/// True when some FIDO HID node shares this reader's USB topology (bus+address) —
/// i.e. they are the same physical device. Used to keep a Token2 *FIDO key* from
/// ever being classified as a Molto2 (the Molto2 has no FIDO HID interface).
fn has_fido_hid_sibling(p: &ReaderProbe, hids: &[&HidDevice]) -> bool {
    match (p.usb_bus, p.usb_address) {
        (Some(bus), Some(addr)) => hids
            .iter()
            .any(|h| h.usb_bus == Some(bus) && h.usb_address == Some(addr)),
        _ => false,
    }
}

/// Correlate FIDO-HID nodes and PC/SC reader probes into one device per physical
/// key. Pure: all I/O is done by the caller ([`enumerate`]). The `hids` slice may
/// contain non-FIDO nodes; they are filtered here.
pub fn correlate(hids: &[HidDevice], probes: &[ReaderProbe], keyring: &Keyring) -> Vec<Device> {
    let hids: Vec<&HidDevice> = hids.iter().filter(|h| h.is_fido()).collect();

    let yk_readers: Vec<YubiKeyCcid> = probes
        .iter()
        .filter(|p| !p.is_molto2)
        .map(|p| YubiKeyCcid {
            reader_name: p.reader_name.clone(),
            usb_bus: p.usb_bus,
            usb_address: p.usb_address,
            serial: p.yubikey_serial.clone(),
        })
        .collect();

    let serials: Vec<Option<String>> = hids
        .iter()
        .map(|h| {
            h.serial_number
                .clone()
                .or_else(|| crate::ccid_serial_for(h, &yk_readers))
        })
        .collect();

    let mut devices: Vec<Device> = Vec::new();

    // --- 1. Molto2 tokens — only when there is NO FIDO HID sibling (#21 guard).
    for p in probes
        .iter()
        .filter(|p| p.is_molto2 && !has_fido_hid_sibling(p, &hids))
    {
        let serial = p.serial.clone().unwrap_or_default();
        let mut caps = Caps::default();
        caps.insert(Caps::TOTP);
        devices.push(Device {
            id: format!("molto:{}", p.reader_name),
            name: keyring.name_for(Some(&serial)).map(str::to_owned),
            vendor: "Token2".into(),
            model: "Molto2".into(),
            serial,
            transport: "USB · PC/SC".into(),
            firmware: String::new(),
            caps,
            kind: DeviceKind::Token,
            hid_path: None,
            reader: Some(p.reader_name.clone()),
        });
    }

    // --- 2. Smart-card keys, one per non-Molto reader that answers an applet.
    for p in probes.iter().filter(|p| !p.is_molto2) {
        let mut caps = Caps::default();
        if p.has_oath {
            caps.insert(Caps::OATH);
        }
        if p.has_openpgp {
            caps.insert(Caps::PGP);
        }
        if p.has_piv {
            caps.insert(Caps::PIV);
        }
        if p.reader_name.to_ascii_lowercase().contains("token2") {
            caps.insert(Caps::OTP);
        }
        if caps.is_empty() {
            continue;
        }
        let serial = p
            .yubikey_serial
            .clone()
            .or_else(|| p.serial.clone())
            .unwrap_or_default();
        let id = if serial.is_empty() {
            format!("reader:{}", p.reader_name)
        } else {
            format!("serial:{serial}")
        };
        let vendor = if p.yubikey_serial.is_some() {
            "Yubico".to_string()
        } else {
            p.reader_name
                .split_whitespace()
                .next()
                .unwrap_or("Key")
                .to_string()
        };
        let model = clean_model(&p.reader_name, &vendor);
        devices.push(Device {
            id,
            name: keyring.name_for(Some(&serial)).map(str::to_owned),
            vendor,
            model,
            serial,
            transport: "USB · PC/SC".into(),
            firmware: String::new(),
            caps,
            kind: DeviceKind::Key,
            hid_path: None,
            reader: Some(p.reader_name.clone()),
        });
    }

    // --- 3. Merge FIDO HID nodes into their physical key.
    for (i, hid) in hids.iter().enumerate() {
        let serial = serials.get(i).cloned().flatten().unwrap_or_default();
        let is_token2 = hid.vendor_id == keyroost_proto::USB_VID;

        let reader_name: Option<String> = if hid.vendor_id == crate::VID_YUBICO {
            yk_readers
                .iter()
                .find(|c| {
                    c.usb_bus == hid.usb_bus
                        && c.usb_address == hid.usb_address
                        && c.usb_bus.is_some()
                })
                .or_else(|| {
                    let only: Vec<_> = yk_readers.iter().collect();
                    if only.len() == 1 {
                        Some(only[0])
                    } else {
                        None
                    }
                })
                .map(|c| c.reader_name.clone())
        } else {
            let vt = vendor_name(hid.vendor_id);
            let matches: Vec<&str> = probes
                .iter()
                .filter(|p| !p.is_molto2)
                .map(|p| p.reader_name.as_str())
                .filter(|r| r.to_ascii_lowercase().contains(&vt.to_ascii_lowercase()))
                .collect();
            match matches.as_slice() {
                [only] => Some((*only).to_string()),
                _ => None,
            }
        };

        let existing = devices.iter_mut().find(|d| {
            d.kind == DeviceKind::Key
                && ((reader_name.is_some() && d.reader == reader_name)
                    || (!serial.is_empty() && d.serial == serial))
        });
        if let Some(dev) = existing {
            dev.caps.insert(Caps::FIDO2);
            if is_token2 {
                dev.caps.insert(Caps::OTP);
            }
            dev.hid_path = Some(hid.path.clone());
            dev.transport = "USB · PC/SC + FIDO HID".into();
            if dev.serial.is_empty() {
                dev.serial = serial.clone();
            }
            if dev.name.is_none() {
                dev.name = keyring.name_for(Some(&serial)).map(str::to_owned);
            }
        } else {
            let id = if !serial.is_empty() {
                format!("serial:{serial}")
            } else {
                format!("hid:{}", hid.path.display())
            };
            let mut caps = Caps::default();
            caps.insert(Caps::FIDO2);
            if is_token2 {
                caps.insert(Caps::OTP);
            }
            let vendor = vendor_name(hid.vendor_id).to_string();
            let model = if is_token2 {
                keyroost_proto::token2_pid_label(hid.product_id)
                    .map(str::to_owned)
                    .unwrap_or_else(|| clean_model(&hid.product_name, &vendor))
            } else {
                clean_model(&hid.product_name, &vendor)
            };
            devices.push(Device {
                id,
                name: keyring.name_for(Some(&serial)).map(str::to_owned),
                vendor,
                model,
                serial,
                transport: "USB · FIDO HID".into(),
                firmware: String::new(),
                caps,
                kind: DeviceKind::Key,
                hid_path: Some(hid.path.clone()),
                reader: reader_name,
            });
        }
    }

    devices.sort_by(|a, b| {
        (a.kind == DeviceKind::Token)
            .cmp(&(b.kind == DeviceKind::Token))
            .then_with(|| a.model.cmp(&b.model))
            .then_with(|| a.id.cmp(&b.id))
    });
    devices
}

/// Build the unified device list. Blocking: enumerates FIDO HID nodes and probes
/// PC/SC readers, then correlates. A HID-layer failure is a hard error; PC/SC
/// problems degrade to an empty probe list (FIDO-only keys still appear).
pub fn enumerate() -> Result<Vec<Device>, String> {
    let hids = keyroost_hid::enumerate().map_err(|e| format!("HID enumeration failed: {e}"))?;
    let probes = keyroost_transport::probe_readers().unwrap_or_default();
    let keyring = Keyring::load_default().unwrap_or_default();
    Ok(correlate(&hids, &probes, &keyring))
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyroost_hid::{HID_USAGE_FIDO_AUTHENTICATOR, HID_USAGE_PAGE_FIDO};

    fn hid(
        vid: u16,
        pid: u16,
        path: &str,
        serial: Option<&str>,
        bus: Option<u8>,
        addr: Option<u8>,
    ) -> HidDevice {
        HidDevice {
            path: path.into(),
            vendor_id: vid,
            product_id: pid,
            product_name: "Security Key".into(),
            usage_page: HID_USAGE_PAGE_FIDO,
            usage: HID_USAGE_FIDO_AUTHENTICATOR,
            serial_number: serial.map(str::to_owned),
            usb_bus: bus,
            usb_address: addr,
        }
    }

    // A test fixture mirroring ReaderProbe's fields; the arg count is inherent.
    #[allow(clippy::too_many_arguments)]
    fn probe(
        name: &str,
        molto2: bool,
        oath: bool,
        pgp: bool,
        piv: bool,
        yk_serial: Option<&str>,
        bus: Option<u8>,
        addr: Option<u8>,
    ) -> ReaderProbe {
        ReaderProbe {
            reader_name: name.into(),
            is_molto2: molto2,
            serial: None,
            has_oath: oath,
            has_openpgp: pgp,
            has_piv: piv,
            yubikey_serial: yk_serial.map(str::to_owned),
            usb_bus: bus,
            usb_address: addr,
        }
    }

    #[test]
    fn molto2_with_no_hid_sibling_is_a_token() {
        let probes = [probe(
            "TOKEN2 Molto2 (5C7D…) 02 00",
            true,
            false,
            false,
            false,
            None,
            Some(9),
            Some(4),
        )];
        let devs = correlate(&[], &probes, &Keyring::default());
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].kind, DeviceKind::Token);
        assert_eq!(devs[0].model, "Molto2");
        assert!(devs[0].caps.has(Caps::TOTP));
    }

    #[test]
    fn molto2_flag_with_hid_sibling_is_not_a_token() {
        let probes = [probe(
            "TOKEN2 something 02 00",
            true,
            false,
            false,
            false,
            None,
            Some(9),
            Some(4),
        )];
        let hids = [hid(
            keyroost_proto::USB_VID,
            0x0013,
            "/dev/hidraw9",
            Some("S1"),
            Some(9),
            Some(4),
        )];
        let devs = correlate(&hids, &probes, &Keyring::default());
        assert!(devs.iter().all(|d| d.kind != DeviceKind::Token));
    }

    #[test]
    fn yubikey_unions_hid_fido_with_ccid_applets() {
        let probes = [probe(
            "Yubico YubiKey OTP+FIDO+CCID 00 00",
            false,
            true,
            true,
            true,
            Some("37806840"),
            Some(9),
            Some(16),
        )];
        let hids = [hid(
            0x1050,
            0x0407,
            "/dev/hidraw17",
            None,
            Some(9),
            Some(16),
        )];
        let devs = correlate(&hids, &probes, &Keyring::default());
        assert_eq!(devs.len(), 1);
        let d = &devs[0];
        assert_eq!(d.kind, DeviceKind::Key);
        assert!(
            d.caps.has(Caps::FIDO2)
                && d.caps.has(Caps::OATH)
                && d.caps.has(Caps::PGP)
                && d.caps.has(Caps::PIV)
        );
        assert_eq!(d.serial, "37806840");
    }

    #[test]
    fn solo2_merges_by_shared_serial() {
        let serial = "07A9568FBE31AD5DAD1F2298476CF0D4";
        let probes = [probe(
            "SoloKeys Solo 2 [CCID/ICCD Interface] 01 00",
            false,
            true,
            false,
            false,
            None,
            Some(9),
            Some(15),
        )];
        let hids = [hid(
            0x1209,
            0xbeee,
            "/dev/hidraw14",
            Some(serial),
            Some(9),
            Some(15),
        )];
        let devs = correlate(&hids, &probes, &Keyring::default());
        assert!(devs
            .iter()
            .any(|d| d.kind == DeviceKind::Key && d.caps.has(Caps::FIDO2)));
        assert!(devs.iter().all(|d| d.kind != DeviceKind::Token));
    }

    #[test]
    fn token2_fido_key_gets_otp_cap_by_pid() {
        let probes: [ReaderProbe; 0] = [];
        let hids = [hid(
            keyroost_proto::USB_VID,
            0x0013,
            "/dev/hidraw9",
            Some("S1"),
            Some(9),
            Some(4),
        )];
        let devs = correlate(&hids, &probes, &Keyring::default());
        assert_eq!(devs.len(), 1);
        assert!(devs[0].caps.has(Caps::FIDO2) && devs[0].caps.has(Caps::OTP));
    }

    #[test]
    fn caps_insert_has_and_empty() {
        let mut c = Caps::default();
        assert!(c.is_empty());
        c.insert(Caps::FIDO2);
        c.insert(Caps::PIV);
        assert!(c.has(Caps::FIDO2));
        assert!(c.has(Caps::PIV));
        assert!(!c.has(Caps::OATH));
        assert!(!c.is_empty());
    }

    #[test]
    fn clean_model_strips_vendor_brackets_and_index() {
        assert_eq!(
            clean_model(
                "SoloKeys Solo 2 [CCID/ICCD Interface] (07A9) 01 00",
                "SoloKeys"
            ),
            "Solo 2"
        );
        assert_eq!(
            clean_model("Yubico YubiKey OTP+FIDO+CCID 00 00", "Yubico"),
            "YubiKey"
        );
        assert_eq!(clean_model("Nitrokey 3", "Nitrokey"), "3");
    }

    #[test]
    fn vendor_name_maps_known_vids() {
        assert_eq!(vendor_name(0x1050), "Yubico");
        assert_eq!(vendor_name(0x1209), "SoloKeys");
        assert_eq!(vendor_name(0x349e), "Token2");
        assert_eq!(vendor_name(0xffff), "Security key");
    }

    #[test]
    fn two_yubikeys_do_not_collapse() {
        // Two YubiKeys, disambiguated by USB topology — must stay two devices, each
        // with its own serial and FIDO2+OATH caps (guards the phase-3 topology match).
        let probes = [
            probe(
                "Yubico YubiKey OTP+FIDO+CCID 00 00",
                false,
                true,
                false,
                false,
                Some("111"),
                Some(9),
                Some(16),
            ),
            probe(
                "Yubico YubiKey OTP+FIDO+CCID 01 00",
                false,
                true,
                false,
                false,
                Some("222"),
                Some(9),
                Some(17),
            ),
        ];
        let hids = [
            hid(0x1050, 0x0407, "/dev/hidraw17", None, Some(9), Some(16)),
            hid(0x1050, 0x0407, "/dev/hidraw18", None, Some(9), Some(17)),
        ];
        let devs = correlate(&hids, &probes, &Keyring::default());
        assert_eq!(devs.len(), 2);
        let serials: std::collections::HashSet<String> =
            devs.iter().map(|d| d.serial.clone()).collect();
        assert!(serials.contains("111") && serials.contains("222"));
        assert!(devs
            .iter()
            .all(|d| d.caps.has(Caps::FIDO2) && d.caps.has(Caps::OATH)));
    }

    #[test]
    fn cap_badges_vocabulary() {
        // A Token shows a single "TOTP token" badge regardless of other bits.
        let probes = [probe(
            "TOKEN2 Molto2 02 00",
            true,
            false,
            false,
            false,
            None,
            Some(9),
            Some(4),
        )];
        let molto = &correlate(&[], &probes, &Keyring::default())[0];
        assert_eq!(molto.cap_badges(), vec!["TOTP token"]);

        // A Token2 FIDO key (FIDO2 + OTP by PID) badges both, in canonical order.
        let hids = [hid(
            keyroost_proto::USB_VID,
            0x0013,
            "/dev/hidraw9",
            Some("S1"),
            Some(9),
            Some(4),
        )];
        let key = &correlate(&hids, &[], &Keyring::default())[0];
        assert_eq!(key.cap_badges(), vec!["FIDO2", "OTP"]);

        // A full YubiKey badges FIDO2/OATH/PGP/PIV in order (no OTP).
        let yk_probe = [probe(
            "Yubico YubiKey OTP+FIDO+CCID 00 00",
            false,
            true,
            true,
            true,
            Some("37806840"),
            Some(9),
            Some(16),
        )];
        let yk_hid = [hid(
            0x1050,
            0x0407,
            "/dev/hidraw17",
            None,
            Some(9),
            Some(16),
        )];
        let yk = &correlate(&yk_hid, &yk_probe, &Keyring::default())[0];
        assert_eq!(yk.cap_badges(), vec!["FIDO2", "OATH", "PGP", "PIV"]);
    }

    #[test]
    fn fido_only_non_token2_key_is_plain_fido2() {
        // A Nitrokey FIDO HID with no CCID reader → one Key, FIDO2 only (no OTP),
        // vendor/model derived from the USB vendor id + product name.
        let probes: [ReaderProbe; 0] = [];
        let mut h = hid(
            0x20a0,
            0x0001,
            "/dev/hidraw3",
            Some("NK1"),
            Some(9),
            Some(20),
        );
        h.product_name = "Nitrokey 3".into();
        let devs = correlate(&[h], &probes, &Keyring::default());
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].kind, DeviceKind::Key);
        assert!(devs[0].caps.has(Caps::FIDO2));
        assert!(!devs[0].caps.has(Caps::OTP));
        assert_eq!(devs[0].vendor, "Nitrokey");
    }
}
