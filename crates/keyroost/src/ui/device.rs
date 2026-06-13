// crates/keyroost/src/ui/device.rs
//
// The unified, device-centric view-model. The redesign lists each *physical*
// key once and shows which applets it offers — so a YubiKey that today appears
// in four separate tabs (FIDO HID, plus OATH / OpenPGP / PIV over PC/SC) becomes
// a single row badged `FIDO2 · OATH · PGP · PIV`.
//
// This is the one genuinely non-cosmetic part of the redesign: it *correlates*
// two independent enumerations (FIDO HID nodes via `keyroost-hid`, and PC/SC
// readers via `keyroost-transport`) into one list. We lean on `keyroost-resolve`
// for the USB↔CCID topology matching that already disambiguates two YubiKeys.
//
// `enumerate()` performs blocking device I/O (PC/SC applet probes), so callers
// run it on the worker thread, never on the egui frame thread.

use std::path::PathBuf;

use keyroost_hid::HidDevice;
use keyroost_keyring::Keyring;

/// Capability bit-set for a device. Hand-rolled (no `bitflags` dep — the repo
/// vendors over depends). Each physical key advertises the union of the applets
/// it answers.
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

/// What kind of physical device this is. `Token` is the Molto2 family, which gets
/// a distinct amber treatment; everything else is a `Key`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DeviceKind {
    Key,
    Token,
}

/// Which capability pane is showing for the selected device.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum CapTab {
    #[default]
    Overview,
    Fido2,
    Oath,
    Pgp,
    Piv,
    Otp,
}

/// A stable identity for a device across refreshes. Prefer the effective serial;
/// fall back to the PC/SC reader name, then the hidraw path. Stable so the
/// current selection survives a re-enumeration (plug/unplug of *other* keys).
pub type DeviceId = String;

/// One physical device in the sidebar. A thin view-model: the whole UI is a
/// function of `Vec<UiDevice>` + the current selection. The `hid_path` / `reader`
/// handles are how each capability pane reaches the underlying applet, reusing
/// the existing worker logic unchanged.
#[derive(Clone)]
pub struct UiDevice {
    pub id: DeviceId,
    /// Friendly name from `keys.json`, when the user has named this key.
    pub name: Option<String>,
    pub vendor: String,
    pub model: String,
    /// Effective serial (USB iSerial, else CCID serial for YubiKeys). May be
    /// empty when a PC/SC-only device exposes none until opened.
    pub serial: String,
    pub transport: String,
    /// Firmware string, filled lazily once a capability pane reads it. Empty
    /// until then (the hero omits `fw …` when empty).
    pub firmware: String,
    pub caps: Caps,
    pub kind: DeviceKind,
    /// hidraw path for FIDO2 ops (PIN, resident creds, reset).
    pub hid_path: Option<PathBuf>,
    /// PC/SC reader name for OATH / OpenPGP / PIV / Molto2 ops.
    pub reader: Option<String>,
}

impl UiDevice {
    /// Display title: the friendly name when set, else the model.
    pub fn title(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.model)
    }

    /// The capability tabs to show for this device, in canonical order:
    /// `Overview` first, then one per capability present.
    pub fn tabs(&self) -> Vec<CapTab> {
        if self.kind == DeviceKind::Token {
            // The Molto2 has its own dedicated pane; no capability tab bar.
            return Vec::new();
        }
        let mut v = vec![CapTab::Overview];
        if self.caps.has(Caps::FIDO2) {
            v.push(CapTab::Fido2);
        }
        if self.caps.has(Caps::OATH) {
            v.push(CapTab::Oath);
        }
        if self.caps.has(Caps::PGP) {
            v.push(CapTab::Pgp);
        }
        if self.caps.has(Caps::PIV) {
            v.push(CapTab::Piv);
        }
        if self.caps.has(Caps::OTP) {
            v.push(CapTab::Otp);
        }
        v
    }
}

/// Map a USB vendor id to a display name. Covers the FIDO key vendors this tool
/// targets; unknown ids fall back to a generic label rather than a raw hex id.
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

/// Turn a raw device string (a PC/SC reader name like
/// `SoloKeys Solo 2 [CCID/ICCD Interface] (07A9…) 00 00`, or a USB product name
/// like `YubiKey OTP+FIDO+CCID`) into a clean model label like `Solo 2` /
/// `YubiKey`. The `vendor` is shown in its own column, so a leading vendor word
/// is stripped to avoid `Yubico  Yubico YubiKey`.
fn clean_model(raw: &str, vendor: &str) -> String {
    // 1. Drop bracketed/parenthesised groups (`[CCID/ICCD Interface]`, `(serial)`).
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
    // 2. Strip transport/interface noise tokens.
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
    // 3. Strip a leading vendor word (shown in its own column).
    let lead = s.trim_start();
    if !vendor.is_empty()
        && lead
            .to_ascii_lowercase()
            .starts_with(&vendor.to_ascii_lowercase())
    {
        s = lead[vendor.len()..].to_string();
    }
    // 4. Collapse whitespace, then drop trailing two-digit pcsc index groups
    //    (`… 00 00`) without eating real model numbers like `Solo 2` / `5C`.
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

/// Build the unified device list. Blocking: probes PC/SC applets. Returns a
/// user-facing error string on hard enumeration failure (HID layer), but PC/SC
/// problems degrade gracefully to "no smart-card capabilities" rather than
/// failing the whole list — a key with only FIDO still shows up.
pub fn enumerate() -> Result<Vec<UiDevice>, String> {
    use keyroost_transport::YubiKeyCcid;

    // --- FIDO HID side (no PC/SC) ------------------------------------------
    let hids: Vec<HidDevice> = keyroost_hid::enumerate()
        .map_err(|e| format!("HID enumeration failed: {e}"))?
        .into_iter()
        .filter(HidDevice::is_fido)
        .collect();
    let keyring = Keyring::load_default().unwrap_or_default();

    // --- PC/SC side: ONE pass, one connection per reader, Molto2 untouched -
    // probe_readers() lists readers once and probes each with a single
    // connection (Molto2 readers are never connected). This replaces the old
    // per-applet scans that reconnected to every card ~4x and reset them.
    let probes = keyroost_transport::probe_readers().unwrap_or_default();

    // YubiKey topology + serial for HID<->CCID matching, taken from the probe
    // pass (no extra PC/SC traffic, no card resets).
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

    // Effective serial per HID node: USB iSerial, else the YubiKey CCID serial
    // matched by USB topology (keyroost-resolve's tested logic, fed our probes).
    let serials: Vec<Option<String>> = hids
        .iter()
        .map(|h| {
            h.serial_number
                .clone()
                .or_else(|| keyroost_resolve::ccid_serial_for(h, &yk_readers))
        })
        .collect();

    let mut devices: Vec<UiDevice> = Vec::new();

    // --- 1. Molto2 tokens: the probe connects gently (device-native `get info`
    //        only, released with `LeaveCard`), so a held/authenticated session
    //        survives a refresh while we still read the serial up front.
    for p in probes.iter().filter(|p| p.is_molto2) {
        let serial = p.serial.clone().unwrap_or_default();
        devices.push(UiDevice {
            id: format!("molto:{}", p.reader_name),
            name: keyring.name_for(Some(&serial)).map(str::to_owned),
            vendor: "Token2".into(),
            model: "Molto2".into(),
            serial,
            transport: "USB · PC/SC".into(),
            firmware: String::new(),
            caps: {
                let mut c = Caps::default();
                c.insert(Caps::TOTP);
                c
            },
            kind: DeviceKind::Token,
            hid_path: None,
            reader: Some(p.reader_name.clone()),
        });
    }

    // --- 2. Smart-card keys, one per non-Molto reader that answers an applet
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
        if caps.is_empty() {
            // No key applet we manage — likely a FIDO-only key's CCID interface.
            // The HID merge step below picks it up if it matches a HID node.
            continue;
        }
        // Prefer a YubiKey management serial; otherwise fall back to a serial
        // recovered from the OpenPGP AID during probing (e.g. Token2 PIN+, which
        // has no HID serial). Either way `serial` drives the header `#…` field.
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
            // First whitespace-delimited token of the reader name is usually the
            // manufacturer (e.g. "Nitrokey", "Yubico").
            p.reader_name
                .split_whitespace()
                .next()
                .unwrap_or("Key")
                .to_string()
        };
        let model = clean_model(&p.reader_name, &vendor);
        devices.push(UiDevice {
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

    // --- 3. Merge FIDO HID nodes into their physical key ------------------
    for (i, hid) in hids.iter().enumerate() {
        let serial = serials.get(i).cloned().flatten().unwrap_or_default();

        // The PC/SC reader name this HID node shares a physical key with, if any.
        // YubiKeys: match the CCID reader by USB topology (resolve's job).
        let reader_name: Option<String> = if hid.vendor_id == keyroost_resolve::VID_YUBICO {
            yk_readers
                .iter()
                .find(|c| {
                    c.usb_bus == hid.usb_bus
                        && c.usb_address == hid.usb_address
                        && c.usb_bus.is_some()
                })
                .or_else(|| {
                    // Single YubiKey reader, no usable topology: unambiguous.
                    let only: Vec<_> = yk_readers.iter().collect();
                    if only.len() == 1 {
                        Some(only[0])
                    } else {
                        None
                    }
                })
                .map(|c| c.reader_name.clone())
        } else {
            // Non-Yubico: correlate by the vendor token appearing in a reader
            // name (e.g. a Nitrokey HID node ↔ "Nitrokey 3 ..." reader). Only
            // merge on an unambiguous single match.
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

        // Find an existing device for that reader, or one already keyed by this
        // serial, and union FIDO2 + attach the hid_path. Otherwise this is a
        // FIDO-only key (no PC/SC applets provisioned) — add a fresh entry.
        let existing = devices.iter_mut().find(|d| {
            d.kind == DeviceKind::Key
                && ((reader_name.is_some() && d.reader == reader_name)
                    || (!serial.is_empty() && d.serial == serial))
        });
        if let Some(dev) = existing {
            dev.caps.insert(Caps::FIDO2);
            // Token2 FIDO keys (VID 0x349E) carry the on-device OTP applet,
            // reachable over CCID and/or HID. Offer the OTP tab for them.
            if hid.vendor_id == 0x349E {
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
            if hid.vendor_id == 0x349E {
                caps.insert(Caps::OTP);
            }
            devices.push(UiDevice {
                id,
                name: keyring.name_for(Some(&serial)).map(str::to_owned),
                vendor: vendor_name(hid.vendor_id).to_string(),
                model: clean_model(&hid.product_name, vendor_name(hid.vendor_id)),
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

    // Stable, readable order: keys first (by model), Molto2 tokens last.
    devices.sort_by(|a, b| {
        (a.kind == DeviceKind::Token)
            .cmp(&(b.kind == DeviceKind::Token))
            .then_with(|| a.model.cmp(&b.model))
            .then_with(|| a.id.cmp(&b.id))
    });
    Ok(devices)
}
