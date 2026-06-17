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
#[derive(Clone, Copy, PartialEq, Eq)]
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
        "CCID/ICCD Interface", "OTP+FIDO+CCID", "FIDO+CCID", "OTP+FIDO", "U2F+CCID",
        "+CCID", "ICCD", "CCID", "Interface", "Smartcard", "Smart Card",
    ] {
        s = s.replace(junk, " ");
    }
    let lead = s.trim_start();
    if !vendor.is_empty()
        && lead.to_ascii_lowercase().starts_with(&vendor.to_ascii_lowercase())
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
    if out.is_empty() { vendor.to_string() } else { out }
}

pub fn correlate(_hids: &[HidDevice], _probes: &[ReaderProbe], _keyring: &Keyring) -> Vec<Device> {
    Vec::new()
}
pub fn enumerate() -> Result<Vec<Device>, String> {
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

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
            clean_model("SoloKeys Solo 2 [CCID/ICCD Interface] (07A9) 01 00", "SoloKeys"),
            "Solo 2"
        );
        assert_eq!(clean_model("Yubico YubiKey OTP+FIDO+CCID 00 00", "Yubico"), "YubiKey");
        assert_eq!(clean_model("Nitrokey 3", "Nitrokey"), "3");
    }

    #[test]
    fn vendor_name_maps_known_vids() {
        assert_eq!(vendor_name(0x1050), "Yubico");
        assert_eq!(vendor_name(0x1209), "SoloKeys");
        assert_eq!(vendor_name(0x349e), "Token2");
        assert_eq!(vendor_name(0xffff), "Security key");
    }
}
