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
}
