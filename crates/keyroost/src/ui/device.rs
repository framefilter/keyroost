// crates/keyroost/src/ui/device.rs
//
// View layer over the shared device model. The correlation/classification logic
// now lives in `keyroost-resolve` (consumed by the CLI too); here we keep only
// the GUI-specific capability-tab bar.

pub use keyroost_resolve::{enumerate, Caps, Device, DeviceId, DeviceKind};

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

/// GUI view helpers on the shared [`Device`]. An extension trait because `Device`
/// is defined in another crate.
pub trait DeviceView {
    fn title(&self) -> &str;
    fn tabs(&self) -> Vec<CapTab>;
}

impl DeviceView for Device {
    fn title(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.model)
    }

    fn tabs(&self) -> Vec<CapTab> {
        if self.kind == DeviceKind::Token {
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
