// crates/keyroost/src/ui/device.rs
//
// View layer over the shared device model. The correlation/classification logic
// now lives in `keyroost-resolve` (consumed by the CLI too); here we keep only
// the GUI-specific capability-tab bar.

pub use keyroost_resolve::{enumerate, CapState, Caps, Device, DeviceId, DeviceKind};

/// Which capability pane is showing for the selected device.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum CapTab {
    #[default]
    Overview,
    Fido2,
    Oath,
    Pgp,
    Piv,
    Otp,
}

/// The capability a tab manages, if it maps to one (`Overview` does not).
pub fn tab_cap(t: CapTab) -> Option<Caps> {
    match t {
        CapTab::Overview => None,
        CapTab::Fido2 => Some(Caps::FIDO2),
        CapTab::Oath => Some(Caps::OATH),
        CapTab::Pgp => Some(Caps::PGP),
        CapTab::Piv => Some(Caps::PIV),
        CapTab::Otp => Some(Caps::OTP),
    }
}

/// GUI view helpers on the shared [`Device`]. An extension trait because `Device`
/// is defined in another crate.
pub trait DeviceView {
    fn title(&self) -> &str;
    fn tabs(&self) -> Vec<CapTab>;
    /// True when the tab's capability is offered without device evidence
    /// ([`CapState::Unverified`]) — the tab still appears and works, it is
    /// only rendered with a quiet "not verified" affordance.
    fn tab_unverified(&self, t: CapTab) -> bool;
}

impl DeviceView for Device {
    fn title(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.model)
    }

    fn tab_unverified(&self, t: CapTab) -> bool {
        tab_cap(t).is_some_and(|c| self.cap_state(c) == CapState::Unverified)
    }

    fn tabs(&self) -> Vec<CapTab> {
        if self.kind == DeviceKind::Token || self.kind == DeviceKind::ProgToken {
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
