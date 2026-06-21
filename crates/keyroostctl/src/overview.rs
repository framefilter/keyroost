//! Friendly, correlated device output for `keyroostctl`: the bare invocation's
//! aligned-columns overview and the `list` command's "Correlated devices"
//! summary. All formatting is pure and unit-tested; the `print_*` fns are thin
//! stdout wrappers.

use keyroost_resolve::{Device, DeviceKind};

/// The display label: the friendly name when set, else the model.
fn label(dev: &Device) -> &str {
    dev.name.as_deref().unwrap_or(&dev.model)
}

/// Capability badges joined for display, e.g. "FIDO2 · OATH · PGP · PIV".
fn badge_line(dev: &Device) -> String {
    dev.cap_badges().join(" · ")
}

/// Short serial for the at-a-glance overview: first 8 chars, "…" if longer.
/// (The full serial lives in `keyroostctl list`.)
fn short_serial(serial: &str) -> String {
    if serial.chars().count() <= 8 {
        serial.to_string()
    } else {
        let head: String = serial.chars().take(8).collect();
        format!("{head}…")
    }
}

/// Abbreviate the `Device.transport` string for the overview column
/// (e.g. "USB · PC/SC + FIDO HID" → "USB·PC/SC+HID").
fn short_transport(t: &str) -> String {
    t.replace("FIDO HID", "HID")
        .replace(" · ", "·")
        .replace(" + ", "+")
}

/// The aligned overview rows (the "Connected devices" header is added by the
/// printer). Returns one line per device, columns padded to the widest value.
pub fn overview_lines(devices: &[Device]) -> Vec<String> {
    if devices.is_empty() {
        return vec!["No devices connected.".to_string()];
    }
    let wv = devices
        .iter()
        .map(|d| d.vendor.chars().count())
        .max()
        .unwrap_or(0);
    let wm = devices
        .iter()
        .map(|d| label(d).chars().count())
        .max()
        .unwrap_or(0);
    let wb = devices
        .iter()
        .map(|d| badge_line(d).chars().count())
        .max()
        .unwrap_or(0);
    let ws = devices
        .iter()
        .map(|d| short_serial(&d.serial).chars().count())
        .max()
        .unwrap_or(0);
    devices
        .iter()
        .map(|d| {
            format!(
                "  {:wv$}  {:wm$}  {:wb$}  {:ws$}  {}",
                d.vendor,
                label(d),
                badge_line(d),
                short_serial(&d.serial),
                short_transport(&d.transport),
                wv = wv,
                wm = wm,
                wb = wb,
                ws = ws,
            )
        })
        .collect()
}

/// One line per correlated physical device for the `list` diagnostic summary:
/// kind · vendor model · badges · the reader/HID it paired.
pub fn correlated_lines(devices: &[Device]) -> Vec<String> {
    if devices.is_empty() {
        return vec!["  (no devices)".to_string()];
    }
    devices
        .iter()
        .map(|d| {
            let kind = match d.kind {
                DeviceKind::Token => "Token",
                DeviceKind::ProgToken => "Programmable token",
                DeviceKind::Key => "Key",
            };
            let pairing = match (&d.hid_path, &d.reader) {
                (Some(p), Some(r)) => format!("{} + '{}'", p.display(), r),
                (Some(p), None) => p.display().to_string(),
                (None, Some(r)) => format!("'{}' (no HID)", r),
                (None, None) => "(none)".to_string(),
            };
            format!(
                "  {:5}  {} {}  {}  {}",
                kind,
                d.vendor,
                label(d),
                badge_line(d),
                pairing
            )
        })
        .collect()
}

/// Print the bare-invocation friendly overview to stdout.
pub fn print_overview(devices: &[Device]) {
    println!("Connected devices");
    println!();
    for line in overview_lines(devices) {
        println!("{line}");
    }
}

/// Print the `list` "Correlated devices" summary section to stdout.
pub fn print_correlated(devices: &[Device]) {
    println!("Correlated devices (what keyroost sees):");
    for line in correlated_lines(devices) {
        println!("{line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyroost_resolve::{Caps, DeviceKind};

    fn dev(
        vendor: &str,
        model: &str,
        name: Option<&str>,
        serial: &str,
        transport: &str,
        caps: Caps,
        kind: DeviceKind,
    ) -> Device {
        Device {
            id: format!("test:{serial}"),
            name: name.map(str::to_owned),
            vendor: vendor.into(),
            model: model.into(),
            serial: serial.into(),
            transport: transport.into(),
            firmware: String::new(),
            caps,
            kind,
            hid_path: None,
            reader: None,
        }
    }

    fn caps_of(list: &[Caps]) -> Caps {
        let mut c = Caps::default();
        for &x in list {
            c.insert(x);
        }
        c
    }

    #[test]
    fn short_serial_truncates_only_when_long() {
        assert_eq!(short_serial("37806840"), "37806840");
        assert_eq!(short_serial("07A9568FBE31"), "07A9568F…");
        assert_eq!(short_serial(""), "");
    }

    #[test]
    fn short_transport_abbreviates() {
        assert_eq!(short_transport("USB · PC/SC + FIDO HID"), "USB·PC/SC+HID");
        assert_eq!(short_transport("USB · PC/SC"), "USB·PC/SC");
        assert_eq!(short_transport("USB · FIDO HID"), "USB·HID");
    }

    #[test]
    fn empty_list_says_none() {
        assert_eq!(overview_lines(&[]), vec!["No devices connected."]);
        assert_eq!(correlated_lines(&[]), vec!["  (no devices)"]);
    }

    #[test]
    fn overview_aligns_columns_and_uses_name_over_model() {
        let devices = [
            dev(
                "Yubico",
                "YubiKey",
                Some("work-key"),
                "37806840",
                "USB · PC/SC + FIDO HID",
                caps_of(&[Caps::FIDO2, Caps::OATH, Caps::PGP, Caps::PIV]),
                DeviceKind::Key,
            ),
            dev(
                "Token2",
                "Molto2",
                None,
                "5C7D6241EF67245B",
                "USB · PC/SC",
                caps_of(&[Caps::TOTP]),
                DeviceKind::Token,
            ),
        ];
        let lines = overview_lines(&devices);
        assert!(lines[0].contains("work-key"));
        assert!(lines[0].contains("FIDO2 · OATH · PGP · PIV"));
        assert!(lines[1].contains("Token2"));
        assert!(lines[1].contains("TOTP token"));
        let m0 = lines[0].find("work-key").unwrap();
        let m1 = lines[1].find("Molto2").unwrap();
        assert_eq!(m0, m1);
    }

    #[test]
    fn correlated_line_shows_kind_and_pairing() {
        let mut d = dev(
            "Token2",
            "Molto2",
            None,
            "5C7D",
            "USB · PC/SC",
            caps_of(&[Caps::TOTP]),
            DeviceKind::Token,
        );
        d.reader = Some("TOKEN2 Molto2 (5C7D) 02 00".into());
        let lines = correlated_lines(&[d]);
        assert!(lines[0].contains("Token"));
        assert!(lines[0].contains("TOTP token"));
        assert!(lines[0].contains("(no HID)"));
    }
}
