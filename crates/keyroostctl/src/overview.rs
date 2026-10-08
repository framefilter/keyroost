//! Friendly, correlated device output for `keyroostctl`: the bare invocation's
//! aligned-columns overview and the `list` command's "Correlated devices"
//! summary. All formatting is pure and unit-tested; the `print_*` fns are thin
//! stdout wrappers.

use crate::sanitize_terminal;
use keyroost_resolve::{CapState, Device, DeviceKind};

/// The display label: the friendly name when set, else the model. Sanitized —
/// the model comes from the device's USB descriptor and the name from
/// user-editable `keys.json`, so both are attacker-influenced.
fn label(dev: &Device) -> String {
    sanitize_terminal(dev.name.as_deref().unwrap_or(&dev.model))
}

/// Capability badges joined for display, e.g. "FIDO2 · OATH · PGP · PIV".
/// A capability keyroost could not check against the device renders with a
/// trailing "?" (e.g. "OTP?"): offered as always, but never claimed as
/// verified present.
fn badge_line(dev: &Device) -> String {
    dev.cap_badge_states()
        .into_iter()
        .map(|(label, state)| match state {
            CapState::Unverified => format!("{label}?"),
            _ => label.to_string(),
        })
        .collect::<Vec<_>>()
        .join(" · ")
}

/// Short serial for the at-a-glance overview: first 8 chars, "…" if longer.
/// (The full serial lives in `keyroostctl list`.) Sanitized: the serial is a
/// device-supplied string.
fn short_serial(serial: &str) -> String {
    let serial = sanitize_terminal(serial);
    if serial.chars().count() <= 8 {
        serial
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

/// Rows paired with their `list` number (1-based, `keyroost_resolve::list_order`)
/// — the numbers `--device N` accepts.
pub fn numbered(devices: &[Device]) -> Vec<(usize, &Device)> {
    keyroost_resolve::list_order(devices)
        .into_iter()
        .enumerate()
        .map(|(pos, i)| (pos + 1, &devices[i]))
        .collect()
}

/// The aligned overview rows (the "Connected devices" header is added by the
/// printer). Returns one line per row, columns padded to the widest value,
/// prefixed with the row's `list` number.
pub fn overview_lines(rows: &[(usize, &Device)]) -> Vec<String> {
    if rows.is_empty() {
        return vec!["No devices connected.".to_string()];
    }
    let wv = rows
        .iter()
        .map(|(_, d)| d.vendor.chars().count())
        .max()
        .unwrap_or(0);
    let wm = rows
        .iter()
        .map(|(_, d)| label(d).chars().count())
        .max()
        .unwrap_or(0);
    let wb = rows
        .iter()
        .map(|(_, d)| badge_line(d).chars().count())
        .max()
        .unwrap_or(0);
    let ws = rows
        .iter()
        .map(|(_, d)| short_serial(&d.serial).chars().count())
        .max()
        .unwrap_or(0);
    rows.iter()
        .map(|(n, d)| {
            format!(
                "{n:>2}) {:wv$}  {:wm$}  {:wb$}  {:ws$}  {}",
                sanitize_terminal(&d.vendor),
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
/// its `list` number · kind · vendor model · badges · the reader/HID it paired.
pub fn correlated_lines(rows: &[(usize, &Device)]) -> Vec<String> {
    if rows.is_empty() {
        return vec!["  (no devices)".to_string()];
    }
    rows.iter()
        .map(|(n, d)| {
            let kind = match d.kind {
                DeviceKind::Token => "Token",
                DeviceKind::ProgToken => "Programmable token",
                DeviceKind::Key => "Key",
            };
            // The reader name embeds the USB product string; sanitize it. The
            // HID path is a device node (e.g. /dev/hidraw0), sanitized for
            // uniformity.
            let pairing = match (&d.hid_path, &d.reader) {
                (Some(p), Some(r)) => format!(
                    "{} + '{}'",
                    sanitize_terminal(&p.display().to_string()),
                    sanitize_terminal(r)
                ),
                (Some(p), None) => sanitize_terminal(&p.display().to_string()),
                (None, Some(r)) => format!("'{}' (no HID)", sanitize_terminal(r)),
                (None, None) => "(none)".to_string(),
            };
            format!(
                "  {n:>2}) {:5}  {} {}  {}  {}",
                kind,
                sanitize_terminal(&d.vendor),
                label(d),
                badge_line(d),
                pairing
            )
        })
        .collect()
}

/// Print the bare-invocation friendly overview to stdout.
pub fn print_overview(rows: &[(usize, &Device)]) {
    println!("Connected devices");
    println!();
    for line in overview_lines(rows) {
        println!("{line}");
    }
}

/// Print the `list` "Correlated devices" summary section to stdout.
pub fn print_correlated(rows: &[(usize, &Device)]) {
    println!("Correlated devices (what keyroost sees):");
    for line in correlated_lines(rows) {
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
            unverified: Caps::default(),
            kind,
            hid_path: None,
            reader: None,
            naming: Default::default(),
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
    fn rows_are_numbered_in_list_order() {
        let a = dev(
            "Yubico",
            "YubiKey 5",
            Some("b-key"),
            "22222222",
            "USB",
            caps_of(&[Caps::FIDO2]),
            DeviceKind::Key,
        );
        let b = dev(
            "SoloKeys",
            "Solo 2",
            None,
            "11111111",
            "USB",
            caps_of(&[Caps::FIDO2]),
            DeviceKind::Key,
        );
        let devs = [a, b];
        let lines = overview_lines(&numbered(&devs));
        assert!(
            lines[0].starts_with(" 1) ") && lines[0].contains("Solo 2"),
            "{lines:?}"
        );
        assert!(
            lines[1].starts_with(" 2) ") && lines[1].contains("b-key"),
            "{lines:?}"
        );
        let corr = correlated_lines(&numbered(&devs));
        assert!(corr[0].starts_with("   1) "), "{corr:?}");
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
        let lines = overview_lines(&numbered(&devices));
        assert!(lines[0].contains("work-key"));
        assert!(lines[0].contains("FIDO2 · OATH · PGP · PIV"));
        assert!(lines[1].contains("Token2"));
        assert!(lines[1].contains("TOTP token"));
        let m0 = lines[0].find("work-key").unwrap();
        let m1 = lines[1].find("Molto2").unwrap();
        assert_eq!(m0, m1);
    }

    #[test]
    fn device_strings_flatten_terminal_escapes() {
        // A hostile USB device puts ANSI/control bytes in its descriptor
        // strings; neither overview nor the correlated summary may emit them raw.
        let mut d = dev(
            "Yub\x1b[31mico",
            "K\x1b]0;pwn\x07ey",
            None,
            "AB\x1bCD\u{9b}6n",
            "USB · PC/SC",
            caps_of(&[Caps::FIDO2]),
            DeviceKind::Key,
        );
        d.reader = Some("Rd\x1b[2Jr".into());

        let devs = std::slice::from_ref(&d);
        for line in overview_lines(&numbered(devs)) {
            assert!(
                !line.chars().any(|c| c.is_control()),
                "overview line leaked a control char: {line:?}"
            );
        }
        for line in correlated_lines(&numbered(devs)) {
            assert!(
                !line.chars().any(|c| c.is_control()),
                "correlated line leaked a control char: {line:?}"
            );
        }
    }

    #[test]
    fn unverified_badges_carry_a_question_mark() {
        // A Token2 key seen only over USB-HID: OTP is offered on the vendor
        // hint but was never checked against the device — the badge must say
        // so ("OTP?"), in both the overview and the correlated summary.
        let mut d = dev(
            "Token2",
            "PIN+",
            None,
            "S1",
            "USB · FIDO HID",
            caps_of(&[Caps::FIDO2, Caps::OTP]),
            DeviceKind::Key,
        );
        d.unverified.insert(Caps::OTP);
        let devs = std::slice::from_ref(&d);
        let lines = overview_lines(&numbered(devs));
        assert!(lines[0].contains("FIDO2 · OTP?"), "got: {}", lines[0]);
        let lines = correlated_lines(&numbered(devs));
        assert!(lines[0].contains("FIDO2 · OTP?"), "got: {}", lines[0]);

        // Verified capabilities keep the bare label.
        d.unverified = Caps::default();
        let devs = std::slice::from_ref(&d);
        let lines = overview_lines(&numbered(devs));
        assert!(lines[0].contains("FIDO2 · OTP"));
        assert!(!lines[0].contains("OTP?"));
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
        let devs = [d];
        let lines = correlated_lines(&numbered(&devs));
        assert!(lines[0].contains("Token"));
        assert!(lines[0].contains("TOTP token"));
        assert!(lines[0].contains("(no HID)"));
    }
}
