//! Target selection glue: the global `--device` plus a command's
//! `--reader` / `--path` → one `Device` via `keyroost_resolve::resolve_target`,
//! the one announce line every device command prints, and a per-process
//! memo so a command never resolves (or announces) twice.

use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use keyroost_resolve::{
    endpoint, resolve_target, Caps, Device, DeviceKind, EnumerateOptions, Need, Picker,
    SelectError, Selector,
};

use crate::prompt::{RealTerm, TermPicker};
use crate::sanitize_terminal;

/// The global `--debug`, captured once in `run()`.
pub(crate) static DEBUG: OnceLock<bool> = OnceLock::new();
static RESOLVED: Mutex<Option<(Need, Device)>> = Mutex::new(None);

pub(crate) fn debug_on() -> bool {
    DEBUG.get().copied().unwrap_or(false)
}

pub(crate) fn device_flag() -> Option<&'static str> {
    crate::SELECTED_KEY_NAME.get().and_then(|o| o.as_deref())
}

/// The shared device model, with identity reads traced under `--debug`.
pub(crate) fn enumerate() -> Result<Vec<Device>, Box<dyn Error>> {
    Ok(keyroost_resolve::enumerate_with(&EnumerateOptions {
        debug: debug_on(),
        skip_identity_reads: false,
        skip_key_names: false,
    })?)
}

/// The shared device model with identity reads but without reading the
/// names stored on keys (local names only). Selection adds those names only
/// when the choice could depend on them (see [`select_from`]).
pub(crate) fn enumerate_without_key_names() -> Result<Vec<Device>, Box<dyn Error>> {
    Ok(keyroost_resolve::enumerate_with(&EnumerateOptions {
        debug: debug_on(),
        skip_identity_reads: false,
        skip_key_names: true,
    })?)
}

/// The device list without identity reads (topology, vendor and reported
/// serials only): for scans that must stay fast or must not talk to an
/// unidentified key, such as the FIDO reset's post-replug look.
pub(crate) fn enumerate_without_identity_reads() -> Result<Vec<Device>, Box<dyn Error>> {
    Ok(keyroost_resolve::enumerate_with(&EnumerateOptions {
        debug: debug_on(),
        skip_identity_reads: true,
        skip_key_names: true,
    })?)
}

/// `→ <name or model> · serial <S> · <reader | path>` (serial omitted when
/// unknown; reader or path chosen by what `need` opens).
pub(crate) fn announce_line(d: &Device, need: Need) -> String {
    let mut line = format!(
        "\u{2192} {}",
        sanitize_terminal(d.name.as_deref().unwrap_or(&d.model))
    );
    if !d.serial.is_empty() {
        line.push_str(&format!(" \u{b7} serial {}", sanitize_terminal(&d.serial)));
    }
    let via = endpoint(d, need);
    if !via.is_empty() {
        line.push_str(&format!(" \u{b7} {via}"));
    }
    line
}

/// The announce line for a `--reader` / `--path` that matched no detected key.
fn typed_announce_line(typed: &str) -> String {
    format!(
        "\u{2192} {} (not detected; using it as typed)",
        sanitize_terminal(typed)
    )
}

const OVERRIDE_PREFIX: &str = "override:";

/// The `--reader` / `--path` typed for a stand-in row (see [`typed_device`]);
/// `None` for a detected key.
pub(crate) fn typed_value(d: &Device) -> Option<&str> {
    d.id.strip_prefix(OVERRIDE_PREFIX)
}

/// A stand-in row for an expert `--reader` / `--path` that matched no
/// detected key: the command opens exactly what was typed.
fn typed_device(reader: Option<String>, hid_path: Option<PathBuf>, typed: &str) -> Device {
    Device {
        id: format!("{OVERRIDE_PREFIX}{typed}"),
        name: None,
        vendor: String::new(),
        model: "key not detected".into(),
        serial: String::new(),
        transport: String::new(),
        firmware: String::new(),
        caps: Caps::default(),
        unverified: Caps::default(),
        kind: DeviceKind::Key,
        hid_path,
        reader,
        hid_serial: None,
        naming: Default::default(),
    }
}

/// Pick the row and its announce line. An unmatched `--reader` / `--path`
/// passes through as typed; every other selection error is returned.
fn choose(
    devices: &[Device],
    sel: &Selector<'_>,
    need: Need,
    picker: &mut dyn Picker,
) -> Result<(Device, String), SelectError> {
    match resolve_target(devices, sel, need, picker) {
        Ok(t) => Ok((t.device.clone(), announce_line(t.device, need))),
        Err(SelectError::ReaderNotFound { reader }) => Ok((
            typed_device(Some(reader.clone()), None, &reader),
            typed_announce_line(&reader),
        )),
        Err(SelectError::PathNotFound { path }) => Ok((
            typed_device(None, Some(PathBuf::from(&path)), &path),
            typed_announce_line(&path),
        )),
        Err(e) => Err(e),
    }
}

/// Return the memoised row for `need`, else run `resolve` and remember it.
fn memoised(
    memo: &Mutex<Option<(Need, Device)>>,
    need: Need,
    resolve: impl FnOnce() -> Result<Device, Box<dyn Error>>,
) -> Result<Device, Box<dyn Error>> {
    if let Some((n, d)) = memo.lock().map_err(|_| "target lock poisoned")?.as_ref() {
        if *n == need {
            return Ok(d.clone());
        }
    }
    let dev = resolve()?;
    *memo.lock().map_err(|_| "target lock poisoned")? = Some((need, dev.clone()));
    Ok(dev)
}

/// Resolve and announce the key this command acts on (once per process
/// per need; later calls return the same row without re-enumerating).
pub(crate) fn select(
    need: Need,
    reader: Option<&str>,
    path: Option<&Path>,
) -> Result<Device, Box<dyn Error>> {
    memoised(&RESOLVED, need, || {
        let sel = Selector {
            device: device_flag(),
            reader,
            path,
        };
        let mut term = RealTerm;
        let mut picker = TermPicker::new(&mut term);
        let (dev, line) = select_from(
            enumerate_without_key_names,
            |devices: &mut Vec<Device>| keyroost_resolve::add_key_names(devices, debug_on()),
            &sel,
            need,
            &mut picker,
        )?;
        eprintln!("{line}");
        Ok(dev)
    })
}

/// Scan with `scan` (no names read from keys), add them with `add_names`
/// only when the choice could depend on them — the name commands always,
/// otherwise per [`keyroost_resolve::selection_needs_key_names`] — then
/// choose. Reading a key's name costs a CTAP round trip per FIDO key, so a
/// key picked by serial, list number or override skips it.
fn select_from(
    scan: impl FnOnce() -> Result<Vec<Device>, Box<dyn Error>>,
    add_names: impl FnOnce(&mut Vec<Device>),
    sel: &Selector<'_>,
    need: Need,
    picker: &mut dyn Picker,
) -> Result<(Device, String), Box<dyn Error>> {
    let mut devices = scan()?;
    if need == Need::Nameable || keyroost_resolve::selection_needs_key_names(&devices, sel, need) {
        add_names(&mut devices);
    }
    Ok(choose(&devices, sel, need, picker)?)
}

/// The exact reader of the selected key (never re-matched as a substring).
pub(crate) fn reader_for(need: Need, reader: Option<&str>) -> Result<String, Box<dyn Error>> {
    reader_of(&select(need, reader, None)?)
}

/// The exact reader of an already-selected smart-card row.
pub(crate) fn reader_of(dev: &Device) -> Result<String, Box<dyn Error>> {
    dev.reader
        .clone()
        .ok_or_else(|| Box::<dyn Error>::from("internal error: a smart-card row without a reader"))
}

pub(crate) fn add_bootloader_hint(e: Box<dyn Error>, bootloader: Option<&str>) -> Box<dyn Error> {
    let no_key = matches!(
        e.downcast_ref::<SelectError>(),
        Some(SelectError::NoCandidates { .. })
    );
    match (no_key, bootloader) {
        (true, Some(bl)) => {
            format!("{e} (Detected {bl} \u{2014} re-plug it to return to application mode.)").into()
        }
        _ => e,
    }
}

/// Extract the HID path a resolved FIDO row carries. Every row `select` can
/// return for `Need::FidoHid` has one: a detected row admitted by that need
/// requires `hid_path`, and an unmatched `--path` passes through as a typed
/// row carrying the path it was given.
pub(crate) fn hid_path_of(dev: &Device) -> Result<PathBuf, Box<dyn Error>> {
    dev.hid_path.clone().ok_or_else(|| {
        Box::<dyn Error>::from("internal error: a FIDO-over-USB row without a HID path")
    })
}

/// Select the FIDO-over-USB key, adding the bootloader hint when none is found.
pub(crate) fn select_fido(path: Option<&Path>) -> Result<Device, Box<dyn Error>> {
    select(Need::FidoHid, None, path).map_err(|e| {
        let bl = keyroost_hid::bootloader_device_present().map(|b| b.to_string());
        add_bootloader_hint(e, bl.as_deref())
    })
}

/// The HID path of the selected FIDO key.
pub(crate) fn fido_path(path: Option<&Path>) -> Result<PathBuf, Box<dyn Error>> {
    hid_path_of(&select_fido(path)?)
}

/// What re-enumerating after a confirmation question says about the key
/// the user confirmed against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Recheck {
    /// Still there, and its serial (if it reports one) is unchanged.
    Same,
    /// Nothing to re-find: a stand-in row for an undetected `--reader` /
    /// `--path`, or a row without any endpoint.
    Skip,
    /// One of its endpoints is no longer present.
    Gone,
    /// A different serial now answers at one of its endpoints.
    Changed,
    /// Its endpoints are present, but none reports a serial to compare.
    Unconfirmed,
}

/// Re-find `before` in a fresh enumeration `now`, by the exact reader and
/// HID path it was selected at.
pub(crate) fn recheck(before: &Device, now: &[Device]) -> Recheck {
    if typed_value(before).is_some() || (before.reader.is_none() && before.hid_path.is_none()) {
        return Recheck::Skip;
    }
    let reader_back = before
        .reader
        .as_ref()
        .is_none_or(|r| now.iter().any(|d| d.reader.as_ref() == Some(r)));
    let path_back = before
        .hid_path
        .as_ref()
        .is_none_or(|p| now.iter().any(|d| d.hid_path.as_ref() == Some(p)));
    if !reader_back || !path_back {
        return Recheck::Gone;
    }
    if before.serial.is_empty() {
        return Recheck::Same;
    }
    let shares_endpoint = |d: &&Device| {
        (before.reader.is_some() && d.reader == before.reader)
            || (before.hid_path.is_some() && d.hid_path == before.hid_path)
    };
    let serials: Vec<&str> = now
        .iter()
        .filter(shares_endpoint)
        .map(|d| d.serial.as_str())
        .filter(|s| !s.is_empty())
        .collect();
    if serials.iter().any(|s| *s != before.serial) {
        Recheck::Changed
    } else if serials.is_empty() {
        Recheck::Unconfirmed
    } else {
        Recheck::Same
    }
}

/// Decide whether `first` (the identity-read-free look) is final, or
/// whether `full_look` — the second look, with identity reads — must be
/// consulted and trusted instead. `Same` and `Gone` are final: the first
/// look can tell those apart without identity reads. `Changed` and
/// `Unconfirmed` cannot be trusted on their own, because the first look
/// can't bind a HID row and a reader row by identity — a split (or
/// unreadable) serial there can look like `Changed` even when the two rows
/// are the same key — so both escalate to the full look, which decides.
fn reverify_verdict(
    first: Recheck,
    full_look: impl FnOnce() -> Result<Recheck, Box<dyn Error>>,
) -> Result<Recheck, Box<dyn Error>> {
    if matches!(first, Recheck::Changed | Recheck::Unconfirmed) {
        full_look()
    } else {
        Ok(first)
    }
}

/// After a question was actually shown, make sure the key the command is
/// about to reopen (by reader name or HID path) is still the one confirmed:
/// a same-model key plugged in meanwhile can reuse both. See
/// [`reverify_verdict`] for which first-look results are escalated.
pub(crate) fn reverify(before: &Device) -> Result<(), Box<dyn Error>> {
    let first = recheck(before, &enumerate_without_identity_reads()?);
    let verdict = reverify_verdict(first, || {
        Ok(recheck(before, &enumerate_without_key_names()?))
    })?;
    let label = crate::prompt::key_label(before);
    match verdict {
        Recheck::Same => Ok(()),
        Recheck::Skip => {
            if debug_on() {
                eprintln!(
                    "[target] {label}: not a detected key; not re-checked after waiting for input"
                );
            }
            Ok(())
        }
        Recheck::Gone | Recheck::Changed => Err(format!(
            "the key changed while waiting for a confirmation or a typed secret ({label}); nothing was changed"
        )
        .into()),
        Recheck::Unconfirmed => Err(format!(
            "could not re-read the serial of {label} after waiting for input; nothing was changed"
        )
        .into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyroost_resolve::NoPicker;
    use std::cell::Cell;

    fn dev(name: Option<&str>, serial: &str) -> Device {
        Device {
            id: "t".into(),
            name: name.map(str::to_owned),
            vendor: "Yubico".into(),
            model: "YubiKey 5 NFC".into(),
            serial: serial.into(),
            transport: String::new(),
            firmware: String::new(),
            caps: Caps::default(),
            unverified: Caps::default(),
            kind: DeviceKind::Key,
            hid_path: Some("/dev/hidraw16".into()),
            reader: Some("Yubico YubiKey OTP+FIDO+CCID 00 00".into()),
            hid_serial: None,
            naming: keyroost_resolve::Naming::local(name),
        }
    }

    /// Two FIDO keys over USB with distinct serials and paths.
    fn two_fido_keys() -> Vec<Device> {
        let mut a = dev(None, "12345678");
        a.id = "serial:12345678".into();
        a.caps = Caps::FIDO2;
        a.reader = None;
        a.hid_path = Some("/dev/hidraw1".into());
        let mut b = dev(None, "ABCDEF01");
        b.id = "serial:ABCDEF01".into();
        b.caps = Caps::FIDO2;
        b.reader = None;
        b.hid_path = Some("/dev/hidraw2".into());
        vec![a, b]
    }

    /// Run `select_from` over `devices` with a name reader that counts calls.
    fn name_reads(
        devices: Vec<Device>,
        device: Option<&str>,
        path: Option<&Path>,
        need: Need,
    ) -> (usize, Result<Device, String>) {
        let reads = Cell::new(0);
        let sel = Selector {
            device,
            reader: None,
            path,
        };
        let got = select_from(
            || Ok(devices),
            |_: &mut Vec<Device>| reads.set(reads.get() + 1),
            &sel,
            need,
            &mut NoPicker,
        )
        .map(|(d, _)| d)
        .map_err(|e| e.to_string());
        (reads.get(), got)
    }

    #[test]
    fn a_serial_picked_command_never_reads_key_names() {
        for v in ["12345678", "serial:12345678", "list:1", "1"] {
            let (reads, got) = name_reads(two_fido_keys(), Some(v), None, Need::FidoHid);
            assert_eq!(reads, 0, "{v}");
            assert_eq!(got.unwrap().serial, "12345678", "{v}");
        }
        // A --path override and a lone candidate need no names either.
        let p = Path::new("/dev/hidraw2");
        assert_eq!(
            name_reads(two_fido_keys(), None, Some(p), Need::FidoHid).0,
            0
        );
        let one = two_fido_keys().into_iter().take(1).collect();
        assert_eq!(name_reads(one, None, None, Need::FidoHid).0, 0);
    }

    #[test]
    fn a_value_that_could_be_a_name_reads_key_names_once() {
        for v in ["Work", "name:Work"] {
            assert_eq!(
                name_reads(two_fido_keys(), Some(v), None, Need::FidoHid).0,
                1,
                "{v}"
            );
        }
        // Several candidates (picker or refusal) and the name commands do too.
        assert_eq!(name_reads(two_fido_keys(), None, None, Need::FidoHid).0, 1);
        assert_eq!(
            name_reads(two_fido_keys(), Some("12345678"), None, Need::Nameable).0,
            1
        );
    }

    #[test]
    fn announce_names_key_serial_and_endpoint() {
        assert_eq!(
            announce_line(&dev(Some("yubi-test"), "12345678"), Need::Piv),
            "\u{2192} yubi-test \u{b7} serial 12345678 \u{b7} Yubico YubiKey OTP+FIDO+CCID 00 00"
        );
        assert_eq!(
            announce_line(&dev(None, ""), Need::FidoHid),
            "\u{2192} YubiKey 5 NFC \u{b7} /dev/hidraw16"
        );
        let mut evil = dev(Some("a\u{1b}[2Jb"), "1\u{1b}");
        evil.reader = None;
        evil.hid_path = Some("/dev/x\u{1b}[2J".into());
        assert!(!announce_line(&evil, Need::Piv).contains('\u{1b}'));
    }

    #[test]
    fn announce_without_any_endpoint_has_no_trailing_separator() {
        let mut d = dev(None, "");
        d.reader = None;
        d.hid_path = None;
        assert_eq!(announce_line(&d, Need::Piv), "\u{2192} YubiKey 5 NFC");
    }

    #[test]
    fn unmatched_reader_or_path_passes_through_as_typed() {
        let devices = vec![dev(Some("k"), "1")];
        let sel = Selector {
            device: None,
            reader: Some("Other\u{1b}[2J Reader"),
            path: None,
        };
        let (d, line) = choose(&devices, &sel, Need::Piv, &mut NoPicker).unwrap();
        assert_eq!(d.reader.as_deref(), Some("Other\u{1b}[2J Reader"));
        assert!(d.hid_path.is_none());
        assert_eq!(d.model, "key not detected");
        assert!(d.id.starts_with("override:"));
        assert!(line.ends_with("(not detected; using it as typed)"));
        assert!(!line.contains('\u{1b}'));

        let p = PathBuf::from("/dev/hidraw99");
        let sel = Selector {
            device: None,
            reader: None,
            path: Some(&p),
        };
        let (d, line) = choose(&devices, &sel, Need::FidoHid, &mut NoPicker).unwrap();
        assert_eq!(d.hid_path.as_deref(), Some(p.as_path()));
        assert!(d.reader.is_none());
        assert_eq!(
            line,
            "\u{2192} /dev/hidraw99 (not detected; using it as typed)"
        );
    }

    #[test]
    fn fido_path_extracts_the_typed_path_from_an_unmatched_passthrough_row() {
        // An unmatched --path --device::select/choose() passes through as a
        // synthetic row carrying the typed path (see
        // `unmatched_reader_or_path_passes_through_as_typed` above); fido_path()
        // must hand that path back rather than treating it as an internal error.
        let p = PathBuf::from("/dev/hidraw99");
        let row = typed_device(None, Some(p.clone()), "/dev/hidraw99");
        assert_eq!(hid_path_of(&row).unwrap(), p);
    }

    #[test]
    fn other_selection_errors_propagate() {
        let devices = vec![dev(Some("k"), "1")];
        let p = PathBuf::from("/dev/hidraw16");
        let sel = Selector {
            device: Some("k"),
            reader: None,
            path: Some(&p),
        };
        assert!(matches!(
            choose(&devices, &sel, Need::FidoHid, &mut NoPicker),
            Err(SelectError::Conflict)
        ));
    }

    #[test]
    fn memo_resolves_once_per_need() {
        let memo = Mutex::new(None);
        let calls = Cell::new(0);
        let resolve = |serial: &'static str| {
            let calls = &calls;
            move || {
                calls.set(calls.get() + 1);
                Ok(dev(None, serial))
            }
        };
        assert_eq!(
            memoised(&memo, Need::Piv, resolve("1")).unwrap().serial,
            "1"
        );
        // Same need: the remembered row, resolver not called again.
        assert_eq!(
            memoised(&memo, Need::Piv, resolve("2")).unwrap().serial,
            "1"
        );
        assert_eq!(calls.get(), 1);
        // A different need resolves afresh.
        assert_eq!(
            memoised(&memo, Need::FidoHid, resolve("3")).unwrap().serial,
            "3"
        );
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn recheck_after_the_question() {
        let before = dev(Some("k"), "12345678");
        // Same serial at the same endpoints.
        assert_eq!(
            recheck(&before, std::slice::from_ref(&before)),
            Recheck::Same
        );
        // A different key now answers at the same reader / path.
        let swapped = dev(None, "87654321");
        assert_eq!(recheck(&before, &[swapped]), Recheck::Changed);
        // Gone entirely, or one of its endpoints is.
        assert_eq!(recheck(&before, &[]), Recheck::Gone);
        let mut no_hid = before.clone();
        no_hid.hid_path = None;
        assert_eq!(recheck(&before, &[no_hid.clone()]), Recheck::Gone);
        // Split rows (no identity reads): the reader row keeps the serial.
        let mut hid_only = dev(None, "");
        hid_only.reader = None;
        assert_eq!(
            recheck(&before, &[no_hid.clone(), hid_only.clone()]),
            Recheck::Same
        );
        // …but any different serial at either endpoint is a swap.
        let mut other_on_hid = dev(None, "87654321");
        other_on_hid.reader = None;
        assert_eq!(recheck(&before, &[no_hid, other_on_hid]), Recheck::Changed);
        // Present but no serial visible anywhere: can't confirm.
        let mut no_serial_reader = dev(None, "");
        no_serial_reader.hid_path = None;
        assert_eq!(
            recheck(&before, &[no_serial_reader, hid_only]),
            Recheck::Unconfirmed
        );
        // A serial-less key passes when its endpoints are still there…
        let serial_less = dev(None, "");
        assert_eq!(
            recheck(&serial_less, std::slice::from_ref(&serial_less)),
            Recheck::Same
        );
        // …and is refused when they are not.
        assert_eq!(recheck(&serial_less, &[]), Recheck::Gone);
        // A stand-in for an undetected --reader / --path is never re-found.
        let typed = typed_device(Some("Some Reader".into()), None, "Some Reader");
        assert_eq!(recheck(&typed, &[]), Recheck::Skip);
    }

    #[test]
    fn reverify_escalates_past_a_false_changed_or_unconfirmed_first_look() {
        // A first look that can't bind sides by identity may call a split
        // row Changed, or see no serial at all (Unconfirmed); neither is
        // final — the full look (with identity reads) decides instead.
        assert_eq!(
            reverify_verdict(Recheck::Changed, || Ok(Recheck::Same)).unwrap(),
            Recheck::Same
        );
        assert_eq!(
            reverify_verdict(Recheck::Unconfirmed, || Ok(Recheck::Same)).unwrap(),
            Recheck::Same
        );
        // A full look can still confirm the swap.
        assert_eq!(
            reverify_verdict(Recheck::Changed, || Ok(Recheck::Changed)).unwrap(),
            Recheck::Changed
        );
        // Same, Gone and Skip are final: the (hardware-touching) full look
        // is never consulted for them.
        for first in [Recheck::Same, Recheck::Gone, Recheck::Skip] {
            assert_eq!(
                reverify_verdict(first, || panic!("full look must not run")).unwrap(),
                first
            );
        }
    }

    #[test]
    fn typed_value_only_for_stand_in_rows() {
        let typed = typed_device(None, Some("/dev/hidraw99".into()), "/dev/hidraw99");
        assert_eq!(typed_value(&typed), Some("/dev/hidraw99"));
        assert_eq!(typed_value(&dev(None, "1")), None);
    }

    #[test]
    fn prompt_label_for_a_stand_in_row_is_what_was_typed() {
        let typed = typed_device(
            Some("Other\u{1b}[2J Reader".into()),
            None,
            "Other\u{1b}[2J Reader",
        );
        let label = crate::prompt::key_label(&typed);
        assert!(!label.contains("not detected"), "{label}");
        assert!(
            label.starts_with("Other") && label.ends_with("Reader"),
            "{label}"
        );
        assert!(!label.contains('\u{1b}'));
        assert_eq!(
            crate::prompt::key_label(&dev(Some("k"), "1")),
            "k (serial 1)"
        );
    }

    #[test]
    fn bootloader_hint_only_on_no_candidates() {
        let none: Box<dyn std::error::Error> = Box::new(SelectError::NoCandidates {
            need: Need::FidoHid,
            connected: Vec::new(),
        });
        assert!(add_bootloader_hint(none, Some("Solo 2 bootloader"))
            .to_string()
            .contains("re-plug it"));
        let other: Box<dyn std::error::Error> = Box::new(SelectError::Conflict);
        assert!(!add_bootloader_hint(other, Some("x"))
            .to_string()
            .contains("re-plug"));
    }
}
