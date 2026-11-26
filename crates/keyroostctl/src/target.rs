//! Target selection glue: the global `--device` plus a command's
//! `--reader` / `--path` → one `Device` via `keyroost_resolve::resolve_target`,
//! the one announce line every device command prints, and a per-process
//! memo so a command never resolves (or announces) twice.

use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use keyroost_resolve::{
    endpoint, list_number, resolve_target, resolve_target_reading, row_label,
    selection_needs_key_names, Caps, Choice, Device, DeviceKind, EnumerateOptions, Need, NoPicker,
    Picker, SelectError, Selector,
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
        skip_protocol_asks: false,
        skip_molto2_reads: false,
    })?)
}

/// The shared device model with identity reads but without reading the
/// names stored on keys (local names only), and without asking a Molto2
/// its serial (one read earlier in this run is used): for the re-check
/// after a question, which runs for every kind of key, so a `fido` or
/// `oath` command doesn't connect to a Molto2 there either. A Molto2 the
/// command acts on was read by its selection scan.
pub(crate) fn enumerate_without_key_names() -> Result<Vec<Device>, Box<dyn Error>> {
    Ok(keyroost_resolve::enumerate_with(&EnumerateOptions {
        debug: debug_on(),
        skip_identity_reads: false,
        skip_key_names: true,
        skip_protocol_asks: false,
        skip_molto2_reads: true,
    })?)
}

/// The selection scan for a command that acts on a key `need` admits, with
/// identity reads and no names stored on keys: a Molto2 is asked its
/// printed serial only when the command could pick one (a `molto` command,
/// `name`, or any key), so `fido`, `oath` and the like never connect to it.
fn enumerate_for(need: Need) -> Result<Vec<Device>, Box<dyn Error>> {
    Ok(keyroost_resolve::enumerate_with(&EnumerateOptions {
        debug: debug_on(),
        skip_identity_reads: false,
        skip_key_names: true,
        skip_protocol_asks: false,
        skip_molto2_reads: !may_pick_a_molto2(need),
    })?)
}

/// Whether a refusal lists connected keys for the user to choose from.
fn lists_keys(e: &SelectError) -> bool {
    matches!(
        e,
        SelectError::NoCandidates { .. }
            | SelectError::NeedsChoice { .. }
            | SelectError::NotFound { .. }
            | SelectError::Ambiguous { .. }
            | SelectError::NameNotConnected { .. }
            | SelectError::LacksCapability { .. }
    )
}

/// Whether selection failed because the `--device` value matched no row.
fn matched_nothing(e: &(dyn Error + 'static)) -> bool {
    matches!(
        e.downcast_ref::<SelectError>(),
        Some(SelectError::NotFound { .. } | SelectError::NameNotConnected { .. })
    )
}

/// Whether a command with `need` could act on a Molto2. Every need is
/// listed, so a new one has to be decided here.
fn may_pick_a_molto2(need: Need) -> bool {
    match need {
        Need::Molto2 | Need::Nameable | Need::Any => true,
        Need::FidoHid
        | Need::FidoAny
        | Need::Oath
        | Need::OpenPgp
        | Need::Piv
        | Need::Otp
        | Need::OtpHid
        | Need::OtpCcid
        | Need::FeitianOtp
        | Need::Prog
        | Need::FactoryReset => false,
    }
}

/// The device list without identity reads (topology, vendor and reported
/// serials only): for scans that must stay fast or must not talk to an
/// unidentified key, such as the FIDO reset's post-replug look.
pub(crate) fn enumerate_without_identity_reads() -> Result<Vec<Device>, Box<dyn Error>> {
    Ok(keyroost_resolve::enumerate_with(&EnumerateOptions {
        debug: debug_on(),
        skip_identity_reads: true,
        skip_key_names: true,
        skip_protocol_asks: true,
        skip_molto2_reads: true,
    })?)
}

/// `→ <name or model> · serial <S> · <reader | path>` (serial omitted when
/// unknown; reader or path chosen by what `need` opens).
pub(crate) fn announce_line(d: &Device, need: Need) -> String {
    announce_via(d, &endpoint(d, need))
}

/// [`announce_line`] for a key picked with `--reader`: the line names the
/// reader the command goes through, even for a need that would otherwise
/// open the key's HID path (`fido info --reader`).
fn announce_line_for(d: &Device, need: Need, sel: &Selector<'_>) -> String {
    match (sel.reader, &d.reader) {
        (Some(_), Some(reader)) => announce_via(d, &sanitize_terminal(reader)),
        _ => announce_line(d, need),
    }
}

/// The announce line with `via` (already sanitised) as its endpoint.
fn announce_via(d: &Device, via: &str) -> String {
    let mut line = format!(
        "\u{2192} {}",
        sanitize_terminal(&d.name.clone().unwrap_or_else(|| d.model_title()))
    );
    if !d.serial.is_empty() {
        line.push_str(&format!(
            " \u{b7} serial {}",
            sanitize_terminal(&keyroost_resolve::serial_for_display(&d.serial))
        ));
    }
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
        former_serial: None,
        naming: Default::default(),
        smart_card_unlisted: false,
    }
}

/// A Molto2's card serial (what `molto info` shows), read in a short
/// session of its own; `None` when the token doesn't answer, after a note
/// saying so (the refusal that follows would otherwise read as if no
/// Molto2 were there). Selection calls it only when `--device` matched
/// nothing without it.
pub(crate) fn molto_card_serial(d: &Device) -> Option<String> {
    let reader = d.reader.as_deref()?;
    let read = || -> Result<String, keyroost_transport::TransportError> {
        let mut session = keyroost_transport::Session::open_named(reader)?;
        session.set_debug(debug_on());
        Ok(session.read_info()?.serial)
    };
    match read() {
        Ok(serial) => Some(
            serial
                .trim_matches(|c: char| c == '\0' || c.is_whitespace())
                .to_owned(),
        ),
        Err(e) => {
            crate::output::note(&unanswered_molto(reader, &e.to_string()));
            None
        }
    }
}

/// The note for a Molto2 whose card serial couldn't be read.
fn unanswered_molto(reader: &str, err: &str) -> String {
    format!(
        "a Molto2 is connected ({}) but didn't answer when its serial was read ({}), \
         so --device couldn't be compared with it",
        sanitize_terminal(reader),
        sanitize_terminal(err)
    )
}

/// Pick the row and its announce line. An unmatched `--reader` / `--path`
/// passes through as typed; every other selection error is returned.
fn choose(
    devices: &[Device],
    sel: &Selector<'_>,
    need: Need,
    picker: &mut dyn Picker,
) -> Result<(Device, String), SelectError> {
    match resolve_target_reading(devices, sel, need, picker, &mut molto_card_serial) {
        Ok(t) => Ok((t.device.clone(), announce_line_for(t.device, need, sel))),
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
        let pick = |scan_need: Need, picker: &mut dyn Picker| {
            select_from(
                || enumerate_for(scan_need),
                |devices: &mut Vec<Device>| keyroost_resolve::add_key_names(devices, debug_on()),
                |dev: &mut Device| {
                    keyroost_resolve::add_fido_models(std::slice::from_mut(dev), debug_on())
                },
                &sel,
                need,
                picker,
            )
        };
        let picked = match pick(need, &mut picker) {
            // The scan didn't ask a Molto2 its serial (this command can't
            // act on one), so a --device naming one by serial or name found
            // nothing. Scan once more, reading it, so the refusal says the
            // token can't do this rather than that nothing matches.
            Err(e) if !may_pick_a_molto2(need) && matched_nothing(e.as_ref()) => {
                pick(Need::Any, &mut picker)
            }
            r => r,
        };
        let (dev, line) =
            picked.map_err(|e| add_admin_hint(e, need, crate::admin_only_fido_key_present))?;
        errln!("{line}");
        Ok(dev)
    })
}

/// Scan with `scan` (no names read from keys), add them with `add_names`
/// only when the choice could depend on them — the name commands always,
/// otherwise per [`keyroost_resolve::selection_needs_key_names`] — then
/// choose. Reading a key's name costs a CTAP round trip per FIDO key, so a
/// key picked by serial, list number or override skips it. The chosen key
/// is then named by its model with `add_model` (one getInfo, unless the
/// name reads already made it), so its line says what the app's header
/// says.
fn select_from(
    scan: impl FnOnce() -> Result<Vec<Device>, Box<dyn Error>>,
    add_names: impl FnOnce(&mut Vec<Device>),
    add_model: impl FnOnce(&mut Device),
    sel: &Selector<'_>,
    need: Need,
    picker: &mut dyn Picker,
) -> Result<(Device, String), Box<dyn Error>> {
    let mut devices = scan()?;
    let mut add_names = Some(add_names);
    if need == Need::Nameable || keyroost_resolve::selection_needs_key_names(&devices, sel, need) {
        if let Some(add) = add_names.take() {
            add(&mut devices);
        }
    }
    let (mut dev, line) = match choose(&devices, sel, need, picker) {
        Ok(chosen) => chosen,
        // A refusal that lists keys to choose from names them as the other
        // refusals do (names stored on keys, full model names), not by the
        // short labels a scan that skipped those reads gives: read them now,
        // on this error path only, and build the refusal again.
        Err(e) if lists_keys(&e) => match add_names.take() {
            Some(add) => {
                add(&mut devices);
                choose(&devices, sel, need, picker)?
            }
            None => return Err(e.into()),
        },
        Err(e) => return Err(e.into()),
    };
    // A --reader / --path passed through as typed is no detected key.
    if typed_value(&dev).is_some() {
        return Ok((dev, line));
    }
    let before = dev.model.clone();
    add_model(&mut dev);
    if dev.model == before {
        return Ok((dev, line));
    }
    let line = announce_line_for(&dev, need, sel);
    Ok((dev, line))
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

/// Windows lets only an administrator open a key's FIDO USB interface, so a
/// program that isn't running as one finds no key for a need that opens it
/// (FIDO2 over USB, Token2 OTP over USB-HID). When a FIDO key is plugged in
/// all the same, say why. `admin_only_fido` is asked only for such an error;
/// it is always false off Windows.
pub(crate) fn add_admin_hint(
    e: Box<dyn Error>,
    need: Need,
    admin_only_fido: impl FnOnce() -> bool,
) -> Box<dyn Error> {
    let opens_hid = matches!(need, Need::FidoHid | Need::FidoAny | Need::OtpHid);
    let no_key = matches!(
        e.downcast_ref::<SelectError>(),
        Some(SelectError::NoCandidates { .. } | SelectError::LacksCapability { .. })
    );
    if opens_hid && no_key && admin_only_fido() {
        format!(
            "{e}. A FIDO key is plugged in, but Windows only lets an administrator open it; \
             run keyroostctl from an administrator terminal"
        )
        .into()
    } else {
        e
    }
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

/// Select a FIDO key over USB or a smart-card reader, adding the bootloader
/// hint when none is found.
pub(crate) fn select_fido_any(
    reader: Option<&str>,
    path: Option<&Path>,
) -> Result<Device, Box<dyn Error>> {
    select(Need::FidoAny, reader, path).map_err(|e| {
        let bl = keyroost_hid::bootloader_device_present().map(|b| b.to_string());
        add_bootloader_hint(e, bl.as_deref())
    })
}

/// Two rows naming the same physical key: the same resolver id, or the same
/// USB HID path. Used both to refuse `--a`/`--b` naming one key and to
/// exclude the named side from the auto-pick candidates.
fn same_physical(a: &Device, b: &Device) -> bool {
    a.id == b.id || (a.hid_path.is_some() && a.hid_path == b.hid_path)
}

/// Refuse a pair naming the same physical key twice.
fn same_pair_check(a: Device, b: Device) -> Result<(Device, Device), Box<dyn Error>> {
    if same_physical(&a, &b) {
        return Err("--a and --b name the same key; pass two different keys".into());
    }
    Ok((a, b))
}

/// Resolve one explicit compare side with no picker: an exact value must match
/// exactly, like `--device`. Errors name the flag passed (`--a`/`--b`), not
/// the global `--device` the resolver message is written for.
fn resolve_compare_side_explicit(
    devices: &[Device],
    sel: &Selector<'_>,
    flag: &str,
    side: &str,
) -> Result<Device, Box<dyn Error>> {
    let rewrite = |e: SelectError| -> Box<dyn Error> {
        format!("{side}: {}", e.to_string().replace("--device", flag)).into()
    };
    match resolve_target(devices, sel, Need::FidoHid, &mut NoPicker) {
        Ok(t) => Ok(t.device.clone()),
        // A Molto2 named by serial matches no FIDO row: rescan admitting any
        // key (which reads its serial) so the refusal says the key can't do
        // this, not that nothing matches — the same fallback `select` uses.
        Err(SelectError::NotFound { .. }) if sel.device.is_some() => {
            let mut any = enumerate_for(Need::Any)?;
            keyroost_resolve::add_key_names(&mut any, debug_on());
            resolve_target_reading(
                &any,
                sel,
                Need::FidoHid,
                &mut NoPicker,
                &mut molto_card_serial,
            )
            .map(|t| t.device.clone())
            .map_err(rewrite)
        }
        Err(e) => Err(rewrite(e)),
    }
}

/// The FIDO-over-USB rows of `devices` in `list` order, without `exclude`.
fn fido_candidates(devices: &[Device], exclude: Option<&Device>) -> Vec<usize> {
    keyroost_resolve::list_order(devices)
        .into_iter()
        .filter(|&i| Need::FidoHid.admits(&devices[i]))
        .filter(|&i| exclude.is_none_or(|x| !same_physical(&devices[i], x)))
        .collect()
}

/// Pick one row of `idxs` at the terminal for `side` (`key A`/`key B`), or
/// refuse with the standard list-the-keys error when not interactive.
fn pick_compare_side(
    devices: &[Device],
    idxs: &[usize],
    picker: &mut dyn Picker,
    side: &str,
) -> Result<Device, Box<dyn Error>> {
    if !picker.interactive() {
        // The standard refusal over the whole scan: it lists every candidate
        // with the selector value that names it.
        return resolve_target(devices, &Selector::default(), Need::FidoHid, &mut NoPicker)
            .map(|t| t.device.clone())
            .map_err(|e| {
                format!("{side}: {}", e.to_string().replace("--device", "--a/--b")).into()
            });
    }
    let choices: Vec<Choice> = idxs
        .iter()
        .map(|&i| Choice {
            number: list_number(devices, i).unwrap_or(0),
            label: row_label(&devices[i]),
            endpoint: endpoint(&devices[i], Need::FidoHid),
        })
        .collect();
    let k = picker
        .pick(
            &format!("Select {side} ({} connected keys qualify):", idxs.len()),
            &choices,
        )
        .map_err(|e| -> Box<dyn Error> { format!("{side}: {e}").into() })?;
    let i = *idxs.get(k).ok_or_else(|| -> Box<dyn Error> {
        format!("{side}: choice {k} is out of range").into()
    })?;
    Ok(devices[i].clone())
}

/// Pair `devices` (one enumerated scan) with the two compare selectors.
/// Explicit sides must match exactly; an unnamed side is the only remaining
/// FIDO row, or picked at the terminal; with neither side named, exactly two
/// connected keys are compared as-is. Takes the picker for the ambiguous
/// cases; an explicit side naming a Molto2 serial re-enumerates admitting any
/// key for the fallback refusal.
fn resolve_compare_pair(
    devices: &[Device],
    sel_a: &Selector<'_>,
    sel_b: &Selector<'_>,
    picker: &mut dyn Picker,
) -> Result<(Device, Device), Box<dyn Error>> {
    let explicit = |s: &Selector<'_>| s.device.is_some() || s.path.is_some();
    let exp_a = explicit(sel_a);
    let exp_b = explicit(sel_b);
    if exp_a && exp_b {
        let a = resolve_compare_side_explicit(devices, sel_a, "--a", "key A")?;
        let b = resolve_compare_side_explicit(devices, sel_b, "--b", "key B")?;
        return same_pair_check(a, b);
    }
    if exp_a || exp_b {
        // One side named: the other is the only remaining FIDO row, if there
        // is exactly one, else picked at the terminal.
        let (sel_named, flag_n, side_n, side_o, named_first) = if exp_a {
            (sel_a, "--a", "key A", "key B", true)
        } else {
            (sel_b, "--b", "key B", "key A", false)
        };
        let named = resolve_compare_side_explicit(devices, sel_named, flag_n, side_n)?;
        let rest = fido_candidates(devices, Some(&named));
        let other = match rest.as_slice() {
            [] => {
                return Err(format!(
                    "only one key with FIDO2 over USB is connected; connect a second key for {side_o}"
                )
                .into());
            }
            [i] => devices[*i].clone(),
            _ => pick_compare_side(devices, &rest, picker, side_o)?,
        };
        let (a, b) = if named_first {
            (named, other)
        } else {
            (other, named)
        };
        return same_pair_check(a, b);
    }
    let all = fido_candidates(devices, None);
    match all.as_slice() {
        [] => {
            let e = resolve_target(devices, &Selector::default(), Need::FidoHid, &mut NoPicker)
                .expect_err("no FIDO row, so no row can be picked");
            Err(e.into())
        }
        [i] => Err(format!(
            "only one key with FIDO2 over USB is connected ({}); connect a second key to compare",
            row_label(&devices[*i])
        )
        .into()),
        [first, second] => same_pair_check(devices[*first].clone(), devices[*second].clone()),
        _ => {
            let a = pick_compare_side(devices, &all, picker, "key A")?;
            let rest = fido_candidates(devices, Some(&a));
            let b = pick_compare_side(devices, &rest, picker, "key B")?;
            same_pair_check(a, b)
        }
    }
}

/// Select the two FIDO-over-USB keys `fido credential compare` compares:
/// explicit `--a`/`--b` sides must match exactly, otherwise two connected
/// keys are compared as-is and more are picked at the terminal. Prints one
/// announce line per key, like `select`, with the same bootloader/admin hints.
pub(crate) fn select_fido_pair(
    a_device: Option<&str>,
    a_path: Option<&Path>,
    b_device: Option<&str>,
    b_path: Option<&Path>,
) -> Result<(Device, Device), Box<dyn Error>> {
    let sel_a = Selector {
        device: a_device,
        reader: None,
        path: a_path,
    };
    let sel_b = Selector {
        device: b_device,
        reader: None,
        path: b_path,
    };
    let mut term = RealTerm;
    let mut picker = TermPicker::new(&mut term);
    let mut devices = enumerate_for(Need::FidoHid)?;
    if selection_needs_key_names(&devices, &sel_a, Need::FidoHid)
        || selection_needs_key_names(&devices, &sel_b, Need::FidoHid)
    {
        keyroost_resolve::add_key_names(&mut devices, debug_on());
    }
    let (mut a, mut b) =
        resolve_compare_pair(&devices, &sel_a, &sel_b, &mut picker).map_err(|e| {
            let bl = keyroost_hid::bootloader_device_present().map(|b| b.to_string());
            add_admin_hint(
                add_bootloader_hint(e, bl.as_deref()),
                Need::FidoHid,
                crate::admin_only_fido_key_present,
            )
        })?;
    // Name the chosen rows by model, as `select_from` does for its one row.
    for d in [&mut a, &mut b] {
        keyroost_resolve::add_fido_models(std::slice::from_mut(d), debug_on());
    }
    errln!("{}", announce_line(&a, Need::FidoHid));
    errln!("{}", announce_line(&b, Need::FidoHid));
    Ok((a, b))
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
                errln!(
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

    /// The rescan that reads a Molto2 runs only when a --device value
    /// matched no row, never for other refusals.
    #[test]
    fn only_a_value_that_matched_nothing_rescans() {
        let not_found: Box<dyn Error> = Box::new(SelectError::NotFound {
            value: "826658711763730".into(),
            need: Need::Otp,
            candidates: Vec::new(),
        });
        assert!(matched_nothing(not_found.as_ref()));
        let conflict: Box<dyn Error> = Box::new(SelectError::Conflict);
        assert!(!matched_nothing(conflict.as_ref()));
        let other: Box<dyn Error> = "some other failure".into();
        assert!(!matched_nothing(other.as_ref()));
    }

    /// A scan asks a Molto2 its serial exactly for the commands that could
    /// pick one: every need that admits a Molto2 row (with a serial, as a
    /// read gives it), and no other.
    #[test]
    fn only_commands_that_could_pick_a_molto2_read_its_serial() {
        let mut molto = typed_device(Some("TOKEN2 Molto2 0".into()), None, "x");
        molto.id = "molto:TOKEN2 Molto2 0".into();
        molto.kind = keyroost_resolve::DeviceKind::Token;
        molto.caps = keyroost_resolve::Caps::TOTP;
        molto.serial = "826658711763730".into();
        for need in [
            Need::FidoHid,
            Need::FidoAny,
            Need::Oath,
            Need::OpenPgp,
            Need::Piv,
            Need::Otp,
            Need::OtpHid,
            Need::OtpCcid,
            Need::Molto2,
            Need::Prog,
            Need::FactoryReset,
            Need::Nameable,
            Need::Any,
        ] {
            assert_eq!(may_pick_a_molto2(need), need.admits(&molto), "{need:?}");
        }
    }

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
            former_serial: None,
            naming: keyroost_resolve::Naming::local(name),
            smart_card_unlisted: false,
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
            |_: &mut Device| {},
            &sel,
            need,
            &mut NoPicker,
        )
        .map(|(d, _)| d)
        .map_err(|e| e.to_string());
        (reads.get(), got)
    }

    /// The chosen key's line names the model `add_model` gives it; only the
    /// chosen key is named, and a --path passed through as typed isn't.
    #[test]
    fn the_chosen_key_is_announced_by_its_model() {
        let sel = Selector {
            device: Some("serial:12345678"),
            reader: None,
            path: None,
        };
        let named = Cell::new(0);
        let (d, line) = select_from(
            || Ok(two_fido_keys()),
            |_: &mut Vec<Device>| {},
            |d: &mut Device| {
                named.set(named.get() + 1);
                d.model = "YubiKey 5 Series with NFC".into();
            },
            &sel,
            Need::FidoHid,
            &mut NoPicker,
        )
        .unwrap();
        assert_eq!(named.get(), 1);
        assert_eq!(d.model, "YubiKey 5 Series with NFC");
        assert!(
            line.starts_with("\u{2192} YubiKey 5 Series with NFC \u{b7} serial 12345678"),
            "{line}"
        );

        let typed = Selector {
            device: None,
            reader: None,
            path: Some(Path::new("/dev/hidraw99")),
        };
        let (_, line) = select_from(
            || Ok(two_fido_keys()),
            |_: &mut Vec<Device>| {},
            |_: &mut Device| panic!("a typed path is no key to read"),
            &typed,
            Need::FidoHid,
            &mut NoPicker,
        )
        .unwrap();
        assert!(line.contains("not detected"), "{line}");
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

    /// A refusal after a serial or list number names the keys it lists the
    /// way every other refusal does: names stored on keys and full model
    /// names are read for it, once, on that error path only.
    #[test]
    fn a_refusal_names_the_keys_it_lists() {
        let reads = Cell::new(0);
        for v in ["12345678", "1"] {
            reads.set(0);
            let sel = Selector {
                device: Some(v),
                reader: None,
                path: None,
            };
            // The second key has OATH, so the refusal lists it.
            let mut keys = two_fido_keys();
            keys[1].caps.insert(Caps::OATH);
            keys[1].reader = Some("Reader B".into());
            let err = select_from(
                || Ok(keys),
                |devices: &mut Vec<Device>| {
                    reads.set(reads.get() + 1);
                    for d in devices.iter_mut() {
                        d.model = "YubiKey 5 Series with NFC".into();
                    }
                },
                |_: &mut Device| {},
                &sel,
                Need::Oath,
                &mut NoPicker,
            )
            .err()
            .expect("an OATH command can't pick a FIDO-only key")
            .to_string();
            assert_eq!(reads.get(), 1, "{v}");
            assert!(err.contains("YubiKey 5 Series with NFC"), "{v}: {err}");
        }
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
    fn a_reader_selector_names_the_reader_even_for_a_fido_need() {
        let d = dev(None, "");
        let by_reader = Selector {
            reader: Some("Yubico YubiKey OTP+FIDO+CCID 00 00"),
            ..Selector::default()
        };
        assert_eq!(
            announce_line_for(&d, Need::FidoAny, &by_reader),
            "\u{2192} YubiKey 5 NFC \u{b7} Yubico YubiKey OTP+FIDO+CCID 00 00"
        );
        // Without --reader a FIDO need still names the HID path.
        assert_eq!(
            announce_line_for(&d, Need::FidoAny, &Selector::default()),
            "\u{2192} YubiKey 5 NFC \u{b7} /dev/hidraw16"
        );
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
    fn unanswered_molto_note_names_the_reader() {
        assert_eq!(
            unanswered_molto("TOKEN2 Molto2 (5C7D) 02 00", "timed out"),
            "a Molto2 is connected (TOKEN2 Molto2 (5C7D) 02 00) but didn't answer when \
             its serial was read (timed out), so --device couldn't be compared with it"
        );
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

    #[test]
    fn admin_hint_only_for_a_usb_need_with_a_hidden_fido_key() {
        let none = |need| -> Box<dyn std::error::Error> {
            Box::new(SelectError::NoCandidates {
                need,
                connected: Vec::new(),
            })
        };
        let hinted = |e, need, hidden| add_admin_hint(e, need, || hidden).to_string();
        for need in [Need::FidoHid, Need::FidoAny, Need::OtpHid] {
            assert!(hinted(none(need), need, true).contains("administrator"));
            assert!(!hinted(none(need), need, false).contains("administrator"));
        }
        // A smart-card need never opens the USB side.
        assert!(!hinted(none(Need::Piv), Need::Piv, true).contains("administrator"));
        // Nor does an error that isn't about finding no key.
        let other: Box<dyn std::error::Error> = Box::new(SelectError::Conflict);
        assert!(!hinted(other, Need::FidoHid, true).contains("administrator"));
    }

    /// A scripted picker for the compare pair tests: answers are indices into
    /// each `pick` call's choices, in order.
    struct FakePicker {
        interactive: bool,
        answers: std::collections::VecDeque<usize>,
        headings: Vec<String>,
    }
    impl FakePicker {
        fn answering(answers: &[usize]) -> Self {
            FakePicker {
                interactive: true,
                answers: answers.iter().copied().collect(),
                headings: Vec::new(),
            }
        }
        fn refusing() -> Self {
            FakePicker {
                interactive: false,
                answers: Default::default(),
                headings: Vec::new(),
            }
        }
    }
    impl Picker for FakePicker {
        fn interactive(&self) -> bool {
            self.interactive
        }
        fn pick(&mut self, heading: &str, _choices: &[Choice]) -> Result<usize, String> {
            self.headings.push(heading.to_string());
            self.answers
                .pop_front()
                .ok_or_else(|| "no more answers".to_string())
        }
    }

    fn side<'a>(device: Option<&'a str>, path: Option<&'a Path>) -> Selector<'a> {
        Selector {
            device,
            reader: None,
            path,
        }
    }

    fn pair_err(
        devices: &[Device],
        a: Selector<'_>,
        b: Selector<'_>,
        picker: &mut dyn Picker,
    ) -> String {
        match resolve_compare_pair(devices, &a, &b, picker) {
            Ok(_) => panic!("expected the pair to be refused"),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn compare_pair_explicit_sides_resolve_in_ab_order() {
        let devices = two_fido_keys();
        let (a, b) = resolve_compare_pair(
            &devices,
            &side(Some("ABCDEF01"), None),
            &side(Some("12345678"), None),
            &mut NoPicker,
        )
        .unwrap();
        assert_eq!(
            (a.serial.as_str(), b.serial.as_str()),
            ("ABCDEF01", "12345678")
        );
        // ... and by HID path.
        let (a, b) = resolve_compare_pair(
            &devices,
            &side(None, Some(Path::new("/dev/hidraw2"))),
            &side(None, Some(Path::new("/dev/hidraw1"))),
            &mut NoPicker,
        )
        .unwrap();
        assert_eq!(
            (a.serial.as_str(), b.serial.as_str()),
            ("ABCDEF01", "12345678")
        );
    }

    #[test]
    fn compare_pair_auto_picks_exactly_two_in_list_order() {
        let devices = two_fido_keys();
        let (a, b) = resolve_compare_pair(
            &devices,
            &side(None, None),
            &side(None, None),
            &mut NoPicker,
        )
        .unwrap();
        // List order sorts by serial: 12345678 before ABCDEF01.
        assert_eq!(a.serial, "12345678");
        assert_eq!(b.serial, "ABCDEF01");
    }

    #[test]
    fn compare_pair_one_named_side_auto_picks_the_other() {
        let devices = two_fido_keys();
        let (a, b) = resolve_compare_pair(
            &devices,
            &side(Some("ABCDEF01"), None),
            &side(None, None),
            &mut NoPicker,
        )
        .unwrap();
        assert_eq!(
            (a.serial.as_str(), b.serial.as_str()),
            ("ABCDEF01", "12345678")
        );
        let (a, b) = resolve_compare_pair(
            &devices,
            &side(None, None),
            &side(Some("12345678"), None),
            &mut NoPicker,
        )
        .unwrap();
        assert_eq!(
            (a.serial.as_str(), b.serial.as_str()),
            ("ABCDEF01", "12345678")
        );
    }

    #[test]
    fn compare_pair_refuses_the_same_key_twice() {
        let devices = two_fido_keys();
        let e = pair_err(
            &devices,
            side(Some("12345678"), None),
            side(Some("12345678"), None),
            &mut NoPicker,
        );
        assert!(e.contains("same key"), "{e}");
        // ... however the row is named twice.
        let e = pair_err(
            &devices,
            side(Some("12345678"), None),
            side(None, Some(Path::new("/dev/hidraw1"))),
            &mut NoPicker,
        );
        assert!(e.contains("same key"), "{e}");
    }

    #[test]
    fn compare_pair_alias_rows_count_as_the_same_key() {
        let mut devices = two_fido_keys();
        // Same physical key under a second id (e.g. friendly name vs
        // serial): the HID path is what ties the rows together.
        let mut alias = devices[0].clone();
        alias.id = "name:My Key".into();
        devices.push(alias.clone());
        assert!(same_physical(&devices[0], &alias));
        // The auto-pick exclusion drops both rows, leaving only the other key.
        assert_eq!(fido_candidates(&devices, Some(&devices[0])).len(), 1);
        // And pairing the two spellings is refused like any same-key pair.
        match same_pair_check(devices[0].clone(), alias) {
            Ok(_) => panic!("expected the alias pair to be refused"),
            Err(e) => assert!(e.to_string().contains("same key"), "{e}"),
        }
    }

    #[test]
    fn compare_pair_errors_name_the_side_flag() {
        let devices = two_fido_keys();
        let e = pair_err(
            &devices,
            side(Some("nope"), None),
            side(None, None),
            &mut NoPicker,
        );
        assert!(e.starts_with("key A: "), "{e}");
        assert!(e.contains("--a nope"), "{e}");
        assert!(!e.contains("--device"), "{e}");
    }

    #[test]
    fn compare_pair_picks_both_sides_at_the_terminal() {
        let mut devices = two_fido_keys();
        let mut third = dev(None, "ZZZZ9999");
        third.id = "serial:ZZZZ9999".into();
        third.caps = Caps::FIDO2;
        third.reader = None;
        third.hid_path = Some("/dev/hidraw3".into());
        devices.push(third);
        // List order by serial: 12345678, ABCDEF01, ZZZZ9999.
        let mut picker = FakePicker::answering(&[2, 0]);
        let (a, b) =
            resolve_compare_pair(&devices, &side(None, None), &side(None, None), &mut picker)
                .unwrap();
        assert_eq!(a.serial, "ZZZZ9999");
        assert_eq!(b.serial, "12345678");
        assert_eq!(
            picker.headings,
            vec![
                "Select key A (3 connected keys qualify):",
                "Select key B (2 connected keys qualify):",
            ]
        );
    }

    #[test]
    fn compare_pair_refuses_without_a_terminal_when_ambiguous() {
        let mut devices = two_fido_keys();
        let mut third = dev(None, "ZZZZ9999");
        third.id = "serial:ZZZZ9999".into();
        third.caps = Caps::FIDO2;
        third.reader = None;
        third.hid_path = Some("/dev/hidraw3".into());
        devices.push(third);
        let e = pair_err(
            &devices,
            side(None, None),
            side(None, None),
            &mut FakePicker::refusing(),
        );
        assert!(e.starts_with("key A: "), "{e}");
        assert!(e.contains("--a/--b"), "{e}");
        assert!(!e.contains("--device"), "{e}");
    }

    #[test]
    fn compare_pair_needs_two_connected_keys() {
        let one = vec![two_fido_keys()[0].clone()];
        let e = pair_err(&one, side(None, None), side(None, None), &mut NoPicker);
        assert!(e.contains("only one key"), "{e}");
        // One named side with nothing else connected names its missing half.
        let e = pair_err(
            &one,
            side(Some("12345678"), None),
            side(None, None),
            &mut NoPicker,
        );
        assert!(e.contains("key B"), "{e}");
        // None connected: the standard no-candidates refusal.
        let e = pair_err(&[], side(None, None), side(None, None), &mut NoPicker);
        assert!(e.contains("FIDO2 over USB"), "{e}");
    }
}
