//! One key finder for every command: capability filter, `--device` /
//! `--reader` / `--path`, a stable list numbering, and the auto-pick /
//! picker / refuse decision. Pure — terminal I/O is injected through
//! [`Picker`], so the whole decision table is unit-tested.

use std::fmt;
use std::path::Path;

use crate::device::{factory_reset_plan, Caps, Device, DeviceKind};

/// What a command needs from the key it acts on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Need {
    FidoHid,
    FidoAny,
    Oath,
    OpenPgp,
    Piv,
    Otp,
    OtpHid,
    OtpCcid,
    Molto2,
    Prog,
    FactoryReset,
    Nameable,
    Any,
}

impl Need {
    /// "key with PIV" etc. — reads after "no … is connected".
    pub fn noun(self) -> &'static str {
        match self {
            Need::FidoHid => "key with FIDO2 over USB",
            Need::FidoAny => "key with FIDO2",
            Need::Oath => "key with OATH",
            Need::OpenPgp => "key with OpenPGP",
            Need::Piv => "key with PIV",
            Need::Otp => "key with Token2 OTP",
            Need::OtpHid => "key with Token2 OTP over USB-HID",
            Need::OtpCcid => "key with Token2 OTP over a smart-card reader",
            Need::Molto2 => "Molto2 token",
            Need::Prog => "programmable token",
            Need::FactoryReset => "key with something to factory-reset",
            Need::Nameable => "key that reports a serial (needed to name it)",
            Need::Any => "key or token",
        }
    }

    /// Whether a row can serve this need (capability plus the transport it uses).
    pub fn admits(self, d: &Device) -> bool {
        let (hid, card) = (d.hid_path.is_some(), d.reader.is_some());
        match self {
            Need::FidoHid => d.caps.has(Caps::FIDO2) && hid,
            Need::FidoAny => d.caps.has(Caps::FIDO2) && (hid || card),
            Need::Oath => d.caps.has(Caps::OATH) && card,
            Need::OpenPgp => d.caps.has(Caps::PGP) && card,
            Need::Piv => d.caps.has(Caps::PIV) && card,
            Need::Otp => d.caps.has(Caps::OTP) && (hid || card),
            Need::OtpHid => d.caps.has(Caps::OTP) && hid,
            Need::OtpCcid => d.caps.has(Caps::OTP) && card,
            Need::Molto2 => d.kind == DeviceKind::Token && card,
            Need::Prog => d.kind == DeviceKind::ProgToken && card,
            Need::FactoryReset => {
                d.kind == DeviceKind::Key && !factory_reset_plan(d.caps).is_empty()
            }
            Need::Nameable => !d.serial.is_empty(),
            Need::Any => true,
        }
    }

    /// Whether this need is served over a smart-card reader first (else the
    /// HID path is preferred). The single home of the need→transport choice.
    fn prefers_reader(self) -> bool {
        matches!(
            self,
            Need::Oath | Need::OpenPgp | Need::Piv | Need::OtpCcid | Need::Molto2 | Need::Prog
        )
    }
}

/// The selectors a command was given. At most one may be set.
#[derive(Clone, Copy, Debug, Default)]
pub struct Selector<'a> {
    pub device: Option<&'a str>,
    pub reader: Option<&'a str>,
    pub path: Option<&'a Path>,
}

/// A parsed `--device` value. `name:` / `serial:` / `list:` force the kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceSpec<'a> {
    /// Unprefixed: matches a name, a serial or a list number.
    Any(&'a str),
    Name(&'a str),
    Serial(&'a str),
    Number(usize),
    /// `list:` followed by something that is not a number; matches nothing.
    BadNumber(&'a str),
}

fn parse_number(s: &str) -> Option<usize> {
    (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        .then(|| s.parse().ok())
        .flatten()
}

/// Parse a `--device` value into the selector kind it names.
pub fn parse_device_spec(v: &str) -> DeviceSpec<'_> {
    if let Some(n) = v.strip_prefix("name:") {
        DeviceSpec::Name(n)
    } else if let Some(s) = v.strip_prefix("serial:") {
        DeviceSpec::Serial(s)
    } else if let Some(n) = v.strip_prefix("list:") {
        parse_number(n).map_or(DeviceSpec::BadNumber(n), DeviceSpec::Number)
    } else {
        DeviceSpec::Any(v)
    }
}

/// Row indices in `list` order: canonical identity (serial, case-folded),
/// rows without one last, ties by id. Stable across runs; numbers can
/// shift when keys are added — scripts should prefer names or serials.
pub fn list_order(devices: &[Device]) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..devices.len()).collect();
    idx.sort_by(|&a, &b| {
        let (x, y) = (&devices[a], &devices[b]);
        x.serial
            .is_empty()
            .cmp(&y.serial.is_empty())
            .then_with(|| {
                x.serial
                    .to_ascii_lowercase()
                    .cmp(&y.serial.to_ascii_lowercase())
            })
            .then_with(|| x.id.cmp(&y.id))
    });
    idx
}

/// 1-based `list` number of `devices[index]`.
pub fn list_number(devices: &[Device], index: usize) -> Option<usize> {
    list_order(devices)
        .iter()
        .position(|&i| i == index)
        .map(|p| p + 1)
}

/// Every row `spec` names, in list order, each once.
pub fn rows_matching(devices: &[Device], spec: DeviceSpec<'_>) -> Vec<usize> {
    let order = list_order(devices);
    let by_name = |n: &str| -> Vec<usize> {
        order
            .iter()
            .copied()
            .filter(|&i| devices[i].name.as_deref() == Some(n))
            .collect()
    };
    let by_serial = |s: &str| -> Vec<usize> {
        order
            .iter()
            .copied()
            .filter(|&i| !s.is_empty() && devices[i].serial.eq_ignore_ascii_case(s))
            .collect()
    };
    let by_number = |k: usize| -> Vec<usize> {
        k.checked_sub(1)
            .and_then(|p| order.get(p).copied())
            .into_iter()
            .collect()
    };
    let mut hits = match spec {
        DeviceSpec::Name(n) => by_name(n),
        DeviceSpec::Serial(s) => by_serial(s),
        DeviceSpec::Number(k) => by_number(k),
        DeviceSpec::BadNumber(_) => Vec::new(),
        DeviceSpec::Any(v) => {
            let mut h = by_name(v);
            h.extend(by_serial(v));
            if let Some(k) = parse_number(v) {
                h.extend(by_number(k));
            }
            h
        }
    };
    hits.sort_by_key(|i| order.iter().position(|j| j == i));
    hits.dedup();
    hits
}

/// The exact `--device` value that selects `devices[index]` and nothing
/// else: its name, serial or list number when that alone is unique, else
/// the prefixed form. Used by refusals and `list --json`.
pub fn device_value(devices: &[Device], index: usize) -> String {
    let d = &devices[index];
    let number = list_number(devices, index).unwrap_or(0);
    let mut tries: Vec<String> = Vec::new();
    if let Some(n) = &d.name {
        tries.push(n.clone());
    }
    if !d.serial.is_empty() {
        tries.push(d.serial.clone());
    }
    tries.push(number.to_string());
    if let Some(n) = &d.name {
        tries.push(format!("name:{n}"));
    }
    if !d.serial.is_empty() {
        tries.push(format!("serial:{}", d.serial));
    }
    tries
        .into_iter()
        .find(|v| rows_matching(devices, parse_device_spec(v)) == [index])
        .unwrap_or_else(|| format!("list:{number}"))
}

/// Replace terminal-hostile characters so a device-supplied string can't
/// spoof or break a one-line message.
fn clean(s: &str) -> String {
    s.chars()
        .map(|c| {
            if keyroost_keyring::is_spoofing_char(c) {
                '?'
            } else {
                c
            }
        })
        .collect()
}

/// "name, model, serial S" (name or model first; empty parts dropped).
pub fn row_label(d: &Device) -> String {
    let mut s = clean(d.name.as_deref().unwrap_or(&d.model));
    if d.name.is_some() && !d.model.is_empty() {
        s.push_str(&format!(", {}", clean(&d.model)));
    }
    if !d.serial.is_empty() {
        s.push_str(&format!(", serial {}", clean(&d.serial)));
    }
    s
}

/// The endpoint a command with `need` would open on `d`: its reader for
/// card-applet needs, else its HID path, each falling back to the other.
/// Sanitised for display.
pub fn endpoint(d: &Device, need: Need) -> String {
    let path = d.hid_path.as_ref().map(|p| p.display().to_string());
    let via = if need.prefers_reader() {
        d.reader.clone().or(path)
    } else {
        path.or_else(|| d.reader.clone())
    };
    clean(&via.unwrap_or_default())
}

/// POSIX-shell quoting for a copy-pasteable value.
pub fn shell_quote(v: &str) -> String {
    let safe = !v.is_empty()
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || "._:/@%+=,-".contains(c));
    if safe {
        v.to_string()
    } else {
        format!("'{}'", v.replace('\'', r"'\''"))
    }
}

/// One selectable row in a refusal: the exact value plus a label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub value: String,
    pub label: String,
}
impl fmt::Display for Candidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "--device {} ({})",
            shell_quote(&clean(&self.value)),
            self.label
        )
    }
}

/// One picker line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Choice {
    pub number: usize,
    pub label: String,
    pub endpoint: String,
}

/// Terminal I/O for the picker, injected by the front end.
pub trait Picker {
    /// True when a terminal can be asked.
    fn interactive(&self) -> bool;
    /// Ask; return the index into `choices`.
    fn pick(&mut self, heading: &str, choices: &[Choice]) -> Result<usize, String>;
}

/// A picker for contexts that must never ask (scripts, `list --device`).
pub struct NoPicker;
impl Picker for NoPicker {
    fn interactive(&self) -> bool {
        false
    }
    fn pick(&mut self, _: &str, _: &[Choice]) -> Result<usize, String> {
        Err("no terminal to choose on".into())
    }
}

/// How the row was chosen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectedBy {
    Device,
    Reader,
    Path,
    OnlyCandidate,
    Picked,
}

/// The resolved row.
#[derive(Clone, Copy)]
pub struct Target<'d> {
    pub device: &'d Device,
    /// Its 1-based `list` number.
    pub number: usize,
    pub how: SelectedBy,
}
impl fmt::Debug for Target<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Target")
            .field("id", &self.device.id)
            .field("number", &self.number)
            .field("how", &self.how)
            .finish()
    }
}

/// Why no row was chosen. Every message is one line and names the exact fix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SelectError {
    Conflict,
    NoCandidates {
        need: Need,
        connected: Vec<Candidate>,
    },
    NeedsChoice {
        need: Need,
        candidates: Vec<Candidate>,
    },
    NotFound {
        value: String,
        need: Need,
        candidates: Vec<Candidate>,
    },
    Ambiguous {
        value: String,
        matches: Vec<Candidate>,
    },
    LacksCapability {
        selector: String,
        need: Need,
        candidates: Vec<Candidate>,
    },
    /// Pass-through: the caller sends the typed value to the opener unchanged.
    /// `--reader` matched no detected row; `reader` is exactly what was typed.
    ReaderNotFound {
        reader: String,
    },
    ReaderAmbiguous {
        substr: String,
        readers: Vec<String>,
    },
    /// Pass-through: the caller sends the typed value to the opener unchanged.
    /// `--path` matched no detected row; `path` is exactly what was typed.
    PathNotFound {
        path: String,
    },
    Picker(String),
}

fn join(c: &[Candidate]) -> String {
    c.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" | ")
}
fn flags(flag: &str, values: &[String]) -> String {
    values
        .iter()
        .map(|v| format!("{flag} {}", shell_quote(&clean(v))))
        .collect::<Vec<_>>()
        .join(" | ")
}

impl fmt::Display for SelectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use SelectError::*;
        match self {
            Conflict => f.write_str(
                "pass only one of --device, --reader and --path (they may name different keys)",
            ),
            NoCandidates { need, connected } if connected.is_empty() => {
                write!(f, "no {} is connected", need.noun())
            }
            NoCandidates { need, connected } => write!(
                f,
                "no {} is connected; connected: {}",
                need.noun(),
                join(connected)
            ),
            NeedsChoice { need, candidates } => write!(
                f,
                "{} connected keys qualify ({}) and there is no terminal to ask on; choose one: {}",
                candidates.len(),
                need.noun(),
                join(candidates)
            ),
            NotFound {
                value,
                need,
                candidates,
            } if candidates.is_empty() => write!(
                f,
                "no connected key matches --device {} (by name, serial or list number), and no {} is connected",
                shell_quote(&clean(value)),
                need.noun()
            ),
            NotFound {
                value, candidates, ..
            } => write!(
                f,
                "no connected key matches --device {} (by name, serial or list number); choose one: {}",
                shell_quote(&clean(value)),
                join(candidates)
            ),
            Ambiguous { value, matches } => write!(
                f,
                "--device {} matches {} keys; choose one: {}",
                shell_quote(&clean(value)),
                matches.len(),
                join(matches)
            ),
            LacksCapability {
                selector,
                need,
                candidates,
            } if candidates.is_empty() => write!(
                f,
                "{selector} does not select a {}, and none is connected",
                need.noun()
            ),
            LacksCapability {
                selector,
                need,
                candidates,
            } => write!(
                f,
                "{selector} does not select a {}; choose one: {}",
                need.noun(),
                join(candidates)
            ),
            ReaderNotFound { reader } => write!(
                f,
                "no detected key matches reader '{}'; using it as typed",
                clean(reader)
            ),
            ReaderAmbiguous { substr, readers } => write!(
                f,
                "--reader {} matches several readers; choose one: {}",
                shell_quote(&clean(substr)),
                flags("--reader", readers)
            ),
            PathNotFound { path } => write!(
                f,
                "no detected key is at {}; using it as typed",
                clean(path)
            ),
            Picker(e) => f.write_str(&clean(e)),
        }
    }
}
impl std::error::Error for SelectError {}

/// Resolve the one row a command acts on.
///
/// - `--device` matches name, serial (case-insensitive) or list number, and
///   the row must serve `need`.
/// - `--reader` matches a reader name exactly (case-insensitive), else by a
///   unique case-insensitive substring; `--path` matches a HID path exactly.
///   Both are expert overrides: the matched row is used without the
///   capability check, and an unmatched value comes back as
///   [`SelectError::ReaderNotFound`] / [`SelectError::PathNotFound`] for the
///   caller to pass through as typed.
/// - No selector: a lone candidate is used, several go to the picker when it
///   is interactive, else refuse listing each candidate's `--device` value.
///
/// Never picks "the first found".
pub fn resolve_target<'d>(
    devices: &'d [Device],
    sel: &Selector<'_>,
    need: Need,
    picker: &mut dyn Picker,
) -> Result<Target<'d>, SelectError> {
    let given = usize::from(sel.device.is_some())
        + usize::from(sel.reader.is_some())
        + usize::from(sel.path.is_some());
    if given > 1 {
        return Err(SelectError::Conflict);
    }
    let order = list_order(devices);
    let number = |i: usize| order.iter().position(|&j| j == i).map_or(0, |p| p + 1);
    let candidates: Vec<usize> = order
        .iter()
        .copied()
        .filter(|&i| need.admits(&devices[i]))
        .collect();
    let describe = |rows: &[usize]| -> Vec<Candidate> {
        rows.iter()
            .map(|&i| Candidate {
                value: device_value(devices, i),
                label: row_label(&devices[i]),
            })
            .collect()
    };
    let target = |i: usize, how: SelectedBy| Target {
        device: &devices[i],
        number: number(i),
        how,
    };

    if let Some(v) = sel.device {
        let rows = rows_matching(devices, parse_device_spec(v));
        return match rows.as_slice() {
            [] => Err(SelectError::NotFound {
                value: v.to_string(),
                need,
                candidates: describe(&candidates),
            }),
            [i] if need.admits(&devices[*i]) => Ok(target(*i, SelectedBy::Device)),
            [_] => Err(SelectError::LacksCapability {
                selector: format!("--device {}", shell_quote(&clean(v))),
                need,
                candidates: describe(&candidates),
            }),
            many => Err(SelectError::Ambiguous {
                value: v.to_string(),
                matches: describe(many),
            }),
        };
    }

    if let Some(typed) = sel.reader {
        let pick_reader = |rows: Vec<usize>| -> Option<Result<Target<'d>, SelectError>> {
            match rows.as_slice() {
                [] => None,
                [i] => Some(Ok(target(*i, SelectedBy::Reader))),
                many => {
                    let mut readers: Vec<String> = many
                        .iter()
                        .filter_map(|&i| devices[i].reader.clone())
                        .collect();
                    readers.sort();
                    readers.dedup();
                    Some(Err(SelectError::ReaderAmbiguous {
                        substr: typed.to_string(),
                        readers,
                    }))
                }
            }
        };
        let rows_where = |hit: &dyn Fn(&str) -> bool| -> Vec<usize> {
            order
                .iter()
                .copied()
                .filter(|&i| devices[i].reader.as_deref().is_some_and(hit))
                .collect()
        };
        let needle = typed.to_ascii_lowercase();
        let exact = rows_where(&|r| r.eq_ignore_ascii_case(typed));
        let partial = || rows_where(&|r| r.to_ascii_lowercase().contains(&needle));
        return pick_reader(exact)
            .or_else(|| pick_reader(partial()))
            .unwrap_or_else(|| {
                Err(SelectError::ReaderNotFound {
                    reader: typed.to_string(),
                })
            });
    }

    if let Some(p) = sel.path {
        // A HID path belongs to one node, so at most one row carries it.
        return match order
            .iter()
            .copied()
            .find(|&i| devices[i].hid_path.as_deref() == Some(p))
        {
            Some(i) => Ok(target(i, SelectedBy::Path)),
            None => Err(SelectError::PathNotFound {
                path: p.display().to_string(),
            }),
        };
    }

    match candidates.as_slice() {
        [] => Err(SelectError::NoCandidates {
            need,
            connected: describe(&order),
        }),
        [i] => Ok(target(*i, SelectedBy::OnlyCandidate)),
        many if picker.interactive() => {
            let choices: Vec<Choice> = many
                .iter()
                .map(|&i| Choice {
                    number: number(i),
                    label: row_label(&devices[i]),
                    endpoint: endpoint(&devices[i], need),
                })
                .collect();
            let k = picker
                .pick(
                    &format!("{} connected keys qualify ({}):", many.len(), need.noun()),
                    &choices,
                )
                .map_err(SelectError::Picker)?;
            let i = *many
                .get(k)
                .ok_or_else(|| SelectError::Picker(format!("choice {k} is out of range")))?;
            Ok(target(i, SelectedBy::Picked))
        }
        many => Err(SelectError::NeedsChoice {
            need,
            candidates: describe(many),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::{Caps, DeviceKind};
    use std::path::PathBuf;

    fn row(
        name: Option<&str>,
        serial: &str,
        caps: &[Caps],
        hid: Option<&str>,
        reader: Option<&str>,
        kind: DeviceKind,
    ) -> Device {
        let mut c = Caps::default();
        for x in caps {
            c.insert(*x);
        }
        Device {
            id: format!("t:{serial}:{}", hid.or(reader).unwrap_or("")),
            name: name.map(str::to_owned),
            vendor: "Vendor".into(),
            model: "Model".into(),
            serial: serial.into(),
            transport: String::new(),
            firmware: String::new(),
            caps: c,
            unverified: Caps::default(),
            kind,
            hid_path: hid.map(PathBuf::from),
            reader: reader.map(str::to_owned),
        }
    }
    fn yubi() -> Device {
        row(
            Some("yubi-test"),
            "11111111",
            &[Caps::FIDO2, Caps::OATH, Caps::PIV],
            Some("/dev/hidraw16"),
            Some("Yubico YubiKey 00 00"),
            DeviceKind::Key,
        )
    }
    fn solo() -> Device {
        row(
            None,
            "07A9568FBE31AD5DAD1F2298476CF0D4",
            &[Caps::FIDO2, Caps::PIV],
            Some("/dev/hidraw14"),
            Some("SoloKeys Solo 2 01 00"),
            DeviceKind::Key,
        )
    }
    fn molto() -> Device {
        row(
            None,
            "",
            &[Caps::TOTP],
            None,
            Some("TOKEN2 Molto2 02 00"),
            DeviceKind::Token,
        )
    }

    struct FakePicker {
        interactive: bool,
        answer: Result<usize, String>,
        seen: Vec<Choice>,
    }
    impl Picker for FakePicker {
        fn interactive(&self) -> bool {
            self.interactive
        }
        fn pick(&mut self, _h: &str, choices: &[Choice]) -> Result<usize, String> {
            self.seen = choices.to_vec();
            self.answer.clone()
        }
    }
    fn sel<'a>(
        device: Option<&'a str>,
        reader: Option<&'a str>,
        path: Option<&'a std::path::Path>,
    ) -> Selector<'a> {
        Selector {
            device,
            reader,
            path,
        }
    }

    #[test]
    fn any_two_selectors_conflict() {
        let devs = [yubi()];
        let p = std::path::Path::new("/dev/hidraw16");
        for s in [
            sel(Some("yubi-test"), Some("Yubico"), None),
            sel(Some("yubi-test"), None, Some(p)),
            sel(None, Some("Yubico"), Some(p)),
        ] {
            assert_eq!(
                resolve_target(&devs, &s, Need::Piv, &mut NoPicker).unwrap_err(),
                SelectError::Conflict
            );
        }
    }

    #[test]
    fn lone_candidate_is_used_and_capability_filters() {
        let devs = [yubi(), molto()];
        let t = resolve_target(&devs, &Selector::default(), Need::Piv, &mut NoPicker).unwrap();
        assert_eq!(t.device.name.as_deref(), Some("yubi-test"));
        assert_eq!(t.how, SelectedBy::OnlyCandidate);
        let t = resolve_target(&devs, &Selector::default(), Need::Molto2, &mut NoPicker).unwrap();
        assert_eq!(t.device.kind, DeviceKind::Token);
    }

    #[test]
    fn several_candidates_without_terminal_refuse_with_exact_values() {
        let devs = [solo(), yubi(), molto()];
        let err =
            resolve_target(&devs, &Selector::default(), Need::Piv, &mut NoPicker).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("--device yubi-test"), "{msg}");
        assert!(
            msg.contains("--device 07A9568FBE31AD5DAD1F2298476CF0D4"),
            "{msg}"
        );
        assert!(!msg.contains('\n'));
        assert!(!msg.contains("Molto2"), "only candidates are listed: {msg}");
    }

    #[test]
    fn several_candidates_with_terminal_run_the_picker_in_list_order() {
        let devs = [yubi(), solo()];
        let mut p = FakePicker {
            interactive: true,
            answer: Ok(1),
            seen: Vec::new(),
        };
        let t = resolve_target(&devs, &Selector::default(), Need::Piv, &mut p).unwrap();
        // list order: by serial lowercase → "07a9…" (solo) is 1, "11111111" (yubi) is 2.
        assert_eq!(
            p.seen.iter().map(|c| c.number).collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(t.device.name.as_deref(), Some("yubi-test"));
        assert_eq!((t.number, t.how), (2, SelectedBy::Picked));
        let mut bad = FakePicker {
            interactive: true,
            answer: Err("'x' is not one of 1, 2".into()),
            seen: Vec::new(),
        };
        assert!(matches!(
            resolve_target(&devs, &Selector::default(), Need::Piv, &mut bad),
            Err(SelectError::Picker(_))
        ));
    }

    #[test]
    fn no_candidate_lists_what_is_connected() {
        let devs = [molto()];
        let msg = resolve_target(&devs, &Selector::default(), Need::Piv, &mut NoPicker)
            .unwrap_err()
            .to_string();
        assert!(msg.starts_with("no key with PIV is connected"), "{msg}");
        assert!(msg.contains("--device 1"), "{msg}");
    }

    #[test]
    fn device_by_name_serial_case_insensitive_and_number() {
        let devs = [yubi(), solo(), molto()];
        for v in [
            "yubi-test",
            "11111111",
            "2",
            "name:yubi-test",
            "serial:11111111",
            "list:2",
        ] {
            let t =
                resolve_target(&devs, &sel(Some(v), None, None), Need::Any, &mut NoPicker).unwrap();
            assert_eq!(t.device.name.as_deref(), Some("yubi-test"), "{v}");
        }
        let t = resolve_target(
            &devs,
            &sel(Some("07a9568fbe31ad5dad1f2298476cf0d4"), None, None),
            Need::Piv,
            &mut NoPicker,
        )
        .unwrap();
        assert_eq!(t.device.reader.as_deref(), Some("SoloKeys Solo 2 01 00"));
        assert!(matches!(
            resolve_target(
                &devs,
                &sel(Some("list:x"), None, None),
                Need::Any,
                &mut NoPicker
            ),
            Err(SelectError::NotFound { .. })
        ));
        assert!(matches!(
            resolve_target(&devs, &sel(Some("9"), None, None), Need::Any, &mut NoPicker),
            Err(SelectError::NotFound { .. })
        ));
    }

    #[test]
    fn every_rows_device_value_round_trips() {
        let mut twin = yubi();
        twin.id.push('#');
        twin.reader = Some("Yubico YubiKey 03 00".into());
        let devs = [yubi(), solo(), molto(), twin];
        for i in 0..devs.len() {
            let v = device_value(&devs, i);
            let t = resolve_target(&devs, &sel(Some(&v), None, None), Need::Any, &mut NoPicker)
                .unwrap();
            assert!(
                std::ptr::eq(t.device, &devs[i]),
                "value {v} must select row {i}"
            );
        }
    }

    #[test]
    fn digit_name_colliding_with_list_number_is_ambiguous() {
        // Row "2" by name is list #1; list #2 is another row.
        let mut a = solo();
        a.name = Some("2".into());
        let devs = [a, yubi()];
        let err = resolve_target(&devs, &sel(Some("2"), None, None), Need::Any, &mut NoPicker)
            .unwrap_err();
        let SelectError::Ambiguous { matches, .. } = &err else {
            panic!("{err}")
        };
        assert_eq!(matches.len(), 2);
        for c in matches {
            let t = resolve_target(
                &devs,
                &sel(Some(&c.value), None, None),
                Need::Any,
                &mut NoPicker,
            )
            .unwrap();
            assert_eq!(
                device_value(
                    &devs,
                    devs.iter().position(|d| std::ptr::eq(d, t.device)).unwrap()
                ),
                c.value
            );
        }
        assert_eq!(
            resolve_target(
                &devs,
                &sel(Some("name:2"), None, None),
                Need::Any,
                &mut NoPicker
            )
            .unwrap()
            .device
            .name
            .as_deref(),
            Some("2")
        );
        assert_eq!(
            resolve_target(
                &devs,
                &sel(Some("list:2"), None, None),
                Need::Any,
                &mut NoPicker
            )
            .unwrap()
            .device
            .name
            .as_deref(),
            Some("yubi-test")
        );
        // A name equal to its own row's number is one row, not two.
        let mut b = solo();
        b.name = Some("1".into());
        let devs = [b, yubi()];
        assert!(
            resolve_target(&devs, &sel(Some("1"), None, None), Need::Any, &mut NoPicker).is_ok()
        );
    }

    #[test]
    fn duplicate_identity_rows_fail_closed_on_serial_resolve_by_number() {
        let mut a = yubi();
        a.hid_path = None;
        let mut b = yubi();
        b.id = "t:11111111:#2".into();
        b.reader = None;
        let devs = [a, b];
        for v in ["yubi-test", "11111111"] {
            assert!(
                matches!(
                    resolve_target(&devs, &sel(Some(v), None, None), Need::Any, &mut NoPicker),
                    Err(SelectError::Ambiguous { .. })
                ),
                "{v}"
            );
        }
        assert!(
            resolve_target(&devs, &sel(Some("1"), None, None), Need::Any, &mut NoPicker).is_ok()
        );
        assert!(
            resolve_target(&devs, &sel(Some("2"), None, None), Need::Any, &mut NoPicker).is_ok()
        );
    }

    #[test]
    fn selected_row_without_the_capability_names_candidates() {
        let mut card_only = yubi();
        card_only.hid_path = None;
        let mut hid_only = row(
            None,
            "",
            &[Caps::FIDO2],
            Some("/dev/hidraw17"),
            None,
            DeviceKind::Key,
        );
        hid_only.model = "YubiKey 5".into();
        let devs = [card_only, hid_only];
        let err = resolve_target(
            &devs,
            &sel(Some("yubi-test"), None, None),
            Need::FidoHid,
            &mut NoPicker,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("--device yubi-test does not select a key with FIDO2 over USB"),
            "{msg}"
        );
        assert!(msg.contains("--device 2"), "{msg}");
    }

    #[test]
    fn exact_reader_name_beats_substring() {
        let mut a = yubi();
        a.reader = Some("Foo Reader 00 00".into());
        let mut b = solo();
        b.reader = Some("Foo Reader 00 00 Contactless".into());
        let devs = [a, b];
        let t = resolve_target(
            &devs,
            &sel(None, Some("foo reader 00 00"), None),
            Need::Piv,
            &mut NoPicker,
        )
        .unwrap();
        assert_eq!(t.device.reader.as_deref(), Some("Foo Reader 00 00"));
        assert_eq!(t.how, SelectedBy::Reader);
        let err = resolve_target(
            &devs,
            &sel(None, Some("Foo"), None),
            Need::Piv,
            &mut NoPicker,
        )
        .unwrap_err();
        let SelectError::ReaderAmbiguous { readers, .. } = &err else {
            panic!("{err}")
        };
        assert_eq!(
            readers,
            &["Foo Reader 00 00", "Foo Reader 00 00 Contactless"]
        );
        // --reader is an expert override: an exact name picks that row even
        // when it lacks the capability, and never falls to a substring candidate.
        let mut c = molto();
        c.reader = Some("Foo Reader 00 00".into());
        let devs = [c, devs[1].clone()];
        let t = resolve_target(
            &devs,
            &sel(None, Some("Foo Reader 00 00"), None),
            Need::Piv,
            &mut NoPicker,
        )
        .unwrap();
        assert_eq!(t.device.kind, DeviceKind::Token);
        // A unique substring also skips the capability check.
        let t = resolve_target(
            &devs,
            &sel(None, Some("contactless"), None),
            Need::Molto2,
            &mut NoPicker,
        )
        .unwrap();
        assert_eq!(
            t.device.reader.as_deref(),
            Some("Foo Reader 00 00 Contactless")
        );
        // A reader nobody detected is handed back verbatim for pass-through.
        assert_eq!(
            resolve_target(
                &devs,
                &sel(None, Some("Bar  Reader"), None),
                Need::Piv,
                &mut NoPicker
            )
            .unwrap_err(),
            SelectError::ReaderNotFound {
                reader: "Bar  Reader".into()
            }
        );
    }

    #[test]
    fn unknown_path_is_reported_for_pass_through() {
        let devs = [yubi(), molto()];
        let ok = resolve_target(
            &devs,
            &sel(None, None, Some(std::path::Path::new("/dev/hidraw16"))),
            Need::FidoHid,
            &mut NoPicker,
        )
        .unwrap();
        assert_eq!(ok.how, SelectedBy::Path);
        assert_eq!(ok.device.name.as_deref(), Some("yubi-test"));
        // No capability check on an explicit path.
        let ok = resolve_target(
            &devs,
            &sel(None, None, Some(std::path::Path::new("/dev/hidraw16"))),
            Need::Molto2,
            &mut NoPicker,
        )
        .unwrap();
        assert_eq!(ok.device.name.as_deref(), Some("yubi-test"));
        let err = resolve_target(
            &devs,
            &sel(None, None, Some(std::path::Path::new("/dev/hidraw99"))),
            Need::FidoHid,
            &mut NoPicker,
        )
        .unwrap_err();
        assert_eq!(
            err,
            SelectError::PathNotFound {
                path: "/dev/hidraw99".into()
            }
        );
        assert!(err.to_string().contains("using it as typed"), "{err}");
    }

    #[test]
    fn list_order_is_by_identity_not_enumeration() {
        let a = [yubi(), solo(), molto()];
        let b = [molto(), yubi(), solo()];
        let serials = |d: &[Device]| {
            list_order(d)
                .into_iter()
                .map(|i| d[i].serial.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(serials(&a), serials(&b));
        assert_eq!(serials(&a).last().map(String::as_str), Some(""));
    }

    #[test]
    fn factory_reset_counts_only_resettable_rows() {
        let prog = row(
            None,
            "P1",
            &[Caps::PROG],
            None,
            Some("NFC 00 00"),
            DeviceKind::ProgToken,
        );
        let devs = [yubi(), molto(), prog];
        let t = resolve_target(
            &devs,
            &Selector::default(),
            Need::FactoryReset,
            &mut NoPicker,
        )
        .unwrap();
        assert_eq!(t.device.name.as_deref(), Some("yubi-test"));
    }

    #[test]
    fn quoting_and_sanitising() {
        assert_eq!(shell_quote("yubi-test"), "yubi-test");
        assert_eq!(shell_quote("work key"), "'work key'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        let mut evil = yubi();
        evil.name = Some("a\u{1b}[31m\nb".into());
        let devs = [evil, solo()];
        let msg = resolve_target(&devs, &Selector::default(), Need::Piv, &mut NoPicker)
            .unwrap_err()
            .to_string();
        assert!(!msg.contains('\u{1b}') && !msg.contains('\n'), "{msg:?}");
    }
}
