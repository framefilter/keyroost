//! One naming pass over a scan's rows: which name each key shows, whether
//! `--device NAME` may select it, and which first-seen records the scan
//! learned. Pure — the caller reads the names stored on keys and saves the
//! keyring.
//!
//! The rules, per row in `list` order:
//!
//! * A valid name stored on the key is shown first. The first key this
//!   computer saw with that name keeps the plain name and is selectable by
//!   it; the sighting is recorded in `keys.json` best-effort. When it can't
//!   be recorded (no usable serial, no config directory, a failed save) the
//!   key is treated as seen for the first time on every scan: shown plain
//!   and selectable, and the caller warns once. Any other key carrying the
//!   same name shows `Name (1234)` — the last four characters of its live
//!   serial, for display only, never stored and never selectable.
//! * A key whose name can't be read (a failed read, a damaged or invalid
//!   name entry, no large-blob storage) is treated as carrying no name.
//! * Otherwise the name this computer saved for the key is shown (looked up
//!   by the row's serial, else by its FIDO HID serial when that differs).
//!
//! Keys that report one fixed serial for every unit are indistinguishable
//! here, as they are everywhere else: units sharing a name are all
//! selectable by it, and selecting then refuses them as ambiguous.

use std::collections::HashMap;

use keyroost_keyring::{canonical_serial, is_spoofing_char, validate_name, Keyring, NameStore};

use crate::device::{Device, DeviceId};

/// Where the name a row shows lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameSource {
    /// On the key itself.
    Key,
    /// Only in this computer's `keys.json`.
    Computer,
}

/// What this scan learned about a name stored on the key itself.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum KeyLabel {
    /// No FIDO HID path, or a scan that skipped name reads.
    #[default]
    NotRead,
    /// The key was asked but didn't answer this time (busy, timeout, I/O):
    /// for this scan it is treated as carrying no name.
    ReadFailed,
    /// The key has no large-blob storage.
    Unsupported,
    /// The key has storage but no name entry.
    Absent,
    /// A name that passes [`keyroost_keyring::validate_name`].
    Present(String),
    /// A name entry whose text fails validation; it is never shown.
    Unreadable,
}

impl KeyLabel {
    /// Classify a name read from a key: text that fails the local-name rules
    /// (control, bidi or zero-width characters, empty, too long) is
    /// [`KeyLabel::Unreadable`] and is never displayed.
    pub fn from_text(text: &str) -> KeyLabel {
        if validate_name(text).is_ok() {
            KeyLabel::Present(text.to_string())
        } else {
            KeyLabel::Unreadable
        }
    }
}

/// How a row is named.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Naming {
    /// The shown name without any serial tail.
    pub plain: Option<String>,
    pub source: Option<NameSource>,
    /// `--device <plain>` may select this key: it is the first key this
    /// computer saw with that name (recording that is best-effort; an
    /// unrecorded first sight selects for the session).
    pub selectable: bool,
    pub on_key: KeyLabel,
    /// A `stored = key` record of this key whose name is no longer on the
    /// key (offer to write it back).
    pub missing_on_key: Option<String>,
}

impl Naming {
    /// A name this computer saved for the key (`None`: unnamed): shown and
    /// selectable. For rows built outside a scan, such as tests.
    pub fn local(name: Option<&str>) -> Naming {
        Naming {
            plain: name.map(str::to_owned),
            source: name.map(|_| NameSource::Computer),
            selectable: name.is_some(),
            ..Naming::default()
        }
    }
}

/// A change to the keyring the naming pass asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NameUpdate {
    /// First sight of a name stored on the key with `serial`.
    FirstSeen { serial: String, name: String },
    /// The key with `serial` now carries `current`; drop its other
    /// `stored = key` records.
    DropStale { serial: String, current: String },
    /// First sight of `name` on a key with no usable serial: it can't be
    /// recorded, so it works for this session only (the caller warns).
    Unrecordable { name: String },
}

/// The last four characters of `serial` (all of it when shorter), cut on a
/// character boundary.
pub fn serial_tail(serial: &str) -> &str {
    match serial.char_indices().rev().nth(3) {
        Some((i, _)) => &serial[i..],
        None => serial,
    }
}

/// [`serial_tail`] made safe to show: control, bidi, zero-width and
/// whitespace characters become `?`.
fn shown_tail(serial: &str) -> String {
    serial_tail(serial)
        .chars()
        .map(|c| {
            if c.is_control() || c.is_whitespace() || is_spoofing_char(c) {
                '?'
            } else {
                c
            }
        })
        .collect()
}

/// Reset and fill `name` and `naming` on every row, in `list` order, from
/// `keyring` and the names read from keys in `labels` (keyed by row id; a
/// missing entry is [`KeyLabel::NotRead`]). Returns the keyring changes the
/// pass learned; the caller applies them ([`apply_updates`]) and saves
/// best-effort. A first-seen name is selectable at once.
pub fn apply_names(
    devices: &mut [Device],
    keyring: &Keyring,
    labels: &HashMap<DeviceId, KeyLabel>,
) -> Vec<NameUpdate> {
    let mut updates = Vec::new();
    // Names claimed earlier in this pass, with the (canonical) serial that
    // claimed them.
    let mut claimed: HashMap<String, String> = HashMap::new();
    for i in crate::select::list_order(devices) {
        let d = &mut devices[i];
        let on_key = match labels.get(&d.id) {
            // Validate again: a label that reached here unchecked is never shown.
            Some(KeyLabel::Present(l)) => KeyLabel::from_text(l),
            Some(other) => other.clone(),
            None => KeyLabel::NotRead,
        };
        let mut naming = Naming {
            on_key: on_key.clone(),
            ..Naming::default()
        };
        let serial = d.serial.clone();
        let canon = canonical_serial(&serial);
        // The serials this row may be known by: its own, then its FIDO HID
        // node's when that differs (a merged row named under the HID serial).
        let known: Vec<&str> = std::iter::once(serial.as_str())
            .chain(d.hid_serial.as_deref())
            .filter(|s| !canonical_serial(s).is_empty())
            .collect();
        let mut shown = None;
        if let KeyLabel::Present(l) = &on_key {
            naming.source = Some(NameSource::Key);
            naming.plain = Some(l.clone());
            shown = Some(l.clone());
            // Who claims a name in this pass: the serial, or for a key
            // without a usable one, the row itself.
            let claim = if canon.is_empty() {
                format!("row:{}", d.id)
            } else {
                canon.clone()
            };
            let holder = keyring.holder(l);
            let first_here = match claimed.get(l) {
                Some(by) => *by == claim,
                None => true,
            };
            if holder.is_none() && first_here {
                // First sight, as on any computer seeing the key for the
                // first time: shown plain and selectable; recorded
                // best-effort.
                naming.selectable = true;
                if !claimed.contains_key(l) {
                    updates.push(if canon.is_empty() {
                        NameUpdate::Unrecordable { name: l.clone() }
                    } else {
                        NameUpdate::FirstSeen {
                            serial: serial.clone(),
                            name: l.clone(),
                        }
                    });
                }
                claimed.insert(l.clone(), claim);
            } else if !canon.is_empty()
                && holder.is_some_and(|h| {
                    h.fingerprint.is_some()
                        && known
                            .iter()
                            .any(|s| keyring.fingerprint_of(s) == h.fingerprint)
                })
            {
                naming.selectable = true;
                claimed.entry(l.clone()).or_insert_with(|| canon.clone());
            } else if !canon.is_empty() {
                shown = Some(format!("{l} ({})", shown_tail(&serial)));
            }
            if !canon.is_empty()
                && keyring
                    .records_for(&serial)
                    .iter()
                    .any(|r| r.stored == NameStore::Key && r.name != *l)
            {
                updates.push(NameUpdate::DropStale {
                    serial: serial.clone(),
                    current: l.clone(),
                });
            }
        } else {
            if let Some(n) = known.iter().find_map(|s| keyring.local_name_for(s)) {
                naming.source = Some(NameSource::Computer);
                naming.plain = Some(n.to_string());
                naming.selectable = true;
                shown = Some(n.to_string());
            }
            if on_key == KeyLabel::Absent && !canon.is_empty() {
                naming.missing_on_key = keyring
                    .records_for(&serial)
                    .into_iter()
                    .find(|r| r.stored == NameStore::Key)
                    .map(|r| r.name.clone());
            }
        }
        d.name = shown;
        d.naming = naming;
    }
    updates
}

/// Apply the pass's updates to `keyring`. Returns how many first-seen
/// records were added and how many stale records were dropped.
pub fn apply_updates(keyring: &mut Keyring, updates: &[NameUpdate]) -> (usize, usize) {
    let (mut recorded, mut dropped) = (0, 0);
    for u in updates {
        match u {
            NameUpdate::FirstSeen { serial, name } => {
                if keyring.record_first_seen(serial, name) {
                    recorded += 1;
                }
            }
            NameUpdate::DropStale { serial, current } => {
                dropped += keyring.drop_stale_key_records(serial, current);
            }
            NameUpdate::Unrecordable { .. } => {}
        }
    }
    (recorded, dropped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::{Caps, DeviceKind};
    use keyroost_keyring::RecordMeta;

    const A: &str = "12345678";
    const B: &str = "ABCDEF01";

    fn key(serial: &str) -> Device {
        let mut caps = Caps::default();
        caps.insert(Caps::FIDO2);
        Device {
            id: if serial.is_empty() {
                "hid:/dev/x".into()
            } else {
                format!("serial:{serial}")
            },
            name: Some("stale".into()),
            vendor: "Vendor".into(),
            model: "Model".into(),
            serial: serial.into(),
            transport: String::new(),
            firmware: String::new(),
            caps,
            unverified: Caps::default(),
            kind: DeviceKind::Key,
            hid_path: Some("/dev/x".into()),
            reader: None,
            hid_serial: None,
            naming: Naming::default(),
        }
    }

    fn labels(pairs: &[(&Device, KeyLabel)]) -> HashMap<DeviceId, KeyLabel> {
        pairs
            .iter()
            .map(|(d, l)| (d.id.clone(), l.clone()))
            .collect()
    }

    fn present(l: &str) -> KeyLabel {
        KeyLabel::Present(l.into())
    }

    fn local(ring: &mut Keyring, serial: &str, name: &str) {
        ring.set_name(serial, name, NameStore::Computer, RecordMeta::default())
            .unwrap();
    }

    #[test]
    fn local_name_shows_and_selects() {
        let mut ring = Keyring::default();
        local(&mut ring, A, "Work");
        let mut devs = vec![key(A)];
        let ups = apply_names(&mut devs, &ring, &HashMap::new());
        assert!(ups.is_empty());
        assert_eq!(devs[0].name.as_deref(), Some("Work"));
        assert_eq!(devs[0].naming.plain.as_deref(), Some("Work"));
        assert_eq!(devs[0].naming.source, Some(NameSource::Computer));
        assert!(devs[0].naming.selectable);
        assert_eq!(devs[0].naming.on_key, KeyLabel::NotRead);
    }

    #[test]
    fn first_on_key_sight_records_and_selects() {
        let ring = Keyring::default();
        let mut devs = vec![key(A)];
        let l = labels(&[(&devs[0], present("Work"))]);
        let ups = apply_names(&mut devs, &ring, &l);
        assert_eq!(
            ups,
            vec![NameUpdate::FirstSeen {
                serial: A.into(),
                name: "Work".into()
            }]
        );
        assert_eq!(devs[0].name.as_deref(), Some("Work"));
        assert_eq!(devs[0].naming.source, Some(NameSource::Key));
        // Like any first sight: shown and selectable, recorded best-effort.
        assert!(devs[0].naming.selectable);
        let mut ring = ring;
        assert_eq!(apply_updates(&mut ring, &ups), (1, 0));
        assert!(apply_names(&mut devs, &ring, &l).is_empty());
        assert_eq!(devs[0].name.as_deref(), Some("Work"));
        assert!(devs[0].naming.selectable);
    }

    #[test]
    fn unrecorded_first_sight_works_for_the_session() {
        // A keys.json that can't be saved (or loaded) leaves every sighting
        // unrecorded: each scan sees the keys for the first time, so their
        // names are shown plain and select them.
        let ring = Keyring::default();
        let mut devs = vec![key(A), key(B)];
        let l = labels(&[(&devs[0], present("Work")), (&devs[1], present("Home"))]);
        for _ in 0..2 {
            apply_names(&mut devs, &ring, &l);
            assert!(devs.iter().all(|d| d.naming.selectable));
        }
    }

    #[test]
    fn unusable_serial_label_shows_selects_and_asks_for_a_warning() {
        let ring = Keyring::default();
        let mut devs = vec![key(" \u{7}\u{200B} ")];
        let l = labels(&[(&devs[0], present("Work"))]);
        assert_eq!(
            apply_names(&mut devs, &ring, &l),
            vec![NameUpdate::Unrecordable {
                name: "Work".into()
            }]
        );
        assert_eq!(devs[0].name.as_deref(), Some("Work"));
        assert!(devs[0].naming.selectable);
    }

    #[test]
    fn tail_is_sanitized() {
        let mut ring = Keyring::default();
        local(&mut ring, A, "Work");
        let mut devs = vec![key(A), key("AB\u{202E}\u{1b}12")];
        let l = labels(&[(&devs[1], present("Work"))]);
        apply_names(&mut devs, &ring, &l);
        let b = devs.iter().find(|d| d.serial != A).unwrap();
        assert_eq!(b.name.as_deref(), Some("Work (??12)"));
    }

    #[test]
    fn local_name_falls_back_to_the_hid_serial() {
        let mut ring = Keyring::default();
        local(&mut ring, A, "Work");
        let mut d = key("CARD0001");
        d.hid_serial = Some(A.into());
        let mut devs = vec![d];
        apply_names(&mut devs, &ring, &HashMap::new());
        assert_eq!(devs[0].name.as_deref(), Some("Work"));
        assert!(devs[0].naming.selectable);
    }

    #[test]
    fn read_failure_is_listed_like_an_unnamed_key() {
        let ring = Keyring::default();
        let mut failed = vec![key(A)];
        let l = labels(&[(&failed[0], KeyLabel::ReadFailed)]);
        assert!(apply_names(&mut failed, &ring, &l).is_empty());
        let mut unnamed = vec![key(A)];
        apply_names(&mut unnamed, &ring, &HashMap::new());
        assert_eq!(failed[0].name, unnamed[0].name);
        assert_eq!(
            Naming {
                on_key: KeyLabel::NotRead,
                ..failed[0].naming.clone()
            },
            unnamed[0].naming
        );
    }

    #[test]
    fn read_failure_is_kept_and_falls_back_to_the_local_name() {
        let mut ring = Keyring::default();
        local(&mut ring, A, "Home");
        let mut devs = vec![key(A)];
        let l = labels(&[(&devs[0], KeyLabel::ReadFailed)]);
        apply_names(&mut devs, &ring, &l);
        assert_eq!(devs[0].naming.on_key, KeyLabel::ReadFailed);
        assert_eq!(devs[0].name.as_deref(), Some("Home"));
    }

    #[test]
    fn newcomer_with_a_local_name_gets_the_tail() {
        let mut ring = Keyring::default();
        local(&mut ring, A, "Work");
        let mut devs = vec![key(A), key("99995678")];
        let l = labels(&[(&devs[1], present("Work"))]);
        let ups = apply_names(&mut devs, &ring, &l);
        assert!(ups.is_empty());
        let b = devs.iter().find(|d| d.serial == "99995678").unwrap();
        assert_eq!(b.name.as_deref(), Some("Work (5678)"));
        assert_eq!(b.naming.plain.as_deref(), Some("Work"));
        assert!(!b.naming.selectable);
        let a = devs.iter().find(|d| d.serial == A).unwrap();
        assert_eq!(a.name.as_deref(), Some("Work"));
        assert!(a.naming.selectable);
    }

    #[test]
    fn newcomer_with_a_first_seen_name_gets_the_tail() {
        let mut ring = Keyring::default();
        assert!(ring.record_first_seen(A, "Work"));
        let mut devs = vec![key(A), key(B)];
        let l = labels(&[(&devs[0], present("Work")), (&devs[1], present("Work"))]);
        let ups = apply_names(&mut devs, &ring, &l);
        assert!(ups.is_empty());
        let a = devs.iter().find(|d| d.serial == A).unwrap();
        let b = devs.iter().find(|d| d.serial == B).unwrap();
        assert_eq!(a.name.as_deref(), Some("Work"));
        assert!(a.naming.selectable);
        assert_eq!(b.name.as_deref(), Some("Work (EF01)"));
        assert!(!b.naming.selectable);
        // Only the newcomer is connected: it is still the newcomer.
        let mut only_b = vec![key(B)];
        let l = labels(&[(&only_b[0], present("Work"))]);
        apply_names(&mut only_b, &ring, &l);
        assert_eq!(only_b[0].name.as_deref(), Some("Work (EF01)"));
        assert!(!only_b[0].naming.selectable);
    }

    #[test]
    fn two_unclaimed_same_label_in_one_scan_first_in_list_order_wins() {
        let ring = Keyring::default();
        // B sorts after A in list order regardless of slice order.
        let mut devs = vec![key(B), key(A)];
        let l = labels(&[(&devs[0], present("Work")), (&devs[1], present("Work"))]);
        let ups = apply_names(&mut devs, &ring, &l);
        assert_eq!(
            ups,
            vec![NameUpdate::FirstSeen {
                serial: A.into(),
                name: "Work".into()
            }]
        );
        let a = devs.iter().find(|d| d.serial == A).unwrap();
        let b = devs.iter().find(|d| d.serial == B).unwrap();
        assert_eq!(a.name.as_deref(), Some("Work"));
        assert!(a.naming.selectable);
        assert!(!b.naming.selectable);
        assert_eq!(b.name.as_deref(), Some("Work (EF01)"));
        let mut ring = ring;
        apply_updates(&mut ring, &ups);
        apply_names(&mut devs, &ring, &l);
        let a = devs.iter().find(|d| d.serial == A).unwrap();
        let b = devs.iter().find(|d| d.serial == B).unwrap();
        assert!(a.naming.selectable);
        assert_eq!(a.name.as_deref(), Some("Work"));
        assert!(!b.naming.selectable);
        assert_eq!(b.name.as_deref(), Some("Work (EF01)"));
    }

    #[test]
    fn serial_less_label_works_for_the_session_unless_recorded_elsewhere() {
        let ring = Keyring::default();
        let mut devs = vec![key("")];
        let l = labels(&[(&devs[0], present("Work"))]);
        let ups = apply_names(&mut devs, &ring, &l);
        assert_eq!(
            ups,
            vec![NameUpdate::Unrecordable {
                name: "Work".into()
            }]
        );
        assert_eq!(devs[0].name.as_deref(), Some("Work"));
        assert_eq!(devs[0].naming.source, Some(NameSource::Key));
        assert!(devs[0].naming.selectable);
        // A key this computer first saw with the name keeps it.
        let mut ring = Keyring::default();
        assert!(ring.record_first_seen(A, "Work"));
        let ups = apply_names(&mut devs, &ring, &l);
        assert!(ups.is_empty());
        assert_eq!(devs[0].name.as_deref(), Some("Work"));
        assert!(!devs[0].naming.selectable);
    }

    #[test]
    fn unreadable_label_falls_back_and_never_matches() {
        let mut ring = Keyring::default();
        local(&mut ring, A, "Home");
        assert!(ring.record_first_seen(B, "Work"));
        let mut devs = vec![key(A), key(B)];
        // A bidi override smuggled in as Present is still never shown.
        let l = labels(&[
            (&devs[0], present("Wo\u{202E}rk")),
            (&devs[1], KeyLabel::Unreadable),
        ]);
        let ups = apply_names(&mut devs, &ring, &l);
        assert!(ups.is_empty());
        let a = devs.iter().find(|d| d.serial == A).unwrap();
        assert_eq!(a.naming.on_key, KeyLabel::Unreadable);
        assert_eq!(a.name.as_deref(), Some("Home"));
        assert_eq!(a.naming.source, Some(NameSource::Computer));
        let b = devs.iter().find(|d| d.serial == B).unwrap();
        assert_eq!(b.name, None);
        assert!(!b.naming.selectable);
        assert_eq!(KeyLabel::from_text("a\u{200B}b"), KeyLabel::Unreadable);
        assert_eq!(KeyLabel::from_text("  "), KeyLabel::Unreadable);
        assert_eq!(KeyLabel::from_text("Work"), present("Work"));
    }

    #[test]
    fn stale_key_record_is_dropped() {
        let mut ring = Keyring::default();
        assert!(ring.record_first_seen(A, "Old"));
        let mut devs = vec![key(A)];
        let l = labels(&[(&devs[0], present("New"))]);
        let ups = apply_names(&mut devs, &ring, &l);
        assert!(ups.contains(&NameUpdate::DropStale {
            serial: A.into(),
            current: "New".into()
        }));
        assert!(ups.contains(&NameUpdate::FirstSeen {
            serial: A.into(),
            name: "New".into()
        }));
        assert_eq!(apply_updates(&mut ring, &ups), (1, 1));
        assert_eq!(ring.holder("Old").map(|r| r.name.as_str()), None);
        assert!(ring.holder("New").is_some());
    }

    #[test]
    fn missing_label_offers_restore() {
        let mut ring = Keyring::default();
        assert!(ring.record_first_seen(A, "Work"));
        let mut devs = vec![key(A)];
        let l = labels(&[(&devs[0], KeyLabel::Absent)]);
        let ups = apply_names(&mut devs, &ring, &l);
        assert!(ups.is_empty());
        assert_eq!(devs[0].naming.missing_on_key.as_deref(), Some("Work"));
        assert_eq!(devs[0].name, None);
        // Not read is not absent: no restore offer.
        apply_names(&mut devs, &ring, &HashMap::new());
        assert_eq!(devs[0].naming.missing_on_key, None);
    }

    #[test]
    fn serial_tail_short_and_multibyte() {
        assert_eq!(serial_tail("12345678"), "5678");
        assert_eq!(serial_tail("123"), "123");
        assert_eq!(serial_tail(""), "");
        assert_eq!(
            serial_tail("ab\u{e9}\u{e9}\u{e9}\u{e9}"),
            "\u{e9}\u{e9}\u{e9}\u{e9}"
        );
        assert_eq!(serial_tail("x\u{1F511}yz"), "x\u{1F511}yz");
    }

    #[test]
    fn fixed_serial_units_both_selectable() {
        let mut ring = Keyring::default();
        local(&mut ring, "00000000", "Shared");
        let mut one = key("00000000");
        one.id = "serial:00000000#/dev/a".into();
        let mut two = key("00000000");
        two.id = "serial:00000000#/dev/b".into();
        let mut devs = vec![one, two];
        apply_names(&mut devs, &ring, &HashMap::new());
        assert!(devs.iter().all(|d| d.naming.selectable));
        assert!(devs.iter().all(|d| d.name.as_deref() == Some("Shared")));
        // The same holds for a name both units carry on the key.
        let mut ring = Keyring::default();
        let l = labels(&[(&devs[0], present("Twin")), (&devs[1], present("Twin"))]);
        let ups = apply_names(&mut devs, &ring, &l);
        assert_eq!(ups.len(), 1);
        assert!(devs.iter().all(|d| d.name.as_deref() == Some("Twin")));
        apply_updates(&mut ring, &ups);
        apply_names(&mut devs, &ring, &l);
        assert!(devs.iter().all(|d| d.naming.selectable));
        assert!(devs.iter().all(|d| d.name.as_deref() == Some("Twin")));
    }

    #[test]
    fn apply_updates_records_first_seen_and_drops_stale() {
        let mut ring = Keyring::default();
        assert!(ring.record_first_seen(A, "Old"));
        local(&mut ring, B, "Taken");
        let ups = [
            NameUpdate::FirstSeen {
                serial: A.into(),
                name: "New".into(),
            },
            NameUpdate::DropStale {
                serial: A.into(),
                current: "New".into(),
            },
            // A name another record holds is never recorded twice.
            NameUpdate::FirstSeen {
                serial: A.into(),
                name: "Taken".into(),
            },
        ];
        assert_eq!(apply_updates(&mut ring, &ups), (1, 1));
        assert!(ring.holder("Old").is_none());
        assert_eq!(ring.holder("New").map(|r| r.stored), Some(NameStore::Key));
        assert_eq!(
            ring.holder("Taken").map(|r| r.stored),
            Some(NameStore::Computer)
        );
        assert_eq!(apply_updates(&mut ring, &[]), (0, 0));
    }

    #[test]
    fn rows_are_reset_every_pass() {
        let ring = Keyring::default();
        let mut devs = vec![key(A)];
        apply_names(&mut devs, &ring, &HashMap::new());
        assert_eq!(devs[0].name, None);
        assert_eq!(devs[0].naming, Naming::default());
    }
}
