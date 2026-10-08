// crates/keyroost/src/ui/device.rs
//
// View layer over the shared device model. The correlation/classification logic
// now lives in `keyroost-resolve` (consumed by the CLI too); here we keep only
// the GUI-specific capability-tab bar.
//
// Rows come from `keyroost_resolve::enumerate()`, the same matcher the CLI
// uses: USB topology, then the identity each side reports (#51,
// Windows/macOS), then the vendor fallback. On Linux topology settles every
// row, so the sidebar is unchanged there.

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

// --- Naming a key (#166) ---------------------------------------------------

use keyroost_resolve::{KeyLabel, NameSource, Naming};

/// Where the naming dialog saves a name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameStoreChoice {
    /// This computer's keys.json.
    Computer,
    /// The key's own large-blob storage.
    Key,
}

/// The places the naming dialog offers for `d`: this computer always; the
/// key too when it is a FIDO2 key on USB whose scan found large-blob
/// storage (with or without a name in it; an unreadable name counts as
/// none).
pub fn store_choices(d: &Device) -> Vec<NameStoreChoice> {
    let mut v = vec![NameStoreChoice::Computer];
    let has_storage = matches!(
        d.naming.on_key,
        KeyLabel::Absent | KeyLabel::Present(_) | KeyLabel::Unreadable
    );
    if d.caps.has(Caps::FIDO2) && d.hid_path.is_some() && has_storage {
        v.push(NameStoreChoice::Key);
    }
    v
}

/// The place the dialog starts on: where the current name lives, else this
/// computer.
pub fn default_store(d: &Device) -> NameStoreChoice {
    if d.naming.source == Some(NameSource::Key) {
        NameStoreChoice::Key
    } else {
        NameStoreChoice::Computer
    }
}

/// Whether the scan found that `d` has no large-blob storage (the dialog
/// then says so instead of offering the key).
pub fn lacks_key_storage(d: &Device) -> bool {
    d.naming.on_key == KeyLabel::Unsupported
}

/// What saving the naming dialog does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NameSave {
    /// The name is already what and where the dialog asks.
    Unchanged,
    /// Set (`Some`) or clear (`None`) the name on this computer.
    Local(Option<String>),
    /// Set or clear the name on the key, first asking `question` when it
    /// replaces or removes a name the key carries.
    OnKey {
        name: Option<String>,
        question: Option<String>,
    },
}

/// Why a rename can't go to this computer: the key carries its name.
pub const NAME_IS_ON_THE_KEY: &str =
    "This key's name is stored on the key. Rename it there, or clear the name first.";

/// Plan saving `input` (trimmed; empty clears the name wherever it lives)
/// to `choice` for a key named as `naming` says. Same rules as
/// `keyroostctl name set|clear`: a rename stays where the name is, and a
/// name on the key is never left there behind a new local one.
pub fn plan_name_save(
    naming: &Naming,
    choice: NameStoreChoice,
    input: &str,
) -> Result<NameSave, &'static str> {
    let on_key = match &naming.on_key {
        KeyLabel::Present(l) if naming.source == Some(NameSource::Key) => Some(l.as_str()),
        _ => None,
    };
    if input.is_empty() {
        return Ok(match on_key {
            Some(old) => NameSave::OnKey {
                name: None,
                question: Some(format!("Remove the name \"{old}\" stored on the key?")),
            },
            None => NameSave::Local(None),
        });
    }
    match (choice, on_key) {
        (NameStoreChoice::Computer, Some(_)) => Err(NAME_IS_ON_THE_KEY),
        (NameStoreChoice::Key, Some(old)) if old == input => Ok(NameSave::Unchanged),
        (NameStoreChoice::Key, old) => Ok(NameSave::OnKey {
            name: Some(input.to_string()),
            question: old.map(|old| {
                format!("Replace the name \"{old}\" stored on the key with \"{input}\"?")
            }),
        }),
        (NameStoreChoice::Computer, None) => {
            if naming.source == Some(NameSource::Computer) && naming.plain.as_deref() == Some(input)
            {
                Ok(NameSave::Unchanged)
            } else {
                Ok(NameSave::Local(Some(input.to_string())))
            }
        }
    }
}

/// Every serial `d` may be recorded under: its own, then its FIDO HID
/// node's when that differs (the serials the naming pass looks names up by).
pub fn row_serials(d: &Device) -> Vec<String> {
    std::iter::once(d.serial.as_str())
        .chain(d.hid_serial.as_deref())
        .filter(|s| !keyroost_keyring::canonical_serial(s).is_empty())
        .map(str::to_owned)
        .collect()
}

/// Whether another key's record (or one matching no key) holds `name`;
/// `serials` are this key's ([`row_serials`]).
pub fn name_held_elsewhere(
    keyring: &keyroost_keyring::Keyring,
    name: &str,
    serials: &[String],
) -> bool {
    let Some(h) = keyring.holder(name) else {
        return false;
    };
    let ours = h.fingerprint.is_some()
        && serials
            .iter()
            .any(|s| keyring.fingerprint_of(s) == h.fingerprint);
    !ours
}

/// [`keyroost_keyring::Keyring::set_name`] for the key with `serials`
/// (its own first), first dropping what it would replace under its other
/// serial, so a rename never leaves a second record.
pub fn set_key_name(
    keyring: &mut keyroost_keyring::Keyring,
    serials: &[String],
    name: &str,
    store: keyroost_keyring::NameStore,
    meta: keyroost_keyring::RecordMeta,
) -> Result<(), keyroost_keyring::KeyringError> {
    use keyroost_keyring::NameStore;
    let Some(primary) = serials.first() else {
        return Err(keyroost_keyring::KeyringError::NoSerial);
    };
    let ours = keyring.fingerprint_of(primary);
    let others: Vec<_> = serials[1..]
        .iter()
        .filter_map(|s| keyring.fingerprint_of(s))
        .filter(|fp| Some(fp) != ours.as_ref())
        .collect();
    keyring.keys.retain(|r| {
        let other = r.fingerprint.as_ref().is_some_and(|fp| others.contains(fp));
        !(other && (store == NameStore::Key || r.stored == NameStore::Computer || r.name == name))
    });
    keyring.set_name(primary, name, store, meta)
}

/// Remove every record of the key with `serials`; returns how many.
pub fn clear_key_names(keyring: &mut keyroost_keyring::Keyring, serials: &[String]) -> usize {
    serials.iter().map(|s| keyring.clear_key(s).len()).sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyroost_keyring::{Keyring, NameStore, RecordMeta};

    fn dev(fido: bool, hid: bool, on_key: KeyLabel) -> Device {
        let mut caps = Caps::default();
        if fido {
            caps.insert(Caps::FIDO2);
        }
        Device {
            id: "serial:12345678".into(),
            name: None,
            vendor: "Vendor".into(),
            model: "Model".into(),
            serial: "12345678".into(),
            transport: "USB".into(),
            firmware: String::new(),
            caps,
            unverified: Caps::default(),
            kind: DeviceKind::Key,
            hid_path: hid.then(|| "/dev/hidraw0".into()),
            reader: None,
            hid_serial: None,
            naming: Naming {
                on_key,
                ..Naming::default()
            },
        }
    }

    fn on_key(name: &str) -> Naming {
        Naming {
            plain: Some(name.into()),
            source: Some(NameSource::Key),
            selectable: true,
            on_key: KeyLabel::Present(name.into()),
            missing_on_key: None,
        }
    }

    use NameStoreChoice::{Computer, Key};

    #[test]
    fn store_choices_fido_with_large_blob_offers_both() {
        for l in [
            KeyLabel::Absent,
            KeyLabel::Present("Desk".into()),
            KeyLabel::Unreadable,
        ] {
            assert_eq!(store_choices(&dev(true, true, l)), vec![Computer, Key]);
        }
    }

    #[test]
    fn store_choices_fido_without_large_blob_is_this_computer_only() {
        let d = dev(true, true, KeyLabel::Unsupported);
        assert_eq!(store_choices(&d), vec![Computer]);
        assert!(lacks_key_storage(&d));
        // Not read (or no answer): nothing is known, so no key option and
        // no "can't store" line either.
        for l in [KeyLabel::NotRead, KeyLabel::ReadFailed] {
            let d = dev(true, true, l);
            assert_eq!(store_choices(&d), vec![Computer]);
            assert!(!lacks_key_storage(&d));
        }
    }

    #[test]
    fn store_choices_card_only_is_this_computer_only() {
        // FIDO over a reader, no HID path: the name can't be written there.
        let d = dev(true, false, KeyLabel::NotRead);
        assert_eq!(store_choices(&d), vec![Computer]);
        assert!(!lacks_key_storage(&d));
    }

    #[test]
    fn store_choices_molto2_is_this_computer_only() {
        let mut d = dev(false, false, KeyLabel::NotRead);
        d.kind = DeviceKind::Token;
        assert_eq!(store_choices(&d), vec![Computer]);
        assert!(!lacks_key_storage(&d));
    }

    #[test]
    fn default_store_follows_current_place() {
        let mut d = dev(true, true, KeyLabel::Absent);
        assert_eq!(default_store(&d), Computer);
        d.naming = Naming::local(Some("Desk"));
        assert_eq!(default_store(&d), Computer);
        d.naming = on_key("Desk");
        assert_eq!(default_store(&d), Key);
    }

    #[test]
    fn plan_name_save_follows_the_cli_rules() {
        let unnamed = Naming {
            on_key: KeyLabel::Absent,
            ..Naming::default()
        };
        let local = Naming::local(Some("Desk"));
        let key = on_key("Desk");
        // New names go where chosen.
        assert_eq!(
            plan_name_save(&unnamed, Computer, "A"),
            Ok(NameSave::Local(Some("A".into())))
        );
        assert_eq!(
            plan_name_save(&unnamed, Key, "A"),
            Ok(NameSave::OnKey {
                name: Some("A".into()),
                question: None
            })
        );
        // Moving a local name onto the key asks nothing (no name on the key).
        assert_eq!(
            plan_name_save(&local, Key, "Desk"),
            Ok(NameSave::OnKey {
                name: Some("Desk".into()),
                question: None
            })
        );
        assert_eq!(
            plan_name_save(&local, Computer, "Desk"),
            Ok(NameSave::Unchanged)
        );
        // A name on the key: rename there (asking), never behind a local one.
        assert_eq!(plan_name_save(&key, Key, "Desk"), Ok(NameSave::Unchanged));
        assert_eq!(
            plan_name_save(&key, Key, "Lab"),
            Ok(NameSave::OnKey {
                name: Some("Lab".into()),
                question: Some("Replace the name \"Desk\" stored on the key with \"Lab\"?".into())
            })
        );
        assert_eq!(
            plan_name_save(&key, Computer, "Lab"),
            Err(NAME_IS_ON_THE_KEY)
        );
        // Empty clears wherever the name lives, whatever is chosen.
        for c in [Computer, Key] {
            assert_eq!(
                plan_name_save(&key, c, ""),
                Ok(NameSave::OnKey {
                    name: None,
                    question: Some("Remove the name \"Desk\" stored on the key?".into())
                })
            );
            assert_eq!(plan_name_save(&local, c, ""), Ok(NameSave::Local(None)));
        }
        // An unreadable name on the key counts as no name.
        let unreadable = Naming {
            on_key: KeyLabel::Unreadable,
            ..Naming::default()
        };
        assert_eq!(
            plan_name_save(&unreadable, Key, "A"),
            Ok(NameSave::OnKey {
                name: Some("A".into()),
                question: None
            })
        );
    }

    #[test]
    fn row_serials_include_a_distinct_hid_serial() {
        let mut d = dev(true, true, KeyLabel::Absent);
        assert_eq!(row_serials(&d), vec!["12345678".to_string()]);
        d.hid_serial = Some("ABCDEF01".into());
        assert_eq!(
            row_serials(&d),
            vec!["12345678".to_string(), "ABCDEF01".to_string()]
        );
        d.serial = String::new();
        assert_eq!(row_serials(&d), vec!["ABCDEF01".to_string()]);
    }

    #[test]
    fn a_name_held_by_another_key_is_refused_ours_is_not() {
        let mut k = Keyring::default();
        k.set_name(
            "ABCDEF01",
            "Other",
            NameStore::Computer,
            RecordMeta::default(),
        )
        .unwrap();
        k.set_name("12345678", "Mine", NameStore::Key, RecordMeta::default())
            .unwrap();
        let ours = vec!["12345678".to_string()];
        assert!(name_held_elsewhere(&k, "Other", &ours));
        assert!(!name_held_elsewhere(&k, "Mine", &ours));
        assert!(!name_held_elsewhere(&k, "Free", &ours));
    }

    #[test]
    fn set_key_name_replaces_the_record_under_the_other_serial() {
        let mut k = Keyring::default();
        k.set_name(
            "ABCDEF01",
            "Old",
            NameStore::Computer,
            RecordMeta::default(),
        )
        .unwrap();
        let serials = vec!["12345678".to_string(), "ABCDEF01".to_string()];
        set_key_name(
            &mut k,
            &serials,
            "New",
            NameStore::Key,
            RecordMeta::default(),
        )
        .unwrap();
        assert_eq!(k.keys.len(), 1);
        assert_eq!(k.keys[0].name, "New");
        assert_eq!(k.keys[0].stored, NameStore::Key);
        assert_eq!(clear_key_names(&mut k, &serials), 1);
        assert!(k.keys.is_empty());
    }
}
