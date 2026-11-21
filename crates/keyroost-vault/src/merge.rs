//! Selective backup import: classify each incoming entry, then apply only
//! the ones the user ticked.

use crate::model::{canon_id, Vault};

/// How an incoming entry relates to the current vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportStatus {
    /// No entry with this id in the current vault (a deleted entry shows up
    /// here too; the user decides).
    New,
    /// Same id, different content, strictly later modification minute.
    Newer,
    /// Same id, different content, same or earlier minute.
    Older,
    /// Same id, identical in every field.
    Same,
}

/// Status of every incoming entry, as `(index into incoming.entries, status)`.
pub fn classify(current: &Vault, incoming: &Vault) -> Vec<(usize, ImportStatus)> {
    incoming
        .entries
        .iter()
        .enumerate()
        .map(|(i, inc)| {
            let id = canon_id(&inc.id);
            let status = match current.entries.iter().find(|c| canon_id(&c.id) == id) {
                None => ImportStatus::New,
                Some(c) if c == inc => ImportStatus::Same,
                Some(c) if inc.modified_minutes > c.modified_minutes => ImportStatus::Newer,
                Some(_) => ImportStatus::Older,
            };
            (i, status)
        })
        .collect()
}

/// Import the incoming entries at the `chosen` indices; returns
/// `(added, replaced)`. A new entry is appended keeping its id; an entry whose
/// id already exists replaces the current one (even if older: the user chose
/// it); identical entries are left alone. Indices out of range are ignored.
pub fn apply_import(current: &mut Vault, incoming: &Vault, chosen: &[usize]) -> (usize, usize) {
    let (mut added, mut replaced) = (0, 0);
    for &i in chosen {
        let Some(inc) = incoming.entries.get(i) else {
            continue;
        };
        let id = canon_id(&inc.id);
        match current.entries.iter_mut().find(|c| canon_id(&c.id) == id) {
            None => {
                current.entries.push(inc.clone());
                added += 1;
            }
            Some(c) if *c == *inc => {}
            Some(c) => {
                *c = inc.clone();
                replaced += 1;
            }
        }
    }
    (added, replaced)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Entry;
    use zeroize::Zeroizing;

    fn e(id: &str, pw: &str, m: i64) -> Entry {
        Entry {
            id: id.into(),
            title: format!("t-{id}"),
            username: "u".into(),
            password: Zeroizing::new(pw.into()),
            url: String::new(),
            notes: String::new(),
            modified_minutes: m,
        }
    }

    fn vault(v: Vec<Entry>) -> Vault {
        Vault { entries: v }
    }

    #[test]
    fn classify_new_newer_older_same() {
        let cur = vault(vec![e("a", "1", 10), e("b", "1", 10), e("c", "1", 10)]);
        let inc = vault(vec![
            e("n", "1", 10),
            e("a", "2", 11),
            e("b", "2", 9),
            e("c", "1", 10),
        ]);
        use ImportStatus::*;
        assert_eq!(
            classify(&cur, &inc),
            vec![(0, New), (1, Newer), (2, Older), (3, Same)]
        );
    }

    #[test]
    fn equal_minutes_different_content_is_older() {
        let cur = vault(vec![e("a", "1", 10)]);
        let inc = vault(vec![e("a", "2", 10)]);
        assert_eq!(classify(&cur, &inc), vec![(0, ImportStatus::Older)]);
    }

    #[test]
    fn deleted_entry_shows_as_new() {
        let cur = vault(vec![]);
        let inc = vault(vec![e("gone", "1", 5)]);
        assert_eq!(classify(&cur, &inc), vec![(0, ImportStatus::New)]);
    }

    #[test]
    fn classify_matches_by_canonical_id() {
        let uuid = "6f1f0c3e-6a2b-4c7e-9a3b-0f2c1d4e5a6b";
        let cur = vault(vec![e(&canon_id(uuid), "1", 10)]);
        let inc = vault(vec![e(uuid, "1", 10)]);
        // Same id, but the id string differs, so not identical content.
        assert_eq!(classify(&cur, &inc), vec![(0, ImportStatus::Older)]);
    }

    #[test]
    fn apply_import_only_chosen() {
        let mut cur = vault(vec![e("a", "1", 10), e("b", "1", 10)]);
        let inc = vault(vec![
            e("n", "1", 1),
            e("a", "2", 11),
            e("b", "2", 9),
            e("m", "1", 1),
        ]);
        // choose: new "n", newer "a", older "b" (explicit), skip "m"; plus junk.
        let r = apply_import(&mut cur, &inc, &[0, 1, 2, 99]);
        assert_eq!(r, (1, 2));
        assert_eq!(cur.entries.len(), 3);
        assert_eq!(cur.entries[0].password.as_str(), "2");
        assert_eq!(cur.entries[1].password.as_str(), "2");
        assert_eq!(cur.entries[1].modified_minutes, 9);
        assert_eq!(cur.entries[2].id, "n");
        assert!(!cur.entries.iter().any(|x| x.id == "m"));
    }

    #[test]
    fn apply_import_same_is_noop_and_repeats_do_not_duplicate() {
        let mut cur = vault(vec![e("a", "1", 10)]);
        let inc = vault(vec![e("a", "1", 10), e("n", "1", 1)]);
        assert_eq!(apply_import(&mut cur, &inc, &[0, 1, 1]), (1, 0));
        assert_eq!(cur.entries.len(), 2);
    }
}
