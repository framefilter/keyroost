//! The write loop: store a plan's codes on a key one at a time, stop on the
//! first error, and report what happened to each one.
//!
//! The key itself is behind [`CodeStore`]; the adapters for real keys live in
//! `keyroost-transport`. An entry already on the key is removed only after
//! the key refused to add it as a duplicate and replacing was asked for —
//! never on a plain add.

use crate::entry::{ImportEntry, ImportFile};
use crate::plan::{Plan, PlanRow, Store, StoredName, Verdict};

/// What a key said when asked to store or remove one code.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StoreError {
    /// The key refused an add because the name exists (OATH SW 6983 only).
    Exists,
    /// The key is full (SW 6A84).
    Full,
    /// Anything else. Shown as is; never contains the seed.
    Failed(String),
}

impl core::fmt::Display for StoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StoreError::Exists => f.write_str("the key says this name is already on it"),
            StoreError::Full => f.write_str("the key is full"),
            StoreError::Failed(m) => f.write_str(m),
        }
    }
}

/// One destination's write side (adapters live in keyroost-transport).
pub trait CodeStore {
    /// Store one code. Keys that overwrite same-name entries do so here.
    fn add(&mut self, name: &StoredName, entry: &ImportEntry) -> Result<(), StoreError>;
    /// Remove one code by name.
    fn delete(&mut self, name: &StoredName) -> Result<(), StoreError>;
}

/// What happened to one planned write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Added,
    Replaced,
    /// The key said the name exists although the listing didn't show it.
    AlreadyThere,
    /// The old entry was removed, then adding the new one failed.
    RemovedNotAdded(String),
    Failed(String),
    /// The key filled up before this one.
    NoRoom,
    /// The run stopped before this one.
    NotTried,
}

impl Outcome {
    /// The one word for the outcome: the JSON's `outcome`, and (with the
    /// dashes read as spaces) the GUI report row.
    pub fn word(&self) -> &'static str {
        match self {
            Outcome::Added => "added",
            Outcome::Replaced => "replaced",
            Outcome::AlreadyThere => "exists",
            Outcome::RemovedNotAdded(_) => "removed-not-added",
            Outcome::Failed(_) => "failed",
            Outcome::NoRoom => "no-room",
            Outcome::NotTried => "not-tried",
        }
    }

    /// What happened, in plain words, when the word alone doesn't say it.
    pub fn reason(&self) -> Option<String> {
        match self {
            Outcome::Added | Outcome::Replaced => None,
            Outcome::AlreadyThere => Some(crate::plan::EXISTS_REASON.to_owned()),
            Outcome::RemovedNotAdded(e) => Some(format!(
                "the old code was removed, but the new one wasn't added ({})",
                e
            )),
            Outcome::Failed(e) => Some(e.clone()),
            Outcome::NoRoom => Some(StoreError::Full.to_string()),
            Outcome::NotTried => Some("stopped before this one".to_owned()),
        }
    }

    /// The write went through, or found its code already on the key.
    pub fn went_through(&self) -> bool {
        matches!(
            self,
            Outcome::Added | Outcome::Replaced | Outcome::AlreadyThere
        )
    }
}

/// What a run did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// One row per written plan row, in order: (index, label, outcome).
    pub rows: Vec<(usize, String, Outcome)>,
    /// Why the run stopped early, if it did.
    pub stopped: Option<String>,
}

impl Report {
    /// How many rows have an outcome `o` accepts.
    pub fn count(&self, o: fn(&Outcome) -> bool) -> usize {
        self.rows.iter().filter(|(_, _, out)| o(out)).count()
    }

    /// True when every planned write ended Added / Replaced / AlreadyThere.
    pub fn ok(&self) -> bool {
        self.rows.iter().all(|(_, _, o)| o.went_through())
    }

    /// The counts line both front ends show after a run:
    /// `Added 2, replaced 1; 3 left as is, 1 skipped.`, with `, N not added`
    /// before the period when the run stopped early.
    pub fn summary(&self, plan: &Plan) -> String {
        let added = self.count(|o| matches!(o, Outcome::Added));
        let replaced = self.count(|o| matches!(o, Outcome::Replaced));
        let there = self.count(|o| matches!(o, Outcome::AlreadyThere));
        let not = self.rows.len() - added - replaced - there;
        let c = plan.counts();
        let mut s = format!(
            "Added {}, replaced {}; {} left as is, {} skipped",
            added,
            replaced,
            c.exists + there,
            c.skip
        );
        if not > 0 {
            s.push_str(&format!(", {} not added", not));
        }
        s.push('.');
        s
    }
}

/// Why the run stops, and what the rows after the stopping one become.
struct Stop {
    reason: String,
    rest: Outcome,
}

/// The stop reason when a replace lost the old entry: what is gone, which
/// entry, and why the new one wasn't stored.
fn removed_not_added(name: &StoredName, why: &StoreError) -> String {
    format!(
        "the old code {} was removed from the key, but the new one could not be added ({})",
        name, why
    )
}

/// Write every Add/Replace row of `plan`, one at a time.
/// `progress(done, total, row)` is called before each write. Report rows
/// carry [`PlanRow::shown_label`] (a Molto2 row keeps its slot number).
pub fn run(
    file: &ImportFile,
    plan: &Plan,
    store: &mut dyn CodeStore,
    progress: &mut dyn FnMut(usize, usize, &PlanRow),
) -> Report {
    let writes: Vec<&PlanRow> = plan.writes().collect();
    let total = writes.len();
    let mut rows = Vec::with_capacity(total);
    let mut stop: Option<Stop> = None;
    for (done, row) in writes.into_iter().enumerate() {
        let outcome = match &stop {
            Some(s) => s.rest.clone(),
            None => {
                progress(done, total, row);
                let (outcome, s) = write_one(file, plan, row, store);
                stop = s;
                outcome
            }
        };
        rows.push((row.index, row.shown_label(), outcome));
    }
    Report {
        rows,
        stopped: stop.map(|s| s.reason),
    }
}

fn fail(m: String) -> (Outcome, Option<Stop>) {
    (
        Outcome::Failed(m.clone()),
        Some(Stop {
            reason: m,
            rest: Outcome::NotTried,
        }),
    )
}

fn full() -> (Outcome, Option<Stop>) {
    (
        Outcome::NoRoom,
        Some(Stop {
            reason: StoreError::Full.to_string(),
            rest: Outcome::NoRoom,
        }),
    )
}

/// One planned write and, when it ends the run, why.
fn write_one(
    file: &ImportFile,
    plan: &Plan,
    row: &PlanRow,
    store: &mut dyn CodeStore,
) -> (Outcome, Option<Stop>) {
    let Some(name) = &row.name else {
        return fail("this entry has no name to store it under".to_owned());
    };
    let entry = file
        .items
        .iter()
        .find(|i| i.index == row.index)
        .and_then(|i| i.entry.as_ref().ok());
    let Some(entry) = entry else {
        return fail("this entry is no longer in the file".to_owned());
    };
    let replacing = row.verdict == Verdict::Replace;
    match store.add(name, entry) {
        Ok(()) if replacing => (Outcome::Replaced, None),
        Ok(()) => (Outcome::Added, None),
        Err(StoreError::Full) => full(),
        Err(StoreError::Failed(m)) => fail(m),
        Err(StoreError::Exists) => {
            // A Molto2 slot write overwrites; nothing there is ever deleted.
            let may_replace = plan.store != Store::Molto2 && (replacing || plan.replace);
            if !may_replace {
                return (Outcome::AlreadyThere, None);
            }
            // The key refuses duplicates: remove the old entry, then add.
            if let Err(e) = store.delete(name) {
                return fail(e.to_string());
            }
            match store.add(name, entry) {
                Ok(()) => (Outcome::Replaced, None),
                Err(e) => (
                    Outcome::RemovedNotAdded(e.to_string()),
                    Some(Stop {
                        reason: removed_not_added(name, &e),
                        rest: Outcome::NotTried,
                    }),
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{Format, HashAlg, ImportItem, OtpKind, Unusable};
    use crate::plan::{plan, Existing, OathFamily, Target};
    use std::collections::{HashMap, VecDeque};
    use zeroize::Zeroizing;

    const YK: Store = Store::Oath(OathFamily::YubiKey {
        version: Some((5, 7, 1)),
    });

    fn file(names: &[(&str, &str)]) -> ImportFile {
        ImportFile {
            format: Format::OtpauthList,
            items: names
                .iter()
                .enumerate()
                .map(|(index, (i, a))| ImportItem {
                    index,
                    label: format!("{}:{}", i, a),
                    entry: Ok(ImportEntry {
                        issuer: Some((*i).to_owned()),
                        account: Some((*a).to_owned()),
                        secret: Zeroizing::new(vec![7; 20]),
                        hash: HashAlg::Sha1,
                        digits: 6,
                        kind: OtpKind::Totp { period: 30 },
                    }),
                })
                .collect(),
            batch: None,
        }
    }

    fn plan_for(f: &ImportFile, store: Store, on_key: &[&str], replace: bool) -> Plan {
        plan(
            f,
            &Target {
                store,
                first_slot: 0,
                existing: Existing {
                    names: on_key
                        .iter()
                        .map(|n| StoredName::Oath((*n).to_owned()))
                        .collect(),
                    hidden: 0,
                },
                replace,
            },
        )
    }

    /// Answers scripted per name (default `Ok`), every call recorded.
    #[derive(Default)]
    struct FakeStore {
        add: HashMap<String, VecDeque<Result<(), StoreError>>>,
        delete: HashMap<String, VecDeque<Result<(), StoreError>>>,
        calls: Vec<String>,
    }

    impl FakeStore {
        fn on_add(mut self, name: &str, answers: Vec<Result<(), StoreError>>) -> Self {
            self.add.insert(name.to_owned(), answers.into());
            self
        }
        fn on_delete(mut self, name: &str, answers: Vec<Result<(), StoreError>>) -> Self {
            self.delete.insert(name.to_owned(), answers.into());
            self
        }
    }

    impl CodeStore for FakeStore {
        fn add(&mut self, name: &StoredName, entry: &ImportEntry) -> Result<(), StoreError> {
            assert_eq!(entry.secret.len(), 20);
            let n = name.to_string();
            self.calls.push(format!("add {}", n));
            self.add
                .get_mut(&n)
                .and_then(VecDeque::pop_front)
                .unwrap_or(Ok(()))
        }
        fn delete(&mut self, name: &StoredName) -> Result<(), StoreError> {
            let n = name.to_string();
            self.calls.push(format!("delete {}", n));
            self.delete
                .get_mut(&n)
                .and_then(VecDeque::pop_front)
                .unwrap_or(Ok(()))
        }
    }

    fn go(f: &ImportFile, p: &Plan, s: &mut FakeStore) -> Report {
        run(f, p, s, &mut |_, _, _| {})
    }

    fn outcomes(r: &Report) -> Vec<Outcome> {
        r.rows.iter().map(|(_, _, o)| o.clone()).collect()
    }

    #[test]
    fn adds_in_order_and_reports_added() {
        let f = file(&[("A", "a"), ("B", "b"), ("C", "c")]);
        let p = plan_for(&f, YK, &[], false);
        let mut s = FakeStore::default();
        let r = go(&f, &p, &mut s);
        assert_eq!(s.calls, vec!["add A:a", "add B:b", "add C:c"]);
        assert_eq!(outcomes(&r), vec![Outcome::Added; 3]);
        assert_eq!(r.rows[1], (1, "B:b".to_owned(), Outcome::Added));
        assert!(r.ok());
        assert_eq!(r.stopped, None);
        assert_eq!(r.count(|o| *o == Outcome::Added), 3);
    }

    #[test]
    fn exists_on_add_continues_and_never_deletes() {
        let f = file(&[("A", "a"), ("B", "b")]);
        let p = plan_for(&f, YK, &[], false);
        let mut s = FakeStore::default().on_add("A:a", vec![Err(StoreError::Exists)]);
        let r = go(&f, &p, &mut s);
        assert_eq!(s.calls, vec!["add A:a", "add B:b"]);
        assert_eq!(outcomes(&r), vec![Outcome::AlreadyThere, Outcome::Added]);
        assert!(r.ok());
    }

    #[test]
    fn exists_on_add_with_overwrite_deletes_then_adds() {
        let f = file(&[("A", "a")]);
        let p = plan_for(&f, YK, &[], true);
        let mut s = FakeStore::default().on_add("A:a", vec![Err(StoreError::Exists), Ok(())]);
        let r = go(&f, &p, &mut s);
        assert_eq!(s.calls, vec!["add A:a", "delete A:a", "add A:a"]);
        assert_eq!(outcomes(&r), vec![Outcome::Replaced]);
    }

    #[test]
    fn replace_on_overwriting_key_never_deletes() {
        let f = file(&[("A", "a")]);
        let p = plan_for(&f, YK, &["A:a"], true);
        assert_eq!(p.rows[0].verdict, Verdict::Replace);
        let mut s = FakeStore::default();
        let r = go(&f, &p, &mut s);
        assert_eq!(s.calls, vec!["add A:a"]);
        assert_eq!(outcomes(&r), vec![Outcome::Replaced]);
    }

    #[test]
    fn replace_deletes_only_after_exists_refusal() {
        let f = file(&[("A", "a"), ("B", "b")]);
        let p = plan_for(&f, Store::Oath(OathFamily::Nitrokey3), &["A:a"], true);
        let mut s = FakeStore::default().on_add("A:a", vec![Err(StoreError::Exists), Ok(())]);
        let r = go(&f, &p, &mut s);
        assert_eq!(s.calls, vec!["add A:a", "delete A:a", "add A:a", "add B:b"]);
        assert_eq!(outcomes(&r), vec![Outcome::Replaced, Outcome::Added]);

        // A failed delete stops the run; nothing more is tried.
        let mut s = FakeStore::default()
            .on_add("A:a", vec![Err(StoreError::Exists)])
            .on_delete(
                "A:a",
                vec![Err(StoreError::Failed("touch timed out".into()))],
            );
        let r = go(&f, &p, &mut s);
        assert_eq!(s.calls, vec!["add A:a", "delete A:a"]);
        assert_eq!(
            outcomes(&r),
            vec![Outcome::Failed("touch timed out".into()), Outcome::NotTried]
        );
        assert_eq!(r.stopped.as_deref(), Some("touch timed out"));
    }

    #[test]
    fn replace_add_failure_reports_removed_not_added() {
        let f = file(&[("A", "a"), ("B", "b"), ("C", "c")]);
        let p = plan_for(&f, Store::Oath(OathFamily::Solo2), &["A:a"], true);
        let mut s = FakeStore::default().on_add(
            "A:a",
            vec![
                Err(StoreError::Exists),
                Err(StoreError::Failed("the key refused it".into())),
            ],
        );
        let r = go(&f, &p, &mut s);
        assert_eq!(s.calls, vec!["add A:a", "delete A:a", "add A:a"]);
        assert_eq!(
            outcomes(&r),
            vec![
                Outcome::RemovedNotAdded("the key refused it".into()),
                Outcome::NotTried,
                Outcome::NotTried
            ]
        );
        assert_eq!(
            r.stopped.as_deref(),
            Some(
                "the old code A:a was removed from the key, but the new one could not be \
                 added (the key refused it)"
            )
        );
        assert!(!r.ok());

        // The key filling up between the delete and the add says so too.
        let mut s = FakeStore::default()
            .on_add("A:a", vec![Err(StoreError::Exists), Err(StoreError::Full)]);
        let r = go(&f, &p, &mut s);
        assert_eq!(
            outcomes(&r),
            vec![
                Outcome::RemovedNotAdded("the key is full".into()),
                Outcome::NotTried,
                Outcome::NotTried
            ]
        );
        assert_eq!(
            r.stopped.as_deref(),
            Some(
                "the old code A:a was removed from the key, but the new one could not be \
                 added (the key is full)"
            )
        );
    }

    #[test]
    fn full_stops_and_marks_rest_no_room() {
        let f = file(&[("A", "a"), ("B", "b"), ("C", "c")]);
        let p = plan_for(&f, Store::Oath(OathFamily::Solo2), &[], false);
        let mut s = FakeStore::default().on_add("B:b", vec![Err(StoreError::Full)]);
        let r = go(&f, &p, &mut s);
        assert_eq!(s.calls, vec!["add A:a", "add B:b"]);
        assert_eq!(
            outcomes(&r),
            vec![Outcome::Added, Outcome::NoRoom, Outcome::NoRoom]
        );
        assert_eq!(r.stopped.as_deref(), Some("the key is full"));
        assert!(!r.ok());
        assert_eq!(r.count(|o| *o == Outcome::NoRoom), 2);
    }

    #[test]
    fn failure_stops_and_marks_rest_not_tried() {
        let f = file(&[("A", "a"), ("B", "b"), ("C", "c")]);
        let p = plan_for(&f, YK, &[], false);
        let mut s =
            FakeStore::default().on_add("A:a", vec![Err(StoreError::Failed("key removed".into()))]);
        let r = go(&f, &p, &mut s);
        assert_eq!(s.calls, vec!["add A:a"]);
        assert_eq!(
            outcomes(&r),
            vec![
                Outcome::Failed("key removed".into()),
                Outcome::NotTried,
                Outcome::NotTried
            ]
        );
        assert_eq!(r.stopped.as_deref(), Some("key removed"));
    }

    #[test]
    fn skip_and_exists_rows_are_never_sent() {
        let mut f = file(&[("A", "a"), ("B", "b"), ("C", "c")]);
        f.items[2].entry = Err(Unusable::BadSecret);
        let p = plan_for(&f, YK, &["A:a"], false);
        let mut s = FakeStore::default();
        let r = go(&f, &p, &mut s);
        assert_eq!(s.calls, vec!["add B:b"]);
        assert_eq!(r.rows, vec![(1, "B:b".to_owned(), Outcome::Added)]);
    }

    #[test]
    fn molto_replace_writes_the_slot_and_never_deletes() {
        let f = file(&[("A", "a"), ("B", "b")]);
        let p = plan(
            &f,
            &Target {
                store: Store::Molto2,
                first_slot: 5,
                existing: Existing {
                    names: vec![StoredName::Molto2 {
                        slot: 5,
                        title: String::new(),
                    }],
                    hidden: 0,
                },
                replace: false,
            },
        );
        let mut s = FakeStore::default().on_add("#6 B", vec![Err(StoreError::Exists)]);
        let r = go(&f, &p, &mut s);
        assert_eq!(s.calls, vec!["add #5 A", "add #6 B"]);
        assert_eq!(outcomes(&r), vec![Outcome::Replaced, Outcome::AlreadyThere]);
        // Report rows keep the slot number.
        let labels: Vec<&str> = r.rows.iter().map(|(_, l, _)| l.as_str()).collect();
        assert_eq!(labels, ["#05 A:a", "#06 B:b"]);
    }

    #[test]
    fn summary_and_outcome_words() {
        let f = file(&[("A", "a"), ("B", "b"), ("C", "c")]);
        let p = plan_for(&f, YK, &["B:b"], false);
        let mut s = FakeStore::default();
        let r = go(&f, &p, &mut s);
        assert_eq!(
            r.summary(&p),
            "Added 2, replaced 0; 1 left as is, 0 skipped."
        );
        let stopped = Report {
            rows: vec![
                (0, "A:a".into(), Outcome::Added),
                (2, "C:c".into(), Outcome::Failed("x".into())),
            ],
            stopped: Some("x".into()),
        };
        assert_eq!(
            stopped.summary(&p),
            "Added 1, replaced 0; 1 left as is, 0 skipped, 1 not added."
        );
        assert_eq!(Outcome::AlreadyThere.word(), "exists");
        assert_eq!(
            Outcome::AlreadyThere.reason().as_deref(),
            Some("already on the key; left as is")
        );
        assert_eq!(Outcome::NotTried.word(), "not-tried");
        assert_eq!(Outcome::NoRoom.reason().as_deref(), Some("the key is full"));
    }

    #[test]
    fn progress_counts_writes_only() {
        let f = file(&[("A", "a"), ("B", "b"), ("C", "c")]);
        let p = plan_for(&f, YK, &["B:b"], false);
        let mut seen = Vec::new();
        let mut s = FakeStore::default();
        run(&f, &p, &mut s, &mut |done, total, row| {
            seen.push((done, total, row.label.clone()))
        });
        assert_eq!(
            seen,
            vec![(0, 2, "A:a".to_owned()), (1, 2, "C:c".to_owned())]
        );
    }

    #[test]
    fn progress_stops_with_the_run() {
        let f = file(&[("A", "a"), ("B", "b")]);
        let p = plan_for(&f, YK, &[], false);
        let mut calls = 0;
        let mut s = FakeStore::default().on_add("A:a", vec![Err(StoreError::Full)]);
        run(&f, &p, &mut s, &mut |_, _, _| calls += 1);
        assert_eq!(calls, 1);
    }
}
