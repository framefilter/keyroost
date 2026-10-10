//! `oath import`, `otp import` and `molto import --in`: read an
//! authenticator export, show what each entry becomes on the chosen key,
//! ask once, re-check the key, write, and report. The plan and the write
//! loop live in `keyroost_import`; the per-key adapters in
//! `keyroost_transport::import`. This module is the CLI flow around them
//! plus the text and JSON they are shown as.

use std::error::Error;
use std::path::Path;

use keyroost_import::plan::{molto_plan, Existing, OathFamily, Plan, Store, StoredName, Verdict};
use keyroost_import::run::{CodeStore, Outcome, Report};
use keyroost_import::{Format, ImportFile};
use keyroost_proto::commands::DisplayTimeout;
use keyroost_qr::file::{OpenError, Opened, MAX_FILE_BYTES};
use keyroost_resolve::{Device, Need, SelectError};
use keyroost_transport::import::{
    read_molto_existing, read_oath_existing, read_token2_existing, MoltoImportStore,
    OathImportStore, Token2ImportStore,
};
use keyroost_transport::Session;

use crate::json_out::{ImportJson, ImportRowJson};
use crate::output::{emit_json, json_output};
use crate::secrets::{SecretIo, SecretSource, Secrets, Source};
use crate::{
    ensure_otp_feature, oath_password_from, open_oath_unlocked, open_otp_on, otp_pin_if_needed,
    otp_precheck, sanitize_terminal, select_otp, OathAccess, OtpFeature, OtpSelect, SecondSecret,
    SecretPair, FILE_PASSWORD, UNUSED_FILE_PASSWORD,
};

/// Where an import writes: an OATH applet, or Token2 OTP storage.
pub(crate) enum CodeDest<'a> {
    Oath(&'a OathAccess),
    Otp(&'a OtpSelect<'a>),
}

/// How the report asks for the applet password when the key turns out to
/// want one nobody gave.
const OATH_PASSWORD_HINT: &str = "pass --password env:NAME or --password stdin";

/// `oath import` / `otp import`. Order: check the secret sources, read the
/// file (its password, when it needs one, is read here, on stdin line 1),
/// select and announce the key, get the key's own secret (line 2), read the
/// key, plan and preview, ask once, re-check the key, write, report. Exits 1
/// (an `Err` whose text is the stop line) when the run stops early.
///
/// `pair` is the command's own (`oath_secret_pair` / `otp_secret_pair`):
/// the file password first, the key's password or PIN second. Both are
/// read through [`read_import_file`] and [`read_key_secret_given`], the
/// functions the stdin line-order test drives.
pub(crate) fn run_code_import(
    dest: CodeDest<'_>,
    file: &Path,
    pair: SecretPair<'_>,
    replace: bool,
    dry_run: bool,
    yes: bool,
    debug: bool,
) -> Result<(), Box<dyn Error>> {
    let mut sec = Secrets::real();
    // Only the sources a flag names: each secret is optional, asked for
    // only when the file or the key turns out to need it.
    if pair.first.1.is_some() {
        pair.check_first(&sec)?;
    }
    if pair.second.flag.is_some() {
        pair.second.check(&sec)?;
    }
    let import = read_import_file(&mut sec, file, pair.first.1)?;
    let shown = Shown::new(file, &import, dry_run, yes);
    match dest {
        CodeDest::Oath(access) => to_oath(
            &mut sec,
            access,
            pair.second,
            &import,
            &shown,
            replace,
            debug,
        ),
        CodeDest::Otp(sel) => to_otp(&mut sec, sel, pair.second, &import, &shown, replace, debug),
    }
}

/// What the preview and the question need besides the plan.
struct Shown {
    file_name: String,
    format: Format,
    dry_run: bool,
    yes: bool,
}

impl Shown {
    fn new(file: &Path, import: &ImportFile, dry_run: bool, yes: bool) -> Self {
        Shown {
            file_name: file
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| file.display().to_string()),
            format: import.format,
            dry_run,
            yes,
        }
    }
}

/// `molto import --in`: the Molto2 and how to write to it.
pub(crate) struct MoltoImport<'a> {
    pub key: &'a crate::KeyArgs,
    /// The molto group's `--reader`.
    pub reader: Option<&'a str>,
    /// The slot the first entry goes to; the others follow in order.
    pub first_slot: u8,
    pub display_timeout: DisplayTimeout,
    pub file_password: Option<&'a SecretSource>,
}

/// `molto import --in`, on the same plan, preview, question, write and
/// report as the other imports. Order: check the secret sources, read the
/// customer key (stdin line 1) and the file (its password on line 2),
/// select and announce the Molto2, read which slots are in use (no key
/// needed), plan and preview, ask once, re-check, authenticate, write,
/// report. Slots in use are replaced (the Molto2's slot model); entries the
/// Molto2 can't store are skipped with the reason.
///
/// `--dry-run` writes nothing and needs no Molto2: with none connected the
/// preview is made without slot use and says so.
pub(crate) fn run_molto_import(
    m: &MoltoImport<'_>,
    file: &Path,
    dry_run: bool,
    yes: bool,
    debug: bool,
) -> Result<(), Box<dyn Error>> {
    let mut sec = Secrets::real();
    if m.file_password.is_some() {
        sec.check(&FILE_PASSWORD, Source::from_flag(m.file_password))?;
    }
    let (key, import) = read_molto_import_secrets(&mut sec, m.key, file, m.file_password, dry_run)?;
    let shown = Shown::new(file, &import, dry_run, yes);
    let Some(key) = key else {
        return molto_dry_run(m, &import, &shown, debug);
    };
    let dev = crate::target::select(Need::Molto2, m.reader, None)?;
    let reader = crate::target::reader_of(&dev)?;
    let (serial, existing) = molto_slot_use(&reader, debug, true)?; // closed before the question
    crate::warn_default_customer_key(&key);
    let first = molto_plan(&import, m.first_slot, existing);
    let view = KeyView::from_slot(m.first_slot);
    let Some(asked) = preview_and_ask(&dev, &shown, &first, view)? else {
        return Ok(());
    };
    crate::prompt::reverify_if_asked(&dev, asked || sec.prompted())?;
    let mut session = Session::open_named(&reader)?;
    session.set_debug(debug);
    crate::same_molto(Some(&serial), &session.read_info()?.serial)?;
    crate::molto_authenticate(&mut session, &key)?;
    let again = molto_plan(&import, m.first_slot, read_molto_existing(&mut session)?);
    recheck(&first, &again)?;
    let mut writer = MoltoImportStore::new(&mut session, m.display_timeout);
    write_and_report(&import, &again, &mut writer)
}

/// The customer key (stdin line 1), then the file (its password, when it
/// needs one, on line 2). A dry run never uses the key: it reads and drops
/// it only when both are piped, to keep the password on line 2, and returns
/// `None`.
pub(crate) fn read_molto_import_secrets<I: SecretIo>(
    sec: &mut Secrets<I>,
    key: &crate::KeyArgs,
    file: &Path,
    file_password: Option<&SecretSource>,
    dry_run: bool,
) -> Result<(Option<crate::CustomerKey>, ImportFile), Box<dyn Error>> {
    let key = if dry_run {
        crate::molto_dry_run_key(sec, key, file_password)?;
        None
    } else {
        Some(crate::customer_key(sec, key)?)
    };
    Ok((key, read_import_file(sec, file, file_password)?))
}

/// The dry run: slot use from the Molto2 when one is connected (or named
/// with `-d` / `--reader`), else the preview without it. A Molto2 that is
/// there but doesn't answer gets the preview without slot use and a note
/// saying so (a real import stops instead).
fn molto_dry_run(
    m: &MoltoImport<'_>,
    import: &ImportFile,
    shown: &Shown,
    debug: bool,
) -> Result<(), Box<dyn Error>> {
    let chosen = m.reader.is_some() || crate::target::device_flag().is_some();
    let dev = match crate::target::select(Need::Molto2, m.reader, None) {
        Ok(dev) => Some(dev),
        Err(e)
            if !chosen
                && matches!(
                    e.downcast_ref::<SelectError>(),
                    Some(SelectError::NoCandidates { .. })
                ) =>
        {
            None
        }
        Err(e) => return Err(e),
    };
    let Some(dev) = dev else {
        let plan = molto_plan(import, m.first_slot, Existing::default());
        let view = KeyView {
            first_slot: m.first_slot,
            unread: Some(MOLTO_SLOTS_UNREAD),
        };
        let lines = preview_lines(&shown.file_name, shown.format, "the Molto2", &plan, view);
        return print_dry_run(&lines, &plan, false);
    };
    let read = crate::target::reader_of(&dev)
        .and_then(|reader| molto_slot_use(&reader, debug, false).map(|(_, existing)| existing));
    let (existing, note) = slot_use_or_note(read);
    let plan = molto_plan(import, m.first_slot, existing);
    let view = KeyView {
        first_slot: m.first_slot,
        unread: note.as_deref(),
    };
    preview_and_ask(&dev, shown, &plan, view).map(|_| ())
}

/// Slot use as read, or none and the note that says the Molto2 didn't
/// answer.
fn slot_use_or_note(read: Result<Existing, Box<dyn Error>>) -> (Existing, Option<String>) {
    match read {
        Ok(existing) => (existing, None),
        Err(e) => (
            Existing::default(),
            Some(format!(
                "Slot use couldn't be read: the Molto2 didn't answer ({}).",
                sanitize_terminal(&e.to_string())
            )),
        ),
    }
}

/// The Molto2's serial and used slots, read in a short session with no key.
/// Before a real import the serial and clock go to stderr, as before every
/// Molto2 write (which token, and the clock-drift warning); a dry run writes
/// nothing, so it skips them.
fn molto_slot_use(
    reader: &str,
    debug: bool,
    show_info: bool,
) -> Result<(String, Existing), Box<dyn Error>> {
    let mut session = Session::open_named(reader)?;
    session.set_debug(debug);
    let info = session.read_info()?;
    if show_info {
        crate::write_info(&mut std::io::stderr(), &info)?;
    }
    Ok((info.serial, read_molto_existing(&mut session)?))
}

/// A dry run's output: the preview on stdout, or its JSON.
fn print_dry_run(lines: &[String], plan: &Plan, key_read: bool) -> Result<(), Box<dyn Error>> {
    if json_output() {
        emit_json(&import_json(plan, None, true, key_read))?;
    } else {
        for l in lines {
            println!("{l}");
        }
    }
    Ok(())
}

/// Read and sort the file before any key is looked at: recognized key
/// material gets the pointer to where it belongs; an encrypted Aegis
/// export asks for its password (stdin line 1). A password given for a
/// file that doesn't need one is still read off a pipe, so the key's own
/// secret stays on line 2, and is then dropped with a warning.
pub(crate) fn read_import_file<I: SecretIo>(
    sec: &mut Secrets<I>,
    path: &Path,
    password: Option<&SecretSource>,
) -> Result<ImportFile, Box<dyn Error>> {
    let read_err = |e: std::io::Error| format!("read {}: {}", path.display(), e);
    let f = std::fs::File::open(path).map_err(read_err)?;
    if f.metadata().map_err(read_err)?.len() > MAX_FILE_BYTES as u64 {
        return Err(format!(
            "{}: larger than 16 MiB, too large for an authenticator export or a \
             screenshot. Nothing was read.",
            path.display()
        )
        .into());
    }
    // Wipe-on-drop: a plain export is every seed in clear.
    let bytes =
        keyroost_qr::file::read_bounded(f).map_err(|e| format!("{}: {e}", path.display()))?;
    let name = path.file_name().and_then(|n| n.to_str());
    let open = |pw: Option<&[u8]>| {
        keyroost_qr::open_file(&bytes, name, pw).map_err(|e: OpenError| e.to_string())
    };
    let file = match open(None)? {
        Opened::Entries(file) => {
            if password.is_some() {
                if matches!(password, Some(SecretSource::Stdin)) && !sec.io.stdin_is_terminal() {
                    drop(sec.read(&FILE_PASSWORD, Source::from_flag(password))?);
                }
                crate::output::warn(UNUSED_FILE_PASSWORD);
            }
            file
        }
        Opened::KeyMaterial(k) => return Err(k.cli_pointer().into()),
        Opened::NeedsPassword => {
            let pw = sec.read(&FILE_PASSWORD, Source::from_flag(password))?;
            match open(Some(pw.as_bytes()))? {
                Opened::Entries(file) => file,
                _ => return Err("this Aegis export couldn't be opened".into()),
            }
        }
    };
    if let Some((i, n)) = file.batch {
        crate::output::note(&format!(
            "this is QR {} of {} in the export — import the other images too",
            i + 1,
            n
        ));
    }
    if matches!(file.format, Format::QrImage | Format::GoogleExport) {
        crate::output::note("remember to delete the screenshot after a successful import");
    }
    Ok(file)
}

/// The key's password or PIN when a flag names its source (the pair's
/// second secret: stdin line 2 after a file password, line 1 alone).
/// `None` when no flag names it; the handler then asks the key whether it
/// needs one and prompts only if it does.
pub(crate) fn read_key_secret_given<I: SecretIo>(
    sec: &mut Secrets<I>,
    second: SecondSecret<'_>,
) -> Result<Option<zeroize::Zeroizing<String>>, String> {
    sec.read_given(second.spec, second.source())
}

/// The plan for `existing` on `store`.
fn plan_for(file: &ImportFile, store: Store, existing: Existing, replace: bool) -> Plan {
    keyroost_import::plan::plan_for(file, store, 0, existing, replace)
}

/// Show the plan and ask. `None` when there is nothing more to do (a dry
/// run, or nothing to write); otherwise whether the question was shown.
fn preview_and_ask(
    dev: &Device,
    shown: &Shown,
    plan: &Plan,
    view: KeyView<'_>,
) -> Result<Option<bool>, Box<dyn Error>> {
    let key = crate::prompt::key_label(dev);
    let lines = preview_lines(&shown.file_name, shown.format, &key, plan, view);
    if shown.dry_run {
        print_dry_run(&lines, plan, view.unread.is_none())?;
        return Ok(None);
    }
    for l in &lines {
        eprintln!("{l}");
    }
    let c = plan.counts();
    let n = c.add + c.replace;
    if n == 0 {
        if json_output() {
            emit_json(&import_json(
                plan,
                Some(&Report {
                    rows: Vec::new(),
                    stopped: None,
                }),
                false,
                true,
            ))?;
        } else {
            println!("Nothing to add.");
        }
        return Ok(None);
    }
    Ok(Some(crate::prompt::confirm_then_read(
        dev,
        shown.yes,
        &question(plan),
    )?))
}

/// What the one question asks to do.
fn question(plan: &Plan) -> String {
    let c = plan.counts();
    let n = c.add + c.replace;
    let replacing = if c.replace > 0 {
        let what = match plan.store {
            Store::Molto2 => "a slot in use",
            _ => "a code of the same name",
        };
        format!(
            " ({} of them replace{} {what})",
            c.replace,
            if c.replace == 1 { "s" } else { "" }
        )
    } else {
        String::new()
    };
    format!(
        "add {n} code{} to this key{replacing}",
        if n == 1 { "" } else { "s" }
    )
}

/// Write `plan` through `store`, one progress line per code on stderr, then
/// the summary (or the JSON) on stdout.
fn write_and_report(
    file: &ImportFile,
    plan: &Plan,
    store: &mut dyn CodeStore,
) -> Result<(), Box<dyn Error>> {
    let report = keyroost_import::run::run(file, plan, store, &mut |done, total, row| {
        eprintln!(
            "[{}/{}] {} {}",
            done + 1,
            total,
            progress_word(&row.verdict),
            sanitize_terminal(&row.shown_label())
        );
    });
    let summary = report_summary(plan, &report);
    if json_output() {
        emit_json(&import_json(plan, Some(&report), false, true))?;
    } else if let Ok(line) = &summary {
        println!("{line}");
    }
    summary.map(|_| ()).map_err(Into::into)
}

/// Into an OATH applet: the applet password (if it has one) is read after
/// the key is announced, by flag or at the prompt with no session open.
fn to_oath(
    sec: &mut Secrets,
    access: &OathAccess,
    password: SecondSecret<'_>,
    file: &ImportFile,
    shown: &Shown,
    replace: bool,
    debug: bool,
) -> Result<(), Box<dyn Error>> {
    let dev = crate::target::select(Need::Oath, access.reader.as_deref(), None)?;
    let (reader, pw) = match read_key_secret_given(sec, password)? {
        Some(pw) => (crate::target::reader_of(&dev)?, Some(pw)),
        None => oath_password_from(sec, access, Source::NONE, debug)?,
    };
    crate::prompt::reverify_if_asked(&dev, sec.prompted())?;
    let pw = pw.as_deref().map(String::as_str);
    let (existing, version) = {
        let mut session = open_oath_unlocked(&reader, pw, debug)?;
        (read_oath_existing(&mut session)?, session.version())
    }; // closed before the question
    let family = OathFamily::from_vendor(&dev.vendor, version);
    let store = Store::Oath(family);
    let first = plan_for(file, store, existing, replace);
    let Some(asked) = preview_and_ask(&dev, shown, &first, KeyView::READ)? else {
        return Ok(());
    };
    crate::prompt::reverify_if_asked(&dev, asked || sec.prompted())?;
    let mut session = open_oath_unlocked(&reader, pw, debug)?;
    let again = plan_for(file, store, read_oath_existing(&mut session)?, replace);
    recheck(&first, &again)?;
    let mut writer = OathImportStore::new(&mut session, family).password_hint(OATH_PASSWORD_HINT);
    write_and_report(file, &again, &mut writer)
}

/// Into Token2 OTP storage: a key without the OTP function is refused
/// before anything is asked; the OTP PIN (if the key has one) is read with
/// no session open.
fn to_otp(
    sec: &mut Secrets,
    sel: &OtpSelect<'_>,
    pin: SecondSecret<'_>,
    file: &ImportFile,
    shown: &Shown,
    replace: bool,
    debug: bool,
) -> Result<(), Box<dyn Error>> {
    let dev = select_otp(sel)?;
    otp_precheck(&dev, sel.transport, debug, OtpFeature::OnDevice)?;
    let waited = sec.prompted();
    let pin = match read_key_secret_given(sec, pin)? {
        Some(pin) => {
            crate::prompt::reverify_if_asked(&dev, waited || sec.prompted())?;
            Some(pin)
        }
        None => otp_pin_if_needed(sec, &dev, sel.transport, debug, Source::NONE, waited)?,
    };
    let pin_str = pin.as_deref().map(String::as_str);
    let existing = {
        let mut session = open_otp_on(&dev, sel.transport, debug)?;
        read_token2_existing(&mut session, pin_str)?
    }; // closed before the question
    let first = plan_for(file, Store::Token2Otp, existing, replace);
    let Some(asked) = preview_and_ask(&dev, shown, &first, KeyView::READ)? else {
        return Ok(());
    };
    crate::prompt::reverify_if_asked(&dev, asked || sec.prompted())?;
    let mut session = open_otp_on(&dev, sel.transport, debug)?;
    ensure_otp_feature(&mut session, OtpFeature::OnDevice)?;
    let existing = read_token2_existing(&mut session, pin_str)?;
    let again = plan_for(file, Store::Token2Otp, existing, replace);
    recheck(&first, &again)?;
    let mut writer = Token2ImportStore::new(&mut session, pin.clone());
    write_and_report(file, &again, &mut writer)
}

/// The name column never grows past this many characters, so a long name
/// can't push its reason off the screen; a longer name gets its reason on
/// the next line.
const NAME_COLUMN_MAX: usize = 32;

/// What the preview knows besides the plan: the Molto2's start slot, and
/// why what is on the key wasn't read (a note), when it wasn't.
#[derive(Clone, Copy)]
pub(crate) struct KeyView<'a> {
    pub first_slot: u8,
    pub unread: Option<&'a str>,
}

impl KeyView<'static> {
    /// The key was read (every OATH and OTP preview).
    pub const READ: Self = KeyView {
        first_slot: 0,
        unread: None,
    };

    /// A Molto2 read from `first_slot`.
    fn from_slot(first_slot: u8) -> Self {
        KeyView {
            first_slot,
            unread: None,
        }
    }
}

/// The storage an import writes to, after the key's label: " OATH",
/// " OTP", or the Molto2 slots the plan fills (", slots #95 to #99").
fn store_words(store: Store, first_slot: u8) -> String {
    match store {
        Store::Token2Otp => " OTP".to_owned(),
        Store::Oath(_) => " OATH".to_owned(),
        Store::Molto2 => format!(", slots #{first_slot:02} to #99"),
    }
}

/// Said when a dry run had no Molto2 to read slot use from.
const MOLTO_SLOTS_UNREAD: &str = "Slot use is read from the Molto2 when one is connected.";

/// The progress line's verb for a write.
fn progress_word(v: &Verdict) -> &'static str {
    match v {
        Verdict::Replace => "replacing",
        _ => "adding",
    }
}

/// Why a row isn't a plain add (the shared reason), plus the CLI's flag
/// hint on a row left as is.
fn verdict_reason(v: &Verdict, store: Store) -> Option<String> {
    let reason = v.reason(store)?;
    Some(match v {
        Verdict::Exists => format!("{reason} (--replace replaces it)"),
        _ => reason,
    })
}

/// A row's name as shown: the stored name, else the file's label; a
/// Molto2 row is its slot and the file's label (`#05 GitHub`), as the
/// progress lines and the GUI name it.
fn shown_name(row: &keyroost_import::plan::PlanRow) -> String {
    let raw = match &row.name {
        Some(StoredName::Molto2 { .. }) => row.shown_label(),
        Some(n) => n.to_string(),
        None => row.label.clone(),
    };
    sanitize_terminal(&raw)
}

/// "1 entry" / "3 entries".
fn entries(n: usize) -> String {
    if n == 1 {
        "1 entry".to_owned()
    } else {
        format!("{n} entries")
    }
}

/// The preview: one header line, one line per entry (two when the name is
/// too long for its column), the counts, then one line per note. Every
/// name and label is sanitized; seeds never appear. `view.unread` is set
/// for a Molto2 dry run that couldn't read slot use, and is the last note.
pub(crate) fn preview_lines(
    file_name: &str,
    format: Format,
    key: &str,
    plan: &Plan,
    view: KeyView<'_>,
) -> Vec<String> {
    let mut out = vec![format!(
        "{} in {} ({}) for {}{}:",
        entries(plan.rows.len()),
        sanitize_terminal(file_name),
        format.name(),
        key,
        store_words(plan.store, view.first_slot)
    )];
    let names: Vec<String> = plan.rows.iter().map(shown_name).collect();
    let width = names
        .iter()
        .map(|n| n.chars().count())
        .max()
        .unwrap_or(0)
        .min(NAME_COLUMN_MAX);
    for (row, name) in plan.rows.iter().zip(&names) {
        let word = row.verdict.word();
        match verdict_reason(&row.verdict, plan.store) {
            None => out.push(format!("  {word:<10}{name}")),
            Some(reason) if name.chars().count() > width => {
                out.push(format!("  {word:<10}{name}"));
                out.push(format!("{}{reason}", " ".repeat(2 + 10 + width + 2)));
            }
            Some(reason) => out.push(format!("  {word:<10}{name:<width$}  {reason}")),
        }
    }
    let c = plan.counts();
    let on_key = match (plan.store, view.unread.is_none()) {
        (_, false) => String::new(),
        (Store::Molto2, true) => format!("{} slots in use on the key; ", plan.on_key),
        (_, true) => {
            let holds = plan
                .capacity
                .map(|n| format!("Holds {n} codes; "))
                .unwrap_or_default();
            format!("{holds}{} on the key; ", plan.on_key)
        }
    };
    out.push(format!(
        "{on_key}{} will be added, {} replaced, {} left as is, {} skipped.",
        c.add, c.replace, c.exists, c.skip
    ));
    out.extend(plan.notes.iter().map(|n| format!("Note: {n}")));
    if let Some(why) = view.unread {
        out.push(format!("Note: {}", sanitize_terminal(why)));
    }
    out
}

/// The closing line of a run: `Ok` with the summary when every planned
/// write went through, otherwise `Err` with the line saying where and why
/// the run stopped (the CLI then exits 1).
pub(crate) fn report_summary(plan: &Plan, report: &Report) -> Result<String, String> {
    let added = report.count(|o| matches!(o, Outcome::Added));
    let replaced = report.count(|o| matches!(o, Outcome::Replaced));
    let Some(stop) = report.rows.iter().position(|(_, _, o)| !o.went_through()) else {
        return Ok(report.summary(plan));
    };
    let (_, label, outcome) = &report.rows[stop];
    let reason = match (&report.stopped, outcome) {
        (Some(r), _) => r.clone(),
        (None, Outcome::Failed(e) | Outcome::RemovedNotAdded(e)) => e.clone(),
        (None, _) => "the key didn't take it".to_owned(),
    };
    let not_tried = report.rows.len() - stop - 1;
    Err(format!(
        "Stopped at {}: {}. {} added before that; {not_tried} not tried.",
        sanitize_terminal(label),
        sanitize_terminal(&reason),
        added + replaced
    ))
}

/// Nothing is written when the key's codes changed between the preview and
/// the write (the person answered a question meanwhile).
pub(crate) fn recheck(first: &Plan, second: &Plan) -> Result<(), String> {
    if first.same_rows(second) {
        Ok(())
    } else {
        Err(
            "the codes on the key changed while waiting; nothing was written. \
             Run the command again."
                .to_owned(),
        )
    }
}

/// An outcome as the JSON's `outcome`, with the key's error where it has one.
fn outcome_json(o: &Outcome) -> (&'static str, Option<String>) {
    let error = match o {
        Outcome::RemovedNotAdded(e) | Outcome::Failed(e) => Some(e.clone()),
        _ => None,
    };
    (o.word(), error)
}

/// The `--json` shape: the plan, plus each write's outcome after a run.
/// `on_key` is null when nothing was read from the key (`key_read` false:
/// a Molto2 dry run with no Molto2 connected).
pub(crate) fn import_json(
    plan: &Plan,
    report: Option<&Report>,
    dry_run: bool,
    key_read: bool,
) -> ImportJson {
    let entries = plan
        .rows
        .iter()
        .map(|row| {
            let done = report
                .and_then(|r| r.rows.iter().find(|(i, _, _)| *i == row.index))
                .map(|(_, _, o)| outcome_json(o));
            ImportRowJson {
                index: row.index,
                label: row.label.clone(),
                name: row.name.as_ref().map(|n| n.to_string()),
                plan: row.verdict.word(),
                reason: verdict_reason(&row.verdict, plan.store),
                outcome: done.as_ref().map(|(o, _)| *o),
                error: done.and_then(|(_, e)| e),
            }
        })
        .collect();
    ImportJson {
        destination: match plan.store {
            Store::Token2Otp => "otp",
            Store::Molto2 => "molto2",
            Store::Oath(_) => "oath",
        },
        dry_run,
        capacity: plan.capacity,
        on_key: key_read.then_some(plan.on_key),
        entries,
        stopped: report.and_then(|r| r.stopped.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyroost_import::plan::{Existing, Note, OathFamily, PlanRow, Skip, StoredName, Target};
    use keyroost_import::run::{CodeStore, StoreError};
    use keyroost_import::{HashAlg, ImportEntry};

    const YK: Store = Store::Oath(OathFamily::YubiKey {
        version: Some((5, 7, 1)),
    });

    fn row(index: usize, name: &str, verdict: Verdict) -> PlanRow {
        PlanRow {
            index,
            label: name.to_owned(),
            name: Some(StoredName::Oath(name.to_owned())),
            verdict,
        }
    }

    fn mixed_plan() -> Plan {
        Plan {
            store: Store::Oath(OathFamily::Solo2),
            rows: vec![
                row(0, "Example:alice", Verdict::Add),
                row(1, "60/Example:bob", Verdict::Add),
                row(2, "Example:dup", Verdict::Exists),
                row(3, "Example:old", Verdict::Replace),
                PlanRow {
                    index: 4,
                    label: "Steam:me".to_owned(),
                    name: None,
                    verdict: Verdict::Skip(Skip::Unusable(keyroost_import::Unusable::Type(
                        "steam".into(),
                    ))),
                },
                row(5, "Bank:x", Verdict::Skip(Skip::Hash(HashAlg::Sha512))),
            ],
            capacity: Some(32),
            on_key: 5,
            replace: false,
            notes: vec![Note::CapacityUnknown],
        }
    }

    #[test]
    fn preview_lines_table() {
        let lines = preview_lines(
            "vault.json",
            Format::AegisEncrypted,
            "solo-test (serial 1234)",
            &mixed_plan(),
            KeyView::READ,
        );
        let want = [
            "6 entries in vault.json (Aegis, encrypted) for solo-test (serial 1234) OATH:",
            "  add       Example:alice",
            "  add       60/Example:bob",
            "  exists    Example:dup     already on the key; left as is (--replace replaces it)",
            "  replace   Example:old     replaces the code of the same name on the key",
            "  skip      Steam:me        Steam codes aren't supported",
            "  skip      Bank:x          Solo 2 doesn't take SHA-512 codes",
            "Holds 32 codes; 5 on the key; 2 will be added, 1 replaced, 1 left as is, 2 skipped.",
            "Note: This key doesn't report how many codes it holds; writing stops if it fills up.",
        ];
        assert_eq!(lines, want);
    }

    #[test]
    fn preview_puts_a_long_names_reason_on_its_own_line_and_sanitizes() {
        let long = format!("Issuer:{}", "a".repeat(40));
        let plan = Plan {
            store: Store::Token2Otp,
            rows: vec![
                row(0, &long, Verdict::Exists),
                row(1, "Evil\u{1b}[2J:x", Verdict::Add),
            ],
            capacity: None,
            on_key: 0,
            replace: false,
            notes: Vec::new(),
        };
        let lines = preview_lines("list.txt", Format::OtpauthList, "t2", &plan, KeyView::READ);
        assert_eq!(
            lines[0],
            "2 entries in list.txt (otpauth:// list) for t2 OTP:"
        );
        assert_eq!(lines[1], format!("  exists    {long}"));
        assert_eq!(
            lines[2],
            format!(
                "{}already on the key; left as is (--replace replaces it)",
                " ".repeat(2 + 10 + NAME_COLUMN_MAX + 2)
            )
        );
        assert!(!lines[3].contains('\u{1b}'), "{}", lines[3]);
        assert_eq!(
            lines[4],
            "0 on the key; 1 will be added, 0 replaced, 1 left as is, 0 skipped."
        );
        assert_eq!(lines.len(), 5);
    }

    fn slot_row(index: usize, label: &str, slot: Option<u8>, verdict: Verdict) -> PlanRow {
        PlanRow {
            index,
            label: label.to_owned(),
            name: slot.map(|slot| StoredName::Molto2 {
                slot,
                title: label.chars().take(12).collect(),
            }),
            verdict,
        }
    }

    /// From slot #95: an add, a replace, a skip and one past #99.
    fn slot_plan(on_key: usize, notes: Vec<Note>) -> Plan {
        Plan {
            store: Store::Molto2,
            rows: vec![
                slot_row(0, "GitHub:alice", Some(95), Verdict::Add),
                slot_row(1, "Bank:bob", Some(96), Verdict::Replace),
                slot_row(
                    2,
                    "Mail:x",
                    None,
                    Verdict::Skip(Skip::Hash(HashAlg::Sha512)),
                ),
                slot_row(3, "Late:y", None, Verdict::Skip(Skip::PastLastSlot)),
            ],
            capacity: Some(5),
            on_key,
            replace: false,
            notes,
        }
    }

    #[test]
    fn molto_preview_shows_slots_and_slot_use() {
        let plan = slot_plan(3, vec![Note::MoltoReplacesSlots]);
        let lines = preview_lines("codes.json", Format::Aegis, "Molto2", &plan, from(95, None));
        let want = [
            "4 entries in codes.json (Aegis) for Molto2, slots #95 to #99:",
            "  add       #95 GitHub:alice",
            "  replace   #96 Bank:bob      replaces the code in this slot",
            "  skip      Mail:x            Molto2 doesn't take SHA-512 codes",
            "  skip      Late:y            no slot left after #99",
            "3 slots in use on the key; 1 will be added, 1 replaced, 0 left as is, 2 skipped.",
            "Note: Slots already in use will be replaced.",
        ];
        assert_eq!(lines, want);
    }

    #[test]
    fn molto_dry_run_without_a_molto2_says_slot_use_is_unread() {
        let plan = slot_plan(0, Vec::new());
        let lines = preview_lines(
            "codes.json",
            Format::Aegis,
            "the Molto2",
            &plan,
            from(95, Some(MOLTO_SLOTS_UNREAD)),
        );
        assert_eq!(
            lines[0],
            "4 entries in codes.json (Aegis) for the Molto2, slots #95 to #99:"
        );
        assert_eq!(
            &lines[5..],
            [
                "1 will be added, 1 replaced, 0 left as is, 2 skipped.",
                "Note: Slot use is read from the Molto2 when one is connected.",
            ]
        );
        let json = import_json(&plan, None, true, false);
        assert_eq!(json.destination, "molto2");
        assert_eq!((json.capacity, json.on_key), (Some(5), None));
        assert_eq!(json.entries[0].name.as_deref(), Some("#95 GitHub:alice"));
        let read = import_json(&plan, None, true, true);
        assert_eq!(read.on_key, Some(0));
    }

    fn from(first_slot: u8, unread: Option<&str>) -> KeyView<'_> {
        KeyView { first_slot, unread }
    }

    /// The header names the start slot it is given, not one worked back
    /// from the plan's capacity.
    #[test]
    fn molto_header_names_the_given_start_slot() {
        let mut plan = slot_plan(0, Vec::new());
        plan.capacity = None;
        let lines = preview_lines("c.json", Format::Aegis, "Molto2", &plan, from(90, None));
        assert_eq!(
            lines[0],
            "4 entries in c.json (Aegis) for Molto2, slots #90 to #99:"
        );
    }

    /// A Molto2 that is there but doesn't answer in a dry run: the preview
    /// is made without slot use and says why.
    #[test]
    fn unreadable_slot_use_falls_back_with_a_note() {
        let (ex, note) = slot_use_or_note(Ok(Existing {
            names: vec![StoredName::Molto2 {
                slot: 3,
                title: "x".into(),
            }],
            hidden: 0,
        }));
        assert_eq!((ex.names.len(), note), (1, None));
        let (ex, note) = slot_use_or_note(Err("card \u{1b}[2Jtimed out".into()));
        assert!(ex.names.is_empty());
        let note = note.unwrap();
        assert!(
            note.starts_with("Slot use couldn't be read: the Molto2 didn't answer (card"),
            "{note}"
        );
        assert!(!note.contains('\u{1b}'), "{note}");
        let plan = slot_plan(0, Vec::new());
        let lines = preview_lines(
            "c.json",
            Format::Aegis,
            "Molto2",
            &plan,
            from(95, Some(&note)),
        );
        assert_eq!(lines.last().unwrap(), &format!("Note: {note}"));
    }

    #[test]
    fn question_names_what_is_replaced() {
        assert_eq!(
            question(&slot_plan(3, Vec::new())),
            "add 2 codes to this key (1 of them replaces a slot in use)"
        );
        assert_eq!(
            question(&mixed_plan()),
            "add 3 codes to this key (1 of them replaces a code of the same name)"
        );
    }

    fn report(rows: Vec<(usize, &str, Outcome)>, stopped: Option<&str>) -> Report {
        Report {
            rows: rows
                .into_iter()
                .map(|(i, l, o)| (i, l.to_owned(), o))
                .collect(),
            stopped: stopped.map(str::to_owned),
        }
    }

    #[test]
    fn import_exit_code_follows_report() {
        let plan = mixed_plan();
        let ok = report(
            vec![
                (0, "Example:alice", Outcome::Added),
                (1, "60/Example:bob", Outcome::AlreadyThere),
                (3, "Example:old", Outcome::Replaced),
            ],
            None,
        );
        assert_eq!(
            report_summary(&plan, &ok),
            Ok("Added 1, replaced 1; 2 left as is, 2 skipped.".to_owned())
        );
        let stopped = report(
            vec![
                (0, "Example:alice", Outcome::Added),
                (
                    1,
                    "60/Example:bob",
                    Outcome::Failed("the key said 6A80".into()),
                ),
                (3, "Example:old", Outcome::NotTried),
            ],
            Some("the key said 6A80"),
        );
        assert_eq!(
            report_summary(&plan, &stopped),
            Err(
                "Stopped at 60/Example:bob: the key said 6A80. 1 added before that; 1 not tried."
                    .to_owned()
            )
        );
        let full = report(
            vec![
                (0, "Example:alice", Outcome::NoRoom),
                (1, "60/Example:bob", Outcome::NoRoom),
                (3, "Example:old", Outcome::NoRoom),
            ],
            Some("the key is full"),
        );
        assert_eq!(
            report_summary(&plan, &full),
            Err(
                "Stopped at Example:alice: the key is full. 0 added before that; 2 not tried."
                    .to_owned()
            )
        );
        let lost = report(
            vec![(
                3,
                "Example:old",
                Outcome::RemovedNotAdded("the key is full".into()),
            )],
            Some(
                "the old code Example:old was removed from the key, but the new one \
                 could not be added (the key is full)",
            ),
        );
        let line = report_summary(&plan, &lost).unwrap_err();
        assert!(
            line.contains("the old code Example:old was removed"),
            "{line}"
        );
    }

    #[test]
    fn plan_changed_while_waiting_writes_nothing() {
        let first = mixed_plan();
        assert_eq!(recheck(&first, &first.clone()), Ok(()));
        let mut second = first.clone();
        second.rows[0].verdict = Verdict::Exists;
        assert_eq!(
            recheck(&first, &second),
            Err(
                "the codes on the key changed while waiting; nothing was written. \
                 Run the command again."
                    .to_owned()
            )
        );
    }

    /// A key that stores everything.
    struct Accepts;
    impl CodeStore for Accepts {
        fn add(&mut self, _: &StoredName, _: &ImportEntry) -> Result<(), StoreError> {
            Ok(())
        }
        fn delete(&mut self, _: &StoredName) -> Result<(), StoreError> {
            Ok(())
        }
    }

    #[test]
    fn preview_report_and_json_never_contain_seed() {
        let file = keyroost_import::parse_list_wide(
            "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example\n\
             otpauth://totp/Bank:x?secret=JBSWY3DPEHPK3PXP&algorithm=SHA512\n",
        )
        .unwrap();
        let plan = keyroost_import::plan::plan(
            &file,
            &Target {
                store: YK,
                first_slot: 0,
                existing: Existing::default(),
                replace: false,
            },
        );
        let report = keyroost_import::run::run(&file, &plan, &mut Accepts, &mut |_, _, _| {});
        let mut text = preview_lines("f.txt", file.format, "k", &plan, KeyView::READ).join("\n");
        text.push_str(&report_summary(&plan, &report).unwrap());
        text.push_str(
            &serde_json::to_string(&import_json(&plan, Some(&report), false, true)).unwrap(),
        );
        text.push_str(&serde_json::to_string(&import_json(&plan, None, true, true)).unwrap());
        assert!(text.contains("Example:alice"), "{text}");
        let lower = text.to_ascii_lowercase();
        for secret in ["JBSWY3DPEHPK3PXP", "48656c6c6f21deadbeef"] {
            assert!(!lower.contains(&secret.to_ascii_lowercase()), "{text}");
        }
    }

    #[test]
    fn json_carries_plan_and_outcomes() {
        let plan = mixed_plan();
        let dry = import_json(&plan, None, true, true);
        assert_eq!(dry.destination, "oath");
        assert!(dry.dry_run);
        assert_eq!((dry.capacity, dry.on_key), (Some(32), Some(5)));
        let plans: Vec<&str> = dry.entries.iter().map(|e| e.plan).collect();
        assert_eq!(plans, ["add", "add", "exists", "replace", "skip", "skip"]);
        assert!(dry.entries.iter().all(|e| e.outcome.is_none()));
        assert_eq!(dry.entries[4].name, None);
        assert_eq!(
            dry.entries[5].reason.as_deref(),
            Some("Solo 2 doesn't take SHA-512 codes")
        );
        let run = report(
            vec![
                (0, "Example:alice", Outcome::Added),
                (1, "60/Example:bob", Outcome::Failed("no".into())),
                (3, "Example:old", Outcome::NotTried),
            ],
            Some("no"),
        );
        let real = import_json(&plan, Some(&run), false, true);
        let outcomes: Vec<Option<&str>> = real.entries.iter().map(|e| e.outcome).collect();
        assert_eq!(
            outcomes,
            [
                Some("added"),
                Some("failed"),
                None,
                Some("not-tried"),
                None,
                None
            ]
        );
        assert_eq!(real.entries[1].error.as_deref(), Some("no"));
        assert_eq!(real.stopped.as_deref(), Some("no"));
    }
}
