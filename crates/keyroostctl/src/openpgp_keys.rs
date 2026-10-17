//! `openpgp key import` (a new key set with a backup, a backup restored, an
//! RSA key file) and `openpgp key expiry`. The clap definitions live in
//! main.rs with the other `openpgp key` commands.
//!
//! Everything that can be refused without the card (the identity, the
//! expiry date, a backup name already taken, a file that doesn't read) is
//! refused before the card is opened and before a key is made.

use std::error::Error;
use std::fmt::Display;
use std::path::{Path, PathBuf};

use keyroost_openpgp::{AlgorithmInformation, KeyAlg, KeyCrt, PW3_ADMIN};
use keyroost_pgpkey::cert::{self, Expiry, Identity};
use keyroost_pgpkey::files::{self, Paths};
use keyroost_pgpkey::keys::KeyType;
use keyroost_pgpkey::read::{self, Slot};
use keyroost_resolve::Need;
use zeroize::Zeroizing;

use crate::output::{self, emit_json, json_output};
use crate::secrets::{SecretSource, Secrets, Source};
use crate::{
    hex_encode, open_openpgp_at, sanitize_terminal, secret_pair, unix_now, CliOpenpgpKeyAlg,
    OpenpgpKeyCmd, OpenpgpSlot, PGP_ADMIN_PIN, PGP_NEW_PASSPHRASE, PGP_PASSPHRASE, PGP_SIGN_PIN,
};

type Res<T> = Result<T, Box<dyn Error>>;

const DAY: i64 = 86_400;

/// What `openpgp key import --generate` will make, checked before the card.
pub(crate) struct CreatePlan {
    pub(crate) paths: Paths,
    pub(crate) identity: Identity,
    /// `None`: the card's default ([`default_key_type`]).
    pub(crate) key_type: Option<KeyType>,
    pub(crate) expiry: Expiry,
}

/// Check the `--generate` flags: a backup name, a user ID, a key type keyroost
/// can back up, and an expiry still ahead of `now`.
pub(crate) fn create_plan(
    backup: Option<&Path>,
    name: Option<&str>,
    email: Option<&str>,
    algorithm: Option<CliOpenpgpKeyAlg>,
    expires: Option<Expiry>,
    now: u32,
) -> Result<CreatePlan, String> {
    let backup =
        backup.ok_or("--generate needs --backup FILE: keyroost saves the keys it makes.")?;
    let name = name.ok_or("--generate needs --name NAME: it goes in the key's user ID.")?;
    if name.trim().is_empty() {
        return Err("--name can't be empty.".into());
    }
    let identity = Identity {
        name: name.to_string(),
        email: email.unwrap_or_default().to_string(),
    };
    identity.user_id()?;
    let key_type = algorithm.map(create_type).transpose()?;
    let expiry = expires.unwrap_or_default();
    expiry.end_time(now)?;
    Ok(CreatePlan {
        paths: files::paths_for(backup),
        identity,
        key_type,
        expiry,
    })
}

/// The key types `--generate` makes: everything but the card-only Brainpool
/// curves. `x25519` alone is half of the `ed25519` set.
fn create_type(a: CliOpenpgpKeyAlg) -> Result<KeyType, String> {
    match a.to_alg() {
        KeyAlg::X25519 => Err(
            "x25519 is the decryption key of an ed25519 set: use --algorithm \
                               ed25519 (Ed25519 signs and logs in, X25519 decrypts)."
                .into(),
        ),
        alg => KeyType::from_key_alg(alg).ok_or_else(|| {
            format!(
                "{} keys can be made on the card with `openpgp key generate`, but not with \
                 a backup.",
                alg.label()
            )
        }),
    }
}

/// The key type `--generate` uses without `--algorithm`: ed25519 (GnuPG's
/// default) when the card lists Ed25519 and X25519 for their slots or
/// publishes no list, rsa3072 otherwise.
pub(crate) fn default_key_type(fa: Option<&AlgorithmInformation>) -> KeyType {
    let Some(fa) = fa else {
        return KeyType::Cv25519;
    };
    let lists = |crt, alg| fa.key_algs(crt).contains(&alg);
    if lists(KeyCrt::Sign, KeyAlg::Ed25519)
        && lists(KeyCrt::Decrypt, KeyAlg::X25519)
        && lists(KeyCrt::Auth, KeyAlg::Ed25519)
    {
        KeyType::Cv25519
    } else {
        KeyType::Rsa3072
    }
}

/// Whether `data` is OpenPGP (an armor header, or a binary packet: the
/// first byte's top bit is always set) rather than a PEM or DER key.
pub(crate) fn is_openpgp(data: &[u8]) -> bool {
    data.trim_ascii_start().starts_with(b"-----BEGIN PGP ")
        || data.first().is_some_and(|b| b & 0x80 != 0)
}

/// pgpkey's errors, with "Cryptographic error:" left off the messages that
/// are about the input or the card rather than the math.
fn plain(e: keyroost_pgpkey::Error) -> String {
    match e {
        keyroost_pgpkey::Error::Crypto(msg) => msg,
        e => e.to_string(),
    }
}

/// `e` followed by where the backup is, for a failure after it was written.
fn with_backup(e: impl Display, backup: &Path) -> String {
    format!(
        "{}. Your backup is saved at {}.",
        e.to_string().trim_end_matches('.'),
        backup.display()
    )
}

fn slot_of(s: OpenpgpSlot) -> Slot {
    match s {
        OpenpgpSlot::Sign => Slot::Sign,
        OpenpgpSlot::Decrypt => Slot::Decrypt,
        OpenpgpSlot::Auth => Slot::Auth,
    }
}

fn slot_label(s: Slot) -> &'static str {
    match s {
        Slot::Sign => "signature",
        Slot::Decrypt => "decryption",
        Slot::Auth => "authentication",
    }
}

fn slot_word(s: Slot) -> &'static str {
    match s {
        Slot::Sign => "sign",
        Slot::Decrypt => "decrypt",
        Slot::Auth => "auth",
    }
}

/// "the signature key", "the signature and decryption keys", "all three
/// OpenPGP keys".
fn replaced(slots: &[Slot]) -> String {
    let names: Vec<&str> = slots.iter().map(|&s| slot_label(s)).collect();
    match names.as_slice() {
        [_, _, _] => "all three OpenPGP keys".to_string(),
        [one] => format!("the OpenPGP {one} key"),
        [a, b] => format!("the OpenPGP {a} and {b} keys"),
        _ => "no keys".to_string(),
    }
}

/// The last day a key works, from its creation time and expiry seconds.
fn last_day(created: u32, secs: Option<u32>) -> String {
    match secs {
        None => "never".to_string(),
        Some(s) => {
            let end = i64::from(created) + i64::from(s);
            let (y, m, d) = cert::civil_from_days((end - 1).div_euclid(DAY));
            format!("{y:04}-{m:02}-{d:02}")
        }
    }
}

fn path_text(p: &Path) -> String {
    p.display().to_string()
}

/// `openpgp key import`.
pub(crate) fn run_import(cmd: &OpenpgpKeyCmd, debug: bool) -> Res<()> {
    let OpenpgpKeyCmd::Import {
        generate,
        in_file,
        backup,
        name,
        email,
        algorithm,
        expires,
        slot,
        passphrase,
        yes,
        admin_pin,
        reader,
    } = cmd
    else {
        unreachable!("run_import is only called for openpgp key import");
    };
    let mut sec = Secrets::real();
    let psrc = Source::from_flag(passphrase.as_ref());
    let asrc = Source::from_flag(admin_pin.as_ref());
    let reader = reader.as_deref();
    if *generate {
        let now = unix_now();
        let plan = create_plan(
            backup.as_deref(),
            name.as_deref(),
            email.as_deref(),
            *algorithm,
            *expires,
            now,
        )?;
        return create(
            &mut sec, plan, now, passphrase, admin_pin, *yes, reader, debug,
        );
    }
    let path = in_file
        .as_deref()
        .ok_or("provide --generate or --in <FILE>")?;
    let data = Zeroizing::new(
        std::fs::read(path).map_err(|e| format!("cannot read key file {}: {e}", path.display()))?,
    );
    if is_openpgp(&data) {
        restore(
            &mut sec, path, &data, *slot, psrc, asrc, *yes, reader, debug,
        )
    } else {
        drop(data);
        if psrc.given() {
            return Err(format!(
                "--passphrase is for OpenPGP backups; {} is a PEM or DER key file.",
                path.display()
            )
            .into());
        }
        import_rsa_file(
            &mut sec,
            path,
            slot.unwrap_or(OpenpgpSlot::Sign),
            asrc,
            *yes,
            reader,
            debug,
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn create(
    sec: &mut Secrets,
    plan: CreatePlan,
    now: u32,
    passphrase: &Option<SecretSource>,
    admin_pin: &Option<SecretSource>,
    yes: bool,
    reader: Option<&str>,
    debug: bool,
) -> Res<()> {
    let paths = &plan.paths;
    for p in [&paths.secret, &paths.public, &paths.revocation] {
        if std::fs::symlink_metadata(p).is_ok() {
            return Err(format!(
                "{} already exists; choose another name for --backup.",
                p.display()
            )
            .into());
        }
    }
    let secrets = secret_pair(
        (&PGP_NEW_PASSPHRASE, passphrase),
        (&PGP_ADMIN_PIN, admin_pin),
    );
    secrets.check(sec)?;
    let dev = crate::target::select(Need::OpenPgp, reader, None)?;
    let key_type = match plan.key_type {
        Some(t) => t,
        None => {
            let mut session = open_openpgp_at(&crate::target::reader_of(&dev)?, debug)?;
            let t = default_key_type(session.supported_algorithms()?.as_ref());
            drop(session);
            output::status(&format!(
                "No --algorithm given: using {} ({}).",
                t.cli_name(),
                t.label()
            ));
            t
        }
    };

    let (pass, admin_secret) = secrets.read_first(sec)?;
    let pass = pass.text()?;
    output::status(&format!("Making the {} keys…", key_type.label()));
    let set = cert::create(key_type, &plan.identity, plan.expiry, now).map_err(plain)?;
    let out = cert::export(&set, pass.as_bytes(), now).map_err(plain)?;
    files::write_new(&paths.secret, &out.secret, true).map_err(plain)?;
    let saved = |e: &dyn Display| with_backup(e, &paths.secret);
    files::write_new(&paths.public, &out.public, false).map_err(|e| saved(&plain(e)))?;
    files::write_new(&paths.revocation, &out.revocation, true).map_err(|e| saved(&plain(e)))?;
    cert::verify_backup(&out.secret, pass.as_bytes(), &set).map_err(|e| {
        format!(
            "The backup just written doesn't read back ({}); the card was not changed. \
             Check {}.",
            plain(e).trim_end_matches('.'),
            paths.secret.display()
        )
    })?;
    drop(pass);

    let asked = crate::prompt::confirm_statement_then_read(
        &dev,
        yes,
        |card| format!("This replaces all three OpenPGP keys on {card}."),
        "replace all three OpenPGP keys",
    )
    .map_err(|e| saved(&e))?;
    let admin = admin_secret
        .read(sec)
        .and_then(|v| v.text())
        .map_err(|e| saved(&e))?;
    crate::prompt::reverify_if_asked(&dev, asked || sec.prompted()).map_err(|e| saved(&e))?;
    let mut session = crate::target::reader_of(&dev)
        .and_then(|r| open_openpgp_at(&r, debug))
        .map_err(|e| saved(&e))?;
    session
        .verify_pin(PW3_ADMIN, admin.as_bytes())
        .map_err(|e| saved(&e))?;
    drop(admin);
    output::status("Putting the keys on the card…");
    let fprs = keyroost_pgpkey::card::import_set(&mut session, &set).map_err(|e| saved(&e))?;
    drop(session);

    let files = [&paths.secret, &paths.public, &paths.revocation];
    let expires = last_day(set.created, set.expiry);
    if json_output() {
        return emit_json(&crate::json_out::OpenpgpKeysJson {
            key_type: Some(key_type.cli_name()),
            slots: vec!["sign", "decrypt", "auth"],
            fingerprints: fprs.iter().map(|f| hex_encode(f)).collect(),
            files: files.iter().map(|p| path_text(p)).collect(),
            expires: Some(expires),
        });
    }
    println!(
        "Made {} keys ({}) for {} and put them on the card.",
        key_type.label(),
        key_type.cli_name(),
        sanitize_terminal(&set.user_id)
    );
    println!("  Fingerprint: {}", hex_encode(&fprs[0]));
    println!("  Expires:     {expires}");
    println!("  Backup:      {}", paths.secret.display());
    println!("  Public key:  {}", paths.public.display());
    println!("  Revocation:  {}", paths.revocation.display());
    println!("Keep the backup and the revocation certificate offline.");
    Ok(())
}

/// `--in` with an OpenPGP file: a keyroost backup or a GnuPG export.
#[allow(clippy::too_many_arguments)]
fn restore(
    sec: &mut Secrets,
    path: &Path,
    data: &[u8],
    slot: Option<OpenpgpSlot>,
    psrc: Source<'_>,
    asrc: Source<'_>,
    yes: bool,
    reader: Option<&str>,
    debug: bool,
) -> Res<()> {
    sec.check(&PGP_ADMIN_PIN, asrc)?;
    // A given passphrase is read first, so `--passphrase stdin` is always
    // line 1 and `--admin-pin stdin` line 2, protected file or not.
    let given = if psrc.given() {
        Some(sec.read(&PGP_PASSPHRASE, psrc)?)
    } else {
        None
    };
    let loaded = match read::open(data, given.as_ref().map(|p| p.as_bytes())) {
        Err(keyroost_pgpkey::Error::NeedsPassphrase) if given.is_none() => {
            sec.check(&PGP_PASSPHRASE, psrc)?;
            let pass = sec.read(&PGP_PASSPHRASE, psrc)?;
            read::open(data, Some(pass.as_bytes())).map_err(plain)?
        }
        r => r.map_err(plain)?,
    };
    drop(given);
    let has = |s: Slot| loaded.keys.iter().any(|k| k.slot == Some(s));
    let slots: Vec<Slot> = match slot.map(slot_of) {
        Some(s) if has(s) => vec![s],
        Some(s) => {
            return Err(format!(
                "{} has no key for the {} slot.",
                path.display(),
                slot_label(s)
            )
            .into())
        }
        None => [Slot::Sign, Slot::Decrypt, Slot::Auth]
            .into_iter()
            .filter(|&s| has(s))
            .collect(),
    };
    if slots.is_empty() {
        return Err(format!("{} has no key that fits a card slot.", path.display()).into());
    }
    for note in &loaded.notes {
        eprintln!("note: {}", sanitize_terminal(note));
    }

    let dev = crate::target::select(Need::OpenPgp, reader, None)?;
    let what = replaced(&slots);
    let asked = crate::prompt::confirm_statement_then_read(
        &dev,
        yes,
        |card| format!("This replaces {what} on {card}."),
        &format!("replace {what}"),
    )?;
    let admin = sec.read(&PGP_ADMIN_PIN, asrc)?;
    crate::prompt::reverify_if_asked(&dev, asked || sec.prompted())?;
    let mut session = open_openpgp_at(&crate::target::reader_of(&dev)?, debug)?;
    session.verify_pin(PW3_ADMIN, admin.as_bytes())?;
    drop(admin);
    output::status("Putting the keys on the card…");
    let fprs = keyroost_pgpkey::card::import_loaded(&mut session, &loaded, &slots)?;
    drop(session);

    if json_output() {
        return emit_json(&crate::json_out::OpenpgpKeysJson {
            key_type: None,
            slots: slots.iter().map(|&s| slot_word(s)).collect(),
            fingerprints: fprs.iter().map(|f| hex_encode(f)).collect(),
            files: vec![path_text(path)],
            expires: None,
        });
    }
    println!("Restored from {}:", path.display());
    for (s, fpr) in slots.iter().zip(&fprs) {
        let kind = loaded
            .keys
            .iter()
            .find(|k| k.slot == Some(*s))
            .and_then(|k| k.key_type)
            .map_or("", |t| t.label());
        println!(
            "  {:<15} {} ({kind})",
            format!("{}:", slot_label(*s)),
            hex_encode(fpr)
        );
    }
    for uid in &loaded.user_ids {
        println!("  User ID:        {}", sanitize_terminal(uid));
    }
    Ok(())
}

/// `--in` with a PEM or DER RSA key: one slot, set to the key's size first.
fn import_rsa_file(
    sec: &mut Secrets,
    path: &Path,
    slot: OpenpgpSlot,
    asrc: Source<'_>,
    yes: bool,
    reader: Option<&str>,
    debug: bool,
) -> Res<()> {
    sec.check(&PGP_ADMIN_PIN, asrc)?;
    // Loaded and checked first, so a wrong path or key type fails before the
    // question and the admin PIN.
    output::status(&format!("Loading RSA key from {}…", path.display()));
    let k = keyroost_rsakey::load_from_file(path)?;
    let alg = match k.n.len() {
        256 => KeyAlg::Rsa2048,
        384 => KeyAlg::Rsa3072,
        512 => KeyAlg::Rsa4096,
        n => return Err(format!("unexpected RSA modulus of {n} bytes").into()),
    };
    let dev = crate::target::select(Need::OpenPgp, reader, None)?;
    let asked = crate::prompt::confirm_then_read(
        &dev,
        yes,
        &format!("overwrite the OpenPGP {} key", slot.label()),
    )?;
    let admin = sec.read(&PGP_ADMIN_PIN, asrc)?;
    crate::prompt::reverify_if_asked(&dev, asked || sec.prompted())?;
    let mut session = open_openpgp_at(&crate::target::reader_of(&dev)?, debug)?;
    session.verify_pin(PW3_ADMIN, admin.as_bytes())?;
    drop(admin);
    output::status(&format!("Importing {} key…", slot.label()));
    let parts = keyroost_transport::RsaPrivateKeyParts {
        e: &k.e,
        p: &k.p,
        q: &k.q,
        u: &k.u,
        dp: &k.dp,
        dq: &k.dq,
        n: &k.n,
    };
    session.import_any(
        slot.to_crt(),
        alg,
        &keyroost_transport::ImportKey::Rsa(parts),
    )?;
    // Register so gpg recognizes it; fingerprint is over (n, e) + time.
    let creation_time = unix_now();
    let fpr = session.register_key(slot.to_crt(), creation_time)?;
    drop(session);
    if json_output() {
        return emit_json(&crate::json_out::OpenpgpKeysJson {
            key_type: Some(match alg {
                KeyAlg::Rsa3072 => "rsa3072",
                KeyAlg::Rsa4096 => "rsa4096",
                _ => "rsa2048",
            }),
            slots: vec![slot_word(slot_of(slot))],
            fingerprints: vec![hex_encode(&fpr)],
            files: vec![path_text(path)],
            expires: None,
        });
    }
    println!("Imported {} key ({}):", slot.label(), alg.label());
    println!("  modulus:  {}", hex_encode(&k.n));
    println!("  exponent: {}", hex_encode(&k.e));
    println!("  fingerprint: {}", hex_encode(&fpr));
    println!("  created:     {} (unix)", creation_time);
    Ok(())
}

/// Write `contents` over `path` without a half-written file at any moment:
/// into `path.tmp` (which must not exist), then renamed over `path`.
fn tmp_for(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".tmp");
    PathBuf::from(name)
}

fn replace_files(writes: &[(&Path, &str, bool)]) -> Result<(), String> {
    let mut done: Vec<PathBuf> = Vec::new();
    for (path, contents, secret) in writes {
        let tmp = tmp_for(path);
        if let Err(e) = files::write_new(&tmp, contents, *secret) {
            for t in &done {
                let _ = std::fs::remove_file(t);
            }
            // write_new names an existing tmp file itself.
            return Err(plain(e));
        }
        done.push(tmp);
    }
    for ((path, ..), tmp) in writes.iter().zip(&done) {
        std::fs::rename(tmp, path).map_err(|e| {
            let _ = std::fs::remove_file(tmp);
            format!("cannot replace {}: {e}", path.display())
        })?;
    }
    Ok(())
}

/// `openpgp key expiry`.
pub(crate) fn run_expiry(cmd: &OpenpgpKeyCmd, debug: bool) -> Res<()> {
    let OpenpgpKeyCmd::Expiry {
        set,
        public,
        backup,
        passphrase,
        pin,
        reader,
    } = cmd
    else {
        unreachable!("run_expiry is only called for openpgp key expiry");
    };
    let now = unix_now();
    let end = set.end_time(now)?;
    let mut sec = Secrets::real();
    let (spec, src) = match backup {
        Some(_) => (&PGP_PASSPHRASE, Source::from_flag(passphrase.as_ref())),
        None => (&PGP_SIGN_PIN, Source::from_flag(pin.as_ref())),
    };
    sec.check(spec, src)?;
    let text = std::fs::read_to_string(public)
        .map_err(|e| format!("cannot read {}: {e}", public.display()))?;
    if text.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----") {
        return Err(format!(
            "{} is a backup, not a public key: give it with --backup and the public key \
             with --public.",
            public.display()
        )
        .into());
    }
    let cert = read::open_public(text.as_bytes()).map_err(plain)?;
    let mut written: Vec<&Path> = Vec::new();
    match backup {
        Some(b) => {
            let secret = Zeroizing::new(
                std::fs::read_to_string(b)
                    .map_err(|e| format!("cannot read {}: {e}", b.display()))?,
            );
            if read::open_public(secret.as_bytes())
                .map_err(plain)?
                .primary
                .fpr
                != cert.primary.fpr
            {
                return Err(format!(
                    "{} is not the public key of {}.",
                    public.display(),
                    b.display()
                )
                .into());
            }
            let pass = sec.read(spec, src)?;
            let (new_secret, new_public) =
                cert::change_expiry_in_backup(&secret, pass.as_bytes(), *set, now)
                    .map_err(plain)?;
            drop(pass);
            let new_secret = Zeroizing::new(new_secret);
            replace_files(&[(b, &new_secret, true), (public, &new_public, false)])?;
            written.extend([b.as_path(), public.as_path()]);
        }
        None => {
            let reader = reader.as_deref();
            let name = crate::target::reader_for(Need::OpenPgp, reader)?;
            let pin = sec.read(spec, src)?;
            crate::reverify_if_prompted(&sec, Need::OpenPgp, reader)?;
            let mut session = open_openpgp_at(&name, debug)?;
            // The signer first checks the card holds this key, then verifies
            // the PIN before each signature: a wrong PIN fails at the first
            // one, before any file is written.
            let mut signer =
                keyroost_pgpkey::card::CardSigner::new(&mut session, &cert, pin.as_bytes())
                    .map_err(plain)?;
            output::status("Signing with the card — touch the key each time it blinks…");
            let new_public = cert::change_expiry(&cert, &mut signer, cert.primary.fpr, *set, now)
                .map_err(plain)?;
            drop(signer);
            drop(session);
            replace_files(&[(public, &new_public, false)])?;
            written.push(public);
        }
    }
    let expires = match end {
        None => "never".to_string(),
        Some(end) => last_day(0, Some(end)),
    };
    if json_output() {
        return emit_json(&crate::json_out::OpenpgpKeysJson {
            key_type: None,
            slots: Vec::new(),
            fingerprints: vec![hex_encode(&cert.primary.fpr)],
            files: written.iter().map(|p| path_text(p)).collect(),
            expires: Some(expires),
        });
    }
    println!("Fingerprint: {}", hex_encode(&cert.primary.fpr));
    println!("Expires:     {expires}");
    for p in &written {
        println!("Updated:     {}", p.display());
    }
    println!("Share the updated public key again.");
    Ok(())
}
