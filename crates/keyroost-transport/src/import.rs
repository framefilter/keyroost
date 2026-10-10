//! Bulk-import adapters: the write side of [`keyroost_import::run`] over the
//! real key sessions.
//!
//! The plan ([`keyroost_import::plan`]) decides what goes where; these
//! adapters only store one code at a time and read the key's answer. What a
//! status word means is decided in small pure functions, so the rules are
//! tested without a key: a duplicate name, a full key, and an applet asking
//! for its password again are each read from the key's own answer.

use crate::{OathSession, OtpTransportError, Session, Token2OtpSession, TransportError};
use keyroost_import::entry::{HashAlg, ImportEntry, OtpKind};
use keyroost_import::plan::{Existing, OathFamily, StoredName};
use keyroost_import::run::{CodeStore, StoreError};
use keyroost_oath as oath;
use keyroost_proto::commands::{
    DisplayTimeout, HmacAlgo, OtpDigits, ProfileConfig, ProfilePublicData, TimeStep,
};
use keyroost_token2otp::OtpError;

// ---------------------------------------------------------------------------
// OATH
// ---------------------------------------------------------------------------

/// What an OATH status word means for an add or delete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OathAnswer {
    Ok,
    Exists,
    Full,
    NeedsAuth,
    Other(u16),
}

/// PUT: `9000` stored, `6983` the name exists (applets that refuse
/// duplicates), `6A84` no space, `6982` or `6985` the password is needed
/// (a password-protected Solo 2 answers `6985` once its one-command unlock
/// has lapsed).
fn oath_put_answer(sw: u16) -> OathAnswer {
    match sw {
        0x6983 => OathAnswer::Exists,
        other => oath_delete_answer(other),
    }
}

/// DELETE: as PUT, except `6983` never means "exists" here.
fn oath_delete_answer(sw: u16) -> OathAnswer {
    match sw {
        oath::SW_OK => OathAnswer::Ok,
        0x6A84 => OathAnswer::Full,
        0x6982 | 0x6985 => OathAnswer::NeedsAuth,
        other => OathAnswer::Other(other),
    }
}

/// The three OATH commands an import needs, so the adapter's rules run
/// against a scripted key in tests.
trait OathIo {
    fn put(&mut self, params: &oath::PutParams<'_>) -> Result<u16, TransportError>;
    fn delete(&mut self, name: &str) -> Result<u16, TransportError>;
    /// VALIDATE again; `Ok(false)` when no password was ever given, so
    /// nothing was sent.
    fn reauth(&mut self) -> Result<bool, TransportError>;
}

impl OathIo for OathSession {
    fn put(&mut self, params: &oath::PutParams<'_>) -> Result<u16, TransportError> {
        self.put_status(params)
    }
    fn delete(&mut self, name: &str) -> Result<u16, TransportError> {
        self.delete_status(name)
    }
    fn reauth(&mut self) -> Result<bool, TransportError> {
        self.reauthenticate()
    }
}

/// Stores planned codes in an OATH applet. The session is already selected
/// and, when the applet has a password, unlocked.
pub struct OathImportStore<'a> {
    session: &'a mut OathSession,
    family: OathFamily,
    password_hint: &'static str,
}

/// What [`OathImportStore`] tells a person to do when the applet turns out
/// to need a password nobody gave, unless the front end says otherwise.
const DEFAULT_PASSWORD_HINT: &str = "unlock it with its password first";

impl<'a> OathImportStore<'a> {
    /// `family` is the one the plan was made for. Whatever the plan let
    /// through, a name past the family's
    /// [`hard_name_limit`](OathFamily::hard_name_limit) (Solo 2: 127 bytes,
    /// past which the key stops responding) is refused here, unsent.
    pub fn new(session: &'a mut OathSession, family: OathFamily) -> Self {
        Self {
            session,
            family,
            password_hint: DEFAULT_PASSWORD_HINT,
        }
    }

    /// How this front end gives the applet password, for the report when
    /// the key asks for one that wasn't given — e.g. the CLI's
    /// "pass --password env:NAME or --password stdin".
    pub fn password_hint(mut self, hint: &'static str) -> Self {
        self.password_hint = hint;
        self
    }
}

impl CodeStore for OathImportStore<'_> {
    fn add(&mut self, name: &StoredName, entry: &ImportEntry) -> Result<(), StoreError> {
        oath_add(self.session, self.family, self.password_hint, name, entry)
    }
    fn delete(&mut self, name: &StoredName) -> Result<(), StoreError> {
        oath_delete(self.session, self.password_hint, name)
    }
}

/// LIST → what the plan needs: the names on the key, and how many entries
/// the listing couldn't show.
pub fn read_oath_existing(session: &mut OathSession) -> Result<Existing, TransportError> {
    let listing = session.list()?;
    Ok(Existing {
        names: listing
            .credentials
            .into_iter()
            .map(|c| StoredName::Oath(c.name))
            .collect(),
        hidden: listing.skipped,
    })
}

fn oath_stored_name(name: &StoredName) -> Result<&str, StoreError> {
    match name {
        StoredName::Oath(n) => Ok(n),
        _ => Err(StoreError::Failed(
            "this entry has no OATH name to store it under".to_owned(),
        )),
    }
}

/// The PUT for one entry. The plan only lets through what the applet
/// stores; anything else fails here instead of panicking.
fn put_params<'a>(
    name: &'a str,
    entry: &'a ImportEntry,
) -> Result<oath::PutParams<'a>, StoreError> {
    let algorithm = match entry.hash {
        HashAlg::Sha1 => oath::Algorithm::Sha1,
        HashAlg::Sha256 => oath::Algorithm::Sha256,
        HashAlg::Sha512 => oath::Algorithm::Sha512,
    };
    let (oath_type, imf) = match entry.kind {
        OtpKind::Totp { .. } => (oath::OathType::Totp, 0),
        OtpKind::Hotp { counter } => {
            let imf = u32::try_from(counter).map_err(|_| {
                StoreError::Failed("the counter doesn't fit this key's 32 bits".to_owned())
            })?;
            (oath::OathType::Hotp, imf)
        }
    };
    Ok(oath::PutParams {
        name,
        secret: &entry.secret,
        oath_type,
        algorithm,
        digits: entry.digits,
        require_touch: false,
        imf,
    })
}

fn oath_transport_failed(e: TransportError) -> StoreError {
    match e {
        TransportError::OathCredentialTooLong => {
            StoreError::Failed("name and seed are too long for one command".to_owned())
        }
        other => StoreError::Failed(other.to_string()),
    }
}

/// Send one command; when the applet asks for its password, VALIDATE again
/// and retry once.
fn oath_with_reauth<I: OathIo + ?Sized>(
    io: &mut I,
    hint: &str,
    send: &mut dyn FnMut(&mut I) -> Result<u16, TransportError>,
    answer: fn(u16) -> OathAnswer,
) -> Result<(), StoreError> {
    let mut a = answer(send(io).map_err(oath_transport_failed)?);
    if a == OathAnswer::NeedsAuth {
        if !io.reauth().map_err(oath_transport_failed)? {
            return Err(StoreError::Failed(format!(
                "this key's authenticator storage is password-protected; {hint}"
            )));
        }
        a = answer(send(io).map_err(oath_transport_failed)?);
    }
    match a {
        OathAnswer::Ok => Ok(()),
        OathAnswer::Exists => Err(StoreError::Exists),
        OathAnswer::Full => Err(StoreError::Full),
        OathAnswer::NeedsAuth => Err(StoreError::Failed(
            "the key asked for its OATH password again and refused it".to_owned(),
        )),
        OathAnswer::Other(sw) => Err(StoreError::Failed(format!(
            "the key refused it (status {sw:04X})"
        ))),
    }
}

fn oath_add<I: OathIo + ?Sized>(
    io: &mut I,
    family: OathFamily,
    hint: &str,
    name: &StoredName,
    entry: &ImportEntry,
) -> Result<(), StoreError> {
    let n = oath_stored_name(name)?;
    if let Some(refusal) = family.name_refusal(n) {
        return Err(StoreError::Failed(refusal));
    }
    let params = put_params(n, entry)?;
    oath_with_reauth(io, hint, &mut |io| io.put(&params), oath_put_answer)
}

fn oath_delete<I: OathIo + ?Sized>(
    io: &mut I,
    hint: &str,
    name: &StoredName,
) -> Result<(), StoreError> {
    let n = oath_stored_name(name)?;
    oath_with_reauth(io, hint, &mut |io| io.delete(n), oath_delete_answer)
}

// ---------------------------------------------------------------------------
// Token2 OTP
// ---------------------------------------------------------------------------

/// What a Token2 OTP status word means for a write or delete. `6983` is
/// the OTP PIN being blocked on these keys — never "the name exists".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Token2Answer {
    Ok,
    Full,
    PinWindow,
    PinBlocked,
    Other(u16),
}

fn token2_answer(sw: u16) -> Token2Answer {
    use keyroost_token2otp::sw;
    match sw {
        sw::OK => Token2Answer::Ok,
        sw::NOT_ENOUGH_SPACE => Token2Answer::Full,
        sw::PIN_INVALID | sw::PIN_CONDITIONS_NOT_SATISFIED => Token2Answer::PinWindow,
        sw::PIN_LOCKED => Token2Answer::PinBlocked,
        other => Token2Answer::Other(other),
    }
}

/// The Token2 OTP commands an import needs, so the PIN rules run against a
/// scripted key in tests.
trait Token2Io {
    fn write(
        &mut self,
        entry: &keyroost_token2otp::WriteEntry<'_>,
        pin: Option<&str>,
    ) -> Result<(), OtpTransportError>;
    fn delete(
        &mut self,
        app: &str,
        account: &str,
        pin: Option<&str>,
    ) -> Result<(), OtpTransportError>;
    fn verify_pin(&mut self, pin: &str) -> Result<(), OtpTransportError>;
}

impl Token2Io for Token2OtpSession {
    fn write(
        &mut self,
        entry: &keyroost_token2otp::WriteEntry<'_>,
        pin: Option<&str>,
    ) -> Result<(), OtpTransportError> {
        self.write_entry_pinned(entry, pin)
    }
    fn delete(
        &mut self,
        app: &str,
        account: &str,
        pin: Option<&str>,
    ) -> Result<(), OtpTransportError> {
        self.delete_entry_pinned(app, account, pin)
    }
    fn verify_pin(&mut self, pin: &str) -> Result<(), OtpTransportError> {
        Token2OtpSession::verify_pin(self, pin)
    }
}

/// Stores planned codes in a Token2 key's OTP storage. `pin` is the OTP
/// PIN when the key has one; it is wiped when the store drops.
pub struct Token2ImportStore<'a> {
    session: &'a mut Token2OtpSession,
    pin: Option<zeroize::Zeroizing<String>>,
    /// The PIN has worked once in this import (a write went through), so
    /// re-verifying it when the key closes its PIN window can't spend an
    /// attempt on a wrong PIN.
    pin_proven: bool,
}

impl<'a> Token2ImportStore<'a> {
    /// A typed PIN already verified on this session (by
    /// [`read_token2_existing`] with the same PIN, just before) counts as
    /// proven; a fingerprint unlock proves no PIN and doesn't count, so a PIN window the key closes before the first write is
    /// reopened with it instead of being reported as a refusal.
    pub fn new(session: &'a mut Token2OtpSession, pin: Option<zeroize::Zeroizing<String>>) -> Self {
        let pin_proven = pin.is_some() && session.typed_pin_verified();
        Self {
            session,
            pin,
            pin_proven,
        }
    }
}

impl CodeStore for Token2ImportStore<'_> {
    fn add(&mut self, name: &StoredName, entry: &ImportEntry) -> Result<(), StoreError> {
        let pin = self.pin.as_deref().map(String::as_str);
        token2_add(self.session, pin, &mut self.pin_proven, name, entry)
    }
    fn delete(&mut self, name: &StoredName) -> Result<(), StoreError> {
        let pin = self.pin.as_deref().map(String::as_str);
        token2_delete(self.session, pin, &mut self.pin_proven, name)
    }
}

/// ENUM_CODES (opening the PIN window first when the key has a PIN) → the
/// (app, account) names on the key.
pub fn read_token2_existing(
    session: &mut Token2OtpSession,
    pin: Option<&str>,
) -> Result<Existing, OtpTransportError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let entries = session.enumerate_pinned(now, pin)?;
    Ok(Existing {
        names: entries
            .into_iter()
            .map(|e| StoredName::Token2 {
                app: e.app_name,
                account: e.account_name,
            })
            .collect(),
        hidden: 0,
    })
}

fn token2_stored_name(name: &StoredName) -> Result<(&str, &str), StoreError> {
    match name {
        StoredName::Token2 { app, account } => Ok((app, account)),
        _ => Err(StoreError::Failed(
            "this entry has no Token2 name to store it under".to_owned(),
        )),
    }
}

/// The `WRITE_SEED` fields for one entry: the TOTP period as the time step
/// (30 for HOTP, as `otp add` does), no button press. What the plan keeps
/// out fails here instead of panicking.
fn token2_write_entry<'a>(
    app: &'a str,
    account: &'a str,
    entry: &'a ImportEntry,
) -> Result<keyroost_token2otp::WriteEntry<'a>, StoreError> {
    use keyroost_token2otp::{Algorithm, OtpType};
    let algorithm = match entry.hash {
        HashAlg::Sha1 => Algorithm::Sha1,
        HashAlg::Sha256 => Algorithm::Sha256,
        HashAlg::Sha512 => {
            return Err(StoreError::Failed(
                "this Token2 key doesn't take SHA-512 codes".to_owned(),
            ))
        }
    };
    let (otp_type, timestep) = match entry.kind {
        OtpKind::Totp { period } => {
            let step = u16::try_from(period).map_err(|_| {
                StoreError::Failed(format!("this Token2 key doesn't take a {period} s period"))
            })?;
            (OtpType::Totp, step)
        }
        OtpKind::Hotp { .. } => (OtpType::Hotp, 30),
    };
    Ok(keyroost_token2otp::WriteEntry {
        otp_type,
        algorithm,
        timestep,
        code_length: entry.digits,
        button_required: false,
        app_name: app,
        account_name: account,
        seed: &entry.secret,
    })
}

/// A transport result as a Token2 answer. `PinRequired` (a PIN is set and
/// none was given) reads as the PIN window being closed.
fn token2_classify(r: Result<(), OtpTransportError>) -> Result<Token2Answer, StoreError> {
    match r {
        Ok(()) => Ok(Token2Answer::Ok),
        Err(OtpTransportError::Applet(e)) => Ok(token2_answer(e.status_word())),
        Err(OtpTransportError::PinRequired) => Ok(Token2Answer::PinWindow),
        Err(other) => Err(StoreError::Failed(other.to_string())),
    }
}

const TOKEN2_PIN_BLOCKED: &str = "the key's OTP PIN is blocked";

/// The key closed its PIN window before this import's PIN was proven on the
/// session: said as it is (the PIN isn't known to be wrong), with no attempt
/// spent.
const TOKEN2_PIN_WINDOW_CLOSED: &str = "the key closed its OTP PIN window; nothing more was \
     sent, so no PIN attempt was used. Run the import again.";

/// Send one command; when the PIN window is closed and a PIN is held,
/// verify it and retry once.
fn token2_with_pin<I: Token2Io + ?Sized>(
    io: &mut I,
    pin: Option<&str>,
    proven: &mut bool,
    send: &mut dyn FnMut(&mut I) -> Result<(), OtpTransportError>,
) -> Result<(), StoreError> {
    let first = send(io);
    // A wrong PIN from the write's own verify: said plainly (with the tries
    // left, when the key reports them) and never sent again.
    if !*proven {
        if let Err(OtpTransportError::Applet(
            e @ (OtpError::PinInvalid | OtpError::PinInvalidRetries(_)),
        )) = &first
        {
            if pin.is_some() {
                return Err(StoreError::Failed(e.to_string()));
            }
        }
    }
    if let Err(OtpTransportError::Applet(e @ OtpError::PinInvalidRetries(_))) = &first {
        return Err(StoreError::Failed(e.to_string()));
    }
    let mut a = token2_classify(first)?;
    if a == Token2Answer::PinWindow {
        let Some(p) = pin else {
            return Err(StoreError::Failed(
                "the key asks for its OTP PIN".to_owned(),
            ));
        };
        // Re-verify only a PIN that already worked in this import, so no
        // attempt is ever spent on a wrong one.
        if !*proven {
            return Err(StoreError::Failed(TOKEN2_PIN_WINDOW_CLOSED.to_owned()));
        }
        io.verify_pin(p).map_err(|e| match e {
            OtpTransportError::Applet(ref a)
                if token2_answer(a.status_word()) == Token2Answer::PinBlocked =>
            {
                StoreError::Failed(TOKEN2_PIN_BLOCKED.to_owned())
            }
            other => StoreError::Failed(other.to_string()),
        })?;
        a = token2_classify(send(io))?;
    }
    if a == Token2Answer::Ok && pin.is_some() {
        *proven = true;
    }
    match a {
        Token2Answer::Ok => Ok(()),
        Token2Answer::Full => Err(StoreError::Full),
        Token2Answer::PinWindow => Err(StoreError::Failed(
            "the key asked for its OTP PIN again and refused it".to_owned(),
        )),
        Token2Answer::PinBlocked => Err(StoreError::Failed(TOKEN2_PIN_BLOCKED.to_owned())),
        Token2Answer::Other(sw) => Err(StoreError::Failed(format!(
            "the key refused it (status {sw:04X})"
        ))),
    }
}

fn token2_add<I: Token2Io + ?Sized>(
    io: &mut I,
    pin: Option<&str>,
    proven: &mut bool,
    name: &StoredName,
    entry: &ImportEntry,
) -> Result<(), StoreError> {
    let (app, account) = token2_stored_name(name)?;
    let w = token2_write_entry(app, account, entry)?;
    token2_with_pin(io, pin, proven, &mut |io| io.write(&w, pin))
}

fn token2_delete<I: Token2Io + ?Sized>(
    io: &mut I,
    pin: Option<&str>,
    proven: &mut bool,
    name: &StoredName,
) -> Result<(), StoreError> {
    let (app, account) = token2_stored_name(name)?;
    token2_with_pin(io, pin, proven, &mut |io| io.delete(app, account, pin))
}

// ---------------------------------------------------------------------------
// Molto2
// ---------------------------------------------------------------------------

/// Stores planned codes in Molto2 slots: seed, title, then config. The
/// session is already authenticated. Each config carries the time read just
/// before it is sent, as the single-slot writes do, so a long run doesn't
/// leave the token's clock behind.
pub struct MoltoImportStore<'a> {
    session: &'a mut Session,
    display_timeout: DisplayTimeout,
    now: fn() -> u32,
}

impl<'a> MoltoImportStore<'a> {
    pub fn new(session: &'a mut Session, display_timeout: DisplayTimeout) -> Self {
        Self::with_clock(session, display_timeout, unix_now_u32)
    }

    /// As [`new`](Self::new), reading the time from `now` instead of the
    /// wall clock.
    pub fn with_clock(
        session: &'a mut Session,
        display_timeout: DisplayTimeout,
        now: fn() -> u32,
    ) -> Self {
        Self {
            session,
            display_timeout,
            now,
        }
    }
}

/// Wall-clock Unix seconds (0 before 1970; saturating past 2106).
fn unix_now_u32() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u32::try_from(d.as_secs()).unwrap_or(u32::MAX))
        .unwrap_or(0)
}

/// The three Molto2 slot writes, so the adapter runs against a scripted
/// token in tests.
trait MoltoIo {
    fn set_seed(&mut self, slot: u8, seed: &[u8]) -> Result<(), TransportError>;
    fn set_title(&mut self, slot: u8, title: &str) -> Result<(), TransportError>;
    fn set_config(&mut self, slot: u8, cfg: &ProfileConfig) -> Result<(), TransportError>;
}

impl MoltoIo for Session {
    fn set_seed(&mut self, slot: u8, seed: &[u8]) -> Result<(), TransportError> {
        Session::set_seed(self, slot, seed)
    }
    fn set_title(&mut self, slot: u8, title: &str) -> Result<(), TransportError> {
        Session::set_title(self, slot, title)
    }
    fn set_config(&mut self, slot: u8, cfg: &ProfileConfig) -> Result<(), TransportError> {
        Session::set_config(self, slot, cfg)
    }
}

/// One slot write, checked so the command builders' limits (seed 1..=63
/// bytes, title 1..=12 bytes) can't panic: the plan keeps such entries
/// out, and anything that slips through fails instead.
struct MoltoWrite<'a> {
    slot: u8,
    title: &'a str,
    config: ProfileConfig,
}

fn molto_write<'a>(
    name: &'a StoredName,
    entry: &ImportEntry,
    display_timeout: DisplayTimeout,
    utc_time: u32,
) -> Result<MoltoWrite<'a>, StoreError> {
    let unsupported = |what: String| StoreError::Failed(format!("Molto2 doesn't take {what}"));
    let StoredName::Molto2 { slot, title } = name else {
        return Err(StoreError::Failed(
            "this entry has no Molto2 slot to store it in".to_owned(),
        ));
    };
    if title.is_empty() || title.len() > 12 {
        return Err(StoreError::Failed(
            "the title must be 1 to 12 bytes".to_owned(),
        ));
    }
    if entry.secret.is_empty() || entry.secret.len() > 63 {
        return Err(unsupported(format!("a {}-byte seed", entry.secret.len())));
    }
    let algorithm = match entry.hash {
        HashAlg::Sha1 => HmacAlgo::Sha1,
        HashAlg::Sha256 => HmacAlgo::Sha256,
        HashAlg::Sha512 => return Err(unsupported("SHA-512 codes".to_owned())),
    };
    let digits = match entry.digits {
        4 => OtpDigits::Four,
        6 => OtpDigits::Six,
        8 => OtpDigits::Eight,
        10 => OtpDigits::Ten,
        d => return Err(unsupported(format!("{d}-digit codes"))),
    };
    let time_step = match entry.kind {
        OtpKind::Totp { period: 30 } => TimeStep::Seconds30,
        OtpKind::Totp { period: 60 } => TimeStep::Seconds60,
        OtpKind::Totp { period } => return Err(unsupported(format!("a {period} s period"))),
        OtpKind::Hotp { .. } => return Err(unsupported("counter-based (HOTP) codes".to_owned())),
    };
    Ok(MoltoWrite {
        slot: *slot,
        title,
        config: ProfileConfig {
            display_timeout,
            algorithm,
            digits,
            time_step,
            utc_time,
        },
    })
}

/// Write one slot: seed, title, then config with the time read just before
/// the config goes out.
fn molto_add<I: MoltoIo + ?Sized>(
    io: &mut I,
    now: fn() -> u32,
    display_timeout: DisplayTimeout,
    name: &StoredName,
    entry: &ImportEntry,
) -> Result<(), StoreError> {
    let mut w = molto_write(name, entry, display_timeout, 0)?;
    let failed = |e: TransportError| StoreError::Failed(e.to_string());
    io.set_seed(w.slot, &entry.secret).map_err(failed)?;
    io.set_title(w.slot, w.title).map_err(failed)?;
    w.config.utc_time = now();
    io.set_config(w.slot, &w.config).map_err(failed)
}

/// The Molto2's used slots: a slot with a seed or a title, the rule the
/// Molto2 slot list, the GUI and `molto import` all read slot use by.
pub fn molto_existing(meta: &[ProfilePublicData]) -> Existing {
    Existing {
        names: meta
            .iter()
            .enumerate()
            .filter_map(|(slot, m)| {
                let title = m.title.as_deref().unwrap_or("");
                (m.seed_present || !title.is_empty()).then(|| StoredName::Molto2 {
                    slot: slot as u8,
                    title: title.to_owned(),
                })
            })
            .collect(),
        hidden: 0,
    }
}

/// Read every slot's public block (no customer key needed) and say which
/// slots are used ([`molto_existing`]). Stops at the first failed read.
pub fn read_molto_existing(session: &mut Session) -> Result<Existing, TransportError> {
    molto_existing_by(|slot| session.read_public_data(slot))
}

fn molto_existing_by(
    mut read: impl FnMut(u8) -> Result<ProfilePublicData, TransportError>,
) -> Result<Existing, TransportError> {
    let meta = (0..=99u8).map(&mut read).collect::<Result<Vec<_>, _>>()?;
    Ok(molto_existing(&meta))
}

impl CodeStore for MoltoImportStore<'_> {
    fn add(&mut self, name: &StoredName, entry: &ImportEntry) -> Result<(), StoreError> {
        molto_add(self.session, self.now, self.display_timeout, name, entry)
    }
    fn delete(&mut self, _name: &StoredName) -> Result<(), StoreError> {
        Err(StoreError::Failed("not supported".to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyroost_import::entry::{Format, ImportFile, ImportItem};
    use keyroost_import::plan::{plan, OathFamily, Store, Target};
    use keyroost_import::run::{run, Outcome};
    use std::collections::VecDeque;
    use zeroize::Zeroizing;

    #[test]
    fn oath_put_6983_is_exists() {
        assert_eq!(oath_put_answer(0x6983), OathAnswer::Exists);
        assert_eq!(oath_put_answer(0x9000), OathAnswer::Ok);
    }

    #[test]
    fn oath_put_6a84_is_full() {
        assert_eq!(oath_put_answer(0x6A84), OathAnswer::Full);
    }

    #[test]
    fn oath_put_6982_needs_auth() {
        assert_eq!(oath_put_answer(0x6982), OathAnswer::NeedsAuth);
        assert_eq!(oath_put_answer(0x6A80), OathAnswer::Other(0x6A80));
    }

    #[test]
    fn oath_6985_needs_auth() {
        // A password-protected Solo 2 (fw 2.3.196) answers a PUT sent after its
        // one-command unlock lapsed with 6985, not 6982 (seen on hardware).
        assert_eq!(oath_put_answer(0x6985), OathAnswer::NeedsAuth);
        assert_eq!(oath_delete_answer(0x6985), OathAnswer::NeedsAuth);
    }

    #[test]
    fn oath_delete_6983_is_not_exists() {
        assert_eq!(oath_delete_answer(0x6983), OathAnswer::Other(0x6983));
        assert_eq!(oath_delete_answer(0x9000), OathAnswer::Ok);
        assert_eq!(oath_delete_answer(0x6982), OathAnswer::NeedsAuth);
        assert_eq!(oath_delete_answer(0x6A84), OathAnswer::Full);
    }

    /// A scripted OATH applet: answers popped per call (default `9000`),
    /// every call recorded.
    #[derive(Default)]
    struct ScriptedOath {
        put: VecDeque<u16>,
        delete: VecDeque<u16>,
        calls: Vec<String>,
        /// A password was given (unlock kept an access key).
        has_key: bool,
    }

    impl OathIo for ScriptedOath {
        fn put(&mut self, p: &oath::PutParams<'_>) -> Result<u16, TransportError> {
            self.calls.push(format!("put {}", p.name));
            Ok(self.put.pop_front().unwrap_or(0x9000))
        }
        fn delete(&mut self, name: &str) -> Result<u16, TransportError> {
            self.calls.push(format!("delete {}", name));
            Ok(self.delete.pop_front().unwrap_or(0x9000))
        }
        fn reauth(&mut self) -> Result<bool, TransportError> {
            self.calls.push("reauth".to_owned());
            Ok(self.has_key)
        }
    }

    /// `run` over the scripted applet through the real adapter rules.
    struct ScriptedStore(ScriptedOath);

    impl CodeStore for ScriptedStore {
        fn add(&mut self, name: &StoredName, entry: &ImportEntry) -> Result<(), StoreError> {
            oath_add(
                &mut self.0,
                OathFamily::Solo2,
                DEFAULT_PASSWORD_HINT,
                name,
                entry,
            )
        }
        fn delete(&mut self, name: &StoredName) -> Result<(), StoreError> {
            oath_delete(&mut self.0, DEFAULT_PASSWORD_HINT, name)
        }
    }

    fn entry(kind: OtpKind) -> ImportEntry {
        ImportEntry {
            issuer: Some("A".to_owned()),
            account: Some("a".to_owned()),
            secret: Zeroizing::new(vec![7; 20]),
            hash: HashAlg::Sha256,
            digits: 8,
            kind,
        }
    }

    fn file(n: usize) -> ImportFile {
        ImportFile {
            format: Format::OtpauthList,
            items: (0..n)
                .map(|index| {
                    let mut e = entry(OtpKind::Totp { period: 30 });
                    e.issuer = Some(format!("I{index}"));
                    ImportItem {
                        index,
                        label: format!("I{index}:a"),
                        entry: Ok(e),
                    }
                })
                .collect(),
            batch: None,
        }
    }

    fn run_scripted(
        f: &ImportFile,
        replace: bool,
        io: ScriptedOath,
    ) -> (Vec<Outcome>, ScriptedOath) {
        let p = plan(
            f,
            &Target {
                store: Store::Oath(OathFamily::Solo2),
                first_slot: 0,
                existing: Existing::default(),
                replace,
            },
        );
        let mut s = ScriptedStore(io);
        let r = run(f, &p, &mut s, &mut |_, _, _| {});
        (r.rows.into_iter().map(|(_, _, o)| o).collect(), s.0)
    }

    #[test]
    fn oath_delete_never_sent_on_plain_add() {
        let f = file(2);
        let io = ScriptedOath {
            put: [0x6983, 0x9000].into(),
            ..Default::default()
        };
        let (out, io) = run_scripted(&f, false, io);
        assert_eq!(io.calls, vec!["put I0:a", "put I1:a"]);
        assert_eq!(out, vec![Outcome::AlreadyThere, Outcome::Added]);

        // With replace, the delete follows the key's 6983 only.
        let io = ScriptedOath {
            put: [0x6983].into(),
            ..Default::default()
        };
        let (out, io) = run_scripted(&file(1), true, io);
        assert_eq!(io.calls, vec!["put I0:a", "delete I0:a", "put I0:a"]);
        assert_eq!(out, vec![Outcome::Replaced]);
    }

    #[test]
    fn needs_auth_retries_once_after_reauthenticate() {
        let e = entry(OtpKind::Totp { period: 30 });
        let name = StoredName::Oath("A:a".to_owned());

        let mut io = ScriptedOath {
            put: [0x6982, 0x9000].into(),
            has_key: true,
            ..Default::default()
        };
        assert_eq!(
            oath_add(&mut io, OathFamily::Other, DEFAULT_PASSWORD_HINT, &name, &e),
            Ok(())
        );
        assert_eq!(io.calls, vec!["put A:a", "reauth", "put A:a"]);

        let mut io = ScriptedOath {
            put: [0x6985, 0x9000].into(),
            has_key: true,
            ..Default::default()
        };
        assert_eq!(
            oath_add(&mut io, OathFamily::Other, DEFAULT_PASSWORD_HINT, &name, &e),
            Ok(())
        );
        assert_eq!(io.calls, vec!["put A:a", "reauth", "put A:a"]);

        let mut io = ScriptedOath {
            put: [0x6982, 0x6982].into(),
            has_key: true,
            ..Default::default()
        };
        assert_eq!(
            oath_add(&mut io, OathFamily::Other, DEFAULT_PASSWORD_HINT, &name, &e),
            Err(StoreError::Failed(
                "the key asked for its OATH password again and refused it".to_owned()
            ))
        );
        assert_eq!(io.calls, vec!["put A:a", "reauth", "put A:a"]);

        let mut io = ScriptedOath {
            delete: [0x6982].into(),
            has_key: true,
            ..Default::default()
        };
        assert_eq!(oath_delete(&mut io, DEFAULT_PASSWORD_HINT, &name), Ok(()));
        assert_eq!(io.calls, vec!["delete A:a", "reauth", "delete A:a"]);
    }

    #[test]
    fn needs_auth_without_a_password_says_how_to_give_one() {
        let e = entry(OtpKind::Totp { period: 30 });
        let name = StoredName::Oath("A:a".to_owned());
        let mut io = ScriptedOath {
            put: [0x6982].into(),
            ..Default::default()
        };
        assert_eq!(
            oath_add(
                &mut io,
                OathFamily::Other,
                "pass --password env:NAME",
                &name,
                &e
            ),
            Err(StoreError::Failed(
                "this key's authenticator storage is password-protected; \
                 pass --password env:NAME"
                    .to_owned()
            ))
        );
        // Nothing to answer with, so nothing is resent.
        assert_eq!(io.calls, vec!["put A:a", "reauth"]);
    }

    #[test]
    fn solo2_name_past_127_bytes_is_never_sent() {
        // Second line of defense behind the plan: whatever a caller planned
        // with, a Solo 2 never gets a name that makes it stop responding.
        let e = entry(OtpKind::Totp { period: 30 });
        let mut io = ScriptedOath::default();
        let long = StoredName::Oath("n".repeat(128));
        match oath_add(&mut io, OathFamily::Solo2, DEFAULT_PASSWORD_HINT, &long, &e) {
            Err(StoreError::Failed(m)) => assert!(m.contains("127 bytes"), "{m}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert!(io.calls.is_empty());
        let ok = StoredName::Oath("n".repeat(127));
        assert_eq!(
            oath_add(&mut io, OathFamily::Solo2, DEFAULT_PASSWORD_HINT, &ok, &e),
            Ok(())
        );
        // Other families keep their own limits (the plan's), not this one.
        assert_eq!(
            oath_add(
                &mut io,
                OathFamily::Nitrokey3,
                DEFAULT_PASSWORD_HINT,
                &long,
                &e
            ),
            Ok(())
        );
    }

    #[test]
    fn oath_other_status_and_full_are_reported() {
        let e = entry(OtpKind::Totp { period: 30 });
        let name = StoredName::Oath("A:a".to_owned());
        let mut io = ScriptedOath {
            put: [0x6A80, 0x6A84].into(),
            ..Default::default()
        };
        assert_eq!(
            oath_add(&mut io, OathFamily::Other, DEFAULT_PASSWORD_HINT, &name, &e),
            Err(StoreError::Failed(
                "the key refused it (status 6A80)".to_owned()
            ))
        );
        assert_eq!(
            oath_add(&mut io, OathFamily::Other, DEFAULT_PASSWORD_HINT, &name, &e),
            Err(StoreError::Full)
        );
    }

    #[test]
    fn oath_put_params_from_entry() {
        let e = entry(OtpKind::Hotp { counter: 5 });
        let p = put_params("A:a", &e).unwrap();
        assert_eq!(p.oath_type, oath::OathType::Hotp);
        assert_eq!(p.algorithm, oath::Algorithm::Sha256);
        assert_eq!(p.digits, 8);
        assert_eq!(p.imf, 5);
        assert!(!p.require_touch);

        let e = entry(OtpKind::Totp { period: 60 });
        let p = put_params("60/A:a", &e).unwrap();
        assert_eq!((p.oath_type, p.imf), (oath::OathType::Totp, 0));

        // Unreachable after `plan`; refused, never truncated.
        let e = entry(OtpKind::Hotp {
            counter: u64::from(u32::MAX) + 1,
        });
        assert!(put_params("A:a", &e).is_err());
    }

    #[test]
    fn apdu_fit_matches_builder() {
        use keyroost_import::plan::oath_put_fits;
        for name_len in 200..=250 {
            let name = "n".repeat(name_len);
            for secret_len in 1..=64 {
                let secret = vec![1u8; secret_len];
                for imf in [false, true] {
                    let p = oath::PutParams {
                        name: &name,
                        secret: &secret,
                        oath_type: if imf {
                            oath::OathType::Hotp
                        } else {
                            oath::OathType::Totp
                        },
                        algorithm: oath::Algorithm::Sha1,
                        digits: 6,
                        require_touch: false,
                        imf: u32::from(imf),
                    };
                    assert_eq!(
                        oath_put_fits(name_len, secret_len, imf),
                        oath::put(&p).is_ok(),
                        "name {name_len}, secret {secret_len}, imf {imf}"
                    );
                }
            }
        }
    }

    // ---- Token2 ----

    /// A scripted Token2 key: write/delete answers popped per call (default
    /// success), every call recorded.
    #[derive(Default)]
    struct ScriptedToken2 {
        write: VecDeque<Result<(), OtpTransportError>>,
        verify: VecDeque<Result<(), OtpTransportError>>,
        calls: Vec<String>,
    }

    impl Token2Io for ScriptedToken2 {
        fn write(
            &mut self,
            e: &keyroost_token2otp::WriteEntry<'_>,
            _pin: Option<&str>,
        ) -> Result<(), OtpTransportError> {
            self.calls.push(format!("write {}", e.account_name));
            self.write.pop_front().unwrap_or(Ok(()))
        }
        fn delete(
            &mut self,
            _app: &str,
            account: &str,
            _pin: Option<&str>,
        ) -> Result<(), OtpTransportError> {
            self.calls.push(format!("delete {account}"));
            self.write.pop_front().unwrap_or(Ok(()))
        }
        fn verify_pin(&mut self, _pin: &str) -> Result<(), OtpTransportError> {
            self.calls.push("verify".to_owned());
            self.verify.pop_front().unwrap_or(Ok(()))
        }
    }

    fn t2name() -> StoredName {
        StoredName::Token2 {
            app: "A".to_owned(),
            account: "a".to_owned(),
        }
    }

    fn applet(e: OtpError) -> Result<(), OtpTransportError> {
        Err(OtpTransportError::Applet(e))
    }

    #[test]
    fn token2_6983_is_pin_blocked_not_exists() {
        let mut proven = true;
        assert_eq!(token2_answer(0x6983), Token2Answer::PinBlocked);
        assert_eq!(token2_answer(0x9000), Token2Answer::Ok);
        assert_eq!(token2_answer(0x6982), Token2Answer::PinWindow);
        assert_eq!(token2_answer(0x6985), Token2Answer::PinWindow);
        assert_eq!(token2_answer(0x6A80), Token2Answer::Other(0x6A80));
        let mut io = ScriptedToken2 {
            write: [applet(OtpError::PinLocked)].into(),
            ..Default::default()
        };
        let e = entry(OtpKind::Totp { period: 30 });
        assert_eq!(
            token2_add(&mut io, Some("1234"), &mut proven, &t2name(), &e),
            Err(StoreError::Failed(
                "the key's OTP PIN is blocked".to_owned()
            ))
        );
        assert_eq!(io.calls, vec!["write a"]);
    }

    #[test]
    fn token2_6a84_is_full() {
        assert_eq!(token2_answer(0x6A84), Token2Answer::Full);
        let mut io = ScriptedToken2 {
            write: [applet(OtpError::NotEnoughSpace)].into(),
            ..Default::default()
        };
        let e = entry(OtpKind::Totp { period: 30 });
        assert_eq!(
            token2_add(&mut io, None, &mut false, &t2name(), &e),
            Err(StoreError::Full)
        );
    }

    #[test]
    fn token2_pin_window_reverifies_once() {
        let e = entry(OtpKind::Totp { period: 30 });
        // The PIN has already worked in this import.
        let mut proven = true;
        let mut io = ScriptedToken2 {
            write: [applet(OtpError::PinConditionsNotSatisfied), Ok(())].into(),
            ..Default::default()
        };
        assert_eq!(
            token2_add(&mut io, Some("1234"), &mut proven, &t2name(), &e),
            Ok(())
        );
        assert_eq!(io.calls, vec!["write a", "verify", "write a"]);

        // Closed again after the verify: reported, not retried forever.
        let mut io = ScriptedToken2 {
            write: [applet(OtpError::PinInvalid), applet(OtpError::PinInvalid)].into(),
            ..Default::default()
        };
        assert_eq!(
            token2_add(&mut io, Some("1234"), &mut proven, &t2name(), &e),
            Err(StoreError::Failed(
                "the key asked for its OTP PIN again and refused it".to_owned()
            ))
        );
        assert_eq!(io.calls, vec!["write a", "verify", "write a"]);

        // No PIN held: never verified, the key's request is reported.
        for first in [
            applet(OtpError::PinConditionsNotSatisfied),
            Err(OtpTransportError::PinRequired),
        ] {
            let mut io = ScriptedToken2 {
                write: [first].into(),
                ..Default::default()
            };
            assert_eq!(
                token2_add(&mut io, None, &mut false, &t2name(), &e),
                Err(StoreError::Failed(
                    "the key asks for its OTP PIN".to_owned()
                ))
            );
            assert_eq!(io.calls, vec!["write a"]);
        }

        // Delete takes the same path.
        let mut io = ScriptedToken2 {
            write: [applet(OtpError::PinConditionsNotSatisfied)].into(),
            ..Default::default()
        };
        assert_eq!(
            token2_delete(&mut io, Some("1234"), &mut proven, &t2name()),
            Ok(())
        );
        assert_eq!(io.calls, vec!["delete a", "verify", "delete a"]);

        // A blocked PIN at verify says so.
        let mut io = ScriptedToken2 {
            write: [applet(OtpError::PinConditionsNotSatisfied)].into(),
            verify: [applet(OtpError::PinLocked)].into(),
            ..Default::default()
        };
        assert_eq!(
            token2_add(&mut io, Some("1234"), &mut proven, &t2name(), &e),
            Err(StoreError::Failed(
                "the key's OTP PIN is blocked".to_owned()
            ))
        );
    }

    #[test]
    fn token2_fingerprint_unlock_never_proves_the_typed_pin() {
        let e = entry(OtpKind::Totp { period: 30 });
        let pin = || Some(Zeroizing::new("0000".to_owned()));
        // Window opened by a fingerprint: the typed PIN was never checked.
        let mut fp = Token2OtpSession::unlocked_for_test(true, false);
        let mut store = Token2ImportStore::new(&mut fp, pin());
        assert!(!store.pin_proven);
        // The key closes its window: the PIN isn't sent, the report is plain.
        let mut io = ScriptedToken2 {
            write: [applet(OtpError::PinConditionsNotSatisfied)].into(),
            ..Default::default()
        };
        assert_eq!(
            token2_add(&mut io, Some("0000"), &mut store.pin_proven, &t2name(), &e),
            Err(StoreError::Failed(TOKEN2_PIN_WINDOW_CLOSED.to_owned()))
        );
        assert_eq!(io.calls, vec!["write a"]);
        // A typed PIN verified on the session is proven; no PIN, never.
        let mut typed = Token2OtpSession::unlocked_for_test(true, true);
        assert!(Token2ImportStore::new(&mut typed, pin()).pin_proven);
        let mut typed = Token2OtpSession::unlocked_for_test(true, true);
        assert!(!Token2ImportStore::new(&mut typed, None).pin_proven);
    }

    #[test]
    fn token2_wrong_pin_is_sent_once_and_said_plainly() {
        let e = entry(OtpKind::Totp { period: 30 });
        // The write's own verify refused the PIN: never verified again.
        for (refusal, msg) in [
            (
                OtpError::PinInvalid,
                "wrong OTP PIN (or authentication tag mismatch)",
            ),
            (
                OtpError::PinInvalidRetries(2),
                "wrong OTP PIN \u{2014} 2 attempts remaining before lockout",
            ),
        ] {
            let mut proven = false;
            let mut io = ScriptedToken2 {
                write: [applet(refusal)].into(),
                ..Default::default()
            };
            assert_eq!(
                token2_add(&mut io, Some("0000"), &mut proven, &t2name(), &e),
                Err(StoreError::Failed(msg.to_owned()))
            );
            assert_eq!(io.calls, vec!["write a"]);
            assert!(!proven);
        }
        // A closed window before the PIN was proven on this session:
        // reported plainly (it isn't known to be wrong), not retried.
        let mut proven = false;
        let mut io = ScriptedToken2 {
            write: [applet(OtpError::PinConditionsNotSatisfied)].into(),
            ..Default::default()
        };
        assert_eq!(
            token2_add(&mut io, Some("0000"), &mut proven, &t2name(), &e),
            Err(StoreError::Failed(TOKEN2_PIN_WINDOW_CLOSED.to_owned()))
        );
        assert_eq!(
            TOKEN2_PIN_WINDOW_CLOSED,
            "the key closed its OTP PIN window; nothing more was sent, so no PIN \
             attempt was used. Run the import again."
        );
        assert_eq!(io.calls, vec!["write a"]);
        // A write that goes through proves the PIN for later re-verifies.
        let mut io = ScriptedToken2 {
            write: [Ok(()), applet(OtpError::PinConditionsNotSatisfied)].into(),
            ..Default::default()
        };
        assert_eq!(
            token2_add(&mut io, Some("1234"), &mut proven, &t2name(), &e),
            Ok(())
        );
        assert!(proven);
        assert_eq!(
            token2_add(&mut io, Some("1234"), &mut proven, &t2name(), &e),
            Ok(())
        );
        assert_eq!(io.calls, vec!["write a", "write a", "verify", "write a"]);
    }

    #[test]
    fn token2_write_entry_fields() {
        let e = ImportEntry {
            secret: Zeroizing::new(vec![0xAB; 3]),
            hash: HashAlg::Sha256,
            digits: 8,
            ..entry(OtpKind::Totp { period: 45 })
        };
        let w = token2_write_entry("Ap", "acc", &e).unwrap();
        let bytes = keyroost_token2otp::serialize_write_entry(&w).unwrap();
        // type TOTP, SHA-256, step 45, 8 digits, no button, "Ap", "acc", seed.
        let want: Vec<u8> = [
            &[
                keyroost_token2otp::OtpType::Totp.to_byte(),
                keyroost_token2otp::Algorithm::Sha256.to_byte(),
                0x00,
                45,
                8,
                0,
                2,
            ][..],
            b"Ap",
            &[3],
            b"acc",
            &[3, 0xAB, 0xAB, 0xAB],
        ]
        .concat();
        assert_eq!(bytes.as_bytes(), &want[..]);

        // HOTP is stored with a 30 s step, as `otp add` does.
        let e = ImportEntry {
            hash: HashAlg::Sha1,
            digits: 6,
            ..entry(OtpKind::Hotp { counter: 0 })
        };
        let w = token2_write_entry("", "acc", &e).unwrap();
        assert_eq!(w.otp_type, keyroost_token2otp::OtpType::Hotp);
        assert_eq!(w.algorithm, keyroost_token2otp::Algorithm::Sha1);
        assert_eq!(
            (w.timestep, w.code_length, w.button_required),
            (30, 6, false)
        );

        // Unreachable after `plan`; refused, never truncated.
        let e = ImportEntry {
            hash: HashAlg::Sha512,
            ..entry(OtpKind::Totp { period: 30 })
        };
        assert!(token2_write_entry("", "acc", &e).is_err());
        assert!(token2_write_entry("", "acc", &entry(OtpKind::Totp { period: 70_000 })).is_err());
    }

    // ---- Molto2 ----

    /// A scripted Molto2 token recording each config's time.
    #[derive(Default)]
    struct ScriptedMolto {
        calls: Vec<String>,
        times: Vec<u32>,
    }

    impl MoltoIo for ScriptedMolto {
        fn set_seed(&mut self, slot: u8, _seed: &[u8]) -> Result<(), TransportError> {
            self.calls.push(format!("seed {slot}"));
            Ok(())
        }
        fn set_title(&mut self, slot: u8, title: &str) -> Result<(), TransportError> {
            self.calls.push(format!("title {slot} {title}"));
            Ok(())
        }
        fn set_config(&mut self, slot: u8, cfg: &ProfileConfig) -> Result<(), TransportError> {
            self.calls.push(format!("config {slot}"));
            self.times.push(cfg.utc_time);
            Ok(())
        }
    }

    static CLOCK: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1_700_000_000);

    /// Each read moves the clock on by 40 s.
    fn ticking_clock() -> u32 {
        CLOCK.fetch_add(40, std::sync::atomic::Ordering::SeqCst)
    }

    #[test]
    fn molto_store_reads_the_clock_for_each_slot() {
        let e = entry(OtpKind::Totp { period: 30 });
        let mut io = ScriptedMolto::default();
        for slot in [3, 4] {
            let name = StoredName::Molto2 {
                slot,
                title: "T".to_owned(),
            };
            molto_add(&mut io, ticking_clock, DisplayTimeout::Sec30, &name, &e).unwrap();
        }
        assert_eq!(
            io.calls,
            vec![
                "seed 3",
                "title 3 T",
                "config 3",
                "seed 4",
                "title 4 T",
                "config 4"
            ]
        );
        assert_eq!(io.times, vec![1_700_000_000, 1_700_000_040]);
    }

    #[test]
    fn molto_store_maps_entry_to_profile_config() {
        let name = StoredName::Molto2 {
            slot: 7,
            title: "Example".to_owned(),
        };
        let e = ImportEntry {
            hash: HashAlg::Sha256,
            digits: 8,
            ..entry(OtpKind::Totp { period: 60 })
        };
        let w = molto_write(&name, &e, DisplayTimeout::Sec60, 1_700_000_000).unwrap();
        assert_eq!((w.slot, w.title), (7, "Example"));
        let c = &w.config;
        assert_eq!(c.display_timeout, DisplayTimeout::Sec60);
        assert_eq!(c.algorithm, HmacAlgo::Sha256);
        assert_eq!(c.digits, OtpDigits::Eight);
        assert_eq!(c.time_step, TimeStep::Seconds60);
        assert_eq!(c.utc_time, 1_700_000_000);
        let e = ImportEntry {
            hash: HashAlg::Sha1,
            digits: 6,
            ..entry(OtpKind::Totp { period: 30 })
        };
        let w = molto_write(&name, &e, DisplayTimeout::Sec30, 1).unwrap();
        assert_eq!(
            (w.config.algorithm, w.config.digits, w.config.time_step),
            (HmacAlgo::Sha1, OtpDigits::Six, TimeStep::Seconds30)
        );
    }

    #[test]
    fn molto_store_refuses_what_it_cannot_write() {
        let name = StoredName::Molto2 {
            slot: 7,
            title: "Example".to_owned(),
        };
        let bad = [
            entry(OtpKind::Hotp { counter: 0 }),
            entry(OtpKind::Totp { period: 45 }),
            ImportEntry {
                hash: HashAlg::Sha512,
                ..entry(OtpKind::Totp { period: 30 })
            },
            ImportEntry {
                digits: 7,
                ..entry(OtpKind::Totp { period: 30 })
            },
            ImportEntry {
                secret: Zeroizing::new(vec![1; 64]),
                ..entry(OtpKind::Totp { period: 30 })
            },
        ];
        for e in &bad {
            assert!(molto_write(&name, e, DisplayTimeout::Sec30, 0).is_err());
        }
        let e = entry(OtpKind::Totp { period: 30 });
        for title in ["", "thirteen byte"] {
            let n = StoredName::Molto2 {
                slot: 7,
                title: title.to_owned(),
            };
            assert!(molto_write(&n, &e, DisplayTimeout::Sec30, 0).is_err());
        }
        assert!(molto_write(&StoredName::Oath("x".into()), &e, DisplayTimeout::Sec30, 0).is_err());
    }

    fn public(title: Option<&str>, seed_present: bool) -> ProfilePublicData {
        ProfilePublicData {
            flag: 0,
            title: title.map(str::to_owned),
            time_a: 0,
            time_b: 0,
            algorithm: 0,
            time_step: 0,
            digits: 0,
            seed_present,
        }
    }

    #[test]
    fn molto_sweep_reads_every_slot_and_stops_at_a_failed_read() {
        let mut asked = Vec::new();
        let ex = molto_existing_by(|slot| {
            asked.push(slot);
            Ok(public(None, slot == 7 || slot == 99))
        })
        .unwrap();
        assert_eq!(asked, (0..=99).collect::<Vec<u8>>());
        assert_eq!(ex.names.len(), 2);
        let mut asked = 0;
        let err = molto_existing_by(|slot| {
            asked += 1;
            if slot == 3 {
                Err(TransportError::NoMolto2Reader)
            } else {
                Ok(public(None, false))
            }
        });
        assert!(err.is_err());
        assert_eq!(asked, 4);
    }

    /// The CLI reads slot use one slot at a time (`read_molto_existing`);
    /// the GUI keeps its slot sweep and calls `molto_existing` on it. The
    /// same token gives both the same slot use and so, through the shared
    /// `molto_plan`, the same plan for the same file and start slot.
    #[test]
    fn cli_and_gui_make_the_same_molto2_plan() {
        let meta: Vec<ProfilePublicData> = (0..=99u8)
            .map(|s| match s {
                95 => public(Some("Old"), true),
                97 => public(Some("Title"), false),
                98 => public(None, true),
                _ => public(None, false),
            })
            .collect();
        let cli = molto_existing_by(|s| Ok(meta[usize::from(s)].clone())).unwrap();
        let gui = molto_existing(&meta);
        assert_eq!(cli.names, gui.names);
        let f = file(6);
        let cli_plan = keyroost_import::plan::molto_plan(&f, 95, cli);
        let gui_plan = keyroost_import::plan::molto_plan(&f, 95, gui);
        assert_eq!(cli_plan, gui_plan);
        let words: Vec<&str> = cli_plan.rows.iter().map(|r| r.verdict.word()).collect();
        assert_eq!(
            words,
            ["replace", "add", "replace", "replace", "add", "skip"]
        );
        // The sixth entry runs past #99: both front ends skip it with the
        // same reason and still write the five that fit.
        let last = cli_plan.rows.last().unwrap();
        assert_eq!(
            last.verdict
                .reason(keyroost_import::plan::Store::Molto2)
                .as_deref(),
            Some("no slot left after #99")
        );
        assert_eq!(cli_plan.writes().count(), 5);
        // From #99 one slot is left: one write, the rest skipped alike.
        let cli_full = molto_existing_by(|s| Ok(meta[usize::from(s)].clone())).unwrap();
        let none_fit_cli = keyroost_import::plan::molto_plan(&file(3), 99, cli_full);
        let none_fit_gui = keyroost_import::plan::molto_plan(&file(3), 99, molto_existing(&meta));
        assert_eq!(none_fit_cli, none_fit_gui);
        assert_eq!(none_fit_cli.writes().count(), 1);
    }

    #[test]
    fn molto_existing_counts_seeded_or_titled_slots() {
        let slot = public;
        // In use: a seed or a title (as the CLI and the slot list read it).
        let meta = vec![
            slot(None, false),
            slot(Some("GitHub"), false),
            slot(Some(""), false),
            slot(None, true),
            slot(Some("Bank"), true),
        ];
        let ex = molto_existing(&meta);
        assert_eq!(
            ex.names,
            vec![
                StoredName::Molto2 {
                    slot: 1,
                    title: "GitHub".into()
                },
                StoredName::Molto2 {
                    slot: 3,
                    title: String::new()
                },
                StoredName::Molto2 {
                    slot: 4,
                    title: "Bank".into()
                },
            ]
        );
    }
}
