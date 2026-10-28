//! The import plan: for one destination, what each entry of a file becomes —
//! added, replacing a same-name entry, already there, or skipped with a plain
//! reason. Pure: the key's current entries come in as [`Existing`], read by
//! the caller just before planning; nothing here talks to a device.
//!
//! The per-device limits live in one table, [`limits`]. Every number there
//! cites the bulk-import research (`[S#]` = its source list). Limits the
//! research marks unverified are not enforced here: the key's own refusal is
//! reported for that entry when it is written.

use crate::entry::{HashAlg, ImportEntry, ImportFile, OtpKind};

/// Which kind of storage the codes go to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Store {
    /// Token2 Molto2 slots.
    Molto2,
    /// An OATH applet (YKOATH protocol).
    Oath(OathFamily),
    /// Token2 OTP-on-FIDO storage.
    Token2Otp,
}

impl Store {
    /// The device as a reason names it ("Solo 2 can't …"). Another vendor's
    /// OATH applet is "this key".
    pub fn device_name(self) -> &'static str {
        match self {
            Store::Molto2 => "Molto2",
            Store::Oath(OathFamily::YubiKey { .. }) => "YubiKey",
            Store::Oath(OathFamily::Solo2) => "Solo 2",
            Store::Oath(OathFamily::Nitrokey3) => "Nitrokey 3",
            Store::Oath(OathFamily::Other) => "this key",
            Store::Token2Otp => "this Token2 key",
        }
    }
}

/// Which OATH applet the key carries, as far as limits go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OathFamily {
    /// `version` from the OATH SELECT reply (YubiKey: firmware version).
    YubiKey {
        version: Option<(u8, u8, u8)>,
    },
    Solo2,
    Nitrokey3,
    /// Another vendor's OATH applet: no limits known up front (C6).
    Other,
}

impl OathFamily {
    /// From `keyroost_resolve::Device::vendor` ("Yubico", "SoloKeys",
    /// "Nitrokey", anything else).
    pub fn from_vendor(vendor: &str, version: Option<(u8, u8, u8)>) -> Self {
        let v = vendor.trim();
        if v.eq_ignore_ascii_case("Yubico") {
            OathFamily::YubiKey { version }
        } else if v.eq_ignore_ascii_case("SoloKeys") {
            OathFamily::Solo2
        } else if v.eq_ignore_ascii_case("Nitrokey") {
            OathFamily::Nitrokey3
        } else {
            OathFamily::Other
        }
    }

    /// The longest name this family stores, in bytes, when known.
    pub fn name_limit(self) -> Option<usize> {
        match self {
            // The whole stored name, `period/` and `issuer:` included [S1].
            OathFamily::YubiKey { .. } => Some(64),
            // Measured on Solo 2 firmware 2.964 (2026-10-09): 127 bytes
            // stored, 128 makes the key stop responding until replugged.
            OathFamily::Solo2 => Some(SOLO2_NAME_MAX),
            // Label is a Trussed `ShortData`, 128 bytes [S14][S19].
            OathFamily::Nitrokey3 => Some(128),
            OathFamily::Other => None,
        }
    }

    /// A limit that must never be crossed because crossing it makes the key
    /// stop responding: Solo 2 only (127). Used by `oath add` and the GUI add
    /// dialog.
    pub fn hard_name_limit(self) -> Option<usize> {
        match self {
            OathFamily::Solo2 => Some(SOLO2_NAME_MAX),
            _ => None,
        }
    }

    /// Why `name` must not be sent to this family at all (past
    /// [`hard_name_limit`](Self::hard_name_limit)), worded once for the CLI
    /// and the GUI.
    pub fn name_refusal(self, name: &str) -> Option<String> {
        let max = self.hard_name_limit()?;
        (name.len() > max).then(|| {
            format!(
                "the name is {} bytes; a {} stores names up to {max} bytes \
                 (a longer one makes the key stop responding until it is unplugged)",
                name.len(),
                Store::Oath(self).device_name()
            )
        })
    }
}

impl OathFamily {
    /// YubiKey 4 firmware after 4.0.0 and before 4.3.5, where ykman refuses
    /// to add a name that starts a different name already on the key
    /// (research S1, S6). Unverified on hardware here; refused up front like
    /// the Solo 2 cap.
    pub fn prefix_issue(self) -> bool {
        matches!(self, OathFamily::YubiKey { version: Some(v) } if (4, 0, 0) < v && v < (4, 3, 5))
    }

    /// Why `name` must not be added next to `others` (names on the key, or
    /// planned before it): ykman's rule on [`prefix_issue`](Self::prefix_issue)
    /// firmware — another name starts with `name` and isn't `name` itself.
    /// The one check `oath add` (CLI and GUI) and the import plan share.
    pub fn prefix_refusal<'a>(
        self,
        name: &str,
        others: impl IntoIterator<Item = &'a str>,
    ) -> Option<String> {
        (self.prefix_issue() && others.into_iter().any(|o| starts_other(name, o)))
            .then(|| Skip::StartsAnotherName.reason(Store::Oath(self)))
    }
}

/// `other` begins with `name` and is a different name.
fn starts_other(name: &str, other: &str) -> bool {
    other != name && other.starts_with(name)
}

/// Longest OATH name a Solo 2 takes (measured; see [`OathFamily::name_limit`]).
const SOLO2_NAME_MAX: usize = 127;

/// Molto2 slots run #0..=#99.
const MOLTO_LAST_SLOT: u8 = 99;

/// How a code is named on the key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum StoredName {
    /// The full OATH name, `period/` prefix included.
    Oath(String),
    /// Token2's identity tuple; `app` may be empty.
    Token2 { app: String, account: String },
    /// A Molto2 slot and the title written there (may be empty when read
    /// back from the key).
    Molto2 { slot: u8, title: String },
}

impl core::fmt::Display for StoredName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StoredName::Oath(n) => write!(f, "{}", n),
            StoredName::Token2 { app, account } if app.is_empty() => write!(f, "{}", account),
            StoredName::Token2 { app, account } => write!(f, "{}:{}", app, account),
            StoredName::Molto2 { slot, title } if title.is_empty() => write!(f, "#{}", slot),
            StoredName::Molto2 { slot, title } => write!(f, "#{} {}", slot, title),
        }
    }
}

/// What the key holds, read just before planning.
#[derive(Debug, Clone, Default)]
pub struct Existing {
    /// OATH names; Token2 (app, account); Molto2 occupied slots (title may be
    /// empty).
    pub names: Vec<StoredName>,
    /// Entries on the key the listing couldn't show (OATH `Listing::skipped`).
    pub hidden: usize,
}

/// One destination, as the plan sees it.
#[derive(Debug, Clone)]
pub struct Target {
    pub store: Store,
    /// Molto2: the first slot to fill (0..=99). Ignored elsewhere.
    pub first_slot: u8,
    pub existing: Existing,
    /// Replace same-name entries (OATH, Token2). Ignored for Molto2, whose
    /// occupied slots are always replaced (C15).
    pub replace: bool,
}

/// What happens to one entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Written; nothing of that name is on the key.
    Add,
    /// Written over (or after removing) the same-name entry on the key.
    Replace,
    /// Same name already on the key and replacing wasn't asked for.
    Exists,
    /// Not written, with the reason.
    Skip(Skip),
}

/// Why an entry isn't written to this destination.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Skip {
    /// No key can take it (bad secret, Steam, …).
    Unusable(crate::entry::Unusable),
    /// Neither an issuer nor an account to name it by.
    NoName,
    NameTooLong {
        len: usize,
        max: usize,
    },
    NotAscii,
    /// The name would read back differently (issuer with ':' or a bare
    /// account that looks like a period prefix).
    AmbiguousName,
    Hash(HashAlg),
    Digits(u8),
    Period(u32),
    /// Nitrokey 3 doesn't store a period; only 30 s codes work there.
    PeriodNotStored(u32),
    /// The key stores only TOTP codes.
    Hotp,
    /// The HOTP counter can't be carried: past 32 bits on OATH, or not 0 on
    /// Token2 (whose write has no counter field).
    Counter(u64),
    SecretLength {
        len: usize,
        max: usize,
    },
    /// Name and seed together are too long for one command.
    TooLongForCommand,
    /// The same stored name as an earlier entry of the file (`first` is that
    /// entry's [`ImportItem::index`](crate::ImportItem::index)).
    SameNameInFile {
        first: usize,
    },
    /// The key would be full before this one.
    NoRoom {
        capacity: usize,
    },
    /// Molto2: past slot #99.
    PastLastSlot,
    /// YubiKey 4 firmware 4.0–4.3.4: the name starts a different name on
    /// the key or planned before it (see [`OathFamily::prefix_issue`]).
    StartsAnotherName,
}

impl Skip {
    /// The reason in plain words, naming the destination's device where it
    /// matters ("Solo 2 doesn't take SHA-512 codes").
    pub fn reason(&self, store: Store) -> String {
        reason(self, store.device_name(), store == Store::Token2Otp)
    }
}

/// [`Skip::reason`] without a known destination: the device is "this key".
impl core::fmt::Display for Skip {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&reason(self, "this key", false))
    }
}

fn reason(skip: &Skip, device: &str, token2: bool) -> String {
    match skip {
        Skip::Unusable(u) => u.to_string(),
        Skip::NoName => "it has no issuer or account to name it by".to_owned(),
        Skip::NameTooLong { len, max } => format!(
            "the name is {} bytes; {} stores names of up to {} bytes",
            len, device, max
        ),
        Skip::NotAscii => format!(
            "{} stores names in plain ASCII characters only, and this name has others",
            device
        ),
        Skip::AmbiguousName => "the name would read back differently on the key \
             (an issuer with ':' or a name that starts like a period, such as 60/)"
            .to_owned(),
        Skip::Hash(h) => format!("{} doesn't take {} codes", device, h.name()),
        Skip::Digits(d) => format!("{} can't store {}-digit codes", device, d),
        Skip::Period(p) => format!("{} can't use a {}-second period", device, p),
        Skip::PeriodNotStored(p) => format!(
            "Nitrokey 3 doesn't store the period, so only 30-second codes work there \
             (this one uses {} seconds)",
            p
        ),
        Skip::Hotp => format!(
            "{} stores only time-based (TOTP) codes, and this one is counter-based (HOTP)",
            device
        ),
        Skip::Counter(c) if token2 => format!(
            "{} always starts the counter at 0, and this code's counter is at {}",
            device, c
        ),
        Skip::Counter(c) => format!("the counter {} is too large for {}", c, device),
        Skip::SecretLength { len, max } => format!(
            "the secret is {} bytes; {} stores secrets of up to {} bytes",
            len, device, max
        ),
        Skip::TooLongForCommand => {
            "the name and secret together are too long to send to the key".to_owned()
        }
        Skip::SameNameInFile { first } => {
            format!("same name as entry #{} in this file", first + 1)
        }
        Skip::NoRoom { capacity } => {
            format!("no room left ({} holds {} codes)", device, capacity)
        }
        Skip::PastLastSlot => "no slot left after #99".to_owned(),
        Skip::StartsAnotherName => format!(
            "{} firmware 4.0\u{2013}4.3.4 can't safely store a name that starts \
             another name on the key",
            device
        ),
    }
}

/// Something the person should know about the plan as a whole.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Note {
    /// Replace removes the old code first on keys that refuse duplicates; if
    /// the add then fails, the old code is gone.
    ReplaceMayLoseOld,
    /// The key doesn't report how many codes it holds; writing stops if it
    /// fills up.
    CapacityUnknown,
    /// Solo 2 HOTP: the README sentence about the 4-byte counter.
    Solo2Hotp,
    /// A Nitrokey 3 may ask for a touch for each code it replaces (firmware
    /// that refuses duplicates removes the old code first; source, not
    /// hardware, says that removal asks for a touch).
    Nitrokey3TouchToReplace,
    /// `n` codes on the key couldn't be listed; a same-name one may still
    /// be refused.
    Hidden(usize),
    /// Molto2 slots already in use will be replaced.
    MoltoReplacesSlots,
}

impl core::fmt::Display for Note {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Note::ReplaceMayLoseOld => f.write_str(
                "Replacing removes the old code first on keys that refuse duplicate \
                 names. If adding the new one then fails, the old code is gone.",
            ),
            Note::CapacityUnknown => f.write_str(
                "This key doesn't report how many codes it holds; writing stops if it fills up.",
            ),
            Note::Solo2Hotp => f.write_str(
                "Solo 2 firmware 2.964 (its latest release) computes HOTP codes over a 4-byte counter \
                 (the HOTP standard uses 8 bytes), so its HOTP codes don't match \
                 what services expect. TOTP codes work normally.",
            ),
            Note::Nitrokey3TouchToReplace => {
                f.write_str("A Nitrokey 3 may ask for a touch for each code it replaces.")
            }
            Note::Hidden(n) => write!(
                f,
                "{} codes on the key couldn't be listed; the key may still refuse \
                 a name that is already on it.",
                n
            ),
            Note::MoltoReplacesSlots => f.write_str("Slots already in use will be replaced."),
        }
    }
}

/// One entry of the file and what happens to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanRow {
    /// [`ImportItem::index`](crate::ImportItem::index).
    pub index: usize,
    /// [`ImportItem::label`](crate::ImportItem::label).
    pub label: String,
    /// The name on the key; `None` when the entry couldn't be named.
    pub name: Option<StoredName>,
    pub verdict: Verdict,
}

impl PlanRow {
    /// The row as every list names it: the file's label, with its slot in
    /// front for a Molto2 (`#05 GitHub`).
    pub fn shown_label(&self) -> String {
        match &self.name {
            Some(StoredName::Molto2 { slot, .. }) => format!("#{:02} {}", slot, self.label),
            _ => self.label.clone(),
        }
    }
}

impl Verdict {
    /// The one word for the verdict: the CLI preview's column, the JSON's
    /// `plan`, and the GUI preview row.
    pub fn word(&self) -> &'static str {
        match self {
            Verdict::Add => "add",
            Verdict::Replace => "replace",
            Verdict::Exists => "exists",
            Verdict::Skip(_) => "skip",
        }
    }

    /// Why a row isn't a plain add, in plain words (`None` for an add).
    pub fn reason(&self, store: Store) -> Option<String> {
        match self {
            Verdict::Add => None,
            Verdict::Replace if store == Store::Molto2 => {
                Some("replaces the code in this slot".to_owned())
            }
            Verdict::Replace => Some("replaces the code of the same name on the key".to_owned()),
            Verdict::Exists => Some(EXISTS_REASON.to_owned()),
            Verdict::Skip(s) => Some(s.reason(store)),
        }
    }
}

/// Why an entry already on the key isn't written: shared by the plan's
/// `exists` rows and the run's `exists` outcome.
pub const EXISTS_REASON: &str = "already on the key; left as is";

/// The whole plan for one destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub store: Store,
    pub rows: Vec<PlanRow>,
    /// How many codes the key holds in all, when known (Molto2: the slots
    /// from the first one to #99).
    pub capacity: Option<usize>,
    /// Entries already on the key, hidden ones included.
    pub on_key: usize,
    pub replace: bool,
    pub notes: Vec<Note>,
}

/// How many rows got each verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Counts {
    pub add: usize,
    pub replace: usize,
    pub exists: usize,
    pub skip: usize,
}

impl Plan {
    pub fn counts(&self) -> Counts {
        let mut c = Counts::default();
        for r in &self.rows {
            match r.verdict {
                Verdict::Add => c.add += 1,
                Verdict::Replace => c.replace += 1,
                Verdict::Exists => c.exists += 1,
                Verdict::Skip(_) => c.skip += 1,
            }
        }
        c
    }

    /// Whether `other` plans the same thing for every row: the re-check
    /// after a question, before anything is written.
    pub fn same_rows(&self, other: &Plan) -> bool {
        self.rows == other.rows
    }

    /// Rows that write (Add or Replace), in file order.
    pub fn writes(&self) -> impl Iterator<Item = &PlanRow> {
        self.rows
            .iter()
            .filter(|r| matches!(r.verdict, Verdict::Add | Verdict::Replace))
    }
}

/// The rule table, one row per store. Every number cites the research (`[S#]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Longest name in bytes (Token2: app and account each; Molto2: the
    /// title, which is shortened to fit rather than skipped).
    pub name_max: Option<usize>,
    pub ascii_only: bool,
    pub hashes: &'static [HashAlg],
    /// Molto2 additionally takes only even lengths (see `molto_digits`).
    pub digits: core::ops::RangeInclusive<u8>,
    pub totp: PeriodRule,
    pub hotp: HotpRule,
    pub secret_max: Option<usize>,
    pub capacity: Option<usize>,
}

/// Which TOTP periods a store keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeriodRule {
    /// Any period; a non-30 s one goes into the name as `period/`.
    Any,
    /// The period isn't stored; only 30 s codes come out right.
    Only30,
    /// 30 or 60 s.
    Molto2,
    /// An inclusive range stored on the key.
    Range(u32, u32),
}

/// Whether a store takes HOTP, and with which starting counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HotpRule {
    No,
    /// Any counter that fits 32 bits.
    CounterU32,
    /// Only a counter of 0 (the write has no counter field).
    CounterZeroOnly,
}

const SHA1_256: &[HashAlg] = &[HashAlg::Sha1, HashAlg::Sha256];
const SHA1_256_512: &[HashAlg] = &[HashAlg::Sha1, HashAlg::Sha256, HashAlg::Sha512];

/// The per-device rule table.
pub fn limits(store: Store) -> Limits {
    match store {
        Store::Oath(OathFamily::YubiKey { version }) => Limits {
            // 64 bytes, whole stored name [S1].
            name_max: Some(64),
            ascii_only: false,
            // SHA-512 needs firmware 4.3.1+ [S1]; unknown version: let the
            // key answer.
            hashes: match version {
                Some(v) if v < (4, 3, 1) => SHA1_256,
                _ => SHA1_256_512,
            },
            // keyroost's `oath add` range; what ykman offers [S6] (decision 6).
            digits: 6..=8,
            // Period is host-side, carried in the name prefix [S5][S7].
            totp: PeriodRule::Any,
            // IMF is a 4-byte initial counter [S1].
            hotp: HotpRule::CounterU32,
            // No documented maximum: the key's own refusal is reported.
            secret_max: None,
            // 64 from 5.7, 32 before [S3][S9] (C7); older: unknown.
            capacity: match version {
                Some(v) if v >= (5, 7, 0) => Some(64),
                Some(v) if v >= (4, 0, 0) => Some(32),
                _ => None,
            },
        },
        Store::Oath(OathFamily::Solo2) => Limits {
            // Measured 2026-10-09 on firmware 2.964.
            name_max: Some(SOLO2_NAME_MAX),
            ascii_only: false,
            // SHA-512 is accepted at PUT but can't compute codes [S11].
            hashes: SHA1_256,
            digits: 6..=8,
            // Host-side period, as on YubiKey [S11].
            totp: PeriodRule::Any,
            // u32 counter [S11]; see `Note::Solo2Hotp`.
            hotp: HotpRule::CounterU32,
            // Spec cap, kept at 64 on purpose. The applet serializes each
            // credential into a 256-byte buffer [S11]; a 127-byte name plus a
            // 64-byte secret plus the few type/digits/counter bytes comes to
            // roughly 200, under that bound by the source's layout. That is an
            // estimate, not a measurement: the 127-byte name measurement did
            // not test long secrets with it, and edge probing on the key is
            // off the table. 64 bytes covers real services' seeds (20–64), so
            // nothing higher is offered.
            secret_max: Some(64),
            // No count limit in the applet [S11]: unknown.
            capacity: None,
        },
        Store::Oath(OathFamily::Nitrokey3) => Limits {
            // Trussed `ShortData` label, 128 bytes [S14][S19].
            name_max: Some(128),
            ascii_only: false,
            // SHA-512 accepted at REGISTER but can't compute [S14]; the
            // Nitrokey SDK refuses it [S23].
            hashes: SHA1_256,
            digits: 6..=8,
            // The period isn't stored anywhere [S23][S24].
            totp: PeriodRule::Only30,
            // 32-bit initial counter [S18][S23].
            hotp: HotpRule::CounterU32,
            // Secret is a `ShortData`, 128 bytes [S14][S19].
            secret_max: Some(128),
            // `SECRETS_APP_CREDENTIALS_COUNT_LIMIT = 50` [S16][S17].
            capacity: Some(50),
        },
        Store::Oath(OathFamily::Other) => Limits {
            // C6: no limits up front beyond 6–8 digits and command size.
            name_max: None,
            ascii_only: false,
            hashes: SHA1_256_512,
            digits: 6..=8,
            totp: PeriodRule::Any,
            // IMF is 4 bytes in the YKOATH protocol [S1].
            hotp: HotpRule::CounterU32,
            secret_max: None,
            capacity: None,
        },
        Store::Token2Otp => Limits {
            // account 1..=64, app 0..=64, ASCII [S20 §6.1, §6.3].
            name_max: Some(64),
            ascii_only: true,
            // C1/C2 algorithm codes only [S20 §6.1].
            hashes: SHA1_256,
            // code_length 4..=10 [S20 §6.3].
            digits: 4..=10,
            // timestep u16, 1..=65535 [S20 §6.3].
            totp: PeriodRule::Range(1, 65535),
            // No counter field in the write [S20 §6.3] (C8).
            hotp: HotpRule::CounterZeroOnly,
            // Seed 1..=64 bytes [S20 §6.3].
            secret_max: Some(64),
            // 50 codes "via the app" [S22].
            capacity: Some(50),
        },
        Store::Molto2 => Limits {
            // Titles are shortened to 12 bytes, never skipped for length
            // (`BulkEntry::suggested_title`).
            name_max: Some(12),
            ascii_only: false,
            // The Molto2 path's existing rules (`bulk::build_entry`).
            hashes: SHA1_256,
            digits: 4..=10,
            totp: PeriodRule::Molto2,
            hotp: HotpRule::No,
            secret_max: Some(63),
            // Slots #0..=#99; the plan counts from the first slot.
            capacity: Some(100),
        },
    }
}

/// Molto2 code lengths: 4, 6, 8 or 10.
fn molto_digits(d: u8) -> bool {
    matches!(d, 4 | 6 | 8 | 10)
}

/// Whether an OATH PUT fits one short APDU: the name TLV, the key TLV
/// (type/algorithm and digits bytes plus the seed, zero-padded to 14 bytes),
/// and the 6-byte IMF TLV when a non-zero HOTP counter is sent — at most 255
/// bytes in all. Mirrors `keyroost_oath::put`.
pub fn oath_put_fits(name_len: usize, secret_len: usize, imf: bool) -> bool {
    const MIN_HMAC_KEY_LEN: usize = 14;
    let body = 2 + name_len + 2 + 2 + secret_len.max(MIN_HMAC_KEY_LEN) + if imf { 6 } else { 0 };
    body <= 255
}

/// `<digits>/…`: what ykman reads as a period prefix.
fn looks_like_period_prefix(s: &str) -> bool {
    match s.split_once('/') {
        Some((head, _)) => !head.is_empty() && head.bytes().all(|b| b.is_ascii_digit()),
        None => false,
    }
}

/// Name an entry for an OATH family (decision 3), or say why it can't be
/// named. Lengths aren't checked here.
pub fn oath_name(e: &ImportEntry, family: OathFamily) -> Result<String, Skip> {
    // Clients read a TOTP name's leading `<digits>/` as its period [S5];
    // Nitrokey 3 keeps no period in the name [S23][S24], so nothing is read
    // there.
    let period_read = matches!(e.kind, OtpKind::Totp { .. }) && family != OathFamily::Nitrokey3;
    let prefix = match e.kind {
        OtpKind::Totp { period } if period != 30 && period_read => Some(period),
        _ => None,
    };
    let base = match (e.issuer.as_deref(), e.account.as_deref()) {
        (Some(i), Some(a)) => {
            if i.contains(':') {
                return Err(Skip::AmbiguousName);
            }
            format!("{}:{}", i, a)
        }
        // A single part with ':' would be read back as `issuer:account`.
        (Some(one), None) | (None, Some(one)) if one.contains(':') => {
            return Err(Skip::AmbiguousName)
        }
        (Some(one), None) | (None, Some(one)) => one.to_owned(),
        (None, None) => return Err(Skip::NoName),
    };
    match prefix {
        // After an explicit prefix the rest reads back whole.
        Some(p) => Ok(format!("{}/{}", p, base)),
        // A 30 s name starting `<digits>/` (issuer or bare account) would
        // be read as a period.
        None if period_read && looks_like_period_prefix(&base) => Err(Skip::AmbiguousName),
        None => Ok(base),
    }
}

/// (app, account) for Token2 (decision 4): app = issuer (or empty), account
/// = account, else the issuer. Lengths aren't checked here.
pub fn token2_name(e: &ImportEntry) -> Result<(String, String), Skip> {
    match (e.issuer.as_deref(), e.account.as_deref()) {
        (Some(i), Some(a)) => Ok((i.to_owned(), a.to_owned())),
        (None, Some(one)) | (Some(one), None) => Ok((String::new(), one.to_owned())),
        (None, None) => Err(Skip::NoName),
    }
}

/// The parameter checks of step 2: kind, hash, digits, period, counter,
/// secret — the first failure wins.
fn check_params(e: &ImportEntry, store: Store, lim: &Limits) -> Result<(), Skip> {
    if let (OtpKind::Hotp { .. }, HotpRule::No) = (e.kind, lim.hotp) {
        return Err(Skip::Hotp);
    }
    if !lim.hashes.contains(&e.hash) {
        return Err(Skip::Hash(e.hash));
    }
    let digits_ok =
        lim.digits.contains(&e.digits) && (store != Store::Molto2 || molto_digits(e.digits));
    if !digits_ok {
        return Err(Skip::Digits(e.digits));
    }
    match e.kind {
        OtpKind::Totp { period } => match lim.totp {
            PeriodRule::Any => {}
            PeriodRule::Only30 if period != 30 => return Err(Skip::PeriodNotStored(period)),
            PeriodRule::Only30 => {}
            PeriodRule::Molto2 if period != 30 && period != 60 => return Err(Skip::Period(period)),
            PeriodRule::Molto2 => {}
            PeriodRule::Range(lo, hi) if !(lo..=hi).contains(&period) => {
                return Err(Skip::Period(period))
            }
            PeriodRule::Range(..) => {}
        },
        OtpKind::Hotp { counter } => match lim.hotp {
            HotpRule::CounterU32 if counter > u64::from(u32::MAX) => {
                return Err(Skip::Counter(counter))
            }
            HotpRule::CounterZeroOnly if counter != 0 => return Err(Skip::Counter(counter)),
            _ => {}
        },
    }
    if let Some(max) = lim.secret_max {
        if e.secret.len() > max {
            return Err(Skip::SecretLength {
                len: e.secret.len(),
                max,
            });
        }
    }
    Ok(())
}

/// Step 3 (and 4 for OATH): the stored name, checked for length, ASCII and
/// command fit. Molto2 names come later, with their slot.
fn name_for(e: &ImportEntry, store: Store, lim: &Limits) -> Result<StoredName, Skip> {
    match store {
        Store::Oath(family) => {
            let name = oath_name(e, family)?;
            if let Some(max) = lim.name_max {
                if name.len() > max {
                    return Err(Skip::NameTooLong {
                        len: name.len(),
                        max,
                    });
                }
            }
            let imf = matches!(e.kind, OtpKind::Hotp { counter } if counter != 0);
            if !oath_put_fits(name.len(), e.secret.len(), imf) {
                return Err(Skip::TooLongForCommand);
            }
            Ok(StoredName::Oath(name))
        }
        Store::Token2Otp => {
            let (app, account) = token2_name(e)?;
            if !app.is_ascii() || !account.is_ascii() {
                return Err(Skip::NotAscii);
            }
            let max = lim.name_max.unwrap_or(usize::MAX);
            for part in [&app, &account] {
                if part.len() > max {
                    return Err(Skip::NameTooLong {
                        len: part.len(),
                        max,
                    });
                }
            }
            Ok(StoredName::Token2 { app, account })
        }
        Store::Molto2 => unreachable!("Molto2 names are assigned with their slot"),
    }
}

/// [`plan`] with the target's parts given one by one.
pub fn plan_for(
    file: &ImportFile,
    store: Store,
    first_slot: u8,
    existing: Existing,
    replace: bool,
) -> Plan {
    plan(
        file,
        &Target {
            store,
            first_slot,
            existing,
            replace,
        },
    )
}

/// The Molto2 plan from `first_slot`: entries fill consecutive slots and
/// slots in use are replaced (there is no replace-by-name choice). The one
/// call the CLI and the GUI both make for a Molto2.
pub fn molto_plan(file: &ImportFile, first_slot: u8, existing: Existing) -> Plan {
    plan_for(file, Store::Molto2, first_slot, existing, false)
}

/// Plan an import of `file` into `target`.
pub fn plan(file: &ImportFile, target: &Target) -> Plan {
    let store = target.store;
    let lim = limits(store);
    let existing = &target.existing;
    let on_key = existing.names.len() + existing.hidden;
    let capacity = match store {
        Store::Molto2 => {
            Some(usize::from(MOLTO_LAST_SLOT + 1).saturating_sub(usize::from(target.first_slot)))
        }
        _ => lim.capacity,
    };

    let mut rows = Vec::with_capacity(file.items.len());
    // Names already planned from this file, with the first entry's index.
    let mut seen: Vec<(StoredName, usize)> = Vec::new();
    // Molto2: the next slot to fill (u16 so passing #99 can be seen).
    let mut next_slot = u16::from(target.first_slot);

    for item in &file.items {
        let (name, verdict) = match &item.entry {
            Err(u) => (None, Verdict::Skip(Skip::Unusable(u.clone()))),
            Ok(e) => match check_params(e, store, &lim) {
                Err(s) => (None, Verdict::Skip(s)),
                Ok(()) if store == Store::Molto2 => {
                    let title =
                        crate::entry::molto_title(e.issuer.as_deref(), e.account.as_deref());
                    if title.is_empty() {
                        // The Molto2 writer skips untitled entries (no issuer
                        // or account to show).
                        (None, Verdict::Skip(Skip::NoName))
                    } else if next_slot > u16::from(MOLTO_LAST_SLOT) {
                        (None, Verdict::Skip(Skip::PastLastSlot))
                    } else {
                        let slot = next_slot as u8;
                        next_slot += 1;
                        let occupied = existing
                            .names
                            .iter()
                            .any(|n| matches!(n, StoredName::Molto2 { slot: s, .. } if *s == slot));
                        let v = if occupied {
                            Verdict::Replace
                        } else {
                            Verdict::Add
                        };
                        (Some(StoredName::Molto2 { slot, title }), v)
                    }
                }
                Ok(()) => match name_for(e, store, &lim) {
                    Err(s) => (None, Verdict::Skip(s)),
                    Ok(n) => {
                        let v = if let Some((_, first)) = seen.iter().find(|(s, _)| *s == n) {
                            Verdict::Skip(Skip::SameNameInFile { first: *first })
                        } else {
                            let on_key = existing.names.contains(&n);
                            // Exists comes first: nothing is written, so the
                            // prefix rule (a write rule) doesn't apply.
                            if on_key && !target.replace {
                                seen.push((n.clone(), item.index));
                                Verdict::Exists
                            } else if starts_another_name(store, &n, existing, &seen) {
                                Verdict::Skip(Skip::StartsAnotherName)
                            } else {
                                seen.push((n.clone(), item.index));
                                if on_key {
                                    Verdict::Replace
                                } else {
                                    Verdict::Add
                                }
                            }
                        };
                        (Some(n), v)
                    }
                },
            },
        };
        rows.push(PlanRow {
            index: item.index,
            label: item.label.clone(),
            name,
            verdict,
        });
    }

    // Step 8: room. Only adds use it; Molto2 runs out of slots instead.
    if store != Store::Molto2 {
        if let Some(cap) = capacity {
            let mut used = on_key;
            for row in &mut rows {
                if row.verdict == Verdict::Add {
                    if used >= cap {
                        row.verdict = Verdict::Skip(Skip::NoRoom { capacity: cap });
                    } else {
                        used += 1;
                    }
                }
            }
        }
    }

    let notes = notes_for(store, &rows, capacity, existing.hidden, file);
    Plan {
        store,
        rows,
        capacity,
        on_key,
        replace: target.replace,
        notes,
    }
}

/// [`OathFamily::prefix_refusal`] over the names on the key and the names
/// planned before this one.
fn starts_another_name(
    store: Store,
    name: &StoredName,
    existing: &Existing,
    seen: &[(StoredName, usize)],
) -> bool {
    let (Store::Oath(family), StoredName::Oath(name)) = (store, name) else {
        return false;
    };
    let others = existing
        .names
        .iter()
        .chain(seen.iter().map(|(n, _)| n))
        .filter_map(|n| match n {
            StoredName::Oath(s) => Some(s.as_str()),
            _ => None,
        });
    family.prefix_refusal(name, others).is_some()
}

fn notes_for(
    store: Store,
    rows: &[PlanRow],
    capacity: Option<usize>,
    hidden: usize,
    file: &ImportFile,
) -> Vec<Note> {
    let any_replace = rows.iter().any(|r| r.verdict == Verdict::Replace);
    let mut notes = Vec::new();
    if any_replace
        && matches!(
            store,
            Store::Oath(OathFamily::Solo2 | OathFamily::Nitrokey3 | OathFamily::Other)
        )
    {
        notes.push(Note::ReplaceMayLoseOld);
    }
    if capacity.is_none() && store != Store::Molto2 {
        notes.push(Note::CapacityUnknown);
    }
    if store == Store::Oath(OathFamily::Solo2) {
        let hotp_write = rows
            .iter()
            .filter(|r| matches!(r.verdict, Verdict::Add | Verdict::Replace))
            .any(|r| {
                file.items.iter().any(|i| {
                    i.index == r.index
                        && matches!(&i.entry, Ok(e) if matches!(e.kind, OtpKind::Hotp { .. }))
                })
            });
        if hotp_write {
            notes.push(Note::Solo2Hotp);
        }
    }
    if any_replace && store == Store::Oath(OathFamily::Nitrokey3) {
        notes.push(Note::Nitrokey3TouchToReplace);
    }
    if hidden > 0 {
        notes.push(Note::Hidden(hidden));
    }
    if any_replace && store == Store::Molto2 {
        notes.push(Note::MoltoReplacesSlots);
    }
    notes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{Format, ImportItem, Unusable};
    use zeroize::Zeroizing;

    #[test]
    fn name_refusal_is_solo2_only_past_127() {
        let long = "n".repeat(128);
        assert_eq!(
            OathFamily::Solo2.name_refusal(&long).as_deref(),
            Some(
                "the name is 128 bytes; a Solo 2 stores names up to 127 bytes \
                 (a longer one makes the key stop responding until it is unplugged)"
            )
        );
        assert_eq!(OathFamily::Solo2.name_refusal(&"n".repeat(127)), None);
        assert_eq!(
            OathFamily::YubiKey { version: None }.name_refusal(&long),
            None
        );
        assert_eq!(OathFamily::Nitrokey3.name_refusal(&long), None);
        assert_eq!(OathFamily::Other.name_refusal(&long), None);
    }

    #[test]
    fn yubikey_4_prefix_rule_is_ykmans() {
        let yk = |v| OathFamily::YubiKey { version: Some(v) };
        let on_key = ["GitHub:alice", "Bank"];
        // Inside 4.0.0 < v < 4.3.5: a new name that starts a different name
        // on the key is refused; the reverse direction and equal names are not.
        let want = "YubiKey firmware 4.0\u{2013}4.3.4 can't safely store a name that starts \
                    another name on the key";
        assert_eq!(
            yk((4, 3, 4)).prefix_refusal("GitHub", on_key).as_deref(),
            Some(want)
        );
        assert_eq!(
            yk((4, 0, 1)).prefix_refusal("GitHub", on_key).as_deref(),
            Some(want)
        );
        assert_eq!(yk((4, 3, 4)).prefix_refusal("GitHub:alice", on_key), None);
        assert_eq!(yk((4, 3, 4)).prefix_refusal("Bank:x", on_key), None);
        assert_eq!(yk((4, 3, 4)).prefix_refusal("Other", on_key), None);
        // Outside the range, and on other families: never.
        for f in [
            yk((4, 0, 0)),
            yk((4, 3, 5)),
            yk((5, 7, 1)),
            OathFamily::YubiKey { version: None },
            OathFamily::Solo2,
            OathFamily::Nitrokey3,
            OathFamily::Other,
        ] {
            assert_eq!(f.prefix_refusal("GitHub", on_key), None, "{f:?}");
        }
    }

    #[test]
    fn yubikey_4_exact_name_on_the_key_is_exists_before_the_prefix_rule() {
        let yk43 = Store::Oath(OathFamily::YubiKey {
            version: Some((4, 3, 1)),
        });
        // "GitHub" is on the key, and so is "GitHub:alice", which it starts.
        let on_key = || vec![oath("GitHub"), oath("GitHub:alice")];
        let f = file(vec![entry(
            None,
            Some("GitHub"),
            20,
            HashAlg::Sha1,
            6,
            TOTP30,
        )]);
        // Without replace: already on the key, left as is.
        let p = plan(&f, &target(yk43, on_key(), false));
        assert_eq!(verdicts(&p), vec![Verdict::Exists]);
        // Replacing it would be the write ykman refuses: skipped.
        let p = plan(&f, &target(yk43, on_key(), true));
        assert_eq!(verdicts(&p), vec![Verdict::Skip(Skip::StartsAnotherName)]);
    }

    #[test]
    fn yubikey_4_prefix_names_are_skipped_in_plan() {
        let yk43 = Store::Oath(OathFamily::YubiKey {
            version: Some((4, 3, 1)),
        });
        let f = file(vec![
            // Starts "GitHub:alice" on the key.
            entry(None, Some("GitHub"), 20, HashAlg::Sha1, 6, TOTP30),
            // Planned first, then a shorter name that starts it.
            simple("Bank", "bob"),
            entry(Some("Bank"), None, 20, HashAlg::Sha1, 6, TOTP30),
            // Longer than a name on the key: allowed (ykman's direction).
            simple("GitHub", "alice2"),
        ]);
        let p = plan(&f, &target(yk43, vec![oath("GitHub:alice")], true));
        assert_eq!(
            verdicts(&p),
            vec![
                Verdict::Skip(Skip::StartsAnotherName),
                Verdict::Add,
                Verdict::Skip(Skip::StartsAnotherName),
                Verdict::Add,
            ]
        );
        // The same file on a 5.x key plans every row.
        let p = plan(&f, &target(YK57, vec![oath("GitHub:alice")], true));
        assert_eq!(p.counts().add, 4);
    }

    const YK57: Store = Store::Oath(OathFamily::YubiKey {
        version: Some((5, 7, 1)),
    });
    const SOLO: Store = Store::Oath(OathFamily::Solo2);
    const NK3: Store = Store::Oath(OathFamily::Nitrokey3);
    const TOTP30: OtpKind = OtpKind::Totp { period: 30 };

    fn entry(
        issuer: Option<&str>,
        account: Option<&str>,
        secret_len: usize,
        hash: HashAlg,
        digits: u8,
        kind: OtpKind,
    ) -> ImportEntry {
        ImportEntry {
            issuer: issuer.map(str::to_owned),
            account: account.map(str::to_owned),
            secret: Zeroizing::new(vec![0x5a; secret_len]),
            hash,
            digits,
            kind,
        }
    }

    fn simple(issuer: &str, account: &str) -> ImportEntry {
        entry(Some(issuer), Some(account), 20, HashAlg::Sha1, 6, TOTP30)
    }

    fn file(entries: Vec<ImportEntry>) -> ImportFile {
        ImportFile {
            format: Format::OtpauthList,
            items: entries
                .into_iter()
                .enumerate()
                .map(|(index, e)| ImportItem {
                    index,
                    label: format!("entry {}", index + 1),
                    entry: Ok(e),
                })
                .collect(),
            batch: None,
        }
    }

    fn target(store: Store, names: Vec<StoredName>, replace: bool) -> Target {
        Target {
            store,
            first_slot: 0,
            existing: Existing { names, hidden: 0 },
            replace,
        }
    }

    fn verdicts(p: &Plan) -> Vec<Verdict> {
        p.rows.iter().map(|r| r.verdict.clone()).collect()
    }

    fn one(store: Store, e: ImportEntry) -> Verdict {
        plan(&file(vec![e]), &target(store, vec![], false)).rows[0]
            .verdict
            .clone()
    }

    fn oath(n: &str) -> StoredName {
        StoredName::Oath(n.to_owned())
    }

    #[test]
    fn existing_name_is_exists_without_overwrite() {
        let f = file(vec![simple("Example", "alice"), simple("Example", "bob")]);
        let p = plan(&f, &target(YK57, vec![oath("Example:alice")], false));
        assert_eq!(verdicts(&p), vec![Verdict::Exists, Verdict::Add]);
        assert!(!p.replace);

        let t2 = StoredName::Token2 {
            app: "Example".into(),
            account: "alice".into(),
        };
        let p = plan(&f, &target(Store::Token2Otp, vec![t2], false));
        assert_eq!(verdicts(&p), vec![Verdict::Exists, Verdict::Add]);
    }

    #[test]
    fn existing_name_is_replace_with_overwrite() {
        let f = file(vec![simple("Example", "alice"), simple("Example", "bob")]);
        let p = plan(&f, &target(YK57, vec![oath("Example:alice")], true));
        assert_eq!(verdicts(&p), vec![Verdict::Replace, Verdict::Add]);
        assert!(p.replace);

        let t2 = StoredName::Token2 {
            app: "Example".into(),
            account: "alice".into(),
        };
        let p = plan(&f, &target(Store::Token2Otp, vec![t2], true));
        assert_eq!(verdicts(&p), vec![Verdict::Replace, Verdict::Add]);
    }

    #[test]
    fn solo2_name_127_bytes_adds_128_skips() {
        // "issuer:account": 10 + 1 + 116 = 127; one more byte is 128.
        let issuer = "I".repeat(10);
        let ok = simple(&issuer, &"a".repeat(116));
        let long = simple(&issuer, &"a".repeat(117));
        assert_eq!(one(SOLO, ok), Verdict::Add);
        assert_eq!(
            one(SOLO, long),
            Verdict::Skip(Skip::NameTooLong { len: 128, max: 127 })
        );
    }

    #[test]
    fn solo2_name_limit_counts_utf8_bytes_and_prefix() {
        // "60/" + "Ü" * 40 (80 bytes) + ":" + 43 'a' = 127 bytes, 84 chars;
        // one more 'a' crosses only in bytes (and only with the prefix).
        let issuer = "Ü".repeat(40);
        let mk = |n: usize| {
            entry(
                Some(&issuer),
                Some(&"a".repeat(n)),
                20,
                HashAlg::Sha1,
                6,
                OtpKind::Totp { period: 60 },
            )
        };
        assert_eq!(one(SOLO, mk(43)), Verdict::Add);
        assert_eq!(
            one(SOLO, mk(44)),
            Verdict::Skip(Skip::NameTooLong { len: 128, max: 127 })
        );
        // The same name at 30 s carries no prefix and fits.
        let e30 = entry(
            Some(&issuer),
            Some(&"a".repeat(44)),
            20,
            HashAlg::Sha1,
            6,
            TOTP30,
        );
        assert_eq!(one(SOLO, e30), Verdict::Add);
        assert_eq!(OathFamily::Solo2.hard_name_limit(), Some(127));
        assert_eq!(OathFamily::Nitrokey3.hard_name_limit(), None);
    }

    #[test]
    fn yubikey_name_limit_is_whole_name_64() {
        // "Example:" is 8 bytes; 56-byte account = 64 total.
        assert_eq!(one(YK57, simple("Example", &"a".repeat(56))), Verdict::Add);
        assert_eq!(
            one(YK57, simple("Example", &"a".repeat(57))),
            Verdict::Skip(Skip::NameTooLong { len: 65, max: 64 })
        );
        // The period prefix counts too: "60/Example:" + 53 = 64.
        let mk = |n: usize| {
            entry(
                Some("Example"),
                Some(&"a".repeat(n)),
                20,
                HashAlg::Sha1,
                6,
                OtpKind::Totp { period: 60 },
            )
        };
        assert_eq!(one(YK57, mk(53)), Verdict::Add);
        assert_eq!(
            one(YK57, mk(54)),
            Verdict::Skip(Skip::NameTooLong { len: 65, max: 64 })
        );
    }

    #[test]
    fn nitrokey3_skips_non_30s_totp_and_sha512() {
        let e60 = entry(
            Some("A"),
            Some("b"),
            20,
            HashAlg::Sha1,
            6,
            OtpKind::Totp { period: 60 },
        );
        assert_eq!(one(NK3, e60), Verdict::Skip(Skip::PeriodNotStored(60)));
        let e512 = entry(Some("A"), Some("b"), 20, HashAlg::Sha512, 6, TOTP30);
        assert_eq!(one(NK3, e512), Verdict::Skip(Skip::Hash(HashAlg::Sha512)));
        assert_eq!(one(NK3, simple("A", "b")), Verdict::Add);
        let s129 = entry(Some("A"), Some("b"), 129, HashAlg::Sha1, 6, TOTP30);
        assert_eq!(
            one(NK3, s129),
            Verdict::Skip(Skip::SecretLength { len: 129, max: 128 })
        );
    }

    #[test]
    fn solo2_skips_sha512_and_secret_over_64() {
        let e512 = entry(Some("A"), Some("b"), 20, HashAlg::Sha512, 6, TOTP30);
        assert_eq!(one(SOLO, e512), Verdict::Skip(Skip::Hash(HashAlg::Sha512)));
        let s64 = entry(Some("A"), Some("b"), 64, HashAlg::Sha256, 6, TOTP30);
        assert_eq!(one(SOLO, s64), Verdict::Add);
        let s65 = entry(Some("A"), Some("b"), 65, HashAlg::Sha256, 6, TOTP30);
        assert_eq!(
            one(SOLO, s65),
            Verdict::Skip(Skip::SecretLength { len: 65, max: 64 })
        );
        // Any period is fine (prefix), and so is HOTP.
        let e45 = entry(
            Some("A"),
            Some("b"),
            20,
            HashAlg::Sha1,
            6,
            OtpKind::Totp { period: 45 },
        );
        assert_eq!(one(SOLO, e45), Verdict::Add);
    }

    #[test]
    fn yubikey_sha512_allowed_from_4_3_1_and_when_unknown() {
        let yk = |v| Store::Oath(OathFamily::YubiKey { version: v });
        let e = || entry(Some("A"), Some("b"), 20, HashAlg::Sha512, 6, TOTP30);
        assert_eq!(
            one(yk(Some((4, 3, 0))), e()),
            Verdict::Skip(Skip::Hash(HashAlg::Sha512))
        );
        assert_eq!(one(yk(Some((4, 3, 1))), e()), Verdict::Add);
        assert_eq!(one(yk(Some((5, 7, 1))), e()), Verdict::Add);
        assert_eq!(one(yk(None), e()), Verdict::Add);
    }

    #[test]
    fn yubikey_capacity_by_version() {
        let yk = |v| Store::Oath(OathFamily::YubiKey { version: v });
        assert_eq!(limits(yk(Some((5, 7, 1)))).capacity, Some(64));
        assert_eq!(limits(yk(Some((5, 4, 3)))).capacity, Some(32));
        assert_eq!(limits(yk(Some((4, 3, 7)))).capacity, Some(32));
        assert_eq!(limits(yk(None)).capacity, None);

        // 30 on the key (one of them "Example:r"), 5 adds and one replace:
        // 2 fit, 3 have no room; the replace takes none.
        let store = yk(Some((5, 4, 3)));
        let mut names: Vec<StoredName> = (0..29).map(|i| oath(&format!("Old:{}", i))).collect();
        names.push(oath("Example:r"));
        let mut entries = vec![simple("Example", "r")];
        entries.extend((0..5).map(|i| simple("Example", &format!("n{}", i))));
        let p = plan(&file(entries), &target(store, names, true));
        let no_room = Verdict::Skip(Skip::NoRoom { capacity: 32 });
        assert_eq!(
            verdicts(&p),
            vec![
                Verdict::Replace,
                Verdict::Add,
                Verdict::Add,
                no_room.clone(),
                no_room.clone(),
                no_room,
            ]
        );
        assert_eq!(p.capacity, Some(32));
        assert_eq!(p.on_key, 30);
    }

    #[test]
    fn hidden_entries_count_toward_room() {
        let store = Store::Oath(OathFamily::YubiKey {
            version: Some((5, 4, 3)),
        });
        let mut t = target(store, vec![], false);
        t.existing.hidden = 31;
        let p = plan(&file(vec![simple("A", "1"), simple("A", "2")]), &t);
        assert_eq!(p.on_key, 31);
        assert_eq!(
            verdicts(&p),
            vec![Verdict::Add, Verdict::Skip(Skip::NoRoom { capacity: 32 })]
        );
    }

    #[test]
    fn token2_rules() {
        let t2 = Store::Token2Otp;
        assert_eq!(
            one(t2, simple("Exämple", "alice")),
            Verdict::Skip(Skip::NotAscii)
        );
        assert_eq!(
            one(t2, simple("Example", &"a".repeat(65))),
            Verdict::Skip(Skip::NameTooLong { len: 65, max: 64 })
        );
        assert_eq!(
            one(t2, simple(&"E".repeat(65), "a")),
            Verdict::Skip(Skip::NameTooLong { len: 65, max: 64 })
        );
        let hotp = |c| {
            entry(
                Some("A"),
                Some("b"),
                20,
                HashAlg::Sha1,
                6,
                OtpKind::Hotp { counter: c },
            )
        };
        assert_eq!(one(t2, hotp(3)), Verdict::Skip(Skip::Counter(3)));
        assert_eq!(one(t2, hotp(0)), Verdict::Add);
        let e512 = entry(Some("A"), Some("b"), 20, HashAlg::Sha512, 6, TOTP30);
        assert_eq!(one(t2, e512), Verdict::Skip(Skip::Hash(HashAlg::Sha512)));
        for d in [4, 10] {
            assert_eq!(
                one(
                    t2,
                    entry(Some("A"), Some("b"), 20, HashAlg::Sha1, d, TOTP30)
                ),
                Verdict::Add
            );
        }
        assert_eq!(
            one(
                t2,
                entry(Some("A"), Some("b"), 20, HashAlg::Sha1, 3, TOTP30)
            ),
            Verdict::Skip(Skip::Digits(3))
        );
        for p in [1, 65535] {
            let e = entry(
                Some("A"),
                Some("b"),
                20,
                HashAlg::Sha1,
                6,
                OtpKind::Totp { period: p },
            );
            assert_eq!(one(t2, e), Verdict::Add);
        }
        let e = entry(
            Some("A"),
            Some("b"),
            20,
            HashAlg::Sha1,
            6,
            OtpKind::Totp { period: 65536 },
        );
        assert_eq!(one(t2, e), Verdict::Skip(Skip::Period(65536)));
        let s65 = entry(Some("A"), Some("b"), 65, HashAlg::Sha1, 6, TOTP30);
        assert_eq!(
            one(t2, s65),
            Verdict::Skip(Skip::SecretLength { len: 65, max: 64 })
        );
        // Issuer only: account = issuer, app empty.
        let p = plan(
            &file(vec![entry(
                Some("Example"),
                None,
                20,
                HashAlg::Sha1,
                6,
                TOTP30,
            )]),
            &target(t2, vec![], false),
        );
        assert_eq!(
            p.rows[0].name,
            Some(StoredName::Token2 {
                app: String::new(),
                account: "Example".into()
            })
        );
        assert_eq!(limits(t2).capacity, Some(50));
    }

    #[test]
    fn oath_digits_are_6_to_8_on_every_family() {
        for store in [YK57, SOLO, NK3, Store::Oath(OathFamily::Other)] {
            for d in [6, 7, 8] {
                let e = entry(Some("A"), Some("b"), 20, HashAlg::Sha1, d, TOTP30);
                assert_eq!(one(store, e), Verdict::Add, "{store:?} {d}");
            }
            for d in [4, 5, 9, 10] {
                let e = entry(Some("A"), Some("b"), 20, HashAlg::Sha1, d, TOTP30);
                assert_eq!(
                    one(store, e),
                    Verdict::Skip(Skip::Digits(d)),
                    "{store:?} {d}"
                );
            }
        }
    }

    #[test]
    fn oath_counter_must_fit_32_bits() {
        let hotp = |c| {
            entry(
                Some("A"),
                Some("b"),
                20,
                HashAlg::Sha1,
                6,
                OtpKind::Hotp { counter: c },
            )
        };
        assert_eq!(one(YK57, hotp(u64::from(u32::MAX))), Verdict::Add);
        assert_eq!(
            one(YK57, hotp(u64::from(u32::MAX) + 1)),
            Verdict::Skip(Skip::Counter(u64::from(u32::MAX) + 1))
        );
    }

    #[test]
    fn other_oath_has_no_name_or_secret_limit_but_must_fit_one_command() {
        let other = Store::Oath(OathFamily::Other);
        // 200-byte name + 30-byte secret: 2+200+4+30 = 236 fits.
        let e = entry(
            Some("I"),
            Some(&"a".repeat(198)),
            30,
            HashAlg::Sha512,
            6,
            TOTP30,
        );
        assert_eq!(one(other, e), Verdict::Add);
        // 2+230+4+30 = 266 doesn't.
        let e = entry(
            Some("I"),
            Some(&"a".repeat(228)),
            30,
            HashAlg::Sha1,
            6,
            TOTP30,
        );
        assert_eq!(one(other, e), Verdict::Skip(Skip::TooLongForCommand));
        assert_eq!(limits(other).capacity, None);
    }

    #[test]
    fn oath_put_fit_rule() {
        // 2 + 235 + 2 + 2 + 14 = 255.
        assert!(oath_put_fits(235, 1, false));
        assert!(oath_put_fits(235, 14, false));
        assert!(!oath_put_fits(236, 1, false));
        assert!(!oath_put_fits(235, 15, false));
        assert!(oath_put_fits(229, 14, true));
        assert!(!oath_put_fits(230, 14, true));
    }

    #[test]
    fn oath_name_rules() {
        let yk = OathFamily::YubiKey { version: None };
        let mk = |i: Option<&str>, a: Option<&str>, kind| entry(i, a, 20, HashAlg::Sha1, 6, kind);
        assert_eq!(
            oath_name(&mk(Some("Ex"), Some("al"), TOTP30), yk).unwrap(),
            "Ex:al"
        );
        assert_eq!(oath_name(&mk(None, Some("al"), TOTP30), yk).unwrap(), "al");
        assert_eq!(oath_name(&mk(Some("Ex"), None, TOTP30), yk).unwrap(), "Ex");
        assert_eq!(oath_name(&mk(None, None, TOTP30), yk), Err(Skip::NoName));
        assert_eq!(
            oath_name(&mk(Some("E:x"), Some("al"), TOTP30), yk),
            Err(Skip::AmbiguousName)
        );
        assert_eq!(
            oath_name(&mk(None, Some("30/x"), TOTP30), yk),
            Err(Skip::AmbiguousName)
        );
        // An account with ':' after an issuer reads back fine.
        assert_eq!(
            oath_name(&mk(Some("Ex"), Some("a:b"), TOTP30), yk).unwrap(),
            "Ex:a:b"
        );
        // HOTP names never carry a period, so a digits/ account is fine.
        let hotp = OtpKind::Hotp { counter: 0 };
        assert_eq!(
            oath_name(&mk(None, Some("30/x"), hotp), yk).unwrap(),
            "30/x"
        );
        let t60 = OtpKind::Totp { period: 60 };
        assert_eq!(
            oath_name(&mk(Some("Example"), Some("alice"), t60), yk).unwrap(),
            "60/Example:alice"
        );
        assert_eq!(
            oath_name(&mk(Some("Example"), Some("alice"), hotp), yk).unwrap(),
            "Example:alice"
        );
        // A name of the file with no name at all is skipped in the plan.
        assert_eq!(
            one(YK57, mk(None, None, TOTP30)),
            Verdict::Skip(Skip::NoName)
        );
    }

    #[test]
    fn issuer_that_looks_like_a_period_is_ambiguous_at_30s() {
        let mk = |kind| entry(Some("2024/Corp"), Some("bob"), 20, HashAlg::Sha1, 6, kind);
        // "2024/Corp:bob" would read back as a 2024-second code.
        assert_eq!(one(YK57, mk(TOTP30)), Verdict::Skip(Skip::AmbiguousName));
        assert_eq!(one(SOLO, mk(TOTP30)), Verdict::Skip(Skip::AmbiguousName));
        // With a prefix the issuer reads back whole: "60/2024/Corp:bob".
        let p = plan(
            &file(vec![mk(OtpKind::Totp { period: 60 })]),
            &target(YK57, vec![], false),
        );
        assert_eq!(p.rows[0].verdict, Verdict::Add);
        assert_eq!(p.rows[0].name, Some(oath("60/2024/Corp:bob")));
        // HOTP names are never read for a period.
        assert_eq!(one(YK57, mk(OtpKind::Hotp { counter: 0 })), Verdict::Add);
        // Nitrokey 3 doesn't keep the period in the name, so nothing is misread.
        assert_eq!(one(NK3, mk(TOTP30)), Verdict::Add);
        let bare = entry(None, Some("30/x"), 20, HashAlg::Sha1, 6, TOTP30);
        assert_eq!(one(NK3, bare), Verdict::Add);
    }

    #[test]
    fn replace_on_a_full_key_is_not_skipped_for_room() {
        // Nitrokey 3 holds 50: a full key still plans the replace (deleting
        // the old entry frees its place); only the new name has no room.
        let mut names: Vec<StoredName> = (0..49).map(|i| oath(&format!("Old:{}", i))).collect();
        names.push(oath("A:a"));
        let f = file(vec![simple("A", "a"), simple("B", "b")]);
        let p = plan(&f, &target(NK3, names, true));
        assert_eq!(
            verdicts(&p),
            vec![
                Verdict::Replace,
                Verdict::Skip(Skip::NoRoom { capacity: 50 })
            ]
        );
    }

    #[test]
    fn molto_title_is_the_molto2_writers_title() {
        let mk = |i: Option<&str>, a: Option<&str>| entry(i, a, 20, HashAlg::Sha1, 6, TOTP30);
        let title = |e| match plan(&file(vec![e]), &target(Store::Molto2, vec![], false)).rows[0]
            .name
            .clone()
        {
            Some(StoredName::Molto2 { title, .. }) => title,
            other => panic!("{other:?}"),
        };
        // Issuer first, else account; cut to 12 bytes on a character boundary.
        assert_eq!(title(mk(Some("Ünïcödé Company"), Some("x"))), "Ünïcödé ");
        assert_eq!(title(mk(None, Some("alice@example.com"))), "alice@exampl");
    }

    #[test]
    fn same_name_in_file_skips_the_second() {
        let f = file(vec![
            simple("Example", "alice"),
            simple("Other", "x"),
            simple("Example", "alice"),
        ]);
        let p = plan(&f, &target(YK57, vec![], false));
        assert_eq!(
            verdicts(&p),
            vec![
                Verdict::Add,
                Verdict::Add,
                Verdict::Skip(Skip::SameNameInFile { first: 0 })
            ]
        );
        assert_eq!(
            Skip::SameNameInFile { first: 0 }.to_string(),
            "same name as entry #1 in this file"
        );
    }

    #[test]
    fn unusable_items_are_skipped_with_their_reason() {
        let mut f = file(vec![simple("A", "b")]);
        f.items.push(ImportItem {
            index: 1,
            label: "Steam:gamer".into(),
            entry: Err(Unusable::Type("steam".into())),
        });
        let p = plan(&f, &target(YK57, vec![], false));
        assert_eq!(
            p.rows[1].verdict,
            Verdict::Skip(Skip::Unusable(Unusable::Type("steam".into())))
        );
        assert_eq!(p.rows[1].name, None);
        assert_eq!(p.rows[1].label, "Steam:gamer");
    }

    fn molto_target(first_slot: u8, occupied: &[u8], replace: bool) -> Target {
        Target {
            store: Store::Molto2,
            first_slot,
            existing: Existing {
                names: occupied
                    .iter()
                    .map(|&slot| StoredName::Molto2 {
                        slot,
                        title: String::new(),
                    })
                    .collect(),
                hidden: 0,
            },
            replace,
        }
    }

    #[test]
    fn molto_slots_assign_consecutively_and_past_99_is_skipped() {
        let hotp = entry(
            Some("H"),
            Some("x"),
            20,
            HashAlg::Sha1,
            6,
            OtpKind::Hotp { counter: 0 },
        );
        let f = file(vec![
            simple("Example Company", "a"),
            hotp,
            simple("B", "b"),
            simple("C", "c"),
        ]);
        let p = plan(&f, &molto_target(98, &[], false));
        assert_eq!(
            verdicts(&p),
            vec![
                Verdict::Add,
                Verdict::Skip(Skip::Hotp),
                Verdict::Add,
                Verdict::Skip(Skip::PastLastSlot)
            ]
        );
        assert_eq!(
            p.rows[0].name,
            Some(StoredName::Molto2 {
                slot: 98,
                title: "Example Comp".into()
            })
        );
        assert_eq!(
            p.rows[0].name.as_ref().unwrap().to_string(),
            "#98 Example Comp"
        );
        assert_eq!(
            p.rows[2].name,
            Some(StoredName::Molto2 {
                slot: 99,
                title: "B".into()
            })
        );
        assert_eq!(p.capacity, Some(2));
    }

    /// The one Molto2 plan the CLI and the GUI both make: `plan` for the
    /// Molto2 from `first_slot`, never asking to replace by name (slots in
    /// use are always replaced).
    #[test]
    fn molto_plan_is_the_molto2_target() {
        let totp = |issuer: &str, period: u32| {
            entry(
                Some(issuer),
                Some("a"),
                20,
                HashAlg::Sha1,
                6,
                OtpKind::Totp { period },
            )
        };
        let f = file(vec![totp("A", 30), totp("B", 60), totp("C", 45)]);
        for replace in [false, true] {
            let mut t = molto_target(98, &[99], replace);
            let got = molto_plan(&f, 98, t.existing.clone());
            t.replace = false;
            assert_eq!(got, plan(&f, &t));
        }
        let p = molto_plan(&f, 98, molto_target(98, &[99], false).existing);
        let verdicts: Vec<&str> = p.rows.iter().map(|r| r.verdict.word()).collect();
        assert_eq!(verdicts, ["add", "replace", "skip"]);
    }

    #[test]
    fn molto_occupied_slot_is_replace_regardless_of_overwrite() {
        for replace in [false, true] {
            let f = file(vec![simple("A", "a"), simple("B", "b")]);
            let p = plan(&f, &molto_target(10, &[11], replace));
            assert_eq!(verdicts(&p), vec![Verdict::Add, Verdict::Replace]);
            assert_eq!(p.notes, vec![Note::MoltoReplacesSlots]);
        }
    }

    #[test]
    fn molto_rules() {
        let m = |e| one(Store::Molto2, e);
        for d in [4, 6, 8, 10] {
            assert_eq!(
                m(entry(Some("A"), None, 20, HashAlg::Sha1, d, TOTP30)),
                Verdict::Add
            );
        }
        for d in [5, 7, 9] {
            assert_eq!(
                m(entry(Some("A"), None, 20, HashAlg::Sha1, d, TOTP30)),
                Verdict::Skip(Skip::Digits(d))
            );
        }
        let t = |p| OtpKind::Totp { period: p };
        assert_eq!(
            m(entry(Some("A"), None, 20, HashAlg::Sha256, 6, t(60))),
            Verdict::Add
        );
        assert_eq!(
            m(entry(Some("A"), None, 20, HashAlg::Sha1, 6, t(45))),
            Verdict::Skip(Skip::Period(45))
        );
        assert_eq!(
            m(entry(Some("A"), None, 63, HashAlg::Sha1, 6, TOTP30)),
            Verdict::Add
        );
        assert_eq!(
            m(entry(Some("A"), None, 64, HashAlg::Sha1, 6, TOTP30)),
            Verdict::Skip(Skip::SecretLength { len: 64, max: 63 })
        );
        assert_eq!(
            m(entry(None, None, 20, HashAlg::Sha1, 6, TOTP30)),
            Verdict::Skip(Skip::NoName)
        );
    }

    #[test]
    fn notes_table() {
        let hotp = || {
            entry(
                Some("H"),
                Some("x"),
                20,
                HashAlg::Sha1,
                6,
                OtpKind::Hotp { counter: 0 },
            )
        };
        let f = || file(vec![simple("A", "a")]);
        let a = || vec![oath("A:a")];

        // ReplaceMayLoseOld: Solo 2, Nitrokey 3, other OATH; not YubiKey.
        for store in [SOLO, NK3, Store::Oath(OathFamily::Other)] {
            let p = plan(&f(), &target(store, a(), true));
            assert!(p.notes.contains(&Note::ReplaceMayLoseOld), "{store:?}");
        }
        let p = plan(&f(), &target(YK57, a(), true));
        assert_eq!(p.notes, vec![]);
        // Without a replace row, no replace notes.
        let p = plan(&f(), &target(NK3, a(), false));
        assert_eq!(p.notes, vec![]);

        // CapacityUnknown: Solo 2, other OATH, YubiKey of unknown version.
        let p = plan(&f(), &target(SOLO, vec![], false));
        assert_eq!(p.notes, vec![Note::CapacityUnknown]);
        let p = plan(&f(), &target(Store::Molto2, vec![], false));
        assert_eq!(p.notes, vec![]);

        // Solo2Hotp only when a HOTP row writes to a Solo 2.
        let p = plan(&file(vec![hotp()]), &target(SOLO, vec![], false));
        assert!(p.notes.contains(&Note::Solo2Hotp));
        let p = plan(&file(vec![hotp()]), &target(SOLO, vec![oath("H:x")], false));
        assert!(!p.notes.contains(&Note::Solo2Hotp));
        let p = plan(&file(vec![hotp()]), &target(YK57, vec![], false));
        assert!(!p.notes.contains(&Note::Solo2Hotp));

        // Nitrokey3TouchToReplace.
        let p = plan(&f(), &target(NK3, a(), true));
        assert_eq!(
            p.notes,
            vec![Note::ReplaceMayLoseOld, Note::Nitrokey3TouchToReplace]
        );

        // Hidden.
        let mut t = target(NK3, vec![], false);
        t.existing.hidden = 2;
        assert_eq!(plan(&f(), &t).notes, vec![Note::Hidden(2)]);

        // MoltoReplacesSlots only with an occupied slot written.
        assert_eq!(
            plan(&f(), &molto_target(0, &[0], false)).notes,
            vec![Note::MoltoReplacesSlots]
        );
        assert_eq!(plan(&f(), &molto_target(0, &[1], false)).notes, vec![]);
    }

    #[test]
    fn counts_and_writes() {
        let f = file(vec![
            simple("A", "a"),
            simple("B", "b"),
            simple("C", "c"),
            entry(Some("D"), Some("d"), 20, HashAlg::Sha1, 4, TOTP30),
        ]);
        let p = plan(&f, &target(YK57, vec![oath("A:a"), oath("B:b")], false));
        let mut t = target(YK57, vec![oath("A:a")], true);
        t.existing.names.push(oath("B:b"));
        let q = plan(&f, &t);
        assert_eq!(
            p.counts(),
            Counts {
                add: 1,
                replace: 0,
                exists: 2,
                skip: 1
            }
        );
        assert_eq!(q.counts().replace, 2);
        assert_eq!(
            q.writes().map(|r| r.index).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
    }

    #[test]
    fn from_vendor_maps_families() {
        assert_eq!(
            OathFamily::from_vendor("Yubico", Some((5, 7, 1))),
            OathFamily::YubiKey {
                version: Some((5, 7, 1))
            }
        );
        assert_eq!(OathFamily::from_vendor("SoloKeys", None), OathFamily::Solo2);
        assert_eq!(
            OathFamily::from_vendor("Nitrokey", None),
            OathFamily::Nitrokey3
        );
        assert_eq!(OathFamily::from_vendor("Token2", None), OathFamily::Other);
        assert_eq!(OathFamily::YubiKey { version: None }.name_limit(), Some(64));
        assert_eq!(OathFamily::Solo2.name_limit(), Some(127));
        assert_eq!(OathFamily::Nitrokey3.name_limit(), Some(128));
        assert_eq!(OathFamily::Other.name_limit(), None);
    }

    #[test]
    fn verdict_words_and_reasons_are_one_vocabulary() {
        let words: Vec<&str> = [
            Verdict::Add,
            Verdict::Replace,
            Verdict::Exists,
            Verdict::Skip(Skip::NoName),
        ]
        .iter()
        .map(Verdict::word)
        .collect();
        assert_eq!(words, ["add", "replace", "exists", "skip"]);
        assert_eq!(Verdict::Add.reason(YK57), None);
        assert_eq!(
            Verdict::Replace.reason(YK57).as_deref(),
            Some("replaces the code of the same name on the key")
        );
        assert_eq!(
            Verdict::Replace.reason(Store::Molto2).as_deref(),
            Some("replaces the code in this slot")
        );
        assert_eq!(
            Verdict::Exists.reason(YK57).as_deref(),
            Some("already on the key; left as is")
        );
        assert_eq!(
            Note::Nitrokey3TouchToReplace.to_string(),
            "A Nitrokey 3 may ask for a touch for each code it replaces."
        );
        assert_eq!(
            Note::MoltoReplacesSlots.to_string(),
            "Slots already in use will be replaced."
        );
        let row = |name| PlanRow {
            index: 0,
            label: "GitHub".into(),
            name,
            verdict: Verdict::Add,
        };
        assert_eq!(
            row(Some(StoredName::Molto2 {
                slot: 5,
                title: "GitHub".into()
            }))
            .shown_label(),
            "#05 GitHub"
        );
        assert_eq!(row(Some(oath("GitHub"))).shown_label(), "GitHub");
        assert_eq!(row(None).shown_label(), "GitHub");
    }

    #[test]
    fn stored_name_display() {
        assert_eq!(oath("60/Example:alice").to_string(), "60/Example:alice");
        let t = |a: &str, b: &str| StoredName::Token2 {
            app: a.into(),
            account: b.into(),
        };
        assert_eq!(t("Example", "alice").to_string(), "Example:alice");
        assert_eq!(t("", "alice").to_string(), "alice");
        let m = StoredName::Molto2 {
            slot: 95,
            title: "Example".into(),
        };
        assert_eq!(m.to_string(), "#95 Example");
    }

    fn all_skips() -> Vec<Skip> {
        vec![
            Skip::Unusable(Unusable::BadSecret),
            Skip::NoName,
            Skip::NameTooLong { len: 128, max: 127 },
            Skip::NotAscii,
            Skip::AmbiguousName,
            Skip::Hash(HashAlg::Sha512),
            Skip::Digits(10),
            Skip::Period(45),
            Skip::PeriodNotStored(60),
            Skip::Hotp,
            Skip::Counter(3),
            Skip::SecretLength { len: 65, max: 64 },
            Skip::TooLongForCommand,
            Skip::SameNameInFile { first: 2 },
            Skip::NoRoom { capacity: 32 },
            Skip::PastLastSlot,
            Skip::StartsAnotherName,
        ]
    }

    #[test]
    fn unusable_and_skip_display_is_plain() {
        let stores = [
            YK57,
            SOLO,
            NK3,
            Store::Oath(OathFamily::Other),
            Store::Token2Otp,
            Store::Molto2,
        ];
        for store in stores {
            for s in all_skips() {
                let text = s.reason(store);
                let lower = text.to_ascii_lowercase();
                for bad in ["error", "invalid", "sw ", "6a", "69", "0x", "overwrite"] {
                    assert!(!lower.contains(bad), "{store:?} {s:?}: {text}");
                }
                assert!(!text.is_empty());
            }
        }
        // The device family is named where it matters.
        assert_eq!(
            Skip::Hash(HashAlg::Sha512).reason(SOLO),
            "Solo 2 doesn't take SHA-512 codes"
        );
        assert_eq!(
            Skip::Digits(10).reason(YK57),
            "YubiKey can't store 10-digit codes"
        );
        assert!(Skip::NameTooLong { len: 128, max: 127 }
            .reason(SOLO)
            .contains("Solo 2"));
        assert!(Skip::PeriodNotStored(60).reason(NK3).contains("Nitrokey 3"));
        assert!(Skip::NoRoom { capacity: 50 }
            .reason(NK3)
            .contains("Nitrokey 3 holds 50"));
        assert!(Skip::Counter(3).reason(Store::Token2Otp).contains("Token2"));
        assert!(Skip::Hotp.reason(Store::Molto2).contains("Molto2"));
        assert_eq!(
            Skip::NotAscii.reason(Store::Token2Otp),
            "this Token2 key stores names in plain ASCII characters only, and this name has others"
        );
        // Without a destination, the device is "this key".
        assert_eq!(
            Skip::Digits(10).to_string(),
            "this key can't store 10-digit codes"
        );
        for n in [
            Note::ReplaceMayLoseOld,
            Note::CapacityUnknown,
            Note::Solo2Hotp,
            Note::Nitrokey3TouchToReplace,
            Note::Hidden(2),
            Note::MoltoReplacesSlots,
        ] {
            let lower = n.to_string().to_ascii_lowercase();
            assert!(
                !lower.contains("error") && !lower.contains("overwrite"),
                "{n:?}"
            );
        }
    }
}
