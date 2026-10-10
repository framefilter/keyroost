//! Plaintext bulk-import parsers for Aegis, 2FAS, and generic otpauth:// lists.
//!
//! All three parsers normalize to `Vec<BulkEntry>`. Encrypted vaults are not
//! supported in v1 — the user must export plaintext from their authenticator.

use keyroost_proto::commands::{DisplayTimeout, HmacAlgo, OtpDigits, ProfileConfig, TimeStep};
use serde::Deserialize;

use crate::entry::{
    decode_secret, finish, hash_from_name, name_label, type_from_name, Format, ImportEntry,
    ImportFile, ImportItem, OtpKind, TypeName, Unusable, MAX_ENTRIES,
};
use crate::otpauth::{parse as parse_otpauth, OtpAuth, OtpAuthError};

/// One normalized entry ready to be programmed into a Molto2 profile slot.
#[derive(Clone)]
pub struct BulkEntry {
    pub issuer: Option<String>,
    pub account: Option<String>,
    pub secret: Vec<u8>,
    pub algorithm: HmacAlgo,
    pub digits: OtpDigits,
    pub time_step: TimeStep,
}

/// Manual Debug so a stray `{:?}` in logs or error context can't print the
/// seed; only its length is shown.
impl std::fmt::Debug for BulkEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BulkEntry")
            .field("issuer", &self.issuer)
            .field("account", &self.account)
            .field("secret", &format_args!("[{} bytes]", self.secret.len()))
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("time_step", &self.time_step)
            .finish()
    }
}

/// Imported seeds are wiped when the entry is dropped — these are the
/// highest-value secrets the tool touches, often dozens at once from a
/// vault or QR batch.
impl Drop for BulkEntry {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret.zeroize();
    }
}

impl BulkEntry {
    pub fn suggested_title(&self) -> String {
        crate::entry::molto_title(self.issuer.as_deref(), self.account.as_deref())
    }

    pub fn to_profile_config(
        &self,
        utc_time: u32,
        display_timeout: DisplayTimeout,
    ) -> ProfileConfig {
        ProfileConfig {
            display_timeout,
            algorithm: self.algorithm,
            digits: self.digits,
            time_step: self.time_step,
            utc_time,
        }
    }
}

impl From<OtpAuth> for BulkEntry {
    fn from(mut p: OtpAuth) -> Self {
        // `take` rather than move: OtpAuth has a zeroizing Drop, so its
        // fields can't be moved out directly. The secret buffer itself is
        // moved (not copied), keeping a single wipeable allocation.
        BulkEntry {
            issuer: p.issuer.take(),
            account: p.account.take(),
            secret: std::mem::take(&mut p.secret),
            algorithm: p.algorithm,
            digits: p.digits,
            time_step: p.time_step,
        }
    }
}

#[non_exhaustive]
#[derive(Debug)]
pub enum BulkError {
    Json(serde_json::Error),
    Encrypted(&'static str),
    UnsupportedFormat(&'static str),
    EntryRejected {
        index: usize,
        reason: OtpAuthError,
    },
    EmptyFile,
    /// More than [`MAX_ENTRIES`] entries (wide
    /// readers only): not an authenticator export.
    TooManyEntries,
    /// An encrypted Aegis vault that no password slot opened with the
    /// password given.
    WrongPassword,
}

impl core::fmt::Display for BulkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BulkError::Json(e) => write!(f, "JSON parse error: {}", e),
            BulkError::Encrypted(msg) => write!(f, "encrypted vault: {}", msg),
            BulkError::UnsupportedFormat(msg) => write!(f, "unsupported format: {}", msg),
            BulkError::EntryRejected { index, reason } => {
                write!(f, "entry #{}: {}", index, reason)
            }
            BulkError::EmptyFile => write!(f, "no entries found"),
            BulkError::TooManyEntries => write!(
                f,
                "more than {} entries; this isn't an authenticator export",
                crate::entry::MAX_ENTRIES
            ),
            // Same text the decryptor reported before this had its own
            // variant, so CLI output is unchanged.
            BulkError::WrongPassword => {
                write!(
                    f,
                    "unsupported format: wrong password (slot did not decrypt)"
                )
            }
        }
    }
}

impl std::error::Error for BulkError {}

impl BulkError {
    /// A sentence for a person, naming `layout` (e.g. "an Aegis export")
    /// when the file's JSON doesn't fit it. Never quotes a value from the
    /// file: serde's own messages can (`invalid type: string "…"`), so a
    /// JSON problem is told by position, keeping only a missing or repeated
    /// field's name, which comes from keyroost's schema.
    pub fn describe(&self, layout: &str) -> String {
        use serde_json::error::Category;
        let BulkError::Json(j) = self else {
            let text = self.to_string();
            let mut c = text.chars();
            return match c.next() {
                Some(first) => format!("{}{}.", first.to_uppercase(), c.as_str()),
                None => String::new(),
            };
        };
        let at = format!("line {}, column {}", j.line(), j.column());
        match j.classify() {
            Category::Syntax | Category::Eof => format!("The file isn't valid JSON ({}).", at),
            Category::Io => "The file couldn't be read.".to_owned(),
            Category::Data => {
                let text = j.to_string();
                let field = ["missing field `", "duplicate field `"]
                    .iter()
                    .find_map(|prefix| {
                        let name = text.strip_prefix(prefix)?.split('`').next()?;
                        let schema_like = !name.is_empty()
                            && name.len() <= 32
                            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
                        schema_like.then(|| format!(": {}`{}`", prefix.trim_end_matches('`'), name))
                    })
                    .unwrap_or_default();
                format!(
                    "The file doesn't match the layout of {}{} ({}).",
                    layout, field, at
                )
            }
        }
    }
}

impl From<serde_json::Error> for BulkError {
    fn from(e: serde_json::Error) -> Self {
        BulkError::Json(e)
    }
}

/// Aegis plaintext export (`db.entries[]`). Encrypted vaults set `db: string`
/// instead of `db: object` — we detect that and reject.
pub mod aegis {
    use super::*;

    // The JSON shape is shared by the narrow (Molto2) and wide mappings; only
    // the per-entry `info` differs (`EntryInfo` vs `CounterOnly`), so that the
    // narrow path deserializes exactly the fields it always did.
    #[derive(Deserialize)]
    struct Root<I> {
        db: DbField<I>,
    }

    /// The `db` field: a plaintext object (parsed straight into [`Db`]) or, for
    /// an encrypted vault, a base64 string we reject.
    ///
    /// Deserialized manually via `deserialize_any` so it dispatches on the JSON
    /// token type directly — the plaintext entries land in the zeroize-on-drop
    /// `Db`/`EntryInfo` without ever transiting a `serde_json::Value` tree
    /// (whose `String` seeds would otherwise drop unscrubbed).
    enum DbField<I> {
        Plain(Db<I>),
        Encrypted,
    }

    impl<'de, I: Deserialize<'de>> serde::Deserialize<'de> for DbField<I> {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            use serde::de::{self, MapAccess, Visitor};
            struct V<I>(std::marker::PhantomData<I>);
            impl<'de, I: Deserialize<'de>> Visitor<'de> for V<I> {
                type Value = DbField<I>;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("an Aegis db object or an encrypted base64 string")
                }
                fn visit_str<E: de::Error>(self, _v: &str) -> Result<DbField<I>, E> {
                    // The encrypted blob is not a secret and is not retained.
                    Ok(DbField::Encrypted)
                }
                fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<DbField<I>, A::Error> {
                    Db::deserialize(de::value::MapAccessDeserializer::new(map)).map(DbField::Plain)
                }
            }
            d.deserialize_any(V(std::marker::PhantomData))
        }
    }

    #[derive(Deserialize)]
    struct Db<I> {
        entries: Vec<Entry<I>>,
    }

    #[derive(Deserialize)]
    struct Entry<I> {
        #[serde(rename = "type")]
        typ: String,
        name: Option<String>,
        issuer: Option<String>,
        info: I,
    }

    /// What the Molto2 path reads of an entry's `info`.
    #[derive(Deserialize)]
    struct EntryInfo {
        secret: String,
        algo: Option<String>,
        digits: Option<u32>,
        period: Option<u32>,
    }

    // `build_entry` copies the seed into a zeroize-on-drop `BulkEntry`; wipe
    // the serde-owned original too so it doesn't linger in freed memory.
    impl Drop for EntryInfo {
        fn drop(&mut self) {
            use zeroize::Zeroize;
            self.secret.zeroize();
        }
    }

    /// How many entries a plaintext export holds, counted without
    /// materializing any of them; `None` when the shape isn't a plaintext
    /// Aegis export (the full parse then reports why).
    fn count_entries(json: &str) -> Option<usize> {
        #[derive(Deserialize)]
        struct P {
            db: PDb,
        }
        #[derive(Deserialize)]
        struct PDb {
            entries: super::Count,
        }
        serde_json::from_str::<P>(json).ok().map(|p| p.db.entries.0)
    }

    /// Read the plaintext `db`, or the encrypted-vault error. Shared by the
    /// narrow (Molto2) and wide mappings.
    fn read_db<I: serde::de::DeserializeOwned>(json: &str) -> Result<Db<I>, BulkError> {
        let root: Root<I> = serde_json::from_str(json)?;
        match root.db {
            DbField::Plain(db) => Ok(db),
            DbField::Encrypted => {
                #[cfg(feature = "encrypted")]
                let msg = "Aegis export is encrypted; supply a password (CLI: --file-password env:NAME or --file-password stdin)";
                #[cfg(not(feature = "encrypted"))]
                let msg = "Aegis export is encrypted; build with --features encrypted or re-export plaintext";
                Err(BulkError::Encrypted(msg))
            }
        }
    }

    pub fn parse(json: &str) -> Result<Vec<BulkEntry>, BulkError> {
        let db = read_db::<EntryInfo>(json)?;
        let mut out = Vec::with_capacity(db.entries.len());
        for (i, e) in db.entries.into_iter().enumerate() {
            if !e.typ.eq_ignore_ascii_case("totp") {
                continue; // skip HOTP / Steam / other types
            }
            let entry = build_entry(
                i,
                e.issuer,
                e.name,
                &e.info.secret,
                e.info.algo.as_deref(),
                e.info.digits.unwrap_or(6),
                e.info.period.unwrap_or(30),
            )?;
            out.push(entry);
        }
        if out.is_empty() {
            return Err(BulkError::EmptyFile);
        }
        Ok(out)
    }

    /// Every entry of a plaintext Aegis export, in file order, each either
    /// usable by some key or marked with why not. Whole-file errors: bad
    /// JSON, an encrypted vault (decrypt first), or no entries at all.
    pub fn parse_wide(json: &str) -> Result<ImportFile, BulkError> {
        if count_entries(json).is_some_and(|n| n > MAX_ENTRIES) {
            return Err(BulkError::TooManyEntries);
        }
        // Two reads: the Molto2 path's fields exactly as it reads them, then
        // each entry's `counter` on its own (see `CounterOnly`).
        let db = read_db::<EntryInfo>(json)?;
        let counters = read_db::<super::CounterOnly>(json)?;
        let items: Vec<ImportItem> = db
            .entries
            .into_iter()
            .zip(counters.entries)
            .enumerate()
            .map(|(i, (e, c))| {
                let label = name_label(e.issuer.as_deref(), e.name.as_deref())
                    .unwrap_or_else(|| format!("entry {}", i + 1));
                let entry = wide_entry(
                    &e.typ,
                    e.issuer.clone(),
                    e.name.clone(),
                    &e.info.secret,
                    e.info.algo.as_deref(),
                    e.info.digits.unwrap_or(6),
                    e.info.period.unwrap_or(30),
                    c.info,
                );
                ImportItem {
                    index: i,
                    label,
                    entry,
                }
            })
            .collect();
        if items.is_empty() {
            return Err(BulkError::EmptyFile);
        }
        Ok(ImportFile {
            format: Format::Aegis,
            items,
            batch: None,
        })
    }

    /// Detect an encrypted Aegis vault without parsing the whole structure.
    /// `Ok(true)` means an `encrypted` decrypt is needed; `Ok(false)` means
    /// the file is already plaintext. Cheap and side-effect-free: the `db`
    /// object is drained with `IgnoredAny`, so — unlike `parse()` — no entry
    /// (and no seed string) is ever materialized just to answer a bool.
    pub fn is_encrypted(json: &str) -> Result<bool, BulkError> {
        #[derive(Deserialize)]
        struct ProbeRoot {
            db: DbProbe,
        }
        enum DbProbe {
            Plain,
            Encrypted,
        }
        impl<'de> serde::Deserialize<'de> for DbProbe {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                use serde::de::{self, IgnoredAny, MapAccess, Visitor};
                struct V;
                impl<'de> Visitor<'de> for V {
                    type Value = DbProbe;
                    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                        f.write_str("an Aegis db object or an encrypted base64 string")
                    }
                    fn visit_str<E: de::Error>(self, _v: &str) -> Result<DbProbe, E> {
                        Ok(DbProbe::Encrypted)
                    }
                    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<DbProbe, A::Error> {
                        // Drain token-by-token without allocating anything.
                        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                        Ok(DbProbe::Plain)
                    }
                }
                d.deserialize_any(V)
            }
        }
        let root: ProbeRoot = serde_json::from_str(json)?;
        Ok(matches!(root.db, DbProbe::Encrypted))
    }

    /// Whether `json` has the full shape of an encrypted Aegis vault: a
    /// `version`, a `header` with a `slots` array and a `params` object, and
    /// a string `db`. Stricter than [`is_encrypted`], which only looks at
    /// `db`, so an unrelated JSON file with a string `db` isn't taken for a
    /// vault. Nothing is materialized.
    pub(crate) fn has_vault_shape(json: &str) -> bool {
        use serde::de::IgnoredAny;
        /// Accepts any JSON object (fields ignored); refuses null and
        /// non-objects.
        #[derive(Deserialize)]
        struct AnyObject {}
        #[derive(Deserialize)]
        struct Header {
            #[allow(dead_code)]
            slots: super::Count,
            #[allow(dead_code)]
            params: AnyObject,
        }
        #[derive(Deserialize)]
        struct Vault {
            #[allow(dead_code)]
            version: IgnoredAny,
            #[allow(dead_code)]
            header: Header,
        }
        serde_json::from_str::<Vault>(json).is_ok() && matches!(is_encrypted(json), Ok(true))
    }

    /// Decrypt an Aegis encrypted vault and return the inner plaintext JSON,
    /// which can then be passed back to `parse()`. The returned buffer wipes
    /// itself on drop. Requires the `encrypted` crate feature.
    #[cfg(feature = "encrypted")]
    pub fn decrypt(json: &str, password: &[u8]) -> Result<zeroize::Zeroizing<String>, BulkError> {
        crate::encrypted::decrypt_aegis(json, password)
    }
}

/// 2FAS plaintext export (`services[]`). The encrypted variant has a top-level
/// `servicesEncrypted` string — we detect and reject.
pub mod twofas {
    use super::*;

    // As for Aegis, the shape is shared and only `otp` differs between the
    // narrow (`Otp`) and counter (`CounterOnly`) reads.
    #[derive(Deserialize)]
    #[serde(bound(deserialize = "O: Deserialize<'de> + Default"))]
    struct Root<O> {
        #[serde(default = "Vec::new")]
        services: Vec<Service<O>>,
        #[serde(rename = "servicesEncrypted", default)]
        services_encrypted: Option<String>,
    }

    #[derive(Deserialize)]
    struct Service<O> {
        name: Option<String>,
        secret: String,
        #[serde(default)]
        otp: O,
    }

    // Same hygiene as the Aegis `EntryInfo`: wipe the serde-owned seed copy.
    impl<O> Drop for Service<O> {
        fn drop(&mut self) {
            use zeroize::Zeroize;
            self.secret.zeroize();
        }
    }

    #[derive(Deserialize, Default)]
    struct Otp {
        account: Option<String>,
        issuer: Option<String>,
        digits: Option<u32>,
        period: Option<u32>,
        algorithm: Option<String>,
        #[serde(rename = "tokenType")]
        token_type: Option<String>,
    }

    /// Whether `json` looks like a 2FAS export, without materializing any
    /// service (or seed): `Some(true)` for an encrypted export (the
    /// `servicesEncrypted` blob and no plaintext services), `Some(false)`
    /// for a plaintext one, `None` when it is neither (or not a JSON object).
    pub(crate) fn probe(json: &str) -> Option<bool> {
        use serde::de::IgnoredAny;
        #[derive(Deserialize)]
        struct ProbeRoot {
            services: Option<super::Count>,
            #[serde(rename = "servicesEncrypted")]
            services_encrypted: Option<IgnoredAny>,
        }
        let root: ProbeRoot = serde_json::from_str(json).ok()?;
        let services = root.services.map(|c| c.0);
        match (services, root.services_encrypted.is_some()) {
            (None, false) => None,
            (Some(n), true) if n > 0 => Some(false),
            (_, true) => Some(true),
            (Some(_), false) => Some(false),
        }
    }

    /// How many services the export lists, counted without materializing
    /// any; `None` when it has no `services` array.
    fn count_services(json: &str) -> Option<usize> {
        #[derive(Deserialize)]
        struct P {
            services: super::Count,
        }
        serde_json::from_str::<P>(json).ok().map(|p| p.services.0)
    }

    /// The counter pass over `services`: each service's `otp` counter and
    /// nothing else — the seed (`secret`) and every other key are skipped
    /// unread, so no second copy of any seed is made.
    #[derive(Deserialize)]
    struct CounterRoot {
        #[serde(default = "Vec::new")]
        services: Vec<CounterService>,
    }

    #[derive(Deserialize)]
    struct CounterService {
        #[serde(default)]
        otp: super::CounterOnly,
    }

    /// Read the plaintext `services`, or the encrypted-export error.
    fn read_root<O: serde::de::DeserializeOwned + Default>(
        json: &str,
    ) -> Result<Root<O>, BulkError> {
        let root: Root<O> = serde_json::from_str(json)?;
        if root.services_encrypted.is_some() && root.services.is_empty() {
            return Err(BulkError::Encrypted(
                "2FAS export is encrypted; re-export without a password",
            ));
        }
        Ok(root)
    }

    pub fn parse(json: &str) -> Result<Vec<BulkEntry>, BulkError> {
        let root = read_root::<Otp>(json)?;
        let mut out = Vec::with_capacity(root.services.len());
        for (i, mut s) in root.services.into_iter().enumerate() {
            // 2FAS includes Steam etc; skip non-TOTP.
            if let Some(tt) = s.otp.token_type.as_deref() {
                if !tt.eq_ignore_ascii_case("TOTP") {
                    continue;
                }
            }
            // `take()` rather than move — `Service` has a Drop impl (it wipes
            // the seed), and Rust forbids moving fields out past one.
            let entry = build_entry(
                i,
                s.otp.issuer.take().or(s.name.take()),
                s.otp.account.take(),
                &s.secret,
                s.otp.algorithm.as_deref(),
                s.otp.digits.unwrap_or(6),
                s.otp.period.unwrap_or(30),
            )?;
            out.push(entry);
        }
        if out.is_empty() {
            return Err(BulkError::EmptyFile);
        }
        Ok(out)
    }

    /// Every service of a plaintext 2FAS export, in file order (see
    /// [`aegis::parse_wide`] for the contract).
    pub fn parse_wide(json: &str) -> Result<ImportFile, BulkError> {
        if count_services(json).is_some_and(|n| n > MAX_ENTRIES) {
            return Err(BulkError::TooManyEntries);
        }
        // As for Aegis: the Molto2 path's fields, then the counters alone.
        let root = read_root::<Otp>(json)?;
        let counters: CounterRoot = serde_json::from_str(json)?;
        let items: Vec<ImportItem> = root
            .services
            .iter()
            .zip(&counters.services)
            .enumerate()
            .map(|(i, (s, c))| {
                // Same issuer rule as the narrow mapping: the otp issuer,
                // else the service name.
                let issuer = s.otp.issuer.clone().or_else(|| s.name.clone());
                let label = name_label(issuer.as_deref(), s.otp.account.as_deref())
                    .unwrap_or_else(|| format!("entry {}", i + 1));
                let entry = wide_entry(
                    s.otp.token_type.as_deref().unwrap_or("TOTP"),
                    issuer,
                    s.otp.account.clone(),
                    &s.secret,
                    s.otp.algorithm.as_deref(),
                    s.otp.digits.unwrap_or(6),
                    s.otp.period.unwrap_or(30),
                    c.otp,
                );
                ImportItem {
                    index: i,
                    label,
                    entry,
                }
            })
            .collect();
        if items.is_empty() {
            return Err(BulkError::EmptyFile);
        }
        Ok(ImportFile {
            format: Format::TwoFas,
            items,
            batch: None,
        })
    }
}

/// Number of elements in a JSON array, drained without allocating (the
/// elements are skipped with `IgnoredAny`; nothing is materialized).
pub(crate) struct Count(pub(crate) usize);

impl<'de> Deserialize<'de> for Count {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::{IgnoredAny, SeqAccess, Visitor};
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Count;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a JSON array")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Count, A::Error> {
                let mut n = 0;
                while a.next_element::<IgnoredAny>()?.is_some() {
                    n += 1;
                }
                Ok(Count(n))
            }
        }
        d.deserialize_seq(V)
    }
}

/// One otpauth:// URI per line; blank lines and `#` comments allowed. Useful
/// for Authy exports done with third-party scripts that emit URI lists.
pub fn parse_otpauth_list(text: &str) -> Result<Vec<BulkEntry>, BulkError> {
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parsed =
            parse_otpauth(line).map_err(|reason| BulkError::EntryRejected { index: i, reason })?;
        out.push(parsed.into());
    }
    if out.is_empty() {
        return Err(BulkError::EmptyFile);
    }
    Ok(out)
}

/// One entry per line, like [`parse_otpauth_list`], but nothing a line
/// holds fails the file: each non-blank, non-`#` line becomes an item (index
/// = line index), unusable lines carrying their reason. A Google
/// Authenticator `otpauth-migration://` line contributes all of its entries
/// under that line's index. Whole-file errors: an empty list, or more than
/// [`MAX_ENTRIES`] entries.
pub fn parse_list_wide(text: &str) -> Result<ImportFile, BulkError> {
    let mut items = Vec::new();
    let mut batch = None;
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Refuse before building the next item, so a giant file never
        // grows the list past the cap.
        if items.len() >= MAX_ENTRIES {
            return Err(BulkError::TooManyEntries);
        }
        if crate::migration::is_migration_uri(line) {
            match crate::migration::parse_wide(line) {
                Err(e @ BulkError::TooManyEntries) => return Err(e),
                Ok(file) => {
                    if items.len() + file.items.len() > MAX_ENTRIES {
                        return Err(BulkError::TooManyEntries);
                    }
                    batch = batch.or(file.batch);
                    items.extend(file.items.into_iter().map(|mut item| {
                        item.index = i;
                        item
                    }));
                }
                Err(_) => items.push(ImportItem {
                    index: i,
                    label: format!("line {}", i + 1),
                    entry: Err(Unusable::Malformed(
                        "the Google Authenticator export couldn't be read",
                    )),
                }),
            }
            continue;
        }
        let (name, entry) = crate::otpauth::parse_entry_labeled(line);
        items.push(ImportItem {
            index: i,
            label: name.unwrap_or_else(|| format!("line {}", i + 1)),
            entry,
        });
    }
    if items.is_empty() {
        return Err(BulkError::EmptyFile);
    }
    Ok(ImportFile {
        format: Format::OtpauthList,
        items,
        batch,
    })
}

/// The wide counterpart of [`parse_any`]: JSON goes to Aegis (an encrypted
/// vault is reported as such), then 2FAS; anything else is read as a list.
pub fn parse_any_wide(text: &str) -> Result<ImportFile, BulkError> {
    if text.trim_start().starts_with('{') {
        match aegis::parse_wide(text) {
            Ok(f) => return Ok(f),
            Err(e @ BulkError::Encrypted(_)) => return Err(e),
            Err(_) => {}
        }
        return twofas::parse_wide(text);
    }
    parse_list_wide(text)
}

/// Map one JSON-export entry to the wide model. Checks run type, secret,
/// hash, digits, period — the Molto2 path's order with the type first.
#[allow(clippy::too_many_arguments)]
fn wide_entry(
    typ: &str,
    issuer: Option<String>,
    account: Option<String>,
    secret_b32: &str,
    algo: Option<&str>,
    digits: u32,
    period: u32,
    counter: CounterOnly,
) -> Result<ImportEntry, Unusable> {
    let kind = type_from_name(typ)?;
    let secret = decode_secret(secret_b32)?;
    let hash = hash_from_name(algo.unwrap_or("SHA1"))?;
    let kind = match kind {
        TypeName::Totp => OtpKind::Totp { period },
        TypeName::Hotp if counter.repeated => {
            return Err(Unusable::Malformed("the counter is given more than once"))
        }
        TypeName::Hotp => OtpKind::Hotp {
            counter: counter.value.unwrap_or(0),
        },
    };
    finish(issuer, account, secret, hash, digits, kind)
}

/// The `counter` of an Aegis `info` / 2FAS `otp` object, read on its own.
///
/// The wide readers read the other fields through the Molto2 path's own
/// structs, then this in a second pass, so a file the Molto2 path takes is
/// never refused for its counter: a `counter` key the Molto2 path ignores
/// (repeated, or of an odd shape) can't fail the file here. Every other key
/// is skipped unread — the seed included — and a value that isn't an object
/// reads as no counter.
#[derive(Default, Clone, Copy)]
struct CounterOnly {
    /// The last well-formed counter (lenient: an odd shape reads as absent).
    value: Option<u64>,
    /// `counter` appeared more than once: a HOTP entry is then unusable.
    repeated: bool,
}

impl<'de> serde::Deserialize<'de> for CounterOnly {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::{IgnoredAny, MapAccess, SeqAccess, Visitor};
        /// A key, compared without keeping it.
        struct IsCounter(bool);
        impl<'de> serde::Deserialize<'de> for IsCounter {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                struct K;
                impl Visitor<'_> for K {
                    type Value = IsCounter;
                    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                        f.write_str("a key")
                    }
                    fn visit_str<E>(self, v: &str) -> Result<IsCounter, E> {
                        Ok(IsCounter(v == "counter"))
                    }
                }
                d.deserialize_str(K)
            }
        }
        struct Lenient(Option<u64>);
        impl<'de> serde::Deserialize<'de> for Lenient {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                lenient_u64(d).map(Lenient)
            }
        }
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = CounterOnly;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("any JSON value")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<CounterOnly, A::Error> {
                let mut out = CounterOnly::default();
                let mut seen = false;
                while let Some(IsCounter(is)) = m.next_key()? {
                    if is {
                        out.repeated |= seen;
                        seen = true;
                        out.value = m.next_value::<Lenient>()?.0;
                    } else {
                        m.next_value::<IgnoredAny>()?;
                    }
                }
                Ok(out)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<CounterOnly, A::Error> {
                while a.next_element::<IgnoredAny>()?.is_some() {}
                Ok(CounterOnly::default())
            }
            fn visit_bool<E>(self, _: bool) -> Result<CounterOnly, E> {
                Ok(CounterOnly::default())
            }
            fn visit_i64<E>(self, _: i64) -> Result<CounterOnly, E> {
                Ok(CounterOnly::default())
            }
            fn visit_u64<E>(self, _: u64) -> Result<CounterOnly, E> {
                Ok(CounterOnly::default())
            }
            fn visit_f64<E>(self, _: f64) -> Result<CounterOnly, E> {
                Ok(CounterOnly::default())
            }
            fn visit_str<E>(self, _: &str) -> Result<CounterOnly, E> {
                Ok(CounterOnly::default())
            }
            fn visit_unit<E>(self) -> Result<CounterOnly, E> {
                Ok(CounterOnly::default())
            }
            fn visit_none<E>(self) -> Result<CounterOnly, E> {
                Ok(CounterOnly::default())
            }
            fn visit_some<D: serde::Deserializer<'de>>(
                self,
                d: D,
            ) -> Result<CounterOnly, D::Error> {
                d.deserialize_any(self)
            }
        }
        d.deserialize_any(V)
    }
}

/// `Option<u64>` from any JSON value: a non-negative integer becomes `Some`,
/// anything else (string, float, null, ...) `None` — never an error.
fn lenient_u64<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
    struct V;
    impl<'de> serde::de::Visitor<'de> for V {
        type Value = Option<u64>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("any JSON value")
        }
        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
            Ok(Some(v))
        }
        fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E> {
            Ok(u64::try_from(v).ok())
        }
        fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_unit<E>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_none<E>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_some<D: serde::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
            d.deserialize_any(self)
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut a: A,
        ) -> Result<Self::Value, A::Error> {
            while a.next_element::<serde::de::IgnoredAny>()?.is_some() {}
            Ok(None)
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut a: A,
        ) -> Result<Self::Value, A::Error> {
            while a
                .next_entry::<serde::de::IgnoredAny, serde::de::IgnoredAny>()?
                .is_some()
            {}
            Ok(None)
        }
    }
    d.deserialize_any(V)
}

/// Try each known format on `bytes` and return the first that parses.
pub fn parse_any(bytes: &str) -> Result<Vec<BulkEntry>, BulkError> {
    if bytes.trim_start().starts_with('{') {
        // JSON — try Aegis first (more specific shape), then 2FAS.
        match aegis::parse(bytes) {
            Ok(v) => return Ok(v),
            // An encrypted vault is a definitive diagnosis with an actionable
            // message — don't let the 2FAS fallback bury it in "no entries".
            Err(e @ BulkError::Encrypted(_)) => return Err(e),
            Err(_) => {}
        }
        return twofas::parse(bytes);
    }
    parse_otpauth_list(bytes)
}

fn build_entry(
    index: usize,
    issuer: Option<String>,
    account: Option<String>,
    secret_b32: &str,
    algo: Option<&str>,
    digits: u32,
    period: u32,
) -> Result<BulkEntry, BulkError> {
    let secret =
        keyroost_proto::codec::base32_decode(secret_b32).map_err(|_| BulkError::EntryRejected {
            index,
            reason: OtpAuthError::InvalidSecret,
        })?;
    if secret.is_empty() || secret.len() > 63 {
        return Err(BulkError::EntryRejected {
            index,
            reason: OtpAuthError::InvalidSecret,
        });
    }
    let algorithm = match algo.unwrap_or("SHA1").to_ascii_uppercase().as_str() {
        "SHA1" => HmacAlgo::Sha1,
        "SHA256" => HmacAlgo::Sha256,
        other => {
            return Err(BulkError::EntryRejected {
                index,
                reason: OtpAuthError::UnsupportedAlgorithm(other.to_owned()),
            })
        }
    };
    let digits = match digits {
        4 => OtpDigits::Four,
        6 => OtpDigits::Six,
        8 => OtpDigits::Eight,
        10 => OtpDigits::Ten,
        other => {
            return Err(BulkError::EntryRejected {
                index,
                reason: OtpAuthError::UnsupportedDigits(other),
            })
        }
    };
    let time_step = match period {
        30 => TimeStep::Seconds30,
        60 => TimeStep::Seconds60,
        other => {
            return Err(BulkError::EntryRejected {
                index,
                reason: OtpAuthError::UnsupportedPeriod(other),
            })
        }
    };
    Ok(BulkEntry {
        issuer: issuer.filter(|s| !s.is_empty()),
        account: account.filter(|s| !s.is_empty()),
        secret,
        algorithm,
        digits,
        time_step,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aegis_plaintext_minimal() {
        let json = r#"{
            "version": 1,
            "header": {"slots": null, "params": null},
            "db": {
                "version": 2,
                "entries": [
                    {
                        "type": "totp",
                        "uuid": "x",
                        "name": "alice@example.com",
                        "issuer": "GitHub",
                        "note": "",
                        "info": {"secret": "JBSWY3DPEHPK3PXP", "algo": "SHA1", "digits": 6, "period": 30}
                    },
                    {
                        "type": "hotp",
                        "uuid": "y",
                        "name": "skipme",
                        "issuer": "",
                        "info": {"secret": "JBSWY3DP", "counter": 0}
                    }
                ]
            }
        }"#;
        let v = aegis::parse(json).unwrap();
        assert_eq!(v.len(), 1); // hotp skipped
        assert_eq!(v[0].issuer.as_deref(), Some("GitHub"));
        assert_eq!(v[0].account.as_deref(), Some("alice@example.com"));
        assert_eq!(v[0].algorithm, HmacAlgo::Sha1);
        assert_eq!(v[0].digits, OtpDigits::Six);
        assert_eq!(v[0].time_step, TimeStep::Seconds30);
    }

    #[test]
    fn aegis_encrypted_rejected() {
        let json = r#"{"db": "ZW5jcnlwdGVk", "header": {}}"#;
        assert!(matches!(aegis::parse(json), Err(BulkError::Encrypted(_))));
    }

    #[test]
    fn twofas_plaintext_minimal() {
        let json = r#"{
            "services": [
                {
                    "name": "Stripe",
                    "secret": "JBSWY3DPEHPK3PXP",
                    "otp": {
                        "account": "ops@example.com",
                        "issuer": "Stripe",
                        "digits": 8,
                        "period": 60,
                        "algorithm": "SHA256",
                        "tokenType": "TOTP"
                    }
                },
                {
                    "name": "SteamGuard",
                    "secret": "JBSWY3DP",
                    "otp": {"tokenType": "STEAM"}
                }
            ]
        }"#;
        let v = twofas::parse(json).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].issuer.as_deref(), Some("Stripe"));
        assert_eq!(v[0].account.as_deref(), Some("ops@example.com"));
        assert_eq!(v[0].digits, OtpDigits::Eight);
        assert_eq!(v[0].time_step, TimeStep::Seconds60);
        assert_eq!(v[0].algorithm, HmacAlgo::Sha256);
    }

    #[test]
    fn twofas_encrypted_rejected() {
        let json = r#"{"servicesEncrypted": "blah", "services": []}"#;
        assert!(matches!(twofas::parse(json), Err(BulkError::Encrypted(_))));
    }

    #[test]
    fn otpauth_list_handles_comments_and_blanks() {
        let text = "
            # my Authy export, exported with otpauth-extractor
            otpauth://totp/GitHub:me@example.com?secret=JBSWY3DPEHPK3PXP

            otpauth://totp/GitLab?secret=JBSWY3DP&algorithm=SHA256
        ";
        let v = parse_otpauth_list(text).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].issuer.as_deref(), Some("GitHub"));
        assert_eq!(v[1].algorithm, HmacAlgo::Sha256);
    }

    #[test]
    fn parse_any_routes_by_shape() {
        let aegis_like = r#"{"db": {"entries":[{"type":"totp","name":"a","issuer":"X","info":{"secret":"JBSWY3DP"}}]}}"#;
        let twofas_like = r#"{"services":[{"name":"X","secret":"JBSWY3DP","otp":{}}]}"#;
        let list = "otpauth://totp/X?secret=JBSWY3DP";
        assert_eq!(parse_any(aegis_like).unwrap().len(), 1);
        assert_eq!(parse_any(twofas_like).unwrap().len(), 1);
        assert_eq!(parse_any(list).unwrap().len(), 1);
    }

    // ---- wide parsers ----------------------------------------------------

    use crate::entry::HashAlg;

    /// The same corpus as `tests/molto_golden.rs`, in the same order.
    const WIDE_AEGIS: &str = r#"{"version":1,"header":{"slots":null,"params":null},"db":{"version":2,"entries":[
        {"type":"totp","name":"alice@example.com","issuer":"GitHub","info":{"secret":"JBSWY3DPEHPK3PXP","algo":"SHA1","digits":6,"period":30}},
        {"type":"hotp","name":"counter","issuer":"Bank","info":{"secret":"JBSWY3DPEHPK3PXP","algo":"SHA1","digits":6,"counter":5}},
        {"type":"steam","name":"gamer","issuer":"Steam","info":{"secret":"JBSWY3DPEHPK3PXP","algo":"SHA1","digits":5,"period":30}},
        {"type":"totp","name":"seven","issuer":"Odd","info":{"secret":"JBSWY3DPEHPK3PXP","algo":"SHA1","digits":7,"period":30}},
        {"type":"totp","name":"slow","issuer":"Slow","info":{"secret":"JBSWY3DPEHPK3PXP","algo":"SHA1","digits":6,"period":45}},
        {"type":"totp","name":"wide","issuer":"Wide","info":{"secret":"JBSWY3DPEHPK3PXP","algo":"SHA512","digits":6,"period":30}},
        {"type":"totp","name":"bad","issuer":"Bad","info":{"secret":"NOT_BASE32!!","algo":"SHA1","digits":6,"period":30}},
        {"type":"totp","name":"long","issuer":"Long","info":{"secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","algo":"SHA1","digits":6,"period":30}},
        {"type":"totp","name":"bob","issuer":"","info":{"secret":"JBSWY3DPEHPK3PXP","algo":"SHA256","digits":8,"period":60}}
    ]}}"#;

    /// `(index, label, kind or unusable reason)` per item, for compact asserts.
    fn shape(file: &crate::entry::ImportFile) -> Vec<(usize, String, Result<OtpKind, Unusable>)> {
        file.items
            .iter()
            .map(|i| {
                (
                    i.index,
                    i.label.clone(),
                    i.entry.as_ref().map(|e| e.kind).map_err(Clone::clone),
                )
            })
            .collect()
    }

    #[test]
    fn aegis_wide_keeps_every_entry_in_order() {
        let f = aegis::parse_wide(WIDE_AEGIS).unwrap();
        assert_eq!(f.format, Format::Aegis);
        assert_eq!(f.batch, None);
        let totp30 = Ok(OtpKind::Totp { period: 30 });
        assert_eq!(
            shape(&f),
            vec![
                (0, "GitHub:alice@example.com".into(), totp30.clone()),
                (1, "Bank:counter".into(), Ok(OtpKind::Hotp { counter: 5 })),
                (2, "Steam:gamer".into(), Err(Unusable::Type("steam".into()))),
                (3, "Odd:seven".into(), totp30.clone()),
                (4, "Slow:slow".into(), Ok(OtpKind::Totp { period: 45 })),
                (5, "Wide:wide".into(), totp30.clone()),
                (6, "Bad:bad".into(), Err(Unusable::BadSecret)),
                (7, "Long:long".into(), totp30),
                (8, "bob".into(), Ok(OtpKind::Totp { period: 60 })),
            ]
        );
        let e = |i: usize| f.items[i].entry.as_ref().unwrap();
        assert_eq!(e(3).digits, 7);
        assert_eq!(e(5).hash, HashAlg::Sha512);
        assert_eq!(e(7).secret.len(), 64);
        assert_eq!(e(8).issuer, None);
        assert_eq!(e(8).hash, HashAlg::Sha256);
        assert_eq!(e(8).digits, 8);
        assert_eq!(f.usable(), 7);
    }

    #[test]
    fn aegis_wide_file_errors() {
        assert!(matches!(
            aegis::parse_wide(r#"{"db":"ZW5jcnlwdGVk","header":{}}"#),
            Err(BulkError::Encrypted(_))
        ));
        assert!(matches!(
            aegis::parse_wide(r#"{"db":{"entries":[]}}"#),
            Err(BulkError::EmptyFile)
        ));
        assert!(matches!(aegis::parse_wide("{"), Err(BulkError::Json(_))));
        // A file of only unusable entries is still a file of items.
        let f = aegis::parse_wide(
            r#"{"db":{"entries":[{"type":"motp","name":"","issuer":"","info":{"secret":"JBSWY3DP"}}]}}"#,
        )
        .unwrap();
        assert_eq!(f.usable(), 0);
        assert_eq!(
            shape(&f),
            vec![(0, "entry 1".into(), Err(Unusable::Type("motp".into())))]
        );
    }

    #[test]
    fn twofas_wide_reads_hotp_counter() {
        let json = r#"{"services":[
            {"name":"Bank","secret":"JBSWY3DPEHPK3PXP","otp":{"account":"me","issuer":"Bank","digits":6,"counter":3,"algorithm":"SHA1","tokenType":"HOTP"}},
            {"name":"Mail","secret":"JBSWY3DPEHPK3PXP","otp":{"account":"you","period":20,"algorithm":"SHA512"}},
            {"name":"Steam","secret":"JBSWY3DPEHPK3PXP","otp":{"tokenType":"STEAM"}}
        ]}"#;
        let f = twofas::parse_wide(json).unwrap();
        assert_eq!(f.format, Format::TwoFas);
        assert_eq!(
            shape(&f),
            vec![
                (0, "Bank:me".into(), Ok(OtpKind::Hotp { counter: 3 })),
                (1, "Mail:you".into(), Ok(OtpKind::Totp { period: 20 })),
                (2, "Steam".into(), Err(Unusable::Type("STEAM".into()))),
            ]
        );
        assert_eq!(f.items[1].entry.as_ref().unwrap().hash, HashAlg::Sha512);
        assert!(matches!(
            twofas::parse_wide(r#"{"servicesEncrypted":"x","services":[]}"#),
            Err(BulkError::Encrypted(_))
        ));
        assert!(matches!(
            twofas::parse_wide(r#"{"services":[]}"#),
            Err(BulkError::EmptyFile)
        ));
    }

    #[test]
    fn list_wide_line_errors_are_items_not_file_errors() {
        let text = "# header\n\notpauth://totp/A:x?secret=JBSWY3DPEHPK3PXP&period=45\n  \notpauth://hotp/B?secret=JBSWY3DPEHPK3PXP&counter=2\nhello there\notpauth://totp/C:y?secret=JBSWY3DP&digits=11\n";
        let f = parse_list_wide(text).unwrap();
        assert_eq!(f.format, Format::OtpauthList);
        assert_eq!(
            shape(&f),
            vec![
                (2, "A:x".into(), Ok(OtpKind::Totp { period: 45 })),
                (4, "B".into(), Ok(OtpKind::Hotp { counter: 2 })),
                (
                    5,
                    "line 6".into(),
                    Err(Unusable::Malformed("not an otpauth:// URI"))
                ),
                (6, "C:y".into(), Err(Unusable::Digits(11))),
            ]
        );
        assert!(matches!(
            parse_list_wide("# nothing\n\n"),
            Err(BulkError::EmptyFile)
        ));
    }

    #[test]
    fn list_wide_accepts_migration_lines() {
        let migration = crate::migration::tests::uri_for(&crate::migration::tests::payload(&[
            crate::migration::tests::otp_params(b"0123456789", "Acme:alice", "Acme", 1, 1, 2),
            crate::migration::tests::otp_params(b"counterkey", "Legacy", "", 1, 1, 1),
        ]));
        let text = format!(
            "otpauth://totp/A?secret=JBSWY3DPEHPK3PXP\n{}\notpauth-migration://offline?data=!!!\n",
            migration
        );
        let f = parse_list_wide(&text).unwrap();
        assert_eq!(
            shape(&f),
            vec![
                (0, "A".into(), Ok(OtpKind::Totp { period: 30 })),
                (1, "Acme:alice".into(), Ok(OtpKind::Totp { period: 30 })),
                (1, "Legacy".into(), Ok(OtpKind::Hotp { counter: 0 })),
                (
                    2,
                    "line 3".into(),
                    Err(Unusable::Malformed(
                        "the Google Authenticator export couldn't be read"
                    ))
                ),
            ]
        );
    }

    #[test]
    fn parse_any_wide_routes_by_shape() {
        let aegis_like = r#"{"db": {"entries":[{"type":"hotp","name":"a","issuer":"X","info":{"secret":"JBSWY3DP","counter":1}}]}}"#;
        let twofas_like = r#"{"services":[{"name":"X","secret":"JBSWY3DP","otp":{}}]}"#;
        assert_eq!(parse_any_wide(aegis_like).unwrap().format, Format::Aegis);
        assert_eq!(parse_any_wide(twofas_like).unwrap().format, Format::TwoFas);
        assert_eq!(
            parse_any_wide("otpauth://hotp/X?secret=JBSWY3DP")
                .unwrap()
                .format,
            Format::OtpauthList
        );
        assert!(matches!(
            parse_any_wide(r#"{"db":"ZW5j"}"#),
            Err(BulkError::Encrypted(_))
        ));
    }

    #[test]
    fn describe_never_quotes_file_values() {
        let err = |json: &str| {
            serde_json::from_str::<Vec<u32>>(json)
                .map(|_| ())
                .unwrap_err()
        };
        let syntax = BulkError::Json(err(r#"[1, "SENTINEL"#)).describe("a list");
        assert!(!syntax.contains("SENTINEL"), "{syntax}");
        assert!(
            syntax.starts_with("The file isn't valid JSON (line 1, column"),
            "{syntax}"
        );
        let data = BulkError::Json(err(r#"[1, "SENTINEL"]"#)).describe("a list");
        assert!(!data.contains("SENTINEL"), "{data}");
        assert_eq!(
            data,
            "The file doesn't match the layout of a list (line 1, column 14)."
        );
        assert_eq!(
            BulkError::TooManyEntries.describe("x"),
            "More than 1000 entries; this isn't an authenticator export."
        );
    }

    #[test]
    fn wide_readers_refuse_more_than_max_entries() {
        use crate::entry::MAX_ENTRIES;
        // A list: one otpauth line makes the file a list; millions of junk
        // lines after it must stop at the cap, not become millions of items.
        let mut huge = String::from("otpauth://totp/A?secret=JBSWY3DP\n");
        huge.push_str(&"x\n".repeat(5_000_000));
        assert!(matches!(
            parse_list_wide(&huge),
            Err(BulkError::TooManyEntries)
        ));
        assert!(matches!(
            parse_any_wide(&huge),
            Err(BulkError::TooManyEntries)
        ));
        // Exactly at the cap is fine; one more is refused.
        let line = "otpauth://totp/A?secret=JBSWY3DP\n";
        assert_eq!(
            parse_list_wide(&line.repeat(MAX_ENTRIES))
                .unwrap()
                .items
                .len(),
            MAX_ENTRIES
        );
        assert!(matches!(
            parse_list_wide(&line.repeat(MAX_ENTRIES + 1)),
            Err(BulkError::TooManyEntries)
        ));
        // Migration lines count every entry they carry.
        let one = crate::migration::tests::otp_params(b"k", "a", "", 1, 1, 2);
        let six_hundred =
            crate::migration::tests::uri_for(&crate::migration::tests::payload(&vec![one; 600]));
        assert!(matches!(
            parse_list_wide(&format!("{six_hundred}\n{six_hundred}\n")),
            Err(BulkError::TooManyEntries)
        ));

        // JSON: counted before any entry is built.
        let aegis_entry = r#"{"type":"totp","name":"a","issuer":"","info":{"secret":"JBSWY3DP"}}"#;
        let aegis = |n: usize| {
            format!(
                r#"{{"db":{{"entries":[{}]}}}}"#,
                vec![aegis_entry; n].join(",")
            )
        };
        assert_eq!(
            aegis::parse_wide(&aegis(MAX_ENTRIES)).unwrap().items.len(),
            MAX_ENTRIES
        );
        assert!(matches!(
            aegis::parse_wide(&aegis(MAX_ENTRIES + 1)),
            Err(BulkError::TooManyEntries)
        ));
        let service = r#"{"name":"X","secret":"JBSWY3DP"}"#;
        let twofas = |n: usize| format!(r#"{{"services":[{}]}}"#, vec![service; n].join(","));
        assert_eq!(
            twofas::parse_wide(&twofas(MAX_ENTRIES))
                .unwrap()
                .items
                .len(),
            MAX_ENTRIES
        );
        assert!(matches!(
            twofas::parse_wide(&twofas(MAX_ENTRIES + 1)),
            Err(BulkError::TooManyEntries)
        ));
        assert_eq!(
            BulkError::TooManyEntries.to_string(),
            "more than 1000 entries; this isn't an authenticator export"
        );
    }

    #[test]
    fn wide_readers_read_the_counter_only_for_hotp() {
        let kinds = |f: ImportFile| -> Vec<Result<OtpKind, Unusable>> {
            f.items
                .into_iter()
                .map(|i| i.entry.map(|e| e.kind))
                .collect()
        };
        // A repeated or odd counter on a TOTP entry is ignored, as the Molto2
        // path ignores it; on a HOTP entry a repeated one is unusable.
        let aegis = r#"{"db":{"entries":[
            {"type":"totp","name":"a","issuer":"X","info":{"secret":"JBSWY3DP","counter":1,"counter":2}},
            {"type":"hotp","name":"b","issuer":"X","info":{"secret":"JBSWY3DP","counter":1,"counter":2}},
            {"type":"hotp","name":"c","issuer":"X","info":{"counter":"x","secret":"JBSWY3DP"}}]}}"#;
        assert_eq!(
            kinds(aegis::parse_wide(aegis).unwrap()),
            vec![
                Ok(OtpKind::Totp { period: 30 }),
                Err(Unusable::Malformed("the counter is given more than once")),
                Ok(OtpKind::Hotp { counter: 0 }),
            ]
        );
        let twofas = r#"{"services":[
            {"name":"A","secret":"JBSWY3DP","otp":{"account":"a","counter":1,"counter":2,"tokenType":"TOTP"}},
            {"name":"B","secret":"JBSWY3DP","otp":{"account":"b","counter":1,"counter":2,"tokenType":"HOTP"}},
            {"name":"C","secret":"JBSWY3DP","otp":{"account":"c","counter":7,"tokenType":"HOTP"}}]}"#;
        assert_eq!(
            kinds(twofas::parse_wide(twofas).unwrap()),
            vec![
                Ok(OtpKind::Totp { period: 30 }),
                Err(Unusable::Malformed("the counter is given more than once")),
                Ok(OtpKind::Hotp { counter: 7 }),
            ]
        );
        let list = "otpauth://totp/A?secret=JBSWY3DP&counter=zz\notpauth://hotp/B?secret=JBSWY3DP&counter=zz\n";
        assert_eq!(
            kinds(parse_list_wide(list).unwrap()),
            vec![
                Ok(OtpKind::Totp { period: 30 }),
                Err(Unusable::Malformed("the counter value isn't a number")),
            ]
        );
    }
}
