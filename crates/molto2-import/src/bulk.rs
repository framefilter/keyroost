//! Plaintext bulk-import parsers for Aegis, 2FAS, and generic otpauth:// lists.
//!
//! All three parsers normalize to `Vec<BulkEntry>`. Encrypted vaults are not
//! supported in v1 — the user must export plaintext from their authenticator.

use molto2_proto::commands::{DisplayTimeout, HmacAlgo, OtpDigits, ProfileConfig, TimeStep};
use serde::Deserialize;

use crate::otpauth::{parse as parse_otpauth, OtpAuth, OtpAuthError};

/// One normalized entry ready to be programmed into a Molto2 profile slot.
#[derive(Debug, Clone)]
pub struct BulkEntry {
    pub issuer: Option<String>,
    pub account: Option<String>,
    pub secret: Vec<u8>,
    pub algorithm: HmacAlgo,
    pub digits: OtpDigits,
    pub time_step: TimeStep,
}

impl BulkEntry {
    pub fn suggested_title(&self) -> String {
        let candidate = self
            .issuer
            .as_deref()
            .or(self.account.as_deref())
            .unwrap_or("");
        let mut end = candidate.len().min(12);
        while end > 0 && !candidate.is_char_boundary(end) {
            end -= 1;
        }
        candidate[..end].to_owned()
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
    fn from(p: OtpAuth) -> Self {
        BulkEntry {
            issuer: p.issuer,
            account: p.account,
            secret: p.secret,
            algorithm: p.algorithm,
            digits: p.digits,
            time_step: p.time_step,
        }
    }
}

#[derive(Debug)]
pub enum BulkError {
    Json(serde_json::Error),
    Encrypted(&'static str),
    UnsupportedFormat(&'static str),
    EntryRejected { index: usize, reason: OtpAuthError },
    EmptyFile,
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
        }
    }
}

impl std::error::Error for BulkError {}

impl From<serde_json::Error> for BulkError {
    fn from(e: serde_json::Error) -> Self {
        BulkError::Json(e)
    }
}

/// Aegis plaintext export (`db.entries[]`). Encrypted vaults set `db: string`
/// instead of `db: object` — we detect that and reject.
pub mod aegis {
    use super::*;

    #[derive(Deserialize)]
    struct Root {
        db: serde_json::Value,
    }

    #[derive(Deserialize)]
    struct Db {
        entries: Vec<Entry>,
    }

    #[derive(Deserialize)]
    struct Entry {
        #[serde(rename = "type")]
        typ: String,
        name: Option<String>,
        issuer: Option<String>,
        info: EntryInfo,
    }

    #[derive(Deserialize)]
    struct EntryInfo {
        secret: String,
        algo: Option<String>,
        digits: Option<u32>,
        period: Option<u32>,
    }

    pub fn parse(json: &str) -> Result<Vec<BulkEntry>, BulkError> {
        let root: Root = serde_json::from_str(json)?;
        let db: Db = match &root.db {
            serde_json::Value::Object(_) => serde_json::from_value(root.db)?,
            serde_json::Value::String(_) => {
                #[cfg(feature = "encrypted")]
                {
                    return Err(BulkError::Encrypted(
                        "Aegis export is encrypted; supply a password (CLI: --password-stdin)",
                    ));
                }
                #[cfg(not(feature = "encrypted"))]
                {
                    return Err(BulkError::Encrypted(
                        "Aegis export is encrypted; build with --features encrypted or re-export plaintext",
                    ));
                }
            }
            _ => return Err(BulkError::UnsupportedFormat("unexpected `db` shape")),
        };
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

    /// Detect an encrypted Aegis vault without parsing the whole structure.
    /// `Ok(true)` means an `encrypted` decrypt is needed; `Ok(false)` means
    /// the file is already plaintext. Cheap and side-effect-free.
    pub fn is_encrypted(json: &str) -> Result<bool, BulkError> {
        let root: Root = serde_json::from_str(json)?;
        Ok(matches!(root.db, serde_json::Value::String(_)))
    }

    /// Decrypt an Aegis encrypted vault and return the inner plaintext JSON,
    /// which can then be passed back to `parse()`. Requires the `encrypted`
    /// crate feature.
    #[cfg(feature = "encrypted")]
    pub fn decrypt(json: &str, password: &[u8]) -> Result<String, BulkError> {
        crate::encrypted::decrypt_aegis(json, password)
    }
}

/// 2FAS plaintext export (`services[]`). The encrypted variant has a top-level
/// `servicesEncrypted` string — we detect and reject.
pub mod twofas {
    use super::*;

    #[derive(Deserialize)]
    struct Root {
        #[serde(default)]
        services: Vec<Service>,
        #[serde(rename = "servicesEncrypted", default)]
        services_encrypted: Option<String>,
    }

    #[derive(Deserialize)]
    struct Service {
        name: Option<String>,
        secret: String,
        #[serde(default)]
        otp: Otp,
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

    pub fn parse(json: &str) -> Result<Vec<BulkEntry>, BulkError> {
        let root: Root = serde_json::from_str(json)?;
        if root.services_encrypted.is_some() && root.services.is_empty() {
            return Err(BulkError::Encrypted(
                "2FAS export is encrypted; re-export without a password",
            ));
        }
        let mut out = Vec::with_capacity(root.services.len());
        for (i, s) in root.services.into_iter().enumerate() {
            // 2FAS includes Steam etc; skip non-TOTP.
            if let Some(tt) = s.otp.token_type.as_deref() {
                if !tt.eq_ignore_ascii_case("TOTP") {
                    continue;
                }
            }
            let entry = build_entry(
                i,
                s.otp.issuer.or(s.name),
                s.otp.account,
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

/// Try each known format on `bytes` and return the first that parses.
pub fn parse_any(bytes: &str) -> Result<Vec<BulkEntry>, BulkError> {
    if bytes.trim_start().starts_with('{') {
        // JSON — try Aegis first (more specific shape), then 2FAS.
        if let Ok(v) = aegis::parse(bytes) {
            return Ok(v);
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
        molto2_proto::codec::base32_decode(secret_b32).map_err(|_| BulkError::EntryRejected {
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
}
