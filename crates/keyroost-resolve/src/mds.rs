//! FIDO Metadata Service (MDS) lookup: map a device AAGUID to the metadata
//! the FIDO Alliance publishes for it — human description, vendor icon, the
//! certification status (e.g. "FIDO Certified L2") with its date and
//! certificate number, and a few descriptive fields from the metadata
//! statement. Shared so `keyroostctl fido info` and the app's metadata card
//! show the same facts; the app decodes the icon itself.
//!
//! Data source: a bundled dataset (`mds_data.json`), curated at build time
//! from the MDS3 BLOB. To update it, regenerate with `tools/gen_mds_data.py`
//! against a freshly downloaded BLOB and rebuild (see that script). There is
//! no download at runtime — the metadata changes rarely and bundling keeps
//! the build offline and dependency-light.
//!
//! The bundled JSON is a slimmed projection of the MDS3 BLOB: per AAGUID only
//! the fields keyroost shows.

use std::collections::HashMap;

/// One authenticator's metadata, projected to the fields keyroost shows.
#[derive(Clone, Debug, Default)]
pub struct MdsEntry {
    pub description: String,
    /// `data:image/png;base64,...` icon, if the statement carried one.
    pub icon: Option<String>,
    /// Latest status, e.g. "FIDO_CERTIFIED_L2" or "NOT_FIDO_CERTIFIED".
    pub status: Option<String>,
    /// Parsed but not currently shown. Kept in the data model so it needn't
    /// be regenerated if surfaced later.
    pub certificate_number: Option<String>,
    /// Date the latest status took effect (ISO-8601, as published).
    pub effective_date: Option<String>,
    /// `metadataStatement.authenticatorVersion` — parsed but not shown (see
    /// `certificate_number`).
    pub authenticator_version: Option<u64>,
    /// `metadataStatement.protocolFamily` — "fido2", "u2f", or "uaf".
    pub protocol_family: Option<String>,
    /// CTAP/U2F versions the statement advertises (e.g. "FIDO_2_1", "U2F_V2"),
    /// from `metadataStatement.authenticatorGetInfo.versions` when present.
    pub mds_versions: Vec<String>,
}

impl MdsEntry {
    /// Human-readable certification label, e.g. "FIDO Certified L2", or `None`
    /// when there is no usable status.
    pub fn certification_label(&self) -> Option<String> {
        let s = self.status.as_deref()?;
        let pretty = match s {
            "FIDO_CERTIFIED" => "FIDO Certified".to_string(),
            "FIDO_CERTIFIED_L1" => "FIDO Certified L1".to_string(),
            "FIDO_CERTIFIED_L1plus" => "FIDO Certified L1+".to_string(),
            "FIDO_CERTIFIED_L2" => "FIDO Certified L2".to_string(),
            "FIDO_CERTIFIED_L2plus" => "FIDO Certified L2+".to_string(),
            "FIDO_CERTIFIED_L3" => "FIDO Certified L3".to_string(),
            "FIDO_CERTIFIED_L3plus" => "FIDO Certified L3+".to_string(),
            "NOT_FIDO_CERTIFIED" => "Not FIDO Certified".to_string(),
            // Revocation / advisory statuses — surface verbatim but readable.
            other => other.replace('_', " "),
        };
        Some(pretty)
    }

    /// Short certification level token, e.g. "L2" or "L1+", when the status is a
    /// normal certification (not an advisory). `None` otherwise.
    pub fn certification_level(&self) -> Option<&'static str> {
        Some(match self.status.as_deref()? {
            "FIDO_CERTIFIED" => "Certified",
            "FIDO_CERTIFIED_L1" => "L1",
            "FIDO_CERTIFIED_L1plus" => "L1+",
            "FIDO_CERTIFIED_L2" => "L2",
            "FIDO_CERTIFIED_L2plus" => "L2+",
            "FIDO_CERTIFIED_L3" => "L3",
            "FIDO_CERTIFIED_L3plus" => "L3+",
            _ => return None,
        })
    }

    /// The day the latest status took effect ("2024-12-27"), without any
    /// time part the statement carries.
    pub fn status_date(&self) -> Option<&str> {
        let date = self.effective_date.as_deref()?;
        date.split(['T', ' ']).next().filter(|d| !d.is_empty())
    }

    /// True for statuses that indicate a problem the user should notice
    /// (revoked, compromised, etc.) rather than a normal certification level.
    pub fn is_advisory(&self) -> bool {
        matches!(
            self.status.as_deref(),
            Some(
                "USER_VERIFICATION_BYPASS"
                    | "ATTESTATION_KEY_COMPROMISE"
                    | "USER_KEY_REMOTE_COMPROMISE"
                    | "USER_KEY_PHYSICAL_COMPROMISE"
                    | "REVOKED"
            )
        )
    }
}

/// The bundled MDS dataset, keyed by canonical AAGUID string.
#[derive(Default)]
pub struct MdsDb {
    by_aaguid: HashMap<String, MdsEntry>,
}

impl MdsDb {
    /// Load the MDS dataset. Never fails fatally — a malformed bundle yields an
    /// empty db so the rest of the output is unaffected. Prefers a user-updatable file on disk so the data
    /// can be refreshed without rebuilding (important for AppImage / signed .exe
    /// / .dmg distributions where the binary is read-only). Falls back to the
    /// dataset embedded at build time.
    ///
    /// Search order (first that parses to a non-empty list wins):
    ///   1. `$KEYROOST_MDS_FILE` (explicit override, any path)
    ///   2. `mds_data.json` in keyroost's config dir, beside `keys.json`
    ///      ([`keyroost_keyring::config_dir`]: `$XDG_CONFIG_HOME/keyroost` /
    ///      `$HOME/.config/keyroost`, `%APPDATA%\keyroost` on Windows), then on
    ///      macOS `$HOME/Library/Application Support/keyroost`
    ///   3. `mds_data.json` next to the executable (portable installs)
    ///   4. the embedded build-time dataset
    pub fn load_bundled() -> Self {
        let mut db = MdsDb::default();
        for path in external_mds_paths() {
            if let Ok(text) = std::fs::read_to_string(&path) {
                if db.merge_json(&text) > 0 {
                    return db;
                }
            }
        }
        db.merge_json(BUNDLED_MDS_JSON);
        db
    }

    /// Look up an entry by 16-byte AAGUID (canonical lowercase 8-4-4-4-12).
    pub fn get(&self, aaguid: &[u8; 16]) -> Option<&MdsEntry> {
        if aaguid.iter().all(|&b| b == 0) {
            return None;
        }
        self.by_aaguid.get(&crate::aaguid::format_aaguid(aaguid))
    }

    /// Merge entries parsed from the slim MDS JSON projection.
    fn merge_json(&mut self, json: &str) -> usize {
        let parsed: Result<Vec<RawEntry>, _> = serde_json::from_str(json);
        let Ok(entries) = parsed else {
            return 0;
        };
        let mut n = 0;
        for r in entries {
            let key = r.aaguid.trim().to_lowercase();
            if key.is_empty() {
                continue;
            }
            self.by_aaguid.insert(
                key.clone(),
                MdsEntry {
                    // Published descriptions can carry stray spaces
                    // ("TOKEN2 PIN Plus Security Key Series ").
                    description: r.description.unwrap_or_default().trim().to_owned(),
                    icon: r.icon,
                    status: r.status,
                    certificate_number: r.certificate_number,
                    effective_date: r.effective_date,
                    authenticator_version: r.authenticator_version,
                    protocol_family: r.protocol_family,
                    mds_versions: r.mds_versions.unwrap_or_default(),
                },
            );
            n += 1;
        }
        n
    }
}

/// Raw shape of one entry in the slim JSON.
#[derive(serde::Deserialize)]
struct RawEntry {
    aaguid: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    icon: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default, rename = "certificateNumber")]
    certificate_number: Option<String>,
    #[serde(default, rename = "effectiveDate")]
    effective_date: Option<String>,
    #[serde(default, rename = "authenticatorVersion")]
    authenticator_version: Option<u64>,
    #[serde(default, rename = "protocolFamily")]
    protocol_family: Option<String>,
    #[serde(default, rename = "versions")]
    mds_versions: Option<Vec<String>>,
}

/// Bundled MDS projection, embedded at build time. Regenerate with
/// `tools/gen_mds_data.py`. Kept small: only AAGUIDs relevant to keyroost's
/// target vendors, only the fields rendered.
static BUNDLED_MDS_JSON: &str = include_str!("../assets/mds_data.json");

/// Candidate on-disk locations for a user-supplied `mds_data.json`, in priority
/// order. Missing env vars simply drop their candidates.
fn external_mds_paths() -> Vec<std::path::PathBuf> {
    use std::path::PathBuf;
    let mut out: Vec<PathBuf> = Vec::new();

    // 1. Explicit override.
    if let Ok(p) = std::env::var("KEYROOST_MDS_FILE") {
        if !p.is_empty() {
            out.push(PathBuf::from(p));
        }
    }

    // 2. keyroost's config dir. A test build (this crate's or a dependent's
    //    with keyroost-keyring's `test-isolation`) gets an isolated directory
    //    under the temp dir, and then the macOS location isn't read either, so
    //    a test never reads the person's files.
    if let Some(dir) = keyroost_keyring::config_dir() {
        let isolated = dir.starts_with(std::env::temp_dir());
        out.push(dir.join("mds_data.json"));
        if cfg!(target_os = "macos") && !isolated {
            if let Some(home) = std::env::var_os("HOME") {
                out.push(
                    PathBuf::from(home)
                        .join("Library")
                        .join("Application Support")
                        .join("keyroost")
                        .join("mds_data.json"),
                );
            }
        }
    }

    // 3. Next to the executable (portable / AppImage-extracted installs).
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            out.push(dir.join("mds_data.json"));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The AAGUID a Token2 PIN+ R3.4 reports.
    const TOKEN2_PIN_PLUS: [u8; 16] = [
        0xea, 0xbb, 0x46, 0xcc, 0xe2, 0x41, 0x80, 0xbf, 0xae, 0x9e, 0x96, 0xfa, 0x6d, 0x29, 0x75,
        0xcf,
    ];

    #[test]
    fn the_bundled_dataset_parses_and_names_a_known_key() {
        let mut db = MdsDb::default();
        assert!(db.merge_json(BUNDLED_MDS_JSON) > 100);
        let e = db
            .get(&TOKEN2_PIN_PLUS)
            .expect("Token2 PIN+ is in the bundle");
        assert_eq!(e.description, "TOKEN2 PIN Plus Security Key Series");
        assert_eq!(
            e.certification_label().as_deref(),
            Some("FIDO Certified L2")
        );
    }

    #[test]
    fn an_all_zero_aaguid_has_no_entry() {
        assert!(MdsDb::load_bundled().get(&[0; 16]).is_none());
    }

    /// A test build never looks in the person's config directory.
    #[test]
    fn a_test_build_reads_no_real_config_dir() {
        let tmp = std::env::temp_dir();
        let exe_dir = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        for p in external_mds_paths() {
            if std::env::var_os("KEYROOST_MDS_FILE").is_some_and(|f| p == std::path::Path::new(&f))
            {
                continue;
            }
            assert!(
                p.starts_with(&tmp) || p.starts_with(&exe_dir),
                "{}",
                p.display()
            );
        }
    }
}
