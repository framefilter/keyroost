// crates/keyroost/src/ui/mds.rs
//
// FIDO Metadata Service (MDS) integration: map a device AAGUID to the metadata
// the FIDO Alliance publishes for it — human description, vendor icon, the
// certification status (e.g. "FIDO Certified L2") with its date and certificate
// number, and a few descriptive fields from the metadata statement.
//
// Data source: a bundled dataset (`mds_data.json`), curated at build time from
// the MDS3 BLOB. To update it, regenerate with `tools/gen_mds_data.py` against a
// freshly downloaded BLOB and rebuild (see that script). There is no in-app
// download — the metadata changes rarely and bundling keeps the build offline
// and dependency-light.
//
// The bundled JSON is a slimmed projection of the MDS3 BLOB: per AAGUID only the
// fields this UI renders.

use std::collections::HashMap;

/// One authenticator's metadata, projected to the fields keyroost shows.
#[derive(Clone, Debug, Default)]
pub struct MdsEntry {
    pub description: String,
    /// `data:image/png;base64,...` icon, if the statement carried one.
    pub icon: Option<String>,
    /// Latest status, e.g. "FIDO_CERTIFIED_L2" or "NOT_FIDO_CERTIFIED".
    pub status: Option<String>,
    /// Parsed but not currently shown in the (compact) card. Kept in the data
    /// model so it needn't be regenerated if re-surfaced later.
    #[allow(dead_code)]
    pub certificate_number: Option<String>,
    /// Date the latest status took effect (ISO-8601, as published).
    pub effective_date: Option<String>,
    /// `metadataStatement.authenticatorVersion` — parsed but not shown in the
    /// compact card (see `certificate_number`).
    #[allow(dead_code)]
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
    /// Load the bundled dataset baked into the binary. Cheap to call; parses the
    /// embedded JSON once. Never fails fatally — a malformed bundle yields an
    /// empty db so the rest of the UI is unaffected.
    /// Load the MDS dataset. Prefers a user-updatable file on disk so the data
    /// can be refreshed without rebuilding (important for AppImage / signed .exe
    /// / .dmg distributions where the binary is read-only). Falls back to the
    /// dataset embedded at build time.
    ///
    /// Search order (first that parses to a non-empty list wins):
    ///   1. `$KEYROOST_MDS_FILE` (explicit override, any path)
    ///   2. the platform config dir: `keyroost/mds_data.json` under
    ///      `$XDG_CONFIG_HOME` / `$HOME/.config` (Linux),
    ///      `$HOME/Library/Application Support` (macOS),
    ///      `%APPDATA%` (Windows)
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
        self.by_aaguid
            .get(&super::aaguid::format_aaguid_pub(aaguid))
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
                    description: r.description.unwrap_or_default(),
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
static BUNDLED_MDS_JSON: &str = include_str!("../../assets/mds_data.json");

/// Candidate on-disk locations for a user-supplied `mds_data.json`, in priority
/// order. Missing env vars simply drop their candidates. No external crate is
/// used so the dependency footprint stays unchanged.
fn external_mds_paths() -> Vec<std::path::PathBuf> {
    use std::path::PathBuf;
    let mut out: Vec<PathBuf> = Vec::new();

    // 1. Explicit override.
    if let Ok(p) = std::env::var("KEYROOST_MDS_FILE") {
        if !p.is_empty() {
            out.push(PathBuf::from(p));
        }
    }

    // 2. Platform config dir.
    let cfg: Option<PathBuf> = if cfg!(target_os = "windows") {
        std::env::var_os("APPDATA").map(PathBuf::from)
    } else if cfg!(target_os = "macos") {
        std::env::var_os("HOME")
            .map(|h| PathBuf::from(h).join("Library").join("Application Support"))
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
    };
    if let Some(dir) = cfg {
        out.push(dir.join("keyroost").join("mds_data.json"));
    }

    // 3. Next to the executable (portable / AppImage-extracted installs).
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            out.push(dir.join("mds_data.json"));
        }
    }

    out
}

// --- icon decoding -----------------------------------------------------------

/// Decode a `data:image/png;base64,...` icon URI to an `egui::ColorImage`.
/// Returns `None` for non-PNG icons, malformed data, or decode errors — callers
/// simply omit the image in that case. Only PNG is handled: every icon in the
/// MDS BLOB is a PNG data URI per the metadata statement spec.
pub fn decode_icon(data_uri: &str) -> Option<egui::ColorImage> {
    let b64 = data_uri
        .strip_prefix("data:image/png;base64,")
        .or_else(|| data_uri.strip_prefix("data:image/png;charset=utf-8;base64,"))?;
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    let decoder = png::Decoder::new(std::io::Cursor::new(bytes));
    let mut reader = decoder.read_info().ok()?;
    let mut buf = vec![0u8; reader.output_buffer_size()?];
    let frame = reader.next_frame(&mut buf).ok()?;
    let (w, h) = (frame.width as usize, frame.height as usize);
    let data = &buf[..frame.buffer_size()];
    // Normalize to RGBA8 for egui.
    let rgba: Vec<u8> = match frame.color_type {
        png::ColorType::Rgba => data.to_vec(),
        png::ColorType::Rgb => data
            .chunks_exact(3)
            .flat_map(|p| [p[0], p[1], p[2], 255])
            .collect(),
        png::ColorType::GrayscaleAlpha => data
            .chunks_exact(2)
            .flat_map(|p| [p[0], p[0], p[0], p[1]])
            .collect(),
        png::ColorType::Grayscale => data.iter().flat_map(|&g| [g, g, g, 255]).collect(),
        // Indexed/other should already be expanded by png's transformations in
        // the common case; bail rather than render garbage.
        _ => return None,
    };
    // `ColorImage::from_rgba_unmultiplied` asserts the buffer is exactly w*h*4;
    // bail with None on any mismatch rather than risk a panic in the UI thread.
    if rgba.len() != w * h * 4 {
        return None;
    }
    Some(egui::ColorImage::from_rgba_unmultiplied([w, h], &rgba))
}
