//! Serializable shapes for the global `--json` output mode. Each struct mirrors
//! 1:1 the data the corresponding command's human handler already prints — no
//! new data, only structure.

use serde::Serialize;

/// A top-level `{"keys": [...]}` envelope: the bare-invocation overview
/// (`keyroostctl --json`) and `keyroostctl list --json`.
#[derive(Serialize)]
pub(crate) struct KeysJson<T: Serialize> {
    pub keys: Vec<T>,
}

/// A top-level `{"accounts": [...]}` envelope: `oath list` and `otp list`.
#[derive(Serialize)]
pub(crate) struct AccountsJson<T: Serialize> {
    pub accounts: Vec<T>,
}

/// One device in the bare-invocation overview (`keyroostctl --json`).
#[derive(Serialize)]
pub(crate) struct DeviceJson {
    pub vendor: String,
    pub model: String,
    /// The name shown (a key carrying a name another key holds here has its
    /// serial tail appended).
    pub name: Option<String>,
    /// Where that name lives: "key" or "computer".
    pub name_source: Option<&'static str>,
    pub serial: String,
    pub transport: String,
    /// "key" or "token".
    pub kind: &'static str,
    pub capabilities: Vec<&'static str>,
    /// The subset of `capabilities` keyroost could not verify against the
    /// device (no card channel was available to ask): still offered, but not
    /// proven present. Tri-state per capability: in `capabilities` only =
    /// verified present; in both lists = offered but unverified; in
    /// neither = absent.
    pub capabilities_unverified: Vec<&'static str>,
}

/// One `keyroostctl list --json` row. `device` is the exact value to pass
/// to `--device` (name if unique, else serial, else list number).
#[derive(Serialize)]
pub(crate) struct ListRowJson {
    pub number: usize,
    pub device: String,
    /// The name shown (a key carrying a name another key holds here has its
    /// serial tail appended); `device` is the exact value that selects it.
    pub name: Option<String>,
    /// Where that name lives: "key" or "computer".
    pub name_source: Option<&'static str>,
    pub vendor: String,
    pub model: String,
    pub serial: String,
    pub kind: &'static str,
    pub capabilities: Vec<&'static str>,
    pub capabilities_unverified: Vec<&'static str>,
    pub readers: Vec<String>,
    pub hid_paths: Vec<String>,
}

/// `keyroostctl name --json list`.
#[derive(Serialize)]
pub(crate) struct NamesJson {
    pub names: Vec<NameRowJson>,
}

/// One name this computer knows, or one a connected key carries.
#[derive(Serialize)]
pub(crate) struct NameRowJson {
    /// The name as shown (a key carrying another key's name has its serial
    /// tail appended).
    pub name: String,
    /// "computer" or "key".
    pub stored: &'static str,
    /// "connected", "not-connected", "hidden", "missing-on-key",
    /// "unmatched", "other-key" or "unrecorded".
    pub status: &'static str,
    /// The connected key's `list` number, if any.
    pub number: Option<usize>,
}

/// `keyroostctl molto --json info`.
#[derive(Serialize)]
pub(crate) struct MoltoInfoJson {
    pub serial: String,
    pub utc_time: u32,
    pub drift_seconds: i64,
}

/// `keyroostctl molto --json slots`.
#[derive(Serialize)]
pub(crate) struct MoltoSlotsJson {
    pub serial: String,
    pub slots: Vec<MoltoSlotJson>,
}

/// One element of [`MoltoSlotsJson::slots`] (full parsed block).
/// `time_a`/`time_b` are raw big-endian u32s with unconfirmed semantics.
///
/// `algorithm` and `digits` are `null` for a code keyroost doesn't know;
/// `period` is the stored seconds byte, `null` when 0. An empty slot may
/// still report default values, so use `occupied`.
#[derive(Serialize)]
pub(crate) struct MoltoSlotJson {
    pub slot: u8,
    pub occupied: bool,
    pub title: Option<String>,
    pub flag: u8,
    /// `"sha1"` or `"sha256"`.
    pub algorithm: Option<&'static str>,
    /// TOTP time step in seconds.
    pub period: Option<u8>,
    /// 4, 6, 8 or 10.
    pub digits: Option<u8>,
    pub time_a: u32,
    pub time_b: u32,
}

impl MoltoSlotJson {
    pub(crate) fn from_block(slot: u8, b: &keyroost_proto::commands::ProfilePublicData) -> Self {
        Self {
            slot,
            occupied: b.seed_present,
            title: b.title.clone(),
            flag: b.flag,
            algorithm: match b.algorithm {
                1 => Some("sha1"),
                2 => Some("sha256"),
                _ => None,
            },
            period: (b.time_step != 0).then_some(b.time_step),
            digits: matches!(b.digits, 4 | 6 | 8 | 10).then_some(b.digits),
            time_a: b.time_a,
            time_b: b.time_b,
        }
    }
}

/// `keyroostctl fido --json info` — the CTAP2 authenticatorGetInfo fields the
/// human handler prints (plus the CTAPHID transport facts).
#[derive(Serialize)]
pub(crate) struct FidoInfoJson {
    pub device: String,
    pub channel_id: u32,
    pub ctaphid_protocol_version: u8,
    /// As the vendor states it ("5.7.4", a Solo 2's "2.964", a Token2's
    /// "R3.4"); `null` when the key doesn't say.
    pub firmware: Option<String>,
    pub hid_caps: Vec<&'static str>,
    pub hid_caps_raw: u8,
    /// `null` when the device does not speak CTAP2 (U2F-only).
    pub ctap2: Option<Ctap2InfoJson>,
    /// `null` when keyroost knows nothing about the key's AAGUID.
    pub metadata: Option<FidoMetadataJson>,
}

/// `keyroostctl fido --json info --reader` — a card in a smart-card reader has
/// no CTAPHID facts, so only the reader name and the CTAP2 payload.
#[derive(Serialize)]
pub(crate) struct FidoReaderInfoJson {
    pub device: String,
    /// `null` when the card speaks U2F only.
    pub ctap2: Option<Ctap2InfoJson>,
    /// `null` when keyroost knows nothing about the card's AAGUID.
    pub metadata: Option<FidoMetadataJson>,
}

/// What keyroost knows about a key's AAGUID: its model name and the FIDO
/// Alliance's published metadata (the app's metadata card). Each field is
/// `null` when that source says nothing.
#[derive(Serialize)]
pub(crate) struct FidoMetadataJson {
    /// "YubiKey 5 Series with NFC".
    pub model: Option<String>,
    /// "FIDO Certified L2", "Not FIDO Certified", or an advisory such as
    /// "REVOKED".
    pub certification: Option<String>,
    /// The status as published ("FIDO_CERTIFIED_L2").
    pub status: Option<String>,
    /// The day the status took effect ("2024-12-27").
    pub since: Option<String>,
    /// "fido2", "u2f" or "uaf".
    pub protocol_family: Option<String>,
}

/// The authenticatorGetInfo payload (CTAP2 devices only).
#[derive(Serialize)]
pub(crate) struct Ctap2InfoJson {
    pub versions: Vec<String>,
    pub extensions: Vec<String>,
    pub aaguid: String,
    pub options: Vec<OptionJson>,
    pub max_msg_size: Option<u64>,
    pub pin_uv_auth_protocols: Vec<u64>,
    pub transports: Vec<String>,
    pub min_pin_length: Option<u64>,
    pub force_pin_change: Option<bool>,
    /// Whether a FIDO2 reset needs a long touch (getInfo `0x18`).
    pub long_touch_for_reset: Option<bool>,
    pub firmware_version: Option<u64>,
}

/// One authenticator option (e.g. `{ "name": "rk", "value": true }`).
#[derive(Serialize)]
pub(crate) struct OptionJson {
    pub name: String,
    pub value: bool,
}

/// `keyroostctl fido --json pin status`, named as `otp --json pin status`.
///
/// `pin_set` is getInfo's clientPin option: `false` means no PIN is set,
/// and then `pin_retries` is `null` (some keys still answer a count, others
/// refuse); `null` when the key doesn't say.
#[derive(Serialize)]
pub(crate) struct FidoPinStatusJson {
    pub pin_set: Option<bool>,
    pub pin_retries: Option<u32>,
}

/// `keyroostctl piv --json info`.
#[derive(Serialize)]
pub(crate) struct PivStatusJson {
    /// Yubico GET VERSION's raw reply, dotted (or hex past 4 bytes),
    /// tolerant of any non-empty byte count.
    pub version: Option<String>,
    /// Ordinarily the Yubico GET SERIAL extension; when a specific
    /// fingerprint's own probe supplies a serial instead (currently: a
    /// Nitrokey's admin application), that one is used and GET SERIAL is
    /// skipped — a Nitrokey answers that extension too, but with a number
    /// that isn't its real serial. `None` when neither source answers.
    ///
    /// A string, not a number: a serial can be up to 128 bits (a
    /// Nitrokey's admin serial), and a bare JSON number past 2^53 loses
    /// precision in most consumers. Decimal within `u64`, `0x`-hex
    /// beyond — the same rendering `piv info`'s text output uses.
    pub serial: Option<String>,
    pub pin_retries: Option<u8>,
    /// `true` when the card reported the PIN verified in the session that
    /// read this status (then `pin_retries` is `null`). `piv info` never
    /// verifies the PIN itself, so this is true only when the card kept a
    /// verification from elsewhere.
    pub pin_verified: bool,
    pub chuid: Option<PivChuidJson>,
    pub slots: Vec<PivSlotJson>,
    /// Best-effort applet fingerprint — from ATR/SELECT text as well as
    /// AID-selectability/instruction-support probes; see
    /// `keyroost_piv::fingerprint` for the full scheme. Its `Display`
    /// form — e.g. `"YubiKey"` or `"OpenFips201::SwissbitIShield2"`.
    pub applet_fingerprint: String,
    /// The token's own reported name, when one was actually discovered
    /// (currently: a Nitrokey's admin application, for `Trussed::Nitrokey`).
    /// Empty when none was — not backfilled with a generic name for
    /// `applet_fingerprint`, so an empty string here means specifically
    /// "the token didn't tell us its name," not "fingerprinting failed."
    /// (The plain-text `piv info` output does apply that fallback —
    /// see `run_piv`.)
    pub applet_name: String,
    /// The key's own firmware version, dotted (same formatting as
    /// `version`), when a specific fingerprint's probe discovered one —
    /// currently `Trussed::Nitrokey` (Trussed's admin application) only.
    /// Not necessarily equal to `version`, which is the PIV applet's own
    /// version. `None` when no such probe applies or it found nothing
    /// parseable. Named like `fido --json info`'s `firmware`.
    pub firmware: Option<String>,
    /// Retired name for `firmware`, same value; kept so scripts written
    /// before 0.16 still read it.
    pub version_firmware: Option<String>,
}

/// The card's CHUID — FASC-N, GUID, expiration, signature, and LRC. The
/// CLI is the one place that prints signature/LRC (empty hex in every
/// CHUID this crate itself writes); the GUI status line omits both, and
/// FASC-N besides.
#[derive(Serialize)]
pub(crate) struct PivChuidJson {
    pub fasc_n: String,
    pub guid: String,
    pub expiration: String,
    pub signature: String,
    pub lrc: String,
}

/// One PIV key slot in the status output.
#[derive(Serialize)]
pub(crate) struct PivSlotJson {
    /// The value `--slot` takes for this slot ([`piv_slot_token`]).
    pub slot: String,
    /// Human name, e.g. `"authentication (9A)"`.
    pub slot_name: String,
    pub cert_present: bool,
    pub cert_len: usize,
    /// `damaged` or `too_large` when the slot holds a certificate that
    /// cannot be read (then `cert_present` is true and `cert_len` is 0);
    /// `null` otherwise.
    pub cert_unreadable: Option<&'static str>,
    /// `true` when the certificate is stored gzip-compressed; `cert_len` is
    /// still the DER length.
    pub cert_compressed: bool,
    /// Whether the slot holds a private key: `true`, `false`, or `null` when
    /// keyroost can't tell ([`piv_key_present`]).
    pub key_present: Option<bool>,
}

/// The JSON form of a slot's key presence. Only a definite answer becomes a
/// bool; `Unknown` (and any variant added later) is `null`.
pub(crate) fn piv_key_present(k: keyroost_transport::SlotKeyPresence) -> Option<bool> {
    use keyroost_transport::SlotKeyPresence;
    match k {
        SlotKeyPresence::Present => Some(true),
        SlotKeyPresence::NoKey => Some(false),
        _ => None,
    }
}

/// The value `--slot` takes for this slot: "9a", "9c", "9d", "9e", "82".."95".
pub(crate) fn piv_slot_token(s: keyroost_piv::Slot) -> String {
    format!("{:02x}", s.key_ref())
}

/// `keyroostctl piv --json test`.
#[derive(Serialize)]
pub(crate) struct PivTestJson {
    /// The value `--slot` takes for this slot ([`piv_slot_token`]).
    pub slot: String,
    /// Human name, e.g. `"authentication (9A)"`.
    pub slot_name: String,
    pub algorithm: String,
    /// Whether the slot's certificate was part of the test: `false` when the
    /// slot had none and the test ran against the public key the card
    /// reports for it.
    pub cert_tested: bool,
    /// `true` when no operation failed (skipped ops don't count).
    pub ok: bool,
    pub operations: Vec<PivTestOpJson>,
}

/// One operation in [`PivTestJson::operations`].
#[derive(Serialize)]
pub(crate) struct PivTestOpJson {
    pub operation: String,
    /// `"passed"`, `"failed"`, or `"skipped"`.
    pub result: String,
    /// A short reason for `"failed"`; `null` otherwise.
    pub detail: Option<String>,
}

/// `keyroostctl openpgp --json info`.
#[derive(Serialize)]
pub(crate) struct OpenpgpStatusJson {
    pub aid: String,
    /// The serial as `openpgp info` shows it: a Token2 key's full serial,
    /// else the AID's serial bytes as GnuPG prints them (a YubiKey's
    /// decimal serial, a Nitrokey's hex one). A string, so leading zeros and
    /// hex digits survive any JSON consumer exactly.
    pub serial: Option<String>,
    pub sig_algo: String,
    pub dec_algo: String,
    pub aut_algo: String,
    pub fingerprint_sig: Option<String>,
    pub fingerprint_dec: Option<String>,
    pub fingerprint_aut: Option<String>,
    /// `true` when the slot's public key reads back; `null` when it doesn't
    /// (an empty slot and a card that won't say look the same), never `false`.
    pub key_present_sig: Option<bool>,
    pub key_present_dec: Option<bool>,
    pub key_present_aut: Option<bool>,
    pub user_pin_retries: u8,
    pub reset_code_retries: u8,
    pub admin_pin_retries: u8,
    pub signature_count: Option<u32>,
    /// Cardholder name (`005B`); `null` when unreadable, `""` when unset.
    pub cardholder_name: Option<String>,
    /// Public-key URL (`5F50`); `null` when unreadable, `""` when unset.
    pub url: Option<String>,
    /// The KDF setting (whether PINs reach the card hashed): `"on"`,
    /// `"off"`, `"not-supported"` or `"unrecognized"`; `null` when it
    /// couldn't be read. See [`kdf_json`].
    pub kdf: Option<&'static str>,
}

/// JSON word for [`OpenpgpStatusJson::kdf`]: the text `KDF:` line's state
/// without its detail (the hash, or what wasn't recognized). The words come
/// from `OpenPgpKdf::state_word`, an exhaustive match in its own crate, so
/// a new state can't turn into `null` unnoticed.
pub(crate) fn kdf_json(kdf: Option<&keyroost_transport::OpenPgpKdf>) -> Option<&'static str> {
    kdf.map(keyroost_transport::OpenPgpKdf::state_word)
}

/// JSON form of a tri-state public text field (`cardholder_name`, `url`):
/// unreadable (`None`) stays `null` ("couldn't tell", as CONTRIBUTING's
/// "Words in output and JSON" has it), unset (`Some(None)`) becomes `""`
/// (nothing stored), a value passes through.
pub(crate) fn optional_text_json(v: Option<Option<String>>) -> Option<String> {
    v.map(|inner| inner.unwrap_or_default())
}

/// `openpgp key import` (a new key set, a backup restored, an RSA key file)
/// and `openpgp key expiry`.
#[derive(Serialize)]
pub(crate) struct OpenpgpKeysJson {
    /// The key type made or imported (`ed25519`, `rsa3072`, ...), when one
    /// type covers it all; null for a restored backup and an expiry change.
    pub key_type: Option<&'static str>,
    /// The slots written ("sign", "decrypt", "auth"), in `fingerprints`
    /// order; empty for an expiry change.
    pub slots: Vec<&'static str>,
    /// Fingerprints, hex: one per slot written, or the main key's for an
    /// expiry change.
    pub fingerprints: Vec<String>,
    /// The files written (backup, public key, revocation certificate), read
    /// (the `--in` file), or rewritten (expiry change).
    pub files: Vec<String>,
    /// The last day the keys work (`YYYY-MM-DD`) or "never"; null when the
    /// command doesn't set it.
    pub expires: Option<String>,
}

/// `keyroostctl otp --json serial`.
#[derive(Serialize)]
pub(crate) struct OtpSerialJson {
    pub serial: String,
}

/// `keyroostctl oath --json list` — one stored OATH credential. Mirrors the
/// human line `<name>  [<type>/<algorithm>]`, with `  (touch)` after it when
/// `touch_required`.
#[derive(Serialize)]
pub(crate) struct OathCredentialJson {
    pub name: String,
    /// "TOTP" or "HOTP".
    #[serde(rename = "type")]
    pub oath_type: &'static str,
    /// "sha1" / "sha256" / "sha512" (lowercase, like `molto list`).
    pub algorithm: &'static str,
    /// Whether the account needs a touch to compute, as the key says it;
    /// `null` when the key doesn't say (an HOTP account on a YubiKey).
    pub touch_required: Option<bool>,
}

/// `keyroostctl oath --json code` — the calculated code. The human handler
/// prints only the code; we also carry the credential name that was queried.
#[derive(Serialize)]
pub(crate) struct OathCodeJson {
    pub name: String,
    pub code: String,
}

/// `keyroostctl feitian --json list` — one account of the Feitian OTP applet.
/// Mirrors the human line `<app:account>  [<type>/<algorithm>]  <period>s`,
/// with `  (slot N)` after it for an account in a keyboard slot.
#[derive(Serialize)]
pub(crate) struct FtotpAccountJson {
    /// The name as stored on the key, period prefix included.
    pub name: String,
    /// "default", "1" or "2".
    pub slot: &'static str,
    /// The app part of the stored name (empty when it has none): what
    /// `feitian code --app` and `feitian delete --app` take, as `otp list`'s
    /// `app` is.
    pub app: String,
    /// The account part of the stored name: what `--account` takes.
    pub account: String,
    /// "TOTP" or "HOTP".
    #[serde(rename = "type")]
    pub oath_type: &'static str,
    /// "sha1" / "sha256" (lowercase, like `oath list`).
    pub algorithm: &'static str,
    /// The TOTP period in seconds, from the stored name's prefix (30 when it
    /// has none); `null` for HOTP.
    pub period: Option<u32>,
}

/// `keyroostctl feitian --json info` — what the applet says when selected.
#[derive(Serialize)]
pub(crate) struct FtotpInfoJson {
    /// The applet version, e.g. "1.0.2"; `null` when the key didn't say.
    pub version: Option<String>,
    pub slots: Vec<FtotpSlotJson>,
}

/// One slot in `feitian --json info`.
#[derive(Serialize)]
pub(crate) struct FtotpSlotJson {
    /// "default", "1" or "2".
    pub slot: &'static str,
    /// Whether the slot has an access code; `null` when the key didn't say.
    pub access_code_set: Option<bool>,
}

/// `keyroostctl otp --json list` — one Token2 OTP entry. Mirrors the human
/// line `<app:account>  [<type>/<algo>]  <code|—>  (touch)?`.
#[derive(Serialize)]
pub(crate) struct OtpEntryJson {
    pub app: String,
    pub account: String,
    /// "TOTP" or "HOTP".
    #[serde(rename = "type")]
    pub otp_type: &'static str,
    /// "sha1" / "sha256" (lowercase, like `molto list`).
    pub algorithm: &'static str,
    /// `None` (JSON `null`) when the code is withheld pending a touch (the
    /// human shows an em-dash); present otherwise.
    pub code: Option<String>,
    pub touch_required: bool,
}

/// `keyroostctl otp --json pin status` — the R3.4 OTP-PIN state.
///
/// `supported: false` means the key never answered the flag read, so the
/// three PIN fields are `null`: the feature is not there to report on.
#[derive(Serialize)]
pub(crate) struct OtpPinStatusJson {
    pub supported: bool,
    pub pin_set: Option<bool>,
    pub pin_retries: Option<u8>,
    pub pin_retries_max: Option<u8>,
}

/// `keyroostctl otp --json code` — a single read OTP code.
#[derive(Serialize)]
pub(crate) struct OtpCodeJson {
    pub app: String,
    pub account: String,
    pub code: String,
}

/// `keyroostctl fido --json credential status` — resident-credential counts.
#[derive(Serialize)]
pub(crate) struct FidoCredsMetadataJson {
    pub existing_resident_credentials: u64,
    pub max_possible_remaining: u64,
}

/// `keyroostctl fido --json credential list` — the resident credentials grouped
/// by relying party.
#[derive(Serialize)]
pub(crate) struct FidoCredsListJson {
    pub relying_parties: Vec<FidoRelyingPartyJson>,
}

/// One relying party in the `credential list` output.
#[derive(Serialize)]
pub(crate) struct FidoRelyingPartyJson {
    pub rp_id: String,
    pub rp_name: Option<String>,
    pub credentials: Vec<FidoCredentialJson>,
}

/// One resident credential under a relying party.
#[derive(Serialize)]
pub(crate) struct FidoCredentialJson {
    /// Full hex credentialId (the value `fido credential delete ID` expects).
    pub credential_id: String,
    /// Full hex user handle, like `credential_id`: the handle is bytes, often
    /// not text.
    pub user_id: String,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    pub algorithm: Option<i64>,
    pub algorithm_name: Option<&'static str>,
}

/// `keyroostctl fido --json credential compare` — resident credentials on two
/// keys compared by (relying-party ID, user handle). Credential IDs always
/// differ between keys, so they are not part of the comparison and not shown.
/// The three groups hold distinct identities (`on_both` shows key A's entry);
/// `total_a`/`total_b` are the readable entry counts, as `fido credential
/// list` counts them. Relying parties whose `rpIdHash` came back malformed
/// can't be listed, so their credentials are neither compared nor counted in
/// the totals; per-side counts go in `unavailable_relying_parties_a`/`_b`.
/// The side is a suffix, as OpenPGP's `_sig`/`_dec`/`_aut` fields are.
#[derive(Serialize)]
pub(crate) struct FidoCredCompareJson {
    pub only_on_a: Vec<FidoCredCompareEntryJson>,
    pub only_on_b: Vec<FidoCredCompareEntryJson>,
    pub on_both: Vec<FidoCredCompareEntryJson>,
    pub total_a: usize,
    pub total_b: usize,
    /// Relying parties skipped on each key (malformed `rpIdHash`, as
    /// `fido credential list` reports them).
    pub unavailable_relying_parties_a: usize,
    pub unavailable_relying_parties_b: usize,
}

/// One resident credential in the `credential compare` output.
#[derive(Serialize)]
pub(crate) struct FidoCredCompareEntryJson {
    pub rp_id: String,
    pub rp_name: Option<String>,
    /// The user handle as lowercase hex: most handles are random bytes, and
    /// a lossy UTF-8 rendering could make two different handles look alike.
    pub user_id: String,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
}

/// `keyroostctl fido ssh --json list` — one entry per resident SSH credential
/// (an `ssh:*` relying party), as the text form prints one line each.
#[derive(Serialize)]
pub(crate) struct FidoSshListJson {
    pub credentials: Vec<FidoSshCredentialJson>,
}

/// One resident SSH credential in the `fido ssh list` output.
#[derive(Serialize)]
pub(crate) struct FidoSshCredentialJson {
    pub rp_id: String,
    /// Full hex credentialId, as `fido credential list` gives it.
    pub credential_id: String,
    /// Whether the key's largeBlob store holds an OpenSSH certificate for this
    /// credential (what `fido ssh export` saves).
    pub cert_present: bool,
}

/// `keyroostctl fido vault --json list` — one entry per vault on the key,
/// and how full the large-blob store that holds them is.
#[derive(Serialize)]
pub(crate) struct FidoVaultListJson {
    pub vaults: Vec<FidoVaultJson>,
    pub capacity: FidoLargeBlobCapacityJson,
}

/// One vault in the `fido vault list` output.
#[derive(Serialize)]
pub(crate) struct FidoVaultJson {
    /// The vault's name; `null` when the credential carries none.
    pub name: Option<String>,
    /// Full hex credentialId, as `fido ssh list` gives it.
    pub credential_id: String,
    /// `ok`, `no-data` (opens empty: nothing stored yet) or `unavailable`.
    pub state: &'static str,
    /// How many entries it holds; `null` when it is `unavailable`.
    pub entry_count: Option<usize>,
    /// Why an `unavailable` vault does not open; `null` otherwise.
    pub detail: Option<String>,
}

/// `keyroostctl --json fido vault entry list` — the entries of one vault,
/// without their passwords or notes.
#[derive(Serialize)]
pub(crate) struct FidoVaultEntryListJson {
    /// The vault's name; `null` when the credential carries none.
    pub vault: Option<String>,
    pub entries: Vec<FidoVaultEntryJson>,
}

/// One entry in `fido vault entry list`. Its fields are entry data, wiped
/// when it is dropped.
#[derive(Serialize)]
pub(crate) struct FidoVaultEntryJson {
    /// The entry's id in the vault, as FidoParole stores it.
    pub id: String,
    pub title: String,
    /// `null` when the entry has none.
    pub username: Option<String>,
    /// `null` when the entry has none.
    pub url: Option<String>,
    /// Last changed, `YYYY-MM-DD` (UTC).
    pub changed: String,
}

impl Drop for FidoVaultEntryJson {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.id.zeroize();
        self.title.zeroize();
        self.username.zeroize();
        self.url.zeroize();
    }
}

/// `keyroostctl --json fido vault import` — what the import does with each
/// backup entry, as the preview shows it. Never a password.
#[derive(Serialize)]
pub(crate) struct FidoVaultImportJson {
    /// The vault imported into; `null` when the credential carries no name.
    pub vault: Option<String>,
    /// Whether the import makes the vault (the key had none of that name).
    pub creates: bool,
    pub dry_run: bool,
    pub entries: Vec<FidoVaultImportRowJson>,
}

/// One backup entry in `fido vault import`. Its text is entry data, wiped
/// when it is dropped.
#[derive(Serialize)]
pub(crate) struct FidoVaultImportRowJson {
    /// Its place in the backup, from 0.
    pub index: usize,
    /// The entry's id, as FidoParole stores it.
    pub id: String,
    pub title: String,
    /// `null` when the entry has none.
    pub username: Option<String>,
    /// `add`, `replace`, `exists` or `skip`.
    pub plan: &'static str,
    /// Why a row is not a plain add; `null` for one.
    pub reason: Option<&'static str>,
}

impl Drop for FidoVaultImportRowJson {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.id.zeroize();
        self.title.zeroize();
        self.username.zeroize();
    }
}

/// `keyroostctl --json fido vault entry show` — one entry; the password
/// only with `--reveal`. Every field is wiped when it is dropped.
#[derive(Serialize)]
pub(crate) struct FidoVaultEntryShowJson {
    pub vault: Option<String>,
    pub id: String,
    pub title: String,
    /// `null` when the entry has none, as for `url` and `notes`.
    pub username: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    /// Last changed, `YYYY-MM-DD` (UTC).
    pub changed: String,
    /// The password with `--reveal`; `null` without it (an entry with no
    /// password is `""`).
    pub password: Option<String>,
}

impl Drop for FidoVaultEntryShowJson {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.vault.zeroize();
        self.id.zeroize();
        self.title.zeroize();
        self.username.zeroize();
        self.url.zeroize();
        self.notes.zeroize();
        self.changed.zeroize();
        self.password.zeroize();
    }
}

/// `keyroostctl fido blob --json list` — one entry per stored blob.
#[derive(Serialize)]
pub(crate) struct FidoLargeBlobListJson {
    pub entries: Vec<FidoLargeBlobEntryJson>,
    /// Elements not in the standard entry format: skipped, kept unchanged.
    pub skipped: usize,
    pub capacity: FidoLargeBlobCapacityJson,
}

/// Space accounting for the whole array (serialized form incl. checksum).
#[derive(Serialize)]
pub(crate) struct FidoLargeBlobCapacityJson {
    pub max_bytes: u64,
    pub used_bytes: u64,
    pub free_bytes: u64,
}

/// One large-blob array entry as the `list` view renders it.
#[derive(Serialize)]
pub(crate) struct FidoLargeBlobEntryJson {
    pub index: usize,
    /// Declared plaintext size of the entry (origSize), in bytes.
    pub size: u64,
    /// Whether this entry is a keyroost-authored plaintext note (true) or an
    /// opaque RP-encrypted record (false).
    pub is_note: bool,
    /// The note text when `is_note`, the name for a "key-name" entry; `null`
    /// for other entries.
    pub text: Option<String>,
    /// Entry classification: "note", "key-name" or "opaque".
    pub kind: &'static str,
}

/// `keyroostctl fido blob --json get <INDEX>` — a single entry in full.
#[derive(Serialize)]
pub(crate) struct FidoLargeBlobGetJson {
    pub index: usize,
    pub size: u64,
    pub is_note: bool,
    pub text: Option<String>,
    /// Entry classification: "note", "key-name" or "opaque".
    pub kind: &'static str,
    /// Hex of the raw ciphertext bytes (the note magic + UTF-8 for a note, or
    /// the RP's AEAD ciphertext for an opaque entry).
    pub hex: String,
}

/// `keyroostctl prog --json info`.
#[derive(Serialize)]
pub(crate) struct ProgInfoJson {
    pub serial: String,
    pub model: Option<String>,
    pub utc_time: u32,
}

/// `keyroostctl --json oath import` / `otp import`: the plan, plus each
/// write's outcome after a real run (a dry run has no outcomes). Names
/// only, never a seed.
#[derive(Serialize)]
pub(crate) struct ImportJson {
    /// "oath", "otp" or "molto2".
    pub destination: &'static str,
    pub dry_run: bool,
    /// How many codes the key holds in all, when known (Molto2: the slots
    /// from the first one to #99).
    pub capacity: Option<usize>,
    /// Codes already on the key (Molto2: slots in use); null when the key
    /// wasn't read (a Molto2 dry run with no Molto2 connected).
    pub on_key: Option<usize>,
    pub entries: Vec<ImportRowJson>,
    /// Why the run stopped early, if it did.
    pub stopped: Option<String>,
}

/// One entry of the file in [`ImportJson`].
#[derive(Serialize)]
pub(crate) struct ImportRowJson {
    /// Position in the file, counting from 0.
    pub index: usize,
    /// The entry as the file names it.
    pub label: String,
    /// The name it is stored under on the key, when it has one.
    pub name: Option<String>,
    /// "add", "replace", "exists" or "skip".
    pub plan: &'static str,
    /// The code will require a touch on the key (`--touch`,
    /// `--touch-for`); false for a code that isn't written. The name
    /// `otp list --json` uses for the same fact.
    pub touch_required: bool,
    /// Why it is skipped or left as is.
    pub reason: Option<String>,
    /// After a run: "added", "replaced", "exists",
    /// "removed-not-added", "failed", "no-room" or "not-tried".
    pub outcome: Option<&'static str>,
    /// The key's error for "failed" and "removed-not-added".
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn kind(v: &Value) -> &'static str {
        match v {
            Value::Null => "null",
            Value::Bool(_) => "bool",
            Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
        }
    }

    /// `v` is an object with exactly these keys, each of one of the `|`-separated kinds.
    #[track_caller]
    fn assert_shape(v: &Value, want: &[(&str, &str)]) {
        let obj = v
            .as_object()
            .unwrap_or_else(|| panic!("not an object: {v}"));
        let mut got: Vec<&str> = obj.keys().map(String::as_str).collect();
        got.sort_unstable();
        let mut exp: Vec<&str> = want.iter().map(|(k, _)| *k).collect();
        exp.sort_unstable();
        assert_eq!(got, exp, "keys of {v}");
        for (k, kinds) in want {
            assert!(
                kinds.split('|').any(|t| t == kind(&obj[*k])),
                "{k}: {} is not {kinds}",
                kind(&obj[*k])
            );
        }
    }

    fn to_v<T: Serialize>(t: &T) -> Value {
        serde_json::to_value(t).unwrap()
    }

    fn block(
        algorithm: u8,
        time_step: u8,
        digits: u8,
        title: Option<&str>,
    ) -> keyroost_proto::commands::ProfilePublicData {
        keyroost_proto::commands::ProfilePublicData {
            flag: 0,
            title: title.map(str::to_string),
            time_a: 1,
            time_b: 2,
            algorithm,
            time_step,
            digits,
            seed_present: title.is_some(),
        }
    }

    #[test]
    fn no_field_is_ever_omitted() {
        assert!(!include_str!("json_out.rs").contains(concat!("skip_serializing", "_if")));
    }

    #[test]
    fn molto_slot_shape_with_and_without_data() {
        let shape = [
            ("slot", "number"),
            ("occupied", "bool"),
            ("title", "string|null"),
            ("flag", "number"),
            ("algorithm", "string|null"),
            ("period", "number|null"),
            ("digits", "number|null"),
            ("time_a", "number"),
            ("time_b", "number"),
        ];
        for (alg, step, digits, title) in [
            (1u8, 30u8, 6u8, Some("a")),
            (0, 0, 0, None),
            (3, 45, 7, None),
        ] {
            let v = to_v(&MoltoSlotJson::from_block(
                7,
                &block(alg, step, digits, title),
            ));
            assert_shape(&v, &shape);
        }
        let v = to_v(&MoltoSlotJson::from_block(7, &block(2, 60, 8, None)));
        assert_eq!(
            (
                v["algorithm"].as_str(),
                v["period"].as_u64(),
                v["digits"].as_u64()
            ),
            (Some("sha256"), Some(60), Some(8))
        );
        let v = to_v(&MoltoSlotJson::from_block(7, &block(3, 45, 7, None)));
        assert!(v["algorithm"].is_null() && v["digits"].is_null()); // unknown codes are null, period is the byte
        assert_eq!(v["period"].as_u64(), Some(45));
        let v = to_v(&MoltoSlotJson::from_block(7, &block(0, 0, 0, None)));
        assert!(v["algorithm"].is_null() && v["period"].is_null() && v["digits"].is_null());
        assert!(v["title"].is_null());
    }

    /// `oath import` / `otp import` / `molto import --in --json`: every key
    /// present, `null` where a dry run or a plain add has no value (and
    /// `on_key` where a Molto2 dry run had no Molto2 to read).
    #[test]
    fn import_shape_with_and_without_outcomes() {
        let top = [
            ("destination", "string"),
            ("dry_run", "bool"),
            ("capacity", "number|null"),
            ("on_key", "number|null"),
            ("entries", "array"),
            ("stopped", "string|null"),
        ];
        let row = [
            ("index", "number"),
            ("label", "string"),
            ("name", "string|null"),
            ("plan", "string"),
            ("touch_required", "bool"),
            ("reason", "string|null"),
            ("outcome", "string|null"),
            ("error", "string|null"),
        ];
        let bare = ImportRowJson {
            index: 0,
            label: "entry 1".into(),
            name: None,
            plan: "skip",
            touch_required: false,
            reason: None,
            outcome: None,
            error: None,
        };
        let full = ImportRowJson {
            index: 1,
            label: "A:a".into(),
            name: Some("A:a".into()),
            plan: "add",
            touch_required: true,
            reason: Some("r".into()),
            outcome: Some("failed"),
            error: Some("e".into()),
        };
        for (capacity, on_key, stopped, rows) in [
            (None, None, None, vec![bare]),
            (
                Some(32),
                Some(0),
                Some("the key is full".to_owned()),
                vec![full],
            ),
        ] {
            let v = to_v(&ImportJson {
                destination: "oath",
                dry_run: capacity.is_none(),
                capacity,
                on_key,
                entries: rows,
                stopped,
            });
            assert_shape(&v, &top);
            assert_shape(&v["entries"][0], &row);
        }
    }

    #[test]
    fn empty_lists_are_present_arrays() {
        let v = to_v(&KeysJson::<ListRowJson> { keys: vec![] });
        assert_eq!(v, serde_json::json!({"keys": []}));
        let v = to_v(&AccountsJson::<OathCredentialJson> { accounts: vec![] });
        assert_eq!(v, serde_json::json!({"accounts": []}));
    }

    #[test]
    fn device_json_shape() {
        let shape = [
            ("vendor", "string"),
            ("model", "string"),
            ("name", "string|null"),
            ("name_source", "string|null"),
            ("serial", "string"),
            ("transport", "string"),
            ("kind", "string"),
            ("capabilities", "array"),
            ("capabilities_unverified", "array"),
        ];
        for name in [Some("work".to_string()), None] {
            let d = DeviceJson {
                vendor: "V".into(),
                model: "M".into(),
                name_source: name.as_ref().map(|_| "computer"),
                name,
                serial: "1".into(),
                transport: "USB".into(),
                kind: "key",
                capabilities: vec!["FIDO2"],
                capabilities_unverified: vec![],
            };
            let v = to_v(&KeysJson { keys: vec![d] });
            assert_shape(&v, &[("keys", "array")]);
            assert_shape(&v["keys"][0], &shape);
        }
    }

    #[test]
    fn list_row_shape() {
        let shape = [
            ("number", "number"),
            ("device", "string"),
            ("name", "string|null"),
            ("name_source", "string|null"),
            ("vendor", "string"),
            ("model", "string"),
            ("serial", "string"),
            ("kind", "string"),
            ("capabilities", "array"),
            ("capabilities_unverified", "array"),
            ("readers", "array"),
            ("hid_paths", "array"),
        ];
        for name in [Some("work".to_string()), None] {
            let r = ListRowJson {
                number: 1,
                device: "1".into(),
                name_source: name.as_ref().map(|_| "key"),
                name,
                vendor: "V".into(),
                model: "M".into(),
                serial: "1".into(),
                kind: "key",
                capabilities: vec![],
                capabilities_unverified: vec![],
                readers: vec![],
                hid_paths: vec![],
            };
            let v = to_v(&KeysJson { keys: vec![r] });
            assert_shape(&v, &[("keys", "array")]);
            assert_shape(&v["keys"][0], &shape);
        }
    }

    #[test]
    fn molto_info_shape() {
        let v = to_v(&MoltoInfoJson {
            serial: "S".into(),
            utc_time: 5,
            drift_seconds: -3,
        });
        assert_shape(
            &v,
            &[
                ("serial", "string"),
                ("utc_time", "number"),
                ("drift_seconds", "number"),
            ],
        );
    }

    #[test]
    fn prog_info_shape() {
        for model in [Some("C302".to_string()), None] {
            let v = to_v(&ProgInfoJson {
                serial: "S".into(),
                model,
                utc_time: 5,
            });
            assert_shape(
                &v,
                &[
                    ("serial", "string"),
                    ("model", "string|null"),
                    ("utc_time", "number"),
                ],
            );
        }
    }

    #[test]
    fn fido_metadata_shape() {
        for known in [true, false] {
            let v = to_v(&FidoMetadataJson {
                model: Some("YubiKey 5 Series with NFC".into()),
                certification: known.then(|| "FIDO Certified L2".into()),
                status: known.then(|| "FIDO_CERTIFIED_L2".into()),
                since: known.then(|| "2024-12-27".into()),
                protocol_family: known.then(|| "fido2".into()),
            });
            assert_shape(
                &v,
                &[
                    ("model", "string|null"),
                    ("certification", "string|null"),
                    ("status", "string|null"),
                    ("since", "string|null"),
                    ("protocol_family", "string|null"),
                ],
            );
        }
    }

    #[test]
    fn fido_info_shape_u2f_only_and_ctap2() {
        let top = [
            ("device", "string"),
            ("channel_id", "number"),
            ("ctaphid_protocol_version", "number"),
            ("firmware", "string|null"),
            ("hid_caps", "array"),
            ("hid_caps_raw", "number"),
            ("ctap2", "object|null"),
            ("metadata", "object|null"),
        ];
        let inner = [
            ("versions", "array"),
            ("extensions", "array"),
            ("aaguid", "string"),
            ("options", "array"),
            ("max_msg_size", "number|null"),
            ("pin_uv_auth_protocols", "array"),
            ("transports", "array"),
            ("min_pin_length", "number|null"),
            ("force_pin_change", "bool|null"),
            ("long_touch_for_reset", "bool|null"),
            ("firmware_version", "number|null"),
        ];
        let info = |ctap2| FidoInfoJson {
            device: "/dev/hidraw0".into(),
            channel_id: 1,
            ctaphid_protocol_version: 2,
            firmware: Some("1.2.3".into()),
            hid_caps: vec!["WINK"],
            hid_caps_raw: 1,
            ctap2,
            metadata: None,
        };
        let v = to_v(&info(None));
        assert_shape(&v, &top);
        assert!(v["ctap2"].is_null());
        for some in [true, false] {
            let c = Ctap2InfoJson {
                versions: vec!["FIDO_2_0".into()],
                extensions: vec![],
                aaguid: "00".into(),
                options: vec![OptionJson {
                    name: "rk".into(),
                    value: true,
                }],
                max_msg_size: some.then_some(1200),
                pin_uv_auth_protocols: vec![2, 1],
                transports: vec![],
                min_pin_length: some.then_some(4),
                force_pin_change: some.then_some(false),
                long_touch_for_reset: some.then_some(true),
                firmware_version: some.then_some(7),
            };
            let v = to_v(&info(Some(c)));
            assert_shape(&v, &top);
            assert_shape(&v["ctap2"], &inner);
        }
    }

    #[test]
    fn piv_status_slot_shape() {
        let shape = [
            ("slot", "string"),
            ("slot_name", "string"),
            ("cert_present", "bool"),
            ("cert_len", "number"),
            ("cert_unreadable", "string|null"),
            ("cert_compressed", "bool"),
            ("key_present", "bool|null"),
        ];
        let slot = keyroost_piv::Slot::Authentication;
        for (unreadable, compressed) in [(Some("damaged"), false), (None, true), (None, false)] {
            let v = to_v(&PivSlotJson {
                slot: piv_slot_token(slot),
                slot_name: slot.label(),
                cert_present: true,
                cert_len: 0,
                cert_unreadable: unreadable,
                cert_compressed: compressed,
                key_present: Some(true),
            });
            assert_shape(&v, &shape);
            assert_eq!(v["slot"], "9a");
            assert_eq!(v["slot_name"], "authentication (9A)");
        }
    }

    #[test]
    fn piv_key_present_maps_all_three() {
        use keyroost_transport::SlotKeyPresence;
        assert_eq!(piv_key_present(SlotKeyPresence::Present), Some(true));
        assert_eq!(piv_key_present(SlotKeyPresence::NoKey), Some(false));
        assert_eq!(piv_key_present(SlotKeyPresence::Unknown), None);
    }

    #[test]
    fn piv_status_shape() {
        let shape = [
            ("version", "string|null"),
            ("serial", "string|null"),
            ("pin_retries", "number|null"),
            ("pin_verified", "bool"),
            ("chuid", "object|null"),
            ("slots", "array"),
            ("applet_fingerprint", "string"),
            ("applet_name", "string"),
            ("firmware", "string|null"),
            ("version_firmware", "string|null"),
        ];
        for some in [true, false] {
            let v = to_v(&PivStatusJson {
                version: some.then(|| "5.7.1".to_string()),
                serial: some.then(|| "12345678".to_string()),
                pin_retries: some.then_some(3),
                pin_verified: !some,
                chuid: some.then(|| PivChuidJson {
                    fasc_n: "d4".into(),
                    guid: "00".into(),
                    expiration: "2030-01-01".into(),
                    signature: String::new(),
                    lrc: String::new(),
                }),
                slots: vec![],
                applet_fingerprint: "YubiKey".into(),
                applet_name: String::new(),
                firmware: some.then(|| "1.0.0".to_string()),
                version_firmware: some.then(|| "1.0.0".to_string()),
            });
            assert_shape(&v, &shape);
            if some {
                assert_shape(
                    &v["chuid"],
                    &[
                        ("fasc_n", "string"),
                        ("guid", "string"),
                        ("expiration", "string"),
                        ("signature", "string"),
                        ("lrc", "string"),
                    ],
                );
            }
        }
    }

    #[test]
    fn piv_test_shape() {
        let slot = keyroost_piv::Slot::retired(1).unwrap();
        for detail in [Some("mismatch".to_string()), None] {
            let v = to_v(&PivTestJson {
                slot: piv_slot_token(slot),
                slot_name: slot.label(),
                algorithm: "ECCP256".into(),
                cert_tested: true,
                ok: detail.is_none(),
                operations: vec![PivTestOpJson {
                    operation: "sign".into(),
                    result: "passed".into(),
                    detail,
                }],
            });
            assert_shape(
                &v,
                &[
                    ("slot", "string"),
                    ("slot_name", "string"),
                    ("algorithm", "string"),
                    ("cert_tested", "bool"),
                    ("ok", "bool"),
                    ("operations", "array"),
                ],
            );
            assert_eq!(v["slot"], "82");
            assert_shape(
                &v["operations"][0],
                &[
                    ("operation", "string"),
                    ("result", "string"),
                    ("detail", "string|null"),
                ],
            );
        }
    }

    #[test]
    fn openpgp_status_shape() {
        let shape = [
            ("aid", "string"),
            ("serial", "string|null"),
            ("sig_algo", "string"),
            ("dec_algo", "string"),
            ("aut_algo", "string"),
            ("fingerprint_sig", "string|null"),
            ("fingerprint_dec", "string|null"),
            ("fingerprint_aut", "string|null"),
            ("key_present_sig", "bool|null"),
            ("key_present_dec", "bool|null"),
            ("key_present_aut", "bool|null"),
            ("user_pin_retries", "number"),
            ("reset_code_retries", "number"),
            ("admin_pin_retries", "number"),
            ("signature_count", "number|null"),
            ("cardholder_name", "string|null"),
            ("url", "string|null"),
            ("kdf", "string|null"),
        ];
        let status = |serial: Option<u32>, fpr: Option<String>| OpenpgpStatusJson {
            aid: "D276".into(),
            serial: serial.map(|s| s.to_string()),
            sig_algo: "RSA-2048".into(),
            dec_algo: "RSA-2048".into(),
            aut_algo: "RSA-2048".into(),
            fingerprint_sig: fpr.clone(),
            fingerprint_dec: fpr.clone(),
            fingerprint_aut: fpr.clone(),
            key_present_sig: Some(true),
            key_present_dec: None,
            key_present_aut: None,
            user_pin_retries: 3,
            reset_code_retries: 0,
            admin_pin_retries: 3,
            signature_count: fpr.as_ref().map(|_| 9),
            cardholder_name: None,
            url: None,
            kdf: Some("on"),
        };
        let v = to_v(&status(Some(0x0000_0001), Some("AB".into())));
        assert_shape(&v, &shape);
        assert_eq!(v["serial"], "1");
        let v = to_v(&status(Some(0x0123_4567), None));
        assert_shape(&v, &shape);
        assert_eq!(v["serial"], "19088743");
        let v = to_v(&status(None, None));
        assert_shape(&v, &shape);
        assert!(v["serial"].is_null());
    }

    #[test]
    fn kdf_json_words() {
        use keyroost_openpgp::{KdfError, KdfHash};
        use keyroost_transport::OpenPgpKdf;
        assert_eq!(kdf_json(Some(&OpenPgpKdf::On(KdfHash::Sha512))), Some("on"));
        assert_eq!(kdf_json(Some(&OpenPgpKdf::Off)), Some("off"));
        assert_eq!(
            kdf_json(Some(&OpenPgpKdf::NotSupported)),
            Some("not-supported")
        );
        assert_eq!(
            kdf_json(Some(&OpenPgpKdf::Unrecognized(KdfError::UnknownHash(9)))),
            Some("unrecognized")
        );
        assert_eq!(kdf_json(None), None);
    }

    #[test]
    fn optional_text_json_keeps_unset_distinct_from_unreadable() {
        assert_eq!(optional_text_json(None), None);
        assert_eq!(optional_text_json(Some(None)), Some(String::new()));
        assert_eq!(
            optional_text_json(Some(Some("Doe<<John".to_string()))),
            Some("Doe<<John".to_string())
        );
    }

    #[test]
    fn oath_accounts_shape() {
        let v = to_v(&AccountsJson {
            accounts: vec![OathCredentialJson {
                name: "a".into(),
                oath_type: "TOTP",
                algorithm: "sha1",
                touch_required: Some(true),
            }],
        });
        assert_shape(&v, &[("accounts", "array")]);
        assert_shape(
            &v["accounts"][0],
            &[
                ("name", "string"),
                ("type", "string"),
                ("algorithm", "string"),
                ("touch_required", "bool|null"),
            ],
        );
        assert_eq!(v["accounts"][0]["algorithm"], "sha1");
        // Unknown is null, and the key is still present.
        let v = to_v(&AccountsJson {
            accounts: vec![OathCredentialJson {
                name: "h".into(),
                oath_type: "HOTP",
                algorithm: "sha1",
                touch_required: None,
            }],
        });
        assert!(v["accounts"][0]
            .get("touch_required")
            .is_some_and(serde_json::Value::is_null));
    }

    #[test]
    fn otp_accounts_shape() {
        for code in [Some("123456".to_string()), None] {
            let v = to_v(&AccountsJson {
                accounts: vec![OtpEntryJson {
                    app: "a".into(),
                    account: "b".into(),
                    otp_type: "TOTP",
                    algorithm: "sha1",
                    touch_required: code.is_none(),
                    code,
                }],
            });
            assert_shape(&v, &[("accounts", "array")]);
            assert_shape(
                &v["accounts"][0],
                &[
                    ("app", "string"),
                    ("account", "string"),
                    ("type", "string"),
                    ("algorithm", "string"),
                    ("code", "string|null"),
                    ("touch_required", "bool"),
                ],
            );
            assert_eq!(v["accounts"][0]["algorithm"], "sha1");
        }
    }

    #[test]
    fn otp_pin_status_shape() {
        let shape = [
            ("supported", "bool"),
            ("pin_set", "bool|null"),
            ("pin_retries", "number|null"),
            ("pin_retries_max", "number|null"),
        ];
        let v = to_v(&OtpPinStatusJson {
            supported: true,
            pin_set: Some(true),
            pin_retries: Some(3),
            pin_retries_max: Some(8),
        });
        assert_shape(&v, &shape);
        let v = to_v(&OtpPinStatusJson {
            supported: false,
            pin_set: None,
            pin_retries: None,
            pin_retries_max: None,
        });
        assert_shape(&v, &shape);
    }

    #[test]
    fn creds_list_shape() {
        for some in [true, false] {
            let v = to_v(&FidoCredsListJson {
                relying_parties: vec![FidoRelyingPartyJson {
                    rp_id: "example.com".into(),
                    rp_name: some.then(|| "Example".to_string()),
                    credentials: vec![FidoCredentialJson {
                        credential_id: "00".into(),
                        user_id: "u".into(),
                        user_name: some.then(|| "n".to_string()),
                        user_display_name: some.then(|| "d".to_string()),
                        algorithm: some.then_some(-7),
                        algorithm_name: some.then_some("ES256"),
                    }],
                }],
            });
            assert_shape(&v, &[("relying_parties", "array")]);
            let rp = &v["relying_parties"][0];
            assert_shape(
                rp,
                &[
                    ("rp_id", "string"),
                    ("rp_name", "string|null"),
                    ("credentials", "array"),
                ],
            );
            assert_shape(
                &rp["credentials"][0],
                &[
                    ("credential_id", "string"),
                    ("user_id", "string"),
                    ("user_name", "string|null"),
                    ("user_display_name", "string|null"),
                    ("algorithm", "number|null"),
                    ("algorithm_name", "string|null"),
                ],
            );
        }
    }

    #[test]
    fn creds_compare_shape() {
        let entry = |rp: &str, user_id: &str| FidoCredCompareEntryJson {
            rp_id: rp.into(),
            rp_name: Some("Example".into()),
            user_id: user_id.into(),
            user_name: Some("n".into()),
            user_display_name: None,
        };
        let v = to_v(&FidoCredCompareJson {
            only_on_a: vec![entry("example.com", "75")],
            only_on_b: vec![entry("other.example", "76")],
            on_both: vec![entry("both.example", "77")],
            total_a: 2,
            total_b: 2,
            unavailable_relying_parties_a: 1,
            unavailable_relying_parties_b: 0,
        });
        assert_shape(
            &v,
            &[
                ("only_on_a", "array"),
                ("only_on_b", "array"),
                ("on_both", "array"),
                ("total_a", "number"),
                ("total_b", "number"),
                ("unavailable_relying_parties_a", "number"),
                ("unavailable_relying_parties_b", "number"),
            ],
        );
        for group in ["only_on_a", "only_on_b", "on_both"] {
            assert_shape(
                &v[group][0],
                &[
                    ("rp_id", "string"),
                    ("rp_name", "string|null"),
                    ("user_id", "string"),
                    ("user_name", "string|null"),
                    ("user_display_name", "string|null"),
                ],
            );
        }
    }

    #[test]
    fn ssh_list_shape() {
        for cert_present in [true, false] {
            let v = to_v(&FidoSshListJson {
                credentials: vec![FidoSshCredentialJson {
                    rp_id: "ssh:".into(),
                    credential_id: "00".into(),
                    cert_present,
                }],
            });
            assert_shape(&v, &[("credentials", "array")]);
            assert_shape(
                &v["credentials"][0],
                &[
                    ("rp_id", "string"),
                    ("credential_id", "string"),
                    ("cert_present", "bool"),
                ],
            );
        }
        let empty = to_v(&FidoSshListJson {
            credentials: Vec::new(),
        });
        assert_shape(&empty, &[("credentials", "array")]);
    }

    #[test]
    fn large_blob_entry_shape() {
        let entry_shape = [
            ("index", "number"),
            ("size", "number"),
            ("is_note", "bool"),
            ("text", "string|null"),
            ("kind", "string"),
        ];
        let entries = vec![
            FidoLargeBlobEntryJson {
                index: 0,
                size: 2,
                is_note: true,
                text: Some("hi".into()),
                kind: "note",
            },
            FidoLargeBlobEntryJson {
                index: 1,
                size: 9,
                is_note: false,
                text: None,
                kind: "opaque",
            },
        ];
        let v = to_v(&FidoLargeBlobListJson {
            entries,
            skipped: 2,
            capacity: FidoLargeBlobCapacityJson {
                max_bytes: 1024,
                used_bytes: 17,
                free_bytes: 1007,
            },
        });
        for e in v["entries"].as_array().unwrap() {
            assert_shape(e, &entry_shape);
        }
        assert_eq!(v["skipped"], 2);
        assert!(v["entries"][1]["text"].is_null());

        let mut get_shape = entry_shape.to_vec();
        get_shape.push(("hex", "string"));
        for text in [Some("hi".to_string()), None] {
            let v = to_v(&FidoLargeBlobGetJson {
                index: 0,
                size: 2,
                is_note: text.is_some(),
                text,
                kind: "note",
                hex: "00".into(),
            });
            assert_shape(&v, &get_shape);
        }
    }
}
