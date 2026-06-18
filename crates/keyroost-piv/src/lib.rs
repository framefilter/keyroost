//! PIV (Personal Identity Verification — NIST SP 800-73-4 / FIPS 201) byte layer.
//!
//! A pure, I/O-free APDU builder + parser layer for the PIV smartcard
//! application, the same shape as [`keyroost_oath`] and [`keyroost_openpgp`]: it
//! turns intentions into APDU byte vectors and response bytes into typed values,
//! and performs **no card I/O** (that lives in `keyroost-transport`'s
//! `PivSession`). PIV is a CCID/APDU applet on YubiKeys (and other PIV cards),
//! reachable over the same PC/SC layer keyroost already uses.
//!
//! # Scope
//!
//! Covers the full management surface: SELECT, GET DATA, the Yubico
//! version/serial/metadata extensions, PIN-retry querying (the read path), plus
//! GENERAL AUTHENTICATE (management-key mutual auth and key-slot signing),
//! GENERATE ASYMMETRIC KEY PAIR, PUT DATA (certificate import), CHANGE
//! REFERENCE DATA / RESET RETRY COUNTER (PIN/PUK), and the Yubico SET MANAGEMENT
//! KEY / SET PIN RETRIES / RESET extensions. The block-cipher math for the
//! management-key challenge/response lives in `keyroost-transport` (where the
//! cipher dependency is); this layer stays pure and I/O-free.

#![forbid(unsafe_code)]

use keyroost_proto::apdu::{build_apdu, build_apdu_get};

pub mod spki;
pub mod x509;
pub mod x509_parse;

/// PIV card-application AID (the 5-byte RID/PIX prefix; the card matches on it).
/// Full PIV AID is `A0 00 00 03 08 00 00 10 00 01 00`; selecting by the prefix
/// is what `yubikey-piv-tool` / `ykman` do and the card resolves it.
pub const AID: [u8; 5] = [0xA0, 0x00, 0x00, 0x03, 0x08];

/// Status word: success.
pub const SW_OK: u16 = 0x9000;
/// First byte of a `61xx` "more data available" status word.
pub const SW_MORE_DATA: u8 = 0x61;
/// File/application or object not found (e.g. an empty certificate slot).
pub const SW_NOT_FOUND: u16 = 0x6A82;

/// Security status not satisfied (a write needed an auth/PIN that wasn't done).
pub const SW_SECURITY_NOT_SATISFIED: u16 = 0x6982;
/// Authentication method blocked (PIN/PUK exhausted, or RESET preconditions
/// unmet).
pub const SW_AUTH_BLOCKED: u16 = 0x6983;
/// Reference data (key/PIN) not found.
pub const SW_REFERENCE_NOT_FOUND: u16 = 0x6A88;

/// PIN reference (P2) for the PIV application PIN.
pub const PIN_REF_APPLICATION: u8 = 0x80;
/// PIN reference (P2) for the PUK.
pub const PIN_REF_PUK: u8 = 0x81;
/// Key reference (P2) for the card-management (9B) key.
pub const KEY_REF_MANAGEMENT: u8 = 0x9B;

/// PIV / Yubico-PIV instruction bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Instruction {
    /// SELECT (ISO 7816) — activate the PIV application by AID.
    Select = 0xA4,
    /// VERIFY — present the PIN (or query its retry counter with an empty body).
    Verify = 0x20,
    /// GET DATA — read a PIV data object (certificate, CHUID, …).
    GetData = 0xCB,
    /// GET RESPONSE — pull the next chunk of a `61xx`-chained reply.
    GetResponse = 0xC0,
    /// GENERAL AUTHENTICATE — management-key mutual auth and key-slot signing.
    GeneralAuthenticate = 0x87,
    /// GENERATE ASYMMETRIC KEY PAIR — create a key in a slot, return its public key.
    GenerateKeyPair = 0x47,
    /// PUT DATA — write a data object (e.g. a slot's certificate).
    PutData = 0xDB,
    /// CHANGE REFERENCE DATA — change the PIN or PUK.
    ChangeReference = 0x24,
    /// RESET RETRY COUNTER — unblock the PIN using the PUK.
    ResetRetryCounter = 0x2C,
    /// Yubico extension: GET VERSION (applet/firmware version, 3 bytes).
    GetVersion = 0xFD,
    /// Yubico extension: GET SERIAL (4-byte device serial; firmware 5+).
    GetSerial = 0xF8,
    /// Yubico extension: GET METADATA (key/PIN algorithm, policy, retries; fw 5.3+).
    GetMetadata = 0xF7,
    /// Yubico extension: SET MANAGEMENT KEY (9B).
    SetManagementKey = 0xFF,
    /// Yubico extension: SET PIN RETRIES (PIN + PUK try counts).
    SetPinRetries = 0xFA,
    /// Yubico extension: RESET the PIV application (only when PIN and PUK blocked).
    Reset = 0xFB,
}

impl Instruction {
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}

const INS_SELECT_P1_BY_AID: u8 = 0x04;
/// P1-P2 addressing the data-object namespace for GET DATA.
const GET_DATA_P1: u8 = 0x3F;
const GET_DATA_P2: u8 = 0xFF;
/// BER tag introducing a GET DATA object selector.
const TAG_OBJECT_SELECTOR: u8 = 0x5C;
/// BER tag wrapping a GET DATA response payload.
const TAG_DATA_TEMPLATE: u8 = 0x53;
/// BER tag for the GENERAL AUTHENTICATE dynamic-authentication template.
const TAG_DYN_AUTH: u8 = 0x7C;

/// The four PIV asymmetric key slots, identified by their key reference and the
/// certificate data object that holds the slot's X.509 certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    /// `9A` — PIV Authentication.
    Authentication,
    /// `9C` — Digital Signature.
    Signature,
    /// `9D` — Key Management (decryption).
    KeyManagement,
    /// `9E` — Card Authentication.
    CardAuthentication,
}

impl Slot {
    /// The key-reference byte (`9A`/`9C`/`9D`/`9E`).
    #[must_use]
    pub const fn key_ref(self) -> u8 {
        match self {
            Slot::Authentication => 0x9A,
            Slot::Signature => 0x9C,
            Slot::KeyManagement => 0x9D,
            Slot::CardAuthentication => 0x9E,
        }
    }

    /// The 3-byte certificate data-object tag for this slot (`5F C1 0x`).
    #[must_use]
    pub const fn cert_object_tag(self) -> [u8; 3] {
        match self {
            Slot::Authentication => [0x5F, 0xC1, 0x05],
            Slot::Signature => [0x5F, 0xC1, 0x0A],
            Slot::KeyManagement => [0x5F, 0xC1, 0x0B],
            Slot::CardAuthentication => [0x5F, 0xC1, 0x01],
        }
    }

    /// Short human label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Slot::Authentication => "authentication (9A)",
            Slot::Signature => "signature (9C)",
            Slot::KeyManagement => "key management (9D)",
            Slot::CardAuthentication => "card authentication (9E)",
        }
    }

    /// All four slots, in canonical order.
    #[must_use]
    pub const fn all() -> [Slot; 4] {
        [
            Slot::Authentication,
            Slot::Signature,
            Slot::KeyManagement,
            Slot::CardAuthentication,
        ]
    }
}

/// CHUID (Card Holder Unique Identifier) data-object tag.
pub const OBJECT_CHUID: [u8; 3] = [0x5F, 0xC1, 0x02];

/// Management-key (9B) cipher algorithm. The card stores one of these; auth
/// uses a witness/challenge round whose block size this dictates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MgmtAlg {
    /// 3DES (TDEA) — pre-5.7 YubiKey default; 24-byte key, 8-byte block.
    TripleDes,
    /// AES-128 — 16-byte key, 16-byte block.
    Aes128,
    /// AES-192 — 24-byte key, 16-byte block; the YubiKey 5.7+ default.
    Aes192,
    /// AES-256 — 32-byte key, 16-byte block.
    Aes256,
}

impl MgmtAlg {
    /// PIV algorithm identifier byte.
    #[must_use]
    pub const fn id(self) -> u8 {
        match self {
            MgmtAlg::TripleDes => 0x03,
            MgmtAlg::Aes128 => 0x08,
            MgmtAlg::Aes192 => 0x0A,
            MgmtAlg::Aes256 => 0x0C,
        }
    }

    /// Resolve a PIV algorithm identifier (e.g. from GET METADATA tag 0x01).
    #[must_use]
    pub const fn from_id(id: u8) -> Option<Self> {
        match id {
            0x03 => Some(MgmtAlg::TripleDes),
            0x08 => Some(MgmtAlg::Aes128),
            0x0A => Some(MgmtAlg::Aes192),
            0x0C => Some(MgmtAlg::Aes256),
            _ => None,
        }
    }

    /// Cipher block size (= witness/challenge length): 8 for 3DES, 16 for AES.
    #[must_use]
    pub const fn block_size(self) -> usize {
        match self {
            MgmtAlg::TripleDes => 8,
            _ => 16,
        }
    }

    /// Expected key length in bytes.
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            MgmtAlg::TripleDes | MgmtAlg::Aes192 => 24,
            MgmtAlg::Aes128 => 16,
            MgmtAlg::Aes256 => 32,
        }
    }

    /// Short human label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            MgmtAlg::TripleDes => "3DES",
            MgmtAlg::Aes128 => "AES-128",
            MgmtAlg::Aes192 => "AES-192",
            MgmtAlg::Aes256 => "AES-256",
        }
    }
}

/// Asymmetric key algorithm for GENERATE ASYMMETRIC KEY PAIR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyAlg {
    Rsa1024,
    Rsa2048,
    Rsa3072,
    Rsa4096,
    EccP256,
    EccP384,
    Ed25519,
    X25519,
}

impl KeyAlg {
    /// PIV algorithm identifier byte.
    #[must_use]
    pub const fn id(self) -> u8 {
        match self {
            KeyAlg::Rsa1024 => 0x06,
            KeyAlg::Rsa2048 => 0x07,
            KeyAlg::Rsa3072 => 0x05,
            KeyAlg::Rsa4096 => 0x16,
            KeyAlg::EccP256 => 0x11,
            KeyAlg::EccP384 => 0x14,
            KeyAlg::Ed25519 => 0xE0,
            KeyAlg::X25519 => 0xE1,
        }
    }

    /// Resolve a PIV algorithm identifier.
    #[must_use]
    pub const fn from_id(id: u8) -> Option<Self> {
        match id {
            0x06 => Some(KeyAlg::Rsa1024),
            0x07 => Some(KeyAlg::Rsa2048),
            0x05 => Some(KeyAlg::Rsa3072),
            0x16 => Some(KeyAlg::Rsa4096),
            0x11 => Some(KeyAlg::EccP256),
            0x14 => Some(KeyAlg::EccP384),
            0xE0 => Some(KeyAlg::Ed25519),
            0xE1 => Some(KeyAlg::X25519),
            _ => None,
        }
    }

    /// Short human label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            KeyAlg::Rsa1024 => "RSA-1024",
            KeyAlg::Rsa2048 => "RSA-2048",
            KeyAlg::Rsa3072 => "RSA-3072",
            KeyAlg::Rsa4096 => "RSA-4096",
            KeyAlg::EccP256 => "ECC P-256",
            KeyAlg::EccP384 => "ECC P-384",
            KeyAlg::Ed25519 => "Ed25519",
            KeyAlg::X25519 => "X25519",
        }
    }
}

/// PIN policy for a generated key (when the slot's private key may be used).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinPolicy {
    Default,
    Never,
    Once,
    Always,
}

impl PinPolicy {
    #[must_use]
    pub const fn id(self) -> u8 {
        match self {
            PinPolicy::Default => 0x00,
            PinPolicy::Never => 0x01,
            PinPolicy::Once => 0x02,
            PinPolicy::Always => 0x03,
        }
    }
}

/// Touch policy for a generated key (whether the key requires a physical touch).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TouchPolicy {
    Default,
    Never,
    Always,
    Cached,
}

impl TouchPolicy {
    #[must_use]
    pub const fn id(self) -> u8 {
        match self {
            TouchPolicy::Default => 0x00,
            TouchPolicy::Never => 0x01,
            TouchPolicy::Always => 0x02,
            TouchPolicy::Cached => 0x03,
        }
    }
}

/// A public key returned by GENERATE ASYMMETRIC KEY PAIR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    /// RSA modulus (`n`) and public exponent (`e`).
    Rsa { modulus: Vec<u8>, exponent: Vec<u8> },
    /// Elliptic-curve / EdDSA public point (uncompressed `04 || X || Y` for the
    /// NIST curves, or the raw 32-byte point for Ed25519/X25519).
    Ecc { point: Vec<u8> },
}

/// Parsed GET METADATA response for a key/PIN reference.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Metadata {
    /// Algorithm identifier (tag 0x01), if reported.
    pub algorithm: Option<u8>,
    /// Whether the credential still holds its factory-default value (tag 0x05).
    pub is_default: Option<bool>,
    /// `(remaining, total)` retry counts (tag 0x06), for PIN/PUK references.
    pub retries: Option<(u8, u8)>,
    /// `(pin_policy, touch_policy)` bytes (tag 0x02), for key references.
    pub policy: Option<(u8, u8)>,
    /// Key origin (tag 0x03): 1 = generated on-card, 2 = imported.
    pub origin: Option<u8>,
    /// The slot's public key (tag 0x04), as the same inner TLVs a GENERATE
    /// response carries (`81`/`82` for RSA, `86` for EC) — feed to
    /// [`parse_public_key`] after wrapping, or match the tags directly.
    pub public_key: Option<Vec<u8>>,
}

/// Errors from parsing PIV responses.
#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    /// A length field ran past the end of the buffer.
    Truncated,
    /// Expected the `0x53` data template wrapper and didn't find it.
    NotDataObject,
    /// A version/serial response was the wrong size.
    BadResponse(&'static str),
    /// A `0x7C` GENERAL AUTHENTICATE template was missing or malformed.
    NotAuthTemplate,
    /// A `0x7F49` generated-public-key template was missing or malformed.
    NotPublicKey,
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ParseError::Truncated => write!(f, "PIV response truncated"),
            ParseError::NotDataObject => write!(f, "PIV response is not a 0x53 data object"),
            ParseError::BadResponse(w) => write!(f, "malformed PIV response: {w}"),
            ParseError::NotAuthTemplate => {
                write!(f, "PIV response is not a 0x7C dynamic-auth template")
            }
            ParseError::NotPublicKey => {
                write!(f, "PIV response is not a 0x7F49 public-key template")
            }
        }
    }
}

impl std::error::Error for ParseError {}

// ---------------------------------------------------------------------------
// APDU builders
// ---------------------------------------------------------------------------

/// SELECT the PIV application by AID (case 4: a trailing `Le` requests the
/// application property template the card returns on success).
#[must_use]
pub fn select() -> Vec<u8> {
    let mut apdu = build_apdu(
        0x00,
        Instruction::Select.code(),
        INS_SELECT_P1_BY_AID,
        0x00,
        &AID,
    );
    apdu.push(0x00); // case-4 Le
    apdu
}

/// GET DATA for the 3-byte object `tag` (e.g. a slot's [`Slot::cert_object_tag`]
/// or [`OBJECT_CHUID`]). Case 4 — a certificate response is large and arrives via
/// the `61xx` / GET RESPONSE loop.
#[must_use]
pub fn get_data(tag: &[u8]) -> Vec<u8> {
    assert!(tag.len() <= 0x7F, "GET DATA object tag too long");
    let mut selector = Vec::with_capacity(2 + tag.len());
    selector.push(TAG_OBJECT_SELECTOR);
    selector.push(tag.len() as u8);
    selector.extend_from_slice(tag);
    let mut apdu = build_apdu(
        0x00,
        Instruction::GetData.code(),
        GET_DATA_P1,
        GET_DATA_P2,
        &selector,
    );
    apdu.push(0x00); // case-4 Le
    apdu
}

/// VERIFY the application PIN. The PIN is padded to 8 bytes with `0xFF` per
/// SP 800-73. The PIN bytes come from the caller and are never logged.
#[must_use]
pub fn verify_pin(pin: &[u8]) -> Vec<u8> {
    build_apdu(
        0x00,
        Instruction::Verify.code(),
        0x00,
        PIN_REF_APPLICATION,
        &pad_pin(pin),
    )
}

/// VERIFY with an empty body — queries the PIN retry counter without consuming a
/// try. The card answers `63Cx` (x tries left), `9000` (already verified), or
/// `6983` (blocked). Case 1 (no `Lc`, no `Le`).
#[must_use]
pub fn verify_pin_status() -> Vec<u8> {
    vec![0x00, Instruction::Verify.code(), 0x00, PIN_REF_APPLICATION]
}

/// Yubico GET VERSION (case 2): 3-byte `major.minor.patch`.
#[must_use]
pub fn get_version() -> Vec<u8> {
    build_apdu_get(0x00, Instruction::GetVersion.code(), 0x00, 0x00, 0x00)
}

/// Yubico GET SERIAL (case 2): 4-byte big-endian serial (firmware 5+).
#[must_use]
pub fn get_serial() -> Vec<u8> {
    build_apdu_get(0x00, Instruction::GetSerial.code(), 0x00, 0x00, 0x00)
}

/// GET RESPONSE for the `61xx` continuation loop.
#[must_use]
pub fn get_response() -> Vec<u8> {
    build_apdu_get(0x00, Instruction::GetResponse.code(), 0x00, 0x00, 0x00)
}

// ---------------------------------------------------------------------------
// TLV + extended-APDU helpers (write path)
// ---------------------------------------------------------------------------

/// Encode a BER-TLV definite length: short form below 0x80, else `0x81`/`0x82`
/// long form. PIV write objects (certs, RSA moduli) exceed 255 bytes, so the
/// 2-byte form is required. Values are host-built and never legitimately exceed
/// the 2-byte form, so anything larger is a caller bug — assert rather than
/// silently truncate the length field.
fn push_ber_len(out: &mut Vec<u8>, len: usize) {
    assert!(len <= 0xFFFF, "BER-TLV value too large");
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
}

/// Append a TLV: `tag || ber_len(value) || value`.
fn push_tlv(out: &mut Vec<u8>, tag: &[u8], value: &[u8]) {
    out.extend_from_slice(tag);
    push_ber_len(out, value.len());
    out.extend_from_slice(value);
}

/// Build a case-3/case-4 APDU, choosing short or extended-length encoding by
/// body size. `le` requests a response (`Some(0)` = "up to 65536" in extended
/// form, 256 in short form). YubiKey accepts extended-length APDUs over CCID;
/// bodies over 255 bytes (cert import, RSA signing input) require them.
fn build_apdu_ext(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8], le: Option<u16>) -> Vec<u8> {
    assert!(data.len() <= 0xFFFF, "extended APDU body too large");
    if data.len() <= 255 && le.map_or(true, |v| v <= 256) {
        // Short form. Le==256 is encoded as the single byte 0x00.
        let mut out = Vec::with_capacity(6 + data.len());
        out.extend_from_slice(&[cla, ins, p1, p2]);
        if !data.is_empty() {
            out.push(data.len() as u8);
            out.extend_from_slice(data);
        }
        if let Some(le) = le {
            out.push(if le == 256 { 0x00 } else { le as u8 });
        }
        return out;
    }
    // Extended form: a leading 0x00 marker, then 2-byte Lc and/or 2-byte Le.
    let mut out = Vec::with_capacity(9 + data.len());
    out.extend_from_slice(&[cla, ins, p1, p2, 0x00]);
    if !data.is_empty() {
        out.push((data.len() >> 8) as u8);
        out.push(data.len() as u8);
        out.extend_from_slice(data);
    }
    if let Some(le) = le {
        // 0 → 0x0000 meaning 65536.
        out.push((le >> 8) as u8);
        out.push(le as u8);
    }
    out
}

// ---------------------------------------------------------------------------
// Write / auth APDU builders
// ---------------------------------------------------------------------------

/// GENERAL AUTHENTICATE step 1: request a witness from the management key. The
/// card replies with `7C L 80 <bs> <ciphertext>` — the witness encrypted under
/// the stored key.
#[must_use]
pub fn general_auth_request_witness(alg: MgmtAlg, key_ref: u8) -> Vec<u8> {
    // 7C 02 80 00  — dynamic-auth template requesting tag 0x80 (witness).
    let data = [TAG_DYN_AUTH, 0x02, 0x80, 0x00];
    build_apdu_ext(
        0x00,
        Instruction::GeneralAuthenticate.code(),
        alg.id(),
        key_ref,
        &data,
        Some(256),
    )
}

/// GENERAL AUTHENTICATE step 2: return the decrypted witness and present our own
/// challenge. The card replies with `7C L 82 <bs> <enc(challenge)>`, which the
/// host verifies to complete mutual authentication.
#[must_use]
pub fn general_auth_mutual(
    alg: MgmtAlg,
    key_ref: u8,
    decrypted_witness: &[u8],
    challenge: &[u8],
) -> Vec<u8> {
    let mut inner = Vec::with_capacity(decrypted_witness.len() + challenge.len() + 6);
    push_tlv(&mut inner, &[0x80], decrypted_witness); // witness (decrypted)
    push_tlv(&mut inner, &[0x81], challenge); // our challenge
    let mut data = Vec::with_capacity(inner.len() + 4);
    push_tlv(&mut data, &[TAG_DYN_AUTH], &inner);
    build_apdu_ext(
        0x00,
        Instruction::GeneralAuthenticate.code(),
        alg.id(),
        key_ref,
        &data,
        Some(256),
    )
}

/// GENERAL AUTHENTICATE in signing mode: ask a key slot to sign/decrypt
/// `payload` (a PKCS#1 block for RSA, or a raw hash for ECC). The card replies
/// with `7C L 82 <l> <result>`. `key_alg` is the slot's algorithm (P1),
/// `key_ref` its slot (P2).
#[must_use]
pub fn general_auth_sign(key_alg: KeyAlg, key_ref: u8, payload: &[u8]) -> Vec<u8> {
    let mut inner = Vec::with_capacity(payload.len() + 6);
    inner.extend_from_slice(&[0x82, 0x00]); // response tag, empty: "give me the answer"
    push_tlv(&mut inner, &[0x81], payload); // challenge / data to sign
    let mut data = Vec::with_capacity(inner.len() + 4);
    push_tlv(&mut data, &[TAG_DYN_AUTH], &inner);
    build_apdu_ext(
        0x00,
        Instruction::GeneralAuthenticate.code(),
        key_alg.id(),
        key_ref,
        &data,
        Some(0), // large RSA result: request the lot
    )
}

/// GENERATE ASYMMETRIC KEY PAIR in `slot`. The card creates a fresh private key
/// and returns its public key (`7F49` template). Requires prior management-key
/// authentication.
#[must_use]
pub fn generate_key(
    slot: Slot,
    alg: KeyAlg,
    pin_policy: PinPolicy,
    touch_policy: TouchPolicy,
) -> Vec<u8> {
    let mut control = Vec::with_capacity(9);
    push_tlv(&mut control, &[0x80], &[alg.id()]); // algorithm
    if pin_policy != PinPolicy::Default {
        push_tlv(&mut control, &[0xAA], &[pin_policy.id()]);
    }
    if touch_policy != TouchPolicy::Default {
        push_tlv(&mut control, &[0xAB], &[touch_policy.id()]);
    }
    let mut data = Vec::with_capacity(control.len() + 3);
    push_tlv(&mut data, &[0xAC], &control); // control reference template
    build_apdu_ext(
        0x00,
        Instruction::GenerateKeyPair.code(),
        0x00,
        slot.key_ref(),
        &data,
        Some(0),
    )
}

/// PUT DATA for the 3-byte object `tag`, writing `value` wrapped in the `0x53`
/// template. Used to import a slot certificate (see [`encode_certificate`]).
/// Requires management-key authentication.
#[must_use]
pub fn put_data(tag: &[u8], value: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(tag.len() + value.len() + 8);
    push_tlv(&mut data, &[TAG_OBJECT_SELECTOR], tag); // 5C <tag>
    push_tlv(&mut data, &[TAG_DATA_TEMPLATE], value); // 53 <value>
    build_apdu_ext(
        0x00,
        Instruction::PutData.code(),
        GET_DATA_P1,
        GET_DATA_P2,
        &data,
        None,
    )
}

/// Wrap a DER X.509 certificate in the PIV cert data-object value: `70 <der>
/// 71 01 <certinfo> FE 00`. `certinfo` is 0 for an uncompressed cert.
#[must_use]
pub fn encode_certificate(der: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(der.len() + 8);
    push_tlv(&mut out, &[0x70], der); // the certificate itself
    push_tlv(&mut out, &[0x71], &[0x00]); // CertInfo: 0 = uncompressed
    push_tlv(&mut out, &[0xFE], &[]); // LRC (empty)
    out
}

/// CHANGE REFERENCE DATA: change the PIN (`PIN_REF_APPLICATION`) or PUK
/// (`PIN_REF_PUK`) from `old` to `new`. Both are padded to 8 bytes.
#[must_use]
pub fn change_reference(reference: u8, old: &[u8], new: &[u8]) -> Vec<u8> {
    let mut body = pad_pin(old);
    body.extend_from_slice(&pad_pin(new));
    build_apdu(
        0x00,
        Instruction::ChangeReference.code(),
        0x00,
        reference,
        &body,
    )
}

/// RESET RETRY COUNTER: unblock the PIN using the PUK, setting a new PIN. Both
/// `puk` and `new_pin` are padded to 8 bytes.
#[must_use]
pub fn unblock_pin(puk: &[u8], new_pin: &[u8]) -> Vec<u8> {
    let mut body = pad_pin(puk);
    body.extend_from_slice(&pad_pin(new_pin));
    build_apdu(
        0x00,
        Instruction::ResetRetryCounter.code(),
        0x00,
        PIN_REF_APPLICATION,
        &body,
    )
}

/// Yubico SET MANAGEMENT KEY: replace the 9B card-management key. `require_touch`
/// gates every future management-key auth on a physical touch. Requires prior
/// management-key authentication.
#[must_use]
pub fn set_management_key(alg: MgmtAlg, key: &[u8], require_touch: bool) -> Vec<u8> {
    assert!(key.len() <= 255, "management key too long");
    // Body: <alg> 9B <keylen> <key>.
    let mut body = Vec::with_capacity(3 + key.len());
    body.push(alg.id());
    body.push(KEY_REF_MANAGEMENT);
    body.push(key.len() as u8);
    body.extend_from_slice(key);
    build_apdu(
        0x00,
        Instruction::SetManagementKey.code(),
        0xFF,
        // P2: 0xFF = no touch required, 0xFE = touch required (Yubico).
        if require_touch { 0xFE } else { 0xFF },
        &body,
    )
}

/// Yubico SET PIN RETRIES: set the PIN and PUK retry counts. Resets both to
/// their defaults. Requires management-key auth **and** a verified PIN.
#[must_use]
pub fn set_pin_retries(pin_tries: u8, puk_tries: u8) -> Vec<u8> {
    vec![
        0x00,
        Instruction::SetPinRetries.code(),
        pin_tries,
        puk_tries,
    ]
}

/// Yubico GET METADATA for a key/PIN reference (`0x9B`, `0x80`, `0x81`, or a
/// slot key ref). Requires firmware 5.3+.
#[must_use]
pub fn get_metadata(key_ref: u8) -> Vec<u8> {
    vec![0x00, Instruction::GetMetadata.code(), 0x00, key_ref]
}

/// Yubico RESET: wipe the PIV application back to factory defaults. Only
/// succeeds when **both** the PIN and PUK are blocked.
#[must_use]
pub fn reset() -> Vec<u8> {
    vec![0x00, Instruction::Reset.code(), 0x00, 0x00]
}

/// Pad a PIN to the fixed 8-byte PIV field with trailing `0xFF`. A PIN already
/// 8 bytes or longer is returned truncated to 8 (PIV PINs are 6–8 bytes).
fn pad_pin(pin: &[u8]) -> Vec<u8> {
    let mut out = [0xFFu8; 8].to_vec();
    let n = pin.len().min(8);
    out[..n].copy_from_slice(&pin[..n]);
    out
}

// ---------------------------------------------------------------------------
// Response parsers
// ---------------------------------------------------------------------------

/// Unwrap a GET DATA response: strip the outer `0x53` template and return the
/// inner value bytes (for a certificate object, the `70`/`71`/`FE` cert TLVs).
pub fn unwrap_data_object(buf: &[u8]) -> Result<&[u8], ParseError> {
    if buf.first() != Some(&TAG_DATA_TEMPLATE) {
        return Err(ParseError::NotDataObject);
    }
    let (len, header) = read_ber_len(&buf[1..])?;
    let start = 1 + header;
    let end = start.checked_add(len).ok_or(ParseError::Truncated)?;
    buf.get(start..end).ok_or(ParseError::Truncated)
}

/// Parse a Yubico GET VERSION reply (exactly 3 bytes) into `(major, minor, patch)`.
pub fn parse_version(buf: &[u8]) -> Result<(u8, u8, u8), ParseError> {
    match buf {
        [a, b, c] => Ok((*a, *b, *c)),
        _ => Err(ParseError::BadResponse("version is not 3 bytes")),
    }
}

/// Parse a Yubico GET SERIAL reply (4-byte big-endian).
pub fn parse_serial(buf: &[u8]) -> Result<u32, ParseError> {
    match buf {
        [a, b, c, d] => Ok(u32::from_be_bytes([*a, *b, *c, *d])),
        _ => Err(ParseError::BadResponse("serial is not 4 bytes")),
    }
}

/// Extract one inner TLV value (`inner_tag`) from a `0x7C` GENERAL AUTHENTICATE
/// response template — the witness (`0x80`) from step 1, or the encrypted
/// challenge / signature (`0x82`) from step 2 / signing.
pub fn parse_general_auth(buf: &[u8], inner_tag: u8) -> Result<&[u8], ParseError> {
    if buf.first() != Some(&TAG_DYN_AUTH) {
        return Err(ParseError::NotAuthTemplate);
    }
    let (len, header) = read_ber_len(&buf[1..])?;
    let start = 1 + header;
    let end = start.checked_add(len).ok_or(ParseError::Truncated)?;
    let inner = buf.get(start..end).ok_or(ParseError::Truncated)?;
    find_tlv(inner, inner_tag).ok_or(ParseError::NotAuthTemplate)
}

/// Parse a `0x7F49` generated-public-key template into a [`PublicKey`]. RSA
/// carries `81` (modulus) and `82` (exponent); EC/EdDSA carry `86` (point).
pub fn parse_public_key(buf: &[u8]) -> Result<PublicKey, ParseError> {
    // The template tag 0x7F49 is two bytes.
    if buf.get(..2) != Some(&[0x7F, 0x49][..]) {
        return Err(ParseError::NotPublicKey);
    }
    let (len, header) = read_ber_len(&buf[2..])?;
    let start = 2 + header;
    let end = start.checked_add(len).ok_or(ParseError::Truncated)?;
    let inner = buf.get(start..end).ok_or(ParseError::Truncated)?;
    if let Some(point) = find_tlv(inner, 0x86) {
        return Ok(PublicKey::Ecc {
            point: point.to_vec(),
        });
    }
    let modulus = find_tlv(inner, 0x81).ok_or(ParseError::NotPublicKey)?;
    let exponent = find_tlv(inner, 0x82).ok_or(ParseError::NotPublicKey)?;
    Ok(PublicKey::Rsa {
        modulus: modulus.to_vec(),
        exponent: exponent.to_vec(),
    })
}

/// Parse a Yubico GET METADATA response (a flat list of `tag len value` TLVs).
pub fn parse_metadata(buf: &[u8]) -> Result<Metadata, ParseError> {
    let mut md = Metadata::default();
    let mut i = 0;
    while i < buf.len() {
        let tag = buf[i];
        let (len, header) = read_ber_len(&buf[i + 1..])?;
        let vstart = i + 1 + header;
        let vend = vstart.checked_add(len).ok_or(ParseError::Truncated)?;
        let value = buf.get(vstart..vend).ok_or(ParseError::Truncated)?;
        match tag {
            0x01 => md.algorithm = value.first().copied(),
            0x02 if value.len() >= 2 => md.policy = Some((value[0], value[1])),
            0x03 => md.origin = value.first().copied(),
            0x04 => md.public_key = Some(value.to_vec()),
            0x05 => md.is_default = value.first().map(|&b| b != 0),
            0x06 if value.len() >= 2 => md.retries = Some((value[0], value[1])),
            _ => {}
        }
        i = vend;
    }
    Ok(md)
}

/// Find the value of the first top-level TLV with single-byte `tag` in `buf`.
/// Public so the transport layer can reuse it instead of growing its own
/// BER-TLV walker.
#[must_use]
pub fn find_tlv(buf: &[u8], tag: u8) -> Option<&[u8]> {
    let mut i = 0;
    while i < buf.len() {
        let t = buf[i];
        let (len, header) = read_ber_len(buf.get(i + 1..)?).ok()?;
        let vstart = i + 1 + header;
        let vend = vstart.checked_add(len)?;
        let value = buf.get(vstart..vend)?;
        if t == tag {
            return Some(value);
        }
        i = vend;
    }
    None
}

/// Read a BER-TLV length field, returning `(length, header_byte_count)`.
/// Handles the short form and the `0x81`/`0x82` long forms (a PIV cert easily
/// exceeds 255 bytes, so the 2-byte form is required). Indefinite (`0x80`) and
/// longer forms are deliberately rejected — no PIV object needs them.
pub fn read_ber_len(buf: &[u8]) -> Result<(usize, usize), ParseError> {
    let first = *buf.first().ok_or(ParseError::Truncated)?;
    if first < 0x80 {
        return Ok((first as usize, 1));
    }
    let n = (first & 0x7F) as usize;
    if n == 0 || n > 2 {
        return Err(ParseError::BadResponse("unsupported BER length form"));
    }
    let bytes = buf.get(1..1 + n).ok_or(ParseError::Truncated)?;
    let len = bytes.iter().fold(0usize, |acc, &b| (acc << 8) | b as usize);
    Ok((len, 1 + n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_bytes() {
        // 00 A4 04 00 05 A0 00 00 03 08 00
        assert_eq!(
            select(),
            vec![0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00]
        );
    }

    #[test]
    fn get_data_auth_cert_bytes() {
        // 00 CB 3F FF 05 5C 03 5F C1 05 00
        assert_eq!(
            get_data(&Slot::Authentication.cert_object_tag()),
            vec![0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x05, 0x00]
        );
    }

    #[test]
    fn slot_key_refs_and_tags() {
        assert_eq!(Slot::Authentication.key_ref(), 0x9A);
        assert_eq!(Slot::Signature.key_ref(), 0x9C);
        assert_eq!(Slot::KeyManagement.key_ref(), 0x9D);
        assert_eq!(Slot::CardAuthentication.key_ref(), 0x9E);
        assert_eq!(Slot::Signature.cert_object_tag(), [0x5F, 0xC1, 0x0A]);
        assert_eq!(
            Slot::CardAuthentication.cert_object_tag(),
            [0x5F, 0xC1, 0x01]
        );
    }

    #[test]
    fn verify_pin_pads_to_eight() {
        // 00 20 00 80 08 31 32 33 34 35 36 FF FF   ("123456" + FF FF)
        assert_eq!(
            verify_pin(b"123456"),
            vec![0x00, 0x20, 0x00, 0x80, 0x08, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF]
        );
    }

    #[test]
    fn verify_status_is_case1() {
        assert_eq!(verify_pin_status(), vec![0x00, 0x20, 0x00, 0x80]);
    }

    #[test]
    fn version_and_serial_apdus() {
        assert_eq!(get_version(), vec![0x00, 0xFD, 0x00, 0x00, 0x00]);
        assert_eq!(get_serial(), vec![0x00, 0xF8, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn unwrap_short_data_object() {
        // 53 03 AA BB CC -> AA BB CC
        assert_eq!(
            unwrap_data_object(&[0x53, 0x03, 0xAA, 0xBB, 0xCC]).unwrap(),
            &[0xAA, 0xBB, 0xCC]
        );
    }

    #[test]
    fn unwrap_long_form_data_object() {
        // 53 81 80 <128 bytes>
        let mut buf = vec![0x53, 0x81, 0x80];
        buf.extend(std::iter::repeat(0x11).take(128));
        let inner = unwrap_data_object(&buf).unwrap();
        assert_eq!(inner.len(), 128);
        assert!(inner.iter().all(|&b| b == 0x11));
    }

    #[test]
    fn unwrap_rejects_non_template_and_truncation() {
        assert_eq!(
            unwrap_data_object(&[0x70, 0x01, 0x00]),
            Err(ParseError::NotDataObject)
        );
        assert_eq!(
            unwrap_data_object(&[0x53, 0x05, 0x00]),
            Err(ParseError::Truncated)
        );
    }

    #[test]
    fn parse_version_and_serial_values() {
        assert_eq!(parse_version(&[5, 7, 1]).unwrap(), (5, 7, 1));
        assert!(parse_version(&[5, 7]).is_err());
        assert_eq!(parse_serial(&[0x02, 0x40, 0x8A, 0x1B]).unwrap(), 0x02408A1B);
        assert!(parse_serial(&[0x00, 0x01]).is_err());
    }

    #[test]
    fn mgmt_alg_round_trips_and_sizes() {
        for a in [
            MgmtAlg::TripleDes,
            MgmtAlg::Aes128,
            MgmtAlg::Aes192,
            MgmtAlg::Aes256,
        ] {
            assert_eq!(MgmtAlg::from_id(a.id()), Some(a));
        }
        assert_eq!(MgmtAlg::Aes192.id(), 0x0A);
        assert_eq!(MgmtAlg::Aes192.block_size(), 16);
        assert_eq!(MgmtAlg::Aes192.key_len(), 24);
        assert_eq!(MgmtAlg::TripleDes.block_size(), 8);
        assert_eq!(MgmtAlg::Aes256.key_len(), 32);
        assert_eq!(MgmtAlg::from_id(0x99), None);
    }

    #[test]
    fn key_alg_round_trips() {
        for a in [
            KeyAlg::Rsa1024,
            KeyAlg::Rsa2048,
            KeyAlg::Rsa3072,
            KeyAlg::Rsa4096,
            KeyAlg::EccP256,
            KeyAlg::EccP384,
            KeyAlg::Ed25519,
            KeyAlg::X25519,
        ] {
            assert_eq!(KeyAlg::from_id(a.id()), Some(a));
        }
        assert_eq!(KeyAlg::Rsa2048.id(), 0x07);
        assert_eq!(KeyAlg::EccP256.id(), 0x11);
    }

    #[test]
    fn witness_request_bytes() {
        // 00 87 0A 9B 04 7C 02 80 00 00  (P1=AES-192 alg, P2=9B, Le=00)
        assert_eq!(
            general_auth_request_witness(MgmtAlg::Aes192, KEY_REF_MANAGEMENT),
            vec![0x00, 0x87, 0x0A, 0x9B, 0x04, 0x7C, 0x02, 0x80, 0x00, 0x00]
        );
    }

    #[test]
    fn mutual_auth_bytes_aes() {
        // 16-byte witness + 16-byte challenge → inner 7C 24 80 10 .. 81 10 ..
        let w = [0xAAu8; 16];
        let c = [0xBBu8; 16];
        let apdu = general_auth_mutual(MgmtAlg::Aes192, KEY_REF_MANAGEMENT, &w, &c);
        assert_eq!(&apdu[..5], &[0x00, 0x87, 0x0A, 0x9B, 0x26]); // Lc = 0x26 = 38
        assert_eq!(&apdu[5..9], &[0x7C, 0x24, 0x80, 0x10]);
        assert_eq!(&apdu[9..25], &w);
        assert_eq!(&apdu[25..27], &[0x81, 0x10]);
        assert_eq!(&apdu[27..43], &c);
        assert_eq!(apdu[43], 0x00); // Le
    }

    #[test]
    fn generate_key_bytes_default_policy() {
        // 00 47 00 9A 05 AC 03 80 01 11 00  (ECC P-256 in 9A, default policies)
        assert_eq!(
            generate_key(
                Slot::Authentication,
                KeyAlg::EccP256,
                PinPolicy::Default,
                TouchPolicy::Default
            ),
            vec![0x00, 0x47, 0x00, 0x9A, 0x05, 0xAC, 0x03, 0x80, 0x01, 0x11, 0x00]
        );
    }

    #[test]
    fn generate_key_bytes_with_policies() {
        // control: 80 01 07, AA 01 02 (pin once), AB 01 02 (touch always)
        assert_eq!(
            generate_key(
                Slot::Signature,
                KeyAlg::Rsa2048,
                PinPolicy::Once,
                TouchPolicy::Always
            ),
            vec![
                0x00, 0x47, 0x00, 0x9C, 0x0B, 0xAC, 0x09, 0x80, 0x01, 0x07, 0xAA, 0x01, 0x02, 0xAB,
                0x01, 0x02, 0x00
            ]
        );
    }

    #[test]
    fn change_pin_bytes() {
        // 00 24 00 80 10 <old pad8> <new pad8>
        let apdu = change_reference(PIN_REF_APPLICATION, b"123456", b"654321");
        assert_eq!(&apdu[..5], &[0x00, 0x24, 0x00, 0x80, 0x10]);
        assert_eq!(
            &apdu[5..],
            &[
                0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF, // 123456 + FF FF
                0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0xFF, 0xFF, // 654321 + FF FF
            ]
        );
    }

    #[test]
    fn unblock_pin_bytes() {
        let apdu = unblock_pin(b"12345678", b"000000");
        assert_eq!(&apdu[..5], &[0x00, 0x2C, 0x00, 0x80, 0x10]);
        assert_eq!(&apdu[5..13], b"12345678");
        assert_eq!(
            &apdu[13..],
            &[0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0xFF, 0xFF]
        );
    }

    #[test]
    fn set_management_key_bytes() {
        let key = [0x42u8; 24];
        // 00 FF FF 00 1B 0A 9B 18 <24 key bytes>
        let apdu = set_management_key(MgmtAlg::Aes192, &key, false);
        assert_eq!(&apdu[..5], &[0x00, 0xFF, 0xFF, 0xFF, 0x1B]);
        assert_eq!(&apdu[5..8], &[0x0A, 0x9B, 0x18]);
        assert_eq!(&apdu[8..], &key);
        // touch flag flips P2 to 0xFE
        assert_eq!(set_management_key(MgmtAlg::Aes192, &key, true)[3], 0xFE);
    }

    #[test]
    fn set_pin_retries_and_reset_and_metadata_bytes() {
        assert_eq!(set_pin_retries(5, 3), vec![0x00, 0xFA, 0x05, 0x03]);
        assert_eq!(reset(), vec![0x00, 0xFB, 0x00, 0x00]);
        assert_eq!(get_metadata(0x9B), vec![0x00, 0xF7, 0x00, 0x9B]);
    }

    #[test]
    fn put_data_short_object() {
        // small value uses short-form Lc
        let apdu = put_data(&OBJECT_CHUID, &[0xDE, 0xAD]);
        // 00 DB 3F FF <Lc> 5C 03 5F C1 02 53 02 DE AD
        assert_eq!(&apdu[..4], &[0x00, 0xDB, 0x3F, 0xFF]);
        assert_eq!(apdu[4], 0x09); // Lc = 9 (5-byte selector + 4-byte template)
        assert_eq!(
            &apdu[5..],
            &[0x5C, 0x03, 0x5F, 0xC1, 0x02, 0x53, 0x02, 0xDE, 0xAD]
        );
    }

    #[test]
    fn put_data_large_object_uses_extended_apdu() {
        // A 1 KB cert forces extended-length encoding (leading 00, 2-byte Lc).
        let der = vec![0x11u8; 1024];
        let value = encode_certificate(&der);
        let apdu = put_data(&Slot::Signature.cert_object_tag(), &value);
        assert_eq!(&apdu[..5], &[0x00, 0xDB, 0x3F, 0xFF, 0x00]); // extended marker
        let lc = ((apdu[5] as usize) << 8) | apdu[6] as usize;
        assert_eq!(lc, apdu.len() - 7); // body length matches 2-byte Lc
    }

    #[test]
    fn encode_certificate_wraps_der() {
        let der = [0xAB, 0xCD, 0xEF];
        // 70 03 AB CD EF 71 01 00 FE 00
        assert_eq!(
            encode_certificate(&der),
            vec![0x70, 0x03, 0xAB, 0xCD, 0xEF, 0x71, 0x01, 0x00, 0xFE, 0x00]
        );
    }

    #[test]
    fn parse_general_auth_extracts_witness() {
        // 7C 0A 80 08 <8-byte witness>
        let mut buf = vec![0x7C, 0x0A, 0x80, 0x08];
        buf.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            parse_general_auth(&buf, 0x80).unwrap(),
            &[1, 2, 3, 4, 5, 6, 7, 8]
        );
        // wrong outer tag
        assert_eq!(
            parse_general_auth(&[0x70, 0x02, 0x80, 0x00], 0x80),
            Err(ParseError::NotAuthTemplate)
        );
    }

    #[test]
    fn parse_public_key_rsa_and_ecc() {
        // RSA: 7F49 <len> 81 04 <mod> 82 03 01 00 01
        let mut rsa = vec![
            0x7F, 0x49, 0x0B, 0x81, 0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0x82, 0x03,
        ];
        rsa.extend_from_slice(&[0x01, 0x00, 0x01]);
        match parse_public_key(&rsa).unwrap() {
            PublicKey::Rsa { modulus, exponent } => {
                assert_eq!(modulus, vec![0xAA, 0xBB, 0xCC, 0xDD]);
                assert_eq!(exponent, vec![0x01, 0x00, 0x01]);
            }
            _ => panic!("expected RSA"),
        }
        // ECC: 7F49 <len> 86 04 <point>
        let ecc = vec![0x7F, 0x49, 0x06, 0x86, 0x04, 0x04, 0x11, 0x22, 0x33];
        match parse_public_key(&ecc).unwrap() {
            PublicKey::Ecc { point } => assert_eq!(point, vec![0x04, 0x11, 0x22, 0x33]),
            _ => panic!("expected ECC"),
        }
    }

    #[test]
    fn parse_metadata_mgmt_and_pin() {
        // mgmt 9B: 01 01 0A  02 02 00 01  05 01 01   (alg AES-192, default)
        let md =
            parse_metadata(&[0x01, 0x01, 0x0A, 0x02, 0x02, 0x00, 0x01, 0x05, 0x01, 0x01]).unwrap();
        assert_eq!(md.algorithm, Some(0x0A));
        assert_eq!(md.is_default, Some(true));
        assert_eq!(md.policy, Some((0x00, 0x01)));
        // PIN 80: 06 02 03 03 (3 of 3 retries), 05 01 00 (not default)
        let pin = parse_metadata(&[0x06, 0x02, 0x03, 0x03, 0x05, 0x01, 0x00]).unwrap();
        assert_eq!(pin.retries, Some((3, 3)));
        assert_eq!(pin.is_default, Some(false));
    }

    #[test]
    fn parse_metadata_origin_and_public_key() {
        // slot 9A: 01 01 11 (ECC P-256), 03 01 01 (generated), 04 04 86 02 AA BB
        let md = parse_metadata(&[
            0x01, 0x01, 0x11, 0x03, 0x01, 0x01, 0x04, 0x04, 0x86, 0x02, 0xAA, 0xBB,
        ])
        .unwrap();
        assert_eq!(md.origin, Some(1));
        assert_eq!(md.public_key, Some(vec![0x86, 0x02, 0xAA, 0xBB]));
    }

    #[test]
    fn parse_metadata_rejects_garbage() {
        // tag with no length byte
        assert_eq!(parse_metadata(&[0x06]), Err(ParseError::Truncated));
        // length runs past the buffer
        assert_eq!(
            parse_metadata(&[0x01, 0x05, 0xAA]),
            Err(ParseError::Truncated)
        );
        // indefinite-length form is rejected, not misread
        assert!(matches!(
            parse_metadata(&[0x01, 0x80, 0x00]),
            Err(ParseError::BadResponse(_))
        ));
    }

    #[test]
    fn general_auth_sign_short_and_extended() {
        // Small ECC payload stays in a short APDU:
        // 00 87 11 9A 0A  7C 08 82 00 81 04 <payload>  00
        let apdu = general_auth_sign(KeyAlg::EccP256, 0x9A, &[0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(
            apdu,
            vec![
                0x00, 0x87, 0x11, 0x9A, 0x0A, 0x7C, 0x08, 0x82, 0x00, 0x81, 0x04, 0xAA, 0xBB, 0xCC,
                0xDD, 0x00,
            ]
        );
        // A 256-byte RSA-2048 block forces the extended form: marker 0x00,
        // 2-byte Lc, body, 2-byte Le 0x0000 ("up to 65536").
        let apdu = general_auth_sign(KeyAlg::Rsa2048, 0x9A, &[0x55; 256]);
        // data: 7C 82 01 06 ( 82 00  81 82 01 00 <256> )
        assert_eq!(&apdu[..5], &[0x00, 0x87, 0x07, 0x9A, 0x00]);
        let lc = ((apdu[5] as usize) << 8) | apdu[6] as usize;
        assert_eq!(lc, 4 + 2 + 4 + 256); // 7C len hdr + 82 00 + 81 len hdr + payload
        assert_eq!(&apdu[7..11], &[0x7C, 0x82, 0x01, 0x06]);
        assert_eq!(&apdu[apdu.len() - 2..], &[0x00, 0x00]);
        assert_eq!(apdu.len(), 7 + lc + 2);
    }

    #[test]
    fn get_response_bytes() {
        assert_eq!(get_response(), vec![0x00, 0xC0, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn pad_pin_truncates_and_pads() {
        // Documented behavior: longer-than-8 input is truncated (callers must
        // validate 6–8 first); shorter input is 0xFF-padded.
        let apdu = verify_pin(b"1234567890");
        assert_eq!(&apdu[5..], b"12345678");
        let apdu = verify_pin(b"123456");
        assert_eq!(
            &apdu[5..],
            &[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF]
        );
    }

    #[test]
    fn read_ber_len_forms() {
        // two-byte long form (a typical certificate length)
        assert_eq!(read_ber_len(&[0x82, 0x01, 0x30]).unwrap(), (0x130, 3));
        assert_eq!(read_ber_len(&[0x81, 0xC8]).unwrap(), (0xC8, 2));
        // indefinite and >2-byte forms are unsupported
        assert!(matches!(
            read_ber_len(&[0x80]),
            Err(ParseError::BadResponse(_))
        ));
        assert!(matches!(
            read_ber_len(&[0x83, 0x01, 0x00, 0x00]),
            Err(ParseError::BadResponse(_))
        ));
        // truncated long form
        assert_eq!(read_ber_len(&[0x82, 0x01]), Err(ParseError::Truncated));
        assert_eq!(read_ber_len(&[]), Err(ParseError::Truncated));
    }
}
