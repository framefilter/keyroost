//! PIV (Personal Identity Verification — NIST SP 800-73-4 / FIPS 201) byte layer.
//!
//! A pure, I/O-free APDU builder + parser layer for the PIV smartcard
//! application, the same shape as `keyroost-oath` and `keyroost-openpgp`: it
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
use zeroize::Zeroizing;

pub mod spki;
pub mod x509;
pub mod x509_parse;

/// The NIST SP 800-73-4 / FIPS 201 standardized PIV Card Application AID —
/// RID `A0 00 00 03 08` + PIX `00 00 10 00 01 00`. Every spec-compliant PIV
/// card (YubiKey included) registers under exactly this AID; it's what
/// [`select_full`] sends first.
pub const AID_FULL: [u8; 11] = [
    0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
];

/// PIV card-application AID, truncated to the 5-byte RID/PIX prefix. This is
/// what `yubikey-piv-tool` / `ykman` send, relying on YubiKey's open-ended
/// AID-prefix matching — not something the spec requires. [`select`] builds
/// this short form; it exists only as [`select_full`]'s fallback, for cards
/// that (hypothetically) reject the full AID. Nitrokey's `piv-authenticator`
/// firmware needs the opposite treatment: it registers its AID as
/// `Aid::new_truncatable(<full 11 bytes>, 9)`, which matches only an *exact*
/// 9- or 11-byte SELECT, not this arbitrary 5-byte prefix — a bare `select()`
/// against it comes back `SW_NOT_FOUND` even though the applet is present,
/// which is why [`select_full`] is tried first.
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
///
/// `#[non_exhaustive]` (since 0.8.0): vendor extensions keep appearing (Attest
/// arrived in 0.7.x and formally broke exhaustive matches), so downstream
/// matches must carry a catch-all arm — and future instruction additions stop
/// being breaking changes.
#[non_exhaustive]
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
    /// Yubico extension: MOVE KEY (also DELETE KEY via the `0xFF` sentinel; fw 5.7+).
    MoveKey = 0xF6,
    /// Yubico extension: SET MANAGEMENT KEY (9B).
    SetManagementKey = 0xFF,
    /// Yubico extension: SET PIN RETRIES (PIN + PUK try counts).
    SetPinRetries = 0xFA,
    /// Yubico extension: RESET the PIV application (only when PIN and PUK blocked).
    Reset = 0xFB,
    /// Yubico extension: ATTEST — a self-signed certificate for a slot's key,
    /// proving on-card generation (fw 4.3+). On firmware older than 5.3 (GET
    /// METADATA's policy support), this certificate's key-policy extension is
    /// also the only source for the slot's PIN/touch policy.
    Attest = 0xF9,
}

impl Instruction {
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Recognise a raw INS byte. `None` for any instruction this crate does not
    /// build. Note `0xF6` (MOVE KEY) doubles as DELETE KEY via a `P1 == 0xFF`
    /// sentinel — the byte alone can't tell them apart; see the `--debug` trace
    /// labelling in `keyroost-transport` for that distinction.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0xA4 => Self::Select,
            0x20 => Self::Verify,
            0xCB => Self::GetData,
            0xC0 => Self::GetResponse,
            0x87 => Self::GeneralAuthenticate,
            0x47 => Self::GenerateKeyPair,
            0xDB => Self::PutData,
            0x24 => Self::ChangeReference,
            0x2C => Self::ResetRetryCounter,
            0xFD => Self::GetVersion,
            0xF8 => Self::GetSerial,
            0xF7 => Self::GetMetadata,
            0xF6 => Self::MoveKey,
            0xFF => Self::SetManagementKey,
            0xFA => Self::SetPinRetries,
            0xFB => Self::Reset,
            0xF9 => Self::Attest,
            _ => return None,
        })
    }

    /// Human-readable command name, for the `--debug` / activity-log APDU trace.
    /// Yubico's proprietary instructions are marked as such.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Select => "SELECT",
            Self::Verify => "VERIFY",
            Self::GetData => "GET DATA",
            Self::GetResponse => "GET RESPONSE",
            Self::GeneralAuthenticate => "GENERAL AUTHENTICATE",
            Self::GenerateKeyPair => "GENERATE ASYMMETRIC KEY PAIR",
            Self::PutData => "PUT DATA",
            Self::ChangeReference => "CHANGE REFERENCE DATA",
            Self::ResetRetryCounter => "RESET RETRY COUNTER",
            Self::GetVersion => "GET VERSION (yubico extension)",
            Self::GetSerial => "GET SERIAL (yubico extension)",
            Self::GetMetadata => "GET METADATA (yubico extension)",
            Self::MoveKey => "MOVE KEY (yubico extension)",
            Self::SetManagementKey => "SET MANAGEMENT KEY (yubico extension)",
            Self::SetPinRetries => "SET PIN RETRIES (yubico extension)",
            Self::Reset => "RESET (yubico extension)",
            Self::Attest => "ATTEST (yubico extension)",
        }
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
    /// Yubico retired key-management slots (fw 5.7+). `Retired(n)` for
    /// n = 1..=20 → key_ref 0x82..=0x95. Construct via [`Slot::retired`],
    /// which rejects out-of-range n.
    Retired(u8),
}

impl Slot {
    /// The key-reference byte (`9A`/`9C`/`9D`/`9E`, or `82`..=`95` for retired).
    #[must_use]
    pub const fn key_ref(self) -> u8 {
        match self {
            Slot::Authentication => 0x9A,
            Slot::Signature => 0x9C,
            Slot::KeyManagement => 0x9D,
            Slot::CardAuthentication => 0x9E,
            Slot::Retired(n) => 0x81 + n,
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
            Slot::Retired(n) => [0x5F, 0xC1, 0x0C + n],
        }
    }

    /// Short human label.
    #[must_use]
    pub fn label(self) -> String {
        match self {
            Slot::Authentication => "authentication (9A)".into(),
            Slot::Signature => "signature (9C)".into(),
            Slot::KeyManagement => "key management (9D)".into(),
            Slot::CardAuthentication => "card authentication (9E)".into(),
            // "retired key 1 (82)" rather than "retired 1 (82)": the bare
            // ordinal reads as part of the slot number, leaving the user to
            // guess whether "1" or "82" identifies the slot. Same shape as the
            // standard slots above — a name, then its hex address.
            Slot::Retired(n) => format!("retired key {n} ({:02X})", 0x81 + n),
        }
    }

    /// All four standard slots, in canonical order. Retired slots are kept
    /// separate — see [`Slot::retired_all`] — so status() stays cheap.
    #[must_use]
    pub const fn all() -> [Slot; 4] {
        [
            Slot::Authentication,
            Slot::Signature,
            Slot::KeyManagement,
            Slot::CardAuthentication,
        ]
    }

    /// Checked constructor for a retired slot: `Some` for n in 1..=20, else `None`.
    /// All retired-slot construction must go through here so an invalid ref can
    /// never be built.
    #[must_use]
    pub fn retired(n: u8) -> Option<Slot> {
        (1..=20).contains(&n).then_some(Slot::Retired(n))
    }

    /// The 20 retired slots in order (Retired(1)..=Retired(20)). Kept separate
    /// from [`Slot::all`] so status() stays cheap — retired occupancy is read
    /// lazily, not on every refresh.
    #[must_use]
    pub fn retired_all() -> [Slot; 20] {
        let mut out = [Slot::Retired(1); 20];
        let mut i = 0u8;
        while i < 20 {
            out[i as usize] = Slot::Retired(i + 1);
            i += 1;
        }
        out
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

    /// Resolve a PIN policy byte, as reported by GET METADATA (tag `0x02`'s
    /// first byte) or the ATTEST certificate's key-policy extension.
    #[must_use]
    pub const fn from_id(id: u8) -> Option<Self> {
        match id {
            0x00 => Some(PinPolicy::Default),
            0x01 => Some(PinPolicy::Never),
            0x02 => Some(PinPolicy::Once),
            0x03 => Some(PinPolicy::Always),
            _ => None,
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

    /// Resolve a touch policy byte, as reported by GET METADATA (tag `0x02`'s
    /// second byte) or the ATTEST certificate's key-policy extension.
    #[must_use]
    pub const fn from_id(id: u8) -> Option<Self> {
        match id {
            0x00 => Some(TouchPolicy::Default),
            0x01 => Some(TouchPolicy::Never),
            0x02 => Some(TouchPolicy::Always),
            0x03 => Some(TouchPolicy::Cached),
            _ => None,
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

/// A PIN/PUK value the fixed 8-byte PIV field can't represent (SP 800-73:
/// 6–8 bytes, `0xFF`-padded). Returned instead of padding or truncating: a
/// truncated value would build a VERIFY/CHANGE for a *different*,
/// valid-length secret and burn a retry against the card. Only the length is
/// captured — never the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinLengthError {
    /// The rejected length, in bytes.
    pub len: usize,
}

impl core::fmt::Display for PinLengthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PIV PIN/PUK must be 6-8 bytes (got {})", self.len)
    }
}

impl std::error::Error for PinLengthError {}

// ---------------------------------------------------------------------------
// APDU builders
// ---------------------------------------------------------------------------

/// SELECT the PIV application by its full, spec-mandated AID ([`AID_FULL`]).
/// Case 4 — a trailing `Le` requests the application property template the
/// card returns on success. Try this before [`select`]: it's what every
/// spec-compliant PIV card recognizes, including cards (like Nitrokey's)
/// that don't answer the short RID-only prefix.
#[must_use]
pub fn select_full() -> Vec<u8> {
    let mut apdu = build_apdu(
        0x00,
        Instruction::Select.code(),
        INS_SELECT_P1_BY_AID,
        0x00,
        &AID_FULL,
    );
    apdu.push(0x00); // case-4 Le
    apdu
}

/// SELECT the PIV application by its short RID/PIX-prefix AID ([`AID`]).
/// Case 4 — a trailing `Le` requests the application property template the
/// card returns on success. Fallback for [`select_full`]; see [`AID`]'s doc
/// comment for why both exist.
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

/// Human-readable name for a PIV data-object tag — the BER tag a GET DATA / PUT
/// DATA command carries in its `5C` field. Covers the SP 800-73-4 Part 1
/// objects and the Yubico extension objects that PivApplet / OpenFIPS201 also
/// follow; `None` for a tag with no assigned name, which the caller renders as
/// raw hex. Diagnostic only (activity-log / `--debug` trace labelling).
#[must_use]
pub fn data_object_name(tag: &[u8]) -> Option<String> {
    // Numbered ranges first: retired key-management certs 1..20 sit at
    // `5F C1 0D..=5F C1 20` (Slot::Retired(n) -> 5F C1 0C+n), and Yubico's
    // MSROOTS 1..5 at `5F FF 11..=5F FF 15`.
    if let [0x5F, 0xC1, n @ 0x0D..=0x20] = tag {
        return Some(format!(
            "Retired X.509 Certificate for Key Management {}",
            n - 0x0C
        ));
    }
    if let [0x5F, 0xFF, n @ 0x11..=0x15] = tag {
        return Some(format!("Yubico MSROOTS {}", n - 0x10));
    }
    let name = match tag {
        [0x7E] => "Discovery Object",
        [0x5F, 0xC1, 0x01] => "X.509 Certificate for Card Authentication",
        [0x5F, 0xC1, 0x02] => "Card Holder Unique Identifier",
        [0x5F, 0xC1, 0x03] => "Cardholder Fingerprints",
        [0x5F, 0xC1, 0x05] => "X.509 Certificate for PIV Authentication",
        [0x5F, 0xC1, 0x06] => "Security Object",
        [0x5F, 0xC1, 0x07] => "Card Capability Container",
        [0x5F, 0xC1, 0x08] => "Cardholder Facial Image",
        [0x5F, 0xC1, 0x09] => "Printed Information",
        [0x5F, 0xC1, 0x0A] => "X.509 Certificate for Digital Signature",
        [0x5F, 0xC1, 0x0B] => "X.509 Certificate for Key Management",
        [0x5F, 0xC1, 0x0C] => "Key History Object",
        [0x5F, 0xC1, 0x21] => "Cardholder Iris Images",
        [0x5F, 0xC1, 0x22] => "Biometric Information Templates Group Template",
        [0x5F, 0xC1, 0x23] => "Secure Messaging Certificate Signer",
        [0x5F, 0xC1, 0x24] => "Pairing Code Reference Data Container",
        [0x5F, 0xFF, 0x01] => "Yubico PIV Attestation Certificate",
        [0x5F, 0xFF, 0x10] => "Yubico MSCMAP",
        _ => return None,
    };
    Some(name.to_string())
}

/// VERIFY the application PIN. The PIN is padded to 8 bytes with `0xFF` per
/// SP 800-73 and must be 6–8 bytes ([`PinLengthError`] otherwise). The PIN
/// bytes come from the caller and are never logged.
pub fn verify_pin(pin: &[u8]) -> Result<Vec<u8>, PinLengthError> {
    Ok(build_apdu(
        0x00,
        Instruction::Verify.code(),
        0x00,
        PIN_REF_APPLICATION,
        &pad_pin(pin)?,
    ))
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
    if data.len() <= 255 && le.is_none_or(|v| v <= 256) {
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

/// Split `data` into an ISO 7816-4 command-chaining sequence: every chunk but
/// the last carries the chaining class bit (`CLA` `0x10`), the final chunk
/// clears it and (if `final_le` is given) appends a one-byte short-form `Le`.
/// Each chunk is a case-3/case-4 APDU `cla[|0x10] ins p1 p2 Lc <chunk> [Le]`
/// with a plain one-byte `Lc` — chaining links are always short-form, that's
/// the whole point of the fallback. The card reassembles the chunks into one
/// logical command whose data field is byte-identical to what a single
/// extended-length APDU (see [`build_apdu_ext`]) would have carried.
///
/// This is the fallback for cards/readers that reject a single extended-`Lc`
/// APDU outright but parse ISO 7816-4 chaining fine — see
/// [`general_auth_sign_chained`] / [`put_data_chained`].
///
/// # Panics
/// Panics if `max_chunk` is 0 or greater than 255 (a single-byte `Lc` can't
/// exceed 255).
fn chain_apdu(
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: &[u8],
    max_chunk: usize,
    final_le: Option<u8>,
) -> Vec<Vec<u8>> {
    assert!(
        (1..=255).contains(&max_chunk),
        "command-chaining chunk size must be 1..=255"
    );
    if data.is_empty() {
        let mut apdu = vec![cla, ins, p1, p2, 0x00];
        if let Some(le) = final_le {
            apdu.push(le);
        }
        return vec![apdu];
    }
    let chunks: Vec<&[u8]> = data.chunks(max_chunk).collect();
    let last = chunks.len() - 1;
    chunks
        .into_iter()
        .enumerate()
        .map(|(i, chunk)| {
            let chained_cla = if i < last { cla | 0x10 } else { cla };
            let mut apdu = Vec::with_capacity(5 + chunk.len() + 1);
            apdu.extend_from_slice(&[chained_cla, ins, p1, p2, chunk.len() as u8]);
            apdu.extend_from_slice(chunk);
            if i == last {
                if let Some(le) = final_le {
                    apdu.push(le);
                }
            }
            apdu
        })
        .collect()
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

/// The GENERAL AUTHENTICATE dynamic-authentication template body shared by
/// [`general_auth_sign`] (single extended-length APDU) and
/// [`general_auth_sign_chained`] (ISO 7816-4 command chaining): `7C L 82 00
/// 81 <l> <payload>`.
fn general_auth_sign_data(payload: &[u8]) -> Vec<u8> {
    let mut inner = Vec::with_capacity(payload.len() + 6);
    inner.extend_from_slice(&[0x82, 0x00]); // response tag, empty: "give me the answer"
    push_tlv(&mut inner, &[0x81], payload); // challenge / data to sign
    let mut data = Vec::with_capacity(inner.len() + 4);
    push_tlv(&mut data, &[TAG_DYN_AUTH], &inner);
    data
}

/// GENERAL AUTHENTICATE in signing mode: ask a key slot to sign/decrypt
/// `payload` (a PKCS#1 block for RSA, or a raw hash for ECC). The card replies
/// with `7C L 82 <l> <result>`. `key_alg` is the slot's algorithm (P1),
/// `key_ref` its slot (P2).
#[must_use]
pub fn general_auth_sign(key_alg: KeyAlg, key_ref: u8, payload: &[u8]) -> Vec<u8> {
    build_apdu_ext(
        0x00,
        Instruction::GeneralAuthenticate.code(),
        key_alg.id(),
        key_ref,
        &general_auth_sign_data(payload),
        Some(0), // large RSA result: request the lot
    )
}

/// Command-chaining form of [`general_auth_sign`]: the same dynamic-auth
/// template, emitted as a sequence of chained `0x87` GENERAL AUTHENTICATE
/// APDUs (see [`chain_apdu`]) instead of one extended-length APDU. The final
/// chunk requests a short-form `Le` of `0x00` ("up to 256 bytes"); a reply
/// longer than that still chains normally through `61xx`/GET RESPONSE, which
/// is unaffected by how the *command* was sent.
///
/// This is the fallback for cards/readers that reject a single extended-`Lc`
/// GENERAL AUTHENTICATE outright — observed on a Token2 PIV token's contact
/// interface, which answers such a command with `SW=6A80` for both an
/// RSA-2048 signature (256-byte payload) and (see
/// [`put_data_chained`]) a PUT DATA certificate import, while accepting the
/// identical data chained.
#[must_use]
pub fn general_auth_sign_chained(
    key_alg: KeyAlg,
    key_ref: u8,
    payload: &[u8],
    max_chunk: usize,
) -> Vec<Vec<u8>> {
    chain_apdu(
        0x00,
        Instruction::GeneralAuthenticate.code(),
        key_alg.id(),
        key_ref,
        &general_auth_sign_data(payload),
        max_chunk,
        Some(0x00),
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

/// The PUT DATA body shared by [`put_data`] (single extended-length APDU) and
/// [`put_data_chained`] (ISO 7816-4 command chaining): `5C <tag> 53 <value>`.
fn put_data_body(tag: &[u8], value: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(tag.len() + value.len() + 8);
    push_tlv(&mut data, &[TAG_OBJECT_SELECTOR], tag); // 5C <tag>
    push_tlv(&mut data, &[TAG_DATA_TEMPLATE], value); // 53 <value>
    data
}

/// PUT DATA for the 3-byte object `tag`, writing `value` wrapped in the `0x53`
/// template. Used to import a slot certificate (see [`encode_certificate`]).
/// Requires management-key authentication.
#[must_use]
pub fn put_data(tag: &[u8], value: &[u8]) -> Vec<u8> {
    build_apdu_ext(
        0x00,
        Instruction::PutData.code(),
        GET_DATA_P1,
        GET_DATA_P2,
        &put_data_body(tag, value),
        None,
    )
}

/// Command-chaining form of [`put_data`]: the same `5C`/`53` body, emitted as
/// a sequence of chained `0xDB` PUT DATA APDUs (see [`chain_apdu`]) instead of
/// one extended-length APDU. PUT DATA returns no data, so no chunk requests an
/// `Le`.
///
/// This is the fallback for cards/readers that reject a single extended-`Lc`
/// PUT DATA outright — see [`general_auth_sign_chained`] for the confirmed
/// Token2 PIV case this addresses.
#[must_use]
pub fn put_data_chained(tag: &[u8], value: &[u8], max_chunk: usize) -> Vec<Vec<u8>> {
    chain_apdu(
        0x00,
        Instruction::PutData.code(),
        GET_DATA_P1,
        GET_DATA_P2,
        &put_data_body(tag, value),
        max_chunk,
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

/// FASC-N filler for a CHUID that doesn't represent a real federal employee —
/// the same 25 BCD/odd-parity-encoded bytes `yubico-piv-tool`'s own
/// `set-chuid` uses (`lib/util.c`'s `CHUID_TMPL`, bytes 2..27). Not meaningful
/// to hand-decode; kept byte-identical to known-good tooling rather than
/// inventing a different filler.
const CHUID_FASC_N: [u8; 25] = [
    0xD4, 0xE7, 0x39, 0xDA, 0x73, 0x9C, 0xED, 0x39, 0xCE, 0x73, 0x9D, 0x83, 0x68, 0x58, 0x21, 0x08,
    0x42, 0x10, 0x84, 0x21, 0xC8, 0x42, 0x10, 0xC3, 0xEB,
];

/// Civil (year, month, day) from a day count since the Unix epoch. Howard
/// Hinnant's `civil_from_days` algorithm — proleptic Gregorian, correct for
/// any non-negative `z` (i.e. any date on or after 1970-01-01, which every
/// realistic [`chuid_expiration_in_days`] call is). Vendored again here
/// rather than pulled in from `keyroost-ctap` (which has its own copy behind
/// SSH certificate timestamp formatting): each protocol crate in this
/// workspace stays free-standing rather than depending on a sibling for one
/// small function.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (y + i64::from(m <= 2), m, d)
}

/// Day count since the Unix epoch for a given (year, month, day). Howard
/// Hinnant's `days_from_civil` — the exact inverse of [`civil_from_days`]
/// (round-trip tested below), proleptic Gregorian.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64; // [0, 399]
    let doy = (153 * (i64::from(m) + if m > 2 { -3 } else { 9 }) + 2) / 5 + i64::from(d) - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy as u64; // [0, 146096]
    era * 146_097 + doe as i64 - 719_468
}

/// The latest year [`chuid_expiration_in_days`]'s clamp — and
/// [`x509::tbs_certificate`]'s own validity encoding — treat as meaningful:
/// `9999`, the conventional ceiling for a 4-digit-year date (ASN.1
/// GeneralizedTime included).
const MAX_EXPIRATION_YEAR: i64 = 9999;

/// The largest "valid for N days from now" a CHUID expiration or a
/// certificate's validity period can actually represent: the day count from
/// `now_unix_secs` to `9999-12-31`, the ceiling both
/// [`chuid_expiration_in_days`] and [`x509::tbs_certificate`] clamp to. Meant
/// to size a "Valid for" input's upper bound with the field's real capacity
/// rather than an arbitrary fixed number — and unlike a fixed cap, this one
/// keeps making sense as "now" moves forward across the calendar.
#[must_use]
pub fn max_valid_days(now_unix_secs: u64) -> u32 {
    let now_days = (now_unix_secs / 86_400) as i64;
    let max_days = days_from_civil(MAX_EXPIRATION_YEAR, 12, 31);
    (max_days - now_days).clamp(0, i64::from(u32::MAX)) as u32
}

/// Compute a CHUID expiration date (tag `0x35`, ASCII `YYYYMMDD`) as
/// `now_unix_secs` plus `valid_days` days — the same "valid for N days"
/// shape [`x509::tbs_certificate`]'s own validity period uses, rather than a
/// freeform date a caller would have to validate. The day count itself
/// (not just the resulting year) is clamped to [`MAX_EXPIRATION_YEAR`]'s
/// last day, so the result is always exactly 8 bytes and saturates cleanly
/// at `9999-12-31` regardless of how large `valid_days` is — clamping only
/// the year would leave an unclamped month/day from whatever the
/// out-of-range date actually landed on, which can read as an *earlier*
/// date than a smaller `valid_days` produces (e.g. year 10000's January 1st
/// clamped to "9999" reads as `9999-01-01`, earlier than `9999-12-31`). No
/// realistic caller ([`max_valid_days`]-bounded) comes anywhere near this.
#[must_use]
pub fn chuid_expiration_in_days(now_unix_secs: u64, valid_days: u32) -> [u8; 8] {
    let expiry_secs = now_unix_secs.saturating_add(u64::from(valid_days).saturating_mul(86_400));
    let days = (expiry_secs / 86_400) as i64;
    let days = days.min(days_from_civil(MAX_EXPIRATION_YEAR, 12, 31));
    let (y, m, d) = civil_from_days(days);
    let mut out = [0u8; 8];
    out.copy_from_slice(format!("{y:04}{m:02}{d:02}").as_bytes());
    out
}

/// Encode a CHUID data-object value (PIV object [`OBJECT_CHUID`], `5F C1 02`)
/// around a 16-byte card GUID and an 8-byte `YYYYMMDD` expiration date (see
/// [`chuid_expiration_in_days`]): `30 <FASC-N> 34 <guid> 35 <expiration> 3E
/// 00 FE 00`. Byte-identical in shape to `yubico-piv-tool`'s `set-chuid`
/// (`ykpiv_util_set_cardid`'s `CHUID_TMPL`) — same fixed FASC-N filler, only
/// the GUID and expiration vary. A fresh random `guid` here is exactly what
/// `set-chuid` does: Windows' PIV minidriver caches by CHUID, so writing a
/// new one is what makes it notice a card's contents changed.
#[must_use]
pub fn encode_chuid(guid: &[u8; 16], expiration: &[u8; 8]) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(2 + CHUID_FASC_N.len() + 2 + guid.len() + 2 + expiration.len() + 2 + 2);
    push_tlv(&mut out, &[0x30], &CHUID_FASC_N); // FASC-N (filler, not a real one)
    push_tlv(&mut out, &[0x34], guid); // GUID — the part that actually varies
    push_tlv(&mut out, &[0x35], expiration); // Expiration Date
    push_tlv(&mut out, &[0x3E], &[]); // Issuer Asymmetric Signature (empty)
    push_tlv(&mut out, &[0xFE], &[]); // LRC (empty)
    out
}

/// A CHUID read back off a card: FASC-N, GUID, expiration date, signature,
/// and LRC (tags `0x3E`/`0xFE` — see [`encode_chuid`]). The signature and LRC
/// carry no information worth surfacing in a UI (this crate's own
/// [`encode_chuid`] always writes both empty), but a caller displaying raw
/// protocol detail (e.g. `keyroostctl piv status`) may still want them, so
/// [`parse_chuid`] keeps all five rather than silently dropping two.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chuid {
    /// FASC-N (tag `0x30`), raw bytes — typically the 25-byte filler this
    /// crate itself writes ([`encode_chuid`]'s doc comment covers why it's
    /// not meaningful to hand-decode).
    pub fasc_n: Vec<u8>,
    /// GUID (tag `0x34`), raw bytes — typically 16.
    pub guid: Vec<u8>,
    /// Expiration date (tag `0x35`), raw bytes — typically 8 ASCII `YYYYMMDD`.
    pub expiration: Vec<u8>,
    /// Issuer Asymmetric Signature (tag `0x3E`), raw bytes — empty in every
    /// CHUID this crate writes. Unlike FASC-N/GUID/expiration, its absence
    /// doesn't make [`parse_chuid`] fail: an empty `Vec` either way.
    pub signature: Vec<u8>,
    /// LRC / error detection code (tag `0xFE`), raw bytes — empty in every
    /// CHUID this crate writes. Same optional treatment as `signature`.
    pub lrc: Vec<u8>,
}

impl Chuid {
    /// FASC-N as plain lowercase hex.
    #[must_use]
    pub fn fasc_n_display(&self) -> String {
        keyroost_proto::codec::hex_encode(&self.fasc_n)
    }

    /// GUID as canonical lowercase `8-4-4-4-12` hex (the conventional
    /// GUID/UUID text form), or plain hex when it isn't the standard 16
    /// bytes — a CHUID from a card this crate didn't write is under no
    /// obligation to be.
    #[must_use]
    pub fn guid_display(&self) -> String {
        format_guid(&self.guid)
    }

    /// Expiration as `YYYY-MM-DD`, or the raw bytes decoded lossily as text
    /// when they aren't 8 ASCII digits.
    #[must_use]
    pub fn expiration_display(&self) -> String {
        if self.expiration.len() == 8 && self.expiration.iter().all(u8::is_ascii_digit) {
            let s = std::str::from_utf8(&self.expiration).expect("validated ASCII digits above");
            format!("{}-{}-{}", &s[0..4], &s[4..6], &s[6..8])
        } else {
            String::from_utf8_lossy(&self.expiration).into_owned()
        }
    }

    /// Signature as plain lowercase hex (empty string when absent).
    #[must_use]
    pub fn signature_display(&self) -> String {
        keyroost_proto::codec::hex_encode(&self.signature)
    }

    /// LRC as plain lowercase hex (empty string when absent).
    #[must_use]
    pub fn lrc_display(&self) -> String {
        keyroost_proto::codec::hex_encode(&self.lrc)
    }
}

/// Format a byte slice as canonical lowercase `8-4-4-4-12` hex (the
/// conventional GUID/UUID text form) when it's exactly 16 bytes, or plain
/// hex otherwise. Used for [`Chuid::guid_display`] and for pre-filling a
/// "New CHUID" GUID input with a freshly-generated value before it's ever
/// been through a [`Chuid`].
#[must_use]
pub fn format_guid(bytes: &[u8]) -> String {
    if bytes.len() != 16 {
        return keyroost_proto::codec::hex_encode(bytes);
    }
    let mut s = String::with_capacity(36);
    for (i, b) in bytes.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            s.push('-');
        }
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Parse a user-typed GUID — hex, optionally with UUID-style dashes and/or
/// surrounding whitespace, case-insensitive — into the 16 raw bytes
/// [`encode_chuid`] writes verbatim into tag `0x34`. `None` for anything that
/// isn't exactly 32 hex digits once dashes and whitespace are stripped, so a
/// caller (the "New CHUID" GUID input) can tell a bad manual override apart
/// from a usable one without duplicating hex parsing itself.
#[must_use]
pub fn parse_guid_hex(s: &str) -> Option<[u8; 16]> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    keyroost_proto::codec::hex_decode(&cleaned)
        .ok()?
        .try_into()
        .ok()
}

/// Parse a CHUID data-object value (what `PivSession::read_chuid` in
/// `keyroost-transport` reads back, or what [`encode_chuid`] builds) into its
/// FASC-N, GUID, and expiration fields.
///
/// `None` when any of the three tags is missing entirely — an emptied
/// (deleted) CHUID object, or a non-PIV data blob — treated the same as "no
/// CHUID" rather than an error; a read-only display shouldn't fail the whole
/// status read over a card that answers something unexpected.
#[must_use]
pub fn parse_chuid(value: &[u8]) -> Option<Chuid> {
    Some(Chuid {
        fasc_n: find_tlv(value, 0x30)?.to_vec(),
        guid: find_tlv(value, 0x34)?.to_vec(),
        expiration: find_tlv(value, 0x35)?.to_vec(),
        // Optional: their absence doesn't invalidate an otherwise-well-formed
        // CHUID, unlike the three mandatory fields above.
        signature: find_tlv(value, 0x3E).unwrap_or(&[]).to_vec(),
        lrc: find_tlv(value, 0xFE).unwrap_or(&[]).to_vec(),
    })
}

/// CHANGE REFERENCE DATA: change the PIN (`PIN_REF_APPLICATION`) or PUK
/// (`PIN_REF_PUK`) from `old` to `new`. Both are padded to 8 bytes and must be
/// 6–8 bytes ([`PinLengthError`] otherwise).
pub fn change_reference(reference: u8, old: &[u8], new: &[u8]) -> Result<Vec<u8>, PinLengthError> {
    let mut body = pad_pin(old)?;
    body.extend_from_slice(&pad_pin(new)?);
    Ok(build_apdu(
        0x00,
        Instruction::ChangeReference.code(),
        0x00,
        reference,
        &body,
    ))
}

/// RESET RETRY COUNTER: unblock the PIN using the PUK, setting a new PIN. Both
/// `puk` and `new_pin` are padded to 8 bytes and must be 6–8 bytes
/// ([`PinLengthError`] otherwise).
pub fn unblock_pin(puk: &[u8], new_pin: &[u8]) -> Result<Vec<u8>, PinLengthError> {
    let mut body = pad_pin(puk)?;
    body.extend_from_slice(&pad_pin(new_pin)?);
    Ok(build_apdu(
        0x00,
        Instruction::ResetRetryCounter.code(),
        0x00,
        PIN_REF_APPLICATION,
        &body,
    ))
}

/// Yubico SET MANAGEMENT KEY: replace the 9B card-management key. `require_touch`
/// gates every future management-key auth on a physical touch. Requires prior
/// management-key authentication.
#[must_use]
pub fn set_management_key(alg: MgmtAlg, key: &[u8], require_touch: bool) -> Vec<u8> {
    assert!(key.len() <= 255, "management key too long");
    // Body: <alg> 9B <keylen> <key>. Holds the new management key; wipe on drop.
    let mut body = Zeroizing::new(Vec::with_capacity(3 + key.len()));
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

/// Yubico ATTEST (case 2): request the self-signed attestation certificate for
/// the key in `key_ref`'s slot. `P1` is the slot's key reference, `P2` is
/// `0x00`; no data field. Requires firmware 4.3+. The certificate can exceed
/// 256 bytes, so the reply chains through `61xx`/GET RESPONSE the same way a
/// GET DATA certificate read does.
#[must_use]
pub fn attest(key_ref: u8) -> Vec<u8> {
    build_apdu_get(0x00, Instruction::Attest.code(), key_ref, 0x00, 0x00)
}

/// Yubico extension: DELETE a slot's private key by issuing MOVE KEY with the
/// `0xFF` destination sentinel (P1 = destination = `0xFF`, P2 = source slot
/// reference). This permanently erases the key material in `slot`; the slot's
/// certificate object is untouched. Requires firmware 5.7+ and prior
/// management-key authentication. There is no standard-PIV equivalent.
#[must_use]
pub fn delete_key(slot: Slot) -> Vec<u8> {
    vec![0x00, Instruction::MoveKey.code(), 0xFF, slot.key_ref()]
}

/// Yubico MOVE KEY: relocate a slot's private key to another slot.
/// `00 F6 <dest key_ref> <src key_ref>`. The move variant of the same 0xF6
/// opcode whose 0xFF-sentinel form deletes (see [`delete_key`]). Moves ONLY
/// the private key — the source slot's certificate object is untouched.
/// Requires firmware 5.7+ and prior management-key authentication.
#[must_use]
pub fn move_key(src: Slot, dest: Slot) -> Vec<u8> {
    vec![
        0x00,
        Instruction::MoveKey.code(),
        dest.key_ref(),
        src.key_ref(),
    ]
}

/// Clear a slot's certificate object by writing an empty PUT DATA template
/// (`53 00`). Standard PIV and universal across firmware. This removes only the
/// X.509 certificate from `slot`; the slot's private key persists. Requires
/// prior management-key authentication.
#[must_use]
pub fn clear_certificate(slot: Slot) -> Vec<u8> {
    put_data(&slot.cert_object_tag(), &[])
}

/// Pad a PIN/PUK to the fixed 8-byte PIV field with trailing `0xFF`.
///
/// PIV PINs and PUKs are 6–8 bytes (SP 800-73). An over-length value must never
/// be silently truncated: that would build a VERIFY/CHANGE for a *different*,
/// valid-length secret than the caller supplied and burn a retry against the
/// card. This crate is a published byte layer, so a direct consumer that skips
/// its own validation gets a typed [`PinLengthError`] here instead of an abort.
fn pad_pin(pin: &[u8]) -> Result<Zeroizing<Vec<u8>>, PinLengthError> {
    if !(6..=8).contains(&pin.len()) {
        return Err(PinLengthError { len: pin.len() });
    }
    // Zeroizing so this padded secret (and any body built from it) is wiped on
    // drop; the final APDU is wrapped in Zeroizing by the transport layer.
    let mut out = Zeroizing::new(vec![0xFFu8; 8]);
    out[..pin.len()].copy_from_slice(pin);
    Ok(out)
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

/// Format a Yubico `GET VERSION` reply for display — tolerant of any
/// non-empty length. Feature gates on the transport side (`move_key_supported`
/// et al.) compare the same raw bytes directly as a slice rather than parsing
/// them into a fixed-width tuple first, so there's no separate strict parse
/// to defer to here either. Up to 4 bytes still reads as a version number, so
/// it's dot-joined as decimal (`major.minor.patch[...]`, covering both real
/// Yubico firmware's 3 bytes and small vendor variants like a 4-byte reply
/// observed from a Swissbit OpenFIPS201 build). Past 4 bytes, dot-joining
/// stops being a meaningful "version" and just obscures the actual bytes, so
/// it falls back to plain lowercase hex.
#[must_use]
pub fn format_version_bytes(bytes: &[u8]) -> String {
    if bytes.len() <= 4 {
        bytes
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(".")
    } else {
        keyroost_proto::codec::hex_encode(bytes)
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
    fn instruction_code_round_trips_to_a_name() {
        // Every instruction this crate builds decodes from its own byte and
        // carries a non-empty human name; Yubico extensions say so.
        for ins in [
            Instruction::Select,
            Instruction::Verify,
            Instruction::GetData,
            Instruction::GetResponse,
            Instruction::GeneralAuthenticate,
            Instruction::GenerateKeyPair,
            Instruction::PutData,
            Instruction::ChangeReference,
            Instruction::ResetRetryCounter,
            Instruction::GetVersion,
            Instruction::GetSerial,
            Instruction::GetMetadata,
            Instruction::MoveKey,
            Instruction::SetManagementKey,
            Instruction::SetPinRetries,
            Instruction::Reset,
            Instruction::Attest,
        ] {
            assert_eq!(Instruction::from_code(ins.code()), Some(ins));
            assert!(!ins.name().is_empty());
        }
        assert_eq!(Instruction::GetVersion.name(), "GET VERSION (yubico extension)");
        assert_eq!(Instruction::Select.name(), "SELECT");
        assert_eq!(Instruction::from_code(0x00), None);
    }

    #[test]
    fn data_object_names() {
        assert_eq!(
            data_object_name(&[0x5F, 0xC1, 0x05]).as_deref(),
            Some("X.509 Certificate for PIV Authentication")
        );
        assert_eq!(data_object_name(&[0x7E]).as_deref(), Some("Discovery Object"));
        // Numbered ranges: 5F C1 0D..20 -> Retired 1..20; 5F FF 11..15 -> MSROOTS 1..5.
        assert_eq!(
            data_object_name(&Slot::Retired(1).cert_object_tag()).as_deref(),
            Some("Retired X.509 Certificate for Key Management 1")
        );
        assert_eq!(
            data_object_name(&Slot::Retired(20).cert_object_tag()).as_deref(),
            Some("Retired X.509 Certificate for Key Management 20")
        );
        assert_eq!(
            data_object_name(&[0x5F, 0xFF, 0x13]).as_deref(),
            Some("Yubico MSROOTS 3")
        );
        assert_eq!(
            data_object_name(&[0x5F, 0xFF, 0x01]).as_deref(),
            Some("Yubico PIV Attestation Certificate")
        );
        // Unassigned tags have no name.
        assert_eq!(data_object_name(&[0x5F, 0xC1, 0x99]), None);
        assert_eq!(data_object_name(&[]), None);
    }

    #[test]
    fn select_full_bytes() {
        // 00 A4 04 00 0B A0 00 00 03 08 00 00 10 00 01 00 00
        assert_eq!(
            select_full(),
            vec![
                0x00, 0xA4, 0x04, 0x00, 0x0B, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00,
                0x01, 0x00, 0x00
            ]
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
    fn retired_slot_refs_and_tags_across_the_range() {
        let r1 = Slot::retired(1).unwrap();
        let r20 = Slot::retired(20).unwrap();
        assert_eq!(r1.key_ref(), 0x82);
        assert_eq!(r20.key_ref(), 0x95);
        assert_eq!(r1.cert_object_tag(), [0x5F, 0xC1, 0x0D]);
        assert_eq!(r20.cert_object_tag(), [0x5F, 0xC1, 0x20]);
        // Out-of-range rejected by the constructor.
        assert!(Slot::retired(0).is_none());
        assert!(Slot::retired(21).is_none());
        // retired_all() is the 20 retired slots in order.
        let all = Slot::retired_all();
        assert_eq!(all.len(), 20);
        assert_eq!(all[0], r1);
        assert_eq!(all[19], r20);
        // The standard Slot::all() is unchanged (still 4).
        assert_eq!(Slot::all().len(), 4);
    }

    #[test]
    fn retired_label_is_stable() {
        assert_eq!(Slot::retired(1).unwrap().label(), "retired key 1 (82)");
        assert_eq!(Slot::retired(20).unwrap().label(), "retired key 20 (95)");
    }

    #[test]
    fn verify_pin_pads_to_eight() {
        // 00 20 00 80 08 31 32 33 34 35 36 FF FF   ("123456" + FF FF)
        assert_eq!(
            verify_pin(b"123456").unwrap(),
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
        buf.extend(std::iter::repeat_n(0x11, 128));
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
    fn parse_serial_values() {
        assert_eq!(parse_serial(&[0x02, 0x40, 0x8A, 0x1B]).unwrap(), 0x02408A1B);
        assert!(parse_serial(&[0x00, 0x01]).is_err());
    }

    #[test]
    fn format_version_bytes_dots_up_to_four_bytes() {
        assert_eq!(format_version_bytes(&[5, 7, 1]), "5.7.1");
        assert_eq!(format_version_bytes(&[1, 0, 0, 0]), "1.0.0.0");
        assert_eq!(format_version_bytes(&[9]), "9");
        assert_eq!(format_version_bytes(&[]), "");
    }

    #[test]
    fn format_version_bytes_falls_back_to_hex_past_four_bytes() {
        assert_eq!(
            format_version_bytes(&[0x01, 0x02, 0x03, 0x04, 0x05]),
            "0102030405"
        );
        assert_eq!(
            format_version_bytes(&[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]),
            "deadbeefcafe"
        );
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
        let apdu = change_reference(PIN_REF_APPLICATION, b"123456", b"654321").unwrap();
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
        let apdu = unblock_pin(b"12345678", b"000000").unwrap();
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
    fn attest_apdu_bytes() {
        // 00 F9 <slot key ref> 00 00 — P1 is the slot, P2 is 0x00, Le=0x00 (256,
        // chained via GET RESPONSE for the certificate's full length).
        assert_eq!(attest(0x9A), vec![0x00, 0xF9, 0x9A, 0x00, 0x00]);
        assert_eq!(attest(0x9C), vec![0x00, 0xF9, 0x9C, 0x00, 0x00]);
    }

    #[test]
    fn pin_touch_policy_id_round_trips() {
        for p in [
            PinPolicy::Default,
            PinPolicy::Never,
            PinPolicy::Once,
            PinPolicy::Always,
        ] {
            assert_eq!(PinPolicy::from_id(p.id()), Some(p));
        }
        assert_eq!(PinPolicy::from_id(0x04), None);

        for t in [
            TouchPolicy::Default,
            TouchPolicy::Never,
            TouchPolicy::Always,
            TouchPolicy::Cached,
        ] {
            assert_eq!(TouchPolicy::from_id(t.id()), Some(t));
        }
        assert_eq!(TouchPolicy::from_id(0x04), None);
    }

    #[test]
    fn delete_key_kat_all_slots() {
        // 00 F6 FF <slot_ref> — MOVE KEY with the 0xFF delete sentinel.
        assert_eq!(delete_key(Slot::Signature), vec![0x00, 0xF6, 0xFF, 0x9C]);
        assert_eq!(
            delete_key(Slot::Authentication),
            vec![0x00, 0xF6, 0xFF, 0x9A]
        );
        assert_eq!(
            delete_key(Slot::KeyManagement),
            vec![0x00, 0xF6, 0xFF, 0x9D]
        );
        assert_eq!(
            delete_key(Slot::CardAuthentication),
            vec![0x00, 0xF6, 0xFF, 0x9E]
        );
    }

    #[test]
    fn move_key_kat() {
        // 00 F6 <dest> <src>. Standard -> retired (archive KeyManagement to Retired1).
        assert_eq!(
            move_key(Slot::KeyManagement, Slot::retired(1).unwrap()),
            vec![0x00, 0xF6, 0x82, 0x9D]
        );
        // Retired -> standard (restore).
        assert_eq!(
            move_key(Slot::retired(20).unwrap(), Slot::Authentication),
            vec![0x00, 0xF6, 0x9A, 0x95]
        );
        // Standard -> standard.
        assert_eq!(
            move_key(Slot::Signature, Slot::CardAuthentication),
            vec![0x00, 0xF6, 0x9E, 0x9C]
        );
    }

    #[test]
    fn clear_certificate_kat_all_slots() {
        // 00 DB 3F FF 07 5C 03 5F C1 0x 53 00 — empty PUT DATA template.
        assert_eq!(
            clear_certificate(Slot::Authentication),
            vec![0x00, 0xDB, 0x3F, 0xFF, 0x07, 0x5C, 0x03, 0x5F, 0xC1, 0x05, 0x53, 0x00]
        );
        assert_eq!(
            clear_certificate(Slot::Signature),
            vec![0x00, 0xDB, 0x3F, 0xFF, 0x07, 0x5C, 0x03, 0x5F, 0xC1, 0x0A, 0x53, 0x00]
        );
        assert_eq!(
            clear_certificate(Slot::KeyManagement),
            vec![0x00, 0xDB, 0x3F, 0xFF, 0x07, 0x5C, 0x03, 0x5F, 0xC1, 0x0B, 0x53, 0x00]
        );
        assert_eq!(
            clear_certificate(Slot::CardAuthentication),
            vec![0x00, 0xDB, 0x3F, 0xFF, 0x07, 0x5C, 0x03, 0x5F, 0xC1, 0x01, 0x53, 0x00]
        );
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
    fn put_data_chained_single_chunk_clears_chain_bit() {
        let value = vec![0xDE, 0xAD];
        let tag = Slot::Signature.cert_object_tag();
        let chunks = put_data_chained(&tag, &value, 254);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0][0], 0x00); // no chaining bit: fits in one link
        assert_eq!(chunks[0][1], 0xDB); // PUT DATA
    }

    #[test]
    fn put_data_chained_reassembles_to_extended_body() {
        // The chained chunks' data fields must concatenate to exactly the
        // same body a single extended-length PUT DATA would carry.
        let der = vec![0x11u8; 1024];
        let value = encode_certificate(&der);
        let tag = Slot::Signature.cert_object_tag();

        let extended = put_data(&tag, &value);
        // Extended form: 00 DB 3F FF 00 <2-byte Lc> <body>.
        let ext_lc = ((extended[5] as usize) << 8) | extended[6] as usize;
        let ext_body = &extended[7..7 + ext_lc];

        let chunks = put_data_chained(&tag, &value, 254);
        assert!(chunks.len() > 1); // 1024+ bytes doesn't fit one 254-byte link
        let last = chunks.len() - 1;
        let mut reassembled = Vec::new();
        for (i, chunk) in chunks.iter().enumerate() {
            let expected_cla = if i < last { 0x10 } else { 0x00 };
            assert_eq!(chunk[0], expected_cla);
            assert_eq!(chunk[1], 0xDB);
            let lc = chunk[4] as usize;
            assert!(lc <= 254);
            reassembled.extend_from_slice(&chunk[5..5 + lc]);
            if i == last {
                assert_eq!(chunk.len(), 5 + lc); // PUT DATA requests no Le
            }
        }
        assert_eq!(reassembled, ext_body);
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
    fn encode_chuid_matches_yubico_piv_tool_template() {
        // Known-answer: `yubico-piv-tool`'s own CHUID_TMPL (lib/util.c,
        // ykpiv_util_set_cardid), reproduced byte-for-byte with the template's
        // own all-zero GUID placeholder substituted in, to pin agreement with
        // an independent reference implementation rather than just this
        // crate's own encoder logic.
        #[rustfmt::skip]
        const CHUID_TMPL: [u8; 59] = [
            0x30, 0x19, 0xD4, 0xE7, 0x39, 0xDA, 0x73, 0x9C, 0xED, 0x39, 0xCE, 0x73, 0x9D,
            0x83, 0x68, 0x58, 0x21, 0x08, 0x42, 0x10, 0x84, 0x21, 0xC8, 0x42, 0x10, 0xC3,
            0xEB, 0x34, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x35, 0x08, 0x32, 0x30, 0x33, 0x30, 0x30,
            0x31, 0x30, 0x31, 0x3E, 0x00, 0xFE, 0x00,
        ];
        let default_expiration = chuid_expiration_in_days(0, 21_915); // 1970-01-01 + 21915d = 2030-01-01
        assert_eq!(&default_expiration, b"20300101");
        assert_eq!(encode_chuid(&[0u8; 16], &default_expiration), CHUID_TMPL);
    }

    #[test]
    fn encode_chuid_places_guid_at_the_yubico_offset() {
        // CHUID_GUID_OFFS in yubico-piv-tool is 29; a distinctive GUID must
        // land exactly there, with the fixed filler on both sides untouched.
        let guid = [
            0xAAu8, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0x00,
        ];
        let value = encode_chuid(&guid, b"20300101");
        assert_eq!(&value[29..45], &guid);
    }

    #[test]
    fn encode_chuid_places_expiration_after_the_guid() {
        let expiration = *b"20991231";
        let value = encode_chuid(&[0u8; 16], &expiration);
        // Tag/length (35 08) at offset 45 (29 + 16), value right after.
        assert_eq!(&value[45..47], &[0x35, 0x08]);
        assert_eq!(&value[47..55], &expiration);
    }

    #[test]
    fn chuid_expiration_in_days_zero_days_is_today() {
        // Known-answer timestamps shared with keyroost-ctap's
        // format_timestamp tests (ssh_cert.rs): 0 = 1970-01-01,
        // 1767225600 = 2026-01-01 — same civil_from_days algorithm, cross-
        // checked against an independent test of it.
        assert_eq!(&chuid_expiration_in_days(0, 0), b"19700101");
        assert_eq!(&chuid_expiration_in_days(1_767_225_600, 0), b"20260101");
    }

    #[test]
    fn chuid_expiration_in_days_adds_whole_days() {
        // +1 day from epoch.
        assert_eq!(&chuid_expiration_in_days(0, 1), b"19700102");
        // +365 days from a non-leap year's Jan 1 lands on the next Jan 1.
        assert_eq!(&chuid_expiration_in_days(1_767_225_600, 365), b"20270101");
        // Crosses a leap-year February (2028): 2026-01-01 + 730d = 2028-01-01
        // (365 + 365, neither 2026 nor 2027 is a leap year); +790d lands
        // 31+29 days into 2028 (a leap year), i.e. 2028-03-01.
        assert_eq!(&chuid_expiration_in_days(1_767_225_600, 730), b"20280101");
        assert_eq!(&chuid_expiration_in_days(1_767_225_600, 790), b"20280301");
    }

    #[test]
    fn chuid_expiration_in_days_extreme_valid_days_does_not_panic() {
        // A caller-supplied day count far beyond any realistic UI bound must
        // degrade (via the year clamp), not panic building the output.
        let out = chuid_expiration_in_days(0, u32::MAX);
        assert_eq!(out.len(), 8);
        assert!(out.iter().all(u8::is_ascii_digit));
    }

    #[test]
    fn days_from_civil_round_trips_civil_from_days() {
        // The exact known-answer pairs format_timestamp's tests in
        // keyroost-ctap already pin (ssh_cert.rs): 0 = 1970-01-01,
        // 1767225600 secs = 2026-01-01 -> day 20454. Round-tripping through
        // both directions of the same algorithm is the strongest available
        // check without an external date library to compare against.
        for days in [0i64, 1, 365, 20_454, 2_932_896, 3_652_364] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days, "round-trip for day {days}");
        }
    }

    #[test]
    fn max_valid_days_reaches_exactly_9999_12_31() {
        let now = 0u64; // 1970-01-01
        let days = max_valid_days(now);
        let expiration = chuid_expiration_in_days(now, days);
        assert_eq!(&expiration, b"99991231");
        // One day more must clamp rather than overshoot into a 5-digit year.
        let expiration = chuid_expiration_in_days(now, days + 1);
        assert_eq!(&expiration, b"99991231");
    }

    #[test]
    fn max_valid_days_shrinks_as_now_advances() {
        assert!(max_valid_days(1_767_225_600) < max_valid_days(0)); // 2026-01-01 vs 1970-01-01
    }

    #[test]
    fn max_valid_days_never_negative_past_the_year_9999_line() {
        // "now" already past 9999-12-31: saturates at 0, not a huge unsigned
        // wraparound from a negative subtraction.
        let far_future_secs = u64::MAX / 2;
        assert_eq!(max_valid_days(far_future_secs), 0);
    }

    #[test]
    fn parse_chuid_round_trips_encode_chuid() {
        let guid = [
            0xAAu8, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0x00,
        ];
        let expiration = *b"20300101";
        let value = encode_chuid(&guid, &expiration);
        let chuid = parse_chuid(&value).expect("well-formed CHUID must parse");
        assert_eq!(chuid.fasc_n, CHUID_FASC_N.to_vec());
        assert_eq!(chuid.guid, guid.to_vec());
        assert_eq!(chuid.expiration, expiration.to_vec());
        // encode_chuid always writes both tags present but empty.
        assert_eq!(chuid.signature, Vec::<u8>::new());
        assert_eq!(chuid.lrc, Vec::<u8>::new());
    }

    #[test]
    fn parse_chuid_tolerates_a_missing_signature_and_lrc() {
        // Only the three mandatory tags — a foreign card is under no
        // obligation to include an (always-empty, in this crate's own
        // writes) signature or LRC tag at all.
        let mut value = Vec::new();
        push_tlv(&mut value, &[0x30], &CHUID_FASC_N);
        push_tlv(&mut value, &[0x34], &[0u8; 16]);
        push_tlv(&mut value, &[0x35], b"20300101");
        let chuid = parse_chuid(&value).expect("the three mandatory tags are present");
        assert_eq!(chuid.signature, Vec::<u8>::new());
        assert_eq!(chuid.lrc, Vec::<u8>::new());
    }

    #[test]
    fn chuid_signature_and_lrc_display_are_plain_hex() {
        let chuid = Chuid {
            fasc_n: vec![],
            guid: vec![],
            expiration: vec![],
            signature: vec![0xAB, 0xCD],
            lrc: vec![0x12],
        };
        assert_eq!(chuid.signature_display(), "abcd");
        assert_eq!(chuid.lrc_display(), "12");
        // Absent (empty Vec) displays as an empty string, not a placeholder.
        let empty = Chuid {
            fasc_n: vec![],
            guid: vec![],
            expiration: vec![],
            signature: vec![],
            lrc: vec![],
        };
        assert_eq!(empty.signature_display(), "");
        assert_eq!(empty.lrc_display(), "");
    }

    #[test]
    fn parse_chuid_missing_a_tag_is_none_not_an_error() {
        // An emptied (deleted) CHUID object: SW_OK, zero-length `53 00` body
        // (see the analogous cert_status_from_reply regression in
        // keyroost-transport) — no FASC-N/GUID/expiration tags at all.
        assert_eq!(parse_chuid(&[]), None);
        // Only a GUID tag present — still not a usable CHUID.
        let mut partial = vec![0x34, 0x02];
        partial.extend_from_slice(&[0xAB, 0xCD]);
        assert_eq!(parse_chuid(&partial), None);
    }

    #[test]
    fn chuid_guid_display_is_canonical_dashed_hex() {
        let chuid = Chuid {
            fasc_n: vec![],
            guid: vec![
                0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                0x99, 0x00,
            ],
            expiration: vec![],
            signature: vec![],
            lrc: vec![],
        };
        assert_eq!(chuid.guid_display(), "aabbccdd-eeff-1122-3344-556677889900");
    }

    #[test]
    fn chuid_guid_display_falls_back_to_plain_hex_for_non_16_bytes() {
        let chuid = Chuid {
            fasc_n: vec![],
            guid: vec![0xAB, 0xCD],
            expiration: vec![],
            signature: vec![],
            lrc: vec![],
        };
        assert_eq!(chuid.guid_display(), "abcd");
    }

    #[test]
    fn parse_guid_hex_round_trips_format_guid() {
        let bytes: [u8; 16] = [
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0x00,
        ];
        let dashed = format_guid(&bytes);
        assert_eq!(dashed, "aabbccdd-eeff-1122-3344-556677889900");
        assert_eq!(parse_guid_hex(&dashed), Some(bytes));
        // Bare hex, no dashes, uppercase, with stray surrounding whitespace.
        assert_eq!(
            parse_guid_hex("  AABBCCDDEEFF112233445566778899 00 "),
            Some(bytes)
        );
    }

    #[test]
    fn parse_guid_hex_rejects_wrong_length_and_non_hex() {
        assert_eq!(parse_guid_hex(""), None);
        assert_eq!(parse_guid_hex("aabb"), None);
        assert_eq!(parse_guid_hex("not-hex-at-all-not-hex-at-all-x"), None);
    }

    #[test]
    fn chuid_expiration_display_inserts_dashes() {
        let chuid = Chuid {
            fasc_n: vec![],
            guid: vec![],
            expiration: b"20300101".to_vec(),
            signature: vec![],
            lrc: vec![],
        };
        assert_eq!(chuid.expiration_display(), "2030-01-01");
    }

    #[test]
    fn chuid_expiration_display_falls_back_to_lossy_text_for_non_digits() {
        let chuid = Chuid {
            fasc_n: vec![],
            guid: vec![],
            expiration: vec![0xFF, 0xFE],
            signature: vec![],
            lrc: vec![],
        };
        // Not asserting the exact replacement-character text, only that it
        // doesn't panic and returns something.
        assert!(!chuid.expiration_display().is_empty());
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
    fn general_auth_sign_chained_single_chunk_keeps_le() {
        let chunks =
            general_auth_sign_chained(KeyAlg::EccP256, 0x9A, &[0xAA, 0xBB, 0xCC, 0xDD], 254);
        assert_eq!(chunks.len(), 1);
        assert_eq!(
            chunks[0],
            vec![
                0x00, 0x87, 0x11, 0x9A, 0x0A, 0x7C, 0x08, 0x82, 0x00, 0x81, 0x04, 0xAA, 0xBB, 0xCC,
                0xDD, 0x00,
            ]
        );
    }

    #[test]
    fn general_auth_sign_chained_reassembles_to_extended_body() {
        // The chained chunks' bodies must reassemble to exactly the same
        // dynamic-auth template a single extended-length APDU would carry,
        // and only the final chunk carries Le.
        let payload = [0x55u8; 256]; // RSA-2048 prepared block
        let extended = general_auth_sign(KeyAlg::Rsa2048, 0x9A, &payload);
        let ext_lc = ((extended[5] as usize) << 8) | extended[6] as usize;
        let ext_body = &extended[7..7 + ext_lc];

        let chunks = general_auth_sign_chained(KeyAlg::Rsa2048, 0x9A, &payload, 254);
        assert!(chunks.len() > 1);
        let last = chunks.len() - 1;
        let mut reassembled = Vec::new();
        for (i, chunk) in chunks.iter().enumerate() {
            let expected_cla = if i < last { 0x10 } else { 0x00 };
            assert_eq!(chunk[0], expected_cla);
            assert_eq!(&chunk[1..4], &[0x87, 0x07, 0x9A]); // INS, P1 (RSA-2048), P2
            let lc = chunk[4] as usize;
            assert!(lc <= 254);
            reassembled.extend_from_slice(&chunk[5..5 + lc]);
            if i == last {
                assert_eq!(&chunk[5 + lc..], &[0x00]); // short-form Le on the final link only
            } else {
                assert_eq!(chunk.len(), 5 + lc); // no Le on intermediate links
            }
        }
        assert_eq!(reassembled, ext_body);
    }

    #[test]
    fn get_response_bytes() {
        assert_eq!(get_response(), vec![0x00, 0xC0, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn pad_pin_pads_short_within_range() {
        // A 6-byte PIN is 0xFF-padded to the fixed 8-byte field.
        let apdu = verify_pin(b"123456").unwrap();
        assert_eq!(
            &apdu[5..],
            &[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF]
        );
    }

    #[test]
    fn pad_pin_rejects_over_length_instead_of_truncating() {
        // A >8-byte value must never be silently truncated into a different,
        // valid-length PIN — that would build a VERIFY for the wrong secret
        // and burn a retry against the card. This crate is published, so the
        // contract is a typed error, not a process abort.
        assert_eq!(
            verify_pin(b"1234567890").unwrap_err(),
            PinLengthError { len: 10 }
        );
    }

    #[test]
    fn pin_length_boundaries_error_instead_of_panicking() {
        // 6 and 8 are the inclusive SP 800-73 bounds; everything outside is a
        // typed error from every PIN-carrying builder.
        for bad in [&b""[..], b"12345", b"123456789"] {
            assert_eq!(
                verify_pin(bad).unwrap_err(),
                PinLengthError { len: bad.len() }
            );
            assert!(change_reference(PIN_REF_APPLICATION, bad, b"654321").is_err());
            assert!(change_reference(PIN_REF_APPLICATION, b"123456", bad).is_err());
            assert!(unblock_pin(bad, b"000000").is_err());
            assert!(unblock_pin(b"12345678", bad).is_err());
        }
        assert!(verify_pin(b"123456").is_ok());
        assert!(verify_pin(b"12345678").is_ok());
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
