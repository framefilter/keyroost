//! OpenPGP Card (v3.4) APDU command/response layer.
//!
//! Phase 4 of extending MoltoUI toward ykman parity. The OpenPGP applet is a
//! CCID/APDU smartcard applet on YubiKeys and Trussed devices (Solo 2 / Nitrokey
//! 3, via `opcard`), reachable over the existing PC/SC transport — no second
//! transport stack. This crate is the pure-Rust command/response layer (APDU
//! builders + the application-related-data TLV parser); the actual card exchange
//! lives in `molto2-transport`.
//!
//! Reference: OpenPGP Card spec v3.4, and `Nitrokey/opcard-rs`.
//!
//! # What is and isn't here
//!
//! This is the *byte layer*: it turns intentions into APDU byte vectors and
//! turns response byte slices into typed structures. It performs **no I/O**.
//! Card transmit, the `61xx` / `GET RESPONSE` reassembly loop, PIN entry, and
//! the higher-level key-management operations are deliberately left for the
//! transport phase; see the `TODO(transport)` notes on [`Instruction`] and the
//! builders that are intentionally absent.
//!
//! Unlike the OATH applet (Yubico's SIMPLE-TLV, short-form lengths only), the
//! OpenPGP applet uses ISO 7816-4 **BER-TLV**: two-byte ("high") tags and
//! long-form lengths. The parser here handles both forms; see [`parse_tlvs`].

use molto2_proto::apdu::{build_apdu, build_apdu_get};

// ---------------------------------------------------------------------------
// Application identifier
// ---------------------------------------------------------------------------

/// OpenPGP application AID *prefix* used to `SELECT` the applet by DF name:
/// RID `D2 76 00 01 24` (PGP) + application `01` (OpenPGP). The full 16-byte
/// AID on the card additionally carries the spec version, manufacturer, and a
/// serial number — but [`select`] addresses the applet with this 6-byte prefix.
pub const AID_PREFIX: [u8; 6] = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];

// ---------------------------------------------------------------------------
// Instruction bytes
// ---------------------------------------------------------------------------

/// ISO 7816 `SELECT` instruction (used to activate the applet).
pub const INS_SELECT: u8 = 0xA4;
/// `SELECT` P1: select by DF name (AID).
pub const P1_SELECT_BY_NAME: u8 = 0x04;

/// OpenPGP Card instruction bytes (OpenPGP Card spec v3.4, §7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Instruction {
    /// `SELECT` (ISO 7816) — activate the OpenPGP applet.
    Select = 0xA4,
    /// `GET DATA` — read a data object by its (1- or 2-byte) tag in P1-P2.
    GetData = 0xCA,
    /// `PUT DATA` — write a data object.
    ///
    /// TODO(transport): the PUT DATA *builders* (cardholder name, URL, PW status
    /// flags, key import) are intentionally not modelled in this byte layer yet;
    /// they need the host-side key encoding decided in the transport phase.
    PutData = 0xDA,
    /// `VERIFY` — present a PIN (PW1/PW3) referenced by P2.
    Verify = 0x20,
    /// `CHANGE REFERENCE DATA` — change a PIN.
    ///
    /// TODO(transport): builder not provided yet (PIN material is the user's;
    /// see the privacy posture in `CLAUDE.md`).
    ChangeReferenceData = 0x24,
    /// `RESET RETRY COUNTER` — unblock PW1 using PW3 or the resetting code.
    ///
    /// TODO(transport): builder not provided yet.
    ResetRetryCounter = 0x2C,
    /// `PERFORM SECURITY OPERATION` — compute signature (P1P2 `9E9A`) or
    /// decipher (P1P2 `8086`).
    ///
    /// TODO(transport): builder not provided yet; needs the host-side hash /
    /// cipher framing decided in the transport phase.
    PerformSecurityOperation = 0x2A,
    /// `INTERNAL AUTHENTICATE` — client/SSH authentication signature.
    ///
    /// TODO(transport): builder not provided yet.
    InternalAuthenticate = 0x88,
    /// `GENERATE ASYMMETRIC KEY PAIR` — P1 `80` generate, `81` read public key.
    ///
    /// TODO(transport): builder not provided yet; on-card key generation is a
    /// destructive, hardware-only operation gated for the transport phase.
    GenerateAsymmetricKeyPair = 0x47,
    /// `GET RESPONSE` — continue reading a response the card split across `61xx`.
    GetResponse = 0xC0,
    /// `ACTIVATE FILE` — paired with [`Instruction::TerminateDf`] for factory reset.
    ///
    /// TODO(transport): builder not provided yet (destructive; hardware-only).
    ActivateFile = 0x44,
    /// `TERMINATE DF` — paired with [`Instruction::ActivateFile`] for factory reset.
    ///
    /// TODO(transport): builder not provided yet (destructive; hardware-only).
    TerminateDf = 0xE6,
}

impl Instruction {
    /// The raw instruction byte.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}

// ---------------------------------------------------------------------------
// VERIFY password-reference (P2) constants
// ---------------------------------------------------------------------------

/// `VERIFY` P2: PW1 in the signing context (valid for PSO:CDS).
pub const PW1_SIGN: u8 = 0x81;
/// `VERIFY` P2: PW1 in the "other" context (decipher, internal authenticate).
pub const PW1_OTHER: u8 = 0x82;
/// `VERIFY` P2: PW3 (admin) PIN.
pub const PW3_ADMIN: u8 = 0x83;

// ---------------------------------------------------------------------------
// PSO / GENERATE parameter bytes (exposed for the transport phase)
// ---------------------------------------------------------------------------

/// `PSO` P1-P2 selecting *compute digital signature* (`9E 9A`).
pub const PSO_COMPUTE_SIGNATURE: u16 = 0x9E9A;
/// `PSO` P1-P2 selecting *decipher* (`80 86`).
pub const PSO_DECIPHER: u16 = 0x8086;
/// `GENERATE ASYMMETRIC KEY PAIR` P1: generate a fresh key pair.
pub const GENERATE_KEY: u8 = 0x80;
/// `GENERATE ASYMMETRIC KEY PAIR` P1: read an existing public key.
pub const READ_PUBLIC_KEY: u8 = 0x81;

// ---------------------------------------------------------------------------
// Data-object tags (BER-TLV; 1- or 2-byte)
// ---------------------------------------------------------------------------

/// Application Identifier (full 16-byte AID).
pub const TAG_AID: u16 = 0x004F;
/// Login data.
pub const TAG_LOGIN_DATA: u16 = 0x005E;
/// URL of the public key.
pub const TAG_URL: u16 = 0x5F50;
/// Historical bytes.
pub const TAG_HISTORICAL_BYTES: u16 = 0x5F52;
/// Cardholder Related Data (constructed: contains `5B`, `5F2D`, `5F35`).
pub const TAG_CARDHOLDER_RELATED_DATA: u16 = 0x0065;
/// Cardholder Name (inside [`TAG_CARDHOLDER_RELATED_DATA`]).
pub const TAG_NAME: u16 = 0x005B;
/// Language preference (inside [`TAG_CARDHOLDER_RELATED_DATA`]).
pub const TAG_LANGUAGE: u16 = 0x5F2D;
/// Sex (inside [`TAG_CARDHOLDER_RELATED_DATA`]).
pub const TAG_SEX: u16 = 0x5F35;
/// Application Related Data (constructed; the big aggregate object).
pub const TAG_APPLICATION_RELATED_DATA: u16 = 0x006E;
/// Discretionary data objects (constructed; inside [`TAG_APPLICATION_RELATED_DATA`]).
pub const TAG_DISCRETIONARY: u16 = 0x0073;
/// Extended capabilities (inside [`TAG_DISCRETIONARY`]).
pub const TAG_EXTENDED_CAPABILITIES: u16 = 0x00C0;
/// Algorithm attributes — signature key (inside [`TAG_DISCRETIONARY`]).
pub const TAG_ALGO_ATTR_SIG: u16 = 0x00C1;
/// Algorithm attributes — decryption key.
pub const TAG_ALGO_ATTR_DEC: u16 = 0x00C2;
/// Algorithm attributes — authentication key.
pub const TAG_ALGO_ATTR_AUT: u16 = 0x00C3;
/// PW status bytes (inside [`TAG_DISCRETIONARY`], also a standalone GET DATA).
pub const TAG_PW_STATUS: u16 = 0x00C4;
/// Fingerprints — 60 bytes = 3×20 (Sig, Dec, Aut).
pub const TAG_FINGERPRINTS: u16 = 0x00C5;
/// CA fingerprints — 60 bytes = 3×20.
pub const TAG_CA_FINGERPRINTS: u16 = 0x00C6;
/// Key generation timestamps.
pub const TAG_GENERATION_TIMES: u16 = 0x00CD;

/// Fingerprint — signature key (`C7`, 20 bytes); a standalone PUT DATA target.
pub const TAG_FPR_SIGN: u16 = 0x00C7;
/// Fingerprint — decryption key (`C8`, 20 bytes); a standalone PUT DATA target.
pub const TAG_FPR_DEC: u16 = 0x00C8;
/// Fingerprint — authentication key (`C9`, 20 bytes); a standalone PUT DATA target.
pub const TAG_FPR_AUTH: u16 = 0x00C9;
/// Generation timestamp — signature key (`CE`, 4-byte big-endian Unix time).
pub const TAG_TIME_SIGN: u16 = 0x00CE;
/// Generation timestamp — decryption key (`CF`, 4-byte big-endian Unix time).
pub const TAG_TIME_DEC: u16 = 0x00CF;
/// Generation timestamp — authentication key (`D0`, 4-byte big-endian Unix time).
pub const TAG_TIME_AUTH: u16 = 0x00D0;
/// Security support template (constructed; contains [`TAG_DS_COUNTER`]).
pub const TAG_SECURITY_SUPPORT: u16 = 0x007A;
/// Digital signature counter (3-byte big-endian; inside [`TAG_SECURITY_SUPPORT`]).
pub const TAG_DS_COUNTER: u16 = 0x0093;

/// Public-key data object (constructed) returned by GENERATE / READ PUBLIC KEY.
pub const TAG_PUBLIC_KEY: u16 = 0x7F49;
/// RSA modulus *n* (inside [`TAG_PUBLIC_KEY`]).
pub const TAG_RSA_MODULUS: u16 = 0x0081;
/// RSA public exponent *e* (inside [`TAG_PUBLIC_KEY`]).
pub const TAG_RSA_EXPONENT: u16 = 0x0082;
/// EC public point (inside [`TAG_PUBLIC_KEY`]) for ECDSA/ECDH/EdDSA keys.
pub const TAG_EC_PUBLIC_POINT: u16 = 0x0086;

/// Status word: success.
pub const SW_OK: u16 = 0x9000;
/// High byte of the "more data available" status (`61xx`).
pub const SW_MORE_DATA: u8 = 0x61;

// ---------------------------------------------------------------------------
// APDU builders
// ---------------------------------------------------------------------------

/// `SELECT` the OpenPGP applet by DF name:
/// `00 A4 04 00 06 D2 76 00 01 24 01`.
#[must_use]
pub fn select() -> Vec<u8> {
    build_apdu(0x00, INS_SELECT, P1_SELECT_BY_NAME, 0x00, &AID_PREFIX)
}

/// `GET DATA` for the data object identified by the 2-byte `tag` (placed in
/// P1-P2). Case-2 APDU with `Le = 0` ("up to 256 bytes"); larger objects are
/// continued with [`get_response`] in the transport phase.
#[must_use]
pub fn get_data(tag: u16) -> Vec<u8> {
    let p1 = (tag >> 8) as u8;
    let p2 = (tag & 0xFF) as u8;
    build_apdu_get(0x00, Instruction::GetData.code(), p1, p2, 0x00)
}

/// `GET DATA 006E` — the Application Related Data aggregate:
/// `00 CA 00 6E 00`.
#[must_use]
pub fn get_application_related_data() -> Vec<u8> {
    get_data(TAG_APPLICATION_RELATED_DATA)
}

/// `GET DATA 00C4` — the standalone PW status bytes: `00 CA 00 C4 00`.
#[must_use]
pub fn get_pw_status() -> Vec<u8> {
    get_data(TAG_PW_STATUS)
}

/// `VERIFY` — present `pin` against the password reference `pw_ref` (one of
/// [`PW1_SIGN`], [`PW1_OTHER`], [`PW3_ADMIN`]).
///
/// Builds a case-3 APDU `00 20 00 <pw_ref> <Lc> <pin...>`. The PIN bytes come
/// from the caller; this layer neither sources nor stores them (see the privacy
/// posture in `CLAUDE.md`).
#[must_use]
pub fn verify(pw_ref: u8, pin: &[u8]) -> Vec<u8> {
    build_apdu(0x00, Instruction::Verify.code(), 0x00, pw_ref, pin)
}

/// `GET RESPONSE` (case-2): retrieve the next chunk after a `61xx` status word.
///
/// TODO(transport): the reassembly loop (transmit, inspect `SW`, repeat) belongs
/// in `molto2-transport`; this builder only emits the request APDU.
#[must_use]
pub fn get_response() -> Vec<u8> {
    build_apdu_get(0x00, Instruction::GetResponse.code(), 0x00, 0x00, 0x00)
}

/// `TERMINATE DF` (`00 E6 00 00`) — the first half of an OpenPGP applet factory
/// reset. Case-1 APDU (no body, no Le). When the applet is unblocked this needs
/// PW3, but once PW1 *and* PW3 are blocked (both retry counters at 0) the card
/// accepts it unconditionally — that's how a forgotten-PIN card is reset. After
/// this the applet is in the "terminated" state and only [`activate_file`] (or
/// re-SELECT) is accepted.
#[must_use]
pub fn terminate_df() -> Vec<u8> {
    vec![0x00, Instruction::TerminateDf.code(), 0x00, 0x00]
}

/// `ACTIVATE FILE` (`00 44 00 00`) — the second half of the reset: re-initialize
/// the terminated applet to factory defaults (PW1 `123456`, PW3 `12345678`, all
/// key slots empty). Case-1 APDU.
#[must_use]
pub fn activate_file() -> Vec<u8> {
    vec![0x00, Instruction::ActivateFile.code(), 0x00, 0x00]
}

// ---------------------------------------------------------------------------
// Control Reference Templates (CRT) for GENERATE ASYMMETRIC KEY PAIR
// ---------------------------------------------------------------------------

/// CRT tag selecting the *signature* key (OpenPGP Card v3.4, §7.2.14, table).
pub const CRT_TAG_SIGN: u8 = 0xB6;
/// CRT tag selecting the *decryption* (confidentiality) key.
pub const CRT_TAG_DECRYPT: u8 = 0xB8;
/// CRT tag selecting the *authentication* key.
pub const CRT_TAG_AUTH: u8 = 0xA4;

/// Selects which on-card key slot a GENERATE / READ PUBLIC KEY operation refers
/// to. The wire form is a 2-byte Control Reference Template — the slot's CRT tag
/// followed by an empty value (`B6 00`, `B8 00`, or `A4 00`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyCrt {
    /// Digital-signature key (CRT tag `B6`).
    Sign,
    /// Decryption / confidentiality key (CRT tag `B8`).
    Decrypt,
    /// Authentication key (CRT tag `A4`).
    Auth,
}

impl KeyCrt {
    /// The CRT tag byte for this key slot.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            KeyCrt::Sign => CRT_TAG_SIGN,
            KeyCrt::Decrypt => CRT_TAG_DECRYPT,
            KeyCrt::Auth => CRT_TAG_AUTH,
        }
    }

    /// The 2-byte Control Reference Template (`<tag> 00`) naming this key slot.
    #[must_use]
    pub const fn crt(self) -> [u8; 2] {
        [self.tag(), 0x00]
    }

    /// The data-object tag of this slot's 20-byte fingerprint (`C7`/`C8`/`C9`),
    /// the target for a [`put_fingerprint`] PUT DATA. The card *also* mirrors
    /// these into the 60-byte [`TAG_FINGERPRINTS`] (`C5`) aggregate, but writes
    /// address the per-slot object.
    #[must_use]
    pub const fn fpr_tag(self) -> u16 {
        match self {
            KeyCrt::Sign => TAG_FPR_SIGN,
            KeyCrt::Decrypt => TAG_FPR_DEC,
            KeyCrt::Auth => TAG_FPR_AUTH,
        }
    }

    /// The data-object tag of this slot's 4-byte generation timestamp
    /// (`CE`/`CF`/`D0`), the target for a [`put_generation_time`] PUT DATA.
    #[must_use]
    pub const fn time_tag(self) -> u16 {
        match self {
            KeyCrt::Sign => TAG_TIME_SIGN,
            KeyCrt::Decrypt => TAG_TIME_DEC,
            KeyCrt::Auth => TAG_TIME_AUTH,
        }
    }
}

// ---------------------------------------------------------------------------
// Operation / write APDU builders
// ---------------------------------------------------------------------------

/// `GENERATE ASYMMETRIC KEY PAIR` with P1 = `80` (generate a fresh key pair).
///
/// Builds a case-4 APDU `00 47 80 00 02 <CRT> 00`, where `<CRT>` is the 2-byte
/// Control Reference Template selecting the key slot (see [`KeyCrt::crt`]). The
/// card answers with a `7F49` public-key object (parse it with
/// [`parse_generated_public_key`]).
///
/// **This is destructive**: generating overwrites any existing key in the slot.
///
/// Case-4 note: [`build_apdu`] only emits case-3 (`CLA INS P1 P2 Lc data`); a
/// GENERATE additionally needs an `Le` so the card returns the public key. We
/// append a trailing `0x00` `Le` byte ("up to 256/extended") by hand.
#[must_use]
pub fn generate_key(crt: KeyCrt) -> Vec<u8> {
    let mut apdu = build_apdu(
        0x00,
        Instruction::GenerateAsymmetricKeyPair.code(),
        GENERATE_KEY,
        0x00,
        &crt.crt(),
    );
    apdu.push(0x00); // case-4 Le
    apdu
}

/// `GENERATE ASYMMETRIC KEY PAIR` with P1 = `81` (read the *existing* public
/// key, no generation).
///
/// Builds a case-4 APDU `00 47 81 00 02 <CRT> 00`. Same CRT data and same
/// trailing-`Le` handling as [`generate_key`] (see its case-4 note); read-only.
#[must_use]
pub fn read_public_key(crt: KeyCrt) -> Vec<u8> {
    let mut apdu = build_apdu(
        0x00,
        Instruction::GenerateAsymmetricKeyPair.code(),
        READ_PUBLIC_KEY,
        0x00,
        &crt.crt(),
    );
    apdu.push(0x00); // case-4 Le
    apdu
}

/// `PERFORM SECURITY OPERATION: COMPUTE DIGITAL SIGNATURE` (P1-P2 = `9E 9A`).
///
/// `data` is the caller-supplied input the card signs — for RSA the `DigestInfo`
/// (a DER `AlgorithmIdentifier` + the already-computed hash), for EdDSA the raw
/// message-hash. This layer never hashes; it just frames the bytes. Requires
/// PW1 verified in the signing context ([`PW1_SIGN`]).
///
/// Builds a case-4 APDU `00 2A 9E 9A <Lc> <data> 00`; the trailing `0x00` `Le`
/// is appended by hand (see the case-4 note on [`generate_key`]).
#[must_use]
pub fn pso_compute_signature(data: &[u8]) -> Vec<u8> {
    let mut apdu = build_apdu(
        0x00,
        Instruction::PerformSecurityOperation.code(),
        (PSO_COMPUTE_SIGNATURE >> 8) as u8,
        (PSO_COMPUTE_SIGNATURE & 0xFF) as u8,
        data,
    );
    apdu.push(0x00); // case-4 Le
    apdu
}

/// `PERFORM SECURITY OPERATION: DECIPHER` (P1-P2 = `80 86`).
///
/// `data` is the cipher Data Object the card deciphers (its exact framing — a
/// padding-indicator byte plus the RSA cryptogram, or an ECDH `A6` template —
/// is the caller's; this layer only frames the bytes). Requires PW1 verified in
/// the "other" context ([`PW1_OTHER`]).
///
/// Builds a case-4 APDU `00 2A 80 86 <Lc> <data> 00`; the trailing `0x00` `Le`
/// is appended by hand (see the case-4 note on [`generate_key`]).
#[must_use]
pub fn pso_decipher(data: &[u8]) -> Vec<u8> {
    let mut apdu = build_apdu(
        0x00,
        Instruction::PerformSecurityOperation.code(),
        (PSO_DECIPHER >> 8) as u8,
        (PSO_DECIPHER & 0xFF) as u8,
        data,
    );
    apdu.push(0x00); // case-4 Le
    apdu
}

/// `CHANGE REFERENCE DATA` (INS `24`) — change a PIN from `old` to `new`.
///
/// `pw_ref` is the password reference in P2: [`PW1_SIGN`] (`0x81`) changes PW1,
/// [`PW3_ADMIN`] (`0x83`) changes PW3. The data field is the old PIN bytes
/// concatenated with the new PIN bytes; the card splits them by the stored PIN
/// length. Builds a case-3 APDU `00 24 00 <pw_ref> <Lc> <old || new>`.
///
/// PIN material is the caller's (see the privacy posture in `CLAUDE.md`); this
/// builder only frames the bytes — it never sources, stores, or logs them.
#[must_use]
pub fn change_reference_data(pw_ref: u8, old: &[u8], new: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(old.len() + new.len());
    data.extend_from_slice(old);
    data.extend_from_slice(new);
    build_apdu(
        0x00,
        Instruction::ChangeReferenceData.code(),
        0x00,
        pw_ref,
        &data,
    )
}

// ---------------------------------------------------------------------------
// PUT DATA builders
// ---------------------------------------------------------------------------

/// `PUT DATA` for the data object identified by the 2-byte `tag` (placed in
/// P1-P2), carrying `value` as the body.
///
/// Builds a case-3 APDU `00 DA <p1> <p2> <Lc> <value...>` (no `Le`). The
/// inverse of [`get_data`]: where GET DATA reads a data object, PUT DATA writes
/// one. Requires the appropriate PIN already verified (most writable objects
/// need PW3; see the OpenPGP Card spec v3.4, §7.2.8). This layer only frames
/// the bytes — it does not present a PIN.
#[must_use]
pub fn put_data(tag: u16, value: &[u8]) -> Vec<u8> {
    let p1 = (tag >> 8) as u8;
    let p2 = (tag & 0xFF) as u8;
    build_apdu(0x00, Instruction::PutData.code(), p1, p2, value)
}

/// `PUT DATA 005B` — write the cardholder name ([`TAG_NAME`]).
///
/// The OpenPGP Card stores the name as the value of the standalone `5B` object
/// (not wrapped in the `65` Cardholder Related Data template on write). The
/// spec recommends the OpenPGP "Name" convention (`Surname<<Given Names`), but
/// the encoding is the caller's; this builder only frames the bytes.
#[must_use]
pub fn put_cardholder_name(name: &[u8]) -> Vec<u8> {
    put_data(TAG_NAME, name)
}

/// `PUT DATA 5F50` — write the URL of the public key ([`TAG_URL`]).
#[must_use]
pub fn put_url(url: &[u8]) -> Vec<u8> {
    put_data(TAG_URL, url)
}

/// `PUT DATA C7`/`C8`/`C9` — write the 20-byte v4 fingerprint of the key in
/// `crt`'s slot (see [`KeyCrt::fpr_tag`]).
///
/// After an on-card GENERATE the applet knows the key material but not the
/// OpenPGP v4 fingerprint (which folds in the host-chosen creation timestamp);
/// the host computes it with [`rsa_v4_fingerprint`] and registers it here so
/// that `gpg` and the card agree on the key's identity.
#[must_use]
pub fn put_fingerprint(crt: KeyCrt, fpr: &[u8; 20]) -> Vec<u8> {
    put_data(crt.fpr_tag(), fpr)
}

/// `PUT DATA CE`/`CF`/`D0` — write the 4-byte big-endian Unix generation
/// timestamp of the key in `crt`'s slot (see [`KeyCrt::time_tag`]).
///
/// This timestamp *must* match the `creation_time` fed to
/// [`rsa_v4_fingerprint`]: the v4 fingerprint hashes the creation time, so a
/// mismatch yields a fingerprint the card and `gpg` disagree on.
#[must_use]
pub fn put_generation_time(crt: KeyCrt, unix_time: u32) -> Vec<u8> {
    put_data(crt.time_tag(), &unix_time.to_be_bytes())
}

// ---------------------------------------------------------------------------
// OpenPGP v4 key fingerprint (RFC 4880 §12.2)
// ---------------------------------------------------------------------------

/// OpenPGP MPI (Multiprecision Integer, RFC 4880 §3.2) encoding of the
/// big-endian integer `bytes`.
///
/// An MPI is a 2-byte big-endian *bit length* followed by the minimal
/// big-endian value bytes. Leading zero *bytes* are stripped first; the bit
/// length then counts from the highest set bit of the first remaining byte
/// (so the encoding never has a leading zero byte). An all-zero or empty
/// integer encodes as bit length 0 with no value bytes.
fn mpi(bytes: &[u8]) -> Vec<u8> {
    // Strip leading zero bytes to reach the minimal big-endian form.
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let value = &bytes[start..];
    if value.is_empty() {
        return vec![0x00, 0x00];
    }
    // Bit length: significant bits in the (non-zero) top byte + 8 per
    // remaining byte. `u8::leading_zeros` is 8 minus the bit position of the
    // highest set bit, so `8 - leading_zeros` is the count we want.
    let top_bits = 8 - value[0].leading_zeros() as usize;
    let bit_len = top_bits + 8 * (value.len() - 1);
    let mut out = Vec::with_capacity(2 + value.len());
    out.push((bit_len >> 8) as u8);
    out.push((bit_len & 0xFF) as u8);
    out.extend_from_slice(value);
    out
}

/// Compute the OpenPGP **v4 fingerprint** (RFC 4880 §12.2) of an RSA public
/// key from its big-endian `modulus`, `exponent`, and the key's `creation_time`
/// (Unix seconds).
///
/// The fingerprint is `SHA1(0x99 || len16 || body)`, where `body` is the
/// public-key packet body: `04` (version) || `creation_time` (4 big-endian
/// bytes) || `01` (RSA algorithm id) || [MPI](modulus) || [MPI](exponent), and
/// `len16` is the 2-byte big-endian length of `body`. The `creation_time` must
/// equal the value later written with [`put_generation_time`], or the card and
/// `gpg` will compute different fingerprints for the same key.
#[must_use]
pub fn rsa_v4_fingerprint(modulus: &[u8], exponent: &[u8], creation_time: u32) -> [u8; 20] {
    let m = mpi(modulus);
    let e = mpi(exponent);
    let ct = creation_time.to_be_bytes();
    let mut body = Vec::with_capacity(1 + 4 + 1 + m.len() + e.len());
    body.push(0x04); // packet version
    body.extend_from_slice(&ct); // key creation time
    body.push(0x01); // public-key algorithm: RSA
    body.extend_from_slice(&m);
    body.extend_from_slice(&e);

    let len = body.len() as u16;
    let mut hashed = Vec::with_capacity(3 + body.len());
    hashed.push(0x99); // old-format CTB: public-key packet, two-octet length
    hashed.push((len >> 8) as u8);
    hashed.push((len & 0xFF) as u8);
    hashed.extend_from_slice(&body);

    molto2_proto::sha1::sha1(&hashed)
}

/// Convenience wrapper around [`rsa_v4_fingerprint`] taking a parsed
/// [`PublicKey`] (e.g. straight from [`parse_generated_public_key`]).
#[must_use]
pub fn rsa_v4_fingerprint_from(key: &PublicKey, creation_time: u32) -> [u8; 20] {
    rsa_v4_fingerprint(&key.modulus, &key.exponent, creation_time)
}

// ---------------------------------------------------------------------------
// BER-TLV parsing
// ---------------------------------------------------------------------------

/// Error returned by the response parsers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// A TLV claimed more bytes than the buffer contained (or a tag/length ran
    /// off the end while being read).
    Truncated,
    /// A tag byte sequence was malformed (e.g. a high-tag-number first byte with
    /// no following byte, or a 3+ byte tag we do not model).
    BadTag,
    /// A length field was malformed or wider than we support (we accept short
    /// form and long form `81`/`82`; `83`+ is rejected).
    UnexpectedLength,
    /// A required tag was absent from the response.
    MissingTag(u16),
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ParseError::Truncated => write!(f, "BER-TLV truncated: length exceeds buffer"),
            ParseError::BadTag => write!(f, "malformed BER-TLV tag"),
            ParseError::UnexpectedLength => write!(f, "malformed or unsupported BER-TLV length"),
            ParseError::MissingTag(t) => write!(f, "expected TLV tag {t:#06x} not present"),
        }
    }
}

impl std::error::Error for ParseError {}

/// A single parsed BER-TLV borrowed from the response buffer.
///
/// `tag` is normalised to a `u16`: a 1-byte tag occupies the low byte (e.g.
/// `0x004F`), a 2-byte high tag fills both (e.g. `0x5F52`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv<'a> {
    /// Tag, normalised to `u16` (see type docs).
    pub tag: u16,
    /// Whether the tag is *constructed* (bit 6 / `0x20` of the first tag byte
    /// set) and so carries nested TLVs, vs. primitive (a raw value). Used by
    /// [`find_nested`] to decide where to descend.
    pub constructed: bool,
    /// Value bytes (length already validated against the buffer).
    pub value: &'a [u8],
}

/// Read a BER-TLV tag at `buf[i..]`, returning `(tag_u16, bytes_consumed)`.
///
/// Supports the single-byte form and the high-tag-number form where the low 5
/// bits of the first byte are all set (`& 0x1F == 0x1F`), in which case a second
/// byte completes the tag (e.g. `5F 52`). Tags wider than two bytes (a second
/// byte with bit 7 set, indicating still more bytes) are rejected as
/// [`ParseError::BadTag`]; no OpenPGP Card object uses one.
fn read_tag(buf: &[u8], i: usize) -> Result<(u16, usize), ParseError> {
    let first = *buf.get(i).ok_or(ParseError::Truncated)?;
    if first & 0x1F != 0x1F {
        return Ok((u16::from(first), 1));
    }
    let second = *buf.get(i + 1).ok_or(ParseError::Truncated)?;
    // A set high bit on the second byte would mean a third tag byte follows.
    if second & 0x80 != 0 {
        return Err(ParseError::BadTag);
    }
    Ok(((u16::from(first) << 8) | u16::from(second), 2))
}

/// Read a BER-TLV length at `buf[i..]`, returning `(length, bytes_consumed)`.
///
/// Short form: a single byte `0x00..=0x7F` is the length. Long form: `0x81`
/// means the next byte is the length; `0x82` means the next two bytes are a
/// big-endian length. `0x80` (indefinite) and `0x83`+ are rejected as
/// [`ParseError::UnexpectedLength`].
fn read_len(buf: &[u8], i: usize) -> Result<(usize, usize), ParseError> {
    let first = *buf.get(i).ok_or(ParseError::Truncated)?;
    if first & 0x80 == 0 {
        return Ok((usize::from(first), 1));
    }
    match first {
        0x81 => {
            let n = *buf.get(i + 1).ok_or(ParseError::Truncated)?;
            Ok((usize::from(n), 2))
        }
        0x82 => {
            let hi = *buf.get(i + 1).ok_or(ParseError::Truncated)?;
            let lo = *buf.get(i + 2).ok_or(ParseError::Truncated)?;
            Ok(((usize::from(hi) << 8) | usize::from(lo), 3))
        }
        _ => Err(ParseError::UnexpectedLength),
    }
}

/// Parse a flat sequence of BER-TLVs from `buf`.
///
/// Handles two-byte high tags and long-form lengths (`81`/`82`). Constructed
/// objects are returned with their full (still-encoded) value; descend into them
/// by parsing the value again or with [`find_nested`]. Returns
/// [`ParseError::Truncated`] if any TLV runs off the end of the buffer.
pub fn parse_tlvs(buf: &[u8]) -> Result<Vec<Tlv<'_>>, ParseError> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < buf.len() {
        // Bit 6 (0x20) of the first tag byte marks a constructed object.
        let constructed = buf[i] & 0x20 != 0;
        let (tag, tag_len) = read_tag(buf, i)?;
        let (len, len_len) = read_len(buf, i + tag_len)?;
        let start = i
            .checked_add(tag_len)
            .and_then(|v| v.checked_add(len_len))
            .ok_or(ParseError::Truncated)?;
        let end = start.checked_add(len).ok_or(ParseError::Truncated)?;
        if end > buf.len() {
            return Err(ParseError::Truncated);
        }
        out.push(Tlv {
            tag,
            constructed,
            value: &buf[start..end],
        });
        i = end;
    }
    Ok(out)
}

/// Find the value of the first TLV with `tag` in a flat bag.
#[must_use]
pub fn find_tag<'a>(tlvs: &[Tlv<'a>], tag: u16) -> Option<&'a [u8]> {
    tlvs.iter().find(|t| t.tag == tag).map(|t| t.value)
}

/// Recursively locate the value of the first TLV with `tag`, descending into
/// constructed objects.
///
/// Recursion is deterministic: it descends *only* into TLVs flagged
/// [`Tlv::constructed`] (BER bit 6 set), so a primitive value whose bytes happen
/// to look like TLVs is never misread. Used to reach, e.g., `C5` fingerprints
/// nested inside `73` inside `6E`.
#[must_use]
pub fn find_nested<'a>(tlvs: &[Tlv<'a>], tag: u16) -> Option<&'a [u8]> {
    for tlv in tlvs {
        if tlv.tag == tag {
            return Some(tlv.value);
        }
        if tlv.constructed {
            if let Ok(children) = parse_tlvs(tlv.value) {
                if let Some(found) = find_nested(&children, tag) {
                    return Some(found);
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Typed parsers
// ---------------------------------------------------------------------------

/// PW status bytes (`C4`), parsed from the 7-byte form.
///
/// The 4-byte legacy form omits the max-length triplet; this parser requires the
/// 7-byte form (OpenPGP Card v3.x), returning [`ParseError::UnexpectedLength`]
/// otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PwStatus {
    /// Byte 0: whether PW1 stays valid for multiple PSO:CDS commands (`01`) or
    /// only one (`00`).
    pub pw1_valid_multiple: bool,
    /// Byte 1: maximum length / format of PW1.
    pub max_pw1: u8,
    /// Byte 2: maximum length of the resetting code (RC).
    pub max_rc: u8,
    /// Byte 3: maximum length of PW3.
    pub max_pw3: u8,
    /// Byte 4: remaining retry counter for PW1.
    pub tries_pw1: u8,
    /// Byte 5: remaining retry counter for the resetting code.
    pub tries_rc: u8,
    /// Byte 6: remaining retry counter for PW3.
    pub tries_pw3: u8,
}

/// Parse the 7-byte PW status (`C4`) value.
pub fn parse_pw_status(buf: &[u8]) -> Result<PwStatus, ParseError> {
    if buf.len() != 7 {
        return Err(ParseError::UnexpectedLength);
    }
    Ok(PwStatus {
        pw1_valid_multiple: buf[0] == 0x01,
        max_pw1: buf[1],
        max_rc: buf[2],
        max_pw3: buf[3],
        tries_pw1: buf[4],
        tries_rc: buf[5],
        tries_pw3: buf[6],
    })
}

/// A 20-byte (SHA-1-sized) OpenPGP key fingerprint.
pub type Fingerprint = [u8; 20];

/// Selected fields pulled out of the Application Related Data (`6E`) object.
///
/// Algorithm-attribute blobs (`C1`/`C2`/`C3`) are kept raw; the first byte (the
/// algorithm id, e.g. `01` = RSA, `12` = ECDH, `13` = ECDSA, `16` = EdDSA) is
/// exposed via [`AppRelatedData::sig_algo_id`] and friends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppRelatedData {
    /// Full AID bytes from `4F` (typically 16 bytes).
    pub aid: Vec<u8>,
    /// Raw algorithm attributes for the signature key (`C1`).
    pub algo_attr_sig: Vec<u8>,
    /// Raw algorithm attributes for the decryption key (`C2`).
    pub algo_attr_dec: Vec<u8>,
    /// Raw algorithm attributes for the authentication key (`C3`).
    pub algo_attr_aut: Vec<u8>,
    /// PW status (`C4`), parsed.
    pub pw_status: PwStatus,
    /// Signature-key fingerprint (`C5`, bytes 0..20).
    pub fingerprint_sig: Fingerprint,
    /// Decryption-key fingerprint (`C5`, bytes 20..40).
    pub fingerprint_dec: Fingerprint,
    /// Authentication-key fingerprint (`C5`, bytes 40..60).
    pub fingerprint_aut: Fingerprint,
}

impl AppRelatedData {
    /// Algorithm id (first byte) of the signature-key attributes, if any.
    #[must_use]
    pub fn sig_algo_id(&self) -> Option<u8> {
        self.algo_attr_sig.first().copied()
    }
    /// Algorithm id (first byte) of the decryption-key attributes, if any.
    #[must_use]
    pub fn dec_algo_id(&self) -> Option<u8> {
        self.algo_attr_dec.first().copied()
    }
    /// Algorithm id (first byte) of the authentication-key attributes, if any.
    #[must_use]
    pub fn aut_algo_id(&self) -> Option<u8> {
        self.algo_attr_aut.first().copied()
    }
}

/// Parse the Application Related Data (`6E`) blob.
///
/// `buf` may be either the raw value of the `6E` object *or* the full `6E`
/// envelope; both are accepted. Required sub-objects are `4F` (AID), `C1`/`C2`/
/// `C3` (algorithm attributes), `C4` (PW status), and `C5` (60-byte
/// fingerprints); a missing one yields [`ParseError::MissingTag`].
pub fn parse_application_related_data(buf: &[u8]) -> Result<AppRelatedData, ParseError> {
    let top = parse_tlvs(buf)?;
    // Accept either the bare value or the wrapping 6E envelope.
    let inner: &[u8] = match find_tag(&top, TAG_APPLICATION_RELATED_DATA) {
        Some(v) => v,
        None => buf,
    };
    let tlvs = parse_tlvs(inner)?;

    let aid = find_nested(&tlvs, TAG_AID)
        .ok_or(ParseError::MissingTag(TAG_AID))?
        .to_vec();
    let algo_attr_sig = find_nested(&tlvs, TAG_ALGO_ATTR_SIG)
        .ok_or(ParseError::MissingTag(TAG_ALGO_ATTR_SIG))?
        .to_vec();
    let algo_attr_dec = find_nested(&tlvs, TAG_ALGO_ATTR_DEC)
        .ok_or(ParseError::MissingTag(TAG_ALGO_ATTR_DEC))?
        .to_vec();
    let algo_attr_aut = find_nested(&tlvs, TAG_ALGO_ATTR_AUT)
        .ok_or(ParseError::MissingTag(TAG_ALGO_ATTR_AUT))?
        .to_vec();

    let pw_raw = find_nested(&tlvs, TAG_PW_STATUS).ok_or(ParseError::MissingTag(TAG_PW_STATUS))?;
    let pw_status = parse_pw_status(pw_raw)?;

    // The spec defines C5 as 60 bytes (3×20: Sig, Dec, Aut), but real cards
    // report more — a YubiKey 5.7 returns 80 bytes (a fourth, "attestation" key
    // slot). Require at least the three standard fingerprints and read those;
    // ignore any trailing slots we don't model.
    let fpr = find_nested(&tlvs, TAG_FINGERPRINTS)
        .ok_or(ParseError::MissingTag(TAG_FINGERPRINTS))?;
    if fpr.len() < 60 {
        return Err(ParseError::UnexpectedLength);
    }
    let mut fingerprint_sig = [0u8; 20];
    let mut fingerprint_dec = [0u8; 20];
    let mut fingerprint_aut = [0u8; 20];
    fingerprint_sig.copy_from_slice(&fpr[0..20]);
    fingerprint_dec.copy_from_slice(&fpr[20..40]);
    fingerprint_aut.copy_from_slice(&fpr[40..60]);

    Ok(AppRelatedData {
        aid,
        algo_attr_sig,
        algo_attr_dec,
        algo_attr_aut,
        pw_status,
        fingerprint_sig,
        fingerprint_dec,
        fingerprint_aut,
    })
}

/// Parse the digital-signature counter from a Security Support Template (`7A`).
///
/// The counter is a 3-byte big-endian value carried in the `93` object nested
/// inside `7A`. `buf` may be the raw value of `7A` or the full `7A` envelope.
pub fn parse_signature_counter(buf: &[u8]) -> Result<u32, ParseError> {
    let top = parse_tlvs(buf)?;
    let inner: &[u8] = find_tag(&top, TAG_SECURITY_SUPPORT).unwrap_or(buf);
    let tlvs = parse_tlvs(inner)?;
    let v = find_nested(&tlvs, TAG_DS_COUNTER).ok_or(ParseError::MissingTag(TAG_DS_COUNTER))?;
    if v.len() != 3 {
        return Err(ParseError::UnexpectedLength);
    }
    Ok((u32::from(v[0]) << 16) | (u32::from(v[1]) << 8) | u32::from(v[2]))
}

/// The RSA public key parsed from a GENERATE / READ PUBLIC KEY response.
///
/// The card returns a `7F49` constructed object; for an RSA key it carries the
/// modulus *n* (tag `81`) and the public exponent *e* (tag `82`). Both are kept
/// as raw big-endian bytes (a 2048-bit modulus is 256 bytes — note the card may
/// or may not include a leading zero byte; we surface the value verbatim).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    /// RSA modulus *n* (`81`), big-endian.
    pub modulus: Vec<u8>,
    /// RSA public exponent *e* (`82`), big-endian (commonly `01 00 01`).
    pub exponent: Vec<u8>,
}

/// Parse the public key from a GENERATE / READ PUBLIC KEY response.
///
/// `buf` may be either the raw value of the `7F49` object *or* the full `7F49`
/// envelope; both are accepted. Only the **RSA** case is decoded: the `81`
/// modulus and `82` exponent are pulled out (a 2048-bit modulus forces a
/// long-form `82` length, which [`parse_tlvs`] handles).
///
/// An ECC key carries an `86` public point instead of `81`/`82`; that case is
/// reported as [`ParseError::MissingTag`] for [`TAG_RSA_MODULUS`] — callers that
/// expect ECC should read the raw `86` value via [`parse_tlvs`]/[`find_nested`]
/// against [`TAG_EC_PUBLIC_POINT`].
pub fn parse_generated_public_key(buf: &[u8]) -> Result<PublicKey, ParseError> {
    let top = parse_tlvs(buf)?;
    // Accept either the bare value or the wrapping 7F49 envelope.
    let inner: &[u8] = find_tag(&top, TAG_PUBLIC_KEY).unwrap_or(buf);
    let tlvs = parse_tlvs(inner)?;

    let modulus = find_nested(&tlvs, TAG_RSA_MODULUS)
        .ok_or(ParseError::MissingTag(TAG_RSA_MODULUS))?
        .to_vec();
    let exponent = find_nested(&tlvs, TAG_RSA_EXPONENT)
        .ok_or(ParseError::MissingTag(TAG_RSA_EXPONENT))?
        .to_vec();

    Ok(PublicKey { modulus, exponent })
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- APDU framing ----------------------------------------------------

    #[test]
    fn select_bytes() {
        assert_eq!(
            select(),
            vec![0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]
        );
    }

    #[test]
    fn get_data_builders() {
        assert_eq!(
            get_application_related_data(),
            vec![0x00, 0xCA, 0x00, 0x6E, 0x00]
        );
        assert_eq!(get_pw_status(), vec![0x00, 0xCA, 0x00, 0xC4, 0x00]);
        // A 2-byte tag splits across P1/P2: 5F52 -> P1=5F P2=52.
        assert_eq!(get_data(TAG_HISTORICAL_BYTES), vec![0x00, 0xCA, 0x5F, 0x52, 0x00]);
    }

    #[test]
    fn verify_bytes() {
        // verify(PW1_OTHER, "123456") = 00 20 00 82 06 31 32 33 34 35 36
        assert_eq!(
            verify(0x82, b"123456"),
            vec![0x00, 0x20, 0x00, 0x82, 0x06, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36]
        );
    }

    #[test]
    fn get_response_is_case2() {
        assert_eq!(get_response(), vec![0x00, 0xC0, 0x00, 0x00, 0x00]);
    }

    // --- BER-TLV: tags ---------------------------------------------------

    #[test]
    fn parses_two_byte_high_tag() {
        // 5F 52 03 00 11 22  -> tag 0x5F52, value 00 11 22
        let buf = [0x5F, 0x52, 0x03, 0x00, 0x11, 0x22];
        let tlvs = parse_tlvs(&buf).unwrap();
        assert_eq!(tlvs.len(), 1);
        assert_eq!(tlvs[0].tag, 0x5F52);
        assert_eq!(tlvs[0].value, &[0x00, 0x11, 0x22]);
    }

    #[test]
    fn single_byte_tag_in_low_byte() {
        // C4 02 AA BB -> tag 0x00C4
        let buf = [0xC4, 0x02, 0xAA, 0xBB];
        let tlvs = parse_tlvs(&buf).unwrap();
        assert_eq!(tlvs[0].tag, 0x00C4);
        assert_eq!(tlvs[0].value, &[0xAA, 0xBB]);
    }

    // --- BER-TLV: long-form lengths --------------------------------------

    #[test]
    fn parses_long_form_length_81() {
        // 53 81 84 <132 bytes>  (0x84 = 132)
        let mut buf = vec![0x53, 0x81, 0x84];
        buf.extend(std::iter::repeat(0xCD).take(132));
        let tlvs = parse_tlvs(&buf).unwrap();
        assert_eq!(tlvs.len(), 1);
        assert_eq!(tlvs[0].tag, 0x0053);
        assert_eq!(tlvs[0].value.len(), 132);
        assert!(tlvs[0].value.iter().all(|&b| b == 0xCD));
    }

    #[test]
    fn parses_long_form_length_82() {
        // 53 82 01 00 <256 bytes>
        let mut buf = vec![0x53, 0x82, 0x01, 0x00];
        buf.extend(std::iter::repeat(0xEE).take(256));
        let tlvs = parse_tlvs(&buf).unwrap();
        assert_eq!(tlvs[0].value.len(), 256);
    }

    #[test]
    fn rejects_indefinite_and_wide_length() {
        assert_eq!(parse_tlvs(&[0xC4, 0x80]), Err(ParseError::UnexpectedLength));
        assert_eq!(parse_tlvs(&[0xC4, 0x83, 0, 0, 1]), Err(ParseError::UnexpectedLength));
    }

    #[test]
    fn detects_truncation() {
        // tag C4, claims length 5 but only 2 bytes follow.
        assert_eq!(parse_tlvs(&[0xC4, 0x05, 0xAA, 0xBB]), Err(ParseError::Truncated));
        // high tag with no second byte.
        assert_eq!(parse_tlvs(&[0x5F]), Err(ParseError::Truncated));
    }

    // --- BER-TLV: nested find --------------------------------------------

    /// Build `6E { 73 { C4(7) C5(60) } }` by hand for the nesting tests.
    fn build_6e_with_73() -> (Vec<u8>, [u8; 7], [u8; 60]) {
        let c4 = [0x01, 0x20, 0x20, 0x40, 0x03, 0x00, 0x03];
        let mut c5 = [0u8; 60];
        for (i, b) in c5.iter_mut().enumerate() {
            *b = i as u8;
        }
        // inner 73 value = C4 TLV + C5 TLV
        let mut inner73 = Vec::new();
        inner73.push(0xC4);
        inner73.push(7);
        inner73.extend_from_slice(&c4);
        inner73.push(0xC5);
        inner73.push(60);
        inner73.extend_from_slice(&c5);
        // 73 wrapper
        let mut v73 = Vec::new();
        v73.push(0x73);
        v73.push(inner73.len() as u8);
        v73.extend_from_slice(&inner73);
        // 6E wrapper (value is the 73 object)
        let mut v6e = Vec::new();
        v6e.push(0x6E);
        v6e.push(v73.len() as u8);
        v6e.extend_from_slice(&v73);
        (v6e, c4, c5)
    }

    #[test]
    fn nested_find_locates_c4_and_c5() {
        let (v6e, c4, c5) = build_6e_with_73();
        let top = parse_tlvs(&v6e).unwrap();
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].tag, 0x006E);

        // find_nested should descend 6E -> 73 -> C4 / C5.
        assert_eq!(find_nested(&top, TAG_PW_STATUS), Some(&c4[..]));
        assert_eq!(find_nested(&top, TAG_FINGERPRINTS), Some(&c5[..]));
    }

    // --- PW status -------------------------------------------------------

    #[test]
    fn parse_pw_status_seven_byte() {
        // pw1 multi=01, max 20/00/40, tries 03/00/03
        let buf = [0x01, 0x20, 0x00, 0x40, 0x03, 0x00, 0x03];
        let s = parse_pw_status(&buf).unwrap();
        assert!(s.pw1_valid_multiple);
        assert_eq!(s.max_pw1, 0x20);
        assert_eq!(s.max_rc, 0x00);
        assert_eq!(s.max_pw3, 0x40);
        assert_eq!(s.tries_pw1, 0x03);
        assert_eq!(s.tries_rc, 0x00);
        assert_eq!(s.tries_pw3, 0x03);
    }

    #[test]
    fn parse_pw_status_rejects_legacy_four_byte() {
        assert_eq!(
            parse_pw_status(&[0x00, 0x20, 0x40, 0x03]),
            Err(ParseError::UnexpectedLength)
        );
    }

    // --- Application Related Data ----------------------------------------

    /// Decode a hex string, ignoring any embedded whitespace (so test vectors
    /// can wrap across lines).
    fn hexbytes(s: &str) -> Vec<u8> {
        let clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        (0..clean.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Append a TLV (1-byte tag) to `out`, emitting BER long-form length when
    /// the value exceeds 127 bytes (e.g. the `73` discretionary object).
    fn push(out: &mut Vec<u8>, tag: u8, value: &[u8]) {
        out.push(tag);
        let len = value.len();
        if len < 0x80 {
            out.push(len as u8);
        } else if len < 0x100 {
            out.push(0x81);
            out.push(len as u8);
        } else {
            out.push(0x82);
            out.push((len >> 8) as u8);
            out.push((len & 0xFF) as u8);
        }
        out.extend_from_slice(value);
    }

    #[test]
    fn parse_application_related_data_realistic() {
        // Assemble a realistic 6E from sub-TLVs:
        //   4F  AID (16 bytes, full form)
        //   5F52 historical bytes (sits directly under 6E)
        //   73 { C0 ext-caps, C1/C2/C3 algo attrs, C4 pw-status, C5 fprs, C6 ca-fprs }
        let aid: [u8; 16] = [
            0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x03, 0x04, 0x00, 0x05, 0x00, 0x00, 0x12, 0x34,
            0x00, 0x00,
        ];
        let hist = [0x00, 0x73, 0x00, 0x80, 0x05, 0x90, 0x00];
        // RSA (01), ECDH (12), EdDSA (16) algorithm ids in the first byte.
        let c1 = [0x01, 0x08, 0x00, 0x00, 0x20, 0x00];
        let c2 = [0x12, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01];
        let c3 = [0x16, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];
        let c4 = [0x01, 0x7F, 0x7F, 0x7F, 0x03, 0x00, 0x03];
        let mut c5 = [0u8; 60];
        for (i, b) in c5.iter_mut().enumerate() {
            *b = (0xA0 + i) as u8;
        }
        let c6 = [0u8; 60];

        let mut disc = Vec::new(); // 73 value
        push(&mut disc, 0xC0, &[0x7F, 0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0x00, 0x00, 0xFF]);
        push(&mut disc, 0xC1, &c1);
        push(&mut disc, 0xC2, &c2);
        push(&mut disc, 0xC3, &c3);
        push(&mut disc, 0xC4, &c4);
        push(&mut disc, 0xC5, &c5);
        push(&mut disc, 0xC6, &c6);

        let mut inner = Vec::new(); // 6E value
        push(&mut inner, 0x4F, &aid);
        // 5F52 is a 2-byte tag; encode by hand.
        inner.push(0x5F);
        inner.push(0x52);
        inner.push(hist.len() as u8);
        inner.extend_from_slice(&hist);
        push(&mut inner, 0x73, &disc);

        let mut blob = Vec::new(); // full 6E
        push(&mut blob, 0x6E, &inner);

        let ard = parse_application_related_data(&blob).unwrap();
        assert_eq!(ard.aid, aid.to_vec());
        assert_eq!(ard.sig_algo_id(), Some(0x01));
        assert_eq!(ard.dec_algo_id(), Some(0x12));
        assert_eq!(ard.aut_algo_id(), Some(0x16));
        assert_eq!(ard.fingerprint_sig, {
            let mut f = [0u8; 20];
            f.copy_from_slice(&c5[0..20]);
            f
        });
        assert_eq!(ard.fingerprint_dec[0], 0xA0 + 20);
        assert_eq!(ard.fingerprint_aut[19], (0xA0 + 59) as u8);
        assert_eq!(ard.pw_status.tries_pw1, 0x03);
        assert_eq!(ard.pw_status.tries_rc, 0x00);
        assert_eq!(ard.pw_status.tries_pw3, 0x03);

        // Parsing the bare value (without the 6E envelope) works too.
        let ard2 = parse_application_related_data(&inner).unwrap();
        assert_eq!(ard2.aid, aid.to_vec());
    }

    #[test]
    fn parse_application_related_data_missing_tag() {
        // A 6E with only an AID and nothing else -> missing C1.
        let mut inner = Vec::new();
        push(&mut inner, 0x4F, &[0x00; 16]);
        let mut blob = Vec::new();
        push(&mut blob, 0x6E, &inner);
        assert_eq!(
            parse_application_related_data(&blob),
            Err(ParseError::MissingTag(TAG_ALGO_ATTR_SIG))
        );
    }

    #[test]
    fn parse_application_related_data_real_yubikey() {
        // Captured from a real YubiKey 5.7 OpenPGP applet (GET DATA 006E, after
        // the 61xx/GET RESPONSE reassembly). Notably its C5 fingerprints object
        // is 80 bytes, not the spec's 60 — this case is the regression that the
        // hardware surfaced. Also exercises tags the synthetic test omits
        // (7F74, DE, 7F66, D6-D9) and a long-form (0x82) length on 6E and 73.
        let ard = hexbytes("6e8201374f10d27600012401030400063780684000005f520800730000e00590007f740381012073820110c00a7d000bfe080000ff0000c106010800001100c206010800001100c306010800001100da06010800001100c407017f7f7f030003c550000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c67e128a58628a5196171e0eb3f78e16490c17d7c6500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000cd10000000000000000000000000683741cdde0801000200030081027f660802020bfe02020bfed6020020d7020020d8020020d9020020");
        let a = parse_application_related_data(&ard).expect("real ARD parses");
        assert_eq!(a.aid, hexbytes("d2760001240103040006378068400000"));
        // RSA (0x01) sig/dec/aut keys.
        assert_eq!(a.sig_algo_id(), Some(0x01));
        assert_eq!(a.dec_algo_id(), Some(0x01));
        assert_eq!(a.aut_algo_id(), Some(0x01));
        // PW status: PW1 multiple = false (0x00 byte0 is actually 0x01 here),
        // and the three retry counters are 3/0/3.
        assert_eq!(a.pw_status.tries_pw1, 3);
        assert_eq!(a.pw_status.tries_rc, 0);
        assert_eq!(a.pw_status.tries_pw3, 3);
        // No keys generated yet -> sig fingerprint all zeros.
        assert_eq!(a.fingerprint_sig, [0u8; 20]);
    }

    // --- Signature counter (7A / 93) -------------------------------------

    #[test]
    fn parse_signature_counter_from_7a() {
        // 7A { 93 03 00 12 34 } -> counter 0x001234 = 4660
        let mut inner = Vec::new();
        push(&mut inner, 0x93, &[0x00, 0x12, 0x34]);
        let mut blob = Vec::new();
        push(&mut blob, 0x7A, &inner);
        assert_eq!(parse_signature_counter(&blob).unwrap(), 0x0000_1234);
        // Bare value form also works.
        assert_eq!(parse_signature_counter(&inner).unwrap(), 4660);
    }

    // --- Operation / write builders --------------------------------------

    #[test]
    fn generate_key_sign_bytes() {
        // GENERATE (P1=80), signature key CRT B6 00, case-4 trailing Le.
        assert_eq!(
            generate_key(KeyCrt::Sign),
            vec![0x00, 0x47, 0x80, 0x00, 0x02, 0xB6, 0x00, 0x00]
        );
    }

    #[test]
    fn generate_key_all_slots() {
        assert_eq!(
            generate_key(KeyCrt::Decrypt),
            vec![0x00, 0x47, 0x80, 0x00, 0x02, 0xB8, 0x00, 0x00]
        );
        assert_eq!(
            generate_key(KeyCrt::Auth),
            vec![0x00, 0x47, 0x80, 0x00, 0x02, 0xA4, 0x00, 0x00]
        );
    }

    #[test]
    fn read_public_key_auth_bytes() {
        // READ PUBLIC KEY (P1=81), authentication key CRT A4 00, case-4 Le.
        assert_eq!(
            read_public_key(KeyCrt::Auth),
            vec![0x00, 0x47, 0x81, 0x00, 0x02, 0xA4, 0x00, 0x00]
        );
        // And the sign/decrypt slots for completeness.
        assert_eq!(
            read_public_key(KeyCrt::Sign),
            vec![0x00, 0x47, 0x81, 0x00, 0x02, 0xB6, 0x00, 0x00]
        );
    }

    #[test]
    fn key_crt_tags() {
        assert_eq!(KeyCrt::Sign.crt(), [0xB6, 0x00]);
        assert_eq!(KeyCrt::Decrypt.crt(), [0xB8, 0x00]);
        assert_eq!(KeyCrt::Auth.crt(), [0xA4, 0x00]);
    }

    #[test]
    fn pso_compute_signature_bytes() {
        // A small fixed DigestInfo (not a real one; exercises framing only).
        let digest_info = [0x30, 0x07, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        // 00 2A 9E 9A <Lc=09> <data...> 00
        assert_eq!(
            pso_compute_signature(&digest_info),
            vec![
                0x00, 0x2A, 0x9E, 0x9A, 0x09, 0x30, 0x07, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00
            ]
        );
    }

    #[test]
    fn pso_decipher_bytes() {
        // Cipher DO with a leading padding-indicator byte (00) + cryptogram.
        let cipher = [0x00, 0xAA, 0xBB, 0xCC];
        // 00 2A 80 86 <Lc=04> <data...> 00
        assert_eq!(
            pso_decipher(&cipher),
            vec![0x00, 0x2A, 0x80, 0x86, 0x04, 0x00, 0xAA, 0xBB, 0xCC, 0x00]
        );
    }

    #[test]
    fn change_reference_data_bytes() {
        // Change PW1 (P2=81): old "123456" || new "654321".
        // 00 24 00 81 <Lc=0C> 31..36 36..31
        assert_eq!(
            change_reference_data(PW1_SIGN, b"123456", b"654321"),
            vec![
                0x00, 0x24, 0x00, 0x81, 0x0C, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x36, 0x35, 0x34,
                0x33, 0x32, 0x31
            ]
        );
        // Change PW3 (admin, P2=83): old "12345678" || new "87654321".
        assert_eq!(
            change_reference_data(PW3_ADMIN, b"12345678", b"87654321"),
            vec![
                0x00, 0x24, 0x00, 0x83, 0x10, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x38,
                0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31
            ]
        );
    }

    // --- Generated public key parsing ------------------------------------

    #[test]
    fn parse_generated_public_key_rsa_long_form() {
        // Build 7F49 { 81 <256-byte modulus> 82 <01 00 01> }. The 256-byte
        // modulus forces a long-form (0x82) length on the 81 object, and the
        // total 7F49 length is also long-form.
        let mut modulus = vec![0u8; 256];
        for (i, b) in modulus.iter_mut().enumerate() {
            *b = (i & 0xFF) as u8;
        }
        // Ensure a top bit set somewhere so it reads as a realistic modulus.
        modulus[0] = 0xC0;
        let exponent = [0x01, 0x00, 0x01];

        // Inner value: 81-TLV (long form) + 82-TLV (short form).
        let mut inner = Vec::new();
        inner.push(0x81);
        inner.push(0x82); // long form, 2 length bytes
        inner.push((modulus.len() >> 8) as u8);
        inner.push((modulus.len() & 0xFF) as u8);
        inner.extend_from_slice(&modulus);
        inner.push(0x82);
        inner.push(exponent.len() as u8);
        inner.extend_from_slice(&exponent);

        // Wrap in 7F49 (2-byte tag) with long-form length.
        let mut blob = Vec::new();
        blob.push(0x7F);
        blob.push(0x49);
        blob.push(0x82);
        blob.push((inner.len() >> 8) as u8);
        blob.push((inner.len() & 0xFF) as u8);
        blob.extend_from_slice(&inner);

        let pk = parse_generated_public_key(&blob).expect("RSA public key parses");
        assert_eq!(pk.modulus, modulus);
        assert_eq!(pk.exponent, exponent.to_vec());

        // Bare value (without the 7F49 envelope) also works.
        let pk2 = parse_generated_public_key(&inner).expect("bare value parses");
        assert_eq!(pk2.modulus, modulus);
        assert_eq!(pk2.exponent, exponent.to_vec());
    }

    #[test]
    fn parse_generated_public_key_ecc_reports_missing_modulus() {
        // An ECC key carries 86 (public point) instead of 81/82.
        let mut inner = Vec::new();
        inner.push(0x86);
        inner.push(0x20);
        inner.extend_from_slice(&[0x04; 32]);
        let mut blob = Vec::new();
        blob.push(0x7F);
        blob.push(0x49);
        blob.push(inner.len() as u8);
        blob.extend_from_slice(&inner);
        assert_eq!(
            parse_generated_public_key(&blob),
            Err(ParseError::MissingTag(TAG_RSA_MODULUS))
        );
    }

    // --- Instruction / constant sanity -----------------------------------

    #[test]
    fn instruction_codes() {
        assert_eq!(Instruction::GetData.code(), 0xCA);
        assert_eq!(Instruction::PutData.code(), 0xDA);
        assert_eq!(Instruction::Verify.code(), 0x20);
        assert_eq!(Instruction::GetResponse.code(), 0xC0);
        assert_eq!(Instruction::GenerateAsymmetricKeyPair.code(), 0x47);
        assert_eq!(Instruction::PerformSecurityOperation.code(), 0x2A);
        assert_eq!(Instruction::ChangeReferenceData.code(), 0x24);
        assert_eq!(GENERATE_KEY, 0x80);
        assert_eq!(READ_PUBLIC_KEY, 0x81);
        assert_eq!(PSO_COMPUTE_SIGNATURE, 0x9E9A);
        assert_eq!(PSO_DECIPHER, 0x8086);
        assert_eq!(PW1_SIGN, 0x81);
        assert_eq!(PW1_OTHER, 0x82);
        assert_eq!(PW3_ADMIN, 0x83);
    }

    // --- PUT DATA builders -----------------------------------------------

    #[test]
    fn key_crt_fpr_and_time_tags() {
        assert_eq!(KeyCrt::Sign.fpr_tag(), 0x00C7);
        assert_eq!(KeyCrt::Decrypt.fpr_tag(), 0x00C8);
        assert_eq!(KeyCrt::Auth.fpr_tag(), 0x00C9);
        assert_eq!(KeyCrt::Sign.time_tag(), 0x00CE);
        assert_eq!(KeyCrt::Decrypt.time_tag(), 0x00CF);
        assert_eq!(KeyCrt::Auth.time_tag(), 0x00D0);
    }

    #[test]
    fn put_data_generic_bytes() {
        // 5F50 splits across P1/P2; case-3 (no Le).
        assert_eq!(
            put_data(TAG_URL, &[0xAA, 0xBB]),
            vec![0x00, 0xDA, 0x5F, 0x50, 0x02, 0xAA, 0xBB]
        );
    }

    #[test]
    fn put_cardholder_name_bytes() {
        // 00 DA 00 5B <Lc=04> "Test"
        assert_eq!(
            put_cardholder_name(b"Test"),
            vec![0x00, 0xDA, 0x00, 0x5B, 0x04, 0x54, 0x65, 0x73, 0x74]
        );
    }

    #[test]
    fn put_url_bytes() {
        // 00 DA 5F 50 <Lc=01> "x"
        assert_eq!(put_url(b"x"), vec![0x00, 0xDA, 0x5F, 0x50, 0x01, 0x78]);
    }

    #[test]
    fn put_fingerprint_bytes() {
        // Signature slot -> C7; 20-byte value of 0xAB.
        let apdu = put_fingerprint(KeyCrt::Sign, &[0xAB; 20]);
        let mut expected = vec![0x00, 0xDA, 0x00, 0xC7, 0x14];
        expected.extend_from_slice(&[0xAB; 20]);
        assert_eq!(apdu, expected);
        assert_eq!(&apdu[..6], &[0x00, 0xDA, 0x00, 0xC7, 0x14, 0xAB]);
    }

    #[test]
    fn put_generation_time_bytes() {
        // Auth slot -> D0; 4-byte big-endian time 0x5D2C0B00.
        assert_eq!(
            put_generation_time(KeyCrt::Auth, 0x5D2C_0B00),
            vec![0x00, 0xDA, 0x00, 0xD0, 0x04, 0x5D, 0x2C, 0x0B, 0x00]
        );
    }

    // --- OpenPGP v4 fingerprint (MPI + SHA-1) ----------------------------

    #[test]
    fn mpi_known_answers() {
        // 8-byte modulus, top byte 0xC1 -> 64 bits (0x40).
        assert_eq!(
            mpi(&[0xC1, 0xF4, 0xD2, 0xA3, 0xC1, 0xF4, 0xD2, 0xA3]),
            vec![0x00, 0x40, 0xC1, 0xF4, 0xD2, 0xA3, 0xC1, 0xF4, 0xD2, 0xA3]
        );
        // exponent 01 00 01 -> 17 bits (0x11).
        assert_eq!(mpi(&[0x01, 0x00, 0x01]), vec![0x00, 0x11, 0x01, 0x00, 0x01]);
    }

    #[test]
    fn mpi_edge_cases() {
        // Leading zero bytes stripped: 00 00 01 -> 1 bit.
        assert_eq!(mpi(&[0x00, 0x00, 0x01]), vec![0x00, 0x01, 0x01]);
        // Top bit set in a single byte: 0x80 -> 8 bits.
        assert_eq!(mpi(&[0x80]), vec![0x00, 0x08, 0x80]);
        // All-zero / empty integers encode as bit length 0 with no value.
        assert_eq!(mpi(&[0x00, 0x00]), vec![0x00, 0x00]);
        assert_eq!(mpi(&[]), vec![0x00, 0x00]);
    }

    #[test]
    fn rsa_v4_fingerprint_known_answer() {
        let modulus = [0xC1, 0xF4, 0xD2, 0xA3, 0xC1, 0xF4, 0xD2, 0xA3];
        let exponent = [0x01, 0x00, 0x01];
        let fpr = rsa_v4_fingerprint(&modulus, &exponent, 0x5D2C_0B00);
        assert_eq!(
            fpr,
            [
                0x51, 0x64, 0x08, 0xC6, 0xA3, 0x00, 0x39, 0xCD, 0xF3, 0x70, 0x93, 0x9F, 0x06, 0x40,
                0x99, 0x5F, 0x21, 0xF3, 0x6C, 0xA5
            ]
        );

        // The PublicKey convenience wrapper agrees.
        let key = PublicKey {
            modulus: modulus.to_vec(),
            exponent: exponent.to_vec(),
        };
        assert_eq!(rsa_v4_fingerprint_from(&key, 0x5D2C_0B00), fpr);
    }
}
