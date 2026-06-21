//! Command builders for the Token2 2nd-generation **single-profile**
//! programmable TOTP token (internally "OTPC P2").
//!
//! This is a close cousin of the multi-profile Molto2 (see [`keyroost_proto`]):
//! same NFC Type-4 / ISO 7816 transport, same SM4 block cipher, same ISO 9797-1
//! SM4-CBC MAC. It differs in a few concrete ways, all encoded here:
//!
//! * **One fixed profile.** There is no profile selector byte; every command
//!   targets the single slot.
//! * **A fixed device key.** Where the Molto2 derives its SM4 key from a
//!   customer key (`SHA1(customer_key)[..16]`), this token uses a fixed 16-byte
//!   key baked into the vendor tool. It is hardcoded here as
//!   [`DEVICE_SM4_KEY`]; no per-device or user-supplied key is involved.
//! * **`get_info` carries data.** The info request sends a two-byte body
//!   (`02 11`) rather than a bare `Le`.
//! * **Two seed-length forms.** A 20-byte seed and a 32-byte seed are framed and
//!   padded differently (see [`set_seed`]).
//!
//! Every builder returns the raw APDU bytes plus a short label; transmission and
//! response parsing live in the transport layer, keeping this crate hardware-
//! free and unit-testable. Crypto primitives (`Sm4`, the MAC, ISO 7816 padding)
//! are reused from `keyroost_proto` rather than re-implemented.

use keyroost_proto::apdu::{build_apdu, mac, CLA_PLAIN, CLA_SECURE};
use keyroost_proto::sm4::Sm4;

/// The fixed 16-byte SM4 key this token family authenticates and encrypts with.
///
/// This token uses a single fixed device key (`8A D2 06 88 3C A3 69 48 2A B2 71
/// 82 B6 E8 32 24`) rather than a per-device or customer-supplied secret, so it
/// is embedded directly.
pub const DEVICE_SM4_KEY: [u8; 16] = [
    0x8A, 0xD2, 0x06, 0x88, 0x3C, 0xA3, 0x69, 0x48, 0x2A, 0xB2, 0x71, 0x82, 0xB6, 0xE8, 0x32, 0x24,
];

/// HMAC algorithm for OTP generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HmacAlgo {
    Sha1 = 1,
    Sha256 = 2,
}

/// OTP time step (validity window).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeStep {
    /// 30 seconds — wire byte `0x1E`.
    Seconds30,
    /// 60 seconds — wire byte `0x3C`.
    Seconds60,
}

impl TimeStep {
    fn wire(self) -> u8 {
        match self {
            // The high two bits flag seconds (b00) vs minutes (b01); the low six
            // carry the count. 30 and 60 both fit the seconds form.
            TimeStep::Seconds30 => 0x1E,
            TimeStep::Seconds60 => 0x3C,
        }
    }
}

/// How long the display stays on before sleeping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayTimeout {
    Sec15 = 0,
    Sec30 = 1,
    Sec60 = 2,
    Sec120 = 3,
}

/// The full configuration written in one `set_config` command.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    pub display_timeout: DisplayTimeout,
    pub algorithm: HmacAlgo,
    pub time_step: TimeStep,
    /// Unix epoch seconds used to set the device clock.
    pub utc_time: u32,
}

/// An APDU ready to transmit, plus a short human label for logs/UI.
#[derive(Debug, Clone)]
pub struct Command {
    pub label: &'static str,
    pub apdu: Vec<u8>,
}

/// `80 41 00 00 02 02 11` — read serial and on-device UTC time. No auth needed.
///
/// Unlike the Molto2's bare-`Le` info request, this token expects a two-byte
/// body `02 11`.
pub fn get_info() -> Command {
    Command {
        label: "get info (serial + time)",
        apdu: build_apdu(CLA_PLAIN, 0x41, 0x00, 0x00, &[0x02, 0x11]),
    }
}

/// `80 4B 08 00 01 00` — request the 8-byte authentication challenge.
pub fn get_challenge() -> Command {
    Command {
        label: "get challenge",
        apdu: build_apdu(CLA_PLAIN, 0x4B, 0x08, 0x00, &[0x00]),
    }
}

/// `80 CE 00 00 10 <SM4(challenge ‖ 8 zero bytes)>` — answer the challenge.
///
/// The 8-byte `challenge` from [`get_challenge`] is "inflated" to a 16-byte
/// block by appending eight zero bytes, then SM4-encrypted under
/// [`DEVICE_SM4_KEY`]. The device replies `9000` on success or `6983` if the
/// key is locked.
pub fn answer_challenge(challenge: &[u8; 8]) -> Command {
    let mut block = [0u8; 16];
    block[..8].copy_from_slice(challenge);
    Sm4::new(&DEVICE_SM4_KEY).encrypt_block(&mut block);
    Command {
        label: "answer challenge",
        apdu: build_apdu(CLA_PLAIN, 0xCE, 0x00, 0x00, &block),
    }
}

/// Normalize a TOTP secret to the device's stored length.
///
/// The vendor tool pads a decoded secret shorter than 20 bytes up to 20 bytes
/// with trailing zero bytes before programming it. An authenticator app set up
/// from the same base32 secret uses those same bytes, so the device's codes only
/// match when keyroost stores the identical zero-padded seed. Secrets that are
/// already 20 bytes or longer are returned unchanged (the device also accepts
/// 32-byte seeds via the longer-seed framing in [`set_seed`]).
pub fn pad_totp_seed(mut seed: Vec<u8>) -> Vec<u8> {
    if seed.len() < 20 {
        seed.resize(20, 0);
    }
    seed
}

/// `84 C5 01 00 Lc <SM4(seed_padded) ‖ mac>` — program the OTP seed.
///
/// `seed` is the raw key bytes (1..=63). Two on-wire forms exist, matching the
/// vendor tool:
///
/// * **≤ 16-byte effective / general case:** the seed is ISO 9797-1 padded to a
///   block boundary, SM4-ECB encrypted, and MAC'd with the plain header
///   `80 C5 01 00 <enc_len>`.
/// * **Exactly 32 bytes:** an extra full pad block is appended (`0x80` followed
///   by fifteen `0x00`) before encryption — a 48-byte ciphertext — reflecting
///   the device's longer-seed framing.
///
/// In both cases the wire APDU uses the secure class `0x84`, while the MAC is
/// computed over the plain class `0x80` with the *encrypted-payload* length.
pub fn set_seed(seed: &[u8]) -> Result<Command, SeedError> {
    if seed.is_empty() || seed.len() > 63 {
        return Err(SeedError::Length(seed.len()));
    }

    let key = Sm4::new(&DEVICE_SM4_KEY);

    let enc: Vec<u8> = if seed.len() == 32 {
        // Longer-seed form: 32 bytes + a full 16-byte 0x80-pad block = 48 bytes.
        let mut padded = Vec::with_capacity(48);
        padded.extend_from_slice(seed);
        padded.push(0x80);
        padded.extend_from_slice(&[0u8; 15]);
        key.encrypt_ecb(&mut padded);
        padded
    } else {
        // General form: ISO 9797-1 minimal pad to a block boundary, then ECB.
        let mut padded = keyroost_proto::apdu::pad_iso7816_minimal(seed);
        key.encrypt_ecb(&mut padded);
        padded
    };

    let enc_len = enc.len() as u8;
    let mac_bytes = mac(&DEVICE_SM4_KEY, &[CLA_PLAIN, 0xC5, 0x01, 0x00, enc_len], &enc);

    let mut body = enc;
    body.extend_from_slice(&mac_bytes);

    Ok(Command {
        label: "set seed",
        apdu: build_apdu(CLA_SECURE, 0xC5, 0x01, 0x00, &body),
    })
}

/// `84 D4 00 00 Lc <TLV ‖ mac>` — write the device configuration.
///
/// The 19-byte TLV body sets the display timeout, the device clock, and the
/// TOTP parameters (HMAC algorithm and time step). As with [`set_seed`], the
/// MAC is computed over the plain header `80 D4 00 00 13` (length `0x13` = 19),
/// while the transmitted APDU uses the secure class `0x84`.
pub fn set_config(cfg: &Config) -> Command {
    let mut tlv = Vec::with_capacity(19);
    // 81 11 — TLV_TAG_SYS_CONFG, 0x11 (17) bytes of children follow.
    tlv.push(0x81);
    tlv.push(0x11);
    // 1F 01 <display_timeout>
    tlv.push(0x1F);
    tlv.push(0x01);
    tlv.push(cfg.display_timeout as u8);
    // 0F 04 <utc_time, big-endian>
    tlv.push(0x0F);
    tlv.push(0x04);
    tlv.extend_from_slice(&cfg.utc_time.to_be_bytes());
    // 86 06 — TLV_TAG_TOTP_PARAM, 6 bytes of children.
    tlv.push(0x86);
    tlv.push(0x06);
    // 0A 01 <hmac_method>
    tlv.push(0x0A);
    tlv.push(0x01);
    tlv.push(cfg.algorithm as u8);
    // 0D 01 <time_step>
    tlv.push(0x0D);
    tlv.push(0x01);
    tlv.push(cfg.time_step.wire());

    debug_assert_eq!(tlv.len(), 19);

    let mac_bytes = mac(
        &DEVICE_SM4_KEY,
        &[CLA_PLAIN, 0xD4, 0x00, 0x00, tlv.len() as u8],
        &tlv,
    );
    let mut body = tlv;
    body.extend_from_slice(&mac_bytes);

    Command {
        label: "set config",
        apdu: build_apdu(CLA_SECURE, 0xD4, 0x00, 0x00, &body),
    }
}

/// Parsed response of [`get_info`]: the printed serial and the device clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Info {
    pub serial: String,
    /// Device UTC clock, Unix epoch seconds.
    pub utc_time: u32,
}

impl Info {
    /// Resolve the human model name from the serial, if recognized.
    /// See [`model_for_serial`].
    pub fn model(&self) -> Option<&'static str> {
        model_for_serial(&self.serial)
    }
}

/// Map a device serial to its Token2 model name by leading-digit prefix.
///
/// Token2 encodes the product in the first digits of the printed serial. The
/// table below is matched longest-prefix-first, so a 7-digit prefix wins over a
/// 6-digit one even though the current set has no overlap. Returns `None` for an
/// unrecognized serial (e.g. a future product) so callers can fall back to
/// showing the raw serial.
pub fn model_for_serial(serial: &str) -> Option<&'static str> {
    // (serial prefix, model name). Kept sorted by descending prefix length at
    // match time; the source order here is for readability.
    const MODELS: &[(&str, &str)] = &[
        ("8659612", "OTPC-P1-i"),
        ("8659622", "OTPC-P2-i"),
        ("8659621", "OTPC-P2-i-NB"),
        ("8659600", "miniOTP-2-i"),
        ("8659601", "miniOTP-3-i"),
        ("8659609", "miniOTP-3-i-NB"),
        ("8659610", "C301-i"),
        ("8659632", "C302-i"),
    ];
    // Trim any surrounding whitespace the device might pad the serial with.
    let s = serial.trim();
    MODELS
        .iter()
        .filter(|(prefix, _)| s.starts_with(prefix))
        // Longest matching prefix wins (defensive against future overlaps).
        .max_by_key(|(prefix, _)| prefix.len())
        .map(|(_, model)| *model)
}

/// Errors decoding a `get_info` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InfoError {
    /// The response was shorter than the framing requires.
    Truncated,
    /// The serial field was not valid UTF-8.
    SerialNotUtf8,
}

/// Decode the body of a [`get_info`] response (status word already stripped).
///
/// Layout (from the device): `?? ?? ?? <serial_len> <serial…> ?? ?? <time:4>`,
/// i.e. the serial length is at offset 3, the serial follows, and a 4-byte
/// big-endian Unix time sits two bytes after the serial.
pub fn parse_info(body: &[u8]) -> Result<Info, InfoError> {
    if body.len() < 4 {
        return Err(InfoError::Truncated);
    }
    let serial_len = body[3] as usize;
    let serial_start = 4;
    let serial_end = serial_start + serial_len;
    let time_start = serial_end + 2;
    let time_end = time_start + 4;
    if body.len() < time_end {
        return Err(InfoError::Truncated);
    }
    let serial =
        core::str::from_utf8(&body[serial_start..serial_end]).map_err(|_| InfoError::SerialNotUtf8)?;
    let utc_time = u32::from_be_bytes([
        body[time_start],
        body[time_start + 1],
        body[time_start + 2],
        body[time_start + 3],
    ]);
    Ok(Info {
        serial: serial.to_string(),
        utc_time,
    })
}

/// Errors building a seed command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedError {
    /// Seed length must be 1..=63 bytes; carries the offending length.
    Length(usize),
}

impl core::fmt::Display for SeedError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SeedError::Length(n) => write!(f, "seed length {n} out of range (must be 1..=63 bytes)"),
        }
    }
}

impl std::error::Error for SeedError {}
