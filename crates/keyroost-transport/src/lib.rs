//! PC/SC transport for the Token2 Molto2.
//!
//! This crate is the bridge between `keyroost-proto` (pure byte builders) and
//! the real device. It handles reader discovery, APDU exchange, and the
//! challenge-response auth handshake.
//!
//! ```no_run
//! use keyroost_transport::{Session, TransportError};
//! use keyroost_proto::commands::DEFAULT_CUSTOMER_KEY;
//!
//! # fn main() -> Result<(), TransportError> {
//! let mut session = Session::open()?;
//! let info = session.read_info()?;
//! session.authenticate(DEFAULT_CUSTOMER_KEY)?;
//! session.set_title(0, "Example")?;
//! # Ok(()) }
//! ```

use std::fmt;

use keyroost_proto::commands::{
    self, derive_sm4_key, sw_auth_failed, sw_completed, sw_ok, Command, ProfileConfig,
    ProfilePublicData, PublicDataError,
};
use pcsc::{
    Attribute, Card, Context, Error as PcscError, Protocols, ReaderState, Scope, ShareMode, State,
    PNP_NOTIFICATION,
};

mod oath;
pub use oath::OathSession;

mod ctap_pcsc;
pub use ctap_pcsc::CtapPcscDevice;

mod token2prog;
pub use token2prog::Token2ProgSession;

mod openpgp;
pub use openpgp::{OpenPgpSession, OpenPgpStatus};

mod piv;
pub use piv::{
    random_chuid_guid, PivSession, PivSlotDetail, PivSlotStatus, PivStatus, PivStatusDetailed,
};

mod token2otp;
pub use token2otp::{
    otp_type_str, ButtonPrompt, HidOtpTransport, OtpTransportError, PcScOtpTransport,
    Token2OtpSession,
};

/// Opt-in per-thread APDU trace capture, for front ends that want the wire
/// exchange behind one operation rather than only a stderr stream. See the
/// module doc for why this is thread-local instead of a passed-in sink.
pub mod trace;

/// Re-exported so front-ends can name a key slot without depending on
/// `keyroost-openpgp` directly (which would duplicate the crate in their graph).
pub use keyroost_openpgp::{
    describe_algorithm_attributes, parse_algorithm_attributes, AlgorithmAttributes,
    AlgorithmInformation, Curve, EccKind, KeyAlg as OpenPgpKeyAlg, KeyCrt,
    PublicKey as OpenPgpPublicKey, RsaPrivateKeyParts, SlotMismatch,
};

/// Things that can go wrong talking to a Molto2.
#[non_exhaustive]
#[derive(Debug)]
pub enum TransportError {
    /// PC/SC service unavailable (the smart-card service is not running).
    PcscUnavailable(pcsc::Error),
    /// No connected reader matches the Molto2 name hint.
    NoMolto2Reader,
    /// Underlying PC/SC error during transmit / connect.
    Pcsc(pcsc::Error),
    /// Device returned a non-success status word.
    Apdu {
        label: &'static str,
        sw1: u8,
        sw2: u8,
    },
    /// Authentication failed; device reports tries remaining.
    AuthFailed { tries_remaining: Option<u8> },
    /// Response payload was shorter than expected.
    ShortResponse {
        label: &'static str,
        got: usize,
        expected_min: usize,
    },
    /// Response payload had unexpected structure.
    MalformedResponse(&'static str),
    /// The per-profile public block failed strict envelope validation.
    PublicData(PublicDataError),
    /// An OATH applet response could not be parsed.
    OathParse(keyroost_oath::ParseError),
    /// The OATH applet rejected the supplied password.
    OathPasswordRejected,
    /// An OpenPGP applet response could not be parsed.
    OpenPgpParse(keyroost_openpgp::ParseError),
    /// No OpenPGP applet is present on the selected card (`SW 6A82`).
    NoOpenPgpApplet,
    /// The OpenPGP applet rejected the supplied PIN. `tries_remaining` is the
    /// count the card reported (`63 Cx`), or `None` when blocked / unknown.
    OpenPgpPinRejected { tries_remaining: Option<u8> },
    /// A deliberately-wrong guess in the factory-reset blocking loop was
    /// *accepted*: it happened to be the card's live PW1/PW3. The counter never
    /// decrements for a correct PIN, so that password can't be blocked this way.
    OpenPgpPinGuessAccepted,
    /// A PIV applet response could not be parsed.
    PivParse(keyroost_piv::ParseError),
    /// No PIV applet is present on the selected card (`SW 6A82` on SELECT).
    NoPivApplet,
    /// PIV management-key authentication failed (the card's challenge response
    /// did not verify, i.e. the supplied management key is wrong).
    PivManagementAuthFailed,
    /// A PIV PIN/PUK verification failed; `tries_remaining` is the count the
    /// card reported (`63 Cx`), or `None` when blocked / unknown.
    PivPinRejected { tries_remaining: Option<u8> },
    /// A PIV write needed an authorization (management key or PIN) that hadn't
    /// been satisfied (`SW 6982`).
    PivSecurityNotSatisfied,
    /// A supplied PIV management key was the wrong length for its algorithm.
    PivBadKeyLength,
    /// A supplied PIV PIN/PUK was outside the 6–8 byte range the card stores.
    /// Caught before transmit — the card would silently truncate or pad.
    PivBadPinLength,
    /// PIV reset refused by the card: the PIN and PUK must both be blocked
    /// before the applet allows a factory reset (`SW 6983`).
    PivResetNotAllowed,
    /// A forced PIV factory reset was refused before it started: the card does
    /// not answer the vendor extensions that carry the RESET instruction, so
    /// blocking its PIN and PUK (which the forced path does deliberately) would
    /// have no way back.
    PivForceResetUnsupported,
    /// A forced PIV factory reset stopped part-way: a blocking loop hit its
    /// attempt cap without the card reporting the credential blocked, so RESET
    /// was never sent. Carries the state the card is actually in.
    PivForceResetIncomplete(&'static str),
    /// A deliberately-wrong PUK guess in the forced factory reset was
    /// *accepted*: RESET RETRY COUNTER really ran, so the card's PIN was
    /// rewritten to a known value and unblocked.
    PivPukGuessAccepted,
    /// A PIV operation needs a newer firmware than the card reports. Carries the
    /// human-readable operation that was attempted.
    PivFirmwareTooOld(&'static str),
    /// A PIV MOVE KEY refused because the destination slot already holds a key
    /// (GET METADATA pre-check, ahead of the card's own refusal).
    PivDestinationOccupied(keyroost_piv::Slot),
    /// The host operating system's random-number source failed; a security
    /// handshake that needs an unpredictable challenge was aborted.
    HostRngFailed,
    /// Building a certificate/CSR structure failed (bad subject, expiry before
    /// start, or an algorithm that cannot sign).
    X509(keyroost_piv::x509::X509Error),
    /// An OATH credential's name and/or secret would overflow the 255-byte
    /// short-APDU body. Mapped from the byte layer's fallible builders;
    /// reachable from an imported otpauth:// URI or QR code, and from a
    /// hostile card whose LIST response names are too long to use in
    /// follow-up CALCULATE/DELETE commands.
    OathCredentialTooLong,
    /// The RSA key's public exponent is wider than the OpenPGP card's declared
    /// exponent field (`e_bits`). Caught before building the import (the pure
    /// builder would otherwise panic); guards against a malformed card
    /// attribute as well as a genuine key/card mismatch.
    OpenPgpExponentTooWide,
    /// The requested OpenPGP key algorithm cannot live in the requested slot
    /// (Ed25519 only signs; X25519 only agrees keys).
    OpenPgpSlotMismatch(keyroost_openpgp::SlotMismatch),
    /// An RSA-only operation (RSA key import) found the slot already holds an
    /// ECC key instead. `slot` is the CLI's `--slot` value (`sign` / `decrypt`
    /// / `auth`); `label` is the ECC algorithm's display label.
    OpenPgpSlotNotRsa { slot: &'static str, label: String },
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::PcscUnavailable(e) => {
                write!(
                    f,
                    "PC/SC service is unavailable ({}). Make sure the smart-card service is running (pcscd on Linux; built in on macOS; the Smart Card service on Windows).",
                    e
                )
            }
            TransportError::NoMolto2Reader => {
                write!(
                    f,
                    "no Token2 Molto2 reader found. Is the device plugged in?"
                )
            }
            TransportError::Pcsc(e) => write!(f, "PC/SC error: {}", e),
            TransportError::Apdu { label, sw1, sw2 } => {
                write!(f, "device rejected {}: SW={:02X}{:02X}", label, sw1, sw2)?;
                if let Some(desc) = iso_sw_description(*sw1, *sw2) {
                    write!(f, " ({desc})")?;
                }
                Ok(())
            }
            TransportError::AuthFailed { tries_remaining } => match tries_remaining {
                Some(n) => write!(
                    f,
                    "authentication failed (wrong customer key); {} attempt(s) remaining",
                    n
                ),
                None => write!(
                    f,
                    "authentication failed (wrong customer key); attempts remaining unknown"
                ),
            },
            TransportError::ShortResponse {
                label,
                got,
                expected_min,
            } => {
                write!(
                    f,
                    "{}: response too short ({} bytes, expected at least {})",
                    label, got, expected_min
                )
            }
            TransportError::MalformedResponse(s) => write!(f, "malformed response: {}", s),
            TransportError::PublicData(e) => {
                write!(f, "malformed per-profile public block: {}", e)
            }
            TransportError::OathParse(e) => write!(f, "OATH response parse error: {}", e),
            TransportError::OathPasswordRejected => {
                write!(f, "OATH applet rejected the password (wrong password)")
            }
            TransportError::OpenPgpParse(e) => write!(f, "OpenPGP response parse error: {}", e),
            TransportError::NoOpenPgpApplet => {
                write!(f, "no OpenPGP applet on this card")
            }
            TransportError::OpenPgpPinRejected {
                tries_remaining: Some(n),
            } => {
                write!(f, "OpenPGP PIN rejected; {} attempt(s) remaining", n)
            }
            TransportError::OpenPgpPinRejected {
                tries_remaining: None,
            } => {
                write!(f, "OpenPGP PIN rejected (PIN may be blocked)")
            }
            TransportError::OpenPgpPinGuessAccepted => write!(
                f,
                "the factory reset's throwaway guess turned out to be this card's \
                 real OpenPGP password, so the retry counter never moved and the \
                 password cannot be blocked this way. Change the card's PW1/PW3 \
                 and run the factory reset again."
            ),
            TransportError::PivParse(e) => write!(f, "PIV response parse error: {}", e),
            TransportError::NoPivApplet => write!(f, "no PIV applet on this card"),
            TransportError::PivManagementAuthFailed => {
                write!(f, "PIV management-key authentication failed (wrong key)")
            }
            TransportError::PivPinRejected {
                tries_remaining: Some(n),
            } => write!(f, "PIV PIN/PUK rejected ({} tries remaining)", n),
            TransportError::PivPinRejected {
                tries_remaining: None,
            } => write!(f, "PIV PIN/PUK rejected (may be blocked)"),
            TransportError::PivSecurityNotSatisfied => write!(
                f,
                "PIV operation needs a management-key auth or PIN that wasn't satisfied"
            ),
            TransportError::PivBadKeyLength => {
                write!(
                    f,
                    "PIV management key length does not match any algorithm this card accepts"
                )
            }
            TransportError::PivBadPinLength => {
                write!(f, "PIV PIN/PUK must be 6-8 characters")
            }
            TransportError::PivResetNotAllowed => {
                write!(
                    f,
                    "PIV reset refused: the PIN and PUK must both be blocked first"
                )
            }
            TransportError::PivForceResetUnsupported => write!(
                f,
                "this card does not implement the RESET instruction a forced \
                 factory reset depends on (it is a vendor extension, not part of \
                 the PIV standard). Getting there means deliberately blocking the \
                 PIN and the PUK, and on this card nothing could unblock them \
                 afterwards, so keyroost will not do it. A card like this has to \
                 be reset by whoever issued it."
            ),
            TransportError::PivForceResetIncomplete(state) => write!(f, "{}", state),
            TransportError::PivPukGuessAccepted => write!(
                f,
                "the factory reset's throwaway PUK guess turned out to be this \
                 card's real PUK, so the card unblocked the PIN and set it to \
                 123456 instead of counting a failed attempt. Change that PIN \
                 (`keyroostctl piv change-pin`) before running the factory reset \
                 again."
            ),
            TransportError::PivFirmwareTooOld(op) => {
                write!(f, "{}", op)
            }
            TransportError::PivDestinationOccupied(slot) => write!(
                f,
                "slot {} already holds a key — delete it first or pick an empty slot",
                slot.label()
            ),
            TransportError::HostRngFailed => {
                write!(f, "the host OS random-number source failed")
            }
            TransportError::X509(e) => write!(f, "{}", e),
            TransportError::OathCredentialTooLong => write!(
                f,
                "OATH credential name/secret is too long for the card \
                 (name + secret must fit a 255-byte command)"
            ),
            TransportError::OpenPgpExponentTooWide => write!(
                f,
                "the key's RSA public exponent is wider than this OpenPGP card's \
                 declared exponent field"
            ),
            TransportError::OpenPgpSlotMismatch(e) => write!(f, "{e}"),
            TransportError::OpenPgpSlotNotRsa { slot, label } => write!(
                f,
                "the {slot} slot holds an ECC key ({label}); RSA import needs an RSA \
                 slot — run `openpgp generate-key --slot {slot} --algorithm rsa2048` first"
            ),
        }
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TransportError::PcscUnavailable(e) | TransportError::Pcsc(e) => Some(e),
            TransportError::PublicData(e) => Some(e),
            TransportError::OathParse(e) => Some(e),
            TransportError::OpenPgpParse(e) => Some(e),
            TransportError::OpenPgpSlotMismatch(e) => Some(e),
            TransportError::PivParse(e) => Some(e),
            TransportError::X509(e) => Some(e),
            _ => None,
        }
    }
}

impl From<pcsc::Error> for TransportError {
    fn from(e: pcsc::Error) -> Self {
        TransportError::Pcsc(e)
    }
}

/// Outcome of a per-profile seed delete (idempotent: both are success).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedDeleteOutcome {
    /// The slot had a seed and it is now gone (`90 00`).
    Deleted,
    /// The slot had no seed to begin with (`6A 83`).
    AlreadyEmpty,
}

/// Information returned by the `get_info` APDU.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    /// Vendor-assigned serial number string (ASCII).
    pub serial: String,
    /// On-device UTC time (unix epoch seconds).
    pub utc_time: u32,
}

/// An authenticated (or pre-auth) session against a Molto2 reader.
pub struct Session {
    card: Card,
    /// SM4 key derived from the customer key once auth succeeds. `None` before auth.
    sm4_key: Option<[u8; 16]>,
    /// When true, every APDU and response is printed to stderr with its label.
    debug: bool,
}

// The derived SM4 key is customer-key-equivalent (it MACs every write and
// decrypts seed ciphertext); scrub it when the session ends.
impl Drop for Session {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let Some(k) = self.sm4_key.as_mut() {
            k.zeroize();
        }
    }
}

impl Session {
    /// Enable per-APDU stderr tracing. Useful for hardware bring-up.
    pub fn set_debug(&mut self, on: bool) {
        self.debug = on;
    }

    /// Find the first Molto2 reader and open a card connection.
    pub fn open() -> Result<Self, TransportError> {
        let ctx = Context::establish(Scope::User).map_err(TransportError::PcscUnavailable)?;
        let mut readers_buf = [0u8; 2048];
        let mut readers = ctx
            .list_readers(&mut readers_buf)
            .map_err(TransportError::PcscUnavailable)?;
        let name = readers
            .find(|r| keyroost_proto::is_molto2_reader(&r.to_string_lossy()))
            .ok_or(TransportError::NoMolto2Reader)?;
        let card = ctx.connect(name, ShareMode::Shared, Protocols::ANY)?;
        Ok(Self {
            card,
            sm4_key: None,
            debug: false,
        })
    }

    /// Open a session against a specific reader name (useful when the user has
    /// multiple Token2 devices plugged in).
    pub fn open_named(reader_name: &str) -> Result<Self, TransportError> {
        let ctx = Context::establish(Scope::User).map_err(TransportError::PcscUnavailable)?;
        let cstring = std::ffi::CString::new(reader_name)
            .map_err(|_| TransportError::MalformedResponse("reader name contained NUL"))?;
        let card = ctx.connect(&cstring, ShareMode::Shared, Protocols::ANY)?;
        Ok(Self {
            card,
            sm4_key: None,
            debug: false,
        })
    }

    /// List the names of all connected PC/SC readers, Molto2 or not. Useful for diagnostics.
    pub fn list_readers() -> Result<Vec<String>, TransportError> {
        let ctx = Context::establish(Scope::User).map_err(TransportError::PcscUnavailable)?;
        let mut buf = [0u8; 4096];
        Ok(ctx
            .list_readers(&mut buf)
            .map_err(TransportError::PcscUnavailable)?
            .map(|r| r.to_string_lossy().into_owned())
            .collect())
    }

    /// Send a pre-built Command and return the response payload (without the SW1/SW2 trailer).
    /// Returns an error if the device responds with anything other than `9000`.
    fn transmit(&mut self, cmd: &Command) -> Result<Vec<u8>, TransportError> {
        trace::line(self.debug, || {
            format!(
                "> {:>20} >> {}",
                cmd.label,
                dump_cmd(&cmd.apdu, molto2_cmd_sensitive(&cmd.apdu))
            )
        });
        let mut buf = [0u8; 2048];
        let response = self.card.transmit(&cmd.apdu, &mut buf)?;
        trace::line(self.debug, || {
            format!("< {:>20} << {}", cmd.label, hex_dump(response))
        });
        if response.len() < 2 {
            return Err(TransportError::ShortResponse {
                label: cmd.label,
                got: response.len(),
                expected_min: 2,
            });
        }
        let (data, sw) = response.split_at(response.len() - 2);
        let (sw1, sw2) = (sw[0], sw[1]);
        if sw_auth_failed(sw1) {
            return Err(TransportError::AuthFailed {
                tries_remaining: auth_tries_remaining(sw2),
            });
        }
        if !sw_ok(sw1, sw2) {
            return Err(TransportError::Apdu {
                label: cmd.label,
                sw1,
                sw2,
            });
        }
        Ok(data.to_vec())
    }

    /// Send a Command but allow non-9000 status words. Returns `(data, sw1, sw2)`.
    /// Used for the probing subcommand.
    pub fn transmit_raw(&mut self, cmd: &Command) -> Result<(Vec<u8>, u8, u8), TransportError> {
        trace::line(self.debug, || {
            format!(
                "> {:>20} >> {}",
                cmd.label,
                dump_cmd(&cmd.apdu, molto2_cmd_sensitive(&cmd.apdu))
            )
        });
        let mut buf = [0u8; 2048];
        let response = self.card.transmit(&cmd.apdu, &mut buf)?;
        trace::line(self.debug, || {
            format!("< {:>20} << {}", cmd.label, hex_dump(response))
        });
        if response.len() < 2 {
            return Err(TransportError::ShortResponse {
                label: cmd.label,
                got: response.len(),
                expected_min: 2,
            });
        }
        let (data, sw) = response.split_at(response.len() - 2);
        Ok((data.to_vec(), sw[0], sw[1]))
    }

    /// Read serial + system time. No auth required.
    pub fn read_info(&mut self) -> Result<DeviceInfo, TransportError> {
        let cmd = commands::get_info();
        let data = self.transmit(&cmd)?;
        // The response byte layout (3-byte header, serial-length, serial,
        // 2-byte separator, 4-byte BE time) is parsed by the pure, fuzzed
        // `parse_info` in keyroost-proto so it's testable without hardware.
        let (serial, utc_time) = commands::parse_info(&data).map_err(|e| match e {
            commands::InfoError::TooShort { got, need } => TransportError::ShortResponse {
                label: "get info",
                got,
                expected_min: need,
            },
            _ => TransportError::MalformedResponse("get info: unrecognized error"),
        })?;
        Ok(DeviceInfo { serial, utc_time })
    }

    /// Read a profile's public block (title, occupancy, TOTP config).
    /// No auth required — the device answers any card holder.
    pub fn read_public_data(&mut self, profile: u8) -> Result<ProfilePublicData, TransportError> {
        let cmd = commands::read_public_data(profile);
        let data = self.transmit(&cmd)?;
        commands::parse_public_data(&data).map_err(TransportError::PublicData)
    }

    /// Delete one profile's seed. No authentication required
    /// (hardware-verified); the destructive-action gate is the caller's
    /// confirmation, not a device auth step. The stored title survives.
    pub fn delete_seed(&mut self, profile: u8) -> Result<SeedDeleteOutcome, TransportError> {
        let cmd = commands::delete_seed(profile);
        // transmit() treats any non-9000 SW as an error, but 6A 83 here just
        // means the slot had no seed — benign for a delete. Go through
        // transmit_raw and map the status words ourselves.
        let (_, sw1, sw2) = self.transmit_raw(&cmd)?;
        if sw_completed(sw1, sw2) {
            return Ok(SeedDeleteOutcome::Deleted);
        }
        if sw1 == 0x6A && sw2 == 0x83 {
            return Ok(SeedDeleteOutcome::AlreadyEmpty);
        }
        Err(TransportError::Apdu {
            label: cmd.label,
            sw1,
            sw2,
        })
    }

    /// Run the challenge-response handshake with the given customer key.
    /// On success, the session caches the derived SM4 key and subsequent
    /// methods can issue secured commands.
    pub fn authenticate(&mut self, customer_key: &[u8]) -> Result<(), TransportError> {
        let challenge_cmd = commands::get_challenge();
        let challenge = self.transmit(&challenge_cmd)?;
        if challenge.len() < 8 {
            return Err(TransportError::ShortResponse {
                label: "get challenge",
                got: challenge.len(),
                expected_min: 8,
            });
        }
        let mut chal = [0u8; 8];
        chal.copy_from_slice(&challenge[..8]);
        let sm4_key = derive_sm4_key(customer_key);
        let answer = commands::answer_challenge(&sm4_key, &chal);
        self.transmit(&answer)?;
        self.sm4_key = Some(sm4_key);
        Ok(())
    }

    /// `true` once `authenticate` has succeeded.
    pub fn is_authenticated(&self) -> bool {
        self.sm4_key.is_some()
    }

    fn key(&self) -> Result<&[u8; 16], TransportError> {
        self.sm4_key.as_ref().ok_or(TransportError::Apdu {
            label: "secure command",
            sw1: 0x69,
            sw2: 0x82,
        })
    }

    pub fn set_seed(&mut self, profile: u8, seed: &[u8]) -> Result<(), TransportError> {
        let key = *self.key()?;
        let cmd = commands::set_seed(&key, profile, seed);
        self.transmit(&cmd)?;
        Ok(())
    }

    pub fn set_title(&mut self, profile: u8, title: &str) -> Result<(), TransportError> {
        let key = *self.key()?;
        let cmd = commands::set_title(&key, profile, title);
        self.transmit(&cmd)?;
        Ok(())
    }

    pub fn set_config(&mut self, profile: u8, cfg: &ProfileConfig) -> Result<(), TransportError> {
        let key = *self.key()?;
        let cmd = commands::set_config(&key, profile, cfg);
        self.transmit(&cmd)?;
        Ok(())
    }

    pub fn sync_time(&mut self, profile: u8, utc_time: u32) -> Result<(), TransportError> {
        let key = *self.key()?;
        let cmd = commands::sync_time(&key, profile, utc_time);
        self.transmit(&cmd)?;
        Ok(())
    }

    pub fn set_customer_key(&mut self, new_key: &[u8]) -> Result<(), TransportError> {
        let key = *self.key()?;
        let cmd = commands::set_customer_key(&key, new_key);
        self.transmit(&cmd)?;
        Ok(())
    }

    pub fn factory_reset(&mut self) -> Result<(), TransportError> {
        let cmd = commands::factory_reset();
        self.transmit(&cmd)?;
        Ok(())
    }
}

// === YubiKey serial over CCID =============================================
//
// YubiKeys expose no USB `iSerialNumber`, but they carry a unique management
// serial reachable over their CCID interface (a visible PC/SC reader). Reading
// it lets the friendly-name resolver target a specific YubiKey by name even
// when same-model keys share VID:PID and AAGUID. The read is read-only — no PIN,
// no touch — and uses the OTP applet's "device serial" API request, which is
// stable across firmware generations.

/// Case-insensitive reader-name fragment identifying a YubiKey CCID interface.
const YUBIKEY_READER_HINT: &str = "yubikey";
/// YubiKey OTP applet AID (`A0 00 00 05 27 20 01 01`).
const YUBIKEY_OTP_AID: [u8; 8] = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01, 0x01];
/// OTP applet "API request" instruction byte.
const YK_INS_API_REQ: u8 = 0x01;
/// OTP applet slot/command selecting the 4-byte device serial.
const YK_SLOT_DEVICE_SERIAL: u8 = 0x10;

/// A connected YubiKey CCID interface: its reader, USB topology (decoded from
/// the reader's PC/SC `CHANNEL_ID`), and management serial if it could be read.
///
/// `usb_bus` / `usb_address` let a caller match this reader to the same physical
/// key's `/dev/hidrawN` node (whose sysfs `busnum`/`devnum` carry the same
/// numbers), which is how two connected YubiKeys are told apart.
#[derive(Debug, Clone)]
pub struct YubiKeyCcid {
    pub reader_name: String,
    pub usb_bus: Option<u8>,
    pub usb_address: Option<u8>,
    pub serial: Option<String>,
}

/// Enumerate connected YubiKey CCID readers and read each one's management
/// serial. Readers that can't be opened or read are still returned (with
/// `serial: None`) so callers can see them. An empty PC/SC reader list yields an
/// empty vec; only PC/SC-service failures error.
pub fn yubikey_ccid_serials() -> Result<Vec<YubiKeyCcid>, TransportError> {
    let ctx = Context::establish(Scope::User).map_err(TransportError::PcscUnavailable)?;
    let mut buf = [0u8; 4096];
    let names: Vec<std::ffi::CString> = ctx
        .list_readers(&mut buf)
        .map_err(TransportError::PcscUnavailable)?
        .filter(|r| {
            r.to_string_lossy()
                .to_ascii_lowercase()
                .contains(YUBIKEY_READER_HINT)
        })
        .map(|r| r.to_owned())
        .collect();

    let mut out = Vec::with_capacity(names.len());
    for name in names {
        let reader_name = name.to_string_lossy().into_owned();
        let (mut usb_bus, mut usb_address, mut serial) = (None, None, None);
        if let Ok(card) = ctx.connect(name.as_c_str(), ShareMode::Shared, Protocols::ANY) {
            (usb_bus, usb_address) = read_channel_id(&card);
            serial = read_yubikey_serial(&card).ok();
            // Release without resetting — pcsc's `Drop` hard-codes ResetCard,
            // which would yank the rug from under any session another process
            // (or this one) holds on the same card.
            let _ = card.disconnect(pcsc::Disposition::LeaveCard);
        }
        out.push(YubiKeyCcid {
            reader_name,
            usb_bus,
            usb_address,
            serial,
        });
    }
    Ok(out)
}

/// One PC/SC reader, probed in a single connection: which applets it answers,
/// plus YubiKey serial/topology when it is a YubiKey. Molto2 readers are flagged
/// but deliberately *not* connected.
#[derive(Debug, Clone)]
pub struct ReaderProbe {
    pub reader_name: String,
    /// True when the reader name matches the Token2 Molto2 hint. Such readers
    /// are listed by name only and never connected during enumeration (see
    /// [`probe_readers`]).
    pub is_molto2: bool,
    /// Reserved for a reader serial read during enumeration. Currently always
    /// `None`: the Molto2 is not connected during a probe (its serial is read
    /// later via [`Session::read_info`]), and security keys carry their serial
    /// in [`ReaderProbe::yubikey_serial`] instead.
    pub serial: Option<String>,
    /// OpenPGP card manufacturer ID (bytes 8..10 of the AID), when an OpenPGP
    /// applet was read. Maps to a vendor name via
    /// `keyroost_openpgp::manufacturer_name` — the card-content vendor signal
    /// that replaces the reader-name guess (#83).
    pub openpgp_manufacturer: Option<u16>,
    pub has_oath: bool,
    pub has_openpgp: bool,
    pub has_piv: bool,
    /// True when the card answers a SELECT of the FIDO applet
    /// (`A0000006472F0001`) — i.e. a FIDO2/U2F security key reached over this
    /// reader (NFC or contact). Lets the GUI offer the FIDO2 tab for reader-
    /// attached keys, served by [`CtapPcscDevice`].
    pub has_fido: bool,
    /// True when the card answers a SELECT of the Token2 on-device OTP applet
    /// (`F00000014F747001`). Detected by actually selecting the applet rather
    /// than guessing from the reader name, so the OTP tab is offered only for
    /// keys that really have it.
    pub has_otp: bool,
    /// True when the card answers the single-profile programmable token's
    /// `get_info` with a serial whose prefix matches a known model. Set during
    /// the same probe connection. The matched serial is carried in
    /// [`ReaderProbe::prog_serial`].
    pub is_prog: bool,
    /// The programmable token's serial, when `is_prog` is true.
    pub prog_serial: Option<String>,
    /// YubiKey management serial, read on the same connection when the reader is
    /// a YubiKey.
    pub yubikey_serial: Option<String>,
    pub usb_bus: Option<u8>,
    pub usb_address: Option<u8>,
}

/// Probe every connected PC/SC reader in a single pass: one context, the reader
/// list once, and **at most one card connection per reader**, on which all
/// applet SELECTs are issued in sequence.
///
/// Molto2 (Token2) readers are detected by name and **never connected** —
/// selecting foreign applets on a Molto2 resets its card and invalidates a held
/// [`Session`], which is what produced spurious "the smart card has been reset"
/// failures when a refresh ran between opening the token and authenticating.
/// The connections we do make are released with `LeaveCard` so they don't reset
/// other cards either.
///
/// PC/SC service failure errors; an individual reader that can't be connected is
/// returned with all-false capabilities rather than failing the whole scan.
pub fn probe_readers() -> Result<Vec<ReaderProbe>, TransportError> {
    let ctx = Context::establish(Scope::User).map_err(TransportError::PcscUnavailable)?;
    let mut buf = [0u8; 4096];
    let names: Vec<std::ffi::CString> = ctx
        .list_readers(&mut buf)
        .map_err(TransportError::PcscUnavailable)?
        .map(|r| r.to_owned())
        .collect();

    let mut out = Vec::with_capacity(names.len());
    for name in names {
        let reader_name = name.to_string_lossy().into_owned();
        // Lowercased copy for the YubiKey-hint check below, taken before
        // `reader_name` is moved into a `ReaderProbe`.
        let lower = reader_name.to_ascii_lowercase();

        // Molto2: list it by name only — NEVER connect during enumeration.
        // Even a gentle `get info` + `LeaveCard` churns the token's CCID slot,
        // and repeated across hotplug-triggered rescans it accumulates state
        // that wedges pcscd until the PC/SC stack is restarted (the reader then
        // stops enumerating entirely). The serial is read later, when the user
        // opens the token (`Session::read_info`).
        //
        // `is_molto2_reader` (not a bare "TOKEN2" substring) so Token2's own
        // FIDO keys — same brand, same VID, also a CCID reader — aren't
        // mis-flagged as a ghost Molto2 (issue #21).
        if keyroost_proto::is_molto2_reader(&reader_name) {
            out.push(ReaderProbe {
                reader_name,
                is_molto2: true,
                serial: None,
                openpgp_manufacturer: None,
                has_oath: false,
                has_openpgp: false,
                has_piv: false,
                has_fido: false,
                has_otp: false,
                is_prog: false,
                prog_serial: None,
                yubikey_serial: None,
                usb_bus: None,
                usb_address: None,
            });
            continue;
        }

        let mut probe = ReaderProbe {
            reader_name,
            is_molto2: false,
            serial: None,
            openpgp_manufacturer: None,
            has_oath: false,
            has_openpgp: false,
            has_piv: false,
            has_fido: false,
            has_otp: false,
            is_prog: false,
            prog_serial: None,
            yubikey_serial: None,
            usb_bus: None,
            usb_address: None,
        };
        let trace = std::env::var_os("KEYROOST_PROBE_DEBUG").is_some();
        if trace {
            eprintln!("[probe] reader seen: {}", probe.reader_name);
        }
        if let Ok(card) = ctx.connect(name.as_c_str(), ShareMode::Shared, Protocols::ANY) {
            (probe.usb_bus, probe.usb_address) = read_channel_id(&card);
            // An applet SELECT counts as "present" on a 9000, and also on the
            // T=0 continuation status words 61xx ("more data available") and
            // 6Cxx ("wrong Le"): both mean the SELECT was accepted and the applet
            // is answering. Some keys (e.g. Token2 PIN+ over CCID) reply 61xx to
            // a bare SELECT rather than 9000; without this they'd be misdetected
            // as lacking the applet and the GUI would hide the tab.
            let answers = |label: &str, apdu: Vec<u8>| {
                let r = transmit_apdu(&card, &apdu);
                if trace {
                    match &r {
                        Ok((_, s1, s2)) => {
                            eprintln!("[probe]   {label} select -> {s1:02X}{s2:02X}")
                        }
                        Err(e) => eprintln!("[probe]   {label} select -> error: {e}"),
                    }
                }
                matches!(r, Ok((_, s1, s2)) if sw_ok(s1, s2) || s1 == 0x61 || s1 == 0x6C)
            };
            probe.has_oath = answers("oath", keyroost_oath::select());
            probe.has_openpgp = answers("openpgp", keyroost_openpgp::select());
            // Full AID first — the spec-mandated identifier every compliant
            // card recognizes, including Nitrokey's `piv-authenticator`,
            // which (unlike YubiKey) rejects the short RID-only prefix.
            // `answers` short-circuits, so the fallback SELECT only goes out
            // when the full-AID one didn't answer. See `piv::AID`'s doc
            // comment in keyroost-piv for the full story.
            probe.has_piv = answers("piv", keyroost_piv::select_full())
                || answers("piv (short aid)", keyroost_piv::select());
            // FIDO2/U2F: a SELECT of the FIDO applet that the card accepts means
            // a security key is reachable over this reader (NFC or contact), to
            // be driven by CtapPcscDevice.
            probe.has_fido = answers(
                "fido",
                keyroost_token2otp::build_select(&keyroost_token2otp::FIDO_APPLET_AID),
            );
            // Token2 on-device OTP applet — select it to confirm presence,
            // rather than inferring from the reader name (which mislabels any
            // key on a "Token2" reader as having OTP).
            probe.has_otp = answers(
                "otp",
                keyroost_token2otp::build_select(&keyroost_token2otp::OTP_APPLET_AID),
            );
            // Single-profile programmable token: it has no distinctive reader
            // name and no applet to SELECT, so identify it by its info response.
            // Only flag it when the returned serial matches a known model prefix
            // — a generic NFC card that happens to answer won't be mislabelled.
            // Skip if an applet already matched (a FIDO/OATH key isn't a prog
            // token), keeping the get_info off cards that clearly aren't one.
            if !probe.has_fido && !probe.has_oath && !probe.has_piv && !probe.has_openpgp {
                let info = keyroost_token2prog::get_info();
                if let Ok((data, s1, s2)) = transmit_apdu(&card, &info.apdu) {
                    let body = if s1 == 0x61 {
                        transmit_apdu(&card, &[0x00, 0xC0, 0x00, 0x00, s2])
                            .map(|(d, _, _)| d)
                            .unwrap_or(data)
                    } else {
                        data
                    };
                    let _ = (s1, s2);
                    if let Ok(parsed) = keyroost_token2prog::parse_info(&body) {
                        if let Some(_model) = keyroost_token2prog::model_for_serial(&parsed.serial)
                        {
                            probe.is_prog = true;
                            probe.prog_serial = Some(parsed.serial);
                            if trace {
                                eprintln!("[probe]   prog token -> {:?}", probe.prog_serial);
                            }
                        }
                    }
                }
            }
            // When OpenPGP is present, recover the card serial from its AID (the
            // standard OpenPGP AID encodes a 4-byte serial at offset 10). This
            // lets keys with no HID serial (e.g. Token2 PIN+) still show one.
            // Re-SELECT OpenPGP first: the PIV probe above left a different applet
            // current, so GET DATA would otherwise hit the wrong one.
            // Token2 keys expose a full serial via the FIDO applet's GET_INFO
            // (spec §6.10), which is longer than the 4-byte serial embedded in the
            // OpenPGP AID. Prefer it so the device header shows the complete serial.
            // Best-effort: SELECT the FIDO applet (ignore its status word, as some
            // PIN+ firmware answers 6A81 yet still switches applets), then GET_INFO.
            // Token2 full serial via the FIDO applet's GET_INFO (spec §6.10) —
            // longer than the 4-byte OpenPGP-AID serial. Gate on card content
            // (the card actually has a FIDO applet), NOT the reader name, so a
            // Token2 card in a generic reader is read too (#83). Self-
            // validating: a well-formed `D1 len ascii-hex` parse proves it is a
            // Token2 device; anything else falls through harmlessly. SELECT is
            // best-effort (some PIN+ firmware answers 6A81 yet switches applets).
            if probe.has_fido {
                let _ = transmit_apdu(
                    &card,
                    &keyroost_token2otp::build_select(&keyroost_token2otp::FIDO_APPLET_AID),
                );
                if let Ok((body, _sw)) = exchange_apdu(
                    &card,
                    &keyroost_token2otp::read_serial_request(),
                    0x61,
                    || vec![0x00, 0xC0, 0x00, 0x00, 0x00],
                ) {
                    if let Ok(sn) = keyroost_token2otp::parse_serial(&body) {
                        let hex: String = sn.iter().map(|b| format!("{b:02x}")).collect();
                        if !hex.is_empty() {
                            probe.serial = Some(hex);
                            if trace {
                                eprintln!("[probe]   token2 full serial -> {:?}", probe.serial);
                            }
                        }
                    } else if trace {
                        eprintln!("[probe]   token2 serial parse failed (not a Token2 card)");
                    }
                }
            }
            // OpenPGP present: read the AID once. Capture the manufacturer ID
            // (card-content vendor signal, #83) always; use the embedded
            // 4-byte serial only as a fallback if a vendor full-serial read
            // didn't already populate one.
            if probe.has_openpgp {
                let _ = transmit_apdu(&card, &keyroost_openpgp::select());
                let get_aid = [0x00u8, 0xCA, 0x00, 0x4F, 0x00];
                if let Ok((resp, _sw)) =
                    exchange_apdu(&card, &get_aid, 0x61, || vec![0x00, 0xC0, 0x00, 0x00, 0x00])
                {
                    // Response may be the raw AID or a `4F len …` TLV wrapper.
                    let aid = if resp.len() >= 2 && resp[0] == 0x4F {
                        &resp[2..]
                    } else {
                        &resp[..]
                    };
                    probe.openpgp_manufacturer = keyroost_openpgp::aid_manufacturer_id(aid);
                    if trace {
                        eprintln!(
                            "[probe]   openpgp manufacturer -> {:?}",
                            probe.openpgp_manufacturer
                        );
                    }
                    if probe.serial.is_none()
                        && aid.len() >= 14
                        && aid[0..6] == [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]
                    {
                        let sn = &aid[10..14];
                        probe.serial =
                            Some(sn.iter().map(|b| format!("{b:02x}")).collect::<String>());
                        if trace {
                            eprintln!("[probe]   openpgp serial (aid) -> {:?}", probe.serial);
                        }
                    }
                }
            }
            if lower.contains(YUBIKEY_READER_HINT) {
                probe.yubikey_serial = read_yubikey_serial(&card).ok();
            }
            // Release without resetting, so a card another session holds is left
            // alone.
            let _ = card.disconnect(pcsc::Disposition::LeaveCard);
        } else if trace {
            eprintln!("[probe]   connect failed");
        }
        out.push(probe);
    }
    Ok(out)
}

/// A background thread that fires a callback whenever a PC/SC reader is added
/// or removed, so a GUI can re-enumerate on hotplug instead of only on a manual
/// refresh. Built on the `\\?PnP?\Notification` pseudo-reader, which reports
/// reader insertions/removals (not card events) without ever connecting to a
/// card — so it never disturbs a held [`Session`].
///
/// Best-effort: if the PC/SC service is unavailable the thread idles and retries,
/// and the app simply falls back to manual rescans. The watcher stops and joins
/// its thread when dropped.
pub struct ReaderWatcher {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl ReaderWatcher {
    /// Spawn the watcher. `on_change` is invoked once shortly after start (so an
    /// already-present reader missed by a startup scan is still picked up) and
    /// again on every subsequent reader insertion/removal. It runs on the
    /// watcher thread, so it must be cheap and thread-safe — typically just
    /// setting a flag and requesting a UI repaint.
    pub fn spawn<F>(on_change: F) -> Self
    where
        F: Fn() + Send + 'static,
    {
        use std::sync::atomic::Ordering;
        use std::time::Duration;
        // A finite wait so the stop flag is observed promptly on shutdown; the
        // call still blocks in the kernel until a real change or this timeout,
        // so idle cost is negligible.
        const WAIT: Duration = Duration::from_millis(750);

        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_thread = stop.clone();
        let handle = std::thread::Builder::new()
            .name("keyroost-reader-watch".into())
            .spawn(move || {
                // Outer loop re-establishes the context if the PC/SC service
                // drops (e.g. pcscd restart).
                while !stop_thread.load(Ordering::Relaxed) {
                    let Ok(ctx) = Context::establish(Scope::User) else {
                        std::thread::sleep(Duration::from_secs(2));
                        continue;
                    };
                    let mut states = [ReaderState::new(PNP_NOTIFICATION(), State::UNAWARE)];
                    while !stop_thread.load(Ordering::Relaxed) {
                        match ctx.get_status_change(WAIT, &mut states) {
                            Ok(()) => {
                                let st = states[0].event_state();
                                if st.contains(State::CHANGED) {
                                    on_change();
                                }
                                states[0].sync_current_state();
                                // Some platforms don't support PnP notification
                                // and report the pseudo-reader as unknown; avoid
                                // spinning if so.
                                if st.intersects(State::UNKNOWN | State::IGNORE) {
                                    std::thread::sleep(Duration::from_secs(2));
                                }
                            }
                            Err(PcscError::Timeout) => {}
                            // Context likely invalidated; break to re-establish.
                            Err(_) => break,
                        }
                    }
                }
            })
            // If the OS can't spawn the watch thread (resource exhaustion),
            // degrade to no live hot-plug detection rather than aborting the
            // process — the UI still works and falls back to manual rescans.
            // Say so on stderr: a session-long loss of hot-plug detection with
            // no diagnostic reads as "the app stopped noticing my key".
            .inspect_err(|e| {
                eprintln!("warning: could not start the reader hot-plug watcher ({e}); plug/unplug events will not be detected this session");
            })
            .ok();
        ReaderWatcher { stop, handle }
    }
}

impl Drop for ReaderWatcher {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Decode a reader's PC/SC `CHANNEL_ID` into `(usb_bus, usb_address)`. For USB
/// readers the DWORD's high word is `0x0020` and the low word is
/// `(bus << 8) | address`; anything else (or an unreadable attribute) is `None`.
fn read_channel_id(card: &Card) -> (Option<u8>, Option<u8>) {
    let mut buf = [0u8; 16];
    match card.get_attribute(Attribute::ChannelId, &mut buf) {
        Ok(b) if b.len() >= 4 => {
            let dw = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
            if (dw >> 16) == 0x0020 {
                (Some(((dw >> 8) & 0xff) as u8), Some((dw & 0xff) as u8))
            } else {
                (None, None)
            }
        }
        _ => (None, None),
    }
}

/// Read the YubiKey management serial by selecting the OTP applet and issuing
/// its device-serial API request. Returns the serial as its decimal string.
fn read_yubikey_serial(card: &Card) -> Result<String, TransportError> {
    // SELECT the OTP applet (case-3 APDU: header + Lc + AID).
    let mut select = vec![0x00, 0xA4, 0x04, 0x00, YUBIKEY_OTP_AID.len() as u8];
    select.extend_from_slice(&YUBIKEY_OTP_AID);
    let (_, sw1, sw2) = transmit_apdu(card, &select)?;
    if !sw_ok(sw1, sw2) {
        return Err(TransportError::Apdu {
            label: "select yubikey otp applet",
            sw1,
            sw2,
        });
    }
    // API request reading the device serial (CLA INS P1 P2 Le).
    let read = [0x00, YK_INS_API_REQ, YK_SLOT_DEVICE_SERIAL, 0x00, 0x00];
    let (data, sw1, sw2) = transmit_apdu(card, &read)?;
    if !sw_ok(sw1, sw2) {
        return Err(TransportError::Apdu {
            label: "read yubikey serial",
            sw1,
            sw2,
        });
    }
    if data.len() < 4 {
        return Err(TransportError::ShortResponse {
            label: "read yubikey serial",
            got: data.len(),
            expected_min: 4,
        });
    }
    let serial = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    Ok(serial.to_string())
}

/// Transmit one raw APDU, returning `(payload, sw1, sw2)`.
fn transmit_apdu(card: &Card, apdu: &[u8]) -> Result<(Vec<u8>, u8, u8), TransportError> {
    // Sized like the session loop's buffer. 256 is *not* enough: a full
    // short-form chunk is 256 data bytes plus SW1/SW2, and pcsc fails the
    // whole transmit with `InsufficientBuffer` rather than truncating — which
    // `answers()` would then report as "applet absent" for a key that is
    // present. 258 is the strict minimum; 4096 keeps both transmit paths
    // consistent and costs nothing (stack-local, per call).
    let mut buf = [0u8; 4096];
    let resp = card.transmit(apdu, &mut buf)?;
    if resp.len() < 2 {
        return Err(TransportError::ShortResponse {
            label: "yubikey apdu",
            got: resp.len(),
            expected_min: 2,
        });
    }
    let (data, sw) = resp.split_at(resp.len() - 2);
    Ok((data.to_vec(), sw[0], sw[1]))
}

/// A body-returning applet exchange for the probe: send `apdu`, follow `61xx`
/// (GET RESPONSE via `get_response`) and `6Cxx` (reissue the same command with
/// the corrected Le — the ISO 7816-4 case that a raw T=0 reader surfaces and
/// broke Token2 serial reads on generic readers, #83/#84), and return
/// `(data, sw)`. Shares the status-word decision with the session path via
/// `classify_sw` + `resend_with_le`, so `6Cxx` handling lives in one place.
fn exchange_apdu(
    card: &Card,
    apdu: &[u8],
    more_data_sw: u8,
    get_response: fn() -> Vec<u8>,
) -> Result<(Vec<u8>, u16), TransportError> {
    let mut acc = Vec::new();
    let mut to_send = apdu.to_vec();
    let mut steps = 0usize;
    loop {
        let (data, s1, s2) = transmit_apdu(card, &to_send)?;
        steps += 1;
        if steps > 32 {
            return Err(TransportError::MalformedResponse(
                "applet exchange exceeded the continuation limit",
            ));
        }
        match advance_exchange(
            more_data_sw,
            get_response,
            &to_send,
            &data,
            s1,
            s2,
            &mut acc,
        ) {
            Continuation::Send(next) => {
                if acc.len() > MAX_REASSEMBLED_RESPONSE {
                    return Err(TransportError::MalformedResponse(
                        "applet exchange exceeded the reassembly limit",
                    ));
                }
                to_send = next;
            }
            Continuation::Done => return Ok((acc, u16::from_be_bytes([s1, s2]))),
        }
    }
}

pub(crate) fn hex_dump(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&format!("{:02X}", b));
    }
    s
}

/// Hex-dump a command APDU for `--debug` traces, hiding the data field of
/// secret-bearing commands (PIN verify, seed/key import, …): the 5-byte
/// header (CLA INS P1 P2 Lc) stays visible for framing diagnosis, the body
/// does not. Debug traces are exactly what users paste into bug reports —
/// they must never carry PINs or key material.
pub(crate) fn dump_cmd(apdu: &[u8], sensitive: bool) -> String {
    if !sensitive || apdu.len() <= 5 {
        return hex_dump(apdu);
    }
    format!(
        "{} [{} data bytes redacted]",
        hex_dump(&apdu[..5]),
        apdu.len() - 5
    )
}

/// Caps on `61xx` / GET RESPONSE reassembly across the CCID sessions. A
/// misbehaving card that answers every continuation with another full chunk
/// would otherwise drive an unbounded loop and allocation. No legitimate
/// applet response approaches either limit.
pub(crate) const MAX_REASSEMBLED_RESPONSE: usize = 1 << 20; // 1 MiB
pub(crate) const MAX_RESPONSE_CHUNKS: usize = 4096;

/// Molto2 commands whose data field must be redacted from `--debug` traces:
/// `C5` set seed and `D7` set customer key carry SM4-ECB ciphertext that is
/// trivially decryptable when the (public) default customer key is still in
/// use, and `CE` answer-challenge pairs with the plaintext challenge from the
/// preceding response to hand an offline brute-force oracle for the customer
/// key.
fn molto2_cmd_sensitive(apdu: &[u8]) -> bool {
    matches!(apdu.get(1), Some(0xC5) | Some(0xD7) | Some(0xCE))
}

/// Decode the ISO-7816 `63 Cx` "warning, x retries remaining" status word.
///
/// Returns `Some(x)` only for the genuine `Cx` form. Any other `63 xx` —
/// notably `63 00`, "warning, no information given" — yields `None`: an
/// *unknown* count, not zero. This is the single decoder for every applet
/// (Molto2 auth, OpenPGP and PIV PINs); keep interpretation changes here.
pub(crate) fn sw_tries_remaining(sw: u16) -> Option<u8> {
    ((sw & 0xFFF0) == 0x63C0).then_some((sw & 0x000F) as u8)
}

/// A short plain-language reading of an ISO 7816-4 status word, for the trace's
/// `< … << SW = …` annotation line (emitted only for applets that opt into
/// command labelling via [`AppletIo::describe`]). Covers the status words the
/// the applets keyroost drives actually return; anything else is reported as non-standard
/// rather than guessed at.
pub(crate) fn iso_sw_summary(sw1: u8, sw2: u8) -> &'static str {
    iso_sw_description(sw1, sw2).unwrap_or("non-standard status word")
}

/// The recognised-status-word half of [`iso_sw_summary`]: `Some(text)` for a
/// status word this table knows, `None` for anything else. Error messages use
/// this to append a parenthetical gloss only when it actually informs —
/// `device rejected piv delete key: SW=6D00 (instruction not supported or
/// invalid)` — and to stay terse (`SW=6AF8`) when there is nothing to add.
pub(crate) fn iso_sw_description(sw1: u8, sw2: u8) -> Option<&'static str> {
    Some(match (sw1, sw2) {
        (0x90, 0x00) => "success",
        (0x61, _) => "success — more response bytes pending, GET RESPONSE needed",
        (0x63, 0x00) => "verification failed",
        (0x63, n) if n & 0xF0 == 0xC0 => {
            "verification failed — retries remaining in SW2 low nibble"
        }
        (0x69, 0x82) => "security status not satisfied — authenticate first",
        (0x69, 0x83) => "authentication method blocked",
        (0x69, 0x85) => "conditions of use not satisfied",
        (0x69, 0x86) => "command not allowed",
        (0x6A, 0x80) => "incorrect parameters in the command data field",
        (0x6A, 0x81) => "function not supported",
        (0x6A, 0x82) => "file or application not found",
        (0x6A, 0x84) => "not enough memory",
        (0x6A, 0x86) => "incorrect P1/P2",
        (0x6A, 0x88) => "referenced data not found",
        (0x67, 0x00) => "wrong length",
        (0x6C, _) => "wrong Le — reissue with the length in SW2",
        (0x6D, 0x00) => "instruction not supported or invalid",
        (0x6E, 0x00) => "class not supported",
        (0x68, 0x82) => "secure messaging not supported",
        (0x6F, 0x00) => "no precise diagnosis",
        _ => return None,
    })
}

/// Decode the remaining-attempts counter from SW2 of a Molto2 `63xx`
/// auth-failure.
///
/// The Molto2 reports it in the ISO-7816 `63 Cx` form — verified on hardware,
/// which returned `63 C7` with 7 tries remaining. A device that instead
/// reports a plain small count (no `Cx` marker) is accepted as a legacy
/// fallback; `63 00` and anything else decodes to `None` (unknown), never to
/// a fabricated "0 attempts left".
fn auth_tries_remaining(sw2: u8) -> Option<u8> {
    sw_tries_remaining(0x6300 | u16::from(sw2))
        .or_else(|| ((0x01..=0x0F).contains(&sw2)).then_some(sw2))
}

/// Hex-dump a response APDU for `--debug` traces, hiding the payload of
/// responses that carry secrets (e.g. PSO:DECIPHER plaintext). The SW1/SW2
/// trailer stays visible.
pub(crate) fn dump_resp(resp: &[u8], sensitive: bool) -> String {
    if !sensitive || resp.len() <= 2 {
        return hex_dump(resp);
    }
    format!(
        "[{} data bytes redacted] {}",
        resp.len() - 2,
        hex_dump(&resp[resp.len() - 2..])
    )
}

/// Static per-applet plumbing for [`transmit_applet`]: the trace label, the
/// SW1 byte that signals more data pending, the continuation-APDU builder, and
/// an optional command-namer.
pub(crate) struct AppletIo {
    pub label: &'static str,
    pub more_data_sw: u8,
    pub get_response: fn() -> Vec<u8>,
    /// When set, each transmitted APDU (the caller's command *and* every GET
    /// RESPONSE / Le-corrected reissue) gets two extra trace lines: a `>` line
    /// naming the command via this function, and a `<` line reading its status
    /// word ([`iso_sw_summary`]). `None` leaves the applet's trace as bare
    /// `>`/`<` hex.
    pub describe: Option<fn(&[u8]) -> String>,
}

/// What [`transmit_applet`] should do after one exchange, given the status word.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SwAction {
    /// Terminal status word — return the accumulated data and this SW.
    Done,
    /// `61xx` (SW1 == the applet's `more_data_sw`): more data pending; send
    /// GET RESPONSE and accumulate the next chunk.
    MoreData,
    /// `6Cxx` (ISO 7816-4 "wrong Le"): the card wants the *same* command
    /// reissued with `Le = xx`. Carries `xx`. No data was returned.
    WrongLe(u8),
}

/// Classify a two-byte status word for the applet reassembly loop.
///
/// `6Cxx` handling is why a T=0 smart-card reader that passes the raw card
/// response through (Alcor, SCM, Realtek, …) no longer fails where a reader
/// that absorbs the Le correction in firmware (the Token2 dual-interface
/// reader) always worked (issue #84). `61xx` is checked first via the
/// applet's `more_data_sw`; no applet uses `0x6C` for that, so the order is
/// unambiguous.
pub(crate) fn classify_sw(sw1: u8, more_data_sw: u8, sw2: u8) -> SwAction {
    if sw1 == more_data_sw {
        SwAction::MoreData
    } else if sw1 == 0x6C {
        SwAction::WrongLe(sw2)
    } else {
        SwAction::Done
    }
}

/// The next move of the applet reassembly loop, from [`advance_exchange`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Continuation {
    /// Terminal status word — `acc` now holds the complete response.
    Done,
    /// Send this APDU next and keep reassembling.
    Send(Vec<u8>),
}

/// Advance the applet reassembly state machine by one exchange: accumulate
/// whatever came back and decide what to send next.
///
/// Pure bookkeeping shared by the probe path ([`exchange_apdu`]) and the
/// session path ([`transmit_applet`]) so both react to a status word
/// identically — and so the `61xx`/`6Cxx` interplay is testable without a card.
///
/// * `61xx` — append the chunk, then ask for exactly the `xx` bytes the card
///   says are pending by putting them in the GET RESPONSE's Le (`xx == 0`
///   meaning 256, the short-form convention). Asking blindly for 256 is what
///   makes a card that validates Le answer `6Cxx` mid-read.
/// * `6Cxx` — no data came back, so `acc` is left alone and the command that
///   was *actually* sent is reissued with the corrected Le. Restarting the
///   caller's original command instead would discard the bytes read so far and
///   re-run a command with side effects (PIV GENERATE ASYMMETRIC KEY PAIR
///   mints a fresh key pair on every reissue). For the first exchange the two
///   are the same command, so nothing changes there.
/// * anything else — terminal; append the chunk and stop.
///
/// The caller owns the iteration and reassembly caps: every response, `6Cxx`
/// included, costs one step there, so a card that answers `6Cxx` forever still
/// terminates. Re-correcting the Le never grows the APDU either — the corrected
/// command already ends in Le, so the byte is replaced rather than appended.
pub(crate) fn advance_exchange(
    more_data_sw: u8,
    get_response: fn() -> Vec<u8>,
    to_send: &[u8],
    data: &[u8],
    sw1: u8,
    sw2: u8,
    acc: &mut Vec<u8>,
) -> Continuation {
    match classify_sw(sw1, more_data_sw, sw2) {
        SwAction::MoreData => {
            acc.extend_from_slice(data);
            Continuation::Send(keyroost_proto::apdu::resend_with_le(&get_response(), sw2))
        }
        SwAction::WrongLe(le) => {
            Continuation::Send(keyroost_proto::apdu::resend_with_le(to_send, le))
        }
        SwAction::Done => {
            acc.extend_from_slice(data);
            Continuation::Done
        }
    }
}

/// One applet APDU exchange with `61xx`-continuation reassembly, shared by the
/// OATH, OpenPGP, and PIV sessions (each computes its own sensitivity
/// predicates). `cmd_sensitive` redacts command bodies from `--debug` traces;
/// `resp_sensitive` redacts every response chunk of the reassembly loop
/// (sticky, so GET RESPONSE chunks of a secret payload stay hidden). The
/// transmitted copy is zeroized so PIN/key bodies don't linger on the heap.
pub(crate) fn transmit_applet(
    card: &Card,
    debug: bool,
    io: &AppletIo,
    apdu: &[u8],
    cmd_sensitive: bool,
    resp_sensitive: bool,
) -> Result<(Vec<u8>, u16), TransportError> {
    let mut acc = Vec::new();
    // The command currently in flight — the caller's APDU, then a GET RESPONSE
    // or an Le-corrected reissue of either. Zeroizing because a sensitive
    // command (VERIFY, CHANGE REFERENCE DATA, key import) must not linger on
    // the heap.
    let mut to_send = zeroize::Zeroizing::new(apdu.to_vec());
    let mut chunks = 0usize;
    loop {
        if let Some(describe) = io.describe {
            trace::line(debug, || {
                format!("> {:>14} >> {}", io.label, describe(&to_send))
            });
        }
        trace::line(debug, || {
            format!(
                "> {:>14} >> {}",
                io.label,
                dump_cmd(&to_send, cmd_sensitive)
            )
        });
        let mut buf = [0u8; 4096];
        let resp = card.transmit(&to_send, &mut buf)?;
        trace::line(debug, || {
            format!("< {:>14} << {}", io.label, dump_resp(resp, resp_sensitive))
        });
        if resp.len() < 2 {
            return Err(TransportError::ShortResponse {
                label: io.label,
                got: resp.len(),
                expected_min: 2,
            });
        }
        let (data, sw) = resp.split_at(resp.len() - 2);
        if io.describe.is_some() {
            let (sw1, sw2) = (sw[0], sw[1]);
            trace::line(debug, || {
                format!(
                    "< {:>14} << SW = {sw1:02X} {sw2:02X} ({})",
                    io.label,
                    iso_sw_summary(sw1, sw2)
                )
            });
        }
        chunks += 1;
        if chunks > MAX_RESPONSE_CHUNKS {
            return Err(TransportError::MalformedResponse(
                "applet continuation exceeded the chunk limit",
            ));
        }
        match advance_exchange(
            io.more_data_sw,
            io.get_response,
            &to_send,
            data,
            sw[0],
            sw[1],
            &mut acc,
        ) {
            Continuation::Send(next) => {
                if acc.len() > MAX_REASSEMBLED_RESPONSE {
                    return Err(TransportError::MalformedResponse(
                        "61xx continuation exceeded the reassembly limit",
                    ));
                }
                to_send = zeroize::Zeroizing::new(next);
            }
            Continuation::Done => return Ok((acc, u16::from_be_bytes([sw[0], sw[1]]))),
        }
    }
}

#[cfg(test)]
mod redaction_tests {
    use super::*;

    /// The applet reassembly loop must distinguish `61xx` (more data),
    /// `6Cxx` (wrong Le — reissue with the corrected length; issue #84), and
    /// terminal status words. `61xx` is keyed off the applet's `more_data_sw`.
    #[test]
    fn classify_sw_handles_more_data_wrong_le_and_terminal() {
        // 61xx: SW1 matches the applet's more-data byte (0x61 for all three).
        assert_eq!(classify_sw(0x61, 0x61, 0x00), SwAction::MoreData);
        // 6Cxx: wrong Le — carries the correct length to reissue with.
        assert_eq!(classify_sw(0x6C, 0x61, 0xFF), SwAction::WrongLe(0xFF));
        assert_eq!(classify_sw(0x6C, 0x61, 0x1D), SwAction::WrongLe(0x1D));
        // Terminal status words fall through to Done.
        assert_eq!(classify_sw(0x90, 0x61, 0x00), SwAction::Done); // 9000 OK
        assert_eq!(classify_sw(0x6A, 0x61, 0x82), SwAction::Done); // 6A82 not found
        assert_eq!(classify_sw(0x69, 0x61, 0x83), SwAction::Done); // 6983 blocked
    }

    #[test]
    fn iso_sw_summary_reads_common_status_words() {
        assert_eq!(iso_sw_summary(0x90, 0x00), "success");
        assert_eq!(iso_sw_summary(0x6A, 0x82), "file or application not found");
        assert_eq!(
            iso_sw_summary(0x69, 0x82),
            "security status not satisfied — authenticate first"
        );
        assert!(iso_sw_summary(0x61, 0x11).starts_with("success"));
        assert!(iso_sw_summary(0x63, 0xC3).starts_with("verification failed"));
        assert!(iso_sw_summary(0x6C, 0x20).starts_with("wrong Le"));
        assert_eq!(iso_sw_summary(0x12, 0x34), "non-standard status word");
    }

    #[test]
    fn apdu_error_appends_known_sw_gloss_and_omits_unknown() {
        // The status word the user's example is about: 6D00 gains a gloss.
        let known = TransportError::Apdu {
            label: "piv delete key",
            sw1: 0x6D,
            sw2: 0x00,
        };
        assert_eq!(
            known.to_string(),
            "device rejected piv delete key: SW=6D00 (instruction not supported or invalid)"
        );

        // A status word not in the table stays terse — no empty parens.
        let unknown = TransportError::Apdu {
            label: "piv sign",
            sw1: 0x6A,
            sw2: 0xF8,
        };
        assert_eq!(unknown.to_string(), "device rejected piv sign: SW=6AF8");
    }

    /// A `6Cxx` on the case-2 GET DATA APDU that OpenPGP `status()` sends
    /// (`00 CA p1 p2 00`) must reissue the SAME command with the trailing Le
    /// replaced by `xx` — the exact behavior that unbreaks OpenPGP reads on
    /// T=0 readers (#84).
    #[test]
    fn wrong_le_reissues_get_data_with_corrected_le() {
        let get_data = keyroost_proto::apdu::build_apdu_get(0x00, 0xCA, 0x00, 0x6E, 0x00);
        assert_eq!(get_data, vec![0x00, 0xCA, 0x00, 0x6E, 0x00]);
        // Card answered 6C FF -> reissue with Le = FF, replacing the 00.
        let reissued = keyroost_proto::apdu::resend_with_le(&get_data, 0xFF);
        assert_eq!(reissued, vec![0x00, 0xCA, 0x00, 0x6E, 0xFF]);
    }

    /// The GET RESPONSE the reassembly loop builds, matching the shape every
    /// applet's builder produces: case 2, `Le = 00`.
    fn test_get_response() -> Vec<u8> {
        vec![0x00, 0xC0, 0x00, 0x00, 0x00]
    }

    /// The Le correction must be applied to the command that was *actually*
    /// sent, and never overwrite a body byte: a case-2 APDU (header + Le) has
    /// its trailing Le replaced, a case-3 APDU (header + Lc + data) gets the Le
    /// appended.
    #[test]
    fn resend_with_le_replaces_case2_le_and_appends_to_case3_body() {
        use keyroost_proto::apdu::resend_with_le;
        // Case 2 — the GET RESPONSE of a continuation.
        assert_eq!(
            resend_with_le(&test_get_response(), 0x08),
            vec![0x00, 0xC0, 0x00, 0x00, 0x08]
        );
        // Case 3 — PIV GENERATE ASYMMETRIC KEY PAIR (RSA-2048, slot 9A). The
        // last byte is the algorithm ID, not an Le; replacing it would ask the
        // card to generate a different key.
        let generate = vec![0x00, 0x47, 0x00, 0x9A, 0x05, 0xAC, 0x03, 0x80, 0x01, 0x07];
        let mut expected = generate.clone();
        expected.push(0x20);
        assert_eq!(resend_with_le(&generate, 0x20), expected);
    }

    /// A `6Cxx` answered to the GET RESPONSE in the middle of a multi-chunk
    /// read must re-ask for the pending bytes and KEEP the accumulated data.
    /// Restarting the caller's command instead would drop the chunks read so
    /// far and re-run a side-effecting command (PIV key generation) on every
    /// iteration until the chunk cap fired.
    #[test]
    fn wrong_le_mid_read_reasks_get_response_and_keeps_acc() {
        let generate = vec![0x00, 0x47, 0x00, 0x9A, 0x05, 0xAC, 0x03, 0x80, 0x01, 0x07];
        let mut acc = Vec::new();

        // 1. The card answers the command with 16 bytes and "16 more pending":
        //    the continuation asks for exactly those 16, not a blind 256.
        let step = advance_exchange(
            0x61,
            test_get_response,
            &generate,
            &[0xAA; 16],
            0x61,
            0x10,
            &mut acc,
        );
        let get_resp_16 = vec![0x00, 0xC0, 0x00, 0x00, 0x10];
        assert_eq!(step, Continuation::Send(get_resp_16.clone()));
        assert_eq!(acc.len(), 16);

        // 2. The card rejects that Le with `6C 08` (no data). The retry targets
        //    the GET RESPONSE — not `generate` — and `acc` survives untouched.
        let step = advance_exchange(
            0x61,
            test_get_response,
            &get_resp_16,
            &[],
            0x6C,
            0x08,
            &mut acc,
        );
        let get_resp_8 = vec![0x00, 0xC0, 0x00, 0x00, 0x08];
        assert_eq!(step, Continuation::Send(get_resp_8.clone()));
        assert_ne!(step, Continuation::Send(generate.clone()));
        assert_eq!(acc, vec![0xAA; 16]);

        // 3. The corrected GET RESPONSE completes the object: 16 + 8 bytes.
        let step = advance_exchange(
            0x61,
            test_get_response,
            &get_resp_8,
            &[0xBB; 8],
            0x90,
            0x00,
            &mut acc,
        );
        assert_eq!(step, Continuation::Done);
        assert_eq!(acc.len(), 24);
        assert_eq!(&acc[16..], &[0xBB; 8]);
    }

    /// `6Cxx` on the *first* exchange still reissues the caller's own command —
    /// the behavior that unbroke reads on T=0 readers (#84) is unchanged,
    /// because there the command in flight *is* the original.
    #[test]
    fn wrong_le_on_first_exchange_reissues_the_callers_command() {
        let get_data = vec![0x00, 0xCA, 0x00, 0x6E, 0x00];
        let mut acc = Vec::new();
        let step = advance_exchange(
            0x61,
            test_get_response,
            &get_data,
            &[],
            0x6C,
            0xFF,
            &mut acc,
        );
        assert_eq!(step, Continuation::Send(vec![0x00, 0xCA, 0x00, 0x6E, 0xFF]));
        assert!(acc.is_empty());
    }

    /// `61 00` means 256 bytes pending, the short-form Le convention — the
    /// continuation keeps `Le = 00` rather than inventing a length.
    #[test]
    fn more_data_with_zero_hint_asks_for_256() {
        let mut acc = Vec::new();
        let step = advance_exchange(
            0x61,
            test_get_response,
            &[0x00, 0xA4, 0x04, 0x00, 0x00],
            &[0x01, 0x02],
            0x61,
            0x00,
            &mut acc,
        );
        assert_eq!(step, Continuation::Send(test_get_response()));
        assert_eq!(acc, vec![0x01, 0x02]);
    }

    /// A card that answers `6Cxx` forever must not grow the APDU: every retry
    /// replaces the Le of a command that already ends in one, so the reissue
    /// is length-stable and the caller's per-response step cap is what stops
    /// the loop.
    #[test]
    fn repeated_wrong_le_retries_are_length_stable() {
        let mut acc = Vec::new();
        let mut to_send = vec![0x00, 0x47, 0x00, 0x9A, 0x05, 0xAC, 0x03, 0x80, 0x01, 0x07];
        for round in 0..8u8 {
            let Continuation::Send(next) = advance_exchange(
                0x61,
                test_get_response,
                &to_send,
                &[],
                0x6C,
                round + 1,
                &mut acc,
            ) else {
                panic!("6Cxx must ask for a retry");
            };
            to_send = next;
            // First round appends the Le to the case-3 body (11 bytes); every
            // later round replaces it.
            assert_eq!(to_send.len(), 11);
            assert_eq!(*to_send.last().unwrap(), round + 1);
        }
        assert!(acc.is_empty());
    }

    /// `TransportError::PublicData` must chain its inner error via
    /// `source()` like the OATH/OpenPGP/PIV parse siblings do, so callers
    /// walking the chain (or `anyhow`-style reporters) see the strict-envelope
    /// detail instead of a dead end.
    #[test]
    fn public_data_error_chains_via_source() {
        use std::error::Error;
        let e = TransportError::PublicData(PublicDataError::BadOuterTag);
        let src = e.source().expect("PublicData must expose a source");
        assert!(src.downcast_ref::<PublicDataError>().is_some());
        assert_eq!(src.to_string(), "leading tag is not 0x95");
    }

    #[test]
    fn auth_tries_decodes_iso_63cx_form() {
        // The Molto2 reports the auth retry counter in ISO-7816 `63 Cx` form
        // (low nibble = tries remaining) — verified on hardware, which returned
        // `63 C7` with 7 attempts left. Reading the raw SW2 byte reported 199.
        assert_eq!(auth_tries_remaining(0xC7), Some(7));
        assert_eq!(auth_tries_remaining(0xC0), Some(0));
        assert_eq!(auth_tries_remaining(0xCA), Some(10));
        // A device that reports a plain count (< 0xCx form) is passed through.
        assert_eq!(auth_tries_remaining(0x03), Some(3));
        // `63 00` is ISO "warning, no information" — the count is unknown,
        // not zero; reporting Some(0) would falsely tell the user the key is
        // out of attempts.
        assert_eq!(auth_tries_remaining(0x00), None);
        assert_eq!(auth_tries_remaining(0x81), None);
    }

    #[test]
    fn sw_tries_remaining_only_decodes_cx_form() {
        assert_eq!(sw_tries_remaining(0x63C5), Some(5));
        assert_eq!(sw_tries_remaining(0x63C0), Some(0));
        assert_eq!(sw_tries_remaining(0x6300), None);
        assert_eq!(sw_tries_remaining(0x6983), None);
        assert_eq!(sw_tries_remaining(0x9000), None);
    }

    #[test]
    fn sensitive_cmd_hides_body_keeps_header() {
        // OpenPGP VERIFY PW1 with PIN "123456".
        let apdu = [
            0x00, 0x20, 0x00, 0x81, 0x06, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        ];
        let dumped = dump_cmd(&apdu, true);
        assert_eq!(dumped, "00 20 00 81 06 [6 data bytes redacted]");
        assert!(!dumped.contains("31 32"));
        // Non-sensitive commands and bodiless APDUs dump in full.
        assert_eq!(dump_cmd(&apdu, false), hex_dump(&apdu));
        let get_response = [0x00, 0xC0, 0x00, 0x00, 0x00];
        assert_eq!(dump_cmd(&get_response, true), hex_dump(&get_response));
    }

    #[test]
    fn sensitive_resp_hides_payload_keeps_sw() {
        let resp = [0xDE, 0xAD, 0xBE, 0xEF, 0x90, 0x00];
        assert_eq!(dump_resp(&resp, true), "[4 data bytes redacted] 90 00");
        assert_eq!(dump_resp(&resp, false), hex_dump(&resp));
        assert_eq!(dump_resp(&[0x90, 0x00], true), "90 00");
    }

    #[test]
    fn molto2_secret_bearing_ins_flagged() {
        for ins in [0xC5, 0xD7, 0xCE] {
            assert!(molto2_cmd_sensitive(&[0x84, ins, 0x00, 0x00]));
        }
        assert!(!molto2_cmd_sensitive(&[0x80, 0x41, 0x00, 0x00, 0x00]));
        assert!(!molto2_cmd_sensitive(&[]));
    }
}
