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
    self, derive_sm4_key, sw_auth_failed, sw_ok, Command, ProfileConfig,
};
use pcsc::{
    Attribute, Card, Context, Error as PcscError, Protocols, ReaderState, Scope, ShareMode, State,
    PNP_NOTIFICATION,
};

mod oath;
pub use oath::OathSession;

mod openpgp;
pub use openpgp::{OpenPgpSession, OpenPgpStatus};

mod piv;
pub use piv::{PivSession, PivSlotStatus, PivStatus};

mod token2otp;
pub use token2otp::{
    otp_type_str, ButtonPrompt, HidOtpTransport, OtpTransportError, PcScOtpTransport,
    Token2OtpSession,
};

/// Re-exported so front-ends can name a key slot without depending on
/// `keyroost-openpgp` directly (which would duplicate the crate in their graph).
pub use keyroost_openpgp::{KeyCrt, RsaPrivateKeyParts};

/// Things that can go wrong talking to a Molto2.
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
    AuthFailed { tries_remaining: u8 },
    /// Response payload was shorter than expected.
    ShortResponse {
        label: &'static str,
        got: usize,
        expected_min: usize,
    },
    /// Response payload had unexpected structure.
    MalformedResponse(&'static str),
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
    /// The host operating system's random-number source failed; a security
    /// handshake that needs an unpredictable challenge was aborted.
    HostRngFailed,
    /// Building a certificate/CSR structure failed (bad subject, expiry before
    /// start, or an algorithm that cannot sign).
    X509(keyroost_piv::x509::X509Error),
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
                write!(f, "device rejected {}: SW={:02X}{:02X}", label, sw1, sw2)
            }
            TransportError::AuthFailed { tries_remaining } => {
                write!(
                    f,
                    "authentication failed (wrong customer key); {} attempt(s) remaining",
                    tries_remaining
                )
            }
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
                    "PIV management key has the wrong length for its algorithm"
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
            TransportError::HostRngFailed => {
                write!(f, "the host OS random-number source failed")
            }
            TransportError::X509(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TransportError::PcscUnavailable(e) | TransportError::Pcsc(e) => Some(e),
            TransportError::OathParse(e) => Some(e),
            TransportError::OpenPgpParse(e) => Some(e),
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
        if self.debug {
            eprintln!(
                "> {:>20} >> {}",
                cmd.label,
                dump_cmd(&cmd.apdu, molto2_cmd_sensitive(&cmd.apdu))
            );
        }
        let mut buf = [0u8; 2048];
        let response = self.card.transmit(&cmd.apdu, &mut buf)?;
        if self.debug {
            eprintln!("< {:>20} << {}", cmd.label, hex_dump(response));
        }
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
                tries_remaining: sw2,
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
        if self.debug {
            eprintln!(
                "> {:>20} >> {}",
                cmd.label,
                dump_cmd(&cmd.apdu, molto2_cmd_sensitive(&cmd.apdu))
            );
        }
        let mut buf = [0u8; 2048];
        let response = self.card.transmit(&cmd.apdu, &mut buf)?;
        if self.debug {
            eprintln!("< {:>20} << {}", cmd.label, hex_dump(response));
        }
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
        // Layout observed in molto2.py:
        //   <something><something><something><serial_len> <serial> <2 bytes ??> <4-byte BE time>
        // The Python code reads info[3] as serial length, then info[4..4+len], then skips 2,
        // then reads 4 bytes BE time.
        if data.len() < 4 {
            return Err(TransportError::ShortResponse {
                label: "get info",
                got: data.len(),
                expected_min: 4,
            });
        }
        let serial_len = data[3] as usize;
        let serial_end = 4 + serial_len;
        if data.len() < serial_end + 2 + 4 {
            return Err(TransportError::ShortResponse {
                label: "get info",
                got: data.len(),
                expected_min: serial_end + 6,
            });
        }
        let serial = String::from_utf8_lossy(&data[4..serial_end]).into_owned();
        let time_offset = serial_end + 2;
        let utc_time = u32::from_be_bytes(
            data[time_offset..time_offset + 4]
                .try_into()
                .map_err(|_| TransportError::MalformedResponse("time field"))?,
        );
        Ok(DeviceInfo { serial, utc_time })
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
    pub has_oath: bool,
    pub has_openpgp: bool,
    pub has_piv: bool,
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
                has_oath: false,
                has_openpgp: false,
                has_piv: false,
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
            has_oath: false,
            has_openpgp: false,
            has_piv: false,
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
            probe.has_piv = answers("piv", keyroost_piv::select());
            // When OpenPGP is present, recover the card serial from its AID (the
            // standard OpenPGP AID encodes a 4-byte serial at offset 10). This
            // lets keys with no HID serial (e.g. Token2 PIN+) still show one.
            // Re-SELECT OpenPGP first: the PIV probe above left a different applet
            // current, so GET DATA would otherwise hit the wrong one.
            if probe.has_openpgp {
                let _ = transmit_apdu(&card, &keyroost_openpgp::select());
                let get_aid = [0x00u8, 0xCA, 0x00, 0x4F, 0x00];
                if let Ok((data, s1, s2)) = transmit_apdu(&card, &get_aid) {
                    let resp = if s1 == 0x61 {
                        transmit_apdu(&card, &[0x00, 0xC0, 0x00, 0x00, s2])
                            .map(|(d, _, _)| d)
                            .unwrap_or(data)
                    } else {
                        data
                    };
                    // The response may be the raw 16-byte AID, or wrapped in a
                    // `4F len ...` TLV. Locate the D2 76 00 01 24 01 prefix.
                    let aid = if resp.len() >= 2 && resp[0] == 0x4F {
                        &resp[2..]
                    } else {
                        &resp[..]
                    };
                    if aid.len() >= 14 && aid[0..6] == [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01] {
                        let sn = &aid[10..14];
                        probe.serial =
                            Some(sn.iter().map(|b| format!("{b:02x}")).collect::<String>());
                        if trace {
                            eprintln!("[probe]   openpgp serial -> {:?}", probe.serial);
                        }
                    } else if trace {
                        let hex: String = resp.iter().map(|b| format!("{b:02x}")).collect();
                        eprintln!("[probe]   openpgp AID unparsed: {hex}");
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
            .expect("spawn reader-watch thread");
        ReaderWatcher {
            stop,
            handle: Some(handle),
        }
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
    let mut buf = [0u8; 256];
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
/// SW1 byte that signals more data pending, and the continuation-APDU builder.
pub(crate) struct AppletIo {
    pub label: &'static str,
    pub more_data_sw: u8,
    pub get_response: fn() -> Vec<u8>,
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
    let mut to_send = zeroize::Zeroizing::new(apdu.to_vec());
    let mut chunks = 0usize;
    loop {
        if debug {
            eprintln!(
                "> {:>14} >> {}",
                io.label,
                dump_cmd(&to_send, cmd_sensitive)
            );
        }
        let mut buf = [0u8; 4096];
        let resp = card.transmit(&to_send, &mut buf)?;
        if debug {
            eprintln!("< {:>14} << {}", io.label, dump_resp(resp, resp_sensitive));
        }
        if resp.len() < 2 {
            return Err(TransportError::ShortResponse {
                label: io.label,
                got: resp.len(),
                expected_min: 2,
            });
        }
        let (data, sw) = resp.split_at(resp.len() - 2);
        acc.extend_from_slice(data);
        chunks += 1;
        if acc.len() > MAX_REASSEMBLED_RESPONSE || chunks > MAX_RESPONSE_CHUNKS {
            return Err(TransportError::MalformedResponse(
                "61xx continuation exceeded reassembly limits",
            ));
        }
        if sw[0] == io.more_data_sw {
            to_send = zeroize::Zeroizing::new((io.get_response)());
            continue;
        }
        return Ok((acc, u16::from_be_bytes([sw[0], sw[1]])));
    }
}

#[cfg(test)]
mod redaction_tests {
    use super::*;

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
