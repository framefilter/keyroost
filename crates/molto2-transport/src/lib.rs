//! PC/SC transport for the Token2 Molto2.
//!
//! This crate is the bridge between `molto2-proto` (pure byte builders) and
//! the real device. It handles reader discovery, APDU exchange, and the
//! challenge-response auth handshake.
//!
//! ```no_run
//! use molto2_transport::{Session, TransportError};
//! use molto2_proto::commands::DEFAULT_CUSTOMER_KEY;
//!
//! # fn main() -> Result<(), TransportError> {
//! let mut session = Session::open()?;
//! let info = session.read_info()?;
//! session.authenticate(DEFAULT_CUSTOMER_KEY)?;
//! session.set_title(0, "Example")?;
//! # Ok(()) }
//! ```

use std::fmt;

use molto2_proto::commands::{self, derive_sm4_key, sw_auth_failed, sw_ok, Command, ProfileConfig};
use molto2_proto::READER_NAME_HINT;
use pcsc::{Attribute, Card, Context, Protocols, Scope, ShareMode};

mod oath;
pub use oath::OathSession;

mod openpgp;
pub use openpgp::{OpenPgpSession, OpenPgpStatus};
/// Re-exported so front-ends can name a key slot without depending on
/// `molto2-openpgp` directly (which would duplicate the crate in their graph).
pub use molto2_openpgp::KeyCrt;

/// Things that can go wrong talking to a Molto2.
#[derive(Debug)]
pub enum TransportError {
    /// PC/SC service unavailable (pcscd not running on Linux, or service stopped).
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
    OathParse(molto2_oath::ParseError),
    /// The OATH applet rejected the supplied password.
    OathPasswordRejected,
    /// An OpenPGP applet response could not be parsed.
    OpenPgpParse(molto2_openpgp::ParseError),
    /// No OpenPGP applet is present on the selected card (`SW 6A82`).
    NoOpenPgpApplet,
    /// The OpenPGP applet rejected the supplied PIN. `tries_remaining` is the
    /// count the card reported (`63 Cx`), or `None` when blocked / unknown.
    OpenPgpPinRejected { tries_remaining: Option<u8> },
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::PcscUnavailable(e) => {
                write!(
                    f,
                    "PC/SC service is unavailable ({}). On Linux make sure pcscd is running.",
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
            TransportError::OpenPgpPinRejected { tries_remaining: Some(n) } => {
                write!(f, "OpenPGP PIN rejected; {} attempt(s) remaining", n)
            }
            TransportError::OpenPgpPinRejected { tries_remaining: None } => {
                write!(f, "OpenPGP PIN rejected (PIN may be blocked)")
            }
        }
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TransportError::PcscUnavailable(e) | TransportError::Pcsc(e) => Some(e),
            TransportError::OathParse(e) => Some(e),
            TransportError::OpenPgpParse(e) => Some(e),
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
        let hint = READER_NAME_HINT.to_ascii_lowercase();
        let name = readers
            .find(|r| r.to_string_lossy().to_ascii_lowercase().contains(&hint))
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
            eprintln!("> {:>20} >> {}", cmd.label, hex_dump(&cmd.apdu));
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
            eprintln!("> {:>20} >> {}", cmd.label, hex_dump(&cmd.apdu));
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
        .filter(|r| r.to_string_lossy().to_ascii_lowercase().contains(YUBIKEY_READER_HINT))
        .map(|r| r.to_owned())
        .collect();

    let mut out = Vec::with_capacity(names.len());
    for name in names {
        let reader_name = name.to_string_lossy().into_owned();
        let (mut usb_bus, mut usb_address, mut serial) = (None, None, None);
        if let Ok(card) = ctx.connect(name.as_c_str(), ShareMode::Shared, Protocols::ANY) {
            (usb_bus, usb_address) = read_channel_id(&card);
            serial = read_yubikey_serial(&card).ok();
        }
        out.push(YubiKeyCcid { reader_name, usb_bus, usb_address, serial });
    }
    Ok(out)
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
        return Err(TransportError::Apdu { label: "select yubikey otp applet", sw1, sw2 });
    }
    // API request reading the device serial (CLA INS P1 P2 Le).
    let read = [0x00, YK_INS_API_REQ, YK_SLOT_DEVICE_SERIAL, 0x00, 0x00];
    let (data, sw1, sw2) = transmit_apdu(card, &read)?;
    if !sw_ok(sw1, sw2) {
        return Err(TransportError::Apdu { label: "read yubikey serial", sw1, sw2 });
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
