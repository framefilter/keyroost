//! PC/SC transport for the Token2 2nd-generation single-profile programmable
//! TOTP token.
//!
//! Mirrors the Molto2 [`crate::Session`] but for the single-profile token: it
//! finds a reader, opens a card connection, and exposes the four operations
//! (`read_info`, `authenticate`, `set_seed`, `set_config`) built by
//! [`keyroost_token2prog`]. Like the Molto2 path — and the vendor reference tool
//! — it talks to the card directly without an applet SELECT.
//!
//! Authentication uses the token's fixed device key (no customer key is
//! supplied), so [`Token2ProgSession::authenticate`] takes no arguments.

use keyroost_token2prog::{self as prog, Command};
use pcsc::{Card, Context, Protocols, Scope, ShareMode};

use crate::TransportError;

/// A session against a single-profile programmable token over a reader.
pub struct Token2ProgSession {
    card: Card,
    /// Set once `authenticate` has succeeded; gates the secured commands.
    authenticated: bool,
    /// When true, every APDU and response is printed to stderr with its label.
    debug: bool,
}

impl Token2ProgSession {
    /// Enable per-APDU stderr tracing. Useful for hardware bring-up.
    pub fn set_debug(&mut self, on: bool) {
        self.debug = on;
    }

    /// Open a session against a specific reader name.
    pub fn open_named(reader_name: &str) -> Result<Self, TransportError> {
        let ctx = Context::establish(Scope::User).map_err(TransportError::PcscUnavailable)?;
        let cstring = std::ffi::CString::new(reader_name)
            .map_err(|_| TransportError::MalformedResponse("reader name contained NUL"))?;
        let card = ctx.connect(&cstring, ShareMode::Shared, Protocols::ANY)?;
        Ok(Self {
            card,
            authenticated: false,
            debug: false,
        })
    }

    /// Transmit a built command, draining any T=0 `61xx` GET RESPONSE
    /// continuation (contact readers), and return the response payload without
    /// the SW1/SW2 trailer. Errors on any status word other than `9000`.
    fn transmit(&mut self, cmd: &Command) -> Result<Vec<u8>, TransportError> {
        if self.debug {
            eprintln!("> {:>16} >> {}", cmd.label, hex(&cmd.apdu));
        }
        let (data, sw1, sw2) = self.exchange_full(&cmd.apdu, cmd.label)?;
        if self.debug {
            eprintln!("< {:>16} << ...{:02X}{:02X}", cmd.label, sw1, sw2);
        }
        // The challenge answer replies with a bare 9000 (no data) on success and
        // 6983 when the device key is locked; surface the latter clearly.
        if (sw1, sw2) == (0x69, 0x83) {
            return Err(TransportError::Apdu {
                label: cmd.label,
                sw1,
                sw2,
            });
        }
        if (sw1, sw2) != (0x90, 0x00) {
            return Err(TransportError::Apdu {
                label: cmd.label,
                sw1,
                sw2,
            });
        }
        Ok(data)
    }

    /// One APDU exchange plus T=0 `61xx`/`6Cxx` continuation handling, returning
    /// `(data, sw1, sw2)`.
    fn exchange_full(
        &mut self,
        apdu: &[u8],
        label: &'static str,
    ) -> Result<(Vec<u8>, u8, u8), TransportError> {
        let (mut data, mut sw1, mut sw2) = self.exchange_once(apdu, label)?;
        loop {
            match (sw1, sw2) {
                (0x90, 0x00) => break,
                (0x61, n) => {
                    let get = [0x00u8, 0xC0, 0x00, 0x00, n];
                    let (more, s1, s2) = self.exchange_once(&get, label)?;
                    data.extend_from_slice(&more);
                    sw1 = s1;
                    sw2 = s2;
                }
                (0x6C, n) => {
                    let mut retry = apdu.to_vec();
                    if let Some(last) = retry.last_mut() {
                        *last = n;
                    }
                    let (again, s1, s2) = self.exchange_once(&retry, label)?;
                    data = again;
                    sw1 = s1;
                    sw2 = s2;
                }
                _ => break,
            }
        }
        Ok((data, sw1, sw2))
    }

    fn exchange_once(
        &mut self,
        apdu: &[u8],
        label: &'static str,
    ) -> Result<(Vec<u8>, u8, u8), TransportError> {
        let mut buf = [0u8; 2048];
        let response = self.card.transmit(apdu, &mut buf)?;
        if response.len() < 2 {
            return Err(TransportError::ShortResponse {
                label,
                got: response.len(),
                expected_min: 2,
            });
        }
        let (data, sw) = response.split_at(response.len() - 2);
        Ok((data.to_vec(), sw[0], sw[1]))
    }

    /// Read the serial and on-device UTC time. No authentication required.
    pub fn read_info(&mut self) -> Result<prog::Info, TransportError> {
        let data = self.transmit(&prog::get_info())?;
        prog::parse_info(&data).map_err(|_| TransportError::MalformedResponse("get info"))
    }

    /// Run the challenge-response handshake with the token's fixed device key.
    pub fn authenticate(&mut self) -> Result<(), TransportError> {
        let challenge = self.transmit(&prog::get_challenge())?;
        if challenge.len() < 8 {
            return Err(TransportError::ShortResponse {
                label: "get challenge",
                got: challenge.len(),
                expected_min: 8,
            });
        }
        let mut chal = [0u8; 8];
        chal.copy_from_slice(&challenge[..8]);
        self.transmit(&prog::answer_challenge(&chal))?;
        self.authenticated = true;
        Ok(())
    }

    /// `true` once `authenticate` has succeeded.
    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    fn require_auth(&self) -> Result<(), TransportError> {
        if self.authenticated {
            Ok(())
        } else {
            Err(TransportError::Apdu {
                label: "secure command",
                sw1: 0x69,
                sw2: 0x82,
            })
        }
    }

    /// Program the OTP seed (raw key bytes, 1..=63). Requires prior `authenticate`.
    pub fn set_seed(&mut self, seed: &[u8]) -> Result<(), TransportError> {
        self.require_auth()?;
        let cmd =
            prog::set_seed(seed).map_err(|_| TransportError::MalformedResponse("seed length"))?;
        self.transmit(&cmd)?;
        Ok(())
    }

    /// Program the device configuration. Requires prior `authenticate`.
    pub fn set_config(&mut self, cfg: &prog::Config) -> Result<(), TransportError> {
        self.require_auth()?;
        self.transmit(&prog::set_config(cfg))?;
        Ok(())
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02X}"));
    }
    s
}
