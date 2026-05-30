//! OATH (TOTP/HOTP) over PC/SC.
//!
//! Drives the Yubico/Trussed OATH applet using the pure-byte builders and
//! parsers in [`molto2_oath`]. The applet is a CCID/APDU smartcard applet on
//! YubiKeys *and* on Trussed devices (Solo 2, Nitrokey 3) — both answer the same
//! protocol over USB PC/SC (verified on hardware) — so one session type targets
//! all of them, reusing this crate's existing PC/SC plumbing.
//!
//! This layer adds what the byte layer deliberately left out: the actual card
//! transmit, the `61xx` / `SEND_REMAINING` reassembly loop, and reader
//! selection. Password-protected OATH (`SET_CODE` / `VALIDATE`) is still TODO —
//! the Trussed variant diverges from Yubico there.

use crate::{hex_dump, TransportError};
use molto2_oath as oath;
use pcsc::{Card, Context, Protocols, Scope, ShareMode};

/// An open OATH applet session on one PC/SC reader.
pub struct OathSession {
    card: Card,
    debug: bool,
    /// What the SELECT response told us — notably the device id (PBKDF2 salt) and
    /// whether a password is set (a CHALLENGE was returned). Refreshed on SELECT.
    select_info: oath::SelectInfo,
}

impl OathSession {
    /// Connect to `reader_name` and SELECT the OATH applet.
    pub fn open(reader_name: &str) -> Result<Self, TransportError> {
        let ctx = Context::establish(Scope::User).map_err(TransportError::PcscUnavailable)?;
        let cstr = std::ffi::CString::new(reader_name)
            .map_err(|_| TransportError::MalformedResponse("reader name contained NUL"))?;
        let card = ctx.connect(&cstr, ShareMode::Shared, Protocols::ANY)?;
        let mut session = Self {
            card,
            debug: false,
            select_info: oath::SelectInfo {
                version: Vec::new(),
                device_id: Vec::new(),
                challenge: None,
            },
        };
        session.select()?;
        Ok(session)
    }

    /// True when the applet is password-protected: data commands will be refused
    /// until [`unlock`](Self::unlock) succeeds.
    pub fn password_required(&self) -> bool {
        self.select_info.password_required()
    }

    /// Authenticate against a password-protected applet (YubiKey OATH). Derives
    /// the access key from the password and the device id, answers the card's
    /// SELECT challenge with VALIDATE, and verifies the card's mutual-auth reply
    /// so a wrong password (or a spoofed card) is rejected. No-op if no password
    /// is set.
    pub fn unlock(&mut self, password: &str) -> Result<(), TransportError> {
        let Some(card_challenge) = self.select_info.challenge.clone() else {
            return Ok(()); // not protected
        };
        let key = oath::derive_access_key(password, &self.select_info.device_id);
        let host_challenge = random_challenge();
        let (data, sw) =
            self.transmit_full(&oath::validate(&key, &card_challenge, &host_challenge))?;
        if sw == 0x6A80 || sw == 0x6982 {
            // Wrong response / security status not satisfied → wrong password.
            return Err(TransportError::OathPasswordRejected);
        }
        ok_or_apdu("oath validate", sw)?;
        let ok = oath::verify_validate(&key, &host_challenge, &data)
            .map_err(TransportError::OathParse)?;
        if !ok {
            return Err(TransportError::MalformedResponse(
                "OATH card failed mutual authentication",
            ));
        }
        Ok(())
    }

    /// Set (or replace) the applet password. Requires the session to be unlocked
    /// already if a password is currently set.
    pub fn set_password(&mut self, password: &str) -> Result<(), TransportError> {
        let key = oath::derive_access_key(password, &self.select_info.device_id);
        let challenge = random_challenge();
        let (_, sw) = self.transmit_full(&oath::set_code(&key, &challenge))?;
        ok_or_apdu("oath set code", sw)?;
        // A password is now set; reflect that locally.
        self.select_info.challenge = Some(challenge.to_vec());
        Ok(())
    }

    /// Remove the applet password. Requires the session to be unlocked already.
    pub fn clear_password(&mut self) -> Result<(), TransportError> {
        let (_, sw) = self.transmit_full(&oath::clear_code())?;
        ok_or_apdu("oath clear code", sw)?;
        self.select_info.challenge = None;
        Ok(())
    }

    /// Enable per-APDU stderr tracing.
    pub fn set_debug(&mut self, on: bool) {
        self.debug = on;
    }

    /// Names of connected readers whose OATH applet answers `SELECT` with `9000`.
    /// Lets a front-end auto-pick a lone OATH key, or list choices when several
    /// are present (never guessing — same posture as the FIDO picker).
    pub fn list_oath_readers() -> Result<Vec<String>, TransportError> {
        let ctx = Context::establish(Scope::User).map_err(TransportError::PcscUnavailable)?;
        let mut buf = [0u8; 4096];
        let names: Vec<std::ffi::CString> = ctx
            .list_readers(&mut buf)
            .map_err(TransportError::PcscUnavailable)?
            .map(|r| r.to_owned())
            .collect();
        let mut out = Vec::new();
        for name in names {
            if let Ok(card) = ctx.connect(name.as_c_str(), ShareMode::Shared, Protocols::ANY) {
                let mut session = OathSession {
                    card,
                    debug: false,
                    select_info: oath::SelectInfo {
                        version: Vec::new(),
                        device_id: Vec::new(),
                        challenge: None,
                    },
                };
                if session.select().is_ok() {
                    out.push(name.to_string_lossy().into_owned());
                }
            }
        }
        Ok(out)
    }

    fn select(&mut self) -> Result<(), TransportError> {
        let (data, sw) = self.transmit_full(&oath::select())?;
        ok_or_apdu("select oath applet", sw)?;
        self.select_info = oath::parse_select(&data).map_err(TransportError::OathParse)?;
        Ok(())
    }

    /// List provisioned credential names (with their type/algorithm).
    pub fn list(&mut self) -> Result<Vec<oath::CredentialInfo>, TransportError> {
        let (data, sw) = self.transmit_full(&oath::list())?;
        ok_or_apdu("oath list", sw)?;
        oath::parse_list(&data).map_err(TransportError::OathParse)
    }

    /// Compute the current TOTP for `name` at `unix_time` with the given `period`
    /// (seconds). A credential that requires touch will block until the user
    /// touches the key (the card returns the code once touched).
    pub fn calculate_totp(
        &mut self,
        name: &str,
        unix_time: u64,
        period: u32,
    ) -> Result<oath::OtpCode, TransportError> {
        let challenge = oath::totp_challenge(unix_time, period);
        let (data, sw) = self.transmit_full(&oath::calculate(name, &challenge))?;
        ok_or_apdu("oath calculate", sw)?;
        oath::parse_calculate(&data).map_err(TransportError::OathParse)
    }

    /// Provision (add) a credential.
    pub fn put(&mut self, params: &oath::PutParams<'_>) -> Result<(), TransportError> {
        let (_, sw) = self.transmit_full(&oath::put(params))?;
        ok_or_apdu("oath put", sw)
    }

    /// Remove a credential by name.
    pub fn delete(&mut self, name: &str) -> Result<(), TransportError> {
        let (_, sw) = self.transmit_full(&oath::delete(name))?;
        ok_or_apdu("oath delete", sw)
    }

    /// Transmit one APDU and reassemble a response the card splits across `61xx`
    /// continuations (`SEND_REMAINING`), returning `(payload, sw)`.
    fn transmit_full(&mut self, apdu: &[u8]) -> Result<(Vec<u8>, u16), TransportError> {
        let mut acc = Vec::new();
        let mut to_send = apdu.to_vec();
        loop {
            if self.debug {
                eprintln!("> {:>14} >> {}", "oath", hex_dump(&to_send));
            }
            let mut buf = [0u8; 4096];
            let resp = self.card.transmit(&to_send, &mut buf)?;
            if self.debug {
                eprintln!("< {:>14} << {}", "oath", hex_dump(resp));
            }
            if resp.len() < 2 {
                return Err(TransportError::ShortResponse {
                    label: "oath apdu",
                    got: resp.len(),
                    expected_min: 2,
                });
            }
            let (data, sw) = resp.split_at(resp.len() - 2);
            acc.extend_from_slice(data);
            if sw[0] == oath::SW_MORE_DATA {
                // More data pending: pull the next chunk and keep accumulating.
                to_send = oath::send_remaining();
                continue;
            }
            return Ok((acc, u16::from_be_bytes([sw[0], sw[1]])));
        }
    }
}

/// An 8-byte random host challenge for OATH mutual authentication.
///
/// Reads `/dev/urandom` directly — this crate is already Linux/PC-SC-bound, so
/// that avoids pulling in an RNG dependency. Falls back to a time-seeded value
/// only if the device can't be read (a challenge needs to be unpredictable, not
/// secret; the security of the handshake rests on the HMAC key, not this value).
fn random_challenge() -> [u8; 8] {
    use std::io::Read;
    let mut buf = [0u8; 8];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .is_ok()
    {
        return buf;
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    nanos.to_le_bytes()
}

/// Map an OATH status word to success or a labelled APDU error.
fn ok_or_apdu(label: &'static str, sw: u16) -> Result<(), TransportError> {
    if sw == oath::SW_OK {
        Ok(())
    } else {
        Err(TransportError::Apdu {
            label,
            sw1: (sw >> 8) as u8,
            sw2: sw as u8,
        })
    }
}
