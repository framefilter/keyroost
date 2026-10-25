//! OATH (TOTP/HOTP) over PC/SC.
//!
//! Drives the Yubico/Trussed OATH applet using the pure-byte builders and
//! parsers in [`keyroost_oath`]. The applet is a CCID/APDU smartcard applet on
//! YubiKeys *and* on Trussed devices (Solo 2, Nitrokey 3) — both answer the same
//! protocol over USB PC/SC (verified on hardware) — so one session type targets
//! all of them, reusing this crate's existing PC/SC plumbing.
//!
//! This layer adds what the byte layer deliberately left out: the actual card
//! transmit, the `61xx` / `SEND_REMAINING` reassembly loop, and reader
//! selection. Password-protected OATH (Yubico `SET_CODE` / `VALIDATE`) is
//! supported — [`unlock`](OathSession::unlock), [`set_password`](OathSession::set_password),
//! and [`clear_password`](OathSession::clear_password) — though Trussed devices
//! (Solo 2 / Nitrokey 3) omit that handshake.

use crate::recover::{self, FirstContact};
use crate::TransportError;
use keyroost_oath as oath;
use pcsc::{Card, Protocols, ShareMode};
use zeroize::Zeroizing;

/// "Security status not satisfied": no VALIDATE yet, or (Nitrokey) no touch.
const SW_SECURITY_NOT_SATISFIED: u16 = 0x6982;

/// An open OATH applet session on one PC/SC reader.
pub struct OathSession {
    card: Card,
    debug: bool,
    /// What the SELECT response told us — notably the device id (PBKDF2 salt) and
    /// whether a password is set (a CHALLENGE was returned). Refreshed on SELECT.
    select_info: oath::SelectInfo,
    /// The access key from the last successful [`unlock`](Self::unlock) (or
    /// [`set_password`](Self::set_password)), kept so
    /// [`reauthenticate`](Self::reauthenticate) can VALIDATE again without
    /// asking for the password. Wiped when the session drops.
    access_key: Option<Zeroizing<[u8; oath::ACCESS_KEY_LEN]>>,
}

impl OathSession {
    /// Connect to `reader_name` and SELECT the OATH applet.
    ///
    /// The session holds a PC/SC transaction for its whole life, so no other
    /// program (a browser scanning for smart-card certificates, say) can put
    /// a command between two of its own. One that SELECTs another applet
    /// would send the session's next commands to that applet; a Nitrokey 3
    /// then answered `6A81` to every CALCULATE until a re-SELECT.
    pub fn open(reader_name: &str) -> Result<Self, TransportError> {
        Self::open_traced(reader_name, false)
    }

    /// [`Self::open`] with per-APDU stderr tracing on from the start, so the
    /// SELECT it sends is traced too.
    ///
    /// A card found just reset or briefly gone while connecting, beginning
    /// the transaction or answering the SELECT is waited for and opened once
    /// more (see `crate::recover`).
    pub fn open_traced(reader_name: &str, debug: bool) -> Result<Self, TransportError> {
        let cstr = std::ffi::CString::new(reader_name)
            .map_err(|_| TransportError::MalformedResponse("reader name contained NUL"))?;
        let mut contact = FirstContact::new(reader_name, debug, "oath");
        loop {
            let ctx = crate::establish_context().map_err(TransportError::PcscUnavailable)?;
            let mut card = match ctx.connect(&cstr, ShareMode::Shared, Protocols::ANY) {
                Ok(card) => card,
                Err(e) => {
                    contact.retry_or_fail(e.into())?;
                    continue;
                }
            };
            // `pcsc::Transaction` borrows the card, so it can't live in the
            // session next to it. Forgetting the guard leaves the transaction
            // open; disconnecting (the card's drop) ends it, as PC/SC specifies.
            if let Err(e) = card.transaction().map(std::mem::forget) {
                recover::release(card);
                contact.retry_or_fail(e.into())?;
                continue;
            }
            let mut session = Self {
                card,
                debug,
                select_info: oath::SelectInfo::default(),
                access_key: None,
            };
            match session.select() {
                Ok(()) => {
                    contact.opened();
                    return Ok(session);
                }
                Err(e) => {
                    recover::release(session.card);
                    contact.retry_or_fail(e)?;
                }
            }
        }
    }

    /// The applet version from SELECT (YubiKey: firmware), when it is 3 bytes.
    pub fn version(&self) -> Option<(u8, u8, u8)> {
        version_of(&self.select_info.version)
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
        if self.select_info.challenge.is_none() {
            return Ok(()); // not protected
        }
        let key = Zeroizing::new(oath::derive_access_key(
            password,
            &self.select_info.device_id,
        ));
        self.validate_with(&key)?;
        self.access_key = Some(key);
        Ok(())
    }

    /// Re-SELECT and VALIDATE with the access key kept from the last
    /// successful [`unlock`](Self::unlock). Returns `Ok(false)`, sending
    /// nothing, when no key is kept (no password was given), and `Ok(true)`
    /// once the applet is unlocked again. For applets that clear
    /// authorization after each command — a Solo 2 on firmware 2.3.196 does,
    /// answering the next write with `6985` — so a refused command can be
    /// retried without asking for the password again.
    pub fn reauthenticate(&mut self) -> Result<bool, TransportError> {
        let Some(key) = self.access_key.clone() else {
            return Ok(false);
        };
        self.select()?;
        if self.select_info.challenge.is_none() {
            return Ok(true); // the password is gone; nothing to answer
        }
        self.validate_with(&key)?;
        Ok(true)
    }

    /// Answer the current SELECT challenge with VALIDATE under `key` and check
    /// the card's mutual-auth reply.
    fn validate_with(&mut self, key: &[u8; oath::ACCESS_KEY_LEN]) -> Result<(), TransportError> {
        let Some(card_challenge) = self.select_info.challenge.clone() else {
            return Ok(());
        };
        let host_challenge = random_challenge()?;
        let apdu = Zeroizing::new(oath::validate(&key[..], &card_challenge, &host_challenge));
        let (data, sw) = self.transmit_full(&apdu)?;
        if sw == 0x6A80 || sw == 0x6982 {
            // Wrong response / security status not satisfied → wrong password.
            return Err(TransportError::OathPasswordRejected);
        }
        ok_or_apdu("oath validate", sw)?;
        let ok = oath::verify_validate(&key[..], &host_challenge, &data)
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
        let key = Zeroizing::new(oath::derive_access_key(
            password,
            &self.select_info.device_id,
        ));
        let challenge = random_challenge()?;
        let apdu = Zeroizing::new(oath::set_code(&key[..], &challenge));
        let (_, sw) = self.transmit_full(&apdu)?;
        ok_or_apdu("oath set code", sw)?;
        // A password is now set; reflect that locally.
        self.select_info.challenge = Some(challenge.to_vec());
        self.access_key = Some(key);
        Ok(())
    }

    /// Remove the applet password. Requires the session to be unlocked already.
    pub fn clear_password(&mut self) -> Result<(), TransportError> {
        let (_, sw) = self.transmit_full(&oath::clear_code())?;
        ok_or_apdu("oath clear code", sw)?;
        self.select_info.challenge = None;
        self.access_key = None;
        Ok(())
    }

    /// Factory-reset the OATH applet: wipe every credential and clear the
    /// access password. Deliberately needs NO prior unlock — the applet's
    /// `RESET` (`00 04 DE AD`) is the documented recovery for a forgotten
    /// password, so gating it on validation would defeat its purpose (same
    /// never-hide-the-recovery-action principle as the FIDO reset). The
    /// destructive confirmation is the caller's job.
    pub fn factory_reset(&mut self) -> Result<(), TransportError> {
        let (_, sw) = self.transmit_full(&oath::reset())?;
        self.write_answer("oath reset", "reset its Authenticator app", sw)?;
        // The wipe cleared any password; reflect that locally so a follow-up
        // command in this session doesn't try to validate against stale state.
        self.select_info.challenge = None;
        self.access_key = None;
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
        let ctx = crate::establish_context().map_err(TransportError::PcscUnavailable)?;
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
                    select_info: oath::SelectInfo::default(),
                    access_key: None,
                };
                if session.select().is_ok() {
                    out.push(name.to_string_lossy().into_owned());
                }
                // Release without resetting (pcsc's `Drop` hard-codes
                // ResetCard) — probing must not disturb cards other sessions
                // hold open.
                let _ = session.card.disconnect(pcsc::Disposition::LeaveCard);
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
    ///
    /// `Listing::skipped` is non-zero when the card holds entries this crate
    /// could not decode; callers should surface that — the listing is partial
    /// and destructive operations would also destroy the invisible entries.
    pub fn list(&mut self) -> Result<oath::Listing, TransportError> {
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
        // `name` may come straight from the card's own LIST response; an
        // overlong one must surface as an error, not a panic (KEY-018).
        let apdu =
            oath::calculate(name, &challenge).map_err(|_| TransportError::OathCredentialTooLong)?;
        let (data, sw) = self.transmit_full(&apdu)?;
        ok_or_apdu("oath calculate", sw)?;
        oath::parse_calculate(&data).map_err(TransportError::OathParse)
    }

    /// Compute every 30-second TOTP at `unix_time` in one `CALCULATE ALL`.
    /// The card flags touch-required and HOTP credentials instead of
    /// computing them, so this never waits for a touch. A credential with a
    /// different period (a `period/` name) comes back computed for the
    /// 30-second window, which is wrong for it: compute those one by one with
    /// [`Self::calculate_totp`].
    pub fn calculate_all(&mut self, unix_time: u64) -> Result<oath::CalculateAll, TransportError> {
        let challenge = oath::totp_challenge(unix_time, 30);
        let (data, sw) = self.transmit_full(&oath::calculate_all(&challenge))?;
        ok_or_apdu("oath calculate all", sw)?;
        oath::parse_calculate_all(&data).map_err(TransportError::OathParse)
    }

    /// Compute the next HOTP for `name`. The card advances its own internal
    /// counter, so no challenge is supplied. A touch-required credential blocks
    /// until the user touches the key.
    pub fn calculate_hotp(&mut self, name: &str) -> Result<oath::OtpCode, TransportError> {
        let apdu = oath::calculate_hotp(name).map_err(|_| TransportError::OathCredentialTooLong)?;
        let (data, sw) = self.transmit_full(&apdu)?;
        ok_or_apdu("oath calculate (hotp)", sw)?;
        oath::parse_calculate(&data).map_err(TransportError::OathParse)
    }

    /// Provision (add) a credential.
    pub fn put(&mut self, params: &oath::PutParams<'_>) -> Result<(), TransportError> {
        let sw = self.put_status(params)?;
        self.write_answer("oath put", "save the account", sw)
    }

    /// PUT and return the raw status word, for callers that read the key's
    /// answer themselves (bulk import: exists, full, needs the password).
    pub fn put_status(&mut self, params: &oath::PutParams<'_>) -> Result<u16, TransportError> {
        // An over-long name/secret (e.g. from an imported otpauth:// URI)
        // surfaces as a typed error from the fallible builder.
        // The PUT body carries the raw TOTP/HOTP seed — wipe it after transmit.
        let apdu =
            Zeroizing::new(oath::put(params).map_err(|_| TransportError::OathCredentialTooLong)?);
        let (_, sw) = self.transmit_full(&apdu)?;
        Ok(sw)
    }

    /// Remove a credential by name.
    pub fn delete(&mut self, name: &str) -> Result<(), TransportError> {
        let sw = self.delete_status(name)?;
        self.write_answer("oath delete", "delete the account", sw)
    }

    /// A PUT, DELETE or RESET answer. `6982` from an applet with no password
    /// is the key waiting for a touch it didn't get ([`TransportError::OathNoTouch`]);
    /// with a password it still means "unlock first".
    fn write_answer(
        &self,
        label: &'static str,
        action: &'static str,
        sw: u16,
    ) -> Result<(), TransportError> {
        if sw == SW_SECURITY_NOT_SATISFIED && !self.password_required() {
            return Err(TransportError::OathNoTouch { action });
        }
        ok_or_apdu(label, sw)
    }

    /// DELETE and return the raw status word.
    pub fn delete_status(&mut self, name: &str) -> Result<u16, TransportError> {
        let apdu = oath::delete(name).map_err(|_| TransportError::OathCredentialTooLong)?;
        let (_, sw) = self.transmit_full(&apdu)?;
        Ok(sw)
    }

    /// Transmit one APDU and reassemble a response the card splits across `61xx`
    /// continuations (`SEND_REMAINING`, or `GET RESPONSE` where the SELECT
    /// answer asks for it: [`oath::SelectInfo::more_data`]), returning
    /// `(payload, sw)`.
    fn transmit_full(&mut self, apdu: &[u8]) -> Result<(Vec<u8>, u16), TransportError> {
        let (cmd_sensitive, resp_sensitive) = trace_sensitivity(apdu);
        // Until SELECT has answered, SEND_REMAINING (the Yubico applet's).
        let io = crate::AppletIo {
            label: "oath",
            more_data_sw: oath::SW_MORE_DATA,
            get_response: match self.select_info.more_data() {
                oath::MoreData::SendRemaining => oath::send_remaining,
                oath::MoreData::GetResponse => oath::get_response,
            },
            describe: None,
        };
        crate::transmit_applet(
            &self.card,
            self.debug,
            &io,
            apdu,
            cmd_sensitive,
            resp_sensitive,
        )
    }
}

/// An 8-byte random host challenge for OATH mutual authentication, from the OS
/// RNG. Fails closed — a predictable challenge would let a recorded card
/// response be replayed, defeating the card-side half of mutual auth.
fn random_challenge() -> Result<[u8; 8], TransportError> {
    let mut buf = [0u8; 8];
    getrandom::getrandom(&mut buf).map_err(|_| TransportError::HostRngFailed)?;
    Ok(buf)
}

/// The SELECT version as `(major, minor, patch)`, only when it is exactly
/// three bytes.
fn version_of(v: &[u8]) -> Option<(u8, u8, u8)> {
    match v {
        [a, b, c] => Some((*a, *b, *c)),
        _ => None,
    }
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

/// Which halves of an OATH exchange `--debug` must hide: `(command body,
/// response body)`. Traces get pasted into public issues, so anything that
/// names an account (it tells which services someone uses), carries a code,
/// or carries a secret is hidden; the status word always stays.
///
/// Commands: PUT (01) holds the seed, SET CODE (03) the password-equivalent
/// access key, VALIDATE (A3) HMACs over known challenges (an offline
/// brute-force oracle for the password); DELETE (02), RENAME (05) and
/// CALCULATE (A2) name an account. Responses: LIST (A1) and CALCULATE ALL
/// (A4 with P1 = 0) list account names, CALCULATE ALL and CALCULATE carry
/// codes, VALIDATE the card's HMAC. SELECT shares INS A4 (P1 = 04); its
/// answer (version, salt, challenge) stays visible for bug reports.
fn trace_sensitivity(apdu: &[u8]) -> (bool, bool) {
    let ins = apdu.get(1).copied();
    let select = ins == Some(0xA4) && apdu.get(2) == Some(&0x04);
    let cmd = matches!(ins, Some(0x01 | 0x02 | 0x03 | 0x05 | 0xA2 | 0xA3));
    let resp = !select && matches!(ins, Some(0xA1..=0xA4));
    (cmd, resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_parses_three_bytes_only() {
        assert_eq!(version_of(&[5, 7, 1]), Some((5, 7, 1)));
        assert_eq!(version_of(&[]), None);
        assert_eq!(version_of(&[5, 7]), None);
        assert_eq!(version_of(&[5, 7, 1, 0]), None);
    }

    /// `--debug` traces are pasted into public issues: whatever names an
    /// account (which services someone uses) or carries a code or secret is
    /// hidden, in both directions. Status words stay visible (the dump keeps
    /// them), and so does the SELECT exchange, whose version is what a bug
    /// report needs. SELECT and CALCULATE ALL share INS 0xA4; P1 tells them
    /// apart.
    #[test]
    fn traces_hide_account_names_codes_and_secrets() {
        let ch = [0u8; 8];
        let key = [0u8; 16];
        let params = oath::PutParams {
            name: "GitHub:alice",
            secret: &[1u8; 20],
            oath_type: oath::OathType::Totp,
            algorithm: oath::Algorithm::Sha1,
            digits: 6,
            require_touch: false,
            imf: 0,
        };
        let cases: [(&str, Vec<u8>, bool, bool); 11] = [
            ("select", oath::select(), false, false),
            ("reset", oath::reset(), false, false),
            ("list", oath::list(), false, true),
            (
                "calculate",
                oath::calculate("GitHub:alice", &ch).unwrap(),
                true,
                true,
            ),
            (
                "calculate hotp",
                oath::calculate_hotp("GitHub:alice").unwrap(),
                true,
                true,
            ),
            ("calculate all", oath::calculate_all(&ch), false, true),
            ("delete", oath::delete("GitHub:alice").unwrap(), true, false),
            (
                "rename",
                oath::rename("GitHub:alice", "GitHub:bob").unwrap(),
                true,
                false,
            ),
            ("put", oath::put(&params).unwrap(), true, false),
            ("set code", oath::set_code(&key, &ch), true, false),
            ("validate", oath::validate(&key, &ch, &ch), true, true),
        ];
        for (what, apdu, cmd, resp) in cases {
            assert_eq!(trace_sensitivity(&apdu), (cmd, resp), "{what}");
        }
    }
}
