//! Feitian OTP (TOTP/HOTP) applet, over PC/SC or the key's FIDO HID
//! interface.
//!
//! Drives the applet on Feitian FIDO keys with the pure-byte builders and
//! parsers in [`keyroost_feitianotp`]. It sits next to the Yubico/Trussed
//! OATH applet's session (`oath.rs`) and reuses the same PC/SC plumbing; the
//! protocol is its own (`docs/PROTOCOL-feitianotp.md`).
//!
//! Not here, because nothing has run them on hardware: the slot access
//! codes. A slot that answers `6982` is reported, never unlocked.

use crate::recover::{self, FirstContact};
use crate::TransportError;
use keyroost_ctap::hid::{CtapHidDevice, CTAPHID_MSG};
use keyroost_feitianotp as fotp;
use pcsc::Card;
use zeroize::Zeroizing;

/// How a session reaches the applet.
enum Link {
    /// The key's smart-card interface (CCID, or NFC) through a PC/SC reader.
    Card(Card),
    /// The key's FIDO HID interface: each APDU rides in a `CTAPHID_MSG`, as
    /// Feitian's client does when there is no smart-card interface to use.
    Hid(HidLink),
}

/// The FIDO HID interface while this session has the OTP applet selected on
/// it. A `CTAPHID_MSG` goes to whichever applet was selected last: with the
/// OTP applet selected, the key answers a U2F command `6D00`. So when the
/// session ends, the FIDO applet is selected again, the way the interface
/// was found.
struct HidLink(Box<CtapHidDevice>);

/// SELECT of the FIDO applet (`A0 00 00 06 47 2F 00 01`).
const SELECT_FIDO: [u8; 13] = [
    0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01,
];

/// How long one exchange over HID may take. A command the key acts on once
/// touched is answered `6984` only after the key has waited for the touch,
/// 3.2 or 5.2 seconds on the two models timed, which is longer than the CTAP
/// layer's own default.
const HID_EXCHANGE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

impl Drop for HidLink {
    fn drop(&mut self) {
        // Best effort: nothing to do about a key that was unplugged.
        let _ = self.0.transact(CTAPHID_MSG, &SELECT_FIDO);
    }
}

/// An open Feitian OTP applet session on one key.
pub struct FeitianOtpSession {
    link: Link,
    debug: bool,
    /// What the SELECT answer said: version and which slots have an access
    /// code.
    select_info: fotp::SelectInfo,
}

/// The credentials of every slot, read in one go by
/// [`FeitianOtpSession::list`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeitianOtpListing {
    /// Slot 1's entries, then slot 2's, then the default slot's.
    pub credentials: Vec<fotp::Credential>,
    /// Entries the slots hold that are not shown (see
    /// [`fotp::Listing::skipped`]). Non-zero means the listing is partial.
    pub skipped: usize,
    /// Keyboard slots that did not answer `9000`, with what they answered.
    /// Their credentials, if any, are not in the listing.
    pub unread: Vec<(fotp::Slot, u16)>,
    /// The key wanted the four-byte LIST ([`fotp::list_legacy`]). Its
    /// entries are filed under the default slot and the keyboard slots were
    /// not asked. No measured key takes this path.
    pub legacy: bool,
}

impl FeitianOtpSession {
    /// Connect to `reader_name` and SELECT the Feitian OTP applet.
    ///
    /// Like [`crate::OathSession`], the session holds a PC/SC transaction for
    /// its whole life, so no other program can put a command (a SELECT of
    /// another applet, say) between two of its own.
    pub fn open(reader_name: &str) -> Result<Self, TransportError> {
        Self::open_traced(reader_name, false)
    }

    /// [`Self::open`] with per-APDU stderr tracing on from the start, so the
    /// SELECT it sends is traced too.
    pub fn open_traced(reader_name: &str, debug: bool) -> Result<Self, TransportError> {
        let cstr = std::ffi::CString::new(reader_name)
            .map_err(|_| TransportError::MalformedResponse("reader name contained NUL"))?;
        let mut contact = FirstContact::new(reader_name, debug, "feitian");
        loop {
            let ctx = crate::establish_context().map_err(TransportError::PcscUnavailable)?;
            let mut card = match crate::connect_shared(&ctx, &cstr) {
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
                link: Link::Card(card),
                debug,
                select_info: fotp::SelectInfo::default(),
            };
            match session.select() {
                Ok(()) => {
                    contact.opened();
                    return Ok(session);
                }
                Err(e) => {
                    if let Link::Card(card) = session.link {
                        recover::release(card);
                    }
                    contact.retry_or_fail(e)?;
                }
            }
        }
    }

    /// Open the applet through the key's FIDO HID interface at `path`, for a
    /// key with no smart-card interface this computer can use.
    ///
    /// Each APDU is sent as it is in a `CTAPHID_MSG`. There is no
    /// transaction here as there is over PC/SC: another program talking to
    /// the same interface can put a command of its own between two of this
    /// session's. On Windows only an administrator can open this interface.
    pub fn open_hid(path: &std::path::Path) -> Result<Self, TransportError> {
        let (mut hid, _) = CtapHidDevice::open(path).map_err(hid_error)?;
        hid.set_timeout(HID_EXCHANGE_TIMEOUT);
        let mut session = Self {
            link: Link::Hid(HidLink(Box::new(hid))),
            debug: false,
            select_info: fotp::SelectInfo::default(),
        };
        session.select()?;
        Ok(session)
    }

    /// Whether this session runs over the FIDO HID interface rather than a
    /// PC/SC reader.
    pub fn over_hid(&self) -> bool {
        matches!(self.link, Link::Hid(_))
    }

    /// The applet version from SELECT, when it is three bytes.
    pub fn version(&self) -> Option<(u8, u8, u8)> {
        self.select_info.version_triple()
    }

    /// Whether SELECT marked `slot` as having an access code; `None` when
    /// the answer did not say.
    pub fn access_code_set(&self, slot: fotp::Slot) -> Option<bool> {
        self.select_info.access_code_set(slot)
    }

    /// Enable per-APDU stderr tracing.
    pub fn set_debug(&mut self, on: bool) {
        self.debug = on;
    }

    /// Names of connected readers whose card answers a SELECT of the Feitian
    /// OTP applet with `9000`.
    pub fn list_readers() -> Result<Vec<String>, TransportError> {
        let ctx = crate::establish_context().map_err(TransportError::PcscUnavailable)?;
        let mut buf = [0u8; 4096];
        let names: Vec<std::ffi::CString> = ctx
            .list_readers(&mut buf)
            .map_err(TransportError::PcscUnavailable)?
            .map(|r| r.to_owned())
            .collect();
        let mut out = Vec::new();
        for name in names {
            if let Ok(card) = crate::connect_shared(&ctx, name.as_c_str()) {
                let mut session = FeitianOtpSession {
                    link: Link::Card(card),
                    debug: false,
                    select_info: fotp::SelectInfo::default(),
                };
                if session.select().is_ok() {
                    out.push(name.to_string_lossy().into_owned());
                }
                // Release without resetting (pcsc's `Drop` hard-codes
                // ResetCard): probing must not disturb cards other sessions
                // hold open.
                if let Link::Card(card) = session.link {
                    let _ = card.disconnect(pcsc::Disposition::LeaveCard);
                }
            }
        }
        Ok(out)
    }

    fn select(&mut self) -> Result<(), TransportError> {
        let (data, sw) = self.transmit_full(&fotp::select())?;
        ok_or_apdu("select feitian otp applet", sw)?;
        self.select_info = fotp::parse_select(&data).map_err(TransportError::FeitianOtpParse)?;
        Ok(())
    }

    /// List every slot's credentials.
    ///
    /// The default slot is where Feitian's apps store codes, and its answer
    /// decides the outcome: anything but `9000` is an error. The two keyboard
    /// slots are read after it; one that does not answer `9000` goes to
    /// [`FeitianOtpListing::unread`] and does not fail the listing.
    pub fn list(&mut self) -> Result<FeitianOtpListing, TransportError> {
        list_all(|apdu| self.transmit_full(apdu))
    }

    /// Compute the current TOTP for the credential stored as `name` in
    /// `slot`, at `unix_time` with the given `period` (seconds). The key
    /// computes once it is touched; with no touch it gives up after a few
    /// seconds ([`TransportError::FeitianOtpNoTouch`]).
    pub fn calculate_totp(
        &mut self,
        slot: fotp::Slot,
        name: &str,
        unix_time: u64,
        period: u32,
    ) -> Result<fotp::OtpCode, TransportError> {
        let challenge = fotp::totp_challenge(unix_time, period);
        // `name` may come straight from the card's own LIST answer; one that
        // cannot be framed is an error, not a panic.
        let apdu = fotp::calculate_totp(slot, name, &challenge)
            .map_err(TransportError::FeitianOtpBuild)?;
        self.calculate(slot, &apdu)
    }

    /// [`Self::calculate_totp`] for the time window current now. The clock is
    /// read when the command is sent and again once the key answered: the
    /// key computes only once it is touched, and a code whose window ended
    /// while it waited is wiped and refused
    /// ([`TransportError::FeitianOtpWindowEnded`]), never returned. Returns
    /// the code and its window (unix time / `period`).
    pub fn calculate_totp_now(
        &mut self,
        slot: fotp::Slot,
        name: &str,
        period: u32,
    ) -> Result<(fotp::OtpCode, u64), TransportError> {
        let asked = unix_now();
        let code = self.calculate_totp(slot, name, asked, period)?;
        same_window(code, asked, unix_now(), period)
    }

    /// Compute the next HOTP for the credential stored as `name` in `slot`.
    /// The key advances its own counter.
    pub fn calculate_hotp(
        &mut self,
        slot: fotp::Slot,
        name: &str,
    ) -> Result<fotp::OtpCode, TransportError> {
        let apdu = fotp::calculate_hotp(slot, name).map_err(TransportError::FeitianOtpBuild)?;
        self.calculate(slot, &apdu)
    }

    fn calculate(
        &mut self,
        slot: fotp::Slot,
        apdu: &[u8],
    ) -> Result<fotp::OtpCode, TransportError> {
        let (data, sw) = self.transmit_for_touch(apdu)?;
        touch_answer("feitian calculate", "compute the code", slot, sw)?;
        fotp::parse_calculate(&data).map_err(TransportError::FeitianOtpParse)
    }

    /// Store a credential. The key stores it once it is touched.
    pub fn put(&mut self, params: &fotp::PutParams<'_>) -> Result<(), TransportError> {
        let sw = self.put_status(params)?;
        touch_answer("feitian put", "save the account", params.slot, sw)
    }

    /// PUT and return the raw status word, for callers that read the key's
    /// answer themselves (bulk import). [`fotp::SW_NO_TOUCH`] means the key
    /// was still untouched after every try.
    pub fn put_status(&mut self, params: &fotp::PutParams<'_>) -> Result<u16, TransportError> {
        // The PUT body carries the raw seed: wipe it after transmit.
        let apdu = Zeroizing::new(fotp::put(params).map_err(TransportError::FeitianOtpBuild)?);
        let (_, sw) = self.transmit_for_touch(&apdu)?;
        Ok(sw)
    }

    /// Remove the credential stored as `name` in `slot`.
    pub fn delete(&mut self, slot: fotp::Slot, name: &str) -> Result<(), TransportError> {
        let sw = self.delete_status(slot, name)?;
        touch_answer("feitian delete", "delete the account", slot, sw)
    }

    /// Wipe the applet with its RESET (`07`), as Feitian's client does: the
    /// five-byte form, then the four-byte one if the key answers `6700`. Like
    /// the other commands that change the key, it is sent again while the
    /// key answers that no touch came.
    pub fn reset(&mut self) -> Result<(), TransportError> {
        let (_, mut sw) = self.transmit_for_touch(&fotp::reset())?;
        if sw == fotp::SW_WRONG_LENGTH {
            (_, sw) = self.transmit_for_touch(&fotp::reset_legacy())?;
        }
        touch_answer("feitian reset", "reset the applet", fotp::Slot::Default, sw)
    }

    /// DELETE and return the raw status word.
    pub fn delete_status(&mut self, slot: fotp::Slot, name: &str) -> Result<u16, TransportError> {
        let apdu = fotp::delete(slot, name).map_err(TransportError::FeitianOtpBuild)?;
        let (_, sw) = self.transmit_for_touch(&apdu)?;
        Ok(sw)
    }

    /// Transmit a command the key acts on once it is touched, asking again
    /// while it answers that no touch came ([`asking_for_touch`]).
    fn transmit_for_touch(&mut self, apdu: &[u8]) -> Result<(Vec<u8>, u16), TransportError> {
        asking_for_touch(|| self.transmit_full(apdu))
    }

    /// Transmit one APDU and reassemble an answer the card splits across
    /// `61xx` continuations, returning `(payload, sw)`.
    fn transmit_full(&mut self, apdu: &[u8]) -> Result<(Vec<u8>, u16), TransportError> {
        let (cmd_sensitive, resp_sensitive) = trace_sensitivity(apdu);
        let card = match &mut self.link {
            Link::Card(card) => card,
            // One switch hides both directions on this link, so an exchange
            // with either half private is sent private.
            Link::Hid(hid) => {
                return transmit_hid(&mut hid.0, apdu, cmd_sensitive || resp_sensitive)
            }
        };
        let io = crate::AppletIo {
            label: "feitian",
            more_data_sw: fotp::SW_MORE_DATA,
            get_response: fotp::get_response,
            describe: None,
        };
        crate::transmit_applet(card, self.debug, &io, apdu, cmd_sensitive, resp_sensitive)
    }
}

/// A HID failure as this session's error.
fn hid_error(e: keyroost_ctap::hid::HidTransportError) -> TransportError {
    TransportError::FeitianOtpHid(e.to_string())
}

/// One APDU exchange over the FIDO HID interface, with the same `61xx`
/// reassembly as over PC/SC. `private` keeps the payloads out of the CTAP
/// trace in both directions.
fn transmit_hid(
    hid: &mut CtapHidDevice,
    apdu: &[u8],
    private: bool,
) -> Result<(Vec<u8>, u16), TransportError> {
    // The PUT body holds the seed: the copy in flight is wiped.
    let mut to_send = Zeroizing::new(apdu.to_vec());
    let mut acc = Vec::new();
    // As many continuations as a full listing could ever need.
    for _ in 0..64 {
        let answer = if private {
            hid.transact_private(CTAPHID_MSG, &to_send)
        } else {
            hid.transact(CTAPHID_MSG, &to_send)
        }
        .map_err(hid_error)?;
        if answer.len() < 2 {
            return Err(TransportError::ShortResponse {
                label: "feitian",
                got: answer.len(),
                expected_min: 2,
            });
        }
        let (data, sw) = answer.split_at(answer.len() - 2);
        match crate::advance_exchange(
            fotp::SW_MORE_DATA,
            fotp::get_response,
            &to_send,
            data,
            sw[0],
            sw[1],
            &mut acc,
        ) {
            crate::Continuation::Send(next) => to_send = Zeroizing::new(next),
            crate::Continuation::Done => return Ok((acc, u16::from_be_bytes([sw[0], sw[1]]))),
        }
    }
    Err(TransportError::MalformedResponse(
        "applet continuation exceeded the chunk limit",
    ))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `code`, computed for the window `asked` falls in, with that window, while
/// `now` is still in it; else wiped and refused.
fn same_window(
    mut code: fotp::OtpCode,
    asked: u64,
    now: u64,
    period: u32,
) -> Result<(fotp::OtpCode, u64), TransportError> {
    let period = u64::from(period.max(1));
    let window = asked / period;
    if now / period != window {
        zeroize::Zeroize::zeroize(&mut code.code);
        return Err(TransportError::FeitianOtpWindowEnded);
    }
    Ok((code, window))
}

/// Read every slot through `exchange` (one APDU in, `(payload, sw)` out).
/// The rules are [`FeitianOtpSession::list`]'s.
fn list_all(
    mut exchange: impl FnMut(&[u8]) -> Result<(Vec<u8>, u16), TransportError>,
) -> Result<FeitianOtpListing, TransportError> {
    let (mut data, mut sw) = exchange(&fotp::list(fotp::Slot::Default))?;
    let mut legacy = false;
    if sw == fotp::SW_WRONG_LENGTH {
        // What Feitian's client does with a 6700. No measured key gets here.
        (data, sw) = exchange(&fotp::list_legacy())?;
        legacy = true;
    }
    slot_answer("feitian list", fotp::Slot::Default, sw)?;
    let default =
        fotp::parse_list(&data, fotp::Slot::Default).map_err(TransportError::FeitianOtpParse)?;

    let mut out = FeitianOtpListing {
        credentials: Vec::new(),
        skipped: default.skipped,
        unread: Vec::new(),
        legacy,
    };
    if !legacy {
        for slot in [fotp::Slot::Keyboard1, fotp::Slot::Keyboard2] {
            let (data, sw) = exchange(&fotp::list(slot))?;
            if sw != fotp::SW_OK {
                out.unread.push((slot, sw));
                continue;
            }
            let listing = fotp::parse_list(&data, slot).map_err(TransportError::FeitianOtpParse)?;
            out.credentials.extend(listing.credentials);
            out.skipped += listing.skipped;
        }
    }
    out.credentials.extend(default.credentials);
    Ok(out)
}

/// How many times a command that waits for a touch is sent before giving up.
///
/// The measured keys answer [`fotp::SW_NO_TOUCH`] 3.2 or 5.2 seconds, by
/// model, after a command they want a touch for, and store or compute
/// nothing. That is short for a person, so the same command is sent again:
/// five tries give about as long as other keys wait on their own.
const TOUCH_TRIES: usize = 5;

/// Send a command through `exchange` until the key answers something other
/// than "no touch", at most [`TOUCH_TRIES`] times. The last answer is
/// returned as it is, so a caller still sees [`fotp::SW_NO_TOUCH`] when no
/// touch ever came.
fn asking_for_touch(
    mut exchange: impl FnMut() -> Result<(Vec<u8>, u16), TransportError>,
) -> Result<(Vec<u8>, u16), TransportError> {
    let mut answer = exchange()?;
    for _ in 1..TOUCH_TRIES {
        if answer.1 != fotp::SW_NO_TOUCH {
            break;
        }
        answer = exchange()?;
    }
    Ok(answer)
}

/// The answer to a command the key acts on once touched: `6984` after every
/// try means no touch came ([`TransportError::FeitianOtpNoTouch`]).
/// `action` is what was asked ("save the account", ...).
fn touch_answer(
    label: &'static str,
    action: &'static str,
    slot: fotp::Slot,
    sw: u16,
) -> Result<(), TransportError> {
    if sw == fotp::SW_NO_TOUCH {
        return Err(TransportError::FeitianOtpNoTouch { action });
    }
    slot_answer(label, slot, sw)
}

/// Map a status word to success or a labeled APDU error.
fn ok_or_apdu(label: &'static str, sw: u16) -> Result<(), TransportError> {
    if sw == fotp::SW_OK {
        Ok(())
    } else {
        Err(TransportError::Apdu {
            label,
            sw1: (sw >> 8) as u8,
            sw2: sw as u8,
        })
    }
}

/// The answer to a command that names a slot. `6982` is what Feitian's own
/// software reads as "this slot has an access code"; it is reported as that.
fn slot_answer(label: &'static str, slot: fotp::Slot, sw: u16) -> Result<(), TransportError> {
    if sw == fotp::SW_ACCESS_CODE_REQUIRED {
        return Err(TransportError::FeitianOtpAccessCode { slot: slot.label() });
    }
    ok_or_apdu(label, sw)
}

/// Which halves of an exchange `--debug` must hide: `(command body, response
/// body)`. Traces get pasted into public issues, so anything that names an
/// account, carries a code, or carries a secret is hidden; the status word
/// always stays.
///
/// Commands: PUT (09) holds the seed in the clear; DELETE (08) and CALCULATE
/// (A2) name an account. Responses: LIST (17) lists account names, CALCULATE
/// carries a code. The SELECT exchange stays visible: its version is what a
/// bug report needs.
fn trace_sensitivity(apdu: &[u8]) -> (bool, bool) {
    let ins = apdu.get(1).copied();
    let cmd = matches!(ins, Some(0x08 | 0x09 | 0xA2));
    let resp = matches!(ins, Some(0x17 | 0xA2));
    (cmd, resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A TOTP code is kept only while the window it was asked for lasts: a
    /// touch that comes after the window ended gets a refusal, not a code
    /// that no server takes any more.
    #[test]
    fn a_totp_code_whose_window_ended_during_the_touch_is_refused() {
        let code = || fotp::OtpCode {
            digits: 6,
            code: "123456".into(),
        };
        let (got, window) = same_window(code(), 1_000, 1_019, 30).unwrap();
        assert_eq!((got.code.as_str(), window), ("123456", 1_000 / 30));
        assert_eq!(same_window(code(), 1_000, 1_000, 60).unwrap().1, 1_000 / 60);
        let err = same_window(code(), 1_019, 1_020, 30).err().unwrap();
        assert!(matches!(err, TransportError::FeitianOtpWindowEnded));
        assert_eq!(
            err.to_string(),
            "that code's time window ended while the key waited for the touch; read it again"
        );
    }

    /// Answers each command from a script and records what was sent.
    struct Script {
        answers: Vec<(Vec<u8>, u16)>,
        sent: Vec<Vec<u8>>,
    }

    impl Script {
        fn new(answers: &[(&[u8], u16)]) -> Self {
            Script {
                answers: answers.iter().map(|(d, sw)| (d.to_vec(), *sw)).collect(),
                sent: Vec::new(),
            }
        }

        fn run(&mut self) -> Result<FeitianOtpListing, TransportError> {
            let mut answers = self.answers.clone().into_iter();
            let sent = &mut self.sent;
            list_all(|apdu| {
                sent.push(apdu.to_vec());
                Ok(answers.next().expect("more commands than scripted answers"))
            })
        }
    }

    // TOTP/SHA-1 "30:a" and HOTP/SHA-1 "h".
    const TOTP_A: &[u8] = &[0x52, 0x05, 0x21, b'3', b'0', b':', b'a'];
    const HOTP_H: &[u8] = &[0x52, 0x02, 0x11, b'h'];

    #[test]
    fn list_asks_the_default_slot_first_and_reports_in_slot_order() {
        let mut s = Script::new(&[(TOTP_A, 0x9000), (&[], 0x9000), (HOTP_H, 0x9000)]);
        let listing = s.run().unwrap();
        assert_eq!(
            s.sent,
            vec![
                fotp::list(fotp::Slot::Default),
                fotp::list(fotp::Slot::Keyboard1),
                fotp::list(fotp::Slot::Keyboard2),
            ]
        );
        assert_eq!(
            listing
                .credentials
                .iter()
                .map(|c| (c.slot, c.name.as_str()))
                .collect::<Vec<_>>(),
            vec![(fotp::Slot::Keyboard2, "h"), (fotp::Slot::Default, "30:a")]
        );
        assert!(listing.unread.is_empty());
        assert!(!listing.legacy);
        assert_eq!(listing.skipped, 0);
    }

    #[test]
    fn a_keyboard_slot_that_refuses_is_reported_not_fatal() {
        for sw in [0x6982u16, 0x6A82, 0x6A86, 0x6D00, 0x6700, 0x6F00] {
            let mut s = Script::new(&[(TOTP_A, 0x9000), (&[], sw), (&[], 0x9000)]);
            let listing = s.run().unwrap();
            assert_eq!(listing.credentials.len(), 1, "SW={sw:04X}");
            assert_eq!(listing.unread, vec![(fotp::Slot::Keyboard1, sw)]);
            // A refused keyboard slot is not asked again in another form.
            assert_eq!(s.sent.len(), 3);
        }
    }

    #[test]
    fn the_default_slot_decides_the_outcome() {
        let mut s = Script::new(&[(&[], 0x6982)]);
        assert!(matches!(
            s.run(),
            Err(TransportError::FeitianOtpAccessCode { slot: "default" })
        ));
        // Nothing else is asked once the default slot has refused.
        assert_eq!(s.sent.len(), 1);

        let mut s = Script::new(&[(&[], 0x6D00)]);
        assert!(matches!(
            s.run(),
            Err(TransportError::Apdu {
                sw1: 0x6D,
                sw2: 0x00,
                ..
            })
        ));
    }

    #[test]
    fn a_6700_falls_back_to_the_four_byte_list_and_stops() {
        let mut s = Script::new(&[(&[], 0x6700), (TOTP_A, 0x9000)]);
        let listing = s.run().unwrap();
        assert_eq!(
            s.sent,
            vec![fotp::list(fotp::Slot::Default), fotp::list_legacy()]
        );
        assert!(listing.legacy);
        assert_eq!(listing.credentials.len(), 1);
        assert_eq!(listing.credentials[0].slot, fotp::Slot::Default);

        // The fallback refused as well: an error.
        let mut s = Script::new(&[(&[], 0x6700), (&[], 0x6700)]);
        assert!(matches!(
            s.run(),
            Err(TransportError::Apdu {
                sw1: 0x67,
                sw2: 0x00,
                ..
            })
        ));
    }

    #[test]
    fn skipped_entries_add_up_across_slots() {
        // One static-password entry (kind 0x30) in the default slot and one
        // in keyboard slot 2.
        let other: &[u8] = &[0x52, 0x02, 0x31, b'p'];
        let mut s = Script::new(&[(other, 0x9000), (&[], 0x9000), (other, 0x9000)]);
        let listing = s.run().unwrap();
        assert!(listing.credentials.is_empty());
        assert_eq!(listing.skipped, 2);
    }

    #[test]
    fn a_command_is_sent_again_while_the_key_waits_for_a_touch() {
        let run = |answers: &[u16]| {
            let mut left = answers.iter().copied();
            let mut sent = 0;
            let got = asking_for_touch(|| {
                sent += 1;
                Ok((Vec::new(), left.next().expect("sent more than scripted")))
            })
            .unwrap();
            (got.1, sent)
        };
        // Touched at once: sent once.
        assert_eq!(run(&[0x9000]), (0x9000, 1));
        // Touched on the third ask.
        assert_eq!(run(&[0x6984, 0x6984, 0x9000]), (0x9000, 3));
        // Another refusal ends the asking: it is not a missing touch.
        assert_eq!(run(&[0x6984, 0x6A82]), (0x6A82, 2));
        // Never touched: the last "no touch" comes back after every try.
        assert_eq!(run(&[0x6984; TOUCH_TRIES]), (0x6984, TOUCH_TRIES));
    }

    #[test]
    fn no_touch_names_what_was_asked() {
        let slot = fotp::Slot::Default;
        assert!(matches!(
            touch_answer("feitian put", "save the account", slot, 0x6984),
            Err(TransportError::FeitianOtpNoTouch {
                action: "save the account"
            })
        ));
        assert!(touch_answer("feitian put", "save the account", slot, 0x9000).is_ok());
        assert!(matches!(
            touch_answer("feitian put", "save the account", slot, 0x6982),
            Err(TransportError::FeitianOtpAccessCode { slot: "default" })
        ));
        let msg = TransportError::FeitianOtpNoTouch {
            action: "save the account",
        }
        .to_string();
        assert!(
            msg.contains("save the account") && msg.contains("touch"),
            "{msg}"
        );
    }

    /// `--debug` traces are pasted into public issues: whatever names an
    /// account or carries a code or a seed is hidden, in both directions.
    #[test]
    fn traces_hide_account_names_codes_and_secrets() {
        let ch = [0u8; 8];
        let slot = fotp::Slot::Default;
        let params = fotp::PutParams {
            slot,
            name: "30:GitHub_#_alice",
            secret: &[1u8; 20],
            oath_type: fotp::OathType::Totp,
            algorithm: fotp::Algorithm::Sha1,
            digits: 6,
        };
        let cases: [(&str, Vec<u8>, bool, bool); 8] = [
            ("select", fotp::select(), false, false),
            ("get response", fotp::get_response(), false, false),
            ("list", fotp::list(slot), false, true),
            ("list legacy", fotp::list_legacy(), false, true),
            (
                "calculate",
                fotp::calculate_totp(slot, "30:GitHub_#_alice", &ch).unwrap(),
                true,
                true,
            ),
            (
                "calculate hotp",
                fotp::calculate_hotp(slot, "GitHub_#_alice").unwrap(),
                true,
                true,
            ),
            ("put", fotp::put(&params).unwrap(), true, false),
            (
                "delete",
                fotp::delete(slot, "30:GitHub_#_alice").unwrap(),
                true,
                false,
            ),
        ];
        for (what, apdu, cmd, resp) in cases {
            assert_eq!(trace_sensitivity(&apdu), (cmd, resp), "{what}");
        }
    }
}
