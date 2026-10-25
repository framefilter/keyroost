//! Opening a smart-card session on a card that was reset just before.
//!
//! A card can be reset, or drop off its reader for a moment, between two
//! sessions — another program resetting it on disconnect, say, or the key
//! itself. On a YubiKey NEO on macOS, keyroost's PIV, OpenPGP and OATH reads
//! failed on their very first command with `SCARD_E_NOT_TRANSACTED` or
//! `SCARD_E_NO_SMARTCARD` while ykman read the same key. The reads came
//! right after FIDO-side traffic to the key; whether that is what resets it
//! is not confirmed.
//!
//! [`FirstContact`] lets a session's opening — connect, begin the
//! transaction, SELECT the applet — wait for such a card and try once more.
//! None of those can change what the card holds, so a second try is safe.
//! Once the opening has succeeded nothing is retried: a later command may
//! already have changed something.

use crate::{trace, TransportError};
use keyroost_proto::trace::{format_line, Dir};
use pcsc::{Card, ReaderState, State};
use std::time::{Duration, Instant};

/// The longest to wait for the card to come back before the one retry.
const CARD_RETURN_TIMEOUT: Duration = Duration::from_secs(3);
/// Head start for a card that is still going away, so the presence check
/// doesn't see it one last time before it leaves.
const CARD_SETTLE: Duration = Duration::from_millis(250);
/// Between two presence checks.
const CARD_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Whether `e` says the card was reset or is momentarily absent: reset
/// (`SCARD_W_RESET_CARD`), removed (`SCARD_W_REMOVED_CARD`), none in the
/// reader (`SCARD_E_NO_SMARTCARD`), or the transaction this handle began is
/// gone (`SCARD_E_NOT_TRANSACTED`). The same codes on every PC/SC stack.
pub(crate) fn is_card_reset_or_absent(e: &pcsc::Error) -> bool {
    matches!(
        e,
        pcsc::Error::ResetCard
            | pcsc::Error::RemovedCard
            | pcsc::Error::NoSmartcard
            | pcsc::Error::NotTransacted
    )
}

/// The retry rule: once per session, only while the opening is still under
/// way (`opened` false), and only for a card that was reset or is absent.
fn should_retry(tries: u32, opened: bool, e: &TransportError) -> bool {
    tries == 0 && !opened && matches!(e, TransportError::Pcsc(pe) if is_card_reset_or_absent(pe))
}

/// Whether a reader state shows a card PC/SC can talk to.
fn card_ready(state: State) -> bool {
    state.contains(State::PRESENT)
        && !state.intersects(State::EMPTY | State::MUTE | State::UNAVAILABLE | State::UNKNOWN)
}

/// Wait, at most [`CARD_RETURN_TIMEOUT`], until `reader` shows a card again.
/// Returns early, without a card, when PC/SC can't be asked; the retry then
/// reports whatever is wrong.
fn wait_for_card(reader: &str) {
    let deadline = Instant::now() + CARD_RETURN_TIMEOUT;
    std::thread::sleep(CARD_SETTLE);
    let (Ok(ctx), Ok(name)) = (crate::establish_context(), std::ffi::CString::new(reader)) else {
        return;
    };
    loop {
        let mut states = [ReaderState::new(name.clone(), State::UNAWARE)];
        let ready = match ctx.get_status_change(Duration::ZERO, &mut states) {
            Ok(()) | Err(pcsc::Error::Timeout) => card_ready(states[0].event_state()),
            Err(_) => return,
        };
        if ready || Instant::now() >= deadline {
            return;
        }
        std::thread::sleep(CARD_POLL_INTERVAL);
    }
}

/// Release a card whose opening failed, without resetting it (the `pcsc`
/// crate's `Drop` hard-codes `ResetCard`). Ends a transaction begun on it.
pub(crate) fn release(card: Card) {
    let _ = card.disconnect(pcsc::Disposition::LeaveCard);
}

/// One session's opening, retried once if it finds the card just reset.
///
/// The caller loops over connect, begin transaction and SELECT, handing each
/// failure to [`Self::retry_or_fail`]: `Ok` means wait over, go round again;
/// `Err` is the error to return. It calls [`Self::opened`] as soon as the
/// opening has succeeded, before anything else is sent.
pub(crate) struct FirstContact<'a> {
    reader: &'a str,
    debug: bool,
    label: &'static str,
    tries: u32,
    opened: bool,
    wait: fn(&str),
}

impl<'a> FirstContact<'a> {
    /// `label` names the session in `--debug` lines (`piv`, `oath`, ...).
    pub(crate) fn new(reader: &'a str, debug: bool, label: &'static str) -> Self {
        Self {
            reader,
            debug,
            label,
            tries: 0,
            opened: false,
            wait: wait_for_card,
        }
    }

    /// After a failed connect, begin-transaction or SELECT: `Ok(())`, once
    /// the card is back (or the wait ran out), when the opening is worth one
    /// more try; otherwise `Err(e)`.
    pub(crate) fn retry_or_fail(&mut self, e: TransportError) -> Result<(), TransportError> {
        if !should_retry(self.tries, self.opened, &e) {
            return Err(e);
        }
        self.tries += 1;
        trace::line(self.debug, || {
            format_line(
                Dir::Note,
                self.label,
                &format!("{e}; waiting for the card to reconnect"),
            )
        });
        (self.wait)(self.reader);
        Ok(())
    }

    /// The opening succeeded: nothing is retried from here on.
    pub(crate) fn opened(&mut self) {
        self.opened = true;
        if self.tries > 0 {
            trace::line(self.debug, || {
                format_line(
                    Dir::Note,
                    self.label,
                    "reopened after the card was reset or briefly gone",
                )
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pcsc(e: pcsc::Error) -> TransportError {
        TransportError::Pcsc(e)
    }

    fn no_wait(_: &str) {}

    fn contact() -> FirstContact<'static> {
        FirstContact {
            wait: no_wait,
            ..FirstContact::new("Reader 00 00", false, "test")
        }
    }

    #[test]
    fn reset_and_absent_codes_are_transient() {
        for e in [
            pcsc::Error::ResetCard,
            pcsc::Error::RemovedCard,
            pcsc::Error::NoSmartcard,
            pcsc::Error::NotTransacted,
        ] {
            assert!(is_card_reset_or_absent(&e), "{e:?}");
        }
        for e in [
            pcsc::Error::SharingViolation,
            pcsc::Error::UnknownReader,
            pcsc::Error::ReaderUnavailable,
            pcsc::Error::NoService,
            pcsc::Error::CommError,
            pcsc::Error::Timeout,
            pcsc::Error::UnpoweredCard,
        ] {
            assert!(!is_card_reset_or_absent(&e), "{e:?}");
        }
    }

    #[test]
    fn retry_rule() {
        let reset = pcsc(pcsc::Error::ResetCard);
        assert!(should_retry(0, false, &reset));
        assert!(!should_retry(1, false, &reset), "only once");
        assert!(!should_retry(0, true, &reset), "never after the opening");
        assert!(!should_retry(
            0,
            false,
            &pcsc(pcsc::Error::SharingViolation)
        ));
        assert!(!should_retry(0, false, &TransportError::NoPivApplet));
        // The service itself being down is not a card coming back.
        assert!(!should_retry(
            0,
            false,
            &TransportError::PcscUnavailable(pcsc::Error::NoSmartcard)
        ));
    }

    #[test]
    fn an_opening_that_finds_the_card_reset_is_tried_once_more() {
        let mut c = contact();
        assert!(c.retry_or_fail(pcsc(pcsc::Error::NotTransacted)).is_ok());
        let second = c.retry_or_fail(pcsc(pcsc::Error::NoSmartcard));
        assert!(matches!(
            second,
            Err(TransportError::Pcsc(pcsc::Error::NoSmartcard))
        ));
    }

    #[test]
    fn nothing_is_retried_once_the_session_is_open() {
        let mut c = contact();
        c.opened();
        assert!(matches!(
            c.retry_or_fail(pcsc(pcsc::Error::ResetCard)),
            Err(TransportError::Pcsc(pcsc::Error::ResetCard))
        ));
    }

    #[test]
    fn other_failures_are_returned_at_once() {
        let mut c = contact();
        assert!(matches!(
            c.retry_or_fail(TransportError::NoOpenPgpApplet),
            Err(TransportError::NoOpenPgpApplet)
        ));
        // ...and don't use up the retry.
        assert!(c.retry_or_fail(pcsc(pcsc::Error::RemovedCard)).is_ok());
    }

    #[test]
    fn a_card_is_ready_only_when_present_and_answering() {
        assert!(card_ready(State::PRESENT));
        assert!(card_ready(State::PRESENT | State::INUSE | State::CHANGED));
        assert!(!card_ready(State::EMPTY));
        assert!(!card_ready(State::PRESENT | State::MUTE));
        assert!(!card_ready(State::UNAVAILABLE));
        assert!(!card_ready(State::empty()));
    }
}
