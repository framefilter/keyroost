//! A session with a CanoKey's Admin applet over PC/SC: its firmware
//! version, its Admin PIN, single-applet resets and the device-wide
//! factory reset. The byte layer is `keyroost-canokey`; what each command
//! needs (PIN, touch, USB) is documented there.

use keyroost_canokey as admin;
use pcsc::Card;
use zeroize::Zeroizing;

use crate::recover::{self, FirstContact};
use crate::{AppletIo, CmdRedact, TransportError};

fn ok_or_apdu(label: &'static str, sw: u16) -> Result<(), TransportError> {
    if sw == admin::SW_OK {
        Ok(())
    } else {
        Err(TransportError::Apdu {
            label,
            sw1: (sw >> 8) as u8,
            sw2: sw as u8,
        })
    }
}

/// An open, selected Admin applet on one CanoKey. Opening it ends any other
/// applet's session on the key (its PIN and management-key authentication
/// included): the firmware powers the other applets off on a switch.
pub struct CanoKeyAdminSession {
    card: Card,
    debug: bool,
}

/// What VERIFY with no PIN says about the Admin PIN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminPinState {
    /// Verified in this session already.
    Verified,
    /// Not verified; this many tries left before it blocks.
    Tries(u8),
    /// Blocked: only a factory reset unblocks it.
    Blocked,
}

impl CanoKeyAdminSession {
    /// Connect to `reader_name` and select the Admin applet. Fails with
    /// [`TransportError::Apdu`] when the card has no such applet (it is no
    /// CanoKey).
    pub fn open_traced(reader_name: &str, debug: bool) -> Result<Self, TransportError> {
        let cstr = std::ffi::CString::new(reader_name)
            .map_err(|_| TransportError::MalformedResponse("reader name contained NUL"))?;
        let mut contact = FirstContact::new(reader_name, debug, "canokey admin");
        loop {
            let ctx = crate::establish_context().map_err(TransportError::PcscUnavailable)?;
            let mut card = match crate::connect_shared(&ctx, &cstr) {
                Ok(card) => card,
                Err(e) => {
                    contact.retry_or_fail(e.into())?;
                    continue;
                }
            };
            // As the other sessions do: the transaction stays open for the
            // session and ends when the card is disconnected.
            if let Err(e) = card.transaction().map(std::mem::forget) {
                recover::release(card);
                contact.retry_or_fail(e.into())?;
                continue;
            }
            let mut session = Self { card, debug };
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

    fn select(&mut self) -> Result<(), TransportError> {
        let (_, sw) = self.transmit(&admin::select_admin(), CmdRedact::Nothing)?;
        ok_or_apdu("select canokey admin applet", sw)
    }

    /// The firmware version, `None` when the key doesn't give one keyroost
    /// reads (see [`keyroost_canokey::parse_firmware_version`]).
    pub fn firmware(&mut self) -> Option<admin::FirmwareVersion> {
        let (data, sw) = self
            .transmit(&admin::read_firmware_version(), CmdRedact::Nothing)
            .ok()?;
        (sw == admin::SW_OK)
            .then(|| admin::parse_firmware_version(&data))
            .flatten()
    }

    /// The Admin PIN's state, read without spending a try.
    pub fn pin_state(&mut self) -> Result<AdminPinState, TransportError> {
        let (_, sw) = self.transmit(&admin::pin_status(), CmdRedact::Nothing)?;
        match (sw, admin::pin_tries_from_sw(sw)) {
            (admin::SW_OK, _) => Ok(AdminPinState::Verified),
            (_, Some(0)) => Ok(AdminPinState::Blocked),
            (_, Some(n)) => Ok(AdminPinState::Tries(n)),
            _ => ok_or_apdu("canokey admin pin status", sw).map(|()| AdminPinState::Verified),
        }
    }

    /// VERIFY the Admin PIN. A wrong one costs a try:
    /// [`TransportError::CanoKeyAdminPinRejected`] says how many are left,
    /// [`TransportError::CanoKeyAdminPinBlocked`] that none are.
    pub fn verify_pin(&mut self, pin: &[u8]) -> Result<(), TransportError> {
        let apdu = admin::verify_pin(pin).map_err(|_| TransportError::CanoKeyAdminPinLength)?;
        let (_, sw) = self.transmit(&apdu, CmdRedact::LengthAndBody)?;
        match (sw, admin::pin_tries_from_sw(sw)) {
            (admin::SW_OK, _) => Ok(()),
            (_, Some(0)) => Err(TransportError::CanoKeyAdminPinBlocked),
            (_, Some(n)) => Err(TransportError::CanoKeyAdminPinRejected { tries_remaining: n }),
            _ => ok_or_apdu("canokey admin verify", sw),
        }
    }

    /// Reset one applet. Needs [`Self::verify_pin`] first, in this session.
    pub fn reset_applet(&mut self, applet: admin::Applet) -> Result<(), TransportError> {
        let (_, sw) = self.transmit(&admin::reset_applet(applet), CmdRedact::Nothing)?;
        if sw == admin::SW_SECURITY_STATUS_NOT_SATISFIED {
            return Err(TransportError::CanoKeyAdminPinNeeded);
        }
        ok_or_apdu("canokey admin reset applet", sw)
    }

    /// Block the Admin PIN with wrong PINs, so a factory reset is accepted:
    /// the firmware takes one only once the PIN is blocked, the way out for
    /// a key whose Admin PIN is forgotten. Each guess is random, so a guess
    /// that happens to be the PIN (it then verifies and costs nothing) is
    /// followed by another.
    pub fn block_pin(&mut self) -> Result<(), TransportError> {
        // Three tries, plus room for guesses that happen to verify.
        for _ in 0..(usize::from(admin::ADMIN_PIN_RETRIES) + 3) {
            if self.pin_state()? == AdminPinState::Blocked {
                return Ok(());
            }
            let guess = random_pin_guess()?;
            match self.verify_pin(guess.as_slice()) {
                Ok(())
                | Err(
                    TransportError::CanoKeyAdminPinRejected { .. }
                    | TransportError::CanoKeyAdminPinBlocked,
                ) => {}
                Err(e) => return Err(e),
            }
        }
        if self.pin_state()? == AdminPinState::Blocked {
            Ok(())
        } else {
            Err(TransportError::CanoKeyAdminPinWouldNotBlock)
        }
    }

    /// The device-wide factory reset: every applet, the Admin PIN and the
    /// device settings return to their defaults; the serial stays. Needs the
    /// Admin PIN blocked ([`Self::block_pin`]) and a USB connection; the key
    /// then blinks five times and must be touched within two seconds each
    /// time. Blocks until it answers.
    pub fn factory_reset(&mut self) -> Result<(), TransportError> {
        let (_, sw) = self.transmit(&admin::factory_reset(), CmdRedact::Nothing)?;
        match sw {
            admin::SW_OK => Ok(()),
            admin::SW_SECURITY_STATUS_NOT_SATISFIED => Err(TransportError::CanoKeyResetNoTouch),
            admin::SW_CONDITIONS_NOT_SATISFIED => Err(TransportError::CanoKeyResetNotAllowed),
            _ => ok_or_apdu("canokey factory reset", sw),
        }
    }

    fn transmit(
        &mut self,
        apdu: &[u8],
        redact: CmdRedact,
    ) -> Result<(Vec<u8>, u16), TransportError> {
        let io = AppletIo {
            label: "canokey admin",
            more_data_sw: 0x61,
            get_response,
            describe: None,
        };
        crate::transmit_applet(&self.card, self.debug, &io, apdu, redact, false)
    }
}

fn get_response() -> Vec<u8> {
    vec![0x00, 0xC0, 0x00, 0x00, 0x00]
}

/// A random wrong-PIN guess for [`CanoKeyAdminSession::block_pin`]:
/// sixteen hex digits, inside the PIN's length limits.
fn random_pin_guess() -> Result<Zeroizing<Vec<u8>>, TransportError> {
    let mut raw = Zeroizing::new([0u8; 8]);
    getrandom::fill(raw.as_mut_slice()).map_err(|_| TransportError::HostRngFailed)?;
    let mut guess = Zeroizing::new(Vec::with_capacity(16));
    for b in raw.iter() {
        for nibble in [b >> 4, b & 0x0F] {
            guess.push(b"0123456789abcdef"[usize::from(nibble)]);
        }
    }
    Ok(guess)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pin_guess_is_a_valid_admin_pin_length() {
        let g = random_pin_guess().unwrap();
        assert!((admin::ADMIN_PIN_MIN_LEN..=admin::ADMIN_PIN_MAX_LEN).contains(&g.len()));
        assert!(g.iter().all(u8::is_ascii_hexdigit));
        assert_ne!(random_pin_guess().unwrap(), g, "random each time");
    }
}
