//! PIV (NIST SP 800-73-4) over PC/SC.
//!
//! Drives the PIV smartcard application using the pure-byte builders/parsers in
//! [`keyroost_piv`]. Like the OATH and OpenPGP sessions, this adds the card
//! transmit, the `61xx` / GET RESPONSE reassembly loop, reader discovery, and a
//! read-only status view assembled from the Yubico version/serial extensions,
//! the PIN retry counter, and per-slot certificate presence.
//!
//! Read-only for now — no PIN is presented and nothing is written. The PIV
//! write/auth surface (GENERAL AUTHENTICATE, key generation, certificate import,
//! PIN/PUK/management-key management) is future work; see PLAN.md.

use crate::{hex_dump, TransportError};
use keyroost_piv as piv;
use pcsc::{Card, Context, Protocols, Scope, ShareMode};

/// A read-only snapshot of a PIV application's state.
#[derive(Debug, Clone)]
pub struct PivStatus {
    /// Applet/firmware version `(major, minor, patch)` from the Yubico GET
    /// VERSION extension, if the card supports it.
    pub version: Option<(u8, u8, u8)>,
    /// Device serial (Yubico GET SERIAL; firmware 5+), if supported.
    pub serial: Option<u32>,
    /// Remaining PIN tries from a no-op VERIFY (`63 Cx`); `Some(0)` when blocked,
    /// `None` when the card didn't report a count.
    pub pin_retries: Option<u8>,
    /// Per-slot certificate presence, in canonical slot order.
    pub slots: Vec<PivSlotStatus>,
}

/// Whether a given PIV key slot holds a certificate (and its size).
#[derive(Debug, Clone)]
pub struct PivSlotStatus {
    pub slot: piv::Slot,
    /// True when GET DATA returned a certificate object for the slot.
    pub cert_present: bool,
    /// Length in bytes of the certificate object's value, when present.
    pub cert_len: usize,
}

/// An open PIV applet session on one PC/SC reader.
pub struct PivSession {
    card: Card,
    debug: bool,
}

impl PivSession {
    /// Connect to `reader_name` and SELECT the PIV application. Returns
    /// [`TransportError::NoPivApplet`] when the card has no PIV applet.
    pub fn open(reader_name: &str) -> Result<Self, TransportError> {
        let ctx = Context::establish(Scope::User).map_err(TransportError::PcscUnavailable)?;
        let cstr = std::ffi::CString::new(reader_name)
            .map_err(|_| TransportError::MalformedResponse("reader name contained NUL"))?;
        let card = ctx.connect(&cstr, ShareMode::Shared, Protocols::ANY)?;
        let mut session = Self { card, debug: false };
        session.select()?;
        Ok(session)
    }

    /// Enable per-APDU stderr tracing.
    pub fn set_debug(&mut self, on: bool) {
        self.debug = on;
    }

    /// Names of connected readers whose PIV applet answers `SELECT` with `9000`.
    pub fn list_piv_readers() -> Result<Vec<String>, TransportError> {
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
                let mut session = PivSession { card, debug: false };
                if session.select().is_ok() {
                    out.push(name.to_string_lossy().into_owned());
                }
            }
        }
        Ok(out)
    }

    fn select(&mut self) -> Result<(), TransportError> {
        let (_, sw) = self.transmit_full(&piv::select())?;
        if sw == piv::SW_NOT_FOUND {
            return Err(TransportError::NoPivApplet);
        }
        ok_or_apdu("select piv applet", sw)
    }

    /// Read a read-only status snapshot: version, serial, PIN retries, and which
    /// slots hold a certificate. No PIN, no touch.
    pub fn status(&mut self) -> Result<PivStatus, TransportError> {
        let version = self.version();
        let serial = self.serial();
        let pin_retries = self.pin_retries();
        let mut slots = Vec::with_capacity(4);
        for slot in piv::Slot::all() {
            slots.push(self.slot_status(slot)?);
        }
        Ok(PivStatus {
            version,
            serial,
            pin_retries,
            slots,
        })
    }

    /// Yubico GET VERSION; `None` if the card doesn't support the extension.
    fn version(&mut self) -> Option<(u8, u8, u8)> {
        let (data, sw) = self.transmit_full(&piv::get_version()).ok()?;
        if sw != piv::SW_OK {
            return None;
        }
        piv::parse_version(&data).ok()
    }

    /// Yubico GET SERIAL; `None` if unsupported (older firmware / non-Yubico).
    fn serial(&mut self) -> Option<u32> {
        let (data, sw) = self.transmit_full(&piv::get_serial()).ok()?;
        if sw != piv::SW_OK {
            return None;
        }
        piv::parse_serial(&data).ok()
    }

    /// Remaining PIN tries via a no-op VERIFY. `63 Cx` → `Some(x)`, `6983`
    /// (blocked) → `Some(0)`, `9000` (already verified) / anything else → `None`.
    fn pin_retries(&mut self) -> Option<u8> {
        let (_, sw) = self.transmit_full(&piv::verify_pin_status()).ok()?;
        if sw & 0xFFF0 == 0x63C0 {
            Some((sw & 0x000F) as u8)
        } else if sw == 0x6983 {
            Some(0)
        } else {
            None
        }
    }

    /// Whether `slot` holds a certificate (GET DATA), and its size if so.
    fn slot_status(&mut self, slot: piv::Slot) -> Result<PivSlotStatus, TransportError> {
        let (data, sw) = self.transmit_full(&piv::get_data(&slot.cert_object_tag()))?;
        let (cert_present, cert_len) = if sw == piv::SW_OK {
            // The object is a 0x53 template; report the inner value length.
            let len = piv::unwrap_data_object(&data).map(<[u8]>::len).unwrap_or(0);
            (true, len)
        } else {
            // 6A82 (not found) and friends just mean the slot is empty.
            (false, 0)
        };
        Ok(PivSlotStatus {
            slot,
            cert_present,
            cert_len,
        })
    }

    /// Transmit one APDU and reassemble a response the card splits across `61xx`
    /// continuations (GET RESPONSE), returning `(payload, sw)`.
    fn transmit_full(&mut self, apdu: &[u8]) -> Result<(Vec<u8>, u16), TransportError> {
        let mut acc = Vec::new();
        let mut to_send = apdu.to_vec();
        loop {
            if self.debug {
                eprintln!("> {:>14} >> {}", "piv", hex_dump(&to_send));
            }
            let mut buf = [0u8; 4096];
            let resp = self.card.transmit(&to_send, &mut buf)?;
            if self.debug {
                eprintln!("< {:>14} << {}", "piv", hex_dump(resp));
            }
            if resp.len() < 2 {
                return Err(TransportError::ShortResponse {
                    label: "piv apdu",
                    got: resp.len(),
                    expected_min: 2,
                });
            }
            let (data, sw) = resp.split_at(resp.len() - 2);
            acc.extend_from_slice(data);
            if sw[0] == piv::SW_MORE_DATA {
                to_send = piv::get_response();
                continue;
            }
            return Ok((acc, u16::from_be_bytes([sw[0], sw[1]])));
        }
    }
}

/// Map a PIV status word to success or a labelled APDU error.
fn ok_or_apdu(label: &'static str, sw: u16) -> Result<(), TransportError> {
    if sw == piv::SW_OK {
        Ok(())
    } else {
        Err(TransportError::Apdu {
            label,
            sw1: (sw >> 8) as u8,
            sw2: sw as u8,
        })
    }
}
