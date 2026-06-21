//! CTAP2 over PC/SC — FIDO2 across NFC and contact smart-card readers.
//!
//! USB security keys speak CTAP-HID; keys presented over an **NFC** or
//! **contact (IC chip)** reader instead speak **CTAP over ISO 7816-4 APDUs**
//! (FIDO CTAP §11.2, "Message Encoding"). This module bridges the two: it
//! implements [`keyroost_ctap::transport::CtapTransport`] on top of a PC/SC card
//! connection, so every existing CTAP2 command (`get_info`, PIN, passkeys,
//! config, large blobs) runs unchanged over a reader.
//!
//! ## How a CTAP message is carried
//!
//! 1. **Applet selection.** On connect we `SELECT` the FIDO applet by AID
//!    (`A0000006472F0001`). A compliant authenticator answers `U2F_V2` or
//!    `FIDO_2_0`.
//! 2. **Request.** A CTAP2 message (command byte + CBOR) is sent in the data
//!    field of an `NFCCTAP_MSG` APDU: `CLA=0x80 INS=0x10 P1=0x00 P2=0x00`. If
//!    the message exceeds the short-APDU limit (255 bytes) it is split across
//!    several APDUs using ISO 7816 **command chaining** (CLA bit 0x10 set on all
//!    but the last).
//! 3. **Response.** The authenticator may return the body directly, or signal
//!    more data with status `61 XX`, in which case we issue `GET RESPONSE`
//!    (`00 C0 00 00 XX`) repeatedly and concatenate until `90 00`.
//!
//! Keep-alive: NFC authenticators that need time (user presence) answer with
//! `91 00` (NFCCTAP_GETRESPONSE pending) — we re-poll with the GET-RESPONSE
//! instruction until a final answer arrives.
//!
//! ## Scope note
//!
//! Read/identity/management operations work over a reader. Fingerprint
//! *enrollment* may be refused by some keys over NFC/contact (they gate the
//! sensor to USB); that is a per-key firmware behaviour, not a limit of this
//! transport.

use keyroost_ctap::cmd::CtapError;
use keyroost_ctap::transport::CtapTransport;
use pcsc::{Card, Context, Protocols, Scope, ShareMode};

/// FIDO applet AID — `A0 00 00 06 47 2F 00 01`.
const FIDO_AID: [u8; 8] = [0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01];

/// `NFCCTAP_MSG` instruction class/byte (CTAP §11.2.3).
const NFCCTAP_CLA: u8 = 0x80;
const NFCCTAP_INS: u8 = 0x10;
/// Continuation-class bit for ISO 7816 command chaining.
const CLA_CHAIN: u8 = 0x10;

/// ISO 7816 `GET RESPONSE`.
const GET_RESPONSE_CLA: u8 = 0x00;
const GET_RESPONSE_INS: u8 = 0xC0;

/// Largest data field in a short-form command APDU.
const MAX_SHORT_DATA: usize = 255;

/// PC/SC receive buffer (large-blob reads can return a few KB per APDU).
const RECV_BUF: usize = 4096;

/// A FIDO2 authenticator reached over a PC/SC reader (NFC or contact).
pub struct CtapPcscDevice {
    /// `Option` so `Drop` can `take()` the card and disconnect it with
    /// `LeaveCard` (the `pcsc` default `Drop` resets the card, which disturbs a
    /// concurrent OTP read on the same contact reader — see the `Drop` impl).
    card: Option<Card>,
    /// Applet-select answer (`U2F_V2` / `FIDO_2_0`), retained for diagnostics.
    selected_version: Vec<u8>,
}

impl Drop for CtapPcscDevice {
    fn drop(&mut self) {
        // The pcsc crate's default Card drop hard-codes Disposition::ResetCard,
        // which resets the smart card. On a contact reader that reset collides
        // with any other session on the same card (e.g. the on-device OTP read
        // that runs right after the FIDO get-info), surfacing as
        // SCARD_W_RESET_CARD / a comms error. Disconnect with LeaveCard instead
        // so dropping a FIDO session leaves the card untouched.
        if let Some(card) = self.card.take() {
            let _ = card.disconnect(pcsc::Disposition::LeaveCard);
        }
    }
}

impl CtapPcscDevice {
    /// Connect to the named reader, select the FIDO applet, and return a ready
    /// transport. Fails if the reader has no card, or the card has no FIDO
    /// applet (e.g. an OATH-only or PIV-only card).
    pub fn open(reader_name: &str) -> Result<Self, CtapError> {
        let ctx = Context::establish(Scope::User)
            .map_err(|e| CtapError::Transport(format!("PC/SC unavailable: {e}")))?;
        let cname = std::ffi::CString::new(reader_name)
            .map_err(|_| CtapError::Transport("reader name contains NUL".into()))?;
        let card = ctx
            .connect(&cname, ShareMode::Shared, Protocols::ANY)
            .map_err(|e| CtapError::Transport(format!("connect to reader failed: {e}")))?;
        let mut dev = CtapPcscDevice {
            card: Some(card),
            selected_version: Vec::new(),
        };
        dev.select_fido_applet()?;
        Ok(dev)
    }

    /// The applet-select answer string (`U2F_V2` or `FIDO_2_0`).
    pub fn selected_version(&self) -> &[u8] {
        &self.selected_version
    }

    fn select_fido_applet(&mut self) -> Result<(), CtapError> {
        // SELECT by DF name: 00 A4 04 00 Lc <AID> 00
        let mut apdu = vec![0x00, 0xA4, 0x04, 0x00, FIDO_AID.len() as u8];
        apdu.extend_from_slice(&FIDO_AID);
        apdu.push(0x00); // Le
        let (data, sw1, sw2) = self.exchange_full(&apdu)?;
        if (sw1, sw2) != (0x90, 0x00) {
            return Err(CtapError::Transport(format!(
                "FIDO applet not present on this card (SELECT -> {sw1:02X}{sw2:02X})"
            )));
        }
        self.selected_version = data;
        Ok(())
    }

    /// One raw APDU exchange. Returns `(response_data, sw1, sw2)`.
    fn exchange(&mut self, apdu: &[u8]) -> Result<(Vec<u8>, u8, u8), CtapError> {
        let mut buf = [0u8; RECV_BUF];
        let card = self
            .card
            .as_mut()
            .ok_or_else(|| CtapError::Transport("card already disconnected".into()))?;
        let resp = card
            .transmit(apdu, &mut buf)
            .map_err(|e| CtapError::Transport(format!("APDU transmit failed: {e}")))?;
        if resp.len() < 2 {
            return Err(CtapError::Transport(format!(
                "APDU response too short ({} bytes)",
                resp.len()
            )));
        }
        let (data, sw) = resp.split_at(resp.len() - 2);
        Ok((data.to_vec(), sw[0], sw[1]))
    }

    /// Perform one APDU exchange and then drain any continuation the card
    /// signals, returning the fully-reassembled response data and the final
    /// status word.
    ///
    /// This is required for **contact (T=0)** readers: where an NFC (T=CL) card
    /// returns the response body inline with `90 00`, a T=0 card replies `61 XX`
    /// ("XX more bytes available — issue GET RESPONSE") and only yields the body
    /// across follow-up `00 C0 00 00 XX` calls. `6C XX` ("wrong Le, retry with
    /// XX") is handled by re-issuing the original APDU with the suggested length.
    /// `91 XX` is the NFC keep-alive (NFCCTAP_GETRESPONSE pending). Handling all
    /// of these in one place lets both applet SELECT and CTAP message exchange
    /// work over contact and contactless alike.
    fn exchange_full(&mut self, apdu: &[u8]) -> Result<(Vec<u8>, u8, u8), CtapError> {
        let (mut data, mut sw1, mut sw2) = self.exchange(apdu)?;
        loop {
            match (sw1, sw2) {
                (0x90, 0x00) => break,
                // More data available: GET RESPONSE for sw2 bytes (0 => 256).
                (0x61, n) => {
                    let get_response = [GET_RESPONSE_CLA, GET_RESPONSE_INS, 0x00, 0x00, n];
                    let (more, s1, s2) = self.exchange(&get_response)?;
                    data.extend_from_slice(&more);
                    sw1 = s1;
                    sw2 = s2;
                }
                // Wrong Le under T=0: re-issue the same command with the
                // length the card asked for (sw2), then continue draining.
                (0x6C, n) => {
                    let mut retry = apdu.to_vec();
                    // Replace/append the Le byte with the card-suggested length.
                    if let Some(last) = retry.last_mut() {
                        *last = n;
                    }
                    let (again, s1, s2) = self.exchange(&retry)?;
                    data = again;
                    sw1 = s1;
                    sw2 = s2;
                }
                // NFC keep-alive / processing: re-poll with GET RESPONSE.
                (0x91, _) => {
                    let get_response = [GET_RESPONSE_CLA, GET_RESPONSE_INS, 0x00, 0x00, 0x00];
                    let (more, s1, s2) = self.exchange(&get_response)?;
                    data.extend_from_slice(&more);
                    sw1 = s1;
                    sw2 = s2;
                }
                _ => break,
            }
        }
        Ok((data, sw1, sw2))
    }

    /// Send a full CTAP message body (command byte + CBOR) wrapped in
    /// `NFCCTAP_MSG`, using command chaining for long payloads, and collect the
    /// full response across any `61 XX` / `91 00` continuations.
    fn send_ctap_message(&mut self, message: &[u8]) -> Result<Vec<u8>, CtapError> {
        // Chain the request if it exceeds one short APDU.
        let chunks: Vec<&[u8]> = if message.is_empty() {
            vec![&[][..]]
        } else {
            message.chunks(MAX_SHORT_DATA).collect()
        };

        let mut last = (Vec::new(), 0u8, 0u8);
        for (i, chunk) in chunks.iter().enumerate() {
            let is_last = i + 1 == chunks.len();
            let cla = if is_last {
                NFCCTAP_CLA
            } else {
                NFCCTAP_CLA | CLA_CHAIN
            };
            let mut apdu = vec![cla, NFCCTAP_INS, 0x00, 0x00, chunk.len() as u8];
            apdu.extend_from_slice(chunk);
            apdu.push(0x00); // Le — expect a response
            if is_last {
                // Final piece: drain any 61xx/6Cxx/91xx continuation (contact T=0
                // and NFC keep-alive) into the full response.
                last = self.exchange_full(&apdu)?;
            } else {
                // Non-final chaining APDUs should answer 90 00 with no data.
                let r = self.exchange(&apdu)?;
                if (r.1, r.2) != (0x90, 0x00) {
                    return Err(CtapError::Transport(format!(
                        "command chaining rejected (SW {:02X}{:02X})",
                        r.1, r.2
                    )));
                }
            }
        }

        let (data, sw1, sw2) = last;
        if (sw1, sw2) != (0x90, 0x00) {
            return Err(CtapError::Transport(format!(
                "authenticator returned ISO status {sw1:02X}{sw2:02X}"
            )));
        }
        Ok(data)
    }
}

impl CtapTransport for CtapPcscDevice {
    /// Carry one CTAP exchange. The HID `cmd` byte is interpreted for the APDU
    /// world: `CTAPHID_CBOR` (and the U2F/MSG-style codes) map onto
    /// `NFCCTAP_MSG`. `CTAPHID_INIT` has no APDU analogue (channel setup is
    /// implicit once the applet is selected), so it is a no-op success.
    fn transact(&mut self, cmd: u8, payload: &[u8]) -> Result<Vec<u8>, CtapError> {
        use keyroost_ctap::hid::{CTAPHID_CBOR, CTAPHID_INIT};
        if cmd == CTAPHID_INIT {
            // No channel negotiation over APDU; report a benign empty response.
            return Ok(Vec::new());
        }
        if cmd != CTAPHID_CBOR {
            return Err(CtapError::Transport(format!(
                "CTAP command 0x{cmd:02X} is not supported over a smart-card reader"
            )));
        }
        self.send_ctap_message(payload)
    }
}
