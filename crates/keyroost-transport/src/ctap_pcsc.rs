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
    card: Card,
    /// Applet-select answer (`U2F_V2` / `FIDO_2_0`), retained for diagnostics.
    selected_version: Vec<u8>,
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
            card,
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
        let (data, sw1, sw2) = self.exchange(&apdu)?;
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
        let resp = self
            .card
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
            let cla = if is_last { NFCCTAP_CLA } else { NFCCTAP_CLA | CLA_CHAIN };
            let mut apdu = vec![cla, NFCCTAP_INS, 0x00, 0x00, chunk.len() as u8];
            apdu.extend_from_slice(chunk);
            apdu.push(0x00); // Le — expect a response
            last = self.exchange(&apdu)?;
            // Non-final chaining APDUs should answer 90 00 with no data.
            if !is_last && (last.1, last.2) != (0x90, 0x00) {
                return Err(CtapError::Transport(format!(
                    "command chaining rejected (SW {:02X}{:02X})",
                    last.1, last.2
                )));
            }
        }

        let (mut data, mut sw1, mut sw2) = last;

        // Pull any continued response.
        loop {
            match (sw1, sw2) {
                (0x90, 0x00) => break,
                // More data available: GET RESPONSE for sw2 bytes (0 => 256).
                (0x61, n) => {
                    let le = n;
                    let apdu = [GET_RESPONSE_CLA, GET_RESPONSE_INS, 0x00, 0x00, le];
                    let (more, s1, s2) = self.exchange(&apdu)?;
                    data.extend_from_slice(&more);
                    sw1 = s1;
                    sw2 = s2;
                }
                // NFC keep-alive / processing: re-poll with GET RESPONSE.
                (0x91, _) => {
                    let apdu = [GET_RESPONSE_CLA, GET_RESPONSE_INS, 0x00, 0x00, 0x00];
                    let (more, s1, s2) = self.exchange(&apdu)?;
                    data.extend_from_slice(&more);
                    sw1 = s1;
                    sw2 = s2;
                }
                (s1, s2) => {
                    return Err(CtapError::Transport(format!(
                        "authenticator returned ISO status {s1:02X}{s2:02X}"
                    )));
                }
            }
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
