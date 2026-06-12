//! PIV (NIST SP 800-73-4) over PC/SC.
//!
//! Drives the PIV smartcard application using the pure-byte builders/parsers in
//! [`keyroost_piv`]. Like the OATH and OpenPGP sessions, this adds the card
//! transmit, the `61xx` / GET RESPONSE reassembly loop, reader discovery, the
//! status view (version/serial/PIN-retries/per-slot certs), and the full
//! management surface: management-key mutual authentication (the AES/3DES
//! witness/challenge round — the only place this crate does block-cipher math),
//! PIN/PUK change and unblock, set-pin-retries, set-management-key, key
//! generation, certificate import/export, and applet reset.

use crate::{dump_cmd, hex_dump, TransportError};
use keyroost_piv as piv;
use keyroost_piv::{KeyAlg, Metadata, MgmtAlg, PinPolicy, PublicKey, Slot, TouchPolicy};
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

    /// GET METADATA for a key/PIN reference (`0x9B`, `0x80`, `0x81`, or a slot
    /// key ref). `None` when the firmware predates the extension (5.3-).
    pub fn metadata(&mut self, key_ref: u8) -> Option<Metadata> {
        let (data, sw) = self.transmit_full(&piv::get_metadata(key_ref)).ok()?;
        if sw != piv::SW_OK {
            return None;
        }
        piv::parse_metadata(&data).ok()
    }

    /// The card-management (9B) key's algorithm, from GET METADATA. Defaults to
    /// [`MgmtAlg::TripleDes`] when the card doesn't report it (pre-5.3 firmware,
    /// where 3DES was the only option).
    pub fn management_key_algorithm(&mut self) -> MgmtAlg {
        self.metadata(piv::KEY_REF_MANAGEMENT)
            .and_then(|m| m.algorithm)
            .and_then(MgmtAlg::from_id)
            .unwrap_or(MgmtAlg::TripleDes)
    }

    /// Authenticate to the card-management key via the GENERAL AUTHENTICATE
    /// witness/challenge round. Required before key generation, certificate
    /// import, set-management-key, and set-pin-retries. `alg` must match the
    /// card's stored management-key algorithm (see [`Self::management_key_algorithm`]).
    pub fn authenticate_management(
        &mut self,
        alg: MgmtAlg,
        key: &[u8],
    ) -> Result<(), TransportError> {
        if key.len() != alg.key_len() {
            return Err(TransportError::PivBadKeyLength);
        }
        // Step 1: ask the card for an encrypted witness.
        let (resp, sw) = self.transmit_full(&piv::general_auth_request_witness(
            alg,
            piv::KEY_REF_MANAGEMENT,
        ))?;
        ok_or_apdu("piv authenticate (request witness)", sw)?;
        let z1 = piv::parse_general_auth(&resp, 0x80).map_err(TransportError::PivParse)?;
        // Decrypt it with the management key — proves we hold the key.
        let witness = block_crypt(alg, key, z1, CryptOp::Decrypt)?;

        // Step 2: return the decrypted witness plus our own random challenge.
        let mut challenge = vec![0u8; alg.block_size()];
        getrandom::getrandom(&mut challenge)
            .map_err(|_| TransportError::MalformedResponse("OS RNG failed"))?;
        let (resp2, sw2) = self.transmit_full(&piv::general_auth_mutual(
            alg,
            piv::KEY_REF_MANAGEMENT,
            &witness,
            &challenge,
        ))?;
        // A wrong key makes the card reject our witness here.
        if sw2 != piv::SW_OK {
            return Err(TransportError::PivManagementAuthFailed);
        }
        // Verify the card encrypted our challenge correctly (authenticates the
        // card to us, completing mutual auth).
        let z2 = piv::parse_general_auth(&resp2, 0x82).map_err(TransportError::PivParse)?;
        let expected = block_crypt(alg, key, &challenge, CryptOp::Encrypt)?;
        if z2 != expected.as_slice() {
            return Err(TransportError::PivManagementAuthFailed);
        }
        Ok(())
    }

    /// Present the PIV application PIN. Required before private-key use and
    /// set-pin-retries.
    pub fn verify_pin(&mut self, pin: &[u8]) -> Result<(), TransportError> {
        let (_, sw) = self.transmit_full(&piv::verify_pin(pin))?;
        map_pin_sw(sw)
    }

    /// Change the PIV PIN. A wrong `old` PIN consumes a try and reports the
    /// remaining count.
    pub fn change_pin(&mut self, old: &[u8], new: &[u8]) -> Result<(), TransportError> {
        let (_, sw) =
            self.transmit_full(&piv::change_reference(piv::PIN_REF_APPLICATION, old, new))?;
        map_pin_sw(sw)
    }

    /// Change the PUK. A wrong `old` PUK consumes a try and reports the count.
    pub fn change_puk(&mut self, old: &[u8], new: &[u8]) -> Result<(), TransportError> {
        let (_, sw) = self.transmit_full(&piv::change_reference(piv::PIN_REF_PUK, old, new))?;
        map_pin_sw(sw)
    }

    /// Unblock a blocked PIN using the PUK, setting a new PIN. A wrong PUK
    /// consumes a try and reports the remaining count.
    pub fn unblock_pin(&mut self, puk: &[u8], new_pin: &[u8]) -> Result<(), TransportError> {
        let (_, sw) = self.transmit_full(&piv::unblock_pin(puk, new_pin))?;
        map_pin_sw(sw)
    }

    /// Set the PIN and PUK retry counts (resetting both to their defaults).
    /// Requires prior management-key auth **and** a verified PIN.
    pub fn set_pin_retries(&mut self, pin_tries: u8, puk_tries: u8) -> Result<(), TransportError> {
        let (_, sw) = self.transmit_full(&piv::set_pin_retries(pin_tries, puk_tries))?;
        ok_or_write("piv set pin retries", sw)
    }

    /// Replace the card-management key. Requires prior management-key auth.
    pub fn set_management_key(
        &mut self,
        alg: MgmtAlg,
        key: &[u8],
        require_touch: bool,
    ) -> Result<(), TransportError> {
        if key.len() != alg.key_len() {
            return Err(TransportError::PivBadKeyLength);
        }
        let (_, sw) = self.transmit_full(&piv::set_management_key(alg, key, require_touch))?;
        ok_or_write("piv set management key", sw)
    }

    /// Generate a fresh asymmetric key pair in `slot`, returning its public key.
    /// Requires prior management-key auth. Overwrites any existing key in the
    /// slot. May require a touch if the slot's touch policy demands it.
    pub fn generate_key(
        &mut self,
        slot: Slot,
        alg: KeyAlg,
        pin_policy: PinPolicy,
        touch_policy: TouchPolicy,
    ) -> Result<PublicKey, TransportError> {
        let (data, sw) =
            self.transmit_full(&piv::generate_key(slot, alg, pin_policy, touch_policy))?;
        ok_or_write("piv generate key", sw)?;
        piv::parse_public_key(&data).map_err(TransportError::PivParse)
    }

    /// Import a DER-encoded X.509 certificate into `slot`. Requires prior
    /// management-key auth.
    pub fn import_certificate(&mut self, slot: Slot, der: &[u8]) -> Result<(), TransportError> {
        let value = piv::encode_certificate(der);
        let (_, sw) = self.transmit_full(&piv::put_data(&slot.cert_object_tag(), &value))?;
        ok_or_write("piv import certificate", sw)
    }

    /// Read the DER-encoded certificate stored in `slot`, or `None` when the
    /// slot is empty. No PIN required (PIV certificates are public objects).
    pub fn read_certificate(&mut self, slot: Slot) -> Result<Option<Vec<u8>>, TransportError> {
        let (data, sw) = self.transmit_full(&piv::get_data(&slot.cert_object_tag()))?;
        if sw != piv::SW_OK {
            return Ok(None);
        }
        let inner = piv::unwrap_data_object(&data).map_err(TransportError::PivParse)?;
        // The cert object wraps the DER in a 0x70 TLV.
        Ok(find_tlv(inner, 0x70).map(<[u8]>::to_vec))
    }

    /// Reset the PIV application to factory defaults. Only succeeds when **both**
    /// the PIN and PUK are blocked (the card enforces this); otherwise the card
    /// returns `6983` and this maps to [`TransportError::PivSecurityNotSatisfied`].
    pub fn reset(&mut self) -> Result<(), TransportError> {
        let (_, sw) = self.transmit_full(&piv::reset())?;
        if sw == piv::SW_AUTH_BLOCKED {
            return Err(TransportError::PivSecurityNotSatisfied);
        }
        ok_or_write("piv reset", sw)
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
        // Redact bodies that carry secret material: VERIFY (20), CHANGE
        // REFERENCE DATA (24), RESET RETRY COUNTER (2C) carry PINs/PUKs;
        // GENERAL AUTHENTICATE (87) carries the decrypted witness/challenge;
        // SET MANAGEMENT KEY (FF) carries the raw new key.
        let cmd_sensitive = matches!(
            apdu.get(1),
            Some(0x20) | Some(0x24) | Some(0x2C) | Some(0x87) | Some(0xFF)
        );
        let mut acc = Vec::new();
        let mut to_send = apdu.to_vec();
        let mut chunks = 0usize;
        loop {
            if self.debug {
                eprintln!("> {:>14} >> {}", "piv", dump_cmd(&to_send, cmd_sensitive));
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
            chunks += 1;
            if acc.len() > crate::MAX_REASSEMBLED_RESPONSE || chunks > crate::MAX_RESPONSE_CHUNKS {
                return Err(TransportError::MalformedResponse(
                    "piv 61xx continuation exceeded reassembly limits",
                ));
            }
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

/// Like [`ok_or_apdu`] but maps the "security status not satisfied" word a write
/// returns when management-key auth or the PIN hasn't been presented.
fn ok_or_write(label: &'static str, sw: u16) -> Result<(), TransportError> {
    if sw == piv::SW_SECURITY_NOT_SATISFIED {
        Err(TransportError::PivSecurityNotSatisfied)
    } else {
        ok_or_apdu(label, sw)
    }
}

/// Map a PIN/PUK-verification status word: `9000` ok, `63 Cx` / `6983` rejected
/// with the remaining-try count, anything else a generic APDU error.
fn map_pin_sw(sw: u16) -> Result<(), TransportError> {
    if sw == piv::SW_OK {
        Ok(())
    } else if sw & 0xFFF0 == 0x63C0 {
        Err(TransportError::PivPinRejected {
            tries_remaining: Some((sw & 0x000F) as u8),
        })
    } else if sw == piv::SW_AUTH_BLOCKED {
        Err(TransportError::PivPinRejected {
            tries_remaining: Some(0),
        })
    } else {
        Err(TransportError::Apdu {
            label: "piv pin/puk",
            sw1: (sw >> 8) as u8,
            sw2: sw as u8,
        })
    }
}

/// What [`block_crypt`] should do with a block.
#[derive(Clone, Copy)]
enum CryptOp {
    Encrypt,
    Decrypt,
}

/// AES / 3DES ECB single-block (or block-aligned) transform for the
/// management-key witness/challenge round. `data` is one cipher block.
fn block_crypt(
    alg: MgmtAlg,
    key: &[u8],
    data: &[u8],
    op: CryptOp,
) -> Result<Vec<u8>, TransportError> {
    use cipher::generic_array::GenericArray;
    use cipher::{BlockDecrypt, BlockEncrypt, KeyInit};

    fn run<C: BlockEncrypt + BlockDecrypt>(c: &C, data: &[u8], op: CryptOp, bs: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len());
        for chunk in data.chunks(bs) {
            let mut block = GenericArray::clone_from_slice(chunk);
            match op {
                CryptOp::Encrypt => c.encrypt_block(&mut block),
                CryptOp::Decrypt => c.decrypt_block(&mut block),
            }
            out.extend_from_slice(&block);
        }
        out
    }

    let bad = |_| TransportError::PivBadKeyLength;
    match alg {
        MgmtAlg::TripleDes => {
            let c = des::TdesEde3::new_from_slice(key).map_err(bad)?;
            Ok(run(&c, data, op, 8))
        }
        MgmtAlg::Aes128 => {
            let c = aes::Aes128::new_from_slice(key).map_err(bad)?;
            Ok(run(&c, data, op, 16))
        }
        MgmtAlg::Aes192 => {
            let c = aes::Aes192::new_from_slice(key).map_err(bad)?;
            Ok(run(&c, data, op, 16))
        }
        MgmtAlg::Aes256 => {
            let c = aes::Aes256::new_from_slice(key).map_err(bad)?;
            Ok(run(&c, data, op, 16))
        }
    }
}

/// Find the value of the first top-level TLV with single-byte `tag`.
fn find_tlv(buf: &[u8], tag: u8) -> Option<&[u8]> {
    let mut i = 0;
    while i < buf.len() {
        let t = buf[i];
        let first = *buf.get(i + 1)?;
        let (len, header) = if first < 0x80 {
            (first as usize, 1)
        } else {
            let n = (first & 0x7F) as usize;
            if n == 0 || n > 2 {
                return None;
            }
            let bytes = buf.get(i + 2..i + 2 + n)?;
            (
                bytes.iter().fold(0usize, |a, &b| (a << 8) | b as usize),
                1 + n,
            )
        };
        let vstart = i + 1 + header;
        let vend = vstart.checked_add(len)?;
        let value = buf.get(vstart..vend)?;
        if t == tag {
            return Some(value);
        }
        i = vend;
    }
    None
}
