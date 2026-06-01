//! OpenPGP Card (v3.4) over PC/SC.
//!
//! Drives the OpenPGP applet using the pure-byte builders and parsers in
//! [`molto2_openpgp`]. The applet is a CCID/APDU smartcard applet present on
//! YubiKeys (verified on hardware) — though *not* on every Trussed build: the
//! test Solo 2's firmware answers `SELECT` with `6A82` (no applet).
//!
//! This layer adds what the byte layer left out: the card transmit, the `61xx` /
//! `GET RESPONSE` reassembly loop, reader discovery, and assembling a read-only
//! status view. Write operations (PUT DATA, key generation, PSO signing) and PIN
//! verification are deliberately not implemented yet — see the byte-layer TODOs.

use crate::{hex_dump, TransportError};
use molto2_openpgp as pgp;
use pcsc::{Card, Context, Protocols, Scope, ShareMode};

/// `SW 6A82`: selected file/application not found — i.e. no OpenPGP applet.
const SW_FILE_NOT_FOUND: u16 = 0x6A82;

/// A read-only snapshot of an OpenPGP card's state, assembled from the
/// Application Related Data (`6E`) and the signature counter (`7A`/`93`).
#[derive(Debug, Clone)]
pub struct OpenPgpStatus {
    /// Full application identifier (16 bytes: RID, version, manufacturer, serial).
    pub aid: Vec<u8>,
    /// Algorithm id (first attribute byte) of the signature key, if present.
    pub sig_algo_id: Option<u8>,
    /// Algorithm id of the decryption key.
    pub dec_algo_id: Option<u8>,
    /// Algorithm id of the authentication key.
    pub aut_algo_id: Option<u8>,
    /// Signature, decryption, and authentication key fingerprints (20 bytes each;
    /// all-zero when no key occupies that slot).
    pub fingerprint_sig: pgp::Fingerprint,
    pub fingerprint_dec: pgp::Fingerprint,
    pub fingerprint_aut: pgp::Fingerprint,
    /// Remaining PIN retry counters (PW1, resetting code, PW3).
    pub tries_pw1: u8,
    pub tries_rc: u8,
    pub tries_pw3: u8,
    /// Digital-signature counter (number of signatures made), if the card
    /// reported a Security Support Template.
    pub signature_count: Option<u32>,
}

impl OpenPgpStatus {
    /// The card serial number — the last 4 bytes of the AID (per the spec, the
    /// manufacturer-assigned serial sits at AID bytes 10..14).
    #[must_use]
    pub fn serial(&self) -> Option<u32> {
        self.aid
            .get(10..14)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
}

/// An open OpenPGP applet session on one PC/SC reader.
pub struct OpenPgpSession {
    card: Card,
    debug: bool,
}

impl OpenPgpSession {
    /// Connect to `reader_name` and SELECT the OpenPGP applet. Returns
    /// [`TransportError::NoOpenPgpApplet`] when the card has no OpenPGP applet.
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

    /// Names of connected readers whose OpenPGP applet answers `SELECT` with
    /// `9000`. Cards without the applet (e.g. the test Solo 2) are skipped, so a
    /// front-end can auto-pick a lone OpenPGP card or list the choices.
    pub fn list_openpgp_readers() -> Result<Vec<String>, TransportError> {
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
                let mut session = OpenPgpSession { card, debug: false };
                if session.select().is_ok() {
                    out.push(name.to_string_lossy().into_owned());
                }
            }
        }
        Ok(out)
    }

    fn select(&mut self) -> Result<(), TransportError> {
        let (_, sw) = self.transmit_full(&pgp::select())?;
        if sw == SW_FILE_NOT_FOUND {
            return Err(TransportError::NoOpenPgpApplet);
        }
        ok_or_apdu("select openpgp applet", sw)
    }

    /// Read a status snapshot: Application Related Data plus the signature
    /// counter. Read-only — no PIN, no touch.
    pub fn status(&mut self) -> Result<OpenPgpStatus, TransportError> {
        let (ard_bytes, sw) = self.transmit_full(&pgp::get_application_related_data())?;
        ok_or_apdu("get application related data", sw)?;
        let ard =
            pgp::parse_application_related_data(&ard_bytes).map_err(TransportError::OpenPgpParse)?;

        // The signature counter lives in the Security Support Template (007A).
        // It's optional; absence or a parse miss just leaves the count unknown.
        let signature_count = match self.transmit_full(&pgp::get_data(pgp::TAG_SECURITY_SUPPORT)) {
            Ok((bytes, sw)) if sw == pgp::SW_OK => pgp::parse_signature_counter(&bytes).ok(),
            _ => None,
        };

        Ok(OpenPgpStatus {
            sig_algo_id: ard.sig_algo_id(),
            dec_algo_id: ard.dec_algo_id(),
            aut_algo_id: ard.aut_algo_id(),
            aid: ard.aid,
            fingerprint_sig: ard.fingerprint_sig,
            fingerprint_dec: ard.fingerprint_dec,
            fingerprint_aut: ard.fingerprint_aut,
            tries_pw1: ard.pw_status.tries_pw1,
            tries_rc: ard.pw_status.tries_rc,
            tries_pw3: ard.pw_status.tries_pw3,
            signature_count,
        })
    }

    /// Present a PIN against the password reference `pw_ref` (one of
    /// [`molto2_openpgp::PW1_SIGN`], [`molto2_openpgp::PW1_OTHER`],
    /// [`molto2_openpgp::PW3_ADMIN`]). A wrong PIN is reported as
    /// [`TransportError::OpenPgpPinRejected`] carrying the remaining-tries count.
    /// The PIN bytes come from the caller and are never logged or stored.
    /// Convenience: verify the admin PIN (PW3). Lets front-ends gate write
    /// operations without naming the `molto2-openpgp` PW reference constants.
    pub fn verify_admin_pin(&mut self, pin: &[u8]) -> Result<(), TransportError> {
        self.verify_pin(pgp::PW3_ADMIN, pin)
    }

    pub fn verify_pin(&mut self, pw_ref: u8, pin: &[u8]) -> Result<(), TransportError> {
        let (_, sw) = self.transmit_full(&pgp::verify(pw_ref, pin))?;
        if sw == pgp::SW_OK {
            return Ok(());
        }
        // Spec form: 63Cx = verification failed, x tries remaining.
        if (sw & 0xFFF0) == 0x63C0 {
            return Err(TransportError::OpenPgpPinRejected {
                tries_remaining: Some((sw & 0x000F) as u8),
            });
        }
        // YubiKey form: a failed VERIFY returns 6982/6983 without an embedded
        // count. Read the PW status to report the actual remaining tries.
        if sw == 0x6982 || sw == 0x6983 {
            let tries_remaining = self.pin_tries_for(pw_ref);
            return Err(TransportError::OpenPgpPinRejected { tries_remaining });
        }
        Err(TransportError::Apdu {
            label: "openpgp verify",
            sw1: (sw >> 8) as u8,
            sw2: sw as u8,
        })
    }

    /// Remaining tries for the counter behind `pw_ref`, read from the PW status
    /// bytes (`C4`). `None` if the status can't be read/parsed.
    fn pin_tries_for(&mut self, pw_ref: u8) -> Option<u8> {
        let (bytes, sw) = self.transmit_full(&pgp::get_pw_status()).ok()?;
        if sw != pgp::SW_OK {
            return None;
        }
        let status = pgp::parse_pw_status(&bytes).ok()?;
        match pw_ref {
            pgp::PW3_ADMIN => Some(status.tries_pw3),
            _ => Some(status.tries_pw1), // PW1_SIGN / PW1_OTHER
        }
    }

    /// Generate a fresh asymmetric key pair in the given slot and return its
    /// public key. **Destructive** — overwrites any existing key in that slot.
    /// Requires the admin PIN (PW3) to have been verified first via
    /// [`verify_pin`](Self::verify_pin); on a YubiKey it also needs a touch.
    pub fn generate_key(&mut self, crt: pgp::KeyCrt) -> Result<pgp::PublicKey, TransportError> {
        let (data, sw) = self.transmit_full(&pgp::generate_key(crt))?;
        ok_or_apdu("openpgp generate key", sw)?;
        pgp::parse_generated_public_key(&data).map_err(TransportError::OpenPgpParse)
    }

    /// Import an existing RSA private key into `crt`'s slot (PUT DATA with the
    /// `4D` Extended Header List). **Destructive** — overwrites any existing key
    /// in that slot. Requires the admin PIN (PW3) verified first. The key parts
    /// (big-endian) come from the caller; this layer transmits them once and
    /// never stores them.
    ///
    /// The card *dictates* the import format and exponent length via its
    /// algorithm attributes, so this first reads them (a read-only GET DATA)
    /// and builds the Extended Header List to match — real YubiKeys (5.7)
    /// declare the CRT format and reject the bare `e`/`p`/`q` triple with
    /// `SW=6A80`. GnuPG branches on the same attribute byte.
    pub fn import_key(
        &mut self,
        crt: pgp::KeyCrt,
        key: &pgp::RsaPrivateKeyParts,
    ) -> Result<(), TransportError> {
        let attrs = self.rsa_attributes(crt)?;

        // Setting MOLTO_OPENPGP_FORCE_CHAINING forces the command-chaining path
        // (so the fallback can be exercised on a card that also accepts extended
        // length, e.g. for verification). Otherwise: extended length first.
        if std::env::var_os("MOLTO_OPENPGP_FORCE_CHAINING").is_none() {
            let apdu = pgp::import_rsa_key(crt, key, attrs.format, attrs.e_bits);
            let (_, sw) = self.transmit_full(&apdu)?;
            if sw == pgp::SW_OK {
                return Ok(());
            }
            // `6700` (wrong length) / `6883` (last command of chain expected)
            // mean the card/reader won't take a single extended-`Lc` APDU — fall
            // back to ISO command chaining. Any other SW is a genuine error
            // (e.g. `6A80` bad data, `6982` no PW3) and is surfaced as-is.
            if sw != 0x6700 && sw != 0x6883 {
                return ok_or_apdu("openpgp import key", sw);
            }
            if self.debug {
                eprintln!(
                    "! openpgp import: extended length rejected (SW={sw:04X}); \
                     retrying with command chaining"
                );
            }
        } else if self.debug {
            eprintln!("! openpgp import: forcing command chaining (env override)");
        }

        let chunks = pgp::import_rsa_key_chained(crt, key, attrs.format, attrs.e_bits, 254);
        self.transmit_chain("openpgp import key", &chunks).map(|_| ())
    }

    /// Transmit an ISO 7816 command-chaining sequence: each intermediate chunk
    /// must be accepted with `9000`; the final chunk's status word is the
    /// command result, and its (reassembled) response payload is returned. Used
    /// by the chaining fallbacks of [`import_key`](Self::import_key) (which
    /// discards the empty payload) and [`decrypt`](Self::decrypt).
    fn transmit_chain(
        &mut self,
        label: &'static str,
        chunks: &[Vec<u8>],
    ) -> Result<Vec<u8>, TransportError> {
        let last = chunks.len().saturating_sub(1);
        for (i, chunk) in chunks.iter().enumerate() {
            let (data, sw) = self.transmit_full(chunk)?;
            if i == last {
                ok_or_apdu(label, sw)?;
                return Ok(data);
            }
            // An intermediate chain link the card didn't accept (anything but
            // 9000) aborts the chain.
            if sw != pgp::SW_OK {
                return Err(TransportError::Apdu {
                    label,
                    sw1: (sw >> 8) as u8,
                    sw2: sw as u8,
                });
            }
        }
        Ok(Vec::new()) // unreachable for a non-empty chunk list
    }

    /// Read and parse the RSA algorithm attributes for `crt`'s slot from the
    /// Application Related Data (`6E`). Errors if the slot isn't RSA.
    fn rsa_attributes(&mut self, crt: pgp::KeyCrt) -> Result<pgp::RsaAttributes, TransportError> {
        let (ard_bytes, sw) = self.transmit_full(&pgp::get_application_related_data())?;
        ok_or_apdu("get application related data", sw)?;
        let ard =
            pgp::parse_application_related_data(&ard_bytes).map_err(TransportError::OpenPgpParse)?;
        let attr = match crt {
            pgp::KeyCrt::Sign => &ard.algo_attr_sig,
            pgp::KeyCrt::Decrypt => &ard.algo_attr_dec,
            pgp::KeyCrt::Auth => &ard.algo_attr_aut,
        };
        pgp::parse_rsa_algorithm_attributes(attr).map_err(TransportError::OpenPgpParse)
    }

    /// Read the public key currently in `crt`'s slot. Read-only; no PIN. Returns
    /// an `OpenPgpParse` error if the slot is empty or holds a non-RSA key.
    pub fn read_public_key(&mut self, crt: pgp::KeyCrt) -> Result<pgp::PublicKey, TransportError> {
        let (data, sw) = self.transmit_full(&pgp::read_public_key(crt))?;
        ok_or_apdu("openpgp read public key", sw)?;
        pgp::parse_generated_public_key(&data).map_err(TransportError::OpenPgpParse)
    }

    /// Compute a signature over `digest_info` (PSO:CDS). The caller supplies the
    /// already-hashed DigestInfo. Requires PW1 (signing context, ref `0x81`)
    /// verified first; on a YubiKey it also needs a touch. Returns the raw
    /// signature bytes.
    pub fn sign(&mut self, digest_info: &[u8]) -> Result<Vec<u8>, TransportError> {
        let (sig, sw) = self.transmit_full(&pgp::pso_compute_signature(digest_info))?;
        ok_or_apdu("openpgp compute signature", sw)?;
        Ok(sig)
    }

    /// Decrypt an RSA `cryptogram` with the on-card decryption key
    /// (PSO:DECIPHER) and return the recovered plaintext. `cryptogram` is the
    /// raw RSA-encrypted value (for RSA-2048, 256 bytes — e.g. a PKCS#1 v1.5
    /// type-2 block raised to the public exponent under the slot's modulus); the
    /// card applies the private key and strips the PKCS#1 padding. Requires PW1
    /// verified in the "other"/decipher context ([`molto2_openpgp::PW1_OTHER`]);
    /// on a YubiKey it also needs a touch.
    ///
    /// The RSA cipher DO is a `0x00` padding-indicator byte followed by the
    /// cryptogram (257 bytes for RSA-2048), which exceeds the short-APDU limit,
    /// so this sends an extended-length APDU and falls back to ISO command
    /// chaining on `6700` / `6883` — the same strategy as
    /// [`import_key`](Self::import_key). `MOLTO_OPENPGP_FORCE_CHAINING` forces
    /// the chaining path for testing.
    pub fn decrypt(&mut self, cryptogram: &[u8]) -> Result<Vec<u8>, TransportError> {
        // RSA cipher DO: 0x00 padding-indicator byte + the cryptogram.
        let mut data = Vec::with_capacity(1 + cryptogram.len());
        data.push(0x00);
        data.extend_from_slice(cryptogram);

        if std::env::var_os("MOLTO_OPENPGP_FORCE_CHAINING").is_none() {
            let (plain, sw) = self.transmit_full(&pgp::pso_decipher(&data))?;
            if sw == pgp::SW_OK {
                return Ok(plain);
            }
            // Only a length/chaining rejection warrants the fallback; any other
            // SW (e.g. 6982 no PW1, 6A80 bad cryptogram) is a real error.
            if sw != 0x6700 && sw != 0x6883 {
                ok_or_apdu("openpgp decipher", sw)?;
            }
            if self.debug {
                eprintln!(
                    "! openpgp decipher: extended length rejected (SW={sw:04X}); \
                     retrying with command chaining"
                );
            }
        } else if self.debug {
            eprintln!("! openpgp decipher: forcing command chaining (env override)");
        }

        let chunks = pgp::pso_decipher_chained(&data, 254);
        self.transmit_chain("openpgp decipher", &chunks)
    }

    /// Write the cardholder name (`PUT DATA 005B`). Requires admin PIN (PW3)
    /// verified first. The name is the caller's UTF-8 bytes (the OpenPGP
    /// convention is `Surname<<Given`, but the card stores it verbatim).
    pub fn set_cardholder_name(&mut self, name: &[u8]) -> Result<(), TransportError> {
        let (_, sw) = self.transmit_full(&pgp::put_cardholder_name(name))?;
        ok_or_apdu("openpgp put cardholder name", sw)
    }

    /// Write the public-key URL (`PUT DATA 5F50`). Requires admin PIN (PW3).
    pub fn set_url(&mut self, url: &[u8]) -> Result<(), TransportError> {
        let (_, sw) = self.transmit_full(&pgp::put_url(url))?;
        ok_or_apdu("openpgp put url", sw)
    }

    /// Register the key in `crt`'s slot so an OpenPGP tool (e.g. gpg) recognizes
    /// it: writes the key's v4 fingerprint and a generation timestamp via
    /// PUT DATA. Reads the slot's public key to compute the fingerprint over the
    /// given `creation_time` (which must match what's stored, or gpg will compute
    /// a different fingerprint). Requires admin PIN (PW3) verified first. Returns
    /// the fingerprint written.
    ///
    /// Note: on-card generation already sets these on a YubiKey, but writing them
    /// explicitly makes the registration deterministic and works for imported
    /// keys / cards that don't auto-populate them.
    pub fn register_key(
        &mut self,
        crt: pgp::KeyCrt,
        creation_time: u32,
    ) -> Result<[u8; 20], TransportError> {
        let key = self.read_public_key(crt)?;
        let fpr = pgp::rsa_v4_fingerprint_from(&key, creation_time);
        let (_, sw) = self.transmit_full(&pgp::put_generation_time(crt, creation_time))?;
        ok_or_apdu("openpgp put generation time", sw)?;
        let (_, sw) = self.transmit_full(&pgp::put_fingerprint(crt, &fpr))?;
        ok_or_apdu("openpgp put fingerprint", sw)?;
        Ok(fpr)
    }

    /// Factory-reset the OpenPGP applet: wipe ALL key slots, fingerprints, and
    /// metadata and restore the default PINs (PW1 `123456`, PW3 `12345678`).
    /// **Destructive and irreversible.**
    ///
    /// TERMINATE DF requires either PW3 (admin) rights or that both PW1 and PW3
    /// are already blocked. To work unconditionally — including the
    /// forgotten-PIN case, and without ever needing the real PIN — this first
    /// *blocks* PW1 and PW3 by exhausting their retry counters with deliberately
    /// wrong guesses, then issues TERMINATE DF + ACTIVATE FILE. (This is the same
    /// approach `ykman` uses.)
    pub fn factory_reset(&mut self) -> Result<(), TransportError> {
        // Read how many tries each PIN has so we exhaust exactly that many.
        let (pw1_tries, pw3_tries) = match self.transmit_full(&pgp::get_pw_status()) {
            Ok((bytes, sw)) if sw == pgp::SW_OK => match pgp::parse_pw_status(&bytes) {
                Ok(s) => (s.tries_pw1, s.tries_pw3),
                // Unknown counts: 15 is the max any OpenPGP card allows.
                Err(_) => (15, 15),
            },
            _ => (15, 15),
        };
        // A guess that cannot be a real PIN (PINs are >= 6 / 8 digits). Looping
        // until the card reports blocked (6983) guards against the count being
        // stale; the trailing guesses past zero just keep returning 6983.
        let bogus = b"00000000";
        self.block_pin(pgp::PW1_OTHER, bogus, pw1_tries);
        self.block_pin(pgp::PW3_ADMIN, bogus, pw3_tries);

        let (_, sw) = self.transmit_full(&pgp::terminate_df())?;
        ok_or_apdu("openpgp terminate df", sw)?;
        let (_, sw) = self.transmit_full(&pgp::activate_file())?;
        ok_or_apdu("openpgp activate file", sw)
    }

    /// Exhaust a PIN's retry counter with wrong guesses so it becomes blocked.
    /// Sends up to `max_tries + 1` attempts, stopping early once the card reports
    /// the PIN blocked (`6983`). Best-effort: transmit errors abort the loop.
    fn block_pin(&mut self, pw_ref: u8, bogus: &[u8], max_tries: u8) {
        for _ in 0..max_tries.saturating_add(1) {
            match self.transmit_full(&pgp::verify(pw_ref, bogus)) {
                Ok((_, 0x6983)) => break, // blocked
                Ok(_) => {}
                Err(_) => break,
            }
        }
    }

    /// Transmit one APDU and reassemble a response the card splits across `61xx`
    /// continuations (`GET RESPONSE`), returning `(payload, sw)`.
    fn transmit_full(&mut self, apdu: &[u8]) -> Result<(Vec<u8>, u16), TransportError> {
        let mut acc = Vec::new();
        let mut to_send = apdu.to_vec();
        loop {
            if self.debug {
                eprintln!("> {:>14} >> {}", "openpgp", hex_dump(&to_send));
            }
            let mut buf = [0u8; 4096];
            let resp = self.card.transmit(&to_send, &mut buf)?;
            if self.debug {
                eprintln!("< {:>14} << {}", "openpgp", hex_dump(resp));
            }
            if resp.len() < 2 {
                return Err(TransportError::ShortResponse {
                    label: "openpgp apdu",
                    got: resp.len(),
                    expected_min: 2,
                });
            }
            let (data, sw) = resp.split_at(resp.len() - 2);
            acc.extend_from_slice(data);
            if sw[0] == pgp::SW_MORE_DATA {
                // The low byte hints at how many bytes remain (0 = up to 256);
                // GET RESPONSE pulls the next chunk regardless.
                to_send = pgp::get_response();
                continue;
            }
            return Ok((acc, u16::from_be_bytes([sw[0], sw[1]])));
        }
    }
}

/// Map an OpenPGP status word to success or a labelled APDU error.
fn ok_or_apdu(label: &'static str, sw: u16) -> Result<(), TransportError> {
    if sw == pgp::SW_OK {
        Ok(())
    } else {
        Err(TransportError::Apdu {
            label,
            sw1: (sw >> 8) as u8,
            sw2: sw as u8,
        })
    }
}
