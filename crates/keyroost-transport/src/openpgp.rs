//! OpenPGP Card (v3.4) over PC/SC.
//!
//! Drives the OpenPGP applet using the pure-byte builders and parsers in
//! [`keyroost_openpgp`]. The applet is a CCID/APDU smartcard applet present on
//! YubiKeys (verified on hardware) — though *not* on every Trussed build: the
//! test Solo 2's firmware answers `SELECT` with `6A82` (no applet).
//!
//! This layer adds what the byte layer left out: the card transmit, the `61xx` /
//! `GET RESPONSE` reassembly loop, reader discovery, the read-only status view,
//! PIN verification/changes, key generation and import, PSO signing/decryption,
//! and factory reset.

use crate::TransportError;
use keyroost_openpgp as pgp;
use pcsc::{Card, Context, Protocols, Scope, ShareMode};
use zeroize::Zeroizing;

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
    /// Raw algorithm attributes (`C1`/`C2`/`C3`); render with [`algorithm_label`](Self::algorithm_label).
    pub sig_attrs: Vec<u8>,
    pub dec_attrs: Vec<u8>,
    pub aut_attrs: Vec<u8>,
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

    /// Human label of the algorithm in `crt`'s slot (`RSA-2048`, `EdDSA
    /// Ed25519`, …), or `none` for an empty attributes object. Never fails.
    #[must_use]
    pub fn algorithm_label(&self, crt: pgp::KeyCrt) -> String {
        let attrs = match crt {
            pgp::KeyCrt::Sign => &self.sig_attrs,
            pgp::KeyCrt::Decrypt => &self.dec_attrs,
            pgp::KeyCrt::Auth => &self.aut_attrs,
        };
        pgp::describe_algorithm_attributes(attrs)
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
                // Release without resetting (pcsc's `Drop` hard-codes
                // ResetCard) — probing must not disturb cards other sessions
                // hold open.
                let _ = session.card.disconnect(pcsc::Disposition::LeaveCard);
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
        let ard = pgp::parse_application_related_data(&ard_bytes)
            .map_err(TransportError::OpenPgpParse)?;

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
            sig_attrs: ard.algo_attr_sig,
            dec_attrs: ard.algo_attr_dec,
            aut_attrs: ard.algo_attr_aut,
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
    /// [`keyroost_openpgp::PW1_SIGN`], [`keyroost_openpgp::PW1_OTHER`],
    /// [`keyroost_openpgp::PW3_ADMIN`]). A wrong PIN is reported as
    /// [`TransportError::OpenPgpPinRejected`] carrying the remaining-tries count.
    /// The PIN bytes come from the caller and are never logged or stored.
    /// Convenience: verify the admin PIN (PW3). Lets front-ends gate write
    /// operations without naming the `keyroost-openpgp` PW reference constants.
    pub fn verify_admin_pin(&mut self, pin: &[u8]) -> Result<(), TransportError> {
        self.verify_pin(pgp::PW3_ADMIN, pin)
    }

    pub fn verify_pin(&mut self, pw_ref: u8, pin: &[u8]) -> Result<(), TransportError> {
        let apdu = Zeroizing::new(pgp::verify(pw_ref, pin));
        let (_, sw) = self.transmit_full(&apdu)?;
        if sw == pgp::SW_OK {
            return Ok(());
        }
        // Spec form: 63Cx = verification failed, x tries remaining.
        if let Some(n) = crate::sw_tries_remaining(sw) {
            return Err(TransportError::OpenPgpPinRejected {
                tries_remaining: Some(n),
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

    /// Map a non-OK status word from a PIN-presenting command to a
    /// tries-remaining [`TransportError::OpenPgpPinRejected`] when it signals a
    /// wrong PIN (`63Cx`, or `6982`/`6983` followed by a PW-status read), else a
    /// generic APDU error labelled `label`.
    fn pin_rejected(&mut self, sw: u16, pw_ref: u8, label: &'static str) -> TransportError {
        if let Some(n) = crate::sw_tries_remaining(sw) {
            return TransportError::OpenPgpPinRejected {
                tries_remaining: Some(n),
            };
        }
        if sw == 0x6982 || sw == 0x6983 {
            return TransportError::OpenPgpPinRejected {
                tries_remaining: self.pin_tries_for(pw_ref),
            };
        }
        TransportError::Apdu {
            label,
            sw1: (sw >> 8) as u8,
            sw2: sw as u8,
        }
    }

    /// Change the PIN behind `pw_ref` (PW1 `0x81` for the user PIN, PW3 `0x83`
    /// for the admin PIN) from `old` to `new`. A wrong `old` is reported as a
    /// tries-remaining error. No prior VERIFY is required — CHANGE REFERENCE
    /// DATA carries the old PIN itself. PINs come from the caller and are never
    /// stored or logged.
    pub fn change_pin(&mut self, pw_ref: u8, old: &[u8], new: &[u8]) -> Result<(), TransportError> {
        let apdu = Zeroizing::new(pgp::change_reference_data(pw_ref, old, new));
        let (_, sw) = self.transmit_full(&apdu)?;
        if sw == pgp::SW_OK {
            return Ok(());
        }
        Err(self.pin_rejected(sw, pw_ref, "openpgp change pin"))
    }

    /// Change the user PIN (PW1) from `old` to `new`.
    pub fn change_user_pin(&mut self, old: &[u8], new: &[u8]) -> Result<(), TransportError> {
        self.change_pin(pgp::PW1_SIGN, old, new)
    }

    /// Change the admin PIN (PW3) from `old` to `new`.
    pub fn change_admin_pin(&mut self, old: &[u8], new: &[u8]) -> Result<(), TransportError> {
        self.change_pin(pgp::PW3_ADMIN, old, new)
    }

    /// Unblock the user PIN (PW1) and set it to `new_user_pin`, authorised by the
    /// admin PIN (PW3). Verifies PW3 first (a wrong admin PIN is reported as a
    /// tries-remaining error), then issues RESET RETRY COUNTER. Recovers a card
    /// whose user PIN is blocked without a factory reset. PINs come from the
    /// caller and are never stored or logged.
    pub fn reset_retry_counter(
        &mut self,
        admin_pin: &[u8],
        new_user_pin: &[u8],
    ) -> Result<(), TransportError> {
        self.verify_pin(pgp::PW3_ADMIN, admin_pin)?;
        let apdu = Zeroizing::new(pgp::reset_retry_counter(new_user_pin));
        let (_, sw) = self.transmit_full(&apdu)?;
        ok_or_apdu("openpgp reset retry counter", sw)
    }

    /// Generate a fresh asymmetric key pair in the given slot and return its
    /// public key. **Destructive** — overwrites any existing key in that slot.
    /// Requires the admin PIN (PW3) to have been verified first via
    /// [`verify_pin`](Self::verify_pin); on a YubiKey it also needs a touch.
    ///
    /// `alg`: `Some` sets the slot's algorithm first when it differs (the
    /// attribute write is only issued when needed, since it wipes the slot —
    /// which the GENERATE overwrites anyway); `None` generates whatever the
    /// slot's current attributes say.
    pub fn generate_key(
        &mut self,
        crt: pgp::KeyCrt,
        alg: Option<pgp::KeyAlg>,
    ) -> Result<pgp::PublicKey, TransportError> {
        if let Some(alg) = alg {
            let current = self.algorithm_attributes(crt)?;
            if needs_attribute_write(&current, alg) {
                if self.debug {
                    eprintln!(
                        "! openpgp generate: setting {crt:?} slot algorithm to {}",
                        alg.label()
                    );
                }
                self.set_algorithm(crt, alg)?;
            }
        }
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

        // The card declares its exponent-field width; the pure builders return
        // a typed ExponentTooWide if the key's exponent is wider. Reject a
        // malformed/hostile attribute (e.g. e_bits=8 against e=65537) here
        // first, before any build work — redundant defense in front of the
        // byte layer's own error.
        if !pgp::rsa_exponent_fits(key.e, attrs.e_bits) {
            return Err(TransportError::OpenPgpExponentTooWide);
        }

        // Setting KEYROOST_OPENPGP_FORCE_CHAINING forces the command-chaining path
        // (so the fallback can be exercised on a card that also accepts extended
        // length, e.g. for verification). Otherwise: extended length first.
        if std::env::var_os("KEYROOST_OPENPGP_FORCE_CHAINING").is_none() {
            let apdu = Zeroizing::new(
                pgp::import_rsa_key(crt, key, attrs.format, attrs.e_bits)
                    .map_err(|_| TransportError::OpenPgpExponentTooWide)?,
            );
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

        let chunks: Vec<Zeroizing<Vec<u8>>> =
            pgp::import_rsa_key_chained(crt, key, attrs.format, attrs.e_bits, 254)
                .map_err(|_| TransportError::OpenPgpExponentTooWide)?
                .into_iter()
                .map(Zeroizing::new)
                .collect();
        self.transmit_chain("openpgp import key", &chunks)
            .map(|_| ())
    }

    /// Transmit an ISO 7816 command-chaining sequence: each intermediate chunk
    /// must be accepted with `9000`; the final chunk's status word is the
    /// command result, and its (reassembled) response payload is returned. Used
    /// by the chaining fallbacks of [`import_key`](Self::import_key) (which
    /// discards the empty payload and passes `Zeroizing` chunks so the key
    /// material wipes on drop) and [`decrypt`](Self::decrypt).
    fn transmit_chain<T: AsRef<[u8]>>(
        &mut self,
        label: &'static str,
        chunks: &[T],
    ) -> Result<Vec<u8>, TransportError> {
        let last = chunks.len().saturating_sub(1);
        for (i, chunk) in chunks.iter().enumerate() {
            let (data, sw) = self.transmit_full(chunk.as_ref())?;
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

    /// Raw algorithm attributes (`C1`/`C2`/`C3`) of `crt`'s slot, from a fresh
    /// Application Related Data read. Read-only; no PIN.
    pub fn algorithm_attributes(&mut self, crt: pgp::KeyCrt) -> Result<Vec<u8>, TransportError> {
        let (ard_bytes, sw) = self.transmit_full(&pgp::get_application_related_data())?;
        ok_or_apdu("get application related data", sw)?;
        let ard = pgp::parse_application_related_data(&ard_bytes)
            .map_err(TransportError::OpenPgpParse)?;
        Ok(match crt {
            pgp::KeyCrt::Sign => ard.algo_attr_sig,
            pgp::KeyCrt::Decrypt => ard.algo_attr_dec,
            pgp::KeyCrt::Auth => ard.algo_attr_aut,
        })
    }

    /// Set `crt`'s slot to `alg` (PUT DATA of the algorithm attributes).
    /// **Destructive**: cards wipe the slot's key when its algorithm changes.
    /// Requires PW3 verified first. A slot/algorithm combination that doesn't
    /// exist (Ed25519 in the decryption slot, X25519 elsewhere) is
    /// [`TransportError::OpenPgpSlotMismatch`]; a card that doesn't allow the
    /// change (or that algorithm) answers with an APDU error, surfaced as-is.
    pub fn set_algorithm(
        &mut self,
        crt: pgp::KeyCrt,
        alg: pgp::KeyAlg,
    ) -> Result<(), TransportError> {
        let attr = alg
            .attributes(crt)
            .map_err(TransportError::OpenPgpSlotMismatch)?;
        let (_, sw) = self.transmit_full(&pgp::put_algorithm_attributes(crt, &attr))?;
        ok_or_apdu("openpgp set algorithm attributes", sw)
    }

    /// The algorithms the card reports each slot accepts (Algorithm Information,
    /// `FA`), or `Ok(None)` when the card doesn't publish it (pre-3.4 cards) —
    /// callers then offer every algorithm and let the card's status word
    /// answer. Read-only; no PIN.
    pub fn supported_algorithms(
        &mut self,
    ) -> Result<Option<pgp::AlgorithmInformation>, TransportError> {
        let (bytes, sw) = self.transmit_full(&pgp::get_algorithm_information())?;
        if sw != pgp::SW_OK {
            if self.debug {
                eprintln!(
                    "! openpgp: card has no Algorithm Information object (SW={sw:04X}); \
                     offering every algorithm"
                );
            }
            return Ok(None);
        }
        let parsed = pgp::parse_algorithm_information(&bytes).ok();
        if parsed.is_none() && self.debug {
            eprintln!(
                "! openpgp: Algorithm Information object did not parse; offering every algorithm"
            );
        }
        Ok(parsed)
    }

    /// Read and parse the RSA algorithm attributes for `crt`'s slot. Errors
    /// with [`TransportError::OpenPgpSlotNotRsa`] if the slot holds an ECC
    /// key instead.
    fn rsa_attributes(&mut self, crt: pgp::KeyCrt) -> Result<pgp::RsaAttributes, TransportError> {
        let attr = self.algorithm_attributes(crt)?;
        match pgp::parse_algorithm_attributes(&attr) {
            Ok(pgp::AlgorithmAttributes::Rsa(r)) => Ok(r),
            Ok(ecc @ pgp::AlgorithmAttributes::Ecc { .. }) => {
                Err(TransportError::OpenPgpSlotNotRsa {
                    slot: crt_flag_name(crt),
                    label: ecc.label(),
                })
            }
            Err(e) => Err(TransportError::OpenPgpParse(e)),
        }
    }

    /// Read the public key currently in `crt`'s slot. Read-only; no PIN. Returns
    /// an `OpenPgpParse` error if the slot is empty or holds a key of a kind
    /// this crate can't parse.
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

    /// Produce a client-authentication signature over `auth_input` with the
    /// on-card Authentication key (INTERNAL AUTHENTICATE). The caller supplies the
    /// already-hashed PKCS#1 `DigestInfo`. Requires PW1 verified in the "other"
    /// context ([`keyroost_openpgp::PW1_OTHER`]) first; on a YubiKey it also needs
    /// a touch. Returns the raw signature bytes.
    pub fn internal_authenticate(&mut self, auth_input: &[u8]) -> Result<Vec<u8>, TransportError> {
        let (sig, sw) = self.transmit_full(&pgp::internal_authenticate(auth_input))?;
        ok_or_apdu("openpgp internal authenticate", sw)?;
        Ok(sig)
    }

    /// Decrypt an RSA `cryptogram` with the on-card decryption key
    /// (PSO:DECIPHER) and return the recovered plaintext. `cryptogram` is the
    /// raw RSA-encrypted value (for RSA-2048, 256 bytes — e.g. a PKCS#1 v1.5
    /// type-2 block raised to the public exponent under the slot's modulus); the
    /// card applies the private key and strips the PKCS#1 padding. Requires PW1
    /// verified in the "other"/decipher context ([`keyroost_openpgp::PW1_OTHER`]);
    /// on a YubiKey it also needs a touch.
    pub fn decrypt(&mut self, cryptogram: &[u8]) -> Result<Vec<u8>, TransportError> {
        // RSA cipher DO: 0x00 padding-indicator byte + the cryptogram.
        let mut data = Vec::with_capacity(1 + cryptogram.len());
        data.push(0x00);
        data.extend_from_slice(cryptogram);
        self.decipher(&data)
    }

    /// ECDH with the on-card decryption key (PSO:DECIPHER, `A6` template):
    /// returns the shared secret the card derives from `ephemeral_point` (the
    /// sender's ephemeral public point — `04||X||Y` for Weierstrass curves, 32
    /// raw bytes for X25519; a leading OpenPGP `0x40` is stripped here). The
    /// RFC 6637 KDF / key unwrap is the OpenPGP tool's job, matching the RSA
    /// path's raw contract. Requires PW1 in the "other" context; on a YubiKey
    /// also a touch.
    pub fn decrypt_ecdh(&mut self, ephemeral_point: &[u8]) -> Result<Vec<u8>, TransportError> {
        let point = match ephemeral_point {
            [0x40, rest @ ..] if rest.len() == 32 => rest,
            p => p,
        };
        let cipher_do = pgp::ecdh_cipher_do(point);
        self.decipher(&cipher_do)
    }

    /// Send a PSO:DECIPHER `cipher_do` (either the RSA `0x00||cryptogram` form
    /// or the ECDH `A6` template) and return the recovered plaintext / shared
    /// secret.
    ///
    /// `cipher_do` can exceed the short-APDU limit (257 bytes for RSA-2048),
    /// so this sends an extended-length APDU and falls back to ISO command
    /// chaining on `6700` / `6883` — the same strategy as
    /// [`import_key`](Self::import_key). `KEYROOST_OPENPGP_FORCE_CHAINING` forces
    /// the chaining path for testing.
    fn decipher(&mut self, cipher_do: &[u8]) -> Result<Vec<u8>, TransportError> {
        if std::env::var_os("KEYROOST_OPENPGP_FORCE_CHAINING").is_none() {
            let (plain, sw) = self.transmit_full(&pgp::pso_decipher(cipher_do))?;
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

        let chunks = pgp::pso_decipher_chained(cipher_do, 254);
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
        let attrs = self.algorithm_attributes(crt)?;
        let attrs =
            pgp::parse_algorithm_attributes(&attrs).map_err(TransportError::OpenPgpParse)?;
        let key = self.read_public_key(crt)?;
        let fpr = pgp::v4_fingerprint(&key, &attrs, creation_time)
            .map_err(TransportError::OpenPgpParse)?;
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
        // Looping until the card reports blocked (6983) guards against the count
        // being stale; the trailing guesses past zero just keep returning 6983.
        self.block_pin(pgp::PW1_OTHER, pw1_tries)?;
        self.block_pin(pgp::PW3_ADMIN, pw3_tries)?;

        let (_, sw) = self.transmit_full(&pgp::terminate_df())?;
        ok_or_apdu("openpgp terminate df", sw)?;
        let (_, sw) = self.transmit_full(&pgp::activate_file())?;
        ok_or_apdu("openpgp activate file", sw)
    }

    /// Exhaust a PIN's retry counter with wrong guesses so it becomes blocked.
    /// Sends up to `max_tries + 1` attempts, stopping early once the card reports
    /// the PIN blocked (`6983`). Best-effort: transmit errors abort the loop.
    ///
    /// The guesses come fresh from the host RNG rather than a compiled-in
    /// constant: a card whose password happened to equal that constant answered
    /// `9000` every iteration, so the counter never moved and PW1 stayed
    /// unblocked while PW3 blocked — leaving the applet unadministrable. A guess
    /// that *is* accepted is now a hard error instead of a silent no-op.
    fn block_pin(&mut self, pw_ref: u8, max_tries: u8) -> Result<(), TransportError> {
        let mut previous: Option<Zeroizing<Vec<u8>>> = None;
        for _ in 0..max_tries.saturating_add(1) {
            let guess =
                crate::piv::random_credential_guess(previous.as_ref().map(|g| g.as_slice()))?;
            let apdu = Zeroizing::new(pgp::verify(pw_ref, &guess));
            match self.transmit_full(&apdu) {
                Ok((_, pgp::SW_OK)) => return Err(TransportError::OpenPgpPinGuessAccepted),
                Ok((_, 0x6983)) => break, // blocked
                Ok(_) => {}
                Err(_) => break,
            }
            previous = Some(guess);
        }
        Ok(())
    }

    /// Transmit one APDU and reassemble a response the card splits across `61xx`
    /// continuations (`GET RESPONSE`), returning `(payload, sw)`.
    fn transmit_full(&mut self, apdu: &[u8]) -> Result<(Vec<u8>, u16), TransportError> {
        // VERIFY (20), CHANGE REFERENCE DATA (24), RESET RETRY COUNTER (2C)
        // carry plaintext PINs; PUT DATA odd (DB) carries imported private
        // keys. PSO:DECIPHER (2A 80 86) *responses* are the recovered
        // plaintext — and so are the GET RESPONSE chunks that follow, hence
        // the sticky flag for the whole reassembly loop.
        let cmd_sensitive = matches!(
            apdu.get(1),
            Some(0x20) | Some(0x24) | Some(0x2C) | Some(0xDB)
        );
        let resp_sensitive = apdu.get(1..4) == Some(&[0x2A, 0x80, 0x86]);
        const IO: crate::AppletIo = crate::AppletIo {
            label: "openpgp",
            more_data_sw: pgp::SW_MORE_DATA,
            get_response: pgp::get_response,
        };
        crate::transmit_applet(
            &self.card,
            self.debug,
            &IO,
            apdu,
            cmd_sensitive,
            resp_sensitive,
        )
    }
}

/// The `--slot` value the CLI accepts for `crt`, for use in a "run this
/// command" hint in an error message.
fn crt_flag_name(crt: pgp::KeyCrt) -> &'static str {
    match crt {
        pgp::KeyCrt::Sign => "sign",
        pgp::KeyCrt::Decrypt => "decrypt",
        pgp::KeyCrt::Auth => "auth",
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

/// Whether generating `alg` in a slot whose attributes currently read `current`
/// requires writing new attributes first. Equal algorithms skip the write —
/// an attribute write wipes the slot, and the card may echo RSA attributes back
/// with its own import-format byte, so compare by parsed algorithm, not bytes.
fn needs_attribute_write(current: &[u8], alg: pgp::KeyAlg) -> bool {
    pgp::parse_algorithm_attributes(current)
        .ok()
        .and_then(|a| a.key_alg())
        != Some(alg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn needs_attribute_write_only_when_the_slot_differs() {
        // Same algorithm: no write (a write would wipe the slot for nothing).
        let cur = pgp::KeyAlg::Ed25519.attributes(pgp::KeyCrt::Sign).unwrap();
        assert!(!needs_attribute_write(&cur, pgp::KeyAlg::Ed25519));
        // RSA-2048 reported with the card's own import-format byte still counts as RSA-2048.
        assert!(!needs_attribute_write(
            &[0x01, 0x08, 0x00, 0x00, 0x20, 0x02],
            pgp::KeyAlg::Rsa2048
        ));
        // Different algorithm, unknown attributes, or garbage: write.
        assert!(needs_attribute_write(&cur, pgp::KeyAlg::X25519));
        assert!(needs_attribute_write(
            &[0x16, 0x2B, 0x65, 0x70],
            pgp::KeyAlg::Ed25519
        ));
        assert!(needs_attribute_write(&[], pgp::KeyAlg::Rsa2048));
    }

    #[test]
    fn status_algorithm_labels_come_from_the_raw_attributes() {
        let st = OpenPgpStatus {
            aid: vec![],
            sig_algo_id: Some(0x16),
            dec_algo_id: Some(0x12),
            aut_algo_id: None,
            sig_attrs: vec![0x16, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01],
            dec_attrs: vec![
                0x12, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01,
            ],
            aut_attrs: vec![],
            fingerprint_sig: [0; 20],
            fingerprint_dec: [0; 20],
            fingerprint_aut: [0; 20],
            tries_pw1: 3,
            tries_rc: 0,
            tries_pw3: 3,
            signature_count: None,
        };
        assert_eq!(st.algorithm_label(pgp::KeyCrt::Sign), "EdDSA Ed25519");
        assert_eq!(st.algorithm_label(pgp::KeyCrt::Decrypt), "ECDH X25519");
        assert_eq!(st.algorithm_label(pgp::KeyCrt::Auth), "none");
    }
}
