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

use crate::recover::{self, FirstContact};
use crate::{trace, TransportError};
use keyroost_openpgp as pgp;
use keyroost_proto::trace::{format_line, Dir};
use pcsc::{Card, Protocols, ShareMode};
use zeroize::Zeroizing;

/// `SW 6A82`: selected file/application not found — i.e. no OpenPGP applet.
const SW_FILE_NOT_FOUND: u16 = 0x6A82;

/// A read-only snapshot of an OpenPGP card's state, assembled from the
/// Application Related Data (`6E`) and the signature counter (`7A`/`93`).
#[non_exhaustive]
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
    /// A Token2 key's full serial, read from its OTP applet by [`OpenPgpSession::status`]
    /// (a cross-applet read, the same one PIV status makes). `None` on other
    /// cards, or when the OTP applet didn't answer.
    pub otp_applet_serial: Option<u128>,
}

impl OpenPgpStatus {
    /// The card serial number — the last 4 bytes of the AID (per the spec, the
    /// manufacturer-assigned serial sits at AID bytes 10..14).
    ///
    /// Token2's OpenPGP applet reports this serial in BCD coding, the same
    /// quirk its PIV applet has: each nibble of the raw value is a decimal
    /// digit of the number printed on the device. When the AID's manufacturer
    /// ID marks the card as Token2 ([`pgp::MANUFACTURER_ID_TOKEN2`]), the raw
    /// value is run through `crate::decode_bcd_serial` to recover the real
    /// serial; every other vendor's serial is a plain integer and passes
    /// through untouched. That is a number to compare, not one to show: a
    /// YubiKey stores its serial there as BCD too (`0x37806840` for 37806840)
    /// and a Nitrokey as its hex serial; [`Self::serial_text`] is the form to
    /// show.
    #[must_use]
    pub fn serial(&self) -> Option<u32> {
        let raw = self
            .aid
            .get(10..14)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))?;
        if pgp::aid_manufacturer_id(&self.aid) == Some(pgp::MANUFACTURER_ID_TOKEN2) {
            // A BCD serial is at most 8 decimal digits (99_999_999), so it
            // always fits back into u32; fall back to the raw value if the
            // decode bailed out on a non-decimal nibble.
            Some(u32::try_from(crate::decode_bcd_serial(u128::from(raw))).unwrap_or(raw))
        } else {
            Some(raw)
        }
    }

    /// [`Self::otp_applet_serial`] when present, else [`Self::serial`], as a
    /// number. To show a serial, use [`Self::serial_text`].
    #[must_use]
    pub fn full_serial(&self) -> Option<u128> {
        self.otp_applet_serial
            .or_else(|| self.serial().map(u128::from))
    }

    /// The serial as front ends show it: [`Self::otp_applet_serial`] (a
    /// Token2 key's full serial, as printed on the key) when present, else
    /// the AID's four serial bytes as eight hex digits, as GnuPG shows them.
    /// That is the number the vendor gives the key: a YubiKey's and a Token2
    /// key's serial are BCD there, so the digits are the decimal serial
    /// (`37806840`); a Nitrokey's is its hex serial (`42682EF7`). `None`
    /// when the card reported neither.
    #[must_use]
    pub fn serial_text(&self) -> Option<String> {
        if let Some(s) = self.otp_applet_serial {
            return Some(s.to_string());
        }
        let b = self.aid.get(10..14)?;
        Some(b.iter().map(|x| format!("{x:02X}")).collect())
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

/// Map a public-key read to "known to hold a key": success is `Some(true)`,
/// every error is `None`, never `Some(false)`.
fn key_present_from<T>(read: Result<T, TransportError>) -> Option<bool> {
    read.ok().map(|_| true)
}

impl OpenPgpSession {
    /// Connect to `reader_name` and SELECT the OpenPGP applet. Returns
    /// [`TransportError::NoOpenPgpApplet`] when the card has no OpenPGP applet.
    pub fn open(reader_name: &str) -> Result<Self, TransportError> {
        Self::open_traced(reader_name, false)
    }

    /// [`Self::open`] with per-APDU stderr tracing on from the start, so the
    /// SELECT it sends is traced too.
    ///
    /// A card found just reset or briefly gone while connecting or answering
    /// the SELECT is waited for and opened once more (see `crate::recover`).
    pub fn open_traced(reader_name: &str, debug: bool) -> Result<Self, TransportError> {
        let cstr = std::ffi::CString::new(reader_name)
            .map_err(|_| TransportError::MalformedResponse("reader name contained NUL"))?;
        let mut contact = FirstContact::new(reader_name, debug, "openpgp");
        loop {
            let ctx = crate::establish_context().map_err(TransportError::PcscUnavailable)?;
            let card = match ctx.connect(&cstr, ShareMode::Shared, Protocols::ANY) {
                Ok(card) => card,
                Err(e) => {
                    contact.retry_or_fail(e.into())?;
                    continue;
                }
            };
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

    /// Enable per-APDU stderr tracing.
    pub fn set_debug(&mut self, on: bool) {
        self.debug = on;
    }

    /// Names of connected readers whose OpenPGP applet answers `SELECT` with
    /// `9000`. Cards without the applet (e.g. the test Solo 2) are skipped, so a
    /// front-end can auto-pick a lone OpenPGP card or list the choices.
    pub fn list_openpgp_readers() -> Result<Vec<String>, TransportError> {
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

        // Cross-applet read: on a Token2 card, the OpenPGP AID carries only a
        // 4-byte BCD serial, while the key's OTP applet reports the full serial
        // printed on the device. Read it on this same card handle, as PIV status
        // does, then re-SELECT OpenPGP whatever the read returned: the next command
        // on this session expects the OpenPGP applet.
        let otp_applet_serial = if wants_otp_applet_serial(&ard.aid) {
            let serial = crate::token2otp::read_otp_applet_serial(|apdu| self.transmit_full(apdu));
            self.select()?;
            serial
        } else {
            None
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
            otp_applet_serial,
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
                trace::line(self.debug, || {
                    format_line(
                        Dir::Note,
                        "openpgp generate",
                        &format!("setting {crt:?} slot algorithm to {}", alg.label()),
                    )
                });
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
        self.import_rsa_tracked(crt, key, &mut false)
    }

    /// [`import_key`](Self::import_key), setting `sent` once the key
    /// import is about to be transmitted (from then on the slot's old key
    /// may be gone, whatever the card answers).
    fn import_rsa_tracked(
        &mut self,
        crt: pgp::KeyCrt,
        key: &pgp::RsaPrivateKeyParts,
        sent: &mut bool,
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

        let apdu = Zeroizing::new(
            pgp::import_rsa_key(crt, key, attrs.format, attrs.e_bits)
                .map_err(|_| TransportError::OpenPgpExponentTooWide)?,
        );
        *sent = true;
        self.put_key_import(&apdu, || {
            Ok(
                pgp::import_rsa_key_chained(crt, key, attrs.format, attrs.e_bits, 254)
                    .map_err(|_| TransportError::OpenPgpExponentTooWide)?
                    .into_iter()
                    .map(Zeroizing::new)
                    .collect(),
            )
        })
    }

    /// Send a key-import PUT DATA: the single extended-length `apdu` first,
    /// then — when the card or reader won't take an extended `Lc` — the
    /// command-chaining form `chained` builds. Shared by the RSA and ECC
    /// imports.
    fn put_key_import(
        &mut self,
        apdu: &[u8],
        chained: impl FnOnce() -> Result<Vec<Zeroizing<Vec<u8>>>, TransportError>,
    ) -> Result<(), TransportError> {
        // Setting KEYROOST_OPENPGP_FORCE_CHAINING forces the command-chaining path
        // (so the fallback can be exercised on a card that also accepts extended
        // length, e.g. for verification). Otherwise: extended length first.
        if std::env::var_os("KEYROOST_OPENPGP_FORCE_CHAINING").is_none() {
            let (_, sw) = self.transmit_full(apdu)?;
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
            trace::line(self.debug, || {
                format_line(
                    Dir::Note,
                    "openpgp import",
                    &format!(
                        "extended length rejected (SW={sw:04X}); \
                         retrying with command chaining"
                    ),
                )
            });
        } else {
            trace::line(self.debug, || {
                format_line(
                    Dir::Note,
                    "openpgp import",
                    "forcing command chaining (env override)",
                )
            });
        }

        let chunks = chained()?;
        self.transmit_chain("openpgp import key", &chunks)
            .map(|_| ())
    }

    /// Import a private key of any kind into `crt`'s slot as `alg`: sets the
    /// slot's algorithm attributes first when they differ (that write wipes
    /// the slot, which the import overwrites anyway), then sends the key —
    /// RSA through [`import_key`](Self::import_key), ECC as the `92` scalar
    /// (the Ed25519 seed for EdDSA), with the public point only when the
    /// slot's attributes ask for it (trailing `FF`). **Destructive**; requires
    /// PW3 verified first.
    ///
    /// A card that refuses the algorithm for this slot — the attribute write
    /// itself answered `6A80`/`6A88` — is
    /// [`TransportError::OpenPgpAlgorithmRefused`], and the slot is as it
    /// was. A failure after a write for the slot was sent (the attribute
    /// change, which wipes the slot, or the key import itself) is
    /// [`TransportError::OpenPgpKeySetPartial`] with no `done` slots: the
    /// slot's old key may be gone.
    pub fn import_any(
        &mut self,
        crt: pgp::KeyCrt,
        alg: pgp::KeyAlg,
        key: &ImportKey,
    ) -> Result<(), TransportError> {
        let mut changed = false;
        self.import_any_tracked(crt, alg, key, &mut changed)
            .map_err(|cause| slot_failure(Vec::new(), crt, changed, cause))
    }

    /// [`import_any`](Self::import_any) without the wrapping, setting
    /// `changed` once a write for the slot has been sent.
    fn import_any_tracked(
        &mut self,
        crt: pgp::KeyCrt,
        alg: pgp::KeyAlg,
        key: &ImportKey,
        changed: &mut bool,
    ) -> Result<(), TransportError> {
        check_import(crt, alg, key)?;
        let current = self.algorithm_attributes(crt)?;
        let set = needs_attribute_write(&current, alg);
        if set {
            trace::line(self.debug, || {
                format_line(
                    Dir::Note,
                    "openpgp import",
                    &format!("setting {crt:?} slot algorithm to {}", alg.label()),
                )
            });
            self.set_algorithm(crt, alg)?;
            *changed = true;
        }
        match key {
            ImportKey::Rsa(parts) => self.import_rsa_tracked(crt, parts, changed),
            ImportKey::Ecc(parts) => {
                let attrs = if set {
                    self.algorithm_attributes(crt)?
                } else {
                    current
                };
                let with_public = matches!(
                    pgp::parse_algorithm_attributes(&attrs),
                    Ok(pgp::AlgorithmAttributes::Ecc {
                        import_with_public_key: true,
                        ..
                    })
                );
                let parts = pgp::EccPrivateKeyParts {
                    scalar: parts.scalar,
                    public: parts.public.filter(|_| with_public),
                };
                let field_len = alg.curve().map_or(0, pgp::Curve::field_len);
                let not_for = || TransportError::OpenPgpKeyNotForAlgorithm {
                    slot: crt_label(crt),
                    label: alg.label(),
                };
                let apdu = Zeroizing::new(
                    pgp::import_ecc_key(crt, &parts, field_len).map_err(|_| not_for())?,
                );
                *changed = true;
                self.put_key_import(&apdu, || {
                    Ok(pgp::import_ecc_key_chained(crt, &parts, field_len, 254)
                        .map_err(|_| not_for())?
                        .into_iter()
                        .map(Zeroizing::new)
                        .collect())
                })
            }
        }
    }

    /// Import a whole key set, one [`KeyImport`] per slot, and register each
    /// key under the file's own fingerprint and creation time. Requires PW3
    /// verified first. Returns the fingerprints written, in `keys` order.
    ///
    /// Everything that can be checked is checked before the first write:
    /// each key against its slot and algorithm, and — reading the card —
    /// each slot's current attributes (the RSA exponent field) and, when the
    /// card publishes its Algorithm Information (`FA`), that it lists the
    /// key's algorithm for that slot ([`TransportError::OpenPgpAlgorithmRefused`]
    /// otherwise). A set that fails these changes nothing on the card.
    ///
    /// Each key's public part is read back after its import and compared with
    /// `expect_public`; a card holding anything else is
    /// [`TransportError::OpenPgpFingerprintMismatch`] and that key is not
    /// registered. The fingerprint is the file's, not one recomputed from the
    /// card: an ECDH key's fingerprint hashes its KDF parameters, which the
    /// card does not store (GnuPG's P-384 keys carry different ones than
    /// [`pgp::ecdh_kdf_params`]).
    ///
    /// A failure once the card has been changed is
    /// [`TransportError::OpenPgpKeySetPartial`], naming the slots that now
    /// hold the new keys and the one that failed, and whether a write for
    /// that one had been sent (its old key may then be gone). A failure on
    /// the first key before anything was written to it — the card refusing
    /// the attribute change, say — is its plain cause: nothing changed.
    pub fn import_key_set(&mut self, keys: &[KeyImport]) -> Result<Vec<[u8; 20]>, TransportError> {
        for k in keys {
            check_import(k.crt, k.alg, &k.key)?;
        }
        let fa = self.supported_algorithms()?;
        for k in keys {
            let current = self.algorithm_attributes(k.crt)?;
            preflight(k, &current, fa.as_ref())?;
        }
        let mut out = Vec::with_capacity(keys.len());
        for k in keys {
            let mut changed = false;
            if let Err(cause) = self.import_one(k, &mut changed) {
                let done = keys[..out.len()].iter().map(|k| crt_label(k.crt)).collect();
                return Err(slot_failure(done, k.crt, changed, cause));
            }
            out.push(k.expect_fpr);
        }
        Ok(out)
    }

    /// One key of [`import_key_set`](Self::import_key_set): import, compare
    /// the card's public key, register. `changed` as for
    /// [`import_any_tracked`](Self::import_any_tracked).
    fn import_one(&mut self, k: &KeyImport, changed: &mut bool) -> Result<(), TransportError> {
        self.import_any_tracked(k.crt, k.alg, &k.key, changed)?;
        let got = self.read_public_key(k.crt)?;
        if !same_public_key(&got, &k.expect_public) {
            return Err(TransportError::OpenPgpFingerprintMismatch {
                slot: crt_label(k.crt),
            });
        }
        let (_, sw) = self.transmit_full(&pgp::put_generation_time(k.crt, k.created))?;
        ok_or_apdu("openpgp put generation time", sw)?;
        let (_, sw) = self.transmit_full(&pgp::put_fingerprint(k.crt, &k.expect_fpr))?;
        ok_or_apdu("openpgp put fingerprint", sw)
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

    /// Whether using `crt`'s key (sign, decrypt, authenticate) may ask for a
    /// touch, for a "touch the key if it blinks" hint: from the card's own
    /// touch setting (its User Interaction Flag, OpenPGP card 3.3+). `false`
    /// only when the card says it is off; a card that doesn't report it may.
    /// Read before verifying a PIN.
    pub fn may_ask_touch_to_use(&mut self, crt: pgp::KeyCrt) -> bool {
        match self.transmit_full(&pgp::get_data(crt.uif_tag())) {
            Ok((reply, 0x9000)) => pgp::uif_asks_touch(&reply).unwrap_or(true),
            _ => true,
        }
    }

    /// Whether generating or importing keys (or restoring a backup) may ask
    /// for a touch on this card, for the same hint: by the AID's
    /// manufacturer ([`pgp::may_ask_touch_to_write`]). A card whose AID
    /// can't be read may.
    pub fn may_ask_touch_to_write(&mut self) -> bool {
        let manufacturer = self
            .transmit_full(&pgp::get_data(pgp::TAG_AID))
            .ok()
            .filter(|(_, sw)| *sw == 0x9000)
            .and_then(|(aid, _)| {
                // The reply may be the raw AID or a `4F len …` wrapper.
                let raw = match aid.as_slice() {
                    [0x4F, _, rest @ ..] => rest.to_vec(),
                    _ => aid,
                };
                pgp::aid_manufacturer_id(&raw)
            });
        pgp::may_ask_touch_to_write(manufacturer)
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
    /// [`TransportError::OpenPgpSlotMismatch`]; a card that refuses that
    /// algorithm in this slot (`6A80` / `6A88`) is
    /// [`TransportError::OpenPgpAlgorithmRefused`], any other status an APDU
    /// error.
    pub fn set_algorithm(
        &mut self,
        crt: pgp::KeyCrt,
        alg: pgp::KeyAlg,
    ) -> Result<(), TransportError> {
        let attr = alg
            .attributes(crt)
            .map_err(TransportError::OpenPgpSlotMismatch)?;
        let (_, sw) = self.transmit_full(&pgp::put_algorithm_attributes(crt, &attr))?;
        if sw == 0x6A80 || sw == 0x6A88 {
            return Err(TransportError::OpenPgpAlgorithmRefused {
                slot: crt_label(crt),
                label: alg.label(),
            });
        }
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
            trace::line(self.debug, || {
                format_line(
                    Dir::Note,
                    "openpgp",
                    &format!(
                        "card has no Algorithm Information object (SW={sw:04X}); \
                             offering every algorithm"
                    ),
                )
            });
            return Ok(None);
        }
        let parsed = pgp::parse_algorithm_information(&bytes).ok();
        if parsed.is_none() {
            trace::line(self.debug, || {
                format_line(
                    Dir::Note,
                    "openpgp",
                    "Algorithm Information object did not parse; offering every algorithm",
                )
            });
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

    /// Read the public key currently in `crt`'s slot. Read-only; no PIN. An
    /// empty slot can return an APDU error (6F00 is observed on some cards), while
    /// an unrecognized public-key encoding returns `OpenPgpParse`.
    pub fn read_public_key(&mut self, crt: pgp::KeyCrt) -> Result<pgp::PublicKey, TransportError> {
        let (data, sw) = self.transmit_full(&pgp::read_public_key(crt))?;
        ok_or_apdu("openpgp read public key", sw)?;
        pgp::parse_generated_public_key(&data).map_err(TransportError::OpenPgpParse)
    }

    /// Whether `crt`'s slot is known to hold a key: `Some(true)` when its public
    /// key reads back, `None` for every failure (status word, parse, transport).
    /// Never `Some(false)`: a status such as 6F00 is not proof the slot is empty.
    /// Read-only; no PIN.
    pub fn key_present(&mut self, crt: pgp::KeyCrt) -> Option<bool> {
        key_present_from(self.read_public_key(crt))
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
            trace::line(self.debug, || {
                format_line(
                    Dir::Note,
                    "openpgp decipher",
                    &format!(
                        "extended length rejected (SW={sw:04X}); \
                         retrying with command chaining"
                    ),
                )
            });
        } else {
            trace::line(self.debug, || {
                format_line(
                    Dir::Note,
                    "openpgp decipher",
                    "forcing command chaining (env override)",
                )
            });
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
            describe: None,
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

/// Private key material for [`OpenPgpSession::import_any`]. `Debug` names
/// the kind only, never the key bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ImportKey<'a> {
    /// An RSA key (full CRT set; the card picks the parts it wants).
    Rsa(pgp::RsaPrivateKeyParts<'a>),
    /// An ECC key: the private scalar (Ed25519: the seed) and its public
    /// point, which is sent only to cards that ask for it.
    Ecc(pgp::EccPrivateKeyParts<'a>),
}

impl std::fmt::Debug for ImportKey<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImportKey::Rsa(_) => f.write_str("ImportKey::Rsa(<redacted>)"),
            ImportKey::Ecc(_) => f.write_str("ImportKey::Ecc(<redacted>)"),
        }
    }
}

/// One key of a set for [`OpenPgpSession::import_key_set`]; made with
/// [`KeyImport::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct KeyImport<'a> {
    /// The slot it goes into.
    pub crt: pgp::KeyCrt,
    /// The slot algorithm it needs.
    pub alg: pgp::KeyAlg,
    /// The private key.
    pub key: ImportKey<'a>,
    /// The key's creation time from the file (Unix seconds), written to the
    /// slot's generation-time object.
    pub created: u32,
    /// The key's fingerprint from the file, written to the slot.
    pub expect_fpr: [u8; 20],
    /// The key's public part from the file, compared with what the card
    /// reports after the import (raw 32 bytes for the 25519 curves).
    pub expect_public: pgp::PublicKey,
}

impl<'a> KeyImport<'a> {
    /// One key for `crt`'s slot as `alg`, with the creation time,
    /// fingerprint and public part its file gives it.
    #[must_use]
    pub fn new(
        crt: pgp::KeyCrt,
        alg: pgp::KeyAlg,
        key: ImportKey<'a>,
        created: u32,
        expect_fpr: [u8; 20],
        expect_public: pgp::PublicKey,
    ) -> Self {
        KeyImport {
            crt,
            alg,
            key,
            created,
            expect_fpr,
            expect_public,
        }
    }
}

/// The error for a failed import into `crt`'s slot, after `done` slots of
/// the same set took their new keys: the plain `cause` when nothing was
/// written at all (`done` empty, `changed` false), otherwise
/// [`TransportError::OpenPgpKeySetPartial`].
fn slot_failure(
    done: Vec<&'static str>,
    crt: pgp::KeyCrt,
    changed: bool,
    cause: TransportError,
) -> TransportError {
    if done.is_empty() && !changed {
        return cause;
    }
    TransportError::OpenPgpKeySetPartial {
        done,
        failed: crt_label(crt),
        slot_changed: changed,
        cause: Box::new(cause),
    }
}

/// Check, without the card, that `key` is the kind and size `alg` takes
/// and that `alg` can live in `crt`'s slot.
fn check_import(crt: pgp::KeyCrt, alg: pgp::KeyAlg, key: &ImportKey) -> Result<(), TransportError> {
    alg.attributes(crt)
        .map_err(TransportError::OpenPgpSlotMismatch)?;
    let fits = match (key, alg.curve()) {
        (ImportKey::Rsa(parts), None) => {
            let n = parts
                .n
                .iter()
                .position(|&b| b != 0)
                .map_or(&[][..], |i| &parts.n[i..]);
            let bits = n
                .first()
                .map_or(0, |&top| n.len() * 8 - top.leading_zeros() as usize);
            alg.rsa_bits().map(usize::from) == Some(bits)
        }
        (ImportKey::Ecc(parts), Some(curve)) => {
            pgp::ecc_scalar_fits(parts.scalar, curve.field_len())
        }
        _ => false,
    };
    if fits {
        Ok(())
    } else {
        Err(TransportError::OpenPgpKeyNotForAlgorithm {
            slot: crt_label(crt),
            label: alg.label(),
        })
    }
}

/// The card-side checks for one key of a set, from what the card reported
/// before anything is written: `current` is the slot's attributes and `fa`
/// its Algorithm Information, if published. A slot `fa` lists nothing for
/// is not judged by it (the card's status word answers later).
fn preflight(
    k: &KeyImport,
    current: &[u8],
    fa: Option<&pgp::AlgorithmInformation>,
) -> Result<(), TransportError> {
    if let Some(fa) = fa {
        let listed = fa.key_algs(k.crt);
        if !listed.is_empty() && !listed.contains(&k.alg) {
            return Err(TransportError::OpenPgpAlgorithmRefused {
                slot: crt_label(k.crt),
                label: k.alg.label(),
            });
        }
    }
    if let ImportKey::Rsa(parts) = &k.key {
        // The attributes the import will meet: the slot's own, or the ones
        // `import_any` writes first.
        let attrs = if needs_attribute_write(current, k.alg) {
            k.alg
                .attributes(k.crt)
                .map_err(TransportError::OpenPgpSlotMismatch)?
        } else {
            current.to_vec()
        };
        match pgp::parse_algorithm_attributes(&attrs) {
            Ok(pgp::AlgorithmAttributes::Rsa(r)) => {
                if !pgp::rsa_exponent_fits(parts.e, r.e_bits) {
                    return Err(TransportError::OpenPgpExponentTooWide);
                }
            }
            Ok(ecc @ pgp::AlgorithmAttributes::Ecc { .. }) => {
                return Err(TransportError::OpenPgpSlotNotRsa {
                    slot: crt_flag_name(k.crt),
                    label: ecc.label(),
                })
            }
            Err(e) => return Err(TransportError::OpenPgpParse(e)),
        }
    }
    Ok(())
}

/// Whether the card's public key `got` is `want`. RSA integers compare
/// without leading zeros (cards may or may not send one); a 25519 point
/// compares without OpenPGP's `0x40` prefix.
fn same_public_key(got: &pgp::PublicKey, want: &pgp::PublicKey) -> bool {
    fn trim(v: &[u8]) -> &[u8] {
        let i = v.iter().position(|&b| b != 0).unwrap_or(v.len());
        &v[i..]
    }
    fn bare(p: &[u8]) -> &[u8] {
        match p {
            [0x40, rest @ ..] if rest.len() == 32 => rest,
            p => p,
        }
    }
    match (got, want) {
        (
            pgp::PublicKey::Rsa {
                modulus: gn,
                exponent: ge,
            },
            pgp::PublicKey::Rsa {
                modulus: wn,
                exponent: we,
            },
        ) => trim(gn) == trim(wn) && trim(ge) == trim(we),
        (pgp::PublicKey::Ecc { point: g }, pgp::PublicKey::Ecc { point: w }) => bare(g) == bare(w),
        _ => false,
    }
}

/// The slot's name in prose ("the signature slot").
fn crt_label(crt: pgp::KeyCrt) -> &'static str {
    match crt {
        pgp::KeyCrt::Sign => "signature",
        pgp::KeyCrt::Decrypt => "decryption",
        pgp::KeyCrt::Auth => "authentication",
    }
}

/// Whether `status` also reads the full serial through the OTP applet: only
/// for a card whose AID names Token2 as the manufacturer, so no other card
/// ever sees the extra SELECT.
fn wants_otp_applet_serial(aid: &[u8]) -> bool {
    pgp::aid_manufacturer_id(aid) == Some(pgp::MANUFACTURER_ID_TOKEN2)
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
    fn key_present_is_true_or_unknown_never_false() {
        assert_eq!(key_present_from(Ok(())), Some(true));
        for sw in [(0x6A, 0x88), (0x6F, 0x00), (0x69, 0x82)] {
            let err = TransportError::Apdu {
                label: "openpgp read public key",
                sw1: sw.0,
                sw2: sw.1,
            };
            assert_eq!(key_present_from::<()>(Err(err)), None);
        }
        let parse = TransportError::OpenPgpParse(keyroost_openpgp::ParseError::Truncated);
        assert_eq!(key_present_from::<()>(Err(parse)), None);
    }

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
    fn import_checks_run_before_the_card() {
        let scalar = [0x11u8; 32];
        let ecc = ImportKey::Ecc(pgp::EccPrivateKeyParts {
            scalar: &scalar,
            public: None,
        });
        let e = [1u8, 0, 1];
        let mut n = vec![0x00u8, 0xC0];
        n.extend_from_slice(&[0x11u8; 383]); // 3072 bits, one leading zero
        let rsa = ImportKey::Rsa(pgp::RsaPrivateKeyParts {
            e: &e,
            p: &e,
            q: &e,
            u: &e,
            dp: &e,
            dq: &e,
            n: &n,
        });
        assert!(check_import(pgp::KeyCrt::Sign, pgp::KeyAlg::NistP256, &ecc).is_ok());
        assert!(check_import(pgp::KeyCrt::Decrypt, pgp::KeyAlg::X25519, &ecc).is_ok());
        assert!(check_import(pgp::KeyCrt::Sign, pgp::KeyAlg::Rsa3072, &rsa).is_ok());
        // An RSA key of another size than the slot algorithm.
        assert!(check_import(pgp::KeyCrt::Sign, pgp::KeyAlg::Rsa2048, &rsa).is_err());
        assert!(check_import(pgp::KeyCrt::Sign, pgp::KeyAlg::Rsa4096, &rsa).is_err());
        // Ed25519 cannot decrypt.
        assert!(matches!(
            check_import(pgp::KeyCrt::Decrypt, pgp::KeyAlg::Ed25519, &ecc),
            Err(TransportError::OpenPgpSlotMismatch(_))
        ));
        // Wrong kind of key for the algorithm.
        assert!(matches!(
            check_import(pgp::KeyCrt::Sign, pgp::KeyAlg::Rsa2048, &ecc),
            Err(TransportError::OpenPgpKeyNotForAlgorithm {
                slot: "signature",
                ..
            })
        ));
        assert!(check_import(pgp::KeyCrt::Sign, pgp::KeyAlg::NistP256, &rsa).is_err());
        // A P-384 scalar does not fit P-256.
        let wide = [0x11u8; 48];
        let wide = ImportKey::Ecc(pgp::EccPrivateKeyParts {
            scalar: &wide,
            public: None,
        });
        assert!(check_import(pgp::KeyCrt::Auth, pgp::KeyAlg::NistP256, &wide).is_err());
        assert!(check_import(pgp::KeyCrt::Auth, pgp::KeyAlg::NistP384, &wide).is_ok());
    }

    #[test]
    fn public_keys_compare_without_encoding_noise() {
        let rsa = |n: &[u8], e: &[u8]| pgp::PublicKey::Rsa {
            modulus: n.to_vec(),
            exponent: e.to_vec(),
        };
        let ecc = |p: &[u8]| pgp::PublicKey::Ecc { point: p.to_vec() };
        assert!(same_public_key(
            &rsa(&[0x00, 0xC1, 0x02], &[0x01, 0x00, 0x01]),
            &rsa(&[0xC1, 0x02], &[0x00, 0x01, 0x00, 0x01])
        ));
        assert!(!same_public_key(
            &rsa(&[0xC1, 0x03], &[0x01, 0x00, 0x01]),
            &rsa(&[0xC1, 0x02], &[0x01, 0x00, 0x01])
        ));
        let raw = [0x09u8; 32];
        let mut prefixed = vec![0x40];
        prefixed.extend_from_slice(&raw);
        assert!(same_public_key(&ecc(&raw), &ecc(&prefixed)));
        assert!(!same_public_key(&ecc(&raw), &ecc(&[0x08u8; 32])));
        assert!(!same_public_key(&ecc(&raw), &rsa(&raw, &[1, 0, 1])));
    }

    fn fa_listing(sig: &[pgp::KeyAlg], dec: &[pgp::KeyAlg]) -> pgp::AlgorithmInformation {
        let mut v = Vec::new();
        for (tag, algs, crt) in [
            (0xC1u8, sig, pgp::KeyCrt::Sign),
            (0xC2, dec, pgp::KeyCrt::Decrypt),
        ] {
            for a in algs {
                let attr = a.attributes(crt).unwrap();
                v.push(tag);
                v.push(attr.len() as u8);
                v.extend_from_slice(&attr);
            }
        }
        let mut fa = vec![0xFA, v.len() as u8];
        fa.extend_from_slice(&v);
        pgp::parse_algorithm_information(&fa).unwrap()
    }

    #[test]
    fn preflight_refuses_what_the_card_does_not_list() {
        let scalar = [0x11u8; 32];
        let k = KeyImport {
            crt: pgp::KeyCrt::Decrypt,
            alg: pgp::KeyAlg::X25519,
            key: ImportKey::Ecc(pgp::EccPrivateKeyParts {
                scalar: &scalar,
                public: None,
            }),
            created: 0,
            expect_fpr: [0; 20],
            expect_public: pgp::PublicKey::Ecc { point: vec![] },
        };
        let rsa_slot = [0x01, 0x08, 0x00, 0x00, 0x20, 0x00];
        let fa = fa_listing(
            &[pgp::KeyAlg::Rsa2048, pgp::KeyAlg::NistP256],
            &[pgp::KeyAlg::Rsa2048, pgp::KeyAlg::NistP256],
        );
        assert!(matches!(
            preflight(&k, &rsa_slot, Some(&fa)),
            Err(TransportError::OpenPgpAlgorithmRefused {
                slot: "decryption",
                label: "X25519"
            })
        ));
        let fa = fa_listing(&[pgp::KeyAlg::Ed25519], &[pgp::KeyAlg::X25519]);
        assert!(preflight(&k, &rsa_slot, Some(&fa)).is_ok());
        // No FA object, or none for this slot: left to the card.
        assert!(preflight(&k, &rsa_slot, None).is_ok());
        let fa = fa_listing(&[pgp::KeyAlg::Ed25519], &[]);
        assert!(preflight(&k, &rsa_slot, Some(&fa)).is_ok());
    }

    #[test]
    fn preflight_checks_the_rsa_exponent_field() {
        let e = [0x01u8, 0x00, 0x00, 0x00, 0x01]; // 5 bytes, wider than 32 bits
        let k = KeyImport {
            crt: pgp::KeyCrt::Sign,
            alg: pgp::KeyAlg::Rsa2048,
            key: ImportKey::Rsa(pgp::RsaPrivateKeyParts {
                e: &e,
                p: &e,
                q: &e,
                u: &e,
                dp: &e,
                dq: &e,
                n: &e,
            }),
            created: 0,
            expect_fpr: [0; 20],
            expect_public: pgp::PublicKey::Ecc { point: vec![] },
        };
        // Slot already RSA-2048 with a 32-bit exponent field.
        let cur = [0x01, 0x08, 0x00, 0x00, 0x20, 0x02];
        assert!(matches!(
            preflight(&k, &cur, None),
            Err(TransportError::OpenPgpExponentTooWide)
        ));
        // An ECC slot gets the attributes import_any would write: also 32 bits.
        let cur = pgp::KeyAlg::NistP256.attributes(pgp::KeyCrt::Sign).unwrap();
        assert!(matches!(
            preflight(&k, &cur, None),
            Err(TransportError::OpenPgpExponentTooWide)
        ));
        let e3 = [0x01u8, 0x00, 0x01];
        let k = KeyImport {
            key: ImportKey::Rsa(pgp::RsaPrivateKeyParts {
                e: &e3,
                p: &e3,
                q: &e3,
                u: &e3,
                dp: &e3,
                dq: &e3,
                n: &e3,
            }),
            ..k
        };
        assert!(preflight(&k, &cur, None).is_ok());
    }

    #[test]
    fn partial_set_errors_name_the_slots() {
        let cause = || TransportError::OpenPgpAlgorithmRefused {
            slot: "decryption",
            label: "X25519",
        };
        assert_eq!(
            slot_failure(vec!["signature"], pgp::KeyCrt::Decrypt, true, cause()).to_string(),
            "loaded the signature key; the decryption key failed (that slot's old key \
             may be gone): this card doesn't accept X25519 keys in the decryption slot"
        );
        assert_eq!(
            slot_failure(vec!["signature"], pgp::KeyCrt::Decrypt, false, cause()).to_string(),
            "loaded the signature key; the decryption key failed (that slot was not \
             changed): this card doesn't accept X25519 keys in the decryption slot"
        );
        let two = slot_failure(
            vec!["signature", "decryption"],
            pgp::KeyCrt::Auth,
            true,
            cause(),
        );
        assert!(two.to_string().starts_with(
            "loaded the signature and decryption keys; the authentication key failed"
        ));
        assert!(std::error::Error::source(&two).is_some());
    }

    #[test]
    fn a_first_key_failure_says_whether_the_slot_was_touched() {
        // Refused before any write (the attribute write itself said no):
        // the plain cause, nothing changed.
        let refused = slot_failure(
            Vec::new(),
            pgp::KeyCrt::Sign,
            false,
            TransportError::OpenPgpAlgorithmRefused {
                slot: "signature",
                label: "Ed25519",
            },
        );
        assert!(matches!(
            refused,
            TransportError::OpenPgpAlgorithmRefused { .. }
        ));
        // Failed after the attribute change or the key went out: the old
        // key may be gone, and the message says so.
        let after = slot_failure(
            Vec::new(),
            pgp::KeyCrt::Sign,
            true,
            TransportError::Apdu {
                label: "openpgp import key",
                sw1: 0x6A,
                sw2: 0x80,
            },
        );
        let msg = after.to_string();
        assert!(
            matches!(
                after,
                TransportError::OpenPgpKeySetPartial {
                    slot_changed: true,
                    ..
                }
            ),
            "{msg}"
        );
        assert!(
            msg.starts_with(
                "the signature key failed after the card began replacing it (that slot's \
                 old key may be gone): "
            ),
            "{msg}"
        );
    }

    #[test]
    fn import_key_debug_never_shows_key_bytes() {
        let secret = [0x5Au8; 32];
        let k = ImportKey::Ecc(pgp::EccPrivateKeyParts {
            scalar: &secret,
            public: Some(&secret),
        });
        let shown = format!("{k:?}");
        assert!(!shown.contains("90") && !shown.contains("5A"), "{shown}");
        let e = [1u8, 0, 1];
        let r = ImportKey::Rsa(pgp::RsaPrivateKeyParts {
            e: &e,
            p: &secret,
            q: &secret,
            u: &secret,
            dp: &secret,
            dq: &secret,
            n: &secret,
        });
        let shown = format!("{r:?}");
        assert!(!shown.contains("90") && !shown.contains("5A"), "{shown}");
    }

    #[test]
    fn import_errors_read_plainly() {
        assert_eq!(
            TransportError::OpenPgpAlgorithmRefused {
                slot: "decryption",
                label: "X25519"
            }
            .to_string(),
            "this card doesn't accept X25519 keys in the decryption slot"
        );
        assert_eq!(
            TransportError::OpenPgpFingerprintMismatch { slot: "signature" }.to_string(),
            "the card holds a different signature key than the file has; it was not registered"
        );
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
            otp_applet_serial: None,
        };
        assert_eq!(st.algorithm_label(pgp::KeyCrt::Sign), "EdDSA Ed25519");
        assert_eq!(st.algorithm_label(pgp::KeyCrt::Decrypt), "ECDH X25519");
        assert_eq!(st.algorithm_label(pgp::KeyCrt::Auth), "none");
    }

    /// Build a minimal 16-byte OpenPGP AID: prefix, version `03 04`,
    /// `manufacturer`, `serial` (big-endian), trailing `00 00`.
    fn aid_with(manufacturer: u16, serial: u32) -> Vec<u8> {
        let mut aid = pgp::AID_PREFIX.to_vec();
        aid.extend_from_slice(&[0x03, 0x04]);
        aid.extend_from_slice(&manufacturer.to_be_bytes());
        aid.extend_from_slice(&serial.to_be_bytes());
        aid.extend_from_slice(&[0x00, 0x00]);
        aid
    }

    /// A status with every field fixed except the AID.
    fn status_with(aid: Vec<u8>) -> OpenPgpStatus {
        OpenPgpStatus {
            aid,
            sig_algo_id: None,
            dec_algo_id: None,
            aut_algo_id: None,
            sig_attrs: vec![],
            dec_attrs: vec![],
            aut_attrs: vec![],
            fingerprint_sig: [0; 20],
            fingerprint_dec: [0; 20],
            fingerprint_aut: [0; 20],
            tries_pw1: 3,
            tries_rc: 0,
            tries_pw3: 3,
            signature_count: None,
            otp_applet_serial: None,
        }
    }

    #[test]
    fn serial_bcd_decodes_only_for_token2_cards() {
        let status = status_with;

        // Token2: the raw AID serial is BCD — its nibbles are the printed digits.
        assert_eq!(
            status(aid_with(pgp::MANUFACTURER_ID_TOKEN2, 0x1234_5678)).serial(),
            Some(12_345_678)
        );
        // A non-decimal nibble can't be BCD, so the raw value passes through.
        assert_eq!(
            status(aid_with(pgp::MANUFACTURER_ID_TOKEN2, 0x1234_ABCD)).serial(),
            Some(0x1234_ABCD)
        );
        // Any other vendor's serial is a plain integer, decoded verbatim.
        assert_eq!(
            status(aid_with(0x0006, 0x1234_5678)).serial(),
            Some(0x1234_5678)
        );
        // Too-short AID still yields no serial rather than panicking.
        assert_eq!(status(vec![]).serial(), None);
    }

    #[test]
    fn serial_text_forms() {
        // The OTP applet's full serial wins, shown as printed on the key.
        let mut st = status_with(aid_with(0x0006, 1));
        st.otp_applet_serial = Some(1_000_000_123_456);
        assert_eq!(st.serial_text().as_deref(), Some("1000000123456"));
        // Otherwise the AID's serial bytes as GnuPG shows them: a YubiKey's
        // BCD bytes are its serial (a YubiKey 5.7, serial 37806840), a
        // Nitrokey's its hex serial (a Nitrokey 3, 42682ef7).
        let shown = |vendor, raw| status_with(aid_with(vendor, raw)).serial_text();
        assert_eq!(shown(0x0006, 0x3780_6840).as_deref(), Some("37806840"));
        assert_eq!(shown(0x000F, 0x4268_2EF7).as_deref(), Some("42682EF7"));
        assert_eq!(shown(0x0006, 0x0123_4567).as_deref(), Some("01234567"));
        // Neither: nothing to show.
        assert_eq!(status_with(vec![]).serial_text(), None);
    }

    #[test]
    fn only_token2_aids_read_the_otp_applet_serial() {
        assert!(wants_otp_applet_serial(&aid_with(
            pgp::MANUFACTURER_ID_TOKEN2,
            1
        )));
        assert!(!wants_otp_applet_serial(&aid_with(0x0006, 1))); // Yubico
        assert!(!wants_otp_applet_serial(&[]));
    }

    #[test]
    fn full_serial_prefers_the_otp_applet() {
        let mut st = status_with(aid_with(pgp::MANUFACTURER_ID_TOKEN2, 0x1234_5678));
        assert_eq!(st.full_serial(), Some(12_345_678));
        st.otp_applet_serial = Some(1_000_000_123_456);
        assert_eq!(st.full_serial(), Some(1_000_000_123_456));
    }
}
