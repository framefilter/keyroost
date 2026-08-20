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

use crate::TransportError;
use keyroost_piv as piv;
use keyroost_piv::{KeyAlg, Metadata, MgmtAlg, PinPolicy, PublicKey, Slot, TouchPolicy};
use pcsc::{Card, Context, Protocols, Scope, ShareMode};
use std::collections::HashMap;
use zeroize::Zeroizing;

/// How many wrong-credential attempts to make when intentionally blocking a
/// PIN or PUK during a factory reset: always more than the card's reported
/// retry count so a block is guaranteed, but hard-capped so a card that
/// misreports (or never decrements) cannot loop forever.
fn block_attempts_cap(reported: Option<u8>) -> u32 {
    reported.map(u32::from).unwrap_or(10).min(20) + 2
}

/// A throwaway 8-ASCII-digit credential for the loops that deliberately block a
/// PIN/PUK during a factory reset, drawn fresh from the host RNG and never equal
/// to `previous`.
///
/// Eight digits is a legal PIV **and** OpenPGP credential (both store 6–8
/// bytes), so the card evaluates the attempt and decrements its counter instead
/// of rejecting it on length. Drawing it fresh matters: any constant compiled in
/// here is also a value a card may legitimately hold, and this source is
/// published — a "wrong" guess that turns out to be right consumes no try at
/// all, and on the PUK path it rewrites the PIN. `previous` is excluded because
/// some applets refuse an unchanged credential without counting the attempt.
/// Shared with the OpenPGP applet's factory reset.
pub(crate) fn random_credential_guess(
    previous: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>, TransportError> {
    let mut raw = Zeroizing::new([0u8; GUESS_LEN]);
    // No fallback to a constant: a factory reset that can't draw fresh entropy
    // has to stop, not go back to guessing something predictable.
    getrandom::getrandom(&mut raw[..]).map_err(|_| TransportError::HostRngFailed)?;
    Ok(credential_guess_from(&raw, previous))
}

/// Length of a blocking-loop guess, in ASCII digits.
const GUESS_LEN: usize = 8;

/// The deterministic half of [`random_credential_guess`]: fold raw entropy into
/// ASCII digits, then step off `previous` if the draw happened to collide with
/// it. (Split out so the collision path is testable without stubbing the RNG.)
fn credential_guess_from(raw: &[u8; GUESS_LEN], previous: Option<&[u8]>) -> Zeroizing<Vec<u8>> {
    let mut guess = Zeroizing::new(Vec::with_capacity(GUESS_LEN));
    for byte in raw.iter() {
        guess.push(b'0' + byte % 10);
    }
    // A repeat is astronomically unlikely but would waste an attempt on an
    // applet that ignores an unchanged credential; bump the last digit rather
    // than re-rolling so this can never spin.
    if previous == Some(guess.as_slice()) {
        let last = GUESS_LEN - 1;
        guess[last] = b'0' + (guess[last] - b'0' + 1) % 10;
    }
    guess
}

/// Re-map an error raised by the final RESET step of [`PivSession::force_reset`]
/// onto what the card is actually left holding.
///
/// By that point the PIN and the PUK are deliberately blocked, so a card that
/// *permanently* refuses RESET is a card keyroost can no longer finish: the
/// single-applet `piv reset` sends the identical instruction and gets the
/// identical refusal. Only the permanent refusals are rewritten — a transport
/// fault (card pulled, reader gone) and an unspecific or transient status word
/// are not the card saying "this instruction does not exist", and re-running
/// the factory reset against a quiescent applet is still right there. The
/// callers append that re-run hint to everything left falling through.
fn map_reset_stage_error(e: TransportError) -> TransportError {
    match e {
        // Two refusals, and only two, are the card's final word.
        //
        // 6983 (mapped to PivResetNotAllowed): the card checked the one
        // precondition RESET has and says it is unmet — with the PIN and PUK
        // already blocked, a second run reaches the same check and gets the
        // same answer, so there is nothing left to retry.
        //
        // 6D00 (INS not supported) / 6A81 (function not supported): the
        // vendor-extension RESET instruction is not implemented at all. No
        // amount of retrying conjures it.
        //
        // Everything else the card can answer under this label — 6F00 (no
        // precise diagnosis), 6881, a 6A82 from an applet that momentarily
        // lost its selection after the blocking loops — says nothing about
        // RESET being unavailable, so it must NOT be rewritten into a verdict
        // of "permanently unusable". 6982 is deliberately absent for the same
        // reason: RESET is not gated behind a security state, so a card
        // answering "security status not satisfied" is in an unexpected
        // transient state rather than declaring RESET impossible.
        TransportError::PivResetNotAllowed
        | TransportError::Apdu {
            label: "piv reset",
            sw1: 0x6D,
            sw2: 0x00,
        }
        | TransportError::Apdu {
            label: "piv reset",
            sw1: 0x6A,
            sw2: 0x81,
        } => TransportError::PivForceResetIncomplete(
            "the PIN and the PUK are now both blocked, but the card refused the \
             RESET instruction, so the PIV applet was NOT wiped. Its keys and \
             certificates are still on the card and there is no keyroost command \
             that can finish this — `keyroostctl piv reset` sends the very \
             instruction the card just refused. The PIV part of the card is \
             unusable until whoever issued or made it resets it with their own \
             tooling. Any non-PIV applets on the same key (FIDO, OATH, OpenPGP) \
             are unaffected.",
        ),
        other => other,
    }
}

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
    /// Algorithm + public key of any slot this session itself generated a key
    /// in, keyed by key reference. This is a fallback source only, for cards
    /// that don't answer GET METADATA (pre-5.3 firmware, or non-Yubico PIV):
    /// `slot_key` (the shared source for CSR/self-sign) falls back to this
    /// when metadata comes back empty. It's populated by `generate_key`, or
    /// explicitly by a caller via [`Self::remember_pubkey`] — never by reading a
    /// card back, so it's exactly as trustworthy as whoever put it there. It
    /// lives only as long as this session (a fresh `open()` on reconnect
    /// starts empty, and there is deliberately no on-disk or cross-process
    /// persistence — see [`Self::remember_pubkey`] for how a caller bridges
    /// that) and any operation that changes what's in a slot (`delete_key`,
    /// `move_key`, `reset`) invalidates the corresponding entries — see
    /// [`PivSession::slot_key`].
    pubkey_cache: PubkeyCache,
}

/// The in-session public-key cache behind `PivSession`, keyed by PIV key
/// reference. Exactly five transitions exist, each mirroring the card
/// operation that makes it true; the session methods are one-line callers so
/// the unit tests below can pin the semantics without a live card:
///
/// * a fresh session starts empty (`new` — deliberately no persistence),
/// * `generate_key` / `remember_pubkey` make the slot's entry exactly the new
///   key (`remember`),
/// * `delete_key` leaves nothing to fall back to (`evict`),
/// * `move_key` relocates the key material, so its entry follows (`migrate`),
/// * `reset` wipes every slot (`clear`).
struct PubkeyCache(HashMap<u8, (KeyAlg, PublicKey)>);

impl PubkeyCache {
    fn new() -> Self {
        Self(HashMap::new())
    }

    /// The slot now holds exactly this key — `generate_key` minted it there,
    /// or the caller vouched for it via `remember_pubkey`. Replaces any
    /// previous entry: after a regenerate, the old pubkey must not survive to
    /// describe the new private key.
    fn remember(&mut self, key_ref: u8, alg: KeyAlg, key: PublicKey) {
        self.0.insert(key_ref, (alg, key));
    }

    /// The slot's key material is gone (`delete_key` succeeded): a stale
    /// entry here would produce a CSR/self-signed cert for a key that no
    /// longer exists. Evicting an uncached slot is a no-op.
    fn evict(&mut self, key_ref: u8) {
        self.0.remove(&key_ref);
    }

    /// The key itself relocated (`move_key` succeeded), not just its
    /// reference — carry a cached entry along with it rather than dropping
    /// it, so a subsequent CSR/self-sign at `dest` still works on
    /// metadata-less firmware, and leave nothing behind at `src`. An uncached
    /// `src` carries nothing and, crucially, invents nothing at `dest`.
    fn migrate(&mut self, src: u8, dest: u8) {
        if let Some(cached) = self.0.remove(&src) {
            self.0.insert(dest, cached);
        }
    }

    /// The applet was factory-reset (`reset`, which `force_reset` also
    /// funnels into): every slot is empty, nothing cached survives.
    fn clear(&mut self) {
        self.0.clear();
    }

    fn get(&self, key_ref: u8) -> Option<&(KeyAlg, PublicKey)> {
        self.0.get(&key_ref)
    }
}

/// Whether MOVE KEY is available given the reported firmware `(major, minor, _)`.
/// fw 5.7+ (Yubico). Unknown version → allow the attempt; the card refuses if
/// it truly can't (belt-and-suspenders with the pre-check).
fn move_key_supported(version: Option<(u8, u8, u8)>) -> bool {
    match version {
        Some((major, minor, _)) => major > 5 || (major == 5 && minor >= 7),
        None => true,
    }
}

impl PivSession {
    /// Connect to `reader_name` and SELECT the PIV application. Returns
    /// [`TransportError::NoPivApplet`] when the card has no PIV applet.
    pub fn open(reader_name: &str) -> Result<Self, TransportError> {
        let ctx = Context::establish(Scope::User).map_err(TransportError::PcscUnavailable)?;
        let cstr = std::ffi::CString::new(reader_name)
            .map_err(|_| TransportError::MalformedResponse("reader name contained NUL"))?;
        let card = ctx.connect(&cstr, ShareMode::Shared, Protocols::ANY)?;
        let mut session = Self {
            card,
            debug: false,
            pubkey_cache: PubkeyCache::new(),
        };
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
                let mut session = PivSession {
                    card,
                    debug: false,
                    pubkey_cache: PubkeyCache::new(),
                };
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
        if let Some(n) = crate::sw_tries_remaining(sw) {
            Some(n)
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
        let witness = Zeroizing::new(block_crypt(alg, key, z1, CryptOp::Decrypt)?);

        // Step 2: return the decrypted witness plus our own random challenge.
        let mut challenge = vec![0u8; alg.block_size()];
        getrandom::getrandom(&mut challenge).map_err(|_| TransportError::HostRngFailed)?;
        let apdu = Zeroizing::new(piv::general_auth_mutual(
            alg,
            piv::KEY_REF_MANAGEMENT,
            &witness,
            &challenge,
        ));
        let (resp2, sw2) = self.transmit_full(&apdu)?;
        // A wrong key makes the card reject our witness here.
        if sw2 != piv::SW_OK {
            return Err(TransportError::PivManagementAuthFailed);
        }
        // Verify the card encrypted our challenge correctly (authenticates the
        // card to us, completing mutual auth). Constant-time out of principle —
        // both sides are fresh per attempt, so the timing leaks nothing useful,
        // but secret-adjacent comparisons shouldn't short-circuit.
        let z2 = piv::parse_general_auth(&resp2, 0x82).map_err(TransportError::PivParse)?;
        let expected = Zeroizing::new(block_crypt(alg, key, &challenge, CryptOp::Encrypt)?);
        if !ct_eq(z2, &expected) {
            return Err(TransportError::PivManagementAuthFailed);
        }
        Ok(())
    }

    /// Present the PIV application PIN. Required before private-key use and
    /// set-pin-retries. The PIN must be 6–8 bytes — the byte layer returns a
    /// typed error on anything else rather than pad/truncate, so an unchecked
    /// over-length PIN can never silently verify (and store) something other
    /// than what the user typed, and no retry counter is consumed.
    pub fn verify_pin(&mut self, pin: &[u8]) -> Result<(), TransportError> {
        let apdu =
            Zeroizing::new(piv::verify_pin(pin).map_err(|_| TransportError::PivBadPinLength)?);
        let (_, sw) = self.transmit_full(&apdu)?;
        map_pin_sw(sw)
    }

    /// Change the PIV PIN. A wrong `old` PIN consumes a try and reports the
    /// remaining count. Both PINs must be 6–8 bytes.
    pub fn change_pin(&mut self, old: &[u8], new: &[u8]) -> Result<(), TransportError> {
        let apdu = Zeroizing::new(
            piv::change_reference(piv::PIN_REF_APPLICATION, old, new)
                .map_err(|_| TransportError::PivBadPinLength)?,
        );
        let (_, sw) = self.transmit_full(&apdu)?;
        map_pin_sw(sw)
    }

    /// Change the PUK. A wrong `old` PUK consumes a try and reports the count.
    /// Both PUKs must be 6–8 bytes.
    pub fn change_puk(&mut self, old: &[u8], new: &[u8]) -> Result<(), TransportError> {
        let apdu = Zeroizing::new(
            piv::change_reference(piv::PIN_REF_PUK, old, new)
                .map_err(|_| TransportError::PivBadPinLength)?,
        );
        let (_, sw) = self.transmit_full(&apdu)?;
        map_pin_sw(sw)
    }

    /// Unblock a blocked PIN using the PUK, setting a new PIN. A wrong PUK
    /// consumes a try and reports the remaining count. Both must be 6–8 bytes.
    pub fn unblock_pin(&mut self, puk: &[u8], new_pin: &[u8]) -> Result<(), TransportError> {
        let apdu = Zeroizing::new(
            piv::unblock_pin(puk, new_pin).map_err(|_| TransportError::PivBadPinLength)?,
        );
        let (_, sw) = self.transmit_full(&apdu)?;
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
        let apdu = Zeroizing::new(piv::set_management_key(alg, key, require_touch));
        let (_, sw) = self.transmit_full(&apdu)?;
        ok_or_write("piv set management key", sw)
    }

    /// Generate a fresh asymmetric key pair in `slot`, returning its public key.
    /// Requires prior management-key auth. Overwrites any existing key in the
    /// slot. May require a touch if the slot's touch policy demands it.
    ///
    /// On success, also caches `(alg, public key)` for `slot` in this
    /// session's in-memory key cache, since [`Self::slot_key`] and
    /// [`Self::slot_key_algorithm`]'s only other source for a key this fresh
    /// (the slot's certificate) doesn't exist yet on cards that don't answer
    /// GET METADATA. That only covers later calls *within this same
    /// session* — a caller that needs the key material to outlive this
    /// session (a separate `keyroostctl` invocation, or the GUI's
    /// fresh-session-per-action pattern) has to carry it forward itself and
    /// hand it to a later session via [`Self::remember_pubkey`]; see that
    /// method's doc comment for why this deliberately doesn't do that on its
    /// own.
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
        let key = piv::parse_public_key(&data).map_err(TransportError::PivParse)?;
        self.pubkey_cache.remember(slot.key_ref(), alg, key.clone());
        Ok(key)
    }

    /// Seed this session's in-memory key cache for `slot` with `(alg, key)`
    /// directly, without a card round-trip — the same cache
    /// [`Self::generate_key`] populates, and the same one [`Self::slot_key`] /
    /// [`Self::slot_key_algorithm`] fall back to when GET METADATA doesn't
    /// cover the slot.
    ///
    /// This is the deliberately-explicit replacement for what used to be an
    /// automatic on-disk cache: `PivSession` itself keeps no persistence
    /// (no file, nothing cross-process) — a fresh `open()` always starts
    /// empty, by design, so key material a caller isn't actively using never
    /// sits on disk. A caller that needs a metadata-less card's freshly
    /// generated key to survive past this session (a later `keyroostctl`
    /// invocation, or the GUI reopening a session for a later action) has to
    /// hold onto `(alg, key)` itself — in its own process-lifetime state, or
    /// wherever the user chose to put it — and call this before the call that
    /// needs it (`generate_csr`, `self_signed_certificate`, or checking
    /// `slot_key_algorithm` for display). Not verified against the card in
    /// any way: what's remembered here is exactly what's trusted later, so a
    /// caller handing over the wrong slot's key gets a CSR/self-signed
    /// certificate whose SPKI doesn't match the private key that actually
    /// signed it.
    pub fn remember_pubkey(&mut self, slot: Slot, alg: KeyAlg, key: PublicKey) {
        self.pubkey_cache.remember(slot.key_ref(), alg, key);
    }

    /// Import a DER-encoded X.509 certificate into `slot`. Requires prior
    /// management-key auth.
    ///
    /// Tries a single extended-length PUT DATA first; a cert big enough to
    /// need one (any real X.509 cert typically is) that gets rejected falls
    /// back to ISO 7816-4 command chaining — see [`Self::sign`] for why.
    pub fn import_certificate(&mut self, slot: Slot, der: &[u8]) -> Result<(), TransportError> {
        let value = piv::encode_certificate(der);
        let tag = slot.cert_object_tag();
        let apdu = piv::put_data(&tag, &value);
        let sw = if force_chaining() {
            if self.debug {
                eprintln!("! piv import certificate: forcing command chaining (env override)");
            }
            self.transmit_chain(
                "piv import certificate",
                &piv::put_data_chained(&tag, &value, CHAIN_CHUNK),
            )?
            .1
        } else {
            let (_, sw) = self.transmit_full(&apdu)?;
            if sw == piv::SW_OK || !uses_extended_length(&apdu) {
                sw
            } else {
                if self.debug {
                    eprintln!(
                        "! piv import certificate: extended length rejected (SW={sw:04X}); \
                         retrying with command chaining"
                    );
                }
                self.transmit_chain(
                    "piv import certificate",
                    &piv::put_data_chained(&tag, &value, CHAIN_CHUNK),
                )?
                .1
            }
        };
        ok_or_write("piv import certificate", sw)
    }

    /// Clear `slot`'s certificate object (standard PIV; universal across
    /// firmware). Removes only the X.509 certificate; the slot's private key
    /// persists. Requires prior management-key auth ([`authenticate_management`]).
    ///
    /// [`authenticate_management`]: PivSession::authenticate_management
    pub fn clear_certificate(&mut self, slot: Slot) -> Result<(), TransportError> {
        let (_, sw) = self.transmit_full(&piv::clear_certificate(slot))?;
        ok_or_write("piv clear certificate", sw)
    }

    /// Delete `slot`'s private key (Yubico MOVE-to-`0xFF` extension). Permanently
    /// erases the key material; the certificate object is untouched. Requires
    /// YubiKey firmware 5.7+ **and** prior management-key auth
    /// ([`authenticate_management`]). Cards older than 5.7 cannot delete a key —
    /// the only recovery there is to overwrite the slot.
    ///
    /// [`authenticate_management`]: PivSession::authenticate_management
    pub fn delete_key(&mut self, slot: Slot) -> Result<(), TransportError> {
        // Version-gate: MOVE/DELETE KEY landed in YubiKey firmware 5.7.
        let new_enough = matches!(self.version(), Some(v) if v >= (5, 7, 0));
        if !new_enough {
            return Err(TransportError::PivFirmwareTooOld(
                "deleting a key requires YubiKey firmware 5.7 or newer (older cards can only overwrite the slot)",
            ));
        }
        let (_, sw) = self.transmit_full(&piv::delete_key(slot))?;
        ok_or_write("piv delete key", sw)?;
        self.pubkey_cache.evict(slot.key_ref());
        Ok(())
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
        Ok(piv::find_tlv(inner, 0x70).map(<[u8]>::to_vec))
    }

    /// Yubico ATTEST: the self-signed attestation certificate for `slot`'s key
    /// (DER), proving it was generated on-card. Firmware 4.3+ (older firmware,
    /// and non-Yubico PIV cards, refuse this instruction). No PIN required.
    pub fn attest(&mut self, slot: Slot) -> Result<Vec<u8>, TransportError> {
        let (data, sw) = self.transmit_full(&piv::attest(slot.key_ref()))?;
        ok_or_write("piv attest", sw)?;
        Ok(data)
    }

    /// Read `slot`'s PIN/touch policy for display:
    ///
    /// 1. GET METADATA, tried unconditionally — cards that don't support it
    ///    (pre-5.3 firmware, or non-Yubico PIV) simply answer with something
    ///    other than `9000`/no policy, which falls through to step 2.
    /// 2. The ATTEST certificate's Yubico key-policy extension
    ///    (`1.3.6.1.4.1.41482.3.8`) — GET METADATA predates policy reporting,
    ///    but ATTEST itself has existed since 4.3. ATTEST is itself a Yubico
    ///    vendor instruction, so a non-Yubico PIV card refuses it too; that
    ///    refusal is handled the same as everything else here, not specially.
    ///
    /// `None` throughout means "not available for display", not a wire
    /// error — this is an informational read, not a precondition for a write,
    /// so every failure mode (missing extension, unparsable metadata, ATTEST
    /// itself being unsupported) collapses to the same answer.
    pub fn slot_policy(&mut self, slot: Slot) -> Option<(PinPolicy, TouchPolicy)> {
        let (pin, touch) =
            if let Some(policy) = self.metadata(slot.key_ref()).and_then(|m| m.policy) {
                policy
            } else {
                // Non-Yubico PIV cards refuse this vendor instruction outright
                // (a status word, not `9000`) — `.ok()?` turns that refusal
                // into the same "no policy available" `None` as every other
                // failure mode here.
                let cert = self.attest(slot).ok()?;
                keyroost_piv::x509_parse::parse_key_policy_extension(&cert)
                    .ok()
                    .flatten()?
            };
        Some((PinPolicy::from_id(pin)?, TouchPolicy::from_id(touch)?))
    }

    /// Read `slot`'s key algorithm for display, compatible with any PIV
    /// token — not just a YubiKey new enough for GET METADATA (5.3+):
    ///
    /// 1. GET METADATA. When it names an algorithm, that's authoritative —
    ///    return it.
    /// 2. This session's in-memory key cache (populated by
    ///    [`Self::generate_key`], or seeded explicitly via
    ///    [`Self::remember_pubkey`]). This is what makes a freshly generated key
    ///    show up immediately on metadata-less firmware: there's no
    ///    certificate yet for step 3 to read (self-sign/import hasn't run),
    ///    and GET METADATA's silence on such firmware doesn't mean "empty" —
    ///    it means "doesn't exist", so without this step a slot that was
    ///    *just* populated would still display as empty. A caller reading
    ///    status in a fresh session has to `remember_pubkey` first if it wants
    ///    this step to see anything.
    /// 3. Otherwise, fall back to the slot's certificate (a standard PIV data
    ///    object every card serves) and parse the algorithm out of its
    ///    SubjectPublicKeyInfo directly.
    ///
    /// Unlike [`Self::slot_key`] — which this does *not* replace — this never
    /// needs the actual public key bytes, only the algorithm, so the
    /// certificate fallback is enough; `slot_key`'s callers (CSR/self-sign)
    /// need the raw key material GET METADATA carries and stay
    /// metadata-only.
    pub fn slot_key_algorithm(&mut self, slot: Slot) -> Option<KeyAlg> {
        let alg_from_metadata = self
            .metadata(slot.key_ref())
            .and_then(|m| m.algorithm)
            .and_then(KeyAlg::from_id);
        if alg_from_metadata.is_some() {
            return alg_from_metadata;
        }
        if let Some((alg, _)) = self.pubkey_cache.get(slot.key_ref()) {
            return Some(*alg);
        }
        self.read_certificate(slot)
            .ok()
            .flatten()
            .and_then(|der| piv::x509_parse::parse_key_algorithm(&der).ok().flatten())
    }

    /// Ask `slot`'s private key to sign a *prepared* block via GENERAL
    /// AUTHENTICATE: a full PKCS#1 v1.5 padded block for RSA, the raw hash for
    /// ECDSA, or the raw message for Ed25519 (see
    /// [`keyroost_piv::x509::signature_hash`]). Requires a verified PIN —
    /// immediately prior for the signature slot (9C), whose policy is
    /// PIN-per-use. ECDSA signatures come back DER-encoded (`SEQUENCE{r,s}`),
    /// RSA/Ed25519 as raw blocks — either drops verbatim into an X.509
    /// signature BIT STRING.
    ///
    /// Tries a single extended-length GENERAL AUTHENTICATE first; for a key
    /// large enough to need one (RSA-2048+, or Ed25519 with a long enough
    /// TBS) that gets rejected falls back to ISO 7816-4 command chaining —
    /// confirmed necessary on a Token2 PIV token's contact interface, which
    /// answers a well-formed extended-`Lc` GENERAL AUTHENTICATE/PUT DATA with
    /// `SW=6A80` (unlike the `6700`/`6883` YubiKey's OpenPGP applet uses for
    /// the same condition — see
    /// [`OpenPgpSession::import_key`](crate::OpenPgpSession::import_key)) but
    /// accepts the identical data chained. The fallback only fires when the
    /// first attempt actually used extended-length encoding, so a genuine
    /// error on a short-form command (bad PIN state, wrong key, …) isn't
    /// retried.
    pub fn sign(
        &mut self,
        slot: Slot,
        alg: KeyAlg,
        prepared: &[u8],
    ) -> Result<Vec<u8>, TransportError> {
        let key_ref = slot.key_ref();
        let apdu = piv::general_auth_sign(alg, key_ref, prepared);
        let (data, sw) = if force_chaining() {
            if self.debug {
                eprintln!("! piv sign: forcing command chaining (env override)");
            }
            self.transmit_chain(
                "piv sign",
                &piv::general_auth_sign_chained(alg, key_ref, prepared, CHAIN_CHUNK),
            )?
        } else {
            let (data, sw) = self.transmit_full(&apdu)?;
            if sw == piv::SW_OK || !uses_extended_length(&apdu) {
                (data, sw)
            } else {
                if self.debug {
                    eprintln!(
                        "! piv sign: extended length rejected (SW={sw:04X}); retrying with \
                         command chaining"
                    );
                }
                self.transmit_chain(
                    "piv sign",
                    &piv::general_auth_sign_chained(alg, key_ref, prepared, CHAIN_CHUNK),
                )?
            }
        };
        ok_or_write("piv sign", sw)?;
        piv::parse_general_auth(&data, 0x82)
            .map(<[u8]>::to_vec)
            .map_err(TransportError::PivParse)
    }

    /// The algorithm and public key of the key stored in `slot`: from GET
    /// METADATA (firmware 5.3+) when the card answers it, else from this
    /// session's in-memory key cache. That cache is populated only by a prior
    /// [`Self::generate_key`] on `slot` in *this* session, or by a caller
    /// explicitly carrying the key material forward via [`Self::remember_pubkey`]
    /// — that's what lets CSR/self-sign work right after generation on cards
    /// that don't support GET METADATA (older YubiKeys, non-Yubico PIV
    /// tokens): the card refuses to name the key material any other way, so
    /// the cache is the only source left once GENERATE ASYMMETRIC has already
    /// told us what it made, and this crate keeps no on-disk or
    /// cross-process copy of that on its own (see [`Self::remember_pubkey`]).
    ///
    /// Errors when the slot is empty, the firmware predates GET METADATA
    /// *and* nothing was generated into `slot` in this session (nor handed to
    /// it via `remember_pubkey`), or a cached entry was invalidated by a later
    /// delete/move/reset.
    pub fn slot_key(&mut self, slot: Slot) -> Result<(KeyAlg, PublicKey), TransportError> {
        let key_ref = slot.key_ref();
        if let Some(md) = self.metadata(key_ref) {
            let alg =
                md.algorithm
                    .and_then(KeyAlg::from_id)
                    .ok_or(TransportError::MalformedResponse(
                        "slot metadata carries no key algorithm",
                    ))?;
            let raw = md.public_key.ok_or(TransportError::MalformedResponse(
                "slot metadata carries no public key",
            ))?;
            let key = public_key_from_metadata(&raw).map_err(TransportError::PivParse)?;
            return Ok((alg, key));
        }
        if let Some(cached) = self.pubkey_cache.get(key_ref).cloned() {
            return Ok(cached);
        }
        Err(TransportError::MalformedResponse(
            "slot has no key, or the firmware lacks GET METADATA and the key \
             material wasn't handed to this session — run `piv generate-key` \
             on this slot in this same session, or pass its previously saved \
             key material to this command, so it can be cached for \
             CSR/self-sign",
        ))
    }

    /// Build a PKCS#10 certificate-signing request for the key in `slot`,
    /// signed on the card, returned as PEM. The slot must hold a key
    /// (generated or imported) and the PIN must already be verified.
    pub fn generate_csr(&mut self, slot: Slot, subject: &str) -> Result<String, TransportError> {
        let (alg, key) = self.slot_key(slot)?;
        let subject = piv::x509::SubjectName::parse(subject).map_err(TransportError::X509)?;
        let spki = piv::spki::subject_public_key_info(&key, alg)
            .map_err(|_| TransportError::MalformedResponse("slot key/algorithm mismatch"))?;
        let cri = piv::x509::csr_info(&subject, &spki);
        let prepared = prepared_block(alg, &cri)?;
        let sig = self.sign(slot, alg, &prepared)?;
        let der = piv::x509::assemble(&cri, alg, &sig).map_err(TransportError::X509)?;
        Ok(piv::x509::pem_csr(&der))
    }

    /// Create a self-signed certificate for the key in `slot` (validity in
    /// unix seconds), sign it on the card, **import it into the slot**, and
    /// return the DER. Requires a verified PIN (for the signature) and prior
    /// management-key auth (for the import).
    pub fn self_signed_certificate(
        &mut self,
        slot: Slot,
        subject: &str,
        not_before: i64,
        not_after: i64,
    ) -> Result<Vec<u8>, TransportError> {
        let (alg, key) = self.slot_key(slot)?;
        let subject = piv::x509::SubjectName::parse(subject).map_err(TransportError::X509)?;
        let spki = piv::spki::subject_public_key_info(&key, alg)
            .map_err(|_| TransportError::MalformedResponse("slot key/algorithm mismatch"))?;
        // 16 random bytes keep the serial unique and well under RFC 5280's
        // 20-octet ceiling even after the positive-INTEGER zero prefix.
        let mut serial = [0u8; 16];
        getrandom::getrandom(&mut serial).map_err(|_| TransportError::HostRngFailed)?;
        let tbs = piv::x509::tbs_certificate(&serial, alg, &subject, not_before, not_after, &spki)
            .map_err(TransportError::X509)?;
        let prepared = prepared_block(alg, &tbs)?;
        let sig = self.sign(slot, alg, &prepared)?;
        let der = piv::x509::assemble(&tbs, alg, &sig).map_err(TransportError::X509)?;
        self.import_certificate(slot, &der)?;
        Ok(der)
    }

    /// Relocate a slot's private key to another slot (Yubico MOVE KEY). Refuses
    /// a same-slot move, firmware below 5.7, and an occupied destination
    /// (GET METADATA pre-check — the card also refuses, this gives a clear error
    /// first). Moves ONLY the key; the source slot's certificate stays put.
    /// Requires prior management-key auth ([`authenticate_management`]), same
    /// as [`delete_key`].
    ///
    /// [`authenticate_management`]: PivSession::authenticate_management
    /// [`delete_key`]: PivSession::delete_key
    pub fn move_key(&mut self, src: Slot, dest: Slot) -> Result<(), TransportError> {
        if src.key_ref() == dest.key_ref() {
            return Err(TransportError::MalformedResponse(
                "source and destination slots are the same",
            ));
        }
        if !move_key_supported(self.version()) {
            return Err(TransportError::PivFirmwareTooOld(
                "moving a key requires YubiKey firmware 5.7 or newer",
            ));
        }
        if self.slot_has_key(dest)? {
            return Err(TransportError::PivDestinationOccupied(dest));
        }
        let (_, sw) = self.transmit_full(&piv::move_key(src, dest))?;
        ok_or_write("piv move key", sw)?;
        // The key itself relocated, not just its reference — carry a cached
        // entry along with it rather than dropping it, so a subsequent
        // CSR/self-sign at `dest` still works on metadata-less firmware.
        self.pubkey_cache.migrate(src.key_ref(), dest.key_ref());
        Ok(())
    }

    /// Whether `slot` holds a private key, via GET METADATA. Works for retired
    /// slots too — it just reads whatever key reference `slot` maps to. This is
    /// the on-demand occupancy check (not part of [`status`]'s snapshot, which
    /// stays 4 GET DATA calls rather than 24 by never touching retired slots).
    ///
    /// Derives occupancy from [`metadata`], which folds a transient/comms
    /// error into the same `None` as a genuinely empty slot, so a rare
    /// transient failure here is reported as an empty slot; the card's own
    /// refusal to write over an occupied destination is the backstop.
    ///
    /// [`status`]: PivSession::status
    /// [`metadata`]: PivSession::metadata
    pub fn slot_has_key(&mut self, slot: Slot) -> Result<bool, TransportError> {
        Ok(self.metadata(slot.key_ref()).is_some())
    }

    /// Reset the PIV application to factory defaults. Only succeeds when **both**
    /// the PIN and PUK are blocked (the card enforces this); otherwise the card
    /// returns `6983` and this maps to [`TransportError::PivResetNotAllowed`].
    pub fn reset(&mut self) -> Result<(), TransportError> {
        let (_, sw) = self.transmit_full(&piv::reset())?;
        if sw == piv::SW_AUTH_BLOCKED {
            return Err(TransportError::PivResetNotAllowed);
        }
        ok_or_write("piv reset", sw)?;
        // Wipes every slot; nothing cached survives it. `force_reset` reaches
        // this same reset() at the end of its own path, so it's covered too.
        self.pubkey_cache.clear();
        Ok(())
    }

    /// Factory-reset the PIV applet the manufacturer-intended way even when the
    /// PIN/PUK are unknown: deliberately exhaust the PIN retry counter with wrong
    /// values, then the PUK counter, then send RESET (which the card only accepts
    /// once BOTH are blocked). This is the documented decommission path; it wipes
    /// all PIV keys, certificates, and PINs and leaves the applet at defaults.
    ///
    /// Used only by the whole-device factory reset — the single-applet PIV reset
    /// keeps requiring an already-blocked card (that path is a user who knows the
    /// card is blocked, not one asking us to block it).
    pub fn force_reset(&mut self) -> Result<(), TransportError> {
        // The PIN a successful PUK guess would leave behind: RESET RETRY COUNTER
        // rewrites the PIN when it succeeds, so this has to be a value we can
        // name back to the user (see PivPukGuessAccepted) rather than something
        // random nobody could recover. The PIV default is the friendliest choice.
        const RECOVERY_PIN: &[u8] = b"123456";

        // RESET (INS FB) is a vendor extension — SP 800-73-4 defines no such
        // instruction, so a standards-only card answers 6D00/6A81 and there is
        // no way back from the blocked PIN and PUK this path deliberately
        // creates. GET VERSION and GET SERIAL come from the same extension
        // family, so a card that answers neither is exactly the card that must
        // be refused. Decide here, before the first wrong VERIFY: afterwards the
        // damage is already done.
        let st = self.status()?;
        if st.version.is_none() && st.serial.is_none() {
            return Err(TransportError::PivForceResetUnsupported);
        }

        // 1. Block the PIN.
        let mut blocked = false;
        let mut previous: Option<Zeroizing<Vec<u8>>> = None;
        for _ in 0..block_attempts_cap(st.pin_retries) {
            let guess = random_credential_guess(previous.as_ref().map(|g| g.as_slice()))?;
            match self.verify_pin(&guess) {
                // The guess matched the live PIN: VERIFY changes nothing, it just
                // costs us an attempt that didn't decrement. Draw another.
                Ok(()) => {}
                Err(TransportError::PivPinRejected {
                    tries_remaining: Some(0),
                }) => {
                    blocked = true;
                    break;
                }
                Err(TransportError::PivPinRejected { .. }) => {}
                Err(e) => return Err(e),
            }
            previous = Some(guess);
        }
        if !blocked {
            return Err(TransportError::PivForceResetIncomplete(
                "the PIV PIN would not report itself blocked within the attempt cap, \
                 so the card was NOT wiped — its keys and certificates are still \
                 there and its PIN retry counter has been spent down. Re-run the \
                 factory reset to finish.",
            ));
        }

        // 2. Block the PUK (via unblock-pin, whose wrong PUK decrements the PUK
        //    counter). Size the loop from the card's real PUK count — `piv
        //    set-retries` can raise it past the default cap, and a loop that
        //    stops short leaves the PIN blocked and the card un-wiped. GET
        //    METADATA is firmware 5.3+, so `None` (the conservative default)
        //    stays the fallback.
        let puk_tries = self
            .metadata(piv::PIN_REF_PUK)
            .and_then(|m| m.retries)
            .map(|(remaining, _total)| remaining);
        let mut puk_blocked = false;
        let mut previous: Option<Zeroizing<Vec<u8>>> = None;
        for _ in 0..block_attempts_cap(puk_tries) {
            let guess = random_credential_guess(previous.as_ref().map(|g| g.as_slice()))?;
            match self.unblock_pin(&guess, RECOVERY_PIN) {
                // The guess *was* the PUK, so RESET RETRY COUNTER really ran: the
                // PIN is now RECOVERY_PIN and unblocked. That is a card-state
                // change the user has to be told about, and on cards that restore
                // the retry counter on success the loop would never end.
                Ok(()) => return Err(TransportError::PivPukGuessAccepted),
                Err(TransportError::PivPinRejected {
                    tries_remaining: Some(0),
                }) => {
                    puk_blocked = true;
                    break;
                }
                Err(TransportError::PivPinRejected { .. }) => {}
                Err(e) => return Err(e),
            }
            previous = Some(guess);
        }
        if !puk_blocked {
            return Err(TransportError::PivForceResetIncomplete(
                "the PIV PUK would not report itself blocked within the attempt cap. \
                 The PIN is now blocked but the card was NOT wiped — re-run the \
                 factory reset to finish, or unblock the PIN with the PUK if you \
                 know it.",
            ));
        }

        // 3. Both blocked — RESET should now succeed. If the card refuses it
        //    for good (the capability pre-check passes on either GET VERSION or
        //    GET SERIAL, so a card can clear it and still have no RESET), say
        //    so honestly: that is the one exit that leaves a card nothing here
        //    can rescue. An unspecific status word is not that exit and keeps
        //    the caller's "re-run the factory reset" hint.
        self.reset().map_err(map_reset_stage_error)
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
        // GENERAL AUTHENTICATE responses today are only ciphertext (witness /
        // encrypted challenge), but the same INS in signing/decrypt mode
        // returns recovered plaintext — redact uniformly so a future caller
        // can't leak through a trace.
        let resp_sensitive = apdu.get(1) == Some(&0x87);
        const IO: crate::AppletIo = crate::AppletIo {
            label: "piv",
            more_data_sw: piv::SW_MORE_DATA,
            get_response: piv::get_response,
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

    /// Transmit an ISO 7816-4 command-chaining sequence (see
    /// [`keyroost_piv::general_auth_sign_chained`] /
    /// [`keyroost_piv::put_data_chained`]): every intermediate chunk must be
    /// accepted with `9000` or the chain aborts; the final chunk's status
    /// word and (already `61xx`-reassembled) response payload are returned
    /// as-is for the caller to interpret. Mirrors
    /// [`OpenPgpSession::transmit_chain`](crate::OpenPgpSession), added here
    /// for the same reason: extended-length rejection ([`Self::sign`],
    /// [`Self::import_certificate`]).
    fn transmit_chain(
        &mut self,
        label: &'static str,
        chunks: &[Vec<u8>],
    ) -> Result<(Vec<u8>, u16), TransportError> {
        let last = chunks.len().saturating_sub(1);
        for (i, chunk) in chunks.iter().enumerate() {
            let (data, sw) = self.transmit_full(chunk)?;
            if i == last {
                return Ok((data, sw));
            }
            // An intermediate chain link the card didn't accept (anything but
            // 9000) aborts the chain.
            if sw != piv::SW_OK {
                return Err(TransportError::Apdu {
                    label,
                    sw1: (sw >> 8) as u8,
                    sw2: sw as u8,
                });
            }
        }
        Ok((Vec::new(), piv::SW_OK)) // unreachable: chunk builders never return an empty list
    }
}

/// Chunk size for the command-chaining fallback, matching the 254-byte chunks
/// [`keyroost-openpgp`](keyroost_openpgp)'s equivalent fallback uses (GnuPG's
/// `exmode = -254`, one byte short of the short-form `Lc` ceiling).
const CHAIN_CHUNK: usize = 254;

/// Whether `apdu` — built by [`piv::general_auth_sign`] or [`piv::put_data`],
/// whose data field is never empty — used extended-length encoding. Both
/// always emit a non-zero short-form `Lc` for a body that fits in one byte,
/// so byte 4 being the `0x00` extended-length marker is unambiguous.
fn uses_extended_length(apdu: &[u8]) -> bool {
    apdu.get(4) == Some(&0x00)
}

/// `KEYROOST_PIV_FORCE_CHAINING` forces the command-chaining path (so the
/// fallback can be exercised on a card that also accepts extended length —
/// mirrors `KEYROOST_OPENPGP_FORCE_CHAINING`).
fn force_chaining() -> bool {
    std::env::var_os("KEYROOST_PIV_FORCE_CHAINING").is_some()
}

/// Turn to-be-signed bytes into the block the card's GENERAL AUTHENTICATE
/// expects: PKCS#1 v1.5 over SHA-256 for RSA (the card does raw RSA), the bare
/// SHA-256/384 digest for ECDSA, and the unhashed message for Ed25519.
fn prepared_block(alg: KeyAlg, tbs: &[u8]) -> Result<Vec<u8>, TransportError> {
    use keyroost_piv::x509::{self, SigHash};
    match x509::signature_hash(alg).map_err(TransportError::X509)? {
        SigHash::Sha256 => {
            let digest = keyroost_proto::sha256::sha256(tbs);
            let rsa_k = match alg {
                KeyAlg::Rsa1024 => Some(128),
                KeyAlg::Rsa2048 => Some(256),
                KeyAlg::Rsa3072 => Some(384),
                KeyAlg::Rsa4096 => Some(512),
                _ => None,
            };
            Ok(match rsa_k {
                Some(k) => x509::pkcs1_v15_sha256(&digest, k),
                None => digest.to_vec(),
            })
        }
        SigHash::Sha384 => Ok(keyroost_proto::sha512::sha384(tbs).to_vec()),
        SigHash::None => Ok(tbs.to_vec()),
    }
}

/// Decode the public key carried in GET METADATA tag `0x04`. Yubico encodes it
/// as the same TLVs a GENERATE response carries — observed both with and
/// without the outer `7F49` template across firmware, so accept either shape.
fn public_key_from_metadata(raw: &[u8]) -> Result<PublicKey, keyroost_piv::ParseError> {
    if raw.starts_with(&[0x7F, 0x49]) {
        return piv::parse_public_key(raw);
    }
    // Bare inner TLVs: 86 (EC point) or 81/82 (RSA modulus/exponent).
    if let Some(point) = piv::find_tlv(raw, 0x86) {
        return Ok(PublicKey::Ecc {
            point: point.to_vec(),
        });
    }
    match (piv::find_tlv(raw, 0x81), piv::find_tlv(raw, 0x82)) {
        (Some(m), Some(e)) => Ok(PublicKey::Rsa {
            modulus: m.to_vec(),
            exponent: e.to_vec(),
        }),
        _ => Err(keyroost_piv::ParseError::NotPublicKey),
    }
}

/// Constant-time slice equality (fold-XOR; no early exit on the bytes).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
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
    } else if let Some(n) = crate::sw_tries_remaining(sw) {
        Err(TransportError::PivPinRejected {
            tries_remaining: Some(n),
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
/// management-key witness/challenge round. `data` must be a non-empty multiple
/// of the cipher block size — the witness comes from the card, and an unaligned
/// length would otherwise panic in the block conversion below.
fn block_crypt(
    alg: MgmtAlg,
    key: &[u8],
    data: &[u8],
    op: CryptOp,
) -> Result<Vec<u8>, TransportError> {
    use cipher::generic_array::GenericArray;
    use cipher::{BlockDecrypt, BlockEncrypt, KeyInit};

    if data.is_empty() || data.len() % alg.block_size() != 0 {
        return Err(TransportError::MalformedResponse(
            "PIV witness/challenge length is not a whole cipher block",
        ));
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn move_key_firmware_gate() {
        // MOVE KEY needs fw 5.7+. Below that -> refuse.
        assert!(!move_key_supported(Some((5, 6, 0))));
        assert!(move_key_supported(Some((5, 7, 0))));
        assert!(move_key_supported(Some((5, 7, 4))));
        assert!(move_key_supported(Some((6, 0, 0))));
        // Unknown version -> allow the attempt (card will reject if unsupported).
        assert!(move_key_supported(None));
    }

    // --- pubkey-cache invalidation semantics ---------------------------------
    //
    // The session methods that drive these transitions need a live card, so
    // what gets pinned here is the PubkeyCache transition each of them is a
    // one-line caller of. What these defend: on metadata-less firmware the
    // cache is the ONLY source for CSR/self-sign key material, so a stale
    // entry silently produces a certificate whose SPKI doesn't match the
    // private key on the card.

    fn ecc(byte: u8) -> PublicKey {
        PublicKey::Ecc {
            point: vec![0x04, byte],
        }
    }

    fn rsa(byte: u8) -> PublicKey {
        PublicKey::Rsa {
            modulus: vec![byte],
            exponent: vec![0x01, 0x00, 0x01],
        }
    }

    #[test]
    fn pubkey_cache_starts_empty_and_remember_seeds_exactly_one_slot() {
        // A fresh open() has nothing to fall back to — there is deliberately
        // no on-disk or cross-process persistence.
        let mut cache = PubkeyCache::new();
        assert!(cache.0.is_empty());
        cache.remember(0x9A, KeyAlg::EccP256, ecc(1));
        assert_eq!(cache.0.len(), 1);
        assert_eq!(cache.get(0x9A), Some(&(KeyAlg::EccP256, ecc(1))));
        // Seeding 9A says nothing about any other slot.
        assert_eq!(cache.get(0x9C), None);
    }

    #[test]
    fn remember_replaces_the_slots_previous_entry() {
        // generate_key over an occupied slot mints a new keypair: the old
        // cached pubkey must not survive to describe the new private key.
        let mut cache = PubkeyCache::new();
        cache.remember(0x9A, KeyAlg::EccP256, ecc(1));
        cache.remember(0x9A, KeyAlg::Rsa2048, rsa(2));
        assert_eq!(cache.0.len(), 1);
        assert_eq!(cache.get(0x9A), Some(&(KeyAlg::Rsa2048, rsa(2))));
    }

    #[test]
    fn evict_forgets_only_the_deleted_slot() {
        let mut cache = PubkeyCache::new();
        cache.remember(0x9A, KeyAlg::EccP256, ecc(1));
        cache.remember(0x9C, KeyAlg::EccP384, ecc(2));
        cache.evict(0x9A);
        // The deleted slot's key material is gone from the card; a bystander
        // slot's entry is still good.
        assert_eq!(cache.get(0x9A), None);
        assert_eq!(cache.get(0x9C), Some(&(KeyAlg::EccP384, ecc(2))));
        // Deleting a slot this session never cached is a quiet no-op.
        cache.evict(0x82);
        assert_eq!(cache.0.len(), 1);
    }

    #[test]
    fn migrate_carries_the_entry_and_leaves_nothing_at_src() {
        let mut cache = PubkeyCache::new();
        cache.remember(0x9A, KeyAlg::EccP256, ecc(1));
        cache.remember(0x9C, KeyAlg::EccP384, ecc(2));
        cache.migrate(0x9A, 0x82);
        // The key relocated: its entry follows it to dest — that's what keeps
        // CSR/self-sign working at dest on metadata-less firmware — and src
        // no longer holds anything to describe.
        assert_eq!(cache.get(0x9A), None);
        assert_eq!(cache.get(0x82), Some(&(KeyAlg::EccP256, ecc(1))));
        // A bystander slot is untouched.
        assert_eq!(cache.get(0x9C), Some(&(KeyAlg::EccP384, ecc(2))));
    }

    #[test]
    fn migrate_of_an_uncached_src_changes_nothing() {
        // Moving a key this session never generated: there is nothing to
        // carry, and crucially nothing gets invented at dest.
        let mut cache = PubkeyCache::new();
        cache.remember(0x9C, KeyAlg::EccP384, ecc(2));
        cache.migrate(0x9A, 0x82);
        assert_eq!(cache.get(0x82), None);
        assert_eq!(cache.get(0x9C), Some(&(KeyAlg::EccP384, ecc(2))));
        assert_eq!(cache.0.len(), 1);
    }

    #[test]
    fn migrate_replaces_a_stale_dest_entry() {
        // The card refuses MOVE KEY into an occupied slot, so any dest entry
        // present here is stale by definition (e.g. remember_pubkey of a slot
        // that was later emptied out-of-session) — the key that actually
        // arrived must win.
        let mut cache = PubkeyCache::new();
        cache.remember(0x9A, KeyAlg::EccP256, ecc(1));
        cache.remember(0x82, KeyAlg::EccP384, ecc(9));
        cache.migrate(0x9A, 0x82);
        assert_eq!(cache.get(0x82), Some(&(KeyAlg::EccP256, ecc(1))));
        assert_eq!(cache.get(0x9A), None);
        assert_eq!(cache.0.len(), 1);
    }

    #[test]
    fn clear_wipes_every_slot() {
        // reset() factory-wipes the applet, and force_reset funnels into the
        // same reset() at the end of its path — both end here, with no
        // survivors for any slot.
        let mut cache = PubkeyCache::new();
        cache.remember(0x9A, KeyAlg::EccP256, ecc(1));
        cache.remember(0x9C, KeyAlg::Rsa2048, rsa(2));
        cache.remember(0x82, KeyAlg::Ed25519, ecc(3));
        cache.clear();
        assert!(cache.0.is_empty());
    }

    #[test]
    fn block_attempts_cap_exceeds_reported_but_is_bounded() {
        // A card reporting 3 tries: we try a few more than 3 to guarantee a block.
        assert_eq!(block_attempts_cap(Some(3)), 5);
        // Unknown count: default to 10 (max PIV retry the spec allows) + margin.
        assert_eq!(block_attempts_cap(None), 12);
        // A pathological huge count is clamped so the loop can't run away.
        assert_eq!(block_attempts_cap(Some(200)), 22);
        // A raised PUK count (set-retries allows more than the old hardcoded 12)
        // still outlasts the card.
        assert_eq!(block_attempts_cap(Some(15)), 17);
    }

    #[test]
    fn credential_guess_is_eight_digits_and_varies() {
        let mut previous: Option<Zeroizing<Vec<u8>>> = None;
        for _ in 0..64 {
            let guess = random_credential_guess(previous.as_ref().map(|g| g.as_slice())).unwrap();
            // 8 bytes keeps it inside the 6-8 range PIV and OpenPGP store, so
            // the card evaluates it instead of rejecting it on length.
            assert_eq!(guess.len(), 8);
            assert!(guess.iter().all(u8::is_ascii_digit));
            // Never the same twice running: an applet that ignores an unchanged
            // credential would not count the attempt.
            assert_ne!(previous.as_ref().map(|g| g.to_vec()), Some(guess.to_vec()));
            previous = Some(guess);
        }
    }

    #[test]
    fn credential_guess_steps_off_a_collision() {
        // Entropy that maps straight onto "01234567".
        let raw = [0u8, 1, 2, 3, 4, 5, 6, 7];
        assert_eq!(credential_guess_from(&raw, None).as_slice(), b"01234567");
        // Same draw, but that's what we just sent: last digit moves on.
        assert_eq!(
            credential_guess_from(&raw, Some(b"01234567")).as_slice(),
            b"01234568"
        );
        // The bump wraps rather than running past '9'.
        let nines = [9u8; 8];
        assert_eq!(
            credential_guess_from(&nines, Some(b"99999999")).as_slice(),
            b"99999990"
        );
    }

    #[test]
    fn reset_refusals_report_an_unrecoverable_card() {
        // The card's final word on RESET, once the PIN and PUK are already
        // blocked: 6983 (the one precondition RESET has, re-checked identically
        // on a re-run) and the 6D00 / 6A81 pair that means the instruction does
        // not exist. 6982 is NOT here — see reset_transient_refusals_fall_through.
        for e in [
            TransportError::PivResetNotAllowed,
            TransportError::Apdu {
                label: "piv reset",
                sw1: 0x6D,
                sw2: 0x00,
            },
            TransportError::Apdu {
                label: "piv reset",
                sw1: 0x6A,
                sw2: 0x81,
            },
        ] {
            let mapped = map_reset_stage_error(e);
            assert!(matches!(mapped, TransportError::PivForceResetIncomplete(_)));
            let text = mapped.to_string();
            // The message has to say what is true and never point back at the
            // command that just failed.
            assert!(text.contains("NOT wiped"));
            assert!(text.contains("no keyroost command"));
            assert!(!text.contains("re-run"));
        }
    }

    #[test]
    fn reset_transient_refusals_fall_through() {
        // Status words the card can answer under the RESET label that say
        // nothing about RESET being unavailable: 6F00 (no precise diagnosis),
        // 6881, and a 6A82 from an applet that momentarily lost its selection
        // after the blocking loops. The PIN and PUK really are blocked by then,
        // but the applet is still resettable — re-running the factory reset
        // against a quiescent applet succeeds — so calling the card
        // permanently unusable would steer the user away from the fix. These
        // pass through untouched and pick up the caller's re-run hint.
        //
        // 6982 (PivSecurityNotSatisfied) belongs here rather than with the
        // terminal set: RESET is not gated behind a security state, so a card
        // answering it is in an unexpected transient state, not declaring the
        // instruction impossible.
        for e in [
            TransportError::Apdu {
                label: "piv reset",
                sw1: 0x6F,
                sw2: 0x00,
            },
            TransportError::Apdu {
                label: "piv reset",
                sw1: 0x68,
                sw2: 0x81,
            },
            TransportError::Apdu {
                label: "piv reset",
                sw1: 0x6A,
                sw2: 0x82,
            },
            TransportError::PivSecurityNotSatisfied,
        ] {
            let before = e.to_string();
            let mapped = map_reset_stage_error(e);
            assert!(!matches!(
                mapped,
                TransportError::PivForceResetIncomplete(_)
            ));
            assert_eq!(mapped.to_string(), before);
        }
    }

    #[test]
    fn transport_faults_at_reset_are_left_alone() {
        // A card that stopped answering is not a card refusing RESET — the wipe
        // may still be finishable, so these must pass through unchanged.
        for e in [
            TransportError::ShortResponse {
                label: "piv",
                got: 1,
                expected_min: 2,
            },
            TransportError::MalformedResponse("applet continuation exceeded the chunk limit"),
            // A label from some other command can only mean an error that did
            // not originate at the RESET step.
            TransportError::Apdu {
                label: "piv pin/puk",
                sw1: 0x6A,
                sw2: 0x81,
            },
        ] {
            let before = e.to_string();
            assert_eq!(map_reset_stage_error(e).to_string(), before);
        }
    }
}
