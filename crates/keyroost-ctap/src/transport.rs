//! Transport abstraction for CTAP2 commands.
//!
//! Every CTAP command in this crate is expressed as a single logical exchange:
//! send a command byte plus a CBOR payload, get back a response byte string
//! (the first byte is the CTAP2 status, the rest is CBOR). Historically that
//! exchange went only over CTAP-HID (USB). [`CtapTransport`] lifts it into a
//! trait so the same command code can run over any link that can carry a CTAP
//! message — in particular PC/SC, which is how both **NFC** and **contact**
//! smart-card readers present a key (see [`crate::pcsc`]).
//!
//! The trait is deliberately tiny: one method, mirroring
//! `CtapHidDevice::transact`. Backends own all the link-specific framing —
//! CTAP-HID channels and continuation packets on one side, ISO 7816 `NFCCTAP_MSG`
//! APDUs with command chaining and `GET RESPONSE` reassembly on the other — and
//! present the command layer with the same clean `Vec<u8>` it always had.

use crate::cmd::CtapError;

/// Forwarding impl so a `&mut T` (and, by extension, the `&mut dyn` produced
/// from a boxed transport) can be passed where `impl CtapTransport` is expected.
impl<T: CtapTransport + ?Sized> CtapTransport for &mut T {
    fn transact(&mut self, cmd: u8, payload: &[u8]) -> Result<Vec<u8>, CtapError> {
        (**self).transact(cmd, payload)
    }
    fn set_timeout(&mut self, timeout: std::time::Duration) {
        (**self).set_timeout(timeout);
    }
    fn set_cancel_flag(&mut self, flag: std::sync::Arc<std::sync::atomic::AtomicBool>) {
        (**self).set_cancel_flag(flag);
    }
}

/// Forwarding impl so a `Box<dyn CtapTransport>` is itself a `CtapTransport`,
/// letting a runtime-selected backend (HID vs PC/SC) be used with the generic
/// command functions that take `&mut impl CtapTransport`.
impl CtapTransport for Box<dyn CtapTransport> {
    fn transact(&mut self, cmd: u8, payload: &[u8]) -> Result<Vec<u8>, CtapError> {
        (**self).transact(cmd, payload)
    }
    fn set_timeout(&mut self, timeout: std::time::Duration) {
        (**self).set_timeout(timeout);
    }
    fn set_cancel_flag(&mut self, flag: std::sync::Arc<std::sync::atomic::AtomicBool>) {
        (**self).set_cancel_flag(flag);
    }
}
///
/// `cmd` is the CTAP-HID command byte the command layer would historically pass
/// (e.g. `CTAPHID_CBOR`). Non-HID transports interpret it as needed — the PC/SC
/// backend, for instance, treats `CTAPHID_CBOR` as "wrap this payload in an
/// `NFCCTAP_MSG` APDU" and ignores HID-only commands like `CTAPHID_INIT`.
pub trait CtapTransport {
    /// Perform one command/response exchange and return the raw response bytes
    /// (CTAP2 status byte followed by the CBOR body).
    fn transact(&mut self, cmd: u8, payload: &[u8]) -> Result<Vec<u8>, CtapError>;

    /// Extend the read timeout for a long, user-present operation (a reset or a
    /// fingerprint-enrollment capture that waits for a touch).
    ///
    /// HID overrides this to widen its report-read deadline. Transports that
    /// manage their own timeouts (PC/SC drivers apply their own card timeouts)
    /// can leave the default no-op.
    fn set_timeout(&mut self, _timeout: std::time::Duration) {}

    /// Wire in a cooperative cancel flag so a capture blocked waiting for a touch
    /// can abort promptly when the user cancels.
    ///
    /// HID checks this between KEEPALIVE frames. PC/SC has no equivalent hook in
    /// its blocking transmit, so the default is a no-op (a reader-attached
    /// enrollment simply runs to its own timeout if not completed).
    fn set_cancel_flag(&mut self, _flag: std::sync::Arc<std::sync::atomic::AtomicBool>) {}
}
