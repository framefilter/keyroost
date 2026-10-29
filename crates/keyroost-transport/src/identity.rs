//! Read-only identity reads used to match a key's FIDO-HID node to its
//! smart-card reader when USB topology is unavailable (#51). Every function
//! sends only reads, answers "nothing" on any failure (a key that doesn't
//! answer is simply not matched by identity), and traces each exchange
//! through [`crate::trace`] so it shows in `--debug` output and in the
//! GUI's activity capture. HID reads say which kind of nothing it was
//! ([`KeyAnswer`](crate::identity::KeyAnswer)), so a caller can remember a key's own "no" and ask again
//! after a failure.

use std::path::Path;
use std::time::Duration;

use pcsc::{Protocols, ShareMode};

use crate::trace;
use keyroost_proto::trace::{format_line, Dir};

pub use crate::token2otp::token2_serial_reply_hid;

/// Yubico management READ CONFIG over CTAPHID (vendor 0x42, init bit set) —
/// the request yubikit's `ManagementSession(FidoConnection)` sends.
pub const YUBICO_CTAPHID_READ_CONFIG: u8 = 0xC2;
/// Solo 2 admin-app UUID over CTAPHID (vendor 0x62, init bit set).
pub const SOLO2_CTAPHID_UUID: u8 = 0xE2;
/// Solo 2 admin applet AID (`A0000008470000 0001`).
pub const SOLO2_ADMIN_AID: [u8; 9] = [0xA0, 0x00, 0x00, 0x08, 0x47, 0x00, 0x00, 0x00, 0x01];
/// Solo 2 admin UUID instruction, sent as the vendor tool sends it (case 1).
pub const SOLO2_UUID_APDU: [u8; 4] = [0x00, 0x62, 0x00, 0x00];

/// An identity read is a nicety: give up quickly rather than stall a scan.
const IDENTITY_HID_TIMEOUT: Duration = Duration::from_millis(1500);

/// What a key said to one HID identity read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyAnswer<T> {
    /// The key answered with this.
    Reply(T),
    /// The key answered, but without what was asked: an error it returned
    /// itself (`ERR_INVALID_CMD`: it doesn't support the command) or a
    /// refusing status word. Asking again gets the same answer.
    Declined,
    /// No answer: the device didn't open, timed out, was busy, or I/O
    /// failed. Worth asking again later.
    NoAnswer,
}

impl<T> KeyAnswer<T> {
    /// Read a reply with `f`; a reply `f` can't use is the key answering
    /// without what was asked.
    pub fn and_then<U>(self, f: impl FnOnce(T) -> Option<U>) -> KeyAnswer<U> {
        match self {
            Self::Reply(t) => f(t).map_or(KeyAnswer::Declined, KeyAnswer::Reply),
            Self::Declined => KeyAnswer::Declined,
            Self::NoAnswer => KeyAnswer::NoAnswer,
        }
    }
}

/// A failed CTAPHID exchange as a [`KeyAnswer`]: an error code the key
/// returned is its answer, except the ones that only say "not now" (busy,
/// locked to another channel, message timeout) or point at another
/// application's traffic interleaving with ours (invalid channel or
/// sequence).
pub(crate) fn ctaphid_error_answer<T>(e: &keyroost_ctap::hid::HidTransportError) -> KeyAnswer<T> {
    use keyroost_ctap::hid::{
        HidTransportError, CTAPHID_ERR_CHANNEL_BUSY, CTAPHID_ERR_INVALID_CHANNEL,
        CTAPHID_ERR_INVALID_SEQ, CTAPHID_ERR_LOCK_REQUIRED, CTAPHID_ERR_MSG_TIMEOUT,
    };
    match e {
        HidTransportError::DeviceError(
            CTAPHID_ERR_CHANNEL_BUSY
            | CTAPHID_ERR_LOCK_REQUIRED
            | CTAPHID_ERR_MSG_TIMEOUT
            | CTAPHID_ERR_INVALID_CHANNEL
            | CTAPHID_ERR_INVALID_SEQ,
        ) => KeyAnswer::NoAnswer,
        HidTransportError::DeviceError(_) => KeyAnswer::Declined,
        _ => KeyAnswer::NoAnswer,
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// What a FIDO interface said to CTAPHID INIT, the first question keyroost
/// asks it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitAnswer {
    /// INIT answered; `true` when its capability byte says CBOR (CTAP2),
    /// `false` for U2F (CTAP1) only.
    Cbor(bool),
    /// The interface didn't open (no permission, held by another program,
    /// gone), an I/O or backend error stopped INIT, or INIT got a "not now"
    /// CTAPHID error (busy, locked to another channel, message timeout,
    /// invalid channel or sequence). Nothing is known about the key; worth
    /// asking again.
    NotOpened,
    /// The interface opened, but INIT timed out, the reply was malformed
    /// (too short, too long, wrong command, out of sequence) or it was
    /// another device error. An INIT answer carrying another program's
    /// nonce is skipped, not counted.
    NoProperAnswer,
}

/// Classify one INIT attempt: `open` is whether the interface could be
/// opened at all ([`keyroost_ctap::CtapHidDevice::check_access`]), and
/// `init` opens it and sends INIT, called only when `open` succeeded.
pub fn init_answer_from(
    open: Result<(), keyroost_ctap::hid::HidTransportError>,
    init: impl FnOnce()
        -> Result<keyroost_ctap::hid::InitResponse, keyroost_ctap::hid::HidTransportError>,
) -> InitAnswer {
    use keyroost_ctap::hid::HidTransportError as E;
    if open.is_err() {
        return InitAnswer::NotOpened;
    }
    match init() {
        Ok(init) => InitAnswer::Cbor(init.supports_cbor()),
        // A "not now" error says nothing about the key; any other error code
        // is its answer, and not a proper one.
        Err(e @ E::DeviceError(_)) => match ctaphid_error_answer::<()>(&e) {
            KeyAnswer::NoAnswer => InitAnswer::NotOpened,
            _ => InitAnswer::NoProperAnswer,
        },
        Err(
            E::Timeout
            | E::InitResponseTooShort
            | E::UnexpectedCommand { .. }
            | E::OutOfSequence { .. }
            | E::PayloadTooLarge(_),
        ) => InitAnswer::NoProperAnswer,
        // I/O on the interface failed (the open for INIT, or a read or
        // write): no exchange took place.
        Err(_) => InitAnswer::NotOpened,
    }
}

/// Whether the FIDO interface at `path` speaks CBOR (CTAP2), from the
/// capability byte of its CTAPHID INIT answer (see [`InitAnswer`]). INIT is
/// the only command sent, and only to an interface that opens.
pub fn ctaphid_speaks_cbor(path: &Path, debug: bool) -> InitAnswer {
    let shown = path.display().to_string();
    let note = |body: String| {
        trace::line(debug, || {
            format_line(Dir::Note, "identity", &format!("{shown} {body}"))
        })
    };
    let open = keyroost_ctap::CtapHidDevice::check_access(path)
        .inspect_err(|e| note(format!("open failed: {e}")));
    let answer = init_answer_from(open, || {
        keyroost_ctap::CtapHidDevice::open(path)
            .map(|(_, init)| init)
            .inspect(|init| note(format!("ctaphid init caps=0x{:02x}", init.capabilities)))
            .inspect_err(|e| note(format!("ctaphid init failed: {e}")))
    });
    if answer == InitAnswer::NoProperAnswer {
        note("no proper init answer".into());
    }
    answer
}

/// Send one CTAPHID vendor command on a fresh channel and return the reply.
pub fn ctaphid_vendor_read(
    path: &Path,
    cmd: u8,
    payload: &[u8],
    debug: bool,
) -> KeyAnswer<Vec<u8>> {
    let shown = path.display().to_string();
    trace::line(debug, || {
        format_line(
            Dir::Sent,
            "identity",
            &format!("{shown} ctaphid cmd=0x{cmd:02x} {}", hex(payload)),
        )
    });
    let (mut dev, _init) = match keyroost_ctap::CtapHidDevice::open(path) {
        Ok(d) => d,
        Err(e) => {
            trace::line(debug, || {
                format_line(Dir::Note, "identity", &format!("{shown} open failed: {e}"))
            });
            return KeyAnswer::NoAnswer;
        }
    };
    dev.set_timeout(IDENTITY_HID_TIMEOUT);
    match dev.transact(cmd, payload) {
        Ok(resp) => {
            trace::line(debug, || {
                format_line(
                    Dir::Received,
                    "identity",
                    &format!("{shown} ctaphid {}", hex(&resp)),
                )
            });
            KeyAnswer::Reply(resp)
        }
        Err(e) => {
            trace::line(debug, || {
                format_line(
                    Dir::Note,
                    "identity",
                    &format!("{shown} ctaphid failed: {e}"),
                )
            });
            ctaphid_error_answer(&e)
        }
    }
}

/// SELECT an applet on `reader`, send one read command, return its data on
/// `9000`. With `select_must_succeed == false` the SELECT's status word is
/// ignored (some Token2 PIN+ firmware answers 6A81 yet switches applets —
/// same rule as `probe_readers`). A Molto2 reader is never connected.
pub fn ccid_applet_read(
    reader: &str,
    select: &[u8],
    command: &[u8],
    select_must_succeed: bool,
    debug: bool,
) -> Option<Vec<u8>> {
    if keyroost_proto::is_molto2_reader(reader) {
        return None;
    }
    let shown = keyroost_proto::trace::reader_name(reader);
    let ctx = crate::establish_context().ok()?;
    let name = std::ffi::CString::new(reader).ok()?;
    let card = match ctx.connect(&name, ShareMode::Shared, Protocols::ANY) {
        Ok(c) => c,
        Err(e) => {
            trace::line(debug, || {
                format_line(
                    Dir::Note,
                    "identity",
                    &format!("{shown} connect failed: {e}"),
                )
            });
            return None;
        }
    };
    let out = (|| -> Option<Vec<u8>> {
        trace::line(debug, || {
            format_line(Dir::Sent, "identity", &format!("{shown} {}", hex(select)))
        });
        let (_, s1, s2) = crate::transmit_apdu(&card, select).ok()?;
        trace::line(debug, || {
            format_line(
                Dir::Received,
                "identity",
                &format!("{shown} {s1:02X}{s2:02X}"),
            )
        });
        if select_must_succeed && !((s1 == 0x90 && s2 == 0x00) || s1 == 0x61) {
            return None;
        }
        trace::line(debug, || {
            format_line(Dir::Sent, "identity", &format!("{shown} {}", hex(command)))
        });
        let (data, sw) =
            crate::exchange_apdu(&card, command, 0x61, || vec![0x00, 0xC0, 0x00, 0x00, 0x00])
                .ok()?;
        trace::line(debug, || {
            format_line(
                Dir::Received,
                "identity",
                &format!("{shown} {} {sw:04X}", hex(&data)),
            )
        });
        (sw == 0x9000).then_some(data)
    })();
    // LeaveCard: never reset a card another session may hold.
    let _ = card.disconnect(pcsc::Disposition::LeaveCard);
    out
}

/// The firmware version a Trussed admin application reports over CCID
/// (`"1.9.1"`), for a key whose CTAPHID INIT carries none: the Nitrokey 3
/// answers INIT with version 0.0.0. `None` if the reader has no admin
/// application or its answer isn't a dotted version.
pub fn trussed_admin_firmware(reader: &str, debug: bool) -> Option<String> {
    use keyroost_piv::fingerprint::{
        parse_ascii_text, parse_dotted_version, NITROKEY_ADMIN_AID, NITROKEY_GET_VERSION_STRING,
    };
    let data = ccid_applet_read(
        reader,
        &keyroost_piv::select_by_aid(&NITROKEY_ADMIN_AID),
        &NITROKEY_GET_VERSION_STRING,
        true,
        debug,
    )?;
    let parts = parse_dotted_version(parse_ascii_text(&data)?.trim())?;
    Some(
        parts
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join("."),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendor_command_bytes_carry_the_ctaphid_init_bit() {
        assert_eq!(YUBICO_CTAPHID_READ_CONFIG, 0x80 | 0x42);
        assert_eq!(SOLO2_CTAPHID_UUID, 0x80 | 0x62);
    }

    #[test]
    fn build_select_is_iso_select_by_aid_for_the_solo2_admin_aid() {
        assert_eq!(
            keyroost_token2otp::build_select(&SOLO2_ADMIN_AID),
            vec![0x00, 0xA4, 0x04, 0x00, 9, 0xA0, 0x00, 0x00, 0x08, 0x47, 0x00, 0x00, 0x00, 0x01]
        );
    }

    #[test]
    fn a_molto2_reader_is_never_connected() {
        // Returns before PC/SC is even established (this passes with no pcscd).
        assert_eq!(
            ccid_applet_read(
                "TOKEN2 Molto2 00 00",
                &keyroost_token2otp::build_select(&SOLO2_ADMIN_AID),
                &SOLO2_UUID_APDU,
                true,
                false
            ),
            None
        );
    }

    #[test]
    fn a_key_returned_error_is_its_answer_but_not_now_errors_are_not() {
        use keyroost_ctap::hid::{HidTransportError as E, *};
        let answer = |e: E| ctaphid_error_answer::<()>(&e);
        assert_eq!(
            answer(E::DeviceError(CTAPHID_ERR_INVALID_CMD)),
            KeyAnswer::Declined
        );
        assert_eq!(
            answer(E::DeviceError(CTAPHID_ERR_OTHER)),
            KeyAnswer::Declined
        );
        for busy in [
            CTAPHID_ERR_CHANNEL_BUSY,
            CTAPHID_ERR_LOCK_REQUIRED,
            CTAPHID_ERR_MSG_TIMEOUT,
            CTAPHID_ERR_INVALID_CHANNEL,
            CTAPHID_ERR_INVALID_SEQ,
        ] {
            assert_eq!(answer(E::DeviceError(busy)), KeyAnswer::NoAnswer);
        }
        assert_eq!(answer(E::Timeout), KeyAnswer::NoAnswer);
        assert_eq!(answer(E::Backend("gone".into())), KeyAnswer::NoAnswer);
    }

    fn init_with_caps(capabilities: u8) -> keyroost_ctap::hid::InitResponse {
        keyroost_ctap::hid::InitResponse {
            channel_id: 1,
            protocol_version: 2,
            device_major: 0,
            device_minor: 0,
            device_build: 0,
            capabilities,
        }
    }

    /// An interface that doesn't open is "couldn't ask" and INIT is never
    /// sent; an answered INIT says CBOR or not; a "not now" error is
    /// "couldn't ask" too; anything else after a good open is no proper
    /// answer.
    #[test]
    fn init_errors_split_into_not_opened_and_no_proper_answer() {
        use keyroost_ctap::hid::{HidTransportError as E, *};
        let denied = || E::Io(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        assert_eq!(
            init_answer_from(Err(denied()), || panic!("INIT sent to a closed interface")),
            InitAnswer::NotOpened
        );
        assert_eq!(
            init_answer_from(Err(E::Backend("busy".into())), || panic!("INIT sent")),
            InitAnswer::NotOpened
        );
        assert_eq!(
            init_answer_from(Ok(()), || Ok(init_with_caps(CAPABILITY_CBOR))),
            InitAnswer::Cbor(true)
        );
        assert_eq!(
            init_answer_from(Ok(()), || Ok(init_with_caps(CAPABILITY_WINK))),
            InitAnswer::Cbor(false)
        );
        for not_now in [
            CTAPHID_ERR_CHANNEL_BUSY,
            CTAPHID_ERR_LOCK_REQUIRED,
            CTAPHID_ERR_MSG_TIMEOUT,
            CTAPHID_ERR_INVALID_CHANNEL,
            CTAPHID_ERR_INVALID_SEQ,
        ] {
            assert_eq!(
                init_answer_from(Ok(()), || Err(E::DeviceError(not_now))),
                InitAnswer::NotOpened,
                "error 0x{not_now:02x}"
            );
        }
        // The check passed, but the open for INIT failed after all.
        assert_eq!(
            init_answer_from(Ok(()), || Err(denied())),
            InitAnswer::NotOpened
        );
        assert_eq!(
            init_answer_from(Ok(()), || Err(E::Backend("gone".into()))),
            InitAnswer::NotOpened
        );
        for no_proper_answer in [
            E::Timeout,
            E::InitResponseTooShort,
            E::UnexpectedCommand {
                expected: 0x86,
                got: 0x83,
            },
            E::OutOfSequence {
                expected: 0,
                got: 3,
            },
            E::PayloadTooLarge(70_000),
            E::DeviceError(CTAPHID_ERR_INVALID_CMD),
            E::DeviceError(CTAPHID_ERR_OTHER),
        ] {
            let shown = format!("{no_proper_answer:?}");
            assert_eq!(
                init_answer_from(Ok(()), || Err(no_proper_answer)),
                InitAnswer::NoProperAnswer,
                "{shown}"
            );
        }
    }

    #[test]
    fn a_reply_that_cant_be_read_is_declined() {
        let reply = KeyAnswer::Reply(vec![1u8]);
        assert_eq!(
            reply.clone().and_then(|r| r.first().copied()),
            KeyAnswer::Reply(1)
        );
        assert_eq!(reply.and_then(|_| None::<u8>), KeyAnswer::Declined);
        assert_eq!(
            KeyAnswer::<Vec<u8>>::NoAnswer.and_then(|r| r.first().copied()),
            KeyAnswer::NoAnswer
        );
    }

    // Every test that tries to open a HID path lives here, so no two run at
    // once: in the macOS nix build, two tests opening HID paths in parallel
    // crashed the test binary.
    #[test]
    fn unreachable_hid_paths_get_no_answer_and_are_traced() {
        let p = std::path::Path::new("/nonexistent/keyroost-identity-test");
        assert_eq!(ctaphid_speaks_cbor(p, false), InitAnswer::NotOpened);
        crate::trace::begin();
        assert_eq!(
            ctaphid_vendor_read(p, YUBICO_CTAPHID_READ_CONFIG, &[0x00], false),
            KeyAnswer::NoAnswer
        );
        let lines = crate::trace::take().unwrap();
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("> identity ") && l.contains("cmd=0xc2")),
            "{lines:?}"
        );
        assert_eq!(token2_serial_reply_hid(p, false), KeyAnswer::NoAnswer);
    }
}
