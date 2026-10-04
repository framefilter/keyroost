//! Read-only identity reads used to match a key's FIDO-HID node to its
//! smart-card reader when USB topology is unavailable (#51). Every function
//! sends only reads, returns `None` on any failure (a key that doesn't
//! answer is simply not matched by identity), and traces each exchange
//! through [`crate::trace`] so it shows in `--debug` output and in the
//! GUI's activity capture.

use std::path::Path;
use std::time::Duration;

use pcsc::{Context, Protocols, Scope, ShareMode};

use crate::trace;

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

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Send one CTAPHID vendor command on a fresh channel and return the reply.
pub fn ctaphid_vendor_read(path: &Path, cmd: u8, payload: &[u8], debug: bool) -> Option<Vec<u8>> {
    let shown = path.display().to_string();
    trace::line(debug, || {
        format!(
            "[identity] {shown} CTAPHID > cmd=0x{cmd:02x} {}",
            hex(payload)
        )
    });
    let (mut dev, _init) = match keyroost_ctap::CtapHidDevice::open(path) {
        Ok(d) => d,
        Err(e) => {
            trace::line(debug, || format!("[identity] {shown} open failed: {e}"));
            return None;
        }
    };
    dev.set_timeout(IDENTITY_HID_TIMEOUT);
    match dev.transact(cmd, payload) {
        Ok(resp) => {
            trace::line(debug, || {
                format!("[identity] {shown} CTAPHID < {}", hex(&resp))
            });
            Some(resp)
        }
        Err(e) => {
            trace::line(debug, || format!("[identity] {shown} CTAPHID failed: {e}"));
            None
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
    let ctx = Context::establish(Scope::User).ok()?;
    let name = std::ffi::CString::new(reader).ok()?;
    let card = match ctx.connect(&name, ShareMode::Shared, Protocols::ANY) {
        Ok(c) => c,
        Err(e) => {
            trace::line(debug, || format!("[identity] {reader} connect failed: {e}"));
            return None;
        }
    };
    let out = (|| -> Option<Vec<u8>> {
        trace::line(debug, || format!("[identity] {reader} > {}", hex(select)));
        let (_, s1, s2) = crate::transmit_apdu(&card, select).ok()?;
        trace::line(debug, || format!("[identity] {reader} < {s1:02X}{s2:02X}"));
        if select_must_succeed && !((s1 == 0x90 && s2 == 0x00) || s1 == 0x61) {
            return None;
        }
        trace::line(debug, || format!("[identity] {reader} > {}", hex(command)));
        let (data, sw) =
            crate::exchange_apdu(&card, command, 0x61, || vec![0x00, 0xC0, 0x00, 0x00, 0x00])
                .ok()?;
        trace::line(debug, || {
            format!("[identity] {reader} < {} {sw:04X}", hex(&data))
        });
        (sw == 0x9000).then_some(data)
    })();
    // LeaveCard: never reset a card another session may hold.
    let _ = card.disconnect(pcsc::Disposition::LeaveCard);
    out
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
    fn unreachable_hid_paths_answer_none_and_are_traced() {
        let p = std::path::Path::new("/nonexistent/keyroost-identity-test");
        crate::trace::begin();
        assert_eq!(
            ctaphid_vendor_read(p, YUBICO_CTAPHID_READ_CONFIG, &[0x00], false),
            None
        );
        let lines = crate::trace::take().unwrap();
        assert!(
            lines
                .iter()
                .any(|l| l.contains("[identity]") && l.contains("cmd=0xc2")),
            "{lines:?}"
        );
        assert_eq!(token2_serial_reply_hid(p, false), None);
    }
}
