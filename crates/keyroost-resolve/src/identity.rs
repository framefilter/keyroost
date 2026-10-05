//! Device-reported identity, used to match a key's FIDO-HID node to its
//! smart-card reader where USB topology is unavailable (Windows, macOS —
//! #51). Each vendor's two channels report the same identity in their own
//! encoding; the canonicalisers below map both to one comparable value.
//! Identities are compared only within the same [`IdScheme`]: two
//! encodings whose relation no real key has confirmed are never equated.
//! They are used for matching only; persisted only when the user names a
//! key (the keyring's existing behaviour).

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;

use keyroost_hid::HidDevice;
use keyroost_transport::ReaderProbe;

/// Which encoding an identity came from. Values are comparable only
/// within one scheme.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IdScheme {
    /// Yubico management serial, decimal without leading zeros.
    YubicoSerial,
    /// Solo 2 device UUID, 32 lowercase hex digits.
    Solo2Uuid,
    /// Token2 §6.10 serial from the FIDO-format reply (`D1 len ascii-hex`),
    /// lowercase hex of the decoded bytes — the form `probe_readers` stores.
    Token2Fido,
    /// Token2 serial from the OTP applet's reply (plain ASCII decimal).
    /// Not compared with [`Self::Token2Fido`] until a real key confirms
    /// how the two encodings relate.
    Token2Otp,
}

/// One canonicalised device-reported identity.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CanonicalId {
    pub scheme: IdScheme,
    pub value: String,
}

impl CanonicalId {
    /// The identity in the form `Device::serial` already uses for this
    /// vendor, when it has one: lets a HID row show the serial its own
    /// channel reported instead of a guessed CCID one.
    pub fn row_serial(&self) -> Option<String> {
        match self.scheme {
            IdScheme::YubicoSerial | IdScheme::Token2Fido => Some(self.value.clone()),
            IdScheme::Solo2Uuid | IdScheme::Token2Otp => None,
        }
    }

    /// First and last two characters plus the length, for traces.
    pub fn abbreviated(&self) -> String {
        let chars: Vec<char> = self.value.chars().collect();
        if chars.len() <= 4 {
            return self.value.clone();
        }
        let head: String = chars[..2].iter().collect();
        let tail: String = chars[chars.len() - 2..].iter().collect();
        format!("{head}\u{2026}{tail} (len {})", chars.len())
    }
}

impl fmt::Display for CanonicalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} {}", self.scheme, self.abbreviated())
    }
}

/// Yubico management READ CONFIG reply (`len || TLV…`, tag 0x02 = 4-byte
/// big-endian serial) — what yubikit's `ManagementSession` parses.
pub fn yubico_from_read_config(reply: &[u8]) -> Option<CanonicalId> {
    let (&len, rest) = reply.split_first()?;
    let mut tlv = rest.get(..len as usize)?;
    while tlv.len() >= 2 {
        let (tag, l) = (tlv[0], tlv[1] as usize);
        let value = tlv.get(2..2 + l)?;
        if tag == 0x02 && l == 4 {
            let n = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
            return (n != 0).then(|| CanonicalId {
                scheme: IdScheme::YubicoSerial,
                value: n.to_string(),
            });
        }
        tlv = &tlv[2 + l..];
    }
    None
}

/// A decimal Yubico serial as read over CCID (`ReaderProbe::yubikey_serial`).
pub fn yubico_from_serial_str(s: &str) -> Option<CanonicalId> {
    let n: u32 = s.trim().parse().ok()?;
    (n != 0).then(|| CanonicalId {
        scheme: IdScheme::YubicoSerial,
        value: n.to_string(),
    })
}

/// The Solo 2 admin app's 16-byte UUID reply.
pub fn solo2_from_uuid_bytes(b: &[u8]) -> Option<CanonicalId> {
    (b.len() == 16).then(|| CanonicalId {
        scheme: IdScheme::Solo2Uuid,
        value: b.iter().map(|x| format!("{x:02x}")).collect(),
    })
}

/// The Solo 2 USB iSerial (the same UUID, uppercase hex).
pub fn solo2_from_iserial(s: &str) -> Option<CanonicalId> {
    let s = s.trim();
    (s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())).then(|| CanonicalId {
        scheme: IdScheme::Solo2Uuid,
        value: s.to_ascii_lowercase(),
    })
}

/// Token2 §6.10 GET_INFO reply in the FIDO format (HID, or CCID after a
/// FIDO-applet SELECT).
pub fn token2_from_fido_reply(reply: &[u8]) -> Option<CanonicalId> {
    let bytes = keyroost_token2otp::parse_serial(reply).ok()?;
    (!bytes.is_empty()).then(|| CanonicalId {
        scheme: IdScheme::Token2Fido,
        value: bytes.iter().map(|b| format!("{b:02x}")).collect(),
    })
}

/// Token2 OTP-applet reply to the same request (plain ASCII decimal).
pub fn token2_from_otp_reply(reply: &[u8]) -> Option<CanonicalId> {
    let n = keyroost_token2otp::parse_otp_serial(reply).ok()?;
    Some(CanonicalId {
        scheme: IdScheme::Token2Otp,
        value: n.to_string(),
    })
}

/// Identities read for one enumeration, keyed by HID path and reader name.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Identities {
    pub hid: HashMap<PathBuf, CanonicalId>,
    pub reader: HashMap<String, CanonicalId>,
}

/// One vendor's way of reading a key's identity on each side. Adding a
/// vendor means adding an implementation to [`IDENTITY_READERS`]; the
/// matching logic in `device.rs` does not change.
pub trait IdentityReader: Sync {
    fn vendor(&self) -> &'static str;
    /// Whether this HID node is one of this vendor's keys.
    fn claims_hid(&self, h: &HidDevice) -> bool;
    /// Whether this reader is worth asking (label-grade: the read is the evidence).
    fn claims_reader(&self, p: &ReaderProbe) -> bool;
    fn read_hid(&self, h: &HidDevice, debug: bool) -> Option<CanonicalId>;
    fn read_ccid(&self, p: &ReaderProbe, debug: bool) -> Option<CanonicalId>;
}

pub const SOLO2_VID: u16 = 0x1209;
pub const SOLO2_PID: u16 = 0xBEEE;

/// Yubico: management READ CONFIG over CTAPHID; CCID serial from the probe.
pub struct YubicoIdentity;
impl IdentityReader for YubicoIdentity {
    fn vendor(&self) -> &'static str {
        "Yubico"
    }
    fn claims_hid(&self, h: &HidDevice) -> bool {
        h.vendor_id == crate::VID_YUBICO
    }
    fn claims_reader(&self, p: &ReaderProbe) -> bool {
        !p.is_molto2
            && (p.yubikey_serial.is_some()
                || p.reader_name.to_ascii_lowercase().contains("yubikey"))
    }
    fn read_hid(&self, h: &HidDevice, debug: bool) -> Option<CanonicalId> {
        use keyroost_transport::identity::{ctaphid_vendor_read, YUBICO_CTAPHID_READ_CONFIG};
        // Payload = config page 0, as yubikit sends it.
        let reply = ctaphid_vendor_read(&h.path, YUBICO_CTAPHID_READ_CONFIG, &[0x00], debug)?;
        yubico_from_read_config(&reply)
    }
    fn read_ccid(&self, p: &ReaderProbe, _debug: bool) -> Option<CanonicalId> {
        // Already read during the probe — no extra traffic.
        p.yubikey_serial.as_deref().and_then(yubico_from_serial_str)
    }
}

/// Solo 2: USB iSerial (fallback: admin UUID over CTAPHID); admin applet over CCID.
pub struct Solo2Identity;
impl IdentityReader for Solo2Identity {
    fn vendor(&self) -> &'static str {
        "Solo 2"
    }
    fn claims_hid(&self, h: &HidDevice) -> bool {
        h.vendor_id == SOLO2_VID && h.product_id == SOLO2_PID
    }
    fn claims_reader(&self, p: &ReaderProbe) -> bool {
        !p.is_molto2
            && !p.is_prog
            && p.yubikey_serial.is_none()
            && (p.has_fido || p.has_oath || p.has_piv || p.has_openpgp)
    }
    fn read_hid(&self, h: &HidDevice, debug: bool) -> Option<CanonicalId> {
        use keyroost_transport::identity::{ctaphid_vendor_read, SOLO2_CTAPHID_UUID};
        h.serial_number
            .as_deref()
            .and_then(solo2_from_iserial)
            .or_else(|| {
                ctaphid_vendor_read(&h.path, SOLO2_CTAPHID_UUID, &[], debug)
                    .and_then(|r| solo2_from_uuid_bytes(&r))
            })
    }
    fn read_ccid(&self, p: &ReaderProbe, debug: bool) -> Option<CanonicalId> {
        use keyroost_transport::identity::{ccid_applet_read, SOLO2_ADMIN_AID, SOLO2_UUID_APDU};
        ccid_applet_read(
            &p.reader_name,
            &keyroost_token2otp::build_select(&SOLO2_ADMIN_AID),
            &SOLO2_UUID_APDU,
            true,
            debug,
        )
        .and_then(|r| solo2_from_uuid_bytes(&r))
    }
}

/// Token2: §6.10 GET_INFO over HID; over CCID after a FIDO-applet SELECT,
/// else the OTP applet's differently-encoded reply (never equated with the
/// FIDO format until confirmed on a real key).
pub struct Token2Identity;
impl IdentityReader for Token2Identity {
    fn vendor(&self) -> &'static str {
        "Token2"
    }
    fn claims_hid(&self, h: &HidDevice) -> bool {
        h.vendor_id == keyroost_proto::USB_VID
    }
    fn claims_reader(&self, p: &ReaderProbe) -> bool {
        !p.is_molto2 && !p.is_prog && p.yubikey_serial.is_none() && (p.has_fido || p.has_otp)
    }
    fn read_hid(&self, h: &HidDevice, debug: bool) -> Option<CanonicalId> {
        keyroost_transport::identity::token2_serial_reply_hid(&h.path, debug)
            .and_then(|r| token2_from_fido_reply(&r))
    }
    fn read_ccid(&self, p: &ReaderProbe, debug: bool) -> Option<CanonicalId> {
        use keyroost_token2otp::{
            build_select, read_serial_request, FIDO_APPLET_AID, OTP_APPLET_AID,
        };
        use keyroost_transport::identity::ccid_applet_read;
        let req = read_serial_request();
        ccid_applet_read(
            &p.reader_name,
            &build_select(&FIDO_APPLET_AID),
            &req,
            !token2_lax_fido_select(p),
            debug,
        )
        .and_then(|r| token2_from_fido_reply(&r))
        .or_else(|| {
            ccid_applet_read(
                &p.reader_name,
                &build_select(&OTP_APPLET_AID),
                &req,
                true,
                debug,
            )
            .and_then(|r| token2_from_otp_reply(&r))
        })
    }
}

/// Whether the Token2 identity read may ignore a refused FIDO-applet SELECT
/// on this reader (some Token2 firmware answers 6A81 yet switches applets).
/// Only for readers that look like a Token2 key — the OTP applet answered,
/// or the reader name says Token2 — so the vendor read never reaches
/// whatever applet happens to be selected on another vendor's key.
fn token2_lax_fido_select(p: &ReaderProbe) -> bool {
    p.has_otp || p.reader_name.to_ascii_lowercase().contains("token2")
}

/// Every vendor that can be matched by identity.
pub static IDENTITY_READERS: &[&dyn IdentityReader] =
    &[&YubicoIdentity, &Solo2Identity, &Token2Identity];

/// What to read: `(registry index, HID path)` and `(registry index, reader)`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IdentityPlan {
    pub hid: Vec<(usize, PathBuf)>,
    pub ccid: Vec<(usize, String)>,
}

/// Plan identity reads for what step 1 (USB topology) leaves unmatched, so
/// a Linux setup — where topology settles everything — sends nothing. A
/// pair is worth reading only when the vendor has candidates on BOTH
/// sides and the two do not both report topology (both reporting and
/// differing is already proof they are different keys). Pure.
///
/// Planned per (vendor, reader) pair, not once per reader: a broad
/// `claims_reader` from one vendor (e.g. Solo 2, which claims any
/// non-Molto2/non-prog reader with any applet) must not starve a second
/// vendor (e.g. Token2) that also has an unmatched HID node eligible
/// against the very same reader. Deduplication below is therefore keyed
/// on `(registry index, path/name)`, not on the path/name alone.
pub fn plan_identity_reads(
    hids: &[HidDevice],
    probes: &[ReaderProbe],
    registry: &[&dyn IdentityReader],
) -> IdentityPlan {
    let fido: Vec<&HidDevice> = hids.iter().filter(|h| h.is_fido()).collect();
    let bound = crate::device::topology_bound(&fido, probes);
    let claimed: Vec<&str> = bound.iter().flatten().map(String::as_str).collect();
    let free_hids: Vec<&HidDevice> = fido
        .iter()
        .zip(&bound)
        .filter(|(_, b)| b.is_none())
        .map(|(h, _)| *h)
        .collect();
    let free_readers: Vec<&ReaderProbe> = probes
        .iter()
        .filter(|p| !p.is_molto2 && !p.is_prog && !claimed.contains(&p.reader_name.as_str()))
        .collect();
    let eligible = |h: &HidDevice, p: &ReaderProbe| !(h.usb_bus.is_some() && p.usb_bus.is_some());
    let mut plan = IdentityPlan::default();
    for (v, r) in registry.iter().enumerate() {
        let hs: Vec<&HidDevice> = free_hids
            .iter()
            .copied()
            .filter(|h| r.claims_hid(h))
            .collect();
        let ps: Vec<&ReaderProbe> = free_readers
            .iter()
            .copied()
            .filter(|p| r.claims_reader(p))
            .collect();
        for h in &hs {
            if ps.iter().any(|p| eligible(h, p))
                && !plan.hid.iter().any(|(pv, x)| *pv == v && x == &h.path)
            {
                plan.hid.push((v, h.path.clone()));
            }
        }
        for p in &ps {
            if hs.iter().any(|h| eligible(h, p))
                && !plan
                    .ccid
                    .iter()
                    .any(|(pv, x)| *pv == v && x == &p.reader_name)
            {
                plan.ccid.push((v, p.reader_name.clone()));
            }
        }
    }
    plan
}

/// Perform the planned reads (read-only; each traced under `--debug`).
pub fn read_identities(
    plan: &IdentityPlan,
    hids: &[HidDevice],
    probes: &[ReaderProbe],
    registry: &[&dyn IdentityReader],
    debug: bool,
) -> Identities {
    let mut ids = Identities::default();
    for (v, path) in &plan.hid {
        let Some(h) = hids.iter().find(|h| &h.path == path) else {
            continue;
        };
        let id = registry[*v].read_hid(h, debug);
        if debug {
            let shown = id
                .as_ref()
                .map_or_else(|| "no answer".to_string(), ToString::to_string);
            eprintln!(
                "[identity] {} {}: {shown}",
                registry[*v].vendor(),
                path.display()
            );
        }
        if let Some(id) = id {
            ids.hid.insert(path.clone(), id);
        }
    }
    for (v, name) in &plan.ccid {
        let Some(p) = probes.iter().find(|p| &p.reader_name == name) else {
            continue;
        };
        let id = registry[*v].read_ccid(p, debug);
        if debug {
            let shown = id
                .as_ref()
                .map_or_else(|| "no answer".to_string(), ToString::to_string);
            eprintln!("[identity] {} '{name}': {shown}", registry[*v].vendor());
        }
        if let Some(id) = id {
            ids.reader.insert(name.clone(), id);
        }
    }
    ids
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yubico_read_config_yields_the_decimal_serial() {
        // len=10; TLV 01/02 (usb supported) then 02/04 serial 0x00BC614E = 12345678.
        let reply = [
            10, 0x01, 0x02, 0x02, 0x3F, 0x02, 0x04, 0x00, 0xBC, 0x61, 0x4E,
        ];
        let id = yubico_from_read_config(&reply).unwrap();
        assert_eq!(
            id,
            CanonicalId {
                scheme: IdScheme::YubicoSerial,
                value: "12345678".into()
            }
        );
    }

    #[test]
    fn yubico_read_config_rejects_truncated_missing_or_zero_serials() {
        assert_eq!(yubico_from_read_config(&[]), None);
        assert_eq!(yubico_from_read_config(&[10, 0x02, 0x04, 0x00]), None); // len past the end
        assert_eq!(yubico_from_read_config(&[4, 0x01, 0x02, 0x02, 0x3F]), None); // no serial tag
        assert_eq!(yubico_from_read_config(&[6, 0x02, 0x04, 0, 0, 0, 0]), None); // serial 0
        assert_eq!(yubico_from_read_config(&[5, 0x02, 0x04, 0, 0, 1]), None); // TLV overruns
    }

    #[test]
    fn yubico_ccid_string_normalises_to_the_same_value() {
        assert_eq!(
            yubico_from_serial_str("0012345678").unwrap().value,
            "12345678"
        );
        assert_eq!(
            yubico_from_serial_str("12345678"),
            yubico_from_read_config(&[6, 0x02, 0x04, 0x00, 0xBC, 0x61, 0x4E])
        );
        assert_eq!(yubico_from_serial_str("abc"), None);
        assert_eq!(yubico_from_serial_str("0"), None);
    }

    #[test]
    fn solo2_usb_iserial_and_admin_uuid_agree() {
        let bytes = [
            0x07, 0xA9, 0x56, 0x8F, 0xBE, 0x31, 0xAD, 0x5D, 0xAD, 0x1F, 0x22, 0x98, 0x47, 0x6C,
            0xF0, 0xD4,
        ];
        let a = solo2_from_uuid_bytes(&bytes).unwrap();
        let b = solo2_from_iserial("07A9568FBE31AD5DAD1F2298476CF0D4").unwrap();
        assert_eq!(a, b);
        assert_eq!(a.value, "07a9568fbe31ad5dad1f2298476cf0d4");
        assert_eq!(solo2_from_uuid_bytes(&bytes[..15]), None);
        assert_eq!(solo2_from_iserial("07A9-not-hex"), None);
    }

    #[test]
    fn token2_encodings_are_never_compared_with_each_other() {
        let fido = token2_from_fido_reply(b"\xD1\x040A1B").unwrap();
        assert_eq!(
            fido,
            CanonicalId {
                scheme: IdScheme::Token2Fido,
                value: "0a1b".into()
            }
        );
        let otp = token2_from_otp_reply(b"\xD1\x0501234").unwrap();
        assert_eq!(
            otp,
            CanonicalId {
                scheme: IdScheme::Token2Otp,
                value: "1234".into()
            }
        );
        // Same digits, different encodings: unequal until a real key confirms the mapping.
        let fido_digits = token2_from_fido_reply(b"\xD1\x041234").unwrap();
        let otp_digits = token2_from_otp_reply(b"\xD1\x041234").unwrap();
        assert_ne!(fido_digits, otp_digits);
        assert_eq!(token2_from_fido_reply(b"\xD0\x00"), None);
    }

    #[test]
    fn row_serial_only_for_formats_rows_already_use() {
        let y = CanonicalId {
            scheme: IdScheme::YubicoSerial,
            value: "1".into(),
        };
        let s = CanonicalId {
            scheme: IdScheme::Solo2Uuid,
            value: "ab".into(),
        };
        let t = CanonicalId {
            scheme: IdScheme::Token2Otp,
            value: "9".into(),
        };
        assert_eq!(y.row_serial().as_deref(), Some("1"));
        assert_eq!(s.row_serial(), None);
        assert_eq!(t.row_serial(), None);
    }

    #[test]
    fn abbreviation_never_prints_the_whole_identity() {
        let id = CanonicalId {
            scheme: IdScheme::YubicoSerial,
            value: "12345678".into(),
        };
        assert_eq!(id.abbreviated(), "12…78 (len 8)");
        assert!(!id.to_string().contains("12345678"));
    }

    use keyroost_hid::{HID_USAGE_FIDO_AUTHENTICATOR, HID_USAGE_PAGE_FIDO};
    use keyroost_transport::ReaderProbe;
    use std::sync::Mutex;

    fn hid(
        vid: u16,
        pid: u16,
        path: &str,
        serial: Option<&str>,
        bus: Option<u8>,
        addr: Option<u8>,
    ) -> HidDevice {
        HidDevice {
            path: path.into(),
            vendor_id: vid,
            product_id: pid,
            product_name: "Key".into(),
            usage_page: HID_USAGE_PAGE_FIDO,
            usage: HID_USAGE_FIDO_AUTHENTICATOR,
            serial_number: serial.map(str::to_owned),
            usb_bus: bus,
            usb_address: addr,
        }
    }
    fn reader(name: &str, yk: Option<&str>, bus: Option<u8>, addr: Option<u8>) -> ReaderProbe {
        ReaderProbe {
            reader_name: name.into(),
            is_molto2: keyroost_proto::is_molto2_reader(name),
            serial: None,
            openpgp_manufacturer: None,
            has_oath: true,
            has_openpgp: false,
            has_piv: false,
            has_fido: false,
            has_otp: false,
            is_prog: false,
            prog_serial: None,
            yubikey_serial: yk.map(str::to_owned),
            usb_bus: bus,
            usb_address: addr,
        }
    }
    #[test]
    fn token2_lax_select_only_on_token2_looking_readers() {
        let mut solo = reader(SOLO, None, None, None);
        solo.has_fido = true;
        assert!(!token2_lax_fido_select(&solo));
        let mut by_name = reader("TOKEN2 FIDO2 Security Key 00 00", None, None, None);
        by_name.has_fido = true;
        assert!(token2_lax_fido_select(&by_name));
        let mut by_otp = reader("Generic CCID Reader 00 00", None, None, None);
        by_otp.has_otp = true;
        assert!(token2_lax_fido_select(&by_otp));
    }

    const YK0: &str = "Yubico YubiKey OTP+FIDO+CCID 00 00";
    const YK1: &str = "Yubico YubiKey OTP+FIDO+CCID 01 00";
    const SOLO: &str = "SoloKeys Solo 2 [CCID/ICCD Interface] 02 00";

    #[test]
    fn linux_shape_plans_no_reads() {
        let hids = [
            hid(0x1050, 0x0407, "/dev/hidraw16", None, Some(9), Some(53)),
            hid(
                0x1209,
                0xBEEE,
                "/dev/hidraw14",
                Some("07A9568FBE31AD5DAD1F2298476CF0D4"),
                Some(9),
                Some(15),
            ),
        ];
        let probes = [
            reader(YK0, Some("11111111"), Some(9), Some(53)),
            reader(SOLO, None, Some(9), Some(15)),
            reader("TOKEN2 Molto2 00 00", None, None, None),
        ];
        assert_eq!(
            plan_identity_reads(&hids, &probes, IDENTITY_READERS),
            IdentityPlan::default()
        );
    }

    #[test]
    fn reported_topology_on_both_sides_is_never_planned() {
        // A FIDO-only YubiKey next to another key's reader: both report
        // bus/address and differ, which is already proof they are two keys.
        let hids = [hid(
            0x1050,
            0x0402,
            "/dev/hidraw20",
            None,
            Some(9),
            Some(60),
        )];
        let probes = [reader(YK0, Some("11111111"), Some(9), Some(53))];
        assert_eq!(
            plan_identity_reads(&hids, &probes, IDENTITY_READERS),
            IdentityPlan::default()
        );
    }

    #[test]
    fn topology_free_pair_plans_both_sides_for_its_vendor_only() {
        let hids = [
            hid(0x1050, 0x0407, "/dev/hidraw17", None, None, None),
            hid(0x1050, 0x0407, "/dev/hidraw18", None, None, None),
        ];
        let probes = [
            reader(YK0, Some("11111111"), None, None),
            reader(YK1, Some("22222222"), None, None),
            reader("TOKEN2 Molto2 00 00", None, None, None),
        ];
        let plan = plan_identity_reads(&hids, &probes, IDENTITY_READERS);
        assert_eq!(
            plan.hid,
            vec![(0, "/dev/hidraw17".into()), (0, "/dev/hidraw18".into())]
        );
        assert_eq!(plan.ccid, vec![(0, YK0.to_string()), (0, YK1.to_string())]);
    }

    #[test]
    fn hid_with_topology_and_reader_without_is_planned() {
        let hids = [hid(
            0x1050,
            0x0407,
            "/dev/hidraw16",
            None,
            Some(9),
            Some(53),
        )];
        let probes = [reader(YK0, Some("11111111"), None, None)];
        let plan = plan_identity_reads(&hids, &probes, IDENTITY_READERS);
        assert_eq!(plan.hid.len(), 1);
        assert_eq!(plan.ccid.len(), 1);
    }

    #[test]
    fn no_counterpart_no_read_and_molto_or_prog_never() {
        let hids = [hid(0x1050, 0x0407, "/dev/hidraw17", None, None, None)];
        let mut prog = reader("Generic NFC 00 00", None, None, None);
        prog.is_prog = true;
        prog.has_oath = false;
        let probes = [reader("TOKEN2 Molto2 00 00", None, None, None), prog];
        assert_eq!(
            plan_identity_reads(&hids, &probes, IDENTITY_READERS),
            IdentityPlan::default()
        );
    }

    #[test]
    fn a_readers_name_is_not_reserved_to_the_vendor_that_claims_it_first() {
        // One Solo 2 HID node, one Token2 HID node, and one topology-free
        // reader that answers both a FIDO and an OTP applet — so Solo 2
        // (broad: any applet) and Token2 (FIDO or OTP) both claim it.
        // Deduplicating the plan by reader name alone (not by vendor) would
        // let whichever vendor is iterated first claim the reader and starve
        // the other, even though each has its own unmatched HID node.
        let hids = [
            hid(SOLO2_VID, SOLO2_PID, "/dev/hidraw30", None, None, None),
            hid(
                keyroost_proto::USB_VID,
                0x0001,
                "/dev/hidraw31",
                None,
                None,
                None,
            ),
        ];
        let mut r = reader("Generic Reader 00 00", None, None, None);
        r.has_fido = true;
        r.has_otp = true;
        let probes = [r];
        let plan = plan_identity_reads(&hids, &probes, IDENTITY_READERS);
        let solo2_idx = IDENTITY_READERS
            .iter()
            .position(|r| r.vendor() == "Solo 2")
            .unwrap();
        let token2_idx = IDENTITY_READERS
            .iter()
            .position(|r| r.vendor() == "Token2")
            .unwrap();
        assert!(plan
            .ccid
            .contains(&(solo2_idx, "Generic Reader 00 00".to_string())));
        assert!(plan
            .ccid
            .contains(&(token2_idx, "Generic Reader 00 00".to_string())));
    }

    struct Fake(Mutex<Vec<String>>);
    impl IdentityReader for Fake {
        fn vendor(&self) -> &'static str {
            "Fake"
        }
        fn claims_hid(&self, _: &HidDevice) -> bool {
            true
        }
        fn claims_reader(&self, _: &ReaderProbe) -> bool {
            true
        }
        fn read_hid(&self, h: &HidDevice, _: bool) -> Option<CanonicalId> {
            self.0.lock().unwrap().push(h.path.display().to_string());
            yubico_from_serial_str("5")
        }
        fn read_ccid(&self, p: &ReaderProbe, _: bool) -> Option<CanonicalId> {
            self.0.lock().unwrap().push(p.reader_name.clone());
            None
        }
    }

    #[test]
    fn read_identities_touches_only_what_was_planned() {
        let fake = Fake(Mutex::new(Vec::new()));
        let registry: [&dyn IdentityReader; 1] = [&fake];
        let hids = [
            hid(1, 1, "/dev/a", None, None, None),
            hid(1, 1, "/dev/b", None, None, None),
        ];
        let probes = [reader("R", None, None, None)];
        let plan = IdentityPlan {
            hid: vec![(0, "/dev/b".into())],
            ccid: vec![(0, "R".into())],
        };
        let ids = read_identities(&plan, &hids, &probes, &registry, false);
        assert_eq!(
            *fake.0.lock().unwrap(),
            vec!["/dev/b".to_string(), "R".to_string()]
        );
        assert_eq!(ids.hid.len(), 1);
        assert!(ids.reader.is_empty());
    }
}
