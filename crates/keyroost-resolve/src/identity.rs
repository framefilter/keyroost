//! Device-reported identity, used to match a key's FIDO-HID node to its
//! smart-card reader where USB topology is unavailable (Windows, macOS —
//! #51). Each vendor's two channels report the same identity in their own
//! encoding; the canonicalisers below map both to one comparable value.
//! Identities are compared only within the same [`IdScheme`]: two
//! encodings whose relation no real key has confirmed are never equated.
//! They are used for matching only; persisted only when the user names a
//! key (the keyring's existing behaviour).

use std::fmt;

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
}
