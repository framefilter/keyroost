//! Pure-Rust protocol layer for the **Token2 2nd-generation single-profile
//! programmable TOTP token** (NFC Type-4 / ISO 7816).
//!
//! This crate builds the APDUs for the four operations the token supports —
//! read info, authenticate, program the seed, and program the configuration —
//! and parses the info response. It performs no I/O; the transport layer sends
//! the APDUs over PC/SC. Crypto (SM4, the SM4-CBC MAC, ISO 7816 padding) is
//! reused from [`keyroost_proto`].
//!
//! See `commands` for the per-command details and the wire format.

pub mod commands;

pub use commands::{
    answer_challenge, get_challenge, get_info, model_for_serial, pad_totp_seed, parse_info,
    set_config, set_seed, Command, Config, DisplayTimeout, HmacAlgo, Info, InfoError, SeedError,
    TimeStep, DEVICE_SM4_KEY,
};

#[cfg(test)]
mod tests {
    use super::commands::*;

    // All expected values below were produced by the vendor reference tool's
    // exact crypto path (the `sm4` Python package, validated against the GM/T
    // 0002 SM4 known-answer test) using this token family's device key.

    #[test]
    fn device_key_is_the_decrypted_constant() {
        assert_eq!(
            DEVICE_SM4_KEY,
            [
                0x8A, 0xD2, 0x06, 0x88, 0x3C, 0xA3, 0x69, 0x48, 0x2A, 0xB2, 0x71, 0x82, 0xB6, 0xE8,
                0x32, 0x24
            ]
        );
    }

    #[test]
    fn get_info_apdu_form() {
        // 80 41 00 00 02 02 11
        assert_eq!(
            get_info().apdu,
            vec![0x80, 0x41, 0x00, 0x00, 0x02, 0x02, 0x11]
        );
    }

    #[test]
    fn get_challenge_apdu_form() {
        // 80 4B 08 00 01 00
        assert_eq!(
            get_challenge().apdu,
            vec![0x80, 0x4B, 0x08, 0x00, 0x01, 0x00]
        );
    }

    #[test]
    fn answer_challenge_matches_reference() {
        // challenge 11 22 33 44 55 66 77 88, inflated to 16 bytes with eight
        // trailing zeros, SM4-encrypted under the device key. Reference value
        // from the vendor crypto path.
        let cmd = answer_challenge(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        // 80 CE 00 00 10 <16-byte response>
        assert_eq!(cmd.apdu[..5], [0x80, 0xCE, 0x00, 0x00, 0x10]);
        assert_eq!(
            &cmd.apdu[5..],
            &[
                0x8B, 0x74, 0x50, 0xF2, 0x27, 0x21, 0xBC, 0x29, 0x98, 0x5C, 0x2C, 0x46, 0x0B, 0x65,
                0x04, 0x5D
            ]
        );
    }

    #[test]
    fn set_seed_rejects_bad_length() {
        assert_eq!(set_seed(&[]).unwrap_err(), SeedError::Length(0));
        assert_eq!(set_seed(&[0u8; 64]).unwrap_err(), SeedError::Length(64));
    }

    #[test]
    fn set_seed_20_byte_form() {
        // A 20-byte seed pads to 32 bytes (two blocks) before ECB; the wire APDU
        // is secure-class 0x84, body = 32-byte ciphertext + 4-byte MAC = 36
        // bytes, so Lc = 0x24.
        let seed = [0xABu8; 20];
        let cmd = set_seed(&seed).unwrap();
        assert_eq!(cmd.apdu[..5], [0x84, 0xC5, 0x01, 0x00, 0x24]);
        assert_eq!(cmd.apdu.len(), 5 + 0x24);
    }

    #[test]
    fn set_seed_32_byte_form() {
        // A 32-byte seed gets an extra full pad block: 48-byte ciphertext + 4
        // MAC = 52 = 0x34.
        let seed = [0xCDu8; 32];
        let cmd = set_seed(&seed).unwrap();
        assert_eq!(cmd.apdu[..5], [0x84, 0xC5, 0x01, 0x00, 0x34]);
        assert_eq!(cmd.apdu.len(), 5 + 0x34);
    }

    #[test]
    fn set_config_tlv_layout() {
        let cmd = set_config(&Config {
            display_timeout: DisplayTimeout::Sec30,
            algorithm: HmacAlgo::Sha1,
            time_step: TimeStep::Seconds30,
            utc_time: 0,
        });
        // Secure class, 19-byte TLV + 4 MAC = 23 = 0x17.
        assert_eq!(cmd.apdu[..5], [0x84, 0xD4, 0x00, 0x00, 0x17]);
        // TLV prefix: 81 11 1F 01 01 (display_timeout = Sec30 = 1) 0F 04 <time>
        assert_eq!(
            cmd.apdu[5..15],
            [0x81, 0x11, 0x1F, 0x01, 0x01, 0x0F, 0x04, 0x00, 0x00, 0x00]
        );
        // TOTP param block: 86 06 0A 01 01 (SHA1) 0D 01 1E (30s)
        assert_eq!(
            cmd.apdu[15..24],
            [0x00, 0x86, 0x06, 0x0A, 0x01, 0x01, 0x0D, 0x01, 0x1E]
        );
    }

    // ---- Golden known-answer tests (full-APDU framing) -------------------
    //
    // The KATs below pin the EXACT bytes the current, hardware-verified
    // implementation emits for the secured commands: the secure-class header,
    // the SM4-ECB-encrypted body, and the 4-byte SM4-CBC MAC. These are golden
    // bytes captured from the current hw-verified output — they lock the
    // device-specific MAC framing (CLA 0x80 in the MAC AAD vs 0x84 on the wire,
    // and the encrypted-payload length used in the AAD) against silent
    // regression. Any change to command construction must reproduce these bytes
    // exactly or be paired with a written justification (see CLAUDE.md).

    #[test]
    fn set_seed_20_byte_golden() {
        // 20-byte seed 01..14: ISO 9797-1 padded to 32 bytes, SM4-ECB encrypted,
        // then 4 MAC bytes. Wire CLA 0x84, INS 0xC5, Lc 0x24 (36-byte body).
        let seed = [
            0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
        ];
        let cmd = set_seed(&seed).unwrap();
        assert_eq!(
            cmd.apdu,
            vec![
                0x84, 0xC5, 0x01, 0x00, 0x24, 0x6E, 0xEA, 0xD2, 0x14, 0x74, 0xBB, 0xF3, 0xA0, 0xA2,
                0xB4, 0xC1, 0x8F, 0x48, 0x9E, 0x54, 0x3C, 0xF4, 0x87, 0x25, 0xA7, 0x1E, 0xE9, 0xC3,
                0xA6, 0x59, 0x63, 0xE8, 0x8B, 0xE9, 0x40, 0x5E, 0x3D, 0x5F, 0x6E, 0xA0, 0xC1,
            ]
        );
    }

    #[test]
    fn set_seed_32_byte_golden() {
        // 32-byte seed 10..2F: longer-seed form (extra 0x80-pad block -> 48-byte
        // ciphertext) + 4 MAC bytes. Wire CLA 0x84, INS 0xC5, Lc 0x34.
        let seed = [
            0x10u8, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
            0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B,
            0x2C, 0x2D, 0x2E, 0x2F,
        ];
        let cmd = set_seed(&seed).unwrap();
        assert_eq!(
            cmd.apdu,
            vec![
                0x84, 0xC5, 0x01, 0x00, 0x34, 0xB8, 0x30, 0x89, 0x9C, 0xFE, 0x9D, 0xE2, 0x92, 0xCD,
                0x26, 0xD3, 0xC7, 0x43, 0x92, 0x15, 0xCE, 0x18, 0x50, 0x3D, 0x57, 0xAC, 0x31, 0x73,
                0x5A, 0xFA, 0x60, 0xEB, 0xA2, 0x0F, 0x64, 0xD6, 0xF7, 0xD2, 0x19, 0xEF, 0xC9, 0x97,
                0x2F, 0xED, 0x91, 0x91, 0xDF, 0x02, 0x7F, 0xD3, 0x6A, 0x80, 0xB0, 0x88, 0x0D, 0x59,
                0xFA,
            ]
        );
    }

    #[test]
    fn set_config_golden() {
        // Known Config: 60s display timeout, SHA-256, 60s step, time 0x65432100.
        // 19-byte TLV + 4 MAC. Wire CLA 0x84, INS 0xD4, Lc 0x17.
        let cmd = set_config(&Config {
            display_timeout: DisplayTimeout::Sec60,
            algorithm: HmacAlgo::Sha256,
            time_step: TimeStep::Seconds60,
            utc_time: 0x6543_2100,
        });
        assert_eq!(
            cmd.apdu,
            vec![
                0x84, 0xD4, 0x00, 0x00, 0x17, 0x81, 0x11, 0x1F, 0x01, 0x02, 0x0F, 0x04, 0x65, 0x43,
                0x21, 0x00, 0x86, 0x06, 0x0A, 0x01, 0x02, 0x0D, 0x01, 0x3C, 0x37, 0xA1, 0x8B, 0xF9,
            ]
        );
    }

    #[test]
    fn parse_info_roundtrip() {
        // serial_len at offset 3, serial "ABC123", two filler bytes, then a
        // 4-byte big-endian time (0x6543_2100).
        let mut body = vec![0x00, 0x00, 0x00, 0x06];
        body.extend_from_slice(b"ABC123");
        body.extend_from_slice(&[0x00, 0x00]);
        body.extend_from_slice(&[0x65, 0x43, 0x21, 0x00]);
        let info = parse_info(&body).unwrap();
        assert_eq!(info.serial, "ABC123");
        assert_eq!(info.utc_time, 0x6543_2100);
    }

    #[test]
    fn parse_info_truncated() {
        assert_eq!(parse_info(&[0x00, 0x00]).unwrap_err(), InfoError::Truncated);
    }

    #[test]
    fn model_resolution() {
        // Exact prefixes resolve.
        assert_eq!(model_for_serial("8659622"), Some("OTPC-P2-i"));
        assert_eq!(model_for_serial("8659621"), Some("OTPC-P2-i-NB"));
        assert_eq!(model_for_serial("8659610"), Some("C301-i"));
        // Non-programmable models are intentionally absent (e.g. C202/C203).
        assert_eq!(model_for_serial("8659623"), None);
        assert_eq!(model_for_serial("865971"), None);
        // A full serial that begins with a prefix resolves too.
        assert_eq!(model_for_serial("8659622000123"), Some("OTPC-P2-i"));
        assert_eq!(model_for_serial("8659600999"), Some("miniOTP-2-i"));
        // Surrounding whitespace is tolerated.
        assert_eq!(model_for_serial("  8659632  "), Some("C302-i"));
        // Unknown serial -> None (caller falls back to the raw serial).
        assert_eq!(model_for_serial("0000000"), None);
        assert_eq!(model_for_serial(""), None);
    }

    #[test]
    fn info_model_accessor() {
        let info = Info {
            serial: "8659622000001".to_string(),
            utc_time: 0,
        };
        assert_eq!(info.model(), Some("OTPC-P2-i"));
    }

    #[test]
    fn pad_totp_seed_matches_vendor() {
        // 10-byte secret (e.g. base32 "JBSWY3DPEHPK3PXP") pads to 20 with zeros.
        let ten = vec![0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0xde, 0xad, 0xbe, 0xef];
        let padded = pad_totp_seed(ten.clone());
        assert_eq!(padded.len(), 20);
        assert_eq!(&padded[..10], &ten[..]);
        assert_eq!(&padded[10..], &[0u8; 10]);
        // Already-20 and longer seeds are untouched.
        assert_eq!(pad_totp_seed(vec![1u8; 20]).len(), 20);
        assert_eq!(pad_totp_seed(vec![1u8; 32]).len(), 32);
    }
}
