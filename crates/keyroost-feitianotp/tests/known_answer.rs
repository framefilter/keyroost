//! Known-answer tests for the Feitian OTP byte layer.
//!
//! Every byte string here says where it comes from:
//!
//! - **captured**: bytes exchanged with a physical key, with the raw output
//!   kept. Key B is a Feitian ePass FIDO NFC Plus (USB `096E:0853`, OTP
//!   applet 1.0.2). Two keys of that model were read: one over direct CCID
//!   on 2026-11-18, the other over PC/SC on 2026-11-19.
//! - **recorded**: bytes noted from a physical key whose raw capture was not
//!   kept. Key A is a Feitian BioPass FIDO Pro (USB `096E:086A`, OTP applet
//!   1.0.1).
//! - **constructed**: bytes written out by hand from the wire format of
//!   Feitian's own client, which the Libre Key Companion Android client
//!   (an independent implementation) pins identically. Not captured.
//!
//! Two things from the keys are not reproduced. In captured and recorded
//! bytes each issuer and account is replaced by a made-up one of the same
//! length, and the eight bytes a key answered under tag 51 are replaced by
//! made-up ones. Every length byte, and everything outside those values, is
//! as the key sent it.
//!
//! None of the expected bytes were produced by this crate.

use keyroost_feitianotp::{
    calculate_hotp, calculate_totp, cos_version_text, delete, device_info, device_serial, list,
    list_legacy, parse_calculate, parse_device_cos, parse_device_serial, parse_list, parse_name,
    parse_select, put, reset, reset_legacy, select, stored_name, totp_challenge, Algorithm,
    OathType, PutParams, Slot,
};

fn hex(s: &str) -> Vec<u8> {
    let digits: Vec<u8> = s
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|b| match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => panic!("not a hex digit: {}", b as char),
        })
        .collect();
    assert!(digits.len().is_multiple_of(2), "odd number of hex digits");
    digits.chunks(2).map(|p| (p[0] << 4) | p[1]).collect()
}

// ---------------------------------------------------------------------------
// SELECT
// ---------------------------------------------------------------------------

#[test]
fn select_is_the_command_key_b_answered() {
    // Captured: sent to Key B over PC/SC, answered 9000 with the FCI below.
    assert_eq!(select(), hex("00 A4 04 00 09 D1 56 00 01 32 83 26 01 01"));
}

#[test]
fn select_answer_of_key_b_over_pcsc() {
    // Captured over PC/SC, 2026-11-19. The value under tag 51 is replaced
    // (see the top of this file).
    let info = parse_select(&hex(
        "59 03 01 00 02  51 08 B0 B1 B2 B3 B4 B5 B6 B7  7B 01 00",
    ))
    .unwrap();
    assert_eq!(info.version_triple(), Some((1, 0, 2)));
    assert_eq!(info.challenge, hex("B0 B1 B2 B3 B4 B5 B6 B7"));
    assert_eq!(info.access, Some(0x00));
    for slot in Slot::ALL {
        assert_eq!(info.access_code_set(slot), Some(false));
    }
}

#[test]
fn select_answer_of_key_b_over_direct_ccid() {
    // Captured over direct CCID, 2026-11-18, from the other key of the same
    // model and applet version, holding four accounts. The value under tag
    // 51 is replaced. Each of the two keys answers its own value there, and
    // each answered it again on 2026-11-22.
    let info = parse_select(&hex(
        "59 03 01 00 02  51 08 D0 D1 D2 D3 D4 D5 D6 D7  7B 01 00",
    ))
    .unwrap();
    assert_eq!(info.version_triple(), Some((1, 0, 2)));
    assert_eq!(info.challenge, hex("D0 D1 D2 D3 D4 D5 D6 D7"));
    assert_eq!(info.access, Some(0x00));
}

#[test]
fn select_answer_of_key_a() {
    // Recorded from Key A. The value under tag 51 is replaced. A key of this
    // model read over PC/SC on 2026-11-19 answered the same version and the
    // same value under tag 51 as the one recorded.
    let info = parse_select(&hex(
        "59 03 01 00 01  51 08 A0 A1 A2 A3 A4 A5 A6 A7  7B 01 00",
    ))
    .unwrap();
    assert_eq!(info.version_triple(), Some((1, 0, 1)));
    assert_eq!(info.challenge.len(), 8);
    assert_eq!(info.access_code_set(Slot::Default), Some(false));
}

// ---------------------------------------------------------------------------
// LIST
// ---------------------------------------------------------------------------

#[test]
fn serial_read_is_the_command_key_b_answered() {
    // Captured 2026-11-22: one Key B answered this `9000` with nothing
    // selected and with the OTP, PIV and OpenPGP applications selected.
    assert_eq!(device_serial(), hex("80 E3 03 00 00"));
}

#[test]
fn serial_answer_of_key_b() {
    // Captured the same day: twelve bytes, nine ASCII digits and three zero
    // bytes. The digits here are made up; the shape is the key's.
    assert_eq!(
        parse_device_serial(&hex("31 32 33 34 35 36 37 38 39 00 00 00")).as_deref(),
        Some("123456789")
    );
}

#[test]
fn device_information_of_key_a_and_key_b() {
    // Captured 2026-11-22 and 23, with made-up digits for the serial under
    // tag 82: Key B (ePass FIDO NFC Plus), whose second byte is the whole
    // answer's length, and Key A (BioPass FIDO Pro), whose second byte is
    // the TLVs' length.
    assert_eq!(device_info(), hex("80 E3 EE 80 00"));
    let key_b = parse_device_cos(&hex(
        "80 2C 81 02 02 02 82 09 31 32 33 34 35 36 37 38 39 83 02 00 00 \
         84 03 07 04 00 85 08 20 26 03 16 15 18 50 00 86 01 70 92 03 01 08 26",
    ));
    assert_eq!(key_b, Some([0x01, 0x08, 0x26]));
    let key_a = parse_device_cos(&hex(
        "80 3D 81 02 04 08 82 09 31 32 33 34 35 36 37 38 39 83 02 00 00 \
         84 03 47 17 00 85 08 20 25 03 05 11 16 53 00 86 01 60 \
         87 07 00 00 00 00 00 3F 04 88 01 00 89 02 00 00 90 01 00 92 03 47 17 00",
    ));
    assert_eq!(key_a, Some([0x47, 0x17, 0x00]));
    // Shown as read, two digits a byte. Feitian lists these two versions as
    // 1.826 and 4.7.17.
    assert_eq!(cos_version_text([0x01, 0x08, 0x26]), "01.08.26");
    assert_eq!(cos_version_text([0x47, 0x17, 0x00]), "47.17.00");
}

#[test]
fn a_device_information_answer_with_no_cos_version() {
    // Constructed: the tag missing, not three bytes under it, a TLV cut
    // short before it, no `80` in front, nothing at all.
    for answer in [
        "80 04 81 02 02 02",
        "80 04 92 02 01 08",
        "80 08 81 02 02 02 92 03 01 08",
        "81 02 02 02 92 03 01 08 26",
        "",
    ] {
        assert_eq!(parse_device_cos(&hex(answer)), None, "{answer}");
    }
}

#[test]
fn a_serial_answer_of_another_shape_is_not_guessed_at() {
    // Constructed. Too short, something after the padding starts, a byte
    // that is neither a letter nor a digit, nothing at all, and eight binary
    // bytes (which Feitian's client would read as a serial).
    for answer in [
        "31 32 33 34 35 00 00 00",
        "31 32 33 34 35 36 00 37",
        "31 32 33 34 35 36 20 37 00",
        "",
        "00 00 00 00 00 00 00 00 00 00 00 00",
        "A1 B2 C3 D4 E5 F6 07 18",
    ] {
        assert_eq!(parse_device_serial(&hex(answer)), None, "{answer}");
    }
    // Six characters are enough, and padding is not required.
    assert_eq!(
        parse_device_serial(&hex("41 42 43 31 32 33")).as_deref(),
        Some("ABC123")
    );
}

#[test]
fn list_commands_are_the_ones_key_b_answered() {
    // Captured: the three commands sent to Key B, each answered 9000.
    assert_eq!(list(Slot::Keyboard1), hex("00 17 00 00 00"));
    assert_eq!(list(Slot::Keyboard2), hex("00 17 00 01 00"));
    assert_eq!(list(Slot::Default), hex("00 17 00 F0 00"));
}

#[test]
fn legacy_list_is_the_four_byte_form() {
    // Constructed: Feitian's client sends this after a 6700. No key at hand
    // answered a LIST that way.
    assert_eq!(list_legacy(), hex("00 17 00 00"));
}

#[test]
fn empty_slot_answers_with_no_data() {
    // Captured: Key B's keyboard slots answered a bare 9000.
    for slot in [Slot::Keyboard1, Slot::Keyboard2] {
        let listing = parse_list(&[], slot).unwrap();
        assert!(listing.credentials.is_empty());
        assert_eq!(listing.skipped, 0);
    }
}

#[test]
fn list_answer_of_key_b_default_slot() {
    // Captured: Key B's default slot, four TOTP credentials. Names replaced
    // (see the top of this file).
    let answer = hex(concat!(
        "52 1D 21 33303A53616D706C654F6E655F235F46697273744163636F756E7431",
        "52 11 21 36303A49535352325F235F4143435432",
        "52 13 22 36303A6973737565725F235F686F6C646572",
        "52 18 21 33303A666F757274686F6E655F235F61636374666F7572",
    ));
    let listing = parse_list(&answer, Slot::Default).unwrap();
    assert_eq!(listing.skipped, 0);
    let got: Vec<_> = listing
        .credentials
        .iter()
        .map(|c| (c.name.as_str(), c.oath_type, c.algorithm, c.slot))
        .collect();
    assert_eq!(
        got,
        vec![
            (
                "30:SampleOne_#_FirstAccount1",
                OathType::Totp,
                Algorithm::Sha1,
                Slot::Default
            ),
            (
                "60:ISSR2_#_ACCT2",
                OathType::Totp,
                Algorithm::Sha1,
                Slot::Default
            ),
            (
                "60:issuer_#_holder",
                OathType::Totp,
                Algorithm::Sha256,
                Slot::Default
            ),
            (
                "30:fourthone_#_acctfour",
                OathType::Totp,
                Algorithm::Sha1,
                Slot::Default
            ),
        ]
    );

    // The names follow Feitian's on-card convention.
    let parts = parse_name(&listing.credentials[0].name, OathType::Totp);
    assert_eq!(
        (parts.period, parts.issuer, parts.account),
        (Some(30), Some("SampleOne"), "FirstAccount1")
    );
    let parts = parse_name(&listing.credentials[2].name, OathType::Totp);
    assert_eq!(
        (parts.period, parts.issuer, parts.account),
        (Some(60), Some("issuer"), "holder")
    );
}

#[test]
fn list_answer_of_key_a_default_slot() {
    // Recorded from Key A: one HOTP and one TOTP credential. Names replaced
    // (see the top of this file).
    let answer = hex(concat!(
        "52 0C 11 49535352415F235F414354",
        "52 16 21 33303A73616D706C655F235F6163636F756E746E6F",
    ));
    let listing = parse_list(&answer, Slot::Default).unwrap();
    assert_eq!(listing.skipped, 0);
    assert_eq!(listing.credentials.len(), 2);

    let hotp = &listing.credentials[0];
    assert_eq!(hotp.name, "ISSRA_#_ACT");
    assert_eq!(hotp.oath_type, OathType::Hotp);
    assert_eq!(hotp.algorithm, Algorithm::Sha1);
    let parts = parse_name(&hotp.name, hotp.oath_type);
    assert_eq!(
        (parts.period, parts.issuer, parts.account),
        (None, Some("ISSRA"), "ACT")
    );

    let totp = &listing.credentials[1];
    assert_eq!(totp.name, "30:sample_#_accountno");
    assert_eq!(totp.oath_type, OathType::Totp);
    let parts = parse_name(&totp.name, totp.oath_type);
    assert_eq!(
        (parts.period, parts.issuer, parts.account),
        (Some(30), Some("sample"), "accountno")
    );
}

// ---------------------------------------------------------------------------
// CALCULATE
// ---------------------------------------------------------------------------

#[test]
fn totp_calculate_is_the_command_key_b_answered() {
    // Captured, with the name replaced: Key B computed 048979 for this
    // command (time step 59831129, period 30) once touched.
    let name = "30:SampleOne_#_FirstAccount1";
    let challenge = totp_challenge(59_831_129 * 30, 30);
    assert_eq!(challenge, hex("00 00 00 00 03 90 F3 59")[..]);
    assert_eq!(
        calculate_totp(Slot::Default, name, &challenge).unwrap(),
        hex(concat!(
            "00 A2 01 F0 28",
            "54 08 00 00 00 00 03 90 F3 59",
            "51 1C 33303A53616D706C654F6E655F235F46697273744163636F756E7431",
        ))
    );
}

#[test]
fn calculate_answers_of_key_b() {
    // Captured: one answer per credential of the listing above, in order.
    // The codes are the ones the capturing script printed for these bytes;
    // they were not compared against a reference computed from the seeds.
    for (answer, code) in [
        ("76 05 06 0A F8 5D 53", "048979"),
        ("76 05 06 19 1A 01 21", "134625"),
        ("76 05 06 68 F1 64 17", "650263"),
        ("76 05 06 50 DC FA F9", "659449"),
    ] {
        let otp = parse_calculate(&hex(answer)).unwrap();
        assert_eq!(otp.digits, 6);
        assert_eq!(otp.code, code, "{answer}");
    }
}

#[test]
fn totp_calculate_for_a_keyboard_slot() {
    // Constructed.
    let challenge = totp_challenge(1_794_930_384, 30);
    assert_eq!(
        calculate_totp(Slot::Keyboard1, "30:a_#_b", &challenge).unwrap(),
        hex("00 A2 01 00 14  54 08 00 00 00 00 03 90 F2 E4  51 08 33 30 3A 61 5F 23 5F 62")
    );
}

#[test]
fn hotp_calculate_sends_an_empty_challenge() {
    // Constructed.
    assert_eq!(
        calculate_hotp(Slot::Default, "ISSRA_#_ACT").unwrap(),
        hex("00 A2 01 F0 0F  54 00  51 0B 49 53 53 52 41 5F 23 5F 41 43 54")
    );
}

// ---------------------------------------------------------------------------
// PUT / DELETE
// ---------------------------------------------------------------------------

#[test]
fn put_declares_the_key_one_byte_short() {
    // Constructed: 53 <len - 1> <algorithm> <type> <digits> <secret>, then
    // 51 <len> <name>. The key value is 8 bytes and is declared as 7.
    let name = stored_name(Some("iss"), "acct", OathType::Totp, 60).unwrap();
    assert_eq!(name, "60:iss_#_acct");
    let apdu = put(&PutParams {
        slot: Slot::Default,
        name: &name,
        secret: &hex("01 02 03 04 05"),
        oath_type: OathType::Totp,
        algorithm: Algorithm::Sha256,
        digits: 8,
    })
    .unwrap();
    assert_eq!(
        apdu,
        hex(concat!(
            "00 09 00 F0 19",
            "53 07 02 20 08 01 02 03 04 05",
            "51 0D 36 30 3A 69 73 73 5F 23 5F 61 63 63 74",
        ))
    );
}

#[test]
fn put_of_an_hotp_credential_has_no_counter_and_no_prefix() {
    // Constructed.
    let name = stored_name(Some("iss"), "acct", OathType::Hotp, 0).unwrap();
    let apdu = put(&PutParams {
        slot: Slot::Keyboard2,
        name: &name,
        secret: &hex("AA BB CC"),
        oath_type: OathType::Hotp,
        algorithm: Algorithm::Sha1,
        digits: 6,
    })
    .unwrap();
    assert_eq!(
        apdu,
        hex(concat!(
            "00 09 00 01 14",
            "53 05 01 10 06 AA BB CC",
            "51 0A 69 73 73 5F 23 5F 61 63 63 74",
        ))
    );
}

#[test]
fn reset_has_no_slot_and_no_data() {
    // Captured: Key B answered the five-byte form 9000 once touched, and its
    // accounts were gone. Constructed: the four-byte form Feitian's client
    // sends after a 6700, which Key B did not answer.
    assert_eq!(reset(), hex("00 07 00 00 00"));
    assert_eq!(reset_legacy(), hex("00 07 00 00"));
}

#[test]
fn delete_names_the_credential_as_stored() {
    // Constructed.
    assert_eq!(
        delete(Slot::Default, "60:iss_#_acct").unwrap(),
        hex("00 08 00 F0 0F  51 0D 36 30 3A 69 73 73 5F 23 5F 61 63 63 74")
    );
}
