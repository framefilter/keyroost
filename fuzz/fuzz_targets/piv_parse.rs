//! PIV response parsers — device-supplied BER.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = keyroost_piv::unwrap_data_object(data);
    let _ = keyroost_piv::format_version_bytes(data);
    let _ = keyroost_piv::parse_serial(data);
    // Write-path response parsers: GENERAL AUTHENTICATE templates, generated
    // public keys, and GET METADATA — all carry attacker-influenceable BER.
    let _ = keyroost_piv::parse_general_auth(data, 0x80);
    let _ = keyroost_piv::parse_general_auth(data, 0x82);
    let _ = keyroost_piv::parse_public_key(data);
    let _ = keyroost_piv::parse_metadata(data);
    // CHUID read-back (#102): the card hands back the object new-chuid wrote,
    // and `piv status` parses whatever any card serves under that tag.
    let _ = keyroost_piv::parse_chuid(data);
    // Applet fingerprinting (#128): every byte here comes from the card —
    // the ATR's historical bytes (COMPACT-TLV), the SELECT FCI (nested BER,
    // walked recursively — depth-capped, which this target guards), and the
    // Nitrokey admin application's status / version-string replies.
    let _ = keyroost_piv::find_tlv_recursive(data, 0x50);
    let _ = keyroost_piv::find_tlv(data, 0x50);
    let atr_id = keyroost_piv::fingerprint::atr_historical_bytes(data)
        .and_then(keyroost_piv::fingerprint::atr_identity);
    let sel_id = keyroost_piv::fingerprint::select_identity(data);
    let _ = keyroost_piv::fingerprint::wants_swissbit_probe(sel_id.as_deref());
    let _ = keyroost_piv::fingerprint::classify(
        atr_id.as_deref(),
        sel_id.as_deref(),
        data.first().is_some_and(|b| b & 1 != 0),
        data.first().is_some_and(|b| b & 2 != 0),
        data.first().is_some_and(|b| b & 4 != 0),
    );
    let _ = keyroost_piv::fingerprint::parse_nitrokey_variant(data);
    let _ = keyroost_piv::fingerprint::parse_ascii_text(data)
        .and_then(|s| keyroost_piv::fingerprint::parse_dotted_version(&s));
    let _ = keyroost_piv::fingerprint::format_yubikey_name(data);
});
