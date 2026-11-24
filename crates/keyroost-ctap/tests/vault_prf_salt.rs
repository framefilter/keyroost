//! `prf_salt` of the vault's own input, against FidoParole's `hmac_salt()`
//! captured independently. Lives here, not in the unit tests, because it
//! reads `PRF_INPUT` from the path-only `keyroost-vault` dev-dependency,
//! which the published package neither carries nor builds this file with.

use keyroost_ctap::hmac_secret::prf_salt;

#[test]
fn prf_salt_of_vault_input() {
    let hex: String = prf_salt(keyroost_vault::PRF_INPUT)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        hex,
        "2cb008f0aa5722f2396e4a7fb744ff15189d98a932e843cc9a6d65eaaf3726c8"
    );
}
