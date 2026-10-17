//! Hardware smoke test for `keyroost_pgpkey::card`: **factory-resets the
//! OpenPGP applet** of a disposable test card, then creates and imports a
//! NIST P-256, a Curve 25519 and an RSA-2048 key set in turn, checking the
//! three fingerprints the card reports against each set's.
//!
//! Ignored by default. Run it only against a test card:
//!
//! ```text
//! KEYROOST_TEST_READER='<PC/SC reader name>' KEYROOST_TEST_ADMIN_PIN=<pin> \
//!   cargo test -p keyroost-pgpkey --features card --test card_smoke -- --ignored --nocapture
//! ```
//!
//! The admin PIN is the factory default after the reset; set it in the
//! environment (from a script, not typed into the command line).
#![cfg(feature = "card")]

use keyroost_openpgp::PW3_ADMIN;
use keyroost_pgpkey::card::import_set;
use keyroost_pgpkey::cert::{create, Expiry, Identity};
use keyroost_pgpkey::keys::KeyType;
use keyroost_transport::OpenPgpSession;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

#[test]
#[ignore = "factory-resets the OpenPGP applet of a test card"]
fn import_sets_onto_a_test_card() {
    let reader = std::env::var("KEYROOST_TEST_READER").expect("KEYROOST_TEST_READER");
    let pin = std::env::var("KEYROOST_TEST_ADMIN_PIN").expect("KEYROOST_TEST_ADMIN_PIN");
    let id = Identity {
        name: "Card Smoke".into(),
        email: "smoke@example.org".into(),
    };
    let now = 1_760_000_000;
    let mut failures = Vec::new();
    for t in [KeyType::NistP256, KeyType::Cv25519, KeyType::Rsa2048] {
        let mut s = OpenPgpSession::open(&reader).expect("open");
        s.factory_reset().expect("factory reset");
        let mut s = OpenPgpSession::open(&reader).expect("reopen");
        s.verify_pin(PW3_ADMIN, pin.as_bytes()).expect("admin PIN");
        let set = create(t, &id, Expiry::Never, now).expect("create");
        let want: Vec<[u8; 20]> = set.parts.iter().map(|p| p.fingerprint()).collect();
        match import_set(&mut s, &set) {
            Ok(written) => {
                let st = s.status().expect("status");
                let card = [st.fingerprint_sig, st.fingerprint_dec, st.fingerprint_aut];
                for i in 0..3 {
                    println!(
                        "{}: slot {i}: card {} / set {}",
                        t.label(),
                        hex(&card[i]),
                        hex(&want[i])
                    );
                }
                println!(
                    "{}: card algorithms {} / {} / {}",
                    t.label(),
                    st.algorithm_label(keyroost_openpgp::KeyCrt::Sign),
                    st.algorithm_label(keyroost_openpgp::KeyCrt::Decrypt),
                    st.algorithm_label(keyroost_openpgp::KeyCrt::Auth)
                );
                if written != want || card.to_vec() != want {
                    failures.push(format!("{}: fingerprints differ", t.label()));
                }
            }
            Err(e) => {
                println!("{}: import failed: {e} ({e:?})", t.label());
                failures.push(format!("{}: {e}", t.label()));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:?}");
}
