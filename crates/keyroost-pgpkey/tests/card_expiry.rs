//! Hardware test for changing a key set's expiry through the card:
//! **factory-resets the OpenPGP applet** of a disposable test card, then for
//! a Curve 25519, a NIST P-256 and an RSA-2048 set in turn imports the set,
//! re-signs its public certificate with the card's signature key
//! ([`CardSigner`]) and checks in a throwaway GnuPG home that gpg shows the
//! new expiry on the primary key and both subkeys.
//!
//! Ignored by default. Run it only against a test card:
//!
//! ```text
//! KEYROOST_TEST_READER='<PC/SC reader name>' KEYROOST_TEST_ADMIN_PIN=<pin> \
//!   KEYROOST_TEST_USER_PIN=<pin> \
//!   cargo test -p keyroost-pgpkey --features card --test card_expiry -- --ignored --nocapture
//! ```
//!
//! Both PINs are the factory defaults after the reset; set them in the
//! environment (from a script, not typed into the command line).
#![cfg(all(feature = "card", unix))]

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use keyroost_openpgp::PW3_ADMIN;
use keyroost_pgpkey::card::{import_set, CardSigner};
use keyroost_pgpkey::cert::{change_expiry, create, export, Expiry, Identity};
use keyroost_pgpkey::keys::KeyType;
use keyroost_pgpkey::read;
use keyroost_transport::OpenPgpSession;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

/// Import `files` into a fresh GnuPG home and return (record, expiry
/// field) for the key set `fpr`. The home's agent is stopped and the home
/// removed afterwards.
fn gpg_expiries(tag: &str, fpr: &str, files: &[&str]) -> Vec<(String, String)> {
    use std::os::unix::fs::PermissionsExt as _;
    let home = PathBuf::from(format!("/tmp/krce-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir(&home).unwrap();
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
    let gpg = |args: &[&str]| {
        let o = Command::new("gpg")
            .arg("--homedir")
            .arg(&home)
            .env("GNUPGHOME", &home)
            .args(["--batch", "--no-tty", "--no-auto-check-trustdb"])
            .args(args)
            .stdin(Stdio::null())
            .output()
            .expect("gpg runs");
        assert!(
            o.status.success(),
            "gpg {args:?}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        String::from_utf8_lossy(&o.stdout).into_owned()
    };
    for (i, data) in files.iter().enumerate() {
        let f = home.join(format!("{i}.asc"));
        std::fs::write(&f, data).unwrap();
        gpg(&["--import", f.to_str().unwrap()]);
    }
    let out = gpg(&["--with-colons", "--list-keys", fpr]);
    let _ = Command::new("gpgconf")
        .arg("--homedir")
        .arg(&home)
        .args(["--kill", "gpg-agent"])
        .env("GNUPGHOME", &home)
        .output();
    let _ = std::fs::remove_dir_all(&home);
    out.lines()
        .map(|l| l.split(':').collect::<Vec<_>>())
        .filter(|f| matches!(f[0], "pub" | "sub"))
        .map(|f| (f[0].to_string(), f[6].to_string()))
        .collect()
}

#[test]
#[ignore = "factory-resets the OpenPGP applet of a test card"]
fn change_expiry_with_a_test_card() {
    let reader = std::env::var("KEYROOST_TEST_READER").expect("KEYROOST_TEST_READER");
    let admin = std::env::var("KEYROOST_TEST_ADMIN_PIN").expect("KEYROOST_TEST_ADMIN_PIN");
    let user = std::env::var("KEYROOST_TEST_USER_PIN").expect("KEYROOST_TEST_USER_PIN");
    let id = Identity {
        name: "Card Expiry".into(),
        email: "expiry@example.org".into(),
    };
    let now = u32::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
        - 120;
    let date = Expiry::Date {
        y: 2031,
        m: 6,
        d: 30,
    };
    let mut failures = Vec::new();
    for (t, new) in [
        (KeyType::Cv25519, date),
        (KeyType::NistP256, Expiry::Years(5)),
        (KeyType::Rsa2048, Expiry::Never),
    ] {
        let mut s = OpenPgpSession::open(&reader).expect("open");
        s.factory_reset().expect("factory reset");
        let mut s = OpenPgpSession::open(&reader).expect("reopen");
        s.verify_pin(PW3_ADMIN, admin.as_bytes())
            .expect("admin PIN");
        let set = create(t, &id, Expiry::Years(1), now).expect("create");
        let out = export(&set, b"card expiry test", now).expect("export");
        import_set(&mut s, &set).expect("import");
        let public = read::open_public(out.public.as_bytes()).expect("public");
        let pfpr = set.parts[0].fingerprint();

        // A different certificate is refused before anything is signed.
        let other = create(t, &id, Expiry::Years(1), now).expect("create other");
        let other_pub = export(&other, b"x", now).expect("export other").public;
        let other_pub = read::open_public(other_pub.as_bytes()).unwrap();
        let refused = CardSigner::new(&mut s, &other_pub, user.as_bytes()).err();
        println!("{}: foreign certificate: {refused:?}", t.label());
        if refused.is_none() {
            failures.push(format!("{}: foreign certificate accepted", t.label()));
        }

        let mut signer = CardSigner::new(&mut s, &public, user.as_bytes()).expect("signer");
        let changed = match change_expiry(&public, &mut signer, pfpr, new, now + 60) {
            Ok(c) => c,
            Err(e) => {
                println!("{}: change failed: {e} ({e:?})", t.label());
                failures.push(format!("{}: {e}", t.label()));
                continue;
            }
        };
        let want = new
            .end_time(now + 60)
            .unwrap()
            .map_or(String::new(), |e| e.to_string());
        let got = gpg_expiries(&format!("{t:?}"), &hex(&pfpr), &[&out.public, &changed]);
        println!("{}: gpg sees {got:?}, want {want:?}", t.label());
        let recs: Vec<&str> = got.iter().map(|(r, _)| r.as_str()).collect();
        if recs != ["pub", "sub", "sub"] || got.iter().any(|(_, e)| *e != want) {
            failures.push(format!("{}: gpg shows {got:?}, want {want}", t.label()));
        }
    }
    assert!(failures.is_empty(), "{failures:?}");
}
