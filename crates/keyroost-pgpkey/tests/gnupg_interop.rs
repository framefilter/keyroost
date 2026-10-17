//! GnuPG interoperability: keyroost's exports must import, verify, sign and
//! decrypt in `gpg`, and keys `gpg` makes must load back here.
//!
//! Every test runs in its own short-lived GNUPGHOME under /tmp (short, for
//! the agent's socket path) and stops its gpg-agent afterwards. Tests skip
//! when `gpg` is not installed.

#![cfg(unix)]

use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use keyroost_pgpkey::cert::{create, export, Expiry, Identity, Outputs};
use keyroost_pgpkey::keys::KeyType;
use keyroost_pgpkey::read::{self, Slot};
use keyroost_pgpkey::Error;

const PASS: &[u8] = b"test pass";

fn have_gpg() -> bool {
    let ok = Command::new("gpg")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !ok {
        eprintln!("gpg not found; skipping");
    }
    ok
}

/// A throwaway GNUPGHOME, removed (agent stopped first) on drop.
struct Home(PathBuf);

impl Home {
    fn new(tag: &str) -> Home {
        let p = PathBuf::from(format!("/tmp/krpg-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        Home(p)
    }

    fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn write(&self, name: &str, data: &[u8]) -> String {
        let p = self.file(name);
        std::fs::write(&p, data).unwrap();
        p.to_str().unwrap().to_string()
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = Command::new("gpgconf")
            .arg("--homedir")
            .arg(&self.0)
            .args(["--kill", "gpg-agent"])
            .env("GNUPGHOME", &self.0)
            .output();
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Run gpg in `home`. With `stdin`, the passphrase is read from it
/// (loopback pinentry, fd 0).
fn gpg(home: &Path, args: &[&str], stdin: Option<&[u8]>) -> Output {
    let mut c = Command::new("gpg");
    c.arg("--homedir").arg(home).env("GNUPGHOME", home).args([
        "--batch",
        "--no-tty",
        "--no-auto-check-trustdb",
    ]);
    if stdin.is_some() {
        c.args(["--pinentry-mode", "loopback", "--passphrase-fd", "0"]);
    }
    c.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = c.spawn().expect("gpg runs");
    {
        let mut si = child.stdin.take().unwrap();
        if let Some(s) = stdin {
            si.write_all(s).unwrap();
            si.write_all(b"\n").unwrap();
        }
    }
    child.wait_with_output().unwrap()
}

fn ok(o: &Output, what: &str) -> String {
    assert!(
        o.status.success(),
        "{what} failed:\n{}\n{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

fn unix_now() -> u32 {
    let s = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    u32::try_from(s).unwrap()
}

/// One key from `--with-colons` output: record type, fingerprint, its own
/// usage letters (sorted), expiry field.
#[derive(Debug)]
struct ColonKey {
    rec: String,
    fpr: String,
    usage: String,
    expires: String,
    validity: String,
}

fn colon_keys(out: &str) -> Vec<ColonKey> {
    let mut keys: Vec<ColonKey> = Vec::new();
    let mut pending = false;
    for line in out.lines() {
        let f: Vec<&str> = line.split(':').collect();
        match f[0] {
            "pub" | "sub" | "sec" | "ssb" => {
                let mut usage: Vec<char> = f[11].chars().filter(char::is_ascii_lowercase).collect();
                usage.sort_unstable();
                keys.push(ColonKey {
                    rec: f[0].into(),
                    fpr: String::new(),
                    usage: usage.into_iter().collect(),
                    expires: f[6].into(),
                    validity: f[1].into(),
                });
                pending = true;
            }
            "fpr" if pending => {
                keys.last_mut().unwrap().fpr = f[9].into();
                pending = false;
            }
            _ => {}
        }
    }
    keys
}

fn make(t: KeyType, e: Expiry) -> (keyroost_pgpkey::cert::KeySet, Outputs, u32) {
    // A minute back so gpg never sees a key from the future.
    let now = unix_now() - 60;
    let id = Identity {
        name: "Test".into(),
        email: "test@example.org".into(),
    };
    let set = create(t, &id, e, now).unwrap();
    let out = export(&set, PASS, now).unwrap();
    (set, out, now)
}

fn our_export_works_in_gpg(t: KeyType) {
    if !have_gpg() {
        return;
    }
    let (set, out, now) = make(t, Expiry::Years(3));
    let home = Home::new(t.cli_name());
    let h = &home.0;
    let sec = home.write("sec.asc", out.secret.as_bytes());
    ok(&gpg(h, &["--import", &sec], Some(PASS)), "import");
    let fprs: Vec<String> = set.parts.iter().map(|p| hex(&p.fingerprint())).collect();

    // Every self-signature and binding verifies in gpg.
    let o = ok(
        &gpg(h, &["--with-colons", "--check-sigs", &fprs[0]], None),
        "check-sigs",
    );
    let sigs: Vec<&str> = o.lines().filter(|l| l.starts_with("sig:")).collect();
    assert_eq!(sigs.len(), 3, "{t:?}: {o}");
    for s in &sigs {
        assert!(s.starts_with("sig:!:"), "{t:?}: bad signature: {s}");
    }

    // Usages and expiry as written.
    let o = ok(
        &gpg(h, &["--with-colons", "--list-secret-keys", &fprs[0]], None),
        "list-secret-keys",
    );
    let keys = colon_keys(&o);
    let want_exp = (u64::from(now) + u64::from(set.expiry.unwrap())).to_string();
    let want = [("sec", "cs"), ("ssb", "e"), ("ssb", "a")];
    assert_eq!(keys.len(), 3, "{t:?}: {o}");
    for (i, k) in keys.iter().enumerate() {
        assert_eq!(
            (k.rec.as_str(), k.fpr.as_str(), k.usage.as_str()),
            (want[i].0, fprs[i].as_str(), want[i].1),
            "{t:?}: {o}"
        );
        assert_eq!(k.expires, want_exp, "{t:?} key {i} expiry");
    }

    // Sign and verify.
    let data = home.write("data.txt", b"keyroost interop\n");
    let sig = home.file("data.sig");
    let sig = sig.to_str().unwrap();
    let signer = format!("{}!", fprs[0]);
    ok(
        &gpg(
            h,
            &["--local-user", &signer, "-o", sig, "--detach-sign", &data],
            Some(PASS),
        ),
        "detach-sign",
    );
    let o = ok(
        &gpg(h, &["--status-fd", "1", "--verify", sig, &data], None),
        "verify",
    );
    assert!(o.contains(&format!("VALIDSIG {}", fprs[0])), "{t:?}: {o}");

    // Encrypt to the decryption subkey and decrypt.
    let msg = home.file("data.gpg");
    let msg = msg.to_str().unwrap();
    let o = ok(
        &gpg(
            h,
            &[
                "--trust-model",
                "always",
                "--yes",
                "--status-fd",
                "1",
                "-r",
                &fprs[0],
                "-o",
                msg,
                "--encrypt",
                &data,
            ],
            None,
        ),
        "encrypt",
    );
    assert!(o.contains("END_ENCRYPTION"), "{t:?}: {o}");
    let plain = home.file("plain.txt");
    let plain_s = plain.to_str().unwrap();
    let o = ok(
        &gpg(
            h,
            &["--yes", "--status-fd", "1", "-o", plain_s, "--decrypt", msg],
            Some(PASS),
        ),
        "decrypt",
    );
    assert!(o.contains("DECRYPTION_OKAY"), "{t:?}: {o}");
    assert!(
        o.contains(&format!("ENC_TO {}", &fprs[1][24..])),
        "{t:?}: {o}"
    );
    assert_eq!(std::fs::read(&plain).unwrap(), b"keyroost interop\n");
}

#[test]
fn rsa2048_export_works_in_gpg() {
    our_export_works_in_gpg(KeyType::Rsa2048);
}

#[test]
#[ignore = "RSA-3072 keygen is slow"]
fn rsa3072_export_works_in_gpg() {
    our_export_works_in_gpg(KeyType::Rsa3072);
}

#[test]
#[ignore = "RSA-4096 keygen is slow"]
fn rsa4096_export_works_in_gpg() {
    our_export_works_in_gpg(KeyType::Rsa4096);
}

#[test]
fn nistp256_export_works_in_gpg() {
    our_export_works_in_gpg(KeyType::NistP256);
}

#[test]
fn nistp384_export_works_in_gpg() {
    our_export_works_in_gpg(KeyType::NistP384);
}

#[test]
fn nistp521_export_works_in_gpg() {
    our_export_works_in_gpg(KeyType::NistP521);
}

#[test]
fn secp256k1_export_works_in_gpg() {
    our_export_works_in_gpg(KeyType::Secp256k1);
}

#[test]
fn cv25519_export_works_in_gpg() {
    our_export_works_in_gpg(KeyType::Cv25519);
}

#[test]
fn revocation_certificate_revokes_in_gpg() {
    if !have_gpg() {
        return;
    }
    let (set, out, _) = make(KeyType::Cv25519, Expiry::Years(3));
    let fpr = hex(&set.parts[0].fingerprint());
    let home = Home::new("rev");
    let h = &home.0;
    let public = home.write("pub.asc", out.public.as_bytes());
    ok(&gpg(h, &["--import", &public], None), "import public");
    let list = || {
        let o = ok(
            &gpg(h, &["--with-colons", "--list-keys", &fpr], None),
            "list-keys",
        );
        colon_keys(&o).remove(0)
    };
    assert_ne!(list().validity, "r");
    let rev = home.write("rev.asc", out.revocation.as_bytes());
    ok(&gpg(h, &["--import", &rev], None), "import revocation");
    let k = list();
    assert_eq!((k.rec.as_str(), k.validity.as_str()), ("pub", "r"));
}

#[test]
fn exported_subpackets_as_gpg_lists_them() {
    if !have_gpg() {
        return;
    }
    let home = Home::new("pkts");
    let h = &home.0;
    for (e, expiring) in [(Expiry::Never, false), (Expiry::Years(3), true)] {
        let (set, out, _) = make(KeyType::Cv25519, e);
        let f = home.write("pub.asc", out.public.as_bytes());
        let o = ok(&gpg(h, &["--list-packets", &f], None), "list-packets");
        let exp_lines = o.matches("hashed subpkt 9 len 4").count();
        assert_eq!(exp_lines, if expiring { 3 } else { 0 }, "{e:?}: {o}");
        if expiring {
            let secs = set.expiry.unwrap();
            assert!(o.contains("(key expires after "), "{o}");
            assert!(secs > 3 * 365 * 86_400 - 86_400 * 2, "{secs}");
        }
        for flags in ["(key flags: 03)", "(key flags: 0C)", "(key flags: 20)"] {
            assert_eq!(o.matches(flags).count(), 1, "{flags}: {o}");
        }
        assert!(!o.contains("subpkt 9 len 4 (key expires after 0"), "{o}");
    }
}

/// Make a key set in gpg (`primary` sign+certify, `enc` encryption and
/// `auth` authentication subkeys), export it and load it here. A bare
/// NIST/secp256k1 curve name makes an ECDH subkey, so `auth` names
/// `<curve>/ecdsa`.
fn gpg_made_key_loads(tag: &str, primary: &str, enc: &str, auth: &str, t: KeyType) {
    if !have_gpg() {
        return;
    }
    let home = Home::new(tag);
    let h = &home.0;
    let uid = "T <t@example.org>";
    ok(
        &gpg(
            h,
            &["--quick-gen-key", uid, primary, "default", "never"],
            Some(PASS),
        ),
        "quick-gen-key",
    );
    let o = ok(
        &gpg(h, &["--with-colons", "--list-secret-keys", uid], None),
        "list",
    );
    let fpr = colon_keys(&o).remove(0).fpr;
    for (algo, usage) in [(enc, "encr"), (auth, "auth")] {
        ok(
            &gpg(
                h,
                &["--quick-add-key", &fpr, algo, usage, "never"],
                Some(PASS),
            ),
            "quick-add-key",
        );
    }
    let o = ok(
        &gpg(h, &["--with-colons", "--list-secret-keys", &fpr], None),
        "list",
    );
    let gkeys = colon_keys(&o);
    assert_eq!(gkeys.len(), 3, "{o}");
    let armored = ok(
        &gpg(h, &["--armor", "--export-secret-keys", &fpr], Some(PASS)),
        "export-secret-keys",
    );

    let loaded = read::open(armored.as_bytes(), Some(PASS)).unwrap();
    assert_eq!(hex(&loaded.primary_fpr), fpr);
    assert_eq!(loaded.user_ids, [uid]);
    assert_eq!(loaded.expiry, None);
    assert!(loaded.notes.is_empty(), "{:?}", loaded.notes);
    assert_eq!(loaded.keys.len(), 3);
    for (g, k) in gkeys.iter().zip(&loaded.keys) {
        assert_eq!(hex(&k.fpr), g.fpr);
        let want = if g.usage.contains('s') {
            Slot::Sign
        } else if g.usage.contains('e') {
            Slot::Decrypt
        } else {
            Slot::Auth
        };
        assert_eq!(k.slot, Some(want), "{tag}: gpg usage {}", g.usage);
        assert_eq!(k.key_type, Some(t), "{tag}");
    }
    if t == KeyType::NistP384 {
        let body = loaded.keys[1].part.public_body();
        assert_eq!(body[body.len() - 4..], [0x03, 0x01, 0x09, 0x09]);
    }
    // Wrong passphrase and no passphrase.
    assert!(matches!(
        read::open(armored.as_bytes(), Some(b"wrong")),
        Err(Error::WrongPassphrase)
    ));
    assert!(matches!(
        read::open(armored.as_bytes(), None),
        Err(Error::NeedsPassphrase)
    ));
    // Subkeys only: the primary's secret was left out.
    let subs = ok(
        &gpg(h, &["--armor", "--export-secret-subkeys", &fpr], Some(PASS)),
        "export-secret-subkeys",
    );
    assert!(matches!(
        read::open(subs.as_bytes(), Some(PASS)),
        Err(Error::NoSecretPart)
    ));
}

#[test]
fn gpg_rsa3072_loads() {
    gpg_made_key_loads("rsa", "rsa3072", "rsa3072", "rsa3072", KeyType::Rsa3072);
}

#[test]
fn gpg_nistp256_loads() {
    gpg_made_key_loads(
        "p256",
        "nistp256",
        "nistp256",
        "nistp256/ecdsa",
        KeyType::NistP256,
    );
}

#[test]
fn gpg_nistp384_loads() {
    gpg_made_key_loads(
        "p384",
        "nistp384",
        "nistp384",
        "nistp384/ecdsa",
        KeyType::NistP384,
    );
}

#[test]
fn gpg_secp256k1_loads() {
    gpg_made_key_loads(
        "k1",
        "secp256k1",
        "secp256k1",
        "secp256k1/ecdsa",
        KeyType::Secp256k1,
    );
}

#[test]
fn gpg_ed25519_loads() {
    gpg_made_key_loads("ed", "ed25519", "cv25519", "ed25519", KeyType::Cv25519);
}
