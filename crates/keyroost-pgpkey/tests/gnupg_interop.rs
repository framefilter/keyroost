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
        // The agent's own log, printed if a step fails (see `Home::ok`).
        std::fs::write(
            p.join("gpg-agent.conf"),
            format!(
                "log-file {}\ndebug-level basic\n",
                p.join("agent.log").display()
            ),
        )
        .unwrap();
        Home(p)
    }

    /// gpg's stdout when the step `what` succeeded; on a failure, panics with
    /// its output plus what's needed to understand a failure that doesn't
    /// reproduce: the gpg version, the agent's log, and the exported key set
    /// when this home has one (`sec.asc`; a throwaway key under the test's
    /// own passphrase), so the failing key can be replayed. Every gpg step in
    /// these tests goes through it.
    fn ok(&self, o: &Output, what: &str) -> String {
        if !o.status.success() {
            let version = Command::new("gpg")
                .arg("--version")
                .output()
                .map(|v| {
                    String::from_utf8_lossy(&v.stdout)
                        .lines()
                        .take(2)
                        .collect::<Vec<_>>()
                        .join("; ")
                })
                .unwrap_or_default();
            let log = std::fs::read_to_string(self.file("agent.log")).unwrap_or_default();
            let tail: Vec<&str> = log
                .lines()
                .rev()
                .take(80)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            let key = std::fs::read_to_string(self.file("sec.asc")).unwrap_or_default();
            panic!(
                "{what} failed:\n{}\n{}\n--- {version}\n--- agent log (tail):\n{}\n--- key set:\n{key}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr),
                tail.join("\n"),
            );
        }
        String::from_utf8_lossy(&o.stdout).into_owned()
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

/// Run `gpg --edit-key fpr` with `commands`. Both arrive on stdin: gpg
/// reads the passphrase line first (`--passphrase-fd 0`), then the
/// commands (`--command-fd 0`).
fn gpg_edit(home: &Path, fpr: &str, commands: &str) -> Output {
    let mut input = PASS.to_vec();
    input.push(b'\n');
    input.extend_from_slice(commands.as_bytes());
    gpg(
        home,
        &["--command-fd", "0", "--edit-key", fpr],
        Some(&input),
    )
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
    created: String,
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
                    created: f[5].into(),
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
    home.ok(&gpg(h, &["--import", &sec], Some(PASS)), "import");
    let fprs: Vec<String> = set.parts.iter().map(|p| hex(&p.fingerprint())).collect();

    // Every self-signature and binding verifies in gpg.
    let o = home.ok(
        &gpg(h, &["--with-colons", "--check-sigs", &fprs[0]], None),
        "check-sigs",
    );
    let sigs: Vec<&str> = o.lines().filter(|l| l.starts_with("sig:")).collect();
    assert_eq!(sigs.len(), 3, "{t:?}: {o}");
    for s in &sigs {
        assert!(s.starts_with("sig:!:"), "{t:?}: bad signature: {s}");
    }

    // Usages and expiry as written.
    let o = home.ok(
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
    home.ok(
        &gpg(
            h,
            &["--local-user", &signer, "-o", sig, "--detach-sign", &data],
            Some(PASS),
        ),
        "detach-sign",
    );
    let o = home.ok(
        &gpg(h, &["--status-fd", "1", "--verify", sig, &data], None),
        "verify",
    );
    assert!(o.contains(&format!("VALIDSIG {}", fprs[0])), "{t:?}: {o}");

    // Encrypt to the decryption subkey and decrypt.
    let msg = home.file("data.gpg");
    let msg = msg.to_str().unwrap();
    let enc = gpg(
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
    );
    // Some GnuPG builds sign with secp256k1 but can't encrypt to it.
    if t == KeyType::Secp256k1
        && !enc.status.success()
        && String::from_utf8_lossy(&enc.stderr).contains("Unknown algorithm")
    {
        eprintln!("this gpg can't encrypt to secp256k1; skipping encrypt/decrypt");
        return;
    }
    let o = home.ok(&enc, "encrypt");
    assert!(o.contains("END_ENCRYPTION"), "{t:?}: {o}");
    let plain = home.file("plain.txt");
    let plain_s = plain.to_str().unwrap();
    let o = home.ok(
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
    home.ok(&gpg(h, &["--import", &public], None), "import public");
    let list = || {
        let o = home.ok(
            &gpg(h, &["--with-colons", "--list-keys", &fpr], None),
            "list-keys",
        );
        colon_keys(&o).remove(0)
    };
    assert_ne!(list().validity, "r");
    let rev = home.write("rev.asc", out.revocation.as_bytes());
    home.ok(&gpg(h, &["--import", &rev], None), "import revocation");
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
        let o = home.ok(&gpg(h, &["--list-packets", &f], None), "list-packets");
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
    home.ok(
        &gpg(
            h,
            &["--quick-gen-key", uid, primary, "default", "never"],
            Some(PASS),
        ),
        "quick-gen-key",
    );
    let o = home.ok(
        &gpg(h, &["--with-colons", "--list-secret-keys", uid], None),
        "list",
    );
    let fpr = colon_keys(&o).remove(0).fpr;
    for (algo, usage) in [(enc, "encr"), (auth, "auth")] {
        home.ok(
            &gpg(
                h,
                &["--quick-add-key", &fpr, algo, usage, "never"],
                Some(PASS),
            ),
            "quick-add-key",
        );
    }
    // An expiry set and then cleared: the newest self-signature has no
    // expiry subpacket, which means never.
    for when in ["1y", "never"] {
        home.ok(
            &gpg(h, &["--quick-set-expire", &fpr, when], Some(PASS)),
            "quick-set-expire",
        );
    }
    let o = home.ok(
        &gpg(h, &["--with-colons", "--list-secret-keys", &fpr], None),
        "list",
    );
    let gkeys = colon_keys(&o);
    assert_eq!(gkeys[0].expires, "", "{o}");
    assert_eq!(gkeys.len(), 3, "{o}");
    let armored = home.ok(
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
    let subs = home.ok(
        &gpg(h, &["--armor", "--export-secret-subkeys", &fpr], Some(PASS)),
        "export-secret-subkeys",
    );
    let subs = read::open(subs.as_bytes(), Some(PASS)).unwrap();
    assert!(!subs.primary_secret);
    assert_eq!(hex(&subs.primary_fpr), fpr);
    let slots: Vec<_> = subs.keys.iter().map(|k| k.slot).collect();
    // gpg's primary here signs; without its secret the Sign slot stays
    // empty rather than falling to a subkey that cannot sign.
    assert_eq!(slots, [Some(Slot::Decrypt), Some(Slot::Auth)], "{tag}");
    assert!(
        subs.notes[0].contains("has no secret part"),
        "{:?}",
        subs.notes
    );
}

/// A key set shaped the way careful gpg users keep theirs: certify-only
/// primary; separate sign, encrypt and auth subkeys; a second user ID;
/// expiry changed on the primary and then on every subkey; three
/// encryption subkeys of which the newest is revoked; and a designated
/// revoker (a newer 0x1F signature with neither flags nor expiry).
#[test]
fn gpg_certify_only_key_with_history_loads() {
    if !have_gpg() {
        return;
    }
    let home = Home::new("hist");
    let h = &home.0;
    let uid = "T <t@example.org>";
    let pass = Some(PASS);
    home.ok(
        &gpg(
            h,
            &["--quick-gen-key", uid, "ed25519", "cert", "never"],
            pass,
        ),
        "quick-gen-key",
    );
    let fpr = colon_keys(&home.ok(
        &gpg(h, &["--with-colons", "--list-secret-keys", uid], None),
        "list",
    ))
    .remove(0)
    .fpr;
    let add = |algo: &str, usage: &str| {
        home.ok(
            &gpg(h, &["--quick-add-key", &fpr, algo, usage, "never"], pass),
            "quick-add-key",
        );
    };
    let pause = || std::thread::sleep(std::time::Duration::from_millis(1100));
    add("ed25519", "sign");
    add("cv25519", "encr");
    add("ed25519", "auth");
    pause();
    add("cv25519", "encr");
    pause();
    add("cv25519", "encr");
    home.ok(
        &gpg(h, &["--quick-add-uid", &fpr, "T2 <t2@example.org>"], pass),
        "quick-add-uid",
    );
    home.ok(
        &gpg(h, &["--quick-set-expire", &fpr, "1y"], pass),
        "set-expire",
    );
    home.ok(
        &gpg(h, &["--quick-set-expire", &fpr, "2y", "*"], pass),
        "set-expire subkeys",
    );
    let gkeys = colon_keys(&home.ok(
        &gpg(h, &["--with-colons", "--list-secret-keys", &fpr], None),
        "list",
    ));
    assert_eq!(gkeys.len(), 6);
    let newest_enc = gkeys[5].fpr.clone();
    home.ok(
        &gpg_edit(
            h,
            &fpr,
            &format!("key {newest_enc}\nrevkey\ny\n0\n\ny\nsave\n"),
        ),
        "revkey",
    );
    pause();
    home.ok(
        &gpg(
            h,
            &[
                "--quick-gen-key",
                "R <r@example.org>",
                "ed25519",
                "cert",
                "never",
            ],
            pass,
        ),
        "revoker key",
    );
    let revoker = colon_keys(&home.ok(
        &gpg(h, &["--with-colons", "--list-keys", "r@example.org"], None),
        "list revoker",
    ))
    .remove(0)
    .fpr;
    home.ok(
        &gpg_edit(h, &fpr, &format!("addrevoker\n{revoker}\ny\nsave\n")),
        "addrevoker",
    );

    let o = home.ok(
        &gpg(h, &["--with-colons", "--list-secret-keys", &fpr], None),
        "list",
    );
    assert!(o.lines().any(|l| l.starts_with("rvk:")), "{o}");
    let gkeys = colon_keys(&o);
    let usage: Vec<&str> = gkeys.iter().map(|k| k.usage.as_str()).collect();
    assert_eq!(usage, ["c", "s", "e", "a", "e", "e"], "{o}");
    assert_eq!(gkeys[5].validity, "r", "{o}");
    // What gpg itself encrypts to.
    let data = home.write("m.txt", b"x\n");
    let msg = home.file("m.gpg");
    let msg = msg.to_str().unwrap();
    home.ok(
        &gpg(
            h,
            &[
                "--trust-model",
                "always",
                "-r",
                &fpr,
                "-o",
                msg,
                "--encrypt",
                &data,
            ],
            None,
        ),
        "encrypt",
    );
    // Lists the recipient key ids without decrypting.
    let listed = gpg(
        h,
        &["--list-only", "--status-fd", "1", "--decrypt", msg],
        None,
    );
    let st = String::from_utf8_lossy(&listed.stdout);
    let enc_to = st
        .lines()
        .find_map(|l| l.strip_prefix("[GNUPG:] ENC_TO "))
        .and_then(|l| l.split(' ').next())
        .unwrap()
        .to_string();
    assert_eq!(enc_to, gkeys[4].fpr[24..], "gpg picks the newest valid one");

    let armored = home.ok(
        &gpg(h, &["--armor", "--export-secret-keys", &fpr], pass),
        "export-secret-keys",
    );
    let loaded = read::open(armored.as_bytes(), pass).unwrap();
    assert!(loaded.primary_secret);
    // In the file's order, which is gpg's; compare as a set.
    let mut uids = loaded.user_ids.clone();
    uids.sort();
    assert_eq!(uids, [uid, "T2 <t2@example.org>"]);
    let created: u64 = gkeys[0].created.parse().unwrap();
    let expires: u64 = gkeys[0].expires.parse().unwrap();
    assert_eq!(loaded.expiry.map(u64::from), Some(expires - created));
    assert_eq!(loaded.keys.len(), 5, "revoked subkey skipped");
    assert_eq!(loaded.notes.len(), 1, "{:?}", loaded.notes);
    assert!(loaded.notes[0].contains("revoked"), "{:?}", loaded.notes);
    let slot_of = |f: &str| {
        loaded
            .keys
            .iter()
            .find(|k| hex(&k.fpr) == f)
            .map(|k| k.slot)
            .unwrap()
    };
    assert_eq!(slot_of(&gkeys[0].fpr), None, "certify-only primary");
    assert_eq!(slot_of(&gkeys[1].fpr), Some(Slot::Sign));
    assert_eq!(slot_of(&gkeys[2].fpr), None, "older encryption subkey");
    assert_eq!(slot_of(&gkeys[3].fpr), Some(Slot::Auth));
    assert_eq!(slot_of(&gkeys[4].fpr), Some(Slot::Decrypt));

    // Subkeys only: the certify-only primary has no secret part; the
    // rest loads and fills the same slots.
    let subs = home.ok(
        &gpg(h, &["--armor", "--export-secret-subkeys", &fpr], pass),
        "export-secret-subkeys",
    );
    let subs = read::open(subs.as_bytes(), pass).unwrap();
    assert!(!subs.primary_secret);
    assert_eq!(subs.keys.len(), 4);
    let slots: Vec<_> = subs.keys.iter().map(|k| k.slot).collect();
    assert_eq!(
        slots,
        [
            Some(Slot::Sign),
            None,
            Some(Slot::Auth),
            Some(Slot::Decrypt)
        ]
    );
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

/// gpg's view (pub + subs) of the expiry fields after importing `files`.
fn expiries_after_import(tag: &str, fpr: &str, files: &[&str]) -> Vec<(String, String)> {
    let home = Home::new(tag);
    let h = &home.0;
    for (i, data) in files.iter().enumerate() {
        let f = home.write(&format!("{i}.asc"), data.as_bytes());
        home.ok(&gpg(h, &["--import", &f], None), "import");
    }
    let o = home.ok(
        &gpg(h, &["--with-colons", "--list-keys", fpr], None),
        "list-keys",
    );
    colon_keys(&o)
        .into_iter()
        .map(|k| (k.rec, k.expires))
        .collect()
}

fn change_expiry_shows_in_gpg(t: KeyType) {
    use keyroost_pgpkey::cert::change_expiry;
    use keyroost_pgpkey::sig::HostSigner;
    let (set, out, now) = make(t, Expiry::Years(1));
    let fpr = hex(&set.parts[0].fingerprint());
    let public = read::open_public(out.public.as_bytes()).unwrap();
    let mut signer = HostSigner(&set.parts[0]);
    let pfpr = set.parts[0].fingerprint();
    let five = change_expiry(&public, &mut signer, pfpr, Expiry::Years(5), now + 1).unwrap();
    let end = Expiry::Years(5).end_time(now + 1).unwrap().unwrap();
    let got = expiries_after_import("exp5", &fpr, &[&out.public, &five]);
    let recs: Vec<&str> = got.iter().map(|(r, _)| r.as_str()).collect();
    assert_eq!(recs, ["pub", "sub", "sub"], "{t:?}");
    for (rec, e) in &got {
        assert_eq!(e, &end.to_string(), "{t:?} {rec}");
    }
    let never = change_expiry(&public, &mut signer, pfpr, Expiry::Never, now + 1).unwrap();
    let got = expiries_after_import("expn", &fpr, &[&out.public, &never]);
    assert_eq!(got.len(), 3);
    assert!(got.iter().all(|(_, e)| e.is_empty()), "{t:?} {got:?}");
}

#[test]
fn changed_expiry_shows_in_gpg() {
    if !have_gpg() {
        return;
    }
    for t in [
        KeyType::Cv25519,
        KeyType::NistP256,
        KeyType::NistP384,
        KeyType::NistP521,
        KeyType::Secp256k1,
        KeyType::Rsa2048,
    ] {
        change_expiry_shows_in_gpg(t);
    }
}

#[test]
fn backup_with_changed_expiry_still_imports_in_gpg() {
    if !have_gpg() {
        return;
    }
    let (set, out, now) = make(KeyType::NistP256, Expiry::Years(1));
    let fpr = hex(&set.parts[0].fingerprint());
    let (secret, public) = keyroost_pgpkey::cert::change_expiry_in_backup(
        out.secret.as_bytes(),
        PASS,
        Expiry::Years(2),
        now + 1,
    )
    .unwrap();
    let end = Expiry::Years(2).end_time(now + 1).unwrap().unwrap();
    let got = expiries_after_import("expb", &fpr, &[&out.public, &public]);
    assert!(got.iter().all(|(_, e)| e == &end.to_string()), "{got:?}");
    let home = Home::new("expbs");
    let h = &home.0;
    let f = home.write("sec.asc", secret.as_bytes());
    home.ok(&gpg(h, &["--import", &f], Some(PASS)), "import secret");
    let o = home.ok(
        &gpg(h, &["--with-colons", "--list-secret-keys", &fpr], None),
        "list-secret-keys",
    );
    let keys = colon_keys(&o);
    assert_eq!(keys.len(), 3);
    assert!(keys.iter().all(|k| k.expires == end.to_string()), "{o}");
    // The secret parts still unlock with the same passphrase: sign.
    let msg = home.write("msg.txt", b"hello");
    home.ok(
        &gpg(
            h,
            &["--local-user", &fpr, "--detach-sign", "--output", "-", &msg],
            Some(PASS),
        ),
        "sign",
    );
}
