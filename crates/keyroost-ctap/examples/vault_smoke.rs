//! Hardware smoke test for the FIDO2 vault on a real key. Not shipped.
//!
//! It exercises the CTAP pieces the vault needs end to end — makeCredential
//! with hmac-secret, largeBlobKey and credProtect 3, getAssertion for the
//! hmac-secret output and the largeBlobKey, the per-credential largeBlob
//! entry, and credential management delete — against the vault format in
//! `keyroost-vault`, so the format and the transport are proven together
//! before any CLI or GUI is built on them.
//!
//! ```text
//! cargo run -p keyroost-ctap --example vault_smoke -- info   --path /dev/hidrawN
//! cargo run -p keyroost-ctap --example vault_smoke -- create --path /dev/hidrawN --name kr-smoke [--out DIR]
//! cargo run -p keyroost-ctap --example vault_smoke -- read   --path /dev/hidrawN
//! cargo run -p keyroost-ctap --example vault_smoke -- delete --path /dev/hidrawN --name kr-smoke
//! ```
//!
//! The PIN comes only from the `KR_PIN` environment variable (never argv).
//! Only credentials of the vault RP (`fido2-vault.token2`) and their own
//! largeBlob entries are ever touched; every other entry in the key's
//! largeBlob array is written back unchanged.
//!
//! `create --out DIR` also writes this test credential's largeBlobKey, its
//! hmac-secret output and its credential ID into DIR, so libfido2's
//! `fido2-token` and an independent implementation can read and write the
//! same vault. Those files are secrets for the test credential: delete them
//! afterwards.

use keyroost_ctap::client_pin::{self, permissions, PinUvAuthToken};
use keyroost_ctap::cred_mgmt::CredentialManager;
use keyroost_ctap::get_assertion::{
    get_assertions, vault_name_from_user_id, Assertion, GetAssertionRequest,
};
use keyroost_ctap::hmac_secret::{self, prf_salt};
use keyroost_ctap::large_blobs::{self, LargeBlobArray};
use keyroost_ctap::make_credential::{make_credential, MakeCredentialRequest};
use keyroost_ctap::{get_info, AuthenticatorInfo, CtapError, CtapHidDevice};
use keyroost_vault::{
    new_id, open, seal, user_handle, Entry, Vault, MAX_NAME_BYTES, PRF_INPUT, RP_ID, RP_NAME,
};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use zeroize::Zeroizing;

/// What `create --out DIR` writes.
const OUT_FILES: [&str; 4] = ["lbk.b64", "hmac.bin", "cred_id.b64", "cred_id.hex"];

type Res<T> = Result<T, Box<dyn std::error::Error>>;

const USAGE: &str = "\
usage: vault_smoke <command> --path HIDPATH [options]

commands:
  info    --path HIDPATH                       show the device (no PIN, no touch)
  create  --path HIDPATH --name NAME [--out DIR]
                                               new vault credential + one-entry vault
  read    --path HIDPATH                       open every vault on the key, list titles
  delete  --path HIDPATH --name NAME           delete that vault credential and its data

The PIN is read from the KR_PIN environment variable (create/read/delete).";

struct Args {
    cmd: String,
    path: PathBuf,
    name: Option<String>,
    out: Option<PathBuf>,
}

fn parse_args() -> Result<Args, String> {
    let mut it = std::env::args().skip(1);
    let cmd = it.next().ok_or("missing command")?;
    if cmd == "-h" || cmd == "--help" {
        return Err(String::new());
    }
    let (mut path, mut name, mut out) = (None, None, None);
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or(format!("{flag} needs a value"));
        match flag.as_str() {
            "--path" => path = Some(PathBuf::from(value()?)),
            "--name" => name = Some(value()?),
            "--out" => out = Some(PathBuf::from(value()?)),
            "-h" | "--help" => return Err(String::new()),
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    let path = path.ok_or("--path HIDPATH is required")?;
    match cmd.as_str() {
        "info" | "read" => {
            if name.is_some() || out.is_some() {
                return Err(format!("{cmd} takes only --path"));
            }
        }
        "create" | "delete" => {
            let n = name.as_deref().ok_or("--name NAME is required")?;
            if n.is_empty() || n.len() > MAX_NAME_BYTES {
                return Err(format!(
                    "the name must be 1 to {MAX_NAME_BYTES} bytes of UTF-8"
                ));
            }
            if cmd == "delete" && out.is_some() {
                return Err("delete does not take --out".into());
            }
        }
        other => return Err(format!("unknown command {other:?}")),
    }
    Ok(Args {
        cmd,
        path,
        name,
        out,
    })
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            if e.is_empty() {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            eprintln!("vault_smoke: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vault_smoke: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &Args) -> Res<()> {
    let (mut dev, info) = open_device(&args.path)?;
    if args.cmd == "info" {
        return Ok(());
    }
    let pin = pin_from_env()?;
    match args.cmd.as_str() {
        "create" => create(
            &mut dev,
            &info,
            &pin,
            args.name.as_deref().unwrap_or_default(),
            args.out.as_deref(),
        ),
        "read" => read(&mut dev, &info, &pin),
        "delete" => delete(
            &mut dev,
            &info,
            &pin,
            args.name.as_deref().unwrap_or_default(),
        ),
        _ => unreachable!("parse_args accepts only known commands"),
    }
}

/// Open the key, then print what identifies it (there is no serial over
/// FIDO HID) and what the vault needs from it, before anything else is sent.
fn open_device(path: &Path) -> Res<(CtapHidDevice, AuthenticatorInfo)> {
    let (mut dev, init) = CtapHidDevice::open(path)?;
    if !init.supports_cbor() {
        return Err("this key speaks only U2F (no CTAP2)".into());
    }
    let info = get_info(&mut dev)?;
    println!("device:      {}", path.display());
    println!("aaguid:      {}", aaguid_str(&info.aaguid));
    println!("versions:    {}", info.versions.join(", "));
    println!("extensions:  {}", info.extensions.join(", "));
    println!(
        "largeBlobs:  {:?}  (max array {:?} bytes)",
        info.option("largeBlobs"),
        info.max_serialized_large_blob_array
    );
    let has = |e: &str| info.extensions.iter().any(|x| x == e);
    let mut missing = Vec::new();
    for ext in ["hmac-secret", "largeBlobKey", "credProtect"] {
        if !has(ext) {
            missing.push(ext);
        }
    }
    if info.option("largeBlobs") != Some(true) {
        missing.push("largeBlobs");
    }
    if info.option("clientPin") != Some(true) {
        missing.push("a PIN set (clientPin)");
    }
    if !missing.is_empty() {
        return Err(format!("this key lacks {}", missing.join(", ")).into());
    }
    Ok((dev, info))
}

fn pin_from_env() -> Res<Zeroizing<String>> {
    match std::env::var("KR_PIN") {
        Ok(p) if !p.is_empty() => Ok(Zeroizing::new(p)),
        _ => Err("set the PIN in the KR_PIN environment variable".into()),
    }
}

/// A pinUvAuthToken with `perms`, bound to `rp_id` when given. Every key the
/// vault runs on has largeBlobs, so it is CTAP 2.1 and has the permissions
/// command.
fn token(
    dev: &mut CtapHidDevice,
    info: &AuthenticatorInfo,
    pin: &str,
    perms: u32,
    rp_id: Option<&str>,
) -> Res<PinUvAuthToken> {
    if info.option("pinUvAuthToken") != Some(true) {
        return Err("this key has no CTAP 2.1 permission tokens".into());
    }
    Ok(client_pin::get_pin_uv_auth_token_with_permissions(
        dev, pin, perms, rp_id,
    )?)
}

/// Write `array` with `tok`. Some keys drop the token after getAssertion
/// (seen on Token2 firmware); when the write is refused for PIN auth, take a
/// fresh token with only the largeBlob-write permission (PIN, no touch) and
/// retry once.
fn write_array(
    dev: &mut CtapHidDevice,
    info: &AuthenticatorInfo,
    pin: &str,
    tok: &PinUvAuthToken,
    array: &LargeBlobArray,
) -> Res<()> {
    let cap = array.capacity(info);
    if cap.used_bytes > cap.max_bytes {
        return Err(format!(
            "the largeBlob array would need {} of {} bytes",
            cap.used_bytes, cap.max_bytes
        )
        .into());
    }
    let bytes = array.serialize_with_checksum()?;
    match large_blobs::write(dev, info, tok, &bytes) {
        Ok(()) => Ok(()),
        Err(e) if e.is_pin_auth_error() => {
            println!("  largeBlob write refused the token ({e}); new token, retrying once");
            let fresh = token(dev, info, pin, permissions::LARGE_BLOB_WRITE, None)?;
            Ok(large_blobs::write(dev, info, &fresh, &bytes)?)
        }
        Err(e) => Err(e.into()),
    }
}

/// One getAssertion for the vault RP asking for the hmac-secret output and
/// the largeBlobKey. `allow` narrows it to one credential; `None` returns
/// every vault credential on the key.
fn vault_assertions(
    dev: &mut CtapHidDevice,
    info: &AuthenticatorInfo,
    tok: &PinUvAuthToken,
    allow: Option<&[u8]>,
) -> Res<Vec<Assertion>> {
    let session = hmac_secret::begin(dev, info)?;
    let req = GetAssertionRequest {
        client_data_hash: random32()?,
        rp_id: RP_ID,
        allow,
        hmac: Some((&session, prf_salt(PRF_INPUT))),
        large_blob_key: true,
        up: true,
        pin_uv_auth: Some(tok),
    };
    println!(">>> touch the key now (getAssertion)");
    Ok(get_assertions(dev, info, &req)?)
}

fn create(
    dev: &mut CtapHidDevice,
    info: &AuthenticatorInfo,
    pin: &str,
    name: &str,
    out: Option<&Path>,
) -> Res<()> {
    // Refuse before anything reaches the key, not after the credential exists.
    if let Some(dir) = out {
        for f in OUT_FILES {
            if dir.join(f).exists() {
                return Err(format!("{} already exists", dir.join(f).display()).into());
            }
        }
    }

    let user_id = user_handle(name)?;

    let mc_tok = token(dev, info, pin, permissions::MAKE_CREDENTIAL, Some(RP_ID))?;
    let req = MakeCredentialRequest {
        client_data_hash: random32()?,
        rp_id: RP_ID,
        rp_name: RP_NAME,
        user_id: &user_id,
        user_name: name,
        resident: true,
        cred_protect: Some(3),
        hmac_secret: true,
        large_blob_key: true,
        pin_uv_auth: Some(&mc_tok),
    };
    println!(">>> touch the key now (makeCredential)");
    let made = make_credential(dev, info, &req)?;
    drop(mc_tok);
    println!(
        "  credential created: id {} bytes, credProtect {:?}, largeBlobKey {}",
        made.credential_id.len(),
        made.cred_protect,
        if made.large_blob_key.is_some() {
            "returned"
        } else {
            "not returned"
        }
    );

    // One token for unlock and write, as the vault will do it.
    let tok = token(
        dev,
        info,
        pin,
        permissions::GET_ASSERTION | permissions::LARGE_BLOB_WRITE,
        Some(RP_ID),
    )?;
    let mut found = vault_assertions(dev, info, &tok, Some(&made.credential_id))?;
    if found.len() != 1 {
        return Err(format!("expected 1 assertion, got {}", found.len()).into());
    }
    let a = found.remove(0);
    if a.credential_id != made.credential_id {
        return Err("the key answered with a different credential".into());
    }
    let hmac = a.hmac_output.ok_or("no hmac-secret output")?;
    let lbk = a.large_blob_key.ok_or("no largeBlobKey")?;
    if let Some(mc_lbk) = &made.large_blob_key {
        if mc_lbk[..] != lbk[..] {
            return Err("makeCredential and getAssertion gave different largeBlobKeys".into());
        }
    }

    let vault = Vault {
        entries: vec![Entry {
            id: new_id(),
            title: "Mail".into(),
            username: "smoke".into(),
            password: Zeroizing::new("correct horse battery staple".into()),
            url: String::new(),
            notes: String::new(),
            modified_minutes: now_minutes(),
        }],
    };
    let blob = seal(&vault, &hmac)?;
    println!("  sealed vault: {} bytes", blob.len());

    // Re-read right before the write so nothing written since is lost.
    let array = large_blobs::read(dev, info)?;
    let before = array.len();
    let updated = array.with_credential_blob(&lbk, &blob)?;
    write_array(dev, info, pin, &tok, &updated)?;
    println!("  largeBlob written ({before} entries before)");

    let reread = large_blobs::read(dev, info)?;
    let stored = reread
        .credential_blob(&lbk)
        .ok_or("the written entry did not read back")?;
    let opened = open(&stored, &hmac)?;
    let title = opened
        .entries
        .first()
        .map_or("<no entries>", |e| e.title.as_str());
    println!("kr-smoke ok: {title}");

    if let Some(dir) = out {
        std::fs::create_dir_all(dir)?;
        let lbk_b64 = Zeroizing::new(base64(&lbk[..]));
        write_secret(&dir.join("lbk.b64"), lbk_b64.as_bytes())?;
        write_secret(&dir.join("hmac.bin"), &hmac[..])?;
        write_secret(
            &dir.join("cred_id.b64"),
            base64(&made.credential_id).as_bytes(),
        )?;
        write_secret(
            &dir.join("cred_id.hex"),
            hex(&made.credential_id).as_bytes(),
        )?;
        println!(
            "WARNING: wrote this test credential's secrets (lbk.b64, hmac.bin) and its ID \
             to {} — delete them when the interop check is done",
            dir.display()
        );
    }
    Ok(())
}

fn read(dev: &mut CtapHidDevice, info: &AuthenticatorInfo, pin: &str) -> Res<()> {
    let tok = token(dev, info, pin, permissions::GET_ASSERTION, Some(RP_ID))?;
    let found = match vault_assertions(dev, info, &tok, None) {
        Err(e)
            if matches!(
                e.downcast_ref::<CtapError>(),
                Some(CtapError::NoCredentials)
            ) =>
        {
            println!("no vault credentials on this key");
            return Ok(());
        }
        r => r?,
    };
    let array = large_blobs::read(dev, info)?;
    println!("{} vault credential(s)", found.len());
    for a in &found {
        let name = a
            .user_id
            .as_deref()
            .and_then(vault_name_from_user_id)
            .or_else(|| a.user_name.clone())
            .unwrap_or_else(|| "<unnamed>".into());
        print!("- {name}: ");
        let (Some(hmac), Some(lbk)) = (&a.hmac_output, &a.large_blob_key) else {
            println!("missing hmac-secret output or largeBlobKey");
            continue;
        };
        let Some(blob) = array.credential_blob(lbk) else {
            println!("no vault data stored");
            continue;
        };
        match open(&blob, hmac) {
            Ok(v) => {
                let titles: Vec<&str> = v.entries.iter().map(|e| e.title.as_str()).collect();
                println!("{} entries: {}", titles.len(), titles.join(", "));
            }
            Err(e) => println!("cannot open: {e}"),
        }
    }
    Ok(())
}

fn delete(dev: &mut CtapHidDevice, info: &AuthenticatorInfo, pin: &str, name: &str) -> Res<()> {
    let rp_hash = keyroost_proto::sha256::sha256(RP_ID.as_bytes());
    let tok = token(
        dev,
        info,
        pin,
        permissions::CREDENTIAL_MANAGEMENT | permissions::LARGE_BLOB_WRITE,
        None,
    )?;

    // Find the one vault credential with this name (credMgmt, no touch).
    let (cred_id, lbk) = {
        let mut mgr = CredentialManager::new(dev, tok.clone(), info)?;
        let mut matches: Vec<_> = mgr
            .list_credentials(&rp_hash)?
            .into_iter()
            .filter(|c| vault_name_from_user_id(&c.user.id).as_deref() == Some(name))
            .collect();
        match matches.len() {
            1 => {}
            0 => return Err(format!("no vault credential named {name:?} on this key").into()),
            n => {
                return Err(format!(
                    "{n} vault credentials are named {name:?}; refusing to guess (ids: {})",
                    matches
                        .iter()
                        .map(|c| hex(&c.credential_id))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
                .into())
            }
        }
        let c = matches.remove(0);
        let lbk = c
            .large_blob_key
            .as_ref()
            .map(|k| Zeroizing::new(*k))
            .ok_or("the key did not return this credential's largeBlobKey")?;
        (c.credential_id.clone(), lbk)
    };
    println!("  found {name:?}: credential id {}", hex(&cred_id));

    // The data first, while the credential (and so its key) still exists:
    // a failure here leaves everything as it was.
    let array = large_blobs::read(dev, info)?;
    let without = array.without_credential_blob(&lbk);
    if without.len() == array.len() {
        println!("  no largeBlob entry for it");
    } else {
        write_array(dev, info, pin, &tok, &without)?;
        println!(
            "  largeBlob entry removed ({} -> {} entries)",
            array.len(),
            without.len()
        );
    }

    let mut mgr = CredentialManager::new(dev, tok.clone(), info)?;
    match mgr.delete(&cred_id) {
        Ok(()) => {}
        Err(e) if e.is_pin_auth_error() => {
            drop(mgr);
            println!("  delete refused the token ({e}); new token, retrying once");
            let fresh = token(dev, info, pin, permissions::CREDENTIAL_MANAGEMENT, None)?;
            CredentialManager::new(dev, fresh, info)?.delete(&cred_id)?;
        }
        Err(e) => return Err(e.into()),
    }
    println!("kr-smoke deleted: {name}");
    Ok(())
}

fn random32() -> Res<[u8; 32]> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).map_err(|_| CtapError::Random)?;
    Ok(b)
}

fn now_minutes() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| (d.as_secs() / 60) as i64)
}

/// Create `path` readable only by the owner; refuse to overwrite.
fn write_secret(path: &Path, data: &[u8]) -> Res<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(data)?;
    Ok(())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn aaguid_str(a: &[u8; 16]) -> String {
    let h = hex(a);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// Standard base64 with padding: what `fido2-token -k` and `-i` read.
fn base64(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n = u32::from(c[0]) << 16
            | u32::from(*c.get(1).unwrap_or(&0)) << 8
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc4648_vectors() {
        let cases = [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ];
        for (plain, enc) in cases {
            assert_eq!(base64(plain.as_bytes()), enc);
        }
        assert_eq!(base64(&[0xfb, 0xff]), "+/8=");
    }

    #[test]
    fn aaguid_prints_as_a_uuid() {
        let a = [
            0xee, 0x88, 0x28, 0x79, 0x72, 0x1c, 0x49, 0x13, 0x97, 0x75, 0x3d, 0xfc, 0xce, 0x97,
            0x07, 0x2a,
        ];
        assert_eq!(aaguid_str(&a), "ee882879-721c-4913-9775-3dfcce97072a");
    }
}
