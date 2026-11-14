#!/usr/bin/env python3
"""Diagnostic only (draft PR, never merged).

Given a failed `cargo test` log from gnupg_interop and the `hwf` helper:
1. check the failing key set with an independent decryption (Python S2K +
   `openssl enc`), so a damaged export is told apart from a gpg-side error;
2. replay the key in fresh gpg homes (import, encrypt, decrypt, sign) with
   libgcrypt's hardware features as they are, then with the VAES/AVX-512
   AES paths denied, then with AES-NI denied as well.

Prints Markdown for the job summary. The key is a throwaway test key under
the test's own passphrase.
"""
import base64
import hashlib
import os
import re
import shutil
import struct
import subprocess
import sys

TEST_PHRASE = b"test pass"
DENY_FILE = "/etc/gcrypt/hwf.deny"
TRIALS = 3
MODES = [
    ("as is", None),
    ("VAES/AVX-512 denied", "intel-vaes-vpclmul\nintel-avx512\n"),
    ("VAES/AVX-512 and AES-NI denied", "intel-vaes-vpclmul\nintel-avx512\nintel-aesni\n"),
]


def dearmor(text):
    body, started = [], False
    for ln in text.strip().splitlines():
        if ln.startswith("-----BEGIN"):
            started = True
            continue
        if ln.startswith("-----END"):
            break
        if not started or (":" in ln and not body) or ln == "" or ln.startswith("="):
            continue
        body.append(ln)
    return base64.b64decode("".join(body))


def packets(d):
    i = 0
    while i < len(d):
        h = d[i]
        i += 1
        if h & 0x40:
            tag = h & 0x3F
            l0 = d[i]
            i += 1
            if l0 < 192:
                n = l0
            elif l0 < 224:
                n = ((l0 - 192) << 8) + d[i] + 192
                i += 1
            else:  # 255: four-byte length (keys never use partial lengths)
                n = struct.unpack(">I", d[i:i + 4])[0]
                i += 4
        else:
            tag = (h >> 2) & 0xF
            lt = h & 3
            size = {0: 1, 1: 2, 2: 4}[lt]
            n = int.from_bytes(d[i:i + size], "big")
            i += size
        yield tag, d[i:i + n]
        i += n


def mpi(b, i):
    bits = struct.unpack(">H", b[i:i + 2])[0]
    n = (bits + 7) // 8
    return bits, b[i + 2:i + 2 + n], i + 2 + n


def s2k_key(phrase, hashalgo, salt, count, keylen):
    h = {8: hashlib.sha256, 2: hashlib.sha1, 10: hashlib.sha512}[hashalgo]
    data = salt + phrase
    total = max(count, len(data))
    buf = (data * (total // len(data) + 1))[:total]
    out, pre = b"", 0
    while len(out) < keylen:
        out += h(b"\0" * pre + buf).digest()
        pre += 1
    return out[:keylen]


def check_key(armored):
    """One line per secret key packet: algorithm, checksum, secret length."""
    lines = []
    for tag, body in packets(dearmor(armored)):
        if tag not in (5, 7):
            continue
        algo = body[5]
        i = 6
        if algo in (18, 19, 22):
            i += 1 + body[i]
            _, _, i = mpi(body, i)
            if algo == 18:
                i += 1 + body[i]
        elif algo == 1:
            _, _, i = mpi(body, i)
            _, _, i = mpi(body, i)
        usage, s2k, hashalgo = body[i], body[i + 2], body[i + 3]
        if usage != 254 or s2k != 3 or body[i + 1] != 9:
            lines.append(f"  - packet {tag} algo {algo}: unexpected protection {body[i:i + 3].hex()}")
            continue
        salt = body[i + 4:i + 12]
        c = body[i + 12]
        count = (16 + (c & 15)) << ((c >> 4) + 6)
        iv = body[i + 13:i + 29]
        ct = body[i + 29:]
        key = s2k_key(TEST_PHRASE, hashalgo, salt, count, 32)
        plain = subprocess.run(
            ["openssl", "enc", "-d", "-aes-256-cfb", "-nopad", "-K", key.hex(), "-iv", iv.hex()],
            input=ct, capture_output=True, check=True).stdout
        mpis, sha = plain[:-20], plain[-20:]
        ok = hashlib.sha1(mpis).digest() == sha
        j, info = 0, []
        while j < len(mpis):
            bits, val, j = mpi(mpis, j)
            info.append(f"{bits} bits/{len(val)} bytes")
        kind = "primary" if tag == 5 else "subkey"
        lines.append(f"  - {kind} algo {algo}: checksum {'OK' if ok else 'BAD'}, secret {', '.join(info)}, "
                     f"ciphertext {len(ct)} bytes")
    return lines


def gpg(home, args, stdin=None, empty_stdin=False):
    cmd = ["gpg", "--homedir", home, "--batch", "--no-tty", "--no-auto-check-trustdb"]
    if stdin is not None:
        cmd += ["--pinentry-mode", "loopback", "--passphrase-fd", "0"]
        data = stdin + b"\n"
    else:
        data = b"" if empty_stdin else b"\n"
    return subprocess.run(cmd + args, input=data, capture_output=True,
                          env=dict(os.environ, GNUPGHOME=home))


# Each switch is one way the Rust test drives gpg that the Python replay
# didn't: agent debug logging, --status-fd 1 on encrypt/decrypt, listing
# and checking the keys before signing, nothing at all on stdin when no
# passphrase is needed.
SWITCHES = ("debug", "status", "listing", "empty")
VARIANTS = [("baseline", set())] + [(f"+{w}", {w}) for w in SWITCHES] + [("all four", set(SWITCHES))]


def trial(keyfile, n, on):
    """Import with the passphrase, sign, encrypt, decrypt in a fresh home,
    with the switches in `on`. Returns (decrypt ok, sign ok, agent error)."""
    home = f"/tmp/krdg-{os.getpid()}-{n}"
    shutil.rmtree(home, ignore_errors=True)
    os.mkdir(home, 0o700)
    with open(os.path.join(home, "gpg-agent.conf"), "w") as f:
        f.write(f"log-file {home}/agent.log\n")
        if "debug" in on:
            f.write("debug-level basic\n")
    empty = "empty" in on
    status = ["--status-fd", "1"] if "status" in on else []
    try:
        gpg(home, ["--import", keyfile], TEST_PHRASE)
        cols = gpg(home, ["--list-keys", "--with-colons"], empty_stdin=empty).stdout.decode()
        fpr = next(l.split(":")[9] for l in cols.splitlines() if l.startswith("fpr"))
        if "listing" in on:
            gpg(home, ["--with-colons", "--check-sigs", fpr], empty_stdin=empty)
            gpg(home, ["--with-colons", "--list-secret-keys", fpr], empty_stdin=empty)
        data = os.path.join(home, "d.txt")
        with open(data, "wb") as f:
            f.write(b"keyroost interop\n")
        sig = gpg(home, ["--local-user", fpr + "!", "-o", f"{data}.sig", "--detach-sign", data], TEST_PHRASE)
        gpg(home, ["--trust-model", "always", "--yes"] + status + ["-r", fpr, "-o", f"{data}.gpg", "--encrypt", data],
            empty_stdin=empty)
        dec = gpg(home, ["--yes"] + status + ["-o", f"{data}.out", "--decrypt", f"{data}.gpg"], TEST_PHRASE)
        err = ""
        try:
            log = open(os.path.join(home, "agent.log")).read()
            m = re.findall(r"failed to unprotect[^\n]*", log)
            err = m[0] if m else ""
        except OSError:
            pass
        return dec.returncode == 0, sig.returncode == 0, err
    finally:
        subprocess.run(["gpgconf", "--homedir", home, "--kill", "gpg-agent"],
                       env=dict(os.environ, GNUPGHOME=home), capture_output=True)
        shutil.rmtree(home, ignore_errors=True)


def set_deny(content):
    if content is None:
        subprocess.run(["sudo", "rm", "-f", DENY_FILE], check=True)
    else:
        subprocess.run(["sudo", "mkdir", "-p", os.path.dirname(DENY_FILE)], check=True)
        subprocess.run(["sudo", "tee", DENY_FILE], input=content.encode(), capture_output=True, check=True)


def main():
    log_path, hwf = sys.argv[1], sys.argv[2]
    log = open(log_path, encoding="utf-8", errors="replace").read()
    tests = re.findall(r"---- (\S+) stdout ----", log)
    print(f"\n## Failure: {', '.join(tests) or 'unknown test'}")
    for l in re.findall(r"gpg-agent\[\d+\] (failed to unprotect[^\n]*|command '[A-Z]+' failed[^\n]*)", log):
        print(f"- agent: {l}")
    m = re.search(r"-----BEGIN PGP PRIVATE KEY BLOCK-----.*?-----END PGP PRIVATE KEY BLOCK-----", log, re.S)
    if not m:
        print("- no key set in the log (failure before export?)")
        print("\n<details><summary>log tail</summary>\n\n```\n" + log[-4000:] + "\n```\n</details>")
        return
    armored = m.group(0) + "\n"
    keyfile = log_path + ".asc"
    with open(keyfile, "w") as f:
        f.write(armored)
    print("- independent check of the exported key (openssl AES-256-CFB):")
    try:
        print("\n".join(check_key(armored)))
    except Exception as e:  # diagnostic: report, don't stop the replay
        print(f"  - check failed: {e!r}")
    for name, on in VARIANTS:
        results = [trial(keyfile, i, on) for i in range(TRIALS)]
        dec_ok = sum(r[0] for r in results)
        sig_ok = sum(r[1] for r in results)
        print(f"  - replay {name}: decrypt {dec_ok}/{TRIALS} ok, sign {sig_ok}/{TRIALS} ok")
    print("\n<details><summary>key set (throwaway test key, passphrase \"test pass\")</summary>\n\n```\n"
          + armored + "```\n</details>")


if __name__ == "__main__":
    main()
