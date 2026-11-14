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
VARIANTS = [
    ("baseline", set()),
    ("+listsecret only", {"listsecret"}),
]


def snapshot(home):
    """The agent's key files: name prefix, size, the s-expression type, hash."""
    d = os.path.join(home, "private-keys-v1.d")
    out = []
    try:
        names = sorted(os.listdir(d))
    except OSError:
        return "(no key dir)"
    for n in names:
        b = open(os.path.join(d, n), "rb").read()
        m = re.search(rb"\((openpgp-private-key|protected-private-key|private-key|shadowed-private-key)", b)
        kind = m.group(1).decode() if m else "?"
        out.append(f"{n[:6]} {len(b)}B {kind} {hashlib.sha1(b).hexdigest()[:8]}")
    return "; ".join(out)


def trial(keyfile, n, on, trace=None):
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
        def snap(step):
            if trace is not None:
                trace.append(f"{step}: {snapshot(home)}")
        snap("after import")
        if "listing" in on or "checksigs" in on:
            gpg(home, ["--with-colons", "--check-sigs", fpr], empty_stdin=empty)
            snap("after check-sigs")
        if "listing" in on or "listsecret" in on:
            gpg(home, ["--with-colons", "--list-secret-keys", fpr], empty_stdin=empty)
            snap("after list-secret-keys")
        data = os.path.join(home, "d.txt")
        with open(data, "wb") as f:
            f.write(b"keyroost interop\n")
        sig = gpg(home, ["--local-user", fpr + "!", "-o", f"{data}.sig", "--detach-sign", data], TEST_PHRASE)
        gpg(home, ["--trust-model", "always", "--yes"] + status + ["-r", fpr, "-o", f"{data}.gpg", "--encrypt", data],
            empty_stdin=empty)
        snap("after sign")
        dec = gpg(home, ["--yes"] + status + ["-o", f"{data}.out", "--decrypt", f"{data}.gpg"], TEST_PHRASE)
        snap(f"after decrypt (rc {dec.returncode})")
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


def crc24(data):
    crc = 0xB704CE
    for b in data:
        crc ^= b << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


def armor_private(raw):
    b64 = base64.b64encode(raw).decode()
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    crc = base64.b64encode(crc24(raw).to_bytes(3, "big")).decode()
    return ("-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n" + "\n".join(lines)
            + f"\n={crc}\n-----END PGP PRIVATE KEY BLOCK-----\n")


def cfb(op, cipher, key, iv, data):
    name = {7: "-aes-128-cfb", 9: "-aes-256-cfb"}[cipher]
    return subprocess.run(["openssl", "enc", op, name, "-nopad", "-K", key.hex(), "-iv", iv.hex()],
                          input=data, capture_output=True, check=True).stdout


def reprotect(armored, cipher, hashalgo, count_byte):
    """Re-encrypt each secret packet's protected part with another cipher,
    S2K hash or count; every other byte (salt, IV, packets) stays as is."""
    raw = bytearray(dearmor(armored))
    i = 0
    while i < len(raw):
        h = raw[i]
        hdr = i
        i += 1
        if h & 0x40:
            tag = h & 0x3F
            l0 = raw[i]
            i += 1
            if l0 < 192:
                n = l0
            elif l0 < 224:
                n = ((l0 - 192) << 8) + raw[i] + 192
                i += 1
            else:
                n = struct.unpack(">I", bytes(raw[i:i + 4]))[0]
                i += 4
        else:
            tag = (h >> 2) & 0xF
            size = {0: 1, 1: 2, 2: 4}[h & 3]
            n = int.from_bytes(raw[i:i + size], "big")
            i += size
        body_start = i
        if tag in (5, 7):
            body = bytes(raw[body_start:body_start + n])
            algo = body[5]
            j = 6
            if algo in (18, 19, 22):
                j += 1 + body[j]
                _, _, j = mpi(body, j)
                if algo == 18:
                    j += 1 + body[j]
            elif algo == 1:
                _, _, j = mpi(body, j)
                _, _, j = mpi(body, j)
            old_cipher, old_hash = body[j + 1], body[j + 3]
            salt = body[j + 4:j + 12]
            c = body[j + 12]
            iv = body[j + 13:j + 29]
            ct = body[j + 29:]
            klen = {7: 16, 9: 32}
            old_key = s2k_key(TEST_PHRASE, old_hash, salt, (16 + (c & 15)) << ((c >> 4) + 6), klen[old_cipher])
            plain = cfb("-d", old_cipher, old_key, iv, ct)
            new_key = s2k_key(TEST_PHRASE, hashalgo, salt,
                              (16 + (count_byte & 15)) << ((count_byte >> 4) + 6), klen[cipher])
            new_ct = cfb("-e", cipher, new_key, iv, plain)
            a = body_start + j
            raw[a + 1] = cipher
            raw[a + 3] = hashalgo
            raw[a + 12] = count_byte
            raw[a + 29:a + 29 + len(ct)] = new_ct
        i = body_start + n
    return armor_private(bytes(raw))


# (label, cipher, hash, count byte); ours is AES-256 (9), SHA-256 (8), 0xE0.
REPROTECT = [
    ("ours, unchanged", 9, 8, 0xE0),
    ("count 65011712 only", 9, 8, 0xFF),
    ("AES-128 only", 7, 8, 0xE0),
    ("SHA-1 only", 9, 2, 0xE0),
    ("gpg's three settings", 7, 2, 0xFF),
]


def reexport(keyfile, out):
    """Import our key set and export it again with gpg's own protection."""
    home = f"/tmp/krdx-{os.getpid()}"
    shutil.rmtree(home, ignore_errors=True)
    os.mkdir(home, 0o700)
    try:
        gpg(home, ["--import", keyfile], TEST_PHRASE)
        r = gpg(home, ["--armor", "--export-secret-keys"], TEST_PHRASE)
        open(out, "wb").write(r.stdout)
        return r.returncode == 0 and b"PRIVATE KEY" in r.stdout
    finally:
        subprocess.run(["gpgconf", "--homedir", home, "--kill", "gpg-agent"],
                       env=dict(os.environ, GNUPGHOME=home), capture_output=True)
        shutil.rmtree(home, ignore_errors=True)


def gpg_made(out):
    """A cv25519 key set made and exported by gpg itself, same passphrase."""
    home = f"/tmp/krdm-{os.getpid()}"
    shutil.rmtree(home, ignore_errors=True)
    os.mkdir(home, 0o700)
    try:
        gpg(home, ["--quick-gen-key", "T <t@example.org>", "ed25519", "sign,cert", "never"], TEST_PHRASE)
        cols = gpg(home, ["--list-keys", "--with-colons"]).stdout.decode()
        fpr = next(l.split(":")[9] for l in cols.splitlines() if l.startswith("fpr"))
        gpg(home, ["--quick-add-key", fpr, "cv25519", "encr", "never"], TEST_PHRASE)
        gpg(home, ["--quick-add-key", fpr, "ed25519", "auth", "never"], TEST_PHRASE)
        r = gpg(home, ["--armor", "--export-secret-keys"], TEST_PHRASE)
        open(out, "wb").write(r.stdout)
        return r.returncode == 0 and b"PRIVATE KEY" in r.stdout
    finally:
        subprocess.run(["gpgconf", "--homedir", home, "--kill", "gpg-agent"],
                       env=dict(os.environ, GNUPGHOME=home), capture_output=True)
        shutil.rmtree(home, ignore_errors=True)


def protection(armored):
    """Cipher/S2K of each secret packet, e.g. 254/9 s2k 3 hash 8 count 65536."""
    out = []
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
        c = body[i + 12]
        out.append(f"algo {algo}: usage {body[i]} cipher {body[i + 1]} s2k {body[i + 2]} hash {body[i + 3]} "
                   f"count {(16 + (c & 15)) << ((c >> 4) + 6)}")
    return "; ".join(out)


def control(n):
    """gpg-made key sets through the failing sequence (list-secret-keys first)."""
    bad = 0
    prot = ""
    for i in range(n):
        f = f"/tmp/krdc-{os.getpid()}-{i}.asc"
        if not gpg_made(f):
            print(f"- control key {i}: gpg could not make/export it")
            continue
        prot = protection(open(f).read())
        ok = trial(f, i, {"listsecret"})[0]
        bad += 0 if ok else 1
        os.remove(f)
    print(f"- control: {n} gpg-made cv25519 key sets with list-secret-keys first: {n - bad} decrypt ok, {bad} failed")
    print(f"  - gpg's export protection: {prot}")


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
        traces = []
        results = []
        for i in range(TRIALS):
            tr = [] if i == 0 and False else None
            results.append(trial(keyfile, i, on, tr))
            if tr:
                traces = tr
        dec_ok = sum(r[0] for r in results)
        sig_ok = sum(r[1] for r in results)
        print(f"  - replay {name}: decrypt {dec_ok}/{TRIALS} ok, sign {sig_ok}/{TRIALS} ok")
        for t in traces:
            print(f"    - {t}")
    print(f"  - our export protection: {protection(armored)}")
    for label, cipher, hashalgo, cb in REPROTECT:
        rp = keyfile + ".rp.asc"
        try:
            open(rp, "w").write(reprotect(armored, cipher, hashalgo, cb))
        except Exception as e:  # diagnostic: report, don't stop
            print(f"  - re-protect {label}: failed {e!r}")
            continue
        results = [trial(rp, i, {"listsecret"}) for i in range(TRIALS)]
        print(f"  - re-protected, {label}, list-secret-keys first: decrypt {sum(r[0] for r in results)}/{TRIALS} ok")
    print("\n<details><summary>key set (throwaway test key, passphrase \"test pass\")</summary>\n\n```\n"
          + armored + "```\n</details>")


if __name__ == "__main__":
    if sys.argv[1] == "--control":
        control(int(sys.argv[2]))
    else:
        main()
