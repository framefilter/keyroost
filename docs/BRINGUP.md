# Hardware bring-up plan for a real Molto2 / Molto2v2

This document is for the first time you connect a real Molto2 to keyroost. The
goal is to surface any wire-format mismatch quickly and with actionable output.
Run each step in order; the riskier writes come last and target an isolated
slot (#99).

If anything in steps 1–3 doesn't look right, save the full `--debug` output
and we'll diff it against the expected format in `docs/PROTOCOL.md`.

> **Safe slot.** Steps 4 onwards write to **profile #99**. If you've already
> programmed #99 for real, pick another slot you're willing to overwrite and
> substitute it in every `--profile 99` below.

## Prerequisites

| OS | What you need |
|---|---|
| Linux | `sudo apt install libpcsclite-dev pcscd && sudo systemctl enable --now pcscd` |
| macOS | nothing — PCSC framework is built in |
| Windows | nothing — winscard.dll is built in |

Then build:

```bash
cargo build --release
```

The `keyroostctl` binary will be at `target/release/keyroostctl`. Either copy it
onto your `$PATH` or invoke it from there.

## Step 1: PC/SC sees the device

Plug the Molto2 in, then:

```bash
keyroostctl --list-readers
```

**Expected:** one line containing "TOKEN2" (case may vary, e.g. `TOKEN2 Molto2 [CCID Interface] 00 00`).

**If it fails:**
- *"PC/SC service is unavailable"* — start the service (`sudo systemctl start pcscd` on Linux). On macOS this shouldn't happen.
- *No reader matching "TOKEN2"* but other readers shown — paste the full output. We can widen the matcher.
- *Empty list* — confirm with `pcsc_scan` (Linux) that PC/SC sees any reader at all. If not, it's a system-level USB / udev problem, not a keyroost one.

## Step 2: Read serial and time (no auth required)

```bash
keyroostctl --debug info
```

**Expected stderr** (something like — the actual hex is device-dependent):

```
>      get info (serial + time) >> 80 41 00 00 00
<      get info (serial + time) << XX XX XX 08 41 42 43 44 45 46 47 48 XX XX 65 4F 12 34 90 00
```

…followed by the parsed output on stdout:

```
device serial: ABCDEFGH
device UTC:    1699999284 (epoch)
```

**Checks:**
1. The status word at the end of the response must be `90 00` (success).
2. The 4th byte (the length field) should be reasonable — typically `08`.
3. The UTC time on stdout should be roughly the device's clock (compare to a watch; close enough for a write-only device).

**If the parsed serial looks garbled or the time is nonsensical** the response layout in `read_info()` is wrong. Paste the full `--debug` line and the parsed output and we'll fix the offsets in `crates/keyroost-transport/src/lib.rs`.

## Step 3: Authenticate with the default customer key

Factory-fresh devices use `TOKEN2MOLTO1-KEY`.

```bash
keyroostctl --debug --key-ascii TOKEN2MOLTO1-KEY set-title --profile 99 "MOLTO_TEST"
```

This will print four `>` / `<` lines on stderr — `get info`, `get challenge`, `answer challenge`, then `set title` — and end with "title set on profile #99".

**Checks:**
1. `get challenge` response: 8 random bytes plus `90 00`.
2. `answer challenge` response: just `90 00` (no data).
3. `set title` response: just `90 00`.

**If `answer challenge` returns `63 NN`:** the customer key on your device isn't the factory default. Try whatever key you set, via `--key-ascii` (text) or `--key` (hex). If you've forgotten it: `keyroostctl molto reset --yes` does **not** require the customer key (it's a plain CLA `0x80` command); it will wipe every profile and reset the key back to `TOKEN2MOLTO1-KEY`. The device will return `SW 90 60` and display a confirmation prompt — press the up-arrow on the device to commit the reset.

**If `set title` returns anything other than `90 00`:** capture the SW bytes. That's the most likely place for a MAC computation mismatch. The SW will be specific (e.g. `69 82` = security status not satisfied, `6A 80` = wrong data) and will tell us where to look.

## Step 4: Verify the title on-device

Press the button on the Molto2 to wake it up and cycle to profile #99. You
should see "MOLTO_TEST" as the title.

## Step 5: Write a known TOTP seed and verify the codes match

```bash
keyroostctl --debug --key-ascii TOKEN2MOLTO1-KEY \
  import --profile 99 \
  --title MOLTO_TEST \
  'otpauth://totp/MoltoTest?secret=JBSWY3DPEHPK3PXPJBSWY3DP&algorithm=SHA1&digits=6&period=30'
```

This writes seed + title + config in one authenticated session.

To verify the device actually generates correct codes, paste the same URI into
any standard authenticator (Google Authenticator, Aegis, Bitwarden) and
compare. Within ±1 step (30 seconds) both should show the same 6 digits. If
they don't, the device's clock is off — fix with:

```bash
keyroostctl --key-ascii TOKEN2MOLTO1-KEY sync-time --profile 99
```

…and try again on the next 30-second boundary.

## Step 6: Bulk import smoke test

Drop a small plaintext Aegis or 2FAS export (1–3 entries) into `/tmp/test.json`
and:

```bash
keyroostctl --debug --key-ascii TOKEN2MOLTO1-KEY \
  import-file /tmp/test.json --start 95 --dry-run
```

`--dry-run` parses and prints the plan without writing. If that looks right,
drop `--dry-run` and let it write.

## Step 7: GUI smoke test

```bash
keyroost
```

Click Connect → confirm device info appears in the top bar → enter the
customer key (or leave blank for the default) → click Authenticate → select a
slot → fill in a title and base32 secret → click Write profile.

The log panel at the bottom should show green "ok" lines for each step.

## FIDO security-key bring-up

Separate from the Molto2 / TOTP path above, keyroost also speaks CTAP2 to FIDO2
security keys (HID transport, PIN protocol, credential management). This
runbook validates that layer against real hardware. Each step is read-only or,
where state-changing, clearly marked. Run it against a **disposable test key**,
not your daily-driver authenticator.

> **Reset to recover.** A factory reset returns a FIDO key to a fully
> functional fresh state; nothing in this runbook can brick the device — at
> worst you re-enter the commissioning PIN.

### Prerequisites

Install the bundled udev rules so a non-root user can open `/dev/hidraw*` for
FIDO devices:

```bash
sudo cp udev/70-keyroost-fido.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger
```

After plugging the key in, look for `+` after the permissions on the new
hidraw node (a POSIX ACL via `uaccess`):

```bash
ls -l /dev/hidraw*
```

### Step F1: Device enumerates

```bash
keyroostctl list
```

**Expected:** one line under "FIDO HID devices" per inserted authenticator,
showing path, VID:PID, usage page `f1d0:0001`, and a model string. With
multiple keys plugged in you'll get one line each — every subsequent
`fido-*` subcommand accepts `--path /dev/hidrawN` to disambiguate, and
kernel hidraw numbers **change on each replug**, so enumerate fresh.

### Step F2: GetInfo round-trips

```bash
keyroostctl fido info --path /dev/hidrawN
```

**Expected** (sample from a SoloKeys Solo 2, firmware 2.3.196):

```
Channel:    0x00000001 (CTAPHID protocol v2)
Versions:   U2F_V2, FIDO_2_0, FIDO_2_1_PRE
Extensions: credProtect, hmac-secret
Options:    rk=true, up=true, plat=false, credMgmt=true, clientPin=false, …
PIN/UV protocols: 1
```

Validates HID transport, CTAPHID INIT, CTAP2 `authenticatorGetInfo`, and
the CBOR decoder. `clientPin=false` confirms an unprovisioned (fresh or
post-reset) key.

### Step F3: Set the initial PIN

First state-changing step. Use a known throwaway PIN for testing — you'll
factory-reset before putting the key into real service.

```bash
printf 'YOUR_TEST_PIN\n' | keyroostctl fido pin-set \
    --path /dev/hidrawN --new-pin-stdin
```

**Expected:** `PIN set.` Re-run `fido info`: `clientPin` should now be
`true`. `fido pin-retries` should still show the full attempt counter —
the initial set doesn't consume a retry.

### Step F4: PIN-protected read paths

```bash
printf 'YOUR_TEST_PIN\n' | keyroostctl fido creds-metadata \
    --path /dev/hidrawN --pin-stdin
printf 'YOUR_TEST_PIN\n' | keyroostctl fido creds-list \
    --path /dev/hidrawN --pin-stdin
```

**Expected on a fresh key:** `0 resident credential(s) stored, room for N
more`, and `(no resident credentials)`. The point isn't the (empty)
contents — it's that the `pinUvAuthToken` exchange (`clientPin` 0x09 with
`cm` permission) succeeded. A correct PIN must **not** decrement the retry
counter; verify with `fido pin-retries` afterwards.

### Step F5: Resident-credential round-trip (create → list → delete)

Plant a discoverable credential using `ssh-keygen` as the simplest external
RP, then exercise `fido creds-list` and `fido creds-delete`:

```bash
# Create — needs PIN entry + a physical touch when the key blinks.
ssh-keygen -t ecdsa-sk -O resident -O application=ssh:moltotest \
           -N '' -f /tmp/sk_moltotest

# Read back — confirm it appears, copy the FULL id= value.
printf 'YOUR_TEST_PIN\n' | keyroostctl fido creds-list \
    --path /dev/hidrawN --pin-stdin

# Destructive: delete by full credentialId.
printf 'YOUR_TEST_PIN\n' | keyroostctl fido creds-delete \
    --path /dev/hidrawN --cred-id <full hex from id=> --pin-stdin

# Confirm empty.
printf 'YOUR_TEST_PIN\n' | keyroostctl fido creds-list \
    --path /dev/hidrawN --pin-stdin
```

The `id=` line is the value you copy — the `cred …` summary above it is
truncated for readability and is **not** a valid `--cred-id` value.

**Use `ecdsa-sk`, not `ed25519-sk`,** if your authenticator's firmware
doesn't support Ed25519 in `makeCredential`. On Solo 2 firmware 2.3.196,
`ed25519-sk` enrollment fails with `Key enrollment failed: invalid format`;
`ecdsa-sk` (ES256 / P-256) works on every CTAP2 device. A firmware update
likely adds Ed25519 support.

### What this validates

Running F1–F5 successfully exercises, end to end against real silicon:

- HID transport + CTAPHID INIT
- CTAP2 `authenticatorGetInfo` + CBOR codec
- PIN protocol v1 (keyAgreement, sharedSecret, `setPIN`)
- `pinUvAuthToken` acquisition with `cm` permission
- `authenticatorCredentialManagement`: `getCredsMetadata`,
  `enumerateRPsBegin/Next`, `enumerateCredentialsBegin/Next`,
  `deleteCredential`

First successful run: 2026-05-27, SoloKeys Solo 2 firmware 2.3.196, on
Linux 6.12 / OpenSSH 10.0p2 / libfido2 1.15.0.

## What to send back if anything goes wrong

Either email me, paste in the chat, or open an issue with:

1. The exact command you ran
2. **All of the `--debug` output** (this is the key piece — the hex tells us
   everything about where the mismatch is)
3. Anything visible on the device's screen at the time
4. OS and `cargo --version`

With that we can almost always fix the issue in one round trip.
