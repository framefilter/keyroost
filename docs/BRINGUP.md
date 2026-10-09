# Hardware bring-up plan for a real Molto2 / Molto2v2

This document is for the first time you connect a real Molto2 to keyroost. The
goal is to surface any wire-format mismatch quickly and with actionable output.
Run each step in order. Steps 1, 2 and 4 are read-only; step 3 onwards writes to
the device, and step 6 writes several slots at once. One recovery path inside
step 3 — `molto reset` — wipes the entire device; it appears out of risk order
because it is the only way past a forgotten customer key.

If anything in steps 1–3 doesn't look right, save the full `--debug` output
and we'll diff it against the expected format in `docs/PROTOCOL.md`.

> **Safe slots.** Step 3 onwards writes to the device. Steps 3 and 5 target
> **slot #99** (Token2 calls slots profiles); step 6 bulk-imports starting at **#95** and fills consecutive
> slots from there — one per entry in your export, so a 3-entry file writes
> #95, #96 and #97. If you've already programmed anything in #95–#99 for real,
> pick a range you're willing to overwrite and substitute it in every
> `--slot 99` (step 6: `--slot 95`) below.

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
keyroostctl list
```

**Expected:** a row for the Molto2 that names its reader, containing "TOKEN2" (case may vary, e.g. `TOKEN2 Molto2 [CCID Interface] 00 00`).

**If it fails:**
- *"PC/SC service is unavailable"* — start the service (`sudo systemctl start pcscd` on Linux). On macOS this shouldn't happen.
- *"no Token2 Molto2 reader found"* but other readers shown — keyroost looks for a reader whose name contains "molto". Paste the full output. We can widen the matcher.
- *Empty list* — confirm with `pcsc_scan` (Linux) that PC/SC sees any reader at all. If not, it's a system-level USB / udev problem, not a keyroost one.

**Faster than any of the above:** `keyroostctl doctor` checks the PC/SC service,
enumerates readers, tests FIDO HID node access, and verifies udev rules in one
pass. It is read-only and touches no key. Run it first if step 1 surprises you,
and paste its output rather than guessing which of the branches above applies.

## Step 2: Read serial and time (no auth required)

```bash
keyroostctl --debug molto info
```

**Expected stderr** (something like — the actual hex is device-dependent):

```
> get info (serial + time)  80 41 00 00 00
< get info (serial + time)  XX XX XX 08 41 42 43 44 45 46 47 48 XX XX 65 4F 12 34 90 00
```

…followed by the parsed output on stdout:

```
Serial:     ABCDEFGH
Device UTC: 1699999284 (epoch)
```

**Checks:**
1. The status word at the end of the response must be `90 00` (success).
2. The 4th byte (the length field) should be reasonable — typically `08`.
3. The UTC time on stdout should be roughly the device's clock (compare to a watch; close enough for a write-only device).

**If the parsed serial looks garbled or the time is nonsensical** the assumed response layout is wrong. Paste the full `--debug` line and the parsed output and we'll fix the offsets in `keyroost_proto::commands::parse_info` (`crates/keyroost-proto/src/commands.rs`) — `Session::read_info` in the transport only transmits and delegates to it.

## Step 3: Authenticate with the default customer key

Factory-fresh devices use `TOKEN2MOLTO1-KEY`. With no customer-key flag,
keyroost uses that factory default, so nothing needs to be passed:

```bash
keyroostctl --debug molto title set --slot 99 "MOLTO_TEST"
```

This will print a `>` / `<` pair on stderr for each of `get info`, `get challenge`, `answer challenge`, then `set title`, along with the serial, the device clock and "Authenticated.", and end with "Title set on slot #99." on stdout.

**Checks:**
1. `get challenge` response: 8 random bytes plus `90 00`.
2. `answer challenge` response: just `90 00` (no data).
3. `set title` response: just `90 00`.

**If `answer challenge` returns `63 CN`:** the customer key on your device isn't the factory default. The low nibble `N` is the number of tries left before the device locks. Try whatever key you set, from an environment variable: `--customer-key env:VAR` (hex), adding `--customer-key-encoding ascii` for a text key, e.g. `keyroostctl --debug molto --customer-key env:MOLTO_KEY --customer-key-encoding ascii title set --slot 99 "MOLTO_TEST"` after setting `MOLTO_KEY` in your own shell. The customer key is never taken on the command line. **Only if you've forgotten it** — and accepting that this is the most destructive command in this runbook — `keyroostctl molto reset` does **not** require the customer key (it's a plain CLA `0x80` command; it names the token and asks y/N first, or takes `--yes` in a script): it wipes **every one of the 100 slots** and resets the key back to `TOKEN2MOLTO1-KEY`. The device returns `SW 90 60` and displays a confirmation prompt — press the up-arrow on the device to commit the reset.

**If `set title` returns anything other than `90 00`:** capture the SW bytes. That's the most likely place for a MAC computation mismatch. The SW will be specific (e.g. `69 82` = security status not satisfied, `6A 80` = wrong data) and will tell us where to look.

## Step 4: Verify the title on-device

Press the button on the Molto2 to wake it up and cycle to slot #99. You
should see "MOLTO_TEST" as the title.

## Step 5: Write a known TOTP seed and verify the codes match

```bash
keyroostctl --debug molto import --slot 99 --title MOLTO_TEST
```

At the hidden `otpauth:// URI:` prompt, paste this throwaway test URI (it is
not shown as you type):

```
otpauth://totp/MoltoTest?secret=JBSWY3DPEHPK3PXPJBSWY3DP&algorithm=SHA1&digits=6&period=30
```

The URI holds the seed, so keyroost never takes it on the command line; a
script pipes it on stdin with `--uri stdin` or names an environment variable
with `--uri env:VAR`. This writes seed + title + config in one authenticated session. If slot #99
already holds a seed, keyroost asks y/N before overwriting it (a script adds
`--yes`).

> **Expected stderr here:** keyroost warns that you're programming a seed under
> the factory-default customer key, which is public, so anyone who captures the
> USB traffic can decrypt the seed. That's correct and expected during bring-up
> with a throwaway secret — it is a nudge, not a failure, and the write
> proceeds. Rotate the key with `keyroostctl molto customer-key change` before
> programming anything real. The same warning appears in step 6 (it fires for
> `seed set` and `import` (with or without `--in`), but not for step 3's `title set`).

To verify the device actually generates correct codes, paste the same URI into
any standard authenticator (Google Authenticator, Aegis, Bitwarden) and
compare. Within ±1 step (30 seconds) both should show the same 6 digits. If
they don't, the device's clock is off — fix with:

```bash
keyroostctl molto sync --slot 99
```

…and try again on the next 30-second boundary.

## Step 6: Bulk import smoke test

Drop a small plaintext Aegis or 2FAS export (1–3 entries) into `/tmp/test.json`
and:

```bash
keyroostctl --debug molto import --in /tmp/test.json --slot 95 --dry-run
```

`--dry-run` parses and prints the plan without writing. If that looks right,
drop `--dry-run` and let it write.

## Step 7: GUI smoke test

```bash
keyroost
```

keyroost scans for devices on its own. Select the Molto2 in the device list →
enter the customer key (or leave blank for the default) → click Authenticate →
select a slot → fill in a title and base32 secret → click Write to slot.

The log panel at the bottom should show green "ok" lines for each step.

## FIDO security-key bring-up

Separate from the Molto2 / TOTP path above, keyroost also speaks CTAP2 to FIDO2
security keys (HID transport, PIN protocol, credential management). This
runbook validates that layer against real hardware. Each step is read-only or,
where state-changing, clearly marked. Run it against a **disposable test key**,
not your daily-driver authenticator.

> **Reset to recover — FIDO only.** A FIDO2 factory reset returns the key to a
> fully functional fresh state; nothing in *this* runbook can brick the device —
> at worst you re-enter the commissioning PIN. That guarantee does not extend to
> the card applets: `keyroostctl factory-reset` also sweeps OATH, OpenPGP, PIV
> and Token2 OTP, and a *forced* PIV reset on a card with no vendor RESET
> instruction can leave the PIN and PUK blocked. keyroost refuses that case up
> front rather than blocking credentials it cannot then clear, but the card
> applets are not covered by the sentence above.

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

**Expected:** one line under "FIDO HID devices:" per inserted authenticator, in
the form `<path> <vid>:<pid> usage=f1d0:0001 <model> serial=… [FIDO]`. A
`serial=…(ccid)` suffix means the serial came from the card interface because
the key exposes none over USB; `name=…` appears once you've named the key with
`keyroostctl name set`. Below the raw sections, `list` prints a correlated
per-device summary built from the same snapshot, numbered. With multiple keys
plugged in you'll get one numbered line each; pick one with the global
`--device N` (that number, a serial, or a saved name). Without it, a terminal
shows a numbered list and a script is refused. `--path /dev/hidrawN` still
works as an override, but kernel hidraw numbers **change on each replug**, so
enumerate fresh.

### Step F2: GetInfo round-trips

```bash
keyroostctl fido info --device N
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
keyroostctl fido pin set --device N
```

It asks for the new PIN twice at a hidden prompt (nothing is shown as you type).

**Expected:** `PIN set.` Re-run `fido info`: `clientPin` should now be
`true`. `fido pin status` should still show the full attempt counter —
the initial set doesn't consume a retry.

### Step F4: PIN-protected read paths

```bash
keyroostctl fido credential status --device N     # asks for the PIN (hidden)
keyroostctl fido credential list --device N
```

**Expected on a fresh key:** `0 resident credential(s) stored, room for N
more`, and `(no resident credentials)`. The point isn't the (empty)
contents — it's that the `pinUvAuthToken` exchange (`clientPin` 0x09 with
`cm` permission) succeeded. A correct PIN must **not** decrement the retry
counter; verify with `fido pin status` afterwards.

### Step F5: Resident-credential round-trip (create → list → delete)

Plant a discoverable credential using `ssh-keygen` as the simplest external
RP, then exercise `fido credential list` and `fido credential delete`:

```bash
# Create — needs PIN entry + a physical touch when the key blinks.
ssh-keygen -t ecdsa-sk -O resident -O application=ssh:moltotest \
           -N '' -f /tmp/sk_moltotest

# Read back — confirm it appears, copy the FULL id= value.
keyroostctl fido credential list --device N

# Destructive: delete by full credentialId. Asks y/N, then for the PIN.
keyroostctl fido credential delete --device N <full hex from id=>

# Confirm empty.
keyroostctl fido credential list --device N
```

The `id=` line is the value you copy — the `cred …` summary above it is
truncated for readability and is **not** a valid credential ID.

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
