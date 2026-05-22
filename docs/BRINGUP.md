# Hardware bring-up plan for a real Molto2 / Molto2v2

This document is for the first time you connect a real Molto2 to MoltoUI. The
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

The `moltoctl` binary will be at `target/release/moltoctl`. Either copy it
onto your `$PATH` or invoke it from there.

## Step 1: PC/SC sees the device

Plug the Molto2 in, then:

```bash
moltoctl --list-readers
```

**Expected:** one line containing "TOKEN2" (case may vary, e.g. `TOKEN2 Molto2 [CCID Interface] 00 00`).

**If it fails:**
- *"PC/SC service is unavailable"* — start the service (`sudo systemctl start pcscd` on Linux). On macOS this shouldn't happen.
- *No reader matching "TOKEN2"* but other readers shown — paste the full output. We can widen the matcher.
- *Empty list* — confirm with `pcsc_scan` (Linux) that PC/SC sees any reader at all. If not, it's a system-level USB / udev problem, not a MoltoUI one.

## Step 2: Read serial and time (no auth required)

```bash
moltoctl --debug info
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

**If the parsed serial looks garbled or the time is nonsensical** the response layout in `read_info()` is wrong. Paste the full `--debug` line and the parsed output and we'll fix the offsets in `crates/molto2-transport/src/lib.rs`.

## Step 3: Authenticate with the default customer key

Factory-fresh devices use `TOKEN2MOLTO1-KEY`.

```bash
moltoctl --debug --key-ascii TOKEN2MOLTO1-KEY set-title --profile 99 "MOLTO_TEST"
```

This will print four `>` / `<` lines on stderr — `get info`, `get challenge`, `answer challenge`, then `set title` — and end with "title set on profile #99".

**Checks:**
1. `get challenge` response: 8 random bytes plus `90 00`.
2. `answer challenge` response: just `90 00` (no data).
3. `set title` response: just `90 00`.

**If `answer challenge` returns `63 NN`:** the customer key on your device isn't the factory default. Try whatever key you set, via `--key-ascii` (text) or `--key` (hex). If you've forgotten it: `moltoctl factory-reset --yes` does **not** require the customer key (it's a plain CLA `0x80` command); it will wipe every profile and reset the key back to `TOKEN2MOLTO1-KEY`. The device will return `SW 90 60` and display a confirmation prompt — press the up-arrow on the device to commit the reset.

**If `set title` returns anything other than `90 00`:** capture the SW bytes. That's the most likely place for a MAC computation mismatch. The SW will be specific (e.g. `69 82` = security status not satisfied, `6A 80` = wrong data) and will tell us where to look.

## Step 4: Verify the title on-device

Press the button on the Molto2 to wake it up and cycle to profile #99. You
should see "MOLTO_TEST" as the title.

## Step 5: Write a known TOTP seed and verify the codes match

```bash
moltoctl --debug --key-ascii TOKEN2MOLTO1-KEY \
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
moltoctl --key-ascii TOKEN2MOLTO1-KEY sync-time --profile 99
```

…and try again on the next 30-second boundary.

## Step 6: Bulk import smoke test

Drop a small plaintext Aegis or 2FAS export (1–3 entries) into `/tmp/test.json`
and:

```bash
moltoctl --debug --key-ascii TOKEN2MOLTO1-KEY \
  import-file /tmp/test.json --start 95 --dry-run
```

`--dry-run` parses and prints the plan without writing. If that looks right,
drop `--dry-run` and let it write.

## Step 7: GUI smoke test

```bash
moltoui
```

Click Connect → confirm device info appears in the top bar → enter the
customer key (or leave blank for the default) → click Authenticate → select a
slot → fill in a title and base32 secret → click Write profile.

The log panel at the bottom should show green "ok" lines for each step.

## What to send back if anything goes wrong

Either email me, paste in the chat, or open an issue with:

1. The exact command you ran
2. **All of the `--debug` output** (this is the key piece — the hex tells us
   everything about where the mismatch is)
3. Anything visible on the device's screen at the time
4. OS and `cargo --version`

With that we can almost always fix the issue in one round trip.
