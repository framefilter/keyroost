# Token2 Molto2 / Molto2v2 wire protocol

This document describes the wire protocol the Molto2 device speaks, as observed
from the running hardware. It is provided so that contributors can work on
keyroost without reading any third-party source code. All facts here describe
behaviour of the Token2 device itself; none of it is copyrighted by anyone.

> **Status:** the algorithm and APDU layouts below are confirmed by byte-for-byte
> agreement between keyroost's protocol layer and an independent third-party SM4
> implementation (`gmssl`), and the command set has been exercised against real
> hardware (see `docs/BRINGUP.md`). The per-profile public block envelope is
> hardware-captured. Still unconfirmed: the **`get info` response layout** — no
> captured trace of it is committed to this repository, so the field boundaries
> below are the parser's working assumption rather than an observed fact — and
> the *meaning* of the opaque fields (`get info`'s 3-byte header and 2-byte
> separator, and the two u32 time fields in the public block).

## Transport

- **Class:** USB CCID smart card (ISO 7816-4 APDUs over PC/SC).
- **Vendor ID:** `0x349E` (shared across all of Token2's products — the Molto2
  *and* the PIN+/FIDO2+ FIDO keys — so VID alone does not identify a Molto2)
- **Product ID:** `0x0300` (Molto2 / Molto2v2) — confirmed by Token2 (issue #25)
  as always and only the Molto2. There is no single "FIDO PID": Token2's FIDO
  line uses many PIDs under the same VID — `0x0010`–`0x0016` (PIN+ Mini),
  `0x0020`–`0x0026` (PIN+ Series / FIDO2 Security Key) and `0x0200`–`0x0206`
  (Bio3 Dual). `0x0430` is the MFA NFC reader, not a FIDO key. Classify with
  `keyroost_proto::token2_product` / `is_molto2_usb` rather than testing against
  any one PID; a Token2 PID that isn't in that table means "not provably a
  Molto2", not "FIDO".
- **Reader name:** the Molto2 reader carries the product name, e.g.
  `TOKEN2 Molto2 [CCID Interface] 00 00`. Matching on the brand "TOKEN2" is
  **too broad** — Token2's FIDO keys (FIDO2+, PIN+, PIN+R3, …) also brand as
  "TOKEN2" and expose a CCID reader (e.g. `Token2 PIN+R3 00 00`,
  `TOKEN2 FIDO2 Security Key 00 00`), so any brand-level match mis-flags them
  as a Molto2 (issue #21). The only reliable signal is the product word: use
  `keyroost_proto::is_molto2_reader`, which matches the product word
  (**`molto`**, case-insensitive) and nothing else — every other Token2 device
  is a FIDO key or the NFC reader.
- On Linux the device requires an entry in libccid's `Info.plist` so that
  pcscd picks it up; recent libccid versions ship that entry pre-configured.

## Cryptographic primitives

| Primitive | Purpose |
|---|---|
| **SM4** (GB/T 32907-2016, 128-bit block, 128-bit key, 32 rounds) | Encrypts seeds, titles, and the auth response; provides the per-command MAC |
| **SHA-1** (RFC 3174) | Derives the SM4 key from the customer key |
| **base32** (RFC 4648) | Encodes TOTP secrets (otpauth:// compatibility); the wire format is raw bytes |

The device's SM4 key is derived as `SHA1(customer_key)[..16]`. The default
customer key on a factory-fresh device is the 16-byte ASCII string
`TOKEN2MOLTO1-KEY`, which derives the SM4 key
`09 92 50 fd b0 17 f4 42 da 42 9e cb be e1 7f 79`.

## Authentication handshake

Required before any "secure" command (CLA `0x84`).

1. Host sends `80 4B 08 00 00` (read 8 bytes challenge).
2. Device responds with 8 random bytes + `SW=9000`.
3. Host zero-pads the challenge to 16 bytes, SM4-encrypts it in-place with the
   derived key, and sends `80 CE 00 00 10 <16-byte ciphertext>`.
4. On success the device returns `SW=9000`. On failure it returns `SW=63 Cx`
   (ISO-7816 retry-counter form) where the low nibble `x` is the number of
   attempts remaining before the device locks — hardware-verified: a wrong key
   returns e.g. `63 C7` with 7 tries left, not a raw count in the whole byte.
   A successful auth resets the counter.

## Per-command MAC (secure commands)

For every CLA `0x84` command the last 4 bytes of the payload are a MAC computed
as follows (`Lc` itself is a one-byte length field covering encrypted body +
MAC):

1. Build the MAC input: `[CLA=0x80, INS, P1, P2, Lc'] || payload` where `Lc'`
   is the **payload** length (not the final `Lc` including the MAC), and
   `payload` is the encrypted body.
2. ISO/IEC 9797-1 padding method 2 ("0x80 then zeros to a 16-byte boundary"),
   but **only if the input isn't already block-aligned**. If it is, no padding
   block is appended.
3. SM4-CBC encrypt the result with IV = 16 zero bytes.
4. The MAC is the first 4 bytes of the last ciphertext block.

Note that step 1 uses `0x80` (the *plain* class byte) in the MAC header even
though the final transmitted APDU uses `0x84`. This appears to be a quirk of
the device's check routine.

## Command catalog

In the tables below "Lc" is the length of the entire payload (encrypted body
+ MAC). All multi-byte numbers are big-endian unless noted.

### Plain commands (CLA `0x80`, no auth, no MAC)

| INS | P1 | P2 | Payload | Returns | Description |
|---|---|---|---|---|---|
| `0x41` | `00` | `00` | — (Le=`00`) | Device info | Serial + system time |
| `0x41` | `00` | profile (0..99) | `70` (Lc=`01`) | Per-profile public block | Title + occupancy + TOTP config |
| `0xE6` | `00` | profile (0..99) | — (Le=`00`) | — (sw=`9000`/`6A83`) | Delete one profile's seed (keyless) |
| `0x4B` | `08` | `00` | — (Le=`00`) | 8-byte challenge | Start auth handshake |
| `0xCE` | `00` | `00` | 16-byte SM4(challenge \|\| zeros) | — | Finish auth handshake |
| `0x56` | `00` | `00` | — (Le=`00`) | — (sw=`9060`, then `9000` once the button is pressed) | Factory reset (physical confirm) |

#### `0x41` get info response layout

```
offset  length  field
0       3       (unknown / device-specific header)
3       1       serial-string length N (typically 8)
4       N       serial number, ASCII
4+N     2       (unknown / separator)
6+N     4       UTC time as a big-endian u32 (unix epoch seconds)
```

The first 3 bytes and the 2-byte separator are not yet confirmed to be constant;
the parser carries them through uninterpreted and bounds-checks every offset it
derives from `data[3]`, so a truncated or hostile response errors cleanly rather
than panicking.

#### `0x41` per-profile public block (P2 = profile)

`80 41 00 <profile> 01 70` — the same INS as get-info, but P2 selects a
profile and the body is the single byte `0x70`. **Case-3 only:** appending
an Le byte is rejected with `6F FB`. The response is a TLV followed by the
status word:

```
95 1F
   70 1D
      offset  length  field
      0       1       flag (observed 0x20 on a written slot)
      1       16      title, PLAINTEXT, zero-padded
      17      4       time field A (u32 BE; semantics unconfirmed)
      21      4       time field B (u32 BE; semantics unconfirmed)
      25      1       OTP algorithm (1=SHA1, 2=SHA256 — same coding as the config TLV)
      26      1       time step in seconds (0x1E = 30)
      27      1       digit count (e.g. 0x06)
      28      1       seed present (00/01)
```

**No authentication is required**, and the title comes back in the clear:
the device decrypts the `set_title` ciphertext on receipt and stores
plaintext (verified live — a title written encrypted read back verbatim).
Anyone with card access can read every slot's title and occupancy without
the customer key. Don't put secrets in titles.

Empty slots may report **default config values** (SHA1 / 30s step / 6 digits
observed on hardware), not all-zero — only byte 28 (seed present) reliably
indicates occupancy. Don't infer "empty" from the algorithm/step/digit bytes.

#### `0xE6` delete profile seed (keyless)

`80 E6 00 <profile> 00` — deletes one profile's seed. Hardware-verified
(the vendor tooling happens to send it after authenticating, but auth is
NOT a precondition — reproduced twice with no auth at all):

- `90 00` on a populated slot; `6A 83` (referenced data not found) on an
  already-empty one.
- The stored title survives the delete — title and seed have independent
  lifecycles. There is no title-delete command short of a factory reset.
- **Security note:** any party with card access can wipe any profile's
  seed without the customer key. That is device behavior, documented here
  so users can weigh it; keyroost gates the operation behind explicit
  confirmation in both UIs.

### Secure commands (CLA `0x84`, MAC required)

| INS | P1 | P2 | Encrypted body | Purpose |
|---|---|---|---|---|
| `0xC5` | `01` | profile (0..99) | SM4-ECB(seed, padded) | Write a profile seed |
| `0xD5` | `00` | profile | SM4-ECB(title-bytes, padded to 16) | Write a profile title (≤12 bytes) |
| `0xD4` | `01` | profile | plaintext TLV (see below) | Write profile config / sync time |
| `0xD7` | `00` | `00` | SM4-ECB(`00 \|\| sha1(new_key)[..16] \|\| 0x80 \|\| 14×00`) | Rotate customer key (physical confirm) |

Seed payloads accept 1..=63 raw bytes. Before SM4 encryption the host pads
them to a 16-byte boundary with `0x80` then zeros. A seed that is already a
multiple of 16 bytes is sent without padding.

Title payloads accept 1..=12 UTF-8 bytes; the host applies the same padding so
the encrypted body is always exactly 16 bytes.

### Config TLV (`INS 0xD4 P1=0x01`)

The body of the config command is a plaintext TLV (not encrypted) followed by
the 4-byte MAC. The outer TLV is:

```
81 14
   1F 01 <display_timeout: 0=15s, 1=30s, 2=60s, 3=120s>
   0F 04 <UTC time u32 BE>
   86 09
      0A 01 <hmac_algo: 1=SHA1, 2=SHA256>
      0B 01 <digits: 04, 06, 08, or 0A>
      0D 01 <time_step: 0x1E for 30s, 0x3C for 60s>
```

The sync-time slim variant uses just:

```
81 06
   0F 04 <UTC time u32 BE>
```

with the same `D4 01 <profile>` header.

## Status words

| SW | Meaning |
|---|---|
| `9000` | Success — command completed |
| `9060` | Success — command queued, awaiting on-device button confirmation (factory reset, set customer key) |
| `63 Cx` | Auth failed; low nibble `x` is attempts remaining before lock (ISO-7816 retry counter) |
| `6A83` | Referenced data not found (e.g. `0xE6` on a slot with no seed) |
| `61 XX` | `XX` more response bytes pending — issue `GET RESPONSE` (T=0 readers; shared applet paths only, never the Molto2 protocol) |
| `6C XX` | Wrong `Le` — reissue the *same* command with `Le = XX` (T=0 readers; shared applet paths only) |
| other `6xxx` / `9xxx` | Command-specific failure |

`9060` is not an error: the device has accepted the request and is waiting for
the user to press the up-arrow button to commit. Both `factory_reset` and
`set_customer_key` return it. Observed on real hardware during bring-up.

keyroost surfaces auth failures specifically (`TransportError::AuthFailed`) so
they can be retried; everything else becomes `TransportError::Apdu { label, sw1, sw2 }`.

### Response continuation (`61xx` / `6Cxx`)

The Molto2 protocol itself is single-exchange: the session's `transmit` sends one
APDU and treats any status word other than `9000` / `9060` as terminal. No Molto2
command returns more data than fits in one response, so no `GET RESPONSE` loop is
needed and none is implemented on this path — a `61xx` here would surface as an
error, not as a continuation.

The **shared smart-card applet paths** (OATH, OpenPGP, PIV over PC/SC) do
reassemble, because they run over readers whose T=0 handling differs:

- `61 XX` — chunk accepted; send `GET RESPONSE` asking for exactly the `XX` bytes
  the card says are pending (`XX == 0` meaning 256, the short-form convention)
  and accumulate. Asking blindly for 256 is what makes a card that validates `Le`
  answer `6Cxx` mid-read.
- `6C XX` — the card returned **no data** and wants the command *currently in
  flight* reissued with `Le = XX`. Whatever has already been accumulated is kept.

Whether a host ever sees `6C XX` is reader-dependent, not card-dependent: readers
that absorb the `Le` correction in firmware (the Token2 dual-interface reader)
never surface it, while readers that pass the raw card response through (Alcor,
SCM, Realtek, …) do — which is why an OpenPGP read after a factory reset failed
with `SW=6CFF` on some hosts and not others (issue #84).

Both loops are bounded — 1 MiB accumulated and 4096 chunks
(`MAX_REASSEMBLED_RESPONSE` / `MAX_RESPONSE_CHUNKS`) — so a card that answers
`6Cxx` forever terminates.

## Known unknowns

1. **Seed read-back.** The per-profile public block (`0x41` with
   P2 = profile) returns each slot's title, occupancy, and TOTP config —
   but no command is known to return a profile's *seed*, and the two
   4-byte time fields' semantics are unconfirmed. Seeds remain write-only.
2. **Screen lock / unlock.** Token2's reference Python script attempts these
   via `INS 0xD8 P1=0x0C P2=0x02`, but the unlock case there is mis-framed and
   probably doesn't work as written. Skipped until verified.
3. **`get info` magic offsets.** The 3-byte preamble and 2-byte separator
   inside the response are taken on faith from the reference. They could be
   serial-number metadata or device class identifiers; their exact meaning
   doesn't affect the parser.
4. **HOTP.** The Molto2 marketing material mentions HOTP; we have no APDU set
   for it and no UI for it.

Contributions adding hardware traces / probing results are welcome — the hidden
`keyroostctl molto probe` subcommand sweeps the plain class (CLA `0x80`), and
with `--authed` the secure class too, classifying each status word. It skips the
INS bytes known to mutate the device (`0xC5`, `0xD5`, `0xD4`, `0xD7`, `0xCE`,
`0x56`, `0xD8`, `0xE6`) unless `--include-destructive` is passed, and requires
`--yes`. The plain sweep always sends P2=`00`; `--slot` sets the P2 profile
index (default 99) for the `--authed` scans only.
