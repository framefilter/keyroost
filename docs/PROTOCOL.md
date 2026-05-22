# Token2 Molto2 / Molto2v2 wire protocol

This document describes the wire protocol the Molto2 device speaks, as observed
from the running hardware. It is provided so that contributors can work on
MoltoUI without reading any third-party source code. All facts here describe
behaviour of the Token2 device itself; none of it is copyrighted by anyone.

> **Status:** the algorithm and APDU layouts below are confirmed by byte-for-byte
> agreement between MoltoUI's protocol layer and an independent third-party SM4
> implementation (`gmssl`). Hardware confirmation is still pending for response
> layouts (notably `get info`).

## Transport

- **Class:** USB CCID smart card (ISO 7816-4 APDUs over PC/SC).
- **Vendor ID:** `0x349E`
- **Product ID:** `0x0300`
- **Reader name hint:** "TOKEN2" (case-insensitive substring match works)
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
4. On success the device returns `SW=9000`. On failure it returns `SW=63 NN`
   where `NN` is the number of attempts remaining before the device locks.

## Per-command MAC (secure commands)

For every CLA `0x84` command the last 4 bytes of `Lc` are a MAC computed as
follows:

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
| `0x4B` | `08` | `00` | — (Le=`00`) | 8-byte challenge | Start auth handshake |
| `0xCE` | `00` | `00` | 16-byte SM4(challenge \|\| zeros) | — | Finish auth handshake |
| `0x56` | `00` | `00` | — (Le=`00`) | — (sw=9000) | Factory reset (physical confirm) |

#### `0x41` get info response layout

```
offset  length  field
0       3       (unknown / device-specific header)
3       1       serial-string length N (typically 8)
4       N       serial number, ASCII
4+N     2       (unknown / separator)
6+N     4       UTC time as a big-endian u32 (unix epoch seconds)
```

The first 3 and the 2-byte separator are not yet confirmed to be constant; the
parser tolerates both because Token2's reference does the same.

### Secure commands (CLA `0x84`, MAC required)

| INS | P1 | P2 | Encrypted body | Purpose |
|---|---|---|---|---|
| `0xC5` | `01` | profile (0..99) | SM4-ECB(seed, padded) | Write a profile seed |
| `0xD5` | `00` | profile | SM4-ECB(title-bytes, padded to 16) | Write a profile title (≤12 bytes) |
| `0xD4` | `01` | profile | plaintext TLV (see below) | Write profile config / sync time |
| `0xD7` | `00` | `00` | SM4-ECB(`00 \|\| sha1(new_key)[..16] \|\| 0x80 \|\| 14×00`) | Rotate customer key (physical confirm) |

Seed payloads accept 1..=63 raw bytes; the host pads with `0x80` then zeros to
a 16-byte boundary before SM4 encryption.

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
| `63 NN` | Auth failed; `NN` is attempts remaining before lock |
| other `6xxx` / `9xxx` | Command-specific failure |

`9060` is not an error: the device has accepted the request and is waiting for
the user to press the up-arrow button to commit. Both `factory_reset` and
`set_customer_key` return it. Observed on real hardware during bring-up.

MoltoUI surfaces auth failures specifically (`TransportError::AuthFailed`) so
they can be retried; everything else becomes `TransportError::Apdu { sw1, sw2 }`.

## Known unknowns

1. **Slot read-back.** No `0x80` plain command is known to return a profile's
   seed or settings. The customer-key-protected read APDU (if it exists) hasn't
   been confirmed. Until we have hardware traces from Token2's Windows tool,
   MoltoUI treats slots as write-only and tracks state in a local sidecar.
2. **Screen lock / unlock.** Token2's reference Python script attempts these
   via `INS 0xD8 P1=0x0C P2=0x02`, but the unlock case there is mis-framed and
   probably doesn't work as written. Skipped until verified.
3. **`get info` magic offsets.** The 3-byte preamble and 2-byte separator
   inside the response are taken on faith from the reference. They could be
   serial-number metadata or device class identifiers; their exact meaning
   doesn't affect the parser.
4. **HOTP.** The Molto2 marketing material mentions HOTP; we have no APDU set
   for it and no UI for it.

Contributions adding hardware traces / probing results are welcome — see the
`moltoctl probe` work item in the README roadmap.
