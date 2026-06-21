# Token2 single-profile programmable TOTP token wire protocol

This document describes the wire protocol the Token2 **2nd-generation
single-profile programmable TOTP token** speaks (internally "OTPC P2"), as
implemented by `keyroost-token2prog` and observed against the vendor's reference
configurator.

> The crypto path (SM4 block encryption and the SM4-CBC MAC) is covered by unit
> tests whose expected values were produced by an independent third-party SM4
> implementation, itself validated against the GM/T 0002 SM4 known-answer test.

It is a close relative of the [Molto2 protocol](PROTOCOL.md): the same NFC
Type-4 / ISO 7816 transport, the same SM4 cipher, and the same ISO/IEC 9797-1
MAC. The differences are called out explicitly below.

## Transport

- **Form factor:** a card-style NFC token, read over a contactless or
  contact-capable PC/SC reader. There is no USB-HID interface.
- **Reader:** any connected PC/SC reader; the token is addressed directly, with
  **no applet SELECT** (the same posture as the Molto2 path and the vendor
  reference tool).
- **APDUs:** short ISO 7816 case-3 (command + data) and case-2 (expecting a
  response). Over T=0 contact readers, responses are reassembled through the
  standard `61 XX` / `GET RESPONSE` continuation; `6C XX` triggers a re-issue
  with the corrected `Le`.

## Cryptographic primitives

| Primitive | Purpose |
|---|---|
| **SM4** (GB/T 32907-2016, 128-bit block, 128-bit key, 32 rounds) | Encrypts the seed and the auth response; provides the per-command MAC |
| **base32** (RFC 4648) | Encodes TOTP secrets for entry; the wire format is raw bytes |

Unlike the Molto2 — which derives its SM4 key from a customer key via
`SHA1(customer_key)[..16]` — this token uses a **single fixed device key**:

```
8A D2 06 88 3C A3 69 48 2A B2 71 82 B6 E8 32 24
```

There is no per-device secret and no customer key to supply. The key is embedded
in `keyroost_token2prog::DEVICE_SM4_KEY`.

## Authentication handshake

Required before either secure command (CLA `0x84`).

1. Host sends `80 4B 08 00 01 00` (request the challenge).
2. Device responds with 8 bytes + `SW=9000`.
3. Host "inflates" the challenge to 16 bytes by appending **eight zero bytes**,
   SM4-encrypts that block with the device key, and sends
   `80 CE 00 00 10 <16-byte ciphertext>`.
4. On success the device returns `SW=9000`. If the device key is locked it
   returns `SW=6983`.

## Per-command MAC (secure commands)

For every CLA `0x84` command, the last 4 bytes of the payload are a MAC computed
exactly as on the Molto2:

1. Build the MAC input: `[CLA=0x80, INS, P1, P2, Lc'] || payload`, where `Lc'`
   is the **encrypted-payload** length (not the final `Lc` including the MAC).
2. ISO/IEC 9797-1 padding method 2 (`0x80` then zeros to a 16-byte boundary),
   only if the input isn't already block-aligned.
3. SM4-CBC encrypt with IV = 16 zero bytes.
4. The MAC is the first 4 bytes of the last ciphertext block.

As on the Molto2, the MAC header in step 1 uses the **plain** class `0x80` even
though the transmitted APDU uses `0x84`.

## Command catalog

In the tables below "Lc" is the length of the entire payload (encrypted body +
MAC). All multi-byte numbers are big-endian unless noted. There is no profile
selector — every command targets the single slot.

### Plain commands (CLA `0x80`, no auth, no MAC)

| INS | P1 | P2 | Payload | Returns | Description |
|---|---|---|---|---|---|
| `0x41` | `00` | `00` | `02 11` | Device info | Serial + system time |
| `0x4B` | `08` | `00` | `00` | 8-byte challenge | Start auth handshake |
| `0xCE` | `00` | `00` | 16-byte SM4(challenge \|\| 8 zeros) | — (sw=9000 / 6983) | Finish auth handshake |

> **Difference from Molto2:** the info request carries a two-byte body `02 11`
> rather than a bare `Le`, and the challenge request carries a one-byte body
> `00`.

#### `0x41` get info response layout

```
offset  length  field
0       3       (unknown / device-specific header)
3       1       serial-string length N
4       N       serial number, ASCII
4+N     2       (unknown / separator)
6+N     4       UTC time as a big-endian u32 (unix epoch seconds)
```

The leading 3 bytes and the 2-byte separator are not confirmed constant; the
parser reads `N` from offset 3 and tolerates the surrounding bytes, mirroring the
vendor reference.

#### Model identification from the serial

The printed serial begins with a product-specific digit prefix. The known
mapping (`keyroost_token2prog::model_for_serial`, matched longest-prefix-first):

| Serial prefix | Model |
|---|---|
| `8659612` | OTPC-P1-i |
| `8659622` | OTPC-P2-i |
| `8659621` | OTPC-P2-i-NB |
| `8659600` | miniOTP-2-i |
| `8659601` | miniOTP-3-i |
| `8659609` | miniOTP-3-i-NB |
| `8659610` | C301-i |
| `8659632` | C302-i |

An unrecognized prefix resolves to no model; callers fall back to displaying the
raw serial.

### Secure commands (CLA `0x84`, MAC required)

| INS | P1 | P2 | Encrypted body | Purpose |
|---|---|---|---|---|
| `0xC5` | `01` | `00` | SM4-ECB(seed, padded) | Write the OTP seed |
| `0xD4` | `00` | `00` | plaintext TLV (see below) | Write configuration / sync time |

#### Seed (`INS 0xC5 P1=0x01`)

The seed is 1..=63 raw bytes. Two on-wire forms exist:

- **General form.** ISO/IEC 9797-1 minimal padding (`0x80` then zeros to a
  16-byte boundary), SM4-ECB encrypted. A 20-byte seed therefore yields a
  32-byte ciphertext; with the 4-byte MAC, `Lc = 0x24`.
- **32-byte form.** A 32-byte seed is given an **extra full pad block** — `0x80`
  followed by fifteen `0x00` — before encryption, yielding a 48-byte
  ciphertext; with the MAC, `Lc = 0x34`. This reflects the device's
  longer-seed framing in the vendor tool.

In both cases the transmitted APDU is `84 C5 01 00 <Lc> <ciphertext> <MAC>`,
while the MAC header is `80 C5 01 00 <ciphertext-length>`.

#### Config TLV (`INS 0xD4 P1=0x00`)

The body is a 19-byte plaintext TLV (not encrypted) followed by the 4-byte MAC:

```
81 11
   1F 01 <display_timeout: 0=15s, 1=30s, 2=60s, 3=120s>
   0F 04 <UTC time u32 BE>
   86 06
      0A 01 <hmac_algo: 1=SHA1, 2=SHA256>
      0D 01 <time_step: 0x1E for 30s, 0x3C for 60s>
```

> **Difference from Molto2:** the outer length is `0x11` (17) rather than `0x14`
> (20), and the inner `TOTP_PARAM` block is `0x06` (6) bytes with **no digits
> field** (`0B 01 <digits>`) — this single-profile token does not expose a
> configurable digit count here. The header is `D4 00 00` (no profile byte)
> rather than `D4 01 <profile>`.

The high two bits of the time-step byte flag seconds (`b00`) vs minutes
(`b01`); only the seconds forms `0x1E` (30s) and `0x3C` (60s) are used.

> **Seed/clock dependency:** writing a new configuration resets the seed on
> tokens with restricted time-sync; tokens with unrestricted sync keep it. When
> changing any configuration value, supply them all (the device expects the full
> TLV).

## Status words

| SW | Meaning |
|---|---|
| `9000` | Success |
| `6983` | Authentication failed — the device key is locked |
| `61 XX` | `XX` more response bytes available (issue `GET RESPONSE`; T=0 readers) |
| `6C XX` | Wrong `Le`; re-issue the command with `Le = XX` (T=0 readers) |
| `6700` | Wrong length — sent if an extended-length `Lc` is used where short-form is required |

## Known unknowns

- The 3-byte header and 2-byte separator inside the `get info` response are
  carried through but not interpreted.
- The exact set of `display_timeout` values the firmware accepts beyond the four
  documented here is not independently confirmed.
- A factory-reset / key-rotation command (present on the Molto2 as `0x56` /
  `0xD7`) has not been observed for this token and is not implemented.
