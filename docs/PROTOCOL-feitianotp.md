# Feitian OTP applet wire protocol

This document describes the protocol of the OTP (TOTP/HOTP) applet on Feitian
FIDO security keys, as implemented by `keyroost-feitianotp`.

It is a smart-card applet like the Yubico/Trussed OATH applet (`oath` group),
and its commands have the same general shape, but it is a different protocol:
its own AID, instruction bytes and tags, three slots, and no field for a TOTP
period.

## How each statement here is known

Every fact below is marked with where it comes from:

- **Measured**: seen in an exchange with a physical key.
  - *Key A*: USB `096E:086A`, OTP applet 1.0.1. Read with Libre Key Companion
    (Android, USB CCID), and with `keyroostctl` over PC/SC on Windows
    (`feitian info`, `list`, `add`, `code` and `delete`; not `reset`).
  - *Key B*: Feitian ePass FIDO-NFC, USB `096E:0853`, OTP applet 1.0.2. Read
    with Libre Key Companion (Android, USB CCID), over direct CCID, and with
    `keyroostctl` over PC/SC on Windows (every `feitian` command). Two keys
    of this model were read. Apart from the value under tag `51` they
    answered alike in what both were asked: SELECT and LIST over PC/SC and
    over FIDO HID, and the wait for a touch. Which of the two an exchange
    was made with was not always noted.
- **Client**: what Feitian's own client applications send or expect. Not yet
  exercised on hardware by this project.

Codes were checked against references computed independently from the
published RFC 4226 and RFC 6238 test seeds, written to the keys for the
purpose.

## Transport

- **Interface:** the key's smart-card interface: CCID over USB, or NFC. The
  applet is selected by AID. *(Measured.)*
- **APDUs:** short ISO 7816. Both keys answer over T=1. *(Measured.)*
- **FIDO HID:** the same APDUs also go through the key's FIDO HID interface,
  each one as it is in a `CTAPHID_MSG`. Feitian's client uses that when there
  is no CCID reader, and so does `keyroost`, for a key with no reader on this
  computer or one whose reader can't be opened. *(Measured, Key A and Key B:
  SELECT, LIST, PUT, CALCULATE and DELETE, with the same answers as over
  PC/SC.)*
  - Short APDUs only: the SELECT in extended-length form is answered `6700`.
    *(Measured.)*
  - A `CTAPHID_MSG` reaches whichever applet was selected last. With this
    applet selected, U2F's VERSION is answered `6D00`; after a SELECT of the
    FIDO applet (`A0 00 00 06 47 2F 00 01`) it answers `U2F_V2` again. So
    `keyroost` selects the FIDO applet again when it is done. *(Measured.)*
  - A command that waits for a touch is answered `6984` only once the key
    has waited for it (see CALCULATE), with nothing sent meanwhile. CTAP's
    usual read timeout runs out first, so an exchange is given longer.
    *(Measured.)* Feitian's client reads for up to 30 seconds per exchange
    there. *(Client.)*
  - Windows lets only an administrator open this interface.
- **Windows:** Key B's card can stay unresponsive after plug-in. The reader's
  cold reset fails, and connecting answers `SCARD_W_UNRESPONSIVE_CARD`, or
  `SCARD_E_PROTO_MISMATCH` about ten seconds after a warm reset. This is the
  whole card, not this applet: OpenPGP and PIV on the key go undetected too. A
  warm reset over a direct connection (`IOCTL_SMARTCARD_POWER` with
  `SCARD_WARM_RESET`) brings the card up, and `keyroost` does that once, for a
  Feitian reader, before it gives up. *(Measured on one PC, Windows 11 with the
  inbox CCID driver: no applet detected without the retry, all three with it.
  Key A connected without it there. Reported on other PCs. Why the cold reset
  fails is not established.)*

## Selecting the applet

```
00 A4 04 00 09  D1 56 00 01 32 83 26 01 01
```

The AID starts with Feitian's registered RID, `D1 56 00 01 32`. There is no
`Le` byte. *(Measured, both keys.)*

The answer is a flat run of TLVs with one-byte lengths:

| Tag | Length | Meaning |
|---|---|---|
| `59` | 3 | Applet version: `01 00 02` is 1.0.2. *(Measured.)* |
| `51` | 8 | A value Feitian's client calls the challenge and uses as the salt of a slot's access-code key. *(Length measured; use is Client.)* |
| `7B` | 1 | One bit per slot that has an access code: bit 0 slot 1, bit 1 slot 2, bit 2 the default slot. Both keys answer `00`. *(Value measured; bit layout is Client.)* |

Each key answers its own `51` value, and none was seen to change it. Key A
answered the same value when it was first read and when it was read again on
2026-11-19 and on 2026-11-22. The two keys of Key B's model answer different
values from each other: one answered its value on 2026-11-18 and on
2026-11-22, the other on 2026-11-19 and on 2026-11-22, across repeated
SELECTs and card resets and, on that second key, a RESET of the applet.
*(Measured.)*

These keys do not host the Yubico OATH applet. A SELECT of its AID
(`A0 00 00 05 27 21 01`) is answered `6700` by Key A and `6D00` by Key B, not
`6A82`. *(Measured.)*

## The key's serial

```
80 E3 03 00 00
```

This is not a command of the OTP applet. The key answers it whichever
application is selected: nothing selected after a reset, and this applet, PIV
and OpenPGP selected, all gave the same answer. *(Measured, one Key B,
2026-11-22.)* It is the command Feitian's client reads the serial it shows
with. *(Client.)*

The answer is the serial in ASCII, padded with zero bytes: twelve bytes, nine
digits and three zeros. *(Measured, one Key B.)* keyroost takes an answer of
that shape, six or more letters or digits and then only zeros, as the key's
serial, and nothing else. Feitian's client also reads an answer of exactly
eight bytes as a binary serial; no key was seen to answer that way.
*(Client.)*

The key's OpenPGP application has a serial field of its own, in its AID:
`00 00 00 01` on the measured key. Feitian's client selects that application
by an AID with those four bytes in it, so the field does not tell one key
from another. *(AID measured, one Key B; the AID the client selects by is
Client.)* keyroost used to show that field as the serial of a Feitian key
with OpenPGP, and showed none for one without.

## Slots

Every command after SELECT names a slot in P2.

| P2 | Slot | |
|---|---|---|
| `F0` | default | Where Feitian's apps store codes. *(Measured: all credentials on both keys.)* |
| `00` | 1 | Keyboard slot. *(LIST measured, empty on Key B; use is Client.)* |
| `01` | 2 | Keyboard slot. *(Same.)* |

A credential is identified by its slot and its stored name together.

## Credential names

The applet has no period field. Feitian's apps keep the period in the stored
name, and so does `keyroost`:

```
TOTP:  30:issuer_#_account      60:issuer_#_account
HOTP:  issuer_#_account
```

- A TOTP name starts with `30:` or `60:`; those are the only two periods.
- Issuer and account are joined with `_#_`. With no issuer the account stands
  alone.
- An HOTP name has no prefix.

*(Measured: every stored name on both keys has this form. That Feitian's apps
write it this way is Client.)* A TOTP name with no prefix is read as a
30-second credential; the card has nothing that says otherwise.

CALCULATE and DELETE send the stored name back unchanged, prefix included.

## Commands

All commands use CLA `00`. Data is a run of TLVs with one-byte lengths.

### LIST (`17`)

```
00 17 00 <slot> 00
```

The answer is one `52` TLV per credential, `52 <len> <kind|algorithm> <name>`.
An empty slot answers `9000` with no data. *(Measured.)*

The first value byte holds the kind in its high nibble and the algorithm in its
low nibble:

| Nibble | Value | Meaning |
|---|---|---|
| high | `1` | HOTP *(Measured, Key A)* |
| high | `2` | TOTP *(Measured)* |
| high | `3`, `4` | Static password, challenge-response *(Client; not handled, counted as skipped)* |
| low | `1` | HMAC-SHA-1 *(Measured)* |
| low | `2` | HMAC-SHA-256 *(Measured, Key B)* |

Feitian's client answers a `6700` here by sending the four bytes `00 17 00 00`
(no slot, no `Le`) and then asks no other slot. *(Client. Neither key returned
`6700` to a LIST.)* `keyroost` does the same for the default slot only.

### CALCULATE (`A2`)

```
00 A2 01 <slot> <Lc>  54 08 <time step, 8 bytes big-endian>  51 <len> <name>
```

P1 is `01`. For TOTP the challenge is `floor(unix time / period)`. The answer
is

```
76 05 <digits> <4 bytes>
```

and the code is those four bytes with the top bit cleared, modulo
`10^digits`, zero-padded (RFC 4226). *(Measured. On Key B, a SHA-1 6-digit
30-second code and a SHA-256 8-digit 60-second code both matched the
reference; on Key A, a SHA-1 6-digit 30-second code.)*

The key computes the code once it is touched. With no touch it answers
`6984`, and how long it waits first differs by model. *(Measured, timed over
PC/SC.)* Key A answers 5.2 seconds after the command: 5.13 to 5.25 s in four
runs. Both keys of Key B's model answer after 3.2 seconds: 3.17 to 3.18 s in
four runs on one of them. `keyroost` sends the command again a few times, so
there is longer to reach the key.

For HOTP the challenge is empty (`54 00`). A new credential's first code is
the one for counter 0, and the key then moves its counter on. A CALCULATE
answered `6984` does not move it. *(Measured, Key B: the first two codes
matched RFC 4226's values for counters 0 and 1, with dozens of untouched
tries before and between them. Key A: the first code matched the value for
counter 0.)*

### PUT (`09`)

```
00 09 00 <slot> <Lc>  53 <len - 1> <algorithm> <kind> <digits> <secret>  51 <len> <name>
```

- `algorithm` is `01` (SHA-1) or `02` (SHA-256); `kind` is `10` (HOTP) or
  `20` (TOTP); `digits` is 6 or 8.
- The length byte of the `53` TLV is **one less** than the real length of its
  value. Feitian's client writes it this way and so does `keyroost`.
- There is no counter field: an HOTP credential starts at 0.
- The secret is sent in the clear.
- The key stores the credential once it is touched. With no touch it answers
  `6984` and stores nothing.

*(Measured, Key A and Key B, default slot: TOTP and HOTP credentials written
this way by `keyroostctl` list back and compute the right codes. The answer
with no touch was seen on Key B. What the applet does
with the true length in the `53` TLV has not been tried, nor what it does
with a name it already holds: `keyroost` never sends one.)*

Feitian's client can add a third TLV, `5C 01 01`, when it stores a credential
that is to need a touch. *(Client.)* `keyroost` does not send it. On Key B a
credential stored with `5C 01 00` and one stored with `5C 01 01` both needed
a touch for a code, answering `6984` after about three seconds without one,
the same as a credential stored with no `5C` at all: the TLV made no
difference that could be seen there. *(Measured, Key B.)*

### DELETE (`08`)

```
00 08 00 <slot> <Lc>  51 <len> <name>
```

The key removes the credential once it is touched. With no touch it answers
`6984` and the credential stays. *(Measured, default slot: the removal on
Key A and Key B, the answer with no touch on Key B.)*

### RESET (`07`)

```
00 07 00 00 00
```

No slot and no data. The key wipes the applet's credentials once it is
touched; with no touch it answers `6984`. *(Measured, Key B: two credentials
in the default slot were gone afterwards, and the `51` value of the SELECT
answer was the same before and after. A second RESET of the empty applet was
answered `9000` as well. Whether it also clears the keyboard slots, and what
it does on a slot with an access code, is not measured.)*

Feitian's client answers a `6700` here with the four bytes `00 07 00 00`, as
for LIST. *(Client. Key B did not answer `6700`.)* `keyroost` does the same.

## Status words

| SW | Meaning | |
|---|---|---|
| `9000` | Success | *Measured* |
| `6984` | CALCULATE, PUT, DELETE, RESET: no touch arrived | *Measured* |
| `6982` | The slot has an access code that must be presented first | *Client* |
| `6700` | LIST: use the four-byte form | *Client* |
| `6A84` | No space left | *Client* |
| `6A82` | Credential not found | *Client* |

## Limits

| | Value | |
|---|---|---|
| Kinds | TOTP, HOTP | *Measured* |
| Algorithms | SHA-1, SHA-256 | *Measured* |
| Digits | 6 or 8 | *Both measured; that there is no other is Client* |
| TOTP period | 30 or 60 seconds | *Measured* |
| HOTP counter | starts at 0 | *Measured* |
| Stored name | 64 bytes, prefix and separator included | Libre Key Companion's limit, the tightest of the known clients; the applet's own limit is not measured |
| Secret | 64 bytes | Libre Key Companion's limit and the HMAC block size of both algorithms; longer is not measured |
| Number of credentials | not known | |

## Not implemented

Known from Feitian's client and left out until measured: the per-slot access
codes (`A3`), and the commands that swap the keyboard slots or pick which
credential a slot types. The touch TLV a PUT can carry (`5C`) is not sent:
see PUT. Static passwords and challenge-response secrets are not handled.
