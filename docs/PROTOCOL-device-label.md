# Device label in the FIDO2 large-blob array

This document describes how a security key's own name (its "device label") is
stored as one entry in the key's FIDO2 large-blob array, as implemented by
`keyroost-ctap` (`device_label.rs`). It is written so any tool can read and
write the same entry. The known-answer vectors at the end are checked by the
crate's tests.

## Purpose

A person names a key once ("Work YubiKey") and every computer and tool that
reads the key shows that name, with no PIN.

The label is **not confidential**. The large-blob array is readable by anyone
who has the key, without a PIN, and the encryption key below is published. The
entry is encrypted only so it has the same shape as every other large-blob
entry (CTAP 2.1 §6.10.3): other tools' readers try their own keys on it, fail,
and skip it, as they skip any entry that isn't theirs.

A label is a name a person chose. It is not an identity: two keys can carry
the same label, and anyone with the key can change it. keyroost never treats
it as proof of which key is which (see "How keyroost uses the label" below).

## Requirements

- The key advertises `largeBlobs: true` in `authenticatorGetInfo`.
- Reading needs no PIN.
- Writing needs a PIN/UV auth token with the large-blob-write (`lbw`)
  permission, so the key must have a FIDO PIN set.

## Format (version 1)

```text
K         = SHA-256("FIDO2 large-blob device label v1")
P         = canonical CBOR map {1: 1, 2: label, 3?: writer}
origSize  = len(P)
compressed= raw DEFLATE (RFC 1951) of P
ciphertext= AES-256-GCM(key K, nonce, compressed,
                        aad = "blob" || u64le(origSize))   ; includes the 16-byte tag
entry     = {1: ciphertext, 2: nonce, 3: origSize}
```

`K` is the SHA-256 of the 32 ASCII bytes `FIDO2 large-blob device label v1`:

```text
K = 2d90176240c249e3f7aaeabd444093437d2f595dc778bf45d3cc0554f326b639
```

### Plaintext `P`

A canonical CBOR map (keys in ascending order):

| Key | Value | Meaning |
|---|---|---|
| 1 | unsigned int `1` | Format version |
| 2 | text, 1–64 Unicode scalar values | The label |
| 3 | text, 1–64 Unicode scalar values (optional) | The tool that wrote it (keyroost writes `keyroost`) |
| 4 | — | Reserved; not used by version 1 |

The label is stored exactly as given. No Unicode normalization (NFC or other)
is applied on either side.

Readers ignore keys they don't know. Later fields will use only CBOR types an
older reader can decode (unsigned and negative integers, byte and text strings,
arrays, maps, booleans, null).

`P` always holds at least keys 1 and 2, so `origSize` is never 0.

### Compression

- **Writers** emit one final *stored* (uncompressed) DEFLATE block:
  `01 || u16le(len) || u16le(!len) || P`. A label's `P` is far below the
  64 KiB limit of one block.
- **Readers** accept any raw DEFLATE stream, compressed or stored, whose
  output is exactly `origSize` bytes.

### Encryption

AES-256-GCM under `K`, with a fresh random 12-byte nonce for each write. The
additional authenticated data is the 4 ASCII bytes `blob` followed by
`origSize` as a 64-bit little-endian integer, as in CTAP 2.1 §6.10.3. The
ciphertext field holds the encrypted bytes followed by the 16-byte tag.

### One label per array

- **Writers** remove every version-1 label entry from the array and append
  one new entry at the end. Clearing the label removes them all.
- **Readers** take the last entry that decodes as a version-1 label.
- Every other element of the array is written back byte for byte, in its
  original order. That includes entries the writer can't decrypt and elements
  that don't follow the large-blob entry format.

The array is then serialized as usual: the CBOR array followed by the first
16 bytes of the SHA-256 of that array.

## Reading

An entry is a version-1 label only if all of these hold:

1. The GCM tag verifies under `K` with the AAD above.
2. The decrypted bytes inflate to exactly `origSize` bytes.
3. Those bytes are one CBOR map with nothing after it.
4. Key 1 is the unsigned integer 1.
5. Key 2 is text of 1–64 Unicode scalar values.

If key 3 is present but isn't text of 1–64 characters, the writer is ignored
and the label still counts. If a key appears twice, the first one counts.

An entry under `K` that fails these checks (a later format version, or a
damaged entry) is not a label to this reader. A writer keeps it unchanged like
any other entry.

keyroost also checks the label's text with the same rules as a name typed on
the computer: no control, zero-width or bidi characters. A label that fails
is never shown, and the key is treated as having no name.

## Writing safely

1. Read the array and plan the change: the new array is the old one with the
   label entries replaced as above. keyroost refuses, rather than removing
   anything else, when the result would not fit the key's
   `maxSerializedLargeBlobArray` (1024 bytes when the key doesn't report it).
2. Get the PIN token.
3. Read the array again. If its bytes differ from the ones the plan was made
   from, send nothing and report that the array changed.
4. Write the planned array.

Step 3 keeps an entry another tool wrote in the meantime from being lost.

## Cautions

- **Platform cleanup.** CTAP 2.1 allows a platform to remove large-blob
  entries that no credential on the key can decrypt. A label entry is such an
  entry. We have not seen Chrome, libfido2 or python-fido2 do this, but if it
  happens the label is gone. A name lives in one place, so keyroost then shows
  the key as unnamed until the name is written back: `keyroostctl name list`
  prints the one command that restores it, and the desktop app offers
  "Write it back".
- **Erasing the array.** `keyroostctl fido blob clear` erases the label with
  everything else unless `--keep-name` is given. A FIDO reset erases the array
  and the label with it.

## How keyroost uses the label

- A label is shown first; a name saved on this computer is shown only when
  the key carries no label.
- Each computer records the first key it sees with a given label, as a salted
  fingerprint of the key's serial in `keys.json` (the serial itself is never
  stored). Only that key is selected by `--device NAME`. Another key carrying
  the same label is shown as `Name (1234)`, the last four characters of its
  serial; that text is for display only and never selects anything.
- If a computer can't record a key (for example, the key reports no serial),
  it warns once and treats the key as seen for the first time on every scan.

## Known-answer vectors

All three use AES-256-GCM under `K` above. V1 and V2 were computed
independently with Python `cryptography` (AESGCM) and `hashlib`, with the
CBOR and the stored DEFLATE block encoded by hand. A writer following this
document must produce V1 and V2 byte for byte from the same nonce. A reader
must decode all three.

### V1: label only

| Field | Value |
|---|---|
| label | `Work YubiKey` |
| writer | (none) |
| nonce | `000102030405060708090a0b` |
| P | `a20101026c576f726b20597562694b6579` |
| origSize | 17 |
| stored DEFLATE | `011100eeff` followed by P |
| ciphertext and tag | `fa202b3626a9c13b79e236fa5b1288777aa854baa7b9071106da74af6ca22511f5913dab35ed` |
| entry CBOR | `a3015826fa202b3626a9c13b79e236fa5b1288777aa854baa7b9071106da74af6ca22511f5913dab35ed024c000102030405060708090a0b0311` |
| one-entry array | `81` followed by the entry |
| array checksum | `9527ae20c7a00a231f6800e4e319d611` |

### V2: non-ASCII label with a writer

| Field | Value |
|---|---|
| label | `Clé de bureau` (é is U+00E9) |
| writer | `keyroost` |
| nonce | `000102030405060708090a0b` |
| P | `a30101026e436cc3a92064652062757265617503686b6579726f6f7374` |
| origSize | 29 |
| stored DEFLATE | `011d00e2ff` followed by P |
| ciphertext and tag | `fa2c2b3a26a8c13b79e022f9ead0884a6aea5f84b0a5ecf7beaca35fe4c4b10d0234607c0eddb263c942a581932e707b715e` |
| entry CBOR | `a3015832fa2c2b3a26a8c13b79e022f9ead0884a6aea5f84b0a5ecf7beaca35fe4c4b10d0234607c0eddb263c942a581932e707b715e024c000102030405060708090a0b03181d` |
| one-entry array | `81` followed by the entry |
| array checksum | `80f2ff1c1dddfa8eb409d589b6ff287b` |

### V3: compressed (readers only)

The same label as V1, compressed with real DEFLATE (fixed Huffman; Python
`zlib` level 9, `wbits=-15`). Writers don't produce this; readers must accept
it.

| Field | Value |
|---|---|
| label | `Work YubiKey` |
| writer | (none) |
| nonce | `a0a1a2a3a4a5a6a7a8a9aaab` |
| origSize | 17 |
| DEFLATE | `5bc4c8c894139e5f94ad10599a94e99d5a0900` |
| entry CBOR | `a301582371eda327a400c713df95d9f1d5fab5675779cad37fb437982c7a5dda50d98d583dc030024ca0a1a2a3a4a5a6a7a8a9aaab0311` |
