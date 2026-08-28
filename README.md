<p align="center">
  <img src="docs/assets/keyroost-logo.png" alt="keyroost" width="200">
</p>

# keyroost

An independent, vendor-neutral app for managing all your hardware security keys
in one place.

## What it is

keyroost is an open-source Rust toolchain for hardware security keys, working
across vendors over PC/SC and USB HID. It speaks FIDO2/CTAP2, OATH (TOTP/HOTP),
and the OpenPGP and PIV card protocols, manages on-device OTP on Token2 FIDO keys,
and also programs the Token2 Molto2 / Molto2v2 TOTP token. Ships a Rust library,
a CLI (`keyroostctl`), and a desktop GUI (`keyroost`) with a dark and light
theme — implemented from public standards, with no vendor SDKs, no Python, and
no Qt.

> **Built with AI.** I saw a real need for this but never learned to code, so
> the parts I author — code, docs, and all — are written end-to-end with AI.
> (Contributions from others, such as Token2's, are their own human-designed and
> -developed work — see the Contributors section.) Since the AI I use learned
> from the vast commons of free and open-source software people have generously
> shared, releasing keyroost as FOSS isn't really a choice; it's giving back to
> what made it possible. Issues, review, and contributions are warmly welcome —
> see [CONTRIBUTING.md](CONTRIBUTING.md).

**New to hardware keys?** Read the companion guide —
[*"So you bought a hardware security key… now what?"*](https://framefilter.github.io/keyroost/) —
a short, vendor-neutral tour of what FIDO2, OATH, OpenPGP, and PIV actually do.

## What it does

- **FIDO2 / CTAP2** — enumerate authenticators, read `authenticatorGetInfo`,
  manage resident credentials (list / metadata / delete), set / change / verify
  the PIN, reset a key (USB replug ceremony, or in place for a card in a
  reader). Fingerprint (bio) enrollment — list / enroll / rename / delete — and
  FIDO Metadata Service (MDS) authenticator identification in the GUI. PIN
  protocols v1 and v2. CTAP 2.1 security policy over
  `authenticatorConfig` (always-require-UV, minimum PIN length, force a PIN
  change, enterprise attestation) and a `large-blob` store for plaintext notes
  over `authenticatorLargeBlobs`. Works over USB-HID and over a PC/SC reader —
  both NFC (CTAP-over-NFC) and a contact / ISO-7816 chip reader (T=0) — not just
  direct USB. Resident-credential metadata surfaces the fuller passkey detail
  too: the user's UPN, display name, user id, and the full credential id.
  Resident SSH credentials can be listed and their stored OpenSSH certificate
  extracted from largeBlob to a `-cert.pub` file (`fido ssh-cert`).
- **OATH (TOTP/HOTP)** — list, add, delete, and compute codes over PC/SC,
  including applet-password set / clear / unlock, and a factory reset of the
  applet (`oath reset --yes`) — the recovery path for a forgotten password. In
  the GUI, secret fields have a reveal (eye) toggle so you can check an OTP
  secret before committing it.
- **OpenPGP card (v3.4)** — read status; generate or import RSA-2048 keys (host
  keygen or a PKCS#1/PKCS#8 PEM/DER file) for the signature, encryption, or
  authentication slot — each writes the v4 fingerprint and a generation timestamp
  so GnuPG recognizes the key; sign (SHA-256 or SHA-1); decrypt; authenticate (a
  client/SSH signature with the Authentication key via INTERNAL AUTHENTICATE);
  set cardholder name / URL; change the user / admin PIN and unblock a locked
  PIN; factory-reset the applet.
- **PIV (SP 800-73-4)** — full management: status (applet/firmware version,
  serial, PIN retries, which slots 9A/9C/9D/9E hold a certificate), on-card key
  generation, certificate import / export, self-signed certs or a CSR for a CA,
  clearing a slot's certificate (`delete-cert`) or key (`delete-key`, on YubiKey
  5.7+), moving a key between slots (`move-key`, on YubiKey 5.7+), writing a
  fresh CHUID with a random GUID (`new-chuid`) so Windows re-reads a
  reprovisioned card, and PIN / PUK / management-key changes and applet reset. Every slot-taking command addresses
  9A/9C/9D/9E *and* the 20 Yubico retired key-management slots (82–95), so keys
  can be archived and rotated. The GUI collects the
  management key per operation (and wipes it after), which is ideal for a slot or
  two; for **provisioning many slots or keys, the CLI is the intended path** — the
  management key and PIN come from env/stdin once, so a shell loop does the batch
  (see the [PIV guide](https://framefilter.github.io/keyroost/piv.html)).
- **Token2 Molto2 / Molto2v2** — program a slot from an `otpauth://` URI;
  bulk-import from Aegis (plaintext or encrypted), 2FAS, a list of `otpauth://`
  URIs, or a QR code scanned from a PNG/JPEG screenshot or the live screen; sync
  the host clock; rotate the customer key; factory reset.
- **Token2 single-profile programmable TOTP token** — program the seed and TOTP
  configuration onto Token2's single-account card/fob tokens (OTPC-P1-i / P2-i,
  miniOTP-2-i / 3-i, C301-i, C302-i) over a PC/SC reader. These authenticate
  with a fixed device key rather than a customer key, and hold one account
  rather than many; keyroost reads the device serial / model and on-device
  clock, writes the seed, and sets the HMAC algorithm, time-step, and
  display-timeout (`prog info` / `seed` / `config`, or the GUI's
  programmable-token pane). The wire protocol is documented in
  [`docs/PROTOCOL-token2prog.md`](docs/PROTOCOL-token2prog.md).
- **Token2 on-device OTP (PIN+ Series FIDO keys)** — store TOTP/HOTP credentials
  directly on a Token2 FIDO security key and read their codes over USB-HID, NFC,
  or CCID; configure the single HOTP-on-touch keystroke slot; read the serial;
  and enable / disable the key's USB interfaces (FIDO / keyboard-HID / CCID).
  On R3.4+ keys the codes can be put behind an OTP PIN (`otp set-pin`,
  `otp verify`, `otp change-pin`, `otp remove-pin`, `otp pin-status`); note
  there is no PIN reset — a blocked PIN is recoverable only by erasing every
  OTP entry.
- **One-shot factory reset** — `keyroostctl factory-reset --yes` (and a card on
  the GUI device Overview tab) resets every resettable applet on a key in turn:
  OATH, OpenPGP, PIV, Token2 OTP, then FIDO2. On a USB key the FIDO2 step ends
  with an unplug/replug and a touch; a card in a smart-card reader is instead
  reset in place (no replug, no touch — the card is power-cycled in the
  reader). Only manufacturer-intended resets are used, and each step reports
  its own outcome rather than being folded into one "done".
- **Friendly device names** — an opt-in `keys.json` registry to target a specific
  physical key by name when several are connected, instead of by a reshuffling
  `/dev/hidrawN` path. Destructive operations always resolve to an explicit
  target, never a default. The registry lives under `%APPDATA%` on Windows (the
  platform config dir elsewhere), and names are validated with anti-spoofing
  checks while allowing a relaxed, readable character set.
  On Windows and macOS the OS reports no USB position, so when two keys of the
  same make could each own the same card reader keyroost shows them separately
  rather than guessing which reader belongs to which key.

## Supported devices

| Device | Capabilities | Notes |
|---|---|---|
| **Token2 Molto2 / Molto2v2** | TOTP slot programming, bulk import | Hardware-verified. Programmed over the vendor-specific SM4-MAC protocol ([docs/PROTOCOL.md](docs/PROTOCOL.md)); supports bulk import from Aegis / 2FAS / otpauth-list, clock sync, and customer-key rotation. |
| **Token2 single-profile tokens** (OTPC-P1-i / P2-i, miniOTP-2-i / 3-i, C301-i, C302-i) | Single-account TOTP seed + config programming | Programmed over the vendor-specific SM4-MAC protocol with a fixed device key ([docs/PROTOCOL-token2prog.md](docs/PROTOCOL-token2prog.md)); writes the seed and the TOTP algorithm / time-step / display-timeout over a contact or contactless PC/SC reader. The model is recognized from the device serial. |
| **Token2 PIN+ Series** | FIDO2 (+ bio), OTP, OpenPGP, PIV | FIDO2 with fingerprint/bio enrollment and FIDO Metadata Service (MDS) display, plus on-device OTP (TOTP/HOTP) over CCID / NFC / USB-HID, validated on PIN+ hardware. HID/keyboard HOTP applies to the models that carry it — recent releases (R3.2+/R3.3+) have no HID-HOTP and ship with the HID channel disabled by design; CCID is the intended path there. Contributed by [@token2](https://github.com/token2). The OATH / OpenPGP / PIV smart-card applets are handled by the standard byte layers but **not yet exercised on PIN+ hardware by this project** (experimental). |
| **YubiKey** (5 series) | FIDO2, OATH, OpenPGP, PIV | Built and verified against a YubiKey 5.7. |
| **SoloKeys Solo 2** | FIDO2, OATH | Trussed firmware; no OpenPGP applet. **HOTP caveat:** the last-shipped Solo 2 firmware (2.3.x) computes HOTP over a 4-byte counter where RFC 4226 specifies 8, so its HOTP codes won't verify against standards-compliant servers (hardware-verified; fixed in the current upstream Trussed secrets app, but Solo 2 no longer receives firmware updates). TOTP is unaffected — its 8-byte time challenge comes from the host. |
| **Nitrokey 3** | FIDO2, OATH, PIV; OpenPGP detected | Built around the same Trussed firmware core as Solo 2, but the final firmware is different — e.g. Nitrokey 3 has PIV support, while Solo 2 does not. PIV verified on a Nitrokey 3A NFC (firmware 1.8.3), contributed by [@episource](https://github.com/episource). The OpenPGP applet is detected but not yet exercised by this project. |
| **Any standards-compliant FIDO2 key** (e.g. Thales, Feitian, Titan) | FIDO2 / CTAP2; OATH / OpenPGP / PIV only if the key carries those applets | keyroost implements the published specs, not vendor-specific behavior, so the `fido` commands — getInfo, passkey management, PIN, reset — work on any CTAP2 authenticator, including ones not listed here. Optional features (fingerprint, large-blob, authenticatorConfig) surface only when the key advertises them in getInfo. The smart-card applets apply only to keys that expose an OATH / OpenPGP / PIV applet over PC/SC. Older U2F-only (CTAP1) keys are detected by `list` but don't support the CTAP2 management commands. |

Each listed row notes what's actually been verified on that device; the final,
generic row describes the standards-based behavior expected on untested but
compliant keys.

## Roadmap

Planned hardware support, not yet shipped:

- **OnlyKey** — it speaks FIDO2/CTAP2 over USB-HID, so the `fido` commands will
  apply, but it exposes no smart-card interface (no OATH / OpenPGP / PIV) and its
  firmware reports a fixed, non-unique serial that needs placeholder handling
  before it's first-class
  ([#37](https://github.com/framefilter/keyroost/issues/37)). Test hardware
  ordered; support lands once it arrives.

Want a different key supported? Open an issue requesting it — hardware-support
requests are tracked here and added to this roadmap.

## Independence, trademarks & acknowledgements

keyroost is an independent implementation, **not affiliated with or endorsed by
any vendor named here.** It works with their products by implementing publicly
documented protocols; vendor and product names are used descriptively.

- *Token2* / *Molto2* — trademarks of **Token2 Sàrl**. The Molto2 protocol was
  determined by observing the device and its public reference tool; SM4 and SHA-1
  follow their published standards (GB/T 32907-2016, RFC 3174) and are checked
  against independent test vectors.
- *YubiKey* — trademark of **Yubico AB**.
- *Solo* / *Solo 2* — trademarks of **SoloKeys**; *Nitrokey* — trademark of
  **Nitrokey GmbH**.

A genuine thank-you to these teams for their work on everyone's security: Yubico
for helping create and champion U2F and FIDO2/WebAuthn and for publishing open
specs and tooling; SoloKeys and Nitrokey for open, auditable security-key
firmware and hardware (Nitrokey maintains the Trussed-based Solo 2 line); and
Token2 for affordable programmable hardware TOTP. keyroost also rests on open
standards from the FIDO Alliance, the OATH/IETF TOTP–HOTP RFCs, and the OpenPGP
card specification.

### Contributors

Beyond the maintainers, keyroost is grateful for community contributions:

- **[@token2](https://github.com/token2)** — contributed on-device TOTP/HOTP
  management for Token2 FIDO keys (PIN+ / FIDO2+), and published the protocol
  reference it was built from
  ([#24](https://github.com/framefilter/keyroost/pull/24)). Followed up with
  fingerprint/bio enrollment, FIDO Metadata Service (MDS) display, and a
  rounding-out of the on-device OTP support — all validated on real PIN+
  hardware ([#29](https://github.com/framefilter/keyroost/issues/29),
  [#30](https://github.com/framefilter/keyroost/pull/30)). Also added CTAP 2.1
  authenticator-config (security policy) and large-blob storage management,
  with a FIDO2 tab redesign
  ([#38](https://github.com/framefilter/keyroost/pull/38)); T=0 contact-reader
  fixes, the single-profile programmable-token support (`keyroost-token2prog`)
  and QR-from-screen import ([#50](https://github.com/framefilter/keyroost/pull/50));
  and the OTP secret-reveal toggle plus a Windows key-naming / anti-spoofing
  fix ([#52](https://github.com/framefilter/keyroost/pull/52),
  [#56](https://github.com/framefilter/keyroost/pull/56)); and OTP-PIN
  protection for R3.4+ keys, in the CLI and the GUI
  ([#107](https://github.com/framefilter/keyroost/issues/107),
  [#108](https://github.com/framefilter/keyroost/pull/108)). Signs the Windows
  and macOS release builds out-of-band.
- **[@Algoritter](https://github.com/Algoritter)** — the project's first
  external code contribution: found, fixed and hardware-verified two
  armed-reset replug bugs (a recycled `/dev/hidrawN` path reading as "never
  left", and card-serial keys failing to re-match after reinsertion)
  ([#96](https://github.com/framefilter/keyroost/pull/96)).
- **[@errant253](https://github.com/errant253)** — README improvements: the
  distro-neutrality disclaimer, install-command corrections and an intro
  rewrite ([#35](https://github.com/framefilter/keyroost/issues/35),
  [#45](https://github.com/framefilter/keyroost/issues/45)).

(This credits their contributions to the codebase; it does not change keyroost's
independent status described above.)

## Standards & protocols

keyroost is built entirely from published specifications — no vendor SDKs. Every
byte layer below is implemented in-tree against the documents named here. The
two **vendor-specific** protocols are called out distinctly; everything else is
an open industry standard.

**FIDO2 / CTAP**
- FIDO **CTAP 2.x** (Client to Authenticator Protocol) over CTAP-HID — device
  info, resident-credential management, client-PIN (protocols v1 and v2), and
  bio (fingerprint) enrollment.
  [Spec](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html)
- ECDH on **NIST P-256** (FIPS 186-4) for the client-PIN/UV key agreement.

**OATH (one-time passwords)**
- **HOTP** — counter-based OTP, [RFC 4226](https://www.rfc-editor.org/rfc/rfc4226).
- **TOTP** — time-based OTP, [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238).
- The
  [Yubico OATH applet protocol](https://developers.yubico.com/OATH/YKOATH_Protocol.html)
  (also implemented by Trussed devices), carried over ISO 7816-4 APDUs.

**OpenPGP card**
- [OpenPGP Card v3.4](https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf)
  applet, with v4 key fingerprints per
  [RFC 4880](https://www.rfc-editor.org/rfc/rfc4880) §12.2.

**PIV**
- **NIST SP 800-73-4** / FIPS 201 Personal Identity Verification card interface,
  including X.509 certificate slots.
  [Spec](https://csrc.nist.gov/pubs/sp/800/73/4/final)

**Token2 Molto2 / Molto2v2 (vendor-specific)**
- The Molto2 / Molto2v2 wire protocol, determined by observing the device and
  its public reference tool and documented independently in
  [`docs/PROTOCOL.md`](docs/PROTOCOL.md). It layers on:
  - **SM4** block cipher — GB/T 32907-2016 — for seed/title encryption and the
    per-command MAC.
  - **SHA-1** — [RFC 3174](https://www.rfc-editor.org/rfc/rfc3174) — to derive
    the SM4 key from the customer key.

**Token2 single-profile programmable token (vendor-specific)**
- The wire protocol of Token2's single-profile programmable TOTP tokens (OTPC /
  miniOTP / C30x), a close relative of the Molto2 protocol — same NFC Type-4 /
  ISO 7816 transport, SM4 cipher, and ISO/IEC 9797-1 MAC — but authenticated
  with a fixed device key (no customer key) and addressing a single slot.
  Documented independently in
  [`docs/PROTOCOL-token2prog.md`](docs/PROTOCOL-token2prog.md).

**Token2 on-device OTP (vendor-specific)**
- The Token2 OTP-on-FIDO management protocol used by the PIN+ Series keys,
  published as the
  [Token2 OTP SDK Protocol](https://github.com/token2/token2-otp-cli/blob/main/docs/Token2-OTP-SDK-Protocol.md)
  (issue [#41](https://github.com/framefilter/keyroost/issues/41)). Seed-bearing
  commands use ECDH (NIST P-256) + AES payload encryption.

**Cryptographic primitives & encodings**
- **AES** (FIPS 197) and **HMAC** ([RFC 2104](https://www.rfc-editor.org/rfc/rfc2104))
  — client-PIN, OTP payload encryption, and PIV management-key auth (also 3DES).
- **RSA** with **PKCS#1** ([RFC 8017](https://www.rfc-editor.org/rfc/rfc8017)) and
  **PKCS#8** ([RFC 5208](https://www.rfc-editor.org/rfc/rfc5208)) key
  serialization, PEM/DER (X.509 / ASN.1 DER) — host-side OpenPGP key import.
- **CBOR** ([RFC 8949](https://www.rfc-editor.org/rfc/rfc8949), canonical
  encoding) — the CTAP2 message format.
- **base32** ([RFC 4648](https://www.rfc-editor.org/rfc/rfc4648)) and the
  **`otpauth://` URI** scheme — OTP secret encoding and 2FA import.
- **ISO 7816-4** APDUs (with BER-TLV / simple-TLV data objects) — the common
  framing for the OATH, OpenPGP, PIV, and Molto2 smart-card applets.

## Design principles

- **Few dependencies, by design.** The protocol and codec layers are hand-written:
  the Molto2 wire protocol (SM4, SHA-1, the MAC), base32, hex, CBOR, CTAP-HID
  framing, and the OATH / OpenPGP / PIV byte layers are all in-tree, pulling in
  nothing beyond `zeroize` for wiping secret buffers.
  External crates are added only when *not* doing so would be irresponsible or
  impractical — audited cryptography we won't hand-roll under `forbid(unsafe_code)`
  (RustCrypto: `sha2` / `hmac` / `aes` / `p256` / `rsa` / …) and platform glue
  (`pcsc`, `hidapi` on macOS/Windows, `clap`, `eframe`/`egui`). The per-crate list
  is in the table below, and the standing goal is to shrink it over time, not grow
  it.
- **Pure-Rust crypto** — no OpenSSL or other C crypto; the in-tree primitives are
  checked against standard test vectors, and standard algorithms come from the
  audited RustCrypto crates.
- **Secrets stay yours.** PINs and passwords come from stdin or env vars, never
  argv; the tool never prints or persists them.
- **Single static binary per OS** — no scripts, no Python, no Qt.
- **Toward native installs everywhere.** The longer-term goal is first-class
  distribution through each platform's mainstream channels. Available today:
  Homebrew, AUR, Flatpak, AppImage, and winget, plus the pre-built release
  binaries and cargo. All while continuing to shrink external dependencies
  toward a self-contained binary.

## Install

keyroost ships through every mainstream channel below. The release archives, the
Flatpak, Homebrew, winget and the AUR package all carry both `keyroost` (the GUI)
and `keyroostctl` (the CLI); the AppImage is GUI-only. Pick whichever
fits your platform; the smart-card features need a host PC/SC daemon (see
[Smart-card prerequisite](#smart-card-prerequisite)).

> Pre-1.0, availability tracks the [latest release](https://github.com/framefilter/keyroost/releases/latest):
> when a version is published, these channels are updated to point at it. Replace
> `vX.Y.Z` below with that release tag.

### Pre-built binaries (GitHub Releases)

No toolchain needed. Download from the
[latest release](https://github.com/framefilter/keyroost/releases/latest):

| Platform | Asset |
|---|---|
| Linux x86_64 | `keyroost-vX.Y.Z-linux-x86_64.tar.gz` |
| macOS (Apple Silicon + Intel) | `keyroost-vX.Y.Z-macos-universal2.tar.gz` |
| Windows x86_64 | `keyroost-vX.Y.Z-windows-x86_64.zip` |
| Windows x86_64, **code-signed** | `keyroost-vX.Y.Z-windows-x86_64-signed.zip` |
| macOS installer, **code-signed** | `keyroost-vX.Y.Z-macos-universal2-signed.pkg` |

The signed builds carry the same binaries as the CI archives, signed
out-of-band by Token2 (Authenticode on Windows; an Apple Developer ID
installer on macOS, signed but not notarization-stapled). They may trail a
release by a few days — winget always waits for the signed zip. The CI
archives are covered by `SHA256SUMS` and build-provenance attestation instead.

Each archive carries both `keyroost` and `keyroostctl`; unpack it and move the
two executables onto your `PATH`. For example, on Linux x86_64:

```bash
curl -L https://github.com/framefilter/keyroost/releases/download/vX.Y.Z/keyroost-vX.Y.Z-linux-x86_64.tar.gz \
  | tar xz   # then move keyroostctl / keyroost onto your PATH
```

The prebuilt binaries need `libpcsclite` at runtime — on a FIDO-only machine install it
(`apt install libpcsclite1` / `dnf install pcsc-lite`) or use a package that declares the dependency.

### cargo (from source)

Needs the Rust toolchain — **1.92+ for the GUI** (`keyroost`), 1.85+ for the CLI
(`keyroostctl`) and libraries — and, on Linux, the PC/SC dev package plus the
GUI's X11/Wayland/GL libraries (see
[Smart-card prerequisite](#smart-card-prerequisite)):

```bash
cargo install keyroostctl keyroost
```

The release binaries and the AppImage are built with the optional `qr` feature
(scan a TOTP QR from the live screen). `cargo install` does not enable it — add
`cargo install keyroost --features qr` if you want it.

Or let `cargo-binstall` fetch the same pre-built release archive instead of
compiling — useful on atomic distros (e.g. Bazzite) where `cargo install`'s
build step is awkward:

```bash
cargo install cargo-binstall   # if you don't have it yet; ensure its dir is on PATH
cargo binstall keyroostctl keyroost
```

### Homebrew (macOS + Linux)

```bash
brew tap framefilter/keyroost
brew install keyroost
```

### AUR (Arch Linux)

The `keyroost-bin` package installs the prebuilt binaries plus the FIDO udev
rules. Use any AUR helper (or `makepkg`):

```bash
yay -S keyroost-bin
```

### winget (Windows)

Live in the Microsoft catalog ([microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs)):

```powershell
winget install Framefilter.Keyroost
```

### Flatpak (Linux — auto-updating, recommended for the GUI)

Add Flathub (for the shared runtime) and the maintainer's GPG-signed remote in
the **same scope**, then install the app (app-id
`io.github.framefilter.keyroost`). Using `--user` needs no root and avoids the
most common failure — a scope mismatch between Flathub and the keyroost remote,
which makes the install fail to find its runtime even when it's installed:

```bash
flatpak remote-add --if-not-exists --user flathub \
  https://dl.flathub.org/repo/flathub.flatpakrepo
flatpak remote-add --if-not-exists --user keyroost \
  https://framefilter.github.io/keyroost-flatpak/keyroost.flatpakrepo
flatpak install --user keyroost io.github.framefilter.keyroost
# updates ride along with `flatpak update`
```

The Flatpak carries the CLI as well; run it with
`flatpak run --command=keyroostctl io.github.framefilter.keyroost`.

Prefer a system-wide install? Use `--system` on all three commands instead —
the key is keeping Flathub and the keyroost remote in the *same* scope.

Or grab the offline single-file bundle (`keyroost.flatpak`) attached to each
release:

```bash
flatpak install ./keyroost.flatpak
```

The Flatpak bundles the pcsc-lite *client* and talks to the **host** `pcscd`, so
you still need that daemon running on the host (see
[Smart-card prerequisite](#smart-card-prerequisite)).

### AppImage (Linux — no install, GUI only)

Download `keyroost-x86_64.AppImage` from the
[latest release](https://github.com/framefilter/keyroost/releases/latest) — the
asset name is version-less, so this URL always fetches the current build:

```bash
curl -LO https://github.com/framefilter/keyroost/releases/latest/download/keyroost-x86_64.AppImage
chmod +x keyroost-x86_64.AppImage
./keyroost-x86_64.AppImage
# On FUSE3-only distros, install libfuse2, or run without FUSE:
./keyroost-x86_64.AppImage --appimage-extract-and-run
```

> **Needs the host's pcsc-lite.** Unlike the other bundles, this AppImage does
> **not** ship the pcsc-lite client library — it uses the host's, so the smart-card
> client always matches the host's `pcscd` daemon. Practically that means the
> host must have `pcsc-lite` installed (it comes with `pcscd`; see
> [Smart-card prerequisite](#smart-card-prerequisite)). Pure-FIDO use still needs
> it present for now, since the GUI links libpcsclite at startup — a future
> release will load it lazily so FIDO-only hosts can run without it.

### Smart-card prerequisite

The smart-card features (OATH / OpenPGP / PIV, and Token2 Molto2 programming)
talk to the card over PC/SC and need the **`pcscd` daemon running on the host**.
macOS and Windows have PC/SC built in. On Linux, install the PC/SC library +
daemon (the package name differs per distro). Building from source with `cargo`
additionally needs the PC/SC *dev* package, and the GUI needs the X11/Wayland/GL
libraries that `eframe`/`egui` link against.

Once installed, `keyroostctl doctor` checks all of this for you — PC/SC service,
readers, FIDO HID access, and udev rules — read-only, touching no key.

keyroost is otherwise distro-neutral — it talks to the kernel's `hidraw`/`sysfs`
and to PC/SC, both of which every mainstream distribution provides; only the
package names differ. Common distro one-liners:

```bash
# Debian / Ubuntu
sudo apt install libpcsclite-dev pcscd \
  libxkbcommon-dev libwayland-dev libxcb1-dev libgl1-mesa-dev

# Fedora / RHEL
sudo dnf install pcsc-lite-devel pcsc-lite pkgconf-pkg-config gcc \
  libxkbcommon-devel libxkbcommon-x11-devel wayland-devel libxcb-devel \
  mesa-libGL-devel

# Arch
sudo pacman -S pcsclite ccid pkgconf gcc \
  libxkbcommon libxcb wayland mesa

sudo systemctl enable --now pcscd
```

(For the **CLI only** you can drop the `libxkbcommon`/`wayland`/`xcb`/`mesa`
packages — those are just for the GUI.) macOS and Windows have PC/SC built in,
and the FIDO HID backend uses `hidapi` (IOKit / hid.dll) automatically — no extra
packages. macOS/Windows are tier-2 (best-effort, not yet hardware-verified).

(Building the **GUI on Windows** compiles a small build script that embeds the
app icon and version info into `keyroost.exe`; it needs a resource compiler —
`rc.exe`, part of the Windows SDK that ships with the standard MSVC toolchain
setup. The CLI has no build script.)

> **Windows and FIDO:** Windows reserves raw FIDO HID access for elevated
> processes (the OS routes normal apps through its own WebAuthn API instead).
> Expect the `fido` commands and the GUI's FIDO2 tab to require an
> elevated ("Run as administrator") session on Windows; the Molto2, OATH,
> OpenPGP, and PIV features go over PC/SC and work unelevated. Elevate for
> the FIDO command you need, then drop back — don't run the whole tool
> elevated as a habit. Even without admin the GUI now *detects* an attached
> FIDO key (via readable HID metadata, without opening the protected
> interface) and shows an "Administrator rights needed" card with a button to
> relaunch elevated or open Windows' own security-key settings.

> **Prebuilt binaries:** the release artifacts are built on Ubuntu and linked
> against its glibc, so they run on glibc-current distros (Arch, recent Fedora)
> but may fail on older ones (e.g. RHEL 9) with a `GLIBC_…` error. When in doubt,
> build from source with the commands above — `cargo install` handles the rest.

> **Wayland and clipboard auto-clear:** after copying an OTP code the GUI
> clears the clipboard ~45 s later, but only if the clipboard still holds that
> code. The check reads the clipboard via X11/XWayland; on a pure-Wayland
> session without XWayland clipboard sync it can't see the contents and fails
> open (nothing is cleared) rather than clobbering whatever you copied since.
> GNOME and KDE sync the two clipboards, so the clear works there; on other
> compositors treat the auto-clear as best-effort.

> **Forcing X11 (`KEYROOST_X11=1`):** the GUI runs natively on Wayland by
> default. The egui/eframe 0.35 bump fixed a Wayland/KDE input bug where text
> entry under native Wayland — notably on KDE Plasma — could misbehave, but if
> you still hit broken text input set `KEYROOST_X11=1` to force the GUI onto
> XWayland as a fallback. It's opt-in; leave it unset for the native-Wayland
> path.

### FIDO HID access (Linux udev rules)

The OATH, OpenPGP, and PIV applets are reached over PC/SC and need no special
permissions. Talking to a key's **FIDO interface** (the `fido` commands, and the
GUI's FIDO2 tab), though, opens a `/dev/hidraw*` node, which is
root-only by default. Install the bundled udev rules to grant the logged-in user
access:

```bash
sudo cp udev/70-keyroost-fido.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger
```

The rules use `uaccess` (and a `plugdev` fallback), are keyed by vendor/USB so
they apply before the hidraw node is created, and cover the common FIDO vendors
(Yubico, SoloKeys, Nitrokey, Feitian, Token2, and others). Re-plug the key after
installing them.

## Quick start

```bash
# discover connected devices: PC/SC readers + FIDO authenticators (USB-HID and NFC)
keyroostctl list

# diagnose the local environment (PC/SC service, readers, FIDO HID access,
# udev rules, registry permissions) — read-only, touches no key
keyroostctl doctor

# --- FIDO2 (YubiKey / Solo 2 / Nitrokey 3), over USB-HID or an NFC reader ---
keyroostctl fido info
keyroostctl fido pin-retries
keyroostctl fido creds-list --pin-stdin        # PIN read from stdin, never argv
keyroostctl fido ssh-cert list --pin-stdin     # list SSH certs stored in resident credentials
keyroostctl fido ssh-cert extract --credential ssh:demo --out demo-cert.pub --pin-stdin

# --- OATH over PC/SC ---
keyroostctl oath list --reader yubikey
keyroostctl oath code 'GitHub:me@x.com' --reader yubikey

# --- OpenPGP card ---
keyroostctl openpgp status --reader yubikey
keyroostctl openpgp sign --in msg.txt --pin-stdin --reader yubikey
keyroostctl openpgp authenticate --in chal.bin --pin-stdin --reader yubikey  # client/SSH auth (Auth key)

# --- PIV (read-only status) ---
keyroostctl piv status --reader yubikey

# bulk-provision several slots: management key + PIN from env once, loop the rest.
# (the GUI asks per operation; the CLI is the path for many slots/keys)
export PIV_MGMT=...   # AES-192 / 3DES management key, hex; never put it in argv
export PIV_PIN=...
for slot in 9a 9c 9d 9e; do
  keyroostctl piv generate-key --slot "$slot" --algorithm eccp256 \
      --mgmt-key-env PIV_MGMT --reader yubikey
  keyroostctl piv self-sign --slot "$slot" --subject "CN=$USER" \
      --mgmt-key-env PIV_MGMT --pin-env PIV_PIN --reader yubikey
done

# --- Token2 Molto2 (TOTP programming) ---
keyroostctl molto info
keyroostctl molto import --profile 0 'otpauth://totp/GitHub:me@x.com?secret=JBSWY3DPEHPK3PXP'
keyroostctl molto import-file ~/Downloads/aegis.json --start 0 --dry-run   # validate first

# --- Token2 single-profile programmable token (OTPC / miniOTP / C30x) ---
keyroostctl prog info                          # serial, model, and on-device clock
keyroostctl prog seed --base32-stdin           # base32 seed from stdin, never argv
keyroostctl prog config --algorithm sha1 --time-step 30 --display-timeout 30

# --- Token2 on-device OTP (PIN+ Series FIDO keys) ---
keyroostctl otp list
keyroostctl otp add --app GitHub --account me@x.com --seed-stdin   # seed from stdin, never argv
keyroostctl otp get --app GitHub --account me@x.com

# --- Destructive operations ---
keyroostctl factory-reset --device my-yubikey --yes   # reset every applet on that key

# name a key to target it when several are plugged in (opt-in)
keyroostctl key-name list

# machine-readable output for scripts (status and query commands)
keyroostctl --json piv status --reader yubikey

# shell completions and man pages
keyroostctl completions bash > /etc/bash_completion.d/keyroostctl
keyroostctl manpage ./man && man -l ./man/keyroostctl-piv.1

# launch the GUI (per-device tabs: Overview, FIDO2, Authenticator, OpenPGP, PIV,
# On-device OTP, plus the distinct Molto2 and single-profile programmable-token views)
keyroost
```

## Breaking changes & migration

Breaking changes are tracked per release on the site's
[migration notes](https://framefilter.github.io/keyroost/migration.html)
page, with the exact before → after for scripts and library consumers. The
two to know about: **v0.7.5** renames the global device selector from
`--name` to `--device`, and **v0.6.0** moved the Molto2 / FIDO commands under
the `molto` and `fido` groups.

One name to watch: in **≤0.5.x** `keyroostctl factory-reset` meant the Molto2
profile reset (now `keyroostctl molto reset`). The name is live again, but it
now wipes *every* applet on a key. See the migration page before re-running an
old script.

## Workspace layout

| Crate | Purpose | External deps |
|---|---|---|
| `keyroost-proto` | Pure-Rust Molto2 wire protocol (SM4, SHA-1, APDU, MAC) | none |
| `keyroost-transport` | PC/SC discovery, Molto2 session, CCID serial, OATH/OpenPGP/PIV applets, Token2 OTP session | `pcsc`, `aes`/`des`/`cipher` (mgmt-key auth), `getrandom`, `zeroize`; `hidapi` on macOS/Windows |
| `keyroost-hid` | USB HID enumeration of FIDO devices | none on Linux (`sysfs`); `hidapi` on macOS/Windows |
| `keyroost-ctap` | FIDO2/CTAP-HID transport, CBOR, PIN protocols, credential management | RustCrypto (`sha2`/`hmac`/`aes`/`cbc`/`p256`/`rand_core`) for client-PIN, `aes-gcm` + `miniz_oxide` for per-credential largeBlob, `zeroize`; `hidapi` on macOS/Windows |
| `keyroost-oath` | Pure-Rust Yubico/Trussed OATH (TOTP/HOTP) byte layer | `zeroize` |
| `keyroost-openpgp` | Pure-Rust OpenPGP Card v3.4 byte layer (APDU + BER-TLV) | `zeroize` |
| `keyroost-piv` | Pure-Rust PIV (SP 800-73-4) byte layer; full management + SPKI/PEM | `zeroize` |
| `keyroost-token2otp` | Pure-Rust Token2 OTP-on-FIDO byte/codec layer (APDU + HID framing) | RustCrypto (`sha2`/`hmac`/`aes`/`cbc`/`p256`/`rand_core`) for ECDH seed encryption and the OTP-PIN session, `zeroize` |
| `keyroost-token2prog` | Pure-Rust Token2 single-profile programmable-token wire protocol (SM4 seed/MAC, fixed device key, config TLV); reuses `keyroost-proto` | `zeroize` |
| `keyroost-keyring` | Friendly-name registry (`keys.json`); serial matching | `serde`, `serde_json` |
| `keyroost-resolve` | Shared key-identity resolution (USB + CCID serials, topology match) | none |
| `keyroost-rsakey` | Host-side RSA-2048 keygen + PKCS#1/PKCS#8 (PEM/DER) loading | `rsa`, `rand`, `zeroize` |
| `keyroost-import` | `otpauth://` + Aegis / 2FAS / otpauth-list parsers | `zeroize`; `serde`/`serde_json` (behind `bulk`); `scrypt`, `aes-gcm`, `base64` (behind `encrypted`, which implies `bulk`) |
| `keyroost-qr` | QR 2FA import from PNG/JPEG screenshots and Google Authenticator export batches — always built in; the GUI's *live screen* capture is behind the `qr` feature (on in the release archives and the AppImage, off in the Flatpak) | `rqrr`, `png`, `jpeg-decoder`, `zeroize` |
| `keyroost-winwebauthn` | Windows-only helper for the non-admin FIDO2 path: detect a FIDO key via the HID access-denied signal, open Windows' security-key settings, and relaunch elevated; inert on non-Windows | `windows-sys` (Windows only) |
| `keyroost-screengrab` | Windows-only still screen capture (GDI `BitBlt`) for QR-from-screen; isolates the unsafe Win32 FFI from the GUI crate; inert on non-Windows | `windows-sys` (Windows only) |
| `keyroostctl` | Command-line interface | `clap`, `clap_complete`, `clap_mangen`, `serde`/`serde_json`, `zeroize` |
| `keyroost` | egui desktop GUI | `eframe`, `egui`, `arboard`, `rfd`, `pollster`, `png`, `base64`, `serde`/`serde_json`, `zeroize`; `x11rb`/`ashpd` on Linux (`qr` feature); `winresource` build-dep on Windows |

## Protocol

The Molto2 wire protocol is documented in [`docs/PROTOCOL.md`](docs/PROTOCOL.md)
— the APDUs, the SM4-based MAC, and the TLV config payload, described as facts
about the device rather than any one implementation. The sibling single-profile
programmable token (OTPC / miniOTP / C30x) is documented the same way in
[`docs/PROTOCOL-token2prog.md`](docs/PROTOCOL-token2prog.md). The FIDO2, OATH,
and OpenPGP layers follow their respective public standards.

## Contact

General questions, packaging notes, and other non-security correspondence are
welcome at **framefilter@proton.me**.

Security issues should not go to email — please use GitHub's private
vulnerability reporting (see [`SECURITY.md`](SECURITY.md)) so the report stays
private until a fix ships.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option. Unless you explicitly state otherwise, any contribution
intentionally submitted for inclusion in the work by you, as defined in the
Apache-2.0 license, shall be dual licensed as above, without any additional
terms or conditions.

This dual-license is the Rust ecosystem default and matches what `serde`,
`tokio`, `clap`, and most of the ecosystem use.
