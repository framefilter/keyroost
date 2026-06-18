# Changelog

All notable changes to keyroost are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0] - 2026-06-17

### Added
- **Device-centric bare overview** — running `keyroostctl` with no subcommand
  now prints a device-centric overview of what is connected, and `list` is
  enriched with per-device detail (applets, serials, friendly names).
- **`--name` targeting on every group** — the friendly-name selector now works
  across all command groups (`molto`, `fido`, `oath`, `openpgp`, `piv`, `otp`),
  not just a subset, so one named key can be addressed consistently everywhere.
- **Per-group man pages** — `keyroostctl manpage <DIR>` now writes a directory
  set of man pages (one per command group) instead of a single page on stdout.
- **Global `--json` output mode** for the status/query commands — `list` /
  overview, `*/status`, `*/info`, `fido pin-retries` / `creds-list` /
  `creds-metadata`, `oath list` / `code`, and `otp list` / `get` / `serial` can
  now emit machine-readable JSON instead of human text.
- **OpenPGP PIN management** — `openpgp change-pin`, `openpgp change-admin-pin`,
  and `openpgp unblock-pin`, closing the OpenPGP PIN-management gap.
- **Token2 PIN+ fingerprint enrollment** (`fido fingerprint-list` / `enroll` /
  `rename` / `delete`), FIDO Metadata Service (MDS) metadata in the GUI, and
  on-device OTP improvements — contributed by
  [@token2](https://github.com/token2)
  ([#29](https://github.com/framefilter/keyroost/pull/29),
  [#30](https://github.com/framefilter/keyroost/pull/30)).
- **GUI PIV pane detail** — each slot now shows its certificate Subject DN and
  key algorithm, and a slot holding a key with no certificate is distinguished
  from an empty one; the pane auto-refreshes after a write
  ([#31](https://github.com/framefilter/keyroost/issues/31)).
- **In-tree X.509 Subject-DN reader** (`keyroost-piv`) — a small, panic-safe,
  dependency-free DER certificate reader backing the slot display above.
- **Confirm-PIN fields** on the GUI PIV Change-PIN and Change-PUK dialogs, so a
  mistyped new PIN can't lock the card
  ([#36](https://github.com/framefilter/keyroost/issues/36)).

### Changed
- **BREAKING: commands nested under `molto` and `fido` groups.** The flat
  Molto2 and FIDO subcommands have been moved under `molto …` and `fido …`.
  Key renames: `info` → `molto info`, `import`/`import-file` →
  `molto import`/`molto import-file`, `set-seed`/`set-title`/`configure` →
  `molto seed`/`molto title`/`molto config`, `set-customer-key` →
  `molto customer-key`, `factory-reset` → `molto reset`, and every `fido-*`
  command → `fido *` (e.g. `fido-info` → `fido info`, `fido-creds-list` →
  `fido creds-list`). The customer-key flags (`--key`, `--key-env`, …) now live
  under `molto customer-key`. See the migration table in the README for the full
  old→new map.

### Fixed
- **Firmware-accurate PIN guidance in the GUI** — removed the inaccurate "touch
  the key to confirm" hint from the FIDO set/change-PIN flow (CTAP PIN changes
  are not touch-gated) and corrected the PIN/PUK length text per applet
  ([#36](https://github.com/framefilter/keyroost/issues/36)).

## [0.5.1] - 2026-06-14

A follow-up to the Token2-vs-Molto2 device-identification fix.

### Fixed
- Molto2 reader matching keys on the product-name word only ("molto"), not the
  broader Token2 brand string, so a Token2 PIN+ / FIDO2 key is no longer
  mis-detected as a Molto2 (#21).

## [0.5.0] - 2026-06-14

On-device OTP for Token2 FIDO security keys joins the Molto2 programmer.

### Added
- **On-device TOTP/HOTP for Token2 FIDO keys (PIN+ / FIDO2+)** — a pure-Rust
  byte/codec layer (`keyroost-token2otp`) plus CLI (`otp` group) and GUI surface
  to enumerate, read, add, and delete OTP credentials stored on a Token2 FIDO
  security key over USB-HID, including the touch/button-HOTP slot and serial
  read. Contributed by @token2, built from the protocol reference they published
  (#20).

### Fixed
- Token2 FIDO keys no longer masquerade as a ghost Molto2 during device
  enumeration (#21).
- The crates.io "already published?" probe now sends a User-Agent, which some
  endpoints require.

### Docs
- Credit @token2 in a Contributors acknowledgement.

## [0.4.0] - 2026-06-12

Full PIV management, screenshot QR import, package-manager distribution, a
fuzzing suite, and a broad security-hardening pass.

### Added
- **Full PIV management** — beyond read-only status: client/card authentication
  (GENERAL AUTHENTICATE), key generation, certificate import/export,
  PIN/PUK/management-key changes, and applet reset, plus card-signed
  certificates (self-sign into a slot, or emit a CSR for a CA).
- **QR-code import** — pull 2FA secrets from PNG/JPEG screenshots, including
  Google Authenticator export batches.
- **Package-manager distribution** — automated release fanout to crates.io, AUR,
  Homebrew, and winget; `cargo binstall` targets the attested release archives.
- **Fuzzing** — `cargo-fuzz` targets for every hand-rolled parser, run weekly in
  CI.
- **`doctor`, `completions`, and `manpage` subcommands** — environment diagnosis
  and generated shell-completion / man-page artifacts.
- **Supply-chain CI** — a `cargo audit` (RUSTSEC) job on lockfile changes and
  weekly, SHA-256 release checksums, and build-provenance attestation on
  published archives.
- **SECURITY.md** — threat model, security invariants, and disclosure policy.

### Changed
- GUI bulk imports run on a dedicated thread instead of the frame loop, and a
  single shared scroller backs every capability pane.

### Fixed
- Broad post-review hardening: zeroize session secrets, CLI-read PINs, imported
  TOTP seeds, and extracted RSA components on drop; bound device-driven loops
  and lengths; strict base32 padding; cap attacker-controlled scrypt parameters
  in encrypted Aegis vaults; reject `otpauth` secrets over the device's 63-byte
  cap at parse time; atomic owner-only `keys.json` writes with field
  sanitization; redact secret-bearing APDU bodies from `--debug` traces.

### Notes
- The crates.io fanout skips publishing until OIDC / trusted-publishing is
  configured; the other targets and the GitHub Release run unconditionally.

## [0.3.0] - 2026-06-08

keyroost goes cross-platform: macOS and Windows join Linux, with a HID backend
that works on all three, a three-OS CI matrix, and a release pipeline that
attaches ready-to-run binaries for each.

### Added
- **macOS and Windows support** — a `hidapi`-based HID backend covers FIDO
  enumeration on macOS (IOKit) and Windows (hid.dll) alongside the existing
  Linux sysfs/hidraw path; PC/SC (OATH / OpenPGP / PIV / Molto2) was already
  cross-platform. `keyroost_hid::hid_supported()` lets front-ends tell "no FIDO
  devices plugged in" apart from "no HID backend on this platform".
- **Pre-built release binaries for all three OSes** — pushing a `vX.Y.Z` tag now
  cuts a public GitHub Release with a Linux x86_64 tarball, a macOS `universal2`
  tarball (`lipo`'d aarch64 + x86_64, one artifact for Apple Silicon and Intel),
  and a Windows zip, with auto-generated notes. A `workflow_dispatch` trigger
  builds the same archives off a branch for smoke-testing without tagging.
- **Three-OS CI matrix plus Fedora/Arch build verification** — Linux, macOS, and
  Windows build/test on every push, and `fedora:latest` / `archlinux:latest`
  container builds verify the documented per-distro package lists rather than
  assuming them.

### Changed
- The GUI empty state now states explicitly when FIDO keys aren't supported on
  the current platform (and notes that the smart-card features still work), so a
  missing-backend case doesn't read as a bug.
- User-facing "is pcscd running?" messages across transport / resolve / CLI are
  reworded to platform-neutral smart-card-service language.
- `CtapHidDevice::open` returns a clear `HidTransportError::Unsupported` on
  platforms without a HID backend instead of an opaque file-open failure.

### Docs
- README gains full Debian / Fedora-RHEL / Arch prerequisite blocks split into
  CLI vs GUI dependencies, corrects the stale "HID is Linux-only" note, and warns
  that the Ubuntu-built release binaries may not run on older-glibc distros
  (build from source there).

### Notes
- The macOS and Windows release jobs are exercised by `workflow_dispatch`; run
  the release workflow manually once before tagging if the build environment has
  changed.

## [0.2.0] - 2026-06-06

A device-centric GUI redesign, reliable hotplug, a FIDO reset that actually
fits the hardware's window, and the OpenPGP write surface rounded out.

### Added
- **Device-centric GUI** — a persistent sidebar listing each *physical* key once
  with merged capability badges, per-device capability tabs (Overview / FIDO2 /
  OATH / OpenPGP / PIV), and a distinct Molto2 view. Dark/light themes, accent
  colors, a colorblind-safe palette (Okabe–Ito), opaque help popovers, a global
  activity log, and a welcoming empty state. Bundled IBM Plex Sans / JetBrains
  Mono.
- **Reader hotplug auto-detect** — a PC/SC PnP-notification watcher re-enumerates
  on plug/unplug, with a staggered rescan burst so a slow-registering reader
  appears without a manual refresh.
- **FIDO reset that beats the ~10 s window** — arm the reset, then re-insert the
  key; it fires on reconnection (matched by HID serial, so any USB port works)
  and prompts for the touch.
- **OpenPGP PIN management** — change the user PIN (PW1) and admin PIN (PW3), and
  unblock a blocked user PIN with the admin PIN (`RESET RETRY COUNTER`), in a
  rebuilt themed write panel (admin PIN, card details, keys, PINs, reset).
- **Learn site "Naming" page** documenting friendly device names.

### Changed
- Interactive controls (buttons, segmented controls, device rows, icons) gained
  clear hover/press states and a pointing-hand cursor.
- Single-pass PC/SC enumeration; the Molto2 is listed by name and never
  connected during a scan (a probe connect intermittently wedged its CCID slot),
  so refreshing no longer disturbs a held, authenticated Molto2 session.

### Fixed
- CTAP `getKeyAgreement` now declares the negotiated PIN/UV protocol, fixing
  Set/Change PIN on authenticators that strictly enforce it (e.g. YubiKey).
- Empty resident-credential enumeration (`CTAP2_ERR_NO_CREDENTIALS`) is reported
  as "no passkeys", not an error.

### Notes
- Molto2 PC/SC detection on some hosts is bounded by a libccid USB-init timeout
  *below* the application; a direct USB port (avoiding hub chains) is the
  mitigation.
- Still Linux-only; Windows/macOS support is on the roadmap.

## [0.1.0] - 2026-06-02

The first release. keyroost grew from a Token2 Molto2 TOTP programmer into a
multi-vendor hardware-security-key manager, then took its neutral name. Highlights:

### Added
- **FIDO2 / CTAP2** — authenticator enumeration, `authenticatorGetInfo`, resident
  credential management (list / metadata / delete), PIN set/change/verify, reset.
  PIN protocols v1 and v2.
- **OATH (TOTP/HOTP)** over PC/SC — list, add, delete, compute codes, and the
  Yubico applet-password handshake (`SET_CODE` / `VALIDATE`, set/clear/unlock).
- **OpenPGP card (v3.4)** — status; RSA-2048 key generate and import (host keygen
  or PKCS#1/PKCS#8 PEM/DER file); sign (SHA-256 / SHA-1); decrypt (PSO:DECIPHER,
  extended-length + command-chaining); set cardholder name / URL; GnuPG key
  registration; applet reset.
- **PIV (SP 800-73-4)** — read-only status: applet/firmware version, serial, PIN
  retries, and per-slot (9A/9C/9D/9E) certificate presence.
- **Token2 Molto2 / Molto2v2** — slot programming from `otpauth://`; bulk import
  from Aegis (plaintext/encrypted), 2FAS, and `otpauth://` lists; time sync;
  customer-key rotation; factory reset.
- **Friendly device names** — opt-in `keys.json` registry and safe multi-key
  selection (USB + CCID serials, USB-topology matching).
- A CLI (`keyroostctl`) and an egui desktop GUI (`keyroost`).

### Notes
- Linux-only for now (HID enumeration uses sysfs; PC/SC is cross-platform).
- Crypto is pure-Rust and verified against standard test vectors; the only
  external dependencies are `pcsc`, `clap`, `eframe`/`egui`, `serde`, and
  (for RSA keygen/parsing) `rsa`/`rand`.

[Unreleased]: https://github.com/framefilter/keyroost/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/framefilter/keyroost/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/framefilter/keyroost/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/framefilter/keyroost/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/framefilter/keyroost/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/framefilter/keyroost/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/framefilter/keyroost/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/framefilter/keyroost/releases/tag/v0.1.0
