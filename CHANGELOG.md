# Changelog

All notable changes to keyroost are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/framefilter/keyroost/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/framefilter/keyroost/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/framefilter/keyroost/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/framefilter/keyroost/releases/tag/v0.1.0
