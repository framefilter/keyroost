# Changelog

All notable changes to keyroost are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

The first release line. keyroost grew from a Token2 Molto2 TOTP programmer into a
multi-vendor hardware-security-key manager, then took its neutral name. Highlights
so far:

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

[Unreleased]: https://github.com/framefilter/keyroost/commits/main
