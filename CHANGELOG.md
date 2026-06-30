# Changelog

All notable changes to keyroost are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.3] - 2026-06-30

### Added
- **Windows: non-admin FIDO2 detection** — an unelevated process can't read a
  FIDO key's HID usage page on Windows, so FIDO-only keys used to disappear from
  the device list with no explanation. keyroost now detects the key via the
  access-denied signal and shows an "Administrator rights needed" card in the
  FIDO2 tab, with buttons to open Windows' built-in security-key settings or to
  relaunch elevated (new `keyroost-winwebauthn` helper crate). Thanks to
  [@token2](https://github.com/token2)
  ([#58](https://github.com/framefilter/keyroost/issues/58),
  [#62](https://github.com/framefilter/keyroost/pull/62)).
- **`KEYROOST_X11=1`** — opt-in environment variable that forces the GUI onto
  XWayland, a fallback for Wayland compositors where native input misbehaves.

### Fixed
- **GUI text input on Wayland / KDE Plasma** — on some compositors (notably KDE
  Plasma 6.7) the window lost keyboard focus shortly after startup and no field
  accepted typed input. The UI-toolkit update (below) resolves it; native
  Wayland input works again
  ([#48](https://github.com/framefilter/keyroost/issues/48)).
- **Light-theme zoom control** — the "Text size" slider, its handle and the ±
  steppers were nearly invisible on the light theme; they now use a contrasting
  control colour. The ± steppers also no longer slide out from under the cursor
  during repeated clicks — they preview and apply once you settle
  ([#59](https://github.com/framefilter/keyroost/issues/59),
  [#42](https://github.com/framefilter/keyroost/issues/42)).
- **winget (Windows):** the package manifest now declares the
  `Microsoft.VCRedist.2015+.x64` dependency, so winget pulls in the VC++
  runtime the Windows build needs alongside keyroost.

### Changed
- **UI toolkit updated** (egui/eframe 0.29 → 0.35) — this fixed the Wayland/KDE
  input bug above and is a sizeable refresh of the GUI layer. It should look and
  behave just as before, but **please
  [open an issue](https://github.com/framefilter/keyroost/issues) if you spot
  anything off** so it can be polished. Building from source now requires
  **Rust 1.85** or newer.

## [0.7.2] - 2026-06-26

### Added
- **Token2 single-profile programmable TOTP token** — a `keyroostctl prog`
  group (`info` / `seed` / `config`) and a GUI pane that program the seed and
  TOTP configuration onto Token2's single-account card/fob tokens (OTPC-P1-i /
  P2-i, miniOTP-2-i / 3-i, C301-i, C302-i) over a PC/SC reader, authenticating
  with the device's fixed key (no customer key, single slot). A new pure-Rust
  `keyroost-token2prog` crate carries the wire protocol — a close relative of
  the Molto2's (same SM4 cipher and ISO/IEC 9797-1 MAC) — documented
  independently in `docs/PROTOCOL-token2prog.md`. The write commands refuse to
  run unless the device serial matches a known model
  ([#49](https://github.com/framefilter/keyroost/pull/49)).
- **Contact-reader (ISO-7816 T=0) support** — FIDO2 and on-device OATH now work
  over a contact / chip reader as well as NFC, completing the PC/SC transport
  begun in 0.7.0 (the `61 XX` / `GET RESPONSE` and `6C XX` continuations are
  reassembled for T=0 readers)
  ([#43](https://github.com/framefilter/keyroost/issues/43)).
- **QR-from-screen scanning** — the `qr` import feature can now scan a QR code
  straight from the live screen, in addition to PNG/JPEG screenshots and Google
  Authenticator export batches, and is compiled into the pre-built release and
  AppImage binaries ([#50](https://github.com/framefilter/keyroost/pull/50)).
- **OTP secret reveal toggle** — secret-entry fields in the GUI gain a reveal
  (eye) toggle so you can verify an OTP secret before committing it
  ([#52](https://github.com/framefilter/keyroost/issues/52)).
- **Fuller passkey details** — resident-credential metadata now surfaces the
  user's UPN, display name, user id, and the full credential id
  ([#55](https://github.com/framefilter/keyroost/issues/55)).
- **AppImage AppStream metainfo + zsync** — the AppImage now ships AppStream
  metainfo and a `.zsync` sidecar for delta updates
  ([#53](https://github.com/framefilter/keyroost/pull/53)).

### Changed
- **Relaxed, anti-spoofing device naming + Windows config path** — friendly
  device names accept a more permissive, readable character set while being
  validated against spoofing (e.g. homoglyph / control-character) tricks, and
  the `keys.json` registry is saved under `%APPDATA%` on Windows
  ([#56](https://github.com/framefilter/keyroost/issues/56)).

### Fixed
- **Duplicate device entries when several keys are plugged in** — keys are now
  de-duplicated by USB topology, so the same physical key no longer appears more
  than once during enumeration
  ([#51](https://github.com/framefilter/keyroost/pull/51)).
- **AppImage uses the host's pcsc-lite** — the AppImage no longer bundles its
  own libpcsclite, instead linking the host's so the smart-card client always
  matches the host `pcscd` daemon
  ([#47](https://github.com/framefilter/keyroost/pull/47)).

## [0.7.1] - 2026-06-21

A bugfix release: it repairs the Flatpak repository install (broken in 0.7.0)
and two text-size controls in the GUI. No library or protocol changes — the
`keyroost-*` crates are unchanged save for the version bump.

### Fixed
- **Flatpak repo install failed GPG verification** — the published OSTree repo
  signed only its summary, not the commit objects, so installing from the remote
  failed with *"GPG verification enabled, but no signatures found"* even though
  `flatpak remote-info` (which checks only the summary) succeeded. The release
  workflow now signs the commits (`flatpak build-sign`) before refreshing the
  summary. The offline `.flatpak` bundle attached to each release was unaffected.
  Reported by [@errant253](https://github.com/errant253)
  ([#46](https://github.com/framefilter/keyroost/issues/46)).
- **GUI text-size slider jumped at the 99%↔100% boundary** — the percentage
  readout grew from 3 to 4 characters as the value crossed 100%, and in the top
  bar's right-to-left layout the wider label shifted the slider track under the
  cursor, making the value lurch (to ~110% going up, ~87% coming back down). The
  readout now reserves a fixed width, so the track stays put. Reported by
  [@StefanSa](https://github.com/StefanSa) with a detailed repro from
  [@errant253](https://github.com/errant253)
  ([#42](https://github.com/framefilter/keyroost/issues/42)).
- **Ctrl +/- zoom ignored the 80–200% bounds** — keyboard and scroll zoom could
  scale the interface past the slider's limits (roughly 20–500%) while the
  readout and the persisted value capped at 200%. Keyboard zoom is now clamped to
  the same range as the slider
  ([#42](https://github.com/framefilter/keyroost/issues/42)).

### Changed
- **README** — the winget entry is marked pending Microsoft's catalog review (the
  manifest is submitted but not yet merged into the public catalog), and the
  available-channels summary now reflects the Flatpak and AppImage bundles that
  shipped in 0.7.0. Prompted by [@errant253](https://github.com/errant253)
  ([#46](https://github.com/framefilter/keyroost/issues/46)).
- **README — supported-devices accuracy + a Roadmap section.** Corrected the
  device table (dropped dated framing, fixed an OpenPGP line that implied a
  standalone "register for GnuPG" command when the fingerprint/timestamp is
  written by generate/import, and added a row describing behavior on any
  standards-compliant FIDO2 key), and added a Roadmap section listing planned
  OnlyKey support ([#37](https://github.com/framefilter/keyroost/issues/37)) and
  inviting hardware-support requests via issues.

## [0.7.0] - 2026-06-20

### Added
- **FIDO2 over NFC readers** — a `CtapTransport` abstraction lets the CTAP
  command layer run over PC/SC as well as USB-HID, so FIDO2 (getInfo, passkey
  management) and on-device OTP now work through an NFC reader, not just direct
  USB. Contact / ISO-7816 chip readers are not yet supported (the contact path
  is deferred to follow-up; the PC/SC transport is shared, so it's an
  incremental fix). Contributed by Emin Huseynov / [@token2](https://github.com/token2)
  ([#44](https://github.com/framefilter/keyroost/pull/44), addressing
  [#43](https://github.com/framefilter/keyroost/issues/43)).
- **OpenPGP INTERNAL AUTHENTICATE** — `openpgp authenticate` produces a
  client/SSH authentication signature with the on-card Authentication key
  (PW1 in the "other" context). The Auth key slot is now selectable for
  provisioning too (`openpgp generate-key --slot auth`, `openpgp import-key
  --slot auth`), completing the third OpenPGP key.
- **PIV slot clearing** — `piv delete-cert` removes a slot's X.509 certificate
  object while leaving the private key in place (standard PIV; works on every
  card), and `piv delete-key` permanently erases a slot's private key (a Yubico
  extension requiring YubiKey firmware 5.7 or newer). Both need the management
  key and require an explicit `--yes`.
- **CTAP 2.1 authenticator config and large-blob storage** — a `fido large-blob`
  group (`list` / `get` / `add` / `edit` / `delete` / `clear`) reads and edits a
  key's `authenticatorLargeBlobs` array, keeping keyroost's own plaintext notes
  alongside relying-party entries (writes pull a `largeBlobWrite` token from the
  PIN and re-read the live array so RP entries are never clobbered; the store is
  world-readable, so it is for notes, not secrets). FIDO security-policy controls
  over `authenticatorConfig` — always-require-UV, raise minimum PIN length, force
  a PIN change, and enable enterprise attestation — plus a FIDO2 tab redesign in
  the GUI. Contributed by [@token2](https://github.com/token2)
  ([#38](https://github.com/framefilter/keyroost/pull/38)).
- **Linux desktop bundles** — a self-hosted Flatpak (signed OSTree remote with
  auto-update, plus an offline `.flatpak` bundle) and an AppImage of the GUI,
  both built by a new `linux-bundles.yml` workflow that triggers on `v*` tags and
  is gated behind the same `release-publish` approval as the other channels. The
  Flatpak OSTree is hosted in a dedicated `keyroost-flatpak` Pages repo (Flathub
  is intentionally not used). A Homebrew tap (`framefilter/homebrew-keyroost`)
  rounds out the fanout. (Flatpak ships the pcsc-lite client lib and talks to the
  host `pcscd`; end-to-end hardware verification of the sandboxed bundles is still
  pending.)

### Changed
- **Consolidated, card-based GUI across the FIDO2, PIV, and OpenPGP panes** — a
  significant redesign so every applet pane shares one visual vocabulary:
  per-slot / per-key sub-tab strips (PIV 9A/9C/9D/9E, OpenPGP sig/enc/auth),
  full-width cards with right-pinned actions, inline `?` help bubbles in place of
  verbose notes, and a global content-width cap (~920px, centered) that fixes the
  wide-window label↔action gap. Applet-wide administration (PIN/PUK, retries,
  management key, reset) is folded into each pane's status card instead of
  floating loose, and secret entry routes through a centered, scroll-independent
  credential modal that shows the operation result in place.
- **Vendor-neutral applet support, documented as such** — the OATH, OpenPGP, and
  PIV byte layers are open-standard implementations that work over CCID with any
  card exposing those applets (YubiKey, Nitrokey, SoloKeys, Feitian, Token2,
  OpenSK, …), not just YubiKeys; the README capability matrix and the github.io
  pages were reconciled to say so
  ([#41](https://github.com/framefilter/keyroost/issues/41)). The OATH / OpenPGP
  / PIV applets on the Token2 PIN+ are this same standards code; they remain
  marked experimental only because the project has not yet exercised them on
  physical PIN+ hardware.
- **Friendlier README intro** — a more approachable opening and a "What it is"
  framing so the project reads clearly to newcomers. Readability suggestion by
  [@errant253](https://github.com/errant253)
  ([#45](https://github.com/framefilter/keyroost/pull/45); the accompanying
  install script was declined).

### Fixed
- **Canonical CBOR key order in large-blob writes** — large-blob payloads now
  emit map keys in canonical order (parameter `0x05` before protocol `0x06`), so
  spec-strict authenticators (Solo 2, Nitrokey) accept the writes. YubiKey is
  lenient, which is why the earlier hardware round-trip passed.
- **Large-blob deletes no longer clobber relying-party entries** — the GUI delete
  path now re-reads the live large-blob array in the worker and removes the
  matching entry by content, instead of writing back a stale cached array. This
  protects RP entries written since the array was last loaded and avoids a
  position-shift wrong-delete (matching the add/edit/CLI paths).
- **Clearer destructive-action wording** — the "Clear all storage" action and the
  FIDO reset-dialog hint now state plainly that clearing erases every large-blob
  entry, including relying-party data, not just keyroost's notes.
- **OATH unlock submits on Enter** — pressing Enter in the OATH unlock field now
  submits, matching the FIDO2 unlock card and the rest of the redesign.

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

[Unreleased]: https://github.com/framefilter/keyroost/compare/v0.7.2...HEAD
[0.7.2]: https://github.com/framefilter/keyroost/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/framefilter/keyroost/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/framefilter/keyroost/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/framefilter/keyroost/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/framefilter/keyroost/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/framefilter/keyroost/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/framefilter/keyroost/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/framefilter/keyroost/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/framefilter/keyroost/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/framefilter/keyroost/releases/tag/v0.1.0
