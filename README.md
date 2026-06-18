# keyroost

An independent, open-source Rust toolchain for managing hardware security keys —
across vendors — over PC/SC and USB HID. It speaks FIDO2/CTAP2, OATH (TOTP/HOTP),
and the OpenPGP card protocol, and also programs the Token2 Molto2 / Molto2v2 TOTP
token it started life targeting. Ships a Rust library, a CLI (`keyroostctl`), and a
dark-themed desktop GUI (`keyroost`) — implemented from public standards, with no
vendor SDKs, no Python, and no Qt.

> **Built with AI.** I saw a real need for this but never learned to code, so
> keyroost — code, docs, and all — was written end-to-end with AI. Since that AI
> learned from the vast commons of free and open-source software people have
> generously shared, releasing keyroost as FOSS isn't really a choice; it's
> giving back to what made it possible. Absent outside contributors it will stay
> AI-authored — issues and review are warmly welcome.

**New to hardware keys?** Read the companion guide —
[*"So you bought a hardware security key… now what?"*](https://framefilter.github.io/keyroost/) —
a short, vendor-neutral tour of what FIDO2, OATH, OpenPGP, and PIV actually do.

## What it does

- **FIDO2 / CTAP2** — enumerate authenticators, read `authenticatorGetInfo`,
  manage resident credentials (list / metadata / delete), set / change / verify
  the PIN, reset a key. PIN protocols v1 and v2.
- **OATH (TOTP/HOTP)** — list, add, delete, and compute codes over PC/SC,
  including applet-password set / clear / unlock.
- **OpenPGP card (v3.4)** — read status; generate or import RSA-2048 keys (host
  keygen or a PKCS#1/PKCS#8 PEM/DER file); sign (SHA-256 or SHA-1); decrypt; set
  cardholder name / URL; register a key for GnuPG; factory-reset the applet.
- **PIV (SP 800-73-4)** — read-only status so far: applet/firmware version,
  serial, PIN retries, and which key slots (9A/9C/9D/9E) hold a certificate.
- **Token2 Molto2 / Molto2v2** — program a slot from an `otpauth://` URI;
  bulk-import from Aegis (plaintext or encrypted), 2FAS, or a list of `otpauth://`
  URIs; sync the host clock; rotate the customer key; factory reset.
- **Friendly device names** — an opt-in `keys.json` registry to target a specific
  physical key by name when several are connected, instead of by a reshuffling
  `/dev/hidrawN` path. Destructive operations always resolve to an explicit
  target, never a default.

## Supported devices

| Device | Capabilities | Notes |
|---|---|---|
| **Token2 Molto2 / Molto2v2** | TOTP slot programming | The original target. |
| **Token2 PIN+ Series** | FIDO2, OTP, OpenPGP, PIV | Also supports on-device OTP, including TOTP/HOTP and HID/keyboard-based HOTP. |
| **YubiKey** (5 series) | FIDO2, OATH, OpenPGP | Built and verified against a YubiKey 5.7. |
| **SoloKeys Solo 2** | FIDO2, OATH | Trussed firmware; no OpenPGP applet. |
| **Nitrokey 3** | FIDO2, OATH | Shares the Solo 2 / Trussed stack. |

Other CCID/FIDO devices implementing these standard applets may work; the table
is what the project has been built and tested against.

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
  ([#24](https://github.com/framefilter/keyroost/pull/24)).

(This credits their contribution to the codebase; it does not change keyroost's
independent status described above.)

## Design principles

- **Vendor over depend.** SM4, SHA-1/256, base32, hex, CBOR, CTAP-HID framing,
  the OATH/OpenPGP byte layers, and `otpauth://` parsing are all in-tree. The only
  external deps are `pcsc`, `clap`, `eframe`/`egui`, `serde`, and — for RSA
  keygen/parsing alone — `rsa`/`rand`.
- **Pure-Rust crypto**, checked against standard test vectors.
- **Secrets stay yours.** PINs and passwords come from stdin or env vars, never
  argv; the tool never prints or persists them.
- **Single static binary per OS** — no scripts, no Python, no Qt.

## Install

```bash
cargo install keyroostctl keyroost
```

### Linux prerequisite

keyroost is mostly¹ distro-neutral — it talks to the kernel's `hidraw`/`sysfs` and to
PC/SC, both of which every mainstream distribution provides. Only the package
names differ. The CLI needs the PC/SC library + daemon; the GUI additionally
needs the X11/Wayland/GL libraries that `eframe`/`egui` link against.   
¹the cargo install does not support atomic distros like Bazzite.

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

> **Windows and FIDO:** Windows reserves raw FIDO HID access for elevated
> processes (the OS routes normal apps through its own WebAuthn API instead).
> Expect the `fido-*` commands and the Security Keys pane to require an
> elevated ("Run as administrator") session on Windows; the Molto2, OATH,
> OpenPGP, and PIV features go over PC/SC and work unelevated. Elevate for
> the FIDO command you need, then drop back — don't run the whole tool
> elevated as a habit.

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

### FIDO HID access (Linux udev rules)

The OATH, OpenPGP, and PIV applets are reached over PC/SC and need no special
permissions. Talking to a key's **FIDO interface** (`fido-*` commands, and the
Security Keys GUI pane), though, opens a `/dev/hidraw*` node, which is
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
# discover connected devices: PC/SC readers + FIDO HID authenticators
keyroostctl list

# --- FIDO2 (YubiKey / Solo 2 / Nitrokey 3) ---
keyroostctl fido-info
keyroostctl fido-pin-retries
keyroostctl fido-creds-list --pin-stdin        # PIN read from stdin, never argv

# --- OATH over PC/SC ---
keyroostctl oath list --reader yubikey
keyroostctl oath code <name> --reader yubikey

# --- OpenPGP card ---
keyroostctl openpgp status --reader yubikey
keyroostctl openpgp sign --in msg.txt --pin-stdin --reader yubikey

# --- PIV (read-only status) ---
keyroostctl piv status --reader yubikey

# --- Token2 Molto2 (TOTP programming) ---
keyroostctl info
keyroostctl import --profile 0 'otpauth://totp/GitHub:me@x.com?secret=JBSWY3DPEHPK3PXP'
keyroostctl import-file ~/Downloads/aegis.json --start 0 --dry-run   # validate first

# name a key to target it when several are plugged in (opt-in)
keyroostctl key-name list

# launch the GUI (tabs: Molto2 profiles, Security Keys, OATH, OpenPGP)
keyroost
```

## Workspace layout

| Crate | Purpose | External deps |
|---|---|---|
| `keyroost-proto` | Pure-Rust Molto2 wire protocol (SM4, SHA-1, SHA-256, APDU, MAC) | none |
| `keyroost-transport` | PC/SC discovery, Molto2 session, YubiKey CCID serial, OATH + OpenPGP applets | `pcsc` |
| `keyroost-hid` | USB HID enumeration of FIDO devices via sysfs | none |
| `keyroost-ctap` | FIDO2/CTAP-HID transport, CBOR, PIN protocols, credential management | none |
| `keyroost-oath` | Pure-Rust Yubico/Trussed OATH (TOTP/HOTP) byte layer | none |
| `keyroost-openpgp` | Pure-Rust OpenPGP Card v3.4 byte layer (APDU + BER-TLV) | none |
| `keyroost-piv` | Pure-Rust PIV (SP 800-73-4) byte layer; read path (status / GET DATA) | none |
| `keyroost-keyring` | Friendly-name registry (`keys.json`); serial matching | `serde`, `serde_json` |
| `keyroost-resolve` | Shared key-identity resolution (USB + CCID serials, topology match) | in-tree only |
| `keyroost-rsakey` | Host-side RSA-2048 keygen + PKCS#1/PKCS#8 (PEM/DER) loading | `rsa`, `rand` |
| `keyroost-import` | `otpauth://` + Aegis / 2FAS / otpauth-list parsers | `serde`, `serde_json` (behind `bulk`) |
| `keyroostctl` | Command-line interface | `clap` |
| `keyroost` | egui desktop GUI | `eframe`, `egui` |

## Protocol

The Molto2 wire protocol is documented in [`docs/PROTOCOL.md`](docs/PROTOCOL.md)
— the APDUs, the SM4-based MAC, and the TLV config payload, described as facts
about the device rather than any one implementation. The FIDO2, OATH, and OpenPGP
layers follow their respective public standards.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option. Unless you explicitly state otherwise, any contribution
intentionally submitted for inclusion in the work by you, as defined in the
Apache-2.0 license, shall be dual licensed as above, without any additional
terms or conditions.

This dual-license is the Rust ecosystem default and matches what `serde`,
`tokio`, `clap`, and most of the ecosystem use.
