# MoltoUI

An independent, open-source toolchain for programming the Token2 Molto2 / Molto2v2
programmable TOTP hardware token. Ships a Rust library, a CLI (`moltoctl`), and a
dark-themed desktop GUI (`moltoui`).

> **Not affiliated with or endorsed by Token2 Sàrl.** This project is an independent
> implementation. The wire protocol was determined from observation of the device
> and the publicly distributed reference Python tool. SM4 and SHA-1 are implemented
> from their published standards (GB/T 32907-2016 and RFC 3174) and verified against
> independent third-party test vectors. *Token2* and *Molto2* are trademarks of
> Token2 Sàrl; they are used here in a descriptive sense only.

## Features

- Program one slot from an `otpauth://` URI (`moltoctl import`)
- Bulk-import from Aegis (plaintext or encrypted), 2FAS plaintext, or any list of
  `otpauth://` URIs (Authy via third-party extractors). Encrypted Aegis vaults
  are decrypted in-process via scrypt + AES-256-GCM.
- Sync the host's UTC clock to one profile or all profiles
- Rotate the customer key, factory reset, and the rest of the molto2.py command set
- 100-slot grid GUI with form editor, severity-colored log, and bulk-import dialog
- Pure-Rust crypto (SM4, SHA-1, base32) verified against standard test vectors
- Single static binary per OS; no scripts, no Python, no Qt

## Install

```bash
cargo install --git https://github.com/framefilter/moltoui moltoctl moltoui
```

(Once published to crates.io: `cargo install moltoctl moltoui`.)

### Linux prerequisite

PC/SC needs the system library and daemon:

```bash
sudo apt install libpcsclite-dev pcscd      # Debian / Ubuntu
sudo dnf install pcsc-lite-devel pcsc-lite  # Fedora
sudo systemctl enable --now pcscd
```

macOS and Windows have PC/SC built into the OS; nothing to install.

## Quick start

```bash
# show device info (no auth needed)
moltoctl info

# program a single slot from a URI
moltoctl import --profile 0 'otpauth://totp/GitHub:me@x.com?secret=JBSWY3DPEHPK3PXP'

# bulk-import a plaintext Aegis or 2FAS export
moltoctl import-file ~/Downloads/aegis.json --start 0 --dry-run   # validate
moltoctl import-file ~/Downloads/aegis.json --start 0             # program

# encrypted Aegis vault: pipe the password in
pass otp/aegis | moltoctl import-file ~/Downloads/aegis.json --start 0 --password-stdin
# or via env var
AEGIS_PW="…" moltoctl import-file ~/Downloads/aegis.json --start 0 --password-env AEGIS_PW

# sync time on all profiles
moltoctl sync-time --all

# launch the GUI
moltoui
```

## Workspace layout

| Crate | Description | External deps |
|---|---|---|
| `molto2-proto` | Pure-Rust protocol layer (SM4, SHA-1, APDU builders, MAC) | none |
| `molto2-transport` | PC/SC reader discovery, session, auth handshake | `pcsc` |
| `molto2-import` | `otpauth://` parser, plus optional Aegis/2FAS bulk parsers | `serde`, `serde_json` (behind `bulk` feature) |
| `moltoctl` | Drop-in CLI replacement for `molto2.py` | `clap` |
| `moltoui` | Desktop GUI | `eframe`, `egui` |

## Protocol

The wire protocol our tools speak is documented in [`docs/PROTOCOL.md`](docs/PROTOCOL.md).
It describes the APDUs, the SM4-based MAC, and the TLV-encoded config payload as
facts about the device — independent of any specific implementation.

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
