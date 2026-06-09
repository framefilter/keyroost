# Security Policy

## Reporting a vulnerability

Use GitHub's private vulnerability reporting ("Report a vulnerability" under
the Security tab) so the report stays out of public issues until a fix
ships. If that's unavailable, open an issue saying only that you have a
sensitive report and a maintainer will arrange a private channel — please
don't put details in the issue itself.

You can expect an acknowledgement within a week. There is no bounty
program; credit in the changelog is offered.

## Supported versions

Only the latest release receives security fixes. The tool talks to local
hardware and has no server component, so updating is the whole story.

## Threat model

What keyroost defends against:

- **Malicious or malformed input files.** Import parsers (otpauth URIs,
  Aegis/2FAS exports, encrypted vaults) are bounds-checked, reject
  attacker-controlled resource demands (e.g. hostile scrypt parameters),
  and authenticate ciphertexts before use.
- **Malicious or buggy devices.** Everything read from USB/NFC — APDU
  responses, TLV/BER structures, CBOR, CTAP-HID frames — is length-checked
  and bounded; a fuzzing device gets an error, not a hang or a panic.
- **Accidental secret disclosure by the tool itself.** Secrets are never
  written to disk; `--debug` traces redact secret-bearing command bodies;
  secret-typed memory (PINs, seeds, RSA components, session tokens) is
  zeroized on drop where Rust allows; secrets are accepted via env/stdin
  rather than argv.

What keyroost does **not** defend against:

- **A compromised host.** Code running as your user can read process
  memory and everything you can read. No host-side tool can fix this.
- **Physical attacks on the token itself**, or weaknesses in a device's
  own firmware/protocol. Notably, the Molto2's wire protocol (4-byte
  SM4-CBC-MAC truncation, SM4-ECB seed encryption keyed from the customer
  key) is fixed by the device; rotating the customer key away from the
  public factory default is the strongest available mitigation, and the
  CLI warns when you haven't.
- **Other software with access to the same device.** Anything the OS
  allows to open the token can talk to it; unplug keys you're not using.

## Invariants you can rely on

- **No network access, by design.** No crate in this workspace opens a
  socket or speaks HTTP; there is no telemetry, no update check, no
  "cloud". A release that broke this would be a security bug — report it
  as one.
- **No `unsafe` code.** `unsafe_code = "forbid"` is enforced
  workspace-wide.
- **Vendored protocol code, minimal dependencies.** SM4, SHA-1/256, HMAC,
  base32/hex, APDU/TLV/CBOR parsing are all in-tree. External
  dependencies are limited to a short, documented list (pcsc, clap,
  eframe/egui, serde, and scoped RustCrypto/rsa exceptions); each
  exception is justified in the relevant `Cargo.toml`.
- **No build scripts.** No workspace crate uses `build.rs`.
- **Reviewable releases.** Release binaries are built by CI from tagged
  commits using SHA-pinned actions, without shared build caches, with
  `SHA256SUMS` and a build-provenance attestation published alongside
  (`gh attestation verify <file> --repo <this repo>`).

## Verifying a download

```sh
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify keyroost-*-linux-x86_64.tar.gz --repo <owner>/<repo>
```

Or skip the question entirely and build from source with
`cargo build --release --locked`.
