# Security Policy

## Reporting a vulnerability

Use GitHub's private vulnerability reporting ("Report a vulnerability" under
the Security tab) so the report stays out of public issues until a fix
ships. If that's unavailable, open an issue saying only that you have a
sensitive report and a maintainer will arrange a private channel — please
don't put details in the issue itself.

You can expect an acknowledgement within a week. There is no bounty
program; credit in the changelog is offered.

Please give a reasonable window before public disclosure — the aim is a fix
and an advisory within 90 days of the report, sooner for anything actively
exploitable. If GitHub is not a workable channel for you, say so in a
content-free issue and a maintainer will arrange an alternative.

Out of scope as vulnerabilities: keyroost displaying a secret you asked it
to display on your own terminal or screen; a compromised host reading the
process's memory; and physical or firmware attacks on the token itself (see
the threat model below).

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
- **Accidental secret disclosure by the tool itself.** keyroost persists no
  secrets of its own accord — the only files it writes unprompted are the
  friendly-name registry (`keys.json`) and the GUI's `settings.json`, both
  created owner-only (`0600`) and neither holding key material. Secret
  output reaches disk only when you name a destination for it (e.g.
  `openpgp decrypt --out`), and those writes go through an owner-only
  temp file that is fsynced and atomically renamed, refusing to follow a
  symlink or to overwrite a file owned by another user. `--debug` traces
  redact secret-bearing command bodies on every applet — Molto2 secure
  writes, OATH `PUT`/`SET CODE`/`VALIDATE`, OpenPGP key import and decipher,
  PIV `GENERAL AUTHENTICATE`, the Token2 OTP seed writes and code reads, and
  CTAP CBOR exchanges, in both directions where a response is as revealing
  as the request. Secret-typed memory is zeroized on drop where Rust
  allows — PINs, CTAP session secrets and per-credential largeBlob keys,
  RSA key components, imported TOTP seeds, and the decrypted-vault /
  QR-payload buffers they pass through (buffer reallocations and
  library-internal copies remain out of reach); secrets are accepted via
  env/stdin rather than argv.

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
  network socket, resolves a hostname, or speaks HTTP; there is no
  telemetry, no update check, no "cloud". A release that broke this would
  be a security bug — report it as one. Two things look adjacent and are
  not: the GUI's "Learn" link hands a documentation URL to your browser
  (keyroost makes no connection itself), and the Wayland screenshot path
  talks to `xdg-desktop-portal` over the session bus, which is local IPC.
- **`unsafe` only in two scoped FFI shims.** `unsafe_code = "forbid"` is
  the workspace-wide default; the sole exceptions are the Windows-only
  `keyroost-winwebauthn` (HID enumeration / shell launch) and
  `keyroost-screengrab` (GDI screen capture) crates, which set
  `unsafe_code = "allow"` to confine their thin `windows-sys` FFI. Both
  are inert on non-Windows targets. No `unsafe` appears in any
  cross-platform crate.
- **Vendored protocol code, scoped dependencies.** SM4, SHA-1/256/512, the
  OATH HMAC, base32/hex, and the APDU/TLV/CBOR and `otpauth://` parsers are
  implemented in-tree with no external crate; `keyroost-proto` and
  `keyroost-resolve` carry no external dependencies at all, and the OATH,
  OpenPGP, PIV and Token2 single-profile byte layers carry nothing but
  `zeroize`. That does not mean no external hash code is in the tree: where
  the CTAP and Token2-OTP paths need those primitives inside a larger
  construction (client-PIN, ECDH, largeBlob), they use RustCrypto's `sha2`
  and `hmac` rather than a hand-rolled equivalent. What is pulled in is
  deliberate, confined to the crate that needs it, and
  annotated in the `Cargo.toml` that declares it: the device and OS
  boundary (`pcsc`; `hidapi` off Linux, where sysfs and `hidraw` are used
  directly; `windows-sys` on Windows), the interface boundary (`clap` and
  `clap_complete`/`clap_mangen`; `eframe`/`egui` with `arboard`, `rfd`,
  `pollster`, `png` and Linux's `x11rb`/`ashpd`; `serde`/`serde_json` and
  `base64`), and cryptography that would be irresponsible to hand-roll
  under `forbid(unsafe_code)` — RustCrypto (`sha2`, `hmac`, `aes`, `des`,
  `cbc`, `cipher`, `p256`, `aes-gcm`), `getrandom`, `zeroize`, `scrypt`
  (Aegis vaults), `rsa`/`rand` (host RSA keygen, confined to
  `keyroost-rsakey`), `p384`/`ed25519-dalek`/`x25519-dalek` (host-side
  verification of the PIV slot self-test, confined to `keyroost-pivtest`),
  and `miniz_oxide` (CTAP large-blob deflate). QR and
  image decoding (`rqrr`, `png`, `jpeg-decoder`) is confined to
  `keyroost-qr`. The README's "Workspace layout" table lists them per
  crate. No new dependency lands without that justification.
- **One build script, Windows-only.** The workspace has exactly one
  `build.rs` (`crates/keyroost/build.rs`). It embeds the application icon
  and the `VS_VERSION_INFO` resource into `keyroost.exe` so that CI,
  `cargo install` and vendor-signed builds all produce the same bytes plus
  a signature. It is `#[cfg(windows)]` — an empty `main()` on every other
  target — and its sole build-dependency (`winresource`) is declared under
  `[target.'cfg(windows)'.build-dependencies]`, so a Linux or macOS build
  neither fetches nor runs it. No build script in this workspace generates
  code, downloads anything, or reads outside its own package.
- **Continuously fuzzed and dependency-audited.** The parsers named in the
  threat model are covered by sixteen `cargo-fuzz` targets
  (`fuzz/fuzz_targets/`) run on a weekly schedule; a RUSTSEC scan
  (`cargo audit`) runs weekly and on every change to a manifest or the
  lockfile, and Dependabot proposes monthly updates for both the cargo and
  the GitHub-Actions dependency sets. The fuzz harness is its own workspace
  so its nightly-only toolchain requirement never enters the shipped
  dependency tree.
- **Reviewable releases.** Release binaries are built by CI from tagged
  commits using SHA-pinned actions, without shared build caches (a tag
  build would otherwise fall back to default-branch caches), with
  `SHA256SUMS` and a build-provenance attestation published alongside
  (`gh attestation verify <file> --repo framefilter/keyroost`). The
  crates.io fanout authenticates through Trusted Publishing (OIDC), so no
  long-lived registry token exists to be stolen.

## Release integrity

Four mechanisms:

- **Signed tags.** Release tags are signed by the maintainer with a hardware
  key; tag creation is restricted to the repository admin by ruleset. The
  maintainer reviews the complete diff since the previous release before
  signing, so the tag signature covers every change in the release,
  including merged contributions.
- **Build provenance.** Release assets carry GitHub build-provenance
  attestations identifying the workflow run and commit that produced them.
  Verification command below.
- **Checksums.** `SHA256SUMS` covers the platform archives. The AppImage and
  flatpak publish separate `.sha256` files.
- **crates.io Trusted Publishing.** Crates are published by the release
  workflow over OIDC. No long-lived publishing token exists.

Commits on `main` are not required to be signed. Changes land through
reviewed pull requests (`packaging/REVIEWING.md` is the review checklist);
only the maintainer can merge, and workflow runs for outside contributors
start only after maintainer approval. Per-commit signature enforcement was
removed because it prevented merging external pull requests, and it does
not address the relevant attack class: a compromised or malicious committer
produces validly signed commits, as in the xz-utils backdoor. The
mechanisms above verify that a release matches the public source, which is
the property that attack violates.

## Verifying a download

```sh
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify keyroost-*-linux-x86_64.tar.gz --repo framefilter/keyroost
```

The release assets are named `keyroost-<tag>-linux-x86_64.tar.gz`,
`keyroost-<tag>-macos-universal2.tar.gz` and
`keyroost-<tag>-windows-x86_64.zip`; `SHA256SUMS` covers all three.

Or skip the question entirely and build from source with
`cargo build --release --locked`.
