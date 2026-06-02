# Context for Claude Code agents working on keyroost

## What this repository is

Independent, MIT/Apache-2.0 dual-licensed Rust toolchain for programming the
Token2 Molto2 / Molto2v2 programmable TOTP hardware token. Built from scratch
based on observation of the device protocol; not a fork of Token2's Python
tool. Workspace contains:

| Crate | Purpose | External deps |
|---|---|---|
| `keyroost-proto` | Pure-Rust protocol layer (SM4, SHA-1, APDU builders, MAC) | none |
| `keyroost-transport` | PC/SC reader discovery, Molto2 session, YubiKey CCID serial, OATH + OpenPGP applets | `pcsc` |
| `keyroost-hid` | USB HID enumeration of FIDO devices via sysfs | none |
| `keyroost-ctap` | FIDO2/CTAP-HID transport, CBOR, PIN protocols, credential mgmt | none |
| `keyroost-oath` | Pure-Rust Yubico/Trussed OATH (TOTP/HOTP) byte layer (APDU + TLV) | none |
| `keyroost-openpgp` | Pure-Rust OpenPGP Card v3.4 byte layer (APDU + BER-TLV) | none |
| `keyroost-piv` | Pure-Rust PIV (SP 800-73-4) byte layer; read path (status/GET DATA) | none |
| `keyroost-keyring` | Friendly-name registry (`keys.json`); serial matching, no hardware | `serde`, `serde_json` |
| `keyroost-resolve` | Shared key-identity resolution (USB + CCID serials, topology match) | in-tree only |
| `keyroost-rsakey` | Host-side RSA-2048 keygen + PKCS#1/PKCS#8 (PEM/DER) loading for OpenPGP import | `rsa`, `rand` (scoped exception) |
| `keyroost-import` | otpauth:// + Aegis / 2FAS / otpauth-list parsers | `serde`, `serde_json` (behind `bulk` feature) |
| `keyroostctl` | CLI binary | `clap` |
| `keyroost` | egui desktop GUI | `eframe`, `egui` |

## Where to start reading

1. **`docs/PROTOCOL.md`** — wire format reference. APDU opcodes, the SM4-CBC
   MAC, the config TLV. Written about the device itself; doesn't reference any
   third-party implementation.
2. **`docs/BRINGUP.md`** — step-by-step plan for first-time hardware bring-up.
   This is the runbook the user wants to execute. Steps 1–4 are read-only or
   write to slot #99 only; steps 5+ are progressively riskier.
3. **`crates/keyroost-proto/src/`** — the protocol layer is the cleanest place
   to understand command construction. Start with `commands.rs`.

## The user's immediate goal

Program their Molto2 from a machine they control, with Claude Code running
locally so debug output and APDU hex traces can be diagnosed in-context. The
workflow during bring-up is:

1. User runs `keyroostctl --debug <subcommand>`.
2. If something looks wrong (status word other than `9000`, garbled response,
   wrong on-device behavior), agent diffs the captured hex against
   `docs/PROTOCOL.md` and edits the offset / framing in either
   `crates/keyroost-transport/src/lib.rs::read_info` or
   `crates/keyroost-proto/src/commands.rs`.
3. `cargo build --release` and retry. The binary is exposed on PATH via a
   symlink (`~/.local/bin/keyroostctl -> target/release/keyroostctl`), so a rebuild is
   live immediately — no copy step. (`~/bin` is intentionally not used; on this
   Debian box `~/.cargo/bin` and `~/.local/bin` are already on PATH.)

## Known soft spots — most likely places for first-contact bugs

- **`read_info()` response parsing** in `keyroost-transport/src/lib.rs`. The
  3-byte preamble and 2-byte separator are taken on faith from the reference
  Python script; the real bytes might be structured differently.
- **`get info` length field.** We treat `info[3]` as the serial-string length.
  If the serial looks garbled, that offset is suspect.
- **MAC framing edge case.** Our MAC uses CLA `0x80` in the AAD header even
  though the wire APDU uses `0x84` (matches the Python tool's behavior). If
  the device rejects a secure command with `SW 6A 80` (wrong data), this is
  the first thing to check.
- **Lock / unlock APDUs** are intentionally not implemented. The reference's
  unlock variant is mis-framed; needs hardware probing before we add it.

## Conventions

- **Don't push to remote without explicit user permission.** Local commits are
  fine; `git push` only when the user says so.
- **Vendor over depend.** SM4, SHA-1, base32, hex, and otpauth parsing are all
  in-tree. PCSC, clap, eframe, serde are the only acceptable external deps.
  No new deps without a discussion first.
- **No documentation files unless explicitly asked.** The two files in `docs/`
  exist for legal posture and bring-up; don't add more without asking.
- **Tests first when changing the protocol layer.** The known-answer suite in
  `crates/keyroost-proto/tests/known_answer_vs_python.rs` locks in byte-level
  agreement with an independent third-party SM4 implementation. Any change to
  command construction must keep those tests green or be paired with a written
  justification for the new expected bytes.
- **Linux build prerequisite:** `sudo apt install libpcsclite-dev pcscd`.

## Running

```bash
# all 50+ tests
cargo test --workspace --offline

# CLI
cargo run -p keyroostctl -- --help
cargo run -p keyroostctl -- --debug info

# GUI
cargo run -p keyroost
```

## Commit style

The repo uses descriptive commits oriented around *why*, not *what*. See
`git log --oneline` for examples. Sign off via the standard footer the harness
appends; don't add the model identifier (`claude-opus-4-7[1m]`) to commits.

## Privacy & secrets (enforced — see `.claude/`)

This is a security-key management tool. Treat PINs, credential listings, and
host secrets as untouchable. A PreToolUse hook (`.claude/hooks/guard.sh`)
enforces the rules below; **don't try to work around the guard** — if it
blocks something, that's intended.

- **Destructive FIDO ops** (`keyroostctl fido-reset`, `fido-creds-delete`) are
  irreversible. This checkout is used only with disposable **test keys**, so
  the guard no longer blocks them — still treat them with care and never point
  them at a security key in real use.
- **Never print or read secrets.** Don't `printenv`, don't `echo` a
  PIN/password/token variable, don't read `.env`, `*.pem`, SSH keys, or
  NetworkManager / `wpa_supplicant` WiFi configs. (Hook-blocked.)
- **PIN entry is the user's job.** PINs come from `--pin-env` / `--pin-stdin`
  the user sets in their own shell. Don't ask for the PIN, don't place it in
  argv, don't read it back.
- **Credential listings are private.** `fido-creds-list` reveals which services
  the user has accounts with. Don't run it speculatively; if the user shares
  output, don't echo usernames / RP names beyond what the task needs.
- **Safe to run freely against any key:** `keyroostctl list`, `keyroostctl fido-info`,
  `keyroostctl fido-pin-retries` (read-only, no PIN, no counter change).
