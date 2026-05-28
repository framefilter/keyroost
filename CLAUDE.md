# Context for Claude Code agents working on MoltoUI

## What this repository is

Independent, MIT/Apache-2.0 dual-licensed Rust toolchain for programming the
Token2 Molto2 / Molto2v2 programmable TOTP hardware token. Built from scratch
based on observation of the device protocol; not a fork of Token2's Python
tool. Workspace contains:

| Crate | Purpose | External deps |
|---|---|---|
| `molto2-proto` | Pure-Rust protocol layer (SM4, SHA-1, APDU builders, MAC) | none |
| `molto2-transport` | PC/SC reader discovery and session | `pcsc` |
| `molto2-import` | otpauth:// + Aegis / 2FAS / otpauth-list parsers | `serde`, `serde_json` (behind `bulk` feature) |
| `moltoctl` | CLI binary | `clap` |
| `moltoui` | egui desktop GUI | `eframe`, `egui` |

## Where to start reading

1. **`docs/PROTOCOL.md`** — wire format reference. APDU opcodes, the SM4-CBC
   MAC, the config TLV. Written about the device itself; doesn't reference any
   third-party implementation.
2. **`docs/BRINGUP.md`** — step-by-step plan for first-time hardware bring-up.
   This is the runbook the user wants to execute. Steps 1–4 are read-only or
   write to slot #99 only; steps 5+ are progressively riskier.
3. **`crates/molto2-proto/src/`** — the protocol layer is the cleanest place
   to understand command construction. Start with `commands.rs`.

## The user's immediate goal

Program their Molto2 from a machine they control, with Claude Code running
locally so debug output and APDU hex traces can be diagnosed in-context. The
workflow during bring-up is:

1. User runs `moltoctl --debug <subcommand>`.
2. If something looks wrong (status word other than `9000`, garbled response,
   wrong on-device behavior), agent diffs the captured hex against
   `docs/PROTOCOL.md` and edits the offset / framing in either
   `crates/molto2-transport/src/lib.rs::read_info` or
   `crates/molto2-proto/src/commands.rs`.
3. `cargo build --release && cp target/release/moltoctl ~/bin/` and retry.

## Known soft spots — most likely places for first-contact bugs

- **`read_info()` response parsing** in `molto2-transport/src/lib.rs`. The
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
  `crates/molto2-proto/tests/known_answer_vs_python.rs` locks in byte-level
  agreement with an independent third-party SM4 implementation. Any change to
  command construction must keep those tests green or be paired with a written
  justification for the new expected bytes.
- **Linux build prerequisite:** `sudo apt install libpcsclite-dev pcscd`.

## Running

```bash
# all 50+ tests
cargo test --workspace --offline

# CLI
cargo run -p moltoctl -- --help
cargo run -p moltoctl -- --debug info

# GUI
cargo run -p moltoui
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

- **Destructive FIDO ops** (`moltoctl fido-reset`, `fido-creds-delete`) are
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
- **Safe to run freely against any key:** `moltoctl list`, `moltoctl fido-info`,
  `moltoctl fido-pin-retries` (read-only, no PIN, no counter change).
