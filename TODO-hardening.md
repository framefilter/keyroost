# Hardening & UX TODO

Working list from the June 2026 security review follow-up. Items are ordered
by the sequence they're being implemented in, not priority. Checked items are
done and committed on this branch.

## Phase 1 — CI / release pipeline (config-only)

- [x] Dependabot: add `cargo` ecosystem (currently only `github-actions`)
- [x] Release: emit `SHA256SUMS` alongside the archives
- [x] Release: GitHub artifact attestation (build provenance) on published archives
- [x] CI: `cargo audit` job (RUSTSEC advisories) on lockfile changes + weekly

## Phase 2 — CLI / GUI quick wins

- [x] Warn when programming Molto2 seeds under the factory-default customer key
- [x] `info`: warn when device clock drifts >30s from host (suggest `sync-time`)
- [x] GUI: clear the seed draft field after a successful write
- [x] GUI: auto-clear clipboard ~45s after copying an OTP code

## Phase 3 — memory hygiene round 2

- [x] Zeroize `PinUvAuthToken` and the CTAP shared secrets on drop
- [x] Zeroize CLI-side secret strings (`read_secret` / `gather_secret` returns)
- [x] Zeroize imported TOTP seeds: `BulkEntry.secret` and `OtpAuth.secret`
      wipe on drop (with Debug redacted to the byte count), and the decrypted
      Aegis plaintext, GA migration buffers, and decoded QR payloads ride in
      `Zeroizing` wrappers end to end

## Phase 4 — documentation

- [x] `SECURITY.md`: threat model, the no-network-access invariant, secret
      handling guarantees, disclosure process
- [x] README: document Windows elevation requirements for FIDO HID access

## Phase 5 — CLI features

- [x] `completions` subcommand (shell completions via clap_complete)
- [x] `manpage` subcommand (troff output via clap_mangen)
- [x] `import-file --dry-run`: print the slot/title/config plan without
      touching the device — *already existed upstream; verified working*
- [x] `doctor` subcommand: diagnose pcscd, readers, udev rules, hidraw
      access, keys.json permissions
- [x] Destructive commands (`fido-reset`, `fido-creds-delete`,
      `factory-reset`): show the resolved friendly name + serial in the
      confirmation/refusal message

## Phase 6 — fuzzing

- [x] `fuzz/` crate with cargo-fuzz targets for the hand-rolled parsers:
      otpauth URI, base32, CBOR, OATH TLV, OpenPGP BER-TLV, PIV BER
- [x] Scheduled CI job running each target briefly (nightly toolchain)

## crates.io publish runbook (readiness verified 2026-06)

All crates carry version/license/description metadata and `cargo package`
succeeds for every crate without in-workspace deps; the rest resolve once
their deps are live (normal first-publish ordering). With a crates.io token
(`cargo login`), publish in this order, waiting ~a minute between tiers for
index propagation:

1. `keyroost-proto`, `keyroost-hid`, `keyroost-keyring`, `keyroost-rsakey`
2. `keyroost-ctap`, `keyroost-oath`, `keyroost-openpgp`, `keyroost-piv`,
   `keyroost-import`
3. `keyroost-transport` (needs proto/oath/openpgp/piv), then
   `keyroost-resolve` (needs transport) and `keyroost-qr` (needs import)
4. `keyroostctl`, `keyroost`

Afterwards `cargo install keyroostctl` / `cargo install keyroost` work for
anyone with the Linux build prerequisites from the README.

## Deferred — decisions or external work needed

- [x] **QR code import** — done: keyroost-qr crate (rqrr/png/jpeg-decoder
      exception), PNG+JPEG screenshots, Google Authenticator migration
      batches, CLI `import --qr` / `import-file <image>`, GUI drag-drop,
      fuzz targets, end-to-end fixtures.
- [x] **Packaging** — automated fanout in .github/workflows/publish.yml
      (crates.io via OIDC trusted publishing, AUR, Homebrew tap, winget),
      templates + one-time setup steps in packaging/. Remaining manual:
      the account/secret setup and first publishes per packaging/README.md.
      Flatpak ruled out (pcscd/hidraw sandboxing).
- [x] **Branch/tag protection (light)** — repository rulesets: `v*` tag
      creation/update/deletion is admin-only (tag push is release
      authority), and `main` rejects force-pushes and deletion for
      everyone. Direct pushes to `main` remain allowed.
- [ ] **Branch protection (full)** — require PR + green CI for `main`.
      Deliberately deferred until the product is feature-complete and
      stable: it ends the direct-push workflow, so adopt it when release
      cadence slows.
- [ ] **PIV write path** — keyroost-piv is read-only by design so far (the
      only PIV commit is the read-path foundation; status/version/serial/
      cert presence). Full functionality means: management-key
      authentication (GENERAL AUTHENTICATE), key generation in the four
      slots, certificate import (PUT DATA), and PIN/PUK/management-key
      changes — SP 800-73-4 byte layer first (vendored, tests), then
      transport, CLI, GUI. Generalizes across YubiKey/Nitrokey since PIV
      is a NIST standard.
- [ ] **Publish-channel accounts** — one-time setup per packaging/README.md
      before the first release: the `release-publish` environment approval
      gate, crates.io account + manual first publish + trusted-publisher
      grants, AUR account/SSH key + first `keyroost-bin` push, the Homebrew
      tap repo + `TAP_PUSH_TOKEN`, and the manual first winget submission +
      `WINGET_TOKEN`. Channels can be enabled one at a time; unset secrets
      skip cleanly.
- [x] **GUI: move slow imports off the frame loop** — QR decode, vault
      decrypt, and export parse run on a dedicated import thread (not the
      device worker, which serializes card I/O behind whatever runs on it);
      the dialog shows a spinner and blocks Load / Program all while one is
      in flight.
- [x] **Wayland clipboard clear** — documented in the README as best-effort
      on pure-Wayland sessions without XWayland clipboard sync (no complete
      fix known; wl-data-control is wlroots-only).
- [x] **CI cache for fuzz/audit jobs** — Swatinem/rust-cache (cache-bin
      covers the installed binaries) added to both workflows.
- [x] **Clipboard conditional clear** — done via arboard (already in the
      tree through eframe): clears only when the clipboard still holds the
      copied code; fails open if unreadable.
