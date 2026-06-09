# Hardening & UX TODO

Working list from the June 2026 security review follow-up. Items are ordered
by the sequence they're being implemented in, not priority. Checked items are
done and committed on this branch.

## Phase 1 — CI / release pipeline (config-only)

- [ ] Dependabot: add `cargo` ecosystem (currently only `github-actions`)
- [ ] Release: emit `SHA256SUMS` alongside the archives
- [ ] Release: GitHub artifact attestation (build provenance) on published archives
- [ ] CI: `cargo audit` job (RUSTSEC advisories) on lockfile changes + weekly

## Phase 2 — CLI / GUI quick wins

- [ ] Warn when programming Molto2 seeds under the factory-default customer key
- [ ] `info`: warn when device clock drifts >30s from host (suggest `sync-time`)
- [ ] GUI: clear the seed draft field after a successful write
- [ ] GUI: auto-clear clipboard ~45s after copying an OTP code

## Phase 3 — memory hygiene round 2

- [ ] Zeroize `PinUvAuthToken` and the CTAP shared secrets on drop
- [ ] Zeroize CLI-side secret strings (`read_secret` / `gather_secret` returns)

## Phase 4 — documentation

- [ ] `SECURITY.md`: threat model, the no-network-access invariant, secret
      handling guarantees, disclosure process
- [ ] README: document Windows elevation requirements for FIDO HID access

## Phase 5 — CLI features

- [ ] `completions` subcommand (shell completions via clap_complete)
- [ ] `manpage` subcommand (troff output via clap_mangen)
- [x] `import-file --dry-run`: print the slot/title/config plan without
      touching the device — *already existed upstream; verified working*
- [ ] `doctor` subcommand: diagnose pcscd, readers, udev rules, hidraw
      access, keys.json permissions
- [ ] Destructive commands (`fido-reset`, `fido-creds-delete`,
      `factory-reset`): show the resolved friendly name + serial in the
      confirmation/refusal message

## Phase 6 — fuzzing

- [ ] `fuzz/` crate with cargo-fuzz targets for the hand-rolled parsers:
      otpauth URI, base32, CBOR, OATH TLV, OpenPGP BER-TLV, PIV BER
- [ ] Scheduled CI job running each target briefly (nightly toolchain)

## Deferred — decisions or external work needed

- [ ] **QR code import** — requires an image-decoding + QR dependency, which
      collides with the vendor-over-depend policy. Decide policy first.
- [ ] **Packaging** (AUR, Homebrew, winget; Flatpak unlikely due to
      pcscd/hidraw sandboxing) — external repos, separate effort.
- [ ] **Branch/tag protection** — repo settings, must be done in the GitHub
      UI by an admin: protect `main` (require PR + green CI), protect `v*`
      tags (maintainers only; tag push is release authority).
- [ ] **Clipboard conditional clear** — proper "only clear if we still own
      the clipboard" needs a clipboard-reading dependency (arboard). The
      Phase 2 implementation clears unconditionally; revisit if that annoys.
