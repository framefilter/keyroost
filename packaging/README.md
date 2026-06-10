# Release fanout — one-time setup

After a GitHub Release is published, `.github/workflows/publish.yml` fans it
out to the package channels below. Each channel is a thin pointer at the
release's attested artifacts; nothing is rebuilt. Jobs whose secret isn't
configured yet skip with a notice, so channels can be enabled one at a time.

**Before anything else:** create an environment protection rule —
Settings → Environments → `release-publish` → add yourself as a required
reviewer. Every fanout job then pauses for one click before any publish
credential is touched.

## crates.io (no stored secret)

1. First publish is manual, in dependency order (see the runbook in
   `TODO-hardening.md`): `cargo login`, then `cargo publish -p <crate>
   --locked` tier by tier.
2. On crates.io, for **each** crate: Settings → Trusted Publishing → add
   GitHub repository `framefilter/keyroost`, workflow `publish.yml`,
   environment `release-publish`.
3. Done — future releases publish via short-lived OIDC tokens; there is no
   long-lived secret to steal.

## AUR (`keyroost-bin`)

1. Create an AUR account; add a dedicated SSH key to it (not your personal
   key).
2. Create the package base once: clone
   `ssh://aur@aur.archlinux.org/keyroost-bin.git`, render
   `packaging/aur/{PKGBUILD,.SRCINFO}.template` by hand for the current
   release (fill `@VERSION@`, `@SHA_LINUX@` from SHA256SUMS, `@SHA_UDEV@` =
   sha256 of `udev/70-keyroost-fido.rules`), commit, push.
3. Add the SSH **private** key as repo secret `AUR_SSH_PRIVATE_KEY`.

## Homebrew tap

1. Create a public repo `framefilter/homebrew-keyroost` (empty is fine; the
   workflow creates `Formula/keyroost.rb`).
2. Create a fine-grained PAT with `contents: write` on **that repo only**;
   add it as secret `TAP_PUSH_TOKEN`.
3. Users: `brew tap framefilter/keyroost && brew install keyroost`.

## winget (`Framefilter.Keyroost`)

1. First submission is manual (Microsoft reviews new packages): fill the
   three templates in `packaging/winget/` (`@VERSION@`, `@SHA_WIN@` from
   SHA256SUMS) and PR them to `microsoft/winget-pkgs` under
   `manifests/f/Framefilter/Keyroost/<version>/`, or run
   `wingetcreate new` interactively.
2. Create a classic PAT with `public_repo`; add it as secret `WINGET_TOKEN`.
3. Future version bumps are PR'd automatically; Microsoft's validation
   pipeline merges routine bumps within hours to days.

## What a release looks like afterwards

```text
git tag v0.4.0 && git push origin v0.4.0
  → release.yml: builds Linux/macOS/Windows archives, SHA256SUMS,
    provenance attestation, publishes the GitHub Release
  → publish.yml (after your one-click environment approval):
      crates.io  — 14 crates in dependency order (OIDC)
      AUR        — keyroost-bin PKGBUILD/.SRCINFO push
      Homebrew   — tap formula push
      winget     — version-bump PR to microsoft/winget-pkgs
  → cargo-binstall needs nothing: it finds the new archives by version
```
