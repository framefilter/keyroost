# Release fanout — one-time setup

When release.yml publishes a GitHub Release, it dispatches
`.github/workflows/publish.yml`, which fans the release out to the package
channels below. Each channel is a thin pointer at the
release's attested artifacts; nothing is rebuilt. Jobs whose secret isn't
configured yet skip with a notice, so channels can be enabled one at a time.

**Before anything else:** create an environment protection rule —
Settings → Environments → `release-publish` → add yourself as a required
reviewer. Every fanout job then pauses for one click before any publish
credential is touched.

## crates.io (no stored secret)

1. First publish is manual, in dependency order: `cargo login`, then
   `cargo publish -p <crate> --locked` crate by crate, waiting ~a minute
   between dependents for index propagation. **The order is the `for crate
   in …` list in `.github/workflows/publish.yml`** — the one copy that is
   validated (`packaging/check-publish-readiness.sh` asserts it covers every
   workspace member in topological order). A prose copy of the list here
   went stale at 15 of 18 crates; don't reintroduce one.
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
   three templates in `packaging/winget/` (`@VERSION@`, and `@SHA_WIN@` from
   the **signed** zip's `.sha256` sidecar — see the note below) and PR them to
   `microsoft/winget-pkgs` under
   `manifests/f/Framefilter/Keyroost/<version>/`, or run
   `wingetcreate new` interactively.
2. Create a classic PAT with `public_repo`; add it as secret `WINGET_TOKEN`.
3. Version bumps are PR'd by the workflow, but **not on the release run**.
   Since v0.7.6 the winget job holds for the Token2-signed Windows build
   (policy, 2026-07-17): on the tag fanout it prints
   `winget is HOLDING for the Token2-signed build` and exits 0. **That skip is
   the designed outcome, not a failure.** The submission happens later:

   ```text
   tag → fanout (winget notices + skips)
       → Token2 signs → maintainer attaches
         keyroost-vX.Y.Z-windows-x86_64-signed.zip (+ .sha256) as NEW assets
         (never replacing the CI zips — that invalidates SHA256SUMS/provenance)
       → gh workflow run publish.yml -f tag=vX.Y.Z
       → every other job no-ops; winget Authenticode-verifies every PE in the
         zip, then submits the PR
   ```

   Microsoft's validation pipeline merges routine bumps within hours to days.
   A hard *failure* of this job (rather than a skip) means the `WINGET_TOKEN`
   PAT is set but rejected — renew it. Full release-day sequence:
   [`RELEASING.md`](RELEASING.md) steps 4–5.

## What a release looks like afterwards

```text
git tag -s vX.Y.Z -m "keyroost vX.Y.Z" && git push origin vX.Y.Z
  → release.yml: builds Linux/macOS/Windows archives, SHA256SUMS,
    provenance attestation, publishes the GitHub Release
  → linux-bundles.yml (same tag, in parallel): AppImage + flatpak bundle,
    attached to that same Release
  → publish.yml (dispatched by release.yml; runs after your one-click
    environment approval):
      crates.io  — the whole workspace in dependency order (OIDC)
      AUR        — keyroost-bin PKGBUILD/.SRCINFO push
      Homebrew   — tap formula push
      winget     — SKIPS with a notice: holds for the Token2-signed zip,
                   then submits on a re-dispatch (see above)
  → cargo-binstall needs nothing: it finds the new archives by version
```
