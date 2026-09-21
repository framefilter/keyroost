# Release-day playbook

The whole cut, in order, from a clean tree to every channel verified. Run it
top to bottom; nothing here is optional unless marked so. Written after
v0.7.5/v0.7.6 — the traps called out below all actually happened.

Conventions: the maintainer runs everything that signs or publishes; an agent
may prepare branches and approve **build-only probe** gates, never a
publishing gate. Version placeholder below: `vX.Y.Z`.

## 1. Pre-flight (no version bump yet)

- [ ] `git fetch origin` — main clean, no unlanded branches you meant to ship.
- [ ] CI green on main (includes the CHANGELOG/Cargo.toml drift guard and the
      pinned-inputs check).
- [ ] `cargo audit` green (the audit workflow runs on pushes; check the last
      run) and the deps-outdated report reviewed.
- [ ] **Semver check against the published crates** — with 17 library crates
      on crates.io, Cargo treats 0.7.x -> 0.7.y as compatible, so an
      accidental API break in a patch release ships silently and breaks
      downstream `cargo update`:
      `cargo semver-checks --workspace --exclude keyroost --exclude keyroostctl`
      (install once: `cargo install cargo-semver-checks`). A reported break
      means either fix the API or bump the minor — a decision, not an
      accident. The binaries are excluded (nothing depends on them as
      libraries).
- [ ] **Publish-readiness check** (one command):
      `packaging/check-publish-readiness.sh v<prev>`
      Proves the crates.io fanout can actually run. Four failure modes, none
      of which any other gate catches and all of which surface only once the
      fanout is already half done:
      (a) a crate added since the last release — Trusted Publishing over OIDC
      cannot CREATE a crate name, so its first publish must be manual, with a
      crates.io Trusted Publishing entry added after;
      (b) a member missing from `publish.yml`'s list, which then silently
      never publishes;
      (c) a stale path-dep version pin (checked against the workspace
      version — invisible inside a series, wrong-series the moment 0.8.0
      happens);
      (d) a NEW inter-crate dependency edge that the publish order does not
      respect — cargo refuses to publish a crate whose path-dep sibling is not
      yet on crates.io at the pinned version, and the run dies with half the
      workspace released.
      (d) is the subtle one: every crate can already be published and the
      release still breaks, because what changed is the ORDER requirement, not
      the set. v0.7.7 added `keyroost-resolve -> keyroost-openpgp` and happened
      to be ordered correctly; nothing would have caught it if it had not been.
      The script cannot see Trusted Publishing config (no API exposes it) — for
      a newly-added crate, confirm that by hand in the crate's crates.io
      settings.
- [ ] **Packaging probe** (mandatory, one command):
      `gh workflow run linux-bundles.yml --ref main`
      No tag input = build-only; approve the gate (probe-safe). Both bundle
      jobs must go green, with "wrote N `<release>` entries" in their logs.
      Packaging pulls from upstreams that drift on their own schedule — the
      v0.7.3 flatpak broke at release time because an upstream source was
      pruned. Probes catch that; release runs must not.
- [ ] **Packaged-crate asset check** (one command):
      `packaging/check-packaged-assets.sh`
      Every file a crate *references* (`include_str!`, `include_bytes!`,
      anything `build.rs` reads) must be a file its published tarball
      *ships*. Cargo packages only files beneath the package root, so a path
      reaching outside it silently vanishes from the crate while resolving
      fine in a git checkout — that is how the Windows icon broke
      `cargo install keyroost` before v0.7.7, and nothing else catches it:
      `cargo publish`'s verification build runs on Linux where `build.rs` is
      a no-op, and no workflow builds the packaged tarball. The script
      checks every referencing macro in every publishable crate, not just
      the asset that already bit. (You cannot *build* the tarball at this
      stage — it resolves sibling crates from crates.io at the unpublished
      new version; contents here, build in step 6.)

## 2. Version bump + changelog (prep branch)

- [ ] Branch off main. Bump the workspace version: every
      `version = "<old>"` in the Cargo.tomls (the workspace field plus the
      inter-crate path-dep pins — `grep -rn 'version = "<old>"' --include=Cargo.toml .`).
- [ ] `cargo update --workspace` at the root AND in `fuzz/` (its own lock).
- [ ] CHANGELOG: assemble the `changelog.d/` fragments PRs have been dropping
      in since the fragment system landed —
      `python3 packaging/assemble-changelog.py --release X.Y.Z` inserts the
      `## [X.Y.Z] - date` section directly under `[Unreleased]`, adds the
      `[#N]` link definitions and compare links, and deletes the fragments
      it consumed (`--date YYYY-MM-DD` to override today). Run
      `python3 packaging/assemble-changelog.py --check` first if unsure —
      it validates every fragment and refuses to assemble a broken one.
      The top entry MUST match the new workspace version —
      `python3 packaging/flatpak/gen-metainfo-releases.py --check` proves it
      (CI enforces the same).
- [ ] **Breaking changes → `docs/migration.html`.** If this release renames a
      flag, moves a command, or changes a library signature, add its section
      (exact before → after) — the README points users there as the canonical
      record, and the Pages deploy rides on the `docs/**` change.
- [ ] **Mechanical documentation checks** (one command, before any agent):
      `packaging/check-docs-mechanical.sh`
      Deterministic and exhaustive — a script cannot decide not to read a
      file. Validates every `keyroostctl` invocation in `docs/*.html` and
      `README.md` against the release binary's real `--help` tree (the `.md`
      runbooks — `docs/BRINGUP.md`, `packaging/*.md` — are not covered; they
      stay part of the semantic pass), every `learn_url(...)` slug against
      `docs/`, every internal link and anchor, the CHANGELOG's reference/link
      integrity, every `changelog.d/` fragment (filename, length, credit ref),
      and contributor credit against `git log`.
      Anything it can check, agents no longer audit by hand.
- [ ] **Semantic documentation audit — every release, every file, no
      sampling.** What no script can check: whether the claims a page makes
      about behavior are TRUE (the v0.7.8 audit's worst finding — a page
      stating the inverse of the shipped Settings-tab gating — was
      grammatical, plausible, and wrong). Protocol, learned from the misses:
      * **Audit from the inventory, not from memory**: the in-scope set is
        every `docs/*.html`, `README.md`, `SECURITY.md`, `CONTRIBUTING.md`,
        `TODO.md`, `CHANGELOG.md` (the new release section plus the emptied
        `[Unreleased]` heading), `packaging/*.md`, `docs/*.md`. Regenerate the
        file list with `ls`, hand it to the audit agents whole, and add a line
        here whenever a new documentation surface appears — scope gaps, not
        laziness alone, caused the #99 miss.
      * **Per-file verdict required**: each agent's report carries one line
        per inventory file — read in full + accurate, or read in full +
        findings. A file with no line means the audit did not happen; treat
        it as red. "Unchanged since last release" is an explicitly
        forbidden reason to skip a file — documentation rots where the code
        changed AROUND it.
      * **Claim-by-claim for behavior statements**: every sentence
        asserting what the app does must be traced to the code that does
        it, with a file:line citation in the report.
      * Findings are fixed on the prep branch, so the release ships
        accurate docs. Parallel agents (Learn pages / README / meta-docs)
        keep the pass tractable.
- [ ] Full gates: clippy `-D warnings`, fmt, workspace tests.
- [ ] Land on main: push the prep branch directly —
      `git push origin <branch>:main` (the require-PR rule's admin bypass
      covers the maintainer; no rebase, no commit signing — the release is
      signed at the tag, not per commit).

## 3. Tag and watch the build

- [ ] **Pre-tag delta review.** Review the full release delta before
      tagging: `git log --oneline <previous-tag>..HEAD` to walk it, then
      `git diff <previous-tag>..HEAD` for anything unfamiliar. Commits on
      main are not individually signed; the tag signature is the only
      cryptographic statement covering the release, and SECURITY.md
      documents that it is made after this review. Each contribution was
      reviewed at merge (`packaging/REVIEWING.md`); this pass reviews the
      aggregate.

- [ ] `git tag -s vX.Y.Z -m "keyroost vX.Y.Z" && git push origin vX.Y.Z`
      (`v*` tags are admin-only by ruleset.)
- [ ] Two workflows start on the tag: `release.yml` (platform archives +
      GitHub Release) and `linux-bundles.yml` (AppImage + flatpak).
      **Approve both release-publish gates promptly and together** — the
      bundle attach steps wait for the Release that release.yml creates.
      The retry window is 10 minutes (v0.7.6 lost the old 2-minute window
      by 16 seconds); if it still expires, re-run the failed job once the
      Release exists — attach is idempotent (`--clobber`).
- [ ] When both finish, the Release must hold: 3 platform archives,
      `SHA256SUMS`, `keyroost-x86_64.AppImage` (+ `.sha256`, `.zsync`),
      `keyroost.flatpak` (+ `.sha256`). Check:
      `gh release view vX.Y.Z --json assets --jq '[.assets[].name]'`

## 4. Fanout (publish.yml)

- [ ] Approve the fanout's release-publish gate.
- [ ] **Verify each channel actually PUBLISHED** (one command):
      `packaging/check-release-live.sh vX.Y.Z`
      A green job can mask a no-op (missing secrets skip-with-notice; caches
      lag), so the script checks the observable side effect on every
      channel: the release asset set, both binaries on crates.io, the
      Homebrew formula, the AUR RPC, the flatpak OSTree remote over plain
      HTTPS (no configured remote needed), and the winget-pkgs manifest.
      winget reporting HOLDING is the designed outcome at this stage — see
      step 5. Re-run the script any time later; it is read-only.
      Channel-specific diagnosis, when the script reports a failure:
  - AUR: trust the job log's push line over the RPC (the RPC lags pushes by
    minutes). **`The AUR is down due to maintenance. We will be back soon.`
    is an AUR-wide push freeze, not our bug** — it is emitted after our key
    authenticates, the freeze is announced only on the aur-general mailing
    list, and the web UI/RPC stay up throughout, so "the site works" proves
    nothing. The job tolerates exactly that message (warns, exits 0; any
    other failure stays fatal); a warning means keyroost-bin was NOT
    updated — re-run the job when pushes reopen. AUR is independent of
    every other channel and can land late.
  - winget: a HARD failure (not a hold) means the `WINGET_TOKEN` PAT died —
    the job fails loudly on an expired token; renew the classic PAT.
  - crates.io: a red crates-io job mid-chain is safe to re-dispatch —
    the already-published probe skips completed crates.

## 5. Signed Windows build (out-of-band, Token2)

- [ ] Ask Token2 to sign the **current** release's Windows build (never an
      older version — it would predate shipped fixes). They deliver into
      issue #77 as `signed_keyroost-vX.Y.Z-*.zip` attachments; macOS may
      arrive separately from Windows, so check for both.
- [ ] **The winget-pkgs fork sync now runs in CI** (`Sync the winget-pkgs
      fork`, non-fatal). wingetcreate submits its PR from that fork and
      cannot fast-forward it itself: `WINGET_TOKEN` is a classic PAT with
      `public_repo` scope, and pushing upstream commits that touch
      `.github/workflows/` needs the `workflow` scope. Left alone the fork
      drifts thousands of commits behind and the job dies at the very end
      with "The forked repository could not be synced with the upstream
      commits" — *after* Authenticode verification passed and the manifests
      were generated, so it reads as a signing problem and is not one
      (v0.7.7).
      `WINGET_TOKEN` carries the `workflow` scope (granted 2026-08-24), so
      the CI sync step handles the fork unattended. If it ever warns anyway,
      the manual fallback still works — the warning prints the command:
      `gh repo sync framefilter/winget-pkgs --source microsoft/winget-pkgs`
      Syncing is lossless while the fork is 0 ahead. First unattended
      exercise of the scoped token was v0.8.0's step 5.
- [ ] When it arrives: attach as **NEW** assets
      `keyroost-vX.Y.Z-windows-x86_64-signed.zip` + `.sha256` (and
      `keyroost-vX.Y.Z-macos-universal2-signed.pkg` + `.sha256`, unwrapped
      from its transport zip). Names are built from the tag by the job and
      matched literally — a near-miss reads as "not attached" and it holds
      again. **Never replace the CI-built assets** — that invalidates
      `SHA256SUMS`, provenance attestations, and any open winget PR's hash.
- [ ] Worth verifying the signed bytes are *our* build before attaching.
      Authenticode appends a certificate table, so stripping it (and zeroing
      the PE checksum + cert directory entry) must reproduce the CI binary
      byte-for-byte; at v0.7.7 it did. macOS cannot be checked this way —
      `codesign` rewrites the Mach-O in place — so there, confirm the Apple
      chain, the Developer ID signer, and universal2 slices instead.
      Note the `.pkg` is signed but **not notarization-stapled** (true since
      at least v0.7.6): Gatekeeper validates online, which fails offline.
- [ ] `gh workflow run publish.yml -f tag=vX.Y.Z` and approve the gate.
      Every channel no-ops (idempotent); the winget job Authenticode-verifies
      every PE in the signed zip (signer logged in the run) and submits the
      manifest. Confirm the winget-pkgs PR opened and (eventually) merged —
      Defender validation false positives on fresh binaries do happen; the
      documented remedies are a pipeline re-run (~18h cycles) or a WDSI
      false-positive report, not resigning.
      Judge this run by the **winget job's own conclusion**, not the run's
      overall status: any other channel that is failing for its own reasons
      (a frozen AUR, say) reds the whole run while winget is fine.
- [ ] Manual fallback from Linux if wingetcreate misbehaves:
      `komac update Framefilter.Keyroost --version X.Y.Z --urls <signed-asset-url> --submit`

## 6. Post-release

- [ ] `packaging/check-release-live.sh vX.Y.Z` once more — after step 5 it
      should report every channel live, winget included; anything still
      HOLDING or STALE here is a follow-through that was forgotten, which
      is exactly what this re-run exists to catch.
- [ ] Install-matrix spot check as machines allow: `cargo install keyroostctl`,
      flatpak update on a real install, AppImage launch, brew upgrade, winget
      after step 5.
- [ ] **`cargo install keyroost` on Windows** — the one configuration that
      actually compiles `build.rs` and embeds the icon from the published
      tarball, and the only place a missing packaged asset shows up. Only
      possible here, once the sibling crates are live (see the pre-flight
      asset check for why it cannot run earlier). If this ever fails, the fix
      belongs under the crate root, not in a wider `include`: cargo cannot
      package paths above the package directory.
- [ ] `keyroostctl --version` prints X.Y.Z, and the GUI shows vX.Y.Z next
      to the wordmark in the top bar.
- [ ] The AppImage carries the version in its metadata (added at v0.8.0,
      first produced by that release's build):
      `./keyroost-x86_64.AppImage --appimage-extract >/dev/null && grep X-AppImage-Version squashfs-root/*.desktop`
      must print `X-AppImage-Version=X.Y.Z`. This is what AppImage managers
      (Gear Lever et al.) display; it comes from the `VERSION` export in
      `build-appimage.sh` (#98).
- [ ] Close/comment the issues the release fixes (drafts usually prepared
      during the work); announcement if any.
- [ ] Out-of-band corrections later (metadata fixes, asset re-attach): use the
      dispatch republish — `packaging/LINUX-BUNDLES.md` "Out-of-band runs".
      A republish builds from the dispatched ref into the tag's release and
      is version-guarded against tree/tag mismatch.


## 7. When a release is bad

Rare, judgment-heavy, and the worst time to improvise — decide against this
list, in this order:

- [ ] **Severity first.** A broken build or wrong metadata is an
      inconvenience: fix forward with a patch release; nothing here applies.
      This section is for a release that must not be installed — a security
      defect, a data-destroying bug, a compromised artifact.
- [ ] **Stop the spread before fixing anything.** Delete the GitHub Release
      (keep the tag — history is not the enemy, distribution is) and mark it
      in the successor's release notes. The registries cannot unship:
      crates.io yank (`cargo yank -p <crate> --version X.Y.Z`) prevents NEW
      dependents but removes nothing already vendored; OSTree cannot retract
      a commit users pulled — the flatpak fix is publishing the successor,
      fast. AUR/Homebrew/winget point at release assets, so deleting the
      Release breaks their installs immediately — acceptable for a
      must-not-install defect, and the successor restores them.
- [ ] **Yank in REVERSE publish order** (binaries first, then the crates
      they depend on) so no moment exists where a fetchable binary crate
      resolves against a yanked dependency.
- [ ] **The successor is a normal release** — full playbook, no shortcuts;
      a rushed fix that skips the probe is how one bad release becomes two.
      Note what happened in the CHANGELOG under the new version, plainly.
- [ ] **If the cause was a compromise** (not a defect): rotate every
      credential the release pipeline touches before the successor ships,
      and say what was compromised, when, and what users should do — the
      same candor SECURITY.md asks of reporters.
