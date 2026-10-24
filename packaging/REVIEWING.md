# Reviewing an external contribution

The review every contributor PR gets before merge. Written from the reviews
of #96, #97 and #100; each step caught a real problem in at least one of
them. Under the contribution model, review-before-merge is the trust
boundary for `main` — the release-time anchors (SECURITY.md, "Release
integrity") are the trust boundary for what ships.

## 1. Mechanical gates

- [ ] Fetch the PR head and rebase it onto current `main` locally. Review the
      rebased result, not the PR as filed.
- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --locked`
- [ ] MSRV: `cargo +1.87 check --workspace --exclude keyroost --all-targets
      --locked`
- [ ] `cd fuzz && cargo build` — a PR that renames or reshapes a parser
      breaks the fuzz workspace without failing any main-workspace gate
      (#100 did).
- [ ] `python3 packaging/assemble-changelog.py --check` — validates the PR's
      `changelog.d/` fragment (filename, section, length, credit ref) so a
      broken one is caught at review, not at release assembly.
- [ ] Scan every commit message for issue-closing keywords:
      `git log <base>..HEAD --format=%B | grep -inE
      '(clos|fix|resolv)[a-z]*[[:space:]]+#[0-9]+'`
      They close issues on merge; only the maintainer closes issues.
- [ ] If the PR touches `.github/`, read those changes before anything else,
      and before approving any workflow run.

## 2. The diff

- [ ] **Wire bytes.** Any change to APDU or frame construction needs a
      byte-exact test, and "no change for standards-only devices" must be
      shown by a test, not asserted (#97: `Default` policy omits the vendor
      tags; a byte-identical test pins it).
- [ ] **New parsing.** Anything that parses bytes from a device, file, or
      the network: read it line-by-line for bounds handling and typed
      errors, and add it to fuzz coverage in the same PR or a same-day
      follow-up. `forbid(unsafe_code)` stays.
- [ ] **Retained state.** For any cache or remembered value: list every
      operation that changes the underlying truth and confirm each one
      invalidates or migrates the copy (#100: generate/delete/move/reset/
      session/device-switch). Answer in the review: what happens if the
      device is swapped, the slot is rewritten, the session is stale?

## 3. Trust boundaries

- [ ] PINs, keys, management keys: zeroized on drop, never in argv, never
      logged, never persisted. Changes here need hardware verification
      before merge.
- [ ] Fail-closed guards (the KEY-005 class: never target a device that
      cannot be re-identified) may only be relaxed by a PR that argues for
      the relaxation explicitly in its description.
- [ ] State the worst case in the review: what happens if hostile input or
      a wrong file reaches the new surface (#100: a mismatched public key
      produces a certificate that fails its own signature check — inert).
- [ ] New persistence to disk defaults to rejected. Persisting key material,
      including public keys, needs explicit maintainer agreement.

## 4. Claims against history

- [ ] Check the PR's claims against `git log` before acting on them, in both
      directions: the #97 review asserted a CLI gap and a breaking signature
      change that the history disproves; a PR can equally re-fix fixed code
      or contradict a standing decision in TODO.md.
- [ ] Contributor hardware verification is recorded in the merge comment as
      theirs. If the hardware class is on hand, verify independently;
      otherwise state what was not independently verified.

## 5. Landing

- [ ] Merge via squash. The squash commit carries the contributor's
      authorship.
- [ ] Maintainer-side fixups (fmt, fuzz-target repairs) land as a separate
      commit or PR under the maintainer's name, not pushed onto the
      contributor's branch before the squash.
- [ ] User-facing changes get a `changelog.d/` fragment (or a CHANGELOG
      entry — pre-fragment PRs) crediting the contributor; a first
      contribution adds them to the README Contributors section.
- [ ] Merge comment: what was reviewed, what was fixed maintainer-side, what
      follow-ups went into TODO.md. Issue closes are the maintainer's,
      separately.

## First-time contributors

Workflow runs for outside collaborators require maintainer approval
("Require approval for all outside collaborators"), so CI does not run
until the diff has been read — item 1's `.github/` check comes first. The
checklist is not reduced for a first PR.
