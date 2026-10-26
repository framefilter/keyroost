# Contributing

Contributions are warmly welcome — code, docs, hardware test reports, and
issue reports alike. This file collects the practical details in one place.

## How a PR lands

PRs are reviewed against `packaging/REVIEWING.md`, then squash-merged. The
squash commit carries your authorship. CI for outside contributors runs
after maintainer approval of the workflow run, so there can be a delay
between opening a PR and checks starting. Contributions are credited in the
changelog and, for a first contribution, in the README's Contributors
section.

For a user-facing change, add one file to `changelog.d/` instead of editing
`CHANGELOG.md` directly — every PR editing the same spot at the top of
`[Unreleased]` is what used to make concurrent branches conflict. Name it
`<section>-<ref>-<slug>.md`, where `<section>` is one of `added`, `changed`,
`fixed`, `deprecated`, `removed`, `security`, `<ref>` is this PR's number,
and `<slug>` is a short kebab-case description — for example
`changelog.d/added-123-widget-export.md` containing:

```
- **Widgets can be exported.** `widget export` writes the selected widget
  to a file. ([#123])
```

`packaging/assemble-changelog.py --check` validates fragments and runs as
part of `packaging/check-docs-mechanical.sh`.

## Before you open a PR

Run the same gates CI does:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
python3 packaging/assemble-changelog.py --check
```

MSRV is Rust 1.87 for the workspace (1.92 for the `keyroost` GUI crate).

The CLI tests run with `KEYROOST_DEVICE_TEST=none`, which makes keyroost act as if no keys are connected, on every system. A new test that runs `keyroostctl` sets it too. It's a test-only setting, not for users.

Two project rules worth knowing up front:

- **Vendor over depend.** Most primitives are implemented in-tree on purpose;
  new external dependencies need a discussion first (open an issue).
- **Reference issues as `re #N`**, not `fixes #N` — the maintainer closes
  issues after verification, and auto-close keywords bypass that.

A hardware-verified fix is worth calling out in the PR description: this
project manages security keys, and "reproduced and verified on my device"
carries real weight (see [#96](https://github.com/framefilter/keyroost/pull/96)
for a model example).

## Adding a command or flag

Look at the nearest existing command first and reuse its words.

- **Shape:** group, topic, action — `piv pin change`, `fido config always-uv enable`.
- **Action words:** reuse the existing pairs — `add`/`delete`, `set`/`clear`,
  `enable`/`disable`, `import`/`export`. A new word is fine when none fits;
  say why in the PR.
- **Reading:** `info` for an overview, `list` for several items, `show` for
  one item, `status` for one topic's state.
- **Short flags:** only `-d` (device), `-y` (yes), `-i` (in), `-o` (out),
  `-s` (slot).
- **Secrets:** never on the command line. Accept `env:NAME` or `stdin`; with
  neither, ask at a hidden prompt.
- **Changing a key:** ask first; `-y` skips the question.
- **Output:** the result on stdout; progress, warnings and questions on stderr.
- **Help:** one plain sentence for every flag.
- **Renaming:** keep the old name as a retired name that points to the new one.

`cargo test -p keyroostctl` catches most of these.

## Words in output and JSON

Check a new JSON field or output word against the existing ones first, and
reuse what is there.

- **Yes/no facts:** a `true`/`false` field named after the thing:
  `cert_present`, `occupied`, `touch_required`.
- **Facts keyroost can't always tell:** `true`, `false` or `null`, where
  `null` means it couldn't tell: `pin_set`, `force_pin_change`. Never a
  string such as `"unknown"`.
- **States:** a word from a fixed list, lowercase, with hyphens between
  words: `not-connected`, `removed-not-added`. Details such as an error go in
  a separate field: `result` and `detail`, `outcome` and `error`.
- **OpenPGP keys:** one field per key, ending in `_sig`, `_dec` or `_aut`:
  `fingerprint_sig`.
- **Nothing there, or can't read:** in text output, `(none)` means nothing is
  there and `(unavailable)` means keyroost couldn't read it.
- **Capabilities keyroost couldn't confirm:** the usual label with a `?`
  after it, such as `FIDO2?`, and the label listed in JSON's
  `capabilities_unverified`.
- **`doctor` lines:** each starts with one mark from a fixed set: `✓` works,
  `✗` broken, `–` missing or not set up. Don't add new marks.
- **Error messages:** say what happened in plain words, with any status code
  in parentheses after it: `FIDO applet not present on this card (SELECT -> 6A82)`.
- **The app:** uses the same words as the CLI for the same thing, fitted to
  its layout. A new word in one means the same word in the other.

## Where to find work

`TODO.md` is the live task list. Items under "Ready to pick up" are
self-contained; items under "Blocked" say what they're waiting on.

## Licensing

keyroost is dual-licensed MIT OR Apache-2.0. By submitting a contribution you
agree it is licensed the same way, per Apache-2.0 §5 — there is no CLA.

## Security issues

Please don't open a public issue for a vulnerability — see
[SECURITY.md](SECURITY.md) for the private reporting path.
