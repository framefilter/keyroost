# keyroost TODO

**This is the single live task list.** History lives in git — completed work is
recorded in `CHANGELOG.md` and the commit log, not here. When something lands,
delete the item rather than ticking it; when something is decided, move the
decision to "Standing decisions" at the bottom so it is not re-litigated.

Deliberately unversioned: the previous `TODO-v0.7.5.md` / `TODO-hardening.md`
pair rotted because version-named files accumulate layers nobody rereads.

---

## In flight

Being worked on right now — check with whoever holds it before starting.

---

## Ready to pick up

**Release steps:**

- **Run the mandatory packaging probe before any version bump.**
  `gh workflow run linux-bundles.yml --ref <ref>` with no tag input = build-only;
  both the flatpak and AppImage jobs must go green *before* any version bump or
  tag. Packaging pulls from upstreams that drift independently (the v0.7.3
  flatpak broke at release time because a source was pruned). Full sequence:
  `packaging/RELEASING.md`, which is the playbook for the whole release.

**Later:**

- **Token2 serial on Windows for keys before R3.4 ([#51](https://github.com/framefilter/keyroost/issues/51)).**
  The duplicate rows are fixed (v0.15.0), and a PIN+ R3.4 shows its full
  printed serial on Windows since v0.16.0, read from its OTP applet
  (checked in the v0.16 Windows rounds). An older key's OTP answer isn't
  used for the serial, so its row may still show the 8-digit OpenPGP serial
  Token2 reported (`#0991…`). Needs a `keyroostctl --debug list` from such
  a key on Windows. On Linux this key's card side isn't visible at all
  (libccid has no entry for 349e:0024); its USB-only row gets its serial
  from the §6.10 read since #236.

- **Drop the broken-pipe workaround when stable Rust lands the SIGPIPE fix.**
  `install_broken_pipe_guard()` in `crates/keyroostctl/src/main.rs` plus its
  `tests/broken_pipe.rs` guard exist only because the clean fix — libstd
  resetting `SIGPIPE` to `SIG_DFL` — is nightly-only today
  (`-Zon-broken-pipe=kill`; tracking issue rust-lang/rust#97889). Checked
  2026-10-29: still unstable, and the flag is to be replaced by an
  attribute, `#[std::io::on_broken_pipe]` (tracking issue
  rust-lang/rust#150588, implementation rust-lang/rust#150591, still open).
  Check periodically; when it reaches stable, delete both and adopt the
  built-in.
  (Same applies to the `keyroost` GUI binary if it ever grows piped stdout.)

---

## Blocked / needs someone else

- **Move CI's Linux test job back to `ubuntu-latest` — waits on Ubuntu.**
  It runs on `ubuntu-24.04` for now: the latest image (26.04) ships libgcrypt
  1.12.0, which randomly rejects valid Curve25519 keys
  ([T8094](https://dev.gnupg.org/T8094), fixed in 1.12.1), so the GnuPG
  interop tests fail about half the time. Switch back in
  `.github/workflows/ci.yml` once 26.04 ships the fix
  ([Launchpad #2174038](https://bugs.launchpad.net/bugs/2174038)). The same
  bug can refuse a keyroost backup restored into GnuPG on Ubuntu 26.04
  ("Bad passphrase" on first decrypt); keyroost's export is not at fault.

- **Drop the carried hidapi fix once a hidapi release has it — waits on
  hidapi.** The root `Cargo.toml` patches hidapi to the commit of
  [ruabmbua/hidapi-rs#189](https://github.com/ruabmbua/hidapi-rs/pull/189),
  carried on the `keyroost-windows-serial-fallback-fix` branch of
  framefilter/hidapi-rs, because hidapi 2.6.7 can panic while listing HID
  devices on some Windows PCs ([#281](https://github.com/framefilter/keyroost/pull/281)).
  Check upstream at the end of every dev cycle, with the Windows test round:
  is #189 merged, and is there a hidapi release on crates.io with it? When
  there is, delete the `[patch.crates-io]` section and the `outputHashes`
  entry in `flake.nix`, run `cargo update -p hidapi`, re-run the Windows
  round, and then delete the fork's branch. Until then, leave that branch as
  it is: the builds and the Flatpak fetch from it.

- **OnlyKey recognition
  ([#37](https://github.com/framefilter/keyroost/issues/37), filed as "serial
  number detection on hardware keys") — needs testing on an OnlyKey.**
  Teach `keyroost-resolve` to recognize `1d50:60fc` / product `ONLYKEY`, label it
  "OnlyKey", and treat serial `1000000000` as a non-unique placeholder (fall
  back to the hidraw path). Today OnlyKey appears only in the AAGUID model table (`keyroost-resolve`).
  **Must be done as part of this work, not after:** on macOS/Windows the
  post-replug reinsert matcher still falls back to serial identity, and every
  OnlyKey ships the *same* serial, so it would accept a different OnlyKey as
  "the same key" there. (On Linux, #96 moved freshness to USB bus/address, which
  narrows but does not remove the hazard — the *identity* match is still the
  serial.)

---

## Hardware verification

Not yet run. Everything here is behavior that automated tests cannot reach;
items marked *(no hardware)* need a device the maintainer does not have.

- **Lift the "experimental" label on the password vault (`fido vault`).**
  Shipped experimental in v0.17 ([#285](https://github.com/framefilter/keyroost/pull/285)).
  Lift it once the vault has run on the Windows test round (consoles,
  `--reveal`), on a Token2 PIN+ (the fresh-token retry) and another key
  with a large-blob store besides the YubiKey, and in the app's
  Vault tab, and user reports have had a release to come in; then drop
  "(experimental)" from the `fido vault` help, the README, `docs/vault.html`,
  and the app's Vault tab and Overview card
  (`vault_pane::experimental_note`).

- **Lift the experimental label on fingerprint unlock** *(no hardware)*.
  Built against scripted keys only (CTAP 2.1 built-in UV, clientPIN 0x06 /
  0x07). On a bio key (Token2 Bio, YubiKey Bio or similar), check:
  - the built-in UV token: `fido credential list --unlock fingerprint`, and
    the app's Touch fingerprint on the FIDO2 tab, the Vault tab, the naming
    field (save on the key) and the Settings dialog (keys with `uvAcfg`);
    fingerprint management by finger on keys with `uvBioEnroll`, and the
    plain "use the PIN" refusal on keys without;
  - `--unlock auto --pin …` falling back to the PIN when the finger is
    refused and when it times out, and printing which one unlocked;
  - a key that clears the token after getAssertion: the vault and the
    app's notes and name writes ask for the finger again, saying why;
  - `fido fingerprint add --unlock fingerprint` with no fingerprint
    enrolled: refused, suggesting the PIN;
  - UV_BLOCKED and the retries count (`getUVRetries`): the refusal before
    any finger at 0 tries;
  - NFC, in the app only (the CLI's FIDO commands are USB-HID only).

  Fingers asked for under `--unlock fingerprint` (each token is its own
  finger; compare against the key): every non-vault command 1 (`credential
  compare` 1 per key). `fido vault list`, `export` and the `entry` commands
  2, then the touch (1 and no touch on a key with no vault); `add` 3 and two
  touches; `delete` 1; `rotate` 5 and three touches; `import` 2 into a vault
  on the key (`--dry-run` too), 4 into a new one. A key that clears the token
  after the touch adds 1 ("asked again") to `entry add|edit|delete`, `add`,
  `rotate` and `import`. The app's Vault tab unlock is
  `vault list`'s 2. Then drop "experimental" from `--unlock`'s help
  (`FIDO_UNLOCK_HELP`), the README, `docs/fido2.html`, `docs/vault.html` and
  the app (`vault_pane::fingerprint_experimental_note`).

- **Lift the "experimental" label on the Token2 PIN+ OATH and OpenPGP
  applets.** PIV is exercised on a PIN+ Dual Ace R3.4 since #251; verify
  OATH and OpenPGP over CCID on a PIN+ key (on Windows: Linux's libccid
  doesn't list it), then update the README's PIN+ row. (Grew out of
  [#23](https://github.com/framefilter/keyroost/issues/23), now closed; no
  live issue tracks this.)

**Device binding and targeting** (deferred from the v0.7.5 security work — the
plan's two-key manual steps were never executed):

- **Wrong-device bindings, GUI — fingerprint enroll:** with two keys plugged
  in, switch the selection mid-enrollment and confirm the stale completion is
  discarded. The other cases (Molto2 session open, the FIDO advanced dialog and
  its typed PIN, OATH delete confirmation, OpenPGP reset modal, a large-blob
  write) were checked on a YubiKey, a Token2 PIN+ and a Molto2; enrollment
  needs a key with a fingerprint sensor.
- **Armed FIDO reset:** arm for key A, replug key A → fires; arm for key A,
  insert a same-model key B during the window → must NOT fire; a serial-less key
  arms only while it is the only key connected and is refused, naming the keys
  to unplug, while any other key is connected. *Partly exercised already* — the
  wrong-key refusal path was hit on hardware and fixed in `55adf2f`; the
  arm-and-fire and refuse-to-arm paths remain.
- **CLI targeting with two Token2 OTP keys** *(needs a second key with
  Token2's OTP applet; one PIN+ on hand)*: `keyroostctl --device <name> otp
  list` must hit the named key only, and with neither named it must fail
  closed with the ambiguity error. Across kinds this is checked (2026-11-16,
  Token2 PIN+, Molto2, YubiKey, Nitrokey 3): `--device` picks only the named
  key, OTP and Molto2 commands aimed at the wrong kind are refused naming the
  right one, and `oath list` with two OATH keys and no terminal refuses.
- **GUI OTP pane binding** *(same second key)*: two Token2 OTP keys —
  list/add/delete operate on the selected key only, and the fail-closed error
  appears when the transport pick cannot be satisfied.
- **Duplicate-serial advisory:** with two same-serial keys connected, the sidebar
  advisory appears and both keys stay separately selectable.
- **Card-content identity ([#83](https://github.com/framefilter/keyroost/issues/83))** *(no hardware)*: with a Token2 PIN+
  smartcard in a GENERIC reader (Alcor / SCM / Realtek), confirm keyroost shows
  vendor "Token2" and the FULL serial (not the 8-digit one); that it still does
  in the Token2 dual reader; that a non-Token2 OpenPGP card (e.g. Nitrokey)
  shows its correct registry vendor; and that a model rejecting GET_INFO over
  contact falls back to the 8-digit serial with no error.
- **v0.7.6 field fixes** *(no hardware)*: the Settings tab + Reset on a CTAP
  2.0-only key ([#81](https://github.com/framefilter/keyroost/issues/81) — the reporter's device class), and the standalone Reset
  card on a key with a blocked or absent PIN. (#82's HID→CCID fallback only
  engages on the quirky firmware; reporter confirmation stands in.)
- **Windows GUI icon:** confirm the embedded icon shows in Explorer (the title
  bar and taskbar were confirmed with egui 0.37, #249), and that Linux/macOS builds
  are unaffected (the `winresource` build-dep is host-gated). Future signed GUI
  binaries should then be byte-identical to CI plus a signature, with nothing
  injected.

---

## Deferred to a later release

- **Interactive CLI import for vault backups.** Start from the
  `fido vault import` preview, where each row says `add`, `replace`,
  `exists` or `skip` with its reason, and explore letting the user pick, in
  the terminal, which rows to bring in or overwrite. Not decided whether it
  gets built, since vaults may grow large; the goal is a smoother CLI path
  than `--entry`. Vault CLI PR: [#285](https://github.com/framefilter/keyroost/pull/285).

- **Keep copied codes out of clipboard history on native Wayland** (waits for
  GNOME). Copies are marked `x-kde-passwordManagerHint=secret` on X11 and
  with the platform markers on Windows and macOS, but on native Wayland they
  go through egui's own clipboard, which can't add the marker. arboard's
  `wayland-data-control` feature would (9 more crates, among them
  `wl-clipboard-rs` and a MIME sniffer); it needs a compositor with a
  data-control protocol. Research (2026-10-20, primary sources): KDE Plasma
  (ext-data-control since 6.4; Klipper honors the hint), COSMIC (both
  protocols since 1.0), Sway 1.11+ and Hyprland have it; GNOME's Mutter does
  not and its developers have said they won't add it
  ([mutter#3941](https://gitlab.gnome.org/GNOME/mutter/-/issues/3941)), so
  arboard falls back to X11 through XWayland there. COSMIC, Sway and (from a
  coming Plasma release) KDE withhold data-control from sandboxed apps, so the
  Flatpak would get the fallback too. Until then, `KEYROOST_X11=1` runs the
  app under X11, where the marker already works. Revisit when GNOME's Mutter
  supports a data-control protocol. (M)

- **Submit keyroost to Flathub** — deferred, not ruled out; not scheduled for a release.
  The maintainer submits it himself. Flathub's generative-AI
  policy allows AI-generated app code with full disclosure (parts and extent),
  but the Flathub manifest itself and the submission PR, its description and
  replies must be written by the maintainer. Claude may explain requirements
  and review in words; it doesn't write the manifest or the submission text.
  The manifest in `packaging/flatpak/` can't be reused for this.

- **Restoring missing OpenPGP fingerprints** from the user's public key
  file — parked until someone asks for it (decided 2026-11-03). Only a bare
  RSA key file import gets a new identity on the card; backups restore
  their own fingerprints. May be a hornet's nest (key-generation times,
  which key matches, writing to the card).

- **Speed up the Nix CI build** (after v0.16, as a measured trial started from
  main) — the Nix build job
  ([#144](https://github.com/framefilter/keyroost/pull/144)) is the slowest
  in CI (10–19 minutes against 3–7). A plain cache of the Nix store won't
  help much (checked 2026-10-29): the flake's source is the whole repo
  (`src = ./.`), so any committed change rebuilds everything, and a cache
  would only save the crate downloads. Each job also builds the dependency
  tree twice (the app and the CLI are separate `buildRustPackage`s). A real
  speedup means building the dependencies as their own cacheable step
  (for example with crane), which adds a flake input and reshapes the
  flake. Optional; changes nothing shipped.
- **PC/SC: `dlopen` libpcsclite at runtime instead of hard-linking it** — the
  real fix for [#47](https://github.com/framefilter/keyroost/issues/47).
  Two payoffs: the *host's* libpcsclite is always used (the only client
  guaranteed to match the host's `pcscd`, for every distribution channel, not
  just the AppImage), and when it is absent keyroost still launches with
  FIDO/USB-HID working and the PC/SC panes showing "PC/SC unavailable".
  Would also let the AppImage drop its bundled-libpcsclite fallback
  (`build-appimage.sh` step 3b). The `pcsc` crate links at build time —
  check whether it exposes a dynamic-load path or whether we wrap libpcsclite in
  a thin FFI loader ourselves. Design first; verify on a host with and without
  the library.
  **Backburnered by the maintainer (2026-08-15): the last attempt required
  `unsafe` on more surface than they were comfortable with.** Do not pick this
  up without a design that keeps the unsafe footprint to a thin, isolated
  loader crate — and maintainer sign-off on that design first. The AppImage
  no longer depends on it: since #157 it falls back to a bundled copy when
  the host has no libpcsclite, which also unblocked AppImageHub (#53,
  AppImage/appimage.github.io#9258). The other prebuilt binaries still
  hard-link it.

- **musl static Linux build** — under consideration, notes-only, not wired into
  any workflow. The draft design and runbook are in `packaging/musl/README.md`;
  the recommendation there is CLI-only (`keyroostctl`), never a musl static GUI.
  Fixes the glibc-version portability caveat; the wrinkle is `libpcsclite`
  linking for the PC/SC path (and the dlopen item above changes that calculus).
  Think it through before committing.

- **Turning an OpenPGP card's KDF setting on or off** from keyroost, in the
  CLI and the app together. Since [#276](https://github.com/framefilter/keyroost/issues/276)
  keyroost honors the setting (`gpg --card-edit` → `kdf-setup`) but doesn't
  change it. Changing it resets the PINs, and how differs by card: GnuPG
  leaves that to YubiKey and Gnuk cards, which reset their PINs themselves
  when the setting is written; on other cards it runs its own sequence from
  the host first (CHANGE REFERENCE DATA 83 → VERIFY 83 → RESET RETRY COUNTER
  81 → clear the resetting code D3 → PUT DATA F9). An interruption partway
  leaves the PINs and the setting out of step, so the order and the way back
  need hardware evidence per vendor before anything is built. A YubiKey
  refuses the change while keys are on the card. Needs "off" as well as "on",
  and wording that says plainly the PINs go back to their defaults (user
  123456, admin 12345678).

- **The app side of `fido credential compare`** — after v0.17. The CLI
  command from [#287](https://github.com/framefilter/keyroost/pull/287)
  lists the passkeys found on only one of two keys; the app needs the same,
  in the same words ("key A", "key B", "Only on key A"). One placement: the
  FIDO2 tab, when two keys are connected. dlacko, who wrote the command,
  offered to build it.

- **Require green CI on `main`** — deliberately deferred; the remaining piece
  of full branch protection. Require-PR, linear history and squash-only merges
  landed 2026-08-24 (see Standing decisions), with an admin bypass so the
  release prep branch can still be pushed straight to `main`; `v*` tag
  create/update/delete is admin-only, and `main` rejects force-push and
  deletion. Adopt the CI gate when release cadence slows.

---

## Standing decisions

Not tasks. Kept so they are not re-litigated or re-researched.

- **The contribution model (decided 2026-08-14, in force 2026-08-24).**
  Commits on `main` are not signed; the ruleset requires a PR (admin bypass
  for the maintainer), linear history, squash-only merges. External PRs are
  reviewed against `packaging/REVIEWING.md` and squash-merged with the
  contributor's authorship; fork CI runs only after maintainer approval, for
  ALL outside collaborators. Release `v*` tags remain hardware-signed and
  admin-only, made after the RELEASING.md pre-tag delta review — the tag
  signature is the release trust anchor (SECURITY.md, "Release integrity").
  Per-commit signing was retired deliberately: it blocked the merge button
  and does not address the attack class that matters (a malicious committer
  signs validly — xz). Do not re-litigate from either direction.

- **No HID workarounds for Token2 R3.2+/R3.3+ keys — the channel is off by
  design.** The "no-status-word HID dialect" that #82 and #95 were both filed
  about (the `80 bf 00 01 05` / "status word 0x0105" response) is not a dialect
  to support: Token2 confirmed on #95 that HID-HOTP is absent on these models
  and the HID channel ships disabled on purpose (an active HID channel makes
  the OS treat the key as a keyboard, and on Windows it needs admin rights).
  CCID is the intended path, auto-transport prefers it, and the error for a
  declined HID probe now points at the CCID fix. OTP management over USB is a
  separate path: since 0.15 it goes through Token2's documented CTAPHID vendor
  command `0x41` ([#155](https://github.com/framefilter/keyroost/issues/155)),
  and the `0x0105` answer turned out to be a CTAPHID error frame replying to
  keyroost's old report framing. Keys that don't answer `0x41` fall back to
  that framing, then CCID. Don't re-add the report-framed dialect as a
  primary path.

- **No device→capability matrix. Ever.** keyroost does not decide what a device
  can do by looking its USB product id up in a table. Capabilities come from
  asking the device — `SELECT` the applet and see what answers — or they are
  *unknown*, and unknown means offer the surface and let the attempt report the
  truth.
  A matrix cannot be maintained: it drifts every time a vendor ships a new
  configuration, we have no way to test entries against hardware we do not own,
  and keeping it current would mean asking the vendor to confirm rows forever.
  v0.7.7 proved the failure mode in a single day — an entry was wrong, the wrong
  entry silently removed a feature, and the only way to find out was a user
  reporting it.
  This settles the v0.7.7 `Caps::OTP` question: the product-id gate is **not**
  coming back, not narrowed, not with a corrected table. Nothing here is blocked
  on a vendor answer.
  What a product id is still good for: **labeling** ("Bio3 Dual (FIDO + PGP)")
  and coloring an error message. Never for granting or withholding a surface.
  `TOKEN2_PRODUCTS` says as much in its own docs — "nothing here may be treated
  as proof that an applet is present" — and the inverse is no safer.
  Scope: the PIV support list (`keyroost-piv/src/compat.rs`, #128) is keyed on
  what the applet itself reports, not a USB product id, and it never hides a
  control: an unknown applet keeps everything, and anything it grays out comes
  back with "Enable Anyway" (GUI) or `--force` (CLI).

- **Windows signing: keep signing with Token2; winget always waits for the
  signed zip.** No own signing identity for now — Azure Artifact Signing /
  Certum would put the maintainer's legal name in the cert CN, and SignPath's
  OSS program rejected the project as too new (re-apply 6–12 months from
  2026-07). Signed bytes carry SmartScreen reputation across releases and move
  the submission off the release-day critical path. Submitting unsigned-first-
  then-refreshing was rejected: two PRs per release doubles validation exposure.
- **Signed assets are attached, never substituted.** Token2's signed build ships
  as a NEW asset (`keyroost-vX.Y.Z-windows-x86_64-signed.zip` + `.sha256`).
  Replacing a CI-built asset would invalidate `SHA256SUMS`, the provenance
  attestations, and any open winget PR's hash. The two variants have
  complementary trust chains (CI provenance vs Authenticode) — label which is
  which in the release notes. The mechanics (including the `komac` manual
  fallback from Linux) live in `packaging/RELEASING.md` step 5.
- **Defender/SmartScreen false positives are about prevalence, not signing.**
  Researched 2026-07-17: no "unsigned variant of normally-signed software"
  heuristic exists — reputation keys on signing-cert identity and per-file hash
  only. The v0.7.5 `Validation-Defender-Error` was the documented
  low-prevalence false positive that hits brand-new binaries, signed ones
  included; it cleared on a moderator re-run. Don't re-derive this.
- **Do NOT host Token2's signed v0.7.4** — it predates the v0.7.5 security
  fixes. Always ask them to sign whatever is current.
- **Flathub submission is deferred, not ruled out** — see "Submit keyroost to
  Flathub" under "Deferred to a later release"; the maintainer submits it
  himself. Until then, distribution is the self-hosted signed OSTree remote
  plus the offline `.flatpak` bundle.
- **crates.io first publishes are manual and ordered.** The OIDC job cannot
  create a brand-new crate, so any crate added since the last release needs a
  one-time `cargo publish` plus a Trusted Publishing entry first. The publish
  order lives in ONE place — the `for crate in …` list in
  `.github/workflows/publish.yml`, validated by
  `packaging/check-publish-readiness.sh` — publish new crates in that order
  (wait ~a minute between dependents for index propagation). Copies of the
  list in prose drift: one here and one in `packaging/README.md` both went
  stale at 15 of 18 crates before being caught.
- **Release verification is per-channel, not per-job.** The crates.io / Homebrew
  / winget / AUR jobs skip-with-a-notice and still exit `success` when their
  secret is absent, so a green check can mask a no-op. Confirm the version
  actually appeared in each catalog. (winget's `WINGET_TOKEN` now fails loudly
  on expiry rather than skipping silently.)
