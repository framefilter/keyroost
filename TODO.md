# keyroost TODO

**This is the single live task list.** History lives in git — completed work is
recorded in `CHANGELOG.md` and the commit log, not here. When something lands,
delete the item rather than ticking it; when something is decided, move the
decision to "Standing decisions" at the bottom so it is not re-litigated.

Deliberately unversioned: the previous `TODO-v0.7.5.md` / `TODO-hardening.md`
pair rotted because version-named files accumulate layers nobody rereads.

Current work: **v0.10.0** — the Nix flake
([#109](https://github.com/framefilter/keyroost/pull/109)) and its cross-build
CI ([#144](https://github.com/framefilter/keyroost/pull/144)), the PIV slot
key self-test ([#127](https://github.com/framefilter/keyroost/pull/127)),
Token2 OTP fingerprint unlock for Bio3 keys
([#130](https://github.com/framefilter/keyroost/pull/130)), the PIV
management-key algorithm probe
([#124](https://github.com/framefilter/keyroost/pull/124)), and OTP PIN-material
redaction from the debug trace
([#131](https://github.com/framefilter/keyroost/pull/131)). The release run is
under way.

---

## In flight

Being worked on right now — check with whoever holds it before starting.

(Nothing at the moment.)

---

## Ready to pick up

- **Run the mandatory packaging probe before any version bump.**
  `gh workflow run linux-bundles.yml --ref <ref>` with no tag input = build-only;
  both the flatpak and AppImage jobs must go green *before* any version bump or
  tag. Packaging pulls from upstreams that drift independently (the v0.7.3
  flatpak broke at release time because a source was pruned). Full sequence:
  `packaging/RELEASING.md`, which is the playbook for the whole release.

- **Responsive layout at high zoom / narrow window.** At ~200% zoom in a
  partial-screen window, horizontal rows overflow and overlap (top-bar Reset vs
  the brand; section-header right-actions over the left text). Fullscreen is
  fine. Fix: elide the left text in those header rows (`Label::truncate`) so the
  right action always has room, and tidy/wrap the top-bar cluster. Cheap partial
  fix: raise the minimum window width. Low-priority polish. (S–M)

- **UI liveness — make "busy" visibly different from "frozen".** Card I/O stalls
  the visible UI for seconds (touch-required sign/decrypt/authenticate, on-card
  RSA keygen, the ~30s reset re-insert window, PC/SC enumeration) and a static
  frame reads as a hang. There is a worker thread and a spinner on imports, but
  it is inconsistent. Needs a coherent activity language: a global working
  indicator while the device worker is busy, per-action busy/disabled button
  states, a cue on long ops. Keep it tasteful — over-animation reads as cheap.
  Research what feels alive vs. annoying before building.

- **Drop the broken-pipe workaround when stable Rust lands the SIGPIPE fix.**
  `install_broken_pipe_guard()` in `crates/keyroostctl/src/main.rs` plus its
  `tests/broken_pipe.rs` guard exist only because the clean fix — libstd
  resetting `SIGPIPE` to `SIG_DFL` — is nightly-only today
  (`-Zon-broken-pipe=kill`; tracking issue rust-lang/rust#97889). Check
  periodically; when it reaches stable, delete both and adopt the built-in.
  (Same applies to the `keyroost` GUI binary if it ever grows piped stdout.)

---

## Blocked / needs someone else

- **OnlyKey recognition
  ([#37](https://github.com/framefilter/keyroost/issues/37), filed as "serial
  number detection on hardware keys") — blocked on hardware** (units ordered).
  Teach `keyroost-resolve` to recognize `1d50:60fc` / product `ONLYKEY`, label it
  "OnlyKey", and treat serial `1000000000` as a non-unique placeholder (fall
  back to the hidraw path). Today OnlyKey appears only in the GUI AAGUID table.
  **Must be done as part of this work, not after:** on macOS/Windows the
  post-replug reinsert matcher still falls back to serial identity, and every
  OnlyKey ships the *same* serial, so it would accept a different OnlyKey as
  "the same key" there. (On Linux, #96 moved freshness to USB bus/address, which
  narrows but does not remove the hazard — the *identity* match is still the
  serial.)

- **Lift the "experimental" label on the Token2 PIN+ standards applets — needs
  PIN+ hardware.** Verify OATH / OpenPGP / PIV over CCID on a real PIN+ key.
  (Grew out of [#23](https://github.com/framefilter/keyroost/issues/23), now
  closed; no live issue tracks this.) Token2 may be able to help, given the
  collaboration.

---

## Hardware verification

Not yet run. Everything here is behaviour that automated tests cannot reach;
items marked *(no hardware)* need a device the maintainer does not have.

**Device binding and targeting** (deferred from the v0.7.5 security work — the
plan's two-key manual steps were never executed):

- **Wrong-device bindings, GUI:** with two keys plugged in, switch the selection
  mid-operation and confirm the stale completion is discarded for Molto2 session
  open/write, the FIDO advanced dialog (a typed PIN must die with the dialog),
  OATH delete confirmation, OpenPGP reset modal, fingerprint enroll, and
  large-blob ops.
- **Armed FIDO reset:** arm for key A, replug key A → fires; arm for key A,
  insert a same-model key B during the window → must NOT fire; a serial-less key
  must refuse to arm. *Partly exercised already* — the wrong-key refusal path
  was hit on hardware and fixed in `55adf2f`; the arm-and-fire and
  refuse-to-arm paths remain.
- **CLI targeting:** with two OTP-capable keys, `keyroostctl --device <name> otp
  list` / `molto info` must hit the named key only; ambiguous or duplicate-serial
  setups must fail closed with the ambiguity error.
- **GUI OTP pane binding:** two OTP-capable keys — list/add/delete operate on the
  selected key only, and the fail-closed error appears when the transport pick
  cannot be satisfied.
- **Duplicate-serial advisory:** with two same-serial keys connected, the sidebar
  advisory appears and both keys stay separately selectable.
- **Linux hidraw bounded reads:** unplug a key mid-`fido info` — the command must
  error within the read budget, not hang.

**Feature verification:**

- **OATH applet reset:** on a password-PROTECTED test key, reset from the GUI
  locked view and via `keyroostctl oath reset --yes`; confirm credentials are
  wiped, the password is cleared, and the pane re-lists empty and unlocked.
- **OATH password carry:** on a password-protected key, unlock + list, then
  "Read code" on an HOTP credential — must succeed without retyping; switch
  devices and confirm the retained password is dropped.
- **SSH-cert extract, interop proof:** on a YubiKey 5.7, store a cert with
  `fido2-token -S -b -n ssh:… cert.pub`, extract it with `keyroostctl fido
  ssh-cert extract` (and via the GUI), and confirm the output `-cert.pub` is
  byte-identical to the original — the cross-implementation check a round-trip
  KAT cannot provide. Also try a cert written by an OLDER libfido2 (pre-~2021),
  which wrote ZLIB-wrapped (RFC 1950) largeBlob data rather than raw DEFLATE:
  keyroost's `inflate_raw` accepts raw only, so an old-format blob will not
  extract. Decide whether to also accept zlib, as libfido2's reader does.
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
- **Windows GUI icon** *(no hardware — needs a Windows machine)*: confirm the
  embedded icon shows in Explorer and the taskbar, and that Linux/macOS builds
  are unaffected (the `winresource` build-dep is host-gated). Future signed GUI
  binaries should then be byte-identical to CI plus a signature, with nothing
  injected.

---

## Deferred to a later release

- **PC/SC: `dlopen` libpcsclite at runtime instead of hard-linking it** — the
  real fix for [#47](https://github.com/framefilter/keyroost/issues/47).
  Two payoffs: the *host's* libpcsclite is always used (the only client
  guaranteed to match the host's `pcscd`, for every distribution channel, not
  just the AppImage), and when it is absent keyroost still launches with
  FIDO/USB-HID working and the PC/SC panes showing "PC/SC unavailable".
  Removes the known limitation documented in
  `packaging/appimage/build-appimage.sh`. The `pcsc` crate links at build time —
  check whether it exposes a dynamic-load path or whether we wrap libpcsclite in
  a thin FFI loader ourselves. Design first; verify on a host with and without
  the library.
  **Backburnered by the maintainer (2026-08-15): the last attempt required
  `unsafe` on more surface than they were comfortable with.** Do not pick this
  up without a design that keeps the unsafe footprint to a thin, isolated
  loader crate — and maintainer sign-off on that design first. Also gates the
  AppImageHub submission (#53): the catalog CI runs on a bare VM without
  libpcsclite, where the hard link fails before main().

- **musl static Linux build** — under consideration, notes-only, not wired into
  any workflow. The draft design and runbook are in `packaging/musl/README.md`;
  the recommendation there is CLI-only (`keyroostctl`), never a musl static GUI.
  Fixes the glibc-version portability caveat; the wrinkle is `libpcsclite`
  linking for the PC/SC path (and the dlopen item above changes that calculus).
  Think it through before committing.

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
  declined HID probe now points at the CCID fix. Do not resurrect "teach the
  HID path to speak this format" — there is nothing to speak to, and what the
  dead channel echoes when poked is not worth settling.

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
  What a product id is still good for: **labelling** ("Bio3 Dual (FIDO + PGP)")
  and colouring an error message. Never for granting or withholding a surface.
  `TOKEN2_PRODUCTS` says as much in its own docs — "nothing here may be treated
  as proof that an applet is present" — and the inverse is no safer.

- **Windows signing: keep signing with Token2; winget always waits for the
  signed zip.** No own signing identity for now — Azure Artifact Signing /
  Certum would put the maintainer's legal name in the cert CN, and SignPath's
  OSS programme rejected the project as too new (re-apply 6–12 months from
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
- **Flathub is intentionally skipped** (its stance against AI-authored code);
  distribution is the self-hosted signed OSTree remote plus the offline
  `.flatpak` bundle.
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
