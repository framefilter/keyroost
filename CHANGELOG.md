# Changelog

All notable changes to keyroost are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **OTP codes on a Token2 key can be put behind a PIN.** Keys running the
  R3.4 OTP applet can require a PIN before they hand out codes: `otp
  set-pin` protects a key, `otp verify` opens the read window,
  `otp change-pin` / `otp remove-pin` manage it, `otp pin-status` reports
  whether one is set and how many attempts remain, and `list` / `add` /
  `delete` take `--pin-env` or `--pin-stdin` to unlock in passing (the
  PIN is never an argument). The GUI's OTP pane grows an unlock prompt, a
  set/change/remove dialog and a "Lock now" action. The PIN travels
  encrypted under a per-connection ECDH session and is never sent in the
  clear. Two things to know before setting one: there is no reset — an
  exhausted retry counter is recoverable only by erasing every OTP entry
  on the key — and keyroost does not verify the device's P-521 agreement
  signature, so over NFC an attacker who runs the key agreement can take
  one verify blob away and brute-force a numeric PIN offline without
  touching the retry counter. Keys without the feature are unaffected:
  they answer the capability probe with "no such command" and everything
  behaves exactly as before. Contributed by @token2. ([#107])

### Changed
- Library API (`keyroost-token2otp`): `EncryptError` gains a `BadLength`
  variant (an exhaustive `match` needs a new arm).

## [0.8.0] - 2026-08-24

**Why 0.8.0 and not 0.7.9:** this release changes the published library
crates in ways that require adjustments from code built on them — a new
`Instruction` variant in `keyroost-piv` and a new public field on
`keyroost-resolve`'s `Device` — so the version number says so, per semver.
Nothing else should be read into the jump: there is no 0.7.9, the 0.7
series simply ends here, only the latest release is ever maintained, and
the app itself is unaffected. Exact adjustments for library users are in
the [migration notes](https://framefilter.github.io/keyroost/migration.html).


### Added
- **`piv new-chuid`** (and a matching GUI action): write a fresh CHUID with a
  random GUID to a PIV card. Windows' PIV minidriver caches a card's contents
  keyed by the CHUID's GUID, so re-randomizing it makes Windows re-read a
  reprovisioned card. Encoding matches `yubico-piv-tool`'s template; the GUID
  comes from the OS's secure random source. Contributed by @episource. ([#102])
- **Nitrokey 3 PIV support.** keyroost's PIV surface now works on the
  Nitrokey 3, whose applet omits several Yubico extensions — the differences
  are detected from the card's own responses, never from its make or model.
  Verified end-to-end on a Nitrokey 3A NFC by the contributor, @episource,
  and cross-checked against Nitrokey's published firmware source. ([#102])

### Changed
- **keyroost now says when it couldn't check a capability instead of guessing
  silently.** A capability can be verified present (the device answered for
  it), absent, or *unverified* — offered without device evidence, which
  happens when a key is seen only over USB-HID and no smart-card reader was
  available to ask. Unverified capabilities behave exactly as before (the
  surface is offered and trying it gives the definite answer), but they are
  now rendered honestly: the GUI tab and capability pill gain a quiet "?"
  with an explanation, the CLI overview and `list` show e.g. `OTP?`, and the
  `--json` device output carries the state in a new `caps_unverified` field.
  This closes the gap behind the #82 → #95 OTP back-and-forth: the old
  present/absent-only model had to write "could not check" down as one or the
  other, giving a guess an authority it should never have had. ([#95])

- **`piv generate-key --pin-policy` / `--touch-policy` now explain
  themselves.** The flags have chosen the key-generation PIN/touch policy
  since PIV management landed, but `--help` never said what the values mean.
  It now spells out that `default` sends the standard PIV command every card
  accepts, and that the other values are a Yubico extension
  (firmware-dependent). Settles the CLI half of the [#97] review follow-ups —
  the GUI/CLI parity itself turned out to already exist. ([#97])

### Fixed
- **PIV commands with large payloads now work on cards that only speak
  short APDUs.** Signing and certificate import used extended-length APDUs
  unconditionally; cards that reject those (the Token2 PIN+ contact
  interface among them) now get the same bytes as a chained sequence of
  short commands instead. Cards that accept extended-length see identical
  traffic to before, pinned by tests. Contributed by @episource. ([#101])
- **The app now says which version it is.** The GUI shows a small version
  next to the wordmark in the top bar, and the AppImage embeds its version in
  the bundle metadata (`X-AppImage-Version`) so AppImage managers such as
  Gear Lever can display it. Previously the version was visible nowhere —
  not in the app, not in the AppImage. Reported by @alphazo. ([#98])

## [0.7.8] - 2026-08-13

### Fixed
- **The armed FIDO reset now survives Linux reusing the device path on
  replug.** The kernel hands a freed `/dev/hidrawN` name straight to the next
  device, so unplugging and replugging a key could bring it back on the exact
  path it had before — which the replug detector read as "never left", and the
  reset waited forever at the touch prompt. Reinsertion is now recognised by
  the USB attach itself (bus and device number, which advance on every plug),
  with the path kept as the fallback on macOS and Windows. Found, fixed and
  hardware-verified by first-time contributor @Algoritter — thank you! ([#96])
- **A replugged key identified by its card serial can re-match again.** The
  reinsertion check could only recognise a key by its USB serial or a YubiKey's
  CCID serial, so a key whose identity comes from a card applet (a Token2
  FIDO+PGP key, for instance) could arm the reset but never be recognised when
  it came back. The check now re-reads identity the same way it was captured
  when arming. Also part of [#96], same contributor.
- **A wrong OTP PIN now says so.** Four documented Token2 OTP status words were
  missing from keyroost's table, so a wrong PIN, a locked PIN, a
  function-not-available answer and a session-ordering fault all surfaced as
  "unexpected status word 0x…". All four are now named, with the locked-PIN
  message saying what recovery requires (a full OTP reset). ([#95])
- **A FIDO2 card in a smart-card reader can now actually be reset.** The reset
  flow assumed a USB key: it waited for an unplug, a replug, and a touch — none
  of which exist for a card sitting in a reader, so the dialog polled forever
  and the only way out was Cancel. A card now resets *in place*: keyroost
  power-cycles it in the reader (which opens the same brief after-power-up
  window a replug does) and sends the wipe immediately — no replug, no touch.
  The CLI gains the same route: `keyroostctl fido reset --yes --reader <name>`,
  and `keyroostctl factory-reset` picks it automatically for a card. USB keys
  keep the replug ceremony unchanged. ([#84])
- **A key that answers is no longer reported as a key that can't be reached.**
  Running an OTP command against a Token2 model that carries OTP over CCID said
  "the OTP applet is not reachable over HID or CCID — HID may be disabled on the
  key", which sent people to enable an interface that was already working: the
  key had completed a full USB-HID exchange and simply declined. These models
  ship with the HID channel disabled *by design*, because they have no
  HOTP-over-HID, so there was nothing on the key to enable. keyroost now tells
  the two apart — an applet that answers with a status word means the interface
  works and the key declined — and reports the failure that can actually be
  acted on: why the CCID path was unavailable (a stopped smart-card service, in
  the reported case), with the status word quoted and `--transport ccid`
  named. ([#95])
- **Token2 keys are offered the OTP surface again, whatever their product id.**
  v0.7.7 stopped listing OTP for product ids whose vendor function set omits it.
  Token2 has since confirmed that a function set omitting OTP does not mean the
  applet is absent: a key can carry OTP over CCID while its id reads FIDO+PGP.
  In practice v0.7.7 rarely got this wrong — when a card reader is present the
  capability comes from actually selecting the applet on the device, and that
  answer always wins — but with no reader, or no smart-card service running, the
  product id was the only evidence and a key could be shown without OTP it may
  well have. The guess is gone. A key that genuinely lacks the applet now
  reports which channel declined and what to do about it, instead of failing
  with a raw protocol error. ([#95])

## [0.7.7] - 2026-08-04

### Added
- **PIV move-key:** relocate a private key between slots (`keyroostctl piv
  move-key --from <slot> --to <slot>` and a GUI "Move key…" action), including
  the 20 Yubico retired key-management slots (82–95) for key archival /
  rotation. Non-destructive — refuses an occupied destination; the certificate
  stays in the source slot. Requires firmware 5.7+.
- **Extract an SSH certificate from a FIDO2 key** (`keyroostctl fido ssh-cert
  extract` and a GUI "Save certificate…" action): pulls the OpenSSH
  certificate a tool like `fido2-token` stored in a resident SSH credential's
  largeBlob and writes it as a standard `-cert.pub` file — so the cert travels
  with the key. Read/extract only; PIN required, no touch.
- **Factory reset (all applets):** one action — `keyroostctl factory-reset`
  and a card on the GUI device Overview tab — resets every resettable applet
  on a key (OATH, OpenPGP, PIV, Token2 OTP, then FIDO2). Uses only
  manufacturer-intended resets, and every applet that completes comes back in
  factory condition. Each step reports its own outcome, so anything that does
  not finish is named rather than folded into an overall "done". Per-applet
  resets remain available individually.
  **The name is reused, and that matters for old scripts.** `factory-reset`
  meant the Molto2 profile reset in 0.5.x and earlier, and became
  `molto reset` in 0.6.0. Both spellings are confirmed with `--yes`, so a
  script written against 0.5.x will *not* fail with "unknown subcommand" — it
  will run and wipe every applet on the key rather than only the Molto2
  profiles. Audit any script from that era for the exact string
  `keyroostctl factory-reset` and change it to `keyroostctl molto reset`.
  See `docs/migration.html`.

### Security
- **A forced PIV reset now refuses cards it could not put back together.**
  Wiping a PIV card whose PIN is unknown works by deliberately blocking the
  PIN and then the PUK, and only then sending a reset instruction — which is a
  vendor extension that standards-only PIV cards (issued corporate or
  government badges, for instance) do not implement. On such a card both
  counters were spent and the reset never arrived, leaving it recoverable only
  by whoever issued it. keyroost now checks for that extension *before*
  touching either counter and refuses outright.
- **Two connected keys can no longer be shown as one.** When a security key's
  USB position did not match any card reader, keyroost could guess that a
  reader belonging to a *different* key was its own, merging two physical keys
  into a single row. Card operations then went to one key while FIDO
  operations — PIN entry, credential deletion, reset — went to the other. Both
  the guess and the ordering bug that could still mispair a key have been
  fixed, and one key can no longer disappear from the list. On Windows and
  macOS, where the operating system does not report USB positions at all,
  keyroost now refuses to guess whenever two keys of the same make could each
  plausibly own the reader: it shows them separately rather than picking one.
  A key that is alone with its reader still pairs up as before.
- **An armed FIDO reset can no longer outlive what it was armed for.** If the
  key list failed to refresh, or arming was refused, an already-armed wipe
  could keep waiting invisibly and fire on the next replug — after the window
  had said nothing was armed. Every such path now cancels the ceremony and
  says so, and the wipe re-checks its target before firing.
- **Factory reset's throwaway PIN/PUK guesses are now random.** They were
  fixed constants that were themselves valid credentials, so a card whose real
  PUK happened to match had its PIN silently reset to a value published in the
  source while the wipe never ran. A guess that is accepted is now a hard error
  that names the resulting PIN and tells you to change it.
- **The CLI factory reset now verifies that the key you plugged back in is the
  key you confirmed.** Previously it reset whatever key was present after the
  replug prompt, so inserting a different key from a drawer of identical ones
  wiped that one instead. The GUI already had this guard.
- **A malicious or faulty security key can no longer make keyroost decompress
  unbounded data.** Reading an SSH certificate out of largeBlob storage took
  its size limit from a value the key itself supplied; there is now a host-side
  ceiling checked before any decompression runs.
- **Per-credential largeBlob keys are wiped from memory** after use, in all
  three places they were held.
- **keyroost no longer claims a Token2 key has the on-device OTP applet just
  because it is a Token2.** Capability was decided from the USB *vendor* id, so
  every Token2 key was offered the On-device OTP pane — including the
  configurations supplied without that applet, which then failed with a raw
  protocol error. The vendor's product id says which functions a unit actually
  has, so nine configurations (the FIDO-only, PGP-only and FIDO+PGP variants of
  PIN+ Mini, PIN+ Series and Bio3 Dual) no longer advertise OTP. A product id
  keyroost does not recognise still gets the feature offered, deliberately:
  hiding a function your key really has would be the worse mistake.

### Fixed
- **A key that has no on-device OTP now says so.** Where the key reports the
  function as absent, both the app and the CLI say it was supplied without it —
  and that Token2 keys cannot be upgraded after purchase, so it is not something
  to switch on — instead of surfacing a protocol error. `keyroostctl otp config`
  is never gated on this and now reports the capability explicitly, including
  "unknown" when the key answers with a short config block.
- **Security-key communication errors are explained rather than numbered.** A
  busy key reported only `CTAPHID_ERROR code 0x06`; each of the nine codes now
  carries a plain-language explanation with the specification's name alongside
  it. A busy channel is also retried briefly before being reported, which the
  specification asks clients to do and keyroost did not — that alone accounted
  for failures that cleared on their own moments later.
- **The retired PIV slots are a tab of their own.** They previously sat between
  the slot headings and the panes those headings introduce, listed as bare text
  under a heading whose caret rendered as a missing-glyph box. They now list all
  twenty in their own pane, marking which hold a key, and `Move key` has its own
  row and its own help rather than sharing the Delete heading — it is
  deliberately non-destructive and was filed under a destructive action.
- **A refusal to reset the wrong key names the right reason.** With an
  unrelated smart-card token also connected, refusing to wipe a key that was not
  the one confirmed reported that it "is not a different key" while a different
  key was plainly attached — a token with no security-key interface was being
  counted among the candidates.
- **The Molto2 troubleshooting guide names the real cause of "the token is
  never detected".** On distributions that start the smart-card service on
  demand, the service is usually not running between commands, so replugging
  notifies nothing and each command cold-starts it into the one attempt most
  likely to fail. Documented with the two checks that rule the token out first.
- **`cargo install keyroost` on Windows.** The Windows icon lived outside the
  published crate, so it was absent from the crates.io package and the build
  aborted. Nothing already released was affected — this would have first
  broken on the next release.
- **A card asking for a corrected length mid-transfer no longer restarts the
  whole command.** On strict readers this could re-run the original operation
  up to thousands of times — for `piv generate-key` that meant generating a
  fresh key pair each time — before failing with an unrelated-sounding error.
  Partial responses are now continued rather than discarded.
- **Reading a full-length card response no longer reports the applet as
  absent.** The probe's buffer had no room for the two status bytes, so a
  maximum-size response failed and the GUI hid a tab for a key that was there.
- **Factory reset can complete on keys that expose no serial number.** The
  new replug check refused them outright, which for a FIDO-only key meant the
  command could never succeed. Such a key is now accepted when it is
  unambiguously the only one connected, and refused the moment a second key
  is visible.
- **A blocked PUK no longer stops a factory reset short.** The blocking step
  used a fixed attempt cap instead of the card's real PUK retry count, so a
  card configured with more retries was left with its PIN blocked and nothing
  wiped.
- **Reset reports now tell the truth about the FIDO step.** The GUI summary
  omitted it entirely, so a FIDO reset that failed, was cancelled, or was
  never armed still read as a completed wipe; a later success could not
  correct an earlier failure; and an outcome could be painted onto a
  *different* key's report if the selection changed mid-ceremony.
- **Saving two SSH certificates at once no longer writes the wrong one.**
  Leaving one "Save certificate…" dialog open and starting another wrote the
  second certificate to the first one's filename.
- **A slow-to-reappear key is no longer accused of being the wrong key.** After
  the replug prompt, a key's serial is read over its card interface, which
  re-registers a moment after the FIDO one. keyroost waited under a second and
  then reported that a different key had been connected. It now waits up to
  three seconds — still well inside the reset window — and, when a key simply
  has not identified itself yet, says so instead of alleging a swap, naming the
  command that finishes the job.
- **A factory reset abandoned part-way now says what it did.** Selecting
  another key while the applets were being wiped discarded the whole report
  silently — including which applets had been erased and whether PIV had been
  left locked. It now records that in the log.
- **PIV reset failures are no longer all called permanent.** A card answering
  the reset with a transient or unspecific status was declared unrecoverable
  and the user was steered away from retrying. Only the statuses that genuinely
  mean the card has no reset instruction say that now.
- **Error messages no longer suggest commands that cannot run.** Several hints
  printed a command without its required `--yes`, or without its subcommand
  group, so following them verbatim failed — including the PIV recovery hint
  shown at exactly the moment it needs to work first try. The PIV hint also no
  longer claims a card is recoverable when the card has refused the reset with
  both credentials already blocked.
- **Smart-card vendor and serial now come from the card, not the reader**
  ([#83]). A Token2 smartcard in a third-party reader now shows the full
  device serial (read over any reader, including T=0 readers) and the vendor
  "Token2" — previously it showed only the 8-digit OpenPGP serial and the
  reader's name. OpenPGP cards from any vendor now get their correct vendor
  name via the standard manufacturer-ID registry.

## [0.7.6] - 2026-07-17

A bug-fix release for three field reports, plus the follow-through on the
v0.7.5 audit: deeper fuzz/property coverage and a self-healing release
pipeline.

### Fixed
- **CTAP 2.0-only keys can be reset again** ([#81]). The FIDO Settings tab —
  home of the "Reset this key" card — was gated on `authenticatorConfig`, a
  CTAP 2.1 feature, while reset itself is baseline CTAP 2.0. The tab now
  appears for any CTAP2 key; only the advanced security-policy controls
  inside it remain 2.1-gated.
- **Reset no longer hides behind the PIN it exists to recover from.** The
  Reset card now renders even when the key can't be unlocked — PIN forgotten
  or blocked, no PIN set, or no PIN support at all. `authenticatorReset`
  never needed a PIN; the GUI just wouldn't show it.
- **On-device OTP works again on firmware with a quirky HID dialect**
  ([#82]). Some keys answer the OTP-over-HID probe with a reply that omits
  the ISO status word, which v0.7.5's strict device binding surfaced as
  `unexpected status word 0x0105`. Automatic transport now falls back from
  USB-HID to the *same key's* smart-card interface — the pre-0.7.5
  resilience, without reopening the first-matching-key hole (KEY-003).
- The Passkeys tab is only offered on keys that actually support credential
  management, and the remembered tab selection snaps to a tab the selected
  key has (switching from a fingerprint key to one without a sensor no
  longer strands the pane on a ghost tab).
- Keys without `clientPin` support now say so, instead of showing
  "Reading key…" forever.
- **Flatpak clients can no longer be stranded on an old version** ([#80]).
  The AppStream release list is now generated from this changelog at bundle
  build time — the hand-maintained copy that silently fell three releases
  behind is gone, and CI fails any change where the changelog and workspace
  version disagree.

### Added
- Two new fuzz targets: the Windows HID interface-detail parser (the
  audit's KEY-020 surface) and the ISO 7816-4 `6C xx` retry classifier,
  which moved into `keyroost-proto` as `apdu::resend_with_le` to be
  fuzzable (new public API).
- Randomized property tests (dev-only, via proptest) over the GUI and CLI
  fail-closed device-binding guards and the terminal-output sanitizers.

### Changed
- The Linux bundle workflow can now be re-run out of band, publish.yml
  style: build-only probes from any branch, and tagged republishes into an
  existing release with a version guard and `flatpak_only` support.
- winget now waits for the Token2-signed Windows build and verifies its
  Authenticode signature before submitting — `winget install` may trail a
  release by a few days, in exchange for signed bytes and no more
  release-day races against Defender validation false positives. An
  expired winget token now fails the job loudly instead of skipping
  silently.

## [0.7.5] - 2026-07-14

A security-focused release: every open finding from an external security
audit (KEY-001..KEY-020) plus a full branch review is closed here. With thanks
to [Texas Cyber Command](https://www.txcc.texas.gov/) for a thorough,
actionable report.

### Security
- **Operations are bound to the exact device you selected.** Previously,
  several GUI flows (Molto2 sessions, FIDO PIN dialogs, OATH/OpenPGP
  confirmations, fingerprint and large-blob operations, the OTP pane) and the
  CLI `otp`/`molto` command groups could act on the *first matching* key or on
  a stale selection — with two keys plugged in, a write, delete, or factory
  reset confirmed for one key could land on the other. Every session, modal,
  and destructive confirmation now records the device it opened for, verifies
  it before acting, and is discarded when the selection changes. An armed FIDO
  reset re-identifies the replugged key by a stable serial and refuses to arm
  for a key that has none.
- **Two keys reporting the same serial no longer collapse into one identity.**
  Name resolution (`--device`, friendly names) fails closed with an ambiguity
  error instead of guessing, and the GUI warns that naming cannot tell such
  keys apart (they stay separately selectable).
- **Hostile or buggy devices can no longer panic or hang keyroost.** The
  published OATH, PIV, and OpenPGP byte layers return typed errors instead of
  panicking on device- or caller-supplied lengths; device-driven loops (OTP
  enumeration pages, fingerprint capture, wrong-length retries, the Windows
  HID path scan) are bounded by host-owned caps; and Linux hidraw reads are
  budgeted so a device that goes silent mid-response can't block forever.
- **Debug traces and terminal output leak less.** CTAP request payloads
  (friendly names, user entities) and large-blob traffic are redacted in
  debug traces; all terminal sanitization goes through one classifier
  covering the full set of spoofing/bidi/zero-width codepoints.
- **Secret file output is symlink-safe.** `keyroostctl`'s private-file writer
  creates an exclusively-owned 0600 file and renames it into place, refusing
  symlinks, non-regular files, and foreign-owned destinations.
- **The release supply chain is pinned.** The AppImage/Flatpak build inputs
  (cargo-sources generator, its Python deps, linuxdeploy, the Flatpak builder
  image) are pinned to immutable commits, content hashes, or digests and
  verified before execution; a CI policy check rejects any return to mutable
  refs; both bundles now ship sha256 sidecars and build-provenance
  attestations like the main archives.
- **6Cxx wrong-length retry regression fixed:** the retry no longer corrupts
  body-carrying Token2 OTP commands (it overwrote the last data byte of the
  encrypted seed with an Le byte).
- SECURITY.md now states precisely where `unsafe` exists (two Windows-only
  FFI shim crates); the workspace-wide forbid stands everywhere else.

### Fixed
- **On-demand HOTP codes on password-protected OATH keys.** The listing
  consumed the typed password, so "Read code" always sent an empty one and
  failed; the accepted password is now retained (zeroized) for follow-up
  reads and dropped on rejection or device switch.
- **Credential listing survives one malformed RP entry** from quirky
  authenticators instead of aborting the whole enumeration — and no longer
  queries a guessed RP hash for such entries.
- GUI settings and the key registry can no longer resolve to different
  config directories on Windows (the duplicated resolver that caused the
  earlier settings-persistence bug is gone).
- The rename field no longer keeps a 2 Hz repaint loop armed while open.

## [0.7.4] - 2026-07-06

### Added
- **Molto2 slot overview.** keyroost now reads each profile slot's stored title,
  occupancy, and TOTP configuration directly from the token, so the GUI slot
  list and the new `keyroostctl molto slots` command show what's actually on the
  device instead of tracking it blind. Adds title-only editing (rename a slot
  without re-entering its seed), per-slot **seed deletion** (`keyroostctl molto
  delete`, confirm-gated in the GUI), title read-back (`molto title -p <N>`), and
  a "Refresh slots" button that re-reads on demand. The wire format is documented
  in `docs/PROTOCOL.md`. **Security note:** slot titles and occupancy are
  readable by anyone holding the token — no customer key needed — so don't put
  secrets in titles.
- **FIDO2 large-blob legibility.** The Storage view classifies each large-blob
  entry (keyroost note / OpenSSH certificate / opaque relying-party data),
  decodes recognized ones (including parsed SSH-certificate validity), shows a
  capacity meter, and can export any entry to a file. `keyroostctl large-blob
  list`/`get` gain the same classification and a capacity line, plus a new
  `export` subcommand.

### Fixed
- **Change-PIN now confirms the new PIN.** The GUI change-PIN flow asked for the
  new PIN only once, unlike the set-PIN flow, so a typo could be committed and
  lock the key. It now requires a matching confirmation entry with the same
  validation as set-PIN, and zeroizes the typed PINs from memory when the dialog
  closes. Thanks to [@token2](https://github.com/token2) and @jurjendevries
  ([#79](https://github.com/framefilter/keyroost/issues/79)).
- **AppImage: a clear message when `libpcsclite` is missing.** The AppImage needs
  the host's PC/SC client library to start; without it the app aborted at the
  dynamic linker with a cryptic error. It now prints an actionable,
  per-distribution "install pcscd" message instead
  ([#78](https://github.com/framefilter/keyroost/issues/78)).
- **The CLI no longer panics on a closed output pipe.** Piping long output into
  `head` (or any early-closing reader) dumped a Rust backtrace; it now exits
  quietly, like a normal Unix filter.
- **Terminal-escape hardening.** Device-provided strings — serial numbers,
  certificate fields, Molto2 titles — are stripped of control characters before
  they reach the terminal, closing an escape-injection vector.
- The GUI's Molto2 slot list refreshes after writes and factory resets instead
  of showing stale data, and `keyroostctl molto slots --json` emits a
  serial-bearing, parseable JSON object.

### Changed
- The Learn site (`framefilter.github.io/keyroost`) gains a Molto2
  troubleshooting section and now deploys through a GitHub Actions workflow.
  `docs/PROTOCOL.md` documents the Molto2 per-profile read (`0x41`) and keyless
  seed delete (`0xE6`).
- **winget:** `Framefilter.Keyroost` is now live in the Microsoft catalog —
  `winget install Framefilter.Keyroost`.

## [0.7.3] - 2026-06-30

### Added
- **Windows: non-admin FIDO2 detection** — an unelevated process can't read a
  FIDO key's HID usage page on Windows, so FIDO-only keys used to disappear from
  the device list with no explanation. keyroost now detects the key via the
  access-denied signal and shows an "Administrator rights needed" card in the
  FIDO2 tab, with buttons to open Windows' built-in security-key settings or to
  relaunch elevated (new `keyroost-winwebauthn` helper crate). Thanks to
  [@token2](https://github.com/token2)
  ([#58](https://github.com/framefilter/keyroost/issues/58),
  [#62](https://github.com/framefilter/keyroost/pull/62)).
- **`KEYROOST_X11=1`** — opt-in environment variable that forces the GUI onto
  XWayland, a fallback for Wayland compositors where native input misbehaves.

### Fixed
- **GUI text input on Wayland / KDE Plasma** — on some compositors (notably KDE
  Plasma 6.7) the window lost keyboard focus shortly after startup and no field
  accepted typed input. The UI-toolkit update (below) resolves it; native
  Wayland input works again
  ([#48](https://github.com/framefilter/keyroost/issues/48)).
- **Light-theme zoom control** — the "Text size" slider, its handle and the ±
  steppers were nearly invisible on the light theme; they now use a contrasting
  control colour. The ± steppers also no longer slide out from under the cursor
  during repeated clicks — they preview and apply once you settle
  ([#59](https://github.com/framefilter/keyroost/issues/59),
  [#42](https://github.com/framefilter/keyroost/issues/42)).
- **winget (Windows):** the package manifest now declares the
  `Microsoft.VCRedist.2015+.x64` dependency, so winget pulls in the VC++
  runtime the Windows build needs alongside keyroost.

### Changed
- **UI toolkit updated** (egui/eframe 0.29 → 0.35) — this fixed the Wayland/KDE
  input bug above and is a sizeable refresh of the GUI layer. It should look and
  behave just as before, but **please
  [open an issue](https://github.com/framefilter/keyroost/issues) if you spot
  anything off** so it can be polished. Building from source now requires
  **Rust 1.85** or newer.

## [0.7.2] - 2026-06-26

### Added
- **Token2 single-profile programmable TOTP token** — a `keyroostctl prog`
  group (`info` / `seed` / `config`) and a GUI pane that program the seed and
  TOTP configuration onto Token2's single-account card/fob tokens (OTPC-P1-i /
  P2-i, miniOTP-2-i / 3-i, C301-i, C302-i) over a PC/SC reader, authenticating
  with the device's fixed key (no customer key, single slot). A new pure-Rust
  `keyroost-token2prog` crate carries the wire protocol — a close relative of
  the Molto2's (same SM4 cipher and ISO/IEC 9797-1 MAC) — documented
  independently in `docs/PROTOCOL-token2prog.md`. The write commands refuse to
  run unless the device serial matches a known model
  ([#49](https://github.com/framefilter/keyroost/pull/49)).
- **Contact-reader (ISO-7816 T=0) support** — FIDO2 and on-device OATH now work
  over a contact / chip reader as well as NFC, completing the PC/SC transport
  begun in 0.7.0 (the `61 XX` / `GET RESPONSE` and `6C XX` continuations are
  reassembled for T=0 readers)
  ([#43](https://github.com/framefilter/keyroost/issues/43)).
- **QR-from-screen scanning** — the `qr` import feature can now scan a QR code
  straight from the live screen, in addition to PNG/JPEG screenshots and Google
  Authenticator export batches, and is compiled into the pre-built release and
  AppImage binaries ([#50](https://github.com/framefilter/keyroost/pull/50)).
- **OTP secret reveal toggle** — secret-entry fields in the GUI gain a reveal
  (eye) toggle so you can verify an OTP secret before committing it
  ([#52](https://github.com/framefilter/keyroost/issues/52)).
- **Fuller passkey details** — resident-credential metadata now surfaces the
  user's UPN, display name, user id, and the full credential id
  ([#55](https://github.com/framefilter/keyroost/issues/55)).
- **AppImage AppStream metainfo + zsync** — the AppImage now ships AppStream
  metainfo and a `.zsync` sidecar for delta updates
  ([#53](https://github.com/framefilter/keyroost/pull/53)).

### Changed
- **Relaxed, anti-spoofing device naming + Windows config path** — friendly
  device names accept a more permissive, readable character set while being
  validated against spoofing (e.g. homoglyph / control-character) tricks, and
  the `keys.json` registry is saved under `%APPDATA%` on Windows
  ([#56](https://github.com/framefilter/keyroost/issues/56)).

### Fixed
- **Duplicate device entries when several keys are plugged in** — keys are now
  de-duplicated by USB topology, so the same physical key no longer appears more
  than once during enumeration
  ([#51](https://github.com/framefilter/keyroost/pull/51)).
- **AppImage uses the host's pcsc-lite** — the AppImage no longer bundles its
  own libpcsclite, instead linking the host's so the smart-card client always
  matches the host `pcscd` daemon
  ([#47](https://github.com/framefilter/keyroost/pull/47)).

## [0.7.1] - 2026-06-21

A bugfix release: it repairs the Flatpak repository install (broken in 0.7.0)
and two text-size controls in the GUI. No library or protocol changes — the
`keyroost-*` crates are unchanged save for the version bump.

### Fixed
- **Flatpak repo install failed GPG verification** — the published OSTree repo
  signed only its summary, not the commit objects, so installing from the remote
  failed with *"GPG verification enabled, but no signatures found"* even though
  `flatpak remote-info` (which checks only the summary) succeeded. The release
  workflow now signs the commits (`flatpak build-sign`) before refreshing the
  summary. The offline `.flatpak` bundle attached to each release was unaffected.
  Reported by [@errant253](https://github.com/errant253)
  ([#46](https://github.com/framefilter/keyroost/issues/46)).
- **GUI text-size slider jumped at the 99%↔100% boundary** — the percentage
  readout grew from 3 to 4 characters as the value crossed 100%, and in the top
  bar's right-to-left layout the wider label shifted the slider track under the
  cursor, making the value lurch (to ~110% going up, ~87% coming back down). The
  readout now reserves a fixed width, so the track stays put. Reported by
  [@StefanSa](https://github.com/StefanSa) with a detailed repro from
  [@errant253](https://github.com/errant253)
  ([#42](https://github.com/framefilter/keyroost/issues/42)).
- **Ctrl +/- zoom ignored the 80–200% bounds** — keyboard and scroll zoom could
  scale the interface past the slider's limits (roughly 20–500%) while the
  readout and the persisted value capped at 200%. Keyboard zoom is now clamped to
  the same range as the slider
  ([#42](https://github.com/framefilter/keyroost/issues/42)).

### Changed
- **README** — the winget entry is marked pending Microsoft's catalog review (the
  manifest is submitted but not yet merged into the public catalog), and the
  available-channels summary now reflects the Flatpak and AppImage bundles that
  shipped in 0.7.0. Prompted by [@errant253](https://github.com/errant253)
  ([#46](https://github.com/framefilter/keyroost/issues/46)).
- **README — supported-devices accuracy + a Roadmap section.** Corrected the
  device table (dropped dated framing, fixed an OpenPGP line that implied a
  standalone "register for GnuPG" command when the fingerprint/timestamp is
  written by generate/import, and added a row describing behavior on any
  standards-compliant FIDO2 key), and added a Roadmap section listing planned
  OnlyKey support ([#37](https://github.com/framefilter/keyroost/issues/37)) and
  inviting hardware-support requests via issues.

## [0.7.0] - 2026-06-20

### Added
- **FIDO2 over NFC readers** — a `CtapTransport` abstraction lets the CTAP
  command layer run over PC/SC as well as USB-HID, so FIDO2 (getInfo, passkey
  management) and on-device OTP now work through an NFC reader, not just direct
  USB. Contact / ISO-7816 chip readers are not yet supported (the contact path
  is deferred to follow-up; the PC/SC transport is shared, so it's an
  incremental fix). Contributed by Emin Huseynov / [@token2](https://github.com/token2)
  ([#44](https://github.com/framefilter/keyroost/pull/44), addressing
  [#43](https://github.com/framefilter/keyroost/issues/43)).
- **OpenPGP INTERNAL AUTHENTICATE** — `openpgp authenticate` produces a
  client/SSH authentication signature with the on-card Authentication key
  (PW1 in the "other" context). The Auth key slot is now selectable for
  provisioning too (`openpgp generate-key --slot auth`, `openpgp import-key
  --slot auth`), completing the third OpenPGP key.
- **PIV slot clearing** — `piv delete-cert` removes a slot's X.509 certificate
  object while leaving the private key in place (standard PIV; works on every
  card), and `piv delete-key` permanently erases a slot's private key (a Yubico
  extension requiring YubiKey firmware 5.7 or newer). Both need the management
  key and require an explicit `--yes`.
- **CTAP 2.1 authenticator config and large-blob storage** — a `fido large-blob`
  group (`list` / `get` / `add` / `edit` / `delete` / `clear`) reads and edits a
  key's `authenticatorLargeBlobs` array, keeping keyroost's own plaintext notes
  alongside relying-party entries (writes pull a `largeBlobWrite` token from the
  PIN and re-read the live array so RP entries are never clobbered; the store is
  world-readable, so it is for notes, not secrets). FIDO security-policy controls
  over `authenticatorConfig` — always-require-UV, raise minimum PIN length, force
  a PIN change, and enable enterprise attestation — plus a FIDO2 tab redesign in
  the GUI. Contributed by [@token2](https://github.com/token2)
  ([#38](https://github.com/framefilter/keyroost/pull/38)).
- **Linux desktop bundles** — a self-hosted Flatpak (signed OSTree remote with
  auto-update, plus an offline `.flatpak` bundle) and an AppImage of the GUI,
  both built by a new `linux-bundles.yml` workflow that triggers on `v*` tags and
  is gated behind the same `release-publish` approval as the other channels. The
  Flatpak OSTree is hosted in a dedicated `keyroost-flatpak` Pages repo (Flathub
  is intentionally not used). A Homebrew tap (`framefilter/homebrew-keyroost`)
  rounds out the fanout. (Flatpak ships the pcsc-lite client lib and talks to the
  host `pcscd`; end-to-end hardware verification of the sandboxed bundles is still
  pending.)

### Changed
- **Consolidated, card-based GUI across the FIDO2, PIV, and OpenPGP panes** — a
  significant redesign so every applet pane shares one visual vocabulary:
  per-slot / per-key sub-tab strips (PIV 9A/9C/9D/9E, OpenPGP sig/enc/auth),
  full-width cards with right-pinned actions, inline `?` help bubbles in place of
  verbose notes, and a global content-width cap (~920px, centered) that fixes the
  wide-window label↔action gap. Applet-wide administration (PIN/PUK, retries,
  management key, reset) is folded into each pane's status card instead of
  floating loose, and secret entry routes through a centered, scroll-independent
  credential modal that shows the operation result in place.
- **Vendor-neutral applet support, documented as such** — the OATH, OpenPGP, and
  PIV byte layers are open-standard implementations that work over CCID with any
  card exposing those applets (YubiKey, Nitrokey, SoloKeys, Feitian, Token2,
  OpenSK, …), not just YubiKeys; the README capability matrix and the github.io
  pages were reconciled to say so
  ([#41](https://github.com/framefilter/keyroost/issues/41)). The OATH / OpenPGP
  / PIV applets on the Token2 PIN+ are this same standards code; they remain
  marked experimental only because the project has not yet exercised them on
  physical PIN+ hardware.
- **Friendlier README intro** — a more approachable opening and a "What it is"
  framing so the project reads clearly to newcomers. Readability suggestion by
  [@errant253](https://github.com/errant253)
  ([#45](https://github.com/framefilter/keyroost/pull/45); the accompanying
  install script was declined).

### Fixed
- **Canonical CBOR key order in large-blob writes** — large-blob payloads now
  emit map keys in canonical order (parameter `0x05` before protocol `0x06`), so
  spec-strict authenticators (Solo 2, Nitrokey) accept the writes. YubiKey is
  lenient, which is why the earlier hardware round-trip passed.
- **Large-blob deletes no longer clobber relying-party entries** — the GUI delete
  path now re-reads the live large-blob array in the worker and removes the
  matching entry by content, instead of writing back a stale cached array. This
  protects RP entries written since the array was last loaded and avoids a
  position-shift wrong-delete (matching the add/edit/CLI paths).
- **Clearer destructive-action wording** — the "Clear all storage" action and the
  FIDO reset-dialog hint now state plainly that clearing erases every large-blob
  entry, including relying-party data, not just keyroost's notes.
- **OATH unlock submits on Enter** — pressing Enter in the OATH unlock field now
  submits, matching the FIDO2 unlock card and the rest of the redesign.

## [0.6.0] - 2026-06-17

### Added
- **Device-centric bare overview** — running `keyroostctl` with no subcommand
  now prints a device-centric overview of what is connected, and `list` is
  enriched with per-device detail (applets, serials, friendly names).
- **`--name` targeting on every group** — the friendly-name selector now works
  across all command groups (`molto`, `fido`, `oath`, `openpgp`, `piv`, `otp`),
  not just a subset, so one named key can be addressed consistently everywhere.
- **Per-group man pages** — `keyroostctl manpage <DIR>` now writes a directory
  set of man pages (one per command group) instead of a single page on stdout.
- **Global `--json` output mode** for the status/query commands — `list` /
  overview, `*/status`, `*/info`, `fido pin-retries` / `creds-list` /
  `creds-metadata`, `oath list` / `code`, and `otp list` / `get` / `serial` can
  now emit machine-readable JSON instead of human text.
- **OpenPGP PIN management** — `openpgp change-pin`, `openpgp change-admin-pin`,
  and `openpgp unblock-pin`, closing the OpenPGP PIN-management gap.
- **Token2 PIN+ fingerprint enrollment** (`fido fingerprint-list` / `enroll` /
  `rename` / `delete`), FIDO Metadata Service (MDS) metadata in the GUI, and
  on-device OTP improvements — contributed by
  [@token2](https://github.com/token2)
  ([#29](https://github.com/framefilter/keyroost/pull/29),
  [#30](https://github.com/framefilter/keyroost/pull/30)).
- **GUI PIV pane detail** — each slot now shows its certificate Subject DN and
  key algorithm, and a slot holding a key with no certificate is distinguished
  from an empty one; the pane auto-refreshes after a write
  ([#31](https://github.com/framefilter/keyroost/issues/31)).
- **In-tree X.509 Subject-DN reader** (`keyroost-piv`) — a small, panic-safe,
  dependency-free DER certificate reader backing the slot display above.
- **Confirm-PIN fields** on the GUI PIV Change-PIN and Change-PUK dialogs, so a
  mistyped new PIN can't lock the card
  ([#36](https://github.com/framefilter/keyroost/issues/36)).

### Changed
- **BREAKING: commands nested under `molto` and `fido` groups.** The flat
  Molto2 and FIDO subcommands have been moved under `molto …` and `fido …`.
  Key renames: `info` → `molto info`, `import`/`import-file` →
  `molto import`/`molto import-file`, `set-seed`/`set-title`/`configure` →
  `molto seed`/`molto title`/`molto config`, `set-customer-key` →
  `molto customer-key`, `factory-reset` → `molto reset`, and every `fido-*`
  command → `fido *` (e.g. `fido-info` → `fido info`, `fido-creds-list` →
  `fido creds-list`). The customer-key flags (`--key`, `--key-env`, …) now live
  under `molto customer-key`. See the migration table in the README for the full
  old→new map.

### Fixed
- **Firmware-accurate PIN guidance in the GUI** — removed the inaccurate "touch
  the key to confirm" hint from the FIDO set/change-PIN flow (CTAP PIN changes
  are not touch-gated) and corrected the PIN/PUK length text per applet
  ([#36](https://github.com/framefilter/keyroost/issues/36)).

## [0.5.1] - 2026-06-14

A follow-up to the Token2-vs-Molto2 device-identification fix.

### Fixed
- Molto2 reader matching keys on the product-name word only ("molto"), not the
  broader Token2 brand string, so a Token2 PIN+ / FIDO2 key is no longer
  mis-detected as a Molto2 (#21).

## [0.5.0] - 2026-06-14

On-device OTP for Token2 FIDO security keys joins the Molto2 programmer.

### Added
- **On-device TOTP/HOTP for Token2 FIDO keys (PIN+ / FIDO2+)** — a pure-Rust
  byte/codec layer (`keyroost-token2otp`) plus CLI (`otp` group) and GUI surface
  to enumerate, read, add, and delete OTP credentials stored on a Token2 FIDO
  security key over USB-HID, including the touch/button-HOTP slot and serial
  read. Contributed by @token2, built from the protocol reference they published
  (#20).

### Fixed
- Token2 FIDO keys no longer masquerade as a ghost Molto2 during device
  enumeration (#21).
- The crates.io "already published?" probe now sends a User-Agent, which some
  endpoints require.

### Docs
- Credit @token2 in a Contributors acknowledgement.

## [0.4.0] - 2026-06-12

Full PIV management, screenshot QR import, package-manager distribution, a
fuzzing suite, and a broad security-hardening pass.

### Added
- **Full PIV management** — beyond read-only status: client/card authentication
  (GENERAL AUTHENTICATE), key generation, certificate import/export,
  PIN/PUK/management-key changes, and applet reset, plus card-signed
  certificates (self-sign into a slot, or emit a CSR for a CA).
- **QR-code import** — pull 2FA secrets from PNG/JPEG screenshots, including
  Google Authenticator export batches.
- **Package-manager distribution** — automated release fanout to crates.io, AUR,
  Homebrew, and winget; `cargo binstall` targets the attested release archives.
- **Fuzzing** — `cargo-fuzz` targets for every hand-rolled parser, run weekly in
  CI.
- **`doctor`, `completions`, and `manpage` subcommands** — environment diagnosis
  and generated shell-completion / man-page artifacts.
- **Supply-chain CI** — a `cargo audit` (RUSTSEC) job on lockfile changes and
  weekly, SHA-256 release checksums, and build-provenance attestation on
  published archives.
- **SECURITY.md** — threat model, security invariants, and disclosure policy.

### Changed
- GUI bulk imports run on a dedicated thread instead of the frame loop, and a
  single shared scroller backs every capability pane.

### Fixed
- Broad post-review hardening: zeroize session secrets, CLI-read PINs, imported
  TOTP seeds, and extracted RSA components on drop; bound device-driven loops
  and lengths; strict base32 padding; cap attacker-controlled scrypt parameters
  in encrypted Aegis vaults; reject `otpauth` secrets over the device's 63-byte
  cap at parse time; atomic owner-only `keys.json` writes with field
  sanitization; redact secret-bearing APDU bodies from `--debug` traces.

### Notes
- The crates.io fanout skips publishing until OIDC / trusted-publishing is
  configured; the other targets and the GitHub Release run unconditionally.

## [0.3.0] - 2026-06-08

keyroost goes cross-platform: macOS and Windows join Linux, with a HID backend
that works on all three, a three-OS CI matrix, and a release pipeline that
attaches ready-to-run binaries for each.

### Added
- **macOS and Windows support** — a `hidapi`-based HID backend covers FIDO
  enumeration on macOS (IOKit) and Windows (hid.dll) alongside the existing
  Linux sysfs/hidraw path; PC/SC (OATH / OpenPGP / PIV / Molto2) was already
  cross-platform. `keyroost_hid::hid_supported()` lets front-ends tell "no FIDO
  devices plugged in" apart from "no HID backend on this platform".
- **Pre-built release binaries for all three OSes** — pushing a `vX.Y.Z` tag now
  cuts a public GitHub Release with a Linux x86_64 tarball, a macOS `universal2`
  tarball (`lipo`'d aarch64 + x86_64, one artifact for Apple Silicon and Intel),
  and a Windows zip, with auto-generated notes. A `workflow_dispatch` trigger
  builds the same archives off a branch for smoke-testing without tagging.
- **Three-OS CI matrix plus Fedora/Arch build verification** — Linux, macOS, and
  Windows build/test on every push, and `fedora:latest` / `archlinux:latest`
  container builds verify the documented per-distro package lists rather than
  assuming them.

### Changed
- The GUI empty state now states explicitly when FIDO keys aren't supported on
  the current platform (and notes that the smart-card features still work), so a
  missing-backend case doesn't read as a bug.
- User-facing "is pcscd running?" messages across transport / resolve / CLI are
  reworded to platform-neutral smart-card-service language.
- `CtapHidDevice::open` returns a clear `HidTransportError::Unsupported` on
  platforms without a HID backend instead of an opaque file-open failure.

### Docs
- README gains full Debian / Fedora-RHEL / Arch prerequisite blocks split into
  CLI vs GUI dependencies, corrects the stale "HID is Linux-only" note, and warns
  that the Ubuntu-built release binaries may not run on older-glibc distros
  (build from source there).

### Notes
- The macOS and Windows release jobs are exercised by `workflow_dispatch`; run
  the release workflow manually once before tagging if the build environment has
  changed.

## [0.2.0] - 2026-06-06

A device-centric GUI redesign, reliable hotplug, a FIDO reset that actually
fits the hardware's window, and the OpenPGP write surface rounded out.

### Added
- **Device-centric GUI** — a persistent sidebar listing each *physical* key once
  with merged capability badges, per-device capability tabs (Overview / FIDO2 /
  OATH / OpenPGP / PIV), and a distinct Molto2 view. Dark/light themes, accent
  colors, a colorblind-safe palette (Okabe–Ito), opaque help popovers, a global
  activity log, and a welcoming empty state. Bundled IBM Plex Sans / JetBrains
  Mono.
- **Reader hotplug auto-detect** — a PC/SC PnP-notification watcher re-enumerates
  on plug/unplug, with a staggered rescan burst so a slow-registering reader
  appears without a manual refresh.
- **FIDO reset that beats the ~10 s window** — arm the reset, then re-insert the
  key; it fires on reconnection (matched by HID serial, so any USB port works)
  and prompts for the touch.
- **OpenPGP PIN management** — change the user PIN (PW1) and admin PIN (PW3), and
  unblock a blocked user PIN with the admin PIN (`RESET RETRY COUNTER`), in a
  rebuilt themed write panel (admin PIN, card details, keys, PINs, reset).
- **Learn site "Naming" page** documenting friendly device names.

### Changed
- Interactive controls (buttons, segmented controls, device rows, icons) gained
  clear hover/press states and a pointing-hand cursor.
- Single-pass PC/SC enumeration; the Molto2 is listed by name and never
  connected during a scan (a probe connect intermittently wedged its CCID slot),
  so refreshing no longer disturbs a held, authenticated Molto2 session.

### Fixed
- CTAP `getKeyAgreement` now declares the negotiated PIN/UV protocol, fixing
  Set/Change PIN on authenticators that strictly enforce it (e.g. YubiKey).
- Empty resident-credential enumeration (`CTAP2_ERR_NO_CREDENTIALS`) is reported
  as "no passkeys", not an error.

### Notes
- Molto2 PC/SC detection on some hosts is bounded by a libccid USB-init timeout
  *below* the application; a direct USB port (avoiding hub chains) is the
  mitigation.
- Still Linux-only; Windows/macOS support is on the roadmap.

## [0.1.0] - 2026-06-02

The first release. keyroost grew from a Token2 Molto2 TOTP programmer into a
multi-vendor hardware-security-key manager, then took its neutral name. Highlights:

### Added
- **FIDO2 / CTAP2** — authenticator enumeration, `authenticatorGetInfo`, resident
  credential management (list / metadata / delete), PIN set/change/verify, reset.
  PIN protocols v1 and v2.
- **OATH (TOTP/HOTP)** over PC/SC — list, add, delete, compute codes, and the
  Yubico applet-password handshake (`SET_CODE` / `VALIDATE`, set/clear/unlock).
- **OpenPGP card (v3.4)** — status; RSA-2048 key generate and import (host keygen
  or PKCS#1/PKCS#8 PEM/DER file); sign (SHA-256 / SHA-1); decrypt (PSO:DECIPHER,
  extended-length + command-chaining); set cardholder name / URL; GnuPG key
  registration; applet reset.
- **PIV (SP 800-73-4)** — read-only status: applet/firmware version, serial, PIN
  retries, and per-slot (9A/9C/9D/9E) certificate presence.
- **Token2 Molto2 / Molto2v2** — slot programming from `otpauth://`; bulk import
  from Aegis (plaintext/encrypted), 2FAS, and `otpauth://` lists; time sync;
  customer-key rotation; factory reset.
- **Friendly device names** — opt-in `keys.json` registry and safe multi-key
  selection (USB + CCID serials, USB-topology matching).
- A CLI (`keyroostctl`) and an egui desktop GUI (`keyroost`).

### Notes
- Linux-only for now (HID enumeration uses sysfs; PC/SC is cross-platform).
- Crypto is pure-Rust and verified against standard test vectors; the only
  external dependencies are `pcsc`, `clap`, `eframe`/`egui`, `serde`, and
  (for RSA keygen/parsing) `rsa`/`rand`.

[#80]: https://github.com/framefilter/keyroost/issues/80
[#81]: https://github.com/framefilter/keyroost/issues/81
[#82]: https://github.com/framefilter/keyroost/issues/82
[#83]: https://github.com/framefilter/keyroost/issues/83
[#84]: https://github.com/framefilter/keyroost/issues/84
[#95]: https://github.com/framefilter/keyroost/issues/95
[#96]: https://github.com/framefilter/keyroost/pull/96
[#97]: https://github.com/framefilter/keyroost/pull/97
[#98]: https://github.com/framefilter/keyroost/issues/98
[#101]: https://github.com/framefilter/keyroost/pull/101
[#102]: https://github.com/framefilter/keyroost/pull/102
[#107]: https://github.com/framefilter/keyroost/issues/107
[Unreleased]: https://github.com/framefilter/keyroost/compare/v0.8.0...HEAD
[0.8.0]: https://github.com/framefilter/keyroost/compare/v0.7.8...v0.8.0
[0.7.8]: https://github.com/framefilter/keyroost/compare/v0.7.7...v0.7.8
[0.7.7]: https://github.com/framefilter/keyroost/compare/v0.7.6...v0.7.7
[0.7.6]: https://github.com/framefilter/keyroost/compare/v0.7.5...v0.7.6
[0.7.5]: https://github.com/framefilter/keyroost/compare/v0.7.4...v0.7.5
[0.7.4]: https://github.com/framefilter/keyroost/compare/v0.7.3...v0.7.4
[0.7.3]: https://github.com/framefilter/keyroost/compare/v0.7.2...v0.7.3
[0.7.2]: https://github.com/framefilter/keyroost/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/framefilter/keyroost/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/framefilter/keyroost/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/framefilter/keyroost/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/framefilter/keyroost/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/framefilter/keyroost/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/framefilter/keyroost/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/framefilter/keyroost/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/framefilter/keyroost/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/framefilter/keyroost/releases/tag/v0.1.0
