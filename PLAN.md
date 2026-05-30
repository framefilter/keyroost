# MoltoUI: extension plan toward a general security-key manager

## Goal

Extend MoltoUI from its current single-purpose role (programming Token2
Molto2 TOTP tokens over PC/SC) into a general-purpose security-key
manager. The long-term feature target is rough parity with Yubico's
`ykman` GUI: FIDO2/U2F first, then OATH, PIV, OpenPGP, and OTP.

The shorthand for this scope is **C-lite**: start with FIDO2/U2F support
and grow from there.

## Current state (as of this branch)

- `molto2-proto` — pure-Rust Molto2 wire protocol (SM4, SHA-1, APDU, MAC).
- `molto2-transport` — PC/SC reader discovery and Molto2 session.
- `molto2-import` — Aegis / 2FAS / otpauth-list bulk import.
- `moltoctl` — CLI binary.
- `moltoui` — egui desktop GUI.

See `docs/PROTOCOL.md` and `CLAUDE.md` for the existing protocol layer.

## Naming policy

`molto2-*` crate names and `moltoctl` / `moltoui` binary names stay for
now. A rename to something neutral (e.g. `keytool-*`) happens once the
FIDO2 work is far enough along that the new identity is obvious — not
before.

## Phases

Sequenced smallest-to-largest. Each phase ends in a working binary; no
half-finished features carried across phase boundaries.

### Phase 0 — Device discovery
USB HID enumeration of FIDO devices via `/dev/hidraw*`. udev rules so an
unprivileged user can talk to FIDO keys. `moltoctl list` learns to show
both PC/SC readers and HID FIDO devices side-by-side.

Linux only at this stage; macOS/Windows are separate later phases.

### Phase 1 — FIDO2/U2F core transport
CTAP HID transport layer (frame assembly, channel `INIT`, channel
allocation), plus a minimal CBOR encoder/decoder. Implement
`authenticatorGetInfo` and `authenticatorReset`. Wire a "Security Keys"
pane into `moltoui` that lists connected keys and shows their CTAP info.

### Phase 2 — FIDO2 credential management
List / add / delete resident credentials (`credentialManagement`
subcommands). PIN set / change / verify.

### Phase 3+ — Reach toward ykman parity

Revised ordering after surveying the Nitrokey 3 / Trussed firmware (the
same stack the user's Solo 2A+ runs). Key insight: OATH, OpenPGP, and PIV
are all **CCID/APDU smartcard applets** on these devices, so our existing
`molto2-transport` PC/SC layer is reusable — each applet just needs generic
APDU framing plus an `AID SELECT`. We do not need a second transport stack
for the smartcard applets.

- **Phase 3 — OATH (TOTP/HOTP).** Best next target: reuses our Molto2
  TOTP/HOTP + base32 code *and* the PC/SC layer. The Nitrokey/Trussed OATH
  applet uses Yubico's AID (`A0 00 00 05 27 21 01`) and the same core INS
  codes (`Put`/`Delete`/`List`/`Calculate`/`SendRemaining`), so one command
  set targets NK3 *and* future YubiKey OATH. Caveat: the Trussed impl
  removed Yubico's `SetCode`/`Validate` authorization handshake, so
  provisioning/list/delete interoperate but OATH password-auth diverges —
  code to the Trussed variant first, treat YubiKey OATH-auth as a later
  compatibility pass.
- **Phase 4 — OpenPGP.** Mature (`opcard`, OpenPGP Card spec v3.4) but
  heavier: full OpenPGP Card APDU set + RSA/curve key management.
- **PIV — demoted.** Upstream `piv-authenticator` was archived read-only
  (2025-03); fine as a spec reference but not a priority target.
- **Yubico OTP — dropped for Trussed devices.** NK3/Solo 2 don't implement
  the 132-char keyboard OTP applet; HMAC challenge-response is folded into
  the OATH/secrets app. Revisit only if we target actual YubiKeys.

**Phase 3 gating question — RESOLVED (2026-05-29, on hardware).** The PC/SC-reuse
plan holds, and better than hoped: the Solo 2 *does* expose a usable USB CCID
interface. `moltoctl list` shows a reader `SoloKeys Solo 2 [CCID/ICCD Interface]
(<serial>) 01 00`, and selecting the Yubico OATH AID (`A0 00 00 05 27 21 01`)
over that reader returns SW `9000` with a 15-byte version TLV, with `LIST`
(INS `0xA1`) also `9000` — i.e. the Trussed secrets/OATH applet answers the
Yubico OATH protocol over USB PC/SC. The same SELECT+LIST succeeds on the test
YubiKey. So OATH goes over PC/SC for **both** stacks; the CTAPHID `0x70` fallback
is not needed. (Earlier worry came from `pynitrokey` driving OATH over CTAPHID
because *their* library lacks CCID support — not a device limitation.)

The pure-Rust OATH byte layer lives in `crates/molto2-oath` (APDU builders,
TLV parsing, RFC-4226 truncation, known-answer tests).

**Phase 3 transport + CLI — DONE (2026-05-29).** `molto2_transport::OathSession`
drives the applet over PC/SC: reader connect, SELECT, the `61xx`/`SEND_REMAINING`
reassembly loop, and `list`/`calculate_totp`/`put`/`delete`. `moltoctl oath
{list,code,add,delete}` wraps it, with reader selection mirroring the FIDO picker
posture (auto-use a lone OATH key, `--reader <substr>` to choose, refuse to guess
among several) and the base32 secret read via stdin/env, never argv. Verified on
hardware: a put→code→delete round-trip on a YubiKey produced a code matching
`oathtool` for the RFC 6238 seed, and SELECT+LIST work on the Solo 2 too.

**OATH password auth — DONE (2026-05-29).** `molto2-oath` gained a vendored
HMAC-SHA1 + PBKDF2-HMAC-SHA1 (on the in-tree SHA-1; no new deps), the
`SET_CODE`/`VALIDATE` builders, the SELECT-response parser (`SelectInfo`,
password-required detection), and the Yubico access-key derivation
(`PBKDF2(password, salt=device id, 1000, 16)`) — all under RFC 2202/6070/6238
known-answer tests. `OathSession` now parses SELECT, exposes `password_required`,
and adds `unlock` (VALIDATE with mutual-auth verification of the card's reply),
`set_password`, and `clear_password`; a dedicated `OathPasswordRejected` error
replaces the misleading Molto2 "wrong customer key" message. `moltoctl oath`
gained `set-password`/`clear-password` and a shared `--password-env/-stdin` on
every subcommand (passwords never in argv); `open_oath` auto-unlocks and errors
clearly when a protected applet has no password supplied. Hardware-verified on a
YubiKey: set → access-refused-without → unlock-with-correct → reject-wrong →
clear → baseline restored.

**HOTP add — DONE (2026-05-29).** `oath add` gained `--type totp|hotp` and a
`--counter` (HOTP initial moving factor); HOTP computation uses a new
`calculate_hotp` that sends an empty CHALLENGE so the card advances its own
counter. `oath code` dispatches on the stored credential type (looked up via
`list`). Hardware-verified on a YubiKey: a HOTP credential provisioned with the
RFC 4226 seed produced the exact documented sequence (755224, 287082, 359152,
969429, 338314) across five reads, then deleted; key restored to baseline.

**OATH GUI pane — DONE (2026-05-29).** `moltoui` gained an "OATH" tab: a
left-panel reader list (enumerated via `OathSession::list_oath_readers`, same
no-guess posture as the CLI), and a central panel that lists credentials and
computes each current TOTP on demand. Password-protected applets surface an
inline unlock field (password sent to the key only, never persisted — disclosed
via the shared `helper_bubble`), and a wrong password is reported distinctly via
the `OathPasswordRejected` path. An inline "Add credential" form (name, base32
secret, TOTP/HOTP, require-touch) provisions via the shared `OathSession::put`,
and each row has a Delete button gated by a modal confirmation (irreversible).
Both honor a set applet password through a shared unlock helper. Verified:
workspace builds, clippy clean, and the pane renders without panicking against a
live YubiKey (launched with the tab defaulted on, then reverted); the underlying
put/delete/unlock paths are the same ones hardware-verified via `moltoctl oath`.
GUI button clicks themselves are not exercisable headlessly.

## Friendly device names (multi-key selection)

Active workstream (branch `fido2-friendly-names`). Motivation: with more than
one FIDO key connected (e.g. a signing YubiKey + a test YubiKey), `/dev/hidrawN`
paths are reassigned on every replug and same-model keys share VID:PID *and*
AAGUID — so there's no safe, durable way to target a specific physical key, and
a destructive op against the wrong one is irreversible.

### Privacy & disclosure (opt-in)

Recording information about a user's keys — notably **persisting serials** to
`keys.json` — is **opt-in**: nothing is written unless the user explicitly runs
`key-name add`. Reading a serial in memory to resolve a *connected* device is
fine (ephemeral); persisting it is the gated step. Any option that can lower
security is disclosed in **plain, concise English** (enough to decide, no walls
of text), surfaced via a reusable **helper-bubble** component (GUI tooltip; CLI:
tight `--help` plus a one-line note at the opt-in moment). The helper-bubble is
a cross-cutting UI item, not specific to this feature.

### Identity source (verified 2026-05-27 on real hardware)

No single mechanism identifies every key — layered resolver:
1. **USB `iSerialNumber`** via sysfs `ATTRS{serial}`: present on Solo 2 (a 32-hex
   string, also embedded in its PC/SC reader name) and many others. Free,
   no device interaction.
2. **Vendor serial over CCID**: YubiKeys expose **no** USB serial but carry a
   unique 8-digit decimal mgmt serial, read via the management/OTP applet over
   PC/SC (the YubiKey's CCID interface is a visible reader; moltoctl already
   speaks PC/SC — dependency-free, no `ykman`). Required for the two-YubiKeys
   case, which (1) cannot solve.
3. **AAGUID** from `authenticatorGetInfo`: model-level display only, not
   per-device identity.

### Config — `~/.config/moltoui/keys.toml`

Array-of-tables, matched on `serial`; `name` is the unique label
(charset `[a-z0-9_-]`):

    [[key]]
    name   = "signing-yubikey"
    serial = "00000000"   # illustrative; real values not recorded here
    source = "ccid"      # "usb" | "ccid"
    vendor = "yubico"
    aaguid = "…"          # optional
    note   = "…"          # optional

Tool-managed via `moltoctl key-name add <name> --path <dev>` /
`key-name list` / `key-name remove <name>`; hand-editing stays possible.

### Selection UX — hybrid (flags + interactive picker)

- `--name <label>` resolves label → serial → live `/dev/hidrawN`. `--path`
  remains the low-level escape hatch; the two are mutually exclusive and always
  win when given (scriptable / non-interactive).
- No flag + a terminal + >1 key → numbered picker read from **`/dev/tty`** (not
  stdin, which `--pin-stdin` already consumes). Hand-rolled, no prompt crate.
- No flag + not a TTY + >1 key → error requiring `--name`/`--path`.
- Exactly one key → use it, printing the resolved target.
- `moltoctl list` shows the friendly name for any connected, configured key.

### Safety

- Always echo the resolved target before acting (`→ test-solo (Solo 2,
  /dev/hidraw5)`).
- >1 key connected → destructive ops must resolve to an explicit target (flag or
  picker), never a default. `fido-reset` additionally requires a typed
  confirmation (retype the name); `fido-creds-delete` is gated by explicit
  targeting alone.

### Architecture

Device identity + resolution lives in a **shared library**, so the CLI (flags +
picker) and the later `moltoui` GUI (dropdown) are thin front-ends over one
resolver.

### Build order

1. **Done.** USB-serial resolver + `keys.json` load + `key-name add/list/remove`
   + `--name`/picker plumbing + `list` name column + the safety guard.
2. **Done.** YubiKey CCID mgmt-serial read (unlocks the two-YubiKey case).
   `molto2-transport::yubikey_ccid_serials()` reads each YubiKey CCID reader's
   management serial via the OTP applet (AID `A0 00 00 05 27 20 01 01`, API
   request slot `0x10`) — read-only, no PIN/touch, no new deps. moltoctl matches
   a YubiKey's `/dev/hidrawN` to its reader by USB topology (sysfs
   `busnum`/`devnum` vs the reader's PC/SC `CHANNEL_ID`), so two connected
   YubiKeys are never confused; it falls back to the unambiguous single-reader
   case and otherwise refuses to guess. Verified on hardware with two YubiKeys
   on the same USB bus (distinct device addresses, distinct CCID serials) + a
   Solo 2.
3. **Done.** Shared-resolver extraction + GUI front-end. The CCID/topology/serial
   logic moved out of `moltoctl` into a new `molto2-resolve` crate (depends on
   keyring + hid + transport; pure `molto2-keyring` stays hardware-free), so both
   front-ends are thin over one resolver. `moltoui`'s Security Keys pane now shows
   friendly names + effective serials in the device list/header and can name /
   un-name a key (opt-in persist), with the disclosure surfaced via a reusable
   `helper_bubble` component — the planned cross-cutting helper-bubble. GUI
   verified by build/clippy only (headless); still needs a visual pass.

## Dependency posture

`CLAUDE.md` mandates "vendor over depend." Restated here so context
compression doesn't lose it:

- HID enumeration: raw `/dev/hidraw*` ioctls. Whether we lean on the
  `nix` crate for ioctl plumbing or hand-write it is a Phase 0 decision.
- CTAP HID framing and CBOR: vendored in-tree.
- **No new heavyweight FIDO crates** (`authenticator`, `ctap-hid-fido2`,
  `fido-device-onboard`, etc.) without explicit discussion first.

## Non-goals (for now)

- Cross-platform support (macOS/Windows) before the Linux story works.
- Renaming the project off the `molto2-*` prefix.
- A web UI or background daemon.

## Deferred follow-ups (not blocking, revisit with hardware)

- **PIN protocol v2 wiring — DONE (2026-05-29).** `client_pin.rs` now negotiates
  from `getInfo.pinUvAuthProtocols`, preferring the device's first-listed
  protocol we support (`select_pin_protocol`, defaulting to v1 when the list is
  absent/unknown). Key agreement + every protocol-bearing request route through
  the chosen `Box<dyn PinProtocol>`, and the issued `PinUvAuthToken` records the
  version so `cred_mgmt` follows suit. No caller-facing API changed. Hardware
  premise confirmed: the test YubiKey advertises `[2, 1]` (→ v2 selected) and
  this Solo 2's firmware advertises `[1]` (→ v1); full end-to-end v2 still wants
  a PIN-authenticated op (PIN entry is the user's job).
- **GUI worker thread.** All CTAP calls block egui synchronously; listing
  many credentials or running Reset (30s touch window) freezes the window.
  Offload to a thread + channel.
- **Reset in the GUI.** Currently CLI-only because of the touch-window
  blocking issue above.
- **CredentialManager double token fetch.** Unlock fetches the pinUvAuthToken
  twice because the manager consumes it; split the listing helpers off the
  manager or make the token `Clone`.
- **Bootloader-mode detection.** A Solo 2 in DFU enumerates as `1209:b000`
  and won't speak FIDO; detect and message clearly rather than hang on INIT.

## Hardware compatibility notes

- **Solo 2 / Solo 2A+** (Trussed firmware, Nitrokey-maintained): spec-faithful.
  Standard `credMgmt` (0x0A), 64-byte CTAPHID, reset = re-plug then touch
  within 30s (our `RESET_TIMEOUT` already handles this). USB IDs: app
  `1209:beee`, bootloader `1209:b000`. Firmware management uses a separate
  HID app + NXP ROM protocol, not CTAP2 vendor commands — out of our scope.
- **Nitrokey 3** shares the Solo 2 firmware stack; USB ID `20a0:42b2`.

### Protocol reference repos (for Phase 3+ work)

- `Nitrokey/nitrokey-3-firmware` — `components/apps/{Cargo.toml,src/lib.rs}`:
  authoritative applet list and the APDU-vs-CTAPHID dispatch mapping.
- `Nitrokey/trussed-secrets-app` — OATH/secrets protocol: AID, INS codes
  (`src/oath.rs`, `src/command.rs`), CTAPHID `0x70` vendor command, and the
  Yubico-compatibility notes (README) about the removed auth handshake.
- `Nitrokey/pynitrokey` — reference host client (`nitropy`); shows the
  CTAPHID secrets transport in practice.
- `Nitrokey/opcard-rs` — OpenPGP Card v3.4 APDU reference (Phase 4).
- `Nitrokey/piv-authenticator` — PIV / SP 800-73-4 APDU reference (archived;
  spec-mapping value only).

## Working agreements

- Work happens on short-lived feature branches off `main` (current:
  `fido2-friendly-names`), fast-forwarded into `main` at defined milestones.
  The original `security-key-integration` branch has merged into `main` and
  been deleted.
- `main` is protected: signed commits, linear history, no force/delete. Land
  work with a fast-forward (`git checkout main && git merge --ff-only <branch>
  && git push`), which preserves commit signatures — *not* GitHub "Rebase and
  merge", which rewrites commits and strips their signatures.
- Don't push or open/merge PRs without explicit user permission (per CLAUDE.md).
- This document is the durable anchor. When a session loses context, the
  next session should read `PLAN.md` first.
