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
  **Byte layer DONE (2026-05-29):** `crates/molto2-openpgp` has the APDU builders
  (`select`, `get_data`, `get_application_related_data`, `get_pw_status`,
  `verify`, `get_response`), a BER-TLV parser (2-byte high tags + long-form
  lengths, with constructed-only nested `find`), and typed parsers for PW status,
  Application Related Data (`6E`), and the signature counter — all under
  RFC/spec known-answer tests. **Verified on a real YubiKey 5.7** (SELECT +
  GET DATA 006E over PC/SC with the `61xx`/GET RESPONSE loop): this surfaced a
  hardware-only bug the synthetic tests missed — the card reports an **80-byte**
  C5 fingerprints object (a 4th key slot) vs the spec's 60, which the parser
  rejected; fixed to require ≥60 and locked in with a regression test built from
  the captured 315-byte ARD. The Solo 2 firmware build has **no** OpenPGP applet
  (`SW 6A82`).
  **Transport + CLI DONE (2026-05-30):** `molto2_transport::OpenPgpSession` drives
  the applet over PC/SC — SELECT (mapping `6A82` to `NoOpenPgpApplet`), the
  `61xx`/`GET RESPONSE` reassembly loop, reader discovery, and a read-only
  `status()` assembling the Application Related Data + signature counter.
  `moltoctl openpgp status` prints AID/serial, key algorithms + fingerprints, PIN
  retry counters, and the signature count. Verified on a real YubiKey 5.7 (its
  OpenPGP serial equals the CCID/mgmt serial used for friendly names); the Solo 2
  is correctly skipped.
  **GUI pane DONE (2026-05-30):** an "OpenPGP" tab in `moltoui` with a reader list
  (same no-guess posture) and a read-only status view (AID/serial, per-key
  algorithm + fingerprint, PIN retry counters, signature count) driven through the
  worker thread. Verified it renders headlessly against a live YubiKey.
  **Writes (CLI) DONE (2026-05-30):** the byte layer gained the operation builders
  (`generate_key`/`read_public_key` CRT, `pso_compute_signature`/`pso_decipher`,
  `change_reference_data`) + an RSA public-key parser, all under byte-exact KAT
  tests. `OpenPgpSession` adds `verify_pin` (decodes both the spec `63Cx` form and
  the YubiKey `6982` form — for the latter it reads PW status to report real
  remaining tries), `read_public_key`, `generate_key`, and `sign`. `moltoctl
  openpgp` gains `verify`, `public-key`, and `generate-key` (PINs via env/stdin
  only, never argv; generate gated by `--yes` + admin PIN). Hardware-verified on a
  YubiKey: status, public-key on an empty slot (`6581`), and PIN verify incl.
  wrong-PIN retry counting and counter recovery.
  **Reset + full write round-trip DONE (2026-05-30):** added `openpgp reset`
  (`OpenPgpSession::factory_reset`) which — like `ykman` — *blocks* PW1 and PW3 by
  exhausting their retry counters with wrong guesses, then issues TERMINATE DF +
  ACTIVATE FILE, so it works unconditionally (incl. forgotten-PIN recovery) and
  never needs the real PIN. (First cut tried a bare TERMINATE and the YubiKey
  refused with `6982` — TERMINATE needs PW3 rights *or* both PINs blocked; the
  block-first approach is the fix.) Verified the whole write path end-to-end on
  the test YubiKey, leaving the card pristine: reset → verify default admin PW3 →
  `generate-key` (RSA-2048, e=65537) → `public-key` read-back (modulus + exponent
  from the `7F49` long-form TLV) → `reset` → both slots empty (`6581`), PINs back
  to 3/0/3.
  **PUT DATA + gpg interop DONE (2026-05-30):** the byte layer gained `put_data`
  and the cardholder-name/URL/fingerprint/generation-time builders, plus the
  OpenPGP v4 key-fingerprint computation (`rsa_v4_fingerprint`, RFC 4880 §12.2 —
  SHA-1 over `0x99||len||0x04||time||0x01||MPI(n)||MPI(e)`, locked to an
  independent KAT). `OpenPgpSession` adds `set_cardholder_name`, `set_url`, and
  `register_key` (reads the slot's pubkey, writes its computed fingerprint +
  creation timestamp). `moltoctl openpgp generate-key` now auto-registers the key,
  and `set-name`/`set-url` were added. The fingerprint computation is locked to an
  independent Python KAT. **Verified end-to-end with GnuPG (2026-05-30):** on the
  test YubiKey, `generate-key --slot sign` (auto-registers) wrote fingerprint
  `01ADBF41…C6D52D28`, and `gpg --card-status` *independently* reported the
  byte-identical Signature key fingerprint + matching serial (37806840) and
  creation timestamp — a third-party tool recognizes the generated key. Card reset
  to pristine afterwards. Two gotchas, both resolved: (1) needs `scdaemon`
  installed; (2) gpg's scdaemon must be told to share the reader via pcscd — a
  `scdaemon.conf` with `pcsc-shared` + `disable-ccid` (without it, scdaemon can't
  open the reader: "No such device").
  **Write GUI DONE (2026-05-30):** the `moltoui` OpenPGP pane gained a "Manage
  (write operations)" section — admin-PIN (PW3) entry, set cardholder name / URL,
  generate RSA key (slot picker, behind a confirm modal since it overwrites), and
  reset applet (typed-`reset` confirm modal). All write ops run on the worker
  thread (so the touch window doesn't freeze the UI) and refresh status on
  success. To avoid duplicating `molto2-openpgp` in moltoui's dependency graph,
  transport re-exports `KeyCrt` and adds `verify_admin_pin`, so moltoui depends
  only on `molto2-transport` (not `molto2-openpgp` directly). The write data paths
  are the same ones hardware-verified via the CLI; the pane renders without
  panicking against a live YubiKey (headless), though button clicks aren't
  exercisable headlessly.
  **Signing DONE (2026-05-30):** `moltoctl openpgp sign --in FILE` hashes the
  input (SHA-1, the in-tree hash), wraps it in a PKCS#1 v1.5 DigestInfo, verifies
  PW1 (signing ref 0x81), and has the card produce an RSA signature via PSO:CDS
  (`OpenPgpSession::sign`); output is hex or `--out FILE` raw. **Verified
  end-to-end on the test YubiKey**: generate sign key → sign a message →
  independently checked with `pow(sig, e, n)` that the recovered EMSA-PKCS1-v1_5
  block is `00 01 FF.. 00 || DigestInfo` and the embedded SHA-1 equals the message
  digest (`18d11190…`). Card reset to pristine after. SHA-1 is used because it's
  the only in-tree hash; the card signs whatever DigestInfo it's handed, so the
  private-key op is proven regardless (SHA-256 signing would need a vendored
  SHA-256).
  **Key import — root cause found & fixed in code; hardware re-test pending (2026-05-31).**
  The earlier `SW=6A80` was **not** a CRT-vs-standard issue (an earlier
  hypothesis). The real bug was the `7F48` Cardholder Private Key Template
  *length-entry encoding*: we emitted each entry as a TLV whose **value** was the
  length (`91 01 03`, `92 01 80`), but the template wants the field's byte length
  to be the tag's **BER length itself, with no value** (`91 03`, `92 81 80`).
  Confirmed against two independent references: GnuPG `scd/app-openpgp.c`
  `build_privkey_template` (uses `add_tlv(tp, tag, len)`) and Yubico `ykman`
  `yubikit/openpgp.py` (`Tlv(0x7F48, join(tlv[:-tlv.length]))`). The card's own
  `C1` attribute (`01 08 00 00 11 00`) decodes to RSA-2048, **e_bits = 17**,
  **import format = 0x00 (standard)** — and ykman imports RSA to YubiKey 5 in
  *standard* form (`use_crt` only for the ancient NEO), so standard is correct
  here; the fix is purely the length encoding. Implemented:
  `molto2-openpgp::key_template_entry` now emits `tag || ber_len(field_len)`;
  `RsaPrivateKeyParts` carries the full CRT set `{e,p,q,u,dp,dq,n}`;
  `RsaImportFormat` + `parse_rsa_algorithm_attributes` read the card's declared
  format & e_bits; `extended_header_list`/`import_rsa_key` take `(format, e_bits)`
  and right-justify `e` to `(e_bits+7)/8`; `OpenPgpSession::import_key` reads the
  slot's algorithm attributes (read-only GET DATA) and builds the matching
  template; `moltoctl generate_rsa_2048` computes `u=q⁻¹ mod p`, `dp`, `dq` from
  the `rsa` crate. Byte-exact KATs rewritten for the corrected encoding (standard
  *and* CRT forms); all 199+ workspace tests + clippy green. Extended-length
  transport retained (the card accepted the extended framing before — `6A80` was
  a pure data error). **Verified end-to-end on the test YubiKey (2026-05-31):**
  `import-key --generate --slot sign` now sends `00 DB 3F FF 00 01 19 4D 82 01 15
  B6 00 7F 48 08 91 03 92 81 80 93 81 80 5F 48 82 01 03 …` and the card accepts
  it with `9000` (was `6A80`); the read-back public key, an independent Python
  OpenPGP-v4 fingerprint over (n, e, creation_time), and the card-stored `C7`
  fingerprint all agree (`1FDB1D89…94F3B6AF`); a PSO:CDS signature over a test
  file verifies with `pow(sig,e,n)` recovering a well-formed EMSA-PKCS1-v1_5/SHA-1
  block whose digest equals `SHA1(message)`; and `gpg --card-status` independently
  reports the byte-identical Signature key fingerprint + serial 37806840. Card
  reset to pristine afterward (all slots empty, PINs 3/0/3). Still TODO:
  file-based import; SHA-256 sign; a command-chaining fallback if a future card
  refuses extended-length APDUs.
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
- **GUI worker thread — DONE (2026-05-29).** All blocking device I/O in `moltoui`
  (CTAP GetInfo/unlock/cred-list/delete/change-PIN and the OATH open/list/code/
  add/delete) now runs on a single background `Worker` thread. A job closure runs
  off-thread and returns an `ApplyFn` (a `Box<dyn FnOnce(&mut App)>`) applied on
  the UI thread in `update()` via `drain_worker`; the worker calls
  `ctx.request_repaint()` to wake the frame loop. A busy spinner + label shows in
  the tab bar, and `spawn_job` drops a new job while one is in flight so device
  access stays serialized (no overlapping card I/O from rapid clicks). Unit tests
  cover the worker round-trip, the busy-guard, and the no-worker inline path; the
  pane was also run headlessly against a live YubiKey without freezing.
- **Reset in the GUI — DONE (2026-05-30).** A red "Reset key…" button in the
  Security Keys pane opens a confirmation modal requiring the user to type
  `reset`; the wipe then runs on the worker thread (so the ~30s touch window no
  longer freezes the UI) and clears the cached session + re-reads CTAP info. The
  underlying `molto2_ctap::reset()` path was confirmed end-to-end on a real
  YubiKey ("All credentials wiped, PIN cleared").
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
