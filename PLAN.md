# keyroost: extension plan toward a general security-key manager

## Goal

Extend keyroost from its current single-purpose role (programming Token2
Molto2 TOTP tokens over PC/SC) into a general-purpose security-key
manager. The long-term feature target is rough parity with Yubico's
`ykman` GUI: FIDO2/U2F first, then OATH, PIV, OpenPGP, and OTP.

The shorthand for this scope is **C-lite**: start with FIDO2/U2F support
and grow from there.

## Current state (as of this branch)

- `keyroost-proto` — pure-Rust Molto2 wire protocol (SM4, SHA-1, APDU, MAC).
- `keyroost-transport` — PC/SC reader discovery and Molto2 session.
- `keyroost-import` — Aegis / 2FAS / otpauth-list bulk import.
- `keyroostctl` — CLI binary.
- `keyroost` — egui desktop GUI.

See `docs/PROTOCOL.md` and `CLAUDE.md` for the existing protocol layer.

## Naming policy

The project is named **`keyroost`**: crates are `keyroost-*`, the CLI is
`keyroostctl`, the GUI is `keyroost`. The rename from the original `molto2-*` /
`moltoctl` / `moltoui` names landed once Phases 0–4 (FIDO2, OATH, OpenPGP) plus
friendly-name selection were done and the tool was no longer Molto2-only — see
**Phase 5 — Rename to keyroost** below. The physical device keeps its real name
(`Molto2` / `Molto2v2`).

## Next up (prioritized backlog)

The planned applet roadmap (FIDO2, OATH, OpenPGP) is complete and the project was
renamed to keyroost. With OATH password-auth done and a hardware-verified PIV
read foundation landed, the agreed next items, in priority order:

1. **Release readiness (CI + first tag).** Highest leverage now that it's public
   FOSS. Add a GitHub Actions workflow running the test suite + clippy on every
   push/PR and building release binaries; close the small verification gaps
   (live click-test the GUI panes; force the OpenPGP decrypt command-chaining
   path on hardware); add a CHANGELOG; document the udev-rules install in the
   README; then tag `v0.1.0`.
2. **Cross-platform.** macOS/Windows — **in progress.** The hidapi HID backend
   has landed behind `cfg(not(target_os = "linux"))` and the PC/SC wording is
   platform-neutral; what remains is CI/release coverage and hardware sign-off.
   See the **Cross-platform roadmap** section below for the agreed plan.
3. **UI/UX design pass.** The GUI grew pane-by-pane (Molto2 profiles, Security
   Keys, OATH, OpenPGP) without a holistic design pass. Revisit information
   architecture, consistency across panes, empty/error states, and the
   multi-key selection flow; add a PIV pane once PIV writes exist.

Further out: finish the **PIV write/auth** surface (see the PIV entry under
Phase 3+), and the YubiKey-OATH/other deferred compatibility notes below.

## Cross-platform roadmap (Linux / macOS / Windows)

Decisions agreed for extending keyroost beyond Linux:

- **One `main`, not per-OS branches.** A single source tree with `cfg`-gated
  backends (`HidIo`, `enumerate_*`). Three long-lived platform branches would
  force every fix to be cherry-picked 3× and would drift; the shared 90%
  (protocol, CBOR, OATH/OpenPGP/PIV, GUI) is identical, and only the thin
  HID/PC-SC backend differs. The **CI matrix is the cross-platform guarantee** —
  the same commit compiled and tested on all three OSes — not branch isolation.
- **HID backend: hybrid (hidapi now, native later).** macOS (IOKit) and Windows
  (hid.dll) use the `hidapi` crate, auto-selected off Linux. This is the one
  accepted C dependency for this scope (cf. `keyroost-rsakey`'s scoped
  exception); a hand-vendored IOKit/SetupAPI backend behind the same seam stays
  a future option, taken only if hidapi becomes a liability. **The Linux release
  never links hidapi** — it keeps the dependency-free sysfs/hidraw backend. The
  `hidapi-backend` feature is a Linux-only test hook (needs `libudev-dev`) and
  must never be enabled in a Linux release build.
- **Support tiers.** Linux is **tier-1** (fully supported, hardware-verified).
  macOS/Windows are **tier-2** (best-effort, community-tested); until the
  hardware sign-off below, they are *experimental/unverified* in user docs.

Phases:

- **A — Honesty pass (done).** Corrected the misleading `hidapi-backend`
  smoke-test comments (libudev prereq, never-in-release), and the macOS PC/SC
  error wording (macOS has no user-run pcscd).
- **B — CI matrix (done).** `ci.yml` builds + clippy + tests on
  `ubuntu-latest`, `macos-latest`, and `windows-latest` (`fail-fast: false`).
  This compiles the real hidapi backend on macOS/Windows — coverage the
  `hidapi-backend` feature only faked — so the non-Linux path can't rot uncaught.
- **C — Release matrix.** Extend `release.yml` to produce macOS (arm64 +
  x86_64) and Windows x86_64 artifacts (`.zip` on Windows). GUI niceties:
  `#![windows_subsystem = "windows"]` so the Windows GUI spawns no console.
- **D — Functional parity gaps.** Document the macOS/Windows degradation in the
  HID↔CCID topology correlation (`keyroost-resolve::ccid_serial_for`): hidapi
  exposes no USB bus/address, so two serial-less YubiKeys can't be
  disambiguated and naming falls back to the single-reader case.
- **E — Hardware sign-off (gates the tier-2 claim).** One real run each on a Mac
  and a Windows box with a YubiKey: enumerate → `getInfo` → an OATH/OpenPGP op
  over PC/SC. Until this passes, user docs say "experimental," not "tier-2."
- **F — Native HID backend (deferred, not scheduled).** Spike hand-written
  IOKit + SetupAPI backends behind the existing `HidIo`/`enumerate_*` seam only
  if hidapi proves a liability; would need an `unsafe_code` scoped exception.

## Phases

Sequenced smallest-to-largest. Each phase ends in a working binary; no
half-finished features carried across phase boundaries.

### Phase 0 — Device discovery
USB HID enumeration of FIDO devices via `/dev/hidraw*`. udev rules so an
unprivileged user can talk to FIDO keys. `keyroostctl list` learns to show
both PC/SC readers and HID FIDO devices side-by-side.

Linux only at this stage; macOS/Windows are separate later phases.

### Phase 1 — FIDO2/U2F core transport
CTAP HID transport layer (frame assembly, channel `INIT`, channel
allocation), plus a minimal CBOR encoder/decoder. Implement
`authenticatorGetInfo` and `authenticatorReset`. Wire a "Security Keys"
pane into `keyroost` that lists connected keys and shows their CTAP info.

### Phase 2 — FIDO2 credential management
List / add / delete resident credentials (`credentialManagement`
subcommands). PIN set / change / verify.

### Phase 3+ — Reach toward ykman parity

Revised ordering after surveying the Nitrokey 3 / Trussed firmware (the
same stack the user's Solo 2A+ runs). Key insight: OATH, OpenPGP, and PIV
are all **CCID/APDU smartcard applets** on these devices, so our existing
`keyroost-transport` PC/SC layer is reusable — each applet just needs generic
APDU framing plus an `AID SELECT`. We do not need a second transport stack
for the smartcard applets.

- **Phase 3 — OATH (TOTP/HOTP).** Best next target: reuses our Molto2
  TOTP/HOTP + base32 code *and* the PC/SC layer. The Nitrokey/Trussed OATH
  applet uses Yubico's AID (`A0 00 00 05 27 21 01`) and the same core INS
  codes (`Put`/`Delete`/`List`/`Calculate`/`SendRemaining`), so one command
  set targets NK3 *and* future YubiKey OATH. Caveat: the Trussed impl
  removed Yubico's `SetCode`/`Validate` authorization handshake, so
  provisioning/list/delete interoperate but OATH password-auth diverges. (Both
  paths are now done: provisioning/list/calculate work on Trussed and YubiKey,
  and the Yubico `SET_CODE`/`VALIDATE` password handshake is implemented and
  hardware-verified — see "OATH password auth — DONE" below.)
- **Phase 4 — OpenPGP.** Mature (`opcard`, OpenPGP Card spec v3.4) but
  heavier: full OpenPGP Card APDU set + RSA/curve key management.
  **Byte layer DONE (2026-05-29):** `crates/keyroost-openpgp` has the APDU builders
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
  **Transport + CLI DONE (2026-05-30):** `keyroost_transport::OpenPgpSession` drives
  the applet over PC/SC — SELECT (mapping `6A82` to `NoOpenPgpApplet`), the
  `61xx`/`GET RESPONSE` reassembly loop, reader discovery, and a read-only
  `status()` assembling the Application Related Data + signature counter.
  `keyroostctl openpgp status` prints AID/serial, key algorithms + fingerprints, PIN
  retry counters, and the signature count. Verified on a real YubiKey 5.7 (its
  OpenPGP serial equals the CCID/mgmt serial used for friendly names); the Solo 2
  is correctly skipped.
  **GUI pane DONE (2026-05-30):** an "OpenPGP" tab in `keyroost` with a reader list
  (same no-guess posture) and a read-only status view (AID/serial, per-key
  algorithm + fingerprint, PIN retry counters, signature count) driven through the
  worker thread. Verified it renders headlessly against a live YubiKey.
  **Writes (CLI) DONE (2026-05-30):** the byte layer gained the operation builders
  (`generate_key`/`read_public_key` CRT, `pso_compute_signature`/`pso_decipher`,
  `change_reference_data`) + an RSA public-key parser, all under byte-exact KAT
  tests. `OpenPgpSession` adds `verify_pin` (decodes both the spec `63Cx` form and
  the YubiKey `6982` form — for the latter it reads PW status to report real
  remaining tries), `read_public_key`, `generate_key`, and `sign`. `keyroostctl
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
  creation timestamp). `keyroostctl openpgp generate-key` now auto-registers the key,
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
  **Write GUI DONE (2026-05-30):** the `keyroost` OpenPGP pane gained a "Manage
  (write operations)" section — admin-PIN (PW3) entry, set cardholder name / URL,
  generate RSA key (slot picker, behind a confirm modal since it overwrites), and
  reset applet (typed-`reset` confirm modal). All write ops run on the worker
  thread (so the touch window doesn't freeze the UI) and refresh status on
  success. To avoid duplicating `keyroost-openpgp` in keyroost's dependency graph,
  transport re-exports `KeyCrt` and adds `verify_admin_pin`, so keyroost depends
  only on `keyroost-transport` (not `keyroost-openpgp` directly). The write data paths
  are the same ones hardware-verified via the CLI; the pane renders without
  panicking against a live YubiKey (headless), though button clicks aren't
  exercisable headlessly.
  **Signing DONE (2026-05-30):** `keyroostctl openpgp sign --in FILE` hashes the
  input (SHA-1, the in-tree hash), wraps it in a PKCS#1 v1.5 DigestInfo, verifies
  PW1 (signing ref 0x81), and has the card produce an RSA signature via PSO:CDS
  (`OpenPgpSession::sign`); output is hex or `--out FILE` raw. **Verified
  end-to-end on the test YubiKey**: generate sign key → sign a message →
  independently checked with `pow(sig, e, n)` that the recovered EMSA-PKCS1-v1_5
  block is `00 01 FF.. 00 || DigestInfo` and the embedded SHA-1 equals the message
  digest (`18d11190…`). Card reset to pristine after.
  **SHA-256 signing DONE + hardware-verified (2026-05-31):** vendored a pure-Rust
  `keyroost_proto::sha256` (FIPS 180-4, NIST KATs incl. the 1e6-`a` vector), and
  `openpgp sign` gained `--hash sha1|sha256` (default **sha256**) building the
  matching PKCS#1 DigestInfo. Verified on the YubiKey: a `--hash sha256` signature
  recovers (via `pow(sig,e,n)`) a well-formed SHA-256 DigestInfo whose digest
  equals `sha256(message)`. SHA-1 stays available for old-verifier interop.
  **Key import — DONE + hardware-verified (2026-05-31).**
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
  `keyroost-openpgp::key_template_entry` now emits `tag || ber_len(field_len)`;
  `RsaPrivateKeyParts` carries the full CRT set `{e,p,q,u,dp,dq,n}`;
  `RsaImportFormat` + `parse_rsa_algorithm_attributes` read the card's declared
  format & e_bits; `extended_header_list`/`import_rsa_key` take `(format, e_bits)`
  and right-justify `e` to `(e_bits+7)/8`; `OpenPgpSession::import_key` reads the
  slot's algorithm attributes (read-only GET DATA) and builds the matching
  template; `keyroostctl generate_rsa_2048` computes `u=q⁻¹ mod p`, `dp`, `dq` from
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
  reset to pristine afterward (all slots empty, PINs 3/0/3).
  **Command-chaining fallback DONE + hardware-verified (2026-05-31):**
  `keyroost-openpgp` gained `put_data_odd_chained` / `import_rsa_key_chained` (ISO
  command chaining: CLA `10` links + a final CLA `00`, 254-byte chunks matching
  GnuPG); `OpenPgpSession::import_key` tries extended length first and falls back
  to chaining on `6700`/`6883` (a `KEYROOST_OPENPGP_FORCE_CHAINING` env hook forces
  the path for testing). KAT-locked (chunks reassemble byte-identically to the
  extended-length data field). Verified on the YubiKey by forcing the chaining
  path: two links `10 DB 3F FF FE …` + `00 DB 3F FF 1B …` both `9000`, key
  imported and registered.
  **File-based import DONE + hardware-verified (2026-05-31):** `import-key` gained
  `--in <FILE>` (mutually exclusive with `--generate`) which loads an RSA-2048
  key via the `rsa` crate's decoders — PKCS#1 or PKCS#8, PEM or DER,
  auto-detected — and runs it through the same import path; non-2048 keys and
  unparseable files are rejected with clear errors. Verified on the YubiKey: a
  PKCS#8 PEM key imported, and the card's read-back modulus was byte-identical to
  the source file's modulus (all four format variants confirmed to parse
  offline). With this, the OpenPGP write story (status / generate / import {gen,
  file} / sign {sha1,sha256} / reset / set-name,url / register) is complete.
  **PSO:DECIPHER wired — code-complete, hardware verification pending (2026-06-01):**
  `keyroost-openpgp::pso_decipher` now auto-selects short vs. *extended*-length
  framing (an RSA-2048 cipher DO is 257 bytes — `0x00` padding indicator + 256
  cryptogram — over the short-APDU limit) and a new `pso_decipher_chained`
  provides the ISO command-chaining fallback (CLA `10` links + final CLA `00`
  with a case-4 `Le`, 254-byte chunks). `OpenPgpSession::decrypt` prepends the
  padding-indicator byte, tries extended length, and falls back to chaining on
  `6700`/`6883` (same `KEYROOST_OPENPGP_FORCE_CHAINING` hook as import);
  `transmit_chain` now returns the final link's response payload. CLI: `keyroostctl
  openpgp decrypt --in <FILE>` verifies PW1 in the decipher context (ref 0x82),
  runs PSO:DECIPHER, and writes plaintext (`--out`) or hex. KAT-locked (extended
  framing + chaining reassembly); builds green; the command parses and reaches
  reader resolution offline. **Extended-length path hardware-verified
  (2026-06-01):** on the test YubiKey (37806840), a decryption-slot key was
  generated, a host-side PKCS#1 v1.5 cryptogram built under its public modulus,
  and `openpgp decrypt` returned the byte-identical plaintext
  (`6d6f…7374` = "molto2 decipher test"); card reset to pristine afterward
  (slots empty, PINs 3/0/3). **Command-chaining decrypt also hardware-verified
  (2026-06-02):** forcing `KEYROOST_OPENPGP_FORCE_CHAINING=1`, a 257-byte cipher
  DO went out as two chained links (`10 2A 80 86 FE …` + `00 2A 80 86 03 …`) and
  the card returned the byte-identical plaintext — so both the extended-length
  and chaining decrypt paths are confirmed on hardware.
  **GUI import parity — code-complete, hardware verification pending (2026-06-01):**
  the `keyroost` OpenPGP pane gained "Generate & import" and "From file" controls
  (slot selector + path field), a confirmation modal, and `import_openpgp_key`
  which obtains the key on the worker thread then imports + registers. The
  host-side RSA key material (keygen + PKCS#1/PKCS#8 PEM/DER loading) moved out of
  `keyroostctl` into a new shared **`keyroost-rsakey`** crate (`generate_2048`,
  `load_from_file`, `RsaKeyParts`), which now owns the workspace's scoped `rsa`
  dependency so both front-ends share one key path; `keyroostctl` was refactored onto
  it. Unit-tested (keygen shapes, DER round-trip, size/garbage rejection); both
  binaries build; the refactored CLI import path was re-confirmed to parse all
  four key formats offline. The GUI calls the same `OpenPgpSession::import_key` +
  `keyroost-rsakey` path the CLI import already hardware-verified, so only the GUI
  UI wiring itself is **not yet click-tested on hardware**.
- **PIV (SP 800-73-4) — read foundation DONE + hardware-verified (2026-06-02).**
  New `keyroost-piv` byte-layer crate (pure-Rust, I/O-free, like the OATH/OpenPGP
  layers): SELECT (5-byte AID prefix), GET DATA for the certificate / CHUID data
  objects, VERIFY (PIN + empty-body retry query), the Yubico GET VERSION / GET
  SERIAL extensions, the `Slot` model (9A/9C/9D/9E + their `5F C1 0x` cert tags),
  and BER-TLV helpers — under 10 byte-exact KATs. `keyroost_transport::PivSession`
  adds the card transmit + `61xx`/GET RESPONSE loop, reader discovery
  (`list_piv_readers`, `NoPivApplet` on `6A82`), and a read-only `status()`
  (version, serial, PIN retries, per-slot cert presence). `keyroostctl piv status`
  prints it.
  **PIV write/auth — DONE + hardware-verified (2026-06-12).** The byte layer
  gained GENERAL AUTHENTICATE (management-key witness/mutual-auth and key-slot
  signing), GENERATE ASYMMETRIC KEY PAIR, PUT DATA (cert import), CHANGE
  REFERENCE DATA / RESET RETRY COUNTER (PIN/PUK), and the Yubico SET MANAGEMENT
  KEY / SET PIN RETRIES / GET METADATA / RESET extensions, plus a pure SPKI→PEM
  builder for generated public keys (RSA + the NIST/Edwards curves). The
  management-key block-cipher math (AES-128/192/256 + 3DES ECB witness/challenge)
  lives in `keyroost_transport::PivSession` behind a scoped `aes`/`des`/`getrandom`
  dependency exception; the byte layer stays pure. `keyroostctl piv` exposes
  change-pin/puk, unblock-pin, set-retries, change-management-key, generate-key,
  import-cert, export-cert, and reset; the GUI PIV pane mirrors all of it. The
  whole lifecycle was exercised on the test YubiKey (5.7.4, AES-192 default
  management key): mutual auth incl. wrong-key rejection, EC/RSA key generation
  (openssl-validated PEM), cert import/export round-trip (extended-length APDUs),
  PIN/PUK change + block/unblock with correct try counts, retry-count setting,
  AES-256 management-key rotation, and reset (which the card gates on PIN+PUK
  both blocked). Out of scope still: host-side self-signed-cert / CSR assembly
  (the slot-signing primitive exists; the X.509 TBS construction does not), and
  X.509 parsing beyond presence/length.
- **Yubico OTP — dropped for Trussed devices.** NK3/Solo 2 don't implement
  the 132-char keyboard OTP applet; HMAC challenge-response is folded into
  the OATH/secrets app. Revisit only if we target actual YubiKeys.
- **Phase 5 — Rename to `keyroost` — DONE (2026-06-01).** The tool outgrew its
  Molto2-only origin (it now manages FIDO2, OATH, and OpenPGP across YubiKey /
  Solo 2 / Nitrokey 3), so the project took the neutral name **`keyroost`**. A
  rename-only, mechanical sweep on its own branch:
  - **Crates:** all ten lib crates moved to the `keyroost-*` prefix —
    *uniformly*, including the device-specific `keyroost-proto` /
    `keyroost-transport` (their docs still describe the Molto2 wire protocol; only
    the package identity changed). Package names, crate directories, path
    dependencies, workspace members, and every `use keyroost_*` / `keyroost_*::`
    call site were updated.
  - **Binaries:** `keyroost` (the GUI — the headline app) and `keyroostctl` (the
    CLI). The `-ctl` suffix reads as "control utility" (cf. `kubectl`); no
    companion daemon is implied or planned.
  - **Project / repo:** the workspace `repository` field, `CLAUDE.md`, `README.md`,
    and `docs/` now say `keyroost`. The physical device name **`Molto2` /
    `Molto2v2`** was deliberately preserved everywhere (it still names the
    hardware), as was the ephemeral `moltoui-test` scratch-dir token.
  - **Verified:** workspace builds, **217 tests pass**, clippy clean, no stray
    `molto2-*` / `moltoctl` / `moltoui` crate tokens remain.
  - **Out-of-tree follow-ups (the user's to do):** rename the GitHub repo
    `framefilter/MoltoUI` → `framefilter/keyroost` (keeps a redirect), and
    recreate the `~/.local/bin` PATH symlink to point at
    `target/release/keyroostctl` (the old `moltoctl` symlink now dangles).

**Phase 3 gating question — RESOLVED (2026-05-29, on hardware).** The PC/SC-reuse
plan holds, and better than hoped: the Solo 2 *does* expose a usable USB CCID
interface. `keyroostctl list` shows a reader `SoloKeys Solo 2 [CCID/ICCD Interface]
(<serial>) 01 00`, and selecting the Yubico OATH AID (`A0 00 00 05 27 21 01`)
over that reader returns SW `9000` with a 15-byte version TLV, with `LIST`
(INS `0xA1`) also `9000` — i.e. the Trussed secrets/OATH applet answers the
Yubico OATH protocol over USB PC/SC. The same SELECT+LIST succeeds on the test
YubiKey. So OATH goes over PC/SC for **both** stacks; the CTAPHID `0x70` fallback
is not needed. (Earlier worry came from `pynitrokey` driving OATH over CTAPHID
because *their* library lacks CCID support — not a device limitation.)

The pure-Rust OATH byte layer lives in `crates/keyroost-oath` (APDU builders,
TLV parsing, RFC-4226 truncation, known-answer tests).

**Phase 3 transport + CLI — DONE (2026-05-29).** `keyroost_transport::OathSession`
drives the applet over PC/SC: reader connect, SELECT, the `61xx`/`SEND_REMAINING`
reassembly loop, and `list`/`calculate_totp`/`put`/`delete`. `keyroostctl oath
{list,code,add,delete}` wraps it, with reader selection mirroring the FIDO picker
posture (auto-use a lone OATH key, `--reader <substr>` to choose, refuse to guess
among several) and the base32 secret read via stdin/env, never argv. Verified on
hardware: a put→code→delete round-trip on a YubiKey produced a code matching
`oathtool` for the RFC 6238 seed, and SELECT+LIST work on the Solo 2 too.

**OATH password auth — DONE (2026-05-29).** `keyroost-oath` gained a vendored
HMAC-SHA1 + PBKDF2-HMAC-SHA1 (on the in-tree SHA-1; no new deps), the
`SET_CODE`/`VALIDATE` builders, the SELECT-response parser (`SelectInfo`,
password-required detection), and the Yubico access-key derivation
(`PBKDF2(password, salt=device id, 1000, 16)`) — all under RFC 2202/6070/6238
known-answer tests. `OathSession` now parses SELECT, exposes `password_required`,
and adds `unlock` (VALIDATE with mutual-auth verification of the card's reply),
`set_password`, and `clear_password`; a dedicated `OathPasswordRejected` error
replaces the misleading Molto2 "wrong customer key" message. `keyroostctl oath`
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

**OATH GUI pane — DONE (2026-05-29).** `keyroost` gained an "OATH" tab: a
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
put/delete/unlock paths are the same ones hardware-verified via `keyroostctl oath`.
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
   PC/SC (the YubiKey's CCID interface is a visible reader; keyroostctl already
   speaks PC/SC — dependency-free, no `ykman`). Required for the two-YubiKeys
   case, which (1) cannot solve.
3. **AAGUID** from `authenticatorGetInfo`: model-level display only, not
   per-device identity.

### Config — `~/.config/keyroost/keys.toml`

Array-of-tables, matched on `serial`; `name` is the unique label
(charset `[a-z0-9_-]`):

    [[key]]
    name   = "signing-yubikey"
    serial = "00000000"   # illustrative; real values not recorded here
    source = "ccid"      # "usb" | "ccid"
    vendor = "yubico"
    aaguid = "…"          # optional
    note   = "…"          # optional

Tool-managed via `keyroostctl key-name add <name> --path <dev>` /
`key-name list` / `key-name remove <name>`; hand-editing stays possible.

### Selection UX — hybrid (flags + interactive picker)

- `--name <label>` resolves label → serial → live `/dev/hidrawN`. `--path`
  remains the low-level escape hatch; the two are mutually exclusive and always
  win when given (scriptable / non-interactive).
- No flag + a terminal + >1 key → numbered picker read from **`/dev/tty`** (not
  stdin, which `--pin-stdin` already consumes). Hand-rolled, no prompt crate.
- No flag + not a TTY + >1 key → error requiring `--name`/`--path`.
- Exactly one key → use it, printing the resolved target.
- `keyroostctl list` shows the friendly name for any connected, configured key.

### Safety

- Always echo the resolved target before acting (`→ test-solo (Solo 2,
  /dev/hidraw5)`).
- >1 key connected → destructive ops must resolve to an explicit target (flag or
  picker), never a default. `fido-reset` additionally requires a typed
  confirmation (retype the name); `fido-creds-delete` is gated by explicit
  targeting alone.

### Architecture

Device identity + resolution lives in a **shared library**, so the CLI (flags +
picker) and the later `keyroost` GUI (dropdown) are thin front-ends over one
resolver.

### Build order

1. **Done.** USB-serial resolver + `keys.json` load + `key-name add/list/remove`
   + `--name`/picker plumbing + `list` name column + the safety guard.
2. **Done.** YubiKey CCID mgmt-serial read (unlocks the two-YubiKey case).
   `keyroost-transport::yubikey_ccid_serials()` reads each YubiKey CCID reader's
   management serial via the OTP applet (AID `A0 00 00 05 27 20 01 01`, API
   request slot `0x10`) — read-only, no PIN/touch, no new deps. keyroostctl matches
   a YubiKey's `/dev/hidrawN` to its reader by USB topology (sysfs
   `busnum`/`devnum` vs the reader's PC/SC `CHANNEL_ID`), so two connected
   YubiKeys are never confused; it falls back to the unambiguous single-reader
   case and otherwise refuses to guess. Verified on hardware with two YubiKeys
   on the same USB bus (distinct device addresses, distinct CCID serials) + a
   Solo 2.
3. **Done.** Shared-resolver extraction + GUI front-end. The CCID/topology/serial
   logic moved out of `keyroostctl` into a new `keyroost-resolve` crate (depends on
   keyring + hid + transport; pure `keyroost-keyring` stays hardware-free), so both
   front-ends are thin over one resolver. `keyroost`'s Security Keys pane now shows
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
- A web UI or background daemon.

(Renaming the project off the original `molto2-*` prefix was once a non-goal; it
is now **done** — see **Phase 5 — Rename to keyroost**.)

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
- **GUI worker thread — DONE (2026-05-29).** All blocking device I/O in `keyroost`
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
  underlying `keyroost_ctap::reset()` path was confirmed end-to-end on a real
  YubiKey ("All credentials wiped, PIN cleared").
- **CredentialManager double token fetch — DONE (2026-06-01).** `PinUvAuthToken`
  now derives `Clone`; `keyroost`'s `open_and_unlock` hands the manager a clone and
  keeps the original for the cached session, dropping the second redundant
  PIN/ECDH exchange. The hand-rolled token reconstructions in `refresh_with_token`
  / `delete_credential` collapsed to `.clone()`. (Verified valid by the existing
  token-reuse across delete+refresh; builds + tests green.)
- **Bootloader-mode detection — DONE (2026-06-01).** `keyroost-hid` gained a
  `KNOWN_BOOTLOADERS` table (Solo 2 / Nitrokey 3 DFU = `1209:b000`),
  `HidDevice::bootloader_label()`, and `bootloader_device_present()`. A device in
  DFU enumerates as plain HID (no FIDO page) and so vanishes from FIDO lists;
  now `keyroostctl list` tags it `[bootloader]` and notes it when the FIDO list is
  empty, `resolve_fido_path`'s "no FIDO device" error names it, and the `keyroost`
  Security Keys pane surfaces "re-plug it to return to application mode" instead of
  a silent empty list. Unit-tested; no hardware DFU device on hand to confirm the
  live VID:PID, but the path is purely ID-table driven.

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
