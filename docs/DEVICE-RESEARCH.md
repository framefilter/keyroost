# Per-device research plan

A runbook for a future Claude to work through **when each device arrives**.
Two independent research threads. Keep findings in this file (it's the durable
record). This is an **outline**, not a finished design — go only as deep as each
step needs.

Hardware in play (all on hand): Token2 Molto2 (`349e:0300`), YubiKey 5
(`1050:0407`, fw 5.7.1) ×2, SoloKeys Solo 2 (`1209:beee`, Trussed, fw 2.3.196).
Nothing here is "incoming" any more — the Solo 2 carried the first successful
FIDO F1–F5 run (`docs/BRINGUP.md`), and the two-YubiKey case is what the
correlation work was verified against. Token2 PIN+ / FIDO2+ coverage
comes from the vendor rather than this bench. An OnlyKey is on order — see the
identity note below; it is the interesting case.

- **Thread A — Device identity** (for local "friendly names"). Narrow, technical,
  has a privacy gate.
- **Thread B — Capabilities & day-to-day security uses** (feeds future in-UI
  guidance). Broad, user-facing, lower technical risk but needs accuracy review.

---

# Thread A — Per-device identity for friendly names

## The question

Let users label each physical unit locally ("yubikey 1", "Molto 1"). That needs
a **stable, per-unit identifier** we can read **without writing to the device**
and **without undermining the key's anti-tracking design**.

## Principles / constraints (hard, not preferences)

1. **Read-only.** No writing markers/UUIDs/largeBlob/credentials to establish identity.
2. **Local-only storage.** Captured ID stays on this host; never transmitted, never shown to a relying party.
3. **Respect FIDO2 anti-correlation.** FIDO2 omits a global device ID on purpose. If the only per-unit ID lives on a non-FIDO interface (e.g. a USB iSerial via OTP/CCID), using it re-introduces a correlatable hardware ID. Local-only use is the mitigation — state the trade-off, gate on the privacy review.
4. **No PINs, no secrets** required for identity probing.
5. **Handle captured IDs as sensitive.** Abbreviate serials (first/last 2 chars) in commits/logs/this file. This governs *durable, shareable* artifacts; it is not a redaction rule for the tool's own terminal output to the device's owner — `keyroostctl list` prints full serials, deliberately, because that is how you tell two of your own keys apart.

## What we already know (code survey, 2026-05)

| Device | Candidate ID | Status |
|---|---|---|
| **Molto2** | `DeviceInfo.serial` (read on connect) | **Works** — stable, per-unit, no extra read, no write. |
| **FIDO (any)** | `HidDevice` path/vid/pid/name | `path` not stable across re-plug; vid:pid per-model; no serial. |
| **FIDO (any)** | CTAP `AuthenticatorInfo.aaguid` | **Per-model, not per-unit** — useless for two identical keys. |
| **OnlyKey** | USB iSerial | **Unusable as identity** — the firmware reports a fixed serial (`1000000000`) on *every* unit (issue #37; the README roadmap records it as "fixed, non-unique"). FIDO-HID only, no CCID interface, so no serial fallback either. Not yet on the bench — vendor/device-survey fact, not one of our captures. |

**A serial is not automatically a per-unit ID.** The OnlyKey row is the
counterexample that constrains E1: a candidate that is stable across re-plug can
still be identical across units. The `X_A != X_B` half of the decisive experiment
below is therefore not optional — with a single unit on the bench, a fixed
vendor-wide serial is indistinguishable from a good one. keyroost already detects
repeated serials across connected keys and surfaces an advisory rather than
merging them (`duplicate_serial_note` in the GUI); a device in that state needs
placeholder handling before friendly names mean anything (issue #37).

Molto2 is solved; the open research is entirely FIDO-side.

## The decisive experiment: two-unit comparison

A candidate ID `X` is usable iff, across units A and B of the same model:
`X_A == X_A'` (stable across re-plug) **and** `X_A != X_B` (unique per unit).
This is why the work waits for a second identical unit.

## Experiments (read-only; note where root is needed)

- **E1 — USB string descriptors.** `lsusb -v -d <vid:pid> | grep -i iSerial`; `/sys/bus/usb/devices/*/serial`. Note which interface owns the serial (whole-device vs FIDO-only) — matters for constraint #3.
- **E2 — HID uniq ioctl.** `HIDIOCGRAWUNIQ` on `/dev/hidrawN` (usually empty for USB HID). Confirm.
- **E3 — AAGUID is model-level (control).** `keyroostctl fido info` on both units; confirm AAGUID is byte-identical.
- **E4 — Other-interface serial (privacy-sensitive).** YubiKey exposes a device serial via OTP/CCID. Establish feasibility + cost only; weigh constraint #3. Do not build a reader during research. *(Overtaken by events: the reader was built and shipped — `keyroost_resolve::ccid_serial_for`.)*
- **E5 — Vendor/management IDs.** Solo 2 / Trussed reports a device UUID via `solo2-cli`. Determine whether it's readable from the **application** (FIDO) interface or only bootloader/management.

## Per-device worksheets

Filled from what shipped rather than from a formal lab run — the thread closed by
being implemented (see "Thread A outcome"). Cells marked *not tested* stayed
untested because an earlier row already answered the question.

### YubiKey 5 (`1050:0407`, fw 5.7.1; two units on the bench)
| Candidate | Stable re-plug? | Unique per unit? | Read-only? | Privacy cost | Verdict |
|---|---|---|---|---|---|
| USB iSerial (E1) | n/a | n/a | yes | cross-interface correlatable | **not available** — most YubiKeys publish no `iSerialNumber`; the serial is only reachable over CCID (`keyroost_resolve::ccid_serial_for`) |
| HID uniq (E2) | not tested | not tested | yes | none | not pursued — E4 answered it first |
| AAGUID (E3) | yes | NO | yes | none | reject (model-level) — confirmed; the GUI treats AAGUID as a static *model* table |
| OTP/CCID serial (E4) | yes | yes — two units told apart on hardware during the correlation work | yes | high (anti-tracking) — mitigated by local-only, opt-in storage | **adopted as the fallback** (`ccid_serial_for`) |

### SoloKey / Solo 2 (`1209:beee`, Trussed, fw 2.3.196)
| Candidate | Stable re-plug? | Unique per unit? | Read-only? | Privacy cost | Verdict |
|---|---|---|---|---|---|
| USB iSerial (E1) | yes | assumed — 32 hex chars, per-unit by design, but only **one** unit was on the bench, so `X_A != X_B` was never run for this model | yes | correlatable across interfaces; mitigated by local-only storage | **adopted as the primary** |
| HID uniq (E2) | not tested | not tested | yes | none | not pursued — E1 sufficed |
| AAGUID (E3) | yes | NO | yes | none | reject (model-level) |
| Trussed/solo2 UUID (E5) | not tested | not tested | — | — | not pursued — E1 sufficed, and this would have needed a management interface |

## Privacy review (gate before any FIDO implementation)

1. Does the chosen ID create a tracking/correlation vector beyond this host?
2. Does reading it touch an interface FIDO2 keeps separate (constraint #3)? Worth it, or degrade gracefully?
3. **Graceful degradation:** if a unit exposes no usable per-unit ID, fall back to a non-persistent label ("the key in this port, now") and say so — don't fake stable identity.
4. Opt-in per device, with the stored ID visible/removable by the user?

## Thread A outcome — CLOSED (shipped)

Resolved in favour of **USB iSerial first, CCID-read serial as fallback**, local
and opt-in. Shipped as `keyroost-keyring` (serial-keyed friendly names, with an
`IdSource` field recording how the serial was obtained; nothing is written to
disk unless the user names a key) and `keyroost-resolve` (`effective_serials` /
`read_effective_serial`, with `ccid_serial_for` / `ccid_serials_for` covering
keys that expose no USB serial — experiment E4, built after all, despite the
"do not build a reader during research" note above). Surfaced as
`keyroostctl key-name` plus a global `--device <NAME>` on every subcommand. E3
resolved as predicted: AAGUID is model-level, which is why
`crates/keyroost/src/ui/aaguid.rs` can be a static model table.

Two constraints the implementation had to add that this plan did not anticipate:

- **Non-unique serials are real.** See the OnlyKey note above — a serial is not
  automatically a per-unit ID. keyroost detects repeats among connected keys and
  shows an advisory rather than treating identical serials as one key.
- **Correlation fails closed where the platform reports no USB topology.**
  Windows and macOS report no USB bus position, so a reader that two HID nodes
  could each own is no longer guessed at by vendor name; contended sets are shown
  separately. That is privacy-review item 3 ("graceful degradation") answered
  concretely: where identity can't be established, say so rather than fake it.
  ([#51](https://github.com/framefilter/keyroost/issues/51) follow-up below.)

The HID-only resolver (`read_effective_serial`, `connected_keys`) was removed in
v0.13.0; the GUI and CLI now share the device model (`keyroost_resolve::enumerate`),
and the CLI picks a row with `select::resolve_target`.

## Identity matching across interfaces (#51, v0.13.0)

On Windows and macOS a key's FIDO-HID node and its smart-card reader carry no
USB position, so the two halves of one key could not be joined when two keys of
the same make were connected. Matching now runs in three steps: USB position
(where the OS reports it), then the identity each side reports, then the
existing vendor fallback. Identities are compared only within one encoding;
two encodings whose relation no real key has confirmed are never equated.

| Vendor | HID side | Smart-card side | Compared as |
|---|---|---|---|
| Yubico | management READ CONFIG over CTAPHID (vendor command `0xC2`, config page 0, as yubikit sends it); serial is TLV tag `0x02` | the serial already read by the reader probe (no extra traffic) | decimal serial |
| Solo 2 | USB `iSerialNumber` (the device UUID); fallback: admin UUID over CTAPHID (vendor command `0xE2`) | SELECT the admin applet `A0000008470000 0001`, then `00 62 00 00` → 16-byte UUID | lowercase hex UUID |
| Token2 | GET_INFO serial request (§6.10 of Token2's public OTP-on-FIDO protocol document) over HID, reply `D1 len …` | the same request after selecting the FIDO applet; if that fails, the OTP applet's reply, which is plain ASCII decimal | the FIDO-format reply with the FIDO-format reply only; the OTP-applet form only with itself |

**Evidence.** YubiKey 5 (fw 5.7) and Solo 2 (fw 2.3.x) were matched by
identity alone on hardware: with USB-position matching switched off in a test
build, the device list came out identical to the USB-position result. The two
CTAPHID vendor commands were confirmed read-only on the same keys (YubiKey
configuration unchanged; Solo 2 returned its UUID, keys unchanged). Token2 is
implemented from its public protocol document; how the FIDO-format and
OTP-applet encodings relate is not yet confirmed on a real key, so they are
compared only like-for-like until it is. A Windows community test is pending.
The Molto2 and the single-profile programmable tokens are never sent an
identity read.

**Privacy.** Identities are read only to join the two halves of a key, held in
memory for that scan, and written to disk only when the user names the key
(`keys.json`, as before). Every read is read-only and traced under `--debug`;
the HID reads give up after 1.5 seconds. Reads are planned only for what USB
position leaves unmatched, so where USB position settles every key (Linux) no
identity read is sent. Where several keys of one make are connected, a key
that doesn't answer is shown as two entries, not guessed at.

---

# Thread B — Capabilities & day-to-day security uses

**Goal of this thread:** for each device, build an accurate picture of what it
can *do* and how a normal person uses it day-to-day to be safer. This research
feeds an EVENTUAL UI deliverable (not built yet): **in-app helper tips,
plain-English explanations of each feature, and generic, vendor-neutral usage
examples** aimed at security-conscious but non-technical users.

Outline for a future Claude (don't over-research — breadth first, depth later):

1. **Enumerate capabilities per device.** FIDO2/WebAuthn (passkeys, resident
   keys), U2F, OATH-TOTP/HOTP, PIV, OpenPGP, Yubico OTP / HMAC challenge-response,
   PIN & policy features. Note which the device actually supports (Solo 2 / NK3
   differ from YubiKey — confirm against the device's own applet responses, not
   a stored table; see the "No device→capability matrix" standing decision in
   `TODO.md`).
2. **Map each capability to a day-to-day use.** Plain language, concrete:
   e.g. "phishing-resistant login to Google/GitHub" (passkey), "log into SSH
   with a hardware key" (FIDO2 SSH), "2FA codes for sites without push" (OATH),
   "sign your git commits" (OpenPGP/PIV). One or two everyday scenarios each.
3. **Frame the security benefit in plain English.** Why it's safer than the
   password/SMS alternative — short, non-alarmist, no jargon.
4. **Collect generic examples** suitable to surface in-UI later. Keep them
   vendor-neutral and provider-agnostic where possible.
5. **Accuracy guardrails.** This becomes user-facing security guidance, so:
   no overpromising ("unhackable"), note real caveats (backup/spare key, what
   happens if lost), and have claims reviewed before they ship in the UI.

## Thread B outcome

A per-device capability → everyday-use → plain-English-benefit table that the
future UI-guidance work draws from. Capture it here as the research progresses.
