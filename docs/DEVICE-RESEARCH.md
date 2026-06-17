# Per-device research plan

A runbook for a future Claude to work through **when each device arrives**.
Two independent research threads. Keep findings in this file (it's the durable
record). This is an **outline**, not a finished design — go only as deep as each
step needs.

Hardware in play: a YubiKey 5 is already on hand (`1050:0407`, fw 5.7.1); a
second YubiKey and a SoloKey / Solo 2 (`1209:beee`, Trussed) are incoming.

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
5. **Handle captured IDs as sensitive.** Abbreviate serials (first/last 2 chars) in commits/logs/this file.

## What we already know (code survey, 2026-05)

| Device | Candidate ID | Status |
|---|---|---|
| **Molto2** | `DeviceInfo.serial` (read on connect) | **Works** — stable, per-unit, no extra read, no write. |
| **FIDO (any)** | `HidDevice` path/vid/pid/name | `path` not stable across re-plug; vid:pid per-model; no serial. |
| **FIDO (any)** | CTAP `AuthenticatorInfo.aaguid` | **Per-model, not per-unit** — useless for two identical keys. |

Molto2 is solved; the open research is entirely FIDO-side.

## The decisive experiment: two-unit comparison

A candidate ID `X` is usable iff, across units A and B of the same model:
`X_A == X_A'` (stable across re-plug) **and** `X_A != X_B` (unique per unit).
This is why the work waits for a second identical unit.

## Experiments (read-only; note where root is needed)

- **E1 — USB string descriptors.** `lsusb -v -d <vid:pid> | grep -i iSerial`; `/sys/bus/usb/devices/*/serial`. Note which interface owns the serial (whole-device vs FIDO-only) — matters for constraint #3.
- **E2 — HID uniq ioctl.** `HIDIOCGRAWUNIQ` on `/dev/hidrawN` (usually empty for USB HID). Confirm.
- **E3 — AAGUID is model-level (control).** `keyroostctl fido info` on both units; confirm AAGUID is byte-identical.
- **E4 — Other-interface serial (privacy-sensitive).** YubiKey exposes a device serial via OTP/CCID. Establish feasibility + cost only; weigh constraint #3. Do not build a reader during research.
- **E5 — Vendor/management IDs.** Solo 2 / Trussed reports a device UUID via `solo2-cli`. Determine whether it's readable from the **application** (FIDO) interface or only bootloader/management.

## Per-device worksheets

### YubiKey 5 (`1050:0407`, fw 5.7.1; second unit incoming)
| Candidate | Stable re-plug? | Unique per unit? | Read-only? | Privacy cost | Verdict |
|---|---|---|---|---|---|
| USB iSerial (E1) | | | | cross-interface correlatable | |
| HID uniq (E2) | | | | | |
| AAGUID (E3) | (exp. yes) | (exp. NO) | yes | none | reject (model-level) |
| OTP/CCID serial (E4) | | | | high (anti-tracking) | |

### SoloKey / Solo 2 (`1209:beee`, Trussed; incoming)
| Candidate | Stable re-plug? | Unique per unit? | Read-only? | Privacy cost | Verdict |
|---|---|---|---|---|---|
| USB iSerial (E1) | | | | | |
| HID uniq (E2) | | | | | |
| AAGUID (E3) | (exp. yes) | (exp. NO) | yes | none | reject (model-level) |
| Trussed/solo2 UUID (E5) | | | | | |

## Privacy review (gate before any FIDO implementation)

1. Does the chosen ID create a tracking/correlation vector beyond this host?
2. Does reading it touch an interface FIDO2 keeps separate (constraint #3)? Worth it, or degrade gracefully?
3. **Graceful degradation:** if a unit exposes no usable per-unit ID, fall back to a non-persistent label ("the key in this port, now") and say so — don't fake stable identity.
4. Opt-in per device, with the stored ID visible/removable by the user?

## Thread A outcome

Fill the worksheets, answer the privacy review, then record the recommendation
here. Until then friendly-naming ships for Molto2 only (serial-keyed) or waits.

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
   differ from YubiKey — cross-check against PLAN.md's applet survey).
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
