- **Unlock with a fingerprint instead of the FIDO2 PIN (experimental).** On a
  key with a fingerprint enrolled, `--unlock fingerprint` unlocks with a touch
  of the sensor and no PIN, and `--unlock auto` tries the finger and falls back
  to the PIN given by `--pin`, saying which one unlocked. Every command that
  takes the FIDO2 PIN has it, apart from `fido pin change`: `fido credential`,
  `fido fingerprint`, `fido config`, `fido pin min-length set` and
  `force-change`, `fido blob`, `fido ssh`, every `fido vault` command, and
  `name set|clear` on the key. The app has a Touch fingerprint button beside
  Unlock on the FIDO2 and Vault tabs and in the naming field, and in the
  Settings dialog on keys that allow settings changes by fingerprint; each tab
  takes its own touch. It follows CTAP 2.1 and was tested against scripted
  keys, not yet on a fingerprint key: please report problems as issues.
  ([#295])
