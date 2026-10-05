- **FIDO2 reset waits for the replug.** `fido reset` on a USB key and the
  FIDO2 step of `factory-reset` now ask you to unplug the key and plug it
  back in (within 60 seconds), check it is the same key, then ask for a
  touch. There is no Enter to press. `factory-reset` ends with "N wiped,
  M skipped, K failed" and exits with an error if any step was skipped
  or failed. ([#165])
