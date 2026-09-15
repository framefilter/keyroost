- **Fingerprint unlock for Token2 Bio3 OTP.** On an R3.4 Bio3 key with a
  fingerprint enrolled, protected OTP codes can be released by a sensor touch
  as well as by the PIN. The CLI's `otp` group gains `fp-status`, `fp-enable`,
  `fp-disable`, `fp-list` (touch to unlock) and `unlock-list` (fingerprint
  first, PIN fallback; `--pin-only` forces the PIN), and the GUI's unlock
  prompt offers a touch button alongside the PIN field when fingerprint
  protection is on. Enrollment itself is done through the key's FIDO2
  fingerprint setup. Contributed by @token2. ([#130])
