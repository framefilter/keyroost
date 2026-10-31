- **`fido pin status --json` says whether a PIN is set.** It printed only
  `pin_retries`: a key with no FIDO2 PIN showed a count anyway (a Nitrokey
  3 said 8), as if one were set, or failed outright (a Token2 PIN+). It
  now prints `pin_set` too, named as in `otp pin status --json`, with
  `pin_retries` null when no PIN is set. ([#245])
