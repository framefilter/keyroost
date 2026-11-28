- **keyroost says when a key wants a long touch to reset** (getInfo
  `longTouchForReset`): `fido info` shows it (`long_touch_for_reset` with
  `--json`), the app's FIDO2 "Security policy" card shows it, and on such
  a key every FIDO2 reset prompt, in `fido reset`, `factory-reset` and the
  app, says to touch and hold the key. Credential listings also name
  ES256K and ML-DSA-44, ML-DSA-65 and ML-DSA-87 keys. ([#297])
