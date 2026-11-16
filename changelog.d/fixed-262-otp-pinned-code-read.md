- **Reading a touch-required OTP code on a PIN-protected Token2 key works.**
  The app showed "malformed response: unknown OTP type byte": such a key
  answers a code read only on the connection that verified its PIN, and
  encrypts the reply. `otp code` now takes `--unlock` and `--pin` like
  `otp list`, and without a PIN it says the key is PIN-protected instead of
  "wrong OTP PIN". Reported by @mielas-mp3. ([#262])
