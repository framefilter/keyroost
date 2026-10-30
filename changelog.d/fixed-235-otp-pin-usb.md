- **A Token2 key with an OTP PIN set stays reachable over USB.** Once a PIN
  was set, every on-device OTP command over USB failed with `0x0105`,
  `otp pin clear` and `otp pin status` included, in the CLI and the app,
  and `fido info` and the app's key header showed its firmware as unknown:
  the check keyroost runs to pick the key's USB channel used a command that
  a PIN-protected key refuses. keyroost now follows that refusal with the
  key's documented PIN-state read, which tells a protected key from one
  that declines the channel. Tested end to end on a PIN+ Dual Ace R3.4
  (set, wrong PIN, codes and adds under the PIN, change, clear). ([#235])
