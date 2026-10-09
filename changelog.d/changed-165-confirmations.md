- **Destructive commands ask first.** In a terminal they show a y/N question
  naming the key; in a script they need `--yes` (`-y`). A command whose
  PIN or seed is piped in on stdin also needs `--yes`. This now also
  covers replacing or deleting what the computer can't restore: `oath
  delete`, `otp delete`, `otp button set` (when a seed is already set) and
  `otp button clear`, `fido credential delete` and `fido fingerprint
  delete`, `molto seed set` and `molto import` on used slots, `molto
  customer-key change`, `prog seed set` and `prog config set`, and on PIV
  `retries set`
  (which also resets the PIN and PUK to their factory defaults) and, when
  the slot is in use, `key generate`, `cert import`, `cert generate` and
  `--generate-key`. If the question was shown, keyroost checks it is
  still the same key before acting. `factory-reset` asks you to type
  `reset`, and `otp interface` reads its phrase from the terminal only.
  ([#165])
