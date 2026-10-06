- **Destructive commands ask first.** In a terminal they show a y/N question
  naming the key; in a script they need `--yes`. A command whose PIN or seed
  is piped in on stdin also needs `--yes`. This now also covers replacing or
  deleting what the computer can't restore: `oath delete`,
  `otp delete`, `otp button-hotp` (when a seed is already set) and
  `delete-button-hotp`,
  `fido creds-delete` and `fingerprint-delete`, `molto seed`, `import` and
  `import-file` on used slots, `prog seed` and `config`, and on PIV
  `set-retries` and, when the slot is in use, `generate-key`,
  `import-cert`, `self-sign` and `--generate-key`. If the question was
  shown, keyroost checks it is still the same key before acting.
  `factory-reset` asks you to type `reset`, and `otp interface` reads its
  phrase from the terminal only. ([#165])
