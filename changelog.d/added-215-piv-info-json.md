- **`piv --json info` says whether the PIN is verified and whether each slot
  holds a key.** New `pin_verified` (true/false) and, per slot, `key_present`
  (true, false, or `null` when the key can't tell). `piv info` and the app's
  PIV header now say "PIN verified" instead of "PIN accepted", matching
  `openpgp pin verify`. ([#215])
