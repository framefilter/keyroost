- **`fido pin status` says when no FIDO2 PIN is set.** It printed the
  retry counter, "8 PIN attempt(s) remaining", on a key with no PIN (a
  Nitrokey 3), and on a key that refuses that question without one (a
  Token2 PIN+) it failed with `CTAP2_ERR_PIN_NOT_SET`. It now says no PIN
  is set, as the app's "No PIN configured" does. `--json` is unchanged.
  ([#237])
