- **`piv cert generate --generate-key` and `piv cert request
  --generate-key` check the key type first, as `piv key generate` does.**
  They skipped keyroost's support list, so asking a YubiKey for an ECC
  P-521 key went to the card and came back as `SW=6A80`; now it stops
  before the management key is sent or anything is generated, says the
  key doesn't support it, and takes `--force` like `piv key generate`. The
  PIN- and touch-policy checks apply too. ([#237])
