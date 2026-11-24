- **A key generated on a Feitian key is read back from the key.** `piv
  cert request` and `piv cert generate` no longer need the public key
  saved when the key was made (`--pubkey-in`): an ePass FIDO NFC Plus
  and a BioPass FIDO Pro attest a key generated on them, with a command
  of Feitian's own, and keyroost reads the public key from that
  certificate. An imported key is not attested, as on a YubiKey. Checked
  on both products with the command line. Contributed by @Snrat. ([#286])
