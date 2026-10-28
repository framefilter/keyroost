- **Enterprise attestation and the minimum PIN length are offered only on
  keys that support them.** The app's FIDO2 Settings show those rows only
  where the key lists them, and `keyroostctl` refuses before asking for
  the PIN, as it already did for Always UV. ([#227])
