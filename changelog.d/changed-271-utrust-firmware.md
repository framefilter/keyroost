- **An Identiv/Hirsch uTrust FIDO2 key's firmware is the version printed
  on it.** The firmware shown for such a key, in the app's key header
  and in `fido info`, was the three version bytes of its FIDO interface
  (0.0.1 on a key with firmware 3.33). It is now the version the key
  itself gives through its smart-card reader, 3.33 on that key. When the
  key doesn't answer that read, for instance with no reader for it here,
  the version bytes of its FIDO interface are shown as before. ([#271])
