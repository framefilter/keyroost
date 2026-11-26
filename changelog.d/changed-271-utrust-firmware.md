- **An Identiv/Hirsch uTrust FIDO2 key's firmware is the version printed
  on it.** The firmware shown for such a key, in the app's key header
  and in `fido info`, was the three version bytes of its FIDO interface
  (0.0.1 on a key with firmware 3.33). It is now the version the key
  itself gives through its smart-card reader, 3.33 on that key, to a
  command found in the vendor's uTrust Token Manager for Windows (it is
  not in the vendor's documentation). The issue's reporter checked it
  on firmware 3.30. When the key doesn't answer that read, for instance
  with no reader for it here, the version bytes of its FIDO interface
  are shown as before. ([#271])
