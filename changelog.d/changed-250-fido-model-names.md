- **The CLI names a FIDO2 key by its model, as the app does.** A key
  showed as "YubiKey" on keyroostctl's `→` line and in `list` while the
  app said "YubiKey 5 Series with NFC". The CLI now reads the targeted
  key's FIDO2 info (one quick read, no PIN) and names it by the model that
  info identifies; `list` and `--json` use the same names. Where the key
  can't be read (Windows without administrator rights) both keep its USB
  name. ([#250])
