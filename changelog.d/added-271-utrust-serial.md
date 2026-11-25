- **An Identiv/Hirsch uTrust FIDO2 key shows its serial number.** A key
  with no USB serial string showed no serial. keyroost now reads the one
  Identiv's own program shows, from the key's card manager through its
  smart-card reader: the last eight digits of the serial number printed
  on the key. Checked on a uTrust FIDO2 NFC with firmware 3.33. A uTrust
  key that has a USB serial string is shown by that one, with or without
  its FIDO interface. ([#271])
