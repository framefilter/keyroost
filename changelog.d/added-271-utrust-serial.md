- **An Identiv/Hirsch uTrust FIDO2 key shows its serial number.** A key
  with no USB serial string showed no serial. keyroost now reads it from
  the key's card manager through its smart-card reader, with the read
  the vendor's uTrust FIDO2 Technical Manual describes. The four bytes
  shown are the serial the vendor's uTrust Token Manager shows: on a
  uTrust FIDO2 NFC with firmware 3.33, the last eight digits of the
  serial number printed on the key. The issue's reporter checked it on
  firmware 3.30. Whether the number differs on every key is not
  verified yet; two connected keys showing the same one are kept apart.
  ([#271])
