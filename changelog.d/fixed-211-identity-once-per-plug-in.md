- **Device scans ask a key for its identity once.** On macOS, the app asked
  a Yubico key for its serial number over the FIDO connection on every
  device scan, so a key that doesn't support that question (such as the
  YubiKey NEO) was asked again and again, and debug logs filled with the
  same two lines. keyroost now keeps the answer for as long as the key stays
  plugged in, wherever that can't be mistaken for a different key.
  ([#211])
