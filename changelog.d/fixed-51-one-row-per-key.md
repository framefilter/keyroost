- **One row per key on Windows and macOS.** Where the system reports no USB
  position, keyroost now asks each side of a key for the identity it reports
  (a YubiKey's serial, a Solo 2's ID, a Token2 key's serial) and joins the
  FIDO and smart-card halves into one row. The GUI sidebar and the CLI share
  this matching. A key that doesn't answer still shows as two rows. On Linux
  nothing changes. ([#51])
