- **FIDO2 reset in the app after a same-port replug on Windows.** A key
  with no USB serial comes back on the same HID path when it goes back
  into the USB port it left, and the app did not take that for the
  replug: the reset window kept waiting and no reset was sent. It is
  now taken for the replug, with the key's identity checked as before.
  Checked on Windows 11 with an ePass FIDO NFC Plus. The app on Windows,
  and `fido reset` and `factory-reset` on the command line everywhere,
  now take a key as unplugged only once two scans in a row miss it, so a
  key that is still connected but left out of one scan is not taken for
  a replug. ([#275])
