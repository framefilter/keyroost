- **FIDO2 reset in the app after a same-port replug on Windows.** A key
  with no USB serial comes back on the same HID path when it goes back
  into the USB port it left, and the app did not take that for the
  replug: the reset window kept waiting and no reset was sent. It is
  now taken for the replug, with the key's identity checked as before.
  Checked on Windows 11 with an ePass FIDO NFC Plus. A key also has to
  be missing for half a second, over at least two scans, before the app
  or `fido reset` and `factory-reset` on the command line take it as
  unplugged, so a key that is still connected but left out of one scan
  is not taken for a replug. Once the key is back, the reset is sent as
  quickly as before. ([#275])
