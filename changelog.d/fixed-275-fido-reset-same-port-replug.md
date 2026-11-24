- **FIDO2 reset in the app after a same-port replug on Windows.** A key
  with no USB serial comes back on the same HID path when it goes back
  into the USB port it left, and the app did not take that for the
  replug: the reset window kept waiting and no reset was sent. It is
  now taken for the replug, with the key's identity checked as before.
  Checked on Windows 11 with an ePass FIDO NFC Plus. On Windows, and for
  keys with a USB serial on every platform, the app now takes a key as
  unplugged only once it has been missing for half a second; so do
  `fido reset` and `factory-reset` on the command line everywhere. On
  every platform, a key missing from a single scan is never taken for a
  replug. Once the key is back, the reset is sent as quickly as before.
  ([#275])
