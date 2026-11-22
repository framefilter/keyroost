- **FIDO2 reset in the app after a same-port replug on Windows.** A key
  with no USB serial comes back on the same HID path when it goes back
  into the USB port it left, and the app did not take that for the
  replug: the reset window kept waiting and no reset was sent. It is
  now taken for the replug, with the key's identity checked as before.
  `fido reset` on the command line was not affected. Checked on
  Windows 11 with an ePass FIDO-NFC. ([#275])
