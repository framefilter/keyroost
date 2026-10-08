- **`--debug` traces FIDO.** FIDO commands over USB now show their messages
  with `--debug`; before, only `KEYROOST_CTAP_DEBUG` did, and it still
  works. FIDO through a smart-card reader isn't traced. FIDO PIN exchanges
  (clientPIN, authenticatorConfig) are hidden except the retry count and
  key agreement, like PIV and OpenPGP PIN checks. Every group now shares one
  line format (`> label  bytes`), which is for people and may change.
  With the GUI's debug capture on, Token2 OTP trace lines (redacted as on
  stderr) now appear in its activity log. ([#165])
