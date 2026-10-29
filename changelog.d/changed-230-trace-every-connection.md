- **The trace covers every connection.** `--debug` now also traces FIDO2
  through a smart-card reader, and the app's APDU trace now includes FIDO2
  traffic over USB and through a reader, plus keyroost's notes on how it
  found and paired each key. In those notes, the serial numbers the reader
  probe reports and the ones some systems put in a reader's name are
  shortened to their first and last two characters. ([#230])
