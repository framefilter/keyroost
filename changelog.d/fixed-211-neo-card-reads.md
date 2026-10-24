- **PIV, OpenPGP and OATH reads wait for a card that was just reset.** On
  macOS, reading a YubiKey NEO's PIV, OpenPGP or OATH applet failed with
  "no Smart Card is currently in the device" or "an attempt was made to end
  a non-existent transaction", while ykman read the same key. The card had
  been reset just before the read. keyroost now waits up to three seconds
  for the card to come back and opens the session once more, before sending
  anything that could change the key. It also no longer asks a YubiKey NEO
  for its serial number over the FIDO connection, a question it does not
  answer. ([#211])
