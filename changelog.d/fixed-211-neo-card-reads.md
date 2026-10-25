- **PIV, OpenPGP and OATH reads work on a YubiKey NEO.** On macOS, reading
  a YubiKey NEO's PIV, OpenPGP or OATH applet failed with "no Smart Card is
  currently in the device" or "an attempt was made to end a non-existent
  transaction", while ykman read the same key. The reads failed right after
  keyroost asked the NEO's FIDO side for its serial number, a question it
  does not answer. keyroost no longer asks it. As an added safeguard,
  keyroost also waits up to three seconds for a card that has just reset and
  opens the session once more, before sending anything that could change the
  key. ([#211])
