- **A Feitian key that Windows reports as not responding is read.** On
  some Windows PCs an ePass FIDO NFC Plus's card stays unresponsive after
  plug-in, so none of its applets (OpenPGP, PIV, OTP) showed up. keyroost
  now warm-resets such a card once and connects again. ([#268])
