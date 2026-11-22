- **A Feitian key's firmware is its COS version.** The firmware shown
  for a Feitian FIDO key, in the app's key header and in `fido info`,
  was the three version bytes of its FIDO interface (1.0.1 on a BioPass
  FIDO Pro). It is now the COS version Feitian publishes for the key
  (4.7.17 on that one, 1.826 on an ePass FIDO NFC Plus), read from the
  key through its smart-card reader. With no reader for the key, no
  firmware is shown. ([#273])
