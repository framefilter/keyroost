- **A Feitian key's firmware is its COS version.** The firmware shown
  for a Feitian FIDO key, in the app's key header and in `fido info`,
  was the three version bytes of its FIDO interface (1.0.1 on a BioPass
  FIDO Pro). It is now the key's COS version, the one Feitian lists for
  the product, read from the key through its smart-card reader and
  shown as read: 47.17.00 on that key, which Feitian writes 4.7.17, and
  01.08.26 on an ePass FIDO NFC Plus, which Feitian writes 1.826. When
  the key doesn't answer that read, for instance with no reader for it
  here, the version bytes of its FIDO interface are shown as before.
  ([#273])
