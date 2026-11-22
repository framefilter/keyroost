- **PIV reset on Feitian keys.** `piv reset` and `factory-reset`, and
  the same actions in the app, now reset the PIV applet of a Feitian
  key: they block its PIN and PUK and send the reset instruction these
  keys use. Before, the key refused keyroost's reset and a factory
  reset reported PIV as failed. Checked on an ePass FIDO-NFC with the
  command line; the card is left with Feitian's factory management
  key. ([#274])
