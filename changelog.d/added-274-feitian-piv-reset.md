- **PIV reset on Feitian keys.** `piv reset` and `factory-reset`, and
  the same actions in the app, now reset the PIV applet of a Feitian
  key: they block its PIN and PUK and send the reset instruction these
  keys use. Before, the key refused keyroost's reset and a factory reset
  reported PIV as failed. After a reset keyroost names the PIN and PUK
  the key is left with (both 12345678). A BioPass FIDO Pro waits for a
  touch before it resets, and keyroost asks for it. Checked on an ePass
  FIDO NFC Plus and a BioPass FIDO Pro with the command line.
  Contributed by @Snrat. ([#274])
