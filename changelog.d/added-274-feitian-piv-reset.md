- **PIV reset on Feitian keys.** `piv reset` and `factory-reset`, and
  the same actions in the app, now reset the PIV applet of a Feitian
  key: they block its PIN and PUK and send the reset instruction these
  keys use. Before, the key refused keyroost's reset and a factory
  reset reported PIV as failed. After a reset keyroost names the PIN
  and PUK the key is left with (both 12345678), and generating an
  RSA-1024, RSA-2048, P-256 or P-384 key no longer carries a warning
  on a Feitian key that reports no version. Checked on an ePass
  FIDO-NFC with the command line. ([#274])
