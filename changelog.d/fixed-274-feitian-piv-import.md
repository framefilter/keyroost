- **PIV key import no longer sends a Feitian key the wrong command.**
  The command keyroost imports a key with is a different command on
  these keys: with the PIN verified they accept it, as a change to the
  PIN and PUK retry counts. `piv key import` and the app's import now
  send a Feitian key its own import command instead. Seen on an ePass
  FIDO NFC Plus with harmless values; a real import was not sent the old
  way. Contributed by @Snrat. ([#274])
