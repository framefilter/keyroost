- **PIV key import no longer reaches a Feitian key.** The command
  keyroost imports a key with is a different command on these keys:
  with the PIN verified they accept it, as a change to the PIN and PUK
  retry counts. `piv key import` and the app's import now stop before
  sending it, the way they do for other keys with an import of their
  own. Seen on an ePass FIDO-NFC with harmless values; a real import
  was not sent. ([#274])
