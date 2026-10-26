- **`openpgp info` notices a key whose fingerprint is missing.** It now
  reads each slot's public key (no PIN) and, when a slot holds a key but no
  fingerprint, says `(none), but a key is present`; the app's OpenPGP card
  says the same, `(none), but a key is present`. `--json` gains
  `key_present_sig`, `key_present_dec` and `key_present_aut` (true, or
  `null` when the card doesn't tell). ([#215])
