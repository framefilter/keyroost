- **Changing a key's expiry on a card that records no fingerprint says
  so.** `openpgp key expiry` (and the app's Change expiry) called such a
  card's signature key a different key; it now says the card records no
  fingerprint for it, so keyroost can't tell whether it is that key.
  ([#254])
- **OpenPGP help no longer says a YubiKey always needs a touch.**
  `openpgp sign`, `authenticate`, `key generate` and `key expiry` said
  so; a touch is needed when the slot's touch setting is on. ([#254])
