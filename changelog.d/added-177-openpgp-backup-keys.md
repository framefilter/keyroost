- **Create OpenPGP keys with a backup.** One step makes the signature,
  decryption and authentication keys, saves them to a passphrase-protected
  backup that GnuPG can read, writes your public key and a revocation
  certificate beside it, and loads the keys onto the card. In the app it is
  **Create keys with a backup…** on the OpenPGP card; on the command line,
  `keyroostctl openpgp key import --generate --backup FILE`. ([#177])
- **Restore a backup** onto a new or reset card, from a keyroost backup or a
  GnuPG export (`keyroostctl openpgp key import --in FILE`).
- **Change expiry date** on a key set, signed with the card or the backup;
  *Never* removes the date. New keys default to three years, as in GnuPG.
- **More key types** for backups: RSA-2048/3072/4096, NIST P-256/384/521,
  secp256k1 and Curve 25519. Brainpool keys can still be made on the card.
- The old *Generate & import* option, which made a key on the computer and
  discarded it after loading, is gone; use *Create keys with a backup* or
  *Generate on-card*.
