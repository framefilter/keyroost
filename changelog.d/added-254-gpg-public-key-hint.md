- **After generating one OpenPGP key or importing a bare RSA key file,
  keyroost says how to get its public key.** Those leave a key on the card
  but no public key file; the CLI and the app now point at GnuPG's
  "Existing key from card", which builds the matching public key from the
  fingerprint and time keyroost recorded. ([#254])
