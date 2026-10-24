- **Import a key and certificate from a .p12/.pfx file.** `keyroostctl piv
  key import --slot 9a --in FILE` writes a private key and its certificate
  from a PKCS#12 file into a PIV slot, then tests the slot as `piv test`
  does; in the app, it's "Import key from file…" on a PIV slot.
  Legacy-encrypted files (RC2/3DES, the kind some certificate authorities
  such as Spain's FNMT still issue) open directly. keyroost checks that the
  key can take the file before it asks for the management key. A file with
  several keys is listed for `--entry N`, and `--chain-out FILE` saves the
  authority certificates, which are not written to the card. On a
  Nitrokey 3, RSA keys go into slot 9A; HID Crescendo cards aren't supported
  yet. An imported key can't be attested as generated on the key. ([#174])
