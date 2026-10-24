- **A PIV slot holding only a certificate no longer reads as holding a
  key.** In the app, such a slot warned that generating or importing
  "destroys the existing key" and offered Move key and Delete key. It now
  reads "certificate present, no key", and importing a key into it says
  the slot's certificate is replaced. Retired slots now show their
  certificates too. `keyroostctl piv info` adds ", no key" to such a
  slot's line. ([#174])
