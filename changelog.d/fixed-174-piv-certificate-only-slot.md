- **A PIV slot holding only a certificate no longer reads as holding a
  key.** In the app, generating a key into such a slot warned that it
  "destroys the existing key", and Move key and Delete key were offered
  for it. It now reads "certificate present, no key", and generating or
  moving a key into it notes that the certificate stays. Retired slots now
  show their certificates too. `keyroostctl piv info` adds ", no key" to
  such a slot's line. ([#174])
