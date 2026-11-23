- **More of PIV works on Feitian keys.** keyroost now sends these keys
  their own form of five things that did not work there: importing a
  private key (`piv key import` and the app's import), a PIN and a touch
  policy for a generated or imported key, RSA-3072 and RSA-4096 keys,
  the PIN and PUK retry counts, and a new management key. What a key
  holds goes by its product: an ePass FIDO NFC Plus takes RSA up to 4096
  bits, P-256 and P-384 and a 3DES management key; a BioPass FIDO Pro
  takes RSA-1024, RSA-2048 and P-256 and a 3DES or AES management key.
  Checked on one key of each with the command line. Contributed by
  @Snrat. ([#274])
