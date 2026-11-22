- **More of PIV works on Feitian keys.** keyroost now sends these keys
  their own form of five things that did not work there: importing a
  private key (`piv key import` and the app's import: RSA-1024 to
  RSA-4096, P-256, P-384), a PIN and a touch policy for a generated or
  imported key, RSA-3072 and RSA-4096 keys, the PIN and PUK retry
  counts, and a new management key (3DES; the key measured refuses an
  AES one). Checked on an ePass FIDO-NFC with the command line. ([#277])
