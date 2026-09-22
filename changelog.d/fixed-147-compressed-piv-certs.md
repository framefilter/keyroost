- **PIV reads now handle gzip-compressed certificates.** YubiKey stores some
  slot certificates gzip-compressed (the cert data object's CertInfo byte,
  `71 01 01`), and keyroost was handing the compressed bytes straight to the
  X.509 parser, which rejected them with "DER length field is implausibly
  large." `piv test` failed on such a slot before it even reached the PIN, and
  `export-cert` and the status pane's Subject-DN read had the same latent gap.
  keyroost now honours the CertInfo flag and inflates the certificate on read
  (size-capped). Separately, `piv test` now takes the slot's public key from
  GET METADATA when the card offers it and falls back to the certificate only
  otherwise, so it reads the key straight from the slot and also works on a
  slot that holds a key but no certificate. Reported by @n0xena. ([#147])
