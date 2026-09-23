- **PIV reads now handle gzip-compressed certificates.** YubiKey stores some
  slot certificates gzip-compressed (the cert data object's CertInfo byte,
  `71 01 01`), and keyroost was handing the compressed bytes straight to the
  X.509 parser, which rejected them with "DER length field is implausibly
  large." `piv test` failed on such a slot before it even reached the PIN, and
  `export-cert` and the status pane's Subject-DN read had the same latent gap.
  keyroost now honours the CertInfo flag and inflates the certificate on read
  (size-capped), so `piv test`, `export-cert`, and the status pane read such a
  certificate correctly. A compressed certificate whose data is damaged, or
  that would decompress past a 64 KiB cap, is reported as present but
  unreadable, with the reason: `export-cert` and `piv test` fail with that
  message rather than writing or parsing the raw bytes, and `piv status`
  (text, and `--json` via a new `cert_unreadable` field) and the GUI show the
  slot as holding an unreadable certificate, not as empty.
  Reported by @n0xena. ([#147])
