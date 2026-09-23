- **PIV reads now handle gzip-compressed certificates.** A PIV certificate
  object may hold its certificate gzip-compressed (the CertInfo byte
  `71 01 01`, part of the PIV standard); the tool that writes the certificate
  chooses this, and tools such as ykman do so on request. keyroost was
  handing the compressed bytes straight to the X.509 parser, which rejected
  them with "DER length field is implausibly large." `piv test` failed on
  such a slot before it even reached the PIN, and `export-cert` and the
  status pane's Subject-DN read had the same latent gap. keyroost now honours
  the CertInfo flag and inflates the certificate on read (size-capped), so
  `piv test`, `export-cert`, and the status pane read such a certificate
  correctly. The gzip checksum and length are verified on read, so a
  corrupted compressed certificate is reported as damaged rather than passed
  on. A compressed certificate whose data is damaged, or that would
  decompress past a 64 KiB cap, is reported as present but unreadable, with
  the reason: `export-cert` and `piv test` fail with that message rather than
  writing or parsing the raw bytes, and `piv status` (text, and `--json` via
  a new `cert_unreadable` field) and the GUI show the slot as holding an
  unreadable certificate, not as empty.
  Reported by @n0xena. ([#147])
