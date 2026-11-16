- **`fido ssh list` takes `--json`.** It printed its text lines instead.
  Each resident SSH credential is an entry with its `rp_id`,
  `credential_id` (as `fido credential list` gives it) and `cert_present`,
  whether the key holds an OpenSSH certificate for it. ([#265])
