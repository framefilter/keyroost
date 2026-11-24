- **`fido credential diff` compares two keys.** The new command lists
  the resident credentials found on only one of two connected FIDO2 keys,
  matched on relying-party ID and user handle, with `--json` support.
  With exactly two keys connected no naming is needed; otherwise `--a`
  and `--b` (or `--a-path`/`--b-path`) name the sides, and `--pin`,
  `--a-pin` and `--b-pin` supply the PINs. ([#287])
