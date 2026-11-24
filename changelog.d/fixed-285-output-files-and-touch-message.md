- **No half-written output files, and a plain message for a missed touch.**
  A file written by `openpgp sign`, `decrypt` or `authenticate --out`, or by
  `fido vault export`, is removed if writing it fails partway, and
  `--overwrite` on Windows no longer cuts the old file short before the new
  one is complete. CTAP status 0x27 is shown in plain words; on a YubiKey 5
  it was the answer when the touch didn't come in time. ([#285])
