- **Flags renamed to match.** `molto` commands take `--slot` in place of
  `-p` / `--profile` (Token2 calls slots profiles), and `molto config` and
  `prog config` take `--period` in place of `--time-step` (same values).
  `otp set-pin` takes `--new-pin-env` / `--new-pin-stdin`. `piv
  import-cert` reads `--in FILE`, and `piv export-cert`, `request-cert` and
  `self-sign` write `--out FILE`, in place of `--file`. `fido large-blob
  export` takes the output file as `--out FILE` instead of a second
  argument: `keyroostctl fido large-blob export 1 --out entry.bin`. An old
  flag is refused with an error naming the new one. ([#165])
