- **Flags renamed to match.** `molto` commands take `--slot` (`-s`) in
  place of `-p` / `--profile` (Token2 calls slots profiles), and `molto
  config` and `prog config` take `--period` in place of `--time-step`
  (same values). `piv cert import` reads `--in FILE` (`-i`), and `piv cert
  export`, `cert request`, `cert generate` and `key generate` write `--out
  FILE` (`-o`), in place of `--file` and `--save-pubkey`; with
  `--generate-key`, `--save-pubkey` and `--load-pubkey` are `--pubkey-out`
  and `--pubkey-in`. `piv mgmt-key change` takes `--algorithm` (was
  `--new-algorithm`). `fido credential delete` and `fido fingerprint
  rename` / `delete` take `--id` (was `--cred-id` / `--template-id`), and
  so does `fido ssh extract` (was `--credential`). `fido blob export`
  takes the output file as `--out FILE` instead of a second argument:
  `keyroostctl fido blob export 1 -o entry.bin`. An old flag is refused
  with an error naming the new one. ([#165])
