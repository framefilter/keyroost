- **One flag per secret; its value says where the secret comes from.**
  `--pin env:NAME` reads an environment variable and `--pin stdin` reads
  one line, replacing `--pin-env NAME` and `--pin-stdin`. The same goes
  for `--new-pin`, `--puk`, `--new-puk`, `--admin-pin`, `--mgmt-key`
  (which also takes `default`), `--new-mgmt-key`, `--password`,
  `--new-password`, `--seed`, `--customer-key`, `--new-customer-key` and
  `--uri`. The `--old-…` flags are now the plain name: `--pin` is the
  current PIN and `--new-pin` the new one. `oath add --secret-env` is
  `--seed env:NAME`, `openpgp verify --pin admin` is `openpgp pin verify
  --admin`, and `otp change-pin --current-env` / `--new-env` are `otp pin
  change --pin env:NAME --new-pin env:NAME`. A secret typed as the value
  itself (`--pin 123456`) is refused with exit 2 and never shown. An old
  flag is refused with an error naming the new one. ([#165])
