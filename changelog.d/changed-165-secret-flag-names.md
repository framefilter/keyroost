- **Secret flags renamed to match.** `oath add --secret-env` /
  `--secret-stdin` are now `--seed-env` / `--seed-stdin`, the names
  `otp add` uses. `openpgp verify --pin user|admin` is now `--which
  user|admin` (the PIN itself comes from `--pin-env`, `--pin-stdin` or
  the prompt). `otp change-pin` takes `--old-pin-env` / `--old-pin-stdin`
  and `--new-pin-env` / `--new-pin-stdin` in place of `--current-env`,
  `--new-env` and the two-line `--pin-stdin`. The old names are refused
  with an error naming the new one. ([#165])
