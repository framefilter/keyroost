- **Command names follow one pattern.** FIDO commands nest by topic:
  `fido pin set` / `change` / `retries`, `fido credentials list` /
  `delete` / `metadata`, `fido fingerprints list` / `add` / `rename` /
  `delete`, and `fido config set-min-pin-length`, `force-pin-change`,
  `enable-enterprise-attestation`, `enable-always-uv` and
  `disable-always-uv`. `piv info`, `openpgp info` and `otp info` replace
  `piv status`, `openpgp status` and `otp config`. On `otp`: `get` is now
  `code`, `button-hotp` is `set-button-hotp`, `erase-all` is `reset`,
  `remove-pin` is `clear-pin`, and `fp-status` / `fp-enable` /
  `fp-disable` are `fingerprint-status` / `fingerprint-enable` /
  `fingerprint-disable`. `otp fp-list` and `otp unlock-list` are now
  `otp list --unlock fingerprint` and `otp list --unlock auto`
  (`--pin-only` is `--unlock pin`, the default). `key-name remove` is
  `key-name delete`. An old name is refused with an error naming the new
  one. The migration page lists every change. ([#165])
