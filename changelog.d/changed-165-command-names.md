- **Commands are grouped by what they act on, in separate words.**
  `piv pin change`, `piv key generate`, `piv cert import`, `openpgp pin
  change --admin`, `openpgp key show`, `oath password set`, `otp pin set`,
  `otp button set`, `fido credential list`, `fido fingerprint add`, `fido
  config always-uv enable`, `fido pin min-length`, `fido blob …` (was
  `large-blob`), `fido ssh …` (was `ssh-cert`), `molto sync`, `molto
  import --file`, and `name set|list|clear` (was `key-name`). `piv info`,
  `openpgp info` and `otp info` replace `piv status`, `openpgp status` and
  `otp config`; `otp get` is `otp code`, `otp erase-all` is `otp reset`,
  and `otp fp-list` / `otp unlock-list` are `otp list --unlock
  fingerprint` / `--unlock auto` (`--pin-only` is `--unlock pin`, the
  default). An old name is refused with an error naming the new one. The
  migration page lists every change. ([#165])
