- **Clearer `--help`.** Every flag and argument has a description.
  Commands that erase or replace something end their first line with one
  marker, such as "Irreversible: asks first (`--yes` to skip)", and that
  now includes commands that replace a key or seed (`piv generate-key`,
  `molto seed`, `otp set-button-hotp` and others). `request-cert
  --generate-key` replaces the slot's key and asks first. The top-level
  description covers every command group, and `--debug`, `--device` and
  `--json` are listed under "Global options" after a command's own flags.
  Two messages now say "canceled" (was "cancelled"). ([#165])
