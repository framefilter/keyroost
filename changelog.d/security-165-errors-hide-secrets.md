- **Errors don't repeat a secret.** A stray value next to a secret flag
  (`--hex-stdin DEADBEEF`, `--hex-stdin=DEADBEEF`), a literal
  `otpauth://` URI or a removed flag's value is refused without being
  printed, and an error about an `--X-env` flag names the flag, not the
  variable, in case the secret was typed where the name goes. ([#165])
