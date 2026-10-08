- **Errors don't repeat a secret.** A secret typed where its source goes
  (`--pin 123456`, `--seed=JBSWY3DP`), a stray value after a source, a
  literal `otpauth://` URI or a removed flag's value is refused without
  being printed, and an error about an `env:NAME` source names the flag,
  not the variable, in case the secret was typed where the name goes.
  ([#165])
