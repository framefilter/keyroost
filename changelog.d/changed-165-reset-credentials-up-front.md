- **Reset credentials are read before the reset starts.** `piv reset`
  and `factory-reset` read their `--mgmt-key` or `--pin` before anything
  is reset, even on a card that turns out not to need it. An unset
  `env:NAME` variable is now an error up front, where before it could be
  ignored. ([#165])
