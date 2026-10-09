- **One word per action, and every command ends in one.** The same job
  has the same word in every group: `fido pin status` (was `pin-retries`)
  and `fido credential status` (was `creds-metadata`) show state like
  `otp pin status`; `fido blob show` (was `large-blob get`) prints one
  entry; `fido ssh export` (was `ssh-cert extract`) saves a file like the
  other `export` commands; `otp button clear` (was `delete-button-hotp`)
  is the opposite of `set`; `molto list` (was `molto slots`) lists like
  every other group. Writes end in an action word: `molto seed set`,
  `molto title set`, `molto config set`, `prog seed set`, `prog config
  set`, `fido pin min-length set` (was `set-min-pin`) and `molto
  customer-key change`. `molto title --slot N` without `set` only shows
  the slot's title. An old name is refused with an error naming the new
  one, and nothing typed after it is repeated. ([#165])
