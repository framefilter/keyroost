- **One JSON shape.** `--json` output is always one object. Lists sit under
  a named key: `keys` for the overview and `list`, `accounts` for `oath
  list` and `otp list`. Every field is present, `null` when unknown. Each
  idea has one name and type: `serial` is a string, PIV `slot` is the
  `--slot` value (`"9a"`) with `slot_name` beside it, `molto info` reports
  `utc_time`, `molto slots` reports `algorithm` (`"sha1"`), `period` and
  `digits`, `oath list` and `otp list` spell `algorithm` the same way
  (`"sha1"`), PIN retries are `user_pin_retries`, `pin_retries` and so on,
  accounts have a `type`, and the overview says `capabilities`. The
  migration page lists every field. ([#165])
