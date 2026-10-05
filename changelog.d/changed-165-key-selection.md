- **Every command finds its key the same way.** A lone key is used
  automatically. With several, a terminal shows a numbered list to pick
  from (now on every platform); a script gets a refusal that lists the
  `--device` value for each key. No command takes "the first key found"
  any more. `--device` takes a name, a serial or a `list` number
  (`name:`, `serial:` or `list:` forces which). `--device` with `--reader`
  or `--path` is refused, and so is `--device` on commands that touch no
  key. `--reader` and `--path` are used exactly as typed, even when
  keyroost didn't detect a key there. ([#165])
