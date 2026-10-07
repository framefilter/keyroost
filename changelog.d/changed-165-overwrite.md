- **An existing output file is never replaced silently.** `piv export-cert`,
  `request-cert`, `self-sign` and `generate-key --save-pubkey`, `openpgp
  sign`, `decrypt` and `authenticate`, and `fido large-blob export` and
  `ssh-cert extract` ask "overwrite? [y/N]" at a terminal when the output
  file exists, and refuse in a script unless `--overwrite` is given. A
  directory as the output is refused before the key is touched, and so is
  a symlink for the `openpgp` outputs. `--overwrite` only covers the local
  file; `--yes` still confirms what happens on the key. ([#165])
