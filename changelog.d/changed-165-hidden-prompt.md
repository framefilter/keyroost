- **A hidden prompt for PINs, passwords and keys.** Every secret comes
  from `--X-env VAR`, from `--X-stdin` (one line), or, with neither and a
  terminal present, from a prompt that doesn't echo what you type, like
  `sudo` or `ssh`. A `--X-stdin` flag typed at a terminal is hidden too.
  New PINs, passwords and keys typed at the prompt are asked twice and
  must match; seeds and URIs are asked once. A script with no source is
  refused with an error naming the flags. Hex and base32 values lose
  surrounding spaces; PINs and passwords are kept exactly. After you type
  a secret at the prompt, keyroost checks it is still the same key before
  acting. In Git Bash (mintty) on Windows the prompt needs a real
  console: run `winpty keyroostctl …` or use the `-env` flags. The prompt
  uses the new `rpassword` dependency. ([#165])
