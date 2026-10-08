- **A hidden prompt for PINs, passwords, keys and seeds.** Every secret
  comes from `env:NAME`, from `stdin` (one line), or, with no flag and a
  terminal present, from a prompt that doesn't show what you type, like
  `sudo` or `ssh`. `stdin` typed at a terminal is hidden too. The Molto2
  and `prog` seeds and the new Molto2 customer key now prompt as well
  (`--encoding` says how they are written). New PINs, passwords and keys
  typed at the prompt are asked twice and must match; seeds and URIs are
  asked once. A script with no source is refused with an error naming
  the flag. Hex and base32 values lose surrounding spaces; PINs and
  passwords are kept exactly. After you type a secret at the prompt,
  keyroost checks it is still the same key before acting. In Git Bash
  (mintty) on Windows the prompt needs a real console: run `winpty
  keyroostctl …` or use `env:NAME`. The prompt uses the new `rpassword`
  dependency. ([#165])
