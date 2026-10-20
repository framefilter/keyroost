- **Piping a secret in Windows PowerShell 5.1 works.** `"SEED" |
  keyroostctl oath add NAME --seed stdin` failed there with "the seed is
  not valid base32 (invalid character in input)": PowerShell 5.1 can start
  piped text with an invisible byte-order mark, which keyroost took as part
  of the seed. A byte-order mark at the start of stdin is now ignored for
  every secret read from it. ([#203])
