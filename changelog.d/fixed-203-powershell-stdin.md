- **Piping a secret in Windows PowerShell 5.1 works.** `"SEED" |
  keyroostctl oath add NAME --seed stdin` failed there with "the seed is
  not valid base32 (invalid character in input)": PowerShell 5.1 can start
  piped text with an invisible byte-order mark, two of them when the
  console also uses UTF-8, which keyroost took as part of the seed.
  Byte-order marks at the start of stdin are now ignored for every secret
  read from it. ([#203])
