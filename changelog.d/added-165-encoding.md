- **`--encoding` for seeds and Molto2 customer keys.** Seeds are base32
  unless `--encoding hex` (`oath add`, `otp add`, `otp button set`,
  `molto seed set`, `prog seed set`). A new Molto2 customer key is hex unless
  `--encoding ascii`; the current key's encoding is
  `--customer-key-encoding`. ([#165])
