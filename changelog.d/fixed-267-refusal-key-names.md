- **A refusal names the keys it lists as everything else does.** When
  `--device` was a serial or list number for the wrong kind of key, the
  keys to choose from were shown by short USB labels ("YubiKey",
  "PIN+ Series (FIDO + PGP)") and without names stored on the keys. It
  now reads those names and the full model names first, as the other
  refusals do ("YubiKey 5 Series with NFC"), only when a command is
  refused. ([#267])
