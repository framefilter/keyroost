- **`fido ssh export ID` picks one of several SSH credentials that share
  an RP ID,** such as ssh-keygen keys made for the same application with
  different `-O user=` names. `--rp` alone couldn't tell them apart, so
  export refused. The ID is the credential's hex ID, an argument as in
  `fido credential delete ID`; `fido ssh list` now prints it under each
  credential. Exported by ID, the default file name carries the ID's
  first 8 hex digits, so two such exports don't land on the same file.
  ([#265])
