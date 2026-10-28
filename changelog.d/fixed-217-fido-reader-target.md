- **`fido info --reader` and `fido reset --reader` name the reader they use.**
  The target line showed the key's USB path instead. `fido reset --reader`
  now checks the reader before asking to confirm: it gives the same error
  as `fido info --reader` when the reader's card has no FIDO side, and on
  Windows without administrator rights it says administrator rights are
  needed. ([#217])
