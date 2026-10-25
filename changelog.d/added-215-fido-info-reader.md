- **`fido info --reader` reads a key through a smart-card reader**, as
  `fido reset --reader` already could. A key that only speaks U2F there gets
  the same line as over USB, in the app too, instead of an error. With no
  options, `fido info` now picks the key the same way `fido reset` does, so
  with several FIDO keys (including one only reachable through a reader) it
  asks which one. ([#215])
