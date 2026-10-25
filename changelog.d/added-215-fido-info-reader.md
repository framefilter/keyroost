- **`fido info --reader` reads a key through a smart-card reader**, as
  `fido reset --reader` already could. A key that only speaks U2F there gets
  the same line as over USB, in the app too, instead of an error. ([#215])
