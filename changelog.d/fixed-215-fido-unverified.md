- **A FIDO key that doesn't answer properly shows as FIDO2?.** A key that
  opened but gave no proper answer to keyroost's first question used to
  show as FIDO2 and get a name read and a FIDO2 reset step; it now shows
  FIDO2? and gets neither until it answers. A key keyroost can't open at
  all keeps FIDO2 as before, and a failed question is asked again on the
  next scan. A key reached only through a smart-card reader now shows
  FIDO2? unless its FIDO applet reports FIDO2. ([#215])
