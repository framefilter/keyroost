- **Authenticator accounts that require a touch can be added again.** The
  "require touch" setting was sent in a form YubiKeys refuse, so adding such
  an account (`oath add --touch`, or the touch option in the app) failed
  with `SW=6A80`. It now uses the layout the YubiKey accepts and the Trussed
  firmware source reads. ([#190])
