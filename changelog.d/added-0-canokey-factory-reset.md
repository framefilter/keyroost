- **`factory-reset` on a CanoKey uses CanoKey's own device reset.** On its
  USB reader, the command and the app's Factory reset block the key's
  Admin PIN (unless it already is), as the key requires, then reset
  everything on it in one step, FIDO2 included and with no replug: every
  applet, PIN and setting goes back to its default once the key gets a
  quick tap each of the five times it blinks (holding it down doesn't
  count). This is also the way back for a forgotten CanoKey Admin PIN.
  ([#0])
