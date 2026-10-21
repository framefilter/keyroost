- **Authenticator debug traces no longer show account names or codes.**
  `keyroostctl --debug` and the app's APDU trace showed the Authenticator's
  account names (in hex) and current codes when listing or reading codes.
  Those parts are now hidden, like seeds and passwords already were; the
  status words stay, which is what a bug report needs. Traces get pasted
  into public issues, and an account list tells which services someone
  uses. ([#206])
