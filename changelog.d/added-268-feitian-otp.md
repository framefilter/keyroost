- **OTP codes on Feitian FIDO keys.** The new `feitian` group reads, adds,
  imports and deletes TOTP and HOTP accounts in the OTP applet these
  keys carry (`info`, `list`, `code`, `add`, `import`, `delete`), naming
  an account by `--app` and `--account` as `otp` does, and the app has a
  Feitian OTP tab that lists accounts, reads a code, and adds, imports
  and deletes accounts. The key computes a code, and saves or deletes an
  account, once it is touched. Checked on an ePass FIDO-NFC; the
  applet's reset and access codes aren't supported yet, so
  `factory-reset` leaves Feitian OTP accounts on the key and says so.
  ([#268])
