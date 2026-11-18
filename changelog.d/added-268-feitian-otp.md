- **OTP codes on Feitian FIDO keys.** The new `ftotp` group reads, adds,
  imports and deletes TOTP and HOTP accounts in the OTP applet these
  keys carry (`info`, `list`, `code`, `add`, `import`, `delete`), and
  the app has a Feitian OTP tab that lists accounts, reads a code, and
  adds and deletes accounts. The key computes a code, and saves or
  deletes an account, once it is touched. Checked on an ePass FIDO-NFC;
  the applet's reset and access codes aren't supported yet. ([#268])
