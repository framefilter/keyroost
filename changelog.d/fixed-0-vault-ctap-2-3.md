- **A fingerprint unlock on a key that reports CTAP 2.3 no longer asks for
  an extra touch to list its vaults.** keyroost looked for `FIDO_2_2` in
  getInfo, which CTAP 2.3 says no key lists, so it read a key that lists
  `FIDO_2_3` as older: it asked for a token bound to the vault first and,
  when the key refused it as CTAP 2.3 is written to, for one more
  fingerprint ("This key needs a second fingerprint to list its vaults").
  A key that lists `FIDO_2_3` or a later 2.x now gets the unbound token
  CTAP 2.3 lists under from the start. Checked against scripted keys, not
  yet on a fingerprint key. ([#0])
