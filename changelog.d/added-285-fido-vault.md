- **A password vault on FIDO2 keys.** `fido vault` keeps passwords in an
  encrypted vault in the key's large-blob store, opened with the FIDO2 PIN
  and a touch: `vault list`, `add`, `delete`, `rotate` (a new key for the
  vault), `export` and `import` (a passphrase-protected backup file, imported
  selectively), and `vault entry list`, `show`, `add`, `edit` and `delete`.
  Every change re-reads the key first, so another program's change is
  reported, not overwritten. It uses the vault and backup formats of Token2's
  FidoParole, checked against FidoParole's own vault code and libfido2;
  Token2 approved building on it in discussion #74. Checked end to end on
  a YubiKey 5. ([#285])
