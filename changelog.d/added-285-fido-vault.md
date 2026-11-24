- **A password vault on FIDO2 keys (experimental).** `fido vault` keeps
  passwords in an encrypted vault in the key's large-blob store, opened with the
  FIDO2 PIN and a touch: `vault list`, `add`, `delete`, `rotate` (a new key for
  the vault), `export` and `import` (a passphrase-protected backup file,
  imported selectively), and `vault entry list`, `show`, `add`, `edit` and
  `delete`. Every change re-reads the key first, so another program's change is
  reported, not overwritten. It uses the vault and backup formats of Token2's
  FidoParole, checked against FidoParole's own vault code and libfido2; Token2
  approved building on it in discussion #74. The large-blob store is shared with
  websites that keep data with their passkeys, so a vault write that leaves less
  than a quarter of it free prints a note saying how full it is. Checked end to
  end on a YubiKey 5; please report problems as issues. ([#285])
