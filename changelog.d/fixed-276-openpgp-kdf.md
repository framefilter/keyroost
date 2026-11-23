- **OpenPGP PINs work on cards with the KDF setting on.** A card set up
  with `gpg --card-edit` → `kdf-setup` keeps its PINs hashed, and keyroost
  sent them as typed: each PIN check failed and spent a retry, enough of
  them could block the admin PIN, and PIN changes were refused. keyroost now
  reads the card's KDF setting (no PIN needed) and hashes every PIN it
  sends the way the setting says, for checking, changing and unblocking
  alike. `openpgp info` and the app show the setting on a `KDF` line (`kdf`
  in `--json`). A setting keyroost doesn't recognize is refused before any
  PIN is sent, and with the setting on, a PIN shorter than the spec allows
  (user 6, admin 8) is refused before the card sees it, since the card can
  no longer check. `--debug` traces of PIN commands no longer show the
  PIN's length either. Reported by @GrassGlass. ([#276])
