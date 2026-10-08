- **`keys.json` no longer holds serials.** Each name is stored with a
  salted fingerprint of its key, the salt kept in `keys.salt` beside it, so
  the file shows no serial and two computers' files can't be matched. An
  older `keys.json` converts the first time it is read; a backup of the old
  file is kept until the conversion succeeds, then removed. v0.12 can't
  read the converted file and shows keys unnamed. If `keys.salt` is lost,
  set the names again; restoring the old salt doesn't bring them back.
  ([#166])
