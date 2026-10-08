- **A key can carry its own name.** `keyroostctl name set NAME --store key`
  (or "On this key" in the app's naming dialog) writes the name into the
  key's FIDO2 large-blob storage, and every computer running keyroost shows
  it, without a PIN. Saving it needs the FIDO PIN; the name is visible to
  anyone who has the key. `name set` also renames, `name clear` removes a
  name wherever it is stored, and `name list` shows where each name lives.
  The entry's format is published with test vectors in
  `docs/PROTOCOL-device-label.md` so other tools can use it. If a key loses
  its name, `name list` and the app offer to write it back. Proposed by
  @token2. ([#166])
