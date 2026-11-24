- **`fido credential list --json` gives `user_id` as hex.** A credential's
  user handle is bytes, often not text, so it now comes as lowercase hex
  like `credential_id`, and every byte can be recovered. Before, bytes that
  weren't text came out as replacement characters. ([#285])
