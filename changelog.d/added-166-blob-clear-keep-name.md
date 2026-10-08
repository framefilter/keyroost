- **`fido blob clear --keep-name`** clears the large-blob storage but keeps
  the key's name ("Keep the key's name" in the app). Without it, the
  warning names the name that goes. `fido blob list` shows the name entry
  as `key name`, and `fido blob edit` points to `name set` instead of
  changing it. ([#166])
