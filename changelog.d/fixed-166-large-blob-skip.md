- **One malformed large-blob element no longer hides the whole store.** An
  element not in the standard entry format is skipped and counted in `fido
  blob list` (and its JSON `skipped`), and kept unchanged by every write.
  ([#166])
