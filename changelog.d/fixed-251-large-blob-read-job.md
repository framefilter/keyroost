- **Reading a key's FIDO2 storage no longer freezes the app.** The Storage
  tab read the large-blob store on the window's own thread, so a slow key
  froze the app until it answered, and the read left nothing in the
  Activity log's APDU trace. It now runs in the background like every
  other read. ([#251])
