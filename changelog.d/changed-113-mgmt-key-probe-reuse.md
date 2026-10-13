- **Fewer round trips for PIV admin actions on keys without GET METADATA.**
  On keys that don't report their management key's algorithm, the app
  tried all four algorithms before every action that needs it. It now
  remembers the answer while the key stays plugged in and checks it with one
  request (two for AES-192), falling back to the full check whenever that
  could choose differently. ([#113])
