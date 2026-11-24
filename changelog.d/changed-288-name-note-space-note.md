- **A key's name and notes: a note when the store is nearly full.** A
  name saved on the key or a `fido blob` note belongs to no passkey, so
  a browser may clear it when the large-blob store is full and a website
  needs room; setting it again restores it. Saving one that leaves less
  than a quarter of the store free now prints the note vault saves print,
  in the CLI and in the app. ([#288])
