- **Larger large-blob writes reach the key.** keyroost now writes the
  large-blob store in pieces of at most 960 bytes. A YubiKey 5 (firmware
  5.7) refused a single 1,290-byte piece even though it reports a larger
  limit, and took the same data in smaller pieces, so names stored on the
  key, `fido blob` and vaults stopped saving once the store held about
  1.1 KB. ([#285])
