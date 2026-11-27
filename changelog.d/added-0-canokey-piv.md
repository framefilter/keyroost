- **CanoKey PIV is supported as CanoKey 3.1 does it.** keyroost reads a
  CanoKey's firmware version and hardware variant from its Admin applet
  and offers what that firmware supports: a PIV reset blocks the PIN and
  PUK first, as the key requires; only an AES-192 management key is
  offered; the default PIN, PUK and management key are known; and long
  commands go chained, since the key takes no extended-length APDU
  (OpenPGP key imports and decryption too). The IDs the key uses for
  Ed25519, X25519, RSA-3072/4096 and P-521 are read from the key, so a
  table changed with CanoKey's tools is followed. Firmware before 3.1 is
  handled as before. ([#0])
