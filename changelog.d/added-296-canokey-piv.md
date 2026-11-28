- **CanoKey PIV is supported as CanoKey 3.1 does it.** keyroost reads a
  CanoKey's firmware version and hardware variant from its Admin applet
  and offers what that firmware supports: a PIV reset blocks the PIN and
  PUK first, as the key requires; only an AES-192 management key is
  offered, and it can be kept PIN-protected so the PIN alone unlocks
  management; the default PIN, PUK and management key are known; long
  commands go chained, since the key takes no extended-length APDU
  (OpenPGP key imports and decryption too); and an RSA-3072 or RSA-4096
  slot's public key is read back, which the key sends only when asked
  with Le, so `piv test` and the slot list see those keys. The IDs the
  key uses for Ed25519, X25519, RSA-3072/4096 and P-521 are read from
  the key, so a table changed with CanoKey's tools is followed. Firmware
  before 3.1 has only a 3DES management key and no P-521, so neither
  AES-192 nor P-521 is offered there, and firmware 2.x's own IDs for
  Ed25519, X25519 and RSA-3072/4096 are used (from CanoKey's source;
  not checked on such a key). ([#296])
