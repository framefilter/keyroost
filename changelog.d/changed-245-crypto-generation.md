- **Building from source needs Rust 1.89** (was 1.87) for the libraries
  and the CLI; the app still needs 1.92. Packaged builds are unaffected.
  The crypto libraries keyroost uses moved to their current generation
  together (AES, SHA-2, HMAC, AES-GCM, PBKDF2, scrypt, 3DES, RC2, the OS
  random source, Ed25519 and X25519), and they now raise their own
  minimum Rust in patch releases. Keys, backups and imports work as
  before. If the operating system can't supply random numbers while
  keyroost makes an OpenPGP key (other than RSA) or a backup, it now
  reports an error instead of crashing. ([#245])
