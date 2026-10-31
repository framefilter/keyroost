- **Building from source needs Rust 1.89** (was 1.87) for the libraries
  and the CLI; the app still needs 1.92. Packaged builds are unaffected.
  The crypto libraries keyroost uses moved to their current generation
  together (AES, SHA-2, HMAC, AES-GCM, PBKDF2, scrypt, 3DES, RC2, the OS
  random source, Ed25519 and X25519), and they now raise their own
  minimum Rust in patch releases. Nothing changes in how keyroost
  behaves; a failing OS random source while making an OpenPGP key or
  backup is now an error instead of a crash. ([#245])
