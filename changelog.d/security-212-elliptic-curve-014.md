- **Newer elliptic-curve crates for P-256, P-384 and secp256k1.** The FIDO2
  PIN protocol, Token2 OTP seed encryption, OpenPGP key generation and
  signing, and the PIV self-test now use the RustCrypto elliptic-curve 0.14
  crates, which clears RUSTSEC-2026-0387, a timing-variability advisory for
  crypto-bigint 0.5. keyroost behaves the same. Building the libraries and
  the CLI from source now needs Rust 1.87 or newer (it was 1.85), because
  the fixed crypto-bigint and ctutils require it; the GUI still needs 1.92.
  ([#212])
