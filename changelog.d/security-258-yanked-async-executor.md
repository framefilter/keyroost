- **Two dependency fixes in the shipped lockfile.** `async-executor` moves
  to 1.14.1: 1.14.0, which v0.16.0 shipped, was yanked for a use-after-free
  when the executor is dropped. keyroost reaches it only through the
  app's QR screen capture on Linux (through `ashpd`/`zbus`), which the
  release binaries and the AppImage include; the Flatpak, Windows and
  macOS builds don't. `rustix` moves to 1.1.6, which clears
  RUSTSEC-2026-0486 (extended-attribute calls). keyroost behaves the same.
  ([#258])
