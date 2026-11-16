- **The app's QR screen capture on Linux moves to ashpd 0.14 and zbus 6.**
  zbus 5 used `zvariant`, `zvariant_derive` and `zbus_names`, which are
  no longer maintained (RUSTSEC-2026-0370, -0371, -0372); zbus 6 replaces
  them, and the app's build sheds about 30 crates. It reaches the
  release binaries and the AppImage, which include QR capture; the
  Flatpak, Windows and macOS builds don't use it. Scanning a QR code from
  the screen works as before. ([#264])
