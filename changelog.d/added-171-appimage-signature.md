- **The AppImage is GPG-signed.** Each release's AppImage carries an
  embedded signature from a dedicated signing key; its fingerprint is in
  SECURITY.md and the README, which also explain how to check it.
  AppImageUpdate-based updaters (appimageupdatetool, AppImageLauncher)
  now refuse an update signed by a different key. Users updating an
  unsigned AppImage (v0.12.x or earlier) with these tools download this
  release by hand once. ([#171])
