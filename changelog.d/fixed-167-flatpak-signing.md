- **Flatpak updates no longer fail on unsigned metadata.** The published
  repository's AppStream and `.Debug` refs went out unsigned, so Flatpak
  clients that verify them refused the metadata refresh. Every ref is now
  signed, and publishing stops if one isn't. ([#167])
