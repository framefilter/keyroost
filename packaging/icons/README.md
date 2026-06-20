# Application icon — REQUIRED before a release can produce valid bundles

> **TODO (maintainer): keyroost has no application icon yet.** This is a separate
> design effort. The Flatpak manifest, the AppImage build script, the `.desktop`
> file, and the AppStream metainfo all already reference the paths below. Until
> the assets exist, the `linux-bundles.yml` CI workflow will **fail at the
> icon-install step** — that is intentional (a release without an icon is not a
> valid bundle).

## What to drop in here

Both files must be named after the app-id `io.github.framefilter.keyroost`:

| Path | Purpose |
|---|---|
| `packaging/icons/io.github.framefilter.keyroost.svg` | Scalable source. Installed by Flatpak to `share/icons/hicolor/scalable/apps/`. |
| `packaging/icons/io.github.framefilter.keyroost-256.png` | 256×256 raster. Used by the AppImage (`linuxdeploy` prefers a PNG) and installed by Flatpak to `share/icons/hicolor/256x256/apps/`. |

Optional extra raster sizes (`-128.png`, `-64.png`, …) can be added later; the
build only requires the SVG + the 256px PNG.

## Constraints

- The **filename must match the app-id** exactly
  (`io.github.framefilter.keyroost`) — Flatpak / AppStream / desktop-file icon
  resolution keys on it. If the app-id ever changes, rename these to match.
- Follow the freedesktop icon-naming spec: a square icon with a transparent
  background reads best across light/dark desktop themes.
- Keep the SVG self-contained (no external font/image references) so it renders
  in the OSTree-exported AppStream catalog.

## Who references these paths

- `packaging/flatpak/io.github.framefilter.keyroost.yml` — installs both into
  `${FLATPAK_DEST}/share/icons/hicolor/...`.
- `packaging/appimage/build-appimage.sh` — passes the 256px PNG to
  `linuxdeploy --icon-file`.
- `packaging/flatpak/io.github.framefilter.keyroost.desktop` — `Icon=` key.
- `packaging/flatpak/io.github.framefilter.keyroost.metainfo.xml` — AppStream
  resolves the icon by app-id from the installed hicolor theme.
