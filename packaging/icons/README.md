# keyroost app icon

The shipped app icon — the **dark-on-amber** `k` monogram (IBM Plex Sans Bold,
outlined, no font dependency), built to the freedesktop icon spec.

```
io.github.framefilter.keyroost.svg        scalable master (vector)
io.github.framefilter.keyroost-256.png    256px raster (AppImage --icon-file)
hicolor/<size>/apps/io.github.framefilter.keyroost.png   16…1024px PNGs
hicolor/scalable/apps/io.github.framefilter.keyroost.svg scalable
```

The Flatpak manifest installs the whole `hicolor/` tree into
`${FLATPAK_DEST}/share/icons/hicolor/`; the AppImage build passes the 256px PNG
to `linuxdeploy --icon-file`. The filename stem **must** stay the app-id
`io.github.framefilter.keyroost` (Flatpak / AppStream / desktop-file icon
resolution keys on it).

The **alternate colorway** — amber-on-dark (amber glyph on the dark surface,
matching the in-app title-bar mark) — is kept for reference in
[`docs/app_icons/`](../../docs/app_icons/) along with the original design bundle.
To switch colorways, replace these files from that set.

For the auto-update Flatpak remote, also place a copy of the SVG in the **root**
of the `framefilter/keyroost-flatpak` repo as `keyroost-icon.svg` (see
[`../LINUX-BUNDLES.md`](../LINUX-BUNDLES.md), setup step 3).

## Who references these paths

- `packaging/flatpak/io.github.framefilter.keyroost.yml` — installs the hicolor tree.
- `packaging/appimage/build-appimage.sh` — passes the 256px PNG to `linuxdeploy`.
- `packaging/flatpak/io.github.framefilter.keyroost.desktop` — `Icon=` key.
- `packaging/flatpak/io.github.framefilter.keyroost.metainfo.xml` — AppStream
  resolves the icon by app-id from the installed hicolor theme.
