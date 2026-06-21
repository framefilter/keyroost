#!/usr/bin/env bash
#
# build-appimage.sh — DRAFT. Build a keyroost (GUI) AppImage. NOT wired into CI.
# See ../LINUX-BUNDLES.md for the full design, caveats, and open decisions.
#
# What this produces: a single self-contained `keyroost-x86_64.AppImage` bundling
# the GUI binary plus its shared libraries (incl. libpcsclite — see PC/SC note).
#
# PORTABILITY: build this on the OLDEST glibc you intend to support (e.g. inside
# an old Ubuntu LTS container). An AppImage built on a new glibc only runs on
# systems with glibc >= the build host's. This is the classic AppImage footgun.
#
# RUNTIME (user side):
#   * FIDO HID needs the host udev rules (udev/70-keyroost-fido.rules) for
#     non-root /dev/hidraw access — the AppImage cannot install them itself.
#   * Smart-card applets need a running HOST pcscd AND the host's libpcsclite:
#     the AppImage deliberately does NOT bundle the pcsc-lite client (see step 3
#     for why), so the host must provide libpcsclite.so.1 — which it does
#     wherever pcscd is installed.
#   * AppImages mount via FUSE. On FUSE3-only distros users may need libfuse2,
#     or can run with:  ./keyroost-x86_64.AppImage --appimage-extract-and-run
#     (TODO(maintainer): pin the appimagetool/runtime version and state the
#      exact FUSE2-vs-FUSE3 story for it — this changed recently.)

set -euo pipefail

# ---------------------------------------------------------------------------
# Config (app-id + icon path match the Flatpak manifest so metadata stays
# consistent across targets).
# ---------------------------------------------------------------------------
APP_ID="io.github.framefilter.keyroost"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DESKTOP_FILE="${REPO_ROOT}/packaging/flatpak/${APP_ID}.desktop"
# Icon: the dark-on-amber 256px raster (linuxdeploy prefers a PNG); the full
# hicolor tree + SVG master live alongside it in packaging/icons/.
# Must be named exactly after the desktop Icon= entry (no size suffix), or
# linuxdeploy reports "Could not find suitable icon". Use the hicolor 256px PNG.
ICON_FILE="${REPO_ROOT}/packaging/icons/hicolor/256x256/apps/${APP_ID}.png"
BUILD_DIR="${REPO_ROOT}/target/appimage"
APPDIR="${BUILD_DIR}/AppDir"

# ---------------------------------------------------------------------------
# 1. Build the GUI binary (glibc, release). The CLI is intentionally NOT shipped
#    as an AppImage — use the musl static CLI (../musl/) or the release tarball.
# ---------------------------------------------------------------------------
echo ">> building keyroost (GUI) release binary"
( cd "${REPO_ROOT}" && cargo build --release -p keyroost )
BIN="${REPO_ROOT}/target/release/keyroost"
[ -x "${BIN}" ] || { echo "ERROR: ${BIN} not built"; exit 1; }

# ---------------------------------------------------------------------------
# 2. Fetch linuxdeploy + its appimage plugin (continuous builds). These bundle
#    the binary's dependent .so files into the AppDir and emit the AppImage.
#    TODO(maintainer): pin specific linuxdeploy/appimagetool releases for
#    reproducibility instead of "continuous".
# ---------------------------------------------------------------------------
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"
LD_BASE="https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous"
LDP_BASE="https://github.com/linuxdeploy/linuxdeploy-plugin-appimage/releases/download/continuous"
fetch() { [ -f "$2" ] || curl -fsSL -o "$2" "$1"; chmod +x "$2"; }
fetch "${LD_BASE}/linuxdeploy-x86_64.AppImage"                    linuxdeploy.AppImage
fetch "${LDP_BASE}/linuxdeploy-plugin-appimage-x86_64.AppImage"   linuxdeploy-plugin-appimage.AppImage

# In CI/containers without FUSE, run the tools extracted:
export APPIMAGE_EXTRACT_AND_RUN=1

# ---------------------------------------------------------------------------
# 3. Stage the AppDir, then DROP the bundled libpcsclite so the host's is used.
#
#    Why not bundle it: libpcsclite is the PC/SC *client*, and it speaks a
#    version-sensitive private protocol to the host's pcscd *daemon*. A client
#    built on one machine can mismatch a user's daemon, which silently breaks
#    every PC/SC feature (serial, OATH/OpenPGP/PIV, the serial-keyed friendly
#    name) while FIDO over USB-HID keeps working — issue #47. The only client
#    guaranteed to match a host's pcscd is that host's OWN libpcsclite (same
#    package), so we delete the auto-bundled copy and let the dynamic linker
#    resolve it from the system at runtime — same as the cargo/Homebrew builds,
#    which work on hosts where the bundling AppImage did not.
#
#    KNOWN LIMITATION: keyroost hard-links libpcsclite, so this AppImage needs
#    libpcsclite.so.1 present on the host to LAUNCH at all. Any host set up for
#    PC/SC has it (it ships with pcscd); a pure-FIDO host without it cannot start
#    this AppImage. The real fix — dlopen pcsc at runtime and degrade gracefully
#    when it is absent — is tracked in TODO-v0.7.5.md; it removes this limitation
#    and fixes the mismatch for every channel, not just the AppImage.
#
#    Mechanics: deploy WITHOUT --output, delete the auto-bundled libpcsclite,
#    then package with the appimage plugin directly. (Re-running linuxdeploy with
#    --output would just re-bundle it, so packaging is a separate step.)
# ---------------------------------------------------------------------------
rm -rf "${APPDIR}"
mkdir -p "${APPDIR}"

[ -f "${DESKTOP_FILE}" ] || { echo "ERROR: missing ${DESKTOP_FILE}"; exit 1; }
[ -f "${ICON_FILE}" ] || {
  echo "ERROR: no icon at ${ICON_FILE} — supply one (see ../icons/README.md)"; exit 1; }

# 3a. Deploy: populate the AppDir + its libraries. No --output yet.
./linuxdeploy.AppImage \
    --appdir "${APPDIR}" \
    --executable "${BIN}" \
    --desktop-file "${DESKTOP_FILE}" \
    --icon-file "${ICON_FILE}"

# 3b. Drop the auto-bundled libpcsclite so the host's copy (which matches its
#     own pcscd) is used at runtime (issue #47 — see the rationale above).
echo ">> dropping bundled libpcsclite (use the host's, which matches its pcscd)"
find "${APPDIR}" -name 'libpcsclite.so*' -delete

# 3c. Package the prepared AppDir into the AppImage (no re-deploy).
./linuxdeploy-plugin-appimage.AppImage --appdir "${APPDIR}"

# ---------------------------------------------------------------------------
# 4. Result: keyroost-x86_64.AppImage in ${BUILD_DIR}. Attach it to a GitHub
#    Release as an asset (manually for now — this script is NOT called by
#    release.yml in these drafts).
#    Optional: pass --output appimage with OUTPUT=... and generate a .zsync for
#    delta auto-updates via AppImageUpdate.
# ---------------------------------------------------------------------------
echo ">> done. AppImage(s):"
ls -la "${BUILD_DIR}"/*.AppImage 2>/dev/null || true
