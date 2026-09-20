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
# AppStream metainfo — the same file the Flatpak build uses. Bundling it into the
# AppDir gives the AppImage proper software-centre metadata, a prerequisite for
# AppImageHub listing (#53).
METAINFO_FILE="${REPO_ROOT}/packaging/flatpak/${APP_ID}.metainfo.xml"
BUILD_DIR="${REPO_ROOT}/target/appimage"
APPDIR="${BUILD_DIR}/AppDir"
# App version for the AppImage metadata (#98): appimagetool picks up $VERSION
# and embeds it into the bundled desktop file as X-AppImage-Version, which is
# what AppImage managers (Gear Lever et al.) display. Without it the installed
# AppImage shows no version at all. Parsed from the workspace Cargo.toml the
# same way ../flatpak/gen-metainfo-releases.py does: the only line-anchored
# `version = "X.Y.Z"` in that file is [workspace.package].
VERSION="$(sed -nE 's/^version = "([0-9]+\.[0-9]+\.[0-9]+)"$/\1/p' "${REPO_ROOT}/Cargo.toml" | head -n1)"
[ -n "${VERSION}" ] || { echo "ERROR: no version = \"X.Y.Z\" line in ${REPO_ROOT}/Cargo.toml"; exit 1; }
export VERSION

# ---------------------------------------------------------------------------
# 1. Build the GUI binary (glibc, release). The CLI is intentionally NOT shipped
#    as an AppImage — use the musl static CLI (../musl/) or the release tarball.
# ---------------------------------------------------------------------------
echo ">> building keyroost (GUI) release binary"
( cd "${REPO_ROOT}" && cargo build --release -p keyroost --features keyroost/qr )
BIN="${REPO_ROOT}/target/release/keyroost"
[ -x "${BIN}" ] || { echo "ERROR: ${BIN} not built"; exit 1; }

# ---------------------------------------------------------------------------
# 2. Fetch linuxdeploy + its appimage plugin. Upstream publishes only the
#    rolling `continuous` release, so we pin by CONTENT: the sha256 below is
#    resolved from the release asset's recorded digest and re-verified on
#    every build. A changed upstream binary fails the build closed rather
#    than silently shipping unreviewed code into an official AppImage.
#
#    When it does fail closed, that is the control working — do NOT paste in
#    whatever hash the build just computed, which would verify the artifact
#    against itself. Re-resolve from the release asset's recorded digest
#    (`gh api repos/linuxdeploy/linuxdeploy/releases/tags/continuous`), then
#    confirm the bytes actually served hash to that same value before pinning.
#    Pins last moved 2026-09-20, after upstream rebuilt both tools on
#    2026-09-01 from the SAME commits as the prior pin (linuxdeploy 07333c6,
#    plugin 536b0687). AppImage builds are not byte-reproducible, so the
#    rebuild alone changed both digests with no source change; recorded and
#    computed digests agreed for both.
# ---------------------------------------------------------------------------
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"
LD_BASE="https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous"
LDP_BASE="https://github.com/linuxdeploy/linuxdeploy-plugin-appimage/releases/download/continuous"
# pinned-verified: sha256 checked below before chmod +x / execution
LD_SHA256="36a2d7e274d12e1050d0e9ecfe11d339ed54720b2bec464c286d53f8b07f5c62"
# pinned-verified: sha256 checked below before chmod +x / execution
LDP_SHA256="0441769ab38009504d2678c38cd7e526955388dd30a215b4a20afaa5471652f2"
fetch() { # url dest sha256
  [ -f "$2" ] || curl -fsSL -o "$2" "$1"
  echo "$3  $2" | sha256sum -c -
  chmod +x "$2"
}
fetch "${LD_BASE}/linuxdeploy-x86_64.AppImage"                  linuxdeploy.AppImage                 "${LD_SHA256}"
fetch "${LDP_BASE}/linuxdeploy-plugin-appimage-x86_64.AppImage" linuxdeploy-plugin-appimage.AppImage "${LDP_SHA256}"

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
#    this AppImage. Step 3b-2 below wraps the launcher so that failure is a clear,
#    actionable message rather than a cryptic linker error, but the app still
#    can't run without the library. The real fix — dlopen pcsc at runtime and
#    degrade gracefully when it is absent — is tracked in TODO.md; it
#    removes this limitation and fixes the mismatch for every channel, not just
#    the AppImage.
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

# 3b-2. Wrap the generated AppRun with a libpcsclite preflight. keyroost
#       hard-links libpcsclite, so on a host without it this AppImage aborts at
#       the dynamic linker before main with a cryptic error. The preflight turns
#       that into an actionable "install pcscd" message; when libpcsclite IS
#       present it hands off to the real (linuxdeploy) launcher unchanged.
#       Stopgap until PC/SC is dlopen'd and degrades gracefully (issue #47).
echo ">> installing libpcsclite preflight launcher"
[ -f "${APPDIR}/AppRun" ] || { echo "ERROR: linuxdeploy produced no AppRun"; exit 1; }
mv "${APPDIR}/AppRun" "${APPDIR}/AppRun.real"
install -m755 "${REPO_ROOT}/packaging/appimage/AppRun.preflight" "${APPDIR}/AppRun"

# 3c. Bundle the AppStream metainfo (software-centre / AppImageHub metadata, #53),
#     then package. UPDATE_INFORMATION makes the plugin embed gh-releases zsync
#     update info and emit keyroost-x86_64.AppImage.zsync, so AppImageUpdate can
#     do delta updates from each GitHub release.
[ -f "${METAINFO_FILE}" ] || { echo "ERROR: missing ${METAINFO_FILE}"; exit 1; }
# Fill the AppStream <releases> block from CHANGELOG.md first — the committed
# block is intentionally empty (single source of truth; #80). Requires
# python3, present on the CI runners and any dev box that builds bundles.
python3 "${REPO_ROOT}/packaging/flatpak/gen-metainfo-releases.py"
install -Dm644 "${METAINFO_FILE}" "${APPDIR}/usr/share/metainfo/$(basename "${METAINFO_FILE}")"
export UPDATE_INFORMATION="gh-releases-zsync|framefilter|keyroost|latest|keyroost-*x86_64.AppImage.zsync"
# With $VERSION set (see Config above), appimagetool would also splice the
# version into its autogenerated file name — but the name must STAY
# version-less: release-asset URLs and the zsync update glob above rely on a
# stable `keyroost-x86_64.AppImage`. Pin the output name explicitly so the
# version lives only in the desktop-file metadata.
export LDAI_OUTPUT="keyroost-x86_64.AppImage"
./linuxdeploy-plugin-appimage.AppImage --appdir "${APPDIR}"

# ---------------------------------------------------------------------------
# 4. Result: keyroost-x86_64.AppImage (+ .zsync for AppImageUpdate) in
#    ${BUILD_DIR}. The Linux-bundles workflow attaches both to the release.
# ---------------------------------------------------------------------------
echo ">> done. AppImage + zsync:"
ls -la "${BUILD_DIR}"/*.AppImage "${BUILD_DIR}"/*.AppImage.zsync 2>/dev/null || true
