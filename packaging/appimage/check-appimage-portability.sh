#!/usr/bin/env bash
#
# check-appimage-portability.sh — fail when the AppImage wouldn't run on an
# older or stripped-down Linux, so a catalog test (AppImageHub tests on its
# own systems; AppImage/appimage.github.io#9258) or a user hits it after a
# release instead of the packaging probe hitting it before.
#
#   1. glibc: no ELF file inside the AppImage may need a glibc newer than
#      MAX_GLIBC (default 2.35, Ubuntu 22.04's, the build image). An
#      AppImage runs only where the glibc is at least what it was built
#      against.
#   2. Start: the AppImage must start and keep running for START_SECONDS
#      (default 15) under a virtual display in a bare Ubuntu 22.04 container
#      that has what every X11 desktop has (graphics drivers, the standard X
#      client libraries) but no libpcsclite, no libxkbcommon and no
#      smart-card service. A missing library or a crash at start fails it.
#      Skipped, with a notice, when no `docker` is available (local runs).
#
# Usage: packaging/appimage/check-appimage-portability.sh <file.AppImage>

set -euo pipefail

img="${1:?usage: $0 <file.AppImage>}"
max_glibc="${MAX_GLIBC:-2.35}"
start_seconds="${START_SECONDS:-15}"
# Ubuntu 22.04, pinned by digest (an image index; the runner pulls amd64).
image="ubuntu@sha256:e0f80c829509ef4df9e76bd8944eb7b8ec25cbb379b112a7f9448b2c77a77c9b"

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
img_abs="$(realpath "${img}")"
(cd "${work}" && "${img_abs}" --appimage-extract >/dev/null)
root="${work}/squashfs-root"
[ -x "${root}/AppRun" ] || { echo "::error::${img} has no AppRun after extraction"; exit 1; }

# --- 1. glibc --------------------------------------------------------------
bad=0
checked=0
while IFS= read -r -d '' f; do
  file -b "${f}" | grep -q '^ELF' || continue
  checked=$((checked + 1))
  need="$(objdump -T "${f}" 2>/dev/null | grep -o 'GLIBC_[0-9.]*' | sed 's/^GLIBC_//' | sort -uV | tail -1 || true)"
  [ -n "${need}" ] || continue
  newest="$(printf '%s\n%s\n' "${need}" "${max_glibc}" | sort -V | tail -1)"
  if [ "${newest}" != "${max_glibc}" ]; then
    echo "::error::${f#"${root}"/} needs glibc ${need}, newer than ${max_glibc}"
    bad=1
  fi
done < <(find "${root}" -type f -print0)
[ "${bad}" -eq 0 ] || exit 1
echo "glibc: ${checked} ELF files need at most glibc ${max_glibc}"

# --- 2. start in a stripped-down system -------------------------------------
if ! command -v docker >/dev/null 2>&1; then
  echo "start: skipped (no docker here; CI runs it)"
  exit 0
fi
docker run --rm -e START_SECONDS="${start_seconds}" -v "${root}:/app:ro" "${image}" bash -c '
  set -e
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  # What every X11 desktop has (a display, software OpenGL, the standard X
  # client libraries the window layer loads at runtime) and nothing else:
  # no libpcsclite, no libxkbcommon, no pcscd. What the AppImage needs
  # beyond this it must bring itself (it bundles libxkbcommon(-x11)).
  apt-get install -y -qq --no-install-recommends \
    xvfb xauth libgl1 libegl1 libgl1-mesa-dri libegl-mesa0 \
    libx11-6 libx11-xcb1 libxcb1 libxcursor1 libxi6 libxrender1 libxrandr2 \
    >/dev/null
  for p in libpcsclite1 libxkbcommon0 pcscd; do
    if dpkg -s "$p" >/dev/null 2>&1; then
      echo "::warning::$p came in with the display packages; the start test is less strict"
    fi
  done
  set +e
  xvfb-run -a timeout "$START_SECONDS" /app/AppRun >/tmp/out 2>&1
  rc=$?
  tail -n 40 /tmp/out
  if [ "$rc" -eq 124 ]; then
    echo "start: the AppImage started and kept running for ${START_SECONDS}s"
    exit 0
  fi
  echo "::error::the AppImage exited (status $rc) within ${START_SECONDS}s on a bare Ubuntu 22.04"
  exit 1
'
