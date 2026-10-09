#!/usr/bin/env bash
#
# verify-appimage-signature.sh — check a keyroost AppImage's embedded GPG
# signature against the PUBLISHED key, not against the key the file carries.
#
#   bash packaging/appimage/verify-appimage-signature.sh keyroost-x86_64.AppImage
#
# linux-bundles.yml runs this as a guard before the AppImage is attested or
# uploaded (with --require-zsync), and anyone can run it on a download from a
# checkout of the matching release tag.
#
# What it checks (any failure exits non-zero):
#   1. The .sha256_sig and .sig_key ELF sections exist and hold ASCII-armored
#      PGP data (an unsigned AppImage has them all zeros).
#   2. The embedded public key's fingerprint equals the committed key's
#      (packaging/appimage/keyroost-appimage-signing.asc by default).
#   3. The signature verifies, in a throwaway GnuPG home holding ONLY the
#      committed key, over the SHA-256 of the file with both sections zeroed
#      (the AppImage spec's signed data: that digest as a lowercase hex
#      string, no newline). gpg must report VALIDSIG for the pinned key.
#   4. The .upd_info section still holds keyroost's update information.
#   5. If <AppImage>.zsync exists (required with --require-zsync): its SHA-1
#      and Length headers match the file, so the .zsync was written after
#      signing and delta updates will reassemble the signed bytes.
#
# Needs: bash, readelf (binutils), gpg, sha256sum, sha1sum, coreutils.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PUBKEY="${REPO_ROOT}/packaging/appimage/keyroost-appimage-signing.asc"
# Must match UPDATE_INFORMATION in build-appimage.sh.
EXPECTED_UPD_INFO="gh-releases-zsync|framefilter|keyroost|latest|keyroost-*x86_64.AppImage.zsync"
REQUIRE_ZSYNC=0

usage() {
  echo "usage: $0 [--key <public.asc>] [--require-zsync] <file.AppImage>" >&2
  exit 2
}

IMG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --key) [ $# -ge 2 ] || usage; PUBKEY="$2"; shift 2 ;;
    --require-zsync) REQUIRE_ZSYNC=1; shift ;;
    -h|--help) usage ;;
    -*) usage ;;
    *) [ -z "${IMG}" ] || usage; IMG="$1"; shift ;;
  esac
done
[ -n "${IMG}" ] || usage

fail() {
  if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::error::AppImage signature check: $*"; fi
  echo "FAIL: $*" >&2
  exit 1
}

for tool in readelf gpg sha256sum sha1sum dd tr; do
  command -v "${tool}" >/dev/null || fail "${tool} is not installed"
done
[ -f "${IMG}" ] || fail "no such file: ${IMG}"
[ -f "${PUBKEY}" ] || fail "public key not found: ${PUBKEY} (the committed signing key; see packaging/LINUX-BUNDLES.md)"

WORK="$(mktemp -d)"
cleanup() {
  GNUPGHOME="${WORK}/gnupg" gpgconf --kill gpg-agent >/dev/null 2>&1 || true
  rm -rf "${WORK}"
}
trap cleanup EXIT
mkdir -m 700 "${WORK}/gnupg"

# Section offset and size (decimal) by name. readelf -SW prints
# "[Nr] Name Type Address Off Size ...", and "[ 9]" splits into two fields,
# so locate the name and count from there instead of using fixed columns.
section() {
  local line off size
  line="$(readelf -SW "${IMG}" 2>/dev/null \
    | awk -v s="$1" '!r {for (i = 1; i <= NF; i++) if ($i == s) {r = $(i+3) " " $(i+4)}} END {if (r) print r}')"
  [ -n "${line}" ] || return 1
  read -r off size <<<"${line}"
  printf '%d %d\n' "$((16#${off}))" "$((16#${size}))"
}

# Section bytes with the NUL padding removed.
extract() { # name dest
  local off="" size=""
  read -r off size <<<"$(section "$1" || true)"
  [ -n "${off}" ] && [ -n "${size}" ] || fail "section $1 is missing"
  [ "${size}" -gt 0 ] || fail "section $1 has size 0"
  dd if="${IMG}" bs=4096 iflag=skip_bytes,count_bytes skip="${off}" count="${size}" status=none \
    | tr -d '\000' > "$2"
}

# Fingerprint of the single primary key in an armored key file.
fingerprint() {
  local colons count
  colons="$(GNUPGHOME="${WORK}/gnupg" gpg --batch --with-colons --show-keys "$1" 2>/dev/null)" || return 1
  count="$(printf '%s\n' "${colons}" | grep -c '^pub:' || true)"
  [ "${count}" = "1" ] || return 1
  printf '%s\n' "${colons}" | awk -F: '/^pub:/ {p = 1; next} p && !f && /^fpr:/ {f = toupper($10)} END {print f}'
}

# --- 1. Sections present and armored --------------------------------------
section .sha256_sig >/dev/null || fail ".sha256_sig section missing (not an AppImage type 2 runtime?)"
section .sig_key >/dev/null || fail ".sig_key section missing"
extract .sha256_sig "${WORK}/sig.asc"
extract .sig_key "${WORK}/embedded.asc"
[ -s "${WORK}/sig.asc" ] || fail ".sha256_sig is empty: the AppImage is not signed"
[ -s "${WORK}/embedded.asc" ] || fail ".sig_key is empty: the AppImage carries no key"
[ "$(head -n1 "${WORK}/sig.asc")" = "-----BEGIN PGP SIGNATURE-----" ] \
  || fail ".sha256_sig does not hold an armored PGP signature"
[ "$(head -n1 "${WORK}/embedded.asc")" = "-----BEGIN PGP PUBLIC KEY BLOCK-----" ] \
  || fail ".sig_key does not hold an armored PGP public key"

# --- 2. Embedded key == published key -------------------------------------
PINNED="$(fingerprint "${PUBKEY}")" || fail "cannot read exactly one key from ${PUBKEY}"
[ -n "${PINNED}" ] || fail "no fingerprint in ${PUBKEY}"
EMBEDDED="$(fingerprint "${WORK}/embedded.asc")" || fail "cannot read exactly one key from .sig_key"
[ "${EMBEDDED}" = "${PINNED}" ] \
  || fail "embedded key ${EMBEDDED} is not the published key ${PINNED}"

# --- 3. Signature over the zeroed-section digest, published key only ------
cp "${IMG}" "${WORK}/zeroed"
for s in .sha256_sig .sig_key; do
  read -r off size <<<"$(section "${s}" || true)"
  [ -n "${off}" ] && [ -n "${size}" ] || fail "section ${s} is missing"
  dd if=/dev/zero of="${WORK}/zeroed" bs=1 seek="${off}" count="${size}" conv=notrunc status=none
done
digest="$(sha256sum "${WORK}/zeroed" | cut -d' ' -f1)"
rm -f "${WORK}/zeroed"
printf '%s' "${digest}" > "${WORK}/digest.txt"
GNUPGHOME="${WORK}/gnupg" gpg --batch --quiet --import "${PUBKEY}" 2>/dev/null \
  || fail "cannot import ${PUBKEY}"
status="$(GNUPGHOME="${WORK}/gnupg" gpg --batch --status-fd 1 \
  --verify "${WORK}/sig.asc" "${WORK}/digest.txt" 2>/dev/null || true)"
# VALIDSIG <signing-fpr> ... <primary-fpr>: require both to be the pinned key.
validsig="$(printf '%s\n' "${status}" | awk '!v && $1 == "[GNUPG:]" && $2 == "VALIDSIG" {v = toupper($3) " " toupper($NF)} END {print v}')"
[ -n "${validsig}" ] || fail "signature does not verify against ${PUBKEY} (digest ${digest})"
[ "${validsig}" = "${PINNED} ${PINNED}" ] \
  || fail "signature made by ${validsig}, expected ${PINNED}"

# --- 4. Update information unchanged --------------------------------------
extract .upd_info "${WORK}/upd_info"
[ "$(cat "${WORK}/upd_info")" = "${EXPECTED_UPD_INFO}" ] \
  || fail ".upd_info is '$(cat "${WORK}/upd_info")', expected '${EXPECTED_UPD_INFO}'"

# --- 5. .zsync describes the signed bytes ---------------------------------
ZSYNC="${IMG}.zsync"
if [ -f "${ZSYNC}" ]; then
  # The header is text lines up to the first blank line; the block checksums
  # after it are binary.
  header="$(dd if="${ZSYNC}" bs=4096 count=1 status=none | tr -d '\000' | sed -n '1,/^$/p')"
  zsha1="$(printf '%s\n' "${header}" | sed -n 's/^SHA-1: \([0-9a-fA-F]\{40\}\)$/\1/p')"
  zlen="$(printf '%s\n' "${header}" | sed -n 's/^Length: \([0-9]\{1,\}\)$/\1/p')"
  [ -n "${zsha1}" ] || fail "${ZSYNC} has no SHA-1 header"
  fsha1="$(sha1sum "${IMG}" | cut -d' ' -f1)"
  [ "${zsha1,,}" = "${fsha1}" ] \
    || fail "${ZSYNC} SHA-1 ${zsha1} != file SHA-1 ${fsha1} (file changed after zsyncmake)"
  [ "${zlen}" = "$(stat -c %s "${IMG}")" ] || fail "${ZSYNC} Length ${zlen} != file size"
  zsync_note="; .zsync matches"
elif [ "${REQUIRE_ZSYNC}" = "1" ]; then
  fail "${ZSYNC} not found"
else
  zsync_note="; no .zsync next to it (not checked)"
fi

echo "OK: $(basename "${IMG}") is signed by ${PINNED}${zsync_note}"
