#!/usr/bin/env python3
"""Generate crates/keyroost/assets/mds_data.json from the live FIDO MDS3 BLOB.

The BLOB is a public JWS at https://mds3.fidoalliance.org/ (no auth token). This
script downloads it over HTTPS, base64url-decodes the JWS *payload* (it does NOT
verify the signature — keyroost treats the bundled file as trusted build input),
and writes a slimmed projection: per AAGUID only description, icon, and the
latest status report. That keeps the embedded asset small.

Usage:
    python3 tools/gen_mds_data.py                # hardware authenticators (default)
    python3 tools/gen_mds_data.py --all          # every FIDO2 entry
    python3 tools/gen_mds_data.py --include-software  # keep software/platform ones
    python3 tools/gen_mds_data.py --filter yubi token2  # extra name filter
    python3 tools/gen_mds_data.py --vendor-filter    # legacy name whitelist
    python3 tools/gen_mds_data.py --no-icons     # omit icons (smaller file)
    python3 tools/gen_mds_data.py --blob file.jwt  # use a local BLOB instead

Run it periodically (the FIDO Alliance suggests ~monthly).

Icon normalisation (optional dependencies: Pillow always, resvg_py when the
BLOB carries SVG icons): SVG data-URIs are rendered to PNG, and every icon is
downscaled so its longest edge is at most --icon-max-px (default 88). The GUI
draws the icon at 44x44 points, so 88 px covers a 200% display scaling exactly
(44 x 2 = 88); icons that already fit are kept byte-for-byte. The GUI decodes
PNG only, so without this step the SVG-only vendors would show no logo at all.

The output (crates/keyroost/assets/mds_data.json) is embedded at build time, but
the app ALSO loads a user-supplied copy at runtime if present, so distributed
binaries (AppImage / .exe / .dmg) can be updated WITHOUT rebuilding. Drop the
regenerated file at one of:
  * $KEYROOST_MDS_FILE                              (explicit override)
  * ~/.config/keyroost/mds_data.json               (Linux; or $XDG_CONFIG_HOME)
  * ~/Library/Application Support/keyroost/mds_data.json   (macOS)
  * %APPDATA%\\keyroost\\mds_data.json                     (Windows)
  * mds_data.json next to the executable           (portable installs)
"""
import argparse
import base64
import json
import re
import sys
import urllib.error
import urllib.request

MDS_URL = "https://mds3.fidoalliance.org/"
OUT = "crates/keyroost/assets/mds_data.json"

# Optional vendor whitelist (--vendor-filter). Kept for backwards compatibility;
# the default selection is device-based (see is_hardware_authenticator) so that
# any hardware key is included, not only the vendors listed here.
TARGET_VENDORS = [
    "token2", "yubico", "yubikey", "feitian", "nitrokey",
    "solokey", "somu", "google titan", "onlykey",
]


def is_hardware_authenticator(stmt: dict) -> bool:
    """Match the device, not the vendor name.

    MDS3 metadata carries ``keyProtection``: hardware keys list "hardware"
    (often also "secure_element"), while software/platform passkey providers
    list "software" only. Dropping the software-only entries keeps the bundle
    to physical authenticators without naming any vendor.

    Some USB security keys (for example Nitrokey 3 AM) still declare
    ``keyProtection: ["software"]``.  ``attachmentHint`` tells us they are
    roaming authenticators, so keep those as well whatever the keyProtection
    claim says.
    """
    hint = stmt.get("attachmentHint")
    if isinstance(hint, int) and hint & 0x02:  # external
        return True
    if isinstance(hint, str) and "external" in hint.lower():
        return True
    if isinstance(hint, (list, tuple)) and any(str(h).lower() == "external" for h in hint):
        return True
    kp = stmt.get("keyProtection") or []
    if not kp:
        return True  # no claim either way: keep it
    return "hardware" in kp or "software" not in kp


# --- icon normalisation ------------------------------------------------------
#
# The MDS icons are a mix of PNG data-URIs and (for a few dozen vendors) SVG
# data-URIs. The GUI decodes PNG only, so SVG entries currently show no icon at
# all, and vendor PNGs can be far larger than the 20-24 px they are drawn at.
# Same treatment as LibreKey Companion's bundler: render SVG to PNG, then cap the
# longest edge. Icons that already fit are kept byte-for-byte.

MAX_ICON_PX = 88


def _render_svg(svg_text: str, max_px: int) -> bytes:
    import resvg_py

    svg_text = re.sub(r'(<svg\b[^>]*?)\s+width="[^"]*"', r"\1", svg_text, count=1)
    svg_text = re.sub(r'(<svg\b[^>]*?)\s+height="[^"]*"', r"\1", svg_text, count=1)
    m = re.search(r'viewBox\s*=\s*"([\d.\s+-]+)"', svg_text, re.I)
    vw = vh = None
    if m:
        parts = m.group(1).split()
        if len(parts) == 4:
            vw, vh = float(parts[2]), float(parts[3])
    if vw and vh:
        s = max_px / max(vw, vh, 1)
        svg_text = svg_text.replace(
            "<svg",
            '<svg width="%d" height="%d" ' % (max(1, round(vw * s)), max(1, round(vh * s))),
            1,
        )
    out = resvg_py.svg_to_bytes(svg_string=svg_text)
    return bytes(out) if isinstance(out, list) else out


PNG_SIG = b"\x89PNG\r\n\x1a\n"


def process_icon(uri: str, max_px: int) -> bytes:
    """Render SVG data-URIs to PNG, convert non-PNG payloads, downscale large icons."""
    import io

    from PIL import Image

    payload = uri.split(",", 1)[1]
    raw = base64.b64decode(payload + "=" * (-len(payload) % 4))
    if uri.startswith("data:image/svg"):
        raw = _render_svg(raw.decode("utf-8", "ignore"), max_px)
        img = Image.open(io.BytesIO(raw))
        w, h = img.size
        scale = min(1.0, max_px / max(w, h))
        if scale < 1.0:
            img = img.resize((max(1, round(w * scale)), max(1, round(h * scale))), Image.LANCZOS)
        out = io.BytesIO()
        img.convert("RGBA").save(out, "PNG", optimize=True)
        return out.getvalue()
    img = Image.open(io.BytesIO(raw))
    w, h = img.size
    is_png = raw.startswith(PNG_SIG)
    if is_png and max(w, h) <= max_px:
        return raw  # already PNG and fits: keep the vendor bytes untouched
    # Some entries carry JPEG bytes behind a data:image/png URI. Re-encode those
    # so keyroost's PNG-only decoder can read every bundled icon.
    img = img.convert("RGBA")
    scale = min(1.0, max_px / max(w, h))
    if scale < 1.0:
        img = img.resize((max(1, round(w * scale)), max(1, round(h * scale))), Image.LANCZOS)
    out = io.BytesIO()
    img.save(out, "PNG", optimize=True)
    return out.getvalue()


def b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def fetch_blob(url: str) -> str:
    """Download the MDS BLOB with retries. The endpoint rate-limits and tends to
    reject the default urllib User-Agent, so send a browser-like UA and back off
    on HTTP 429."""
    import time
    headers = {
        "User-Agent": "Mozilla/5.0 (keyroost gen_mds_data)",
        "Accept": "*/*",
    }
    last_err = None
    for attempt in range(4):
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.read().decode("ascii").strip()
        except urllib.error.HTTPError as e:
            last_err = e
            if e.code == 429:
                wait = 10 * (attempt + 1)
                print(
                    f"  rate-limited (429); waiting {wait}s before retry "
                    f"{attempt + 2}/4 ...",
                    file=sys.stderr,
                )
                time.sleep(wait)
                continue
            raise
    # Out of retries.
    raise SystemExit(
        "error: the FIDO endpoint kept returning HTTP 429 (Too Many Requests).\n"
        "The BLOB changes rarely, so download it once by hand and pass it in:\n"
        "    # PowerShell\n"
        '    Invoke-WebRequest -Uri "https://mds3.fidoalliance.org/" -OutFile mds.jwt\n'
        "    python tools/gen_mds_data.py --all --blob mds.jwt\n"
        f"(last error: {last_err})"
    )


CERT_RANK = {
    "FIDO_CERTIFIED": 1,
    "FIDO_CERTIFIED_L1": 2,
    "FIDO_CERTIFIED_L1plus": 3,
    "FIDO_CERTIFIED_L2": 4,
    "FIDO_CERTIFIED_L2plus": 5,
    "FIDO_CERTIFIED_L3": 6,
    "FIDO_CERTIFIED_L3plus": 7,
}
ADVISORY = {
    "USER_VERIFICATION_BYPASS", "ATTESTATION_KEY_COMPROMISE",
    "USER_KEY_REMOTE_COMPROMISE", "USER_KEY_PHYSICAL_COMPROMISE", "REVOKED",
}


def latest_status(entry: dict):
    """Pick the status report to display. An advisory (revoked/compromised) wins
    if present, since it's safety-critical. Otherwise the highest certification
    level the authenticator has earned, regardless of report order — FIDO often
    lists FIDO_CERTIFIED first and the leveled status (e.g. _L2) in a later
    report, so 'last report' alone can miss the real level."""
    reports = entry.get("statusReports") or []
    advisory = [r for r in reports if r.get("status") in ADVISORY]
    if advisory:
        return advisory[-1]
    certs = [r for r in reports if r.get("status") in CERT_RANK]
    if certs:
        return max(certs, key=lambda r: CERT_RANK[r["status"]])
    # Fall back to the last report carrying any status.
    for r in reversed(reports):
        if r.get("status"):
            return r
    return {}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true", help="keep every FIDO2 entry")
    ap.add_argument("--include-software", action="store_true",
                    help="keep software/platform authenticators (default: dropped)")
    ap.add_argument("--filter", nargs="*", default=None,
                    help="only keep authenticators whose description contains any of these")
    ap.add_argument("--vendor-filter", action="store_true",
                    help="use the legacy TARGET_VENDORS description whitelist")
    ap.add_argument("--no-icons", action="store_true", help="omit icon data URIs")
    ap.add_argument("--icon-max-px", type=int, default=MAX_ICON_PX,
                    help=f"cap the icon's longest edge (default {MAX_ICON_PX}; 0 keeps icons as-is)")
    ap.add_argument("--blob", help="path to a local BLOB (.jwt) instead of downloading")
    ap.add_argument("--out", default=OUT)
    args = ap.parse_args()

    if args.blob:
        jwt = open(args.blob, "r", encoding="utf-8").read().strip()
    else:
        print(f"downloading {MDS_URL} ...", file=sys.stderr)
        jwt = fetch_blob(MDS_URL)

    try:
        payload_seg = jwt.split(".")[1]
    except IndexError:
        print("error: BLOB is not a JWS (no payload segment)", file=sys.stderr)
        return 1
    payload = json.loads(b64url_decode(payload_seg))
    entries = payload.get("entries", [])
    print(f"BLOB has {len(entries)} entries", file=sys.stderr)

    # Icon processing is the only part of this script that needs third-party
    # packages, and they stay optional: without Pillow the icons are embedded as
    # they are, without resvg_py the SVG-only ones are left alone (the GUI cannot
    # render SVG, so those vendors keep showing no logo). One warning, no failure.
    skip_svg = False
    if not args.no_icons and args.icon_max_px > 0:
        import importlib.util

        if importlib.util.find_spec("PIL") is None:
            print("warning: Pillow is not installed, icons are embedded as-is "
                  "(pip install pillow)", file=sys.stderr)
            args.icon_max_px = 0
        elif importlib.util.find_spec("resvg_py") is None:
            svg = sum(1 for e in entries
                      if ((e.get("metadataStatement") or {}).get("icon") or "").startswith("data:image/svg"))
            if svg:
                print(f"warning: resvg_py is not installed, {svg} SVG icon(s) left as-is "
                      f"(pip install resvg-py)", file=sys.stderr)
                skip_svg = True

    out = []
    for e in entries:
        aaguid = e.get("aaguid")
        if not aaguid:
            continue  # U2F/UAF entries have no AAGUID
        stmt = e.get("metadataStatement", {}) or {}
        desc = stmt.get("description", "") or ""
        if not args.all:
            desc_l = desc.lower()
            if args.vendor_filter and not any(v in desc_l for v in TARGET_VENDORS):
                continue
            if args.filter and not any(f.lower() in desc_l for f in args.filter):
                continue
            if not args.include_software and not is_hardware_authenticator(stmt):
                continue
        st = latest_status(e)
        get_info = stmt.get("authenticatorGetInfo", {}) or {}
        icon = None
        if not args.no_icons:
            icon = stmt.get("icon")
            if icon and skip_svg and icon.startswith("data:image/svg"):
                pass  # no SVG renderer available; keep the vendor bytes
            elif icon and args.icon_max_px > 0:
                try:
                    png = process_icon(icon, args.icon_max_px)
                    icon = "data:image/png;base64," + base64.b64encode(png).decode()
                except Exception as ex:  # noqa: BLE001
                    # Leave the vendor bytes untouched rather than dropping the icon.
                    print(f"  ! icon kept as-is for {desc[:44]}: {ex}", file=sys.stderr)
        out.append({
            "aaguid": aaguid.lower(),
            "description": desc,
            "icon": icon,
            "status": st.get("status"),
            "certificateNumber": st.get("certificateNumber"),
            "effectiveDate": st.get("effectiveDate"),
            "authenticatorVersion": stmt.get("authenticatorVersion"),
            "protocolFamily": stmt.get("protocolFamily"),
            "versions": get_info.get("versions"),
        })

    out.sort(key=lambda r: r["description"].lower())
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"wrote {len(out)} entries to {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
