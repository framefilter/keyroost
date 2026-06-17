#!/usr/bin/env python3
"""Generate crates/keyroost/assets/mds_data.json from the live FIDO MDS3 BLOB.

The BLOB is a public JWS at https://mds3.fidoalliance.org/ (no auth token). This
script downloads it over HTTPS, base64url-decodes the JWS *payload* (it does NOT
verify the signature — keyroost treats the bundled file as trusted build input),
and writes a slimmed projection: per AAGUID only description, icon, and the
latest status report. That keeps the embedded asset small.

Usage:
    python3 tools/gen_mds_data.py                # target vendors only (default)
    python3 tools/gen_mds_data.py --all          # every FIDO2 entry
    python3 tools/gen_mds_data.py --no-icons     # omit icons (smaller file)
    python3 tools/gen_mds_data.py --blob file.jwt  # use a local BLOB instead

Run it periodically (the FIDO Alliance suggests ~monthly).

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
import sys
import urllib.error
import urllib.request

MDS_URL = "https://mds3.fidoalliance.org/"
OUT = "crates/keyroost/assets/mds_data.json"

# Substrings (case-insensitive) matched against the statement description to keep
# the bundled file focused on the hardware keys keyroost targets. Edit freely.
TARGET_VENDORS = [
    "token2", "yubico", "yubikey", "feitian", "nitrokey",
    "solokey", "somu", "google titan", "onlykey",
]


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
    ap.add_argument("--no-icons", action="store_true", help="omit icon data URIs")
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

    out = []
    for e in entries:
        aaguid = e.get("aaguid")
        if not aaguid:
            continue  # U2F/UAF entries have no AAGUID
        stmt = e.get("metadataStatement", {}) or {}
        desc = stmt.get("description", "") or ""
        if not args.all:
            if not any(v in desc.lower() for v in TARGET_VENDORS):
                continue
        st = latest_status(e)
        get_info = stmt.get("authenticatorGetInfo", {}) or {}
        out.append({
            "aaguid": aaguid.lower(),
            "description": desc,
            "icon": None if args.no_icons else stmt.get("icon"),
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
