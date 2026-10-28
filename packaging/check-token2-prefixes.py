#!/usr/bin/env python3
"""Release pre-flight: is keyroost's copy of Token2's serial prefix table current?

keyroost names a Token2 PIN+ key's firmware release ("R3.4") from the first
five digits of its serial number, using a copy of Token2's published "PIN+
Serial Number Prefix Reference" (TOKEN2_PREFIXES in
crates/keyroost-resolve/src/firmware.rs). Token2 adds rows when it ships a
new model or release; a key whose prefix keyroost's copy lacks shows no
firmware. This fetches Token2's page and compares the two, row by row.

    python3 packaging/check-token2-prefixes.py

Exits 0 when they match. Otherwise prints every prefix added, removed or
given a different release, and exits 1: update TOKEN2_PREFIXES (and its
"updated" date) to match the page, before the version bump. Exits 2 when the
page can't be fetched or its table can't be found (a site redesign): check
the page by hand. Stdlib only. Run from the repository root.

Rows whose prefix cell isn't five digits (a range of whole serials for a
custom card) are not prefixes and are left out on both sides.
"""

import html
import re
import sys
import urllib.request

PAGE = (
    "https://www.token2.com/site/page/"
    "pin-firmware-feature-support-matrix-openpgp-fido2-otp-and-piv-across-releases"
)
SOURCE = "crates/keyroost-resolve/src/firmware.rs"


def page_table(text):
    """{prefix: release} from the page's prefix reference table."""
    table = {}
    for row in re.findall(r"<tr[^>]*>(.*?)</tr>", text, re.S):
        cells = [
            html.unescape(re.sub(r"<[^>]+>", "", c)).strip()
            for c in re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", row, re.S)
        ]
        if len(cells) < 4:
            continue
        # "R3.4 (PIV + OTP Protection)" -> "R3.4"; "Initial (R1)" -> "R1"
        m = re.search(r"\bR\d+(?:\.\d+)?\b", cells[0])
        if not m:
            continue
        prefix = cells[-1]
        if not re.fullmatch(r"\d{5}", prefix):
            continue
        release = m.group(0)
        if table.get(prefix, release) != release:
            sys.exit(f"the page lists prefix {prefix} under two releases")
        table[prefix] = release
    return table


def source_table(text):
    """{prefix: release} from TOKEN2_PREFIXES in the Rust source."""
    m = re.search(r"const TOKEN2_PREFIXES[^=]*=\s*&\[(.*?)\];", text, re.S)
    if not m:
        sys.exit(f"TOKEN2_PREFIXES not found in {SOURCE}")
    return dict(re.findall(r'\("(\d{5})",\s*"([^"]+)"\)', m.group(1)))


def main():
    with open(SOURCE, encoding="utf-8") as f:
        ours = source_table(f.read())
    try:
        req = urllib.request.Request(PAGE, headers={"User-Agent": "keyroost-release-check"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            theirs = page_table(resp.read().decode("utf-8", errors="replace"))
    except OSError as e:
        print(f"could not fetch {PAGE}: {e}", file=sys.stderr)
        return 2
    if not theirs:
        print(f"no prefix table found on {PAGE}; check the page by hand", file=sys.stderr)
        return 2

    added = sorted(p for p in theirs if p not in ours)
    removed = sorted(p for p in ours if p not in theirs)
    changed = sorted(p for p in theirs if p in ours and theirs[p] != ours[p])
    if not (added or removed or changed):
        print(f"OK: {len(ours)} Token2 serial prefixes match the published table.")
        return 0
    for p in added:
        print(f"added on the page:   {p} -> {theirs[p]}")
    for p in removed:
        print(f"gone from the page:  {p} (keyroost has {ours[p]})")
    for p in changed:
        print(f"release changed:     {p}: page {theirs[p]}, keyroost {ours[p]}")
    print(f"Update TOKEN2_PREFIXES in {SOURCE} to match {PAGE}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
