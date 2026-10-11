#!/usr/bin/env python3
"""Generate the command reference at the bottom of docs/cli.html.

The Learn site's "Command line" page ends with every keyroostctl command and
its one-line description. Copied by hand, that list would drift from the real
binary within a release, so it is generated from the `--help` tree instead,
between these two markers in docs/cli.html:

    <!-- BEGIN generated: cli-reference -->
    <!-- END generated: cli-reference -->

Usage (from the repository root):

    packaging/gen-cli-reference.py [--bin PATH]
        Rewrite the block in docs/cli.html from PATH's --help tree.

    packaging/gen-cli-reference.py --check [--bin PATH]
        Exit 1 (writing nothing) when the block differs from what PATH's
        --help tree would produce. packaging/check-docs-mechanical.sh runs
        this.

PATH defaults to target/docs-check/release/keyroostctl, the build that
check-docs-mechanical.sh makes (`CARGO_TARGET_DIR=target/docs-check cargo
build --release --offline -p keyroostctl`). Stdlib only.
"""

import argparse
import html
import re
import subprocess
import sys
from pathlib import Path

PAGE = Path("docs/cli.html")
BEGIN = "<!-- BEGIN generated: cli-reference -->"
END = "<!-- END generated: cli-reference -->"
DEFAULT_BIN = "target/docs-check/release/keyroostctl"


def commands(binary, path):
    """[(name, description)] from the `Commands:` list of `path`'s help."""
    out = subprocess.run([binary, *path, "--help"], capture_output=True,
                         text=True, check=True).stdout
    found, listing = [], False
    for line in out.splitlines():
        if line.strip() == "Commands:":
            listing = True
            continue
        if listing:
            m = re.match(r"^  ([a-z0-9][a-z0-9-]*)\s+(.*)$", line)
            if m:
                if m.group(1) != "help":
                    found.append((m.group(1), m.group(2).strip()))
            elif not line.strip():
                break
    return found


def walk(binary, path=()):
    """Every command under `path`, depth first: [(path tuple, description)]."""
    rows = []
    for name, desc in commands(binary, list(path)):
        sub = path + (name,)
        rows.append((sub, desc))
        rows.extend(walk(binary, sub))
    return rows


def describe(text):
    """Escape a description; `backticked` words become <code>."""
    parts = text.split("`")
    return "".join(f"<code>{html.escape(p)}</code>" if i % 2 else html.escape(p)
                   for i, p in enumerate(parts))


def block(binary):
    rows = walk(binary)
    top = [r for r in rows if len(r[0]) == 1]
    out = [BEGIN,
           "<!-- Generated from keyroostctl --help by "
           "packaging/gen-cli-reference.py; do not edit by hand. -->"]
    general = [r for r in top if not any(len(p) > 1 and p[0] == r[0][0]
                                         for p, _ in rows)]
    groups = [r for r in top if r not in general]

    def table(entries):
        out.append('    <div class="kr-table-wrap"><table class="kr-table">')
        out.append("      <tr><th>Command</th><th>What it does</th></tr>")
        for p, desc in entries:
            out.append(f"      <tr><td><code>keyroostctl {' '.join(p)}</code></td>"
                       f"<td>{describe(desc)}</td></tr>")
        out.append("    </table></div>")

    out.append('    <h3 id="ref-general">General</h3>')
    table(general)
    for (p, desc) in groups:
        out.append(f'    <h3 id="ref-{p[0]}">{p[0]}</h3>')
        out.append(f'    <p class="kr-muted">{describe(desc)}</p>')
        table([r for r in rows if len(r[0]) > 1 and r[0][0] == p[0]])
    out.append("    " + END)
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--bin", default=DEFAULT_BIN, help="keyroostctl to read")
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if the block is stale; write nothing")
    args = ap.parse_args()

    page = PAGE.read_text(encoding="utf-8")
    m = re.search(re.escape(BEGIN) + r".*?" + re.escape(END), page, flags=re.S)
    if not m:
        sys.exit(f"error: {PAGE} has no {BEGIN} … {END} block")
    new = block(args.bin)
    if args.check:
        if m.group(0) != new:
            print(f"{PAGE}: the command reference is stale; regenerate it with "
                  f"packaging/gen-cli-reference.py")
            sys.exit(1)
        print(f"ok: {PAGE}'s command reference matches `{args.bin} --help`")
        return
    if m.group(0) == new:
        print(f"{PAGE}: command reference already current")
        return
    PAGE.write_text(page[:m.start()] + new + page[m.end():], encoding="utf-8")
    print(f"{PAGE}: command reference rewritten")


if __name__ == "__main__":
    main()
