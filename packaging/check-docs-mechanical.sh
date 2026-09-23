#!/usr/bin/env bash
#
# Mechanical documentation audit — run pre-release on the prep branch.
#
# The incident classes this exists to catch, all of which shipped in real
# releases because only humans were checking:
#
#   1. Docs teaching commands the binary does not have. Pages showed
#      invocations that had been renamed or re-grouped releases earlier;
#      nothing diffed prose against the real `--help` tree.
#   2. The GUI linking Learn pages that do not exist. The `learn_url(...)`
#      slugs are the app->site inventory, and the GUI shipped three releases
#      linking a /devices page that was not there — the link direction no
#      audit used to walk.
#   3. Dead internal links and anchors inside the Learn site itself.
#   4. CHANGELOG reference-link rot: a `[#NN]` with no definition renders as
#      literal brackets on GitHub; an orphan definition means a reference was
#      deleted without its plumbing; a broken compare chain gives readers the
#      wrong diff.
#   5. Contributor credit trailing reality (it trailed by five PRs at the
#      v0.7.8 audit). Reported as WARN — crediting judgment (aliases, who
#      counts as a maintainer) belongs to the maintainer, not a script.
#   6. A malformed changelog.d/ fragment (bad filename, missing credit ref,
#      an overlong line) going unnoticed until release, when assembling it
#      into CHANGELOG.md would either fail or ship a broken entry.
#
# Usage:
#   packaging/check-docs-mechanical.sh
#
# Entirely offline. Always (re)builds target/release/keyroostctl first — a
# no-op when current — so CLI invocations are validated against the REAL,
# up-to-date binary's --help tree, never against the source or a stale build.
#
# Deliberate-old-command escapes in docs/migration.html:
#   - the first column of any table whose header starts with "Old" is skipped;
#   - <pre> lines whose trailing # comment contains "≤" (the page's own
#     old-syntax marker) are skipped.
#
# Exits non-zero on any FAIL; WARNs never fail the run.

set -euo pipefail

cd "$(dirname "$0")/.."

for arg in "$@"; do
  case "$arg" in
    -h|--help) sed -n '2,38p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "error: unrecognized argument '$arg'" >&2; exit 2 ;;
  esac
done

BIN=target/release/keyroostctl
# Always build: a binary left over from an older checkout would validate the
# docs against a stale --help tree. On an up-to-date tree this is a no-op.
cargo build --release --offline -p keyroostctl
"$BIN" --version >/dev/null || { echo "error: ${BIN} does not run" >&2; exit 2; }

KEYROOSTCTL_BIN="$BIN" python3 - <<'PY'
import html
import os
import re
import subprocess
import sys

BIN = os.environ["KEYROOSTCTL_BIN"]
FAILS = 0
WARNS = 0

def fail(msg):
    global FAILS
    FAILS += 1
    print(f"FAIL: {msg}")

def warn(msg):
    global WARNS
    WARNS += 1
    print(f"WARN: {msg}")

# --- (a) every documented CLI invocation resolves against the binary --------

_help_cache = {}

def help_text(path):
    """--help output for a subcommand path tuple, or None if clap rejects it."""
    if path not in _help_cache:
        r = subprocess.run([BIN, *path, "--help"],
                           capture_output=True, text=True)
        _help_cache[path] = r.stdout if r.returncode == 0 else None
    return _help_cache[path]

def subcommands(helptext):
    subs = set()
    in_cmds = False
    for line in helptext.splitlines():
        if line.strip() == "Commands:":
            in_cmds = True
            continue
        if in_cmds:
            m = re.match(r"^  ([A-Za-z0-9][A-Za-z0-9-]*)(\s|$)", line)
            if m:
                subs.add(m.group(1))
            elif not line.strip():
                break
    return subs

def flag_known(helptext, flag):
    return re.search(re.escape(flag) + r"(?![A-Za-z0-9-])", helptext) is not None

def flag_takes_value(helptext, flag):
    return re.search(re.escape(flag) + r"[ =]\[?<", helptext) is not None

STOP_TOKENS = {">", "<", ">>", "|", ";", "&&", "||", "&"}
WORD = re.compile(r"[a-z][a-z0-9-]*\Z")
ALTERNATION = re.compile(r"[a-z0-9-]+(\|[a-z0-9-]+)+\Z")

def check_invocation(where, cmdline, tokens):
    """Validate one `keyroostctl …` token stream against the --help tree."""
    path = ()
    ht = help_text(path)
    can_descend = True
    i = 0
    while i < len(tokens):
        t = tokens[i]
        at = " ".join(("keyroostctl",) + path)
        if t in STOP_TOKENS or t == "--":
            break
        if t in ("…", "..."):
            can_descend = False
            i += 1
            continue
        if t.startswith("--"):
            name = t.split("=", 1)[0]
            if not flag_known(ht, name):
                fail(f"{where}: `{cmdline}` — `{name}` is not a flag of `{at}`")
            elif "=" not in t and flag_takes_value(ht, name) \
                    and i + 1 < len(tokens) and not tokens[i + 1].startswith("-"):
                i += 1  # consume the flag's value
        elif t.startswith("-") and len(t) > 1 and not t[1].isdigit():
            if not flag_known(ht, t[:2]):
                fail(f"{where}: `{cmdline}` — `{t[:2]}` is not a flag of `{at}`")
        elif can_descend:
            subs = subcommands(ht)
            if t in subs:
                if t == "help":
                    can_descend = False
                else:
                    path += (t,)
                    ht = help_text(path) or ht
            elif ALTERNATION.match(t):
                for alt in t.split("|"):
                    if alt not in subs:
                        fail(f"{where}: `{cmdline}` — `{alt}` is not a "
                             f"subcommand of `{at}`")
                can_descend = False
            elif WORD.match(t) and subs:
                fail(f"{where}: `{cmdline}` — `{t}` is not a subcommand of `{at}`")
            else:
                can_descend = False  # positional / placeholder
        i += 1

def tokenize(segment):
    import shlex
    try:
        return shlex.split(segment)
    except ValueError:
        return segment.split()

def check_command_text(where, text):
    """Validate every segment-initial keyroostctl command in plain text."""
    # join backslash continuations
    text = re.sub(r"\\\n\s*", " ", text)
    for lineno_off, line in enumerate(text.splitlines()):
        line = re.sub(r"(^|\s)#.*$", "", line)  # trailing comments
        for segment in re.split(r"\s(?:&&|\|\||;|\|)\s|^\$\s+", line):
            segment = segment.strip()
            if not segment.startswith("keyroostctl"):
                continue
            tokens = tokenize(segment)
            if tokens and tokens[0] == "keyroostctl":
                check_invocation(where, " ".join(tokens), tokens[1:])

def strip_tags(s):
    return html.unescape(re.sub(r"<[^>]+>", "", s))

PLACEHOLDER_LINE = re.compile(r"X\.Y\.Z|<[A-Za-z_-]+>|\bvX\b")

def audit_html_doc(fname):
    raw = open(fname, encoding="utf-8").read()
    if os.path.basename(fname) == "migration.html":
        # Skip the deliberately-old first column of any "Old …" table.
        def fix_table(m):
            tbl = m.group(0)
            if re.search(r"<th>\s*Old", tbl):
                tbl = re.sub(r"<tr><td>.*?</td>", "<tr>", tbl)
            return tbl
        raw = re.sub(r"<table.*?</table>", fix_table, raw, flags=re.S)
    lines_before = lambda pos: raw.count("\n", 0, pos) + 1
    # <pre> blocks (shell examples), then inline <code> spans.
    consumed = []
    for m in re.finditer(r"<pre[^>]*>(.*?)</pre>", raw, flags=re.S):
        consumed.append(m.span())
        text = strip_tags(m.group(1))
        if os.path.basename(fname) == "migration.html":
            # the page's own old-syntax marker: a trailing "# ≤ 0.x" comment
            text = "\n".join(l for l in text.splitlines()
                             if "≤" not in (l.split("#", 1) + [""])[1])
        check_command_text(f"{fname}:{lines_before(m.start())}", text)
    def in_consumed(pos):
        return any(a <= pos < b for a, b in consumed)
    for m in re.finditer(r"<code[^>]*>(.*?)</code>", raw, flags=re.S):
        if in_consumed(m.start()):
            continue
        text = strip_tags(m.group(1))
        if PLACEHOLDER_LINE.search(text):
            continue
        check_command_text(f"{fname}:{lines_before(m.start())}", text)

def audit_markdown(fname):
    raw = open(fname, encoding="utf-8").read()
    lines_before = lambda pos: raw.count("\n", 0, pos) + 1
    consumed = []
    for m in re.finditer(r"```.*?\n(.*?)```", raw, flags=re.S):
        consumed.append(m.span())
        check_command_text(f"{fname}:{lines_before(m.start())}", m.group(1))
    def in_consumed(pos):
        return any(a <= pos < b for a, b in consumed)
    for m in re.finditer(r"`([^`\n]+)`", raw):
        if in_consumed(m.start()) or PLACEHOLDER_LINE.search(m.group(1)):
            continue
        check_command_text(f"{fname}:{lines_before(m.start())}", m.group(1))

print("== (a) CLI invocations in docs vs the real binary ==")
DOCS = sorted(f"docs/{f}" for f in os.listdir("docs") if f.endswith(".html"))
fails_before = FAILS
for f in DOCS:
    audit_html_doc(f)
audit_markdown("README.md")
if FAILS == fails_before:
    print(f"ok: every keyroostctl invocation in {len(DOCS)} pages + README.md "
          f"resolves against `{BIN} --help`")

# --- (b) learn_url slugs resolve to docs pages ------------------------------

print()
print("== (b) GUI learn_url slugs vs docs/ ==")

def anchors_of(page_path):
    txt = open(page_path, encoding="utf-8").read()
    return set(re.findall(r'\bid="([^"]+)"', txt)) \
         | set(re.findall(r'<a\s+name="([^"]+)"', txt))

slugs = []
for root, _dirs, files in os.walk("crates/keyroost/src"):
    for f in files:
        if not f.endswith(".rs"):
            continue
        p = os.path.join(root, f)
        txt = open(p, encoding="utf-8").read()
        for m in re.finditer(r'(?:learn_url\(\s*|slug:\s*)"([^"]*)"', txt):
            slugs.append((p, txt.count("\n", 0, m.start()) + 1, m.group(1)))

fails_before = FAILS
for p, ln, slug in slugs:
    if slug == "":
        continue  # site root
    if not slug.startswith("/"):
        fail(f"{p}:{ln}: slug \"{slug}\" does not start with '/'")
        continue
    page, _, anchor = slug[1:].partition("#")
    target = f"docs/{page}.html" if page else "docs/index.html"
    if not os.path.isfile(target):
        fail(f"{p}:{ln}: learn_url slug \"{slug}\" — {target} does not exist")
    elif anchor and anchor not in anchors_of(target):
        fail(f"{p}:{ln}: learn_url slug \"{slug}\" — no id=\"{anchor}\" in {target}")
if FAILS == fails_before:
    print(f"ok: all {len(slugs)} learn_url/slug references resolve into docs/")

# --- (c) internal links + anchors inside docs/ ------------------------------

print()
print("== (c) internal hrefs and anchors in docs/*.html ==")
fails_before = FAILS
n_links = 0
for f in DOCS:
    raw = open(f, encoding="utf-8").read()
    for m in re.finditer(r'href="([^"]+)"', raw):
        href = m.group(1)
        ln = raw.count("\n", 0, m.start()) + 1
        if re.match(r"^(https?:|mailto:|data:)", href):
            continue
        n_links += 1
        if href.startswith("#"):
            if href[1:] not in anchors_of(f):
                fail(f"{f}:{ln}: href \"{href}\" — no such id in this page")
            continue
        page, _, anchor = href.partition("#")
        target = os.path.normpath(os.path.join("docs", page))
        if not os.path.isfile(target):
            # GitHub Pages serves extensionless URLs for .html files
            if os.path.isfile(target + ".html"):
                target += ".html"
            else:
                fail(f"{f}:{ln}: href \"{href}\" — {target} does not exist")
                continue
        if anchor and target.endswith(".html") and anchor not in anchors_of(target):
            fail(f"{f}:{ln}: href \"{href}\" — no id=\"{anchor}\" in {target}")
if FAILS == fails_before:
    print(f"ok: all {n_links} internal hrefs (and their #anchors) resolve")

# --- (d) CHANGELOG reference links + compare chain --------------------------

print()
print("== (d) CHANGELOG.md link plumbing ==")
fails_before = FAILS
cl = open("CHANGELOG.md", encoding="utf-8").read()
defs = dict(re.findall(r"^\[([^\]]+)\]:\s*(\S+)", cl, flags=re.M))
body = re.sub(r"^\[[^\]]+\]:\s*\S+.*$", "", cl, flags=re.M)

# Reference-style uses only: `[#NN](url)` inline links carry their own URL
# and need no definition.
issue_refs = set(re.findall(r"\[(#\d+)\](?!\()", body))
issue_defs = {k for k in defs if re.fullmatch(r"#\d+", k)}
for r in sorted(issue_refs - issue_defs, key=lambda s: int(s[1:])):
    fail(f"CHANGELOG.md: [{r}] is referenced but has no link definition")
for d in sorted(issue_defs - issue_refs, key=lambda s: int(s[1:])):
    fail(f"CHANGELOG.md: [{d}] has a link definition but is never referenced")

headings = re.findall(r"^## \[([^\]]+)\]", cl, flags=re.M)
version_defs = {k for k in defs if k == "Unreleased" or re.fullmatch(r"[\d.]+", k)}
for h in headings:
    if h not in defs:
        fail(f"CHANGELOG.md: heading [{h}] has no link definition")
for d in sorted(version_defs - set(headings)):
    fail(f"CHANGELOG.md: version link [{d}] has no `## [{d}]` heading")

# compare chain: each version's link must diff from the NEXT-OLDER heading
for i, label in enumerate(headings):
    url = defs.get(label)
    if url is None:
        continue
    if i + 1 < len(headings):
        older = headings[i + 1]
        want = (f"/compare/v{older}...HEAD" if label == "Unreleased"
                else f"/compare/v{older}...v{label}")
        if not url.endswith(want):
            fail(f"CHANGELOG.md: [{label}] link is {url} — expected …{want}")
    else:
        if not url.endswith(f"/releases/tag/v{label}"):
            fail(f"CHANGELOG.md: oldest entry [{label}] should link "
                 f"…/releases/tag/v{label}, not {url}")
if FAILS == fails_before:
    print(f"ok: {len(issue_refs)} issue refs and the {len(headings)}-entry "
          f"compare chain are all well-formed")

# --- (e) contributor credit (WARN only) -------------------------------------

print()
print("== (e) contributor credit in README (WARN only) ==")
authors = subprocess.run(["git", "log", "--format=%an"],
                         capture_output=True, text=True, check=True).stdout.split("\n")
MAINTAINERS = {"framefilter", "note"}
BOTS = {"claude"}
seen = {}
for a in (x.strip() for x in authors):
    if not a:
        continue
    k = a.lower()
    if "[bot]" in k or k in BOTS or k in MAINTAINERS:
        continue
    seen.setdefault(k, a)
readme = open("README.md", encoding="utf-8").read().lower()
warns_before = WARNS
for k, name in sorted(seen.items()):
    if k not in readme:
        warn(f"README.md: git author \"{name}\" not found in the Contributors "
             f"section (alias? maintainer judgment applies)")
if WARNS == warns_before:
    print(f"ok: all {len(seen)} non-bot, non-maintainer authors appear in README.md")

# --- (f) changelog.d/ fragment validation -----------------------------------

print()
print("== (f) changelog.d/ fragment validation ==")
r = subprocess.run([sys.executable, "packaging/assemble-changelog.py", "--check"],
                   capture_output=True, text=True)
for line in (r.stdout + r.stderr).splitlines():
    print(line)
if r.returncode != 0:
    fail("changelog.d/ fragment validation failed (packaging/assemble-changelog.py "
         "--check exited non-zero — see its output above)")

# --- verdict ----------------------------------------------------------------

print()
if FAILS:
    print(f"FAILED — {FAILS} problem(s), {WARNS} warning(s).", file=sys.stderr)
    sys.exit(1)
print(f"PASS — mechanical documentation audit clean ({WARNS} warning(s)).")
PY
