#!/usr/bin/env bash
#
# Contributor credit gate: a PR from an outside contributor carries its own
# credit in README.md's "### Contributors" section, the same way it carries
# its changelog.d/ fragment. Without a gate the section trailed main by
# eleven merged PRs, because adding the credit was nobody's job in particular.
#
# Passes for the maintainer and for Dependabot. Anyone else passes only when
# the Contributors section contains "pull/<number>)", i.e. a link to this PR
# in the section's existing ([#N](https://github.com/.../pull/N)) style.
#
# Usage:
#   packaging/check-contributor-credit.sh <pr-number> <author-login> [readme]
#   packaging/check-contributor-credit.sh --self-test
#
# CI passes the PR number and author through env:, never interpolated into
# the shell command. --self-test builds a throwaway README in a temp
# directory; the real README.md is never touched.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MAINTAINER="framefilter"

# Prints the "### Contributors" section: from its heading up to the next
# Markdown heading.
contributors_section() {
    awk '
        /^### Contributors[[:space:]]*$/ { inside = 1; next }
        inside && /^#/ { exit }
        inside { print }
    ' "$1"
}

check() {
    local pr="$1" login="$2" readme="${3:-$ROOT/README.md}"

    if ! [[ "$pr" =~ ^[0-9]+$ ]]; then
        echo "error: PR number must be digits, got '$pr'" >&2
        return 2
    fi
    if [[ -z "$login" ]]; then
        echo "error: author login is empty" >&2
        return 2
    fi

    case "$login" in
        "$MAINTAINER")
            echo "ok: PR #$pr is the maintainer's; no contributor credit needed"
            return 0 ;;
        "dependabot[bot]" | "app/dependabot")
            echo "ok: PR #$pr is Dependabot's; no contributor credit needed"
            return 0 ;;
    esac

    if [[ ! -f "$readme" ]]; then
        echo "error: $readme not found" >&2
        return 2
    fi

    local section
    section="$(contributors_section "$readme")"
    if [[ -z "$section" ]]; then
        echo "error: no '### Contributors' section in $readme" >&2
        return 2
    fi

    if grep -qF "pull/$pr)" <<<"$section"; then
        echo "ok: README.md's Contributors section credits PR #$pr"
        return 0
    fi

    cat >&2 <<EOF
error: README.md's Contributors section does not credit PR #$pr.

@$login, thanks for the PR. Please add this PR to your line in the
"### Contributors" section of README.md, in the same style as the other
entries:

  ([#$pr](https://github.com/framefilter/keyroost/pull/$pr))

On a first PR, add a line for yourself in the section's existing style.
CONTRIBUTING.md ("How a PR lands") has the details. A PR without its credit
isn't merged.
EOF
    return 1
}

self_test() {
    local tmp fails=0
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' RETURN

    cat >"$tmp/README.md" <<'EOF'
# Project

### Contributors

- **[@someone](https://github.com/someone)** — a thing
  ([#273](https://github.com/framefilter/keyroost/pull/273)).

## Next section

Not part of the credits: ([#999](https://github.com/framefilter/keyroost/pull/999))
EOF

    # expect <want-exit> <description> <args...>
    expect() {
        local want="$1" what="$2" got=0
        shift 2
        check "$@" >/dev/null 2>&1 || got=$?
        if [[ "$got" -eq "$want" ]]; then
            echo "pass: $what"
        else
            echo "FAIL: $what (exit $got, want $want)"
            fails=$((fails + 1))
        fi
    }

    expect 0 "maintainer passes without a credit"  1 "$MAINTAINER" "$tmp/README.md"
    expect 0 "dependabot[bot] passes"              2 "dependabot[bot]" "$tmp/README.md"
    expect 0 "app/dependabot passes"               3 "app/dependabot" "$tmp/README.md"
    expect 0 "credited PR number passes"           273 someone "$tmp/README.md"
    expect 1 "missing PR number fails"             274 someone "$tmp/README.md"
    expect 1 "number as a suffix does not match"   73 someone "$tmp/README.md"
    expect 1 "number outside the section fails"    999 someone "$tmp/README.md"
    expect 2 "non-numeric PR number is an error"   "27x" someone "$tmp/README.md"
    expect 2 "empty login is an error"             273 "" "$tmp/README.md"

    if [[ "$fails" -ne 0 ]]; then
        echo "$fails self-test case(s) failed"
        return 1
    fi
    echo "all self-test cases passed"
}

if [[ "${1:-}" == "--self-test" ]]; then
    self_test
    exit $?
fi

if [[ $# -lt 2 || $# -gt 3 ]]; then
    echo "usage: $0 <pr-number> <author-login> [readme]" >&2
    echo "       $0 --self-test" >&2
    exit 2
fi

check "$@"
