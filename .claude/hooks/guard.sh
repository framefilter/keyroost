#!/usr/bin/env bash
# PreToolUse guard for MoltoUI.
#
# A deterministic, enforced backstop that runs BEFORE Claude Code executes a
# Bash or Read tool call. Exit code 2 blocks the call and feeds the message
# on stderr back to Claude as the reason; exit 0 allows it.
#
# It blocks commands or file reads that would surface a secret (PINs, env
# dumps, private keys, .env files, SSH keys, WiFi/NetworkManager configs).
#
# Destructive FIDO operations (fido-reset, fido-creds-delete) are intentionally
# NOT guarded here: this checkout is used only with disposable test keys.
#
# This is intentionally conservative: when something looks like it would expose
# a secret, it blocks and tells the human to run it themselves in a separate
# terminal. Tune the patterns below if it gets in the way.

set -u

payload="$(cat)"

# Pull the tool name and the field we care about (Bash command or Read path).
# Prefer python3 for correct JSON parsing; fall back to scanning the raw
# payload so the guard still functions (fail-closed) without python3.
if command -v python3 >/dev/null 2>&1; then
    arg="$(printf '%s' "$payload" | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
ti = d.get("tool_input", {}) or {}
print(ti.get("command", ti.get("file_path", "")))
' 2>/dev/null)"
    # If python produced nothing (parse failure), fall back to the raw payload.
    [ -z "$arg" ] && arg="$payload"
else
    arg="$payload"
fi

block() {
    printf 'BLOCKED by .claude/hooks/guard.sh: %s\n' "$1" >&2
    printf 'If you really need this, run it yourself in a separate terminal — do not route it through Claude Code.\n' >&2
    exit 2
}

matches() { printf '%s' "$arg" | grep -Eiq "$1"; }

# --- 1. Secret-dumping commands ---------------------------------------------
matches '(^|[^[:alnum:]_])printenv([^[:alnum:]_]|$)' \
    && block 'printenv would dump environment variables (a PIN may live there).'
matches 'echo[^|;&]*\$\{?[[:alnum:]_]*(PIN|PASS|PASSWORD|PASSPHRASE|SECRET|TOKEN|KEY)' \
    && block 'this would echo a secret-bearing variable.'

# --- 2. Reading files that commonly hold secrets ----------------------------
# Covers both shell readers (cat/less/grep ...) and the Read tool's file_path.
matches '(\.env([^[:alnum:]]|$)|\.pem([^[:alnum:]]|$)|id_rsa|id_ed25519|/\.ssh/|credentials|\.nmconnection|wpa_supplicant|(^|[^[:alnum:]_])psk=)' \
    && block 'this touches a file that commonly holds secrets (keys, .env, SSH, WiFi/NetworkManager configs).'

exit 0
