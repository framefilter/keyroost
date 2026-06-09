#!/usr/bin/env bash
# PreToolUse guard for keyroost.
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
#
# Exemption: paths under the scratch dir below hold only *disposable OpenPGP
# test keys* generated during hardware bring-up (e.g. a throwaway RSA key to
# import into a test YubiKey). They are intentionally allowed so trace/import
# flows can run in-session. Real secrets — $HOME keys, .ssh, .env, WiFi configs —
# stay blocked because they don't live under this prefix. Keep the prefix
# narrow; never widen it to a directory that could hold a real key.
#
# The scratch dir lives under $XDG_RUNTIME_DIR (per-user, mode 0700) — NOT
# world-writable /tmp. That closes a symlink-planting bypass: in shared /tmp,
# another user could create `/tmp/moltoui-test/x.pem -> ~victim/.ssh/id_rsa`,
# and the exemption would strip the path and let the read through. A 0700
# per-user runtime dir can't be written by anyone else, so a symlink there is
# the user's own. If XDG_RUNTIME_DIR is unset, the exemption is disabled
# entirely (we scan the full command) rather than guess an unsafe location.
test_key_dir="${XDG_RUNTIME_DIR:-}/moltoui-test/"
# Apply the exemption by stripping scratch-dir tokens before the secret scan —
# but ONLY when XDG_RUNTIME_DIR is set AND the command contains no `..`.
# Otherwise a traversal path like
# `$XDG_RUNTIME_DIR/moltoui-test/../../home/user/.ssh/id_rsa` would be stripped
# wholesale (the `[^[:space:]]*` swallows the `..` and everything after),
# bypassing the scan and exposing a real key. In either unsafe case we fail
# closed and scan the full, unstripped command, so traversal can never reach a
# real secret.
# The exemption additionally requires XDG_RUNTIME_DIR to consist only of
# plain path characters: the value is interpolated into the sed pattern
# below, where a regex metacharacter or the `@` delimiter would corrupt the
# expression (and with it, what gets stripped from the scan). Fail closed —
# scan the full command — on anything unusual rather than try to escape it.
case "${XDG_RUNTIME_DIR:-}" in
    ""|*[!A-Za-z0-9/_-]*) xdg_safe=0 ;;
    *) xdg_safe=1 ;;
esac
if [ "$xdg_safe" = 1 ] && ! printf '%s' "$arg" | grep -q '\.\.'; then
    scan="$(printf '%s' "$arg" | sed -E "s@${test_key_dir}[^[:space:]]*@@g")"
else
    scan="$arg"
fi

printf '%s' "$scan" | grep -Eiq '(\.env([^[:alnum:]]|$)|\.pem([^[:alnum:]]|$)|id_rsa|id_ed25519|/\.ssh/|credentials|\.nmconnection|wpa_supplicant|(^|[^[:alnum:]_])psk=)' \
    && block 'this touches a file that commonly holds secrets (keys, .env, SSH, WiFi/NetworkManager configs).'

exit 0
