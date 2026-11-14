#!/usr/bin/env bash
# Diagnostic only (draft PR, never merged). Loops keyroost-pgpkey's
# `*_export_works_in_gpg` tests and replays the key from every failure.
# Results go to the job summary.
set -u

out=${RUNNER_TEMP:-/tmp}/gnupg-diag
mkdir -p "$out"
summary=${GITHUB_STEP_SUMMARY:-/dev/stdout}
here=$(dirname "$0")

gcc -o "$out/hwf" "$here/hwf.c" -lgcrypt

cpu=$(lscpu | sed -n 's/^Model name: *//p' | head -1)
flags=$(grep -m1 '^flags' /proc/cpuinfo | tr ' ' '\n' \
  | grep -E '^(aes|vaes|vpclmulqdq|avx2|avx512f|avx512vl|sha_ni|gfni)$' \
  | sort | tr '\n' ' ')
{
  echo "## Runner"
  echo "- CPU: $cpu"
  echo "- CPU flags of interest: $flags"
  echo "- $(gpg --version | head -1); $(gpg --version | sed -n 2p)"
  echo "- libgcrypt: $("$out/hwf" | grep -E '^(version|hwflist):' | tr '\n' ' ')"
} >> "$summary"

cargo test -q -p keyroost-pgpkey --locked --test gnupg_interop --no-run

runs=${RUNS:-40}
good=0
bad=0
for _ in $(seq 1 "$runs"); do
  if cargo test -q -p keyroost-pgpkey --locked --test gnupg_interop \
      -- export_works_in_gpg > "$out/run.log" 2>&1; then
    good=$((good + 1))
  else
    bad=$((bad + 1))
    cp "$out/run.log" "$out/fail-$bad.log"
  fi
done
echo "- Loop: $runs runs of the export tests, $good ok, $bad failed" >> "$summary"

for f in "$out"/fail-*.log; do
  [ -e "$f" ] || continue
  python3 -I "$here/replay.py" "$f" "$out/hwf" >> "$summary" 2>&1
done

# Fail the job when the loop saw a failure, so it stands out in the PR.
[ "$bad" -eq 0 ]
