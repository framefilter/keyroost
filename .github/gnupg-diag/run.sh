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


# Replay the first three failures only; each replay runs 60 gpg trials.
for f in "$out"/fail-1.log "$out"/fail-2.log "$out"/fail-3.log; do
  [ -e "$f" ] || continue
  DIAG_NO_DENY=1 python3 -I "$here/replay.py" "$f" "$out/hwf" >> "$summary" 2>&1
  # The same key through the test's own Rust helpers.
  [ -e "$f.asc" ] || continue
  r_good=0
  r_bad=0
  for _ in $(seq 1 2); do
    if KR_REPLAY_KEY="$f.asc" cargo test -q -p keyroost-pgpkey --locked \
        --test gnupg_interop -- --ignored --exact replay_saved_key_in_gpg \
        > "$out/rreplay.log" 2>&1; then
      r_good=$((r_good + 1))
    else
      r_bad=$((r_bad + 1))
      cp "$out/rreplay.log" "$f.rreplay-fail.log"
    fi
  done
  echo "  - replay through the test's Rust helpers: 2 runs, $r_good ok, $r_bad failed" >> "$summary"
  if [ -e "$f.rreplay-fail.log" ]; then
    grep -E "failed:|gpg: |gpg-agent\[[0-9]+\] (failed|command)" "$f.rreplay-fail.log" \
      | head -8 | sed 's/^/    - /' >> "$summary"
  fi
done

# The job summary isn't readable through the API; repeat it in the log.
echo "===== gnupg-diag summary ====="
cat "$summary"
echo "===== end of gnupg-diag summary ====="

# Fail the job when the loop saw a failure, so it stands out in the PR.
[ "$bad" -eq 0 ]
