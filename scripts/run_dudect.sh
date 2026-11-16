#!/usr/bin/env bash
# Build and run the dudect constant-time benches.
#
# `cargo bench` passes `--bench` to the binary, which dudect-bencher's argument parser rejects,
# so the bench executable is built with --no-run and invoked directly. On Linux the process is
# pinned to one CPU with taskset to keep scheduler migrations out of the measurements.
#
#   scripts/run_dudect.sh [output-file]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/docs/.dudect-raw.txt}"
cd "$ROOT"

EXE=$(cargo bench -p qshield-crypto --bench dudect --no-run --message-format=json 2>/dev/null \
  | python3 -c 'import json,sys
for line in sys.stdin:
    m = json.loads(line)
    if m.get("reason") == "compiler-artifact" and m["target"]["name"] == "dudect" and m.get("executable"):
        print(m["executable"])')

if [[ -z "$EXE" ]]; then
  echo "dudect bench executable not found" >&2
  exit 1
fi

if command -v taskset >/dev/null 2>&1; then
  taskset -c 2 "$EXE" | tee "$OUT"
else
  "$EXE" | tee "$OUT"
fi
