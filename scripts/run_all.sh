#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
mkdir -p results/raw results/processed results/plots results/logs results/failures

echo "=== Phase 0: Environment ==="
bash scripts/check_environment.sh 2>&1 | tee results/logs/environment.log

echo "=== Phase 1: Build ==="
bash scripts/build.sh 2>&1 | tee results/logs/build.log

echo "=== Phase 2: Correctness experiments ==="
for wl in classical liboqs-mlkem negative; do
  for i in $(seq 1 3); do
    rid="correctness-${wl}-${i}"
    if ! bash scripts/run_experiment.sh "$rid" "$wl" 3 2>&1 | tee "results/logs/${rid}.log"; then
      cp "results/logs/${rid}.log" "results/failures/${rid}.log" 2>/dev/null || true
    fi
  done
done

echo "=== Phase 3: Analysis ==="
python3 scripts/analyze.py 2>&1 | tee results/logs/analyze.log
python3 scripts/plot.py 2>&1 | tee results/logs/plot.log

echo "=== Done ==="
echo "Results: $ROOT/results/"
echo "See STATUS.md for summary"
