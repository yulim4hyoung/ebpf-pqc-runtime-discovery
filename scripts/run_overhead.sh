#!/usr/bin/env bash
# Compare workload runtime with monitor OFF (M0) vs ON (M3)
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
OUT="$ROOT/results/raw/overhead"
mkdir -p "$OUT"
REPS="${1:-10}"
MONITOR="$ROOT/build/crypto-monitor"
WL="$ROOT/workloads/openssl/classical.sh"

run_timed() {
  local mode="$1"
  local i="$2"
  local log="$OUT/${mode}_run${i}.log"
  local start end elapsed

  start=$(date +%s.%N)
  if [ "$mode" = "M0" ]; then
    bash "$WL" > "$log" 2>&1
  else
    "$MONITOR" -o "$OUT/events_${mode}_${i}.jsonl" &
    local mpid=$!
    sleep 0.3
    bash "$WL" >> "$log" 2>&1
    sleep 0.3
    kill "$mpid" 2>/dev/null || true
    wait "$mpid" 2>/dev/null || true
  fi
  end=$(date +%s.%N)
  elapsed=$(python3 -c "print(float('$end') - float('$start'))")
  echo "$mode,$i,$elapsed" >> "$OUT/times.csv"
}

echo "mode,run,seconds" > "$OUT/times.csv"
for i in $(seq 1 "$REPS"); do
  run_timed M0 "$i"
  run_timed M3 "$i"
done

python3 - <<'PY'
import csv, json, statistics
from pathlib import Path
p = Path("results/raw/overhead/times.csv")
rows = list(csv.DictReader(p.open()))
by_mode = {}
for r in rows:
    by_mode.setdefault(r["mode"], []).append(float(r["seconds"]))
summary = {}
for mode, vals in by_mode.items():
    base = statistics.mean(by_mode.get("M0", vals)) if mode != "M0" else statistics.mean(vals)
    mean = statistics.mean(vals)
    summary[mode] = {
        "n": len(vals),
        "mean_sec": mean,
        "median_sec": statistics.median(vals),
        "stdev_sec": statistics.stdev(vals) if len(vals) > 1 else 0,
        "overhead_pct": ((mean / base) - 1) * 100 if mode != "M0" and base else 0,
    }
out = Path("results/processed/overhead_summary.json")
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(summary, indent=2))
print(f"Wrote {out}")
for m, s in summary.items():
    print(f"  {m}: mean={s['mean_sec']:.3f}s overhead={s.get('overhead_pct', 0):.1f}%")
PY
