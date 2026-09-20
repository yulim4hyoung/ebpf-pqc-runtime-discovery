#!/usr/bin/env bash
# Run correctness + detection experiment for one workload
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RUN_ID="${1:-exp-$(date +%s)}"
WORKLOAD="${2:-classical}"
DURATION="${3:-5}"
RAW="$ROOT/results/raw/$RUN_ID"
mkdir -p "$RAW"

MONITOR="$ROOT/build/crypto-monitor"
if [ ! -x "$MONITOR" ]; then
  ./scripts/build.sh
fi

case "$WORKLOAD" in
  classical)
    GT='{"run_id":"'"$RUN_ID"'","expected_algorithm":"RSA","expected_operation":"keygen","expected_crypto":true,"expected_pqc":false}'
    WL="$ROOT/workloads/openssl/classical.sh"
    ;;
  liboqs-mlkem)
    GT='{"run_id":"'"$RUN_ID"'","expected_algorithm":"ML-KEM-768","expected_operation":"encapsulation","expected_crypto":true,"expected_pqc":true}'
    WL="$ROOT/workloads/liboqs/run_mlkem.sh"
    ;;
  negative)
    GT='{"run_id":"'"$RUN_ID"'","expected_algorithm":"","expected_operation":"","expected_crypto":false,"expected_pqc":false}'
    WL="$ROOT/workloads/negative/random_only.sh"
    ;;
  *)
    echo "Unknown workload: $WORKLOAD"
    exit 1
    ;;
esac

echo "$GT" > "$RAW/ground_truth.json"

# Run monitor with CAP_BPF if not root
run_monitor() {
  if [ "$(id -u)" -eq 0 ]; then
    "$MONITOR" -o "$RAW/events.jsonl" -d "$DURATION"
  elif command -v capsh >/dev/null 2>&1; then
    capsh --caps="cap_bpf,cap_perfmon,cap_sys_admin+ep" --keep=1 \
      -- -c "$MONITOR -o $RAW/events.jsonl -d $DURATION"
  else
    echo "ERROR: root or capsh required for BPF" | tee "$RAW/error.log"
    return 1
  fi
}

run_monitor &
MPID=$!
sleep 1
bash "$WL" 2>&1 | tee "$RAW/workload.log" || true
wait "$MPID" 2>/dev/null || true

EVENT_COUNT=$(wc -l < "$RAW/events.jsonl" 2>/dev/null || echo 0)
echo "{\"run_id\":\"$RUN_ID\",\"events\":$EVENT_COUNT,\"workload\":\"$WORKLOAD\"}" > "$RAW/summary.json"
echo "Run $RUN_ID complete: $EVENT_COUNT events -> $RAW"
