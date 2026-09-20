#!/usr/bin/env bash
# Wait for 1h longrun to finish, then regenerate results/plots/paper.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG="/tmp/auto_refresh_longrun.log"
SAMPLES="$ROOT/results/tuning/round4_minimal_output/longrun/samples.csv"
TARGET_SEC=3600
POLL=60

log() { echo "[$(date -Iseconds)] $*" >> "$LOG"; echo "[$(date -Iseconds)] $*"; }

log "Auto-refresh started. Waiting for longrun (${TARGET_SEC}s)..."

while true; do
  # Docker longrun container still running?
  if docker ps --format '{{.Names}}' 2>/dev/null | grep -qE 'busy_wiles|longrun'; then
    elapsed=0
    if [ -f "$SAMPLES" ]; then
      elapsed=$(tail -1 "$SAMPLES" | cut -d, -f1)
    fi
    log "Longrun in progress: ${elapsed}s / ${TARGET_SEC}s"
    sleep "$POLL"
    continue
  fi

  # Container stopped — check if we reached target
  if [ -f "$SAMPLES" ]; then
    elapsed=$(tail -1 "$SAMPLES" | cut -d, -f1)
    if [ "$elapsed" -ge "$((TARGET_SEC - 120))" ]; then
      log "Longrun complete (${elapsed}s). Regenerating artifacts..."
      break
    fi
  fi

  # No container and samples short — wait a bit more or timeout
  if [ -f "$SAMPLES" ]; then
    elapsed=$(tail -1 "$SAMPLES" | cut -d, -f1)
    log "Container ended at ${elapsed}s, proceeding with refresh..."
    break
  fi

  log "Waiting for longrun data..."
  sleep "$POLL"
done

# Regenerate inside Docker (handles root-owned files + matplotlib)
docker run --rm \
  -v "$ROOT:/work" \
  -w /work ubuntu:24.04 bash -c '
    apt-get update -qq && apt-get install -y -qq python3 python3-yaml python3-matplotlib 2>/dev/null | tail -1
    python3 scripts/aggregate_tuning.py
    python3 scripts/plot.py
    python3 scripts/generate_paper_results.py
    chown -R '"$(id -u):$(id -g)"' /work/results/processed /work/results/plots /work/paper 2>/dev/null || true
  ' >> "$LOG" 2>&1

log "Done. Updated:"
log "  - results/processed/tuning_comparison.json"
log "  - results/plots/fig*.png"
log "  - paper/paper_draft.md (Section 3.7 longrun)"
log "Auto-refresh complete."
