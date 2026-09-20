#!/usr/bin/env bash
# Run only the randomness-detector ablation (scripts/run_randomness_eval.py)
# in the privileged container, honouring RESULTS_DIR (default: results).
# Added 2026-09-20 for the A10/A11 validation rerun; mount pattern copied
# from scripts/run_qed_realworld.sh.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${DOCKER_IMAGE:-ubuntu:24.04}"

TRACEFS_MOUNT=()
[ -d /sys/kernel/tracing ] && TRACEFS_MOUNT=(-v /sys/kernel/tracing:/sys/kernel/tracing:ro)
docker run --rm --privileged --pid=host \
  -v "$ROOT:/work" \
  -v /usr/local/lib:/usr/local/lib:ro \
  -v /usr/local/include:/usr/local/include:ro \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v /sys/fs/bpf:/sys/fs/bpf \
  "${TRACEFS_MOUNT[@]}" \
  -e RESULTS_DIR="${RESULTS_DIR:-results}" \
  -w /work "$IMAGE" bash -c '
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq openssl python3 libelf1 zlib1g gcc libssl-dev 2>/dev/null | tail -1
    ulimit -l unlimited 2>/dev/null || true
    R="${RESULTS_DIR:-results}"
    mkdir -p "$R/logs" "$R/randomness-eval"
    # rebuild the liboqs workload against the mounted liboqs, as the QED runner does
    gcc -Wall -O2 -o workloads/liboqs/mlkem_workload workloads/liboqs/mlkem_workload.c \
      -I/usr/local/include -L/usr/local/lib -loqs -Wl,-rpath,/usr/local/lib 2>/dev/null || true
    python3 scripts/run_randomness_eval.py 2>&1 | tee "$R/logs/randomness_eval.log"
    chown -R $(stat -c "%u:%g" /work/results) "/work/$R" 2>/dev/null || true
  '
echo "Randomness eval: $ROOT/${RESULTS_DIR:-results}/randomness-eval/"
