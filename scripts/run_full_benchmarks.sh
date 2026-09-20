#!/usr/bin/env bash
# Full benchmark suite: 4 tuning rounds + plots + paper
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${DOCKER_IMAGE:-ubuntu:24.04}"
LONGRUN_SEC="${LONGRUN_SEC:-3600}"
HOST_UID="$(id -u)"
HOST_GID="$(id -g)"

echo "=== Full Benchmark Suite (longrun=${LONGRUN_SEC}s) ==="

# tracefs is needed for the getrandom syscall tracepoint; absent on WSL2 kernels, so mount only if present
TRACEFS_MOUNT=()
[ -d /sys/kernel/tracing ] && TRACEFS_MOUNT=(-v /sys/kernel/tracing:/sys/kernel/tracing:ro)
docker run --rm --privileged \
  --pid=host \
  -e LONGRUN_SEC="$LONGRUN_SEC" \
  -e HOST_UID="$HOST_UID" \
  -e HOST_GID="$HOST_GID" \
  -v "$ROOT:/work" \
  -v /usr/local/lib:/usr/local/lib:ro \
  -v /usr/local/include:/usr/local/include:ro \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v /sys/fs/bpf:/sys/fs/bpf \
  "${TRACEFS_MOUNT[@]}" \
  -w /work \
  "$IMAGE" \
  bash -c '
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq openssl python3 python3-pip python3-yaml python3-matplotlib libelf1 gcc build-essential 2>/dev/null | tail -1
    pip3 install -q matplotlib pyyaml --break-system-packages 2>/dev/null || true

    ulimit -l unlimited 2>/dev/null || true

    # Patch longrun duration from env
    python3 scripts/patch_longrun.py

    ./scripts/build.sh
    mkdir -p results/tuning results/processed results/plots paper

    echo "=== Running 4 tuning rounds ==="
    python3 scripts/run_tuning_benchmarks.py 2>&1 | tee results/logs/tuning_benchmarks.log

    echo "=== Generating plots ==="
    python3 scripts/plot.py 2>&1 | tee results/logs/plot.log

    echo "=== Generating paper draft ==="
    python3 scripts/generate_paper_results.py 2>&1 | tee results/logs/paper.log

    chown -R "${HOST_UID}:${HOST_GID}" /work/results /work/paper 2>/dev/null || true

    echo "=== Done ==="
  '

echo "Results: $ROOT/results/"
echo "Paper:   $ROOT/paper/paper_draft.md"
echo "Plots:   $ROOT/results/plots/"
