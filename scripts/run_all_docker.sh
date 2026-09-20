#!/usr/bin/env bash
# Run full experiment suite inside privileged Docker (for environments without sudo)
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${DOCKER_IMAGE:-ubuntu:24.04}"

echo "Running experiments in privileged Docker ($IMAGE)..."

docker run --rm --privileged \
  --pid=host \
  -v "$ROOT:/work" \
  -v /usr/lib/x86_64-linux-gnu/libcrypto.so.3:/usr/lib/x86_64-linux-gnu/libcrypto.so.3:ro \
  -v /usr/local/lib:/usr/local/lib:ro \
  -v /usr/local/include:/usr/local/include:ro \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  -w /work \
  "$IMAGE" \
  bash -c '
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq openssl python3 python3-pip python3-venv libelf1 gcc build-essential 2>/dev/null
    pip3 install -q matplotlib pyyaml 2>/dev/null || true

    ulimit -l unlimited 2>/dev/null || true

    ./scripts/check_environment.sh
    ./scripts/build.sh

    mkdir -p results/raw results/logs results/failures

    for wl in classical liboqs-mlkem negative; do
      for i in 1 2 3; do
        rid="docker-${wl}-${i}"
        echo "=== Run $rid ==="
        if ! ./scripts/run_experiment.sh "$rid" "$wl" 5 2>&1 | tee "results/logs/${rid}.log"; then
          cp "results/logs/${rid}.log" "results/failures/${rid}.log" 2>/dev/null || true
        fi
      done
    done

    python3 scripts/analyze.py
    python3 scripts/plot.py
    ./scripts/run_overhead.sh 5 2>&1 | tee results/logs/overhead.log
    echo "Docker experiment complete"
  '

echo "Results available at $ROOT/results/"
