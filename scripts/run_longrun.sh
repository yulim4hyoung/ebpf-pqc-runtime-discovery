#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SEC="${LONGRUN_SEC:-3600}"
echo "Starting ${SEC}s longrun in Docker..."
docker run --rm --privileged --pid=host \
  -e LONGRUN_SEC="$SEC" \
  -v "$ROOT:/work" \
  -v /usr/lib/x86_64-linux-gnu/libcrypto.so.3:/usr/lib/x86_64-linux-gnu/libcrypto.so.3:ro \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -w /work ubuntu:24.04 bash -c "
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq && apt-get install -y -qq openssl python3 python3-yaml libelf1 2>/dev/null | tail -1
    ulimit -l unlimited || true
    LONGRUN_SEC=$SEC python3 scripts/patch_longrun.py
    python3 scripts/run_longrun.py 2>&1 | tee results/logs/longrun.log
  "
