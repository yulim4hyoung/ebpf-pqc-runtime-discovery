#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
docker run --rm --privileged --pid=host \
  -v "$ROOT:/work" \
  -v /usr/lib/x86_64-linux-gnu/libcrypto.so.3:/usr/lib/x86_64-linux-gnu/libcrypto.so.3:ro \
  -v /usr/local/lib:/usr/local/lib:ro \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -w /work ubuntu:24.04 bash -c '
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq && apt-get install -y -qq openssl python3 python3-yaml libelf1 gcc 2>/dev/null | tail -1
    ulimit -l unlimited || true
    python3 scripts/rerun_overhead.py
    python3 scripts/aggregate_tuning.py
  '
