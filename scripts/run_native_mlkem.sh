#!/usr/bin/env bash
# Native OpenSSL 3.5+ ML-KEM detection experiment (vs liboqs baseline).
# Requires the host libcrypto.so.3 to be OpenSSL >= 3.5 (native ML-KEM).
# The host libssl/libcrypto are mounted at a shadow path and bind-mounted
# over the container's copies AFTER apt finishes (dpkg cannot replace a
# bind-mounted file), so the monitored library is the host 3.5+ build.
# Three monitored cases, each with its own event stream:
#   native_evp  - workloads/openssl_native/mlkem_native_workload.c (EVP API)
#   native_cli  - openssl genpkey -algorithm ML-KEM-768
#   liboqs      - workloads/liboqs/mlkem_workload.c (existing baseline)
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${DOCKER_IMAGE:-ubuntu:24.04}"

# tracefs is needed for the getrandom syscall tracepoint; absent on WSL2 kernels, so mount only if present
TRACEFS_MOUNT=()
[ -d /sys/kernel/tracing ] && TRACEFS_MOUNT=(-v /sys/kernel/tracing:/sys/kernel/tracing:ro)
docker run --rm --privileged --pid=host \
  -v "$ROOT:/work" \
  -v /usr/lib/x86_64-linux-gnu/libcrypto.so.3:/hostssl/libcrypto.so.3:ro \
  -v /usr/lib/x86_64-linux-gnu/libssl.so.3:/hostssl/libssl.so.3:ro \
  -v /usr/local/lib:/usr/local/lib:ro \
  -v /usr/local/include:/usr/local/include:ro \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v /sys/fs/bpf:/sys/fs/bpf \
  "${TRACEFS_MOUNT[@]}" \
  -w /work "$IMAGE" bash -c '
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq gcc libssl-dev libelf1 zlib1g python3 openssl 2>/dev/null | tail -1
    ulimit -l unlimited 2>/dev/null || true

    # Overlay host OpenSSL 3.5+ on the standard path (post-apt, see header)
    mount --bind /hostssl/libcrypto.so.3 /usr/lib/x86_64-linux-gnu/libcrypto.so.3
    mount --bind /hostssl/libssl.so.3 /usr/lib/x86_64-linux-gnu/libssl.so.3
    openssl version

    mkdir -p results/native-mlkem results/logs

    gcc -Wall -O2 -o /tmp/mlkem-native \
      workloads/openssl_native/mlkem_native_workload.c -lcrypto
    gcc -Wall -O2 -o /tmp/mlkem_workload workloads/liboqs/mlkem_workload.c \
      -I/usr/local/include -L/usr/local/lib -loqs -Wl,-rpath,/usr/local/lib

    run_case() {
      name="$1"; shift
      rm -f "results/native-mlkem/${name}.jsonl"
      ./build/crypto-monitor -o "results/native-mlkem/${name}.jsonl" \
        -S "results/native-mlkem/${name}_stats.json" -p 1 -d 30 \
        2> "results/logs/native_mlkem_${name}.log" &
      MON=$!
      sleep 2
      "$@" || true
      sleep 1
      kill -TERM "$MON" 2>/dev/null || true
      wait "$MON" 2>/dev/null || true
    }

    run_case native_evp /tmp/mlkem-native
    run_case native_cli openssl genpkey -algorithm ML-KEM-768 -out /tmp/mlkem_key.pem
    run_case liboqs /tmp/mlkem_workload

    python3 scripts/analyze_native_mlkem.py
    chown -R "$(stat -c %u:%g /work/results)" results/native-mlkem 2>/dev/null || true
  '

echo "Results: $ROOT/results/native-mlkem/"
