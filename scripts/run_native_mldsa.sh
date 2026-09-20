#!/usr/bin/env bash
# Native OpenSSL 3.5+ ML-DSA detection experiment (vs liboqs baseline).
# Mirrors scripts/run_native_mlkem.sh for the signature family (TODO ①).
# Requires the host libcrypto.so.3 to be OpenSSL >= 3.5 (native ML-DSA).
# Three monitored cases, each with its own event stream:
#   native_evp  - workloads/openssl_native/mldsa_native_workload.c (EVP API)
#   native_cli  - openssl genpkey -algorithm ML-DSA-65 + pkeyutl sign/verify
#   liboqs      - workloads/liboqs/mldsa_workload.c (existing OQS_SIG baseline)
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

    mkdir -p results/native-mldsa results/logs

    gcc -Wall -O2 -o /tmp/mldsa-native \
      workloads/openssl_native/mldsa_native_workload.c -lcrypto
    gcc -Wall -O2 -o /tmp/mldsa_workload workloads/liboqs/mldsa_workload.c \
      -I/usr/local/include -L/usr/local/lib -loqs -Wl,-rpath,/usr/local/lib

    run_case() {
      name="$1"; shift
      rm -f "results/native-mldsa/${name}.jsonl"
      ./build/crypto-monitor -o "results/native-mldsa/${name}.jsonl" \
        -S "results/native-mldsa/${name}_stats.json" -p 1 -d 30 \
        2> "results/logs/native_mldsa_${name}.log" &
      MON=$!
      sleep 2
      "$@" || true
      sleep 1
      kill -TERM "$MON" 2>/dev/null || true
      wait "$MON" 2>/dev/null || true
    }

    run_native_cli() {
      rm -f "results/native-mldsa/native_cli.jsonl"
      ./build/crypto-monitor -o "results/native-mldsa/native_cli.jsonl" \
        -S "results/native-mldsa/native_cli_stats.json" -p 1 -d 30 \
        2> "results/logs/native_mldsa_native_cli.log" &
      MON=$!
      sleep 2
      openssl genpkey -algorithm ML-DSA-65 -out /tmp/mldsa_cli.pem || true
      printf "runtime-pqc-discovery ML-DSA cli test\n" > /tmp/mldsa_cli_msg.txt
      openssl pkeyutl -sign -inkey /tmp/mldsa_cli.pem -rawin \
        -in /tmp/mldsa_cli_msg.txt -out /tmp/mldsa_cli_sig.bin || true
      openssl pkeyutl -verify -inkey /tmp/mldsa_cli.pem -rawin \
        -in /tmp/mldsa_cli_msg.txt -sigfile /tmp/mldsa_cli_sig.bin || true
      sleep 1
      kill -TERM "$MON" 2>/dev/null || true
      wait "$MON" 2>/dev/null || true
    }

    run_case native_evp /tmp/mldsa-native
    run_native_cli
    run_case liboqs /tmp/mldsa_workload

    python3 scripts/analyze_native_mldsa.py
    chown -R "$(stat -c %u:%g /work/results)" results/native-mldsa 2>/dev/null || true
  '

echo "Results: $ROOT/results/native-mldsa/"
