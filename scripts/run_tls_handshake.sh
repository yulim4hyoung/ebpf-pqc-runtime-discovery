#!/usr/bin/env bash
# Real TLS 1.3 PQC handshake detection experiment (TODO ②) — the highest-
# impact addition: instead of a synthetic ML-KEM workload, this drives an
# actual TLS 1.3 handshake through openssl s_server/s_client and checks
# that the monitor's existing probes catch the KEM operations inside it.
# Requires the host libcrypto.so.3/libssl.so.3 to be OpenSSL >= 3.5
# (native X25519MLKEM768 hybrid group support). Mount/overlay pattern
# copied from scripts/run_native_mlkem.sh.
# Two monitored cases, each with its own event stream:
#   pqc_kem           - handshake with -groups X25519MLKEM768 (hybrid PQC)
#   classical_x25519  - handshake with -groups X25519 (classical baseline)
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${DOCKER_IMAGE:-ubuntu:24.04}"

TRACEFS_MOUNT=()
[ -d /sys/kernel/tracing ] && TRACEFS_MOUNT=(-v /sys/kernel/tracing:/sys/kernel/tracing:ro)
docker run --rm --privileged --pid=host \
  -v "$ROOT:/work" \
  -v /usr/lib/x86_64-linux-gnu/libcrypto.so.3:/hostssl/libcrypto.so.3:ro \
  -v /usr/lib/x86_64-linux-gnu/libssl.so.3:/hostssl/libssl.so.3:ro \
  -v /usr/local/lib:/usr/local/lib:ro \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v /sys/fs/bpf:/sys/fs/bpf \
  "${TRACEFS_MOUNT[@]}" \
  -w /work "$IMAGE" bash -c '
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq openssl libelf1 zlib1g python3 2>/dev/null | tail -1
    ulimit -l unlimited 2>/dev/null || true

    mount --bind /hostssl/libcrypto.so.3 /usr/lib/x86_64-linux-gnu/libcrypto.so.3
    mount --bind /hostssl/libssl.so.3 /usr/lib/x86_64-linux-gnu/libssl.so.3
    openssl version

    mkdir -p results/tls-handshake results/logs

    # Self-signed server cert (RSA is fine here — the group flag governs
    # the key-exchange KEM, not the certificate key type).
    openssl req -x509 -newkey rsa:2048 -keyout /tmp/tls_server.key \
      -out /tmp/tls_server.crt -days 1 -nodes -subj "/CN=localhost" 2>/dev/null

    run_tls_case() {
      name="$1"; group="$2"
      rm -f "results/tls-handshake/${name}.jsonl"
      ./build/crypto-monitor -o "results/tls-handshake/${name}.jsonl" \
        -S "results/tls-handshake/${name}_stats.json" -p 1 -d 20 \
        2> "results/logs/tls_${name}.log" &
      MON=$!
      sleep 1

      openssl s_server -accept 4433 -cert /tmp/tls_server.crt \
        -key /tmp/tls_server.key -groups "$group" -naccept 1 -quiet \
        > "/tmp/tls_${name}_server.log" 2>&1 &
      SRV=$!
      sleep 1

      openssl s_client -connect 127.0.0.1:4433 -groups "$group" \
        </dev/null > "/tmp/tls_${name}_client.log" 2>&1 || true
      sleep 1

      kill -TERM "$SRV" 2>/dev/null || true
      wait "$SRV" 2>/dev/null || true
      sleep 1
      kill -TERM "$MON" 2>/dev/null || true
      wait "$MON" 2>/dev/null || true
    }

    run_tls_case pqc_kem X25519MLKEM768
    run_tls_case classical_x25519 X25519

    python3 scripts/analyze_tls_handshake.py
    chown -R "$(stat -c %u:%g /work/results)" results/tls-handshake 2>/dev/null || true
  '

echo "Results: $ROOT/results/tls-handshake/"
