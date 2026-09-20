#!/usr/bin/env bash
# Validation run for the 2026-09-20 monitor changes:
#   A10  algorithm-name attribution for contexts created from a key
#        (EVP_PKEY_CTX_new_from_pkey / EVP_PKEY_CTX_new, key producers
#        keygen / fromdata / new_raw_*_key_ex, EVP_PKEY_CTX_free cleanup,
#        unnamed events reported as family "unknown")
#   A11  OQS_KEM_keypair / OQS_SIG_keypair emitted on return (anchored)
#
# Writes to results_a10a11/ and never touches results/ (the paper's numbers).
# Mount/overlay pattern copied from scripts/run_native_mlkem.sh and
# scripts/run_tls_handshake.sh (host OpenSSL 3.5 libcrypto/libssl bind-mounted
# over the container's copies after apt finishes).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${DOCKER_IMAGE:-ubuntu:24.04}"
OUT="${OUT_DIR:-results_a10a11}"

TRACEFS_MOUNT=()
[ -d /sys/kernel/tracing ] && TRACEFS_MOUNT=(-v /sys/kernel/tracing:/sys/kernel/tracing:ro)
docker run --rm --privileged --pid=host \
  -v "$ROOT:/work" \
  -v /usr/lib/x86_64-linux-gnu/libcrypto.so.3:/hostssl/libcrypto.so.3:ro \
  -v /usr/lib/x86_64-linux-gnu/libssl.so.3:/hostssl/libssl.so.3:ro \
  -v /usr/local/lib:/usr/local/lib:ro \
  -v /usr/local/include:/usr/local/include:ro \
  -v "${HOST_OPENSSL_INCLUDE:-/usr/include/openssl}:/hostssl/include/openssl:ro" \
  -v "${HOST_OPENSSL_INCLUDE_ARCH:-/usr/include/x86_64-linux-gnu/openssl}:/hostssl/include-arch/openssl:ro" \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v /sys/fs/bpf:/sys/fs/bpf \
  "${TRACEFS_MOUNT[@]}" \
  -e OUT="$OUT" \
  -w /work "$IMAGE" bash -c '
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq gcc libssl-dev libelf1 zlib1g python3 openssl curl 2>/dev/null | tail -1
    ulimit -l unlimited 2>/dev/null || true

    mount --bind /hostssl/libcrypto.so.3 /usr/lib/x86_64-linux-gnu/libcrypto.so.3
    mount --bind /hostssl/libssl.so.3 /usr/lib/x86_64-linux-gnu/libssl.so.3
    openssl version

    mkdir -p "$OUT" "$OUT/logs"

    gcc -Wall -O2 -o /tmp/mlkem-native workloads/openssl_native/mlkem_native_workload.c -lcrypto
    # 2026-09-20: the ML-DSA workload uses the 3.5 message-signing API -> host 3.5 headers
    gcc -Wall -O2 -I/hostssl/include -I/hostssl/include-arch \
      -o /tmp/mldsa-native workloads/openssl_native/mldsa_native_workload.c -lcrypto
    gcc -Wall -O2 -o /tmp/mlkem_workload workloads/liboqs/mlkem_workload.c \
      -I/usr/local/include -L/usr/local/lib -loqs -Wl,-rpath,/usr/local/lib
    gcc -Wall -O2 -o /tmp/mldsa_workload workloads/liboqs/mldsa_workload.c \
      -I/usr/local/include -L/usr/local/lib -loqs -Wl,-rpath,/usr/local/lib

    wait_ready() {  # block until the daemon has attached all probes
      for i in $(seq 1 600); do
        grep -q "monitor ready" "$1" 2>/dev/null && return 0
        sleep 0.05
      done
      echo "[warn] monitor readiness not observed for $1" >&2
    }

    start_mon() {
      name="$1"; dur="$2"
      rm -f "$OUT/${name}.jsonl"
      ./build/crypto-monitor -o "$OUT/${name}.jsonl" -S "$OUT/${name}_stats.json" \
        -p 1 -d "$dur" 2> "$OUT/logs/${name}_monitor.log" &
      MON=$!
      wait_ready "$OUT/logs/${name}_monitor.log"
    }
    stop_mon() {
      sleep 1
      kill -TERM "$MON" 2>/dev/null || true
      wait "$MON" 2>/dev/null || true
    }
    run_case() {  # run_case <name> <cmd...>
      name="$1"; shift
      start_mon "$name" 40
      "$@" > "$OUT/logs/${name}_workload.log" 2>&1 || true
      stop_mon
      echo "[case] $name done"
    }

    run_case native_evp   /tmp/mlkem-native
    run_case native_cli   openssl genpkey -algorithm ML-KEM-768 -out /tmp/mlkem_key.pem
    run_case native_mldsa /tmp/mldsa-native
    run_case liboqs_mlkem /tmp/mlkem_workload
    run_case liboqs_mldsa /tmp/mldsa_workload
    run_case curl_https   curl -sI --max-time 10 https://example.com

    # Real TLS 1.3 handshakes (server and client both run as "openssl")
    openssl req -x509 -newkey rsa:2048 -keyout /tmp/tls_server.key \
      -out /tmp/tls_server.crt -days 1 -nodes -subj "/CN=localhost" 2>/dev/null
    run_tls_case() {
      name="$1"; group="$2"
      start_mon "$name" 30
      openssl s_server -accept 4433 -cert /tmp/tls_server.crt -key /tmp/tls_server.key \
        -groups "$group" -naccept 1 -quiet > "$OUT/logs/${name}_server.log" 2>&1 &
      SRV=$!
      sleep 1
      openssl s_client -connect 127.0.0.1:4433 -groups "$group" </dev/null \
        > "$OUT/logs/${name}_client.log" 2>&1 || true
      sleep 1
      kill -TERM "$SRV" 2>/dev/null || true
      wait "$SRV" 2>/dev/null || true
      stop_mon
      echo "[case] $name done"
    }
    run_tls_case tls_pqc_kem X25519MLKEM768
    run_tls_case tls_classical_x25519 X25519

    python3 scripts/analyze_a10a11.py "$OUT"
    chown -R "$(stat -c %u:%g /work/results)" "$OUT" 2>/dev/null || true
  '

echo "Results: $ROOT/$OUT/summary.md"
