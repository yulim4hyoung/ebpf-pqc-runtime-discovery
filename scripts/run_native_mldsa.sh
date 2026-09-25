#!/usr/bin/env bash
# Native OpenSSL 3.5+ ML-DSA detection experiment (vs liboqs baseline).
# Mirrors scripts/run_native_mlkem.sh for the signature family (TODO ①).
# Requires, on the host: libcrypto.so.3/libssl.so.3 from OpenSSL >= 3.5, the
# matching headers (libssl-dev) and the matching `openssl` command.
# Three monitored cases, each with its own event stream:
#   native_evp  - workloads/openssl_native/mldsa_native_workload.c (EVP API,
#                 EVP_PKEY_sign_message_init + EVP_PKEY_sign, OpenSSL >= 3.5)
#   native_cli  - openssl genpkey -algorithm ML-DSA-65 + pkeyutl sign/verify
#   liboqs      - workloads/liboqs/mldsa_workload.c (existing OQS_SIG baseline)
#
# 2026-09-20 revision (results/logs/native_mldsa_prefix_*.log document the
# earlier failure):
#   * The workload is compiled against the host 3.5 headers (bind-mounted at
#     /hostssl/include{,-arch}); the container libssl-dev is 3.0, which lacks
#     the message-signing API that ML-DSA requires.
#   * The CLI case runs the host `openssl` command (bind-mounted at
#     /hostssl/openssl) so that application and library are the same 3.5
#     release. The container's own `openssl` is the 3.0 application: with
#     the 3.5 library underneath it, `pkeyutl -rawin` drives ML-DSA through
#     the streaming EVP_DigestSignUpdate() path, which the one-shot ML-DSA
#     provider rejects ("provider signature not supported").
#   * Workload and CLI output and exit codes are recorded in
#     results/logs/native_mldsa_<case>_cmd.log instead of being discarded.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${DOCKER_IMAGE:-ubuntu:24.04}"
HOST_OPENSSL="$(readlink -f "${HOST_OPENSSL:-$(command -v openssl)}")"
HOST_INC="${HOST_OPENSSL_INCLUDE:-/usr/include/openssl}"
HOST_INC_ARCH="${HOST_OPENSSL_INCLUDE_ARCH:-/usr/include/x86_64-linux-gnu/openssl}"
for p in "$HOST_OPENSSL" "$HOST_INC/evp.h" "$HOST_INC_ARCH/configuration.h"; do
  [ -e "$p" ] || { echo "missing on host: $p (need OpenSSL >= 3.5 command and libssl-dev)" >&2; exit 1; }
done

# tracefs is needed for the getrandom syscall tracepoint; absent on WSL2 kernels, so mount only if present
TRACEFS_MOUNT=()
[ -d /sys/kernel/tracing ] && TRACEFS_MOUNT=(-v /sys/kernel/tracing:/sys/kernel/tracing:ro)
docker run --rm --privileged --pid=host \
  -v "$ROOT:/work" \
  -v /usr/lib/x86_64-linux-gnu/libcrypto.so.3:/hostssl/libcrypto.so.3:ro \
  -v /usr/lib/x86_64-linux-gnu/libssl.so.3:/hostssl/libssl.so.3:ro \
  -v "$HOST_OPENSSL:/hostssl/openssl:ro" \
  -v "$HOST_INC:/hostssl/include/openssl:ro" \
  -v "$HOST_INC_ARCH:/hostssl/include-arch/openssl:ro" \
  -v /usr/local/lib:/usr/local/lib:ro \
  -v /usr/local/include:/usr/local/include:ro \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v /sys/fs/bpf:/sys/fs/bpf \
  "${TRACEFS_MOUNT[@]}" \
  -e OUT_DIR="${OUT_DIR:-results}" \
  -w /work "$IMAGE" bash -c '
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq gcc libssl-dev libelf1 zlib1g libzstd1 python3 openssl 2>/dev/null | tail -1
    ulimit -l unlimited 2>/dev/null || true

    # Overlay host OpenSSL 3.5+ on the standard path (post-apt, see header)
    mount --bind /hostssl/libcrypto.so.3 /usr/lib/x86_64-linux-gnu/libcrypto.so.3
    mount --bind /hostssl/libssl.so.3 /usr/lib/x86_64-linux-gnu/libssl.so.3
    echo "container openssl: $(openssl version)"
    echo "host openssl     : $(/hostssl/openssl version)"
    HV="$(/hostssl/openssl version | cut -d" " -f2)"
    case "$HV" in
      3.[5-9]*|[4-9].*) ;;
      *) echo "host openssl command is $HV, need >= 3.5" >&2; exit 1 ;;
    esac

    R="${OUT_DIR:-results}"
    mkdir -p "$R/native-mldsa" "$R/logs"

    gcc -Wall -O2 -I/hostssl/include -I/hostssl/include-arch \
      -o /tmp/mldsa-native workloads/openssl_native/mldsa_native_workload.c -lcrypto
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
      name="$1"
      rm -f "$R/native-mldsa/${name}.jsonl"
      ./build/crypto-monitor -o "$R/native-mldsa/${name}.jsonl" \
        -S "$R/native-mldsa/${name}_stats.json" -p 1 -d 40 \
        2> "$R/logs/native_mldsa_${name}.log" &
      MON=$!
      wait_ready "$R/logs/native_mldsa_${name}.log"
    }
    stop_mon() {
      sleep 1
      kill -TERM "$MON" 2>/dev/null || true
      wait "$MON" 2>/dev/null || true
    }
    logged() {  # logged <log> <cmd...>: record stdout+stderr and exit code, never abort
      log="$1"; shift
      echo "\$ $*" >> "$log"
      rc=0; "$@" >> "$log" 2>&1 || rc=$?
      echo "rc=$rc" >> "$log"
      return 0
    }

    run_case() {  # run_case <name> <cmd...>
      name="$1"; shift
      cmdlog="$R/logs/native_mldsa_${name}_cmd.log"
      : > "$cmdlog"
      start_mon "$name"
      logged "$cmdlog" "$@"
      stop_mon
      echo "[case] $name done: $(tail -1 "$cmdlog")"
    }

    run_native_cli() {
      cmdlog="$R/logs/native_mldsa_native_cli_cmd.log"
      : > "$cmdlog"
      echo "# $(/hostssl/openssl version)" >> "$cmdlog"
      printf "runtime-pqc-discovery ML-DSA cli test\n" > /tmp/mldsa_cli_msg.txt
      start_mon native_cli
      logged "$cmdlog" /hostssl/openssl genpkey -algorithm ML-DSA-65 -out /tmp/mldsa_cli.pem
      logged "$cmdlog" /hostssl/openssl pkeyutl -sign -inkey /tmp/mldsa_cli.pem -rawin \
        -in /tmp/mldsa_cli_msg.txt -out /tmp/mldsa_cli_sig.bin
      echo "signature size: $(stat -c %s /tmp/mldsa_cli_sig.bin 2>/dev/null || echo none) bytes" >> "$cmdlog"
      logged "$cmdlog" /hostssl/openssl pkeyutl -verify -inkey /tmp/mldsa_cli.pem -rawin \
        -in /tmp/mldsa_cli_msg.txt -sigfile /tmp/mldsa_cli_sig.bin
      stop_mon
      echo "[case] native_cli done: $(grep -c "^rc=0" "$cmdlog")/3 commands rc=0"
    }

    run_case native_evp /tmp/mldsa-native
    run_native_cli
    run_case liboqs /tmp/mldsa_workload

    python3 scripts/analyze_native_mldsa.py
    chown -R "$(stat -c %u:%g /work)" "$R/native-mldsa" "$R/logs" 2>/dev/null || true
  '

echo "Results: $ROOT/${OUT_DIR:-results}/native-mldsa/"
