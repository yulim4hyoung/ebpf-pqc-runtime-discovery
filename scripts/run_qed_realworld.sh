#!/usr/bin/env bash
# Test QED paper real-world apps (TPM, network, coreutils) with runtime eBPF monitor
# Ref: https://github.com/norrathep/qed
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
QED="${QED_ROOT:-$ROOT/../qed}"

echo "=== QED Real-World Application Tests ==="
echo "QED repo: $QED"

# tracefs is needed for the getrandom syscall tracepoint; absent on WSL2 kernels, so mount only if present
TRACEFS_MOUNT=()
[ -d /sys/kernel/tracing ] && TRACEFS_MOUNT=(-v /sys/kernel/tracing:/sys/kernel/tracing:ro)
docker run --rm --privileged --pid=host \
  -v "$ROOT:/work" \
  -v "$QED:/work/qed:ro" \
  -v "$ROOT/build/crypto-monitor:/work/build/crypto-monitor:ro" \
  -v "$ROOT/build/crypto_monitor.bpf.o:/work/build/crypto_monitor.bpf.o:ro" \
  -v /usr/local/lib:/usr/local/lib:ro \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v /sys/fs/bpf:/sys/fs/bpf \
  "${TRACEFS_MOUNT[@]}" \
  -e RESULTS_DIR="${RESULTS_DIR:-results}" \
  -w /work ubuntu:24.04 bash -c '
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq openssl python3 python3-yaml libelf1 gcc build-essential zlib1g-dev \
      tpm2-tools swtpm swtpm-tools libtss2-esys-3.0.2-0 libtss2-mu-4.0.1-0 \
      libtss2-tcti-swtpm0 curl wget 2>/dev/null | tail -1

    # Install libcrypto 1.1 for QED ssh/tpm binaries
    apt-get install -y -qq libssl1.1 2>/dev/null || {
      echo "libssl1.1 not in repo, trying manual fetch"
      apt-get install -y -qq wget
      wget -q http://archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2_amd64.deb -O /tmp/libssl.deb || true
      dpkg -i /tmp/libssl.deb 2>/dev/null || true
    }

    ulimit -l unlimited || true

    # Use pre-built monitor from host (avoid rebuild in container)
    if [ ! -x /work/build/crypto-monitor ]; then
      apt-get install -y -qq zlib1g libelf1 2>/dev/null
      ./scripts/build.sh || echo "build failed, continuing if binary exists"
    fi

    # TPM software simulator (QED tpm2-tools need TCTI)
    mkdir -p /tmp/tpmstate
    swtpm socket --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 \
      --flags not-need-init --tpmstate dir=/tmp/tpmstate &
    sleep 2
    export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=2321"
    tpm2_startup -c 2>/dev/null || true

    ls -la /work/build/crypto-monitor
    R="${RESULTS_DIR:-results}"
    mkdir -p "$R/logs" "$R/processed" "$R/qed-realworld" "$R/randomness-eval"
    python3 scripts/run_qed_realworld.py 2>&1 | tee "$R/logs/qed_realworld.log"
    python3 scripts/run_randomness_eval.py 2>&1 | tee "$R/logs/randomness_eval.log"
    chown -R $(stat -c '%u:%g' /work/results) "/work/$R" 2>/dev/null || true
  '

echo "Results: $ROOT/${RESULTS_DIR:-results}/qed-realworld/"
echo "Randomness eval: $ROOT/${RESULTS_DIR:-results}/randomness-eval/"
