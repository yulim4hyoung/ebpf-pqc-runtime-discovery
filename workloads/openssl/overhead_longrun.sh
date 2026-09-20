#!/usr/bin/env bash
# Long-running RSA-2048 keygen loop for overhead measurement (TODO ③).
# workloads/openssl/classical.sh finishes in ~0.13s, so its M0/M3 timing
# comparison is dominated by run-to-run process-scheduling noise (Table 4's
# negative overhead values). This workload loops keygen enough times to run
# for tens of seconds, so the monitor's fixed attach/detach cost becomes
# negligible relative to total runtime and the overhead sign stops flipping.
set -euo pipefail
REPS="${1:-500}"

for i in $(seq 1 "$REPS"); do
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out "/tmp/oh_longrun_${i}.pem" 2>/dev/null
  rm -f "/tmp/oh_longrun_${i}.pem"
done
echo "[overhead-longrun] completed $REPS x RSA-2048 keygen"
