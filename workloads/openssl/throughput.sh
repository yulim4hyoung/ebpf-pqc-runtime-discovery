#!/usr/bin/env bash
# High-frequency crypto ops for throughput benchmark
set -euo pipefail
OPS="${1:-100}"
ALG="${2:-RSA}"

for i in $(seq 1 "$OPS"); do
  openssl genpkey -algorithm "$ALG" -pkeyopt rsa_keygen_bits:2048 -out "/tmp/tp_${i}.pem" 2>/dev/null
done
echo "[throughput] completed $OPS x $ALG keygen"
