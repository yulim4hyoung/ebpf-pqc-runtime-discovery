#!/usr/bin/env bash
set -euo pipefail

OPENSSL_VER=$(openssl version | awk '{print $2}')
MAJOR=$(echo "$OPENSSL_VER" | cut -d. -f1)
MINOR=$(echo "$OPENSSL_VER" | cut -d. -f2)

if [ "$MAJOR" -lt 3 ] || { [ "$MAJOR" -eq 3 ] && [ "$MINOR" -lt 5 ]; }; then
  echo "[SKIP] OpenSSL $OPENSSL_VER < 3.5 — native ML-KEM/ML-DSA unavailable"
  exit 0
fi

for alg in ML-KEM-512 ML-KEM-768 ML-KEM-1024; do
  echo "[workload] $alg keygen"
  openssl genpkey -algorithm "$alg" -out "/tmp/${alg}.pem" 2>/dev/null || echo "[SKIP] $alg"
done

echo "[workload] done"
