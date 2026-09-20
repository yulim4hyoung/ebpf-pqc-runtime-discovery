#!/usr/bin/env bash
# OpenSSL classical crypto workloads
set -euo pipefail

echo "[workload] RSA-2048 keygen"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /tmp/test_rsa.pem 2>/dev/null
echo "[workload] ECDSA P-256 keygen"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out /tmp/test_ec.pem 2>/dev/null
echo "[workload] X25519 keygen"
openssl genpkey -algorithm X25519 -out /tmp/test_x25519.pem 2>/dev/null
echo "[workload] SHA-256 digest"
echo "test data" | openssl dgst -sha256
echo "[workload] AES-256-GCM encrypt"
key=$(openssl rand -hex 32)
iv=$(openssl rand -hex 12)
echo "secret" | openssl enc -aes-256-gcm -K "$key" -iv "$iv" 2>/dev/null || true
echo "[workload] done"
