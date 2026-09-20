#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
BIN="$ROOT/workloads/liboqs/mlkem_workload"
if [ ! -x "$BIN" ]; then
  gcc -Wall -O2 -o "$BIN" "$ROOT/workloads/liboqs/mlkem_workload.c" \
    -I/usr/local/include -L/usr/local/lib -loqs -Wl,-rpath,/usr/local/lib
fi
for alg in ML-KEM-512 ML-KEM-768 ML-KEM-1024; do
  "$BIN" "$alg" || true
done
