#!/usr/bin/env bash
# Negative workloads — random use without crypto
set -euo pipefail

echo "[negative] UUID generation"
python3 - <<'PY'
import uuid
for _ in range(3):
    print(uuid.uuid4())
PY

echo "[negative] random filename"
mktemp /tmp/neg_XXXXXX

echo "[negative] /dev/urandom read"
head -c 64 /dev/urandom | wc -c

echo "[negative] getrandom loop"
python3 - <<'PY'
import os
for _ in range(10):
    os.getrandom(32)
print("[negative] getrandom done")
PY

echo "[negative] Monte Carlo pi estimate"
python3 - <<'PY'
import random
n = 10000
inside = sum(1 for _ in range(n) if random.random()**2 + random.random()**2 <= 1)
print(f"pi ~ {4*inside/n}")
PY

echo "[negative] done"
