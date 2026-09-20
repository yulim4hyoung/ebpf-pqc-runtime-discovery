#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
make -j"$(nproc)"
echo "Build complete: $ROOT/build/crypto-monitor"
