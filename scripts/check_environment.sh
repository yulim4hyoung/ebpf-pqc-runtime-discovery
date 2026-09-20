#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/results"
mkdir -p "$OUT"

JSON="$OUT/environment.json"
MD="$OUT/environment.md"

{
  echo "{"
  echo "  \"timestamp\": \"$(date -Iseconds)\","
  echo "  \"uname\": \"$(uname -a | sed 's/"/\\"/g')\","
  echo "  \"openssl\": \"$(openssl version 2>/dev/null | sed 's/"/\\"/g' || echo unknown)\","
  echo "  \"clang\": \"$(clang --version 2>/dev/null | head -1 | sed 's/"/\\"/g' || echo unknown)\","
  echo "  \"bpftool\": \"$(${BPFTOOL:-bpftool} version 2>/dev/null | head -1 | sed 's/"/\\"/g' || echo unknown)\","
  echo "  \"btf\": $(test -r /sys/kernel/btf/vmlinux && echo true || echo false),"
  echo "  \"liboqs\": $(test -r /usr/local/lib/liboqs.so && echo true || echo false),"
  echo "  \"uid\": $(id -u),"
  echo "  \"kernel_config\": {"
  for k in CONFIG_BPF CONFIG_BPF_SYSCALL CONFIG_UPROBE_EVENTS CONFIG_KPROBE_EVENTS CONFIG_BPF_JIT; do
    v=$(zcat /proc/config.gz 2>/dev/null | grep "^${k}=" | cut -d= -f2 || echo unknown)
    echo "    \"${k}\": \"${v}\","
  done
  echo "    \"CONFIG_BPF\": \"end\""
  echo "  }"
  echo "}"
} > "$JSON" 2>/dev/null || true

{
  echo "# Environment"
  echo
  echo "- Date: $(date -Iseconds)"
  echo "- Host: $(hostname)"
  echo "- Kernel: $(uname -r)"
  echo "- OpenSSL: $(openssl version 2>/dev/null || echo N/A)"
  echo "- BTF: $(test -r /sys/kernel/btf/vmlinux && echo available || echo missing)"
  echo "- liboqs: $(test -r /usr/local/lib/liboqs.so && echo present || echo absent)"
  echo "- UID: $(id -u) (root required for BPF load unless CAP_BPF set)"
  uname -a
  echo
  cat /etc/os-release 2>/dev/null || true
  echo
  lscpu 2>/dev/null | head -20 || true
  echo
  free -h 2>/dev/null || true
} > "$MD"

echo "Wrote $JSON and $MD"
