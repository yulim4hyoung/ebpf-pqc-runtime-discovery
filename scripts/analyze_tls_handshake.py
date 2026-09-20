#!/usr/bin/env python3
"""Summarize the real TLS 1.3 PQC handshake detection experiment (TODO ②).

Reads results/tls-handshake/*.jsonl (monitor event streams for the
pqc_kem and classical_x25519 handshake cases; both server and client show
up under the same "openssl" process name, aggregated per case since each
case already runs in its own monitored session) and writes
results/tls-handshake/summary.md plus summary.json.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "results" / "tls-handshake"

CASES = {
    "pqc_kem": {"procs": {"openssl"}},
    "classical_x25519": {"procs": {"openssl"}},
}


def load(case: str, procs: set[str]) -> list[dict]:
    path = OUT / f"{case}.jsonl"
    rows = []
    if not path.exists():
        return rows
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if ev.get("process") in procs:
            rows.append(ev)
    return rows


def summarize(rows: list[dict]) -> dict:
    crypto = [e for e in rows if e.get("event_type") == 1]
    rand = [e for e in rows if e.get("event_type") != 1]
    return {
        "events_total": len(rows),
        "crypto_events": len(crypto),
        "random_events": len(rand),
        "by_api": dict(Counter(e.get("api", "?") for e in crypto)),
        "by_algorithm": dict(Counter(e.get("algorithm", "") for e in crypto)),
        "pqc_events": sum(1 for e in crypto if e.get("crypto_family") == "PQC"),
        "anchored_events": sum(
            1 for e in crypto if e.get("randomness_recently_observed")
        ),
        "anchored_pqc": sum(
            1
            for e in crypto
            if e.get("crypto_family") == "PQC"
            and e.get("randomness_recently_observed")
        ),
        "max_confidence": max((e.get("confidence", 0) for e in crypto), default=0),
    }


def main() -> None:
    report = {}
    for case, cfg in CASES.items():
        report[case] = summarize(load(case, cfg["procs"]))

    (OUT / "summary.json").write_text(json.dumps(report, indent=2))

    lines = ["# Real TLS 1.3 handshake: PQC hybrid group vs classical group", ""]
    lines.append("| Case | Crypto ev | RNG ev | PQC ev | Anchored PQC | Max conf | APIs |")
    lines.append("|---|---:|---:|---:|---:|---:|---|")
    for case, s in report.items():
        apis = ", ".join(f"{k}×{v}" for k, v in sorted(s["by_api"].items()))
        lines.append(
            f"| {case} | {s['crypto_events']} | {s['random_events']} | "
            f"{s['pqc_events']} | {s['anchored_pqc']} | {s['max_confidence']} | {apis} |"
        )
    lines.append("")
    for case, s in report.items():
        algs = {k: v for k, v in s["by_algorithm"].items() if k}
        lines.append(f"- **{case}** algorithms attributed: {algs or 'none'}")
    lines.append("")
    lines.append(
        "> Server and client both run as \"openssl\" and are aggregated "
        "together within each case; the two cases (pqc_kem vs "
        "classical_x25519) are separate monitored sessions, so there is no "
        "cross-contamination between them."
    )
    (OUT / "summary.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
