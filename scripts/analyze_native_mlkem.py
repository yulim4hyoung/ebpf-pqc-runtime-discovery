#!/usr/bin/env python3
"""Summarize the native-vs-liboqs ML-KEM detection experiment.

Reads results/native-mlkem/*.jsonl (monitor event streams for three cases:
native EVP workload, openssl CLI genpkey, liboqs workload) and writes
results/native-mlkem/summary.md plus summary.json.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "results" / "native-mlkem"

CASES = {
    "native_evp": {"procs": {"mlkem-native"}},
    "native_cli": {"procs": {"openssl"}},
    "liboqs": {"procs": {"mlkem_workload"}},
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
        "detection_latency_us_median": sorted(
            e.get("detection_latency_us", 0) for e in crypto
        )[len(crypto) // 2]
        if crypto
        else None,
    }


def main() -> None:
    report = {}
    for case, cfg in CASES.items():
        report[case] = summarize(load(case, cfg["procs"]))

    (OUT / "summary.json").write_text(json.dumps(report, indent=2))

    lines = ["# Native OpenSSL 3.5 ML-KEM vs liboqs detection", ""]
    lines.append(
        "| Case | Crypto ev | RNG ev | PQC ev | Anchored PQC | Max conf | APIs |"
    )
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
    (OUT / "summary.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
