#!/usr/bin/env python3
"""Summarize the native-vs-liboqs ML-DSA detection experiment.

Mirrors scripts/analyze_native_mlkem.py for the signature family (TODO ①).
Reads results/native-mldsa/*.jsonl (monitor event streams for three cases:
native EVP workload, openssl CLI genpkey+pkeyutl, liboqs workload) and
writes results/native-mldsa/summary.md plus summary.json.
"""
from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# OUT_DIR (default "results") lets a validation run write elsewhere.
OUT = ROOT / os.environ.get("OUT_DIR", "results") / "native-mldsa"

CASES = {
    "native_evp": {"procs": {"mldsa-native"}},
    "native_cli": {"procs": {"openssl"}},
    "liboqs": {"procs": {"mldsa_workload"}},
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

    lines = ["# Native OpenSSL 3.5 ML-DSA vs liboqs detection", ""]
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
    lines.append("")
    lines.append(
        "> Expected (2026-09-20): every case shows keygen, sign and verify. "
        "native_evp signs through EVP_PKEY_sign_message_init + EVP_PKEY_sign "
        "(the size query and the signature are two EVP_PKEY_sign calls, so sign "
        "counts twice per parameter set, as encapsulation does in the ML-KEM "
        "experiment); its sign/verify contexts inherit the generated key's name "
        "(A10), so all events are named and anchored at confidence 1.0. "
        "native_cli signs through the OpenSSL 3.5 openssl app (one-shot "
        "EVP_DigestSignInit_ex / EVP_DigestVerifyInit_ex): those two events are "
        "detected but carry no name, because pkeyutl decodes its key from the PEM "
        "file written by a separate genpkey process, and keys decoded from "
        "encodings are outside the name producers (the open gap named in the "
        "paper's future work)."
    )
    (OUT / "summary.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
