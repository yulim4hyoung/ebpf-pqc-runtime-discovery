#!/usr/bin/env python3
"""Summarize the A10/A11 validation run (results_a10a11/) and compare it with the
paper's baseline logs under results/ where the same case exists.

Per case: every cryptographic event (api, algorithm, family, anchored, delta,
confidence) plus counts of named/unnamed events, family distribution,
anchored events and confidence levels. Writes <out>/summary.md and
<out>/summary.json.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / (sys.argv[1] if len(sys.argv) > 1 else "results_a10a11")

# case -> (process names to keep, baseline jsonl relative to results/ or None)
CASES = {
    "native_evp": ({"mlkem-native"}, "native-mlkem/native_evp.jsonl"),
    "native_cli": ({"openssl"}, "native-mlkem/native_cli.jsonl"),
    "native_mldsa": ({"mldsa-native"}, "native-mldsa/native_evp.jsonl"),
    "liboqs_mlkem": ({"mlkem_workload"}, "native-mlkem/liboqs.jsonl"),
    "liboqs_mldsa": ({"mldsa_workload"}, "native-mldsa/liboqs.jsonl"),
    "curl_https": ({"curl"}, "qed-realworld/curl-https/events.jsonl"),
    "tls_pqc_kem": ({"openssl"}, "tls-handshake/pqc_kem.jsonl"),
    "tls_classical_x25519": ({"openssl"}, "tls-handshake/classical_x25519.jsonl"),
}


def load(path: Path, procs: set[str]) -> list[dict]:
    rows = []
    if not path.exists():
        return rows
    for line in path.read_text(errors="ignore").splitlines():
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


def crypto_only(rows: list[dict]) -> list[dict]:
    return [e for e in rows if e.get("event_type") == 1 and e.get("api") != "Esys_GetRandom"]


def summarize(rows: list[dict]) -> dict:
    cr = crypto_only(rows)
    return {
        "events_total": len(rows),
        "crypto_events": len(cr),
        "named": sum(1 for e in cr if e.get("algorithm")),
        "unnamed": sum(1 for e in cr if not e.get("algorithm")),
        "by_api": dict(Counter(e.get("api", "?") for e in cr)),
        "by_algorithm": dict(Counter(e.get("algorithm", "") or "(none)" for e in cr)),
        "by_family": dict(Counter(e.get("crypto_family", "?") for e in cr)),
        "anchored": sum(1 for e in cr if e.get("randomness_recently_observed")),
        "confidence": dict(Counter(str(e.get("confidence")) for e in cr)),
        "max_confidence": max((e.get("confidence", 0) for e in cr), default=0),
    }


def event_rows(rows: list[dict]) -> list[str]:
    lines = ["| # | API | algorithm | family | anchored | Δt (μs) | conf |", "|---:|---|---|---|:-:|---:|---:|"]
    for i, e in enumerate(crypto_only(rows), 1):
        lines.append(
            f"| {i} | {e.get('api')} | {e.get('algorithm') or '(none)'} | {e.get('crypto_family')} | "
            f"{'yes' if e.get('randomness_recently_observed') else 'no'} | "
            f"{e.get('random_delta_us', 0) if e.get('randomness_recently_observed') else ''} | {e.get('confidence')} |"
        )
    return lines


def main() -> None:
    report = {}
    md = ["# A10/A11 validation (2026-09-20 monitor) vs paper baseline", ""]
    md.append("Baseline = the logs under `results/` that the paper's numbers come from (unchanged).")
    md.append("")
    md.append("| Case | Crypto ev (new/base) | Named (new/base) | Anchored (new/base) | Family new | Family base | Conf new | Conf base |")
    md.append("|---|---:|---:|---:|---|---|---|---|")
    details = []
    for case, (procs, base_rel) in CASES.items():
        new_rows = load(OUT / f"{case}.jsonl", procs)
        base_rows = load(ROOT / "results" / base_rel, procs) if base_rel else []
        ns, bs = summarize(new_rows), summarize(base_rows)
        report[case] = {"new": ns, "baseline": bs}
        md.append(
            f"| {case} | {ns['crypto_events']}/{bs['crypto_events']} | {ns['named']}/{bs['named']} | "
            f"{ns['anchored']}/{bs['anchored']} | {ns['by_family']} | {bs['by_family']} | {ns['confidence']} | {bs['confidence']} |"
        )
        details += [f"## {case}", "", f"process filter: `{sorted(procs)}`", "", "### new"] + event_rows(new_rows)
        details += ["", "### baseline"] + (event_rows(base_rows) if base_rows else ["(no baseline log)"]) + [""]
    md += ["", *details]
    (OUT / "summary.json").write_text(json.dumps(report, indent=2))
    (OUT / "summary.md").write_text("\n".join(md) + "\n")
    print("\n".join(md[:14]))
    print(f"\nwritten {OUT / 'summary.md'}")


if __name__ == "__main__":
    main()
