#!/usr/bin/env python3
"""Aggregate per-round summary.json files into tuning_comparison.json."""
from __future__ import annotations

import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TUNING = ROOT / "results" / "tuning"
PROCESSED = ROOT / "results" / "processed"
CONFIG = ROOT / "config" / "tuning.yaml"


def main() -> None:
    try:
        import yaml
        cfg = yaml.safe_load(CONFIG.read_text())
        rounds = cfg.get("tuning_rounds", [])
    except Exception:
        rounds = [{"id": d.name} for d in sorted(TUNING.iterdir()) if d.is_dir()]

    all_results = []
    for rnd in rounds:
        rid = rnd["id"] if isinstance(rnd, dict) else rnd
        sf = TUNING / rid / "summary.json"
        if sf.exists():
            all_results.extend(json.loads(sf.read_text()))

    comparison = {"rounds": rounds, "results": all_results}
    PROCESSED.mkdir(parents=True, exist_ok=True)
    (PROCESSED / "tuning_comparison.json").write_text(json.dumps(comparison, indent=2, default=str))

    lat_rows = [r for r in all_results if r.get("benchmark") == "latency"]
    oh_rows = [r for r in all_results if r.get("benchmark") == "overhead"]
    rows = []
    for r in lat_rows:
        lat = r.get("latency_us", {})
        oh = next((o for o in oh_rows if o["round"] == r["round"]), {})
        rows.append({
            "round": r["round"],
            "latency_median_us": lat.get("median", 0),
            "latency_p95_us": lat.get("p95", 0),
            "latency_p99_us": lat.get("p99", 0),
            "latency_mean_us": lat.get("mean", 0),
            "overhead_pct": round(oh.get("overhead_pct", 0), 2) if oh else "",
            "m0_sec": round(oh.get("m0_mean_sec", 0), 4) if oh else "",
            "m3_sec": round(oh.get("m3_mean_sec", 0), 4) if oh else "",
        })
    if rows:
        with (PROCESSED / "tuning_comparison.csv").open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=rows[0].keys())
            w.writeheader()
            w.writerows(rows)

    print(f"Aggregated {len(all_results)} results from {len(lat_rows)} rounds")
    print(f"Wrote {PROCESSED / 'tuning_comparison.json'}")


if __name__ == "__main__":
    main()
