#!/usr/bin/env python3
"""Analyze experiment results: accuracy, overhead, latency."""
from __future__ import annotations

import csv
import json
import math
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"
PROCESSED = RESULTS / "processed"
PROCESSED.mkdir(parents=True, exist_ok=True)


def load_jsonl(path: Path) -> list[dict]:
    rows = []
    if not path.exists():
        return rows
    for line in path.read_text().splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def compute_accuracy(events: list[dict], ground_truth: dict) -> dict:
    tp = tn = fp = fn = 0
    crypto_events = [e for e in events if e.get("event_type") == 1 or
                     e.get("api", "").startswith(("EVP_", "OQS_"))]

    expected_crypto = ground_truth.get("expected_crypto", False)
    detected = len(crypto_events) > 0

    if expected_crypto and detected:
        tp = 1
    elif expected_crypto and not detected:
        fn = 1
    elif not expected_crypto and detected:
        fp = 1
    else:
        tn = 1

    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    acc = (tp + tn) / max(tp + tn + fp + fn, 1)

    return {
        "TP": tp, "TN": tn, "FP": fp, "FN": fn,
        "precision": prec, "recall": rec, "f1": f1, "accuracy": acc,
        "samples": len(events),
    }


def stats(values: list[float]) -> dict:
    if not values:
        return {"n": 0, "mean": 0, "median": 0, "stdev": 0, "p95": 0, "p99": 0}
    s = sorted(values)
    n = len(s)
    return {
        "n": n,
        "mean": statistics.mean(s),
        "median": statistics.median(s),
        "stdev": statistics.stdev(s) if n > 1 else 0.0,
        "p95": s[min(int(n * 0.95), n - 1)],
        "p99": s[min(int(n * 0.99), n - 1)],
    }


def main() -> int:
    summary = {"accuracy": [], "overhead": []}

    for gt_file in sorted((RESULTS / "raw").glob("**/ground_truth.json")):
        run_dir = gt_file.parent
        events = load_jsonl(run_dir / "events.jsonl")
        gt = json.loads(gt_file.read_text())
        metrics = compute_accuracy(events, gt)
        metrics["run_id"] = gt.get("run_id", run_dir.name)
        metrics["expected_algorithm"] = gt.get("expected_algorithm", "")
        summary["accuracy"].append(metrics)

    acc_path = PROCESSED / "accuracy_summary.json"
    acc_path.write_text(json.dumps(summary, indent=2))

    csv_path = PROCESSED / "accuracy_summary.csv"
    if summary["accuracy"]:
        keys = list(summary["accuracy"][0].keys())
        with csv_path.open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=keys)
            w.writeheader()
            w.writerows(summary["accuracy"])

    print(f"Wrote {acc_path} ({len(summary['accuracy'])} runs)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
