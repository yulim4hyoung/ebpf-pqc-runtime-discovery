#!/usr/bin/env python3
"""Generate all publication plots from benchmark results."""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLOTS = ROOT / "results" / "plots"
PROCESSED = ROOT / "results" / "processed"
TUNING = ROOT / "results" / "tuning"


def load_json(p: Path) -> dict | list:
    if p.exists():
        return json.loads(p.read_text())
    return {}


def main() -> int:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print("Installing matplotlib...", file=sys.stderr)
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "matplotlib"])
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np

    PLOTS.mkdir(parents=True, exist_ok=True)

    def save_fig(fig, stem: str) -> None:
        """Save raster (PNG, quick viewing) and vector (PDF, publication)."""
        fig.savefig(PLOTS / f"{stem}.png", dpi=150)
        fig.savefig(PLOTS / f"{stem}.pdf")
        plt.close(fig)
        print(f"Wrote {PLOTS / stem}.png/.pdf")

    comparison = load_json(PROCESSED / "tuning_comparison.json")

    # Fig 3: Accuracy (if available)
    acc = load_json(PROCESSED / "accuracy_summary.json")
    if acc.get("accuracy"):
        rows = acc["accuracy"]
        labels = [r.get("run_id", "")[:16] for r in rows[:8]]
        fig, ax = plt.subplots(figsize=(10, 5))
        x = np.arange(len(labels))
        w = 0.25
        ax.bar(x - w, [r.get("precision", 0) for r in rows[:8]], w, label="Precision")
        ax.bar(x, [r.get("recall", 0) for r in rows[:8]], w, label="Recall")
        ax.bar(x + w, [r.get("f1", 0) for r in rows[:8]], w, label="F1")
        ax.set_xticks(x)
        ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=8)
        ax.set_ylim(0, 1.05)
        ax.set_title("Detection Accuracy")
        ax.legend()
        fig.tight_layout()
        save_fig(fig, "fig3_accuracy")

    if not comparison:
        print("No tuning comparison data")
        return 0

    results = comparison.get("results", [])
    rounds = [r["id"] for r in comparison.get("rounds", [])]

    # Fig 4: Overhead by tuning round
    oh = [r for r in results if r.get("benchmark") == "overhead"]
    if oh:
        fig, ax = plt.subplots(figsize=(8, 5))
        labels = [r["round"].replace("round", "R") for r in oh]
        overheads = [r["overhead_pct"] for r in oh]
        colors = plt.cm.viridis(np.linspace(0.2, 0.8, len(labels)))
        ax.bar(labels, overheads, color=colors)
        ax.set_ylabel("Overhead (%)")
        ax.set_title("Runtime Overhead by Tuning Round (M3 vs M0)")
        ax.axhline(y=0, color="gray", linestyle="--", alpha=0.5)
        fig.tight_layout()
        save_fig(fig, "fig4_overhead")

    # Fig 5: Detection latency CDF by tuning round
    lat = [r for r in results if r.get("benchmark") == "latency"]
    if lat:
        fig, ax = plt.subplots(figsize=(8, 5))
        for r in lat:
            lat_dir = TUNING / r["round"] / "latency"
            samples = []
            for line in (lat_dir / "events.jsonl").read_text().splitlines() if (lat_dir / "events.jsonl").exists() else []:
                try:
                    ev = json.loads(line)
                    if "detection_latency_us" in ev:
                        samples.append(ev["detection_latency_us"])
                except json.JSONDecodeError:
                    pass
            if samples:
                s = sorted(samples)
                cdf = np.arange(1, len(s) + 1) / len(s)
                ax.plot(s, cdf, label=r["round"].replace("round", "R"))
        ax.set_xlabel("Detection Latency (μs)")
        ax.set_ylabel("CDF")
        ax.set_title("Detection Latency CDF by Tuning Round")
        ax.legend(fontsize=8)
        ax.set_xscale("log")
        fig.tight_layout()
        save_fig(fig, "fig5_latency_cdf")

    # Fig 6: Scalability (best round = last)
    if rounds:
        best = rounds[-1]
        scal = next((r for r in results if r.get("benchmark") == "scalability" and r["round"] == best), None)
        if scal and scal.get("results"):
            fig, ax = plt.subplots(figsize=(8, 5))
            procs = [x["processes"] for x in scal["results"]]
            ev = [x["events_crypto"] for x in scal["results"]]
            ax.plot(procs, ev, "o-", linewidth=2)
            ax.set_xlabel("Concurrent Processes")
            ax.set_ylabel("Crypto Events Detected")
            ax.set_title(f"Scalability ({best})")
            fig.tight_layout()
            save_fig(fig, "fig6_scalability")

    # Fig 7: Throughput
    if rounds:
        best = rounds[-1]
        tp = next((r for r in results if r.get("benchmark") == "throughput" and r["round"] == best), None)
        if tp and tp.get("results"):
            fig, ax = plt.subplots(figsize=(8, 5))
            targets = [x["target_ops"] for x in tp["results"]]
            achieved = [x["achieved_ops_sec"] for x in tp["results"]]
            detected = [x["events_detected"] for x in tp["results"]]
            ax.plot(targets, achieved, "o-", label="Achieved ops/s")
            ax.plot(targets, [d / max(x["elapsed_sec"], 0.001) for x, d in zip(tp["results"], detected)],
                    "s--", label="Detected events/s")
            ax.set_xlabel("Target Operations")
            ax.set_ylabel("Operations / sec")
            ax.set_title(f"Event Throughput ({best})")
            ax.legend()
            ax.set_xscale("log")
            fig.tight_layout()
            save_fig(fig, "fig7_throughput")

    # Fig 9: Long-running CPU/Memory
    longrun = next((r for r in results if r.get("benchmark") == "longrun"), None)
    if longrun:
        lr_dir = TUNING / longrun["round"] / "longrun"
        samples_csv = lr_dir / "samples.csv"
        if samples_csv.exists():
            elapsed, rss, events, eps = [], [], [], []
            with samples_csv.open() as f:
                reader = csv.DictReader(f)
                for row in reader:
                    elapsed.append(int(row["elapsed_sec"]))
                    rss.append(int(row["rss_kb"]))
                    events.append(int(row["events_total"]))
                    eps.append(float(row["events_per_sec"]))
            fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 6), sharex=True)
            ax1.plot(elapsed, rss, "b-")
            ax1.set_ylabel("RSS (KB)")
            ax1.set_title(f"Long-running Monitor ({longrun.get('duration_sec', 0)}s)")
            ax2.plot(elapsed, eps, "g-")
            ax2.set_xlabel("Elapsed (sec)")
            ax2.set_ylabel("Events/sec")
            fig.tight_layout()
            save_fig(fig, "fig9_longrun")

    # Fig 10: Tuning comparison summary
    lat_rows = [r for r in results if r.get("benchmark") == "latency"]
    oh_rows = [r for r in results if r.get("benchmark") == "overhead"]
    if lat_rows and oh_rows:
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
        labels = [r["round"].replace("round", "R") for r in lat_rows]
        medians = [r.get("latency_us", {}).get("median", 0) for r in lat_rows]
        p99s = [r.get("latency_us", {}).get("p99", 0) for r in lat_rows]
        x = np.arange(len(labels))
        ax1.bar(x - 0.2, medians, 0.4, label="Median")
        ax1.bar(x + 0.2, p99s, 0.4, label="P99")
        ax1.set_xticks(x)
        ax1.set_xticklabels(labels)
        ax1.set_ylabel("Latency (μs)")
        ax1.set_title("Detection Latency by Round")
        ax1.legend()

        oh_labels = [r["round"].replace("round", "R") for r in oh_rows]
        oh_vals = [r["overhead_pct"] for r in oh_rows]
        ax2.bar(oh_labels, oh_vals, color="coral")
        ax2.set_ylabel("Overhead (%)")
        ax2.set_title("Overhead by Round")
        fig.suptitle("Tuning Round Comparison (4 iterations)")
        fig.tight_layout()
        save_fig(fig, "fig10_tuning_comparison")

    return 0


if __name__ == "__main__":
    sys.exit(main())
