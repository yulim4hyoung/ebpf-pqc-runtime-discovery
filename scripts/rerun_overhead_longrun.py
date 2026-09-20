#!/usr/bin/env python3
"""Re-run the overhead benchmark with a long-running workload (TODO ③).

Mirrors scripts/rerun_overhead.py, but replaces the ~0.13s
workloads/openssl/classical.sh with workloads/openssl/overhead_longrun.sh
(500x RSA-2048 keygen, tens of seconds) and reports the MEDIAN of 5+ reps
instead of the mean, so a single slow/fast outlier rep does not flip the
overhead sign the way it does with the short workload.

Writes results under results/tuning/<round>/overhead_longrun/, and — like
rerun_overhead.py — replaces the "overhead" entry in each round's
summary.json (same benchmark key, same field names m0_mean_sec/
m3_mean_sec/overhead_pct) so it flows into Table 4 via the existing
aggregate_tuning.py / generate_paper_results.py pipeline without needing to
touch either of those files. The old measurement is not deleted from the
repo — results/tuning/<round>/overhead/ (from rerun_overhead.py) stays on
disk for comparison; only the summary.json entry that feeds the paper is
replaced.
"""
from __future__ import annotations

import json
import statistics
import subprocess
import time
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
MONITOR = ROOT / "build" / "crypto-monitor"
WL = ROOT / "workloads" / "openssl" / "overhead_longrun.sh"
WORKLOAD_REPS = "500"  # keygens per workload invocation (~tens of seconds)
MEASURE_REPS = 5       # repetitions of the M0/M3 comparison per round


def run_monitor(poll_ms: int, minimal: bool, events: Path, stats: Path):
    cmd = [str(MONITOR), "-o", str(events), "-S", str(stats), "-p", str(poll_ms)]
    if minimal:
        cmd.append("-m")
    return subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main() -> None:
    cfg = yaml.safe_load((ROOT / "config" / "tuning.yaml").read_text())
    for rnd in cfg["tuning_rounds"]:
        rid = rnd["id"]
        rdir = ROOT / "results" / "tuning" / rid / "overhead_longrun"
        rdir.mkdir(parents=True, exist_ok=True)
        m0, m3 = [], []

        for i in range(1, MEASURE_REPS + 1):
            t0 = time.perf_counter()
            subprocess.run(["bash", str(WL), WORKLOAD_REPS], capture_output=True, timeout=300)
            m0.append(time.perf_counter() - t0)

            ev = rdir / f"events_{i}.jsonl"
            st = rdir / f"stats_{i}.json"
            ev.unlink(missing_ok=True)
            proc = run_monitor(rnd["poll_ms"], rnd.get("minimal_json", False), ev, st)
            time.sleep(0.2)
            t1 = time.perf_counter()
            subprocess.run(["bash", str(WL), WORKLOAD_REPS], capture_output=True, timeout=300)
            elapsed = time.perf_counter() - t1
            proc.send_signal(15)
            proc.wait(timeout=5)
            m3.append(elapsed)

        m0_med = statistics.median(m0)
        m3_med = statistics.median(m3)
        result = {
            "round": rid,
            "benchmark": "overhead",
            "methodology": "longrun_v2",
            "workload": "overhead_longrun.sh",
            "workload_reps": WORKLOAD_REPS,
            "measure_reps": MEASURE_REPS,
            "measure": "median",
            # kept under the original field names so aggregate_tuning.py /
            # generate_paper_results.py pick this up unmodified
            "m0_mean_sec": m0_med,
            "m3_mean_sec": m3_med,
            "overhead_pct": ((m3_med / m0_med) - 1) * 100 if m0_med else 0,
            "m0_times": m0,
            "m3_times": m3,
        }
        summary = ROOT / "results" / "tuning" / rid / "summary.json"
        data = json.loads(summary.read_text()) if summary.exists() else []
        data = [x for x in data if x.get("benchmark") != "overhead"] + [result]
        summary.write_text(json.dumps(data, indent=2))
        print(f"{rid}: M0={m0_med:.2f}s M3={m3_med:.2f}s overhead={result['overhead_pct']:.1f}%")


if __name__ == "__main__":
    main()
