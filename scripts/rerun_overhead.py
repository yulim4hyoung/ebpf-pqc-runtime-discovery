#!/usr/bin/env python3
"""Re-run overhead benchmark with fixed measurement for all tuning rounds."""
from __future__ import annotations

import json
import statistics
import subprocess
import time
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
MONITOR = ROOT / "build" / "crypto-monitor"
WL = ROOT / "workloads" / "openssl" / "classical.sh"


def run_monitor(rdir: Path, poll_ms: int, minimal: bool, events: Path, stats: Path):
    cmd = [str(MONITOR), "-o", str(events), "-S", str(stats), "-p", str(poll_ms)]
    if minimal:
        cmd.append("-m")
    return subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main() -> None:
    cfg = yaml.safe_load((ROOT / "config" / "tuning.yaml").read_text())
    for rnd in cfg["tuning_rounds"]:
        rid = rnd["id"]
        rdir = ROOT / "results" / "tuning" / rid / "overhead"
        rdir.mkdir(parents=True, exist_ok=True)
        m0, m3 = [], []
        for i in range(1, 11):
            t0 = time.perf_counter()
            subprocess.run(["bash", str(WL)], capture_output=True, timeout=60)
            m0.append(time.perf_counter() - t0)

            ev = rdir / f"events_{i}.jsonl"
            st = rdir / f"stats_{i}.json"
            ev.unlink(missing_ok=True)
            proc = run_monitor(rdir, rnd["poll_ms"], rnd.get("minimal_json", False), ev, st)
            time.sleep(0.2)
            t1 = time.perf_counter()
            subprocess.run(["bash", str(WL)], capture_output=True, timeout=60)
            elapsed = time.perf_counter() - t1
            proc.send_signal(15)
            proc.wait(timeout=5)
            m3.append(elapsed)

        m0m = statistics.mean(m0)
        m3m = statistics.mean(m3)
        result = {
            "round": rid,
            "benchmark": "overhead",
            "m0_mean_sec": m0m,
            "m3_mean_sec": m3m,
            "overhead_pct": ((m3m / m0m) - 1) * 100 if m0m else 0,
            "m0_times": m0,
            "m3_times": m3,
        }
        summary = ROOT / "results" / "tuning" / rid / "summary.json"
        data = json.loads(summary.read_text()) if summary.exists() else []
        data = [x for x in data if x.get("benchmark") != "overhead"] + [result]
        summary.write_text(json.dumps(data, indent=2))
        print(f"{rid}: M0={m0m:.3f}s M3={m3m:.3f}s overhead={result['overhead_pct']:.1f}%")


if __name__ == "__main__":
    main()
