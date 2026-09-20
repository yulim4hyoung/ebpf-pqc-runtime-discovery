#!/usr/bin/env python3
"""Run long-running stability benchmark for the best tuning round."""
from __future__ import annotations

import csv
import json
import subprocess
import time
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    cfg = yaml.safe_load((ROOT / "config" / "tuning.yaml").read_text())
    rnd = cfg["tuning_rounds"][-1]
    rid = rnd["id"]
    total = cfg["benchmarks"]["longrun_seconds"]
    interval = cfg["benchmarks"]["longrun_sample_interval"]
    rdir = ROOT / "results" / "tuning" / rid / "longrun"
    rdir.mkdir(parents=True, exist_ok=True)
    monitor = ROOT / "build" / "crypto-monitor"

    cmd = [str(monitor), "-o", str(rdir / "events.jsonl"), "-S", str(rdir / "stats_final.json"),
           "-d", str(total + 30), "-p", str(rnd["poll_ms"])]
    if rnd.get("minimal_json"):
        cmd.append("-m")

    proc = subprocess.Popen(cmd, cwd=ROOT)
    time.sleep(0.5)
    wl = subprocess.Popen(
        ["bash", "-c", f"while true; do bash {ROOT}/workloads/openssl/classical.sh; sleep 2; done"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    samples = rdir / "samples.csv"
    start = time.time()
    last = 0
    with samples.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["elapsed_sec", "rss_kb", "events_total", "events_per_sec"])
        while time.time() - start < total:
            time.sleep(interval)
            el = int(time.time() - start)
            rss = 0
            try:
                for line in open(f"/proc/{proc.pid}/status"):
                    if line.startswith("VmRSS:"):
                        rss = int(line.split()[1])
            except (FileNotFoundError, ProcessLookupError, ValueError):
                pass
            ev_path = rdir / "events.jsonl"
            ev = sum(1 for _ in ev_path.open()) if ev_path.exists() else 0
            eps = (ev - last) / interval
            last = ev
            w.writerow([el, rss, ev, f"{eps:.2f}"])
            f.flush()
            print(f"[longrun] {el}/{total}s events={ev} rss={rss}KB eps={eps:.2f}")

    wl.terminate()
    wl.wait(timeout=5)
    proc.wait(timeout=15)

    lr = json.loads((rdir / "stats_final.json").read_text())
    result = {"round": rid, "benchmark": "longrun", "duration_sec": total, **lr}
    summary = ROOT / "results" / "tuning" / rid / "summary.json"
    data = json.loads(summary.read_text())
    data = [x for x in data if x.get("benchmark") != "longrun"] + [result]
    summary.write_text(json.dumps(data, indent=2))
    print(f"Longrun {total}s complete: {lr.get('events_total', 0)} events")


if __name__ == "__main__":
    main()
