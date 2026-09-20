#!/usr/bin/env python3
"""Run all benchmarks across 4 tuning rounds and produce comparison tables."""
from __future__ import annotations

import csv
import json
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

try:
    import yaml
except ImportError:
    yaml = None

MONITOR = ROOT / "build" / "crypto-monitor"
OUT = ROOT / "results" / "tuning"
PROCESSED = ROOT / "results" / "processed"


def load_tuning_config() -> dict:
    cfg_path = ROOT / "config" / "tuning.yaml"
    if yaml and cfg_path.exists():
        return yaml.safe_load(cfg_path.read_text())
    return {
        "tuning_rounds": [
            {"id": "round1_baseline", "poll_ms": 100, "minimal_json": False},
            {"id": "round2_fast_poll", "poll_ms": 10, "minimal_json": False},
            {"id": "round3_aggressive_poll", "poll_ms": 1, "minimal_json": False},
            {"id": "round4_minimal_output", "poll_ms": 1, "minimal_json": True},
        ],
        "benchmarks": {
            "latency_reps": 30,
            "overhead_reps": 10,
            "throughput_ops": [1, 10, 50, 100, 500],
            "scalability_procs": [1, 2, 4, 8, 16],
            "longrun_seconds": 3600,
            "longrun_sample_interval": 60,
        },
    }


def stats_from_json(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def run_monitor(round_dir: Path, poll_ms: int, minimal: bool, duration: int,
                events: Path, stats: Path) -> subprocess.Popen:
    cmd = [str(MONITOR), "-o", str(events), "-S", str(stats),
           "-d", str(duration), "-p", str(poll_ms)]
    if minimal:
        cmd.append("-m")
    log = open(round_dir / "monitor.log", "a")
    return subprocess.Popen(cmd, stdout=log, stderr=log, cwd=ROOT)


def wait_monitor(proc: subprocess.Popen, timeout: float = 30) -> int:
    if proc.poll() is not None:
        return proc.returncode or 0
    try:
        return proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.send_signal(15)
        try:
            return proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            return proc.wait(timeout=2)


def benchmark_latency(round_cfg: dict, bench_cfg: dict) -> dict:
    rid = round_cfg["id"]
    rdir = OUT / rid / "latency"
    rdir.mkdir(parents=True, exist_ok=True)
    reps = bench_cfg.get("latency_reps", 30)
    poll_ms = round_cfg["poll_ms"]
    minimal = round_cfg.get("minimal_json", False)

    events = rdir / "events.jsonl"
    stats = rdir / "stats.json"
    events.unlink(missing_ok=True)

    proc = run_monitor(rdir, poll_ms, minimal, duration=reps * 2 + 5, events=events, stats=stats)
    time.sleep(0.5)

    for i in range(reps):
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "RSA",
             "-pkeyopt", "rsa_keygen_bits:2048", "-out", f"/tmp/lat_{rid}_{i}.pem"],
            capture_output=True, timeout=30,
        )

    wait_monitor(proc, timeout=reps * 2 + 10)
    s = stats_from_json(stats)
    return {"round": rid, "benchmark": "latency", **s}


def benchmark_overhead(round_cfg: dict, bench_cfg: dict) -> dict:
    rid = round_cfg["id"]
    rdir = OUT / rid / "overhead"
    rdir.mkdir(parents=True, exist_ok=True)
    reps = bench_cfg.get("overhead_reps", 10)
    poll_ms = round_cfg["poll_ms"]
    minimal = round_cfg.get("minimal_json", False)
    wl = ROOT / "workloads" / "openssl" / "classical.sh"

    m0_times, m3_times = [], []
    for i in range(1, reps + 1):
        t0 = time.perf_counter()
        subprocess.run(["bash", str(wl)], capture_output=True, timeout=60)
        m0_times.append(time.perf_counter() - t0)

        events = rdir / f"events_{i}.jsonl"
        stats = rdir / f"stats_{i}.json"
        events.unlink(missing_ok=True)
        proc = run_monitor(rdir, poll_ms, minimal, duration=0, events=events, stats=stats)
        time.sleep(0.2)
        t1 = time.perf_counter()
        subprocess.run(["bash", str(wl)], capture_output=True, timeout=60)
        elapsed = time.perf_counter() - t1
        proc.send_signal(15)
        wait_monitor(proc, timeout=5)
        m3_times.append(elapsed)

    m0_mean = statistics.mean(m0_times)
    m3_mean = statistics.mean(m3_times)
    return {
        "round": rid,
        "benchmark": "overhead",
        "m0_mean_sec": m0_mean,
        "m3_mean_sec": m3_mean,
        "overhead_pct": ((m3_mean / m0_mean) - 1) * 100 if m0_mean else 0,
        "m0_times": m0_times,
        "m3_times": m3_times,
    }


def benchmark_throughput(round_cfg: dict, bench_cfg: dict) -> dict:
    rid = round_cfg["id"]
    rdir = OUT / rid / "throughput"
    rdir.mkdir(parents=True, exist_ok=True)
    poll_ms = round_cfg["poll_ms"]
    minimal = round_cfg.get("minimal_json", False)
    targets = bench_cfg.get("throughput_ops", [1, 10, 50, 100, 500])
    results = []

    for ops in targets:
        events = rdir / f"events_{ops}.jsonl"
        stats = rdir / f"stats_{ops}.json"
        events.unlink(missing_ok=True)
        duration = max(30, ops // 2 + 10)

        proc = run_monitor(rdir, poll_ms, minimal, duration=duration, events=events, stats=stats)
        time.sleep(0.3)
        t0 = time.perf_counter()
        subprocess.run(["bash", str(ROOT / "workloads" / "openssl" / "throughput.sh"), str(ops)],
                       capture_output=True, timeout=max(600, ops * 2))
        elapsed = time.perf_counter() - t0
        wait_monitor(proc, timeout=15)
        s = stats_from_json(stats)
        detected = s.get("events_crypto", 0)
        results.append({
            "target_ops": ops,
            "elapsed_sec": elapsed,
            "achieved_ops_sec": ops / elapsed if elapsed else 0,
            "events_detected": detected,
            "detection_rate": detected / ops if ops else 0,
            "latency": s.get("latency_us", {}),
        })

    return {"round": rid, "benchmark": "throughput", "results": results}


def benchmark_scalability(round_cfg: dict, bench_cfg: dict) -> dict:
    rid = round_cfg["id"]
    rdir = OUT / rid / "scalability"
    rdir.mkdir(parents=True, exist_ok=True)
    poll_ms = round_cfg["poll_ms"]
    minimal = round_cfg.get("minimal_json", False)
    procs_list = bench_cfg.get("scalability_procs", [1, 2, 4, 8, 16])
    results = []

    for n in procs_list:
        events = rdir / f"events_{n}proc.jsonl"
        stats = rdir / f"stats_{n}proc.json"
        events.unlink(missing_ok=True)
        duration = max(30, n * 5)

        proc = run_monitor(rdir, poll_ms, minimal, duration=duration, events=events, stats=stats)
        time.sleep(0.3)
        t0 = time.perf_counter()
        children = []
        for _ in range(n):
            p = subprocess.Popen(["bash", str(ROOT / "workloads" / "openssl" / "classical.sh")],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            children.append(p)
        for p in children:
            p.wait(timeout=120)
        elapsed = time.perf_counter() - t0
        wait_monitor(proc, timeout=15)
        s = stats_from_json(stats)
        results.append({
            "processes": n,
            "elapsed_sec": elapsed,
            "events_total": s.get("events_total", 0),
            "events_crypto": s.get("events_crypto", 0),
            "latency": s.get("latency_us", {}),
        })

    return {"round": rid, "benchmark": "scalability", "results": results}


def benchmark_longrun(round_cfg: dict, bench_cfg: dict) -> dict:
    rid = round_cfg["id"]
    rdir = OUT / rid / "longrun"
    rdir.mkdir(parents=True, exist_ok=True)
    poll_ms = round_cfg["poll_ms"]
    minimal = round_cfg.get("minimal_json", False)
    total_sec = bench_cfg.get("longrun_seconds", 3600)
    interval = bench_cfg.get("longrun_sample_interval", 60)

    events = rdir / "events.jsonl"
    stats = rdir / "stats_final.json"
    samples = rdir / "samples.csv"
    events.unlink(missing_ok=True)

    with samples.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["elapsed_sec", "rss_kb", "events_total", "events_per_sec"])

        proc = run_monitor(rdir, poll_ms, minimal, duration=total_sec + 10, events=events, stats=stats)
        time.sleep(0.5)
        workload = subprocess.Popen(
            ["bash", "-c", f"while true; do bash {ROOT}/workloads/openssl/classical.sh; sleep 2; done"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

        start = time.time()
        last_events = 0
        while time.time() - start < total_sec:
            time.sleep(interval)
            elapsed = int(time.time() - start)
            rss = 0
            try:
                with open(f"/proc/{proc.pid}/status") as pf:
                    for line in pf:
                        if line.startswith("VmRSS:"):
                            rss = int(line.split()[1])
            except (FileNotFoundError, ProcessLookupError, ValueError):
                pass
            ev_count = sum(1 for _ in events.open()) if events.exists() else 0
            eps = (ev_count - last_events) / interval if interval else 0
            last_events = ev_count
            w.writerow([elapsed, rss, ev_count, f"{eps:.2f}"])

        workload.terminate()
        workload.wait(timeout=5)
        wait_monitor(proc, timeout=15)

    s = stats_from_json(stats)
    return {"round": rid, "benchmark": "longrun", "duration_sec": total_sec, **s}


def main() -> int:
    cfg = load_tuning_config()
    rounds = cfg["tuning_rounds"]
    bench = cfg.get("benchmarks", {})
    all_results = []

    OUT.mkdir(parents=True, exist_ok=True)
    PROCESSED.mkdir(parents=True, exist_ok=True)

    # Longrun only on round4 (best tuned) to save time; others skip longrun
    for rnd in rounds:
        print(f"\n=== Tuning round: {rnd['id']} ===")
        round_results = []

        print("  latency...")
        round_results.append(benchmark_latency(rnd, bench))
        print("  overhead...")
        round_results.append(benchmark_overhead(rnd, bench))
        print("  throughput...")
        round_results.append(benchmark_throughput(rnd, bench))
        print("  scalability...")
        round_results.append(benchmark_scalability(rnd, bench))

        if rnd["id"] == rounds[-1]["id"]:
            print(f"  longrun ({bench.get('longrun_seconds', 3600)}s)...")
            round_results.append(benchmark_longrun(rnd, bench))

        all_results.extend(round_results)
        (OUT / rnd["id"] / "summary.json").write_text(
            json.dumps(round_results, indent=2, default=str)
        )

    comparison = {"rounds": rounds, "results": all_results}
    (PROCESSED / "tuning_comparison.json").write_text(json.dumps(comparison, indent=2, default=str))

    # Summary tables (separate CSV per benchmark type)
    lat_rows = [r for r in all_results if r.get("benchmark") == "latency"]
    oh_rows = [r for r in all_results if r.get("benchmark") == "overhead"]

    if lat_rows:
        lat_csv = [{
            "round": r["round"],
            "latency_median_us": r.get("latency_us", {}).get("median", 0),
            "latency_p95_us": r.get("latency_us", {}).get("p95", 0),
            "latency_p99_us": r.get("latency_us", {}).get("p99", 0),
            "latency_mean_us": r.get("latency_us", {}).get("mean", 0),
            "events_total": r.get("events_total", 0),
        } for r in lat_rows]
        with (PROCESSED / "latency_by_round.csv").open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=lat_csv[0].keys())
            w.writeheader()
            w.writerows(lat_csv)

    if oh_rows:
        oh_csv = [{
            "round": r["round"],
            "m0_mean_sec": round(r["m0_mean_sec"], 4),
            "m3_mean_sec": round(r["m3_mean_sec"], 4),
            "overhead_pct": round(r["overhead_pct"], 2),
        } for r in oh_rows]
        with (PROCESSED / "overhead_by_round.csv").open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=oh_csv[0].keys())
            w.writeheader()
            w.writerows(oh_csv)

    # Combined comparison JSON rows for markdown
    rows = []
    for r in lat_rows:
        lat = r.get("latency_us", {})
        oh = next((o for o in oh_rows if o["round"] == r["round"]), {})
        rows.append({
            "round": r["round"],
            "latency_median_us": lat.get("median", 0),
            "latency_p95_us": lat.get("p95", 0),
            "latency_p99_us": lat.get("p99", 0),
            "overhead_pct": round(oh.get("overhead_pct", 0), 2) if oh else None,
            "m0_sec": round(oh.get("m0_mean_sec", 0), 4) if oh else None,
            "m3_sec": round(oh.get("m3_mean_sec", 0), 4) if oh else None,
        })
    if rows:
        with (PROCESSED / "tuning_comparison.csv").open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=rows[0].keys())
            w.writeheader()
            w.writerows(rows)

    print(f"\nWrote {PROCESSED / 'tuning_comparison.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
