#!/usr/bin/env python3
import json
from pathlib import Path

ROOT = Path("/work") if Path("/work/scripts").exists() else Path(__file__).resolve().parent.parent
rid = "round4_minimal_output"
stats = json.loads((ROOT / "results/tuning" / rid / "longrun/stats_final.json").read_text())
samples = (ROOT / "results/tuning" / rid / "longrun/samples.csv").read_text().strip().splitlines()
last = samples[-1].split(",") if len(samples) > 1 else ["3600"]
result = {"round": rid, "benchmark": "longrun", "duration_sec": int(last[0]), **stats}
summary = ROOT / "results/tuning" / rid / "summary.json"
data = json.loads(summary.read_text())
data = [x for x in data if x.get("benchmark") != "longrun"] + [result]
summary.write_text(json.dumps(data, indent=2))
print(f"Updated longrun: {result['duration_sec']}s, events={stats.get('events_total')}")
