#!/usr/bin/env python3
import os
import yaml
from pathlib import Path

p = Path(__file__).resolve().parent.parent / "config" / "tuning.yaml"
cfg = yaml.safe_load(p.read_text())
sec = int(os.environ.get("LONGRUN_SEC", cfg["benchmarks"]["longrun_seconds"]))
cfg["benchmarks"]["longrun_seconds"] = sec
p.write_text(yaml.dump(cfg, default_flow_style=False))
print(f"longrun_seconds={sec}")
