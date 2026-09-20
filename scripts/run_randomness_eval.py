#!/usr/bin/env python3
"""
Validate randomness-as-indicator vs crypto-API detection.

Compares three detectors on positive crypto + negative random-only workloads:
  D_random:  any RAND_bytes/getrandom  => "crypto?"
  D_api:     crypto API event_type=1
  D_corr:    crypto API + randomness_recently_observed
"""
from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MONITOR = ROOT / "build" / "crypto-monitor"
# RESULTS_DIR (default "results") lets a validation run write elsewhere (2026-09-20)
OUT = ROOT / os.environ.get("RESULTS_DIR", "results") / "randomness-eval"
OUT.mkdir(parents=True, exist_ok=True)




def wait_monitor_ready(log_path, timeout=120.0):
    """Block until the daemon prints 'monitor ready' on stderr (all probes attached).

    Uprobe attachment takes well under a second on a fast host but several
    seconds on VMs; a fixed sleep let short-lived workloads finish before the
    probes landed. Falls back to returning False after `timeout` seconds.
    """
    t0 = time.time()
    deadline = t0 + timeout
    while time.time() < deadline:
        try:
            if "monitor ready" in Path(log_path).read_text(errors="ignore"):
                print(f"  monitor ready after {time.time() - t0:.1f} s")
                return True
        except FileNotFoundError:
            pass
        time.sleep(0.05)
    return False

def run_case(name: str, cmd: list[str], duration: int = 8) -> list[dict]:
    events = OUT / f"{name}.jsonl"
    stats = OUT / f"{name}_stats.json"
    events.unlink(missing_ok=True)
    mon = subprocess.Popen(
        [str(MONITOR), "-o", str(events), "-S", str(stats), "-p", "1", "-d", str(duration)],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=open(OUT / f"{name}_monitor.log", "w"),
    )
    if not wait_monitor_ready(OUT / f"{name}_monitor.log"):
        print(f"  [warn] {name}: monitor readiness not observed within 120 s; proceeding")
    subprocess.run(cmd, capture_output=True, timeout=60)
    time.sleep(0.5)
    mon.send_signal(15)
    try:
        mon.wait(timeout=5)
    except subprocess.TimeoutExpired:
        mon.kill()
    rows = []
    if events.exists():
        for line in events.read_text().splitlines():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return rows


def score(rows: list[dict], procs: set[str] | None = None) -> dict:
    def keep(e):
        return procs is None or e.get("process") in procs

    rows = [e for e in rows if keep(e)]
    random_hits = [e for e in rows if e.get("event_type") == 2 or e.get("api", "").startswith(("RAND_", "getrandom"))]
    api_hits = [e for e in rows if e.get("event_type") == 1 and not e.get("api", "").startswith(("RAND_", "getrandom", "Esys_GetRandom"))]
    # Esys_GetRandom is TPM random — treat as random indicator
    tpm_rand = [e for e in rows if e.get("api") == "Esys_GetRandom"]
    random_hits += tpm_rand
    api_hits = [e for e in api_hits if e.get("api") != "Esys_GetRandom"]
    corr = [e for e in api_hits if e.get("randomness_recently_observed")]
    rand_apis = sorted(set(e.get("api", "") for e in random_hits))
    return {
        "n_events": len(rows),
        "D_random": len(random_hits) > 0,
        "D_api": len(api_hits) > 0,
        "D_corr": len(corr) > 0,
        "random_count": len(random_hits),
        "api_count": len(api_hits),
        "corr_count": len(corr),
        "apis": sorted(set(e.get("api", "") for e in api_hits + random_hits)),
        "random_apis": rand_apis,
        "corr_sample": [
            {
                "api": e.get("api"),
                "algorithm": e.get("algorithm"),
                "random_delta_us": e.get("random_delta_us"),
                "random_bytes": e.get("random_bytes"),
            }
            for e in corr[:3]
        ],
    }


def main() -> None:
    cases = []

    # Positive: OpenSSL RSA keygen (expects API + likely correlation)
    print("[+] positive openssl RSA keygen")
    rows = run_case("pos_rsa", [
        "openssl", "genpkey", "-algorithm", "RSA",
        "-pkeyopt", "rsa_keygen_bits:2048", "-out", "/tmp/pos_rsa.pem",
    ])
    s = score(rows, {"openssl"})
    cases.append({"id": "pos_rsa", "label": "crypto", "expected_crypto": True, **s})

    # Positive: ML-KEM via liboqs if available
    wl = ROOT / "workloads" / "liboqs" / "mlkem_workload"
    if wl.exists():
        print("[+] positive liboqs ML-KEM")
        rows = run_case("pos_mlkem", [str(wl), "ML-KEM-768"])
        s = score(rows, {"mlkem_workload"})
        cases.append({"id": "pos_mlkem", "label": "crypto", "expected_crypto": True, **s})

    # Negative: getrandom only
    print("[-] negative getrandom-only")
    rows = run_case("neg_getrandom", [
        "python3", "-c", "import os\n[os.getrandom(32) for _ in range(20)]",
    ])
    s = score(rows)  # any process
    # Filter to python
    s = score(rows, {e.get("process") for e in rows if e.get("api") == "getrandom"} or None)
    cases.append({"id": "neg_getrandom", "label": "random_only", "expected_crypto": False, **s})

    # Negative: urandom read (may not hit RAND_bytes uprobe)
    print("[-] negative /dev/urandom")
    rows = run_case("neg_urandom", ["dd", "if=/dev/urandom", "bs=32", "count=10", "of=/tmp/ur.bin"])
    s = score(rows)
    cases.append({"id": "neg_urandom", "label": "random_only", "expected_crypto": False, **s})

    # Negative: uuid (stdlib)
    print("[-] negative uuid")
    rows = run_case("neg_uuid", ["python3", "-c", "import uuid\n[uuid.uuid4() for _ in range(20)]"])
    s = score(rows)
    cases.append({"id": "neg_uuid", "label": "random_only", "expected_crypto": False, **s})

    # Metrics
    def metrics(det_key: str) -> dict:
        tp = tn = fp = fn = 0
        for c in cases:
            pred = c[det_key]
            exp = c["expected_crypto"]
            if exp and pred:
                tp += 1
            elif exp and not pred:
                fn += 1
            elif not exp and pred:
                fp += 1
            else:
                tn += 1
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        return {"TP": tp, "TN": tn, "FP": fp, "FN": fn, "precision": prec, "recall": rec, "f1": f1}

    table = {
        "D_random (random alone)": metrics("D_random"),
        "D_api (crypto API)": metrics("D_api"),
        "D_corr (API + random correlation)": metrics("D_corr"),
        "cases": cases,
    }
    (OUT / "summary.json").write_text(json.dumps(table, indent=2))

    md = ["# Randomness detector evaluation", "",
          "| Detector | Precision | Recall | F1 | FP | FN |",
          "|---|---:|---:|---:|---:|---:|"]
    for name, m in table.items():
        if name == "cases":
            continue
        md.append(
            f"| {name} | {m['precision']:.2f} | {m['recall']:.2f} | {m['f1']:.2f} | {m['FP']} | {m['FN']} |"
        )
    md += ["", "## Per-case", "",
           "| Case | Label | D_random | D_api | D_corr | APIs |",
           "|---|---|---|---|---|---|"]
    for c in cases:
        md.append(
            f"| {c['id']} | {c['label']} | {c['D_random']} | {c['D_api']} | {c['D_corr']} | "
            f"{', '.join(c['apis'][:6])} |"
        )
    md += ["",
           "## Interpretation",
           "- **D_random alone is NOT a valid crypto detector** — negatives that call getrandom become FPs.",
           "- **D_api** is the primary detector.",
           "- **D_corr** raises confidence when randomness precedes a crypto API; it does not invent detections.",
           ]
    (OUT / "evaluation.md").write_text("\n".join(md) + "\n")
    print((OUT / "evaluation.md").read_text())


if __name__ == "__main__":
    main()
