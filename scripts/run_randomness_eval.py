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
    # Per-event detail kept for the workload-level report (name attribution,
    # anchor delta, confidence distribution).
    named = [e for e in api_hits if e.get("algorithm")]
    deltas = [e.get("random_delta_us") for e in corr if e.get("random_delta_us") is not None]
    confs = [e.get("confidence") for e in api_hits if e.get("confidence") is not None]
    return {
        "n_events": len(rows),
        "D_random": len(random_hits) > 0,
        "D_api": len(api_hits) > 0,
        "D_corr": len(corr) > 0,
        "random_count": len(random_hits),
        "api_count": len(api_hits),
        "corr_count": len(corr),
        "named_count": len(named),
        "corr_deltas_us": deltas,
        "confidences": confs,
        "apis": sorted(set(e.get("api", "") for e in api_hits + random_hits)),
        "random_apis": rand_apis,
        "algorithms": sorted(set(e.get("algorithm", "") for e in named)),
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


def build_workloads():
    """Return (positives, negatives) as (base_id, cmd, proc_filter, label) tuples.

    proc_filter: a set restricts scoring to those process names; None scores any
    process; the sentinel "GETRANDOM" restricts to whichever process actually
    issued getrandom (the original neg_getrandom behaviour).
    """
    wl = ROOT / "workloads" / "liboqs" / "mlkem_workload"
    positives = [
        ("pos_rsa", ["openssl", "genpkey", "-algorithm", "RSA",
                     "-pkeyopt", "rsa_keygen_bits:2048", "-out", "/tmp/pos_rsa.pem"],
         {"openssl"}, "crypto"),
        ("pos_ec", ["openssl", "genpkey", "-algorithm", "EC",
                    "-pkeyopt", "ec_paramgen_curve:P-256", "-out", "/tmp/pos_ec.pem"],
         {"openssl"}, "crypto"),
        ("pos_x25519", ["openssl", "genpkey", "-algorithm", "X25519",
                        "-out", "/tmp/pos_x25519.pem"],
         {"openssl"}, "crypto"),
    ]
    if wl.exists():
        for base, alg in [("pos_mlkem512", "ML-KEM-512"),
                          ("pos_mlkem768", "ML-KEM-768"),
                          ("pos_mlkem1024", "ML-KEM-1024")]:
            positives.append((base, [str(wl), alg], {"mlkem_workload"}, "crypto"))
    negatives = [
        ("neg_getrandom",
         ["python3", "-c", "import os\n[os.getrandom(32) for _ in range(20)]"],
         "GETRANDOM", "random_only"),
        ("neg_urandom",
         ["dd", "if=/dev/urandom", "bs=32", "count=10", "of=/tmp/ur.bin"],
         None, "random_only"),
        ("neg_uuid",
         ["python3", "-c", "import uuid\n[uuid.uuid4() for _ in range(20)]"],
         None, "random_only"),
    ]
    return positives, negatives


def main() -> None:
    # REPEAT (default 1) runs every workload N times; each repeat is a separate
    # case (id suffixed _r01, _r02, ...) so process-level TP/FP/FN accumulate.
    repeat = int(os.environ.get("REPEAT", "1"))
    positives, negatives = build_workloads()
    cases = []

    for rep in range(1, repeat + 1):
        suf = f"_r{rep:02d}"
        for base, cmd, procs, label in positives:
            cid = base + suf
            print(f"[+] {cid}")
            rows = run_case(cid, cmd)
            s = score(rows, procs)
            cases.append({"id": cid, "workload": base, "label": label,
                          "expected_crypto": True, **s})
        for base, cmd, pf, label in negatives:
            cid = base + suf
            print(f"[-] {cid}")
            rows = run_case(cid, cmd)
            if pf == "GETRANDOM":
                s = score(rows, {e.get("process") for e in rows
                                 if e.get("api") == "getrandom"} or None)
            elif pf is None:
                s = score(rows)
            else:
                s = score(rows, pf)
            cases.append({"id": cid, "workload": base, "label": label,
                          "expected_crypto": False, **s})

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

    from statistics import median

    def agg(base: str) -> dict:
        cs = [c for c in cases if c["workload"] == base]
        n = len(cs)
        expected = cs[0]["expected_crypto"]
        det_key = "D_api" if expected else "D_random"
        det = sum(1 for c in cs if c[det_key])
        api_total = sum(c["api_count"] for c in cs)
        named_total = sum(c["named_count"] for c in cs)
        anchored = sum(c["corr_count"] for c in cs)
        deltas = [x for c in cs for x in c.get("corr_deltas_us", [])]
        confs = [x for c in cs for x in c.get("confidences", [])]
        return {
            "workload": base,
            "label": cs[0]["label"],
            "repeats": n,
            "detector": det_key,
            "detection_rate": det / n if n else 0.0,
            "api_events_total": api_total,
            "name_attribution_rate": (named_total / api_total) if api_total else None,
            "anchor_rate": (anchored / api_total) if api_total else None,
            "delta_us_median": median(deltas) if deltas else None,
            "delta_us_max": max(deltas) if deltas else None,
            "confidence_min": min(confs) if confs else None,
            "confidence_max": max(confs) if confs else None,
        }

    order = list(dict.fromkeys(c["workload"] for c in cases))
    workloads = [agg(b) for b in order]

    table = {
        "repeat": repeat,
        "D_random (random alone)": metrics("D_random"),
        "D_api (crypto API)": metrics("D_api"),
        "D_corr (API + random correlation)": metrics("D_corr"),
        "workloads": workloads,
        "cases": cases,
    }
    (OUT / "summary.json").write_text(json.dumps(table, indent=2))

    n_proc = len(cases)
    md = ["# Randomness detector evaluation", "",
          f"Repeats: {repeat}  |  Processes scored: {n_proc}", "",
          "| Detector | Precision | Recall | F1 | TP | FP | FN |",
          "|---|---:|---:|---:|---:|---:|---:|"]
    for name in ("D_random (random alone)", "D_api (crypto API)",
                 "D_corr (API + random correlation)"):
        m = table[name]
        md.append(
            f"| {name} | {m['precision']:.2f} | {m['recall']:.2f} | {m['f1']:.2f} | "
            f"{m['TP']} | {m['FP']} | {m['FN']} |"
        )
    md += ["", "## Per-workload", "",
           "| Workload | Label | Reps | Det.rate | Name attr. | Anchor | "
           "Δt med (μs) | Δt max | Conf |",
           "|---|---|---:|---:|---:|---:|---:|---:|---:|"]
    for w in workloads:
        def pct(x):
            return "-" if x is None else f"{x*100:.0f}%"
        conf = "-" if w["confidence_min"] is None else (
            f"{w['confidence_min']:.1f}-{w['confidence_max']:.1f}")
        dm = "-" if w["delta_us_median"] is None else f"{w['delta_us_median']:.0f}"
        dx = "-" if w["delta_us_max"] is None else f"{w['delta_us_max']:.0f}"
        md.append(
            f"| {w['workload']} | {w['label']} | {w['repeats']} | "
            f"{w['detection_rate']*100:.0f}% | {pct(w['name_attribution_rate'])} | "
            f"{pct(w['anchor_rate'])} | {dm} | {dx} | {conf} |"
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
