#!/usr/bin/env python3
"""
Run QED real-world apps under eBPF monitor with strict process filtering.

Detection rules (research playbook):
  - Crypto detection = event_type==1 (crypto API), NOT RAND_bytes alone
  - Random events are indicators only; correlation is reported separately
  - Only events whose process name matches the target binary count

Reference: https://github.com/norrathep/qed
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MONITOR = ROOT / "build" / "crypto-monitor"
# RESULTS_DIR (default "results") lets a validation run write elsewhere (2026-09-20)
RESULTS = ROOT / os.environ.get("RESULTS_DIR", "results")
OUT = RESULTS / "qed-realworld"
PROCESSED = RESULTS / "processed"

QV_LIBS = ("libcrypto", "libssl", "libtss2", "libgcrypt", "libgnutls", "libwolfssl", "libmbedcrypto")
TASK_COMM_LEN = 16


def load_apps() -> list[dict]:
    import yaml
    return yaml.safe_load((ROOT / "config" / "qed_apps.yaml").read_text()).get("apps", [])


def process_prefix(binary: Path) -> str:
    """Linux TASK_COMM is first 15 chars (+NUL). Match that truncation."""
    name = binary.name
    return name[: TASK_COMM_LEN - 1]


def process_matches(event_proc: str, expected_prefix: str) -> bool:
    if not event_proc or not expected_prefix:
        return False
    return event_proc == expected_prefix or event_proc.startswith(expected_prefix[:12])


def static_inventory(binary: Path) -> dict:
    if not binary.exists():
        return {"exists": False, "qv_libs": [], "crypto_libs": [], "static_qv": False}
    try:
        out = subprocess.run(["ldd", str(binary)], capture_output=True, text=True, timeout=10)
        crypto, qv = [], []
        for line in out.stdout.splitlines():
            low = line.lower()
            for lib in QV_LIBS:
                if lib in low:
                    crypto.append(line.strip())
                    if lib in ("libcrypto", "libssl", "libtss2", "libgcrypt", "libgnutls"):
                        qv.append(lib)
        return {
            "exists": True,
            "crypto_libs": crypto,
            "qv_libs": sorted(set(qv)),
            "static_qv": len(qv) > 0,
        }
    except Exception as e:
        return {"exists": True, "error": str(e), "static_qv": False}


def classify_events(lines: list[str], proc_prefix: str) -> dict:
    matched_crypto, matched_random = [], []
    other_crypto, other_random = [], []
    correlated = []

    for line in lines:
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        proc = e.get("process", "")
        etype = e.get("event_type", e.get("etype"))
        api = e.get("api", "")
        # Normalize: RAND_* / getrandom are random even if mislabeled
        is_random = etype == 2 or api in ("RAND_bytes", "getrandom", "Esys_GetRandom") or api.startswith("RAND_")
        is_crypto = (etype == 1 or api.startswith(("EVP_", "OQS_", "Esys_Create", "Esys_RSA"))) and not is_random

        bucket_c = matched_crypto if process_matches(proc, proc_prefix) else other_crypto
        bucket_r = matched_random if process_matches(proc, proc_prefix) else other_random

        if is_crypto:
            bucket_c.append(e)
            if process_matches(proc, proc_prefix) and e.get("randomness_recently_observed"):
                correlated.append(e)
        elif is_random:
            bucket_r.append(e)

    return {
        "matched_crypto": matched_crypto,
        "matched_random": matched_random,
        "other_crypto": other_crypto,
        "other_random": other_random,
        "correlated": correlated,
    }




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

def run_with_monitor(app: dict, out_dir: Path) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    events = out_dir / "events.jsonl"
    stats = out_dir / "stats.json"
    log = out_dir / "run.log"
    events.unlink(missing_ok=True)

    cmd = app["cmd"]
    # Resolve host paths when running outside docker /work layout
    resolved = []
    for c in cmd:
        if c.startswith("/work/qed/"):
            host = str(ROOT.parent / "qed" / c[len("/work/qed/"):])
            resolved.append(host if Path(host).exists() else c)
        else:
            resolved.append(c)
    cmd = resolved

    binary = Path(cmd[0])
    prefix = process_prefix(binary)
    static = static_inventory(binary)

    env = os.environ.copy()
    # Isolate from any leftover TPM env if unset
    proc = subprocess.Popen(
        [str(MONITOR), "-o", str(events), "-S", str(stats), "-p", "1", "-d", "20"],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=open(out_dir / "monitor.log", "w"), env=env,
    )
    if not wait_monitor_ready(out_dir / "monitor.log"):
        print("  [warn] monitor readiness not observed within 120 s; proceeding")

    run_ok, err = False, ""
    try:
        # errors="replace": tpm2_getrandom writes raw random bytes to stdout, which
        # are not valid UTF-8; strict decoding raised and marked a clean run failed.
        r = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                           timeout=30, env=env)
        run_ok = r.returncode == 0
        log.write_text(r.stdout + "\n" + r.stderr)
        if not run_ok:
            err = f"exit={r.returncode}"
    except Exception as e:
        err = str(e)

    time.sleep(0.3)
    proc.send_signal(15)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()

    lines = events.read_text().splitlines() if events.exists() else []
    cls = classify_events(lines, prefix)

    expected_crypto = app.get("expected_crypto", False)
    expected_random = app.get("expected_random", False)
    # If only expected_crypto set historically, keep meaning = crypto API
    runtime_crypto = len(cls["matched_crypto"]) > 0
    runtime_random = len(cls["matched_random"]) > 0
    contaminated = len(cls["other_crypto"]) + len(cls["other_random"]) > 0

    crypto_match = runtime_crypto == expected_crypto
    # random expectation optional
    if "expected_random" in app:
        random_match = runtime_random == expected_random
    else:
        random_match = True

    overall = crypto_match and random_match and (not contaminated or runtime_crypto)

    return {
        "id": app["id"],
        "category": app.get("category", ""),
        "process_filter": prefix,
        "run_ok": run_ok,
        "run_error": err,
        "static": static,
        "runtime_crypto_detected": runtime_crypto,
        "runtime_random_detected": runtime_random,
        "randomness_correlated_crypto": len(cls["correlated"]) > 0,
        "matched_crypto_count": len(cls["matched_crypto"]),
        "matched_random_count": len(cls["matched_random"]),
        "contaminating_events": len(cls["other_crypto"]) + len(cls["other_random"]),
        "apis_matched": sorted(set(e.get("api", "") for e in cls["matched_crypto"] + cls["matched_random"])),
        "algorithms_matched": sorted(set(
            e.get("algorithm", e.get("alg", "")) for e in cls["matched_crypto"] if e.get("algorithm") or e.get("alg")
        )),
        "expected_crypto": expected_crypto,
        "expected_random": app.get("expected_random"),
        "crypto_match": crypto_match,
        "random_match": random_match,
        "contaminated": contaminated,
        "verdict": "PASS" if (crypto_match and (random_match if "expected_random" in app else True)) else "FAIL",
        "notes": app.get("notes", ""),
    }


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    PROCESSED.mkdir(parents=True, exist_ok=True)
    apps = load_apps()
    results = []

    for app in apps:
        bin_path = app["cmd"][0]
        if bin_path.startswith("/work/qed/"):
            bin_path = str(ROOT.parent / "qed" / bin_path[len("/work/qed/"):])
        if app.get("optional") and not Path(bin_path).exists() and not Path(app["cmd"][0]).exists():
            results.append({"id": app["id"], "skipped": True, "reason": "binary missing"})
            print(f"[SKIP] {app['id']}")
            continue
        print(f"[RUN] {app['id']} (filter={process_prefix(Path(app['cmd'][0]))}) ...")
        r = run_with_monitor(app, OUT / app["id"])
        results.append(r)
        print(
            f"  crypto={r['matched_crypto_count']} random={r['matched_random_count']} "
            f"contam={r['contaminating_events']} correlated={r['randomness_correlated_crypto']} "
            f"-> {r['verdict']}"
        )

    summary = {
        "reference": "https://github.com/norrathep/qed",
        "method": "process-filtered; crypto=event_type1; random is indicator only",
        "apps_tested": len([r for r in results if not r.get("skipped")]),
        "results": results,
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2))
    (PROCESSED / "qed_realworld_comparison.json").write_text(json.dumps(summary, indent=2))

    lines = [
        "| App | Filter | Crypto API | Random | Correlated | Contam | Verdict |",
        "|---|---|---:|---:|---|---:|---|",
    ]
    for r in results:
        if r.get("skipped"):
            continue
        lines.append(
            f"| {r['id']} | `{r['process_filter']}` | {r['matched_crypto_count']} | "
            f"{r['matched_random_count']} | {r['randomness_correlated_crypto']} | "
            f"{r['contaminating_events']} | **{r['verdict']}** |"
        )
    (OUT / "comparison.md").write_text("\n".join(lines) + "\n")

    # Randomness evaluation note
    note = """# Randomness detection — how to read this

## What we do NOT claim
`RAND_bytes` / `getrandom` alone ≠ cryptographic operation.

## What we claim
1. **Crypto API probe** (`EVP_*`, `OQS_*`, `Esys_CreatePrimary`, …) = primary detector
2. **Randomness** = behavioral *indicator*
3. **Correlation** = crypto event with `randomness_recently_observed=true` (same PID, window ≤1s)

## Columns
- **Crypto API**: process-matched event_type=1 only
- **Random**: process-matched RAND_bytes / getrandom / Esys_GetRandom
- **Correlated**: crypto event that saw a prior random call from same process
- **Contam**: events from other processes (ignored for verdict)
"""
    (OUT / "RANDOMNESS.md").write_text(note)
    print(f"\nWrote {OUT / 'comparison.md'}")
    print(f"Wrote {OUT / 'RANDOMNESS.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
