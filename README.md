# runtime-pqc-discovery

Runtime discovery of cryptographic operations on Linux with eBPF, using
randomness as a temporal anchor.

`crypto-monitor` attaches eBPF uprobes/uretprobes to the public entry points of
OpenSSL 3 (`libcrypto.so.3`), liboqs (`liboqs.so`), and TPM2-TSS, and records
every key generation, encapsulation/decapsulation, signature, and TLS handshake
step as a JSON event in real time. Randomness events (`RAND_bytes`,
`OQS_randombytes`, the `getrandom` syscall) are not used as a detector on their
own; they serve as a time anchor that lets the daemon attribute an observed
operation to a concrete algorithm (for example ML-KEM-768 versus X25519) and
classify it as post-quantum or classical. The prototype, the workloads, and the
measurement scripts are automated end to end, so every number reported in the
paper can be regenerated from the measurement scripts and the summary logs kept
in this repository.

This is the artifact for the paper *Runtime detection of cryptographic
operations on Linux with eBPF and randomness anchors* (2026). The tag
`paper-2026-09` marks the state referenced from the paper.

## Requirements

- Linux 6.x kernel with BTF (`/sys/kernel/btf/vmlinux`) and uprobe support.
  Measurements were taken on WSL2 (kernel 6.6, inside a privileged Docker
  container) and on a native Ubuntu 26.04 VM.
- `clang`/`llvm` (BPF target), `gcc`, `make`, `libelf-dev`, `zlib1g-dev`.
- `bpftool` (Ubuntu: `linux-tools-common` and `linux-tools-$(uname -r)`).
  Only needed to regenerate `include/bpf/vmlinux.h`; a generated copy is
  checked in.
- OpenSSL 3.x. Native ML-KEM / ML-DSA workloads and the TLS 1.3 hybrid
  handshake experiment need OpenSSL 3.5 or later.
- liboqs installed under `/usr/local/lib` (used by the liboqs workloads).
- Python 3 with the packages in `requirements.txt` (`pyyaml`, `matplotlib`).
- Docker, if you want to use the `scripts/run_*_docker.sh` and benchmark
  wrappers as they were run for the paper.
- Root or `CAP_BPF` to load the programs.

libbpf 1.4 is vendored under `third_party/libbpf/` and built statically by the
Makefile, so no system libbpf is required.

## Build

```sh
make            # builds third_party/libbpf/src/libbpf.a, build/crypto_monitor.bpf.o, build/crypto-monitor
make vmlinux    # optional: regenerate include/bpf/vmlinux.h for the running kernel (uses $BPFTOOL, default `bpftool`)
```

## Run

```sh
sudo ./build/crypto-monitor -o events.jsonl -S stats.json -d 60
```

| Option | Meaning |
|---|---|
| `-o FILE` | append JSON events to FILE (default: stdout) |
| `-S FILE` | write latency/throughput statistics to FILE on exit |
| `-d SEC` | stop after SEC seconds (default: run until SIGINT) |
| `-p MS` | ring-buffer poll timeout in milliseconds (default 100) |
| `-m` | compact JSON output |

`-p` and `-m` are the two knobs swept in the four tuning rounds of the paper
(see `config/tuning.yaml`). The library paths probed by default are defined in
`include/crypto_api.h`.

## Layout

| Path | Contents |
|---|---|
| `src/bpf/crypto_monitor.bpf.c` | eBPF programs (uprobes, uretprobes, `getrandom` tracepoint) |
| `src/userspace/crypto_monitor.c` | user-space daemon: symbol resolution, attachment, anchoring, JSON output |
| `include/` | shared event definitions, probe table, generated `vmlinux.h` |
| `workloads/` | OpenSSL, OpenSSL-native ML-KEM/ML-DSA, liboqs, and negative-control workloads |
| `config/` | experiment parameters, tuning rounds, real-world application list |
| `scripts/` | build, experiment drivers, analysis and plotting |
| `third_party/libbpf/` | vendored libbpf (LGPL-2.1 OR BSD-2-Clause) |
| `results/` | measurements the paper's numbers come from (see below) |
| `results_vm_native/` | re-run of the real-world study on a native (non-WSL2) kernel, Sect. 5 |
| `results_a10a11/` | validation of algorithm-name propagation and the keypair uretprobes, `summary.md` |

## Reproducing the paper's numbers

All experiment drivers live in `scripts/`. The ones used for the paper are:

| Script | Produces |
|---|---|
| `run_full_benchmarks.sh` | four tuning rounds (overhead, latency, scalability, throughput, long run) into `results/tuning/`, plus `results/processed/` and `results/plots/` |
| `run_tuning_benchmarks.py` | the same rounds without Docker (run inside a privileged container or as root) |
| `run_qed_realworld.sh` | static-vs-runtime comparison on the real-world applications of the QED dataset (`QED_ROOT` must point at a checkout of <https://github.com/norrathep/qed>) |
| `run_randomness_eval_docker.sh` | randomness-detector ablation (`results/randomness-eval/`) |
| `run_native_mlkem.sh`, `run_native_mldsa.sh` | OpenSSL 3.5 native ML-KEM / ML-DSA versus liboqs |
| `run_tls_handshake.sh` | TLS 1.3 handshake, X25519 versus hybrid ML-KEM |
| `run_a10a11_validation.sh` | validation of the later monitor changes, writes to `results_a10a11/` only |
| `analyze.py`, `aggregate_tuning.py`, `plot.py` | summary tables and figures from the stats files |

Each run writes a per-case `stats.json` (latency percentiles, event counts,
CPU overhead), a `monitor.log`, and the per-round `summary.json` that the
tables in the paper are built from.

**What is and is not included.** The `stats.json`, `summary.*`, `processed/`
CSV/JSON files, plots, and run logs for every experiment are included, as are
the raw latency samples (`results/tuning/round*/latency/events.jsonl`) behind
the latency CDF and the small per-application event logs of the real-world
study. The full raw event dumps of the overhead, scalability, throughput, and
one-hour long-run experiments (about 2.9 GB of JSONL) are not in the
repository because of their size. They do not affect any reported figure and
are available from the authors on request.

`results/environment.md` and `results_vm_native/environment.md` record the
kernel, OpenSSL, clang, bpftool, and CPU of the two measurement hosts.

## License

MIT, see `LICENSE`. The BPF programs in `src/bpf/` carry a
`SEC("license") = "Dual BSD/GPL"` declaration, which is required by the kernel
to use GPL-only helpers and is unchanged. `third_party/libbpf/` keeps its own
license (LGPL-2.1 OR BSD-2-Clause).
