# HDDS Reproducible Benchmark Harness

Every published HDDS latency figure has a harness in this directory that
regenerates it and names the regime it belongs to. A number with no harness and
no named regime does not get published.

| Harness | Regime |
|---|---|
| `bench-repro.sh` | intra-process, single thread, 16-byte payload, end-to-end write to take |
| `bench-machine.sh` | one machine, with full provenance (libc, governor, idle states, repetitions): the single-thread regime, and the cross-thread regime on two pinned cores |
| `bench-loopback-rtt.sh` | same-device loopback, two processes, RELIABLE, 64-byte payload, round trip |

These figures are not comparable with one another, and none of them is a
one-way network latency. A figure measured on particular hardware belongs to
that hardware: a harness reproduces the MEASUREMENT, not the value. Reading a
published number therefore means reading the regime next to it.

The rest of this document describes `bench-repro.sh`.

## What it measures

**Intra-process end-to-end roundtrip latency, single thread, 16-byte payload
struct (2x u64).**

The harness builds and runs the tracked example
`crates/hdds/examples/latency_benchmark.rs` (or the 10M-iteration variant
`latency_benchmark_prof.rs` via `HDDS_BENCH_EXAMPLE`). Per message, the
benchmark:

1. reads a wall-clock timestamp (`SystemTime::now()`),
2. calls `writer.write(&msg)` on a best-effort, KeepLast(1) DataWriter,
3. calls `reader.take()` on a reader bound directly to the writer
   (intra-process path, no network),
4. records `now - timestamp` once `take()` returns the sample.

So the number covers: serialize + intra-process delivery + take, **plus two
wall-clock reads**. It is NOT a UDP number, NOT cross-process, and NOT a
one-way latency. The benchmark performs its own warmup (1k msgs, or 100k for
the prof variant) before measuring.

Known caveat: the timestamps come from `CLOCK_REALTIME`; a clock step (NTP)
during a run can skew samples (negative deltas floor at 0 via
`saturating_sub`). Runs are short; if a round looks absurd, rerun it.

## How to run

```sh
./scripts/bench-repro.sh
```

Defaults: 5 rounds of 10k messages, pinned to core 3, portable build (no
`target-cpu=native`).

| Variable | Default | Meaning |
|---|---|---|
| `HDDS_BENCH_CORE` | `3` | CPU core the benchmark is pinned to (taskset) |
| `HDDS_BENCH_ROUNDS` | `5` | Number of rounds (one process run per round) |
| `HDDS_BENCH_EXAMPLE` | `latency_benchmark` | Or `latency_benchmark_prof` (10M msgs/round) |
| `HDDS_BENCH_OUT_DIR` | `<repo>/target/bench-repro` | Where results are written |
| `HDDS_BENCH_RUSTFLAGS` | empty | Opt-in extra RUSTFLAGS (stamped in results) |

Dependencies: `bash`, `cargo`/`rustc`, coreutils, `awk`, `sed`. Optional:
`taskset` (util-linux; without it the run is unpinned and stamped
`core_pinned: false`), `git` (stamp only), `jq` or `python3` (JSON
self-validation only).

### Build pinning (do not fight it)

The benchmark is always built `--locked` on the release profile with
**thin-LTO and codegen-units=1**, enforced via
`CARGO_PROFILE_RELEASE_LTO=thin CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1`
environment overrides. These beat `Cargo.toml` and any `.cargo/config.toml`,
so manifest edits cannot silently drift the flags. Ambient `RUSTFLAGS` is
cleared (with a warning); mixed build flags have produced phantom deltas in
the tens of nanoseconds on this codebase, which is exactly the failure mode
this script exists to prevent. To benchmark with extra flags (e.g.
`-C target-cpu=native`), pass them through `HDDS_BENCH_RUSTFLAGS` so they are
recorded in the stamp.

## How to read results

Each run prints a per-round table (p50/min/p99/mean/max/throughput) and
writes:

- `bench-results-<sha>-<host>.json` -- machine-readable results, including
  the full environment stamp (CPU model, cores, pinned core, scaling
  governor, kernel, rustc, git SHA + dirty flag, exact build flags and cargo
  invocation) plus per-round stats and the summary block. If the file already
  exists, a UTC timestamp suffix is appended instead of overwriting.
- `...rounds.log` -- the raw benchmark output of every round, for audit.

**The headline number is `summary.p50_ns_median_of_rounds`.** Per-round `min`
is a curiosity, not a claim. `max` is dominated by scheduler noise unless the
machine is isolated. If rounds disagree wildly (like p50 drifting 258 -> 161
across rounds), that is frequency scaling: fix the governor.

The script warns prominently (without failing) when the pinned core's scaling
governor is not `performance`. Such runs are stamped
`governor_is_performance: false` and are not reference-grade.

## Honesty rules

1. Publish only numbers this script produced, and only from the JSON it
   wrote. No hand-copied figures from one-off terminal runs.
2. Every published number travels with its stamp: commit SHA, CPU model,
   governor, pinned core, build flags. A latency number without its stamp is
   a rumor.
3. Reference-grade requires: `git_dirty: false`, `core_pinned: true`,
   `governor_is_performance: true`, and the default pinned build (empty
   `rustflags` unless the claim explicitly says otherwise).
4. Always state the scope with the number: "intra-process e2e roundtrip,
   single thread, 16-byte payload, p50 median-of-rounds". Never a bare
   "latency: X ns".
5. Comparisons (A/B, before/after) are only valid between runs with identical
   stamps except the code under test. Same machine, same governor, same
   flags, same core.

## Release-validation integration (suggested)

Wire a benchmark evidence gate into your release-validation script with one
line (e.g. as a new gate after the existing ones):

```sh
HDDS_BENCH_OUT_DIR="${EVIDENCE_DIR}/bench" "${SCRIPT_DIR}/bench-repro.sh" > "${LOG_DIR}/gate-bench-repro.log" 2>&1
```

This drops the stamped JSON + raw logs into the release evidence package, so
each release ships with a regenerable performance record for the machine that
validated it.
