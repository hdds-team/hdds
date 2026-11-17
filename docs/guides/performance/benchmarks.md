# Performance Benchmarks

This page lists the performance results the project publishes, each with the
regime it was measured in and how to reproduce it. Results from different
operations, transports, payloads, QoS policies, or machines are not
interchangeable. Every figure below was measured on the 1.5.0 release unless the row says
otherwise.

All measurements on this page ran on one machine, called the benchmark host below:
Intel Core i9-9900KF, Debian 13, `performance` CPU governor, release build with thin
LTO, one codegen unit, empty `RUSTFLAGS` and `--locked` (rustc 1.92.0). Each
figure is the median of the per-round values over interleaved rounds.

## One-thread intra-process write then take

Operation: `write()` of a 16-byte POD followed by `take()` on the same thread,
reader bound to the writer in the same process, BEST_EFFORT, KEEP_LAST(1).
Example `latency_benchmark_prof` (10,000,000 messages per round after a
100,000-message warm-up), pinned to logical CPU 3, stock idle policy,
`HDDS_INTERFACE=lo` so that no participant on the LAN is discovered,
5 rounds interleaved between the two builds.

| Build | p50 | p99 | Delivered rate |
|-------|-----|-----|----------------|
| default | 180 ns | 190 ns | 5.05 M msg/s |
| `--features fast-consumer-gate` | 178 ns | 191 ns | 5.09 M msg/s |

Both rows come from one series in which the two builds alternated round by
round, so they are comparable with each other. Across three separate series of
the default build the p50 median was 179 to 180 ns, the p99 median 190 to
191 ns and the rate 5.05 to 5.07 M msg/s; a single round of either build
ranged 177 to 181 ns at p50. Read the two rows as indistinguishable: the
feature is 2 ns lower at p50 and 1 ns higher at p99, inside that spread, so
this recipe does not show it to be faster than the default build.

An earlier series on this same recipe reported 176 ns p50, 187 ns p99 and
5.14 M msg/s for the default build. Those values were not reproduced when the
release binary was measured again on the same host: no round of any build
reached 176 ns, and a build of an earlier revision measured the same as the
release binary, so the difference is not a change in the code. The figures in
the table are the ones a reader following this recipe should expect.

This is slower than the figure certified for an earlier revision
(p50 114 ns, p99 127 ns, 7.28 M msg/s with the same recipe). The changelog
lists what has and has not been attributed so far.

Scope: single-threaded; intra-process; one write followed by one take per
iteration; two wall-clock reads included. It is not a UDP result, a
cross-process result, a burst ceiling, a payload-bandwidth figure, a ROS 2
RMW result, or a cross-vendor comparison. A host that discovers any other
participant on the same domain sends every write down the wire path as well,
which is a different and much slower figure.

Reproduce the default build:

```bash
HDDS_INTERFACE=lo \
HDDS_BENCH_EXAMPLE=latency_benchmark_prof \
HDDS_BENCH_ROUNDS=5 \
./scripts/bench-repro.sh
```

The harness stamps the source revision, dirty state, CPU, pinned core,
governor, kernel, toolchain and build flags into JSON and keeps every round's
raw output; see `scripts/BENCH.md`. It has no feature switch: the feature row
was built the same way with `--features fast-consumer-gate`.

## Cross-thread intra-process write to take

Operation: writer and reader on two threads pinned to CPUs 2 and 3, one
sample every 200 us, 10,000 samples after 2,000 warm-up, BEST_EFFORT,
KEEP_LAST(1), idle states past C1 disabled on both cores, `HDDS_INTERFACE=lo`,
example `latency_benchmark_xthread` (`HDDS_XBENCH_ARM=both`), 10 rounds
interleaved between the two builds.

| Reader | Build | p50 | p99 |
|--------|-------|-----|-----|
| busy-polls `take()` | default | 369 ns | 596 ns |
| busy-polls `take()` | `--features fast-consumer-gate` | 379 ns | 616.5 ns |
| blocks in `WaitSet::wait()` | default | 2593 ns | 3027 ns |
| blocks in `WaitSet::wait()` | `--features fast-consumer-gate` | 2604.5 ns | 3036.5 ns |

The four rows above are one series, so they are comparable with each other. The
default build was measured again on the release head, on its own (10 rounds,
same regime): p50 366.5 ns and p99 595.5 ns polling, p50 2603.5 ns and p99
3006 ns on a WaitSet, with 0 of 100,000 samples missed polling and 10 of
100,000 on the WaitSet arm. That reproduces the default rows within 1 %, and
those are the figures quoted elsewhere for this release.

Over the 100,000 samples of each row, between 3 and 12 were replaced in the
KEEP_LAST(1) history before the reader took them (the reader thread was late
by more than one 200 us period); they count as missed, not as latency.
With the stock idle policy both arms are slower: the
cores' exit latency from deep idle lands inside the measurement.

```bash
HDDS_INTERFACE=lo HDDS_XBENCH_WRITER_CPU=2 HDDS_XBENCH_READER_CPU=3 HDDS_XBENCH_MESSAGES=10000 \
HDDS_XBENCH_WARMUP=2000 HDDS_XBENCH_INTERVAL_US=200 HDDS_XBENCH_ARM=both \
CARGO_PROFILE_RELEASE_LTO=thin CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
cargo run --release --locked -p hdds --example latency_benchmark_xthread
```

## Available Component Benches

The `hdds` crate also contains Criterion benches. Run all non-stress benches:

```bash
cargo bench -p hdds
```

Run one operation explicitly:

```bash
cargo bench -p hdds --bench write_latency
cargo bench -p hdds --bench read_latency
cargo bench -p hdds --bench discovery
cargo bench -p hdds --bench runtime
cargo bench -p hdds --bench reader_api
cargo bench -p hdds --bench throughput
```

The stress benches require their feature:

```bash
cargo bench -p hdds --features bench-stress --bench stress_multi_node
cargo bench -p hdds --features bench-stress --bench stress_phase7a
```

These commands produce local measurements, not automatically publishable
baselines. A number becomes a project claim only when its operation, payload,
QoS, topology, revision, environment, raw output, and calculation are retained
in a committed evidence certificate.

## Missing Measurement Matrix

There is currently no published result for:

- UDP latency and throughput, on loopback or over a real network;
- shared-memory latency and throughput;
- reliable-delivery throughput;
- serialization or history-cache operation costs;
- discovery convergence latency;
- per-entity memory use;
- ROS 2 application performance;
- comparisons with other DDS implementations;
- QoS or transport percentage impacts.

Until those measurements exist, do not infer values from the results above or
restore historical tables without their raw artifacts.

## Reporting Checklist

Every published result must include:

1. The exact operation and payload.
2. Transport, topology, QoS, and concurrency.
3. Source revision and dirty state.
4. Toolchain and complete build flags.
5. CPU, pinned core, governor, kernel, and relevant network configuration.
6. Warmup, sample count, round count, summary statistic, and variability.
7. Delivered, dropped, or timed-out sample counts.
8. A committed reproducer and hashes for the raw artifacts.

## Related Guides

- [Latency Tuning](tuning-latency.md)
- [Throughput Tuning](tuning-throughput.md)
