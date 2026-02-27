# Performance Benchmarks

Reference performance measurements for HDDS components.

## Test Environment

| Component | Specification |
|-----------|---------------|
| CPU | AMD EPYC 7763 (64 cores) |
| Memory | 256 GB DDR4-3200 |
| Network | 25 Gbps Ethernet |
| OS | Linux 6.1 (Debian 12) |
| Rust | 1.75+ (release build) |

## Latency Benchmarks

### End-to-End Latency (Same Host)

| Payload Size | p50 | p95 | p99 |
|-------------|-----|-----|-----|
| 64 bytes | 8 us | 15 us | 25 us |
| 256 bytes | 10 us | 18 us | 30 us |
| 1 KB | 15 us | 25 us | 45 us |
| 4 KB | 25 us | 45 us | 80 us |
| 64 KB | 120 us | 200 us | 350 us |

### Shared Memory Transport

| Payload Size | p50 | p95 | p99 |
|-------------|-----|-----|-----|
| 64 bytes | 1.2 us | 2.5 us | 4 us |
| 256 bytes | 1.5 us | 3 us | 5 us |
| 1 KB | 2 us | 4 us | 7 us |
| 4 KB | 4 us | 8 us | 15 us |

### UDP Unicast (Same LAN)

| Payload Size | p50 | p95 | p99 |
|-------------|-----|-----|-----|
| 64 bytes | 45 us | 80 us | 150 us |
| 256 bytes | 50 us | 90 us | 180 us |
| 1 KB | 60 us | 110 us | 220 us |
| 4 KB | 90 us | 160 us | 300 us |

## Throughput Benchmarks

### Message Rate (BestEffort)

| Payload Size | Throughput (msg/s) | Bandwidth |
|-------------|-------------------|-----------|
| 64 bytes | 2.5 M | 160 MB/s |
| 256 bytes | 1.8 M | 460 MB/s |
| 1 KB | 850 K | 850 MB/s |
| 4 KB | 280 K | 1.1 GB/s |
| 64 KB | 35 K | 2.2 GB/s |

### Message Rate (Reliable)

| Payload Size | Throughput (msg/s) | Bandwidth |
|-------------|-------------------|-----------|
| 64 bytes | 1.2 M | 77 MB/s |
| 256 bytes | 900 K | 230 MB/s |
| 1 KB | 450 K | 450 MB/s |
| 4 KB | 150 K | 600 MB/s |

### Sustained Throughput

```
RingBuffer ingestion: 10.4 M msg/s (256 bytes)
Capture file write:   481 MB/s (sequential)
Capture file read:    5.3 M frames/s
```

## Component Benchmarks

### Serialization (CDR2)

| Operation | 64 B | 256 B | 1 KB | 4 KB |
|-----------|------|-------|------|------|
| Serialize | 50 ns | 120 ns | 400 ns | 1.5 us |
| Deserialize | 40 ns | 100 ns | 350 ns | 1.3 us |

### History Cache

| Operation | Time |
|-----------|------|
| Insert sample | 150 ns |
| Lookup by key | 80 ns |
| Remove sample | 120 ns |
| Match ACK | 200 ns |

### Discovery

| Operation | Time |
|-----------|------|
| SPDP parse | 5 us |
| SEDP parse | 8 us |
| Endpoint match | 2 us |
| Cold start (2 participants) | 150-300 ms |

## Memory Usage

### Per-Entity Overhead

| Entity | Memory |
|--------|--------|
| DomainParticipant | ~2 MB |
| Publisher | ~64 KB |
| Subscriber | ~64 KB |
| DataWriter | ~128 KB + history |
| DataReader | ~128 KB + history |
| Topic | ~16 KB |

### History Cache Memory

```
Memory = instances x history_depth x sample_size + overhead

Example (100 sensors, 10-deep history, 1KB samples):
= 100 x 10 x 1024 + 100 x 256
= 1.02 MB + 25 KB = ~1.05 MB
```

## Running Benchmarks

### Built-in Benchmarks

```bash
# Run all benchmarks
cargo bench --package hdds

# Latency benchmark
cargo bench --package hdds -- latency

# Throughput benchmark
cargo bench --package hdds -- throughput

# Serialization benchmark
cargo bench --package hdds -- serialize
```

### Performance Testing Tool

```bash
# Publisher side
hdds-perf pub --topic Benchmark --rate 10000 --size 256

# Subscriber side
hdds-perf sub --topic Benchmark --stats
```

Output:
```
Received 100000 samples in 10.02s
  Throughput: 9980 msg/s (2.55 MB/s)
  Latency p50: 45 us, p95: 82 us, p99: 156 us
  Jitter: 12 us (std dev)
```

## Profiling

### CPU Profiling

```bash
# Using perf
perf record -g cargo run --release --example benchmark
perf report

# Using flamegraph
cargo flamegraph --example benchmark
```

### Memory Profiling

```bash
# Using heaptrack
heaptrack cargo run --release --example benchmark
heaptrack_gui heaptrack.benchmark.*.gz
```

## Performance Targets

### Real-Time Targets

| Metric | Target | Notes |
|--------|--------|-------|
| Latency p99 | < 100 us | Same host, < 1 KB |
| Jitter | < 20 us | Standard deviation |
| Message rate | > 100 K/s | Per writer |

### High-Throughput Targets

| Metric | Target | Notes |
|--------|--------|-------|
| Bandwidth | > 1 GB/s | Large payloads |
| Message rate | > 1 M/s | Small payloads |
| CPU efficiency | < 5% per 100K msg/s | |

## Comparison with Other Implementations

| Metric | HDDS | FastDDS | CycloneDDS |
|--------|------|---------|------------|
| Latency (64B) | 8 us | 12 us | 10 us |
| Throughput | 2.5 M/s | 1.8 M/s | 2.2 M/s |
| Memory (idle) | 2 MB | 4 MB | 3 MB |

*Measurements on equivalent hardware and configuration.*

## Optimization Impact

### QoS Impact on Performance

| Configuration | Latency | Throughput |
|---------------|---------|------------|
| BestEffort + KeepLast(1) | Baseline | Baseline |
| Reliable + KeepLast(10) | +20% | -30% |
| Reliable + KeepAll | +50% | -50% |
| + TransientLocal | +10% | -10% |

### Transport Impact

| Transport | Latency | Throughput |
|-----------|---------|------------|
| Shared Memory | 1x | 1x |
| UDP Loopback | 4x | 0.7x |
| UDP Network | 10x | 0.5x |

## Next Steps

- [Latency Tuning](../../guides/performance/tuning-latency.md) - Minimize latency
- [Throughput Tuning](../../guides/performance/tuning-throughput.md) - Maximize bandwidth
