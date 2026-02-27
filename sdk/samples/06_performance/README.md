# 06 - Performance Samples

This directory contains samples demonstrating performance measurement and optimization techniques for HDDS.

## Overview

These samples help you measure and optimize DDS performance:
- **Latency**: Round-trip time measurement with percentile analysis
- **Throughput**: Maximum message rate and bandwidth
- **Batching**: Combine messages for efficiency
- **Zero-Copy**: Shared memory for large payloads

## Samples

| Sample | Description |
|--------|-------------|
| **latency** | Ping-pong latency measurement with histograms |
| **throughput** | Maximum messages/sec and MB/sec benchmarks |
| **batching** | Message batching for improved throughput |
| **zero_copy** | Shared memory for eliminating data copies |

## Sample Descriptions

### latency

Measures round-trip latency using ping-pong pattern:

- High-resolution timestamps (nanoseconds)
- Warmup phase for JIT and cache warming
- Statistical analysis (min, max, mean, std dev)
- Percentiles (p50, p90, p99, p99.9)
- ASCII histogram visualization

**Usage:**
```bash
# Run with 1000 samples
./latency 1000

# Run as pong (echo) side
./latency 1000 --pong
```

**Output:**
```
Round-trip latency (microseconds):
  Min:       45.23 us
  Max:      892.15 us
  Mean:     125.67 us
  StdDev:    45.32 us

Percentiles:
  p50:      112.45 us (median)
  p90:      178.92 us
  p99:      456.78 us
  p99.9:    789.12 us
```

### throughput

Measures maximum sustainable throughput:

- Publisher and subscriber modes
- Configurable payload size
- Messages/second and MB/second metrics
- Gbps calculation

**Usage:**
```bash
# Publisher mode (default)
./throughput --pub --duration 10 --size 256

# Subscriber mode
./throughput --sub --duration 10

# Large payload test
./throughput --size 65536 --duration 30
```

**Typical results:**
| Payload | Messages/sec | MB/sec | Gbps |
|---------|--------------|--------|------|
| 64 B | 1,000,000+ | 64 | 0.5 |
| 1 KB | 500,000+ | 500 | 4.0 |
| 64 KB | 50,000+ | 3,200 | 25.6 |

### batching

Demonstrates message batching for efficiency:

- Configurable batch size
- Timeout-based flushing
- Network packet reduction
- Throughput vs latency trade-off

**Key parameters:**
- `max_batch_size`: Maximum bytes per batch
- `batch_timeout`: Max wait time for batch
- `flush()`: Force send incomplete batch

**Comparison:**
| Configuration | Packets | Efficiency |
|---------------|---------|------------|
| No batching | 10,000 | 1.0x |
| Batch 1KB | 640 | 15.6x |
| Batch 8KB | 80 | 125x |
| Batch 64KB | 10 | 1000x |

### zero_copy

Shows zero-copy data transfer using shared memory:

- Loan API for buffer borrowing
- Intra-process pointer sharing
- Inter-process shared memory
- Performance comparison vs copy

**Key APIs:**
```cpp
// Writer side
void* buffer = writer.loan_sample(size);
fill_data(buffer);
writer.write_loaned(buffer);

// Reader side
auto sample = reader.take_loan();
process(sample.data);
reader.return_loan(sample);
```

**When to use:**
- Payload > 64 KB
- Same-host communication
- CPU-bound scenarios

## Performance Tuning Guide

### Latency Optimization

1. **Reduce batching** - smaller batches or disable
2. **Pin threads** - avoid scheduler migration
3. **Increase priority** - real-time scheduling
4. **Disable Nagle** - TCP_NODELAY for TCP transport
5. **Use UDP** - lower overhead than TCP

### Throughput Optimization

1. **Enable batching** - 8KB-64KB batch sizes
2. **Use zero-copy** - for large payloads
3. **Increase history** - larger queue depths
4. **Parallel writers** - multiple data streams
5. **Tune socket buffers** - SO_SNDBUF/SO_RCVBUF

### Memory Optimization

1. **Pre-allocate** - avoid runtime allocation
2. **Use loans** - reduce copies
3. **Pool buffers** - reuse allocations
4. **Align data** - cache line alignment
5. **Minimize fragmentation** - fixed-size messages

## Benchmarking Best Practices

### Warmup

Always include warmup phase:
```cpp
// Warmup (discard results)
for (int i = 0; i < WARMUP; i++) {
    send_message();
}

// Measurement
for (int i = 0; i < SAMPLES; i++) {
    measure_latency();
}
```

### Statistical Validity

- Run multiple iterations
- Calculate confidence intervals
- Report percentiles, not just mean
- Watch for outliers
- Account for system noise

### System Preparation

```bash
# Disable CPU frequency scaling
sudo cpupower frequency-set --governor performance

# Set process priority
sudo nice -n -20 ./benchmark

# Pin to CPU core
taskset -c 0 ./benchmark

# Increase socket buffers
sudo sysctl -w net.core.rmem_max=26214400
sudo sysctl -w net.core.wmem_max=26214400
```

## Building

### C
```bash
cd c
mkdir build && cd build
cmake ..
make
```

### C++
```bash
cd cpp
mkdir build && cd build
cmake ..
make
```

### Rust
```bash
cd rust
cargo build --release
```

### Python
```bash
cd python
python latency.py
```

## Performance Comparison Table

| Metric | Small (64B) | Medium (1KB) | Large (64KB) |
|--------|-------------|--------------|--------------|
| Latency | ~50 us | ~75 us | ~200 us |
| Throughput | 1M msg/s | 500K msg/s | 50K msg/s |
| Bandwidth | 64 MB/s | 500 MB/s | 3.2 GB/s |
| CPU Usage | Low | Medium | High |

## Common Issues

### High Latency Spikes
- Check for GC pauses (Java/Python)
- Verify no disk I/O in critical path
- Check for priority inversion
- Monitor system interrupts

### Low Throughput
- Check network bandwidth
- Verify batching is enabled
- Increase history depth
- Check for flow control

### Memory Growth
- Return loaned samples promptly
- Check for leaks in callback handlers
- Verify proper cleanup on shutdown
