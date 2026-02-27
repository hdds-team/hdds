# System Limits

This page documents the hard limits and recommended values for HDDS configuration.

## Domain & Participant Limits

| Limit | Value | Notes |
|-------|-------|-------|
| Domain ID range | 0-232 | 233 domains max (RTPS spec) |
| Participants per domain | 0-119 | 120 participants max |
| Total participants | 27,960 | 233 × 120 |

## Port Ranges

| Port Type | Formula | Domain 0, Participant 0 |
|-----------|---------|-------------------------|
| SPDP Multicast | 7400 + (250 × domainId) | 7400 |
| SEDP Unicast | 7410 + (250 × domainId) + (2 × participantId) | 7410 |
| User Unicast | 7411 + (250 × domainId) + (2 × participantId) | 7411 |
| Data Multicast | 7401 + (250 × domainId) | 7401 |

**Port range per domain:** 7400-7469 (70 ports)

## Resource Limits (Default)

| Resource | Default | Maximum |
|----------|---------|---------|
| max_samples | 100,000 | Platform memory |
| max_instances | 1 | Platform memory |
| max_samples_per_instance | 100,000 | ≤ max_samples |
| max_quota_bytes | 100 MB | Platform memory |

## Message Size Limits

| Limit | Value | Notes |
|-------|-------|-------|
| Max CDR payload | 16 MB | Per message |
| Max UDP datagram | 65,507 bytes | Fragmented if larger |
| RTPS fragment size | 64 KB | Default fragmentation |

## Discovery Timing

| Parameter | Default | Adjustable |
|-----------|---------|------------|
| SPDP announcement period | 3 seconds | Yes |
| SPDP aggressive phase | 200 ms × 5 | First 5 announcements |
| Participant lease duration | 30 seconds | Yes |
| Lease check interval | 1 second | Internal |

## History Limits

| Configuration | Constraint |
|---------------|------------|
| KEEP_LAST depth | > 0 |
| KEEP_ALL | Limited by ResourceLimits |
| Queue validation | max_samples ≥ max_samples_per_instance × max_instances |

## Identifier Limits

| Limit | Value |
|-------|-------|
| Topic name length | 256 characters |
| Type name length | 256 characters |
| Partition name | 256 characters |
| UserData size | 64 KB |

## IDL Limits (hdds_gen)

| Limit | Value |
|-------|-------|
| Identifier length | 255 characters |
| Collection nesting depth | 5 levels |
| Reserved keywords | 34 words |
| Supported annotations | 26 standard |

## Shared Memory Transport

:::warning Experimental
Shared memory transport is experimental with significant limitations.
:::

| Parameter | Default |
|-----------|---------|
| Ring buffer slots | 256 (power of 2) |
| Payload size per slot | 4 KB |
| Writer push latency | < 200 ns |
| Reader poll latency | < 100 ns |

### SHM Limitations

| Limitation | Description |
|------------|-------------|
| **QoS Support** | BestEffort only - no ACK/NACK/retransmission |
| **Platforms** | Linux/macOS (POSIX shm_open) - Windows not supported |
| **Data Loss** | Possible overrun if reader is slow (lock-free ring buffer) |
| **Cross-Vendor** | No interop with other DDS vendors (Iceoryx, RTI SHM) |
| **Security** | CryptoPlugin bypassed on SHM path |

### When to Use SHM

✅ **Good for:**
- High-frequency sensor data (same host)
- BestEffort acceptable scenarios
- Maximum performance (< 1μs latency)
- Single-process / intra-process communication

❌ **Not for:**
- Reliable delivery requirements
- Cross-host communication
- Mixed vendor environments
- Security-critical data

## Performance Benchmarks

| Metric | Value |
|--------|-------|
| Write latency (best) | 257 ns |
| Throughput | 4.48 M msg/s |
| Memory (idle) | < 100 KB |
| Memory (per topic) | < 50 KB |

## hdds_viewer Limits

| Limit | Value |
|-------|-------|
| Frame table buffer | 10,000 messages |
| Timeline buffer | 10,000 messages |
| Undo history | 100 levels |
| Write throughput | 625 MB/s |
| Ingestion rate | 41 M msg/s |

## Recommended Practices

### High Frequency Topics (> 1000 Hz)

```rust
use hdds::QoS;

let qos = QoS::best_effort().keep_last(1);
```

### Large Messages (> 64 KB)

```rust
use hdds::QoS;
use std::time::Duration;

let qos = QoS::reliable()
    .max_blocking_time(Duration::from_secs(5))
    .max_quota_bytes(500 * 1024 * 1024);  // 500 MB
```

### Many Instances (> 1000)

```rust
use hdds::QoS;

let qos = QoS::reliable()
    .max_instances(10_000)
    .max_samples_per_instance(10)
    .max_samples(100_000);
```
