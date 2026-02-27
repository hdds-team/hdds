# Performance Issues

Identify and resolve performance problems in HDDS applications.

## Diagnosing Performance Issues

### Quick Health Check

```bash
# Check CPU usage
top -H -p $(pgrep my_app)

# Check memory
ps -o rss,vsz,pid,cmd -p $(pgrep my_app)

# Check network
ss -u -n | grep 7400
netstat -su
```

### Identify Bottleneck

```
Performance issue?
       │
       ▼
   High CPU? ──────────> Profiling section
       │
       ▼
   High memory? ───────> Memory section
       │
       ▼
   High latency? ──────> Latency section
       │
       ▼
   Low throughput? ────> Throughput section
       │
       ▼
   Packet loss? ───────> Network section
```

## High Latency

### Symptoms

- End-to-end delay exceeds requirements
- Inconsistent timing (jitter)
- Timeout errors

### Diagnosis

```rust
use std::time::Instant;

// Measure write latency
let start = Instant::now();
writer.write(&sample)?;
let write_time = start.elapsed();
println!("Write took: {:?}", write_time);

// If blocking:
if write_time > std::time::Duration::from_millis(10) {
    println!("Write blocked - check reliability/history");
}
```

### Solutions

**1. Use Best Effort for non-critical data:**
```rust
use hdds::QoS;

let qos = QoS::best_effort().keep_last(1);
```

**2. Use IntraProcess for same-process communication:**
```rust
use hdds::{Participant, TransportMode};

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::IntraProcess)  // Zero-copy, same process only
    .build()?;
```

**3. Reduce history depth:**
```rust
use hdds::QoS;

let qos = QoS::reliable().keep_last(1);
```

**4. Disable batching:**
(Batching is disabled by default for lowest latency)

**5. Tune network:**
```bash
# Reduce buffer bloat
sysctl -w net.core.rmem_default=262144
sysctl -w net.core.wmem_default=262144

# Disable interrupt coalescing
ethtool -C eth0 rx-usecs 0 tx-usecs 0
```

## Low Throughput

### Symptoms

- Can't achieve expected message rate
- Publish rate limited
- Bandwidth underutilized

### Diagnosis

```rust
use std::time::{Duration, Instant};

// Measure throughput
let start = Instant::now();
let mut count = 0;

while start.elapsed() < Duration::from_secs(10) {
    match writer.write(&sample) {
        Ok(()) => count += 1,
        Err(hdds::Error::WouldBlock) => {
            // Buffer full - backpressure
            println!("Backpressure at {} samples", count);
            break;
        }
        Err(e) => return Err(e.into()),
    }
}

println!("Throughput: {} samples/sec", count as f64 / 10.0);
```

### Solutions

**1. Increase history buffer:**
```rust
use hdds::QoS;

let qos = QoS::reliable()
    .keep_last(10000)
    .max_samples(10000);
```

**2. Enable batching:**
```rust
use hdds::QoS;
use std::time::Duration;

let qos = QoS::reliable()
    .keep_last(1000)
    .batching(true)
    .max_batch_size(64 * 1024)
    .batch_flush_period(Duration::from_millis(1));
```

**3. Use parallel writers:**
```rust
use hdds::{Participant, QoS, DDS, TransportMode};
use std::thread;

// Multiple writers for parallel publishing
let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

let handles: Vec<_> = (0..4)
    .map(|_| {
        let participant = participant.clone();
        thread::spawn(move || -> Result<(), hdds::Error> {
            let topic = participant.topic::<SensorData>("data")?;
            let writer = topic.writer().qos(QoS::reliable()).build()?;

            for _ in 0..250_000 {
                writer.write(&sample)?;
            }
            Ok(())
        })
    })
    .collect();

for handle in handles {
    handle.join().unwrap()?;
}
```

**4. Increase socket buffers:**
```bash
sysctl -w net.core.rmem_max=16777216
sysctl -w net.core.wmem_max=16777216
```

```rust
use hdds::{Participant, TransportMode};

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .socket_buffer_size(16 * 1024 * 1024)
    .build()?;
```

**5. Use IntraProcess for same-process testing:**
```rust
use hdds::{Participant, TransportMode};

// For same-process: maximum throughput (zero-copy)
let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::IntraProcess)
    .build()?;
```

:::note
`IntraProcess` only works within the same process. For cross-process communication, use `UdpMulticast`.
:::

## High CPU Usage

### Symptoms

- CPU at 100% on one or more cores
- System becomes unresponsive
- Other processes starved

### Diagnosis

```bash
# Profile with perf
perf record -g ./my_app
perf report

# Or flamegraph
cargo flamegraph --bin my_app
```

### Solutions

**1. Reduce polling:**
```rust
use std::time::Duration;

// Bad: busy loop
loop {
    while let Some(sample) = reader.try_take()? {
        process(&sample);
    }
    // 100% CPU!
}

// Good: sleep between polls
loop {
    while let Some(sample) = reader.try_take()? {
        process(&sample);
    }
    std::thread::sleep(Duration::from_millis(10));
}

// Better: use WaitSet
use hdds::WaitSet;

let waitset = WaitSet::new()?;
waitset.attach(reader.status_condition())?;

loop {
    waitset.wait(Duration::from_secs(1))?;
    while let Some(sample) = reader.try_take()? {
        process(&sample);
    }
}
```

**2. Reduce logging:**
```bash
# Production: errors only
export RUST_LOG=hdds=error
```

**3. Use release build:**
```bash
cargo build --release
```

**4. Offload processing:**
```rust
use std::sync::mpsc;
use std::thread;

// Receive in one thread
let (tx, rx) = mpsc::channel();
thread::spawn(move || {
    loop {
        while let Some(sample) = reader.try_take().unwrap() {
            tx.send(sample).unwrap();
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
});

// Process in another
thread::spawn(move || {
    while let Ok(sample) = rx.recv() {
        heavy_processing(&sample);  // Won't block reader
    }
});
```

## High Memory Usage

### Symptoms

- Memory grows over time
- OOM errors
- System swapping

### Diagnosis

```bash
# Track allocations
heaptrack ./my_app
heaptrack_gui heaptrack.my_app.*.gz

# Check at runtime
ps -o rss,vsz,pid,cmd -p $(pgrep my_app)
```

### Solutions

**1. Limit history:**
```rust
use hdds::QoS;

// Don't use keep_all() without limits
let qos = QoS::reliable()
    .keep_last(100)  // Not keep_all()
    .max_samples(1000)
    .max_instances(100)
    .max_samples_per_instance(10);
```

**2. Dispose instances:**
```rust
// For keyed topics, dispose old instances
writer.dispose(&sample)?;

// Or unregister to free memory
writer.unregister_instance(&sample)?;
```

**3. Reduce sample size:**
```c
// Use bounded types
struct Efficient {
    string<256> name;    // Max 256 chars
    sequence<float, 100> values;  // Max 100 elements
};
```

**4. Use external storage:**
```c
// Mark large fields as external
struct LargeData {
    @external sequence<octet> image_data;
};
```

## Packet Loss

### Symptoms

- `SampleLost` callbacks
- Sequence gaps
- Unreliable even with `Reliable` QoS

### Diagnosis

```bash
# Check interface errors
ip -s link show eth0 | grep -E "(dropped|errors)"

# Check socket buffer overruns
netstat -su | grep buffer

# Check HDDS stats
export RUST_LOG=hdds::transport=debug
```

### Solutions

**1. Increase socket buffers:**
```bash
sysctl -w net.core.rmem_max=16777216
sysctl -w net.core.wmem_max=16777216
```

**2. Increase history for reliable:**
```rust
use hdds::QoS;

// More retransmission buffer
let qos = QoS::reliable().keep_last(1000);
```

**3. Reduce publish rate:**
```rust
use std::time::{Duration, Instant};

// Implement rate limiting
let interval = Duration::from_micros(100);  // 10kHz max
let mut last_write = Instant::now();

loop {
    let elapsed = last_write.elapsed();
    if elapsed < interval {
        std::thread::sleep(interval - elapsed);
    }
    writer.write(&sample)?;
    last_write = Instant::now();
}
```

**4. Use flow control:**
```rust
use std::time::Duration;

// Check backpressure before writing
loop {
    match writer.write(&sample) {
        Ok(()) => break,
        Err(hdds::Error::WouldBlock) => {
            // Back off
            std::thread::sleep(Duration::from_millis(1));
        }
        Err(e) => return Err(e.into()),
    }
}
```

## Discovery Performance

### Symptoms

- Slow startup
- Takes seconds to match endpoints
- Frequent re-discovery

### Solutions

**1. Static discovery:**
```rust
use hdds::{Participant, TransportMode};

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .add_static_peer("192.168.1.100:7400")
    .build()?;
```

**2. Faster announcements:**
```rust
use hdds::{Participant, TransportMode};
use std::time::Duration;

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .discovery_interval(Duration::from_millis(50))
    .build()?;
```

**3. Shorter lease:**
```rust
use hdds::{Participant, TransportMode};
use std::time::Duration;

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .lease_duration(Duration::from_secs(10))
    .build()?;
```

## Performance Tuning Checklist

### Low Latency

- [ ] Use `IntraProcess` transport (same-process only, zero-copy)
- [ ] Best effort reliability (if acceptable)
- [ ] keep_last(1) history
- [ ] Disable batching
- [ ] Pre-register instances
- [ ] Pin threads to CPU cores
- [ ] Disable kernel interrupt coalescing

### High Throughput

- [ ] Enable batching
- [ ] Large history buffers
- [ ] Large socket buffers
- [ ] Multiple parallel writers
- [ ] Use `IntraProcess` for same-process benchmarks
- [ ] Compress large payloads
- [ ] Use fixed-size types

### Low Memory

- [ ] keep_last with small depth
- [ ] Set resource limits
- [ ] Dispose/unregister instances
- [ ] Use bounded types
- [ ] Mark large fields external
- [ ] Monitor and alert

### Low CPU

- [ ] Use WaitSet instead of polling
- [ ] Release builds
- [ ] Reduce logging
- [ ] Offload processing to threads
- [ ] Use efficient serialization

## Performance Monitoring

```rust
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

// Add performance metrics
struct PerformanceMonitor {
    throughput_counter: AtomicU64,
    last_report: Instant,
}

impl PerformanceMonitor {
    fn new() -> Self {
        Self {
            throughput_counter: AtomicU64::new(0),
            last_report: Instant::now(),
        }
    }

    fn record_sample(&self) {
        self.throughput_counter.fetch_add(1, Ordering::Relaxed);
    }

    fn report(&self) {
        let elapsed = self.last_report.elapsed().as_secs_f64();
        let count = self.throughput_counter.load(Ordering::Relaxed);
        let throughput = count as f64 / elapsed;

        println!("Performance Report:");
        println!("  Throughput: {:.0} samples/sec", throughput);
    }
}
```

## Next Steps

- [Common Issues](../troubleshooting/common-issues.md) - General troubleshooting
- [Debug Guide](../troubleshooting/debug-guide.md) - Debugging techniques
- [Benchmarks](../guides/performance/benchmarks.md) - Performance baselines
