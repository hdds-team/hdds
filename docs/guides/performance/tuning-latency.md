# Latency Optimization

Guide to achieving minimal latency in HDDS applications.

## Latency Components

```
Total Latency = Serialization + Queue + Network + Deserialization + Delivery

Typical breakdown (64-byte payload, same host):
  Serialization:    50 ns   (0.6%)
  Queue/History:    500 ns  (6%)
  Network (UDP):    5 us    (63%)
  Deserialization:  40 ns   (0.5%)
  Delivery:         2.4 us  (30%)
  ─────────────────────────────────
  Total:            ~8 us
```

## Transport Selection

### IntraProcess (Lowest Latency)

For same-process communication (zero-copy):

```rust
use hdds::{Participant, TransportMode};

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::IntraProcess)
    .build()?;
```

**Latency**: < 1 us for small payloads

:::note
`IntraProcess` only works within the same process. For cross-process or network communication, use `UdpMulticast`.
:::

### UDP Multicast (Network)

```rust
use hdds::{Participant, TransportMode};

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;
```

**Latency**: 20-100 us depending on network

## QoS Configuration

### Best Effort (Fastest)

```rust
use hdds::QoS;

let qos = QoS::best_effort().keep_last(1).volatile();
```

No acknowledgment overhead, but may lose samples.

### Low-Latency Reliable

```rust
use hdds::QoS;

let qos = QoS::reliable()
    .keep_last(1)       // Minimal buffering
    .volatile();        // No persistence overhead
```

### Disable Unnecessary Features

```rust
use hdds::QoS;
use std::time::Duration;

let qos = QoS::reliable()
    // No deadline monitoring (saves timer overhead)
    // Automatic liveliness (no manual assertions)
    .liveliness_automatic(Duration::from_secs(30));
```

## Writer Optimization

### Batching Disabled

For lowest latency, disable batching to send immediately:

```rust
use hdds::{Participant, QoS, DDS, TransportMode};

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

let topic = participant.topic::<SensorData>("SensorTopic")?;
let writer = topic
    .writer()
    .qos(QoS::best_effort().keep_last(1))
    .build()?;
```

### Pre-Register Instances

```rust
// Pre-register for keyed topics
let handle = writer.register_instance(&sample)?;

// Fast write path
loop {
    sample.value = get_sensor_value();
    writer.write_with_handle(&sample, handle)?;  // Skip key lookup
}
```

### Zero-Copy Write

```rust
// Loan buffer from writer (avoids copy)
let mut loan = writer.loan_sample()?;
*loan = SensorData {
    sensor_id: 1,
    value: 42.5,
    timestamp: now(),
};
loan.write()?;  // Direct to transport buffer
```

## Reader Optimization

### Polling Mode

```rust
// Tight polling loop (lowest latency)
loop {
    while let Some(sample) = reader.try_take()? {
        process(&sample);
    }
    // Optional: yield to prevent 100% CPU
    std::hint::spin_loop();
}
```

### WaitSet with Short Timeout

```rust
use hdds::WaitSet;
use std::time::Duration;

let waitset = WaitSet::new()?;
waitset.attach(reader.status_condition())?;

loop {
    // Short wait, fast wakeup
    if waitset.wait(Duration::from_micros(100)).is_ok() {
        while let Some(sample) = reader.try_take()? {
            process(&sample);
        }
    }
}
```

### Take vs Read

```rust
// try_take() is faster (no copy, removes from cache)
while let Some(sample) = reader.try_take()? {
    process(&sample);
}

// read() is slower (copies, keeps in cache)
for sample in reader.read()? {
    process(&sample);
}
```

## Threading Model

### Dedicated Reader Thread

```rust
use std::thread;

// Pin to CPU core for cache locality
let reader_thread = thread::Builder::new()
    .name("dds-reader".into())
    .spawn(move || {
        // Set thread priority (Linux)
        #[cfg(target_os = "linux")]
        unsafe {
            libc::setpriority(libc::PRIO_PROCESS, 0, -20);
        }

        loop {
            while let Some(sample) = reader.try_take().unwrap() {
                // Process inline, no channel overhead
                process_sample(&sample);
            }
        }
    })?;
```

### CPU Affinity

```rust
#[cfg(target_os = "linux")]
fn pin_to_core(core_id: usize) {
    use libc::{cpu_set_t, sched_setaffinity, CPU_SET};
    unsafe {
        let mut set: cpu_set_t = std::mem::zeroed();
        CPU_SET(core_id, &mut set);
        sched_setaffinity(0, std::mem::size_of::<cpu_set_t>(), &set);
    }
}
```

## Network Tuning

### Socket Buffer Sizes

```rust
use hdds::{Participant, TransportMode};

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .socket_buffer_size(4 * 1024 * 1024)  // 4 MB
    .build()?;
```

### Linux Kernel Parameters

```bash
# Increase socket buffers
sysctl -w net.core.rmem_max=16777216
sysctl -w net.core.wmem_max=16777216
sysctl -w net.core.rmem_default=4194304
sysctl -w net.core.wmem_default=4194304

# Reduce latency
sysctl -w net.ipv4.tcp_low_latency=1

# Disable Nagle's algorithm (already off for UDP)
# For TCP transport:
sysctl -w net.ipv4.tcp_nodelay=1
```

### Network Interface

```bash
# Disable interrupt coalescing
ethtool -C eth0 rx-usecs 0 tx-usecs 0

# Enable busy polling
sysctl -w net.core.busy_poll=50
sysctl -w net.core.busy_read=50
```

## Serialization Optimization

### Use Fixed-Size Types

```c
// Faster (no length prefix)
struct FastSensor {
    uint32 sensor_id;
    float values[8];  // Fixed array
};

// Slower (variable length)
struct SlowSensor {
    uint32 sensor_id;
    sequence<float> values;  // Dynamic sequence
};
```

### Minimize Payload Size

```c
// Use smallest types that fit
struct CompactSensor {
    uint16 sensor_id;    // Not uint32
    int16 value_x10;     // Fixed-point, not float
    uint32 timestamp_ms; // Not uint64 nanoseconds
};
```

## Discovery Optimization

### Fast Discovery

```rust
use hdds::{Participant, TransportMode};
use std::time::Duration;

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .discovery_interval(Duration::from_millis(50))  // Faster announcements
    .build()?;
```

### Static Discovery

```rust
use hdds::{Participant, TransportMode};

// Pre-configure peers for faster discovery
let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .add_static_peer("192.168.1.100:7400")
    .build()?;
```

## Measuring Latency

### Instrumentation

```rust
use std::time::Instant;

// Publisher side
let start = Instant::now();
writer.write(&sample)?;
let write_time = start.elapsed();

// Subscriber side (requires synchronized clocks or round-trip)
let receive_time = Instant::now();
while let Some(sample) = reader.try_take()? {
    let delivery_time = receive_time.duration_since(sample.timestamp);
}
```

### Latency Histogram

```rust
use std::time::Duration;

struct LatencyStats {
    samples: Vec<Duration>,
}

impl LatencyStats {
    fn add(&mut self, latency: Duration) {
        self.samples.push(latency);
    }

    fn percentile(&self, p: f64) -> Duration {
        let mut sorted = self.samples.clone();
        sorted.sort();
        let idx = (sorted.len() as f64 * p / 100.0) as usize;
        sorted[idx.min(sorted.len() - 1)]
    }

    fn report(&self) {
        println!("Latency p50: {:?}", self.percentile(50.0));
        println!("Latency p95: {:?}", self.percentile(95.0));
        println!("Latency p99: {:?}", self.percentile(99.0));
    }
}
```

## Latency Checklist

- [ ] Use shared memory transport when possible
- [ ] Set BestEffort reliability for non-critical data
- [ ] Use keep_last(1) history
- [ ] Disable batching
- [ ] Pre-register instances
- [ ] Use try_take() instead of read()
- [ ] Pin threads to CPU cores
- [ ] Tune socket buffer sizes
- [ ] Use fixed-size types in IDL
- [ ] Minimize payload size

## Common Latency Issues

| Issue | Symptom | Solution |
|-------|---------|----------|
| GC pauses | Periodic spikes | Use pre-allocated buffers |
| Lock contention | Inconsistent latency | Reduce shared state |
| Large payloads | High baseline | Fragment or compress |
| Multicast | Added delay | Use unicast |
| Reliable ACKs | Blocking writes | Increase history depth |

## Next Steps

- [Throughput Tuning](../../guides/performance/tuning-throughput.md) - Maximize bandwidth
- [Benchmarks](../../guides/performance/benchmarks.md) - Performance baselines
