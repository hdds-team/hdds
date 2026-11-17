# Throughput Optimization

Guide to achieving maximum throughput in HDDS applications.

## Throughput Factors

```
Throughput = min(
    Serialization rate,
    Network bandwidth,
    Writer capacity,
    Reader capacity,
    Transport efficiency
)
```

No throughput figure is published for UDP, shared memory or reliable delivery
(see [Benchmarks](benchmarks.md)); measure your own deployment.

## QoS Configuration

### Best Effort (Maximum Throughput)

```rust
use hdds::QoS;

let qos = QoS::best_effort().keep_last(1).volatile();
```

### High-Throughput Reliable

```rust
use hdds::QoS;

let qos = QoS::reliable()
    .keep_last(1000)    // Deeper history
    .volatile();
```

A deeper history gives a slow reader more room before a reliable writer's
`write()` has to wait.

## Writer Optimization

### Burst Writes

HDDS has no batching setting. Samples are written one by one:

```rust
// Collect samples
let batch: Vec<SensorData> = collect_samples();

// Write in a burst
for sample in &batch {
    writer.write(sample)?;
}
```

When a reliable writer's history is full, `write()` waits up to the QoS
`max_blocking_time` (100 ms by default), then fails with `Error::WriteTimeout`.
A best-effort writer does not wait.

### Backpressure from Write Errors

```rust
use hdds::QoS;
use std::time::Duration;

// Wait longer for room in the history before write() gives up
let qos = QoS::reliable()
    .keep_last(10000)
    .max_blocking_time(Duration::from_millis(500));

match writer.write(&sample) {
    Ok(()) => { /* written */ }
    Err(hdds::Error::WouldBlock) => {
        // No room right now (for example the payload pool is exhausted)
    }
    Err(hdds::Error::WriteTimeout) => {
        // The reader did not make room in time
    }
    Err(e) => return Err(e.into()),
}
```

### Pre-allocate Samples

```rust
// Reuse a sample to avoid allocation
let mut sample = SensorData::default();

for i in 0..1_000_000 {
    sample.sensor_id = 1;
    sample.value = get_value(i);
    sample.timestamp = now();
    writer.write(&sample)?;
}
```

### Multiple Writers

```rust
use hdds::{Participant, QoS};
use std::thread;

// Writers on separate threads, when one thread cannot keep up.
// Measure: the transport or the readers may be the limit.
let handles: Vec<_> = (0..4)
    .map(|_| {
        let participant = participant.clone();
        thread::spawn(move || -> Result<(), hdds::Error> {
            let topic = participant.topic::<SensorData>("SensorTopic")?;
            let writer = topic
                .writer()
                .qos(QoS::reliable().keep_last(1000))
                .build()?;

            let sample = SensorData::default();
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

## Reader Optimization

### Batch Reading

```rust
// Take up to 256 samples in one call
let samples = reader.take_batch(256)?;

// Or drain everything that is available
let samples = reader.take_all()?;
for sample in &samples {
    process(sample);
}

// Or read without removing, up to 256 samples
let samples = reader.read_batch(256)?;
```

`take_all()` drains the reader's history under one lock, so a coherent set is
observed whole.

### Parallel Processing

```rust
use rayon::prelude::*;

let samples = reader.take_all()?;

// Process in parallel
samples.par_iter().for_each(|sample| {
    process(sample);
});
```

### Multiple Readers (Partitioned)

```rust
use hdds::QoS;

// Create readers for different partitions; a reader matches the writers
// of its own partition
let topic = participant.topic::<SensorData>("SensorTopic")?;

let reader_a = topic
    .reader()
    .qos(QoS::reliable().partition_single("sensor_a"))
    .build()?;

let reader_b = topic
    .reader()
    .qos(QoS::reliable().partition_single("sensor_b"))
    .build()?;

// Process in parallel threads
```

## Transport Optimization

### Large Socket Buffers

HDDS requests an 8 MiB receive buffer on its user-data sockets by default; the
kernel caps the request at `net.core.rmem_max`. A receive buffer too small for a
burst of datagrams makes the kernel drop some, which a reliable reader repairs
with NACK_FRAG or ACKNACK requests. Set the sizes on the builder, or with the
`HDDS_RCVBUF_BYTES` and `HDDS_SNDBUF_BYTES` environment variables (the builder
value wins):

```rust
use hdds::{Participant, TransportMode};
use std::num::NonZeroUsize;

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .with_socket_receive_buffer_size(NonZeroUsize::new(16 * 1024 * 1024).unwrap())
    .with_socket_send_buffer_size(NonZeroUsize::new(16 * 1024 * 1024).unwrap())
    .build()?;
```

### Large Samples

A sample larger than 8192 bytes is sent as DATA_FRAG submessages and
reassembled by the reader; there is nothing to enable.

### IntraProcess for Same-Process Testing

```rust
use hdds::{Participant, TransportMode};

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::IntraProcess)  // Same process only
    .build()?;
```

:::note
`IntraProcess` only works within the same process. For cross-process or cross-host communication, use `UdpMulticast`.
:::

## Network Configuration

### Linux Kernel Tuning

```bash
# Raise buffer limits so that the requested socket buffer sizes are granted
# (example values)
sysctl -w net.core.rmem_max=268435456
sysctl -w net.core.wmem_max=268435456
sysctl -w net.core.netdev_max_backlog=100000
```

### Network Interface

```bash
# Host-level options; measure their effect in your deployment
ethtool -G eth0 rx 4096 tx 4096
ethtool -K eth0 gso on gro on tso on

# Jumbo frames, if every device on the path supports them
ip link set eth0 mtu 9000
```

## Payload Optimization

### Payload Size

Very small samples spend a large share of each datagram on RTPS headers;
combining several readings into one sample (for example a sequence member)
amortizes that. A sample larger than 8192 bytes is fragmented. No payload-size
guideline is published.

### Compression

```rust
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::Write;

// Compress large payloads
let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
encoder.write_all(&large_data)?;
let compressed = encoder.finish()?;

sample.compressed_data = compressed;
writer.write(&sample)?;
```

### Efficient Serialization

```c
// Use arrays instead of sequences
struct FixedData {
    float values[1024];  // Fixed, no length prefix
};

// Use bounded strings
struct LimitedData {
    string<64> name;  // Max 64 chars
};
```

## History and Resource Limits

### Writer History

```rust
use hdds::QoS;

let mut qos = QoS::reliable().keep_last(10000);
qos.resource_limits = hdds::qos::ResourceLimits {
    max_samples: 10000,
    max_instances: 1,
    max_samples_per_instance: 10000,
    ..Default::default()
};
```

### Reader History

```rust
use hdds::QoS;

let mut qos = QoS::reliable().keep_last(1000);
qos.resource_limits = hdds::qos::ResourceLimits {
    max_samples: 100000,
    max_instances: 100,
    max_samples_per_instance: 1000,
    ..Default::default()
};
```

The limits default to unlimited.

## Backpressure Handling

### Flow Control

```rust
use std::time::Duration;

// Wait until every matched reliable reader has acknowledged what was written
match writer.wait_for_acknowledgments(Duration::from_millis(100)) {
    Ok(()) => { /* readers caught up */ }
    Err(hdds::Error::AcknowledgmentTimeout) => {
        // Readers are behind: slow down publishing
    }
    Err(e) => return Err(e.into()),
}

// Or poll without blocking
if !writer.fully_acked() {
    // Some reliable reader has unacknowledged samples
}
```

### Adaptive Rate

```rust
use hdds::DataWriter;

struct AdaptivePublisher<T: hdds::DdsTrait> {
    writer: DataWriter<T>,
    rate: f64,
    min_rate: f64,
    max_rate: f64,
}

impl<T: hdds::DdsTrait> AdaptivePublisher<T> {
    fn publish(&mut self, sample: &T) -> Result<(), hdds::Error> {
        match self.writer.write(sample) {
            Ok(()) => {
                // Increase rate on success
                self.rate = (self.rate * 1.01).min(self.max_rate);
                Ok(())
            }
            Err(hdds::Error::WouldBlock) => {
                // Decrease rate on backpressure
                self.rate = (self.rate * 0.9).max(self.min_rate);
                Err(hdds::Error::WouldBlock)
            }
            Err(e) => Err(e),
        }
    }
}
```

## Measuring Throughput

```rust
use std::time::{Duration, Instant};

let start = Instant::now();

loop {
    writer.write(&sample)?;

    if start.elapsed() >= Duration::from_secs(10) {
        break;
    }
}

// Counters kept by the writer: serialized payload bytes, before RTPS framing
let stats = writer.stats();
let elapsed = start.elapsed().as_secs_f64();
println!("Throughput: {:.0} msg/s", stats.messages_sent as f64 / elapsed);
println!("Payload: {:.2} MB/s", stats.bytes_sent as f64 / elapsed / 1_000_000.0);
```

A writer's counters measure what it wrote, not what a reader received. Compare
with a reader-side count and with the delivered and dropped sample counts of a
reproducible harness (see the reporting checklist in [Benchmarks](benchmarks.md)).

## Throughput Checklist

- [ ] Use BestEffort for non-critical high-rate data
- [ ] Increase history depth for reliable delivery
- [ ] Use large socket buffers
- [ ] Keep shared memory enabled for same-host peers (the default)
- [ ] Pre-allocate and reuse samples
- [ ] Use parallel writers/readers
- [ ] Compress large payloads
- [ ] Handle backpressure gracefully

## Common Throughput Issues

| Issue | Symptom | Solution |
|-------|---------|----------|
| Small payloads | Per-sample overhead dominates | Combine readings into one sample |
| Reliable blocking | Writer stalls, then `WriteTimeout` | Increase history |
| Slow reader | Best-effort samples lost, reliable writer waits | Speed up the reader loop, deepen the history |
| Network saturation | Packet loss | Reduce rate |
| CPU bottleneck | Low throughput | Parallel processing |

## Next Steps

- [Latency Tuning](../../guides/performance/tuning-latency.md) - Minimize latency
- [Benchmarks](../../guides/performance/benchmarks.md) - Performance baselines
