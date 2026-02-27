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
    .keep_last(1000)    // Large buffer
    .volatile();
```

Large history depth prevents blocking when reader is slow.

## Batching

### Enable Batching

```rust
use hdds::{Participant, QoS, DDS, TransportMode};
use std::time::Duration;

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

let topic = participant.topic::<SensorData>("SensorTopic")?;
let writer = topic
    .writer()
    .qos(QoS::reliable()
        .keep_last(1000)
        .batching(true)
        .max_batch_size(64 * 1024)                    // 64 KB batches
        .batch_flush_period(Duration::from_millis(1)))
    .build()?;
```

### Manual Batching

```rust
// Collect samples
let batch: Vec<SensorData> = collect_samples();

// Write in burst
for sample in batch {
    writer.write(&sample)?;
}

// Explicit flush
writer.flush()?;
```

## Writer Optimization

### Asynchronous Write

```rust
use hdds::QoS;

// Non-blocking write (queue and continue)
let qos = QoS::reliable().keep_last(10000);

// Write without waiting
match writer.write(&sample) {
    Ok(()) => { /* queued */ }
    Err(hdds::Error::WouldBlock) => {
        // Buffer full, handle backpressure
    }
    Err(e) => return Err(e.into()),
}
```

### Pre-allocate Samples

```rust
// Reuse sample to avoid allocation
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
use hdds::{Participant, QoS, DDS, TransportMode};
use std::thread;

// Parallel writers for higher throughput
let handles: Vec<_> = (0..4)
    .map(|i| {
        let participant = participant.clone();
        thread::spawn(move || -> Result<(), hdds::Error> {
            let topic = participant.topic::<SensorData>("SensorTopic")?;
            let writer = topic
                .writer()
                .qos(QoS::reliable().keep_last(1000))
                .build()?;

            for j in 0..250_000 {
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
// Take all available samples
while let Some(sample) = reader.try_take()? {
    process(&sample);
}

// Or read without removing
for sample in reader.read()? {
    process(&sample);
}
```

### Parallel Processing

```rust
use rayon::prelude::*;

let samples: Vec<_> = std::iter::from_fn(|| reader.try_take().ok().flatten())
    .collect();

// Process in parallel
samples.par_iter().for_each(|sample| {
    process(sample);
});
```

### Multiple Readers (Partitioned)

```rust
use hdds::{Participant, QoS, DDS, TransportMode};

// Create readers for different partitions
let topic = participant.topic::<SensorData>("SensorTopic")?;

let reader_a = topic
    .reader()
    .qos(QoS::reliable().partition(&["sensor_a"]))
    .build()?;

let reader_b = topic
    .reader()
    .qos(QoS::reliable().partition(&["sensor_b"]))
    .build()?;

// Process in parallel threads
```

## Transport Optimization

### Large Socket Buffers

```rust
use hdds::{Participant, TransportMode};

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .socket_buffer_size(16 * 1024 * 1024)  // 16 MB
    .build()?;
```

### UDP with Fragmentation

```rust
use hdds::{Participant, TransportMode};

// Enable for payloads > 64 KB
let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .max_message_size(256 * 1024)  // 256 KB max
    .build()?;
```

### IntraProcess for Same-Process Testing

```rust
use hdds::{Participant, TransportMode};

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::IntraProcess)  // Zero-copy, same process only
    .build()?;
```

:::note
`IntraProcess` provides maximum throughput but only works within the same process. For cross-process or cross-host communication, use `UdpMulticast`.
:::

## Network Configuration

### Linux Kernel Tuning

```bash
# Increase buffer limits
sysctl -w net.core.rmem_max=268435456
sysctl -w net.core.wmem_max=268435456
sysctl -w net.core.netdev_max_backlog=100000

# UDP buffer sizes
sysctl -w net.ipv4.udp_rmem_min=16384
sysctl -w net.ipv4.udp_wmem_min=16384
```

### Network Interface

```bash
# Increase ring buffer
ethtool -G eth0 rx 4096 tx 4096

# Enable hardware offloading
ethtool -K eth0 gso on gro on tso on

# Set MTU (if supported)
ip link set eth0 mtu 9000  # Jumbo frames
```

## Payload Optimization

### Optimal Payload Sizes

| Payload Size | Efficiency | Use Case |
|-------------|------------|----------|
| < 64 bytes | Low (header overhead) | Status flags |
| 256-1024 bytes | Good | Sensor data |
| 4-16 KB | Optimal | Video frames |
| 64 KB+ | Fragmentation overhead | Bulk transfer |

### Compression

```rust
use flate2::write::GzEncoder;
use flate2::Compression;

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
struct FastData {
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

let qos = QoS::reliable()
    .keep_last(10000)
    .max_samples(10000)
    .max_instances(1)
    .max_samples_per_instance(10000);
```

### Reader History

```rust
use hdds::QoS;

let qos = QoS::reliable()
    .keep_last(1000)
    .max_samples(100000)
    .max_instances(100)
    .max_samples_per_instance(1000);
```

## Backpressure Handling

### Flow Control

```rust
// Monitor write status
let status = writer.deadline_missed_status()?;
if status.total_count > 0 {
    // Slow down publishing
    publish_rate *= 0.9;
}

// Check for blocked writes
match writer.write(&sample) {
    Err(hdds::Error::Timeout) => {
        eprintln!("Reader can't keep up!");
        // Reduce rate or drop samples
    }
    _ => {}
}
```

### Adaptive Rate

```rust
use hdds::DataWriter;

struct AdaptivePublisher<T> {
    writer: DataWriter<T>,
    rate: f64,
    min_rate: f64,
    max_rate: f64,
}

impl<T: hdds::DDS> AdaptivePublisher<T> {
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
let mut count = 0u64;
let mut bytes = 0u64;
let sample_size = std::mem::size_of::<SensorData>() as u64;

loop {
    writer.write(&sample)?;
    count += 1;
    bytes += sample_size;

    if start.elapsed() >= Duration::from_secs(10) {
        break;
    }
}

let elapsed = start.elapsed().as_secs_f64();
println!("Throughput: {:.0} msg/s", count as f64 / elapsed);
println!("Bandwidth: {:.2} MB/s", bytes as f64 / elapsed / 1_000_000.0);
```

## Throughput Checklist

- [ ] Use BestEffort for non-critical high-rate data
- [ ] Enable batching for small messages
- [ ] Increase history depth for reliable delivery
- [ ] Use large socket buffers
- [ ] Enable shared memory for same-host
- [ ] Pre-allocate and reuse samples
- [ ] Use parallel writers/readers
- [ ] Compress large payloads
- [ ] Handle backpressure gracefully
- [ ] Use optimal payload sizes (256-16KB)

## Common Throughput Issues

| Issue | Symptom | Solution |
|-------|---------|----------|
| Small payloads | Low bandwidth | Batch messages |
| Reliable blocking | Writer stalls | Increase history |
| Slow reader | Dropped samples | Add readers/partitions |
| Network saturation | Packet loss | Reduce rate |
| CPU bottleneck | Low throughput | Parallel processing |

## Next Steps

- [Latency Tuning](../../guides/performance/tuning-latency.md) - Minimize latency
- [Benchmarks](../../guides/performance/benchmarks.md) - Performance baselines
