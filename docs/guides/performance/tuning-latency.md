# Latency Optimization

Guide to achieving minimal latency in HDDS applications.

## Latency Components

```
Total Latency = Serialization + Queue + Network + Deserialization + Delivery
```

The relative cost of these components depends on transport, payload, QoS,
topology, and machine. No numeric breakdown is published; measure your own
deployment.

## Transport Selection

### IntraProcess (Lowest Latency)

For same-process communication:

```rust
use hdds::{Participant, TransportMode};

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::IntraProcess)
    .build()?;
```

The published figure for this path is one operation: `write(16-byte POD)`
then `take()` on one thread, 180 ns p50 and 190 ns p99 on the benchmark host
(Intel i9-9900KF, performance governor) for 1.5.0 (regime and reproducer in
[Benchmarks](benchmarks.md)). Keep the operation name beside the number; it is
not a generic transport latency.

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

UDP latency depends on the hosts, network, socket configuration, QoS, and
payload. Measure the deployment topology instead of applying an unscoped
range.

Participants on the same host advertise shared memory and use it for
qualifying pairings by default (`ShmPolicy::Prefer`); `shm_disable()` on the
builder turns it off. No shared-memory latency figure is published.

## QoS Configuration

### Best Effort (Fastest)

```rust
use hdds::QoS;

let qos = QoS::best_effort().keep_last(1).volatile();
```

No acknowledgment traffic, but samples may be lost.

### Low-Latency Reliable

```rust
use hdds::QoS;

let qos = QoS::reliable()
    .keep_last(1)       // Minimal buffering
    .volatile();        // No persistence
```

### Leave Optional Policies Unset

```rust
use hdds::QoS;

let qos = QoS::reliable()
    // No deadline monitoring: leave DEADLINE unset unless the application needs it
    // Automatic liveliness (no manual assertions)
    .liveliness_automatic_secs(30);
```

## Writer Setup

```rust
use hdds::{Participant, QoS, TransportMode};

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

let topic = participant.topic::<SensorData>("SensorTopic")?;
let writer = topic
    .writer()
    .qos(QoS::best_effort().keep_last(1))
    .build()?;

writer.write(&sample)?;
```

### Instance Registration

`register_instance(&sample)` on a keyed topic returns the instance handle. It is
optional and is not a tuning knob: every `DataWriter` method also takes the
sample directly and computes the same key hash itself.

## Reader Optimization

### Polling Mode

```rust
// Tight polling loop
loop {
    while let Some(sample) = reader.take()? {
        process(&sample);
    }
    // Optional: hint the CPU while spinning
    std::hint::spin_loop();
}
```

### WaitSet with Short Timeout

```rust
use hdds::WaitSet;
use std::time::Duration;

let waitset = WaitSet::new();
waitset.attach(&reader)?;

loop {
    // wait() returns Err(WouldBlock) once the timeout has elapsed
    if waitset.wait(Some(Duration::from_micros(100))).is_ok() {
        while let Some(sample) = reader.take()? {
            process(&sample);
        }
    }
}
```

A reader that polls and a reader that blocks in a `WaitSet` have different
latencies. On the 1.5.0 intra-process cross-thread benchmark (writer and reader
on two pinned threads, one sample every 200 us, `BEST_EFFORT`, `KEEP_LAST(1)`,
idle states past C1 disabled, default build, benchmark host, median of 10
rounds) the p50 is 366.5 ns for a reader that busy-polls `take()` and 2603.5 ns
for a reader blocked in `WaitSet::wait()`; the full regime is in [Benchmarks](benchmarks.md).

### Take vs Read

```rust
// take() removes the sample from the reader's history
while let Some(sample) = reader.take()? {
    process(&sample);
}

// read() returns a copy and leaves the sample in the history
if let Some(sample) = reader.read()? {
    process(&sample);
}
```

## Threading Model

### Dedicated Reader Thread

```rust
use std::thread;

let reader_thread = thread::Builder::new()
    .name("dds-reader".into())
    .spawn(move || {
        // Set thread priority (Linux; lowering the value needs privileges)
        #[cfg(target_os = "linux")]
        unsafe {
            libc::setpriority(libc::PRIO_PROCESS, 0, -20);
        }

        loop {
            while let Some(sample) = reader.take().unwrap() {
                // Process inline, no channel hand-off
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

HDDS requests an 8 MiB receive buffer on its user-data sockets by default; the
kernel caps the request at `net.core.rmem_max`. The size can be set on the
builder or with the `HDDS_RCVBUF_BYTES` and `HDDS_SNDBUF_BYTES` environment
variables (the builder value wins):

```rust
use hdds::{Participant, TransportMode};
use std::num::NonZeroUsize;

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .with_socket_receive_buffer_size(NonZeroUsize::new(16 * 1024 * 1024).unwrap())
    .build()?;
```

### Linux Kernel Parameters

```bash
# Raise the socket buffer limits so that the requested sizes are granted
sysctl -w net.core.rmem_max=16777216
sysctl -w net.core.wmem_max=16777216
```

For the TCP endpoint, `TcpConfig::nodelay` (TCP_NODELAY) is on by default.

### Network Interface

```bash
# Host-level options; measure their effect in your deployment
ethtool -C eth0 rx-usecs 0 tx-usecs 0
sysctl -w net.core.busy_poll=50
sysctl -w net.core.busy_read=50
```

## Serialization Optimization

### Use Fixed-Size Types

```c
// Fixed encoded size
struct FixedSensor {
    uint32 sensor_id;
    float values[8];  // Fixed array
};

// Variable encoded size: a sequence adds a 4-byte element count
struct VariableSensor {
    uint32 sensor_id;
    sequence<float> values;  // Dynamic sequence
};
```

### Minimize Payload Size

```c
// Use the smallest types that fit
struct CompactSensor {
    uint16 sensor_id;    // Not uint32
    int16 value_x10;     // Fixed-point, not float
    uint32 timestamp_ms; // Not uint64 nanoseconds
};
```

A sample larger than 8192 bytes is sent as DATA_FRAG submessages.

## Discovery Optimization

### SPDP Announcement Period

```rust
use hdds::{Participant, TransportMode};
use std::time::Duration;

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .with_spdp_announcement_period(Duration::from_millis(500))  // Default: 3 s
    .build()?;
```

The period applies after the startup burst and must be shorter than the
participant lease duration (`with_participant_lease_duration`, default 30 s).

### Seed Peers

```rust
use hdds::{Participant, TransportMode};

// SPDP announcements are also sent by unicast to these addresses
let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .with_seed_peers("192.0.2.10:7410")
    .build()?;
```

## Measuring Latency

### Instrumentation

```rust
use std::time::Instant;

// Time the write call
let start = Instant::now();
writer.write(&sample)?;
let write_time = start.elapsed();
```

End-to-end latency needs either a timestamp in the sample taken from a clock
both hosts share, or a round trip measured on one host.

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

- [ ] Keep shared memory enabled for same-host peers (the default)
- [ ] Set BestEffort reliability for non-critical data
- [ ] Use keep_last(1) history
- [ ] Use take() instead of read()
- [ ] Pin threads to CPU cores
- [ ] Tune socket buffer sizes
- [ ] Use fixed-size types in IDL
- [ ] Minimize payload size

## Common Latency Issues

| Issue | Symptom | Solution |
|-------|---------|----------|
| Lock contention | Inconsistent latency | Reduce shared state |
| Large payloads | Samples above 8192 bytes are fragmented | Reduce the payload size |
| Reliable writer, full history | `write()` blocks up to `max_blocking_time`, then returns `WriteTimeout` | Increase history depth or slow the publisher |
| Reader blocked in a WaitSet | Higher latency than a polling reader | Poll, if the CPU cost is acceptable |

## Next Steps

- [Throughput Tuning](../../guides/performance/tuning-throughput.md) - Maximize bandwidth
- [Benchmarks](../../guides/performance/benchmarks.md) - Performance baselines
