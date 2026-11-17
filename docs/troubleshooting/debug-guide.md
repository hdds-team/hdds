# Debug Guide

Comprehensive guide to debugging HDDS applications.

## Logging

HDDS logs through the Rust `log` crate. In a Rust application, install a
backend such as `env_logger` (for example `env_logger::init()` at startup);
in C and Python, call the SDK's logging init. The ROS 2 adapter installs one
itself.

### Enable Logging

```bash
# Basic logging
export RUST_LOG=hdds=info

# Detailed logging
export RUST_LOG=hdds=debug

# Trace all DDS operations
export RUST_LOG=hdds=trace

# Specific modules
export RUST_LOG=hdds=debug,hdds::transport=trace
```

### Log Levels

| Level | Use Case |
|-------|----------|
| `error` | Critical failures only |
| `warn` | Warnings and errors |
| `info` | General operation status |
| `debug` | Detailed debugging info |
| `trace` | Very verbose, all operations |

### Log to File

```bash
# Redirect to file
RUST_LOG=hdds=debug ./my_app 2> hdds.log
```

## Discovery Debugging

### Check Discovery Status

```rust
// List discovered endpoints (writers and readers of every remote participant)
for ep in participant.discover_endpoints()? {
    println!("{:?} {} {}", ep.kind, ep.topic_name, ep.type_name);
    println!("  endpoint: {:?}", ep.endpoint_guid);
    println!("  participant: {:?}", ep.participant_guid);
}

// List matched endpoints
println!("Writer matched {} readers", writer.matched_reader_count());
println!("Reader matched {} writers",
    reader.get_subscription_matched_status().current_count);
```

### Network Debugging

```bash
# Watch SPDP traffic
tcpdump -i any -n udp port 7400 -X

# Watch all DDS traffic of domain 0
tcpdump -i any -n 'udp and portrange 7400-7649'

# With Wireshark filter
rtps
```

### Discovery Log Analysis

```bash
export RUST_LOG=hdds=trace
./my_app 2>&1 | grep -iE "(spdp|sedp|match)"
```

## Communication Debugging

### Trace Data Flow

Implement the listener traits to see matches, deadline misses and losses as
they happen:

```rust
use hdds::dds::{DataReaderListener, DataWriterListener, PublicationMatchedStatus,
                SampleLostStatus, SubscriptionMatchedStatus};

struct DebugListener;

// Writer side
impl<T: hdds::DdsTrait> DataWriterListener<T> for DebugListener {
    fn on_publication_matched(&self, status: PublicationMatchedStatus) {
        println!("Matched: {} readers", status.current_count);
    }
}

// Reader side
impl<T: hdds::DdsTrait + std::fmt::Debug> DataReaderListener<T> for DebugListener {
    fn on_data_available(&self, sample: &T) {
        println!("Received {:?}", sample);
    }

    fn on_subscription_matched(&self, status: SubscriptionMatchedStatus) {
        println!("Matched: {} writers", status.current_count);
    }

    fn on_sample_lost(&self, status: SampleLostStatus) {
        println!("SAMPLE LOST: {} total", status.total_count);
    }
}
```

Attach a listener with `with_listener(Arc::new(listener))` on the writer or
reader builder.

### Monitor Write/Read Cycle

```rust
use std::time::Instant;

let start = Instant::now();
writer.write(&sample)?;
println!("Write took: {:?}", start.elapsed());

// On reader side
while let Some(sample) = reader.take()? {
    println!("Received: {:?}", sample);
}
```

## QoS Debugging

### Print QoS Settings

```rust
fn print_qos(qos: &QoS) {
    println!("QoS settings:");
    println!("  {:?}", qos);
}
```

### Check QoS Compatibility

```rust
// QoS compatibility is checked automatically by HDDS
// Writer reliability must be >= Reader reliability
// Writer durability must be >= Reader durability
// Check matched status to verify compatibility

println!("Writer matched {} readers", writer.matched_reader_count());
println!("Reader matched {} writers", reader.get_matched_publications().len());
```

## Memory Debugging

### Track Allocations

```bash
# Using heaptrack
heaptrack ./my_app
heaptrack_gui heaptrack.my_app.*.gz

# Using valgrind
valgrind --tool=massif ./my_app
ms_print massif.out.*
```

### Check for Leaks

```bash
# Using valgrind
valgrind --leak-check=full ./my_app
```

## Performance Debugging

### Profile CPU Usage

```bash
# Using perf
perf record -g ./my_app
perf report

# Using flamegraph
cargo install flamegraph
cargo flamegraph --bin my_app
```

### Measure Latency

Time a write or a round trip in your own application. For a reproducible
figure, follow the reporting checklist and the regimes on the
[Benchmarks](../guides/performance/benchmarks.md) page: a number taken in
another regime is not comparable.

```rust
use std::time::Instant;

let start = Instant::now();
writer.write(&sample)?;
println!("write() took {:?}", start.elapsed());
```

### Measure Throughput

```rust
use std::time::Instant;

let sample_count = 100000;
let start = Instant::now();

for _ in 0..sample_count {
    writer.write(&sample)?;
}

let elapsed = start.elapsed();
let throughput = sample_count as f64 / elapsed.as_secs_f64();
println!("Throughput: {:.0} samples/sec", throughput);
```

## Network Debugging

### Capture Packets

```bash
# Capture to file
tcpdump -i any -w hdds_capture.pcap 'udp and portrange 7400-7649'

# Analyze with Wireshark
wireshark hdds_capture.pcap
# Filter: rtps
```

### Check Network Stats

```bash
# Socket buffer usage
ss -u -n | grep 7400

# Network errors
netstat -su

# Interface stats
ip -s link show eth0
```

### Simulate Network Issues

```bash
# Add latency
sudo tc qdisc add dev eth0 root netem delay 10ms

# Add packet loss
sudo tc qdisc add dev eth0 root netem loss 1%

# Remove rules
sudo tc qdisc del dev eth0 root
```

## Debug Tools

### Tools in this Repository

| Tool | Purpose |
|------|---------|
| `tools/hdds-discovery-dump` | Dump live discovery state (participants, readers, writers) |
| `tools/hdds-topic-echo` | Echo the samples of a topic in real time |
| `tools/hdds-latency-probe` | Ping-pong latency measurement |
| `tools/hdds-shm-viewer` | Inspect HDDS shared memory segments |
| `tools/wireshark` | Wireshark dissector for RTPS and HDDS traffic |

Build one with `cargo run -p <tool>` or `cargo install --path tools/<tool>`.

### HDDS Viewer

HDDS Viewer, distributed separately, analyzes captures: convert a pcap with
`pcap2hddscap` and open the result in `hdds-viewer` (see
[Debugging ROS2 Traffic](../ros2/debugging.md)).

### Debug Assertions

```rust
// Enable debug assertions in release
// Cargo.toml:
// [profile.release]
// debug-assertions = true

debug_assert!(writer.matched_reader_count() > 0,
    "No readers matched!");
```

## Common Debug Patterns

### Minimal Reproducer

```rust
// Simplified test case
use hdds::{Participant, QoS, DDS, TransportMode};

#[derive(Debug, Clone, DDS)]
struct TestData {
    id: u32,
    value: f64,
}

fn main() -> Result<(), hdds::Error> {
    // Minimal setup
    let participant = Participant::builder("test")
        .domain_id(0)
        .with_transport(TransportMode::UdpMulticast)
        .build()?;

    // Single writer
    let topic = participant.topic::<TestData>("TestTopic")?;
    let writer = topic.writer().qos(QoS::reliable()).build()?;

    // Write test data
    let sample = TestData { id: 1, value: 42.0 };
    writer.write(&sample)?;

    println!("Write succeeded");
    Ok(())
}
```

### Binary Search Debug

When issue appears in complex code:

1. Add logging at midpoint
2. If issue before midpoint, search first half
3. If issue after midpoint, search second half
4. Repeat until isolated

### Comparison Debug

```rust
// Compare working vs broken configuration
let working_qos = QoS::reliable();
let broken_qos = QoS::best_effort();

// Test both and compare behavior
```

## Debug Checklist

1. **Enable logging**: `export RUST_LOG=hdds=debug`
2. **Check discovery**: Are participants/endpoints matched?
3. **Verify QoS**: Are writer/reader QoS compatible?
4. **Check network**: Can hosts reach each other?
5. **Monitor resources**: Memory, CPU, file descriptors
6. **Capture traffic**: Use tcpdump/Wireshark
7. **Isolate issue**: Create minimal reproducer
8. **Check versions**: Are all components same version?

## Next Steps

- [Common Issues](../troubleshooting/common-issues.md) - Known issues and fixes
- [Performance Issues](../troubleshooting/performance-issues.md) - Performance debugging
- [Error Codes](../reference/error-codes.md) - Error reference
