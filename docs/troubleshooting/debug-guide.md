# Debug Guide

Comprehensive guide to debugging HDDS applications.

## Logging

### Enable Logging

```bash
# Basic logging
export RUST_LOG=hdds=info

# Detailed logging
export RUST_LOG=hdds=debug

# Trace all DDS operations
export RUST_LOG=hdds=trace

# Specific modules
export RUST_LOG=hdds::discovery=debug,hdds::transport=trace
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

# Or configure in code
use tracing_subscriber::fmt::writer::MakeWriterExt;
let file = std::fs::File::create("hdds.log")?;
tracing_subscriber::fmt()
    .with_writer(file)
    .init();
```

### Structured Logging

```rust
use tracing::{info, debug, span, Level};

let span = span!(Level::INFO, "dds_operation", topic = "SensorTopic");
let _guard = span.enter();

info!(sensor_id = 42, value = 23.5, "Publishing sample");
```

## Discovery Debugging

### Check Discovery Status

```rust
// List discovered participants
println!("Discovered participants:");
for info in participant.discovered_participants() {
    println!("  GUID: {:?}", info.guid);
    println!("  Vendor: {:?}", info.vendor_id);
    println!("  Locators: {:?}", info.unicast_locators);
}

// List matched endpoints
println!("Writer matched {} readers",
    writer.publication_matched_status()?.current_count);
println!("Reader matched {} writers",
    reader.subscription_matched_status()?.current_count);
```

### Network Debugging

```bash
# Watch SPDP traffic
tcpdump -i any -n udp port 7400 -X

# Watch all DDS traffic
tcpdump -i any -n 'udp and portrange 7400-7500'

# With Wireshark filter
rtps
```

### Discovery Log Analysis

```bash
export RUST_LOG=hdds::discovery=trace
./my_app 2>&1 | grep -E "(SPDP|SEDP|match)"
```

Expected flow:
```
SPDP: Sending announcement
SPDP: Received participant 01.0f.aa.bb...
SEDP: Publishing writer info
SEDP: Received subscription info
SEDP: Match found - writer 01... <-> reader 02...
```

## Communication Debugging

### Trace Data Flow

```rust
// Writer side
impl DataWriterListener for DebugListener {
    fn on_publication_matched(&mut self, _w: &DataWriter<T>, status: PublicationMatchedStatus) {
        println!("Matched: {} readers", status.current_count);
    }

    fn on_offered_deadline_missed(&mut self, _w: &DataWriter<T>, status: OfferedDeadlineMissedStatus) {
        println!("DEADLINE MISSED: instance {:?}", status.last_instance_handle);
    }
}

// Reader side
impl DataReaderListener for DebugListener {
    fn on_data_available(&mut self, reader: &DataReader<T>) {
        match reader.take() {
            Ok(samples) => println!("Received {} samples", samples.len()),
            Err(e) => println!("Take error: {:?}", e),
        }
    }

    fn on_sample_lost(&mut self, _r: &DataReader<T>, status: SampleLostStatus) {
        println!("SAMPLE LOST: {} total", status.total_count);
    }
}
```

### Monitor Write/Read Cycle

```rust
// Add timestamps
use std::time::Instant;

let start = Instant::now();
writer.write(&sample)?;
println!("Write took: {:?}", start.elapsed());

// On reader side
let samples = reader.take()?;
for (sample, info) in samples {
    println!("Received: timestamp={:?}, latency={:?}",
        info.source_timestamp,
        Instant::now() - info.source_timestamp);
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

println!("Writer matched {} readers", writer.matched_subscriptions().len());
println!("Reader matched {} writers", reader.matched_publications().len());
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

### Monitor Runtime Memory

```rust
// Add memory stats endpoint
fn print_memory_stats(participant: &DomainParticipant) {
    let stats = participant.memory_stats();
    println!("Memory usage:");
    println!("  History cache: {} bytes", stats.history_cache_bytes);
    println!("  Samples stored: {}", stats.samples_count);
    println!("  Instances: {}", stats.instances_count);
}
```

### Check for Leaks

```bash
# Using valgrind
valgrind --leak-check=full ./my_app

# Using AddressSanitizer
RUSTFLAGS="-Z sanitizer=address" cargo run --release
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

```rust
use std::time::Instant;
use hdrhistogram::Histogram;

let mut histogram = Histogram::<u64>::new(3).unwrap();

for _ in 0..10000 {
    let start = Instant::now();

    // Operation to measure
    writer.write(&sample)?;

    let latency_us = start.elapsed().as_micros() as u64;
    histogram.record(latency_us)?;
}

println!("Latency stats:");
println!("  p50: {} us", histogram.value_at_percentile(50.0));
println!("  p95: {} us", histogram.value_at_percentile(95.0));
println!("  p99: {} us", histogram.value_at_percentile(99.0));
println!("  max: {} us", histogram.max());
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
tcpdump -i any -w hdds_capture.pcap 'udp and portrange 7400-7500'

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

### HDDS Viewer

```bash
# Monitor traffic
hdds-viewer capture --interface eth0 --domain 0

# Show discovered entities
hdds-viewer show participants
hdds-viewer show topics
hdds-viewer show endpoints
```

### Built-in Diagnostics

```rust
// Enable internal diagnostics
let config = DomainParticipantConfig::default()
    .enable_diagnostics(true)
    .diagnostics_topic("hdds/diagnostics");

// Subscribe to diagnostics
let diag_reader = subscriber.create_datareader::<DiagnosticsData>(
    participant.find_topic("hdds/diagnostics")?
)?;
```

### Debug Assertions

```rust
// Enable debug assertions in release
// Cargo.toml:
// [profile.release]
// debug-assertions = true

debug_assert!(writer.publication_matched_status()?.current_count > 0,
    "No readers matched!");
```

## Common Debug Patterns

### Minimal Reproducer

```rust
// Simplified test case
use hdds::{Participant, QoS, DDS, TransportMode};

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
