# Rust API Reference

HDDS is written in Rust, providing a safe, fast, and zero-copy DDS implementation.

:::info Version 1.0.0
This documents the v1.0.0 stable API. Some features (async, listeners, instance management) are not yet implemented.
:::

## Installation

```toml
# Cargo.toml
[dependencies]
hdds = "1.0"

# With XTypes support
hdds = { version = "1.0", features = ["xtypes"] }
```

## Core Types

### Participant

The entry point to HDDS. Uses a builder pattern for configuration.

```rust
use hdds::Participant;

// Basic creation
let participant = Participant::builder("my_app")
    .domain_id(0)
    .build()?;

// With UDP multicast transport (for network communication)
use hdds::TransportMode;

let participant = Participant::builder("sensor_node")
    .domain_id(42)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// With custom discovery ports
let participant = Participant::builder("custom_app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .with_discovery_ports(7400, 7401, 7410)  // spdp, sedp, user
    .build()?;

// Properties
let domain_id = participant.domain_id();
let guid = participant.guid();
let name = participant.name();
let mode = participant.transport_mode();
```

### TransportMode

```rust
pub enum TransportMode {
    IntraProcess,   // Default - shared memory between participants in same process
    UdpMulticast,   // Network communication via UDP multicast
}
```

### Topic

Topics are created from a participant and used to build readers/writers.

```rust
use hdds::{Participant, DDS};

// Create a topic (T must implement DDS trait)
let topic = participant.topic::<SensorData>("sensors/temperature")?;

// Topic is used to create readers and writers
let writer = topic.writer().build()?;
let reader = topic.reader().build()?;
```

### DataWriter

Writers publish data to a topic.

```rust
use hdds::QoS;

// Create writer with default QoS
let writer = participant.topic::<SensorData>("sensors/temp")?
    .writer()
    .build()?;

// Create writer with custom QoS
let writer = participant.topic::<SensorData>("sensors/temp")?
    .writer()
    .qos(QoS::reliable().keep_last(10).transient_local())
    .build()?;

// Write data
let sample = SensorData {
    sensor_id: 1,
    value: 25.5,
    timestamp: 1234567890,
};
writer.write(&sample)?;

// Get writer stats
let stats = writer.stats();
println!("Sent: {} samples", stats.samples_sent);
```

### DataReader

Readers receive data from a topic.

```rust
use hdds::QoS;

// Create reader with default QoS
let reader = participant.topic::<SensorData>("sensors/temp")?
    .reader()
    .build()?;

// Create reader with custom QoS
let reader = participant.topic::<SensorData>("sensors/temp")?
    .reader()
    .qos(QoS::reliable().keep_last(100))
    .build()?;

// Take single sample (removes from cache)
if let Some(sample) = reader.try_take()? {
    println!("Received: {:?}", sample);
}

// Take batch of samples
let samples = reader.take_batch(10)?;
for sample in samples {
    println!("Received: {:?}", sample);
}

// Polling loop
loop {
    while let Some(sample) = reader.try_take()? {
        process(&sample);
    }
    std::thread::sleep(std::time::Duration::from_millis(10));
}
```

### InstanceHandle

For keyed topics, `InstanceHandle` identifies specific instances (16-byte key hash).

```rust
use hdds::InstanceHandle;

// Create from key hash
let handle = InstanceHandle::new([0u8; 16]);

// Nil handle (for keyless topics)
let nil_handle = InstanceHandle::nil();
assert!(nil_handle.is_nil());

// Get raw bytes
let bytes: &[u8; 16] = handle.as_bytes();
```

### Instance-Based Read/Take

For keyed topics, you can read/take samples for a specific instance.

```rust
use hdds::{QoS, InstanceHandle};

// Keyed topic type
#[derive(Debug, Clone, DDS)]
struct SensorData {
    #[key]
    sensor_id: u32,
    value: f32,
    timestamp: u64,
}

let reader = participant.topic::<SensorData>("sensors/temp")?
    .reader()
    .qos(QoS::reliable().keep_last(100))
    .build()?;

// Get instance handle from a sample's key
let handle: InstanceHandle = /* from sample key hash */;

// Take single sample for specific instance (removes from cache)
if let Some(sample) = reader.take_instance(handle)? {
    println!("Instance {} value: {}", sample.sensor_id, sample.value);
}

// Take batch for specific instance
let samples = reader.take_instance_batch(handle, 10)?;
for sample in samples {
    println!("Received: {:?}", sample);
}

// Read single sample (non-destructive, requires T: Clone)
if let Some(sample) = reader.read_instance(handle)? {
    println!("Read: {:?}", sample);
}

// Read batch for specific instance
let samples = reader.read_instance_batch(handle, 10)?;
```

**Instance Methods Summary:**

| Method | Behavior | Removes from cache |
|--------|----------|-------------------|
| `take_instance(handle)` | Takes first matching sample | Yes |
| `take_instance_batch(handle, max)` | Takes up to max matching samples | Yes |
| `read_instance(handle)` | Reads first unread matching sample (T: Clone) | No |
| `read_instance_batch(handle, max)` | Reads up to max unread matching samples | No |

:::note Performance
Instance methods use O(n) linear scan over the cache. For high-throughput scenarios with many instances, consider using `take_batch()` and filtering client-side.
:::

### Publisher / Subscriber

Optional grouping for writers/readers with shared QoS.

```rust
use hdds::QoS;

// Create publisher
let publisher = participant.create_publisher(QoS::default())?;
let writer = publisher.create_writer::<SensorData>("sensors/temp", QoS::reliable())?;

// Create subscriber
let subscriber = participant.create_subscriber(QoS::default())?;
let reader = subscriber.create_reader::<SensorData>("sensors/temp", QoS::reliable())?;
```

## QoS Configuration

HDDS uses a single unified `QoS` type with a fluent builder API.

### Basic QoS

```rust
use hdds::QoS;

// Predefined profiles
let qos = QoS::default();        // Best effort, volatile, keep last 1
let qos = QoS::best_effort();    // Explicit best effort
let qos = QoS::reliable();       // Reliable delivery

// Fluent configuration
let qos = QoS::reliable()
    .keep_last(50)
    .transient_local();
```

### Reliability

```rust
use hdds::qos::Reliability;

// Best effort - fire and forget
let qos = QoS::default(); // Reliability::BestEffort

// Reliable - guaranteed delivery
let qos = QoS::reliable(); // Reliability::Reliable
```

### History

```rust
use hdds::qos::History;

// Keep last N samples per instance
let qos = QoS::default().keep_last(10);

// Keep all samples (unbounded)
let qos = QoS::default().keep_all();
```

### Durability

```rust
use hdds::qos::Durability;

// Volatile - no persistence (default)
let qos = QoS::default().volatile();

// Transient local - persist for late joiners
let qos = QoS::default().transient_local();

// Transient - persist in memory service
let qos = QoS::default().transient();

// Persistent - persist to disk
let qos = QoS::default().persistent();
```

### Liveliness

```rust
use hdds::qos::{Liveliness, LivelinessKind};
use std::time::Duration;

let liveliness = Liveliness {
    kind: LivelinessKind::Automatic,
    lease_duration: Duration::from_secs(1),
};

// Or ManualByParticipant, ManualByTopic
```

### Complete QoS Example

```rust
let writer_qos = QoS::reliable()
    .keep_last(100)
    .transient_local();

let reader_qos = QoS::reliable()
    .keep_last(1000);
```

## The DDS Trait

All topic types must implement the `DDS` trait for CDR2 serialization.

### Using hdds_gen (Recommended)

The IDL code generator creates complete implementations:

```idl
// sensor_data.idl
module sensors {
    struct SensorData {
        @key unsigned long sensor_id;
        float value;
        unsigned long long timestamp;
    };
};
```

```rust
// build.rs
use hdds_gen::Parser;
use hdds_gen::codegen::rust_backend::RustGenerator;

fn main() {
    let idl = std::fs::read_to_string("sensor_data.idl").unwrap();
    let mut parser = Parser::new(&idl);
    let ast = parser.parse().unwrap();

    let code = RustGenerator::new().generate(&ast).unwrap();

    let out_dir = std::env::var("OUT_DIR").unwrap();
    std::fs::write(format!("{}/sensor_data.rs", out_dir), code).unwrap();

    println!("cargo:rerun-if-changed=sensor_data.idl");
}
```

```rust
// main.rs
include!(concat!(env!("OUT_DIR"), "/sensor_data.rs"));

use sensors::SensorData;

fn main() -> Result<(), hdds::Error> {
    let participant = Participant::builder("app").domain_id(0).build()?;
    let writer = participant.topic::<SensorData>("sensors/temp")?.writer().build()?;

    writer.write(&SensorData {
        sensor_id: 1,
        value: 25.5,
        timestamp: 0,
    })?;

    Ok(())
}
```

### Using derive macro

```rust
use hdds::DDS;

#[derive(Debug, Clone, DDS)]
struct Temperature {
    celsius: f32,
    timestamp: u32,
}
```

### Manual Implementation

```rust
use hdds::{DDS, Result};
use hdds::core::types::TypeDescriptor;

impl DDS for MyType {
    fn type_descriptor() -> &'static TypeDescriptor {
        // Return type metadata
        &MY_TYPE_DESCRIPTOR
    }

    fn encode_cdr2(&self, buf: &mut [u8]) -> Result<usize> {
        // Encode to CDR2 little-endian
        // Return bytes written
    }

    fn decode_cdr2(buf: &[u8]) -> Result<Self> {
        // Decode from CDR2 little-endian
    }

    fn compute_key(&self) -> [u8; 16] {
        // MD5 hash of @key fields (or zeros if no keys)
        [0u8; 16]
    }

    fn has_key() -> bool {
        false
    }
}
```

## WaitSet

Event-based waiting for data availability.

```rust
use hdds::{WaitSet, StatusMask};
use std::time::Duration;

let reader = participant.topic::<SensorData>("sensors/temp")?
    .reader()
    .build()?;

// Get status condition
let condition = reader.get_status_condition();

// Create waitset and attach condition
let mut waitset = WaitSet::new();
waitset.attach(&condition)?;

// Wait for data
loop {
    let active = waitset.wait(Duration::from_secs(1))?;

    for cond in active {
        if cond == condition {
            while let Some(sample) = reader.try_take()? {
                process(&sample);
            }
        }
    }
}
```

## Error Handling

```rust
use hdds::Error;

match writer.write(&sample) {
    Ok(()) => println!("Written"),
    Err(Error::Timeout) => eprintln!("Write timed out"),
    Err(Error::NotEnabled) => eprintln!("Writer not enabled"),
    Err(e) => eprintln!("Error: {}", e),
}
```

## XTypes Support

Optional type introspection (feature-gated).

```toml
[dependencies]
hdds = { version = "0.2", features = ["xtypes"] }
```

```rust
#[cfg(feature = "xtypes")]
{
    // Access type cache
    let type_cache = participant.type_cache();

    // Types implementing DDS can provide TypeObject
    let type_obj = SensorData::get_type_object();
}
```

## Complete Example

```rust
use hdds::{Participant, QoS, TransportMode, DDS};
use std::time::Duration;

#[derive(Debug, Clone, DDS)]
struct Temperature {
    #[key]
    sensor_id: u32,
    celsius: f32,
    timestamp: u64,
}

fn main() -> Result<(), hdds::Error> {
    // Create participant with UDP transport
    let participant = Participant::builder("temp_sensor")
        .domain_id(0)
        .with_transport(TransportMode::UdpMulticast)
        .build()?;

    // Create writer with reliable QoS
    let writer = participant
        .topic::<Temperature>("sensors/temperature")?
        .writer()
        .qos(QoS::reliable().keep_last(10).transient_local())
        .build()?;

    // Publish temperature readings
    for i in 0..100 {
        let sample = Temperature {
            sensor_id: 1,
            celsius: 20.0 + (i as f32 * 0.1),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
        };

        writer.write(&sample)?;
        println!("Published: {:?}", sample);

        std::thread::sleep(Duration::from_millis(100));
    }

    Ok(())
}
```

## Not Yet Implemented (v1.0.0)

The following features are planned but not available in v1.0.0:

| Feature | Status |
|---------|--------|
| Async API (`async`/`await`) | Phase 7 - Planned |
| DataWriterListener / DataReaderListener | Not implemented |
| Instance lifecycle (`dispose`, `unregister`) | Not implemented |
| SampleInfo with metadata | Not implemented |
| `wait_for_acknowledgments()` | Not implemented |
| Content-filtered topics | Not implemented |

:::tip What's New in v1.0.0
- **Instance-based read/take** - `read_instance()`, `take_instance()`, `read_instance_batch()`, `take_instance_batch()`
- **InstanceHandle type** - 16-byte key hash for keyed topics
- **Non-destructive read** - `read_instance()` methods (requires `T: Clone`)
:::

## Next Steps

- [Hello World Rust](../getting-started/hello-world-rust.md) - Complete tutorial
- [QoS Policies](../guides/qos-policies/overview.md) - QoS configuration
- [hdds_gen](../tools/hdds-gen/overview.md) - IDL code generator
- [Examples](../examples.md) - More examples
