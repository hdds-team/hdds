# Rust API Reference

HDDS is a DDS implementation written in Rust. The Rust API is the native one: the C, C++ and Python bindings wrap it.

:::info Version 1.5.0
This documents the 1.5.0 API. The API is synchronous: there is no `async` reader or writer API.
:::

## Installation

Clone the repository, then add `crates/hdds` as a path dependency. Replace
`/absolute/path/to/hdds` with the absolute path of your clone (see the
[Hello World tutorial](../getting-started/hello-world-rust.md)):

```toml
# Cargo.toml
[dependencies]
hdds = { path = "/absolute/path/to/hdds/crates/hdds" }
```

The default features are `xtypes`, `qos-loaders` and
`xtypes-structural-assignability`. Other Cargo features (`security`, `quic`,
`tcp-tls`, `rpc`, `k8s`, `cloud-discovery`, ...) are opt-in:

```toml
hdds = { path = "/absolute/path/to/hdds/crates/hdds", features = ["security"] }
```

## Core Types

### Participant

The entry point to HDDS. Uses a builder pattern for configuration.

```rust
use hdds::Participant;

// Basic creation: no domain in code, so HDDS_DOMAIN_ID decides
let participant = Participant::builder("my_app")
    .build()?;

// With UDP multicast transport (for network communication)
use hdds::TransportMode;

let participant = Participant::builder("sensor_node")
    .domain_id(42)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// With custom discovery ports
let participant = Participant::builder("custom_app")
    .with_transport(TransportMode::UdpMulticast)
    .with_discovery_ports(9400, 9410, 9411)  // spdp multicast, sedp unicast, user unicast
    .build()?;

// Properties
let domain_id = participant.domain_id();
let guid = participant.guid();
let name = participant.name();
let mode = participant.transport_mode();
```

**Domain.** Without a `domain_id()` call, `build()` reads `HDDS_DOMAIN_ID`: a malformed value makes `build()` fail, and an unset variable means domain 0. A `domain_id()` call in code always wins. The full rule is on the [Environment variables](../reference/environment-vars.md) page.

### TransportMode

```rust
pub enum TransportMode {
    IntraProcess,   // Shared memory between participants in the same process
    UdpMulticast,   // Default: network communication via UDP multicast
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

// Get writer stats (WriterStats.messages_sent)
let stats = writer.stats();
println!("Sent: {} messages", stats.messages_sent);
```

There is no wait-for-match call on the writer. Before the first write, poll
`matched_reader_count()` with a deadline, as the tutorial does. The example
returns `Error::DiscoveryTimeout` when no reader matches in time:

```rust
use std::time::{Duration, Instant};

let deadline = Instant::now() + Duration::from_secs(10);
while writer.matched_reader_count() == 0 {
    if Instant::now() >= deadline {
        return Err(hdds::Error::DiscoveryTimeout);
    }
    std::thread::sleep(Duration::from_millis(100));
}
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
if let Some(sample) = reader.take()? {
    println!("Received: {:?}", sample);
}

// Take batch of samples
let samples = reader.take_batch(10)?;
for sample in samples {
    println!("Received: {:?}", sample);
}

// Polling loop
loop {
    while let Some(sample) = reader.take()? {
        process(&sample);
    }
    std::thread::sleep(std::time::Duration::from_millis(10));
}
```

### InstanceHandle

For keyed topics, `InstanceHandle` identifies specific instances (16-byte key hash).

```rust
use hdds::dds::InstanceHandle;

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
use hdds::{DdsTrait, QoS, DDS};
use hdds::dds::InstanceHandle;

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

// Instance handle of sensor 1: the key hash of a sample that carries that key
let key_sample = SensorData { sensor_id: 1, value: 0.0, timestamp: 0 };
let handle = InstanceHandle::new(key_sample.compute_key());

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

Optional grouping for writers/readers with shared QoS. A writer joins a
publisher, and a reader joins a subscriber, through the topic builder.

```rust
use hdds::QoS;
use std::sync::Arc;

// Create publisher and subscriber
let publisher = Arc::new(participant.create_publisher(QoS::default())?);
let subscriber = participant.create_subscriber(QoS::default())?;

// Writers and readers are built from the topic, joined to the group
let writer = participant.topic::<SensorData>("sensors/temp")?
    .writer()
    .publisher(&publisher)
    .qos(QoS::reliable())
    .build()?;
let reader = participant.topic::<SensorData>("sensors/temp")?
    .reader()
    .subscriber(&subscriber)
    .qos(QoS::reliable())
    .build()?;
```

## QoS Configuration

HDDS uses a single unified `QoS` type with a fluent builder API.

### Basic QoS

```rust
use hdds::QoS;

// Predefined profiles
let qos = QoS::default();        // Best effort, volatile, keep last 100
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

// Transient - announced as TRANSIENT; the core library has no durability
// service of its own, locally it behaves like transient local
let qos = QoS::default().transient();

// Persistent - announced as PERSISTENT
let qos = QoS::default().persistent();
```

Data that outlives the writer (TRANSIENT, PERSISTENT) is the job of the
`hdds-persistence` service (SQLite or RocksDB store), a separate crate of this
repository.

### Liveliness

```rust
use hdds::dds::{Liveliness, LivelinessKind};
use std::time::Duration;

let liveliness = Liveliness {
    kind: LivelinessKind::Automatic,
    lease_duration: Duration::from_secs(1),
};
let qos = QoS::reliable().liveliness(liveliness);

// Or LivelinessKind::ManualByParticipant, LivelinessKind::ManualByTopic
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

### Using hddsgen (Recommended)

The IDL code generator `hddsgen` writes complete implementations. It is a
separate repository: install it with
`git clone https://git.hdds.io/hdds/hdds_gen.git && cargo install --path hdds_gen`
(see the [hddsgen installation page](../tools/hdds-gen/installation.md)).

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

```bash
hddsgen gen rust sensor_data.idl -o src/sensor_data.rs
```

The output is one file meant for `include!`. It refers to the `hdds` crate
(`hdds >= 1.5.0`), so no other dependency is needed:

```rust
// main.rs
include!("sensor_data.rs");

use hdds::Participant;
use sensors::SensorData;

fn main() -> Result<(), hdds::Error> {
    let participant = Participant::builder("app").build()?;
    let writer = participant.topic::<SensorData>("sensors/temp")?.writer().build()?;

    writer.write(&SensorData {
        sensor_id: 1,
        value: 25.5,
        timestamp: 0,
    })?;

    Ok(())
}
```

A type without an extensibility annotation is generated as APPENDABLE (the
DDS-XTypes default). See the [CLI reference](../tools/hdds-gen/cli-reference.md)
for `--default-extensibility` and the other options.

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

Implement `hdds::DdsTrait` (the trait that `#[derive(DDS)]` implements; `DDS`
in `use hdds::DDS` is the derive macro). Its `encode` and `decode` take a
`CdrVersion` and must produce the layout of that version.

`Cdr2Encode` / `Cdr2Decode` give a type the XCDR2 layout. Their default
`encode_xcdr1_le` / `encode_xcdr2_le` methods (and the `_at` forms) both
delegate to the XCDR2 code, so an 8-byte member lands at offset 4 where XCDR1
puts it at 8 (DDS-XTypes 1.3, 7.4.3.2.2, `MAXALIGN(VERSION1) = 8`). HDDS takes
a type to encode XCDR1 only when it says so through
`encodes_xcdr1_natively()`, which defaults to `false`: a writer of such a type
that sets no DATA_REPRESENTATION offers and encodes XCDR2, and a pair that
negotiates XCDR1 for it (an explicit XCDR1 list, or a remote reader that
requests XCDR1 only) is not matched (INCOMPATIBLE_QOS, policy 23) instead of
carrying the XCDR2 layout under an XCDR1 header. Answer `true` only when your
XCDR1 bytes are XCDR1: you implement both layouts, your body is the same under
both (no 8-byte member, no DHEADER), or the type carries opaque bytes whose
representation the QoS names. `#[derive(DDS)]` and the Rust code `hddsgen`
emits answer `true`.

The example is a final struct with one 4-byte member, whose body is the same
under both layouts:

```rust
use hdds::core::types::TypeDescriptor;
use hdds::{Cdr2Decode, Cdr2Encode, CdrError, CdrVersion, DdsTrait, Result};

#[derive(Debug, Clone, PartialEq)]
pub struct Counter {
    pub value: u32,
}

impl Cdr2Encode for Counter {
    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> std::result::Result<(), CdrError> {
        *offset = (*offset + 3) & !3; // align to 4
        let end = *offset + 4;
        dst.get_mut(*offset..end)
            .ok_or(CdrError::BufferTooSmall)?
            .copy_from_slice(&self.value.to_le_bytes());
        *offset = end;
        Ok(())
    }

    fn max_cdr2_size(&self) -> usize {
        4
    }
}

impl Cdr2Decode for Counter {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> std::result::Result<Self, CdrError> {
        *offset = (*offset + 3) & !3;
        let end = *offset + 4;
        let bytes: [u8; 4] = src
            .get(*offset..end)
            .ok_or(CdrError::UnexpectedEof)?
            .try_into()
            .map_err(|_| CdrError::UnexpectedEof)?;
        *offset = end;
        Ok(Counter { value: u32::from_le_bytes(bytes) })
    }
}

static COUNTER_DESCRIPTOR: TypeDescriptor =
    TypeDescriptor::new(0x434F_554E, "Counter", 4, 4, false, &[]);

impl DdsTrait for Counter {
    fn type_descriptor() -> &'static TypeDescriptor {
        &COUNTER_DESCRIPTOR
    }

    fn encode(&self, buf: &mut [u8], version: CdrVersion) -> Result<usize> {
        match version {
            CdrVersion::Xcdr1 => self.encode_xcdr1_le(buf).map_err(Into::into),
            CdrVersion::Xcdr2 => self.encode_xcdr2_le(buf).map_err(Into::into),
        }
    }

    fn decode(buf: &[u8], version: CdrVersion) -> Result<Self> {
        match version {
            CdrVersion::Xcdr1 => Self::decode_xcdr1_le(buf).map(|(v, _)| v).map_err(Into::into),
            CdrVersion::Xcdr2 => Self::decode_xcdr2_le(buf).map(|(v, _)| v).map_err(Into::into),
        }
    }

    // A single 4-byte member: the body is the same under both layouts.
    fn encodes_xcdr1_natively() -> bool {
        true
    }
}
```

A type with `@key` members also overrides `has_key()` (returning `true`) and
`write_key_holder()`, which `compute_key()` uses to build the instance
KeyHash; `encode_key()` serializes the key members for key-only samples
(dispose, unregister). The defaults are keyless (`has_key()` is `false`).

## WaitSet

Event-based waiting for data availability.

```rust
use hdds::WaitSet;
use std::time::Duration;

let reader = participant.topic::<SensorData>("sensors/temp")?
    .reader()
    .build()?;

// A DataReader is a HasStatusCondition: attach it directly.
// (attach(&reader.get_status_condition()) does not compile: that is an Arc<StatusCondition>.)
let waitset = WaitSet::new();
waitset.attach(&reader)?;

// Wait for data. wait() returns Ok when a condition triggered; on timeout it returns
// Err(Error::WouldBlock), which is not a failure.
loop {
    match waitset.wait(Some(Duration::from_secs(1))) {
        Ok(_) => {
            while let Some(sample) = reader.take()? {
                process(&sample);
            }
        }
        Err(hdds::Error::WouldBlock) => {} // timeout, no data yet
        Err(e) => return Err(e),
    }
}
```

With several readers, keep one WaitSet per reader, or attach them all and call
`take()` on each reader after `wait()` returns.

### ReadCondition / QueryCondition

A condition created by the reader triggers on the samples the reader
holds (states masks, plus a query for a QueryCondition) and is taken
through `take_w_condition`. The reader must be in an `Arc`.

```rust
use hdds::dds::{InstanceStateMask, SampleStateMask, ViewStateMask};

let reader = Arc::new(reader);
let hot = reader.create_querycondition(
    SampleStateMask::NOT_READ,
    ViewStateMask::ANY,
    InstanceStateMask::ALIVE,
    "value > %0",
    vec!["10".to_string()],
)?;
waitset.attach_condition(hot.clone())?;
for (data, info) in reader.take_w_condition(&hot, usize::MAX)? {
    // data: Some(sample), or None for an instance-state transition
}
```

Semantics, limits and the C binding: [read-query-conditions.md](../read-query-conditions.md).

## Listeners

`hdds::dds::DataReaderListener<T>` / `DataWriterListener<T>` are traits whose
callbacks have default bodies, so an implementation overrides only what it needs. Give one to the builder (`.with_listener(Arc::new(l))`) or
install, replace or remove it on a live entity:

```rust
use hdds::dds::{DataReaderListener, StatusMask, SubscriptionMatchedStatus};
use std::sync::Arc;

struct Heard;
impl DataReaderListener<Temperature> for Heard {
    fn on_data_available(&self, sample: &Temperature) { /* ... */ }
    fn on_subscription_matched(&self, s: SubscriptionMatchedStatus) { /* ... */ }
}

reader.set_listener(Some(Arc::new(Heard)), StatusMask::ALL);
// A status outside the mask is not reported; SAMPLE_REJECTED outside it
// stays on the StatusCondition.
reader.set_listener(None, StatusMask::NONE);
```

Callbacks run on HDDS threads: the router / control thread for network
deliveries, discovery threads for matched events, and the writer's own thread
(inside `write()`) for a writer of the same participant. No lock the
entity's own operations take is held across a callback. `set_listener` does
not wait for a callback already running (it holds its own `Arc`).

## Error Handling

```rust
use hdds::Error;

match writer.write(&sample) {
    Ok(()) => println!("Written"),
    Err(Error::WriteTimeout) => eprintln!("Write timed out (reliable delivery)"),
    Err(Error::WouldBlock) => eprintln!("Resource limit reached, try again later"),
    Err(e) => eprintln!("Error: {}", e),
}
```

`Error` is the enum in `hdds::Error`: for example `WouldBlock`,
`WriteTimeout`, `DiscoveryTimeout`, `AcknowledgmentTimeout`, `QosIncompatible`,
`TypeMismatch`, `Config(String)`, `IoError(std::io::Error)`.

## XTypes Support

Type introspection, behind the `xtypes` Cargo feature (enabled by default).

```rust
use hdds::DdsTrait;

// Access the participant's type cache
let type_cache = participant.type_cache();

// A type can provide its XTypes TypeObject (`#[derive(DDS)]` and hddsgen do)
let type_obj = SensorData::get_type_object();
```

## Complete Example

```rust
use hdds::{Participant, QoS, TransportMode, DDS};
use std::time::{Duration, Instant};

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
        .with_transport(TransportMode::UdpMulticast)
        .build()?;

    // Create writer with reliable QoS
    let writer = participant
        .topic::<Temperature>("sensors/temperature")?
        .writer()
        .qos(QoS::reliable().keep_last(10).transient_local())
        .build()?;

    // Wait for a subscriber to match before the first write (10 s at most)
    let deadline = Instant::now() + Duration::from_secs(10);
    while writer.matched_reader_count() == 0 {
        if Instant::now() >= deadline {
            return Err(hdds::Error::DiscoveryTimeout);
        }
        std::thread::sleep(Duration::from_millis(100));
    }

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

## Instance Lifecycle, SampleInfo and Filtering

```rust
use std::time::Duration;

let sample = SensorData { sensor_id: 1, value: 25.5, timestamp: 0 };

// Writer side: register, write, wait for acknowledgment, dispose, unregister
let handle = writer.register_instance(&sample)?;
writer.write(&sample)?;
writer.wait_for_acknowledgments(Duration::from_secs(5))?; // Err(Error::AcknowledgmentTimeout) on timeout
writer.dispose(&sample)?;
writer.unregister_instance(&sample)?;

// Reader side: a sample with its SampleInfo
if let Some((data, info)) = reader.take_with_info()? {
    // data is None for an instance-state transition (info.valid_data == false)
    println!("{:?} {:?} {}", data, info.instance_state, info.sequence_number);
}

// Content-filtered topic: only samples matching the expression are delivered
let filtered = participant
    .create_content_filtered_topic::<SensorData>(
        "hot_sensors",
        "sensors/temp",
        "value > %0",
        vec!["25.0".to_string()],
    )
    .expect("valid filter expression");
let hot_reader = filtered.reader().build()?;
```

`wait_for_acknowledgments` returns at once on a best-effort writer. A filter
expression is evaluated through `DDS::get_fields`, which `#[derive(DDS)]`
implements. A type that leaves the default (the Rust code `hddsgen` 2.0 emits
does) has no fields to filter on: a content filter then passes every sample.

## Next Steps

- [Hello World Rust](../getting-started/hello-world-rust.md) - Complete tutorial
- [QoS Policies](../guides/qos-policies/overview.md) - QoS configuration
- [hdds_gen](../tools/hdds-gen/overview.md) - IDL code generator
- [Examples](../examples/index.md) - More examples
