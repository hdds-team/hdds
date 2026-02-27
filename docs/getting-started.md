# Getting Started with HDDS

This guide walks you through your first HDDS application: from installation to
publishing and subscribing to DDS topics, configuring transports, and running
the SDK samples.

HDDS is a pure Rust implementation of the OMG DDS (Data Distribution Service)
and RTPS 2.5 specifications for real-time systems, robotics, IoT, and
high-frequency data distribution.

---

## Table of Contents

1. [Installation](#1-installation)
2. [First Publisher](#2-first-publisher)
3. [First Subscriber](#3-first-subscriber)
4. [IDL Code Generation](#4-idl-code-generation)
5. [Transport Configuration](#5-transport-configuration)
6. [QoS Configuration](#6-qos-configuration)
7. [Running the Examples](#7-running-the-examples)
8. [Interoperability](#8-interoperability)
9. [Next Steps](#9-next-steps)

---

## 1. Installation

### Add HDDS to Your Cargo.toml

```toml
[dependencies]
hdds = "1.0"
```

Default features include `xtypes` (type discovery and compatibility) and
`qos-loaders` (XML/YAML QoS profile loading). That covers most use cases.

### Feature Flags

Enable additional capabilities by selecting feature flags:

| Feature | What It Enables | Dependencies |
|---------|----------------|--------------|
| `xtypes` (default) | XTypes v1.3 type discovery and compatibility | `md-5` |
| `qos-loaders` (default) | Load QoS from FastDDS XML or YAML files | `roxmltree`, `serde`, `serde_yaml` |
| `security` | DDS Security v1.1 (authentication, encryption, access control) | `ring`, `x509-parser`, `pem`, `webpki`, `base64` |
| `tcp-tls` | TLS encryption for TCP transport | `rustls`, `webpki-roots`, `rustls-pemfile` |
| `quic` | QUIC transport for NAT traversal and connection migration | `quinn`, `rustls`, `tokio` |
| `cloud-discovery` | Cloud discovery backends (Consul, AWS Cloud Map, Azure) | `reqwest`, `serde`, `tokio` |
| `k8s` | Kubernetes DNS-based discovery (zero dependencies) | none |
| `rpc` | DDS-RPC Request/Reply pattern | `tokio` |
| `lowbw-lz4` | LZ4 compression for low-bandwidth links | `lz4_flex` |
| `logging` | Compile-time logging (zero-cost when disabled) | none |
| `trace` | Verbose trace logging (implies `logging`) | none |
| `telemetry` | Metrics collection and export | none |

Example with multiple features:

```toml
[dependencies]
hdds = { version = "1.0", features = ["security", "tcp-tls", "k8s"] }
```

### Install the IDL Compiler

```bash
cargo install hdds-gen
```

This installs `idl-gen`, the command-line tool for generating Rust (and C, C++,
Python) type support code from IDL files. See
[Section 4](#4-idl-code-generation) for usage.

---

## 2. First Publisher

A minimal program that creates a DDS participant and publishes messages.

### Step 1: Define Your IDL

Create a file `HelloWorld.idl`:

```idl
module my_app {
    struct HelloWorld {
        string message;
        unsigned long count;
    };
};
```

### Step 2: Generate Rust Types

```bash
idl-gen gen rust HelloWorld.idl -o src/generated/hello_world.rs
```

### Step 3: Write the Publisher

```rust
use std::thread;
use std::time::Duration;

// Include generated types
mod generated {
    include!("generated/hello_world.rs");
}
use generated::my_app::HelloWorld;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a DDS participant -- the entry point to DDS.
    // IntraProcess transport is used here for single-machine communication.
    let participant = hdds::Participant::builder("my_publisher")
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()?;

    // Create a typed DataWriter on topic "HelloWorldTopic".
    // The generic parameter <HelloWorld> determines the CDR encoding
    // and the type name advertised during discovery.
    let writer = participant.create_writer::<HelloWorld>(
        "HelloWorldTopic",
        hdds::QoS::default(),
    )?;

    // Publish 10 messages
    for i in 0..10u32 {
        let msg = HelloWorld::new("Hello from HDDS!", i);
        writer.write(&msg)?;
        println!("Published: count={}", i);
        thread::sleep(Duration::from_millis(500));
    }

    Ok(())
}
```

Key API elements:

- `Participant::builder(name)` -- creates a `ParticipantBuilder` for fluent
  configuration.
- `.with_transport(TransportMode::IntraProcess)` -- selects in-process
  communication. Use `TransportMode::UdpMulticast` for network communication.
- `.build()` -- returns `Arc<Participant>`.
- `participant.create_writer::<T>(topic_name, qos)` -- creates a typed
  `DataWriter<T>`.
- `writer.write(&msg)` -- serializes the message to CDR and sends it.

---

## 3. First Subscriber

A minimal program that subscribes to messages using a WaitSet.

```rust
use std::time::Duration;

mod generated {
    include!("generated/hello_world.rs");
}
use generated::my_app::HelloWorld;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let participant = hdds::Participant::builder("my_subscriber")
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()?;

    // Create a typed DataReader on the same topic name.
    let reader = participant.create_reader::<HelloWorld>(
        "HelloWorldTopic",
        hdds::QoS::default(),
    )?;

    // WaitSet pattern: block efficiently until data arrives.
    let status_condition = reader.get_status_condition();
    let waitset = hdds::dds::WaitSet::new();
    waitset.attach_condition(status_condition)?;

    let mut received = 0;
    while received < 10 {
        match waitset.wait(Some(Duration::from_secs(5))) {
            Ok(triggered) => {
                if !triggered.is_empty() {
                    // take() retrieves AND removes samples from the reader cache.
                    // Use read() to leave samples in the cache.
                    while let Some(msg) = reader.take()? {
                        println!("Received: \"{}\" count={}", msg.message, msg.count);
                        received += 1;
                    }
                }
            }
            Err(hdds::Error::WouldBlock) => {
                println!("Timeout -- waiting for publisher...");
            }
            Err(e) => {
                eprintln!("Wait error: {:?}", e);
            }
        }
    }

    Ok(())
}
```

Key API elements:

- `participant.create_reader::<T>(topic_name, qos)` -- creates a typed
  `DataReader<T>`.
- `reader.get_status_condition()` -- returns a condition that triggers when data
  is available.
- `WaitSet::new()` / `waitset.attach_condition(condition)` -- standard DDS
  pattern for blocking reads.
- `waitset.wait(Some(timeout))` -- blocks until a condition triggers or the
  timeout expires. Returns `Err(Error::WouldBlock)` on timeout.
- `reader.take()` -- retrieves and removes the next sample from the cache.
  Returns `Result<Option<T>>`.
- `reader.read()` -- retrieves the next sample without removing it from the
  cache.

---

## 4. IDL Code Generation

HDDS uses standard OMG IDL 4.2 files for type definitions. The `hdds-gen` tool
(CLI name: `idl-gen`) compiles IDL into type support code with CDR2
serialization, XTypes metadata, and the `DDS` trait implementation.

### Basic Usage

```bash
# Generate Rust code
idl-gen gen rust MyTypes.idl -o src/generated/my_types.rs

# Generate to a directory (creates mod.rs)
idl-gen gen rust MyTypes.idl --out-dir src/generated/

# Generate C++ code
idl-gen gen cpp MyTypes.idl -o my_types.hpp

# Generate Python code
idl-gen gen python MyTypes.idl --out-dir ./generated/

# Validate IDL without generating code
idl-gen check MyTypes.idl
```

### IDL Example

```idl
module sensors {
    @topic
    struct Temperature {
        @key string sensor_id;
        float value;
        unsigned long long timestamp;
    };
};
```

The `@key` annotation marks fields used for DDS instance identity. The `@topic`
annotation marks the struct as a DDS topic type.

### Including Generated Code in Rust

The generated files are designed for use with the `include!()` macro:

```rust
mod generated {
    include!("generated/my_types.rs");
}
use generated::sensors::Temperature;
```

The generated code provides:

- `Cdr2Encode` and `Cdr2Decode` implementations for wire-format serialization.
- The `DDS` trait implementation (type descriptor, CDR encode/decode, key
  computation, XTypes TypeObject).
- A `::new(...)` constructor and a builder pattern (`::builder().field(val).build()`).

### Supported IDL Types

| IDL Type | Rust Mapping |
|----------|-------------|
| `boolean` | `bool` |
| `octet` | `u8` |
| `short` / `unsigned short` | `i16` / `u16` |
| `long` / `unsigned long` | `i32` / `u32` |
| `long long` / `unsigned long long` | `i64` / `u64` |
| `float` / `double` | `f32` / `f64` |
| `char` | `char` |
| `string` | `String` |
| `sequence<T>` | `Vec<T>` |
| `T[N]` (array) | `[T; N]` |
| `map<K,V>` | `HashMap<K,V>` |
| `enum` | Rust `enum` |
| `union` | Rust `enum` (tagged) |
| `@optional` fields | `Option<T>` |

### Include Directories

When IDL files reference other IDL via `#include`:

```bash
idl-gen gen rust -I ./common_types -I /opt/dds/idl MyTypes.idl -o types.rs
```

---

## 5. Transport Configuration

HDDS supports multiple transport modes configured through the
`ParticipantBuilder`.

### IntraProcess (Default)

Zero-copy, in-process communication. Best for testing and single-process
applications.

```rust
let participant = hdds::Participant::builder("app")
    .with_transport(hdds::TransportMode::IntraProcess)
    .build()?;
```

### UDP Multicast

Standard RTPS network transport. Required for multi-process and multi-host
communication, and for interoperability with other DDS implementations.

```rust
let participant = hdds::Participant::builder("app")
    .with_transport(hdds::TransportMode::UdpMulticast)
    .domain_id(0)  // Default DDS domain; same as ROS 2 default
    .build()?;
```

### TCP

For WAN, firewalled, or NAT environments where UDP is not available.

```rust
use hdds::transport::tcp::TcpConfig;

// Simple: enable TCP with a listen port
let participant = hdds::Participant::builder("gateway")
    .with_transport(hdds::TransportMode::UdpMulticast)
    .with_tcp(7410)
    .build()?;

// TCP-only (no UDP at all)
let tcp = TcpConfig::tcp_only(vec![
    "10.0.0.1:7410".parse().unwrap(),
    "10.0.0.2:7410".parse().unwrap(),
]);

let participant = hdds::Participant::builder("client")
    .with_transport(hdds::TransportMode::UdpMulticast)
    .tcp_config(tcp)
    .tcp_only()
    .build()?;
```

### TCP with TLS

Requires the `tcp-tls` feature.

```rust
use hdds::transport::tcp::TcpConfig;

let tcp = TcpConfig::server_only(7410)
    .with_tls(true);

let participant = hdds::Participant::builder("secure_server")
    .with_transport(hdds::TransportMode::UdpMulticast)
    .tcp_config(tcp)
    .build()?;
```

### QUIC

Requires the `quic` feature. Provides NAT traversal, 0-RTT reconnection,
built-in TLS 1.3, and connection migration (survives IP changes).

```rust
use hdds::transport::quic::QuicConfig;

let quic = QuicConfig::builder()
    .bind_addr("0.0.0.0:7400".parse().unwrap())
    .enable_migration(true)
    .build();

let participant = hdds::Participant::builder("mobile_node")
    .with_transport(hdds::TransportMode::UdpMulticast)
    .with_quic(quic)
    .build()?;
```

### Shared Memory

Ultra-low-latency zero-copy communication between processes on the same host.
Enabled by default with `ShmPolicy::Prefer`.

```rust
use hdds::ShmPolicy;

// Force SHM (fail if not same-host)
let participant = hdds::Participant::builder("local_app")
    .shm_require()
    .build()?;

// Disable SHM (always use UDP)
let participant = hdds::Participant::builder("debug_app")
    .shm_disable()
    .build()?;
```

### Static Peers (No Multicast)

For environments without multicast support, specify peers explicitly:

```rust
let participant = hdds::Participant::builder("app")
    .with_transport(hdds::TransportMode::UdpMulticast)
    .domain_id(0)
    .add_static_peer("192.168.1.100:7411")
    .add_static_peer("192.168.1.101:7411")
    .build()?;
```

### Discovery Server

For cloud or corporate networks without multicast:

```rust
use hdds::DiscoveryServerConfig;

let config = DiscoveryServerConfig::new(
    "discovery.example.com:7400".parse()?
);

let participant = hdds::Participant::builder("cloud_node")
    .with_transport(hdds::TransportMode::UdpMulticast)
    .with_discovery_server(config)
    .build()?;
```

### Custom Discovery Ports

Override the default RTPS port formula for firewall compatibility:

```rust
let participant = hdds::Participant::builder("app")
    .with_transport(hdds::TransportMode::UdpMulticast)
    .domain_id(0)
    .with_discovery_ports(9400, 9410, 9411)
    .build()?;
```

---

## 6. QoS Configuration

HDDS provides a fluent builder API for all 22 standard DDS QoS policies. The
two main entry points are `QoS::best_effort()` and `QoS::reliable()`.

### Best Effort (Fire-and-Forget)

Lowest latency. No retransmission. Ideal for high-frequency sensor data, video
streams, and soft real-time telemetry.

```rust
let qos = hdds::QoS::best_effort();

let writer = participant.create_writer::<MyData>("SensorTopic", qos)?;
```

### Reliable (Guaranteed Delivery)

NACK-based retransmission ensures complete, in-order delivery. Ideal for
commands, configuration, and state synchronization.

```rust
let qos = hdds::QoS::reliable();

let writer = participant.create_writer::<MyData>("CommandTopic", qos)?;
```

### Transient Local (Late-Joiner Support)

Caches samples in the writer so that late-joining subscribers receive
historical data. Must be combined with `reliable()`.

```rust
let qos = hdds::QoS::reliable()
    .transient_local()
    .keep_last(10);  // Cache up to 10 samples

let writer = participant.create_writer::<MyData>("ConfigTopic", qos)?;
```

Both writer AND reader must use `transient_local()` for this to work. A
volatile reader will not receive cached samples.

### History Depth

```rust
// Keep the last N samples per instance
let qos = hdds::QoS::reliable().keep_last(50);

// Keep all samples (unbounded)
let qos = hdds::QoS::reliable().keep_all();
```

### Deadline Monitoring

Detect when data stops arriving:

```rust
let qos = hdds::QoS::best_effort().deadline_millis(100);
// Triggers a missed deadline event if no sample arrives within 100ms.
```

### Liveliness

Monitor whether a writer is still alive:

```rust
// Automatic liveliness with 5-second lease
let qos = hdds::QoS::reliable().liveliness_automatic_secs(5);

// Manual-by-participant liveliness
let qos = hdds::QoS::reliable().liveliness_manual_participant_secs(3);
```

### Ownership

Control which writer "owns" an instance when multiple writers publish to the
same topic:

```rust
// Shared (default): all writers coexist
let qos = hdds::QoS::reliable().ownership_shared();

// Exclusive: highest-strength writer wins
let qos = hdds::QoS::reliable()
    .ownership_exclusive()
    .ownership_strength(100);
```

### Partition Filtering

Logical separation within a topic:

```rust
let qos = hdds::QoS::reliable().partition_single("sensor_zone_a");
// Only readers with a matching partition will receive data.
```

### Time-Based Filter

Rate-limit delivery to the reader:

```rust
// Accept samples at most every 100ms (10 Hz max)
let qos = hdds::QoS::best_effort().time_based_filter_millis(100);
```

### Transport Priority

Prioritize critical data:

```rust
let qos = hdds::QoS::reliable().transport_priority_high();
```

### Lifespan

Expire stale samples automatically:

```rust
// Samples expire after 5 seconds
let qos = hdds::QoS::best_effort().lifespan_secs(5);
```

### Loading QoS from FastDDS XML

Requires the `qos-loaders` feature (enabled by default):

```rust
let qos = hdds::QoS::load_fastdds("fastdds_profile.xml")?;
let writer = participant.create_writer::<MyData>("Topic", qos)?;
```

### Common QoS Recipes

| Use Case | QoS Configuration |
|----------|-------------------|
| Sensor streaming | `QoS::best_effort()` |
| Command delivery | `QoS::reliable()` |
| Configuration sync | `QoS::reliable().transient_local().keep_last(1)` |
| Event logging | `QoS::reliable().transient_local().keep_all()` |
| High-frequency telemetry | `QoS::best_effort().time_based_filter_millis(50)` |
| Redundant writers | `QoS::reliable().ownership_exclusive().ownership_strength(100)` |
| Stale data cleanup | `QoS::best_effort().lifespan_secs(10)` |
| RTI Connext interop | `QoS::rti_defaults()` |

---

## 7. Running the Examples

The SDK includes samples in `sdk/samples/` organized by category. Each sample
set includes Rust, C, C++, and Python variants.

### Sample Categories

| Directory | Topic |
|-----------|-------|
| `01_basics` | Hello World, instance keys, multi-topic, multi-participant |
| `02_qos` | Reliable, best-effort, transient-local, deadline, liveliness, ownership, partition |
| `03_types` | Primitives, strings, sequences, arrays, maps, enums, unions, nested structs, optional fields, bitsets |
| `04_discovery` | Simple SPDP discovery, partitions, static peers |
| `05_security` | Authentication, encryption, access control, secure discovery |
| `06_performance` | Throughput, latency, zero-copy, batching |
| `07_advanced` | WaitSets, content filtering, request/reply, dynamic data |
| `08_interop` | Cross-vendor interop, string interop, discovery testing |
| `09_ros2` | ROS 2 String talker/listener, pose publisher |
| `10_usecases` | Robot telemetry, sensor network |
| `11_embedded` | ARM64 hello, ARM64 latency |

### Running a Rust Sample

From the workspace root:

```bash
# Run the hello world subscriber
cargo run -p hdds-samples-basics --bin hello_world

# Run the hello world publisher (in another terminal)
cargo run -p hdds-samples-basics --bin hello_world -- pub
```

Or from inside the sample directory:

```bash
cd sdk/samples/01_basics/rust

# Subscriber
cargo run --bin hello_world

# Publisher (another terminal)
cargo run --bin hello_world -- pub
```

### Running QoS Samples

```bash
# Reliable delivery
cargo run -p hdds-samples-qos --bin reliable_delivery
cargo run -p hdds-samples-qos --bin reliable_delivery -- pub

# Best effort
cargo run -p hdds-samples-qos --bin best_effort
cargo run -p hdds-samples-qos --bin best_effort -- pub

# Transient local (start publisher first, then late-joining subscriber)
cargo run -p hdds-samples-qos --bin transient_local -- pub
cargo run -p hdds-samples-qos --bin transient_local
```

### Running Interop Samples

For cross-vendor testing, the interop samples use UDP multicast:

```bash
# Start HDDS subscriber
cargo run -p hdds-samples-interop --bin string_interop

# Start HDDS publisher (or a FastDDS/CycloneDDS/RTI publisher on the same topic)
cargo run -p hdds-samples-interop --bin string_interop -- pub
```

---

## 8. Interoperability

HDDS implements the RTPS 2.5 wire protocol and can communicate with any
compliant DDS implementation. Tested vendors:

| Vendor | Status |
|--------|--------|
| eProsima FastDDS 3.x | Full interop (bidirectional, 50/50 samples) |
| RTI Connext DDS 6.x | Full interop |
| Eclipse CycloneDDS | Full interop |
| OpenDDS | Full interop |

### Requirements for Cross-Vendor Communication

1. **Same domain ID** on all participants.
2. **Same topic name** and compatible type definition (generate from the same
   IDL).
3. **Compatible QoS** (a reliable reader cannot match a best-effort writer).
4. **UDP multicast** enabled (`TransportMode::UdpMulticast`), or matching
   static peer configuration.

### Quick Cross-Vendor Test

HDDS side:

```rust
let participant = hdds::Participant::builder("hdds_node")
    .with_transport(hdds::TransportMode::UdpMulticast)
    .domain_id(0)
    .build()?;

let writer = participant.create_writer::<HelloWorld>(
    "HelloWorldTopic",
    hdds::QoS::reliable(),
)?;
```

FastDDS side (C++):

```cpp
auto factory = DomainParticipantFactory::get_instance();
auto participant = factory->create_participant(0, PARTICIPANT_QOS_DEFAULT);

TypeSupport type(new HelloWorldPubSubType());
type.register_type(participant);

auto topic = participant->create_topic(
    "HelloWorldTopic", "HelloWorld", TOPIC_QOS_DEFAULT);
auto subscriber = participant->create_subscriber(SUBSCRIBER_QOS_DEFAULT);
auto reader = subscriber->create_datareader(topic, DATAREADER_QOS_DEFAULT);
```

Both sides must use the same IDL to generate their type support:

```bash
# For HDDS
idl-gen gen rust HelloWorld.idl -o hello_world.rs

# For FastDDS
fastddsgen HelloWorld.idl
```

### Troubleshooting Interop

- **Discovery fails**: Verify domain ID matches, UDP ports 7400-7500 are open,
  and multicast is enabled on the network (`ping 239.255.0.1`).
- **Type mismatch**: Ensure field names, types, and order match exactly in the
  IDL.
- **QoS incompatible**: A reliable reader cannot connect to a best-effort
  writer. A transient-local reader cannot connect to a volatile writer.

---

## 9. Next Steps

- [QoS Policies Overview](guides/qos-policies/overview.md) -- detailed
  coverage of all 22 DDS QoS policies.
- [Security Guide](guides/security/overview.md) -- DDS Security v1.1 setup
  (authentication, encryption, access control).
- [Performance Tuning](guides/performance/tuning-latency.md) -- optimizing
  latency and throughput.
- [FastDDS Interop](interop/fastdds/setup.md) -- detailed FastDDS
  interoperability guide.
- [CycloneDDS Interop](interop/cyclonedds/setup.md) -- CycloneDDS
  interoperability guide.
- [RTI Connext Interop](interop/rti-connext/setup.md) -- RTI Connext
  interoperability guide.
- [Migration from FastDDS](migration-from-fastdds.md) -- migrating existing
  FastDDS/CycloneDDS applications to HDDS.
- [hdds-gen CLI Reference](tools/hdds-gen/cli-reference.md) -- full IDL
  compiler documentation.
- [API Reference](api/rust.md) -- complete Rust API documentation.
- [Troubleshooting](troubleshooting/common-issues.md) -- common issues and
  solutions.
