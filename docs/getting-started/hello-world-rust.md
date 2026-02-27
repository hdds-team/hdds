# Hello World in Rust

In this tutorial, you'll build a simple temperature sensor application with a publisher and subscriber.

**Prerequisites:** [Rust installed](../getting-started/installation/linux.md)

## What We're Building

```mermaid
graph LR
    P[Publisher<br/>Temperature Sensor] -->|"temperature/room1"| S[Subscriber<br/>Display]
```

The publisher simulates a temperature sensor sending readings every second. The subscriber receives and displays them.

## Step 1: Create a New Project

```bash
cargo new hdds-hello-world
cd hdds-hello-world
```

## Step 2: Add Dependencies

Edit `Cargo.toml`:

```toml
[package]
name = "hdds-hello-world"
version = "0.1.0"
edition = "2021"

[dependencies]
hdds = "0.2"

[[bin]]
name = "publisher"
path = "src/bin/publisher.rs"

[[bin]]
name = "subscriber"
path = "src/bin/subscriber.rs"
```

## Step 3: Define the Data Type

Create `src/lib.rs` with your data type:

```rust
use hdds::DDS;

/// Temperature reading from a sensor
#[derive(Debug, Clone, DDS)]
pub struct Temperature {
    /// Unique sensor identifier (key field)
    #[key]
    pub sensor_id: u32,

    /// Temperature in Celsius
    pub value: f32,

    /// Unix timestamp in nanoseconds
    pub timestamp: u64,
}
```

:::tip The `#[key]` attribute
The `#[key]` attribute marks `sensor_id` as the **instance key**. This means:
- Each unique `sensor_id` is tracked independently
- DDS maintains separate history per sensor
:::

## Step 4: Create the Publisher

Create `src/bin/publisher.rs`:

```rust
use hdds::{Participant, QoS, TransportMode};
use hdds_hello_world::Temperature;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn main() -> Result<(), hdds::Error> {
    println!("Starting temperature publisher...");

    // 1. Create a Participant on domain 0
    let participant = Participant::builder("temp_publisher")
        .domain_id(0)
        .with_transport(TransportMode::UdpMulticast)
        .build()?;
    println!("Joined domain 0");

    // 2. Create a DataWriter for the topic with reliable QoS
    let writer = participant
        .topic::<Temperature>("temperature/room1")?
        .writer()
        .qos(QoS::reliable().keep_last(10).transient_local())
        .build()?;
    println!("DataWriter created on topic: temperature/room1");

    // 3. Publish temperature readings
    let sensor_id = 1u32;

    for i in 0..10 {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let temperature = Temperature {
            sensor_id,
            value: 22.0 + (i as f32 * 0.5),
            timestamp,
        };

        writer.write(&temperature)?;
        println!("Published: {:?}", temperature);

        std::thread::sleep(Duration::from_secs(1));
    }

    println!("Publisher finished");
    Ok(())
}
```

## Step 5: Create the Subscriber

Create `src/bin/subscriber.rs`:

```rust
use hdds::{Participant, QoS, TransportMode};
use hdds_hello_world::Temperature;
use std::time::Duration;

fn main() -> Result<(), hdds::Error> {
    println!("Starting temperature subscriber...");

    // 1. Create a Participant on domain 0
    let participant = Participant::builder("temp_subscriber")
        .domain_id(0)
        .with_transport(TransportMode::UdpMulticast)
        .build()?;
    println!("Joined domain 0");

    // 2. Create a DataReader for the topic with reliable QoS
    let reader = participant
        .topic::<Temperature>("temperature/room1")?
        .reader()
        .qos(QoS::reliable().keep_last(100))
        .build()?;
    println!("DataReader created, waiting for data...");

    // 3. Poll for samples in a loop
    loop {
        // Try to take available samples
        while let Some(sample) = reader.try_take()? {
            println!(
                "Received: sensor={}, temp={:.1}C, time={}",
                sample.sensor_id, sample.value, sample.timestamp
            );
        }

        // Small delay to avoid busy-waiting
        std::thread::sleep(Duration::from_millis(100));
    }
}
```

## Step 6: Build and Run

Open two terminals:

**Terminal 1 - Start the Subscriber:**

```bash
cargo run --bin subscriber
```

**Terminal 2 - Start the Publisher:**

```bash
cargo run --bin publisher
```

### Expected Output

**Subscriber:**
```
Starting temperature subscriber...
Joined domain 0
DataReader created, waiting for data...
Received: sensor=1, temp=22.0C, time=1703001234567000000
Received: sensor=1, temp=22.5C, time=1703001235567000000
Received: sensor=1, temp=23.0C, time=1703001236567000000
...
```

**Publisher:**
```
Starting temperature publisher...
Joined domain 0
DataWriter created on topic: temperature/room1
Published: Temperature { sensor_id: 1, value: 22.0, timestamp: 1703001234567000000 }
Published: Temperature { sensor_id: 1, value: 22.5, timestamp: 1703001235567000000 }
...
Publisher finished
```

## Understanding the Code

### Participant

```rust
let participant = Participant::builder("temp_publisher")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;
```

The `Participant` is your entry point to HDDS:
- **Name**: `"temp_publisher"` - identifies this participant
- **Domain ID**: `0` - participants must use the same domain to communicate
- **Transport**: `UdpMulticast` - for network communication (use `IntraProcess` for same-process)

### Topic and Writer

```rust
let writer = participant
    .topic::<Temperature>("temperature/room1")?
    .writer()
    .qos(QoS::reliable().keep_last(10))
    .build()?;
```

- `topic::<T>()` creates a topic handle for the type
- `.writer()` starts building a DataWriter
- `.qos()` configures Quality of Service
- `.build()` creates the writer

### Topic and Reader

```rust
let reader = participant
    .topic::<Temperature>("temperature/room1")?
    .reader()
    .qos(QoS::reliable().keep_last(100))
    .build()?;
```

Same pattern as writer, but creates a DataReader.

### Reading Data

```rust
while let Some(sample) = reader.try_take()? {
    // process sample
}
```

`try_take()` returns `Option<T>`:
- `Some(sample)` - a sample was available and removed from the cache
- `None` - no samples available

## Using WaitSet (Alternative to Polling)

Instead of polling with `sleep()`, use a WaitSet for event-driven reading:

```rust
use hdds::WaitSet;
use std::time::Duration;

let reader = participant
    .topic::<Temperature>("temperature/room1")?
    .reader()
    .build()?;

// Get status condition and create waitset
let condition = reader.get_status_condition();
let mut waitset = WaitSet::new();
waitset.attach(&condition)?;

loop {
    // Wait for data (blocks until data available or timeout)
    let _active = waitset.wait(Duration::from_secs(5))?;

    // Take all available samples
    while let Some(sample) = reader.try_take()? {
        println!("Received: {:?}", sample);
    }
}
```

## QoS Configuration

### Reliable Delivery

```rust
let qos = QoS::reliable();
```

Guarantees all samples are delivered (with retransmission if needed).

### Keep History for Late Joiners

```rust
let qos = QoS::reliable()
    .keep_last(10)        // Keep last 10 samples per instance
    .transient_local();   // Replay to late-joining readers
```

### Best Effort (Fire and Forget)

```rust
let qos = QoS::best_effort();
```

Fastest, but samples may be lost.

## Multiple Sensors

The `#[key]` field allows tracking multiple instances:

```rust
for sensor_id in [1, 2, 3] {
    let temp = Temperature {
        sensor_id,
        value: 22.0 + (sensor_id as f32),
        timestamp: now(),
    };
    writer.write(&temp)?;
}
```

Each `sensor_id` is tracked independently with its own history.

## Complete Source Code

The complete example is available:

```bash
git clone https://git.hdds.io/hdds/hdds-examples.git
cd hdds-examples/hello-world-rust
cargo run --bin subscriber &
cargo run --bin publisher
```

## What's Next?

- **[Rust API Reference](../api/rust.md)** - Complete API documentation
- **[QoS Policies](../guides/qos-policies/overview.md)** - Fine-tune data distribution
- **[Examples](../examples.md)** - More complex examples
