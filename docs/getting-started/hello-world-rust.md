# Hello World in Rust

In this tutorial, you'll build a simple temperature sensor application with a publisher and subscriber.

**Prerequisites:** [Rust installed](../getting-started/installation/linux.md)

:::info Network prerequisites
Discovery uses UDP multicast. If the subscriber receives nothing and nothing
reports an error, discovery is probably not happening (VPN, container,
firewall). For a single-machine test, run both programs with
`HDDS_INTERFACE=lo` (see [Environment variables](../reference/environment-vars.md)).
:::

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

Edit `Cargo.toml`. Replace `/absolute/path/to/hdds` with the absolute path of your HDDS clone (for example `/home/you/hdds`). A relative path only works from one directory layout:

```toml
[package]
name = "hdds-hello-world"
version = "0.1.0"
edition = "2021"

[dependencies]
hdds = { path = "/absolute/path/to/hdds/crates/hdds" }

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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn main() -> hdds::Result<()> {
    println!("Starting temperature publisher...");

    // 1. Create a Participant. No domain is set in code: the library reads
    //    HDDS_DOMAIN_ID (0 when unset), so both programs must export the same value.
    let participant = Participant::builder("temp_publisher")
        .with_transport(TransportMode::UdpMulticast)
        .build()?;
    println!("Joined domain {}", participant.domain_id());

    // 2. Create a DataWriter for the topic with reliable QoS
    let writer = participant
        .topic::<Temperature>("temperature/room1")?
        .writer()
        .qos(QoS::reliable().keep_last(10).transient_local())
        .build()?;
    println!("DataWriter created on topic: temperature/room1");

    // 3. Wait until a subscriber is matched (10 s at most), so the first
    //    write does not go out before discovery has found the reader.
    let deadline = Instant::now() + Duration::from_secs(10);
    while writer.matched_reader_count() == 0 {
        if Instant::now() >= deadline {
            eprintln!("No subscriber matched after 10 s: same HDDS_DOMAIN_ID in both terminals? multicast reachable?");
            return Err(hdds::Error::DiscoveryTimeout);
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // 4. Publish temperature readings
    for i in 0..10 {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let temperature = Temperature {
            sensor_id: 1,
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

The publisher waits for a subscriber to match before its first write, so the first
samples are not written while discovery is still running.

## Step 5: Create the Subscriber

Create `src/bin/subscriber.rs`:

```rust
use hdds::{Participant, QoS, TransportMode, WaitSet};
use hdds_hello_world::Temperature;
use std::time::{Duration, Instant};

/// Stop after this many samples...
const EXPECTED_SAMPLES: usize = 10;
/// ...or after this long without any sample.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

fn main() -> hdds::Result<()> {
    println!("Starting temperature subscriber...");

    // 1. Create a Participant. No domain is set in code: the library reads
    //    HDDS_DOMAIN_ID (0 when unset), so both programs must export the same value.
    let participant = Participant::builder("temp_subscriber")
        .with_transport(TransportMode::UdpMulticast)
        .build()?;
    println!("Joined domain {}", participant.domain_id());

    // 2. Create a DataReader for the topic with reliable QoS
    let reader = participant
        .topic::<Temperature>("temperature/room1")?
        .reader()
        .qos(QoS::reliable().keep_last(100))
        .build()?;
    println!("DataReader created, waiting for data...");

    // 3. Use WaitSet for efficient blocking reads. A DataReader can be
    //    attached directly: it is a HasStatusCondition.
    let waitset = WaitSet::new();
    waitset.attach(&reader)?;

    // 4. Read until EXPECTED_SAMPLES arrived or the stream went quiet
    let mut received = 0;
    let mut last_data = Instant::now();
    while received < EXPECTED_SAMPLES && last_data.elapsed() < IDLE_TIMEOUT {
        match waitset.wait(Some(Duration::from_secs(1))) {
            Ok(_) => {
                while let Some(sample) = reader.take()? {
                    println!(
                        "Received: sensor={}, temp={:.1}C, time={}",
                        sample.sensor_id, sample.value, sample.timestamp
                    );
                    received += 1;
                    last_data = Instant::now();
                }
            }
            // WouldBlock = the wait timed out, no data yet
            Err(hdds::Error::WouldBlock) => {}
            Err(e) => return Err(e),
        }
    }

    println!("Received {} samples, exiting", received);
    Ok(())
}
```

## Step 6: Build and Run

Open two terminals. In **each** of them, export the same domain first (any value from 0 to 232; the rule is on the [Environment variables](../reference/environment-vars.md) page):

```bash
export HDDS_DOMAIN_ID=42
```

Then run:

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
Joined domain 42
DataReader created, waiting for data...
Received: sensor=1, temp=22.0C, time=1703001234567000000
Received: sensor=1, temp=22.5C, time=1703001235567000000
Received: sensor=1, temp=23.0C, time=1703001236567000000
...
Received 10 samples, exiting
```

**Publisher:**
```
Starting temperature publisher...
Joined domain 42
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
    .with_transport(TransportMode::UdpMulticast)
    .build()?;
```

The `Participant` is your entry point to HDDS:
- **Name**: `"temp_publisher"` - identifies this participant
- **Domain ID**: not set in code, so `HDDS_DOMAIN_ID` picks it (0 when unset). Both programs must use the same domain. A `domain_id()` call in code overrides the variable. The full rule is on the [Environment variables](../reference/environment-vars.md) page.
- **Transport**: `UdpMulticast` - for network communication (use `IntraProcess` for same-process)

### Topic and Writer

```rust
let writer = participant
    .topic::<Temperature>("temperature/room1")?
    .writer()
    .qos(QoS::reliable().keep_last(10).transient_local())
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
while let Some(sample) = reader.take()? {
    // process sample
}
```

`take()` returns `Result<Option<T>>`:
- `Ok(Some(sample))` - a sample was available and removed from the cache
- `Ok(None)` - no samples available
- `Err(e)` - a DDS error occurred

## Using WaitSet (Alternative to Polling)

Instead of polling with `sleep()`, use a WaitSet for event-driven reading. A
DataReader can be attached directly, because it is a `HasStatusCondition`:

```rust
use hdds::WaitSet;
use std::time::Duration;

let reader = participant
    .topic::<Temperature>("temperature/room1")?
    .reader()
    .build()?;

let waitset = WaitSet::new();
waitset.attach(&reader)?;

// Keep reading. Step 5 shows how to stop after N samples.
loop {
    match waitset.wait(Some(Duration::from_secs(5))) {
        Ok(_) => {
            while let Some(sample) = reader.take()? {
                println!("Received: {:?}", sample);
            }
        }
        Err(hdds::Error::WouldBlock) => {} // timeout, no data yet
        Err(e) => return Err(e),
    }
}
```

`waitset.attach(&reader.get_status_condition())` does not compile: the status
condition is an `Arc<StatusCondition>`. Attach the reader itself, or call
`waitset.attach_condition(reader.get_status_condition())`. A timed-out `wait()`
returns `Err(hdds::Error::WouldBlock)`, which is not a failure.

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

No retransmission: lower overhead, but samples may be lost.

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

The repository carries a similar hello-world sample, in `sdk/samples/01_basics/rust`:

```bash
cd /path/to/hdds/sdk/samples/01_basics/rust
export HDDS_DOMAIN_ID=42      # in both terminals
# Terminal 1 - subscriber
cargo run --bin hello_world
# Terminal 2 - publisher
cargo run --bin hello_world -- pub
```

## What's Next?

- **[Rust API Reference](../api/rust.md)** - Complete API documentation
- **[QoS Policies](../guides/qos-policies/overview.md)** - Fine-tune data distribution
- **[Examples](../examples/index.md)** - More complex examples
