# Temperature Sensor Example

A complete example showing how to publish and subscribe to sensor data.

## Overview

This example demonstrates:
- Defining a sensor data type
- Publishing temperature readings at 10 Hz
- Subscribing and processing sensor data
- Using Best Effort QoS for high-frequency data

## Project Setup

HDDS is used as a path dependency on a clone of the repository
(`git clone https://git.hdds.io/hdds/hdds.git`):

```toml title="Cargo.toml"
[dependencies]
hdds = { path = "../hdds/crates/hdds" }

[[bin]]
name = "publisher"
path = "src/publisher.rs"

[[bin]]
name = "subscriber"
path = "src/subscriber.rs"
```

## Data Type Definition

The `DDS` derive macro supports primitive fields, `String` and `Vec<u8>`.
Types with enums, arrays or nested structs are generated from IDL with
`hddsgen` instead (see the [Key Instance](../examples/key-instance.md)
example).

```rust
use hdds::DDS;

#[derive(Debug, Clone, DDS)]
struct SensorData {
    #[key]
    sensor_id: u32,      // Unique sensor identifier
    timestamp: u64,      // Nanoseconds since epoch
    temperature: f32,    // Celsius
    pressure: f32,       // Pascals
    humidity: f32,       // Percentage (0-100)
}
```

## Publisher

```rust title="src/publisher.rs"
use hdds::{Participant, QoS, TransportMode, DDS};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, DDS)]
struct SensorData {
    #[key]
    sensor_id: u32,
    timestamp: u64,
    temperature: f32,
    pressure: f32,
    humidity: f32,
}

fn main() -> Result<(), hdds::Error> {
    // Create participant on domain 0
    let participant = Participant::builder("sensor_publisher")
        .domain_id(0)
        .with_transport(TransportMode::UdpMulticast)
        .build()?;

    // Create topic and writer with best effort QoS
    let topic = participant.topic::<SensorData>("SensorTopic")?;
    let writer = topic
        .writer()
        .qos(QoS::best_effort().keep_last(1))
        .build()?;

    println!("Publishing sensor data at 10 Hz...");

    let sensor_id = 1;
    let mut tick: u32 = 0;
    loop {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        // A slow triangle wave stands in for real sensor readings.
        let wave = (tick % 20) as f32 / 20.0 - 0.5;
        let sample = SensorData {
            sensor_id,
            timestamp,
            temperature: 22.5 + wave,
            pressure: 101325.0 + wave * 100.0,
            humidity: 45.0 + wave * 5.0,
        };

        writer.write(&sample)?;
        tick += 1;

        std::thread::sleep(Duration::from_millis(100)); // 10 Hz
    }
}
```

## Subscriber

```rust title="src/subscriber.rs"
use hdds::{Participant, QoS, TransportMode, DDS};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, DDS)]
struct SensorData {
    #[key]
    sensor_id: u32,
    timestamp: u64,
    temperature: f32,
    pressure: f32,
    humidity: f32,
}

fn main() -> Result<(), hdds::Error> {
    let participant = Participant::builder("sensor_subscriber")
        .domain_id(0)
        .with_transport(TransportMode::UdpMulticast)
        .build()?;

    let topic = participant.topic::<SensorData>("SensorTopic")?;
    let reader = topic
        .reader()
        .qos(QoS::best_effort().keep_last(10))
        .build()?;

    println!("Listening for sensor data...");

    loop {
        // Non-blocking: take() returns Ok(None) when nothing is queued
        while let Some(sample) = reader.take()? {
            println!(
                "Sensor {}: temp={:.2}C, pressure={:.0} Pa, humidity={:.1}%",
                sample.sensor_id, sample.temperature, sample.pressure, sample.humidity
            );
        }

        // Brief sleep to avoid busy-waiting
        thread::sleep(Duration::from_millis(10));
    }
}
```

## Running the Example

Terminal 1 - Start the subscriber:
```bash
cargo run --bin subscriber
```

Terminal 2 - Start the publisher:
```bash
cargo run --bin publisher
```

Expected output (the values follow the publisher's triangle wave):
```
Listening for sensor data...
Sensor 1: temp=22.00C, pressure=101275 Pa, humidity=42.5%
Sensor 1: temp=22.05C, pressure=101280 Pa, humidity=42.8%
Sensor 1: temp=22.10C, pressure=101285 Pa, humidity=43.0%
...
```

Discovery uses UDP multicast: if nothing is received, see the network
prerequisites in the README.

## Multiple Sensors

The `#[key]` annotation on `sensor_id` enables tracking multiple sensors:

```rust
// Publish from multiple sensors
for sensor_id in 1..=4 {
    let sample = SensorData {
        sensor_id,
        timestamp, // computed as in the publisher above
        temperature: 20.0 + sensor_id as f32,
        pressure: 101325.0,
        humidity: 45.0,
    };
    writer.write(&sample)?;
}
```

Each `sensor_id` creates a separate instance with independent:
- History buffer
- Deadline tracking

## QoS Considerations

| Scenario | Recommended QoS |
|----------|-----------------|
| High-rate sensors (>100 Hz) | `QoS::best_effort().keep_last(1)` |
| Critical measurements | `QoS::reliable().keep_last(10).transient_local()` |
| Logging/recording | `QoS::reliable().keep_all()` |

## Tips

1. **Use best_effort()**: For high-frequency non-critical data
2. **Keep history small**: `keep_last(1)` minimizes memory for streaming data
3. **Keep the participant alive**: Writers and readers stop being discovered
   once the `Participant` is dropped, so hold it for the life of the program

## Next Steps

- [Reliable Delivery](../examples/reliable-delivery.md) - Guaranteed message delivery
- [Key Instance](../examples/key-instance.md) - Multi-instance topics
- [QoS Policies](../guides/qos-policies/overview.md) - Complete QoS reference
