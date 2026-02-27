# Temperature Sensor Example

A complete example showing how to publish and subscribe to sensor data.

## Overview

This example demonstrates:
- Defining a sensor data type
- Publishing temperature readings at 10 Hz
- Subscribing and processing sensor data
- Using Best Effort QoS for high-frequency data

## Data Type Definition

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
use hdds::{Participant, QoS, DDS, TransportMode};
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
    loop {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let sample = SensorData {
            sensor_id,
            timestamp: now,
            temperature: 22.5 + (rand::random::<f32>() - 0.5),
            pressure: 101325.0 + (rand::random::<f32>() - 0.5) * 100.0,
            humidity: 45.0 + (rand::random::<f32>() - 0.5) * 5.0,
        };

        writer.write(&sample)?;

        std::thread::sleep(Duration::from_millis(100)); // 10 Hz
    }
}
```

## Subscriber

```rust title="src/subscriber.rs"
use hdds::{Participant, QoS, DDS, TransportMode};
use std::time::Duration;
use std::thread;

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
        // Non-blocking read
        while let Some(sample) = reader.try_take()? {
            println!(
                "Sensor {}: temp={:.2}C, pressure={:.0} Pa, humidity={:.1}%",
                sample.sensor_id,
                sample.temperature,
                sample.pressure,
                sample.humidity
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

Expected output:
```
Sensor 1: temp=22.43C, pressure=101312 Pa, humidity=44.8%
Sensor 1: temp=22.51C, pressure=101340 Pa, humidity=45.2%
Sensor 1: temp=22.48C, pressure=101298 Pa, humidity=44.9%
...
```

## Multiple Sensors

The `#[key]` annotation on `sensor_id` enables tracking multiple sensors:

```rust
// Publish from multiple sensors
for sensor_id in 1..=4 {
    let sample = SensorData {
        sensor_id,
        timestamp: now,
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
- Liveliness monitoring

## QoS Considerations

| Scenario | Recommended QoS |
|----------|-----------------|
| High-rate sensors (>100 Hz) | `QoS::best_effort().keep_last(1)` |
| Critical measurements | `QoS::reliable().keep_last(10).transient_local()` |
| Logging/recording | `QoS::reliable().keep_all().persistent()` |

## Performance Tips

1. **Batch small samples**: Group multiple readings if sending faster than 1 kHz
2. **Use best_effort()**: For high-frequency non-critical data
3. **Keep history small**: `keep_last(1)` minimizes memory for streaming data
4. **Pre-allocate**: Reuse SensorData struct to avoid allocations

## Next Steps

- [Reliable Delivery](../examples/reliable-delivery.md) - Guaranteed message delivery
- [Key Instance](../examples/key-instance.md) - Multi-instance topics
- [QoS Policies](../guides/qos-policies/overview.md) - Complete QoS reference
