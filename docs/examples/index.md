# Examples

Learn HDDS through practical examples. Each example includes complete, runnable code.

## Basic Examples

| Example | Description | Languages |
|---------|-------------|-----------|
| [Temperature Sensor](../examples/temperature-sensor.md) | Simple pub/sub with sensor data | Rust, C, Python |
| [Key Instances](../examples/key-instance.md) | Using @key for multi-instance tracking | Rust |
| [Reliable Delivery](../examples/reliable-delivery.md) | Guaranteed message delivery | Rust, C++ |

## Intermediate Examples

| Example | Description | Languages |
|---------|-------------|-----------|
| [Multi-Topic](../examples/multi-topic.md) | Publishing to multiple topics | Rust |
| [Cross-Vendor](../examples/cross-vendor.md) | HDDS + FastDDS interop | Rust, C++ |

## Advanced Examples

| Example | Description | Languages |
|---------|-------------|-----------|
| Multi-Node Cluster | Distributed system with 3+ nodes | Rust |
| Security Enabled | DDS Security with TLS | Rust |
| Real-time Constraints | Deterministic latency | Rust |

## Running Examples

### From the Repository

```bash
git clone https://git.hdds.io/hdds/hdds-examples.git
cd hdds-examples

# Run a specific example
cargo run --example temperature_sensor

# Run with release optimizations
cargo run --release --example temperature_sensor
```

### Structure

Each example includes:

```
examples/
├── temperature_sensor/
│   ├── README.md           # Explanation and instructions
│   ├── Cargo.toml          # Dependencies
│   ├── src/
│   │   ├── publisher.rs    # Publisher code
│   │   ├── subscriber.rs   # Subscriber code
│   │   └── types.rs        # Data types
│   └── Temperature.idl     # IDL definition (optional)
```

## Example: Temperature Sensor

The classic "Hello World" of DDS:

```rust
use hdds::{Participant, TransportMode};

#[derive(Topic, Serialize, Deserialize)]
struct Temperature {
    #[key]
    sensor_id: String,
    value: f32,
}

fn main() -> Result<()> {
    let participant = Participant::builder("temp_sensor")
        .domain_id(0)
        .with_transport(TransportMode::UdpMulticast)
        .build()?;
    let topic = participant.create_topic::<Temperature>("sensors/temp")?;
    let writer = participant.create_writer(&topic)?;

    writer.write(&Temperature {
        sensor_id: "kitchen".into(),
        value: 23.5,
    })?;

    Ok(())
}
```

[See full example →](../examples/temperature-sensor.md)
