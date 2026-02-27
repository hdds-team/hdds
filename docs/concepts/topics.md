# Topics

A Topic is a named channel for exchanging data of a specific type between publishers and subscribers.

## Overview

Topics define:
- **Name**: A string identifier (e.g., "SensorData", "RobotStatus")
- **Type**: The data structure being exchanged
- **QoS**: Quality of Service policies for the topic

```rust
use hdds::{Participant, QoS, TransportMode};

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// Create a topic for SensorData type
let topic = participant.topic::<SensorData>("SensorTopic")?;
```

## Topic Naming

Topic names are strings that identify data channels:

```rust
use hdds::{Participant, TransportMode};

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// Simple names
let sensor_topic = participant.topic::<SensorData>("sensors")?;

// Hierarchical naming (convention, not enforced)
let lidar_topic = participant.topic::<PointCloud>("/robot/sensors/lidar")?;
let cmd_topic = participant.topic::<Command>("/robot/control/commands")?;

// Namespaced (common in ROS2)
let ros_topic = participant.topic::<Image>("rt/camera/image_raw")?;
```

### Naming Rules

- Case-sensitive: `SensorData` != `sensordata`
- No length limit (but keep reasonable)
- Characters: alphanumeric, `/`, `_`, `-`
- Avoid: spaces, special characters

## Type Registration

Before creating a topic, the type must be known:

```rust
use hdds::{Participant, DDS, TransportMode};

#[derive(Debug, Clone, DDS)]
struct SensorData {
    sensor_id: u32,
    value: f32,
}

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// Types using #[derive(DDS)] are auto-registered
// when you use topic::<T>()
let topic = participant.topic::<SensorData>("SensorTopic")?;
```

## Topic Matching

Writers and readers match when:

1. **Same topic name** - Exact string match
2. **Compatible type** - Type name and structure match
3. **Compatible QoS** - QoS policies are compatible

```
Publisher (Domain 0)              Subscriber (Domain 0)
┌─────────────────────┐          ┌─────────────────────┐
│ Topic: "SensorData" │  MATCH   │ Topic: "SensorData" │
│ Type: SensorData    │ <─────>  │ Type: SensorData    │
│ QoS: Reliable       │          │ QoS: Reliable       │
└─────────────────────┘          └─────────────────────┘

Publisher (Domain 0)              Subscriber (Domain 0)
┌─────────────────────┐          ┌─────────────────────┐
│ Topic: "SensorData" │ NO MATCH │ Topic: "OtherTopic" │
│ Type: SensorData    │    ✗     │ Type: SensorData    │
└─────────────────────┘          └─────────────────────┘
```

## Creating Topics

### Basic Creation

```rust
use hdds::{Participant, TransportMode};

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// Default QoS
let topic = participant.topic::<SensorData>("SensorTopic")?;
```

### With Writer/Reader QoS

```rust
use hdds::{Participant, QoS, TransportMode};

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

let topic = participant.topic::<SensorData>("SensorTopic")?;

// Create writer with specific QoS
let writer = topic
    .writer()
    .qos(QoS::reliable().keep_last(100).transient_local())
    .build()?;

// Create reader with specific QoS
let reader = topic
    .reader()
    .qos(QoS::reliable().keep_last(100))
    .build()?;
```

### Topic Description

```rust
let topic = participant.topic::<SensorData>("SensorTopic")?;

println!("Name: {}", topic.name());         // "SensorTopic"
println!("Type: {}", topic.type_name());    // "SensorData"
```

## Keyed Topics

Topics with `#[key]` fields support multiple instances:

```rust
use hdds::{Participant, DDS, TransportMode};

#[derive(Debug, Clone, DDS)]
struct RobotStatus {
    #[key]
    robot_id: u32,  // Key field
    battery: f32,
    position_x: f32,
    position_y: f32,
}

let participant = Participant::builder("robot_monitor")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

let topic = participant.topic::<RobotStatus>("robot/status")?;
let writer = topic.writer().qos(QoS::reliable()).build()?;

// Multiple robots on same topic - each robot_id creates a separate instance
writer.write(&RobotStatus { robot_id: 1, battery: 95.0, position_x: 0.0, position_y: 0.0 })?;
writer.write(&RobotStatus { robot_id: 2, battery: 87.0, position_x: 1.0, position_y: 2.0 })?;

// Each robot has independent history
```

See [Key Instance Example](../examples/key-instance.md) for details.

## Multi-Topic

Create topics with the same type but different names:

```rust
use hdds::{Participant, TransportMode};

let participant = Participant::builder("home_sensors")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// Different rooms, same sensor type
let kitchen = participant.topic::<Temperature>("kitchen/temp")?;
let bedroom = participant.topic::<Temperature>("bedroom/temp")?;
let bathroom = participant.topic::<Temperature>("bathroom/temp")?;
```

## Best Practices

1. **Use meaningful names**: `robot/sensors/lidar` not `topic1`
2. **Match types exactly**: Same data structure on both sides
3. **Use keys for instances**: When tracking multiple entities
4. **Consider partitions**: For topic-level filtering

## Common Patterns

### Topic per Sensor Type

```rust
use hdds::{Participant, TransportMode};

let participant = Participant::builder("sensor_hub")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

let temperature = participant.topic::<TempReading>("temperature")?;
let humidity = participant.topic::<HumidReading>("humidity")?;
let pressure = participant.topic::<PressReading>("pressure")?;
```

### Topic with Keyed Instances

```rust
use hdds::{Participant, DDS, TransportMode};

#[derive(Debug, Clone, DDS)]
struct SensorData {
    #[key]
    sensor_id: u32,  // Key creates separate instances
    value: f32,
}

let participant = Participant::builder("multi_sensor")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// Single topic, multiple sensors via @key
let sensors = participant.topic::<SensorData>("all_sensors")?;
```

### Hierarchical Topics

```rust
use hdds::{Participant, TransportMode};

let participant = Participant::builder("navigation")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// Navigation subsystem
let gps = participant.topic::<GPS>("/nav/gps")?;
let imu = participant.topic::<IMU>("/nav/imu")?;
let odom = participant.topic::<Odometry>("/nav/odom")?;
```

## Next Steps

- [Publishers and Subscribers](../concepts/publishers-subscribers.md) - Data distribution
- [Key Instance Example](../examples/key-instance.md) - Working with instances
- [QoS Overview](../concepts/qos-overview.md) - Quality of Service
