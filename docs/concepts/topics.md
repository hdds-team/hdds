# Topics

A Topic is a named channel for exchanging data of a specific type between publishers and subscribers.

## Overview

Topics define:
- **Name**: A string identifier (e.g., "SensorData", "RobotStatus")
- **Type**: The data structure being exchanged

QoS policies are set on the writers and readers created from a topic, not on
the topic itself.

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

- Matching is an exact string comparison, so names are case-sensitive:
  `SensorData` != `sensordata`
- `participant.topic()` does not validate the name; an unusual name is
  accepted and simply never matches a different spelling
- Stick to alphanumeric characters, `/`, `_` and `-`, which every DDS
  implementation accepts, so that other vendors can match your topics

## Type Registration

The type of a topic is a Rust type that implements the `hdds::DDS` trait. Derive it
on your own structs, or use types generated from IDL with `hddsgen`:

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

// The type is described by the derive; no separate registration step
let topic = participant.topic::<SensorData>("SensorTopic")?;
```

## Topic Matching

Writers and readers match when:

1. **Same topic name** - Exact string match
2. **Compatible type** - Type name and structure match
3. **Compatible QoS** - QoS policies are compatible

```
Publisher (Domain 0)              Subscriber (Domain 0)
+---------------------+          +---------------------+
| Topic: "SensorData" |  MATCH   | Topic: "SensorData" |
| Type: SensorData    | <----->  | Type: SensorData    |
| QoS: Reliable       |          | QoS: Reliable       |
+---------------------+          +---------------------+

Publisher (Domain 0)              Subscriber (Domain 0)
+---------------------+          +---------------------+
| Topic: "SensorData" | NO MATCH | Topic: "OtherTopic" |
| Type: SensorData    |    X     | Type: SensorData    |
+---------------------+          +---------------------+
```

## Creating Topics

### Basic Creation

```rust
use hdds::{Participant, TransportMode};

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// QoS is chosen when the writer or reader is built
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

## Keyed Topics

Topics with `#[key]` fields support multiple instances:

```rust
use hdds::{Participant, QoS, DDS, TransportMode};

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
4. **Consider partitions**: To separate groups of endpoints on one topic

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

// Single topic, multiple sensors via #[key]
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
