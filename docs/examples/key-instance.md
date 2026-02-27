# Key Instance Example

Demonstrates using `@key` fields to create multi-instance topics.

## Overview

In DDS, a **key** identifies unique instances within a topic. Each instance:
- Has independent lifecycle (register, write, dispose, unregister)
- Maintains separate QoS tracking (deadline, liveliness)
- Can have different history buffers

## IDL Definition

```c title="Robot.idl"
module fleet {
    enum RobotState {
        IDLE,
        MOVING,
        CHARGING,
        ERROR
    };

    @topic
    struct RobotStatus {
        @key string<32> robot_id;       // Primary key
        @key uint32 zone_id;            // Composite key part
        RobotState state;
        float battery_percent;
        float position_x;
        float position_y;
        uint64 timestamp;
    };
};
```

The combination of `robot_id` + `zone_id` forms the instance key.

## Publisher

```rust title="src/robot_publisher.rs"
use hdds::{Participant, QoS, DDS, TransportMode};
use fleet::{RobotStatus, RobotState};

#[derive(Debug, Clone, DDS)]
struct RobotStatus {
    #[key]
    robot_id: String,
    #[key]
    zone_id: u32,
    state: RobotState,
    battery_percent: f32,
    position_x: f32,
    position_y: f32,
    timestamp: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let participant = Participant::builder("robot_publisher")
        .domain_id(0)
        .with_transport(TransportMode::UdpMulticast)
        .build()?;

    let topic = participant.topic::<RobotStatus>("RobotStatusTopic")?;
    let writer = topic
        .writer()
        .qos(QoS::reliable().keep_last(10))
        .build()?;

    // Simulate 3 robots in 2 zones
    let robots = vec![
        ("robot_001", 1),
        ("robot_002", 1),
        ("robot_003", 2),
    ];

    for tick in 0..100 {
        for (robot_id, zone_id) in &robots {
            let status = RobotStatus {
                robot_id: robot_id.to_string(),
                zone_id: *zone_id,
                state: RobotState::Moving,
                battery_percent: 100.0 - (tick as f32 * 0.5),
                position_x: tick as f32 * 0.1,
                position_y: tick as f32 * 0.05,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_nanos() as u64,
            };

            writer.write(&status)?;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    Ok(())
}
```

## Subscriber with Instance Filtering

```rust title="src/robot_subscriber.rs"
use hdds::{Participant, QoS, DDS, TransportMode};
use fleet::RobotStatus;
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let participant = Participant::builder("robot_subscriber")
        .domain_id(0)
        .with_transport(TransportMode::UdpMulticast)
        .build()?;

    let topic = participant.topic::<RobotStatus>("RobotStatusTopic")?;
    let reader = topic
        .reader()
        .qos(QoS::reliable().keep_last(1))  // Latest state per robot
        .build()?;

    // Track latest state per robot
    let mut robot_states: HashMap<(String, u32), RobotStatus> = HashMap::new();

    loop {
        while let Some(sample) = reader.try_take()? {
            let key = (sample.robot_id.clone(), sample.zone_id);

            println!(
                "[{}:zone{}] {} - battery: {:.1}%, pos: ({:.2}, {:.2})",
                sample.robot_id,
                sample.zone_id,
                format!("{:?}", sample.state),
                sample.battery_percent,
                sample.position_x,
                sample.position_y
            );

            robot_states.insert(key, sample);
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
```

## Instance Lifecycle

### Register Instance

```rust
// Pre-register instance for faster first write
let handle = writer.register_instance(&RobotStatus {
    robot_id: "robot_001".to_string(),
    zone_id: 1,
    ..Default::default()
})?;

// Write using handle (faster than key lookup)
writer.write_with_handle(&status, handle)?;
```

### Dispose Instance

```rust
// Mark instance as "no longer available"
writer.dispose(&RobotStatus {
    robot_id: "robot_001".to_string(),
    zone_id: 1,
    ..Default::default()
})?;
```

Subscribers receive dispose notification:

```rust
match reader.take_with_info() {
    Ok(samples) => {
        for (sample, info) in samples {
            if info.instance_state == InstanceState::NotAliveDisposed {
                println!("Robot {} left zone {}", sample.robot_id, sample.zone_id);
            }
        }
    }
    // ...
}
```

### Unregister Instance

```rust
// Writer no longer responsible for instance
writer.unregister_instance(&status)?;
```

## Reading Specific Instances

```rust
// Read only data for a specific robot
let key = RobotStatus {
    robot_id: "robot_001".to_string(),
    zone_id: 1,
    ..Default::default()
};

let handle = reader.lookup_instance(&key)?;
let samples = reader.take_instance(handle)?;
```

## Instance States

| State | Meaning |
|-------|---------|
| `Alive` | Writer is actively publishing |
| `NotAliveDisposed` | Writer called `dispose()` |
| `NotAliveNoWriters` | All writers unregistered or lost liveliness |

## Per-Instance QoS

Deadline and liveliness are tracked per instance:

```rust
use hdds::QoS;
use std::time::Duration;

let qos = QoS::reliable().deadline(Duration::from_millis(500));

// Each robot instance has independent deadline
// robot_001 can miss deadline while robot_002 is fine
```

Listener callback includes instance info:

```rust
impl DataReaderListener for MyListener {
    fn on_requested_deadline_missed(
        &mut self,
        reader: &DataReader<RobotStatus>,
        status: RequestedDeadlineMissedStatus,
    ) {
        // status.last_instance_handle identifies which robot
        println!(
            "Deadline missed for instance {:?}",
            status.last_instance_handle
        );
    }
}
```

## Key Design Patterns

### Single Key

```c
@topic
struct SensorReading {
    @key uint32 sensor_id;
    float value;
};
```

### Composite Key

```c
@topic
struct FlightData {
    @key string<8> airline_code;
    @key uint16 flight_number;
    @key uint32 date;  // YYYYMMDD
    // ... data
};
```

### No Key (Singleton)

```c
@topic
struct SystemConfig {
    // No @key - single instance per topic
    string config_data;
};
```

## Memory Considerations

| History | Memory per Instance |
|---------|---------------------|
| keep_last(1) | 1 x sample_size |
| keep_last(N) | N x sample_size |
| keep_all() | Unbounded (use resource limits) |

Total memory = instances x history_depth x sample_size

```rust
use hdds::QoS;

let qos = QoS::reliable()
    .keep_last(10)
    .max_instances(1000)
    .max_samples_per_instance(10)
    .max_samples(10000);
```

## Next Steps

- [Multi-Topic](../examples/multi-topic.md) - Multiple topics in one application
- [History QoS](../guides/qos-policies/history.md) - History buffer configuration
- [Deadline QoS](../guides/qos-policies/deadline.md) - Per-instance deadlines
