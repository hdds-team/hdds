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
        @key unsigned long zone_id;     // Composite key part
        RobotState state;
        float battery_percent;
        float position_x;
        float position_y;
        unsigned long long timestamp;
    };
};
```

The combination of `robot_id` + `zone_id` forms the instance key.

Generate the Rust types with `hddsgen` (built from the separate `hdds_gen`
repository: `git clone https://git.hdds.io/hdds/hdds_gen.git && cargo install --path hdds_gen`):

```bash
hddsgen gen rust Robot.idl -o src/robot.rs
```

Declare the generated file as a module of the package. The programs below
refer to the package as `my_app`; use your own package name:

```rust title="src/lib.rs"
pub mod robot;
```

The IDL module `fleet` becomes the Rust module `robot::fleet`. Generated enum
variants keep the case used in the IDL (`RobotState::MOVING`), and generated
structs have public fields, no `new(...)` and no `Default`.

## Publisher

```rust title="src/bin/robot_publisher.rs"
use hdds::{Participant, QoS, TransportMode};
use my_app::robot::fleet::{RobotState, RobotStatus};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
    let robots = [("robot_001", 1), ("robot_002", 1), ("robot_003", 2)];

    for tick in 0..100 {
        for (robot_id, zone_id) in robots {
            let status = RobotStatus {
                robot_id: robot_id.to_string(),
                zone_id,
                state: RobotState::MOVING,
                battery_percent: 100.0 - (tick as f32 * 0.5),
                position_x: tick as f32 * 0.1,
                position_y: tick as f32 * 0.05,
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64,
            };

            writer.write(&status)?;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    Ok(())
}
```

## Subscriber

The reader keeps the last sample of each instance (`keep_last(1)` is applied
per instance), and the application tracks the latest state per robot:

```rust title="src/bin/robot_subscriber.rs"
use hdds::{Participant, QoS, TransportMode};
use my_app::robot::fleet::RobotStatus;
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let participant = Participant::builder("robot_subscriber")
        .domain_id(0)
        .with_transport(TransportMode::UdpMulticast)
        .build()?;

    let topic = participant.topic::<RobotStatus>("RobotStatusTopic")?;
    let reader = topic
        .reader()
        .qos(QoS::reliable().keep_last(1)) // Latest state per robot
        .build()?;

    // Track latest state per robot
    let mut robot_states: HashMap<(String, u32), RobotStatus> = HashMap::new();

    loop {
        while let Some(sample) = reader.take()? {
            let key = (sample.robot_id.clone(), sample.zone_id);

            println!(
                "[{}:zone{}] {:?} - battery: {:.1}%, pos: ({:.2}, {:.2})",
                sample.robot_id,
                sample.zone_id,
                sample.state,
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

The lifecycle calls take a sample of the topic type, and only its key fields
matter. This helper builds such a "key only" sample:

```rust
use my_app::robot::fleet::{RobotState, RobotStatus};

fn key_only(robot_id: &str, zone_id: u32) -> RobotStatus {
    RobotStatus {
        robot_id: robot_id.to_string(),
        zone_id,
        state: RobotState::IDLE,
        battery_percent: 0.0,
        position_x: 0.0,
        position_y: 0.0,
        timestamp: 0,
    }
}
```

### Register Instance

```rust
// Pre-register the instance. The returned handle is the instance's key hash;
// registering starts deadline monitoring (if a deadline is set) before the
// first write, and sends nothing on the wire.
let handle = writer.register_instance(&key_only("robot_001", 1))?;
```

Registration is optional: `write`, `dispose` and `unregister_instance` all take
the sample itself and compute the key from it.

### Dispose Instance

```rust
// Mark instance as "no longer available"
writer.dispose(&key_only("robot_001", 1))?;
```

Subscribers receive a notification that carries no data. `take_with_info()`
returns it as `(None, info)` with `info.valid_data == false`; the notification
identifies the instance by `info.instance_handle` only, so keep a map from the
handle to the key while data samples arrive:

```rust
use hdds::dds::{InstanceHandle, InstanceState};
use std::collections::HashMap;

let mut keys: HashMap<InstanceHandle, (String, u32)> = HashMap::new();

while let Some((sample, info)) = reader.take_with_info()? {
    match sample {
        Some(s) => {
            keys.insert(info.instance_handle, (s.robot_id.clone(), s.zone_id));
            println!("{} in zone {}: {:?}", s.robot_id, s.zone_id, s.state);
        }
        None if info.instance_state == InstanceState::NotAliveDisposed => {
            if let Some((robot_id, zone_id)) = keys.get(&info.instance_handle) {
                println!("Robot {} left zone {}", robot_id, zone_id);
            }
        }
        None => {}
    }
}
```

### Unregister Instance

```rust
// Writer no longer responsible for instance
writer.unregister_instance(&status)?;
```

## Reading Specific Instances

An instance handle is the 16-byte key hash of the sample. Compute it from a
key-only sample and read just that instance:

```rust
use hdds::dds::InstanceHandle;
use hdds::DdsTrait;

// Take only the data of one robot
let handle = InstanceHandle::new(key_only("robot_001", 1).compute_key());
while let Some(sample) = reader.take_instance(handle)? {
    println!("robot_001 battery: {:.1}%", sample.battery_percent);
}
```

`read_instance(handle)` is the non-removing variant, and `take_instance_batch`
/ `read_instance_batch` return several samples at once.

## Instance States

| State | Meaning |
|-------|---------|
| `Alive` | Writer is actively publishing |
| `NotAliveDisposed` | Writer called `dispose()` |
| `NotAliveNoWriters` | All writers unregistered or lost liveliness |

## Per-Instance QoS

Deadline is tracked per instance:

```rust
use hdds::QoS;

let qos = QoS::reliable().deadline_millis(500);

// Each robot instance has independent deadline
// robot_001 can miss deadline while robot_002 is fine
```

A reader listener reports which instance missed its deadline:

```rust
use hdds::dds::{DataReaderListener, RequestedDeadlineMissedStatus};
use std::sync::Arc;

struct MyListener;

impl DataReaderListener<RobotStatus> for MyListener {
    fn on_requested_deadline_missed(&self, status: RequestedDeadlineMissedStatus) {
        // status.last_instance_handle identifies which robot
        println!(
            "Deadline missed for instance {:?}",
            status.last_instance_handle
        );
    }
}

let reader = topic
    .reader()
    .qos(QoS::reliable().deadline_millis(500))
    .with_listener(Arc::new(MyListener))
    .build()?;
```

## Key Design Patterns

### Single Key

```c
@topic
struct SensorReading {
    @key unsigned long sensor_id;
    float value;
};
```

### Composite Key

```c
@topic
struct FlightData {
    @key string<8> airline_code;
    @key unsigned short flight_number;
    @key unsigned long date;  // YYYYMMDD
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

Memory is bounded by instances x history_depth x sample_size.

```rust
use hdds::QoS;

let mut qos = QoS::reliable().keep_last(10);
qos.resource_limits = hdds::qos::ResourceLimits {
    max_samples: 10000,
    max_instances: 1000,
    max_samples_per_instance: 10,
    ..Default::default()
};
```

## Next Steps

- [Multi-Topic](../examples/multi-topic.md) - Multiple topics in one application
- [History QoS](../guides/qos-policies/history.md) - History buffer configuration
- [Deadline QoS](../guides/qos-policies/deadline.md) - Per-instance deadlines
