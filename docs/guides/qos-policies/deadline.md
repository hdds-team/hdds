# Deadline QoS Policy

The Deadline policy specifies the maximum time between data updates.

## Purpose

Deadline monitors data freshness:
- **Writers** commit to publishing within the deadline period
- **Readers** expect samples within the deadline period
- **Violations** are tracked via status

## Configuration

```rust
use hdds::{Participant, QoS, TransportMode};
use std::time::Duration;

let participant = Participant::builder("sensor_app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// Writer commits to 100ms update rate
let writer = participant
    .topic::<SensorData>("sensors/temperature")?
    .writer()
    .qos(QoS::best_effort().keep_last(1).deadline(Duration::from_millis(100)))
    .build()?;

// Reader expects updates within 100ms
let reader = participant
    .topic::<SensorData>("sensors/temperature")?
    .reader()
    .qos(QoS::best_effort().deadline(Duration::from_millis(100)))
    .build()?;
```

## Default Value

Default is **infinite** (no deadline monitoring):

```rust
let qos = QoS::best_effort();
// deadline = Duration::MAX (infinite)
```

## Compatibility Rules

Writer deadline must be less than or equal to Reader deadline (writer must be faster):

| Writer | Reader | Match? |
|--------|--------|--------|
| 100 ms | 200 ms | ✅ Yes |
| 100 ms | 100 ms | ✅ Yes |
| 200 ms | 100 ms | ❌ No |
| Infinite | 100 ms | ❌ No |
| 100 ms | Infinite | ✅ Yes |

**Rule**: `Writer.deadline ≤ Reader.deadline`

## Deadline Tracking

### Writer Side

The writer tracks time since last `write()` call:

```rust
use hdds::{Participant, QoS, TransportMode};

let participant = Participant::builder("sensor_writer")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

let writer = participant
    .topic::<SensorData>("sensors/temperature")?
    .writer()
    .qos(QoS::best_effort().deadline(Duration::from_millis(100)))
    .build()?;

// Start deadline timer
writer.write(&sample)?;

// If no write within 100ms → deadline missed
```

### Reader Side

The reader tracks time since last sample received per instance:

```rust
use hdds::{Participant, QoS, TransportMode};

let participant = Participant::builder("sensor_reader")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

let reader = participant
    .topic::<SensorData>("sensors/temperature")?
    .reader()
    .qos(QoS::best_effort().deadline(Duration::from_millis(100)))
    .build()?;

// Deadline timer starts when first sample received
// If no new sample within 100ms → deadline missed
```

## Per-Instance Deadline

For keyed topics, deadline is tracked per instance:

```rust
use hdds::{Participant, QoS, DDS, TransportMode};

#[derive(Debug, Clone, DDS)]
struct SensorReading {
    #[key]
    sensor_id: u32,
    value: f32,
}

let participant = Participant::builder("multi_sensor")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// Each sensor_id has its own deadline timer
let reader = participant
    .topic::<SensorReading>("sensors/readings")?
    .reader()
    .qos(QoS::best_effort().deadline(Duration::from_millis(500)))
    .build()?;

// sensor_1: last_update=T1, deadline at T1+500ms
// sensor_2: last_update=T2, deadline at T2+500ms
```

## Use Cases

### Periodic Sensor Data

```rust
use hdds::{Participant, QoS, TransportMode};
use std::time::Duration;

let participant = Participant::builder("sensor_system")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// Sensor publishes at 10 Hz, reader expects updates
let writer = participant
    .topic::<SensorData>("sensors/imu")?
    .writer()
    .qos(QoS::best_effort().keep_last(1).deadline(Duration::from_millis(100)))
    .build()?;

let reader = participant
    .topic::<SensorData>("sensors/imu")?
    .reader()
    .qos(QoS::best_effort().deadline(Duration::from_millis(200))) // 2x tolerance
    .build()?;
```

### Heartbeat Monitoring

```rust
use hdds::{Participant, QoS, TransportMode};
use std::time::Duration;

let participant = Participant::builder("heartbeat_monitor")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// Monitor node liveness with heartbeats
let writer = participant
    .topic::<Heartbeat>("system/heartbeat")?
    .writer()
    .qos(QoS::reliable().deadline(Duration::from_secs(1)))
    .build()?;

let reader = participant
    .topic::<Heartbeat>("system/heartbeat")?
    .reader()
    .qos(QoS::reliable().deadline(Duration::from_secs(3))) // 3x tolerance
    .build()?;
```

### Control Loop

```rust
use hdds::{Participant, QoS, TransportMode};
use std::time::Duration;

let participant = Participant::builder("control_system")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// Real-time control at 1 kHz
let writer = participant
    .topic::<ControlData>("control/commands")?
    .writer()
    .qos(QoS::best_effort().keep_last(1).deadline(Duration::from_micros(1000)))
    .build()?;
```

## Best Practices

1. **Set reader deadline >= writer deadline**
2. **Add tolerance for network jitter** (2-3× expected period)
3. **Monitor deadline statistics** in production

```rust
use hdds::{Participant, QoS, TransportMode};
use std::time::Duration;

let participant = Participant::builder("example")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// Good: Reader has tolerance
let writer = participant
    .topic::<SensorData>("sensors/data")?
    .writer()
    .qos(QoS::best_effort().deadline(Duration::from_millis(100)))
    .build()?;

let reader = participant
    .topic::<SensorData>("sensors/data")?
    .reader()
    .qos(QoS::best_effort().deadline(Duration::from_millis(150))) // 50% tolerance
    .build()?;
```

## Interaction with Other Policies

### Deadline + Liveliness

Both monitor entity health, but differently:

| Policy | Monitors | Granularity |
|--------|----------|-------------|
| Deadline | Data updates | Per instance |
| Liveliness | Writer existence | Per writer |

### Deadline + Reliability

| Deadline | Reliability | Behavior |
|----------|-------------|----------|
| Set | best_effort() | Deadline may miss on network loss |
| Set | reliable() | Retransmissions help meet deadline |

## Performance Notes

- Deadline checking adds minimal CPU overhead (~1 μs per sample)
- Per-instance tracking requires memory per active instance
- High-frequency deadlines (< 1ms) require careful tuning

## Next Steps

- [Liveliness](../../guides/qos-policies/liveliness.md) - Writer health monitoring
- [Overview](../../guides/qos-policies/overview.md) - All QoS policies
