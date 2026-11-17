# Deadline QoS Policy

The Deadline policy specifies the maximum time between data updates.

## Purpose

Deadline monitors data freshness:
- **Writers** commit to publishing within the deadline period
- **Readers** expect samples within the deadline period
- **Violations** are counted in a status (`get_offered_deadline_missed_status()` on the writer, `get_requested_deadline_missed_status()` on the reader) and reported to listeners

## Configuration

```rust
use hdds::{Participant, QoS, TransportMode};

let participant = Participant::builder("sensor_app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// Writer commits to 100ms update rate
let writer = participant
    .topic::<SensorData>("sensors/temperature")?
    .writer()
    .qos(QoS::best_effort().keep_last(1).deadline_millis(100))
    .build()?;

// Reader expects updates within 100ms
let reader = participant
    .topic::<SensorData>("sensors/temperature")?
    .reader()
    .qos(QoS::best_effort().deadline_millis(100))
    .build()?;
```

## Default Value

Default is **infinite** (no deadline monitoring):

```rust
let qos = QoS::best_effort();
assert!(qos.deadline.is_infinite());
```

## Compatibility Rules

Writer deadline must be less than or equal to Reader deadline (writer must be faster):

| Writer | Reader | Match? |
|--------|--------|--------|
| 100 ms | 200 ms | Yes |
| 100 ms | 100 ms | Yes |
| 200 ms | 100 ms | No |
| Infinite | 100 ms | No |
| 100 ms | Infinite | Yes |

**Rule**: `Writer.deadline <= Reader.deadline`

## Deadline Tracking

### Writer Side

The writer tracks, per instance, the time since the last `write()` of that instance (an unkeyed topic has a single instance):

```rust
use hdds::{Participant, QoS, TransportMode};

let participant = Participant::builder("sensor_writer")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

let writer = participant
    .topic::<SensorData>("sensors/temperature")?
    .writer()
    .qos(QoS::best_effort().deadline_millis(100))
    .build()?;

// Start the deadline timer for this instance
writer.write(&sample)?;

// If the instance is not written again within 100ms -> offered deadline missed
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
    .qos(QoS::best_effort().deadline_millis(100))
    .build()?;

// The deadline timer of an instance starts when its first sample is received
// If no new sample arrives within 100ms -> requested deadline missed
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
    .qos(QoS::best_effort().deadline_millis(500))
    .build()?;

// sensor_1: last_update=T1, deadline at T1+500ms
// sensor_2: last_update=T2, deadline at T2+500ms
```

## Use Cases

### Periodic Sensor Data

```rust
use hdds::{Participant, QoS, TransportMode};

let participant = Participant::builder("sensor_system")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// Sensor publishes at 10 Hz, reader expects updates
let writer = participant
    .topic::<SensorData>("sensors/imu")?
    .writer()
    .qos(QoS::best_effort().keep_last(1).deadline_millis(100))
    .build()?;

let reader = participant
    .topic::<SensorData>("sensors/imu")?
    .reader()
    .qos(QoS::best_effort().deadline_millis(200)) // 2x tolerance
    .build()?;
```

### Heartbeat Monitoring

```rust
use hdds::{Participant, QoS, TransportMode};

let participant = Participant::builder("heartbeat_monitor")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// Monitor node liveness with heartbeats
let writer = participant
    .topic::<Heartbeat>("system/heartbeat")?
    .writer()
    .qos(QoS::reliable().deadline_secs(1))
    .build()?;

let reader = participant
    .topic::<Heartbeat>("system/heartbeat")?
    .reader()
    .qos(QoS::reliable().deadline_secs(3)) // 3x tolerance
    .build()?;
```

### Control Loop

```rust
use hdds::{Participant, QoS, TransportMode};

let participant = Participant::builder("control_system")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// Real-time control at 1 kHz
let writer = participant
    .topic::<ControlData>("control/commands")?
    .writer()
    .qos(QoS::best_effort().keep_last(1).deadline_millis(1))
    .build()?;
```

## Best Practices

1. **Set reader deadline >= writer deadline**
2. **Add tolerance for network jitter** (2-3x expected period)
3. **Monitor the missed-deadline counters** in production (see below)

```rust
use hdds::{Participant, QoS, TransportMode};

let participant = Participant::builder("example")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// Good: Reader has tolerance
let writer = participant
    .topic::<SensorData>("sensors/data")?
    .writer()
    .qos(QoS::best_effort().deadline_millis(100))
    .build()?;

let reader = participant
    .topic::<SensorData>("sensors/data")?
    .reader()
    .qos(QoS::best_effort().deadline_millis(150)) // 50% tolerance
    .build()?;
```

## Reading the Status

A missed deadline is counted per instance and again for every further period the instance stays silent. The counters are read-and-reset: `total_count_change` is the change since the previous call.

```rust
// Reader side
let status = reader.get_requested_deadline_missed_status();
if status.total_count_change > 0 {
    eprintln!("deadline missed {} times in total", status.total_count);
}

// Writer side
let status = writer.get_offered_deadline_missed_status();
if status.total_count_change > 0 {
    eprintln!("offered deadline missed {} times in total", status.total_count);
}
```

The same events are delivered to a `DataReaderListener` (`on_requested_deadline_missed`) or `DataWriterListener` (`on_offered_deadline_missed`) when one is attached. Detection does not depend on the application calling `take()` or `write()`: the participant evaluates deadlines on its own timer.

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

- Deadline checking cost depends on instance count, timer cadence, build, and
  machine; no reference-grade per-sample cost is currently published
- An infinite deadline (the default) creates no tracking state at all
- Per-instance tracking requires memory per active instance
- Very short deadline periods require careful tuning

## Next Steps

- [Liveliness](../../guides/qos-policies/liveliness.md) - Writer health monitoring
- [Overview](../../guides/qos-policies/overview.md) - All QoS policies
