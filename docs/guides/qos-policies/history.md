# History QoS Policy

The History policy controls how many samples are kept in the writer/reader queue.

## Values

| Value | Description | Memory |
|-------|-------------|--------|
| `keep_last(N)` | Keep only the N most recent samples per instance | Bounded |
| `keep_all()` | Keep all samples until acknowledged | Unbounded* |

*Bounded by ResourceLimits

## Keep Last

Maintains a fixed-size queue of the N most recent samples per instance.

```rust
use hdds::{Participant, QoS, TransportMode};

let participant = Participant::builder("sensor_app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// Keep last 10 samples
let writer = participant
    .topic::<SensorData>("sensors/temperature")?
    .writer()
    .qos(QoS::best_effort().keep_last(10))
    .build()?;
```

**Behavior**:
- When queue is full, oldest sample is replaced
- No blocking on write (unless reliable + buffer full)
- Memory usage is predictable: `depth × sample_size × instances`

**Use cases**:
- Sensor data (latest reading matters most)
- State updates (only current state needed)
- High-frequency data with bounded memory

## Keep All

Maintains all samples until delivered and acknowledged.

```rust
use hdds::{Participant, QoS, TransportMode};

let participant = Participant::builder("command_app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// Keep all samples (bounded by resource limits)
let writer = participant
    .topic::<Command>("robot/commands")?
    .writer()
    .qos(QoS::reliable().keep_all())
    .build()?;
```

**Behavior**:
- Samples accumulate until read/acknowledged
- Memory grows with unread samples
- Must configure ResourceLimits to prevent OOM
- Writer blocks when limits reached (if reliable)

**Use cases**:
- Command queues (every command matters)
- Event logs (no sample loss)
- Reliable data transfer

## Depth Selection Guidelines

| Scenario | Recommended Depth |
|----------|-------------------|
| Real-time control (1 kHz+) | 1-5 |
| Periodic status (10 Hz) | 10-50 |
| Event notifications | 100+ or keep_all() |
| Configuration data | 1 |
| Logs/audit | keep_all() |

## Writer vs Reader History

Both writers and readers have History policies:

### Writer History

Controls retransmission buffer for reliable communication:

```rust
use hdds::{Participant, QoS, TransportMode};

let participant = Participant::builder("reliable_writer")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// Writer keeps 100 samples for retransmission
let writer = participant
    .topic::<StateUpdate>("system/state")?
    .writer()
    .qos(QoS::reliable().keep_last(100))
    .build()?;
```

### Reader History

Controls samples available for `try_take()`:

```rust
use hdds::{Participant, QoS, TransportMode};

let participant = Participant::builder("reader_app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// Reader keeps 50 samples available
let reader = participant
    .topic::<StateUpdate>("system/state")?
    .reader()
    .qos(QoS::reliable().keep_last(50))
    .build()?;
```

## Instance Behavior

For keyed topics, history is **per instance**:

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

// Each sensor_id gets its own 5-sample queue:
// sensor_1: [s1, s2, s3, s4, s5]
// sensor_2: [s1, s2, s3, s4, s5]
let writer = participant
    .topic::<SensorReading>("sensors/readings")?
    .writer()
    .qos(QoS::reliable().keep_last(5))
    .build()?;
```

## Memory Calculation

### Keep Last

```
Memory = depth × max_instances × avg_sample_size
```

Example:
- Depth: 10
- Instances: 100
- Sample size: 1 KB
- **Memory: 1 MB**

### Keep All

```
Memory = max_samples × avg_sample_size
```

Example:
- Max samples: 100,000
- Sample size: 1 KB
- **Memory: 100 MB**

## Interaction with Other Policies

### History + Reliability

| History | Reliability | Behavior |
|---------|-------------|----------|
| keep_last(1) | best_effort() | Fastest, may lose samples |
| keep_last(N) | reliable() | Retransmit from last N samples |
| keep_all() | reliable() | Full reliability, memory grows |

### History + Durability

| History | Durability | Cache for Late Joiners |
|---------|------------|----------------------|
| keep_last(N) | transient_local() | Last N samples |
| keep_all() | transient_local() | All cached samples |
| keep_last(N) | persistent() | Last N on disk |

## Examples

### High-Frequency Sensor

```rust
use hdds::{Participant, QoS, TransportMode};

let participant = Participant::builder("imu_sensor")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// 1 kHz sensor, only latest value matters
let writer = participant
    .topic::<ImuData>("sensors/imu")?
    .writer()
    .qos(QoS::best_effort().keep_last(1))
    .build()?;
```

### Command Queue

```rust
use hdds::{Participant, QoS, TransportMode};

let participant = Participant::builder("command_processor")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// All commands must be executed
let writer = participant
    .topic::<Command>("robot/commands")?
    .writer()
    .qos(QoS::reliable().keep_all())
    .build()?;
```

### State Synchronization

```rust
use hdds::{Participant, QoS, TransportMode};

let participant = Participant::builder("state_sync")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// Keep last 10 states per entity
let writer = participant
    .topic::<EntityState>("system/entities")?
    .writer()
    .qos(QoS::reliable().keep_last(10).transient_local())
    .build()?;
```

### Event Buffer

```rust
use hdds::{Participant, QoS, TransportMode};

let participant = Participant::builder("event_processor")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// Buffer events for slow readers
let writer = participant
    .topic::<Event>("system/events")?
    .writer()
    .qos(QoS::reliable().keep_last(1000))
    .build()?;

let reader = participant
    .topic::<Event>("system/events")?
    .reader()
    .qos(QoS::reliable().keep_last(100))
    .build()?;
```

## Validation Rules

HDDS validates history configuration:

- `keep_last()` depth must be > 0
- `keep_all()` should be used with ResourceLimits to prevent OOM

```rust
// Invalid: depth 0
let qos = QoS::best_effort().keep_last(0);
// Error: History depth must be > 0
```

## Performance Tips

1. **Use keep_last(1)** for real-time control loops
2. **Match writer/reader depths** to avoid overflow
3. **Set ResourceLimits** with keep_all() to prevent OOM
4. **Monitor queue sizes** in production

## Next Steps

- [Deadline](../../guides/qos-policies/deadline.md) - Update frequency requirements
- [Reliability](../../guides/qos-policies/reliability.md) - Delivery guarantees
