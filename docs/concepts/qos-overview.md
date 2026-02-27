# Quality of Service Overview

Quality of Service (QoS) policies control how DDS delivers data, providing fine-grained control over reliability, timing, resource usage, and more.

## Why QoS?

Different applications have different requirements:

| Use Case | Requirements |
|----------|--------------|
| Sensor streaming | High rate, some loss OK |
| Commands | Guaranteed delivery, ordered |
| State sync | Late joiners get current state |
| Real-time control | Low latency, deadline monitoring |

QoS policies let you configure these behaviors declaratively.

## QoS Policy Categories

```
┌─────────────────────────────────────────────────────────────┐
│                    QoS Policy Groups                         │
├─────────────────┬─────────────────┬─────────────────────────┤
│ Data Delivery   │ Timing          │ Resource Management     │
│ - Reliability   │ - Deadline      │ - History               │
│ - Durability    │ - Latency Budget│ - ResourceLimits        │
│ - History       │ - Lifespan      │                         │
├─────────────────┼─────────────────┼─────────────────────────┤
│ Ownership       │ Ordering        │ Lifecycle               │
│ - Ownership     │ - DestinationOrd│ - Liveliness            │
│ - OwnershipStr  │ - Presentation  │ - WriterDataLifecycle   │
│                 │                 │ - ReaderDataLifecycle   │
├─────────────────┴─────────────────┴─────────────────────────┤
│ Metadata: UserData, TopicData, GroupData, Partition         │
└─────────────────────────────────────────────────────────────┘
```

## Core QoS Policies

### Reliability

Controls whether data delivery is guaranteed:

```rust
use hdds::{Participant, QoS, TransportMode};

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

let topic = participant.topic::<SensorData>("sensors/data")?;

// Best effort - may lose samples (fast)
let writer = topic
    .writer()
    .qos(QoS::best_effort())
    .build()?;

// Reliable - guaranteed delivery with retransmits
let writer = topic
    .writer()
    .qos(QoS::reliable())
    .build()?;
```

### Durability

Controls data persistence for late-joining subscribers:

```rust
use hdds::{Participant, QoS, TransportMode};

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

let topic = participant.topic::<SensorData>("sensors/data")?;

// Volatile - no history for late joiners (default)
let writer = topic
    .writer()
    .qos(QoS::reliable().volatile())
    .build()?;

// Transient Local - keep samples in memory for late joiners
let writer = topic
    .writer()
    .qos(QoS::reliable().transient_local())
    .build()?;

// Persistent - survive process restart
let writer = topic
    .writer()
    .qos(QoS::reliable().persistent())
    .build()?;
```

### History

Controls how many samples are kept:

```rust
use hdds::{Participant, QoS, TransportMode};

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

let topic = participant.topic::<SensorData>("sensors/data")?;

// Keep last N samples per instance
let writer = topic
    .writer()
    .qos(QoS::reliable().keep_last(10))
    .build()?;

// Keep all samples
let writer = topic
    .writer()
    .qos(QoS::reliable().keep_all())
    .build()?;
```

## QoS Compatibility

Writers and readers must have compatible QoS to communicate:

```
Writer QoS          Reader QoS           Match?
──────────────────────────────────────────────────
reliable()    -->   reliable()           Yes
reliable()    -->   best_effort()        Yes
best_effort() -->   best_effort()        Yes
best_effort() -->   reliable()           NO

persistent()      -->   persistent()       Yes
persistent()      -->   transient_local()  Yes
persistent()      -->   volatile()         Yes
transient_local() -->   transient_local()  Yes
transient_local() -->   volatile()         Yes
transient_local() -->   persistent()       NO
volatile()        -->   volatile()         Yes
volatile()        -->   transient_local()  NO
```

**Rule**: Writer must offer at least what Reader requests.

## Fluent Builder API

HDDS uses a fluent builder pattern for QoS:

```rust
use hdds::QoS;

// Start with a preset
let qos = QoS::reliable()
    .keep_last(100)        // History: keep last 100 samples
    .transient_local();    // Durability: cache for late joiners

// Or best effort for speed
let qos = QoS::best_effort()
    .keep_last(1)          // Minimal history
    .volatile();           // No caching
```

## Common QoS Profiles

### Sensor Streaming

```rust
use hdds::{Participant, QoS, TransportMode};

let participant = Participant::builder("sensor_stream")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

let topic = participant.topic::<SensorData>("sensors/imu")?;

// Fast, may lose samples
let writer = topic
    .writer()
    .qos(QoS::best_effort().keep_last(1))
    .build()?;
```

### State Synchronization

```rust
use hdds::{Participant, QoS, TransportMode};

let participant = Participant::builder("state_sync")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

let topic = participant.topic::<StateData>("system/state")?;

// Reliable with caching for late joiners
let writer = topic
    .writer()
    .qos(QoS::reliable().keep_last(1).transient_local())
    .build()?;
```

### Command Queue

```rust
use hdds::{Participant, QoS, TransportMode};

let participant = Participant::builder("command_queue")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

let topic = participant.topic::<Command>("robot/commands")?;

// Every command must be delivered
let writer = topic
    .writer()
    .qos(QoS::reliable().keep_all())
    .build()?;
```

### Event Log

```rust
use hdds::{Participant, QoS, TransportMode};

let participant = Participant::builder("event_log")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

let topic = participant.topic::<AuditEvent>("audit/events")?;

// Persistent event log survives restarts
let writer = topic
    .writer()
    .qos(QoS::reliable().keep_all().persistent())
    .build()?;
```

## Timing Policies

### Deadline

Monitor data freshness:

```rust
use hdds::{Participant, QoS, TransportMode};
use std::time::Duration;

let participant = Participant::builder("deadline_example")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

let topic = participant.topic::<SensorData>("sensors/data")?;

// Writer must publish within 100ms
let writer = topic
    .writer()
    .qos(QoS::reliable().deadline(Duration::from_millis(100)))
    .build()?;
```

### Liveliness

Detect writer failures:

```rust
use hdds::{Participant, QoS, TransportMode};
use std::time::Duration;

let participant = Participant::builder("liveliness_example")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

let topic = participant.topic::<Heartbeat>("system/heartbeat")?;

// Writer automatically asserts liveliness
// Reader notified if writer stops for 10s
let writer = topic
    .writer()
    .qos(QoS::reliable().liveliness_automatic(Duration::from_secs(10)))
    .build()?;
```

## QoS Policy Summary

| Policy | Purpose |
|--------|---------|
| `reliable()` / `best_effort()` | Delivery guarantee |
| `transient_local()` / `volatile()` / `persistent()` | Historical data |
| `keep_last(n)` / `keep_all()` | Sample buffer |
| `deadline()` | Update rate monitoring |
| `liveliness_*()` | Failure detection |

## Troubleshooting QoS

### No Match (QoS Incompatible)

```
Warning: Writer and Reader QoS incompatible
```

Check:
- Reliability: Writer ≥ Reader
- Durability: Writer ≥ Reader
- Deadline: Writer ≤ Reader
- Liveliness: Writer kind ≥ Reader kind

### Missed Deadlines

```
Warning: Deadline missed
```

Solutions:
- Increase deadline period
- Reduce publish rate
- Check for network issues

## Next Steps

- [Reliability](../guides/qos-policies/reliability.md) - Detailed reliability guide
- [Durability](../guides/qos-policies/durability.md) - Historical data
- [Deadline](../guides/qos-policies/deadline.md) - Timing requirements
- [QoS Cheatsheet](../reference/qos-cheatsheet.md) - Quick reference
