# QoS Policies Overview

DDS provides **22 Quality of Service policies** to fine-tune data distribution behavior. HDDS implements all standard policies from DDS v1.4.

## Most Important Policies

| Policy | Description | Default |
|--------|-------------|---------|
| [Reliability](../../guides/qos-policies/reliability.md) | Delivery guarantee | BEST_EFFORT |
| [Durability](../../guides/qos-policies/durability.md) | Data persistence | VOLATILE |
| [History](../../guides/qos-policies/history.md) | Sample buffering | KEEP_LAST(10) |
| [Deadline](../../guides/qos-policies/deadline.md) | Update frequency | Infinite |
| [Liveliness](../../guides/qos-policies/liveliness.md) | Failure detection | AUTOMATIC |

## All 22 QoS Policies

### Data Distribution

| Policy | Purpose |
|--------|---------|
| **Reliability** | BEST_EFFORT vs RELIABLE delivery |
| **History** | KEEP_LAST(n) vs KEEP_ALL buffering |
| **Durability** | VOLATILE, TRANSIENT_LOCAL, PERSISTENT |
| **DurabilityService** | Late-joiner delivery configuration |
| **ResourceLimits** | Max samples, instances, memory |

### Timing

| Policy | Purpose |
|--------|---------|
| **Deadline** | Maximum time between samples |
| **LatencyBudget** | Acceptable delay hint |
| **Lifespan** | Data expiration time |
| **TimeBasedFilter** | Minimum separation between samples |

### Ownership

| Policy | Purpose |
|--------|---------|
| **Ownership** | SHARED vs EXCLUSIVE writer control |
| **OwnershipStrength** | Priority for exclusive ownership |

### Ordering

| Policy | Purpose |
|--------|---------|
| **DestinationOrder** | BY_RECEPTION_TIMESTAMP vs BY_SOURCE_TIMESTAMP |
| **Presentation** | Coherent/ordered access scope |

### Lifecycle

| Policy | Purpose |
|--------|---------|
| **Liveliness** | AUTOMATIC, MANUAL_BY_PARTICIPANT, MANUAL_BY_TOPIC |
| **WriterDataLifecycle** | Auto-dispose unregistered instances |
| **ReaderDataLifecycle** | Auto-purge samples without writers |
| **EntityFactory** | Auto-enable child entities |

### Metadata

| Policy | Purpose |
|--------|---------|
| **UserData** | Custom user metadata |
| **TopicData** | Topic-level metadata |
| **GroupData** | Publisher/Subscriber metadata |
| **Partition** | Logical data separation |
| **TransportPriority** | Network QoS hint |

## Quick Start

```rust
use hdds::{Participant, QoS, TransportMode};

let participant = Participant::builder("my_app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// Create writer with fluent QoS builder
let writer = participant
    .topic::<SensorData>("sensors/temperature")?
    .writer()
    .qos(QoS::reliable().keep_last(10).transient_local())
    .build()?;
```

## QoS Presets

HDDS provides built-in presets for common scenarios:

```rust
use hdds::{Participant, QoS, TransportMode};

let participant = Participant::builder("my_app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// Low latency (gaming, real-time control)
let writer = participant
    .topic::<ControlData>("control/commands")?
    .writer()
    .qos(QoS::best_effort().keep_last(1))
    .build()?;

// High throughput (bulk data transfer)
let writer = participant
    .topic::<BulkData>("data/transfer")?
    .writer()
    .qos(QoS::best_effort().keep_last(1000))
    .build()?;

// Reliable (guaranteed delivery with caching)
let writer = participant
    .topic::<StateData>("state/updates")?
    .writer()
    .qos(QoS::reliable().keep_last(100).transient_local())
    .build()?;
```

## QoS Compatibility

Writers and readers must have compatible QoS to communicate:

| Writer | Reader | Result |
|--------|--------|--------|
| reliable() | reliable() | Match |
| reliable() | best_effort() | Match |
| best_effort() | reliable() | **No Match** |
| best_effort() | best_effort() | Match |

:::warning Compatibility
A BEST_EFFORT writer cannot satisfy a RELIABLE reader. The reader expects acknowledgments that the writer won't send.
:::

## Fluent Builder API

HDDS uses a fluent builder pattern for QoS configuration:

```rust
use hdds::QoS;

// Start with a preset
let qos = QoS::reliable()
    .keep_last(100)        // History: keep last 100 samples
    .transient_local();    // Durability: cache for late joiners

// Or start from scratch
let qos = QoS::best_effort()
    .keep_last(1)          // Minimal history
    .volatile();           // No caching
```

### Available Methods

| Method | Description |
|--------|-------------|
| `QoS::reliable()` | Guaranteed delivery with ACK/NACK |
| `QoS::best_effort()` | Fire and forget |
| `.keep_last(n)` | Keep last N samples per instance |
| `.keep_all()` | Keep all samples |
| `.volatile()` | No persistence |
| `.transient_local()` | In-memory cache for late joiners |
| `.persistent()` | Disk persistence |

## Next Steps

- [Reliability](../../guides/qos-policies/reliability.md) - RELIABLE vs BEST_EFFORT
- [Durability](../../guides/qos-policies/durability.md) - Data persistence
- [History](../../guides/qos-policies/history.md) - Sample buffering
