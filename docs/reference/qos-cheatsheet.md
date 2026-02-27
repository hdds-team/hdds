# QoS Cheatsheet

Quick reference for HDDS QoS policies and the fluent builder API.

## Data Distribution

| Policy | Values | Default | Compatibility |
|--------|--------|---------|---------------|
| **Reliability** | `best_effort()`, `reliable()` | best_effort | Exact match |
| **History** | `keep_last(N)`, `keep_all()` | keep_last(100) | N/A |
| **Durability** | `volatile()`, `transient_local()`, `persistent()` | volatile | Writer >= Reader |
| **ResourceLimits** | max_samples, max_instances, max_quota_bytes | Unlimited | N/A |

## Timing

| Policy | Values | Default | Compatibility |
|--------|--------|---------|---------------|
| **Deadline** | `deadline(Duration)` | Infinite | Writer ≤ Reader |
| **Lifespan** | `lifespan(Duration)` | Infinite | Writer >= Reader |

## Lifecycle

| Policy | Values | Default | Compatibility |
|--------|--------|---------|---------------|
| **Liveliness** | `liveliness_automatic()`, `liveliness_manual_by_participant()`, `liveliness_manual_by_topic()` | Automatic | Writer >= Reader |

## Common Profiles

### Sensor Streaming (High Rate)

```rust
use hdds::QoS;

let qos = QoS::best_effort().keep_last(1).volatile();
```

### State Synchronization

```rust
use hdds::QoS;

let qos = QoS::reliable().keep_last(10).transient_local();
```

### Command Queue

```rust
use hdds::QoS;

let qos = QoS::reliable().keep_all();
```

### Event Log

```rust
use hdds::QoS;

let qos = QoS::reliable().keep_all().persistent();
```

## Full Example

```rust
use hdds::{Participant, QoS, TransportMode};

let participant = Participant::builder("example_app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

let topic = participant.topic::<SensorData>("sensors/data")?;

// Writer with reliable QoS
let writer = topic
    .writer()
    .qos(QoS::reliable().keep_last(100).transient_local())
    .build()?;

// Reader with reliable QoS
let reader = topic
    .reader()
    .qos(QoS::reliable().keep_last(50))
    .build()?;
```

## Compatibility Matrix

### Reliability

| Writer | Reader | Match |
|--------|--------|-------|
| reliable() | reliable() | ✅ |
| reliable() | best_effort() | ✅ |
| best_effort() | best_effort() | ✅ |
| best_effort() | reliable() | ❌ |

### Durability

| Writer | Reader | Match |
|--------|--------|-------|
| persistent() | Any | ✅ |
| transient_local() | transient_local()/volatile() | ✅ |
| transient_local() | persistent() | ❌ |
| volatile() | volatile() | ✅ |
| volatile() | transient_local()/persistent() | ❌ |

### Liveliness

| Writer | Reader | Match |
|--------|--------|-------|
| manual_by_topic | Any | ✅ |
| manual_by_participant | manual_by_participant/automatic | ✅ |
| manual_by_participant | manual_by_topic | ❌ |
| automatic | automatic | ✅ |
| automatic | manual_* | ❌ |

## Fluent Builder API

### Available Methods

| Method | Description |
|--------|-------------|
| `QoS::reliable()` | Guaranteed delivery with ACK/NACK |
| `QoS::best_effort()` | Fire and forget, lowest latency |
| `.keep_last(n)` | Keep last N samples per instance |
| `.keep_all()` | Keep all samples (bounded by ResourceLimits) |
| `.volatile()` | No persistence |
| `.transient_local()` | In-memory cache for late joiners |
| `.persistent()` | Disk persistence |
| `.deadline(Duration)` | Maximum time between samples |
| `.liveliness_automatic(Duration)` | DDS manages liveness assertions |
| `.liveliness_manual_by_participant(Duration)` | Application asserts per participant |
| `.liveliness_manual_by_topic(Duration)` | Application asserts per writer |

## See Also

- [Reliability](../guides/qos-policies/reliability.md)
- [Durability](../guides/qos-policies/durability.md)
- [History](../guides/qos-policies/history.md)
- [Deadline](../guides/qos-policies/deadline.md)
- [Liveliness](../guides/qos-policies/liveliness.md)
