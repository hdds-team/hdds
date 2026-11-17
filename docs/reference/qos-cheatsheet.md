# QoS Cheatsheet

Quick reference for HDDS QoS policies and the fluent builder API.

## Data Distribution

| Policy | Values | Default | Compatibility |
|--------|--------|---------|---------------|
| **Reliability** | `best_effort()`, `reliable()` | best_effort | Writer >= Reader |
| **History** | `keep_last(N)`, `keep_all()` | keep_last(100) | N/A |
| **Durability** | `volatile()`, `transient_local()`, `persistent()` | volatile | Writer >= Reader |
| **ResourceLimits** | max_samples, max_instances, max_quota_bytes | Unlimited | N/A |

## Timing

| Policy | Values | Default | Compatibility |
|--------|--------|---------|---------------|
| **Deadline** | `deadline_millis(N)`, `deadline_secs(N)` | Infinite | Writer <= Reader |
| **Lifespan** | `lifespan_millis(N)`, `lifespan_secs(N)` | Infinite | N/A |

## Lifecycle

| Policy | Values | Default | Compatibility |
|--------|--------|---------|---------------|
| **Liveliness** | `liveliness_automatic_secs(N)`, `liveliness_manual_participant_secs(N)`, `liveliness(Liveliness::manual_by_topic(d))` | Automatic | Writer >= Reader |

## Reliability and Resource Limits

A RELIABLE reader acknowledges a sample once the RTPS layer receives it
(the per-writer proxy registry and the control-plane ACKNACK track receipt,
RTPS v2.5 Sec.8.4.9) -- not once the application reads it. If the reader's
own ring or slab-pool allocation is full at that moment, the sample is
REJECTED after being received: the writer is never NACKed for it and never
retransmits it, because it was already acknowledged. This is reported
through `SampleRejectedStatus` / `DataReaderListener::on_sample_rejected`
(reason `ResourceLimit`) and the `samples_rejected_ring_full` /
`samples_rejected_slab_exhausted` telemetry counters -- never through
`SampleLostStatus`, which is reserved for a real wire gap or writer-side
history eviction.

To avoid resource rejection: size `History` depth for the expected burst,
and drain promptly with a `WaitSet` or a listener. A resource-limit drop is
final: the writer is not asked to resend it.

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
| reliable() | reliable() | Yes |
| reliable() | best_effort() | Yes |
| best_effort() | best_effort() | Yes |
| best_effort() | reliable() | No |

### Durability

| Writer | Reader | Match |
|--------|--------|-------|
| persistent() | Any | Yes |
| transient_local() | transient_local()/volatile() | Yes |
| transient_local() | persistent() | No |
| volatile() | volatile() | Yes |
| volatile() | transient_local()/persistent() | No |

### Liveliness

| Writer | Reader | Match |
|--------|--------|-------|
| manual_by_topic | Any | Yes |
| manual_by_participant | manual_by_participant/automatic | Yes |
| manual_by_participant | manual_by_topic | No |
| automatic | automatic | Yes |
| automatic | manual_* | No |

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
| `.persistent()` | Persistent durability kind |
| `.deadline_millis(N)`, `.deadline_secs(N)` | Maximum time between samples |
| `.lifespan_millis(N)`, `.lifespan_secs(N)` | Sample expiration time |
| `.liveliness_automatic_secs(N)`, `.liveliness_automatic_millis(N)` | DDS manages liveness assertions |
| `.liveliness_manual_participant_secs(N)`, `.liveliness_manual_participant_millis(N)` | Application asserts per participant |
| `.liveliness(Liveliness::manual_by_topic(d))` | Application asserts per writer (`hdds::dds::Liveliness`) |

## See Also

- [Reliability](../guides/qos-policies/reliability.md)
- [Durability](../guides/qos-policies/durability.md)
- [History](../guides/qos-policies/history.md)
- [Deadline](../guides/qos-policies/deadline.md)
- [Liveliness](../guides/qos-policies/liveliness.md)
