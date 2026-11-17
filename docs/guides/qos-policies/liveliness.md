# Liveliness QoS Policy

The Liveliness policy detects when writers become unavailable.

## Purpose

Liveliness monitors writer health:
- **Writers** assert their liveliness periodically
- **Readers** detect when writers stop responding
- **Enables** failure detection and recovery

## Kinds

| Kind | Description | Assertion Method |
|------|-------------|------------------|
| `automatic` | DDS infrastructure handles assertions | Implicit (the participant asserts for its writers) |
| `manual_by_participant` | Application asserts per participant | `write()`, `dispose()`, `unregister_instance()` or an explicit call |
| `manual_by_topic` | Application asserts per writer | `write()`, `dispose()`, `unregister_instance()` or an explicit call |

The default (`QoS::default()`, `QoS::reliable()`) is `automatic` with an infinite lease, which means no liveliness tracking. A finite lease is set with `liveliness_automatic_secs()` / `liveliness_automatic_millis()`, `liveliness_manual_participant_secs()` / `liveliness_manual_participant_millis()`, or `liveliness(Liveliness::manual_topic_secs(n))` (also `manual_topic_millis`).
## Automatic (Default)

The participant asserts liveliness on behalf of every `automatic` writer it owns, for as long as the writer exists. The application has nothing to call.

```rust
use hdds::{Participant, QoS, TransportMode};

let participant = Participant::builder("sensor_app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

let writer = participant
    .topic::<SensorData>("sensors/temperature")?
    .writer()
    .qos(QoS::reliable().liveliness_automatic_secs(10))
    .build()?;
```

**Behavior**:
- The writer is considered alive while its participant is running
- Simplest to use
- Lease duration defines the "alive" timeout readers apply

## Manual By Participant

Application explicitly asserts liveliness for all writers in a participant.

```rust
use hdds::{Participant, QoS, TransportMode};
use std::time::Duration;

let participant = Participant::builder("heartbeat_app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

let writer = participant
    .topic::<Heartbeat>("system/heartbeat")?
    .writer()
    .qos(QoS::reliable().liveliness_manual_participant_secs(5))
    .build()?;

// In application loop
loop {
    participant.assert_liveliness();
    std::thread::sleep(Duration::from_secs(1));
}
```

**Behavior**:
- `participant.assert_liveliness()` renews the lease of every `manual_by_participant` writer of that participant
- A `write()`, `dispose()` or `unregister_instance()` on a writer also asserts it
- Useful for grouped health monitoring
- Application controls assertion timing

## Manual By Topic

Application explicitly asserts liveliness per writer.

```rust
use hdds::dds::Liveliness;
use hdds::{Participant, QoS, TransportMode};
use std::time::Duration;

let participant = Participant::builder("writer_app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

let writer = participant
    .topic::<SensorData>("sensors/temperature")?
    .writer()
    .qos(QoS::reliable().liveliness(Liveliness::manual_topic_secs(5)))
    .build()?;

// In application loop
loop {
    writer.assert_liveliness()?;
    std::thread::sleep(Duration::from_secs(1));
}
```

**Behavior**:
- `writer.assert_liveliness()` renews only that writer's lease, without writing a sample; a liveliness HEARTBEAT is sent to every matched reader
- A `write()`, `dispose()` or `unregister_instance()` on the writer also asserts it
- Fine-grained control per writer
- Detects individual writer failures

## Lease Duration

The lease duration defines how long without assertion before considered "not alive":

```rust
use hdds::{Participant, QoS, TransportMode};

let participant = Participant::builder("liveliness_example")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// Writer must assert within 5 seconds
let writer = participant
    .topic::<StateData>("system/state")?
    .writer()
    .qos(QoS::reliable().liveliness_automatic_secs(5))
    .build()?;

// Reader expects assertions within 10 seconds
let reader = participant
    .topic::<StateData>("system/state")?
    .reader()
    .qos(QoS::reliable().liveliness_automatic_secs(10))
    .build()?;
```

## Compatibility Rules

Both kind and lease duration must be compatible:

### Kind Compatibility

| Writer | Reader | Match? |
|--------|--------|--------|
| manual_by_topic | manual_by_topic | Yes |
| manual_by_topic | manual_by_participant | Yes |
| manual_by_topic | automatic | Yes |
| manual_by_participant | manual_by_participant | Yes |
| manual_by_participant | automatic | Yes |
| manual_by_participant | manual_by_topic | No |
| automatic | automatic | Yes |
| automatic | manual_by_participant | No |
| automatic | manual_by_topic | No |

**Rule**: Writer kind must be >= Reader kind (more strict -> less strict)

### Duration Compatibility

Writer lease must be <= Reader lease:

| Writer | Reader | Match? |
|--------|--------|--------|
| 5s | 10s | Yes |
| 5s | 5s | Yes |
| 10s | 5s | No |

**Rule**: `Writer.lease_duration <= Reader.lease_duration`

## Use Cases

### Heartbeat Monitoring

```rust
use hdds::dds::Liveliness;
use hdds::{Participant, QoS, TransportMode};
use std::time::Duration;

let participant = Participant::builder("heartbeat_system")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// Simple heartbeat for node health
let writer = participant
    .topic::<Heartbeat>("system/heartbeat")?
    .writer()
    .qos(QoS::reliable().liveliness(Liveliness::manual_topic_secs(3)))
    .build()?;

// Writer loop
loop {
    writer.write(&heartbeat)?;  // Implicitly asserts liveliness
    std::thread::sleep(Duration::from_secs(1));
}
```

### Failover Detection

```rust
use hdds::{Participant, QoS, TransportMode};

let participant = Participant::builder("primary_service")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// Primary/secondary pattern
let writer = participant
    .topic::<State>("service/state")?
    .writer()
    .qos(QoS::reliable().liveliness_automatic_secs(5))
    .build()?;
```

### Application Health Check

```rust
use hdds::{Participant, QoS, TransportMode};
use std::time::Duration;

let participant = Participant::builder("health_monitored_app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// Application-level health monitoring
let writer = participant
    .topic::<StatusData>("app/status")?
    .writer()
    .qos(QoS::reliable().liveliness_manual_participant_secs(10))
    .build()?;

// Health check thread
std::thread::spawn(move || {
    loop {
        if application_healthy() {
            participant.assert_liveliness();
        }
        std::thread::sleep(Duration::from_secs(2));
    }
});
```

## Observing Liveliness

On the reader side, `get_liveliness_changed_status()` reports how many matched writers are currently alive and how many are not; on the writer side, `get_liveliness_lost_status()` counts the times a `manual_by_participant` or `manual_by_topic` writer failed to assert within its lease. Both are read-and-reset. The same events reach `on_liveliness_changed` (`DataReaderListener`) and `on_liveliness_lost` (`DataWriterListener`).

```rust
let status = reader.get_liveliness_changed_status();
println!("alive: {}, not alive: {}", status.alive_count, status.not_alive_count);

let lost = writer.get_liveliness_lost_status();
println!("liveliness lost {} times", lost.total_count);
```

## Comparison: Liveliness vs Deadline

| Aspect | Liveliness | Deadline |
|--------|------------|----------|
| Monitors | Writer existence | Data updates |
| Granularity | Per writer or participant | Per instance |
| Trigger | No assertion | No data received |
| Use case | Failure detection | Data freshness |

Use both for comprehensive monitoring:

```rust
use hdds::{Participant, QoS, TransportMode};

let participant = Participant::builder("comprehensive_monitoring")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

let writer = participant
    .topic::<SensorData>("sensors/temperature")?
    .writer()
    .qos(QoS::reliable()
        // Data must arrive every 100ms
        .deadline_millis(100)
        // Writer must be alive (even if not publishing)
        .liveliness_automatic_secs(10))
    .build()?;
```

## Best Practices

1. **Set reader lease >= writer lease** with margin for network delays
2. **Use manual_by_topic** for critical per-writer monitoring
3. **Use automatic** when simplicity is preferred
4. **Assert faster than lease** (e.g., assert every 1s for 5s lease)

```rust
// Good practice: Assert at 1/3 to 1/5 of lease duration
let lease = Duration::from_secs(5);
let assert_period = lease / 3;  // ~1.67s
```

## Performance Notes

- Automatic: No application overhead
- ManualByParticipant: Single assertion, minimal overhead
- ManualByTopic: One assertion per writer, scales with writer count
- Lease checking cost depends on participant and writer count, timer cadence,
  build, and machine; no reference-grade cost is currently published.

## Next Steps

- [Deadline](../../guides/qos-policies/deadline.md) - Data update requirements
- [Overview](../../guides/qos-policies/overview.md) - All QoS policies
