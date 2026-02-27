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
| `automatic` | DDS infrastructure handles assertions | Implicit (network activity) |
| `manual_by_participant` | Application asserts per participant | Explicit call |
| `manual_by_topic` | Application asserts per writer | Explicit call |

## Automatic (Default)

DDS automatically asserts liveliness based on network activity.

```rust
use hdds::{Participant, QoS, TransportMode};
use std::time::Duration;

let participant = Participant::builder("sensor_app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

let writer = participant
    .topic::<SensorData>("sensors/temperature")?
    .writer()
    .qos(QoS::reliable().liveliness_automatic(Duration::from_secs(10)))
    .build()?;
```

**Behavior**:
- Any DDS activity (write, heartbeat) counts as assertion
- Simplest to use
- Lease duration defines "alive" timeout

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
    .qos(QoS::reliable().liveliness_manual_by_participant(Duration::from_secs(5)))
    .build()?;

// In application loop
loop {
    participant.assert_liveliness()?;
    std::thread::sleep(Duration::from_secs(1));
}
```

**Behavior**:
- Single assertion covers all writers in participant
- Useful for grouped health monitoring
- Application controls assertion timing

## Manual By Topic

Application explicitly asserts liveliness per writer.

```rust
use hdds::{Participant, QoS, TransportMode};
use std::time::Duration;

let participant = Participant::builder("writer_app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

let writer = participant
    .topic::<SensorData>("sensors/temperature")?
    .writer()
    .qos(QoS::reliable().liveliness_manual_by_topic(Duration::from_secs(5)))
    .build()?;

// In application loop
loop {
    writer.assert_liveliness()?;
    std::thread::sleep(Duration::from_secs(1));
}
```

**Behavior**:
- Fine-grained control per writer
- Detects individual writer failures
- Most overhead but most precise

## Lease Duration

The lease duration defines how long without assertion before considered "not alive":

```rust
use hdds::{Participant, QoS, TransportMode};
use std::time::Duration;

let participant = Participant::builder("liveliness_example")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// Writer must assert within 5 seconds
let writer = participant
    .topic::<StateData>("system/state")?
    .writer()
    .qos(QoS::reliable().liveliness_automatic(Duration::from_secs(5)))
    .build()?;

// Reader expects assertions within 10 seconds
let reader = participant
    .topic::<StateData>("system/state")?
    .reader()
    .qos(QoS::reliable().liveliness_automatic(Duration::from_secs(10)))
    .build()?;
```

## Compatibility Rules

Both kind and lease duration must be compatible:

### Kind Compatibility

| Writer | Reader | Match? |
|--------|--------|--------|
| manual_by_topic | manual_by_topic | ✅ Yes |
| manual_by_topic | manual_by_participant | ✅ Yes |
| manual_by_topic | automatic | ✅ Yes |
| manual_by_participant | manual_by_participant | ✅ Yes |
| manual_by_participant | automatic | ✅ Yes |
| manual_by_participant | manual_by_topic | ❌ No |
| automatic | automatic | ✅ Yes |
| automatic | manual_by_participant | ❌ No |
| automatic | manual_by_topic | ❌ No |

**Rule**: Writer kind must be >= Reader kind (more strict → less strict)

### Duration Compatibility

Writer lease must be ≤ Reader lease:

| Writer | Reader | Match? |
|--------|--------|--------|
| 5s | 10s | ✅ Yes |
| 5s | 5s | ✅ Yes |
| 10s | 5s | ❌ No |

**Rule**: `Writer.lease_duration ≤ Reader.lease_duration`

## Use Cases

### Heartbeat Monitoring

```rust
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
    .qos(QoS::reliable().liveliness_manual_by_topic(Duration::from_secs(3)))
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
use std::time::Duration;

let participant = Participant::builder("primary_service")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// Primary/secondary pattern
let writer = participant
    .topic::<State>("service/state")?
    .writer()
    .qos(QoS::reliable().liveliness_automatic(Duration::from_secs(5)))
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
    .qos(QoS::reliable().liveliness_manual_by_participant(Duration::from_secs(10)))
    .build()?;

// Health check thread
std::thread::spawn(move || {
    loop {
        if application_healthy() {
            participant.assert_liveliness().ok();
        }
        std::thread::sleep(Duration::from_secs(2));
    }
});
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
use std::time::Duration;

let participant = Participant::builder("comprehensive_monitoring")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

let writer = participant
    .topic::<SensorData>("sensors/temperature")?
    .writer()
    .qos(QoS::reliable()
        // Data must arrive every 100ms
        .deadline(Duration::from_millis(100))
        // Writer must be alive (even if not publishing)
        .liveliness_automatic(Duration::from_secs(10)))
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
- Lease checking: ~1 μs per check

## Next Steps

- [Deadline](../../guides/qos-policies/deadline.md) - Data update requirements
- [Overview](../../guides/qos-policies/overview.md) - All QoS policies
