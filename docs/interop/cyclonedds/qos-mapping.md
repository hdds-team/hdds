# CycloneDDS QoS Mapping

Detailed QoS policy mapping between HDDS and CycloneDDS.

## Reliability

### HDDS

```rust
use hdds::QoS;

// Best Effort
let qos = QoS::best_effort();

// Reliable
let qos = QoS::reliable();
```

### CycloneDDS (C API)

```c
// Best Effort
dds_qset_reliability(qos, DDS_RELIABILITY_BEST_EFFORT, 0);

// Reliable
dds_qset_reliability(qos, DDS_RELIABILITY_RELIABLE, DDS_MSECS(100));
```

### CycloneDDS (XML)

```xml
<Reliability>
    <Kind>reliable</Kind>
    <MaxBlockingTime>100ms</MaxBlockingTime>
</Reliability>
```

## Durability

### HDDS

```rust
use hdds::QoS;

let qos = QoS::reliable().transient_local();
```

### CycloneDDS (C API)

```c
dds_qset_durability(qos, DDS_DURABILITY_TRANSIENT_LOCAL);
```

### CycloneDDS (XML)

```xml
<Durability><Kind>transient_local</Kind></Durability>
```

### Mapping Table

| HDDS | CycloneDDS C | CycloneDDS XML |
|------|--------------|----------------|
| `volatile()` | `DDS_DURABILITY_VOLATILE` | `volatile` |
| `transient_local()` | `DDS_DURABILITY_TRANSIENT_LOCAL` | `transient_local` |
| `persistent()` | `DDS_DURABILITY_PERSISTENT` | `persistent` |

## History

### HDDS

```rust
use hdds::QoS;

// Keep Last
let qos = QoS::reliable().keep_last(10);

// Keep All
let qos = QoS::reliable().keep_all();
```

### CycloneDDS (C API)

```c
// Keep Last
dds_qset_history(qos, DDS_HISTORY_KEEP_LAST, 10);

// Keep All
dds_qset_history(qos, DDS_HISTORY_KEEP_ALL, DDS_LENGTH_UNLIMITED);
```

### CycloneDDS (XML)

```xml
<History>
    <Kind>keep_last</Kind>
    <Depth>10</Depth>
</History>
```

## Deadline

### HDDS

```rust
use hdds::QoS;
use std::time::Duration;

let qos = QoS::reliable().deadline(Duration::from_millis(100));
```

### CycloneDDS (C API)

```c
dds_qset_deadline(qos, DDS_MSECS(100));
```

### CycloneDDS (XML)

```xml
<Deadline>100ms</Deadline>
```

## Liveliness

### HDDS

```rust
use hdds::QoS;
use std::time::Duration;

let qos = QoS::reliable().liveliness_manual_by_topic(Duration::from_secs(1));
```

### CycloneDDS (C API)

```c
dds_qset_liveliness(qos, DDS_LIVELINESS_MANUAL_BY_TOPIC, DDS_SECS(1));
```

### CycloneDDS (XML)

```xml
<Liveliness>
    <Kind>manual_by_topic</Kind>
    <LeaseDuration>1s</LeaseDuration>
</Liveliness>
```

### Mapping Table

| HDDS | CycloneDDS C | CycloneDDS XML |
|------|--------------|----------------|
| `liveliness_automatic()` | `DDS_LIVELINESS_AUTOMATIC` | `automatic` |
| `liveliness_manual_by_participant()` | `DDS_LIVELINESS_MANUAL_BY_PARTICIPANT` | `manual_by_participant` |
| `liveliness_manual_by_topic()` | `DDS_LIVELINESS_MANUAL_BY_TOPIC` | `manual_by_topic` |

## Complete QoS Example

### HDDS Writer QoS

```rust
use hdds::{Participant, QoS, TransportMode};
use std::time::Duration;

let participant = Participant::builder("example")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

let topic = participant.topic::<SensorData>("SensorTopic")?;

let writer = topic
    .writer()
    .qos(QoS::reliable()
        .keep_last(10)
        .transient_local()
        .deadline(Duration::from_millis(200))
        .liveliness_automatic(Duration::from_secs(5)))
    .build()?;
```

### CycloneDDS Writer QoS (C)

```c
dds_qos_t *qos = dds_create_qos();
dds_qset_reliability(qos, DDS_RELIABILITY_RELIABLE, DDS_MSECS(100));
dds_qset_durability(qos, DDS_DURABILITY_TRANSIENT_LOCAL);
dds_qset_history(qos, DDS_HISTORY_KEEP_LAST, 10);
dds_qset_deadline(qos, DDS_MSECS(200));
dds_qset_liveliness(qos, DDS_LIVELINESS_AUTOMATIC, DDS_SECS(5));

dds_entity_t writer = dds_create_writer(participant, topic, qos, NULL);
dds_delete_qos(qos);
```

### CycloneDDS Writer QoS (XML)

```xml
<DataWriter name="SensorWriter">
    <Reliability>
        <Kind>reliable</Kind>
        <MaxBlockingTime>100ms</MaxBlockingTime>
    </Reliability>
    <Durability><Kind>transient_local</Kind></Durability>
    <History><Kind>keep_last</Kind><Depth>10</Depth></History>
    <Deadline>200ms</Deadline>
    <Liveliness>
        <Kind>automatic</Kind>
        <LeaseDuration>5s</LeaseDuration>
    </Liveliness>
</DataWriter>
```

## Compatibility Notes

1. **Default differences**: Both default to BestEffort, Volatile, KeepLast(1)
2. **Duration format**: HDDS uses Rust `Duration`, CycloneDDS uses nanoseconds or string format
3. **XTypes**: CycloneDDS has partial XTypes support; use `@appendable` for safety

## Next Steps

- [Setup](../../interop/cyclonedds/setup.md) - Installation and configuration
- [Example](../../interop/cyclonedds/example.md) - Complete interop example
- [QoS Translation Matrix](../../interop/qos-translation-matrix.md) - All vendors
