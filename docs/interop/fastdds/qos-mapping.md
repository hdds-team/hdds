# FastDDS QoS Mapping

Detailed QoS policy mapping between HDDS and FastDDS (eProsima Fast DDS).

## Reliability

### HDDS

```rust
use hdds::QoS;

// Best Effort
let qos = QoS::best_effort();

// Reliable
let qos = QoS::reliable();
```

### FastDDS (C++ API)

```cpp
// Best Effort
DataWriterQos wqos;
wqos.reliability().kind = BEST_EFFORT_RELIABILITY_QOS;

// Reliable
DataWriterQos wqos;
wqos.reliability().kind = RELIABLE_RELIABILITY_QOS;
wqos.reliability().max_blocking_time = {0, 100000000}; // 100ms
```

### FastDDS (XML)

```xml
<reliability>
    <kind>RELIABLE_RELIABILITY_QOS</kind>
    <max_blocking_time>
        <sec>0</sec>
        <nanosec>100000000</nanosec>
    </max_blocking_time>
</reliability>
```

## Durability

### HDDS

```rust
use hdds::QoS;

let qos = QoS::reliable().transient_local();
```

### FastDDS (C++ API)

```cpp
DataWriterQos wqos;
wqos.durability().kind = TRANSIENT_LOCAL_DURABILITY_QOS;
```

### FastDDS (XML)

```xml
<durability>
    <kind>TRANSIENT_LOCAL_DURABILITY_QOS</kind>
</durability>
```

### Mapping Table

| HDDS | FastDDS C++ | FastDDS XML |
|------|-------------|-------------|
| `volatile()` | `VOLATILE_DURABILITY_QOS` | `VOLATILE_DURABILITY_QOS` |
| `transient_local()` | `TRANSIENT_LOCAL_DURABILITY_QOS` | `TRANSIENT_LOCAL_DURABILITY_QOS` |
| `persistent()` | `PERSISTENT_DURABILITY_QOS` | `PERSISTENT_DURABILITY_QOS` |

## History

### HDDS

```rust
use hdds::QoS;

// Keep Last
let qos = QoS::reliable().keep_last(10);

// Keep All
let qos = QoS::reliable().keep_all();
```

### FastDDS (C++ API)

```cpp
// Keep Last
DataWriterQos wqos;
wqos.history().kind = KEEP_LAST_HISTORY_QOS;
wqos.history().depth = 10;

// Keep All
DataWriterQos wqos;
wqos.history().kind = KEEP_ALL_HISTORY_QOS;
```

### FastDDS (XML)

```xml
<history>
    <kind>KEEP_LAST_HISTORY_QOS</kind>
    <depth>10</depth>
</history>
```

## Deadline

### HDDS

```rust
use hdds::QoS;
use std::time::Duration;

let qos = QoS::reliable().deadline(Duration::from_millis(100));
```

### FastDDS (C++ API)

```cpp
DataWriterQos wqos;
wqos.deadline().period = {0, 100000000}; // 100ms
```

### FastDDS (XML)

```xml
<deadline>
    <period>
        <sec>0</sec>
        <nanosec>100000000</nanosec>
    </period>
</deadline>
```

## Liveliness

### HDDS

```rust
use hdds::QoS;
use std::time::Duration;

let qos = QoS::reliable().liveliness_manual_by_topic(Duration::from_secs(1));
```

### FastDDS (C++ API)

```cpp
DataWriterQos wqos;
wqos.liveliness().kind = MANUAL_BY_TOPIC_LIVELINESS_QOS;
wqos.liveliness().lease_duration = {1, 0}; // 1 second
```

### FastDDS (XML)

```xml
<liveliness>
    <kind>MANUAL_BY_TOPIC_LIVELINESS_QOS</kind>
    <lease_duration>
        <sec>1</sec>
        <nanosec>0</nanosec>
    </lease_duration>
</liveliness>
```

### Mapping Table

| HDDS | FastDDS C++ | FastDDS XML |
|------|-------------|-------------|
| `liveliness_automatic()` | `AUTOMATIC_LIVELINESS_QOS` | `AUTOMATIC_LIVELINESS_QOS` |
| `liveliness_manual_by_participant()` | `MANUAL_BY_PARTICIPANT_LIVELINESS_QOS` | `MANUAL_BY_PARTICIPANT_LIVELINESS_QOS` |
| `liveliness_manual_by_topic()` | `MANUAL_BY_TOPIC_LIVELINESS_QOS` | `MANUAL_BY_TOPIC_LIVELINESS_QOS` |

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

### FastDDS Writer QoS (C++)

```cpp
DataWriterQos wqos;

// Reliability
wqos.reliability().kind = RELIABLE_RELIABILITY_QOS;
wqos.reliability().max_blocking_time = {0, 100000000};

// Durability
wqos.durability().kind = TRANSIENT_LOCAL_DURABILITY_QOS;

// History
wqos.history().kind = KEEP_LAST_HISTORY_QOS;
wqos.history().depth = 10;

// Deadline
wqos.deadline().period = {0, 200000000};

// Liveliness
wqos.liveliness().kind = AUTOMATIC_LIVELINESS_QOS;
wqos.liveliness().lease_duration = {5, 0};

DataWriter* writer = publisher->create_datawriter(topic, wqos);
```

### FastDDS Writer QoS (XML Profile)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<profiles xmlns="http://www.eprosima.com/XMLSchemas/fastRTPS_Profiles">
    <data_writer profile_name="SensorWriter">
        <qos>
            <reliability>
                <kind>RELIABLE_RELIABILITY_QOS</kind>
                <max_blocking_time>
                    <sec>0</sec>
                    <nanosec>100000000</nanosec>
                </max_blocking_time>
            </reliability>
            <durability>
                <kind>TRANSIENT_LOCAL_DURABILITY_QOS</kind>
            </durability>
            <history>
                <kind>KEEP_LAST_HISTORY_QOS</kind>
                <depth>10</depth>
            </history>
            <deadline>
                <period>
                    <sec>0</sec>
                    <nanosec>200000000</nanosec>
                </period>
            </deadline>
            <liveliness>
                <kind>AUTOMATIC_LIVELINESS_QOS</kind>
                <lease_duration>
                    <sec>5</sec>
                    <nanosec>0</nanosec>
                </lease_duration>
            </liveliness>
        </qos>
    </data_writer>
</profiles>
```

## Duration Format

FastDDS uses a two-part structure for durations:

| HDDS | FastDDS |
|------|---------|
| `Duration::from_secs(5)` | `{5, 0}` (sec, nanosec) |
| `Duration::from_millis(100)` | `{0, 100000000}` |
| `Duration::from_micros(500)` | `{0, 500000}` |
| `Duration::MAX` | `{0x7FFFFFFF, 0xFFFFFFFF}` (INFINITE) |

## Compatibility Notes

1. **XTypes**: FastDDS supports XTypes; use `@appendable` for type evolution compatibility
2. **Transport**: Disable FastDDS data sharing for cross-vendor interop
3. **Discovery**: Both use standard SPDP/SEDP; ports must align

## Next Steps

- [Setup](../../interop/fastdds/setup.md) - Installation and configuration
- [Example](../../interop/fastdds/example.md) - Complete interop example
- [QoS Translation Matrix](../../interop/qos-translation-matrix.md) - All vendors
