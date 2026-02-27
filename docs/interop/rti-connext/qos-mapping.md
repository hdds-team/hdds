# RTI Connext QoS Mapping

Detailed QoS policy mapping between HDDS and RTI Connext DDS.

## Reliability

### HDDS

```rust
use hdds::QoS;

// Best Effort
let qos = QoS::best_effort();

// Reliable
let qos = QoS::reliable();
```

### RTI Connext (C++ API)

```cpp
// Best Effort
DDS_DataWriterQos wqos;
wqos.reliability.kind = DDS_BEST_EFFORT_RELIABILITY_QOS;

// Reliable
DDS_DataWriterQos wqos;
wqos.reliability.kind = DDS_RELIABLE_RELIABILITY_QOS;
wqos.reliability.max_blocking_time.sec = 0;
wqos.reliability.max_blocking_time.nanosec = 100000000; // 100ms
```

### RTI Connext (XML)

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

### RTI Connext (C++ API)

```cpp
DDS_DataWriterQos wqos;
wqos.durability.kind = DDS_TRANSIENT_LOCAL_DURABILITY_QOS;
```

### RTI Connext (XML)

```xml
<durability>
    <kind>TRANSIENT_LOCAL_DURABILITY_QOS</kind>
</durability>
```

### Mapping Table

| HDDS | RTI Connext C++ | RTI Connext XML |
|------|-----------------|-----------------|
| `volatile()` | `DDS_VOLATILE_DURABILITY_QOS` | `VOLATILE_DURABILITY_QOS` |
| `transient_local()` | `DDS_TRANSIENT_LOCAL_DURABILITY_QOS` | `TRANSIENT_LOCAL_DURABILITY_QOS` |
| `transient()` | `DDS_TRANSIENT_DURABILITY_QOS` | `TRANSIENT_DURABILITY_QOS` |
| `persistent()` | `DDS_PERSISTENT_DURABILITY_QOS` | `PERSISTENT_DURABILITY_QOS` |

## History

### HDDS

```rust
use hdds::QoS;

// Keep Last
let qos = QoS::reliable().keep_last(10);

// Keep All
let qos = QoS::reliable().keep_all();
```

### RTI Connext (C++ API)

```cpp
// Keep Last
DDS_DataWriterQos wqos;
wqos.history.kind = DDS_KEEP_LAST_HISTORY_QOS;
wqos.history.depth = 10;

// Keep All
DDS_DataWriterQos wqos;
wqos.history.kind = DDS_KEEP_ALL_HISTORY_QOS;
```

### RTI Connext (XML)

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

### RTI Connext (C++ API)

```cpp
DDS_DataWriterQos wqos;
wqos.deadline.period.sec = 0;
wqos.deadline.period.nanosec = 100000000;
```

### RTI Connext (XML)

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

### RTI Connext (C++ API)

```cpp
DDS_DataWriterQos wqos;
wqos.liveliness.kind = DDS_MANUAL_BY_TOPIC_LIVELINESS_QOS;
wqos.liveliness.lease_duration.sec = 1;
wqos.liveliness.lease_duration.nanosec = 0;
```

### RTI Connext (XML)

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

| HDDS | RTI Connext C++ | RTI Connext XML |
|------|-----------------|-----------------|
| `liveliness_automatic()` | `DDS_AUTOMATIC_LIVELINESS_QOS` | `AUTOMATIC_LIVELINESS_QOS` |
| `liveliness_manual_by_participant()` | `DDS_MANUAL_BY_PARTICIPANT_LIVELINESS_QOS` | `MANUAL_BY_PARTICIPANT_LIVELINESS_QOS` |
| `liveliness_manual_by_topic()` | `DDS_MANUAL_BY_TOPIC_LIVELINESS_QOS` | `MANUAL_BY_TOPIC_LIVELINESS_QOS` |

## Ownership

### HDDS

```rust
use hdds::QoS;

let qos = QoS::reliable().ownership_exclusive(100);
```

### RTI Connext (C++ API)

```cpp
DDS_DataWriterQos wqos;
wqos.ownership.kind = DDS_EXCLUSIVE_OWNERSHIP_QOS;
wqos.ownership_strength.value = 100;
```

### RTI Connext (XML)

```xml
<ownership>
    <kind>EXCLUSIVE_OWNERSHIP_QOS</kind>
</ownership>
<ownership_strength>
    <value>100</value>
</ownership_strength>
```

## Resource Limits

### HDDS

```rust
use hdds::QoS;

let qos = QoS::reliable()
    .max_samples(1000)
    .max_instances(100)
    .max_samples_per_instance(10);
```

### RTI Connext (C++ API)

```cpp
DDS_DataReaderQos rqos;
rqos.resource_limits.max_samples = 1000;
rqos.resource_limits.max_instances = 100;
rqos.resource_limits.max_samples_per_instance = 10;
```

### RTI Connext (XML)

```xml
<resource_limits>
    <max_samples>1000</max_samples>
    <max_instances>100</max_instances>
    <max_samples_per_instance>10</max_samples_per_instance>
</resource_limits>
```

## Partition

### HDDS

```rust
use hdds::QoS;

let qos = QoS::reliable().partition(&["sensors", "telemetry"]);
```

### RTI Connext (C++ API)

```cpp
DDS_PublisherQos pqos;
pqos.partition.name.ensure_length(2, 2);
pqos.partition.name[0] = DDS_String_dup("sensors");
pqos.partition.name[1] = DDS_String_dup("telemetry");
```

### RTI Connext (XML)

```xml
<partition>
    <name>
        <element>sensors</element>
        <element>telemetry</element>
    </name>
</partition>
```

## Time-Based Filter

### HDDS

```rust
use hdds::QoS;
use std::time::Duration;

let qos = QoS::reliable().time_based_filter(Duration::from_millis(100));
```

### RTI Connext (C++ API)

```cpp
DDS_DataReaderQos rqos;
rqos.time_based_filter.minimum_separation.sec = 0;
rqos.time_based_filter.minimum_separation.nanosec = 100000000;
```

### RTI Connext (XML)

```xml
<time_based_filter>
    <minimum_separation>
        <sec>0</sec>
        <nanosec>100000000</nanosec>
    </minimum_separation>
</time_based_filter>
```

## Content Filter (RTI Extension)

RTI Connext supports content-filtered topics with SQL-like expressions:

### RTI Connext

```cpp
DDS_ContentFilteredTopic* cft = participant->create_contentfilteredtopic(
    "FilteredSensor",
    topic,
    "sensor_id = 1 AND value > 25.0",
    DDS_StringSeq());
```

### HDDS Equivalent

```rust
let topic = participant.topic::<SensorData>("SensorTopic")?;
let cft = topic.content_filter(
    "FilteredSensor",
    "sensor_id = %0 AND value > %1",
    &["1", "25.0"],
)?;
```

## Batching (RTI Extension)

### RTI Connext

```cpp
DDS_DataWriterQos wqos;
wqos.batch.enable = DDS_BOOLEAN_TRUE;
wqos.batch.max_data_bytes = 65536;
wqos.batch.max_flush_delay.sec = 0;
wqos.batch.max_flush_delay.nanosec = 1000000; // 1ms
```

### HDDS Equivalent

```rust
use hdds::QoS;
use std::time::Duration;

let qos = QoS::reliable()
    .batching(true)
    .max_batch_size(65536)
    .batch_flush_period(Duration::from_millis(1));
```

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

### RTI Connext Writer QoS (C++)

```cpp
DDS_DataWriterQos wqos;
DDSTheParticipantFactory->get_default_datawriter_qos(wqos);

// Reliability
wqos.reliability.kind = DDS_RELIABLE_RELIABILITY_QOS;
wqos.reliability.max_blocking_time.sec = 0;
wqos.reliability.max_blocking_time.nanosec = 100000000;

// Durability
wqos.durability.kind = DDS_TRANSIENT_LOCAL_DURABILITY_QOS;

// History
wqos.history.kind = DDS_KEEP_LAST_HISTORY_QOS;
wqos.history.depth = 10;

// Deadline
wqos.deadline.period.sec = 0;
wqos.deadline.period.nanosec = 200000000;

// Liveliness
wqos.liveliness.kind = DDS_AUTOMATIC_LIVELINESS_QOS;
wqos.liveliness.lease_duration.sec = 5;
wqos.liveliness.lease_duration.nanosec = 0;

DDSDataWriter* writer = publisher->create_datawriter(topic, wqos, NULL, DDS_STATUS_MASK_NONE);
```

### RTI Connext Writer QoS (XML Profile)

```xml
<?xml version="1.0"?>
<dds xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     xsi:noNamespaceSchemaLocation="http://community.rti.com/schema/current/rti_dds_qos_profiles.xsd">
    <qos_library name="SensorLibrary">
        <qos_profile name="SensorProfile">
            <datawriter_qos>
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
            </datawriter_qos>
        </qos_profile>
    </qos_library>
</dds>
```

## Duration Format

RTI Connext uses DDS_Duration_t structure:

| HDDS | RTI Connext |
|------|-------------|
| `Duration::from_secs(5)` | `{.sec = 5, .nanosec = 0}` |
| `Duration::from_millis(100)` | `{.sec = 0, .nanosec = 100000000}` |
| `Duration::from_micros(500)` | `{.sec = 0, .nanosec = 500000}` |
| `Duration::MAX` | `DDS_DURATION_INFINITE` |
| `Duration::ZERO` | `DDS_DURATION_ZERO` |

## RTI-Specific Extensions

These RTI Connext QoS policies have no direct HDDS equivalent:

| RTI Connext Policy | Description |
|--------------------|-------------|
| `entity_factory` | Control entity creation |
| `wire_protocol` | RTPS wire protocol settings |
| `reader_data_lifecycle` | Sample lifecycle management |
| `writer_data_lifecycle` | Instance lifecycle management |
| `type_consistency` | XTypes type matching settings |

## Compatibility Notes

1. **XTypes**: RTI Connext has full XTypes support; use compatible type annotations
2. **Builtin types**: RTI uses different namespaces for builtin types
3. **Wire format**: Standard RTPS 2.4; compatible at protocol level
4. **License**: RTI Connext requires a commercial license

## Next Steps

- [Setup](../../interop/rti-connext/setup.md) - Installation and configuration
- [Example](../../interop/rti-connext/example.md) - Complete interop example
- [QoS Translation Matrix](../../interop/qos-translation-matrix.md) - All vendors
