# QoS Translation Matrix

Reference for translating QoS policies between HDDS and other DDS implementations.

## Reliability

| HDDS | FastDDS | CycloneDDS | RTI Connext |
|------|---------|------------|-------------|
| `QoS::best_effort()` | `BEST_EFFORT_RELIABILITY_QOS` | `DDS_RELIABILITY_BEST_EFFORT` | `DDS_BEST_EFFORT_RELIABILITY_QOS` |
| `QoS::reliable()` | `RELIABLE_RELIABILITY_QOS` | `DDS_RELIABILITY_RELIABLE` | `DDS_RELIABLE_RELIABILITY_QOS` |

### Configuration Examples

**HDDS:**
```rust
use hdds::QoS;

let qos = QoS::reliable();
```

**FastDDS (XML):**
```xml
<reliability>
    <kind>RELIABLE_RELIABILITY_QOS</kind>
    <max_blocking_time><sec>0</sec><nanosec>100000000</nanosec></max_blocking_time>
</reliability>
```

**CycloneDDS (XML):**
```xml
<Reliability><Kind>reliable</Kind><MaxBlockingTime>100ms</MaxBlockingTime></Reliability>
```

**RTI Connext:**
```xml
<reliability><kind>RELIABLE_RELIABILITY_QOS</kind>
    <max_blocking_time><sec>0</sec><nanosec>100000000</nanosec></max_blocking_time>
</reliability>
```

## Durability

| HDDS | FastDDS | CycloneDDS | RTI Connext |
|------|---------|------------|-------------|
| `volatile()` | `VOLATILE_DURABILITY_QOS` | `volatile` | `DDS_VOLATILE_DURABILITY_QOS` |
| `transient_local()` | `TRANSIENT_LOCAL_DURABILITY_QOS` | `transient_local` | `DDS_TRANSIENT_LOCAL_DURABILITY_QOS` |
| `transient()` | `TRANSIENT_DURABILITY_QOS` | `transient` | `DDS_TRANSIENT_DURABILITY_QOS` |
| `persistent()` | `PERSISTENT_DURABILITY_QOS` | `persistent` | `DDS_PERSISTENT_DURABILITY_QOS` |

## History

| HDDS | FastDDS | CycloneDDS | RTI Connext |
|------|---------|------------|-------------|
| `.keep_last(N)` | `KEEP_LAST_HISTORY_QOS, depth=N` | `keep_last, depth=N` | `DDS_KEEP_LAST_HISTORY_QOS` |
| `.keep_all()` | `KEEP_ALL_HISTORY_QOS` | `keep_all` | `DDS_KEEP_ALL_HISTORY_QOS` |

### Configuration Examples

**HDDS:**
```rust
use hdds::QoS;

let qos = QoS::reliable().keep_last(10);
```

**FastDDS:**
```xml
<history><kind>KEEP_LAST_HISTORY_QOS</kind><depth>10</depth></history>
```

**CycloneDDS:**
```xml
<History><Kind>keep_last</Kind><Depth>10</Depth></History>
```

**RTI Connext:**
```xml
<history><kind>KEEP_LAST_HISTORY_QOS</kind><depth>10</depth></history>
```

## Deadline

| HDDS | FastDDS | CycloneDDS | RTI Connext |
|------|---------|------------|-------------|
| `.deadline(Duration)` | `<period><sec/><nanosec/></period>` | `<Deadline>Nms</Deadline>` | `<period><sec/><nanosec/></period>` |

### Configuration Examples

**HDDS:**
```rust
use hdds::QoS;
use std::time::Duration;

let qos = QoS::reliable().deadline(Duration::from_millis(100));
```

**FastDDS:**
```xml
<deadline><period><sec>0</sec><nanosec>100000000</nanosec></period></deadline>
```

**CycloneDDS:**
```xml
<Deadline>100ms</Deadline>
```

**RTI Connext:**
```xml
<deadline><period><sec>0</sec><nanosec>100000000</nanosec></period></deadline>
```

## Liveliness

| HDDS | FastDDS | CycloneDDS | RTI Connext |
|------|---------|------------|-------------|
| `liveliness_automatic()` | `AUTOMATIC_LIVELINESS_QOS` | `automatic` | `DDS_AUTOMATIC_LIVELINESS_QOS` |
| `liveliness_manual_by_participant()` | `MANUAL_BY_PARTICIPANT_LIVELINESS_QOS` | `manual_by_participant` | `DDS_MANUAL_BY_PARTICIPANT_LIVELINESS_QOS` |
| `liveliness_manual_by_topic()` | `MANUAL_BY_TOPIC_LIVELINESS_QOS` | `manual_by_topic` | `DDS_MANUAL_BY_TOPIC_LIVELINESS_QOS` |

## Ownership

| HDDS | FastDDS | CycloneDDS | RTI Connext |
|------|---------|------------|-------------|
| `ownership_shared()` | `SHARED_OWNERSHIP_QOS` | `shared` | `DDS_SHARED_OWNERSHIP_QOS` |
| `ownership_exclusive(N)` | `EXCLUSIVE_OWNERSHIP_QOS` | `exclusive` | `DDS_EXCLUSIVE_OWNERSHIP_QOS` |

## Presentation

| HDDS | FastDDS | CycloneDDS | RTI Connext |
|------|---------|------------|-------------|
| `presentation_instance()` | `INSTANCE_PRESENTATION_QOS` | `instance` | `DDS_INSTANCE_PRESENTATION_QOS` |
| `presentation_topic()` | `TOPIC_PRESENTATION_QOS` | `topic` | `DDS_TOPIC_PRESENTATION_QOS` |
| `presentation_group()` | `GROUP_PRESENTATION_QOS` | `group` | `DDS_GROUP_PRESENTATION_QOS` |

## Destination Order

| HDDS | FastDDS | CycloneDDS | RTI Connext |
|------|---------|------------|-------------|
| `destination_order_by_reception()` | `BY_RECEPTION_TIMESTAMP` | `by_reception_timestamp` | `DDS_BY_RECEPTION_TIMESTAMP` |
| `destination_order_by_source()` | `BY_SOURCE_TIMESTAMP` | `by_source_timestamp` | `DDS_BY_SOURCE_TIMESTAMP` |

## Resource Limits

| HDDS | FastDDS | CycloneDDS | RTI Connext |
|------|---------|------------|-------------|
| `max_samples(N)` | `max_samples` | `MaxSamples` | `max_samples` |
| `max_instances(N)` | `max_instances` | `MaxInstances` | `max_instances` |
| `max_samples_per_instance(N)` | `max_samples_per_instance` | `MaxSamplesPerInstance` | `max_samples_per_instance` |

### Configuration Examples

**HDDS:**
```rust
use hdds::QoS;

let qos = QoS::reliable()
    .max_samples(1000)
    .max_instances(100)
    .max_samples_per_instance(10);
```

**FastDDS:**
```xml
<resource_limits>
    <max_samples>1000</max_samples>
    <max_instances>100</max_instances>
    <max_samples_per_instance>10</max_samples_per_instance>
</resource_limits>
```

**CycloneDDS:**
```xml
<ResourceLimits>
    <MaxSamples>1000</MaxSamples>
    <MaxInstances>100</MaxInstances>
    <MaxSamplesPerInstance>10</MaxSamplesPerInstance>
</ResourceLimits>
```

## Partition

| HDDS | FastDDS | CycloneDDS | RTI Connext |
|------|---------|------------|-------------|
| `partition(&["a", "b"])` | `<name>a</name><name>b</name>` | `Partition("a,b")` | `<name>a</name><name>b</name>` |

## Time-Based Filter

| HDDS | FastDDS | CycloneDDS | RTI Connext |
|------|---------|------------|-------------|
| `time_based_filter(Duration)` | `minimum_separation` | `MinimumSeparation` | `minimum_separation` |

## Transport Priority

| HDDS | FastDDS | CycloneDDS | RTI Connext |
|------|---------|------------|-------------|
| `transport_priority(N)` | `<value>N</value>` | N/A | `<value>N</value>` |

## Compatibility Rules

### Matching Requirements

| QoS Policy | Requirement for Match |
|------------|----------------------|
| Reliability | Writer ≥ Reader |
| Durability | Writer ≥ Reader |
| Deadline | Writer period ≤ Reader period |
| Ownership | Writer = Reader |
| Liveliness | Writer kind ≥ Reader kind |
| Presentation | Access scope compatible |
| Partition | At least one overlap |

### Default Values Comparison

| Policy | HDDS Default | FastDDS Default | CycloneDDS Default | RTI Default |
|--------|--------------|-----------------|---------------------|-------------|
| Reliability | BestEffort | BestEffort | BestEffort | BestEffort |
| Durability | Volatile | Volatile | Volatile | Volatile |
| History | KeepLast(1) | KeepLast(1) | KeepLast(1) | KeepLast(1) |
| Deadline | Infinite | Infinite | Infinite | Infinite |
| Liveliness | Automatic | Automatic | Automatic | Automatic |

## Wire Compatibility Notes

All DDS implementations use the same RTPS wire protocol, so QoS policies are communicated during discovery. However:

1. **Vendor extensions**: Some vendors have proprietary QoS extensions not compatible with others
2. **Defaults may differ**: Explicit configuration recommended for interoperability
3. **Type consistency**: XTypes support varies; use `@appendable` for safety

## Next Steps

- [FastDDS QoS Mapping](../interop/fastdds/qos-mapping.md) - FastDDS details
- [CycloneDDS QoS Mapping](../interop/cyclonedds/qos-mapping.md) - CycloneDDS details
- [RTI Connext QoS Mapping](../interop/rti-connext/qos-mapping.md) - RTI details
