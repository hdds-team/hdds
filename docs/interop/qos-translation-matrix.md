# QoS Translation Matrix

Reference for translating QoS policies between HDDS and other DDS implementations.

## Reliability

| HDDS | FastDDS | CycloneDDS |
|------|---------|------------|
| `QoS::best_effort()` | `BEST_EFFORT_RELIABILITY_QOS` | `DDS_RELIABILITY_BEST_EFFORT` |
| `QoS::reliable()` | `RELIABLE_RELIABILITY_QOS` | `DDS_RELIABILITY_RELIABLE` |

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

## Durability

| HDDS | FastDDS | CycloneDDS |
|------|---------|------------|
| `volatile()` | `VOLATILE_DURABILITY_QOS` | `volatile` |
| `transient_local()` | `TRANSIENT_LOCAL_DURABILITY_QOS` | `transient_local` |
| `transient()` | `TRANSIENT_DURABILITY_QOS` | `transient` |
| `persistent()` | `PERSISTENT_DURABILITY_QOS` | `persistent` |

## History

| HDDS | FastDDS | CycloneDDS |
|------|---------|------------|
| `.keep_last(N)` | `KEEP_LAST_HISTORY_QOS, depth=N` | `keep_last, depth=N` |
| `.keep_all()` | `KEEP_ALL_HISTORY_QOS` | `keep_all` |

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

## Deadline

| HDDS | FastDDS | CycloneDDS |
|------|---------|------------|
| `.deadline_millis(N)` | `<period><sec/><nanosec/></period>` | `<Deadline>Nms</Deadline>` |

### Configuration Examples

**HDDS:**
```rust
use hdds::QoS;

let qos = QoS::reliable().deadline_millis(100);
```

**FastDDS:**
```xml
<deadline><period><sec>0</sec><nanosec>100000000</nanosec></period></deadline>
```

**CycloneDDS:**
```xml
<Deadline>100ms</Deadline>
```

## Liveliness

| HDDS | FastDDS | CycloneDDS |
|------|---------|------------|
| `liveliness_automatic_secs(N)` | `AUTOMATIC_LIVELINESS_QOS` | `automatic` |
| `liveliness(Liveliness::manual_by_participant(d))` | `MANUAL_BY_PARTICIPANT_LIVELINESS_QOS` | `manual_by_participant` |
| `liveliness(Liveliness::manual_by_topic(d))` | `MANUAL_BY_TOPIC_LIVELINESS_QOS` | `manual_by_topic` |

## Ownership

| HDDS | FastDDS | CycloneDDS |
|------|---------|------------|
| `ownership_shared()` | `SHARED_OWNERSHIP_QOS` | `shared` |
| `ownership_exclusive()` and `ownership_strength(N)` | `EXCLUSIVE_OWNERSHIP_QOS` | `exclusive` |

## Presentation

| HDDS | FastDDS | CycloneDDS |
|------|---------|------------|
| `presentation_instance()` | `INSTANCE_PRESENTATION_QOS` | `instance` |
| `presentation_topic_coherent()` or `presentation_topic_ordered()` | `TOPIC_PRESENTATION_QOS` | `topic` |
| `presentation_group_coherent()` | `GROUP_PRESENTATION_QOS` | `group` |

## Destination Order

| HDDS | FastDDS | CycloneDDS |
|------|---------|------------|
| `destination_order_by_reception()` | `BY_RECEPTION_TIMESTAMP` | `by_reception_timestamp` |
| `destination_order_by_source()` | `BY_SOURCE_TIMESTAMP` | `by_source_timestamp` |

## Resource Limits

| HDDS | FastDDS | CycloneDDS |
|------|---------|------------|
| `resource_limits.max_samples` | `max_samples` | `MaxSamples` |
| `resource_limits.max_instances` | `max_instances` | `MaxInstances` |
| `resource_limits.max_samples_per_instance` | `max_samples_per_instance` | `MaxSamplesPerInstance` |

### Configuration Examples

**HDDS:**
```rust
use hdds::QoS;

let mut qos = QoS::reliable();
qos.resource_limits = hdds::qos::ResourceLimits {
    max_samples: 1000,
    max_instances: 100,
    max_samples_per_instance: 10,
    ..Default::default()
};
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

| HDDS | FastDDS | CycloneDDS |
|------|---------|------------|
| `partition_single("a")` and `add_partition("b")` | `<name>a</name><name>b</name>` | `Partition("a,b")` |

## Time-Based Filter

| HDDS | FastDDS | CycloneDDS |
|------|---------|------------|
| `time_based_filter_millis(N)` | `minimum_separation` | `MinimumSeparation` |

## Transport Priority

| HDDS | FastDDS | CycloneDDS |
|------|---------|------------|
| `transport_priority(N)` | `<value>N</value>` | N/A |

## Compatibility Rules

### Matching Requirements

| QoS Policy | Requirement for Match |
|------------|----------------------|
| Reliability | Writer >= Reader |
| Durability | Writer >= Reader |
| Deadline | Writer period <= Reader period |
| Ownership | Writer = Reader |
| Liveliness | Writer kind >= Reader kind |
| Presentation | Access scope compatible |
| Partition | At least one overlap |

### HDDS Defaults

`QoS::default()` is `QoS::best_effort()`:

| Policy | HDDS Default |
|--------|--------------|
| Reliability | BestEffort |
| Durability | Volatile |
| History | KeepLast(100) |
| Deadline | Infinite |
| Liveliness | Automatic |

The defaults of other implementations differ (the DDS specification makes a
DataWriter reliable and a DataReader best-effort by default), so set the QoS
explicitly on both sides of an interoperating pair.

## Wire Compatibility Notes

All DDS implementations use the same RTPS wire protocol, so QoS policies are communicated during discovery. However:

1. **Vendor extensions**: Some vendors have proprietary QoS extensions not compatible with others
2. **Defaults may differ**: Explicit configuration recommended for interoperability
3. **Type consistency**: XTypes support varies; use `@appendable` for safety

## Next Steps

- [FastDDS QoS Mapping](../interop/fastdds/qos-mapping.md) - FastDDS details
- [CycloneDDS QoS Mapping](../interop/cyclonedds/qos-mapping.md) - CycloneDDS details
- [RTI Connext QoS Mapping](../interop/rti-connext/qos-mapping.md) - RTI details
