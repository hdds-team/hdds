# HDDS QoS Guide

> Comprehensive reference for all 22 DDS Quality of Service policies in HDDS.

---

## Table of Contents

1. [Overview](#overview)
2. [QoS Builder Pattern](#qos-builder-pattern)
3. [Reliability](#reliability)
4. [Durability](#durability)
5. [History](#history)
6. [Deadline](#deadline)
7. [Lifespan](#lifespan)
8. [Liveliness](#liveliness)
9. [Ownership and OwnershipStrength](#ownership-and-ownershipstrength)
10. [Partition](#partition)
11. [LatencyBudget](#latencybudget)
12. [TimeBasedFilter](#timebasedfilter)
13. [TransportPriority](#transportpriority)
14. [ResourceLimits](#resourcelimits)
15. [DestinationOrder](#destinationorder)
16. [Presentation](#presentation)
17. [DurabilityService](#durabilityservice)
18. [EntityFactory](#entityfactory)
19. [WriterDataLifecycle](#writerdatalifecycle)
20. [ReaderDataLifecycle](#readerdatalifecycle)
21. [Metadata Policies (UserData, GroupData, TopicData)](#metadata-policies)
22. [QoS Compatibility (Request/Offered Matching)](#qos-compatibility)
23. [Common Patterns](#common-patterns)
24. [XML/YAML QoS Loading](#xmlyaml-qos-loading)

---

## Overview

Quality of Service (QoS) policies define the behavioral contract between DDS writers and readers. Each policy controls a specific aspect of data distribution -- reliability, durability, timing, resource usage, and more.

HDDS implements all 22 standard DDS QoS policies from the OMG DDS v1.4 specification. Policies are aggregated into a single `QoS` struct and configured using a fluent builder pattern.

**Key concepts:**

- **Offered QoS** -- The QoS that a DataWriter provides (what it offers).
- **Requested QoS** -- The QoS that a DataReader requires (what it requests).
- **QoS Matching** -- For communication to occur, the offered QoS must be compatible with the requested QoS. Incompatible QoS prevents endpoint matching.
- **Mutable vs Immutable** -- Some policies can be changed after entity creation; others are fixed at creation time.

---

## QoS Builder Pattern

HDDS uses a fluent builder pattern starting from one of the preset profiles. All builder methods consume `self` and return `Self`, allowing method chaining.

### Preset Profiles

```rust
// BestEffort baseline (default) -- fire-and-forget, lowest latency
let qos = hdds::QoS::best_effort();

// Reliable baseline -- NACK-driven retransmission
let qos = hdds::QoS::reliable();

// RTI Connext-compatible defaults (for interop)
let qos = hdds::QoS::rti_defaults();

// Default (same as best_effort)
let qos = hdds::QoS::default();
```

### Builder Chaining

```rust
let qos = hdds::QoS::reliable()
    .transient_local()
    .keep_last(50)
    .deadline_millis(1000)
    .partition_single("sensors")
    .liveliness_automatic_secs(5)
    .transport_priority_high();
```

### Direct Field Access

All QoS fields are public, so you can also construct or modify them directly:

```rust
let mut qos = hdds::QoS::best_effort();
qos.reliability = hdds::Reliability::Reliable;
qos.history = hdds::History::KeepLast(200);
```

---

## Reliability

Controls whether data delivery is guaranteed.

### Variants

| Variant | Description | Use Case |
|---------|-------------|----------|
| `BestEffort` | Fire-and-forget. No ACKs, no retransmission. | Sensors, video, telemetry |
| `Reliable` | NACK-driven retransmission. Guarantees in-order delivery. | Commands, state, config |

### Builder Methods

```rust
// Using preset profiles
let qos = hdds::QoS::best_effort();   // Reliability::BestEffort
let qos = hdds::QoS::reliable();      // Reliability::Reliable
```

### How Reliable Works

```text
Writer                                    Reader
  |                                         |
  |-------- DATA (seq=1) ----------------->|
  |<------- ACKNACK (received=1) ---------|
  |                                         |
  |-------- DATA (seq=2) ------X (lost)   |
  |                                         |
  |<------- ACKNACK (missing=2) ----------|  <- Reader detects gap
  |                                         |
  |-------- DATA (seq=2) ----------------->|  <- Retransmit
  |<------- ACKNACK (received=2) ---------|
```

### Matching Rules

The offered reliability must be at least as strong as the requested reliability:

| Writer Offers | Reader Requests | Match? |
|---------------|-----------------|--------|
| Reliable | Reliable | Yes |
| Reliable | BestEffort | Yes |
| BestEffort | BestEffort | Yes |
| BestEffort | Reliable | **No** |

---

## Durability

Controls whether late-joining readers receive historical data.

### Variants

| Variant | Description | Persistence |
|---------|-------------|-------------|
| `Volatile` | No history for late-joiners. | None |
| `TransientLocal` | Writer caches samples in memory for late-joiners. | Writer lifetime only |
| `Persistent` | Writer persists samples to disk for late-joiners. | Survives restarts |

### Builder Methods

```rust
let qos = hdds::QoS::reliable().volatile();
let qos = hdds::QoS::reliable().transient_local();
let qos = hdds::QoS::reliable().persistent();
```

### Matching Rules (Ordered Strength)

Volatile < TransientLocal < Persistent

The offered durability must be at least as strong as the requested durability:

| Writer Offers | Reader Requests | Match? |
|---------------|-----------------|--------|
| TransientLocal | Volatile | Yes |
| TransientLocal | TransientLocal | Yes |
| Volatile | TransientLocal | **No** |

### Example: State Replication with TransientLocal

```rust
// Writer: cache last 100 state updates for late joiners
let writer_qos = hdds::QoS::reliable()
    .transient_local()
    .keep_last(100);

let writer = participant.create_writer::<RobotState>("robot/state", writer_qos)?;

// Reader: late-joiner will receive cached history
let reader_qos = hdds::QoS::reliable()
    .transient_local()
    .keep_last(100);

let reader = participant.create_reader::<RobotState>("robot/state", reader_qos)?;
```

---

## History

Controls how many samples are kept in the writer/reader queue.

### Variants

| Variant | Description |
|---------|-------------|
| `KeepLast(n)` | Bounded queue of size `n`. Drops oldest when full. |
| `KeepAll` | Keeps all samples within ResourceLimits. Inserts fail at capacity. |

### Builder Methods

```rust
let qos = hdds::QoS::reliable().keep_last(100);
let qos = hdds::QoS::reliable().keep_all();
```

### Validation Rules

- `KeepLast(0)` is invalid (depth must be > 0).
- `KeepAll` requires `ResourceLimits.max_samples > 0`.

### When to Use Which

- **KeepLast(1)**: Sensor data where only the latest value matters.
- **KeepLast(100)**: Moderate history for retransmission buffer.
- **KeepAll**: Event logs, transactions where every sample matters (bounded by ResourceLimits).

---

## Deadline

Specifies the maximum expected time between samples. A missed deadline triggers a status change event.

### Builder Methods

```rust
// Expect a sample at least every 100ms
let qos = hdds::QoS::best_effort().deadline_millis(100);

// Expect a sample at least every 5 seconds
let qos = hdds::QoS::best_effort().deadline_secs(5);

// Using the Deadline type directly
let qos = hdds::QoS::best_effort().deadline(hdds::Deadline::from_millis(250));

// Infinite deadline (no constraint, default)
let qos = hdds::QoS::best_effort().deadline(hdds::Deadline::infinite());
```

### Matching Rules

The offered deadline period must be <= the requested deadline period. A writer offering a 500ms deadline can match a reader requesting a 1000ms deadline, but not one requesting 100ms.

---

## Lifespan

Controls how long a sample remains valid after writing. Expired samples are discarded and never delivered.

### Builder Methods

```rust
// Samples expire after 5 seconds
let qos = hdds::QoS::best_effort().lifespan_secs(5);

// Samples expire after 200ms
let qos = hdds::QoS::best_effort().lifespan_millis(200);

// Using the Lifespan type directly
let qos = hdds::QoS::best_effort().lifespan(hdds::Lifespan::from_secs(30));

// Infinite lifespan (never expires, default)
let qos = hdds::QoS::best_effort().lifespan(hdds::Lifespan::infinite());
```

### Use Cases

- **Sensor data**: Set lifespan to 2x the expected sample rate. Stale readings are useless.
- **Commands**: Infinite lifespan (default). Commands must never expire.
- **Market data**: Short lifespan. Old quotes are misleading.

---

## Liveliness

Defines how a writer asserts that it is still alive. If no assertion arrives within the lease duration, the writer is considered "not alive" and readers are notified.

### Kinds

| Kind | How It Works |
|------|-------------|
| `Automatic` | DDS infrastructure asserts liveliness automatically via heartbeats. |
| `ManualByParticipant` | Application must call `assert_liveliness()` on the participant. |
| `ManualByTopic` | Application must call `assert_liveliness()` on each writer individually. |

### Builder Methods

```rust
// Automatic with 5-second lease
let qos = hdds::QoS::reliable().liveliness_automatic_secs(5);

// Automatic with 500ms lease
let qos = hdds::QoS::reliable().liveliness_automatic_millis(500);

// Manual by participant with 10-second lease
let qos = hdds::QoS::reliable().liveliness_manual_participant_secs(10);

// Manual by participant with 2000ms lease
let qos = hdds::QoS::reliable().liveliness_manual_participant_millis(2000);

// Using the Liveliness type directly
let qos = hdds::QoS::reliable().liveliness(hdds::Liveliness::automatic_secs(5));

// Infinite lease (no liveliness tracking, default)
let qos = hdds::QoS::reliable().liveliness(hdds::Liveliness::infinite());
```

### Matching Rules (Ordered Strength)

Automatic < ManualByParticipant < ManualByTopic

The offered liveliness kind must be at least as strong as the requested kind, and the offered lease duration must be <= the requested lease duration.

---

## Ownership and OwnershipStrength

Controls whether multiple writers can publish to the same instance simultaneously.

### Ownership Kinds

| Kind | Description |
|------|-------------|
| `Shared` | Multiple writers can publish simultaneously (default). All data is delivered. |
| `Exclusive` | Only the highest-strength writer "owns" the instance. Others are silenced. |

### Builder Methods

```rust
// Shared ownership (default)
let qos = hdds::QoS::reliable().ownership_shared();

// Exclusive ownership with strength
let qos = hdds::QoS::reliable()
    .ownership_exclusive()
    .ownership_strength(50);

// Convenience: high priority writer (strength: 100)
let qos_primary = hdds::QoS::reliable()
    .ownership_exclusive()
    .ownership_strength_high();

// Convenience: low priority writer (strength: -100)
let qos_backup = hdds::QoS::reliable()
    .ownership_exclusive()
    .ownership_strength_low();

// Custom strength value
let qos = hdds::QoS::reliable()
    .ownership_exclusive()
    .ownership_strength(75);
```

### Exclusive Ownership Example: Primary/Backup Redundancy

```rust
// Primary controller (high strength -- owns the instance)
let primary_qos = hdds::QoS::reliable()
    .ownership_exclusive()
    .ownership_strength(100);
let primary = participant.create_writer::<Command>("robot/cmd", primary_qos)?;

// Backup controller (low strength -- only active if primary fails)
let backup_qos = hdds::QoS::reliable()
    .ownership_exclusive()
    .ownership_strength(10);
let backup = participant.create_writer::<Command>("robot/cmd", backup_qos)?;
```

---

## Partition

Provides logical data separation within a domain. Writers and readers in different partitions do not communicate, even if they share the same topic.

### Builder Methods

```rust
// Single partition
let qos = hdds::QoS::reliable().partition_single("sensors");

// Multiple partitions via chaining
let qos = hdds::QoS::reliable()
    .add_partition("sensors")
    .add_partition("building_a");

// Using the Partition type directly
let qos = hdds::QoS::reliable().partition(
    hdds::Partition::new(vec!["sensors".to_string(), "actuators".to_string()])
);

// Default partition (empty string -- matches other default partitions)
let qos = hdds::QoS::reliable().partition(hdds::Partition::default());
```

### Matching Rules

For endpoints to match, they must share at least one partition name. Wildcard patterns (`*`, `?`) are supported in partition names per the DDS specification.

### Use Case: Multi-Tenant Isolation

```rust
// Building A sensors
let qos_a = hdds::QoS::best_effort().partition_single("building_a");
let writer_a = participant.create_writer::<Temperature>("temperature", qos_a)?;

// Building B sensors (isolated from A)
let qos_b = hdds::QoS::best_effort().partition_single("building_b");
let writer_b = participant.create_writer::<Temperature>("temperature", qos_b)?;

// Central reader (receives from both buildings)
let qos_central = hdds::QoS::best_effort()
    .add_partition("building_a")
    .add_partition("building_b");
let reader = participant.create_reader::<Temperature>("temperature", qos_central)?;
```

---

## LatencyBudget

Provides a hint about the maximum acceptable delay from write to delivery. The DDS implementation may use this to optimize batching and transport scheduling.

### Builder Methods

```rust
// 10ms latency budget (critical data)
let qos = hdds::QoS::reliable().latency_budget_millis(10);

// 1-second latency budget (bulk data)
let qos = hdds::QoS::best_effort().latency_budget_secs(1);

// Using the LatencyBudget type directly
let qos = hdds::QoS::reliable().latency_budget(hdds::LatencyBudget::from_millis(50));

// Zero latency budget (deliver ASAP, default)
let qos = hdds::QoS::reliable().latency_budget(hdds::LatencyBudget::zero());
```

### Matching Rules

The offered latency budget must be <= the requested latency budget. A writer offering 10ms latency can match a reader requesting 100ms, but not one requesting 5ms.

---

## TimeBasedFilter

Controls the minimum time between accepted samples on the reader side. Samples arriving faster than the filter rate are silently discarded.

### Builder Methods

```rust
// Accept at most 10 samples per second (100ms separation)
let qos = hdds::QoS::best_effort().time_based_filter_millis(100);

// Accept at most 1 sample per second
let qos = hdds::QoS::best_effort().time_based_filter_secs(1);

// Using the TimeBasedFilter type directly
let qos = hdds::QoS::best_effort().time_based_filter(
    hdds::TimeBasedFilter::from_millis(500)
);

// No filtering (accept all samples, default)
let qos = hdds::QoS::best_effort().time_based_filter(hdds::TimeBasedFilter::zero());
```

### Use Case: High-Rate Sensor Throttling

```rust
// Writer publishes at 1000 Hz
let writer_qos = hdds::QoS::best_effort();
let writer = participant.create_writer::<SensorData>("imu", writer_qos)?;

// Display reader only needs 10 Hz
let display_qos = hdds::QoS::best_effort().time_based_filter_millis(100);
let display = participant.create_reader::<SensorData>("imu", display_qos)?;

// Logger reader needs full 1000 Hz
let logger_qos = hdds::QoS::reliable(); // no filter
let logger = participant.create_reader::<SensorData>("imu", logger_qos)?;
```

---

## TransportPriority

Provides a hint for network-level prioritization. Higher values indicate more important data. Maps to DSCP/TOS bits when supported by the transport.

### Builder Methods

```rust
// High priority (value: 50)
let qos = hdds::QoS::reliable().transport_priority_high();

// Normal priority (value: 0, default)
let qos = hdds::QoS::reliable().transport_priority_normal();

// Low priority (value: -50)
let qos = hdds::QoS::best_effort().transport_priority_low();

// Custom priority value
let qos = hdds::QoS::reliable().transport_priority(75);
```

---

## ResourceLimits

Controls memory allocation and queue sizes for writers and readers.

### Fields

| Field | Default | Description |
|-------|---------|-------------|
| `max_samples` | 100,000 | Maximum total samples across all instances |
| `max_instances` | 1 | Maximum number of instances (keyed topics) |
| `max_samples_per_instance` | 100,000 | Maximum samples per instance |
| `max_quota_bytes` | 100 MB | Maximum total payload bytes |

### Configuration

```rust
use hdds::qos::ResourceLimits;

let mut qos = hdds::QoS::reliable();
qos.resource_limits = ResourceLimits {
    max_samples: 500,
    max_instances: 10,
    max_samples_per_instance: 50,
    max_quota_bytes: 5_000_000, // 5 MB
};
```

### Validation

- `max_samples >= max_samples_per_instance * max_instances` (must hold, or validation fails)
- `KeepAll` history requires `max_samples > 0`

---

## DestinationOrder

Controls how samples are ordered when delivered to readers.

### Kinds

| Kind | Description |
|------|-------------|
| `ByReceptionTimestamp` | Order by when samples arrived at the reader (default, fastest). |
| `BySourceTimestamp` | Order by when samples were written at the writer (temporal consistency). |

### Builder Methods

```rust
// Order by reception timestamp (default)
let qos = hdds::QoS::reliable().destination_order_by_reception();

// Order by source timestamp (temporal consistency across writers)
let qos = hdds::QoS::reliable().destination_order_by_source();

// Using the DestinationOrder type directly
let qos = hdds::QoS::reliable().destination_order(
    hdds::DestinationOrder::by_source_timestamp()
);
```

### Use Case: Multi-Writer Temporal Consistency

When multiple writers publish to the same topic, `BySourceTimestamp` ensures readers see samples in true temporal order, regardless of network delays.

---

## Presentation

Controls how changes are presented to readers in terms of coherence and ordering.

### Access Scopes

| Scope | Description |
|-------|-------------|
| `Instance` | Each instance is independent. No transactional semantics (default). |
| `Topic` | All instances of a topic are presented together. Supports coherent snapshots. |
| `Group` | Multiple topics are presented as a coherent set. Full transactional semantics. |

### Builder Methods

```rust
// Instance-level (default)
let qos = hdds::QoS::reliable().presentation_instance();

// Topic-level with coherent access
let qos = hdds::QoS::reliable().presentation_topic_coherent();

// Topic-level with ordered access
let qos = hdds::QoS::reliable().presentation_topic_ordered();

// Group-level with coherent access
let qos = hdds::QoS::reliable().presentation_group_coherent();

// Group-level with coherent AND ordered access
let qos = hdds::QoS::reliable().presentation_group_coherent_ordered();

// Custom presentation
let qos = hdds::QoS::reliable().presentation(
    hdds::Presentation::new(
        hdds::PresentationAccessScope::Topic,
        true,   // coherent_access
        true,   // ordered_access
    )
);
```

---

## DurabilityService

Configures the history cache for `TransientLocal` and `Persistent` durability, controlling how many samples are stored for late-joining readers.

### Builder Methods

```rust
// Keep last 100 samples for late-joiners
let qos = hdds::QoS::reliable()
    .transient_local()
    .durability_service_keep_last(100, 1000, 10, 100);
    // Args: history_depth, max_samples, max_instances, max_samples_per_instance

// With cleanup delay (60 seconds)
let qos = hdds::QoS::reliable()
    .transient_local()
    .durability_service_cleanup_delay_secs(60);

// Using the DurabilityService type directly
let qos = hdds::QoS::reliable()
    .transient_local()
    .durability_service(hdds::DurabilityService::keep_last(100, 1000, 10, 100));
```

---

## EntityFactory

Controls whether entities are automatically enabled when created.

### Builder Methods

```rust
// Auto-enable (default -- entities are active immediately)
let qos = hdds::QoS::reliable().entity_factory_auto_enable();

// Manual enable (entities start disabled, must be explicitly enabled)
let qos = hdds::QoS::reliable().entity_factory_manual_enable();

// Using the EntityFactory type directly
let qos = hdds::QoS::reliable().entity_factory(hdds::EntityFactory::auto_enable());
let qos = hdds::QoS::reliable().entity_factory(hdds::EntityFactory::manual_enable());
```

---

## WriterDataLifecycle

Controls automatic disposal of unregistered instances on the writer side.

### Builder Methods

```rust
// Auto-dispose (default -- unregistered instances are automatically disposed)
let qos = hdds::QoS::reliable().writer_data_lifecycle_auto_dispose();

// Manual dispose (instances stay alive after unregister)
let qos = hdds::QoS::reliable().writer_data_lifecycle_manual_dispose();

// Using the WriterDataLifecycle type directly
let qos = hdds::QoS::reliable().writer_data_lifecycle(
    hdds::WriterDataLifecycle::auto_dispose()
);
```

---

## ReaderDataLifecycle

Controls automatic purging of reader instances that are no longer alive.

### Builder Methods

```rust
// Keep all instances indefinitely (default)
let qos = hdds::QoS::reliable().reader_data_lifecycle_keep_all();

// Immediate cleanup (purge as soon as instance becomes NOT_ALIVE)
let qos = hdds::QoS::reliable().reader_data_lifecycle_immediate_cleanup();

// Custom delays (30 seconds for both nowriter and disposed)
let qos = hdds::QoS::reliable().reader_data_lifecycle_secs(30, 30);

// Using the ReaderDataLifecycle type directly
let qos = hdds::QoS::reliable().reader_data_lifecycle(
    hdds::ReaderDataLifecycle::from_secs(60, 60)
);
```

---

## Metadata Policies

Opaque byte sequences attached to entities for application-specific purposes. These are propagated during discovery.

### UserData

Attached to a DomainParticipant or entity for identification.

```rust
let qos = hdds::QoS::reliable()
    .user_data_bytes(b"version=1.0.5");

// Using the UserData type directly
let qos = hdds::QoS::reliable()
    .user_data(hdds::UserData::new(b"my-app-metadata".to_vec()));
```

### GroupData

Attached to a Publisher or Subscriber.

```rust
let qos = hdds::QoS::reliable()
    .group_data_bytes(b"deployment=production");

let qos = hdds::QoS::reliable()
    .group_data(hdds::GroupData::new(b"group-info".to_vec()));
```

### TopicData

Attached to a Topic.

```rust
let qos = hdds::QoS::reliable()
    .topic_data_bytes(b"schema=v2");

let qos = hdds::QoS::reliable()
    .topic_data(hdds::TopicData::new(b"topic-info".to_vec()));
```

---

## QoS Compatibility

DDS uses a Request/Offered matching model. When a DataReader discovers a DataWriter on the same topic, the middleware checks that the writer's offered QoS is compatible with the reader's requested QoS. If incompatible, the endpoints do not match and no data flows between them.

### Compatibility Rules Summary

| Policy | Rule |
|--------|------|
| **Reliability** | Offered >= Requested (Reliable >= BestEffort) |
| **Durability** | Offered >= Requested (Persistent > TransientLocal > Volatile) |
| **Deadline** | Offered period <= Requested period |
| **LatencyBudget** | Offered duration <= Requested duration |
| **Liveliness** | Offered kind >= Requested kind; Offered lease <= Requested lease |
| **Ownership** | Must be identical (both Shared or both Exclusive) |
| **Partition** | Must share at least one partition name |
| **Presentation** | Offered scope >= Requested scope |
| **DestinationOrder** | Offered kind >= Requested kind |

### Example: Incompatible QoS

```rust
// Writer offers BestEffort
let writer_qos = hdds::QoS::best_effort();
let writer = participant.create_writer::<SensorData>("topic", writer_qos)?;

// Reader requests Reliable -- MISMATCH! Endpoints will NOT match.
let reader_qos = hdds::QoS::reliable();
let reader = participant.create_reader::<SensorData>("topic", reader_qos)?;
// reader will never receive data from this writer
```

### Detecting Incompatibility

Monitor the `REQUESTED_INCOMPATIBLE_QOS` and `OFFERED_INCOMPATIBLE_QOS` status conditions on readers and writers respectively.

---

## Common Patterns

### Pattern 1: High-Frequency Sensor Data

Low-latency, loss-tolerant. Latest value matters most.

```rust
let qos = hdds::QoS::best_effort()
    .keep_last(1)
    .lifespan_millis(500)
    .time_based_filter_millis(10);

let writer = participant.create_writer::<SensorReading>("imu/accel", qos.clone())?;
let reader = participant.create_reader::<SensorReading>("imu/accel", qos)?;
```

### Pattern 2: Command / Control

Every message must be delivered. No losses, no expiration.

```rust
let qos = hdds::QoS::reliable()
    .keep_last(100)
    .deadline_secs(1)
    .liveliness_automatic_secs(5);

let writer = participant.create_writer::<Command>("robot/cmd", qos.clone())?;
let reader = participant.create_reader::<Command>("robot/cmd", qos)?;
```

### Pattern 3: State Replication (Late Joiners)

New subscribers get the current state immediately upon joining.

```rust
let qos = hdds::QoS::reliable()
    .transient_local()
    .keep_last(1)
    .ownership_exclusive()
    .ownership_strength(100);

let writer = participant.create_writer::<SystemState>("system/state", qos.clone())?;
let reader = participant.create_reader::<SystemState>("system/state", qos)?;
```

### Pattern 4: Event Logging (Keep All)

Every event must be captured. No sample may be dropped.

```rust
use hdds::qos::ResourceLimits;

let mut qos = hdds::QoS::reliable()
    .keep_all()
    .persistent();

qos.resource_limits = ResourceLimits {
    max_samples: 1_000_000,
    max_instances: 1,
    max_samples_per_instance: 1_000_000,
    max_quota_bytes: 500_000_000, // 500 MB
};

let writer = participant.create_writer::<AuditEvent>("audit/events", qos)?;
```

### Pattern 5: Multi-Partition Fleet Management

Different vehicle groups on separate partitions, central monitoring on all.

```rust
// Vehicle in fleet A
let vehicle_qos = hdds::QoS::reliable()
    .transient_local()
    .partition_single("fleet_a");

// Central monitor sees all fleets
let monitor_qos = hdds::QoS::reliable()
    .transient_local()
    .add_partition("fleet_a")
    .add_partition("fleet_b")
    .add_partition("fleet_c");
```

### Pattern 6: Primary/Backup Writer Redundancy

```rust
// Primary writer (high strength)
let primary_qos = hdds::QoS::reliable()
    .ownership_exclusive()
    .ownership_strength(100)
    .liveliness_automatic_secs(2);

// Backup writer (low strength -- takes over when primary fails liveliness)
let backup_qos = hdds::QoS::reliable()
    .ownership_exclusive()
    .ownership_strength(10)
    .liveliness_automatic_secs(2);
```

---

## XML/YAML QoS Loading

HDDS supports loading QoS profiles from external files via the `qos-loaders` feature (enabled by default).

### YAML Format (HDDS Native)

YAML is the recommended format for HDDS-native configuration.

```yaml
# qos_profiles.yaml

default_profile: reliable_sensor

profiles:
  reliable_sensor:
    reliability: RELIABLE
    durability: TRANSIENT_LOCAL
    history:
      kind: KEEP_LAST
      depth: 100
    deadline:
      period_ms: 1000
    liveliness:
      kind: AUTOMATIC
      lease_duration_ms: 5000
    partition:
      - sensors
      - building_a
    transport_priority: 10

  best_effort_telemetry:
    reliability: BEST_EFFORT
    durability: VOLATILE
    history:
      kind: KEEP_LAST
      depth: 1
    latency_budget:
      duration_us: 100
    time_based_filter:
      minimum_separation_ms: 100

  full_config:
    reliability: RELIABLE
    durability: PERSISTENT
    history:
      kind: KEEP_ALL
    ownership: EXCLUSIVE
    ownership_strength: 50
    destination_order: BY_SOURCE_TIMESTAMP
    presentation:
      access_scope: TOPIC
      coherent_access: true
      ordered_access: false
    lifespan:
      duration_secs: 3600
    resource_limits:
      max_samples: 10000
      max_instances: 100
      max_samples_per_instance: 100
    writer_data_lifecycle:
      autodispose_unregistered_instances: false
    reader_data_lifecycle:
      autopurge_nowriter_samples_delay_ms: 30000
      autopurge_disposed_samples_delay_ms: 60000
    entity_factory:
      autoenable_created_entities: true
    user_data: "app=hdds,version=1.0.5"
```

### Loading YAML Profiles

```rust
use hdds::dds::qos::loaders::YamlLoader;

// Load a specific profile
let qos = YamlLoader::load_qos("qos_profiles.yaml", Some("reliable_sensor"))?;

// Load the default profile
let qos = YamlLoader::load_qos("qos_profiles.yaml", None)?;

// Parse from string
let doc = YamlLoader::parse_yaml(yaml_content)?;
let qos = YamlLoader::get_profile(&doc, "reliable_sensor")?;
```

### FastDDS XML Format

HDDS can also load QoS from FastDDS XML profile files for interoperability.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<dds xmlns="http://www.eprosima.com/XMLSchemas/fastRTPS_Profiles">
  <profiles>
    <data_writer profile_name="reliable" is_default_profile="true">
      <qos>
        <reliability><kind>RELIABLE</kind></reliability>
        <durability><kind>TRANSIENT_LOCAL</kind></durability>
      </qos>
    </data_writer>
  </profiles>
</dds>
```

```rust
// Load from FastDDS XML
let qos = hdds::QoS::load_fastdds("fastdds_profiles.xml")?;

// Auto-detect format (XML or YAML)
let qos = hdds::QoS::from_xml("profile.xml")?;
```

### ProfileLoader (Auto-Detect Format)

The `ProfileLoader` automatically detects the file format from extension or content.

```rust
use hdds::dds::qos::loaders::ProfileLoader;

// Auto-detect by extension (.yaml, .yml, .xml)
let qos = ProfileLoader::load("config.yaml", Some("reliable"))?;
let qos = ProfileLoader::load("fastdds_profiles.xml", None)?;

// Auto-detect from string content
let qos = ProfileLoader::load_from_str_auto(content, Some("my_profile"))?;

// Explicit format
use hdds::dds::qos::loaders::profile_loader::ConfigFormat;
let qos = ProfileLoader::load_from_str(content, ConfigFormat::Yaml, Some("profile"))?;
```

### Supported YAML QoS Fields

| Field | Type | Values |
|-------|------|--------|
| `reliability` | String | `RELIABLE`, `BEST_EFFORT` |
| `durability` | String | `VOLATILE`, `TRANSIENT_LOCAL`, `PERSISTENT` |
| `history.kind` | String | `KEEP_LAST`, `KEEP_ALL` |
| `history.depth` | u32 | Depth for KEEP_LAST |
| `liveliness.kind` | String | `AUTOMATIC`, `MANUAL_BY_PARTICIPANT`, `MANUAL_BY_TOPIC` |
| `liveliness.lease_duration_ms` | u64 | Lease in milliseconds |
| `liveliness.lease_duration_secs` | u64 | Lease in seconds |
| `ownership` | String | `SHARED`, `EXCLUSIVE` |
| `ownership_strength` | i32 | Strength value |
| `destination_order` | String | `BY_RECEPTION_TIMESTAMP`, `BY_SOURCE_TIMESTAMP` |
| `presentation.access_scope` | String | `INSTANCE`, `TOPIC`, `GROUP` |
| `presentation.coherent_access` | bool | |
| `presentation.ordered_access` | bool | |
| `deadline.period_ms` | u64 | Period in milliseconds |
| `deadline.period_secs` | u64 | Period in seconds |
| `lifespan.duration_ms` | u64 | Duration in milliseconds |
| `lifespan.duration_secs` | u64 | Duration in seconds |
| `latency_budget.duration_ms` | u64 | Budget in milliseconds |
| `latency_budget.duration_us` | u64 | Budget in microseconds |
| `time_based_filter.minimum_separation_ms` | u64 | Min separation in ms |
| `partition` | List\<String\> | Partition names |
| `user_data` | String | UTF-8 data |
| `group_data` | String | UTF-8 data |
| `topic_data` | String | UTF-8 data |
| `transport_priority` | i32 | Priority value |
| `resource_limits.max_samples` | i32 | -1 = unlimited |
| `resource_limits.max_instances` | i32 | -1 = unlimited |
| `resource_limits.max_samples_per_instance` | i32 | -1 = unlimited |
| `writer_data_lifecycle.autodispose_unregistered_instances` | bool | |
| `reader_data_lifecycle.autopurge_nowriter_samples_delay_ms` | u64 | |
| `reader_data_lifecycle.autopurge_disposed_samples_delay_ms` | u64 | |
| `entity_factory.autoenable_created_entities` | bool | |

---

## Quick Reference: All Builder Methods

| Method | Category | Description |
|--------|----------|-------------|
| `best_effort()` | Constructor | BestEffort baseline |
| `reliable()` | Constructor | Reliable baseline |
| `rti_defaults()` | Constructor | RTI Connext interop defaults |
| `keep_last(n)` | History | KeepLast(n) |
| `keep_all()` | History | KeepAll |
| `volatile()` | Durability | Volatile |
| `transient_local()` | Durability | TransientLocal |
| `persistent()` | Durability | Persistent |
| `deadline_millis(ms)` | Timing | Deadline from ms |
| `deadline_secs(s)` | Timing | Deadline from seconds |
| `lifespan_millis(ms)` | Timing | Lifespan from ms |
| `lifespan_secs(s)` | Timing | Lifespan from seconds |
| `time_based_filter_millis(ms)` | Timing | TimeBasedFilter from ms |
| `time_based_filter_secs(s)` | Timing | TimeBasedFilter from seconds |
| `latency_budget_millis(ms)` | Timing | LatencyBudget from ms |
| `latency_budget_secs(s)` | Timing | LatencyBudget from seconds |
| `liveliness_automatic_secs(s)` | Liveliness | Automatic with lease in seconds |
| `liveliness_automatic_millis(ms)` | Liveliness | Automatic with lease in ms |
| `liveliness_manual_participant_secs(s)` | Liveliness | ManualByParticipant |
| `liveliness_manual_participant_millis(ms)` | Liveliness | ManualByParticipant |
| `ownership_shared()` | Ownership | Shared ownership |
| `ownership_exclusive()` | Ownership | Exclusive ownership |
| `ownership_strength(v)` | Ownership | Custom strength |
| `ownership_strength_high()` | Ownership | High priority (100) |
| `ownership_strength_low()` | Ownership | Low priority (-100) |
| `partition_single(name)` | Partition | Single partition |
| `add_partition(name)` | Partition | Add partition |
| `transport_priority(v)` | Transport | Custom priority |
| `transport_priority_high()` | Transport | High priority (50) |
| `transport_priority_low()` | Transport | Low priority (-50) |
| `transport_priority_normal()` | Transport | Normal priority (0) |
| `destination_order_by_reception()` | Ordering | ByReceptionTimestamp |
| `destination_order_by_source()` | Ordering | BySourceTimestamp |
| `presentation_instance()` | Presentation | Instance scope |
| `presentation_topic_coherent()` | Presentation | Topic + coherent |
| `presentation_topic_ordered()` | Presentation | Topic + ordered |
| `presentation_group_coherent()` | Presentation | Group + coherent |
| `presentation_group_coherent_ordered()` | Presentation | Group + coherent + ordered |
| `entity_factory_auto_enable()` | Factory | Auto-enable entities |
| `entity_factory_manual_enable()` | Factory | Manual enable |
| `writer_data_lifecycle_auto_dispose()` | Lifecycle | Auto-dispose unregistered |
| `writer_data_lifecycle_manual_dispose()` | Lifecycle | Manual dispose |
| `reader_data_lifecycle_keep_all()` | Lifecycle | Keep all instances |
| `reader_data_lifecycle_immediate_cleanup()` | Lifecycle | Immediate purge |
| `reader_data_lifecycle_secs(nw, d)` | Lifecycle | Custom purge delays |
| `durability_service_keep_last(...)` | Service | DurabilityService KeepLast |
| `durability_service_cleanup_delay_secs(s)` | Service | Cleanup delay |
| `user_data_bytes(b)` | Metadata | UserData from bytes |
| `group_data_bytes(b)` | Metadata | GroupData from bytes |
| `topic_data_bytes(b)` | Metadata | TopicData from bytes |
