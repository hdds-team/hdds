# HDDS QoS Guide

> Comprehensive reference for all 22 DDS Quality of Service policies in HDDS, including per-policy implementation status.

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

All 22 standard DDS QoS policies from the OMG DDS v1.4 specification are part of the public API: each has a policy type and builder methods (the YAML loader covers every policy except Durability Service; the Fast DDS XML loader covers a subset), aggregated into a single `QoS` struct configured with a fluent builder pattern. Not every policy changes runtime behavior: 14 are enforced in the runtime data path, 3 are partially enforced, and 5 are accepted and stored only. The table below gives the per-policy status; each policy section states exactly what is and is not wired.

### Implementation Status

| Policy | Status | Behavioral tests | Exercised in OMG interop suite |
|--------|--------|------------------|--------------------------------|
| Reliability | Enforced | Yes | Yes |
| Durability | Partial | Yes | Yes |
| History | Enforced | Yes | Yes |
| Deadline | Enforced | Yes | Yes |
| Lifespan | Enforced | Yes | Yes |
| Ownership | Enforced | Yes | Yes |
| Ownership Strength | Enforced | Yes | Yes |
| Partition | Enforced | Yes | Yes |
| Time-Based Filter | Enforced | Yes | Yes |
| Resource Limits | Enforced | Yes | No |
| Presentation | Enforced | Yes | Yes |
| Durability Service | Enforced | Yes | No |
| Liveliness | Enforced | Yes | No |
| Latency Budget | Partial | Yes | No |
| Transport Priority | Accepted | No | No |
| Destination Order | Enforced | Yes | No |
| Entity Factory | Accepted | No | No |
| Writer Data Lifecycle | Enforced | Yes | No |
| Reader Data Lifecycle | Accepted | No | No |
| User Data | Partial | Yes | No |
| Group Data | Accepted | No | No |
| Topic Data | Accepted | No | No |

Reading the table:

- **Enforced** -- a runtime code path reads the policy value and changes behavior. Some policies are enforced with stated limits; each section below gives the exact scope (for example, Presentation enforces coherent access and GROUP ordered access, and Durability Service applies to TRANSIENT and PERSISTENT writers only).
- **Partial** -- part of the policy (a kind, a field, or only the matching rule) is acted on; the rest is accepted but has no runtime effect. Durability enforces `Volatile` and `TransientLocal` (`Transient` and `Persistent` are held in memory only); Latency Budget is applied as a matching rule only; User Data is announced in discovery but no API returns a remote value.
- **Accepted** -- the policy type, builder methods, and loaders exist and the value is stored, but no runtime path acts on it.
- **Behavioral tests** -- the repository has compiled tests asserting an observable runtime effect (not just struct or serialization round-trips).
- **Exercised in OMG interop suite** -- the policy is exercised cross-vendor by the official OMG dds-rtps interoperability suite; the suite has no test family for the policies marked No.

Totals: 14 enforced and 3 partial of 22, 17 with behavioral test coverage, 10 exercised cross-vendor.

DATA_REPRESENTATION (an XTypes policy, not one of the 22) is also enforced: a writer resolves its representation at creation, and a pair with no common representation does not match.

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

// Default (same as best_effort)
let qos = hdds::QoS::default();
```

The policy types (`Reliability`, `History`, `Deadline`, `Lifespan`, ...) are
exported from `hdds::dds`; `QoS` is also available at the crate root.

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
qos.reliability = hdds::dds::Reliability::Reliable;
qos.history = hdds::dds::History::KeepLast(200);
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
| `Transient` | Accepted; ranks between `TransientLocal` and `Persistent`. In-core it behaves like `TransientLocal` (in-memory cache). | Writer lifetime only (in-core) |
| `Persistent` | Accepted; strongest matching rank. In-core it behaves like `TransientLocal` (in-memory cache). | Writer lifetime only (in-core) |

**Status:** partial. `Volatile` and `TransientLocal` are fully enforced (cache gating plus late-joiner replay). `Transient` and `Persistent` are accepted and rank higher at discovery matching, but the core runtime keeps history in memory only; disk-backed persistence is provided by the separate opt-in `hdds-persistence` service and is not wired into the core data path.

### Builder Methods

```rust
let qos = hdds::QoS::reliable().volatile();
let qos = hdds::QoS::reliable().transient_local();
let qos = hdds::QoS::reliable().transient();
let qos = hdds::QoS::reliable().persistent();
```

### Matching Rules (Ordered Strength)

Volatile < TransientLocal < Transient < Persistent

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

let writer = participant.topic::<RobotState>("robot/state")?.writer().qos(writer_qos).build()?;

// Reader: late-joiner will receive cached history
let reader_qos = hdds::QoS::reliable()
    .transient_local()
    .keep_last(100);

let reader = participant.topic::<RobotState>("robot/state")?.reader().qos(reader_qos).build()?;
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
- `KeepAll` requires `ResourceLimits.max_samples` to be > 0 or LENGTH_UNLIMITED (the default).

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
let qos = hdds::QoS::best_effort().deadline(hdds::dds::Deadline::from_millis(250));

// Infinite deadline (no constraint, default)
let qos = hdds::QoS::best_effort().deadline(hdds::dds::Deadline::infinite());
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
let qos = hdds::QoS::best_effort().lifespan(hdds::dds::Lifespan::from_secs(30));

// Infinite lifespan (never expires, default)
let qos = hdds::QoS::best_effort().lifespan(hdds::dds::Lifespan::infinite());
```

### Use Cases

- **Sensor data**: Set lifespan to 2x the expected sample rate. Stale readings are useless.
- **Commands**: Infinite lifespan (default). Commands must never expire.
- **Market data**: Short lifespan. Old quotes are misleading.

---

## Liveliness

Defines how a writer asserts that it is still alive. Per the spec, if no assertion arrives within the lease duration the writer is considered "not alive" and readers are notified.

**Status:** enforced. Kind and lease compatibility are checked at discovery matching, and all three kinds are tracked at runtime: a writer whose lease expires is declared not alive, `on_liveliness_changed` / `on_liveliness_lost` fire, and `assert_liveliness()` is available on writers and the participant.

### Kinds (spec semantics)

| Kind | How It Works |
|------|-------------|
| `Automatic` | The middleware asserts liveliness automatically. |
| `ManualByParticipant` | The application asserts liveliness at participant level. |
| `ManualByTopic` | The application asserts liveliness on each writer individually. |

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
let qos = hdds::QoS::reliable().liveliness(hdds::dds::Liveliness::automatic_secs(5));

// Infinite lease (no liveliness tracking, default)
let qos = hdds::QoS::reliable().liveliness(hdds::dds::Liveliness::infinite());
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

**Status:** exclusive per-instance arbitration is enforced in the data path: the highest-strength writer owns each instance, samples from lower-strength writers are dropped, and a higher-strength writer takes over on its first sample. Ownership is released automatically when the owning writer unregisters, leaves the domain, loses its lease or liveliness, or misses its deadline, and the next-strongest live writer takes over the instance.

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

### Exclusive Ownership Example: Highest Strength Wins

```rust
// Primary controller (high strength -- owns the instance)
let primary_qos = hdds::QoS::reliable()
    .ownership_exclusive()
    .ownership_strength(100);
let primary = participant.topic::<Command>("robot/cmd")?.writer().qos(primary_qos).build()?;

// Backup controller (low strength -- its samples are dropped while the
// primary publishes; it takes over when the primary stops, unregisters,
// or loses liveliness)
let backup_qos = hdds::QoS::reliable()
    .ownership_exclusive()
    .ownership_strength(10);
let backup = participant.topic::<Command>("robot/cmd")?.writer().qos(backup_qos).build()?;
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
    hdds::dds::Partition::new(vec!["sensors".to_string(), "actuators".to_string()])
);

// Default partition (empty string -- matches other default partitions)
let qos = hdds::QoS::reliable().partition(hdds::dds::Partition::default());
```

### Matching Rules

For endpoints to match, they must share at least one partition name. Wildcard patterns (`*`, `?`) are supported in partition names per the DDS specification.

### Use Case: Multi-Tenant Isolation

```rust
// Building A sensors
let qos_a = hdds::QoS::best_effort().partition_single("building_a");
let writer_a = participant.topic::<Temperature>("temperature")?.writer().qos(qos_a).build()?;

// Building B sensors (isolated from A)
let qos_b = hdds::QoS::best_effort().partition_single("building_b");
let writer_b = participant.topic::<Temperature>("temperature")?.writer().qos(qos_b).build()?;

// Central reader (receives from both buildings)
let qos_central = hdds::QoS::best_effort()
    .add_partition("building_a")
    .add_partition("building_b");
let reader = participant.topic::<Temperature>("temperature")?.reader().qos(qos_central).build()?;
```

---

## LatencyBudget

Provides a hint about the maximum acceptable delay from write to delivery.

**Status:** partial. The offered <= requested compatibility check below is applied at discovery matching; the value has no delivery effect (no batching or scheduling).

### Builder Methods

```rust
// 10ms latency budget (critical data)
let qos = hdds::QoS::reliable().latency_budget_millis(10);

// 1-second latency budget (bulk data)
let qos = hdds::QoS::best_effort().latency_budget_secs(1);

// Using the LatencyBudget type directly
let qos = hdds::QoS::reliable().latency_budget(hdds::dds::LatencyBudget::from_millis(50));

// Zero latency budget (deliver ASAP, default)
let qos = hdds::QoS::reliable().latency_budget(hdds::dds::LatencyBudget::zero());
```

### Matching Rules

Per the DDS spec, the offered latency budget must be <= the requested latency budget. HDDS enforces this check at discovery matching: a writer offering a larger budget than the reader requests does not match (QoS incompatibility on `LATENCY_BUDGET`). The budget itself does not change delivery timing.

---

## TimeBasedFilter

Controls the minimum time between accepted samples on the reader side, tracked per instance. Samples arriving faster than the filter rate are silently discarded.

### Builder Methods

```rust
// Accept at most 10 samples per second (100ms separation)
let qos = hdds::QoS::best_effort().time_based_filter_millis(100);

// Accept at most 1 sample per second
let qos = hdds::QoS::best_effort().time_based_filter_secs(1);

// Using the TimeBasedFilter type directly
let qos = hdds::QoS::best_effort().time_based_filter(
    hdds::dds::TimeBasedFilter::from_millis(500)
);

// No filtering (accept all samples, default)
let qos = hdds::QoS::best_effort().time_based_filter(hdds::dds::TimeBasedFilter::zero());
```

### Use Case: High-Rate Sensor Throttling

```rust
// Writer publishes at 1000 Hz
let writer_qos = hdds::QoS::best_effort();
let writer = participant.topic::<SensorData>("imu")?.writer().qos(writer_qos).build()?;

// Display reader only needs 10 Hz
let display_qos = hdds::QoS::best_effort().time_based_filter_millis(100);
let display = participant.topic::<SensorData>("imu")?.reader().qos(display_qos).build()?;

// Logger reader needs full 1000 Hz
let logger_qos = hdds::QoS::reliable(); // no filter
let logger = participant.topic::<SensorData>("imu")?.reader().qos(logger_qos).build()?;
```

---

## TransportPriority

Provides a hint for network-level prioritization. Higher values indicate more important data.

**Status:** accepted and stored only. The value is not mapped to network-level mechanisms (DSCP/TOS, socket priority, VLAN PCP) and is not propagated in discovery. Socket DSCP is configured separately, per participant, through the transport options (`HDDS_DSCP`), independent of this QoS.

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
| `max_samples` | LENGTH_UNLIMITED | Maximum total samples across all instances |
| `max_instances` | LENGTH_UNLIMITED | Maximum number of instances (keyed topics) |
| `max_samples_per_instance` | LENGTH_UNLIMITED | Maximum samples per instance |
| `max_quota_bytes` | 100 MB | Maximum total payload bytes |

**Status:** enforced on the writer history cache: `max_samples` (oldest-eviction, or admission rejection under `KeepAll`), `max_instances`, `max_samples_per_instance`, and `max_quota_bytes`. On the reader side `max_samples`, `max_instances`, and `max_samples_per_instance` are enforced (admission under `KeepAll`, per-instance depth under `KeepLast`); `max_quota_bytes` is applied on the writer cache only. Under `KeepLast(n)` history the depth takes precedence, so `max_samples` acts as an independent bound only under `KeepAll`.

### Configuration

```rust
use hdds::qos::ResourceLimits;

// KEEP_LAST depth must be <= max_samples_per_instance (the default depth,
// 100, would make this QoS inconsistent).
let mut qos = hdds::QoS::reliable().keep_last(50);
qos.resource_limits = ResourceLimits {
    max_samples: 500,
    max_instances: 10,
    max_samples_per_instance: 50,
    max_quota_bytes: 5_000_000, // 5 MB
};
```

### Validation

DDS 1.4 2.2.3.18 and 2.2.3.19. Creating a DataWriter or a DataReader whose
QoS breaks one of these fails, naming the rule:

- every limit is > 0 or LENGTH_UNLIMITED (an unlimited value takes part in no
  comparison)
- `max_samples >= max_samples_per_instance`
- `KeepLast(depth)`: `depth <= max_samples_per_instance`

There is no rule on `max_samples_per_instance * max_instances`: `max_samples`
may be smaller than that product.

---

## DestinationOrder

Controls how samples are ordered when delivered to readers.

**Status:** enforced. A `BySourceTimestamp` reader orders samples per instance by source timestamp and discards samples older than the newest one already accepted for the instance; `ByReceptionTimestamp` (the default) delivers in arrival order. The offered kind >= requested kind compatibility check is applied at discovery matching.

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
    hdds::dds::DestinationOrder::by_source_timestamp()
);
```

### Use Case: Multi-Writer Temporal Consistency

When multiple writers publish to the same topic, `BySourceTimestamp` presents samples in source temporal order regardless of network delays: a late-arriving sample with an older source timestamp than the newest one already accepted for the instance is not delivered (see status above).

---

## Presentation

Controls how changes are presented to readers in terms of coherence and ordering.

### Access Scopes

| Scope | Description |
|-------|-------------|
| `Instance` | Each instance is independent. No transactional semantics (default). |
| `Topic` | All instances of a topic are presented together. Supports coherent snapshots. |
| `Group` | Multiple topics under one publisher are presented as a coherent set. |

**Status:** coherent access is enforced end-to-end at both Topic and Group scope (writer-side coherent-change gating, group-scope generation numbering, and a reader-side barrier that releases whole coherent sets). GROUP ordered access enforces Publisher sequence order across the Subscriber's DataReaders inside `begin_access`/`end_access`, for ordinary and coherent changes, over both local and RTPS delivery. A later change waits until the earlier change has been read or taken.

A durable reader's historical obligation comes only from announcements known
when it joins. A reader present before the Publisher's first traffic does not
turn that live traffic into replay. Later associations establish their own
announced history obligations.

There is no elapsed-wait or retry-count degradation of GROUP order or RELIABLE
delivery. While a live writer retains the missing data, the reader keeps its
order wait and the writer keeps repairing unaccepted data. A wait can end on a
GAP, a HEARTBEAT whose first sequence number passes the owed data, departure of
the concerned writer or participant, or the waiting sample's offered LIFESPAN
expiring from its source timestamp. LIFESPAN does not prove an unknown GSN hole
absent. Maintenance continues inside an access bracket, while application
publication remains subject to that bracket.

Writer and participant departure proofs are tied to the announcement captured
before the queued departure. Accepted rediscovery or authenticated returning
traffic revokes stale evidence. A participant departure can resolve an unknown
roster; an individual writer's departure cannot certify unknown members gone.
Already received reconstructible units remain ordered. An unavailable member
invalidates its entire coherent unit. SAMPLE_LOST reports identified received
or owed samples once, without controls or counts guessed from GSN holes.

RELIABLE ordered GROUP network admission keeps previously accepted bytes. When
memory or reader capacity is unavailable, new data is refused without receipt
credit; concurrent duplicates of a provisional admission cannot acknowledge it
either. Future units stay repairable until their predecessor can be staged.
Resource limits still apply: a head coherent unit larger than the available
reader/staging capacity cannot be accepted merely to end an order wait
(DDS 1.4 Sec.2.2.3.19). A unit already acknowledged in staging also remains owned
if the history cannot hold it whole. Under fixed limits an intrinsically
oversized unit can stay blocked; capacity failure is not absence proof and
fabricates neither receipt nor loss. TOPIC, INSTANCE and unordered GROUP keep
their existing whole-set resource rejection policy. Shared process pressure
also preserves charged loss markers, which can require refusal instead of
reclaiming another set.

GAP proofs use exact half-open intervals and compressed finite arithmetic runs.
At most 512 descriptors are retained per writer/reader pair, including sparse
alternating traces longer than 512 intervals. On genuinely irregular overflow,
the lowest proofs gating progress are retained; omitted positions remain
unknown until an actual protocol proof supplies the missing information.
A RELIABLE reader keeps a native GAP repairable until its own ordered cursor
has consumed the GAP's GSN interval. ACKNACK therefore requests omitted proofs
again after the retained prefix advances, even when TRANSIENT_LOCAL keeps an
older sample and HEARTBEAT firstSN stays unchanged. HEARTBEAT processing keeps
the repair range available without bypassing outstanding proof debt. Receipt
of a real copy after proven abandonment or source-time LIFESPAN expiry is still
credited and reported lost once; repairing that already abandoned sample again
cannot restore an already abandoned unit.

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
    hdds::dds::Presentation::new(
        hdds::dds::PresentationAccessScope::Topic,
        true,   // coherent_access
        true,   // ordered_access
    )
);
```

---

## DurabilityService

Configures the history cache of `Transient` and `Persistent` writers, controlling how many samples are stored for late-joining readers. It does not apply to `Volatile` or `TransientLocal` writers, whose history is bounded by History and ResourceLimits alone.

**Status:** enforced for `Transient` and `Persistent` writers only. The sizing fields (`history_depth`, `max_samples`, `max_instances`, `max_samples_per_instance`) are enforced on the durable writer's replay cache. `service_cleanup_delay` drives a cleanup timer that removes an instance once it has been disposed and unregistered by the writer, every matched reliable reader has acknowledged its latest change, and the delay has elapsed since the later of the two events; a delay of 0 (the default) disables timed cleanup. Replay suppresses an entire coherent set if history replacement removed one of its members, including surviving members in other writers' histories. Raw history remains available for RTPS repair. When a writer leaves retention, future snapshots of the entire shared set become ineligible. A complete composite already captured for one Subscriber keeps its owned bytes; independently captured partial composites do not qualify.

### Builder Methods

```rust
// Keep last 100 samples for late-joiners
let qos = hdds::QoS::reliable()
    .transient()
    .durability_service_keep_last(100, 1000, 10, 100);
    // Args: history_depth, max_samples, max_instances, max_samples_per_instance

// With cleanup delay (60 seconds)
let qos = hdds::QoS::reliable()
    .transient()
    .durability_service_cleanup_delay_secs(60);

// Using the DurabilityService type directly
let qos = hdds::QoS::reliable()
    .transient()
    .durability_service(hdds::dds::DurabilityService::keep_last(100, 1000, 10, 100));
```

---

## EntityFactory

Controls whether entities are automatically enabled when created.

**Status:** accepted and stored only. Entities are always created enabled and there is no `enable()` API, so `manual_enable` has no runtime effect.

### Builder Methods

```rust
// Auto-enable (default -- entities are active immediately)
let qos = hdds::QoS::reliable().entity_factory_auto_enable();

// Manual enable (spec semantics: entities start disabled -- not enforced)
let qos = hdds::QoS::reliable().entity_factory_manual_enable();

// Using the EntityFactory type directly
let qos = hdds::QoS::reliable().entity_factory(hdds::dds::EntityFactory::auto_enable());
let qos = hdds::QoS::reliable().entity_factory(hdds::dds::EntityFactory::manual_enable());
```

---

## WriterDataLifecycle

Controls automatic disposal of unregistered instances on the writer side.

**Status:** the `autodispose_unregistered_instances` flag is consulted on `unregister_instance()`: when true, the writer marks the instance disposed-and-unregistered; when false, it sends a plain unregister. Explicit `dispose()` calls are implemented separately and propagate instance state to readers.

### Builder Methods

```rust
// Auto-dispose on unregister (default value)
let qos = hdds::QoS::reliable().writer_data_lifecycle_auto_dispose();

// Keep instances alive after unregister
let qos = hdds::QoS::reliable().writer_data_lifecycle_manual_dispose();

// Using the WriterDataLifecycle type directly
let qos = hdds::QoS::reliable().writer_data_lifecycle(
    hdds::dds::WriterDataLifecycle::auto_dispose()
);
```

---

## ReaderDataLifecycle

Controls automatic purging of reader instances that are no longer alive.

**Status:** accepted and stored only. The autopurge delays have no runtime effect: no purge timer exists, and instances are not purged automatically.

### Builder Methods

```rust
// Keep all instances indefinitely (default)
let qos = hdds::QoS::reliable().reader_data_lifecycle_keep_all();

// Zero delays (spec semantics: purge as soon as an instance becomes
// NOT_ALIVE -- not enforced)
let qos = hdds::QoS::reliable().reader_data_lifecycle_immediate_cleanup();

// Custom delays (30 seconds for both nowriter and disposed)
let qos = hdds::QoS::reliable().reader_data_lifecycle_secs(30, 30);

// Using the ReaderDataLifecycle type directly
let qos = hdds::QoS::reliable().reader_data_lifecycle(
    hdds::dds::ReaderDataLifecycle::from_secs(60, 60)
);
```

---

## Metadata Policies

Opaque byte sequences attached to entities for application-specific purposes.

**Status:** UserData is partial: it is announced on writer and reader endpoints in SEDP (PID_USER_DATA), but no API returns a remote entity's value and nothing is carried in SPDP, so participant-level user data is not announced. GroupData and TopicData are accepted and stored in the local QoS only; they are not propagated in discovery.

### UserData

Attached to a DomainParticipant or entity for identification.

```rust
let qos = hdds::QoS::reliable()
    .user_data_bytes(b"version=1.0.5");

// Using the UserData type directly
let qos = hdds::QoS::reliable()
    .user_data(hdds::dds::UserData::new(b"my-app-metadata".to_vec()));
```

### GroupData

Attached to a Publisher or Subscriber.

```rust
let qos = hdds::QoS::reliable()
    .group_data_bytes(b"deployment=production");

let qos = hdds::QoS::reliable()
    .group_data(hdds::dds::GroupData::new(b"group-info".to_vec()));
```

### TopicData

Attached to a Topic.

```rust
let qos = hdds::QoS::reliable()
    .topic_data_bytes(b"schema=v2");

let qos = hdds::QoS::reliable()
    .topic_data(hdds::dds::TopicData::new(b"topic-info".to_vec()));
```

---

## QoS Compatibility

DDS uses a Request/Offered matching model. When a DataReader discovers a DataWriter on the same topic, the middleware checks that the writer's offered QoS is compatible with the reader's requested QoS. If incompatible, the endpoints do not match and no data flows between them.

### Compatibility Rules Summary

| Policy | Rule | Checked by HDDS |
|--------|------|-----------------|
| **Reliability** | Offered >= Requested (Reliable >= BestEffort) | Yes |
| **Durability** | Offered >= Requested (Persistent > TransientLocal > Volatile) | Yes |
| **Deadline** | Offered period <= Requested period | Yes |
| **LatencyBudget** | Offered duration <= Requested duration | Yes |
| **Liveliness** | Offered kind >= Requested kind; Offered lease <= Requested lease | Yes |
| **Ownership** | Must be identical (both Shared or both Exclusive) | Yes |
| **Partition** | Must share at least one partition name (wildcards supported); a mismatch is not reported as an incompatible-QoS status | Yes |
| **Presentation** | Offered scope >= Requested scope; a requested `coherent_access` / `ordered_access` must be offered | Yes |
| **DestinationOrder** | Offered kind >= Requested kind | Yes |

### Example: Incompatible QoS

```rust
// Writer offers BestEffort
let writer_qos = hdds::QoS::best_effort();
let writer = participant.topic::<SensorData>("topic")?.writer().qos(writer_qos).build()?;

// Reader requests Reliable -- MISMATCH! Endpoints will NOT match.
let reader_qos = hdds::QoS::reliable();
let reader = participant.topic::<SensorData>("topic")?.reader().qos(reader_qos).build()?;
// reader will never receive data from this writer
```

### Detecting Incompatibility

Attach a listener and implement `on_requested_incompatible_qos` (readers) or `on_offered_incompatible_qos` (writers) to be notified when a discovered endpoint fails QoS matching.

---

## Common Patterns

### Pattern 1: High-Frequency Sensor Data

Low-latency, loss-tolerant. Latest value matters most.

```rust
let qos = hdds::QoS::best_effort()
    .keep_last(1)
    .lifespan_millis(500)
    .time_based_filter_millis(10);

let writer = participant.topic::<SensorReading>("imu/accel")?.writer().qos(qos.clone()).build()?;
let reader = participant.topic::<SensorReading>("imu/accel")?.reader().qos(qos).build()?;
```

### Pattern 2: Command / Control

Every message must be delivered. No losses, no expiration.

```rust
let qos = hdds::QoS::reliable()
    .keep_last(100)
    .deadline_secs(1)
    .liveliness_automatic_secs(5);

let writer = participant.topic::<Command>("robot/cmd")?.writer().qos(qos.clone()).build()?;
let reader = participant.topic::<Command>("robot/cmd")?.reader().qos(qos).build()?;
```

### Pattern 3: State Replication (Late Joiners)

New subscribers get the current state immediately upon joining.

```rust
let qos = hdds::QoS::reliable()
    .transient_local()
    .keep_last(1)
    .ownership_exclusive()
    .ownership_strength(100);

let writer = participant.topic::<SystemState>("system/state")?.writer().qos(qos.clone()).build()?;
let reader = participant.topic::<SystemState>("system/state")?.reader().qos(qos).build()?;
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

let writer = participant.topic::<AuditEvent>("audit/events")?.writer().qos(qos).build()?;
```

Note: `persistent()` in-core behaves like `transient_local()` (see [Durability](#durability)); disk-backed storage requires the separate `hdds-persistence` service.

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

// Backup writer (low strength)
let backup_qos = hdds::QoS::reliable()
    .ownership_exclusive()
    .ownership_strength(10)
    .liveliness_automatic_secs(2);
```

Note: exclusive arbitration keeps the backup silenced while the primary publishes. When the primary unregisters, leaves, or loses liveliness (here a 2-second lease), the backup takes over the instance (see [Liveliness](#liveliness) and [Ownership](#ownership-and-ownershipstrength) status).

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
// Load the default writer/reader profile from a FastDDS XML file
let qos = hdds::QoS::load_fastdds("fastdds_profiles.xml")?;

// Same loader; FastDDS is the only vendor XML format implemented
let qos = hdds::QoS::from_xml("profile.xml")?;
```

### ProfileLoader (Auto-Detect Format)

The `ProfileLoader` automatically detects the file format from extension or content. For XML input the profile name is ignored and the profile marked `is_default_profile="true"` is used.

```rust
use hdds::dds::qos::loaders::ProfileLoader;

// Auto-detect by extension (.yaml, .yml, .xml)
let qos = ProfileLoader::load("config.yaml", Some("reliable"))?;
let qos = ProfileLoader::load("fastdds_profiles.xml", None)?;

// Auto-detect from string content
let qos = ProfileLoader::load_from_str_auto(content, Some("my_profile"))?;
```

### Supported YAML QoS Fields

| Field | Type | Values |
|-------|------|--------|
| `reliability` | String | `RELIABLE`, `BEST_EFFORT` |
| `max_blocking_time_ms` | u64 | Maximum blocking time of a reliable `write()` in milliseconds |
| `durability` | String | `VOLATILE`, `TRANSIENT_LOCAL`, `TRANSIENT`, `PERSISTENT` |
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
| `keep_last(n)` | History | KeepLast(n) |
| `keep_all()` | History | KeepAll |
| `max_blocking_time(d)` | Reliability | Maximum time a reliable `write()` may block |
| `volatile()` | Durability | Volatile |
| `transient_local()` | Durability | TransientLocal |
| `transient()` | Durability | Transient |
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
| `data_representation_xcdr1()` / `data_representation_xcdr2()` | Representation | Offered data representation |
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
