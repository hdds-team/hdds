# HDDS SDK Features

> **Last Updated:** 2026-01-22
> **Version:** 1.0.5

This document provides an accurate overview of HDDS SDK features across all supported languages.

## Feature Matrix

### Core Entities

| Feature | Rust | C | C++ | Python | Notes |
|---------|:----:|:-:|:---:|:------:|-------|
| Participant | ✅ | ✅ | ✅ | ✅ | Full support |
| Publisher | ✅ | ✅ | ✅ | ✅ | Full support |
| Subscriber | ✅ | ✅ | ✅ | ✅ | Full support |
| DataWriter | ✅ | ✅ | ✅ | ✅ | Typed + Raw |
| DataReader | ✅ | ✅ | ✅ | ✅ | Typed + Raw |
| Topic | ✅ | ✅ | ✅ | ✅ | Full support |
| ContentFilteredTopic | ⚠️ | ❌ | ❌ | ❌ | Rust internal only |

### QoS Policies (22 policies)

| Policy | Rust | C | C++ | Python | Notes |
|--------|:----:|:-:|:---:|:------:|-------|
| Reliability | ✅ | ✅ | ✅ | ✅ | RELIABLE/BEST_EFFORT |
| Durability | ✅ | ✅ | ✅ | ✅ | VOLATILE/TRANSIENT_LOCAL/PERSISTENT |
| History | ✅ | ✅ | ✅ | ✅ | KEEP_LAST(n)/KEEP_ALL |
| Deadline | ✅ | ✅ | ✅ | ✅ | Nanosecond precision |
| Lifespan | ✅ | ✅ | ✅ | ✅ | Nanosecond precision |
| Liveliness | ✅ | ✅ | ✅ | ✅ | AUTOMATIC/MANUAL_BY_PARTICIPANT/MANUAL_BY_TOPIC |
| Ownership | ✅ | ✅ | ✅ | ✅ | SHARED/EXCLUSIVE |
| Ownership Strength | ✅ | ✅ | ✅ | ✅ | Integer priority |
| Partition | ✅ | ✅ | ✅ | ✅ | Multiple partitions |
| Time-Based Filter | ✅ | ✅ | ✅ | ✅ | Minimum separation |
| Latency Budget | ✅ | ✅ | ✅ | ✅ | Hint for optimization |
| Transport Priority | ✅ | ✅ | ✅ | ✅ | Integer priority |
| Resource Limits | ✅ | ✅ | ✅ | ✅ | max_samples, max_instances, max_samples_per_instance |

### WaitSet & Conditions

| Feature | Rust | C | C++ | Python | Notes |
|---------|:----:|:-:|:---:|:------:|-------|
| WaitSet | ✅ | ✅ | ✅ | ✅ | Full support |
| GuardCondition | ✅ | ✅ | ✅ | ✅ | Manual trigger |
| StatusCondition | ✅ | ✅ | ✅ | ✅ | Entity status changes |
| ReadCondition | ⚠️ | ❌ | ❌ | ❌ | Rust internal only |
| QueryCondition | ❌ | ❌ | ❌ | ❌ | Not implemented |

### Listeners (Callbacks)

| Feature | Rust | C | C++ | Python | Notes |
|---------|:----:|:-:|:---:|:------:|-------|
| DataReaderListener | ❌ | ❌ | ❌ | ❌ | Use WaitSet instead |
| DataWriterListener | ❌ | ❌ | ❌ | ❌ | Use WaitSet instead |
| SubscriberListener | ❌ | ❌ | ❌ | ❌ | Not implemented |
| PublisherListener | ❌ | ❌ | ❌ | ❌ | Not implemented |
| ParticipantListener | ❌ | ❌ | ❌ | ❌ | Not implemented |

### Telemetry & Monitoring

| Feature | Rust | C | C++ | Python | Notes |
|---------|:----:|:-:|:---:|:------:|-------|
| Metrics Collection | ✅ | ✅ | ✅ | ✅ | Full support |
| Prometheus Exporter | ✅ | ✅ | ✅ | ✅ | HTTP endpoint |
| Latency Recording | ✅ | ✅ | ✅ | ✅ | Nanosecond precision |
| Snapshot API | ✅ | ✅ | ✅ | ✅ | Point-in-time metrics |

### Logging

| Feature | Rust | C | C++ | Python | Notes |
|---------|:----:|:-:|:---:|:------:|-------|
| Init from level | ✅ | ✅ | ✅ | ✅ | ERROR/WARN/INFO/DEBUG/TRACE |
| Init from env | ✅ | ✅ | ✅ | ✅ | RUST_LOG compatible |
| Filter by module | ✅ | ✅ | ✅ | ✅ | e.g., "hdds::discovery=debug" |

### Discovery

| Feature | Rust | C | C++ | Python | Notes |
|---------|:----:|:-:|:---:|:------:|-------|
| SPDP (Participant) | ✅ | ✅ | ✅ | ✅ | Automatic multicast |
| SEDP (Endpoint) | ✅ | ✅ | ✅ | ✅ | Automatic exchange |
| Static Peers | ✅ | ⚠️ | ⚠️ | ⚠️ | Rust builder only |

### Security (DDS Security v1.1)

| Feature | Rust | C | C++ | Python | Notes |
|---------|:----:|:-:|:---:|:------:|-------|
| Authentication | ✅ | ❌ | ❌ | ❌ | Rust internal, not exported |
| Access Control | ✅ | ❌ | ❌ | ❌ | Rust internal, not exported |
| Cryptographic | ✅ | ❌ | ❌ | ❌ | Rust internal, not exported |

### Transport

| Feature | Rust | C | C++ | Python | Notes |
|---------|:----:|:-:|:---:|:------:|-------|
| UDP Multicast | ✅ | ✅ | ✅ | ✅ | Default transport |
| UDP Unicast | ✅ | ✅ | ✅ | ✅ | Automatic |
| IntraProcess | ✅ | ❌ | ❌ | ❌ | Rust only |
| Shared Memory | ⚠️ | ❌ | ❌ | ❌ | Experimental |
| TCP | ⚠️ | ❌ | ❌ | ❌ | Experimental |

### Dynamic Data

| Feature | Rust | C | C++ | Python | Notes |
|---------|:----:|:-:|:---:|:------:|-------|
| DynamicData | ⚠️ | ❌ | ❌ | ❌ | Rust internal only |
| DynamicType | ⚠️ | ❌ | ❌ | ❌ | Rust internal only |
| TypeBuilder | ❌ | ❌ | ❌ | ❌ | Not implemented |

---

## C API Summary (`hdds.h`)

The C API exports **80+ functions** covering:

```c
// Participant (7 functions)
hdds_participant_create()
hdds_participant_create_with_transport()
hdds_participant_destroy()
hdds_participant_name()
hdds_participant_domain_id()
hdds_participant_id()
hdds_participant_graph_guard_condition()

// Publisher/Subscriber (8 functions)
hdds_publisher_create()
hdds_publisher_create_with_qos()
hdds_publisher_destroy()
hdds_publisher_create_writer()
hdds_publisher_create_writer_with_qos()
hdds_subscriber_create()
hdds_subscriber_create_with_qos()
hdds_subscriber_destroy()
hdds_subscriber_create_reader()
hdds_subscriber_create_reader_with_qos()

// Writer/Reader (10 functions)
hdds_writer_create()
hdds_writer_create_with_qos()
hdds_writer_write()
hdds_writer_destroy()
hdds_writer_topic_name()
hdds_reader_create()
hdds_reader_create_with_qos()
hdds_reader_take()
hdds_reader_destroy()
hdds_reader_topic_name()
hdds_reader_get_status_condition()

// QoS (30+ functions)
hdds_qos_default()
hdds_qos_best_effort()
hdds_qos_reliable()
hdds_qos_rti_defaults()
hdds_qos_from_xml()
hdds_qos_set_*()  // All 22 policies
hdds_qos_get_*()  // Corresponding getters

// WaitSet (7 functions)
hdds_waitset_create()
hdds_waitset_destroy()
hdds_waitset_attach_status_condition()
hdds_waitset_attach_guard_condition()
hdds_waitset_detach_condition()
hdds_waitset_wait()
hdds_guard_condition_create()
hdds_guard_condition_release()
hdds_guard_condition_set_trigger()

// Telemetry (7 functions)
hdds_telemetry_init()
hdds_telemetry_get()
hdds_telemetry_release()
hdds_telemetry_snapshot()
hdds_telemetry_record_latency()
hdds_telemetry_start_exporter()
hdds_telemetry_stop_exporter()

// Logging (3 functions)
hdds_logging_init()
hdds_logging_init_env()
hdds_logging_init_with_filter()
```

---

## C++ API Summary (`hdds.hpp`)

Fluent builder API wrapping the C API:

```cpp
// Participant
auto participant = hdds::Participant::create("MyApp")
    .domain_id(0)
    .transport(hdds::Transport::UdpMulticast)
    .build();

// QoS Builder
auto qos = hdds::QoS::reliable()
    .history_depth(100)
    .deadline(std::chrono::milliseconds(100))
    .partition("sensors")
    .build();

// Writer/Reader
auto writer = participant.create_writer<MyType>("topic", qos);
auto reader = participant.create_reader<MyType>("topic", qos);
```

---

## Python API Summary (`hdds.py`)

Pythonic API with context managers:

```python
from hdds import Participant, QoS, TransportMode

# Participant
with Participant("MyApp", domain_id=0, transport=TransportMode.UdpMulticast) as p:
    # QoS
    qos = QoS.reliable().history_depth(100).deadline_ms(100)

    # Writer/Reader
    writer = p.create_writer("topic", qos=qos)
    reader = p.create_reader("topic", qos=qos)

    # Pub/Sub
    writer.write({"message": "hello"})
    data = reader.take()
```

---

## What's NOT Exported (Roadmap)

These features exist in the Rust core but are not yet exposed in SDK APIs:

| Feature | Priority | Notes |
|---------|----------|-------|
| Listeners (callbacks) | P1 | Use WaitSet pattern for now |
| ContentFilteredTopic | P2 | SQL-like filtering |
| Dynamic Data | P2 | Runtime type introspection |
| Security APIs | P2 | Authentication, encryption |
| Transport Config | P3 | UDP/TCP/SHM tuning |

---

## SDK Samples

See [FEATURES_SDK_SAMPLES.md](./FEATURES_SDK_SAMPLES.md) for complete sample documentation.

| Category | Samples | Description |
|----------|---------|-------------|
| 01_basics | 4 | Hello world, pub/sub fundamentals |
| 02_qos | 9 | All QoS policies demonstrated |
| 03_types | 10 | IDL types (primitives, sequences, maps, etc.) |
| 04_discovery | 4 | SPDP/SEDP, partitions, static peers |
| 05_security | 4 | Auth, encryption, access control |
| 06_performance | 4 | Throughput, latency, batching, zero-copy |
| 07_advanced | 4 | WaitSets, content filters, request-reply |
| 08_interop | 2 | Cross-vendor interop (FastDDS, RTI, Cyclone) |
| 09_ros2 | 2 | ROS2 integration patterns |
| 10_usecases | 2 | Robot telemetry, IoT sensor network |

**Total: 45 samples** across 10 categories
