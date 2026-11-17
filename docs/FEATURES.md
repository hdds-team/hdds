# HDDS SDK Features

This document gives an overview of HDDS SDK features across the supported
languages (Rust core, C, C++, Python). It describes the current state of the
tree; a language reference page (`api/rust.md`, `api/c.md`, `api/cpp.md`,
`api/python.md`) is authoritative for the details of one SDK.

## Feature Matrix

### Core Entities

| Feature | Rust | C | C++ | Python | Notes |
|---------|:----:|:-:|:---:|:------:|-------|
| Participant | Yes | Yes | Yes | Yes | Full support |
| Publisher | Yes | Yes | Yes | Yes | Full support |
| Subscriber | Yes | Yes | Yes | Yes | Full support |
| DataWriter | Yes | Yes | Yes | Yes | Rust: typed and raw. C: raw CDR bytes. C++: typed and raw. Python: bytes, or typed through generated classes |
| DataReader | Yes | Yes | Yes | Yes | Same split as DataWriter |
| Topic | Yes | No | No | No | Rust: `participant.topic::<T>(name)`. C, C++ and Python pass the topic name when creating a writer or reader |
| ContentFilteredTopic | Yes | Yes | No | No | Filter runs before the reader, intra-process and network; C evaluates through a dynamic type descriptor ([details](read-query-conditions.md)) |

### QoS Policies

| Policy | Rust | C | C++ | Python | Notes |
|--------|:----:|:-:|:---:|:------:|-------|
| Reliability | Yes | Yes | Yes | Yes | RELIABLE/BEST_EFFORT |
| Durability | Yes | Yes | Yes | Yes | VOLATILE/TRANSIENT_LOCAL/PERSISTENT |
| History | Yes | Yes | Yes | Yes | KEEP_LAST(n)/KEEP_ALL |
| Deadline | Yes | Yes | Yes | Yes | Duration |
| Lifespan | Yes | Yes | Yes | Yes | Duration |
| Liveliness | Yes | Yes | Yes | Yes | AUTOMATIC/MANUAL_BY_PARTICIPANT/MANUAL_BY_TOPIC |
| Ownership | Yes | Yes | Yes | Yes | SHARED/EXCLUSIVE |
| Ownership Strength | Yes | Yes | Yes | Yes | Integer priority |
| Partition | Yes | Yes | Yes | Yes | Multiple partitions |
| Time-Based Filter | Yes | Yes | Yes | Yes | Minimum separation |
| Latency Budget | Yes | Yes | Yes | Yes | Hint for optimization |
| Transport Priority | Yes | Yes | Yes | Yes | Integer priority |
| Resource Limits | Yes | Yes | Yes | Yes | max_samples, max_instances, max_samples_per_instance |

Rust carries all 22 DDS v1.4 policies in `QoS` (the repository README gives
the runtime status of each one). The table lists the policies every SDK sets;
the C, C++ and Python SDKs also expose RELIABILITY `max_blocking_time` and
DATA_REPRESENTATION, and cover the remaining policies to a different extent:
see the API reference of each language.

### WaitSet & Conditions

| Feature | Rust | C | C++ | Python | Notes |
|---------|:----:|:-:|:---:|:------:|-------|
| WaitSet | Yes | Yes | Yes | Yes | Full support |
| GuardCondition | Yes | Yes | Yes | Yes | Manual trigger |
| StatusCondition | Yes | Yes | Yes | Yes | Entity status changes |
| ReadCondition | Yes | Yes | No | No | Sample/view/instance masks, WaitSet wake, `take_w_condition` / `read_w_condition` ([details](read-query-conditions.md)) |
| QueryCondition | Yes | Yes | No | No | `filter` module SQL subset with `%n` parameters; C needs a dynamic type descriptor ([details](read-query-conditions.md)) |

### Listeners (Callbacks)

| Feature | Rust | C | C++ | Python | Notes |
|---------|:----:|:-:|:---:|:------:|-------|
| DataReaderListener | Yes | Yes | Yes | Yes | Installable at runtime (`set_listener`); the statuses each SDK delivers are listed in its API reference ([C contract](api/c.md#listeners)) |
| DataWriterListener | Yes | Yes | Yes | Yes | Same: see the API reference of each language |
| SubscriberListener | No | No | No | No | Not implemented |
| PublisherListener | No | No | No | No | Not implemented |
| ParticipantListener | No | No | No | No | Not implemented |

### Telemetry & Monitoring

| Feature | Rust | C | C++ | Python | Notes |
|---------|:----:|:-:|:---:|:------:|-------|
| Metrics Collection | Yes | Yes | Yes | Yes | Rust: `hdds::telemetry` |
| Telemetry Exporter | Yes | Yes | Yes | Yes | TCP server streaming HDMX binary frames (for HDDS Viewer); not an HTTP or Prometheus endpoint |
| Latency Recording | Yes | Yes | Yes | Yes | Start and end timestamps in nanoseconds |
| Snapshot API | Yes | Yes | Yes | Yes | Point-in-time metrics |

### Logging

| Feature | Rust | C | C++ | Python | Notes |
|---------|:----:|:-:|:---:|:------:|-------|
| Init from level | Yes | Yes | Yes | Yes | Rust: `hdds::logging::init_logger`, behind the `logging` Cargo feature |
| Init from env | No | Yes | Yes | Yes | `RUST_LOG` compatible. In Rust, install a `log`-compatible logger of your choice |
| Filter by module | No | Yes | Yes | Yes | e.g., "hdds=debug" (C: `hdds_logging_init_with_filter`) |

### Discovery

| Feature | Rust | C | C++ | Python | Notes |
|---------|:----:|:-:|:---:|:------:|-------|
| SPDP (Participant) | Yes | Yes | Yes | Yes | Automatic multicast |
| SEDP (Endpoint) | Yes | Yes | Yes | Yes | Automatic exchange |
| Static Peers | Yes | Yes | No | No | Rust: `add_static_peer` on the participant builder. C: `hdds_config_add_static_peer` |

### Security (DDS Security v1.1, HDDS-to-HDDS)

| Feature | Rust | C | C++ | Python | Notes |
|---------|:----:|:-:|:---:|:------:|-------|
| Authentication | Yes | Yes | No | No | Rust: `security` Cargo feature. C: `hdds_security_config_*`, needs a library built with the `security` feature of `hdds-c`. No C++ or Python wrapper |
| Access Control | Yes | Yes | No | No | Same |
| Cryptographic | Yes | Yes | No | No | Same. Cross-vendor security interoperability is not covered ([security guide](security-guide.md)) |

### Transport

| Feature | Rust | C | C++ | Python | Notes |
|---------|:----:|:-:|:---:|:------:|-------|
| UDP Multicast | Yes | Yes | Yes | Yes | Default transport |
| UDP Unicast | Yes | Yes | Yes | Yes | Automatic |
| IntraProcess | Yes | Yes | Yes | Yes | Endpoints of one process only |
| Shared Memory | Yes | Yes | No | No | On by default for qualifying same-host BEST_EFFORT pairs. Configurable in Rust (`shm_prefer`, `shm_disable`) and C (`hdds_config_set_shm_policy`) |
| TCP | Partial | Partial | No | No | HDDS-to-HDDS building block; `DataWriter::write` stays on UDP ([getting started](getting-started.md#tcp-building-block)). Rust: manual `tcp_connect` / `tcp_send`. C: configuration only (`hdds_config_enable_tcp`, `hdds_config_add_tcp_peer`, TLS setters) |

### Dynamic Data

| Feature | Rust | C | C++ | Python | Notes |
|---------|:----:|:-:|:---:|:------:|-------|
| DynamicData | Yes | Yes | No | No | Rust: `hdds::dynamic::DynamicData`. C: `hdds_dynamic_data_*` (local get/set and CDR encode/decode, see `sdk/c/DYNAMIC_FILTER.md`) |
| DynamicType | Yes | Yes | No | No | Rust: `hdds::dynamic::TypeDescriptor`. C: `HddsTypeDescriptor` |
| TypeBuilder | Yes | Yes | No | No | Rust: `TypeDescriptorBuilder`. C: `hdds_type_builder_*` |

---

## C API Summary (`hdds.h`)

The header `sdk/c/include/hdds.h` declares a few hundred `hdds_*` functions.
Besides the core entities below it covers listeners, read and query
conditions, content-filtered topics, a participant configuration API
(`hdds_config_*`), dynamic types, optional security and RPC, and the ROS 2
(`rmw`) entry points. Excerpt of the core calls:

```c
// Participant
hdds_participant_create()
hdds_participant_create_with_transport()
hdds_participant_destroy()
hdds_participant_name()
hdds_participant_domain_id()
hdds_participant_id()
hdds_participant_graph_guard_condition()

// Publisher/Subscriber
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

// Writer/Reader
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

// QoS
hdds_qos_default()
hdds_qos_best_effort()
hdds_qos_reliable()
hdds_qos_from_xml()
hdds_qos_set_*()  // setters for the policies in the table above
hdds_qos_get_*()  // corresponding getters

// WaitSet
hdds_waitset_create()
hdds_waitset_destroy()
hdds_waitset_attach_status_condition()
hdds_waitset_attach_guard_condition()
hdds_waitset_detach_condition()
hdds_waitset_wait()
hdds_guard_condition_create()
hdds_guard_condition_release()
hdds_guard_condition_set_trigger()

// Telemetry
hdds_telemetry_init()
hdds_telemetry_get()
hdds_telemetry_release()
hdds_telemetry_snapshot()
hdds_telemetry_record_latency()
hdds_telemetry_start_exporter()
hdds_telemetry_stop_exporter()

// Logging
hdds_logging_init()
hdds_logging_init_env()
hdds_logging_init_with_filter()
```

---

## C++ API Summary (`hdds.hpp`)

C++17 RAII classes over the C API (headers in `sdk/cxx/include`, static
library `hdds_cxx`). QoS setters chain; types come from `hddsgen gen cpp`:

```cpp
#include <chrono>
#include <hdds.hpp>
#include "HelloWorld.hpp"   // generated by hddsgen

// Participant (transport and domain id are constructor arguments)
hdds::Participant participant("MyApp", hdds::TransportMode::UdpMulticast, 0);

// QoS
auto qos = hdds::QoS::reliable()
    .history_depth(100)
    .deadline(std::chrono::milliseconds(100))
    .partition("sensors");

// Writer/Reader
auto writer = participant.create_writer<my_app::HelloWorld>("topic", qos);
auto reader = participant.create_reader<my_app::HelloWorld>("topic", qos);
```

---

## Python API Summary (`hdds` package)

Pure-Python `ctypes` bindings to `libhdds_c.so`, with context managers. The
raw API moves `bytes`; typed access goes through `write_typed()` /
`take_typed()` with generated classes:

```python
from hdds import Participant, QoS, TransportMode

# Participant
with Participant("MyApp", domain_id=0, transport=TransportMode.UDP_MULTICAST) as p:
    # QoS
    qos = QoS.reliable().history_depth(100).deadline_ms(100)

    # Writer/Reader
    writer = p.create_writer("topic", qos=qos)
    reader = p.create_reader("topic", qos=qos)

    # Pub/Sub
    writer.write(b"hello")
    data = reader.take()   # bytes, or None when nothing is available
```

---

## Not Available in Every SDK

These parts of the Rust core are not exposed by every SDK today:

| Feature | Rust | C | C++ | Python |
|---------|:----:|:-:|:---:|:------:|
| ContentFilteredTopic, ReadCondition, QueryCondition | Yes | Yes | No | No ([details](read-query-conditions.md)) |
| Dynamic types and data | Yes | Yes (local, not bound to readers and writers) | No | No |
| Security configuration | Yes | Yes (library built with `security`) | No | No |
| Transport configuration (TCP, QUIC, TLS) | Yes | TCP and TLS configuration | Use the C API | No |

---

## SDK Samples

The complete sample sources live in the `sdk/samples/` directory of the
repository. Types are generated from `sdk/samples/idl/` with
`sdk/samples/scripts/generate.sh` (see [Getting Started](getting-started.md#7-running-the-examples)).

| Category | Rust programs | Description |
|----------|:-------------:|-------------|
| 01_basics | 4 | Hello world, instance keys, multi-topic, multi-participant |
| 02_qos | 14 | Reliable, best effort, transient local, deadline, liveliness, ownership, partition, history, lifespan, latency budget, time-based filter, transport priority, resource limits |
| 03_types | 10 | IDL types (primitives, strings, sequences, arrays, maps, enums, unions, nested structs, optional fields, bitsets) |
| 04_discovery | 4 | Simple discovery, discovery listeners, partitions, static peers |
| 05_security | 4 | Authentication, encryption, access control, secure discovery |
| 06_performance | 4 | Throughput, latency, batching, zero-copy |
| 07_advanced | 4 | WaitSets, content filter, request-reply, dynamic data |
| 08_interop | 2 | String interop, discovery test |
| 09_ros2 | 2 | String talker/listener, pose publisher |
| 10_usecases | 2 | Robot telemetry, sensor network |
| 11_embedded | 2 | ARM64 hello, ARM64 latency |

The same categories exist for C, C++ and Python (not every category in every
language), and `12_typescript` holds the TypeScript samples.
