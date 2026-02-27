# Migration Guide: FastDDS / CycloneDDS to HDDS

This guide helps developers migrating existing FastDDS (eProsima) or CycloneDDS
(Eclipse) applications to HDDS. It covers API mapping, QoS translation,
transport configuration, and common patterns.

---

## Table of Contents

1. [API Comparison Table](#1-api-comparison-table)
2. [Key Differences](#2-key-differences)
3. [QoS Mapping](#3-qos-mapping)
4. [Transport Configuration](#4-transport-configuration)
5. [Common Patterns](#5-common-patterns)
6. [IDL Workflow](#6-idl-workflow)

---

## 1. API Comparison Table

### Entity Creation

| Concept | FastDDS (C++) | CycloneDDS (C) | HDDS (Rust) |
|---------|---------------|-----------------|-------------|
| Create participant | `DomainParticipantFactory::get_instance()->create_participant(0, qos)` | `dds_create_participant(0, NULL, NULL)` | `Participant::builder("name").domain_id(0).build()?` |
| Create topic | `participant->create_topic("T", "Type", qos)` | `dds_create_topic(p, &desc, "T", NULL, NULL)` | Implicit -- created by `create_writer` / `create_reader` |
| Create publisher | `participant->create_publisher(qos)` | N/A (flat API) | Implicit -- managed internally |
| Create subscriber | `participant->create_subscriber(qos)` | N/A (flat API) | Implicit -- managed internally |
| Create writer | `publisher->create_datawriter(topic, qos)` | `dds_create_writer(p, topic, qos, NULL)` | `participant.create_writer::<T>("topic", qos)?` |
| Create reader | `subscriber->create_datareader(topic, qos)` | `dds_create_reader(p, topic, qos, NULL)` | `participant.create_reader::<T>("topic", qos)?` |

### Data Operations

| Operation | FastDDS (C++) | CycloneDDS (C) | HDDS (Rust) |
|-----------|---------------|-----------------|-------------|
| Write | `writer->write(&sample)` | `dds_write(writer, &sample)` | `writer.write(&sample)?` |
| Take (remove) | `reader->take_next_sample(&sample, &info)` | `dds_take(reader, &samples, &infos, n, n)` | `reader.take()?` returns `Result<Option<T>>` |
| Read (peek) | `reader->read_next_sample(&sample, &info)` | `dds_read(reader, &samples, &infos, n, n)` | `reader.read()?` returns `Result<Option<T>>` |
| Wait for data | `StatusCondition + WaitSet` | `dds_waitset_wait(ws, ...)` | `waitset.wait(Some(timeout))?` |

### Entity Lifecycle

| Operation | FastDDS (C++) | CycloneDDS (C) | HDDS (Rust) |
|-----------|---------------|-----------------|-------------|
| Destroy participant | `DomainParticipantFactory::delete_participant(p)` | `dds_delete(participant)` | Automatic via `Drop` (when `Arc` refcount reaches zero) |
| Destroy writer | `publisher->delete_datawriter(writer)` | `dds_delete(writer)` | Automatic via `Drop` |
| Destroy reader | `subscriber->delete_datareader(reader)` | `dds_delete(reader)` | Automatic via `Drop` |
| Destroy topic | `participant->delete_topic(topic)` | `dds_delete(topic)` | Automatic via `Drop` |

### QoS Construction

| Operation | FastDDS (C++) | CycloneDDS (C) | HDDS (Rust) |
|-----------|---------------|-----------------|-------------|
| Default QoS | `DATAWRITER_QOS_DEFAULT` | `dds_create_qos()` | `QoS::default()` (best-effort) |
| Reliable | `qos.reliability().kind = RELIABLE_RELIABILITY_QOS` | `dds_qset_reliability(q, DDS_RELIABILITY_RELIABLE, ...)` | `QoS::reliable()` |
| Best effort | `qos.reliability().kind = BEST_EFFORT_RELIABILITY_QOS` | `dds_qset_reliability(q, DDS_RELIABILITY_BEST_EFFORT, 0)` | `QoS::best_effort()` |
| Transient local | `qos.durability().kind = TRANSIENT_LOCAL_DURABILITY_QOS` | `dds_qset_durability(q, DDS_DURABILITY_TRANSIENT_LOCAL)` | `.transient_local()` |
| History depth | `qos.history().depth = 10` | `dds_qset_history(q, DDS_HISTORY_KEEP_LAST, 10)` | `.keep_last(10)` |

---

## 2. Key Differences

### 2.1 Ownership Model

**FastDDS/CycloneDDS**: Manual memory management. You create entities, store raw
pointers, and explicitly delete them in the correct order (reader before
subscriber before participant). Forgetting to delete causes resource leaks.

**HDDS**: Rust ownership. Entities are returned as owned types (`DataWriter<T>`,
`DataReader<T>`) or `Arc<Participant>`. When they go out of scope, cleanup
happens automatically via `Drop`. No manual deletion is needed.

```rust
// HDDS: entities are automatically cleaned up
{
    let participant = hdds::Participant::builder("app")
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()?;

    let writer = participant.create_writer::<MyData>("topic", hdds::QoS::default())?;
    writer.write(&data)?;

} // writer and participant are dropped here -- cleanup is automatic
```

### 2.2 Builder Pattern (Not Setter Chains)

**FastDDS**: Mutable QoS structs with individual field setters.

```cpp
DataWriterQos wqos;
wqos.reliability().kind = RELIABLE_RELIABILITY_QOS;
wqos.durability().kind = TRANSIENT_LOCAL_DURABILITY_QOS;
wqos.history().kind = KEEP_LAST_HISTORY_QOS;
wqos.history().depth = 10;
```

**HDDS**: Fluent builder with method chaining. The QoS struct is consumed and
returned at each step.

```rust
let qos = hdds::QoS::reliable()
    .transient_local()
    .keep_last(10);
```

The same builder pattern applies to the Participant:

```rust
let participant = hdds::Participant::builder("app")
    .with_transport(hdds::TransportMode::UdpMulticast)
    .domain_id(0)
    .with_tcp(7410)
    .build()?;
```

### 2.3 Error Handling

**FastDDS**: Return codes (`ReturnCode_t`). Easy to ignore.

```cpp
ReturnCode_t ret = writer->write(&sample);
if (ret != ReturnCode_t::RETCODE_OK) {
    // handle error
}
```

**CycloneDDS**: Integer return codes. Negative values indicate errors.

```c
dds_return_t rc = dds_write(writer, &sample);
if (rc < 0) { /* handle error */ }
```

**HDDS**: `Result<T, hdds::Error>`. The compiler enforces that you handle errors
via `?` or `match`. Unhandled `Result` values produce a compiler warning.

```rust
// Propagate with ?
writer.write(&msg)?;

// Or handle explicitly
match writer.write(&msg) {
    Ok(()) => println!("sent"),
    Err(hdds::Error::WouldBlock) => println!("buffer full"),
    Err(e) => eprintln!("write failed: {:?}", e),
}
```

### 2.4 Typed Generics (Not Void Pointers)

**FastDDS/CycloneDDS**: Type information is registered separately. Writers and
readers operate on `void*` internally.

**HDDS**: Writers and readers are generic over the data type: `DataWriter<T>`
and `DataReader<T>`. The type parameter `T` must implement the `DDS` trait
(generated by `idl-gen`). This provides compile-time type safety -- you cannot
accidentally write `TypeA` to a reader expecting `TypeB`.

```rust
// Type-safe: only HelloWorld can be written
let writer = participant.create_writer::<HelloWorld>("topic", qos)?;
writer.write(&HelloWorld::new("msg", 1))?;

// This would not compile:
// writer.write(&SomeOtherType { ... })?;
```

### 2.5 No Explicit Topic or Publisher/Subscriber Objects

**FastDDS**: You create Topic, Publisher, and Subscriber objects explicitly
before creating writers and readers.

**HDDS**: Topics, Publishers, and Subscribers are managed internally. You go
directly from Participant to DataWriter or DataReader:

```rust
// FastDDS equivalent of: create_topic + create_publisher + create_datawriter
let writer = participant.create_writer::<MyData>("TopicName", qos)?;

// FastDDS equivalent of: create_topic + create_subscriber + create_datareader
let reader = participant.create_reader::<MyData>("TopicName", qos)?;
```

### 2.6 Thread Safety

**FastDDS**: Thread safety depends on the specific API. Some operations require
external locking.

**CycloneDDS**: Generally thread-safe with some caveats around listener
callbacks.

**HDDS**: All public types are `Send + Sync`. The `Participant` is returned as
`Arc<Participant>` and can be safely shared across threads. Internal state is
protected by `parking_lot` locks and lock-free data structures.

---

## 3. QoS Mapping

### 3.1 Reliability

| Level | FastDDS XML | FastDDS C++ | CycloneDDS C | HDDS Rust |
|-------|-------------|-------------|--------------|-----------|
| Best effort | `BEST_EFFORT_RELIABILITY_QOS` | `BEST_EFFORT_RELIABILITY_QOS` | `DDS_RELIABILITY_BEST_EFFORT` | `QoS::best_effort()` |
| Reliable | `RELIABLE_RELIABILITY_QOS` | `RELIABLE_RELIABILITY_QOS` | `DDS_RELIABILITY_RELIABLE` | `QoS::reliable()` |

### 3.2 Durability

| Level | FastDDS XML | CycloneDDS C | HDDS Rust |
|-------|-------------|--------------|-----------|
| Volatile | `VOLATILE_DURABILITY_QOS` | `DDS_DURABILITY_VOLATILE` | `.volatile()` |
| Transient local | `TRANSIENT_LOCAL_DURABILITY_QOS` | `DDS_DURABILITY_TRANSIENT_LOCAL` | `.transient_local()` |
| Persistent | `PERSISTENT_DURABILITY_QOS` | `DDS_DURABILITY_PERSISTENT` | `.persistent()` |

### 3.3 History

| Policy | FastDDS XML | CycloneDDS C | HDDS Rust |
|--------|-------------|--------------|-----------|
| Keep last N | `<kind>KEEP_LAST_HISTORY_QOS</kind><depth>N</depth>` | `dds_qset_history(q, DDS_HISTORY_KEEP_LAST, N)` | `.keep_last(N)` |
| Keep all | `<kind>KEEP_ALL_HISTORY_QOS</kind>` | `dds_qset_history(q, DDS_HISTORY_KEEP_ALL, ...)` | `.keep_all()` |

### 3.4 Deadline

| Vendor | Configuration |
|--------|--------------|
| FastDDS XML | `<deadline><period><sec>0</sec><nanosec>100000000</nanosec></period></deadline>` |
| FastDDS C++ | `qos.deadline().period = {0, 100000000}` |
| CycloneDDS C | `dds_qset_deadline(qos, DDS_MSECS(100))` |
| HDDS Rust | `.deadline_millis(100)` |

### 3.5 Liveliness

| Kind | FastDDS C++ | CycloneDDS C | HDDS Rust |
|------|-------------|--------------|-----------|
| Automatic | `AUTOMATIC_LIVELINESS_QOS` | `DDS_LIVELINESS_AUTOMATIC` | `.liveliness_automatic_secs(5)` |
| Manual by participant | `MANUAL_BY_PARTICIPANT_LIVELINESS_QOS` | `DDS_LIVELINESS_MANUAL_BY_PARTICIPANT` | `.liveliness_manual_participant_secs(3)` |

### 3.6 Ownership

| Mode | FastDDS C++ | CycloneDDS C | HDDS Rust |
|------|-------------|--------------|-----------|
| Shared | `SHARED_OWNERSHIP_QOS` | `DDS_OWNERSHIP_SHARED` | `.ownership_shared()` |
| Exclusive | `EXCLUSIVE_OWNERSHIP_QOS` | `DDS_OWNERSHIP_EXCLUSIVE` | `.ownership_exclusive().ownership_strength(100)` |

### 3.7 Time-Based Filter

| Vendor | Configuration |
|--------|--------------|
| FastDDS XML | `<time_based_filter><minimum_separation><nanosec>100000000</nanosec></minimum_separation></time_based_filter>` |
| CycloneDDS C | `dds_qset_time_based_filter(qos, DDS_MSECS(100))` |
| HDDS Rust | `.time_based_filter_millis(100)` |

### 3.8 Transport Priority

| Vendor | Configuration |
|--------|--------------|
| FastDDS C++ | `qos.transport_priority().value = 50` |
| HDDS Rust | `.transport_priority(50)` or `.transport_priority_high()` |

### 3.9 Partition

| Vendor | Configuration |
|--------|--------------|
| FastDDS C++ | `qos.partition().push_back("sensor_zone_a")` |
| CycloneDDS C | `dds_qset_partition1(qos, "sensor_zone_a")` |
| HDDS Rust | `.partition_single("sensor_zone_a")` |

### 3.10 Lifespan

| Vendor | Configuration |
|--------|--------------|
| FastDDS C++ | `qos.lifespan().duration = {5, 0}` |
| HDDS Rust | `.lifespan_secs(5)` |

### 3.11 Loading FastDDS QoS XML Directly

If you have existing FastDDS QoS XML profiles, HDDS can load them directly
(requires the `qos-loaders` feature, enabled by default):

```rust
// Load QoS from existing FastDDS XML profile
let qos = hdds::QoS::load_fastdds("fastdds_profile.xml")?;

// Or auto-detect vendor
let qos = hdds::QoS::from_xml("qos_profile.xml")?;
```

### 3.12 RTI Connext Defaults

For RTI Connext interoperability, HDDS provides a built-in QoS profile that
matches RTI defaults (Reliable, Volatile, KeepLast(10)):

```rust
let qos = hdds::QoS::rti_defaults();
```

### 3.13 Complete QoS Translation Example

**FastDDS XML:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<profiles xmlns="http://www.eprosima.com/XMLSchemas/fastRTPS_Profiles">
    <data_writer profile_name="SensorWriter">
        <qos>
            <reliability>
                <kind>RELIABLE_RELIABILITY_QOS</kind>
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

**HDDS Rust equivalent:**

```rust
let qos = hdds::QoS::reliable()
    .transient_local()
    .keep_last(10)
    .deadline_millis(200)
    .liveliness_automatic_secs(5);
```

**CycloneDDS C equivalent:**

```c
dds_qos_t *qos = dds_create_qos();
dds_qset_reliability(qos, DDS_RELIABILITY_RELIABLE, DDS_MSECS(100));
dds_qset_durability(qos, DDS_DURABILITY_TRANSIENT_LOCAL);
dds_qset_history(qos, DDS_HISTORY_KEEP_LAST, 10);
dds_qset_deadline(qos, DDS_MSECS(200));
dds_qset_liveliness(qos, DDS_LIVELINESS_AUTOMATIC, DDS_SECS(5));
```

---

## 4. Transport Configuration

### 4.1 FastDDS XML Transport to HDDS Builder

**FastDDS UDP Multicast (Default):**

```xml
<participant profile_name="default">
    <rtps>
        <builtin>
            <discovery_config>
                <discoveryProtocol>SIMPLE</discoveryProtocol>
            </discovery_config>
        </builtin>
    </rtps>
</participant>
```

**HDDS equivalent:**

```rust
let participant = hdds::Participant::builder("app")
    .with_transport(hdds::TransportMode::UdpMulticast)
    .domain_id(0)
    .build()?;
```

### 4.2 Custom Ports

**FastDDS XML:**

```xml
<participant profile_name="custom_ports">
    <rtps>
        <builtin>
            <metatrafficUnicastLocatorList>
                <locator><udpv4><port>9410</port></udpv4></locator>
            </metatrafficUnicastLocatorList>
        </builtin>
    </rtps>
</participant>
```

**HDDS equivalent:**

```rust
let participant = hdds::Participant::builder("app")
    .with_transport(hdds::TransportMode::UdpMulticast)
    .with_discovery_ports(9400, 9410, 9411)
    .build()?;
```

### 4.3 Unicast Peers (No Multicast)

**FastDDS XML:**

```xml
<participant profile_name="unicast">
    <rtps>
        <builtin>
            <initialPeersList>
                <locator>
                    <udpv4>
                        <address>192.168.1.100</address>
                        <port>7400</port>
                    </udpv4>
                </locator>
            </initialPeersList>
        </builtin>
    </rtps>
</participant>
```

**HDDS equivalent:**

```rust
let participant = hdds::Participant::builder("app")
    .with_transport(hdds::TransportMode::UdpMulticast)
    .add_static_peer("192.168.1.100:7411")
    .build()?;
```

**CycloneDDS XML:**

```xml
<CycloneDDS xmlns="https://cdds.io/config">
    <Domain id="0">
        <General>
            <AllowMulticast>false</AllowMulticast>
        </General>
        <Discovery>
            <Peers>
                <Peer address="192.168.1.100"/>
            </Peers>
        </Discovery>
    </Domain>
</CycloneDDS>
```

### 4.4 TCP Transport

**FastDDS XML:**

```xml
<transport_descriptors>
    <transport_descriptor>
        <transport_id>tcp_transport</transport_id>
        <type>TCPv4</type>
        <listening_ports>
            <port>7410</port>
        </listening_ports>
    </transport_descriptor>
</transport_descriptors>
```

**HDDS equivalent:**

```rust
// Simple TCP
let participant = hdds::Participant::builder("app")
    .with_transport(hdds::TransportMode::UdpMulticast)
    .with_tcp(7410)
    .build()?;

// TCP-only (no UDP)
use hdds::transport::tcp::TcpConfig;

let tcp = TcpConfig::tcp_only(vec![
    "192.168.1.100:7410".parse().unwrap(),
]);

let participant = hdds::Participant::builder("app")
    .tcp_config(tcp)
    .tcp_only()
    .build()?;
```

### 4.5 Shared Memory

**FastDDS XML:**

```xml
<transport_descriptors>
    <transport_descriptor>
        <transport_id>shm_transport</transport_id>
        <type>SHM</type>
    </transport_descriptor>
</transport_descriptors>
```

**CycloneDDS XML (Iceoryx):**

```xml
<CycloneDDS xmlns="https://cdds.io/config">
    <Domain id="any">
        <SharedMemory>
            <Enable>true</Enable>
        </SharedMemory>
    </Domain>
</CycloneDDS>
```

**HDDS equivalent:**

```rust
use hdds::ShmPolicy;

// SHM is enabled by default (Prefer policy).
// To force SHM:
let participant = hdds::Participant::builder("app")
    .shm_require()
    .build()?;

// To disable SHM:
let participant = hdds::Participant::builder("app")
    .shm_disable()
    .build()?;
```

Note: HDDS shared memory uses its own implementation, not Iceoryx. SHM between
HDDS and CycloneDDS/FastDDS is not supported -- use UDP loopback for same-host
interoperability.

### 4.6 DDS Security

**FastDDS XML:**

```xml
<participant profile_name="secure">
    <rtps>
        <propertiesPolicy>
            <properties>
                <property>
                    <name>dds.sec.auth.plugin</name>
                    <value>builtin.PKI-DH</value>
                </property>
                <property>
                    <name>dds.sec.auth.builtin.PKI-DH.identity_ca</name>
                    <value>file:///path/to/ca.pem</value>
                </property>
                <property>
                    <name>dds.sec.auth.builtin.PKI-DH.identity_certificate</name>
                    <value>file:///path/to/identity.pem</value>
                </property>
                <property>
                    <name>dds.sec.auth.builtin.PKI-DH.private_key</name>
                    <value>file:///path/to/identity_key.pem</value>
                </property>
            </properties>
        </propertiesPolicy>
    </rtps>
</participant>
```

**HDDS equivalent (requires `security` feature):**

```rust
use hdds::security::SecurityConfig;

let config = SecurityConfig {
    identity_cert_path: Some("/path/to/identity.pem".to_string()),
    identity_key_path: Some("/path/to/identity_key.pem".to_string()),
    ca_cert_path: Some("/path/to/ca.pem".to_string()),
    permissions_xml_path: Some("/path/to/permissions.xml".to_string()),
    governance_xml: None,
    audit_log_path: None,
};

let participant = hdds::Participant::builder("secure_app")
    .with_transport(hdds::TransportMode::UdpMulticast)
    .with_security(config)
    .build()?;
```

---

## 5. Common Patterns

### 5.1 Publish-Subscribe

**FastDDS (C++):**

```cpp
// Setup
auto factory = DomainParticipantFactory::get_instance();
auto participant = factory->create_participant(0, PARTICIPANT_QOS_DEFAULT);
TypeSupport type(new HelloWorldPubSubType());
type.register_type(participant);
auto topic = participant->create_topic("HelloWorldTopic", "HelloWorld", TOPIC_QOS_DEFAULT);
auto publisher = participant->create_publisher(PUBLISHER_QOS_DEFAULT);
auto writer = publisher->create_datawriter(topic, DATAWRITER_QOS_DEFAULT);

// Write
HelloWorld sample;
sample.message("Hello!");
writer->write(&sample);
```

**HDDS (Rust):**

```rust
// Setup + Write -- much less boilerplate
let participant = hdds::Participant::builder("app")
    .with_transport(hdds::TransportMode::UdpMulticast)
    .domain_id(0)
    .build()?;

let writer = participant.create_writer::<HelloWorld>(
    "HelloWorldTopic",
    hdds::QoS::default(),
)?;

writer.write(&HelloWorld::new("Hello!", 0))?;
```

### 5.2 WaitSet Pattern

**FastDDS (C++):**

```cpp
StatusCondition& condition = reader->get_statuscondition();
condition.set_enabled_statuses(StatusMask::data_available());

WaitSet waitset;
waitset.attach_condition(condition);

ConditionSeq triggered;
Duration_t timeout = {5, 0};
waitset.wait(triggered, timeout);
```

**CycloneDDS (C):**

```c
dds_entity_t ws = dds_create_waitset(participant);
dds_waitset_attach(ws, reader, reader);

dds_attach_t results[1];
dds_waitset_wait(ws, results, 1, DDS_SECS(5));
```

**HDDS (Rust):**

```rust
let status_condition = reader.get_status_condition();
let waitset = hdds::dds::WaitSet::new();
waitset.attach_condition(status_condition)?;

match waitset.wait(Some(Duration::from_secs(5))) {
    Ok(triggered) if !triggered.is_empty() => {
        while let Some(msg) = reader.take()? {
            println!("Received: {:?}", msg);
        }
    }
    Ok(_) | Err(hdds::Error::WouldBlock) => {
        println!("Timeout");
    }
    Err(e) => eprintln!("Error: {:?}", e),
}
```

### 5.3 Multiple Topics from One Participant

**FastDDS (C++):**

```cpp
auto topic1 = participant->create_topic("SensorData", "SensorType", qos);
auto topic2 = participant->create_topic("Commands", "CommandType", qos);
auto writer1 = publisher->create_datawriter(topic1, wqos);
auto writer2 = publisher->create_datawriter(topic2, wqos);
```

**HDDS (Rust):**

```rust
let sensor_writer = participant.create_writer::<SensorData>(
    "SensorData", hdds::QoS::best_effort())?;
let command_writer = participant.create_writer::<Command>(
    "Commands", hdds::QoS::reliable())?;
```

### 5.4 Keyed Instances

**FastDDS (C++):**

```cpp
// Key is defined in IDL with @key annotation
// FastDDS handles instance tracking automatically
KeyedData sample;
sample.id(42);
sample.data("update");
writer->write(&sample);  // instance identified by key field
```

**HDDS (Rust):**

```rust
// Same concept: @key in IDL, instance tracked by key hash
let msg = KeyedData::new(42, "update", 0);
writer.write(&msg)?;
// HDDS computes the instance key from @key fields automatically
```

### 5.5 Discovery

**FastDDS**: Discovery is automatic with SPDP multicast. For unicast, configure
initial peers in XML.

**CycloneDDS**: Discovery is automatic. For unicast, configure peers in
`cyclonedds.xml`.

**HDDS**: Same automatic SPDP/SEDP discovery. For unicast or cloud:

```rust
// Standard multicast discovery
let participant = hdds::Participant::builder("app")
    .with_transport(hdds::TransportMode::UdpMulticast)
    .build()?;

// Static peers (no multicast)
let participant = hdds::Participant::builder("app")
    .with_transport(hdds::TransportMode::UdpMulticast)
    .add_static_peer("192.168.1.100:7411")
    .build()?;

// Discovery server (cloud/corporate)
let participant = hdds::Participant::builder("app")
    .discovery_server_addr("discovery.example.com:7400".parse()?)
    .build()?;

// Kubernetes DNS discovery (requires k8s feature)
let participant = hdds::Participant::builder("app")
    .with_transport(hdds::TransportMode::UdpMulticast)
    .with_k8s_discovery("hdds-discovery", "default")
    .build()?;
```

---

## 6. IDL Workflow

### 6.1 Same IDL, Different Code Generators

The key to interoperability is using the same IDL file for all vendors. Each
vendor has its own code generator that produces type support in the target
language.

```idl
// SensorData.idl -- shared across all vendors
module sensors {
    @topic
    struct SensorData {
        @key unsigned long sensor_id;
        float temperature;
        unsigned long long timestamp;
    };
};
```

| Vendor | Command | Output |
|--------|---------|--------|
| HDDS | `idl-gen gen rust SensorData.idl -o sensor_data.rs` | Rust types with CDR2, DDS trait, XTypes |
| FastDDS | `fastddsgen SensorData.idl` | C++ types with PubSubType |
| CycloneDDS | `idlc -l c SensorData.idl` | C types with descriptor |
| RTI Connext | `rtiddsgen -language C++ SensorData.idl` | C++ types with TypePlugin |

### 6.2 HDDS Code Generation Details

```bash
# Generate Rust types
idl-gen gen rust SensorData.idl -o src/generated/sensor_data.rs

# Generate with include directories
idl-gen gen rust -I ./common_idl -I /opt/dds/idl SensorData.idl -o types.rs

# Validate IDL without generating
idl-gen check SensorData.idl

# Format IDL to canonical style
idl-gen fmt SensorData.idl

# Generate a full example project
idl-gen gen rust SensorData.idl --example --out-dir ./my_project
```

### 6.3 Generated Code Structure

The generated Rust code includes:

1. **Struct definition** with public fields.
2. **`Cdr2Encode` / `Cdr2Decode`** implementations for wire-format
   serialization.
3. **`DDS` trait** implementation (type descriptor, CDR encode/decode, key
   computation, XTypes TypeObject).
4. **`::new(...)` constructor** for convenient initialization.
5. **Builder pattern** (`::builder().field(val).build()`) for complex types.

Include the generated code in your Rust project:

```rust
mod generated {
    include!("generated/sensor_data.rs");
}
use generated::sensors::SensorData;
```

### 6.4 FastDDS IDL Differences

Most IDL differences are handled transparently. A few points to watch:

| Feature | FastDDS IDL | HDDS IDL |
|---------|-------------|----------|
| Key annotation | `@key` | `@key` (identical) |
| Topic annotation | Not required | `@topic` (optional) |
| Module wrapping | Optional | Recommended |
| Wide strings | `wstring` | `wstring` (partial support) |
| Bitsets | Supported | Supported |
| Unions | Supported | Supported |

### 6.5 Migration Checklist

1. **Copy your IDL files** unchanged. HDDS supports the same IDL 4.2 syntax.
2. **Generate HDDS types**: `idl-gen gen rust MyTypes.idl -o my_types.rs`
3. **Replace entity creation** with HDDS builder pattern (see Section 1).
4. **Replace QoS setup** with HDDS fluent builders (see Section 3) or load
   your existing FastDDS XML: `QoS::load_fastdds("profile.xml")?`.
5. **Replace write/take calls** with HDDS typed methods.
6. **Remove manual cleanup** code -- Rust `Drop` handles it.
7. **Replace XML transport config** with HDDS builder methods (see Section 4).
8. **Test interop** by running both the old and new implementation
   side-by-side on the same domain ID with UDP multicast.

---

## Appendix: Quick Reference Card

```
FastDDS                                HDDS
-------                                ----
DomainParticipantFactory               Participant::builder("name")
  ->create_participant(0, qos)           .domain_id(0).build()?

participant->create_topic(...)         (implicit in create_writer/create_reader)
publisher->create_datawriter(t, qos)   participant.create_writer::<T>("t", qos)?
subscriber->create_datareader(t, qos)  participant.create_reader::<T>("t", qos)?

writer->write(&sample)                 writer.write(&sample)?
reader->take_next_sample(&s, &i)       reader.take()?
reader->read_next_sample(&s, &i)       reader.read()?

RELIABLE_RELIABILITY_QOS               QoS::reliable()
BEST_EFFORT_RELIABILITY_QOS            QoS::best_effort()
TRANSIENT_LOCAL_DURABILITY_QOS         .transient_local()
KEEP_LAST_HISTORY_QOS, depth=N         .keep_last(N)
KEEP_ALL_HISTORY_QOS                   .keep_all()

DDS_INFINITY                           Deadline::infinite() (default)
{sec, nanosec}                         .deadline_millis(ms) / .deadline_secs(s)

factory->delete_participant(p)         (automatic via Drop)

fastddsgen MyTypes.idl                 idl-gen gen rust MyTypes.idl -o types.rs
```
