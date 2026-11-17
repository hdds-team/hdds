# DomainParticipant

The DomainParticipant is your entry point to DDS communication and the factory for all other DDS entities. In HDDS the type is `hdds::Participant`.

## Overview

A Participant:
- Represents an application's presence in a DDS domain
- Creates Publishers, Subscribers, Topics, DataWriters and DataReaders
- Runs discovery of other participants
- Owns the network resources (sockets, discovery threads) its entities share

## Creating a Participant

`Participant::builder` returns a builder; `build()` returns an `Arc<Participant>`.

```rust
use hdds::{Participant, TransportMode};

// Join domain 0
let participant = Participant::builder("my_app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// With an explicit participant ID
let participant = Participant::builder("my_application")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .participant_id(Some(5))
    .build()?;
```

The domain ID is taken from `domain_id(..)`. When it is not set, `build()` reads
the `HDDS_DOMAIN_ID` environment variable, and falls back to domain 0. When the
participant ID is not set, one is assigned automatically (0 to 119).

## Domain Isolation

Participants only communicate within the same domain:

```
Domain 0                          Domain 1
+---------------------+          +---------------------+
|  Participant A      |          |  Participant C      |
|  Participant B      |          |  Participant D      |
|      ^v             |          |      ^v             |
|  (can communicate)  |    X     |  (can communicate)  |
+---------------------+          +---------------------+
```

Domain IDs map to network ports (RTPS port mapping):
- SPDP multicast port: 7400 + 250 x domain
- Metatraffic unicast port: 7410 + 250 x domain + 2 x participant ID
- User-data unicast port: 7411 + 250 x domain + 2 x participant ID

Valid domain IDs are 0 to 232.

```rust
// Different domains are isolated
let domain_0 = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;
let domain_1 = Participant::builder("app")
    .domain_id(1)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// A writer on domain_0 and a reader on domain_1 never match
```

## Entity Factory

The participant creates all DDS entities. The recommended path goes through a
typed topic:

```rust
use hdds::{Participant, QoS};

#[derive(hdds::DDS)]
struct SensorData {
    value: f64,
}

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// Typed topic handle
let topic = participant.topic::<SensorData>("SensorTopic")?;

// Endpoints are created from builders
let writer = topic.writer().qos(QoS::reliable()).build()?;
let reader = topic.reader().qos(QoS::reliable()).build()?;
```

A Publisher or Subscriber carries entity-level QoS (for example a partition)
shared by the endpoints created under it:

```rust
let publisher = participant.create_publisher(QoS::default().partition_single("production"))?;
let subscriber = participant.create_subscriber(QoS::default())?;
```

### Entity Ownership

```
Participant
+-- Topic "SensorTopic"
+-- Publisher
|   +-- DataWriter<SensorData>
+-- Subscriber
    +-- DataReader<SensorData>
```

When the last reference to a participant is dropped, every thread it started is
stopped and its sockets and shared memory are closed before `drop` returns.
Readers and writers that outlive their participant keep what they share with it
until they are dropped too, so drop the endpoints first:

```rust
drop(writer);
drop(reader);
drop(participant);
```

## Participant GUID

Each participant has a globally unique identifier (GUID):

```rust
let guid = participant.guid();
println!("Participant GUID: {:?}", guid);
```

The GUID structure:
- **Prefix** (12 bytes): Identifies the participant
- **Entity ID** (4 bytes): Identifies the entity within the participant

## Discovery

Participants automatically discover each other via SPDP. The participant's
discovery state lists the remote participants learned so far:

```rust
use std::time::Duration;

// Wait for other participants
loop {
    let count = participant
        .discovery()
        .map(|d| d.get_participants().len())
        .unwrap_or(0);
    println!("Found {} other participants", count);

    if count > 0 {
        break;
    }
    std::thread::sleep(Duration::from_millis(100));
}
```

There is no participant-level listener. Discovery of remote endpoints is
reported through the match status of readers and writers; see
[Discovery](discovery.md#discovery-events).

## Liveliness

A participant announces itself with periodic SPDP announcements and is removed
by its peers when its lease expires. The lease and the announcement period are
set on the builder:

```rust
use std::time::Duration;

let participant = Participant::builder("app")
    .domain_id(0)
    .with_participant_lease_duration(Duration::from_secs(30)) // default
    .with_spdp_announcement_period(Duration::from_secs(3))   // default
    .build()?;
```

For writers using MANUAL_BY_PARTICIPANT liveliness, the application renews the
lease of all of them at once:

```rust
participant.assert_liveliness();
```

## Configuration Options

The builder methods are named `with_*`. The most common ones:

| Area | Methods |
|------|---------|
| Identity | `Participant::builder(name)`, `domain_id`, `participant_id` |
| Transport | `with_transport(TransportMode)`, `with_transport_options`, `with_tcp`, `with_quic` (feature `quic`), `with_lowbw`, `shm_policy` / `shm_prefer` / `shm_require` / `shm_disable` |
| Discovery | `with_participant_lease_duration`, `with_spdp_announcement_period`, `with_discovery_ports`, `add_static_peer`, `with_seed_peers`, `with_discovery_server`, `with_k8s_discovery` (feature `k8s`) |
| Sockets | `with_socket_receive_buffer_size`, `with_socket_send_buffer_size` |
| Security | `with_security(SecurityConfig)` (feature `security`) |

```rust
use hdds::{Participant, TransportMode};
use std::time::Duration;

let participant = Participant::builder("my_application")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .with_participant_lease_duration(Duration::from_secs(30))
    .add_static_peer("192.168.1.100:7410")
    .build()?;
```

With the `security` feature enabled, `with_security` takes a `SecurityConfig`
built from certificate and governance files; see the
[Security Guide](../security-guide.md).

## Multiple Participants

You can create multiple participants in one application:

```rust
// Join multiple domains
let domain_0 = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;
let domain_1 = Participant::builder("app")
    .domain_id(1)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// Or multiple participants in same domain (less common)
let p1 = Participant::builder("app1")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;
let p2 = Participant::builder("app2")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;  // Separate GUID
```

## Lifecycle

```rust
// Create
let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// Use (create entities, exchange data)
let topic = participant.topic::<Message>("Topic")?;
let writer = topic.writer().build()?;
// ...

// Cleanup happens on drop: endpoints first, then the participant
drop(writer);
drop(participant);
```

## Error Handling

```rust
match Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()
{
    Ok(_p) => println!("Joined domain 0"),
    Err(hdds::Error::InvalidDomainId(id)) => {
        eprintln!("Domain {} is out of range (0-232)", id);
    }
    Err(hdds::Error::BindFailed(reason)) => {
        eprintln!("Cannot bind a socket: {}", reason);
    }
    Err(e) => eprintln!("Failed: {}", e),
}
```

## Best Practices

1. **One participant per application** - Unless you need domain isolation
2. **Set meaningful names** - Helps with debugging and monitoring
3. **Watch match status** - Use writer and reader listeners to know when peers join or leave
4. **Clean shutdown** - Drop endpoints, then the participant, to release resources

## Thread Safety

`Participant::build()` returns an `Arc<Participant>`, which can be shared between threads:

```rust
let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// Safe to use from multiple threads
let p1 = participant.clone();
std::thread::spawn(move || -> hdds::Result<()> {
    let topic = p1.topic::<SensorData>("SensorTopic")?;
    let _writer = topic.writer().build()?;
    // ...
    Ok(())
});
```

## Next Steps

- [Topics](../concepts/topics.md) - Creating data channels
- [Publishers and Subscribers](../concepts/publishers-subscribers.md) - Data distribution
- [Discovery](../concepts/discovery.md) - How participants find each other
