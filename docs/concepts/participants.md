# DomainParticipant

The DomainParticipant is your entry point to DDS communication and the factory for all other DDS entities.

## Overview

A DomainParticipant:
- Represents an application's presence in a DDS domain
- Creates Publishers, Subscribers, and Topics
- Manages discovery of other participants
- Owns all child entities and their resources

## Creating a Participant

```rust
use hdds::{Participant, TransportMode};

// Join domain 0
let participant = Participant::builder("my_app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// With custom configuration
let participant = Participant::builder("my_application")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .participant_id(Some(5))  // Explicit participant ID
    .build()?;
```

## Domain Isolation

Participants only communicate within the same domain:

```
Domain 0                          Domain 1
┌─────────────────────┐          ┌─────────────────────┐
│  Participant A      │          │  Participant C      │
│  Participant B      │          │  Participant D      │
│       ↕             │          │       ↕             │
│  (can communicate)  │    ✗     │  (can communicate)  │
└─────────────────────┘          └─────────────────────┘
```

Domain IDs map to network ports:
- Domain 0: ports 7400-7410
- Domain 1: ports 7411-7421
- Domain N: ports 7400 + (N * 11)

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

// These writers cannot see each other's readers
let writer_0 = /* ... on domain_0 */;
let reader_1 = /* ... on domain_1 */;  // No match
```

## Entity Factory

The participant creates all DDS entities:

```rust
let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// Create topic (type must be registered)
let topic = participant.create_topic::<SensorData>("SensorTopic")?;

// Create publisher and subscriber
let publisher = participant.create_publisher()?;
let subscriber = participant.create_subscriber()?;

// Create endpoints
let writer = publisher.create_writer(&topic)?;
let reader = subscriber.create_reader(&topic)?;
```

### Entity Ownership

```
DomainParticipant (owner)
├── Topic "SensorTopic"
├── Publisher
│   └── DataWriter<SensorData>
└── Subscriber
    └── DataReader<SensorData>
```

Deleting the participant deletes all child entities:

```rust
// All writers, readers, topics are cleaned up
drop(participant);
```

## Participant GUID

Each participant has a globally unique identifier (GUID):

```rust
let guid = participant.guid();
println!("Participant GUID: {:?}", guid);
// Output: GUID { prefix: [01, 0f, aa, ...], entity_id: [00, 00, 01, c1] }
```

The GUID structure:
- **Prefix** (12 bytes): Identifies the participant
- **Entity ID** (4 bytes): Identifies the entity within participant

## Discovery

Participants automatically discover each other via SPDP:

```rust
// Wait for other participants
loop {
    let count = participant.discovered_participants().len();
    println!("Found {} other participants", count);

    if count > 0 {
        break;
    }
    std::thread::sleep(Duration::from_millis(100));
}
```

### Discovery Callbacks

```rust
use hdds::{Participant, TransportMode};

struct MyListener;

impl DomainParticipantListener for MyListener {
    fn on_participant_discovered(
        &mut self,
        participant: &DomainParticipant,
        info: DiscoveredParticipantInfo,
    ) {
        println!("New participant: {:?}", info.guid);
        println!("  User data: {:?}", info.user_data);
    }

    fn on_participant_lost(
        &mut self,
        participant: &DomainParticipant,
        guid: GUID,
    ) {
        println!("Participant left: {:?}", guid);
    }
}

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .with_listener(MyListener)
    .build()?;
```

## Liveliness

Participants assert their liveliness automatically:

```rust
// Manual assertion (if using ManualByParticipant)
participant.assert_liveliness()?;
```

Liveliness lease duration:

```rust
let config = DomainParticipantConfig::default()
    .lease_duration(Duration::from_secs(30));  // 30-second lease
```

## User Data

Attach application-specific metadata:

```rust
let config = DomainParticipantConfig::default()
    .user_data(b"app=sensor_node;version=2.1".to_vec());

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .user_data(b"app=sensor_node;version=2.1".to_vec())
    .build()?;

// Other participants can read this
for info in participant.discovered_participants() {
    if let Some(data) = &info.user_data {
        println!("Peer user data: {}", String::from_utf8_lossy(data));
    }
}
```

## Configuration Options

```rust
let config = DomainParticipantConfig::default()
    // Identity
    .name("my_application")
    .user_data(b"metadata".to_vec())

    // Discovery
    .lease_duration(Duration::from_secs(30))
    .initial_peers(vec!["192.168.1.100:7400".parse()?])

    // Transport
    .transport(TransportConfig::default()
        .enable_udp_multicast(true)
        .enable_shared_memory(true))

    // Security (if enabled)
    .security(SecurityConfig::builder()
        .identity_certificate("cert.pem")
        .private_key("key.pem")
        .build()?);
```

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
let topic = participant.create_topic::<Message>("Topic")?;
// ...

// Explicit cleanup (optional, happens on drop)
participant.delete_contained_entities()?;

// Participant is destroyed when dropped
drop(participant);
```

## Error Handling

```rust
match Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()
{
    Ok(p) => println!("Joined domain 0"),
    Err(hdds::Error::InvalidDomainId(id)) => {
        eprintln!("Domain {} is out of range (0-232)", id);
    }
    Err(hdds::Error::BindFailed { address, reason }) => {
        eprintln!("Cannot bind to {}: {}", address, reason);
    }
    Err(e) => eprintln!("Failed: {}", e),
}
```

## Best Practices

1. **One participant per application** - Unless you need domain isolation
2. **Set meaningful names** - Helps with debugging and monitoring
3. **Use user data** - Share version info, capabilities
4. **Handle discovery events** - Know when peers join/leave
5. **Clean shutdown** - Drop participant to release resources

## Thread Safety

DomainParticipant is thread-safe:

```rust
use std::sync::Arc;

let participant = Arc::new(Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?);

// Safe to use from multiple threads
let p1 = participant.clone();
std::thread::spawn(move || {
    let writer = p1.create_publisher()?.create_writer(&topic)?;
    // ...
});
```

## Next Steps

- [Topics](../concepts/topics.md) - Creating data channels
- [Publishers and Subscribers](../concepts/publishers-subscribers.md) - Data distribution
- [Discovery](../concepts/discovery.md) - How participants find each other
