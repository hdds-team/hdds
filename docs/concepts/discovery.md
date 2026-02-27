# Discovery

Discovery is the automatic process by which DDS participants and endpoints find each other on the network.

## Overview

DDS uses two discovery protocols:

| Protocol | Purpose | Traffic |
|----------|---------|---------|
| **SPDP** | Find participants | Multicast |
| **SEDP** | Exchange endpoints | Unicast |

```
┌──────────────────────────────────────────────────────────────┐
│                     Discovery Flow                            │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  Participant A                      Participant B             │
│       │                                  │                    │
│       │ ──── SPDP (multicast) ────────> │  Phase 1: Find     │
│       │ <─── SPDP (multicast) ───────── │  participants      │
│       │                                  │                    │
│       │ ──── SEDP (unicast) ──────────> │  Phase 2: Exchange │
│       │ <─── SEDP (unicast) ─────────── │  endpoints         │
│       │                                  │                    │
│       │ ──── User Data ─────────────────>│  Phase 3: Data    │
│       │                                  │  flow begins       │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

## SPDP (Simple Participant Discovery Protocol)

SPDP discovers other DomainParticipants in the same domain.

### How It Works

1. Each participant sends periodic announcements via multicast
2. Announcements contain participant GUID, locators, lease duration
3. Participants maintain a list of discovered participants

### SPDP Messages

```
SPDP Announcement:
┌────────────────────────────────────────┐
│ GUID Prefix: [01, 0f, aa, ...]         │
│ Vendor ID: HDDS (0x01aa)               │
│ Unicast Locator: 192.168.1.100:7411    │
│ Multicast Locator: 239.255.0.1:7400    │
│ Lease Duration: 30s                    │
│ User Data: "app=sensor"                │
└────────────────────────────────────────┘
```

### Network Configuration

Default multicast settings:

| Setting | Default | Domain N |
|---------|---------|----------|
| Multicast Address | 239.255.0.1 | 239.255.0.1 |
| Discovery Port | 7400 | 7400 + N*10 |
| Participant Offset | +0, +1 | +0 to +9 |

```rust
// Customize discovery
let config = DomainParticipantConfig::default()
    .discovery_multicast("239.255.0.1:7400")
    .lease_duration(Duration::from_secs(30));
```

### SPDP Timing

```
Initial announcements:  Quick burst (0.5s, 1s, 2s)
Steady state:           Every lease_duration/3
Lease expiration:       Remove after lease_duration
```

## SEDP (Simple Endpoint Discovery Protocol)

SEDP exchanges information about DataWriters and DataReaders.

### How It Works

1. After SPDP discovers a participant, SEDP begins
2. Participants exchange endpoint information via unicast
3. Each side learns about remote writers and readers

### SEDP Messages

```
SEDP Publication (Writer Info):
┌────────────────────────────────────────┐
│ Endpoint GUID: [01, 0f, aa, ..., c2]   │
│ Topic Name: "SensorTopic"              │
│ Type Name: "sensors::SensorData"       │
│ Reliability: Reliable                  │
│ Durability: TransientLocal             │
│ Ownership: Shared                      │
│ Type Object: (XTypes info)             │
└────────────────────────────────────────┘

SEDP Subscription (Reader Info):
┌────────────────────────────────────────┐
│ Endpoint GUID: [02, 1a, bb, ..., c7]   │
│ Topic Name: "SensorTopic"              │
│ Type Name: "sensors::SensorData"       │
│ Reliability: Reliable                  │
│ Durability: Volatile                   │
└────────────────────────────────────────┘
```

### Built-in Endpoints

Each participant has built-in endpoints for discovery:

| Entity ID | Purpose |
|-----------|---------|
| 0x000100c2 | SPDP Writer |
| 0x000100c7 | SPDP Reader |
| 0x000003c2 | Publications Writer |
| 0x000003c7 | Publications Reader |
| 0x000004c2 | Subscriptions Writer |
| 0x000004c7 | Subscriptions Reader |

## Matching Process

After SEDP exchange, endpoints are matched:

```
Match Criteria:
1. Same Topic Name        (exact string match)
2. Compatible Type        (type name + XTypes)
3. Compatible QoS         (see QoS rules)
4. Same Domain            (implicit from discovery)
5. Partition Overlap      (if configured)
```

### QoS Compatibility Check

| Policy | Requirement |
|--------|-------------|
| Reliability | Writer ≥ Reader |
| Durability | Writer ≥ Reader |
| Deadline | Writer ≤ Reader |
| Liveliness | Writer kind ≥ Reader kind |
| Ownership | Writer = Reader |

## Discovery Events

### Participant Events

```rust
impl DomainParticipantListener for MyListener {
    fn on_participant_discovered(&mut self, participant: &DomainParticipant, info: DiscoveredParticipantInfo) {
        println!("Found participant: {:?}", info.guid);
        println!("  Vendor: {:?}", info.vendor_id);
        println!("  User data: {:?}", info.user_data);
    }

    fn on_participant_lost(&mut self, participant: &DomainParticipant, guid: GUID) {
        println!("Participant left: {:?}", guid);
    }
}
```

### Endpoint Events

```rust
impl DataWriterListener for MyListener {
    fn on_publication_matched(&mut self, writer: &DataWriter<T>, status: PublicationMatchedStatus) {
        println!("Writer matched {} readers (total: {})",
            status.current_count_change,
            status.current_count);
    }
}

impl DataReaderListener for MyListener {
    fn on_subscription_matched(&mut self, reader: &DataReader<T>, status: SubscriptionMatchedStatus) {
        println!("Reader matched {} writers (total: {})",
            status.current_count_change,
            status.current_count);
    }
}
```

## Discovery Queries

### List Discovered Participants

```rust
for info in participant.discovered_participants() {
    println!("Participant: {:?}", info.guid);
    println!("  Unicast: {:?}", info.unicast_locators);
}
```

### List Discovered Topics

```rust
for info in participant.discovered_topics() {
    println!("Topic: {} (type: {})", info.name, info.type_name);
}
```

### Check Matched Endpoints

```rust
// Writer side
let matched_readers = writer.matched_subscriptions();
for reader_guid in matched_readers {
    println!("Matched reader: {:?}", reader_guid);
}

// Reader side
let matched_writers = reader.matched_publications();
for writer_guid in matched_writers {
    println!("Matched writer: {:?}", writer_guid);
}
```

## Static Discovery

For networks without multicast:

```rust
let config = DomainParticipantConfig::default()
    // Disable multicast discovery
    .enable_multicast_discovery(false)

    // Manually specify peer addresses
    .initial_peers(vec![
        "192.168.1.100:7400".parse()?,
        "192.168.1.101:7400".parse()?,
    ]);
```

## Discovery Timing

### Typical Discovery Times

| Scenario | Time |
|----------|------|
| Same host | 50-100 ms |
| Same LAN | 100-500 ms |
| Cross-subnet (static) | 100-200 ms |

### Speeding Up Discovery

```rust
let config = DomainParticipantConfig::default()
    // Faster initial announcements
    .initial_announcement_period(Duration::from_millis(100))

    // Shorter lease (faster detection of failures)
    .lease_duration(Duration::from_secs(10));
```

## Troubleshooting Discovery

### No Participants Found

```bash
# Check multicast connectivity
ping -c 3 239.255.0.1

# Verify SPDP traffic
tcpdump -i any -n udp port 7400

# Enable discovery debug
export RUST_LOG=hdds::discovery=debug
```

### Endpoints Not Matching

Common causes:

| Issue | Solution |
|-------|----------|
| Different domain ID | Use same domain |
| Topic name mismatch | Check spelling, case |
| Type name mismatch | Use same IDL |
| QoS incompatible | Check reliability, durability |
| Partition mismatch | Check partition strings |

### Firewall Configuration

Required ports:

```
UDP 7400-7500    (discovery + data, per domain)
UDP 239.255.0.0/16  (multicast, if enabled)
```

## Vendor Interoperability

Discovery works across DDS vendors:

| Vendor | SPDP | SEDP | Notes |
|--------|------|------|-------|
| FastDDS | Yes | Yes | Default settings work |
| RTI Connext | Yes | Yes | May need interop mode |
| CycloneDDS | Yes | Yes | Excellent compliance |
| OpenDDS | Yes | Yes | Works with RTPS |

### Vendor Detection

```rust
for info in participant.discovered_participants() {
    match info.vendor_id {
        VendorId::HDDS => println!("HDDS participant"),
        VendorId::RTI => println!("RTI Connext participant"),
        VendorId::EPROSIMA => println!("FastDDS participant"),
        VendorId::CYCLONE => println!("CycloneDDS participant"),
        _ => println!("Unknown vendor: {:?}", info.vendor_id),
    }
}
```

## Discovery Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Discovery Subsystem                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐   │
│  │ SPDP Writer  │    │ SEDP Pubs    │    │ SEDP Subs    │   │
│  │   (builtin)  │    │   Writer     │    │   Writer     │   │
│  └──────────────┘    └──────────────┘    └──────────────┘   │
│         │                   │                   │            │
│         ▼                   ▼                   ▼            │
│  ┌──────────────────────────────────────────────────────┐   │
│  │               Discovery Database                      │   │
│  │  - Discovered Participants                           │   │
│  │  - Discovered Endpoints                              │   │
│  │  - Matching State                                    │   │
│  └──────────────────────────────────────────────────────┘   │
│         ▲                   ▲                   ▲            │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐   │
│  │ SPDP Reader  │    │ SEDP Pubs    │    │ SEDP Subs    │   │
│  │   (builtin)  │    │   Reader     │    │   Reader     │   │
│  └──────────────┘    └──────────────┘    └──────────────┘   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Next Steps

- [Architecture](../concepts/architecture.md) - System overview
- [Cross-Vendor Example](../examples/cross-vendor.md) - Interoperability demo
- [Wire Compatibility](../interop/wire-compatibility.md) - Protocol details
