# Discovery

Discovery is the automatic process by which DDS participants and endpoints find each other on the network.

## Overview

DDS uses two discovery protocols:

| Protocol | Purpose | Traffic |
|----------|---------|---------|
| **SPDP** | Find participants | Multicast |
| **SEDP** | Exchange endpoints | Unicast |

```
+--------------------------------------------------------------+
|                     Discovery Flow                            |
+--------------------------------------------------------------+
|                                                               |
|  Participant A                      Participant B             |
|       |                                  |                    |
|       | ---- SPDP (multicast) --------> |  Phase 1: Find     |
|       | <--- SPDP (multicast) --------- |  participants      |
|       |                                  |                    |
|       | ---- SEDP (unicast) ----------> |  Phase 2: Exchange |
|       | <--- SEDP (unicast) ----------- |  endpoints         |
|       |                                  |                    |
|       | ---- User Data ----------------->|  Phase 3: Data    |
|       |                                  |  flow begins       |
|                                                               |
+--------------------------------------------------------------+
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
+----------------------------------------+
| GUID Prefix: [01, 0f, aa, ...]         |
| Vendor ID: HDDS (0x011a)               |
| Unicast Locator: 192.168.1.100:7411    |
| Multicast Locator: 239.255.0.1:7400    |
| Lease Duration: 30s                    |
+----------------------------------------+
```

### Network Configuration

Default settings (RTPS port mapping, domain `N`, participant index `P`):

| Setting | Value |
|---------|-------|
| Multicast address | 239.255.0.1 |
| SPDP multicast port | 7400 + 250 x N |
| Metatraffic unicast port (SEDP) | 7410 + 250 x N + 2 x P |
| User-data unicast port | 7411 + 250 x N + 2 x P |
| Valid domain IDs | 0 to 232 |
| Valid participant indices | 0 to 119 |

Discovery timing and the discovery ports are set on the participant builder:

```rust
use hdds::Participant;
use std::time::Duration;

let participant = Participant::builder("sensor_node")
    .domain_id(0)
    // Steady-state SPDP announcement period (default 3 s)
    .with_spdp_announcement_period(Duration::from_secs(1))
    // Lease advertised in every SPDP announcement (default 30 s)
    .with_participant_lease_duration(Duration::from_secs(10))
    .build()?;
```

`with_discovery_ports(spdp_multicast, sedp_unicast, user_unicast)` replaces the
standard port formula when a firewall or another vendor's configuration
requires fixed ports. Every participant that must discover each other has to
use the same ports.

### SPDP Timing

```
Startup:       a burst of one announcement every 200 ms for the first 5 s
               (or every configured period, if that is shorter)
Steady state:  one announcement every announcement period (default 3 s)
Lease expiry:  a participant is removed when no announcement arrives
               within its advertised lease (default 30 s)
```

The lease must be longer than the announcement period. `build()` fails with
`Error::Config` otherwise, and logs a warning when the lease is shorter than
three announcement periods.

## SEDP (Simple Endpoint Discovery Protocol)

SEDP exchanges information about DataWriters and DataReaders.

### How It Works

1. After SPDP discovers a participant, SEDP begins
2. Participants exchange endpoint information via unicast
3. Each side learns about remote writers and readers

### SEDP Messages

```
SEDP Publication (Writer Info):
+----------------------------------------+
| Endpoint GUID: [01, 0f, aa, ..., c2]   |
| Topic Name: "SensorTopic"              |
| Type Name: "sensors::SensorData"       |
| Reliability: Reliable                  |
| Durability: TransientLocal             |
| Ownership: Shared                      |
| Type Object: (XTypes info)             |
+----------------------------------------+

SEDP Subscription (Reader Info):
+----------------------------------------+
| Endpoint GUID: [02, 1a, bb, ..., c7]   |
| Topic Name: "SensorTopic"              |
| Type Name: "sensors::SensorData"       |
| Reliability: Reliable                  |
| Durability: Volatile                   |
+----------------------------------------+
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
| Reliability | Writer >= Reader |
| Durability | Writer >= Reader |
| Deadline | Writer <= Reader |
| Liveliness | Writer kind >= Reader kind |
| Ownership | Writer = Reader |

## Discovery Events

HDDS reports discovery through endpoint matching. There is no participant-level
listener: a participant appearing or disappearing is visible through the
queries below, and through the match status of the endpoints it affects.

### Endpoint Events

Match changes are delivered to the listener attached to a writer or a reader.
Both listener traits take `&self` and a status struct.

```rust
use hdds::dds::{
    DataReaderListener, DataWriterListener, PublicationMatchedStatus, SubscriptionMatchedStatus,
};

struct MyListener;

impl<T: hdds::DdsTrait> DataWriterListener<T> for MyListener {
    fn on_publication_matched(&self, status: PublicationMatchedStatus) {
        println!(
            "Writer matched readers: change {}, current {}",
            status.current_count_change, status.current_count
        );
    }
}

impl<T: hdds::DdsTrait> DataReaderListener<T> for MyListener {
    fn on_subscription_matched(&self, status: SubscriptionMatchedStatus) {
        println!(
            "Reader matched writers: change {}, current {}",
            status.current_count_change, status.current_count
        );
    }
}
```

Attach a listener with `.with_listener(Arc::new(MyListener))` on the writer or
reader builder, or with `set_listener` on an existing entity. The same
information is available by polling `get_publication_matched_status()` on a
writer and `get_subscription_matched_status()` on a reader.

## Discovery Queries

### List Discovered Participants

The discovery state machine of a participant lists the remote participants
learned through SPDP:

```rust
if let Some(discovery) = participant.discovery() {
    for info in discovery.get_participants() {
        println!("Participant: {:?}", info.guid);
        println!("  Lease: {} ms", info.lease_duration_ms);
        println!("  Unicast locators: {:?}", info.endpoints);
    }
}
```

### List Discovered Topics and Endpoints

```rust
for topic in participant.discover_topics()? {
    println!("Topic: {} (type: {})", topic.name, topic.type_name);
}

for endpoint in participant.discover_endpoints()? {
    println!(
        "{:?} on {} (type: {})",
        endpoint.kind, endpoint.topic_name, endpoint.type_name
    );
}
```

`discover_endpoints()` returns every discovered user endpoint with its
advertised QoS; built-in `DCPS*` endpoints are omitted.

### Check Matched Endpoints

```rust
// Writer side
println!("Matched readers: {}", writer.matched_reader_count());
for reader_guid in writer.get_matched_subscriptions() {
    println!("Matched reader: {:?}", reader_guid);
}

// Reader side
for writer_guid in reader.get_matched_publications() {
    println!("Matched writer: {:?}", writer_guid);
}
```

## Static Discovery

For networks without multicast, list the peers by unicast. Point each entry at
the peer's metatraffic unicast port (7410 + 250 x domain + 2 x participant
index):

```rust
use hdds::{Participant, TransportOptions};

let participant = Participant::builder("gateway")
    .domain_id(0)
    // Never send or listen on multicast
    .with_transport_options(TransportOptions::default().unicast_only())
    // Peers to announce to
    .add_static_peer("192.168.1.100:7410")
    .add_static_peer("192.168.1.101:7410")
    .build()?;
```

`with_seed_peers("ip:port,ip:port")` takes a comma-separated list, and the
`HDDS_SPDP_UNICAST_PEERS` environment variable accepts the same list. For
larger deployments, see the Discovery Server (`with_discovery_server`).

## Discovery Timing

Discovery convergence depends on participant count, announcement policy,
topology, packet loss, vendor behavior, and machine load. HDDS does not
currently publish a reference-grade convergence matrix. A valid measurement must
assert that every expected participant and endpoint matched instead of relying
on a fixed sleep.

### Speeding Up Discovery

A shorter announcement period makes late joiners visible sooner, and a shorter
lease detects a failed participant sooner, at the cost of more discovery
traffic:

```rust
use hdds::Participant;
use std::time::Duration;

let participant = Participant::builder("sensor_node")
    .with_spdp_announcement_period(Duration::from_secs(1))
    .with_participant_lease_duration(Duration::from_secs(10))
    .build()?;
```

## Troubleshooting Discovery

### No Participants Found

```bash
# Verify SPDP traffic (domain 0)
tcpdump -i any -n udp port 7400

# Pin discovery to one interface (interface name or IPv4 address)
export HDDS_INTERFACE=eth0
```

HDDS logs through the `log` crate. In a Rust program, install a log backend
such as `env_logger` and run with `RUST_LOG=hdds=debug` to see discovery
activity; each participant logs a `discovery config:` line at startup.

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

Required ports, for domain `N`:

```
UDP 7400 + 250 x N  to  7649 + 250 x N   (discovery + data)
UDP 239.255.0.1                           (multicast group, if enabled)
```

## Vendor Interoperability

Discovery follows the standard RTPS protocols, so SPDP and SEDP work across
DDS vendors. The interoperability runs published with the project cover:

| Vendor | SPDP | SEDP |
|--------|------|------|
| Fast DDS | Yes | Yes |
| Cyclone DDS | Yes | Yes |
| OpenDDS | Yes | Yes |

Versions and the commands to reproduce these runs are listed in
[Interoperability](../interop/index.md).

## Discovery Architecture

```
+-------------------------------------------------------------+
|                    Discovery Subsystem                       |
+-------------------------------------------------------------+
|                                                              |
|  +--------------+    +--------------+    +--------------+   |
|  | SPDP Writer  |    | SEDP Pubs    |    | SEDP Subs    |   |
|  |   (builtin)  |    |   Writer     |    |   Writer     |   |
|  +--------------+    +--------------+    +--------------+   |
|         |                   |                   |            |
|         v                   v                   v            |
|  +------------------------------------------------------+   |
|  |               Discovery Database                      |   |
|  |  - Discovered Participants                           |   |
|  |  - Discovered Endpoints                              |   |
|  |  - Matching State                                    |   |
|  +------------------------------------------------------+   |
|         ^                   ^                   ^            |
|  +--------------+    +--------------+    +--------------+   |
|  | SPDP Reader  |    | SEDP Pubs    |    | SEDP Subs    |   |
|  |   (builtin)  |    |   Reader     |    |   Reader     |   |
|  +--------------+    +--------------+    +--------------+   |
|                                                              |
+-------------------------------------------------------------+
```

## Next Steps

- [Architecture](../concepts/architecture.md) - System overview
- [Cross-Vendor Example](../examples/cross-vendor.md) - Interoperability demo
- [Wire Compatibility](../interop/wire-compatibility.md) - Protocol details
