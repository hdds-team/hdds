# HDDS Architecture

HDDS follows a layered architecture designed for performance, modularity, and standards compliance.

## Layer Overview

```
+-------------------------------------------------------------+
|                     Application Layer                        |
|            (Your Rust/C/C++/Python Application)              |
+-------------------------------------------------------------+
|                        DCPS Layer                            |
|   Participant | Publisher | Subscriber | Topic | QoS        |
+-------------------------------------------------------------+
|                        RTPS Layer                            |
|    Discovery (SPDP/SEDP) | Writers | Readers | History      |
+-------------------------------------------------------------+
|                     Transport Layer                          |
|   UDP Multicast | UDP Unicast | Shared Memory | TCP | QUIC     |
+-------------------------------------------------------------+
```

## DCPS Layer (Data-Centric Publish-Subscribe)

The DCPS layer provides the DDS API that applications interact with:

| Entity | Purpose |
|--------|---------|
| **Participant** (DomainParticipant) | Entry point, factory for all other entities |
| **Publisher** | Groups DataWriters, applies common QoS |
| **Subscriber** | Groups DataReaders, applies common QoS |
| **Topic** | Named data channel with type |
| **DataWriter** | Writes samples to a topic |
| **DataReader** | Reads samples from a topic |

### Entity Hierarchy

```
Participant
+-- Publisher
|   +-- DataWriter<SensorData>
|   +-- DataWriter<Command>
+-- Subscriber
|   +-- DataReader<SensorData>
|   +-- DataReader<Status>
+-- Topic
    +-- "SensorTopic"
    +-- "CommandTopic"
```

Writers and readers are usually created through a typed topic
(`participant.topic::<T>(name)?.writer().build()?`); a Publisher or Subscriber
is only needed to share entity-level QoS such as a partition.

## RTPS Layer (Real-Time Publish-Subscribe)

The RTPS layer implements the wire protocol for interoperability:

### RTPS Writers and Readers

```
+------------------+     RTPS Protocol      +------------------+
|   RTPS Writer    | ---------------------> |   RTPS Reader    |
|                  |                        |                  |
|  +------------+  |     DATA, HEARTBEAT    |  +------------+  |
|  |  History   |  | ------------------->   |  |  History   |  |
|  |   Cache    |  |                        |  |   Cache    |  |
|  +------------+  |     ACKNACK, GAP       |  +------------+  |
|                  | <-------------------   |                  |
+------------------+                        +------------------+
```

### History Cache

Each writer and reader maintains a history cache:

- **Writer History**: Stores samples until acknowledged
- **Reader History**: Stores received samples until consumed

```rust
use hdds::QoS;

// History depth controlled by QoS
let qos = QoS::reliable().keep_last(100);
```

## Discovery Architecture

Discovery uses two protocols running on built-in endpoints:

```
+-------------------------------------------------------------+
|                        Participant                           |
+------------------------+------------------------------------+
|   SPDP (Participants)  |   SEDP (Endpoints)                 |
|                        |                                    |
|  BuiltinParticipant    |  BuiltinPublications              |
|    Writer/Reader       |    Writer/Reader                   |
|                        |                                    |
|  Multicast: 239.255.0.1|  BuiltinSubscriptions             |
|  Port: 7400 + 250 x    |    Writer/Reader                   |
|        domain          |                                    |
+------------------------+------------------------------------+
```

### Discovery Flow

```
1. SPDP Announcement (multicast)
   Participant A --> 239.255.0.1:7400 --> Participant B   (domain 0)

2. SEDP Exchange (unicast)
   A.Publications ------> B (endpoints info)
   A <------ B.Publications (endpoints info)

3. Matching
   A.Writer matches B.Reader (QoS compatible)

4. User Data Flow
   A.Writer --> DATA --> B.Reader
```

## Transport Layer

HDDS supports multiple transports:

| Transport | Use Case | Path |
|-----------|----------|------|
| **UDP Multicast** | Discovery, multi-subscriber | Network |
| **UDP Unicast** | Point-to-point, no-multicast networks | Network |
| **Shared Memory** | Same-host BEST_EFFORT readers and writers (Linux) | Same host |
| **TCP** | Networks where UDP does not pass (optional TLS, feature `tcp-tls`) | Network |
| **QUIC** | NAT traversal, connection migration (feature `quic`) | Network |

Discovery and the reliability control traffic (HEARTBEAT, ACKNACK) always use
UDP. Shared memory carries the DATA of a BEST_EFFORT writer paired with a
BEST_EFFORT reader on the same host; the choice is made once per peer, when
the two are paired.

### Transport Selection

```rust
use hdds::{Participant, ShmPolicy, TransportMode};

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast) // default
    .shm_policy(ShmPolicy::Prefer)               // default; Disable turns it off
    .build()?;
```

`with_tcp`, `with_quic` and `with_lowbw` configure the optional transports.

## Threading Model

HDDS runs a small set of dedicated background threads per participant. There
is no async runtime in the default build; the `tokio` runtime is only used by
the optional `quic`, `cloud-discovery` and `rpc` features.

```
+-------------------------------------------------------------+
|                      User Threads                            |
|    (write(), take(), topic(), etc.)                         |
+-------------------------------------------------------------+
|                     HDDS Background Threads                  |
|  +-------------+  +-------------+  +---------------------+  |
|  |  Discovery  |  |   Receive   |  |  Timers: heartbeat, |  |
|  |  + leases   |  |  + routing  |  |  liveliness, cleanup|  |
|  +-------------+  +-------------+  +---------------------+  |
+-------------------------------------------------------------+
```

- **User threads**: `write()` and `take()` run on the calling thread
- **Discovery threads**: SPDP announcements, SEDP exchange and lease tracking
- **Receive threads**: Multicast and unicast sockets, routing of samples to readers
- **Timer threads**: Heartbeats, deadlines, liveliness, history cleanup

Dropping the participant stops and joins every thread it started.

## Memory Architecture

Each writer and reader owns a history cache whose size is bounded by the
HISTORY and RESOURCE_LIMITS policies, so memory growth is bounded by
configuration:

```rust
use hdds::QoS;

let mut qos = QoS::reliable();
qos.resource_limits = hdds::qos::ResourceLimits {
    max_samples: 10000,
    max_instances: 100,
    max_samples_per_instance: 100,
    ..Default::default()
};
```

The defaults follow the DDS specification: `max_samples`, `max_instances` and
`max_samples_per_instance` are unlimited, and `max_quota_bytes` (the byte quota
of a RELIABLE history cache) is an HDDS-specific bound.

## Data Flow

### Write Path

```
1. Application calls writer.write(&sample)
2. Sample serialized (CDR, XCDR1 or XCDR2 as negotiated with the reader)
3. Added to writer history cache
4. Packed into RTPS DATA submessage
5. Sent via transport (UDP/SHM)
6. Acknowledged (if reliable)
7. Removed from history (if acknowledged)
```

### Read Path

```
1. Network receives RTPS packet
2. Parse submessages (DATA, HEARTBEAT, etc.)
3. Deserialize sample
4. Add to reader history cache
5. Send ACKNACK (if reliable)
6. Application calls reader.take()
7. Sample removed from history
```

## Module Structure

The `hdds` crate (`crates/hdds/src`):

```
hdds/
+-- dds/            # Public DDS API (Participant, Topic, DataWriter, DataReader, listeners, WaitSet)
+-- qos/            # QoS policy types
+-- core/           # Serialization (CDR), runtime, discovery state machines
+-- protocol/       # RTPS message and discovery wire formats
+-- reliability/    # Reliable delivery: history cache, ACKNACK/HEARTBEAT state
+-- engine/         # Receive path: routing and demultiplexing to readers
+-- discovery/      # Discovery backends (Kubernetes, DNS-SD, cloud)
+-- discovery_server/ # Discovery Server client and protocol
+-- transport/      # UDP, shared memory, TCP, QUIC, low-bandwidth
+-- security/       # DDS Security (feature `security`)
+-- xtypes/         # XTypes type system
```

## Performance Characteristics

Latency depends on the transport, topology, payload, QoS, concurrency, build,
and machine. See the [benchmark guide](../guides/performance/benchmarks.md) for
the currently certified operation and the evidence required for new claims.

## Next Steps

- [DomainParticipant](../concepts/participants.md) - Entry point details
- [Topics](../concepts/topics.md) - Data channels
- [Discovery](../concepts/discovery.md) - How endpoints find each other
