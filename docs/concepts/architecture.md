# HDDS Architecture

HDDS follows a layered architecture designed for performance, modularity, and standards compliance.

## Layer Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     Application Layer                        │
│            (Your Rust/C/C++/Python Application)              │
├─────────────────────────────────────────────────────────────┤
│                        DCPS Layer                            │
│   DomainParticipant │ Publisher │ Subscriber │ Topic │ QoS  │
├─────────────────────────────────────────────────────────────┤
│                        RTPS Layer                            │
│    Discovery (SPDP/SEDP) │ Writers │ Readers │ History      │
├─────────────────────────────────────────────────────────────┤
│                     Transport Layer                          │
│           UDP Multicast │ UDP Unicast │ Shared Memory        │
└─────────────────────────────────────────────────────────────┘
```

## DCPS Layer (Data-Centric Publish-Subscribe)

The DCPS layer provides the DDS API that applications interact with:

| Entity | Purpose |
|--------|---------|
| **DomainParticipant** | Entry point, owns all other entities |
| **Publisher** | Groups DataWriters, applies common QoS |
| **Subscriber** | Groups DataReaders, applies common QoS |
| **Topic** | Named data channel with type |
| **DataWriter** | Writes samples to a topic |
| **DataReader** | Reads samples from a topic |

### Entity Hierarchy

```
DomainParticipant
├── Publisher
│   ├── DataWriter<SensorData>
│   └── DataWriter<Command>
├── Subscriber
│   ├── DataReader<SensorData>
│   └── DataReader<Status>
└── Topic
    ├── "SensorTopic"
    └── "CommandTopic"
```

## RTPS Layer (Real-Time Publish-Subscribe)

The RTPS layer implements the wire protocol for interoperability:

### RTPS Writers and Readers

```
┌──────────────────┐     RTPS Protocol      ┌──────────────────┐
│   RTPS Writer    │ ─────────────────────> │   RTPS Reader    │
│                  │                        │                  │
│  ┌────────────┐  │     DATA, HEARTBEAT    │  ┌────────────┐  │
│  │  History   │  │ ───────────────────>   │  │  History   │  │
│  │   Cache    │  │                        │  │   Cache    │  │
│  └────────────┘  │     ACKNACK, GAP       │  └────────────┘  │
│                  │ <───────────────────   │                  │
└──────────────────┘                        └──────────────────┘
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
┌─────────────────────────────────────────────────────────────┐
│                    DomainParticipant                         │
├────────────────────────┬────────────────────────────────────┤
│   SPDP (Participants)  │   SEDP (Endpoints)                 │
│                        │                                    │
│  BuiltinParticipant    │  BuiltinPublications              │
│    Writer/Reader       │    Writer/Reader                   │
│                        │                                    │
│  Multicast: 239.255.x.x│  BuiltinSubscriptions             │
│  Port: 7400 + offset   │    Writer/Reader                   │
└────────────────────────┴────────────────────────────────────┘
```

### Discovery Flow

```
1. SPDP Announcement (multicast)
   Participant A ──> 239.255.0.1:7400 ──> Participant B

2. SEDP Exchange (unicast)
   A.Publications ──────> B (endpoints info)
   A <────── B.Publications (endpoints info)

3. Matching
   A.Writer matches B.Reader (QoS compatible)

4. User Data Flow
   A.Writer ──> DATA ──> B.Reader
```

## Transport Layer

HDDS supports multiple transports:

| Transport | Use Case | Latency |
|-----------|----------|---------|
| **UDP Multicast** | Discovery, multi-subscriber | Medium |
| **UDP Unicast** | Point-to-point, WAN | Medium |
| **Shared Memory** | Same-host, high performance | Low (~1 us) |

### Transport Selection

```rust
let config = ParticipantConfig::default()
    .transport(Transport::UdpMulticast)   // Default
    .transport(Transport::SharedMemory);   // Add SHM
```

## Threading Model

HDDS uses an async runtime with dedicated threads:

```
┌─────────────────────────────────────────────────────────────┐
│                      User Threads                            │
│    (write(), take(), create_reader(), etc.)                 │
├─────────────────────────────────────────────────────────────┤
│                     HDDS Runtime                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  Discovery  │  │   I/O Pool  │  │   Timer/Scheduler   │  │
│  │   Thread    │  │  (tokio)    │  │                     │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

- **User threads**: Application calls are non-blocking where possible
- **Discovery thread**: Handles SPDP/SEDP protocol
- **I/O pool**: Async network operations (tokio-based)
- **Timer thread**: Heartbeats, deadlines, liveliness

## Memory Architecture

### Zero-Copy Path

For high-performance scenarios, HDDS supports zero-copy:

```rust
// Standard path (copy)
writer.write(&sample)?;

// Zero-copy path (loan buffer)
let mut loan = writer.loan_sample()?;
*loan = sample;
loan.write()?;  // No copy to internal buffer
```

### Buffer Management

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   User Buffer   │ -> │  History Cache  │ -> │ Network Buffer  │
│                 │    │   (per-writer)  │    │   (per-send)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

Resource limits prevent unbounded memory growth:

```rust
use hdds::QoS;

let qos = QoS::reliable()
    .max_samples(10000)
    .max_instances(100)
    .max_samples_per_instance(100);
```

## Data Flow

### Write Path

```
1. Application calls writer.write(&sample)
2. Sample serialized (CDR2/XCDR2)
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

```
hdds/
├── dcps/           # DDS API (Participant, Publisher, etc.)
├── rtps/           # RTPS protocol implementation
│   ├── writer.rs   # RTPS writer state machine
│   ├── reader.rs   # RTPS reader state machine
│   ├── discovery/  # SPDP and SEDP
│   └── messages/   # RTPS message types
├── transport/      # Network transports
│   ├── udp.rs
│   └── shm.rs
├── serialization/  # CDR/XCDR2 codecs
└── qos/           # QoS policy implementations
```

## Performance Characteristics

| Operation | Typical Latency |
|-----------|-----------------|
| write() to network | 5-50 us |
| Network to take() | 10-100 us |
| Shared memory RTT | 1-5 us |
| Discovery (cold start) | 100-500 ms |

## Next Steps

- [DomainParticipant](../concepts/participants.md) - Entry point details
- [Topics](../concepts/topics.md) - Data channels
- [Discovery](../concepts/discovery.md) - How endpoints find each other
