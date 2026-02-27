# 04 - Discovery Samples

This directory contains samples demonstrating DDS discovery mechanisms and endpoint matching.

## Overview

DDS discovery enables participants to automatically find each other and establish communication. These samples show different discovery modes and configurations.

## Samples

| Sample | Description |
|--------|-------------|
| **simple_discovery** | Automatic participant discovery using SPDP multicast |
| **static_peers** | Manual peer configuration for non-multicast networks |
| **discovery_listeners** | Callbacks for discovery events (match/unmatch) |
| **partitions** | Logical data separation with partition QoS |

## Sample Descriptions

### simple_discovery

Demonstrates the default SPDP (Simple Participant Discovery Protocol) using multicast:

- Automatic participant discovery on the same domain
- Endpoint discovery (writers/readers)
- Liveliness and lease duration
- Discovery timeout handling

**Usage:**
```bash
# Terminal 1
./simple_discovery

# Terminal 2 (same domain)
./simple_discovery
```

### static_peers

Shows manual peer configuration for environments without multicast:

- TCP and UDP unicast support
- Explicit peer addresses
- Cloud/container deployments
- VPN and WAN scenarios

**Usage:**
```bash
# Terminal 1: Listen on port 7400
./static_peers --listen 7400

# Terminal 2: Connect to peer
./static_peers --peer 127.0.0.1:7400

# Using TCP transport
./static_peers --tcp --peer 192.168.1.10:7400
```

### discovery_listeners

Demonstrates discovery event callbacks:

- `on_participant_discovered` / `on_participant_lost`
- `on_publication_matched` / `on_publication_unmatched`
- `on_subscription_matched` / `on_subscription_unmatched`
- Event-driven architecture patterns

**Key concepts:**
- ParticipantListener for domain events
- WriterListener for publication matching
- ReaderListener for subscription matching
- Thread-safe event queuing

### partitions

Shows logical data separation within a domain:

- Publisher/Subscriber partition QoS
- Wildcard partition matching (`*`, `Sensor*`)
- Dynamic partition changes at runtime
- Multi-partition endpoints

**Usage:**
```bash
# Terminal 1: SensorA partition
./partitions --partition SensorA

# Terminal 2: SensorB partition (won't match Terminal 1)
./partitions --partition SensorB

# Terminal 3: Wildcard (matches both)
./partitions --partition "Sensor*"

# Multiple partitions
./partitions --partition SensorA --partition SensorB
```

## Discovery Concepts

### SPDP (Simple Participant Discovery Protocol)

- Multicast-based automatic discovery
- Default ports: 7400 (domain 0), 7401 (domain 1), etc.
- Participant announcements every few seconds
- Liveliness lease duration

### SEDP (Simple Endpoint Discovery Protocol)

- Follows SPDP to discover endpoints
- Matches DataWriters with DataReaders
- QoS compatibility checking
- Topic name and type matching

### Partition Matching

Partitions provide logical separation:

```
Partition A ────┬──── Partition B
                │
Topic "Data"    │    Topic "Data"
Writer ─────────┼──── Reader (NO MATCH - different partitions)
                │
                │
Partition A ────┴──── Partition A
Topic "Data"         Topic "Data"
Writer ────────────── Reader (MATCH - same partition)
```

Wildcard matching:
- `*` matches any partition
- `Sensor*` matches `SensorA`, `SensorB`, `SensorXYZ`

## Building

### C
```bash
cd c
mkdir build && cd build
cmake ..
make
```

### C++
```bash
cd cpp
mkdir build && cd build
cmake ..
make
```

### Rust
```bash
cd rust
cargo build --release
```

### Python
```bash
cd python
python simple_discovery.py
```

## Running Examples

### Two-Node Discovery Test
```bash
# Node 1
./simple_discovery

# Node 2 (separate terminal)
./simple_discovery
```

### Static Peer Configuration
```bash
# Server node
./static_peers --listen 7400

# Client node
./static_peers --peer server_ip:7400
```

### Partition Isolation
```bash
# These two will NOT communicate (different partitions)
./partitions --partition TeamA &
./partitions --partition TeamB &

# This one communicates with TeamA only
./partitions --partition TeamA
```

## Network Requirements

| Sample | Multicast | Unicast | TCP |
|--------|-----------|---------|-----|
| simple_discovery | Required | Optional | No |
| static_peers | Not used | Required | Optional |
| discovery_listeners | Required | Optional | No |
| partitions | Required | Optional | No |

## Troubleshooting

### No Peers Discovered
1. Check firewall allows UDP ports 7400-7410
2. Verify multicast is enabled on network interface
3. Ensure same domain ID (default: 0)
4. Check network interface binding

### Static Peers Not Connecting
1. Verify peer address is reachable: `ping <peer_ip>`
2. Check port is open: `nc -zv <peer_ip> <port>`
3. Ensure both sides have matching domain ID
4. For TCP, verify `--tcp` flag on both sides

### Partition Mismatch
1. Verify partition names match exactly (case-sensitive)
2. Check wildcard patterns are correct
3. Ensure partition is set on Publisher/Subscriber (not Participant)
