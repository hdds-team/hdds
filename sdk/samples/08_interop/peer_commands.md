# Vendor Peer Commands for Interop Samples

Each HDDS interop sample runs on one side of the wire. This document
describes how to start the vendor counterpart on the other side.

All samples use **domain 0** and standard RTPS multicast discovery
(`239.255.0.1`). Both peers must run on the same LAN or share multicast
connectivity.

---

## FastDDS — "InteropTest"

HDDS side: **publisher** (`fastdds_interop`).
FastDDS side: **subscriber**.

### Option A: fastdds CLI (v3.x)

```bash
# Generate types from IDL (StringMsg: {uint32 id; string message;})
fastddsgen StringMsg.idl

# Build and run the generated subscriber
cd StringMsg && mkdir build && cd build
cmake .. && make
./StringMsgSubscriber
```

### Option B: fastdds ShapesDemo

```bash
fastdds discovery   # start discovery server if needed
ShapesDemo          # subscribe to "InteropTest" with default QoS
```

### Option C: fastdds micro (ROS 2)

```bash
# If the IDL matches a ROS 2 message, use:
ros2 topic echo /InteropTest std_msgs/msg/String
```

---

## RTI Connext — "InteropTest"

HDDS side: **subscriber** (`rti_interop`).
RTI Connext side: **publisher**.

### Using rtiddsgen + generated code

```bash
# Generate publisher from IDL
rtiddsgen -language C++11 -example x64Linux4gcc7.3.0 StringMsg.idl

# Build
cd StringMsg && mkdir build && cd build
cmake .. && make

# Run publisher — publishes to domain 0 by default
./StringMsg_publisher -t InteropTest
```

### Using rtiddsping (quick test)

```bash
# Ping on the topic — sends small payloads
rtiddsping -topic InteropTest -domainId 0
```

### Using Admin Console

1. Open RTI Admin Console
2. Join domain 0
3. Create a DataWriter on topic `InteropTest`
4. Publish test messages

---

## CycloneDDS — "InteropTest"

HDDS side: **bidirectional** (`cyclone_interop`).
CycloneDDS side: **bidirectional** (pub + sub).

### Option A: ddsperf (built-in benchmark)

```bash
# ddsperf does pub+sub on a configurable topic
ddsperf -T InteropTest pub sub
```

### Option B: CycloneDDS examples

```bash
# Clone and build CycloneDDS examples
git clone https://github.com/eclipse-cyclonedds/cyclonedds
cd cyclonedds && mkdir build && cd build
cmake -DBUILD_EXAMPLES=ON .. && make

# Terminal 1 — publisher
./bin/HelloworldPublisher   # modify topic name to "InteropTest"

# Terminal 2 — subscriber
./bin/HelloworldSubscriber  # modify topic name to "InteropTest"
```

### Option C: cyclonedds Python bindings

```bash
pip install cyclonedds
python3 -c "
import cyclonedds.core as dds
import cyclonedds.topic as topic
import cyclonedds.pub as pub

dp = dds.DomainParticipant(0)
tp = topic.Topic(dp, 'InteropTest', bytes)
wr = pub.DataWriter(dp, tp)
wr.write(b'CycloneDDS pong #1')
"
```

---

## IDL Reference

All samples use this wire-compatible type:

```idl
struct StringMsg {
    unsigned long id;       // 4 bytes, LE
    string        message;  // CDR string (4-byte length + data + null + padding)
};
```

CDR encoding (little-endian):
```
Offset  Size  Field
0       4     id (uint32 LE)
4       4     string length including null (uint32 LE)
8       N     string bytes + null terminator
8+N     pad   0-3 bytes to align to 4
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| No discovery | Multicast blocked | Check firewall / `iptables -L` |
| Type mismatch | Different CDR layout | Ensure same IDL / field order |
| QoS incompatible | Reliability mismatch | Both sides reliable or both best-effort |
| Domain mismatch | Different domain ID | Both must use domain 0 (default) |
