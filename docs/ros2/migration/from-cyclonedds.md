# Migrate from CycloneDDS

Guide to switching from CycloneDDS (rmw_cyclonedds) to HDDS (rmw_hdds) in ROS2 applications.

## Quick Migration

### Step 1: Install rmw_hdds

```bash
sudo apt install ros-$ROS_DISTRO-rmw-hdds
```

### Step 2: Update Environment

```bash
# Remove CycloneDDS setting
unset CYCLONEDDS_URI

# Set HDDS
export RMW_IMPLEMENTATION=rmw_hdds_cpp
```

### Step 3: Verify

```bash
ros2 doctor --report | grep rmw
# Output: middleware name    : rmw_hdds_cpp
```

## Configuration Migration

### Environment Variables

| CycloneDDS | HDDS | Description |
|------------|------|-------------|
| `ROS_DOMAIN_ID` | `ROS_DOMAIN_ID` or `HDDS_DOMAIN_ID` | Domain ID (HDDS var takes priority) |
| `CYCLONEDDS_URI` | `HDDS_QOS_PROFILE_PATH` | QoS profile file path |
| `CYCLONEDDS_PID_FILE` | N/A | Not applicable |

### XML Configuration

**CycloneDDS configuration:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<CycloneDDS xmlns="https://cdds.io/config">
    <Domain id="any">
        <General>
            <NetworkInterfaceAddress>eth0</NetworkInterfaceAddress>
            <AllowMulticast>true</AllowMulticast>
        </General>
        <Discovery>
            <ParticipantIndex>auto</ParticipantIndex>
            <MaxAutoParticipantIndex>100</MaxAutoParticipantIndex>
        </Discovery>
        <Tracing>
            <Verbosity>warning</Verbosity>
        </Tracing>
    </Domain>
</CycloneDDS>
```

**Equivalent HDDS configuration:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<hdds>
    <domain id="0">
        <transport>
            <udp enabled="true">
                <interface>eth0</interface>
                <multicast enabled="true"/>
            </udp>
        </transport>
        <logging level="warn"/>
    </domain>
</hdds>
```

## QoS Configuration Mapping

### Reliability

**CycloneDDS (XML):**
```xml
<Reliability>
    <Kind>reliable</Kind>
    <MaxBlockingTime>1s</MaxBlockingTime>
</Reliability>
```

**HDDS:**
```xml
<reliability kind="RELIABLE" max_blocking_ms="1000"/>
```

### History

**CycloneDDS:**
```xml
<History>
    <Kind>keep_last</Kind>
    <Depth>10</Depth>
</History>
```

**HDDS:**
```xml
<history kind="KEEP_LAST" depth="10"/>
```

### Durability

| CycloneDDS | HDDS |
|------------|------|
| `volatile` | `VOLATILE` |
| `transient_local` | `TRANSIENT_LOCAL` |
| `transient` | `TRANSIENT` |
| `persistent` | `PERSISTENT` |

## Transport Configuration

### Network Interface

**CycloneDDS:**
```xml
<General>
    <NetworkInterfaceAddress>192.168.1.0/24</NetworkInterfaceAddress>
</General>
```

**HDDS:**
```xml
<transport>
    <udp>
        <interface>192.168.1.0/24</interface>
    </udp>
</transport>
```

### Multicast Settings

**CycloneDDS:**
```xml
<General>
    <AllowMulticast>spdp</AllowMulticast>
    <MulticastTimeToLive>1</MulticastTimeToLive>
</General>
```

**HDDS:**
```xml
<transport>
    <udp>
        <multicast enabled="true">
            <spdp>true</spdp>
            <sedp>false</sedp>
            <ttl>1</ttl>
        </multicast>
    </udp>
</transport>
```

### Socket Buffers

**CycloneDDS:**
```xml
<Internal>
    <SocketReceiveBufferSize min="1MB"/>
    <SocketSendBufferSize min="1MB"/>
</Internal>
```

**HDDS:**
```xml
<transport>
    <udp>
        <receive_buffer_size>1048576</receive_buffer_size>
        <send_buffer_size>1048576</send_buffer_size>
    </udp>
</transport>
```

## Discovery Configuration

### Peers/Initial Locators

**CycloneDDS:**
```xml
<Discovery>
    <Peers>
        <Peer address="192.168.1.100"/>
        <Peer address="192.168.1.101"/>
    </Peers>
</Discovery>
```

**HDDS:**
```xml
<discovery>
    <initial_peers>
        <peer>192.168.1.100:7400</peer>
        <peer>192.168.1.101:7400</peer>
    </initial_peers>
</discovery>
```

### Lease Duration

**CycloneDDS:**
```xml
<Discovery>
    <LeaseDuration>10s</LeaseDuration>
</Discovery>
```

**HDDS:**
```xml
<discovery>
    <lease_duration_sec>10</lease_duration_sec>
</discovery>
```

## Shared Memory (Iceoryx)

### CycloneDDS with Iceoryx

**CycloneDDS:**
```xml
<Domain id="any">
    <SharedMemory>
        <Enable>true</Enable>
        <LogLevel>warning</LogLevel>
    </SharedMemory>
</Domain>
```

### HDDS Shared Memory

**HDDS (built-in, no Iceoryx needed):**
```xml
<transport>
    <shared_memory enabled="true">
        <segment_size_mb>64</segment_size_mb>
        <prefer>true</prefer>
    </shared_memory>
</transport>
```

:::note
HDDS supports UDP, TCP, and shared memory transports. Transport configuration is done via QoS profiles or the [HDDS core configuration](../../reference/environment-vars.md).
:::

## Logging Configuration

### CycloneDDS Tracing

**CycloneDDS:**
```xml
<Tracing>
    <Verbosity>config</Verbosity>
    <OutputFile>cyclone.log</OutputFile>
    <Category>discovery</Category>
</Tracing>
```

### HDDS Logging

**HDDS:**
```bash
export HDDS_LOG_LEVEL=debug
export HDDS_LOG_FILE=/var/log/hdds.log
export HDDS_LOG_DISCOVERY=1
```

Or in XML:
```xml
<logging>
    <level>debug</level>
    <file>/var/log/hdds.log</file>
    <categories>
        <discovery>true</discovery>
    </categories>
</logging>
```

## Code Changes

### No Code Changes Required

rmw_hdds is API-compatible with standard ROS2:

```python
# Works unchanged with HDDS
import rclpy
from std_msgs.msg import String

def main():
    rclpy.init()
    node = rclpy.create_node('my_node')

    pub = node.create_publisher(String, 'topic', 10)
    sub = node.create_subscription(
        String, 'topic', lambda msg: print(msg.data), 10)

    rclpy.spin(node)

if __name__ == '__main__':
    main()
```

### Remove CycloneDDS-Specific Code

If you used CycloneDDS C API directly:

**Before (CycloneDDS-specific):**
```c
#include <dds/dds.h>
dds_entity_t participant = dds_create_participant(0, NULL, NULL);
```

**After (RMW-agnostic):**
```cpp
// Use only ROS2 APIs
auto node = rclcpp::Node::make_shared("my_node");
```

## Performance Comparison

| Metric | CycloneDDS | HDDS | Notes |
|--------|------------|------|-------|
| Latency (64B) | 35 us | 8 us | Same host, SHM |
| Latency (UDP) | 50 us | 45 us | Same LAN |
| Throughput | 2.2 M/s | 2.5 M/s | 64B messages |
| Memory (idle) | 3 MB | 2 MB | Per participant |

## Common Migration Issues

### Issue: CYCLONEDDS_URI Not Recognized

**Symptom**: Configuration ignored after migration

**Solution**: Use HDDS configuration:
```bash
# Replace
export CYCLONEDDS_URI=file:///path/to/cyclone.xml

# With
export HDDS_QOS_PROFILE_PATH=/path/to/qos_profiles.yaml
```

### Issue: Different Multicast Behavior

**Symptom**: Discovery works differently

**Solution**: Match multicast settings:
```xml
<transport>
    <udp>
        <multicast enabled="true">
            <address>239.255.0.1</address>
        </multicast>
    </udp>
</transport>
```

### Issue: Shared Memory Performance Different

CycloneDDS uses Iceoryx, HDDS has built-in SHM.

**Solution**: Configure HDDS SHM:
```bash
# Increase segment size if needed
export HDDS_SHM_SEGMENT_SIZE=268435456  # 256 MB
```

### Issue: Security Configuration

**Solution**: Both use standard ROS2 SROS2:
```bash
export ROS_SECURITY_ENABLE=true
export ROS_SECURITY_STRATEGY=Enforce
```

## Feature Comparison

| Feature | CycloneDDS | HDDS |
|---------|------------|------|
| RTPS 2.4 | Yes | Yes |
| DDS Security | Yes | Yes |
| Shared Memory | Iceoryx | Built-in |
| XTypes | Partial | Full |
| Zero-copy | Iceoryx | Built-in |
| Content Filter | Yes | Yes |

## Mixed RMW Testing

CycloneDDS and HDDS interoperate via RTPS:

```bash
# Terminal 1: CycloneDDS
export RMW_IMPLEMENTATION=rmw_cyclonedds_cpp
ros2 run demo_nodes_cpp talker

# Terminal 2: HDDS
export RMW_IMPLEMENTATION=rmw_hdds_cpp
ros2 run demo_nodes_cpp listener

# Both communicate successfully
```

## Rollback

To revert to CycloneDDS:

```bash
unset HDDS_QOS_PROFILE_PATH
export RMW_IMPLEMENTATION=rmw_cyclonedds_cpp
export CYCLONEDDS_URI=file:///path/to/cyclone.xml
```

## Migration Checklist

- [ ] Install rmw_hdds package
- [ ] Remove `CYCLONEDDS_URI` environment variable
- [ ] Set `RMW_IMPLEMENTATION=rmw_hdds_cpp`
- [ ] Convert XML configuration to HDDS format
- [ ] Test with `ros2 doctor`
- [ ] Verify topic communication
- [ ] Check shared memory operation
- [ ] Performance test
- [ ] Update launch files and scripts
- [ ] Remove CycloneDDS packages (optional)

## Automated Conversion

Convert CycloneDDS XML to HDDS format:

```bash
# Using hdds-tools
hdds-convert cyclone-to-hdds \
    --input /path/to/cyclonedds.xml \
    --output /path/to/hdds.xml
```

## Next Steps

- [rmw_hdds Configuration](../../ros2/rmw-hdds/configuration.md) - Detailed settings
- [Performance Tuning](../../ros2/performance.md) - Optimization guide
- [Migration from FastDDS](../../ros2/migration/from-fastdds.md) - Alternative path
