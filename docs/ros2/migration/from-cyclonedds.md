# Migrate from CycloneDDS

Guide to switching from CycloneDDS (rmw_cyclonedds) to HDDS (rmw_hdds) in ROS2 applications.

## Quick Migration

### Step 1: Build rmw_hdds

`rmw_hdds` is built from source with colcon; see
[rmw_hdds Installation](../rmw-hdds/installation.md).

### Step 2: Update Environment

```bash
# Remove CycloneDDS setting
unset CYCLONEDDS_URI

# Set HDDS
export RMW_IMPLEMENTATION=rmw_hdds
```

### Step 3: Verify

```bash
ros2 doctor --report | grep middleware
ros2 run demo_nodes_cpp talker
```

## Configuration Migration

`rmw_hdds` does not read CycloneDDS XML configuration: `CYCLONEDDS_URI` has no
effect, and `HDDS_QOS_PROFILE_PATH` is parsed but not applied. Move the
settings you need to the environment variables below and to ROS 2 QoS profiles
in your code.

### Environment Variables

| CycloneDDS | HDDS | Description |
|------------|------|-------------|
| `ROS_DOMAIN_ID` | `ROS_DOMAIN_ID` or `HDDS_DOMAIN_ID` | Domain ID (HDDS var takes priority) |
| `General/NetworkInterfaceAddress` | `HDDS_INTERFACE` | Interface name or IPv4 address |
| `General/AllowMulticast` = `false` | `HDDS_MULTICAST_DISABLE=true` | Unicast discovery only |
| `Discovery/Peers` | `HDDS_DISCOVERY_PEERS` | Static peers, as `host:port` of each peer's metatraffic unicast port |
| `General/MulticastTimeToLive` | `HDDS_MULTICAST_TTL` (or `HDDS_TTL` for both) | TTL |
| `Internal/SocketReceiveBufferSize`, `SocketSendBufferSize` | `HDDS_RCVBUF_BYTES`, `HDDS_SNDBUF_BYTES` | UDP socket buffer requests |
| `Discovery/ParticipantIndex` | `HDDS_PARTICIPANT_ID` | Participant index (0-119) |

See the [HDDS core environment variables](../../reference/environment-vars.md)
and the [rmw_hdds Configuration](../rmw-hdds/configuration.md) page for what the
adapter applies.

### QoS

QoS is set the standard ROS 2 way, on the publisher or subscription:

| CycloneDDS | ROS 2 QoS |
|------------|-----------|
| `reliable` / `best_effort` | `reliability = RELIABLE` / `BEST_EFFORT` |
| `transient_local` / `volatile` | `durability = TRANSIENT_LOCAL` / `VOLATILE` |
| `keep_last`, `depth` | `history = KEEP_LAST`, `depth` |
| `keep_all` | `history = KEEP_ALL` |
| Deadline | `deadline` |
| Liveliness | `liveliness`, `liveliness_lease_duration` |

## Shared Memory (Iceoryx)

CycloneDDS shared memory uses Iceoryx and is not compatible with the HDDS
shared-memory transport. HDDS has its own shared-memory transport, offered to
co-located endpoints by default (`ShmPolicy::Prefer`); it applies only to
`BestEffort` endpoints, so it will not engage for most ROS 2 topics. See
[System Limits](../../reference/limits.md#shared-memory-transport).

## Logging

```bash
# Sets RUST_LOG when RUST_LOG is not already set
export HDDS_LOG_LEVEL=debug
# or a per-module filter
export RUST_LOG=hdds=debug
```

## Code Changes

### No Code Changes Required

`rmw_hdds` implements the standard RMW interface:

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

If you used the CycloneDDS C API directly:

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

## Performance Validation

A measured RMW comparison over ten rounds is published in [ROS 2 Performance](../performance.md).
Measure the migrated application under
identical conditions before drawing a performance conclusion.

## Common Migration Issues

### Issue: CYCLONEDDS_URI Not Recognized

**Symptom**: Configuration ignored after migration

**Solution**: `rmw_hdds` does not read it. Use the environment variables
above:
```bash
unset CYCLONEDDS_URI
export HDDS_INTERFACE=eth0
```

### Issue: Different Multicast Behavior

**Symptom**: Discovery works differently

**Solution**: Select the interface that carries multicast, or turn multicast
off and use static peers:
```bash
export HDDS_INTERFACE=eth0
# or
export HDDS_MULTICAST_DISABLE=true
export HDDS_DISCOVERY_PEERS=192.168.1.100:7410
```

### Issue: Security Configuration

`rmw_hdds` does not enable DDS Security in this release.
`ROS_SECURITY_STRATEGY=Enforce` makes the node refuse to start; with
`Permissive` the node starts unsecured. See
[rmw_hdds Configuration](../rmw-hdds/configuration.md#security-settings).

## Mixed RMW Testing

HDDS speaks standard RTPS; test the pairing with your own QoS:

```bash
# Terminal 1: CycloneDDS
export RMW_IMPLEMENTATION=rmw_cyclonedds_cpp
ros2 run demo_nodes_cpp talker

# Terminal 2: HDDS
export RMW_IMPLEMENTATION=rmw_hdds
ros2 run demo_nodes_cpp listener
```

## Rollback

To revert to CycloneDDS:

```bash
export RMW_IMPLEMENTATION=rmw_cyclonedds_cpp
export CYCLONEDDS_URI=file:///path/to/cyclone.xml
```

## Migration Checklist

- [ ] Build rmw_hdds
- [ ] Remove the `CYCLONEDDS_URI` environment variable
- [ ] Set `RMW_IMPLEMENTATION=rmw_hdds`
- [ ] Move network settings from XML to environment variables
- [ ] Verify topic communication
- [ ] Performance test
- [ ] Update launch files and scripts
- [ ] Remove CycloneDDS packages (optional)

## Next Steps

- [rmw_hdds Configuration](../../ros2/rmw-hdds/configuration.md) - Detailed settings
- [Performance Tuning](../../ros2/performance.md) - Optimization guide
- [Migration from FastDDS](../../ros2/migration/from-fastdds.md) - Alternative path
