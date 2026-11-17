# Migrate from FastDDS

Guide to switching from FastDDS (rmw_fastrtps) to HDDS (rmw_hdds) in ROS2 applications.

## Quick Migration

### Step 1: Build rmw_hdds

`rmw_hdds` is built from source with colcon; see
[rmw_hdds Installation](../rmw-hdds/installation.md).

### Step 2: Set Environment

```bash
export RMW_IMPLEMENTATION=rmw_hdds
```

### Step 3: Test

```bash
ros2 run demo_nodes_cpp talker
```

That's it for basic applications. The sections below cover advanced configurations.

## Configuration Migration

`rmw_hdds` does not read FastDDS XML profiles: `FASTRTPS_DEFAULT_PROFILES_FILE`
and `RMW_FASTRTPS_USE_QOS_FROM_XML` have no effect, and `HDDS_QOS_PROFILE_PATH`
is parsed but not applied. Move the settings you need to the environment
variables below and to ROS 2 QoS profiles in your code.

### Environment Variables

| FastDDS | HDDS | Description |
|---------|------|-------------|
| `ROS_DOMAIN_ID` | `ROS_DOMAIN_ID` or `HDDS_DOMAIN_ID` | Domain ID (HDDS var takes priority) |
| `<initialPeersList>` locators | `HDDS_DISCOVERY_PEERS` | Static peers, as `host:port` of each peer's metatraffic unicast port |
| UDPv4 transport `<interfaceWhiteList>` | `HDDS_INTERFACE` | Interface name or IPv4 address |
| `<sendBufferSize>` / `<receiveBufferSize>` | `HDDS_SNDBUF_BYTES` / `HDDS_RCVBUF_BYTES` | UDP socket buffer requests |
| Multicast disabled | `HDDS_MULTICAST_DISABLE=true` | Unicast discovery only |

See the [HDDS core environment variables](../../reference/environment-vars.md)
and the [rmw_hdds Configuration](../rmw-hdds/configuration.md) page for what the
adapter applies.

### QoS

QoS is set the standard ROS 2 way, on the publisher or subscription, so a
FastDDS QoS XML profile becomes a QoS profile in code:

| FastDDS | ROS 2 QoS |
|---------|-----------|
| `RELIABLE_RELIABILITY_QOS` | `reliability = RELIABLE` |
| `BEST_EFFORT_RELIABILITY_QOS` | `reliability = BEST_EFFORT` |
| `TRANSIENT_LOCAL_DURABILITY_QOS` | `durability = TRANSIENT_LOCAL` |
| `VOLATILE_DURABILITY_QOS` | `durability = VOLATILE` |
| `KEEP_LAST_HISTORY_QOS`, `depth` | `history = KEEP_LAST`, `depth` |
| `<deadline>` period | `deadline` |
| `<liveliness>` kind and lease | `liveliness`, `liveliness_lease_duration` |

```cpp
auto qos = rclcpp::QoS(10)
    .reliable()
    .transient_local();
auto pub = node->create_publisher<std_msgs::msg::String>("topic", qos);
```

## Code Changes

### No Code Changes Required

`rmw_hdds` implements the standard RMW interface. Standard ROS2 code works without modification:

```cpp
// This code works with both FastDDS and HDDS
#include <rclcpp/rclcpp.hpp>
#include <std_msgs/msg/string.hpp>

int main(int argc, char** argv) {
    rclcpp::init(argc, argv);
    auto node = std::make_shared<rclcpp::Node>("my_node");

    auto pub = node->create_publisher<std_msgs::msg::String>("topic", 10);
    auto sub = node->create_subscription<std_msgs::msg::String>(
        "topic", 10,
        [](std_msgs::msg::String::SharedPtr msg) {
            RCLCPP_INFO(rclcpp::get_logger("sub"), "Received: %s", msg->data.c_str());
        });

    rclcpp::spin(node);
    return 0;
}
```

### Optional: Vendor-Specific Extensions

If you used FastDDS-specific APIs, remove them:

**Before (FastDDS-specific):**
```cpp
#include <fastdds/dds/domain/DomainParticipantFactory.hpp>
// Direct FastDDS API calls...
```

**After (RMW-agnostic):**
```cpp
// Use only standard ROS2 APIs
#include <rclcpp/rclcpp.hpp>
```

## Performance Validation

A measured RMW comparison over ten rounds is published in [ROS 2 Performance](../performance.md).
Measure the migrated application under
identical conditions before drawing a performance conclusion.

## Common Migration Issues

### Issue: Different Default QoS

FastDDS and HDDS may have different defaults.

**Solution**: Explicitly set QoS in code:

```cpp
auto qos = rclcpp::QoS(10)
    .reliable()
    .durability_volatile();
auto pub = node->create_publisher<MyMsg>("topic", qos);
```

### Issue: Discovery Does Not Complete

**Solution**: Check the domain id and the network. Without multicast, list
the peers by their metatraffic unicast port (`7410 + 250 x domain + 2 x
participant index`):

```bash
export HDDS_MULTICAST_DISABLE=true
export HDDS_DISCOVERY_PEERS=192.168.1.100:7410
```

### Issue: Wrong Network Interface

```bash
export HDDS_INTERFACE=eth0
```

### Issue: Security Configuration Differs

`rmw_hdds` does not enable DDS Security in this release.
`ROS_SECURITY_STRATEGY=Enforce` makes the node refuse to start; with
`Permissive` the node starts unsecured. See
[rmw_hdds Configuration](../rmw-hdds/configuration.md#security-settings).

## Rollback Plan

To switch back to FastDDS:

```bash
# Unset HDDS
unset RMW_IMPLEMENTATION

# Or explicitly set FastDDS
export RMW_IMPLEMENTATION=rmw_fastrtps_cpp
```

## Gradual Migration

For large systems, migrate incrementally:

1. **Test environment**: Switch one node at a time
2. **Verify communication**: HDDS speaks standard RTPS, so test it against your FastDDS nodes with your QoS
3. **Performance test**: Measure latency and throughput
4. **Production rollout**: Switch all nodes

### Mixed RMW Testing

```bash
# Terminal 1: FastDDS publisher
export RMW_IMPLEMENTATION=rmw_fastrtps_cpp
ros2 run demo_nodes_cpp talker

# Terminal 2: HDDS subscriber
export RMW_IMPLEMENTATION=rmw_hdds
ros2 run demo_nodes_cpp listener
```

## Checklist

- [ ] Build rmw_hdds
- [ ] Set `RMW_IMPLEMENTATION=rmw_hdds`
- [ ] Move network settings from XML to environment variables
- [ ] Set QoS in code
- [ ] Remove FastDDS-specific code (if any)
- [ ] Test basic communication
- [ ] Verify QoS behavior matches expectations
- [ ] Performance test critical paths
- [ ] Update deployment scripts
- [ ] Document new configuration

## Next Steps

- [rmw_hdds Configuration](../../ros2/rmw-hdds/configuration.md) - Detailed configuration
- [Performance Tuning](../../ros2/performance.md) - Optimize for your use case
- [Migration from CycloneDDS](../../ros2/migration/from-cyclonedds.md) - Alternative migration
