# Migrate from FastDDS

Guide to switching from FastDDS (rmw_fastrtps) to HDDS (rmw_hdds) in ROS2 applications.

## Quick Migration

### Step 1: Install rmw_hdds

```bash
sudo apt install ros-$ROS_DISTRO-rmw-hdds
```

### Step 2: Set Environment

```bash
export RMW_IMPLEMENTATION=rmw_hdds_cpp
```

### Step 3: Test

```bash
ros2 run demo_nodes_cpp talker
```

That's it for basic applications. The sections below cover advanced configurations.

## Configuration Migration

### Environment Variables

| FastDDS | HDDS | Description |
|---------|------|-------------|
| `ROS_DOMAIN_ID` | `ROS_DOMAIN_ID` or `HDDS_DOMAIN_ID` | Domain ID (HDDS var takes priority) |
| `FASTRTPS_DEFAULT_PROFILES_FILE` | `HDDS_QOS_PROFILE_PATH` | QoS profile file path |
| `RMW_FASTRTPS_USE_QOS_FROM_XML` | N/A | HDDS always respects profile file |
| `FASTRTPS_INTRAPROCESS_DELIVERY` | Transport config | HDDS supports SHM via transport configuration |

### XML Configuration

**FastDDS profile:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<profiles xmlns="http://www.eprosima.com/XMLSchemas/fastRTPS_Profiles">
    <participant profile_name="default_participant" is_default_profile="true">
        <rtps>
            <builtin>
                <discovery_config>
                    <leaseDuration>
                        <sec>10</sec>
                    </leaseDuration>
                </discovery_config>
            </builtin>
        </rtps>
    </participant>

    <data_writer profile_name="default_datawriter" is_default_profile="true">
        <qos>
            <reliability>
                <kind>RELIABLE_RELIABILITY_QOS</kind>
            </reliability>
            <durability>
                <kind>TRANSIENT_LOCAL_DURABILITY_QOS</kind>
            </durability>
        </qos>
    </data_writer>
</profiles>
```

**Equivalent HDDS configuration:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<hdds>
    <domain id="0">
        <participant>
            <discovery>
                <lease_duration_sec>10</lease_duration_sec>
            </discovery>
        </participant>
    </domain>

    <qos_profiles>
        <profile name="default">
            <reliability kind="RELIABLE"/>
            <durability kind="TRANSIENT_LOCAL"/>
        </profile>
    </qos_profiles>
</hdds>
```

## QoS Configuration Mapping

### Reliability

**FastDDS:**
```xml
<reliability>
    <kind>RELIABLE_RELIABILITY_QOS</kind>
    <max_blocking_time>
        <sec>1</sec>
        <nanosec>0</nanosec>
    </max_blocking_time>
</reliability>
```

**HDDS:**
```xml
<reliability kind="RELIABLE" max_blocking_ms="1000"/>
```

### History

**FastDDS:**
```xml
<history>
    <kind>KEEP_LAST_HISTORY_QOS</kind>
    <depth>10</depth>
</history>
```

**HDDS:**
```xml
<history kind="KEEP_LAST" depth="10"/>
```

### Durability

| FastDDS | HDDS |
|---------|------|
| `VOLATILE_DURABILITY_QOS` | `VOLATILE` |
| `TRANSIENT_LOCAL_DURABILITY_QOS` | `TRANSIENT_LOCAL` |
| `TRANSIENT_DURABILITY_QOS` | `TRANSIENT` |
| `PERSISTENT_DURABILITY_QOS` | `PERSISTENT` |

### Deadline and Liveliness

**FastDDS:**
```xml
<deadline>
    <period>
        <sec>0</sec>
        <nanosec>100000000</nanosec>
    </period>
</deadline>
<liveliness>
    <kind>MANUAL_BY_TOPIC_LIVELINESS_QOS</kind>
    <lease_duration>
        <sec>1</sec>
    </lease_duration>
</liveliness>
```

**HDDS:**
```xml
<deadline period_ms="100"/>
<liveliness kind="MANUAL_BY_TOPIC" lease_ms="1000"/>
```

## Transport Configuration

### Shared Memory

**FastDDS:**
```xml
<transport_descriptors>
    <transport_descriptor>
        <transport_id>shm_transport</transport_id>
        <type>SHM</type>
        <segment_size>1048576</segment_size>
    </transport_descriptor>
</transport_descriptors>
```

**HDDS:**
```xml
<transport>
    <shared_memory enabled="true">
        <segment_size_mb>1</segment_size_mb>
    </shared_memory>
</transport>
```

### UDP Configuration

**FastDDS:**
```xml
<transport_descriptors>
    <transport_descriptor>
        <transport_id>udp_transport</transport_id>
        <type>UDPv4</type>
        <sendBufferSize>1048576</sendBufferSize>
        <receiveBufferSize>1048576</receiveBufferSize>
    </transport_descriptor>
</transport_descriptors>
```

**HDDS:**
```xml
<transport>
    <udp enabled="true">
        <send_buffer_size>1048576</send_buffer_size>
        <receive_buffer_size>1048576</receive_buffer_size>
    </udp>
</transport>
```

## Discovery Configuration

### Static Discovery

**FastDDS:**
```xml
<builtin>
    <discovery_config>
        <discoveryProtocol>SIMPLE</discoveryProtocol>
        <EDP>STATIC</EDP>
        <static_edp_xml_config>file://static_discovery.xml</static_edp_xml_config>
    </discovery_config>
    <metatrafficUnicastLocatorList>
        <locator>
            <udpv4>
                <address>192.168.1.100</address>
                <port>7400</port>
            </udpv4>
        </locator>
    </metatrafficUnicastLocatorList>
</builtin>
```

**HDDS:**
```xml
<discovery>
    <static_peers>
        <peer>192.168.1.100:7400</peer>
    </static_peers>
</discovery>
```

### Initial Peers

**FastDDS:**
```xml
<initialPeersList>
    <locator>
        <udpv4>
            <address>192.168.1.100</address>
            <port>7400</port>
        </udpv4>
    </locator>
</initialPeersList>
```

**HDDS:**
```xml
<discovery>
    <initial_peers>
        <peer>192.168.1.100:7400</peer>
    </initial_peers>
</discovery>
```

## Code Changes

### No Code Changes Required

rmw_hdds is a drop-in replacement. Standard ROS2 code works without modification:

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

## Performance Comparison

| Metric | FastDDS | HDDS | Notes |
|--------|---------|------|-------|
| Latency (64B) | 45 us | 8 us | Same host |
| Throughput | 1.8 M/s | 2.5 M/s | 64B messages |
| Memory (idle) | 4 MB | 2 MB | Per participant |
| Discovery time | 200 ms | 150 ms | 2 participants |

## Common Migration Issues

### Issue: Different Default QoS

FastDDS and HDDS may have slightly different defaults.

**Solution**: Explicitly set QoS in code or configuration:

```cpp
auto qos = rclcpp::QoS(10)
    .reliable()
    .durability_volatile();
auto pub = node->create_publisher<MyMsg>("topic", qos);
```

### Issue: Discovery Slower

HDDS uses different discovery timing by default.

**Solution**: Configure faster discovery:
```xml
<discovery>
    <initial_announcements count="10" period_ms="50"/>
</discovery>
```

### Issue: Multicast Not Working

**Solution**: Check network configuration. Use HDDS core environment variables for advanced transport settings:
```bash
# See /reference/environment-vars for multicast configuration
export HDDS_INTERFACE=eth0
```

### Issue: Security Configuration Differs

**Solution**: Security uses standard ROS2 SROS2 tooling:
```bash
ros2 security create_keystore /path/to/keystore
ros2 security create_enclave /path/to/keystore /my_enclave
```

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
2. **Verify communication**: HDDS and FastDDS can interoperate
3. **Performance test**: Measure latency and throughput
4. **Production rollout**: Switch all nodes

### Mixed RMW Testing

```bash
# Terminal 1: FastDDS publisher
export RMW_IMPLEMENTATION=rmw_fastrtps_cpp
ros2 run demo_nodes_cpp talker

# Terminal 2: HDDS subscriber
export RMW_IMPLEMENTATION=rmw_hdds_cpp
ros2 run demo_nodes_cpp listener
```

Both work together via standard RTPS protocol.

## Checklist

- [ ] Install rmw_hdds package
- [ ] Set `RMW_IMPLEMENTATION=rmw_hdds_cpp`
- [ ] Convert XML configuration (if applicable)
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
